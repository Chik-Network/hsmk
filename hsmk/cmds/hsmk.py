from decimal import Decimal
from typing import BinaryIO, Iterable, List, TextIO

import argparse
import io
import readline  # noqa: F401  this allows long lines on stdin
import subprocess
import sys
import zlib

from chik_base.atoms import bytes32
from chik_base.bls12_381 import BLSSecretExponent, BLSSignature
from chik_base.util.bech32 import bech32_encode


import segno

from hsmk.consensus.conditions import conditions_by_opcode
from hsmk.core.unsigned_spend import UnsignedSpend
from hsmk.process.sign import conditions_for_coin_spend, sign
from hsmk.puzzles import conlang
from hsmk.util.byte_chunks import ChunkAssembler
from hsmk.util.qrint_encoding import a2b_qrint, b2a_qrint


XCK_PER_MOJO = Decimal("1e12")


def unsigned_spend_from_blob(blob: bytes) -> UnsignedSpend:
    try:
        uncompressed_blob = zlib.decompress(blob)
        return UnsignedSpend.from_bytes(uncompressed_blob)
    except Exception:
        return UnsignedSpend.from_bytes(blob)


def create_unsigned_spend_pipeline(
    nochunks: bool, f=sys.stdout
) -> Iterable[UnsignedSpend]:
    print("waiting for qrint-encoded signing requests", file=f)
    partial_encodings = {}
    while True:
        try:
            print("> ", end="", file=f)
            line = input("").strip()
            if len(line) == 0:
                break
            blob = a2b_qrint(line)

            if nochunks:
                yield unsigned_spend_from_blob(blob)
                break

            part_count = blob[-1]
            if part_count not in partial_encodings:
                partial_encodings[part_count] = ChunkAssembler()
            ca = partial_encodings[part_count]
            ca.add_chunk(blob)
            if ca.is_assembled():
                del partial_encodings[part_count]
                blob = ca.assemble()
                yield unsigned_spend_from_blob(blob)
        except EOFError:
            break
        except Exception as ex:
            print(ex, file=f)


def replace_with_gpg_pipe(args, f: BinaryIO) -> TextIO:
    gpg_args = ["gpg", "-d"]
    if args.gpg_argument:
        gpg_args.extend(args.gpg_argument.split())
    gpg_args.append(f.name)
    popen = subprocess.Popen(gpg_args, stdout=subprocess.PIPE)
    if popen is None or popen.stdout is None:
        raise ValueError("couldn't launch gpg")
    return io.TextIOWrapper(popen.stdout)


def parse_private_key_file(args) -> List[BLSSecretExponent]:
    secret_exponents = []
    for f in args.private_key_file:
        if f.name.endswith(".gpg"):
            f = replace_with_gpg_pipe(args, f)
        for line in f.readlines():
            try:
                secret_exponent = BLSSecretExponent.from_bech32m(line.strip())
                secret_exponents.append(secret_exponent)
            except ValueError:
                pass
    return secret_exponents


def summarize_unsigned_spend(unsigned_spend: UnsignedSpend, f=sys.stdout):
    print(file=f)
    for coin_spend in unsigned_spend.coin_spends:
        xck_amount = Decimal(coin_spend.coin.amount) / XCK_PER_MOJO
        address = address_for_puzzle_hash(coin_spend.coin.puzzle_hash)
        print(f"COIN SPENT: {xck_amount:0.12f} xck at address {address}", file=f)
        conditions = conditions_for_coin_spend(coin_spend)

    print(file=f)
    for coin_spend in unsigned_spend.coin_spends:
        conditions = conditions_for_coin_spend(coin_spend)
        conditions_lookup = conditions_by_opcode(conditions)
        for create_coin in conditions_lookup.get(conlang.CREATE_COIN, []):
            puzzle_hash = create_coin.at("rf").atom
            address = address_for_puzzle_hash(puzzle_hash)
            amount = int(create_coin.at("rrf"))
            xck_amount = Decimal(amount) / XCK_PER_MOJO
            print(f"COIN CREATED: {xck_amount:0.12f} xck to {address}", file=f)
    print(file=f)


def address_for_puzzle_hash(puzzle_hash: bytes32) -> str:
    return bech32_encode("xck", puzzle_hash)


def check_ok():
    text = input('if this looks reasonable, enter "ok" to generate signature> ')
    return text.lower() == "ok"


def hsmk(args, parser):
    wallet = parse_private_key_file(args)
    f = sys.stderr
    unsigned_spend_pipeline = create_unsigned_spend_pipeline(args.nochunks, f)
    for unsigned_spend in unsigned_spend_pipeline:
        if not args.yes:
            summarize_unsigned_spend(unsigned_spend, f)
            if not check_ok():
                continue
        signature_info = sign(unsigned_spend, wallet)
        if signature_info:
            signature = sum(
                [_.signature for _ in signature_info], start=BLSSignature.zero()
            )
            encoded_sig = b2a_qrint(bytes(signature))
            if args.qr:
                qr = segno.make_qr(encoded_sig)
                print()
                qr.terminal(compact=True)
                print()
            else:
                print(encoded_sig)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage private keys and process signing requests"
    )
    parser.add_argument(
        "-y",
        "--yes",
        help="skip confirmations",
        action="store_true",
    )
    parser.add_argument(
        "--qr",
        help="show signature as QR code",
        action="store_true",
    )
    parser.add_argument(
        "--nochunks",
        help="read the spend in its entirety rather than as chunks (testing only)",
        action="store_true",
    )
    parser.add_argument(
        "-g", "--gpg-argument", help="argument to pass to gpg (besides -d).", default=""
    )
    parser.add_argument(
        # "-f",
        "private_key_file",
        metavar="path-to-private-keys",
        action="append",
        default=[],
        help=(
            "file containing bech32m-encoded secret exponents. "
            """If file name ends with .gpg, "gpg -d" will be invoked """
            "automatically. File is read one line at a time."
        ),
        type=argparse.FileType("r"),
    )
    return parser


def main(argv=sys.argv[1:]):
    parser = create_parser()
    args = parser.parse_args(argv)
    return hsmk(args, parser)


if __name__ == "__main__":
    main()
