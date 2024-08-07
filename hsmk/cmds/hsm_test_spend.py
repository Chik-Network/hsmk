import argparse
import hashlib
import sys
import zlib

from klvm_rs import Program  # type: ignore

from chik_base.bls12_381 import BLSPublicKey
from chik_base.core import Coin, CoinSpend

from hsmk.core.signing_hints import SumHint, PathHint
from hsmk.core.unsigned_spend import UnsignedSpend
from hsmk.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    DEFAULT_HIDDEN_PUZZLE,
    puzzle_for_public_key_and_hidden_puzzle,
    solution_for_conditions,
    calculate_synthetic_offset,
)
from hsmk.puzzles.conlang import CREATE_COIN
from hsmk.util.byte_chunks import (
    create_chunks_for_blob,
    optimal_chunk_size_for_max_chunk_size,
)
from hsmk.util.qrint_encoding import b2a_qrint

MAINNET_AGG_SIG_ME_ADDITIONAL_DATA = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)


DEFAULT_HIDDEN_PUZZLE_HASH = DEFAULT_HIDDEN_PUZZLE.tree_hash()


def hsm_test_spend(args, parser):
    root_public_keys = [BLSPublicKey.from_bech32m(_) for _ in args.public_key]

    paths = [[index, index + 1] for index in range(len(root_public_keys))]

    public_keys = [
        root_key.child_for_path(path) for root_key, path in zip(root_public_keys, paths)
    ]

    # create "sum public keys" that are the sum of pubkeys from each of A and B
    sum_pk = sum(public_keys, start=BLSPublicKey.zero())

    # create a standard puzzle using the sum of the public keys
    puzzle = puzzle_for_public_key_and_hidden_puzzle(sum_pk, DEFAULT_HIDDEN_PUZZLE)

    # make the coin
    FAKE_PARENT = hashlib.sha256(b"parent").digest()
    coin = Coin(FAKE_PARENT, puzzle.tree_hash(), 1)

    synthetic_secret_exponent = calculate_synthetic_offset(
        sum_pk, DEFAULT_HIDDEN_PUZZLE_HASH
    )

    sum_hints = [SumHint(public_keys, synthetic_secret_exponent)]

    path_hints = [
        PathHint(root_key, path) for root_key, path in zip(root_public_keys, paths)
    ]

    # destination

    dest_puzzle_hash_1 = Program.to(100).tree_hash()
    dest_puzzle_hash_2 = Program.to(200).tree_hash()
    conditions_for_spend = Program.to(
        [
            [CREATE_COIN, dest_puzzle_hash_1, int(3 * 1e12)],
            [CREATE_COIN, dest_puzzle_hash_2, int(2 * 1e12)],
        ]
    )
    solution = solution_for_conditions(conditions_for_spend)

    coin_spend = CoinSpend(coin, puzzle, solution)

    unsigned_spend = UnsignedSpend(
        [coin_spend], sum_hints, path_hints, MAINNET_AGG_SIG_ME_ADDITIONAL_DATA
    )

    b = bytes(unsigned_spend)
    if args.hex:
        print(b.hex())
    else:
        if args.no_chunks:
            chunks = [b]
        else:
            cb = zlib.compress(b)
            optimal_size = optimal_chunk_size_for_max_chunk_size(
                len(cb), args.max_chunk_size
            )
            chunks = create_chunks_for_blob(cb, optimal_size)
        for chunk in chunks:
            print(b2a_qrint(chunk))

    us = UnsignedSpend.from_bytes(b)
    assert bytes(us) == b


def create_parser():
    parser = argparse.ArgumentParser(
        description="Generate a `UnsignedSpend` test as a proof-of-concept"
    )
    parser.add_argument(
        "-m",
        "--max-chunk-size",
        metavar="maximum-bytes-per-chunk",
        default=8192,
        help="maximum number of bytes encoded into each chunk",
        type=int,
    )
    parser.add_argument(
        "-H",
        "--hex",
        action="store_true",
        help="hex output",
    )
    parser.add_argument(
        "-n",
        "--no-chunks",
        action="store_true",
        help="don't compress or chunk output",
    )
    parser.add_argument(
        "public_key",
        metavar="public-key",
        nargs="+",
        help="bech32m-encoded public key",
        type=str,
    )
    return parser


def main(argv=sys.argv[1:]):
    parser = create_parser()
    args = parser.parse_args(argv)
    return hsm_test_spend(args, parser)


if __name__ == "__main__":  # pragma: no cover
    main()
