from typing import List

from chik_base.core import Coin
from chik_base.util.std_hash import std_hash

from klvm_rs import Program  # type: ignore

from hsmk.klvm.disasm import disassemble as bu_disassemble, KEYWORD_FROM_ATOM
from hsmk.consensus.conditions import conditions_by_opcode
from hsmk.process.sign import generate_verify_pairs
from hsmk.puzzles import conlang

KFA = {bytes([getattr(conlang, k)]): k for k in dir(conlang) if k[0] in "ACR"}

AGG_SIG_ME_ADDITIONAL_DATA = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

MAX_COST = 1 << 34


# information needed to spend a cc
# if we ever support more genesis conditions, like a re-issuable coin,
# we may need also to save the `genesis_coin_mod` or its hash


def disassemble(sexp):
    """
    This version of `disassemble` also disassembles condition opcodes like
    `ASSERT_ANNOUNCEMENT_CONSUMED`.
    """
    kfa = dict(KEYWORD_FROM_ATOM)
    kfa.update((Program.to(k).atom, v) for k, v in KFA.items())
    return bu_disassemble(sexp, kfa)


def coin_as_program(coin: Coin) -> Program:
    """
    Convenience function for when putting `coin_info` into a solution.
    """
    return Program.to([coin.parent_coin_info, coin.puzzle_hash, coin.amount])


def dump_coin(coin: Coin) -> str:
    return disassemble(coin_as_program(coin))


def debug_spend_bundle(
    spend_bundle, agg_sig_additional_data=AGG_SIG_ME_ADDITIONAL_DATA
) -> None:
    """
    Print a lot of useful information about a `SpendBundle` that might help with
    debugging its klvm.
    """

    pks = []
    msgs = []

    created_coin_announcements: List[List[bytes]] = []
    asserted_coin_announcements = []
    created_puzzle_announcements: List[List[bytes]] = []
    asserted_puzzle_announcements = []

    print("=" * 80)
    for coin_spend in spend_bundle.coin_spends:
        coin = coin_spend.coin
        puzzle_reveal = Program.from_bytes(bytes(coin_spend.puzzle_reveal))
        solution = Program.from_bytes(bytes(coin_spend.solution))
        coin_name = coin.name()

        if puzzle_reveal.tree_hash() != coin_spend.coin.puzzle_hash:
            print("*** BAD PUZZLE REVEAL")
            print(
                f"{puzzle_reveal.tree_hash().hex()} vs"
                f" {coin_spend.coin.puzzle_hash.hex()}"
            )
            print("*" * 80)
            continue

        print(f"consuming coin {dump_coin(coin)}")
        print(f"  with id {coin_name}")
        print()
        print(
            f"\nbrun -y main.sym '{bu_disassemble(puzzle_reveal)}'"
            f" '{bu_disassemble(solution)}'"
        )
        cost, r = puzzle_reveal.run_with_cost(solution, max_cost=MAX_COST)
        conditions = conditions_by_opcode(r)
        error = None
        if error:
            print(f"*** error {error}")
        elif conditions is not None:
            for public_key, m in generate_verify_pairs(
                coin_spend, agg_sig_additional_data
            ):
                pks.append(public_key)
                msgs.append(m)
            print()
            print(disassemble(r))
            print(f"cost = {cost}")
            print()
            if conditions and len(conditions) > 0:
                print("grouped conditions:")
                for condition_programs in conditions.values():
                    print()
                    for c in condition_programs:
                        print(f"  {disassemble(Program.to(c))}")
                created_coin_announcements.extend(
                    [coin_name] + _.vars
                    for _ in conditions.get(conlang.CREATE_COIN_ANNOUNCEMENT, [])
                )
                asserted_coin_announcements.extend(
                    [
                        _.vars[0].hex()
                        for _ in conditions.get(conlang.ASSERT_COIN_ANNOUNCEMENT, [])
                    ]
                )
                created_puzzle_announcements.extend(
                    [puzzle_reveal.tree_hash()] + _.vars
                    for _ in conditions.get(conlang.CREATE_PUZZLE_ANNOUNCEMENT, [])
                )
                asserted_puzzle_announcements.extend(
                    [
                        _.vars[0].hex()
                        for _ in conditions.get(conlang.ASSERT_PUZZLE_ANNOUNCEMENT, [])
                    ]
                )
                print()
            else:
                print("(no output conditions generated)")
        print()
        print("-------")

    if 0:
        created = set(spend_bundle.additions())
        spent = set(spend_bundle.removals())

        zero_coin_set = set(coin.name() for coin in created if coin.amount == 0)

        ephemeral = created.intersection(spent)
        created.difference_update(ephemeral)
        spent.difference_update(ephemeral)
        print()
        print("spent coins")
        for coin in sorted(spent, key=lambda _: _.name()):
            print(f"  {dump_coin(coin)}")
            print(f"      => spent coin id {coin.name()}")
        print()
        print("created coins")
        for coin in sorted(created, key=lambda _: _.name()):
            print(f"  {dump_coin(coin)}")
            print(f"      => created coin id {coin.name()}")

        if ephemeral:
            print()
            print("ephemeral coins")
            for coin in sorted(ephemeral, key=lambda _: _.name()):
                print(f"  {dump_coin(coin)}")
                print(f"      => created coin id {coin.name()}")

        created_coin_announcement_pairs = [
            (_, std_hash(b"".join(_)).hex()) for _ in created_coin_announcements
        ]
        if created_coin_announcement_pairs:
            print("created coin announcements")
            for announcement, hashed in sorted(
                created_coin_announcement_pairs, key=lambda _: _[-1]
            ):
                as_hex = [f"0x{_.hex()}" for _ in announcement]
                print(f"  {as_hex} =>\n      {hashed}")

        eor_coin_announcements = sorted(
            set(_[-1] for _ in created_coin_announcement_pairs)
            ^ set(asserted_coin_announcements)
        )

        created_puzzle_announcement_pairs = [
            (_, std_hash(b"".join(_)).hex()) for _ in created_puzzle_announcements
        ]
        if created_puzzle_announcements:
            print("created puzzle announcements")
            for announcement, hashed in sorted(
                created_puzzle_announcement_pairs, key=lambda _: _[-1]
            ):
                as_hex = [f"0x{_.hex()}" for _ in announcement]
                print(f"  {as_hex} =>\n      {hashed}")

        eor_puzzle_announcements = sorted(
            set(_[-1] for _ in created_puzzle_announcement_pairs)
            ^ set(asserted_puzzle_announcements)
        )

        print()
        print()
        print(f"zero_coin_set = {sorted(zero_coin_set)}")
        print()
        if created_coin_announcement_pairs or asserted_coin_announcements:
            sa = sorted([_[-1] for _ in created_coin_announcement_pairs])
            print(f"created  coin announcements = {sa}")
            print()
            print(
                f"asserted coin announcements = {sorted(asserted_coin_announcements)}"
            )
            print()
            print(f"symdiff of coin announcements = {sorted(eor_coin_announcements)}")
            print()
        if created_puzzle_announcement_pairs or asserted_puzzle_announcements:
            sa = sorted([_[-1] for _ in created_puzzle_announcement_pairs])
            print(f"created  puzzle announcements = {sa}")
            print()
            print(
                f"asserted puzzle announcements ="
                f" {sorted(asserted_puzzle_announcements)}"
            )
            print()
            print(
                f"symdiff of puzzle announcements ="
                f" {sorted(eor_puzzle_announcements)}"
            )
            print()
    print()
    print("=" * 80)
    print()
    signature = spend_bundle.aggregated_signature
    validates = signature.verify(list(zip(pks, msgs)))
    print(f"aggregated signature check pass: {validates}")
    print(f"pks: {pks}")
    print(f"msgs: {[msg.hex() for msg in msgs]}")
    print(f"  msg_data: {[msg.hex()[:-128] for msg in msgs]}")
    print(f"  coin_ids: {[msg.hex()[-128:-64] for msg in msgs]}")
    print(f"  add_data: {[msg.hex()[-64:] for msg in msgs]}")
    print(f"signature: {signature}")
    return validates
