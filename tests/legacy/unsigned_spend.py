from dataclasses import dataclass
from typing import List

from chik_base.atoms import bytes32
from chik_base.bls12_381 import BLSPublicKey, BLSSignature
from chik_base.core import Coin, CoinSpend

from klvm_rs import Program

from .klvm_serialization import (
    as_atom,
    as_int,
    klvm_to_list,
    no_op,
    transform_dict,
    transform_dict_by_key,
    transform_as_struct,
)
from .signing_hints import SumHint, PathHint


@dataclass
class SignatureInfo:
    signature: BLSSignature
    partial_public_key: BLSPublicKey
    final_public_key: BLSPublicKey
    message: bytes


@dataclass
class UnsignedSpend:
    coin_spends: List[CoinSpend]
    sum_hints: List[SumHint]
    path_hints: List[PathHint]
    agg_sig_me_network_suffix: bytes32

    def as_program(self):
        as_klvm = [("a", self.agg_sig_me_network_suffix)]
        cs_as_klvm = [
            [_.coin.parent_coin_info, _.puzzle_reveal, _.coin.amount, _.solution]
            for _ in self.coin_spends
        ]
        as_klvm.append(("c", cs_as_klvm))
        sh_as_klvm = [_.as_program() for _ in self.sum_hints]
        as_klvm.append(("s", sh_as_klvm))
        ph_as_klvm = [_.as_program() for _ in self.path_hints]
        as_klvm.append(("p", ph_as_klvm))
        self_as_program = Program.to(as_klvm)
        return self_as_program

    @classmethod
    def from_program(cls, program) -> "UnsignedSpend":
        d = transform_dict(program, transform_dict_by_key(UNSIGNED_SPEND_TRANSFORMER))
        return cls(d["c"], d.get("s", []), d.get("p", []), d["a"])


def coin_spend_from_program(program: Program) -> CoinSpend:
    struct = transform_as_struct(program, as_atom, no_op, as_int, no_op)
    parent_coin_info, puzzle_reveal, amount, solution = struct
    return CoinSpend(
        Coin(
            parent_coin_info,
            puzzle_reveal.tree_hash(),
            amount,
        ),
        puzzle_reveal,
        solution,
    )


UNSIGNED_SPEND_TRANSFORMER = {
    "c": lambda x: klvm_to_list(x, coin_spend_from_program),
    "s": lambda x: klvm_to_list(x, SumHint.from_program),
    "p": lambda x: klvm_to_list(x, PathHint.from_program),
    "a": lambda x: x.atom,
}
