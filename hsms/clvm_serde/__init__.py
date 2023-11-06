from dataclasses import is_dataclass, fields, MISSING
from types import GenericAlias
from typing import Any, Callable, Type

from chia_base.atoms import bytes32
from chia_base.meta.type_tree import ArgsType, CompoundLookup, OriginArgsType, TypeTree

from clvm_rs import Program  # type: ignore

ToProgram = Callable[[Any], Program]
FromProgram = Callable[[Program], Any]


class EncodingError(BaseException):
    pass


class tuple_frugal(tuple):
    pass


class Frugal:
    """
    This is a tag. Subclasses, when serialized, don't use a nil terminator when
    serialized.
    """

    pass


# some helper methods to implement chia serialization
#
def read_bytes(p: Program) -> bytes:
    if p.atom is None:
        raise EncodingError("expected atom for str")
    return p.atom


def read_str(p: Program) -> str:
    return read_bytes(p).decode()


def read_int(p: Program) -> int:
    return Program.int_from_bytes(read_bytes(p))


def serialize_for_list(origin, args, type_tree: TypeTree) -> Program:
    write_item = type_tree(args[0])

    def serialize_list(items):
        return Program.to([write_item(_) for _ in items])

    return serialize_list


def serialize_for_tuple(origin, args, type_tree: TypeTree) -> Program:
    write_items = [type_tree(_) for _ in args]

    def serialize_tuple(items):
        return Program.to(
            [
                write_f(item)
                for write_f, item in zip(
                    write_items,
                    items,
                )
            ]
        )

    return serialize_tuple


def ser_for_tuple_frugal(origin, args, type_tree: TypeTree) -> Program:
    streaming_calls = [
        type_tree(
            _,
        )
        for _ in args
    ]

    def ser(item):
        if len(item) != len(streaming_calls):
            raise EncodingError("incorrect number of items in tuple")

        values = list(zip(streaming_calls, item))
        sc, v = values.pop()
        t = sc(v)
        while values:
            sc, v = values.pop()
            t = (sc(v), t)
        return Program.to(t)

    return ser


SERIALIZER_COMPOUND_TYPE_LOOKUP: CompoundLookup[ToProgram] = {
    list: serialize_for_list,
    tuple: serialize_for_tuple,
    tuple_frugal: ser_for_tuple_frugal,
}


def types_for_fields(t: type, call_morpher, type_tree: TypeTree):
    # split into key-based and location-based

    key_based = []
    location_based = []
    for f in fields(t):
        default_value = (
            f.default if f.default_factory is MISSING else f.default_factory()
        )
        m = f.metadata
        key = m.get("key")
        if key is None:
            location_based.append(f)
        else:
            alt_serde_type = m.get("alt_serde_type")
            storage_type = alt_serde_type[0] if alt_serde_type else f.type
            call = type_tree(storage_type)
            key_based.append((key, f.name, call_morpher(call, f), default_value))

    return location_based, key_based


def ser_dataclass(origin: Type, args_type: ArgsType, type_tree: TypeTree) -> Program:
    def morph_call(call, f):
        alt_serde_type = f.metadata.get("alt_serde_type")
        if alt_serde_type:
            _type, from_storage, _to_storage = alt_serde_type

            def f(x):
                return call(from_storage(x))

            return f
        return call

    location_based, key_based = types_for_fields(origin, morph_call, type_tree)

    types = tuple(f.type for f in location_based)
    tuple_type = GenericAlias(tuple, types)
    if key_based:
        types = types + (
            GenericAlias(list, (GenericAlias(tuple_frugal, (str, Program)),)),
        )
    if key_based or issubclass(origin, Frugal):
        tuple_type = GenericAlias(tuple_frugal, types)

    names = tuple(f.name for f in location_based)

    ser_tuple = type_tree(tuple_type)

    def ser(item):
        # convert to a tuple
        v = []
        for name in names:
            v.append(getattr(item, name))
        if key_based:
            d = []
            for key, name, call, default_value in key_based:
                a = getattr(item, name)
                if a == default_value:
                    continue
                d.append((key, call(a)))
            v.append(d)

        return ser_tuple(v)

    return ser


def fail_ser(
    origin: Type, args_type: ArgsType, type_tree: TypeTree
) -> None | ToProgram:
    if origin in [str, bytes, int]:
        return Program.to

    if is_dataclass(origin):
        return ser_dataclass(origin, args_type, type_tree)

    if hasattr(origin, "__bytes__"):
        return lambda x: Program.to(bytes(x))

    return None


def deser_dataclass(origin: Type, args_type: ArgsType, type_tree: TypeTree):
    def morph_call(call, f):
        alt_serde_type = f.metadata.get("alt_serde_type")
        if alt_serde_type:
            _type, _from_storage, to_storage = alt_serde_type

            def f(x):
                return to_storage(call(x))

            return f
        return call

    location_based, key_based = types_for_fields(origin, morph_call, type_tree)

    types = tuple(f.type for f in location_based)
    tuple_type = GenericAlias(tuple, types)
    if key_based:
        types = types + (
            GenericAlias(list, GenericAlias(tuple_frugal, (str, Program))),
        )
    if key_based or issubclass(origin, Frugal):
        tuple_type = GenericAlias(tuple_frugal, types)

    de_tuple = type_tree(tuple_type)

    if key_based:

        def de(p: Program):
            the_tuple = de_tuple(p)
            args = the_tuple[:-1]
            d = dict((k, v) for k, v in the_tuple[-1])
            kwargs = {}
            for key, name, call, default_value in key_based:
                if key in d:
                    kwargs[name] = call(d[key])
                else:
                    if default_value == MISSING:
                        raise EncodingError(
                            f"missing required field for {name} with key {key}"
                        )
                    kwargs[name] = default_value

            return origin(*args, **kwargs)

    else:

        def de(p: Program):
            the_tuple = de_tuple(p)
            return origin(*the_tuple)

    return de


def fail_deser(origin: Type, args_type: ArgsType, type_tree: TypeTree):
    if is_dataclass(origin):
        return deser_dataclass(origin, args_type, type_tree)

    if hasattr(origin, "from_bytes"):
        return lambda p: origin.from_bytes(p.atom)

    return None


def to_program_for_type(t: type) -> Callable[[Any], Program]:
    return TypeTree(
        {(Program, None): lambda x: x},
        SERIALIZER_COMPOUND_TYPE_LOOKUP,
        fail_ser,
    )(t)


def deser_for_list(origin, args, type_tree: TypeTree):
    read_item = type_tree(args[0])

    def deserialize_list(p: Program) -> list:
        return [read_item(_) for _ in p.as_iter()]

    return deserialize_list


def deser_for_tuple(origin, args, type_tree: TypeTree):
    read_items = [type_tree(_) for _ in args]

    def deserialize_tuple(p: Program) -> tuple[Any, ...]:
        items = list(p.as_iter())
        if len(items) != len(read_items):
            raise EncodingError("wrong size program")
        return tuple(f(_) for f, _ in zip(read_items, items))

    return deserialize_tuple


def de_for_tuple_frugal(origin, args, type_tree: TypeTree):
    read_items = [type_tree(_) for _ in args]

    def de(p: Program) -> tuple[Any, ...]:
        args = []
        todo = list(reversed(read_items))
        while todo:
            des = todo.pop()
            if todo:
                v = p.pair[0]
                p = p.pair[1]
            else:
                v = p
            args.append(des(v))
        return tuple(args)

    return de


DESERIALIZER_COMPOUND_TYPE_LOOKUP: CompoundLookup[FromProgram] = {
    list: deser_for_list,
    tuple: deser_for_tuple,
    tuple_frugal: de_for_tuple_frugal,
}


def from_program_for_type(t: type) -> FromProgram:
    simple_lookup: dict[OriginArgsType, FromProgram] = {
        (bytes, None): read_bytes,
        (bytes32, None): read_bytes,
        (str, None): read_str,
        (int, None): read_int,
        (Program, None): lambda x: x,
    }
    return TypeTree(
        simple_lookup,
        DESERIALIZER_COMPOUND_TYPE_LOOKUP,
        fail_deser,
    )(t)


def merging_function_for_callable_parameters(f: Callable) -> Callable:
    parameter_names = [k for k in f.__annotations__.keys() if k != "return"]

    def merging_function(*args, **kwargs) -> tuple[Any, ...]:
        merged_args = args + tuple(kwargs[_] for _ in parameter_names[len(args) :])
        return merged_args

    return merging_function
