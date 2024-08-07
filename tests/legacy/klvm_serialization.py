from typing import Any, Callable, Dict, List, Tuple, TypeVar

from klvm_rs import Program


K = TypeVar("K")
T = TypeVar("T")
V = TypeVar("V")


def transform_dict(program, dict_transformer_f):
    """
    Transform elements of the dict d using the xformer (also a dict,
    where the keys match the keys in d and the values of d are transformed
    by invoking the corresponding values in xformer.
    """
    r = klvm_to_list(program, lambda x: dict_transformer_f(x.pair[0], x.pair[1]))
    d = dict(r)
    return d


def transform_by_key(
    key: Program,
    value: Program,
    transformation_lookup: Dict[str, Callable[[Program], Any]],
) -> Tuple[str, Any]:
    """
    Use this if the key is utf-8 and the value decoding depends on the key.
    """
    key_str = key.atom.decode()
    f = transformation_lookup.get(key_str, lambda x: x)
    final_value = f(value)
    return (key_str, final_value)


def transform_dict_by_key(
    transformation_lookup: Dict[str, Callable[[Program], Any]]
) -> Any:
    return lambda k, v: transform_by_key(k, v, transformation_lookup)


def transform_as_struct(items: Program, *struct_transformers) -> Tuple[Any, ...]:
    r = []
    for f in struct_transformers:
        r.append(f(items.pair[0]))
        items = items.pair[1]
    return tuple(r)


def klvm_to_list(
    item_list: Program, item_transformation_f: Callable[[Program], T]
) -> List[T]:
    r = []
    while item_list.pair:
        this_item, item_list = item_list.pair
        r.append(item_transformation_f(this_item))
    return r


def klvm_to_list_of_ints(items: Program) -> List[int]:
    return klvm_to_list(items, lambda obj: Program.to(obj).as_int())


def no_op(x):
    return x


def as_atom(x):
    return x.atom


def as_int(x):
    return x.as_int()
