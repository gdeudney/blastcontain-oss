"""Strict data-only wire records. Decoding never resolves or imports plugin code."""

from __future__ import annotations

import math
import types
from dataclasses import fields, is_dataclass
from typing import Any, Literal, Union, get_args, get_origin, get_type_hints


class ContractError(ValueError):
    """A contract is malformed or uses an unsupported schema version."""


def _json_data(value, path, parents=frozenset()):
    """Validate actual JSON types, without json.dumps coercing keys or tuples."""
    if type(value) in (str, int, bool, type(None)):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) not in (list, dict):
        raise ContractError(f"{path}: expected JSON data")
    if id(value) in parents:
        raise ContractError(f"{path}: cyclic JSON data")
    parents = parents | {id(value)}
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ContractError(f"{path}: JSON object keys must be strings")
        children = value.items()
    else:
        children = enumerate(value)
    for key, child in children:
        _json_data(child, f"{path}[{key!r}]", parents)


def _value(kind, value, path, wire=False):
    origin, args = get_origin(kind), get_args(kind)
    if origin in (Union, types.UnionType):
        for choice in args:
            try:
                return _value(choice, value, path, wire)
            except ContractError:
                pass
        raise ContractError(f"{path}: value does not match the declared type")
    if origin is Literal:
        if not any(type(value) is type(v) and value == v for v in args):
            raise ContractError(f"{path}: expected one of {args}")
    elif origin is tuple:
        if type(value) is not (list if wire else tuple):
            raise ContractError(f"{path}: expected {'array' if wire else 'tuple'}")
        return tuple(_value(args[0], v, f"{path}[{i}]", wire) for i, v in enumerate(value))
    elif origin is dict:
        if type(value) is not dict:
            raise ContractError(f"{path}: expected a JSON object")
        try:
            _json_data(value, path)
        except RecursionError as exc:
            raise ContractError(f"{path}: JSON data is too deeply nested") from exc
        if wire:
            return _encode(value)  # detach nested data from the caller's wire object
    elif isinstance(kind, type) and is_dataclass(kind):
        if wire:
            return kind.from_dict(value)
        if type(value) is not kind:
            raise ContractError(f"{path}: expected {kind.__name__}")
    elif kind is Any:
        return value
    elif type(value) is not kind:
        raise ContractError(f"{path}: expected {kind.__name__}")
    elif kind is float and not math.isfinite(value):
        raise ContractError(f"{path}: expected a finite number")
    return value


def _encode(value):
    if isinstance(value, WireRecord):
        return value.to_dict()
    if isinstance(value, (tuple, list)):
        return [_encode(v) for v in value]
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    return value


class WireRecord:
    """Subclasses are frozen dataclasses with explicitly versioned top-level records."""

    def __post_init__(self):
        kinds = get_type_hints(type(self))
        for f in fields(self):
            _value(kinds[f.name], getattr(self, f.name), f.name)
        self.validate()

    def validate(self):
        pass

    def to_dict(self):
        # Frozen records still contain mutable JSON objects. Revalidate at the
        # serialization boundary instead of claiming those objects are immutable.
        self.__post_init__()
        return {f.name: _encode(getattr(self, f.name)) for f in fields(self)}

    @classmethod
    def from_dict(cls, data):
        if type(data) is not dict or any(type(key) is not str for key in data):
            raise ContractError(f"{cls.__name__}: expected an object")
        allowed = {f.name for f in fields(cls)}
        unknown = set(data) - allowed
        if unknown:
            raise ContractError(f"{cls.__name__}: unknown fields {sorted(unknown)}")
        if "schema_version" in allowed and "schema_version" not in data:
            raise ContractError(f"{cls.__name__}: schema_version is required on the wire")
        kinds = get_type_hints(cls)
        try:
            return cls(**{k: _value(kinds[k], v, k, wire=True) for k, v in data.items()})
        except TypeError as exc:
            raise ContractError(f"{cls.__name__}: missing required fields") from exc


def require_text(value, name):
    if not value.strip():
        raise ContractError(f"{name} must not be blank")


def unique(values, name):
    if len(set(values)) != len(values):
        raise ContractError(f"{name} must be unique")
