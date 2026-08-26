from __future__ import annotations

from collections.abc import Callable
from typing import Any

Field = tuple[int, int, Any]


def _read_varint(data: bytes, i: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def decode_fields(data: bytes) -> list[Field]:
    fields: list[Field] = []
    i = 0
    n = len(data)
    while i < n:
        try:
            tag, i = _read_varint(data, i)
        except (IndexError, ValueError):
            break
        fn, wt = tag >> 3, tag & 7
        if fn == 0:
            break
        if wt == 0:
            try:
                v, i = _read_varint(data, i)
            except (IndexError, ValueError):
                break
            fields.append((fn, wt, v))
        elif wt == 2:
            try:
                ln, i = _read_varint(data, i)
            except (IndexError, ValueError):
                break
            if ln > n - i:
                break
            fields.append((fn, wt, bytes(data[i : i + ln])))
            i += ln
        elif wt == 5:
            if n - i < 4:
                break
            fields.append((fn, wt, data[i : i + 4]))
            i += 4
        elif wt == 1:
            if n - i < 8:
                break
            fields.append((fn, wt, data[i : i + 8]))
            i += 8
        else:
            break
    return fields


def first_bytes(fields: list[Field], num: int) -> bytes | None:
    for fn, wt, v in fields:
        if fn == num and wt == 2 and isinstance(v, (bytes, bytearray)):
            return bytes(v)
    return None


def first_string(fields: list[Field], num: int) -> str:
    for fn, wt, v in fields:
        if fn == num and wt == 2 and isinstance(v, (bytes, bytearray)):
            return bytes(v).decode("utf-8", "replace")
    return ""


def first_int(fields: list[Field], num: int) -> int | None:
    for fn, wt, v in fields:
        if fn == num and wt == 0:
            return int(v)
    return None


def all_bytes(fields: list[Field], num: int) -> list[bytes]:
    return [
        bytes(v)
        for fn, wt, v in fields
        if fn == num and wt == 2 and isinstance(v, (bytes, bytearray))
    ]


def navigate(raw: bytes, *path: int) -> list[Field]:
    data = raw
    for field_num in path:
        sub = first_bytes(decode_fields(data), field_num)
        if sub is None:
            return []
        data = sub
    return decode_fields(data)


def walk_find(data: bytes, match: Callable[[list[Field]], Any], depth: int = 0) -> list[Any]:
    found: list[Any] = []
    if depth > 12:
        return found
    try:
        fields = decode_fields(data)
    except Exception:
        return found
    m = match(fields)
    if m is not None:
        found.append(m)
    for _fn, wt, v in fields:
        if wt == 2 and isinstance(v, (bytes, bytearray)) and len(v) > 1:
            found.extend(walk_find(bytes(v), match, depth + 1))
    return found
