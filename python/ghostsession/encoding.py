"""Strict JSON, RFC 8785 JCS, canonical base64url, and ID rules (spec §3).

Byte-identical to the TypeScript implementation: same rejections, same key
ordering (UTF-16 code units), same number domain (non-negative safe ints).
"""

from __future__ import annotations

import base64
import json
import re
import secrets

from .errors import B64Error, JcsError, StrictJsonError

MAX_JSON_DEPTH = 32
MAX_SAFE_UINT = 9007199254740991

ID_SUFFIX_LENGTH = 21
ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"
ID_PREFIXES = (
    "gs", "gt", "gd", "ga", "gr", "gl", "go", "gh", "gv", "gk", "ge", "gq",
)
_PREFIX_SET = frozenset(ID_PREFIXES)


def _has_lone_surrogate(s: str) -> bool:
    i = 0
    while i < len(s):
        c = ord(s[i])
        if 0xD800 <= c <= 0xDBFF:
            if i + 1 >= len(s) or not 0xDC00 <= ord(s[i + 1]) <= 0xDFFF:
                return True
            i += 2
            continue
        if 0xDC00 <= c <= 0xDFFF:
            return True
        i += 1
    return False


def _check_depth(v, depth: int) -> None:
    if depth > MAX_JSON_DEPTH:
        raise StrictJsonError("depth limit exceeded")
    if isinstance(v, dict):
        for x in v.values():
            _check_depth(x, depth + 1)
    elif isinstance(v, list):
        for x in v:
            _check_depth(x, depth + 1)


def _reject_constant(value: str):
    raise StrictJsonError(f"non-finite literal {value}")


def _parse_int(lexeme: str) -> int:
    if lexeme.startswith("-"):
        raise StrictJsonError("negative number")  # covers -0
    v = int(lexeme)
    if v > MAX_SAFE_UINT:
        raise StrictJsonError("number out of range")
    return v


def _parse_float(lexeme: str):
    # Non-integral values are not part of the protocol number domain.
    f = float(lexeme)
    if f.is_integer() and 0 <= f <= MAX_SAFE_UINT:
        raise StrictJsonError("integral floats must be written as integers")
    raise StrictJsonError("non-integral number")


def _object_pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise StrictJsonError("duplicate object key")
        out[k] = v
    return out


def strict_loads(raw: bytes | str):
    """Parse JSON with protocol rules: UTF-8, no BOM, no duplicate keys,
    no lone surrogates, non-negative safe integers only, depth <= 32."""
    if isinstance(raw, (bytes, bytearray)):
        buf = bytes(raw)
        if buf[:3] == b"\xef\xbb\xbf":
            raise StrictJsonError("BOM rejected")
        try:
            src = buf.decode("utf-8")
        except UnicodeDecodeError as e:
            raise StrictJsonError("invalid UTF-8") from e
    else:
        src = raw
    try:
        value = json.loads(
            src,
            object_pairs_hook=_object_pairs,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except StrictJsonError:
        raise
    except json.JSONDecodeError as e:
        raise StrictJsonError(str(e)) from e
    except RecursionError as e:
        raise StrictJsonError("depth limit exceeded") from e
    for s in _iter_strings(value):
        if _has_lone_surrogate(s):
            raise StrictJsonError("lone surrogate in string")
    _check_depth(value, 0)
    return value


def _iter_strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from _iter_strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _iter_strings(x)


_ESCAPES = {0x22: '\\"', 0x5C: "\\\\", 0x08: "\\b", 0x09: "\\t",
            0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}


def _escape_string(s: str, out: list[str]) -> None:
    out.append('"')
    for ch in s:
        c = ord(ch)
        esc = _ESCAPES.get(c)
        if esc is not None:
            out.append(esc)
        elif c < 0x20:
            out.append("\\u%04x" % c)
        else:
            out.append(ch)
    out.append('"')


def _utf16_order_key(k: str) -> bytes:
    # RFC 8785 sorts by UTF-16 code units, not Unicode code points.
    return k.encode("utf-16-be", "surrogatepass")


def _write(v, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif isinstance(v, bool):
        out.append("true" if v else "false")
    elif isinstance(v, int):
        if v < 0 or v > MAX_SAFE_UINT:
            raise JcsError("number not a safe non-negative integer")
        out.append(str(v))
    elif isinstance(v, float):
        raise JcsError("number not a safe non-negative integer")
    elif isinstance(v, str):
        _escape_string(v, out)
    elif isinstance(v, list):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _write(x, out)
        out.append("]")
    elif isinstance(v, dict):
        out.append("{")
        for i, k in enumerate(sorted(v.keys(), key=_utf16_order_key)):
            if i:
                out.append(",")
            _escape_string(k, out)
            out.append(":")
            _write(v[k], out)
        out.append("}")
    else:
        raise JcsError(f"unsupported value type {type(v).__name__}")


def jcs_str(value) -> str:
    """RFC 8785 canonical JSON text. No trailing newline."""
    out: list[str] = []
    _write(value, out)
    return "".join(out)


def jcs_bytes(value) -> bytes:
    return jcs_str(value).encode("utf-8")


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64_encode(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def b64_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL_RE.match(s):
        raise B64Error("invalid base64url characters")
    if "=" in s:
        raise B64Error("padding not permitted")
    pad = "=" * (-len(s) % 4)
    try:
        buf = base64.urlsafe_b64decode(s + pad)
    except Exception as e:
        raise B64Error("invalid base64url") from e
    if b64_encode(buf) != s:
        raise B64Error("non-canonical base64url")
    return buf


def is_canonical_b64(s: str) -> bool:
    try:
        b64_decode(s)
        return True
    except B64Error:
        return False


def is_valid_id(value, prefix: str | None = None) -> bool:
    if not isinstance(value, str):
        return False
    sep = value.find("_")
    if sep <= 0:
        return False
    p = value[:sep]
    if p not in _PREFIX_SET or (prefix is not None and p != prefix):
        return False
    suffix = value[sep + 1:]
    if len(suffix) != ID_SUFFIX_LENGTH:
        return False
    return all(ch in ID_ALPHABET for ch in suffix)


def new_id(prefix: str) -> str:
    """Nanoid-style ID: cryptographic rejection sampling over the 64-symbol
    alphabet, exactly as the TypeScript generator."""
    size = len(ID_ALPHABET)
    mask = 1
    while mask < size - 1:
        mask = (mask << 1) | 1
    bound = (256 // size) * size
    out: list[str] = []
    while len(out) < ID_SUFFIX_LENGTH:
        for b in secrets.token_bytes(ID_SUFFIX_LENGTH):
            if len(out) >= ID_SUFFIX_LENGTH:
                break
            m = b & mask
            if m < size and b < bound:
                out.append(ID_ALPHABET[m])
    return f"{prefix}_{''.join(out)}"
