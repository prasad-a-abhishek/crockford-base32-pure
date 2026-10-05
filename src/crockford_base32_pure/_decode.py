"""Decoding helpers for crockford-base32-pure."""

from ._alphabet import ALPHABET, EXTENDED, lookup_body, lookup_check, encode_check_value
from ._errors import CrockfordBase32Error


def _is_str(x: object) -> bool:
    return isinstance(x, str)


def _bad_type(param: str, got: object) -> "CrockfordBase32Error":
    return CrockfordBase32Error(
        "invalid_type",
        f"{param!r} must be bytes or int, got {type(got).__name__}",
        parameter=param,
        got_type=type(got).__name__,
    )


def checksum_symbol(s: str) -> str:
    """Compute the mod-37 check symbol for ``s``."""
    if not _is_str(s):
        raise _bad_type("s", s)
    body = s.replace("-", "")
    n = 0
    for c in body:
        v = lookup_body(c)
        if v < 0:
            if c in ("U", "u"):
                raise CrockfordBase32Error(
                    "u_in_main_body",
                    "the letter U is reserved for the check-symbol "
                    "position and is not valid in the body",
                    character=c,
                )
            ext_val = lookup_check(c)
            if ext_val >= 0:
                raise CrockfordBase32Error(
                    "extended_in_main_body",
                    f"extended check symbol {c!r} is not valid in the body",
                    character=c,
                )
            raise CrockfordBase32Error(
                "invalid_character",
                f"invalid Crockford symbol in body: {c!r}",
                character=c,
            )
        n = (n * 32 + v) % 37
    return encode_check_value(n)


def decode(s: str, *, checksum: bool = False) -> bytes:
    """Decode a Crockford Base32 string."""
    if not _is_str(s):
        raise _bad_type("s", s)

    if checksum:
        if not s:
            raise CrockfordBase32Error(
                "empty_with_checksum",
                "decode(..., checksum=True) requires a non-empty string",
            )
        body_str, check_char = s[:-1], s[-1]
        check_val = lookup_check(check_char)
        if check_val < 0:
            raise CrockfordBase32Error(
                "invalid_check_symbol",
                f"invalid check symbol: {check_char!r}",
                character=check_char,
            )
    else:
        body_str, check_char = s, None
        check_val = -1

    body_str = body_str.replace("-", "")
    bits = 0
    value = 0
    out = bytearray()
    for c in body_str:
        v = lookup_body(c)
        if v < 0:
            ext_val = lookup_check(c)
            if c in ("U", "u"):
                raise CrockfordBase32Error(
                    "u_in_main_body",
                    "the letter U is reserved for the check-symbol "
                    "position and is not valid in the main body",
                    character=c,
                )
            if ext_val >= 0:
                raise CrockfordBase32Error(
                    "extended_in_main_body",
                    f"extended check symbol {c!r} is not valid in the main body",
                    character=c,
                )
            raise CrockfordBase32Error(
                "invalid_character",
                f"invalid Crockford symbol in main body: {c!r}",
                character=c,
            )
        value = (value << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)

    if checksum:
        expected = checksum_symbol(body_str)
        if expected != check_char:
            raise CrockfordBase32Error(
                "check_mismatch",
                "check symbol does not match the body",
                expected=expected,
                got=check_char,
            )

    return bytes(out)


def validate_checksum(s: str) -> bool:
    """Return ``True`` if the trailing check symbol of ``s`` is valid."""
    if not _is_str(s) or not s:
        return False
    body, check_char = s[:-1], s[-1]
    if lookup_check(check_char) < 0:
        return False
    try:
        expected = checksum_symbol(body)
    except CrockfordBase32Error:
        return False
    return expected == check_char
