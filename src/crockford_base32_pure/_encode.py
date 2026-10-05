"""Encoding helpers for crockford-base32-pure."""

from ._alphabet import ALPHABET
from ._errors import CrockfordBase32Error


def _bad_type(param: str, got: object) -> "CrockfordBase32Error":
    return CrockfordBase32Error(
        "invalid_type",
        f"{param!r} must be bytes or int, got {type(got).__name__}",
        parameter=param,
        got_type=type(got).__name__,
    )


def encode(
    data,
    *,
    checksum: bool = False,
) -> str:
    """Encode ``data`` as a Crockford Base32 string.

    ``data`` is ``bytes``/``bytearray``/``memoryview`` or a non-negative
    ``int``. Other types raise ``CrockfordBase32Error`` with code
    ``"invalid_type"``.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return _encode_bytes(bytes(data), checksum=checksum)
    if isinstance(data, int) and not isinstance(data, bool):
        if data < 0:
            raise CrockfordBase32Error(
                "negative_integer",
                "encode() requires a non-negative integer for the int path",
                value=data,
            )
        return encode_int(data, checksum=checksum)
    raise _bad_type("data", data)


def encode_int(n: int, *, checksum: bool = False) -> str:
    """Encode a non-negative integer as Crockford Base32 (LSQ-first, no
    leading zeros). Negative ints raise ``CrockfordBase32Error``."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise _bad_type("n", n)
    if n < 0:
        raise CrockfordBase32Error(
            "negative_integer",
            "encode_int() requires a non-negative integer",
            value=n,
        )
    if n == 0:
        body = "0"
    else:
        digits = []
        v = n
        while v > 0:
            digits.append(ALPHABET[v & 0x1F])
            v >>= 5
        body = "".join(reversed(digits))
    if not checksum:
        return body
    from ._decode import checksum_symbol
    return body + checksum_symbol(body)


def _encode_bytes(data: bytes, *, checksum: bool) -> str:
    """MSB-first bit accumulator (spec's bytes→Base32 path)."""
    bits = 0
    value = 0
    out: list[str] = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(value >> bits) & 0x1F])
    if bits > 0:
        out.append(ALPHABET[(value << (5 - bits)) & 0x1F])
    body = "".join(out)
    if not checksum:
        return body
    from ._decode import checksum_symbol
    return body + checksum_symbol(body)
