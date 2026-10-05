"""crockford-base32-pure - Douglas Crockford's Base32 v1 (pure Python, stdlib-only).

A faithful pure-Python implementation of the encoding described at
https://www.crockford.com/base32.html (Douglas Crockford, 2019-03-04).
The 32-symbol alphabet ``0123456789ABCDEFGHJKMNPQRSTVWXYZ`` excludes the
confusable letters ``I L O U``. Decode accepts upper- and lower-case
input, treats ``I`` / ``L`` as ``1`` and ``O`` as ``0``, and strips
hyphens. A single-character mod-37 check symbol may be appended
optionally (using the five extended symbols ``* ~ $ = U`` for
check values 32..36).

No third-party dependencies. No CLI surface. Library total over
arbitrary input: hostile types and out-of-range values raise
``CrockfordBase32Error`` (a ``ValueError`` subclass) with a machine-
readable ``code`` and ``details`` dict.

Public API
----------

- :func:`encode`        - bytes (or non-negative int) -> Crockford Base32
- :func:`decode`        - Crockford Base32 -> bytes
- :func:`encode_int`    - non-negative int -> Crockford Base32
- :func:`checksum_symbol`   - compute the mod-37 check symbol
- :func:`validate_checksum` - validate the trailing check symbol
- :func:`version`       - the spec version string ("1.0", 2019-03-04)
"""

from ._alphabet import (
    ALPHABET,
    EXTENDED,
    encode_check_value,
    encode_value,
    lookup_body,
    lookup_check,
)
from ._errors import CrockfordBase32Error

__all__ = [
    "ALPHABET",
    "EXTENDED",
    "CrockfordBase32Error",
    "checksum_symbol",
    "decode",
    "encode",
    "encode_int",
    "validate_checksum",
    "version",
]

__version__ = "0.1.0"
_SPEC_VERSION = "1.0"  # matches spec date 2019-03-04


def version() -> str:
    """Return the spec version this library implements.

    Returns the literal string ``"1.0"`` (the spec is dated 2019-03-04
    and has no other revision tag).
    """
    return _SPEC_VERSION


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _bad_type(param: str, got: object) -> "CrockfordBase32Error":
    return CrockfordBase32Error(
        "invalid_type",
        f"{param!r} must be bytes or int, got {type(got).__name__}",
        parameter=param,
        got_type=type(got).__name__,
    )


def _is_str(x: object) -> bool:
    # Avoid importing the str/bytes distinction from builtins via isinstance
    # in case the host has shadowed builtins. Keep the check explicit.
    return isinstance(x, str)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def encode(
    data,
    *,
    checksum: bool = False,
) -> str:
    """Encode ``data`` as a Crockford Base32 string.

    Parameters
    ----------
    data:
        ``bytes`` / ``bytearray`` / ``memoryview`` for the bytes
        path, or a non-negative ``int`` for the integer path. Other
        types raise :class:`CrockfordBase32Error` with code
        ``"invalid_type"``.
    checksum:
        If ``True``, append the single-character mod-37 check symbol
        to the output. Defaults to ``False``.

    Returns
    -------
    str
        The Crockford Base32 representation. Empty input returns the
        empty string ``""``. Integer ``0`` returns ``"0"``.

    Raises
    ------
    CrockfordBase32Error
        With code ``"invalid_type"`` for unsupported types or
        ``"negative_integer"`` for negative ints.
    """
    # Bytes-like path
    if isinstance(data, (bytes, bytearray, memoryview)):
        bytes_data = bytes(data)
        return _encode_bytes(bytes_data, checksum=checksum)
    # Integer path
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
    """Encode a non-negative integer as Crockford Base32.

    The integer is rendered LSQ-first / MSB-last, like ordinary base-32
    with no leading zeros (except the special case ``encode_int(0) =
    "0"``).

    Parameters
    ----------
    n:
        Non-negative integer. Negative values raise
        :class:`CrockfordBase32Error` with code ``"negative_integer"``.
    checksum:
        If ``True``, append the mod-37 check symbol. Defaults to
        ``False``.

    Returns
    -------
    str
        The Crockford Base32 representation of the integer.
    """
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
    return body + checksum_symbol(body)


def _encode_bytes(data: bytes, *, checksum: bool) -> str:
    """MSB-first bit accumulator (the spec's bytes-to-base32 path)."""
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
    return body + checksum_symbol(body)


def decode(s: str, *, checksum: bool = False) -> bytes:
    """Decode a Crockford Base32 string to bytes.

    Accepts upper- and lower-case input, treats ``I`` / ``L`` as ``1``,
    ``O`` as ``0``, and strips hyphens. Trailing bits that don't
    fill a complete byte are discarded (this is per the spec's
    MSB-first bit accumulator; the bytes path is not lossless for
    inputs whose bit length is not a multiple of 8).

    Parameters
    ----------
    s:
        The Crockford Base32 string to decode. Must be a ``str``;
        any other type raises :class:`CrockfordBase32Error` with
        code ``"invalid_type"``.
    checksum:
        If ``True``, the last character is interpreted as the mod-37
        check symbol and validated against the body. A mismatched
        check raises code ``"check_mismatch"``.

    Returns
    -------
    bytes
        The decoded byte string. May be empty (``b""``) when the
        input has fewer than 8 bits of payload.

    Raises
    ------
    CrockfordBase32Error
        On invalid character, ``U`` in main body, extended symbol
        in main body, mismatched check symbol, etc. All instances
        carry a ``code`` and ``details`` dict.
    """
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
            # Distinguish 'U' (check-only) from the extended set from
            # truly invalid characters.
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
                    f"extended check symbol {c!r} is not valid in "
                    "the main body of a symbol string",
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
        # Recompute the check symbol from the (hyphen-stripped) body
        # and compare against the trailing check character.
        body_for_checksum = body_str
        expected = checksum_symbol(body_for_checksum)
        if expected != check_char:
            raise CrockfordBase32Error(
                "check_mismatch",
                "check symbol does not match the body",
                expected=expected,
                got=check_char,
            )

    return bytes(out)


def checksum_symbol(s: str) -> str:
    """Compute the single-character mod-37 check symbol for ``s``.

    Hyphens are stripped before computation. The check value is the
    body interpreted as a base-32 number, taken modulo 37; values
    0..31 map to the Crockford alphabet, values 32..36 map to the
    five extended symbols ``* ~ $ = U``.

    Parameters
    ----------
    s:
        The body string (without a check symbol). Must be a ``str``
        whose characters are all valid Crockford main-body symbols.
        The empty string is accepted and yields ``"0"``.

    Returns
    -------
    str
        A single-character string with the check symbol.

    Raises
    ------
    CrockfordBase32Error
        With code ``"invalid_type"`` if ``s`` is not a ``str``, or
        ``"invalid_character"`` / ``"u_in_main_body"`` /
        ``"extended_in_main_body"`` for invalid body characters.
    """
    if not _is_str(s):
        raise _bad_type("s", s)
    body = s.replace("-", "")
    n = 0
    for c in body:
        v = lookup_body(c)
        if v < 0:
            ext_val = lookup_check(c)
            if c in ("U", "u"):
                raise CrockfordBase32Error(
                    "u_in_main_body",
                    "the letter U is reserved for the check-symbol "
                    "position and is not valid in the body",
                    character=c,
                )
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


def validate_checksum(s: str) -> bool:
    """Return True iff the trailing check symbol of ``s`` is valid.

    Per Invariant 21 this function is total: it returns ``False`` for
    any invalid input (wrong type, empty string, missing check, body
    containing invalid characters, mismatched check symbol) rather
    than raising.

    Parameters
    ----------
    s:
        A Crockford symbol string whose last character is the check
        symbol (i.e. the format produced by
        ``encode(..., checksum=True)``).

    Returns
    -------
    bool
        ``True`` if the trailing check symbol matches the body,
        ``False`` otherwise.
    """
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
