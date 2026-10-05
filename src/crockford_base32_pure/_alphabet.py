"""Crockford Base32 v1 alphabet tables (Douglas Crockford, 2019-03-04).

Reference: https://www.crockford.com/base32.html

The 32-symbol Crockford alphabet intentionally excludes the four
confusable letters I, L, O, U. Decode substitutes I/L -> 1 and O -> 0;
hyphens are treated as noise and stripped. The letter U and the five
extended check symbols * ~ $ = are reserved for the check-symbol
position only; they are rejected in the main body of a symbol string.
"""

# The 32-symbol Crockford alphabet in value order (index = value 0..31).
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Five extra symbols for check values 32..36. Used ONLY in the
# check-symbol position per the spec's Check section.
EXTENDED = "*~$=U"

# Decode table for the main body. Case-insensitive. I, L, i, l all
# decode to 1; O, o decode to 0. Hyphens are stripped before lookup.
# All other ASCII characters not listed raise decode error.
_DECODE_BODY: dict[str, int] = {}
for _i, _c in enumerate(ALPHABET):
    _DECODE_BODY[_c] = _i
    _DECODE_BODY[_c.lower()] = _i
_DECODE_BODY["I"] = 1
_DECODE_BODY["i"] = 1
_DECODE_BODY["L"] = 1
_DECODE_BODY["l"] = 1
_DECODE_BODY["O"] = 0
_DECODE_BODY["o"] = 0

# Decode table for the check-symbol position. Same as body plus the
# five extended symbols (and their lowercase variants, which the
# main body does NOT accept).
_DECODE_CHECK: dict[str, int] = dict(_DECODE_BODY)
for _i, _c in enumerate(EXTENDED):
    _DECODE_CHECK[_c] = 32 + _i
    _DECODE_CHECK[_c.lower()] = 32 + _i

# Reverse map for check-symbol encoding: int 0..36 -> single character.
_CHECK_ENCODE: str = ALPHABET + EXTENDED


def lookup_body(c: str) -> int:
    """Look up a main-body character. Returns the 5-bit value, or -1
    if the character is not a valid main-body symbol."""
    return _DECODE_BODY.get(c, -1)


def lookup_check(c: str) -> int:
    """Look up a check-position character. Returns the value 0..36,
    or -1 if the character is not a valid check symbol."""
    return _DECODE_CHECK.get(c, -1)


def encode_value(v: int) -> str:
    """Encode a 5-bit value (0..31) to its Crockford alphabet symbol."""
    return ALPHABET[v & 0x1F]


def encode_check_value(v: int) -> str:
    """Encode a check value (0..36) to its single character (alphabet
    or extended)."""
    return _CHECK_ENCODE[v % 37]
