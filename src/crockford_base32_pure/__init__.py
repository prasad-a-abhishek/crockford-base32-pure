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
"""

from ._alphabet import ALPHABET, EXTENDED
from ._errors import CrockfordBase32Error
from ._encode import encode, encode_int
from ._decode import checksum_symbol, decode, validate_checksum

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
