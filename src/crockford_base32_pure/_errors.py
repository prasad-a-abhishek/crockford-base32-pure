"""Structured errors for crockford-base32-pure.

Per Invariant 21 of the repo-factory contract, every public function
must be total over arbitrary input. Invalid inputs raise a
``CrockfordBase32Error`` (a single structured exception type) with
a descriptive ``code`` and a ``details`` dict so callers can
distinguish failure modes programmatically. Common codes:

- ``"empty_input"`` - empty bytes/str where non-empty is required
- ``"invalid_type"`` - wrong type for the parameter
- ``"negative_integer"`` - encode() got a negative int
- ``"invalid_character"`` - decode() saw a character outside the
  Crockford alphabet and the extended check set
- ``"u_in_main_body"`` - decode() saw ``U`` / ``u`` in the main
  body (reserved for the check-symbol position)
- ``"extended_in_main_body"`` - decode() saw ``*`` / ``~`` / ``$`` /
  ``=`` in the main body (reserved for the check-symbol position)
- ``"invalid_check_symbol"`` - decode(..., checksum=True) got a
  trailing character that isn't in the check set
- ``"check_mismatch"`` - decode(..., checksum=True) got a check
  symbol that does not match the body
- ``"empty_with_checksum"`` - decode(..., checksum=True) got an
  empty string
"""


class CrockfordBase32Error(ValueError):
    """Total-safety exception for invalid Crockford Base32 input.

    Subclasses ``ValueError`` so existing code that catches
    ``ValueError`` continues to work, while also carrying a
    machine-readable ``code`` and ``details`` dict for callers
    that want to handle specific failure modes.
    """

    def __init__(self, code: str, message: str, **details):
        super().__init__(message)
        self.code = code
        self.details: dict = dict(details)

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"CrockfordBase32Error(code={self.code!r}, message={str(self)!r}, details={self.details!r})"
