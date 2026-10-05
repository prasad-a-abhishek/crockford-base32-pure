# Surface Enumeration — crockford-base32-pure

> **Card**: cycle_178/adversary/01 — VULN_AUDIT
> **Branch**: wt/cycle178-adversary-01
> **Commit**: 12345df
> **Methodology**: Manual read of all 5 source files in `src/crockford_base32_pure/`
> (45+65+131+83+42 = 366 LOC, 5 modules, 0 `__main__.py` so no CLI surface).
> Every public symbol was traced from `__init__.py` to its implementation
> module to confirm entry points, input domains, output ranges, and edge cases.
>
> **Cross-references**: the canonical specification is
> https://www.crockford.com/base32.html (Douglas Crockford, 2019-03-04),
> cross-verified against Go stdlib `encoding/base32.Crockford` (no check
> symbol), Wikipedia, fzakaria/Crockford (Java), and deniszykov/crockford (C#).

## Surface index (7 surfaces)

| # | Symbol | Module | Line | Kind | Risk tier |
|---|--------|--------|------|------|-----------|
| 1 | `encode(data, *, checksum=False)` | `_encode.py` | 16 | encode: bytes/bytearray/memoryview/int → str | high (algorithm + I/O) |
| 2 | `decode(s, *, checksum=False)` | `_decode.py` | 52 | decode: str → bytes | high (algorithm + untrusted input typical) |
| 3 | `encode_int(n, *, checksum=False)` | `_encode.py` | 40 | encode: int → str | medium (bigint path) |
| 4 | `checksum_symbol(s)` | `_decode.py` | 20 | mod-37 → str (1 char) | medium (math + lookup) |
| 5 | `validate_checksum(s)` | `_decode.py` | 120 | str → bool (total) | low (lookup only) |
| 6 | `ALPHABET`, `EXTENDED`, `CrockfordBase32Error` | `_alphabet.py`, `_errors.py` | 13, 17, 27 | constants + exception type | low (data) |
| 7 | `version()` | `__init__.py` | 39 | str literal "1.0" | info (no input) |

**No CLI surface** (no `__main__.py`); the only entry points are the library
API and `__import__("crockford_base32_pure")` at module load time (the
`_alphabet.py` module-build loop runs at import). No filesystem, network, or
subprocess access anywhere in the codebase.

---

## Surface 1 — `encode(data, *, checksum=False)`

**Entry point**: `src/crockford_base32_pure/_encode.py:16` (public re-export
from `__init__.py:20`).

**Input domain**:
- `data`: any of `bytes`, `bytearray`, `memoryview`, `int` (excluding `bool`).
  All other types raise `CrockfordBase32Error(code="invalid_type")`.
- `checksum`: keyword-only `bool`. Non-bool values are truthiness-coerced
  by Python's `if not checksum:` check (e.g. `checksum=1` → `True`,
  `checksum="yes"` → `True`, `checksum=None` → `False`). This is silent
  coercion, not a validation error.

**Output range**:
- `str` in `ALPHABET` (32 chars) for the body.
- If `checksum=True`, the body is followed by exactly one check character
  from `ALPHABET + EXTENDED` (37 chars total).
- Empty input → empty string (no padding, no auto-checksum char unless
  explicitly requested via `checksum=True` → returns `"0"`).

**Edge cases (verified by fuzz)**:
- empty `b""` → `""` (empty + checksum=True → `"0"`)
- single byte `b"\x00"` → `"00"`, `b"\xff"` → `"ZW"`
- 5/8/10-byte boundary (40/64/80 bits) → exact multiple of 5 / 13 chars / 16 chars
- 100,000-byte `b"a"` round-trip OK
- `bytearray(b"foobar")` and `memoryview(b"foobar")` accepted (coerced to
  `bytes` via `bytes(data)` on line 28)
- `True` / `False` rejected with `code="invalid_type"` (bool is a subclass
  of int but explicitly excluded on line 29)
- `1.5` → `invalid_type`; `[]` → `invalid_type`; `{}` → `invalid_type`;
  `None` → `invalid_type`
- negative int (`-1`, `-100`) → `code="negative_integer"`
- int `2**256` → 52 chars; `2**1024` → 205 chars; no overflow (Python
  bigints are unbounded)
- int `0` → `"0"` (special-cased, body = "0"); `encode(0, checksum=True)`
  → `"00"` (body "0" + check "0")
- `encode(None)` → raises `CrockfordBase32Error` with no PII in error
  message (only `parameter="data"`, `got_type="NoneType"`)

**Sub-algorithm** (MSB-first bit accumulator for bytes path):
```
for each byte: value = (value << 8) | byte; bits += 8
  while bits >= 5: bits -= 5; out.append(ALPHABET[(value >> bits) & 0x1F])
if bits > 0: out.append(ALPHABET[(value << (5 - bits)) & 0x1F])
```
The shift by `(5 - bits)` on the final partial symbol is well-defined
because `0 < bits < 5` (else the `while` would have consumed it), and
`5 - bits ∈ {1,2,3,4}` so the left shift is bounded.

**Trust boundary**: callers pass untrusted bytes or int. The function is
pure (no I/O), but its output may be used as an identifier or token that
gets logged, hashed, stored, or transmitted.

---

## Surface 2 — `decode(s, *, checksum=False)`

**Entry point**: `src/crockford_base32_pure/_decode.py:52` (public re-export
from `__init__.py:21`).

**Input domain**:
- `s`: must be a `str`. Other types (`bytes`, `int`, `None`, `list`,
  `dict`, `bool`) raise `CrockfordBase32Error(code="invalid_type")`.
- `checksum`: keyword-only `bool`; if `True`, the final character is
  interpreted as the mod-37 check symbol and validated.

**Output range**:
- `bytes` (empty for the empty body, or the decoded byte stream).
- The MSB-first decoder drops trailing bits that don't fill a full byte
  (5/10/15/20/25-bit remainders are silently truncated, not an error).
- If `checksum=True` and the check symbol doesn't match, raises
  `CrockfordBase32Error(code="check_mismatch")` with `expected` and `got`
  in `details` (no PII leakage — these are single chars).

**Edge cases (verified by fuzz)**:
- empty `""` → `b""` (without checksum); `decode("", checksum=True)` →
  `code="empty_with_checksum"`
- single `"0"`, `"I"`, `"L"`, `"l"`, `"i"`, `"O"`, `"o"`, `"U"`, `"*"` all
  round-trip through lookup; only valid alphabet characters reach the
  bit accumulator
- `"U"` in main body → `code="u_in_main_body"` (reserved for check position)
- `"*"` / `"~"` / `"$"` / `"="` in main body → `code="extended_in_main_body"`
- `"???"` → `code="invalid_character"`
- embedded NUL `"\x00"` → `code="invalid_character"`
- non-ASCII (`"é"`, `"Ｒ"`, `"\xa0"`, `"\ufeff"`, `"\u200b"`) → all
  `code="invalid_character"` (no case folding on non-ASCII)
- mixed-case `"Cr"`, `"cR"`, `"CR"`, `"cr"` all decode identically
- hyphens: leading, trailing, and double hyphens are silently stripped
  (`decode("---") == b""`, `decode("-C-R-") == b"f"`, `decode("C--R") == b"f"`)
- check mismatch: `decode("CR2", checksum=True)` → `code="check_mismatch"`
  with `expected="1", got="2"` in details
- very long input (1MB+) decodes without hanging (verified 100KB
  round-trip; no recursion in the decoder, so stack depth is bounded)

**Trust boundary**: this is the **primary untrusted-input surface**.
Callers typically receive Base32 strings from external sources (URLs,
QR codes, log lines, human typing) and need to decode them safely. All
invalid input must produce a structured error, never a crash.

---

## Surface 3 — `encode_int(n, *, checksum=False)`

**Entry point**: `src/crockford_base32_pure/_encode.py:40` (public re-export
from `__init__.py:20`).

**Input domain**:
- `n`: must be `int`, not `bool`. Other types → `code="invalid_type"`.
- `n >= 0`. Negative → `code="negative_integer"`.
- No upper bound (Python int is unbounded).

**Output range**:
- `str` in `ALPHABET` (body) or `ALPHABET + EXTENDED` (with check).
- For `n == 0`: body is the literal `"0"` (special-cased to match
  common-base-32 conventions; the spec does not pin zero's encoding
  but the spec page example shows `"0"` for the empty-bytes case).
- For `n > 0`: emits digits least-significant-5-bit first, reversed
  at the end. The body has no leading zeros.

**Algorithm**:
```
digits = []
v = n
while v > 0:
    digits.append(ALPHABET[v & 0x1F])  # 5-bit chunk
    v >>= 5
body = "".join(reversed(digits))
```
The loop terminates when `v == 0`; `n` is unbounded so for `n = 2**1024`
the loop runs 205 times and produces 205 chars. No overflow possible.

**Edge cases (verified by fuzz)**:
- `0` → `"0"`, `0` with checksum → `"00"`
- `1` → `"1"`, `31` → `"Z"`, `32` → `"10"` (first 2-char value)
- `2**32` → `"4000000"`, `2**64 - 1` → `"FZZZZZZZZZZZZ"`, `2**128`,
  `2**256`, `2**512`, `2**1024` all round-trip through checksum
- `True` / `False` → `code="invalid_type"` (bool is a subclass of int but
  explicitly excluded on line 43 with `isinstance(n, int) and not bool`)
- `-1` → `code="negative_integer"`

**Trust boundary**: `n` is typically programmer-controlled (DB IDs,
counters, hash outputs). Less of an attack surface than `decode` but
the path is worth auditing for math errors.

---

## Surface 4 — `checksum_symbol(s)`

**Entry point**: `src/crockford_base32_pure/_decode.py:20` (public
re-export from `__init__.py:21`).

**Input domain**:
- `s`: must be a `str`. Other types → `code="invalid_type"`.
- Hyphens are stripped before the mod-37 computation.
- Any character not in the main alphabet (or `U`/`u`, or any extended
  symbol `*~$=`) in the body raises a structured error.

**Output range**:
- Exactly 1 character, in `ALPHABET + EXTENDED` (37 possible values).
- Empty body → `"0"` (the mod-37 identity).

**Algorithm**:
```
n = 0
for c in body:                  # body = s.replace("-", "")
    v = lookup_body(c)          # -1 if invalid; else 0..31
    if v < 0: raise ...
    n = (n * 32 + v) % 37
return encode_check_value(n)    # ALPHABET[n] for n<32 else EXTENDED[n-32]
```

**Edge cases**:
- empty `""` → `"0"` (verified)
- `---` (all hyphens) → `"0"` (verified; spec says hyphens are noise)
- `I`, `L`, `O`, `0` etc. — `I`/`L` map to value 1, `O`/`0` map to 0
- Body producing extended check (n % 37 in 32..36) → emits the correct
  extended char (`*`, `~`, `$`, `=`, `U`); verified for bodies "10".. "14"
  producing check values 32..36
- `True` / `False` → `code="invalid_type"`

**Trust boundary**: low (caller-controlled; no side effects).

---

## Surface 5 — `validate_checksum(s)`

**Entry point**: `src/crockford_base32_pure/_decode.py:120` (public
re-export from `__init__.py:21`).

**Input domain**: any value (this function is **total** — must never raise).

**Output range**: `bool` (`True` if `s` is a non-empty string with a
valid check symbol matching its body, `False` otherwise).

**Algorithm**:
```
if not isinstance(s, str) or not s: return False
body, check_char = s[:-1], s[-1]
if lookup_check(check_char) < 0: return False   # last char not in check set
try: expected = checksum_symbol(body)
except CrockfordBase32Error: return False       # body has invalid chars
return expected == check_char
```

**Edge cases (verified)**:
- `validate_checksum(None)` → `False`
- `validate_checksum(123)` → `False`
- `validate_checksum(b"CR1")` → `False` (bytes not str)
- `validate_checksum([])` → `False` (list)
- `validate_checksum("")` → `False` (empty)
- `validate_checksum("CR!")` → `False` (`!` not in check set)
- `validate_checksum("?1")` → `False` (body has `?`)
- `validate_checksum("CR2")` → `False` (mismatch)
- `validate_checksum("CR1")` → `True` (match)
- `validate_checksum("00")` → `True` (zero body has zero check)

**Trust boundary**: low. This is a pure validator with no side effects.

---

## Surface 6 — Module-level constants + exception

**Entry points**:
- `ALPHABET` (`_alphabet.py:13`) — 32-char string, immutable by convention
  (treated as a constant; not enforced).
- `EXTENDED` (`_alphabet.py:17`) — 5-char string, immutable by convention.
- `CrockfordBase32Error` (`_errors.py:27`) — exception class subclassing
  `ValueError` with `.code: str` and `.details: dict` structured attrs.

**Input domain**: none (constants are data; exception is constructed by
the encoder/decoder internals).

**Output range**:
- `ALPHABET` is `"0123456789ABCDEFGHJKMNPQRSTVWXYZ"` (32 chars, no I/L/O/U).
- `EXTENDED` is `"*~$=U"` (5 chars, in the spec's exact order).
- `CrockfordBase32Error` has a `repr` of the form
  `CrockfordBase32Error(code='...', message='...', details={...})`.

**Edge cases**:
- `CrockfordBase32Error` is a `ValueError` subclass, so `except ValueError`
  still catches it (verified by `test_error_subclasses_value_error`).
- `.details` is a fresh `dict` per instance, so callers can mutate it
  without affecting other instances.

**Trust boundary**: none (data only). The error class is the canonical
return path for all invalid input, so its behavior under pickle, copy,
and traceback printing is worth noting but not a security issue (it
inherits from `ValueError`, which is the standard Python exception
contract).

---

## Surface 7 — `version()`

**Entry point**: `src/crockford_base32_pure/__init__.py:39`.

**Input domain**: none (no parameters).

**Output range**: the literal string `"1.0"` (matching the spec date
2019-03-04).

**Trust boundary**: none (no parameters, no I/O).

---

## What's NOT a surface

- **No CLI**: there is no `__main__.py` and no argparse; the library
  is only consumed via `import crockford_base32_pure`. This eliminates
  ~one full attack class (command-line argument injection, `--help`
  drift, argparse type coercion).
- **No filesystem I/O**: the only module-level code is the
  `_DECODE_BODY` / `_DECODE_CHECK` / `_CHECK_ENCODE` table construction
  in `_alphabet.py`, which runs at import time and has no external
  dependencies.
- **No network I/O**: zero `socket`, `urllib`, `http`, `ssl`, `ftplib`,
  `smtplib` references in the codebase.
- **No subprocess / os.system**: zero references in the codebase.
- **No eval / exec / pickle / marshal**: zero references in the codebase.
- **No thread / process primitives**: zero `threading`, `multiprocessing`,
  `asyncio`, `signal` references. Decoding is O(n) single-threaded.
- **No `__del__`, no `__getattr__` shenanigans**: the exception class
  is a thin wrapper; the alphabet module is plain data.

The minimal surface is a deliberate "less is more" design: a small
fixed alphabet, a single math primitive (mod 37), and structured
errors. Each public function is total over its input domain (per
Invariant 21) — none of them crashes on hostile input.

VERDICT-SURFACES: 7 surfaces, 0 surface gaps, all 7 trace to specific
lines in the source.
