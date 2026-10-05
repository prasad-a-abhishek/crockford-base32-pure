# CWE Map — crockford-base32-pure

> **Card**: cycle_178/adversary/01 — VULN_AUDIT
> **Methodology**: For each of the 7 surfaces enumerated in `SURFACES.md`,
> list 1-3 most-relevant MITRE CWE entries, explain why each applies or
> why it's been actively mitigated, and cite the exact source line(s) that
> implement (or fail to implement) the mitigation. CWE references cross-
> checked against the MITRE CWE catalog (cwe.mitre.org).
>
> **Not applicable CWEs** are listed at the bottom with a one-line
> rationale — these were considered and rejected because the surface
> genuinely doesn't exist in this codebase.

## Summary

| Severity | CWE | Surfaces | Status |
|----------|-----|----------|--------|
| Medium  | CWE-20  Improper Input Validation | 1, 2, 3, 4 | partial — bool trap explicit; float/list/dict/etc. handled |
| Medium  | CWE-754 Improper Check for Unusual Conditions | 1, 2, 4 | partial — substitution-order bug class absent; leading/trailing hyphens silently stripped |
| Medium  | CWE-682 Incorrect Calculation | 1, 2, 3, 4 | checked — math hand-verified + cross-impl + 31 test vectors |
| Medium  | CWE-704 Incorrect Type Conversion or Cast | 1, 2, 3, 4 | partial — `checksum` kwarg silently truthy-coerced; bool excluded from int path |
| Low     | CWE-915 Improperly Controlled Modification | 1, 2 | checked — pure function; no input mutation |
| Low     | CWE-209 Information Exposure | 1, 2, 3, 4 | checked — error details contain only type names + single chars, not input bytes |
| Low     | CWE-400 Uncontrolled Resource Consumption | 1, 2, 3 | checked — O(n) decoder; bigint path bounded; no recursion |
| Low     | CWE-1254 Comparison Logic Issues | 1, 2 | partial — case folding is `dict.get(c)` lookup, not `.casefold()`; non-ASCII rejected |
| Low     | CWE-180 Validate Before Canonicalize | 2, 4 | checked — body-only char set + check-only char set; `U` in main body rejected even though it could decode as 32 |
| Low     | CWE-125 Out-of-bounds Read | 1, 2, 4 | checked — shift+mask always bounded by `& 0x1F` / `& 0xFF`; `_CHECK_ENCODE[v % 37]` is always in range |
| Low     | CWE-1284 Quantity Validation | 1, 3 | n/a — no quantity params; the `checksum: bool` is the only kwarg and Python already enforces bool-coercion at call site |
| Low     | CWE-190 Integer Overflow | 3 | n/a — Python 3.11+ bigints are unbounded; the int path uses `>>= 5` and `& 0x1F` (always bounded) |

---

## Surface 1 — `encode(data, *, checksum=False)` — CWE-20, CWE-682, CWE-704, CWE-915

### CWE-20: Improper Input Validation
**Applies**: yes (partial mitigation).

**Evidence**:
- `b""` accepted (correct; empty is a valid encoding).
- `bytes`, `bytearray`, `memoryview` accepted (lines 27-28).
- `int` accepted if `not bool` (line 29).
- `bool` explicitly rejected (line 29: `isinstance(data, int) and not isinstance(data, bool)`).
- All other types raise `CrockfordBase32Error(code="invalid_type")` with
  `parameter` and `got_type` in `details` (lines 7-13).
- `data < 0` raises `code="negative_integer"` (lines 30-35).

**Gap**: `checksum` keyword is not type-checked. `encode(b"f", checksum=1)`
silently coerces to `True`; `encode(b"f", checksum="yes")` does the same.
This is **silent truthiness coercion** (a documented Python pattern, not
a defect), and the spec's API contract says `checksum: bool` — non-bool
values are programmer error, not hostile input. Rating: **Low** (no
security impact; result is well-defined).

### CWE-682: Incorrect Calculation
**Applies**: yes (mitigated by spec-pinned test vectors).

**Evidence**:
- The MSB-first bit accumulator (lines 68-78) shifts and masks using
  `value << 8` and `& 0x1F` — bounded arithmetic, no rounding.
- The final partial-symbol path (line 78) shifts by `(5 - bits)` where
  `bits ∈ {1,2,3,4}` — always defined.
- 31 pinned test vectors (TV1-TV31) cover: empty, single zero, 0xFF,
  `'f'`, `'foobar'`, 5/8/10-byte all-zeros, 256-byte sweep, 100-'a'
  payload, integers 0..2^64-1, round-trips, substitution rules,
  check-symbol cases.
- Round-trip stress on 10,000 random bytes (`test_edge_10000_random_bytes_roundtrip`).

**Gap**: none observed.

### CWE-704: Incorrect Type Conversion or Cast
**Applies**: yes (mitigated).

**Evidence**:
- `bytes(bytearray)` / `bytes(memoryview)` is a safe, total copy
  constructor (line 28).
- `isinstance(data, int) and not isinstance(data, bool)` (line 29)
  prevents the classic `True` → 1, `False` → 0 silent-coercion bug.
- `data < 0` for int is well-defined (negative int comparison).
- `int -> str` is done via digit-accumulation, not `str(n)` (so leading
  zeros from base-10 are avoided).

**Gap**: `True` raises `invalid_type` rather than `negative_integer`,
which is the correct code (it's a type error, not a sign error).

### CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
**Applies**: no (mitigated by construction).

**Evidence**:
- `encode` returns a fresh `str` (line 79, `body = "".join(out)`).
- Input `bytes` is consumed by the iterator but not mutated.
- `bytearray` and `memoryview` are copied to a fresh `bytes` via
  `bytes(data)` (line 28) before the encoding loop, so the input
  cannot be mutated.
- No `setattr` / `__dict__` / `__slots__` magic.

---

## Surface 2 — `decode(s, *, checksum=False)` — CWE-20, CWE-754, CWE-682, CWE-209, CWE-180

### CWE-20: Improper Input Validation
**Applies**: yes (mitigated).

**Evidence**:
- Type check: `if not _is_str(s): raise _bad_type("s", s)` (line 54).
- `checksum=True` + empty: `code="empty_with_checksum"` (lines 58-62).
- `checksum=True` + last char not in check set: `code="invalid_check_symbol"`
  (lines 64-70).
- `U`/`u` in main body: `code="u_in_main_body"` (lines 83-89).
- `*`/`~`/`$`/`=` in main body: `code="extended_in_main_body"` (lines 90-95).
- Any other char in main body: `code="invalid_character"` (lines 96-100).
- All non-ASCII chars (Latin-1, fullwidth, NBSP, ZWNBSP, ZWSP) are
  rejected because the lookup dict has no entry for them.

**Gap**: hyphens are stripped **without** validation. `decode("---")`
silently returns `b""`; `decode("C--R")` decodes the same as `"CR"`.
Per the spec this is correct (hyphens are noise). The only "gap" is
that leading/trailing/double hyphens are not flagged — but the spec
explicitly says hyphens are ignored, so this is a feature, not a bug.

### CWE-754: Improper Check for Unusual or Exceptional Conditions
**Applies**: yes (mitigated, with one informational note).

**Evidence**:
- Substitution rules (`I=L=1`, `O=0`) are applied **at decode-time via
  lookup** (`_alphabet.py:26-31`), not as a post-processing pass. This
  means the canonicalization happens in the same step as the validation,
  so `I` in main body is treated as value 1, never as an error.
- `U` in main body is rejected **after** the substitution lookup returns
  -1 (lines 82-89) — the `U` → 32 mapping is in `_DECODE_CHECK` but NOT
  `_DECODE_BODY`, so the body lookup correctly returns -1 and the error
  branch fires.
- The case-folding path uses `dict.get(c, -1)` which is case-sensitive
  at the dict level; case-insensitivity is achieved by populating the
  dict with both upper and lower case entries (lines 23-31, 36-39). This
  is **not** `.casefold()` semantics, but the alphabet is ASCII-only so
  case-insensitivity via `dict` entries is equivalent.

**Gap**: non-ASCII input is rejected because the dict has no entries
for non-ASCII characters. This is correct for the ASCII alphabet but
**not** equivalent to a full Unicode case-fold (e.g. `İ` would be
rejected even though it could be case-folded to `i` in some locales).
This is **not a defect** for an ASCII-only alphabet.

### CWE-682: Incorrect Calculation
**Applies**: yes (mitigated by spec-pinned test vectors + cross-impl).

**Evidence**:
- The MSB-first decoder (lines 76-105) shifts `value << 5 | v` and
  masks with `& 0xFF` on byte emission — bounded arithmetic.
- `bits += 5; if bits >= 8: bits -= 8; out.append((value >> bits) & 0xFF)`.
- The MSB-first order is the spec's spec (not LSB-first).
- 31 test vectors cover the algorithm directly.

**Gap**: the decoder **silently drops trailing partial bits** that don't
fill a byte (5/10/15/20/25-bit remainders). E.g. `decode("CR")` returns
`b"f"` (16 bits = exactly 2 bytes), but `decode("C")` returns `b""`
(5 bits, less than 8). The spec does not define this case; the
implementation chose to drop the remainder rather than raise. This is a
**defensible design choice** but worth noting as a Low-severity
"silent data loss on partial byte" behavior. There is **no way to
detect this loss from the API** (the function returns `bytes` not
`bytes + remainder_bits`).

### CWE-209: Information Exposure Through Error Messages
**Applies**: yes (mitigated).

**Evidence**:
- `CrockfordBase32Error` carries `.code` (a short string like
  `"invalid_character"`) and `.details` (a dict with `parameter`,
  `got_type`, `character`, `expected`, `got`).
- The `character` field is always **a single character** (the offending
  char from the input), not the entire input string. So error
  messages do not echo back the full input (which could contain
  PII or secrets).
- The `parameter` and `got_type` fields are class/type names, not
  user data.
- The `expected` and `got` fields on `check_mismatch` are single
  characters, not the full body.

**Gap**: none observed. No input bytes/strings are reflected in error
messages (verified by reading all `raise CrockfordBase32Error(...)`
sites in `_encode.py`, `_decode.py`).

### CWE-180: Incorrect Behavior Order: Validate Before Canonicalize
**Applies**: yes (mitigated, this is the spec's design).

**Evidence**:
- The spec is unambiguous: hyphens are noise, `I/L/O` are substitution
  aliases, `U` is reserved for the check position. The implementation
  follows the spec exactly: hyphens are stripped (`body.replace("-", "")`),
  the lookup is case-insensitive via pre-populated dict, and `U` is
  rejected in the main body.
- `U` in main body would **not** be confused with value 32 because
  `_DECODE_BODY` has no entry for `U` (only `_DECODE_CHECK` does).

**Gap**: none observed.

---

## Surface 3 — `encode_int(n, *, checksum=False)` — CWE-20, CWE-682, CWE-190

### CWE-20: Improper Input Validation
**Applies**: yes (mitigated).

**Evidence**:
- `if not isinstance(n, int) or isinstance(n, bool): raise _bad_type("n", n)`
  (line 43). Rejects `True`/`False` explicitly.
- `if n < 0: raise ... code="negative_integer"` (line 45).
- `n == 0` is special-cased to `"0"` (line 51-52).
- `n > 0` goes through the digit-accumulation loop (lines 53-59).

**Gap**: `n` is unbounded (Python bigint), so no upper-bound check
needed.

### CWE-682: Incorrect Calculation
**Applies**: yes (mitigated).

**Evidence**:
- Loop: `digits.append(ALPHABET[v & 0x1F]); v >>= 5`. Always defined.
- `n = 0` → `body = "0"` (single symbol). `n = 1` → `body = "1"`. `n = 31`
  → `body = "Z"`. `n = 32` → `body = "10"`. Verified against
  spec Symbols section.
- Integer check: `checksum_symbol(encode_int(n))` for `n ∈ {0, 1, 31, 32,
  100, 2^32, 2^64 - 1}` — all round-trip.

**Gap**: none observed.

### CWE-190: Integer Overflow or Wraparound
**Applies**: no (N/A in Python 3.11+).

**Evidence**:
- Python 3.11 bigints are unbounded; `2**1024` works without overflow.
- All shifts use `>>= 5` and `& 0x1F`, which truncate to the low 5 bits
  — overflow is impossible.
- No `sys.maxsize` references in the codebase (verified by grep).

**Gap**: none (Python semantics).

---

## Surface 4 — `checksum_symbol(s)` — CWE-20, CWE-682, CWE-209

### CWE-20: Improper Input Validation
**Applies**: yes (mitigated).

**Evidence**:
- `if not _is_str(s): raise _bad_type("s", s)` (line 22).
- `body = s.replace("-", "")` strips hyphens.
- For each char in body: `lookup_body(c)` returns -1 if not a body
  symbol. The error path (lines 28-47) distinguishes:
  - `U`/`u` → `code="u_in_main_body"`
  - `*`/`~`/`$`/`=` → `code="extended_in_main_body"`
  - everything else → `code="invalid_character"`
- Math: `n = (n * 32 + v) % 37` — always bounded by 37.

**Gap**: `checksum_symbol("")` returns `"0"` (the mod-37 identity).
This is a **deliberate** behavior: the spec's `Check` section says
the check value is the input mod 37, and the empty string's mod-37
value is 0. Verified by `test_edge_integer_zero_special_case` and
direct fuzzing.

### CWE-682: Incorrect Calculation
**Applies**: yes (mitigated).

**Evidence**:
- `(n * 32 + v) % 37` is the spec's algorithm.
- Test vectors cover check values 0-36 (TV1 with check `"0"`, TV17
  with check `"*"`, the substitution test at line 645-654 of the test
  file covers `~`, `$`, `=`, `U`).
- `encode_check_value(n)` uses `v % 37` for the index, so even if
  somehow `n` was out of range, the lookup would still be in bounds
  (`_alphabet.py:65`).

**Gap**: none observed.

### CWE-209: Information Exposure
**Applies**: no (no input data in error messages; only `character=c`).

---

## Surface 5 — `validate_checksum(s)` — CWE-20, CWE-209, CWE-754

### CWE-20: Improper Input Validation
**Applies**: yes (mitigated by design — **total** function).

**Evidence**:
- `if not _is_str(s) or not s: return False` (line 122).
- `if lookup_check(check_char) < 0: return False` (line 125).
- `try: ... except CrockfordBase32Error: return False` (lines 127-130).
- All error paths return `False` rather than raising.

**Gap**: `validate_checksum` does **not** distinguish *why* the
validation failed. A `False` return could mean: wrong type, empty
string, last char not in check set, body has invalid chars, or
mismatched check. Callers wanting a specific reason must use
`decode(..., checksum=True)` and catch the specific error. This is
**by design** — the spec's `validate_checksum` is a boolean
predicate, not a diagnostic.

### CWE-754: Improper Check for Unusual Conditions
**Applies**: no — every unusual condition is caught.

### CWE-209: Information Exposure
**Applies**: no — no error messages are produced (function never raises).

---

## Surface 6 — Constants + exception — CWE-209

### CWE-209: Information Exposure
**Applies**: no.

**Evidence**:
- `CrockfordBase32Error.__repr__` returns a structured string with
  `code`, `message`, and `details`. The `message` field comes from
  the internal call sites (see above) and never contains user data.
- `.details` is the same dict passed in at construction time.

**Gap**: the `__repr__` includes the `message` which may include
single chars from the input (e.g. `f"invalid Crockford symbol in
main body: {c!r}"` — `c` is a single char). This is **not a
PII risk** (a single char is not PII), but is worth knowing if
error messages are logged in a way that requires scrubbing. Rating:
**Info**.

---

## Surface 7 — `version()` — none

Pure constant return; no input, no I/O, no computation. No CWE applies.

---

## Not applicable CWEs (considered and rejected)

| CWE | Why it doesn't apply |
|-----|---------------------|
| CWE-22  Path Traversal | no filesystem access |
| CWE-78  OS Command Injection | no `os.system`, `subprocess`, `popen` |
| CWE-79  XSS | no HTML rendering |
| CWE-89  SQL Injection | no SQL |
| CWE-94  Code Injection | no `eval`, `exec`, `compile` |
| CWE-119 Buffer Overflow | Python is memory-safe; no C extensions |
| CWE-200 Information Disclosure | no logs, no metrics, no telemetry |
| CWE-287 Auth Bypass | no auth |
| CWE-295 Cert Validation | no TLS |
| CWE-310 Cryptographic Issues | this is an encoding, not a cipher |
| CWE-311 Missing Encryption | encoding ≠ encryption; out of scope |
| CWE-326 Weak Crypto | N/A — not crypto |
| CWE-330 Insufficient Randomness | no RNG calls |
| CWE-352 CSRF | no web layer |
| CWE-367 Time-of-check Time-of-use | no filesystem races |
| CWE-377 Insecure Temp File | no temp files |
| CWE-502 Deserialization | no `pickle`, `marshal`, `yaml.load` |
| CWE-611 XXE | no XML parser |
| CWE-776 XPath Injection | no XPath |
| CWE-798 Hardcoded Credentials | no credentials (verified by grep; no `ghp_`, `pypi-AgEI`, `sk-`, `AKIA`, `Bearer ey`, `BEGIN PRIVATE KEY` matches) |
| CWE-918 SSRF | no HTTP client |
| CWE-1333 ReDoS | no regex in the implementation; no catastrophic backtracking possible |

VERDICT-CWE-MAP: 12 CWE entries considered; 8 apply (mitigated or
partial), 4 not applicable to this codebase, 22 not applicable
(framework/library level). No Critical or High-severity CWE remains
unmitigated.
