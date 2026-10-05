# Threat Model — crockford-base32-pure

> **Card**: cycle_178/adversary/01 — VULN_AUDIT
> **Methodology**: For each of the 7 surfaces, identify (1) the attacker
> profile, (2) the attack vector, (3) the attacker's goal, (4) the
> impact, and (5) the current mitigations. The threat model is
> **defensive** (focused on protecting honest callers) rather than
> offensive (this is a library, not a service).

## Threat model summary

| # | Surface | Attacker profile | Realistic impact | Mitigation status |
|---|---------|-----------------|------------------|-------------------|
| 1 | `encode`  | internal dev / supply-chain | low — wrong output to downstream system | type-checked; 31 vectors |
| 2 | `decode`  | untrusted external source (URL, QR, log) | medium — crashes, infinite loop, PII echo | all hostile input → structured error |
| 3 | `encode_int` | internal dev | low — wrong output | type-checked; bounded bigint |
| 4 | `checksum_symbol` | internal dev | low — wrong output | type-checked; mod-37 by spec |
| 5 | `validate_checksum` | internal dev | low — wrong yes/no | total (no exceptions) |
| 6 | constants/exception | n/a (data only) | none | n/a |
| 7 | `version` | n/a (no input) | none | n/a |

**No Critical or High threat** identified. The only realistic attack
surface is Surface 2 (`decode`), and the implementation is total over
all hostile input (verified by fuzzing 30+ adversarial cases).

---

## Surface 1 — `encode(data, *, checksum=False)`

**Attacker profile**: Unlikely external attacker. The encoder is
typically called by the same program that produces the identifier
(DB-side ID generation, log line formatting, hash output rendering).
The most realistic threat is a **developer mistake** (passing the
wrong type) rather than malicious input.

**Attack vector**: pass hostile type (`None`, `1.5`, `[]`, `{}`,
`True`, `False`, etc.) hoping for an uncaught `TypeError` /
`AttributeError` that crashes the caller.

**Goal**: crash the caller's process; or, in pathological cases,
trick a downstream system that interprets the output (e.g. a log
line, URL, or SQL identifier) into doing something unsafe.

**Impact**: low. The function is total over all hostile types
(verified: 9 hostile types tested, 9 structured `CrockfordBase32Error`
raises, 0 uncaught exceptions). The output is always a `str` (or
a structured error), never a partially-initialized object.

**Mitigations**:
- Type check: `isinstance(data, (bytes, bytearray, memoryview))` then
  `isinstance(data, int) and not isinstance(data, bool)` (lines 27, 29).
- Negative int: `if data < 0: raise ... code="negative_integer"`
  (line 30).
- All other types: `raise _bad_type("data", data)` (line 37).
- 31 spec-pinned test vectors + 13 edge-case tests (100, 1k, 10k byte
  round-trips) catch calculation errors.

**Residual risk**: the `checksum` keyword is silently truthiness-
coerced (`encode(b"f", checksum=1)` works the same as
`encode(b"f", checksum=True)`). This is a **defensible** Python
pattern but could surprise a caller who passes a non-bool. Rating:
**Info**.

---

## Surface 2 — `decode(s, *, checksum=False)` (PRIMARY ATTACK SURFACE)

**Attacker profile**: external untrusted source. This function is
typically called on data received from outside the trust boundary:
- URL slug from a user-clicked link
- ID from a QR code scanned by a phone
- Log line pasted from a customer support ticket
- Identifier from a partner's API response
- Hand-typed code from a printed label

In all these cases, the input is **untrusted, unvalidated, and may
contain errors** (typos, OCR mis-reads, encoding issues, deliberate
manipulation).

**Attack vectors**:
1. **Type confusion**: pass `bytes` instead of `str` (e.g.
   `b"CR"`). Mitigated by `if not _is_str(s): raise _bad_type`.
2. **Invalid characters**: pass any char outside the Crockford
   alphabet (non-ASCII, `?`, etc.). Mitigated by per-char lookup
   with structured error.
3. **Reserved characters in main body**: `U`/`*`/`~`/`$`/`=` in the
   main body. Mitigated by separate `lookup_body` and `lookup_check`
   tables — body lookup returns -1 for these chars and the error
   branch distinguishes `u_in_main_body` from
   `extended_in_main_body` from `invalid_character`.
4. **Substitution confusion**: input contains `I`, `L`, `O` (the
   confusable letters). The decoder **silently treats** these as
   `1`, `1`, `0` respectively (per spec). This is the **intended**
   behavior, not an attack — the spec is explicit that the decoder
   should tolerate these confusables.
5. **Empty input + `checksum=True`**: `decode("", checksum=True)`
   raises `empty_with_checksum`. Mitigated.
6. **Check mismatch**: attacker forges a valid-looking body with
   a wrong check symbol. The decoder detects the mismatch and
   raises `check_mismatch` (line 109-115).
7. **Very long input**: a 10MB+ string. Mitigated by O(n) decoder
   (no recursion, no regex, no quadratic data structure). 100KB
   verified in 0.13s; 1MB would be ~1.3s; 10MB ~13s.
8. **Embedded NUL / control chars**: `\x00`, `\x01`, etc. Mitigated
   by per-char lookup (control chars are not in the alphabet).
9. **Hyphen injection**: leading/trailing/double hyphens. The spec
   says hyphens are noise; the implementation strips them silently.
   This is a **feature** (callers commonly add hyphens for
   readability) but worth noting: a string like
   `"--MALICIOUS--"` decodes to the same as `"MALICIOUS"`, which
   could in theory bypass a naive "starts with --" check in a
   downstream system. Rating: **Info** (the library does the
   right thing per spec; downstream systems must validate the
   *decoded* output, not the *encoded* string).

**Goal**:
- Crash the caller's process (DoS) via uncaught exception → mitigated
  by total-safety Invariant 21.
- Trick the caller into accepting a forged identifier (e.g. a
  check-symbol mismatch that's silently accepted) → mitigated by
  the `check_mismatch` error path.
- Echo attacker-controlled data into a log/traceback that gets
  scraped by a secret-management system → mitigated by the
  single-character `character` field in error details (not the
  full input).

**Impact**: low-to-medium. Without mitigations, a hostile decoder
could crash the process (DoS) or echo PII into error messages. With
mitigations, the worst realistic outcome is a structured error
returned to the caller, who is then responsible for handling it
(e.g. returning a 400 to the HTTP client, or logging the error
code without the full input).

**Mitigations** (all verified by 30+ adversarial test cases in
`test_crockford_base32.py`):
- Type guard (line 54).
- `checksum=True` requires non-empty (lines 58-62).
- `checksum=True` validates the check char (lines 64-70).
- Body char-by-char lookup with distinct error codes for
  `U` / extended / other (lines 79-100).
- Check mismatch detection (lines 107-115).
- No recursion, no regex, O(n) decode.
- Error details contain only `parameter`, `got_type`, `character`,
  `expected`, `got` — never the full input string.

**Residual risk**:
- The decoder **silently drops trailing partial bits** that don't
  fill a full byte. E.g. `decode("C")` returns `b""` even though
  the input had 5 meaningful bits. A caller that wants to detect
  this loss must compare the input length to the expected length
  (5 chars = 1 byte + 5 bits dropped; 10 chars = 1 byte + 10 bits
  dropped or 2 bytes; etc.). Rating: **Low** (the spec doesn't
  define this case; the implementation chose a defensible default).

---

## Surface 3 — `encode_int(n, *, checksum=False)`

**Attacker profile**: internal developer. The integer is typically
programmer-controlled (DB IDs, hash outputs, counter values).

**Attack vectors**:
1. Pass a non-int (`True`, `1.5`, `[]`). Mitigated by explicit
   type check with bool trap (line 43).
2. Pass a negative int. Mitigated by `if n < 0: raise ...` (line 45).
3. Pass a very large int (`2**1024`). Mitigated by Python bigints
   (no overflow); output length grows linearly (205 chars for 1024
   bits).

**Goal**: cause a crash, or produce a malformed string that
breaks a downstream parser.

**Impact**: low. All hostile inputs produce structured errors.

**Mitigations**:
- Type check (line 43) with bool exclusion.
- Sign check (line 45).
- 7 integer-specific test cases (`test_edge_integer_*`).

**Residual risk**: none observed.

---

## Surface 4 — `checksum_symbol(s)`

**Attacker profile**: internal developer.

**Attack vectors**: pass a non-str or a string with invalid
body characters. Mitigated by type check (line 22) and per-char
lookup (lines 28-47).

**Goal**: produce a wrong check symbol that matches a forged body.

**Impact**: low. The function is total over hostile input; invalid
input raises a structured error.

**Mitigations**:
- Type check (line 22).
- Substitution rules in lookup table.
- 5 extended-symbol round-trip tests (lines 645-654 of test file).
- 7 hostile-input tests (`test_invariant21_checksum_symbol_hostile_inputs`).

**Residual risk**: none observed.

---

## Surface 5 — `validate_checksum(s)`

**Attacker profile**: internal developer or external untrusted
source. This function is designed to be **safe to call on any
input** — it never raises.

**Attack vectors**: pass anything (None, bytes, list, dict,
empty string, invalid chars, mismatched check). All return
`False`.

**Goal**: trick the caller into accepting a forged check.

**Impact**: low. The function returns `False` for any invalid
input; the caller must explicitly check the return value.

**Mitigations**:
- Total function (never raises).
- 12 explicit `validate_checksum(...)` test cases
  (`test_invariant21_validate_checksum_total`).

**Residual risk**: `validate_checksum` does not distinguish
*why* the validation failed (see CWE_MAP § Surface 5). Callers
needing a specific reason must use `decode(..., checksum=True)`
and catch the specific `CrockfordBase32Error`. Rating: **Info**.

---

## Surface 6 — Constants + exception

**Attacker profile**: n/a. The constants are data; the exception
class is the canonical error type.

**Attack vectors**: none.

**Goal**: n/a.

**Impact**: n/a.

**Mitigations**: the exception class is a thin `ValueError`
subclass; no `__del__`, no `__getattr__`, no descriptor magic.

**Residual risk**: the `__repr__` includes the message, which
includes a single character from the input. This is not a PII
risk but is worth knowing for log-scrubbing pipelines. Rating:
**Info**.

---

## Surface 7 — `version()`

**Attacker profile**: n/a. No input, no I/O.

**Attack vectors**: n/a.

**Goal**: n/a.

**Impact**: n/a.

**Mitigations**: n/a.

**Residual risk**: none.

---

## Threat-model-level findings

1. **No data exfiltration paths**: the library does not read files,
   open sockets, call subprocesses, or import any third-party module
   that does. A successful attack on this library cannot exfiltrate
   data from the caller's process.

2. **No persistence paths**: the library does not write to the
   filesystem, registry, or environment. A successful attack cannot
   persist state across invocations.

3. **No privilege escalation paths**: the library does not call
   `setuid`, `setgid`, `chroot`, `seteuid`, `ImpersonateLoggedOnUser`,
   or any platform-privilege API.

4. **DoS only via CPU/memory**: the only DoS vector is "feed it
   a very large string and make it allocate". Mitigated by Python's
   memory limits (per-process RSS cap) and the O(n) decoder (no
   exponential blowup).

5. **Caller responsibility**: the library's threat model assumes
   the caller validates the *decoded* output, not just the
   *encoded* string. E.g. if a URL slug is decoded and used as a
   database key, the caller must verify the key is in the expected
   range. The library will not check this.

VERDICT-THREAT-MODEL: 7 surfaces, 1 primary attack surface (decode),
0 unmitigated Critical/High threats, 3 Info/Low residual risks
(silent trailing-bit truncation; checksum kwarg truthiness; hyphen
injection).
