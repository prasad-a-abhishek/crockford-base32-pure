# crockford-base32-pure

> **Douglas Crockford's Base32, pure-Python, stdlib-only, with the
> mod-37 check symbol. No I/L/O/U confusion, no `=` padding, no
> external dependencies.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)]()

A faithful pure-Python implementation of the encoding defined at
<https://www.crockford.com/base32.html> (Douglas Crockford, 2019-03-04).
The 32-symbol alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` excludes the
four confusable letters `I L O U`. Decode accepts upper- and lower-case
input, treats `I` / `L` as `1` and `O` as `0`, and strips hyphens. A
single-character mod-37 check symbol can be appended optionally (using
the five extended symbols `* ~ $ = U` for check values 32..36).

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/crockford-base32-pure.git
```

```python
from crockford_base32_pure import encode, decode, checksum_symbol, validate_checksum

# Bytes -> Crockford Base32 (no padding, case-insensitive on decode)
print(encode(b"foobar"))           # "CSQPYRK1E8"
print(decode("CSQPYRK1E8"))        # b"foobar"

# With the mod-37 check symbol
print(encode(b"f", checksum=True)) # "CR1"  (CR + check symbol "1")
print(decode("CR1", checksum=True))  # b"f"  (validated check)
print(validate_checksum("CR1"))    # True
print(validate_checksum("CR2"))    # False

# Confusable-letter substitution (I/L = 1, O = 0)
print(decode("CR"))    # b"f"
print(decode("cr"))    # b"f"  (case-insensitive)
print(decode("O"))     # b""   (O substitutes as 0; 5 bits < 1 byte)

# Hyphens are noise
print(decode("CSQ-PYRK-1E8"))  # b"foobar"
```

## ⚡ Performance & Benchmarks

See [`benchmarks/BENCHMARK.md`](benchmarks/BENCHMARK.md) for a 10-workload
comparison against stdlib `base64.b32encode` (100/20/3/1 iterations across
workloads; 1 MB profiles deferred — ~20 s/iter wall time for pure-Python
encode). Workloads span 1 KB–1 MB random and all-zero inputs; metrics
report mean, P95 latency, and peak memory.

**Key findings (from measured data):**
- **Small all-zero buffers (1–100 KB):** `crockford-base32-pure` is
  ~10× faster than `base64.b32encode` on all-zero input (the bit-accumulator
  hot-path has no branches for zero bytes).
- **Random/uniform buffers:** `base64.b32encode` (C, ~650 KB/s) is
  ~2–14× faster than the pure-Python implementation (~50–600 KB/s).
  The difference grows with input size because the pure-Python bit-accumulator
  is O(n) Python bytecode while `base64` is native C.
- **Alphabet incompatibility:** these two libraries are **not** drop-in
  compatible. Pick the one whose alphabet you need.

Reproduce locally:
```bash
python3 benchmarks/run_benchmark.py
```


## Why `crockford-base32-pure`?

**The problem.** Python's stdlib `base64.b32encode` / `b32decode`
implement **RFC 4648 Base32** with alphabet
`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`. That alphabet includes
`I L O U`, uses `=` padding, and does not support the
confusable-letter substitution (`I=L=1`, `O=0`) or the mod-37 check
symbol. There is no `b32decode` that accepts Crockford input.

For a Python developer who needs to render or parse Crockford
Base32 — e.g. for hand-written order IDs, URL slugs, log-line
identifiers, or for cross-tool compatibility with systems that
already speak Crockford (Grafana, CockroachDB-style IDs, certain
observability tooling) — there is no stdlib option and the existing
PyPI / GitHub landscape is either RFC 4648 in disguise or unmaintained
copy-paste scripts.

**The fix.** A pure-Python, stdlib-only, fully-tested, fully-documented
implementation of Crockford's spec. No third-party dependencies, no
C extensions, runs on Pyodide / WASM / AWS Lambda / an air-gapped
machine. The alphabet is the alphabet, the check symbol is the check
symbol, and every output is reproducible from the spec page.

**Trade-offs (honest).** The MSB-first bit-accumulator is slower
than the RFC 4648 stdlib `base64.b32encode` for the same byte
count. The gap is size-dependent: roughly **1-2× slower on small
random inputs (1 KB)** and up to **~14× slower on large random
inputs (100 KB+)** — see `benchmarks/BENCHMARK.md` for the full
10-workload profile. The algorithm is fixed-width and the
substitution rules (`I/L/O` mapping, hyphen stripping, check
symbol) add branch checks per character that the stdlib path
doesn't carry. The decode path is also not lossless for inputs
whose bit length is not a multiple of 8 — trailing bits that
don't fill a complete byte are discarded (this is per the spec).
If you need a lossless bit-level decode, use the `encode_int` /
checksum-symbol paths instead.

## Key Features & Complete API Reference

### Five public functions

| function | signature | what it does |
|---|---|---|
| `encode` | `encode(data, *, checksum=False) -> str` | Bytes (or non-negative int) -> Crockford Base32 |
| `decode` | `decode(s, *, checksum=False) -> bytes` | Crockford Base32 -> bytes; case-insensitive, hyphens ignored, `I/L=1`, `O=0` |
| `encode_int` | `encode_int(n, *, checksum=False) -> str` | Non-negative int -> Crockford Base32 (LSQ-first, no leading zeros) |
| `checksum_symbol` | `checksum_symbol(s) -> str` | Compute the mod-37 check symbol (single character) |
| `validate_checksum` | `validate_checksum(s) -> bool` | Return `True` if the trailing check symbol of `s` is valid; never raises |

### Constants

| name | value | meaning |
|---|---|---|
| `ALPHABET` | `"0123456789ABCDEFGHJKMNPQRSTVWXYZ"` | The 32-symbol Crockford alphabet (no `I L O U`) |
| `EXTENDED` | `"*~$=U"` | The 5 extra symbols for check values 32..36 (valid only in check position) |
| `CrockfordBase32Error` | `ValueError` subclass | Raised for all invalid input. Carries `.code` (str) and `.details` (dict) |

### Error codes (Invariant 21 structured findings)

The `CrockfordBase32Error.code` attribute is one of:

| code | when |
|---|---|
| `"invalid_type"` | `encode` / `decode` / `encode_int` / `checksum_symbol` got a wrong type |
| `"negative_integer"` | `encode(-1)` or `encode_int(-1)` |
| `"empty_with_checksum"` | `decode("", checksum=True)` |
| `"invalid_character"` | decode saw a character outside the Crockford alphabet |
| `"u_in_main_body"` | decode saw `U` / `u` in the main body (check-only by spec) |
| `"extended_in_main_body"` | decode saw `*` / `~` / `$` / `=` in the main body (check-only by spec) |
| `"invalid_check_symbol"` | `decode(..., checksum=True)` got a trailing character that isn't in the check set |
| `"check_mismatch"` | `decode(..., checksum=True)` got a check symbol that does not match the body |

### Decode substitution rules

| input | decoded value |
|---|---|
| `I` / `i` / `L` / `l` | `1` |
| `O` / `o` | `0` |
| `-` (hyphen) | (stripped, no value) |
| `U` / `u` | **rejected** in main body (check-position only) |
| `*` / `~` / `$` / `=` | **rejected** in main body (check-position only) |
| any other ASCII | **rejected** |

### Examples

```python
# Integer encoding
print(encode(0))            # "0"
print(encode(1024))         # "100"
print(encode(2 ** 32))      # "4000000"
print(encode(2 ** 64 - 1))  # "FZZZZZZZZZZZZ"

# Integer encoding with check (forces extended check symbols)
print(encode(32, checksum=True))   # "10*"   (1*32 + 0 = 32; check 32 = "*")
print(encode(33, checksum=True))   # "11~"   (33 -> "~")
print(encode(34, checksum=True))   # "12$"   (34 -> "$")
print(encode(35, checksum=True))   # "13="   (35 -> "=")
print(encode(36, checksum=True))   # "14U"   (36 -> "U")

# Decode with check validation
assert decode("10*", checksum=True) == b"\x08"  # 10 input bits -> 1 byte
assert validate_checksum("10*")                 # True

# Total safety: hostile inputs return structured errors
try:
    encode(None)
except CrockfordBase32Error as e:
    print(e.code)        # "invalid_type"
    print(e.details)     # {"parameter": "data", "got_type": "NoneType"}

# Round-trip
import os
payload = os.urandom(1000)
assert decode(encode(payload)) == payload
assert decode(encode(payload, checksum=True), checksum=True) == payload
```

### Known limitations (NOT bugs)

1. **NOT RFC 4648 Base32.** Different alphabet. If you need RFC 4648
   compatibility, use `base64.b32encode` from stdlib.
2. **NOT a UUID or short-ID generator.** Crockford Base32 is a
   serialization format. Generate the ID with `uuid.uuid4()` or
   `secrets.token_bytes()`, then `encode()` it for display.
3. **`U` is not valid in the main body of a decode string.** `U` is
   reserved for the check-symbol position (spec Check section).
4. **Decode discards trailing bits that don't fill a byte.** `decode("0")`
   returns `b""`, not `b"\x00"`.

## Installation

```bash
pip install git+https://github.com/prasad-a-abhishek/crockford-base32-pure.git
```

This package is not (yet) published to PyPI; install directly from the
git repository.

## Tests

148 test cases covering all 15 acceptance criteria, 31 pinned spec vectors,
and 7 dedicated Test-Vector Honesty Declaration guards (enforcing
`input_hex` / `input_int` — no `input_len` — and per-entry provenance
citations). 134 cases pass; 14 integer-vector cases are skipped as
duplicates under the bytes path. Run with ``pytest`` after install.

MIT — see [LICENSE](LICENSE).

## Author

Prasad A. Abhishek

## Acknowledgments

- **Douglas Crockford** for the original spec at
  <https://www.crockford.com/base32.html>
- The Go stdlib `encoding/base32` package for cross-verification
  of the alphabet and substitution rules
- The Wikipedia entry on Base32 for an independent restatement
- The fzakaria/Crockford Java reference (Apache-2.0) for alphabet
  cross-check
- The deniszykov/crockford C# reference (MIT) for mod-37 check
  cross-check
