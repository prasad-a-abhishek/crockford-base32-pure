# Seed corpus — integer_path surface

> **Card**: cycle_178/adversary/02
> **Surface**: `fuzz/integer_path` — `encode_int` + `decode` of int-derived strings
> **Seed size**: 18 hand-curated entries + dynamic random generation

The integer path is the medium-risk surface (bigint math + type
boundary). Most hostile-type fuzzing for integers is redundant with
the encode/decode surface, so this harness leans harder into:

- 2^8 / 2^32 / 2^64 / 2^128 / 2^256 / 2^512 / 2^1024 boundary values.
- Negative int at multiple magnitudes.
- Non-int hostile types (None, float, str, list, dict, bool, bytes, tuple).
- True round-trip: encode_int(n) → decode → n.to_bytes.

## Hand-curated seed shapes

| # | Input | Operation | Why |
|---|-------|-----------|-----|
| 1 | `0` | encode_int | Body "0". |
| 2 | `1` | encode_int | Body "1". |
| 3 | `31` | encode_int | Last single-char value. |
| 4 | `32` | encode_int | First 2-char value. |
| 5 | `2**32` | encode_int | 7-char value. |
| 6 | `2**64 - 1` | encode_int | 13-char value. |
| 7 | `2**128` | encode_int | 26-char value. |
| 8 | `2**256` | encode_int | 52-char value. |
| 9 | `2**512` | encode_int | 103-char value. |
| 10 | `2**1024` | encode_int | 205-char value. |
| 11 | `-1` | encode_int | Negative → `negative_integer`. |
| 12 | `-2**64` | encode_int | Large negative. |
| 13 | `True` | encode_int | bool excluded → `invalid_type`. |
| 14 | `False` | encode_int | bool excluded → `invalid_type`. |
| 15 | `1.0` | encode_int | float not int. |
| 16 | `None` | encode_int | Hostile. |
| 17 | `"1"` | encode_int | str not int. |
| 18 | `[1]` | encode_int | list not int. |
| 19 | `0` with `checksum=True` | encode_int | Body "0" + check "0" → "00". |
| 20 | `2**1024` with `checksum=True` | encode_int+decode | 205+1 chars. |
| 21 | `encode_int(0)` | decode | "" |
| 22 | `encode_int(2**32)` | decode | Spec TV. |
| 23 | `encode_int(2**256)` | decode | Round-trip path. |
| 24 | `encode_int(2**1024)` | decode | Round-trip path. |

## Generator biases

- 55% non-negative int path (with bigint ladder)
- 10% negative int (must raise)
- 5% large negative int
- 30% non-int hostile type (None, float, str, list, dict, bool, bytes, tuple)
- 50% of decode calls are round-trips of encode_int output
- 50% of decode calls are random valid/bad alphabet strings
