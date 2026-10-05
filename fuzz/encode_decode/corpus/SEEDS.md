# Seed corpus — encode_decode surface

> **Card**: cycle_178/adversary/02
> **Surface**: `fuzz/encode_decode` — primary I/O surface
> **Seed size**: 16 hand-curated entries + dynamic random generation

These are the starting seed inputs the harness uses to bias its random
generator toward known boundary cases before adding coverage-guided
mutation. The harness itself uses a fresh `random.Random(seed)` per
run, so these seeds exist in the form of biases toward known
problematic shapes (empty input, single byte, max-byte, bigint,
checkmismatch, hyphen placement, case variants, hostile types).

## Fixed hand-curated seed shapes (logical, not files)

| # | Input | Operation | Why |
|---|-------|-----------|-----|
| 1 | `b""` (empty) | encode | Empty body → empty string. Spec-pinned. |
| 2 | `b"\x00"` | encode | NUL byte → "00". Boundary. |
| 3 | `b"\xff"` | encode | Max byte → "ZW". Boundary. |
| 4 | `b"foobar"` | encode | Spec example. |
| 5 | `b"foobar"` with `checksum=True` | encode | Spec example. |
| 6 | `b"a" * 5` | encode | 40-bit boundary. |
| 7 | `b"a" * 8` | encode | 64-bit boundary (13 chars). |
| 8 | `b"a" * 10` | encode | 80-bit boundary (16 chars). |
| 9 | `bytearray(b"foobar")` | encode | Coercion path. |
| 10 | `memoryview(b"foobar")` | encode | Coercion path. |
| 11 | `2**256` (int) | encode | Bigint path. |
| 12 | `2**1024` (int) | encode | Bigint path. |
| 13 | `-1` (int) | encode | Negative int → `negative_integer`. |
| 14 | `0` (int) | encode | Zero → "0" body. |
| 15 | `True` (bool) | encode | Bool is excluded → `invalid_type`. |
| 16 | `None` (hostile) | encode | All hostile types → `invalid_type`. |
| 17 | `b"f" * 1000` (large) | encode+decode round-trip | Large input fuzz. |
| 18 | `"C"` | decode | Single valid char (drops to b""). |
| 19 | `"CR"` | decode | Spec example. |
| 20 | `"CR"` with `checksum=True` | decode | Match. |
| 21 | `"CR2"` with `checksum=True` | decode | Mismatch → `check_mismatch`. |
| 22 | `""` with `checksum=True` | decode | Empty with checksum → `empty_with_checksum`. |
| 23 | `"???"` | decode | Invalid char → `invalid_character`. |
| 24 | `"U"` | decode | Reserved → `u_in_main_body`. |
| 25 | `"*"` | decode | Extended in main body. |
| 26 | `"C-R"` | decode | Hyphen stripped. |
| 27 | `"cr"` (lowercase) | decode | Case-insensitive. |
| 28 | `"é"`, `"Ｒ"`, `"\xa0"`, `"\ufeff"`, `"\u200b"` | decode | Non-ASCII → `invalid_character`. |

## Generator biases (in harness)

- 30% chance of all-zeros payload
- 30% chance of random byte values
- 30% chance of printable ASCII
- 10% chance of structured / boundary (single byte, max byte, all 0x00)
- 30% chance of bigint for the int path
- 5% chance of negative int (must raise)
- 10% chance of each of {None, float, str, list, dict, bool, bytes, tuple} for hostile-type fuzzing
- 55% valid alphabet chars in decode strings, 15% bad chars, 10% case-variants, 10% hyphens, 10% non-ASCII
