# Seed corpus — checksum_validate surface

> **Card**: cycle_178/adversary/02
> **Surface**: `fuzz/checksum_validate` — mod-37 check symbol + total validator
> **Seed size**: 14 hand-curated entries + dynamic random generation

The check-symbol path is the medium-risk math surface; validate_checksum
is a low-risk total predicate. Together they cover the mod-37
arithmetic and the lookup tables for the body alphabet and the
extended check alphabet.

## Hand-curated seed shapes

| # | Input | Operation | Why |
|---|-------|-----------|-----|
| 1 | `""` (empty) | checksum_symbol | mod-37 identity → "0". |
| 2 | `"---"` (hyphens only) | checksum_symbol | Strip → empty → "0". |
| 3 | `"0"` | checksum_symbol | Single zero → "0". |
| 4 | `"1"` | checksum_symbol | Single one. |
| 5 | `"10"` (extended check value 32) | checksum_symbol | First extended check. |
| 6 | `"11"` (33) | checksum_symbol | "~" |
| 7 | `"12"` (34) | checksum_symbol | "$" |
| 8 | `"13"` (35) | checksum_symbol | "=" |
| 9 | `"14"` (36) | checksum_symbol | "U" |
| 10 | `"U"` | checksum_symbol | Reserved → `u_in_main_body`. |
| 11 | `"?"` | checksum_symbol | Invalid → `invalid_character`. |
| 12 | `None` | checksum_symbol | Hostile type → `invalid_type`. |
| 13 | `b"CR"` | checksum_symbol | bytes (not str) → `invalid_type`. |
| 14 | `123` | checksum_symbol | int (not str) → `invalid_type`. |
| 15 | `None` | validate_checksum | Total predicate → False. |
| 16 | `""` | validate_checksum | Empty → False. |
| 17 | `"CR"` (no check char) | validate_checksum | Last char "R" not in check set → False. |
| 18 | `"CR1"` (match) | validate_checksum | True. |
| 19 | `"CR2"` (mismatch) | validate_checksum | False. |
| 20 | `"00"` (zero body) | validate_checksum | True. |
| 21 | `b"CR1"` | validate_checksum | bytes → False. |
| 22 | `123` | validate_checksum | int → False. |
| 23 | `[]` | validate_checksum | list → False. |
| 24 | `{}` | validate_checksum | dict → False. |
| 25 | `True` | validate_checksum | bool → False. |
| 26 | `1.5` | validate_checksum | float → False. |
| 27 | `"??1"` | validate_checksum | Body has `?` → False. |
| 28 | `"é"` | validate_checksum | Non-ASCII → False. |

## Generator biases

- 20% chance of hostile non-str type for validate_checksum
- 30% chance of empty/whitespace-only string
- 60% valid alphabet chars, 15% bad chars, 10% case variants, 10% hyphens
