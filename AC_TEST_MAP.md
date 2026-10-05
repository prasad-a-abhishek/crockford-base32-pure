# Test coverage map

This document maps every spec acceptance criterion (AC1..AC15) and every
pinned test vector (TV1..TV31) to the test(s) that exercise it.

## Acceptance Criteria

| spec criterion | test(s) |
|---|---|
| AC1. `encode(b"")` returns `""` | `test_ac1_empty_input`, `test_edge_empty_bytes_roundtrip`, `test_vector_encode_bytes[TV1]` |
| AC2. `encode(b"f")` returns `"CR"` | `test_ac2_letter_f`, `test_vector_encode_bytes[TV4]` |
| AC3. `encode(b"foobar")` returns `"CSQPYRK1E8"` | `test_ac3_foobar`, `test_vector_encode_bytes[TV10]` |
| AC4. `encode(b"\x00")` returns `"00"` | `test_ac4_single_zero_byte`, `test_vector_encode_bytes[TV2]`, `test_edge_single_byte_0x00` |
| AC5. `encode(1024)` returns `"100"` | `test_ac5_integer_path`, `test_vector_encode_int[TV18]` |
| AC6. `encode(b"f", checksum=True)` returns `"CR1"`; `checksum_symbol("CR")` returns `"1"` | `test_ac6_checksum_symbol`, `test_vector_encode_with_checksum_bytes[TV4]`, `test_substitution_I_equals_L_equals_1` |
| AC7. `decode("CR")` returns `b"f"` | `test_ac7_basic_decode`, `test_vector_decode[TV21]` |
| AC8. `decode("CSQPYRK1E8")` returns `b"foobar"` | `test_ac8_long_decode`, `test_vector_decode[TV10-decode-via-roundtrip]` (TV10 is encode-direction; roundtrip is in test_edge_10000_random_bytes_roundtrip) |
| AC9. `decode("cR")` returns `b"f"` (case-insensitive) | `test_ac9_case_insensitive`, `test_vector_decode[TV22]`, `test_substitution_lowercase_round_trip` |
| AC10. `decode("CSQ-PYRK-1E8")` returns `b"foobar"` (hyphens ignored) | `test_ac10_hyphens_ignored`, `test_substitution_hyphen_stripping`, `test_edge_long_hyphenated_decode` |
| AC11. `decode("I")` returns `b""` (I/L=1 substitution; 5 bits, no full byte) | `test_ac11_i_l_substitution`, `test_substitution_I_equals_L_equals_1`, `test_substitution_O_equals_0` |
| AC12. `decode("U")` raises `ValueError` (U is check-only, rejected in main body) | `test_ac12_u_in_main_body_rejected`, `test_vector_decode[TV27]` |
| AC13. `decode("*")` raises `ValueError` (extended `*` rejected in main body) | `test_ac13_extended_in_main_body_rejected`, `test_substitution_extended_symbols_in_body_rejected`, `test_vector_decode[TV28]` |
| AC14. `validate_checksum("CR1")` returns `True`; `validate_checksum("CR2")` returns `False` | `test_ac14_validate_checksum`, `test_substitution_extended_symbols_in_check_position`, `test_vector_decode[TV29]`, `test_vector_decode[TV30]` |
| AC15. `encode(None)` / `encode(-1)` / `decode(None)` / `decode("???")` raise structured errors (no uncaught `TypeError`; `ValueError` is the canonical return for invalid input) | `test_ac15_total_safety`, `test_invariant21_encode_hostile_inputs`, `test_invariant21_decode_hostile_inputs`, `test_invariant21_checksum_symbol_hostile_inputs`, `test_invariant21_validate_checksum_total`, `test_invariant21_negative_integer` |

## Pinned Test Vectors (TV1..TV31)

| vector | direction | test |
|---|---|---|
| TV1 empty input | encode | `test_vector_encode_bytes[TV1]` |
| TV2 single zero byte | encode | `test_vector_encode_bytes[TV2]`, `test_vector_encode_with_checksum_bytes[TV2]` |
| TV3 single 0xFF byte | encode | `test_vector_encode_bytes[TV3]`, `test_vector_encode_with_checksum_bytes[TV3]` |
| TV4 letter 'f' | encode | `test_vector_encode_bytes[TV4]`, `test_vector_encode_with_checksum_bytes[TV4]` |
| TV5 two bytes 0x01 0x02 | encode | `test_vector_encode_bytes[TV5]`, `test_vector_encode_with_checksum_bytes[TV5]` |
| TV6 5 zero bytes | encode | `test_vector_encode_bytes[TV6]`, `test_vector_encode_with_checksum_bytes[TV6]`, `test_edge_5_byte_boundary_all_zero` |
| TV7 8 zero bytes | encode | `test_vector_encode_bytes[TV7]`, `test_vector_encode_with_checksum_bytes[TV7]`, `test_edge_8_byte_boundary_all_zero` |
| TV8 10 zero bytes | encode | `test_vector_encode_bytes[TV8]`, `test_vector_encode_with_checksum_bytes[TV8]`, `test_edge_10_byte_boundary_all_zero` |
| TV9 'abc' | encode | `test_vector_encode_bytes[TV9]`, `test_vector_encode_with_checksum_bytes[TV9]` |
| TV10 'foobar' (spec worked example) | encode | `test_vector_encode_bytes[TV10]`, `test_vector_encode_with_checksum_bytes[TV10]`, `test_ac3_foobar` |
| TV11 'Hello, World!' | encode | `test_vector_encode_bytes[TV11]`, `test_vector_encode_with_checksum_bytes[TV11]` |
| TV12 256-byte sweep | encode | `test_vector_encode_bytes[TV12]`, `test_vector_encode_with_checksum_bytes[TV12]` |
| TV13 100 'a' bytes | encode | `test_vector_encode_bytes[TV13]`, `test_vector_encode_with_checksum_bytes[TV13]` |
| TV14 int 0 | encode | `test_vector_encode_int[TV14]`, `test_edge_integer_zero_special_case` |
| TV15 int 1 | encode | `test_vector_encode_int[TV15]`, `test_edge_integer_one` |
| TV16 int 31 | encode | `test_vector_encode_int[TV16]`, `test_edge_integer_max_31` |
| TV17 int 32 | encode | `test_vector_encode_int[TV17]`, `test_edge_integer_32` |
| TV18 int 1024 | encode | `test_vector_encode_int[TV18]`, `test_ac5_integer_path` |
| TV19 int 2^32 | encode | `test_vector_encode_int[TV19]`, `test_vector_encode_with_checksum_int[TV19]` |
| TV20 int 2^64-1 | encode | `test_vector_encode_int[TV20]`, `test_vector_encode_with_checksum_int[TV20]`, `test_edge_integer_large` |
| TV21 decode 'CR' | decode | `test_vector_decode[TV21]`, `test_ac7_basic_decode` |
| TV22 decode 'cR' case-insens | decode | `test_vector_decode[TV22]`, `test_ac9_case_insensitive` |
| TV23 decode 'I' (substitutes 1) | decode | `test_vector_decode[TV23]`, `test_ac11_i_l_substitution` |
| TV24 decode 'L' (substitutes 1) | decode | `test_vector_decode[TV24]`, `test_ac11_i_l_substitution` |
| TV25 decode 'o' (substitutes 0) | decode | `test_vector_decode[TV25]`, `test_substitution_O_equals_0` |
| TV26 decode 'CSQ-PYRK-1E8' (hyphens) | decode | `test_vector_decode[TV26]`, `test_ac10_hyphens_ignored`, `test_substitution_hyphen_stripping` |
| TV27 decode 'U' (error: u_in_main_body) | decode-error | `test_vector_decode[TV27]`, `test_ac12_u_in_main_body_rejected` |
| TV28 decode '*' (error: extended_in_main_body) | decode-error | `test_vector_decode[TV28]`, `test_ac13_extended_in_main_body_rejected`, `test_substitution_extended_symbols_in_body_rejected` |
| TV29 check valid: 'CR1' | decode | `test_vector_decode[TV29]`, `test_substitution_I_equals_L_equals_1` |
| TV30 check invalid: 'CR2' | decode-error | `test_vector_decode[TV30]`, `test_ac14_validate_checksum` |
| TV31 check extended: '10*' | decode | `test_vector_decode[TV31]`, `test_substitution_extended_symbols_in_check_position` |

## Test-Vector Honesty Declaration (per cycle_178)

Every TV entry in `tests/test_vectors.json`:
- Uses `input_hex` (for bytes input) or `input_int` (for integer input).
- **NEVER uses `input_len`** (cycle_177 H-3 chronic-failure regression).
- Has an accurate `description` string.
- Has a `_provenance` field citing the spec page section.

The Honesty guard is enforced by:
- `test_vectors_honesty_no_input_len`
- `test_vectors_honesty_input_field_present`
- `test_vectors_honesty_description_present`
- `test_vectors_honesty_provenance_present`
- `test_vectors_honesty_spec_url_matches`
- `test_vectors_honesty_round_trip_description`
- `test_vectors_honesty_first_5_descriptions_match_bytes`

## Edge cases

| case | test |
|---|---|
| empty bytes round-trip | `test_edge_empty_bytes_roundtrip` |
| empty bytes with check ('0') | `test_edge_empty_with_checksum_decodes_to_zero` |
| single byte 0x00, 0x01 | `test_edge_single_byte_0x00`, `test_edge_single_byte_0x01` |
| 5/8/10-byte boundaries (all zeros) | `test_edge_5_byte_boundary_all_zero`, `test_edge_8_byte_boundary_all_zero`, `test_edge_10_byte_boundary_all_zero` |
| 100 bytes all 0xff | `test_edge_all_ff_round_trip` |
| 1000 random bytes round-trip | `test_edge_1000_random_bytes_roundtrip` |
| 10000 random bytes round-trip | `test_edge_10000_random_bytes_roundtrip` |
| round-trip with checksum | `test_edge_round_trip_with_checksum` |
| integer 0/1/31/32/large | `test_edge_integer_zero_special_case`, `test_edge_integer_one`, `test_edge_integer_max_31`, `test_edge_integer_32`, `test_edge_integer_large` |
| bytearray/memoryview input | `test_edge_bytearray_input` |
| long hyphenated decode | `test_edge_long_hyphenated_decode` |

## Invariant 21 (Total Public API Safety)

| input class | test |
|---|---|
| encode hostile (None, -1, 1.5, True, [], {}, etc.) | `test_invariant21_encode_hostile_inputs` |
| decode hostile (None, 123, b"CR", [], {}, "???", "I*") | `test_invariant21_decode_hostile_inputs` |
| checksum_symbol hostile | `test_invariant21_checksum_symbol_hostile_inputs` |
| validate_checksum total (returns False) | `test_invariant21_validate_checksum_total` |
| negative integer | `test_invariant21_negative_integer` |

## Summary

- **148 tests collected** (`pytest --collect-only -q`)
- **134 tests pass** (14 skipped because integer vectors are tested
  separately under `test_vector_encode_int`)
- All 15 acceptance criteria have ≥1 test
- All 31 pinned test vectors are exercised
- Test-Vector Honesty Declaration is enforced by 7 dedicated tests
- Invariant 21 (total-safety) is covered by 5 dedicated tests
