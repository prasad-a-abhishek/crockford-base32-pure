# Test Gap Analysis — crockford-base32-pure

> **Card**: cycle_178/adversary/01 — VULN_AUDIT (Honest-pillar requirement)
> **Methodology**: For each of the 15 acceptance criteria (AC1-AC15)
> in `spec.md`, identify the test function(s) in
> `tests/test_crockford_base32.py` that exercise it. If 0 tests cover
> an AC, that's a finding.
>
> **Test inventory**: 148 collected tests across 7 categories
> (vector-encode, vector-decode, AC1-15, round-trip, edge,
> invariant-21, test-vector-honesty). 134 pass + 14 skipped (the
> 14 skipped are TV entries that are exercised in the opposite
> direction; no actual coverage loss).

## AC → test mapping

| AC | Spec criterion | Test function(s) | Coverage |
|----|----------------|-----------------|----------|
| AC1  | `encode(b"")` returns `""` | `test_ac1_empty_input` (line 216), `test_edge_empty_bytes_roundtrip` (line 344), `test_vector_encode_bytes[TV1]` (line 98) | **complete** (3 tests) |
| AC2  | `encode(b"f")` returns `"CR"` | `test_ac2_letter_f` (line 221), `test_vector_encode_bytes[TV4]` (line 98) | **complete** (2 tests) |
| AC3  | `encode(b"foobar")` returns `"CSQPYRK1E8"` | `test_ac3_foobar` (line 226), `test_vector_encode_bytes[TV10]` (line 98), `test_substitution_hyphen_stripping` (line 616) | **complete** (3 tests) |
| AC4  | `encode(b"\x00")` returns `"00"` | `test_ac4_single_zero_byte` (line 231), `test_vector_encode_bytes[TV2]` (line 98), `test_edge_single_byte_0x00` (line 355) | **complete** (3 tests) |
| AC5  | `encode(1024)` returns `"100"` | `test_ac5_integer_path` (line 236), `test_vector_encode_int[TV18]` (line 118) | **complete** (2 tests) |
| AC6  | `encode(b"f", checksum=True)` returns `"CR1"`; `checksum_symbol("CR")` returns `"1"` | `test_ac6_checksum_symbol` (line 241), `test_vector_encode_with_checksum_bytes[TV4]` (line 132), `test_substitution_I_equals_L_equals_1` (line 589) | **complete** (3 tests) |
| AC7  | `decode("CR")` returns `b"f"` | `test_ac7_basic_decode` (line 248), `test_vector_decode[TV21]` (line 172) | **complete** (2 tests) |
| AC8  | `decode("CSQPYRK1E8")` returns `b"foobar"` | `test_ac8_long_decode` (line 253), `test_vector_decode[TV26]` (line 172) | **complete** (2 tests) |
| AC9  | `decode("cR")` returns `b"f"` (case-insensitive) | `test_ac9_case_insensitive` (line 258), `test_vector_decode[TV22]` (line 172), `test_substitution_lowercase_round_trip` (line 610) | **complete** (3 tests) |
| AC10 | `decode("CSQ-PYRK-1E8")` returns `b"foobar"` (hyphens ignored) | `test_ac10_hyphens_ignored` (line 263), `test_substitution_hyphen_stripping` (line 616), `test_edge_long_hyphenated_decode` (line 470) | **complete** (3 tests) |
| AC11 | `decode("I")` returns `b""` (I/L=1 substitution; 5 bits, no full byte) | `test_ac11_i_l_substitution` (line 268), `test_vector_decode[TV23,TV24]` (line 172) | **complete** (2 tests) — note: also implicitly tests L, l, i (line 270-271) |
| AC12 | `decode("U")` raises `ValueError` (U is check-only, rejected in main body) | `test_ac12_u_in_main_body_rejected` (line 274), `test_vector_decode[TV27]` (line 172), `test_error_subclasses_value_error` (line 775) | **complete** (3 tests) |
| AC13 | `decode("*")` raises `ValueError` (extended `*` rejected in main body) | `test_ac13_extended_in_main_body_rejected` (line 281), `test_vector_decode[TV28]` (line 172), `test_substitution_extended_symbols_in_body_rejected` (line 624, parametrized over `*~$=`) | **complete** (3 tests) — `test_substitution_extended_symbols_in_body_rejected` covers **all 4** extended symbols, not just `*` |
| AC14 | `validate_checksum("CR1")` returns `True`; `validate_checksum("CR2")` returns `False` | `test_ac14_validate_checksum` (line 288), `test_edge_round_trip_with_checksum` (line 405, checks corruption), `test_substitution_extended_symbols_in_check_position` (line 635, parametrized over all 5 check values 0-4) | **complete** (3 tests) |
| AC15 | `encode(None)` / `encode(-1)` / `decode(None)` / `decode("???")` raise structured errors | `test_ac15_total_safety` (line 294), `test_invariant21_encode_hostile_inputs` (line 489, parametrized over 12 hostile types), `test_invariant21_decode_hostile_inputs` (line 520, parametrized over 8 hostile types), `test_invariant21_checksum_symbol_hostile_inputs` (line 539, parametrized over 9 hostile types), `test_invariant21_validate_checksum_total` (line 557), `test_invariant21_negative_integer` (line 575) | **complete** (6 tests) |

**All 15 ACs are covered by at least 2 tests each, and most are
covered by 3+ tests.** No AC has zero coverage.

## Additional coverage (beyond ACs)

The test suite also covers scenarios that the AC list does not
explicitly call out but are exercised:

| Extra scenario | Test |
|----------------|------|
| `encode(b"\xff")` returns `"ZW"` | `test_vector_encode_bytes[TV3]` |
| `encode(b"abc")` returns `"C5H66"` | `test_vector_encode_bytes[TV9]` |
| `encode(b"Hello, World!")` returns `"91JPRV3F5GG5EVVJDHJ22"` | `test_vector_encode_bytes[TV11]` |
| 256-byte sweep (`bytes(range(256))`) round-trip | `test_vector_encode_bytes[TV12]` + `test_vector_decode[TV12]` |
| 100 ASCII 'a' bytes round-trip | `test_vector_encode_bytes[TV13]` |
| Integer 0/1/31/32/2^32/2^64-1 paths | `test_vector_encode_int[TV14..TV20]`, `test_edge_integer_*` (lines 430-461) |
| `encode(b"", checksum=True)` returns `"0"` | `test_edge_empty_with_checksum_decodes_to_zero` (line 349) |
| `decode("0", checksum=True)` returns `b""` | same as above |
| 5/8/10-byte boundary all-zeros | `test_edge_5_byte_boundary_all_zero`, `test_edge_8_byte_boundary_all_zero`, `test_edge_10_byte_boundary_all_zero` |
| 100x `b"\xff"` round-trip | `test_edge_all_ff_round_trip` |
| 1000 random bytes (20 deterministic iterations) | `test_edge_1000_random_bytes_roundtrip` |
| 10000 random bytes (1 iteration) | `test_edge_10000_random_bytes_roundtrip` |
| `bytearray` and `memoryview` inputs | `test_edge_bytearray_input` |
| `decode("---")` returns `b""` (all-hyphens) | `test_substitution_hyphen_stripping` (line 619) |
| `decode("0-0-0-0-0-0-0-0")` returns 8 zero bytes | `test_substitution_hyphen_stripping` (line 621) |
| 5 extended check symbols (`*~$=U`) round-trip | `test_substitution_extended_symbols_in_check_position` (parametrized over 5 bodies) |
| Check symbol corruption (random byte) detected | `test_edge_round_trip_with_checksum` (corrupts and expects either raise or different output) |
| `ALPHABET` excludes `I L O U` | `test_alphabet_excludes_confusable_letters` |
| `ALPHABET` has exactly 32 chars | `test_alphabet_has_exactly_32_chars` |
| `EXTENDED` has exactly 5 chars | `test_extended_has_exactly_5_chars` |
| `EXTENDED` equals `"*~$=U"` | `test_extended_set_equals_spec` |
| `CrockfordBase32Error` subclasses `ValueError` | `test_error_subclasses_value_error` |
| `version()` returns `"1.0"` | `test_version_returns_spec_string` |

## Test-Vector Honesty Declaration guard (cycle_177 H-3 regression)

The test suite explicitly guards against the cycle_177 H-3 chronic
defect (entries that claim non-zero content but are actually all
zeros due to an `input_len` mislabeling):

| Guard | Test |
|-------|------|
| No `input_len` key in any TV | `test_vectors_honesty_no_input_len` (line 662) |
| Every TV has `input_hex` or `input_int` | `test_vectors_honesty_input_field_present` (line 671) |
| Every TV has a non-empty `description` | `test_vectors_honesty_description_present` (line 679) |
| Every TV has a `_provenance` URL | `test_vectors_honesty_provenance_present` (line 687) |
| All `_provenance` URLs reference the spec page | `test_vectors_honesty_spec_url_matches` (line 695) |
| Every `input_hex` is valid hex | `test_vectors_honesty_round_trip_description` (line 703) |
| First 5 TV descriptions match their bytes (hand-audit) | `test_vectors_honesty_first_5_descriptions_match_bytes` (line 722) |

## Honest-pillar coverage summary

| Honest-pillar requirement | Status |
|---------------------------|--------|
| ≥120 test floor | **148 tests** (collected) — exceeds by 23% |
| Every AC has ≥1 test | **all 15 ACs covered by 2-6 tests each** |
| Every spec test vector is a real test | **31/31 TVs are exercised** (TV1-31 via `_encode_entries` and `_decode_entries` filters) |
| Test-Vector Honesty Declaration guard | **7/7 guards present** (no `input_len`, fields present, descriptions match) |
| Invariant 21 (total safety) covered | **6 explicit tests** (encode hostile, decode hostile, checksum_symbol hostile, validate_checksum total, negative integer, AC15) |
| Round-trip stress (random bytes) | **2 tests** (1000 bytes x 20 iters, 10000 bytes x 1 iter) |
| Boundary cases (5/8/10 bytes) | **3 tests** |
| Adversarial fuzz (hostile types) | **30+ parametrized cases** across 3 hostile-input tests |

## Gaps identified (Low/Info severity)

The following **Low/Info-level** coverage gaps are noted. None
are Medium or above because each is either (a) the spec is silent
on the case, (b) the behavior is correct by design, or (c) the
gap is cosmetic (test count would be higher with more granularity
but the underlying behavior is already covered).

| Gap | Severity | Why it's not a defect |
|-----|----------|----------------------|
| No test for `encode(2**256)` or `encode(2**1024)` exact output | Low | `test_edge_integer_large` covers the bigint path with `2**64 - 1`; larger values are tested by `encode(2**256) == "2000...0"` (52 chars) verified in the fuzz run but not pinned as a test vector. Adding `test_encode_int_2_to_256` would be a **nice-to-have**, not required. |
| No test for `decode("C")` returning `b""` (single 5-bit symbol, no full byte) | Low | This is the same behavior as `decode("I")` (AC11) — 5 bits < 8, no byte emitted. The `test_ac11_i_l_substitution` test demonstrates the path. |
| No test for `decode("CRU")` (U in main body) | Low | `test_ac12_u_in_main_body_rejected` covers `U` in main body; the `CR` prefix is irrelevant. |
| No test for `encode_int(True)` raising `invalid_type` | Info | `test_invariant21_encode_hostile_inputs[True]` and `test_invariant21_negative_integer` cover the bool trap for `encode` and `encode_int` separately. The `encode_int` hostile case is implied by the parametrized `test_invariant21_encode_hostile_inputs` which routes `True` through `encode()` (which delegates to `encode_int`). |
| No test for `decode` of a string with mixed `I` and `L` in the same body | Low | `test_substitution_I_equals_L_equals_1` covers the equivalence; `decode("lI") == b"\x08"` is verified by the spec's substitution rules but not pinned as a test. |
| No test for `decode` of a string with a fullwidth `Ｒ` (Unicode 0xFF32) | Info | The alphabet is ASCII-only; non-ASCII is rejected. `test_substitution_lowercase_round_trip` covers case-insensitivity for the ASCII alphabet. Non-ASCII is tested in the fuzz run but not pinned. |
| No test for `decode` of a string with embedded NUL `\x00` | Info | `test_invariant21_decode_hostile_inputs` does not include `"\x00"`. Adding it would verify `code="invalid_character"`. Nice-to-have. |
| No test for `checksum_symbol` of `"I"` (I→1) | Low | `test_ac6_checksum_symbol` covers `checksum_symbol("CR")` returning `"1"`. The `I→1` substitution is implicit in the alphabet table and exercised by `decode("I") == b""` (AC11). |

**None of these gaps affect security or correctness.** They are
noted as **opportunities for future test expansion** if a future
cycle wants to push the test count above 148.

## Cross-verification of test count

```
$ python3 -m pytest --collect-only -q | tail -1
148 tests collected in 0.07s

$ python3 -m pytest -q
134 passed, 14 skipped in 0.13s
```

The 14 skipped are TV entries that are exercised in the *opposite*
direction (e.g. TV21 is a decode-direction vector, so the encode
test for TV21 is skipped; TV21 is then run via `test_vector_decode`).
**No actual coverage loss**: every TV has its non-skipped
counterpart running.

VERDICT-TEST-GAPS: 15/15 ACs covered, 31/31 TVs exercised,
7/7 honesty guards present, 0 Medium-or-higher gaps.
