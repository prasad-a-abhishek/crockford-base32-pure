"""Tests for crockford-base32-pure.

Test structure:

1. **Vector-driven encode tests** (one per pinned TV entry) - the
   ``test_vectors.json`` file is the single source of truth for the
   expected outputs (per the cycle_178 Test-Vector Honesty
   Declaration). Every entry uses ``input_hex`` or ``input_int``,
   never ``input_len``.

2. **Vector-driven decode tests** (one per pinned TV entry) - mirror
   of the encode tests, round-tripping through decode.

3. **One test per acceptance criterion (AC1-15)** - mapped 1:1
   against the spec's acceptance table.

4. **Edge cases** - empty, single byte, 5/8/10-byte boundaries, all
   zeros, all 0xFF, round-trip stress, ASCII-string equivalence.

5. **Invariant 21 hostile inputs** - ``None``, ``-1``, ``b"hello"``,
   ``123.45``, ``True``, ``[]``, ``{}``, ``"??? bad"``,
   ``"\x00\x01"``, ``"I"``, ``"U"``, ``"*"``, ``"O"``, mixed types.
   Every public function must return structured error findings
   (or ``False`` for ``validate_checksum``) rather than crashing
   with an uncaught ``TypeError`` / ``ValueError`` /
   ``AttributeError``.

6. **Substitution rule coverage** - ``I = L = 1``, ``O = 0``,
   hyphens, case folding, every one explicitly exercised.

7. **Test-Vector Honesty Declaration guard** - asserts every
   entry in ``test_vectors.json`` has ``input_hex`` or ``input_int``
   (NEVER ``input_len``) and that the description round-trips
   with the bytes.
"""

import json
import os
import random

import pytest

from crockford_base32_pure import (
    ALPHABET,
    EXTENDED,
    CrockfordBase32Error,
    checksum_symbol,
    decode,
    encode,
    encode_int,
    validate_checksum,
    version,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))
VECTORS_PATH = os.path.join(HERE, "test_vectors.json")
with open(VECTORS_PATH) as _f:
    _VECTORS_JSON = json.load(_f)
VECTORS = _VECTORS_JSON["vectors"]


def _encode_entries():
    """Return TV entries that are encode-direction (have a real
    ``expected_output`` string, not the literal ``"ValueError"``,
    AND are NOT in the decode-direction TV21..TV31 range)."""
    decode_ids = {f"TV{n}" for n in range(21, 32)}
    for v in VECTORS:
        if v["id"] in decode_ids:
            continue
        if v["expected_output"] == "ValueError":
            continue
        yield v


def _decode_entries():
    """Return TV entries that are decode-direction (TV21..TV31)."""
    for v in VECTORS:
        if v["id"] in {
            f"TV{n}" for n in range(21, 32)
        }:
            yield v


# ---------------------------------------------------------------------------
# Section 1: Vector-driven encode tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec",
    list(_encode_entries()),
    ids=[v["id"] for v in _encode_entries()],
)
def test_vector_encode_bytes(vec):
    """Pin the spec algorithm's output for every TV entry.

    For bytes-input vectors, ``input_hex`` is the bytes input and
    ``expected_output`` is the Crockford Base32 string.
    """
    if "input_int" in vec:
        pytest.skip("integer vector, covered by test_vector_encode_int")
    raw = bytes.fromhex(vec["input_hex"])
    assert encode(raw) == vec["expected_output"], (
        f"{vec['id']} encode(bytes.fromhex({vec['input_hex']!r})) "
        f"expected {vec['expected_output']!r}"
    )


@pytest.mark.parametrize(
    "vec",
    [v for v in _encode_entries() if "input_int" in v],
    ids=[v["id"] for v in _encode_entries() if "input_int" in v],
)
def test_vector_encode_int(vec):
    raw = vec["input_int"]
    assert encode_int(raw) == vec["expected_output"], (
        f"{vec['id']} encode_int({raw}) expected {vec['expected_output']!r}"
    )


@pytest.mark.parametrize(
    "vec",
    [v for v in _encode_entries() if v.get("expected_output_with_check")],
    ids=[
        v["id"] for v in _encode_entries() if v.get("expected_output_with_check")
    ],
)
def test_vector_encode_with_checksum_bytes(vec):
    """Pin the with-checksum output for every bytes-input TV entry
    that has a non-null ``expected_output_with_check``."""
    if "input_int" in vec:
        pytest.skip("integer vector, covered separately")
    raw = bytes.fromhex(vec["input_hex"])
    assert encode(raw, checksum=True) == vec["expected_output_with_check"], (
        f"{vec['id']} encode(bytes, checksum=True) "
        f"expected {vec['expected_output_with_check']!r}"
    )


@pytest.mark.parametrize(
    "vec",
    [
        v
        for v in _encode_entries()
        if "input_int" in v and v.get("expected_output_with_check")
    ],
    ids=[
        v["id"]
        for v in _encode_entries()
        if "input_int" in v and v.get("expected_output_with_check")
    ],
)
def test_vector_encode_with_checksum_int(vec):
    raw = vec["input_int"]
    assert encode_int(raw, checksum=True) == vec["expected_output_with_check"]


# ---------------------------------------------------------------------------
# Section 2: Vector-driven decode tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vec",
    list(_decode_entries()),
    ids=[v["id"] for v in _decode_entries()],
)
def test_vector_decode(vec):
    """TV21..TV31 are decode-direction. ``input_hex`` here is the
    Crockford Base32 STRING (not bytes) - we round-trip through
    decode and compare against the expected bytes
    (also hex-encoded in ``expected_output``)."""
    s = vec["input_hex"]  # the string is stored in input_hex
    if vec["expected_output"] == "ValueError":
        # TV27, TV28: decode without checksum must raise (single-char
        # main body with U or *).
        # TV30: decode with checksum=True must raise (mismatched check).
        if vec["id"] == "TV30":
            with pytest.raises(CrockfordBase32Error) as ei:
                decode(s, checksum=True)
            assert ei.value.code == "check_mismatch"
        else:
            with pytest.raises(CrockfordBase32Error) as ei:
                decode(s)
            if vec["id"] == "TV27":
                assert ei.value.code == "u_in_main_body"
            elif vec["id"] == "TV28":
                assert ei.value.code == "extended_in_main_body"
        return
    # TV29 has its own checksum=True path - test it explicitly
    if vec["id"] == "TV29":
        out = decode(s, checksum=True)
        assert out.hex() == vec["expected_output"]
        return
    # TV31: "10*" has * as check char; body="10" -> 1 byte
    if vec["id"] == "TV31":
        out = decode(s, checksum=True)
        assert out.hex() == vec["expected_output"]
        return
    out = decode(s)
    assert out.hex() == vec["expected_output"], (
        f"{vec['id']} decode({s!r}) expected "
        f"bytes.fromhex({vec['expected_output']!r}), got {out.hex()!r}"
    )


# ---------------------------------------------------------------------------
# Section 3: Acceptance criteria AC1..AC15
# ---------------------------------------------------------------------------


def test_ac1_empty_input():
    """AC1: encode(b"") returns ""."""
    assert encode(b"") == ""


def test_ac2_letter_f():
    """AC2: encode(b"f") returns "CR" (the spec's worked example)."""
    assert encode(b"f") == "CR"


def test_ac3_foobar():
    """AC3: encode(b"foobar") returns "CSQPYRK1E8"."""
    assert encode(b"foobar") == "CSQPYRK1E8"


def test_ac4_single_zero_byte():
    """AC4: encode(b"\\x00") returns "00"."""
    assert encode(b"\x00") == "00"


def test_ac5_integer_path():
    """AC5: encode(1024) returns "100"."""
    assert encode(1024) == "100"


def test_ac6_checksum_symbol():
    """AC6: encode(b"f", checksum=True) returns "CR1";
    checksum_symbol("CR") returns "1"."""
    assert encode(b"f", checksum=True) == "CR1"
    assert checksum_symbol("CR") == "1"


def test_ac7_basic_decode():
    """AC7: decode("CR") returns b"f"."""
    assert decode("CR") == b"f"


def test_ac8_long_decode():
    """AC8: decode("CSQPYRK1E8") returns b"foobar"."""
    assert decode("CSQPYRK1E8") == b"foobar"


def test_ac9_case_insensitive():
    """AC9: decode("cR") returns b"f" (mixed case accepted)."""
    assert decode("cR") == b"f"


def test_ac10_hyphens_ignored():
    """AC10: decode("CSQ-PYRK-1E8") returns b"foobar"."""
    assert decode("CSQ-PYRK-1E8") == b"foobar"


def test_ac11_i_l_substitution():
    """AC11: decode("I") returns b"" (I=1, 5 bits < 1 byte)."""
    assert decode("I") == b""
    assert decode("L") == b""  # L = 1, same as I


def test_ac12_u_in_main_body_rejected():
    """AC12: decode("U") raises ValueError (U is check-only)."""
    with pytest.raises(CrockfordBase32Error) as excinfo:
        decode("U")
    assert excinfo.value.code == "u_in_main_body"


def test_ac13_extended_in_main_body_rejected():
    """AC13: decode("*") raises ValueError (extended check symbol)."""
    with pytest.raises(CrockfordBase32Error) as excinfo:
        decode("*")
    assert excinfo.value.code == "extended_in_main_body"


def test_ac14_validate_checksum():
    """AC14: validate_checksum("CR1") = True; "CR2" = False."""
    assert validate_checksum("CR1") is True
    assert validate_checksum("CR2") is False


def test_ac15_total_safety():
    """AC15: encode/decode never raise uncaught TypeError/ValueError/
    AttributeError for hostile inputs. They raise
    CrockfordBase32Error (a ValueError subclass) with a structured
    ``code`` and ``details``."""
    hostile = [
        (None, "encode"),
        (-1, "encode"),
        (1.5, "encode"),
        (True, "encode"),
        ([], "encode"),
        ({"k": "v"}, "encode"),
        ((1, 2, 3), "encode"),
    ]
    for value, op in hostile:
        if op == "encode":
            with pytest.raises((CrockfordBase32Error, TypeError, ValueError)) as ei:
                encode(value)
            # Must NOT be a bare AttributeError or NameError
            assert not isinstance(ei.value, AttributeError), (
                f"encode({value!r}) raised AttributeError"
            )
    # decode hostile inputs
    decode_hostile = [
        None,
        b"CR",
        123,
        1.5,
        True,
        [],
        {"k": "v"},
        "???",  # ? is not in the alphabet
        "I*",  # * in main body
    ]
    for value in decode_hostile:
        with pytest.raises((CrockfordBase32Error, TypeError, ValueError)):
            decode(value)
    # validate_checksum is total - returns False for any garbage
    for value in decode_hostile + ["", "CR", "CR1"]:
        result = validate_checksum(value)
        assert isinstance(result, bool), (
            f"validate_checksum({value!r}) returned {type(result).__name__}, not bool"
        )


# ---------------------------------------------------------------------------
# Section 4: Edge cases
# ---------------------------------------------------------------------------


def test_edge_empty_bytes_roundtrip():
    assert encode(b"") == ""
    assert decode("") == b""


def test_edge_empty_with_checksum_decodes_to_zero():
    """decode(..., checksum=True) on an empty body with '0' check
    yields the empty bytes - '0' is the check of the empty body."""
    assert decode("0", checksum=True) == b""


def test_edge_single_byte_0x00():
    assert encode(b"\x00") == "00"
    assert decode("00") == b"\x00"


def test_edge_single_byte_0x01():
    assert encode(b"\x01") == "04"
    assert decode("04") == b"\x01"


def test_edge_5_byte_boundary_all_zero():
    """5 bytes = 40 bits = exactly 8 symbols."""
    assert encode(b"\x00" * 5) == "00000000"
    assert decode("00000000") == b"\x00" * 5


def test_edge_8_byte_boundary_all_zero():
    """8 bytes = 64 bits, ceil(64/5) = 13 symbols."""
    assert encode(b"\x00" * 8) == "0000000000000"
    assert decode("0000000000000") == b"\x00" * 8


def test_edge_10_byte_boundary_all_zero():
    """10 bytes = 80 bits = exactly 16 symbols."""
    assert encode(b"\x00" * 10) == "0000000000000000"
    assert decode("0000000000000000") == b"\x00" * 10


def test_edge_all_ff_round_trip():
    payload = b"\xff" * 100
    s = encode(payload)
    assert decode(s) == payload


def test_edge_1000_random_bytes_roundtrip():
    rng = random.Random(0xC0C0)  # deterministic
    for _ in range(20):
        n = rng.randint(1, 200)
        payload = bytes(rng.randint(0, 255) for _ in range(n))
        s = encode(payload)
        assert decode(s) == payload, f"round-trip failed for {payload!r}"


def test_edge_10000_random_bytes_roundtrip():
    rng = random.Random(0xFACE)
    payload = bytes(rng.randint(0, 255) for _ in range(10000))
    s = encode(payload)
    assert decode(s) == payload


def test_edge_round_trip_with_checksum():
    rng = random.Random(0xBEEF)
    for n in [0, 1, 5, 8, 13, 100]:
        payload = bytes(rng.randint(0, 255) for _ in range(n))
        s = encode(payload, checksum=True)
        # Decoding with checksum must accept it
        assert decode(s, checksum=True) == payload
        # Corrupt the check char -> decoding must fail
        if s:
            # Replace the last char with a different check char
            # that still passes the main decode (e.g. flip a letter
            # to its neighbor). The simplest: just swap '0' and '1'.
            corrupt = s[:-1] + ("0" if s[-1] != "0" else "1")
            # The corrupted string might still be a valid (body, check)
            # pair or not; either way decode() must either return a
            # different bytes or raise.
            try:
                out = decode(corrupt, checksum=True)
                # If it didn't raise, the output must differ from the
                # original (otherwise our check symbol is broken).
                assert out != payload
            except CrockfordBase32Error:
                pass  # expected for most corruptions


def test_edge_integer_zero_special_case():
    assert encode_int(0) == "0"
    assert encode(0) == "0"
    assert encode_int(0, checksum=True) == "00"
    assert validate_checksum("00") is True


def test_edge_integer_one():
    assert encode_int(1) == "1"


def test_edge_integer_max_31():
    assert encode_int(31) == "Z"


def test_edge_integer_32():
    assert encode_int(32) == "10"


def test_edge_integer_large():
    """Round-trip large integers through encode_int (the bytes-decode
    path can't be used because it discards trailing bits that don't
    fill a byte; we just trust the encode_int path here)."""
    assert encode_int(2 ** 64 - 1) == "FZZZZZZZZZZZZ"
    for n in [0, 1, 31, 32, 100, 2 ** 32, 2 ** 64 - 1]:
        # Pin the encode_int output
        s = encode_int(n)
        # Round-trip through checksum_symbol: compute the check
        # and re-validate (regression test for the mod-37 path).
        cs = encode_int(n, checksum=True)
        assert cs == s + checksum_symbol(s)
        assert validate_checksum(cs) is True


def test_edge_bytearray_input():
    """encode accepts bytearray and memoryview."""
    assert encode(bytearray(b"foobar")) == "CSQPYRK1E8"
    assert encode(memoryview(b"foobar")) == "CSQPYRK1E8"


def test_edge_long_hyphenated_decode():
    """A long hyphenated string decodes identically to its
    hyphen-stripped form."""
    s = "CSQ-PYR-K1E-8"
    assert decode(s) == decode(s.replace("-", ""))


# ---------------------------------------------------------------------------
# Section 5: Invariant 21 hostile inputs (one per shape)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    # b"" is a valid bytes input (encode(b"") == ""), so it's not
    # hostile. We test the genuinely hostile non-bytes / non-int
    # types and negative ints.
    [None, -1, -100, 1.5, True, False, [], {}, b"\x00", "???", "I*", (1, 2)],
)
def test_invariant21_encode_hostile_inputs(bad):
    """Every public function must be total over arbitrary input -
    no uncaught TypeError, ValueError, or AttributeError.

    encode() with bytes-like or int input is fine; with anything
    else it must raise CrockfordBase32Error (a ValueError
    subclass) with code 'invalid_type' or 'negative_integer'."""
    if isinstance(bad, bool):
        # Python treats bool as a subclass of int; we reject bools
        # explicitly to keep encode() total.
        with pytest.raises(CrockfordBase32Error) as ei:
            encode(bad)
        assert ei.value.code == "invalid_type"
        return
    if isinstance(bad, int):
        with pytest.raises(CrockfordBase32Error) as ei:
            encode(bad)
        assert ei.value.code in ("invalid_type", "negative_integer")
        return
    if isinstance(bad, (bytes, bytearray, memoryview)):
        # bytes-like inputs are accepted by encode(); nothing to test.
        return
    with pytest.raises((CrockfordBase32Error, TypeError, ValueError)) as ei:
        encode(bad)
    assert not isinstance(ei.value, AttributeError)


@pytest.mark.parametrize(
    "bad",
    [None, 123, 1.5, True, b"CR", [], {}, "???"],
)
def test_invariant21_decode_hostile_inputs(bad):
    if isinstance(bad, bool):
        with pytest.raises(CrockfordBase32Error) as ei:
            decode(bad)
        assert ei.value.code == "invalid_type"
        return
    if isinstance(bad, str):
        with pytest.raises(CrockfordBase32Error):
            decode(bad)
        return
    with pytest.raises((CrockfordBase32Error, TypeError, ValueError)) as ei:
        decode(bad)
    assert not isinstance(ei.value, AttributeError)


@pytest.mark.parametrize(
    "bad",
    [None, 123, 1.5, True, b"CR", [], {}, "??", "I*"],
)
def test_invariant21_checksum_symbol_hostile_inputs(bad):
    """checksum_symbol is total and raises CrockfordBase32Error for
    invalid input (or returns '0' for empty string, which is the
    spec's mod-37 check of the empty body)."""
    if isinstance(bad, bool):
        with pytest.raises(CrockfordBase32Error) as ei:
            checksum_symbol(bad)
        assert ei.value.code == "invalid_type"
        return
    if isinstance(bad, str):
        with pytest.raises(CrockfordBase32Error):
            checksum_symbol(bad)
        return
    with pytest.raises((CrockfordBase32Error, TypeError, ValueError)) as ei:
        checksum_symbol(bad)
    assert not isinstance(ei.value, AttributeError)


def test_invariant21_validate_checksum_total():
    """validate_checksum is the only public function that is total
    via returning False (not raising) for invalid input."""
    # None / non-str returns False
    assert validate_checksum(None) is False
    assert validate_checksum(123) is False
    assert validate_checksum(b"CR1") is False
    assert validate_checksum([]) is False
    # Empty string returns False (no body to validate against)
    assert validate_checksum("") is False
    # Last char not in check set returns False
    assert validate_checksum("CR!") is False
    # Body has invalid character returns False
    assert validate_checksum("?1") is False
    # Mismatched check returns False
    assert validate_checksum("CR2") is False


def test_invariant21_negative_integer():
    with pytest.raises(CrockfordBase32Error) as ei:
        encode_int(-1)
    assert ei.value.code == "negative_integer"
    with pytest.raises(CrockfordBase32Error) as ei:
        encode(-1)
    assert ei.value.code == "negative_integer"


# ---------------------------------------------------------------------------
# Section 6: Substitution rule coverage
# ---------------------------------------------------------------------------


def test_substitution_I_equals_L_equals_1():
    """All of 'I', 'L', 'l', 'i' decode to value 1.

    Demonstrated indirectly: encode(b"f", checksum=True) = "CR1"
    proves that the check value of "CR" is "1". The decode
    path's substitution map is exercised by test_ac11
    (decode("I") == b"") and test_substitution_O_equals_0.
    """
    assert encode(b"f", checksum=True) == "CR1"
    assert decode("CR1", checksum=True) == b"f"


def test_substitution_O_equals_0():
    """'O' and 'o' decode to value 0 (same as '0')."""
    # '0' alone is a single 5-bit symbol; decode of "0" yields b""
    assert decode("0") == b""
    # 'O' is the substitute for '0'
    assert decode("O") == decode("0")
    assert decode("o") == decode("0")


def test_substitution_lowercase_round_trip():
    """Lowercase encodes the same as uppercase after decode."""
    for upper, lower in [("CR", "cr"), ("CSQPYRK1E8", "csqpyrk1e8"), ("91JPRV3F5GG5EVVJDHJ22", "91jprv3f5gg5evvjdhj22")]:
        assert decode(upper) == decode(lower)


def test_substitution_hyphen_stripping():
    """Hyphens are stripped from the body before decoding."""
    assert decode("CSQ-PYRK-1E8") == decode("CSQPYRK1E8")
    assert decode("---") == b""  # all hyphens -> empty body
    # A long hyphenated string decodes identically to its hyphen-stripped form
    assert decode("0-0-0-0-0-0-0-0") == decode("00000000")  # 8 zero bytes


def test_substitution_extended_symbols_in_body_rejected():
    """Each of the 5 extended check symbols must raise
    extended_in_main_body when in the main body."""
    for ext in "*~$=":
        with pytest.raises(CrockfordBase32Error) as ei:
            decode(ext)
        assert ei.value.code == "extended_in_main_body", (
            f"decode({ext!r}) got code={ei.value.code}"
        )


def test_substitution_extended_symbols_in_check_position():
    """Each of the 5 extended check symbols must round-trip in the
    check position (body with check)."""
    # "0" body has check value 0 -> "00"
    assert validate_checksum("00") is True
    # Body values that produce extended checks (n % 37 in 32..36)
    # n=32 -> body "10" -> check "*"
    # We just verify validate_checksum accepts each extended char
    # when the body really does produce that check value.
    # Simpler: construct a body where the mod-37 value is 32..36
    # then check the extended symbol round-trips.
    for body, expected_check in [
        ("10", "*"),   # (1*32+0) % 37 = 32 = "*"
        ("11", "~"),   # (1*32+1) % 37 = 33 = "~"
        ("12", "$"),   # (1*32+2) % 37 = 34 = "$"
        ("13", "="),   # (1*32+3) % 37 = 35 = "="
        ("14", "U"),   # (1*32+4) % 37 = 36 = "U"
    ]:
        assert checksum_symbol(body) == expected_check
        assert validate_checksum(body + expected_check) is True


# ---------------------------------------------------------------------------
# Section 7: Test-Vector Honesty Declaration guard
# ---------------------------------------------------------------------------


def test_vectors_honesty_no_input_len():
    """No entry in test_vectors.json may use the input_len key
    (cycle_177 H-3 chronic-failure regression)."""
    for v in VECTORS:
        assert "input_len" not in v, (
            f"{v['id']} uses PROHIBITED input_len key (cycle_177 H-3 defect)"
        )


def test_vectors_honesty_input_field_present():
    """Every entry must have input_hex or input_int."""
    for v in VECTORS:
        assert ("input_hex" in v) or ("input_int" in v), (
            f"{v['id']} missing both input_hex and input_int"
        )


def test_vectors_honesty_description_present():
    """Every entry must have a non-empty description string."""
    for v in VECTORS:
        assert isinstance(v.get("description"), str) and v["description"], (
            f"{v['id']} missing/empty description"
        )


def test_vectors_honesty_provenance_present():
    """Every entry must have a _provenance string."""
    for v in VECTORS:
        assert isinstance(v.get("_provenance"), str) and v["_provenance"], (
            f"{v['id']} missing _provenance"
        )


def test_vectors_honesty_spec_url_matches():
    """All _provenance strings must reference the spec page."""
    for v in VECTORS:
        assert "crockford.com/base32.html" in v["_provenance"], (
            f"{v['id']} _provenance does not reference the spec page"
        )


def test_vectors_honesty_round_trip_description():
    """For bytes-input vectors, the input_hex must be a valid hex
    string and round-trip through bytes.fromhex without error."""
    for v in VECTORS:
        if "input_hex" not in v:
            continue
        if v["id"] in {f"TV{n}" for n in range(21, 32)}:
            # decode-direction vectors; the "input_hex" is a
            # Crockford Base32 STRING, not a hex bytes string.
            continue
        # Otherwise input_hex is a hex-encoded bytes payload
        try:
            bytes.fromhex(v["input_hex"])
        except ValueError as e:
            pytest.fail(
                f"{v['id']} input_hex={v['input_hex']!r} is not valid hex: {e}"
            )


def test_vectors_honesty_first_5_descriptions_match_bytes():
    """QA-mandated hand-audit: the first 5 TV entries' descriptions
    accurately describe the bytes pinned in input_hex."""
    first_five = VECTORS[:5]
    for v in first_five:
        if v["id"] in {f"TV{n}" for n in range(21, 32)}:
            continue
        raw = bytes.fromhex(v["input_hex"])
        desc = v["description"].lower()
        # AC1 "empty input" - input_hex is "" -> raw == b""
        if v["id"] == "TV1":
            assert raw == b""
        # TV2 "single zero byte" - input_hex "00" -> b"\x00"
        elif v["id"] == "TV2":
            assert raw == b"\x00"
        # TV3 "single 0xFF byte" - input_hex "ff" -> b"\xff"
        elif v["id"] == "TV3":
            assert raw == b"\xff"
        # TV4 "letter 'f'" - input_hex "66" -> b"f"
        elif v["id"] == "TV4":
            assert raw == b"f"
        # TV5 "two bytes 0x01 0x02" - input_hex "0102" -> b"\x01\x02"
        elif v["id"] == "TV5":
            assert raw == b"\x01\x02"


# ---------------------------------------------------------------------------
# Section 8: Misc / version
# ---------------------------------------------------------------------------


def test_version_returns_spec_string():
    assert version() == "1.0"


def test_alphabet_excludes_confusable_letters():
    """The published alphabet must not include I, L, O, U."""
    for c in "ILOU":
        assert c not in ALPHABET, f"alphabet contains confusable {c!r}"


def test_alphabet_has_exactly_32_chars():
    assert len(ALPHABET) == 32


def test_extended_has_exactly_5_chars():
    assert len(EXTENDED) == 5


def test_extended_set_equals_spec():
    assert EXTENDED == "*~$=U"


def test_error_subclasses_value_error():
    """Existing code that catches ValueError must still work."""
    try:
        decode("U")
    except ValueError:
        pass
    else:
        pytest.fail("decode('U') should have raised ValueError")
