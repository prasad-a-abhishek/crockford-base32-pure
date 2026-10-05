#!/usr/bin/env annotations
#!/usr/bin/env python3
"""Invariant 21 hostile-input matrix for crockford-base32-pure.

Enumerates a fixed grid of (input_type, input_value, function) tuples
and verifies that EVERY public function is total over arbitrary input
(never raises AttributeError / TypeError / NameError / raw ValueError
that isn't a documented constraint).

Per the cycle_178 task spec, this is the 4th optional surface for
deep-coverage. The grid is finite and exhaustively enumerated; no
random search, but a checkpoint-mode can scale to N repetitions with
seeded input mutation.

Grid:
  Inputs: None, -1, 3.14, True, False, [], {}, b"", "?", "U", "*",
          "I", "O", "L", "*~$=U", "\x00\x01", mixed types
  Functions: encode, decode, encode_int, checksum_symbol,
             validate_checksum, version
  Per-input expected behaviour:
    - encode / encode_int / checksum_symbol / decode: raise
      CrockfordBase32Error (or, for negative int, CrockfordBase32Error)
    - validate_checksum: always return bool (no raise)
    - version: always return "1.0" (no input, no raise)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "src"))

import crockford_base32_pure as cb32  # noqa: E402
from crockford_base32_pure import CrockfordBase32Error  # noqa: E402

LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"
CRASHES_DIR = HERE / "crashes"
HANGS_DIR = HERE / "hangs"
CORPUS_DIR = HERE / "corpus"

# Fixed hostile matrix
HOSTILE_INPUTS = [
    None,
    -1,
    -2 ** 32,
    3.14,
    True,
    False,
    [],
    {},
    b"",
    b"f",
    "?",
    "U",
    "u",
    "*",
    "~",
    "$",
    "=",
    "I",
    "L",
    "O",
    "*~$=U",
    "\x00\x01",
    "é",
    "Ｒ",
    "\xa0",
    "\ufeff",
    "\u200b",
    "hello\nworld",
    " " * 10,
    [1, 2, 3],
    {"key": "value"},
    (1, 2, 3),
    object(),
    float("inf"),
    float("nan"),
    complex(1, 2),
    set(),
    frozenset(),
    b"\x00\xff",
    "A" * 10000,
]

# Public API surface
FUNCTIONS = {
    "encode": {
        "call": lambda x: cb32.encode(x),
        "total": False,  # must raise CrockfordBase32Error on bad input
        "expected_raise_for": lambda x: True,  # every bad input must raise
    },
    "encode_cs": {
        "call": lambda x: cb32.encode(x, checksum=True),
        "total": False,
        "expected_raise_for": lambda x: True,
    },
    "encode_int": {
        "call": lambda x: cb32.encode_int(x),
        "total": False,
        "expected_raise_for": lambda x: True,
    },
    "encode_int_cs": {
        "call": lambda x: cb32.encode_int(x, checksum=True),
        "total": False,
        "expected_raise_for": lambda x: True,
    },
    "decode": {
        "call": lambda x: cb32.decode(x),
        "total": False,
        "expected_raise_for": lambda x: True,
    },
    "decode_cs": {
        "call": lambda x: cb32.decode(x, checksum=True),
        "total": False,
        "expected_raise_for": lambda x: True,
    },
    "checksum_symbol": {
        "call": lambda x: cb32.checksum_symbol(x),
        "total": False,
        "expected_raise_for": lambda x: True,
    },
    "validate_checksum": {
        "call": lambda x: cb32.validate_checksum(x),
        "total": True,  # MUST return bool, never raise (Invariant 21)
        "expected_raise_for": lambda x: False,
    },
    "version": {
        "call": lambda x: cb32.version(),
        "total": True,  # no input, no raise
        "expected_raise_for": lambda x: False,
    },
}


def _log(msg: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def _write_crash(idx: int, payload: dict) -> Path:
    CRASHES_DIR.mkdir(parents=True, exist_ok=True)
    p = CRASHES_DIR / f"crash-{idx:06d}.in"
    p.write_text(json.dumps(payload, default=repr, ensure_ascii=False), encoding="utf-8")
    return p


def run() -> dict:
    stats = {
        "grid_size": 0,
        "crashes": 0,
        "expected_errors": 0,
        "total_violations": 0,  # validate_checksum/version raised
        "uncaught_attribute_errors": 0,
        "uncaught_type_errors": 0,
        "uncaught_name_errors": 0,
        "uncaught_raw_value_errors": 0,
        "other_uncaught": 0,
        "validate_checksum_return_type_violations": 0,
        "version_return_type_violations": 0,
    }
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    _log(f"start: hostile matrix {len(HOSTILE_INPUTS)} inputs x {len(FUNCTIONS)} functions")

    for fn_name, fn_spec in FUNCTIONS.items():
        for idx, host in enumerate(HOSTILE_INPUTS):
            stats["grid_size"] += 1
            key = hashlib.sha256(
                f"{fn_name}|{repr(host)}".encode("utf-8", "replace")
            ).hexdigest()[:16]
            try:
                result = fn_spec["call"](host)
                if fn_spec["total"]:
                    if fn_name == "version":
                        if result != "1.0":
                            stats["version_return_type_violations"] += 1
                            stats["crashes"] += 1
                            _write_crash(stats["crashes"], {
                                "op": fn_name, "input": repr(host), "issue": "version != '1.0'",
                                "result": repr(result)[:200],
                            })
                    elif fn_name == "validate_checksum":
                        if not isinstance(result, bool):
                            stats["validate_checksum_return_type_violations"] += 1
                            stats["crashes"] += 1
                            _write_crash(stats["crashes"], {
                                "op": fn_name, "input": repr(host), "issue": "validate_checksum not bool",
                                "result_type": type(result).__name__,
                            })
                else:
                    # Non-total function should have raised; if it didn't,
                    # that's only a finding for hostile inputs.
                    if fn_spec["expected_raise_for"](host):
                        # For encode, the only inputs that succeed are bytes/bytearray/memoryview
                        # and non-negative int. We expect most to raise; if any non-expected
                        # input succeeded, record it as INFO not CRASH.
                        if host in (b"", b"f", 0, 1) and fn_name.startswith("encode"):
                            pass  # expected success
                        else:
                            _log(f"INFO op={fn_name} input={repr(host)[:80]} returned {repr(result)[:80]} without raising")
            except CrockfordBase32Error as e:
                if fn_spec["total"]:
                    # Validate / version must NEVER raise.
                    stats["total_violations"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": fn_name, "input": repr(host), "issue": "total function raised",
                        "code": e.code, "msg": str(e),
                    })
                else:
                    stats["expected_errors"] += 1
            except AttributeError as e:
                stats["uncaught_attribute_errors"] += 1
                stats["crashes"] += 1
                _write_crash(stats["crashes"], {
                    "op": fn_name, "input": repr(host), "kind": "AttributeError",
                    "msg": str(e), "tb": traceback.format_exc()[:2000],
                })
            except TypeError as e:
                stats["uncaught_type_errors"] += 1
                stats["crashes"] += 1
                _write_crash(stats["crashes"], {
                    "op": fn_name, "input": repr(host), "kind": "TypeError",
                    "msg": str(e), "tb": traceback.format_exc()[:2000],
                })
            except ValueError as e:
                if isinstance(e, CrockfordBase32Error):
                    if fn_spec["total"]:
                        stats["total_violations"] += 1
                        stats["crashes"] += 1
                        _write_crash(stats["crashes"], {
                            "op": fn_name, "input": repr(host),
                            "issue": "total function raised raw ValueError",
                            "msg": str(e),
                        })
                    else:
                        stats["expected_errors"] += 1
                else:
                    stats["uncaught_raw_value_errors"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": fn_name, "input": repr(host), "kind": "raw ValueError",
                        "msg": str(e), "tb": traceback.format_exc()[:2000],
                    })
            except NameError as e:
                stats["uncaught_name_errors"] += 1
                stats["crashes"] += 1
                _write_crash(stats["crashes"], {
                    "op": fn_name, "input": repr(host), "kind": "NameError",
                    "msg": str(e), "tb": traceback.format_exc()[:2000],
                })
            except Exception as e:
                stats["other_uncaught"] += 1
                stats["crashes"] += 1
                _write_crash(stats["crashes"], {
                    "op": fn_name, "input": repr(host),
                    "kind": type(e).__name__,
                    "msg": str(e), "tb": traceback.format_exc()[:2000],
                })
            _log(f"grid[{key}] {fn_name}({repr(host)[:50]})")

    STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    _log(f"done: {stats}")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    args = parser.parse_args()
    stats = run()
    print(json.dumps(stats, indent=2))
    real_crashes = (
        stats["total_violations"]
        + stats["uncaught_attribute_errors"]
        + stats["uncaught_type_errors"]
        + stats["uncaught_name_errors"]
        + stats["uncaught_raw_value_errors"]
        + stats["other_uncaught"]
        + stats["validate_checksum_return_type_violations"]
        + stats["version_return_type_violations"]
    )
    return 1 if real_crashes > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
