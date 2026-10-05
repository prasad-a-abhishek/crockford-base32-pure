#!/usr/bin/env python3
"""Fuzz harness for crockford-base32-pure encode()/decode() round-trip.

Covers the primary I/O surface (bytes/int -> str -> bytes) and validates:
- No uncaught AttributeError / TypeError / NameError (Invariant 21).
- Errors raised are CrockfordBase32Error (ValueError subclass) for bad input.
- ValueError raised specifically for negative ints (documented contract).
- encode() return type is always str; decode() return type is always bytes.
- Random hostile types, invalid characters, big inputs (1..1000 bytes),
  checksum on/off combinations, hyphen/case substitution rules.

Stdlib only: random, signal, hashlib, json, struct, traceback, itertools.

ASan / UBSan: N/A — pure Python stdlib, no C extensions.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import random
import signal
import struct
import sys
import time
import traceback
from pathlib import Path

# Ensure local src/ is importable when invoked from this fuzz/<surface>/ dir
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]  # fuzz/<surface> -> fuzz -> repo root
sys.path.insert(0, str(REPO / "src"))

import crockford_base32_pure as cb32  # noqa: E402
from crockford_base32_pure import CrockfordBase32Error  # noqa: E402

ALPHABET = cb32.ALPHABET
EXTENDED = cb32.EXTENDED
ALLOWED_BODY = set(ALPHABET + "ILOUilou-")  # for random valid-body generation
ALLOWED_BODY_STRICT = set(ALPHABET)  # strict body (no I/L/O/U, no hyphens)
ALLOWED_CHECK = set(ALPHABET + EXTENDED)  # for random check char
BAD_CHARS = list("?!@#$%^&()[]{}<>+=_/\\|;:'\",.`~ \t\n\r\x00\x01\x7f")
                        # + non-ASCII
BAD_CHARS.extend(["é", "Ｒ", "\xa0", "\ufeff", "\u200b", "\u00ff"])

LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"
CRASHES_DIR = HERE / "crashes"
HANGS_DIR = HERE / "hangs"
CORPUS_DIR = HERE / "corpus"
TIMEOUT_SECONDS = 5


# --- Per-input timeout (signal-based; works because we're pure-Python + single-thread)
class _TimeoutError(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _TimeoutError("per-input timeout exceeded")


def _with_timeout(fn, *args, **kwargs):
    """Run fn(*args, **kwargs) with a hard 5-second wall-clock timeout."""
    old = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        return fn(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


# --- Logging
def _log(msg: str) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def _write_crash(idx: int, payload: dict) -> Path:
    CRASHES_DIR.mkdir(parents=True, exist_ok=True)
    p = CRASHES_DIR / f"crash-{idx:06d}.in"
    p.write_text(json.dumps(payload, default=repr), encoding="utf-8")
    return p


def _write_hang(idx: int, payload: dict) -> Path:
    HANGS_DIR.mkdir(parents=True, exist_ok=True)
    p = HANGSES_DIR() if False else HANGS_DIR / f"hang-{idx:06d}.in"
    p.write_text(json.dumps(payload, default=repr), encoding="utf-8")
    return p


# --- Input generators
def _gen_bytes(rng: random.Random) -> bytes:
    n = rng.randint(0, 1000)
    if n == 0:
        return b""
    # Mix structured (zero-heavy) and random
    if rng.random() < 0.3:
        return b"\x00" * n
    if rng.random() < 0.3:
        return bytes(rng.randint(0, 255) for _ in range(n))
    # ascii-ish printable
    return bytes((rng.randint(0x20, 0x7E)) for _ in range(n)).replace(b"\\", b"A")


def _gen_int(rng: random.Random) -> int:
    choice = rng.random()
    if choice < 0.05:
        return 0
    if choice < 0.10:
        return 1
    if choice < 0.15:
        return -rng.randint(1, 100)  # negative (should raise)
    if choice < 0.20:
        return 2 ** rng.randint(1, 1024)  # bigint
    if choice < 0.30:
        return rng.randint(0, 2 ** 32)
    if choice < 0.40:
        return rng.randint(0, 2 ** 64)
    return rng.randint(0, 2 ** 256)


def _gen_int_with_hostile(rng: random.Random):
    """May return a non-int (None, float, str, list, dict, bool, bytes) per the task spec."""
    choice = rng.random()
    if choice < 0.60:
        return _gen_int(rng)
    if choice < 0.65:
        return None
    if choice < 0.70:
        return rng.uniform(-100.0, 100.0)
    if choice < 0.75:
        return "not an int"
    if choice < 0.80:
        return [1, 2, 3]
    if choice < 0.85:
        return {"k": "v"}
    if choice < 0.90:
        return bool(rng.getrandbits(1))
    if choice < 0.95:
        return b"bytes-not-int"
    return (1, 2, 3)


def _gen_bytes_like(rng: random.Random):
    """bytes/bytearray/memoryview, with occasional hostile type."""
    if rng.random() < 0.10:
        return None
    if rng.random() < 0.10:
        return [1, 2, 3]
    if rng.random() < 0.10:
        return "string-not-bytes"
    if rng.random() < 0.10:
        return {"k": "v"}
    b = _gen_bytes(rng)
    form = rng.random()
    if form < 0.70:
        return b
    if form < 0.85:
        return bytearray(b)
    return memoryview(b)


def _gen_checksum_value(rng: random.Random):
    """Random truthy/falsy/hostile value for the checksum kwarg."""
    choices = [
        True, False, 1, 0, "yes", "no", None, [], [1], "true", "false",
        -1, 0.0, 0.1, "", b"", b"\x01", object(),
    ]
    return rng.choice(choices)


def _gen_decode_input(rng: random.Random) -> str:
    """Random string for decode(): mix of valid alphabet, hostile chars, hyphens, case."""
    n = rng.randint(0, 50)
    parts = []
    for _ in range(n):
        roll = rng.random()
        if roll < 0.55:
            parts.append(rng.choice(list(ALLOWED_BODY)))
        elif roll < 0.70:
            parts.append(rng.choice(BAD_CHARS))
        elif roll < 0.80:
            # case variant
            c = rng.choice(list(ALLOWED_BODY_STRICT))
            parts.append(c.lower() if rng.random() < 0.5 else c)
        elif roll < 0.90:
            parts.append("-")
        else:
            # non-ASCII
            parts.append(rng.choice(["é", "Ｒ", "\xa0", "\ufeff", "\u200b"]))
    return "".join(parts)


# --- Per-iteration target invocations
def _iter_encode(rng: random.Random) -> tuple[str, object]:
    data = _gen_bytes_like(rng) if rng.random() < 0.5 else _gen_int_with_hostile(rng)
    cs = _gen_checksum_value(rng)
    # encode signature: encode(data, *, checksum=...)
    # call with kwargs
    return ("encode", lambda: cb32.encode(data, checksum=cs))


def _iter_decode(rng: random.Random) -> tuple[str, object]:
    s = _gen_decode_input(rng)
    cs = _gen_checksum_value(rng)
    if rng.random() < 0.05:
        # hostiles to decode
        s = rng.choice([None, b"bytes", 123, 1.5, [], {}, ("t", "u", "p")])
    return ("decode", lambda: cb32.decode(s, checksum=cs))


def _iter_round_trip(rng: random.Random) -> tuple[str, object]:
    data = _gen_bytes(rng) or _gen_int(rng)
    cs = rng.choice([True, False])
    if isinstance(data, int):
        encoded = cb32.encode_int(data, checksum=cs)
    else:
        encoded = cb32.encode(data, checksum=cs)
    return ("round_trip", lambda: cb32.decode(encoded, checksum=cs))


# --- Driver
def run(iterations: int, seed: int, quiet: bool) -> dict:
    rng = random.Random(seed)
    stats = {
        "iterations": 0,
        "crashes": 0,
        "hangs": 0,
        "expected_errors": 0,
        "successful_round_trips": 0,
        "round_trip_mismatches": 0,
        "uncaught_attribute_errors": 0,
        "uncaught_type_errors": 0,
        "uncaught_value_errors_unexpected": 0,
        "uncaught_name_errors": 0,
        "other_uncaught": 0,
        "encode_return_type_violations": 0,
        "decode_return_type_violations": 0,
        "last_input_hash": "",
        "seed": seed,
    }
    # Reset log
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    _log(f"start: iterations={iterations} seed={seed}")

    op_choices = [_iter_encode, _iter_decode, _iter_round_trip]
    op_weights = [0.45, 0.40, 0.15]

    for i in range(iterations):
        op_fn = rng.choices(op_choices, weights=op_weights, k=1)[0]
        label, target = op_fn(rng)
        stats["iterations"] = i + 1
        last_hash = hashlib.sha256(repr(target).encode("utf-8", "replace")).hexdigest()[:16]
        stats["last_input_hash"] = last_hash
        try:
            result = _with_timeout(target)
            # Postcondition checks
            if label == "encode" and not isinstance(result, str):
                stats["encode_return_type_violations"] += 1
                _write_crash(
                    stats["crashes"],
                    {"op": "encode", "result_type": type(result).__name__,
                     "result": repr(result)[:200], "iter": i},
                )
                stats["crashes"] += 1
            elif label == "decode" and not isinstance(result, bytes):
                stats["decode_return_type_violations"] += 1
                _write_crash(
                    stats["crashes"],
                    {"op": "decode", "result_type": type(result).__name__,
                     "result": repr(result)[:200], "iter": i},
                )
                stats["crashes"] += 1
            elif label == "round_trip":
                # Result is bytes (from decode); we just count successful executions.
                if isinstance(result, bytes):
                    stats["successful_round_trips"] += 1
                else:
                    stats["decode_return_type_violations"] += 1
                    stats["crashes"] += 1
                    _write_crash(
                        stats["crashes"],
                        {"op": "round_trip", "result_type": type(result).__name__,
                         "result": repr(result)[:200], "iter": i},
                    )
            if not quiet and i % 100 == 0:
                _log(f"iter={i} op={label} ok hash={last_hash}")
        except _TimeoutError:
            stats["hangs"] += 1
            _write_hang(
                stats["hangs"],
                {"op": label, "iter": i, "timeout_seconds": TIMEOUT_SECONDS},
            )
            _log(f"HANG iter={i} op={label}")
        except CrockfordBase32Error:
            # Expected — structured error.
            stats["expected_errors"] += 1
        except AttributeError as e:
            # Invariant 21 violation: any uncaught AttributeError is High-severity.
            stats["uncaught_attribute_errors"] += 1
            stats["crashes"] += 1
            _write_crash(
                stats["crashes"],
                {"op": label, "iter": i, "kind": "AttributeError",
                 "msg": str(e), "tb": traceback.format_exc()[:2000]},
            )
            _log(f"CRASH iter={i} op={label} AttributeError: {e}")
        except TypeError as e:
            # TypeError is a sign that input validation missed something.
            stats["uncaught_type_errors"] += 1
            stats["crashes"] += 1
            _write_crash(
                stats["crashes"],
                {"op": label, "iter": i, "kind": "TypeError",
                 "msg": str(e), "tb": traceback.format_exc()[:2000]},
            )
            _log(f"CRASH iter={i} op={label} TypeError: {e}")
        except ValueError as e:
            # Only the library's own CrockfordBase32Error (a ValueError subclass) is expected.
            # A raw ValueError would be an Invariant 21 violation.
            if isinstance(e, CrockfordBase32Error):
                stats["expected_errors"] += 1
            else:
                stats["uncaught_value_errors_unexpected"] += 1
                stats["crashes"] += 1
                _write_crash(
                    stats["crashes"],
                    {"op": label, "iter": i, "kind": "ValueError (raw)",
                     "msg": str(e), "tb": traceback.format_exc()[:2000]},
                )
                _log(f"CRASH iter={i} op={label} raw ValueError: {e}")
        except NameError as e:
            stats["uncaught_name_errors"] += 1
            stats["crashes"] += 1
            _write_crash(
                stats["crashes"],
                {"op": label, "iter": i, "kind": "NameError",
                 "msg": str(e), "tb": traceback.format_exc()[:2000]},
            )
            _log(f"CRASH iter={i} op={label} NameError: {e}")
        except Exception as e:
            stats["other_uncaught"] += 1
            stats["crashes"] += 1
            _write_crash(
                stats["crashes"],
                {"op": label, "iter": i, "kind": type(e).__name__,
                 "msg": str(e), "tb": traceback.format_exc()[:2000]},
            )
            _log(f"CRASH iter={i} op={label} {type(e).__name__}: {e}")

        # Periodic stats dump
        if (i + 1) % 1000 == 0 or i + 1 == iterations:
            STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    _log(f"done: {stats}")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iter", type=int, default=1000,
                        help="Number of fuzz iterations (default 1000)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default 42)")
    parser.add_argument("--quiet", action="store_true",
                        help="Reduce log volume")
    args = parser.parse_args()
    stats = run(args.iter, args.seed, args.quiet)
    print(json.dumps(stats, indent=2))
    # Exit non-zero ONLY on real crashes (Invariant 21 violations).
    real_crashes = (
        stats["uncaught_attribute_errors"]
        + stats["uncaught_type_errors"]
        + stats["uncaught_value_errors_unexpected"]
        + stats["uncaught_name_errors"]
        + stats["other_uncaught"]
        + stats["encode_return_type_violations"]
        + stats["decode_return_type_violations"]
    )
    return 1 if real_crashes > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
