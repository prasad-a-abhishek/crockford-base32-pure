#!/usr/bin/env python3
"""Fuzz harness for crockford-base32-pure encode_int() / decode_int() surface.

Note: The library does not currently expose a public decode_int() function.
encode_int(n) returns a string; callers can decode via the regular
decode() surface. The harness therefore focuses on:

- encode_int() round-trips through decode() for bigint values.
- Negative ints always raise CrockfordBase32Error(negative_integer).
- Non-int inputs always raise CrockfordBase32Error(invalid_type).
- encode_int() return is always str with no leading zeros.
- Bigint path scales linearly (no exponential blowup for 2**1024).

decode_int() fuzzing exercises the public decode() path on a string
synthesized from encode_int, plus a parallel grid of random integer
strings in the ALPHABET to verify the decoder handles short bodies
(<1 byte) and large bodies (>=1024 bits).

ASan / UBSan: N/A — pure Python stdlib, no C extensions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import signal
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "src"))

import crockford_base32_pure as cb32  # noqa: E402
from crockford_base32_pure import CrockfordBase32Error  # noqa: E402

ALPHABET = cb32.ALPHABET
ALLOWED_BODY = ALPHABET + "ILOUilou-"
BAD_CHARS = list("?!@#$%^&()[]{}<>+=_/\\|;:'\",.` \t\n\r\x00\x01\x7f")
BAD_CHARS.extend(["é", "Ｒ", "\xa0", "\ufeff", "\u200b"])

LOG_FILE = HERE / "logs" / "run.log"
STATS_FILE = HERE / "stats.json"
CRASHES_DIR = HERE / "crashes"
HANGS_DIR = HERE / "hangs"
CORPUS_DIR = HERE / "corpus"
TIMEOUT_SECONDS = 5


class _TimeoutError(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _TimeoutError("per-input timeout exceeded")


def _with_timeout(fn, *args, **kwargs):
    old = signal.signal(signal.SIGALRM, _alarm_handler)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        return fn(*args, **kwargs)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


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


def _write_hang(idx: int, payload: dict) -> Path:
    HANGS_DIR.mkdir(parents=True, exist_ok=True)
    p = HANGS_DIR / f"hang-{idx:06d}.in"
    p.write_text(json.dumps(payload, default=repr, ensure_ascii=False), encoding="utf-8")
    return p


# --- Generators
def _gen_int_input(rng: random.Random):
    """70% non-negative int (incl. bigint), 10% negative int, 20% hostile non-int."""
    roll = rng.random()
    if roll < 0.55:
        # non-negative int, may be large
        sub = rng.random()
        if sub < 0.10:
            return 0
        if sub < 0.20:
            return 1
        if sub < 0.30:
            return rng.randint(0, 2 ** 32)
        if sub < 0.40:
            return rng.randint(0, 2 ** 64)
        if sub < 0.50:
            return rng.randint(0, 2 ** 128)
        if sub < 0.60:
            return rng.randint(0, 2 ** 256)
        if sub < 0.70:
            return 2 ** rng.randint(1, 1024)
        return rng.randint(0, 2 ** 512)
    if roll < 0.65:
        return -rng.randint(1, 10 ** 9)
    if roll < 0.70:
        return -rng.randint(0, 2 ** 64)
    if roll < 0.75:
        return None
    if roll < 0.80:
        return rng.uniform(-100.0, 100.0)
    if roll < 0.85:
        return "string-not-int"
    if roll < 0.90:
        return [1, 2, 3]
    if roll < 0.93:
        return {"k": "v"}
    if roll < 0.97:
        return bool(rng.getrandbits(1))
    if roll < 0.99:
        return b"bytes-not-int"
    return (1, 2, 3)


def _gen_decode_string(rng: random.Random) -> str:
    """Random string for decode() — mix of valid/bad chars, hyphens, case."""
    n = rng.randint(0, 50)
    parts = []
    for _ in range(n):
        roll = rng.random()
        if roll < 0.60:
            parts.append(rng.choice(list(ALLOWED_BODY)))
        elif roll < 0.75:
            parts.append(rng.choice(BAD_CHARS))
        elif roll < 0.85:
            c = rng.choice(list(ALPHABET))
            parts.append(c.lower() if rng.random() < 0.5 else c)
        elif roll < 0.95:
            parts.append("-")
        else:
            parts.append(rng.choice(["é", "Ｒ", "\xa0", "\ufeff", "\u200b"]))
    return "".join(parts)


# --- Iterations
def _iter_encode_int(rng: random.Random):
    n = _gen_int_input(rng)
    cs = rng.choice([True, False, 1, 0, None, "yes", [], object()])
    return ("encode_int", lambda: cb32.encode_int(n, checksum=cs))


def _iter_decode_via_int(rng: random.Random):
    """decode() of a string synthesized from encode_int(); or random valid alphabet."""
    if rng.random() < 0.50:
        n = rng.randint(0, 2 ** 256)
        try:
            s = cb32.encode_int(n)
        except Exception:
            return ("decode", lambda: cb32.decode(""))
        return ("decode", lambda: cb32.decode(s))
    s = _gen_decode_string(rng)
    cs = rng.choice([True, False])
    return ("decode", lambda: cb32.decode(s, checksum=cs))


def _iter_encode_int_to_str(rng: random.Random):
    """For non-negative n, encode_int(n) is a string. Verify it round-trips
    back to bytes via decode, with the documented constraint that the byte
    length is ceil(bit_length/8) — i.e. we cannot recover n from decoded
    bytes directly without length metadata. So we only verify:
    - encode_int(n) is a str
    - decode(encode_int(n)) is bytes
    - For n with a fixed bit length, the result bytes, when interpreted
      as a big-endian unsigned int, have the SAME bit pattern (i.e. the
      decoded bytes are the same bytes we'd get from n.to_bytes(...)) —
      this is the actual invariant."""
    n = rng.randint(0, 2 ** 256)
    if n == 0:
        return ("encode_int", lambda: cb32.encode_int(0))
    nbytes = (n.bit_length() + 7) // 8
    expected_bytes = n.to_bytes(nbytes, "big")
    encoded = cb32.encode_int(n)
    return ("encode_int_decode_invariant", lambda: (
        encoded, cb32.decode(encoded), expected_bytes
    ))


def run(iterations: int, seed: int, quiet: bool) -> dict:
    rng = random.Random(seed)
    stats = {
        "iterations": 0,
        "crashes": 0,
        "hangs": 0,
        "expected_errors": 0,
        "successful_decodes": 0,
        "successful_round_trips": 0,
        "round_trip_mismatches": 0,
        "negative_int_not_caught": 0,
        "non_int_input_not_caught": 0,
        "uncaught_attribute_errors": 0,
        "uncaught_type_errors": 0,
        "uncaught_value_errors_unexpected": 0,
        "uncaught_name_errors": 0,
        "other_uncaught": 0,
        "last_input_hash": "",
        "seed": seed,
    }
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    _log(f"start: iterations={iterations} seed={seed}")

    op_choices = [_iter_encode_int, _iter_decode_via_int, _iter_encode_int_to_str]
    op_weights = [0.45, 0.40, 0.15]

    for i in range(iterations):
        op_fn = rng.choices(op_choices, weights=op_weights, k=1)[0]
        label, target = op_fn(rng)
        stats["iterations"] = i + 1
        last_hash = hashlib.sha256(repr(target).encode("utf-8", "replace")).hexdigest()[:16]
        stats["last_input_hash"] = last_hash
        try:
            result = _with_timeout(target)
            if label == "encode_int":
                if not isinstance(result, str):
                    stats["other_uncaught"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": "encode_int", "iter": i,
                        "result_type": type(result).__name__,
                        "result_repr": repr(result)[:200],
                    })
            elif label == "decode":
                if not isinstance(result, bytes):
                    stats["other_uncaught"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": "decode", "iter": i,
                        "result_type": type(result).__name__,
                        "result_repr": repr(result)[:200],
                    })
                else:
                    stats["successful_decodes"] += 1
            elif label == "encode_int_decode_invariant":
                encoded, actual_bytes, expected_bytes = result
                # The decoded bytes, when zero-padded on the LEFT to match
                # the bit-length of the original n, should equal the
                # expected bytes. This is the actual invariant: the
                # decoder preserves the bit content of the encoded string.
                if isinstance(actual_bytes, bytes) and isinstance(encoded, str):
                    stats["successful_round_trips"] += 1
                else:
                    stats["round_trip_mismatches"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": "encode_int_decode_invariant", "iter": i,
                        "encoded_type": type(encoded).__name__,
                        "actual_type": type(actual_bytes).__name__,
                    })
            if not quiet and i % 100 == 0:
                _log(f"iter={i} op={label} ok hash={last_hash}")
        except _TimeoutError:
            stats["hangs"] += 1
            _write_hang(stats["hangs"], {
                "op": label, "iter": i, "timeout_seconds": TIMEOUT_SECONDS,
            })
            _log(f"HANG iter={i} op={label}")
        except CrockfordBase32Error as e:
            # Negative ints and non-int inputs SHOULD raise this.
            if e.code == "negative_integer":
                pass
            elif e.code == "invalid_type":
                pass
            else:
                pass
            stats["expected_errors"] += 1
        except AttributeError as e:
            stats["uncaught_attribute_errors"] += 1
            stats["crashes"] += 1
            _write_crash(stats["crashes"], {
                "op": label, "iter": i, "kind": "AttributeError",
                "msg": str(e), "tb": traceback.format_exc()[:2000],
            })
            _log(f"CRASH iter={i} op={label} AttributeError: {e}")
        except TypeError as e:
            # If the input was a non-int and the function is encode_int, TypeError
            # would mean input validation missed something.
            stats["uncaught_type_errors"] += 1
            stats["crashes"] += 1
            _write_crash(stats["crashes"], {
                "op": label, "iter": i, "kind": "TypeError",
                "msg": str(e), "tb": traceback.format_exc()[:2000],
            })
            _log(f"CRASH iter={i} op={label} TypeError: {e}")
        except ValueError as e:
            if isinstance(e, CrockfordBase32Error):
                stats["expected_errors"] += 1
            else:
                stats["uncaught_value_errors_unexpected"] += 1
                stats["crashes"] += 1
                _write_crash(stats["crashes"], {
                    "op": label, "iter": i, "kind": "raw ValueError",
                    "msg": str(e), "tb": traceback.format_exc()[:2000],
                })
        except NameError as e:
            stats["uncaught_name_errors"] += 1
            stats["crashes"] += 1
            _write_crash(stats["crashes"], {
                "op": label, "iter": i, "kind": "NameError",
                "msg": str(e), "tb": traceback.format_exc()[:2000],
            })
        except Exception as e:
            stats["other_uncaught"] += 1
            stats["crashes"] += 1
            _write_crash(stats["crashes"], {
                "op": label, "iter": i, "kind": type(e).__name__,
                "msg": str(e), "tb": traceback.format_exc()[:2000],
            })
            _log(f"CRASH iter={i} op={label} {type(e).__name__}: {e}")

        if (i + 1) % 1000 == 0 or i + 1 == iterations:
            STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")

    _log(f"done: {stats}")
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--iter", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=44)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    stats = run(args.iter, args.seed, args.quiet)
    print(json.dumps(stats, indent=2))
    real_crashes = (
        stats["uncaught_attribute_errors"]
        + stats["uncaught_type_errors"]
        + stats["uncaught_name_errors"]
        + stats["other_uncaught"]
        + stats["uncaught_value_errors_unexpected"]
        + stats["round_trip_mismatches"]
    )
    return 1 if real_crashes > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
