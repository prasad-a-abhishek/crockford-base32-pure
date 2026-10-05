#!/usr/bin/env python3
"""Fuzz harness for crockford-base32-pure checksum_symbol() / validate_checksum().

Covers the mod-37 check-symbol surface (medium-risk math + lookup).

Validates:
- checksum_symbol() always returns a 1-char str in ALPHABET+EXTENDED (or raises).
- validate_checksum() is TOTAL — never raises, always returns bool (Invariant 21).
- CrockfordBase32Error raised for invalid input on checksum_symbol().
- Random body+check combinations match/don't-match correctly.

ASan / UBSan: N/A — pure Python stdlib, no C extensions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
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
EXTENDED = cb32.EXTENDED
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
def _gen_body_str(rng: random.Random) -> str:
    """Body for checksum_symbol() — must be str."""
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


def _gen_validate_str(rng: random.Random):
    """May return a non-str (None, int, bytes, list, dict, bool, float) to verify
    validate_checksum's total-over-arbitrary-input contract."""
    if rng.random() < 0.20:
        return rng.choice([None, 123, b"CR1", [], {}, True, False, 1.5])
    if rng.random() < 0.30:
        return ""
    if rng.random() < 0.50:
        return rng.choice(BAD_CHARS + ["?", "!", " ", "\t", "\n"])
    return _gen_body_str(rng)


def _iter_checksum_symbol(rng: random.Random):
    s = _gen_body_str(rng) if rng.random() < 0.85 else rng.choice(
        [None, 123, b"bytes", [], {}, True, False, 1.5]
    )
    return ("checksum_symbol", lambda: cb32.checksum_symbol(s))


def _iter_validate_checksum(rng: random.Random):
    s = _gen_validate_str(rng)
    return ("validate_checksum", lambda: cb32.validate_checksum(s))


def _iter_end_to_end(rng: random.Random):
    """Compute the check symbol for a valid body, append it, then validate — must
    always return True. Then validate a tampered version — must return False."""
    n = rng.randint(1, 30)
    body = "".join(rng.choice(list(ALPHABET)) for _ in range(n))
    try:
        check = cb32.checksum_symbol(body)
    except CrockfordBase32Error:
        return ("end_to_end", lambda: None)
    valid_str = body + check
    # Tamper: replace the check char with a random one
    tampered_check = rng.choice(list(ALPHABET + EXTENDED + "?!@"))
    tampered_str = body + tampered_check
    return ("end_to_end", lambda: (
        cb32.validate_checksum(valid_str), cb32.validate_checksum(tampered_str)
    ))


def run(iterations: int, seed: int, quiet: bool) -> dict:
    rng = random.Random(seed)
    stats = {
        "iterations": 0,
        "crashes": 0,
        "hangs": 0,
        "expected_errors": 0,
        "validate_total_violations": 0,
        "checksum_symbol_return_violations": 0,
        "checksum_symbol_unexpected_value_errors": 0,
        "end_to_end_valid_mismatches": 0,
        "end_to_end_tampered_unexpected_matches": 0,
        "uncaught_attribute_errors": 0,
        "uncaught_type_errors": 0,
        "uncaught_name_errors": 0,
        "other_uncaught": 0,
        "last_input_hash": "",
        "seed": seed,
    }
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE.write_text("", encoding="utf-8")
    _log(f"start: iterations={iterations} seed={seed}")

    op_choices = [_iter_checksum_symbol, _iter_validate_checksum, _iter_end_to_end]
    op_weights = [0.40, 0.40, 0.20]

    for i in range(iterations):
        op_fn = rng.choices(op_choices, weights=op_weights, k=1)[0]
        label, target = op_fn(rng)
        stats["iterations"] = i + 1
        last_hash = hashlib.sha256(repr(target).encode("utf-8", "replace")).hexdigest()[:16]
        stats["last_input_hash"] = last_hash
        try:
            result = _with_timeout(target)
            if label == "checksum_symbol":
                if not isinstance(result, str) or len(result) != 1:
                    stats["checksum_symbol_return_violations"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": "checksum_symbol", "iter": i,
                        "result_type": type(result).__name__,
                        "result_repr": repr(result)[:200],
                    })
            elif label == "validate_checksum":
                if not isinstance(result, bool):
                    stats["validate_total_violations"] += 1
                    stats["crashes"] += 1
                    _write_crash(stats["crashes"], {
                        "op": "validate_checksum", "iter": i,
                        "result_type": type(result).__name__,
                        "result_repr": repr(result)[:200],
                    })
            elif label == "end_to_end":
                if result is None:
                    pass
                else:
                    valid_ok, tampered_ok = result
                    if not valid_ok:
                        stats["end_to_end_valid_mismatches"] += 1
                        stats["crashes"] += 1
                        _write_crash(stats["crashes"], {
                            "op": "end_to_end", "iter": i, "issue": "valid_ok=False",
                        })
                    if tampered_ok:
                        stats["end_to_end_tampered_unexpected_matches"] += 1
                        stats["crashes"] += 1
                        _write_crash(stats["crashes"], {
                            "op": "end_to_end", "iter": i, "issue": "tampered_ok=True",
                        })
            if not quiet and i % 100 == 0:
                _log(f"iter={i} op={label} ok hash={last_hash}")
        except _TimeoutError:
            stats["hangs"] += 1
            _write_hang(stats["hangs"], {
                "op": label, "iter": i, "timeout_seconds": TIMEOUT_SECONDS,
            })
            _log(f"HANG iter={i} op={label}")
        except CrockfordBase32Error:
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
            stats["uncaught_type_errors"] += 1
            stats["crashes"] += 1
            _write_crash(stats["crashes"], {
                "op": label, "iter": i, "kind": "TypeError",
                "msg": str(e), "tb": traceback.format_exc()[:2000],
            })
            _log(f"CRASH iter={i} op={label} TypeError: {e}")
        except ValueError as e:
            # raw ValueError that isn't a CrockfordBase32Error
            if isinstance(e, CrockfordBase32Error):
                stats["expected_errors"] += 1
            else:
                stats["checksum_symbol_unexpected_value_errors"] += 1
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
    parser.add_argument("--seed", type=int, default=43)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    stats = run(args.iter, args.seed, args.quiet)
    print(json.dumps(stats, indent=2))
    real_crashes = (
        stats["uncaught_attribute_errors"]
        + stats["uncaught_type_errors"]
        + stats["uncaught_name_errors"]
        + stats["other_uncaught"]
        + stats["validate_total_violations"]
        + stats["checksum_symbol_return_violations"]
        + stats["checksum_symbol_unexpected_value_errors"]
        + stats["end_to_end_valid_mismatches"]
        + stats["end_to_end_tampered_unexpected_matches"]
    )
    return 1 if real_crashes > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
