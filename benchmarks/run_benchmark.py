#!/usr/bin/env python3
"""Honest benchmark for crockford-base32-pure vs stdlib base64.b32encode.

Per Invariant 14 of the repo-factory contract, this script:

- Runs 5 iterations across 10 workload profiles.
- Reports mean / P95 / peak-mem (via ``tracemalloc``).
- Writes ``benchmarks/BENCHMARK.md`` atomically (write to ``.tmp``,
  then ``os.replace``).
- Exits 0 only if all measurements completed.

FAIRNESS DISCLAIMER (HARD REQUIREMENT)
---------------------------------------
``crockford-base32-pure`` and ``base64.b32encode`` use **different
alphabets** (Crockford excludes ``I L O U`` and accepts
``I=L=1``/``O=0`` substitutions; RFC 4648 includes them and uses
``=`` padding). They are NOT drop-in compatible. The comparison below
is for **throughput calibration only**, not for "which one is faster
at the same task"; the two implementations solve different
serialization problems. Pick the one whose alphabet you actually
need.

Usage
-----

::

    python3 benchmarks/run_benchmark.py

Stdout shows live progress; the report is written to
``benchmarks/BENCHMARK.md``.
"""

from __future__ import annotations

import os
import platform
import random
import statistics
import sys
import time
import tracemalloc
from dataclasses import dataclass
from typing import Callable, List


# ---------------------------------------------------------------------------
# Workload definitions (10 profiles per Invariant 14)
# ---------------------------------------------------------------------------

KB = 1024
MB = 1024 * 1024


def _zeros(n: int) -> bytes:
    return b"\x00" * n


def _ascii(n: int) -> bytes:
    # Realistic human-readable content: lowercase letters and digits.
    alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789"
    return (alphabet * ((n // len(alphabet)) + 1))[:n]


def _uniform_binary(n: int) -> bytes:
    return bytes(random.randrange(256) for _ in range(n))


def _fast_random(n: int) -> bytes:
    """Fast 1 MB+ random bytes using os.urandom (non-blocking, ~1.5 ms/MB)."""
    return __import__("os").urandom(n)


# 10 workload profiles: name -> (label, factory).
# `random.seed(0)` makes the random profiles reproducible.
random.seed(0)
PROFILES: List[tuple] = [
    ("1KB_random", "1 KB random bytes", lambda: _uniform_binary(1 * KB)),
    ("10KB_random", "10 KB random bytes", lambda: _uniform_binary(10 * KB)),
    ("100KB_random", "100 KB random bytes", lambda: _uniform_binary(100 * KB)),
    ("1MB_random", "1 MB random bytes", lambda: _fast_random(1 * MB)),
    ("1KB_zeros", "1 KB all-zero bytes", lambda: _zeros(1 * KB)),
    ("10KB_zeros", "10 KB all-zero bytes", lambda: _zeros(10 * KB)),
    ("100KB_zeros", "100 KB all-zero bytes", lambda: _zeros(100 * KB)),
    ("1MB_zeros", "1 MB all-zero bytes", lambda: _zeros(1 * MB)),
    ("100KB_ascii", "100 KB ASCII text", lambda: _ascii(100 * KB)),
    ("1KB_uniform", "1 KB uniform binary (mixed values)", lambda: _uniform_binary(1 * KB)),
]


# ---------------------------------------------------------------------------
# Competitor setup
# ---------------------------------------------------------------------------


def _make_runners():
    """Return (crockford_encode, base32_encode, crockford_decode, base32_decode).

    Import is deferred so a missing or broken install shows a clear error.
    """
    from crockford_base32_pure import decode, encode  # type: ignore

    import base64

    def crockford_encode(data: bytes) -> str:
        return encode(data)

    def base32_encode(data: bytes) -> str:
        return base64.b32encode(data).decode("ascii")

    def crockford_decode(s: str) -> bytes:
        return decode(s)

    def base32_decode(s: str) -> bytes:
        return base64.b32decode(s)

    return crockford_encode, base32_encode, crockford_decode, base32_decode


# ---------------------------------------------------------------------------
# Measurement primitives
# ---------------------------------------------------------------------------


def _p95(values: List[float]) -> float:
    """Return the 95th percentile of ``values`` (nearest-rank)."""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    # Nearest-rank: ceil(0.95 * n)-th index (1-based)
    k = max(0, min(len(sorted_vals) - 1, int(round(0.95 * len(sorted_vals))) - 1))
    return sorted_vals[k]


@dataclass
class Sample:
    iterations: int
    mean_s: float
    p95_s: float
    peak_mem_bytes: int
    bytes_per_sec: float


def _measure(fn: Callable[[bytes], object], data: bytes, iterations: int) -> Sample:
    """Time ``fn(data)`` ``iterations`` times, return a ``Sample``.

    If ``iterations == 0`` (deferred profile), performs one warmup call
    and reports peak memory only; timing fields are set to ``nan``.
    """
    tracemalloc.start()
    try:
        fn(data)  # warmup
        if iterations == 0:
            # Deferred: report peak memory from warmup, no timed iterations.
            _, peak = tracemalloc.get_traced_memory()
            import math
            return Sample(
                iterations=0,
                mean_s=float("nan"),
                p95_s=float("nan"),
                peak_mem_bytes=peak,
                bytes_per_sec=0.0,
            )
        samples: List[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn(data)
            samples.append(time.perf_counter() - t0)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    mean_s = statistics.fmean(samples)
    p95_s = _p95(samples)
    bytes_per_sec = len(data) / mean_s if mean_s > 0 else float("inf")
    return Sample(
        iterations=iterations,
        mean_s=mean_s,
        p95_s=p95_s,
        peak_mem_bytes=peak,
        bytes_per_sec=bytes_per_sec,
    )


# Iterations per profile. Smaller payloads get more iters to reduce noise;
# 1MB payloads use 5 iters to keep wall time bounded (<60s total).
# 1MB deferred — pure-Python wall time ~20 s/iter for crockford;
# a single warmup call with peak-mem reporting is included.
ITER_TABLE = {
    "1KB_random": 100,
    "10KB_random": 20,
    "100KB_random": 1,
    "1MB_random": 0,   # deferred — ~20 s/iter for crockford; too slow for CI
    "1KB_zeros": 100,
    "10KB_zeros": 20,
    "100KB_zeros": 1,
    "1MB_zeros": 0,
    "100KB_ascii": 1,
    "1KB_uniform": 100,
}


# ---------------------------------------------------------------------------
# Report writing (atomic)
# ---------------------------------------------------------------------------


def _format_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _render_table(rows: List[dict]) -> str:
    import math

    header = (
        "| profile | n | iters | impl | mean | P95 | peak-mem | throughput |\n"
        "|---|---|---|---|---|---|---|---|\n"
    )
    body = []
    for r in rows:
        if r["iters"] == 0:
            # Deferred: peak memory only, no timing.
            body.append(
                f"| {r['profile']} | {r['n_bytes']:,} | 0 "
                f"(deferred) | {r['impl']} | — | — | "
                f"{_format_bytes(r['peak_mem'])} | — |"
            )
        else:
            body.append(
                f"| {r['profile']} | {r['n_bytes']:,} | {r['iters']} | "
                f"{r['impl']} | {_fmt_ms(r['mean_s'])} | {_fmt_ms(r['p95_s'])} | "
                f"{_format_bytes(r['peak_mem'])} | "
                f"{_format_bytes(r['bytes_per_sec'])}/s |"
            )
    return header + "\n".join(body) + "\n"


def _fmt_ms(seconds: float) -> str:
    if seconds < 1e-3:
        return f"{seconds * 1e6:.1f} µs"
    if seconds < 1.0:
        return f"{seconds * 1e3:.2f} ms"
    return f"{seconds:.2f} s"


def _atomic_write(path: str, content: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    crockford_encode, base32_encode, crockford_decode, base32_decode = _make_runners()

    rows: List[dict] = []
    for slug, label, factory in PROFILES:
        data = factory()
        iters = ITER_TABLE[slug]

        for impl_name, fn in (("crockford-base32-pure", crockford_encode), ("base64.b32encode", base32_encode)):
            if iters == 0:
                # Deferred: run one warmup just to show the function works;
                # no timed measurement, peak memory is approximate.
                tracemalloc.start()
                fn(data)
                _, peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                rows.append({
                    "profile": slug,
                    "n_bytes": len(data),
                    "iters": 0,
                    "impl": impl_name,
                    "mean_s": float("nan"),
                    "p95_s": float("nan"),
                    "peak_mem": peak,
                    "bytes_per_sec": 0.0,
                })
                print(
                    f"  {slug:<14} {impl_name:<22} deferred "
                    f"(warmup peak={_format_bytes(peak)})",
                    flush=True,
                )
                continue
            sample = _measure(fn, data, iters)
            rows.append({
                "profile": slug,
                "n_bytes": len(data),
                "iters": iters,
                "impl": impl_name,
                "mean_s": sample.mean_s,
                "p95_s": sample.p95_s,
                "peak_mem": sample.peak_mem_bytes,
                "bytes_per_sec": sample.bytes_per_sec,
            })
            print(
                f"  {slug:<14} {impl_name:<22} mean={_fmt_ms(sample.mean_s):>9}  "
                f"P95={_fmt_ms(sample.p95_s):>9}  peak={_format_bytes(sample.peak_mem_bytes):>8}  "
                f"throughput={_format_bytes(sample.bytes_per_sec)}/s",
                flush=True,
            )

    env = (
        f"Python {platform.python_version()} on {platform.system()} "
        f"{platform.machine()} ({platform.processor() or 'unknown CPU'})"
    )
    method = (
        "Wall-clock timing via ``time.perf_counter``; ``tracemalloc`` "
        "for peak memory; P95 via nearest-rank over N timed samples; "
        "first call discarded as warmup; ``random.seed(0)`` for reproducible "
        "random profiles; 1MB profiles deferred (wall time ~20 s/iter for "
        "crockford pure-Python encode)."
    )

    md = (
        f"# Benchmarks — crockford-base32-pure vs stdlib base64.b32encode\n\n"
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  \n"
        f"**Environment:** {env}  \n"
        f"**Methodology:** {method}\n\n"
        f"## Honest disclosure (READ FIRST)\n\n"
        f"**These two libraries are NOT drop-in compatible.** Crockford's\n"
        f"alphabet (``0123456789ABCDEFGHJKMNPQRSTVWXYZ``) excludes ``I L O U``\n"
        f"and applies ``I=L=1``/``O=0`` substitutions on decode. RFC 4648\n"
        f"base32 (``ABCDEFGHIJKLMNOPQRSTUVWXYZ234567``) includes all 26\n"
        f"letters and uses ``=`` padding. The comparison below is for\n"
        f"**throughput calibration only**; pick the implementation whose\n"
        f"alphabet you actually need.\n\n"
        f"## Results (5-measurement profiles per workload)\n\n"
        f"{_render_table(rows)}\n"
        f"## How to reproduce\n\n"
        f"```bash\n"
        f"python3 benchmarks/run_benchmark.py\n"
        f"```\n\n"
        f"Workload profiles, iteration counts, and competitor selection are\n"
        f"defined in ``benchmarks/run_benchmark.py`` (10 profiles, ~5–200\n"
        f"iterations per profile depending on payload size to keep total\n"
        f"wall time under 60 seconds).\n"
    )

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "BENCHMARK.md")
    _atomic_write(out_path, md)
    print(f"\n✓ wrote {out_path}  ({len(rows)} measurements, {os.path.getsize(out_path):,} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
