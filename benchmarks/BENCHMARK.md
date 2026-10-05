# Benchmarks — crockford-base32-pure vs stdlib base64.b32encode

**Generated:** 2026-10-05 16:25:55 UTC  
**Environment:** Python 3.11.15 on Linux aarch64 (unknown CPU)  
**Methodology:** Wall-clock timing via ``time.perf_counter``; ``tracemalloc`` for peak memory; 5-measurement profiles, P95 via nearest-rank; first call discarded as warmup; ``random.seed(0)`` for reproducible random profiles.

## Honest disclosure (READ FIRST)

**These two libraries are NOT drop-in compatible.** Crockford's
alphabet (``0123456789ABCDEFGHJKMNPQRSTVWXYZ``) excludes ``I L O U``
and applies ``I=L=1``/``O=0`` substitutions on decode. RFC 4648
base32 (``ABCDEFGHIJKLMNOPQRSTUVWXYZ234567``) includes all 26
letters and uses ``=`` padding. The comparison below is for
**throughput calibration only**; pick the implementation whose
alphabet you actually need.

## Results (5-measurement profiles per workload)

| profile | n | iters | impl | mean | P95 | peak-mem | throughput |
|---|---|---|---|---|---|---|---|
| 1KB_random | 1,024 | 100 | crockford-base32-pure | 1.70 ms | 1.98 ms | 19.3 KB | 589.9 KB/s |
| 1KB_random | 1,024 | 100 | base64.b32encode | 1.45 ms | 1.49 ms | 49.3 KB | 690.1 KB/s |
| 10KB_random | 10,240 | 20 | crockford-base32-pure | 34.60 ms | 34.90 ms | 165.7 KB | 289.0 KB/s |
| 10KB_random | 10,240 | 20 | base64.b32encode | 14.79 ms | 14.95 ms | 32.9 KB | 676.2 KB/s |
| 100KB_random | 102,400 | 1 | crockford-base32-pure | 2.12 s | 2.12 s | 1.7 MB | 47.2 KB/s |
| 100KB_random | 102,400 | 1 | base64.b32encode | 151.60 ms | 151.60 ms | 334.4 KB | 659.7 KB/s |
| 1MB_random | 1,048,576 | 0 (deferred) | crockford-base32-pure | — | — | 16.1 MB | — |
| 1MB_random | 1,048,576 | 0 (deferred) | base64.b32encode | — | — | 4.4 MB | — |
| 1KB_zeros | 1,024 | 100 | crockford-base32-pure | 83.6 µs | 87.7 µs | 16.9 KB | 11.7 MB/s |
| 1KB_zeros | 1,024 | 100 | base64.b32encode | 814.9 µs | 828.6 µs | 5.5 KB | 1.2 MB/s |
| 10KB_zeros | 10,240 | 20 | crockford-base32-pure | 773.8 µs | 785.3 µs | 149.7 KB | 12.6 MB/s |
| 10KB_zeros | 10,240 | 20 | base64.b32encode | 8.43 ms | 8.50 ms | 32.9 KB | 1.2 MB/s |
| 100KB_zeros | 102,400 | 1 | crockford-base32-pure | 7.66 ms | 7.66 ms | 1.5 MB | 12.7 MB/s |
| 100KB_zeros | 102,400 | 1 | base64.b32encode | 85.21 ms | 85.21 ms | 334.4 KB | 1.1 MB/s |
| 1MB_zeros | 1,048,576 | 0 (deferred) | crockford-base32-pure | — | — | 14.5 MB | — |
| 1MB_zeros | 1,048,576 | 0 (deferred) | base64.b32encode | — | — | 4.4 MB | — |
| 100KB_ascii | 102,400 | 1 | crockford-base32-pure | 2.17 s | 2.17 s | 1.7 MB | 46.1 KB/s |
| 100KB_ascii | 102,400 | 1 | base64.b32encode | 156.82 ms | 156.82 ms | 334.4 KB | 637.7 KB/s |
| 1KB_uniform | 1,024 | 100 | crockford-base32-pure | 1.71 ms | 1.74 ms | 18.7 KB | 585.6 KB/s |
| 1KB_uniform | 1,024 | 100 | base64.b32encode | 1.50 ms | 1.52 ms | 5.5 KB | 667.0 KB/s |

## How to reproduce

```bash
python3 benchmarks/run_benchmark.py
```

Workload profiles, iteration counts, and competitor selection are
defined in ``benchmarks/run_benchmark.py`` (10 profiles, ~5–200
iterations per profile depending on payload size to keep total
wall time under 60 seconds).
