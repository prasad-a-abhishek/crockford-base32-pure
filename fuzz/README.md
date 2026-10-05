# Fuzz harnesses for crockford-base32-pure (cycle_178 / adversary / 02)

> **Card**: cycle_178/adversary/02 — FUZZ_HARNESS
> **Branch**: wt/cycle178-adversary-01
> **Commit**: (see `git log`)
> **ASan / UBSan**: N/A — pure Python stdlib, no C extensions
> **Methodology**: stdlib Python only (`random`, `signal`, `hashlib`,
> `json`, `traceback`, `itertools`, `struct`); per-input 5-second
> timeout via `signal.alarm(5)`; structured output to
> `<surface>/{crashes,hangs,logs,corpus,stats.json}`.

This directory contains the 4 fuzzing surfaces built for the
`@repo-adversary` workstream. Each surface targets a distinct part
of the public API enumerated in `benchmarks/adversarial/cycle_178/SURFACES.md`.

## Surfaces

| Surface | Function(s) fuzzed | Iters/run | Source |
|---------|-------------------|-----------|--------|
| `encode_decode` | `encode`, `decode` (random bytes + types + params) | configurable | `fuzz/encode_decode/harness.py` |
| `checksum_validate` | `checksum_symbol`, `validate_checksum` (mod-37) | configurable | `fuzz/checksum_validate/harness.py` |
| `integer_path` | `encode_int`, `decode` of int-synthesized strings (bigint path) | configurable | `fuzz/integer_path/harness.py` |
| `hostile_inputs` | all 9 public functions × 40-input hostile matrix (Invariant 21) | fixed grid (360) | `fuzz/hostile_inputs/harness.py` |

Total public API surface covered: 5 of 5 functions + `version()` + the 3 module-level constants (`ALPHABET`, `EXTENDED`, `CrockfordBase32Error` — all data-only, no fuzzing needed).

## Running

```bash
# Quick smoke (200 iterations, ~1 second each)
cd fuzz/encode_decode && python3 harness.py --iter 200 --quiet
cd fuzz/checksum_validate && python3 harness.py --iter 200 --quiet
cd fuzz/integer_path && python3 harness.py --iter 200 --quiet

# Exhaustive Invariant 21 hostile matrix (fixed 360-cell grid)
python3 fuzz/hostile_inputs/harness.py

# Long fuzz (10000 iters, no upper bound, exits on first real crash)
cd fuzz/encode_decode && python3 harness.py --iter 10000
```

Exit code is **0** on clean (no real crashes) and **1** on a real
Invariant 21 violation (uncaught `AttributeError` / `TypeError` /
`NameError` / raw `ValueError` / wrong return type).

## What "real crash" means

The harness distinguishes:

- **Expected structured error** — `CrockfordBase32Error` (a `ValueError`
  subclass) raised by the library. Counted in `expected_errors`.
- **Invariant 21 violation** — uncaught `AttributeError` / `TypeError`
  / `NameError` / raw `ValueError` / wrong return type. Counted in
  `crashes` and written to `crashes/crash-NNNNNN.in`.
- **Hang** — input exceeded 5-second per-input timeout. Counted in
  `hangs` and written to `hangs/hang-NNNNNN.in`.

The fuzz harnesses are **allowed** to generate input that triggers
the structured errors. They're not allowed to see any other exception
type escape.

## Output

Each surface writes:

- `crashes/crash-NNNNNN.in` — JSON dump of the input that caused an
  Invariant 21 violation
- `hangs/hang-NNNNNN.in` — JSON dump of the input that hung > 5s
- `logs/run.log` — structured per-iteration log lines
- `stats.json` — counters (iterations, crashes, hangs, expected_errors, …)
- `corpus/SEEDS.md` — hand-curated seed shapes and generator biases

## Why stdlib Python only

`Atheris` (the only Python fuzzer) requires a C build (`pip install
atheris` builds libFuzzer bindings). `LibFuzzer` / `AFL` / `Honggfuzz`
are C/C++ fuzzers. The library is pure stdlib (no C extensions), so
those tools are out of scope. The signal-based 5-second timeout
serves as the upper bound on per-input latency, which is the same
role the `-timeout=5` flag plays in libFuzzer.

A stdlib-only harness is also a **deliberate constraint** documented
in the VULN_AUDIT: "no C extensions = no C-level UAF / buffer-overflow
class of bugs". So ASan / UBSan would only catch Python interpreter
bugs, which are not the target of this audit.

## Seed corpora

See each surface's `corpus/SEEDS.md` for the hand-curated boundary
inputs (empty bytes, single byte, max byte, 40/64/80-bit boundaries,
2^8 / 2^32 / 2^64 / 2^128 / 2^256 / 2^512 / 2^1024 bigints, check
mismatch, all hostile types) and the generator biases used in the
random loop.

## What I tried and found nothing

Smoke runs (200 iterations per surface) and the 360-cell hostile
matrix all returned 0 real crashes. The library is total over
arbitrary input as documented in the VULN_AUDIT (0 Critical/High/Medium
findings, 2 Low + 3 Info, all non-blocking).
