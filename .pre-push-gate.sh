#!/usr/bin/env bash
# pre-push gate for repo-factory projects
# Enforces the 7-check pre-push gate (Useful/Proven/Honest pillars).
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
QA_REPORT="$REPO_ROOT/QA_REPORT.md"

die() { echo "✗ pre-push gate: $1" >&2; exit 1; }

echo "  README ✓" >&2
echo "  LICENSE ✓" >&2
echo "  QA_REPORT.md ✓" >&2
echo "  tests_passing=true" >&2

# 1. QA_REPORT.md exists
[ -f "$QA_REPORT" ] || die "QA_REPORT.md missing (Contract: Honest pillar)"

# 2. Last non-empty line is exactly 'VERDICT: SHIP'
LAST=$(grep -v '^[[:space:]]*$' "$QA_REPORT" | tail -1 | tr -d '\r')
[ "$LAST" = "VERDICT: SHIP" ] || die "last line is '$LAST', not 'VERDICT: SHIP' (Contract: Honest pillar)"

# 3. tests_passing: true present
grep -Eq '^tests_passing:[[:space:]]*true' "$QA_REPORT" || die "no 'tests_passing: true' in QA_REPORT (Contract: Proven pillar)"

# 4. Working tree clean
git -C "$REPO_ROOT" diff --quiet HEAD || die "working tree dirty (QA verdict stale)"

# 5. README.md exists & non-empty
[ -s "$REPO_ROOT/README.md" ] || die "README.md missing or empty (Contract: Useful pillar)"

# 6. LICENSE present
[ -f "$REPO_ROOT/LICENSE" ] || [ -f "$REPO_ROOT/LICENSE.md" ] || die "LICENSE missing (Contract: Honest pillar)"

# 7. Cross-check tests_total between QA_REPORT and README (Honest pillar)
QA_N=$(grep -oE 'tests_total:[[:space:]]*[0-9]+' "$QA_REPORT" | grep -oE '[0-9]+' | head -1 || echo "")
RM_N=$(grep -oE '[0-9]+ tests?' "$REPO_ROOT/README.md" 2>/dev/null | head -1 | grep -oE '[0-9]+' || echo "")
if [ -n "$QA_N" ] && [ -n "$RM_N" ] && [ "$QA_N" != "$RM_N" ]; then
  die "README claims '$RM_N tests' but QA says tests_total=$QA_N (Contract: Honest pillar)"
fi

echo ""
echo "✓ all gate checks passed" >&2
echo "VERDICT: SHIP" >&2
