#!/usr/bin/env bash
# Run every fleet check from the course and write one report.
#   org        check-org.sh (1.1); failures listed in accepted-gaps.txt count as ACCEPTED until their date
#   baseline   check-drift.sh baseline.json (2.2, with the 3.1 required check)
#   coverage   check-coverage.sh: gate caller, CODEOWNERS, event policy, secret scanning, dependabot.yml
#   agents     check-agent-guardrails.sh (7.3)
#   exceptions exceptions-register.sh (8.1): EXPIRED or INVALID entries
#   inventory  inventory.sh (0.3), saved for history, never drift by itself
#   bypasses   bypasses.sh PERIOD=day (8.1), listed for the weekly review, never drift by itself
# Writes $OUT/report.md plus each check's output, exits 1 if anything drifted.
# Needs gh (a token that can read org settings and every repo's rulesets), jq, yq.
#   ORG=<your-test-org> [OUT=dir] ./fleet-audit.sh
set -uo pipefail
: "${ORG:?set ORG=<your-org>}"
H="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-fleet-audit-out}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
TODAY="$(date -u +%F)"
export ORG
drift=0; rows=()

check() {  # check <name> <counts-as-drift 0|1> <command...>
  local name=$1 counts=$2; shift 2
  if (cd "$OUT" && "$@") >"$OUT/$name.txt" 2>&1; then rows+=("| $name | OK |")
  elif [[ $counts == 1 ]]; then rows+=("| $name | **DRIFT** |"); drift=1
  else rows+=("| $name | see below |"); fi
}

# Org settings, minus accepted gaps that haven't expired.
"$H/check-org.sh" >"$OUT/org-raw.txt" 2>&1
awk -v today="$TODAY" 'NR == FNR { if ($0 !~ /^#/ && NF >= 2 && $2 >= today) ok[$1] = $2; next }
  ($1 == "FAIL" || $1 == "UNKNOWN") && ($2 in ok) { $1 = "ACCEPTED(" ok[$2] ")" } { print }' \
  "$H/accepted-gaps.txt" "$OUT/org-raw.txt" > "$OUT/org.txt"
if grep -qE '^(FAIL|UNKNOWN)' "$OUT/org.txt"; then rows+=("| org | **DRIFT** |"); drift=1; else rows+=("| org | OK |"); fi

check baseline 1 "$H/check-drift.sh" "$H/baseline.json"
check coverage 1 "$H/check-coverage.sh"
check agents 1 "$H/check-agent-guardrails.sh"
check exceptions 1 env OUT="$OUT/register.json" "$H/exceptions-register.sh"
check inventory 0 env OUT="$OUT/inventory.json" "$H/inventory.sh"
check bypasses 0 env PERIOD=day OUT="$OUT/bypasses.json" "$H/bypasses.sh"

{
  echo "Fleet audit of \`$ORG\` on $(date -u '+%F %H:%M UTC')"
  echo
  echo "| Check | Result |"; echo "|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  # Only the lines that need a look: failures, plus the exception and bypass summaries.
  for c in org baseline coverage agents; do
    lines=$(grep -vE '^(PASS|OK|INFO)\b|^ACCEPTED|checks not passing|^$' "$OUT/$c.txt" || true)
    [[ -n "$lines" ]] && printf '### %s\n\n```text\n%s\n```\n\n' "$c" "$lines"
  done
  printf '### exceptions\n\n'; grep -E '^\| (EXPIRED|INVALID|SOON) ' "$OUT/exceptions.txt" || echo "No exception is expired, invalid or expiring soon."
  printf '\n### bypasses in the last 24 hours\n\n'; tail -n +1 "$OUT/bypasses.txt" | grep -E 'bypasses in the last' || echo "Could not read bypasses."
  echo
  echo "Accepted gaps: $(grep -c '^ACCEPTED' "$OUT/org.txt") (see audit/accepted-gaps.txt)."
} > "$OUT/report.md"

cat "$OUT/report.md"
exit $drift
