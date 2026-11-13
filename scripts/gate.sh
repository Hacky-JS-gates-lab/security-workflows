#!/usr/bin/env bash
# Security gate: Semgrep on what a PR changes. Runs in the checkout of the repo under test.
# On a pull request only findings that are new against the merge base count; on any other
# event (workflow_dispatch) it scans the whole repo. Fails closed: a scanner error fails the gate.
set -euo pipefail
: "${GATE_DIR:?}"
MODE="${MODE:-block}"
case "$MODE" in audit|warn|block) ;; *) echo "::error::mode must be audit, warn or block, got '$MODE'"; exit 1 ;; esac
OUT="${RUNNER_TEMP:-/tmp}/gate"
mkdir -p "$OUT"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
SEMGREP="semgrep/semgrep:1.185.0@sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d"

baseline=()
if [[ -n "${PR_BASE_SHA:-}" ]]; then
  if ! base=$(git merge-base HEAD "$PR_BASE_SHA"); then
    echo "::error::no merge base with $PR_BASE_SHA; refusing to scan without a baseline"; exit 1
  fi
  baseline=(--baseline-commit "$base")
  scope="new findings since \`${base:0:12}\`"
else
  scope="whole repo (not a pull request)"
fi

# Run as the runner's user so git inside the container trusts the checkout.
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD:/src" -v "$GATE_DIR/rules:/rules:ro" -v "$OUT:/out" -w /src "$SEMGREP" \
  semgrep scan --config /rules/semgrep.yml --metrics=off --quiet \
  --json --output /out/semgrep.json "${baseline[@]}"

jq '[.results[] | {tool: "semgrep", rule: (.check_id | split(".") | last), path, line: .start.line,
     message: (.extra.message | gsub("\\s+"; " "))}]' "$OUT/semgrep.json" > "$OUT/findings.json"
n=$(jq length "$OUT/findings.json")

{
  echo "## Security gate"
  echo "Gate \`${GATE_REF:-local}\`, mode \`$MODE\`, scope: $scope"
  echo
  echo "| Tool | Findings |"
  echo "|---|---|"
  echo "| semgrep | $n |"
  echo
  jq -r '.[] | "- `\(.rule)` \(.path):\(.line) \(.message)"' "$OUT/findings.json"
} >> "$SUMMARY"
jq -r '.[] | "::error file=\(.path),line=\(.line),title=\(.tool) \(.rule)::\(.message)"' "$OUT/findings.json"

if [[ "$MODE" == block && "$n" -gt 0 ]]; then
  echo "$n new finding(s); failing in block mode"; exit 1
fi
echo "$n new finding(s), mode $MODE"
