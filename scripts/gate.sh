#!/usr/bin/env bash
# Security gate: Semgrep, gitleaks, dependency review and actionlint on what a PR changes,
# with three modes and expiring exceptions. Runs in the checkout of the repo under test.
#   audit  record findings in the summary and the artifact; never fail
#   warn   also annotate the PR with warnings; never fail
#   block  annotate with errors; fail on any finding not covered by a valid exception,
#          and on any expired or invalid exception
# On a pull request only findings that are new against the merge base count; on any other
# event (workflow_dispatch) it scans the whole repo and its history. Fails closed: a scanner
# error fails the gate in every mode.
set -euo pipefail
: "${GATE_DIR:?}"
MODE="${MODE:-block}"
case "$MODE" in audit|warn|block) ;; *) echo "::error::mode must be audit, warn or block, got '$MODE'"; exit 1 ;; esac
OUT="${RUNNER_TEMP:-/tmp}/gate"
mkdir -p "$OUT"
rm -f "$OUT"/f-*.json
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/stdout}"
EXCEPTIONS=".github/security-exceptions.yml"
MAX_DAYS=90
SEMGREP="semgrep/semgrep:1.185.0@sha256:67518c174185a2043fdbed16c70631b79209499b3671178e7194379b48295a0d"
GITLEAKS="zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
ACTIONLINT="rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
# Scanners run as the runner's user so git inside the containers trusts the checkout.
run() { docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$OUT:/out" "$@"; }

base=""
if [[ -n "${PR_BASE_SHA:-}" ]]; then
  if ! base=$(git merge-base HEAD "$PR_BASE_SHA"); then
    echo "::error::no merge base with $PR_BASE_SHA; refusing to scan without a baseline"; exit 1
  fi
  scope="new findings since \`${base:0:12}\`"
else
  scope="whole repo and history (not a pull request)"
fi

# 1. Semgrep: findings on lines the PR changed (--baseline-commit), with the gate's own rules.
args=(); [[ -n "$base" ]] && args=(--baseline-commit "$base")
run -v "$PWD:/src" -v "$GATE_DIR/rules:/rules:ro" -w /src "$SEMGREP" \
  semgrep scan --config /rules/semgrep.yml --metrics=off --quiet --json --output /out/semgrep.json "${args[@]}"
jq '[.results[] | {tool: "semgrep", rule: (.check_id | split(".") | last), path, line: .start.line,
     message: (.extra.message | gsub("\\s+"; " "))}]' "$OUT/semgrep.json" > "$OUT/f-semgrep.json"

# 2. gitleaks: every commit in the PR, not only the final diff. A token added in one commit
#    and removed in the next is still in the branch, and in refs/pull/<n>/head for good.
args=(); [[ -n "$base" ]] && args=(--log-opts="$base..$PR_HEAD_SHA")
run -v "$PWD:/repo" -v "$GATE_DIR/rules:/rules:ro" "$GITLEAKS" \
  git /repo --config /rules/gitleaks.toml --redact --no-banner --log-level warn \
  --exit-code 0 --report-format json --report-path /out/gitleaks.json "${args[@]}"
jq '[.[] | {tool: "gitleaks", rule: .RuleID, path: .File, line: .StartLine,
     message: "\(.Description) in commit \(.Commit[0:12])"}]' "$OUT/gitleaks.json" > "$OUT/f-gitleaks.json"

# 3. Dependencies: packages the PR adds with a high or critical advisory, from GitHub's
#    dependency graph (the API behind actions/dependency-review-action). PRs only.
if [[ -n "$base" ]]; then
  gh api "repos/$REPO/dependency-graph/compare/$base...$PR_HEAD_SHA" > "$OUT/deps.json"
else
  echo '[]' > "$OUT/deps.json"
fi
jq '[.[] | select(.change_type == "added") | . as $d | .vulnerabilities[]?
     | select(.severity == "high" or .severity == "critical")
     | {tool: "deps", rule: .advisory_ghsa_id, path: $d.manifest, line: 1,
        message: "\($d.name)@\($d.version): \(.severity) \(.advisory_summary)"}]' "$OUT/deps.json" > "$OUT/f-deps.json"

# 4. actionlint: workflow errors the PR adds. Lint the base too and keep only new ones,
#    matched on file, kind and message (line numbers shift).
lint() {
  [[ -d "$1/.github/workflows" ]] || { echo '[]'; return; }
  local rc=0
  run -v "$1:/repo" -w /repo "$ACTIONLINT" -format '{{json .}}' -no-color > "$OUT/lint.tmp" || rc=$?
  [[ $rc -le 1 ]] || { echo "::error::actionlint failed (exit $rc)" >&2; return 1; }
  jq '. // [] | [.[] | {filepath, line, kind, message}]' "$OUT/lint.tmp"
}
lint "$PWD" > "$OUT/lint-head.json"
echo '[]' > "$OUT/lint-base.json"
if [[ -n "$base" ]]; then
  rm -rf "$OUT/base" && mkdir -p "$OUT/base"
  git archive "$base" | tar -x -C "$OUT/base" && git -C "$OUT/base" init -q
  lint "$OUT/base" > "$OUT/lint-base.json"
fi
jq --slurpfile old "$OUT/lint-base.json" '
  ($old[0] | map("\(.filepath)|\(.kind)|\(.message)")) as $seen
  | [.[] | select(("\(.filepath)|\(.kind)|\(.message)") as $k | $seen | index($k) | not)
     | {tool: "actionlint", rule: .kind, path: .filepath, line, message}]' \
  "$OUT/lint-head.json" > "$OUT/f-actionlint.json"

# 5. Exceptions: entries in .github/security-exceptions.yml (owned by the security team in
#    CODEOWNERS). A valid entry covers findings with the same rule and path. An expired or
#    invalid entry is itself a finding, so it fails the gate in block mode until someone
#    fixes the code and removes it, or the security team approves a new date.
if [[ -f "$EXCEPTIONS" ]]; then
  yq -o=json '.exceptions // []' < "$EXCEPTIONS" > "$OUT/exceptions.json"
else
  echo '[]' > "$OUT/exceptions.json"
fi
today=$(date -u +%F)
limit=$(date -u -d "+$MAX_DAYS days" +%F)
jq --arg today "$today" --arg limit "$limit" '
  map(. as $e | (["id", "rule", "path", "reason", "owner", "expires"]
      | map(select(($e[.] // "") | tostring | length == 0))) as $missing
    | (($e.expires // "") | tostring) as $exp
    | . + {problem: (
        if ($missing | length) > 0 then "invalid: missing \($missing | join(", "))"
        elif ($exp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$") | not) then "invalid: expires must be YYYY-MM-DD, got \($exp)"
        elif $exp < $today then "expired on \($exp)"
        elif $exp > $limit then "invalid: expires \($exp) is later than the limit \($limit)"
        else null end)})' "$OUT/exceptions.json" > "$OUT/exceptions-checked.json"
jq --arg file "$EXCEPTIONS" '[.[] | select(.problem)
  | {tool: "exceptions", rule: (.problem | split(":")[0] | split(" ")[0]), path: $file, line: 1,
     message: "\(.id // "entry"): \(.rule // "?") in \(.path // "?"), owner \(.owner // "?"): \(.problem)"}]' \
  "$OUT/exceptions-checked.json" > "$OUT/f-exceptions.json"
jq '[.[] | select(.problem == null)]' "$OUT/exceptions-checked.json" > "$OUT/exceptions-valid.json"

# Report: every finding, with the id of the exception that covers it, if any.
jq -s 'add' "$OUT"/f-*.json \
  | jq --slurpfile ex "$OUT/exceptions-valid.json" '
      map(. as $f | . + {excepted: ([$ex[0][] | select(.rule == $f.rule and .path == $f.path) | .id] | first)})' \
  > "$OUT/findings.json"
n=$(jq 'map(select(.excepted == null)) | length' "$OUT/findings.json")
{
  echo "## Security gate"
  echo "Gate \`${GATE_REF:-local}\`, mode \`$MODE\`, scope: $scope"
  echo
  echo "| Tool | Findings | Covered by an exception |"
  echo "|---|---|---|"
  for t in semgrep gitleaks deps actionlint exceptions; do
    jq -r --arg t "$t" 'map(select(.tool == $t)) | "| \($t) | \(map(select(.excepted == null)) | length) | \(map(select(.excepted != null)) | length) |"' "$OUT/findings.json"
  done
  echo
  jq -r '.[] | "- **\(.tool)** `\(.rule)` \(.path):\(.line) \(.message)\(if .excepted then " (exception \(.excepted))" else "" end)"' "$OUT/findings.json"
} >> "$SUMMARY"

level=$([[ "$MODE" == block ]] && echo error || echo warning)
[[ "$MODE" == audit ]] || jq -r --arg l "$level" '.[] | select(.excepted == null)
  | "::\($l) file=\(.path),line=\(.line),title=\(.tool) \(.rule)::\(.message)"' "$OUT/findings.json"

if [[ "$MODE" == block && "$n" -gt 0 ]]; then
  echo "$n finding(s); failing in block mode"; exit 1
fi
echo "$n finding(s), mode $MODE"
