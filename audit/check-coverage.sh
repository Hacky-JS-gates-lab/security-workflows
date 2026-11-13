#!/usr/bin/env bash
# Per repo, check that the controls from modules 2-5 are still in place:
#   caller     .github/workflows/security.yml calls the org gate, pinned to the SHA of the
#              newest vX.Y.Z tag of security-workflows, in block mode (fleet repos only)
#   codeowners .github/CODEOWNERS exists and GitHub reports no errors in it
#   events     the Actions event policy no-pwn-triggers is active and doesn't allow
#              pull_request_target or workflow_run
#   secrets    secret scanning and push protection are enabled
#   dependabot .github/dependabot.yml exists (fleet repos only)
# Prints "PASS|FAIL <repo> <check> <detail>", exits 1 on any FAIL.
#   ORG=<your-test-org> ./check-coverage.sh
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
GATE_REPO="${GATE_REPO:-security-workflows}"
rc=0
out() { echo "$1 $2 $3 $4"; [[ $1 == PASS ]] || rc=1; }
file() { gh api "repos/$ORG/$1/contents/$2" --jq .content 2>/dev/null | base64 -d 2>/dev/null; }

tag=$(gh api "repos/$ORG/$GATE_REPO/git/matching-refs/tags/v" --jq '.[].ref' | sed 's|refs/tags/||' | sort -V | tail -1)
sha=$(gh api "repos/$ORG/$GATE_REPO/commits/$tag" --jq .sha)

while read -r r; do
  if [[ $r != "$GATE_REPO" ]]; then
    caller=$(file "$r" .github/workflows/security.yml || true)
    if grep -q "uses: $ORG/$GATE_REPO/.github/workflows/security-gate.yml@$sha" <<<"$caller" && grep -qE '^\s*mode: block' <<<"$caller"; then
      out PASS "$r" caller "$tag block"
    elif [[ -z "$caller" ]]; then out FAIL "$r" caller "security.yml missing"
    else out FAIL "$r" caller "not $tag ($sha) in block mode: $(grep -oE '(@[0-9a-f]{7}|mode: \w+)' <<<"$caller" | tr '\n' ' ')"
    fi
    file "$r" .github/dependabot.yml >/dev/null && out PASS "$r" dependabot "dependabot.yml" || out FAIL "$r" dependabot "dependabot.yml missing"
  fi

  if file "$r" .github/CODEOWNERS >/dev/null; then
    n=$(gh api "repos/$ORG/$r/codeowners/errors" --jq '.errors | length')
    [[ $n == 0 ]] && out PASS "$r" codeowners "0 errors" || out FAIL "$r" codeowners "$n errors"
  else out FAIL "$r" codeowners "CODEOWNERS missing"; fi

  # The list has no rules, so read the policy itself.
  pid=$(gh api "repos/$ORG/$r/actions/policies" --jq '[.policies[] | select(.name == "no-pwn-triggers")][0].id // empty' 2>/dev/null || true)
  ev=missing
  [[ -n "$pid" ]] && ev=$(gh api "repos/$ORG/$r/actions/policies/$pid" --jq '
      if .enforcement != "active" then "enforcement \(.enforcement)"
      elif ([.rules[].parameters.allowed_events[]?] | any(. == "pull_request_target" or . == "workflow_run")) then "allows a dangerous trigger"
      else "ok" end' 2>/dev/null || echo unreadable)
  [[ $ev == ok ]] && out PASS "$r" events "no-pwn-triggers active" || out FAIL "$r" events "no-pwn-triggers $ev"

  ss=$(gh api "repos/$ORG/$r" --jq '"\(.security_and_analysis.secret_scanning.status)/\(.security_and_analysis.secret_scanning_push_protection.status)"')
  [[ $ss == enabled/enabled ]] && out PASS "$r" secrets "scanning + push protection" || out FAIL "$r" secrets "scanning/push protection $ss"
done < <(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[] | select(.archived | not) | .name')
exit $rc
