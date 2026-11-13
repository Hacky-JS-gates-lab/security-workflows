#!/usr/bin/env bash
# Check the guardrails that keep a coding agent or autofix bot from merging its own work:
#   org:   Actions can't approve PRs, default GITHUB_TOKEN is read-only
#   repos: no App or deploy key on the baseline ruleset's bypass list, code owner review on,
#          CODEOWNERS covers /.github/
#   apps:  every installed GitHub App, flagged if it can write workflows or administration,
#          or is installed on all repos
# Exit 1 on any FAIL. WARN lines don't fail.
#   ORG=<your-test-org> ./check-agent-guardrails.sh
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
rc=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; rc=1; }

w=$(gh api "orgs/$ORG/actions/permissions/workflow")
[ "$(jq -r .can_approve_pull_request_reviews <<<"$w")" = false ] && pass "org: Actions can't approve PRs" || fail "org: Actions can approve PRs"
[ "$(jq -r .default_workflow_permissions <<<"$w")" = read ] && pass "org: default token read" || fail "org: default token write"

for r in $(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[]|select(.archived|not)|.name'); do
  id=$(gh api "repos/$ORG/$r/rulesets" --jq '.[]|select(.name=="baseline")|.id')
  if [ -z "$id" ]; then fail "$r: no baseline ruleset"; continue; fi
  rs=$(gh api "repos/$ORG/$r/rulesets/$id")
  bots=$(jq -r '[.bypass_actors[]|select(.actor_type=="Integration" or .actor_type=="DeployKey")|"\(.actor_type):\(.actor_id)"]|join(",")' <<<"$rs")
  [ -z "$bots" ] && pass "$r: no App/deploy key can bypass" || fail "$r: bypass list has $bots"
  [ "$(jq -r '[.rules[]|select(.type=="pull_request")|.parameters.require_code_owner_review]|any' <<<"$rs")" = true ] &&
    pass "$r: code owner review required" || fail "$r: code owner review not required"
  co=$(gh api "repos/$ORG/$r/contents/.github/CODEOWNERS" --jq .content 2>/dev/null | base64 -d || true)
  grep -qE '^(/?\.github/|\*)[[:space:]]+@' <<<"$co" && pass "$r: CODEOWNERS covers .github/" || fail "$r: CODEOWNERS doesn't cover .github/"
done

# Listing installations needs an org owner token (admin:org scope).
gh api --paginate "orgs/$ORG/installations" --jq '.installations[] |
  "\(.app_slug) repos=\(.repository_selection) workflows=\(.permissions.workflows // "none") administration=\(.permissions.administration // "none") contents=\(.permissions.contents // "none")"' |
while read -r line; do
  case "$line" in
    *workflows=write*|*administration=write*|*repos=all*) echo "WARN app $line" ;;
    *) echo "INFO app $line" ;;
  esac
done
[ "$(gh api "orgs/$ORG/installations" --jq .total_count)" = 0 ] && echo "INFO no GitHub Apps installed"
exit $rc
