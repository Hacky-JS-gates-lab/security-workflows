#!/usr/bin/env bash
# Read the org settings with security impact and compare them with policy.json.
# Scalars must match exactly; lists are allowlists (anything not in the list fails).
# Exit code 1 if any check fails or can't be read. Needs gh (org owner, admin:org) and jq.
#
#   ORG=<your-test-org> ./check-org.sh
#   ORG=<your-test-org> POLICY=my-policy.json ./check-org.sh
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
POLICY="${POLICY:-$(dirname "$0")/policy.json}"

# null means "couldn't read" (403, 404, rate limit) and is reported as UNKNOWN, never as PASS.
get() { local out; if out=$(gh api "$1" 2>/dev/null); then echo "$out"; else echo null; fi; }
list() {  # a JSON array of strings from a paginated endpoint, or null
  local out
  if out=$(gh api --paginate "$1" --jq "$2" 2>/dev/null); then
    jq -R . <<<"$out" | jq -sc 'map(select(length > 0))'
  else echo null; fi
}
arr() { printf '%s\n' "$@" | jq -R . | jq -sc 'map(select(length > 0))'; }

o=$(get "orgs/$ORG")
a=$(get "orgs/$ORG/actions/permissions")
w=$(get "orgs/$ORG/actions/permissions/workflow")
f=$(get "orgs/$ORG/actions/permissions/fork-pr-contributor-approval" | jq -r '.approval_policy // "?"')

# Per repo: a repo admin can loosen fork PR approval, and deploy keys live on repos.
overrides=(); keys=(); repos_ok=true
repos=$(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[] | select(.archived | not) | .full_name' 2>/dev/null) || repos_ok=false
while read -r repo; do
  [[ -z "$repo" ]] && continue
  rp=$(gh api "repos/$repo/actions/permissions/fork-pr-contributor-approval" --jq .approval_policy 2>/dev/null || echo "?")
  [[ "$rp" != "$f" ]] && overrides+=("$repo:$rp")
  n=$(gh api "repos/$repo/keys" --jq length 2>/dev/null || echo "?")
  [[ "$n" != 0 ]] && keys+=("$repo:$n")
done <<<"$repos"
ov=$(arr "${overrides[@]}"); ky=$(arr "${keys[@]}")
$repos_ok || { ov=null; ky=null; }

current=$(jq -n --argjson o "$o" --argjson a "$a" --argjson w "$w" --arg f "$f" \
  --argjson overrides "$ov" --argjson keys "$ky" \
  --argjson no2fa "$(list "orgs/$ORG/members?filter=2fa_disabled&per_page=100" '.[].login')" \
  --argjson outside "$(list "orgs/$ORG/outside_collaborators?per_page=100" '.[].login')" \
  --argjson apps "$(list "orgs/$ORG/installations?per_page=100" '.installations[].app_slug')" '
  ($o // {}) + {
    allowed_actions: $a.allowed_actions, sha_pinning_required: $a.sha_pinning_required,
    default_workflow_permissions: $w.default_workflow_permissions,
    can_approve_pull_request_reviews: $w.can_approve_pull_request_reviews,
    fork_pr_approval: (if $f == "?" then null else $f end),
    fork_pr_approval_repo_overrides: $overrides, repos_with_deploy_keys: $keys,
    members_without_2fa: $no2fa, outside_collaborators: $outside, apps_installed: $apps }')

result=$(jq -r --argjson cur "$current" '
  to_entries[] | .key as $k | .value as $want | $cur[$k] as $got
  | (if $got == null then "UNKNOWN"
     elif ($want | type) == "array" then (if ($got - $want) == [] then "PASS" else "FAIL" end)
     elif $got == $want then "PASS" else "FAIL" end) as $r
  | "\($r)\t\($k)\t\($got | tojson)\t\(if $r == "PASS" then "" else "want \($want | tojson)" end)"' "$POLICY")

column -t -s $'\t' <<<"$result"
fails=$(grep -cv '^PASS' <<<"$result" || true)
echo; echo "$fails of $(wc -l <<<"$result") checks not passing"
[[ "$fails" == 0 ]]
