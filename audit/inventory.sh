#!/usr/bin/env bash
# Inventory every repo in an org: the settings this course hardens, plus an org-level snapshot.
# Writes inventory.json and prints a table. Needs gh (admin:org scope, org owner) and jq.
#
#   ORG=<your-test-org> ./inventory.sh            # writes ./inventory.json
#   ORG=<your-test-org> OUT=before.json ./inventory.sh
set -euo pipefail
: "${ORG:?set ORG=<your-org>}"
OUT="${OUT:-inventory.json}"

# true if the API call succeeds, false on 404, null if we can't tell (403, rate limit, ...).
# GitHub also answers 404 when you lack access, so run this as an org owner.
probe() {
  local err
  if err=$(gh api "$1" --silent 2>&1); then echo true
  elif [[ "$err" == *"HTTP 404"* ]]; then echo false
  else echo null; fi
}

org=$(jq -n \
  --argjson o "$(gh api "orgs/$ORG")" \
  --argjson a "$(gh api "orgs/$ORG/actions/permissions")" \
  --argjson w "$(gh api "orgs/$ORG/actions/permissions/workflow")" '{
    plan: $o.plan.name,
    two_factor_required: $o.two_factor_requirement_enabled,
    default_repository_permission: $o.default_repository_permission,
    members_can_create_public_repos: $o.members_can_create_public_repositories,
    secret_scanning_new_repos: $o.secret_scanning_enabled_for_new_repositories,
    push_protection_new_repos: $o.secret_scanning_push_protection_enabled_for_new_repositories,
    dependabot_alerts_new_repos: $o.dependabot_alerts_enabled_for_new_repositories,
    allowed_actions: $a.allowed_actions,
    sha_pinning_required: $a.sha_pinning_required,
    default_workflow_permissions: $w.default_workflow_permissions,
    actions_can_approve_prs: $w.can_approve_pull_request_reviews }')

rows=()
# --paginate follows every page; per_page=100 keeps the number of calls low.
while read -r repo; do
  full=$(jq -r .full_name <<<"$repo"); branch=$(jq -r .default_branch <<<"$repo")
  dep_yml=$(probe "repos/$full/contents/.github/dependabot.yml")
  [[ "$dep_yml" == false ]] && dep_yml=$(probe "repos/$full/contents/.github/dependabot.yaml")
  rows+=("$(jq -c \
    --argjson rulesets "$(gh api "repos/$full/rulesets" --jq length 2>/dev/null || echo null)" \
    --argjson protection "$(probe "repos/$full/branches/$branch/protection")" \
    --argjson dep_alerts "$(probe "repos/$full/vulnerability-alerts")" \
    --argjson dep_yml "$dep_yml" \
    --argjson workflows "$(gh api "repos/$full/actions/workflows" --jq '[.workflows[].path]' 2>/dev/null || echo null)" '{
      name, visibility, default_branch, archived, pushed_at,
      rulesets: $rulesets,
      branch_protection: $protection,
      secret_scanning: .security_and_analysis.secret_scanning.status,
      push_protection: .security_and_analysis.secret_scanning_push_protection.status,
      dependabot_alerts: $dep_alerts,
      dependabot_security_updates: .security_and_analysis.dependabot_security_updates.status,
      dependabot_yml: $dep_yml,
      workflows: $workflows }' <<<"$repo")")
done < <(gh api --paginate "orgs/$ORG/repos?per_page=100" --jq '.[] | @json')

printf '%s\n' "${rows[@]}" | jq -s --arg org "$ORG" --argjson settings "$org" \
  '{org: $org, generated_at: (now | todate), settings: $settings, repos: .}' > "$OUT"

echo "Org $ORG settings:"
jq -r '.settings | to_entries[] | "  \(.key) = \(.value)"' "$OUT"
echo
jq -r '["REPO","VIS","BRANCH","ARCH","RULESETS","PROTECT","SECRET_SCAN","PUSH_PROT","DEP_ALERTS","DEP_UPDATES","DEP_YML","WORKFLOWS","LAST_PUSH"],
  (.repos[] | [.name, .visibility, .default_branch, .archived, .rulesets, .branch_protection,
    .secret_scanning, .push_protection, .dependabot_alerts, .dependabot_security_updates, .dependabot_yml,
    ((.workflows // []) | map(split("/") | last) | join(",")), .pushed_at[:10]])
  | map(if . == null then "?" else tostring end) | @tsv' "$OUT" | column -t -s $'\t'
echo
echo "$(jq '.repos | length' "$OUT") repos written to $OUT"
