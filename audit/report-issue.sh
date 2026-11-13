#!/usr/bin/env bash
# Keep one open issue for fleet drift in $REPO.
#   drift found, no open issue  -> open one with the report
#   drift found, issue open     -> replace its body with the new report and comment the date
#   no drift, issue open        -> comment and close it
# Needs gh with issues:write on $REPO only (the workflow's GITHUB_TOKEN is enough).
#   REPO=<org>/security-workflows ./report-issue.sh <report.md> <drift: 0|1>
set -euo pipefail
: "${REPO:?set REPO=<org>/<repo>}"
REPORT="${1:?usage: report-issue.sh <report.md> <0|1>}"
DRIFT="${2:?drift 0 or 1}"
TITLE="Fleet audit: drift detected"

n=$(gh issue list -R "$REPO" --state open --search "\"$TITLE\" in:title" --json number,title \
  --jq "[.[] | select(.title == \"$TITLE\")][0].number // empty")
if [[ $DRIFT == 1 ]]; then
  if [[ -z "$n" ]]; then
    gh issue create -R "$REPO" --title "$TITLE" --body-file "$REPORT"
  else
    gh issue edit "$n" -R "$REPO" --body-file "$REPORT" >/dev/null
    gh issue comment "$n" -R "$REPO" --body "Still drifting on $(date -u '+%F %H:%M UTC'). Body updated with the latest report."
  fi
elif [[ -n "$n" ]]; then
  gh issue close "$n" -R "$REPO" --comment "No drift on $(date -u '+%F %H:%M UTC'). Closing."
else
  echo "no drift, no open issue"
fi
