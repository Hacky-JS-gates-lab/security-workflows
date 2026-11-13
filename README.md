# security-workflows

The org's central security gate. Every repo calls `.github/workflows/security-gate.yml`
from a small `.github/workflows/security.yml`, pinned to a full commit SHA of this repo.

- Change the gate with a PR here. `self-test.yml` runs the PR's version of the gate.
- After merge, tag the commit (`vX.Y.Z`) and bump the callers with a PR per repo.
- The required status check in every repo's ruleset is `security / gate`.
- Dependabot (`.github/dependabot.yml` in each fleet repo) also proposes the bump when a new
  tag appears; the gate is excluded from cooldown and gets its own PR.
- `scripts/new-packages.js` looks up every npm package a PR adds on the registry; its
  self-test (`node --test scripts/*.test.js`) runs as the `unit` job of `self-test.yml`.
- zizmor (v2.3.0) audits the repo's workflows. New high-severity findings fail the gate;
  every finding goes to code scanning as SARIF (category `zizmor`). Callers must grant
  `security-events: write` to the `security` job for the upload, so a version that needs it
  is rolled out with `rollout-callers.sh` (new caller template), not by a Dependabot SHA bump.
