# security-workflows

The org's central security gate. Every repo calls `.github/workflows/security-gate.yml`
from a small `.github/workflows/security.yml`, pinned to a full commit SHA of this repo.

- Change the gate with a PR here. `self-test.yml` runs the PR's version of the gate.
- After merge, tag the commit (`vX.Y.Z`) and bump the callers with a PR per repo.
- The required status check in every repo's ruleset is `security / gate`.
