# Releasing hass-opnsense

<!-- cspell:ignore Hassfest -->

## Stable releases

1. Merge release-ready changes into the default branch, then publish a GitHub
   Release with an unused valid `v`-prefixed stable tag targeting that branch.
   The new tag and branch must initially name the same commit.
2. The **Release** workflow creates one deterministic commit changing only
   `manifest.json` and `const.py`, then builds and validates `opnsense.zip`.
3. It publishes that candidate to a unique validation branch and dispatches its
   exact SHA to HACS, Hassfest, pytest, and lint checks. After they pass, it
   atomically advances the default branch and annotated tag, verifies both refs,
   uploads the archive, and idempotently adds the firmware compatibility note.

No personal access token is required. The workflow uses `GITHUB_TOKEN` with
step-scoped access; branch protection remains active for promotion.

## Prereleases

Publish an explicit unused prerelease tag whose `manifest.json` and `const.py`
versions already match. The workflow builds and uploads `opnsense.zip` without
creating a commit or moving a branch or tag. It also idempotently maintains the
firmware compatibility note. Before upload, the default branch and tag must
still resolve to the exact source selected by the published release.

## Failures and retries

A failed stable validation retains its `release-validation/...` branch. Verify
its exact SHA before deleting it; do not promote that commit directly or
force-move its tag.

If an upload fails after promotion, rerun the workflow only when the default
branch and annotated tag still name the same one-parent `Release <tag>` commit,
its only changed paths are the two version files, and regenerating those files
from the parent produces identical contents. Otherwise, start a new release
from current default-branch state.
