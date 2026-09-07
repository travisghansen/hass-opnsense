# Releasing hass-opnsense

<!-- cspell:ignore Hassfest -->

## Prerequisites

Publishing a GitHub Release is the only release trigger (`release: published`).
Create it with a new `v`-prefixed tag targeting the repository default branch.
At the start of the run, that tag and the default branch must name the same
commit. Stable tags are numeric `v` versions with two, three, or four
components; the prerelease setting must agree with the tag format. A
prerelease archive must already contain its tag in both
`custom_components/opnsense/manifest.json` and `const.py`.

## Stable releases

The workflow rechecks the default branch before running its trusted helpers,
then creates a deterministic candidate commit that changes only those two
version files. It builds and verifies `opnsense.zip` from that commit before
pushing the candidate to a unique `release-validation/...` branch.

It dispatches and verifies these exact candidate-SHA gates:

- `pytest_check.yml::pytest check and post coverage`
- `uv-lock-check.yml::Validate uv lock consistency`
- `validate.yml::Hassfest Validation`
- `validate.yml::HACS Validation`
- `linters.yml::review`

After every gate succeeds, the workflow atomically advances the default branch
and replaces the tag with an annotated tag, using leases for both original
refs. It fetches them again, requires both to resolve to the candidate, verifies
the archive again, adds the OPNsense firmware-compatibility note if absent, and
uploads the archive. The validation branch is deleted only after success.

## Prereleases

A prerelease builds `opnsense.zip` directly from the published source. It does
not create a candidate commit, dispatch release gates, create a validation
branch, or move the branch or tag. Before upload, the workflow rechecks the
original branch, tag object, and tag target; it verifies the archive and
idempotently adds the firmware-compatibility note.

## Failures and recovery

The workflow stops if the target is not the default branch, the default branch
moves, the tag identity changes, the tag kind is inconsistent, archive
validation fails, a gate does not complete successfully for the dispatched
SHA, or a guarded ref check fails. Do not promote a validation branch directly
or force-move its tag.

If a stable run has created a validation branch, it remains after failure.
Confirm its candidate SHA before removing it:

```sh
git fetch origin "refs/heads/<temporary-ref>:refs/remotes/origin/<temporary-ref>"
git rev-parse "refs/remotes/origin/<temporary-ref>"
git push --force-with-lease="refs/heads/<temporary-ref>:<candidate-sha>" origin --delete "<temporary-ref>"
```

If promotion reports an error, inspect both remote refs before retrying. Do
not assume an atomic push left them unchanged; treat a branch/tag split as an
incident. If upload fails after promotion, rerun only when the branch and tag
still name the same one-parent `Release <tag>` commit, it changed only the two
version files, and recreating those files from its parent is identical.
Otherwise, publish a new release from current default-branch state without
moving the original tag.
