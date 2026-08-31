# Releasing hass-opnsense

## Normal release

1. Merge the release-ready changes into the default branch.
2. Create and publish a GitHub release targeted at that default branch, using a
   valid `v`-prefixed tag. Tags containing only numeric components are stable;
   tags with a suffix are prereleases. The tag initially points at the current
   default-branch commit.
3. The **Release** workflow runs on the published release event.

For a stable release, the workflow validates the tag and release target,
creates a deterministic version-only commit, builds and tests `opnsense.zip`,
publishes the candidate to a temporary validation branch, and dispatches the
immutable validation, pytest, and lint gates. Only their exact successful jobs
allow a lease-guarded atomic promotion of the default branch and annotated tag.
It then uploads `opnsense.zip` and adds the firmware compatibility note.

Prereleases build, validate, and upload the archive from the published tag but
never mutate the default branch or move the tag. Their source must already have
the matching manifest and `const.py` version.

No personal access token is needed. The workflow uses the scoped GitHub token
only for the release API, temporary validation ref, gate dispatch, guarded
promotion, and cleanup.

## Recovery

Do not force-move a tag or default branch after any failure. A failed stable
release intentionally leaves its temporary validation branch for inspection;
delete it only after determining that its candidate and CI evidence are no
longer needed. Create a new correctly targeted release after fixing any source
or workflow issue.

For an upload-only recovery, inspect the promoted annotated tag, version files,
and archive before attaching `opnsense.zip` to the existing release. Preserve
the firmware compatibility note using the firmware bounds from the tagged
`custom_components/opnsense/const.py`.
