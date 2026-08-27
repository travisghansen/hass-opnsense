# Releasing hass-opnsense

## Normal release

1. Merge the release-ready changes into the default branch.
2. From that branch, run the **Release** workflow with one of these inputs:

   - To release an explicit tag (including every prerelease), provide an unused,
     valid `v`-prefixed tag, leave **bump** set to `none`, and set
     **prerelease** to match the tag. Tags with a suffix are prereleases; tags
     containing only numeric components are stable.
   - To make a stable automatic bump, leave **tag** blank, set **prerelease** to
     false, and choose `patch`, `minor`, or `major`. The workflow derives the
     next tag from the published stable releases.

3. Wait for the workflow to validate the tag, create a local version-only
   commit and annotated tag, build and test `opnsense.zip` from that tag, push
   only the tag, and create the GitHub release with generated and firmware
   compatibility notes.

No personal access token is needed. The workflow never pushes `main`.

## Rare recovery after a tag push

If the tag push succeeds but GitHub release creation fails, do not rerun the
workflow: it correctly rejects existing tags. This is especially important for
automatic bumps, which intentionally have no persisted retry state. Do not
force-move the tag.

1. Inspect the existing tag and its version files:

   ```sh
   git fetch --tags origin
   git show --no-patch --decorate <tag>
   git show <tag>:custom_components/opnsense/manifest.json
   git show <tag>:custom_components/opnsense/const.py
   ```

2. If the tag and both version files are correct, build and test the archive
   directly from the tag:

   ```sh
   git archive --format=zip --output=opnsense.zip \
     <tag>:custom_components/opnsense
   unzip -t opnsense.zip
   ```

3. Inspect the GitHub release. If none exists, create it with the archive; if a
   matching draft exists, finish that draft and attach the archive. Do not
   create a second release for the tag. Preserve the firmware compatibility
   note used by the workflow when creating the release manually.

   ```sh
   gh release view <tag>
   gh release create <tag> opnsense.zip \
     --generate-notes --title <tag> --verify-tag
   # Or, for an existing matching draft:
   gh release upload <tag> opnsense.zip --clobber
   gh release edit <tag> --draft=false
   ```

   Add `--prerelease` when the tag is a prerelease.

If the tag points to the wrong commit or contains wrong version files, leave it
unchanged and release a new, correct version instead.
