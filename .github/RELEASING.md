# Releasing hass-opnsense

<!-- cspell:ignore Hassfest -->

Release Please runs when a commit reaches `main`. It opens or updates a release
pull request based on conventional commit messages. Merging that pull request
updates both integration version files and the Release Please manifest; the next
run creates the `vMAJOR.MINOR.PATCH` tag and GitHub Release. The same run builds
`opnsense.zip` from the tagged `custom_components/opnsense` directory, verifies
its contents and versions, adds the OPNsense firmware compatibility note, and
uploads the archive.

The Release Please configuration retains `changelog-sections` for release notes
and sets `skip-changelog: true`. It does not create a `CHANGELOG.md` file.
`.github/release.yml` remains available for GitHub's generated release notes.

Release Please uses the repository's `GITHUB_TOKEN`. GitHub does not start new
workflow runs for the release pull request or release event created with that
token. Review and run the applicable CI checks before merging a release pull
request; the archive verification runs in the Release Please workflow after
the release is created.

If archive upload fails for a new Release Please GitHub Release, run the
**Release Please** workflow manually with that release's `vMAJOR.MINOR.PATCH`
tag as `release_tag`.
The recovery run checks the tagged integration versions, rebuilds and verifies
the archive, and replaces the existing `opnsense.zip` asset. It does not create
another release or move the tag.
