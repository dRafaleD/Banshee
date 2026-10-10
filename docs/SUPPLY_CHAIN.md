# Package provenance and dependency inventory

CI and release packaging produce one target-specific CycloneDX 1.5 inventory per
archive. `scripts/sbom.ps1` checks that generation did not change Cargo.lock;
`scripts/package.ps1 -SbomPath target/banshee.sbom.json` includes that inventory
inside the archive and uploads it alongside the archive. This inventory covers
Cargo dependencies, not every OS library, compiler or tool used by the build.

Trusted CI runs attest candidate archives; pull requests do not receive signing
permissions. Tagged release jobs attest their own archives before creating a draft.
All actions are pinned to reviewed commit SHAs. Dependabot updates those pins;
review the new source and test results before merging. Signing permissions are
limited to provenance/release-build jobs; release creation has only contents write.

## Verify a downloaded archive

First check the SHA-256 sidecar. Then verify the signing repository, workflow and
source commit, not just that some signature exists:

```sh
gh attestation verify ARCHIVE --repo dRafaleD/Banshee \
  --signer-workflow dRafaleD/Banshee/.github/workflows/release.yml \
  --source-ref refs/tags/vVERSION --source-digest FULL_COMMIT_SHA
gh attestation verify ARCHIVE --repo dRafaleD/Banshee \
  --signer-workflow dRafaleD/Banshee/.github/workflows/release.yml \
  --source-ref refs/tags/vVERSION --source-digest FULL_COMMIT_SHA \
  --predicate-type https://cyclonedx.org/bom
```

For a development candidate, use `ci.yml` and the actual `refs/heads/codex/...`
branch and commit instead. A verified candidate is not a published release.
v0.1.1 predates this infrastructure: do not claim it has attestations or new
platform downloads. Existing tags and releases are never rewritten to add them.

An attestation establishes who made a claim about these exact archive bytes. It
does not guarantee a reproducible build, absence of bugs or a malware verdict.

Reference: [GitHub artifact attestation guide](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
