# Releasing Banshee

Release tags are immutable. A pushed tag is distinct from a GitHub Release with
notes and downloadable assets. Never move a published tag to repair CI.

## Prepare

1. Choose a new version. During 0.x, use minor releases for interface changes and
   patch releases for compatible fixes; document any schema/CLI incompatibility.
2. Update Cargo.toml and Cargo.lock together, and move Unreleased changelog entries
   into a dated release section. Add `docs/releases/vVERSION.md` with the public
   release notes. Review all security and compatibility notes.
3. Run format, tests, Clippy, release build and both lockfile audits; inspect all
   five native CI targets for the exact commit being released.
4. Install cargo-cyclonedx 0.5.9 with `--locked`, run `scripts/sbom.ps1`, then
   `pwsh -File scripts/package.ps1 -SbomPath target/banshee.sbom.json` after building.
   Packaging refuses existing archives,
   generates completions/manuals, unpacks and tests the binary, and emits SHA-256
   sidecars in `dist/`. Move previous output aside before packaging the same version.

## Publish

Create an annotated tag matching Cargo's version and push that tag. The release
workflow checks the version, runs tests and builds Windows x86_64 MSVC, Linux GNU
x86_64/ARM64 and macOS Intel/Apple Silicon packages on native runners. It generates
target-specific SBOMs and verifies provenance/SBOM attestations for every archive.
Only after all jobs pass does it create a **draft** GitHub
Release using the versioned release notes. Review the notes and alpha prerelease flag, then
publish. Do not describe a draft as publicly available.

Manual workflow dispatch accepts an existing version tag containing this workflow
and packaging script. Select that same tag as the workflow's run ref (for example,
`gh workflow run release.yml --ref vVERSION -f tag=vVERSION`); branch-based dispatch
is rejected so the signing identity and source digest match the package's tag.
The original v0.1.0 tag predates them and cannot use this
pipeline; use a new version for the first packaged release. Existing releases are
not overwritten automatically; inspect any partial draft before retrying.

## Distribution channels

None of these steps run automatically; each is a reviewed, manual action taken
only after the GitHub Release is published and its checksums are verified.

- **crates.io**: `cargo package --locked` must pass locally (it builds the
  packaged crate without uploading). Publishing with `cargo publish` is an
  irreversible public action for that version number.
- **cargo-binstall**: `[package.metadata.binstall]` in Cargo.toml points at the
  release archives, so `cargo binstall banshee` works once a release exists.
- **Scoop, Homebrew and winget**: download the release archives and `.sha256`
  sidecars into `dist/`, then run
  `pwsh -File scripts/render-packaging.ps1 -Version VERSION`. It verifies each
  sidecar (and the archive when present), fills the templates in `packaging/`
  and writes the results to `dist/packaging/`. Review them and submit them to a
  bucket, tap or the winget-pkgs repository by hand. A manifest is skipped when
  a platform it needs has no verified checksum.

## Verify downloads

On Linux, download the archive and matching sidecar into the same directory:

```sh
sha256sum --check banshee-VERSION-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf banshee-VERSION-x86_64-unknown-linux-gnu.tar.gz
```

On PowerShell, compare the hash with the first field in the sidecar:

```powershell
$archive = 'banshee-VERSION-x86_64-pc-windows-msvc.zip'
$expected = ((Get-Content "$archive.sha256").Trim() -split '\s+')[0]
if ((Get-FileHash $archive -Algorithm SHA256).Hash -ine $expected) { throw 'Checksum mismatch' }
Expand-Archive $archive
```

Checksums detect corrupted or inconsistent downloads; they are not signatures.
See [supply-chain verification](SUPPLY_CHAIN.md) for signing identity and source
commit checks. Candidate CI attestations are not release attestations.
Linux GNU binaries are built on Ubuntu 24.04 and require compatible glibc/liblzma;
they are not static/musl builds. macOS packages use native macOS 15 runners and
Homebrew xz; they are unsigned/not notarized and may require Homebrew xz at runtime.
Five-platform packages with attestations first shipped in v0.2.0; the older
v0.1.1 release remains Windows/Linux x86_64 without these attestations.
Releases are published as alpha pre-releases while Banshee is pre-1.0.
