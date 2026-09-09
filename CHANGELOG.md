# Changelog

Changes are grouped by release. Pre-1.0 interfaces can change; format/schema
changes must be called out explicitly. Tags are immutable.

## Unreleased

No changes recorded yet.

## 0.1.1 — 2026-09-09

First release prepared with the cross-platform packaging workflow. No report or
rule schema migration is required. Downloads are available after release publication.

### Added

- Linux and Windows CI with packaged-binary smoke checks.
- Release packaging with SHA-256 sidecars, completions and a manual page.
- Tag-driven draft release workflow and scheduled dependency audits.
- Contribution/security policies, issue forms and a PR template.
- Quick-start examples and exit-code guidance in top-level CLI help.

### Fixed

- Replace two identity `map_or` calls with `unwrap_or` for newer Clippy versions.

## 0.1.0 — 2026-09-08

Initial tagged alpha release (`c24785f`).

- Offline codecs, recipes, hashes, JWT/certificate inspection, timestamps and regex tools.
- IOC extraction, secret masking, bounded bulk analysis and log watching.
- PE/ELF and archive inspection, local TOML rules and directory scanning.
- Unified reports, manifest-backed evidence bundles and saved-report comparison.
- Regression coverage for evidence replacement, manifest validation and secret previews.
- Use ring-backed JWT verification to remove the vulnerable rsa dependency.

The original tag's Linux CI failed on a Clippy lint; the correction is listed
under Unreleased. A tag alone does not imply downloadable binaries or a passed CI run.
