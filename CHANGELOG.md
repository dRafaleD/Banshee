# Changelog

Changes are grouped by release. Pre-1.0 interfaces can change; format/schema
changes must be called out explicitly. Tags are immutable.

## Unreleased

### Added

- Six-phase quality plan, synthetic parser mutation checks and bounded cargo-fuzz infrastructure.
- Native Linux ARM64 and macOS Intel/Apple Silicon CI/package candidates.
- Target-specific CycloneDX inventories and verified build/SBOM attestations;
  SHA-pinned actions with scoped signing permissions.
- Safe source installers, frozen report compatibility fixtures and documented
  ongoing dependency/fuzz review procedures.
- UTF-16LE text layers inside Base64/Hex payloads, such as PowerShell
  `-EncodedCommand` arguments.
- Heuristic single-byte XOR layers inside Base64/Hex payloads (16 B to 64 KiB),
  reported with the recovered key and capped at 80% confidence. Raw binary
  input is never brute-forced.
- `report --format html`: a single offline page with summary, severity-sorted
  findings, decoded layer chains, indicators, rule matches and executable or
  archive details. It contains no script or external resource, declares a
  `default-src 'none'` Content-Security-Policy, escapes every sample-derived
  value and masks detected credentials. Long tables are capped with a note
  pointing to the JSON report.
- `export --format stix|misp|csv` for saved reports and verified evidence
  bundles. STIX 2.1 output holds deterministic cyber-observable objects in a
  `grouping` (no `indicator` objects); MISP attributes use `to_ids: false`; CSV
  fields are quoted and protected against spreadsheet formulas. Redacted
  credentials are never exported.
- Indicators that only appear after decoding (for example a URL inside a
  Base64 UTF-16LE PowerShell command) are added to content analysis with a
  `(decoded)` source, the encoded token's line and the layer chain as detail.
- Optional rule `attack` metadata for MITRE ATT&CK tactic, technique and
  sub-technique identifiers, strictly validated and shown with rule findings
  and as rule-declared coverage in HTML reports. Omitted from JSON when unset.
- In-memory `cert::inspect_bytes`/`inspect_chain_bytes` and
  `rules::validate_source`/`scan_source` library entry points.
- Eight additional fuzz targets: content analysis, IOC extraction, rule
  compilation/scanning, certificates, JWT inspection, report compatibility,
  recipes and codec round trips.

### Changed

- Analysis layers may carry an optional `detail` field (for example, an XOR
  key). It is omitted when empty, so existing schema version 1 consumers are
  unaffected.
- `file_inspect` is split into archive, PE, ELF and shared byte-reader modules
  without behavior changes.

### Fixed

- Apply the 256 MiB inspection input cap to memory-based callers and reads that
  grow past their initial file metadata size.
- Unicode escape decoding no longer panics when `\u` is followed by a
  multi-byte character, and it rejects signed digits such as `\u+041`. Found by
  the new codec fuzz target; reachable through `decode unicode` and `whatis`.
- Certificates (4 MiB), JWT keys (1 MiB) and IOC allow/deny lists (4 MiB) are
  now read with explicit limits; rule files, saved reports, evidence manifests
  and report inputs also stop reading if they grow past their checked size.
- PEM chains are limited to 64 certificates.
- Domain extraction no longer reports file names whose final label is a
  common non-TLD file extension, such as `gate.php` or `payload.exe`.

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
