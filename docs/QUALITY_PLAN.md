# Banshee next development cycle

Agreed sequence: implement and verify each phase, using independent agents for
bounded parallel work. The owner authorized completing all remaining phases on
2026-10-10 and pushing a separate development branch for native/attestation
verification, without changing existing tags or publishing a new release.
Record results and limitations here. Completed v0.1 features remain in ROADMAP.md.

| Phase | Scope | Acceptance | Status |
| --- | --- | --- | --- |
| 1. Parser resilience | PE/ELF, ZIP/TAR and gzip/XZ/BZip2 fuzzing; input and expansion limits | Synthetic mutation tests, sanitizer fuzz runs and resource assertions; reproducible failures retained | Completed locally; remote CI pending |
| 2. Release provenance | SBOM, build attestations, action SHA pinning, minimum workflow permissions | Verify exact candidate archives and inventory; future releases use the same signing controls | Local package passed; native CI pending |
| 3. Platform coverage | macOS, Linux ARM64, then macOS ARM64 | Each advertised target builds and its packaged binary runs on that architecture | Native CI pending |
| 4. Report compatibility | Versioned schema, saved fixtures, migration/compatibility policy | Older saved reports compare predictably; schema changes are documented | Local tests passed; native CI pending |
| 5. Daily CLI use | Windows/Linux installation, help, troubleshooting and command examples | Documented installation and example commands work on supported platforms | Windows tests passed; native CI pending |
| 6. Ongoing security | Scheduled audits, clear support policy, tracked security review | Failures stay visible and supported versions/reporting channels are documented | Both local lockfile audits passed; remote checks pending |

## Phase 1 delivery

- Use synthetic files only. Include valid headers so fuzzing reaches deeper parsing.
- Keep deterministic mutation checks in ordinary Linux/Windows tests.
- Use cargo-fuzz with AddressSanitizer in Linux for coverage-guided testing.
- Set explicit run time, per-input timeout, input length and RSS limits.
- Preserve generated failures as artifacts; turn confirmed bugs into regressions.
- Ensure the 256 MiB input cap applies to memory and file reads, including a file
  growing during reading. Keep decompression capped at 64 MiB.
- A short fuzz run is a smoke check, not an exhaustive security assessment.

### Verified results (2026-10-10)

- Windows: all 142 tests passed (84 unit, 49 CLI, 6 bug regressions, 3 security
  regressions). Clippy with warnings denied, both formatting checks and diff
  whitespace checks passed.
- Eight synthetic seed files validated before fuzzing.
- Ubuntu/WSL: cargo-fuzz 0.13.2, Rust nightly 1.101.0 (2026-10-09), default
  AddressSanitizer. Seed 451248681; 107,188 executions in 61 seconds; exit code 0,
  no crash or sanitizer report.
- Campaign: max input 1 MiB, per-input timeout 10 seconds, RSS limit 1024 MiB;
  input/output resource assertions enabled. This is not exhaustive coverage.
- File reads now stop after the limit plus one detection byte. Memory inspection
  rejects oversized inputs before hashing. Added boundary, high-expansion gzip,
  mutation and truncation regressions.
- Added pull-request/push/weekly fuzz smoke workflow with failure artifacts.
  The workflow has not yet been pushed or verified on GitHub.
- The fuzz workspace keeps its own dependency lockfile; ordinary regression
  tests use the application's root lockfile. Neither is an unpinned dependency run.

## Remaining-cycle implementation

- [Supply-chain guide](SUPPLY_CHAIN.md): CycloneDX 1.5 inventory, pinned actions,
  scoped OIDC permissions, and repository/workflow/source verification for archives.
- Native CI/package matrix: Windows x86_64, Linux GNU x86_64/ARM64,
  macOS Intel/Apple Silicon. New release downloads require a future release;
  macOS packages are not code-signed/notarized or promised dependency-free.
- [Report contract](REPORT_COMPATIBILITY.md): explicit v1 validation, synthetic
  saved fixtures, unknown-field tolerance, missing/empty semantics and redaction.
  Current schema remains 1; no invented cross-version migration.
- [Installation guide](INSTALLATION.md): native-source installers respect Cargo
  directories, refuse implicit overwrite, and have isolated end-to-end tests.
- [Security review process](SECURITY_CHECKS.md): both lockfiles audited, bounded
  fuzz checks, dependency update coverage and actionable failure handling. Existing
  support/reporting policy is retained; no SLA or automatic disclosure is added.
- Local integration: all 156 Rust tests passed; Windows release archive unpacked
  and smoke-tested with its 138-component Windows Cargo inventory. Windows
  isolated installation/examples, formatting, Clippy and actionlint passed.

Remote validation results will be recorded below after the exact branch commit
passes. No new release/tag is authorized or created by this development cycle.

Follow-up work discovered during a phase belongs in its result notes or the next
phase; do not silently expand into all six phases at once.
