# Banshee next development cycle

Agreed sequence: implement and verify each phase, using independent agents for
bounded parallel work. The owner authorized completing all remaining phases on
2026-10-10 and pushing a separate development branch for native/attestation
verification, without changing existing tags or publishing a new release.
Record results and limitations here. Completed v0.1 features remain in ROADMAP.md.

| Phase | Scope | Acceptance | Status |
| --- | --- | --- | --- |
| 1. Parser resilience | PE/ELF, ZIP/TAR and gzip/XZ/BZip2 fuzzing; input and expansion limits | Synthetic mutation tests, sanitizer fuzz runs and resource assertions; reproducible failures retained | Complete; local and GitHub fuzz passed |
| 2. Release provenance | SBOM, build attestations, action SHA pinning, minimum workflow permissions | Verify exact candidate archives and inventory; future releases use the same signing controls | Complete; five candidate archives attested and verified |
| 3. Platform coverage | macOS, Linux ARM64, then macOS ARM64 | Each advertised target builds and its packaged binary runs on that architecture | Complete; all five native targets passed |
| 4. Report compatibility | Versioned schema, saved fixtures, migration/compatibility policy | Older saved reports compare predictably; schema changes are documented | Complete; all native regression suites passed |
| 5. Daily CLI use | Windows/Linux installation, help, troubleshooting and command examples | Documented installation and example commands work on supported platforms | Complete; isolated installation/examples passed on five targets |
| 6. Ongoing security | Scheduled audits, clear support policy, tracked security review | Failures stay visible and supported versions/reporting channels are documented | Complete on development branch; expanded schedules activate on merge |

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
- Added pull-request/push/weekly fuzz smoke workflow with failure artifacts;
  the branch push has now been verified on GitHub (see results below).
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

## GitHub verification (2026-10-10)

Implementation commit `55ae93286682c240a6cf4325cfce278cedf817d0` on
`codex/quality-cycle-20261010` passed:

- [Native CI and provenance](https://github.com/dRafaleD/Banshee/actions/runs/38075397375):
  all five native test/build/package/installer jobs and all five provenance jobs
  succeeded. Both provenance and CycloneDX assertions verified archive bytes,
  repository, signer workflow, source branch and source commit for each package.
- [Dependency audit](https://github.com/dRafaleD/Banshee/actions/runs/38075397441):
  application and fuzz lockfiles passed with warnings denied.
- [Parser fuzz smoke](https://github.com/dRafaleD/Banshee/actions/runs/38075397497):
  seed 1835644270, 676,572 executions in 61 seconds, exit code 0.
- Downloaded Windows/Linux/Apple Silicon candidates were independently checksum
  checked; downloaded Windows package ran locally and its internal/external SBOMs
  matched. Windows archive provenance and SBOM were also independently verified
  with the exact source commit/ref using the GitHub CLI.
- SBOM counts: Windows/macOS 138 Cargo components; Linux 139. These are target
  dependency inventories, not OS/runtime-library inventories.

Final refinements upgrade checkout/artifact actions to SHA-pinned Node 24 versions
and reject wrong-target inventories. Local negative inventory tests passed; all
changes remain subject to the branch's latest CI status before handoff.

No new release/tag is authorized or created. New public platform downloads and
release-tag attestations await a future authorized release. Existing v0.1.1 stays
unchanged. GitHub's expanded schedules activate only after merge to master.

Follow-up work discovered during a phase belongs in its result notes or the next
phase; do not silently expand into all six phases at once.

## Hardening cycle (2026-10-12 to 2026-10-14)

Local verification on Windows with Ubuntu/WSL for sanitizer fuzzing. These are
bounded runs, not exhaustive coverage.

- Fuzzing: ten cargo-fuzz targets with AddressSanitizer, five minutes each with
  a retained corpus, about 64 million executions in total and no failures.
  Earlier short runs found two panics, both fixed with regression tests:
  Unicode escape decoding split a UTF-8 sequence (`codec_roundtrip`), and YARA
  condition splitting sliced inside a multi-byte character (`yara_import`).
- Mutation testing: cargo-mutants on the ssdeep, decoder, script, YARA, PE
  metadata, TLD and export modules (library tests only). Missed mutants led to
  golden ssdeep vectors, decoder limit and confidence tests, direct export
  tests, TLD snapshot checks, and a guard against reporting an all-zero XOR
  key. A full rerun after these changes is still pending.
- Cross-checks: imphash and TLS callback counts matched pefile on 300 local
  Windows system binaries; ssdeep digests matched an independent
  implementation on 426 of 427 inputs (the remaining one-byte case follows
  ssdeep's C source).
