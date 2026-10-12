![Banshee — offline security analysis toolkit](assets/banshee-banner-green-animated-v3.gif)

# Banshee

[![Status: Alpha](https://img.shields.io/badge/status-alpha-f59e0b)](https://github.com/dRafaleD/Banshee)
[![CI](https://github.com/dRafaleD/Banshee/actions/workflows/ci.yml/badge.svg)](https://github.com/dRafaleD/Banshee/actions/workflows/ci.yml)
[![Primary language: Rust](https://img.shields.io/badge/primary%20language-Rust-dea584)](https://github.com/dRafaleD/Banshee)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Banshee is an offline, pipe-friendly security analysis toolkit written in Rust.
Turn a suspicious value, local file, or log into explainable findings and
shareable reports. Decode nested content, normalize indicators, inspect PE/ELF
metadata, apply local rules, and preserve results in verifiable evidence bundles.
Analysis runs locally without uploading your inputs.

[Quick start](#quick-guide) · [Capabilities](#choose-a-workflow) ·
[Install](#build) · [Command examples](examples/usage.md) ·
[Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

Development guides: [installation](docs/INSTALLATION.md),
[report compatibility](docs/REPORT_COMPATIBILITY.md),
[package provenance](docs/SUPPLY_CHAIN.md),
[ongoing security checks](docs/SECURITY_CHECKS.md).

> [!WARNING]
> **Alpha / early draft.** Banshee is under active development. Expect incomplete,
> broken, or incorrect behavior; commands, output formats, rule syntax, and
> limits may change before a stable release. Treat its findings as analyst
> assistance—not as a final security verdict.

## Choose a workflow

| Task | Commands | Result |
| --- | --- | --- |
| Understand an unknown value | `whatis`, `entropy`, `recipe` | Decoding layers and explainable signals |
| Collect indicators from logs | `extract`, `analyze`, `watch` | Normalized IOCs, bounded context, masked secret candidates |
| Inspect local artifacts | `file inspect`, `jwt`, `cert`, `hash` | Structural metadata for archives, executables, Office, PDF and LNK files |
| Apply detection logic | `rules validate`, `rules scan`, `scan` | Local rule matches and per-file statuses |
| Prepare an investigation report | `report` | Text, JSON, Markdown or self-contained HTML |
| Preserve and compare results | `evidence`, `diff` | Hash-checked bundles and saved-report differences |
| Share observables with other tools | `export` | STIX 2.1, MISP event JSON or CSV |

Output formats vary by command. Use `banshee <command> --help` for supported
formats and limits. Findings are triage signals; review them before acting.

## Quick guide

Try a harmless decoding example after building:

```text
$ banshee decode base64 aGVsbG8=
hello
```

Build the release binary, then pass Banshee a value, a file, or standard input:

```bash
cargo build --release

# Identify and unpack suspicious encoded content.
target/release/banshee whatis "aGVsbG8lMjB3b3JsZA=="

# Extract IOCs from a local log without sending it anywhere.
cat suspicious.log | target/release/banshee extract --defang

# Locate possible credentials while keeping values and context redacted.
target/release/banshee extract --secret --context 2 --file application.log

# Inspect a local file, archive, certificate, or executable.
target/release/banshee file inspect suspicious.zip
target/release/banshee cert inspect certificate.pem

# Emit structured output for scripts and pipelines.
target/release/banshee analyze --format json --file suspicious.bin

# Combine file metadata, hashes, entropy, IOCs, and local rule results.
target/release/banshee report suspicious.bin --format markdown --output report.md

# Scan a directory with explicit recursion and bounded resource limits.
target/release/banshee scan ./samples --recursive --include '*.bin' --format jsonl

# Create and later verify a redacted evidence directory.
target/release/banshee evidence create suspicious.bin --output case-evidence
target/release/banshee evidence verify case-evidence

# Compare two saved reports or verified evidence directories.
target/release/banshee diff baseline-report.json current-report.json

# Share observables from a saved report or verified bundle (never verdicts or secrets).
target/release/banshee export case-evidence --format stix --output observables.stix.json
```

### What it can help with

- Decode layered Base64, hexadecimal, URL/HTML encoding, compression, and recipes.
- Extract and normalize URLs, domains, IP addresses, hashes, emails, and other IOCs.
- Track IOC source, line, column, and bounded optional context.
- Detect common credential and private-key markers with safe default redaction.
- Analyze entropy, common encodings, JWTs, hashes, timestamps, certificates, archives, ELF, and PE files.
- Run local TOML rules, inspect regex patterns, and watch fresh log lines.
- Build unified text, JSON, Markdown, or script-free HTML reports for individual
  local files.
- Create manifest-backed evidence directories and verify their file hashes
  completely offline.
- Compare compatible reports or evidence bundles without reopening or
  re-analyzing their original samples.
- Scan local directories with explicit recursion, path filters, deterministic
  ordering, and per-file status reporting.
- Work offline with pipe-friendly human, JSON, JSONL, and CSV output.

## Capabilities (alpha)

The initial foundation includes the following commands:

- Detects Base64, hexadecimal, URL encoding, and HTML entities.
- Recursively decodes nested layers with depth and size limits.
- Detects Base64/Hex-wrapped gzip and zlib layers with a 16 MiB decompression limit.
- Unwraps UTF-16LE text (for example PowerShell `-EncodedCommand`) and
  heuristic single-byte and repeating-key XOR layers inside Base64/Hex
  payloads; XOR keys are reported and never treated as certain.
- Rewrites common script obfuscation without executing it: character-code
  arrays, `\xNN` escapes, string concatenation, PowerShell format strings and
  reversed literals.
- Flags JWTs, IPv4 addresses, domains, URLs, and common hash lengths.
- Measures Shannon entropy and gives an explainable triage score.
- Inspects JWT headers and payloads without claiming signature verification.
- Extracts and normalizes defanged URLs, domains, IPv4/IPv6, hashes, emails, and MAC addresses.
- Records bounded source locations and optional surrounding-line context for text IOCs.
- Detects common cloud access-key, GitHub/Slack-style token, bearer-token,
  credential-assignment, database-URI password, and private-key candidates.
- Calculates and identifies MD5, NTLM, and SHA-family hashes; supports offline wordlists.
- Converts Unix timestamps (s/ms/us/ns) and RFC3339 date-times.
- Tests regular expressions and provides common security patterns.
- Inspects local PEM/DER X.509 certificates, fingerprints, key sizes, constraints, KU/EKU, and SANs.
- Parses PEM certificate chains and checks leaf-to-root names, signatures, CA authorization, and validity offline.
- Performs bounded bulk analysis of tokens, nested encodings, entropy, and IOCs.
- Reads raw binary files for analysis, hashing, and Base64/Base64URL/Hex encoding.
- Verifies HS, RS, PS, ES, and EdDSA JWT signatures with explicit algorithms.
- Encodes and decodes Base64, Base64URL, Base32, Ascii85, Hex, Binary, Octal, ROT13, Punycode/IDNA, URL, HTML, and Unicode escapes.
- Applies auditable, bounded transformation recipes including gzip and zlib layers.
- Lists ZIP/TAR contents without extraction, inspects gzip/XZ/BZip2 payloads, and flags unsafe archive paths.
- Inspects Office (OOXML and legacy OLE), PDF and Windows shortcut (LNK) files
  for macros, remote templates, DDE fields, embedded objects, PDF actions and
  JavaScript, and hidden or script-launching shortcut arguments. Nothing is
  rendered, executed or extracted, and macro source code is not decompressed.
- Parses PE imports, named exports, section permissions, overlay data, and
  certificate-table presence metadata without verifying Authenticode trust.
- Computes pefile-compatible PE import hashes, decodes and validates Rich
  headers, counts TLS callbacks and reports per-section entropy.
- Parses ELF interpreters, dynamic dependencies, RPATH/RUNPATH, section
  permissions, and stripped/debug indicators.
- Validates and scans with bounded local TOML rules using regex, literal, or
  wildcard-hex patterns, optional metadata, file/entropy predicates, and
  compound conditions.
- Follows appended log lines and analyzes fresh IOCs and encoded values without network access.
- Produces unified single-file reports with MD5, SHA-1, SHA-256, file metadata,
  entropy, content analysis, IOCs, and optional local rule matches.
- Performs bounded directory scans with optional `*`, `**`, and `?` glob
  filters, per-file/combined byte limits, JSONL output, and partial-failure
  reporting.
- Accepts a positional value, a file, or stdin.
- Supports human-readable, JSON, JSONL, and CSV output for extraction, bulk analysis, and log watching.

## Build

### Requirements

- The native CI matrix covers **Windows x86_64, Linux x86_64/ARM64 and macOS
  Intel/Apple Silicon**. The CI badge links to actual run results; source support
  does not imply every platform is already available on the Releases page.
- **Rust 1.88 or newer**. The repository selects the latest stable toolchain
  through `rust-toolchain.toml`; the minimum version is declared, not separately
  tested in the CI matrix.
- Linux: C build tools, `pkg-config`, and liblzma development headers (on Ubuntu:
  `sudo apt-get install build-essential pkg-config liblzma-dev`). Windows: Visual
  Studio C++ build tools and a Windows SDK with the Rust MSVC toolchain.
- macOS: Xcode command line tools and Homebrew `xz`; native installer scripts
  also need Python 3. See the [installation guide](docs/INSTALLATION.md).

> [!NOTE]
> Banshee has not been published to crates.io during the alpha phase, so
> `cargo install banshee` is not available yet. Build from a clone instead.

```bash
git clone https://github.com/dRafaleD/Banshee.git
cd Banshee
cargo build --release --locked
```

The binary will be available at `target/release/banshee` on Linux or
`target\release\banshee.exe` on Windows. In PowerShell:

```powershell
.\target\release\banshee.exe --help
.\target\release\banshee.exe decode base64 aGVsbG8=
```

Versioned binary archives are built by the release workflow. Check the assets on
the [Releases page](https://github.com/dRafaleD/Banshee/releases) before expecting
a download; the original `v0.1.0` tag predates the packaging pipeline.
See [release and checksum instructions](docs/RELEASING.md).

On Linux, install it for the current user with:

```bash
sh scripts/install.sh
```

Use `--prefix /chosen/path` or set `PREFIX` to choose another installation root.
Existing installations require explicit `--force`. Windows users can run
`pwsh -File scripts/install.ps1`; both installers offer help and a custom prefix.
See [safe installation and troubleshooting](docs/INSTALLATION.md).

## Examples

These are a few common workflows. For the complete command catalog, see
[examples/usage.md](examples/usage.md); local rule examples live in
[examples/rules.toml](examples/rules.toml).

```bash
# Detect and recursively decode an unknown value.
banshee whatis "aGVsbG8lMjB3b3JsZA=="

# Extract and defang indicators from stdin.
cat suspicious.log | banshee extract --url --domain --defang

# Show bounded context while masking possible credentials by default.
banshee extract --secret --context 2 --file application.log

# Inspect a local file or archive without extracting it.
banshee file inspect suspicious.zip

# Inspect a JWT or certificate locally.
banshee jwt inspect "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
banshee cert inspect certificate.pem

# Produce machine-readable output for a pipeline.
banshee analyze --format json --file suspicious.bin

# Save a unified report; add --rules to include local rule matches.
banshee report suspicious.bin --format json --output report.json
banshee report suspicious.bin --rules examples/rules.toml --format markdown --output report.md

# Scan direct children, or opt into recursive traversal.
banshee scan ./samples
banshee scan ./samples --recursive --include '*.exe' --exclude 'known-safe/**'
banshee scan ./samples --recursive --rules examples/rules.toml --format jsonl
```

### Help and CLI discovery

```bash
banshee --help
banshee extract --help
banshee help rules
```

Generate completions for your shell and a manual page:

```bash
banshee completions bash > banshee.bash
source ./banshee.bash
banshee manpage > banshee.1
man ./banshee.1
```

PowerShell session completion:

```powershell
banshee completions powershell | Out-String | Invoke-Expression
```

The completion code above is generated by your local Banshee binary. Bash, Zsh,
Fish, PowerShell and Elvish are supported.

### Exit codes and troubleshooting

| Status | Meaning | Action |
| --- | --- | --- |
| `0` | Completed successfully | Consume the requested output |
| `1` | Findings with `--fail-on-findings`, diff changes, or failed evidence integrity | Review the results |
| `2` | Invalid input, operational error, or partial scan failure | Read stderr and per-file scan statuses |

Use `--file PATH` for sensitive input instead of placing it in shell history.
An existing `--output` path is refused by default; choose a new path or explicitly
use `--force` where supported. Evidence force replacement requires a valid bundle.
For CI failures, open the badge's run log; local success alone does not prove that
the other platform passed.

## Testing

The next development cycle is tracked in [the quality plan](docs/QUALITY_PLAN.md).
Parser resilience checks include ordinary tests for synthetic truncated
and mutated PE/ELF/archive inputs and expansion limits. For bounded sanitizer fuzz
campaigns and failure reproduction, see [fuzz/README.md](fuzz/README.md).

Run the same checks used by CI before opening a pull request:

```bash
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

## Design principles

- Offline by default: analyzed values are never sent to a remote service.
- Pipe friendly: stdin and stable JSON output are first-class interfaces.
- Modular: detection, decoding, findings, input, and output are separate layers.
- Bounded: recursive decoding has configurable depth and fixed input-size limits.
- Recipes are local, limited to 32 steps and 64 MiB output; decompression is limited to 16 MiB.
- `file inspect` never extracts entries. Input is limited to 256 MiB, decompressed inspection payloads to 64 MiB, and archive listing is bounded by `--max-entries`.
- Executable inspection is bounded to 256 sections, 256 PE import libraries,
  4,096 imported symbols or named exports, and 1,024 bytes per parsed string.
  Parser warnings remain separate from suspicious-property findings.
- Rule files are limited to 1 MiB and 1,000 rules; scan input is limited to 64
  MiB, compiled regex memory is bounded, and match reporting is capped per
  rule. Each `all`/`any` group is limited to 16 conditions and a rule file may
  compile at most 4,096 matchers.
- `watch` processes completed appended lines; use `Ctrl+C` to stop continuous monitoring.
- `--fail-on-findings` gives scripts a status of `1` for discovered IOCs/analysis findings; operational errors return `2` and ordinary successful runs return `0`.
- Human output colors are automatic on an interactive terminal; use `--color always`, `--color never`, or `--no-color` to control them. Structured formats never include ANSI codes.
- `--output PATH` redirects all command output without shell syntax and refuses to replace an existing file unless `--force` is provided. Processing failures do not create a pending output file.
- `report` analyzes one regular file at a time, uses the existing 256 MiB file
  limit, bounds archive entries and content tokens, and never embeds or
  extracts the source sample. Its schema is versioned for future comparison.
- `scan` does not recurse unless `--recursive` is present and never follows
  symbolic links. It defaults to 10,000 considered regular files, 64 MiB per
  file, and 1 GiB total analyzed bytes; all limits can be lowered explicitly.
  Skipped, unreadable, unsupported, and failed entries remain distinct.
- A scan that preserves partial results but encounters unreadable or failed
  files returns status `2`. A complete scan uses the ordinary success or
  `--fail-on-findings` status behavior.
- `evidence create` writes fixed, sorted evidence filenames into a sibling
  staging directory and publishes the target only after `manifest.json` is
  complete. Existing targets are refused unless `--force` is supplied, and
  force replacement is restricted to bundles whose manifests and contents verify.
- Evidence manifests cover every generated evidence file except the manifest
  itself, avoiding a recursive self-hash. Verification accepts at most 32
  listed files and 512 MiB of combined evidence, rejects unsafe paths,
  symlinks, missing/unlisted files, size changes, and SHA-256 mismatches.
  A failed integrity check returns status `1`; malformed or unreadable bundles
  return operational status `2`.
- `diff` accepts report JSON files or evidence directories whose manifests pass
  verification. It compares compatible schema versions with deterministic
  ordering and limits each input report to 64 MiB. Missing sections remain
  distinct from present-but-empty sections, and original samples are never
  opened or re-analyzed. A detected difference returns status `1`.
- `--quiet` suppresses normal output while preserving errors and exit statuses. `--verbose` writes timing and output-target diagnostics to stderr without echoing analyzed values, tokens, or secrets.
- IOC lists are local text files: blank lines and `#` comments are ignored, comparisons are case-insensitive, and `*` is supported as a wildcard. An allowlist suppresses known-safe values; a denylist limits output to matching values.
- IOC records include a source label and, for UTF-8 text, original line and
  column positions. `--context 1` through `--context 5` adds bounded surrounding
  lines; `--max-context-chars`, `--max-locations`, and `--max-matches` provide
  explicit collection limits.
- Secret and private-key candidates are masked in human, JSON, JSONL, CSV,
  batch, report, scan, compressed-preview, and local-rule sample output.
  `extract --reveal-secrets` is an explicit unsafe opt-in intended only for
  controlled local review. Verbose diagnostics never print analyzed values.
- Binary and extracted-string analysis reports source positions as unavailable
  instead of presenting extracted-string line numbers as original file offsets.

## Local rule format

Rules use schema version 1 TOML and remain entirely offline. Existing v1 files
need no migration. `kind` may be `regex`, `literal`, or `hex`; hex patterns
accept `??` as a one-byte wildcard. `severity` may be `info`, `low`, `medium`,
`high`, or `critical`.

```toml
version = 1

[[rules]]
id = "powershell-encoded-command"
description = "PowerShell invocation using an encoded command"
severity = "high"
kind = "regex"
pattern = '(?i)powershell(?:\.exe)?\s+[^\r\n]{0,120}-enc\b'
tags = ["powershell", "execution"]
category = "execution"
confidence = "medium"
references = ["internal-playbook-7"]
attack = ["T1059.001", "T1027"]
max_matches = 100

[[rules]]
id = "mz-marker"
kind = "hex"
pattern = "4D 5A ?? ??"
```

Use `min_matches = 2` to require repeated primary-pattern occurrences and
`max_matches` to lower the per-rule reporting cap. `case_insensitive = true`
is available for regex and literal matchers. Optional `file_types` values are
`text`, `binary`, `elf`, `pe`, `zip`, `tar`, `gzip`, `xz`, and `bzip2`; they are
detected from content signatures rather than filename extensions.

`min_entropy` and `max_entropy` use Shannon bits per byte from `0.0` through
`8.0`. Every `[[rules.all]]` condition must occur, while at least one
`[[rules.any]]` condition must occur when that group is present. These are
bounded whole-input predicates; the primary `pattern` supplies reported
offsets and match counts.

```toml
[[rules]]
id = "pe-command-markers"
kind = "hex"
pattern = "4D 5A"
file_types = ["pe"]
min_entropy = 1.0
max_matches = 1

[[rules.all]]
kind = "literal"
pattern = "This program cannot be run in DOS mode"

[[rules.any]]
kind = "literal"
pattern = "powershell"
case_insensitive = true

[[rules.any]]
kind = "literal"
pattern = "cmd.exe"
case_insensitive = true
```

`category`, `confidence` (`low`, `medium`, or `high`), `references`, and
`attack` are reporting metadata only. `attack` accepts up to 16 unique MITRE
ATT&CK tactic (`TA0002`), technique (`T1059`) or sub-technique (`T1059.001`)
identifiers; reports list them with the matching rule and HTML reports
summarize them as rule-declared coverage. References are never opened or fetched. Unknown TOML
fields, duplicate IDs, invalid ranges, oversized condition groups, invalid
patterns, and unsupported schema versions are rejected with actionable errors
by `rules validate` and `rules scan`.

## Security & responsible use

- `jwt inspect` never claims signature verification.
- `jwt verify` requires an explicit expected algorithm to reduce algorithm-confusion risk.
- JWT `exp` and `nbf` claims are validated by default; `--ignore-time` is an explicit escape hatch.
- Prefer a key file where possible; command-line secrets may appear in process listings.
- Hash wordlist matching is local and never queries an online reverse-hash service.
- `cert chain` validates only the supplied chain; it does not establish trust against an OS trust store or query OCSP/CRL services.
- Archive inspection reports metadata and suspicious paths but deliberately does not extract files or execute payloads.
- Executable inspection never loads or runs a sample. A PE certificate-table
  entry reports only structural presence; it does not establish signature
  validity, signer identity, trust, or revocation status. Writable-executable
  sections, packer-associated names, and overlays are explainable triage
  properties, not malware verdicts.
- Local rule matches are triage signals, not proof that a payload is malicious; review offsets and context before acting.
- Rule confidence, references and ATT&CK identifiers are author-supplied
  metadata, not validation of a claim or observed behavior. Banshee never
  fetches rule references.
- Evidence bundles omit the source sample by default. `--include-sample` is an
  explicit opt-in that copies it as `source-sample.bin`; protect and share such
  bundles according to the sensitivity of the original data.
- Diff output reflects only the saved reports. It does not prove that either
  report is complete, current, or a malware verdict.
- Secret matches are heuristic candidates, not confirmation that a credential
  is valid. Keep redaction enabled when saving or sharing results.

### Authorized use and liability

Banshee is intended for defensive research, education, incident response, and
analysis of systems or data you own or are explicitly authorized to assess. Do
not use it to access, probe, disrupt, or analyze third-party systems or data
without permission.

You are solely responsible for how you use this software and for complying with
applicable laws, regulations, and organizational policies. The software is
provided "as is", without warranty of any kind. Its authors and contributors
accept no liability for misuse or for any loss, damage, or legal consequence
arising from its use, to the fullest extent permitted by law.

## Project development

Read the [contribution guide](CONTRIBUTING.md), [changelog](CHANGELOG.md) and
[roadmap](ROADMAP.md). Report reproducible bugs with synthetic inputs using the
issue forms. For vulnerabilities, follow the [security policy](SECURITY.md).

CI checks formatting, tests, Clippy and release builds on the five native targets,
then smoke-tests packaged binaries and isolated source installation. Trusted
candidate/release runs verify archive provenance and dependency inventories.
Scheduled audits cover both lockfiles; parser fuzzing retains failures for review.
A passing check is not a guarantee of security. See [check handling](docs/SECURITY_CHECKS.md).

## License

Distributed under the [MIT License](LICENSE). See [LICENSE](LICENSE) for the
full text.
