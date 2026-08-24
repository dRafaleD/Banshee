![Banshee — offline security analysis toolkit](assets/banshee-banner-green-animated-v3.gif)

# Banshee

[![Status: Alpha](https://img.shields.io/badge/status-alpha-f59e0b)](https://github.com/dRafaleD/Banshee)
[![CI](https://github.com/dRafaleD/Banshee/actions/workflows/ci.yml/badge.svg)](https://github.com/dRafaleD/Banshee/actions/workflows/ci.yml)
[![Primary language: Rust](https://img.shields.io/badge/primary%20language-Rust-dea584)](https://github.com/dRafaleD/Banshee)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)

Banshee is an offline, pipe-friendly security analysis toolkit written in Rust.
It aims to bring common CyberChef-style transformations, JWT inspection, IOC
normalization, hashing, certificate inspection, timestamps, entropy analysis,
and regex utilities into one Linux terminal application.

> [!WARNING]
> **Alpha / early draft.** Banshee is under active development. Expect incomplete,
> broken, or incorrect behavior; commands, output formats, rule syntax, and
> limits may change before a stable release. Treat its findings as analyst
> assistance—not as a final security verdict.

## Quick guide

Build the release binary, then pass Banshee a value, a file, or standard input:

```bash
cargo build --release

# Identify and unpack suspicious encoded content.
target/release/banshee whatis "aGVsbG8lMjB3b3JsZA=="

# Extract IOCs from a local log without sending it anywhere.
cat suspicious.log | target/release/banshee extract --defang

# Inspect a local file, archive, certificate, or executable.
target/release/banshee file inspect suspicious.zip
target/release/banshee cert inspect certificate.pem

# Emit structured output for scripts and pipelines.
target/release/banshee analyze --format json --file suspicious.bin
```

### What it can help with

- Decode layered Base64, hexadecimal, URL/HTML encoding, compression, and recipes.
- Extract and normalize URLs, domains, IP addresses, hashes, emails, and other IOCs.
- Analyze entropy, common encodings, JWTs, hashes, timestamps, certificates, archives, ELF, and PE files.
- Run local TOML rules, inspect regex patterns, and watch fresh log lines.
- Work offline with pipe-friendly human, JSON, JSONL, and CSV output.

## Capabilities (alpha)

The initial foundation includes the following commands:

- Detects Base64, hexadecimal, URL encoding, and HTML entities.
- Recursively decodes nested layers with depth and size limits.
- Detects Base64/Hex-wrapped gzip and zlib layers with a 16 MiB decompression limit.
- Flags JWTs, IPv4 addresses, domains, URLs, and common hash lengths.
- Measures Shannon entropy and gives an explainable triage score.
- Inspects JWT headers and payloads without claiming signature verification.
- Extracts and normalizes defanged URLs, domains, IPv4/IPv6, hashes, emails, and MAC addresses.
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
- Parses basic ELF and PE architecture, bitness, entry-point, section, and subsystem metadata.
- Validates and scans with bounded local TOML rules using regex, literal, or wildcard-hex patterns.
- Follows appended log lines and analyzes fresh IOCs and encoded values without network access.
- Accepts a positional value, a file, or stdin.
- Supports human-readable, JSON, JSONL, and CSV output for extraction, bulk analysis, and log watching.

## Build

### Requirements

- **Linux** is the primary supported target; CI runs on `ubuntu-latest`.
- **Rust 1.88 or newer**. The repository selects the latest stable toolchain
  through `rust-toolchain.toml`.

> [!NOTE]
> Banshee has not been published to crates.io during the alpha phase, so
> `cargo install banshee` is not available yet. Build from a clone instead.

```bash
cargo build --release
```

The binary will be available at `target/release/banshee`.

On Linux, install it for the current user with:

```bash
sh scripts/install.sh
```

Use `--prefix /chosen/path` or set `PREFIX` to choose another installation root.

## Examples

These are a few common workflows. For the complete command catalog, see
[examples/usage.md](examples/usage.md); local rule examples live in
[examples/rules.toml](examples/rules.toml).

```bash
# Detect and recursively decode an unknown value.
banshee whatis "aGVsbG8lMjB3b3JsZA=="

# Extract and defang indicators from stdin.
cat suspicious.log | banshee extract --url --domain --defang

# Inspect a local file or archive without extracting it.
banshee file inspect suspicious.zip

# Inspect a JWT or certificate locally.
banshee jwt inspect "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
banshee cert inspect certificate.pem

# Produce machine-readable output for a pipeline.
banshee analyze --format json --file suspicious.bin
```

### Help and CLI discovery

```bash
banshee --help
banshee extract --help
banshee help rules
```

## Testing

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
- Rule files are limited to 1 MiB and 1,000 rules; scan input is limited to 64 MiB, compiled regex memory is bounded, and match reporting is capped per rule.
- `watch` processes completed appended lines; use `Ctrl+C` to stop continuous monitoring.
- `--fail-on-findings` gives scripts a status of `1` for discovered IOCs/analysis findings; operational errors return `2` and ordinary successful runs return `0`.
- Human output colors are automatic on an interactive terminal; use `--color always`, `--color never`, or `--no-color` to control them. Structured formats never include ANSI codes.
- `--output PATH` redirects all command output without shell syntax and refuses to replace an existing file unless `--force` is provided. Processing failures do not create a pending output file.
- `--quiet` suppresses normal output while preserving errors and exit statuses. `--verbose` writes timing and output-target diagnostics to stderr without echoing analyzed values, tokens, or secrets.
- IOC lists are local text files: blank lines and `#` comments are ignored, comparisons are case-insensitive, and `*` is supported as a wildcard. An allowlist suppresses known-safe values; a denylist limits output to matching values.

## Local rule format

Rules use TOML and remain entirely offline. `kind` may be `regex`, `literal`, or `hex`; hex patterns accept `??` as a one-byte wildcard. `severity` may be `info`, `low`, `medium`, `high`, or `critical`.

```toml
version = 1

[[rules]]
id = "powershell-encoded-command"
description = "PowerShell invocation using an encoded command"
severity = "high"
kind = "regex"
pattern = '(?i)powershell(?:\.exe)?\s+[^\r\n]{0,120}-enc\b'
tags = ["powershell", "execution"]

[[rules]]
id = "mz-marker"
kind = "hex"
pattern = "4D 5A ?? ??"
```

Use `min_matches = 2` to require repeated occurrences, or `case_insensitive = true` with regex and literal rules. Unknown TOML fields, duplicate IDs, invalid patterns, and unsupported schema versions are rejected by `rules validate` and `rules scan`.

## Security & responsible use

- `jwt inspect` never claims signature verification.
- `jwt verify` requires an explicit expected algorithm to reduce algorithm-confusion risk.
- JWT `exp` and `nbf` claims are validated by default; `--ignore-time` is an explicit escape hatch.
- Prefer a key file where possible; command-line secrets may appear in process listings.
- Hash wordlist matching is local and never queries an online reverse-hash service.
- `cert chain` validates only the supplied chain; it does not establish trust against an OS trust store or query OCSP/CRL services.
- Archive inspection reports metadata and suspicious paths but deliberately does not extract files or execute payloads.
- Local rule matches are triage signals, not proof that a payload is malicious; review offsets and context before acting.

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

## Language breakdown

GitHub currently reports the codebase as **Rust 99.7%** and **Shell 0.3%** by
source bytes. The repository's language indicator updates automatically as the
project evolves.

## License

Distributed under the [MIT License](LICENSE). See [LICENSE](LICENSE) for the
full text.
