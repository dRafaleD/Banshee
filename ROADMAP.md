# Banshee Development Roadmap

This roadmap grows Banshee incrementally while preserving its offline,
pipe-friendly, bounded, and explainable design. Each phase should be completed
and validated before work begins on the next one.

## Delivery rules

Every phase must include:

- bounded input and output limits;
- human-readable and machine-readable output where appropriate;
- unit and CLI integration tests;
- README and `examples/usage.md` updates;
- `cargo fmt --all -- --check`;
- `cargo test --all-targets --locked`;
- `cargo clippy --all-targets --locked -- -D warnings`;
- no runtime network requests and no automatic security verdicts.

## Phase 1 — Unified report command (completed)

Add a `banshee report` command that combines existing analysis modules into a
single reproducible report for one local file.

Initial scope:

- file identity, size, and cryptographic hashes;
- file/archive/executable metadata from `file inspect`;
- entropy and explainable findings;
- extracted and normalized IOCs;
- optional local TOML rule matches;
- human and JSON output;
- Markdown export through `--format markdown`;
- atomic output behavior through the existing global output mechanism.

Acceptance criteria:

- the report reuses existing modules instead of duplicating detectors;
- unavailable sections are represented explicitly, not treated as clean;
- findings retain their source and severity;
- the command obeys current file-size and analysis limits;
- operational errors return exit status 2 and `--fail-on-findings` returns 1
  only when findings exist.

Deferred from this phase: HTML output, directory traversal, embedded raw file
content, and archive extraction.

Delivered in v0.1 development:

- `banshee report PATH` with text, JSON, and Markdown output;
- MD5, SHA-1, and SHA-256 plus file/archive/executable metadata;
- entropy, bounded content analysis, normalized IOCs, and optional TOML rules;
- versioned schema, source-labelled findings, and existing exit-status behavior.

## Phase 2 — Recursive directory scan (completed)

Add bounded multi-file scanning on top of the report model.

Initial scope:

- explicit `--recursive` traversal;
- maximum file count, individual file size, and total-byte limits;
- deterministic path ordering;
- optional include/exclude glob filters;
- per-file results plus a final summary;
- JSONL output for streaming pipelines;
- clear unreadable, skipped, unsupported, and failed states.

Acceptance criteria:

- symbolic links are not followed by default;
- archives are inspected but never extracted;
- one unreadable file does not silently invalidate the full scan;
- partial results and errors remain distinguishable.

Delivered in v0.1 development:

- `banshee scan PATH` for one file or a directory, with explicit recursion;
- deterministic relative-path ordering and `*`, `**`, `?` include/exclude filters;
- regular-file count, per-file byte, total-byte, traversal, archive-entry,
  token, and decode-depth limits;
- text, JSON, and record-oriented JSONL output;
- analyzed, skipped, unreadable, unsupported, and failed result states;
- partial results with exit status 2 for unreadable or failed entries.

## Phase 3 — IOC context and secret detection (completed)

Improve analyst usefulness while preventing accidental secret disclosure.

Initial scope:

- line, column, and optional surrounding-line context for text inputs;
- source labels for each IOC;
- bounded context length and match count;
- detection of common credential and private-key markers;
- masked human output and redacted structured output by default;
- an explicit opt-in flag for revealing full matched values.

Acceptance criteria:

- secrets never appear in verbose diagnostics;
- masking is tested for short and long values;
- binary input does not produce misleading line positions;
- existing IOC normalization and allow/deny lists remain compatible.

Delivered in v0.1 development:

- per-IOC source labels and original text line/column locations;
- optional 0-5 line context with character, location, and global match limits;
- offset mapping that preserves original positions for defanged indicators;
- heuristic secret and private-key marker detection with default masking;
- explicit `extract --reveal-secrets` opt-in for controlled local use;
- redaction across structured output, batch/report/scan data, compressed
  previews, context lines, private-key blocks, and local-rule samples;
- unavailable rather than synthetic positions for binary extracted strings;
- backward-compatible text and CSV field ordering for existing consumers.

## Phase 4 — Deeper PE and ELF inspection (completed)

Extend local executable metadata without executing files.

Initial scope:

- PE imports, exports, section permissions, overlay presence, and signature
  presence metadata;
- ELF interpreter, dynamic dependencies, RPATH/RUNPATH, section permissions,
  and stripped/debug indicators;
- bounded entry counts and string lengths;
- explainable suspicious properties without declaring malware.

Acceptance criteria:

- malformed binaries fail safely;
- truncated output is marked explicitly;
- parser errors remain separate from suspicious findings;
- fixture coverage includes benign, malformed, and edge-case binaries.

Delivered in v0.1 development:

- bounded PE section permissions, import libraries/symbols, named exports,
  overlay ranges, and certificate-table presence metadata;
- bounded ELF program/section metadata, interpreter, `DT_NEEDED`, RPATH,
  RUNPATH, and stripped/debug indicators;
- explainable writable-executable, packer-name, and non-certificate overlay
  findings without automatic malware classification;
- explicit truncation markers and parser warnings kept separate from
  suspicious findings;
- benign, malformed, edge-case, and CLI fixture coverage without loading or
  executing inspected files.

## Phase 5 — Rule metadata and compound conditions (completed)

Evolve the local TOML rule format while retaining validation and hard limits.

Initial scope:

- optional `category`, `confidence`, and `references` metadata;
- per-rule `max_matches`;
- optional file-type and entropy predicates;
- bounded `all` and `any` condition groups;
- rule schema versioning and actionable validation errors.

Acceptance criteria:

- version 1 rule files remain supported or receive a deterministic migration
  error with documentation;
- references are metadata only and never fetched;
- rule matches remain triage signals rather than verdicts;
- regex and aggregate match limits remain enforced.

Delivered in v0.1 development:

- backward-compatible schema version 1 rules with optional `category`,
  `confidence`, and bounded `references` metadata;
- configurable per-rule `max_matches` while retaining the global ceiling;
- content-signature file-type and bounded Shannon-entropy predicates;
- bounded `all` and `any` content-condition groups with explicit match
  summaries;
- metadata-only references that are never fetched and rule matches that remain
  explainable triage signals;
- validation and CLI coverage for legacy rules, compound matches, predicate
  gating, truncation, and invalid ranges.

## Phase 6 — Evidence bundle (completed)

Create a deterministic directory or archive containing analysis evidence.

Initial scope:

- report JSON and Markdown;
- hashes, normalized IOC list, and rule matches;
- Banshee version, command options, and UTC analysis timestamp;
- manifest containing hashes of generated evidence files;
- no source sample inclusion unless explicitly requested.

Acceptance criteria:

- existing output is never overwritten without `--force`;
- interrupted generation does not leave a bundle presented as complete;
- secret redaction follows Phase 3 defaults;
- manifest verification is available offline.

Delivered in v0.1 development:

- `banshee evidence create SAMPLE --output BUNDLE_DIR` with report JSON and
  Markdown, hashes, normalized IOCs, rule results, version/options, and UTC
  metadata;
- a sorted SHA-256/size manifest covering generated evidence files;
- sibling staging plus publish-on-completion behavior so partial work is not
  presented as a finished bundle;
- default source-sample exclusion and explicit `--include-sample` opt-in;
- guarded `--force` replacement limited to manifest-marked evidence bundles;
- `banshee evidence verify BUNDLE_DIR` with bounded, offline path, type, size,
  unlisted-file, and SHA-256 integrity checks.

## Phase 7 — Analysis diff (completed)

Compare two Banshee reports or evidence bundles.

Initial scope:

- added, removed, and changed IOCs;
- changed hashes and file metadata;
- new and resolved findings or rule matches;
- entropy and archive-entry changes;
- human and JSON output.

Acceptance criteria:

- comparisons require compatible schema versions;
- ordering is deterministic;
- missing data is distinct from an empty result;
- the diff never re-analyzes or executes the original sample.

Delivered in v0.1 development:

- `banshee diff LEFT RIGHT` for report JSON files and manifest-verified evidence
  bundle directories;
- deterministic added, removed, and changed IOC, finding, rule-match, and
  archive-entry sets;
- explicit hash/file metadata changes and entropy deltas;
- strict compatible report-schema enforcement and bounded 64 MiB report
  loading;
- missing-data states kept distinct from available empty collections;
- text and JSON output with status `1` for differences and no access to the
  original analyzed samples.

## Later candidates

The next agreed sequence is tracked in [docs/QUALITY_PLAN.md](docs/QUALITY_PLAN.md):
parser resilience, release provenance, platform coverage, report compatibility,
daily CLI use, and ongoing security. Each phase has explicit verification;
independent implementation work may run in parallel.

These remain outside the committed sequence until the core phases are stable:

- export compatible Banshee rules to a limited YARA subset;
- `banshee doctor` for local installation diagnostics;
- optional HTML report rendering;
- expanded shell integration (PowerShell completion is already available).
