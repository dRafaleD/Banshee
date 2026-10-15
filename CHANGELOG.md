# Changelog

Changes are grouped by release. Pre-1.0 interfaces can change; format/schema
changes must be called out explicitly. Tags are immutable.

## Unreleased

## 0.3.0 — 2026-10-16

### Added

- Java archive (JAR) and Android package (APK) inspection in `file inspect`,
  `report` and `scan`: manifest fields, signing, Class-Path to remote
  locations, embedded Windows executables, runtime class loading combined with
  decoding, process creation combined with networking, APK permissions (SMS,
  accessibility, overlay, device admin, package install), native ABIs and
  `DexClassLoader` references. Bytecode is not decompiled.
- `--format sarif` for `report` and `scan` writes a SARIF 2.1.0 log. Each
  finding keeps its source (rule ID `banshee/<source>/<kind>`), severity
  (`note`, `warning`, `error`) and the file hash; absolute paths are written
  as `file://` URIs.
- `banshee strings` lists printable ASCII and UTF-16LE strings with their
  offsets (`--min-length`, `--encoding`, `--plain`, `--json`); `--max-strings`
  bounds the list while the total is still counted.
- ELF inspection flags executable stacks, non-PIE dynamic executables, entry
  points outside executable segments, non-standard interpreters, RPATH,
  RUNPATH and needed libraries in temporary or relative paths, UPX markers
  and files without section headers. `$ORIGIN` search paths are not reported.
- Mach-O inspection in `file inspect`, `report`, `scan` and evidence bundles:
  CPU, file type, segments with protections and entropy, linked dylibs,
  `LC_RPATH`, dynamic linker, entry point and code-signature presence.
  Universal binaries list their architectures and describe the first slice.
  Writable and executable segments, stack execution, non-PIE executables,
  encrypted images and libraries loaded from writable or relative paths are
  flagged. Report JSON gains an optional `universal_architectures` field.
- RTF inspection: object classes from `\objclass` and the OLE1 header in
  `\objdata`, Equation Editor, Package, OLE2Link and script objects,
  automatically updating objects, remote templates, DDE fields and
  `INCLUDEPICTURE`/`INCLUDETEXT` fields that fetch remote or UNC content.
- .NET metadata for managed PE files: runtime version, CLI flags, assembly
  identity, referenced assemblies, P/Invoke imports and notable framework
  references (reflection loading, Base64, decryption, process and network
  calls). Obfuscator markers, P/Invoked process-injection APIs and
  `Assembly.Load(byte[])` combined with decoding are flagged. Identity and
  references matched .NET reflection on 230 framework assemblies.
- Authenticode details for signed PE files: signer and issuer, validity,
  digest algorithm, timestamp presence, embedded certificates and the signers
  of nested signatures. Nothing is verified. Matched Get-AuthenticodeSignature
  on 150 embedded-signed files. The text report now also prints imphash, Rich
  header, TLS, .NET and Authenticode lines, and HTML reports show the latter two.
- Script inspection for PowerShell, VBScript, JScript, HTA and batch files:
  encoded commands, download-and-execute cradles, AMSI and Defender tampering,
  in-memory loading, LOLBin abuse, shadow-copy deletion and persistence, each
  quoting its line. Constructs common in admin scripts are only reported next
  to a high-signal behavior (3 of 400 bundled Windows scripts are flagged).
- Email (`.eml`) inspection: headers, Received chain, SPF/DKIM/DMARC results,
  attachments with SHA-256 and links; spoofed sender domains, risky or
  double-extension attachments and links whose text shows another domain are
  flagged.
- ISO 9660 images (with Joliet names) and cabinets are listed like archives,
  flagging executables, shortcuts, scripts and hidden files; 7-Zip, RAR, VHD,
  VHDX and WIM files are identified.
- `banshee hexdump` shows a `hexdump -C` style window (`--offset`, `--length`,
  `--width`); `strings` tags URLs, IPs, domains, emails, paths, registry keys,
  commands, user agents and Base64 in JSON, and `--interesting` keeps only
  those.
- Console `history`, `!N`, `save <file>` and `run <file>` record, repeat,
  save and replay a session's commands.
- Local rules: `encoding = "wide" | "both"` matches literal and regex
  patterns as UTF-16LE text, `min_size`/`max_size` bound the input size, and
  `within = N` on an `all` condition requires it to follow one primary match
  within N bytes. YARA import maps `ascii`/`wide` modifiers, `filesize`
  comparisons and `for any i in (1..#a) : ($b in (@a[i]..@a[i]+N))` proximity
  loops to them, and export writes them back. All 60 AsphDex YARA library
  rules now convert and match its fixtures as YARA does.

### Fixed

- YARA import no longer misreads rule boundaries when a regex string contains
  `{` or `}`.

### Changed

- Executable signature, linker and dependency labels follow the format (for
  example "Code signature present" for Mach-O instead of the PE wording).

## 0.2.0 — 2026-10-14

### Added

- Interactive console: `banshee` on a terminal (or `banshee shell`) opens a `banshee>` prompt that runs commands without the `banshee` prefix, with a categorized `help` menu (`help <category>`, `help <command>`), `pwd`/`cd`/`ls`, `clear` and `exit`. Tab completion and line history use the optional `line-editor` feature (on by default, off for the browser build). `banshee --help` lists commands in the same categories.
- Console sessions: `open <file>` keeps a file open (shown in the prompt), `@` stands for it in any command, lone `report`/`file`/`cert`/`scan`/`entropy`/`whatis`/`analyze`/`extract` use it, and `status` and `close` inspect or clear the session.
- `--lang tr|en` global option (and `BANSHEE_LANG=tr`): Turkish help menu, options and quick start, and Turkish labels for `whatis`, `entropy`, `jwt inspect`, `hash identify` and `timestamp`. JSON, JSONL, CSV, Markdown, HTML, STIX, MISP, rule and finding texts stay English.
- Turkish console: `tr` / `lang tr` switches the console menu, command descriptions and built-in messages to Turkish and `en` switches back; `BANSHEE_LANG=tr` starts in Turkish.
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
- Script deobfuscation layers: character codes (`String.fromCharCode`,
  `[char]` runs and arrays, VBScript `Chr`/`ChrW`, including nearby `-bxor`/`^`
  keys), `\xNN` escapes, string concatenation, PowerShell `-f` format strings
  and reversed literals. Only the construct is rewritten; nothing is executed.
  Lines containing such constructs are also analyzed as a whole in reports,
  scans and bulk analysis.
- Repeating-key XOR (2-16 byte keys) inside Base64/Hex payloads up to 16 KiB,
  reported with the recovered key after single-byte keys are ruled out.
- Document and shortcut inspection in `file inspect`, `report`, `scan` and
  evidence bundles, reported in an optional `file.document` section:
  - OOXML: VBA projects, embedded OLE objects, ActiveX controls, external
    relationships (remote templates, OLE links, frames) and DDE fields;
  - OLE compound files: document type, VBA storages, `Ole10Native` packages and
    encrypted packages from a bounded FAT/directory walk with a name-scan
    fallback;
  - PDF: JavaScript, automatic and launch actions, embedded files, `#xx`
    name obfuscation and `/URI` targets;
  - Windows shortcuts: target, arguments, working directory and icon, with
    script-host launches, whitespace-padded or overlong arguments, minimized
    windows and document-like icons flagged.
  Targets and shortcut strings also feed content analysis and IOC extraction.
- PE triage metadata: pefile-compatible `imphash` (including its Winsock and
  OLE Automation ordinal names), decoded Rich header entries with checksum
  validation, TLS callback counts, and per-section Shannon entropy (also for
  ELF). High-entropy executable sections, entry points outside executable
  sections, TLS callbacks and Rich checksum mismatches are flagged. Verified
  against pefile on 300 local Windows system binaries with identical imphash
  and TLS results.
- `rules export-yara` and `rules import-yara` convert between Banshee TOML and
  a documented YARA subset. Export maps literal/hex/regex strings, match
  counts, `all`/`any` groups, file-type magic and entropy (`math`), and writes
  explicit warnings for predicates YARA cannot express. Import accepts text,
  plain hex and regex strings with `nocase`, string counts, `and`/`or`,
  `any/all of them` and string sets, magic checks and entropy bounds; other
  constructs are skipped with a per-rule reason, and the generated TOML is
  validated before output. Example rules round-trip with identical matches.
- `scan --jobs N` analyzes files concurrently (default: available cores, at
  most 4) without new dependencies. Results are written in path order, so
  reports are byte-identical for any job count; 150 system DLLs scanned about
  twice as fast with the default.
- `banshee doctor` checks the installation offline: gzip/zlib, bzip2 and
  liblzma round trips, decoder and rule-engine self-tests, the embedded TLD
  snapshot version, a writable temporary directory and whether PATH resolves
  to the running binary. Failed checks exit with status 2.
- Distribution preparation: crates.io metadata with an explicit file list,
  cargo-binstall metadata for release archives, and Scoop, Homebrew and winget
  templates filled from verified checksums by `scripts/render-packaging.ps1`.
  Nothing is published automatically.
- ssdeep fuzzy hashing in safe Rust without new dependencies: reports include
  `hashes.ssdeep`, `diff` shows a 0-100 `ssdeep_similarity` and imphash
  changes, and `hash ssdeep` / `hash compare-ssdeep` work on any input.
  Digests matched an independent implementation on 426 of 427 inputs (400
  system binaries, text files and block-size boundaries); the remaining case
  is a one-byte input where that implementation drops a character ssdeep's
  C source emits.
- Browser build: `scripts/build-web.ps1` produces `dist/web/banshee.html`, a
  single file with an embedded WebAssembly module that analyzes files and
  decodes values inside the tab. The module imports no host functions and the
  page's Content-Security-Policy blocks all network requests; reports render
  in a script-less sandboxed frame. CI builds it and checks the import count.
- Cargo features `xz` and `crypto-verify` (both on by default) gate liblzma and
  ring. Without them XZ payloads are identified but not decompressed, JWT
  verification reports that it is unavailable, and certificate chain
  signatures report `unsupported`; `doctor` lists which are built in.
- `report::generate_from_bytes` builds reports from memory with file or
  inline rule sources.
- Running `banshee` without arguments shows a neofetch-style start screen
  (green-on-black emblem, build summary and quick-start commands) instead of a
  usage error. Plain text is used for pipes and when `NO_COLOR` is set.
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
- `scan` reserves the `--max-total-size` budget by each file's declared size in
  path order, before analysis starts. A file that later fails to read still
  counts against the budget, which keeps skip decisions independent of
  concurrency.

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
- YARA import no longer panics on conditions containing multi-byte text
  (found by the new `yara_import` fuzz target), and compiles its parsing
  expressions once instead of per rule.
- Domains are validated against an embedded IANA TLD snapshot plus reserved
  special-use names (`test`, `example`, `invalid`, `localhost`, `onion`, `alt`,
  `internal`) and common private suffixes (`local`, `lan`, `corp`), so code
  identifiers such as `System.Net.WebClient` and file names such as `gate.php`
  are no longer reported. Refresh the snapshot with `scripts/update-tlds.sh`.

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
