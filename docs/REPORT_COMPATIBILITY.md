# Saved report compatibility

Unified JSON reports use `schema_version: 1`. Analysis diffs independently use
`schema_version: 1` and record the input version in `report_schema_version`.
Evidence manifests and metadata have separate versions; their version is not a
substitute for the version inside `report.json`. Application package versions do
not determine report compatibility.

## Supported versions and validation

`report::validate_compatibility` dispatches by the saved report's wire version.
Currently only v1 is supported. The root must be an object and `schema_version`
must be a non-negative JSON integer representable as u8. Missing, null, string,
fractional, negative and out-of-range versions fail. Version 0 is not an implicit
legacy schema. Unknown versions fail even when both inputs use the same version.
Different input versions fail with `incompatible report schema versions` before
shape validation. CLI compatibility failures exit with code 2; a valid diff exits
0 when unchanged and 1 when changes exist.

Validation is a compatibility check for the comparison projection, not full
deserialization of every producer field, authenticity verification, or a check
that findings, counts, hashes and entropy agree with a source sample. It preserves
the established permissive v1 core instead of requiring every field emitted by
today's producer. Hex digest lengths and enum vocabularies are not restricted by
this reader; hash values and categorical fields must be strings.

Required v1 fields:

- Object sections: `file`, `hashes`, `entropy`, `content_analysis`, `rule_analysis`,
  `summary`; array section: `findings`.
- Strings: `file.path`, `file.format`, `hashes.md5`, `hashes.sha1`, `hashes.sha256`.
- Non-negative integer: `file.size`; number: `entropy.bits_per_byte`.
- Present collection items must be objects with string identity fields: IOC
  `kind` and `value`; finding `source`, `kind`, `value` and `detail`; rule match
  `id`; archive entry and executable section `name`.

Historical optional fields can be absent or null. When present, comparison
sections must have their expected object/array shape. Compared descriptive
attributes must be strings, sizes/counts must be non-negative integers, and flags
must be booleans. Rule `conditions` must be an object with non-negative integer
counts when supplied. Summary counters are optional non-negative integers.
Unknown additive fields are accepted by validation. Uncompared producer metadata
is not exhaustively validated. Malformed known comparison fields are rejected
rather than used as arbitrary JSON values or collection identities.

## Comparison semantics

Missing and null optional fields both mean unavailable. Zero and empty arrays
mean available. The reader does not synthesize defaults or rewrite saved reports.
A missing-versus-empty collection changes availability without inventing added
or removed items. Item deltas are calculated only when both collections are
available. Optional item attributes normalize absent/null to null in the diff.

Scalar comparison covers hashes, file format/size, executable format,
architecture, bitness, kind and entry point, archive totals, and entropy. Entropy
delta is right minus left. Collections compare IOCs, unified findings, local rule
matches, archive entries and executable section details. Keys and selected
attributes are listed in `src/diff.rs`; this remains a semantic projection rather
than a byte-for-byte JSON diff. Source paths, timestamps, IOC positions/context,
rule samples and additions outside the selected attributes do not independently
cause changes. The selected rule `conditions` object is compared as a whole,
including unknown attributes within that object; this preserves the existing
diff contract.

Collection ordering is irrelevant. Duplicate identities remain separate and are
sorted by their projected attributes; subsequent duplicates receive numbered
keys. This is deterministic multiset comparison, not inferred occurrence lineage.

## Sensitive data and evidence

The diff recursively applies existing sensitive-text redaction before comparison
and explicitly redacts values marked `secret` or `private_key`, including older
reports containing raw values. Two different raw secret values can therefore
compare equal after redaction. Diff output is not a way to recover those values.
Validation diagnostics identify fixed schema locations and item indices without
echoing rejected values or unknown object keys. Existing redaction remains
heuristic; arbitrary strings are not guaranteed to be detected as secrets.

Diffing saved reports requires no original sample and does not alter the input.
Evidence bundles must pass manifest/hash verification before their report enters
the same compatibility validator. Compatibility does not bypass verification.

## Evolution and migration policy

Keep v1 for optional additive fields whose absence retains its existing meaning.
Changing required fields, types, identity rules or meanings requires a new wire
version and a documented reader/migration decision. Do not replace versioned
validation with an equality check against the latest producer constant.

There is currently no cross-version migration. Future support must keep explicit
validation for each supported version, preserve unavailable-versus-empty state,
redact before any comparison output, and retain original evidence. A migration
must document its loss/default behavior and add saved input and expected-result
regressions before enabling comparison across versions. Unsupported versions
must continue to fail explicitly until that work exists.

## Regression fixtures and local checks

`tests/fixtures/reports/` contains hand-authored synthetic compatibility fixtures,
not captures from claimed historical releases or real analyzed samples:

- `v1-legacy-minimal.json`: original permissive core with optional data absent.
- `v1-legacy-executable.json`: executable summary without section details.
- `v1-archive-rules.json`: archive, IOC and rule data without newer rule metadata.

Zero/repeated-digit hashes are placeholders. `.example` domains and sample paths
are synthetic. Never replace these files with private reports or real secrets.
Tests also generate current text, binary and TAR reports and verified evidence
bundles, and inject synthetic sensitive markers into temporary saved reports.

Run `cargo test --test report_compatibility`, `cargo test --lib diff::tests`, and
`cargo test --test cli diff_compares_reports_and_verified_bundles_without_source_samples`.
These checks cover compatibility, error/exit contracts, deterministic comparison,
redaction, current producer acceptance and verified-bundle loading. They are
local regression evidence, not remote CI or release validation.
