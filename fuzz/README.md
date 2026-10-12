# Parser fuzzing

Each target feeds bounded arbitrary bytes into the same public API used by
Banshee, accepts errors for invalid input, and fails on panics, sanitizer reports
or broken invariants. Samples are never loaded or executed.

| Target | API | Invariants |
| --- | --- | --- |
| `file_inspect` | `file_inspect::inspect_bytes` | archive, decompression, section and symbol limits |
| `analyze` | `analysis::Analyzer` | decode depth limit |
| `ioc_extract` | `ioc::extract` | match/location/context limits; secrets redacted by default |
| `rules_scan` | `rules::validate_source`, `scan_source` | validated rules always scan; counts consistent |
| `cert_parse` | `cert::inspect_bytes`, `inspect_chain_bytes` | chain length and link count |
| `jwt_inspect` | `jwt::inspect` | object header/payload; never reports verification |
| `report_compat` | `report::validate_compatibility` | only schema version 1 is accepted |
| `recipe` | `recipe::run` | step limit; reported size matches output |
| `codec_roundtrip` | `codec::encode_bytes`, `decode` | binary-safe codecs round-trip exactly |

`rules_scan` splits its input at the first `0x00` byte (rule TOML, then content);
`recipe` splits at the first newline (recipe expression, then input bytes).

Seed generation for `file_inspect` verifies twelve synthetic PE/ELF/archive/
compressed/OOXML/OLE/PDF/LNK fixtures before writing them with exclusive creation. Small harmless
seeds for the other targets live in `fuzz/seeds/<target>/`; copy them into the
corpus directory before the first run.

## Run on Linux (or Ubuntu in WSL)

Install Rust nightly, cargo-fuzz, a C++ compiler and liblzma development headers.
Keep the main project on stable; select nightly only for the fuzz command.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo run --locked --example fuzz_seeds -- fuzz/corpus/file_inspect
cargo +nightly fuzz run file_inspect -- -max_total_time=60 -timeout=10 -max_len=1048576 -rss_limit_mb=1024

# Any other target, for example:
mkdir -p fuzz/corpus/analyze && cp fuzz/seeds/analyze/* fuzz/corpus/analyze/
cargo +nightly fuzz run analyze -- -max_total_time=60 -timeout=10 -rss_limit_mb=1024
```

The default cargo-fuzz sanitizer is AddressSanitizer. Do not catch panics or suppress
sanitizer failures. Reuse the corpus on subsequent runs; seed generation refuses
existing files. Windows users can run deterministic mutation tests on stable;
the sanitizer CI job runs on Linux.

If fuzzing fails, retain the reported input in `fuzz/artifacts/file_inspect/`, record
the seed, toolchain and command, and reproduce using:

```sh
cargo +nightly fuzz run file_inspect fuzz/artifacts/file_inspect/FAILURE_FILE
```

Minimize failures with `cargo +nightly fuzz tmin file_inspect FAILURE_FILE`, then
add the minimized synthetic reproduction to ordinary tests. Generated corpus,
artifacts and build directories are ignored; upload artifacts for failed CI runs.

Time/input/RSS limits apply to this campaign, not as new CLI guarantees. A short
run only samples parser behavior. Long-running campaigns should use isolated
workers with an OS memory/CPU limit and retain their corpus between runs.

Reference: [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz.html).
