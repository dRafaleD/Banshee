# Parser fuzzing

The `file_inspect` target feeds bounded arbitrary bytes into the same public parser
used by Banshee. It accepts errors for invalid input, fails on panics/sanitizer
reports, and asserts archive, decompression, executable section and symbol limits.
Samples are never loaded or executed. Seed generation verifies eight synthetic
PE/ELF/archive/compressed fixtures before writing them with exclusive creation.

## Run on Linux (or Ubuntu in WSL)

Install Rust nightly, cargo-fuzz, a C++ compiler and liblzma development headers.
Keep the main project on stable; select nightly only for the fuzz command.

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
cargo run --locked --example fuzz_seeds -- fuzz/corpus/file_inspect
cargo +nightly fuzz run file_inspect -- -max_total_time=60 -timeout=10 -max_len=1048576 -rss_limit_mb=1024
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
