# Contributing to Banshee

Start with a small, reproducible issue or a focused pull request. Describe the
analyst workflow and expected output before proposing a new command.

## Development

Use stable Rust and clone this repository. Linux builds require a C compiler,
pkg-config and liblzma development headers; Windows builds require the MSVC C++
build tools and Windows SDK. macOS needs Xcode command line tools and Homebrew xz;
Unix source installer tests require Python 3. Run:

```sh
cargo fmt --all -- --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

CI runs these checks on Windows x86_64, Linux GNU x86_64/ARM64 and macOS
Intel/Apple Silicon, then smoke-tests packages and isolated installation.
Keep both application and fuzz Cargo.lock files committed. A successful local
run does not replace another platform's CI result. Review SHA-pinned action
updates and inventory/attestation checks as described in docs/SUPPLY_CHAIN.md.

## Review expectations

- Preserve offline analysis, input limits, secret redaction and exit-code semantics.
- Add a regression test for a bug or a meaningful test for new behavior.
- Use synthetic, harmless fixtures; never submit credentials, private samples or personal data.
- Update help, usage examples and CHANGELOG.md when behavior changes.
- Explain format/schema compatibility and dependency changes in the PR.
- Keep findings explainable: a pattern match is not a malware verdict.

Use [SECURITY.md](SECURITY.md) for vulnerabilities. Do not disclose exploit
details or sensitive samples in public issues. Contributions are under the
repository's MIT license.
