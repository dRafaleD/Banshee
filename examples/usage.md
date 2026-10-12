# Banshee command examples

The examples below use `banshee` after installation. When running from a source
checkout without installation, replace it with `target/release/banshee` after
building with `cargo build --release`.

## Detect and decode

```bash
banshee whatis "aGVsbG8lMjB3b3JsZA=="
echo "Njg2NTZjNmM2Zg==" | banshee whatis
banshee whatis --file suspicious.txt
banshee whatis --json "aGVsbG8="
# UTF-16LE inside Base64, as used by PowerShell -EncodedCommand.
banshee whatis "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAxAA=="
# Script obfuscation is rewritten in place, never executed.
banshee whatis "\$u=(\"{1}{0}\" -f 'tp://x.example.test','ht'); iex ([char[]](105,101,120) -join '')"
# Heuristic single-byte XOR inside Base64; the layer reports the key.
banshee whatis "xsrLy8DG0YXRyoXA3cTI1cnAi9HA1tGFwNPA19yFk5WF1sDGysvB1g=="
banshee entropy "aGVsbG8gd29ybGQ="
banshee encode base64 "hello"
echo 'aGVsbG8=' | banshee decode base64
banshee encode unicode "Banshee 👻"
banshee encode base32 "hello"
banshee encode punycode "bücher.de"
banshee decode binary "01101000 01101001"
banshee recipe 'base64|url' 'aGVsbG8lMjB3b3JsZA=='
banshee recipe 'base64|gzip|url' --file encoded-payload.txt
banshee recipe 'rot13|encode:base32' 'Uryyb'
```

## IOCs, hashes, and timestamps

```bash
cat access.log | banshee extract
cat access.log | banshee extract --url --domain --defang
banshee extract --hash --json --file suspicious.log
banshee extract --context 2 --file suspicious.log
banshee extract --secret --context 1 --file application.log
# Unsafe opt-in for controlled local review only:
banshee extract --secret --reveal-secrets --file application.log
banshee hash calculate --algorithm sha256 "hello"
banshee hash identify d41d8cd98f00b204e9800998ecf8427e
banshee hash crack HASH --algorithm md5 --wordlist words.txt
banshee timestamp to-human 1704067200000
banshee timestamp to-unix "2024-01-01T00:00:00Z"
```

## JWTs, regexes, and certificates

```bash
banshee jwt inspect "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature"
banshee jwt verify TOKEN --algorithm hs256 --secret "local-secret"
banshee jwt verify TOKEN --algorithm rs256 --key public.pem
banshee jwt verify TOKEN --algorithm es256 --key public.pem --audience banshee --issuer local
banshee regex test 'user=(\w+)' "user=alice"
banshee regex patterns
banshee cert inspect certificate.pem
banshee cert inspect certificate.der --json
banshee cert chain leaf-to-root-chain.pem
```

## Files, rules, and watch mode

```bash
cat suspicious.log | banshee analyze --json
banshee analyze --file suspicious.bin
banshee encode base64 --file payload.bin
banshee file inspect suspicious.zip
banshee file inspect package.tar.xz --json
banshee file inspect suspicious.exe
banshee file inspect application.elf --json
# PE certificate-table presence is metadata only; signature trust is not verified.
banshee report suspicious.exe
banshee report suspicious.zip --format json --output report.json
banshee report suspicious.bin --rules examples/rules.toml --format markdown --output report.md
# Offline HTML page: no scripts, no external resources, restrictive CSP.
banshee report suspicious.bin --rules examples/rules.toml --format html --output report.html
banshee evidence create suspicious.bin --rules examples/rules.toml --output case-evidence
banshee evidence verify case-evidence
# Explicit opt-in only when the original sample must be preserved in the bundle.
banshee evidence create suspicious.bin --include-sample --output full-evidence
banshee diff baseline-report.json current-report.json
banshee diff baseline-evidence current-evidence --json
banshee export report.json --format stix --output observables.stix.json
banshee export case-evidence --format misp --output event.misp.json
banshee export report.json --format csv
banshee scan ./samples
banshee scan ./samples --recursive --include '*.exe' --exclude 'known-safe/**'
banshee scan ./samples --recursive --max-file-size 32MiB --max-total-size 512MiB
banshee scan ./samples --recursive --rules examples/rules.toml --format jsonl
banshee rules validate examples/rules.toml
banshee rules validate examples/rules.toml --json
cat suspicious.log | banshee rules scan --rules examples/rules.toml
banshee rules scan --rules examples/rules.toml --file payload.bin --fail-on-findings
banshee watch /var/log/auth.log
banshee watch suspicious.log --from-start --once --json
```

## Output, presentation, and shell integration

```bash
banshee extract --format csv --file suspicious.log
banshee analyze --format jsonl --file suspicious.log
banshee extract --fail-on-findings --file suspicious.log
banshee extract --summary --sort count --file suspicious.log
banshee extract --allowlist known-safe.txt --denylist priority-iocs.txt --file suspicious.log
banshee --color always extract "https://evil.example 8.8.8.8"
banshee --no-color whatis "aGVsbG8="
banshee banner
banshee banner --compact
banshee banner --mask-only
banshee analyze --format json --output report.json --file suspicious.log
banshee banner --output banner.txt
banshee extract --quiet --fail-on-findings --file suspicious.log
banshee analyze --verbose --format jsonl --file suspicious.log
banshee completions bash > ~/.local/share/bash-completion/completions/banshee
banshee manpage > banshee.1
```

## Developer parser checks

Use synthetic corpus files only. See [the fuzz guide](../fuzz/README.md) for setup
and reproducing sanitizer findings; the [quality plan](../docs/QUALITY_PLAN.md)
defines the phase acceptance criteria.

```bash
cargo test --locked file_inspect::tests
cargo run --locked --example fuzz_seeds -- fuzz/corpus/file_inspect
cargo +nightly fuzz run file_inspect -- -max_total_time=60 -timeout=10 -max_len=1048576 -rss_limit_mb=1024
```
