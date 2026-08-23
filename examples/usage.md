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
banshee rules validate examples/rules.toml
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
