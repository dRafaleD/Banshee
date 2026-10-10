#!/usr/bin/env sh
set -eu
repo=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
installer="$repo/scripts/install.sh"
work=$(mktemp -d "${TMPDIR:-/tmp}/banshee-install-test.XXXXXX")
trap 'printf "Test artifacts: %s\n" "$work"' 0
cd "$work"
expect_install() {
    expected=$1; shift
    actual=0
    sh "$installer" --skip-build "$@" >"$work/install.stdout" 2>"$work/install.stderr" || actual=$?
    if [ "$actual" -ne "$expected" ]; then
        cat "$work/install.stdout" "$work/install.stderr" >&2
        printf 'Installer expected %s, got %s\n' "$expected" "$actual" >&2
        exit 1
    fi
}
expect_cli() {
    expected=$1; shift
    actual=0
    "$binary" "$@" >"$work/cli.stdout" 2>"$work/cli.stderr" || actual=$?
    if [ "$actual" -ne "$expected" ]; then
        cat "$work/cli.stdout" "$work/cli.stderr" >&2
        printf 'CLI expected %s, got %s\n' "$expected" "$actual" >&2
        exit 1
    fi
}
digest_file() {
    python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
}
expect_install 0 --help
grep -q 'Usage:' "$work/install.stdout"
expect_install 2 --unknown-option
expect_install 2 --prefix
expect_install 2 --prefix ''
expect_install 2 --prefix --force
host=$(rustc -vV | sed -n 's/^host: //p')
(cd "$repo" && cargo metadata --no-deps --locked --format-version 1) >"$work/metadata.json"
target_directory=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target_directory"])' "$work/metadata.json")
source_binary="$target_directory/$host/release/banshee"
if [ ! -f "$source_binary" ]; then source_binary="$target_directory/release/banshee"; fi
if [ ! -f "$source_binary" ]; then
    (cd "$repo" && cargo build --release --locked --bin banshee --target "$host")
    source_binary="$target_directory/$host/release/banshee"
fi
export CARGO_TARGET_DIR="$work/cargo target"
export CARGO_BUILD_TARGET=unavailable-test-target
export PREFIX="$work/local prefix"
expect_install 2 # A missing release binary must fail without installing anything.
mkdir -p "$CARGO_TARGET_DIR/$host/release"
cp "$source_binary" "$CARGO_TARGET_DIR/$host/release/banshee"
expect_install 0
binary="$PREFIX/bin/banshee"
test -x "$binary"
digest=$(digest_file "$binary")
test -n "$(find "$CARGO_TARGET_DIR" -type f -name banshee -print)"
expect_install 2
test "$(digest_file "$binary")" = "$digest"
printf 'preserve this sentinel' >"$binary"
expect_install 2
test "$(cat "$binary")" = 'preserve this sentinel'
expect_install 0 --force
test "$(digest_file "$binary")" = "$digest"
expect_install 0 --prefix 'relative prefix'
test -x "$work/relative prefix/bin/banshee"
mkdir -p "$work/directory prefix/bin/banshee"
expect_install 2 --prefix "$work/directory prefix" --force
mkdir -p "$work/link prefix/bin"
ln -s "$binary" "$work/link prefix/bin/banshee"
expect_install 2 --prefix "$work/link prefix" --force
rm "$work/link prefix/bin/banshee"
ln -s "$work/does-not-exist" "$work/link prefix/bin/banshee"
expect_install 2 --prefix "$work/link prefix" --force
mkdir "$work/linked bin prefix"
ln -s "$PREFIX/bin" "$work/linked bin prefix/bin"
expect_install 2 --prefix "$work/linked bin prefix" --force
native_target_directory="$CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$work/flat cargo target"
mkdir -p "$CARGO_TARGET_DIR/release"
cp "$source_binary" "$CARGO_TARGET_DIR/release/banshee"
expect_install 0 --prefix "$work/flat prefix"
export CARGO_TARGET_DIR="$native_target_directory"
test -z "$(find "$PREFIX/bin" -name '.banshee-install-*' -print)"
expect_cli 0 --help
grep -q 'QUICK START:' "$work/cli.stdout"
expect_cli 0 --version
expect_cli 0 extract --help
expect_cli 0 decode base64 aGVsbG8=
test "$(cat "$work/cli.stdout")" = hello
expect_cli 0 recipe 'base64|url' aGVsbG8lMjB3b3JsZA== --raw
test "$(cat "$work/cli.stdout")" = 'hello world'
test "$(printf aGVsbG8= | "$binary" decode base64)" = hello
expect_cli 0 whatis aGVsbG8=
expect_cli 0 hash calculate hello --algorithm sha256
expect_cli 0 timestamp to-human 1704067200
expect_cli 0 extract 'https://example.com 192.0.2.1' --defang
expect_cli 1 --fail-on-findings extract 192.0.2.1
expect_cli 2 unknown-command
printf hello >sample.txt
expect_cli 0 report sample.txt --format json --output report.json
python3 -c 'import json; json.load(open("report.json"))'
expect_cli 2 report sample.txt --format json --output report.json
expect_cli 0 report sample.txt --format json --output report.json --force
expect_cli 0 evidence create sample.txt --output case-evidence
expect_cli 0 evidence verify case-evidence
expect_cli 0 diff report.json report.json
for shell in bash zsh fish powershell elvish; do
    expect_cli 0 completions "$shell"
    test -s "$work/cli.stdout"
done
expect_cli 0 completions powershell --output banshee-completion.ps1
test -s banshee-completion.ps1
expect_cli 0 completions bash --output banshee-completion.bash
bash -n banshee-completion.bash
expect_cli 0 manpage
test -s "$work/cli.stdout"
expect_cli 0 manpage --output banshee.1
test -s banshee.1
printf 'PASS: isolated Linux installation, overwrite/link policy, Cargo target override, help, errors and daily examples.\n'
