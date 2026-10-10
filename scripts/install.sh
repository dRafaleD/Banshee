#!/usr/bin/env sh
set -eu

usage() {
    cat <<'HELP'
Usage: sh scripts/install.sh [--prefix PATH] [--force] [--skip-build] [-h|--help]
Build the local checkout and install its native release binary to PREFIX/bin/banshee.
Default prefix: $PREFIX or $HOME/.local. Relative prefixes use your current directory.
Existing files are refused unless --force is supplied; links/directories are refused.
Requires Cargo/Rust, a native linker, Python 3 (Cargo JSON), and standard Unix tools.
Cargo target-directory settings are respected. No downloaded executable is installed.
--skip-build reuses a local release binary (native-target layout first, then release/).
Example: sh scripts/install.sh --prefix "$HOME/.local"
HELP
}
fail() { printf 'error: %s\n' "$*" >&2; exit 2; }
prefix="${PREFIX:-${HOME:?HOME is required unless PREFIX is set}/.local}"
force=0
skip_build=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            if [ "$#" -lt 2 ]; then
                fail '--prefix requires a path'
            fi
            prefix="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        --force) force=1; shift ;;
        --skip-build) skip_build=1; shift ;;
        *)
            fail "unknown option: $1 (use --help)"
            ;;
    esac
done

[ -n "$prefix" ] || fail '--prefix must not be empty'
case "$prefix" in -*) fail '--prefix must not start with a dash' ;; esac
command -v python3 >/dev/null 2>&1 || fail 'missing prerequisite: python3'
prefix=$(python3 -c 'import os,sys; print(os.path.abspath(sys.argv[1]))' "$prefix") || fail 'cannot resolve prefix'
destination="$prefix/bin/banshee"
check_destination() {
    [ ! -L "$prefix/bin" ] || fail "bin directory is a symbolic link: $prefix/bin"
    [ ! -L "$destination" ] || fail "destination is a symbolic link: $destination"
    if [ -e "$destination" ]; then
        [ -f "$destination" ] || fail "destination is not a regular file: $destination"
        [ "$force" -eq 1 ] || fail "destination exists: $destination (use --force to replace)"
    fi
}
check_destination
for tool in cargo rustc python3 install mktemp; do
    command -v "$tool" >/dev/null 2>&1 || fail "missing prerequisite: $tool"
done
repo=$(CDPATH= cd "$(dirname "$0")/.." && pwd) || fail 'cannot locate checkout'
log=$(mktemp) || fail 'cannot allocate build log'
stage=''
trap 'rm -f "$log"; if [ -n "$stage" ]; then rm -f "$stage"; fi' 0
trap 'exit 2' HUP INT TERM
host=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$host" ] || fail 'cannot determine native Rust host'
# Running at the repository root retains its .cargo configuration, regardless of caller cwd.
if [ "$skip_build" -eq 1 ]; then
    (cd "$repo" && cargo metadata --no-deps --locked --format-version 1) >"$log" || fail 'Cargo metadata failed'
    binary=$(python3 - "$log" "$host" <<'PY'
import json, os, sys
root = json.load(open(sys.argv[1], encoding='utf-8'))['target_directory']
paths = [os.path.join(root, sys.argv[2], 'release', 'banshee'), os.path.join(root, 'release', 'banshee')]
for path in paths:
    if os.path.isfile(path):
        print(path)
        break
else:
    sys.exit('error: no local release binary; run installer without --skip-build')
PY
    ) || fail 'cannot locate local release binary'
else
(cd "$repo" && cargo build --release --locked --bin banshee --target "$host" --message-format=json-render-diagnostics) >"$log" || fail 'Cargo build failed; see diagnostics above'
binary=$(python3 - "$log" <<'PY'
import json, sys
paths = []
for line in open(sys.argv[1], encoding='utf-8'):
    event = json.loads(line)
    if (event.get('reason') == 'compiler-artifact'
            and event.get('target', {}).get('name') == 'banshee'
            and 'bin' in event.get('target', {}).get('kind', []) and event.get('executable')):
        paths.append(event['executable'])
if len(paths) != 1:
    sys.exit('error: Cargo did not report exactly one Banshee executable')
print(paths[0])
PY
) || fail 'cannot read Cargo executable path'
fi
[ -f "$binary" ] && [ -x "$binary" ] || fail "built executable missing: $binary"
"$binary" --version >/dev/null || fail 'local binary does not run on this host; rebuild without --skip-build'
install -d "$prefix/bin" || fail 'cannot create installation directory'
stage=$(mktemp "$prefix/bin/.banshee-install.XXXXXX") || fail 'cannot stage executable'
install -m 755 "$binary" "$stage" || fail 'cannot copy built executable'
check_destination
if [ "$force" -eq 1 ]; then
    python3 -c 'import os,sys; os.replace(sys.argv[1], sys.argv[2])' "$stage" "$destination" || fail 'cannot replace executable'
else
    # Hard-link publication is atomic and cannot replace a file created during the build.
    python3 -c 'import os,sys; os.link(sys.argv[1], sys.argv[2])' "$stage" "$destination" || fail 'cannot publish executable (destination may now exist)'
fi

printf 'Installed banshee to %s\nAdd %s/bin to PATH, then run: banshee --help\n' "$destination" "$prefix"

