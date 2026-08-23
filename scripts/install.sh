#!/usr/bin/env sh
set -eu

prefix="${PREFIX:-$HOME/.local}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            if [ "$#" -lt 2 ]; then
                echo "error: --prefix requires a path" >&2
                exit 2
            fi
            prefix="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: scripts/install.sh [--prefix PATH]"
            echo "Default prefix: \$PREFIX or \$HOME/.local"
            exit 0
            ;;
        *)
            echo "error: unknown option: $1" >&2
            exit 2
            ;;
    esac
done

cargo build --release --locked
install -d "$prefix/bin"
install -m 755 target/release/banshee "$prefix/bin/banshee"

echo "Installed banshee to $prefix/bin/banshee"

