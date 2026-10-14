#!/bin/sh
# Refresh the embedded IANA TLD snapshot used to validate extracted domains.
# Run manually from the repository root; review the diff before committing.
set -eu
source_url="https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
target="src/data/tlds.txt"
temporary="$(mktemp)"
trap 'rm -f "$temporary"' EXIT
curl --fail --silent --show-error --proto '=https' --tlsv1.2 "$source_url" -o "$temporary"
version="$(head -n 1 "$temporary")"
case "$version" in
  "# Version "*) ;;
  *) echo "unexpected IANA header: $version" >&2; exit 1 ;;
esac
{
  echo "# IANA root zone TLDs, lowercased. Source: $source_url"
  echo "$version"
  echo "# Refresh with scripts/update-tlds.sh; Banshee never downloads this at runtime."
  tail -n +2 "$temporary" | tr 'A-Z' 'a-z' | tr -d '\r'
} > "$target"
echo "updated $target ($(grep -vc '^#' "$target") TLDs)"
