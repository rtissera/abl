#!/bin/bash
# Map each ROCKNIX commit to the concrete strings it added/removed in the inner
# LinuxLoader PE. Extracts the PE for every historical version of a given SoC's
# signed ABL and diffs the sorted string tables between consecutive commits.
#
# Usage:  tools/diff_versions.sh [SOC]      (default SOC=SM8250)
#
# Requires: python3 with the `uefi_firmware` package (pip install uefi_firmware).
set -euo pipefail
SOC="${1:-SM8250}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/str"

i=0
git -C "$REPO_ROOT" log --all --reverse --format='%H %s' -- "abl_signed-${SOC}.elf" \
| while read -r h msg; do
    git -C "$REPO_ROOT" show "${h}:abl_signed-${SOC}.elf" > "$TMP/b.elf" 2>/dev/null || continue
    [ -s "$TMP/b.elf" ] || continue
    python3 "$HERE/extract_pe.py" "$TMP/b.elf" > "$TMP/pe" 2>/dev/null || continue
    idx="$(printf '%02d' "$i")"
    strings -n 4 "$TMP/pe" | sort -u > "$TMP/str/${idx}.txt"
    if [ "$i" -gt 0 ]; then
      prev="$(printf '%02d' $((i-1)))"
      echo "==== ${h:0:8}  ${msg}"
      comm -13 "$TMP/str/${prev}.txt" "$TMP/str/${idx}.txt" \
        | grep -viE '^/workspaces|\.c$' | sed 's/^/  +/'
    fi
    i=$((i+1))
  done
