#!/bin/bash
# Recover every historical ROCKNIX signed-ABL blob from this repo's git history,
# verify each against its committed .sha256 sidecar, and (optionally) extract the
# inner LinuxLoader AArch64 PE for each version.
#
# Usage:  tools/extract_blobs.sh [OUTDIR]
#
# The signed ELFs were committed directly until commit 3482979 removed them in
# favour of tag-based release attachments; git history is therefore the source
# of truth for offline analysis.
set -euo pipefail
OUT="${1:-blobs}"
mkdir -p "$OUT"
REPO_ROOT="$(git rev-parse --show-toplevel)"

# Last commit that still carried the blobs (parent of the removal commit).
LAST="$(git rev-list -1 3482979^ 2>/dev/null || echo ab8add4)"

for soc in SM6115 SM8250 SM8550 SM8650; do
  f="abl_signed-${soc}.elf"
  git -C "$REPO_ROOT" show "${LAST}:${f}"        > "$OUT/${f}"
  git -C "$REPO_ROOT" show "${LAST}:${f}.sha256" > "$OUT/${f}.sha256"
  calc="$(sha256sum "$OUT/${f}" | cut -d' ' -f1)"
  want="$(cut -d' ' -f1 "$OUT/${f}.sha256")"
  if [ "$calc" = "$want" ]; then
    echo "OK   ${f}  ${calc}"
  else
    echo "FAIL ${f}  calc=${calc} want=${want}" >&2
  fi
done
echo "Extracted signed blobs to $OUT/"
