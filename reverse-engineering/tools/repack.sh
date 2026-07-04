#!/bin/bash
# repack.sh - end-to-end: reconstructed C source -> flashable signed ABL ELF.
#
#   LinuxLoader.efi (from build_abl.sh)  --fvpack.py-->  outer FV (.fd)
#                                        --sign--------->  abl_signed-<SoC>.elf
#
# Signing uses the SAME scheme as the shipped ROCKNIX blobs, whose cert chain is
# "qtestsign ... NOT SECURE" (public test keys) - so no OEM secret is needed for
# devices with an unfused/unlocked boot chain (the emulation handhelds this ABL
# targets). Two signers are supported:
#   * qtestsign  (recommended - the exact tool ROCKNIX uses; reproduces the
#                 shipped format bit-for-bit). Point QTESTSIGN at a checkout of
#                 https://github.com/msm8916-mainline/qtestsign
#   * mkabl.py   (built-in - reproduces the container + SHA-384 measurement
#                 exactly, verified byte-identical on all four shipped SoCs, and
#                 re-signs with an RSA key via openssl).
#
# Usage:
#   repack.sh <LinuxLoader.efi> <SoC> <out.elf> [--qtestsign] [--key key.pem]
#
# <SoC> selects the template blob (recovered from git history) that supplies the
# ELF header + MBN header + cert chain geometry for that SoC.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PE="${1:?LinuxLoader.efi}"; SOC="${2:?SoC e.g. SM8250}"; OUT="${3:?out.elf}"; shift 3 || true
USE_QTS=0; KEY=""
while [ $# -gt 0 ]; do case "$1" in
  --qtestsign) USE_QTS=1;; --key) KEY="$2"; shift;; *) echo "unknown arg $1"; exit 2;;
esac; shift; done

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
"$HERE/extract_blobs.sh" "$W/blobs" >/dev/null
TPL="$W/blobs/abl_signed-$SOC.elf"
[ -f "$TPL" ] || { echo "no template for $SOC"; exit 1; }

echo "[1/2] packing FV around $PE"
python3 "$HERE/fvpack.py" pack "$PE" "$W/payload.fd"

echo "[2/2] wrapping + signing ($SOC)"
if [ "$USE_QTS" = 1 ]; then
  : "${QTESTSIGN:?set QTESTSIGN=/path/to/qtestsign checkout}"
  # qtestsign consumes a bare ELF/hash-less image; feed it the FV payload as the
  # loadable segment. It emits the full signed MBN ELF with the qtestsign certs.
  python3 "$QTESTSIGN/qtestsign.py" aboot "$W/payload.fd" -o "$OUT"
elif [ -n "$KEY" ]; then
  python3 "$HERE/mkabl.py" "$W/payload.fd" "$TPL" "$OUT" --key "$KEY" --sigdigest sha384
else
  echo "provide --qtestsign (with QTESTSIGN=...) or --key <rsa2048.pem>"; exit 2
fi

# sidecar sha256, matching what update.sh verifies before flashing
( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
echo "wrote $OUT (+ .sha256)"
echo "flash with the repo's update.sh, or: dd if=$OUT of=/dev/disk/by-partlabel/abl_a bs=\$(blockdev --getss ...) conv=fsync,notrunc"
