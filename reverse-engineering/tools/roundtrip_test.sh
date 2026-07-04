#!/bin/bash
# Proof harness for the repack tooling. Requires nothing but this repo + python
# (uefi_firmware, capstone) and openssl. Recovers blobs from git history and:
#
#   1. mkabl.py reproduces every signed ABL byte-for-byte from its own payload
#      (proves ELF layout + SHA-384 measurement + MBN geometry are exact).
#   2. fvpack.py unpacks the real FV to the exact LinuxLoader PE, then rebuilds a
#      fresh FV around that PE that a STRICT independent parser (uefi_firmware)
#      fully descends (outer FV -> LZMA -> inner FV -> LinuxLoader).
#   3. End-to-end: PE -> fvpack -> mkabl(sign) -> a valid signed ABL whose inner
#      PE re-extracts identically.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT

echo "== recover + verify blobs =="
"$HERE/extract_blobs.sh" "$W/blobs" >/dev/null
echo

echo "== 1) mkabl byte-exact round-trip (all SoCs) =="
for soc in SM6115 SM8250 SM8550 SM8650; do
  python3 "$HERE/extract_pe.py" "$W/blobs/abl_signed-$soc.elf" >/dev/null 2>&1  # sanity
  python3 - "$W/blobs/abl_signed-$soc.elf" "$W/$soc.fd" <<'PY'
import sys,struct
d=open(sys.argv[1],'rb').read()
o=struct.unpack_from('<I',d,0x1c)[0];n=struct.unpack_from('<H',d,0x2c)[0]
ph=max((struct.unpack_from('<8I',d,o+i*32) for i in range(n)),key=lambda p:p[4] if p[0]==1 else 0)
open(sys.argv[2],'wb').write(d[ph[1]:ph[1]+ph[4]])
PY
  python3 "$HERE/mkabl.py" "$W/$soc.fd" "$W/blobs/abl_signed-$soc.elf" "$W/$soc.rp" --preserve-sig >/dev/null
  a=$(sha256sum "$W/blobs/abl_signed-$soc.elf"|cut -d' ' -f1)
  b=$(sha256sum "$W/$soc.rp"|cut -d' ' -f1)
  [ "$a" = "$b" ] && echo "   $soc  byte-identical" || { echo "   $soc  MISMATCH"; exit 1; }
done
echo

echo "== 2) fvpack unpack->rebuild, strict parser descends rebuilt FV =="
python3 "$HERE/fvpack.py" unpack "$W/SM8250.fd" "$W/ll.pe" >/dev/null
python3 "$HERE/fvpack.py" pack   "$W/ll.pe" "$W/rebuilt.fd" >/dev/null
python3 - "$W/rebuilt.fd" <<'PY'
import sys
from uefi_firmware import AutoParser
fw=AutoParser(open(sys.argv[1],'rb').read()).parse()
ok=[]
def w(o):
    if getattr(o,'name',None)=='LinuxLoader': ok.append(1)
    for c in getattr(o,'objects',[]) or []: w(c)
w(fw)
print("   strict parser reaches LinuxLoader in rebuilt FV:", "YES" if ok else "NO")
sys.exit(0 if ok else 1)
PY
echo

echo "== 3) end-to-end: PE -> fvpack -> mkabl(sign) -> re-extract =="
openssl genrsa -out "$W/test.pem" 2048 2>/dev/null
python3 "$HERE/mkabl.py" "$W/rebuilt.fd" "$W/blobs/abl_signed-SM8250.elf" "$W/out.elf" --key "$W/test.pem" >/dev/null
python3 "$HERE/extract_pe.py" "$W/out.elf" > "$W/final.pe" 2>/dev/null
if cmp -s "$W/ll.pe" "$W/final.pe"; then
  echo "   PE survives full build+sign+extract cycle: YES"
else
  echo "   PE survives full build+sign+extract cycle: NO"; exit 1
fi
echo
echo "ALL CHECKS PASSED"
