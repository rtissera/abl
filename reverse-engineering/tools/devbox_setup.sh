#!/bin/bash
# devbox_setup.sh - provision a real dev box to complete the full 1:1 rebuild.
# Everything the sandbox used, plus the heavier RE + EDK2 build stack it lacked.
# Ubuntu 24.04 assumed (matches this repo's CI runner). Re-run is idempotent.
set -euo pipefail

echo "== apt: build + RE toolchain =="
sudo apt-get update
sudo apt-get install -y \
  build-essential crossbuild-essential-arm64 libc6-dev uuid-dev \
  llvm clang lld nasm acpica-tools \
  python3 python3-pip python3-venv git curl \
  binwalk radare2 binutils-aarch64-linux-gnu openssl
# ghidra: install separately (needs a JDK) - see FULL_REBUILD.md; or `snap install ghidra`

echo "== python analysis libs =="
python3 -m pip install --user --upgrade capstone pyelftools uefi_firmware cryptography

echo "== EDK2 (base for the build) =="
: "${EDK2_DIR:=$HOME/edk2}"
if [ ! -d "$EDK2_DIR" ]; then
  git clone --recurse-submodules https://github.com/tianocore/edk2.git "$EDK2_DIR"
fi
echo "   EDK2 at $EDK2_DIR (pin to the revision matching the embedded assert paths - see FULL_REBUILD.md B)"

echo "== qtestsign (the exact signer ROCKNIX uses; public test keys) =="
: "${QTESTSIGN_DIR:=$HOME/qtestsign}"
if [ ! -d "$QTESTSIGN_DIR" ]; then
  git clone https://github.com/msm8916-mainline/qtestsign.git "$QTESTSIGN_DIR"
fi
echo "   qtestsign at $QTESTSIGN_DIR  (export QTESTSIGN=$QTESTSIGN_DIR)"

cat <<EOF

Done. Next:
  1. Recover the shipped blobs from this repo's history:
        reverse-engineering/tools/extract_blobs.sh blobs
  2. Obtain + pin the Qualcomm QcomModulePkg (abl) base (FULL_REBUILD.md B).
  3. Diff-driven completion:
        reverse-engineering/tools/diff_text.py <ref>.pe <built>.efi
  4. Repack + verify:
        reverse-engineering/tools/roundtrip_test.sh
EOF
