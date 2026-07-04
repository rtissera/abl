#!/bin/bash
# build_abl.sh - build LinuxLoader.efi from the EDK2/Qualcomm base with the
# reconstructed ROCKNIX delta overlaid. Mirrors the toolchain named in this
# repo's CI (.github/workflows/release-abl.yaml: build-essential,
# crossbuild-essential-arm64, llvm, clang, lld) and the binary's own build path
# (DEBUG_CLANG35 / AARCH64, tree rooted at /workspaces/LinuxLoader).
#
# This script documents and drives the standard EDK2 build; it must run on a host
# that has the base source tree (see ../METHODOLOGY.md ss B for how to obtain it).
# It is intentionally explicit rather than magic - point BASE at your tree.
#
#   BASE=/path/to/LinuxLoader   ./build_abl.sh
#
# Layout expected under $BASE:  MdePkg/ MdeModulePkg/ ArmPkg/ QcomModulePkg/
# and edksetup.sh (EDK2). The reconstructed delta in ../reconstructed/ is copied
# over QcomModulePkg/Application/LinuxLoader/ before building.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="${BASE:?set BASE=/path/to/LinuxLoader source tree}"
RECON="$HERE/../reconstructed/QcomModulePkg/Application/LinuxLoader"
TARGET="${TARGET:-DEBUG}"
TOOLCHAIN="${TOOLCHAIN:-CLANG35}"
ARCH="${ARCH:-AARCH64}"

echo "== overlaying reconstructed ROCKNIX delta =="
cp -v "$RECON"/*.c "$RECON"/*.h "$BASE/QcomModulePkg/Application/LinuxLoader/"

echo "== EDK2 build ($TOOLCHAIN/$TARGET/$ARCH) =="
cd "$BASE"
# shellcheck disable=SC1091
export WORKSPACE="$BASE"
export PACKAGES_PATH="$BASE"
source ./edksetup.sh
make -C BaseTools
build -p QcomModulePkg/QcomModulePkg.dsc \
      -a "$ARCH" -t "$TOOLCHAIN" -b "$TARGET" \
      -m QcomModulePkg/Application/LinuxLoader/LinuxLoader.inf

OUT="Build/*/${TARGET}_${TOOLCHAIN}/${ARCH}/QcomModulePkg/Application/LinuxLoader/LinuxLoader/OUTPUT/LinuxLoader.efi"
echo "built: $(ls $OUT)"
echo "next:  ./repack.sh $OUT <SoC> abl_signed-<SoC>.elf --qtestsign   (or --key key.pem)"
