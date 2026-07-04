# Methodology & path to a byte-verified 1:1 rebuild

This documents (a) exactly how the analysis in [`ANALYSIS.md`](ANALYSIS.md) was
produced so it is fully reproducible, and (b) the remaining steps to obtain a
*recompiling, binary-matching* 1:1 source tree — steps that require the upstream
source base and an AArch64 EDK2 toolchain.

## A. Reproduce the analysis (offline, from this repo)

Everything below runs against blobs recovered from git history — no network or
device needed.

```bash
cd <this repo>
pip install uefi_firmware capstone           # analysis deps

# 1. Recover + verify the four signed ABL blobs from git history
reverse-engineering/tools/extract_blobs.sh /tmp/blobs

# 2. Carve the Qualcomm signed ELF -> UEFI FV -> LZMA -> inner LinuxLoader PE
python3 reverse-engineering/tools/extract_pe.py /tmp/blobs/abl_signed-SM8250.elf > /tmp/LinuxLoader.pe

# 3. Map every commit to the strings/functions it introduced
reverse-engineering/tools/diff_versions.sh SM8250

# 4. Disassemble a located function (AArch64), e.g. GetSocName
python3 reverse-engineering/tools/disasm_fn.py 0x451c0 0x450e8 0x45264
```

`tools/pe64.py` provides the PE parser (RVA<->offset), an ASCII-string locator,
and an ADRP/ADD cross-reference map used to find a function from the DEBUG
string it prints — the core trick that makes a DEBUG_CLANG35 build tractable.

## B. Obtain the exact upstream base

The binary self-identifies its tree (embedded `/workspaces/LinuxLoader/...`
paths and the `DEBUG_CLANG35/AARCH64` object path). Assemble the base:

* **EDK2** (`MdePkg`, `MdeModulePkg`, `ArmPkg`) — TianoCore, BSD-2-Clause-Patent.
  Pin to the revision whose `MdePkg/Library/BaseLib/...`,
  `BasePrintLib/PrintLibInternal.c`, `SafeString.c` line/assert layout matches
  the embedded assert strings.
* **Qualcomm `QcomModulePkg`** (the `LinuxLoader`/`abl` application, `BootLib`,
  `avb/libavb`) — from CodeLinaro/CAF `boot_images` for the matching QCOM
  release, again BSD-licensed.
* **Toolchain:** clang/LLVM in EDK2's `CLANG35` (a.k.a. CLANGDWARF-family)
  profile, `lld`, `AARCH64`, `TARGET=DEBUG` — exactly the CI toolchain named in
  this repo's `.github/workflows/release-abl.yaml`
  (`llvm clang lld crossbuild-essential-arm64`).

Confirm the base is right *before* adding the ROCKNIX delta: build stock
QcomModulePkg LinuxLoader for AARCH64/DEBUG and diff its `.text` against the
extracted PE — the bulk of functions should match, leaving only the ROCKNIX
delta as differences.

## C. Apply the ROCKNIX delta

Drop the reconstructed units under
[`reconstructed/QcomModulePkg/Application/LinuxLoader/`](reconstructed/) into the
base package and wire them into `LinuxLoader.inf` / the boot entry. The commit
map in ANALYSIS.md §4 tells you, feature-by-feature, what else to (re)create:
boot-mode selection + DevInfo default, the fastboot menu additions (System
Stats, NUKE/UNINSTALL ROCKNIX, Device Model Selection), `RocknixAblVer`
auto-update, and the boot-image/ESP paths. Use `disasm_fn.py` on each function
address (locate via its DEBUG string with `pe64.build_adr_map`) to fill in the
medium-confidence bodies.

## D. Byte-verify

Iterate: compile → extract the resulting `LinuxLoader.efi` PE → diff `.text`
and `.data` against the reference PE (align by section, ignore the ASLR/reloc
and timestamp fields). Converge to zero diff. The outer Qualcomm signing
(hash-table segment + RSA signature) is **not** reproducible without ROCKNIX's
private signing key — a functional rebuild matches the *payload PE*, not the
outer signature. Re-signing for a device is a separate, key-dependent step.

## Notes

* This is interoperability/security reverse engineering of a bootloader that
  runs on the analyst's own hardware, cross-referenced against permissively
  licensed (BSD) upstream sources. The recovered blobs came from this
  repository's own public git history.
* SM8250 and SM8550 share a byte-identical payload PE; analyse once, applies to
  both. SM6115 and SM8650 are separate builds — repeat §C/§D per distinct PE.
