# Full 1:1 source reconstruction & migrating off the sandbox

How to go from "reversed delta + open-source base" to a **complete, recompiling
1:1 source tree**, and how to move this work onto a real dev box to finish it.

Two useful definitions of "1:1" — pick your target:

* **Functional 1:1** — source that rebuilds to an ABL that boots and behaves
  identically. Very achievable: stock base + the reconstructed delta.
* **Byte-exact 1:1** — the rebuilt `LinuxLoader.efi` `.text`/`.data` match the
  shipped PE byte-for-byte. Achievable too, but needs the *exact* upstream
  revision + compiler version + build flags. This is the "iterate until
  `diff_text.py` says IDENTICAL" loop below.

---

## 0. What the sandbox already produced (nothing is lost)

Everything needed is committed to this branch; a plain `git clone` on the dev box
carries it all:

* the shipped blobs — recoverable from git history (`tools/extract_blobs.sh`),
  SHA-256-verified;
* the reversed delta — `reconstructed/…` (`BootCFW`, `GetSocName`,
  `VerifyClusterSize`, `PartitionValidation`/REGLINUX);
* the full commit→feature→binary-delta map — `ANALYSIS.md` §4;
* the toolchain fingerprint & base identification — `ANALYSIS.md` §3;
* the tooling — `tools/` (extract, disassemble, diff, FV pack, MBN sign, repack,
  round-trip proof).

The sandbox's `/tmp/.../scratchpad` working files are all reproducible from these
committed tools, so there is nothing extra to smuggle out.

---

## 1. Migrate to a dev box

```bash
git clone -b claude/qualcomm-abl-reverse-engineer-1xm7pc <your-fork-or-remote> abl
cd abl
reverse-engineering/tools/devbox_setup.sh     # installs RE + EDK2 + qtestsign stack
reverse-engineering/tools/extract_blobs.sh blobs   # recover + verify the 4 blobs
reverse-engineering/tools/roundtrip_test.sh        # sanity: tooling works here
```

The sandbox deliberately lacked the heavy pieces (`binwalk`, `radare2`,
`ghidra`, the AArch64 EDK2 build). `devbox_setup.sh` adds them. Ghidra (optional,
for GUI-assisted decompilation) needs a JDK — `snap install ghidra` or a manual
install; point it at the extracted `LinuxLoader.efi`.

---

## 2. Get the exact open-source base

The binary self-identifies its tree (`ANALYSIS.md` §3): EDK2
(`MdePkg`/`MdeModulePkg`/`ArmPkg`) + Qualcomm `QcomModulePkg` (the
`LinuxLoader`/`abl` application) + `libavb`, built `DEBUG_CLANG35`/`AARCH64`,
tree rooted at `/workspaces/LinuxLoader`.

1. **Qualcomm ABL / QcomModulePkg** — the `LinuxLoader` application source is
   published on CodeLinaro/CAF (`boot_images`, the `abl` component). Get the
   release matching these SoCs (SM6115/SM8250/SM8550/SM8650). ROCKNIX's own
   private `ROCKNIX/LinuxLoader` is a fork of exactly this.
2. **EDK2** — pin to the revision whose source *line/offset layout* matches the
   embedded assert strings. The binary carries dozens of exact paths like
   `MdePkg/Library/BaseLib/SafeString.c`,
   `MdePkg/Library/BasePrintLib/PrintLibInternal.c`,
   `ArmPkg/Library/ArmArchTimerLib/ArmArchTimerLib.c`. Bisect EDK2 tags until a
   stock build of those libs reproduces the referenced strings/asserts at the
   same relative offsets.
3. **Toolchain** — `CLANG35` profile (clang/LLVM + `lld`), `AARCH64`,
   `TARGET=DEBUG`. For byte-exact output the clang *version* matters; this repo's
   CI runs `ubuntu-24.04` with distro `llvm clang lld` (clang 18), which is the
   strongest available pin. Match it on the dev box.

**Confirm the base before touching the delta:** build stock QcomModulePkg
LinuxLoader for `AARCH64`/`DEBUG`, extract its PE, and diff against the reference:

```bash
reverse-engineering/tools/diff_text.py \
    <extracted-shipped>.pe  <stock-build>/LinuxLoader.efi
```

If the base + toolchain are right, the vast majority of `.text` matches and the
only remaining regions are the ROCKNIX delta. If huge swaths differ, the base
revision or compiler is wrong — fix that first (differences from the *wrong base*
are noise you can't reconstruct your way out of).

---

## 3. Apply the reconstructed delta

Overlay the reversed units onto the base package and wire them into the build:

```
reconstructed/QcomModulePkg/Application/LinuxLoader/
    BootCFW.c / BootCFW.h        boot dispatch (BootImg -> BootESP), cluster check
    SystemStats.c                GetSocName (chip-id table) + stats screen
    PartitionValidation.c        IsPartitionValid + the REGLINUX exclusion
```

`build_abl.sh` copies these over `QcomModulePkg/Application/LinuxLoader/` and
builds. Then use `ANALYSIS.md` §4 — the commit→feature map — as the worklist for
everything not yet reconstructed (boot-mode selection + DevInfo default, the
fastboot menus: System Stats / NUKE / UNINSTALL / Device-Model-Selection,
`RocknixAblVer` auto-update, the boot-image/ESP path bodies).

---

## 4. The diff-driven completion loop (the heart of 1:1)

You do **not** hand-reconstruct 483 KB of code. Most of it is stock and appears
for free once the base is right. You only reconstruct what still differs:

```
loop:
  build LinuxLoader.efi                       # base + current reconstructed delta
  diff_text.py <reference>.pe LinuxLoader.efi  # lists differing .text regions,
                                               #   each annotated w/ nearby string
  pick the top differing region
  disasm_fn.py <reference>.pe <rva>            # reverse that function
  write/adjust its C in reconstructed/
until diff_text.py prints "IDENTICAL"
```

Repeat for `.data` (`--section .data`). Tips for closing the last byte-level gaps
(these are compiler-determined, not logic):

* **function/data ordering** — EDK2 emits functions in source/`.inf` order; match
  the source ordering and the `.inf` `[Sources]` list.
* **string pooling & `.data` layout** — identical string literals in identical
  order reproduce the rodata; a stray/missing `DEBUG(())` shifts everything after
  it (this is exactly how `41156820` shifted layout when it dropped the REGLINUX
  log strings).
* **inlining / optimization** — same `-O`/`TARGET` and clang version.
* **PECOFF timestamp / build GUID** — normalize/ignore these fields when diffing;
  they are not code.

Run all four SoC targets — SM8250 ≡ SM8550 (one payload), SM6115 and SM8650 are
separate builds (`ANALYSIS.md` §2), so converge each distinct PE.

---

## 5. Repack, sign, verify, flash

Once `diff_text.py` is IDENTICAL (or functionally complete):

```bash
# build -> flashable signed ABL (qtestsign = the exact ROCKNIX scheme, public keys)
QTESTSIGN=$HOME/qtestsign \
  reverse-engineering/tools/repack.sh <build>/LinuxLoader.efi SM8250 abl_signed-SM8250.elf --qtestsign
# verify the whole pipeline is sound in-repo:
reverse-engineering/tools/roundtrip_test.sh
# flash (verifies .sha256 first):
./update.sh
```

See `REPACK.md` for the FV-packing/MBN-signing internals and the qtestsign
(public test-key) finding that makes re-signing possible without an OEM secret.

---

## 6. Definition-of-done checklist

- [ ] stock base + toolchain reproduce the non-delta `.text` (diff shrinks to
      only ROCKNIX regions)
- [ ] every region `diff_text.py` reports is reconstructed in `reconstructed/`
- [ ] `.text` and `.data` diff to IDENTICAL for each distinct SoC payload
      (SM8250/SM8550 shared; SM6115; SM8650)
- [ ] `fvpack` + `mkabl`/qtestsign reproduce a signed ABL; `roundtrip_test.sh`
      passes
- [ ] (byte-exact target) the re-signed ELF matches the shipped blob's SHA-256,
      or (functional target) the image boots on the device from a spare slot
