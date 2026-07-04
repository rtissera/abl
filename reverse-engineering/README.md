# ROCKNIX ABL — Reverse Engineering

Reverse engineering of the ROCKNIX custom Qualcomm **LinuxLoader** ABL
(Application Bootloader) to recover, in rebuildable C form, the modifications
ROCKNIX applied over the open Qualcomm `QcomModulePkg` + TianoCore **EDK2**
source. ROCKNIX ships only signed binary blobs and keeps its LinuxLoader source
private (`github.com/ROCKNIX/LinuxLoader` → HTTP 404); this recovers the delta.

## What's here

| path | contents |
|------|----------|
| [`ANALYSIS.md`](ANALYSIS.md) | Full report: provenance, container format, base identification, and the complete commit→binary-delta modification catalogue. |
| [`METHODOLOGY.md`](METHODOLOGY.md) | Reproduce the analysis; obtain the upstream base; apply the delta; byte-verify a 1:1 rebuild. |
| [`reconstructed/`](reconstructed/) | EDK2-style C reconstruction of the ROCKNIX delta (`BootCFW`, `GetSocName`, `VerifyClusterSize`, …). |
| [`tools/`](tools/) | Reproducible pipeline: blob recovery, PE extraction, version diffing, disassembly. |

## TL;DR of findings

* **Container:** Qualcomm signed ELF32/ARM (hash-table segment = the signature)
  wrapping a UEFI Firmware Volume → LZMA section → inner FV → a single AArch64
  PE32+ application **`LinuxLoader.efi`** (`.text` 483 KB).
* **Base:** Qualcomm `QcomModulePkg/Application/LinuxLoader` + EDK2
  (`MdePkg`/`MdeModulePkg`/`ArmPkg`) + `libavb`, built `DEBUG_CLANG35/AARCH64`.
  Self-identified by embedded `/workspaces/LinuxLoader/...` build paths.
* **Delta (branded "BootCFW"):** default-Linux boot-mode selection with Vol-Up
  Android override; a boot-image-container→ESP Linux boot path; fastboot System
  Stats (SoC/RAM/storage/SD); Device Model Selection via DTB scan; NUKE /
  UNINSTALL ROCKNIX partition tools; `RocknixAblVer` self-update; 16 KB ESP
  cluster-size enforcement. Each feature is pinned to the commit that introduced
  it in ANALYSIS.md §4.
* **Builds:** 3 distinct payloads across 4 SoCs — SM8250 ≡ SM8550 (byte
  identical payload), SM6115 and SM8650 separate.

Source blobs were recovered and SHA-256-verified from this repository's own git
history (committed directly until commit `3482979`).

## Reproduce

```bash
pip install uefi_firmware capstone
reverse-engineering/tools/extract_blobs.sh /tmp/blobs
python3 reverse-engineering/tools/extract_pe.py /tmp/blobs/abl_signed-SM8250.elf > /tmp/LinuxLoader.pe
reverse-engineering/tools/diff_versions.sh SM8250
```

## Scope & licensing

This is interoperability/security reverse engineering of a bootloader that runs
on the owner's own hardware, cross-referenced against permissively licensed
(BSD-2-Clause-Patent) upstream EDK2/Qualcomm sources. The reconstruction covers
the ROCKNIX-authored delta; the unmodified base remains upstream code obtainable
per METHODOLOGY.md §B. The outer Qualcomm RSA signature cannot be reproduced
without ROCKNIX's private key — a rebuild matches the payload PE, not the
signature.
