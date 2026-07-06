# ROCKNIX ABL — Reverse-Engineering Analysis

Reverse engineering of the ROCKNIX custom Qualcomm **LinuxLoader** Application
Bootloader (ABL). The goal is to recover, in a fully documented and rebuildable
form, the modifications ROCKNIX applied on top of the open Qualcomm
`QcomModulePkg` / TianoCore **EDK2** source, and to make those modifications
reproducible as C source.

> **Scope & honesty note.** ROCKNIX publishes only *signed binary blobs*; the
> LinuxLoader source repository (`github.com/ROCKNIX/LinuxLoader`) is private
> (returns HTTP 404). The `.text` of the application is 483 KB of AArch64 code
> (~120k instructions), the overwhelming majority of which is **unmodified,
> already-open Qualcomm/EDK2 code**. This document reconstructs the *ROCKNIX
> delta* — the part that is actually unknown/locked — at high fidelity, and
> gives the exact base identification and build recipe needed to reproduce a
> matching binary. Per-function reconstruction confidence is labelled
> throughout. Nothing here is presented as byte-verified against a recompile,
> because the AArch64 EDK2 toolchain + full source base required for a
> differential recompile are not available in this analysis environment.

---

## 1. Source material (provenance)

All four production blobs were recovered from the **git history of this very
repository** (`rtissera/abl`). ROCKNIX committed the signed ELFs directly until
commit `3482979` ("Release remove deprecated blobs … use tags"), which deleted
them in favour of GitHub release attachments. The last committed set (parent
commit `ab8add4`) was extracted and verified against the checked-in
`.sha256` sidecars:

| SoC     | file                    | SHA-256 (verified against repo sidecar)                            |
|---------|-------------------------|--------------------------------------------------------------------|
| SM6115  | `abl_signed-SM6115.elf` | `4513e25057ea43ea23644ee7988f3a642033fea03820c1559c7f2095b5d34543` |
| SM8250  | `abl_signed-SM8250.elf` | `f595cf4779c122b08f1e91f40f8752aa2bf94efa400dc0511b7d24ab8846c182` |
| SM8550  | `abl_signed-SM8550.elf` | `3e771f5859f4379549c33db55b94ceb6c5ee8e7cb8eed0005ac3259cd4d691c8` |
| SM8650  | `abl_signed-SM8650.elf` | `8ce8b082916c14ad89e4c6886273e44dadbc65b7a766f1a5fd624a2a84ad6dff` |

Each file is exactly **258048 bytes**.

The public `v1.1.3` release (which the network policy of this environment
cannot download) is built from **LinuxLoader commit
`b1ed734da482e921b72efe8911f2e9186213a678`** and adds only three incremental
commits over the analysed set ("FatDxe: patch cache struct live on sm8250
only", "RawFat: use blockio as fallback", the "PatchArray" merge). The
recovered blobs are therefore the immediate lineage of 1.1.3 and share its
entire architecture.

---

## 2. Container format (Qualcomm signed ELF → UEFI FD → PE)

The blob is the standard **Qualcomm sboot / MBN "hash-table-segment" ELF**:

```
ELF32, EM_ARM, EXEC, entry 0x9fa00000, 3 program headers
  PT_NULL  off 0x00000  ELF header + program-header table
  PT_NULL  off 0x01000  vaddr 0x9fa3d000  hash-table segment (SHA-256 digests
                        of each segment + RSA signature + cert chain)  ← "signed"
  PT_LOAD  off 0x02000  vaddr 0x9fa00000  filesz 0x3d000  RWE  ← the UEFI payload
```

The `PT_LOAD` payload (249856 bytes) is a single EDK2 **Firmware Volume**:

```
EFI_FIRMWARE_VOLUME_HEADER  (_FVH at +0x28, FvNameGuid 8c8ce578-…-c32dd3 = FFS2)
└─ FFS file 9e21fd93-…-b2d792   (EFI_FIRMWARE_CONTENTS_SIGNED wrapper)
   └─ GUIDED section ee4e5898-3914-4259-9d6e-dc7bd79403cf  (LZMA custom decompress)
      └─ inner FIRMWARE_VOLUME (FFS2)
         ├─ pad file ffffffff-…
         └─ FFS file f536d559-459f-48fa-8bbc-43b554ecae8d  type 0x09 APPLICATION
            ├─ UI section        "LinuxLoader"
            └─ PE32 section      → LinuxLoader.efi  (AArch64 PE32+)
```

The extracted PE:

```
Machine 0xAA64 (AArch64), PE32+, AddressOfEntryPoint 0x1000, ImageBase 0
  .text   RVA 0x001000  size 0x76000  (RX)   483328 bytes
  .data   RVA 0x077000  size 0x22000  (RW)
  .reloc  RVA 0x099000  size 0x01000
```

The extraction pipeline is fully automated in
[`tools/extract_pe.py`](tools/extract_pe.py) (carve `PT_LOAD` → parse FV → LZMA
decompress → dump largest PE) and is byte-reproducible.

### Per-SoC build matrix

The application is **SoC-agnostic at build time** and dispatches on the runtime
`EFI_CHIPINFO_PROTOCOL`. Three distinct PE payloads exist across the four SoCs:

| SoC    | inner PE SHA-256 (first 16) | note                                   |
|--------|-----------------------------|----------------------------------------|
| SM8250 | `0ee817f238557713…`         | identical payload to SM8550            |
| SM8550 | `0ee817f238557713…`         | identical payload to SM8250            |
| SM6115 | `276cc3509bf07f28…`         | distinct build (32-bit-ish PCD deltas) |
| SM8650 | `3f28eb7eb404b55a…`         | distinct build                         |

SM8250 and SM8550 differ **only** in the outer Qualcomm signature/cert, not in
code.

---

## 3. Base identification

The binary embeds absolute build paths and the DEBUG assert file table, which
pin the exact upstream tree and toolchain:

```
/workspaces/LinuxLoader/MdePkg/…            ← TianoCore EDK2 (BSD-2-Clause-Patent)
/workspaces/LinuxLoader/ArmPkg/…            ← EDK2 ArmPkg
/workspaces/LinuxLoader/MdeModulePkg/…      ← EDK2 MdeModulePkg
/workspaces/LinuxLoader/QcomModulePkg/…     ← Qualcomm ABL (LinuxLoader) package
/workspaces/LinuxLoader/QcomModulePkg/Library/avb/libavb/…   ← Android Verified Boot
/workspaces/LinuxLoader/obj/ABL_OBJ/Build/DEBUG_CLANG35/AARCH64/
        QcomModulePkg/Application/LinuxLoader/LinuxLoader/DEBUG/LinuxLoader.dll
```

* **Base project:** Qualcomm's `QcomModulePkg/Application/LinuxLoader` (the "ABL"
  a.k.a. `abl` / `boot_images` LinuxLoader), the same codebase distributed on
  CodeLinaro/CAF, built against upstream **EDK2** (`MdePkg`, `MdeModulePkg`,
  `ArmPkg`) with **`libavb`**.
* **Toolchain / target:** `DEBUG_CLANG35`, `AARCH64`. It is a DEBUG build — the
  full `DEBUG()` / `ASSERT()` machinery is compiled in, which is what makes the
  reconstruction tractable (every log string and source filename is present).
* The EDK2/Qualcomm portions are permissively licensed (BSD-2-Clause-Patent);
  the ROCKNIX modifications are the delta catalogued below.

---

## 4. ROCKNIX modification catalogue (commit → binary delta)

The full development history is recoverable from the ~20 blob versions in git.
Extracting the inner PE for every historical commit and diffing the string
tables maps each commit message to the concrete code it introduced. This is the
authoritative feature map of the ROCKNIX delta:

| # | commit    | message                                                   | introduced (evidence: new strings/functions)                                                            |
|---|-----------|-----------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| 00| `4e94345` | Add SM8250, support Batocera+Knulli                       | fork point from Qualcomm ABL; Linux/Android boot-mode split                                               |
| 01| `d2f5bc6` | Default mode Linux, fix cold-boot keypress                | `Failed to read DevInfo, default to Linux: %r`; DevInfo-backed default mode                               |
| 02| `bbc794d` | Rename to ROCKNIX-ABL                                      | `ROCKNIX-ABL`                                                                                             |
| 03| `894f0fc` | Error screens for no-Linux / corrupt boot                 | `LINUX NOT FOUND`, `BootMode=Linux selected, but ESP not found`, `Insert an SD card…`, `Press any key…`  |
| 04| `43d8bad` | Fix Android memory size                                   | RAM-partition sizing change                                                                               |
| 05| `931f890` | ABL-mode dev toggle + NUKE ROCKNIX partition              | `NukeRocknixMenu`, `NUKE THE ROCKNIX PARTITION`, `Welcome to ROCKNIX ABL!`, `Booting to Linux`           |
| 06| `6ae3d5e` | System Stats menu (SoC/RAM/storage/battery), cfg charging | `System Stats`, `Snapdragon %d`, `Snapdragon 865 (SM8250)`, `RAM - `, `STORAGE - `, `%d GB`, `Fastboot Mode` |
| 07| `c1a410a` | SD8 Gen2 + 1/2 TB storage in stats                        | `Snapdragon G3x Gen 2`, `undefined %d`                                                                    |
| 08| `d0778f0` | UNINSTALL ROCKNIX fastboot menu                           | `UNINSTALL ROCKNIX`, `… & EXPAND USERDATA`, `CANCEL - KEEP ROCKNIX & MY DATA`, `Snapdragon G3 Gen 3`      |
| 09| `5b90b35` | Chip ID for SD8 Elite Gen 1                               | `Snapdragon 8 Elite Gen 1` (soc_id 0x2c2)                                                                 |
| 10| `ed836fe` | Auto-updating ABL                                         | `RocknixAblVer`, `CheckBootAA64:`, `LoadBootAA64AndStart:`                                                |
| 11| `64fb3fc` | Fix system-stats calculations                             | stats arithmetic fixes                                                                                    |
| 12| `097e3bb` | Fix forced Android factory reset; REGLINUX block          | `REGLINUX partition detected`, `REGLINUX is not supported…`                                               |
| 13| `4c1dd97` | Bug fixes                                                 | `Error returned from GetRamPartitions %r`                                                                 |
| 14| `4115682` | Remove battery stats + white list                        | battery/whitelist code removed                                                                            |
| 15| `91c0ba8` | **Android boot-image container** (major)                  | `BootCFW`, `BootImg`, `BootESP`, `GetDtModelFromBuffer`, `Device model selection`, `ModelSelectionMenu`  |
| 16| `e4e0564` | Batocera boot-image path                                  | additional ESP/image path handling                                                                       |
| 17| `08511d0` | Model in fastboot menu + verify cluster size              | `VerifyClusterSize`, `INVALID CLUSTER SIZE`, `MODEL - `, `… 16KB cluster size`                            |
| 18| `1d6c948` | SD-card size in system stats                              | `SD CARD - `                                                                                             |
| 19| `204f927` | Don't populate cmdline with Android data when Linux       | cmdline gating on boot mode                                                                               |

Full per-commit string diffs are reproducible with
[`tools/diff_versions.sh`](tools/diff_versions.sh).

### Functional summary of the delta

ROCKNIX layered a custom firmware boot path — branded **"BootCFW"** (Boot Custom
FirmWare) — plus a set of fastboot-menu tools onto the stock Qualcomm ABL:

1. **Boot-mode selection.** Default boot target is Linux (persisted in DevInfo);
   holding Volume-Up forces Android. On Linux, Android cmdline data is not
   populated (commit 19).
2. **`BootCFW` dispatcher.** Boots Linux by first trying an Android-style
   boot-image container (`BootImg`), then falling back to the EFI System
   Partition (`BootESP` → `LoadBootAA64AndStart` → `bootaa64.efi`/GRUB).
   Supports ROCKNIX, Batocera and Knulli layouts; explicitly refuses REGLINUX.
3. **Device-model selection.** For multi-model SoC families the fastboot menu
   scans the appended DTB payload (`ModelSelectionMenuShowScreen`), lists model
   names parsed from DTB, and applies a model override used to pick the DT.
4. **System Stats** fastboot screen: SoC name (from ChipInfo → `GetSocName`),
   RAM, internal storage, SD-card size.
5. **NUKE / UNINSTALL ROCKNIX** fastboot tools: erase the internal ROCKNIX
   partition (recover SD boot), or uninstall and expand Android `userdata`.
6. **Auto-update** of the ABL itself, versioned by `RocknixAblVer`.
7. **`VerifyClusterSize`**: refuses to boot a FAT ESP whose cluster size is not
   16 KB (16384), showing an `INVALID CLUSTER SIZE` screen.
8. **REGLINUX exclusion** (`IsPartitionValid`): a targeted boot-time block of the
   REGLINUX distribution, detected by GPT label `REGLINUX` **or** the marker file
   `\boot\reglinux.update`, ending in an `UNSUPPORTED` screen. Introduced with
   explanatory strings in commit `097e3bb2`; the strings were stripped in
   `41156820` but the mechanism persists in every shipped build. Full writeup in
   [`REGLINUX_BLOCK.md`](REGLINUX_BLOCK.md).

Reconstructed C for these is under
[`reconstructed/QcomModulePkg/Application/LinuxLoader/`](reconstructed/).

---

## 5. Reconstruction confidence

| function / unit                        | confidence | basis                                                          |
|----------------------------------------|------------|---------------------------------------------------------------|
| `GetSocName` (chip-ID → name table)    | **exact**  | full disassembly; every switch case + string resolved         |
| `VerifyClusterSize` control flow       | high       | full disassembly; BPB read + 16 KB check + error menu         |
| `BootCFW` dispatcher control flow      | high       | full disassembly; DEBUG strings pin each branch               |
| `BootImg` / `BootESP` bodies            | medium     | full disassembly; control flow + magic/paths/strings verified |
| `IsPartitionValid` (REGLINUX gate)      | high       | full disassembly; both fingerprints + UNSUPPORTED path        |
| `RocknixAblVer` read/write              | medium     | full disassembly; tag build + DevInfo r/w + strings verified  |
| menus (SystemStats/Nuke/Uninstall/Model)| medium    | string map + partial disassembly; UI layout inferred          |
| everything else (stock ABL/EDK2)       | n/a        | unmodified upstream — see §3 for how to obtain the exact base  |

See [`METHODOLOGY.md`](METHODOLOGY.md) for how to complete and *byte-verify* a
full 1:1 rebuild using the identified upstream base and the `DEBUG_CLANG35`
toolchain, on a host that has the binary and network access.
