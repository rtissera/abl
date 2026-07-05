# The REGLINUX exclusion in the ROCKNIX ABL

This documents a targeted boot-time exclusion of the **REGLINUX** Linux
distribution built into the ROCKNIX ABL. It is included here as a factual
reverse-engineering finding: what the code does, where it lives, and how it
evolved. (The user who requested this analysis characterises the mechanism as
illegal; whether it is a legal violation is a legal question outside the scope
of this technical document — the facts below are stated neutrally.)

## Summary

When the ABL validates a candidate boot volume, it refuses to boot the volume if
it is identified as REGLINUX by **either** of two independent fingerprints:

| # | fingerprint | how | data (final SM8250) |
|---|-------------|-----|---------------------|
| 1 | partition GPT label `REGLINUX` | `StrCmp(label, L"REGLINUX")` | UTF-16 `\x71f36` |
| 2 | marker file `\boot\reglinux.update` present | `Root->Open(..., EFI_FILE_MODE_READ)` on the volume's filesystem | UTF-16 `\x71f48` |

Either match ⇒ the **"UNSUPPORTED"** screen is shown and the validator returns
*invalid*, so the OS does not boot. All other (non-REGLINUX) volumes pass.

The blessed OS entry points the ABL will actually boot are ROCKNIX-scoped:
`\EFI\ROCKNIX\BOOTAA64.EFI`, `\EFI\BOOT\BOOTAA64.EFI`, `\boot\Image`, `\KERNEL`.

## Where it is (final shipped build, SM8250/SM8550 payload)

* Validation function: `.text ~0x42fe0` (reconstructed as `IsPartitionValid`,
  see [`reconstructed/.../PartitionValidation.c`](reconstructed/QcomModulePkg/Application/LinuxLoader/PartitionValidation.c)).
* Filesystem access: `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`
  `09576e93-6d3f-11d2-8e39-00a0c969723b` (GUID at `.data 0x763c0`), then an
  `OpenVolume`/`Open` on the volume.
* Partition-label compare: `StrCmp` @ `.text 0x4304c`, referencing UTF-16
  `REGLINUX` at `.data 0x71f36` (`adrp/add` site `0x43040`).
* Marker-file open: `.text 0x43058–0x43074`, referencing UTF-16
  `\boot\reglinux.update` at `.data 0x71f48`.
* Rejection UI: `ShowRebootPrompt` (`.text 0x3b200`) then `ShowMenuScreen`
  (`.text 0x14c0`) with title `"UNSUPPORTED"` (`.data 0x7a4d4`).

Relevant `.data` neighbourhood (final build), verbatim:

```
0x71f36  REGLINUX
0x71f48  \boot\reglinux.update
0x71f74  \KERNEL
0x71f84  \boot\Image
0x71f9c  \EFI\ROCKNIX\BOOTAA64.EFI
0x71fd0  \EFI\BOOT\BOOTAA64.EFI
0x71ffe  ROCKNIX
0x72008  userdata
0x72020  STORAGE
```

## Control flow (disassembly, final build)

```
0x42fe0  open EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on the handle (GUID @0x763c0)
0x43014  OpenVolume  -> Root (x19)                         ; bl 0x5997c
0x43048  x0 = &Vol->Label (x19+0x24)
0x4304c  bl StrCmp(Label, L"REGLINUX")                     ; ref 0x71f36
0x43050  cbz x0, <blocked>          ; label == REGLINUX -> block
0x43054  Root->Open(&File, L"\boot\reglinux.update", READ) ; ref 0x71f48
0x43078  tbnz <open failed> -> valid (file absent)
         <blocked>:
0x4308c  bl ShowRebootPrompt                               ; 0x3b200
0x430b4  ShowMenuScreen("UNSUPPORTED", 5)                  ; 0x14c0, title 0x7a4d4
0x430c4  w20 = 0  (invalid -> boot refused)
0x430cc  Close(Root)
```

## Complete marker & file inventory

Every partition label and file path the ABL keys off (all UTF-16LE, embedded in
`.text` rodata; **present and identical in all four shipped SoC builds** —
SM6115/SM8250/SM8550/SM8650):

### REGLINUX detection (the exclusion)
| rva | string | role |
|-----|--------|------|
| `0x71f36` | `REGLINUX` | blocked GPT partition label (`StrCmp` @ `0x4304c`) |
| `0x71f48` | `\boot\reglinux.update` | blocked-if-present marker file (`Open` @ `0x43058`) |

### Boot-method file lists (what it *will* boot)
Two boot-method descriptors, each an ordered path list terminated by NULL and
followed by a 16-byte GUID, live in a table at `.text 0x74ce8` / `0x74d10`:

| rva | string | method |
|-----|--------|--------|
| `0x71f74` | `\KERNEL` | kernel/boot-image method (`BootImg`) |
| `0x71f84` | `\boot\Image` | kernel/boot-image method (`BootImg`) |
| `0x71f9c` | `\EFI\ROCKNIX\BOOTAA64.EFI` | ESP / GRUB method (`BootESP`) |
| `0x71fd0` | `\EFI\BOOT\BOOTAA64.EFI` | ESP / GRUB method (`BootESP`) |

So a volume boots only if it is **not** REGLINUX **and** exposes one of these
four files; the kernel paths feed `BootImg`, the `BOOTAA64.EFI` paths feed
`BootESP` (matching the `BootCFW` dispatch in `BootCFW.c`).

### Partition labels used for selection / logic
| rva | label | refs (code sites) |
|-----|-------|-------------------|
| `0x71ffe` | `ROCKNIX` | `0x4443c 0x44658 0x44ae8` |
| `0x72020` | `STORAGE` | `0x44444 0x44afc` |
| `0x7200e` | `userdata` | `0x44434 0x44ad4 0x44b98 0x52384` |
| `0x71c28` | `system` | `0x8558 0x3ef08 0x5435c` |
| `0x71c02` | `recovery` | `0x7964 0x7e3c 0x802c 0xac4c 0xaf30` |
| `0x71d0c` | `misc` | `0x2d254` |
| `0x720e8` | `frp` | `0x5009c` |
| `0x72198` | `metadata` | — |

The earlier `097e3bb2` form also carried an explicit label **whitelist**
`{ROCKNIX, KNULLI, BATOCERA}` (the counterpart to the REGLINUX blacklist); the
`KNULLI`/`BATOCERA` labels were dropped from `.text` when the whitelist code was
removed in `41156820`, while the REGLINUX blacklist stayed.

## Evolution (why "the strings were removed" is misleading)

Tracing the ~20 historical blob versions in this repo's git history
(`tools/diff_versions.sh SM8250`):

* **commit `097e3bb2`** ("fix forced Android factory reset") introduced an
  explicit, *logged* form inside `IsPartitionValid`:
  * `IsPartitionValid: REGLINUX partition detected.`
  * a DEBUG/screen banner: *"REGLINUX is not supported because it relies on
    closed-source components that are incompatible with Free and Open Source
    Software standards."*
  * plus a partition-label **whitelist** of `{ROCKNIX, KNULLI, BATOCERA}`.
* **commit `41156820`** ("Update ABL, remove battery stats and **white list**")
  removed those human-readable strings. This can look like the block was
  removed — it was not. The **final shipped build contains no REGLINUX log
  strings, but still contains the REGLINUX partition-name and
  `\boot\reglinux.update` checks and the `UNSUPPORTED` rejection** (verified: the
  UTF-16 `REGLINUX` string at `0x71f36` is referenced by code at `0x43040` in
  all shipped payloads; the explanatory ASCII strings are absent).

So across the history the *mechanism* persisted while its self-describing text
was stripped.

## Reproduce this finding

```bash
# it's still in every shipped payload:
python3 tools/extract_pe.py blobs/abl_signed-SM8250.elf > LinuxLoader.pe
python3 - <<'PY'
d=open('LinuxLoader.pe','rb').read()
for n in ['REGLINUX','\\boot\\reglinux.update','ROCKNIX']:
    print(n, 'utf16@', hex(d.find(n.encode('utf-16-le'))))
PY

# disassemble the gate:
python3 tools/disasm_fn.py LinuxLoader.pe 0x43040 0x42fe0 0x430d0

# and see when the log strings came/went:
tools/diff_versions.sh SM8250 | grep -i reglinux -A2 -B2
```
