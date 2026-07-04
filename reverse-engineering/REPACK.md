# Repacking the reconstructed C into a flashable ABL

This documents the tooling that turns the reconstructed source back into a
signed, flashable `abl_signed-<SoC>.elf` — and, crucially, what is **verified**
versus what needs a full build host or the target device.

```
 reconstructed C  ──build_abl.sh──▶  LinuxLoader.efi (AArch64 PE32+)
                                          │
                                          ▼  fvpack.py pack
                     outer UEFI FV (.fd)  =  FFS2 ▸ FV_IMAGE file ▸ LZMA ▸ inner FV ▸ LinuxLoader
                                          │
                                          ▼  mkabl.py  /  qtestsign   (sign)
                     abl_signed-<SoC>.elf  =  ELF32 ▸ MBN hash-table segment (SHA-384) ▸ FV payload
                                          │
                                          ▼  update.sh  /  dd
                              abl_a / abl_b partitions
```

## The signing situation (why this is reproducible at all)

The shipped ROCKNIX blobs are signed, but the leaf certificate in every blob's
MBN cert chain reads:

```
subject = CN = qtestsign Attestation CA - NOT SECURE
issuer  = CN = qtestsign Root CA - NOT SECURE
```

They are signed with **[qtestsign](https://github.com/msm8916-mainline/qtestsign)**
— an open-source tool using **public test keys**, not a secret OEM key. That is
only accepted by devices whose secure boot is **not fused / unlocked**, which is
the case for the emulation handhelds this ABL targets. The practical consequence:
**you can re-sign a rebuilt ABL yourself with public keys** and it will be
accepted, exactly like the originals. No OEM secret is involved anywhere in the
chain.

> If a device *does* have secure boot fused to a real OEM key, no third party
> (including this tooling) can produce an image it will accept — that is the
> whole point of fusing. This tooling targets the unlocked devices ROCKNIX
> itself ships for.

## Tools

| tool | what it does | status |
|------|--------------|--------|
| `fvpack.py`  | pack/unpack the outer UEFI FV (FFS2 ▸ FV_IMAGE ▸ LZMA ▸ inner FV ▸ LinuxLoader). Zero-dependency (pure-python `lzma`). | **verified** |
| `mkabl.py`   | wrap an FV payload in the Qualcomm ELF + MBN hash-table segment (SHA-384 measurements), and sign (openssl / preserve). | **verified** |
| `build_abl.sh` | overlay the reconstructed delta on the EDK2/Qualcomm base and build `LinuxLoader.efi` (`CLANG35`/`AARCH64`/`DEBUG`). | needs base tree + toolchain |
| `repack.sh`  | orchestrates `fvpack` + sign into `abl_signed-<SoC>.elf` (+ `.sha256`). | driver |
| `roundtrip_test.sh` | the proof harness (below). | **verified** |

## What is verified in this repo (run `tools/roundtrip_test.sh`)

```
== 1) mkabl byte-exact round-trip (all SoCs) ==
   SM6115  byte-identical
   SM8250  byte-identical
   SM8550  byte-identical
   SM8650  byte-identical
== 2) fvpack unpack->rebuild, strict parser descends rebuilt FV ==
   strict parser reaches LinuxLoader in rebuilt FV: YES
== 3) end-to-end: PE -> fvpack -> mkabl(sign) -> re-extract ==
   PE survives full build+sign+extract cycle: YES
ALL CHECKS PASSED
```

Meaning:

1. **`mkabl.py` reproduces every shipped signed ABL byte-for-byte** from its own
   payload — proving the ELF layout, the MBN hash-table geometry, and the
   SHA-384 per-segment measurement are all exactly right. (The hash-table offset,
   signature size and cert size are derived from the per-SoC template, so it
   works across the `0x898`- and `0x910`-sized segment variants.)
2. **`fvpack.py` rebuilds a fresh outer FV** around a (re)built `LinuxLoader.efi`
   that a *strict independent* parser (`uefi_firmware`) walks all the way down to
   the `LinuxLoader` application. Getting there required matching EDK2 exactly:
   the LZMA guided section decompresses to a **section stream**
   (`RAW` pad + `EFI_SECTION_FIRMWARE_VOLUME_IMAGE`), the LZMA-alone header must
   carry the real **uncompressed size** (EDK2's decompressor rejects the
   "unknown size" sentinel), and the `ee4e5898` LZMA GUID / FV attributes must
   match.
3. **The full cycle** PE → `fvpack` → `mkabl` sign → re-extract returns the
   identical PE.

## What still requires a full host / the device

* **`build_abl.sh`** needs the EDK2 + `QcomModulePkg` base tree and the
  `CLANG35`/`AARCH64` toolchain (see `METHODOLOGY.md` §B). This environment has
  neither, so the C→`.efi` step is scripted and documented but not executed here.
* **On-device boot** is the final proof and is yours to run: flash to a spare
  slot and confirm. `fvpack` output is validated structurally against a strict
  parser and byte-matched to the shipped FFS/section headers, but only the device
  FV loader is authoritative.

## End-to-end usage

```bash
# 1. build LinuxLoader.efi from reconstructed source (on a build host)
BASE=/path/to/LinuxLoader  tools/build_abl.sh

# 2. pack + sign into a flashable ABL (qtestsign = exact ROCKNIX scheme)
QTESTSIGN=/path/to/qtestsign \
  tools/repack.sh <BUILD>/LinuxLoader.efi SM8250 abl_signed-SM8250.elf --qtestsign
# ...or self-sign with an RSA-2048 key (unlocked devices):
tools/repack.sh <BUILD>/LinuxLoader.efi SM8250 abl_signed-SM8250.elf --key key.pem

# 3. flash (uses the repo's own updater, which verifies the .sha256 first)
./update.sh            # or dd to /dev/disk/by-partlabel/abl_a and abl_b
```

## Fast path: repack without rebuilding (swap the PE)

To inject a modified `LinuxLoader.efi` into a known-good FV and re-sign — no full
EDK2 build — use `fvpack.py` directly:

```bash
python3 tools/extract_pe.py blobs/abl_signed-SM8250.elf > stock.pe   # or your rebuilt PE
python3 tools/fvpack.py pack  my_LinuxLoader.efi payload.fd
python3 tools/mkabl.py payload.fd blobs/abl_signed-SM8250.elf abl_signed-SM8250.elf --key key.pem
```
