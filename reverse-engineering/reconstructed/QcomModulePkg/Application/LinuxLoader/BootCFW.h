/** @file BootCFW.h
  ROCKNIX custom-firmware boot extensions for the Qualcomm LinuxLoader ABL.

  Reconstructed from the shipped ROCKNIX signed ABL blobs (AArch64 PE32+,
  DEBUG_CLANG35 build). Declarations for the ROCKNIX delta over the stock
  QcomModulePkg/Application/LinuxLoader base. See ../../../../ANALYSIS.md.

  The EDK2/Qualcomm base is BSD-2-Clause-Patent; this file documents the
  ROCKNIX-authored additions in rebuildable form.
**/

#ifndef __ROCKNIX_BOOTCFW_H__
#define __ROCKNIX_BOOTCFW_H__

#include <Uefi.h>
#include <Library/DebugLib.h>

//
// EFI_CHIPINFO_PROTOCOL soc_id values observed in the ROCKNIX ABL chip-name
// table (see GetSocName()). Values are the raw ChipId returned by
// EFI_CHIPINFO_PROTOCOL.GetChipId().
//
#define SOC_ID_SM8250          0x164   // Snapdragon 865 (SM8250)
#define SOC_ID_SM6115          0x1BC   // Snapdragon 662 (SM6115)
#define SOC_ID_SG8275          0x259   // Snapdragon G3x Gen 2
#define SOC_ID_SM8550          0x25B   // Snapdragon 8 Gen 2 (SM8550)
#define SOC_ID_SG3_GEN3        0x2AA   // Snapdragon G3 Gen 3
#define SOC_ID_SM8650_ELITE    0x2C2   // Snapdragon 8 Elite Gen 1

//
// FAT cluster size the ROCKNIX ESP must use (bytes). VerifyClusterSize() refuses
// to boot an ESP whose cluster size differs.
//
#define ROCKNIX_ESP_CLUSTER_SIZE   16384   // 16 KB

//
// Format an SoC display name for the runtime chip into Buf.
// Reconstructed 1:1 from disassembly (see BootCFW.c).
//
VOID
EFIAPI
GetSocName (
  OUT CHAR8   *Buf,
  IN  UINTN    BufSize
  );

//
// Verify the active ESP FAT volume uses a 16 KB cluster size; shows the
// "INVALID CLUSTER SIZE" screen and returns FALSE on mismatch.
//
BOOLEAN
EFIAPI
VerifyClusterSize (
  VOID
  );

//
// ROCKNIX Linux boot dispatcher: try the boot-image container, then fall back
// to booting from the EFI System Partition.
//
EFI_STATUS
EFIAPI
BootCFW (
  VOID
  );

EFI_STATUS EFIAPI BootImg (VOID);   // Android-style boot image container path
EFI_STATUS EFIAPI BootESP (VOID);   // EFI System Partition (bootaa64.efi / GRUB)

//
// ROCKNIX ABL self-version stamp / auto-update (RocknixAblVer.c).
//
EFI_STATUS EFIAPI SetRocknixAblVer (VOID);    // stamp "ROCKNIX-ABL-<ver>" to DevInfo
BOOLEAN    EFIAPI CheckRocknixAblVer (VOID);  // TRUE if stored tag matches running ABL

//
// Partition-validation gate incl. the REGLINUX exclusion (PartitionValidation.c).
//
BOOLEAN    EFIAPI IsPartitionValid (IN EFI_HANDLE Handle);

//
// Persistent boot-mode state + the boot-mode decision (BootMode.c).
//
EFI_STATUS EFIAPI SetAndroidBootMode (IN BOOLEAN Enable);
BOOLEAN    EFIAPI GetAndroidBootMode (VOID);
VOID       EFIAPI LinuxLoaderBootDecision (VOID);  // default Linux; Vol-Up -> Android

#endif // __ROCKNIX_BOOTCFW_H__
