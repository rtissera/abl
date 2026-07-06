/** @file BootCFW.c
  ROCKNIX "BootCFW" custom-firmware Linux boot path + ESP cluster validation.

  Reconstructed from the shipped ROCKNIX ABL (AArch64 PE32+, DEBUG_CLANG35).
  Control flow and every log string match the binary; helper prototypes into
  the stock QcomModulePkg base are inferred (medium/high confidence — see
  ANALYSIS.md §5). The many `DEBUG(())` statements below correspond 1:1 to the
  inlined EDK2 DebugLib guard sequences observed in .text
  (DebugPrintLevelEnabled -> DebugAssertEnabled -> DebugPrint), so they are
  restored to their source form here.

  Verification anchors (SM8250 LinuxLoader PE):
    BootCFW dispatcher      .text 0x43560..0x43690, 0x43c7c
    "using image file"      .data 0x6d6c8   (DEBUG_INFO)
    "using ESP"             .data 0x6d73d   (DEBUG_INFO,  ref 0x43620)
    "BootImg returned…"     .data 0x6d6f4   (DEBUG_ERROR, ref 0x435bc)
    "BootESP returned…"     .data 0x6d762   (DEBUG_ERROR, ref 0x43c7c)
    VerifyClusterSize       .text 0x43140..0x4324c
    cluster compare         0x43188  ldr w8,[x19,#0x20]; cmp w8,#0x4000 (16384)
    "Invalid cluster size"  .data 0x6d78f   (DEBUG_ERROR, ref 0x431ec)
    "INVALID CLUSTER SIZE"  .data 0x7aa4c   (screen title, ref 0x43214, count 6)
**/

#include "BootCFW.h"
#include <Library/UefiBootServicesTableLib.h>

//
// --- Prototypes into the stock ABL / ROCKNIX helpers (inferred) -------------
//
// FAT BPB info block populated by the ESP FAT reader. Only BytesPerCluster at
// +0x20 is consumed by VerifyClusterSize.
//
typedef struct {
  UINT8   Reserved0[0x20];
  UINT32  BytesPerCluster;   // +0x20
} ROCKNIX_FAT_INFO;

ROCKNIX_FAT_INFO *OpenEspFatInfo (VOID);           // .text 0x5997c (returns NULL on fail)
VOID              CloseEspFatInfo (ROCKNIX_FAT_INFO *Info); // .text 0x59b84
BOOLEAN           ShowInvalidClusterScreen (VOID); // .text 0x3b200 (TRUE = user chose reboot)
VOID              ShowMenuScreen (CONST CHAR8 *Title, UINTN Count); // .text 0x14c0

/**
  Verify the active ESP FAT volume uses a 16 KB cluster size.

  Reads the FAT BPB info for the boot ESP and compares BytesPerCluster to
  16384. On mismatch it logs and shows the "INVALID CLUSTER SIZE" screen
  instructing the user to reformat with a 16 KB cluster size.

  Added in commit 08511d0 ("verify cluster size before attempting to boot").
**/
BOOLEAN
EFIAPI
VerifyClusterSize (
  VOID
  )
{
  ROCKNIX_FAT_INFO  *Info;

  Info = OpenEspFatInfo ();
  if (Info == NULL) {
    return FALSE;
  }

  if (Info->BytesPerCluster == ROCKNIX_ESP_CLUSTER_SIZE) {   // == 16384
    CloseEspFatInfo (Info);
    return TRUE;
  }

  DEBUG ((EFI_D_ERROR,
    "VerifyClusterSize: Invalid cluster size. Expected 16384 (16KB).\n"));

  if (!ShowInvalidClusterScreen ()) {
    // User acknowledged; render the fatal "INVALID CLUSTER SIZE" screen.
    ShowMenuScreen ("INVALID CLUSTER SIZE", 6);
  }

  CloseEspFatInfo (Info);
  return FALSE;
}

//
// --- BootCFW dispatcher -----------------------------------------------------
//
// ROCKNIX boots Linux by first attempting the Android-style boot-image
// container (BootImg), then falling back to the EFI System Partition (BootESP,
// which calls LoadBootAA64AndStart -> bootaa64.efi / GRUB). Both helpers only
// return on failure. Added/finalised in commit 91c0ba8 ("Android boot image
// container") and e4e0564 ("Batocera boot image path").
//
// Reconstructed from the dispatcher at .text 0x43560; the two DEBUG_INFO
// "Booting to Linux using …" banners and the two DEBUG_ERROR "… returned
// unexpectedly" logs bracket each fallback stage.
//

/**
  Boot ROCKNIX/Batocera/Knulli Linux: boot-image container first, ESP fallback.
  Returns only on failure of both paths.
**/
EFI_STATUS
EFIAPI
BootCFW (
  VOID
  )
{
  EFI_STATUS  Status;

  //
  // Stage 1: Android-style boot-image container.
  //
  DEBUG ((EFI_D_INFO, "BootCFW: Booting to Linux using image file\n"));
  Status = BootImg ();
  DEBUG ((EFI_D_ERROR,
    "BootCFW: BootImg returned unexpectedly (%r), fallback to boot using ESP\n",
    Status));

  //
  // Stage 2: EFI System Partition (bootaa64.efi / GRUB).
  //
  DEBUG ((EFI_D_INFO, "BootCFW: Booting to Linux using ESP\n"));
  Status = BootESP ();
  DEBUG ((EFI_D_ERROR, "BootCFW: BootESP returned unexpectedly (%r)\n", Status));

  return Status;
}

//
// --- BootImg: Android-style boot-image container path ----------------------
//
// Reads a boot image (from the kernel/image paths \KERNEL, \boot\Image), checks
// the "ANDROID!"/"ANDROID-BOOT!" magic and header, validates size, then
// LoadImageAndAuth + BootLinux. Reconstructed from .text ~0x43310..0x44200;
// control flow and strings verified, header/loader helper prototypes inferred
// (medium confidence). Added in commit 91c0ba8.
//
#define BOOT_MAGIC      "ANDROID!"       // .data 0x65733
#define BOOT_MAGIC_SIZE 8

EFI_STATUS ReadBootImageHeader (VOID *Vol, VOID *Hdr, UINTN Size); // .text 0x56428
EFI_STATUS LoadImageAndAuth (VOID *Info);                          // authenticate+load
EFI_STATUS BootLinux (VOID *Info);                                 // hand off to kernel

EFI_STATUS
EFIAPI
BootImg (
  VOID
  )
{
  EFI_STATUS  Status;
  UINT8       Header[BOOT_MAGIC_SIZE];
  VOID       *Vol = NULL;    // current boot volume/handle

  Status = ReadBootImageHeader (Vol, Header, sizeof (Header));
  if (EFI_ERROR (Status) ||
      CompareMem (Header, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0) {
    DEBUG ((EFI_D_ERROR, "BootImg: Invalid boot image magic\n"));
    return EFI_NOT_FOUND;
  }
  DEBUG ((EFI_D_INFO, "BootImg: Valid boot image header found\n"));

  DEBUG ((EFI_D_INFO, "BootImg: Calling LoadImageAndAuth...\n"));
  Status = LoadImageAndAuth (Vol);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "BootImg: Failed to load/authenticate boot image: %r\n", Status));
    return Status;
  }

  DEBUG ((EFI_D_INFO, "BootImg: Starting BootLinux...\n"));
  Status = BootLinux (Vol);
  DEBUG ((EFI_D_ERROR, "BootImg: BootLinux returned unexpectedly\n"));
  return Status;
}

//
// --- BootESP: EFI System Partition path (bootaa64.efi / GRUB) ---------------
//
// Loads and starts \EFI\ROCKNIX\BOOTAA64.EFI (then \EFI\BOOT\BOOTAA64.EFI) from
// the ESP. Reconstructed from .text ~0x43ae0..0x43c1c. Added in commit 894f0fc /
// finalized 91c0ba8.
//
EFI_STATUS LoadBootAA64AndStart (CONST CHAR16 *Path);   // load+StartImage a PE app

EFI_STATUS
EFIAPI
BootESP (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = LoadBootAA64AndStart (L"\\EFI\\ROCKNIX\\BOOTAA64.EFI");   // .data 0x71f9c
  if (EFI_ERROR (Status)) {
    Status = LoadBootAA64AndStart (L"\\EFI\\BOOT\\BOOTAA64.EFI");    // .data 0x71fd0
  }
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "BootESP: LoadBootAA64AndStart failed: %r\n", Status));
  }
  return Status;
}
