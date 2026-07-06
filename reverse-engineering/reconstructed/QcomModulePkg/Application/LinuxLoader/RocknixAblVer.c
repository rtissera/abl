/** @file RocknixAblVer.c
  ROCKNIX ABL self-version stamp / auto-update check.

  Reconstructed from the shipped ROCKNIX ABL (final SM8250/SM8550 build):
    * writer  @ .text 0x3ba60  (SetRocknixAblVer)   - stamps the version to DevInfo
    * reader  @ .text 0x3bc14  (CheckRocknixAblVer)  - compares stored vs current

  The ABL records its own version string "ROCKNIX-ABL-<ver>" in Qualcomm DevInfo
  so a later boot (and the OS updater) can tell whether the flashed ABL is
  current; on mismatch the reader logs "RocknixAblVer does not match or exist"
  and the auto-update path re-flashes/updates the ABL (added in commit ed836fe,
  "add support for auto-updating abl"). Confidence: medium (control flow + all
  strings verified; EDK2/DevInfo helper prototypes inferred).

  Verification anchors:
    "ROCKNIX-ABL"                       .data 0x6b126   (id prefix)
    "-"                                 .data 0x6975b   (separator)
    "1.0"                               .data 0x6b132   (fallback version)
    "Unable to Write Device Info: %r"   .data 0x6b136   (writer error)
    "RocknixAblVer does not match or exist" .data 0x6b182 (reader, ref 0x3bdc0)
    ReadDevInfo/WriteDevInfo            .text 0x2d044   (flag 0 = read, 1 = write)
    AsciiStrCpyS / AsciiStrCatS         .text 0x3aa8 / 0x4058
    AsciiStrCmp                         .text 0x49e8 / 0x57ec
**/

#include "BootCFW.h"
#include <Library/BaseLib.h>

#define ROCKNIX_ABL_ID        "ROCKNIX-ABL"
#define ROCKNIX_ABL_SEP       "-"
#define ROCKNIX_ABL_FALLBACK  "1.0"
#define DEVINFO_VER_MAX       0x40         // version-field capacity in DevInfo

// Qualcomm DevInfo access (QcomModulePkg). flag: 0 read, 1 write.
EFI_STATUS DeviceInfo (UINTN Flag, VOID *Buffer, UINTN Size);   // .text 0x2d044
CHAR8     *GetRocknixAblVersion (VOID);   // build-time version string (may be NULL)

/**
  Compose "ROCKNIX-ABL-<Version>" (or "ROCKNIX-ABL-1.0" when no version is set)
  into Out (capacity DEVINFO_VER_MAX).
**/
STATIC
VOID
BuildVersionTag (
  OUT CHAR8   *Out,
  IN  CHAR8   *Version
  )
{
  AsciiStrCpyS (Out, DEVINFO_VER_MAX, ROCKNIX_ABL_ID);
  AsciiStrCatS (Out, DEVINFO_VER_MAX, ROCKNIX_ABL_SEP);
  AsciiStrCatS (Out, DEVINFO_VER_MAX, Version ? Version : ROCKNIX_ABL_FALLBACK);
}

/**
  Persist the current ABL version tag into DevInfo. Logged on failure.
**/
EFI_STATUS
EFIAPI
SetRocknixAblVer (
  VOID
  )
{
  CHAR8       Tag[DEVINFO_VER_MAX];
  EFI_STATUS  Status;

  BuildVersionTag (Tag, GetRocknixAblVersion ());
  Status = DeviceInfo (1 /*write*/, Tag, sizeof (Tag));
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Unable to Write Device Info: %r\n", Status));
  }
  return Status;
}

/**
  Return TRUE if the version tag stored in DevInfo matches the running ABL.
  On mismatch (or absent), logs and returns FALSE so the caller can trigger the
  ABL auto-update path.
**/
BOOLEAN
EFIAPI
CheckRocknixAblVer (
  VOID
  )
{
  CHAR8       Tag[DEVINFO_VER_MAX];
  CHAR8       Stored[DEVINFO_VER_MAX];

  BuildVersionTag (Tag, GetRocknixAblVersion ());

  if (EFI_ERROR (DeviceInfo (0 /*read*/, Stored, sizeof (Stored))) ||
      AsciiStrCmp (Stored, Tag) != 0) {
    DEBUG ((EFI_D_ERROR, "RocknixAblVer does not match or exist\n"));
    return FALSE;
  }
  return TRUE;
}
