/** @file PartitionValidation.c
  ROCKNIX partition-validation gate, including the REGLINUX exclusion.

  Reconstructed from the shipped ROCKNIX ABL (final SM8250/SM8550 build,
  function @ .text ~0x42fe0). This is the code that decides whether a candidate
  boot partition/volume is allowed to boot. It contains a targeted exclusion of
  the **REGLINUX** distribution, detected by two independent fingerprints:

    1. the partition's GPT label equals  L"REGLINUX"                (.data 0x71f36)
    2. the volume contains the marker file L"\\boot\\reglinux.update" (.data 0x71f48)

  Either fingerprint causes the "UNSUPPORTED" screen to be shown and the
  partition to be rejected (return FALSE), so the OS will not boot.

  History (see ../../../../ANALYSIS.md §4 and REGLINUX_BLOCK.md):
    * commit 097e3bb2 added an explicit, logged version ("IsPartitionValid:
      REGLINUX partition detected." + a DEBUG banner: "REGLINUX is not supported
      because it relies on closed-source components ...") with a partition-name
      whitelist {ROCKNIX, KNULLI, BATOCERA}.
    * commit 41156820 ("remove ... white list") removed the DEBUG strings but
      NOT the mechanism: the final build still blocks REGLINUX by partition name
      and additionally by the \boot\reglinux.update marker file.

  Verification anchors (final SM8250 PE):
    file-system protocol open   .text 0x42fe0 (gEfiSimpleFileSystemProtocolGuid
                                               09576e93-6d3f-11d2-8e39-00a0c969723b @ .data 0x763c0)
    OpenVolume helper           .text 0x5997c        Close helper .text 0x59b84
    StrCmp(label,"REGLINUX")    .text 0x4304c  (ref .data 0x71f36)  cbz 0x43050
    Open("\boot\reglinux.update").text 0x43074  (ref .data 0x71f48, mode=1 read)
    reboot-prompt / UNSUPPORTED .text 0x3b200 / ShowMenuScreen 0x14c0 (title 0x7a4d4, 5)
**/

#include "BootCFW.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Protocol/SimpleFileSystem.h>

//
// Volume/partition descriptor as used by the ROCKNIX boot path. Only the GPT
// label at +0x24 (CHAR16[]) is consumed here; the rest is opaque to this gate.
//
typedef struct {
  UINT8   Reserved0[0x24];
  CHAR16  Label[36];        // +0x24  partition GPT label (NUL-terminated)
} ROCKNIX_VOLUME;

ROCKNIX_VOLUME *OpenVolumeInfo (EFI_HANDLE Handle);   // .text 0x5997c (NULL on failure)
VOID            CloseVolumeInfo (ROCKNIX_VOLUME *V);  // .text 0x59b84
BOOLEAN         ShowRebootPrompt (VOID);              // .text 0x3b200 (TRUE if handled)
VOID            ShowMenuScreen (CONST CHAR8 *Title, UINTN Count); // .text 0x14c0

//
// REGLINUX fingerprints (verbatim from the binary).
//
#define REGLINUX_PART_LABEL   L"REGLINUX"
#define REGLINUX_MARKER_FILE  L"\\boot\\reglinux.update"

/**
  Decide whether a candidate boot volume is permitted to boot.

  Returns FALSE (blocking boot, after showing the "UNSUPPORTED" screen) when the
  volume is identified as REGLINUX by either its partition label or the presence
  of the \boot\reglinux.update marker file. Returns TRUE otherwise.
**/
BOOLEAN
EFIAPI
IsPartitionValid (
  IN EFI_HANDLE  Handle
  )
{
  EFI_STATUS                        Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_PROTOCOL                *Root;
  EFI_FILE_PROTOCOL                *File;
  ROCKNIX_VOLUME                   *Vol;
  BOOLEAN                           Valid;

  Status = gBS->HandleProtocol (Handle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (Status == EFI_UNSUPPORTED) {         // no filesystem here -> nothing to validate
    return TRUE;
  }

  Vol = OpenVolumeInfo (Handle);
  if (Vol == NULL) {
    return TRUE;
  }

  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) {
    CloseVolumeInfo (Vol);
    return TRUE;
  }

  Valid = TRUE;

  //
  // Fingerprint 1: GPT label == "REGLINUX".
  // Fingerprint 2: presence of the \boot\reglinux.update marker file.
  //
  if (StrCmp (Vol->Label, REGLINUX_PART_LABEL) == 0) {
    Valid = FALSE;
  } else {
    Status = Root->Open (Root, &File, REGLINUX_MARKER_FILE, EFI_FILE_MODE_READ, 0);
    if (!EFI_ERROR (Status)) {
      File->Close (File);
      Valid = FALSE;
    }
  }

  if (!Valid) {
    if (!ShowRebootPrompt ()) {
      ShowMenuScreen ("UNSUPPORTED", 5);   // REGLINUX excluded -> refuse to boot
    }
  }

  Root->Close (Root);
  CloseVolumeInfo (Vol);
  return Valid;
}

//
// NOTE — the boot path only starts the OS from ROCKNIX-blessed locations:
//   L"\\EFI\\ROCKNIX\\BOOTAA64.EFI"  (.data 0x71f9c)
//   L"\\EFI\\BOOT\\BOOTAA64.EFI"     (.data 0x71fd0)
//   L"\\boot\\Image"                 (.data 0x71f84)
//   L"\\KERNEL"                      (.data 0x71f74)
// and partition selection keys off L"ROCKNIX" / L"STORAGE" / L"userdata".
// The earlier (097e3bb2) form additionally whitelisted L"ROCKNIX", L"KNULLI",
// L"BATOCERA" partition labels explicitly.
//
