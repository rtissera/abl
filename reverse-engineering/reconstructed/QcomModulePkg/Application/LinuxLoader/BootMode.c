/** @file BootMode.c
  ROCKNIX persistent boot-mode / dev-mode / device-model state (DevInfo-backed).

  Reconstructed from the shipped ROCKNIX ABL (final SM8250/SM8550 build). The ABL
  keeps a small amount of persistent state in Qualcomm DevInfo:
    * Android-vs-Linux boot mode  (default Linux; Vol-Up forces Android)
    * developer "ABL mode" toggle
    * selected device model
  This file reconstructs the DevInfo setter family; all three share one pattern:
  read the current byte, no-op if unchanged, else update the DevInfo field and
  write it back, logging "Error %a <thing>" (Enabling/Disabling) on failure.

  Verification anchors (final SM8250 PE):
    SetAndroidBootMode          .text 0x3cd54
      cached flag global        .data 0x90578 (+0x578)  ; last-written value
      DevInfo boot-mode field   DevInfo[+0xd08]
      WriteDevInfo              .text 0x2d044 (flag 1)
      "Enabling" / "Disabling"  .data 0x6b041 / 0x6b04a
      "Error %a Android boot mode: %r"  .data 0x6b3f4
    twin messages:  "Error %a dev mode: %r"          .data 0x6b414
                    "...e to Write Device Model: %r" .data 0x6b430
  Confidence: medium (control flow + strings + field offsets verified; DevInfo
  struct layout inferred).

  NOTE — the boot-mode *decision* (default = Linux, persisted default set in
  commit d2f5bc6; Volume-Up held at boot forces Android, per README) is a
  separate, larger routine; its location is on the dev-box worklist
  (FULL_REBUILD.md §3). Commit 204f927 additionally gates Android cmdline
  population on the resolved mode.
**/

#include "BootCFW.h"

//
// Minimal view of the Qualcomm DevInfo block. Only the fields ROCKNIX toggles
// are named; the real struct lives in QcomModulePkg BootLib.
//
#define DEVINFO_SIZE            0xd50
typedef struct {
  UINT8   Reserved0[0xd08];
  UINT8   AndroidBootMode;   // +0xd08  0 = Linux (default), 1 = Android
  UINT8   DevMode;           // +0xd09  developer/ABL-mode toggle
  // ... device-model and remaining DevInfo fields follow
} ROCKNIX_DEVINFO;

extern ROCKNIX_DEVINFO gDevInfo;      // DevInfo working copy (.data 0x8f870+0xd08 region)
extern UINT8           gAndroidBootModeCache;  // .data 0x90578 (last written value)

EFI_STATUS DeviceInfo (UINTN Flag, VOID *Buffer, UINTN Size);  // .text 0x2d044

/**
  Persist the Android boot-mode flag (0 = Linux, 1 = Android). No-op if already
  at the requested value. Returns EFI_SUCCESS (or the write error).
**/
EFI_STATUS
EFIAPI
SetAndroidBootMode (
  IN BOOLEAN  Enable
  )
{
  EFI_STATUS  Status;

  if (gAndroidBootModeCache == (UINT8)Enable) {
    return EFI_SUCCESS;                       // unchanged
  }

  gDevInfo.AndroidBootMode = (UINT8)Enable;
  Status = DeviceInfo (1 /*write*/, &gDevInfo, DEVINFO_SIZE);
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "Error %a Android boot mode: %r\n",
            Enable ? "Enabling" : "Disabling", Status));
  }
  return Status;
}

//
// The developer "ABL mode" toggle (commit 931f890) and the device-model setter
// (commit 08511d0) are the same pattern with the "Error %a dev mode: %r" and
// "...Write Device Model: %r" messages respectively; reconstruct alongside once
// their DevInfo field offsets are confirmed against the base struct.
//
