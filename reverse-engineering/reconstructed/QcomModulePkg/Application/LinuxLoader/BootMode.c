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

//
// ============================================================================
//  The boot-mode DECISION (1:1) - the core ROCKNIX default-Linux / Vol-Up-Android
//  logic, inlined in the LinuxLoader entry. Reconstructed exactly from the
//  shipped final SM8250/SM8550 build, .text 0x2144..0x218c.
// ============================================================================
//
// Trivial DevInfo getters (each is `ldrb w0,[global]; ret`), verified:
//   GetAndroidBootMode()  .text 0x3b1bc  -> byte 0x90578 (DevInfo[+0xd08])
//
// Key scan codes (Qualcomm key-press enum; values verified from the compares):
//   1 = Volume-Up  (README: "Hold Volume Up during boot to force Android")
//   5 = secondary force-Android key/combo
//
// Global flags read here (verified offsets):
//   gDevInfo state byte 0x7fd58  -> Fastboot requested (checked first)
//
// Disassembly (canonical):
//   0x2144  ldrb w8,[Fastboot]; tbnz w8,#0 -> Fastboot            (0x2618)
//   0x214c  ZeroMem(&BootInfo, 0x468)
//   0x215c  GetBootModeInfo(&Info)          ; fills the force-Android flag [sp+8]
//   0x2164  if (GetAndroidBootMode())       -> Android            (0x234c)
//   0x2170  if (ForceAndroid  [sp+8])       -> Android
//   0x2178  if (KeyPress == 1)              -> Android            ; Volume-Up
//   0x2184  if (KeyPress == 5)              -> Android
//   0x218c  BootCFW()                       ; DEFAULT = Linux     (0x43254)
//   0x2190  ShowRebootPrompt()              ; only if BootCFW returned (failed)
//
// KeyPress is the key read earlier in the entry (logged as "KeyPress:%u,
// BootReason:%u" @ .text 0x2054, stored at [sp+0x18]); the force flag comes from
// GetBootModeInfo. Modelled together below for clarity; the decision predicate
// is exact.
//

#define KEY_VOLUME_UP     1
#define KEY_FORCE_ANDROID 5

BOOLEAN    EFIAPI GetAndroidBootMode (VOID);   // .text 0x3b1bc (DevInfo[+0xd08])
VOID       GetBootModeInfo (OUT VOID *Info);   // .text 0x2e300 (KeyPress + force flag)
BOOLEAN    IsFastbootRequested (VOID);         // DevInfo Fastboot state 0x7fd58
VOID       EnterFastboot (VOID);               // 0x2618
EFI_STATUS BootAndroid (VOID);                 // 0x234c (LoadImageAndAuth + BootLinux)
BOOLEAN    ShowRebootPrompt (VOID);            // 0x3b200

typedef struct {
  UINT8   Reserved[0x10];
  UINT8   ForceAndroid;   // set by GetBootModeInfo (misc/force-normal-boot etc.)
  UINT8   Pad[0x0f];
  UINT32  KeyPress;       // +0x18 relative to the on-stack info block
} ROCKNIX_BOOTMODE_INFO;

/**
  Resolve and execute the boot target. Boots Android when the mode is explicitly
  Android, when a force flag is set, or when Volume-Up (or the secondary force
  key) is held at boot; otherwise boots Linux via BootCFW (the ROCKNIX default).
  Only returns if every boot path failed.
**/
VOID
EFIAPI
LinuxLoaderBootDecision (
  VOID
  )
{
  ROCKNIX_BOOTMODE_INFO  Info;

  //
  // Fastboot takes precedence over the OS decision.
  //
  if (IsFastbootRequested ()) {
    EnterFastboot ();
    return;
  }

  ZeroMem (&Info, sizeof (Info));      // .text 0x214c  (0x468-byte boot-info block)
  GetBootModeInfo (&Info);             // .text 0x215c/0x2160

  //
  // Boot Android if: persisted mode is Android, OR a force flag is set,
  // OR Volume-Up (1) / the secondary force key (5) is held at boot.
  //
  if (GetAndroidBootMode () ||
      Info.ForceAndroid ||
      Info.KeyPress == KEY_VOLUME_UP ||
      Info.KeyPress == KEY_FORCE_ANDROID) {
    BootAndroid ();                    // .text 0x234c
    return;
  }

  //
  // Default: boot Linux (ROCKNIX / Batocera / Knulli) via the custom-firmware
  // path. BootCFW only returns on total failure, after which the reboot prompt
  // / "LINUX NOT FOUND" screen is shown.
  //
  BootCFW ();                          // .text 0x43254  (DEFAULT)
  ShowRebootPrompt ();                 // .text 0x3b200
}
