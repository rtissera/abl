/** @file SystemStats.c
  ROCKNIX fastboot "System Stats" support — SoC name lookup.

  GetSocName() is reconstructed **1:1** from the shipped ROCKNIX ABL
  (function @ .text RVA 0x450e8 in the SM8250/SM8550 build). Every switch case
  and every string was resolved from the binary; see ANALYSIS.md §5.

  Verification anchors (SM8250 LinuxLoader PE):
    * function prologue        .text 0x450e8  (sub sp,#0x40; frame 0x40)
    * LocateProtocol call via gBS[.140]       -> gEfiChipInfoProtocolGuid
    * GetChipId call via ChipInfo->[0x18]     -> UINT32 soc_id (w3)
    * dispatch                 0x45140..0x45204
    * AsciiSPrint helper       .text 0x58520
    * strings                  .data 0x6dbcb / 0x6dc04 .. 0x6dc79 / 0x6dbd7
**/

#include "BootCFW.h"
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>

//
// EFI_CHIPINFO_PROTOCOL (Qualcomm). Only the two vtable slots the ROCKNIX code
// touches are modelled here; the real protocol lives in QcomModulePkg.
//   +0x18  GetChipId (ChipId out)   (per the observed ChipInfo->[0x18] call)
//
typedef struct _EFI_CHIPINFO_PROTOCOL EFI_CHIPINFO_PROTOCOL;
struct _EFI_CHIPINFO_PROTOCOL {
  UINT64      Revision;                                             // +0x00
  EFI_STATUS (EFIAPI *GetChipId)(EFI_CHIPINFO_PROTOCOL *This, UINT32 *ChipId); // +0x18
  // ... remaining ChipInfo members omitted (unused by GetSocName)
};

extern EFI_GUID gEfiChipInfoProtocolGuid;

/**
  Format the human-readable SoC name for the running chip into Buf.

  Exact reconstruction of the shipped GetSocName(): dispatch order, case
  values and output strings all match the binary. On any protocol failure the
  string "Unknown SoC" is emitted; an unrecognised soc_id yields "undefined %d".
**/
VOID
EFIAPI
GetSocName (
  OUT CHAR8   *Buf,
  IN  UINTN    BufSize
  )
{
  EFI_STATUS               Status;
  EFI_CHIPINFO_PROTOCOL   *ChipInfo;
  UINT32                   SocId;
  CONST CHAR8             *Name;

  Status = gBS->LocateProtocol (&gEfiChipInfoProtocolGuid, NULL, (VOID **)&ChipInfo);
  if (EFI_ERROR (Status)) {
    AsciiSPrint (Buf, BufSize, "Unknown SoC");     // .data 0x6dbcb
    return;
  }

  ChipInfo->GetChipId (ChipInfo, &SocId);

  switch (SocId) {
    case SOC_ID_SM8250:       Name = "Snapdragon 865 (SM8250)";     break; // 0x164
    case SOC_ID_SM6115:       Name = "Snapdragon 662 (SM6115)";     break; // 0x1BC
    case SOC_ID_SG8275:       Name = "Snapdragon G3x Gen 2";        break; // 0x259
    case SOC_ID_SM8550:       Name = "Snapdragon 8 Gen 2 (SM8550)"; break; // 0x25B
    case SOC_ID_SG3_GEN3:     Name = "Snapdragon G3 Gen 3";         break; // 0x2AA
    case SOC_ID_SM8650_ELITE: Name = "Snapdragon 8 Elite Gen 1";    break; // 0x2C2
    default:
      AsciiSPrint (Buf, BufSize, "undefined %d", SocId);            // .data 0x6dbd7
      return;
  }

  AsciiSPrint (Buf, BufSize, "%a", Name);                          // fmt .data 0x6e0b6
}

//
// NOTE — the surrounding "System Stats" fastboot screen (added in commit
// 6ae3d5e, refined by c1a410a/64fb3fc/1d6c948) renders, using the helper above:
//
//     SOC     - <GetSocName()>
//     RAM     - <RAM total, from GetRamPartitions>
//     STORAGE - <internal storage size> %d GB
//     SD CARD - <sd card size>          %d GB
//     - ROCKNIX <RocknixAblVer>
//
// The exact label table/order is captured in ANALYSIS.md §4; the layout code
// is medium-confidence and is left to the full-tree rebuild (METHODOLOGY.md).
//
