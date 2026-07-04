#!/usr/bin/env python3
"""fvpack.py - (un)pack the ROCKNIX ABL outer Firmware Volume.

Structure (all standard EDK2, no keys involved):

  OUTER FV  (EFI_FIRMWARE_FILE_SYSTEM2_GUID 8c8ce578-...)   hdr 0x48
  └ FFS file 9e21fd93-...  type 0x0B FIRMWARE_VOLUME_IMAGE
    └ section type 0x02 GUID_DEFINED  guid ee4e5898-... (LZMA), attr PROCESSING_REQUIRED
      └ LZMA(inner FV)
        └ FFS file f536d559-...  type 0x09 APPLICATION
          ├ section 0x15 USER_INTERFACE  "LinuxLoader"
          └ section 0x10 PE32            LinuxLoader.efi

`unpack` extracts the inner LinuxLoader PE. `pack` rebuilds the whole FV around a
(new) PE, recompressing with LZMA-alone (the format EDK2's
LzmaCustomDecompressLib consumes: 5 prop bytes + 8-byte size + stream). The
result is a valid, parseable FV of the same layout; feed it to mkabl.py to sign.
"""
import sys, struct, lzma, argparse

FFS2_GUID  = bytes.fromhex('78e58c8c3d8a1c4f9935896185c32dd3')  # 8c8ce578-8a3d-4f1c-9935-896185c32dd3 (mixed-endian)
LZMA_GUID  = bytes.fromhex('98584eee143959429d6edc7bd79403cf')  # ee4e5898-3914-4259-9d6e-dc7bd79403cf
FVIMG_FILE = bytes.fromhex('93fd219e729c154c8c4be77f1db2d792')  # 9e21fd93-...
APP_FILE   = bytes.fromhex('59d536f59f45fa488bbc43b554ecae8d')  # f536d559-...
UI_NAME    = "LinuxLoader"

def cksum16(b):
    s = 0
    for i in range(0, len(b), 2):
        s = (s + (b[i] | (b[i+1] << 8))) & 0xffff
    return (0x10000 - s) & 0xffff

def sec(stype, body, guid=None, guid_attr=0):
    if guid is not None:                       # GUID_DEFINED (0x02)
        dataoff = 4 + 16 + 2 + 2
        hdr = struct.pack('<HB', 0, 0)         # placeholder size handled below
        raw = guid + struct.pack('<HH', dataoff, guid_attr) + body
        total = 4 + len(raw)
        return struct.pack('<I', (total & 0xffffff) | (stype << 24))[:3] + bytes([stype]) + raw
    body = bytes(body)
    total = 4 + len(body)
    return (total & 0xffffff).to_bytes(3, 'little') + bytes([stype]) + body

def ffs(guid, ftype, sections, attr=0x00):
    body = b''.join(sections)
    size = 24 + len(body)
    hdr = bytearray(guid + b'\x00\x00' + bytes([ftype, attr]) +
                    (size & 0xffffff).to_bytes(3, 'little') + b'\x00')  # state fixed below
    # integrity check: header checksum (sum of header w/ IntegrityCheck=0, State=0)
    hdr[16] = 0; hdr[17] = 0; hdr[23] = 0
    hc = (0x100 - (sum(hdr[:23]) & 0xff)) & 0xff
    hdr[16] = hc
    hdr[17] = 0xAA          # file checksum not used (attr bit unset) -> fixed 0xAA
    hdr[23] = 0xF8          # State: EFI_FILE_HEADER_CONSTRUCTION|VALID|DATA_VALID (0x07) complemented -> 0xF8; erase-polarity 1
    return bytes(hdr) + body

def fv(files, total_len=None, block=0x200):
    body = b''.join(files)
    hdrlen = 0x48
    raw_len = hdrlen + len(body)
    if total_len is None:
        total_len = (raw_len + block - 1) // block * block
    nblocks = total_len // block
    hdr = bytearray(64 + 8)
    hdr[0:16] = b'\x00'*16                       # ZeroVector
    hdr[16:32] = FFS2_GUID
    struct.pack_into('<Q', hdr, 32, total_len)   # FvLength
    hdr[40:44] = b'_FVH'
    struct.pack_into('<I', hdr, 44, 0x0003feff)  # Attributes (matches shipped image)
    struct.pack_into('<H', hdr, 48, hdrlen)      # HeaderLength
    struct.pack_into('<H', hdr, 50, 0)           # Checksum placeholder
    struct.pack_into('<H', hdr, 54, 2)           # Revision = 2
    struct.pack_into('<II', hdr, 56, nblocks, block)  # block map entry
    struct.pack_into('<II', hdr, 64, 0, 0)            # block map terminator
    struct.pack_into('<H', hdr, 50, cksum16(bytes(hdr[:hdrlen])))
    out = bytes(hdr) + body
    return out + b'\xff' * (total_len - len(out))

def lzma_alone(data):
    # EDK2 LzmaCustomDecompressLib expects LZMA_Alone: props(5) + size(8 LE) + stream.
    # Match EDK2 LzmaCompress defaults exactly: lc=3 lp=0 pb=2 (props 0x5d), 16 MB dict.
    f = lzma.LZMACompressor(format=lzma.FORMAT_ALONE,
                            filters=[{'id': lzma.FILTER_LZMA1, 'dict_size': 0x1000000,
                                      'lc': 3, 'lp': 0, 'pb': 2, 'mode': lzma.MODE_NORMAL,
                                      'nice_len': 273, 'mf': lzma.MF_BT4, 'depth': 0}])
    out = bytearray(f.compress(data) + f.flush())
    # Python streams with size=unknown (0xffff...); EDK2's decoder needs the real
    # uncompressed size in the 8-byte LZMA_Alone size field (offset 5..13).
    struct.pack_into('<Q', out, 5, len(data))
    return bytes(out)

def pack(pe_bytes, total_len=0x3d000):
    ui = UI_NAME.encode('utf-16-le') + b'\x00\x00'
    inner_app = ffs(APP_FILE, 0x09, [sec(0x15, ui), sec(0x10, pe_bytes)])
    inner_fv  = fv([inner_app], block=0x40)
    # The LZMA guided section decompresses to a SECTION STREAM, not a raw FV:
    #   [4-byte empty RAW section (0x19), for 8-byte alignment of the FV]
    #   [EFI_SECTION_FIRMWARE_VOLUME_IMAGE (0x17) wrapping the inner FV]
    align_raw = bytes([0x04, 0x00, 0x00, 0x19])                 # size=4, type=RAW, empty
    fv_img    = sec(0x17, inner_fv)                             # FIRMWARE_VOLUME_IMAGE
    stream    = align_raw + fv_img
    comp = lzma_alone(stream)
    guided = sec(0x02, comp, guid=LZMA_GUID, guid_attr=0x01)
    outer_file = ffs(FVIMG_FILE, 0x0B, [guided])
    return fv([outer_file], total_len=total_len)

def unpack(fd):
    hdrlen = struct.unpack_from('<H', fd, 48)[0]
    fo = hdrlen
    so = fo + 24
    assert fd[so+3] == 0x02, "expected GUID_DEFINED outer section"
    dataoff = struct.unpack_from('<H', fd, so+20)[0]
    ssize = (fd[so] | (fd[so+1]<<8) | (fd[so+2]<<16))
    comp = fd[so+dataoff: so+ssize]
    inner = lzma.decompress(comp, format=lzma.FORMAT_ALONE)
    fvbase = inner.find(b'_FVH') - 0x28             # skip any leading pad before the FV
    ih = fvbase + struct.unpack_from('<H', inner, fvbase+48)[0]
    fvlen = min(fvbase + struct.unpack_from('<Q', inner, fvbase+32)[0], len(inner))
    p = ih
    while p + 24 <= fvlen:
        fguid = inner[p:p+16]
        ftype = inner[p+18]
        fsize = inner[p+20] | (inner[p+21]<<8) | (inner[p+22]<<16)
        if fsize == 0:
            break
        if ftype == 0x09 or fguid == APP_FILE:      # APPLICATION
            q = p + 24; end = p + fsize
            while q < end:
                ssz = inner[q] | (inner[q+1]<<8) | (inner[q+2]<<16); st = inner[q+3]
                if ssz == 0: break
                if st == 0x10:
                    return inner[q+4: q+ssz]
                q += (ssz + 3) & ~3
        p += (fsize + 7) & ~7                          # files are 8-byte aligned
    raise SystemExit("no PE32 section found")

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    u = sub.add_parser('unpack'); u.add_argument('fd'); u.add_argument('out_pe')
    p = sub.add_parser('pack');   p.add_argument('pe'); p.add_argument('out_fd')
    p.add_argument('--len', default='0x3d000')
    a = ap.parse_args()
    if a.cmd == 'unpack':
        open(a.out_pe,'wb').write(unpack(open(a.fd,'rb').read()))
        print("extracted PE ->", a.out_pe)
    else:
        fd = pack(open(a.pe,'rb').read(), int(a.len,0))
        open(a.out_fd,'wb').write(fd)
        print("packed FV ->", a.out_fd, len(fd), "bytes")

if __name__ == '__main__':
    main()
