#!/usr/bin/env python3
"""mkabl.py - pack a UEFI payload (.fd) into a Qualcomm signed ABL ELF.

The ABL is an ELF32/ARM container carrying a Qualcomm MBN hash-table segment:

  PH0 PT_NULL  off 0x0     ELF header + program headers   -> measured as hash[0]
  PH1 PT_NULL  off 0x1000  hash-table segment             -> self, hash[1] = 0
  PH2 PT_LOAD  off 0x2000  the UEFI FV payload            -> measured as hash[2]

Per-segment digests are SHA-384; the segment is RSA-signed and carries a DER
cert chain. The exact geometry (hash-table offset, signature size, cert size)
varies between SoC builds, so it is DERIVED FROM A TEMPLATE blob (an existing
abl_signed-<SoC>.elf for the same SoC): the template's own hash[0] digest is
located to find the table, and the signature/cert regions follow it. Only the
hashes are recomputed for a new payload; the header and cert chain are kept.

Verification: repacking a blob's own payload with --preserve-sig reproduces the
original byte-for-byte (see roundtrip_test.sh). This proves the layout and the
SHA-384 measurement are exact.

Signing a MODIFIED payload requires a key:
  --preserve-sig     reuse template signature (valid only if payload is
                     unchanged; used for the byte-exact round-trip check)
  --key KEY.pem      re-sign the regenerated segment with an RSA key via openssl
  --pss              use RSA-PSS padding (default: PKCS#1 v1.5)
  --sigdigest ALGO   digest for the signature (default sha384)

NOTE: a device with secure boot fused will only accept an image signed by the
OEM/ROCKNIX private key over the exact range/scheme its PBL/XBL expects. This
tool reproduces the container and measurements exactly; the signing scheme flags
let you match a target. Unlocked/test devices accept a self/test key.
"""
import sys, struct, hashlib, argparse, subprocess, tempfile, os

HDR_LEN  = 0x94        # ELF header (52) + 3 * phdr (32) = 0x94
HASH_OFF = 0x1000      # PH1 file offset
LOAD_OFF = 0x2000      # PH2 file offset
HASH_SZ  = 48          # SHA-384
NHASH    = 3

def phdrs_of(d):
    e_phoff = struct.unpack_from('<I', d, 0x1c)[0]
    n       = struct.unpack_from('<H', d, 0x2c)[0]
    return e_phoff, [struct.unpack_from('<8I', d, e_phoff + i*32) for i in range(n)]

def parse_template(tpl):
    """Locate hash table + sig + cert in the template's hash segment."""
    e_phoff, phs = phdrs_of(tpl)
    seglen = phs[1][4]
    seg = bytearray(tpl[HASH_OFF:HASH_OFF+seglen])
    # find hash[0] = SHA-384(template ELF header+phdrs) -> table offset
    h0 = hashlib.sha384(tpl[:HDR_LEN]).digest()
    tbl = seg.find(h0)
    if tbl < 0:
        raise SystemExit("template: could not locate hash table (unexpected format)")
    sig_off  = tbl + NHASH*HASH_SZ
    # cert chain is DER: starts 0x30 0x82 after the signature
    cert_off = seg.find(b'\x30\x82', sig_off)
    if cert_off < 0:
        cert_off = seglen
    return e_phoff, seg, tbl, sig_off, cert_off

def openssl_sign(data, key, pss, digest):
    with tempfile.TemporaryDirectory() as t:
        di = os.path.join(t, 'd'); so = os.path.join(t, 's')
        open(di, 'wb').write(data)
        cmd = ['openssl', 'dgst', '-'+digest, '-sign', key, '-out', so]
        if pss:
            cmd += ['-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:-1']
        cmd.append(di)
        subprocess.run(cmd, check=True)
        return open(so, 'rb').read()

def build(payload, template, preserve_sig=False, key=None, pss=False, digest='sha384'):
    e_phoff, seg, tbl, sig_off, cert_off = parse_template(template)
    sig_size = cert_off - sig_off
    # rebuild ELF header region from template, patch PH2 size to new payload len
    hdr = bytearray(template[:HDR_LEN])
    po = e_phoff + 2*32
    struct.pack_into('<I', hdr, po+16, len(payload))   # p_filesz
    struct.pack_into('<I', hdr, po+20, len(payload))   # p_memsz
    # recompute measurements
    seg[tbl:tbl+HASH_SZ]                 = hashlib.sha384(bytes(hdr)).digest()   # hash[0]
    seg[tbl+HASH_SZ:tbl+2*HASH_SZ]       = b'\0'*HASH_SZ                          # hash[1] self
    seg[tbl+2*HASH_SZ:tbl+3*HASH_SZ]     = hashlib.sha384(payload).digest()       # hash[2]
    # signature over header .. end of hash table (MBN convention)
    to_sign = bytes(seg[0:sig_off])
    if preserve_sig:
        pass
    elif key is not None:
        sig = openssl_sign(to_sign, key, pss, digest)
        if len(sig) != sig_size:
            raise SystemExit("signature %d bytes != template sig field %d (wrong key size?)"
                             % (len(sig), sig_size))
        seg[sig_off:sig_off+sig_size] = sig
    else:
        raise SystemExit("need --preserve-sig or --key")
    # assemble
    out = bytearray(LOAD_OFF + len(payload))
    out[0:HDR_LEN]                = hdr
    out[HASH_OFF:HASH_OFF+len(seg)] = seg
    out[LOAD_OFF:LOAD_OFF+len(payload)] = payload
    return bytes(out)

def main():
    ap = argparse.ArgumentParser(description="pack a UEFI .fd into a Qualcomm signed ABL ELF")
    ap.add_argument('payload'); ap.add_argument('template'); ap.add_argument('out')
    ap.add_argument('--preserve-sig', action='store_true')
    ap.add_argument('--key'); ap.add_argument('--pss', action='store_true')
    ap.add_argument('--sigdigest', default='sha384')
    a = ap.parse_args()
    blob = build(open(a.payload,'rb').read(), open(a.template,'rb').read(),
                 a.preserve_sig, a.key, a.pss, a.sigdigest)
    open(a.out,'wb').write(blob)
    print("wrote %s (%d bytes)" % (a.out, len(blob)))

if __name__ == '__main__':
    main()
