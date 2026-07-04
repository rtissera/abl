#!/usr/bin/env python3
"""Given a Qualcomm signed ABL ELF, return the inner LinuxLoader PE bytes."""
import sys, struct
from uefi_firmware import AutoParser

def carve_load(elf):
    # ELF32 LE. program headers at e_phoff, e_phnum entries of 32 bytes
    e_phoff=struct.unpack_from('<I',elf,0x1c)[0]
    e_phentsize=struct.unpack_from('<H',elf,0x2a)[0]
    e_phnum=struct.unpack_from('<H',elf,0x2c)[0]
    best=None
    for i in range(e_phnum):
        o=e_phoff+i*e_phentsize
        p_type,p_off,p_vaddr,p_paddr,p_filesz,p_memsz,p_flags,p_align=struct.unpack_from('<IIIIIIII',elf,o)
        # LOAD=1, pick the biggest filesz (the payload)
        if p_filesz>0 and (best is None or p_filesz>best[1]):
            best=(p_off,p_filesz,p_type,p_flags)
    off,sz,_,_=best
    return elf[off:off+sz]

def find_pe(obj, out):
    # recursively find PE32 image section bodies
    cls=obj.__class__.__name__
    data=getattr(obj,'data',None)
    # uefi_firmware Section with type 0x10 = PE32
    stype=getattr(obj,'type',None)
    if stype==0x10 and data:
        out.append(bytes(data))
    for c in getattr(obj,'objects',[]) or []:
        find_pe(c,out)

def get_pe(elfbytes):
    payload=carve_load(elfbytes)
    fw=AutoParser(payload).parse()
    out=[]
    find_pe(fw,out)
    if not out:
        return None
    # largest PE = LinuxLoader
    out.sort(key=len)
    return out[-1]

if __name__=='__main__':
    elf=open(sys.argv[1],'rb').read()
    pe=get_pe(elf)
    if pe is None:
        sys.stderr.write("no PE found\n"); sys.exit(1)
    sys.stdout.buffer.write(pe)
