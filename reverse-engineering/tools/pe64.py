"""Minimal AArch64 PE helper: RVA<->offset, string table, ADRP/ADD xref."""
import struct, capstone

class PE:
    def __init__(self, path):
        self.d=open(path,'rb').read()
        pe=struct.unpack_from('<I',self.d,0x3c)[0]
        self.machine=struct.unpack_from('<H',self.d,pe+4)[0]
        nsec=struct.unpack_from('<H',self.d,pe+6)[0]
        opt=pe+24
        self.optmagic=struct.unpack_from('<H',self.d,opt)[0]
        self.entry=struct.unpack_from('<I',self.d,opt+16)[0]
        self.imagebase=struct.unpack_from('<Q',self.d,opt+24)[0]
        sohdr=struct.unpack_from('<H',self.d,pe+20)[0]
        sect=opt+sohdr
        self.sections=[]
        for i in range(nsec):
            o=sect+i*40
            name=self.d[o:o+8].split(b'\0')[0].decode('latin1')
            vsz,va,rsz,rptr=struct.unpack_from('<IIII',self.d,o+8)
            self.sections.append((name,va,vsz,rptr,rsz))
    def rva2off(self,rva):
        for name,va,vsz,rptr,rsz in self.sections:
            if va<=rva<va+max(vsz,rsz):
                return rptr+(rva-va)
        return None
    def off2rva(self,off):
        for name,va,vsz,rptr,rsz in self.sections:
            if rptr<=off<rptr+rsz:
                return va+(off-rptr)
        return None
    def text(self):
        for name,va,vsz,rptr,rsz in self.sections:
            if name=='.text':
                return va,self.d[rptr:rptr+rsz]
        return None,None
    def cstr_at_rva(self,rva,maxlen=200):
        o=self.rva2off(rva)
        if o is None: return None
        end=self.d.find(b'\0',o,o+maxlen)
        if end<0: return None
        try: return self.d[o:end].decode('latin1')
        except: return None

def find_strings(pe, pattern):
    """return list of (rva, string) for ascii strings matching substring pattern (bytes)."""
    d=pe.d; res=[]
    idx=0
    while True:
        i=d.find(pattern, idx)
        if i<0: break
        # find start of string (back to previous NUL)
        s=d.rfind(b'\0', 0, i)+1
        e=d.find(b'\0', i)
        if e<0: e=i+len(pattern)
        rva=pe.off2rva(s)
        if rva is not None:
            try: res.append((rva, d[s:e].decode('latin1')))
            except: pass
        idx=i+len(pattern)
    return res

def build_adr_map(pe):
    """Scan .text, resolve ADRP(+ADD/LDR) → target rva, return dict target_rva -> list of insn rvas."""
    va,code=pe.text()
    md=capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail=True
    xref={}
    adrp_val={}  # reg -> (page_base, insn_rva)
    for insn in md.disasm(code, va):
        m=insn.mnemonic
        ops=insn.operands
        if m=='adrp' and len(ops)==2:
            reg=insn.reg_name(ops[0].reg)
            adrp_val[reg]=(ops[1].imm, insn.address)
        elif m in('add','ldr') and len(ops)>=2:
            reg=insn.reg_name(ops[0].reg)
            base=insn.reg_name(ops[1].reg) if ops[1].type==capstone.arm64.ARM64_OP_REG else None
            if base in adrp_val:
                pageb,adrp_rva=adrp_val[base]
                imm=0
                if m=='add' and ops[2].type==capstone.arm64.ARM64_OP_IMM:
                    imm=ops[2].imm
                elif m=='ldr' and ops[1].type==capstone.arm64.ARM64_OP_MEM:
                    imm=ops[1].mem.disp
                target=pageb+imm
                xref.setdefault(target,[]).append(adrp_rva)
    return xref

if __name__=='__main__':
    import sys
    pe=PE(sys.argv[1])
    print("machine %04x entry rva 0x%x imagebase 0x%x"%(pe.machine,pe.entry,pe.imagebase))
    for s in pe.sections: print("  sec",s)
