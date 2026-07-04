#!/usr/bin/env python3
"""Disassemble an AArch64 region of a LinuxLoader PE and resolve string refs.

Usage:
    disasm_fn.py <LinuxLoader.pe> <target_rva> [start_rva] [end_rva]

<target_rva> is any RVA inside the function (e.g. the site that references a
DEBUG string, found via pe64.build_adr_map). start/end default to a window
around it. ADRP/ADD-computed pointers into .data are annotated with the C
string they resolve to, which is what lets you recover a function from the
messages it prints.
"""
import sys, capstone, pe64

def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    pe = pe64.PE(sys.argv[1])
    target = int(sys.argv[2], 16)
    start = int(sys.argv[3], 16) if len(sys.argv) > 3 else target - 0x120
    end   = int(sys.argv[4], 16) if len(sys.argv) > 4 else target + 0x80
    va, code = pe.text()
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    adrp = {}
    for insn in md.disasm(code[start - va:end - va], start):
        ann = ""
        ops = insn.operands
        if insn.mnemonic == 'adrp' and len(ops) == 2:
            adrp[insn.reg_name(ops[0].reg)] = ops[1].imm
        elif insn.mnemonic in ('add', 'ldr') and len(ops) >= 2 and \
                ops[1].type == capstone.arm64.ARM64_OP_REG:
            base = insn.reg_name(ops[1].reg)
            if base in adrp and insn.mnemonic == 'add' and \
                    ops[2].type == capstone.arm64.ARM64_OP_IMM:
                tgt = adrp[base] + ops[2].imm
                s = pe.cstr_at_rva(tgt)
                if s:
                    ann = "   ; 0x%x %r" % (tgt, s[:60])
        print("0x%06x  %-8s %s%s" % (insn.address, insn.mnemonic, insn.op_str, ann))

if __name__ == '__main__':
    main()
