#!/usr/bin/env python3
"""diff_text.py - section-level diff of two LinuxLoader PEs, to drive a 1:1 rebuild.

Compare a freshly-built LinuxLoader.efi (from the base + your reconstructed
delta) against the reference PE extracted from a shipped blob. Both are ImageBase
0, so .text/.data align by RVA. Differing bytes are clustered into ranges; each
range is annotated with the nearest preceding DEBUG/format string it references,
which usually names the enclosing function. Iterate: rebuild, diff, reconstruct
the next differing function, until this prints "IDENTICAL".

Usage:  diff_text.py <reference.pe> <candidate.pe> [--section .text] [--gap N]
"""
import sys, argparse, pe64

def cluster(ref, cand, base, gap):
    diffs=[i for i in range(min(len(ref),len(cand))) if ref[i]!=cand[i]]
    if len(ref)!=len(cand):
        diffs += list(range(min(len(ref),len(cand)), max(len(ref),len(cand))))
    ranges=[]
    for i in sorted(set(diffs)):
        if ranges and i-ranges[-1][1] <= gap:
            ranges[-1][1]=i+1
        else:
            ranges.append([i,i+1])
    return ranges

def nearest_string(pe, rva):
    """best-effort: find a DEBUG/format string referenced by code near rva."""
    xref=pe._xref
    best=None
    for tgt,sites in xref.items():
        for s in sites:
            if 0 <= rva-s < 0x400:      # a ref site just before/at the diff
                cs=pe.cstr_at_rva(tgt)
                if cs and (best is None or s>best[0]):
                    best=(s,cs)
    return best

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('ref'); ap.add_argument('cand')
    ap.add_argument('--section', default='.text')
    ap.add_argument('--gap', type=int, default=32)
    a=ap.parse_args()
    R=pe64.PE(a.ref); C=pe64.PE(a.cand)
    R._xref=pe64.build_adr_map(R)
    def sec(pe,name):
        for n,va,vsz,rptr,rsz in pe.sections:
            if n==name: return va, pe.d[rptr:rptr+rsz]
        return None,None
    rva,rb=sec(R,a.section); cva,cb=sec(C,a.section)
    if rb is None or cb is None:
        sys.exit("section %s not found in both"%a.section)
    ranges=cluster(rb,cb,rva,a.gap)
    total=sum(e-s for s,e in ranges)
    if not ranges:
        print("IDENTICAL (%s, %d bytes)"%(a.section,len(rb))); return
    print("%s: %d differing byte(s) in %d region(s)  (ref=%d cand=%d bytes)"%(
        a.section,total,len(ranges),len(rb),len(cb)))
    for s,e in ranges:
        anno=""
        if a.section=='.text':
            ns=nearest_string(R, rva+s)
            if ns: anno="  ~ %r"%(ns[1][:48])
        print("  0x%06x .. 0x%06x  (%d bytes)%s"%(rva+s, rva+e, e-s, anno))
    print("\n%d region(s) still differ from reference -> reconstruct these next."%len(ranges))

if __name__=='__main__':
    main()
