#!/usr/bin/env python3
"""
bitfield_census.py - decoder-free census of above-baseline encodings, plus a
structural triage of every hit.
======================================================================

WHY THIS EXISTS
---------------
tools/sweep_image.py counts findings by decoding instructions with capstone
and then resolving each byte to a terminal state. Two independent things can
go wrong with a count produced that way:

  * UNDER-reporting, if the decoder has a gap. capstone 5.0 has no SME
    decoder at all, and its SYS alias table is missing entries, so a category
    can be invisible rather than zero.
  * OVER-reporting, if constant data happens to form a valid encoding. In the
    userland dyld shared cache this is not hypothetical: one mnemonic
    (`fnmls`) decoded 4,935,874 times out of what turned out to be literal
    pools, and 19.56% of the executable-mapping bytes reach a proven-data
    terminal state.

This tool addresses both from the other side. It never calls a disassembler.
Each 4-byte word is tested against bit-field predicates taken straight from
the ARM ARM encoding tables, which gives a count that CANNOT be lowered by a
decoder gap - i.e. a genuine upper bound. And it buckets every hit by what
Apple's own Mach-O section headers say about the byte:

    instr        inside a section carrying S_ATTR_PURE_INSTRUCTIONS or
                 S_ATTR_SOME_INSTRUCTIONS  -> Apple says this is code
    noncode      inside a section carrying neither                -> Apple
                 says this is data, so a hit here is a decode collision
    unsectioned  inside the executable mapping but outside every section of
                 every image (inter-image padding, stub islands)

That bucketing is the triage. It is structural, not statistical: the evidence
is the linker's own declaration, recorded in the shipped bytes, and it is
produced without reference to reachability, to literal-pool heuristics, or to
any output of the capstone-based sweep.

WHAT "INDEPENDENT" MEANS HERE, EXACTLY
--------------------------------------
Independent of: capstone, the five-pass byte-state machine, the recursive
descent reachability pass, the data-blob growth heuristics, and
armmac_baseline.py's mnemonic tables. This file imports none of them.

NOT independent of: the ARM ARM encoding tables themselves, and the
assumption that a 4-byte-aligned word boundary is the right grid. The grid
assumption is why the numbers are upper bounds rather than measurements: a
constant pool read at the wrong phase still produces hits, which is precisely
what the section bucketing then quantifies.

The predicates are cross-checked against llvm-mc by
tools/testdata/verify_bitfield_masks.py, which assembles a corpus of real
instructions for every category and asserts that each one is claimed by
exactly the predicate it should be, and that baseline instructions are
claimed by none. A predicate with no llvm-mc witness is not shipped.

USAGE
-----
    # a dyld shared cache: point at the MAIN file, subcaches are followed
    py tools/bitfield_census.py dsc --target .../dyld_shared_cache_arm64e \
        --out out/census.json

    # any Mach-O (FAT aware), or an MH_FILESET kernelcache
    py tools/bitfield_census.py macho --target extracted_kernel/com.apple.kernel \
        --out out/kernel-census.json

    # restrict to one shard of the executable ranges, for a matrix job
    ... --shard 3/8

Output JSON (schema armmac-bitfield-census/1):
    totals            words scanned, bytes scanned, per-bucket byte counts
    categories        per category: hits, and the instr/noncode/unsectioned
                      split, plus the distinct encodings seen
    encodings         per category, the distinct raw words or field tuples
                      with counts, so any single number can be re-derived
"""

import argparse
import array
import collections
import json
import os
import struct
import sys
import time

SCHEMA = "armmac-bitfield-census/1"

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
VM_PROT_EXECUTE = 4
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
DSC_MAGIC = b"dyld_v1"
DSC_SIDECAR_SUFFIXES = (".map", ".atlas", ".symbols", ".json", ".txt")

# ---------------------------------------------------------------------------
# Field extractors. Deliberately re-implemented here rather than imported
# from sweep_kernelcache.py: if both counts came from the same extractor a
# bug in it would agree with itself. These are the ARM ARM field positions.
# ---------------------------------------------------------------------------


def f_sysclass(w):
    """System instruction class 0xD5000000-0xD53FFFFF.

    -> (L, op0, op1, CRn, CRm, op2, Rt) or None.
    Layout: 1101 0101 00 L op0(2) op1(3) CRn(4) CRm(4) op2(3) Rt(5)
    """
    if (w >> 22) != 0x354:
        return None
    return ((w >> 21) & 1, (w >> 19) & 3, (w >> 16) & 7, (w >> 12) & 0xF,
            (w >> 8) & 0xF, (w >> 5) & 7, w & 0x1F)


# HINT space: op0=0b00, CRn=0b0010. The (CRm, op2) pairs the architecture
# allocates to PAC and to BTI. Every other pair in CRn=2 executes as NOP on
# any implementation, which is why this table is the whole PAC-HINT story.
PAC_HINT_ENC = {
    (0, 7): "xpaclri",
    (1, 0): "pacia1716", (1, 2): "pacib1716",
    (1, 4): "autia1716", (1, 6): "autib1716",
    (3, 0): "paciaz", (3, 1): "paciasp",
    (3, 2): "pacibz", (3, 3): "pacibsp",
    (3, 4): "autiaz", (3, 5): "autiasp",
    (3, 6): "autibz", (3, 7): "autibsp",
}
BTI_HINT_ENC = {(4, 0): "bti", (4, 2): "bti c", (4, 4): "bti j",
                (4, 6): "bti jc"}

# Data-processing (1 source), sf=1 S=0 opcode2=0b00001: the PAC/AUT/XPAC
# register forms. opcode 0b000000..0b010001 are allocated; the rest of that
# opcode2 slot is unallocated.
PAC_DP1_OPCODE = {
    0x00: "pacia", 0x01: "pacib", 0x02: "pacda", 0x03: "pacdb",
    0x04: "autia", 0x05: "autib", 0x06: "autda", 0x07: "autdb",
    0x08: "paciza", 0x09: "pacizb", 0x0A: "pacdza", 0x0B: "pacdzb",
    0x0C: "autiza", 0x0D: "autizb", 0x0E: "autdza", 0x0F: "autdzb",
    0x10: "xpaci", 0x11: "xpacd",
}

# Unconditional branch (register): 1101011 opc(4) op2(5) op3(6) Rn op4.
# The PAC variants are exactly those with op3 in {0b000010, 0b000011}
# (M=0 -> key A, M=1 -> key B), plus the ERETA* pair.
PACBR_OPC = {0x0: "braa/brab", 0x1: "blraa/blrab", 0x2: "retaa/retab",
             0x4: "eretaa/eretab", 0x8: "braaz/brabz", 0x9: "blraaz/blrabz"}

# MSR (immediate) / PSTATE: op0=0b00, CRn=0b0100. (op1, op2) -> field.
# CRm carries the immediate except for SVCR, where it selects SM/ZA.
PSTATE_ENC = {
    (0, 0): ("CFINV", "FEAT_FlagM(v8.4)"),
    (0, 1): ("XAFlag", "FEAT_FlagM2(v8.5)"),
    (0, 2): ("AXFlag", "FEAT_FlagM2(v8.5)"),
    (0, 3): ("UAO", None),
    (0, 4): ("PAN", None),
    (0, 5): ("SPSel", None),
    (1, 0): ("ALLINT", "FEAT_NMI(v8.8)"),
    (3, 1): ("SSBS", "FEAT_SSBS"),
    (3, 2): ("DIT", "FEAT_DIT(v8.4)"),
    (3, 3): ("SVCR", "FEAT_SME(v9.2)"),
    (3, 4): ("TCO", "FEAT_MTE(v8.5)"),
    (3, 6): ("DAIFSet", None),
    (3, 7): ("DAIFClr", None),
}

AMX_OP_NAMES = {
    0: "ldx", 1: "ldy", 2: "stx", 3: "sty", 4: "ldz", 5: "stz", 6: "ldzi",
    7: "stzi", 8: "extrx", 9: "extry", 10: "fma64", 11: "fms64", 12: "fma32",
    13: "fms32", 14: "mac16", 15: "fma16", 16: "fms16", 17: "set/clr",
    18: "vecint", 19: "vecfp", 20: "matint", 21: "matfp", 22: "genlut",
}

# Categories, in the order they are tested. The FIRST match wins, so the
# order matters and is asserted by the llvm-mc verifier: a `pacia` must be
# claimed by PAC_DP1 and nothing else.
CATEGORIES = (
    "PAC_DP1",            # pacia/autda/xpaci... register forms, UNDEFINED
    "PAC_PACGA",          # pacga, UNDEFINED
    "PAC_BRANCH",         # braa/blraa/retaa/ereta*, UNDEFINED
    "PAC_LDRA",           # ldraa/ldrab, UNDEFINED
    "PAC_HINT",           # paciasp/autiasp/xpaclri..., executes as NOP
    "BTI",                # bti, executes as NOP
    "IMPDEF_SYSREG",      # MRS/MSR with op0 in {2,3} and CRn in {11,15}
    "IMPDEF_SYSINSTR",    # SYS/SYSL with CRn in {11,15}
    "SYSREG_ABOVE_V82",   # named-era sysregs are NOT judged here; see note
    "PSTATE_ABOVE_V82",   # DIT / SVCR / TCO / ALLINT / FlagM msr-immediate
    "PSTATE_UNALLOCATED",
    "HVC", "SMC",
    "SB",                 # speculation barrier, Barriers group not HINT
    "SVE_SME_SPACE",      # UNALLOCATED on v8.2, SVE/SME later
    "SME_ZA_SPACE",
    "APPLE_AMX",          # exact Apple AMX encodings
    "APPLE_RESERVED",     # rest of 0x002xxxxx
    "LDAPR", "LDAPUR",    # FEAT_LRCPC / LRCPC2
    "MTE",                # tag ops with no other home
)


def classify(w):
    """-> (category, key) or None. Decoder-free, first match wins.

    `key` is the identity a reader can re-derive the count from: the field
    tuple for system encodings, the mnemonic group for instruction forms.
    """
    # --- system instruction class (covers HINT, barriers, MRS/MSR, SYS) ---
    sc = f_sysclass(w)
    if sc is not None:
        L, op0, op1, crn, crm, op2, rt = sc
        if op0 == 0:
            if crn == 2:                                     # HINT space
                ent = PAC_HINT_ENC.get((crm, op2))
                if ent:
                    return "PAC_HINT", ent
                ent = BTI_HINT_ENC.get((crm, op2))
                if ent:
                    return "BTI", ent
                return None            # any other hint is a NOP everywhere
            if crn == 3:                                     # Barriers
                # SB is op1=0b011 CRm=0b0000 op2=0b111 Rt=0b11111. It is in
                # the Barriers group, NOT the HINT group, so on a PE without
                # FEAT_SB it is UNDEFINED rather than a NOP - the distinction
                # INCOMPATIBILITY-MASTER-LIST 3.15 had to correct.
                if op1 == 3 and crm == 0 and op2 == 7 and rt == 31:
                    return "SB", "sb"
                return None
            if crn == 4:                                     # MSR immediate
                ent = PSTATE_ENC.get((op1, op2))
                if ent is None:
                    return "PSTATE_UNALLOCATED", f"op1={op1} op2={op2}"
                field, feat = ent
                if feat is None:
                    return None
                return "PSTATE_ABOVE_V82", f"{field} ({feat})"
            return None
        if op0 == 1:                                         # SYS / SYSL
            if crn in (11, 15):
                return ("IMPDEF_SYSINSTR",
                        f"{'sysl' if L else 'sys'} #{op1}, c{crn}, c{crm}, #{op2}")
            return None
        # op0 in {2,3}: MRS / MSR register forms
        if crn in (11, 15):
            return "IMPDEF_SYSREG", f"s{op0}_{op1}_c{crn}_c{crm}_{op2}"
        return None

    # --- exception generation: 1101 0100 op(3) imm16 op2(3) LL(2) ---------
    if (w >> 24) == 0xD4:
        op = (w >> 21) & 7
        ll = w & 3
        if op == 0 and ll == 2:
            return "HVC", f"hvc #{(w >> 5) & 0xFFFF:#x}"
        if op == 0 and ll == 3:
            return "SMC", f"smc #{(w >> 5) & 0xFFFF:#x}"
        return None

    # --- unconditional branch (register), PAC variants -------------------
    if (w & 0xFE000000) == 0xD6000000:
        op3 = (w >> 10) & 0x3F
        if op3 in (2, 3):
            opc = (w >> 21) & 0xF
            return "PAC_BRANCH", PACBR_OPC.get(opc, f"opc={opc}")
        return None

    # --- data-processing (1 source): PAC/AUT/XPAC register forms ----------
    # sf(1) S(1) 11010110 opcode2(5) opcode(6) Rn(5) Rd(5)
    if (w & 0x7FE00000) == 0x5AC00000:
        opcode2 = (w >> 16) & 0x1F
        opcode = (w >> 10) & 0x3F
        if (w >> 31) & 1 and opcode2 == 1:
            nm = PAC_DP1_OPCODE.get(opcode)
            if nm:
                return "PAC_DP1", nm
        return None

    # --- data-processing (2 source): PACGA ---------------------------------
    # sf=1 S=0 11010110 Rm opcode=001100 Rn Rd
    if (w & 0xFFE0FC00) == 0x9AC03000:
        return "PAC_PACGA", "pacga"

    # --- LDRAA / LDRAB: 11111000 M S 1 imm9 W 1 Rn Rt ---------------------
    if (w & 0xFF200400) == 0xF8200400:
        return "PAC_LDRA", "ldrab" if (w >> 23) & 1 else "ldraa"

    # --- top-level group bits[28:25] --------------------------------------
    # A64's top-level decode selects on op0 = bits[28:25]. 0b0010 is the SVE
    # group; 0b0000 splits on bit31, with SME above and the Reserved space
    # (where Apple put AMX) below. Both groups are UNALLOCATED in full on
    # ARMv8.2-A, so group membership alone is a sound UPPER BOUND - and a
    # wide one: see noise_floor in the output, because 4 of the 16 possible
    # op0 values means roughly 1 word in 16 of arbitrary data lands in the
    # SVE group. That is not a defect of the predicate, it is the reason the
    # instr/noncode bucketing is the part that carries information.
    grp = (w >> 25) & 0xF
    if grp == 0b0010:
        # RDSVL reads the SME streaming vector length but is encoded in the
        # SVE group next to RDVL, so group membership alone would file it
        # under SVE. Split it out: the two features are adjudicated
        # separately (FEAT_SME is T1, FEAT_SVE's 247 BootKC hits split 240/7).
        if (w & 0xFFFFF800) == 0x04BF5800:
            return "SME_ZA_SPACE", "rdsvl"
        if (w & 0xFFFFF800) == 0x04BF5000:
            return "SVE_SME_SPACE", "rdvl"
        return "SVE_SME_SPACE", "sve group (op0=0b0010)"
    if grp == 0b0000:
        if w >> 31:
            if (w >> 22) == 0x384:
                if (w & 0xFFFFFC1F) == 0xE11F8000:
                    return "SME_ZA_SPACE", "ldr zt0"
                if (w & 0xFFFFFC1F) == 0xE13F8000:
                    return "SME_ZA_SPACE", "str zt0"
                return "SME_ZA_SPACE", "ldr/str za group"
            return "SME_ZA_SPACE", "sme group (op0=0b0000, bit31=1)"
        # Reserved half. Only the slice Apple actually uses is claimed; UDF
        # (0x0000xxxx) and the rest of the half are left alone, because
        # calling them Apple-private would assert a vendor meaning the
        # encoding does not carry.
        if (w & 0xFFE00000) == 0x00200000:
            if (w & 0xFFFFFC00) == 0x00201000:
                op = (w >> 5) & 0x1F
                return "APPLE_AMX", f"amx op={op} ({AMX_OP_NAMES.get(op, '?')})"
            return "APPLE_RESERVED", "reserved 0x002xxxxx"
        return None

    # --- FEAT_LRCPC: LDAPR / LDAPRB / LDAPRH ------------------------------
    # size(2) 111000 1 0 1 1 11111 1100 00 Rn Rt
    if (w & 0x3FFFFC00) == 0x38BFC000:
        return "LDAPR", {0: "ldaprb", 1: "ldaprh", 2: "ldapr w",
                         3: "ldapr x"}[(w >> 30) & 3]

    # --- FEAT_LRCPC2: LDAPUR* / STLUR* ------------------------------------
    # size(2) 011001 opc(2) 0 imm9 00 Rn Rt
    if (w & 0x3F200C00) == 0x19000000:
        return "LDAPUR", f"ldapur/stlur opc={(w >> 22) & 3} size={(w >> 30) & 3}"

    # --- FEAT_MTE tag ops with distinctive encodings ----------------------
    if (w & 0xFFE0FC00) == 0x9AC01000:
        return "MTE", "irg"
    if (w & 0xFFE0FC00) == 0x9AC01400:
        return "MTE", "gmi"
    if (w >> 22) == 0x246:
        return "MTE", "addg"
    if (w >> 22) == 0x346:
        return "MTE", "subg"
    return None


# Categories the architecture makes UNDEFINED on a baseline PE vs ones that
# execute as a NOP. Recorded in the output so the hard/soft split does not
# have to be re-derived by the reader.
UNDEFINED_ON_V82 = {
    "PAC_DP1", "PAC_PACGA", "PAC_BRANCH", "PAC_LDRA", "IMPDEF_SYSREG",
    "IMPDEF_SYSINSTR", "PSTATE_ABOVE_V82", "PSTATE_UNALLOCATED", "SB",
    "SVE_SME_SPACE", "SME_ZA_SPACE", "APPLE_AMX", "APPLE_RESERVED",
    "LDAPR", "LDAPUR", "MTE",
}
NOP_ON_V82 = {"PAC_HINT", "BTI"}
TRAPS_TO_HOST = {"HVC", "SMC"}


# ---------------------------------------------------------------------------
# section bucketing
# ---------------------------------------------------------------------------
class SectionMap:
    """Sorted, non-overlapping-by-construction VA -> bucket lookup.

    Built from every section of every executable segment of every image. Two
    sections of different images cannot overlap (an image owns a VA range),
    and two sections of one segment do not overlap, so a plain sorted array
    plus bisect is correct. Overlaps are counted rather than assumed away.
    """

    __slots__ = ("starts", "ends", "bucket", "names", "overlaps", "_rows")

    def __init__(self):
        self._rows = []
        self.overlaps = 0
        self.starts = self.ends = self.bucket = self.names = []

    def add(self, addr, size, flags, name):
        if size <= 0:
            return
        code = bool(flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
        self._rows.append((addr, addr + size, "instr" if code else "noncode",
                           name))

    def freeze(self):
        self._rows.sort()
        prev_end = -1
        for a, b, _k, _n in self._rows:
            if a < prev_end:
                self.overlaps += 1
            prev_end = max(prev_end, b)
        self.starts = [r[0] for r in self._rows]
        self.ends = [r[1] for r in self._rows]
        self.bucket = [r[2] for r in self._rows]
        self.names = [r[3] for r in self._rows]

    def lookup(self, va):
        import bisect
        i = bisect.bisect_right(self.starts, va) - 1
        if i < 0 or va >= self.ends[i]:
            return "unsectioned", None
        return self.bucket[i], self.names[i]

    def ranges(self):
        return list(zip(self.starts, self.ends, self.bucket, self.names))


# ---------------------------------------------------------------------------
# containers
# ---------------------------------------------------------------------------
def dsc_members(main_path):
    main_abs = os.path.realpath(main_path)
    d = os.path.dirname(main_abs)
    base = os.path.basename(main_abs)
    members, seen = [], set()
    for name in sorted(os.listdir(d)):
        if not name.startswith(base) or name.endswith(DSC_SIDECAR_SUFFIXES):
            continue
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            members.append(p)
    if main_abs not in seen:
        members.insert(0, main_abs)
    return members


def dsc_ranges_and_sections(main_path):
    """-> (exec_ranges, SectionMap, meta).

    exec_ranges rows: (file_path, file_offset, va, size). They are the cache's
    executable mappings, i.e. exactly the byte universe sweep_image.py uses,
    so the two tools' denominators are comparable without adjustment.
    """
    members = dsc_members(main_path)
    exec_ranges = []
    all_ranges = []
    images = []
    for p in members:
        with open(p, "rb") as f:
            head = f.read(0x200)
            if not head.startswith(DSC_MAGIC):
                continue
            mo, mc = struct.unpack("<II", head[0x10:0x18])
            f.seek(mo)
            mraw = f.read(mc * 32)
            for i in range(mc):
                addr, sz, foff, _maxp, initp = struct.unpack(
                    "<QQQII", mraw[i * 32:(i + 1) * 32])
                if not sz:
                    continue
                all_ranges.append((addr, addr + sz, p, foff))
                if initp & VM_PROT_EXECUTE:
                    exec_ranges.append((p, foff, addr, sz))
            io = ic = 0
            if mo >= 0x1C8 and len(head) >= 0x1C8:
                io, ic = struct.unpack("<II", head[0x1C0:0x1C8])
            if (io == 0 or ic == 0) and len(head) >= 0x20:
                io, ic = struct.unpack("<II", head[0x18:0x20])
            if io and ic and ic < 100000 and not images:
                f.seek(io)
                iraw = f.read(ic * 32)
                for i in range(ic):
                    rec = iraw[i * 32:(i + 1) * 32]
                    if len(rec) < 32:
                        break
                    addr, _mt, _ino, poff, _pad = struct.unpack("<QQQII", rec)
                    if addr:
                        images.append(addr)
    all_ranges.sort()
    exec_ranges.sort(key=lambda r: r[2])

    # resolver over every mapping, so an image header in the TEXT subcache can
    # be read even though its LINKEDIT lives in another file
    starts = [r[0] for r in all_ranges]
    handles = {}

    def read_va(va, n):
        import bisect
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return b""
        lo, hi, path, foff = all_ranges[i]
        if not (lo <= va < hi):
            return b""
        n = min(n, hi - va)
        h = handles.get(path)
        if h is None:
            h = open(path, "rb", buffering=0)
            handles[path] = h
        h.seek(foff + (va - lo))
        return h.read(n)

    sm = SectionMap()
    n_img_ok = n_img_bad = n_sect = 0
    for img in images:
        head = read_va(img, 32)
        if len(head) < 32:
            n_img_bad += 1
            continue
        magic, cputype = struct.unpack("<II", head[:8])
        if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64:
            n_img_bad += 1
            continue
        ncmds, sizeofcmds = struct.unpack("<II", head[16:24])
        cmds = read_va(img + 32, min(sizeofcmds, 512 * 1024))
        idx = 0
        got = 0
        for _ in range(ncmds):
            if idx + 8 > len(cmds):
                break
            cmd, csz = struct.unpack("<II", cmds[idx:idx + 8])
            if csz < 8:
                break
            c = cmds[idx + 8:idx + csz]
            if cmd == LC_SEGMENT_64 and len(c) >= 64:
                nm = c[:16].rstrip(b"\x00").decode("ascii", "replace")
                _va, _vs, _fo, _fs, _mp, initp, nsects, _fl = \
                    struct.unpack("<QQQQIIII", c[16:64])
                if initp & VM_PROT_EXECUTE:
                    so = 64
                    for _s in range(nsects):
                        raw = c[so:so + 80]
                        if len(raw) < 80:
                            break
                        sname = raw[:16].rstrip(b"\x00").decode("ascii", "replace")
                        saddr, ssize, _off, _al, _ro, _nr, sflags = \
                            struct.unpack("<QQIIIII", raw[32:68])
                        sm.add(saddr, ssize, sflags, f"{nm},{sname}")
                        got += 1
                        so += 80
            idx += csz
        n_sect += got
        if got:
            n_img_ok += 1
        else:
            n_img_bad += 1
    for h in handles.values():
        h.close()
    sm.freeze()
    meta = {"container": "dyld_shared_cache", "members": len(members),
            "images": len(images), "images_with_exec_sections": n_img_ok,
            "images_without_exec_sections": n_img_bad,
            "exec_sections": n_sect,
            "exec_mappings": len(exec_ranges),
            "exec_mapping_bytes": sum(r[3] for r in exec_ranges),
            "section_overlaps": sm.overlaps}
    return exec_ranges, sm, meta


def macho_ranges_and_sections(path):
    """-> (exec_ranges, SectionMap, meta) for a Mach-O, FAT or MH_FILESET."""
    with open(path, "rb") as f:
        data = f.read()
    size = len(data)
    slices = []
    if size >= 8:
        magic_be = struct.unpack(">I", data[:4])[0]
        if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
            wide = magic_be == FAT_MAGIC_64
            nfat = struct.unpack(">I", data[4:8])[0]
            rec = 32 if wide else 20
            for i in range(min(nfat, 64)):
                o = 8 + i * rec
                if wide:
                    ct, _cs, off, sz, _al, _r = struct.unpack(">iiQQII", data[o:o + rec])
                else:
                    ct, _cs, off, sz, _al = struct.unpack(">iiIII", data[o:o + rec])
                if (ct & 0xFFFFFFFF) == CPU_TYPE_ARM64:
                    slices.append((off, sz))
    if not slices:
        slices = [(0, size)]

    exec_ranges = []
    sm = SectionMap()
    n_sect = 0
    headers = []
    for (soff, ssz) in slices:
        if struct.unpack("<I", data[soff:soff + 4])[0] != MH_MAGIC_64:
            continue
        filetype = struct.unpack("<I", data[soff + 12:soff + 16])[0]
        headers.append(soff)
        if filetype == 0xC:                                 # MH_FILESET
            ncmds = struct.unpack("<I", data[soff + 16:soff + 20])[0]
            idx = soff + 32
            for _ in range(ncmds):
                cmd, csz = struct.unpack("<II", data[idx:idx + 8])
                if csz < 8:
                    break
                if cmd == LC_FILESET_ENTRY:
                    c = data[idx + 8:idx + csz]
                    _vm, fo, _eo, _r = struct.unpack("<QQII", c[:24])
                    headers.append(fo)
                idx += csz
    # A fileset's own outer segments cover the same bytes its entries do, so
    # only the entry headers contribute ranges when there are entries.
    inner = [h for h in headers[1:]] if len(headers) > 1 else []
    use = inner or headers
    for hoff in use:
        if hoff + 32 > size or struct.unpack("<I", data[hoff:hoff + 4])[0] != MH_MAGIC_64:
            continue
        ncmds = struct.unpack("<I", data[hoff + 16:hoff + 20])[0]
        idx = hoff + 32
        for _ in range(ncmds):
            cmd, csz = struct.unpack("<II", data[idx:idx + 8])
            if csz < 8:
                break
            c = data[idx + 8:idx + csz]
            if cmd == LC_SEGMENT_64 and len(c) >= 64:
                nm = c[:16].rstrip(b"\x00").decode("ascii", "replace")
                vmaddr, _vs, fileoff, filesize, _mp, initp, nsects, _fl = \
                    struct.unpack("<QQQQIIII", c[16:64])
                if (initp & VM_PROT_EXECUTE) and filesize:
                    exec_ranges.append((path, fileoff, vmaddr, filesize))
                    so = 64
                    for _s in range(nsects):
                        raw = c[so:so + 80]
                        if len(raw) < 80:
                            break
                        sname = raw[:16].rstrip(b"\x00").decode("ascii", "replace")
                        saddr, ssize, _off, _al, _ro, _nr, sflags = \
                            struct.unpack("<QQIIIII", raw[32:68])
                        sm.add(saddr, ssize, sflags, f"{nm},{sname}")
                        n_sect += 1
                        so += 80
            idx += csz
    sm.freeze()
    exec_ranges.sort(key=lambda r: r[2])
    meta = {"container": "macho", "arm64_slices": len(slices),
            "headers": len(use), "exec_sections": n_sect,
            "exec_mappings": len(exec_ranges),
            "exec_mapping_bytes": sum(r[3] for r in exec_ranges),
            "section_overlaps": sm.overlaps}
    return exec_ranges, sm, meta


# ---------------------------------------------------------------------------
# the scan
# ---------------------------------------------------------------------------
CHUNK = 16 * 1024 * 1024


def chunk_ranges(exec_ranges, chunk=CHUNK):
    """Split executable ranges into <=chunk pieces, so --shard can balance.

    The cache's executable mappings are 5 ranges spanning three orders of
    magnitude (573,440 bytes to 1.82 GB), so sharding over whole ranges would
    put one job on 49% of the work. Chunking first makes the shards even and
    keeps the merge identity exact: every chunk belongs to exactly one shard
    and the chunk sizes sum to exec_mapping_bytes.
    """
    out = []
    for (path, foff, va, sz) in exec_ranges:
        done = 0
        while done < sz:
            take = min(chunk, sz - done)
            out.append((path, foff + done, va + done, take))
            done += take
    return out


def scan(exec_ranges, sm, max_bytes=0):
    cat_hits = collections.Counter()
    cat_bucket = collections.Counter()           # (cat, bucket) -> n
    enc_hits = collections.defaultdict(collections.Counter)   # cat -> key -> n
    enc_bucket = collections.defaultdict(collections.Counter)  # cat -> (key,bucket)
    bucket_bytes = collections.Counter()
    sect_bytes = collections.Counter()
    words_total = 0
    bytes_total = 0
    tail_bytes = 0
    t0 = time.time()

    # bucket byte accounting, computed from the section map against the
    # ranges rather than by counting words: this is the denominator split the
    # per-category percentages are quoted over. Every byte of every range
    # lands in exactly one bucket, so the three bucket totals sum to the
    # scanned byte count - the same identity a11_coverage_check.py enforces
    # on the capstone side.
    import bisect as _bi
    srows = sm.ranges()
    sstarts = [r[0] for r in srows]
    for (_p, _fo, va, sz) in exec_ranges:
        pos = va
        end = va + sz
        i = max(0, _bi.bisect_right(sstarts, va) - 1)
        while i < len(srows) and pos < end:
            a, b, kind, name = srows[i]
            i += 1
            if b <= pos:
                continue
            if a >= end:
                break
            a2, b2 = max(a, pos), min(b, end)
            if a2 > pos:
                bucket_bytes["unsectioned"] += a2 - pos
            bucket_bytes[kind] += b2 - a2
            sect_bytes[name] += b2 - a2
            pos = max(pos, b2)
        if pos < end:
            bucket_bytes["unsectioned"] += end - pos

    for (path, foff, va, sz) in exec_ranges:
        if max_bytes and bytes_total >= max_bytes:
            break
        with open(path, "rb", buffering=0) as f:
            done = 0
            while done < sz:
                take = min(CHUNK, sz - done)
                if max_bytes:
                    take = min(take, max(0, max_bytes - bytes_total))
                    if take <= 0:
                        break
                f.seek(foff + done)
                buf = f.read(take)
                if not buf:
                    break
                n = len(buf) - (len(buf) % 4)
                tail_bytes += len(buf) - n
                words = array.array("I")
                words.frombytes(buf[:n])
                base = va + done
                for i, w in enumerate(words):
                    r = classify(w)
                    if r is None:
                        continue
                    cat, key = r
                    bucket, _nm = sm.lookup(base + i * 4)
                    cat_hits[cat] += 1
                    cat_bucket[(cat, bucket)] += 1
                    enc_hits[cat][key] += 1
                    enc_bucket[cat][(key, bucket)] += 1
                words_total += n // 4
                bytes_total += len(buf)
                done += len(buf)
        print(f"    {bytes_total:,} bytes, {sum(cat_hits.values()):,} hits "
              f"({time.time() - t0:.0f}s)", flush=True)
    return {
        "words_scanned": words_total, "bytes_scanned": bytes_total,
        "unaligned_tail_bytes": tail_bytes,
        "bucket_bytes": dict(bucket_bytes.most_common()),
        "section_bytes_top": dict(sect_bytes.most_common(60)),
        "cat_hits": cat_hits, "cat_bucket": cat_bucket,
        "enc_hits": enc_hits, "enc_bucket": enc_bucket,
        "scan_seconds": round(time.time() - t0, 1),
    }


def noise_floor(n_words, seed=0x5DEECE66):
    """Hits per category on n_words of uniform-random data.

    Every predicate here constrains some number of bits, so every predicate
    has a rate at which arbitrary CONSTANT data satisfies it. Quoting an
    upper bound without that rate invites the reader to treat noise as
    signal: the SVE predicate is group membership on 4 bits, so roughly one
    word in 16 of a literal pool is an "SVE hit", while the AMX predicate
    constrains 22 bits and essentially never fires by accident.

    Measured rather than derived, with a fixed seed so the figure is
    reproducible, and reported next to the real counts so the comparison
    needs no arithmetic from the reader.
    """
    import random
    rnd = random.Random(seed)
    c = collections.Counter()
    for _ in range(n_words):
        r = classify(rnd.getrandbits(32))
        if r is not None:
            c[r[0]] += 1
    return c, n_words


def build_doc(res, meta, tag, shard, nf=None, nf_words=0):
    cats = {}
    for cat in CATEGORIES:
        n = res["cat_hits"].get(cat, 0)
        if not n:
            continue
        instr = res["cat_bucket"].get((cat, "instr"), 0)
        noncode = res["cat_bucket"].get((cat, "noncode"), 0)
        unsect = res["cat_bucket"].get((cat, "unsectioned"), 0)
        encs = []
        for key, kn in res["enc_hits"][cat].most_common(400):
            encs.append({
                "key": key, "n": kn,
                "instr": res["enc_bucket"][cat].get((key, "instr"), 0),
                "noncode": res["enc_bucket"][cat].get((key, "noncode"), 0),
                "unsectioned": res["enc_bucket"][cat].get((key, "unsectioned"), 0)})
        rec = {
            "hits_upper_bound": n,
            "in_instruction_sections": instr,
            "in_noncode_sections": noncode,
            "unsectioned": unsect,
            "distinct_encodings": len(res["enc_hits"][cat]),
            "architectural_effect_on_v82": (
                "UNDEFINED" if cat in UNDEFINED_ON_V82 else
                "NOP" if cat in NOP_ON_V82 else
                "TRAPS_TO_HOST" if cat in TRAPS_TO_HOST else "SEE_NOTE"),
            "encodings": encs,
        }
        if nf is not None and nf_words:
            exp = nf.get(cat, 0) * res["words_scanned"] / float(nf_words)
            rec["noise_floor"] = {
                "expected_hits_if_all_bytes_were_random": round(exp, 1),
                "signal_to_noise": (round(n / exp, 3) if exp else None),
                "note": "expected_hits scales the measured random-data rate "
                        "to this corpus. A ratio near 1 means the category's "
                        "upper bound is indistinguishable from constant-data "
                        "collisions and carries no information on its own.",
            }
        cats[cat] = rec
    return {
        "schema": SCHEMA, "image": tag, "shard": shard,
        "decoder": "none (bit-field predicates only)",
        "buckets": {
            "instr": "inside a section with S_ATTR_PURE_INSTRUCTIONS or "
                     "S_ATTR_SOME_INSTRUCTIONS: Apple declares it code",
            "noncode": "inside a section with neither instruction attribute: "
                       "Apple declares it data, so a hit is a decode collision",
            "unsectioned": "inside the executable mapping but outside every "
                           "section of every image",
        },
        "totals": {
            "words_scanned": res["words_scanned"],
            "bytes_scanned": res["bytes_scanned"],
            "unaligned_tail_bytes": res["unaligned_tail_bytes"],
            "bucket_bytes": res["bucket_bytes"],
            "hits_total": sum(res["cat_hits"].values()),
            "scan_seconds": res["scan_seconds"],
        },
        "container": meta,
        "section_bytes_top": res["section_bytes_top"],
        "categories": cats,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def do_merge(inputs, out, tag):
    """Fold shard census documents, and prove the shards tile the container.

    The check that matters: the shards' scanned bytes must sum to the
    container's whole exec_mapping_bytes. If they do not, a chunk was swept
    twice or not at all and every category total below is void - the same
    identity the capstone side enforces, applied here.
    """
    cats = collections.defaultdict(lambda: collections.Counter())
    encs = collections.defaultdict(lambda: collections.Counter())
    enc_b = collections.defaultdict(lambda: collections.Counter())
    tot = collections.Counter()
    buckets = collections.Counter()
    sect_b = collections.Counter()
    nf = collections.Counter()
    nf_words = 0
    meta = {}
    shards = []
    declared = None
    for p in inputs:
        try:
            with open(p, encoding="utf-8") as fh:
                d = json.load(fh)
        except Exception as exc:
            print(f"[!] {p}: {exc}", file=sys.stderr)
            continue
        meta = d.get("container", meta) or meta
        if declared is None:
            declared = (d.get("container") or {}).get("whole_container_exec_bytes")
        t = d.get("totals", {})
        tot["words_scanned"] += t.get("words_scanned", 0)
        tot["bytes_scanned"] += t.get("bytes_scanned", 0)
        tot["unaligned_tail_bytes"] += t.get("unaligned_tail_bytes", 0)
        tot["hits_total"] += t.get("hits_total", 0)
        buckets.update(t.get("bucket_bytes", {}))
        sect_b.update(d.get("section_bytes_top", {}))
        if d.get("noise_floor_raw") and not nf_words:
            nf.update(d["noise_floor_raw"])
            nf_words = d.get("noise_floor_words", 0)
        for cat, rec in (d.get("categories") or {}).items():
            c = cats[cat]
            c["hits_upper_bound"] += rec.get("hits_upper_bound", 0)
            c["in_instruction_sections"] += rec.get("in_instruction_sections", 0)
            c["in_noncode_sections"] += rec.get("in_noncode_sections", 0)
            c["unsectioned"] += rec.get("unsectioned", 0)
            for e in rec.get("encodings", []):
                encs[cat][e["key"]] += e.get("n", 0)
                for bk in ("instr", "noncode", "unsectioned"):
                    enc_b[cat][(e["key"], bk)] += e.get(bk, 0)
        shards.append({"file": p, "shard": d.get("shard"),
                       "bytes": t.get("bytes_scanned", 0)})

    out_cats = {}
    for cat in CATEGORIES:
        if cat not in cats:
            continue
        c = cats[cat]
        rec = {
            "hits_upper_bound": c["hits_upper_bound"],
            "in_instruction_sections": c["in_instruction_sections"],
            "in_noncode_sections": c["in_noncode_sections"],
            "unsectioned": c["unsectioned"],
            "distinct_encodings": len(encs[cat]),
            "architectural_effect_on_v82": (
                "UNDEFINED" if cat in UNDEFINED_ON_V82 else
                "NOP" if cat in NOP_ON_V82 else
                "TRAPS_TO_HOST" if cat in TRAPS_TO_HOST else "SEE_NOTE"),
            "encodings": [
                {"key": k, "n": n,
                 "instr": enc_b[cat].get((k, "instr"), 0),
                 "noncode": enc_b[cat].get((k, "noncode"), 0),
                 "unsectioned": enc_b[cat].get((k, "unsectioned"), 0)}
                for k, n in encs[cat].most_common(400)],
        }
        if nf_words:
            exp = nf.get(cat, 0) * tot["words_scanned"] / float(nf_words)
            rec["noise_floor"] = {
                "expected_hits_if_all_bytes_were_random": round(exp, 1),
                "signal_to_noise": (round(c["hits_upper_bound"] / exp, 3)
                                    if exp else None)}
        out_cats[cat] = rec

    bsum = sum(buckets.values())
    doc = {
        "schema": SCHEMA, "image": tag, "merged_from": shards,
        "shards": len(shards),
        "decoder": "none (bit-field predicates only)",
        "totals": dict(tot),
        "bucket_bytes": dict(buckets.most_common()),
        "bucket_byte_sum": bsum,
        "bucket_identity_holds": bsum == tot["bytes_scanned"],
        "declared_container_exec_bytes": declared,
        "shard_tiling_holds": (declared is not None
                               and tot["bytes_scanned"] == declared),
        "container": meta,
        "section_bytes_top": dict(sect_b.most_common(60)),
        "categories": out_cats,
        "noise_floor_words": nf_words,
        "noise_floor_raw": dict(nf) if nf_words else None,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)
    print(f"[+] merged {len(shards)} census shard(s) -> {out}")
    print(f"    bytes scanned        : {tot['bytes_scanned']:,}")
    print(f"    declared container   : {declared}")
    print(f"    shard tiling holds   : {doc['shard_tiling_holds']}")
    print(f"    bucket identity holds: {doc['bucket_identity_holds']} "
          f"({bsum:,} vs {tot['bytes_scanned']:,})")
    print(f"\n{'category':<20}{'upper bound':>13}{'code sect':>13}"
          f"{'data sect':>13}{'unsect':>11}{'noise':>13}{'S/N':>8}")
    for cat, rec in out_cats.items():
        nfr = rec.get("noise_floor") or {}
        print(f"{cat:<20}{rec['hits_upper_bound']:>13,}"
              f"{rec['in_instruction_sections']:>13,}"
              f"{rec['in_noncode_sections']:>13,}"
              f"{rec['unsectioned']:>11,}"
              f"{nfr.get('expected_hits_if_all_bytes_were_random', 0):>13,.0f}"
              f"{str(nfr.get('signal_to_noise', '-')):>8}")
    return 0 if (doc["bucket_identity_holds"] and doc["shard_tiling_holds"]) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("dsc", "macho", "merge"))
    ap.add_argument("--target", default=None)
    ap.add_argument("--inputs", nargs="*", default=[])
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag", default=None)
    ap.add_argument("--shard", default=None, help="I/N over executable ranges")
    ap.add_argument("--max-bytes", type=int, default=0)
    ap.add_argument("--noise-words", type=int, default=2_000_000,
                    help="uniform-random words used to measure each "
                         "predicate's constant-data collision rate. 0 skips.")
    args = ap.parse_args(argv)

    if args.mode == "merge":
        return do_merge(args.inputs, args.out, args.tag or "merged")
    if not args.target:
        raise SystemExit("FATAL: --target is required for this mode")
    tag = args.tag or os.path.basename(args.target.rstrip("/\\"))
    if args.mode == "dsc":
        ranges, sm, meta = dsc_ranges_and_sections(args.target)
    else:
        ranges, sm, meta = macho_ranges_and_sections(args.target)
    if not ranges:
        print(f"::error::no executable ranges in {args.target}", file=sys.stderr)
        return 1

    si, sn = 0, 1
    all_bytes = sum(r[3] for r in ranges)
    ranges = chunk_ranges(ranges)
    if args.shard:
        a, _, b = args.shard.partition("/")
        si, sn = int(a), int(b or 1)
        # Shard by CHUNK index, not range index: see chunk_ranges. meta keeps
        # the whole-container exec_mapping_bytes, so merging N shards must
        # reproduce it exactly or the merge says so.
        ranges = [r for i, r in enumerate(ranges) if i % sn == si]
    meta["whole_container_exec_bytes"] = all_bytes

    print(f"[*] {args.mode} {args.target}")
    print(f"[*] container: {json.dumps(meta)}")
    print(f"[*] shard {si}/{sn}: {len(ranges)} executable range(s), "
          f"{sum(r[3] for r in ranges):,} bytes")
    if meta.get("section_overlaps"):
        print(f"::warning::{meta['section_overlaps']} overlapping sections; "
              "bucket byte totals are approximate for those ranges")

    res = scan(ranges, sm, max_bytes=args.max_bytes)
    nf, nfw = (None, 0)
    if args.noise_words:
        print(f"[*] measuring the random-data collision rate over "
              f"{args.noise_words:,} words")
        nf, nfw = noise_floor(args.noise_words)
    doc = build_doc(res, meta, tag, f"{si}/{sn}", nf=nf, nf_words=nfw)
    doc["noise_floor_words"] = nfw
    doc["noise_floor_raw"] = dict(nf) if nf else None
    doc["shard_exec_bytes"] = sum(r[3] for r in ranges)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)

    print("\n" + "=" * 78)
    print(f"decoder-free bit-field census: {tag}  shard {si}/{sn}")
    print("=" * 78)
    print(f"words scanned : {res['words_scanned']:,}")
    print("bucket bytes  : " + ", ".join(
        f"{k}={v:,}" for k, v in res["bucket_bytes"].items()))
    print(f"\n{'category':<20}{'upper bound':>13}{'code sect':>13}"
          f"{'data sect':>13}{'unsect':>11}{'noise':>13}{'S/N':>8}  v8.2")
    for cat, rec in doc["categories"].items():
        nfr = rec.get("noise_floor") or {}
        print(f"{cat:<20}{rec['hits_upper_bound']:>13,}"
              f"{rec['in_instruction_sections']:>13,}"
              f"{rec['in_noncode_sections']:>13,}"
              f"{rec['unsectioned']:>11,}"
              f"{nfr.get('expected_hits_if_all_bytes_were_random', 0):>13,.0f}"
              f"{str(nfr.get('signal_to_noise', '-')):>8}"
              f"  {rec['architectural_effect_on_v82']}")
    print(f"\n[+] wrote {args.out} ({res['scan_seconds']}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
