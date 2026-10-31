#!/usr/bin/env python3
"""
sweep_kernelcache.py - full-coverage ARMv8.2-A incompatibility sweep
=====================================================================
Gate 1 / Gate 4 instrument for docs/compatibility-compiler.md.

What it does differently from macos-arm64-compat-scanner/scan_incompatible.py:

  1. Covers EVERY LC_FILESET_ENTRY and EVERY executable segment of each entry
     (not just com.apple.kernel / __TEXT_EXEC), plus the interstitial bytes of
     the outer MH_FILESET executable segments that no entry claims.
  2. Gives every byte of that universe a terminal state, and proves coverage
     arithmetically instead of asserting it.
  3. Global recursive-descent reachability over each executable segment
     (roots = LC_FUNCTION_STARTS + every direct branch target), instead of
     per-function linear walk with a "max forward target" heuristic.
  4. Closed-world classification: every mnemonic and every system register
     must be explicitly listed as baseline or above-baseline. Unlisted ones
     are emitted as UNCLASSIFIED_* findings, never silently treated as fine.
  5. Undecodable words are never dropped. They are resolved to a data state
     only with positive evidence (literal-pool target, non-code section,
     zero padding outside reachable code); otherwise they become
     UNKNOWN_ENCODING, which fails the gate.

Usage
-----
    py tools/sweep_kernelcache.py 25G83__MacOS/kernelcache.release.vma2.decompressed \
        --outdir analysis/compat

    py tools/sweep_kernelcache.py extracted_kernel/com.apple.kernel \
        --outdir analysis/compat/standalone --tag standalone-kernel

Options
    --outdir DIR        output directory (default analysis/compat)
    --tag NAME          label written into every record (default: file name)
    --entry ID          restrict to one fileset entry (debugging)
    --no-manifest       skip writing the per-finding JSONL (stats only)
    --max-manifest N    cap JSONL lines (0 = unlimited)

Outputs (in --outdir)
    coverage-manifest.jsonl     one JSON object per finding
    byte-coverage.json          byte terminal-state accounting
    summary.json                counts by category / kext / function
    mnemonic-census.json        every decoded mnemonic + its verdict
    sysreg-census.json          every MRS/MSR encoding + its verdict
    components.csv              component closure rows
    findings-by-function.jsonl  per-function aggregation (triage view)
"""

import argparse
import array
import bisect
import collections
import csv
import hashlib
import json
import os
import re
import struct
import sys
import time

import capstone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import armmac_baseline as B

# ---------------------------------------------------------------------------
# Mach-O constants
# ---------------------------------------------------------------------------
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_FILESET = 0xC
LC_SYMTAB = 0x2
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26
LC_FILESET_ENTRY = 0x80000035
VM_PROT_EXECUTE = 4
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

# ---------------------------------------------------------------------------
# Byte terminal states
# ---------------------------------------------------------------------------
ST_UNSET = 0
ST_CODE_BASELINE = 1
ST_CODE_SUPRA = 2
ST_DATA_NONCODE_SECTION = 3
ST_DATA_LITERAL_POOL = 4
ST_DATA_PADDING_ZERO = 5
ST_DATA_SEGMENT_GAP = 6
ST_DATA_UNREACHABLE_UNDECODABLE = 7
ST_UNKNOWN_ENCODING = 8
ST_DATA_REFERENCED_BLOB = 9
ST_DATA_INLINE_STRING = 10
ST_DATA_OR_TRAP_UDF = 11

STATE_NAMES = {
    ST_UNSET: "UNSET",
    ST_CODE_BASELINE: "CODE_BASELINE",
    ST_CODE_SUPRA: "CODE_SUPRA_BASELINE",
    ST_DATA_NONCODE_SECTION: "DATA_NONCODE_SECTION",
    ST_DATA_LITERAL_POOL: "DATA_LITERAL_POOL",
    ST_DATA_PADDING_ZERO: "DATA_PADDING_ZERO",
    ST_DATA_SEGMENT_GAP: "DATA_SEGMENT_GAP",
    ST_DATA_UNREACHABLE_UNDECODABLE: "DATA_UNREACHABLE_UNDECODABLE",
    ST_UNKNOWN_ENCODING: "UNKNOWN_ENCODING",
    ST_DATA_REFERENCED_BLOB: "DATA_REFERENCED_BLOB",
    ST_DATA_INLINE_STRING: "DATA_INLINE_STRING",
    ST_DATA_OR_TRAP_UDF: "DATA_OR_TRAP_UDF",
}
# States that fail the Gate-1 "every byte has a terminal state" requirement.
FAILING_STATES = {ST_UNSET, ST_UNKNOWN_ENCODING}
# Categories whose decode is routinely faked by random constant bytes, so a
# classified word may be absorbed into a proven data blob. Apple-specific and
# PAC/BTI categories are never absorbed.
ABSORBABLE_CATS = {B.CAT_SVE, B.CAT_SME_SVCR, B.CAT_MTE, B.CAT_ARCH_EXT,
                   B.CAT_OPT_V82, B.CAT_UNCLASSIFIED_MNEMONIC,
                   B.CAT_UNCLASSIFIED_SYSREG}
NEAR_DATA_STATES = {ST_DATA_REFERENCED_BLOB, ST_DATA_LITERAL_POOL,
                    ST_DATA_NONCODE_SECTION, ST_DATA_SEGMENT_GAP,
                    ST_DATA_INLINE_STRING, ST_DATA_OR_TRAP_UDF,
                    ST_DATA_PADDING_ZERO, ST_DATA_UNREACHABLE_UNDECODABLE}

# Largest slice handed to capstone in one pass-B call. Caps the decode loop's
# transient allocation at this size instead of letting it scale with the
# segment, which is what made a dyld-cache range exhaust memory
# (register-audit.md U1; see sweep_segment for the full note). MUST stay a
# multiple of 4 so no A64 instruction straddles a window edge.
DECODE_WINDOW = 1 << 18          # 256 KiB = 65,536 words
assert DECODE_WINDOW % 4 == 0
# States resolved only by weak (negative) evidence; reported separately.
WEAK_STATES = {ST_DATA_UNREACHABLE_UNDECODABLE}

CAT_SYSREG_EL23 = "SYSREG_EL2_EL3"

NUMERIC_SYSREG_RE = re.compile(r"^s(\d)_(\d)_c(\d+)_c(\d+)_(\d)$")
ZP_REG_RE = re.compile(r"\b[zp]\d+\b")
FP16_RE = re.compile(r"(\bh\d+\b|\.[248]h\b)")


# ---------------------------------------------------------------------------
# armmac-generic-v1 baseline produced by the profile task (A1)
# ---------------------------------------------------------------------------
FEATURE_CAT = (
    ("PAuth", B.CAT_PAC), ("PAC", B.CAT_PAC), ("EPAC", B.CAT_PAC),
    ("FPAC", B.CAT_PAC), ("CONSTPACFIELD", B.CAT_PAC),
    ("SME", B.CAT_SME_SVCR), ("SVE", B.CAT_SVE), ("MTE", B.CAT_MTE),
    ("BTI", B.CAT_BTI), ("APPLE_AMX", B.CAT_APPLE_AMX),
    ("APPLE_GXF", B.CAT_APPLE_GXF), ("APPLE_", B.CAT_IMPDEF_SYSREG),
)


class Baseline:
    """Loads analysis/compat/armmac-generic-v1-baseline.json when present."""

    def __init__(self, path):
        self.path = path
        self.loaded = False
        self.sysregs = {}
        self.features = {}
        self.meta = {}
        if not path or not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        for s in doc.get("sysreg_whitelist", []):
            self.sysregs[s["encoding"].lower()] = (s["name"], s["verdict"],
                                                   s.get("feature"),
                                                   s.get("min_el"))
        for ft in doc.get("features", []):
            self.features[ft["name"]] = ft["verdict"]
        self.meta = {
            "baseline_id": doc.get("baseline_id"),
            "schema_version": doc.get("schema_version"),
            "sysreg_entries": len(self.sysregs),
            "feature_entries": len(self.features),
            "path": path,
        }
        self.loaded = True

    @staticmethod
    def norm_feature(feat):
        if not feat:
            return None
        return re.split(r"[ (/:]", feat.strip())[0]

    def feature_verdict(self, feat):
        if not self.loaded:
            return None
        f = self.norm_feature(feat)
        return self.features.get(f, "NEEDS_REVIEW") if f else None

    @staticmethod
    def category_for_feature(feat, min_el=None):
        f = feat or ""
        for needle, cat in FEATURE_CAT:
            if needle in f:
                return cat
        if min_el in ("EL2", "EL3"):
            return CAT_SYSREG_EL23
        return B.CAT_ARCH_EXT


BASELINE = Baseline(None)

# Default feature name per finding category, for baseline verdict lookup.
CAT_FEATURE = {
    B.CAT_PAC: "FEAT_PAuth", B.CAT_BTI: "FEAT_BTI", B.CAT_SVE: "FEAT_SVE",
    B.CAT_SME_SVCR: "FEAT_SME", B.CAT_MTE: "FEAT_MTE",
    B.CAT_APPLE_AMX: "APPLE_AMX", B.CAT_APPLE_GXF: "APPLE_GXF",
}
# Categories whose baseline verdict follows from the baseline's own rules
# rather than from a FEAT_ table lookup.
CAT_FIXED_VERDICT = {
    B.CAT_IMPDEF_SYSREG: "IMPDEF",
    B.CAT_APPLE_RESERVED: "VENDOR_PRIVATE",
    B.CAT_HVC_SMC: "NEEDS_REVIEW",
    B.CAT_UNKNOWN_ENCODING: "NEEDS_REVIEW",
    B.CAT_UNCLASSIFIED_MNEMONIC: "NEEDS_REVIEW",
    B.CAT_UNCLASSIFIED_SYSREG: "NEEDS_REVIEW",
    CAT_SYSREG_EL23: "OUT_OF_BASELINE_FATAL",
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def uleb128(buf, off):
    result = 0
    shift = 0
    n = len(buf)
    while off < n:
        byte = buf[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break
        shift += 7
    return result, off


def sx(val, bits):
    if val & (1 << (bits - 1)):
        val -= 1 << bits
    return val


def branch_info(w):
    """Raw-encoding control-flow classification.

    returns (kind, target_delta)
      kind: 'b'  unconditional direct branch      (terminates fallthrough)
            'bl' direct call                      (fallthrough continues)
            'c'  conditional direct branch        (fallthrough continues)
            't'  terminator, no static target     (ret/br/brk/eret/udf...)
            None ordinary instruction
    """
    op26 = w >> 26
    if op26 == 0x05:                                   # B
        return "b", sx(w & 0x03FFFFFF, 26) << 2
    if op26 == 0x25:                                   # BL
        return "bl", sx(w & 0x03FFFFFF, 26) << 2
    hi8 = w >> 24
    if hi8 in (0x54, 0xD4):                            # B.cond / BC.cond / exc
        if hi8 == 0x54:
            return "c", sx((w >> 5) & 0x7FFFF, 19) << 2
        # 0xD4: SVC/HVC/SMC/BRK/HLT/DCPS -> BRK/HLT terminate
        op = (w >> 21) & 0x7
        if op in (1, 2, 5):                            # BRK, HLT, DCPS
            return "t", 0
        return None, 0
    if (w & 0x7F000000) in (0x34000000, 0x35000000):   # CBZ / CBNZ
        return "c", sx((w >> 5) & 0x7FFFF, 19) << 2
    if (w & 0x7E000000) == 0x36000000:                 # TBZ / TBNZ
        return "c", sx((w >> 5) & 0x3FFF, 14) << 2
    if (w & 0xFE000000) == 0xD6000000:                 # BR/BLR/RET/ERET + PAC
        op = (w >> 21) & 0xF
        if op in (0x1, 0x9):                           # BLR / BLRAA(Z)
            return None, 0
        return "t", 0
    if w == 0 or (w & 0xFFFF0000) == 0:                # UDF #imm16
        return "t", 0
    return None, 0


def literal_target(w, pc):
    """PC-relative literal load -> (target_va, nbytes) or None."""
    top = w & 0xFF000000
    if top == 0x18000000:                              # LDR Wt, label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 4
    if top == 0x58000000:                              # LDR Xt, label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 8
    if top == 0x98000000:                              # LDRSW Xt, label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 4
    if top == 0xD8000000:                              # PRFM label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 8
    if top == 0x1C000000:                              # LDR St, label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 4
    if top == 0x5C000000:                              # LDR Dt, label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 8
    if top == 0x9C000000:                              # LDR Qt, label
        return pc + (sx((w >> 5) & 0x7FFFF, 19) << 2), 16
    return None


def sysreg_fields(w):
    """MRS/MSR (register) -> (is_read, op0, op1, crn, crm, op2, rt) or None."""
    if (w >> 22) != 0x354 or ((w >> 20) & 1) != 1:
        return None
    return (
        bool((w >> 21) & 1),
        2 + ((w >> 19) & 1),
        (w >> 16) & 7,
        (w >> 12) & 0xF,
        (w >> 8) & 0xF,
        (w >> 5) & 7,
        w & 0x1F,
    )


def sysinstr_fields(w):
    """Any word of the system-instruction class 0xD5000000-0xD53FFFFF.

    -> (is_read, op0, op1, crn, crm, op2, rt) with op0 in 0..3, or None.

    sysreg_fields() above only admits op0 in {2,3}, the MRS/MSR register
    forms. The other two quarters of this class carry real state accesses as
    well - op0=0b00 is PSTATE (MSR immediate) plus the hint and barrier space,
    op0=0b01 is SYS/SYSL, which includes the IMPLEMENTATION DEFINED
    system-instruction space at CRn 11 and 15 - so they need their own
    field-indexed classification rather than being judged by whatever
    mnemonic text a disassembler prints.
    """
    if (w >> 22) != 0x354:
        return None
    return (
        bool((w >> 21) & 1),
        (w >> 19) & 3,
        (w >> 16) & 7,
        (w >> 12) & 0xF,
        (w >> 8) & 0xF,
        (w >> 5) & 7,
        w & 0x1F,
    )


def pcrel_data_ref(w, pc):
    """ADR / ADRP page computation -> (kind, value, rd, rn)."""
    if (w & 0x9F000000) == 0x10000000:                 # ADR Xd, label
        imm = sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21)
        return "adr", pc + imm, w & 0x1F, None
    if (w & 0x9F000000) == 0x90000000:                 # ADRP Xd, page
        imm = sx((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3), 21) << 12
        return "adrp", (pc & ~0xFFF) + imm, w & 0x1F, None
    if (w & 0xFF800000) == 0x91000000:                 # ADD Xd, Xn, #imm12{,lsl 12}
        imm = (w >> 10) & 0xFFF
        if (w >> 22) & 1:
            imm <<= 12
        return "add", imm, w & 0x1F, (w >> 5) & 0x1F
    # load/store register, unsigned immediate offset: scale by access size
    scale = LDST_UIMM.get(w & 0xFFC00000)
    if scale is not None:
        return "ldst", ((w >> 10) & 0xFFF) * scale, w & 0x1F, (w >> 5) & 0x1F
    scale = LDST_PAIR.get(w & 0xFFC00000)
    if scale is not None:
        return "ldst", sx((w >> 15) & 0x7F, 7) * scale, w & 0x1F, (w >> 5) & 0x1F
    return None


# Load/store (unsigned immediate) opcode -> offset scale.
LDST_UIMM = {
    0x39400000: 1, 0x39000000: 1,          # LDRB  / STRB
    0x39800000: 1, 0x39C00000: 1,          # LDRSB
    0x79400000: 2, 0x79000000: 2,          # LDRH  / STRH
    0x79800000: 2, 0x79C00000: 2,          # LDRSH
    0xB9400000: 4, 0xB9000000: 4,          # LDR W / STR W
    0xB9800000: 4,                         # LDRSW
    0xF9400000: 8, 0xF9000000: 8,          # LDR X / STR X
    0x3D400000: 1, 0x3D000000: 1,          # LDR B / STR B (SIMD)
    0x7D400000: 2, 0x7D000000: 2,          # LDR H / STR H
    0xBD400000: 4, 0xBD000000: 4,          # LDR S / STR S
    0xFD400000: 8, 0xFD000000: 8,          # LDR D / STR D
    0x3DC00000: 16, 0x3D800000: 16,        # LDR Q / STR Q
}
# Load/store pair (signed offset) opcode -> scale.
LDST_PAIR = {
    0x29400000: 4, 0x29000000: 4,          # LDP/STP W
    0xA9400000: 8, 0xA9000000: 8,          # LDP/STP X
    0x2D400000: 4, 0x2D000000: 4,          # LDP/STP S
    0x6D400000: 8, 0x6D000000: 8,          # LDP/STP D
    0xAD400000: 16, 0xAD000000: 16,        # LDP/STP Q
}


def textual_word(w):
    for sh in (0, 8, 16, 24):
        b = (w >> sh) & 0xFF
        if b in (0x00, 0x09, 0x0A, 0x0D):
            continue
        if 0x20 <= b <= 0x7E:
            continue
        return False
    return True


def sve_sme_class(w):
    """Words in encoding spaces that are UNALLOCATED on ARMv8.2-A but are
    allocated to SVE / SME by later architecture versions. capstone 5.0.1 has
    no SME decoder, so SME words reach us as 'undecodable'.

      bits[31:25] == 0b0000010  -> SVE / SME stack-allocation group
      bits[31:22] == 0b1110000100 -> SME LDR/STR ZA-array and ZT0 group
                                     (cross-checked against adjacent words
                                      capstone *does* decode as
                                      'str za[wN, #k], [xM, #k, mul vl]')
    """
    if (w >> 22) == 0x384:
        if (w & 0xFFFFFC1F) == 0xE11F8000:
            return B.CAT_SME_SVCR, f"ldr zt0, [x{(w >> 5) & 0x1F}] (FEAT_SME2 ZT0)"
        if (w & 0xFFFFFC1F) == 0xE13F8000:
            return B.CAT_SME_SVCR, f"str zt0, [x{(w >> 5) & 0x1F}] (FEAT_SME2 ZT0)"
        return B.CAT_SME_SVCR, "SME ZA-array / ZT0 load-store group"
    if (w >> 25) != 0b0000010:
        return None
    if (w & 0xFFFFF800) == 0x04BF5800:                 # RDSVL Xd, #imm6 (SME)
        return (B.CAT_SME_SVCR,
                f"rdsvl x{w & 0x1F}, #{(w >> 5) & 0x3F} (SME streaming vector length)")
    if (w & 0xFFFFF800) == 0x04BF5000:                 # RDVL Xd, #imm6 (SVE)
        return B.CAT_SVE, f"rdvl x{w & 0x1F}, #{(w >> 5) & 0x3F}"
    return B.CAT_SVE, "SVE/SME encoding space (UNALLOCATED on ARMv8.2-A)"


def strong_textual(w):
    """All four bytes printable ASCII, or printable followed by NUL padding."""
    bs = [(w >> s) & 0xFF for s in (0, 8, 16, 24)]
    seen_nul = False
    letters = 0
    for b in bs:
        if seen_nul:
            if b != 0:
                return None
            continue
        if b == 0:
            seen_nul = True
            continue
        if not (0x20 <= b <= 0x7E):
            return None
        if (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A):
            letters += 1
    return letters, seen_nul


def apple_reserved_class(w):
    """Words in the ARMv8 reserved/UNALLOCATED space 0x00200000-0x003fffff.

    Apple's AMX coprocessor ops live here as
        0x00201000 | (op << 5) | operand
    with op taken from the published m1n1/Asahi op numbering. Other words in
    the space are reported as APPLE_RESERVED_SPACE rather than guessed at.
    """
    if (w & 0xFFE00000) != 0x00200000:
        return None
    if (w & 0xFFFFFC00) == 0x00201000:
        op = (w >> 5) & 0x1F
        names = {
            0: "ldx", 1: "ldy", 2: "stx", 3: "sty", 4: "ldz", 5: "stz",
            6: "ldzi", 7: "stzi", 8: "extrx", 9: "extry", 10: "fma64",
            11: "fms64", 12: "fma32", 13: "fms32", 14: "mac16", 15: "fma16",
            16: "fms16", 17: "set/clr", 18: "vecint", 19: "vecfp",
            20: "matint", 21: "matfp", 22: "genlut",
        }
        return B.CAT_APPLE_AMX, f"AMX op={op} ({names.get(op, '?')}) operand={w & 0x1F}"
    return B.CAT_APPLE_RESERVED, "reserved/UNALLOCATED encoding space 0x002xxxxx"


# ---------------------------------------------------------------------------
# container parsing
# ---------------------------------------------------------------------------
class Section:
    __slots__ = ("segname", "sectname", "addr", "size", "offset", "flags")


class Segment:
    __slots__ = ("name", "vmaddr", "vmsize", "fileoff", "filesize",
                 "maxprot", "initprot", "sections")

    @property
    def is_exec(self):
        return bool(self.initprot & VM_PROT_EXECUTE)


class Entry:
    __slots__ = ("entry_id", "vmaddr", "fileoff", "segments", "func_starts",
                 "syms", "sym_addrs", "fs_base")


def parse_macho(data, header_off, entry_id):
    magic, cputype = struct.unpack("<II", data[header_off:header_off + 8])
    if magic != MH_MAGIC_64:
        raise ValueError(f"{entry_id}: bad magic {magic:#x} at {header_off:#x}")
    if cputype != CPU_TYPE_ARM64:
        raise ValueError(f"{entry_id}: non-arm64 cputype {cputype:#x}")
    ncmds = struct.unpack("<I", data[header_off + 16:header_off + 20])[0]

    e = Entry()
    e.entry_id = entry_id
    e.fileoff = header_off
    e.segments = []
    e.func_starts = []
    e.syms = []
    e.fs_base = None
    fs_off = fs_sz = None

    idx = header_off + 32
    for _ in range(ncmds):
        cmd, csz = struct.unpack("<II", data[idx:idx + 8])
        if csz < 8:
            raise ValueError(f"{entry_id}: bogus load command size {csz}")
        c = data[idx + 8:idx + csz]
        if cmd == LC_SEGMENT_64:
            s = Segment()
            s.name = c[:16].rstrip(b"\x00").decode("ascii", "replace")
            (s.vmaddr, s.vmsize, s.fileoff, s.filesize,
             s.maxprot, s.initprot, nsects, _flags) = struct.unpack("<QQQQIIII", c[16:64])
            s.sections = []
            so = 64
            for _s in range(nsects):
                raw = c[so:so + 80]
                if len(raw) < 80:
                    raise ValueError(f"{entry_id}: truncated section in {s.name}")
                sec = Section()
                sec.sectname = raw[:16].rstrip(b"\x00").decode("ascii", "replace")
                sec.segname = raw[16:32].rstrip(b"\x00").decode("ascii", "replace")
                sec.addr, sec.size, sec.offset, _align, _ro, _nr, sec.flags = \
                    struct.unpack("<QQIIIII", raw[32:68])
                s.sections.append(sec)
                so += 80
            if e.fs_base is None:
                e.fs_base = s.vmaddr
            e.segments.append(s)
        elif cmd == LC_FUNCTION_STARTS:
            fs_off, fs_sz = struct.unpack("<II", c[:8])
        elif cmd == LC_SYMTAB:
            symoff, nsyms, stroff, strsz = struct.unpack("<IIII", c[:16])
            strtab = data[stroff:stroff + strsz]
            for si in range(nsyms):
                o = symoff + si * 16
                strx, stype, _sect, _desc, sval = struct.unpack("<IBBhQ", data[o:o + 16])
                if sval and strx < len(strtab):
                    end = strtab.find(b"\x00", strx)
                    name = strtab[strx:end if end >= 0 else None].decode("ascii", "replace")
                    if name:
                        e.syms.append((sval, name))
        idx += csz

    if fs_off is not None and fs_sz:
        raw = data[fs_off:fs_off + fs_sz]
        cur = e.fs_base or 0
        off = 0
        first = True
        while off < len(raw):
            delta, off = uleb128(raw, off)
            if delta == 0 and not first:
                break
            if delta == 0 and first:
                break
            first = False
            cur += delta
            e.func_starts.append(cur)
    e.func_starts.sort()
    e.syms.sort()
    e.sym_addrs = [s[0] for s in e.syms]
    return e


def parse_container(path):
    with open(path, "rb") as f:
        data = f.read()
    magic, cputype, _cpusub, filetype, ncmds = struct.unpack("<IIIII", data[:20])
    if magic != MH_MAGIC_64:
        raise SystemExit(f"FATAL: {path} is not a 64-bit Mach-O (magic={magic:#x}). "
                         "Unknown format must fail, not be skipped.")
    if cputype != CPU_TYPE_ARM64:
        raise SystemExit(f"FATAL: {path} cputype={cputype:#x} is not arm64.")

    outer_segs = []
    entries = []
    idx = 32
    for _ in range(ncmds):
        cmd, csz = struct.unpack("<II", data[idx:idx + 8])
        c = data[idx + 8:idx + csz]
        if cmd == LC_SEGMENT_64:
            s = Segment()
            s.name = c[:16].rstrip(b"\x00").decode("ascii", "replace")
            (s.vmaddr, s.vmsize, s.fileoff, s.filesize,
             s.maxprot, s.initprot, _nsects, _fl) = struct.unpack("<QQQQIIII", c[16:64])
            s.sections = []
            outer_segs.append(s)
        elif cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff, eoff, _rsv = struct.unpack("<QQII", c[:24])
            eid = c[eoff - 8:].split(b"\x00")[0].decode("ascii", "replace")
            entries.append((eid, vmaddr, fileoff))
        idx += csz

    if filetype == MH_FILESET:
        if not entries:
            raise SystemExit("FATAL: MH_FILESET with zero LC_FILESET_ENTRY.")
        parsed = [parse_macho(data, fo, eid) for eid, _vm, fo in entries]
    else:
        parsed = [parse_macho(data, 0, os.path.basename(path))]
    return data, filetype, outer_segs, parsed


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------
class Classifier:
    def __init__(self):
        self.mnem_census = collections.Counter()
        # (mnemonic, verdict) -> n. A mnemonic can carry several verdicts: `mov`
        # is baseline as `mov x0, x1` and SVE as `mov z0.s, p0/m, z1.s`.
        self.mnem_verdict = collections.Counter()
        self.sysreg_census = collections.Counter()
        self.sysreg_verdict = {}
        # op0 in {0,1}: SYS / SYSL and MSR-immediate (PSTATE). Kept in its own
        # census so that sysreg-census.json keeps meaning exactly what it
        # meant before (MRS/MSR register forms only).
        self.sysinstr_census = collections.Counter()
        self.sysinstr_verdict = {}

    def classify_mnemonic(self, mnem, ops):
        """-> None if baseline, else (category, detail, feature, severity)."""
        if mnem in B.SUPRA_MNEMONICS:
            cat, feat, sev = B.SUPRA_MNEMONICS[mnem]
            if mnem in B.SVE_AMBIGUOUS_MNEMONICS and not ZP_REG_RE.search(ops):
                pass  # AdvSIMD / base form, fall through to baseline check
            else:
                self.mnem_verdict[(mnem, f"{cat}:{feat}")] += 1
                return cat, f"{mnem} {ops}".strip(), feat, sev
        if ZP_REG_RE.search(ops) and mnem not in ("msr", "mrs", "sys", "sysl"):
            self.mnem_verdict[(mnem, f"{B.CAT_SVE}:FEAT_SVE/SME(z/p operand)")] += 1
            return B.CAT_SVE, f"{mnem} {ops}".strip(), "FEAT_SVE/SME", "block"
        if mnem in B.BASELINE_MNEMONICS or mnem.startswith("b."):
            if mnem in B.FP_ARITH_MNEMONICS and FP16_RE.search(ops):
                self.mnem_verdict[(mnem, f"{B.CAT_OPT_V82}:FEAT_FP16")] += 1
                return (B.CAT_OPT_V82, f"{mnem} {ops}".strip(), "FEAT_FP16(v8.2 opt)",
                        "likely_present")
            self.mnem_verdict[(mnem, "BASELINE")] += 1
            return None
        self.mnem_verdict[(mnem, B.CAT_UNCLASSIFIED_MNEMONIC)] += 1
        return (B.CAT_UNCLASSIFIED_MNEMONIC, f"{mnem} {ops}".strip(),
                "not in baseline or above-baseline table", "block")

    def classify_sysreg(self, w, mnem, ops):
        f = sysreg_fields(w)
        if f is None:
            return None
        is_read, op0, op1, crn, crm, op2 = f[:6]
        enc = f"s{op0}_{op1}_c{crn}_c{crm}_{op2}"
        # LLVM/capstone symbolic name, if it has one
        name = None
        for tok in (t.strip().lower() for t in ops.split(",")):
            if not tok:
                continue
            if NUMERIC_SYSREG_RE.match(tok):
                name = None
                break
            if tok in ("xzr", "wzr") or re.match(r"^[wx]\d+$", tok):
                continue
            name = tok
            break
        key = name or enc
        self.sysreg_census[(enc, key)] += 1

        # The A1 baseline is authoritative when it covers the encoding.
        if BASELINE.loaded and enc in BASELINE.sysregs:
            bname, bverdict, bfeat, bminel = BASELINE.sysregs[enc]
            if bverdict == "IN_BASELINE":
                self.sysreg_verdict.setdefault(key, "BASELINE(armmac-generic-v1)")
                return None
            if bverdict in ("IMPDEF", "VENDOR_PRIVATE"):
                cat = B.CAT_IMPDEF_SYSREG
            else:
                cat = BASELINE.category_for_feature(bfeat, bminel)
            sev = "degrade" if bverdict == "OUT_OF_BASELINE_BENIGN" else "block"
            self.sysreg_verdict[key] = f"{cat}:{bverdict}:{bfeat or bminel}"
            detail = (f"{bfeat or 'EL2_EL3_REGISTER'}: {enc} {bname} "
                      f"verdict={bverdict} min_el={bminel or '-'}")
            return cat, f"{mnem} {ops}".strip(), detail, sev, enc, key

        if crn in (11, 15):
            self.sysreg_verdict[key] = (
                f"{B.CAT_IMPDEF_SYSREG}:CRn={crn} is IMPLEMENTATION DEFINED (ARM ARM)")
            return (B.CAT_IMPDEF_SYSREG, f"{mnem} {ops}".strip(),
                    f"{enc} CRn={crn} IMPDEF", "block", enc, key)
        if name is None:
            # Unnamed and outside CRn 11/15, so it is NOT in the IMP-DEF
            # register space: it is an unallocated encoding of the
            # architectural space. Calling that "IMPDEF" asserts a vendor
            # meaning the encoding does not carry (and for op0=2 the IMP-DEF
            # sub-space rule is itself unverified - see the baseline's
            # unverified-items list). Report it, but as needing review.
            self.sysreg_verdict[key] = (
                f"{B.CAT_UNCLASSIFIED_SYSREG}:unallocated in the architectural "
                f"register space (op0={op0}, CRn={crn} is not an IMP-DEF CRn)")
            return (B.CAT_UNCLASSIFIED_SYSREG, f"{mnem} {ops}".strip(),
                    f"{enc} unallocated: no architectural name and CRn={crn} is "
                    f"outside the IMP-DEF space (CRn 11/15); "
                    f"{'debug/trace' if op0 == 2 else 'non-debug'} half, "
                    "IMP-DEF sub-space rule unverified",
                    "block", enc, key)
        if name in B.SUPRA_SYSREGS:
            cat, feat = B.SUPRA_SYSREGS[name]
            self.sysreg_verdict[key] = f"{cat}:{feat}"
            return cat, f"{mnem} {ops}".strip(), f"{feat} ({enc})", "block", enc, key
        if name in B.BASELINE_SYSREGS or re.match(
                r"^(dbgb[cv]r|dbgw[cv]r|pmevcntr|pmevtyper|icc_ap[01]r|ich_ap[01]r|ich_lr)\d+", name):
            self.sysreg_verdict.setdefault(key, "BASELINE")
            return None
        self.sysreg_verdict[key] = B.CAT_UNCLASSIFIED_SYSREG
        return (B.CAT_UNCLASSIFIED_SYSREG, f"{mnem} {ops}".strip(),
                f"{enc} name={name} not in baseline or above-baseline table",
                "block", enc, key)


    # -- op0 = 0b01: SYS / SYSL -------------------------------------------
    def classify_sys_instruction(self, w, mnem, ops):
        """Field-indexed classification of the SYS / SYSL space.

        -> None if baseline, else (category, disasm, detail, severity).

        The operation identity is (L, op1, CRn, CRm, op2); Rt is an operand.
        B.SYS_NAMED_ENC holds every encoding the reference decoder names
        (229 of 32,768, all in CRn 7/8/9), so anything outside it is
        unallocated and anything unallocated inside CRn 11/15 is the IMP-DEF
        system-instruction space.
        """
        L, op0, op1, crn, crm, op2, _rt = sysinstr_fields(w)
        form = f"{'sysl' if L else 'sys'} #{op1}, c{crn}, c{crm}, #{op2}"
        op = B.SYS_NAMED_ENC.get((int(L), op1, crn, crm, op2))
        key = op or form
        self.sysinstr_census[(form, key)] += 1
        text = f"{mnem} {ops}".strip()

        if op is not None:
            if op in B.SUPRA_SYS_OPS:
                cat, feat = B.SUPRA_SYS_OPS[op]
                self.sysinstr_verdict[key] = f"{cat}:{feat}"
                return cat, text, f"{feat} ({form} = {op})", "block"
            if op in B.BASELINE_SYS_OPS:
                self.sysinstr_verdict.setdefault(key, "BASELINE")
                return None
            era = B.sys_op_era(op)
            if era is not None:
                cat, feat = era
                self.sysinstr_verdict[key] = f"{cat}:{feat}"
                return cat, text, f"{feat} ({form} = {op})", "block"
            self.sysinstr_verdict[key] = B.CAT_UNCLASSIFIED_SYSREG
            return (B.CAT_UNCLASSIFIED_SYSREG, text,
                    f"{form} = {op}: architectural SYS operation that is in "
                    "neither the baseline nor the above-baseline era table",
                    "block")

        if crn in (11, 15):
            self.sysinstr_verdict[key] = (
                f"{B.CAT_IMPDEF_SYSREG}:op0=0b01 CRn={crn} IMP-DEF "
                "system-instruction space")
            return (B.CAT_IMPDEF_SYSREG, text,
                    f"{form}: op0=0b01 with CRn={crn} is the IMPLEMENTATION "
                    "DEFINED system-instruction space; no architectural "
                    "operation is allocated here (confidence: medium, see "
                    "baseline rule 2)", "block")
        self.sysinstr_verdict[key] = (
            f"{B.CAT_UNCLASSIFIED_SYSREG}:unallocated SYS/SYSL encoding")
        return (B.CAT_UNCLASSIFIED_SYSREG, text,
                f"{form}: unallocated SYS/SYSL encoding - no architectural "
                f"operation and CRn={crn} is outside the IMP-DEF space "
                "(CRn 11/15); UNDEFINED on a baseline PE", "block")

    # -- op0 = 0b00: MSR immediate (PSTATE), hints, barriers ---------------
    def classify_pstate(self, w, mnem, ops):
        """-> None if baseline, 'MNEMONIC' to defer to mnemonic classification,
        else (category, disasm, detail, severity)."""
        _L, _op0, op1, crn, crm, op2, _rt = sysinstr_fields(w)
        text = f"{mnem} {ops}".strip()
        if crn == 4:
            form = f"msr-imm op1={op1} CRm={crm} op2={op2}"
            ent = B.PSTATE_FIELDS.get((op1, op2))
            key = ent[0] if ent else f"msr-imm op1={op1} op2={op2}"
            self.sysinstr_census[(form, key)] += 1
            if ent is None:
                self.sysinstr_verdict[key] = (
                    f"{B.CAT_UNCLASSIFIED_SYSREG}:unallocated PSTATE field")
                return (B.CAT_UNCLASSIFIED_SYSREG, text,
                        f"{form}: unallocated PSTATE field - the architecture "
                        "allocates 10 of the 64 (op1, op2) slots and this is "
                        "not one of them; UNDEFINED on a baseline PE", "block")
            field, cat, feat = ent
            if cat is None:
                self.sysinstr_verdict.setdefault(key, "BASELINE")
                return None
            self.sysinstr_verdict[key] = f"{cat}:{feat}"
            return cat, text, f"{feat}: PSTATE.{field} via {form}", "block"
        if crn not in B.OP0_0_ALLOCATED_CRN:
            form = f"op0=0 op1={op1} CRn={crn} CRm={crm} op2={op2}"
            self.sysinstr_census[(form, "<unallocated op0=0 CRn>")] += 1
            self.sysinstr_verdict["<unallocated op0=0 CRn>"] = (
                f"{B.CAT_UNCLASSIFIED_SYSREG}:unallocated op0=0b00 CRn")
            return (B.CAT_UNCLASSIFIED_SYSREG, text,
                    f"{form}: op0=0b00 holds named encodings only at "
                    "CRn 1/2/3/4; this CRn is UNALLOCATED", "block")
        # CRn 1/2/3: hint, barrier and CLREX space. These decode to real
        # mnemonics (nop / isb / dsb / hint #N / bti / pacia1716 ...) and the
        # mnemonic tables already carry the era judgement for each. But if the
        # decoder fell back to the raw `sys`/`msr S0_...` form it recognised
        # nothing, and deferring to the mnemonic tables would accept the word
        # as baseline on the strength of the word `sys` alone.
        if mnem in ("sys", "sysl") or NUMERIC_SYSREG_RE.match(
                ops.split(",")[0].strip().lower()):
            form = f"op0=0 op1={op1} CRn={crn} CRm={crm} op2={op2}"
            key = "<unaliased op0=0 CRn 1/2/3>"
            self.sysinstr_census[(form, key)] += 1
            self.sysinstr_verdict[key] = (
                f"{B.CAT_UNCLASSIFIED_SYSREG}:decoder produced no alias")
            return (B.CAT_UNCLASSIFIED_SYSREG, text,
                    f"{form}: inside the op0=0b00 hint/barrier/CLREX space but "
                    "the decoder produced no alias, so no era judgement is "
                    "available for it", "block")
        return "MNEMONIC"


SYS_OP_RE = re.compile(r"^(dc|ic|at|tlbi)$")


def classify_sys_alias(mnem, ops):
    op = ops.split(",")[0].strip().lower()
    if op in B.SUPRA_SYS_OPS:
        cat, feat = B.SUPRA_SYS_OPS[op]
        return cat, f"{mnem} {ops}".strip(), feat, "block"
    if op in B.BASELINE_SYS_OPS:
        return None
    return (B.CAT_UNCLASSIFIED_SYSREG, f"{mnem} {ops}".strip(),
            f"{mnem} operation '{op}' not in baseline or above-baseline table", "block")


# ---------------------------------------------------------------------------
# the sweep
# ---------------------------------------------------------------------------
class Sweep:
    def __init__(self, data, tag, outdir, write_manifest=True, max_manifest=0):
        self.data = data
        self.tag = tag
        self.outdir = outdir
        self.cls = Classifier()
        self.state_bytes = collections.Counter()
        self.state_bytes_by_kext = collections.defaultdict(collections.Counter)
        self.cat_counts = collections.Counter()
        self.cat_sev_counts = collections.Counter()
        self.kext_counts = collections.Counter()
        self.func_counts = collections.Counter()
        self.feature_counts = collections.Counter()
        self.findings_total = 0
        self.unknown_list = []
        self.unclassified_list = []
        self.hvc_list = []
        self.amx_list = []
        self.reserved_list = []
        self.gxf_list = []
        self.decoder_conflicts = []
        self.extra_bytes = collections.Counter()
        self.components = []
        self.va_hits = {}
        self.va_map = []
        self.baseline_verdicts = collections.Counter()
        self.baseline_verdict_by_cat = collections.Counter()
        self.write_manifest = write_manifest
        self.max_manifest = max_manifest
        self.manifest_lines = 0
        self.fn_agg = collections.defaultdict(lambda: collections.Counter())
        self.fn_meta = {}
        os.makedirs(outdir, exist_ok=True)
        self.mf = (open(os.path.join(outdir, "coverage-manifest.jsonl"), "w",
                        encoding="utf-8", newline="\n") if write_manifest else None)
        self.cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.cs.detail = False
        self.csd = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        self.csd.detail = True

    # -- finding emission -------------------------------------------------
    def emit(self, kext, seg, sect, va, off, word, disasm, cat, detail,
             feature, sev, reach, fn_entry, fn_sym, note=None, near_data=False):
        self.findings_total += 1
        if not reach:
            self.extra_bytes["findings_unreachable"] += 1
        if near_data:
            self.extra_bytes["findings_adjacent_to_data"] += 1
        bverdict = CAT_FIXED_VERDICT.get(cat)
        if bverdict is None:
            bverdict = (BASELINE.feature_verdict(feature or CAT_FEATURE.get(cat))
                        or "NO_BASELINE_LOADED")
        self.baseline_verdicts[bverdict] += 1
        self.baseline_verdict_by_cat[(cat, bverdict)] += 1
        self.cat_counts[cat] += 1
        self.cat_sev_counts[(cat, sev)] += 1
        self.kext_counts[kext] += 1
        if feature:
            self.feature_counts[feature] += 1
        fkey = (kext, fn_entry if fn_entry is not None else -1)
        self.func_counts[fkey] += 1
        self.fn_agg[fkey][cat] += 1
        if fkey not in self.fn_meta:
            self.fn_meta[fkey] = (fn_sym, seg, sect)
        self.va_hits.setdefault(va, []).append(cat)
        if cat == B.CAT_UNKNOWN_ENCODING and len(self.unknown_list) < 4000:
            self.unknown_list.append((kext, seg, sect, va, word, fn_sym, reach))
        elif cat in (B.CAT_UNCLASSIFIED_MNEMONIC, B.CAT_UNCLASSIFIED_SYSREG) \
                and len(self.unclassified_list) < 4000:
            self.unclassified_list.append((kext, va, word, disasm, detail))
        elif cat == B.CAT_HVC_SMC:
            self.hvc_list.append((kext, va, disasm, detail, fn_sym, reach))
        elif cat == B.CAT_APPLE_AMX and len(self.amx_list) < 4000:
            self.amx_list.append((kext, va, word, detail, fn_sym, reach))
        elif cat == B.CAT_APPLE_RESERVED and len(self.reserved_list) < 4000:
            self.reserved_list.append((kext, va, word, detail, fn_sym, reach))
        if self.mf is not None and (self.max_manifest == 0
                                    or self.manifest_lines < self.max_manifest):
            rec = {
                "image": self.tag, "kext": kext, "seg": seg, "sect": sect,
                "va": f"{va:#x}", "off": f"{off:#x}", "word": f"{word:#010x}",
                "disasm": disasm, "cat": cat, "detail": detail,
                "feature": feature, "sev": sev, "reach": reach,
                "near_data": near_data, "baseline_verdict": bverdict,
                "fn_entry": (f"{fn_entry:#x}" if fn_entry is not None else None),
                "fn_sym": fn_sym,
            }
            if note:
                rec["note"] = note
            self.mf.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self.manifest_lines += 1

    # -- per-segment work -------------------------------------------------
    def sweep_segment(self, e, seg, fn_starts, fn_index):
        data = self.data
        nbytes = seg.filesize
        nwords = nbytes // 4
        tail = nbytes - nwords * 4
        base_off = seg.fileoff
        base_va = seg.vmaddr
        kext = e.entry_id
        sym_addrs = e.sym_addrs

        if tail:
            self.extra_bytes["DATA_UNALIGNED_TAIL"] += tail
        if seg.vmsize > seg.filesize:
            self.extra_bytes["DATA_ZEROFILL_VM"] += seg.vmsize - seg.filesize

        if nwords == 0:
            return

        buf = data[base_off:base_off + nwords * 4]
        words = array.array("I")
        words.frombytes(buf)
        self.va_map.append((base_va, base_va + nwords * 4, base_off, kext, seg.name))

        state = bytearray(nwords)          # ST_*
        is_code_region = bytearray(nwords)  # 1 if inside an instruction section

        # --- section map ---------------------------------------------------
        if seg.sections:
            for sec in seg.sections:
                if sec.size == 0:
                    continue
                lo = (sec.addr - base_va) // 4
                hi = (sec.addr + sec.size - base_va + 3) // 4
                lo = max(0, lo)
                hi = min(nwords, hi)
                if hi <= lo:
                    continue
                code = bool(sec.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))
                if code:
                    for i in range(lo, hi):
                        is_code_region[i] = 1
                else:
                    for i in range(lo, hi):
                        state[i] = ST_DATA_NONCODE_SECTION
        else:
            # segment without section headers: whole thing is an instruction region
            for i in range(nwords):
                is_code_region[i] = 1

        lo_fs = bisect.bisect_left(fn_starts, base_va)
        hi_fs = bisect.bisect_right(fn_starts, base_va + nwords * 4 - 4)
        seg_fn_starts = fn_starts[lo_fs:hi_fs]
        fs_idx = set((fv - base_va) // 4 for fv in seg_fn_starts)

        # --- pass B: linear decode, literal pools, PC-relative data refs ---
        decoded = bytearray(nwords)
        is_udf = bytearray(nwords)
        lit_targets = set()
        ref_targets = set()
        adrp_page = {}
        cs = self.cs
        census = self.cls.mnem_census
        pending = {}
        pos = 0
        n = nwords * 4
        # The decoder is restarted at every word capstone cannot decode. It
        # used to be handed `buf[pos:]`, i.e. a fresh copy of the WHOLE
        # remaining tail, so a segment with N undecodable words copied its
        # tail N times and held a second full-size block live across the FFI
        # call. On BootKC's largest segment that is 1,113 slices / 10.84 GB
        # memcpy'd and a 9.7 MB transient; on a dyld-cache range with no
        # image table entries the "segment" is a whole executable mapping,
        # and six parallel workers each holding 3x a multi-hundred-MB block
        # is what raised MemoryError (register-audit.md U1).
        #
        # Slicing to a bounded window caps the transient at DECODE_WINDOW
        # regardless of segment size. Every A64 instruction is 4 bytes and
        # DECODE_WINDOW is 4-aligned, so no instruction can straddle a window
        # edge; `adrp_page` is deliberately NOT cleared at a window edge, so
        # an adrp/add pair split across one still resolves. Equivalence is
        # not assumed: tools/testdata/bench_memoryview_fix.py decodes this
        # segment with six slicing strategies and fails unless all six
        # produce the same sha256 instruction stream.
        #
        # NOTE on the one-line fix U1 actually proposed (pass
        # `memoryview(buf)[pos:]`): with capstone 5.0.7 that is NOT zero
        # copy and does NOT fix the OOM. The binding does
        #     view = memoryview(code)
        #     if not view.readonly: ...from_buffer...   # zero copy
        #     elif not isinstance(code, bytes): code = view.tobytes()
        # and a view over immutable bytes is read-only and not a `bytes`, so
        # it takes the tobytes() branch: same full tail copy, plus overhead.
        # Measured: 0.82x the speed of the shipped loop, identical 9.74 MB
        # transient. See analysis/compat/oomfix-bench.json.
        while pos < n:
            end = n if n - pos <= DECODE_WINDOW else pos + DECODE_WINDOW
            consumed = 0
            for (addr, size, mnem, ops) in cs.disasm_lite(buf[pos:end], base_va + pos):
                widx = (addr - base_va) >> 2
                consumed += size
                if state[widx] == ST_DATA_NONCODE_SECTION:
                    continue
                census[mnem] += 1
                w = words[widx]
                if mnem == "udf":
                    is_udf[widx] = 1
                    adrp_page.clear()
                    continue  # permanently undefined: resolve through data evidence
                decoded[widx] = 1

                lt = literal_target(w, addr)
                if lt is not None:
                    tva, nb = lt
                    ti = (tva - base_va) >> 2
                    if 0 <= ti < nwords:
                        for k in range(ti, min(nwords, ti + max(1, nb // 4))):
                            lit_targets.add(k)
                pr = pcrel_data_ref(w, addr)
                if pr is not None:
                    kind, val, rd, rn = pr
                    if kind == "adrp":
                        adrp_page[rd] = val
                    elif kind == "adr":
                        ti = (val - base_va) >> 2
                        if 0 <= ti < nwords:
                            ref_targets.add(ti)
                        adrp_page.pop(rd, None)
                    else:
                        page = adrp_page.get(rn)
                        if page is not None:
                            ti = (page + val - base_va) >> 2
                            if 0 <= ti < nwords:
                                ref_targets.add(ti)
                        if kind == "add":
                            if page is not None and rd != rn:
                                adrp_page[rd] = page + val
                            elif rd != rn:
                                adrp_page.pop(rd, None)
                        else:
                            adrp_page.pop(rd, None)

                verdict = None
                # The whole system-instruction class is dispatched on the
                # decoded op0 field, not on the mnemonic text: `sys`, `sysl`
                # and `msr` are baseline mnemonics, so a mnemonic-first
                # dispatch accepts every encoding a decoder cannot alias.
                si = sysinstr_fields(w)
                if si is not None and si[1] >= 2:
                    sr = self.cls.classify_sysreg(w, mnem, ops)
                    if sr is not None:
                        verdict = sr[:4]
                elif si is not None and si[1] == 1:
                    verdict = self.cls.classify_sys_instruction(w, mnem, ops)
                    if verdict is not None and not SYS_OP_RE.match(mnem) \
                            and mnem not in ("sys", "sysl"):
                        # a decoder-specific alias we did not anticipate
                        verdict = (verdict[0], verdict[1],
                                   verdict[2] + f"; decoder printed '{mnem}'",
                                   verdict[3])
                elif si is not None and si[1] == 0:
                    verdict = self.cls.classify_pstate(w, mnem, ops)
                    if verdict == "MNEMONIC":
                        verdict = self.cls.classify_mnemonic(mnem, ops)
                elif mnem in ("hvc", "smc"):
                    imm = (w >> 5) & 0xFFFF
                    verdict = (B.CAT_HVC_SMC, f"{mnem} {ops}".strip(),
                               f"imm16={imm:#x}", "block")
                else:
                    verdict = self.cls.classify_mnemonic(mnem, ops)
                if verdict is None:
                    state[widx] = ST_CODE_BASELINE
                else:
                    state[widx] = ST_CODE_SUPRA
                    pending[widx] = verdict
            if consumed:
                pos += consumed
                if pos < end:
                    # capstone stopped short of the window: the word at the
                    # new `pos` is undecodable. A full window means we simply
                    # advance to the next one, and `adrp_page` must survive
                    # that edge so an adrp/add pair split across it resolves.
                    pos += 4
                    adrp_page.clear()
            else:
                pos += 4          # capstone could not decode the word at pos
                adrp_page.clear()

        # --- pass C: positive data evidence --------------------------------
        def undecidable(i):
            return (not decoded[i]) or is_udf[i]

        def data_island(j, step):
            """True if an undecodable word sits within 3 words in direction step:
            isolated decodable words inside a constant pool are accidents."""
            for k in range(j + step, j + 4 * step, step):
                if 0 <= k < nwords and undecidable(k):
                    return True
            return False

        def grow_blob(start, mark=ST_DATA_REFERENCED_BLOB):
            for step in (1, -1):
                j = start
                marked = 0
                while 0 <= j < nwords and marked < 8192:
                    if state[j] in (ST_DATA_REFERENCED_BLOB, ST_DATA_LITERAL_POOL,
                                    ST_DATA_NONCODE_SECTION):
                        j += step
                        continue
                    w = words[j]
                    soft = undecidable(j) or textual_word(w) or w == 0
                    # A function start that looks like code ends the blob. Apple's
                    # linker also lists pure data labels (.Lbswap_mask, _Rcon) in
                    # LC_FUNCTION_STARTS, so the boundary alone is not decisive.
                    if j != start and step == 1 and j in fs_idx and not soft:
                        break
                    if state[j] == ST_CODE_SUPRA:
                        cat = pending.get(j, (None,))[0]
                        if cat in ABSORBABLE_CATS and data_island(j, step):
                            del pending[j]
                            self.extra_bytes["findings_absorbed_into_data_blobs"] += 1
                            state[j] = mark
                            marked += 1
                            j += step
                            continue
                        break      # never hide an Apple-specific finding as data
                    if soft or data_island(j, step):
                        state[j] = mark
                        marked += 1
                        j += step
                        continue
                    break

        # seeds with positive evidence that an address holds data
        seeds = set()
        for i in lit_targets:
            seeds.add(i)
        for i in ref_targets:
            if undecidable(i) or textual_word(words[i]) or words[i] == 0 \
                    or data_island(i, 1):
                seeds.add(i)
        # a symbol that LC_FUNCTION_STARTS does not list as a function entry is
        # a labelled data object inside the text section (.Lbswap_mask, _Rcon...)
        s_lo = bisect.bisect_left(sym_addrs, base_va)
        s_hi = bisect.bisect_right(sym_addrs, base_va + nwords * 4 - 4)
        for sa in sym_addrs[s_lo:s_hi]:
            si = (sa - base_va) >> 2
            if undecidable(si) or words[si] == 0 or textual_word(words[si]) \
                    or data_island(si, 1):
                seeds.add(si)
        for i in sorted(seeds):
            if not is_code_region[i] or state[i] == ST_DATA_NONCODE_SECTION:
                continue
            grow_blob(i, ST_DATA_LITERAL_POOL if i in lit_targets
                      else ST_DATA_REFERENCED_BLOB)

        # inline C strings in __text: a run of >=3 strongly-textual words that
        # contains at least one word no decoder accepts and >=6 letters.
        i = 0
        while i < nwords:
            if state[i] != ST_UNSET or strong_textual(words[i]) is None:
                i += 1
                continue
            j = i
            letters = 0
            has_undec = False
            has_nul = False
            # A run may pass through words capstone happened to decode (ASCII
            # bytes often form a valid encoding), but never through a word
            # already classified as an above-baseline instruction.
            while j < nwords and state[j] in (ST_UNSET, ST_CODE_BASELINE):
                t = strong_textual(words[j])
                if t is None:
                    break
                letters += t[0]
                has_nul = has_nul or t[1]
                has_undec = has_undec or undecidable(j)
                j += 1
            if j - i >= 3 and has_undec and letters >= 6 and has_nul:
                for k in range(i, j):
                    state[k] = ST_DATA_INLINE_STRING
                while j < nwords and state[j] in (ST_UNSET, ST_CODE_BASELINE) \
                        and words[j] == 0:
                    state[j] = ST_DATA_INLINE_STRING
                    j += 1
            i = max(j, i + 1)

        # --- pass D: recursive-descent reachability, data words are barriers
        reach = bytearray(nwords)
        work = [(fv - base_va) // 4 for fv in seg_fn_starts]
        if not seg_fn_starts:
            work.append(0)
        DATA_STATES = (ST_DATA_REFERENCED_BLOB, ST_DATA_LITERAL_POOL,
                       ST_DATA_NONCODE_SECTION, ST_DATA_SEGMENT_GAP,
                       ST_DATA_INLINE_STRING)
        while work:
            i = work.pop()
            while 0 <= i < nwords and not reach[i]:
                if state[i] in DATA_STATES:
                    break
                reach[i] = 1
                w = words[i]
                kind, delta = branch_info(w)
                if kind == "t":
                    break
                if kind in ("b", "bl", "c"):
                    t = i + (delta >> 2)
                    if 0 <= t < nwords and not reach[t]:
                        work.append(t)
                    if kind == "b":
                        break
                i += 1

        # --- pass E: resolve everything still unset -------------------------
        for i in range(nwords):
            st = state[i]
            if st != ST_UNSET:
                continue
            if not is_code_region[i]:
                state[i] = ST_DATA_SEGMENT_GAP
                continue
            w = words[i]
            if w == 0:
                state[i] = ST_DATA_PADDING_ZERO
                if reach[i]:
                    self.extra_bytes["zero_words_reachable_by_fallthrough"] += 1
                continue
            if is_udf[i]:
                # UDF #imm16 is PERMANENTLY UNDEFINED on every AArch64
                # implementation, Apple's included, so it cannot be an
                # ARMv8.2-A compatibility delta: it is either inline data or a
                # deliberate trap.
                state[i] = ST_DATA_OR_TRAP_UDF
                if reach[i]:
                    self.extra_bytes["udf_words_reachable_by_fallthrough"] += 1
                continue
            ar = apple_reserved_class(w)
            canonical_amx = (w & 0xFFFFFC00) == 0x00201000
            if ar is None:
                ar = sve_sme_class(w)
            if ar is not None and (reach[i] or canonical_amx):
                cat, det = ar
                state[i] = ST_CODE_SUPRA
                pending[i] = (cat, f"<undecoded-by-capstone> {w:#010x}", det, "block")
                continue
            if not reach[i]:
                state[i] = ST_DATA_UNREACHABLE_UNDECODABLE
                continue
            state[i] = ST_UNKNOWN_ENCODING
            pending[i] = (B.CAT_UNKNOWN_ENCODING, f"<undecodable> {w:#010x}",
                          "no decoder produced an instruction; word is reachable "
                          "by direct control flow and has no positive data evidence",
                          "block")
        pending = sorted(pending.items())

        # --- emit findings -------------------------------------------------
        for widx, verdict in pending:
            cat, disasm, detail, sev = verdict
            va = base_va + widx * 4
            feature = detail if cat in (B.CAT_ARCH_EXT, B.CAT_OPT_V82,
                                        CAT_SYSREG_EL23) else None
            if cat == B.CAT_PAC:
                feature = "FEAT_PAuth"
            elif cat == B.CAT_SVE:
                feature = "FEAT_SVE"
            elif cat == B.CAT_SME_SVCR:
                feature = "FEAT_SME"
            elif cat == B.CAT_MTE:
                feature = "FEAT_MTE"
            elif cat == B.CAT_BTI:
                feature = "FEAT_BTI"
            fn_entry, fn_sym, note = fn_index(va)
            sect = self.sect_of(seg, va)
            if cat == B.CAT_HVC_SMC:
                src = self.x0_source(words, widx, base_va, nwords)
                detail = f"{detail}; x0={src}"
            near_data = any(state[k] in NEAR_DATA_STATES
                            for k in range(max(0, widx - 2), min(nwords, widx + 3)))
            self.emit(kext, seg.name, sect, va, base_off + widx * 4, words[widx],
                      disasm, cat, detail, feature, sev,
                      bool(reach[widx]), fn_entry, fn_sym, note, near_data)

        # --- byte accounting ------------------------------------------------
        cnt = collections.Counter(state)
        for st, c in cnt.items():
            self.state_bytes[STATE_NAMES[st]] += c * 4
            self.state_bytes_by_kext[kext][STATE_NAMES[st]] += c * 4
        if tail:
            self.state_bytes["DATA_UNALIGNED_TAIL"] += tail
            self.state_bytes_by_kext[kext]["DATA_UNALIGNED_TAIL"] += tail

        return {
            "kext": kext, "seg": seg.name,
            "vmaddr": f"{seg.vmaddr:#x}", "fileoff": f"{seg.fileoff:#x}",
            "filesize": seg.filesize, "vmsize": seg.vmsize,
            "initprot": seg.initprot,
            "words": nwords,
            "fn_starts_in_seg": len(seg_fn_starts),
            "reachable_words": sum(reach),
            "states": {STATE_NAMES[k]: v for k, v in cnt.items()},
        }

    @staticmethod
    def sect_of(seg, va):
        for sec in seg.sections:
            if sec.addr <= va < sec.addr + sec.size:
                return sec.sectname
        return None

    def x0_source(self, words, widx, base_va, nwords):
        """Reconstruct the constant in x0 feeding an HVC, if statically known.

        Uses capstone's register-write set so that stores/compares whose Rt
        field happens to be x0 are not mistaken for definitions of x0.
        """
        csd = self.csd
        seen = {}
        for j in range(widx - 1, max(-1, widx - 33), -1):
            w = words[j]
            kind, _ = branch_info(w)
            if kind in ("b", "t"):
                break
            insns = list(csd.disasm(struct.pack("<I", w), base_va + j * 4))
            if not insns:
                continue
            ins = insns[0]
            try:
                _r, wr = ins.regs_access()
            except capstone.CsError:
                continue
            if not any(ins.reg_name(r) in ("x0", "w0") for r in wr):
                continue
            top = w & 0xFF800000
            imm16 = (w >> 5) & 0xFFFF
            hw = (w >> 21) & 3
            if top == 0xD2800000:                      # MOVZ x0, #imm, lsl hw
                base = imm16 << (16 * hw)
                for sh, v in seen.items():
                    base = (base & ~(0xFFFF << (16 * sh))) | (v << (16 * sh))
                return f"{base:#x} (from {ins.mnemonic} {ins.op_str})"
            if top == 0x92800000:                      # MOVN x0
                return f"{(~(imm16 << (16 * hw))) & 0xFFFFFFFFFFFFFFFF:#x}"
            if top == 0xF2800000:                      # MOVK x0
                seen[hw] = imm16
                continue
            return (f"dynamic: last writer at {base_va + j * 4:#x} is "
                    f"'{ins.mnemonic} {ins.op_str}'")
        return "not statically determined within the basic block (<=32 insns)"

    # -- driver -----------------------------------------------------------
    def run(self, filetype, outer_segs, entries, only_entry=None):
        t0 = time.time()
        inner_exec_ranges = []
        for e in entries:
            if only_entry and e.entry_id != only_entry:
                continue
            fn_starts = e.func_starts
            sym_addrs = e.sym_addrs
            syms = e.syms

            exec_segs = [s for s in e.segments if s.is_exec and s.filesize]
            fs_in_exec = 0
            for fv in fn_starts:
                for s in exec_segs:
                    if s.vmaddr <= fv < s.vmaddr + s.filesize:
                        fs_in_exec += 1
                        break
            if fn_starts and fs_in_exec * 2 < len(fn_starts):
                raise SystemExit(
                    f"FATAL: {e.entry_id}: only {fs_in_exec}/{len(fn_starts)} "
                    "LC_FUNCTION_STARTS land in executable segments; the ULEB128 "
                    "base is wrong. Refusing to produce a coverage claim.")

            fstarts = fn_starts

            def fn_index(va, _fs=fstarts, _sa=sym_addrs, _sy=syms, _ex=exec_segs):
                pos = bisect.bisect_right(_fs, va) - 1
                fn_entry = None
                note = None
                if pos >= 0:
                    cand = _fs[pos]
                    nxt = _fs[pos + 1] if pos + 1 < len(_fs) else None
                    inside = any(s.vmaddr <= cand < s.vmaddr + s.filesize for s in _ex)
                    if inside and (nxt is None or va < nxt):
                        fn_entry = cand
                if fn_entry is None:
                    note = "no LC_FUNCTION_STARTS attribution"
                sp = bisect.bisect_right(_sa, fn_entry if fn_entry is not None else va) - 1
                fn_sym = None
                if sp >= 0:
                    sval, sname = _sy[sp]
                    ref = fn_entry if fn_entry is not None else va
                    fn_sym = sname if sval == ref else f"{sname}+{ref - sval:#x}"
                return fn_entry, fn_sym, note

            for s in e.segments:
                if not s.is_exec:
                    continue
                if not s.filesize:
                    # executable segment with no file content: pure zero-fill at
                    # runtime. Recorded so the closure has no silent skips.
                    self.extra_bytes["DATA_ZEROFILL_VM"] += s.vmsize
                    self.components.append({
                        "kext": e.entry_id, "seg": s.name,
                        "vmaddr": f"{s.vmaddr:#x}", "fileoff": f"{s.fileoff:#x}",
                        "filesize": 0, "vmsize": s.vmsize,
                        "initprot": s.initprot, "words": 0,
                        "fn_starts_in_seg": 0, "reachable_words": 0,
                        "states": {"DATA_ZEROFILL_VM": s.vmsize},
                        "n_func_starts_entry": len(fn_starts),
                        "n_syms": len(syms)})
                    continue
                inner_exec_ranges.append((s.fileoff, s.fileoff + s.filesize))
                comp = self.sweep_segment(e, s, fstarts, fn_index)
                if comp:
                    comp["n_func_starts_entry"] = len(fn_starts)
                    comp["n_syms"] = len(syms)
                    self.components.append(comp)
            print(f"    [{e.entry_id}] {len(exec_segs)} exec seg(s), "
                  f"{len(fn_starts)} function starts, "
                  f"{self.kext_counts.get(e.entry_id, 0)} findings "
                  f"({time.time() - t0:.0f}s)", flush=True)

        # interstitial bytes of outer exec segments not claimed by any entry
        if filetype == MH_FILESET and not only_entry:
            inner_exec_ranges.sort()
            for s in outer_segs:
                if not (s.is_exec and s.filesize):
                    continue
                lo, hi = s.fileoff, s.fileoff + s.filesize
                cur = lo
                gaps = []
                for a, b in inner_exec_ranges:
                    if b <= cur or a >= hi:
                        continue
                    if a > cur:
                        gaps.append((cur, a))
                    cur = max(cur, b)
                if cur < hi:
                    gaps.append((cur, hi))
                for a, b in gaps:
                    chunk = self.data[a:b]
                    nz = len(chunk) - chunk.count(0)
                    if nz == 0:
                        self.state_bytes["DATA_PADDING_ZERO"] += len(chunk)
                        self.state_bytes_by_kext["<fileset interstitial>"]["DATA_PADDING_ZERO"] += len(chunk)
                    else:
                        self.state_bytes["DATA_INTERSTITIAL_NONZERO"] += len(chunk)
                        self.state_bytes_by_kext["<fileset interstitial>"]["DATA_INTERSTITIAL_NONZERO"] += len(chunk)
                        self.extra_bytes["interstitial_nonzero_bytes"] += nz


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def crosscheck_patch_table(sweep, outdir):
    """Compare findings against tools/apply_kernel_patches.py EXACT_VA_PATCHES."""
    here = os.path.dirname(os.path.abspath(__file__))
    src = os.path.join(here, "apply_kernel_patches.py")
    vas = []
    ranges = []
    if os.path.exists(src):
        txt = open(src, "r", encoding="utf-8").read()
        m = re.search(r"EXACT_VA_PATCHES\s*=\s*\{(.*?)\n\}", txt, re.S)
        if m:
            for line in m.group(1).splitlines():
                mm = re.match(r"\s*(0x[0-9a-fA-F]+)\s*:\s*(0x[0-9a-fA-F]+)", line)
                if mm:
                    vas.append((int(mm.group(1), 16), int(mm.group(2), 16)))
        m2 = re.search(r"AMX_DEAD_CODE_RANGES\s*=\s*\[(.*?)\n\]", txt, re.S)
        if m2:
            for mm in re.finditer(r"\((0x[0-9a-fA-F]+),\s*(0x[0-9a-fA-F]+)\)", m2.group(1)):
                ranges.append((int(mm.group(1), 16), int(mm.group(2), 16)))

    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

    def orig_at(va):
        for lo, hi, off, kext, segn in sweep.va_map:
            if lo <= va < hi:
                o = off + (va - lo)
                w = struct.unpack("<I", sweep.data[o:o + 4])[0]
                dis = list(cs.disasm_lite(sweep.data[o:o + 4], va))
                txt = f"{dis[0][2]} {dis[0][3]}".strip() if dis else "<undecodable>"
                return {"kext": kext, "seg": segn, "word": f"{w:#010x}", "disasm": txt}
        return None

    covered, missed = [], []
    for va, _new in vas:
        cats = sweep.va_hits.get(va)
        if cats:
            covered.append({"va": f"{va:#x}", "cats": sorted(set(cats))})
        else:
            rec = {"va": f"{va:#x}", "sweep_verdict": "baseline-or-data"}
            rec.update(orig_at(va) or {"note": "VA outside swept executable range"})
            missed.append(rec)

    patch_vas = set(va for va, _ in vas)
    for lo, hi in ranges:
        patch_vas.update(range(lo, hi + 4, 4))
    delta = sorted(va for va in sweep.va_hits if va not in patch_vas)

    out = {
        "patch_table_exact_vas": len(vas),
        "patch_table_amx_range_vas": sum((hi - lo) // 4 + 1 for lo, hi in ranges),
        "patch_vas_confirmed_by_sweep": len(covered),
        "patch_vas_not_seen_by_sweep": missed,
        "sweep_vas_not_covered_by_patch_table": len(delta),
        "confirmed_detail": covered,
    }
    with open(os.path.join(outdir, "patch-crosscheck.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    # delta VA list can be huge; store separately, compacted by category
    bycat = collections.Counter()
    for va in delta:
        for c in set(sweep.va_hits[va]):
            bycat[c] += 1
    out["sweep_delta_by_category"] = dict(bycat.most_common())
    with open(os.path.join(outdir, "patch-crosscheck.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--outdir", default=os.path.join("analysis", "compat"))
    ap.add_argument("--tag", default=None)
    ap.add_argument("--entry", default=None)
    ap.add_argument("--no-manifest", action="store_true")
    ap.add_argument("--max-manifest", type=int, default=0)
    ap.add_argument("--baseline", default=os.path.join(
        "analysis", "compat", "armmac-generic-v1-baseline.json"),
        help="machine-readable armmac-generic-v1 baseline (A1 output)")
    args = ap.parse_args()

    global BASELINE
    BASELINE = Baseline(args.baseline)
    if BASELINE.loaded:
        print(f"[*] baseline loaded: {BASELINE.meta}")
    else:
        print(f"[!] baseline {args.baseline} not found: falling back to the "
              "tables in tools/armmac_baseline.py")

    t0 = time.time()
    print(f"[*] sweep target: {args.target}")
    data, filetype, outer, entries = parse_container(args.target)
    sha = hashlib.sha256(data).hexdigest()
    tag = args.tag or os.path.basename(args.target)
    print(f"[*] {len(data)} bytes, sha256={sha}")
    print(f"[*] filetype={filetype:#x} outer_segments={len(outer)} entries={len(entries)}")

    os.makedirs(args.outdir, exist_ok=True)
    sweep = Sweep(data, tag, args.outdir,
                  write_manifest=not args.no_manifest,
                  max_manifest=args.max_manifest)
    sweep.run(filetype, outer, entries, only_entry=args.entry)
    if sweep.mf:
        sweep.mf.close()

    # ---- byte coverage -------------------------------------------------
    total = sum(sweep.state_bytes.values())
    failing = sum(v for k, v in sweep.state_bytes.items()
                  if k in ("UNKNOWN_ENCODING", "UNSET"))
    weak = sum(v for k, v in sweep.state_bytes.items()
               if k in ("DATA_UNREACHABLE_UNDECODABLE", "DATA_INTERSTITIAL_NONZERO"))
    cov = {
        "image": tag, "sha256": sha, "total_executable_bytes_accounted": total,
        "states": dict(sorted(sweep.state_bytes.items(), key=lambda kv: -kv[1])),
        "evidence_classes": {
            "strong_positive": ["CODE_BASELINE", "CODE_SUPRA_BASELINE",
                                "DATA_NONCODE_SECTION", "DATA_LITERAL_POOL",
                                "DATA_REFERENCED_BLOB", "DATA_INLINE_STRING",
                                "DATA_SEGMENT_GAP", "DATA_PADDING_ZERO",
                                "DATA_OR_TRAP_UDF", "DATA_UNALIGNED_TAIL"],
            "weak_negative_only": ["DATA_UNREACHABLE_UNDECODABLE",
                                   "DATA_INTERSTITIAL_NONZERO"],
            "failing": ["UNKNOWN_ENCODING", "UNSET"],
        },
        "bytes_with_failing_state": failing,
        "bytes_with_weak_evidence": weak,
        "bytes_with_strong_terminal_state": total - failing - weak,
        "strong_coverage_pct": round(100.0 * (total - failing - weak) / total, 6) if total else 0,
        "gate1_pass": failing == 0,
        "extra_byte_notes": dict(sweep.extra_bytes),
        "by_kext": {k: dict(v) for k, v in sorted(sweep.state_bytes_by_kext.items())},
    }
    with open(os.path.join(args.outdir, "byte-coverage.json"), "w", encoding="utf-8") as f:
        json.dump(cov, f, indent=1)

    # ---- summary -------------------------------------------------------
    uniq_funcs = len([k for k in sweep.func_counts if k[1] != -1])
    summary = {
        "image": tag, "sha256": sha,
        "scan_seconds": round(time.time() - t0, 1),
        "baseline": BASELINE.meta if BASELINE.loaded else None,
        "findings_total": sweep.findings_total,
        "by_category": dict(sweep.cat_counts.most_common()),
        "by_baseline_verdict": dict(sweep.baseline_verdicts.most_common()),
        "by_category_baseline_verdict": {
            f"{c}/{v}": n for (c, v), n
            in sorted(sweep.baseline_verdict_by_cat.items(), key=lambda kv: -kv[1])},
        "by_category_severity": {f"{c}/{s}": n for (c, s), n
                                 in sorted(sweep.cat_sev_counts.items(), key=lambda kv: -kv[1])},
        "by_feature": dict(sweep.feature_counts.most_common()),
        "by_kext": dict(sweep.kext_counts.most_common()),
        "kexts_with_findings": len(sweep.kext_counts),
        "unique_functions_with_findings": uniq_funcs,
        "findings_without_function_attribution": sweep.func_counts.get(
            ("com.apple.kernel", -1), 0) + sum(n for k, n in sweep.func_counts.items() if k[1] == -1),
        "unknown_encoding_count": sweep.cat_counts.get(B.CAT_UNKNOWN_ENCODING, 0),
        "unclassified_mnemonic_count": sweep.cat_counts.get(B.CAT_UNCLASSIFIED_MNEMONIC, 0),
        "unclassified_sysreg_count": sweep.cat_counts.get(B.CAT_UNCLASSIFIED_SYSREG, 0),
        "top_functions": [
            {"kext": k[0], "fn_entry": f"{k[1]:#x}" if k[1] != -1 else None,
             "fn_sym": sweep.fn_meta.get(k, (None,))[0], "findings": n,
             "cats": dict(sweep.fn_agg[k])}
            for k, n in sweep.func_counts.most_common(80)],
    }
    with open(os.path.join(args.outdir, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=1)

    # ---- censuses ------------------------------------------------------
    per_mnem = collections.defaultdict(dict)
    for (m, v), n in sweep.cls.mnem_verdict.items():
        per_mnem[m][v] = n
    with open(os.path.join(args.outdir, "mnemonic-census.json"), "w", encoding="utf-8") as f:
        json.dump({"count": len(sweep.cls.mnem_census),
                   "note": "verdicts is a breakdown: one mnemonic can be both "
                           "baseline and above-baseline depending on operands "
                           "(mov x0,x1 vs mov z0.s,p0/m,z1.s). 'n' counts every "
                           "decoded occurrence including words later resolved as "
                           "data.",
                   "mnemonics": [{"mnemonic": m, "n": n,
                                  "verdicts": per_mnem.get(m, {"BASELINE": 0})}
                                 for m, n in sweep.cls.mnem_census.most_common()]},
                  f, indent=1)
    sysregs = [{"encoding": enc, "name": key, "n": n,
                "verdict": sweep.cls.sysreg_verdict.get(key, "BASELINE")}
               for (enc, key), n in sweep.cls.sysreg_census.most_common()]
    with open(os.path.join(args.outdir, "sysreg-census.json"), "w", encoding="utf-8") as f:
        json.dump({"count": len(sysregs), "sysregs": sysregs}, f, indent=1)
    sysinstrs = [{"form": form, "operation": key, "n": n,
                  "verdict": sweep.cls.sysinstr_verdict.get(key, "BASELINE")}
                 for (form, key), n in sweep.cls.sysinstr_census.most_common()]
    with open(os.path.join(args.outdir, "sysinstr-census.json"), "w",
              encoding="utf-8") as f:
        json.dump({"count": len(sysinstrs),
                   "note": "op0=0b00 (MSR immediate / PSTATE) and op0=0b01 "
                           "(SYS / SYSL) halves of the system-instruction "
                           "class, classified from decoded fields. "
                           "sysreg-census.json covers op0 in {0b10,0b11} "
                           "(MRS/MSR register forms) and keeps its earlier "
                           "meaning unchanged.",
                   "sysinstrs": sysinstrs}, f, indent=1)

    # ---- component closure --------------------------------------------
    with open(os.path.join(args.outdir, "components.csv"), "w", encoding="utf-8",
              newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["kext", "segment", "vmaddr", "fileoff", "filesize", "vmsize",
                     "initprot", "words", "reachable_words", "fn_starts_in_seg",
                     "entry_fn_starts", "entry_syms", "states"])
        for c in sweep.components:
            wr.writerow([c["kext"], c["seg"], c["vmaddr"], c["fileoff"], c["filesize"],
                         c["vmsize"], c["initprot"], c["words"], c["reachable_words"],
                         c["fn_starts_in_seg"], c.get("n_func_starts_entry"),
                         c.get("n_syms"),
                         ";".join(f"{k}={v}" for k, v in sorted(c["states"].items()))])

    # ---- per-function aggregation -------------------------------------
    with open(os.path.join(args.outdir, "findings-by-function.jsonl"), "w",
              encoding="utf-8", newline="\n") as f:
        for k, n in sweep.func_counts.most_common():
            sym, seg, sect = sweep.fn_meta.get(k, (None, None, None))
            f.write(json.dumps({
                "kext": k[0],
                "fn_entry": f"{k[1]:#x}" if k[1] != -1 else None,
                "fn_sym": sym, "seg": seg, "sect": sect,
                "findings": n, "cats": dict(sweep.fn_agg[k]),
            }, separators=(",", ":")) + "\n")

    # ---- detail dumps --------------------------------------------------
    details = {
        "unknown_encoding": [
            {"kext": a, "seg": b, "sect": c, "va": f"{d:#x}", "word": f"{w:#010x}",
             "fn_sym": s, "reachable": r}
            for (a, b, c, d, w, s, r) in sweep.unknown_list],
        "unclassified": [
            {"kext": a, "va": f"{v:#x}", "word": f"{w:#010x}", "disasm": d, "detail": t}
            for (a, v, w, d, t) in sweep.unclassified_list],
        "hvc_smc": [
            {"kext": a, "va": f"{v:#x}", "disasm": d, "detail": t, "fn_sym": s,
             "reachable": r} for (a, v, d, t, s, r) in sweep.hvc_list],
        "apple_amx": [
            {"kext": a, "va": f"{v:#x}", "word": f"{w:#010x}", "detail": t,
             "fn_sym": s, "reachable": r} for (a, v, w, t, s, r) in sweep.amx_list],
        "apple_reserved_space": [
            {"kext": a, "va": f"{v:#x}", "word": f"{w:#010x}", "detail": t,
             "fn_sym": s, "reachable": r} for (a, v, w, t, s, r) in sweep.reserved_list],
    }
    with open(os.path.join(args.outdir, "detail-lists.json"), "w", encoding="utf-8") as f:
        json.dump(details, f, indent=1)

    xc = crosscheck_patch_table(sweep, args.outdir)

    # ---- console -------------------------------------------------------
    print("\n" + "=" * 78)
    print(f"ARMv8.2-A sweep: {tag}")
    print("=" * 78)
    print(f"executable bytes accounted : {total}")
    for k, v in sorted(sweep.state_bytes.items(), key=lambda kv: -kv[1]):
        print(f"   {k:<32} {v:>12}  {100.0*v/total:6.3f}%")
    print(f"strong terminal state      : {cov['strong_coverage_pct']}%")
    print(f"UNKNOWN_ENCODING bytes     : {failing}  (gate1_pass={cov['gate1_pass']})")
    print(f"\nfindings total             : {sweep.findings_total}")
    for c, n in sweep.cat_counts.most_common():
        print(f"   {c:<28} {n:>8}")
    print("\nbaseline verdicts (armmac-generic-v1):")
    for v, n in sweep.baseline_verdicts.most_common():
        print(f"   {v:<28} {n:>8}")
    print(f"kexts with findings        : {len(sweep.kext_counts)} / {len(entries)}")
    print(f"unique functions to handle : {uniq_funcs}")
    print(f"distinct mnemonics decoded : {len(sweep.cls.mnem_census)}")
    print(f"distinct sysreg encodings  : {len(sysregs)}  (op0=0b1x)")
    print(f"distinct sys-instr forms   : {len(sysinstrs)}  (op0=0b0x)")
    print(f"\npatch-table crosscheck: {xc['patch_vas_confirmed_by_sweep']}"
          f"/{xc['patch_table_exact_vas']} EXACT_VA_PATCHES confirmed; "
          f"{len(xc['patch_vas_not_seen_by_sweep'])} not seen; "
          f"{xc['sweep_vas_not_covered_by_patch_table']} swept VAs outside the patch table")
    print(f"\n[+] outputs in {args.outdir} ({time.time()-t0:.0f}s)")


if __name__ == "__main__":
    main()
