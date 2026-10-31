#!/usr/bin/env python3
"""
verify_bitfield_masks.py - hold tools/bitfield_census.py to a reference
assembler instead of to its own author.

A decoder-free census is only worth anything if its bit-field predicates are
right. "I read the encoding tables carefully" is not evidence; a predicate
that is one bit wide too far silently inflates a category, and a predicate
one bit too narrow silently zeroes one. So every predicate here has to earn
its place twice:

  POSITIVE  llvm-mc assembles a real instruction of the category, and
            classify() must claim that word for exactly that category.
  NEGATIVE  llvm-mc assembles plain ARMv8.2-A baseline instructions, and
            classify() must claim NONE of them. A false positive on `ldr` or
            `bl` would contaminate the whole census.

llvm-mc is the third party: LLVM's AArch64 encoder is independent of both
capstone (which the census does not use) and of this project's tables.

    py tools/testdata/verify_bitfield_masks.py
    py tools/testdata/verify_bitfield_masks.py --mc path/to/llvm-mc

Exit 0 only if every positive and every negative case holds.
"""
import argparse
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)
import bitfield_census as BC            # noqa: E402

DEFAULT_MC = os.path.join(ROOT, "tools", "llvm", "bin", "llvm-mc.exe")

# (category, mattr, [instructions...])
# mattr is what llvm-mc needs to ACCEPT the instruction; it says nothing
# about the target profile. armmac-generic-v1 is +v8.2a and every feature
# named below is outside it, which is the point.
POSITIVE = [
    ("PAC_DP1", "+v8.2a,+pauth", [
        "pacia x0, x1", "pacib x2, x3", "pacda x4, x5", "pacdb x6, x7",
        "autia x8, x9", "autib x10, x11", "autda x12, x13", "autdb x14, x15",
        "paciza x16", "pacizb x17", "pacdza x18", "pacdzb x19",
        "autiza x20", "autizb x21", "autdza x22", "autdzb x23",
        "xpaci x24", "xpacd x25",
    ]),
    ("PAC_PACGA", "+v8.2a,+pauth", ["pacga x0, x1, x2"]),
    ("PAC_BRANCH", "+v8.2a,+pauth", [
        "braa x0, x1", "brab x2, x3", "blraa x4, x5", "blrab x6, x7",
        "braaz x8", "brabz x9", "blraaz x10", "blrabz x11",
        "retaa", "retab", "eretaa", "eretab",
    ]),
    ("PAC_LDRA", "+v8.2a,+pauth", [
        "ldraa x0, [x1]", "ldrab x2, [x3]", "ldraa x4, [x5, #8]",
        "ldrab x6, [x7, #-8]!",
    ]),
    ("PAC_HINT", "+v8.2a,+pauth", [
        "paciasp", "pacibsp", "autiasp", "autibsp",
        "paciaz", "pacibz", "autiaz", "autibz",
        "pacia1716", "pacib1716", "autia1716", "autib1716", "xpaclri",
    ]),
    ("BTI", "+v8.2a,+bti", ["bti", "bti c", "bti j", "bti jc"]),
    ("IMPDEF_SYSREG", "+v8.2a", [
        # The Apple encodings this project actually found, written in the
        # numeric form so no symbolic-name table is involved.
        "mrs x0, s3_5_c15_c5_0", "msr s3_5_c15_c5_0, x0",
        "mrs x1, s3_6_c15_c1_5", "msr s3_6_c15_c1_5, x1",
        "mrs x2, s3_4_c15_c2_7", "msr s3_4_c15_c2_7, x2",
        "mrs x3, s3_0_c11_c0_0", "msr s3_0_c11_c0_0, x3",
        "mrs x4, s2_3_c15_c7_1",
    ]),
    ("IMPDEF_SYSINSTR", "+v8.2a", [
        "sys #0, c11, c0, #0, x0", "sys #3, c15, c4, #2, x1",
        "sysl x2, #1, c11, c9, #5",
    ]),
    ("PSTATE_ABOVE_V82", "+v8.2a,+dit,+sme,+mte,+flagm", [
        "msr dit, #1", "msr tco, #1", "cfinv",
    ]),
    ("HVC", "+v8.2a", ["hvc #0", "hvc #0xc1", "hvc #0xffff"]),
    ("SMC", "+v8.2a", ["smc #0", "smc #1"]),
    ("SB", "+v8.2a,+sb", ["sb"]),
    ("SVE_SME_SPACE", "+v8.2a,+sve", [
        "ptrue p0.s", "whilelo p1.b, x0, x1", "ld1b { z0.b }, p0/z, [x1]",
        "st1d { z3.d }, p2, [x4]", "fnmls z0.s, p0/m, z1.s, z2.s",
        "rdvl x0, #1", "index z0.s, #0, #1",
    ]),
    ("SME_ZA_SPACE", "+v8.2a,+sme,+sme2", [
        "ldr za[w12, 0], [x0]", "str za[w12, 0], [x0]", "rdsvl x0, #1",
    ]),
    ("LDAPR", "+v8.2a,+rcpc", [
        "ldapr x0, [x1]", "ldapr w2, [x3]", "ldaprb w4, [x5]",
        "ldaprh w6, [x7]",
    ]),
    ("LDAPUR", "+v8.2a,+rcpc-immo", [
        "ldapur x0, [x1, #8]", "ldapurb w2, [x3]", "stlur x4, [x5, #-8]",
    ]),
    ("MTE", "+v8.2a,+mte", [
        "irg x0, x1", "gmi x2, x3, x4", "addg x5, x6, #16, #1",
        "subg x7, x8, #32, #2",
    ]),
]

# Optional ARMv8.0/8.2 extensions that the host-profile work adjudicated as
# present on every candidate host. They are above armmac-generic-v1 but they
# are NOT in any of the census categories, so a predicate claiming one would
# be a false positive just as surely as one claiming `ldr`. They need their
# own mattr, which is why they cannot sit in the plain baseline batch.
NEGATIVE_OPTIONAL = [
    ("+v8.2a,+aes", ["aese v0.16b, v1.16b", "aesd v0.16b, v1.16b",
                     "aesmc v0.16b, v1.16b", "pmull v0.1q, v1.1d, v2.1d"]),
    ("+v8.2a,+sha2", ["sha256h q0, q1, v2.4s", "sha256su0 v0.4s, v1.4s",
                      "sha1c q0, s1, v2.4s"]),
    ("+v8.2a,+sha3", ["eor3 v0.16b, v1.16b, v2.16b, v3.16b",
                      "rax1 v0.2d, v1.2d, v2.2d"]),
    ("+v8.2a,+sha3", ["xar v0.2d, v1.2d, v2.2d, #1"]),
    ("+v8.2a,+fullfp16", ["fadd h0, h1, h2", "fmul h0, h1, h2"]),
    ("+v8.2a,+dotprod", ["sdot v0.4s, v1.16b, v2.16b",
                         "udot v0.4s, v1.16b, v2.16b"]),
    ("+v8.2a,+fp16fml", ["fmlal v0.4s, v1.4h, v2.4h"]),
]

# Baseline ARMv8.2-A. classify() must return None for every one of these.
# If any predicate claims one, the census is counting ordinary code.
NEGATIVE = ("+v8.2a", [
    "nop", "ret", "br x0", "blr x1", "bl #4", "b #8", "b.eq #12",
    "cbz x0, #16", "tbnz x1, #3, #20", "eret",
    "ldr x0, [x1]", "ldr x0, [x1, #8]", "str x2, [x3, #16]",
    "ldp x0, x1, [sp, #16]", "stp x2, x3, [sp, #-16]!",
    "ldr x0, #8", "adrp x0, #0", "adr x1, #4", "add x0, x1, #16",
    "mov x0, x1", "movz x0, #1", "movk x0, #2, lsl #16", "movn x0, #3",
    "and x0, x1, x2", "orr x0, x1, x2", "eor x0, x1, x2",
    "subs x0, x1, x2", "ands x0, x1, x2", "cmp x0, x1", "ccmp x0, x1, #0, eq",
    "csel x0, x1, x2, eq", "madd x0, x1, x2, x3", "udiv x0, x1, x2",
    "rbit x0, x1", "clz x0, x1", "rev x0, x1", "rev16 x0, x1", "rev32 x0, x1",
    "ldar x0, [x1]", "stlr x0, [x1]", "ldaxr x0, [x1]", "stlxr w2, x0, [x1]",
    "casal x0, x1, [x2]", "ldadd x0, x1, [x2]", "swp x0, x1, [x2]",
    "dsb sy", "dmb ish", "isb", "clrex", "wfi", "wfe", "yield", "sevl",
    "msr daifset, #2", "msr daifclr, #2", "msr spsel, #1",
    "msr pan, #1", "msr uao, #1",
    "mrs x0, tpidr_el0", "mrs x1, midr_el1", "mrs x2, sctlr_el1",
    "msr sctlr_el1, x2", "mrs x3, id_aa64isar0_el1", "mrs x4, cntvct_el0",
    "tlbi vmalle1is", "dc civac, x0", "ic iallu", "at s1e1r, x0",
    "fadd d0, d1, d2", "fmul s0, s1, s2", "fcvtzs w0, d0", "scvtf d0, x0",
    "add v0.4s, v1.4s, v2.4s", "mul v0.8h, v1.8h, v2.8h",
    "ldr q0, [x0]", "str q1, [x1, #16]", "ld1 { v0.16b }, [x0]",
    "aese v0.16b, v1.16b", "sha256h q0, q1, v2.4s", "pmull v0.1q, v1.1d, v2.1d",
    "crc32x w0, w1, x2", "sqrdmlah v0.4s, v1.4s, v2.4s",
    "brk #1", "udf #0", "svc #0",
    "stxr w0, x1, [x2]", "prfm pldl1keep, [x0]",
    "sdiv x0, x1, x2", "smulh x0, x1, x2", "umaddl x0, w1, w2, x3",
    "bfi x0, x1, #2, #4", "ubfx x0, x1, #2, #4", "sbfx x0, x1, #2, #4",
    "extr x0, x1, x2, #4", "lsl x0, x1, #2", "asr x0, x1, x2",
    "ccmn x0, #1, #0, ne", "cinc x0, x1, eq", "cneg x0, x1, eq",
    "dc cvap, x0", "tlbi vae1, x0",
])


def assemble(mc, mattr, instrs):
    """-> [(asm, word)]. One llvm-mc call per batch; .inst-free, real asm."""
    src = "\n".join(instrs) + "\n"
    p = subprocess.run(
        [mc, "--arch=aarch64", "--triple=aarch64-none-elf",
         f"--mattr={mattr}", "--show-encoding", "--assemble"],
        input=src, capture_output=True, text=True)
    if p.returncode != 0:
        return None, p.stderr.strip()
    out = []
    # llvm-mc prints:   pacia x0, x1   // encoding: [0x20,0x00,0xc1,0xda]
    rx = re.compile(r"^\s*(\S.*?)\s*//\s*encoding:\s*\[([^\]]+)\]")
    for line in p.stdout.splitlines():
        m = rx.match(line)
        if not m:
            continue
        asm = m.group(1).strip()
        parts = [x.strip() for x in m.group(2).split(",")]
        try:
            bs = bytes(int(x, 16) for x in parts)
        except ValueError:
            continue
        if len(bs) != 4:
            continue
        out.append((asm, struct.unpack("<I", bs)[0]))
    return out, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mc", default=DEFAULT_MC)
    ap.add_argument("--json", default=os.path.join(
        ROOT, "analysis", "compat", "bitfield-mask-verification.json"))
    args = ap.parse_args()

    if not os.path.exists(args.mc):
        print(f"FATAL: llvm-mc not found at {args.mc}. The masks are NOT "
              "verified without a reference assembler; refusing to pass.")
        return 1

    results = {"llvm_mc": args.mc, "positive": [], "negative": [],
               "skipped": [], "failures": []}
    ok = True

    for (cat, mattr, instrs) in POSITIVE:
        got, err = assemble(args.mc, mattr, instrs)
        if got is None:
            # Try one at a time so one unsupported mnemonic does not blind the
            # whole category, and record the ones llvm-mc will not assemble.
            got = []
            for one in instrs:
                g, e = assemble(args.mc, mattr, [one])
                if g:
                    got.extend(g)
                else:
                    results["skipped"].append(
                        {"category": cat, "asm": one,
                         "llvm_mc_error": (e or "").splitlines()[:2]})
        for (asm, w) in got:
            r = BC.classify(w)
            rec = {"category": cat, "asm": asm, "word": f"{w:#010x}",
                   "classified": (r[0] if r else None),
                   "key": (r[1] if r else None)}
            results["positive"].append(rec)
            if not r or r[0] != cat:
                ok = False
                results["failures"].append(
                    {"kind": "positive_miss", **rec,
                     "expected": cat})

    neg_batches = [("BASELINE",) + NEGATIVE] + \
                  [("OPTIONAL_EXT", m, i) for (m, i) in NEGATIVE_OPTIONAL]
    for (label, nattr, ninstrs) in neg_batches:
        got, err = assemble(args.mc, nattr, ninstrs)
        if got is None:
            got = []
            for one in ninstrs:
                g, e = assemble(args.mc, nattr, [one])
                if g:
                    got.extend(g)
                else:
                    results["skipped"].append(
                        {"category": label, "asm": one,
                         "llvm_mc_error": (e or "").splitlines()[:2]})
        for (asm, w) in got:
            r = BC.classify(w)
            rec = {"group": label, "asm": asm, "word": f"{w:#010x}",
                   "classified": (r[0] if r else None),
                   "key": (r[1] if r else None)}
            results["negative"].append(rec)
            if r is not None:
                ok = False
                results["failures"].append({"kind": "false_positive", **rec})

    results["positive_cases"] = len(results["positive"])
    results["negative_cases"] = len(results["negative"])
    results["skipped_cases"] = len(results["skipped"])
    results["pass"] = ok

    os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)

    print(f"llvm-mc            : {args.mc}")
    print(f"positive cases     : {results['positive_cases']}")
    print(f"negative cases     : {results['negative_cases']}")
    print(f"skipped (llvm-mc refused): {results['skipped_cases']}")
    for s in results["skipped"][:20]:
        print(f"    SKIP {s['category']:<20} {s['asm']}")
    if results["failures"]:
        print(f"\nFAILURES ({len(results['failures'])}):")
        for f in results["failures"][:60]:
            print(f"    {f['kind']:<16} {f.get('asm'):<34} {f['word']} "
                  f"got={f.get('classified')} want={f.get('expected', 'None')}")
    print(f"\nwrote {args.json}")
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
