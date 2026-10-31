#!/usr/bin/env python3
"""
census_vs_sweep.py - put the decoder's count and the decoder-free count side
by side, per category, and say what their relation proves.

This is the file that turns two independent measurements into an evidence
grade. The master list's rubric asks, for grade A, for "instruction-level
decode plus an independent decoder-free bit-field scan that agree". Agreement
is not a feeling; it is a specific arithmetic relation, and there are exactly
three ways it can fail:

  TOO_MANY       sweep > census_total
                 The decoder reported more instructions of a category than
                 the encoding predicate can possibly match. Either the
                 predicate is too narrow (a mask bug), or the sweep is
                 classifying by mnemonic text in a way that crosses encoding
                 spaces. Both are defects and both must be named.

  DECODER_GAP    sweep < census_in_instruction_sections, by a wide margin
                 The predicate found hits inside sections Apple declares to
                 be code, which the decoder did not report. capstone 5.0 has
                 no SME decoder, so this is the shape a real decoder gap
                 takes. It makes the sweep's count a LOWER bound, which is
                 the dangerous direction.

  NOISE_BOUND    census_total is at or below its own uniform-random noise
                 floor
                 The predicate is too wide for its count to carry
                 information on its own (group-membership predicates such as
                 the SVE encoding group are like this: 4 constrained bits
                 means 1 word in 16 of any constant pool is a "hit"). The
                 sweep number is not contradicted, but the census cannot
                 corroborate it either, so the category stays at grade B on
                 this evidence alone.

and one way it can hold:

  CORROBORATED   sweep <= census_total, and sweep is within tolerance of
                 census_in_instruction_sections, and the census is above its
                 noise floor. Two methods with no shared code agree on the
                 count. That is the grade-A condition.

Nothing here adjudicates severity or host availability; see tools/n1_rollup.py.

    py tools/census_vs_sweep.py --census out/bitfield-census-dsc.json \
        --sweep analysis/compat/userland-dsc --out out/agreement.json
"""
import argparse
import json
import os
import sys

# census category -> sweep category. Several census categories fold into one
# sweep category because the sweep's taxonomy is per FEATURE while the census
# is per ENCODING GROUP; folding is done explicitly and the parts are kept.
FOLD = {
    "PAC": ["PAC_DP1", "PAC_PACGA", "PAC_BRANCH", "PAC_LDRA", "PAC_HINT"],
    "BTI": ["BTI"],
    "IMPDEF_SYSREG": ["IMPDEF_SYSREG", "IMPDEF_SYSINSTR"],
    "HVC_SMC": ["HVC", "SMC"],
    "APPLE_AMX": ["APPLE_AMX"],
    "APPLE_RESERVED_SPACE": ["APPLE_RESERVED"],
    "SVE": ["SVE_SME_SPACE"],
    "SME_SVCR": ["SME_ZA_SPACE"],
    "MTE": ["MTE"],
    "ARCH_EXT_ABOVE_V82": ["LDAPR", "LDAPUR", "SB", "PSTATE_ABOVE_V82"],
}

# Sweep categories whose census fold is KNOWN to be partial, so the only
# sound relation is sweep >= census and "sweep is bigger" is not a defect.
# ARCH_EXT_ABOVE_V82 is the sweep's bucket for every standard extension newer
# than v8.2: FEAT_JSCVT, FEAT_FCMA, FEAT_FlagM, FEAT_FRINTTS, FEAT_SPECRES,
# FEAT_BF16, FEAT_I8MM, FEAT_WFxT, FEAT_MOPS, FEAT_GCS and more. The census
# ships predicates for four of them. Reporting that difference as a decoder
# disagreement would be reporting the taxonomy as a bug.
PARTIAL_FOLD = {
    "ARCH_EXT_ABOVE_V82":
        "census covers FEAT_LRCPC, FEAT_LRCPC2, FEAT_SB and the PSTATE "
        "fields only; the sweep bucket also holds JSCVT, FCMA, FlagM, "
        "FRINTTS, SPECRES, BF16, I8MM, WFxT, MOPS and GCS",
    "MTE":
        "census covers IRG, GMI, ADDG and SUBG; the sweep bucket also holds "
        "the ST*G store-tag family and PSTATE.TCO",
}

# How close the two have to be to count as corroboration. 2% absorbs the
# genuine taxonomy differences: the sweep folds FEAT_LRCPC2 and PSTATE into
# ARCH_EXT_ABOVE_V82 alongside features the census has no predicate for, and
# the census buckets by section while the sweep buckets by terminal state.
TOLERANCE = 0.02
# A census count below this multiple of its measured random-data rate cannot
# corroborate anything.
MIN_SNR = 2.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", required=True)
    ap.add_argument("--sweep", required=True,
                    help="directory holding summary.json, or the file itself")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    with open(args.census, encoding="utf-8") as fh:
        cen = json.load(fh)
    sp = args.sweep
    if os.path.isdir(sp):
        sp = os.path.join(sp, "summary.json")
    with open(sp, encoding="utf-8") as fh:
        swp = json.load(fh)
    by_cat = swp.get("by_category", {})
    ccats = cen.get("categories", {})

    rows = []
    for sweep_cat, parts in FOLD.items():
        present = [p for p in parts if p in ccats]
        if not present and sweep_cat not in by_cat:
            continue
        c_tot = sum(ccats[p]["hits_upper_bound"] for p in present)
        c_instr = sum(ccats[p]["in_instruction_sections"] for p in present)
        c_noncode = sum(ccats[p]["in_noncode_sections"] for p in present)
        c_unsect = sum(ccats[p]["unsectioned"] for p in present)
        noise = sum((ccats[p].get("noise_floor") or {})
                    .get("expected_hits_if_all_bytes_were_random", 0)
                    for p in present)
        s = by_cat.get(sweep_cat, 0)
        snr = (c_tot / noise) if noise else None

        partial = PARTIAL_FOLD.get(sweep_cat)
        if c_tot and s == c_tot and s == c_instr and s > 0:
            # Exact equality between two methods that share no code is the
            # strongest form this comparison can take, and it does not need
            # the predicate to be narrow: the chance that constant-data
            # collisions land on precisely the decoder's count is negligible.
            # This is the relation the BootKC IMP-DEF register figure (50)
            # was graded A on in the first place.
            verdict = "CORROBORATED_EXACT"
            why = (f"decoder and predicate agree exactly at {s:,}, all of it "
                   "inside sections Apple declares to be code")
        elif partial and s >= c_tot:
            verdict = "CENSUS_PARTIAL_FOLD"
            why = (f"decoder {s:,} >= predicate {c_tot:,}, as expected: "
                   f"{partial}")
        elif c_tot and s > c_tot:
            verdict = "TOO_MANY"
            why = (f"the decoder reported {s:,} but no more than {c_tot:,} "
                   "words in the corpus match the encoding predicate at all")
        elif snr is not None and snr < MIN_SNR:
            verdict = "NOISE_BOUND"
            why = (f"the predicate's upper bound {c_tot:,} is only {snr:.3f}x "
                   f"its uniform-random rate ({noise:,.0f}), so it cannot "
                   "corroborate or contradict the decoder")
        elif c_instr and s < c_instr * (1 - TOLERANCE) and (c_instr - s) > 64:
            verdict = "DECODER_GAP"
            why = (f"{c_instr:,} hits sit inside sections Apple declares to "
                   f"be code, but the decoder reported only {s:,}; the "
                   "sweep count is a LOWER bound for this category")
        elif c_instr and abs(s - c_instr) <= max(64, c_instr * TOLERANCE):
            verdict = "CORROBORATED"
            why = (f"two methods with no shared code agree: decoder {s:,} vs "
                   f"predicate-in-code-sections {c_instr:,}")
        elif s <= c_tot:
            verdict = "CONSISTENT_NOT_TIGHT"
            why = (f"decoder {s:,} is within the predicate's bound {c_tot:,} "
                   f"but not close to the in-code-section figure {c_instr:,}")
        else:
            verdict = "UNDETERMINED"
            why = "no relation established"

        rows.append({
            "sweep_category": sweep_cat,
            "census_parts": present,
            "census_upper_bound": c_tot,
            "census_in_instruction_sections": c_instr,
            "census_in_noncode_sections": c_noncode,
            "census_unsectioned": c_unsect,
            "census_noise_floor": round(noise, 1),
            "census_signal_to_noise": (round(snr, 3) if snr is not None else None),
            "sweep_findings": s,
            "verdict": verdict,
            "reasoning": why,
            "census_fold_is_partial": partial,
            "data_collision_share_of_census": (
                round(c_noncode / c_tot, 6) if c_tot else None),
        })

    unmatched = sorted(set(ccats) - {p for ps in FOLD.values() for p in ps})
    doc = {
        "schema": "armmac-decoder-agreement/1",
        "census": args.census, "sweep": sp,
        "census_image": cen.get("image"), "sweep_image": swp.get("image"),
        "census_bytes_scanned": (cen.get("totals") or {}).get("bytes_scanned"),
        "census_bucket_bytes": cen.get("bucket_bytes") or
                               (cen.get("totals") or {}).get("bucket_bytes"),
        "census_shard_tiling_holds": cen.get("shard_tiling_holds"),
        "sweep_findings_total": swp.get("findings_total"),
        "tolerance": TOLERANCE, "min_signal_to_noise": MIN_SNR,
        "categories": rows,
        "census_categories_not_folded": unmatched,
        "verdict_counts": {},
    }
    for r in rows:
        doc["verdict_counts"][r["verdict"]] = \
            doc["verdict_counts"].get(r["verdict"], 0) + 1

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)

    print(f"census : {args.census}")
    print(f"sweep  : {sp}")
    print(f"\n{'sweep category':<24}{'decoder':>12}{'predicate':>13}"
          f"{'in code':>12}{'in data':>12}{'S/N':>9}  verdict")
    for r in rows:
        print(f"{r['sweep_category']:<24}{r['sweep_findings']:>12,}"
              f"{r['census_upper_bound']:>13,}"
              f"{r['census_in_instruction_sections']:>12,}"
              f"{r['census_in_noncode_sections']:>12,}"
              f"{str(r['census_signal_to_noise']):>9}  {r['verdict']}")
    print("\nverdicts: " + ", ".join(f"{k}={v}" for k, v
                                     in doc["verdict_counts"].items()))
    if unmatched:
        print("census categories with no sweep counterpart: "
              + ", ".join(unmatched))
    for r in rows:
        if r["verdict"] in ("TOO_MANY", "DECODER_GAP"):
            print(f"\n::warning title={r['verdict']} in {r['sweep_category']}::"
                  f"{r['reasoning']}")
    print(f"\n[+] wrote {args.out}")
    # A gap or an impossible count is a finding to be recorded, not a reason
    # to fail the aggregate: the aggregate's own gate reads missing_components.
    return 0


if __name__ == "__main__":
    sys.exit(main())
