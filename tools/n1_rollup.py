#!/usr/bin/env python3
"""
n1_rollup.py - re-express the sweep's findings as "how many words have to
change to run this on a Neoverse N1", instead of as a distance from an
abstract baseline.

WHY THE RE-EXPRESSION MATTERS
-----------------------------
The sweep counts findings against armmac-generic-v1, which stops at
ARMv8.2-A and promises only FP, AdvSIMD, FEAT_LSE and FEAT_TGran16. A real
Neoverse N1 is ARMv8.2-A but implements more than that promise: AES, PMULL,
SHA1, SHA256, FP16, DotProd and FEAT_LRCPC are all present. Counting those as
work to be done overstates the job. Counting PAC's HINT half as work to be
done overstates it again, because those encodings execute as a NOP.

And the converse trap: FEAT_BTI is ABSENT on Neoverse N1, yet BTI needs no
work at all, for the same HINT-space reason. "The host lacks the feature" and
"the guest must change" are different claims, and only the encoding space
decides between them. A rollup driven purely off host support tables gets
this backwards.

Each finding lands in exactly one action class:

  REWRITE_REQUIRED       UNDEFINED on N1. The word must change or the guest
                         takes an Undefined Instruction exception.
  NO_ACTION_NOP          In the HINT encoding space. Executes as a NOP on an
                         implementation that lacks the feature, so the word
                         may stay. Semantics are lost, which is a correctness
                         question for the software, not a loading question.
  NO_ACTION_HOST_HAS_IT  Above the armmac-generic-v1 promise, but the N1
                         profile records the feature as present on every
                         first-class host. Zero work.
  PROTOCOL_UNDEFINED     HVC / SMC. The instruction is architectural; the
                         call interface behind it is not, and nothing in a
                         static scan can decide it.
  UNADJUDICATED          No host-profile entry and no architectural rule.
                         Counted, never assumed either way.

Apportionment runs over summary.json's by_feature for the findings that carry
a feature, plus the feature-less categories from CATEGORY_RULE below. Those
two halves partition the findings, and the sum is checked against
findings_total: apportionment_complete=false means a number in this file is
not trustworthy and says so rather than balancing silently.

Host availability is read from analysis/compat/host-cpu-profiles.json, not
asserted here. A feature counts as present only if the profile says YES for
every first-class key; NO or unverified on any of them sends it to
REWRITE_REQUIRED, which is the conservative direction.

Every class total is reported next to the scope's own data-collision
indicators, because a count of words to rewrite is only as good as the
proportion of those words that are really instructions.

    py tools/n1_rollup.py --scopes bootkc=analysis/compat \
        userland_dsc=analysis/compat/userland-dsc \
        rootfs_macho=analysis/compat/rootfs-macho \
        --out analysis/compat/n1-action-rollup.json
"""
import argparse
import collections
import json
import os
import re
import sys

FEAT_RE = re.compile(r"(FEAT_[A-Za-z0-9_]+)")

# First-class hosts, per the converged host set: AWS t4g (Graviton2), Oracle
# A1 VM (Ampere Altra), Azure Bpsv2 (Ampere Altra). All three are Arm
# Neoverse N1. The profile document keys them as below; Azure has no key of
# its own there, which is recorded rather than invented.
N1_HOST_KEYS = ("graviton2", "altra")
TESTBED_HOST_KEYS = ("qemu_neoverse_n1",)
HOSTS_NOT_IN_PROFILE = {
    "azure_bpsv2": "Azure Bpsv2 is an Ampere Altra (Neoverse N1) shape, but "
                   "host-cpu-profiles.json has no entry for it. It is treated "
                   "as covered by the `altra` profile for the ISA questions, "
                   "and listed here so the substitution is visible rather "
                   "than implied.",
}

# Action class from the architecture alone, for categories the sweep does not
# give a feature string. The reason is recorded with each one because these
# are the judgements the whole rollup rests on.
CATEGORY_RULE = {
    "IMPDEF_SYSREG": ("REWRITE_REQUIRED",
                      "IMPLEMENTATION DEFINED register and system-instruction "
                      "space. No non-Apple implementer allocates it, so the "
                      "access is UNDEFINED on any N1."),
    "APPLE_AMX": ("REWRITE_REQUIRED",
                  "Apple-private coprocessor encodings in a space the "
                  "architecture reserves for the implementer; UNDEFINED on "
                  "every non-Apple implementation."),
    "APPLE_GXF": ("REWRITE_REQUIRED", "Apple-private guarded execution."),
    "APPLE_RESERVED_SPACE": ("REWRITE_REQUIRED",
                             "reserved/UNALLOCATED encoding space."),
    "HVC_SMC": ("PROTOCOL_UNDEFINED",
                "the instruction is architectural on every ARMv8-A; the call "
                "interface behind the immediate is not, and a static scan "
                "cannot decide it."),
    "UNKNOWN_ENCODING": ("REWRITE_REQUIRED",
                         "no decoder produced an instruction and the word is "
                         "reachable with no data evidence; it cannot be left "
                         "in place on an unknown-good assumption."),
    "UNCLASSIFIED_MNEMONIC": ("UNADJUDICATED",
                              "decoded, but in neither the baseline nor the "
                              "above-baseline table."),
    "UNCLASSIFIED_SYSREG": ("UNADJUDICATED",
                            "unallocated encoding in the architectural "
                            "register space."),
}

# Features whose action class follows from the encoding space, overriding the
# host lookup in both directions.
FEATURE_RULE = {
    "FEAT_BTI": ("NO_ACTION_NOP",
                 "absent on Neoverse N1, but the encodings are in the HINT "
                 "space, where unallocated encodings execute as NOP rather "
                 "than faulting"),
    "FEAT_SVE": ("REWRITE_REQUIRED",
                 "absent on Neoverse N1, and the encoding group is "
                 "UNALLOCATED on ARMv8.2-A"),
    "FEAT_SME": ("REWRITE_REQUIRED", "absent on Neoverse N1"),
    "FEAT_MTE": ("REWRITE_REQUIRED", "absent on Neoverse N1"),
}

ACTION_CLASSES = ("REWRITE_REQUIRED", "NO_ACTION_NOP", "NO_ACTION_HOST_HAS_IT",
                  "PROTOCOL_UNDEFINED", "UNADJUDICATED")


def jload(p):
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def host_support(profile, feat):
    """-> (verdict, detail). Reads the adjudicated profile, asserts nothing."""
    if not profile:
        return None, "host-cpu-profiles.json not loaded"
    f = (profile.get("features") or {}).get(feat)
    if not f:
        return None, f"{feat} has no entry in host-cpu-profiles.json"
    yes, no = [], []
    for h in N1_HOST_KEYS:
        rec = (f.get("support") or {}).get(h) or {}
        v = rec.get("value")
        tag = f"{h}={v or '?'}/{rec.get('grade', '?')}"
        (yes if v == "YES" else no).append(tag)
    if no:
        return "NO", ("present on " + ",".join(yes) + "; " if yes else "") + \
                     "absent or unverified on " + ",".join(no)
    return "YES", "present on " + ",".join(yes)


def classify_feature(profile, feat):
    v, detail = host_support(profile, feat)
    if v == "YES":
        return "NO_ACTION_HOST_HAS_IT", detail
    if v == "NO":
        return "REWRITE_REQUIRED", detail
    return "UNADJUDICATED", detail


def roll_scope(label, d, profile):
    summ = jload(os.path.join(d, "summary.json"))
    cov = jload(os.path.join(d, "byte-coverage.json"))
    if not summ:
        return {"scope": label, "dir": d, "present": False}

    by_cat = summ.get("by_category", {}) or {}
    by_sev = summ.get("by_category_severity", {}) or {}
    by_feat = summ.get("by_feature", {}) or {}

    actions = collections.Counter()
    rows = []

    # --- half 1: findings that carry a FEAT_ string ----------------------
    for fk, fn in sorted(by_feat.items(), key=lambda kv: -kv[1]):
        m = FEAT_RE.search(fk or "")
        feat = m.group(1) if m else None
        if feat == "FEAT_PAuth":
            # The one feature that MUST be split, because its halves have
            # opposite action classes. The sweep already carries the split in
            # by_category_severity: "block" is the register and branch forms,
            # which are UNDEFINED, and "degrade" is the HINT forms, which NOP.
            blk = by_sev.get("PAC/block", 0)
            deg = by_sev.get("PAC/degrade", 0)
            if blk + deg != fn:
                actions["UNADJUDICATED"] += fn
                rows.append({"feature": fk, "action": "UNADJUDICATED",
                             "findings": fn,
                             "reason": f"severity split {blk}+{deg} does not "
                                       f"sum to {fn}; refusing to apportion"})
                continue
            actions["REWRITE_REQUIRED"] += blk
            actions["NO_ACTION_NOP"] += deg
            rows.append({"feature": fk + " (register and branch forms)",
                         "action": "REWRITE_REQUIRED", "findings": blk,
                         "reason": "absent on Neoverse N1 and outside the "
                                   "HINT space, therefore UNDEFINED"})
            rows.append({"feature": fk + " (HINT forms)",
                         "action": "NO_ACTION_NOP", "findings": deg,
                         "reason": "HINT-space encodings execute as NOP. The "
                                   "paired RETAB is safe to downgrade because "
                                   "PACIBSP never signed anything, not "
                                   "because we also turned it into a NOP"})
            continue
        if feat in FEATURE_RULE:
            act, why = FEATURE_RULE[feat]
        elif feat:
            act, why = classify_feature(profile, feat)
        else:
            act, why = "UNADJUDICATED", "no FEAT_ string in the feature label"
        actions[act] += fn
        rows.append({"feature": fk, "action": act, "findings": fn,
                     "reason": why})

    # --- half 2: findings whose category carries no feature ---------------
    for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
        rule = CATEGORY_RULE.get(cat)
        if not rule:
            continue
        actions[rule[0]] += n
        rows.append({"category": cat, "action": rule[0], "findings": n,
                     "reason": rule[1]})

    extra = (cov or {}).get("extra_byte_notes", {}) or {}
    total = sum(actions.values())
    reported = summ.get("findings_total")
    unaccounted = sorted(
        (c, n) for c, n in by_cat.items()
        if c not in CATEGORY_RULE and c not in (
            "PAC", "BTI", "SVE", "SME_SVCR", "MTE", "ARCH_EXT_ABOVE_V82",
            "OPT_EXT_V82", "SYSREG_EL2_EL3"))
    return {
        "scope": label, "dir": d, "present": True,
        "image": summ.get("image"),
        "findings_total_reported_by_sweep": reported,
        "findings_apportioned": total,
        "apportionment_complete": total == reported,
        "apportionment_delta": (total - reported) if reported is not None else None,
        "categories_with_no_rule_and_no_feature": [
            {"category": c, "findings": n} for c, n in unaccounted],
        "actions": {k: actions.get(k, 0) for k in ACTION_CLASSES},
        "rows": rows,
        "confidence_indicators": {
            "executable_bytes": (cov or {}).get(
                "total_executable_bytes_accounted"),
            "strong_coverage_pct": (cov or {}).get("strong_coverage_pct"),
            "bytes_with_weak_evidence": (cov or {}).get(
                "bytes_with_weak_evidence"),
            "bytes_with_failing_state": (cov or {}).get(
                "bytes_with_failing_state"),
            "findings_unreachable": extra.get("findings_unreachable"),
            "findings_adjacent_to_data": extra.get("findings_adjacent_to_data"),
            "findings_absorbed_into_data_blobs": extra.get(
                "findings_absorbed_into_data_blobs"),
            "proven_data_bytes": sum(
                v for k, v in ((cov or {}).get("states") or {}).items()
                if k.startswith("DATA_")),
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scopes", nargs="+", required=True,
                    help="label=dir pairs")
    ap.add_argument("--profile", default=os.path.join(
        "analysis", "compat", "host-cpu-profiles.json"))
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    profile = jload(args.profile)
    scopes = []
    for spec in args.scopes:
        label, _, d = spec.partition("=")
        scopes.append(roll_scope(label, d, profile))

    grand = collections.Counter()
    incomplete = []
    for s in scopes:
        if s.get("present"):
            for k, v in s["actions"].items():
                grand[k] += v
            if not s["apportionment_complete"]:
                incomplete.append(s["scope"])

    doc = {
        "schema": "armmac-n1-action-rollup/1",
        "target_host_class": {
            "core": "Arm Neoverse N1",
            "isa": "ARMv8.2-A",
            "first_class_shapes": ["AWS t4g (Graviton2)",
                                   "Oracle A1 VM (Ampere Altra)",
                                   "Azure Bpsv2 (Ampere Altra)"],
            "profile_keys_used": list(N1_HOST_KEYS),
            "testbed_keys": list(TESTBED_HOST_KEYS),
            "shapes_without_a_profile_entry": HOSTS_NOT_IN_PROFILE,
            "absent_features_that_drive_the_work": [
                "FEAT_PAuth", "FEAT_BTI", "FEAT_SVE", "FEAT_SME",
                "FEAT_MTE", "FEAT_SHA3", "FEAT_SHA512"],
            "present_features_that_remove_work": [
                "FEAT_AES", "FEAT_PMULL", "FEAT_SHA1", "FEAT_SHA256",
                "FEAT_FP16", "FEAT_DotProd", "FEAT_LRCPC", "FEAT_LSE"],
            "kvm_caveat":
                "host-cpu-profiles.json records KVM on Graviton as possible "
                "only on bare metal, and Ampere Altra KVM only on "
                "BM.Standard.A1.160. The three first-class shapes named above "
                "are all ordinary VM shapes, so this rollup answers the ISA "
                "question for them and does NOT assert that a KVM guest can "
                "be started on them.",
        },
        "action_class_docs": {
            "REWRITE_REQUIRED": "UNDEFINED on N1; the word must change",
            "NO_ACTION_NOP": "HINT space; executes as NOP, the word may stay",
            "NO_ACTION_HOST_HAS_IT": "above the armmac-generic-v1 promise but "
                                     "present on every first-class N1 host",
            "PROTOCOL_UNDEFINED": "HVC/SMC; interface not decidable statically",
            "UNADJUDICATED": "counted, not assumed either way",
        },
        "profile": args.profile,
        "profile_loaded": profile is not None,
        "scopes": scopes,
        "grand_total": {k: grand.get(k, 0) for k in ACTION_CLASSES},
        "grand_total_findings": sum(grand.values()),
        "scopes_with_incomplete_apportionment": incomplete,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1)

    print("Neoverse N1 action rollup  (ARMv8.2-A; no PAC, BTI, SVE, SME, MTE,")
    print("                            SHA3 or SHA512; LRCPC and the v8.0/8.2")
    print("                            crypto and FP16/DotProd group present)")
    print("=" * 104)
    print(f"{'scope':<22}{'REWRITE':>14}{'NOP':>14}{'HOST_HAS_IT':>14}"
          f"{'PROTOCOL':>11}{'UNADJ':>10}{'coverage':>13}")
    for s in scopes:
        if not s.get("present"):
            print(f"{s['scope']:<22}  ABSENT ({s['dir']})")
            continue
        a = s["actions"]
        ci = s["confidence_indicators"]
        print(f"{s['scope']:<22}{a['REWRITE_REQUIRED']:>14,}"
              f"{a['NO_ACTION_NOP']:>14,}{a['NO_ACTION_HOST_HAS_IT']:>14,}"
              f"{a['PROTOCOL_UNDEFINED']:>11,}{a['UNADJUDICATED']:>10,}"
              f"{str(ci['strong_coverage_pct']) + '%':>13}")
        if not s["apportionment_complete"]:
            print(f"{'':<22}  ::warning:: apportioned "
                  f"{s['findings_apportioned']:,} vs reported "
                  f"{s['findings_total_reported_by_sweep']:,} "
                  f"(delta {s['apportionment_delta']:+,})")
        if s["categories_with_no_rule_and_no_feature"]:
            print(f"{'':<22}  no rule: "
                  + ", ".join(f"{r['category']}={r['findings']:,}"
                              for r in s["categories_with_no_rule_and_no_feature"]))
    print("-" * 104)
    for c in ACTION_CLASSES:
        print(f"  {c:<26} {grand.get(c, 0):>14,}")
    print(f"  {'TOTAL':<26} {sum(grand.values()):>14,}")
    if incomplete:
        print(f"\n::warning title=Incomplete apportionment::{incomplete}")
    print(f"\n[+] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
