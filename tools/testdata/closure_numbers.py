#!/usr/bin/env python3
"""
closure_numbers.py - print every figure userland-coverage-closure.md quotes,
from the committed artefacts, so each one can be re-derived with one command
instead of trusted.

    py tools/testdata/closure_numbers.py
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
C = os.path.join(ROOT, "analysis", "compat")

WEAK = ("DATA_UNREACHABLE_UNDECODABLE", "DATA_INTERSTITIAL_NONZERO")
FAIL = ("UNKNOWN_ENCODING", "UNSET")


def jload(*p):
    with open(os.path.join(C, *p), encoding="utf-8") as fh:
        return json.load(fh)


def scope(name, d):
    try:
        cov = jload(d, "byte-coverage.json")
        summ = jload(d, "summary.json")
    except Exception as exc:
        print(f"{name:<26} ABSENT ({exc})")
        return None
    tot = cov["total_executable_bytes_accounted"]
    proven = sum(v for k, v in cov["states"].items()
                 if k.startswith("DATA_") and k not in WEAK)
    extra = cov.get("extra_byte_notes", {}) or {}
    print(f"\n### {name}   ({d})")
    print(f"  executable bytes          {tot:>16,}")
    print(f"  strong coverage           {cov['strong_coverage_pct']:>16}%")
    print(f"  bytes weak                {cov['bytes_with_weak_evidence']:>16,}")
    print(f"  bytes failing             {cov['bytes_with_failing_state']:>16,}")
    print(f"  gate1_pass                {str(cov['gate1_pass']):>16}")
    print(f"  proven-data bytes         {proven:>16,}  "
          f"({100.0 * proven / tot:.2f}% of the mapping)")
    print(f"  findings_total            {summ['findings_total']:>16,}")
    print(f"  components with findings  "
          f"{(summ.get('components_with_findings') or summ.get('kexts_with_findings') or 0):>16,}")
    for k in ("findings_unreachable", "findings_adjacent_to_data",
              "findings_absorbed_into_data_blobs",
              "dsc_images_with_section_headers",
              "dsc_images_without_section_headers",
              "untiled_bytes_outside_every_section",
              "untiled_code_sections", "untiled_noncode_sections"):
        if k in extra:
            print(f"  {k:<26}{extra[k]:>16,}")
    sv = summ.get("by_category_severity", {}) or {}
    if "PAC/block" in sv or "PAC/degrade" in sv:
        print(f"  PAC/block                 {sv.get('PAC/block', 0):>16,}")
        print(f"  PAC/degrade               {sv.get('PAC/degrade', 0):>16,}")
    return {"cov": cov, "summ": summ, "proven": proven}


def main():
    print("=" * 78)
    print("userland-coverage-closure.md: every quoted figure, re-derived")
    print("=" * 78)

    scopes = [
        ("bootkc", "."),
        ("userland_dsc BEFORE (grade C)", "userland-dsc"),
        ("userland_dsc AFTER (sections)", "userland-dsc-sections"),
        ("rootfs_macho", "rootfs-macho"),
        ("driverkit_dsc", "driverkit-dsc"),
        ("cryptex_macho", "cryptex-macho"),
        ("fat_macho_control", os.path.join("local-validate", "fat-dyld")),
        ("standalone_kernel_control", os.path.join("local-validate",
                                                   "kernel-control-after")),
    ]
    got = {}
    for n, d in scopes:
        got[n] = scope(n, d)

    print("\n" + "=" * 78)
    print("mnemonic census: the decode that was quoted as proof of data")
    print("=" * 78)
    for label, d in (("before", "userland-dsc"),
                     ("after", "userland-dsc-sections")):
        try:
            m = jload(d, "mnemonic-census.json")
        except Exception:
            continue
        tot = sum(r["n"] for r in m["mnemonics"])
        row = next((r for r in m["mnemonics"] if r["mnemonic"] == "fnmls"), None)
        print(f"  {label:<8} distinct mnemonics {m['count']:>8,}   "
              f"decoded words {tot:>14,}   "
              f"fnmls {(row or {}).get('n', 0):>12,}")
        print("           top: " + ", ".join(
            f"{r['mnemonic']}={r['n']:,}" for r in m["mnemonics"][:5]))

    print("\n" + "=" * 78)
    print("decoder-free census: identities and the structural ceilings")
    print("=" * 78)
    try:
        cen = jload("bitfield-census-userland-dsc.json")
        print(f"  bytes scanned           {cen['totals']['bytes_scanned']:>16,}")
        print(f"  declared container      "
              f"{cen['declared_container_exec_bytes']:>16,}")
        print(f"  shard tiling holds      {str(cen['shard_tiling_holds']):>16}")
        print(f"  bucket identity holds   {str(cen['bucket_identity_holds']):>16}")
        print(f"  bucket bytes            {cen['bucket_bytes']}")
        print(f"  {'category':<20}{'upper bound':>14}{'in code':>12}"
              f"{'in data':>14}{'unsect':>11}{'noise':>14}")
        for k, v in cen["categories"].items():
            nf = (v.get("noise_floor") or {}).get(
                "expected_hits_if_all_bytes_were_random", 0)
            print(f"  {k:<20}{v['hits_upper_bound']:>14,}"
                  f"{v['in_instruction_sections']:>12,}"
                  f"{v['in_noncode_sections']:>14,}{v['unsectioned']:>11,}"
                  f"{nf:>14,.0f}")
    except Exception as exc:
        print(f"  census absent: {exc}")

    print("\n" + "=" * 78)
    print("N1 action rollup")
    print("=" * 78)
    try:
        r = jload("n1-action-rollup.json")
        for s in r["scopes"]:
            if not s.get("present"):
                continue
            a = s["actions"]
            print(f"  {s['scope']:<24}"
                  f"REWRITE {a['REWRITE_REQUIRED']:>12,}  "
                  f"NOP {a['NO_ACTION_NOP']:>12,}  "
                  f"HOST {a['NO_ACTION_HOST_HAS_IT']:>9,}  "
                  f"PROTO {a['PROTOCOL_UNDEFINED']:>6,}  "
                  f"UNADJ {a['UNADJUDICATED']:>8,}  "
                  f"{'OK' if s['apportionment_complete'] else 'INCOMPLETE'}")
        g = r["grand_total"]
        print(f"  {'TOTAL':<24}"
              f"REWRITE {g['REWRITE_REQUIRED']:>12,}  "
              f"NOP {g['NO_ACTION_NOP']:>12,}  "
              f"HOST {g['NO_ACTION_HOST_HAS_IT']:>9,}  "
              f"PROTO {g['PROTOCOL_UNDEFINED']:>6,}  "
              f"UNADJ {g['UNADJUDICATED']:>8,}")
    except Exception as exc:
        print(f"  rollup absent: {exc}")

    print("\n" + "=" * 78)
    print("decoder agreement")
    print("=" * 78)
    try:
        ag = jload("decoder-agreement-userland-dsc.json")
        for row in ag["categories"]:
            print(f"  {row['sweep_category']:<22}"
                  f"decoder {row['sweep_findings']:>12,}  "
                  f"predicate {row['census_upper_bound']:>12,}  "
                  f"in-code {row['census_in_instruction_sections']:>12,}  "
                  f"{row['verdict']}")
        print(f"  verdicts: {ag['verdict_counts']}")
    except Exception as exc:
        print(f"  agreement absent: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
