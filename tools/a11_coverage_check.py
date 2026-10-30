#!/usr/bin/env python3
"""
a11_coverage_check.py - prove the merged sweep's arithmetic, or fail.

"The sweep ran without errors" is not a coverage claim. This checks the one
identity that makes the percentage mean anything:

    sum(byte terminal states) == declared total executable bytes

If those differ, a byte was counted twice or not at all, and every figure
derived from the total is void. Run as the aggregate step of
.github/workflows/sweep_full_25G83.yml.

    python3 tools/a11_coverage_check.py --scopes dyld=out/merged-dsc \
        rootfs=out/merged-rootfs full=out/merged \
        --out reports/coverage_rows.json --missing reports/missing_components.txt

Exit 0 if every scope's identity holds, 1 otherwise.
"""

import argparse
import json
import os
import sys


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scopes", nargs="+", required=True,
                    help="label=dir pairs, e.g. full=out/merged")
    ap.add_argument("--out", default="reports/coverage_rows.json")
    ap.add_argument("--missing", default="reports/missing_components.txt")
    args = ap.parse_args()

    rows = []
    for spec in args.scopes:
        label, _, d = spec.partition("=")
        cov = load(os.path.join(d, "byte-coverage.json"))
        if not cov:
            print(f"(no byte-coverage.json in {d}; scope '{label}' skipped)")
            continue
        fc = load(os.path.join(d, "file-coverage.json")) or {}
        sm = load(os.path.join(d, "summary.json")) or {}
        fx = load(os.path.join(d, "fixup-coverage.json")) or {}
        states = cov.get("states", {})
        total = cov.get("total_executable_bytes_accounted", 0)
        ssum = sum(states.values())
        rows.append({
            "scope": label,
            "dir": d,
            "executable_bytes": total,
            "state_sum": ssum,
            "identity_holds": ssum == total,
            "strong_coverage_pct": cov.get("strong_coverage_pct"),
            "bytes_failing": cov.get("bytes_with_failing_state"),
            "bytes_weak": cov.get("bytes_with_weak_evidence"),
            "gate1_pass": cov.get("gate1_pass"),
            "shards": cov.get("shards"),
            "findings_total": sm.get("findings_total"),
            "by_category": sm.get("by_category"),
            "components_with_findings": sm.get("components_with_findings"),
            "files_with_terminal_state": fc.get("files_with_terminal_state"),
            "files_failing": fc.get("files_with_failing_state"),
            "file_states": fc.get("file_states"),
            "arch_slices_seen": fc.get("arch_slices_seen"),
            "fixups_total": fx.get("fixups_total"),
            "fixups_auth": fx.get("auth_total"),
            "fixup_p1_gate_failures": len(fx.get("p1_gate_failures") or []),
        })

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)

    for r in rows:
        print(f"--- {r['scope']} ({r['dir']})")
        for k in ("executable_bytes", "state_sum", "identity_holds",
                  "strong_coverage_pct", "bytes_failing", "bytes_weak",
                  "gate1_pass", "findings_total", "components_with_findings",
                  "files_with_terminal_state", "files_failing",
                  "fixups_total", "fixups_auth", "fixup_p1_gate_failures"):
            print(f"    {k:<28} {r.get(k)}")

    bad = [r for r in rows if not r["identity_holds"]]
    if bad:
        print("::error title=Coverage identity broken::per-state bytes do not "
              "sum to the declared total; the percentage is not usable")
        try:
            with open(args.missing, "a", encoding="utf-8") as f:
                for r in bad:
                    f.write(f"AGGREGATE_COVERAGE_IDENTITY_BROKEN {r['scope']} "
                            f"declared={r['executable_bytes']} "
                            f"sum={r['state_sum']}\n")
        except OSError:
            pass
        return 1
    if not rows:
        print("::error title=No coverage to check::no scope produced a report")
        try:
            with open(args.missing, "a", encoding="utf-8") as f:
                f.write("AGGREGATE_NO_COVERAGE_ROWS\n")
        except OSError:
            pass
        return 1
    print("coverage identity holds for every scope.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
