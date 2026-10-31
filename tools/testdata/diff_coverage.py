#!/usr/bin/env python3
"""
diff_coverage.py - compare two sweep output directories, byte state by byte
state and category by category.

Used two ways:
  * regression control: prove a change to the state machine moved nothing in a
    scope it should not have touched (the standalone kernel must still produce
    81,453 findings over 9,814,016 bytes).
  * before/after: quantify, with no hand arithmetic, what a change did to the
    scope it was aimed at.

    py tools/testdata/diff_coverage.py <before_dir> <after_dir> [--json OUT]
"""
import argparse
import json
import os
import sys


def jload(d, name):
    p = os.path.join(d, name)
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    a = jload(args.before, "byte-coverage.json")
    b = jload(args.after, "byte-coverage.json")
    sa = jload(args.before, "summary.json")
    sb = jload(args.after, "summary.json")

    scalar = ["total_executable_bytes_accounted",
              "bytes_with_strong_terminal_state",
              "bytes_with_weak_evidence", "bytes_with_failing_state",
              "strong_coverage_pct", "gate1_pass"]
    rows = []
    identical = True
    print(f"before: {args.before}")
    print(f"after : {args.after}\n")
    print(f"{'field':<42}{'before':>16}{'after':>16}{'delta':>16}")
    for k in scalar:
        x, y = a.get(k), b.get(k)
        if isinstance(x, (int, float)) and isinstance(y, (int, float)) \
                and not isinstance(x, bool):
            d = round(y - x, 6)
        else:
            d = "" if x == y else f"{x} -> {y}"
        if x != y:
            identical = False
        rows.append({"field": k, "before": x, "after": y, "delta": d})
        print(f"{k:<42}{str(x):>16}{str(y):>16}{str(d):>16}")

    print(f"\n{'byte terminal state':<42}{'before':>16}{'after':>16}{'delta':>16}")
    states = {}
    for k in sorted(set(a.get("states", {})) | set(b.get("states", {}))):
        x = a.get("states", {}).get(k, 0)
        y = b.get("states", {}).get(k, 0)
        states[k] = {"before": x, "after": y, "delta": y - x}
        if x != y:
            identical = False
        print(f"{k:<42}{x:>16,}{y:>16,}{y-x:>+16,}")

    print(f"\n{'finding category':<42}{'before':>16}{'after':>16}{'delta':>16}")
    cats = {}
    ca, cb = sa.get("by_category", {}), sb.get("by_category", {})
    for k in sorted(set(ca) | set(cb)):
        x, y = ca.get(k, 0), cb.get(k, 0)
        cats[k] = {"before": x, "after": y, "delta": y - x}
        if x != y:
            identical = False
        print(f"{k:<42}{x:>16,}{y:>16,}{y-x:>+16,}")
    ft_a, ft_b = sa.get("findings_total", 0), sb.get("findings_total", 0)
    print(f"{'findings_total':<42}{ft_a:>16,}{ft_b:>16,}{ft_b-ft_a:>+16,}")

    doc = {"before": args.before, "after": args.after, "scalars": rows,
           "states": states, "categories": cats,
           "findings_total": {"before": ft_a, "after": ft_b,
                              "delta": ft_b - ft_a},
           "identical": identical,
           "extra_byte_notes": {"before": a.get("extra_byte_notes"),
                                "after": b.get("extra_byte_notes")}}
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)
        print(f"\n[+] wrote {args.json}")
    print(f"\nIDENTICAL: {identical}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
