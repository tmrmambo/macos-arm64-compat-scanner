#!/usr/bin/env python3
"""
census_scope_probe.py - answer "is this scope already inside a swept corpus?"
from the authoritative root-volume file census, instead of guessing.

The master list's scopes_not_swept lists auxkc_preboot_recovery as NOT SWEPT.
That claim has to be checked against the census rather than restated: if those
paths are root-volume files, the rootfs_macho sweep already covered them and
the "not swept" row is wrong; if they are absent, the row is right and names a
real gap that needs its own container.

    py tools/testdata/census_scope_probe.py <worklist.jsonl> [--prefix P ...]
"""
import argparse
import collections
import json
import sys

DEFAULT_PATTERNS = {
    # AuxKC / kernel collections
    "System/Library/KernelCollections": "auxkc",
    "AuxKernelCollection": "auxkc",
    "BootKernelExtensions": "auxkc",
    "SystemKernelExtensions": "auxkc",
    # Preboot / Recovery / BaseSystem
    "Preboot": "preboot",
    "Recovery": "recovery",
    "BaseSystem": "recovery",
    "RestoreRamDisk": "recovery",
    "/Restore": "recovery",
    # DriverKit userland (separate cache group)
    "System/DriverKit": "driverkit",
    # the dyld caches themselves
    "System/Library/dyld": "dsc",
    # cryptex mount points, if any appear as root-volume paths
    "Cryptexes": "cryptex",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("worklist")
    ap.add_argument("--max-examples", type=int, default=5)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    total = 0
    states = collections.Counter()
    state_bytes = collections.Counter()
    scope_states = collections.defaultdict(collections.Counter)
    scope_bytes = collections.defaultdict(collections.Counter)
    examples = collections.defaultdict(list)

    with open(args.worklist, encoding="utf-8") as fh:
        for line in fh:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            total += 1
            rel = r.get("rel") or ""
            st = r.get("state") or "?"
            sz = r.get("size") or 0
            states[st] += 1
            state_bytes[st] += sz
            for pat, scope in DEFAULT_PATTERNS.items():
                if pat in rel:
                    scope_states[scope][st] += 1
                    scope_bytes[scope][st] += sz
                    if len(examples[scope]) < args.max_examples:
                        examples[scope].append({"state": st, "rel": rel, "size": sz})

    doc = {
        "worklist": args.worklist,
        "entries": total,
        "states": dict(states.most_common()),
        "state_bytes": dict(state_bytes.most_common()),
        "scopes": {
            s: {
                "states": dict(c.most_common()),
                "bytes": dict(scope_bytes[s].most_common()),
                "macho_todo": sum(n for k, n in c.items()
                                  if str(k).startswith("TODO_MACHO")),
                "examples": examples[s],
            } for s, c in sorted(scope_states.items())
        },
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1)

    print(f"entries: {total:,}")
    for k, n in states.most_common():
        print(f"  {k:<30} {n:>9,}  {state_bytes[k]:>16,} B")
    print("\nscope probes (does the root-volume census already contain it?)")
    for s, rec in doc["scopes"].items():
        print(f"\n  {s}: {sum(rec['states'].values()):,} entries, "
              f"{rec['macho_todo']:,} Mach-O queued for sweep")
        for k, n in rec["states"].items():
            print(f"      {k:<28} {n:>8,}")
        for ex in rec["examples"]:
            print(f"      e.g. {ex['state']:<24} {ex['rel'][:100]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
