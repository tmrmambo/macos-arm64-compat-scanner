#!/usr/bin/env python3
"""
merge_cloud_shards.py - fold downloaded cloud shard reports into
analysis/compat/<scope>/, choosing the scope from the artifact directory name
rather than from a human's memory of which job did what.

Written because run 41163495630's artifacts do NOT mean what their names say:
its `a11-shard-dsc-*` artifacts hold a sweep of the System/DriverKit cache,
not of the main System/Library/dyld cache, because the shard job selected its
target with a glob that System/DriverKit/System/Library/dyld also matches. So
the mapping from artifact name to scope is given explicitly here, with the
reason, instead of being inferred.

    py tools/testdata/merge_cloud_shards.py --root downloaded_sweep_41163495630 \
        --map a11-shard-rootfs=rootfs-macho a11-shard-dsc=driverkit-dsc
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--map", nargs="+", required=True,
                    help="artifact-name-substring=scope-dir pairs")
    ap.add_argument("--outbase", default=os.path.join("analysis", "compat"))
    ap.add_argument("--tag-prefix", default="25G83-vma2-")
    args = ap.parse_args()

    rc = 0
    for spec in args.map:
        pat, _, scope = spec.partition("=")
        dirs = []
        for dirpath, _dn, files in os.walk(args.root):
            if "byte-coverage.json" in files and pat in dirpath.replace("\\", "/"):
                dirs.append(dirpath)
        dirs.sort()
        if not dirs:
            print(f"[!] {pat}: no shard dirs found under {args.root}")
            rc = 1
            continue
        out = os.path.join(args.outbase, scope)
        print(f"\n=== {pat} -> {out}  ({len(dirs)} shard dirs)")
        for d in dirs:
            print(f"    {d}")
        cmd = [sys.executable, os.path.join("tools", "sweep_image.py"), "merge",
               "--outdir", out, "--tag", args.tag_prefix + scope,
               "--baseline", os.path.join("analysis", "compat",
                                          "armmac-generic-v1-baseline.json"),
               "--inputs"] + dirs
        env = dict(os.environ)
        env["PYTHONPATH"] = "tools"
        p = subprocess.run(cmd, cwd=ROOT, env=env)
        if p.returncode not in (0, 1):
            rc = p.returncode
        # exit 1 from the merge means a FAILING terminal state exists in the
        # merged scope, which is a finding to report, not a tool error.
    return rc


if __name__ == "__main__":
    sys.exit(main())
