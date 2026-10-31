#!/usr/bin/env python3
"""
sweep_image.py - whole-image ARMv8.2-A incompatibility sweep (A11)
==================================================================
Extends tools/sweep_kernelcache.py from "one MH_FILESET kernelcache" to
"every executable byte of the 25G83 vma2 image", i.e. the four containers
that kernelcache-sweep.md 10.5 / 10.6 list as NOT scanned:

    * dyld shared cache + every subcache  (30 files in cryptex-sys)
    * standalone Mach-O in the root volume (executables, dylibs, frameworks,
      bundles), most of which are FAT/universal
    * non-Mach-O files, which are the overwhelming majority of the 299,960
      root-volume files and must be *counted*, not silently skipped
    * LC_DYLD_CHAINED_FIXUPS in __DATA_CONST / __DATA (route-A risk R1)

WHY A NEW FILE AND NOT AN EDIT
------------------------------
tools/sweep_kernelcache.py and tools/armmac_baseline.py are concurrently
being edited by the register-audit workstream (A10). This module imports
both and reuses their classifier, their five-pass byte-state pipeline and
their byte-terminal-state taxonomy verbatim, so the two workstreams cannot
overwrite each other and the verdicts stay identical by construction.
Nothing here redefines a category, a severity or a terminal state.

    import sweep_kernelcache as SK      # Sweep, Segment, Entry, parse_macho
    import armmac_baseline as B         # categories + baseline tables

DYLD SHARED CACHE: STRATEGY AND ITS EFFECT ON THE COVERAGE DENOMINATOR
----------------------------------------------------------------------
Two options were available.

  (a) `ipsw dyld split` into ~3,000 standalone dylibs, then scan each.
  (b) Scan the shipped cache files in place.

This module does (b), for one reason that outranks convenience: option (a)
scans *reconstructed* Mach-O files. dyld's extractor re-synthesises segment
headers and LINKEDIT, so the bytes examined are not the bytes Apple ships.
A coverage claim measured against a rebuilt artefact cannot be stated as
coverage of the image. Option (a) also costs ~15 GB of extra disk and a
long serial extraction before the first instruction is decoded.

The task brief correctly warns that an in-place scan can double-count,
because a cache's __TEXT is shared and images can be walked more than once.
That is avoided here BY CONSTRUCTION, not by a cleanup pass:

  1. The byte universe is the MAPPING TABLE, never the image table. A cache
     file's dyld_cache_mapping_info entries are disjoint file ranges that
     tile the file; summing the executable ones gives each byte exactly one
     chance to be claimed.
  2. The image table is used ONLY for naming. Inside one executable mapping
     the sorted image addresses induce a PARTITION: image i owns
     [addr_i, addr_i+1) clipped to the mapping. Bytes before the first image
     or after the last belong to no image and are attributed to the synthetic
     component "<cache-unclaimed>" rather than folded into a neighbour.
  3. Because the per-image ranges partition the mapping, the per-image byte
     totals sum to the mapping size exactly. The merge step asserts this.
  4. Every subcache is a separate file with its own mapping table, so the
     union over files tiles the whole cache with no overlap.

Consequence for the coverage denominator, stated plainly: the denominator is
"executable mapping bytes of every arm64e cache file", NOT "sum over images
of image __TEXT size". The two differ by the stub/branch-island/padding
regions that belong to no image; under option (a) those bytes would simply
vanish from the denominator, which would inflate the percentage. Keeping
them is the stricter choice and makes the number comparable to the BootKC
figure, which is also a mapping/segment denominator.

FAT / UNIVERSAL
---------------
Root-volume binaries are mostly universal. Only CPU_TYPE_ARM64 slices are
swept. x86_64 slices are skipped EXPLICITLY: the slice count and its byte
size land in file-coverage.json under FAT_X86_SLICE_SKIPPED, so "we did not
scan Rosetta code" is a recorded number, not an omission.

NON-MACH-O
----------
Every file gets exactly one file-level terminal state, decided by magic.
"Not a Mach-O" is a terminal state with a reason (AR / ELF / PE / script /
plist / image / archive / text / empty / other-binary), never a skip.

OUTPUTS (schema-compatible with sweep_kernelcache.py so shards merge)
---------------------------------------------------------------------
    byte-coverage.json          byte terminal-state accounting
    summary.json                counts by category / component / function
    components.csv              component closure rows
    coverage-manifest.jsonl     one JSON object per finding
    findings-by-function.jsonl  per-function aggregation
    mnemonic-census.json        every decoded mnemonic + its verdict
    sysreg-census.json          every MRS/MSR encoding + its verdict
    detail-lists.json           unknown / AMX / HVC / reserved detail
  new in this module:
    file-coverage.json          FILE-level terminal-state accounting
    fixup-coverage.json         LC_DYLD_CHAINED_FIXUPS accounting
    fixup-manifest.jsonl        one JSON object per chained fixup
    shard-manifest.json         what this shard was asked to do, and did

USAGE
-----
    # discovery only: classify every file, emit the work list (cheap)
    py tools/sweep_image.py discover --target /mnt/rootfs \
        --outdir out/discover

    # one standalone Mach-O (FAT aware)
    py tools/sweep_image.py macho --target /bin/zsh --outdir out/zsh

    # a dyld shared cache: point at the MAIN cache file, subcaches are found
    py tools/sweep_image.py dsc --target .../dyld_shared_cache_arm64e \
        --outdir out/dsc --shard 0/8 --jobs 4

    # a tree of files, sharded
    py tools/sweep_image.py tree --target /mnt/rootfs --outdir out/t0 \
        --shard 0/16 --jobs 4

    # merge shard directories into one report
    py tools/sweep_image.py merge --outdir analysis/compat/full-image \
        --inputs out/t0 out/t1 out/dsc

Exit status: 0 on success, 1 if any file reached a FAILING terminal state
(UNREADABLE / PARSE_FAILED / UNKNOWN_ENCODING bytes), so CI turns red on a
coverage hole rather than on an exception.
"""

import argparse
import bisect
import collections
import csv
import hashlib
import json
import os
import stat
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep_kernelcache as SK          # noqa: E402
import armmac_baseline as B             # noqa: E402

SCHEMA = "armmac-image-sweep/1"

# ---------------------------------------------------------------------------
# Mach-O / FAT / dyld-cache constants not already in sweep_kernelcache
# ---------------------------------------------------------------------------
MH_MAGIC_64 = 0xFEEDFACF          # 64-bit, host-endian
MH_CIGAM_64 = 0xCFFAEDFE          # 64-bit, byte-swapped
MH_MAGIC_32 = 0xFEEDFACE
MH_CIGAM_32 = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE            # big-endian on disk
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_ARM = 0x0000000C
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_X86 = 0x00000007
CPU_SUBTYPE_MASK = 0x00FFFFFF
CPU_SUBTYPE_ARM64E = 2
CPU_SUBTYPE_ARM64_ALL = 0

LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_SEGMENT_64 = SK.LC_SEGMENT_64
LC_FUNCTION_STARTS = SK.LC_FUNCTION_STARTS
LC_SYMTAB = SK.LC_SYMTAB

MH_OBJECT, MH_EXECUTE, MH_FVMLIB, MH_CORE, MH_PRELOAD = 1, 2, 3, 4, 5
MH_DYLIB, MH_DYLINKER, MH_BUNDLE, MH_DSYM, MH_KEXT = 6, 7, 8, 0xA, 0xB
MH_FILESET = SK.MH_FILESET

VM_PROT_EXECUTE = SK.VM_PROT_EXECUTE

DSC_MAGIC = b"dyld_v1"
# A cache file's sidecars carry no mappings at all.
DSC_SIDECAR_SUFFIXES = (".map", ".atlas", ".symbols", ".json", ".txt")

# ---------------------------------------------------------------------------
# FILE-level terminal states. Mirrors the byte-level taxonomy in
# sweep_kernelcache.STATE_NAMES: every file ends in exactly one of these,
# and the two FAILING ones are what turns the run red.
# ---------------------------------------------------------------------------
FILE_STATES_SWEPT = (
    "MACHO_ARM64_SWEPT",
    "MACHO_ARM64E_SWEPT",
    "FAT_ARM64_SLICE_SWEPT",
    "MACHO_FILESET_SWEPT",
    "DYLD_CACHE_ARM64E_SWEPT",
)
FILE_STATES_SKIPPED_BY_RULE = (
    "FAT_X86_SLICE_SKIPPED",
    "MACHO_X86_ONLY_SKIPPED",
    "MACHO_OTHER_ARCH_SKIPPED",
    "DYLD_CACHE_NON_ARM64_SKIPPED",
)
FILE_STATES_NOTHING_TO_SWEEP = (
    "MACHO_NO_EXECUTABLE_SEGMENT",
    "DYLD_CACHE_NO_EXEC_MAPPING",
    "NOT_MACHO",
    "NOT_A_REGULAR_FILE",
    "EMPTY_FILE",
)
FILE_STATES_FAILING = ("UNREADABLE", "PARSE_FAILED")

MAGIC_TABLE = (
    (b"!<arch>\n", "AR_STATIC_ARCHIVE"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE_COFF"),
    (b"#!", "SCRIPT_SHEBANG"),
    (b"<?xml", "PLIST_OR_XML"),
    (b"bplist00", "PLIST_BINARY"),
    (b"\x89PNG", "IMAGE_PNG"),
    (b"\xff\xd8\xff", "IMAGE_JPEG"),
    (b"GIF8", "IMAGE_GIF"),
    (b"icns", "IMAGE_ICNS"),
    (b"CTSw", "ASSET_CATALOG"),
    (b"PK\x03\x04", "ARCHIVE_ZIP"),
    (b"\x1f\x8b", "ARCHIVE_GZIP"),
    (b"\xfd7zXZ", "ARCHIVE_XZ"),
    (b"BZh", "ARCHIVE_BZIP2"),
    (b"bvx", "ARCHIVE_LZFSE"),
    (b"\x28\xb5\x2f\xfd", "ARCHIVE_ZSTD"),
    (b"SQLite format 3", "DB_SQLITE"),
    (b"\x00\x01\x00\x00", "FONT_TTF"),
    (b"OTTO", "FONT_OTF"),
    (b"true", "FONT_TTF"),
    (b"wOF", "FONT_WOFF"),
    (b"\xcf\xa0\x00\x00", "CODE_DIRECTORY"),
    (b"\xfa\xde\x0c", "CODE_SIGNATURE"),
    (b"TZif", "TZDATA"),
    (b"%PDF", "PDF"),
    (b"\x42\x4f\x4d\x53", "BOM_STORE"),
    (b"\x00\x05\x16\x07", "RESOURCE_FORK"),
    (b"META-INF", "ARCHIVE_ZIP"),
    (b"strs", "LOCALIZATION_STRINGS"),
    (b"\xd0\xcf\x11\xe0", "OLE_COMPOUND"),
    (b"GPUC", "GPU_SHADER_CACHE"),
    (b"MTLB", "METAL_LIBRARY"),
    (b"AEA1", "AEA_ARCHIVE"),
    (b"\x62\x76\x78\x32", "ARCHIVE_LZFSE"),
)


def classify_non_macho(head, size):
    """head = first 64 bytes. -> short reason string for NOT_MACHO."""
    if size == 0:
        return "EMPTY"
    for pat, name in MAGIC_TABLE:
        if head.startswith(pat):
            return name
    if head.startswith(DSC_MAGIC):
        return "DYLD_CACHE_SIDECAR_OR_UNMAPPED"
    probe = head[:64]
    if probe and all(b in (9, 10, 13) or 32 <= b <= 126 for b in probe):
        return "TEXT_ASCII"
    try:
        probe.decode("utf-8")
        return "TEXT_UTF8"
    except UnicodeDecodeError:
        pass
    if probe.count(0) * 2 > len(probe):
        return "BINARY_MOSTLY_ZERO"
    return "BINARY_OTHER"


# ---------------------------------------------------------------------------
# FileWindow: lets SK.Sweep index a multi-hundred-MB cache file without
# loading it. SK.Sweep only ever does self.data[a:b], so this is sufficient
# and keeps a 4-worker pool inside the runner's memory budget.
# ---------------------------------------------------------------------------
class FileWindow:
    __slots__ = ("path", "_f", "size")

    def __init__(self, path):
        self.path = path
        self._f = open(path, "rb", buffering=0)
        self.size = os.fstat(self._f.fileno()).st_size

    def __len__(self):
        return self.size

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = 0 if key.start is None else key.start
            stop = self.size if key.stop is None else key.stop
            if start < 0 or stop < start:
                return b""
            self._f.seek(start)
            return self._f.read(stop - start)
        self._f.seek(key)
        b = self._f.read(1)
        return b[0] if b else 0

    def close(self):
        try:
            self._f.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# FAT / universal front end
# ---------------------------------------------------------------------------
class Slice:
    __slots__ = ("cputype", "cpusubtype", "offset", "size", "align")

    def __init__(self, cputype, cpusubtype, offset, size, align):
        self.cputype = cputype
        self.cpusubtype = cpusubtype
        self.offset = offset
        self.size = size
        self.align = align

    @property
    def is_arm64(self):
        return self.cputype == CPU_TYPE_ARM64

    @property
    def arch_name(self):
        if self.cputype == CPU_TYPE_ARM64:
            return "arm64e" if (self.cpusubtype & CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E else "arm64"
        if self.cputype == CPU_TYPE_X86_64:
            return "x86_64"
        if self.cputype == CPU_TYPE_X86:
            return "i386"
        if self.cputype == CPU_TYPE_ARM:
            return "arm32"
        return f"cputype_{self.cputype:#x}"


def parse_fat(head, size):
    """-> list[Slice] for a FAT header, or None if `head` is not FAT.

    FAT headers are big-endian on disk regardless of host. Both the 32-bit
    (fat_arch) and 64-bit (fat_arch_64) forms are handled; the 64-bit form
    appears for slices past 4 GiB and must not be mistaken for the 32-bit one.
    """
    if len(head) < 8:
        return None
    magic = struct.unpack(">I", head[:4])[0]
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        wide = magic == FAT_MAGIC_64
    elif magic in (FAT_CIGAM, FAT_CIGAM_64):
        # little-endian FAT does exist in the wild for some tooling output
        magic_le = struct.unpack("<I", head[:4])[0]
        wide = magic_le == FAT_MAGIC_64
    else:
        return None
    nfat = struct.unpack(">I", head[4:8])[0]
    if nfat > 64:
        raise ValueError(f"implausible FAT nfat_arch={nfat}")
    rec = 32 if wide else 20
    need = 8 + nfat * rec
    if len(head) < need:
        raise ValueError("FAT header truncated")
    out = []
    for i in range(nfat):
        o = 8 + i * rec
        if wide:
            ct, cs, off, sz, al, _r = struct.unpack(">iiQQII", head[o:o + rec])
        else:
            ct, cs, off, sz, al = struct.unpack(">iiIII", head[o:o + rec])
        ct &= 0xFFFFFFFF
        cs &= 0xFFFFFFFF
        if off + sz > size:
            raise ValueError(f"FAT slice {i} runs past EOF ({off}+{sz} > {size})")
        out.append(Slice(ct, cs, off, sz, al))
    return out


# ---------------------------------------------------------------------------
# LC_DYLD_CHAINED_FIXUPS
# ---------------------------------------------------------------------------
# Pointer formats, from dyld's mach-o/fixup-chains.h. Only the arm64-relevant
# ones are walked; anything else is counted as UNSUPPORTED with its number so
# the gap is visible instead of silent.
PTR_ARM64E = 1
PTR_64 = 2
PTR_64_OFFSET = 6
PTR_ARM64E_KERNEL = 7
PTR_64_KERNEL_CACHE = 8
PTR_ARM64E_USERLAND = 9
PTR_ARM64E_FIRMWARE = 10
PTR_ARM64E_USERLAND24 = 12
PTR_ARM64E_SHARED_CACHE = 13

PTR_FORMAT_NAMES = {
    1: "DYLD_CHAINED_PTR_ARM64E", 2: "DYLD_CHAINED_PTR_64",
    3: "DYLD_CHAINED_PTR_32", 4: "DYLD_CHAINED_PTR_32_CACHE",
    5: "DYLD_CHAINED_PTR_32_FIRMWARE", 6: "DYLD_CHAINED_PTR_64_OFFSET",
    7: "DYLD_CHAINED_PTR_ARM64E_KERNEL", 8: "DYLD_CHAINED_PTR_64_KERNEL_CACHE",
    9: "DYLD_CHAINED_PTR_ARM64E_USERLAND", 10: "DYLD_CHAINED_PTR_ARM64E_FIRMWARE",
    11: "DYLD_CHAINED_PTR_x86_64_KERNEL_CACHE",
    12: "DYLD_CHAINED_PTR_ARM64E_USERLAND24",
    13: "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE",
}
PAC_KEY_NAMES = {0: "IA", 1: "IB", 2: "DA", 3: "DB"}
# stride in bytes implied by the format's `next` field
PTR_STRIDE = {1: 8, 2: 8, 6: 8, 7: 4, 8: 4, 9: 8, 10: 4, 12: 8, 13: 8}
WALKABLE_FORMATS = set(PTR_STRIDE)


def _decode_fixup(raw, fmt):
    """-> (rec, next_delta_bytes). rec is None for an unsupported format."""
    if fmt in (PTR_64_KERNEL_CACHE, PTR_ARM64E_KERNEL, PTR_ARM64E_FIRMWARE):
        # dyld_chained_ptr_64_kernel_cache_rebase:
        #   target:30 cacheLevel:2 diversity:16 addrDiv:1 key:2 next:12 isAuth:1
        target = raw & 0x3FFFFFFF
        cache_level = (raw >> 30) & 0x3
        diversity = (raw >> 32) & 0xFFFF
        addr_div = (raw >> 48) & 0x1
        key = (raw >> 49) & 0x3
        nxt = (raw >> 51) & 0xFFF
        is_auth = (raw >> 63) & 0x1
        rec = {"kind": "rebase", "auth": bool(is_auth), "target": target,
               "cache_level": cache_level,
               "key": PAC_KEY_NAMES[key] if is_auth else None,
               "diversity": diversity if is_auth else None,
               "addr_div": bool(addr_div) if is_auth else None}
        return rec, nxt * 4
    if fmt in (PTR_ARM64E, PTR_ARM64E_USERLAND, PTR_ARM64E_USERLAND24,
               PTR_ARM64E_SHARED_CACHE):
        is_auth = (raw >> 63) & 0x1
        is_bind = (raw >> 62) & 0x1
        if fmt == PTR_ARM64E_SHARED_CACHE:
            nbits, nshift = 8, 52
        elif fmt == PTR_ARM64E:
            nbits, nshift = 11, 51
        else:
            nbits, nshift = 11, 51
        nxt = (raw >> nshift) & ((1 << nbits) - 1)
        if is_auth:
            # auth: target/ordinal:(32|24) diversity:16 addrDiv:1 key:2 next bind auth
            diversity = (raw >> 32) & 0xFFFF
            addr_div = (raw >> 48) & 0x1
            key = (raw >> 49) & 0x3
            if is_bind:
                ordw = 24 if fmt == PTR_ARM64E_USERLAND24 else 16
                rec = {"kind": "bind", "auth": True,
                       "ordinal": raw & ((1 << ordw) - 1),
                       "key": PAC_KEY_NAMES[key], "diversity": diversity,
                       "addr_div": bool(addr_div)}
            else:
                rec = {"kind": "rebase", "auth": True, "target": raw & 0xFFFFFFFF,
                       "key": PAC_KEY_NAMES[key], "diversity": diversity,
                       "addr_div": bool(addr_div)}
        else:
            if is_bind:
                ordw = 24 if fmt == PTR_ARM64E_USERLAND24 else 16
                rec = {"kind": "bind", "auth": False,
                       "ordinal": raw & ((1 << ordw) - 1),
                       "addend": (raw >> (ordw if ordw == 24 else 32)) & 0x7FFFF}
            else:
                rec = {"kind": "rebase", "auth": False,
                       "target": raw & 0x7FFFFFFFFFF,
                       "high8": (raw >> 43) & 0xFF}
        return rec, nxt * 8
    if fmt in (PTR_64, PTR_64_OFFSET):
        is_bind = (raw >> 63) & 0x1
        nxt = (raw >> 51) & 0xFFF
        if is_bind:
            rec = {"kind": "bind", "auth": False, "ordinal": raw & 0xFFFFFF,
                   "addend": (raw >> 24) & 0xFF}
        else:
            rec = {"kind": "rebase", "auth": False, "target": raw & 0xFFFFFFFFFFF,
                   "high8": (raw >> 36) & 0xFF}
        return rec, nxt * 8
    return None, 0


def parse_chained_fixups(data, header_off, segments, tag, component,
                         text_vmaddr, fn_starts, mf=None, max_lines=0):
    """Walk LC_DYLD_CHAINED_FIXUPS. -> accounting dict.

    `text_vmaddr` is the rebase base. docs/function-recompilation.md 1.2
    established for 25G83 BootKC that the correct base is the OUTER __TEXT
    vmaddr (0xfffffe0007004000), not the container load address; using it,
    all 575,856 IA targets land in __TEXT_EXEC and 98.74% hit an
    LC_FUNCTION_STARTS entry. That 98.74% is re-measured here and reported as
    `ia_target_on_function_start_pct` so the regression gate in 3.2 P1
    ("must stay >= 98%") has a producer.
    """
    ncmds = struct.unpack("<I", data[header_off + 16:header_off + 20])[0]
    cf_off = cf_size = None
    idx = header_off + 32
    for _ in range(ncmds):
        cmd, csz = struct.unpack("<II", data[idx:idx + 8])
        if csz < 8:
            break
        if cmd == LC_DYLD_CHAINED_FIXUPS:
            cf_off, cf_size = struct.unpack("<II", data[idx + 8:idx + 16])
        idx += csz
    if cf_off is None or not cf_size:
        return {"present": False, "component": component}

    blob = data[cf_off:cf_off + cf_size]
    if len(blob) < 32:
        return {"present": True, "component": component,
                "error": "LC_DYLD_CHAINED_FIXUPS payload truncated"}
    (fx_version, starts_off, imports_off, symbols_off,
     imports_count, imports_format, symbols_format) = struct.unpack("<7I", blob[:28])

    si = blob[starts_off:]
    if len(si) < 4:
        return {"present": True, "component": component,
                "error": "dyld_chained_starts_in_image truncated"}
    seg_count = struct.unpack("<I", si[:4])[0]
    seg_info_offsets = struct.unpack(f"<{seg_count}I", si[4:4 + 4 * seg_count])

    out = {
        "present": True, "component": component, "tag": tag,
        "fixups_version": fx_version, "imports_count": imports_count,
        "imports_format": imports_format, "symbols_format": symbols_format,
        "lc_file_offset": f"{cf_off:#x}", "lc_size": cf_size,
        "segment_slots": seg_count,
        "rebase_base_vmaddr": f"{text_vmaddr:#x}",
        "by_segment": [], "pointer_formats": {},
        "total": 0, "auth": 0, "non_auth": 0, "binds": 0,
        "by_auth_key": {}, "chains_crossing_page": 0,
        "unsupported_format_pages": 0, "lines_written": 0,
    }
    fs_set = set(fn_starts or ())
    ia_targets = 0
    ia_on_fn = 0
    lines = 0

    for sidx, soff in enumerate(seg_info_offsets):
        if soff == 0:
            out["by_segment"].append({"slot": sidx, "pages": 0, "fixups": 0,
                                      "note": "no fixups in this segment"})
            continue
        s = si[soff:]
        if len(s) < 22:
            out["by_segment"].append({"slot": sidx, "error": "starts_in_segment truncated"})
            continue
        (size, page_size, ptr_fmt, seg_offset, max_valid_ptr,
         page_count) = struct.unpack("<IHHQIH", s[:22])
        starts = struct.unpack(f"<{page_count}H", s[22:22 + 2 * page_count]) \
            if len(s) >= 22 + 2 * page_count else ()
        fname = PTR_FORMAT_NAMES.get(ptr_fmt, f"format_{ptr_fmt}")
        out["pointer_formats"][fname] = out["pointer_formats"].get(fname, 0) + 1
        segname = segments[sidx].name if sidx < len(segments) else f"slot{sidx}"

        if ptr_fmt not in WALKABLE_FORMATS:
            out["unsupported_format_pages"] += page_count
            out["by_segment"].append({
                "slot": sidx, "segment": segname, "pointer_format": fname,
                "pages": page_count, "fixups": 0,
                "error": f"pointer format {ptr_fmt} not walked by this module"})
            continue

        n_fix = n_auth = n_bind = 0
        pages_with = 0
        for p, start in enumerate(starts):
            if start == 0xFFFF:                 # DYLD_CHAINED_PTR_START_NONE
                continue
            pages_with += 1
            cur = seg_offset + p * page_size + start
            page_lo = seg_offset + p * page_size
            page_hi = page_lo + page_size
            guard = 0
            while True:
                guard += 1
                if guard > page_size:           # malformed chain, do not spin
                    break
                raw = struct.unpack("<Q", data[cur:cur + 8])[0]
                rec, delta = _decode_fixup(raw, ptr_fmt)
                if rec is None:
                    break
                n_fix += 1
                if rec["kind"] == "bind":
                    n_bind += 1
                if rec.get("auth"):
                    n_auth += 1
                    k = rec.get("key")
                    out["by_auth_key"][k] = out["by_auth_key"].get(k, 0) + 1
                    if k == "IA" and rec["kind"] == "rebase":
                        tgt = text_vmaddr + rec["target"]
                        ia_targets += 1
                        if tgt in fs_set:
                            ia_on_fn += 1
                if mf is not None and (max_lines == 0 or lines < max_lines):
                    row = {"image": tag, "component": component,
                           "segment": segname, "slot": sidx,
                           "pointer_format": fname,
                           "file_offset": f"{cur:#x}",
                           "raw": f"{raw:#018x}", "page": p}
                    row.update(rec)
                    if rec.get("auth") and rec["kind"] == "rebase":
                        row["resolved_va"] = f"{text_vmaddr + rec['target']:#x}"
                        row["lands_on_function_start"] = \
                            (text_vmaddr + rec["target"]) in fs_set
                    mf.write(json.dumps(row, separators=(",", ":")) + "\n")
                    lines += 1
                if delta == 0:
                    break
                nxt = cur + delta
                if nxt >= page_hi:
                    out["chains_crossing_page"] += 1
                cur = nxt
                if cur + 8 > len(data) if hasattr(data, "__len__") else False:
                    break
        out["by_segment"].append({
            "slot": sidx, "segment": segname, "pointer_format": fname,
            "page_size": page_size, "pages": page_count,
            "pages_with_fixups": pages_with, "fixups": n_fix,
            "auth": n_auth, "non_auth": n_fix - n_auth, "binds": n_bind,
            "segment_offset": f"{seg_offset:#x}",
            "max_valid_pointer": max_valid_ptr, "declared_size": size})
        out["total"] += n_fix
        out["auth"] += n_auth
        out["non_auth"] += n_fix - n_auth
        out["binds"] += n_bind

    out["ia_rebase_targets"] = ia_targets
    out["ia_targets_on_function_start"] = ia_on_fn
    out["ia_target_on_function_start_pct"] = (
        round(100.0 * ia_on_fn / ia_targets, 4) if ia_targets else None)
    # docs/function-recompilation.md 3.2 P1 regression gate
    out["p1_gate_threshold_pct"] = 98.0
    out["p1_gate_pass"] = (out["ia_target_on_function_start_pct"] is None
                           or out["ia_target_on_function_start_pct"] >= 98.0)
    out["lines_written"] = lines
    return out


# ---------------------------------------------------------------------------
# dyld shared cache
# ---------------------------------------------------------------------------
class CacheFile:
    """One dyld_v1 file: its own header and its own mapping table."""

    __slots__ = ("path", "magic", "arch", "mappings", "images",
                 "images_from_this_file", "size", "mapping_offset")

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(0x200)
            if not head.startswith(DSC_MAGIC):
                raise ValueError(f"{path}: not a dyld shared cache (magic "
                                 f"{head[:16]!r})")
            self.magic = head[:16].rstrip(b"\x00").decode("ascii", "replace")
            self.arch = self.magic.replace("dyld_v1", "").strip()
            mo, mc = struct.unpack("<II", head[0x10:0x18])
            self.mapping_offset = mo
            f.seek(mo)
            mraw = f.read(mc * 32)
            self.mappings = []
            for i in range(mc):
                addr, sz, foff, maxp, initp = struct.unpack(
                    "<QQQII", mraw[i * 32:(i + 1) * 32])
                self.mappings.append({"index": i, "address": addr, "size": sz,
                                      "file_offset": foff, "max_prot": maxp,
                                      "init_prot": initp})
            # imagesOffset moved in the modern header. dyld's own rule: the
            # new pair lives at 0x1C0/0x1C4 and is only present when the
            # header is long enough to contain it, which mappingOffset tells
            # us. scan_incompatible.py read 0x168, which is programTrieAddr
            # in this layout and yields garbage on 25G83.
            self.images = []
            self.images_from_this_file = False
            io = ic = 0
            if mo >= 0x1C8 and len(head) >= 0x1C8:
                io, ic = struct.unpack("<II", head[0x1C0:0x1C8])
            if (io == 0 or ic == 0) and len(head) >= 0x20:
                io, ic = struct.unpack("<II", head[0x18:0x20])
            if io and ic and ic < 100000:
                f.seek(io)
                iraw = f.read(ic * 32)
                for i in range(ic):
                    rec = iraw[i * 32:(i + 1) * 32]
                    if len(rec) < 32:
                        break
                    addr, _mt, _ino, poff, _pad = struct.unpack("<QQQII", rec)
                    f.seek(poff)
                    p = f.read(1024).split(b"\x00")[0].decode("utf-8", "replace")
                    if addr:
                        self.images.append((addr, p))
                self.images.sort()
                self.images_from_this_file = bool(self.images)

    @property
    def is_arm64(self):
        return "arm64" in self.arch

    @property
    def exec_mappings(self):
        return [m for m in self.mappings
                if (m["init_prot"] & VM_PROT_EXECUTE) and m["size"]]

    @property
    def exec_bytes(self):
        return sum(m["size"] for m in self.exec_mappings)


def cache_group(main_path):
    """Every file belonging to one cache: the main file plus its subcaches.

    Subcaches are siblings named <main>.NN[.kind]. Each is a real dyld_v1
    file with its OWN mapping table, which is exactly why the union of their
    executable mappings tiles the cache without overlap. Sidecars (.map,
    .atlas, .symbols) are returned separately so they get a file-level
    terminal state instead of being ignored.
    """
    main_abs = os.path.realpath(main_path)
    d = os.path.dirname(main_abs)
    base = os.path.basename(main_abs)
    members, sidecars, seen = [], [], set()
    for name in sorted(os.listdir(d)):
        if not name.startswith(base):
            continue
        p = os.path.join(d, name)
        if not os.path.isfile(p):
            continue
        key = os.path.realpath(p)
        if key in seen:
            continue
        seen.add(key)
        if name.endswith(DSC_SIDECAR_SUFFIXES):
            sidecars.append(p)
            continue
        members.append(p)
    # Compare resolved paths: `--target testsamples/dsc/x` and the
    # os.listdir() spelling are the same file, and adding both would
    # double-count that file's executable mapping bytes.
    if main_abs not in seen:
        members.insert(0, main_abs)
    return members, sidecars


class CacheSet:
    """All cache files of one group + a VA -> (file, offset) resolver.

    The resolver is what makes in-cache LC_FUNCTION_STARTS / LC_SYMTAB
    readable: in a split cache those tables live in the *.dyldlinkedit
    subcache, so an offset taken from an image header in the TEXT subcache
    has to be followed across files.
    """

    def __init__(self, main_path):
        self.members, self.sidecars = cache_group(main_path)
        self.files = []
        self.broken = []
        for p in self.members:
            try:
                self.files.append(CacheFile(p))
            except Exception as exc:
                self.broken.append((p, str(exc)))
        self.images = []
        for cf in self.files:
            if cf.images_from_this_file:
                self.images = cf.images
                break
        # flat, sorted VA ranges across every member file
        self._ranges = []
        for cf in self.files:
            for m in cf.mappings:
                if m["size"]:
                    self._ranges.append((m["address"], m["address"] + m["size"],
                                         m["file_offset"], cf.path))
        self._ranges.sort()
        self._starts = [r[0] for r in self._ranges]
        self._handles = {}
        self.image_addrs = [a for a, _ in self.images]

    def close(self):
        for h in self._handles.values():
            try:
                h.close()
            except Exception:
                pass
        self._handles.clear()

    def read_va(self, va, n):
        i = bisect.bisect_right(self._starts, va) - 1
        if i < 0:
            return b""
        lo, hi, foff, path = self._ranges[i]
        if not (lo <= va < hi):
            return b""
        n = min(n, hi - va)
        h = self._handles.get(path)
        if h is None:
            h = open(path, "rb", buffering=0)
            self._handles[path] = h
        h.seek(foff + (va - lo))
        return h.read(n)

    def image_for_va(self, va):
        i = bisect.bisect_right(self.image_addrs, va) - 1
        if i < 0:
            return None
        return self.images[i][1]


def _parse_sections(c, nsects):
    """section_64 records that follow a segment_command_64, as SK.Section.

    They are already in the load-command bytes we read for the image header,
    so this costs no extra I/O. They are the ONLY authoritative statement of
    which bytes of an executable segment are instructions: __text and
    __auth_stubs carry S_ATTR_PURE_INSTRUCTIONS, while __cstring,
    __objc_methname, __const, __unwind_info and __gcc_except_tab carry
    neither instruction attribute and are therefore data by Apple's own
    declaration, not by any heuristic of ours.
    """
    out = []
    so = 64
    for _ in range(nsects):
        raw = c[so:so + 80]
        if len(raw) < 80:
            break
        sec = SK.Section()
        sec.sectname = raw[:16].rstrip(b"\x00").decode("ascii", "replace")
        sec.segname = raw[16:32].rstrip(b"\x00").decode("ascii", "replace")
        sec.addr, sec.size, sec.offset, _align, _ro, _nr, sec.flags = \
            struct.unpack("<QQIIIII", raw[32:68])
        out.append(sec)
        so += 80
    return out


def _dsc_image_metadata(cs, img_addr):
    """Read one in-cache image's exec segments, function starts and symbols.

    Returns (exec_segs, fn_starts, syms, source). `source` records how the
    function-start roots were obtained so the component row can say so; a
    failed resolution is reported, never papered over.

    exec_segs rows are (name, vmaddr, vmsize, filesize, sections).
    """
    head = cs.read_va(img_addr, 32)
    if len(head) < 32:
        return [], [], [], "HEADER_UNREADABLE"
    magic, cputype = struct.unpack("<II", head[:8])
    if magic != MH_MAGIC_64 or cputype != CPU_TYPE_ARM64:
        return [], [], [], "NOT_ARM64_MACHO"
    ncmds, sizeofcmds = struct.unpack("<II", head[16:24])
    cmds = cs.read_va(img_addr + 32, min(sizeofcmds, 512 * 1024))
    exec_segs, fn_starts, syms = [], [], []
    fs_off = fs_sz = None
    symoff = nsyms = stroff = strsz = None
    linkedit_va = linkedit_fileoff = None
    idx = 0
    for _ in range(ncmds):
        if idx + 8 > len(cmds):
            break
        cmd, csz = struct.unpack("<II", cmds[idx:idx + 8])
        if csz < 8:
            break
        c = cmds[idx + 8:idx + csz]
        if cmd == LC_SEGMENT_64 and len(c) >= 64:
            name = c[:16].rstrip(b"\x00").decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize, maxp, initp, nsects, _fl = \
                struct.unpack("<QQQQIIII", c[16:64])
            if name == "__LINKEDIT":
                linkedit_va, linkedit_fileoff = vmaddr, fileoff
            if initp & VM_PROT_EXECUTE:
                exec_segs.append((name, vmaddr, vmsize, filesize,
                                  _parse_sections(c, nsects)))
        elif cmd == LC_FUNCTION_STARTS and len(c) >= 8:
            fs_off, fs_sz = struct.unpack("<II", c[:8])
        elif cmd == LC_SYMTAB and len(c) >= 16:
            symoff, nsyms, stroff, strsz = struct.unpack("<IIII", c[:16])
        idx += csz

    source = "NO_LC_FUNCTION_STARTS"
    if fs_off and fs_sz and linkedit_va is not None:
        # In a split cache the LINKEDIT offsets are relative to the file that
        # holds LINKEDIT, so convert offset -> VA through the image's own
        # __LINKEDIT (vmaddr, fileoff) pair and then resolve the VA across
        # subcaches.
        fs_va = linkedit_va + (fs_off - linkedit_fileoff)
        raw = cs.read_va(fs_va, min(fs_sz, 8 * 1024 * 1024))
        base = exec_segs[0][1] if exec_segs else img_addr
        cur, off, first = base, 0, True
        while off < len(raw):
            delta, off = SK.uleb128(raw, off)
            if delta == 0:
                break
            first = False
            cur += delta
            fn_starts.append(cur)
        fn_starts.sort()
        inside = 0
        for fv in fn_starts:
            for row in exec_segs:
                va, fsz = row[1], row[3]
                if va <= fv < va + fsz:
                    inside += 1
                    break
        if fn_starts and inside * 2 >= len(fn_starts):
            source = "LC_FUNCTION_STARTS"
        else:
            fn_starts = []
            source = "LC_FUNCTION_STARTS_UNRESOLVABLE"
        del first
    if symoff and nsyms and linkedit_va is not None and nsyms < 400000:
        sym_va = linkedit_va + (symoff - linkedit_fileoff)
        str_va = linkedit_va + (stroff - linkedit_fileoff)
        nraw = cs.read_va(sym_va, nsyms * 16)
        sraw = cs.read_va(str_va, min(strsz, 16 * 1024 * 1024))
        for i in range(min(nsyms, len(nraw) // 16)):
            strx, _st, _sect, _desc, sval = struct.unpack(
                "<IBBhQ", nraw[i * 16:(i + 1) * 16])
            if sval and strx < len(sraw):
                end = sraw.find(b"\x00", strx)
                nm = sraw[strx:end if end >= 0 else None].decode("ascii", "replace")
                if nm:
                    syms.append((sval, nm))
        syms.sort()
    return exec_segs, fn_starts, syms, source


def bl_target_roots(win, file_off, nbytes, base_va):
    """Positive-evidence root set when LC_FUNCTION_STARTS is unavailable.

    Every direct BL target inside the range is provably a call target, hence
    a function entry. Using these as recursive-descent roots keeps the
    reachability pass honest instead of starting from offset 0 and declaring
    most of the mapping unreachable.
    """
    import array as _array
    roots = set()
    CH = 32 * 1024 * 1024
    done = 0
    while done < nbytes:
        take = min(CH, nbytes - done)
        take -= take % 4
        if take <= 0:
            break
        buf = win[file_off + done:file_off + done + take]
        if len(buf) < 4:
            break
        words = _array.array("I")
        words.frombytes(buf[:len(buf) - len(buf) % 4])
        pc0 = base_va + done
        for i, w in enumerate(words):
            if (w >> 26) == 0x25:                        # BL
                t = pc0 + i * 4 + (SK.sx(w & 0x03FFFFFF, 26) << 2)
                if base_va <= t < base_va + nbytes:
                    roots.add(t)
        done += take
    return sorted(roots)


# ---------------------------------------------------------------------------
# shard result: everything a worker hands back, all mergeable
# ---------------------------------------------------------------------------
def _new_result():
    return {
        "schema": SCHEMA,
        "state_bytes": collections.Counter(),
        "state_bytes_by_component": collections.defaultdict(collections.Counter),
        "file_states": collections.Counter(),
        "file_state_bytes": collections.Counter(),
        "not_macho_reasons": collections.Counter(),
        "arch_slices": collections.Counter(),
        "cat_counts": collections.Counter(),
        "cat_sev_counts": collections.Counter(),
        "component_counts": collections.Counter(),
        "feature_counts": collections.Counter(),
        "baseline_verdicts": collections.Counter(),
        "baseline_verdict_by_cat": collections.Counter(),
        "mnem_census": collections.Counter(),
        "mnem_verdict": collections.Counter(),
        "sysreg_census": collections.Counter(),
        "sysreg_verdict": {},
        "extra_bytes": collections.Counter(),
        "findings_total": 0,
        "unique_functions": 0,
        "components": [],
        "fn_rows": [],
        "detail": {"unknown_encoding": [], "unclassified": [], "hvc_smc": [],
                   "apple_amx": [], "apple_reserved_space": []},
        "fixups": [],
        "files_scanned": 0,
        "failures": [],
    }


def _absorb_sweep(res, sweep, component_label=None):
    res["state_bytes"].update(sweep.state_bytes)
    for k, v in sweep.state_bytes_by_kext.items():
        res["state_bytes_by_component"][k].update(v)
    res["cat_counts"].update(sweep.cat_counts)
    res["cat_sev_counts"].update(
        {f"{c}/{s}": n for (c, s), n in sweep.cat_sev_counts.items()})
    res["component_counts"].update(sweep.kext_counts)
    res["feature_counts"].update(sweep.feature_counts)
    res["baseline_verdicts"].update(sweep.baseline_verdicts)
    res["baseline_verdict_by_cat"].update(
        {f"{c}/{v}": n for (c, v), n in sweep.baseline_verdict_by_cat.items()})
    res["mnem_census"].update(sweep.cls.mnem_census)
    res["mnem_verdict"].update(
        {f"{m}\t{v}": n for (m, v), n in sweep.cls.mnem_verdict.items()})
    res["sysreg_census"].update(
        {f"{e}\t{k}": n for (e, k), n in sweep.cls.sysreg_census.items()})
    res["sysreg_verdict"].update(sweep.cls.sysreg_verdict)
    res["extra_bytes"].update(sweep.extra_bytes)
    res["findings_total"] += sweep.findings_total
    res["components"].extend(sweep.components)
    uniq = 0
    for k, n in sweep.func_counts.items():
        sym, seg, sect = sweep.fn_meta.get(k, (None, None, None))
        if k[1] != -1:
            uniq += 1
        res["fn_rows"].append({
            "component": k[0],
            "fn_entry": f"{k[1]:#x}" if k[1] != -1 else None,
            "fn_sym": sym, "seg": seg, "sect": sect,
            "findings": n, "cats": dict(sweep.fn_agg[k]),
        })
    res["unique_functions"] += uniq
    d = res["detail"]
    for (a, b_, c, dd, w, s, r) in sweep.unknown_list[:2000]:
        d["unknown_encoding"].append({"component": a, "seg": b_, "sect": c,
                                      "va": f"{dd:#x}", "word": f"{w:#010x}",
                                      "fn_sym": s, "reachable": r})
    for (a, v, w, dis, t) in sweep.unclassified_list[:2000]:
        d["unclassified"].append({"component": a, "va": f"{v:#x}",
                                  "word": f"{w:#010x}", "disasm": dis, "detail": t})
    for (a, v, dis, t, s, r) in sweep.hvc_list[:4000]:
        d["hvc_smc"].append({"component": a, "va": f"{v:#x}", "disasm": dis,
                             "detail": t, "fn_sym": s, "reachable": r})
    for (a, v, w, t, s, r) in sweep.amx_list[:2000]:
        d["apple_amx"].append({"component": a, "va": f"{v:#x}",
                               "word": f"{w:#010x}", "detail": t,
                               "fn_sym": s, "reachable": r})
    for (a, v, w, t, s, r) in sweep.reserved_list[:2000]:
        d["apple_reserved_space"].append({"component": a, "va": f"{v:#x}",
                                          "word": f"{w:#010x}", "detail": t,
                                          "fn_sym": s, "reachable": r})
    if component_label:
        res["state_bytes_by_component"][component_label].update({})

# ---------------------------------------------------------------------------
# sweeping one standalone Mach-O (FAT aware)
# ---------------------------------------------------------------------------
def _lc_function_starts_blob(data, hoff):
    """-> (dataoff, datasize) of LC_FUNCTION_STARTS, or (None, None)."""
    ncmds = struct.unpack("<I", data[hoff + 16:hoff + 20])[0]
    idx = hoff + 32
    for _ in range(ncmds):
        cmd, csz = struct.unpack("<II", data[idx:idx + 8])
        if csz < 8:
            break
        if cmd == LC_FUNCTION_STARTS:
            return struct.unpack("<II", data[idx + 8:idx + 16])
        idx += csz
    return None, None


def _header_segment_vmaddr(e):
    """vmaddr of the segment that carries the mach_header.

    LC_FUNCTION_STARTS deltas are relative to the load address of the image,
    i.e. the vmaddr of the segment mapped at file offset 0 with content.
    sweep_kernelcache.parse_macho uses "the first LC_SEGMENT_64 it sees",
    which is right for a kernelcache fileset entry but wrong for an
    MH_EXECUTE whose first segment is __PAGEZERO (vmaddr 0, filesize 0):
    there the base must be __TEXT.vmaddr, usually 0x100000000.
    """
    for s in e.segments:
        if s.fileoff == 0 and s.filesize:
            return s.vmaddr
    for s in e.segments:
        if s.name == "__TEXT":
            return s.vmaddr
    return e.segments[0].vmaddr if e.segments else 0


def _fn_starts_quality(e):
    exec_segs = [s for s in e.segments if s.is_exec and s.filesize]
    if not e.func_starts:
        return 0, 0
    inside = 0
    for fv in e.func_starts:
        for s in exec_segs:
            if s.vmaddr <= fv < s.vmaddr + s.filesize:
                inside += 1
                break
    return inside, len(e.func_starts)


def repair_function_starts(data, hoff, e, res=None):
    """Make e.func_starts usable, and say which way it was obtained.

    Order of attempts, each one strictly better evidence than the next:
      1. as parsed (sweep_kernelcache's base)
      2. re-walked against the header-bearing segment's vmaddr
      3. direct BL targets inside the executable segments (positive evidence
         that the address is a call target, hence a function entry)
    Whichever is used is recorded, so a component row never implies it had
    LC_FUNCTION_STARTS when it did not.
    """
    inside, total = _fn_starts_quality(e)
    if total and inside * 2 >= total:
        return "LC_FUNCTION_STARTS"

    fs_off, fs_sz = _lc_function_starts_blob(data, hoff)
    if fs_off and fs_sz:
        base = _header_segment_vmaddr(e)
        raw = data[fs_off:fs_off + fs_sz]
        cur, off, out = base, 0, []
        while off < len(raw):
            delta, off = SK.uleb128(raw, off)
            if delta == 0:
                break
            cur += delta
            out.append(cur)
        out.sort()
        saved = e.func_starts
        e.func_starts = out
        e.fs_base = base
        inside, total = _fn_starts_quality(e)
        if total and inside * 2 >= total:
            if res is not None:
                res["extra_bytes"]["fn_starts_rebased_to_header_segment"] += 1
            return "LC_FUNCTION_STARTS(rebased)"
        e.func_starts = saved

    roots = set()
    for s in e.segments:
        if not (s.is_exec and s.filesize):
            continue
        import array as _a
        buf = data[s.fileoff:s.fileoff + (s.filesize // 4) * 4]
        if len(buf) < 4:
            continue
        w = _a.array("I")
        w.frombytes(buf)
        for i, word in enumerate(w):
            if (word >> 26) == 0x25:                 # BL
                t = s.vmaddr + i * 4 + (SK.sx(word & 0x03FFFFFF, 26) << 2)
                if s.vmaddr <= t < s.vmaddr + s.filesize:
                    roots.add(t)
        roots.add(s.vmaddr)
    e.func_starts = sorted(roots)
    e.fs_base = _header_segment_vmaddr(e)
    if res is not None:
        res["extra_bytes"]["fn_starts_from_bl_targets"] += 1
    return "BL_TARGET_ROOTS"


def _mk_segment(name, vmaddr, vmsize, fileoff, filesize, initprot,
                sections=None, default_code_region=False):
    s = SK.Segment()
    s.name = name
    s.vmaddr = vmaddr
    s.vmsize = vmsize
    s.fileoff = fileoff
    s.filesize = filesize
    s.maxprot = initprot
    s.initprot = initprot
    s.sections = sections or []
    s.default_code_region = default_code_region
    return s


def _clip_sections(exec_segs, lo, hi):
    """Sections of an image's executable segments, clipped to [lo, hi).

    [lo, hi) is this image's slice of the cache's executable mapping, which is
    the byte universe (sweep_image's module docstring). Clipping rather than
    extending keeps the denominator exactly where it was: a section is only
    allowed to label bytes the mapping partition already handed to this image.
    """
    out = []
    for row in exec_segs:
        for sec in row[4] if len(row) > 4 else []:
            if sec.size == 0:
                continue
            a = max(sec.addr, lo)
            b = min(sec.addr + sec.size, hi)
            if b <= a:
                continue
            c = SK.Section()
            c.sectname = sec.sectname
            c.segname = sec.segname
            c.addr = a
            c.size = b - a
            c.offset = sec.offset + (a - sec.addr)
            c.flags = sec.flags
            out.append(c)
    return out


def sweep_macho_file(path, outdir, res, cfg, rel=None, want_fixups=True):
    """One file on disk. Assigns a FILE-level terminal state in every branch."""
    rel = rel or path
    try:
        st = os.lstat(path)
    except OSError as exc:
        res["file_states"]["UNREADABLE"] += 1
        res["failures"].append({"path": rel, "state": "UNREADABLE", "error": str(exc)})
        return
    if not stat.S_ISREG(st.st_mode):
        res["file_states"]["NOT_A_REGULAR_FILE"] += 1
        return
    size = st.st_size
    if size == 0:
        res["file_states"]["EMPTY_FILE"] += 1
        return
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as exc:
        res["file_states"]["UNREADABLE"] += 1
        res["file_state_bytes"]["UNREADABLE"] += size
        res["failures"].append({"path": rel, "state": "UNREADABLE", "error": str(exc)})
        return

    # ---- dyld shared cache reached through a tree walk -------------------
    if head.startswith(DSC_MAGIC):
        res["file_states"]["DYLD_CACHE_SEEN_IN_TREE"] += 1
        res["file_state_bytes"]["DYLD_CACHE_SEEN_IN_TREE"] += size
        return

    # ---- FAT -------------------------------------------------------------
    slices = None
    try:
        slices = parse_fat(head, size)
    except ValueError as exc:
        res["file_states"]["PARSE_FAILED"] += 1
        res["file_state_bytes"]["PARSE_FAILED"] += size
        res["failures"].append({"path": rel, "state": "PARSE_FAILED",
                                "error": f"FAT: {exc}"})
        return

    targets = []          # (header_off, arch_name, slice_bytes)
    if slices is not None:
        for sl in slices:
            res["arch_slices"][sl.arch_name] += 1
            if sl.is_arm64:
                targets.append((sl.offset, sl.arch_name, sl.size))
            else:
                # explicit, counted, byte-accurate: never a silent ignore
                res["file_states"]["FAT_X86_SLICE_SKIPPED"] += 1
                res["file_state_bytes"]["FAT_X86_SLICE_SKIPPED"] += sl.size
        if not targets:
            res["file_states"]["MACHO_X86_ONLY_SKIPPED"] += 1
            return
    else:
        magic = struct.unpack("<I", head[:4])[0] if len(head) >= 4 else 0
        if magic == MH_MAGIC_64:
            cputype = struct.unpack("<I", head[4:8])[0]
            if cputype == CPU_TYPE_ARM64:
                sub = struct.unpack("<I", head[8:12])[0] & CPU_SUBTYPE_MASK
                arch = "arm64e" if sub == CPU_SUBTYPE_ARM64E else "arm64"
                res["arch_slices"][arch] += 1
                targets.append((0, arch, size))
            elif cputype == CPU_TYPE_X86_64:
                res["arch_slices"]["x86_64"] += 1
                res["file_states"]["MACHO_X86_ONLY_SKIPPED"] += 1
                res["file_state_bytes"]["MACHO_X86_ONLY_SKIPPED"] += size
                return
            else:
                res["arch_slices"][f"cputype_{cputype:#x}"] += 1
                res["file_states"]["MACHO_OTHER_ARCH_SKIPPED"] += 1
                return
        elif magic in (MH_MAGIC_32, MH_CIGAM_32, MH_CIGAM_64):
            res["file_states"]["MACHO_OTHER_ARCH_SKIPPED"] += 1
            return
        else:
            reason = classify_non_macho(head, size)
            res["file_states"]["NOT_MACHO"] += 1
            res["file_state_bytes"]["NOT_MACHO"] += size
            res["not_macho_reasons"][reason] += 1
            return

    # ---- parse + sweep each arm64 slice ---------------------------------
    with open(path, "rb") as f:
        whole = f.read()

    for (slice_off, arch, slice_bytes) in targets:
        # CRITICAL: inside a FAT container every load-command file offset
        # (LC_SEGMENT_64.fileoff, LC_SYMTAB.symoff, LC_FUNCTION_STARTS.dataoff)
        # is relative to the SLICE, not to the file. Handing the whole file to
        # parse_macho with header_off=slice_off makes every one of those
        # offsets point into the neighbouring slice, which silently sweeps the
        # wrong bytes and manufactures SVE/MTE findings out of x86 code. So a
        # slice is handed over as its own buffer with header_off = 0.
        data = (whole if slice_off == 0 and slices is None
                else whole[slice_off:slice_off + slice_bytes])
        hoff = 0
        try:
            filetype = struct.unpack("<I", data[hoff + 12:hoff + 16])[0]
            if filetype == MH_FILESET:
                ncmds = struct.unpack("<I", data[hoff + 16:hoff + 20])[0]
                entries = []
                idx = hoff + 32
                for _ in range(ncmds):
                    cmd, csz = struct.unpack("<II", data[idx:idx + 8])
                    if csz < 8:
                        break
                    c = data[idx + 8:idx + csz]
                    if cmd == SK.LC_FILESET_ENTRY:
                        vmaddr, fileoff, eoff, _r = struct.unpack("<QQII", c[:24])
                        eid = c[eoff - 8:].split(b"\x00")[0].decode("ascii", "replace")
                        entries.append((eid, vmaddr, fileoff))
                    idx += csz
                parsed = [SK.parse_macho(data, fo, f"{rel}!{eid}")
                          for eid, _v, fo in entries]
                label = "MACHO_FILESET_SWEPT"
            else:
                parsed = [SK.parse_macho(data, hoff, rel)]
                label = ("MACHO_ARM64E_SWEPT" if arch == "arm64e"
                         else "MACHO_ARM64_SWEPT")
                if slices is not None:
                    label = "FAT_ARM64_SLICE_SWEPT"
        except Exception as exc:
            res["file_states"]["PARSE_FAILED"] += 1
            res["file_state_bytes"]["PARSE_FAILED"] += slice_bytes
            res["failures"].append({"path": rel, "state": "PARSE_FAILED",
                                    "error": f"{type(exc).__name__}: {exc}"})
            continue

        has_exec = any(s.is_exec and s.filesize for e in parsed for s in e.segments)
        if not has_exec:
            res["file_states"]["MACHO_NO_EXECUTABLE_SEGMENT"] += 1
            continue

        fs_sources = set()
        for e in parsed:
            fs_sources.add(repair_function_starts(data, e.fileoff, e, res))

        sweep = SK.Sweep(data, rel, outdir, write_manifest=False)
        try:
            sweep.run(filetype, [], parsed)
        except SystemExit as exc:
            res["file_states"]["PARSE_FAILED"] += 1
            res["failures"].append({"path": rel, "state": "PARSE_FAILED",
                                    "error": f"sweep refused: {exc}"})
            continue
        finally:
            if sweep.mf:
                sweep.mf.close()
        src = ",".join(sorted(fs_sources)) or "LC_FUNCTION_STARTS"
        for c in sweep.components:
            c["fn_starts_source"] = src
            c["arch"] = arch
        _absorb_sweep(res, sweep)
        res["file_states"][label] += 1
        res["file_state_bytes"][label] += slice_bytes
        res["files_scanned"] += 1
        res["extra_bytes"][f"fn_root_source:{src}"] += 1

        if want_fixups:
            outer_text = None
            for e in parsed:
                for s in e.segments:
                    if s.name == "__TEXT":
                        outer_text = s.vmaddr
                        break
                if outer_text is not None:
                    break
            if outer_text is None and parsed and parsed[0].segments:
                outer_text = parsed[0].segments[0].vmaddr
            all_fs = sorted(set(fv for e in parsed for fv in e.func_starts))
            try:
                fx = parse_chained_fixups(
                    data, hoff, parsed[0].segments if parsed else [], rel, rel,
                    outer_text or 0, all_fs,
                    mf=cfg.get("_fixup_mf"), max_lines=cfg.get("max_fixup_lines", 0))
                if fx.get("present"):
                    res["fixups"].append(fx)
            except Exception as exc:
                res["failures"].append({"path": rel, "state": "FIXUP_PARSE_FAILED",
                                        "error": f"{type(exc).__name__}: {exc}"})


# ---------------------------------------------------------------------------
# sweeping one dyld shared cache executable mapping
# ---------------------------------------------------------------------------
def assert_mappings_disjoint(cs):
    """The whole no-double-counting claim rests on this. Prove it, per run.

    Every mapping of every member file is turned into a VA interval; if any
    two overlap, the byte universe is not a partition and no coverage figure
    from this run may be believed. Measured on 25G83 arm64e: 14 files, 34
    mappings, zero overlaps, exactly abutting (e.g. .01 map0 ends at
    0x1e6138000 and .02 map0 begins at 0x1e6138000).
    """
    iv = []
    for cf in cs.files:
        for m in cf.mappings:
            if m["size"]:
                iv.append((m["address"], m["address"] + m["size"],
                           os.path.basename(cf.path), m["index"]))
    iv.sort()
    overlaps = []
    for a, b in zip(iv, iv[1:]):
        if b[0] < a[1]:
            overlaps.append({"a": f"{a[2]}:map{a[3]}", "b": f"{b[2]}:map{b[3]}",
                             "a_range": [f"{a[0]:#x}", f"{a[1]:#x}"],
                             "b_range": [f"{b[0]:#x}", f"{b[1]:#x}"]})
    return {"mappings": len(iv), "overlaps": overlaps,
            "disjoint": not overlaps,
            "exec_mapping_bytes": sum(cf.exec_bytes for cf in cs.files
                                      if cf.is_arm64),
            "total_mapping_bytes": sum(b - a for a, b, _f, _i in iv)}


def sweep_dsc_task(cs, cache_path, mapping_index, img_lo, img_hi, outdir,
                   res, cfg):
    """Sweep images [img_lo, img_hi) of one executable mapping.

    The mapping is the byte universe; the image table only names the pieces.
    Per-image ranges are a partition of [lo, hi), so byte totals add up to
    the mapping size exactly.
    """
    cf = next((c for c in cs.files if c.path == cache_path), None)
    if cf is None:
        res["failures"].append({"path": cache_path, "state": "PARSE_FAILED",
                                "error": "cache file not in group"})
        return
    m = next((x for x in cf.exec_mappings if x["index"] == mapping_index), None)
    if m is None:
        res["failures"].append({"path": cache_path, "state": "PARSE_FAILED",
                                "error": f"no exec mapping {mapping_index}"})
        return

    lo, hi = m["address"], m["address"] + m["size"]
    foff = m["file_offset"]
    win = FileWindow(cache_path)
    try:
        # the image addresses that fall inside this mapping, in order
        inside = [a for a, _p in cs.images if lo <= a < hi]
        bounds = []
        if img_lo == 0 and (not inside or inside[0] > lo):
            # bytes before the first image belong to no image at all
            bounds.append(("<cache-unclaimed>", lo, inside[0] if inside else hi))
        sel = inside[img_lo:img_hi]
        for k, a in enumerate(sel):
            gi = img_lo + k
            nxt = inside[gi + 1] if gi + 1 < len(inside) else hi
            bounds.append((cs.image_for_va(a) or f"<image@{a:#x}>", a, nxt))

        base_name = os.path.basename(cache_path)
        cap = cfg.get("max_bytes") or 0
        for (label, a, b) in bounds:
            nbytes = b - a
            if nbytes <= 0:
                continue
            # Clamp to what the file actually holds. This matters twice: it
            # lets a truncated local sample be swept honestly, and in the
            # cloud it turns "short or corrupt cache file" into a counted
            # number instead of a short read that silently drops bytes.
            start_off = foff + (a - lo)
            avail = max(0, win.size - start_off)
            if cap:
                avail = min(avail, cap)
            if avail < nbytes:
                res["extra_bytes"]["dsc_input_bytes_not_present_in_file"] += \
                    nbytes - avail
                nbytes = avail
            if nbytes < 4:
                res["extra_bytes"]["dsc_ranges_skipped_no_bytes"] += 1
                continue
            comp = f"{base_name}:{label}"
            exec_segs, fn_starts, syms, src = ([], [], [], "UNCLAIMED_RANGE")
            if label != "<cache-unclaimed>":
                exec_segs, fn_starts, syms, src = _dsc_image_metadata(cs, a)
            if not fn_starts:
                fn_starts = bl_target_roots(win, foff + (a - lo), nbytes, a)
                src = (src + "+BL_TARGET_ROOTS") if src else "BL_TARGET_ROOTS"
                if a not in fn_starts:
                    fn_starts = sorted(set(fn_starts) | {a})

            e = SK.Entry()
            e.entry_id = comp
            e.vmaddr = a
            e.fileoff = foff + (a - lo)
            e.fs_base = a
            e.func_starts = fn_starts
            e.syms = [s for s in syms if a <= s[0] < b]
            e.sym_addrs = [s[0] for s in e.syms]
            # Attach the image's OWN section headers, clipped to this range.
            # Without them sweep_segment takes the "segment without section
            # headers" branch and linearly decodes an image's __cstring,
            # __objc_methname, __const, __unwind_info and __gcc_except_tab as
            # if they were instructions - which is where the userland DSC
            # scope's upper-bound-only category counts came from (a single
            # mnemonic, fnmls, decoded 4,935,874 times out of constant data).
            # This is not a new criterion: it is the same S_ATTR_*_INSTRUCTIONS
            # test sweep_segment already applies to the BootKC, which is why
            # that scope reaches 99.9996% while this one sat at 98.75%.
            secs = (_clip_sections(exec_segs, a, a + nbytes)
                    if cfg.get("dsc_sections", True) else [])
            e.segments = [_mk_segment(f"__TEXT(map{mapping_index})",
                                      a, nbytes, foff + (a - lo), nbytes,
                                      m["init_prot"], sections=secs,
                                      default_code_region=True)]
            if secs:
                res["extra_bytes"]["dsc_images_with_section_headers"] += 1
            elif label != "<cache-unclaimed>":
                res["extra_bytes"]["dsc_images_without_section_headers"] += 1

            sweep = SK.Sweep(win, base_name, outdir, write_manifest=False)
            try:
                sweep.run(0, [], [e])
            except SystemExit as exc:
                res["failures"].append({"path": comp, "state": "PARSE_FAILED",
                                        "error": f"sweep refused: {exc}"})
                continue
            finally:
                if sweep.mf:
                    sweep.mf.close()
            for c in sweep.components:
                c["fn_starts_source"] = src
                c["cache_file"] = base_name
                c["mapping_index"] = mapping_index
            _absorb_sweep(res, sweep)
            res["extra_bytes"][f"dsc_fn_root_source:{src}"] += 1
    finally:
        win.close()


# ---------------------------------------------------------------------------
# discovery: classify every file in a tree, emit the work list
# ---------------------------------------------------------------------------
PRUNE_DIR_NAMES = set()      # nothing pruned: pruning is how coverage is lost


def discover_tree(root, out_jsonl, limit=0):
    """One line per filesystem entry, with a provisional terminal state.

    Deliberately prunes nothing. scan_incompatible.py pruned Resources /
    Headers / Modules, which is exactly the kind of silent narrowing the
    coverage identity forbids.
    """
    counts = collections.Counter()
    bytes_by = collections.Counter()
    n = 0
    with open(out_jsonl, "w", encoding="utf-8", newline="\n") as f:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            counts["DIR"] += len(dirnames)
            for name in sorted(filenames):
                p = os.path.join(dirpath, name)
                rel = os.path.relpath(p, root).replace("\\", "/")
                try:
                    st = os.lstat(p)
                except OSError as exc:
                    counts["UNREADABLE"] += 1
                    f.write(json.dumps({"rel": rel, "state": "UNREADABLE",
                                        "error": str(exc)},
                                       separators=(",", ":")) + "\n")
                    continue
                if stat.S_ISLNK(st.st_mode):
                    counts["SYMLINK"] += 1
                    f.write(json.dumps({"rel": rel, "state": "SYMLINK"},
                                       separators=(",", ":")) + "\n")
                    continue
                if not stat.S_ISREG(st.st_mode):
                    counts["NOT_A_REGULAR_FILE"] += 1
                    f.write(json.dumps({"rel": rel, "state": "NOT_A_REGULAR_FILE"},
                                       separators=(",", ":")) + "\n")
                    continue
                size = st.st_size
                kind, arch = _sniff(p, size)
                counts[kind] += 1
                bytes_by[kind] += size
                rec = {"rel": rel, "size": size, "state": kind}
                if arch:
                    rec["arch"] = arch
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
                n += 1
                if limit and n >= limit:
                    return counts, bytes_by
    return counts, bytes_by


def _sniff(path, size):
    """Cheap magic sniff -> (provisional_state, arch_list_or_None)."""
    if size == 0:
        return "EMPTY_FILE", None
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return "UNREADABLE", None
    if head.startswith(DSC_MAGIC):
        return "DYLD_CACHE", head[:16].rstrip(b"\x00").decode("ascii", "replace")
    try:
        sl = parse_fat(head, size)
    except ValueError:
        return "PARSE_FAILED", None
    if sl is not None:
        archs = [s.arch_name for s in sl]
        return ("TODO_MACHO_FAT" if any(s.is_arm64 for s in sl)
                else "MACHO_X86_ONLY_SKIPPED"), archs
    if len(head) >= 8:
        magic = struct.unpack("<I", head[:4])[0]
        if magic == MH_MAGIC_64:
            cputype = struct.unpack("<I", head[4:8])[0]
            if cputype == CPU_TYPE_ARM64:
                sub = struct.unpack("<I", head[8:12])[0] & CPU_SUBTYPE_MASK
                return "TODO_MACHO_ARM64", ["arm64e" if sub == CPU_SUBTYPE_ARM64E
                                            else "arm64"]
            if cputype == CPU_TYPE_X86_64:
                return "MACHO_X86_ONLY_SKIPPED", ["x86_64"]
            return "MACHO_OTHER_ARCH_SKIPPED", [f"cputype_{cputype:#x}"]
        if magic in (MH_MAGIC_32, MH_CIGAM_32, MH_CIGAM_64):
            return "MACHO_OTHER_ARCH_SKIPPED", None
    return "NOT_MACHO", [classify_non_macho(head, size)]


# ---------------------------------------------------------------------------
# multiprocessing workers
# ---------------------------------------------------------------------------
def _worker_init(baseline_path):
    SK.BASELINE = SK.Baseline(baseline_path)


def _worker_files(payload):
    """payload = (root, [rel...], outdir, cfg). Returns a picklable result."""
    root, rels, outdir, cfg = payload
    if not getattr(SK.BASELINE, "loaded", False):
        SK.BASELINE = SK.Baseline(cfg.get("baseline"))
    res = _new_result()
    for rel in rels:
        sweep_macho_file(os.path.join(root, rel), outdir, res, cfg, rel=rel,
                         want_fixups=cfg.get("fixups", True))
    return _pack(res)


def _worker_dsc(payload):
    main_path, cache_path, mi, lo, hi, outdir, cfg = payload
    if not getattr(SK.BASELINE, "loaded", False):
        SK.BASELINE = SK.Baseline(cfg.get("baseline"))
    res = _new_result()
    cs = CacheSet(main_path)
    try:
        sweep_dsc_task(cs, cache_path, mi, lo, hi, outdir, res, cfg)
    finally:
        cs.close()
    return _pack(res)


def _pack(res):
    out = {}
    for k, v in res.items():
        if isinstance(v, collections.Counter):
            out[k] = dict(v)
        elif isinstance(v, collections.defaultdict):
            out[k] = {kk: dict(vv) for kk, vv in v.items()}
        else:
            out[k] = v
    return out


def _unpack_into(res, packed):
    for k, v in packed.items():
        if k not in res:
            res[k] = v
            continue
        cur = res[k]
        if isinstance(cur, collections.Counter):
            cur.update(v)
        elif isinstance(cur, collections.defaultdict):
            for kk, vv in v.items():
                cur[kk].update(vv)
        elif isinstance(cur, list):
            cur.extend(v)
        elif isinstance(cur, dict):
            cur.update(v)
        elif isinstance(cur, int):
            res[k] = cur + v
        elif isinstance(cur, str):
            pass
        else:
            res[k] = v


def _merge_detail(dst, src):
    for k, v in (src or {}).items():
        dst.setdefault(k, [])
        room = 4000 - len(dst[k])
        if room > 0:
            dst[k].extend(v[:room])


def _combine(res, packed):
    detail = packed.pop("detail", None)
    _unpack_into(res, packed)
    if detail:
        _merge_detail(res["detail"], detail)


# ---------------------------------------------------------------------------
# writers (schema-compatible with sweep_kernelcache.py)
# ---------------------------------------------------------------------------
STRONG = ["CODE_BASELINE", "CODE_SUPRA_BASELINE", "DATA_NONCODE_SECTION",
          "DATA_LITERAL_POOL", "DATA_REFERENCED_BLOB", "DATA_INLINE_STRING",
          "DATA_SEGMENT_GAP", "DATA_PADDING_ZERO", "DATA_OR_TRAP_UDF",
          "DATA_UNALIGNED_TAIL"]
WEAK = ["DATA_UNREACHABLE_UNDECODABLE", "DATA_INTERSTITIAL_NONZERO"]
FAILING = ["UNKNOWN_ENCODING", "UNSET"]


def write_outputs(res, outdir, tag, meta):
    os.makedirs(outdir, exist_ok=True)
    sb = collections.Counter(res["state_bytes"])
    total = sum(sb.values())
    failing = sum(v for k, v in sb.items() if k in FAILING)
    weak = sum(v for k, v in sb.items() if k in WEAK)
    cov = {
        "schema": SCHEMA, "image": tag,
        "total_executable_bytes_accounted": total,
        "states": dict(sorted(sb.items(), key=lambda kv: -kv[1])),
        "evidence_classes": {"strong_positive": STRONG,
                             "weak_negative_only": WEAK, "failing": FAILING},
        "bytes_with_failing_state": failing,
        "bytes_with_weak_evidence": weak,
        "bytes_with_strong_terminal_state": total - failing - weak,
        "strong_coverage_pct": round(100.0 * (total - failing - weak) / total, 6)
        if total else 0.0,
        "gate1_pass": failing == 0,
        "extra_byte_notes": dict(res["extra_bytes"]),
        "by_component": {k: dict(v) for k, v
                         in sorted(res["state_bytes_by_component"].items())},
    }
    cov.update(meta)
    _dump(os.path.join(outdir, "byte-coverage.json"), cov)

    fs = collections.Counter(res["file_states"])
    files_total = sum(fs.values())
    f_fail = sum(v for k, v in fs.items() if k in FILE_STATES_FAILING)
    fcov = {
        "schema": SCHEMA, "image": tag,
        "files_with_terminal_state": files_total,
        "file_states": dict(sorted(fs.items(), key=lambda kv: -kv[1])),
        "file_state_bytes": dict(sorted(collections.Counter(
            res["file_state_bytes"]).items(), key=lambda kv: -kv[1])),
        "state_classes": {
            "swept": list(FILE_STATES_SWEPT),
            "skipped_by_rule": list(FILE_STATES_SKIPPED_BY_RULE),
            "nothing_to_sweep": list(FILE_STATES_NOTHING_TO_SWEEP),
            "failing": list(FILE_STATES_FAILING),
        },
        "files_with_failing_state": f_fail,
        "file_gate_pass": f_fail == 0,
        "not_macho_reasons": dict(sorted(collections.Counter(
            res["not_macho_reasons"]).items(), key=lambda kv: -kv[1])),
        "arch_slices_seen": dict(sorted(collections.Counter(
            res["arch_slices"]).items(), key=lambda kv: -kv[1])),
        "failures": res["failures"][:2000],
        "failures_total": len(res["failures"]),
    }
    fcov.update(meta)
    _dump(os.path.join(outdir, "file-coverage.json"), fcov)

    summary = {
        "schema": SCHEMA, "image": tag,
        "findings_total": res["findings_total"],
        "by_category": dict(collections.Counter(res["cat_counts"]).most_common()),
        "by_baseline_verdict": dict(collections.Counter(
            res["baseline_verdicts"]).most_common()),
        "by_category_baseline_verdict": dict(collections.Counter(
            res["baseline_verdict_by_cat"]).most_common()),
        "by_category_severity": dict(collections.Counter(
            res["cat_sev_counts"]).most_common()),
        "by_feature": dict(collections.Counter(res["feature_counts"]).most_common()),
        "by_component": dict(collections.Counter(
            res["component_counts"]).most_common(5000)),
        "components_with_findings": len(res["component_counts"]),
        "unique_functions_with_findings": res["unique_functions"],
        "files_scanned": res["files_scanned"],
        "unknown_encoding_count": res["cat_counts"].get(B.CAT_UNKNOWN_ENCODING, 0),
        "unclassified_mnemonic_count": res["cat_counts"].get(
            B.CAT_UNCLASSIFIED_MNEMONIC, 0),
        "unclassified_sysreg_count": res["cat_counts"].get(
            B.CAT_UNCLASSIFIED_SYSREG, 0),
        "top_functions": sorted(res["fn_rows"], key=lambda r: -r["findings"])[:120],
    }
    summary.update(meta)
    _dump(os.path.join(outdir, "summary.json"), summary)

    per_mnem = collections.defaultdict(dict)
    for key, n in res["mnem_verdict"].items():
        m, _, v = key.partition("\t")
        per_mnem[m][v] = per_mnem[m].get(v, 0) + n
    _dump(os.path.join(outdir, "mnemonic-census.json"), {
        "count": len(res["mnem_census"]),
        "mnemonics": [{"mnemonic": m, "n": n,
                       "verdicts": per_mnem.get(m, {"BASELINE": 0})}
                      for m, n in collections.Counter(
                          res["mnem_census"]).most_common()]})

    sysregs = []
    for key, n in collections.Counter(res["sysreg_census"]).most_common():
        enc, _, nm = key.partition("\t")
        sysregs.append({"encoding": enc, "name": nm, "n": n,
                        "verdict": res["sysreg_verdict"].get(nm, "BASELINE")})
    _dump(os.path.join(outdir, "sysreg-census.json"),
          {"count": len(sysregs), "sysregs": sysregs})

    _dump(os.path.join(outdir, "detail-lists.json"), res["detail"])

    fx = res["fixups"]
    agg = {
        "schema": SCHEMA, "image": tag,
        "images_with_chained_fixups": len(fx),
        "fixups_total": sum(x.get("total", 0) for x in fx),
        "auth_total": sum(x.get("auth", 0) for x in fx),
        "non_auth_total": sum(x.get("non_auth", 0) for x in fx),
        "binds_total": sum(x.get("binds", 0) for x in fx),
        "chains_crossing_page": sum(x.get("chains_crossing_page", 0) for x in fx),
        "unsupported_format_pages": sum(x.get("unsupported_format_pages", 0)
                                        for x in fx),
        "by_auth_key": dict(sum((collections.Counter(x.get("by_auth_key") or {})
                                 for x in fx), collections.Counter())),
        "by_pointer_format": dict(sum((collections.Counter(
            x.get("pointer_formats") or {}) for x in fx), collections.Counter())),
        "p1_gate_failures": [x["component"] for x in fx
                             if x.get("p1_gate_pass") is False],
        "per_image": fx[:4000],
    }
    agg.update(meta)
    _dump(os.path.join(outdir, "fixup-coverage.json"), agg)

    with open(os.path.join(outdir, "components.csv"), "w", encoding="utf-8",
              newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["component", "segment", "vmaddr", "fileoff", "filesize",
                     "vmsize", "initprot", "words", "reachable_words",
                     "fn_starts_in_seg", "fn_starts_source", "cache_file",
                     "mapping_index", "states"])
        for c in res["components"]:
            wr.writerow([c.get("kext"), c.get("seg"), c.get("vmaddr"),
                         c.get("fileoff"), c.get("filesize"), c.get("vmsize"),
                         c.get("initprot"), c.get("words"),
                         c.get("reachable_words"), c.get("fn_starts_in_seg"),
                         c.get("fn_starts_source", "LC_FUNCTION_STARTS"),
                         c.get("cache_file", ""), c.get("mapping_index", ""),
                         ";".join(f"{k}={v}" for k, v
                                  in sorted((c.get("states") or {}).items()))])

    with open(os.path.join(outdir, "findings-by-function.jsonl"), "w",
              encoding="utf-8", newline="\n") as f:
        for row in sorted(res["fn_rows"], key=lambda r: -r["findings"]):
            f.write(json.dumps(row, separators=(",", ":")) + "\n")

    return cov, fcov


def _dump(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, default=str)


# ---------------------------------------------------------------------------
# merge
# ---------------------------------------------------------------------------
def do_merge(inputs, outdir, tag):
    res = _new_result()
    shards = []
    for d in inputs:
        bc = os.path.join(d, "byte-coverage.json")
        if not os.path.exists(bc):
            print(f"[!] {d}: no byte-coverage.json, skipping", file=sys.stderr)
            continue
        cov = json.load(open(bc, encoding="utf-8"))
        res["state_bytes"].update(cov.get("states", {}))
        res["extra_bytes"].update(cov.get("extra_byte_notes", {}))
        for k, v in (cov.get("by_component") or {}).items():
            res["state_bytes_by_component"][k].update(v)
        fp = os.path.join(d, "file-coverage.json")
        if os.path.exists(fp):
            fc = json.load(open(fp, encoding="utf-8"))
            res["file_states"].update(fc.get("file_states", {}))
            res["file_state_bytes"].update(fc.get("file_state_bytes", {}))
            res["not_macho_reasons"].update(fc.get("not_macho_reasons", {}))
            res["arch_slices"].update(fc.get("arch_slices_seen", {}))
            res["failures"].extend(fc.get("failures", []))
        sp = os.path.join(d, "summary.json")
        if os.path.exists(sp):
            s = json.load(open(sp, encoding="utf-8"))
            res["findings_total"] += s.get("findings_total", 0)
            res["cat_counts"].update(s.get("by_category", {}))
            res["baseline_verdicts"].update(s.get("by_baseline_verdict", {}))
            res["baseline_verdict_by_cat"].update(
                s.get("by_category_baseline_verdict", {}))
            res["cat_sev_counts"].update(s.get("by_category_severity", {}))
            res["feature_counts"].update(s.get("by_feature", {}))
            res["component_counts"].update(s.get("by_component", {}))
            res["unique_functions"] += s.get("unique_functions_with_findings", 0)
            res["files_scanned"] += s.get("files_scanned", 0)
            res["fn_rows"].extend(s.get("top_functions", []))
        mp = os.path.join(d, "mnemonic-census.json")
        if os.path.exists(mp):
            mc = json.load(open(mp, encoding="utf-8"))
            for row in mc.get("mnemonics", []):
                res["mnem_census"][row["mnemonic"]] += row.get("n", 0)
                for v, n in (row.get("verdicts") or {}).items():
                    res["mnem_verdict"][f"{row['mnemonic']}\t{v}"] += n
        rp = os.path.join(d, "sysreg-census.json")
        if os.path.exists(rp):
            rc = json.load(open(rp, encoding="utf-8"))
            for row in rc.get("sysregs", []):
                res["sysreg_census"][f"{row['encoding']}\t{row['name']}"] += \
                    row.get("n", 0)
                res["sysreg_verdict"].setdefault(row["name"], row.get("verdict"))
        dp = os.path.join(d, "detail-lists.json")
        if os.path.exists(dp):
            _merge_detail(res["detail"], json.load(open(dp, encoding="utf-8")))
        xp = os.path.join(d, "fixup-coverage.json")
        if os.path.exists(xp):
            res["fixups"].extend(json.load(open(xp, encoding="utf-8"))
                                 .get("per_image", []))
        cpath = os.path.join(d, "components.csv")
        if os.path.exists(cpath):
            with open(cpath, encoding="utf-8", newline="") as f:
                for row in csv.DictReader(f):
                    res["components"].append({
                        "kext": row.get("component"), "seg": row.get("segment"),
                        "vmaddr": row.get("vmaddr"), "fileoff": row.get("fileoff"),
                        "filesize": row.get("filesize"), "vmsize": row.get("vmsize"),
                        "initprot": row.get("initprot"), "words": row.get("words"),
                        "reachable_words": row.get("reachable_words"),
                        "fn_starts_in_seg": row.get("fn_starts_in_seg"),
                        "fn_starts_source": row.get("fn_starts_source"),
                        "cache_file": row.get("cache_file"),
                        "mapping_index": row.get("mapping_index"),
                        "states": dict(
                            (kv.split("=", 1)[0], int(kv.split("=", 1)[1]))
                            for kv in (row.get("states") or "").split(";") if "=" in kv),
                    })
        shards.append({"dir": d,
                       "bytes": cov.get("total_executable_bytes_accounted", 0),
                       "shard": cov.get("shard"), "target": cov.get("target")})

    meta = {"merged_from": shards, "shards": len(shards),
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    cov, fcov = write_outputs(res, outdir, tag, meta)
    print(f"[+] merged {len(shards)} shard(s) -> {outdir}")
    print(f"    executable bytes : {cov['total_executable_bytes_accounted']}")
    print(f"    strong coverage  : {cov['strong_coverage_pct']}%  "
          f"(gate1_pass={cov['gate1_pass']})")
    print(f"    findings         : {res['findings_total']}")
    print(f"    files            : {fcov['files_with_terminal_state']} with a "
          f"terminal state, {fcov['files_with_failing_state']} failing")
    return cov, fcov


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _parse_shard(spec):
    if not spec:
        return 0, 1
    i, _, n = spec.partition("/")
    i, n = int(i), int(n or 1)
    if not (0 <= i < n):
        raise SystemExit(f"FATAL: bad --shard {spec!r}")
    return i, n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("discover", "macho", "dsc", "tree", "merge"))
    ap.add_argument("--target", default=None)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--inputs", nargs="*", default=[])
    ap.add_argument("--tag", default=None)
    ap.add_argument("--shard", default=None, help="I/N, 0-based")
    ap.add_argument("--jobs", type=int, default=0, help="0 = os.cpu_count()")
    ap.add_argument("--worklist", default=None,
                    help="discover JSONL to shard over (tree mode)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--max-bytes", type=int, default=0,
                    help="stop a dsc/macho sweep after N bytes (local smoke test)")
    ap.add_argument("--task-bytes", type=int, default=24 * 1024 * 1024,
                    help="dsc mode: target bytes per parallel task")
    ap.add_argument("--no-fixups", action="store_true")
    ap.add_argument("--no-dsc-sections", action="store_true",
                    help="dsc mode: do NOT read the per-image section headers. "
                         "Reproduces the pre-2026-10-31 behaviour, in which an "
                         "image's whole slice of an executable mapping was "
                         "treated as an instruction region and its __cstring / "
                         "__objc_methname / __const / __unwind_info were "
                         "linearly decoded as code. Kept only so the before/"
                         "after of that change can be re-derived on demand.")
    ap.add_argument("--max-fixup-lines", type=int, default=200000)
    ap.add_argument("--baseline", default=os.path.join(
        "analysis", "compat", "armmac-generic-v1-baseline.json"))
    args = ap.parse_args(argv)

    os.makedirs(args.outdir, exist_ok=True)
    si, sn = _parse_shard(args.shard)
    jobs = args.jobs or (os.cpu_count() or 1)
    tag = args.tag or (os.path.basename(args.target.rstrip("/\\"))
                       if args.target else args.mode)

    if args.mode == "merge":
        cov, fcov = do_merge(args.inputs, args.outdir, tag)
        return 0 if (cov["gate1_pass"] and fcov["file_gate_pass"]) else 1

    SK.BASELINE = SK.Baseline(args.baseline)
    print(f"[*] baseline: "
          f"{SK.BASELINE.meta if SK.BASELINE.loaded else 'NOT LOADED (table fallback)'}")

    if not args.target:
        raise SystemExit("FATAL: --target is required for this mode")

    t0 = time.time()
    cfg = {"baseline": args.baseline, "fixups": not args.no_fixups,
           "max_fixup_lines": args.max_fixup_lines,
           "max_bytes": args.max_bytes,
           "dsc_sections": not args.no_dsc_sections}
    res = _new_result()
    meta = {"target": args.target, "mode": args.mode,
            "shard": f"{si}/{sn}", "jobs": jobs,
            "dsc_section_evidence": not args.no_dsc_sections,
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    # ---------------- discover ------------------------------------------
    if args.mode == "discover":
        wl = os.path.join(args.outdir, "worklist.jsonl")
        counts, bytes_by = discover_tree(args.target, wl, limit=args.limit)
        # Also emit a tar -T member list, so the caller can carve just the
        # Mach-O out of a 21 GB tree without re-implementing the selection.
        members = os.path.join(args.outdir, "macho-members.txt")
        n_sel = 0
        with open(wl, encoding="utf-8") as f, \
                open(members, "w", encoding="utf-8", newline="\n") as o:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if str(r.get("state", "")).startswith("TODO_MACHO"):
                    o.write("./" + r["rel"] + "\n")
                    n_sel += 1
        doc = {"schema": SCHEMA, "root": args.target, "worklist": wl,
               "macho_members_file": members,
               "provisional_states": dict(counts.most_common()),
               "provisional_state_bytes": dict(bytes_by.most_common()),
               "todo_macho": counts.get("TODO_MACHO_ARM64", 0)
               + counts.get("TODO_MACHO_FAT", 0),
               "macho_members_written": n_sel,
               "generated": meta["generated"]}
        _dump(os.path.join(args.outdir, "discovery.json"), doc)
        print(json.dumps(doc["provisional_states"], indent=1))
        print(f"[+] worklist: {wl}  ({doc['todo_macho']} Mach-O to sweep, "
              f"{n_sel} member lines, {time.time()-t0:.1f}s)")
        return 0

    fixup_path = os.path.join(args.outdir, "fixup-manifest.jsonl")
    fmf = open(fixup_path, "w", encoding="utf-8", newline="\n")
    cfg["_fixup_mf"] = fmf
    try:
        # ---------------- single Mach-O --------------------------------
        if args.mode == "macho":
            sweep_macho_file(args.target, args.outdir, res, cfg,
                             rel=os.path.basename(args.target),
                             want_fixups=not args.no_fixups)

        # ---------------- dyld shared cache ----------------------------
        elif args.mode == "dsc":
            cs = CacheSet(args.target)
            print(f"[*] cache group: {len(cs.files)} mapped file(s), "
                  f"{len(cs.sidecars)} sidecar(s), {len(cs.images)} images")
            disj = assert_mappings_disjoint(cs)
            meta["mapping_partition_proof"] = disj
            _dump(os.path.join(args.outdir, "dsc-mapping-proof.json"), disj)
            print(f"[*] mapping partition: {disj['mappings']} mappings, "
                  f"disjoint={disj['disjoint']}, "
                  f"exec bytes={disj['exec_mapping_bytes']}")
            if not disj["disjoint"]:
                print("::error title=Cache mappings overlap::the byte universe "
                      "is not a partition; coverage from this run is void")
                res["failures"].append({"path": args.target,
                                        "state": "PARSE_FAILED",
                                        "error": "overlapping cache mappings"})
                res["file_states"]["PARSE_FAILED"] += 1
            for p, err in cs.broken:
                res["file_states"]["PARSE_FAILED"] += 1
                res["failures"].append({"path": p, "state": "PARSE_FAILED",
                                        "error": err})
            for p in cs.sidecars:
                res["file_states"]["NOT_MACHO"] += 1
                res["not_macho_reasons"]["DYLD_CACHE_SIDECAR"] += 1
                res["file_state_bytes"]["NOT_MACHO"] += os.path.getsize(p)
            tasks = []
            for cf in cs.files:
                if not cf.is_arm64:
                    res["file_states"]["DYLD_CACHE_NON_ARM64_SKIPPED"] += 1
                    res["file_state_bytes"]["DYLD_CACHE_NON_ARM64_SKIPPED"] += cf.size
                    continue
                em = cf.exec_mappings
                if not em:
                    res["file_states"]["DYLD_CACHE_NO_EXEC_MAPPING"] += 1
                    continue
                res["file_states"]["DYLD_CACHE_ARM64E_SWEPT"] += 1
                res["file_state_bytes"]["DYLD_CACHE_ARM64E_SWEPT"] += cf.exec_bytes
                for m in em:
                    # Chunk by BYTES, not by image count. Image sizes in the
                    # cache span four orders of magnitude (libswiftCore vs a
                    # 16 KiB shim), so an equal-image-count split leaves one
                    # worker holding most of the mapping. Measured on the
                    # 25G83 arm64e sample, count-based chunking put 113k of
                    # 180k findings into the last two tasks.
                    lo, hi = m["address"], m["address"] + m["size"]
                    inside = [a for a, _ in cs.images if lo <= a < hi]
                    n = len(inside)
                    if n == 0:
                        tasks.append((cf.path, m["index"], 0, 0, m["size"]))
                        continue
                    target = max(1, int(args.task_bytes))
                    start = 0
                    acc = 0
                    for k in range(n):
                        end_va = inside[k + 1] if k + 1 < n else hi
                        acc += end_va - inside[k]
                        if acc >= target or k == n - 1:
                            tasks.append((cf.path, m["index"], start, k + 1, acc))
                            start = k + 1
                            acc = 0
            tasks.sort(key=lambda t: -t[4])          # biggest first
            tasks = [t[:4] for i, t in enumerate(tasks) if i % sn == si]
            print(f"[*] shard {si}/{sn}: {len(tasks)} task(s) on {jobs} process(es)")
            meta["dsc_tasks"] = len(tasks)
            meta["dsc_exec_bytes_in_group"] = sum(
                cf.exec_bytes for cf in cs.files if cf.is_arm64)
            if jobs > 1 and len(tasks) > 1:
                import multiprocessing as mp
                payloads = [(args.target, cp, mi, lo, hi, args.outdir,
                             {k: v for k, v in cfg.items() if k != "_fixup_mf"})
                            for (cp, mi, lo, hi) in tasks]
                with mp.Pool(jobs, initializer=_worker_init,
                             initargs=(args.baseline,)) as pool:
                    for k, packed in enumerate(
                            pool.imap_unordered(_worker_dsc, payloads, 1), 1):
                        _combine(res, packed)
                        if k % 8 == 0 or k == len(payloads):
                            print(f"    {k}/{len(payloads)} tasks, "
                                  f"{res['findings_total']} findings "
                                  f"({time.time()-t0:.0f}s)", flush=True)
            else:
                for (cp, mi, lo, hi) in tasks:
                    sweep_dsc_task(cs, cp, mi, lo, hi, args.outdir, res, cfg)
            cs.close()

        # ---------------- tree of files --------------------------------
        elif args.mode == "tree":
            rels = []
            if args.worklist:
                with open(args.worklist, encoding="utf-8") as f:
                    for line in f:
                        try:
                            r = json.loads(line)
                        except ValueError:
                            continue
                        if str(r.get("state", "")).startswith("TODO_MACHO"):
                            rels.append(r["rel"])
            else:
                wl = os.path.join(args.outdir, "worklist.jsonl")
                counts, _b = discover_tree(args.target, wl, limit=args.limit)
                # Every shard walks the WHOLE corpus to build the same work
                # list, so only one of them may contribute the file-level
                # states that come from the walk rather than from the sweep.
                # Letting all N contribute multiplied `DIR` by the shard
                # count in the merged file census (129,684 reported for a
                # corpus with 10,807 directories, over 12 shards). The
                # per-file swept states are unaffected either way, because a
                # file belongs to exactly one shard.
                if si == 0:
                    res["file_states"].update(
                        {k: v for k, v in counts.items()
                         if not str(k).startswith("TODO_MACHO")})
                else:
                    res["extra_bytes"]["walk_states_suppressed_non_zero_shard"] += 1
                with open(wl, encoding="utf-8") as f:
                    for line in f:
                        r = json.loads(line)
                        if str(r.get("state", "")).startswith("TODO_MACHO"):
                            rels.append(r["rel"])
            rels.sort()
            mine = [r for i, r in enumerate(rels) if i % sn == si]
            if args.limit:
                mine = mine[:args.limit]
            print(f"[*] shard {si}/{sn}: {len(mine)}/{len(rels)} Mach-O files "
                  f"on {jobs} process(es)")
            meta["tree_macho_total"] = len(rels)
            meta["tree_macho_in_shard"] = len(mine)
            if jobs > 1 and len(mine) > 8:
                import multiprocessing as mp
                batch = max(1, len(mine) // (jobs * 8))
                payloads = [(args.target, mine[i:i + batch], args.outdir,
                             {k: v for k, v in cfg.items() if k != "_fixup_mf"})
                            for i in range(0, len(mine), batch)]
                with mp.Pool(jobs, initializer=_worker_init,
                             initargs=(args.baseline,)) as pool:
                    for k, packed in enumerate(
                            pool.imap_unordered(_worker_files, payloads, 1), 1):
                        _combine(res, packed)
                        if k % 16 == 0 or k == len(payloads):
                            print(f"    {k}/{len(payloads)} batches, "
                                  f"{res['files_scanned']} files, "
                                  f"{res['findings_total']} findings "
                                  f"({time.time()-t0:.0f}s)", flush=True)
            else:
                for rel in mine:
                    sweep_macho_file(os.path.join(args.target, rel), args.outdir,
                                     res, cfg, rel=rel,
                                     want_fixups=not args.no_fixups)
    finally:
        fmf.close()

    meta["scan_seconds"] = round(time.time() - t0, 1)
    cov, fcov = write_outputs(res, args.outdir, tag, meta)
    _dump(os.path.join(args.outdir, "shard-manifest.json"), meta)

    total = cov["total_executable_bytes_accounted"]
    print("\n" + "=" * 74)
    print(f"image sweep: {tag}  shard {si}/{sn}")
    print("=" * 74)
    print(f"executable bytes accounted : {total}")
    for k, v in sorted(cov["states"].items(), key=lambda kv: -kv[1]):
        print(f"   {k:<32} {v:>13}  {100.0*v/total if total else 0:6.3f}%")
    print(f"strong terminal state      : {cov['strong_coverage_pct']}%  "
          f"(gate1_pass={cov['gate1_pass']})")
    print(f"findings total             : {res['findings_total']}")
    for c, n in collections.Counter(res["cat_counts"]).most_common():
        print(f"   {c:<30} {n:>9}")
    print("\nfile terminal states:")
    for k, v in sorted(fcov["file_states"].items(), key=lambda kv: -kv[1]):
        print(f"   {k:<34} {v:>9}")
    if fcov["not_macho_reasons"]:
        print("not-Mach-O reasons (top 12):")
        for k, v in list(fcov["not_macho_reasons"].items())[:12]:
            print(f"   {k:<34} {v:>9}")
    fx = json.load(open(os.path.join(args.outdir, "fixup-coverage.json"),
                        encoding="utf-8"))
    if fx["fixups_total"]:
        print(f"\nchained fixups             : {fx['fixups_total']} "
              f"({fx['auth_total']} auth / {fx['non_auth_total']} non-auth), "
              f"keys {fx['by_auth_key']}")
        for x in fx["per_image"][:3]:
            if x.get("ia_target_on_function_start_pct") is not None:
                print(f"   {x['component']}: IA targets on "
                      f"LC_FUNCTION_STARTS = "
                      f"{x['ia_target_on_function_start_pct']}%  "
                      f"(P1 gate {'PASS' if x['p1_gate_pass'] else 'FAIL'})")
    print(f"\n[+] outputs in {args.outdir} ({meta['scan_seconds']}s)")

    return 0 if (cov["gate1_pass"] and fcov["file_gate_pass"]) else 1


if __name__ == "__main__":
    sys.exit(main())
