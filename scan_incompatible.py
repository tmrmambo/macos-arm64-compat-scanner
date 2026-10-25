#!/usr/bin/env python3
"""
High-Performance Apple Silicon AArch64 Compatibility Scanner
============================================================
Scans Mach-O binaries (including MH_FILESET kernelcaches) and Dyld Shared Caches
for instructions and system registers incompatible with standard AArch64 processors.

Features:
- O(1) Pre-filtering bitmasks (filters 99.8% of normal ARM instructions in seconds).
- Strict CPU architecture validation (skips x86_64 legacy drivers).
- Native support for Dyld Shared Caches (dyld_shared_cache_arm64e).
- Resolves cache addresses to real dylib/framework paths.
- Accurate MH_FILESET inner segment mapping.
- Memory barrier and hint instruction filtering (dsb, dmb, isb, etc.).
- ARM ARM DDI 0487 standard system register whitelist.
"""

import os
import sys
import struct
import json
import time
import array
import capstone

ARM_STANDARD_SYSREGS = {
    "midr_el1", "mpidr_el1", "revidr_el1", "id_aa64pfr0_el1", "id_aa64pfr1_el1",
    "id_aa64dfr0_el1", "id_aa64dfr1_el1", "id_aa64isar0_el1", "id_aa64isar1_el1",
    "id_aa64mmfr0_el1", "id_aa64mmfr1_el1", "id_aa64mmfr2_el1", "ctr_el0", "clidr_el1",
    "csselr_el1", "ccsidr_el1", "ccsidr2_el1", "sctlr_el1", "sctlr_el2", "sctlr_el3",
    "actlr_el1", "actlr_el2", "actlr_el3", "cpacr_el1", "cptr_el2", "cptr_el3",
    "tcr_el1", "tcr_el2", "tcr_el3", "ttbr0_el1", "ttbr1_el1", "ttbr0_el2", "ttbr0_el3",
    "mair_el1", "mair_el2", "mair_el3", "amair_el1", "amair_el2", "amair_el3",
    "vbar_el1", "vbar_el2", "vbar_el3", "contextidr_el1", "tpidr_el0", "tpidrro_el0",
    "tpidr_el1", "tpidr_el2", "tpidr_el3", "sp_el0", "sp_el1", "sp_el2", "spsel",
    "currentel", "daif", "nzcv", "fpcr", "fpsr", "elr_el1", "elr_el2", "elr_el3",
    "spsr_el1", "spsr_el2", "spsr_el3", "esr_el1", "esr_el2", "esr_el3", "far_el1",
    "far_el2", "far_el3", "par_el1", "afsr0_el1", "afsr1_el1", "cntfrq_el0", "cntvct_el0",
    "cntpct_el0", "cntkctl_el1", "cntp_tval_el0", "cntp_ctl_el0", "cntp_cval_el0",
    "cntv_tval_el0", "cntv_ctl_el0", "cntv_cval_el0", "icc_iar0_el1", "icc_iar1_el1",
    "icc_eoir0_el1", "icc_eoir1_el1", "icc_pmr_el1", "icc_bpr0_el1", "icc_bpr1_el1",
    "icc_ctlr_el1", "icc_sre_el1", "icc_sre_el2", "icc_sre_el3", "icc_dir_el1",
    "icc_rpr_el1", "icc_sgi1r_el1", "icc_asgi1r_el1", "icc_sgi0r_el1", "pmcr_el0",
    "pmcntenset_el0", "pmcntenclr_el0", "pmovsr_el0", "pmselr_el0", "pmccntr_el0",
    "pmxevtyper_el0", "pmxevcntr_el0", "pmuserenr_el0", "pmintenset_el1", "pmintenclr_el1"
}

IGNORED_MNEMONICS = {
    'dsb', 'dmb', 'isb', 'clrex', 'nop', 'yield', 'wfe', 'wfi', 'sev', 'sevl',
    'pacia', 'pacib', 'pacda', 'pacdb', 'autia', 'autib', 'autda', 'autdb',
    'paciasp', 'pacibsp', 'autiasp', 'autibsp'
}

def decode_uleb128(data, offset):
    result, shift = 0, 0
    while offset < len(data):
        byte = data[offset]; offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0: break
        shift += 7
    return result, offset

def parse_sysreg_operand(op_str):
    ops = [op.strip().lower() for op in op_str.split(',')]
    for op in ops:
        if not op.startswith('x') and not op.startswith('w') and not op.isdigit() and op not in ['xzr', 'wzr']:
            return op
    return None

def scan_macho_bytes(data, comp_name="standalone", header_off=0):
    if len(data) < header_off + 32: return []
    magic = struct.unpack('<I', data[header_off:header_off+4])[0]
    if magic != 0xfeedfacf: return []

    cputype = struct.unpack('<I', data[header_off+4:header_off+8])[0]
    if cputype != 0x0100000c: # CPU_TYPE_ARM64
        return []

    ncmds = struct.unpack('<I', data[header_off+16:header_off+20])[0]
    idx = header_off + 32

    seg0_vm = None
    fn_starts_off, fn_starts_sz = None, None
    text_exec_data = None
    text_exec_vm = None
    syms = []

    for _ in range(ncmds):
        if idx + 8 > len(data): break
        cmd, csz = struct.unpack('<II', data[idx:idx+8])
        cdata = data[idx+8:idx+csz]
        if cmd == 0x19: # LC_SEGMENT_64
            sname = cdata[:16].rstrip(b'\x00').decode('ascii', errors='ignore')
            svm, ssz, soff, sfsz = struct.unpack('<QQQQ', cdata[16:48])
            if seg0_vm is None: seg0_vm = svm
            if sname in ['__TEXT_EXEC', '__TEXT']:
                if sname == '__TEXT_EXEC' or text_exec_data is None:
                    text_exec_vm = svm
                    if soff + sfsz <= len(data):
                        text_exec_data = data[soff:soff+sfsz]
        elif cmd == 0x26: # LC_FUNCTION_STARTS
            fn_starts_off, fn_starts_sz = struct.unpack('<II', cdata[:8])
        elif cmd == 0x2: # LC_SYMTAB
            symoff, nsyms, stroff, strsz = struct.unpack('<IIII', cdata[:16])
            if stroff < len(data) and symoff < len(data):
                strtab = data[stroff:stroff+strsz]
                for s in range(min(nsyms, 30000)):
                    s_off = symoff + s*16
                    if s_off + 16 <= len(data):
                        strx, stype, ssect, sdesc, sval = struct.unpack('<IBBhQ', data[s_off:s_off+16])
                        if sval != 0:
                            syms.append((sval, strtab[strx:].split(b'\x00')[0].decode('ascii', errors='ignore')))
        idx += csz

    if not text_exec_data or text_exec_vm is None:
        return []

    syms.sort()
    def get_symbol(pc):
        cur = ('<func>', 0)
        for sval, sname in syms:
            if sval <= pc: cur = (sname, sval)
            else: break
        return f"{cur[0]}+0x{pc - cur[1]:x}"

    fn_addrs = []
    if fn_starts_off and fn_starts_sz and fn_starts_off + fn_starts_sz <= len(data):
        raw = data[fn_starts_off:fn_starts_off+fn_starts_sz]
        c_off, cur_a = 0, seg0_vm if seg0_vm else text_exec_vm
        while c_off < len(raw):
            val, c_off = decode_uleb128(raw, c_off)
            if val == 0: break
            cur_a += val
            fn_addrs.append(cur_a)

    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cs.detail = True

    issues = []
    text_end = text_exec_vm + len(text_exec_data)

    if not fn_addrs:
        fn_addrs = [text_exec_vm]

    for i in range(len(fn_addrs)):
        f_start = fn_addrs[i]
        f_end = fn_addrs[i+1] if i+1 < len(fn_addrs) else text_end
        if f_start < text_exec_vm or f_end > text_end or f_end <= f_start: continue
        
        fn_off = f_start - text_exec_vm
        fn_sz = min(f_end - f_start, 0x10000)
        fn_code = text_exec_data[fn_off:fn_off+fn_sz]

        max_target = 0
        terminated = False

        for j in range(0, len(fn_code)-4, 4):
            pc = f_start + j
            if terminated and pc > max_target:
                break

            w = struct.unpack('<I', fn_code[j:j+4])[0]

            # Fast branch CFG tracking
            op26 = w >> 26
            if op26 == 0x05: # b
                imm26 = w & 0x03ffffff
                if imm26 & 0x02000000: imm26 -= 0x04000000
                tgt = pc + (imm26 << 2)
                terminated = True
                if tgt > max_target: max_target = tgt
            elif op26 == 0x25: # bl
                imm26 = w & 0x03ffffff
                if imm26 & 0x02000000: imm26 -= 0x04000000
                tgt = pc + (imm26 << 2)
                if tgt > max_target: max_target = tgt
            elif (w >> 25) in [0x2a, 0x1a, 0x1b]: # b.cond / cbz / cbnz
                imm19 = (w >> 5) & 0x7ffff
                if imm19 & 0x40000: imm19 -= 0x80000
                tgt = pc + (imm19 << 2)
                if tgt > max_target: max_target = tgt
            elif (w & 0xffe0001f) in [0xd65f0000, 0xd69f0000]: # ret / eret
                terminated = True
            elif (w & 0xffe00000) == 0xd4200000: # brk
                terminated = True

            # Fast bitmask pre-filtering:
            is_sysreg = ((w >> 22) == 0x354)
            is_amx = ((w & 0xffe00000) == 0x00200000)

            if is_sysreg or is_amx:
                chunk = fn_code[j:j+4]
                dis = list(cs.disasm(chunk, pc))
                if dis:
                    insn = dis[0]
                    if insn.mnemonic in IGNORED_MNEMONICS:
                        continue

                    reg_name = parse_sysreg_operand(insn.op_str)
                    if not reg_name:
                        continue

                    if '_c15_' in reg_name:
                        issues.append({
                            "component": comp_name,
                            "function": get_symbol(f_start),
                            "fn_start": hex(f_start),
                            "pc": hex(pc),
                            "type": "IMP_DEF_SYSREG",
                            "detail": f"{insn.mnemonic} {insn.op_str}"
                        })
                    elif reg_name.startswith('s') and reg_name not in ARM_STANDARD_SYSREGS:
                        issues.append({
                            "component": comp_name,
                            "function": get_symbol(f_start),
                            "fn_start": hex(f_start),
                            "pc": hex(pc),
                            "type": "NON_STD_SYSREG",
                            "detail": f"{insn.mnemonic} {insn.op_str}"
                        })
                else:
                    if is_amx and (w & 0xffff) in [0x1000, 0x1020, 0x1040, 0x1060, 0x1080, 0x10a0]:
                        issues.append({
                            "component": comp_name,
                            "function": get_symbol(f_start),
                            "fn_start": hex(f_start),
                            "pc": hex(pc),
                            "type": "CUSTOM_ISA_AMX",
                            "detail": f"Apple AMX Opcode 0x{w:08x}"
                        })

    return issues

def scan_dyld_cache_file(fpath):
    print(f"[*] Parsing Dyld Shared Cache: {fpath}")
    issues = []
    try:
        with open(fpath, 'rb') as f:
            hdr = f.read(0x200)
    except Exception as e:
        print(f"    [-] Cannot read cache header: {e}")
        return []

    if len(hdr) < 0x24: return []
    magic = hdr[:16].rstrip(b'\x00')
    if not magic.startswith(b'dyld_v1'):
        return []
    if b'arm64' not in magic:
        print(f"    [-] Skipping non-arm64 cache: {magic}")
        return []

    map_off, map_cnt = struct.unpack('<II', hdr[16:24])
    try:
        with open(fpath, 'rb') as f:
            f.seek(map_off)
            map_data = f.read(map_cnt * 32)
    except Exception as e:
        print(f"    [-] Failed to read mapping table: {e}")
        return []

    images = []
    # Check for images table
    img_off, img_cnt = 0, 0
    if len(hdr) >= 0x170:
        img_off, img_cnt = struct.unpack('<II', hdr[0x168:0x170])
    if img_off == 0 and len(hdr) >= 0x20:
        img_off, img_cnt = struct.unpack('<II', hdr[0x18:0x20])

    if img_off > 0 and img_cnt > 0:
        try:
            with open(fpath, 'rb') as f:
                f.seek(img_off)
                img_data = f.read(min(img_cnt, 4000) * 32)
                for idx in range(min(img_cnt, 4000)):
                    addr, _, _, path_off, _ = struct.unpack('<QQQII', img_data[idx*32:(idx+1)*32])
                    f.seek(path_off)
                    path = f.read(256).split(b'\x00')[0].decode('ascii', errors='ignore')
                    images.append((addr, path))
            images.sort()
        except: pass

    def get_image_for_addr(va):
        if not images: return os.path.basename(fpath)
        cur = os.path.basename(fpath)
        for iaddr, ipath in images:
            if iaddr <= va: cur = ipath
            else: break
        return cur

    cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    cs.detail = True

    try:
        with open(fpath, 'rb') as f:
            for m in range(map_cnt):
                addr, sz, foff, max_prot, init_prot = struct.unpack('<QQQII', map_data[m*32:(m+1)*32])
                # Only scan executable mappings (VM_PROT_EXECUTE = 4)
                if (init_prot & 4) == 0:
                    continue

                print(f"    [+] Scanning executable mapping @ 0x{addr:x} ({sz // (1024*1024)} MB)...")
                f.seek(foff)
                CHUNK = 64 * 1024 * 1024
                scanned = 0
                while scanned < sz:
                    to_read = min(CHUNK, sz - scanned)
                    chunk = f.read(to_read)
                    if not chunk: break

                    arr = array.array('I')
                    arr.frombytes(chunk)
                    cur_va = addr + scanned

                    for idx, w in enumerate(arr):
                        is_sysreg = ((w >> 22) == 0x354)
                        is_amx = ((w & 0xffe00000) == 0x00200000)

                        if is_sysreg or is_amx:
                            pc = cur_va + idx * 4
                            raw_insn = chunk[idx*4:idx*4+4]
                            dis = list(cs.disasm(raw_insn, pc))
                            comp_name = get_image_for_addr(pc)

                            if dis:
                                insn = dis[0]
                                if insn.mnemonic in IGNORED_MNEMONICS:
                                    continue
                                reg_name = parse_sysreg_operand(insn.op_str)
                                if not reg_name: continue

                                if '_c15_' in reg_name:
                                    issues.append({
                                        "component": comp_name,
                                        "function": f"0x{pc:x}",
                                        "fn_start": hex(pc),
                                        "pc": hex(pc),
                                        "type": "IMP_DEF_SYSREG",
                                        "detail": f"{insn.mnemonic} {insn.op_str}"
                                    })
                                elif reg_name.startswith('s') and reg_name not in ARM_STANDARD_SYSREGS:
                                    issues.append({
                                        "component": comp_name,
                                        "function": f"0x{pc:x}",
                                        "fn_start": hex(pc),
                                        "pc": hex(pc),
                                        "type": "NON_STD_SYSREG",
                                        "detail": f"{insn.mnemonic} {insn.op_str}"
                                    })
                            else:
                                if is_amx and (w & 0xffff) in [0x1000, 0x1020, 0x1040, 0x1060, 0x1080, 0x10a0]:
                                    issues.append({
                                        "component": comp_name,
                                        "function": f"0x{pc:x}",
                                        "fn_start": hex(pc),
                                        "pc": hex(pc),
                                        "type": "CUSTOM_ISA_AMX",
                                        "detail": f"Apple AMX Opcode 0x{w:08x}"
                                    })

                    scanned += to_read
    except Exception as e:
        print(f"    [-] Error scanning mappings: {e}")

    return issues

def scan_path(target_path):
    all_issues = []
    if os.path.isfile(target_path):
        try:
            with open(target_path, 'rb') as f:
                hdr = f.read(16)
        except: return []

        if hdr.startswith(b'dyld_v1'):
            return scan_dyld_cache_file(target_path)

        if len(hdr) >= 8:
            magic = struct.unpack('<I', hdr[:4])[0]
            if magic == 0xfeedfacf: # MH_MAGIC_64
                cputype = struct.unpack('<I', hdr[4:8])[0]
                if cputype != 0x0100000c: # Skip x86_64 and other non-ARM64
                    return []

                with open(target_path, 'rb') as f:
                    data = f.read()

                filetype = struct.unpack('<I', data[12:16])[0]
                if filetype == 0xc: # MH_FILESET
                    ncmds = struct.unpack('<I', data[16:20])[0]
                    idx = 32
                    for _ in range(ncmds):
                        cmd, csz = struct.unpack('<II', data[idx:idx+8])
                        cdata = data[idx+8:idx+csz]
                        if cmd == 0x80000035: # LC_FILESET_ENTRY
                            vmaddr, fileoff, entry_id_off, _ = struct.unpack('<QQII', cdata[:24])
                            entry_id = cdata[entry_id_off - 8:].split(b'\x00')[0].decode('ascii', errors='ignore')
                            # Accurate fileset entry scan
                            issues = scan_macho_bytes(data, entry_id, header_off=fileoff)
                            if issues:
                                print(f"    [{entry_id}]: {len(issues)} issues")
                                all_issues.extend(issues)
                        idx += csz
                else:
                    issues = scan_macho_bytes(data, os.path.basename(target_path), header_off=0)
                    all_issues.extend(issues)
    elif os.path.isdir(target_path):
        for root, dirs, files in os.walk(target_path):
            # Prune non-binary and heavy asset directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'Resources', '_CodeSignature', 'Headers', 'Modules']]
            for file in files:
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, 'rb') as f:
                        magic = f.read(16)
                    if magic.startswith(b'\xcf\xfa\xed\xfe'):
                        cputype = struct.unpack('<I', magic[4:8])[0]
                        if cputype == 0x0100000c: # Strictly ARM64
                            print(f"[*] Scanning ARM64 Mach-O: {fpath}")
                            all_issues.extend(scan_path(fpath))
                    elif magic.startswith(b'dyld_v1') and b'arm64' in magic:
                        all_issues.extend(scan_dyld_cache_file(fpath))
                except: pass
    return all_issues

def main():
    if len(sys.argv) < 2:
        print("Usage: scan_incompatible.py <file_or_dir> [--json out.json]")
        sys.exit(1)

    target = sys.argv[1]
    json_out = sys.argv[sys.argv.index("--json") + 1] if "--json" in sys.argv else None

    t0 = time.time()
    print(f"[*] Starting high-performance scan on: {target}")
    results = scan_path(target)
    t1 = time.time()

    print("\n" + "="*80)
    print("           APPLE SILICON NON-STANDARD AARCH64 COMPATIBILITY REPORT")
    print("="*80)
    print(f"Scan completed in: {t1 - t0:.2f} seconds")
    print(f"Total incompatibilities detected: {len(results)}")

    type_counts = {}
    for r in results:
        type_counts[r['type']] = type_counts.get(r['type'], 0) + 1
    for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"  - {t:<22}: {count:>5} occurrences")

    funcs = {}
    for r in results:
        key = (r['component'], r['function'], r['fn_start'])
        funcs.setdefault(key, []).append(r)

    print(f"\nUnique functions/locations requiring LLVM IR Lifting & Stubbing: {len(funcs)}")
    print("-" * 80)
    for (comp, fn, fstart), items in sorted(funcs.items())[:30]:
        print(f"[{comp}] {fn} (Entry: {fstart}) -> {len(items)} issues")
        for it in items[:2]:
            print(f"    0x{it['pc']} [{it['type']}]: {it['detail']}")
        if len(items) > 2:
            print(f"    ... and {len(items)-2} more issues")

    if json_out:
        os.makedirs(os.path.dirname(os.path.abspath(json_out)), exist_ok=True)
        with open(json_out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Full JSON report saved to: {json_out}")

if __name__ == '__main__':
    main()
