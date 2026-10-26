# macOS AArch64 Cloud Compatibility Scanner & Rewriting Pipeline

Automated analysis pipeline and scanner designed to identify, catalog, and evaluate **Apple-proprietary ARM assembly opcodes and Implementation-Defined (IMP-DEF) system registers** across macOS kernel (`vma2`) and userland components.

The ultimate objective of this project is to prepare macOS system images for porting to **standard, generic AArch64 cloud hypervisors (e.g., KVM on AWS Graviton, Ampere Altra, Alibaba Yitian)** without relying on Apple hardware virtualization or host-side kernel modifications.

---

## 🎯 Target Architecture & Porting Strategy

Instead of manual, brittle byte patching, this project supports an **LLVM IR Lifting & Function Stubbing** architecture:
1. **Accurate Identification**: Locate every function containing instructions incompatible with generic ARM64.
2. **LLVM IR Lifting**: Lift only the offending functions into LLVM IR (using binary translation lifters such as McSema, Revng, or custom LLVM MC lifters).
3. **Instruction Translation & Lowering**:
   - **AMX Coprocessor Opcodes**: Recompile matrix kernels to standard ARM NEON / SVE vector operations, or NOP thread-switching routines.
   - **SPRR / GXF Registers**: Lower to standard POSIX `mprotect` or standard ARMv8.9 Permission Indirection Extension (PIE) logic.
   - **Apple PMU / Timebase**: Lower to standard ARM Generic Counter (`CNTVCT_EL0`) and PMUv3 registers.
4. **Binary Relocation & Stubbing**: Compile the lifted functions into a new Mach-O/ELF segment and place a clean `b <new_function>` stub at the original function entry point.

---

## 🔍 Incompatibility Categorization

| Category | Hardware Signature / Bitmask | Impact on Generic Cloud AArch64 |
| :--- | :--- | :--- |
| **Apple IMP-DEF Registers** | `MRS`/`MSR` with `CRn == 15`<br>(e.g. `s3_6_c15_c1_x` SPRR, `s3_4_c15_...` PMU) | Triggers **Undefined Instruction Trap** (`ESR_ELx.EC == 0x18`) on standard CPUs. |
| **Apple AMX Coprocessor** | `0x00200000` - `0x0027FFFF`<br>(`amxset`, `amxclr`, `ldx`, `ldy`, `fma32`, etc.) | Triggers **`SIGILL` / Illegal Instruction Exception** on generic cores. |
| **Apple GXF Sub-EL Isolation** | Custom system space jumps (`gcall`, `gret`) | Hardware isolation trap. |
| **Architecture Feature Gaps** | ARMv8.3 PAC (`pacia`, `autia`, `pacga`), ARMv8.5 BTI | Functions as NOP on ARMv8.0/8.2, but breaks if the ABI enforces strict key verification. |

---

## ⚙️ Industrial-Grade Scanner Features

Unlike naive 4-byte raw binary scans that suffer from false positives due to **Data-in-Code (Literal Pools, jump tables, embedded panic strings)**:
- **`LC_FUNCTION_STARTS` Aware**: Follows Apple's ULEB128 function entry stream to disassemble valid functions.
- **Control-Flow Graph (CFG) Tracking**: Disassembles basic blocks and truncates at unconditional terminators (`ret`, `eret`, `b`, `brk`) when no forward branch targets exist, completely eliminating constant-string false positives.
- **ARM ARM DDI 0487 Whitelist**: System registers are verified against the authoritative standard ARM specification.

---

## 🚀 Running on GitHub Actions (Cloud Runner)

This repository includes a turnkey GitHub Actions workflow (`.github/workflows/scan.yml`) that overcomes local platform constraints (such as Windows lacking `apfs-fuse`):
- **Remote Extraction via HTTP Range**: Downloads *only* the target 5.8GB DMG / 30MB kernelcache from Apple's CDN without pulling the entire 20GB IPSW.
- **Automated AEA Decryption**: Interacts with Apple's WKMS server to fetch archive decryption keys and decrypts AEA1 images in pure Go.
- **Native APFS Mounting**: Mounts the decrypted APFS volume with `apfs-fuse` and transparently handles Apple's `decmpfs` compression.
- **Automated Report Generation**: Generates Markdown and JSON reports uploaded directly as workflow artifacts.

### Triggering via GitHub CLI (`gh`)

```bash
# Run compatibility scanner
gh workflow run scan.yml -f scan_target=both

# Run minimal rootfs & boot disk cloud packager
gh workflow run package_minimal_rootfs.yml -f build_disk_image=true
```

---

## 📦 Cloud RootFS & Boot Disk Packaging Pipeline

The workflow `.github/workflows/package_minimal_rootfs.yml` automates the extraction and packaging of the minimal macOS 15 root filesystem directly on GitHub Actions runners, offloading heavy APFS mounting and disk I/O:
1. **Remote Range Fetching & WKMS Decryption**: Fetches `FileSystem` (Base OS) and `SystemOS` (Cryptex) DMGs directly from Apple CDN and decrypts with `ipsw fw aea`.
2. **APFS Container Mounting**: Dual mounts both containers with `apfs-fuse`.
3. **Minimal Bootable RootFS Extraction**:
   - `/sbin/launchd` (PID 1)
   - `/usr/lib/dyld` (Dynamic linker)
   - `/bin/zsh`, `/bin/sh`
   - `/System/Library/dyld/dyld_shared_cache_arm64e*` (All shared cache subcaches)
   - Base configs: `/private/var/db/.AppleSetupDone`, `/private/etc/*`, standard symlinks.
4. **Multi-Format Packaging**:
   - `minimal_rootfs.tar.zst`: Compressed root filesystem archive.
   - `macos_minimal_disk.qcow2`: GPT partitioned disk (ESP FAT32 + Apple APFS Container) ready for QEMU / KVM VirtIO-Block.
   - `macos_minimal_disk.raw.zst`: Compressed raw GPT disk image.
   - `kernelcache.vma2.dec` & `DeviceTree.vma2macosap.im4p`: ESP boot assets.

```bash
gh workflow run scan.yml -f ipsw_url="<APPLE_IPSW_URL>" -f scan_target="both"
```

Or trigger manually via the **Actions** tab in the GitHub web interface.

---

## 💻 Local CLI Usage

```bash
python3 scan_incompatible.py <path_to_binary_or_directory> [--json report.json]
```

### Example Output:
```text
================================================================================
           APPLE SILICON NON-STANDARD AARCH64 COMPATIBILITY REPORT
================================================================================
Total incompatibilities detected: 210
  - CUSTOM_ISA_AMX        :   160 occurrences
  - IMP_DEF_SYSREG        :    50 occurrences

Unique functions requiring LLVM IR Lifting & Stubbing: 17
--------------------------------------------------------------------------------
[com.apple.kernel] _Switch_context+0x584 (Entry: 0xfffffe0009c1cbe4) -> 80 issues
    0xfffffe0009c1cc00 [CUSTOM_ISA_AMX]: Apple AMX Opcode 0x00201040 (Action: Lift to IR & NEON)
[com.apple.kernel] _invalidate_icache64+0x2b24 (Entry: 0xfffffe0009c14218) -> 2 issues
    0xfffffe0009c1428c [IMP_DEF_SYSREG]: msr s3_6_c15_c8_3, x0 (Action: Stub/NOP)
```

---

## 📄 License
MIT License.
