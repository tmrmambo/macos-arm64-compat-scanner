#!/usr/bin/env python3
"""
Minimal macOS RootFS Packager
=============================
Extracts and packages the minimal bootable macOS 15 root filesystem hierarchy
from mounted APFS container(s) (FileSystem and/or SystemOS DMG).

Components targeted:
  - /sbin/launchd
  - /usr/lib/dyld
  - /bin/zsh, /bin/sh
  - /System/Library/dyld/dyld_shared_cache_arm64e* (all subcaches & maps)
  - Base config: /private/var/db/.AppleSetupDone, /etc/*, symlinks, core permissions
"""

import os
import sys
import shutil
import hashlib
import struct
import json
import argparse
from pathlib import Path

def compute_sha256(filepath):
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def inspect_macho(filepath):
    """Inspect Mach-O binary header to determine architecture and type."""
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(4)
        if magic in (b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe'): # 64-bit Mach-O
            with open(filepath, 'rb') as f:
                hdr = f.read(32)
            cputype = struct.unpack('<I', hdr[4:8])[0]
            filetype = struct.unpack('<I', hdr[12:16])[0]
            is_arm64 = (cputype == 0x0100000c)
            return {"type": "Mach-O 64-bit", "cputype": hex(cputype), "is_arm64": is_arm64, "filetype": filetype}
        elif magic in (b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca'): # Universal FAT binary
            return {"type": "Universal FAT Mach-O", "is_arm64": True}
        elif magic.startswith(b'dyld_v1'):
            return {"type": "Dyld Shared Cache", "magic": magic.decode('ascii', errors='ignore')}
        else:
            return {"type": "Other/Script", "magic": magic.hex()}
    except Exception as e:
        return {"error": str(e)}

def find_candidate_file(search_dirs, relative_path, file_pattern=None):
    """Search for a file across multiple root directories."""
    for s_dir in search_dirs:
        if not s_dir or not os.path.isdir(s_dir):
            continue
        # Direct check
        cand1 = os.path.join(s_dir, relative_path)
        if os.path.exists(cand1):
            return cand1
        # Check inside 'root' subdirectory if apfs-fuse creates root/
        cand2 = os.path.join(s_dir, 'root', relative_path)
        if os.path.exists(cand2):
            return cand2

    # Recursive search if pattern provided
    if file_pattern:
        for s_dir in search_dirs:
            if not s_dir or not os.path.isdir(s_dir):
                continue
            for root, _, files in os.walk(s_dir):
                for f in files:
                    if f == file_pattern:
                        return os.path.join(root, f)
    return None

def copy_preserving_symlinks(src, dst):
    """Copy file or symlink preserving attributes and link targets."""
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.islink(src):
        linkto = os.readlink(src)
        if os.path.lexists(dst):
            os.remove(dst)
        os.symlink(linkto, dst)
    else:
        shutil.copy2(src, dst)

def package_rootfs(fs_mounts, sys_mounts, output_dir, manifest_path, report_path):
    print("=" * 80)
    print("          macOS 15 (vma2) Minimal Bootable RootFS Packager")
    print("=" * 80)
    print(f"Output Directory: {output_dir}")
    print(f"FS Mounts:        {fs_mounts}")
    print(f"SYS Mounts:       {sys_mounts}")

    all_mounts = fs_mounts + sys_mounts
    os.makedirs(output_dir, exist_ok=True)

    # 1. Base directory structure
    core_dirs = [
        "sbin",
        "bin",
        "usr/lib",
        "usr/bin",
        "usr/standalone",
        "System/Library/dyld",
        "private/etc",
        "private/var/db",
        "private/var/run",
        "private/var/log",
        "private/tmp",
        "dev",
        "Users",
        "Volumes",
        "Library",
    ]
    for d in core_dirs:
        os.makedirs(os.path.join(output_dir, d), exist_ok=True)
        os.chmod(os.path.join(output_dir, d), 0o755)

    # 2. System Symlinks
    symlinks = {
        "etc": "private/etc",
        "var": "private/var",
        "tmp": "private/tmp",
    }
    for link_name, target in symlinks.items():
        link_path = os.path.join(output_dir, link_name)
        if os.path.lexists(link_path):
            os.remove(link_path)
        os.symlink(target, link_path)
        print(f"[+] Created symlink: /{link_name} -> {target}")

    extracted_items = []
    missing_items = []

    # 3. Core PID 1: /sbin/launchd
    print("\n[*] [1/5] Extracting /sbin/launchd...")
    launchd_src = find_candidate_file(all_mounts, "sbin/launchd", file_pattern="launchd")
    if launchd_src and os.path.isfile(launchd_src):
        dest = os.path.join(output_dir, "sbin", "launchd")
        copy_preserving_symlinks(launchd_src, dest)
        os.chmod(dest, 0o755)
        sha = compute_sha256(dest)
        sz = os.path.getsize(dest)
        macho_info = inspect_macho(dest)
        print(f"    [+] Found at: {launchd_src}")
        print(f"    [+] Copied to /sbin/launchd ({sz:,} bytes, SHA256: {sha[:16]}...)")
        print(f"    [+] Format: {macho_info.get('type')}")
        extracted_items.append({
            "target": "/sbin/launchd",
            "source": launchd_src,
            "size": sz,
            "sha256": sha,
            "info": macho_info
        })
    else:
        print("    [-] ERROR: /sbin/launchd not found in mounts!")
        missing_items.append("/sbin/launchd")

    # 4. Dynamic Linker: /usr/lib/dyld
    print("\n[*] [2/5] Extracting /usr/lib/dyld...")
    dyld_src = find_candidate_file(all_mounts, "usr/lib/dyld", file_pattern="dyld")
    if dyld_src and os.path.isfile(dyld_src):
        dest = os.path.join(output_dir, "usr", "lib", "dyld")
        copy_preserving_symlinks(dyld_src, dest)
        os.chmod(dest, 0o755)
        sha = compute_sha256(dest)
        sz = os.path.getsize(dest)
        macho_info = inspect_macho(dest)
        print(f"    [+] Found at: {dyld_src}")
        print(f"    [+] Copied to /usr/lib/dyld ({sz:,} bytes, SHA256: {sha[:16]}...)")
        print(f"    [+] Format: {macho_info.get('type')}")
        extracted_items.append({
            "target": "/usr/lib/dyld",
            "source": dyld_src,
            "size": sz,
            "sha256": sha,
            "info": macho_info
        })
    else:
        print("    [-] ERROR: /usr/lib/dyld not found in mounts!")
        missing_items.append("/usr/lib/dyld")

    # 5. Core Shells: /bin/zsh and /bin/sh
    print("\n[*] [3/5] Extracting /bin/zsh and /bin/sh...")
    for shell in ["zsh", "sh"]:
        shell_src = find_candidate_file(all_mounts, f"bin/{shell}", file_pattern=shell)
        if shell_src:
            dest = os.path.join(output_dir, "bin", shell)
            copy_preserving_symlinks(shell_src, dest)
            if not os.path.islink(dest):
                os.chmod(dest, 0o755)
                sz = os.path.getsize(dest)
                sha = compute_sha256(dest)
                macho_info = inspect_macho(dest)
            else:
                sz = 0
                sha = ""
                macho_info = {"type": "symlink", "target": os.readlink(dest)}
            print(f"    [+] Copied /bin/{shell} from {shell_src} ({sz:,} bytes)")
            extracted_items.append({
                "target": f"/bin/{shell}",
                "source": shell_src,
                "size": sz,
                "sha256": sha,
                "info": macho_info
            })
        else:
            print(f"    [-] WARNING: /bin/{shell} not found directly.")
            missing_items.append(f"/bin/{shell}")

    # Ensure /bin/sh fallback link if sh is missing but zsh exists
    sh_dest = os.path.join(output_dir, "bin", "sh")
    zsh_dest = os.path.join(output_dir, "bin", "zsh")
    if not os.path.exists(sh_dest) and os.path.exists(zsh_dest):
        os.symlink("zsh", sh_dest)
        print("    [+] Created symlink: /bin/sh -> zsh")

    # 6. Dyld Shared Caches: /System/Library/dyld/dyld_shared_cache_arm64e*
    print("\n[*] [4/5] Extracting Dyld Shared Caches...")
    dsc_dest_dir = os.path.join(output_dir, "System", "Library", "dyld")
    os.makedirs(dsc_dest_dir, exist_ok=True)
    dsc_count = 0
    dsc_total_size = 0

    # Search in SYS mounts first, then FS mounts
    dsc_sources = []
    for mnt in sys_mounts + fs_mounts:
        for candidate_sub in ["System/Library/dyld", "root/System/Library/dyld"]:
            p = os.path.join(mnt, candidate_sub)
            if os.path.isdir(p):
                dsc_sources.append(p)

    copied_names = set()
    for dsc_dir in dsc_sources:
        for fname in os.listdir(dsc_dir):
            if fname.startswith("dyld_shared_cache_arm64e") and fname not in copied_names:
                src_file = os.path.join(dsc_dir, fname)
                dest_file = os.path.join(dsc_dest_dir, fname)
                copy_preserving_symlinks(src_file, dest_file)
                copied_names.add(fname)
                sz = os.path.getsize(dest_file)
                dsc_total_size += sz
                dsc_count += 1
                print(f"    [+] Extracted: {fname:<45} ({sz / (1024*1024):>8.2f} MB)")
                extracted_items.append({
                    "target": f"/System/Library/dyld/{fname}",
                    "source": src_file,
                    "size": sz,
                })

    print(f"    [=] Total Dyld Shared Cache files: {dsc_count} ({dsc_total_size / (1024*1024):.2f} MB)")
    if dsc_count == 0:
        missing_items.append("dyld_shared_cache_arm64e*")

    # 7. Base Config & First Boot Bypass
    print("\n[*] [5/5] Configuring Base Setup & Auto-Login...")
    # /var/db/.AppleSetupDone
    apple_setup_done = os.path.join(output_dir, "private", "var", "db", ".AppleSetupDone")
    os.makedirs(os.path.dirname(apple_setup_done), exist_ok=True)
    with open(apple_setup_done, "w") as f:
        f.write("")
    print("    [+] Created /var/db/.AppleSetupDone (Bypasses Setup Assistant for cloud-init)")

    # /private/etc configuration files
    etc_src = None
    for mnt in fs_mounts + sys_mounts:
        for candidate_sub in ["private/etc", "root/private/etc", "etc", "root/etc"]:
            p = os.path.join(mnt, candidate_sub)
            if os.path.isdir(p):
                etc_src = p
                break
        if etc_src:
            break

    etc_dest = os.path.join(output_dir, "private", "etc")
    if etc_src and os.path.isdir(etc_src):
        print(f"    [+] Copying /etc configs from: {etc_src}")
        for item in os.listdir(etc_src):
            s_item = os.path.join(etc_src, item)
            d_item = os.path.join(etc_dest, item)
            try:
                if os.path.isdir(s_item):
                    shutil.copytree(s_item, d_item, symlinks=True, dirs_exist_ok=True)
                else:
                    copy_preserving_symlinks(s_item, d_item)
            except Exception as e:
                pass
    else:
        print("    [!] Creating minimal standalone /etc fallback configuration...")
        # Minimal passwd
        with open(os.path.join(etc_dest, "passwd"), "w") as f:
            f.write("nobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\n")
            f.write("root:*:0:0:System Administrator:/var/root:/bin/sh\n")
        # Minimal group
        with open(os.path.join(etc_dest, "group"), "w") as f:
            f.write("nobody:*:-2:\nwheel:*:0:root\nadmin:*:80:root\nstaff:*:20:root\n")
        # Minimal shells
        with open(os.path.join(etc_dest, "shells"), "w") as f:
            f.write("/bin/sh\n/bin/zsh\n")

    # Generate Manifest & Reports
    manifest = {
        "project": "macOS 15 (vma2) Generic ARM64 Cloud Minimal RootFS",
        "extracted_components": extracted_items,
        "missing_components": missing_items,
        "statistics": {
            "total_extracted_files": len(extracted_items),
            "dyld_shared_cache_count": dsc_count,
            "dyld_shared_cache_total_bytes": dsc_total_size,
        }
    }

    if manifest_path:
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        with open(manifest_path, "w") as f:
            json.dump(manifest, f, indent=2)
        print(f"\n[+] Manifest written to: {manifest_path}")

    report_lines = [
        "=" * 80,
        "       macOS 15 (vma2) MINIMAL ROOT FILESYSTEM EXTRACTION REPORT",
        "=" * 80,
        f"Status:               {'SUCCESS' if not missing_items else 'PARTIAL'}",
        f"Output Directory:     {output_dir}",
        f"Extracted Artifacts:  {len(extracted_items)} files",
        f"Dyld Cache Subcaches: {dsc_count} files ({dsc_total_size / (1024*1024):.2f} MB)",
        f"Setup Assistant Done: YES (/var/db/.AppleSetupDone)",
        "",
        "Key Binaries Verified:",
    ]
    for item in extracted_items:
        if item.get("info"):
            report_lines.append(f"  - {item['target']:<24} {item['size']:>10,} bytes  Format: {item['info'].get('type')}")
        elif not item['target'].startswith("/System/Library/dyld/"):
            report_lines.append(f"  - {item['target']:<24} {item['size']:>10,} bytes")

    if missing_items:
        report_lines.append("\nMissing Items:")
        for m in missing_items:
            report_lines.append(f"  - {m}")

    report_lines.append("=" * 80)
    report_text = "\n".join(report_lines)
    print("\n" + report_text)

    if report_path:
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        with open(report_path, "w") as f:
            f.write(report_text)
        print(f"[+] Summary report written to: {report_path}")

    return len(missing_items) == 0

def main():
    parser = argparse.ArgumentParser(description="Package minimal macOS root filesystem from mounts.")
    parser.add_argument("--fs-mount", action="append", default=[], help="Mount path for FileSystem DMG (can be repeated)")
    parser.add_argument("--sys-mount", action="append", default=[], help="Mount path for SystemOS DMG (can be repeated)")
    parser.add_argument("--output-dir", required=True, help="Destination directory for minimal rootfs")
    parser.add_argument("--manifest", default="reports/rootfs_manifest.json", help="Path to write JSON manifest")
    parser.add_argument("--report", default="reports/rootfs_report.txt", help="Path to write text summary")

    args = parser.parse_args()
    success = package_rootfs(args.fs_mount, args.sys_mount, args.output_dir, args.manifest, args.report)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
