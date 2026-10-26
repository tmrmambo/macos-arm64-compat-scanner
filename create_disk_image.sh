#!/usr/bin/env bash
# ==============================================================================
# Standard Generic ARM64 Disk Image Builder for macOS 15 (vma2)
# ==============================================================================
# Generates a UEFI-bootable GPT partitioned raw disk image + QCOW2 image:
#   - Partition 1: EFI System Partition (ESP, 256 MiB FAT32)
#   - Partition 2: Apple APFS Container (Raw APFS Container Superblock NXSB)
# ==============================================================================

set -euo pipefail

APFS_DMG="${1:-}"
ESP_DIR="${2:-}"
OUTPUT_RAW="${3:-/tmp/work/artifacts/macos_minimal_disk.raw}"
OUTPUT_QCOW2="${4:-/tmp/work/artifacts/macos_minimal_disk.qcow2}"

if [ -z "$APFS_DMG" ] || [ ! -f "$APFS_DMG" ]; then
  echo "[-] ERROR: APFS DMG source file not specified or not found: '$APFS_DMG'"
  exit 1
fi

echo "================================================================================"
echo "          macOS 15 (vma2) GPT Boot Disk Image Generator"
echo "================================================================================"
echo "APFS Source:        $APFS_DMG"
echo "ESP Boot Assets:    $ESP_DIR"
echo "Output RAW Disk:    $OUTPUT_RAW"
echo "Output QCOW2 Disk:  $OUTPUT_QCOW2"

mkdir -p "$(dirname "$OUTPUT_RAW")"
mkdir -p "$(dirname "$OUTPUT_QCOW2")"

# 1. Calculate partition boundaries (512-byte sectors)
DMG_BYTES=$(stat -c%s "$APFS_DMG")
DMG_SECTORS=$(( (DMG_BYTES + 511) / 512 ))

# 256 MiB ESP = 268,435,456 bytes = 524,288 sectors
ESP_SECTORS=524288
ESP_START=2048
ESP_END=$(( ESP_START + ESP_SECTORS - 1 )) # 526335

APFS_START=$(( ESP_END + 1 )) # 526336
APFS_END=$(( APFS_START + DMG_SECTORS - 1 ))

# Total sectors: end of APFS partition + 2048 sectors for secondary GPT header/table
TOTAL_SECTORS=$(( APFS_END + 2048 ))
TOTAL_BYTES=$(( TOTAL_SECTORS * 512 ))

echo "[*] Disk Geometry Calculation:"
echo "    Sector size:           512 bytes"
echo "    Total Sectors:         $TOTAL_SECTORS ($(( TOTAL_BYTES / 1024 / 1024 )) MiB)"
echo "    Partition 1 (ESP):     Sectors $ESP_START - $ESP_END ($(( ESP_SECTORS * 512 / 1024 / 1024 )) MiB, Type: ef00)"
echo "    Partition 2 (APFS):    Sectors $APFS_START - $APFS_END ($(( DMG_SECTORS * 512 / 1024 / 1024 )) MiB, Type: APFS)"

# 2. Build ESP FAT32 partition filesystem using mtools (No root / no loop mount required)
echo ""
echo "[*] [1/5] Formatting EFI System Partition (FAT32)..."
ESP_IMG="/tmp/work/esp_partition.img"
truncate -s $(( ESP_SECTORS * 512 )) "$ESP_IMG"
mkfs.vfat -F 32 -n "EFI" "$ESP_IMG"

echo "[*] [2/5] Populating EFI System Partition with Boot Assets..."
mmd -i "$ESP_IMG" ::EFI
mmd -i "$ESP_IMG" ::EFI/BOOT

if [ -n "$ESP_DIR" ] && [ -d "$ESP_DIR" ]; then
  find "$ESP_DIR" -type f | while read -r f; do
    rel_path="${f#$ESP_DIR/}"
    echo "    [+] Adding to ESP: $rel_path"
    parent_dir=$(dirname "$rel_path")
    if [ "$parent_dir" != "." ]; then
      mmd -D s -i "$ESP_IMG" "::$parent_dir" 2>/dev/null || true
    fi
    mcopy -o -i "$ESP_IMG" "$f" "::$rel_path"
  done
else
  echo "    [!] Notice: No ESP boot directory provided; creating basic EFI hierarchy."
fi

# 3. Create sparse raw disk file
echo ""
echo "[*] [3/5] Allocating sparse raw disk file ($(( TOTAL_BYTES / 1024 / 1024 )) MiB)..."
truncate -s "$TOTAL_BYTES" "$OUTPUT_RAW"

# 4. Write GPT Partition Table with sgdisk
echo "[*] Writing GPT partition table (ESP + APFS)..."
sgdisk -Z "$OUTPUT_RAW"
sgdisk -o "$OUTPUT_RAW"
sgdisk -n 1:${ESP_START}:${ESP_END} -t 1:ef00 -c 1:"EFI System Partition" "$OUTPUT_RAW"
sgdisk -n 2:${APFS_START}:${APFS_END} -t 2:7C3457EF-0000-11AA-AA11-00306543ECAC -c 2:"Apple APFS Container" "$OUTPUT_RAW"
sgdisk -p "$OUTPUT_RAW"

# 5. Burn partition images into raw disk
echo ""
echo "[*] [4/5] Writing partition data to raw disk image..."
echo "    [+] Writing ESP partition data (Sectors $ESP_START..$ESP_END)..."
dd if="$ESP_IMG" of="$OUTPUT_RAW" bs=512 seek=$ESP_START count=$ESP_SECTORS conv=notrunc status=progress

echo ""
echo "    [+] Writing APFS container data (Sectors $APFS_START..$APFS_END)..."
dd if="$APFS_DMG" of="$OUTPUT_RAW" bs=512 seek=$APFS_START count=$DMG_SECTORS conv=notrunc status=progress

rm -f "$ESP_IMG"
echo ""
echo "[+] RAW disk image created successfully: $(ls -lh "$OUTPUT_RAW")"

# 6. Convert to compressed QCOW2 (VirtIO-Block optimized)
echo ""
echo "[*] [5/5] Generating compressed QCOW2 and compressed RAW artifacts..."
if [ -n "$OUTPUT_QCOW2" ]; then
  echo "    [+] Converting to compressed QCOW2: $OUTPUT_QCOW2..."
  qemu-img convert -f raw -O qcow2 -c "$OUTPUT_RAW" "$OUTPUT_QCOW2"
  echo "    [+] QCOW2 Created: $(ls -lh "$OUTPUT_QCOW2")"
fi

# 7. Compress RAW image with Zstandard
RAW_ZST="${OUTPUT_RAW}.zst"
echo "    [+] Compressing RAW disk with Zstandard (multithreaded)..."
zstd -T0 -3 "$OUTPUT_RAW" -o "$RAW_ZST"
echo "    [+] ZST RAW Disk Created: $(ls -lh "$RAW_ZST")"

# Remove large uncompressed RAW file to conserve disk space
echo "    [+] Reclaiming runner disk space (removing uncompressed RAW)..."
rm -f "$OUTPUT_RAW"

echo ""
echo "================================================================================"
echo "          GPT BOOT DISK CREATION COMPLETE"
echo "================================================================================"
