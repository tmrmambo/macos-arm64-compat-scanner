#!/usr/bin/env bash
#
# pack_full_volume.sh - mount one APFS container read-only through apfs-fuse and
#                       write a FULL, metadata-preserving tar.zst of everything
#                       the mount exposes.
#
# This is deliberately NOT package_rootfs.py. That script copies five
# hand-picked path groups, and when it cannot find /private/etc it synthesises
# a two-line passwd and still reports SUCCESS (F1 in docs/cloud-extraction.md).
# Here nothing is selected and nothing is synthesised: the entire mount is
# archived, and the diagnostics below record what the mount actually looked
# like, so an absent path shows up in the report instead of being papered over.
#
# Usage:
#   pack_full_volume.sh <container.dmg> <mountpoint> <out.tar.zst> <label> <reports_dir>
#
# Environment:
#   ZSTD_LEVEL    compression level, default 12
#   ZSTD_EXTRA    extra zstd flags, default "--long=27"
#   VERIFY        1 (default) = read the archive back, count members, save the
#                 member list; 0 = skip both decompression passes
#   MISSING_FILE  where to append every degraded/not-found branch,
#                 default <reports_dir>/missing_components.txt
#
# Side effects: writes <out>.sha256 and <out:r:r>.meta.json next to the tar so
# each artifact is self-verifying even without the reports artifact.

set -uo pipefail
set +x

CONTAINER="${1:?usage: pack_full_volume.sh <container> <mnt> <out.tar.zst> <label> <reports_dir>}"
MNT="${2:?missing mountpoint}"
OUT="${3:?missing output path}"
LABEL="${4:?missing label}"
REPORTS="${5:?missing reports dir}"

ZSTD_LEVEL="${ZSTD_LEVEL:-12}"
ZSTD_EXTRA="${ZSTD_EXTRA:---long=27}"
VERIFY="${VERIFY:-1}"
MISSING_FILE="${MISSING_FILE:-$REPORTS/missing_components.txt}"

mkdir -p "$MNT" "$REPORTS" "$(dirname "$OUT")"
TREE="$REPORTS/mount_tree_${LABEL}.txt"
WARN="$REPORTS/tar_warnings_${LABEL}.txt"
META="${OUT%.tar.zst}.meta.json"

note_missing() { echo "$1" >> "$MISSING_FILE"; return 0; }

banner() { echo ""; echo "=============== $* ==============="; }

# ---------------------------------------------------------------- mount -------
banner "$LABEL: mounting $CONTAINER"
if [ ! -f "$CONTAINER" ]; then
    echo "::error title=No container::$CONTAINER does not exist"
    note_missing "CONTAINER_MISSING ${LABEL} ${CONTAINER}"
    exit 1
fi
CONTAINER_BYTES=$(stat -c %s "$CONTAINER")
echo "container: $CONTAINER_BYTES bytes"

# apfsutil ships with apfs-fuse and lists the volumes in the container. Logging
# it makes "which volume did we actually get" answerable from the log alone.
if command -v apfsutil >/dev/null 2>&1; then
    echo "--- apfsutil volume list ---"
    apfsutil "$CONTAINER" 2>&1 | head -n 40 || true
else
    echo "(apfsutil not on PATH; skipping volume list)"
fi

if ! sudo apfs-fuse -o allow_other "$CONTAINER" "$MNT"; then
    echo "::error title=apfs-fuse mount failed::$LABEL container would not mount"
    note_missing "MOUNT_FAILED ${LABEL} ${CONTAINER}"
    exit 1
fi
echo "mounted at $MNT"

cleanup() {
    sudo umount "$MNT" 2>/dev/null \
        || sudo fusermount3 -u "$MNT" 2>/dev/null \
        || sudo fusermount -u "$MNT" 2>/dev/null \
        || echo "::warning title=Unmount failed::$MNT still mounted"
}
trap cleanup EXIT

# ---------------------------------------------------------- diagnostics -------
# Requirement from the audit: after mounting, always dump the directory tree and
# probe the /etc candidates, so a fallback can never be mistaken for a success.
probe() {   # probe <base> <relpath>
    local base="$1" rel="$2" p="$1/$2"
    if sudo test -L "$p"; then
        printf 'LINK  %-52s -> %s\n' "$rel" "$(sudo readlink "$p" 2>/dev/null)"
    elif sudo test -d "$p"; then
        printf 'DIR   %-52s (%s entries)\n' "$rel" "$(sudo ls -1A "$p" 2>/dev/null | wc -l)"
    elif sudo test -e "$p"; then
        printf 'FILE  %-52s (%s bytes)\n' "$rel" "$(sudo stat -c %s "$p" 2>/dev/null)"
    else
        printf 'MISS  %-52s\n' "$rel"
    fi
}

banner "$LABEL: mount diagnostics"
{
    echo "###############################################################"
    echo "# label            : $LABEL"
    echo "# container        : $CONTAINER ($CONTAINER_BYTES bytes)"
    echo "# mountpoint       : $MNT"
    echo "# apfs-fuse commit : ${APFS_FUSE_SHA:-unknown}"
    echo "# ipsw version     : ${IPSW_RESOLVED_VERSION:-unknown}"
    echo "# date (UTC)       : $(date -u +%FT%TZ)"
    echo "###############################################################"
    echo ""
    echo "--- nested mounts under $MNT (tar walks all of them) ---"
    findmnt -R -o TARGET,SOURCE,FSTYPE "$MNT" 2>/dev/null || echo "(findmnt reported nothing)"
    echo ""
    echo "--- ls -la $MNT ---"
    sudo ls -la "$MNT" 2>&1 | head -n 60
    echo ""
    echo "--- du -sh per top-level entry ---"
    sudo du -sh --max-depth=1 "$MNT" 2>/dev/null | sort -h || true
    echo ""
    echo "--- find -maxdepth 3 -type d ---"
    sudo find "$MNT" -maxdepth 3 -type d 2>/dev/null | sed "s|^$MNT|.|" | sort | head -n 3000
    echo ""
    echo "--- path probes (mount root and, if present, the root/ payload dir) ---"
    for BASE in "$MNT" "$MNT/root"; do
        if ! sudo test -d "$BASE"; then
            echo "[base $BASE: not a directory, skipped]"
            continue
        fi
        echo "[base $BASE]"
        # The four /etc candidates package_rootfs.py tried and missed.
        for REL in private/etc root/private/etc etc root/etc; do
            probe "$BASE" "$REL"
        done
        # Everything else Gate F depends on.
        for REL in \
            private/var/db \
            System/Library/dyld \
            System/Library/LaunchDaemons \
            System/Library/CoreServices/SystemVersion.plist \
            System/Library/CoreServices/boot.efi \
            System/Library/Caches/com.apple.dyld \
            System/Library/xpc \
            usr/lib/dyld usr/libexec usr/standalone \
            sbin/launchd bin/sh bin/zsh \
            Library Applications
        do
            probe "$BASE" "$REL"
        done
        echo ""
    done
    echo "--- every dyld shared cache file visible (both arm64e and plain arm64) ---"
    sudo find "$MNT" -maxdepth 6 -name 'dyld_shared_cache*' -printf '%10s  %p\n' 2>/dev/null \
        | sed "s| $MNT| .|" | sort -k2 || echo "(none)"
} | tee "$TREE"

# Inventory counts. Cheap, and it gives an independent number to check the tar
# member count against.
# No -xdev here on purpose: tar walks nested mounts, so the counts must too,
# otherwise the member-count cross-check below would fire a false alarm.
banner "$LABEL: inventory"
N_FILES=$(sudo find "$MNT" -type f 2>/dev/null | wc -l)
N_DIRS=$(sudo find "$MNT" -type d 2>/dev/null | wc -l)
N_LINKS=$(sudo find "$MNT" -type l 2>/dev/null | wc -l)
N_OTHER=$(sudo find "$MNT" ! -type f ! -type d ! -type l 2>/dev/null | wc -l)
N_ENTRIES=$((N_FILES + N_DIRS + N_LINKS + N_OTHER))
APPARENT_BYTES=$(sudo du -sb "$MNT" 2>/dev/null | cut -f1)
APPARENT_BYTES="${APPARENT_BYTES:-0}"
{
    echo ""
    echo "--- inventory ---"
    echo "files    : $N_FILES"
    echo "dirs     : $N_DIRS"
    echo "symlinks : $N_LINKS"
    echo "other    : $N_OTHER"
    echo "entries  : $N_ENTRIES"
    echo "du -sb   : $APPARENT_BYTES"
} | tee -a "$TREE"

if [ "$N_ENTRIES" -lt 10 ]; then
    echo "::error title=Mount looks empty::$MNT exposes only $N_ENTRIES entries"
    note_missing "MOUNT_NEARLY_EMPTY ${LABEL} entries=${N_ENTRIES}"
    exit 1
fi

# ------------------------------------------------------------------ tar -------
# --numeric-owner  : runner has no macOS passwd db, so names would be garbage
# -p / --acls / --xattrs : keep whatever apfs-fuse chooses to expose
# --format=posix   : pax, required for xattrs and for >8 GiB / long names
# no -h            : symlinks and firmlinks stay symlinks, never dereferenced
# tar exit 1 means "file changed / could not read some attribute" -> keep going
#   but record every line; exit 2 is fatal.
banner "$LABEL: tar + zstd -${ZSTD_LEVEL} ${ZSTD_EXTRA}"
echo "writing $OUT"
: > "$WARN"
# shellcheck disable=SC2086
sudo tar -C "$MNT" \
        --numeric-owner -p --acls --xattrs --xattrs-include='*' \
        --format=posix \
        -cf - . 2>"$WARN" \
    | zstd -T0 "-${ZSTD_LEVEL}" ${ZSTD_EXTRA} -f -o "$OUT"
# PIPESTATUS is rebuilt by every simple command, including the assignment that
# reads it, so `TAR_RC=${PIPESTATUS[0]}` leaves a one-element array behind and
# the next line sees PIPESTATUS[1] as unset. Under set -u that is fatal, and it
# killed run 41045152598 after the 7.96 GiB tar had already been written. Copy
# the whole array in one go.
RCS=("${PIPESTATUS[@]}")
TAR_RC=${RCS[0]:-0}
ZSTD_RC=${RCS[1]:-0}
WARN_LINES=$(wc -l < "$WARN" | tr -d ' ')

echo "tar exit=$TAR_RC  zstd exit=$ZSTD_RC  tar diagnostics=$WARN_LINES lines"
if [ "$WARN_LINES" -gt 0 ]; then
    echo "--- first 60 tar diagnostics (full list in $(basename "$WARN")) ---"
    head -n 60 "$WARN"
    echo "::warning title=tar diagnostics ($LABEL)::$WARN_LINES lines recorded in reports/$(basename "$WARN")"
    note_missing "TAR_DIAGNOSTICS ${LABEL} lines=${WARN_LINES} (see reports/$(basename "$WARN"))"
fi
if [ "$ZSTD_RC" -ne 0 ]; then
    echo "::error title=zstd failed::$LABEL compression exited $ZSTD_RC"
    note_missing "ZSTD_FAILED ${LABEL} rc=${ZSTD_RC}"
    exit 1
fi
if [ "$TAR_RC" -gt 1 ]; then
    echo "::error title=tar failed::$LABEL tar exited $TAR_RC (2 = fatal)"
    note_missing "TAR_FATAL ${LABEL} rc=${TAR_RC}"
    exit 1
fi

df -h /

# -------------------------------------------------- checksums and verify ------
banner "$LABEL: checksums"
COMP_BYTES=$(stat -c %s "$OUT")
SHA=$(sha256sum "$OUT" | cut -d' ' -f1)
( cd "$(dirname "$OUT")" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256" )
echo "sha256 : $SHA"
echo "bytes  : $COMP_BYTES"

UNCOMP_BYTES=0
MEMBERS=0
if [ "$VERIFY" = "1" ]; then
    echo "reading the archive back (this also proves it decompresses)"
    # Nothing below aborts. The tar is the expensive thing and it already
    # exists; a verification problem is recorded in missing_components so the
    # run's final gate turns red, but the archive still gets uploaded and can
    # be examined. Throwing away 8 GiB because a check stumbled is the wrong
    # trade.
    UNCOMP_BYTES=$(zstd -dc "$OUT" | wc -c)
    if [ "${UNCOMP_BYTES:-0}" -le 0 ]; then
        echo "::error title=Archive unreadable::zstd -dc produced nothing for $OUT"
        note_missing "ARCHIVE_UNREADABLE ${LABEL}"
        UNCOMP_BYTES=0
    else
        # The member list is the authoritative statement of what shipped, and
        # it costs one pass we are already paying for.
        zstd -dc "$OUT" | tar -tf - 2>/dev/null \
            | zstd -T0 -9 -f -o "$REPORTS/filelist_${LABEL}.txt.zst"
        MEMBERS=$(zstd -dc "$REPORTS/filelist_${LABEL}.txt.zst" 2>/dev/null | wc -l)
        echo "uncompressed : $UNCOMP_BYTES"
        echo "members      : $MEMBERS (find counted $N_ENTRIES entries)"
        DELTA=$((MEMBERS - N_ENTRIES))
        if [ "${DELTA#-}" -gt $((N_ENTRIES / 50 + 16)) ]; then
            echo "::warning title=Member count drift ($LABEL)::tar holds $MEMBERS members, find saw $N_ENTRIES entries"
            note_missing "MEMBER_COUNT_DRIFT ${LABEL} tar=${MEMBERS} find=${N_ENTRIES}"
        fi
    fi
else
    echo "VERIFY=0, skipping the read-back passes"
    note_missing "VERIFY_SKIPPED ${LABEL} (uncompressed size and member count unknown)"
fi

RATIO="n/a"
if [ "${UNCOMP_BYTES:-0}" -gt 0 ]; then
    RATIO=$(awk -v u="$UNCOMP_BYTES" -v c="$COMP_BYTES" 'BEGIN{printf "%.3f", u/c}')
fi
echo "ratio  : $RATIO x"

jq -n \
    --arg label "$LABEL" \
    --arg artifact "$(basename "$OUT")" \
    --arg sha256 "$SHA" \
    --arg zstd "-${ZSTD_LEVEL} ${ZSTD_EXTRA}" \
    --arg ratio "$RATIO" \
    --arg mount "$MNT" \
    --arg container "$(basename "$CONTAINER")" \
    --arg apfs_fuse "${APFS_FUSE_SHA:-unknown}" \
    --arg ipsw "${IPSW_RESOLVED_VERSION:-unknown}" \
    --argjson container_bytes "$CONTAINER_BYTES" \
    --argjson compressed_bytes "$COMP_BYTES" \
    --argjson uncompressed_bytes "${UNCOMP_BYTES:-0}" \
    --argjson apparent_bytes "$APPARENT_BYTES" \
    --argjson members "${MEMBERS:-0}" \
    --argjson files "$N_FILES" \
    --argjson dirs "$N_DIRS" \
    --argjson symlinks "$N_LINKS" \
    --argjson other "$N_OTHER" \
    --argjson tar_exit "$TAR_RC" \
    --argjson tar_diagnostics "$WARN_LINES" \
    '{label:$label, artifact:$artifact, sha256:$sha256,
      compressed_bytes:$compressed_bytes, uncompressed_bytes:$uncompressed_bytes,
      apparent_bytes:$apparent_bytes, compression:$zstd, ratio:$ratio,
      members:$members, files:$files, dirs:$dirs, symlinks:$symlinks, other:$other,
      source_container:$container, source_container_bytes:$container_bytes,
      mountpoint:$mount, tar_exit:$tar_exit, tar_diagnostics:$tar_diagnostics,
      apfs_fuse_commit:$apfs_fuse, ipsw_version:$ipsw}' \
    | tee "$META" | tee -a "$REPORTS/artifact_manifest.jsonl" >/dev/null

{
    printf '%s  %s\n' "$SHA" "$(basename "$OUT")"
} >> "$REPORTS/SHA256SUMS.txt"

{
    echo "[$LABEL]"
    echo "  artifact            : $(basename "$OUT")"
    echo "  sha256              : $SHA"
    echo "  compressed bytes    : $COMP_BYTES"
    echo "  uncompressed bytes  : $UNCOMP_BYTES"
    echo "  ratio               : $RATIO x"
    echo "  zstd                : -${ZSTD_LEVEL} ${ZSTD_EXTRA}"
    echo "  tar members         : $MEMBERS"
    echo "  files/dirs/links    : $N_FILES / $N_DIRS / $N_LINKS"
    echo "  tar exit / warnings : $TAR_RC / $WARN_LINES"
    echo "  source container    : $(basename "$CONTAINER") ($CONTAINER_BYTES bytes)"
    echo ""
} >> "$REPORTS/pack_summary.txt"

banner "$LABEL: done"
cat "$META"
