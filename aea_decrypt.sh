#!/usr/bin/env bash
#
# aea_decrypt.sh - fetch the WKMS key for one AEA1 container and decrypt it
#                  without ever letting the key reach the log.
#
# Fixes F6 in docs/cloud-extraction.md. The previous pipeline ran
#
#     KEY_VAL=$(echo "$KEY_RAW" | grep "base64:" | cut -d':' -f2)
#     echo "Decryption Key retrieved: $KEY_VAL"
#
# in a PUBLIC repository, so that key is permanently world readable in the log
# of run 40319004513. Three changes here:
#
#   1. `ipsw fw aea -k` output goes to a temp file, never to stdout, and
#      ::add-mask:: is emitted before anything else is printed.
#   2. An empty key is a hard failure. Previously an output-format change would
#      have passed an empty --key-val and failed later, somewhere else.
#   3. Diagnostics on failure are redacted with sed, so a parse error still
#      cannot leak a key that was present but matched differently.
#
# Usage: aea_decrypt.sh <input.dmg.aea> <output_dir> [missing_components_file]
#
# On success the decrypted container is in <output_dir> and the .aea input has
# been deleted to reclaim disk (the caller's budget assumes this).

set -uo pipefail
set +x   # never trace: --key-val lands in argv

AEA="${1:?usage: aea_decrypt.sh <input.dmg.aea> <output_dir> [missing_file]}"
OUT_DIR="${2:?missing output dir}"
MISSING_FILE="${3:-}"

note_missing() {
    [ -n "$MISSING_FILE" ] && echo "$1" >> "$MISSING_FILE"
    return 0
}

redact() {
    # Strip anything that looks like a key before it can be printed.
    sed -E 's#base64:[A-Za-z0-9+/=]+#base64:<redacted>#g; s#[A-Za-z0-9+/]{40,}={0,2}#<redacted>#g'
}

if [ ! -f "$AEA" ]; then
    echo "::error title=AEA missing::$AEA does not exist"
    note_missing "AEA_INPUT_MISSING $AEA"
    exit 1
fi

mkdir -p "$OUT_DIR"
KEY_OUT=$(mktemp)
KEY_ERR=$(mktemp)
chmod 600 "$KEY_OUT" "$KEY_ERR"
trap 'rm -f "$KEY_OUT" "$KEY_ERR"' EXIT

echo "Requesting WKMS archive key for $(basename "$AEA") ($(stat -c %s "$AEA") bytes)"
ipsw fw aea -k "$AEA" >"$KEY_OUT" 2>"$KEY_ERR"
RC=$?

KEY=$(grep -oE 'base64:[A-Za-z0-9+/=]+' "$KEY_OUT" | head -n 1 | cut -d: -f2 | tr -d '[:space:]')

if [ -z "$KEY" ]; then
    # Mask whatever we did get, in case it is a key in an unexpected shape.
    while IFS= read -r line; do
        [ -n "$line" ] && echo "::add-mask::$line"
    done < <(grep -oE '[A-Za-z0-9+/]{40,}={0,2}' "$KEY_OUT" "$KEY_ERR" 2>/dev/null | sed 's/^[^:]*://')
    echo "::error title=Empty AEA key::ipsw fw aea -k returned no base64 key for $(basename "$AEA") (exit $RC). Redacted output follows."
    echo "--- stdout (redacted) ---"; redact <"$KEY_OUT" | head -n 40
    echo "--- stderr (redacted) ---"; redact <"$KEY_ERR" | head -n 40
    note_missing "AEA_KEY_EMPTY $(basename "$AEA") ipsw_exit=$RC"
    exit 1
fi

# Mask first, print second. Everything after this point is safe even if some
# tool decides to echo the key itself.
echo "::add-mask::$KEY"
echo "WKMS key acquired for $(basename "$AEA"): masked, ${#KEY} base64 chars"

if ! ipsw fw aea "$AEA" -o "$OUT_DIR" --key-val "$KEY" 2> >(redact >&2); then
    echo "::error title=AEA decrypt failed::ipsw fw aea could not decrypt $(basename "$AEA")"
    note_missing "AEA_DECRYPT_FAILED $(basename "$AEA")"
    exit 1
fi
unset KEY

DEC=$(find "$OUT_DIR" -maxdepth 2 -type f -name '*.dmg' | head -n 1)
if [ -z "$DEC" ]; then
    echo "::error title=No decrypted container::nothing matching *.dmg appeared under $OUT_DIR"
    note_missing "AEA_DECRYPT_NO_OUTPUT $(basename "$AEA")"
    ls -lR "$OUT_DIR" || true
    exit 1
fi

echo "Decrypted: $DEC ($(stat -c %s "$DEC") bytes)"
rm -f "$AEA"
echo "Removed the .aea input to reclaim $(basename "$AEA")'s space."
df -h /
