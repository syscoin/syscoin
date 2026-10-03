#!/usr/bin/env bash
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <pinned-bitcoin-source-archive>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SOURCE_ARCHIVE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [[ ! -f "$SOURCE_ARCHIVE" ]]; then
    echo "Source archive does not exist: $SOURCE_ARCHIVE" >&2
    exit 2
fi

TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/btcheader-provenance.XXXXXXXX")"
cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

COPYING_MEMBER="$(tar -tf "$SOURCE_ARCHIVE" | awk '
    /^[^\/]+\/COPYING$/ { member = $0; count++ }
    END { if (count != 1) exit 1; print member }
')" || {
    echo "Pinned source archive must contain exactly one top-level COPYING" >&2
    exit 1
}
tar -xOf "$SOURCE_ARCHIVE" "$COPYING_MEMBER" > "$TEST_ROOT/COPYING"
if ! cmp -s "$SCRIPT_DIR/COPYING.bitcoin-core" "$TEST_ROOT/COPYING"; then
    echo "Pinned Bitcoin license does not match the authenticated source archive" >&2
    exit 1
fi

TAMPERED_ARCHIVE="$TEST_ROOT/tampered.tar.gz"
cp "$SOURCE_ARCHIVE" "$TAMPERED_ARCHIVE"
printf '\0' >> "$TAMPERED_ARCHIVE"

# SYSCOIN: A same-named poisoned Guix/cache artifact must be rejected before
# extraction, patch application, or any compiler invocation.
if BTCHEADERNODE_SOURCE_ARCHIVE="$TAMPERED_ARCHIVE" \
        "$SCRIPT_DIR/build-bitcoin-header-node.sh" \
            --src-root "$SRC_ROOT" \
            --build-root "$TEST_ROOT/build" \
            --jobs 1 >"$TEST_ROOT/stdout" 2>"$TEST_ROOT/stderr"; then
    echo "Tampered pinned source archive was unexpectedly accepted" >&2
    exit 1
fi

if ! grep -Fq "Pinned Bitcoin source archive SHA-256 mismatch." \
        "$TEST_ROOT/stderr"; then
    echo "Tampered archive failed for an unexpected reason" >&2
    cat "$TEST_ROOT/stderr" >&2
    exit 1
fi

echo "btcheadernode source provenance rejection: PASS"
