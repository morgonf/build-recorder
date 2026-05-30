#!/bin/bash
set -euo pipefail

SRPM="${SRPM:-/srpms/civetweb-1.16-alt5.git588860e.src.rpm}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
OUTPUT_FILE="${OUTPUT_DIR}/civetweb-build.out"

if [[ ! -f "$SRPM" ]]; then
    echo "ERROR: SRPM not found at $SRPM" >&2
    echo "       Mount the SRPM directory or set the SRPM env variable." >&2
    exit 1
fi

echo "=== Installing SRPM: $(basename "$SRPM") ==="
rpm -i --nodeps "$SRPM"

TOPDIR="$(rpm --eval '%_topdir')"
SPEC="$TOPDIR/SPECS/civetweb.spec"
if [[ ! -f "$SPEC" ]]; then
    echo "ERROR: spec not found after rpm -i: $SPEC" >&2
    exit 1
fi

echo "=== Starting build-recorder + rpmbuild ==="
echo "    SRPM    : $SRPM"
echo "    Output  : $OUTPUT_FILE"
echo ""

build-recorder -o "$OUTPUT_FILE" \
    rpmbuild --nodeps --nocheck --define '_allow_root_build 1' -bb "$SPEC"

echo ""
echo "=== Build complete ==="
echo "    Triples written: $(grep -c '\.' "$OUTPUT_FILE" || true)"
echo "    Processes found: $(grep -c 'a.*b:process' "$OUTPUT_FILE" || true)"
echo "    Files tracked  : $(grep -c 'a.*b:file' "$OUTPUT_FILE" || true)"
echo ""
echo "Output saved to: $OUTPUT_FILE"
