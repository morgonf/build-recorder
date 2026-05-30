#!/bin/bash
set -euo pipefail

SRPM="${SRPM:?ERROR: SRPM env variable is required (path to .src.rpm inside container)}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"

if [[ ! -f "$SRPM" ]]; then
    echo "ERROR: SRPM not found at $SRPM" >&2
    echo "       Mount the SRPM directory and set SRPM to the path inside the container." >&2
    exit 1
fi

PKG_NAME=$(rpm -qp --qf '%{NAME}' "$SRPM" 2>/dev/null)
OUTPUT_FILE="${OUTPUT_DIR}/${PKG_NAME}-build.out"

echo "=== Installing SRPM: $(basename "$SRPM") ==="
rpm -i --nodeps "$SRPM" 2>&1 | grep -v "does not exist - using root" || true

TOPDIR="$(rpm --eval '%_topdir')"
SPEC=$(find "$TOPDIR/SPECS" -name '*.spec' | head -1)

if [[ -z "$SPEC" ]]; then
    echo "ERROR: no spec file found in $TOPDIR/SPECS after rpm -i" >&2
    exit 1
fi

# rpmbuild on ALT Linux p11 (rpm 4.13) has no --nocheck flag.
# Strip the %check section from the spec before building.
awk '
    /^%check/ { print "%check"; print "exit 0"; skip=1; next }
    skip && /^%[a-zA-Z_]/ { skip=0; print; next }
    !skip { print }
' "$SPEC" > "${SPEC}.nocheck" && mv "${SPEC}.nocheck" "$SPEC"

echo "=== Starting build-recorder + rpmbuild ==="
echo "    Package : $PKG_NAME"
echo "    Spec    : $SPEC"
echo "    Output  : $OUTPUT_FILE"
echo ""

build-recorder -o "$OUTPUT_FILE" \
    rpmbuild --nodeps --define '_allow_root_build 1' -bb "$SPEC"

echo ""
echo "=== Build complete ==="
echo "    Triples  : $(grep -c '\.' "$OUTPUT_FILE" 2>/dev/null || echo 0)"
echo "    Processes: $(grep -c 'a.*b:process' "$OUTPUT_FILE" 2>/dev/null || echo 0)"
echo "    Files    : $(grep -c 'a.*b:file' "$OUTPUT_FILE" 2>/dev/null || echo 0)"
echo "    Size     : $(du -sh "$OUTPUT_FILE" | cut -f1)"
echo ""
echo "Output: $OUTPUT_FILE"
