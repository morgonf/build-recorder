#!/bin/bash
# Build one SRPM under build-recorder and collect, in the same run, whatever the
# toolchain says about its own inputs.  Everything lands in /output:
#
#   <name>-build.out        the trace
#   depfiles/*.d            gcc's own header lists (C, via the cc wrapper)
#   rust-depinfo/*.d        rustc's own file lists (cargo writes them itself)
#   ground-truth/           Cargo.lock, vendor/modules.txt, go module stamps
#   rpm-dump.txt            file → package index
#   rpm-deps.txt            provides/requires graph
#   builddeps-declared.txt  declared BuildRequires
#   build.log               full build output
#   payload/                the buildroot, when RPMBUILD_STAGE=-bi
#
# Usage (inside the container):  run-build.sh /srpms/pkg-1.0-alt1.src.rpm
set -euo pipefail

SRPM="${1:?usage: run-build.sh <path-to.src.rpm>}"
OUTPUT_DIR="${OUTPUT_DIR:-/output}"
export DEPFILE_DIR="${OUTPUT_DIR}/depfiles"

mkdir -p "$OUTPUT_DIR" "$DEPFILE_DIR" "$OUTPUT_DIR/ground-truth" "$OUTPUT_DIR/rust-depinfo"

name=$(rpm -qp --qf '%{NAME}' "$SRPM" 2>/dev/null)
trace="${OUTPUT_DIR}/${name}-build.out"

# ── The reference instrument for C: gcc that also writes depfiles ────────────
# Shadowing by PATH rather than by rpm macros: specs pass compiler flags in too
# many different ways for a macro override to be reliable.
for tool in gcc cc g++ c++; do
    cp /experiment/cc-wrapper.sh "/usr/local/bin/$tool"
    chmod +x "/usr/local/bin/$tool"
done
export PATH="/usr/local/bin:$PATH"

echo "=== Installing SRPM: $(basename "$SRPM") ==="
rpm -i --nodeps "$SRPM" 2>&1 | grep -v "does not exist - using root" || true

topdir="$(rpm --eval '%_topdir')"
spec=$(find "$topdir/SPECS" -name '*.spec' | head -1)
[ -n "$spec" ] || { echo "ERROR: no spec in $topdir/SPECS" >&2; exit 1; }

# rpm 4.13 has no --nocheck
awk '
    /^%check/ { print "%check"; print "exit 0"; skip=1; next }
    skip && /^%[a-zA-Z_]/ { skip=0; print; next }
    !skip { print }
' "$spec" > "${spec}.nocheck" && mv "${spec}.nocheck" "$spec"

# -bc covers %prep and %build, which is what the file- and component-level
# comparisons need.  -bi also runs %install, which fills the buildroot: that is
# the only way to point `brec verdict --payload` at what actually ships, and
# without it a fidelity number is computed over every file the build touched,
# most of which is a compiler cache nobody delivers.
STAGE="${RPMBUILD_STAGE:--bc}"

echo "=== Building under build-recorder: $name ($STAGE) ==="
set +e
build-recorder -o "$trace" \
    rpmbuild --nodeps --define '_allow_root_build 1' "$STAGE" "$spec" \
    > "${OUTPUT_DIR}/build.log" 2>&1
rc=$?
set -e
echo "    rpmbuild exit code: $rc"
tail -20 "${OUTPUT_DIR}/build.log"

# ── Collect what the toolchains say about themselves ─────────────────────────
builddir="$topdir/BUILD"
gt="${OUTPUT_DIR}/ground-truth"

# Rust: cargo writes dep-info next to every artifact; Cargo.lock pins components.
find "$builddir" -path '*/target/*/deps/*.d' -exec cp -t "${OUTPUT_DIR}/rust-depinfo/" {} + 2>/dev/null || true
find "$builddir" -maxdepth 3 -name Cargo.lock -exec cp -t "$gt/" {} + 2>/dev/null || true

# Go: vendor/modules.txt is the vendored module list; the built binary carries
# its own stamp, which is the toolchain's own answer to "what is in here".
find "$builddir" -maxdepth 3 -path '*/vendor/modules.txt' -exec cp -t "$gt/" {} + 2>/dev/null || true
find "$builddir" -maxdepth 3 -name 'go.sum' -exec cp -t "$gt/" {} + 2>/dev/null || true
if command -v go >/dev/null 2>&1 && [ -n "$(ls -A "$gt" 2>/dev/null)" ]; then
    while IFS= read -r bin; do
        go version -m "$bin" > "$gt/go-version-m.txt" 2>/dev/null && break
    done < <(find "$builddir" -type f -perm -u+x -newer "$spec" 2>/dev/null | head -20)
fi

# ── What the package would ship, when %install ran ───────────────────────────
# Copied out whole rather than listed: the payload check matches by content
# hash, so it needs the files themselves.
# %buildroot only exists while a spec is being built, so look for what it left:
# ALT puts it in %_tmppath as <name>-buildroot.
tmppath="$(rpm --eval '%_tmppath' 2>/dev/null)"
buildroot="$(find "$tmppath" -maxdepth 1 -type d -name '*-buildroot' 2>/dev/null | head -1)"
if [ -n "$buildroot" ] && [ -d "$buildroot" ]; then
    echo "=== Buildroot: $buildroot ==="
    mkdir -p "${OUTPUT_DIR}/payload"
    cp -a "$buildroot/." "${OUTPUT_DIR}/payload/" 2>/dev/null || true
fi

# ── The rpm side, same as the SRPM mode of the main entrypoint ───────────────
rpm -qa --qf '[%{FILENAMES}\t%{NAME}\t%{NEVRA}\n]' 2>/dev/null > "${OUTPUT_DIR}/rpm-dump.txt"
{
    rpm -qa --qf '[P\t%{PROVIDENAME}\t%{NAME}\n]'
    rpm -qa --qf '[R\t%{NAME}\t%{REQUIRENAME}\n]'
} 2>/dev/null > "${OUTPUT_DIR}/rpm-deps.txt"
rpm -qp --requires "$SRPM" 2>/dev/null | sort -u > "${OUTPUT_DIR}/builddeps-declared.txt"

# The build runs as root inside the container; the analysis runs as whoever owns
# the host directory.  Without this the collected evidence is unreadable outside.
chmod -R a+rX "$OUTPUT_DIR" 2>/dev/null || true

echo ""
echo "=== Collected ==="
printf "    trace        : %s (%s lines)\n" "$trace" "$(wc -l < "$trace" 2>/dev/null || echo 0)"
printf "    gcc depfiles : %s\n" "$(find "$DEPFILE_DIR" -name '*.d' | wc -l)"
printf "    rustc depinfo: %s\n" "$(find "${OUTPUT_DIR}/rust-depinfo" -name '*.d' | wc -l)"
printf "    ground truth : %s\n" "$(ls "$gt" 2>/dev/null | tr '\n' ' ')"
printf "    payload      : %s file(s)\n" "$(find "${OUTPUT_DIR}/payload" -type f 2>/dev/null | wc -l)"
exit "$rc"
