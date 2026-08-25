#!/bin/bash
# A gcc that also states, in its own words, which headers it read.
#
# Installed ahead of /usr/bin on PATH during the experiment, it appends
# `-MD -MF <unique>.d` to every compilation and then execs the real compiler.
# The resulting depfiles are the reference instrument: the compiler's internal
# bookkeeping, produced by a mechanism entirely unlike ptrace observation.
#
# Only compilations are touched (`-c` present).  Preprocess-only runs, link
# steps, configure probes that already ask for dependencies, and anything that
# already carries a -M flag are passed through untouched, because a depfile
# there is either meaningless or would overwrite the build's own.

set -u

: "${DEPFILE_DIR:=/output/depfiles}"

real="/usr/bin/${0##*/}"
[ -x "$real" ] || real="/usr/bin/gcc"

add_md=1
have_c=0
for arg in "$@"; do
    case "$arg" in
        -c) have_c=1 ;;
        -E|-M|-MM|-MD|-MMD|-MF|-MT|-MQ) add_md=0 ;;
    esac
done

if [ "$have_c" = 1 ] && [ "$add_md" = 1 ] && mkdir -p "$DEPFILE_DIR" 2>/dev/null; then
    dep=$(mktemp -p "$DEPFILE_DIR" -t "XXXXXXXX.d" 2>/dev/null) || dep=""
    if [ -n "$dep" ]; then
        # Depfiles name their inputs the way the command line did, so relative
        # paths only mean something next to the directory the compiler ran in.
        pwd > "${dep%.d}.cwd" 2>/dev/null || true
        exec "$real" "$@" -MD -MF "$dep"
    fi
fi

exec "$real" "$@"
