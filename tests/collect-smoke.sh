#!/bin/sh
# End-to-end check of brec-collect, run by CI on an rpm and a dpkg image.
#
# Expects build-recorder and brec-collect on PATH and the source tree in the
# current directory.  Builds a tiny payload under the collector and checks the
# promises the bundle makes: the exit status is the build's, the bundle exists
# even for a failed build, payload hashes are the tracer's own hashes of the
# written files, and every system file the build read has a package.

set -eu

src=$PWD
work=$(mktemp -d)
cd "$work"
cp "$src/examples/f1.c" .

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# A build that ships one object twice (a copy) and one symlink.
set +e
brec-collect -o ok.tar.gz --payload dist --declared "$src/README.md" -- \
    sh -c 'mkdir -p dist && gcc -c f1.c -o dist/f1.o && cp dist/f1.o dist/copy.o && ln -sf f1.o dist/link.o'
rc_ok=$?
brec-collect -o fail.tar.gz -- sh -c 'exit 3'
rc_fail=$?
brec-collect --bogus -- true 2>/dev/null
rc_usage=$?
set -e

[ "$rc_ok" -eq 0 ] || fail "successful build returned $rc_ok"
[ "$rc_fail" -eq 3 ] || fail "failed build returned $rc_fail, not the build's 3"
[ "$rc_usage" -eq 125 ] || fail "bad usage returned $rc_usage, not 125"
[ -s fail.tar.gz ] || fail "no bundle for a failed build"

mkdir ok fl
tar -C ok -xzf ok.tar.gz
tar -C fl -xzf fail.tar.gz
[ "$(tar -tzf ok.tar.gz | head -n 1)" = MANIFEST ] || fail "MANIFEST is not the first member"
for m in MANIFEST trace.out packages.tsv payload.tsv declared.txt env.txt; do
    [ -s "ok/$m" ] || fail "bundle lacks $m"
done
grep -qx 'build_status=3' fl/MANIFEST || fail "failed bundle does not record status 3"
grep -qx 'payload_files=2' ok/MANIFEST || fail "expected 2 payload files"
grep -qx 'payload_symlinks=1' ok/MANIFEST || fail "expected 1 payload symlink"
grep -Eqx 'pkgdb=(rpm|dpkg)' ok/MANIFEST || fail "no package database recorded"
cat ok/MANIFEST

cd "$src"
python3 - "$work/ok" <<'PY'
import sys
from pathlib import Path
from brec.model import parse_out

b = Path(sys.argv[1])
g = parse_out(b / "trace.out")

written = {g.files[u].git_blob_sha1 for p in g.procs.values() for u in p.writes if u in g.files}
for line in (b / "payload.tsv").read_text().splitlines():
    h, path = line.split("\t")
    assert h in written, f"payload {path} hashes to {h}, which no written node carries"

# The same alias pairs the rpm backend indexes: a trace records the resolved
# /usr form, a package may list either.
alias = {"/lib/": "/usr/lib/", "/lib64/": "/usr/lib64/", "/bin/": "/usr/bin/", "/sbin/": "/usr/sbin/"}
owned = set()
for line in (b / "packages.tsv").read_text(errors="replace").splitlines():
    parts = line.split("\t")
    if len(parts) == 3:
        owned.add(parts[0])
        for s, l in alias.items():
            if parts[0].startswith(s):
                owned.add(l + parts[0][len(s):])
            elif parts[0].startswith(l):
                owned.add(s + parts[0][len(l):])

reads = {g.files[u].abspath for p in g.procs.values() for u in p.reads if u in g.files}
system = sorted(a for a in reads if a.startswith("/usr/"))
missing = [a for a in system if a not in owned]
assert system, "the build read no system file"
assert not missing, f"system files without a package: {missing}"
print(f"ok: payload matches the trace, {len(system)} system reads all attributed")
PY

# The other half: the bundle alone must be enough for a verdict, here GREEN,
# since the build compiled a source file with packaged tools and shipped the
# result.  A RED here is what an unowned system file looked like before.
python3 -m brec analyze "$work/ok.tar.gz" --json "$work/verdict.json" || fail "brec analyze did not say GREEN (exit $?)"
python3 -m brec analyze "$work/fail.tar.gz" >/dev/null && rc=0 || rc=$?
[ "$rc" -ne 2 ] || fail "brec analyze could not read the bundle of a failed build"

# Positive controls: a prebuilt archive that does go into the binary must make
# the verdict RED, wherever it came from.  First one compiled here before and
# outside the trace, then, where the image has it, a static library from a
# distribution package; the verdict used to trust the second one.
cd "$work"
printf 'int planted_marker(void){return 42;}\n' > planted.c
gcc -c planted.c -o planted.o && ar rcs libplanted.a planted.o
printf 'int planted_marker(void);\nint main(void){return planted_marker() != 42;}\n' > uses.c
brec-collect -o planted.tar.gz --payload pdist -- \
    sh -c 'mkdir -p pdist && gcc uses.c libplanted.a -o pdist/uses' 2>/dev/null
cd "$src"
set +e
python3 -m brec analyze "$work/planted.tar.gz" > "$work/planted.txt"
rc=$?
set -e
[ "$rc" -eq 1 ] || { cat "$work/planted.txt"; fail "a planted prebuilt archive did not make the verdict RED (exit $rc)"; }
grep -q 'prebuilt: .*libplanted.a' "$work/planted.txt" || fail "the RED does not name libplanted.a"

libz_a=$(ls /usr/lib/x86_64-linux-gnu/libz.a /usr/lib64/libz.a 2>/dev/null | head -n 1 || true)
if [ -n "$libz_a" ]; then
    cd "$work"
    printf '#include <zlib.h>\nint main(void){return zlibVersion()[0] == 0;}\n' > z.c
    brec-collect -o zstatic.tar.gz --payload zdist -- \
        sh -c "mkdir -p zdist && gcc z.c $libz_a -o zdist/z" 2>/dev/null
    cd "$src"
    set +e
    python3 -m brec analyze "$work/zstatic.tar.gz" > "$work/zstatic.txt"
    rc=$?
    set -e
    [ "$rc" -eq 1 ] || { cat "$work/zstatic.txt"; fail "packaged static $libz_a did not make the verdict RED (exit $rc)"; }
    echo "ok: static $libz_a from a package is reported as prebuilt"
else
    echo "skip: no static libz in this image"
fi
echo "ok: planted prebuilt archive is RED"

# Which members of an archive went into the link: gcc's LTO plugin reads the
# header of each object the linker loads, and the trace names those members.
# Without the plugin nothing can be said, and nothing is claimed.
cd "$work"
for n in one two three; do printf 'int m_%s(void){return 1;}\n' "$n" > "m_$n.c"; done
gcc -c m_one.c m_two.c m_three.c && ar rcs libthree.a m_one.o m_two.o m_three.o
printf 'int m_two(void);\nint main(void){return m_two() != 1;}\n' > two.c
brec-collect -o members.tar.gz -- gcc two.c libthree.a -o two 2>/dev/null
mkdir mem && tar -C mem -xzf members.tar.gz
cd "$src"
python3 - "$work/mem/trace.out" <<'PY'
import re
import sys

t = open(sys.argv[1]).read()
name = dict(re.findall(r'^(:m\d+)\s+b:name\s+"([^"]*)"', t, re.M))
loaded = sorted({name[m] for m in re.findall(r'^:p\d+\s+b:loads_member\s+(:m\d+)', t, re.M)})
if not re.search(r'b:abspath\s+"[^"]*liblto_plugin[^"]*"', t):
    assert not loaded, f"members claimed without the LTO plugin: {loaded}"
    print("skip: the linker loaded no LTO plugin, members not visible")
else:
    assert loaded == ["m_two.o"], f"loaded members {loaded}, expected only m_two.o"
    print("ok: the trace names m_two.o as the one member linked from libthree.a")
PY

# Go, where the image has it: no cgo, and still two ways in for a prebuilt.
# A .syso in the package directory is linked in as it is, and a warm build
# cache hands the linker packages compiled outside the trace.  The cold build
# first: the tracer used to die on it, once Go's threads outgrew the first 32
# slots of its process table.
if command -v go >/dev/null 2>&1; then
    export GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=mod GOCACHE="$work/gocache"
    mkdir -p "$work/gosrc" && cd "$work/gosrc"
    printf 'module demo\n\ngo 1.21\n' > go.mod
    printf 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hi") }\n' > main.go
    set +e
    brec-collect -o "$work/gocold.tar.gz" --payload gdist -- go build -o gdist/demo . 2>/dev/null
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || fail "a cold go build under the tracer exited $rc"
    brec-collect -o "$work/gowarm.tar.gz" --payload wdist -- go build -o wdist/demo . 2>/dev/null
    printf 'int planted_marker = 42;\n' > "$work/p.c"
    gcc -c "$work/p.c" -o "planted_$(go env GOARCH).syso"
    rm -rf "$GOCACHE"
    brec-collect -o "$work/gosyso.tar.gz" --payload sdist -- go build -o sdist/demo . 2>/dev/null
    cd "$src"
    for b in gowarm gosyso; do
        set +e
        python3 -m brec analyze "$work/$b.tar.gz" > "$work/$b.txt"
        rc=$?
        set -e
        [ "$rc" -eq 1 ] || { cat "$work/$b.txt"; fail "$b did not make the verdict RED (exit $rc)"; }
    done
    grep -q 'GOCACHE' "$work/gowarm.txt" || fail "the warm-cache RED does not point at GOCACHE"
    grep -q 'prebuilt: .*planted_.*\.syso' "$work/gosyso.txt" || fail "the RED does not name the .syso"
    echo "ok: a warm Go build cache and a planted .syso are RED"
else
    echo "skip: no go in this image"
fi
