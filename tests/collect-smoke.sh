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
