"""brec analyze and the pieces it needs: the dpkg backend, telling an rpm dump
from a dpkg one, and a payload given as brec-collect's payload.tsv."""

from __future__ import annotations

import io
import tarfile
from argparse import Namespace
from pathlib import Path

import pytest

from brec.commands import analyze
from brec.commands import verdict as pv
from brec.model import parse_out
from brec.provenance.dpkg import DpkgBackend
from brec.provenance.registry import detect_backends
from brec.provenance.rpm import RpmBackend

LIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"
APP = b"\x7fELF fake binary\n"


def _file(uri, abspath, name, sha):
    return (
        f"{uri} a b:file .\n"
        f'{uri} b:abspath "{abspath}" .\n'
        f'{uri} b:name "{name}" .\n'
        f'{uri} b:hash "{sha}" .\n'
    )


def _trace(path: Path) -> Path:
    """ld reads main.o and the system libc, writes the app.

    libc is a binary nobody built here: without package attribution it is a
    foreign prebuilt (RED), with it a system library (GREEN).
    """
    path.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        + _file(":fld", "/usr/bin/ld", "ld", "1" * 40)
        + _file(":fmain", "/w/main.c", "main.c", "2" * 40)
        + _file(":flibc", LIBC, "libc.so.6", "3" * 40)
        + _file(":fapp", "/w/dist/app", "app", _blob(APP))
        + ":pld a b:process .\n:pld b:executable :fld .\n"
        + ":pld b:reads :fmain .\n:pld b:reads :flibc .\n:pld b:writes :fapp .\n"
    )
    return path


def _blob(data: bytes) -> str:
    import hashlib
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


DPKG_DUMP = (
    f"{LIBC}\tlibc6\tlibc6_2.39-0ubuntu8_amd64\n"
    "/usr/bin/ld\tbinutils\tbinutils_2.42-4ubuntu2_amd64\n"
    "/usr/bin/vim\tvim\tvim_2:9.1.0016-1ubuntu7_amd64\n"
)
RPM_DUMP = (
    "/lib64/libc.so.6\tglibc\tglibc-2.38-alt1.x86_64\n"
    "/usr/bin/ld\tbinutils\tbinutils-2.41-alt1.x86_64\n"
)


def _bundle(tmp_path: Path, manifest: dict[str, str], payload: str | None = None,
            packages: str | None = DPKG_DUMP) -> Path:
    root = tmp_path / "bundle"
    root.mkdir()
    base = {"format": "1", "collector": "brec-collect test", "hash": "sha1",
            "pkgdb": "dpkg", "payload": "absent", "build_status": "0"}
    base.update(manifest)
    (root / "MANIFEST").write_text("".join(f"{k}={v}\n" for k, v in base.items()))
    _trace(root / "trace.out")
    if packages is not None:
        (root / "packages.tsv").write_text(packages)
    if payload is not None:
        (root / "payload.tsv").write_text(payload)
    (root / "env.txt").write_text("# os-release\nID=ubuntu\n")
    return root


def _run(bundle: Path, **kw) -> int:
    return analyze.run(Namespace(bundle=bundle, json=kw.get("json"),
                                 fail_on=kw.get("fail_on", "grey")))


# ── dpkg backend and dump detection ──────────────────────────────────────────

def test_dpkg_backend_splits_version_and_arch(tmp_path):
    dump = tmp_path / "packages.tsv"
    dump.write_text(DPKG_DUMP)
    b = DpkgBackend(namespace="ubuntu")
    b.build_index(dump)

    ref = b.lookup(LIBC, "")
    assert (ref.backend, ref.name, ref.version, ref.arch) == \
        ("dpkg", "libc6", "2.39-0ubuntu8", "amd64")
    assert ref.purl == "pkg:deb/ubuntu/libc6@2.39-0ubuntu8?arch=amd64"
    # The epoch colon is percent-encoded in a purl.
    assert b.lookup("/usr/bin/vim", "").purl == \
        "pkg:deb/ubuntu/vim@2%3A9.1.0016-1ubuntu7?arch=amd64"


def test_dpkg_backend_indexes_both_alias_forms(tmp_path):
    dump = tmp_path / "packages.tsv"
    dump.write_text("/lib/x86_64-linux-gnu/libm.so.6\tlibc6\tlibc6_2.39-0ubuntu8_amd64\n")
    b = DpkgBackend()
    b.build_index(dump)
    assert b.lookup("/usr/lib/x86_64-linux-gnu/libm.so.6", "") is not None


@pytest.mark.parametrize("text, cls", [(DPKG_DUMP, DpkgBackend), (RPM_DUMP, RpmBackend)])
def test_a_dump_is_read_only_by_its_own_backend(tmp_path, text, cls):
    """Same three columns for both: loading a dpkg dump as rpm would label
    every file with the wrong package manager."""
    dump = tmp_path / "packages.tsv"
    dump.write_text(text)
    found = detect_backends(dump)
    assert [type(b) for b in found] == [cls]


# ── payload.tsv in brec verdict ──────────────────────────────────────────────

def test_payload_manifest_carries_the_hash(tmp_path):
    lst = tmp_path / "payload.tsv"
    lst.write_text(f"{_blob(APP)}\tbin/app\n")
    assert pv.collect_payload(lst) == [("bin/app", None, _blob(APP))]


def test_payload_manifest_matches_without_the_files(tmp_path):
    """The payload is gone with the CI container; its hashes are enough."""
    out = _trace(tmp_path / "t.out")
    lst = tmp_path / "payload.tsv"
    lst.write_text(f"{_blob(APP)}\tbin/app\n{_blob(b'other')}\tbin/stray\n")
    dump = tmp_path / "packages.tsv"
    dump.write_text(DPKG_DUMP)
    rep = pv.compute_verdict(parse_out(out), [], detect_backends(dump),
                             payload=pv.collect_payload(lst))
    by_path = {e.path: e for e in rep.payload_entries}
    assert by_path["bin/app"].status == "green"
    assert by_path["bin/stray"].status == "grey"
    assert "without being observed" in by_path["bin/stray"].reason
    assert rep.payload.total == 2


def test_payload_manifest_in_the_other_digest_is_not_blamed_on_the_build(tmp_path):
    out = _trace(tmp_path / "t.out")
    lst = tmp_path / "payload.tsv"
    lst.write_text(f"{'a' * 64}\tbin/app\n")
    rep = pv.compute_verdict(parse_out(out), [], [], payload=pv.collect_payload(lst))
    assert "hashed with sha256" in rep.payload_entries[0].reason


# ── brec analyze ─────────────────────────────────────────────────────────────

def test_analyze_uses_the_bundled_package_database(tmp_path, capsys):
    root = _bundle(tmp_path, {"payload": "present", "payload_files": "1"},
                   payload=f"{_blob(APP)}\tdist/app\n")
    assert _run(root) == 0
    assert "GREEN" in capsys.readouterr().out


def test_analyze_without_packages_gives_the_same_verdict(tmp_path):
    """libc.so.6 is a shared object: not code in the output, with or without
    a package database to name its owner."""
    root = _bundle(tmp_path, {"pkgdb": "none", "payload": "present"},
                   payload=f"{_blob(APP)}\tdist/app\n", packages=None)
    assert _run(root) == 0


def test_analyze_reads_a_tarball_and_ignores_foreign_members(tmp_path, capsys):
    root = _bundle(tmp_path, {"payload": "present"}, payload=f"{_blob(APP)}\tdist/app\n")
    tgz = tmp_path / "bundle.tar.gz"
    with tarfile.open(tgz, "w:gz") as tar:
        for name in ("MANIFEST", "trace.out", "packages.tsv", "payload.tsv", "env.txt"):
            tar.add(root / name, arcname=name)
        evil = tarfile.TarInfo("../escaped.txt")
        evil.size = 3
        tar.addfile(evil, io.BytesIO(b"bad"))
    assert _run(tgz) == 0
    assert not (tmp_path / "escaped.txt").exists()


def test_analyze_missing_payload_is_never_green(tmp_path):
    root = _bundle(tmp_path, {"payload": "missing", "payload_root": "/w/dist"})
    assert _run(root) == 3
    assert _run(root, fail_on="red") == 0


def test_analyze_refuses_an_unknown_format(tmp_path, capsys):
    root = _bundle(tmp_path, {"format": "99"})
    assert _run(root) == 2
    assert "format" in capsys.readouterr().err


def test_analyze_writes_the_manifest_into_the_json(tmp_path):
    import json
    root = _bundle(tmp_path, {"payload": "present"}, payload=f"{_blob(APP)}\tdist/app\n")
    out = tmp_path / "v.json"
    _run(root, json=out)
    doc = json.loads(out.read_text())
    assert doc["verdict"] == "GREEN"
    assert doc["bundle"]["pkgdb"] == "dpkg"


# ── what counts as a shared object ───────────────────────────────────────────

@pytest.mark.parametrize("name, so", [
    ("libc.so.6", True), ("libz.so", True), ("libstdc++.so.6.0.33", True),
    ("ld.so.cache", False), ("ld.so.conf", False),
    ("libz.so.1.3.1.debug", False), ("libstdc++.so.6.0.33-gdb.py", False),
])
def test_shared_object_names(name, so):
    from brec.classify import is_shared_object_name
    assert is_shared_object_name(name) is so


def test_loader_cache_is_not_a_prebuilt(tmp_path):
    """Every process reads /etc/ld.so.cache, and no Debian package owns it.
    Taken for a shared object by its name, it made every output on a dpkg
    image RED."""
    root = _bundle(tmp_path, {"payload": "present"}, payload=f"{_blob(APP)}\tdist/app\n")
    trace = root / "trace.out"
    trace.write_text(
        trace.read_text()
        + _file(":fcache", "/etc/ld.so.cache", "ld.so.cache", "4" * 40)
        + ":pld b:reads :fcache .\n"
    )
    assert _run(root) == 0
