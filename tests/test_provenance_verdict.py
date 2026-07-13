"""Tests for provenance-verdict.py — GREEN/RED/GREY built-from-source verdict."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.ir import PackageRef
from brec.model import parse_out

# Load the hyphenated script as a module.
_spec = importlib.util.spec_from_file_location(
    "provenance_verdict", Path(__file__).parent.parent / "provenance-verdict.py"
)
pv = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = pv          # needed for dataclasses under importlib load
_spec.loader.exec_module(pv)


class StubBackend:
    """Marks anything under /usr or /lib* as OS-package provided."""

    def available(self) -> bool:
        return True

    def lookup(self, abspath: str, sha1: str):
        if abspath.startswith(("/usr/", "/lib/", "/lib64/", "/bin/")):
            return PackageRef(backend="rpm", name="glibc", version="glibc-2.38")
        return None


def _file(uri, abspath, name):
    return (
        f"{uri} a b:file .\n"
        f'{uri} b:abspath "{abspath}" .\n'
        f'{uri} b:name "{name}" .\n'
        f'{uri} b:hash "{uri[2:]:0<40}" .\n'
    )


# A build with: one clean app (GREEN), one app that links a vendored prebuilt
# archive (RED), a plugin hardlinked from a prebuilt .so (RED), and a blob that
# was written with no reads at all — as if downloaded (GREY).
OUT = (
    "@prefix : <http://build-recorder.org/data#> .\n"
    "@prefix b: <http://build-recorder.org/rdf#> .\n"
    + _file(":fcc1", "/usr/libexec/gcc/cc1", "cc1")
    + _file(":fld", "/usr/bin/ld", "ld")
    + _file(":fmainc", "/home/u/proj/main.c", "main.c")
    + _file(":fmaino", "/home/u/proj/main.o", "main.o")
    + _file(":flibc", "/usr/lib64/libc.so.6", "libc.so.6")
    + _file(":fapp", "/home/u/proj/build/app", "app")
    + _file(":fvenda", "/home/u/proj/third_party/foo/libfoo.a", "libfoo.a")
    + _file(":fapp2", "/home/u/proj/build/app2", "app2")
    + _file(":fpre", "/opt/pre/plugin.so", "plugin.so")
    + _file(":fplug", "/home/u/proj/build/plugin.so", "plugin.so")
    + _file(":fblob", "/home/u/proj/build/blob.bin", "blob.bin")
    # cc1: main.c -> main.o
    + ":pcc1 a b:process .\n:pcc1 b:executable :fcc1 .\n"
    + ":pcc1 b:reads :fmainc .\n:pcc1 b:writes :fmaino .\n"
    # ld: main.o + system libc -> app  (GREEN)
    + ":pld a b:process .\n:pld b:executable :fld .\n"
    + ":pld b:reads :fmaino .\n:pld b:reads :flibc .\n:pld b:writes :fapp .\n"
    # ld2: main.o + vendored prebuilt libfoo.a -> app2  (RED)
    + ":pld2 a b:process .\n:pld2 b:executable :fld .\n"
    + ":pld2 b:reads :fmaino .\n:pld2 b:reads :fvenda .\n:pld2 b:writes :fapp2 .\n"
    # curl: no reads -> blob.bin  (GREY)
    + ":pcurl a b:process .\n:pcurl b:writes :fblob .\n"
    # hardlink a prebuilt .so into the build tree  (RED)
    + ":pcp a b:process .\n:pcp b:hardlink _:hardlink0 .\n"
    + "_:hardlink0 b:hardlink-from :fpre .\n"
    + "_:hardlink0 b:hardlink-to :fplug .\n"
)


@pytest.fixture
def out_file(tmp_path) -> Path:
    p = tmp_path / "build.out"
    p.write_text(OUT)
    return p


def test_parse_copies_recovers_hardlink(out_file):
    copies = pv.parse_copies(out_file)
    assert len(copies) == 1
    assert copies[0].kind == "hardlink"
    assert copies[0].src == ":fpre"
    assert copies[0].dst == ":fplug"


def test_verdict_flags_prebuilt_binaries(out_file):
    graph = parse_out(out_file)
    copies = pv.parse_copies(out_file)
    rep = pv.compute_verdict(graph, copies, [StubBackend()])

    assert rep.verdict == "RED"
    assert rep.red == 2      # app2 (linked libfoo.a) + plugin.so (hardlinked)
    assert rep.grey == 1     # blob.bin (no lineage)
    assert rep.green == 2    # app + main.o

    by_art = {f.artifact: f for f in rep.findings}
    assert "/home/u/proj/build/app2" in by_art
    assert "/home/u/proj/third_party/foo/libfoo.a" in by_art[
        "/home/u/proj/build/app2"].foreign_leaves
    assert by_art["/home/u/proj/build/plugin.so"].verdict == "RED"
    assert "/opt/pre/plugin.so" in by_art["/home/u/proj/build/plugin.so"].foreign_leaves
    assert by_art["/home/u/proj/build/blob.bin"].verdict == "GREY"


def test_clean_build_is_green(out_file, tmp_path):
    # Keep only the clean cc1 -> ld -> app chain.
    clean = "\n".join(
        ln for ln in OUT.splitlines()
        if not any(t in ln for t in (
            ":fvenda", ":fapp2", ":pld2", ":fpre", ":fplug", ":fblob",
            ":pcurl", ":pcp", "hardlink"))
    )
    p = tmp_path / "clean.out"
    p.write_text(clean + "\n")
    rep = pv.compute_verdict(parse_out(p), pv.parse_copies(p), [StubBackend()])
    assert rep.verdict == "GREEN"
    assert rep.red == 0 and rep.grey == 0
    assert rep.fidelity == 1.0


def test_no_package_backend_flags_system_libs(out_file):
    # Without OS-package attribution, the system libc.so.6 becomes a foreign
    # binary — demonstrates why enrichment is required for a clean verdict.
    graph = parse_out(out_file)
    copies = pv.parse_copies(out_file)
    rep = pv.compute_verdict(graph, copies, [])  # no backends
    assert rep.verdict == "RED"
    # app now also flagged because libc.so.6 has no package
    by_art = {f.artifact: f for f in rep.findings}
    assert "/home/u/proj/build/app" in by_art
