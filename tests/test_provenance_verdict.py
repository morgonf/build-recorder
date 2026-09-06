"""Tests for provenance-verdict.py — GREEN/RED/GREY built-from-source verdict."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.ir import PackageRef
from brec.model import parse_out

from brec.commands import verdict as pv


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


def test_findings_for_one_path_keep_graph_order(tmp_path):
    """Two nodes, one path: the tie must break the same way on every run.

    Findings are sorted by (verdict, artifact), so a path written more than once
    produces findings the sort cannot separate.  The sort is stable, so their
    order is the order they were appended in, which came from iterating a set
    and so differed between runs: two runs of `brec verdict` over one trace
    disagreed about which piece of evidence belonged to which line.
    """
    out = tmp_path / "twice.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        + _file(":fprea", "/opt/pre/a.a", "a.a")
        + _file(":fpreb", "/opt/pre/b.a", "b.a")
        + _file(":fout1", "/home/u/proj/build/libx.a", "libx.a")
        + _file(":fout2", "/home/u/proj/build/libx.a", "libx.a")
        + ":par1 a b:process .\n:par1 b:reads :fprea .\n:par1 b:writes :fout1 .\n"
        + ":par2 a b:process .\n:par2 b:reads :fpreb .\n:par2 b:writes :fout2 .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()])

    tied = [f for f in rep.findings if f.artifact == "/home/u/proj/build/libx.a"]
    assert [f.foreign_leaves for f in tied] == [["/opt/pre/a.a"], ["/opt/pre/b.a"]]


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


# ── Coverage gaps (io_uring) ──────────────────────────────────────────────────

GAP_TRIPLE = ':pld b:coverage_gap "io_uring" .\n'


def test_parse_coverage_gaps_dedupes_per_process_and_kind(tmp_path):
    p = tmp_path / "gap.out"
    p.write_text(OUT + GAP_TRIPLE + GAP_TRIPLE + ':pcc1 b:coverage_gap "io_uring" .\n')
    gaps = pv.parse_coverage_gaps(p)
    assert [(g.proc, g.kind) for g in gaps] == [
        (":pld", "io_uring"), (":pcc1", "io_uring"),
    ]


def test_io_uring_denies_green(tmp_path):
    """A clean build is no longer GREEN once a process used io_uring."""
    clean = "\n".join(
        ln for ln in OUT.splitlines()
        if not any(t in ln for t in (
            ":fvenda", ":fapp2", ":pld2", ":fpre", ":fplug", ":fblob",
            ":pcurl", ":pcp", "hardlink"))
    )
    p = tmp_path / "gap.out"
    p.write_text(clean + "\n" + GAP_TRIPLE)

    rep = pv.compute_verdict(parse_out(p), pv.parse_copies(p), [StubBackend()],
                             gaps=pv.parse_coverage_gaps(p))
    assert rep.verdict == "GREY"
    assert [g.kind for g in rep.coverage_gaps] == ["io_uring"]
    # the linker's output is what the gap process wrote: its lineage is no
    # longer trustworthy even though reads were observed
    by_art = {f.artifact: f for f in rep.findings}
    assert by_art["/home/u/proj/build/app"].verdict == "GREY"
    assert "io_uring" in by_art["/home/u/proj/build/app"].reason
    # main.o came from a process without a gap: still GREEN
    assert "/home/u/proj/main.o" not in by_art


def test_io_uring_gap_alone_denies_green(tmp_path):
    """Even with nothing observed written through it, a gap forbids GREEN."""
    p = tmp_path / "gap.out"
    p.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        ":px a b:process .\n"
        ':px b:cmd "helper" .\n'
        ':px b:coverage_gap "io_uring" .\n'
    )
    rep = pv.compute_verdict(parse_out(p), [], [StubBackend()],
                             gaps=pv.parse_coverage_gaps(p))
    assert rep.verdict == "GREY"
    assert rep.coverage_gaps[0].cmd == "helper"


# ── Payload closure ───────────────────────────────────────────────────────────

def _payload_out(tmp_path, app_hash: str,
                 abspath: str = "/home/u/proj/buildroot/usr/bin/app") -> Path:
    """Graph of a build that compiled main.c and linked ./app with that hash."""
    text = (
        "@prefix : <http://build-recorder.org/data#> .\n"
        + _file(":fld", "/usr/bin/ld", "ld")
        + _file(":fmainc", "/home/u/proj/main.c", "main.c")
        + ":fapp a b:file .\n"
        + f':fapp b:abspath "{abspath}" .\n'
        + ':fapp b:name "app" .\n'
        + f':fapp b:hash "{app_hash}" .\n'
        + ":pld a b:process .\n:pld b:executable :fld .\n"
        + ":pld b:reads :fmainc .\n:pld b:writes :fapp .\n"
    )
    p = tmp_path / "payload.out"
    p.write_text(text)
    return p


@pytest.fixture
def shipped(tmp_path):
    root = tmp_path / "buildroot" / "usr" / "bin"
    root.mkdir(parents=True)
    app = root / "app"
    app.write_bytes(b"\x7fELF fake binary\n")
    return root, app


def test_payload_all_observed_is_green(tmp_path, shipped):
    root, app = shipped
    out = _payload_out(tmp_path, pv.git_blob_hash(app))
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(root))
    assert rep.verdict == "GREEN"
    assert (rep.payload.total, rep.payload.green, rep.payload.grey) == (1, 1, 0)
    assert rep.fidelity == 1.0


def test_payload_file_missing_from_graph_is_grey(tmp_path, shipped):
    """The P1 case: a shipped file the trace never saw: invisible without this."""
    root, app = shipped
    (root / "stray.so").write_bytes(b"written through an unobserved channel\n")
    out = _payload_out(tmp_path, pv.git_blob_hash(app))

    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(root))
    assert rep.verdict == "GREY"
    assert (rep.payload.total, rep.payload.green, rep.payload.grey) == (2, 1, 1)
    assert rep.fidelity == 0.5
    stray = [e for e in rep.payload_entries if e.path.endswith("stray.so")][0]
    assert stray.status == "grey"
    assert "without being observed" in stray.reason


def test_payload_matches_by_hash_after_relocation(tmp_path, shipped):
    """Content match, not path match: an extracted package still verifies."""
    root, app = shipped
    out = _payload_out(tmp_path, pv.git_blob_hash(app))
    elsewhere = tmp_path / "extracted" / "usr" / "bin"
    elsewhere.mkdir(parents=True)
    (elsewhere / "app").write_bytes(app.read_bytes())

    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(elsewhere))
    assert rep.verdict == "GREEN"
    assert rep.payload.green == 1


def test_payload_content_changed_after_last_write_is_grey(tmp_path, shipped):
    """Same path as the observed write, different content: touched afterwards."""
    root, app = shipped
    out = _payload_out(tmp_path, pv.git_blob_hash(app), abspath=str(app))
    app.write_bytes(b"\x7fELF fake binary, patched afterwards\n")

    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(root))
    assert rep.verdict == "GREY"
    assert "differs from every observed version" in rep.payload_entries[0].reason


def test_payload_symlinks_are_skipped(tmp_path, shipped):
    root, app = shipped
    (root / "app-1.0").symlink_to("app")
    out = _payload_out(tmp_path, pv.git_blob_hash(app))

    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(root))
    assert rep.verdict == "GREEN"
    assert (rep.payload.total, rep.payload.symlinks) == (1, 1)


def test_payload_list_file_falls_back_to_path_check(tmp_path, shipped):
    """rpm -qpl style input: paths only, no content available locally."""
    root, app = shipped
    out = _payload_out(tmp_path, pv.git_blob_hash(app))
    lst = tmp_path / "files.list"
    lst.write_text(
        "# rpm -qpl foo.rpm\n"
        "/home/u/proj/buildroot/usr/bin/app\n"
        "/home/u/proj/buildroot/usr/lib64/libmystery.so\n"
    )

    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(lst))
    assert rep.verdict == "GREY"
    assert (rep.payload.total, rep.payload.unreadable) == (2, 2)
    by_path = {e.path: e for e in rep.payload_entries}
    assert by_path["/home/u/proj/buildroot/usr/bin/app"].status == "green"
    assert by_path["/home/u/proj/buildroot/usr/lib64/libmystery.so"].status == "grey"


def test_payload_inherits_red_from_the_output_it_ships(tmp_path):
    """A shipped file whose content is a RED output makes the package RED."""
    root = tmp_path / "buildroot"
    root.mkdir()
    plug = root / "plugin.so"
    plug.write_bytes(b"prebuilt content\n")
    h = pv.git_blob_hash(plug)
    out = tmp_path / "red.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        + _file(":fld", "/usr/bin/ld", "ld")
        + _file(":fpre", "/opt/pre/libfoo.a", "libfoo.a")
        + ":fplug a b:file .\n"
        + ':fplug b:abspath "/home/u/proj/buildroot/plugin.so" .\n'
        + ':fplug b:name "plugin.so" .\n'
        + f':fplug b:hash "{h}" .\n'
        + ":pld a b:process .\n:pld b:executable :fld .\n"
        + ":pld b:reads :fpre .\n:pld b:writes :fplug .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()],
                             payload=pv.collect_payload(root))
    assert rep.verdict == "RED"
    assert rep.payload.red == 1


def test_git_blob_hash_matches_git(tmp_path):
    f = tmp_path / "x.txt"
    f.write_bytes(b"hello\n")
    # git hash-object of "hello\n"
    assert pv.git_blob_hash(f) == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_detect_hash_algo_from_graph(tmp_path):
    """A trace made with -2/--sha256 must be hashed the same way here."""
    sha256_out = tmp_path / "sha256.out"
    sha256_out.write_text(
        ":f0 a b:file .\n"
        ':f0 b:abspath "/x" .\n'
        f':f0 b:hash "{"a" * 64}" .\n'
    )
    assert pv.detect_hash_algo(parse_out(sha256_out).files) == "sha256"
    assert pv.detect_hash_algo(parse_out(_payload_out(tmp_path, "b" * 40)).files) == "sha1"


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
