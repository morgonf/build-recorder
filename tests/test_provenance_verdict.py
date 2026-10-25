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


def test_lineage_survives_a_cycle(tmp_path):
    """A file on its own lineage must not hide what the cycle read.

    Cargo and Go builds do this constantly: a file is written, read back and
    written again, so its lineage passes through itself.  Walking recursively
    and stopping at the second visit answered per walk-path rather than per
    file, and the cached answer then depended on the order files were walked
    in.  Here the prebuilt archive is reachable only through the cycle: if the
    walk truncates, the artifact comes out GREEN and the prebuilt is missed.
    """
    out = tmp_path / "cycle.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        + _file(":fpre", "/opt/pre/libvendor.a", "libvendor.a")
        + _file(":fa", "/home/u/proj/build/a.o", "a.o")
        + _file(":fb", "/home/u/proj/build/b.o", "b.o")
        + _file(":fapp", "/home/u/proj/build/app", "app")
        # a.o and b.o each read the other: a two-file cycle
        + ":pa a b:process .\n:pa b:reads :fb .\n:pa b:reads :fpre .\n:pa b:writes :fa .\n"
        + ":pb a b:process .\n:pb b:reads :fa .\n:pb b:writes :fb .\n"
        # the shipped artifact is produced from one side of the cycle only
        + ":pld a b:process .\n:pld b:reads :fb .\n:pld b:writes :fapp .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()])

    by_art = {f.artifact: f for f in rep.findings}
    assert by_art["/home/u/proj/build/app"].verdict == "RED"
    assert "/opt/pre/libvendor.a" in by_art["/home/u/proj/build/app"].foreign_leaves


def test_cycle_lineage_does_not_depend_on_where_the_walk_starts(tmp_path):
    """Every file in a cycle gets the same lineage, so order cannot change it."""
    out = tmp_path / "cycle2.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        + _file(":fsrc", "/home/u/proj/main.c", "main.c")
        + _file(":fa", "/home/u/proj/build/a.o", "a.o")
        + _file(":fb", "/home/u/proj/build/b.o", "b.o")
        + ":pa a b:process .\n:pa b:reads :fb .\n:pa b:reads :fsrc .\n:pa b:writes :fa .\n"
        + ":pb a b:process .\n:pb b:reads :fa .\n:pb b:writes :fb .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()])

    # Neither is GREY: the source both of them ultimately come from is visible
    # from either end of the cycle.
    assert rep.grey == 0
    assert rep.green == 2


def test_unattributed_content_at_a_written_path_is_grey_not_red(tmp_path):
    """Content nobody was seen writing, at a path the build did write.

    The tracer hashes a file opened for writing at close(), so when two threads
    hold one path open, the hash recorded for one write is what the other left
    and the intermediate state a reader saw belongs to no write node.  Go's
    build cache does this on every build.  Such an orphan is not a prebuilt
    from outside: the build was writing that path.  It is not clean either.
    """
    out = tmp_path / "orphan.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        + _file(":fsrc", "/home/u/proj/main.go", "main.go")
        # two nodes for one cache path: one written here, one only ever read
        + _file(":fcache1", "/tmp/go-build1/b010/_pkg_.a", "_pkg_.a")
        + _file(":fcache2", "/tmp/go-build1/b010/_pkg_.a", "_pkg_.a")
        + _file(":fbin", "/home/u/proj/bin/app", "app")
        + ":pw a b:process .\n:pw b:reads :fsrc .\n:pw b:writes :fcache1 .\n"
        + ":pld a b:process .\n:pld b:reads :fcache2 .\n:pld b:writes :fbin .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()])

    finding = {f.artifact: f for f in rep.findings}["/home/u/proj/bin/app"]
    assert finding.verdict == "GREY"
    assert finding.unattributed_leaves == ["/tmp/go-build1/b010/_pkg_.a"]
    assert finding.foreign_leaves == []
    assert rep.red == 0


def test_same_shape_at_a_path_the_build_never_wrote_stays_red(tmp_path):
    """The softening is bounded by the path: an outside binary is still RED."""
    out = tmp_path / "outside.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        + _file(":fsrc", "/home/u/proj/main.go", "main.go")
        + _file(":fpre", "/opt/vendor/libthing.a", "libthing.a")
        + _file(":fbin", "/home/u/proj/bin/app", "app")
        + ":pld a b:process .\n:pld b:reads :fsrc .\n:pld b:reads :fpre .\n"
        + ":pld b:writes :fbin .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()])

    finding = {f.artifact: f for f in rep.findings}["/home/u/proj/bin/app"]
    assert finding.verdict == "RED"
    assert finding.foreign_leaves == ["/opt/vendor/libthing.a"]


def test_writes_to_dev_null_are_not_produced_files(tmp_path):
    """A build that only wrote to /dev/null produced nothing to judge."""
    out = tmp_path / "devnull.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        + _file(":fnull", "/dev/null", "null")
        + _file(":fproc", "/proc/self/oom_score_adj", "oom_score_adj")
        + ":pconf a b:process .\n:pconf b:writes :fnull .\n"
        + ":ptune a b:process .\n:ptune b:writes :fproc .\n"
    )
    rep = pv.compute_verdict(parse_out(out), [], [StubBackend()])

    assert rep.produced == 0
    assert rep.findings == []
    assert rep.verdict == "GREEN"


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


def test_the_verdict_does_not_depend_on_packages(out_file):
    """Package attribution used to be the trust criterion: without it the
    system libc.so.6 was a foreign binary and every output RED.  A shared
    object is not code copied into the output, and where a prebuilt came from
    decides nothing now, so the verdict is the same with or without packages."""
    graph = parse_out(out_file)
    copies = pv.parse_copies(out_file)
    bare = pv.compute_verdict(graph, copies, [])
    labelled = pv.compute_verdict(parse_out(out_file), copies, [StubBackend()])
    assert [(f.artifact, f.verdict, f.foreign_leaves) for f in bare.findings] == \
        [(f.artifact, f.verdict, f.foreign_leaves) for f in labelled.findings]
    assert "/home/u/proj/build/app" not in {f.artifact for f in bare.findings}


# ── Prebuilt objects, whoever packaged them ───────────────────────────────────

def _link_out(tmp_path, *leaves: str, copied: str | None = None) -> Path:
    """cc1 compiles main.c to main.o (reading its own libgmp on the way), ld
    links main.o and *leaves* into app; optionally *copied* is hardlinked into
    the output tree as a second shipped file."""
    text = (
        "@prefix : <http://build-recorder.org/data#> .\n"
        + _file(":fcc1", "/usr/libexec/gcc/cc1", "cc1")
        + _file(":fgmp", "/usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0", "libgmp.so.10.5.0")
        + _file(":fld", "/usr/bin/ld", "ld")
        + _file(":fmain", "/home/u/proj/main.c", "main.c")
        + _file(":fmaino", "/home/u/proj/main.o", "main.o")
        + _file(":fapp", "/home/u/proj/app", "app")
        + ":pcc a b:process .\n:pcc b:executable :fcc1 .\n"
        + ":pcc b:reads :fmain .\n:pcc b:reads :fgmp .\n:pcc b:writes :fmaino .\n"
        + ":pld a b:process .\n:pld b:executable :fld .\n:pld b:reads :fmaino .\n"
        + ":pld b:writes :fapp .\n"
    )
    for i, leaf in enumerate(leaves):
        text += _file(f":fl{i}", leaf, Path(leaf).name) + f":pld b:reads :fl{i} .\n"
    if copied:
        text += (_file(":fsrc", copied, Path(copied).name)
                 + _file(":fdst", "/home/u/proj/dist/" + Path(copied).name, Path(copied).name)
                 + "_:hardlink0 b:hardlink-from :fsrc .\n_:hardlink0 b:hardlink-to :fdst .\n")
    p = tmp_path / "link.out"
    p.write_text(text)
    return p


def _verdict(p: Path, **kw):
    return pv.compute_verdict(parse_out(p), pv.parse_copies(p), [StubBackend()], **kw)


def test_a_packaged_static_archive_is_a_prebuilt(tmp_path):
    """libz.a from a -devel package is code nobody compiled in this build.
    The package is reported, and decides nothing."""
    rep = _verdict(_link_out(tmp_path, "/usr/lib/x86_64-linux-gnu/libz.a"))
    assert rep.verdict == "RED"
    (f,) = [f for f in rep.findings if f.artifact.endswith("/app")]
    assert f.foreign_leaves == ["/usr/lib/x86_64-linux-gnu/libz.a"]
    assert rep.prebuilt_packages["/usr/lib/x86_64-linux-gnu/libz.a"] == "glibc-2.38"


def test_the_toolchain_runtime_is_listed_not_red(tmp_path):
    out = _link_out(tmp_path, "/usr/lib/x86_64-linux-gnu/Scrt1.o",
                    "/usr/lib/gcc/x86_64-linux-gnu/13/libgcc.a",
                    "/usr/lib/x86_64-linux-gnu/libc_nonshared.a")
    rep = _verdict(out)
    assert rep.verdict == "GREEN"
    assert sorted(Path(p).name for p in rep.runtime) == \
        ["Scrt1.o", "libc_nonshared.a", "libgcc.a"]
    # --strict: the literal answer to "is there any prebuilt object in it".
    assert _verdict(out, runtime=[]).verdict == "RED"


def test_allow_extends_the_exemption(tmp_path):
    out = _link_out(tmp_path, "/opt/sdk/lib/libvendor.a")
    assert _verdict(out).verdict == "RED"
    rep = _verdict(out, runtime=list(pv.DEFAULT_RUNTIME) + ["/opt/sdk/*"])
    assert rep.verdict == "GREEN"
    assert "/opt/sdk/lib/libvendor.a" in rep.runtime


def test_a_shared_object_linked_against_is_not_incorporated(tmp_path):
    """Read by ld it is a reference; cc1's own libgmp is cc1's code."""
    rep = _verdict(_link_out(tmp_path, "/opt/pre/libthing.so.1"), runtime=[])
    assert rep.verdict == "GREEN"


def test_a_shared_object_copied_into_the_output_is_shipped_prebuilt(tmp_path):
    rep = _verdict(_link_out(tmp_path, copied="/usr/lib/x86_64-linux-gnu/libfoo.so.1"))
    assert rep.verdict == "RED"
    (f,) = [f for f in rep.findings if f.artifact.endswith("dist/libfoo.so.1")]
    assert f.foreign_leaves == ["/usr/lib/x86_64-linux-gnu/libfoo.so.1"]


def test_rust_standard_library_is_toolchain_runtime(tmp_path):
    std = "/usr/lib/rustlib/x86_64-unknown-linux-gnu/lib/libstd-6f17d22bba15001f.rlib"
    rep = _verdict(_link_out(tmp_path, std))
    assert rep.verdict == "GREEN"
    assert std in rep.runtime


def test_a_go_syso_is_a_prebuilt(tmp_path):
    """Go links a package's .syso objects in as they are, without cgo."""
    rep = _verdict(_link_out(tmp_path, "/home/u/proj/planted_amd64.syso"))
    assert rep.verdict == "RED"


def test_a_warm_go_build_cache_is_a_prebuilt(tmp_path):
    """A compiled package the linker takes from GOCACHE was compiled outside
    this trace: to the trace it is a prebuilt, named or not."""
    entry = "/root/.cache/go-build/02/" + "026ea442" * 8 + "-d"
    rep = _verdict(_link_out(tmp_path, entry))
    assert rep.verdict == "RED"
    (f,) = [f for f in rep.findings if f.artifact.endswith("/app")]
    assert f.foreign_leaves == [entry]
    assert "GOCACHE" in f.reason
    # The action records beside it are not code.
    assert not pv.is_binary("/root/.cache/go-build/02/" + "026ea442" * 8 + "-a")


def _hashed(uri, abspath, sha):
    return (f"{uri} a b:file .\n{uri} b:abspath \"{abspath}\" .\n"
            f"{uri} b:name \"{Path(abspath).name}\" .\n{uri} b:hash \"{sha}\" .\n")


def _reread_out(tmp_path, write_first: bool) -> Path:
    """go writes _pkg_.a and reads the same bytes back through a second node;
    link turns it into app.  *write_first* puts the write node before the
    read, as when the file is read while still open for writing."""
    pkg = "/tmp/go-build1/b027/_pkg_.a"
    w = _hashed(":fw", pkg, "5c" * 20)
    r = _hashed(":fr", pkg, "5c" * 20)
    text = (
        "@prefix : <http://build-recorder.org/data#> .\n"
        + _file(":fsrc", "/home/u/proj/main.go", "main.go")
        + _file(":fapp", "/home/u/proj/app", "app")
        + (w + r if write_first else r + w)
        + ":pgo a b:process .\n:pgo b:reads :fsrc .\n:pgo b:writes :fw .\n"
        + ":pgo b:reads :fr .\n"
        + ":pld a b:process .\n:pld b:reads :fr .\n:pld b:writes :fapp .\n"
    )
    p = tmp_path / "reread.out"
    p.write_text(text)
    return p


def test_reading_back_an_open_write_is_the_write(tmp_path):
    rep = _verdict(_reread_out(tmp_path, write_first=True))
    assert rep.verdict == "GREEN"


def test_a_prebuilt_rewritten_with_its_own_bytes_is_not_vouched_for(tmp_path):
    """Read first, then written at the same path with the same content: the
    write may be a copy of the prebuilt, so it proves nothing about it."""
    rep = _verdict(_reread_out(tmp_path, write_first=False))
    assert rep.verdict != "GREEN"


# ── Content kinds: code nobody compiled, and the programs a build runs ───────

def _kfile(uri, abspath, kind=""):
    return _file(uri, abspath, Path(abspath).name) + (
        f'{uri} b:kind "{kind}" .\n' if kind else "")


def _kinds_out(tmp_path, body: str) -> Path:
    """A trace with b:kind: cc1 and ld from /usr, main.c in the tree."""
    p = tmp_path / "kinds.out"
    p.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        + _kfile(":fcc1", "/usr/libexec/gcc/x86_64-linux-gnu/13/cc1", "elf-exec")
        + _kfile(":fld", "/usr/bin/x86_64-linux-gnu-ld.bfd", "elf-exec")
        + _kfile(":ftar", "/usr/bin/tar", "elf-dyn")
        + _kfile(":fmainc", "/home/u/proj/main.c")
        + body
    )
    return p


def _verdict_ordered(p: Path, **kw):
    return _verdict(p, io_order=pv.parse_io_order(p), **kw)


def test_an_archive_unpacked_from_a_tarball_is_a_prebuilt(tmp_path):
    """tar writes libfoo.a: to the graph a file this build produced, its whole
    lineage a gzip file.  Its content is code, and tar compiles nothing."""
    p = _kinds_out(tmp_path,
        _kfile(":ftgz", "/home/u/proj/vendor.tar.gz", "gzip")
        + _kfile(":flib", "/home/u/proj/libfoo.a", "ar")
        + _kfile(":fmaino", "/home/u/proj/main.o", "elf-rel")
        + _kfile(":fapp", "/home/u/proj/app", "elf-dyn")
        + ":ptar a b:process .\n:ptar b:executable :ftar .\n"
        + ":ptar b:reads :ftgz .\n:ptar b:writes :flib .\n"
        + ":pcc a b:process .\n:pcc b:executable :fcc1 .\n"
        + ":pcc b:reads :fmainc .\n:pcc b:writes :fmaino .\n"
        + ":pld a b:process .\n:pld b:executable :fld .\n"
        + ":pld b:reads :fmaino .\n:pld b:reads :flib .\n:pld b:writes :fapp .\n")
    rep = _verdict_ordered(p)
    assert rep.verdict == "RED"
    by = {f.artifact: f for f in rep.findings}
    assert "unpacked" in by["/home/u/proj/libfoo.a"].reason
    assert by["/home/u/proj/app"].foreign_leaves == ["/home/u/proj/libfoo.a"]
    # main.o came from cc1, from source.
    assert "/home/u/proj/main.o" not in by


def _rewrite_out(tmp_path, read_first: bool) -> Path:
    """strip opens app.stripped, reads app (linked here), and closes
    app.stripped; *read_first* puts the read before the close in the trace.
    The open comes first either way, as strip does it."""
    out = (':fout a b:file .\n:fout b:abspath "/home/u/proj/app.stripped" .\n'
           ':fout b:name "app.stripped" .\n')
    opened = ":pstrip b:writes :fout .\n"
    read = ":pstrip b:reads :fapp .\n"
    closed = ':fout b:hash "' + "0f" * 20 + '" .\n:fout b:kind "elf-dyn" .\n'
    return _kinds_out(tmp_path,
        _kfile(":fstrip", "/usr/bin/strip", "elf-exec")
        + _kfile(":fmaino", "/home/u/proj/main.o", "elf-rel")
        + _kfile(":fapp", "/home/u/proj/app", "elf-dyn")
        + ":pcc a b:process .\n:pcc b:executable :fcc1 .\n"
        + ":pcc b:reads :fmainc .\n:pcc b:writes :fmaino .\n"
        + ":pld a b:process .\n:pld b:executable :fld .\n"
        + ":pld b:reads :fmaino .\n:pld b:writes :fapp .\n"
        + ":pstrip a b:process .\n:pstrip b:executable :fstrip .\n"
        + out + opened + (read + closed if read_first else closed + read))


def test_a_rewrite_of_code_built_here_is_not_unpacking(tmp_path):
    assert _verdict_ordered(_rewrite_out(tmp_path, read_first=True)).verdict == "GREEN"


def test_code_read_after_the_write_explains_nothing(tmp_path):
    """The write was closed before anything compiled here was read."""
    rep = _verdict_ordered(_rewrite_out(tmp_path, read_first=False))
    assert rep.verdict == "RED"
    (f,) = [f for f in rep.findings if f.artifact.endswith("app.stripped")]
    assert "unpacked" in f.reason


def test_a_prebuilt_program_run_from_the_tree_taints_what_it_writes(tmp_path):
    """./gen > gen.c: the shell opened gen.c, gen wrote it through the
    descriptor it was handed (both edges are in the trace)."""
    p = _kinds_out(tmp_path,
        _kfile(":fsh", "/usr/bin/dash", "elf-dyn")
        + _kfile(":fgen", "/home/u/proj/tools/gen", "elf-dyn")
        + _kfile(":fgenc", "/home/u/proj/gen.c")
        + _kfile(":fgeno", "/home/u/proj/gen.o", "elf-rel")
        + ":psh a b:process .\n:psh b:executable :fsh .\n:psh b:writes :fgenc .\n"
        + ":pgen a b:process .\n:pgen b:executable :fgen .\n"
        + ":pgen b:reads :fmainc .\n:pgen b:writes :fgenc .\n"
        + ":pcc a b:process .\n:pcc b:executable :fcc1 .\n"
        + ":pcc b:reads :fgenc .\n:pcc b:writes :fgeno .\n")
    rep = _verdict_ordered(p)
    assert rep.verdict == "RED"
    by = {f.artifact: f for f in rep.findings}
    assert by["/home/u/proj/gen.c"].tool_leaves == ["/home/u/proj/tools/gen"]
    assert by["/home/u/proj/gen.o"].tool_leaves == ["/home/u/proj/tools/gen"]
    # Under --tool-root it is part of the toolchain.
    tc = pv.Toolchain(roots=pv.DEFAULT_TOOL_ROOTS + ("/home/u/proj/tools/*",))
    assert _verdict_ordered(p, toolchain=tc).verdict == "GREEN"


def test_a_program_built_here_passes_its_lineage_on(tmp_path):
    """gen compiled from source in this build, then run: GREEN.  The same gen
    linked with a prebuilt archive makes what it writes RED."""
    def out(extra_read: str) -> Path:
        return _kinds_out(tmp_path,
            _kfile(":fgenmain", "/home/u/proj/genmain.c")
            + _kfile(":fgeno", "/home/u/proj/genmain.o", "elf-rel")
            + _kfile(":fgen", "/home/u/proj/gen", "elf-dyn")
            + _kfile(":fpre", "/home/u/proj/third_party/libpre.a", "ar")
            + _kfile(":fout", "/home/u/proj/out.c")
            + ":pcc a b:process .\n:pcc b:executable :fcc1 .\n"
            + ":pcc b:reads :fgenmain .\n:pcc b:writes :fgeno .\n"
            + ":pld a b:process .\n:pld b:executable :fld .\n"
            + ":pld b:reads :fgeno .\n" + extra_read + ":pld b:writes :fgen .\n"
            + ":pgen a b:process .\n:pgen b:executable :fgen .\n:pgen b:writes :fout .\n")
    assert _verdict_ordered(out("")).verdict == "GREEN"
    rep = _verdict_ordered(out(":pld b:reads :fpre .\n"))
    (f,) = [f for f in rep.findings if f.artifact.endswith("out.c")]
    assert f.foreign_leaves == ["/home/u/proj/third_party/libpre.a"]


def test_an_archive_under_a_text_name_is_still_an_archive(tmp_path):
    """cp libfoo.txt libfoo.a: by name the source is text, by content code."""
    p = _kinds_out(tmp_path,
        _kfile(":fcp", "/usr/bin/cp", "elf-dyn")
        + _kfile(":ftxt", "/home/u/proj/libfoo.txt", "ar")
        + _kfile(":flib", "/home/u/proj/libfoo.a", "ar")
        + ":pcp a b:process .\n:pcp b:executable :fcp .\n"
        + ":pcp b:reads :ftxt .\n:pcp b:writes :flib .\n")
    rep = _verdict_ordered(p)
    assert rep.verdict == "RED"


def test_a_trace_without_kinds_says_what_it_cannot_check(tmp_path, out_file):
    rep = _verdict(out_file)
    assert rep.kinds_recorded is False
    assert "content kinds: not in this trace" in pv._format_report(rep, "x")
    assert rep.to_dict()["content_kinds_recorded"] is False


@pytest.mark.parametrize("exe,kind,ok", [
    ("/usr/bin/x86_64-linux-gnu-gcc-13", "elf-rel", True),
    ("/usr/bin/x86_64-alt-linux-gcc-ar-14", "ar", True),
    ("/usr/lib/llvm-18/bin/clang-18", "elf-rel", True),
    ("/usr/libexec/gcc/x86_64-linux-gnu/13/lto-wrapper", "elf-rel", True),
    ("/usr/lib/go-1.22/pkg/tool/linux_amd64/compile", "ar", True),
    ("/home/u/proj/compile", "ar", False),       # Go's names count only in GOROOT
    ("/usr/lib/jvm/java-21/bin/java", "class", True),
    ("/usr/lib/jvm/java-21/bin/java", "elf-exec", False),  # a JVM unpacking a native tool
    ("/usr/bin/tar", "ar", False),
    ("/usr/bin/curl", "elf-exec", False),
])
def test_who_may_write_code(exe, kind, ok):
    assert pv.compiler_matcher(pv.DEFAULT_COMPILERS)(exe, kind) is ok


def test_code_a_process_wrote_itself_explains_nothing(tmp_path):
    """curl writes a.so, reads it back, writes b.so: b.so was not made from
    anything compiled here, whatever curl read of its own output."""
    p = _kinds_out(tmp_path,
        _kfile(":fcurl", "/usr/bin/curl", "elf-dyn")
        + _kfile(":fa", "/home/u/proj/a.so", "elf-dyn")
        + _kfile(":fb", "/home/u/proj/b.so", "elf-dyn")
        + ":pcurl a b:process .\n:pcurl b:executable :fcurl .\n"
        + ":pcurl b:writes :fa .\n:pcurl b:reads :fa .\n:pcurl b:writes :fb .\n")
    rep = _verdict_ordered(p)
    unpacked = {f.artifact for f in rep.findings if "unpacked" in f.reason}
    assert unpacked == {"/home/u/proj/a.so", "/home/u/proj/b.so"}
