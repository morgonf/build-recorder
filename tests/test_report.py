"""Tests for `brec report`, the summary that used to run on rdflib.

The queries moved from SPARQL to brec.model; these pin the answers that moved
with them, in particular the ones where RDF set semantics and a Python list
disagree (a repeated read is one triple but two list entries) and the ones a
set-ordered graph used to make unreproducible.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from brec.commands import report as rp
from brec.model import parse_out

GOLDEN_DIR = Path(__file__).parent / "golden"


def _file(uri: str, abspath: str, digest: str = "") -> str:
    out = f"{uri} a b:file .\n{uri} b:abspath \"{abspath}\" .\n"
    if digest:
        out += f"{uri} b:hash \"{digest}\" .\n"
    return out


# A build with: one shell that execs three programs in turn, a compiler that
# reads the same header twice, a linker producing a library, a system .so that
# nothing here built, and a temp file renamed into place.
OUT = (
    "@prefix : <http://build-recorder.org/data#> .\n"
    "@prefix b: <http://build-recorder.org/rdf#> .\n"
    + _file(":fsh", "/bin/sh")
    + _file(":fwrap", "/usr/bin/gcc_wrapper")
    + _file(":fcc1", "/usr/libexec/cc1")
    + _file(":fld", "/usr/bin/ld")
    + _file(":fmainc", "/root/RPM/BUILD/proj-1.0/src/main.c", "a" * 40)
    + _file(":fhdr", "/usr/include/stdio.h")
    + _file(":fmaino", "/root/RPM/BUILD/proj-1.0/src/main.o", "b" * 40)
    + _file(":flibc", "/usr/lib64/libc.so.6", "c" * 40)
    + _file(":flib", "/root/RPM/BUILD/proj-1.0/libproj.so", "d" * 40)
    + _file(":ftmp", "/root/RPM/BUILD/proj-1.0/libproj.so.tmp", "d" * 40)
    + ":p0 a b:process .\n:p0 b:pid 1 .\n:p0 b:cmd \"make\" .\n"
    + ":p0 b:start \"2026-01-01T10:00:00Z\" .\n:p0 b:end \"2026-01-01T10:00:30Z\" .\n"
    + ":p0 b:executable :fsh .\n:p0 b:executable :fwrap .\n:p0 b:executable :fcc1 .\n"
    + ":p0 b:creates :p1 .\n"
    # the compiler reads main.c once and stdio.h twice: one RDF triple each
    + ":p1 a b:process .\n:p1 b:pid 2 .\n:p1 b:cmd \"cc1 main.c\" .\n"
    + ":p1 b:start \"2026-01-01T10:00:05Z\" .\n:p1 b:end \"2026-01-01T10:00:20Z\" .\n"
    + ":p1 b:executable :fcc1 .\n"
    + ":p1 b:reads :fmainc .\n:p1 b:reads :fhdr .\n:p1 b:reads :fhdr .\n"
    + ":p1 b:writes :fmaino .\n"
    + ":p2 a b:process .\n:p2 b:pid 3 .\n:p2 b:cmd \"ld\" .\n"
    + ":p2 b:executable :fld .\n"
    + ":p2 b:reads :fmaino .\n:p2 b:reads :flibc .\n:p2 b:writes :ftmp .\n"
    + ":p2 b:rename _:rename0 .\n"
    + "_:rename0 b:rename-from :ftmp .\n"
    + "_:rename0 b:rename-to :flib .\n"
)


@pytest.fixture
def graph(tmp_path):
    out = tmp_path / "proj-build.out"
    out.write_text(OUT, encoding="utf-8")
    return parse_out(out)


# ── Counting ─────────────────────────────────────────────────────────────────

def test_stats_counts_distinct_read_edges(graph, capsys):
    """A file read twice by one process is one edge, as it was one RDF triple."""
    rp.stats(graph)
    out = capsys.readouterr().out
    assert "Чтений (reads)                 4" in out       # main.c, stdio.h, main.o, libc
    assert "Записей (writes)               2" in out
    assert "Переименований                 1" in out
    assert "Создано подпроцессов           1" in out


def test_every_exec_counts_as_an_invocation(graph):
    counts = rp.executable_counts(graph)
    assert counts["/bin/sh"] == 1
    assert counts["/usr/bin/gcc_wrapper"] == 1
    assert counts["/usr/libexec/cc1"] == 2      # p0 exec'd it, and p1 ran it
    assert counts["/usr/bin/ld"] == 1


def test_ties_are_broken_by_name_not_by_run(graph):
    """Equal counts must come out in a fixed order, or two runs disagree."""
    assert rp.by_count({"b": 2, "a": 2, "c": 5}) == [("c", 5), ("a", 2), ("b", 2)]


# ── Time ─────────────────────────────────────────────────────────────────────

def test_build_span_spans_all_processes(graph):
    begin, finish, seconds = rp.build_span(graph)
    assert (begin, finish) == ("2026-01-01T10:00:00Z", "2026-01-01T10:00:30Z")
    assert seconds == 30


def test_timeline_survives_a_timestamp_without_z(tmp_path, capsys):
    """The old report died with ValueError on any format but the tracer's."""
    out = tmp_path / "odd.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":p0 a b:process .\n:p0 b:pid 1 .\n:p0 b:cmd \"x\" .\n"
        ":p0 b:start \"2024-01-15T10:00:00\" .\n:p0 b:end \"2024-01-15T10:05:00\" .\n",
        encoding="utf-8",
    )
    rp.timeline(parse_out(out))
    printed = capsys.readouterr().out
    assert "2024-01-15T10:00:00" in printed
    assert "300 секунд" in printed


def test_duration_of_a_build_longer_than_a_day(tmp_path):
    out = tmp_path / "long.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":p0 a b:process .\n:p0 b:pid 1 .\n:p0 b:cmd \"x\" .\n"
        ":p0 b:start \"2026-01-01T00:00:00Z\" .\n:p0 b:end \"2026-01-02T01:00:00Z\" .\n",
        encoding="utf-8",
    )
    assert rp.build_span(parse_out(out))[2] == 25 * 3600


# ── What the build did and did not produce ───────────────────────────────────

def test_externals_are_what_the_build_never_wrote(graph):
    assert rp.unwritten_executables(graph) == [
        "/bin/sh", "/usr/bin/gcc_wrapper", "/usr/bin/ld", "/usr/libexec/cc1",
    ]
    assert rp.system_libs(graph) == [("/usr/lib64/libc.so.6", "c" * 40)]


def test_produced_libs_include_the_renamed_artifact(graph):
    """ld wrote a temp and renamed it into place; both are the build's output.

    Counting only b:writes named the temp and dropped libproj.so itself, which
    is the file the build actually produced.
    """
    assert rp.produced_libs(graph) == [
        ("/root/RPM/BUILD/proj-1.0/libproj.so", "d" * 40),
        ("/root/RPM/BUILD/proj-1.0/libproj.so.tmp", "d" * 40),
    ]


def test_project_sources_come_from_the_build_tree(graph):
    assert rp.project_sources(graph, ("/BUILD/",)) == [
        "/root/RPM/BUILD/proj-1.0/src/main.c",
    ]


def test_headers_counted_per_reading_process(graph):
    assert rp.header_counts(graph) == [("/usr/include/stdio.h", 1)]


def test_process_roots_exclude_created_children(graph):
    assert [p.uri for p in rp.process_roots(graph)] == [":p0", ":p2"]


# ── Package provenance ───────────────────────────────────────────────────────

def test_packages_needs_enrichment(graph, capsys):
    rp.packages(graph)
    assert "Данные о пакетах недоступны" in capsys.readouterr().out


def test_packages_reads_enriched_fields(tmp_path, capsys):
    out = tmp_path / "enriched.out"
    out.write_text(
        OUT
        + ":flibc\n"
        + "    b:dep_type \"dynamic_lib\" ;\n"
        + "    b:rpm_name \"glibc\" ;\n"
        + "    b:rpm_package \"glibc-2.38-alt1.x86_64\" .\n",
        encoding="utf-8",
    )
    rp.packages(parse_out(out))
    printed = capsys.readouterr().out
    assert "dynamic_lib" in printed
    assert "glibc" in printed
    assert "libc.so.6" in printed


# ── The whole Markdown report ────────────────────────────────────────────────

_NORM = re.compile(r"Сгенерировано: .*|Источник: .*")


def test_markdown_report_golden(graph, tmp_path):
    got = _NORM.sub("<normalised>", rp.generate_report(graph, tmp_path / "proj-build.out"))
    golden = GOLDEN_DIR / "report.md"
    if not golden.exists():                      # first run writes the baseline
        golden.write_text(got, encoding="utf-8")
    assert got == golden.read_text(encoding="utf-8")


# ── Structural: the dependency is gone ───────────────────────────────────────

def test_no_module_imports_rdflib() -> None:
    package = Path(__file__).parent.parent / "brec"
    offenders = [
        path.relative_to(package.parent)
        for path in package.rglob("*.py")
        if re.search(r"^\s*(import|from)\s+rdflib", path.read_text(encoding="utf-8"), re.M)
    ]
    assert offenders == []
