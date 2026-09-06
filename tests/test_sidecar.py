"""Tests for the provenance sidecar: attribution kept beside the trace.

The point of the sidecar is that the trace stays as the tracer wrote it, so
these check both halves: what the sidecar says, and that pairing one with the
wrong trace is noticed instead of silently attributing packages to unrelated
files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from brec.ir import SCHEMA_VERSION, IRDocument
from brec.model import parse_out
from brec.provenance import sidecar
from brec.provenance.rpm import RpmBackend

FIXTURES = Path(__file__).parent / "fixtures"
TRACE = FIXTURES / "enrich_test.out"
DUMP = FIXTURES / "enrich_rpm_dump.txt"


@pytest.fixture
def backend():
    b = RpmBackend()
    b.build_index(DUMP)
    return b


@pytest.fixture
def doc(backend):
    return sidecar.build(parse_out(TRACE), [backend], source_out=TRACE, env_dump=DUMP)


def test_default_path_sits_next_to_the_trace():
    assert sidecar.default_path(Path("/o/civetweb-build.out")) == \
        Path("/o/civetweb-build.provenance.json")


def test_document_is_a_versioned_envelope(doc):
    assert doc.schema_version == SCHEMA_VERSION
    assert doc.stage == "provenance"
    assert doc.payload["backends"] == ["rpm"]
    assert doc.payload["trace_files"] == 5


def test_apply_fills_the_graph(doc):
    graph = parse_out(TRACE)
    assert graph.files[":f2"].pkg_name == ""          # nothing in the trace itself

    stats = sidecar.apply(graph, doc)

    assert stats.annotated == 5
    assert not stats.suspicious
    node = graph.files[":f2"]
    assert (node.pkg_backend, node.pkg_name) == ("rpm", "glibc")
    assert node.pkg_version == "glibc-2.33-alt1.x86_64"
    assert node.dep_type == "dynamic_lib"
    # the rpm_* names most of the codebase still reads
    assert (node.rpm_name, node.rpm_nevra) == ("glibc", "glibc-2.33-alt1.x86_64")


def test_round_trip_through_json(doc, tmp_path):
    path = tmp_path / "p.json"
    doc.dump(path)
    graph = parse_out(TRACE)
    assert sidecar.apply(graph, sidecar.load(path)).annotated == 5


def test_a_sidecar_for_another_trace_is_reported(doc, tmp_path):
    """Same URIs, different files: applying it blind would mislabel everything."""
    other = tmp_path / "other.out"
    other.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f1 a b:file .\n:f1 b:abspath \"/somewhere/else/main.c\" .\n"
        ":f9 a b:file .\n:f9 b:abspath \"/usr/include/stdio.h\" .\n",
        encoding="utf-8",
    )
    graph = parse_out(other)

    stats = sidecar.apply(graph, doc)

    assert stats.annotated == 0
    assert stats.path_mismatch == 1        # :f1 is a different file here
    assert stats.unknown_uri == 4          # :f2..:f5 are not in this trace
    assert stats.suspicious
    assert graph.files[":f1"].pkg_name == ""


def test_load_rejects_a_document_of_another_stage(tmp_path):
    path = tmp_path / "graph.json"
    IRDocument(schema_version=SCHEMA_VERSION, stage="graph",
               source_out="x.out", payload={}).dump(path)
    with pytest.raises(ValueError, match="expected 'provenance'"):
        sidecar.load(path)


def test_read_graph_picks_up_the_neighbouring_sidecar(tmp_path, backend):
    trace = tmp_path / "build.out"
    trace.write_bytes(TRACE.read_bytes())
    sidecar.build(parse_out(trace), [backend], source_out=trace,
                  env_dump=DUMP).dump(sidecar.default_path(trace))

    graph, stats = sidecar.read_graph(trace)

    assert stats.annotated == 5
    assert graph.files[":f5"].rpm_name == "gcc"


def test_read_graph_without_a_sidecar_says_so(tmp_path):
    trace = tmp_path / "build.out"
    trace.write_bytes(TRACE.read_bytes())
    graph, stats = sidecar.read_graph(trace)
    assert stats is None
    assert graph.files[":f5"].rpm_name == ""


def test_a_named_sidecar_that_is_missing_is_an_error(tmp_path):
    trace = tmp_path / "build.out"
    trace.write_bytes(TRACE.read_bytes())
    with pytest.raises(FileNotFoundError):
        sidecar.read_graph(trace, tmp_path / "nope.json")


def test_sidecar_wins_over_triples_written_into_the_trace(tmp_path, backend):
    """Both can be present on an old trace; the explicit, newer one decides."""
    trace = tmp_path / "build.out"
    trace.write_text(
        TRACE.read_text(encoding="utf-8")
        + ":f2\n"
        + '    b:rpm_name "stale-package" ;\n'
        + '    b:rpm_package "stale-package-0.1-alt1.x86_64" ;\n'
        + '    b:dep_type "system_runtime" .\n',
        encoding="utf-8",
    )
    assert parse_out(trace).files[":f2"].rpm_name == "stale-package"

    sidecar.build(parse_out(TRACE), [backend], source_out=trace,
                  env_dump=DUMP).dump(sidecar.default_path(trace))
    graph, _ = sidecar.read_graph(trace)

    assert graph.files[":f2"].rpm_name == "glibc"
    assert graph.files[":f2"].dep_type == "dynamic_lib"


def test_files_no_package_owns_still_get_an_entry(doc):
    """"No package owns this" is an answer, and it is what marks a source file."""
    entry = doc.payload["files"][":f3"]
    assert entry["dep_type"] == "project_source"
    assert "pkg_name" not in entry


def test_json_is_deterministic(doc, tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    doc.dump(a)
    doc.dump(b)
    assert a.read_bytes() == b.read_bytes()
    assert json.loads(a.read_text())["stage"] == "provenance"
