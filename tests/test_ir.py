"""T0.1 acceptance tests — brec/ir.py IR dataclasses."""

import json
import tempfile
from pathlib import Path

import pytest

from brec.ir import (
    SCHEMA_VERSION,
    BuildGraph,
    FileNode,
    IRDocument,
    IRVersionError,
    ProcessNode,
)


# ── Helpers / shared fixtures ─────────────────────────────────────────────────

def make_file_node(uri: str = ":f0") -> FileNode:
    return FileNode(
        uri=uri,
        abspath="/usr/lib/libfoo.so.1",
        name="libfoo.so.1",
        size=98304,
        git_blob_sha1="da39a3ee5e6b4b0d3255bfef95601890afd80709",
    )


def make_process_node(uri: str = ":p0") -> ProcessNode:
    return ProcessNode(
        uri=uri,
        pid=42,
        cmd="gcc -o foo foo.c",
        executable=":f0",
        start="2024-01-15T10:00:00",
        end="2024-01-15T10:00:01",
        reads=[":f1", ":f2"],
        writes=[":f3"],
        execs=[":p1"],
        role="compiler",
    )


def make_build_graph() -> BuildGraph:
    f0 = make_file_node(":f0")
    f1 = FileNode(":f1", "/home/user/foo.c", "foo.c", 512,
                  "aabbcc0000000000000000000000000000000001")
    f2 = FileNode(":f2", "/tmp/foo.o", "foo.o", 2048,
                  "aabbcc0000000000000000000000000000000002")
    p0 = make_process_node(":p0")
    p1 = ProcessNode(":p1", 43, "ld -o foo foo.o", ":f0",
                     None, None, [":f2"], [":f3"], [], None)
    return BuildGraph(
        files={":f0": f0, ":f1": f1, ":f2": f2},
        procs={":p0": p0, ":p1": p1},
    )


def make_ir_document(graph: BuildGraph | None = None) -> IRDocument:
    if graph is None:
        graph = make_build_graph()
    return IRDocument(
        schema_version=SCHEMA_VERSION,
        stage="graph",
        source_out="tests/fixtures/tiny.out",
        payload=graph.to_dict(),
    )


# ── FileNode round-trip ───────────────────────────────────────────────────────

def test_file_node_round_trip() -> None:
    node = make_file_node()
    assert FileNode.from_dict(node.to_dict()) == node


def test_file_node_to_dict_keys() -> None:
    d = make_file_node().to_dict()
    assert set(d.keys()) == {
        "uri", "abspath", "name", "size", "git_blob_sha1",
        "dep_type", "rpm_name", "rpm_nevra",
        "pkg_backend", "pkg_name", "pkg_version", "purl",
    }


def test_file_node_size_is_int_after_round_trip() -> None:
    node = make_file_node()
    d = node.to_dict()
    d["size"] = str(d["size"])          # simulate string coming from JSON
    restored = FileNode.from_dict(d)
    assert isinstance(restored.size, int)
    assert restored.size == node.size


# ── ProcessNode round-trip ────────────────────────────────────────────────────

def test_process_node_round_trip() -> None:
    node = make_process_node()
    assert ProcessNode.from_dict(node.to_dict()) == node


def test_process_node_round_trip_minimal() -> None:
    node = ProcessNode(
        uri=":p99",
        pid=1,
        cmd="true",
        executable=None,
        start=None,
        end=None,
        reads=[],
        writes=[],
        execs=[],
        role=None,
    )
    assert ProcessNode.from_dict(node.to_dict()) == node


def test_process_node_lists_are_independent_copies() -> None:
    node = make_process_node()
    d = node.to_dict()
    d["reads"].append(":fEXTRA")
    restored = ProcessNode.from_dict(d)
    assert ":fEXTRA" in restored.reads
    assert ":fEXTRA" not in node.reads


# ── ProcessNode from_dict: missing optional fields ───────────────────────────

def test_process_node_from_dict_missing_optionals() -> None:
    """from_dict must tolerate absent optional fields (forward-compat)."""
    minimal = {
        "uri": ":p0",
        "pid": 7,
        "cmd": "echo",
        # executable, start, end, reads, writes, execs, role all absent
    }
    node = ProcessNode.from_dict(minimal)
    assert node.executable is None
    assert node.start is None
    assert node.end is None
    assert node.reads == []
    assert node.writes == []
    assert node.execs == []
    assert node.role is None


# ── BuildGraph round-trip ─────────────────────────────────────────────────────

def test_build_graph_round_trip() -> None:
    graph = make_build_graph()
    assert BuildGraph.from_dict(graph.to_dict()) == graph


def test_build_graph_empty_round_trip() -> None:
    graph = BuildGraph(files={}, procs={})
    assert BuildGraph.from_dict(graph.to_dict()) == graph


def test_build_graph_from_dict_missing_keys() -> None:
    graph = BuildGraph.from_dict({})
    assert graph.files == {}
    assert graph.procs == {}


# ── IRDocument round-trip ─────────────────────────────────────────────────────

def test_ir_document_round_trip() -> None:
    doc = make_ir_document()
    restored = IRDocument.from_dict(doc.to_dict())
    assert restored == doc


def test_ir_document_to_dict_has_all_keys() -> None:
    d = make_ir_document().to_dict()
    assert set(d.keys()) == {"schema_version", "stage", "source_out", "payload"}


# ── IRVersionError ────────────────────────────────────────────────────────────

def test_ir_version_error_on_wrong_version() -> None:
    d = make_ir_document().to_dict()
    d["schema_version"] = 999
    with pytest.raises(IRVersionError):
        IRDocument.from_dict(d)


def test_ir_version_error_message_contains_version() -> None:
    d = make_ir_document().to_dict()
    d["schema_version"] = 42
    with pytest.raises(IRVersionError, match="42"):
        IRDocument.from_dict(d)


# ── dump / load ───────────────────────────────────────────────────────────────

def test_ir_document_dump_load_identity(tmp_path: Path) -> None:
    doc = make_ir_document()
    out = tmp_path / "doc.json"
    doc.dump(out)
    loaded = IRDocument.load(out)
    assert loaded == doc


def test_ir_document_dump_load_preserves_payload(tmp_path: Path) -> None:
    graph = make_build_graph()
    doc = make_ir_document(graph)
    out = tmp_path / "doc.json"
    doc.dump(out)
    loaded = IRDocument.load(out)
    restored_graph = BuildGraph.from_dict(loaded.payload)
    assert restored_graph == graph


def test_ir_document_dump_is_valid_json(tmp_path: Path) -> None:
    out = tmp_path / "doc.json"
    make_ir_document().dump(out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == SCHEMA_VERSION


# ── Determinism ───────────────────────────────────────────────────────────────

def test_ir_document_dump_deterministic(tmp_path: Path) -> None:
    """Repeated dump of the same object must produce byte-identical output."""
    doc = make_ir_document()
    out1 = tmp_path / "a.json"
    out2 = tmp_path / "b.json"
    doc.dump(out1)
    doc.dump(out2)
    assert out1.read_bytes() == out2.read_bytes()


def test_ir_document_dump_keys_are_sorted(tmp_path: Path) -> None:
    out = tmp_path / "doc.json"
    make_ir_document().dump(out)
    text = out.read_text(encoding="utf-8")
    # top-level keys must appear in sorted order
    positions = {k: text.index(f'"{k}"') for k in
                 ("payload", "schema_version", "source_out", "stage")}
    keys_sorted = sorted(positions, key=lambda k: positions[k])
    assert keys_sorted == sorted(keys_sorted)


def test_ir_document_dump_ends_with_newline(tmp_path: Path) -> None:
    out = tmp_path / "doc.json"
    make_ir_document().dump(out)
    assert out.read_bytes().endswith(b"\n")


# ── Unicode / ensure_ascii=False ──────────────────────────────────────────────

def test_ir_document_dump_non_ascii_preserved(tmp_path: Path) -> None:
    """Non-ASCII characters must not be escaped in the output file."""
    node = FileNode(":f0", "/пути/к/файлу.c", "файлу.c", 100,
                    "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    graph = BuildGraph(files={":f0": node}, procs={})
    doc = IRDocument(SCHEMA_VERSION, "graph", "test.out", graph.to_dict())
    out = tmp_path / "doc.json"
    doc.dump(out)
    text = out.read_text(encoding="utf-8")
    assert "файлу.c" in text
    assert "\\u" not in text


# ── IRDocument.load raises IRVersionError ────────────────────────────────────

def test_ir_document_load_raises_on_wrong_version(tmp_path: Path) -> None:
    bad = {"schema_version": 0, "stage": "graph", "source_out": "", "payload": {}}
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(IRVersionError):
        IRDocument.load(p)


# ── Tabular round-trip cases ──────────────────────────────────────────────────

@pytest.mark.parametrize("size", [0, 1, 2**31 - 1])
def test_file_node_various_sizes(size: int) -> None:
    node = FileNode(":fX", "/tmp/x", "x", size, "a" * 40)
    assert FileNode.from_dict(node.to_dict()).size == size


@pytest.mark.parametrize("role", [None, "compiler", "linker", "assembler", "archiver", "other"])
def test_process_node_roles(role: str | None) -> None:
    node = ProcessNode(":p0", 1, "cmd", None, None, None, [], [], [], role)
    assert ProcessNode.from_dict(node.to_dict()).role == role
