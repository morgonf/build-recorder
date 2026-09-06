"""Tests for `brec enrich`: package attribution derived beside the trace.

Golden baseline: tests/golden/enrich_test.provenance.json, the sidecar for
tests/fixtures/enrich_test.out + tests/fixtures/enrich_rpm_dump.txt.  It
carries the same attribution the command used to append to the .out itself,
which is what the per-dep_type tests below check entry by entry.

The invariant these tests exist for is the first one: the trace is evidence,
and running enrich must leave it byte-for-byte as the tracer wrote it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.cli import main as cli_main
from brec.commands import enrich
from brec.model import parse_out
from brec.provenance import sidecar
from brec.provenance.rpm import RpmBackend

GOLDEN_DIR = Path(__file__).parent / "golden"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

_ENRICH_PATH = Path(__file__).parent.parent / "brec" / "commands" / "enrich.py"


# ── Structural: load_rpm_dump and classify_dep_type must be gone ──────────────

def test_enrich_has_no_load_rpm_dump() -> None:
    """`brec enrich` must not contain its own load_rpm_dump function."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "def load_rpm_dump" not in src, "load_rpm_dump still defined in brec/commands/enrich.py"


def test_enrich_has_no_classify_dep_type() -> None:
    """`brec enrich` must not contain its own classify_dep_type function."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "def classify_dep_type" not in src, "classify_dep_type still defined in brec/commands/enrich.py"


def test_enrich_uses_rpm_backend() -> None:
    """`brec enrich` must import and use RpmBackend from brec."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "RpmBackend" in src, "RpmBackend not found in brec/commands/enrich.py"


def test_dep_type_classification_is_not_reimplemented() -> None:
    """The one definition lives in brec.classify; the sidecar builder calls it."""
    src = (Path(__file__).parent.parent / "brec" / "provenance" /
           "sidecar.py").read_text(encoding="utf-8")
    assert "from brec.classify import dep_type_from_path" in src


def test_enrich_has_no_tool_dirs_definition() -> None:
    """TOOL_DIRS local definition removed (classification logic now in brec)."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "TOOL_DIRS = " not in src, "TOOL_DIRS still locally defined in brec/commands/enrich.py"


# ── The trace is evidence: enrich must not touch it ──────────────────────────

def test_run_leaves_the_trace_byte_for_byte(tmp_path: Path, capsys) -> None:
    trace = tmp_path / "build.out"
    trace.write_bytes((FIXTURES_DIR / "enrich_test.out").read_bytes())
    before = trace.read_bytes()

    rc = cli_main(["enrich", str(trace), str(FIXTURES_DIR / "enrich_rpm_dump.txt")])

    assert rc == 0
    assert trace.read_bytes() == before
    assert (tmp_path / "build.provenance.json").exists()


def test_run_writes_the_sidecar_where_asked(tmp_path: Path) -> None:
    trace = tmp_path / "build.out"
    trace.write_bytes((FIXTURES_DIR / "enrich_test.out").read_bytes())
    target = tmp_path / "elsewhere" / "p.json"
    target.parent.mkdir()

    rc = cli_main(["enrich", str(trace), str(FIXTURES_DIR / "enrich_rpm_dump.txt"),
                   "-o", str(target)])

    assert rc == 0
    assert target.exists()
    assert not (tmp_path / "build.provenance.json").exists()


def test_dry_run_writes_nothing(tmp_path: Path) -> None:
    trace = tmp_path / "build.out"
    trace.write_bytes((FIXTURES_DIR / "enrich_test.out").read_bytes())

    rc = cli_main(["enrich", str(trace), str(FIXTURES_DIR / "enrich_rpm_dump.txt"),
                   "--dry-run"])

    assert rc == 0
    assert list(tmp_path.iterdir()) == [trace]


# ── Golden: the sidecar for the fixture trace ────────────────────────────────

def _sidecar_for(out_file: Path, rpm_dump: Path):
    backend = RpmBackend()
    backend.build_index(rpm_dump)
    return sidecar.build(parse_out(out_file), [backend], source_out=out_file,
                         env_dump=rpm_dump)


def test_sidecar_golden(tmp_path: Path) -> None:
    doc = _sidecar_for(FIXTURES_DIR / "enrich_test.out",
                       FIXTURES_DIR / "enrich_rpm_dump.txt")
    # Paths of the inputs are environment-specific; the attribution is not.
    doc.source_out = "enrich_test.out"
    doc.payload["env_dump"] = "enrich_rpm_dump.txt"
    written = tmp_path / "got.json"
    doc.dump(written)

    golden = GOLDEN_DIR / "enrich_test.provenance.json"
    if not golden.exists():
        golden.write_bytes(written.read_bytes())
    assert written.read_text(encoding="utf-8") == golden.read_text(encoding="utf-8")


# ── Per-dep_type correctness ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def entries():
    doc = _sidecar_for(FIXTURES_DIR / "enrich_test.out",
                       FIXTURES_DIR / "enrich_rpm_dump.txt")
    return doc.payload["files"]


def test_enrich_static_header(entries) -> None:
    assert entries[":f1"]["dep_type"] == "static_header"
    assert entries[":f1"]["pkg_name"] == "glibc-devel"
    assert entries[":f1"]["pkg_version"] == "glibc-devel-2.33-alt1.x86_64"
    assert entries[":f1"]["purl"] == "pkg:rpm/glibc-devel@glibc-devel-2.33-alt1.x86_64"


def test_enrich_dynamic_lib(entries) -> None:
    assert entries[":f2"]["dep_type"] == "dynamic_lib"
    assert entries[":f2"]["pkg_name"] == "glibc"


def test_enrich_project_source_no_rpm(entries) -> None:
    assert entries[":f3"]["dep_type"] == "project_source"
    assert "pkg_name" not in entries[":f3"]
    assert "pkg_version" not in entries[":f3"]


def test_enrich_static_archive(entries) -> None:
    assert entries[":f4"]["dep_type"] == "static_archive"
    assert entries[":f4"]["pkg_name"] == "zlib-devel-static"


def test_enrich_build_tool(entries) -> None:
    assert entries[":f5"]["dep_type"] == "build_tool"
    assert entries[":f5"]["pkg_name"] == "gcc"


def test_every_file_node_gets_an_entry(entries) -> None:
    """Including the ones no package owns: that is what makes them sources."""
    assert set(entries) == {":f1", ":f2", ":f3", ":f4", ":f5"}


def test_enrich_is_already_enriched_false(tmp_path: Path) -> None:
    out = tmp_path / "plain.out"
    out.write_text("@prefix b: <x> .\n:f0 a b:file .\n", encoding="utf-8")
    assert enrich.is_already_enriched(out) is False


def test_enrich_is_already_enriched_true(tmp_path: Path) -> None:
    marker = "# --- package provenance triples (added by enrich.py) ---\n"
    out = tmp_path / "enriched.out"
    out.write_text(f"content\n{marker}more\n", encoding="utf-8")
    assert enrich.is_already_enriched(out) is True


# ── Lib64 alias canonicalization via RpmBackend ────────────────────────────────

def test_enrich_lib64_alias_via_rpm_backend(tmp_path: Path) -> None:
    """A /lib64/... path is attributed through the /usr/lib64/... RPM entry."""
    dump = tmp_path / "dump.txt"
    dump.write_text("/usr/lib64/libfoo.so.1\tlibfoo\tlibfoo-1.0-alt1.x86_64\n",
                    encoding="utf-8")
    out = tmp_path / "test.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":fa a b:file .\n"
        ':fa b:abspath "/lib64/libfoo.so.1" .\n'
        ":fa b:size 1000 .\n"
        ':fa b:hash "aabbcc0000000000000000000000000000000001" .\n',
        encoding="utf-8",
    )
    entry = _sidecar_for(out, dump).payload["files"][":fa"]
    assert entry["dep_type"] == "dynamic_lib"
    assert entry["pkg_name"] == "libfoo"
