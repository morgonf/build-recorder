"""T1.4 regression tests — enrich.py behavior-preserving refactor.

Golden baseline: tests/golden/enrich_test.triples
Captured BEFORE T1.4 changes by running the original enrich.build_triples()
on tests/fixtures/enrich_test.out + tests/fixtures/enrich_rpm_dump.txt.

Non-deterministic fields: none — build_triples output is fully deterministic
(sorted by URI, fixed format).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

GOLDEN_DIR = Path(__file__).parent / "golden"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

_ENRICH_PATH = Path(__file__).parent.parent / "enrich.py"
_spec = importlib.util.spec_from_file_location("enrich", _ENRICH_PATH)
enrich = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(enrich)


# ── Structural: load_rpm_dump and classify_dep_type must be gone ──────────────

def test_enrich_has_no_load_rpm_dump() -> None:
    """enrich.py must not contain its own load_rpm_dump function."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "def load_rpm_dump" not in src, "load_rpm_dump still defined in enrich.py"


def test_enrich_has_no_classify_dep_type() -> None:
    """enrich.py must not contain its own classify_dep_type function."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "def classify_dep_type" not in src, "classify_dep_type still defined in enrich.py"


def test_enrich_uses_rpm_backend() -> None:
    """enrich.py must import and use RpmBackend from brec."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "RpmBackend" in src, "RpmBackend not found in enrich.py"


def test_enrich_uses_dep_type_from_path() -> None:
    """enrich.py must import dep_type_from_path from brec.classify."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "dep_type_from_path" in src, "dep_type_from_path not found in enrich.py"


def test_enrich_has_no_tool_dirs_definition() -> None:
    """TOOL_DIRS local definition removed (classification logic now in brec)."""
    src = _ENRICH_PATH.read_text(encoding="utf-8")
    assert "TOOL_DIRS = " not in src, "TOOL_DIRS still locally defined in enrich.py"


# ── Golden: build_triples output is byte-identical to pre-T1.4 baseline ──────

def test_enrich_build_triples_golden() -> None:
    """build_triples() with new enrich.py produces byte-identical output."""
    from brec.provenance.rpm import RpmBackend

    out_file = FIXTURES_DIR / "enrich_test.out"
    rpm_dump = FIXTURES_DIR / "enrich_rpm_dump.txt"

    backend = RpmBackend()
    backend.build_index(rpm_dump)
    uri_to_abspath = enrich.parse_file_abspaths(out_file)
    triples = enrich.build_triples(uri_to_abspath, backend)

    golden = (GOLDEN_DIR / "enrich_test.triples").read_text(encoding="utf-8").rstrip("\n")
    assert "\n".join(triples) == golden


# ── Per-dep_type correctness ──────────────────────────────────────────────────

@pytest.fixture(scope="module")
def enrich_triples():
    from brec.provenance.rpm import RpmBackend
    backend = RpmBackend()
    backend.build_index(FIXTURES_DIR / "enrich_rpm_dump.txt")
    uri_to_abspath = enrich.parse_file_abspaths(FIXTURES_DIR / "enrich_test.out")
    return {uri: block for uri, block in zip(
        sorted(uri_to_abspath.keys()),
        enrich.build_triples(uri_to_abspath, backend)
    )}


def test_enrich_static_header(enrich_triples) -> None:
    block = enrich_triples[":f1"]
    assert 'b:dep_type "static_header"' in block
    assert 'b:rpm_name "glibc-devel"' in block
    assert 'b:rpm_package "glibc-devel-2.33-alt1.x86_64"' in block


def test_enrich_dynamic_lib(enrich_triples) -> None:
    block = enrich_triples[":f2"]
    assert 'b:dep_type "dynamic_lib"' in block
    assert 'b:rpm_name "glibc"' in block


def test_enrich_project_source_no_rpm(enrich_triples) -> None:
    block = enrich_triples[":f3"]
    assert 'b:dep_type "project_source"' in block
    assert "b:rpm_name" not in block
    assert "b:rpm_package" not in block


def test_enrich_static_archive(enrich_triples) -> None:
    block = enrich_triples[":f4"]
    assert 'b:dep_type "static_archive"' in block
    assert 'b:rpm_name "zlib-devel-static"' in block


def test_enrich_build_tool(enrich_triples) -> None:
    block = enrich_triples[":f5"]
    assert 'b:dep_type "build_tool"' in block
    assert 'b:rpm_name "gcc"' in block


# ── Functional: parse_file_abspaths still works ───────────────────────────────

def test_enrich_parse_file_abspaths() -> None:
    result = enrich.parse_file_abspaths(FIXTURES_DIR / "enrich_test.out")
    assert len(result) == 5
    assert ":f1" in result
    assert result[":f1"] == "/usr/include/stdio.h"
    assert result[":f3"] == "/home/user/project/main.c"


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
    """build_triples finds /lib64/... paths via /usr/lib64/... RPM entry."""
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
    from brec.provenance.rpm import RpmBackend
    backend = RpmBackend()
    backend.build_index(dump)
    uri_to_abspath = enrich.parse_file_abspaths(out)
    triples = enrich.build_triples(uri_to_abspath, backend)
    assert len(triples) == 1
    assert 'b:dep_type "dynamic_lib"' in triples[0]
    assert 'b:rpm_name "libfoo"' in triples[0]
