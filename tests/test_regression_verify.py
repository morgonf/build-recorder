"""T0.3 regression tests — verify-build.py behavior-preserving refactor.

Golden files: tests/golden/tiny_verify.json, tests/golden/tiny_verify.md

Non-deterministic fields normalized before comparison:
  - "generated" ISO-8601 datetime in JSON
  - "Generated: YYYY-MM-DD HH:MM UTC" line in Markdown
"""

import json
import re
from pathlib import Path

import pytest

from brec.commands import verify as vb
from brec.model import parse_out

GOLDEN_DIR = Path(__file__).parent / "golden"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

_VB_PATH = Path(__file__).parent.parent / "brec" / "commands" / "verify.py"

_NORM_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    r"|Generated: \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"
)
_NORM_SRC = re.compile(r"(?<=Source: `)([^`]+)(?=`)")


def _normalize(text: str) -> str:
    text = _NORM_TS.sub("TIMESTAMP", text)
    text = _NORM_SRC.sub("PATH", text)
    return text


# ── The parser contract verify-build.py relies on ─────────────────────────────
#
# verify-build.py used to keep its own FileNode/ProcessNode and convert
# brec.model's graph into them.  The converter is gone and the report reads the
# graph directly, so what these tests guard is that graph, in the shapes the
# report needs: hashes, read/write edges, and enrichment fields in both the
# flat and the grouped .out layout.

def test_graph_file_count(tiny_out: Path) -> None:
    graph = parse_out(tiny_out)
    assert len(graph.files) == 3
    assert len(graph.procs) == 2


def test_graph_file_fields(tiny_out: Path) -> None:
    f1 = parse_out(tiny_out).files[":f1"]
    assert f1.abspath == "/home/user/project/hello.c"
    assert f1.git_blob_sha1 == "aabbcc0000000000000000000000000000000001"


def test_graph_proc_relations(tiny_out: Path) -> None:
    p1 = parse_out(tiny_out).procs[":p1"]
    assert p1.executable == ":f0"
    assert ":f1" in p1.reads
    assert ":f2" in p1.writes


def test_graph_enrichment_fields(tmp_path: Path) -> None:
    """dep_type, rpm_name and rpm_nevra survive parsing of an enriched .out."""
    out = tmp_path / "enriched.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file .\n"
        ':f0 b:abspath "/usr/include/stdio.h" .\n'
        ":f0 b:size 100 .\n"
        ':f0 b:hash "aabbcc0000000000000000000000000000000001" .\n'
        ':f0 b:dep_type "static_header" .\n'
        ':f0 b:rpm_name "glibc-devel" .\n'
        ':f0 b:rpm_package "glibc-devel-2.35-alt1.x86_64" .\n',
        encoding="utf-8",
    )
    f0 = parse_out(out).files[":f0"]
    assert f0.dep_type  == "static_header"
    assert f0.rpm_name  == "glibc-devel"
    assert f0.rpm_nevra == "glibc-devel-2.35-alt1.x86_64"


def test_graph_enrichment_grouped_format(tmp_path: Path) -> None:
    """Same, in the grouped enrichment-block layout (bare URI + indented lines)."""
    out = tmp_path / "grouped_enriched.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file ;\n"
        '    b:abspath "/usr/lib/libz.so.1" ;\n'
        "    b:size 200 ;\n"
        '    b:hash "bbbbcc0000000000000000000000000000000001" .\n'
        ":f0\n"
        '    b:dep_type "dynamic_lib" ;\n'
        '    b:rpm_name "zlib" ;\n'
        '    b:rpm_package "zlib-1.2.11-alt1.x86_64" .\n',
        encoding="utf-8",
    )
    f0 = parse_out(out).files[":f0"]
    assert f0.dep_type  == "dynamic_lib"
    assert f0.rpm_name  == "zlib"
    assert f0.rpm_nevra == "zlib-1.2.11-alt1.x86_64"


# ── Golden: JSON report ───────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def tiny_analysis():
    out_path = FIXTURES_DIR / "tiny.out"
    graph = parse_out(out_path)
    deps = vb.analyze(graph)
    return deps, graph.files, out_path


def test_verify_json_golden(tiny_analysis) -> None:
    """JSON report is byte-identical to the pre-refactor baseline."""
    deps, files, out_path = tiny_analysis
    pkg_name = out_path.stem.replace("-build", "")
    produced = json.dumps(vb.make_json(deps, pkg_name), indent=2, ensure_ascii=False)
    golden = (GOLDEN_DIR / "tiny_verify.json").read_text(encoding="utf-8")
    assert _normalize(produced) == _normalize(golden)


# ── Golden: Markdown report ───────────────────────────────────────────────────

def test_verify_md_golden(tiny_analysis) -> None:
    """Markdown report is identical to the pre-refactor baseline."""
    deps, files, out_path = tiny_analysis
    pkg_name = out_path.stem.replace("-build", "")
    produced = vb.make_markdown(deps, files, pkg_name, out_path)
    golden = (GOLDEN_DIR / "tiny_verify.md").read_text(encoding="utf-8")
    assert _normalize(produced) == _normalize(golden)


# ── No own Turtle parser ──────────────────────────────────────────────────────

def test_verify_has_no_own_turtle_parser() -> None:
    """`brec verify` must not contain its own line-by-line .out parser."""
    src = _VB_PATH.read_text(encoding="utf-8")
    assert r"a\s+b:file" not in src, "verify-build.py still has b:file Turtle pattern"
    assert "file_uris" not in src, "verify-build.py still has file_uris parser variable"


# ── T1.4: No local copies of name sets, no _proc_kind ────────────────────────

def test_verify_no_local_compiler_names() -> None:
    """COMPILER_NAMES must not be defined locally; it comes from brec.classify."""
    src = _VB_PATH.read_text(encoding="utf-8")
    assert "COMPILER_NAMES = " not in src, \
        "COMPILER_NAMES still locally defined in verify-build.py"


def test_verify_no_local_linker_names() -> None:
    src = _VB_PATH.read_text(encoding="utf-8")
    assert "LINKER_NAMES = " not in src, \
        "LINKER_NAMES still locally defined in verify-build.py"


def test_verify_no_local_assembler_names() -> None:
    src = _VB_PATH.read_text(encoding="utf-8")
    assert "ASSEMBLER_NAMES = " not in src, \
        "ASSEMBLER_NAMES still locally defined in verify-build.py"


def test_verify_no_local_archiver_names() -> None:
    src = _VB_PATH.read_text(encoding="utf-8")
    assert "ARCHIVER_NAMES = " not in src, \
        "ARCHIVER_NAMES still locally defined in verify-build.py"


def test_verify_no_proc_kind_function() -> None:
    """_proc_kind must be removed; process roles come from brec.classify."""
    src = _VB_PATH.read_text(encoding="utf-8")
    assert "def _proc_kind(" not in src, \
        "_proc_kind still defined in verify-build.py"


def test_verify_uses_brec_classify_roles() -> None:
    """`brec verify` must import and use classify_roles from brec.classify."""
    src = _VB_PATH.read_text(encoding="utf-8")
    assert "classify_roles" in src, "classify_roles not imported in verify-build.py"


# ── T1.4: Golden output unchanged after refactoring ──────────────────────────
# (The existing test_verify_json_golden and test_verify_md_golden above already
#  cover this — they compare against the pre-T1.4 baseline captured in T0.3)
