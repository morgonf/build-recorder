"""T0.3 regression tests — sbom.py behavior-preserving refactor.

Golden files: tests/golden/tiny_sbom.json, tests/golden/tiny_sbom_report.md

Non-deterministic fields normalized before comparison:
  - metadata.timestamp  ISO-8601 datetime in CycloneDX JSON
  - "Generated: YYYY-MM-DD HH:MM UTC" line in the Markdown report
"""

import json
import re
from pathlib import Path

from brec.commands import sbom
from brec.model import parse_out

GOLDEN_DIR = Path(__file__).parent / "golden"

# Matches ISO-8601 datetimes, human-readable date lines, and the source file path
# (absolute vs relative path varies depending on how tests are invoked).
_NORM_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
    r"|Generated: \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC"
)
_NORM_SRC = re.compile(r"(?<=Source: `)([^`]+)(?=`)")


def _normalize(text: str) -> str:
    text = _NORM_TS.sub("TIMESTAMP", text)
    text = _NORM_SRC.sub("PATH", text)
    return text


# ── The file nodes the SBOM is built from ─────────────────────────────────────
#
# sbom.py used to copy each file node into a FileRecord of its own; it now reads
# brec.ir.FileNode straight from the graph.  These tests state what the SBOM
# needs from a node: path, hash, and the dep_type that marks project source.

def test_file_nodes_count(tiny_out: Path) -> None:
    assert len(parse_out(tiny_out).files) == 3


def test_file_nodes_abspath(tiny_out: Path) -> None:
    abspaths = {f.abspath for f in parse_out(tiny_out).files.values()}
    assert "/home/user/project/hello.c" in abspaths


def test_file_nodes_git_hash(tiny_out: Path) -> None:
    by_path = {f.abspath: f for f in parse_out(tiny_out).files.values()}
    assert by_path["/home/user/project/hello.c"].git_blob_sha1 == (
        "aabbcc0000000000000000000000000000000001"
    )


def test_file_nodes_dep_type_enriched(tmp_path: Path) -> None:
    """dep_type from an enriched .out reaches the component detector."""
    out = tmp_path / "enriched.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":f0 a b:file .\n"
        ':f0 b:abspath "/project/third_party/sqlite3.c" .\n'
        ":f0 b:size 100 .\n"
        ':f0 b:hash "aabbcc0000000000000000000000000000000001" .\n'
        ':f0 b:dep_type "project_source" .\n',
        encoding="utf-8",
    )
    records = list(parse_out(out).files.values())
    assert len(records) == 1
    assert records[0].dep_type == "project_source"
    assert records[0].abspath == "/project/third_party/sqlite3.c"


# ── Golden: CycloneDX SBOM JSON ──────────────────────────────────────────────

def test_sbom_json_golden(tiny_out: Path) -> None:
    """CycloneDX SBOM JSON output is byte-identical to the pre-refactor baseline."""
    records = list(parse_out(tiny_out).files.values())
    components = sbom.detect_vendored_components(records)
    produced = json.dumps(
        sbom.generate_cyclonedx(components, tiny_out),
        indent=2,
        ensure_ascii=False,
    )
    golden = (GOLDEN_DIR / "tiny_sbom.json").read_text(encoding="utf-8")
    assert _normalize(produced) == _normalize(golden)


# ── Golden: Markdown report ───────────────────────────────────────────────────

def test_sbom_report_golden(tiny_out: Path) -> None:
    """Markdown SBOM report is identical to the pre-refactor baseline."""
    records = list(parse_out(tiny_out).files.values())
    components = sbom.detect_vendored_components(records)
    produced = sbom.generate_report(components, tiny_out)
    golden = (GOLDEN_DIR / "tiny_sbom_report.md").read_text(encoding="utf-8")
    assert _normalize(produced) == _normalize(golden)


# ── No own Turtle parser ──────────────────────────────────────────────────────

def test_sbom_has_no_own_turtle_parser() -> None:
    """sbom.py must not contain its own line-by-line .out parser."""
    src = (Path(__file__).parent.parent / "brec" / "commands" / "sbom.py").read_text(encoding="utf-8")
    assert r"a\s+b:file" not in src, "sbom.py still has b:file Turtle pattern"
    assert "file_uris" not in src, "sbom.py still has file_uris parser variable"
