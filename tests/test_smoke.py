"""T0.0 acceptance tests — package scaffold and fixtures."""

import json
from pathlib import Path


# ── Criterion 1: brec package importable, __version__ defined ────────────────

def test_brec_importable() -> None:
    import brec  # noqa: F401


def test_brec_version_is_string() -> None:
    import brec
    assert isinstance(brec.__version__, str)
    assert brec.__version__ == "0.0.0"


# ── Criterion 2: tiny.out exists and looks like build-recorder Turtle ────────

def test_tiny_out_exists(tiny_out: Path) -> None:
    assert tiny_out.exists(), f"Fixture not found: {tiny_out}"
    assert tiny_out.stat().st_size > 0


def test_tiny_out_has_prefix_declarations(tiny_out: Path) -> None:
    text = tiny_out.read_text(encoding="utf-8")
    assert "@prefix :" in text
    assert "@prefix b:" in text


def test_tiny_out_has_process_and_file_nodes(tiny_out: Path) -> None:
    text = tiny_out.read_text(encoding="utf-8")
    assert "a b:process" in text
    assert "a b:file" in text


def test_tiny_out_has_required_relations(tiny_out: Path) -> None:
    text = tiny_out.read_text(encoding="utf-8")
    # At least one of: b:execs or b:creates (process→process)
    assert ("b:execs" in text or "b:creates" in text)
    assert "b:reads" in text
    assert "b:writes" in text
    assert "b:executable" in text


def test_tiny_out_minimum_counts(tiny_out: Path) -> None:
    """Fixture must have at least 2 processes and 3 files (per T0.0 spec)."""
    import re
    text = tiny_out.read_text(encoding="utf-8")
    proc_decls = re.findall(r"^:[a-zA-Z_]\w*\s+a\s+b:process\b", text, re.MULTILINE)
    file_decls = re.findall(r"^:[a-zA-Z_]\w*\s+a\s+b:file\b", text, re.MULTILINE)
    assert len(proc_decls) >= 2, f"Need ≥2 process nodes, found {len(proc_decls)}"
    assert len(file_decls) >= 3, f"Need ≥3 file nodes, found {len(file_decls)}"


# ── Criterion 3: tiny.expected.json is valid JSON with expected structure ─────

def test_tiny_expected_json_is_valid(tiny_expected: Path) -> None:
    assert tiny_expected.exists(), f"Fixture not found: {tiny_expected}"
    data = json.loads(tiny_expected.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_tiny_expected_json_structure(tiny_expected: Path) -> None:
    data = json.loads(tiny_expected.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert data["stage"] == "graph"
    assert "payload" in data
    payload = data["payload"]
    assert "files" in payload
    assert "procs" in payload


def test_tiny_expected_matches_tiny_out_counts(tiny_out: Path, tiny_expected: Path) -> None:
    """Expected JSON counts must match what's declared in tiny.out."""
    import re
    text = tiny_out.read_text(encoding="utf-8")
    proc_decls = re.findall(r"^:[a-zA-Z_]\w*\s+a\s+b:process\b", text, re.MULTILINE)
    file_decls = re.findall(r"^:[a-zA-Z_]\w*\s+a\s+b:file\b", text, re.MULTILINE)

    data = json.loads(tiny_expected.read_text(encoding="utf-8"))
    payload = data["payload"]
    assert len(payload["files"]) == len(file_decls)
    assert len(payload["procs"]) == len(proc_decls)
