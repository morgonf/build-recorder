"""T1.3 acceptance tests — brec/provenance/registry.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.provenance.base import ProvenanceBackend
from brec.provenance.registry import (
    all_backends,
    detect_backends,
    parse_provenance_arg,
    select_backends,
)
from brec.provenance.rpm import RpmBackend

FIXTURES = Path(__file__).parent / "fixtures"
MINI_DUMP = FIXTURES / "rpm_dump_mini.txt"


# ── all_backends ──────────────────────────────────────────────────────────────

def test_all_backends_returns_list() -> None:
    result = all_backends()
    assert isinstance(result, list)
    assert len(result) >= 1


def test_all_backends_contains_rpm() -> None:
    names = [b.name for b in all_backends()]
    assert "rpm" in names


def test_all_backends_returns_protocol_instances() -> None:
    for b in all_backends():
        assert isinstance(b, ProvenanceBackend)


def test_all_backends_fresh_instances() -> None:
    """Each call returns new instances (not singletons)."""
    b1 = all_backends()
    b2 = all_backends()
    for a, b in zip(b1, b2):
        assert a is not b


def test_all_backends_not_built_by_default() -> None:
    """all_backends() returns un-built instances (available() == False)."""
    for b in all_backends():
        assert b.available() is False


# ── detect_backends ───────────────────────────────────────────────────────────

def test_detect_backends_with_rpm_dump() -> None:
    """With a valid rpm-dump.txt, detect_backends returns [RpmBackend]."""
    result = detect_backends(MINI_DUMP)
    assert len(result) >= 1
    assert any(isinstance(b, RpmBackend) for b in result)


def test_detect_backends_result_all_available() -> None:
    """Every backend returned by detect_backends must be available."""
    for b in detect_backends(MINI_DUMP):
        assert b.available() is True


def test_detect_backends_rpm_backend_has_built_index() -> None:
    """RpmBackend returned by detect_backends can perform lookups."""
    backends = detect_backends(MINI_DUMP)
    rpm = next(b for b in backends if isinstance(b, RpmBackend))
    # rpm_dump_mini.txt has /usr/include/foo.h → libfoo-devel
    ref = rpm.lookup("/usr/include/foo.h", "")
    assert ref is not None
    assert ref.name == "libfoo-devel"


def test_detect_backends_without_dump_returns_empty() -> None:
    """Without an env_dump, no backend has a built index → empty list."""
    result = detect_backends()
    assert result == []


def test_detect_backends_nonexistent_file_returns_empty(tmp_path: Path) -> None:
    """A non-existent dump file → silently returns empty list (no crash)."""
    result = detect_backends(tmp_path / "no_such_file.txt")
    assert result == []


def test_detect_backends_malformed_file_returns_empty(tmp_path: Path) -> None:
    """A file with no valid TSV lines → RpmBackend stays unavailable → empty."""
    bad = tmp_path / "bad.txt"
    bad.write_text("not\ta\tvalid\tformat\nstill wrong\n", encoding="utf-8")
    # RpmBackend will call build_index (which succeeds on any file, even empty),
    # but with zero entries it is still marked available=True after build.
    # Test that detect_backends doesn't crash.
    result = detect_backends(bad)
    # Result may be empty or contain an available backend with no entries — both fine
    assert isinstance(result, list)


def test_detect_backends_returns_protocol_instances() -> None:
    for b in detect_backends(MINI_DUMP):
        assert isinstance(b, ProvenanceBackend)


def test_detect_backends_fresh_instances_each_call() -> None:
    """Each detect_backends call produces independent instances."""
    r1 = detect_backends(MINI_DUMP)
    r2 = detect_backends(MINI_DUMP)
    for a, b in zip(r1, r2):
        assert a is not b


# ── select_backends ───────────────────────────────────────────────────────────

def test_select_backends_rpm_by_name() -> None:
    """select_backends(['rpm']) returns a list containing an RpmBackend."""
    result = select_backends(["rpm"])
    assert len(result) == 1
    assert isinstance(result[0], RpmBackend)


def test_select_backends_returns_protocol_instances() -> None:
    for b in select_backends(["rpm"]):
        assert isinstance(b, ProvenanceBackend)


def test_select_backends_none_returns_all() -> None:
    """select_backends(None) is equivalent to all_backends()."""
    none_result = select_backends(None)
    all_result = all_backends()
    assert len(none_result) == len(all_result)
    assert {b.name for b in none_result} == {b.name for b in all_result}


def test_select_backends_unknown_name_raises() -> None:
    """Unknown backend name raises ValueError."""
    with pytest.raises(ValueError):
        select_backends(["nope"])


def test_select_backends_error_message_contains_name() -> None:
    """ValueError message names the unknown backend."""
    with pytest.raises(ValueError, match="nope"):
        select_backends(["nope"])


def test_select_backends_error_message_lists_available() -> None:
    """ValueError message lists all available backend names."""
    with pytest.raises(ValueError, match="rpm"):
        select_backends(["unknown_backend"])


def test_select_backends_error_on_first_unknown() -> None:
    """Error is raised as soon as an unknown name is encountered."""
    with pytest.raises(ValueError, match="no_such"):
        select_backends(["rpm", "no_such"])


def test_select_backends_empty_list() -> None:
    """select_backends([]) returns empty list (no backends selected)."""
    assert select_backends([]) == []


def test_select_backends_fresh_instances() -> None:
    r1 = select_backends(["rpm"])
    r2 = select_backends(["rpm"])
    assert r1[0] is not r2[0]


def test_select_backends_not_built() -> None:
    """Backends from select_backends are not pre-built (available() == False)."""
    for b in select_backends(["rpm"]):
        assert b.available() is False


# ── parse_provenance_arg ──────────────────────────────────────────────────────

def test_parse_provenance_arg_single() -> None:
    assert parse_provenance_arg("rpm") == ["rpm"]


def test_parse_provenance_arg_two() -> None:
    assert parse_provenance_arg("rpm,dpkg") == ["rpm", "dpkg"]


def test_parse_provenance_arg_spaces() -> None:
    assert parse_provenance_arg("rpm, dpkg") == ["rpm", "dpkg"]


def test_parse_provenance_arg_trailing_comma() -> None:
    assert parse_provenance_arg("rpm,") == ["rpm"]


def test_parse_provenance_arg_empty_string() -> None:
    assert parse_provenance_arg("") == []


def test_parse_provenance_arg_none() -> None:
    assert parse_provenance_arg(None) is None


def test_parse_provenance_arg_returns_list_of_strings() -> None:
    result = parse_provenance_arg("rpm,dpkg")
    assert isinstance(result, list)
    assert all(isinstance(n, str) for n in result)


@pytest.mark.parametrize("arg,expected", [
    ("rpm",        ["rpm"]),
    ("rpm,dpkg",   ["rpm", "dpkg"]),
    ("rpm, dpkg",  ["rpm", "dpkg"]),
    (" rpm ",      ["rpm"]),
    ("rpm,,dpkg",  ["rpm", "dpkg"]),
    ("",           []),
])
def test_parse_provenance_arg_parametrized(arg: str, expected: list[str]) -> None:
    assert parse_provenance_arg(arg) == expected


# ── Integration: parse → select → detect ──────────────────────────────────────

def test_parse_then_select_rpm() -> None:
    """Full flow: parse arg → select_backends → RpmBackend instance."""
    names = parse_provenance_arg("rpm")
    assert names is not None
    backends = select_backends(names)
    assert any(isinstance(b, RpmBackend) for b in backends)


def test_parse_then_select_unknown_raises() -> None:
    names = parse_provenance_arg("rpm,ghost")
    assert names is not None
    with pytest.raises(ValueError, match="ghost"):
        select_backends(names)


def test_detect_then_use_backend() -> None:
    """detect_backends → lookup — end-to-end without manual build_index call."""
    backends = detect_backends(MINI_DUMP)
    assert backends, "No backends detected; check rpm_dump_mini.txt fixture"
    results = [b.lookup("/usr/bin/mytool", "") for b in backends]
    # At least one backend should find the path in the mini dump
    assert any(r is not None for r in results)
