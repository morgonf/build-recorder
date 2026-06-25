"""T0.4 acceptance tests — backward-compatible reading of legacy RDF predicates.

Three scenarios:
  1. Old enriched .out  (b:rpm_name / b:rpm_package / b:dep_type only)
     → pkg_* fields are derived with backend="rpm"; raw rpm_* preserved.
  2. New enriched .out  (b:pkg_* present alongside b:rpm_*)
     → new predicates win; rpm_* raw values still preserved.
  3. Unenriched .out    (no package predicates at all)
     → pkg_* fields are empty strings; no exception.

Also covers FileNode round-trip with the new fields.
"""

from pathlib import Path

import pytest

from brec.ir import FileNode
from brec.model import parse_out


# ── Fixture: old enriched (b:rpm_* + b:dep_type) ─────────────────────────────

def test_old_enriched_pkg_name_derived(old_enriched_out: Path) -> None:
    graph = parse_out(old_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.pkg_name == "openssl-devel"


def test_old_enriched_pkg_version_derived(old_enriched_out: Path) -> None:
    graph = parse_out(old_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.pkg_version == "openssl-devel-3.0.1-alt1.x86_64"


def test_old_enriched_pkg_backend_is_rpm(old_enriched_out: Path) -> None:
    graph = parse_out(old_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.pkg_backend == "rpm"


def test_old_enriched_raw_rpm_fields_preserved(old_enriched_out: Path) -> None:
    """Legacy rpm_name / rpm_nevra are kept verbatim alongside derived pkg_*."""
    graph = parse_out(old_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.rpm_name  == "openssl-devel"
    assert f0.rpm_nevra == "openssl-devel-3.0.1-alt1.x86_64"


def test_old_enriched_dep_type_preserved(old_enriched_out: Path) -> None:
    graph = parse_out(old_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.dep_type == "static_header"


def test_old_enriched_purl_empty(old_enriched_out: Path) -> None:
    graph = parse_out(old_enriched_out)
    assert graph.files[":f0"].purl == ""


# ── Fixture: new enriched (b:pkg_* present; also b:rpm_* present) ─────────────

def test_new_enriched_pkg_backend_uses_new(new_enriched_out: Path) -> None:
    """b:pkg_backend value wins over the rpm fallback."""
    graph = parse_out(new_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.pkg_backend == "dpkg"


def test_new_enriched_pkg_name_uses_new(new_enriched_out: Path) -> None:
    """b:pkg_name wins; the legacy rpm_name value must NOT appear in pkg_name."""
    graph = parse_out(new_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.pkg_name == "libssl3"
    assert f0.pkg_name != "old-rpm-name-should-not-win"


def test_new_enriched_pkg_version_uses_new(new_enriched_out: Path) -> None:
    graph = parse_out(new_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.pkg_version == "3.0.2-0ubuntu1.10"


def test_new_enriched_purl_parsed(new_enriched_out: Path) -> None:
    graph = parse_out(new_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.purl == "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64"


def test_new_enriched_raw_rpm_fields_still_preserved(new_enriched_out: Path) -> None:
    """Even when new predicates win, raw rpm_* values are not discarded."""
    graph = parse_out(new_enriched_out)
    f0 = graph.files[":f0"]
    assert f0.rpm_name  == "old-rpm-name-should-not-win"
    assert f0.rpm_nevra == "old-rpm-nevra-should-not-win-1.0-alt1.x86_64"


def test_new_enriched_dep_type_preserved(new_enriched_out: Path) -> None:
    graph = parse_out(new_enriched_out)
    assert graph.files[":f0"].dep_type == "dynamic_lib"


# ── Fixture: unenriched (tiny.out — no package predicates) ───────────────────

def test_unenriched_parses_without_error(tiny_out: Path) -> None:
    graph = parse_out(tiny_out)
    assert len(graph.files) > 0


def test_unenriched_pkg_fields_are_empty(tiny_out: Path) -> None:
    graph = parse_out(tiny_out)
    for fn in graph.files.values():
        assert fn.pkg_name    == ""
        assert fn.pkg_version == ""
        assert fn.pkg_backend == ""
        assert fn.purl        == ""


def test_unenriched_rpm_fields_are_empty(tiny_out: Path) -> None:
    graph = parse_out(tiny_out)
    for fn in graph.files.values():
        assert fn.rpm_name  == ""
        assert fn.rpm_nevra == ""
        assert fn.dep_type  == ""


# ── FileNode round-trip with pkg_* fields ─────────────────────────────────────

def test_file_node_round_trip_with_pkg_fields() -> None:
    node = FileNode(
        uri=":f0",
        abspath="/usr/lib/libssl.so.3",
        name="libssl.so.3",
        size=512000,
        git_blob_sha1="bbbb000000000000000000000000000000000010",
        dep_type="dynamic_lib",
        rpm_name="old-rpm-name",
        rpm_nevra="old-rpm-nevra-1.0-alt1.x86_64",
        pkg_backend="dpkg",
        pkg_name="libssl3",
        pkg_version="3.0.2-0ubuntu1.10",
        purl="pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.10?arch=amd64",
    )
    assert FileNode.from_dict(node.to_dict()) == node


def test_file_node_round_trip_empty_pkg_fields() -> None:
    node = FileNode(
        uri=":f0",
        abspath="/home/user/foo.c",
        name="foo.c",
        size=256,
        git_blob_sha1="aabbcc0000000000000000000000000000000001",
    )
    restored = FileNode.from_dict(node.to_dict())
    assert restored == node
    assert restored.pkg_name    == ""
    assert restored.pkg_backend == ""
    assert restored.purl        == ""


def test_file_node_to_dict_includes_pkg_keys() -> None:
    node = FileNode(":f0", "/tmp/x", "x", 1,
                    "0" * 40, pkg_backend="rpm", pkg_name="foo", pkg_version="1.0")
    d = node.to_dict()
    assert "pkg_backend" in d
    assert "pkg_name"    in d
    assert "pkg_version" in d
    assert "purl"        in d


def test_file_node_from_dict_missing_pkg_fields_defaults_to_empty() -> None:
    """from_dict must tolerate absent pkg_* (forward-compat with older IR JSON)."""
    d = {
        "uri": ":f0",
        "abspath": "/tmp/x",
        "name": "x",
        "size": 1,
        "git_blob_sha1": "0" * 40,
        # pkg_* fields absent
    }
    node = FileNode.from_dict(d)
    assert node.pkg_backend == ""
    assert node.pkg_name    == ""
    assert node.pkg_version == ""
    assert node.purl        == ""
