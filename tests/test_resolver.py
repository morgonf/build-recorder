"""T2.1 acceptance tests — brec/identify/base.py + resolver.py + IR structures."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

from brec.identify.base import IdentificationBackend, VendoredUnit
from brec.identify.resolver import (
    _abs_root_of_vendor_dir,
    _merge_matches,
    _normalize_url,
    _rel_path_in_vendor_dir,
    build_units,
    resolve,
)
from brec.ir import (
    ClassifiedFile,
    DepClass,
    FileHash,
    FileNode,
    IdentifiedComponent,
    Match,
    PackageRef,
)

# ── Helpers / shared fixtures ─────────────────────────────────────────────────

def _make_file_node(uri: str, abspath: str) -> FileNode:
    return FileNode(
        uri=uri,
        abspath=abspath,
        name=Path(abspath).name,
        size=1000,
        git_blob_sha1="a" * 40,
    )


def _make_classified(
    uri: str,
    abspath: str,
    dep_class: DepClass = DepClass.VENDORED,
    vendor_dir: Optional[str] = None,
    git_hash: str = "a" * 40,
) -> ClassifiedFile:
    f = FileNode(uri=uri, abspath=abspath, name=Path(abspath).name,
                 size=1000, git_blob_sha1=git_hash)
    return ClassifiedFile(file=f, dep_class=dep_class, vendor_dir=vendor_dir,
                          read_by_roles={"compiler"})


# Stub backend: discover returns a fixed list, refine raises NotImplementedError
@dataclass
class _DiscoverStub:
    name: str
    requires_network: bool
    _matches: list[Match]

    def discover(self, unit: VendoredUnit) -> list[Match]:
        return list(self._matches)

    def refine(self, unit: VendoredUnit, repo_url: str) -> Optional[Match]:
        raise NotImplementedError


# Stub backend: refine returns a fixed Match, discover returns []
@dataclass
class _RefineStub:
    name: str
    requires_network: bool
    _match: Optional[Match]

    def discover(self, unit: VendoredUnit) -> list[Match]:
        return []

    def refine(self, unit: VendoredUnit, repo_url: str) -> Optional[Match]:
        return self._match


# ── FileHash round-trip ───────────────────────────────────────────────────────

def test_filehash_round_trip_full() -> None:
    fh = FileHash(
        rel_path="lib/foo.c",
        git_blob_sha1="a" * 40,
        plain_sha1="b" * 40,
        other={"md5": "c" * 32},
    )
    assert FileHash.from_dict(fh.to_dict()) == fh


def test_filehash_round_trip_minimal() -> None:
    fh = FileHash(rel_path="foo.h", git_blob_sha1="d" * 40)
    assert fh.plain_sha1 is None
    assert fh.other == {}
    assert FileHash.from_dict(fh.to_dict()) == fh


def test_filehash_to_dict_keys() -> None:
    d = FileHash("x.c", "e" * 40).to_dict()
    assert set(d.keys()) == {"rel_path", "git_blob_sha1", "plain_sha1", "other"}


# ── Match round-trip ──────────────────────────────────────────────────────────

def test_match_round_trip_full() -> None:
    m = Match(
        backend="swh",
        repo_url="https://github.com/foo/bar",
        project="bar",
        version="1.2.3",
        commit="a" * 40,
        nearest_tag="v1.2.3",
        commits_past_tag=0,
        confidence=1.0,
        method="exact",
        files_matched=10,
        files_total=10,
    )
    assert Match.from_dict(m.to_dict()) == m


def test_match_round_trip_defaults() -> None:
    m = Match(backend="cache")
    restored = Match.from_dict(m.to_dict())
    assert restored == m
    assert restored.confidence == 0.0
    assert restored.commits_past_tag == 0
    assert restored.method == "exact"


def test_match_to_dict_keys() -> None:
    d = Match(backend="osv").to_dict()
    expected = {"backend", "repo_url", "project", "version", "commit",
                "nearest_tag", "commits_past_tag", "confidence", "method",
                "files_matched", "files_total"}
    assert set(d.keys()) == expected


def test_match_is_tagged_release_true() -> None:
    m = Match(backend="gitwalk", nearest_tag="v1.0", commits_past_tag=0)
    assert m.is_tagged_release is True


def test_match_is_tagged_release_false_no_tag() -> None:
    assert Match(backend="gitwalk", commits_past_tag=0).is_tagged_release is False


def test_match_is_tagged_release_false_past_tag() -> None:
    m = Match(backend="gitwalk", nearest_tag="v1.0", commits_past_tag=5)
    assert m.is_tagged_release is False


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_match_confidence_preserved(confidence: float) -> None:
    m = Match(backend="swh", confidence=confidence)
    assert Match.from_dict(m.to_dict()).confidence == confidence


# ── IdentifiedComponent round-trip ────────────────────────────────────────────

def test_identified_component_round_trip_full() -> None:
    m = Match(backend="gitwalk", repo_url="https://github.com/foo/bar",
              commit="a" * 40, confidence=0.9)
    ic = IdentifiedComponent(
        key="third_party/bar",
        files=[":f1", ":f2"],
        candidates=[m],
        best=m,
        purl="pkg:github/foo/bar@1.0",
    )
    assert IdentifiedComponent.from_dict(ic.to_dict()) == ic


def test_identified_component_round_trip_tier0() -> None:
    """Tier-0: no candidates, best=None."""
    ic = IdentifiedComponent(key="deps/wslay", files=[":f1", ":f2"])
    assert ic.best is None
    assert ic.candidates == []
    restored = IdentifiedComponent.from_dict(ic.to_dict())
    assert restored == ic
    assert restored.best is None


def test_identified_component_to_dict_keys() -> None:
    ic = IdentifiedComponent(key="v", files=[])
    assert set(ic.to_dict().keys()) == {"key", "files", "candidates", "best", "purl"}


# ── IdentificationBackend Protocol ────────────────────────────────────────────

def test_discover_stub_implements_protocol() -> None:
    stub = _DiscoverStub("test", False, [])
    assert isinstance(stub, IdentificationBackend)


def test_refine_stub_implements_protocol() -> None:
    stub = _RefineStub("test", False, None)
    assert isinstance(stub, IdentificationBackend)


# ── Path helpers ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("abspath,vendor_dir,expected", [
    ("/home/user/project/src/third_party/sqlite/sqlite3.c", "third_party/sqlite", "sqlite3.c"),
    ("/proj/third_party/sqlite/include/sqlite3.h", "third_party/sqlite", "include/sqlite3.h"),
    ("/proj/deps/wslay/lib/wslay.c", "deps/wslay", "lib/wslay.c"),
    ("/proj/vendor/zlib/inflate.c", "vendor/zlib", "inflate.c"),
])
def test_rel_path_in_vendor_dir(abspath: str, vendor_dir: str, expected: str) -> None:
    assert _rel_path_in_vendor_dir(abspath, vendor_dir) == expected


@pytest.mark.parametrize("abspath,vendor_dir,expected", [
    ("/home/user/project/src/third_party/sqlite/sqlite3.c",
     "third_party/sqlite",
     "/home/user/project/src/third_party/sqlite"),
    ("/proj/deps/wslay/lib/wslay.c",
     "deps/wslay",
     "/proj/deps/wslay"),
])
def test_abs_root_of_vendor_dir(abspath: str, vendor_dir: str, expected: str) -> None:
    assert _abs_root_of_vendor_dir(abspath, vendor_dir) == expected


# ── build_units: civetweb-style fixture ──────────────────────────────────────

def _make_civetweb_classified() -> list[ClassifiedFile]:
    """Synthetic civetweb classified files: two vendor dirs."""
    base = "/home/user/civetweb"
    files = [
        # third_party/sqlite
        (":fs1", f"{base}/src/third_party/sqlite/sqlite3.c", "third_party/sqlite", "a1" * 20),
        (":fs2", f"{base}/src/third_party/sqlite/sqlite3.h", "third_party/sqlite", "a2" * 20),
        # third_party/lua
        (":fl1", f"{base}/src/third_party/lua/lua.h",        "third_party/lua",    "b1" * 20),
        (":fl2", f"{base}/src/third_party/lua/ldo.c",        "third_party/lua",    "b2" * 20),
        (":fl3", f"{base}/src/third_party/lua/lvm.c",        "third_party/lua",    "b3" * 20),
    ]
    return [
        _make_classified(uri, abspath, DepClass.VENDORED, vdir, git_hash)
        for uri, abspath, vdir, git_hash in files
    ]


def test_build_units_count() -> None:
    classified = _make_civetweb_classified()
    units = build_units(classified)
    assert len(units) == 2


def test_build_units_keys() -> None:
    units = build_units(_make_civetweb_classified())
    keys = {u.key for u in units}
    assert keys == {"third_party/sqlite", "third_party/lua"}


def test_build_units_sqlite_file_count() -> None:
    units = build_units(_make_civetweb_classified())
    sqlite = next(u for u in units if u.key == "third_party/sqlite")
    assert len(sqlite.files) == 2


def test_build_units_lua_file_count() -> None:
    units = build_units(_make_civetweb_classified())
    lua = next(u for u in units if u.key == "third_party/lua")
    assert len(lua.files) == 3


def test_build_units_rel_paths() -> None:
    units = build_units(_make_civetweb_classified())
    sqlite = next(u for u in units if u.key == "third_party/sqlite")
    rel_paths = {fh.rel_path for fh in sqlite.files}
    assert rel_paths == {"sqlite3.c", "sqlite3.h"}


def test_build_units_git_hashes_preserved() -> None:
    units = build_units(_make_civetweb_classified())
    sqlite = next(u for u in units if u.key == "third_party/sqlite")
    hashes = {fh.git_blob_sha1 for fh in sqlite.files}
    assert "a1" * 20 in hashes


def test_build_units_abs_root() -> None:
    units = build_units(_make_civetweb_classified())
    sqlite = next(u for u in units if u.key == "third_party/sqlite")
    assert sqlite.abs_root == "/home/user/civetweb/src/third_party/sqlite"


def test_build_units_file_uris_preserved() -> None:
    units = build_units(_make_civetweb_classified())
    sqlite = next(u for u in units if u.key == "third_party/sqlite")
    assert ":fs1" in sqlite.file_uris
    assert ":fs2" in sqlite.file_uris


def test_build_units_skips_non_vendored() -> None:
    classified = _make_civetweb_classified()
    extra = _make_classified(":fx", "/usr/include/stdio.h", DepClass.SYSTEM_STATIC)
    units = build_units(classified + [extra])
    assert len(units) == 2  # extra not included


def test_build_units_skips_vendored_without_vendor_dir() -> None:
    classified = [
        _make_classified(":f0", "/home/user/project/main.c",
                         DepClass.VENDORED, vendor_dir=None)
    ]
    units = build_units(classified)
    assert units == []


def test_build_units_sorted_by_key() -> None:
    classified = _make_civetweb_classified()
    units = build_units(classified)
    assert [u.key for u in units] == sorted(u.key for u in units)


def test_build_units_empty_classified() -> None:
    assert build_units([]) == []


# ── resolve: Tier-0 (empty backends) ─────────────────────────────────────────

def _make_wslay_unit() -> VendoredUnit:
    return VendoredUnit(
        key="deps/wslay",
        files=[
            FileHash("lib/wslay_event.c", "a" * 40),
            FileHash("lib/wslay_frame.c", "b" * 40),
        ],
        abs_root="/home/user/aria2/deps/wslay",
        file_uris=[":fw1", ":fw2"],
    )


def test_resolve_empty_backends_tier0() -> None:
    unit = _make_wslay_unit()
    result = resolve(unit, [])
    assert isinstance(result, IdentifiedComponent)
    assert result.key == "deps/wslay"
    assert result.best is None
    assert result.candidates == []


def test_resolve_empty_backends_files_populated() -> None:
    unit = _make_wslay_unit()
    result = resolve(unit, [])
    assert set(result.files) == {":fw1", ":fw2"}


def test_resolve_empty_backends_returns_identified_component() -> None:
    result = resolve(_make_wslay_unit(), [])
    assert isinstance(result, IdentifiedComponent)


# ── resolve: single discover backend ─────────────────────────────────────────

def test_resolve_single_discover_returns_match() -> None:
    m = Match(backend="cache", repo_url="https://github.com/foo/wslay",
              confidence=0.5, files_total=2)
    stub = _DiscoverStub("cache", False, [m])
    result = resolve(_make_wslay_unit(), [stub])
    assert result.best is not None
    assert result.best.repo_url == "https://github.com/foo/wslay"


def test_resolve_single_discover_candidates_populated() -> None:
    m = Match(backend="cache", repo_url="https://github.com/foo/wslay", confidence=0.5)
    stub = _DiscoverStub("cache", False, [m])
    result = resolve(_make_wslay_unit(), [stub])
    assert len(result.candidates) == 1


def test_resolve_best_is_highest_confidence() -> None:
    m1 = Match(backend="cache", repo_url="https://github.com/a/b", confidence=0.3)
    m2 = Match(backend="swh",   repo_url="https://github.com/c/d", confidence=0.9)
    stub = _DiscoverStub("multi", False, [m1, m2])
    result = resolve(_make_wslay_unit(), [stub])
    assert result.best is not None
    assert result.best.confidence == 0.9


def test_resolve_candidates_sorted_descending() -> None:
    matches = [
        Match(backend="a", repo_url="https://a.com", confidence=0.3),
        Match(backend="b", repo_url="https://b.com", confidence=0.9),
        Match(backend="c", repo_url="https://c.com", confidence=0.6),
    ]
    stub = _DiscoverStub("multi", False, matches)
    result = resolve(_make_wslay_unit(), [stub])
    confidences = [m.confidence for m in result.candidates]
    assert confidences == sorted(confidences, reverse=True)


# ── resolve: refine backend ───────────────────────────────────────────────────

def test_resolve_refine_enriches_match() -> None:
    discover_m = Match(backend="cache", repo_url="https://github.com/foo/wslay",
                       confidence=0.5, files_total=2)
    refined_m  = Match(backend="gitwalk", repo_url="https://github.com/foo/wslay",
                       confidence=0.95, commit="a" * 40, nearest_tag="v1.0",
                       commits_past_tag=0, files_matched=2, files_total=2)
    discover_stub = _DiscoverStub("cache", False, [discover_m])
    refine_stub   = _RefineStub("gitwalk", True, refined_m)

    result = resolve(_make_wslay_unit(), [discover_stub, refine_stub])
    assert result.best is not None
    assert result.best.commit == "a" * 40
    assert result.best.confidence == 0.95


def test_resolve_refine_not_implemented_handled() -> None:
    """Backends that raise NotImplementedError from refine are silently skipped."""
    discover_m = Match(backend="cache", repo_url="https://github.com/foo/wslay", confidence=0.5)
    discover_stub = _DiscoverStub("cache", False, [discover_m])
    # Both stubs raise NotImplementedError from refine
    result = resolve(_make_wslay_unit(), [discover_stub])
    assert result.best is not None
    assert result.best.confidence == 0.5


# ── resolve: offline mode ─────────────────────────────────────────────────────

def test_resolve_offline_skips_network_backends() -> None:
    m = Match(backend="swh", repo_url="https://github.com/foo/wslay", confidence=0.9)
    network_stub = _DiscoverStub("swh", requires_network=True, _matches=[m])
    local_m = Match(backend="cache", repo_url="https://github.com/bar/wslay", confidence=0.5)
    local_stub = _DiscoverStub("cache", requires_network=False, _matches=[local_m])

    result = resolve(_make_wslay_unit(), [network_stub, local_stub], offline=True)
    assert result.best is not None
    assert result.best.backend == "cache"
    assert result.best.confidence == 0.5


def test_resolve_offline_all_network_backends_is_tier0() -> None:
    m = Match(backend="swh", repo_url="https://r.com", confidence=0.9)
    stub = _DiscoverStub("swh", requires_network=True, _matches=[m])
    result = resolve(_make_wslay_unit(), [stub], offline=True)
    assert result.best is None


# ── resolve: URL merging ──────────────────────────────────────────────────────

def test_resolve_merges_same_url_git_suffix() -> None:
    """repo_url with and without .git should be merged."""
    m1 = Match(backend="cache",   repo_url="https://github.com/foo/wslay.git", confidence=0.5, project="wslay")
    m2 = Match(backend="gitwalk", repo_url="https://github.com/foo/wslay",     confidence=0.9, commit="a" * 40)
    stub = _DiscoverStub("multi", False, [m1, m2])
    result = resolve(_make_wslay_unit(), [stub])
    # Should produce one merged candidate, not two
    assert len(result.candidates) == 1
    # Higher confidence wins; missing fields filled from lower
    assert result.best is not None
    assert result.best.confidence == 0.9
    assert result.best.project == "wslay"
    assert result.best.commit == "a" * 40


def test_resolve_different_urls_produce_separate_candidates() -> None:
    m1 = Match(backend="a", repo_url="https://github.com/a/a", confidence=0.6)
    m2 = Match(backend="b", repo_url="https://github.com/b/b", confidence=0.7)
    stub = _DiscoverStub("x", False, [m1, m2])
    result = resolve(_make_wslay_unit(), [stub])
    assert len(result.candidates) == 2


def test_resolve_none_url_matches_grouped_separately() -> None:
    m1 = Match(backend="swh", repo_url=None, confidence=0.5)
    m2 = Match(backend="swh", repo_url=None, confidence=0.6)
    stub = _DiscoverStub("swh", False, [m1, m2])
    result = resolve(_make_wslay_unit(), [stub])
    # Both have url=None → same key → merged into one
    assert len(result.candidates) == 1


# ── _normalize_url ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("https://github.com/foo/bar.git", "https://github.com/foo/bar"),
    ("https://github.com/foo/bar",     "https://github.com/foo/bar"),
    ("https://github.com/foo/bar/",    "https://github.com/foo/bar"),
    ("HTTPS://GITHUB.COM/foo/bar",     "https://github.com/foo/bar"),
    (None,                             None),
])
def test_normalize_url(url: Optional[str], expected: Optional[str]) -> None:
    assert _normalize_url(url) == expected


# ── _merge_matches ────────────────────────────────────────────────────────────

def test_merge_matches_base_has_priority() -> None:
    base  = Match(backend="gitwalk", repo_url="https://r.com", confidence=0.9, commit="a" * 40)
    other = Match(backend="cache",   repo_url="https://r.com", confidence=0.5, project="mylib")
    merged = _merge_matches(base, other)
    assert merged.confidence == 0.9
    assert merged.commit == "a" * 40
    assert merged.project == "mylib"  # filled from other


def test_merge_matches_fills_missing_fields() -> None:
    base  = Match(backend="swh",  repo_url=None, confidence=0.7)
    other = Match(backend="osv",  repo_url="https://r.com", confidence=0.4, version="1.0")
    merged = _merge_matches(base, other)
    assert merged.repo_url == "https://r.com"
    assert merged.version == "1.0"
    assert merged.confidence == 0.7


# ── Integration: build_units + resolve ────────────────────────────────────────

def test_build_then_resolve_tier0() -> None:
    classified = _make_civetweb_classified()
    units = build_units(classified)
    # With no backends: every unit returns Tier-0
    for unit in units:
        result = resolve(unit, [])
        assert result.best is None
        assert len(result.files) == len(unit.file_uris)


def test_build_then_resolve_with_stub() -> None:
    classified = _make_civetweb_classified()
    units = build_units(classified)
    sqlite_unit = next(u for u in units if u.key == "third_party/sqlite")

    m = Match(backend="cache", repo_url="https://github.com/sqlite/sqlite",
              confidence=0.5, files_total=2)
    stub = _DiscoverStub("cache", False, [m])
    result = resolve(sqlite_unit, [stub])
    assert result.best is not None
    assert "sqlite" in result.best.repo_url


def test_resolve_files_match_unit_file_uris() -> None:
    unit = _make_wslay_unit()
    result = resolve(unit, [])
    assert result.files == unit.file_uris
