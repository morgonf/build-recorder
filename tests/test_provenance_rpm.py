"""T1.1 acceptance tests — brec/provenance/rpm.py + PackageRef in brec/ir.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure repo root is importable when run directly.
sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.ir import PackageRef
from brec.provenance.base import ProvenanceBackend
from brec.provenance.rpm import RpmBackend

FIXTURES = Path(__file__).parent / "fixtures"
MINI_DUMP = FIXTURES / "rpm_dump_mini.txt"


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_backend() -> RpmBackend:
    b = RpmBackend()
    b.build_index(MINI_DUMP)
    return b


# ── PackageRef dataclass ──────────────────────────────────────────────────────

def test_package_ref_round_trip_full() -> None:
    ref = PackageRef(
        backend="rpm",
        name="libfoo",
        version="libfoo-1.0-alt1.x86_64",
        arch="x86_64",
        source_package="libfoo-src",
        purl="pkg:rpm/libfoo@libfoo-1.0-alt1.x86_64",
    )
    assert PackageRef.from_dict(ref.to_dict()) == ref


def test_package_ref_round_trip_optional_none() -> None:
    ref = PackageRef(backend="rpm", name="foo", version="foo-1.0-alt1.x86_64")
    assert ref.arch is None
    assert ref.source_package is None
    assert ref.purl is None
    restored = PackageRef.from_dict(ref.to_dict())
    assert restored == ref


def test_package_ref_to_dict_keys() -> None:
    ref = PackageRef(backend="rpm", name="foo", version="foo-1.0.x86_64")
    d = ref.to_dict()
    assert set(d.keys()) == {"backend", "name", "version", "arch", "source_package", "purl"}


def test_package_ref_from_dict_missing_optionals() -> None:
    d = {"backend": "rpm", "name": "foo", "version": "foo-1.0-alt1.x86_64"}
    ref = PackageRef.from_dict(d)
    assert ref.arch is None
    assert ref.source_package is None
    assert ref.purl is None


@pytest.mark.parametrize("backend,name,version", [
    ("rpm", "glibc", "glibc-2.33-alt9.x86_64"),
    ("dpkg", "libc6", "2.35-0ubuntu3"),
    ("rpm", "bash", "bash-5.2-alt1.noarch"),
])
def test_package_ref_round_trip_parametrized(backend: str, name: str, version: str) -> None:
    ref = PackageRef(backend=backend, name=name, version=version)
    assert PackageRef.from_dict(ref.to_dict()) == ref


# ── RpmBackend Protocol conformance ──────────────────────────────────────────

def test_rpm_backend_implements_protocol() -> None:
    assert isinstance(RpmBackend(), ProvenanceBackend)


def test_rpm_backend_name() -> None:
    assert RpmBackend.name == "rpm"


# ── available() / build_index() ──────────────────────────────────────────────

def test_available_false_before_build_index() -> None:
    b = RpmBackend()
    assert b.available() is False


def test_available_true_after_build_index() -> None:
    b = make_backend()
    assert b.available() is True


def test_build_index_skips_malformed_lines(tmp_path: Path) -> None:
    dump = tmp_path / "bad.txt"
    dump.write_text("just-one-field\n/path\tname\tnevra\n\n", encoding="utf-8")
    b = RpmBackend()
    b.build_index(dump)
    assert b.available() is True
    ref = b.lookup("/path", "")
    assert ref is not None and ref.name == "name"


# ── lookup() basic ────────────────────────────────────────────────────────────

def test_lookup_known_path() -> None:
    b = make_backend()
    ref = b.lookup("/usr/include/foo.h", "")
    assert ref is not None
    assert ref.name == "libfoo-devel"
    assert ref.version == "libfoo-devel-1.0-alt1.x86_64"
    assert ref.backend == "rpm"


def test_lookup_unknown_path_returns_none() -> None:
    b = make_backend()
    assert b.lookup("/not/in/dump.h", "") is None


def test_lookup_ignores_git_hash() -> None:
    b = make_backend()
    ref1 = b.lookup("/usr/bin/mytool", "")
    ref2 = b.lookup("/usr/bin/mytool", "abc123deadbeef")
    assert ref1 == ref2


# ── Symlink canonicalization: /lib64 ↔ /usr/lib64 ────────────────────────────

def test_symlink_lib64_short_to_long() -> None:
    """File registered as /lib64/… must also be found as /usr/lib64/…"""
    b = make_backend()
    ref_short = b.lookup("/lib64/libfoo.so.1", "")
    ref_long  = b.lookup("/usr/lib64/libfoo.so.1", "")
    assert ref_short is not None
    assert ref_long is not None
    assert ref_short == ref_long


def test_symlink_lib_short_to_long() -> None:
    """File registered as /lib/… must also be found as /usr/lib/…"""
    b = make_backend()
    ref_short = b.lookup("/lib/libbar.so.2", "")
    ref_long  = b.lookup("/usr/lib/libbar.so.2", "")
    assert ref_short is not None
    assert ref_long is not None
    assert ref_short == ref_long


def test_symlink_bin_short_to_long() -> None:
    b = make_backend()
    ref_short = b.lookup("/bin/sh", "")
    ref_long  = b.lookup("/usr/bin/sh", "")
    assert ref_short is not None
    assert ref_long is not None
    assert ref_short == ref_long


def test_symlink_lib64_long_registered_found_as_short() -> None:
    """/usr/lib64/libbaz.a registered under long form → also found via /lib64/…"""
    b = make_backend()
    ref_long  = b.lookup("/usr/lib64/libbaz.a", "")
    ref_short = b.lookup("/lib64/libbaz.a", "")
    assert ref_long is not None
    assert ref_short is not None
    assert ref_long == ref_short


# ── PackageRef fields populated by lookup() ──────────────────────────────────

def test_lookup_arch_parsed_from_nevra() -> None:
    b = make_backend()
    ref = b.lookup("/usr/bin/mytool", "")
    assert ref is not None
    assert ref.arch == "x86_64"


def test_lookup_noarch_parsed() -> None:
    b = make_backend()
    ref = b.lookup("/usr/lib64/libbaz.a", "")
    assert ref is not None
    assert ref.arch == "noarch"


def test_lookup_purl_constructed() -> None:
    b = make_backend()
    ref = b.lookup("/usr/bin/mytool", "")
    assert ref is not None
    assert ref.purl == "pkg:rpm/mytool@mytool-2.5-alt3.x86_64"


def test_lookup_source_package_is_none() -> None:
    b = make_backend()
    ref = b.lookup("/usr/bin/mytool", "")
    assert ref is not None
    assert ref.source_package is None


# ── Equivalence with original load_rpm_dump logic ────────────────────────────

def _reference_load_rpm_dump(dump_file: Path) -> dict[str, tuple[str, str]]:
    """Reference reimplementation of the original enrich.load_rpm_dump() logic.

    After T1.4, load_rpm_dump() was removed from enrich.py and its logic moved
    into RpmBackend.  This local copy preserves the pre-T1.4 behaviour for the
    equivalence test.
    """
    ALIAS_PREFIXES = {
        "/lib/":   "/usr/lib/",
        "/lib64/": "/usr/lib64/",
        "/bin/":   "/usr/bin/",
        "/sbin/":  "/usr/sbin/",
    }
    path_to_pkg: dict[str, tuple[str, str]] = {}
    with open(dump_file, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) != 3:
                continue
            filepath, rpm_name, rpm_nevra = parts
            if not filepath:
                continue
            pkg: tuple[str, str] = (rpm_name, rpm_nevra)
            path_to_pkg[filepath] = pkg
            for short, long_ in ALIAS_PREFIXES.items():
                if filepath.startswith(short):
                    path_to_pkg[long_ + filepath[len(short):]] = pkg
                elif filepath.startswith(long_):
                    path_to_pkg[short + filepath[len(long_):]] = pkg
    return path_to_pkg


def test_equivalence_with_enrich_load_rpm_dump() -> None:
    """The index built by RpmBackend must be identical to the original load_rpm_dump().

    After T1.4, load_rpm_dump() moved into RpmBackend.  The reference
    implementation above captures the pre-T1.4 logic for this comparison.
    """
    enrich_index = _reference_load_rpm_dump(MINI_DUMP)

    b = make_backend()
    rpm_index = b.index_as_dict()

    assert rpm_index == enrich_index


# ── Rebuild clears old state ──────────────────────────────────────────────────

def test_rebuild_replaces_index(tmp_path: Path) -> None:
    dump1 = tmp_path / "d1.txt"
    dump1.write_text("/usr/bin/a\tpkgA\tpkgA-1.0-alt1.x86_64\n", encoding="utf-8")
    dump2 = tmp_path / "d2.txt"
    dump2.write_text("/usr/bin/b\tpkgB\tpkgB-2.0-alt1.x86_64\n", encoding="utf-8")

    b = RpmBackend()
    b.build_index(dump1)
    assert b.lookup("/usr/bin/a", "") is not None
    assert b.lookup("/usr/bin/b", "") is None

    b.build_index(dump2)
    assert b.lookup("/usr/bin/a", "") is None
    assert b.lookup("/usr/bin/b", "") is not None
