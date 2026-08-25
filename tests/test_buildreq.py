"""Tests for brec.buildreq — declared BuildRequires versus packages actually read."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.buildreq import (
    audit,
    dependency_closure,
    dependency_depths,
    observed_usage,
    parse_declared,
    parse_rpm_deps,
    resolve_caps,
    strip_constraint,
)
from brec.model import parse_out
from brec.provenance.rpm import RpmBackend

# Load the hyphenated CLI as a module, same trick as test_provenance_verdict.py.
_spec = importlib.util.spec_from_file_location(
    "buildreq_audit", Path(__file__).parent.parent / "buildreq-audit.py"
)
bra = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = bra
_spec.loader.exec_module(bra)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_out(fixtures_dir: Path) -> Path:
    return fixtures_dir / "buildreq_sample.out"


@pytest.fixture
def declared_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "buildreq_declared.txt"


@pytest.fixture
def rpm_deps_file(fixtures_dir: Path) -> Path:
    return fixtures_dir / "buildreq_rpm_deps.txt"


@pytest.fixture
def rpm_dump(fixtures_dir: Path) -> Path:
    return fixtures_dir / "rpm_dump_mini.txt"


def _run(sample_out: Path, declared_file: Path, rpm_dump: Path,
         rpm_deps_file: Path | None = None, implicit=()):
    graph = parse_out(sample_out)
    declared = parse_declared(declared_file)
    provides, requires = parse_rpm_deps(rpm_deps_file) if rpm_deps_file else ({}, {})
    package_of, file_lookup = bra.make_resolvers(graph, rpm_dump)
    return audit(
        graph,
        declared=declared,
        provides=provides,
        requires=requires,
        package_of=package_of,
        file_lookup=file_lookup,
        implicit=implicit,
    )


# ── Parsing ──────────────────────────────────────────────────────────────────

def test_strip_constraint():
    assert strip_constraint("libfoo-devel >= 1.2") == "libfoo-devel"
    assert strip_constraint("  gcc  ") == "gcc"
    assert strip_constraint("") == ""


def test_parse_declared_drops_comments_pseudo_caps_and_duplicates(declared_file: Path):
    caps = parse_declared(declared_file)
    assert caps == ["mytool", "libfoo-devel", "libbar-devel", "/bin/sh"]
    assert not any(c.startswith("rpmlib(") for c in caps)


def test_parse_rpm_deps(rpm_deps_file: Path):
    provides, requires = parse_rpm_deps(rpm_deps_file)
    assert provides["mytool"] == {"mytool"}
    assert requires["mytool"] == {"libbaz-devel"}
    assert "libbaz" in requires["libbaz-devel"]


def test_parse_rpm_deps_skips_malformed(tmp_path: Path):
    path = tmp_path / "deps.txt"
    path.write_text("P\tonly-two-fields\nP\tcap\tpkg\ngarbage\n", encoding="utf-8")
    provides, requires = parse_rpm_deps(path)
    assert provides == {"cap": {"pkg"}}
    assert requires == {}


# ── Resolution ───────────────────────────────────────────────────────────────

def test_resolve_caps_uses_file_index_for_path_capabilities(rpm_dump: Path):
    backend = RpmBackend()
    backend.build_index(rpm_dump)
    lookup = lambda p: (ref.name if (ref := backend.lookup(p, "")) else None)

    resolved, unresolved = resolve_caps(["/bin/sh", "nosuchcap"], {}, lookup)
    assert resolved == {"/bin/sh": {"bash"}}
    assert unresolved == ["nosuchcap"]


def test_resolve_caps_degraded_mode_assumes_package_name():
    resolved, unresolved = resolve_caps(["gcc"], {}, None, assume_cap_is_package=True)
    assert resolved == {"gcc": {"gcc"}}
    assert unresolved == []


def test_dependency_closure_follows_requires():
    provides = {"a": {"a"}, "b": {"b"}, "c": {"c"}}
    requires = {"a": {"b"}, "b": {"c"}}
    assert dependency_closure({"a"}, provides, requires) == {"a", "b", "c"}


def test_dependency_closure_survives_missing_provider():
    provides = {"a": {"a"}}
    requires = {"a": {"not-installed"}}
    assert dependency_closure({"a"}, provides, requires) == {"a"}


def test_dependency_closure_terminates_on_cycle():
    provides = {"a": {"a"}, "b": {"b"}}
    requires = {"a": {"b"}, "b": {"a"}}
    assert dependency_closure({"a"}, provides, requires) == {"a", "b"}


# ── Observation ──────────────────────────────────────────────────────────────

def test_observed_usage_counts_executables_and_skips_written_files(
    sample_out: Path, rpm_dump: Path
):
    graph = parse_out(sample_out)
    package_of, _ = bra.make_resolvers(graph, rpm_dump)
    used = observed_usage(graph, package_of)

    # mytool is only ever exec'd, never read as a file: it must still count.
    assert "mytool" in used
    assert used["mytool"].files == ["/usr/bin/mytool"]
    # /usr/libexec/helper is read but the build wrote it: not an input.
    assert "mypkg" not in used
    # A project source belongs to no package and contributes nothing.
    assert all("/build/src/main.c" not in u.files for u in used.values())


# ── Audit ────────────────────────────────────────────────────────────────────

def test_audit_with_closure_separates_transitive_from_undeclared(
    sample_out, declared_file, rpm_dump, rpm_deps_file
):
    rep = _run(sample_out, declared_file, rpm_dump, rpm_deps_file)

    assert [u.name for u in rep.used_declared] == ["libfoo-devel", "mytool"]
    # libbaz-devel was never declared, but mytool requires it: legal, fragile.
    assert [u.name for u in rep.used_transitive] == ["libbaz-devel"]
    assert rep.used_undeclared == []
    # Declared and never opened.
    assert [d.cap for d in rep.declared_unused] == ["/bin/sh"]
    # Nothing installed provides libbar-devel: it is not in this build root.
    assert rep.unresolved_caps == ["libbar-devel"]
    assert rep.have_closure is True


def test_audit_without_closure_reports_transitive_use_as_undeclared(
    sample_out, declared_file, rpm_dump
):
    rep = _run(sample_out, declared_file, rpm_dump)

    assert [u.name for u in rep.used_undeclared] == ["libbaz-devel"]
    assert rep.used_transitive == []
    assert rep.have_closure is False
    # Degraded mode takes capability names for package names.
    assert {d.cap for d in rep.declared_unused} == {"/bin/sh", "libbar-devel"}


def test_audit_implicit_packages_are_excluded_but_reported(
    sample_out, declared_file, rpm_dump
):
    rep = _run(sample_out, declared_file, rpm_dump, implicit=["libbaz-devel"])
    assert rep.used_undeclared == []
    assert "libbaz-devel" in rep.implicit


def test_audit_counts_match_the_lists(sample_out, declared_file, rpm_dump, rpm_deps_file):
    rep = _run(sample_out, declared_file, rpm_dump, rpm_deps_file)
    listed = rep.used_declared + rep.used_transitive + rep.used_undeclared
    assert rep.packages_read == len(listed)
    assert rep.files_read == sum(u.count for u in listed)


def test_report_json_is_serialisable(sample_out, declared_file, rpm_dump, rpm_deps_file):
    import json

    rep = _run(sample_out, declared_file, rpm_dump, rpm_deps_file)
    payload = json.loads(json.dumps(rep.to_dict(max_files=2)))
    assert payload["summary"]["packages_read"] == rep.packages_read
    assert payload["summary"]["closure_available"] is True
    assert payload["used_transitive"][0]["package"] == "libbaz-devel"


def test_enriched_trace_needs_no_rpm_dump(fixtures_dir: Path, tmp_path: Path):
    """Attribution baked in by enrich.py is enough: the audit runs offline."""
    out = tmp_path / "enriched.out"
    out.write_text(
        "@prefix : <http://build-recorder.org/data#> .\n"
        "@prefix b: <http://build-recorder.org/rdf#> .\n"
        ":p0 a b:process .\n"
        ':p0 b:pid 1 .\n'
        ':p0 b:cmd "cc" .\n'
        ":f0 a b:file .\n"
        ':f0 b:abspath "/usr/include/zlib.h" .\n'
        ':f0 b:name "zlib.h" .\n'
        ":f0 b:size 10 .\n"
        ':f0 b:hash "cc00000000000000000000000000000000000001" .\n'
        ':f0 b:rpm_name "zlib-devel" .\n'
        ":p0 b:reads :f0 .\n",
        encoding="utf-8",
    )
    declared = tmp_path / "declared.txt"
    declared.write_text("zlib-devel\n", encoding="utf-8")

    graph = parse_out(out)
    package_of, file_lookup = bra.make_resolvers(graph, None)
    rep = audit(
        graph,
        declared=parse_declared(declared),
        provides={},
        requires={},
        package_of=package_of,
        file_lookup=file_lookup,
    )
    assert [u.name for u in rep.used_declared] == ["zlib-devel"]
    assert rep.used_undeclared == []


def test_cli_strict_exit_code(monkeypatch, sample_out, declared_file, rpm_dump, capsys):
    argv = [
        "buildreq-audit.py", str(sample_out),
        "--declared", str(declared_file),
        "--rpm-dump", str(rpm_dump),
        "--strict",
    ]
    monkeypatch.setattr(sys, "argv", argv)
    rc = bra.main()
    out = capsys.readouterr().out
    assert rc == 1                       # libbaz-devel is used and undeclared
    assert "USED, NOT DECLARED (1)" in out
    assert "libbaz-devel" in out


def test_cli_missing_input_file(monkeypatch, sample_out, rpm_dump, capsys):
    argv = [
        "buildreq-audit.py", str(sample_out),
        "--declared", str(sample_out.parent / "no-such-file.txt"),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    assert bra.main() == 2
    assert "not found" in capsys.readouterr().err


# ── Depth-bounded attribution ────────────────────────────────────────────────

def _trace_with(tmp_path: Path, files: list[tuple[str, str]]) -> Path:
    """Write a trace whose files carry rpm attribution already: (abspath, pkg)."""
    lines = [
        "@prefix : <http://build-recorder.org/data#> .",
        "@prefix b: <http://build-recorder.org/rdf#> .",
        ":p0 a b:process .",
        ":p0 b:pid 1 .",
        ':p0 b:cmd "build" .',
    ]
    for i, (abspath, pkg) in enumerate(files):
        lines += [
            f":f{i} a b:file .",
            f':f{i} b:abspath "{abspath}" .',
            f':f{i} b:name "{abspath.rsplit("/", 1)[-1]}" .',
            f":f{i} b:size 1 .",
            f':f{i} b:hash "{i:040d}" .',
            f':f{i} b:rpm_name "{pkg}" .',
            f":p0 b:reads :f{i} .",
        ]
    path = tmp_path / "trace.out"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _audit_chain(tmp_path: Path, read_pkg: str, depth: int):
    """Declare `head`, read *read_pkg*, over the chain head→a→b→c."""
    provides = {p: {p} for p in ("head", "a", "b", "c", "other")}
    requires = {"head": {"a"}, "a": {"b"}, "b": {"c"}}
    graph = parse_out(_trace_with(tmp_path, [(f"/usr/lib/{read_pkg}.so", read_pkg)]))
    return audit(
        graph,
        declared=["head"],
        provides=provides,
        requires=requires,
        package_of=lambda uri: graph.files[uri].rpm_name or None,
        attribution_depth=depth,
    )


def test_dependency_depths_reports_hops():
    provides = {"a": {"a"}, "b": {"b"}, "c": {"c"}}
    requires = {"a": {"b"}, "b": {"c"}}
    assert dependency_depths({"a"}, provides, requires) == {"a": 0, "b": 1, "c": 2}


def test_wrapper_package_counts_as_satisfied_indirectly(tmp_path: Path):
    """ALT's `gcc` is a wrapper: `gcc13` gets read, and that honours it."""
    rep = _audit_chain(tmp_path, read_pkg="a", depth=1)
    assert [d.cap for d in rep.declared_indirect] == ["head"]
    assert rep.declared_indirect[0].satisfied_by == ["a"]
    assert rep.declared_unused == []


def test_distant_declaration_stays_unused_at_default_depth(tmp_path: Path):
    """Three hops away is the toolchain, not evidence the declaration was used."""
    rep = _audit_chain(tmp_path, read_pkg="c", depth=1)
    assert [d.cap for d in rep.declared_unused] == ["head"]
    assert rep.declared_indirect == []
    # It is still implied, so it is not reported as undeclared use.
    assert rep.used_undeclared == []
    assert [u.name for u in rep.used_transitive] == ["c"]


def test_raising_attribution_depth_credits_the_declaration(tmp_path: Path):
    rep = _audit_chain(tmp_path, read_pkg="c", depth=3)
    assert [d.cap for d in rep.declared_indirect] == ["head"]
    assert rep.declared_unused == []


def test_implied_by_names_the_nearest_declaration(tmp_path: Path):
    """Every declaration can reach the toolchain; only the closest is credited."""
    provides = {p: {p} for p in ("near", "far", "target", "mid")}
    requires = {"near": {"target"}, "far": {"mid"}, "mid": {"target"}}
    graph = parse_out(_trace_with(tmp_path, [("/usr/lib/target.so", "target")]))
    rep = audit(
        graph,
        declared=["near", "far"],
        provides=provides,
        requires=requires,
        package_of=lambda uri: graph.files[uri].rpm_name or None,
    )
    assert [u.name for u in rep.used_transitive] == ["target"]
    assert rep.used_transitive[0].implied_by == ["near"]
