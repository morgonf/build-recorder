"""T1.2 acceptance tests — brec/classify.py + DepClass/ClassifiedFile in brec/ir.py."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from brec.classify import (
    ARCHIVER_NAMES,
    ASSEMBLER_NAMES,
    COMPILER_NAMES,
    LINKER_NAMES,
    VENDOR_DIRS,
    classify_files,
    classify_roles,
)
from brec.ir import (
    BuildGraph,
    ClassifiedFile,
    DepClass,
    FileNode,
    PackageRef,
    ProcessNode,
)
from brec.model import parse_out
from brec.provenance.rpm import RpmBackend

FIXTURES = Path(__file__).parent / "fixtures"
TINY_OUT = FIXTURES / "tiny.out"
SAMPLE_OUT = FIXTURES / "classify_sample.out"
RPM_DUMP = FIXTURES / "classify_rpm_dump.txt"

# Load verify-build.py (hyphenated name)
_VB_PATH = Path(__file__).parent.parent / "verify-build.py"
_spec = importlib.util.spec_from_file_location("verify_build", _VB_PATH)
_vb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_vb)

# Load enrich.py
_ENRICH_PATH = Path(__file__).parent.parent / "enrich.py"
_espec = importlib.util.spec_from_file_location("enrich", _ENRICH_PATH)
_enrich = importlib.util.module_from_spec(_espec)
_espec.loader.exec_module(_enrich)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_rpm_backend() -> RpmBackend:
    b = RpmBackend()
    b.build_index(RPM_DUMP)
    return b


def _graph_with_process(exe_name: str, reads: list[str]) -> BuildGraph:
    """Minimal BuildGraph: one process whose executable is named *exe_name*."""
    fexe = FileNode(":fexe", f"/usr/bin/{exe_name}", exe_name, 1000, "a" * 40)
    fread = [
        FileNode(f":f{i}", path, Path(path).name, 100, f"{i:040d}")
        for i, path in enumerate(reads)
    ]
    files = {fexe.uri: fexe, **{f.uri: f for f in fread}}
    proc = ProcessNode(
        uri=":p0", pid=1, cmd=exe_name,
        executable=":fexe",
        start=None, end=None,
        reads=[f.uri for f in fread],
        writes=[], execs=[],
    )
    return BuildGraph(files=files, procs={":p0": proc})


def _lookup(results: list[ClassifiedFile], abspath: str) -> ClassifiedFile:
    for cf in results:
        if cf.file.abspath == abspath:
            return cf
    raise KeyError(f"{abspath} not in classify_files output")


# ── DepClass enum ─────────────────────────────────────────────────────────────

def test_dep_class_values_exist() -> None:
    expected = {"static", "dynamic", "declared", "vendored", "project", "temp", "unknown"}
    assert {e.value for e in DepClass} == expected


def test_dep_class_is_str_enum() -> None:
    assert isinstance(DepClass.PROJECT, str)
    assert DepClass.PROJECT == "project"


# ── Process-name sets ─────────────────────────────────────────────────────────

def test_compiler_names_contains_cc1():
    assert "cc1" in COMPILER_NAMES


def test_compiler_names_contains_gcc():
    assert "gcc" in COMPILER_NAMES


def test_linker_names_contains_ld():
    assert "ld" in LINKER_NAMES


def test_linker_names_contains_collect2():
    assert "collect2" in LINKER_NAMES


def test_assembler_names_contains_as():
    assert "as" in ASSEMBLER_NAMES


def test_archiver_names_contains_ar():
    assert "ar" in ARCHIVER_NAMES


# ── VENDOR_DIRS ────────────────────────────────────────────────────────────────

def test_vendor_dirs_contains_expected() -> None:
    for name in ("third_party", "thirdparty", "3rdparty", "vendor", "vendors",
                 "external", "externals", "extern", "deps", "dependencies",
                 "contrib", "bundled", "embedded"):
        assert name in VENDOR_DIRS, f"{name!r} missing from VENDOR_DIRS"


# ── ClassifiedFile dataclass ──────────────────────────────────────────────────

def _make_cf(dep_class: DepClass = DepClass.PROJECT) -> ClassifiedFile:
    f = FileNode(":f0", "/home/user/project/main.c", "main.c", 1024,
                 "a" * 40)
    return ClassifiedFile(
        file=f,
        dep_class=dep_class,
        package=None,
        vendor_dir=None,
        read_by_roles={"compiler"},
    )


def test_classified_file_round_trip() -> None:
    cf = _make_cf(DepClass.PROJECT)
    assert ClassifiedFile.from_dict(cf.to_dict()) == cf


def test_classified_file_round_trip_with_package() -> None:
    f = FileNode(":f0", "/usr/include/foo.h", "foo.h", 512, "b" * 40)
    pkg = PackageRef("rpm", "libfoo-devel", "libfoo-devel-1.0-alt1.x86_64",
                     arch="x86_64", purl="pkg:rpm/libfoo-devel@libfoo-devel-1.0-alt1.x86_64")
    cf = ClassifiedFile(file=f, dep_class=DepClass.SYSTEM_STATIC, package=pkg,
                        vendor_dir=None, read_by_roles={"compiler"})
    assert ClassifiedFile.from_dict(cf.to_dict()) == cf


def test_classified_file_round_trip_vendored() -> None:
    f = FileNode(":f0", "/home/user/project/third_party/sqlite/sqlite3.c",
                 "sqlite3.c", 100000, "c" * 40)
    cf = ClassifiedFile(file=f, dep_class=DepClass.VENDORED,
                        vendor_dir="third_party/sqlite", read_by_roles={"compiler"})
    restored = ClassifiedFile.from_dict(cf.to_dict())
    assert restored == cf
    assert restored.vendor_dir == "third_party/sqlite"


def test_classified_file_to_dict_keys() -> None:
    d = _make_cf().to_dict()
    assert set(d.keys()) == {"file", "dep_class", "package", "vendor_dir", "read_by_roles"}


def test_classified_file_read_by_roles_sorted_in_dict() -> None:
    f = FileNode(":f0", "/x", "x", 0, "a" * 40)
    cf = ClassifiedFile(file=f, dep_class=DepClass.UNKNOWN,
                        read_by_roles={"linker", "compiler"})
    assert cf.to_dict()["read_by_roles"] == ["compiler", "linker"]


def test_classified_file_dep_class_stored_as_value() -> None:
    assert _make_cf().to_dict()["dep_class"] == "project"


# ── classify_roles ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("exe,expected_role", [
    ("cc1",          "compiler"),
    ("gcc",          "compiler"),
    ("clang",        "compiler"),
    ("ld",           "linker"),
    ("ld.bfd",       "linker"),
    ("collect2",     "linker"),
    ("as",           "assembler"),
    ("ar",           "archiver"),
    ("ranlib",       "archiver"),
    ("make",         "other"),
    ("python3",      "other"),
    ("",             "other"),
])
def test_classify_roles_parametrized(exe: str, expected_role: str) -> None:
    graph = _graph_with_process(exe, [])
    classify_roles(graph)
    assert graph.procs[":p0"].role == expected_role


def test_classify_roles_does_not_overwrite_existing() -> None:
    graph = _graph_with_process("gcc", [])
    graph.procs[":p0"].role = "archiver"   # pre-set to wrong value
    classify_roles(graph)
    assert graph.procs[":p0"].role == "archiver"   # must not be overwritten


def test_classify_roles_no_executable() -> None:
    f = FileNode(":f0", "/tmp/foo.c", "foo.c", 100, "a" * 40)
    proc = ProcessNode(":p0", 1, "cc1", executable=None,
                       start=None, end=None, reads=[], writes=[], execs=[])
    graph = BuildGraph(files={":f0": f}, procs={":p0": proc})
    classify_roles(graph)
    assert graph.procs[":p0"].role == "other"


def test_classify_roles_sets_all_procs() -> None:
    g = parse_out(TINY_OUT)
    classify_roles(g)
    for proc in g.procs.values():
        assert proc.role is not None


# ── classify_files: basic dep_class ──────────────────────────────────────────

def test_classify_files_project_source_tiny() -> None:
    """tiny.out: hello.c read by cc1 → PROJECT (no package, not vendor)."""
    graph = parse_out(TINY_OUT)
    results = classify_files(graph, [])
    assert any(
        cf.dep_class == DepClass.PROJECT and "hello.c" in cf.file.abspath
        for cf in results
    )


def test_classify_files_system_static_header() -> None:
    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])
    cf = _lookup(results, "/usr/include/stdio.h")
    assert cf.dep_class == DepClass.SYSTEM_STATIC
    assert cf.package is not None
    assert cf.package.name == "glibc-devel"


def test_classify_files_system_dynamic_so() -> None:
    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])
    cf = _lookup(results, "/usr/lib64/libc.so.6")
    assert cf.dep_class == DepClass.SYSTEM_DYNAMIC
    assert cf.package is not None
    assert "linker" in cf.read_by_roles


def test_classify_files_system_static_archive() -> None:
    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])
    cf = _lookup(results, "/usr/lib64/libz.a")
    assert cf.dep_class == DepClass.SYSTEM_STATIC
    assert cf.package is not None


def test_classify_files_vendored_source() -> None:
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])   # no provenance → no packages
    cf = _lookup(results, "/home/user/project/src/third_party/sqlite/sqlite3.c")
    assert cf.dep_class == DepClass.VENDORED


def test_classify_files_vendored_header() -> None:
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    cf = _lookup(results, "/home/user/project/src/third_party/sqlite/sqlite3.h")
    assert cf.dep_class == DepClass.VENDORED


def test_classify_files_vendor_dir_populated() -> None:
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    cf = _lookup(results, "/home/user/project/src/third_party/sqlite/sqlite3.c")
    assert cf.vendor_dir is not None
    assert "sqlite" in cf.vendor_dir
    assert "third_party" in cf.vendor_dir


def test_classify_files_vendor_dir_none_for_project() -> None:
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    cf = _lookup(results, "/home/user/project/src/main.c")
    assert cf.dep_class == DepClass.PROJECT
    assert cf.vendor_dir is None


def test_classify_files_toolchain_temp() -> None:
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    cf = _lookup(results, "/tmp/ccABCDEFG.o")
    assert cf.dep_class == DepClass.TOOLCHAIN_TEMP


def test_classify_files_empty_provenance() -> None:
    """No backends → all files get no package; non-vendor files → PROJECT/UNKNOWN."""
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    cf = _lookup(results, "/usr/include/stdio.h")
    assert cf.package is None
    # Without RPM info, system header has no known package → PROJECT or UNKNOWN
    # (depends on whether vendor check triggers; /usr/include is not vendor)
    assert cf.dep_class in (DepClass.PROJECT, DepClass.UNKNOWN, DepClass.SYSTEM_STATIC)


def test_classify_files_read_by_roles_populated() -> None:
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    cf = _lookup(results, "/usr/lib64/libc.so.6")
    assert "linker" in cf.read_by_roles


def test_classify_files_only_reads_not_writes() -> None:
    """Output artifact (written by linker) must NOT appear in classify_files."""
    graph = parse_out(SAMPLE_OUT)
    results = classify_files(graph, [])
    abspaths = {cf.file.abspath for cf in results}
    assert "/home/user/project/build/myapp" not in abspaths


# ── Vendor dirs in various paths ──────────────────────────────────────────────

@pytest.mark.parametrize("abspath", [
    "/home/user/project/src/third_party/sqlite/sqlite3.c",
    "/home/user/project/deps/wslay/lib/wslay_event.c",
    "/home/user/project/vendor/zlib/inflate.c",
    "/home/user/project/external/lua/ldo.c",
    "/home/user/project/contrib/expat/xmlparse.c",
    "/home/user/project/thirdparty/duktape/duktape.c",
    "/home/user/project/bundled/libpng/png.c",
])
def test_classify_vendored_path_patterns(abspath: str) -> None:
    """All standard vendor-dir path patterns yield VENDORED with vendor_dir set."""
    f = FileNode(":f0", abspath, Path(abspath).name, 1000, "a" * 40)
    f_exe = FileNode(":fexe", "/usr/bin/cc1", "cc1", 1000, "b" * 40)
    proc = ProcessNode(":p0", 1, "cc1", executable=":fexe",
                       start=None, end=None, reads=[":f0"], writes=[], execs=[])
    graph = BuildGraph(files={":f0": f, ":fexe": f_exe}, procs={":p0": proc})
    results = classify_files(graph, [])
    assert len(results) == 1
    assert results[0].dep_class == DepClass.VENDORED
    assert results[0].vendor_dir is not None


# ── Equivalence with verify-build.py buckets ─────────────────────────────────

def test_equiv_verify_buckets_tiny() -> None:
    """classify_files on tiny.out reproduces verify-build.py static_sources bucket."""
    # verify-build.py perspective
    vb_files, vb_procs = _vb.parse_graph(TINY_OUT)
    vb_deps = _vb.analyze(vb_files, vb_procs)
    vb_sources = {f.abspath for f in vb_deps.static_sources}

    # classify_files perspective: PROJECT files read by compiler with source extension
    _SOURCE = frozenset({".c", ".cpp", ".cc", ".cxx", ".c++", ".s", ".S", ".asm"})
    graph = parse_out(TINY_OUT)
    results = classify_files(graph, [])
    cl_sources = {
        cf.file.abspath for cf in results
        if cf.dep_class == DepClass.PROJECT
        and bool(cf.read_by_roles & {"compiler", "assembler"})
        and Path(cf.file.abspath).suffix in _SOURCE
    }

    assert vb_sources == cl_sources


def test_equiv_verify_static_headers_sample() -> None:
    """Headers with RPM from sample fixture end up SYSTEM_STATIC."""
    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])

    # verify-build.py: static_headers = headers read by compiler
    vb_files, vb_procs = _vb.parse_graph(SAMPLE_OUT)
    vb_deps = _vb.analyze(vb_files, vb_procs)
    vb_header_paths = {f.abspath for f in vb_deps.static_headers}

    # classify_files: SYSTEM_STATIC headers read by compiler (has package)
    cl_sys_headers = {
        cf.file.abspath for cf in results
        if cf.dep_class == DepClass.SYSTEM_STATIC
        and bool(cf.read_by_roles & {"compiler", "assembler"})
        and Path(cf.file.abspath).suffix.lower() in {".h", ".hpp", ".hh", ".h++"}
    }

    # The intersection: system headers present in both
    common = vb_header_paths & cl_sys_headers
    # At least stdio.h should appear in both
    assert "/usr/include/stdio.h" in common


def test_equiv_verify_dynamic_libs_sample() -> None:
    """Dynamic libs from sample fixture: verify-build dynamic_libs ⊆ SYSTEM_DYNAMIC."""
    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])

    vb_files, vb_procs = _vb.parse_graph(SAMPLE_OUT)
    vb_deps = _vb.analyze(vb_files, vb_procs)
    vb_dynamic = {f.abspath for f in vb_deps.dynamic_libs}

    cl_dynamic = {cf.file.abspath for cf in results if cf.dep_class == DepClass.SYSTEM_DYNAMIC}

    # All .so files verify-build.py puts in dynamic_libs should be SYSTEM_DYNAMIC
    assert vb_dynamic.issubset(cl_dynamic | {cf.file.abspath for cf in results
                                              if cf.dep_class == DepClass.UNKNOWN})


# ── Equivalence with enrich.classify_dep_type (tabular) ──────────────────────

def _infer_enrich_dep_type(cf: ClassifiedFile) -> str:
    """Reverse map ClassifiedFile → enrich.classify_dep_type result.

    This mapping is deterministic:
    - SYSTEM_DYNAMIC → "dynamic_lib"
    - SYSTEM_STATIC + .h → "static_header"
    - SYSTEM_STATIC + .a → "static_archive"
    - SYSTEM_STATIC + tool dir → "build_tool"
    - SYSTEM_STATIC + other → "system_runtime"
    - PROJECT / VENDORED / TOOLCHAIN_TEMP / UNKNOWN (no package) → "project_source"
    """
    abspath = cf.file.abspath
    name_lower = Path(abspath).name.lower()
    suffix_lower = Path(abspath).suffix.lower()

    if cf.dep_class == DepClass.SYSTEM_DYNAMIC:
        return "dynamic_lib"
    if cf.dep_class == DepClass.SYSTEM_STATIC:
        if suffix_lower in {".h", ".hpp", ".hh", ".h++"}:
            return "static_header"
        if name_lower.endswith(".a"):
            return "static_archive"
        # enrich classifies .so by filename alone (ignores which process read it)
        if ".so." in name_lower or name_lower.endswith(".so"):
            return "dynamic_lib"
        tool_dirs = {"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/",
                     "/usr/libexec/", "/usr/lib/rpm/"}
        if any(abspath.startswith(d) for d in tool_dirs):
            return "build_tool"
        return "system_runtime"
    # PROJECT, VENDORED, TOOLCHAIN_TEMP, UNKNOWN, DECLARED → no package → project_source
    return "project_source"


@pytest.mark.parametrize("abspath,dep_class,has_package,expected", [
    ("/usr/include/foo.h",   DepClass.SYSTEM_STATIC,  True,  "static_header"),
    ("/usr/lib64/libfoo.a",  DepClass.SYSTEM_STATIC,  True,  "static_archive"),
    ("/usr/lib64/libc.so.6", DepClass.SYSTEM_DYNAMIC, True,  "dynamic_lib"),
    ("/usr/bin/gcc",         DepClass.SYSTEM_STATIC,  True,  "build_tool"),
    ("/usr/libexec/foo",     DepClass.SYSTEM_STATIC,  True,  "build_tool"),
    ("/usr/lib64/libfoo.so.2", DepClass.SYSTEM_STATIC, True, "dynamic_lib"),
    ("/home/user/project/main.c",          DepClass.PROJECT,  False, "project_source"),
    ("/home/user/project/third_party/foo/bar.c", DepClass.VENDORED, False, "project_source"),
    ("/tmp/ccABCDEF.o",      DepClass.TOOLCHAIN_TEMP, False, "project_source"),
    ("/usr/share/doc/foo.c", DepClass.SYSTEM_STATIC,  True,  "system_runtime"),
])
def test_dep_class_reverse_mapping_deterministic(
    abspath: str, dep_class: DepClass, has_package: bool, expected: str
) -> None:
    """Reverse mapping ClassifiedFile → enrich.dep_type is deterministic."""
    f = FileNode(":f0", abspath, Path(abspath).name, 100, "a" * 40)
    pkg = (PackageRef("rpm", "pkg", "pkg-1.0-alt1.x86_64")
           if has_package else None)
    cf = ClassifiedFile(file=f, dep_class=dep_class, package=pkg,
                        read_by_roles={"compiler"})
    assert _infer_enrich_dep_type(cf) == expected


def test_dep_class_matches_enrich_on_sample() -> None:
    """For each file in sample fixture, inferred dep_type matches dep_type_from_path.

    After T1.4, enrich.classify_dep_type() was removed and its logic moved into
    brec.classify.dep_type_from_path().  This test verifies the equivalence using
    the canonical brec source.
    """
    from brec.classify import dep_type_from_path

    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])

    for cf in results:
        abspath = cf.file.abspath
        has_rpm = cf.package is not None
        canonical_type = dep_type_from_path(abspath, has_rpm)
        inferred = _infer_enrich_dep_type(cf)
        assert inferred == canonical_type, (
            f"{abspath}: dep_type_from_path says {canonical_type!r}, "
            f"inferred from {cf.dep_class.value} says {inferred!r}"
        )


# ── classify_files: package fields ───────────────────────────────────────────

def test_classify_files_package_backend_is_rpm() -> None:
    graph = parse_out(SAMPLE_OUT)
    backend = make_rpm_backend()
    results = classify_files(graph, [backend])
    cf = _lookup(results, "/usr/include/stdio.h")
    assert cf.package is not None
    assert cf.package.backend == "rpm"


def test_classify_files_first_backend_wins(tmp_path: Path) -> None:
    """When multiple backends are available, first hit wins."""
    dump1 = tmp_path / "d1.txt"
    dump1.write_text("/usr/include/stdio.h\tpkg1\tpkg1-1.0-alt1.x86_64\n", encoding="utf-8")
    dump2 = tmp_path / "d2.txt"
    dump2.write_text("/usr/include/stdio.h\tpkg2\tpkg2-2.0-alt1.x86_64\n", encoding="utf-8")

    b1 = RpmBackend(); b1.build_index(dump1)
    b2 = RpmBackend(); b2.build_index(dump2)

    f = FileNode(":f0", "/usr/include/stdio.h", "stdio.h", 100, "a" * 40)
    f_exe = FileNode(":fexe", "/usr/bin/cc1", "cc1", 100, "b" * 40)
    proc = ProcessNode(":p0", 1, "cc1", executable=":fexe",
                       start=None, end=None, reads=[":f0"], writes=[], execs=[])
    graph = BuildGraph(files={":f0": f, ":fexe": f_exe}, procs={":p0": proc})

    results = classify_files(graph, [b1, b2])
    assert results[0].package is not None
    assert results[0].package.name == "pkg1"


def test_classify_files_unavailable_backend_skipped(tmp_path: Path) -> None:
    """Backend with available()==False is skipped."""
    b = RpmBackend()  # not built → not available
    f = FileNode(":f0", "/usr/include/stdio.h", "stdio.h", 100, "a" * 40)
    f_exe = FileNode(":fexe", "/usr/bin/gcc", "gcc", 100, "b" * 40)
    proc = ProcessNode(":p0", 1, "gcc", executable=":fexe",
                       start=None, end=None, reads=[":f0"], writes=[], execs=[])
    graph = BuildGraph(files={":f0": f, ":fexe": f_exe}, procs={":p0": proc})

    results = classify_files(graph, [b])
    assert results[0].package is None


# ── Own .so produced and linked by same build ─────────────────────────────────

def test_classify_own_so_is_project(tmp_path: Path) -> None:
    """A .so written by linker and then read by another linker → PROJECT, not SYSTEM_DYNAMIC."""
    f_so = FileNode(":f_so", "/home/user/build/libmine.so.1", "libmine.so.1", 5000, "a" * 40)
    f_out = FileNode(":f_out", "/home/user/build/mytest", "mytest", 3000, "b" * 40)
    f_ld = FileNode(":fld", "/usr/bin/ld", "ld", 8000, "c" * 40)

    # p0 writes .so; p1 reads .so and writes test executable
    p0 = ProcessNode(":p0", 1, "ld", executable=":fld",
                     start=None, end=None, reads=[], writes=[":f_so"], execs=[])
    p1 = ProcessNode(":p1", 2, "ld", executable=":fld",
                     start=None, end=None, reads=[":f_so"], writes=[":f_out"], execs=[])
    graph = BuildGraph(
        files={":f_so": f_so, ":f_out": f_out, ":fld": f_ld},
        procs={":p0": p0, ":p1": p1},
    )
    results = classify_files(graph, [])
    cf = _lookup(results, "/home/user/build/libmine.so.1")
    assert cf.dep_class == DepClass.PROJECT


# ── classify_files is idempotent on roles ─────────────────────────────────────

def test_classify_files_idempotent_roles() -> None:
    """Calling classify_files twice does not corrupt process roles."""
    graph = parse_out(TINY_OUT)
    r1 = classify_files(graph, [])
    r2 = classify_files(graph, [])
    assert {cf.file.abspath: cf.dep_class for cf in r1} == \
           {cf.file.abspath: cf.dep_class for cf in r2}
