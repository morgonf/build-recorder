"""brec.classify — process-role classification and per-file dep_class assignment.

This module is the single authoritative source for:

  * ``COMPILER_NAMES`` / ``LINKER_NAMES`` / ``ASSEMBLER_NAMES`` / ``ARCHIVER_NAMES``
    — process-tool name sets (formerly in ``verify-build.py``).

  * ``VENDOR_DIRS``
    — vendor-directory segment names (formerly in ``sbom.py``).

  * ``classify_roles(graph)``
    — stamps ProcessNode.role in-place.

  * ``classify_files(graph, provenance)``
    — returns a ClassifiedFile for each read file in the graph.

The core (this module) does not import any distro-specific code: package
lookup is performed only through the ProvenanceBackend interface.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from brec.ir import BuildGraph, ClassifiedFile, DepClass, PackageRef

if TYPE_CHECKING:
    from brec.provenance.base import ProvenanceBackend

# ── Process-kind sets (single source of truth) ────────────────────────────────

COMPILER_NAMES: frozenset[str] = frozenset({
    "cc1", "cc1plus", "lto1", "lto-wrapper",
    "gcc", "g++", "gcc_wrapper",
    "x86_64-alt-linux-gcc-13", "x86_64-alt-linux-g++-13",
    "x86_64-alt-linux-gcc-14", "x86_64-alt-linux-g++-14",
    "clang", "clang++",
})
LINKER_NAMES: frozenset[str] = frozenset({
    "ld", "ld.bfd", "ld.gold", "ld.lld", "gold", "collect2",
})
ASSEMBLER_NAMES: frozenset[str] = frozenset({
    "as", "x86_64-alt-linux-as",
})
ARCHIVER_NAMES: frozenset[str] = frozenset({
    "ar", "ranlib",
    "x86_64-alt-linux-ar", "x86_64-alt-linux-ranlib",
    "x86_64-alt-linux-gcc-ar-13", "x86_64-alt-linux-gcc-ranlib-13",
    "x86_64-alt-linux-gcc-ar-14", "x86_64-alt-linux-gcc-ranlib-14",
})

# ── Vendor-directory segment names (single source of truth) ──────────────────

VENDOR_DIRS: frozenset[str] = frozenset({
    "third_party", "thirdparty", "3rdparty",
    "vendor", "vendors",
    "external", "externals", "extern",
    "deps", "dependencies",
    "contrib", "bundled", "embedded",
})

# ── Internal helpers ──────────────────────────────────────────────────────────

# Tool directories: executables here (with an OS package) = build_tool
_TOOL_DIRS: frozenset[str] = frozenset({
    "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/",
    "/usr/libexec/", "/usr/lib/rpm/",
})

# Temp/toolchain intermediate file patterns (from verify-build.py)
_TEMP_RE = re.compile(
    r"/(cc[0-9A-Za-z]{6,}\.(res|lto_wrapper_args|s|o)"
    r"|cmTC_[0-9a-f]+"
    r"|conftest|confcache|confdefs\.h|config\.log"
    r"|CMakeFiles/|TryCompile|CMakeTmp)"
)

_HEADER_EXTS: frozenset[str] = frozenset({".h", ".hpp", ".hh", ".h++"})
_C_SOURCE_EXTS: frozenset[str] = frozenset({".c", ".cpp", ".cc", ".cxx", ".c++"})
_ASSEMBLY_EXTS: frozenset[str] = frozenset({".s", ".asm"})

# What a compiler may be handed as a translation unit: C-family or assembly.
# ".S" is kept for the case-sensitive comparison in _dep_class_for().
_SOURCE_EXTS: frozenset[str] = _C_SOURCE_EXTS | _ASSEMBLY_EXTS | {".S"}

# Suffixes of files that are build *outputs*.  Deliberately excludes ".d":
# a make dependency file is bookkeeping about the build, not a product of it.
_ARTIFACT_EXTS: frozenset[str] = frozenset({
    ".so", ".a", ".la", ".dll", ".dylib", ".ko",
})


def _dep_class_for(
    abspath: str,
    furi: str,
    roles: set[str],
    package: Optional[PackageRef],
    written_uris: set[str],
) -> tuple[DepClass, Optional[str]]:
    """Determine DepClass and vendor_dir for a single file."""
    name_lower = Path(abspath).name.lower()
    suffix = Path(abspath).suffix

    # ── Toolchain temp files ──────────────────────────────────────────────────
    if _TEMP_RE.search(abspath):
        return DepClass.TOOLCHAIN_TEMP, None

    has_compiler = bool(roles & {"compiler", "assembler"})
    has_linker = "linker" in roles
    is_so = ".so." in name_lower or name_lower.endswith(".so")
    is_archive = name_lower.endswith(".a")
    is_header = suffix.lower() in _HEADER_EXTS
    is_source = suffix in _SOURCE_EXTS

    # ── .so read by linker ───────────────────────────────────────────────────
    if is_so and has_linker:
        if furi in written_uris:
            # Own .so produced by this build and then linked (e.g. for tests)
            return DepClass.PROJECT, None
        if package is not None:
            return DepClass.SYSTEM_DYNAMIC, None
        if is_vendor_path(abspath):
            return DepClass.VENDORED, vendor_dir(abspath)
        return DepClass.UNKNOWN, None

    # ── Static archive ───────────────────────────────────────────────────────
    if is_archive:
        if package is not None:
            return DepClass.SYSTEM_STATIC, None
        if is_vendor_path(abspath):
            return DepClass.VENDORED, vendor_dir(abspath)
        return DepClass.PROJECT, None

    # ── Header read by compiler/assembler ────────────────────────────────────
    if is_header and has_compiler:
        if package is not None:
            return DepClass.SYSTEM_STATIC, None
        if is_vendor_path(abspath):
            return DepClass.VENDORED, vendor_dir(abspath)
        return DepClass.PROJECT, None

    # ── Source file read by compiler/assembler ───────────────────────────────
    if is_source and has_compiler:
        if package is not None:
            return DepClass.SYSTEM_STATIC, None
        if is_vendor_path(abspath):
            return DepClass.VENDORED, vendor_dir(abspath)
        return DepClass.PROJECT, None

    # ── Executable / build tool (has OS package, in a tool directory) ────────
    if package is not None:
        for tdir in _TOOL_DIRS:
            if abspath.startswith(tdir):
                return DepClass.SYSTEM_STATIC, None

    # ── Vendor path without OS package ───────────────────────────────────────
    if package is None and is_vendor_path(abspath):
        return DepClass.VENDORED, vendor_dir(abspath)

    # ── Any remaining system file with a package ─────────────────────────────
    if package is not None:
        return DepClass.SYSTEM_STATIC, None

    return DepClass.UNKNOWN, None


# ── Public API ────────────────────────────────────────────────────────────────

def process_role(exe_abspath: str) -> str:
    """Return the role of the process running *exe_abspath*.

    Roles: ``compiler | linker | assembler | archiver | other``.
    """
    name = Path(exe_abspath).name
    if name in COMPILER_NAMES:
        return "compiler"
    if name in LINKER_NAMES:
        return "linker"
    if name in ASSEMBLER_NAMES:
        return "assembler"
    if name in ARCHIVER_NAMES:
        return "archiver"
    return "other"


def is_vendor_path(abspath: str) -> bool:
    """True when *abspath* lies inside a vendor / third-party directory."""
    parts = abspath.lower().replace("\\", "/").split("/")
    return any(p in VENDOR_DIRS for p in parts)


def vendor_dir(abspath: str) -> Optional[str]:
    """Return ``"<vendor_segment>/<component>"`` for *abspath*, else ``None``.

    ``None`` means either that the path is not vendored at all, or that the
    vendor segment is the final component and no component name follows it.
    """
    parts = abspath.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p.lower() in VENDOR_DIRS and i + 1 < len(parts):
            return f"{parts[i]}/{parts[i + 1]}"
    return None


def file_role(abspath: str) -> str:
    """Return what kind of file *abspath* is, judged by its name alone.

    Roles: ``dynamic_lib | static_archive | header | source | object |
    assembly | other``.  This is the extension-level question ("what is this
    file?"), kept apart from :func:`dep_type_from_path`, which also weighs
    package ownership, and from :func:`classify_files`, which weighs who read
    the file.  ``verify-build.py`` sorts its report by this role.
    """
    name = Path(abspath).name.lower()
    if ".so." in name or name.endswith(".so"):
        return "dynamic_lib"
    if name.endswith(".a"):
        return "static_archive"
    suffix = Path(name).suffix
    if suffix in _HEADER_EXTS:
        return "header"
    if suffix in _C_SOURCE_EXTS:
        return "source"
    if suffix == ".o":
        return "object"
    if suffix in _ASSEMBLY_EXTS:
        return "assembly"
    return "other"


def is_build_artifact(abspath: str) -> bool:
    """True when *abspath* is a meaningful build output.

    The single definition behind the artifact lists of ``verify-build.py`` and
    the artifact counts of ``provenance-verdict.py``.  Those two carried
    separate copies that had drifted apart, so the same ``.out`` file could
    yield two different artifact sets; two decisions settle that drift:

    * **Toolchain probes are never artifacts.**  ``conftest``, ``cmTC_*``,
      ``CMakeTmp`` and friends are extensionless executables, so without the
      temp filter every ``./configure`` run contributed dozens of them.  In
      ``provenance-verdict.py`` they landed in the denominator of *fidelity*,
      diluting it with files nobody ships.
    * **A ``.d`` file is not an artifact.**  ``verify-build.py`` used to list
      make dependency files among the outputs; they describe the build rather
      than result from it.  ``.ko``, previously known only to the verdict, is
      an artifact everywhere now.
    """
    if _TEMP_RE.search(abspath):
        return False
    name = Path(abspath).name
    if Path(name).suffix.lower() in _ARTIFACT_EXTS:
        return True
    if ".so." in name:                      # libfoo.so.2, libc.so.6
        return True
    return "." not in name and not name.startswith(".")   # bare executable


def dep_type_from_path(abspath: str, has_package: bool) -> str:
    """Return the ``b:dep_type`` string that ``enrich.py`` would write for a file.

    This is the path-only (process-context-free) variant of the classification
    used when annotating files without knowledge of which process read them.
    The logic mirrors ``enrich.classify_dep_type()`` exactly so that the RDF
    triples written by the refactored ``enrich.py`` are byte-identical.

    Mapping:

    * no package → ``"project_source"``
    * ``.h``/``.hpp``/… → ``"static_header"``
    * ``.so``/``.so.N`` → ``"dynamic_lib"``
    * ``.a`` → ``"static_archive"``
    * path in tool directory (``/usr/bin/``, ``/usr/libexec/``, …) → ``"build_tool"``
    * anything else with a package → ``"system_runtime"``
    """
    if not has_package:
        return "project_source"
    name = Path(abspath).name.lower()
    if name.endswith((".h", ".hpp", ".hh", ".h++")):
        return "static_header"
    if ".so." in name or name.endswith(".so"):
        return "dynamic_lib"
    if name.endswith(".a"):
        return "static_archive"
    for tdir in _TOOL_DIRS:
        if abspath.startswith(tdir):
            return "build_tool"
    return "system_runtime"


def classify_roles(graph: BuildGraph) -> None:
    """Stamp ProcessNode.role for every process in *graph* (in-place).

    Roles: ``compiler | linker | assembler | archiver | other``.
    Already-set roles (role is not None) are left unchanged.
    """
    for proc in graph.procs.values():
        if proc.role is not None:
            continue
        exe_abspath = ""
        if proc.executable and proc.executable in graph.files:
            exe_abspath = graph.files[proc.executable].abspath
        proc.role = process_role(exe_abspath)


def classify_files(
    graph: BuildGraph,
    provenance: list["ProvenanceBackend"],
    source_dir: Optional[Path] = None,
) -> list[ClassifiedFile]:
    """Return a ClassifiedFile for every file that was read during the build.

    Steps:
    1. Call :func:`classify_roles` to ensure process roles are set.
    2. Build a ``{file_uri: set_of_reader_roles}`` index from all ``reads`` edges.
    3. For each file, look up its OS package via *provenance* backends (first hit wins).
    4. Assign :class:`DepClass` using extension + reader roles + package + vendor path.

    *source_dir* is accepted for API compatibility with future phases (OSV
    determineversion, manifest parsers) but is not used in this implementation.

    Files that only appear as executables or outputs (writes/renames), but never
    as direct inputs, are excluded from the result.
    """
    classify_roles(graph)

    # URIs produced by this build (written or renamed by any process)
    written_uris: set[str] = set()
    for proc in graph.procs.values():
        written_uris.update(proc.writes)
        written_uris.update(proc.renames)

    # Build {furi: set of roles} from all reads edges
    reader_roles: dict[str, set[str]] = {}
    for proc in graph.procs.values():
        role = proc.role or "other"
        for furi in proc.reads:
            reader_roles.setdefault(furi, set()).add(role)

    result: list[ClassifiedFile] = []
    for furi, roles in reader_roles.items():
        fnode = graph.files.get(furi)
        if fnode is None:
            continue

        # Package lookup: try each backend in order, first hit wins
        package: Optional[PackageRef] = None
        for backend in provenance:
            if backend.available():
                ref = backend.lookup(fnode.abspath, fnode.git_blob_sha1)
                if ref is not None:
                    package = ref
                    break

        # Not "vendor_dir": that name is a module-level function here.
        dep_class, vdir = _dep_class_for(
            fnode.abspath, furi, roles, package, written_uris
        )
        result.append(ClassifiedFile(
            file=fnode,
            dep_class=dep_class,
            package=package,
            vendor_dir=vdir,
            read_by_roles=set(roles),
        ))

    return result
