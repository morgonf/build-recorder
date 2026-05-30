#!/usr/bin/env python3
"""
verify-build.py — Build dependency verification report.

Reads a build-recorder .out file (enriched by enrich.py) and produces a
structured report of EXACTLY what went into the build:
  - static dependencies: headers/sources/archives read by the compiler
  - dynamic dependencies: .so files linked at runtime
  - build artifacts: the final binaries produced
  - provenance: which RPM package provides each dependency
  - verification: hash from build-recorder vs RPM-provided provenance

Usage:
  python3 verify-build.py <build.out>
  python3 verify-build.py <build.out> --report report.md
  python3 verify-build.py <build.out> --json report.json
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Process classification ────────────────────────────────────────────────────

COMPILER_NAMES = {
    "cc1", "cc1plus", "lto1", "lto-wrapper",
    "gcc", "g++", "gcc_wrapper",
    "x86_64-alt-linux-gcc-13", "x86_64-alt-linux-g++-13",
    "x86_64-alt-linux-gcc-14", "x86_64-alt-linux-g++-14",
    "clang", "clang++",
}
LINKER_NAMES = {
    "ld", "ld.bfd", "ld.gold", "ld.lld", "gold", "collect2",
}
ASSEMBLER_NAMES = {"as", "x86_64-alt-linux-as"}
ARCHIVER_NAMES = {
    "ar", "ranlib",
    "x86_64-alt-linux-ar", "x86_64-alt-linux-ranlib",
    "x86_64-alt-linux-gcc-ar-13", "x86_64-alt-linux-gcc-ranlib-13",
    "x86_64-alt-linux-gcc-ar-14", "x86_64-alt-linux-gcc-ranlib-14",
}

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class FileNode:
    uri: str
    abspath: str = ""
    git_hash: str = ""
    dep_type: str = ""
    rpm_name: str = ""
    rpm_nevra: str = ""

    @property
    def name(self) -> str:
        return Path(self.abspath).name

    @property
    def role(self) -> str:
        n = self.name.lower()
        if ".so." in n or n.endswith(".so"):
            return "dynamic_lib"
        if n.endswith(".a"):
            return "static_archive"
        if n.endswith((".h", ".hpp", ".hh", ".h++")):
            return "header"
        if n.endswith((".c", ".cpp", ".cc", ".cxx", ".c++")):
            return "source"
        if n.endswith(".o"):
            return "object"
        if n.endswith((".s", ".S", ".asm")):
            return "assembly"
        return "other"

    @property
    def is_from_rpm(self) -> bool:
        return bool(self.rpm_name)

    @property
    def is_project_source(self) -> bool:
        return self.dep_type == "project_source" and not self.rpm_name

    @property
    def is_vendored(self) -> bool:
        return self.is_project_source and _is_vendor_path(self.abspath)

    @property
    def provenance(self) -> str:
        if self.rpm_nevra:
            return self.rpm_nevra
        if self.is_vendored:
            return "VENDORED (not from any RPM)"
        if self.is_project_source:
            return "project source"
        return "unknown"


@dataclass
class ProcessNode:
    uri: str
    exe_uri: Optional[str] = None      # URI of executable file
    reads:   list[str] = field(default_factory=list)   # file URIs
    writes:  list[str] = field(default_factory=list)   # file URIs
    renames: list[str] = field(default_factory=list)   # file URIs (new name after rename)


_TEMP_PATTERNS = re.compile(
    r'/(cc[0-9A-Za-z]{6,}\.(res|lto_wrapper_args|s|o)|'
    r'cmTC_[0-9a-f]+|'
    r'conftest|confcache|confdefs\.h|config\.log|'
    r'CMakeFiles/|TryCompile|CMakeTmp)'
)

def _is_real_artifact(abspath: str) -> bool:
    """True if path looks like a meaningful build output, not a temp file."""
    if _TEMP_PATTERNS.search(abspath):
        return False
    name = Path(abspath).name
    # Keep: .so, .a, executables (no ext), .d dependency files, .la
    sfx = Path(name).suffix.lower()
    if sfx in (".so", ".a", ".la", ".d", ".dll", ".dylib"):
        return True
    if ".so." in name:
        return True
    # Executable: no extension, not a hidden file
    if "." not in name and not name.startswith("."):
        return True
    return False


def _is_vendor_path(abspath: str) -> bool:
    VENDOR = {
        "third_party", "thirdparty", "3rdparty",
        "vendor", "vendors", "external", "externals", "extern",
        "deps", "dependencies", "contrib", "bundled", "embedded",
    }
    return any(p in VENDOR for p in abspath.lower().replace("\\", "/").split("/"))


def _proc_kind(exe_path: str) -> str:
    name = Path(exe_path).name
    if name in COMPILER_NAMES:
        return "compiler"
    if name in LINKER_NAMES:
        return "linker"
    if name in ASSEMBLER_NAMES:
        return "assembler"
    if name in ARCHIVER_NAMES:
        return "archiver"
    return "other"

# ── Parser ────────────────────────────────────────────────────────────────────

def parse_graph(out_file: Path) -> tuple[dict[str, FileNode], dict[str, ProcessNode]]:
    """
    Fast line-by-line parser for flat-triple Turtle format.
    Returns (files_by_uri, procs_by_uri).
    """
    files: dict[str, FileNode] = {}
    procs: dict[str, ProcessNode] = {}
    file_uris: set[str] = set()
    proc_uris: set[str] = set()

    file_re    = re.compile(r"^(:[a-zA-Z_]\w*)\s+a\s+b:file\b")
    proc_re    = re.compile(r"^(:[a-zA-Z_]\w*)\s+a\s+b:process\b")
    prop_re    = re.compile(r"^(:[a-zA-Z_]\w*)\s+b:(\w+)\s+\"((?:[^\"\\]|\\.)*)\"\s*[.;]")
    rel_re     = re.compile(r"^(:[a-zA-Z_]\w*)\s+b:(\w+)\s+(:[a-zA-Z_]\w*)\s*[.;]")
    bare_re    = re.compile(r"^(:[a-zA-Z_]\w*)\s*$")
    istr_re    = re.compile(r"^\s+b:(\w+)\s+\"((?:[^\"\\]|\\.)*)\"\s*[.;]")
    irel_re    = re.compile(r"^\s+b:(\w+)\s+(:[a-zA-Z_]\w*)\s*[.;]")
    current: Optional[str] = None

    def _unescape(s: str) -> str:
        return (s.replace('\\"', '"').replace("\\\\", "\\")
                  .replace("\\n", "\n").replace("\\t", "\t"))

    def _set_prop(uri: str, prop: str, val: str) -> None:
        if uri in file_uris:
            f = files.setdefault(uri, FileNode(uri=uri))
            if prop == "abspath":  f.abspath  = val
            elif prop == "hash":   f.git_hash = val
            elif prop == "dep_type":  f.dep_type  = val
            elif prop == "rpm_name":  f.rpm_name  = val
            elif prop == "rpm_package": f.rpm_nevra = val
        elif uri in proc_uris:
            pass  # we only need relationship props for processes

    def _set_rel(subj: str, pred: str, obj: str) -> None:
        if subj in proc_uris:
            p = procs.setdefault(subj, ProcessNode(uri=subj))
            if pred == "reads":        p.reads.append(obj)
            elif pred == "writes":     p.writes.append(obj)
            elif pred == "rename":     p.renames.append(obj)
            elif pred == "executable": p.exe_uri = obj

    with open(out_file, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")

            m = file_re.match(line)
            if m:
                current = m.group(1)
                file_uris.add(current)
                files.setdefault(current, FileNode(uri=current))
                continue

            m = proc_re.match(line)
            if m:
                current = m.group(1)
                proc_uris.add(current)
                procs.setdefault(current, ProcessNode(uri=current))
                continue

            # Direct property triple: :fN  b:prop  "value"
            m = prop_re.match(line)
            if m:
                _set_prop(m.group(1), m.group(2), _unescape(m.group(3)))
                current = None
                continue

            # Direct relationship triple: :pN  b:reads  :fM
            m = rel_re.match(line)
            if m:
                _set_rel(m.group(1), m.group(2), m.group(3))
                current = None
                continue

            # Bare URI (enrichment block header)
            m = bare_re.match(line)
            if m:
                current = m.group(1)
                continue

            if current and line and line[0].isspace():
                m = istr_re.match(line)
                if m:
                    _set_prop(current, m.group(1), _unescape(m.group(2)))
                    continue
                m = irel_re.match(line)
                if m:
                    _set_rel(current, m.group(1), m.group(2))
            elif current and line and not line.startswith("#"):
                current = None

    return files, procs

# ── Analysis ──────────────────────────────────────────────────────────────────

@dataclass
class BuildDeps:
    # Static: files read by compiler/assembler processes
    static_headers:   list[FileNode] = field(default_factory=list)
    static_sources:   list[FileNode] = field(default_factory=list)
    static_archives:  list[FileNode] = field(default_factory=list)
    # Dynamic external: .so read by linker, NOT produced by this build
    dynamic_libs:     list[FileNode] = field(default_factory=list)
    # Dynamic own: .so produced by this build and linked by tests/other targets
    dynamic_own:      list[FileNode] = field(default_factory=list)
    # Build artifacts: files written by linker/archiver
    artifacts:        list[FileNode] = field(default_factory=list)


def analyze(files: dict[str, FileNode],
            procs: dict[str, ProcessNode]) -> BuildDeps:
    deps = BuildDeps()
    seen_static:  set[str] = set()
    seen_dynamic: set[str] = set()
    seen_artifact: set[str] = set()

    # Pre-compute set of URIs written OR renamed during this build (= own artifacts)
    written_uris: set[str] = set()
    for proc in procs.values():
        written_uris.update(proc.writes)
        written_uris.update(proc.renames)

    for proc in procs.values():
        exe_path = files[proc.exe_uri].abspath if proc.exe_uri and proc.exe_uri in files else ""
        kind = _proc_kind(exe_path)

        if kind in ("compiler", "assembler"):
            for furi in proc.reads:
                if furi not in seen_static and furi in files:
                    f = files[furi]
                    seen_static.add(furi)
                    role = f.role
                    if role == "header":
                        deps.static_headers.append(f)
                    elif role == "source":
                        deps.static_sources.append(f)
                    elif role == "static_archive":
                        deps.static_archives.append(f)

        elif kind == "linker":
            for furi in proc.reads:
                if furi in files:
                    f = files[furi]
                    role = f.role
                    if role == "dynamic_lib" and furi not in seen_dynamic:
                        seen_dynamic.add(furi)
                        # Own artifact (produced by this build) vs external dep
                        if furi in written_uris:
                            deps.dynamic_own.append(f)
                        else:
                            deps.dynamic_libs.append(f)
                    elif role == "static_archive" and furi not in seen_static:
                        seen_static.add(furi)
                        deps.static_archives.append(f)
            for furi in proc.writes:
                if furi not in seen_artifact and furi in files:
                    f = files[furi]
                    if _is_real_artifact(f.abspath):
                        seen_artifact.add(furi)
                        deps.artifacts.append(f)

        elif kind == "archiver":
            for furi in proc.writes + proc.renames:
                if furi not in seen_artifact and furi in files:
                    f = files[furi]
                    if f.role == "static_archive" and _is_real_artifact(f.abspath):
                        seen_artifact.add(furi)
                        deps.artifacts.append(f)

        # Renames from any process type can produce final artifacts
        for furi in proc.renames:
            if furi not in seen_artifact and furi in files:
                f = files[furi]
                if _is_real_artifact(f.abspath) and furi not in written_uris - set(proc.renames):
                    seen_artifact.add(furi)
                    deps.artifacts.append(f)

    return deps

# ── Formatting helpers ────────────────────────────────────────────────────────

def _group_by_package(files: list[FileNode]) -> dict[str, list[FileNode]]:
    groups: dict[str, list[FileNode]] = defaultdict(list)
    for f in files:
        key = f.rpm_nevra or ("VENDORED" if f.is_vendored else "PROJECT_SOURCE")
        groups[key].append(f)
    return dict(sorted(groups.items(), key=lambda x: (-len(x[1]), x[0])))


def _status(f: FileNode) -> str:
    if f.is_from_rpm:
        return "✓"
    if f.is_vendored:
        return "⚠ vendored"
    return "·"

# ── Console report ────────────────────────────────────────────────────────────

def _section(title: str):
    w = 66
    print(f"\n{'═' * w}")
    print(f"  {title}")
    print('═' * w)


def print_report(deps: BuildDeps, files: dict[str, FileNode], pkg_name: str):
    _section(f"Build Verification: {pkg_name}")

    # ── Static ────────────────────────────────────────────────────────────────
    _section("Static dependencies  (compiled into binary)")

    if deps.static_headers:
        print(f"\n  Headers ({len(deps.static_headers)} files):\n")
        for nevra, grp in _group_by_package(deps.static_headers).items():
            short = nevra.split("-")[-1] if "-" in nevra and nevra != "VENDORED" else nevra
            status = "✓" if grp[0].is_from_rpm else "⚠"
            print(f"  {status} {nevra:<55} {len(grp):4d} files")

    if deps.static_archives:
        print(f"\n  Static archives ({len(deps.static_archives)}):\n")
        for f in sorted(deps.static_archives, key=lambda x: x.name):
            print(f"  {_status(f)}  {f.name:<40} {f.provenance}")

    if deps.static_sources:
        vendored = [f for f in deps.static_sources if f.is_vendored]
        own_src  = [f for f in deps.static_sources if not f.is_vendored]
        print(f"\n  Source files: {len(deps.static_sources)} total  "
              f"({len(own_src)} project, {len(vendored)} vendored)\n")
        if vendored:
            print(f"  ⚠  Vendored source (no RPM provenance — {len(vendored)} files):")
            by_dir: dict[str, list] = defaultdict(list)
            for f in vendored:
                # Group by vendor subdirectory
                parts = f.abspath.replace("\\", "/").split("/")
                for i, p in enumerate(parts):
                    if p.lower() in {"third_party","thirdparty","deps","vendor",
                                     "external","contrib","bundled","embedded"}:
                        key = "/".join(parts[i:i+2]) if i+1 < len(parts) else p
                        by_dir[key].append(f)
                        break
                else:
                    by_dir["other"].append(f)
            for vdir, vfiles in sorted(by_dir.items()):
                hashes = " ".join(f.git_hash[:8] for f in vfiles[:3])
                print(f"       {vdir:<40} {len(vfiles):3d} files  sha1: {hashes}…")

    # ── Dynamic ───────────────────────────────────────────────────────────────
    _section("Dynamic dependencies  (loaded at runtime)")
    if deps.dynamic_libs:
        print()
        by_pkg: dict[str, list[FileNode]] = defaultdict(list)
        for f in deps.dynamic_libs:
            by_pkg[f.rpm_nevra or "— (path not in RPM dump)"].append(f)
        for nevra, libs in sorted(by_pkg.items(), key=lambda x: x[0]):
            status = "✓" if libs[0].is_from_rpm else "?"
            for lib in sorted(libs, key=lambda f: f.name):
                h = lib.git_hash[:16] if lib.git_hash else "—"
                print(f"  {status}  {lib.name:<45} {nevra}")
                print(f"        hash: {h}")
    else:
        print("  (no external dynamic libraries)")

    if deps.dynamic_own:
        print(f"\n  Own build artifacts also linked ({len(deps.dynamic_own)}):")
        for f in sorted(deps.dynamic_own, key=lambda x: x.name):
            print(f"  ·  {f.name}")

    # ── Artifacts ─────────────────────────────────────────────────────────────
    _section("Build artifacts  (produced by this build)")
    if deps.artifacts:
        print()
        seen = set()
        for f in sorted(deps.artifacts, key=lambda x: x.name):
            if f.name in seen:
                continue
            seen.add(f.name)
            h = f.git_hash[:20] if f.git_hash else "—"
            print(f"  {f.name:<50} sha1: {h}")

    # ── Summary ───────────────────────────────────────────────────────────────
    _section("Verification summary")
    all_static = deps.static_headers + deps.static_sources + deps.static_archives
    rpm_verified = sum(1 for f in all_static if f.is_from_rpm)
    project_src  = sum(1 for f in all_static if f.is_project_source and not f.is_vendored)
    vendored     = sum(1 for f in all_static if f.is_vendored)
    dynamic_rpm  = sum(1 for f in deps.dynamic_libs if f.is_from_rpm)
    dynamic_unk  = sum(1 for f in deps.dynamic_libs if not f.is_from_rpm)

    print(f"""
  Static inputs:
    ✓ From RPM packages (headers + archives)  {rpm_verified:6d}
    · Project own source                      {project_src:6d}
    ⚠ Vendored source (no RPM provenance)     {vendored:6d}

  Dynamic (runtime) links:
    ✓ From RPM packages                       {dynamic_rpm:6d}
    ✗ Not from any package                    {dynamic_unk:6d}

  Build artifacts produced:                   {len(set(f.name for f in deps.artifacts)):6d}
""")
    if vendored > 0:
        print("  ⚠  Vendored dependencies require manual verification:")
        print("     Their source code is not tracked by any RPM package.")
        print("     Review commit hashes and compare against upstream releases.\n")
    if dynamic_unk > 0:
        print("  ✗  Unattributed runtime libraries detected.\n")
    if vendored == 0 and dynamic_unk == 0:
        print("  ✓  All build inputs attributed to known RPM packages or project source.\n")

# ── Markdown report ───────────────────────────────────────────────────────────

def make_markdown(deps: BuildDeps, files: dict[str, FileNode],
                  pkg_name: str, src_path: Path) -> str:
    lines = []
    W = lines.append
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    W(f"# Build Verification Report: {pkg_name}")
    W(f"\nGenerated: {now}  \nSource: `{src_path}`\n")

    # Summary table
    all_static = deps.static_headers + deps.static_sources + deps.static_archives
    rpm_static  = sum(1 for f in all_static if f.is_from_rpm)
    own_src     = sum(1 for f in all_static if f.is_project_source and not f.is_vendored)
    vendored    = sum(1 for f in all_static if f.is_vendored)
    dyn_rpm     = sum(1 for f in deps.dynamic_libs if f.is_from_rpm)
    dyn_unk     = sum(1 for f in deps.dynamic_libs if not f.is_from_rpm)

    W("## Summary\n")
    W("| Category | Files | Status |")
    W("|---|---|---|")
    W(f"| Static: from RPM packages | {rpm_static} | ✓ provenance verified |")
    W(f"| Static: project own source | {own_src} | · project code |")
    W(f"| Static: vendored (no RPM) | {vendored} | {'⚠ needs manual review' if vendored else '—'} |")
    W(f"| Dynamic: from RPM packages | {dyn_rpm} | ✓ provenance verified |")
    W(f"| Dynamic: unattributed | {dyn_unk} | {'✗ unknown origin' if dyn_unk else '—'} |")
    W(f"| Build artifacts produced | {len(set(f.name for f in deps.artifacts))} | |")

    # Static headers by package
    W("\n## Static Dependencies (compiled into binary)\n")
    W("### Headers by package\n")
    W("| Package (NEVRA) | Files | Verified |")
    W("|---|---|---|")
    for nevra, grp in _group_by_package(deps.static_headers).items():
        ok = "✓" if grp[0].is_from_rpm else "⚠ no RPM"
        W(f"| `{nevra}` | {len(grp)} | {ok} |")

    # Static archives
    if deps.static_archives:
        W("\n### Static archives linked\n")
        W("| Archive | Package | SHA-1 (git) | Verified |")
        W("|---|---|---|---|")
        seen = set()
        for f in sorted(deps.static_archives, key=lambda x: x.name):
            if f.name in seen:
                continue
            seen.add(f.name)
            ok = "✓" if f.is_from_rpm else "⚠"
            W(f"| `{f.name}` | `{f.rpm_nevra or '—'}` | `{f.git_hash[:16] or '—'}` | {ok} |")

    # Vendored source
    vendored_files = [f for f in deps.static_sources if f.is_vendored]
    if vendored_files:
        W("\n### ⚠ Vendored source (not from any RPM package)\n")
        W("These files are compiled directly from third-party source code "
          "bundled in the project repository. They carry no RPM provenance "
          "and must be reviewed manually against upstream releases.\n")
        W("| File | Directory | SHA-1 (git) |")
        W("|---|---|---|")
        for f in sorted(vendored_files, key=lambda x: x.abspath):
            parent = str(Path(f.abspath).parent).split("/")[-2:]
            W(f"| `{f.name}` | `{'/'.join(parent)}` | `{f.git_hash[:16]}` |")

    # Dynamic libs
    W("\n## Dynamic Dependencies (loaded at runtime)\n")
    W("| Library | Package (NEVRA) | SHA-1 (git) | Verified |")
    W("|---|---|---|---|")
    for f in sorted(deps.dynamic_libs, key=lambda x: x.name):
        ok = "✓" if f.is_from_rpm else "✗ unknown"
        W(f"| `{f.name}` | `{f.rpm_nevra or '—'}` | `{f.git_hash[:16] or '—'}` | {ok} |")

    # Artifacts
    W("\n## Build Artifacts\n")
    W("| Artifact | SHA-1 (git) |")
    W("|---|---|")
    seen = set()
    for f in sorted(deps.artifacts, key=lambda x: x.name):
        if f.name in seen:
            continue
        seen.add(f.name)
        W(f"| `{f.name}` | `{f.git_hash[:20] or '—'}` |")

    W("\n---")
    W("*Generated by `verify-build.py` / build-recorder*")
    return "\n".join(lines)

# ── JSON export ───────────────────────────────────────────────────────────────

def make_json(deps: BuildDeps, pkg_name: str) -> dict:
    def _fmt(files: list[FileNode]) -> list[dict]:
        seen = set()
        result = []
        for f in files:
            if f.abspath in seen:
                continue
            seen.add(f.abspath)
            result.append({
                "path":       f.abspath,
                "name":       f.name,
                "sha1_git":   f.git_hash,
                "rpm_name":   f.rpm_name,
                "rpm_nevra":  f.rpm_nevra,
                "dep_type":   f.dep_type,
                "role":       f.role,
                "verified":   f.is_from_rpm,
                "vendored":   f.is_vendored,
            })
        return result

    return {
        "package": pkg_name,
        "generated": datetime.now(timezone.utc).isoformat(),
        "static": {
            "headers":  _fmt(deps.static_headers),
            "sources":  _fmt(deps.static_sources),
            "archives": _fmt(deps.static_archives),
        },
        "dynamic": _fmt(deps.dynamic_libs),
        "artifacts": _fmt(deps.artifacts),
    }

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Build dependency verification: static + dynamic, with RPM provenance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("out_file", help="Enriched .out file (run enrich.py first)")
    ap.add_argument("--report", "-r", metavar="FILE.md",
                    help="Save Markdown report (default: <out>.verify.md)")
    ap.add_argument("--json", "-j", metavar="FILE.json",
                    help="Save JSON report (default: <out>.verify.json)")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="Skip console output")
    args = ap.parse_args()

    out_path = Path(args.out_file)
    if not out_path.exists():
        print(f"ERROR: {out_path} not found", file=sys.stderr)
        sys.exit(1)

    md_path   = Path(args.report) if args.report   else out_path.with_suffix(".verify.md")
    json_path = Path(args.json)   if args.json     else out_path.with_suffix(".verify.json")
    pkg_name  = out_path.stem.replace("-build", "")

    print(f"Parsing {out_path.name} ...", end=" ", flush=True)
    files, procs = parse_graph(out_path)
    print(f"{len(files)} files, {len(procs)} processes")

    print("Analysing dependency graph ...", end=" ", flush=True)
    deps = analyze(files, procs)
    n_static = len(deps.static_headers) + len(deps.static_sources) + len(deps.static_archives)
    print(f"{n_static} static, {len(deps.dynamic_libs)} dynamic, "
          f"{len(deps.artifacts)} artifacts")

    if not args.quiet:
        print_report(deps, files, pkg_name)

    md_path.write_text(make_markdown(deps, files, pkg_name, out_path), encoding="utf-8")
    json_path.write_text(json.dumps(make_json(deps, pkg_name), indent=2, ensure_ascii=False),
                         encoding="utf-8")
    print(f"\nReport : {md_path}")
    print(f"JSON   : {json_path}")


if __name__ == "__main__":
    main()
