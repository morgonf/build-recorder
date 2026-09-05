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
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from brec.classify import (
    classify_roles,
    file_role,
    is_build_artifact,
    is_vendor_path,
    vendor_dir as vendor_dir_of,
)
from brec.components import Component, upstream_for
from brec.ir import BuildGraph, FileNode
from brec.model import parse_out

# ── File predicates ───────────────────────────────────────────────────────────
#
# Report-level questions asked of a brec.ir.FileNode.  The graph itself is
# brec's; only the wording of the report lives here.

def is_from_rpm(f: FileNode) -> bool:
    return bool(f.rpm_name)


def is_project_source(f: FileNode) -> bool:
    return f.dep_type == "project_source" and not f.rpm_name


def is_vendored(f: FileNode) -> bool:
    return is_project_source(f) and is_vendor_path(f.abspath)


def provenance(f: FileNode) -> str:
    if f.rpm_nevra:
        return f.rpm_nevra
    if is_vendored(f):
        return "VENDORED (not from any RPM)"
    if is_project_source(f):
        return "project source"
    return "unknown"


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


def analyze(graph: BuildGraph) -> BuildDeps:
    deps = BuildDeps()
    seen_static:  set[str] = set()
    seen_dynamic: set[str] = set()
    seen_artifact: set[str] = set()

    files, procs = graph.files, graph.procs
    classify_roles(graph)

    # Pre-compute set of URIs written OR renamed during this build (= own artifacts)
    written_uris: set[str] = set()
    for proc in procs.values():
        written_uris.update(proc.writes)
        written_uris.update(proc.renames)

    for proc in procs.values():
        kind = proc.role or "other"

        if kind in ("compiler", "assembler"):
            for furi in proc.reads:
                if furi not in seen_static and furi in files:
                    f = files[furi]
                    seen_static.add(furi)
                    role = file_role(f.abspath)
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
                    role = file_role(f.abspath)
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
                    if is_build_artifact(f.abspath):
                        seen_artifact.add(furi)
                        deps.artifacts.append(f)

        elif kind == "archiver":
            for furi in proc.writes + proc.renames:
                if furi not in seen_artifact and furi in files:
                    f = files[furi]
                    if file_role(f.abspath) == "static_archive" and is_build_artifact(f.abspath):
                        seen_artifact.add(furi)
                        deps.artifacts.append(f)

        # Renames from any process type can produce final artifacts
        for furi in proc.renames:
            if furi not in seen_artifact and furi in files:
                f = files[furi]
                if is_build_artifact(f.abspath) and furi not in written_uris - set(proc.renames):
                    seen_artifact.add(furi)
                    deps.artifacts.append(f)

    return deps

# ── Formatting helpers ────────────────────────────────────────────────────────

def _group_by_package(files: list[FileNode]) -> dict[str, list[FileNode]]:
    groups: dict[str, list[FileNode]] = defaultdict(list)
    for f in files:
        key = f.rpm_nevra or ("VENDORED" if is_vendored(f) else "PROJECT_SOURCE")
        groups[key].append(f)
    return dict(sorted(groups.items(), key=lambda x: (-len(x[1]), x[0])))


def _status(f: FileNode) -> str:
    if is_from_rpm(f):    return "✓"
    if is_vendored(f):    return "⚠"
    return "·"

# ── Console report ────────────────────────────────────────────────────────────

def _section(title: str):
    w = 66
    print(f"\n{'═' * w}")
    print(f"  {title}")
    print('═' * w)


def print_report(deps: BuildDeps, files: dict[str, FileNode], pkg_name: str,
                 upstream: Optional[dict] = None):
    _section(f"Build Verification: {pkg_name}")

    # ── Static ────────────────────────────────────────────────────────────────
    _section("Static dependencies  (compiled into binary)")

    if deps.static_headers:
        print(f"\n  Headers ({len(deps.static_headers)} files):\n")
        for nevra, grp in _group_by_package(deps.static_headers).items():
            short = nevra.split("-")[-1] if "-" in nevra and nevra != "VENDORED" else nevra
            status = "✓" if is_from_rpm(grp[0]) else "⚠"
            print(f"  {status} {nevra:<55} {len(grp):4d} files")

    if deps.static_archives:
        print(f"\n  Static archives ({len(deps.static_archives)}):\n")
        for f in sorted(deps.static_archives, key=lambda x: x.name):
            print(f"  {_status(f)}  {f.name:<40} {provenance(f)}")

    if deps.static_sources:
        vendored = [f for f in deps.static_sources if is_vendored(f)]
        own_src  = [f for f in deps.static_sources if not is_vendored(f)]
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
                hashes = " ".join(f.git_blob_sha1[:8] for f in vfiles[:3])
                print(f"       {vdir:<40} {len(vfiles):3d} files  sha1: {hashes}…")

    # ── Dynamic ───────────────────────────────────────────────────────────────
    _section("Dynamic dependencies  (loaded at runtime)")
    if deps.dynamic_libs:
        print()
        by_pkg: dict[str, list[FileNode]] = defaultdict(list)
        for f in deps.dynamic_libs:
            by_pkg[f.rpm_nevra or "— (path not in RPM dump)"].append(f)
        for nevra, libs in sorted(by_pkg.items(), key=lambda x: x[0]):
            status = "✓" if is_from_rpm(libs[0]) else "?"
            for lib in sorted(libs, key=lambda f: f.name):
                h = lib.git_blob_sha1[:16] if lib.git_blob_sha1 else "—"
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
            h = f.git_blob_sha1[:20] if f.git_blob_sha1 else "—"
            print(f"  {f.name:<50} sha1: {h}")

    # ── Summary ───────────────────────────────────────────────────────────────
    _section("Verification summary")
    all_static = deps.static_headers + deps.static_sources + deps.static_archives
    rpm_verified = sum(1 for f in all_static if is_from_rpm(f))
    project_src  = sum(1 for f in all_static if is_project_source(f) and not is_vendored(f))
    vendored     = sum(1 for f in all_static if is_vendored(f))
    dynamic_rpm  = sum(1 for f in deps.dynamic_libs if is_from_rpm(f))
    dynamic_unk  = sum(1 for f in deps.dynamic_libs if not is_from_rpm(f))

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
    if vendored > 0 and not upstream:
        print("  ⚠  Vendored dependencies require manual verification.")
        print("     Run with --upstream-verify to compare hashes against upstream git.\n")
    if dynamic_unk > 0:
        print("  ✗  Unattributed runtime libraries detected.\n")
    if vendored == 0 and dynamic_unk == 0:
        print("  ✓  All build inputs attributed to known RPM packages or project source.\n")

    # ── Upstream verification results ─────────────────────────────────────────
    if upstream:
        _section("Upstream verification  (git hash comparison)")
        print()
        for dir_name, match in upstream.items():
            print(f"  [{dir_name}]")
            if match is None:
                print("    ✗  Could not verify (no upstream database entry or clone failed)")
            else:
                for line in _format_upstream_match(match):
                    print(line)
            print()

# ── Markdown report ───────────────────────────────────────────────────────────

def make_markdown(deps: BuildDeps, files: dict[str, FileNode],
                  pkg_name: str, src_path: Path,
                  upstream: Optional[dict] = None) -> str:
    lines = []
    W = lines.append
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    W(f"# Build Verification Report: {pkg_name}")
    W(f"\nGenerated: {now}  \nSource: `{src_path}`\n")

    # Summary table
    all_static = deps.static_headers + deps.static_sources + deps.static_archives
    rpm_static  = sum(1 for f in all_static if is_from_rpm(f))
    own_src     = sum(1 for f in all_static if is_project_source(f) and not is_vendored(f))
    vendored    = sum(1 for f in all_static if is_vendored(f))
    dyn_rpm     = sum(1 for f in deps.dynamic_libs if is_from_rpm(f))
    dyn_unk     = sum(1 for f in deps.dynamic_libs if not is_from_rpm(f))

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
        ok = "✓" if is_from_rpm(grp[0]) else "⚠ no RPM"
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
            ok = "✓" if is_from_rpm(f) else "⚠"
            W(f"| `{f.name}` | `{f.rpm_nevra or '—'}` | `{f.git_blob_sha1[:16] or '—'}` | {ok} |")

    # Vendored source
    vendored_files = [f for f in deps.static_sources if is_vendored(f)]
    if vendored_files:
        W("\n### ⚠ Vendored source (not from any RPM package)\n")
        W("These files are compiled directly from third-party source code "
          "bundled in the project repository. They carry no RPM provenance "
          "and must be reviewed manually against upstream releases.\n")
        W("| File | Directory | SHA-1 (git) |")
        W("|---|---|---|")
        for f in sorted(vendored_files, key=lambda x: x.abspath):
            parent = str(Path(f.abspath).parent).split("/")[-2:]
            W(f"| `{f.name}` | `{'/'.join(parent)}` | `{f.git_blob_sha1[:16]}` |")

    # Dynamic libs
    W("\n## Dynamic Dependencies (loaded at runtime)\n")
    W("| Library | Package (NEVRA) | SHA-1 (git) | Verified |")
    W("|---|---|---|---|")
    for f in sorted(deps.dynamic_libs, key=lambda x: x.name):
        ok = "✓" if is_from_rpm(f) else "✗ unknown"
        W(f"| `{f.name}` | `{f.rpm_nevra or '—'}` | `{f.git_blob_sha1[:16] or '—'}` | {ok} |")

    # Artifacts
    W("\n## Build Artifacts\n")
    W("| Artifact | SHA-1 (git) |")
    W("|---|---|")
    seen = set()
    for f in sorted(deps.artifacts, key=lambda x: x.name):
        if f.name in seen:
            continue
        seen.add(f.name)
        W(f"| `{f.name}` | `{f.git_blob_sha1[:20] or '—'}` |")

    if upstream:
        W("\n## Upstream Verification\n")
        W("Git blob hashes from build-recorder compared directly against upstream "
          "git history. No guessing from version strings.\n")
        for dir_name, match in upstream.items():
            W(f"### `{dir_name}`\n")
            if match is None:
                W("✗ Could not verify — no upstream database entry or clone failed.\n")
                continue
            pct = f"{match.confidence:.0%}"
            status = "✓" if match.is_tagged_release else "⚠"
            W(f"| | |")
            W(f"|---|---|")
            W(f"| Upstream repo | [{match.repo_url}]({match.repo_url}) |")
            W(f"| Matched commit | `{match.short_commit}` ({match.date[:10]}) |")
            W(f"| Hash match | {pct} ({match.matched}/{match.total} key files) |")
            W(f"| Nearest tag | `{match.nearest_tag or '—'}` |")
            if match.is_tagged_release:
                W(f"| **Status** | ✓ **Exact tagged release** |")
            else:
                W(f"| Commits past tag | +{match.commits_past_tag} |")
                W(f"| **Status** | ⚠ **Post-release snapshot, NOT `{match.nearest_tag}`** |")
            W(f"| Commit message | `{match.message}` |")
            if match.confidence < 1.0:
                W(f"\n⚠ Only {match.matched}/{match.total} key files matched — "
                  f"local patches may be present.\n")
            else:
                W("")

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
                "sha1_git":   f.git_blob_sha1,
                "rpm_name":   f.rpm_name,
                "rpm_nevra":  f.rpm_nevra,
                "dep_type":   f.dep_type,
                "role":       file_role(f.abspath),
                "verified":   is_from_rpm(f),
                "vendored":   is_vendored(f),
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

# ── Upstream verification ─────────────────────────────────────────────────────

@dataclass
class UpstreamMatch:
    repo_url: str
    commit:   str         # full SHA-1
    date:     str
    message:  str
    matched:  int         # files with matching blob hash
    total:    int         # files compared
    nearest_tag:       Optional[str] = None
    commits_past_tag:  int = 0

    @property
    def confidence(self) -> float:
        return self.matched / self.total if self.total else 0.0

    @property
    def is_tagged_release(self) -> bool:
        return self.commits_past_tag == 0 and self.nearest_tag is not None

    @property
    def short_commit(self) -> str:
        return self.commit[:12]


def _git(git_dir: Path, *args, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "--git-dir", str(git_dir)] + list(args),
        capture_output=True, text=True,
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args, result.stderr)
    return result.stdout


def _ensure_clone(url: str, cache_dir: Path) -> Path:
    """Return path to bare clone, cloning or fetching as needed."""
    repo_name = url.rstrip("/").split("/")[-1].removesuffix(".git")
    git_dir = cache_dir / f"{repo_name}.git"
    if git_dir.exists():
        print(f"    updating {repo_name} ...", end=" ", flush=True)
        try:
            _git(git_dir, "fetch", "--all", "-q")
            print("ok")
        except subprocess.CalledProcessError:
            print("fetch failed, using cached")
    else:
        print(f"    cloning {url} ...", end=" ", flush=True)
        cache_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--bare", "-q", url, str(git_dir)],
            check=True, capture_output=True,
        )
        print("done")
    return git_dir


def _build_tree_index(git_dir: Path, commit: str) -> dict[str, str]:
    """Return {relative_path: blob_sha1} for all files at a commit."""
    out = _git(git_dir, "ls-tree", "-r", commit, check=False)
    index: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            index[parts[3]] = parts[2]
    return index


def _tag_map(git_dir: Path) -> dict[str, str]:
    """Return {commit_sha1: tag_name} for all annotated and lightweight tags."""
    tags: dict[str, str] = {}
    for line in _git(git_dir, "show-ref", "--tags", check=False).splitlines():
        if not line:
            continue
        sha, ref = line.split(None, 1)
        tag = ref.replace("refs/tags/", "")
        # Dereference annotated tags
        deref = _git(git_dir, "rev-parse", f"{sha}^{{commit}}", check=False).strip()
        tags[deref or sha] = tag
    return tags


def _map_build_path(abspath: str, vendor_dir_name: str) -> Optional[str]:
    """Strip path prefix up to and including the vendor dir, return relative path."""
    parts = abspath.replace("\\", "/").split("/")
    for i, part in enumerate(parts):
        if part == vendor_dir_name:
            return "/".join(parts[i + 1:])
    return None


def verify_vendored(
    vendor_dir: str,
    vendor_files: list["FileNode"],
    spec: Component,
    cache_dir: Path,
) -> Optional[UpstreamMatch]:
    """
    Compare git-blob hashes of vendored files against upstream commits.
    Returns the best matching UpstreamMatch, or None on error.
    """
    # Map build paths to upstream-relative paths
    dir_name = vendor_dir.split("/")[-1]  # e.g. "wslay" from "deps/wslay"

    # Build {upstream_path: git_blob_hash} from build-recorder data
    if spec.upstream_key_files:
        target: dict[str, str] = {}
        for f in vendor_files:
            rel = _map_build_path(f.abspath, dir_name)
            if rel and f.git_blob_sha1 and rel in spec.upstream_key_files:
                target[rel] = f.git_blob_sha1
    else:
        # No upstream_key_files specified → use all .c/.h files
        target = {}
        for f in vendor_files:
            rel = _map_build_path(f.abspath, dir_name)
            if rel and f.git_blob_sha1 and Path(rel).suffix in (".c", ".h", ".cpp", ".hpp"):
                target[rel] = f.git_blob_sha1

    if not target:
        print(f"    no comparable files found in {vendor_dir}")
        return None

    print(f"    comparing {len(target)} files against upstream ...", end=" ", flush=True)

    try:
        git_dir = _ensure_clone(spec.upstream_url, cache_dir)
    except subprocess.CalledProcessError as e:
        print(f"clone failed: {e}")
        return None

    # Get all commits newest-first
    log = _git(git_dir,
               "log", "--all", "--format=%H %ai %s",
               check=False).splitlines()[:spec.upstream_max_commits]

    tags = _tag_map(git_dir)

    best_match: Optional[UpstreamMatch] = None
    best_score = -1

    for line in log:
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        commit_sha, date, message = parts[0], parts[1], parts[2]

        tree = _build_tree_index(git_dir, commit_sha)
        matched = sum(1 for path, h in target.items() if tree.get(path) == h)
        score = matched / len(target)

        if matched > best_score:
            best_score = matched
            best_match = UpstreamMatch(
                repo_url=spec.upstream_url,
                commit=commit_sha,
                date=date,
                message=message[:80],
                matched=matched,
                total=len(target),
            )
            if score == 1.0:
                break   # perfect match found, stop early

    if best_match is None:
        print("no match")
        return None

    # Find nearest tag and distance
    for line in _git(git_dir,
                     "log", "--all", "--format=%H",
                     best_match.commit, check=False).splitlines():
        commit_in_history = line.strip()
        if commit_in_history in tags:
            best_match.nearest_tag = tags[commit_in_history]
            break

    if best_match.nearest_tag:
        # Count commits between tag and best_match
        tag_commit = _git(
            git_dir, "rev-parse", f"refs/tags/{best_match.nearest_tag}^{{commit}}",
            check=False
        ).strip()
        if tag_commit:
            count_out = _git(
                git_dir, "rev-list", "--count",
                f"{tag_commit}..{best_match.commit}",
                check=False
            ).strip()
            best_match.commits_past_tag = int(count_out) if count_out.isdigit() else 0

    pct = f"{best_match.confidence:.0%}"
    print(f"{pct} match → {best_match.short_commit} ({best_match.date[:10]})")
    return best_match


def collect_vendored_groups(
    deps: "BuildDeps",
) -> dict[str, tuple[str, list["FileNode"]]]:
    """
    Group vendored source files by their vendor directory.
    Returns {vendor_dir_name: (vendor_dir_path, [FileNode, ...])}
    """
    groups: dict[str, tuple[str, list["FileNode"]]] = {}

    all_vendored = [f for f in deps.static_sources + deps.static_headers
                    if is_vendored(f)]
    # Also include vendored archives
    all_vendored += [f for f in deps.static_archives if is_vendored(f)]

    for f in all_vendored:
        vdir = vendor_dir_of(f.abspath)
        if vdir:
            dir_name = vdir.split("/")[-1]
            if dir_name not in groups:
                groups[dir_name] = (vdir, [])
            groups[dir_name][1].append(f)

    return groups


def run_upstream_verification(
    deps: "BuildDeps",
    cache_dir: Path,
) -> dict[str, Optional[UpstreamMatch]]:
    """Verify all detected vendored groups against upstream repositories."""
    groups = collect_vendored_groups(deps)
    results: dict[str, Optional[UpstreamMatch]] = {}

    for dir_name, (vendor_dir, files) in groups.items():
        spec = upstream_for(dir_name)
        if spec is None:
            print(f"  {dir_name}: no upstream repository on record, skipping")
            results[dir_name] = None
            continue

        print(f"  {dir_name} ({len(files)} files, {vendor_dir}):")
        results[dir_name] = verify_vendored(vendor_dir, files, spec, cache_dir)

    return results


def _format_upstream_match(m: UpstreamMatch) -> list[str]:
    lines = []
    pct = f"{m.confidence:.0%}"
    lines.append(f"  Upstream  : {m.repo_url}")
    lines.append(f"  Commit    : {m.short_commit}  ({m.date[:10]})  {pct} match")
    lines.append(f"  Message   : {m.message}")

    if m.nearest_tag:
        if m.is_tagged_release:
            lines.append(f"  Tag       : {m.nearest_tag}  ✓ EXACT RELEASE")
        else:
            lines.append(f"  Nearest tag : {m.nearest_tag} (+{m.commits_past_tag} commits)")
            lines.append(f"  ⚠  This is NOT {m.nearest_tag} — post-release snapshot")
    else:
        lines.append("  ⚠  No matching tag found in upstream history")

    if m.confidence < 1.0:
        lines.append(f"  ⚠  Only {m.matched}/{m.total} key files matched "
                     f"— possible local patches")
    return lines


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
    ap.add_argument("--upstream-verify", "-u", action="store_true",
                    help="Verify vendored deps against upstream git repos (clones repos)")
    ap.add_argument("--cache-dir", metavar="DIR",
                    default=str(Path.home() / ".cache" / "build-recorder" / "repos"),
                    help="Cache directory for upstream git clones")
    args = ap.parse_args()

    out_path = Path(args.out_file)
    if not out_path.exists():
        print(f"ERROR: {out_path} not found", file=sys.stderr)
        sys.exit(1)

    md_path   = Path(args.report) if args.report   else out_path.with_suffix(".verify.md")
    json_path = Path(args.json)   if args.json     else out_path.with_suffix(".verify.json")
    pkg_name  = out_path.stem.replace("-build", "")

    print(f"Parsing {out_path.name} ...", end=" ", flush=True)
    graph = parse_out(out_path)
    files = graph.files
    print(f"{len(files)} files, {len(graph.procs)} processes")

    print("Analysing dependency graph ...", end=" ", flush=True)
    deps = analyze(graph)
    n_static = len(deps.static_headers) + len(deps.static_sources) + len(deps.static_archives)
    print(f"{n_static} static, {len(deps.dynamic_libs)} dynamic, "
          f"{len(deps.artifacts)} artifacts")

    upstream_results: dict[str, Optional[UpstreamMatch]] = {}
    if args.upstream_verify:
        cache_dir = Path(args.cache_dir)
        print("\nVerifying vendored dependencies against upstream repositories ...")
        upstream_results = run_upstream_verification(deps, cache_dir)

    if not args.quiet:
        print_report(deps, files, pkg_name, upstream_results)

    md_path.write_text(
        make_markdown(deps, files, pkg_name, out_path, upstream_results),
        encoding="utf-8",
    )
    json_path.write_text(json.dumps(make_json(deps, pkg_name), indent=2, ensure_ascii=False),
                         encoding="utf-8")
    print(f"\nReport : {md_path}")
    print(f"JSON   : {json_path}")


if __name__ == "__main__":
    main()
