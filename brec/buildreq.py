"""brec.buildreq — declared build dependencies versus the ones actually read.

A spec file states what a package needs to build (``BuildRequires``).  The
trace states what the build actually opened.  The two are independent, and
where they disagree the disagreement is a packaging bug in one of two
directions:

  * **used, not declared** — the build read files from a package it never asked
    for.  It succeeded only because that package happened to be installed in
    this build root; on a leaner one it breaks.
  * **declared, never read** — the package is pulled into every build root for
    nothing.

Nothing here talks to rpm directly.  The caller supplies three plain-text
inputs, all produced inside the build environment where they are meaningful:

  ``declared``   one capability per line, as printed by ``rpm -qp --requires``;
  ``rpm-deps``   the provides/requires graph of the installed packages, typed
                 lines ``P<TAB>capability<TAB>package`` and
                 ``R<TAB>package<TAB>capability``;
  ``rpm-dump``   the file→package index already used by the rest of brec, which
                 doubles here as the resolver for file capabilities
                 (``/bin/sh`` and friends are legitimate requires).

Resolution runs in three steps: declared capabilities → the packages providing
them → the transitive closure of those packages over ``rpm-deps``.  A package
read by the build is "implied" if it is in that closure.  The distinction
between *directly* declared and *only transitively* implied is kept, because
the second is fragile: it holds until some unrelated package drops a
dependency.

Reachability alone, however, credits far too much: in a distribution every
``-devel`` package eventually requires the toolchain, so a declaration can be
"satisfied" by packages that have nothing to do with it.  Attribution is
therefore bounded by hop count (see ``attribution_depth``), which keeps the
useful case — a wrapper package honoured by what it requires — without
pronouncing every declaration used.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from brec.ir import BuildGraph

# Capabilities that never correspond to an installed package: rpm's own
# metadata assertions and the dynamic-loader marker.
_PSEUDO_CAP_PREFIXES = ("rpmlib(", "rtld(", "config(")


# ── Parsing ───────────────────────────────────────────────────────────────────

def strip_constraint(cap: str) -> str:
    """``libfoo-devel >= 1.2`` → ``libfoo-devel``.

    rpm prints a capability, then optionally a comparison and a version.  Only
    the name identifies the provider, so the tail is dropped.
    """
    return cap.strip().split()[0] if cap.strip() else ""


def is_pseudo_cap(cap: str) -> bool:
    """True for capabilities that no installed package can provide."""
    return cap.startswith(_PSEUDO_CAP_PREFIXES)


def parse_declared(path: Path) -> list[str]:
    """Read a declared-dependency list: one capability per line.

    Blank lines and ``#`` comments are ignored, version constraints stripped,
    pseudo-capabilities dropped, order preserved, duplicates removed.
    """
    seen: set[str] = set()
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        cap = strip_constraint(line)
        if not cap or is_pseudo_cap(cap) or cap in seen:
            continue
        seen.add(cap)
        out.append(cap)
    return out


def parse_rpm_deps(path: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Read the typed provides/requires dump.

    Returns ``(provides, requires)`` where ``provides[cap]`` is the set of
    packages providing *cap* and ``requires[pkg]`` the set of capabilities
    *pkg* requires.  Malformed lines are skipped rather than raising: the dump
    is machine-generated, but a truncated one should still yield a usable
    partial answer.
    """
    provides: dict[str, set[str]] = defaultdict(set)
    requires: dict[str, set[str]] = defaultdict(set)
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 3:
            continue
        kind, a, b = (p.strip() for p in parts)
        if kind == "P" and a and b:
            provides[strip_constraint(a)].add(b)
        elif kind == "R" and a and b:
            cap = strip_constraint(b)
            if cap and not is_pseudo_cap(cap):
                requires[a].add(cap)
    return dict(provides), dict(requires)


# ── Resolution ────────────────────────────────────────────────────────────────

def resolve_caps(
    caps: Iterable[str],
    provides: dict[str, set[str]],
    file_lookup: Optional[Callable[[str], Optional[str]]] = None,
    assume_cap_is_package: bool = False,
) -> tuple[dict[str, set[str]], list[str]]:
    """Map capabilities to providing packages.

    A capability starting with ``/`` is a path: it is looked up in the
    file→package index via *file_lookup* when the provides map has no entry,
    which is the common case because file provides are usually implicit.

    *assume_cap_is_package* is the degraded mode used when no provides map was
    supplied at all: most build requires do name a package directly, so taking
    the capability for a package name beats resolving nothing.  With a provides
    map present it stays off, because there an unresolved capability carries
    real information (nothing installed provides it).

    Returns ``({cap: {pkg, ...}}, [unresolved caps])``.
    """
    resolved: dict[str, set[str]] = {}
    unresolved: list[str] = []
    for cap in caps:
        pkgs = set(provides.get(cap, ()))
        if not pkgs and cap.startswith("/") and file_lookup is not None:
            owner = file_lookup(cap)
            if owner:
                pkgs = {owner}
        if not pkgs and assume_cap_is_package and not cap.startswith("/"):
            pkgs = {cap}
        if pkgs:
            resolved[cap] = pkgs
        else:
            unresolved.append(cap)
    return resolved, unresolved


def dependency_depths(
    seed: Iterable[str],
    provides: dict[str, set[str]],
    requires: dict[str, set[str]],
    file_lookup: Optional[Callable[[str], Optional[str]]] = None,
) -> dict[str, int]:
    """Packages reachable from *seed*, mapped to their distance in hops.

    Breadth-first over installed packages only; a capability nothing installed
    provides simply ends that branch.  Seed packages are at depth 0.

    Distance matters because reachability alone credits far too much: in a
    distribution every ``-devel`` package eventually requires the toolchain, so
    "reachable from the declaration" is almost always true and says nothing.
    """
    depth: dict[str, int] = {}
    frontier = [p for p in seed]
    level = 0
    while frontier:
        nxt: list[str] = []
        for pkg in frontier:
            if pkg in depth:
                continue
            depth[pkg] = level
            for cap in requires.get(pkg, ()):
                owners = provides.get(cap)
                if not owners and cap.startswith("/") and file_lookup is not None:
                    owner = file_lookup(cap)
                    owners = {owner} if owner else None
                for owner in owners or ():
                    if owner not in depth:
                        nxt.append(owner)
        frontier = nxt
        level += 1
    return depth


def dependency_closure(
    seed: Iterable[str],
    provides: dict[str, set[str]],
    requires: dict[str, set[str]],
    file_lookup: Optional[Callable[[str], Optional[str]]] = None,
) -> set[str]:
    """Packages reachable from *seed*; the depth-free view of the same walk."""
    return set(dependency_depths(seed, provides, requires, file_lookup))


# ── Observation ───────────────────────────────────────────────────────────────

@dataclass
class PkgUse:
    """One package the build actually read from."""

    name: str
    files: list[str] = field(default_factory=list)
    implied_by: list[str] = field(default_factory=list)   # declared caps reaching it

    @property
    def count(self) -> int:
        return len(self.files)

    def to_dict(self, max_files: int = 0) -> dict:
        files = sorted(self.files)
        if max_files:
            files = files[:max_files]
        out = {"package": self.name, "files_read": self.count, "sample": files}
        if self.implied_by:
            out["implied_by"] = sorted(self.implied_by)
        return out


def observed_usage(graph: BuildGraph, package_of: Callable[[str], Optional[str]]) -> dict[str, PkgUse]:
    """Packages whose files the build read, with the paths that named them.

    *package_of* maps a file URI to a package name (``None`` when the file
    belongs to no package).  Two exclusions keep the answer honest:

      * files the build itself wrote are not inputs, even when their path falls
        inside a packaged directory;
      * a file is counted once per package, however many processes opened it.

    Executed binaries count as reads: a build tool must be declared exactly
    like a header.
    """
    written: set[str] = set()
    for proc in graph.procs.values():
        written.update(proc.writes)

    used: dict[str, PkgUse] = {}
    seen_files: set[str] = set()
    for proc in graph.procs.values():
        candidates = list(proc.reads)
        if proc.executable:
            candidates.append(proc.executable)
        for furi in candidates:
            if furi in written or furi in seen_files:
                continue
            seen_files.add(furi)
            pkg = package_of(furi)
            if not pkg:
                continue
            fn = graph.files.get(furi)
            used.setdefault(pkg, PkgUse(name=pkg)).files.append(
                fn.abspath if fn is not None else furi
            )
    return used


# ── Audit ─────────────────────────────────────────────────────────────────────

@dataclass
class DeclaredCap:
    """A declared capability and the packages that satisfy it."""

    cap: str
    providers: list[str] = field(default_factory=list)
    satisfied_by: list[str] = field(default_factory=list)  # read packages it pulled in

    def to_dict(self) -> dict:
        out = {"capability": self.cap, "providers": sorted(self.providers)}
        if self.satisfied_by:
            out["satisfied_by"] = sorted(self.satisfied_by)
        return out


@dataclass
class BuildReqReport:
    used_undeclared: list[PkgUse] = field(default_factory=list)
    used_transitive: list[PkgUse] = field(default_factory=list)
    used_declared: list[PkgUse] = field(default_factory=list)
    declared_unused: list[DeclaredCap] = field(default_factory=list)
    declared_indirect: list[DeclaredCap] = field(default_factory=list)
    unresolved_caps: list[str] = field(default_factory=list)
    implicit: list[str] = field(default_factory=list)
    have_closure: bool = True
    files_read: int = 0
    packages_read: int = 0

    def to_dict(self, max_files: int = 5) -> dict:
        return {
            "summary": {
                "packages_read": self.packages_read,
                "files_read": self.files_read,
                "used_undeclared": len(self.used_undeclared),
                "used_transitive": len(self.used_transitive),
                "used_declared": len(self.used_declared),
                "declared_unused": len(self.declared_unused),
                "declared_indirect": len(self.declared_indirect),
                "unresolved_capabilities": len(self.unresolved_caps),
                "closure_available": self.have_closure,
            },
            "used_undeclared": [u.to_dict(max_files) for u in self.used_undeclared],
            "used_transitive": [u.to_dict(max_files) for u in self.used_transitive],
            "used_declared": [u.to_dict(max_files) for u in self.used_declared],
            "declared_unused": [d.to_dict() for d in self.declared_unused],
            "declared_indirect": [d.to_dict() for d in self.declared_indirect],
            "unresolved_capabilities": sorted(self.unresolved_caps),
            "implicit": sorted(self.implicit),
        }


def audit(
    graph: BuildGraph,
    declared: list[str],
    provides: dict[str, set[str]],
    requires: dict[str, set[str]],
    package_of: Callable[[str], Optional[str]],
    file_lookup: Optional[Callable[[str], Optional[str]]] = None,
    implicit: Iterable[str] = (),
    attribution_depth: int = 1,
) -> BuildReqReport:
    """Compare declared build dependencies against the packages actually read.

    *implicit* names packages assumed present in every build root (on ALT,
    the closure of ``rpm-build``); they are excluded from the undeclared list
    but still reported, so the assumption stays visible.

    *attribution_depth* bounds how far a declaration may be credited for a
    package it did not name.  At the default 1 a wrapper package counts when
    its immediate dependency was read (ALT's ``gcc`` is honoured by ``gcc13``),
    while a declaration whose only link to the build is five hops of toolchain
    away is reported as unused, which is what it is.

    With an empty *requires* map there is no closure to compute: every read
    package is then judged against the direct providers alone, and
    ``have_closure`` is set to False so the caller can say so.
    """
    resolved, unresolved = resolve_caps(
        declared, provides, file_lookup, assume_cap_is_package=not provides
    )
    direct: set[str] = set()
    for pkgs in resolved.values():
        direct |= pkgs

    have_closure = bool(requires)

    # Closure per declared capability, not just one over all of them: it is what
    # lets the report say *which* declaration pulled a package in, and tell a
    # wrapper package honoured through its own dependency (ALT's `gcc` → `gcc13`)
    # apart from one nothing ever touched.
    per_cap: dict[str, dict[str, int]] = {}
    memo: dict[frozenset, dict[str, int]] = {}
    for cap, pkgs in resolved.items():
        key = frozenset(pkgs)
        if key not in memo:
            memo[key] = (
                dependency_depths(pkgs, provides, requires, file_lookup)
                if have_closure
                else {p: 0 for p in pkgs}
            )
        per_cap[cap] = memo[key]

    closure: set[str] = set()
    for depths in per_cap.values():
        closure |= set(depths)

    # A package is attributed to the declaration(s) nearest to it.  Listing every
    # declaration that can reach it drowns the answer: in practice they all can.
    best_depth: dict[str, int] = {}
    for depths in per_cap.values():
        for pkg, d in depths.items():
            if pkg not in best_depth or d < best_depth[pkg]:
                best_depth[pkg] = d
    implied_by: dict[str, list[str]] = defaultdict(list)
    for cap, depths in per_cap.items():
        for pkg, d in depths.items():
            if d == best_depth[pkg]:
                implied_by[pkg].append(cap)

    implicit_set = set(implicit)
    implicit_closure = (
        dependency_closure(implicit_set, provides, requires, file_lookup)
        if have_closure and implicit_set
        else set(implicit_set)
    )

    used = observed_usage(graph, package_of)

    undeclared: list[PkgUse] = []
    transitive: list[PkgUse] = []
    declared_used: list[PkgUse] = []
    for name, use in used.items():
        if name in direct:
            declared_used.append(use)
        elif name in closure:
            use.implied_by = sorted(implied_by.get(name, ()))
            transitive.append(use)
        elif name in implicit_closure:
            continue
        else:
            undeclared.append(use)

    used_names = set(used)
    unused: list[DeclaredCap] = []
    indirect: list[DeclaredCap] = []
    for cap, pkgs in resolved.items():
        if pkgs & used_names:
            continue                                   # provider read directly
        # Credit a declaration only for what sits within attribution_depth hops
        # of it.  Beyond that the walk reaches the whole toolchain and would
        # pronounce every declaration satisfied.
        satisfied = {
            pkg for pkg, d in per_cap.get(cap, {}).items()
            if pkg in used_names and 0 < d <= attribution_depth
        }
        entry = DeclaredCap(cap=cap, providers=sorted(pkgs), satisfied_by=sorted(satisfied))
        (indirect if satisfied else unused).append(entry)

    by_size = lambda items: sorted(items, key=lambda u: (-u.count, u.name))
    return BuildReqReport(
        used_undeclared=by_size(undeclared),
        used_transitive=by_size(transitive),
        used_declared=by_size(declared_used),
        declared_unused=sorted(unused, key=lambda d: d.cap),
        declared_indirect=sorted(indirect, key=lambda d: d.cap),
        unresolved_caps=unresolved,
        implicit=sorted(implicit_closure),
        have_closure=have_closure,
        files_read=sum(u.count for u in used.values()),
        packages_read=len(used),
    )
