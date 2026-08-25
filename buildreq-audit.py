#!/usr/bin/env python3
"""
buildreq-audit.py — declared BuildRequires versus the packages actually read.

The spec says what the build needs; the trace says what it opened.  This
compares the two and prints the disagreements:

  USED, NOT DECLARED   the build read files from a package it never asked for.
                       It worked because that package was in this build root;
                       it is not guaranteed to be in the next one.
  DECLARED, NOT READ   the package is installed into every build root and
                       never opened.

Two further buckets are informational: packages reached only through the
dependency closure of what was declared (legal today, fragile tomorrow, since it
holds only while some other package keeps requiring them), and declarations
honoured through a dependency rather than directly, which is how a wrapper
package looks from a trace (ALT declares `gcc`, the build reads `gcc13`).

Inputs (all produced inside the build environment, where they mean something):

  <build.out>        build-recorder trace, ideally already enriched by
                     enrich.py; otherwise pass --rpm-dump and attribution
                     happens here.
  --declared FILE    one capability per line: rpm -qp --requires <pkg>.src.rpm
  --rpm-deps FILE    provides/requires graph of the installed packages:
                       rpm -qa --qf '[P\\t%{PROVIDENAME}\\t%{NAME}\\n]'
                       rpm -qa --qf '[R\\t%{NAME}\\t%{REQUIRENAME}\\n]'
                     Without it there is no transitive closure and every
                     indirectly used package lands in the undeclared list.
  --rpm-dump FILE    file→package index (rpm-dump.txt), also used to resolve
                     file capabilities such as /bin/sh.

The docker entrypoint writes all three next to the trace in SRPM mode.

Caveats that belong in any reading of the output:
  * a trace of `rpmbuild -bc` covers %prep and %build only; dependencies used
    solely by %install or %check will look unused;
  * --implicit names the packages every build root has anyway (on ALT: pass
    rpm-build); without it the base system fills the undeclared list;
  * a package can be legitimately declared and never read when it is a runtime
    dependency of the built package rather than a build-time one;
  * the docker entrypoint builds with `rpmbuild --nodeps`, so declared
    dependencies are not installed on demand: capabilities nothing provides are
    reported as unresolved, which is the gap between the spec and the image.

Usage:
  python3 buildreq-audit.py build.out --declared builddeps-declared.txt \\
      --rpm-deps rpm-deps.txt --rpm-dump rpm-dump.txt --implicit rpm-build
  python3 buildreq-audit.py build.out --declared d.txt --json audit.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from brec.buildreq import BuildReqReport, audit, parse_declared, parse_rpm_deps
from brec.ir import BuildGraph
from brec.model import parse_out
from brec.provenance.registry import detect_backends


def make_resolvers(graph: BuildGraph, rpm_dump: Optional[Path]):
    """Build (package_of, file_lookup) over the enriched graph and/or a dump.

    Attribution already baked into the trace by enrich.py wins; the live
    backend is the fallback, and the only source for capability paths that
    the build never opened.
    """
    backends = detect_backends(rpm_dump) if rpm_dump else []

    def file_lookup(abspath: str) -> Optional[str]:
        for backend in backends:
            if backend.available():
                ref = backend.lookup(abspath, "")
                if ref is not None and ref.name:
                    return ref.name
        return None

    cache: dict[str, Optional[str]] = {}

    def package_of(furi: str) -> Optional[str]:
        if furi in cache:
            return cache[furi]
        node = graph.files.get(furi)
        name: Optional[str] = None
        if node is not None:
            name = node.pkg_name or node.rpm_name or None
            if name is None and node.abspath:
                name = file_lookup(node.abspath)
        cache[furi] = name
        return name

    return package_of, file_lookup


def render(rep: BuildReqReport, max_files: int) -> str:
    out: list[str] = []
    out.append("=== BuildRequires audit ===")
    out.append(f"  packages read : {rep.packages_read}")
    out.append(f"  files read    : {rep.files_read}")
    if not rep.have_closure:
        out.append("  NOTE: no --rpm-deps given, transitive dependencies count as undeclared")
    if rep.implicit:
        out.append(f"  implicit      : {len(rep.implicit)} package(s) assumed present, excluded")
    out.append("")

    out.append(f"  declared and read: {len(rep.used_declared)} package(s)")
    out.append("")

    out.append(f"USED, NOT DECLARED ({len(rep.used_undeclared)}):")
    if not rep.used_undeclared:
        out.append("  none")
    for use in rep.used_undeclared:
        out.append(f"  {use.name}  ({use.count} file(s) read)")
        for path in sorted(use.files)[:max_files]:
            out.append(f"      {path}")
        if use.count > max_files:
            out.append(f"      ... {use.count - max_files} more")
    out.append("")

    out.append(f"DECLARED, NOT READ ({len(rep.declared_unused)}):")
    if not rep.declared_unused:
        out.append("  none")
    for dec in rep.declared_unused:
        providers = ", ".join(dec.providers)
        out.append(f"  {dec.cap}  → {providers}")
    out.append("")

    if rep.declared_indirect:
        out.append(f"DECLARED, SATISFIED INDIRECTLY ({len(rep.declared_indirect)}):")
        out.append("  (the named package itself was never read, its dependencies were)")
        for dec in rep.declared_indirect:
            out.append(f"  {dec.cap}  → read: {', '.join(dec.satisfied_by)}")
        out.append("")

    if rep.used_transitive:
        out.append(f"USED VIA CLOSURE, NOT DECLARED DIRECTLY ({len(rep.used_transitive)}):")
        for use in rep.used_transitive:
            via = f"  ← {', '.join(use.implied_by)}" if use.implied_by else ""
            out.append(f"  {use.name}  ({use.count} file(s) read){via}")
        out.append("")

    if rep.unresolved_caps:
        out.append(f"UNRESOLVED CAPABILITIES ({len(rep.unresolved_caps)}):")
        out.append("  (declared, but nothing installed provides them: not installed here)")
        for cap in sorted(rep.unresolved_caps):
            out.append(f"  {cap}")
        out.append("")

    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Compare declared BuildRequires with the packages the build actually read",
    )
    ap.add_argument("out_file", type=Path, help="build-recorder .out trace")
    ap.add_argument("--declared", type=Path, required=True,
                    help="declared capabilities, one per line (rpm -qp --requires)")
    ap.add_argument("--rpm-deps", type=Path,
                    help="installed provides/requires dump for the transitive closure")
    ap.add_argument("--rpm-dump", type=Path,
                    help="file→package index; needed when the trace is not enriched")
    ap.add_argument("--implicit", action="append", default=[], metavar="PKG",
                    help="package assumed present in every build root (repeatable)")
    ap.add_argument("--indirect-depth", type=int, default=1, metavar="N",
                    help="how many dependency hops may still credit a declaration "
                         "(default 1: a wrapper package honoured by what it requires)")
    ap.add_argument("--max-files", type=int, default=5,
                    help="how many example paths to print per package (default 5)")
    ap.add_argument("--json", type=Path, help="also write the report as JSON")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when something was used but not declared")
    args = ap.parse_args()

    for path in (args.out_file, args.declared, args.rpm_deps, args.rpm_dump):
        if path is not None and not path.exists():
            print(f"ERROR: file not found: {path}", file=sys.stderr)
            return 2

    graph = parse_out(args.out_file)
    declared = parse_declared(args.declared)
    provides, requires = parse_rpm_deps(args.rpm_deps) if args.rpm_deps else ({}, {})
    package_of, file_lookup = make_resolvers(graph, args.rpm_dump)

    rep = audit(
        graph,
        declared=declared,
        provides=provides,
        requires=requires,
        package_of=package_of,
        file_lookup=file_lookup,
        implicit=args.implicit,
        attribution_depth=args.indirect_depth,
    )

    print(render(rep, args.max_files))

    if args.json:
        args.json.write_text(
            json.dumps(rep.to_dict(args.max_files), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"JSON written: {args.json}")

    return 1 if (args.strict and rep.used_undeclared) else 0


if __name__ == "__main__":
    sys.exit(main())
