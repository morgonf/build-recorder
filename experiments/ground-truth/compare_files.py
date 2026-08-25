#!/usr/bin/env python3
"""
compare_files.py — the trace against the compiler's own account of its inputs.

Two instruments answer one question here.  The compiler keeps its own list of
the files it read (`gcc -MD`, `rustc --emit=dep-info`, both in Make depfile
syntax); build-recorder observes the same build from outside, through ptrace.
The mechanisms share nothing, so their disagreements are informative.

The asymmetry matters and is the whole point:

  R \\ T   the compiler says it read a file the tracer never saw.
          This must be empty.  A single entry is a defect in the tracer, and
          worth more than any number of clean runs.
  T \\ R   the tracer saw files the depfile does not list.  This must NOT be
          empty: a depfile covers preprocessing only, so the compiler binary
          itself, its specs, crt objects, libraries, linker inputs and any
          generated sources are missing from it by construction.  What is
          required here is that every such file falls into a nameable category.

Depfiles record paths as the command line spelled them, so relative names only
resolve next to the directory the compiler ran in; the cc wrapper stores that
directory beside each depfile as `<name>.cwd`.  Without it, `--build-root` is
the fallback.

Usage:
  compare_files.py TRACE.out --depfiles DIR [--depfiles DIR] \\
      [--build-root /root/RPM/BUILD/pkg-1.0] [--rpm-dump rpm-dump.txt] [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from brec.model import parse_out
from brec.provenance.registry import detect_backends

# A depfile is Make syntax: "target: dep dep \" with backslash continuations
# and backslash-escaped spaces inside names.
_TARGET_SPLIT = re.compile(r"(?<!\\):\s")


def parse_depfile(path: Path) -> tuple[str, list[str]]:
    """Return (target, dependencies) from one Make-style depfile."""
    text = path.read_text(encoding="utf-8", errors="replace")
    text = text.replace("\\\n", " ")
    parts = _TARGET_SPLIT.split(text, maxsplit=1)
    if len(parts) != 2:
        return ("", [])
    target, deps = parts
    items = [d.replace("\\ ", " ") for d in deps.split()]
    # rustc emits extra "file:" lines after the rule; they repeat what is above.
    items = [d for d in items if not d.endswith(":")]
    return (target.strip(), items)


def collect_reference(dirs: list[Path], build_root: str | None) -> tuple[set[str], int, int]:
    """Union of everything the compilers recorded, as absolute paths.

    Returns (paths, depfiles_read, entries_seen).  Relative names resolve
    against the `.cwd` sidecar written next to the depfile, falling back to
    *build_root*; a name that resolves nowhere is kept as-is so it shows up in
    the report rather than disappearing quietly.
    """
    out: set[str] = set()
    files = 0
    entries = 0
    for d in dirs:
        for dep in sorted(d.rglob("*.d")):
            target, items = parse_depfile(dep)
            if not items:
                continue
            files += 1
            cwd_file = dep.with_suffix(".cwd")
            cwd = None
            if cwd_file.exists():
                cwd = cwd_file.read_text(encoding="utf-8", errors="replace").strip()
            cwd = cwd or build_root
            for item in items:
                entries += 1
                if item.startswith("/"):
                    out.add(os.path.normpath(item))
                elif cwd:
                    out.add(os.path.normpath(os.path.join(cwd, item)))
                else:
                    out.add(item)
    return out, files, entries


def _names(node) -> set[str]:
    """Both spellings of one file node.

    The tracer resolves symlinks, so `b:abspath` can name a file the build
    never mentioned: on ALT `/usr/include/asm/errno.h` resolves into
    `/usr/include/linux-default/include/asm-x86/errno.h`.  A depfile records
    what the command line said instead.  Both belong in the comparison, or the
    same file counts as missing under one name and surplus under the other.
    """
    out: set[str] = set()
    if node is None:
        return out
    if node.abspath:
        out.add(os.path.normpath(node.abspath))
    if node.name and node.name.startswith("/"):
        out.add(os.path.normpath(node.name))
    return out


def trace_reads(trace: Path) -> tuple[set[str], set[str]]:
    """(files read by the build, files written by it), under every spelling."""
    graph = parse_out(trace)
    reads: set[str] = set()
    writes: set[str] = set()
    for proc in graph.procs.values():
        for uri in proc.reads:
            reads |= _names(graph.files.get(uri))
        for uri in proc.writes:
            writes |= _names(graph.files.get(uri))
        if proc.executable:
            reads |= _names(graph.files.get(proc.executable))
    return reads, writes


def categorise(paths: set[str], writes: set[str], package_of) -> dict[str, list[str]]:
    """Sort the tracer's surplus into categories a reader can accept or reject."""
    cats: dict[str, list[str]] = defaultdict(list)
    for path in sorted(paths):
        name = os.path.basename(path)
        if path in writes:
            cat = "generated by this build"
        elif path.startswith(("/proc", "/sys", "/dev")):
            cat = "kernel interfaces"
        elif name.endswith((".so", ".a")) or ".so." in name:
            cat = "libraries (link stage, absent from depfiles)"
        elif name.endswith((".o", ".lo", ".obj")):
            cat = "object files (link stage)"
        elif name.endswith((".c", ".cc", ".cpp", ".cxx", ".rs", ".go", ".S", ".s")):
            cat = "source read outside a recorded compilation"
        elif name.endswith((".h", ".hpp", ".hh", ".inc")):
            cat = "headers outside a recorded compilation"
        elif package_of(path):
            cat = "toolchain and OS package files"
        else:
            cat = "other"
        cats[cat].append(path)
    return dict(cats)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("trace", type=Path)
    ap.add_argument("--depfiles", type=Path, action="append", required=True,
                    help="directory holding *.d files (repeatable)")
    ap.add_argument("--build-root", help="fallback directory for relative depfile entries")
    ap.add_argument("--rpm-dump", type=Path, help="file→package index, for categorising the surplus")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--show", type=int, default=15, help="how many paths to print per list")
    args = ap.parse_args()

    reference, n_files, n_entries = collect_reference(
        [d for d in args.depfiles if d.exists()], args.build_root
    )
    reads, writes = trace_reads(args.trace)

    missed = reference - reads          # must be empty
    surplus = reads - reference

    backends = detect_backends(args.rpm_dump) if args.rpm_dump else []

    def package_of(path: str):
        for b in backends:
            if b.available():
                ref = b.lookup(path, "")
                if ref is not None:
                    return ref.name
        return None

    cats = categorise(surplus, writes, package_of)

    print("=== Trace against the compiler's own depfiles ===")
    print(f"  depfiles read      : {n_files} ({n_entries} entries)")
    print(f"  reference files R  : {len(reference)}")
    print(f"  files read in trace: {len(reads)}")
    print()
    print(f"MISSED BY THE TRACER — R \\ T ({len(missed)}):")
    if not missed:
        print("  none: everything the compiler recorded was observed")
    for path in sorted(missed)[: args.show]:
        print(f"  {path}")
    if len(missed) > args.show:
        print(f"  ... {len(missed) - args.show} more")
    print()
    print(f"SEEN BEYOND THE DEPFILES — T \\ R ({len(surplus)}), by category:")
    for cat, items in sorted(cats.items(), key=lambda kv: -len(kv[1])):
        print(f"  {cat}: {len(items)}")
        for path in items[:3]:
            print(f"      {path}")

    if args.json:
        args.json.write_text(json.dumps({
            "reference_files": len(reference),
            "trace_reads": len(reads),
            "depfiles": n_files,
            "missed_by_tracer": sorted(missed),
            "surplus_by_category": {k: sorted(v) for k, v in cats.items()},
        }, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nJSON written: {args.json}")

    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
