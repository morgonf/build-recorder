#!/usr/bin/env python3
"""
compare_modules.py — the trace against the ecosystem's own component list.

Where a language has a lock file, the declared component list is exact, so it
can serve as the reference for what the build was made of.  Two references are
used here, both written by the toolchain rather than by a person:

  Go    `vendor/modules.txt` lists every vendored module; the built binary
        carries its own stamp (`go version -m`), which names the modules that
        actually went in.
  Rust  `Cargo.lock` pins every crate in the dependency graph; the dep-info
        files cargo leaves in `target/*/deps/` name the crates it actually
        compiled.

The comparison asks two different questions, and the interesting one is the
second:

  1. Did the trace see every component the toolchain says it used?
     Anything here is a hole in the observation.
  2. Which vendored components did the build never touch?
     A lock file names what could be used; the trace shows what was.  This is
     the claim "the trace excludes what was never compiled", stated as a number
     instead of an anecdote.

Usage:
  compare_modules.py TRACE.out --go-modules vendor-modules.txt --go-stamp go-version-m.txt
  compare_modules.py TRACE.out --cargo-lock Cargo.lock --rust-depinfo DIR
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from brec.model import parse_out


# ── Reference sides ──────────────────────────────────────────────────────────

def parse_go_modules_txt(path: Path) -> set[str]:
    """Modules present in vendor/, from the lines `# module version`."""
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("# "):
            parts = line[2:].split()
            if parts:
                out.add(parts[0])
    return out


def parse_go_stamp(path: Path) -> set[str]:
    """Modules the built binary says it contains (`go version -m`)."""
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2 and parts[0] in ("dep", "mod"):
            out.add(parts[1])
    return out


def _canon(name: str) -> str:
    """One spelling for one crate.

    Cargo publishes some crates with a dash and vendors them under an
    underscore (`clap-builder` against `clap_builder/`), and rustc uses the
    underscore form throughout. Comparing the raw strings reports a difference
    where there is none.
    """
    return name.replace("-", "_")


def parse_cargo_lock(path: Path) -> set[str]:
    """Crate names pinned in Cargo.lock."""
    out = set()
    for m in re.finditer(r'^name\s*=\s*"([^"]+)"', path.read_text(
            encoding="utf-8", errors="replace"), re.M):
        out.add(_canon(m.group(1)))
    return out


def parse_rust_depinfo(dirpath: Path) -> set[str]:
    """Crates cargo actually compiled, from the dep-info files it wrote.

    Cargo names them `<crate>-<metadata hash>.d`; the crate name is everything
    before the last dash.
    """
    out = set()
    for dep in dirpath.glob("*.d"):
        stem = dep.stem
        crate = stem.rsplit("-", 1)[0] if "-" in stem else stem
        out.add(_canon(crate))
    return out


# ── Trace side ───────────────────────────────────────────────────────────────

def trace_components(trace: Path, marker: str,
                     known: set[str] | None = None) -> dict[str, int]:
    """Components named by the paths the build read, with a file count.

    *marker* is the directory that separates the component space from the rest
    of the tree (`/vendor/`).  Component names have no fixed depth — a Rust
    crate is one segment, a Go module path is three or more — so when the
    reference list is available the name is the longest one that prefixes the
    path, and otherwise the first segment.
    """
    graph = parse_out(trace)
    reads: set[str] = set()
    for proc in graph.procs.values():
        for uri in proc.reads:
            node = graph.files.get(uri)
            if node is not None and node.abspath:
                reads.add(node.abspath)

    ordered = sorted(known or (), key=len, reverse=True)
    counts: dict[str, int] = {}
    for path in reads:
        idx = path.find(marker)
        if idx < 0:
            continue
        rest = path[idx + len(marker):]
        if not rest:
            continue
        name = None
        for candidate in ordered:
            if rest == candidate or rest.startswith(candidate + "/"):
                name = candidate
                break
        if name is None:
            name = rest.split("/")[0]
        counts[name] = counts.get(name, 0) + 1
    return counts


def _report(title: str, used: set[str], declared: set[str], seen: dict[str, int],
            show: int) -> dict:
    unseen_used = sorted(u for u in used if u not in seen)
    untouched = sorted(d for d in declared if d not in seen and d not in used)
    touched_unused = sorted(s for s in seen if s not in used and s in declared)

    print(f"=== {title} ===")
    print(f"  declared in the lock file : {len(declared)}")
    print(f"  used per the toolchain    : {len(used)}")
    print(f"  seen in the trace         : {len(seen)}")
    print()
    print(f"USED BUT NEVER SEEN — a hole in the observation ({len(unseen_used)}):")
    if not unseen_used:
        print("  none")
    for name in unseen_used[:show]:
        print(f"  {name}")
    print()
    print(f"VENDORED AND NEVER TOUCHED — dead weight the trace excludes ({len(untouched)}):")
    for name in untouched[:show]:
        print(f"  {name}")
    if len(untouched) > show:
        print(f"  ... {len(untouched) - show} more")
    print()
    if touched_unused:
        print(f"TOUCHED BUT NOT IN THE FINAL ARTIFACT ({len(touched_unused)}):")
        print("  (read during the build — build scripts, probes — yet absent from what shipped)")
        for name in touched_unused[:show]:
            print(f"  {name} ({seen[name]} file(s))")
        print()

    return {
        "declared": sorted(declared),
        "used": sorted(used),
        "seen": {k: seen[k] for k in sorted(seen)},
        "used_but_never_seen": unseen_used,
        "vendored_never_touched": untouched,
        "touched_but_not_shipped": touched_unused,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("trace", type=Path)
    ap.add_argument("--go-modules", type=Path, help="vendor/modules.txt")
    ap.add_argument("--go-stamp", type=Path, help="output of `go version -m <binary>`")
    ap.add_argument("--cargo-lock", type=Path)
    ap.add_argument("--rust-depinfo", type=Path, help="directory of cargo dep-info files")
    ap.add_argument("--marker", default="/vendor/", help="path segment that starts a component")
    ap.add_argument("--show", type=int, default=12)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    if args.go_modules or args.go_stamp:
        declared = parse_go_modules_txt(args.go_modules) if args.go_modules else set()
        used = parse_go_stamp(args.go_stamp) if args.go_stamp else set()
        # Go module paths have several segments: match against the longest
        # declared name that a path starts with, rather than guessing a depth.
        seen = trace_components(args.trace, args.marker, known=declared | used)
        # The main module is the project itself: its sources do not live under
        # vendor/, so it is not a component this comparison can speak about.
        main = {m for m in used if not any(
            m == d or m.startswith(d + "/") for d in declared)} & used
        used = used - main
        payload = _report("Go modules", used, declared, seen, args.show)
        payload["main_module_excluded"] = sorted(main)
    elif args.cargo_lock or args.rust_depinfo:
        declared = parse_cargo_lock(args.cargo_lock) if args.cargo_lock else set()
        used = parse_rust_depinfo(args.rust_depinfo) if args.rust_depinfo else set()
        seen = {
            _canon(k): v
            for k, v in trace_components(args.trace, args.marker,
                                         known=declared | used).items()
        }
        # The crate being built lives in the source tree, not in vendor/, so no
        # path can attest to it. Cargo also names the binary after the target
        # rather than the package (`fd` out of `fd-find`), which no path can
        # reconcile either; both are excluded rather than reported as holes.
        local = {c for c in used if c not in declared}
        used = used - local
        payload = _report("Rust crates", used, declared, seen, args.show)
        payload["local_crates_excluded"] = sorted(local)
    else:
        ap.error("give either the Go inputs or the Rust ones")

    if args.json:
        args.json.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                             encoding="utf-8")
        print(f"JSON written: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
