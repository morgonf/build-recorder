#!/usr/bin/env python3
"""
provenance-verdict.py — "built entirely from source, no prebuilt binaries" verdict.

Answers the core question build-recorder exists for, from observation alone:
does the package build fully from source, with no previously-compiled binary
incorporated into its outputs?

Every file the build PRODUCED is classified by tracing its content lineage
through the observed process/file graph down to input leaves:

  GREEN  — lineage terminates only in source text and trusted inputs
           (OS-package files = toolchain/system; project source);
  RED    — incorporates a FOREIGN prebuilt binary: a .o/.a/.so/blob that was
           not compiled from source in this build and is not provided by an OS
           package (a phantom binary dependency), whether linked in or copied /
           hardlinked straight into an output;
  GREY   — produced with no observable source lineage (content from a socket or
           other unobserved channel, or a syscall-coverage gap) — the tool
           cannot assert GREEN, and says so rather than guessing.

Package verdict = GREEN iff zero RED and zero GREY.

Run enrich.py on the .out first: without OS-package attribution, system
libraries look like foreign binaries and inflate RED/GREY. The verdict is only
as sound as the graph — see the syscall-coverage audit for its assumptions
(trusted toolchain, no covert channels, in-process JVM/.NET out of scope).

Usage:
  python3 provenance-verdict.py <build.out>
  python3 provenance-verdict.py <build.out> --rpm-dump rpm-dump.txt
  python3 provenance-verdict.py <build.out> --json verdict.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from brec.ir import BuildGraph, FileNode
from brec.model import parse_out
from brec.provenance.base import ProvenanceBackend
from brec.provenance.registry import detect_backends

# ── File-kind heuristics ──────────────────────────────────────────────────────

_BIN_EXTS = frozenset({
    ".o", ".a", ".so", ".ko", ".dll", ".dylib", ".lib", ".obj",
    ".bin", ".elf", ".rlib", ".rmeta", ".class", ".jar",
})

# Copy-provenance edges written by the tracer as blank nodes (b:hardlink /
# b:rename), which brec.model does not parse. E.g.:
#   _:hardlink0  b:hardlink-from  :f20 .
#   _:hardlink0  b:hardlink-to    :f21 .
_COPY_RE = re.compile(
    r"^\s*(_:\w+)\s+b:(hardlink|rename)-(from|to)\s+(:[A-Za-z_]\w*)\s*[.;]?"
)


def is_binary(abspath: str) -> bool:
    name = Path(abspath).name.lower()
    if ".so." in name:
        return True
    return Path(name).suffix in _BIN_EXTS


def is_real_artifact(abspath: str) -> bool:
    """A meaningful build output (library or executable), not a temp/aux file."""
    name = Path(abspath).name
    sfx = Path(name).suffix.lower()
    if sfx in (".so", ".a", ".la", ".dll", ".dylib", ".ko"):
        return True
    if ".so." in name:
        return True
    if "." not in name and not name.startswith("."):   # bare executable
        return True
    return False


# ── Copy-edge parsing (supplements brec.model) ────────────────────────────────

@dataclass
class Copy:
    src: str
    dst: str
    kind: str   # "hardlink" | "rename"


def parse_copies(path: Path) -> list[Copy]:
    """Recover file→file content-copy edges (hardlink/rename) from the .out."""
    bn: dict[str, dict[str, str]] = {}
    bn_kind: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _COPY_RE.match(line)
            if not m:
                continue
            node, kind, end, target = m.group(1), m.group(2), m.group(3), m.group(4)
            bn.setdefault(node, {})[end] = target
            bn_kind[node] = kind
    copies: list[Copy] = []
    for node, ends in bn.items():
        if "from" in ends and "to" in ends:
            copies.append(Copy(src=ends["from"], dst=ends["to"], kind=bn_kind[node]))
    return copies


# ── Verdict ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    artifact: str            # abspath of the produced file
    verdict: str             # "RED" | "GREY"
    reason: str
    foreign_leaves: list[str] = field(default_factory=list)  # abspaths


@dataclass
class Report:
    verdict: str                       # GREEN | RED | GREY
    produced: int
    artifacts: int                     # real artifacts among produced
    green: int
    red: int
    grey: int
    fidelity: float                    # green / artifacts (real), 1.0 if none
    findings: list[Finding]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "produced_files": self.produced,
            "real_artifacts": self.artifacts,
            "green": self.green, "red": self.red, "grey": self.grey,
            "fidelity": round(self.fidelity, 4),
            "findings": [
                {"artifact": f.artifact, "verdict": f.verdict,
                 "reason": f.reason, "foreign_leaves": f.foreign_leaves}
                for f in self.findings
            ],
        }


def compute_verdict(
    graph: BuildGraph,
    copies: list[Copy],
    backends: list[ProvenanceBackend],
) -> Report:
    files = graph.files
    procs = graph.procs

    # produced-in-build set and the maps needed to walk lineage backwards
    writer_procs: dict[str, list] = {}
    for p in procs.values():
        for w in p.writes:
            writer_procs.setdefault(w, []).append(p)
    copy_src: dict[str, str] = {c.dst: c.src for c in copies}
    produced: set[str] = set(writer_procs) | set(copy_src)

    _pkg_cache: dict[str, bool] = {}

    def has_package(furi: str) -> bool:
        if furi in _pkg_cache:
            return _pkg_cache[furi]
        fn = files.get(furi)
        ok = False
        if fn is not None:
            # Package attribution baked in by enrich.py takes precedence, so the
            # verdict runs on an enriched .out with no live backend needed.
            if fn.pkg_name or fn.rpm_name:
                ok = True
            else:
                for b in backends:
                    if b.available() and b.lookup(fn.abspath, fn.git_blob_sha1):
                        ok = True
                        break
        _pkg_cache[furi] = ok
        return ok

    def is_foreign_binary(furi: str) -> bool:
        """A pre-existing binary leaf with no OS package — a prebuilt not built here."""
        if furi in produced:
            return False
        fn = files.get(furi)
        if fn is None:
            return False
        return is_binary(fn.abspath) and not has_package(furi)

    # Terminal input leaves feeding a produced file's content.
    _leaf_cache: dict[str, set[str]] = {}

    def leaves(furi: str, seen: frozenset[str]) -> set[str]:
        if furi in _leaf_cache:
            return _leaf_cache[furi]
        if furi in seen:
            return set()
        seen = seen | {furi}
        result: set[str] = set()
        if furi in copy_src:                      # content is the copy source
            src = copy_src[furi]
            result = leaves(src, seen) if src in produced else {src}
        elif furi in writer_procs:                # produced by a process
            for p in writer_procs[furi]:
                for r in p.reads:
                    if r in produced and r != furi:
                        result |= leaves(r, seen)
                    else:
                        result.add(r)
        _leaf_cache[furi] = result
        return result

    findings: list[Finding] = []
    green = red = grey = 0
    real = 0
    for furi in produced:
        fn = files.get(furi)
        if fn is None:
            continue
        real_art = is_real_artifact(fn.abspath)
        if real_art:
            real += 1
        ls = leaves(furi, frozenset())
        foreign = sorted(
            files[l].abspath for l in ls if is_foreign_binary(l)
        )
        if foreign:
            red += 1
            findings.append(Finding(
                artifact=fn.abspath, verdict="RED",
                reason="incorporates prebuilt binary not built from source in this build",
                foreign_leaves=foreign,
            ))
        elif not ls:
            # No observable lineage. Only flag real artifacts / copied binaries;
            # a produced temp with no reads is not evidence of a prebuilt.
            if real_art or is_binary(fn.abspath):
                grey += 1
                findings.append(Finding(
                    artifact=fn.abspath, verdict="GREY",
                    reason="produced with no observable source lineage",
                ))
            else:
                green += 1
        else:
            green += 1

    verdict = "RED" if red else ("GREY" if grey else "GREEN")
    fidelity = 1.0 if real == 0 else (real - _real_bad(findings, files)) / real
    return Report(
        verdict=verdict, produced=len(produced), artifacts=real,
        green=green, red=red, grey=grey, fidelity=fidelity,
        findings=sorted(findings, key=lambda f: (f.verdict, f.artifact)),
    )


def _real_bad(findings: list[Finding], files: dict[str, FileNode]) -> int:
    return sum(1 for f in findings if is_real_artifact(f.artifact))


# ── CLI ────────────────────────────────────────────────────────────────────────

_BANNER = {"GREEN": "🟢 GREEN", "RED": "🔴 RED", "GREY": "⚪ GREY"}


def _format_report(rep: Report, out_path: str) -> str:
    lines = []
    lines.append(f"Provenance verdict for {out_path}: {_BANNER[rep.verdict]}")
    lines.append(
        f"  produced files: {rep.produced}   real artifacts: {rep.artifacts}   "
        f"GREEN {rep.green} · RED {rep.red} · GREY {rep.grey}"
    )
    lines.append(f"  artifact fidelity (real GREEN / real): {rep.fidelity:.1%}")
    if rep.verdict == "GREEN":
        lines.append("  → every produced file traces to source + trusted inputs.")
    for f in rep.findings:
        lines.append("")
        lines.append(f"  {_BANNER[f.verdict]}  {f.artifact}")
        lines.append(f"      {f.reason}")
        for leaf in f.foreign_leaves:
            lines.append(f"      ← prebuilt: {leaf}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Built-from-source / no-prebuilt-binary verdict.")
    ap.add_argument("out_file", type=Path, help="build-recorder .out (enriched)")
    ap.add_argument("--rpm-dump", type=Path, default=None,
                    help="rpm file→package dump for OS-package attribution")
    ap.add_argument("--json", type=Path, default=None, help="write JSON report here")
    args = ap.parse_args()

    if not args.out_file.exists():
        print(f"error: {args.out_file} not found", file=sys.stderr)
        return 2

    graph = parse_out(args.out_file)
    copies = parse_copies(args.out_file)
    backends = detect_backends(args.rpm_dump)

    rep = compute_verdict(graph, copies, backends)

    print(_format_report(rep, str(args.out_file)))
    if args.json:
        args.json.write_text(json.dumps(rep.to_dict(), indent=2))
        print(f"\nJSON report → {args.json}")

    # Exit code: 0 GREEN, 1 RED, 2 GREY (unverifiable)
    return {"GREEN": 0, "RED": 1, "GREY": 3}[rep.verdict]


if __name__ == "__main__":
    sys.exit(main())
