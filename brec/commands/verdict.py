"""
brec verdict — "built entirely from source, no prebuilt binaries" verdict.

Answers the core question build-recorder exists for, from observation alone:
does the package build fully from source, with no previously-compiled binary
incorporated into its outputs?

Every file the build PRODUCED is classified by tracing its content lineage
through the observed process/file graph down to input leaves:

  GREEN  — lineage terminates only in source text and trusted inputs
           (OS-package files = toolchain/system; project source);
  RED    — incorporates a FOREIGN prebuilt binary: a .o/.a/.so/blob that was
           not compiled from source in this build, is not provided by an OS
           package, and sits at a path this build never wrote (a phantom binary
           dependency), whether linked in or copied / hardlinked into an output;
  GREY   — produced with no observable source lineage (content from a socket or
           other unobserved channel, or a syscall-coverage gap), or built from
           binary content that no observed write produced at a path this build
           did write.  The tool cannot assert GREEN, and says so rather than
           guessing either way.

Package verdict = GREEN iff zero RED and zero GREY.

Two things keep that verdict from being vacuous:

  --payload   closes the quantifier over what actually ships. Without it the
              verdict speaks only about files the trace happened to observe;
              a delivered file the trace never saw does not become GREY, it
              simply is not there. Each payload file is matched to the graph
              by content hash (path-independent, so a relocated buildroot
              still matches); anything unmatched is GREY.
  coverage    b:coverage_gap triples record mechanisms the tracer cannot see
    gaps      through (io_uring). A trace with a gap can never be GREEN: its
              file layer is known-incomplete, so silence is not evidence.

Run `brec enrich` on the .out first: without OS-package attribution, system
libraries look like foreign binaries and inflate RED/GREY. The verdict is only
as sound as the graph — see the syscall-coverage audit for its assumptions
(trusted toolchain, no covert channels, in-process JVM/.NET out of scope).

Usage:
  brec verdict <build.out>
  brec verdict <build.out> --rpm-dump rpm-dump.txt
  brec verdict <build.out> --payload /path/to/buildroot
  brec verdict <build.out> --payload files.list --json verdict.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from brec.classify import is_build_artifact
from brec.commands.common import add_provenance_option, load_graph
from brec.ir import BuildGraph, FileNode
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

# Self-declared blind spot of the tracer:  :p3  b:coverage_gap  "io_uring" .
_GAP_RE = re.compile(
    r"^\s*(:[A-Za-z_]\w*)\s+b:coverage_gap\s+\"([^\"]*)\"\s*[.;]?"
)


def is_binary(abspath: str) -> bool:
    name = Path(abspath).name.lower()
    if ".so." in name:
        return True
    return Path(name).suffix in _BIN_EXTS


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


# ── Coverage gaps declared by the tracer ──────────────────────────────────────

@dataclass
class CoverageGap:
    proc: str        # process URI
    kind: str        # "io_uring"
    cmd: str = ""    # filled in from the graph


def parse_coverage_gaps(path: Path) -> list[CoverageGap]:
    """Recover b:coverage_gap triples: processes whose I/O may be unobserved."""
    seen: set[tuple[str, str]] = set()
    gaps: list[CoverageGap] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = _GAP_RE.match(line)
            if not m:
                continue
            key = (m.group(1), m.group(2))
            if key in seen:
                continue
            seen.add(key)
            gaps.append(CoverageGap(proc=m.group(1), kind=m.group(2)))
    return gaps


# ── Payload closure ───────────────────────────────────────────────────────────
#
# The lineage analysis above quantifies over files the *graph* contains. That is
# not the claim we need: the claim is about files that *ship*. A payload file
# with no node in the graph (written through an unobserved channel, or by a
# process that escaped tracing) would otherwise be invisible to the verdict,
# its absence read as "nothing to report". Here it reads as GREY.

_ALGO_BY_HEXLEN = {40: "sha1", 64: "sha256"}


@dataclass
class PayloadEntry:
    path: str                # as listed / found
    sha: str = ""            # git-blob hash, "" when content unavailable
    status: str = ""         # green | red | grey
    reason: str = ""
    matched_uri: str = ""


@dataclass
class PayloadStats:
    total: int = 0           # regular files considered
    green: int = 0
    red: int = 0
    grey: int = 0
    symlinks: int = 0        # skipped: no content of their own
    unreadable: int = 0      # listed but not present locally → path-only check
    algo: str = "sha1"

    def to_dict(self) -> dict:
        return {
            "total": self.total, "green": self.green, "red": self.red,
            "grey": self.grey, "symlinks_skipped": self.symlinks,
            "path_only_checked": self.unreadable, "hash_algorithm": self.algo,
        }


def git_blob_hash(path: Path, algo: str = "sha1") -> str:
    """git-blob digest of a file: hash("blob <size>\\0" + content).

    Mirrors src/hash.c so payload files hash identically to graph nodes; the
    algorithm follows whatever the trace used (-2/--sha256 writes sha256).
    """
    size = path.stat().st_size
    h = hashlib.new(algo)
    h.update(f"blob {size}\0".encode())
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def detect_hash_algo(files: dict[str, FileNode]) -> str:
    """Pick the digest the trace used, from the length of the hashes in it."""
    counts: dict[str, int] = {}
    for fn in files.values():
        algo = _ALGO_BY_HEXLEN.get(len(fn.git_blob_sha1 or ""))
        if algo:
            counts[algo] = counts.get(algo, 0) + 1
    if not counts:
        return "sha1"
    return max(counts, key=lambda a: counts[a])


def collect_payload(spec: Path) -> list[tuple[str, Path | None]]:
    """Payload file list from a directory tree (buildroot) or a list of paths.

    Returns (recorded-path, local-path-or-None); the local path is where the
    content can be read, when it can be read at all.
    """
    if spec.is_dir():
        out: list[tuple[str, Path | None]] = []
        for p in sorted(spec.rglob("*")):
            out.append((str(p), p))
        return out

    entries: list[tuple[str, Path | None]] = []
    for line in spec.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        p = Path(line)
        entries.append((line, p if p.exists() else None))
    return entries


# ── Verdict ───────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    artifact: str            # abspath of the produced file
    verdict: str             # "RED" | "GREY"
    reason: str
    foreign_leaves: list[str] = field(default_factory=list)  # abspaths
    unattributed_leaves: list[str] = field(default_factory=list)  # abspaths


@dataclass
class Report:
    verdict: str                       # GREEN | RED | GREY
    produced: int
    artifacts: int                     # real artifacts among produced
    green: int
    red: int
    grey: int
    fidelity: float                    # green share (of payload if given)
    findings: list[Finding]
    coverage_gaps: list[CoverageGap] = field(default_factory=list)
    payload: PayloadStats | None = None
    payload_entries: list[PayloadEntry] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "produced_files": self.produced,
            "real_artifacts": self.artifacts,
            "green": self.green, "red": self.red, "grey": self.grey,
            "fidelity": round(self.fidelity, 4),
            "findings": [
                {"artifact": f.artifact, "verdict": f.verdict,
                 "reason": f.reason, "foreign_leaves": f.foreign_leaves,
                 "unattributed_leaves": f.unattributed_leaves}
                for f in self.findings
            ],
            "coverage_gaps": [
                {"process": g.proc, "kind": g.kind, "cmd": g.cmd}
                for g in self.coverage_gaps
            ],
            "payload": self.payload.to_dict() if self.payload else None,
            "payload_findings": [
                {"path": e.path, "verdict": e.status.upper(), "reason": e.reason}
                for e in self.payload_entries if e.status != "green"
            ],
        }


def _condense(
    nodes: set[str],
    inputs: dict[str, set[str]],
    direct: dict[str, set[str]],
) -> tuple[dict[str, int], list[set[str]]]:
    """Contract cycles, then collect each component's terminal inputs.

    Strongly connected components of the produced-file graph (Tarjan, iterative
    so a deep build tree cannot overflow the stack).  Tarjan closes a component
    only after every component it points to, so a component's leaves are its
    members' own terminal inputs plus the leaves of the components they reach,
    all of them already computed.

    Returns ``(component of each node, leaves of each component)``.
    """
    comp_of: dict[str, int] = {}
    comp_leaves: list[set[str]] = []

    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    counter = 0

    for root in nodes:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[str, object]] = [(root, iter(inputs.get(root, ())))]

        while work:
            node, it = work[-1]
            descended = False
            for nxt in it:                       # type: ignore[union-attr]
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, iter(inputs.get(nxt, ()))))
                    descended = True
                    break
                if nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
            if descended:
                continue

            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])

            if low[node] != index[node]:
                continue

            members: list[str] = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                members.append(member)
                if member == node:
                    break

            cid = len(comp_leaves)
            collected: set[str] = set()
            for member in members:
                comp_of[member] = cid
                collected |= direct.get(member, set())
            for member in members:
                for nxt in inputs.get(member, ()):
                    other = comp_of.get(nxt)
                    if other is not None and other != cid:
                        collected |= comp_leaves[other]
            comp_leaves.append(collected)

    return comp_of, comp_leaves


def compute_verdict(
    graph: BuildGraph,
    copies: list[Copy],
    backends: list[ProvenanceBackend],
    gaps: list[CoverageGap] | None = None,
    payload: list[tuple[str, Path | None]] | None = None,
) -> Report:
    files = graph.files
    procs = graph.procs
    gaps = list(gaps or [])

    # produced-in-build set and the maps needed to walk lineage backwards
    writer_procs: dict[str, list] = {}
    for p in procs.values():
        for w in p.writes:
            writer_procs.setdefault(w, []).append(p)

    # Processes that used a mechanism able to move file content past the tracer.
    # Anything they wrote has a lineage we cannot vouch for, even when the graph
    # shows one: the reads we saw need not be all the reads there were.
    gap_procs = {g.proc for g in gaps}
    for g in gaps:
        pn = procs.get(g.proc)
        if pn is not None:
            g.cmd = pn.cmd
    copy_src: dict[str, str] = {c.dst: c.src for c in copies}
    produced: set[str] = set(writer_procs) | set(copy_src)

    _pkg_cache: dict[str, bool] = {}

    def has_package(furi: str) -> bool:
        if furi in _pkg_cache:
            return _pkg_cache[furi]
        fn = files.get(furi)
        ok = False
        if fn is not None:
            # Package attribution baked in by `brec enrich` takes precedence, so the
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

    # Paths this build wrote at least once.  Content found at such a path is a
    # different question from content found anywhere else: see
    # is_unattributed_binary() below.
    written_paths = {
        files[u].abspath for u in writer_procs if u in files
    }

    def _unowned_binary(furi: str) -> bool:
        if furi in produced:
            return False
        fn = files.get(furi)
        if fn is None:
            return False
        return is_binary(fn.abspath) and not has_package(furi)

    def is_foreign_binary(furi: str) -> bool:
        """A pre-existing binary leaf with no OS package: a prebuilt not built here."""
        if not _unowned_binary(furi):
            return False
        return files[furi].abspath not in written_paths

    def is_unattributed_binary(furi: str) -> bool:
        """Binary content at a path this build wrote, that no observed write produced.

        The tracer hashes a file opened for writing at close(), not at the write
        (src/tracer.c), so when two threads hold the same path open the hash
        recorded for one write is the content the other left.  The intermediate
        state a reader saw then belongs to no write node, and it is that orphan
        node arriving here.  Calling it a prebuilt from outside would be wrong:
        this build was writing that path.  Calling it source-clean would be a
        guess.  It is the definition of GREY, and it is reported as such.
        """
        if not _unowned_binary(furi):
            return False
        return files[furi].abspath in written_paths

    # ── Terminal input leaves feeding a produced file's content ──────────────
    #
    # Each produced file's inputs split in two: the ones this build also
    # produced, which are edges to follow, and the terminal ones, which are the
    # leaves being looked for.
    #
    # The build graph has cycles: a file written, read and written again is on
    # its own lineage.  Following the edges recursively and stopping at the
    # second visit answers per walk-path, not per file, and caching that answer
    # hands it to every later caller, so the verdict depended on the order the
    # files were walked in.  On the fd build that moved the GREY count between
    # 192 and 197 across runs of the same trace.  Contracting each cycle into a
    # single node removes the question: whatever a cycle reads is lineage for
    # every file in it, whichever way the walk enters.

    inputs: dict[str, set[str]] = {}     # produced -> produced (edges)
    direct: dict[str, set[str]] = {}     # produced -> terminal inputs (leaves)
    for furi in produced:
        ins: set[str] = set()
        lvs: set[str] = set()
        if furi in copy_src:                      # content is the copy source
            src = copy_src[furi]
            (ins if src in produced else lvs).add(src)
        elif furi in writer_procs:                # produced by a process
            for p in writer_procs[furi]:
                for r in p.reads:
                    # A file that reads itself is its own earlier content, not
                    # an edge to follow; it stays a leaf, as it always was.
                    if r in produced and r != furi:
                        ins.add(r)
                    else:
                        lvs.add(r)
        inputs[furi] = ins
        direct[furi] = lvs

    comp_of, comp_leaves = _condense(produced, inputs, direct)

    def leaves(furi: str) -> set[str]:
        cid = comp_of.get(furi)
        return comp_leaves[cid] if cid is not None else set()

    findings: list[Finding] = []
    verdict_by_uri: dict[str, str] = {}
    green = red = grey = 0
    real = 0
    # In graph order, not set order: the findings below are printed in the order
    # they are appended, and iterating the set put the same trace's findings in a
    # different order on every run (string hashing is randomised).
    for furi in files:
        if furi not in produced:
            continue
        fn = files[furi]
        real_art = is_build_artifact(fn.abspath)
        if real_art:
            real += 1
        ls = leaves(furi)
        foreign = sorted(
            files[l].abspath for l in ls if is_foreign_binary(l)
        )
        unattributed = sorted(
            files[l].abspath for l in ls if is_unattributed_binary(l)
        )
        written_through_gap = any(
            p.uri in gap_procs for p in writer_procs.get(furi, [])
        )
        if foreign:
            red += 1
            verdict_by_uri[furi] = "RED"
            findings.append(Finding(
                artifact=fn.abspath, verdict="RED",
                reason="incorporates prebuilt binary not built from source in this build",
                foreign_leaves=foreign,
            ))
        elif unattributed:
            grey += 1
            verdict_by_uri[furi] = "GREY"
            findings.append(Finding(
                artifact=fn.abspath, verdict="GREY",
                reason="incorporates binary content that no observed write "
                       "produced, at a path this build did write",
                unattributed_leaves=unattributed,
            ))
        elif written_through_gap:
            grey += 1
            verdict_by_uri[furi] = "GREY"
            findings.append(Finding(
                artifact=fn.abspath, verdict="GREY",
                reason="written by a process using io_uring: its reads may be unobserved, "
                       "so the lineage shown is not known to be complete",
            ))
        elif not ls:
            # No observable lineage. Only flag real artifacts / copied binaries;
            # a produced temp with no reads is not evidence of a prebuilt.
            if real_art or is_binary(fn.abspath):
                grey += 1
                verdict_by_uri[furi] = "GREY"
                findings.append(Finding(
                    artifact=fn.abspath, verdict="GREY",
                    reason="produced with no observable source lineage",
                ))
            else:
                green += 1
                verdict_by_uri[furi] = "GREEN"
        else:
            green += 1
            verdict_by_uri[furi] = "GREEN"

    pstats, pentries = (
        check_payload(files, produced, verdict_by_uri, payload)
        if payload is not None else (None, [])
    )

    verdict = (
        "RED" if red or (pstats and pstats.red)
        else "GREY" if grey or gaps or (pstats and pstats.grey)
        else "GREEN"
    )
    if pstats and pstats.total:
        # With a payload, fidelity means what it should: the share of *shipped*
        # files whose content traces back to source.
        fidelity = pstats.green / pstats.total
    else:
        fidelity = 1.0 if real == 0 else (real - _real_bad(findings, files)) / real
    return Report(
        verdict=verdict, produced=len(produced), artifacts=real,
        green=green, red=red, grey=grey, fidelity=fidelity,
        findings=sorted(findings, key=lambda f: (f.verdict, f.artifact)),
        coverage_gaps=gaps, payload=pstats, payload_entries=pentries,
    )


def check_payload(
    files: dict[str, FileNode],
    produced: set[str],
    verdict_by_uri: dict[str, str],
    payload: list[tuple[str, Path | None]],
) -> tuple[PayloadStats, list[PayloadEntry]]:
    """Match every shipped file to the graph, by content hash then by path.

    Hash first, because it is path-independent: a buildroot inspected after the
    fact, or an extracted package, still matches the nodes written during the
    build. A file that matches nothing was shipped without being observed, the
    one case a graph-only verdict cannot see at all.
    """
    algo = detect_hash_algo(files)
    stats = PayloadStats(algo=algo)
    entries: list[PayloadEntry] = []

    by_hash: dict[str, list[str]] = {}
    by_path: dict[str, list[str]] = {}
    for uri, fn in files.items():
        if fn.git_blob_sha1:
            by_hash.setdefault(fn.git_blob_sha1, []).append(uri)
        by_path.setdefault(fn.abspath, []).append(uri)

    def worst(uris: list[str]) -> str:
        vs = {verdict_by_uri.get(u, "GREEN") for u in uris}
        return "RED" if "RED" in vs else ("GREY" if "GREY" in vs else "GREEN")

    for recorded, local in payload:
        if local is not None:
            if local.is_symlink():
                stats.symlinks += 1
                continue
            if not local.is_file():
                continue

        e = PayloadEntry(path=recorded)
        stats.total += 1

        if local is not None:
            try:
                e.sha = git_blob_hash(local, algo)
            except OSError as exc:
                e.sha = ""
                e.reason = f"unreadable: {exc.strerror}"
        else:
            stats.unreadable += 1

        hits = by_hash.get(e.sha, []) if e.sha else []
        made = [u for u in hits if u in produced]

        if made:
            e.matched_uri = made[0]
            v = worst(made)
            if v == "RED":
                e.status, e.reason = "red", "content is a build output flagged RED"
            elif v == "GREY":
                e.status, e.reason = "grey", "content is a build output flagged GREY"
            else:
                e.status = "green"
        elif hits:
            e.matched_uri = hits[0]
            e.status = "grey"
            e.reason = ("content matches a file the build only read, never wrote: "
                        "the copy that put it in the payload was not observed")
        elif not e.sha and by_path.get(recorded):
            # Path-only evidence (content not available locally): weaker, but a
            # produced node for that exact path is still something.
            made_path = [u for u in by_path[recorded] if u in produced]
            if made_path:
                e.matched_uri = made_path[0]
                v = worst(made_path)
                e.status = "green" if v == "GREEN" else v.lower()
                if v != "GREEN":
                    e.reason = f"path matches a build output flagged {v}"
                else:
                    e.reason = "matched by path only (content not available)"
            else:
                e.status = "grey"
                e.reason = "path known to the build only as an input, never written"
        elif by_path.get(recorded):
            e.status = "grey"
            e.reason = ("content differs from every observed version of this path: "
                        "it was modified after the last observed write")
        else:
            e.status = "grey"
            e.reason = "not present in the build graph: shipped without being observed"

        entries.append(e)
        if e.status == "green":
            stats.green += 1
        elif e.status == "red":
            stats.red += 1
        else:
            stats.grey += 1

    return stats, entries


def _real_bad(findings: list[Finding], files: dict[str, FileNode]) -> int:
    return sum(1 for f in findings if is_build_artifact(f.artifact))


# ── CLI ────────────────────────────────────────────────────────────────────────

_BANNER = {"GREEN": "🟢 GREEN", "RED": "🔴 RED", "GREY": "⚪ GREY"}


def _format_report(rep: Report, out_path: str) -> str:
    lines = []
    lines.append(f"Provenance verdict for {out_path}: {_BANNER[rep.verdict]}")
    lines.append(
        f"  produced files: {rep.produced}   real artifacts: {rep.artifacts}   "
        f"GREEN {rep.green} · RED {rep.red} · GREY {rep.grey}"
    )
    scope = "payload GREEN / payload" if rep.payload else "real GREEN / real"
    lines.append(f"  artifact fidelity ({scope}): {rep.fidelity:.1%}")

    if rep.payload:
        p = rep.payload
        lines.append(
            f"  payload closure: {p.total} files ({p.algo}): "
            f"GREEN {p.green} · RED {p.red} · GREY {p.grey}"
            + (f"; {p.symlinks} symlinks skipped" if p.symlinks else "")
            + (f"; {p.unreadable} checked by path only" if p.unreadable else "")
        )
    else:
        lines.append("  payload closure: not checked (--payload); the verdict "
                     "covers observed files only, not what ships")

    if rep.coverage_gaps:
        lines.append(f"  coverage gaps: {len(rep.coverage_gaps)} process(es) used "
                     "I/O this tracer cannot observe; GREEN is not available")

    if rep.verdict == "GREEN":
        lines.append("  → every produced file traces to source + trusted inputs.")
        if rep.payload:
            lines.append("  → every shipped file matches an observed build output.")

    for g in rep.coverage_gaps:
        lines.append("")
        lines.append(f"  {_BANNER['GREY']}  {g.kind} in {g.proc}"
                     + (f": {g.cmd}" if g.cmd else ""))
        lines.append("      operations on the ring bypass syscall observation; "
                     "files it opened or wrote may be missing from the graph")

    for f in rep.findings:
        lines.append("")
        lines.append(f"  {_BANNER[f.verdict]}  {f.artifact}")
        lines.append(f"      {f.reason}")
        for leaf in f.foreign_leaves:
            lines.append(f"      ← prebuilt: {leaf}")
        for leaf in f.unattributed_leaves:
            lines.append(f"      ← unattributed: {leaf}")

    for e in rep.payload_entries:
        if e.status == "green":
            continue
        lines.append("")
        lines.append(f"  {_BANNER[e.status.upper()]}  [payload] {e.path}")
        lines.append(f"      {e.reason}")
    return "\n".join(lines)

def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("out_file", type=Path, help="build-recorder .out")
    add_provenance_option(ap)
    ap.add_argument("--rpm-dump", type=Path, default=None,
                    help="rpm file→package dump for OS-package attribution")
    ap.add_argument("--payload", type=Path, default=None,
                    help="what actually ships: a buildroot/extracted-package "
                         "directory, or a file listing one path per line "
                         "(e.g. rpm -qpl). Every entry must trace to the graph.")
    ap.add_argument("--json", type=Path, default=None, help="write JSON report here")


def run(args) -> int:
    """Exit code: 0 GREEN, 1 RED, 3 GREY (unverifiable), 2 usage error."""
    if not args.out_file.exists():
        print(f"error: {args.out_file} not found", file=sys.stderr)
        return 2
    if args.payload is not None and not args.payload.exists():
        print(f"error: {args.payload} not found", file=sys.stderr)
        return 2

    graph = load_graph(args.out_file, args.provenance)
    copies = parse_copies(args.out_file)
    gaps = parse_coverage_gaps(args.out_file)
    backends = detect_backends(args.rpm_dump)
    payload = collect_payload(args.payload) if args.payload else None

    rep = compute_verdict(graph, copies, backends, gaps=gaps, payload=payload)

    print(_format_report(rep, str(args.out_file)))
    if args.json:
        args.json.write_text(json.dumps(rep.to_dict(), indent=2))
        print(f"\nJSON report → {args.json}")

    return {"GREEN": 0, "RED": 1, "GREY": 3}[rep.verdict]
