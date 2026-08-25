"""parse_out: unified .out (Turtle) → BuildGraph parser.

Handles both flat (one triple per line) and grouped (semicolon-terminated)
Turtle formats produced by build-recorder, as well as the enrichment bare-URI
block format written by enrich.py.  Processing is single-pass, line-by-line,
without any external RDF library.
"""
from __future__ import annotations

import re
from pathlib import Path

from brec.ir import BuildGraph, FileNode, ProcessNode

# ── Pre-compiled patterns ─────────────────────────────────────────────────────

# Type declaration:  :X a b:type [.; or continuation]
_TYPE_RE = re.compile(r"^(:[a-zA-Z_]\w*)\s+a\s+b:(\w+)")

# Flat string property:  :X b:prop "value" [.;]
_STR_RE = re.compile(
    r"^(:[a-zA-Z_]\w*)\s+b:(\w+)\s+\"((?:[^\"\\]|\\.)*)\"\s*[.;]"
)

# Flat integer property:  :X b:prop 123 [.;]
_INT_RE = re.compile(r"^(:[a-zA-Z_]\w*)\s+b:(\w+)\s+(\d+)\s*[.;]")

# Flat URI relationship:  :X b:pred :Y [.;]
_URI_RE = re.compile(r"^(:[a-zA-Z_]\w*)\s+b:(\w+)\s+(:[a-zA-Z_]\w*)\s*[.;]")

# Bare URI line (enrichment block header):  :X
_BARE_RE = re.compile(r"^(:[a-zA-Z_]\w*)\s*$")

# Indented string property:  WS b:prop "value" [.;]
_ISTR_RE = re.compile(r"^\s+b:(\w+)\s+\"((?:[^\"\\]|\\.)*)\"\s*[.;]?")

# Indented integer property:  WS b:prop 123 [.;]
_IINT_RE = re.compile(r"^\s+b:(\w+)\s+(\d+)\s*[.;]?")

# Indented URI relationship:  WS b:pred :Y [.;]
_IURI_RE = re.compile(r"^\s+b:(\w+)\s+(:[a-zA-Z_]\w*)\s*[.;]?")

# ── Predicates we store per node type ────────────────────────────────────────

_FILE_STR  = frozenset({
    "abspath", "name", "hash",
    "dep_type", "rpm_name", "rpm_package",      # legacy enrichment predicates
    "pkg_backend", "pkg_name", "pkg_version", "purl",  # new generalised predicates
})
_PROC_STR  = frozenset({"cmd", "start", "end"})
_PROC_LINK = frozenset({"creates", "execs", "reads", "writes", "rename", "executable"})


# ── Unescape helper (same logic as enrich.py / verify-build.py) ──────────────

def _unescape(s: str) -> str:
    return (
        s.replace('\\"', '"')
         .replace("\\\\", "\\")
         .replace("\\n", "\n")
         .replace("\\t", "\t")
    )


# ── Parser ────────────────────────────────────────────────────────────────────

def parse_out(path: Path) -> BuildGraph:
    """Parse a build-recorder .out file into a :class:`BuildGraph`.

    Recognises both the flat format (one triple per line) and the grouped
    semicolon-terminated format, plus the bare-URI enrichment block written by
    ``enrich.py``.  Nodes are identified by their ``a b:file`` / ``a b:process``
    type declarations, not by URI prefix.

    ``role`` is left ``None``; it is populated by the CLASSIFY stage.
    """
    raw: dict[str, dict] = {}       # uri  →  mixed str/int/list values
    file_uris: set[str] = set()
    proc_uris: set[str] = set()
    current: str | None = None

    # ── Inner helpers ─────────────────────────────────────────────────────────

    def _as_process(uri: str) -> None:
        """Accept a subject as a process on the strength of its predicates.

        Traces written before the tracer declared forked children only typed a
        process when it exec\'d, so workers that merely fork (make, cargo, and
        every thread) carried reads and writes under an untyped subject.  Keying
        strictly on the type declaration dropped those edges without a word: on
        a cargo build, a third of all processes.  Predicates that only a process
        can carry are declaration enough.
        """
        if uri not in proc_uris and uri not in file_uris:
            proc_uris.add(uri)
            raw.setdefault(uri, {})

    def _set_str(uri: str, prop: str, val: str) -> None:
        if uri in file_uris and prop in _FILE_STR:
            raw.setdefault(uri, {})[prop] = val
            return
        if prop in _PROC_STR:
            _as_process(uri)
        if uri in proc_uris and prop in _PROC_STR:
            raw.setdefault(uri, {})[prop] = val

    def _set_int(uri: str, prop: str, val: str) -> None:
        if uri in file_uris and prop == "size":
            raw.setdefault(uri, {})["size"] = int(val)
        elif prop == "pid":
            _as_process(uri)
            if uri in proc_uris:
                raw.setdefault(uri, {})["pid"] = int(val)

    def _set_uri_rel(subj: str, pred: str, obj: str) -> None:
        _as_process(subj)
        if subj not in proc_uris:
            return
        d = raw.setdefault(subj, {})
        if pred in ("creates", "execs"):
            d.setdefault("execs", []).append(obj)
        elif pred == "reads":
            d.setdefault("reads", []).append(obj)
        elif pred == "writes":
            d.setdefault("writes", []).append(obj)
        elif pred == "rename":
            d.setdefault("renames", []).append(obj)
        elif pred == "executable":
            d["executable"] = obj

    # ── Line-by-line scan ─────────────────────────────────────────────────────

    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")

            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # @prefix / @base — reset context, not a triple
            if stripped.startswith("@"):
                current = None
                continue

            # Type declaration: :X a b:type [.;]
            m = _TYPE_RE.match(line)
            if m:
                uri, typ = m.group(1), m.group(2)
                if typ == "file":
                    file_uris.add(uri)
                    raw.setdefault(uri, {})
                elif typ == "process":
                    proc_uris.add(uri)
                    raw.setdefault(uri, {})
                current = uri
                continue

            # Flat string property: :X b:prop "val" [.;]
            m = _STR_RE.match(line)
            if m:
                _set_str(m.group(1), m.group(2), _unescape(m.group(3)))
                current = None
                continue

            # Flat integer property: :X b:prop 123 [.;]
            m = _INT_RE.match(line)
            if m:
                _set_int(m.group(1), m.group(2), m.group(3))
                current = None
                continue

            # Flat URI relationship: :X b:pred :Y [.;]
            m = _URI_RE.match(line)
            if m:
                _set_uri_rel(m.group(1), m.group(2), m.group(3))
                current = None
                continue

            # Bare URI (enrichment block header): :X
            m = _BARE_RE.match(line)
            if m:
                current = m.group(1)
                raw.setdefault(current, {})
                continue

            # Indented triples (grouped / enrichment continuation)
            if current and line and line[0].isspace():
                m = _ISTR_RE.match(line)
                if m:
                    _set_str(current, m.group(1), _unescape(m.group(2)))
                    continue
                m = _IINT_RE.match(line)
                if m:
                    _set_int(current, m.group(1), m.group(2))
                    continue
                m = _IURI_RE.match(line)
                if m:
                    _set_uri_rel(current, m.group(1), m.group(2))
                    continue
            elif line and not line[0].isspace():
                current = None

    # ── Assemble FileNode objects ─────────────────────────────────────────────

    files: dict[str, FileNode] = {}
    for uri in file_uris:
        d = raw.get(uri, {})
        abspath = d.get("abspath", "")
        if not abspath:
            continue  # incomplete node — no absolute path recorded

        # Canonical pkg_* fields: new predicates take priority; fall back to rpm_*
        pkg_backend = d.get("pkg_backend", "")
        pkg_name    = d.get("pkg_name", "")
        pkg_version = d.get("pkg_version", "")
        purl        = d.get("purl", "")
        if not pkg_name and d.get("rpm_name"):
            pkg_name    = d["rpm_name"]
            pkg_version = d.get("rpm_package", "")
            pkg_backend = "rpm"

        files[uri] = FileNode(
            uri=uri,
            abspath=abspath,
            name=d.get("name") or Path(abspath).name,
            size=d.get("size", 0),
            git_blob_sha1=d.get("hash", ""),
            dep_type=d.get("dep_type", ""),
            rpm_name=d.get("rpm_name", ""),
            rpm_nevra=d.get("rpm_package", ""),
            pkg_backend=pkg_backend,
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            purl=purl,
        )

    # ── Assemble ProcessNode objects ──────────────────────────────────────────

    procs: dict[str, ProcessNode] = {}
    for uri in proc_uris:
        d = raw.get(uri, {})
        procs[uri] = ProcessNode(
            uri=uri,
            pid=d.get("pid", 0),
            cmd=d.get("cmd", ""),
            executable=d.get("executable"),
            start=d.get("start"),
            end=d.get("end"),
            reads=list(d.get("reads", [])),
            writes=list(d.get("writes", [])),
            execs=list(d.get("execs", [])),
            renames=list(d.get("renames", [])),
            role=None,
        )

    return BuildGraph(files=files, procs=procs)
