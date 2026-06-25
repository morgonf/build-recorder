"""Intermediate representation for the build-recorder pipeline.

All structures are plain dataclasses with to_dict()/from_dict() and
IRDocument.dump()/load() for stable, versioned JSON serialization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

SCHEMA_VERSION = 1


class IRVersionError(ValueError):
    """Raised when loading an IRDocument whose schema_version != SCHEMA_VERSION."""


# ── Graph-stage structures (output of CAPTURE / T0.2 parser) ─────────────────

@dataclass
class FileNode:
    uri: str
    abspath: str
    name: str
    size: int
    git_blob_sha1: str
    dep_type: str = ""     # b:dep_type written by enrich.py; preserved for T1.2 mapping
    rpm_name: str = ""     # b:rpm_name (legacy; raw value kept for reference)
    rpm_nevra: str = ""    # b:rpm_package (legacy; raw NEVRA kept for reference)
    pkg_backend: str = ""  # canonical: "rpm" | "dpkg" | ... (from b:pkg_backend or derived)
    pkg_name: str = ""     # canonical package name (from b:pkg_name or b:rpm_name)
    pkg_version: str = ""  # canonical version (from b:pkg_version or b:rpm_package NEVRA)
    purl: str = ""         # Package URL (from b:purl)

    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "abspath": self.abspath,
            "name": self.name,
            "size": self.size,
            "git_blob_sha1": self.git_blob_sha1,
            "dep_type": self.dep_type,
            "rpm_name": self.rpm_name,
            "rpm_nevra": self.rpm_nevra,
            "pkg_backend": self.pkg_backend,
            "pkg_name": self.pkg_name,
            "pkg_version": self.pkg_version,
            "purl": self.purl,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileNode":
        return cls(
            uri=d["uri"],
            abspath=d["abspath"],
            name=d["name"],
            size=int(d["size"]),
            git_blob_sha1=d["git_blob_sha1"],
            dep_type=d.get("dep_type", ""),
            rpm_name=d.get("rpm_name", ""),
            rpm_nevra=d.get("rpm_nevra", ""),
            pkg_backend=d.get("pkg_backend", ""),
            pkg_name=d.get("pkg_name", ""),
            pkg_version=d.get("pkg_version", ""),
            purl=d.get("purl", ""),
        )


@dataclass
class ProcessNode:
    uri: str
    pid: int
    cmd: str
    executable: Optional[str]
    start: Optional[str]
    end: Optional[str]
    reads: list[str]
    writes: list[str]
    execs: list[str]          # uri ProcessNode
    role: Optional[str] = None
    renames: list[str] = field(default_factory=list)   # b:rename targets

    def to_dict(self) -> dict:
        return {
            "uri": self.uri,
            "pid": self.pid,
            "cmd": self.cmd,
            "executable": self.executable,
            "start": self.start,
            "end": self.end,
            "reads": list(self.reads),
            "writes": list(self.writes),
            "execs": list(self.execs),
            "role": self.role,
            "renames": list(self.renames),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ProcessNode":
        return cls(
            uri=d["uri"],
            pid=int(d["pid"]),
            cmd=d["cmd"],
            executable=d.get("executable"),
            start=d.get("start"),
            end=d.get("end"),
            reads=list(d.get("reads", [])),
            writes=list(d.get("writes", [])),
            execs=list(d.get("execs", [])),
            role=d.get("role"),
            renames=list(d.get("renames", [])),
        )


@dataclass
class BuildGraph:
    files: dict[str, FileNode]
    procs: dict[str, ProcessNode]

    def to_dict(self) -> dict:
        return {
            "files": {k: v.to_dict() for k, v in self.files.items()},
            "procs": {k: v.to_dict() for k, v in self.procs.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BuildGraph":
        return cls(
            files={k: FileNode.from_dict(v) for k, v in d.get("files", {}).items()},
            procs={k: ProcessNode.from_dict(v) for k, v in d.get("procs", {}).items()},
        )


# ── Provenance-stage structure (T1.1) ────────────────────────────────────────

@dataclass
class PackageRef:
    """Reference to an OS package that owns a file.

    ``version`` holds the full version string as returned by the backend
    (NEVRA for rpm, deb-version for dpkg, …).  ``purl`` is optional and
    assembled by the backend when trivially constructible.
    """
    backend: str                    # "rpm" | "dpkg" | ...
    name: str
    version: str                    # NEVRA for rpm, deb-version for dpkg
    arch: Optional[str] = None
    source_package: Optional[str] = None
    purl: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "name": self.name,
            "version": self.version,
            "arch": self.arch,
            "source_package": self.source_package,
            "purl": self.purl,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PackageRef":
        return cls(
            backend=d["backend"],
            name=d["name"],
            version=d["version"],
            arch=d.get("arch"),
            source_package=d.get("source_package"),
            purl=d.get("purl"),
        )


# ── Classify-stage structures (T1.2) ─────────────────────────────────────────

class DepClass(str, Enum):
    """Coarse-grained provenance class for a file read during the build.

    Mapping from the finer-grained ``b:dep_type`` values written by ``enrich.py``
    and the ``role`` computed by ``verify-build.py``:

    ===========================  ==============================  ============
    enrich ``b:dep_type``        verify ``role``                 DepClass
    ===========================  ==============================  ============
    static_header                header (read by compiler)       SYSTEM_STATIC
    static_archive               static_archive                  SYSTEM_STATIC
    build_tool                   other (exec in /usr/bin etc.)   SYSTEM_STATIC
    system_runtime               other (system file, has pkg)    SYSTEM_STATIC
    dynamic_lib                  dynamic_lib (read by linker)    SYSTEM_DYNAMIC
    project_source (vendor path) source/header, no pkg, vendor  VENDORED
    project_source (own code)    source, no pkg, no vendor       PROJECT
    — (temp toolchain files)     —                               TOOLCHAIN_TEMP
    — (future: manifest entry)   —                               DECLARED
    unknown / other              —                               UNKNOWN
    ===========================  ==============================  ============
    """
    SYSTEM_STATIC  = "static"    # .h/.a/tool from OS package
    SYSTEM_DYNAMIC = "dynamic"   # .so linked at runtime, from OS package
    DECLARED       = "declared"  # in manifest/lockfile (phase 4+)
    VENDORED       = "vendored"  # in project tree, no package, vendor-dir segment
    PROJECT        = "project"   # own project source code
    TOOLCHAIN_TEMP = "temp"      # /tmp/cc* and similar build intermediates
    UNKNOWN        = "unknown"


@dataclass
class ClassifiedFile:
    """A file node annotated with its provenance class and optional package info."""
    file: FileNode
    dep_class: DepClass
    package: Optional[PackageRef] = None      # set when dep_class is SYSTEM_*
    vendor_dir: Optional[str] = None          # e.g. "third_party/sqlite"
    read_by_roles: set[str] = field(default_factory=set)  # "compiler"|"linker"|…

    def to_dict(self) -> dict:
        return {
            "file": self.file.to_dict(),
            "dep_class": self.dep_class.value,
            "package": self.package.to_dict() if self.package is not None else None,
            "vendor_dir": self.vendor_dir,
            "read_by_roles": sorted(self.read_by_roles),   # sorted for determinism
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ClassifiedFile":
        return cls(
            file=FileNode.from_dict(d["file"]),
            dep_class=DepClass(d["dep_class"]),
            package=PackageRef.from_dict(d["package"]) if d.get("package") else None,
            vendor_dir=d.get("vendor_dir"),
            read_by_roles=set(d.get("read_by_roles", [])),
        )


# ── Identify-stage structures (T2.1) ─────────────────────────────────────────

@dataclass
class FileHash:
    """Hash record for a single file within a vendored unit.

    ``git_blob_sha1`` is the git-compatible blob hash already present in the
    ``.out`` file (``b:hash`` predicate).  ``plain_sha1`` is computed lazily
    when needed by backends that expect plain (non-git) SHA-1 (e.g. OSV).
    ``other`` holds any additional hash types keyed by algorithm name.
    """
    rel_path: str                          # path within vendor_dir
    git_blob_sha1: str                     # from b:hash in .out
    plain_sha1: Optional[str] = None       # lazy; for OSV
    other: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "rel_path": self.rel_path,
            "git_blob_sha1": self.git_blob_sha1,
            "plain_sha1": self.plain_sha1,
            "other": dict(self.other),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileHash":
        return cls(
            rel_path=d["rel_path"],
            git_blob_sha1=d["git_blob_sha1"],
            plain_sha1=d.get("plain_sha1"),
            other=dict(d.get("other", {})),
        )


@dataclass
class Match:
    """One identification candidate for a vendored unit.

    ``confidence`` is 0..1; 1.0 means all key files matched exactly.
    ``method`` reflects how the match was produced.
    ``commits_past_tag`` is 0 when the matched commit IS the tag.
    """
    backend: str                           # "swh"|"osv"|"gitwalk"|"cache"|"fuzzy"
    repo_url: Optional[str] = None
    project: Optional[str] = None
    version: Optional[str] = None
    commit: Optional[str] = None
    nearest_tag: Optional[str] = None
    commits_past_tag: int = 0
    confidence: float = 0.0                # 0..1
    method: str = "exact"                  # exact|manifest|fuzzy|snippet
    files_matched: int = 0
    files_total: int = 0

    @property
    def is_tagged_release(self) -> bool:
        return self.commits_past_tag == 0 and self.nearest_tag is not None

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "repo_url": self.repo_url,
            "project": self.project,
            "version": self.version,
            "commit": self.commit,
            "nearest_tag": self.nearest_tag,
            "commits_past_tag": self.commits_past_tag,
            "confidence": self.confidence,
            "method": self.method,
            "files_matched": self.files_matched,
            "files_total": self.files_total,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Match":
        return cls(
            backend=d["backend"],
            repo_url=d.get("repo_url"),
            project=d.get("project"),
            version=d.get("version"),
            commit=d.get("commit"),
            nearest_tag=d.get("nearest_tag"),
            commits_past_tag=int(d.get("commits_past_tag", 0)),
            confidence=float(d.get("confidence", 0.0)),
            method=d.get("method", "exact"),
            files_matched=int(d.get("files_matched", 0)),
            files_total=int(d.get("files_total", 0)),
        )


@dataclass
class IdentifiedComponent:
    """Result of the IDENTIFY stage for one vendored unit.

    ``files`` holds the FileNode URI strings from the original graph.
    ``candidates`` is sorted by confidence descending.
    ``best`` is ``None`` in the Tier-0 case (no backend produced a match).
    """
    key: str                               # = vendor_dir
    files: list[str]                       # uri FileNode (from original graph)
    candidates: list[Match] = field(default_factory=list)
    best: Optional[Match] = None
    purl: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "files": list(self.files),
            "candidates": [m.to_dict() for m in self.candidates],
            "best": self.best.to_dict() if self.best is not None else None,
            "purl": self.purl,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IdentifiedComponent":
        return cls(
            key=d["key"],
            files=list(d.get("files", [])),
            candidates=[Match.from_dict(m) for m in d.get("candidates", [])],
            best=Match.from_dict(d["best"]) if d.get("best") else None,
            purl=d.get("purl"),
        )


# ── Envelope ─────────────────────────────────────────────────────────────────

@dataclass
class IRDocument:
    schema_version: int        # = SCHEMA_VERSION; bump on breaking changes
    stage: str                 # "graph" | "classified" | "identified" | "vuln"
    source_out: str            # path to the originating .out file
    payload: dict              # stage-specific content

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "stage": self.stage,
            "source_out": self.source_out,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IRDocument":
        sv = int(d["schema_version"])
        if sv != SCHEMA_VERSION:
            raise IRVersionError(
                f"Unsupported schema_version {sv!r}; expected {SCHEMA_VERSION}"
            )
        return cls(
            schema_version=sv,
            stage=d["stage"],
            source_out=d.get("source_out", ""),
            payload=d.get("payload", {}),
        )

    def dump(self, path: Path) -> None:
        """Write to *path* as UTF-8 JSON with sorted keys (deterministic)."""
        text = json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        Path(path).write_text(text + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "IRDocument":
        """Load from *path*; raises IRVersionError on schema_version mismatch."""
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(d)
