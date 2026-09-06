"""Package provenance kept beside the trace instead of written into it.

`brec enrich` used to append b:rpm_name / b:rpm_package / b:dep_type triples to
the .out file.  That made the trace unusable as evidence: after enrichment the
file on disk was no longer what the tracer recorded, and nothing in it said
which lines came from the tracer and which from a package database consulted
later, possibly on another machine, possibly months after the build.

The attribution now goes to a sidecar next to the trace:

    civetweb-build.out            what the tracer observed, never modified
    civetweb-build.provenance.json   which package owns each file, derived later

Commands load the sidecar automatically when it sits next to the trace, so the
pipeline reads the same as before.  Traces enriched the old way keep working:
parse_out still reads those triples, and a sidecar, being the newer and
explicit statement, takes precedence for the files it covers.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from brec.classify import dep_type_from_path
from brec.ir import SCHEMA_VERSION, BuildGraph, IRDocument, PackageRef
from brec.provenance.base import ProvenanceBackend

STAGE = "provenance"
DEFAULT_SUFFIX = ".provenance.json"


def default_path(trace: Path) -> Path:
    """Where the sidecar for *trace* lives: foo-build.out → foo-build.provenance.json."""
    return trace.with_suffix(DEFAULT_SUFFIX)


@dataclass
class ApplyStats:
    """What applying a sidecar to a graph actually did."""
    annotated: int = 0        # file nodes that got package/dep_type fields
    unknown_uri: int = 0      # entries naming a file node the trace does not have
    path_mismatch: int = 0    # entries whose abspath disagrees with that node

    @property
    def suspicious(self) -> bool:
        """True when the sidecar looks like it belongs to a different trace."""
        return bool(self.unknown_uri or self.path_mismatch)


def build(
    graph: BuildGraph,
    backends: Iterable[ProvenanceBackend],
    source_out: Path,
    env_dump: Optional[Path] = None,
) -> IRDocument:
    """Attribute every file node in *graph* and return the sidecar document.

    One entry per file node, in trace order.  A file no backend claims still
    gets an entry: "no package owns this" is an answer, and it is what makes a
    path count as project source rather than as an unanswered question.
    """
    backend_list = [b for b in backends if b.available()]
    files: dict[str, dict] = {}
    for uri, node in graph.files.items():
        ref = _lookup(backend_list, node.abspath, node.git_blob_sha1)
        entry: dict = {
            "abspath": node.abspath,
            "dep_type": dep_type_from_path(node.abspath, ref is not None),
        }
        if ref is not None:
            entry.update({
                "pkg_backend": ref.backend,
                "pkg_name": ref.name,
                "pkg_version": ref.version,
            })
            if ref.purl:
                entry["purl"] = ref.purl
        files[uri] = entry

    return IRDocument(
        schema_version=SCHEMA_VERSION,
        stage=STAGE,
        source_out=str(source_out),
        payload={
            "backends": [b.name for b in backend_list],
            "env_dump": str(env_dump) if env_dump is not None else None,
            "trace_files": len(graph.files),
            "files": files,
        },
    )


def _lookup(
    backends: list[ProvenanceBackend], abspath: str, git_hash: str
) -> Optional[PackageRef]:
    for backend in backends:
        ref = backend.lookup(abspath, git_hash)
        if ref is not None:
            return ref
    return None


def apply(graph: BuildGraph, doc: IRDocument) -> ApplyStats:
    """Overlay a provenance document onto *graph*, in place.

    An entry is applied only when its abspath matches the node it names: a
    sidecar paired with the wrong trace would otherwise attribute packages to
    unrelated files, which is exactly the kind of quiet corruption keeping the
    trace immutable is meant to prevent.
    """
    stats = ApplyStats()
    for uri, entry in doc.payload.get("files", {}).items():
        node = graph.files.get(uri)
        if node is None:
            stats.unknown_uri += 1
            continue
        if entry.get("abspath") != node.abspath:
            stats.path_mismatch += 1
            continue

        node.dep_type = entry.get("dep_type", node.dep_type)
        name = entry.get("pkg_name", "")
        if name:
            node.pkg_backend = entry.get("pkg_backend", "")
            node.pkg_name = name
            node.pkg_version = entry.get("pkg_version", "")
            node.purl = entry.get("purl", "")
            # The rpm_* fields are what most of the codebase still reads.
            if node.pkg_backend == "rpm":
                node.rpm_name = name
                node.rpm_nevra = entry.get("pkg_version", "")
        stats.annotated += 1
    return stats


def load(path: Path) -> IRDocument:
    """Read a sidecar, refusing a document that is not one."""
    doc = IRDocument.load(path)
    if doc.stage != STAGE:
        raise ValueError(f"{path}: stage is {doc.stage!r}, expected {STAGE!r}")
    return doc


def read_graph(
    trace: Path, provenance: Optional[Path] = None
) -> tuple[BuildGraph, Optional[ApplyStats]]:
    """Parse *trace* and overlay its provenance sidecar if there is one.

    Returns the graph and, when a sidecar was applied, what applying it did.
    With no *provenance* given the sidecar is looked for next to the trace;
    naming one that does not exist is an error, since the caller asked for it.
    """
    from brec.model import parse_out          # local: keeps model free of this layer

    graph = parse_out(trace)
    if provenance is None:
        candidate = default_path(trace)
        if not candidate.exists():
            return graph, None
    else:
        candidate = provenance
        if not candidate.exists():
            raise FileNotFoundError(f"provenance sidecar not found: {candidate}")

    return graph, apply(graph, load(candidate))
