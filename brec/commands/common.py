"""Pieces every trace-reading command shares.

The commands differ in what they ask of a trace, not in how they get one: each
parses the .out and, if package attribution has been derived for it, overlays
the sidecar sitting beside it.  That belongs in one place, so that adding a
second provenance format later changes one function and not five commands.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from brec.ir import BuildGraph
from brec.provenance import sidecar


def add_provenance_option(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--provenance", type=Path, metavar="FILE.provenance.json",
        help="package attribution written by `brec enrich` "
             "(default: <trace>.provenance.json beside the trace, when present)",
    )


def load_graph(trace: Path, provenance: Optional[Path] = None,
               quiet: bool = False) -> BuildGraph:
    """Parse *trace* and overlay its provenance sidecar, reporting what happened.

    A sidecar whose entries name files the trace does not have, or name them at
    different paths, was derived from some other trace; that is worth saying out
    loud, because silently attributing packages to the wrong files is the exact
    failure keeping the trace immutable is meant to rule out.
    """
    try:
        graph, stats = sidecar.read_graph(trace, provenance)
    except (OSError, ValueError) as exc:
        # A sidecar the user named by hand, or one that is not what it claims:
        # a message, not a traceback.
        raise SystemExit(f"error: {exc}")

    if stats is not None and not quiet:
        source = provenance or sidecar.default_path(trace)
        # Leading newline: callers announce their own parsing on an open line.
        print(f"\nProvenance: {stats.annotated} files from {source}")
        if stats.suspicious:
            print(
                f"WARNING: {source} does not match this trace: "
                f"{stats.unknown_uri} unknown file nodes, "
                f"{stats.path_mismatch} at a different path",
                file=sys.stderr,
            )
    return graph
