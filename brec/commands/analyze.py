"""
brec analyze — the verdict for a brec-collect bundle, in one step.

brec-collect runs on the build side and only gathers evidence: the trace, the
package database of the build environment, the hashes of what ships.  This is
the other half.  It reads the bundle and gives the verdict `brec verdict` would
give with the right package dump and payload, without the user having to know
which file goes to which option:

    packages.tsv   → package attribution (rpm or dpkg, as MANIFEST says)
    payload.tsv    → the payload closure, matched by hash
    MANIFEST       → what was collected and how the build ended

Usage:
  brec analyze build-bundle.tar.gz
  brec analyze build-bundle.tar.gz --json verdict.json
  brec analyze extracted-bundle/ --fail-on red

Exit code: 0 GREEN, 1 RED, 3 GREY, as `brec verdict`; 2 when the bundle cannot
be read.  --fail-on red lets GREY through with 0, for a pipeline that wants to
stop on a proven prebuilt but not on what the tracer could not see.

A bundle whose MANIFEST says the payload directory was missing after the build
is never GREEN: the closure over what ships was asked for and could not be
checked, and saying GREEN about everything the build touched instead would
answer a question nobody asked.
"""

from __future__ import annotations

import argparse
import json
import sys
import tarfile
import tempfile
from pathlib import Path

from brec.commands import verdict as v
from brec.commands.common import load_graph
from brec.provenance.base import ProvenanceBackend
from brec.provenance.dpkg import DpkgBackend
from brec.provenance.rpm import RpmBackend

# The bundle format this reader understands (MANIFEST "format=").
FORMAT = "1"

# Everything else in an archive is ignored: the bundle comes from a CI job,
# and nothing in it gets to choose where it is written.
MEMBERS = ("MANIFEST", "trace.out", "packages.tsv", "payload.tsv",
           "declared.txt", "env.txt")


class BundleError(Exception):
    """The bundle cannot be read; reported as a message, exit code 2."""


def unpack(bundle: Path, into: Path) -> Path:
    """Directory holding the bundle members: *bundle* itself, or *into*."""
    if bundle.is_dir():
        return bundle
    try:
        with tarfile.open(bundle, "r:*") as tar:
            for member in tar.getmembers():
                if member.name not in MEMBERS or not member.isfile():
                    continue
                src = tar.extractfile(member)
                if src is not None:
                    (into / member.name).write_bytes(src.read())
    except (OSError, tarfile.TarError) as exc:
        raise BundleError(f"{bundle}: not a readable bundle ({exc})")
    return into


def read_manifest(root: Path) -> dict[str, str]:
    path = root / "MANIFEST"
    if not path.is_file():
        raise BundleError(f"{root}: no MANIFEST, not a brec-collect bundle")
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            out[key] = value
    if out.get("format") != FORMAT:
        raise BundleError(
            f"bundle format {out.get('format')!r}, this brec reads {FORMAT!r}"
        )
    if not (root / "trace.out").is_file():
        raise BundleError(f"{root}: the bundle has no trace.out")
    return out


def os_release_id(root: Path) -> str:
    """The distribution's os-release ID from env.txt, for dpkg purls."""
    env = root / "env.txt"
    if env.is_file():
        for line in env.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ID="):
                return line[3:].strip().strip('"') or "debian"
    return "debian"


def backends_for(root: Path, manifest: dict[str, str]) -> list[ProvenanceBackend]:
    """The backend MANIFEST names, indexed from packages.tsv."""
    kind = manifest.get("pkgdb", "none")
    dump = root / "packages.tsv"
    if kind == "none":
        return []
    if not dump.is_file():
        raise BundleError(f"MANIFEST says pkgdb={kind}, but packages.tsv is missing")
    if kind == "rpm":
        backend: ProvenanceBackend = RpmBackend()
    elif kind == "dpkg":
        backend = DpkgBackend(namespace=os_release_id(root))
    else:
        raise BundleError(f"unknown package database in MANIFEST: pkgdb={kind}")
    if not backend.recognizes(dump):  # type: ignore[attr-defined]
        print(f"WARNING: packages.tsv does not read as a {kind} dump", file=sys.stderr)
    backend.build_index(dump)
    return [backend]


def _header(bundle: Path, manifest: dict[str, str], backends: list) -> str:
    lines = [f"Bundle {bundle}: {manifest.get('collector', '?')}, "
             f"recorder sha256 {manifest.get('recorder_sha256', '?')[:12]}"]
    if backends:
        n = len(backends[0].index_as_dict())
        lines.append(f"  package database: {manifest['pkgdb']}, {n} indexed paths")
    else:
        lines.append("  package database: none (system files will look foreign)")
    state = manifest.get("payload", "absent")
    if state == "present":
        lines.append(f"  payload: {manifest.get('payload_files', '?')} files from "
                     f"{manifest.get('payload_root', '?')}")
    elif state == "missing":
        lines.append(f"  payload: {manifest.get('payload_root', '?')} was missing "
                     "after the build: the verdict cannot be GREEN")
    else:
        lines.append("  payload: not given, the verdict covers every file the build touched")
    status = manifest.get("build_status", "?")
    if status != "0":
        lines.append(f"  build status {status}: the build failed, the verdict "
                     "is about whatever it got to")
    return "\n".join(lines)


def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("bundle", type=Path, help="brec-collect bundle (.tar.gz) or its extracted directory")
    ap.add_argument("--json", type=Path, default=None, help="write the JSON report here")
    ap.add_argument("--fail-on", choices=("grey", "red"), default="grey",
                    help="lowest verdict that fails: grey (default) also fails "
                         "on what could not be verified, red only on a proven prebuilt")


def run(args) -> int:
    if not args.bundle.exists():
        print(f"error: {args.bundle} not found", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="brec-analyze.") as tmp:
        try:
            root = unpack(args.bundle, Path(tmp))
            manifest = read_manifest(root)
            backends = backends_for(root, manifest)
        except BundleError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        trace = root / "trace.out"
        payload = None
        if manifest.get("payload") == "present" and (root / "payload.tsv").is_file():
            payload = v.collect_payload(root / "payload.tsv")

        print(_header(args.bundle, manifest, backends))
        graph = load_graph(trace)
        rep = v.compute_verdict(graph, v.parse_copies(trace), backends,
                                gaps=v.parse_coverage_gaps(trace), payload=payload)

    if manifest.get("payload") == "missing" and rep.verdict == "GREEN":
        rep.verdict = "GREY"

    print()
    print(v._format_report(rep, str(args.bundle)))
    if args.json:
        doc = rep.to_dict()
        doc["bundle"] = manifest
        args.json.write_text(json.dumps(doc, indent=2))
        print(f"\nJSON report → {args.json}")

    if rep.verdict == "GREY" and args.fail_on == "red":
        return 0
    return {"GREEN": 0, "RED": 1, "GREY": 3}[rep.verdict]
