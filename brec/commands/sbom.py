"""
brec sbom — SBOM and CVE report for vendored C/C++ dependencies in build-recorder output.

Reads an enriched .out file (after `brec enrich`) and identifies third-party libraries
that were statically compiled into the project. Works in three modes:

  Offline (default):  path pattern matching + known component database
  + --source-dir:     version string extraction from source files
  + --osv-api:        OSV determineversion API + CVE lookup (requires internet)

Output:
  <build>.sbom.json      CycloneDX 1.6 SBOM
  <build>.sbom-report.md Human-readable CVE report

Usage:
  brec sbom civetweb-build.out
  brec sbom civetweb-build.out --source-dir /path/to/src --osv-api
  brec sbom civetweb-build.out -o sbom.json --report report.md

See: doc/sbom-vendored-deps.md for full design documentation.
"""

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from brec.classify import is_vendor_path, vendor_dir
from brec.commands.common import add_provenance_option, load_graph
from brec.components import COMPONENTS, Component, match_by_dirname, match_by_filename
from brec.ir import FileNode

# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class VendoredComponent:
    key: str
    spec: Component
    version: Optional[str]
    version_method: str          # "dir_name" | "version_string" | "osv_api" | "unknown"
    version_confidence: float    # 0.0 – 1.0
    source_files: list[str]      # abspaths of compiled files
    vendor_dir: str
    osv_match: Optional[dict] = None
    cves: list[dict] = field(default_factory=list)

    @property
    def purl(self) -> str:
        spec = self.spec
        ver = f"@{self.version}" if self.version else ""
        if spec.purl_type == "github":
            return f"pkg:github/{spec.purl_ns}/{spec.purl_name}{ver}"
        if spec.purl_type == "generic":
            ns = f"/{spec.purl_ns}" if spec.purl_ns else ""
            return f"pkg:generic{ns}/{spec.purl_name}{ver}"
        return f"pkg:{spec.purl_type}/{spec.purl_name}{ver}"

    @property
    def bom_ref(self) -> str:
        return f"{self.key}-{self.version or 'unknown'}"

# ── Layer 1: path-based component detection ───────────────────────────────────

def detect_vendored_components(records: list[FileNode]) -> list[VendoredComponent]:
    vendor_files = [r for r in records if r.dep_type == "project_source" and is_vendor_path(r.abspath)]

    # Group by (component_key, vendor_dir) — multiple versions of same lib may coexist
    bucket: dict[tuple[str, str], list[FileNode]] = defaultdict(list)
    bucket_meta: dict[tuple[str, str], tuple[Optional[str], str, float]] = {}  # → (version, method, conf)

    for rec in vendor_files:
        vdir = vendor_dir(rec.abspath) or ""
        dirname = vdir.split("/")[-1]
        fname = Path(rec.abspath).name

        comp_key = match_by_filename(fname)
        dir_match = match_by_dirname(dirname)

        if not comp_key and dir_match:
            comp_key = dir_match[0]
        if not comp_key:
            continue

        key = (comp_key, vdir)
        bucket[key].append(rec)
        if key not in bucket_meta:
            if dir_match and dir_match[0] == comp_key:
                bucket_meta[key] = (dir_match[1], "dir_name", 0.9)
            else:
                bucket_meta[key] = (None, "unknown", 0.0)

    # For each component key, pick the vendor_dir with the most compiled files
    # (heuristic: the most-referenced version was actually built)
    best: dict[str, tuple[str, list[FileNode]]] = {}
    for (comp_key, vdir), files in bucket.items():
        if comp_key not in best or len(files) > len(best[comp_key][1]):
            best[comp_key] = (vdir, files)

    components = {}
    for comp_key, (vdir, files) in best.items():
        version, method, conf = bucket_meta[(comp_key, vdir)]
        components[comp_key] = VendoredComponent(
            key=comp_key,
            spec=COMPONENTS[comp_key],
            version=version,
            version_method=method,
            version_confidence=conf,
            source_files=[r.abspath for r in files],
            vendor_dir=vdir,
        )

    return list(components.values())

# ── Layer 2: version string extraction from source files ──────────────────────

def extract_versions_from_source(
    components: list[VendoredComponent],
    source_dir: Path,
) -> None:
    """Update version in-place for components where source files are readable."""
    for comp in components:
        if comp.version and comp.version_confidence >= 0.9:
            continue  # already known from dir name
        spec = comp.spec
        if not spec.version_re:
            continue

        for abspath in comp.source_files:
            # Map container path to host path via source_dir heuristic
            fname = Path(abspath).name
            candidates = list(source_dir.rglob(fname))
            for candidate in candidates:
                try:
                    content = candidate.read_text(encoding="utf-8", errors="replace")
                    m = spec.version_re.search(content)
                    if m:
                        raw = m.group(1)
                        version = spec.version_transform(raw) if spec.version_transform else raw
                        comp.version = version
                        comp.version_method = "version_string"
                        comp.version_confidence = 1.0
                        break
                except OSError:
                    continue
            if comp.version_confidence == 1.0:
                break

# ── Layer 3: OSV determineversion API ─────────────────────────────────────────

def _plain_sha1(filepath: Path) -> str:
    h = hashlib.sha1()
    h.update(filepath.read_bytes())
    return h.hexdigest()


def query_osv_determineversion(
    comp: VendoredComponent,
    source_dir: Path,
) -> None:
    """Call OSV determineversion API using plain SHA-1 of source files."""
    file_hashes = []
    for abspath in comp.source_files[:20]:   # API limit: reasonable subset
        fname = Path(abspath).name
        candidates = list(source_dir.rglob(fname))
        if candidates:
            try:
                fhash = _plain_sha1(candidates[0])
                rel = str(candidates[0].relative_to(source_dir))
                file_hashes.append({"file_path": rel, "hash": fhash})
            except OSError:
                continue

    if not file_hashes:
        return

    payload = json.dumps({
        "name": comp.spec.display_name,
        "file_hashes": file_hashes,
    }).encode()

    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1experimental/determineversion",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"  [OSV determineversion] {comp.key}: {e}", file=sys.stderr)
        return

    matches = data.get("matches", [])
    if not matches:
        return

    best = max(matches, key=lambda m: m.get("score", 0))
    score = best.get("score", 0)
    repo_info = best.get("repo_info", {})
    api_version = repo_info.get("version") or repo_info.get("tag", "").lstrip("v")

    comp.osv_match = best
    if api_version and (comp.version is None or comp.version_confidence < score):
        comp.version = api_version
        comp.version_method = "osv_api"
        comp.version_confidence = score

# ── Layer 4: OSV CVE query ────────────────────────────────────────────────────

def query_osv_cves(comp: VendoredComponent) -> None:
    """Query OSV /v1/query for vulnerabilities."""
    if not comp.version and not comp.spec.osv_name:
        return

    # Build query by PURL if possible, otherwise by package name
    if comp.version and comp.spec.purl_type in ("github",):
        payload: dict = {"package": {"purl": comp.purl}}
    elif comp.spec.osv_name and comp.version:
        pkg: dict = {"name": comp.spec.osv_name}
        if comp.spec.osv_ecosystem:
            pkg["ecosystem"] = comp.spec.osv_ecosystem
        payload = {"version": comp.version, "package": pkg}
    else:
        return

    try:
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        print(f"  [OSV query] {comp.key}: {e}", file=sys.stderr)
        return

    comp.cves = data.get("vulns", [])

# ── CycloneDX SBOM generation ─────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


def _osv_severity(vuln: dict) -> tuple[str, float]:
    for sev in vuln.get("severity", []):
        score_type = sev.get("type", "")
        score_val = sev.get("score", "")
        if score_type in ("CVSS_V3", "CVSS_V4") and score_val:
            try:
                score = float(score_val)
                if score >= 9.0:
                    return "critical", score
                if score >= 7.0:
                    return "high", score
                if score >= 4.0:
                    return "medium", score
                return "low", score
            except ValueError:
                pass
    return "unknown", 0.0


def generate_cyclonedx(
    components: list[VendoredComponent],
    source_file: Path,
) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cdx_components = []
    cdx_vulns = []

    for comp in components:
        spec = comp.spec
        evidence_methods = []
        if comp.version_method == "dir_name":
            evidence_methods.append({"technique": "filename", "confidence": comp.version_confidence,
                                     "value": comp.vendor_dir})
        elif comp.version_method == "version_string":
            evidence_methods.append({"technique": "source-code-analysis",
                                     "confidence": comp.version_confidence})
        elif comp.version_method == "osv_api":
            evidence_methods.append({"technique": "hash-comparison",
                                     "confidence": comp.version_confidence})

        c: dict = {
            "type": "library",
            "bom-ref": comp.bom_ref,
            "name": spec.display_name,
            "scope": "required",
            "evidence": {
                "identity": {
                    "field": "version" if comp.version else "name",
                    "confidence": comp.version_confidence,
                    "methods": evidence_methods,
                }
            },
            "properties": [
                {"name": "build-recorder:vendorDir", "value": comp.vendor_dir},
                {"name": "build-recorder:sourceFiles",
                 "value": str(len(comp.source_files))},
                {"name": "build-recorder:versionMethod", "value": comp.version_method},
            ],
        }
        if comp.version:
            c["version"] = comp.version
        c["purl"] = comp.purl
        if spec.homepage:
            c["externalReferences"] = [{"type": "website", "url": spec.homepage}]
        cdx_components.append(c)

        for vuln in comp.cves:
            vid = vuln.get("id", "UNKNOWN")
            severity, score = _osv_severity(vuln)
            entry: dict = {
                "bom-ref": vid,
                "id": vid,
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"},
                "affects": [{"ref": comp.bom_ref}],
                "ratings": [{"severity": severity, "score": score, "method": "CVSSv3"}],
            }
            aliases = vuln.get("aliases", [])
            cve_aliases = [a for a in aliases if a.startswith("CVE-")]
            if cve_aliases:
                entry["id"] = cve_aliases[0]
                entry["references"] = [{"id": a, "source": {"name": "NVD"}} for a in cve_aliases]
            summary = vuln.get("summary", "")
            if summary:
                entry["description"] = summary
            cdx_vulns.append(entry)

    sbom: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:build-recorder-sbom",
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "build-recorder", "name": "brec sbom", "version": "1.0"}],
            "component": {
                "type": "application",
                "name": source_file.stem.replace("-build", ""),
            },
        },
        "components": cdx_components,
    }
    if cdx_vulns:
        sbom["vulnerabilities"] = cdx_vulns

    return sbom

# ── Markdown report ───────────────────────────────────────────────────────────

def generate_report(
    components: list[VendoredComponent],
    source_file: Path,
) -> str:
    lines = []
    W = lines.append
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    pkg = source_file.stem.replace("-build", "")

    W(f"# SBOM: Vendored dependencies — {pkg}")
    W(f"\nGenerated: {now}  \nSource: `{source_file}`\n")

    total_cves = sum(len(c.cves) for c in components)
    critical = sum(1 for c in components for v in c.cves
                   if _osv_severity(v)[0] in ("critical", "high"))

    W("## Summary\n")
    W(f"| | |")
    W(f"|---|---|")
    W(f"| Vendored components detected | {len(components)} |")
    W(f"| Components with known version | {sum(1 for c in components if c.version)} |")
    W(f"| CVEs found | {total_cves} |")
    W(f"| Critical/High CVEs | {critical} |")

    W("\n## Detected Components\n")
    W("| Component | Version | Method | Files compiled | CVEs |")
    W("|---|---|---|---|---|")
    for comp in sorted(components, key=lambda c: c.spec.display_name):
        ver = comp.version or "**unknown**"
        cve_col = str(len(comp.cves)) if comp.cves else "—"
        if any(_osv_severity(v)[0] in ("critical", "high") for v in comp.cves):
            cve_col = f"**{cve_col} ⚠**"
        W(f"| [{comp.spec.display_name}]({comp.spec.homepage or '#'}) "
          f"| `{ver}` | {comp.version_method} | {len(comp.source_files)} | {cve_col} |")

    if any(c.cves for c in components):
        W("\n## CVE Details\n")
        for comp in components:
            if not comp.cves:
                continue
            W(f"### {comp.spec.display_name} {comp.version or ''}\n")
            for vuln in sorted(comp.cves,
                               key=lambda v: SEVERITY_ORDER.get(
                                   _osv_severity(v)[0].upper(), 5)):
                vid = vuln.get("id", "UNKNOWN")
                aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
                sev, score = _osv_severity(vuln)
                summary = vuln.get("summary", "No description")
                W(f"**{vid}**" + (f" / {', '.join(aliases)}" if aliases else ""))
                W(f"- Severity: `{sev.upper()}` (score: {score})")
                W(f"- {summary}")
                fix = ""
                for affected in vuln.get("affected", []):
                    for rng in affected.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev:
                                fix = ev["fixed"]
                if fix:
                    W(f"- Fixed in: `{fix}`")
                W(f"- OSV: https://osv.dev/vulnerability/{vid}\n")
    else:
        W("\n*No CVEs found. Run with `--osv-api` for online lookup, or version data may be unavailable.*\n")

    W("\n## Component Details\n")
    for comp in components:
        W(f"### {comp.spec.display_name}\n")
        W(f"- **Version**: {comp.version or '*(unknown)*'} "
          f"(detected via: {comp.version_method}, confidence: {comp.version_confidence:.0%})")
        W(f"- **Vendor dir**: `{comp.vendor_dir}`")
        W(f"- **PURL**: `{comp.purl}`")
        if comp.spec.homepage:
            W(f"- **Homepage**: {comp.spec.homepage}")
        W(f"- **Compiled files** ({len(comp.source_files)}):")
        for f in sorted(comp.source_files)[:10]:
            W(f"  - `{Path(f).name}`")
        if len(comp.source_files) > 10:
            W(f"  - *…and {len(comp.source_files) - 10} more*")
        if comp.osv_match:
            ri = comp.osv_match.get("repo_info", {})
            W(f"- **OSV match**: `{ri.get('address', '')}` "
              f"commit `{ri.get('commit', '')[:12]}` "
              f"(score: {comp.osv_match.get('score', 0):.0%})")
        W("")

    W("---")
    W("*Report generated by `brec sbom` / build-recorder*")
    return "\n".join(lines)

# ── CLI ───────────────────────────────────────────────────────────────────────

def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("out_file", help="build-recorder .out file")
    add_provenance_option(ap)
    ap.add_argument("-o", "--output", metavar="sbom.json",
                    help="CycloneDX SBOM output path (default: <input>.sbom.json)")
    ap.add_argument("--report", metavar="report.md",
                    help="Markdown report output path (default: <input>.sbom-report.md)")
    ap.add_argument("--source-dir", metavar="DIR",
                    help="Project source directory for version string extraction and OSV hashing")
    ap.add_argument("--osv-api", action="store_true",
                    help="Call OSV API for determineversion and CVE lookup (requires internet)")
    ap.add_argument("--no-cve", action="store_true",
                    help="Skip CVE lookup (generate SBOM only)")


def run(args) -> int:
    out_file = Path(args.out_file)
    if not out_file.exists():
        print(f"ERROR: not found: {out_file}", file=sys.stderr)
        return 1

    sbom_path = Path(args.output) if args.output else out_file.with_suffix(".sbom.json")
    report_path = Path(args.report) if args.report else out_file.with_suffix(".sbom-report.md")
    source_dir = Path(args.source_dir) if args.source_dir else None

    print(f"Parsing {out_file.name} ...", end=" ", flush=True)
    records = list(load_graph(out_file, args.provenance).files.values())
    print(f"{len(records)} file records")

    print("Detecting vendored components (Layer 1: path patterns) ...", end=" ", flush=True)
    components = detect_vendored_components(records)
    print(f"{len(components)} components found")

    for comp in components:
        status = f"{comp.version} ({comp.version_method})" if comp.version else "version unknown"
        print(f"  {comp.spec.display_name:20s}  {len(comp.source_files):3d} files  {status}")

    if source_dir:
        print(f"\nExtracting version strings from {source_dir} (Layer 2) ...")
        extract_versions_from_source(components, source_dir)
        for comp in components:
            if comp.version_method == "version_string":
                print(f"  {comp.spec.display_name}: {comp.version} (from source)")

    if args.osv_api and source_dir:
        print("\nQuerying OSV determineversion API (Layer 3) ...")
        for comp in components:
            if comp.version_confidence < 0.8:
                print(f"  {comp.spec.display_name} ...", end=" ", flush=True)
                query_osv_determineversion(comp, source_dir)
                print(comp.version or "no match")

    if args.osv_api and not args.no_cve:
        print("\nQuerying OSV CVE database (Layer 4) ...")
        for comp in components:
            print(f"  {comp.spec.display_name} {comp.version or '?'} ...", end=" ", flush=True)
            query_osv_cves(comp)
            if comp.cves:
                print(f"{len(comp.cves)} CVEs")
            else:
                print("no CVEs found")

    print(f"\nGenerating CycloneDX SBOM → {sbom_path}")
    sbom = generate_cyclonedx(components, out_file)
    sbom_path.write_text(json.dumps(sbom, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Generating Markdown report → {report_path}")
    report = generate_report(components, out_file)
    report_path.write_text(report, encoding="utf-8")

    total_cves = sum(len(c.cves) for c in components)
    critical = sum(1 for c in components for v in c.cves
                   if _osv_severity(v)[0] in ("critical", "high"))
    print(f"\n=== Done ===")
    print(f"  Components : {len(components)}")
    print(f"  With version: {sum(1 for c in components if c.version)}/{len(components)}")
    print(f"  CVEs found : {total_cves} ({critical} critical/high)")
    print(f"  SBOM       : {sbom_path}")
    print(f"  Report     : {report_path}")
    return 0
