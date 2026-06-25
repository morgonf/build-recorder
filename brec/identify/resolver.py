"""brec.identify.resolver — orchestrate identification backends for vendored units.

Public API:

    build_units(classified)  →  list[VendoredUnit]
    resolve(unit, backends, offline=False)  →  IdentifiedComponent
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from brec.identify.base import IdentificationBackend, VendoredUnit
from brec.ir import (
    ClassifiedFile,
    DepClass,
    FileHash,
    IdentifiedComponent,
    Match,
)

# ── Path helpers ──────────────────────────────────────────────────────────────

def _rel_path_in_vendor_dir(abspath: str, vendor_dir: str) -> str:
    """Return the path of *abspath* relative to its vendor_dir root.

    Example::

        _rel_path_in_vendor_dir(
            "/home/user/project/src/third_party/sqlite/subdir/foo.c",
            "third_party/sqlite",
        )
        # → "subdir/foo.c"
    """
    parts = abspath.replace("\\", "/").split("/")
    vparts = vendor_dir.replace("\\", "/").split("/")
    vn = len(vparts)
    for i in range(len(parts) - vn):
        if [p.lower() for p in parts[i : i + vn]] == [v.lower() for v in vparts]:
            remaining = "/".join(parts[i + vn :])
            return remaining if remaining else Path(abspath).name
    return Path(abspath).name


def _abs_root_of_vendor_dir(abspath: str, vendor_dir: str) -> Optional[str]:
    """Return the absolute path of the vendor_dir root directory.

    Example::

        _abs_root_of_vendor_dir(
            "/home/user/project/src/third_party/sqlite/sqlite3.c",
            "third_party/sqlite",
        )
        # → "/home/user/project/src/third_party/sqlite"
    """
    parts = abspath.replace("\\", "/").split("/")
    vparts = vendor_dir.replace("\\", "/").split("/")
    vn = len(vparts)
    for i in range(len(parts) - vn):
        if [p.lower() for p in parts[i : i + vn]] == [v.lower() for v in vparts]:
            root_parts = parts[: i + vn]
            return "/".join(root_parts) if root_parts[0] else "/" + "/".join(root_parts[1:])
    return None


# ── build_units ───────────────────────────────────────────────────────────────

def build_units(classified: list[ClassifiedFile]) -> list[VendoredUnit]:
    """Group VENDORED files by vendor_dir into :class:`~brec.identify.base.VendoredUnit` objects.

    Only files with ``dep_class == VENDORED`` and a non-empty ``vendor_dir``
    are included.  Files without a ``git_blob_sha1`` are skipped (no hash to
    compare).  Units are returned sorted by key for determinism.
    """
    groups: dict[str, list[ClassifiedFile]] = {}
    for cf in classified:
        if cf.dep_class != DepClass.VENDORED:
            continue
        if not cf.vendor_dir:
            continue
        groups.setdefault(cf.vendor_dir, []).append(cf)

    units: list[VendoredUnit] = []
    for vendor_dir in sorted(groups):
        cfs = groups[vendor_dir]
        file_hashes: list[FileHash] = []
        file_uris: list[str] = []
        abs_root: Optional[str] = None

        for cf in cfs:
            abspath = cf.file.abspath
            rel = _rel_path_in_vendor_dir(abspath, vendor_dir)
            file_hashes.append(FileHash(
                rel_path=rel,
                git_blob_sha1=cf.file.git_blob_sha1,
            ))
            file_uris.append(cf.file.uri)
            if abs_root is None:
                abs_root = _abs_root_of_vendor_dir(abspath, vendor_dir)

        units.append(VendoredUnit(
            key=vendor_dir,
            files=file_hashes,
            abs_root=abs_root,
            file_uris=file_uris,
        ))

    return units


# ── Merge helpers ─────────────────────────────────────────────────────────────

def _normalize_url(url: Optional[str]) -> Optional[str]:
    """Normalise a repo URL for deduplication (strip trailing slash and .git)."""
    if not url:
        return None
    url = url.strip().rstrip("/")
    if url.lower().endswith(".git"):
        url = url[:-4]
    return url.lower()


def _merge_matches(base: Match, other: Match) -> Match:
    """Merge two Matches for the same repo_url; *base* has equal-or-higher confidence."""
    return Match(
        backend=base.backend,
        repo_url=base.repo_url or other.repo_url,
        project=base.project or other.project,
        version=base.version or other.version,
        commit=base.commit or other.commit,
        nearest_tag=base.nearest_tag or other.nearest_tag,
        commits_past_tag=base.commits_past_tag if base.commits_past_tag else other.commits_past_tag,
        confidence=base.confidence,
        method=base.method,
        files_matched=base.files_matched if base.files_matched else other.files_matched,
        files_total=base.files_total if base.files_total else other.files_total,
    )


# ── resolve ───────────────────────────────────────────────────────────────────

def resolve(
    unit: VendoredUnit,
    backends: list[IdentificationBackend],
    offline: bool = False,
) -> IdentifiedComponent:
    """Identify a vendored unit by orchestrating discover + refine backends.

    Pipeline:

    1. **Discovery** — call ``backend.discover(unit)`` on each applicable
       backend (skipping ``requires_network=True`` when ``offline``).
       Errors are silently swallowed; the resolver always degrades gracefully.

    2. **Refinement** — for each unique ``repo_url`` discovered, call
       ``backend.refine(unit, repo_url)`` on all applicable backends.
       ``NotImplementedError`` (raised by non-refining backends) is caught.

    3. **Merge** — group all Matches by normalised ``repo_url``; for each group
       keep the highest-confidence Match as the primary, filling in ``None``
       fields from the lower-confidence one.

    4. **Sort** — candidates sorted by ``confidence`` descending; ``best``
       is the first element (or ``None`` if no candidates).

    5. **Tier-0 guarantee** — always returns a non-empty ``IdentifiedComponent``
       with ``files`` populated from ``unit.file_uris``, even when no backend
       produced any result (``best=None``, ``candidates=[]``).
    """
    # ── 1. Discovery ──────────────────────────────────────────────────────────
    all_matches: list[Match] = []
    for backend in backends:
        if offline and backend.requires_network:
            continue
        try:
            matches = backend.discover(unit)
            all_matches.extend(matches)
        except Exception:
            pass   # degrade silently

    # ── 2. Collect unique repo_urls for refinement ───────────────────────────
    seen_urls: set[str] = set()
    ordered_urls: list[str] = []
    for m in all_matches:
        if m.repo_url:
            nurl = _normalize_url(m.repo_url)
            if nurl and nurl not in seen_urls:
                seen_urls.add(nurl)
                ordered_urls.append(m.repo_url)   # keep original form

    # ── 3. Refinement ────────────────────────────────────────────────────────
    for repo_url in ordered_urls:
        for backend in backends:
            if offline and backend.requires_network:
                continue
            try:
                refined = backend.refine(unit, repo_url)
                if refined is not None:
                    all_matches.append(refined)
            except NotImplementedError:
                pass
            except Exception:
                pass

    # ── 4. Merge by normalised URL ────────────────────────────────────────────
    merged: dict[Optional[str], Match] = {}
    for m in all_matches:
        key = _normalize_url(m.repo_url)
        if key not in merged:
            merged[key] = m
        else:
            existing = merged[key]
            if m.confidence >= existing.confidence:
                merged[key] = _merge_matches(m, existing)
            else:
                merged[key] = _merge_matches(existing, m)

    # ── 5. Sort and select best ───────────────────────────────────────────────
    candidates = sorted(merged.values(), key=lambda m: -m.confidence)
    best: Optional[Match] = candidates[0] if candidates else None

    # ── 6. Tier-0: always return a result with files populated ────────────────
    return IdentifiedComponent(
        key=unit.key,
        files=list(unit.file_uris),
        candidates=candidates,
        best=best,
        purl=None,
    )
