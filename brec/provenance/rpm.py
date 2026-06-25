"""RpmBackend — ProvenanceBackend implementation for RPM-based distros.

Ports ``load_rpm_dump()`` from ``enrich.py`` verbatim in behaviour, including
the double-indexing of /lib64↔/usr/lib64 (and /lib, /bin, /sbin) symlink
aliases that are common on modern Linux where those paths are symlinked to
their /usr/... counterparts.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from brec.ir import PackageRef

# Symlink alias pairs: short_prefix → long_prefix.
# Both forms are indexed so build-recorder paths (which follow symlinks to
# /usr/...) match RPM database paths regardless of which form they used.
_ALIAS_PREFIXES: dict[str, str] = {
    "/lib/":   "/usr/lib/",
    "/lib64/": "/usr/lib64/",
    "/bin/":   "/usr/bin/",
    "/sbin/":  "/usr/sbin/",
}

# Regex to validate a NEVRA arch suffix: the last .component must be purely
# alphanumeric + underscore (x86_64, noarch, aarch64, i686, …).
_ARCH_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _parse_arch(nevra: str) -> Optional[str]:
    """Extract arch from a NEVRA string, e.g. 'glibc-2.33-alt9.x86_64' → 'x86_64'."""
    parts = nevra.rsplit(".", 1)
    if len(parts) == 2 and _ARCH_RE.match(parts[1]):
        return parts[1]
    return None


def _make_purl(name: str, nevra: str) -> Optional[str]:
    """Construct a minimal Package URL: pkg:rpm/<name>@<nevra>."""
    if not name or not nevra:
        return None
    return f"pkg:rpm/{name}@{nevra}"


class RpmBackend:
    """Provenance backend for RPM-based distributions (ALT Linux, RHEL, Fedora, …).

    Usage::

        backend = RpmBackend()
        backend.build_index(Path("rpm-dump.txt"))
        ref = backend.lookup("/usr/lib64/libfoo.so.1", "")
    """

    name: str = "rpm"

    def __init__(self) -> None:
        # {abspath: (rpm_name, rpm_nevra)} — both /lib64 and /usr/lib64 forms stored
        self._index: dict[str, tuple[str, str]] = {}
        self._built: bool = False

    # ── ProvenanceBackend interface ───────────────────────────────────────────

    def available(self) -> bool:
        """Return True once build_index() has been called successfully."""
        return self._built

    def build_index(self, env_dump: Path) -> None:
        """Load *env_dump* (rpm-dump.txt) and build the internal path index.

        *env_dump* must be a TSV file produced by::

            rpm -qa --qf '[%{FILENAMES}\\t%{NAME}\\t%{NEVRA}\\n]'

        Each line: ``filepath<TAB>rpm_name<TAB>rpm_nevra``.

        Path canonicalization mirrors ``enrich.load_rpm_dump()``:
        for every path both the short alias form (e.g. /lib64/…) and the
        long /usr/… form are indexed so lookups succeed regardless of which
        variant build-recorder recorded.
        """
        self._index = {}
        with open(env_dump, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t", 2)
                if len(parts) != 3:
                    continue
                filepath, rpm_name, rpm_nevra = parts
                if not filepath:
                    continue
                pkg = (rpm_name, rpm_nevra)
                self._index[filepath] = pkg
                # Add alias: /lib64/foo → /usr/lib64/foo (and vice versa)
                for short, long_ in _ALIAS_PREFIXES.items():
                    if filepath.startswith(short):
                        self._index[long_ + filepath[len(short):]] = pkg
                    elif filepath.startswith(long_):
                        self._index[short + filepath[len(long_):]] = pkg
        self._built = True

    def lookup(self, abspath: str, git_hash: str) -> Optional[PackageRef]:
        """Return the PackageRef for *abspath*, or None if not in the index.

        *git_hash* is accepted for interface compatibility but ignored —
        the rpm backend uses path-only lookup.
        """
        entry = self._index.get(abspath)
        if entry is None:
            return None
        rpm_name, rpm_nevra = entry
        return PackageRef(
            backend="rpm",
            name=rpm_name,
            version=rpm_nevra,
            arch=_parse_arch(rpm_nevra),
            source_package=None,
            purl=_make_purl(rpm_name, rpm_nevra),
        )

    # ── Convenience ──────────────────────────────────────────────────────────

    def index_as_dict(self) -> dict[str, tuple[str, str]]:
        """Return the raw {abspath: (name, nevra)} dict (for equivalence tests)."""
        return dict(self._index)
