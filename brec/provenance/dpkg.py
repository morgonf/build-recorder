"""DpkgBackend — ProvenanceBackend implementation for Debian and its derivatives.

Reads the same three-column dump as the rpm backend (see tsvdump), written by
brec-collect from the dpkg database::

    /usr/lib/x86_64-linux-gnu/libc.so.6<TAB>libc6<TAB>libc6_2.39-0ubuntu8_amd64

The third column is ``package_version_arch``.  Neither a package name nor a
Debian version may contain "_", so the split is unambiguous.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional
from urllib.parse import quote

from brec.ir import PackageRef
from brec.provenance import tsvdump


class DpkgBackend:
    """Provenance backend for dpkg-based distributions (Debian, Ubuntu, …).

    *namespace* is the purl namespace, the distribution's os-release ID:
    ``pkg:deb/debian/...`` and ``pkg:deb/ubuntu/...`` name different packages
    even when the name and version agree.
    """

    name: str = "dpkg"

    def __init__(self, namespace: str = "debian") -> None:
        self.namespace = namespace
        self._index: dict[str, tuple[str, str]] = {}
        self._built: bool = False

    def available(self) -> bool:
        return self._built

    def build_index(self, env_dump: Path) -> None:
        self._index = tsvdump.index(env_dump)
        self._built = True

    @staticmethod
    def recognizes(env_dump: Path) -> bool:
        """True when *env_dump* reads as a dpkg dump (package_version_arch)."""
        return tsvdump.written_by(env_dump, "_")

    def lookup(self, abspath: str, git_hash: str) -> Optional[PackageRef]:
        entry = self._index.get(abspath)
        if entry is None:
            return None
        name, full = entry
        version, arch = full, None
        parts = full.split("_")
        if len(parts) == 3 and parts[0] == name:
            version, arch = parts[1], parts[2]
        # purl percent-encodes the epoch colon: 1:2.3-4 → 1%3A2.3-4.
        purl = f"pkg:deb/{self.namespace}/{name}@{quote(version, safe='')}"
        if arch:
            purl += f"?arch={arch}"
        return PackageRef(
            backend="dpkg",
            name=name,
            version=version,
            arch=arch,
            source_package=None,
            purl=purl,
        )

    def index_as_dict(self) -> dict[str, tuple[str, str]]:
        return dict(self._index)
