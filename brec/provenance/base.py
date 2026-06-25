"""ProvenanceBackend Protocol — the distro-agnostic interface for file→package lookup."""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

from brec.ir import PackageRef


@runtime_checkable
class ProvenanceBackend(Protocol):
    """Map file paths to the OS packages that own them.

    Implementations are distro-specific (rpm, dpkg, apk, …) but share this
    interface so that the core classify/identify pipeline never imports
    distribution-specific code directly.
    """

    name: str  # unique backend identifier: "rpm" | "dpkg" | ...

    def available(self) -> bool:
        """Return True if this backend can be used in the current environment.

        Typically checks whether the index has been built or the OS package
        database is accessible.
        """
        ...

    def build_index(self, env_dump: Path) -> None:
        """Build (or rebuild) the internal path→package index from *env_dump*.

        For ``RpmBackend`` *env_dump* is the path to ``rpm-dump.txt``; other
        backends may use a different file format.  After this call
        :meth:`available` returns ``True`` and :meth:`lookup` is usable.
        """
        ...

    def lookup(self, abspath: str, git_hash: str) -> Optional[PackageRef]:
        """Return the package that owns *abspath*, or ``None`` if unknown.

        *git_hash* is the git-blob SHA-1 from the ``.out`` file; backends
        that support content-based lookup (future) may use it.  The rpm
        backend ignores it (path-only lookup) but the signature is fixed
        here so all backends are interchangeable.
        """
        ...
