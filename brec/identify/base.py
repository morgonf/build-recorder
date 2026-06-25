"""brec.identify.base — identification backend interface and VendoredUnit."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from brec.ir import FileHash, Match


@dataclass
class VendoredUnit:
    """A group of files sharing the same vendor directory, ready for identification.

    ``key`` matches :attr:`brec.ir.IdentifiedComponent.key` (= the vendor_dir
    string, e.g. ``"third_party/sqlite"``).

    ``files`` is a list of :class:`~brec.ir.FileHash` objects — one per file.
    ``file_uris`` runs parallel to ``files`` and contains the original
    :class:`~brec.ir.FileNode` URI strings from the build graph, preserved so
    that :func:`~brec.identify.resolver.resolve` can populate
    :attr:`~brec.ir.IdentifiedComponent.files` without losing traceability.

    ``abs_root`` is the absolute filesystem path of the vendor directory root
    (e.g. ``/home/user/project/src/third_party/sqlite``).  It is ``None`` when
    the directory is not reachable in the current environment.
    """
    key: str
    files: list[FileHash]
    abs_root: Optional[str] = None
    file_uris: list[str] = field(default_factory=list)   # parallel to files


@runtime_checkable
class IdentificationBackend(Protocol):
    """Interface for a single identification strategy.

    A backend may implement either or both of:

    * **discover** — find candidate repo_url / version / project for a unit
      (e.g. by querying SWH / OSV / a local cache).  Returns ``[]`` if it
      cannot help.

    * **refine** — given a known ``repo_url``, walk the git history to find the
      exact commit and tag (e.g. gitwalk).  Returns ``None`` if it cannot help,
      or raises ``NotImplementedError`` if refinement is not supported at all.
      The resolver catches both.

    Attributes
    ----------
    name:
        Short identifier used in ``Match.backend`` and log messages.
    requires_network:
        When ``True`` the backend is skipped in ``offline`` mode.
    """

    name: str
    requires_network: bool

    def discover(self, unit: VendoredUnit) -> list[Match]:
        """Return candidate matches for *unit* (may be an empty list)."""
        ...

    def refine(self, unit: VendoredUnit, repo_url: str) -> Optional[Match]:
        """Refine an existing ``repo_url`` candidate to a precise commit/tag.

        Return ``None`` (or raise ``NotImplementedError``) when this backend
        does not support refinement.
        """
        ...
