"""brec.provenance.registry — backend registration and auto-detection.

Usage::

    # Auto-detect: build index from env dump, return available backends
    backends = detect_backends(Path("rpm-dump.txt"))

    # Explicit selection via --provenance flag value
    names = parse_provenance_arg("rpm")       # → ["rpm"]
    backends = select_backends(names)          # → [RpmBackend()]

    # Validate and list
    all_b = all_backends()                     # → [RpmBackend()]
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from brec.provenance.base import ProvenanceBackend
from brec.provenance.rpm import RpmBackend

# ── Backend table ─────────────────────────────────────────────────────────────
# Maps the backend's ``name`` identifier to its class.
# Add new backends here; the rest of the registry code needs no changes.

_REGISTRY: dict[str, type] = {
    "rpm": RpmBackend,
}

# ── Public API ────────────────────────────────────────────────────────────────

def all_backends() -> list[ProvenanceBackend]:
    """Return a fresh instance of every registered backend (index not built).

    Instances are in registration order.  Use :func:`detect_backends` when you
    need only those that are actually usable in the current environment.
    """
    return [cls() for cls in _REGISTRY.values()]  # type: ignore[return-value]


def detect_backends(env_dump: Optional[Path] = None) -> list[ProvenanceBackend]:
    """Return backends that are available in the current environment.

    If *env_dump* is given, each backend attempts ``build_index(env_dump)``
    first (errors are silently ignored).  A backend is included in the result
    only if ``available()`` returns ``True`` after this attempt.

    If *env_dump* is ``None``, only pre-built backends (already have an index
    from a previous ``build_index`` call) are included — which in practice
    means an empty list unless a backend was built elsewhere.
    """
    result: list[ProvenanceBackend] = []
    for cls in _REGISTRY.values():
        backend: ProvenanceBackend = cls()  # type: ignore[assignment]
        if env_dump is not None:
            try:
                backend.build_index(env_dump)
            except (OSError, ValueError, Exception):
                pass  # file missing / wrong format → backend stays unavailable
        if backend.available():
            result.append(backend)
    return result


def select_backends(names: Optional[list[str]]) -> list[ProvenanceBackend]:
    """Return backend instances for the given *names* list.

    If *names* is ``None``, returns :func:`all_backends` (same as no explicit
    selection — auto-detect later via :func:`detect_backends`).

    Raises :class:`ValueError` with a human-readable message listing all
    registered backend names if any name in *names* is unknown.
    """
    if names is None:
        return all_backends()

    result: list[ProvenanceBackend] = []
    for name in names:
        if name not in _REGISTRY:
            available = sorted(_REGISTRY.keys())
            raise ValueError(
                f"Unknown provenance backend {name!r}. "
                f"Available: {', '.join(available)}"
            )
        result.append(_REGISTRY[name]())  # type: ignore[return-value]
    return result


def parse_provenance_arg(arg: Optional[str]) -> Optional[list[str]]:
    """Parse the ``--provenance`` CLI flag value into a list of backend names.

    Examples::

        parse_provenance_arg("rpm")        → ["rpm"]
        parse_provenance_arg("rpm,dpkg")   → ["rpm", "dpkg"]
        parse_provenance_arg("rpm, dpkg")  → ["rpm", "dpkg"]  (spaces stripped)
        parse_provenance_arg("")           → []
        parse_provenance_arg(None)         → None  (not provided → auto-detect)

    The caller is responsible for passing the result to :func:`select_backends`.
    """
    if arg is None:
        return None
    return [name.strip() for name in arg.split(",") if name.strip()]
