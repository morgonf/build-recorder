"""The package-database dump shared by every path-indexed backend.

One format whatever the distribution, as brec-collect writes it::

    path<TAB>package<TAB>full-version

The third column is what the package manager calls the installed instance:
the NEVRA for rpm (``glibc-2.33-alt9.x86_64``), ``package_version_arch`` for
dpkg (``libc6_2.39-0ubuntu8_amd64``, the name a .deb file carries).  Both start
with the package name, followed by "-" for rpm and "_" for dpkg, and that
separator is how a dump says which of the two it is.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

# Symlink alias pairs: short_prefix → long_prefix.
# Both forms are indexed so build-recorder paths (which follow symlinks to
# /usr/...) match package database paths regardless of which form they used.
ALIAS_PREFIXES: dict[str, str] = {
    "/lib/":   "/usr/lib/",
    "/lib64/": "/usr/lib64/",
    "/bin/":   "/usr/bin/",
    "/sbin/":  "/usr/sbin/",
}

# How many rows decide what a dump is.  The first rows are as typical as any:
# both package managers list packages one after another.
_SNIFF_ROWS = 200


def rows(env_dump: Path) -> Iterator[tuple[str, str, str]]:
    """Yield (path, package, full-version) for every well-formed line."""
    with open(env_dump, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) != 3 or not parts[0]:
                continue
            yield parts[0], parts[1], parts[2]


def index(env_dump: Path) -> dict[str, tuple[str, str]]:
    """{abspath: (package, full-version)}, with both alias forms of each path."""
    out: dict[str, tuple[str, str]] = {}
    for filepath, name, full in rows(env_dump):
        pkg = (name, full)
        out[filepath] = pkg
        for short, long_ in ALIAS_PREFIXES.items():
            if filepath.startswith(short):
                out[long_ + filepath[len(short):]] = pkg
            elif filepath.startswith(long_):
                out[short + filepath[len(long_):]] = pkg
    return out


def written_by(env_dump: Path, sep: str) -> bool:
    """True when the dump's full versions are "<package><sep>...".

    Nine rows in ten, not all: a dump is a live database, and one odd row
    should not make a whole dump unrecognisable.
    """
    seen = hits = 0
    try:
        for _path, name, full in rows(env_dump):
            seen += 1
            if name and full.startswith(name + sep):
                hits += 1
            if seen >= _SNIFF_ROWS:
                break
    except OSError:
        return False
    return seen > 0 and hits * 10 >= seen * 9
