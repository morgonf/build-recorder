#!/usr/bin/env python3
"""
enrich.py — добавляет трипли о пакетном происхождении файлов в .out файл build-recorder.

Использование:
    python3 enrich.py <build.out> <rpm-dump.txt>
    python3 enrich.py <build.out> <rpm-dump.txt> --dry-run

Входные данные:
    <build.out>    — RDF Turtle, вывод build-recorder
    <rpm-dump.txt> — таблица "путь<TAB>rpm_name<TAB>nevra", экспортированная из контейнера:
                     rpm -qa --qf '[%{FILENAMES}\\t%{NAME}\\t%{NEVRA}\\n]'

Добавляет в <build.out> тройки:
    b:rpm_package — NEVRA пакета (NAME-VERSION-RELEASE.ARCH)
    b:rpm_name    — имя пакета без версии
    b:dep_type    — роль файла: static_header | dynamic_lib | static_archive |
                                build_tool | project_source | system_runtime | unknown

Типы зависимостей:
    project_source  — файл НЕ из RPM-пакета (исходник проекта)
    static_header   — .h/.hpp/.hh из пакета (компилируется статически)
    dynamic_lib     — .so из пакета (динамическая линковка)
    static_archive  — .a из пакета (статическая линковка)
    build_tool      — исполняемый файл в /usr/bin, /bin и т.д. (инструмент сборки)
    system_runtime  — прочие файлы из пакета
    unknown         — не удалось определить
"""

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

from brec.classify import dep_type_from_path
from brec.provenance.rpm import RpmBackend

MARKER = "# --- package provenance triples (added by enrich.py) ---\n"


def _unescape(s: str) -> str:
    return (
        s.replace('\\"', '"')
        .replace("\\\\", "\\")
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
    )


def parse_file_abspaths(out_file: Path) -> dict[str, str]:
    """
    Scans the .out file line-by-line to extract {uri: abspath} for all b:file nodes.
    Handles two formats:
      - Flat (new): each triple on its own line, subject repeated
          :f0  a  b:file .
          :f0  b:abspath  "/path" .
      - Grouped (old): semicolon-separated predicate blocks
          :f0 a b:file ;
              b:abspath "/path" ;
              ...
    """
    file_uris: set[str] = set()
    abspaths: dict[str, str] = {}
    current_uri: str | None = None

    file_re       = re.compile(r"^(:[a-zA-Z_]\w*)\s+a\s+b:file\b")
    abs_direct_re = re.compile(r"^(:[a-zA-Z_]\w*)\s+b:abspath\s+\"((?:[^\"\\]|\\.)*)\"")
    abs_indent_re = re.compile(r"^\s+b:abspath\s+\"((?:[^\"\\]|\\.)*)\"")

    with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")

            m = file_re.match(line)
            if m:
                file_uris.add(m.group(1))
                current_uri = m.group(1)
                continue

            m = abs_direct_re.match(line)
            if m:
                abspaths[m.group(1)] = _unescape(m.group(2))
                current_uri = None
                continue

            if current_uri:
                m = abs_indent_re.match(line)
                if m:
                    abspaths[current_uri] = _unescape(m.group(1))
                    continue
                if line and not line[0].isspace() and not line.startswith("#"):
                    current_uri = None

    return {uri: path for uri, path in abspaths.items() if uri in file_uris}


def is_already_enriched(out_file: Path) -> bool:
    with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line == MARKER:
                return True
    return False


def escape_ttl(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def build_triples(
    uri_to_abspath: dict[str, str],
    rpm_backend: RpmBackend,
) -> list[str]:
    blocks: list[str] = []
    for uri, abspath in sorted(uri_to_abspath.items()):
        pkg_ref = rpm_backend.lookup(abspath, "") if rpm_backend.available() else None
        dep_type = dep_type_from_path(abspath, pkg_ref is not None)

        parts: list[str] = []
        if pkg_ref:
            parts.append(f'    b:rpm_name "{escape_ttl(pkg_ref.name)}" ;')
            parts.append(f'    b:rpm_package "{escape_ttl(pkg_ref.version)}" ;')
        parts.append(f'    b:dep_type "{dep_type}" .')

        blocks.append(uri + "\n" + "\n".join(parts))

    return blocks


def print_stats(
    uri_to_abspath: dict[str, str],
    rpm_backend: RpmBackend,
) -> None:
    dep_counts: dict[str, int] = defaultdict(int)
    pkg_counts: dict[str, int] = defaultdict(int)

    for abspath in uri_to_abspath.values():
        pkg_ref = rpm_backend.lookup(abspath, "") if rpm_backend.available() else None
        dep_type = dep_type_from_path(abspath, pkg_ref is not None)
        dep_counts[dep_type] += 1
        if pkg_ref:
            pkg_counts[pkg_ref.name] += 1

    print("\n=== Enrichment summary ===")
    print("Dependency types:")
    for dt, n in sorted(dep_counts.items(), key=lambda x: -x[1]):
        print(f"  {dt:22s}: {n}")

    if pkg_counts:
        print("\nTop packages (by file count):")
        for pkg, n in sorted(pkg_counts.items(), key=lambda x: -x[1])[:25]:
            print(f"  {pkg:45s}: {n}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Add RPM package provenance triples to a build-recorder .out file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("out_file", help="Path to build-recorder .out (RDF Turtle)")
    ap.add_argument("rpm_dump", help="Path to rpm-dump.txt (path<TAB>name<TAB>nevra)")
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Show stats but do not modify <out_file>",
    )
    args = ap.parse_args()

    out_file = Path(args.out_file)
    rpm_dump = Path(args.rpm_dump)

    if not out_file.exists():
        print(f"ERROR: not found: {out_file}", file=sys.stderr)
        sys.exit(1)
    if not rpm_dump.exists():
        print(f"ERROR: not found: {rpm_dump}", file=sys.stderr)
        sys.exit(1)

    if is_already_enriched(out_file):
        print(
            f"WARNING: {out_file} appears already enriched (marker found). "
            "Remove the enrichment section manually before re-running.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Loading RPM dump from {rpm_dump} ...", end=" ", flush=True)
    backend = RpmBackend()
    backend.build_index(rpm_dump)
    print(f"{len(backend.index_as_dict())} file-package mappings")

    print(f"Scanning file nodes in {out_file} ...", end=" ", flush=True)
    uri_to_abspath = parse_file_abspaths(out_file)
    print(f"{len(uri_to_abspath)} file nodes")

    print_stats(uri_to_abspath, backend)

    if args.dry_run:
        print("\n[dry-run] No changes written.")
        return

    triples = build_triples(uri_to_abspath, backend)
    print(f"\nAppending {len(triples)} enriched file blocks to {out_file} ...")
    with open(out_file, "a", encoding="utf-8") as fh:
        fh.write("\n")
        fh.write(MARKER)
        fh.write("\n".join(triples))
        fh.write("\n")

    print("Done.")


if __name__ == "__main__":
    main()
