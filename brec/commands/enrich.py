"""
brec enrich: приписывает файлам трассы пакет-владельца, не трогая трассу.

Использование:
    brec enrich <build.out> <rpm-dump.txt>
    brec enrich <build.out> <rpm-dump.txt> -o where/to/put.provenance.json
    brec enrich <build.out> <rpm-dump.txt> --dry-run

Входные данные:
    <build.out>     RDF Turtle, вывод build-recorder
    <rpm-dump.txt>  таблица "путь<TAB>rpm_name<TAB>nevra", экспортированная из контейнера:
                     rpm -qa --qf '[%{FILENAMES}\\t%{NAME}\\t%{NEVRA}\\n]'

Результат: sidecar рядом с трассой (`<build>.provenance.json`), по записи на
каждый файловый узел:

    pkg_backend, pkg_name, pkg_version, purl: пакет, которому принадлежит файл
    dep_type: роль файла (static_header | dynamic_lib | static_archive |
              build_tool | project_source | system_runtime)

Раньше эти данные дописывались тройками в сам .out. Так делать нельзя: трасса
после этого не то, что записал трассировщик, и по ней уже не отличить
наблюдение от более позднего вывода по чужой пакетной базе. Остальные
подкоманды подхватывают sidecar рядом с трассой сами.

Типы зависимостей:
    project_source  файл НЕ из RPM-пакета (исходник проекта)
    static_header   .h/.hpp/.hh из пакета (компилируется статически)
    dynamic_lib     .so из пакета (динамическая линковка)
    static_archive  .a из пакета (статическая линковка)
    build_tool      исполняемый файл в /usr/bin, /bin и т.д. (инструмент сборки)
    system_runtime  прочие файлы из пакета
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

from brec.model import parse_out
from brec.provenance import sidecar
from brec.provenance.rpm import RpmBackend

# Текст, которым старая версия помечала вписанный в .out блок. Пишущего кода
# больше нет, но узнавать такие трассы надо: их данные и sidecar могут спорить.
MARKER = "# --- package provenance triples (added by enrich.py) ---\n"


def is_already_enriched(out_file: Path) -> bool:
    with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line == MARKER:
                return True
    return False


def print_stats(doc) -> None:
    dep_counts: dict[str, int] = defaultdict(int)
    pkg_counts: dict[str, int] = defaultdict(int)

    for entry in doc.payload["files"].values():
        dep_counts[entry["dep_type"]] += 1
        name = entry.get("pkg_name")
        if name:
            pkg_counts[name] += 1

    print("\n=== Enrichment summary ===")
    print("Dependency types:")
    for dt, n in sorted(dep_counts.items(), key=lambda x: (-x[1], x[0])):
        print(f"  {dt:22s}: {n}")

    if pkg_counts:
        print("\nTop packages (by file count):")
        for pkg, n in sorted(pkg_counts.items(), key=lambda x: (-x[1], x[0]))[:25]:
            print(f"  {pkg:45s}: {n}")


def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("out_file", help="Path to build-recorder .out (RDF Turtle)")
    ap.add_argument("rpm_dump", help="Path to rpm-dump.txt (path<TAB>name<TAB>nevra)")
    ap.add_argument(
        "-o", "--output", metavar="FILE.provenance.json",
        help="Where to write the sidecar (default: next to the trace)",
    )
    ap.add_argument(
        "--dry-run", action="store_true",
        help="Show stats but write nothing",
    )


def run(args) -> int:
    out_file = Path(args.out_file)
    rpm_dump = Path(args.rpm_dump)

    if not out_file.exists():
        print(f"ERROR: not found: {out_file}", file=sys.stderr)
        return 1
    if not rpm_dump.exists():
        print(f"ERROR: not found: {rpm_dump}", file=sys.stderr)
        return 1

    if is_already_enriched(out_file):
        print(
            f"NOTE: {out_file} carries package triples written into it by an "
            "older brec enrich. They are left alone; the sidecar is written "
            "beside the trace and takes precedence where the two disagree.",
            file=sys.stderr,
        )

    print(f"Loading RPM dump from {rpm_dump} ...", end=" ", flush=True)
    backend = RpmBackend()
    backend.build_index(rpm_dump)
    print(f"{len(backend.index_as_dict())} file-package mappings")

    print(f"Scanning file nodes in {out_file} ...", end=" ", flush=True)
    graph = parse_out(out_file)
    print(f"{len(graph.files)} file nodes")

    doc = sidecar.build(graph, [backend], source_out=out_file, env_dump=rpm_dump)
    print_stats(doc)

    if args.dry_run:
        print("\n[dry-run] No changes written.")
        return 0

    target = Path(args.output) if args.output else sidecar.default_path(out_file)
    doc.dump(target)
    print(f"\nProvenance for {len(doc.payload['files'])} files → {target}")
    print(f"The trace itself is unchanged: {out_file}")
    return 0
