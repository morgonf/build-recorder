"""
brec report — автономный анализатор файлов build-recorder.

Читает .out файл (RDF Turtle) через brec.model и выводит отчёт в консоль
и/или сохраняет в Markdown-файл.

Использование:
    brec report <file.out>
    brec report <file.out> --query stats
    brec report <file.out> --report [output.md]
    brec report <file.out> --report --quiet

Запросы (--query):
    all        — все запросы (по умолчанию)
    stats      — сводка по графу
    timeline   — временной диапазон сборки
    languages  — языки программирования
    tools      — инструменты/пакеты, задействованные в сборке
    externals  — готовые бинари, не собранные в этом билде
    sources    — исходные файлы проекта
    artifacts  — все артефакты (по расширениям)
    libs       — собранные библиотеки (.so, .a)
    tree       — дерево процессов
    headers    — топ системных заголовков
    packages   — пакетные зависимости (требует `brec enrich`)
    report     — полный Markdown-отчёт

Раньше эти запросы были SPARQL поверх rdflib. Сам SPARQL никуда не делся:
рецепты для ad-hoc запросов лежат в USAGE.md, и rdflib для них по-прежнему
годится. Здесь он не нужен: те же вопросы задаются к BuildGraph, который
brec.model собирает из трассы за один проход, без внешних зависимостей.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from brec.commands.common import add_provenance_option, load_graph as _load_graph
from brec.ir import BuildGraph, FileNode, ProcessNode

# ── Вспомогательные данные ────────────────────────────────────────────────────

EXT_LANG = {
    'c':    'C',
    'cpp':  'C++', 'cc': 'C++', 'cxx': 'C++',
    'inl':  'C/C++ (inline headers)',
    'h':    'C/C++ header', 'hpp': 'C++ header',
    'lua':  'Lua',
    'py':   'Python',
    'js':   'JavaScript',
    'ssjs': 'JavaScript (Duktape server-side)',
    'sh':   'Shell',
    'cmake':'CMake',
}

PKG_MAP = {
    'cc1': 'gcc', 'cc1plus': 'gcc', 'lto1': 'gcc', 'lto-wrapper': 'gcc',
    'collect2': 'gcc', 'gcc': 'gcc', 'g++': 'gcc',
    'x86_64-alt-linux-gcc-13':     'gcc',
    'x86_64-alt-linux-g++-13':     'gcc',
    'x86_64-alt-linux-gcc-ar-13':  'gcc',
    'x86_64-alt-linux-gcc-ranlib-13': 'gcc',
    'as': 'binutils', 'ld': 'binutils', 'ld.bfd': 'binutils',
    'ar': 'binutils', 'ranlib': 'binutils',
    'cmake': 'cmake', 'make': 'make', 'gmake': 'make',
    'pkg-config': 'pkg-config',
    'sh': 'bash', 'sh5': 'bash', 'bash': 'bash',
    'python3': 'python3', 'python2.7': 'python2', 'python': 'python3',
    'lua': 'lua', 'lua5.3': 'lua', 'lua-5.3': 'lua', 'lua5.4': 'lua',
    'patch': 'patch', 'tar': 'tar',
    'mkdir': 'coreutils', 'mv': 'coreutils', 'rm': 'coreutils',
    'cat': 'coreutils', 'chmod': 'coreutils', 'touch': 'coreutils',
    'uname': 'coreutils', 'ln': 'coreutils', 'cp': 'coreutils',
    'gcc_wrapper': 'gcc-common',
    'rpmb': 'rpm-build',
}

PKG_ROLE = {
    'gcc':        'Компиляция C/C++, LTO, линковка',
    'binutils':   'Ассемблер, линковщик, ar/ranlib',
    'bash':       'RPM-скрипты, cmake-зонды',
    'cmake':      'Конфигурация системы сборки',
    'make':       'Исполнение сборочных целей',
    'gcc-common': 'ALT-специфичный wrapper компилятора',
    'coreutils':  'Файловые операции (mv, mkdir, rm…)',
    'pkg-config': 'Поиск флагов зависимостей',
    'lua':        'Lua-скрипты в cmake-зондах',
    'python3':    'Python-скрипты в cmake-зондах',
    'patch':      'Применение патчей (%prep)',
    'tar':        'Распаковка исходников (%prep)',
    'rpm-build':  'Точка входа (rpmbuild/rpmb)',
}

# ── Загрузка графа ────────────────────────────────────────────────────────────

def load_graph(path: Path, provenance: Optional[Path] = None) -> BuildGraph:
    return _load_graph(path, provenance, quiet=True)


# ── Вопросы к графу ───────────────────────────────────────────────────────────
#
# Ровно то, что раньше спрашивал SPARQL. Пары (процесс, файл) внутри одного
# процесса дедуплицируются: в RDF повторная тройка `:p b:reads :f` это та же
# тройка, а в списке ProcessNode.reads она лежит столько раз, сколько было
# системных вызовов.

def read_pairs(g: BuildGraph) -> Iterator[tuple[ProcessNode, FileNode]]:
    for proc in g.procs.values():
        for uri in dict.fromkeys(proc.reads):
            node = g.files.get(uri)
            if node is not None:
                yield proc, node


def write_pairs(g: BuildGraph) -> Iterator[tuple[ProcessNode, FileNode]]:
    """Пары (процесс, произведённый им файл).

    Произведённым считается и записанный (b:writes), и переименованный в это
    имя (b:rename): `ar` собирает архив во временном файле и переименовывает
    его на место, поэтому по одним b:writes итоговый артефакт в отчёт не
    попадал, а попадал его временный предшественник. Так же на переименование
    смотрят brec.classify и `brec verify`.
    """
    for proc in g.procs.values():
        for uri in dict.fromkeys(list(proc.writes) + list(proc.renames)):
            node = g.files.get(uri)
            if node is not None:
                yield proc, node


def written_uris(g: BuildGraph) -> set[str]:
    """Файлы, которые эта сборка произвела: записала или переименовала на место."""
    return {
        uri
        for proc in g.procs.values()
        for uri in list(proc.writes) + list(proc.renames)
    }


def executable_counts(g: BuildGraph) -> Counter:
    """abspath запускавшегося файла → сколько раз его запускали.

    Считаются все b:executable процесса, а не только последний: один pid
    успевает сменить программу несколько раз (sh → gcc_wrapper → gcc → cc1),
    и каждый такой запуск трассировщик записывает отдельной тройкой.
    """
    counts: Counter = Counter()
    for proc in g.procs.values():
        for uri in proc.executables:
            node = g.files.get(uri)
            if node is not None:
                counts[node.abspath] += 1
    return counts


def by_count(counts) -> list[tuple[str, int]]:
    """Убывание счётчика, ничьи по имени: порядок не должен зависеть от прогона."""
    items = counts.items() if hasattr(counts, "items") else counts
    return sorted(items, key=lambda kv: (-kv[1], kv[0]))


_TS_FORMATS = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S")


def parse_ts(value: str) -> Optional[datetime]:
    """Разобрать метку времени трассы, не падая на незнакомом формате.

    Трассировщик пишет `...Z`, но фикстуры и чужие производители формата
    встречаются и без него. Раньше на такой метке отчёт падал с ValueError.
    """
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def build_span(g: BuildGraph) -> tuple[Optional[str], Optional[str], Optional[int]]:
    """(начало, конец, длительность в секундах) по процессам, у которых есть обе метки."""
    spans = [(p.start, p.end) for p in g.procs.values() if p.start and p.end]
    if not spans:
        return None, None, None
    begin = min(s for s, _ in spans)
    finish = max(e for _, e in spans)
    t1, t2 = parse_ts(begin), parse_ts(finish)
    seconds = int((t2 - t1).total_seconds()) if t1 and t2 else None
    return begin, finish, seconds


def source_ext_counts(g: BuildGraph) -> Counter:
    exts = (".c", ".cpp", ".cc", ".inl", ".lua", ".py", ".js", ".ssjs", ".sh")
    counts: Counter = Counter()
    for _proc, node in read_pairs(g):
        path = node.abspath
        if "TryCompile" in path or not path.endswith(exts):
            continue
        counts[path.rsplit(".", 1)[-1]] += 1
    return counts


def project_sources(g: BuildGraph, dirs: tuple[str, ...]) -> list[str]:
    """Прочитанные исходники проекта: .c/.cpp/.cc из сборочного дерева."""
    found = {
        node.abspath
        for _proc, node in read_pairs(g)
        if node.abspath.endswith((".c", ".cpp", ".cc"))
        and not any(skip in node.abspath for skip in ("CMakeFiles", "TryCompile", "conftest"))
        and any(d in node.abspath for d in dirs)
    }
    return sorted(found)


def unwritten_executables(g: BuildGraph) -> list[str]:
    written = written_uris(g)
    return sorted({
        node.abspath
        for proc in g.procs.values()
        for uri in proc.executables
        if uri not in written
        for node in (g.files.get(uri),) if node is not None
    })


def system_libs(g: BuildGraph) -> list[tuple[str, str]]:
    """Системные .so, прочитанные, но не собранные здесь: (путь, хеш)."""
    written = written_uris(g)
    found = {
        (node.abspath, node.git_blob_sha1)
        for _proc, node in read_pairs(g)
        if node.uri not in written
        and node.abspath.startswith(("/usr/lib", "/lib"))
        and ".so" in node.abspath
    }
    return sorted(found)


def produced_paths(g: BuildGraph) -> list[str]:
    found = {
        node.abspath
        for _proc, node in write_pairs(g)
        if not node.abspath.startswith("/tmp")
        and node.abspath != "/dev/null"
        and "CMakeFiles" not in node.abspath
        and "TryCompile" not in node.abspath
    }
    return sorted(found)


def produced_libs(g: BuildGraph) -> list[tuple[str, str]]:
    found = {
        (node.abspath, node.git_blob_sha1)
        for _proc, node in write_pairs(g)
        if (".so" in node.abspath or node.abspath.endswith(".a"))
        and not node.abspath.startswith("/tmp")
        and "TryCompile" not in node.abspath
    }
    return sorted(found)


def header_counts(g: BuildGraph) -> list[tuple[str, int]]:
    counts: Counter = Counter()
    for _proc, node in read_pairs(g):
        if node.abspath.endswith(".h") and node.abspath.startswith("/usr/"):
            counts[node.abspath] += 1
    return by_count(counts)[:15]


def process_roots(g: BuildGraph) -> list[ProcessNode]:
    """Процессы, которых никто не порождал.

    b:creates и b:execs brec.model держит в одном поле: трассировщик пишет
    только creates (record_child в src/record.c), execs остался в онтологии от
    апстрима. Если в трассе встретятся оба, здесь они сложатся.
    """
    children = {uri for proc in g.procs.values() for uri in proc.execs}
    return [p for uri, p in g.procs.items() if uri not in children]


def files_with_dep_type(g: BuildGraph) -> list[FileNode]:
    return [f for f in g.files.values() if f.dep_type]


def short(uri: str) -> str:
    """:p12 в p12, как печатал URI SPARQL-вывод: без префикса."""
    return uri.lstrip(":")


def name_of(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def hash_or_dash(value: str, width: Optional[int] = None) -> str:
    if not value:
        return "—"
    return value[:width] if width else value


# ── Вывод в консоль ───────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{'═'*62}")
    print(f"  {title}")
    print('═'*62)

def trow(label: str, value, w: int = 30):
    print(f"  {label:<{w}} {value}")

# ── Запросы ───────────────────────────────────────────────────────────────────

def stats(g: BuildGraph):
    section("Обзор графа")
    trow("Процессов",            len(g.procs))
    trow("Файлов",               len(g.files))
    trow("Чтений (reads)",       sum(len(set(p.reads)) for p in g.procs.values()))
    trow("Записей (writes)",     sum(len(set(p.writes)) for p in g.procs.values()))
    trow("Переименований",       sum(len(p.renames) for p in g.procs.values()))
    trow("Создано подпроцессов", sum(len(set(p.execs)) for p in g.procs.values()))


def timeline(g: BuildGraph):
    section("Временной диапазон сборки")
    begin, finish, seconds = build_span(g)
    if begin is None:
        return
    trow("Начало", begin)
    trow("Конец",  finish)
    trow("Длительность", f"{seconds} секунд" if seconds is not None else "—")


def languages(g: BuildGraph):
    section("Языки программирования")

    print("\n  Компиляторы/интерпретаторы:")
    for path, n in by_count(executable_counts(g)):
        print(f"  {n:5d}×  {name_of(path)}")

    print("\n  Исходные файлы по расширению:")
    for ext, n in source_ext_counts(g).most_common():
        print(f"  {'.' + ext:<10} {n:4d} файлов  → {EXT_LANG.get(ext, ext)}")


def tools(g: BuildGraph):
    section("Инструменты и пакеты, задействованные в сборке")
    by_pkg: dict[str, int] = defaultdict(int)
    detail = []
    for path, n in by_count(executable_counts(g)):
        name = name_of(path)
        pkg = PKG_MAP.get(name, name)
        by_pkg[pkg] += n
        detail.append((n, name, pkg))

    print("\n  По пакетам:")
    for pkg, total in by_count(by_pkg):
        print(f"  {total:5d}×  {pkg}")

    print("\n  Детально (утилита → пакет):")
    for n, name, pkg in sorted(detail, key=lambda x: (-x[0], x[1])):
        print(f"  {n:5d}×  {name:<42} [{pkg}]")


def externals(g: BuildGraph):
    section("Готовые бинари: использованы, но не собраны в этом билде")

    exes = unwritten_executables(g)
    print(f"\n  Запущенные исполняемые файлы ({len(exes)}):")
    for path in exes:
        print(f"    {path}")

    libs_ = system_libs(g)
    print(f"\n  Системные .so библиотеки ({len(libs_)}):")
    for path, digest in libs_:
        print(f"    {name_of(path):<50} {hash_or_dash(digest, 16)}")


def sources(g: BuildGraph):
    section("Исходники проекта, прочитанные при сборке")
    paths = project_sources(g, ("/BUILD/", "/build/src/", "/src/"))
    base = ""
    for path in paths:
        if not base:
            m = re.search(r'/BUILD/[^/]+/|/build/src/', path)
            base = path[:m.end()] if m else ""
    print(f"\n  Всего: {len(paths)} файлов")
    for path in paths:
        print(f"    {path.replace(base, '')}")


def artifacts(g: BuildGraph):
    section("Артефакты сборки (записанные файлы, не /tmp)")
    by_ext: dict[str, list] = defaultdict(list)
    for path in produced_paths(g):
        fn = name_of(path)
        ext = fn.rsplit('.', 1)[-1] if '.' in fn else 'no-ext'
        by_ext[ext].append(fn)
    for ext in sorted(by_ext):
        names = by_ext[ext]
        sample = ', '.join(names[:3]) + (f' … (+{len(names)-3})' if len(names) > 3 else '')
        trow(f".{ext} ({len(names)})", sample, w=20)


def libs(g: BuildGraph):
    section("Библиотеки, собранные в ходе сборки (.so, .a)")
    for path, digest in produced_libs(g):
        trow(name_of(path), f"hash: {hash_or_dash(digest, 16)}", w=44)


def tree(g: BuildGraph):
    section("Дерево процессов (2 уровня)")
    for root in process_roots(g)[:5]:
        print(f"\n  {short(root.uri)}: {root.cmd[:70] if root.cmd else '?'}")
        children = [g.procs.get(uri) for uri in dict.fromkeys(root.execs)]
        children = [c for c in children if c is not None]
        for child in children[:6]:
            print(f"    └─ {short(child.uri)}: {child.cmd[:65] if child.cmd else '?'}")
        if len(children) > 6:
            print(f"       … и ещё {len(children) - 6}")


def packages(g: BuildGraph):
    section("Пакетные зависимости (данные `brec enrich`)")

    enriched = files_with_dep_type(g)
    if not enriched:
        print("\n  Данные о пакетах недоступны.")
        print("  Запустите: brec enrich <build.out> <rpm-dump.txt>")
        return

    print("\n  По типу зависимости:")
    for dep_type, n in by_count(Counter(f.dep_type for f in enriched)):
        trow(dep_type, n)

    print("\n  Пакеты, участвующие в сборке (по числу файлов):")
    pkg_counts = Counter(f.rpm_name for f in g.files.values() if f.rpm_name)
    for name, n in by_count(pkg_counts):
        trow(name, f"{n} файлов", w=40)

    dyn = sorted({(f.abspath, f.rpm_name) for f in enriched if f.dep_type == "dynamic_lib"})
    if dyn:
        print(f"\n  Динамические библиотеки .so ({len(dyn)}):")
        for path, pkg in dyn:
            trow(name_of(path), f"[{pkg or '—'}]", w=44)

    arc = sorted({(f.abspath, f.rpm_name) for f in enriched if f.dep_type == "static_archive"})
    if arc:
        print(f"\n  Статические архивы .a ({len(arc)}):")
        for path, pkg in arc:
            trow(name_of(path), f"[{pkg or '—'}]", w=44)


def headers(g: BuildGraph):
    section("Наиболее читаемые системные заголовки")
    for path, n in header_counts(g):
        trow(str(n),
             path.replace("/usr/lib64/gcc/x86_64-alt-linux/13/", "<gcc>/")
                 .replace("/usr/include/", "<inc>/"),
             w=5)


# ── Генерация Markdown-отчёта ─────────────────────────────────────────────────

def generate_report(g: BuildGraph, src_path: Path) -> str:
    lines = []
    W = lines.append

    pkg_name = src_path.stem.replace('-build', '')
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

    W(f"# Build Report: {pkg_name}")
    W(f"\nСгенерировано: {now}  ")
    W(f"Источник: `{src_path}`\n")

    # ── Summary ──
    W("## Обзор\n")
    begin, finish, seconds = build_span(g)
    duration = f"{seconds} сек ({begin} → {finish})" if seconds is not None else "?"

    W("| Метрика | Значение |")
    W("|---------|---------|")
    W(f"| Процессов | {len(g.procs)} |")
    W(f"| Файлов | {len(g.files)} |")
    W(f"| Чтений (reads) | {sum(len(set(p.reads)) for p in g.procs.values())} |")
    W(f"| Записей (writes) | {sum(len(set(p.writes)) for p in g.procs.values())} |")
    W(f"| Создано подпроцессов | {sum(len(set(p.execs)) for p in g.procs.values())} |")
    W(f"| Длительность | {duration} |")

    # ── Languages ──
    W("\n## Языки программирования\n")
    W("| Расширение | Файлов | Язык |")
    W("|-----------|--------|------|")
    for ext, n in source_ext_counts(g).most_common():
        W(f"| `.{ext}` | {n} | {EXT_LANG.get(ext, ext)} |")

    # ── Source files ──
    W("\n## Исходники проекта\n")
    proj_src = project_sources(g, ("/BUILD/",))
    base = ""
    for path in proj_src:
        if not base:
            m = re.search(r'/BUILD/[^/]+/', path)
            base = path[:m.end()] if m else ""
    W(f"Всего: **{len(proj_src)}** файлов\n")
    for path in proj_src:
        W(f"- `{path.replace(base, '')}`")

    # ── Build tools ──
    W("\n## Инструменты сборки\n")
    by_pkg: dict[str, int] = defaultdict(int)
    for path, n in executable_counts(g).items():
        by_pkg[PKG_MAP.get(name_of(path), name_of(path))] += n

    W("| Пакет | Инвокаций | Роль |")
    W("|-------|----------|------|")
    for pkg, total in by_count(by_pkg):
        W(f"| `{pkg}` | {total} | {PKG_ROLE.get(pkg, '—')} |")

    # ── External binaries ──
    W("\n## Внешние бинарные зависимости\n")
    W("Файлы, **использованные** в сборке, но **не созданные** в ней.\n")

    exes = unwritten_executables(g)
    W(f"### Исполняемые файлы ({len(exes)})\n")
    for path in exes:
        W(f"- `{path}`")

    syslibs = system_libs(g)
    W(f"\n### Системные .so библиотеки ({len(syslibs)})\n")
    W("| Библиотека | SHA1 (git-compatible) |")
    W("|-----------|----------------------|")
    for path, digest in syslibs:
        W(f"| `{name_of(path)}` | `{hash_or_dash(digest)}` |")

    # ── Produced libs ──
    lib_rows = produced_libs(g)
    if lib_rows:
        W("\n## Собранные библиотеки\n")
        W("| Библиотека | SHA1 |")
        W("|-----------|------|")
        for path, digest in lib_rows:
            W(f"| `{name_of(path)}` | `{hash_or_dash(digest)}` |")

    # ── Package provenance (if `brec enrich` was run) ──
    enriched = files_with_dep_type(g)
    if enriched:
        W("\n## Пакетные зависимости\n")
        W("*Данные добавлены `brec enrich` на основе RPM-базы контейнера.*\n")

        W("### По типу зависимости\n")
        W("| Тип | Файлов |")
        W("|-----|--------|")
        for dep_type, n in by_count(Counter(f.dep_type for f in enriched)):
            W(f"| `{dep_type}` | {n} |")

        W("\n### Пакеты\n")
        W("| Пакет | Файлов |")
        W("|-------|--------|")
        pkg_counts = Counter(f.rpm_name for f in g.files.values() if f.rpm_name)
        for name, n in by_count(pkg_counts):
            W(f"| `{name}` | {n} |")

        dyn_rows = sorted({(f.abspath, f.rpm_name) for f in enriched
                           if f.dep_type == "dynamic_lib"})
        if dyn_rows:
            W(f"\n### Динамические библиотеки ({len(dyn_rows)})\n")
            W("| Библиотека | Пакет |")
            W("|-----------|-------|")
            for path, pkg in dyn_rows:
                W(f"| `{name_of(path)}` | `{pkg or '—'}` |")

        arc_rows = sorted({(f.abspath, f.rpm_name) for f in enriched
                           if f.dep_type == "static_archive"})
        if arc_rows:
            W(f"\n### Статические архивы ({len(arc_rows)})\n")
            W("| Архив | Пакет |")
            W("|-------|-------|")
            for path, pkg in arc_rows:
                W(f"| `{name_of(path)}` | `{pkg or '—'}` |")

    W("\n---\n")
    W(f"*Отчёт сгенерирован `brec report` на основе данных `build-recorder`*")
    return "\n".join(lines)

# ── CLI ───────────────────────────────────────────────────────────────────────

AVAILABLE = {
    "stats":     stats,
    "timeline":  timeline,
    "languages": languages,
    "tools":     tools,
    "externals": externals,
    "sources":   sources,
    "artifacts": artifacts,
    "libs":      libs,
    "tree":      tree,
    "headers":   headers,
    "packages":  packages,
}


def add_arguments(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("file", help="Путь к .out файлу build-recorder")
    add_provenance_option(ap)
    ap.add_argument(
        "--query", "-q",
        default="all",
        choices=["all"] + list(AVAILABLE) + ["report"],
        help="Запрос для выполнения (по умолчанию: all)",
    )
    ap.add_argument(
        "--report", "-r",
        nargs="?", const=True, metavar="OUTPUT.md",
        help="Сгенерировать Markdown-отчёт (опционально: путь к файлу)",
    )
    ap.add_argument(
        "--quiet", action="store_true",
        help="Не выводить отчёт в консоль (только сохранить в файл)",
    )


def run(args) -> int:
    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: файл не найден: {path}", file=sys.stderr)
        return 1

    print(f"Загрузка {path.name} ...", end=" ", flush=True)
    t0 = time.time()
    g = load_graph(path, args.provenance)
    print(f"{len(g.procs)} процессов, {len(g.files)} файлов "
          f"за {time.time() - t0:.1f}с")

    if args.report is not None:
        md = generate_report(g, path)
        out_path = path.with_suffix('.md') if args.report is True else Path(args.report)
        out_path.write_text(md, encoding='utf-8')
        if not args.quiet:
            print(md)
        print(f"\n✓ Отчёт сохранён: {out_path}", file=sys.stderr)
        return 0

    if args.query == "all":
        for fn in AVAILABLE.values():
            fn(g)
    elif args.query == "report":
        md = generate_report(g, path)
        out_path = path.with_suffix('.md')
        out_path.write_text(md, encoding='utf-8')
        print(md)
        print(f"\n✓ Отчёт сохранён: {out_path}", file=sys.stderr)
    else:
        AVAILABLE[args.query](g)

    print()
    return 0
