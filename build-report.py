#!/usr/bin/env python3
"""
build-report.py — автономный анализатор файлов build-recorder.

Читает .out файл (RDF Turtle), выполняет SPARQL-запросы через rdflib
и выводит отчёт в консоль и/или сохраняет в Markdown-файл.

Использование:
    build-report.py <file.out>
    build-report.py <file.out> --query stats
    build-report.py <file.out> --report [output.md]
    build-report.py <file.out> --report --quiet

Зависимости:
    pip3 install rdflib

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
    packages   — пакетные зависимости (требует enrich.py)
    report     — полный Markdown-отчёт
"""

import argparse
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

try:
    import rdflib
except ImportError:
    print("ERROR: rdflib не установлен. Выполните: pip3 install rdflib", file=sys.stderr)
    sys.exit(1)

# ── Пространства имён ─────────────────────────────────────────────────────────

B   = "http://build-recorder.org/rdf#"
D   = "http://build-recorder.org/data#"
PFX = f"""
PREFIX b:   <{B}>
PREFIX :    <{D}>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
"""

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

def load_graph(path: Path) -> rdflib.Graph:
    g = rdflib.Graph()
    g.parse(str(path), format="turtle")
    return g

def q(g: rdflib.Graph, query: str):
    return list(g.query(PFX + query))

# ── Вывод в консоль ───────────────────────────────────────────────────────────

def section(title: str):
    print(f"\n{'═'*62}")
    print(f"  {title}")
    print('═'*62)

def trow(label: str, value, w: int = 30):
    print(f"  {label:<{w}} {value}")

# ── Запросы ───────────────────────────────────────────────────────────────────

def stats(g: rdflib.Graph):
    section("Обзор графа")
    for label, query in [
        ("Процессов",           "SELECT (COUNT(?p) AS ?n) WHERE { ?p a b:process }"),
        ("Файлов",              "SELECT (COUNT(?f) AS ?n) WHERE { ?f a b:file }"),
        ("Чтений (reads)",      "SELECT (COUNT(?r) AS ?n) WHERE { ?s b:reads ?r }"),
        ("Записей (writes)",    "SELECT (COUNT(?w) AS ?n) WHERE { ?s b:writes ?w }"),
        ("Переименований",      "SELECT (COUNT(?r) AS ?n) WHERE { ?s b:rename ?r }"),
        ("Создано подпроцессов","SELECT (COUNT(?c) AS ?n) WHERE { ?s b:creates ?c }"),
    ]:
        trow(label, q(g, query)[0][0])


def timeline(g: rdflib.Graph):
    section("Временной диапазон сборки")
    rows = q(g, """
        SELECT (MIN(?s) AS ?begin) (MAX(?e) AS ?finish)
        WHERE { ?p a b:process ; b:start ?s ; b:end ?e . }
    """)
    if rows and rows[0][0]:
        t1 = datetime.strptime(str(rows[0][0]), "%Y-%m-%dT%H:%M:%SZ")
        t2 = datetime.strptime(str(rows[0][1]), "%Y-%m-%dT%H:%M:%SZ")
        trow("Начало",       rows[0][0])
        trow("Конец",        rows[0][1])
        trow("Длительность", f"{(t2 - t1).seconds} секунд")


def languages(g: rdflib.Graph):
    section("Языки программирования")

    print("\n  Компиляторы/интерпретаторы:")
    rows = q(g, """
        SELECT DISTINCT ?path (COUNT(?proc) AS ?n)
        WHERE { ?proc a b:process ; b:executable ?exe . ?exe b:abspath ?path . }
        GROUP BY ?path ORDER BY DESC(?n)
    """)
    for (path, n) in rows:
        name = str(path).split('/')[-1]
        print(f"  {int(n):5d}×  {name}")

    print("\n  Исходные файлы по расширению:")
    rows2 = q(g, """
        SELECT ?path
        WHERE {
            ?proc a b:process ; b:reads ?file . ?file b:abspath ?path .
            FILTER(!CONTAINS(STR(?path), "TryCompile"))
            FILTER(
                STRENDS(STR(?path),".c")   || STRENDS(STR(?path),".cpp") ||
                STRENDS(STR(?path),".cc")  || STRENDS(STR(?path),".inl") ||
                STRENDS(STR(?path),".lua") || STRENDS(STR(?path),".py")  ||
                STRENDS(STR(?path),".js")  || STRENDS(STR(?path),".ssjs")||
                STRENDS(STR(?path),".sh")
            )
        }
    """)
    cnt = Counter(str(p).rsplit('.', 1)[-1] for (p,) in rows2)
    for ext, n in cnt.most_common():
        lang = EXT_LANG.get(ext, ext)
        print(f"  {'.' + ext:<10} {n:4d} файлов  → {lang}")


def tools(g: rdflib.Graph):
    section("Инструменты и пакеты, задействованные в сборке")
    rows = q(g, """
        SELECT ?path (COUNT(?proc) AS ?n)
        WHERE { ?proc a b:process ; b:executable ?exe . ?exe b:abspath ?path . }
        GROUP BY ?path ORDER BY DESC(?n)
    """)
    by_pkg: dict[str, int] = defaultdict(int)
    detail = []
    for (path, n) in rows:
        name = str(path).split('/')[-1]
        pkg = PKG_MAP.get(name, name)
        by_pkg[pkg] += int(n)
        detail.append((int(n), name, pkg))

    print("\n  По пакетам:")
    for pkg, total in sorted(by_pkg.items(), key=lambda x: -x[1]):
        print(f"  {total:5d}×  {pkg}")

    print("\n  Детально (утилита → пакет):")
    for n, name, pkg in sorted(detail, key=lambda x: -x[0]):
        print(f"  {n:5d}×  {name:<42} [{pkg}]")


def externals(g: rdflib.Graph):
    section("Готовые бинари: использованы, но не собраны в этом билде")

    exes = q(g, """
        SELECT DISTINCT ?path
        WHERE {
            ?proc b:executable ?file . ?file b:abspath ?path .
            FILTER NOT EXISTS { ?any b:writes ?file }
        }
        ORDER BY ?path
    """)
    print(f"\n  Запущенные исполняемые файлы ({len(exes)}):")
    for (path,) in exes:
        print(f"    {path}")

    libs = q(g, """
        SELECT DISTINCT ?path ?hash
        WHERE {
            ?proc b:reads ?file . ?file b:abspath ?path .
            OPTIONAL { ?file b:hash ?hash }
            FILTER NOT EXISTS { ?any b:writes ?file }
            FILTER(STRSTARTS(STR(?path),"/usr/lib") || STRSTARTS(STR(?path),"/lib"))
            FILTER(CONTAINS(STR(?path),".so"))
        }
        ORDER BY ?path
    """)
    print(f"\n  Системные .so библиотеки ({len(libs)}):")
    for (path, hash_) in libs:
        name = str(path).split('/')[-1]
        h = str(hash_)[:16] if hash_ else '—'
        print(f"    {name:<50} {h}")


def sources(g: rdflib.Graph):
    section("Исходники проекта, прочитанные при сборке")
    rows = q(g, """
        SELECT DISTINCT ?path
        WHERE {
            ?proc a b:process ; b:reads ?file . ?file b:abspath ?path .
            FILTER(
                STRENDS(STR(?path),".c")  || STRENDS(STR(?path),".cpp") ||
                STRENDS(STR(?path),".cc")
            )
            FILTER(!CONTAINS(STR(?path), "CMakeFiles"))
            FILTER(!CONTAINS(STR(?path), "TryCompile"))
            FILTER(!CONTAINS(STR(?path), "conftest"))
            FILTER(
                CONTAINS(STR(?path), "/BUILD/") ||
                CONTAINS(STR(?path), "/build/src/") ||
                CONTAINS(STR(?path), "/src/")
            )
        }
        ORDER BY ?path
    """)
    base = ""
    for (path,) in rows:
        p = str(path)
        if not base:
            m = re.search(r'/BUILD/[^/]+/|/build/src/', p)
            base = p[:m.end()] if m else ""
    print(f"\n  Всего: {len(rows)} файлов")
    for (path,) in rows:
        print(f"    {str(path).replace(base, '')}")


def artifacts(g: rdflib.Graph):
    section("Артефакты сборки (записанные файлы, не /tmp)")
    rows = q(g, """
        SELECT DISTINCT ?path
        WHERE {
            ?proc a b:process ; b:writes ?file . ?file b:abspath ?path .
            FILTER(!STRSTARTS(STR(?path), "/tmp"))
            FILTER(STR(?path) != "/dev/null")
            FILTER(!CONTAINS(STR(?path), "CMakeFiles"))
            FILTER(!CONTAINS(STR(?path), "TryCompile"))
        }
        ORDER BY ?path
    """)
    by_ext: dict[str, list] = defaultdict(list)
    for (path,) in rows:
        fn = str(path).split('/')[-1]
        ext = fn.rsplit('.', 1)[-1] if '.' in fn else 'no-ext'
        by_ext[ext].append(fn)
    for ext in sorted(by_ext):
        paths = by_ext[ext]
        sample = ', '.join(paths[:3]) + (f' … (+{len(paths)-3})' if len(paths) > 3 else '')
        trow(f".{ext} ({len(paths)})", sample, w=20)


def libs(g: rdflib.Graph):
    section("Библиотеки, собранные в ходе сборки (.so, .a)")
    rows = q(g, """
        SELECT DISTINCT ?path ?hash
        WHERE {
            ?proc a b:process ; b:writes ?file . ?file b:abspath ?path .
            OPTIONAL { ?file b:hash ?hash }
            FILTER(CONTAINS(STR(?path),".so") || STRENDS(STR(?path),".a"))
            FILTER(!STRSTARTS(STR(?path),"/tmp"))
            FILTER(!CONTAINS(STR(?path),"TryCompile"))
        }
        ORDER BY ?path
    """)
    for (path, hash_) in rows:
        h = str(hash_)[:16] if hash_ else '—'
        trow(str(path).split('/')[-1], f"hash: {h}", w=44)


def tree(g: rdflib.Graph):
    section("Дерево процессов (2 уровня)")
    roots = q(g, """
        SELECT ?p WHERE {
            ?p a b:process .
            FILTER NOT EXISTS { ?parent b:creates ?p }
        } LIMIT 5
    """)
    for (root,) in roots:
        cmd_r = q(g, f"SELECT ?cmd WHERE {{ <{root}> b:cmd ?cmd }} LIMIT 1")
        cmd = str(cmd_r[0][0])[:70] if cmd_r else "?"
        rid = str(root).split('#')[-1]
        children = q(g, f"""
            SELECT ?child ?cmd WHERE {{
                <{root}> b:creates ?child .
                OPTIONAL {{ ?child b:cmd ?cmd }}
            }}
        """)
        print(f"\n  {rid}: {cmd}")
        for (child, ccmd) in children[:6]:
            print(f"    └─ {str(child).split('#')[-1]}: {str(ccmd)[:65] if ccmd else '?'}")
        if len(children) > 6:
            print(f"       … и ещё {len(children) - 6}")


def packages(g: rdflib.Graph):
    section("Пакетные зависимости (данные enrich.py)")

    check = q(g, "SELECT (COUNT(?f) AS ?n) WHERE { ?f b:dep_type ?t }")
    if not check or int(check[0][0]) == 0:
        print("\n  Данные о пакетах недоступны.")
        print("  Запустите: python3 enrich.py <build.out> <rpm-dump.txt>")
        return

    print("\n  По типу зависимости:")
    rows = q(g, """
        SELECT ?dep_type (COUNT(DISTINCT ?file) AS ?n)
        WHERE { ?file b:dep_type ?dep_type }
        GROUP BY ?dep_type ORDER BY DESC(?n)
    """)
    for (dep_type, n) in rows:
        trow(str(dep_type), n)

    print("\n  Пакеты, участвующие в сборке (по числу файлов):")
    rows = q(g, """
        SELECT ?rpm_name (COUNT(DISTINCT ?file) AS ?n)
        WHERE { ?file b:rpm_name ?rpm_name }
        GROUP BY ?rpm_name ORDER BY DESC(?n)
    """)
    for (name, n) in rows:
        trow(str(name), f"{n} файлов", w=40)

    dyn = q(g, """
        SELECT DISTINCT ?path ?rpm_name WHERE {
            ?file b:abspath ?path ; b:dep_type "dynamic_lib" .
            OPTIONAL { ?file b:rpm_name ?rpm_name }
        } ORDER BY ?path
    """)
    if dyn:
        print(f"\n  Динамические библиотеки .so ({len(dyn)}):")
        for (path, name) in dyn:
            pkg = str(name) if name else "—"
            trow(str(path).split("/")[-1], f"[{pkg}]", w=44)

    arc = q(g, """
        SELECT DISTINCT ?path ?rpm_name WHERE {
            ?file b:abspath ?path ; b:dep_type "static_archive" .
            OPTIONAL { ?file b:rpm_name ?rpm_name }
        } ORDER BY ?path
    """)
    if arc:
        print(f"\n  Статические архивы .a ({len(arc)}):")
        for (path, name) in arc:
            pkg = str(name) if name else "—"
            trow(str(path).split("/")[-1], f"[{pkg}]", w=44)


def headers(g: rdflib.Graph):
    section("Наиболее читаемые системные заголовки")
    rows = q(g, """
        SELECT ?path (COUNT(?proc) AS ?n)
        WHERE {
            ?proc a b:process ; b:reads ?file . ?file b:abspath ?path .
            FILTER(STRENDS(STR(?path),".h"))
            FILTER(STRSTARTS(STR(?path),"/usr/"))
        }
        GROUP BY ?path ORDER BY DESC(?n) LIMIT 15
    """)
    for (path, n) in rows:
        p = (str(path)
             .replace("/usr/lib64/gcc/x86_64-alt-linux/13/", "<gcc>/")
             .replace("/usr/include/", "<inc>/"))
        trow(str(n), p, w=5)

# ── Генерация Markdown-отчёта ─────────────────────────────────────────────────

def generate_report(g: rdflib.Graph, src_path: Path) -> str:
    lines = []
    W = lines.append

    pkg_name = src_path.stem.replace('-build', '')
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')

    W(f"# Build Report: {pkg_name}")
    W(f"\nСгенерировано: {now}  ")
    W(f"Источник: `{src_path}`\n")

    # ── Summary ──
    W("## Обзор\n")
    counts = {}
    for key, query in [
        ("processes", "SELECT (COUNT(?p) AS ?n) WHERE { ?p a b:process }"),
        ("files",     "SELECT (COUNT(?f) AS ?n) WHERE { ?f a b:file }"),
        ("reads",     "SELECT (COUNT(?r) AS ?n) WHERE { ?s b:reads ?r }"),
        ("writes",    "SELECT (COUNT(?w) AS ?n) WHERE { ?s b:writes ?w }"),
        ("creates",   "SELECT (COUNT(?c) AS ?n) WHERE { ?s b:creates ?c }"),
    ]:
        counts[key] = int(q(g, query)[0][0])

    ts = q(g, """
        SELECT (MIN(?s) AS ?begin) (MAX(?e) AS ?finish)
        WHERE { ?p a b:process ; b:start ?s ; b:end ?e . }
    """)
    duration = "?"
    if ts and ts[0][0]:
        t1 = datetime.strptime(str(ts[0][0]), "%Y-%m-%dT%H:%M:%SZ")
        t2 = datetime.strptime(str(ts[0][1]), "%Y-%m-%dT%H:%M:%SZ")
        duration = f"{(t2 - t1).seconds} сек ({ts[0][0]} → {ts[0][1]})"

    W("| Метрика | Значение |")
    W("|---------|---------|")
    W(f"| Процессов | {counts['processes']} |")
    W(f"| Файлов | {counts['files']} |")
    W(f"| Чтений (reads) | {counts['reads']} |")
    W(f"| Записей (writes) | {counts['writes']} |")
    W(f"| Создано подпроцессов | {counts['creates']} |")
    W(f"| Длительность | {duration} |")

    # ── Languages ──
    W("\n## Языки программирования\n")
    src_rows = q(g, """
        SELECT ?path WHERE {
            ?proc a b:process ; b:reads ?file . ?file b:abspath ?path .
            FILTER(!CONTAINS(STR(?path),"TryCompile"))
            FILTER(
                STRENDS(STR(?path),".c")   || STRENDS(STR(?path),".cpp") ||
                STRENDS(STR(?path),".cc")  || STRENDS(STR(?path),".inl") ||
                STRENDS(STR(?path),".lua") || STRENDS(STR(?path),".py")  ||
                STRENDS(STR(?path),".js")  || STRENDS(STR(?path),".ssjs")||
                STRENDS(STR(?path),".sh")
            )
        }
    """)
    cnt = Counter(str(p).rsplit('.', 1)[-1] for (p,) in src_rows)
    W("| Расширение | Файлов | Язык |")
    W("|-----------|--------|------|")
    for ext, n in cnt.most_common():
        W(f"| `.{ext}` | {n} | {EXT_LANG.get(ext, ext)} |")

    # ── Source files ──
    W("\n## Исходники проекта\n")
    proj_src = q(g, """
        SELECT DISTINCT ?path WHERE {
            ?proc a b:process ; b:reads ?file . ?file b:abspath ?path .
            FILTER(STRENDS(STR(?path),".c") || STRENDS(STR(?path),".cpp") || STRENDS(STR(?path),".cc"))
            FILTER(CONTAINS(STR(?path),"/BUILD/"))
            FILTER(!CONTAINS(STR(?path),"CMakeFiles"))
            FILTER(!CONTAINS(STR(?path),"TryCompile"))
        }
        ORDER BY ?path
    """)
    base = ""
    for (path,) in proj_src:
        p = str(path)
        if not base:
            m = re.search(r'/BUILD/[^/]+/', p)
            base = p[:m.end()] if m else ""
    W(f"Всего: **{len(proj_src)}** файлов\n")
    for (path,) in proj_src:
        W(f"- `{str(path).replace(base, '')}`")

    # ── Build tools ──
    W("\n## Инструменты сборки\n")
    tool_rows = q(g, """
        SELECT ?path (COUNT(?proc) AS ?n)
        WHERE { ?proc a b:process ; b:executable ?exe . ?exe b:abspath ?path . }
        GROUP BY ?path ORDER BY DESC(?n)
    """)
    by_pkg: dict[str, int] = defaultdict(int)
    for (path, n) in tool_rows:
        name = str(path).split('/')[-1]
        by_pkg[PKG_MAP.get(name, name)] += int(n)

    W("| Пакет | Инвокаций | Роль |")
    W("|-------|----------|------|")
    for pkg, total in sorted(by_pkg.items(), key=lambda x: -x[1]):
        W(f"| `{pkg}` | {total} | {PKG_ROLE.get(pkg, '—')} |")

    # ── External binaries ──
    W("\n## Внешние бинарные зависимости\n")
    W("Файлы, **использованные** в сборке, но **не созданные** в ней.\n")

    exes = q(g, """
        SELECT DISTINCT ?path WHERE {
            ?proc b:executable ?file . ?file b:abspath ?path .
            FILTER NOT EXISTS { ?any b:writes ?file }
        }
        ORDER BY ?path
    """)
    W(f"### Исполняемые файлы ({len(exes)})\n")
    for (path,) in exes:
        W(f"- `{path}`")

    syslibs = q(g, """
        SELECT DISTINCT ?path ?hash WHERE {
            ?proc b:reads ?file . ?file b:abspath ?path .
            OPTIONAL { ?file b:hash ?hash }
            FILTER NOT EXISTS { ?any b:writes ?file }
            FILTER(STRSTARTS(STR(?path),"/usr/lib") || STRSTARTS(STR(?path),"/lib"))
            FILTER(CONTAINS(STR(?path),".so"))
        }
        ORDER BY ?path
    """)
    W(f"\n### Системные .so библиотеки ({len(syslibs)})\n")
    W("| Библиотека | SHA1 (git-compatible) |")
    W("|-----------|----------------------|")
    for (path, hash_) in syslibs:
        h = str(hash_) if hash_ else '—'
        W(f"| `{str(path).split('/')[-1]}` | `{h}` |")

    # ── Produced libs ──
    lib_rows = q(g, """
        SELECT DISTINCT ?path ?hash WHERE {
            ?proc a b:process ; b:writes ?file . ?file b:abspath ?path .
            OPTIONAL { ?file b:hash ?hash }
            FILTER(CONTAINS(STR(?path),".so") || STRENDS(STR(?path),".a"))
            FILTER(!STRSTARTS(STR(?path),"/tmp"))
            FILTER(!CONTAINS(STR(?path),"TryCompile"))
        }
        ORDER BY ?path
    """)
    if lib_rows:
        W("\n## Собранные библиотеки\n")
        W("| Библиотека | SHA1 |")
        W("|-----------|------|")
        for (path, hash_) in lib_rows:
            h = str(hash_) if hash_ else '—'
            W(f"| `{str(path).split('/')[-1]}` | `{h}` |")

    # ── Package provenance (if enrich.py was run) ──
    pkg_check = q(g, "SELECT (COUNT(?f) AS ?n) WHERE { ?f b:dep_type ?t }")
    if pkg_check and int(pkg_check[0][0]) > 0:
        W("\n## Пакетные зависимости\n")
        W("*Данные добавлены `enrich.py` на основе RPM-базы контейнера.*\n")

        dep_rows = q(g, """
            SELECT ?dep_type (COUNT(DISTINCT ?file) AS ?n)
            WHERE { ?file b:dep_type ?dep_type }
            GROUP BY ?dep_type ORDER BY DESC(?n)
        """)
        W("### По типу зависимости\n")
        W("| Тип | Файлов |")
        W("|-----|--------|")
        for (dep_type, n) in dep_rows:
            W(f"| `{dep_type}` | {n} |")

        pkg_rows = q(g, """
            SELECT ?rpm_name (COUNT(DISTINCT ?file) AS ?n)
            WHERE { ?file b:rpm_name ?rpm_name }
            GROUP BY ?rpm_name ORDER BY DESC(?n)
        """)
        W("\n### Пакеты\n")
        W("| Пакет | Файлов |")
        W("|-------|--------|")
        for (name, n) in pkg_rows:
            W(f"| `{name}` | {n} |")

        dyn_rows = q(g, """
            SELECT DISTINCT ?path ?rpm_name WHERE {
                ?file b:abspath ?path ; b:dep_type "dynamic_lib" .
                OPTIONAL { ?file b:rpm_name ?rpm_name }
            } ORDER BY ?path
        """)
        if dyn_rows:
            W(f"\n### Динамические библиотеки ({len(dyn_rows)})\n")
            W("| Библиотека | Пакет |")
            W("|-----------|-------|")
            for (path, name) in dyn_rows:
                pkg = str(name) if name else "—"
                W(f"| `{str(path).split('/')[-1]}` | `{pkg}` |")

        arc_rows = q(g, """
            SELECT DISTINCT ?path ?rpm_name WHERE {
                ?file b:abspath ?path ; b:dep_type "static_archive" .
                OPTIONAL { ?file b:rpm_name ?rpm_name }
            } ORDER BY ?path
        """)
        if arc_rows:
            W(f"\n### Статические архивы ({len(arc_rows)})\n")
            W("| Архив | Пакет |")
            W("|-------|-------|")
            for (path, name) in arc_rows:
                pkg = str(name) if name else "—"
                W(f"| `{str(path).split('/')[-1]}` | `{pkg}` |")

    W("\n---\n")
    W(f"*Отчёт сгенерирован `build-report.py` на основе данных `build-recorder`*")
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

def main():
    parser = argparse.ArgumentParser(
        description="Анализ файла build-recorder (.out, RDF Turtle) через SPARQL.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file", help="Путь к .out файлу build-recorder")
    parser.add_argument(
        "--query", "-q",
        default="all",
        choices=["all"] + list(AVAILABLE) + ["report"],
        help="Запрос для выполнения (по умолчанию: all)",
    )
    parser.add_argument(
        "--report", "-r",
        nargs="?", const=True, metavar="OUTPUT.md",
        help="Сгенерировать Markdown-отчёт (опционально: путь к файлу)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Не выводить отчёт в консоль (только сохранить в файл)",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.exists():
        print(f"ERROR: файл не найден: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"Загрузка {path.name} ...", end=" ", flush=True)
    t0 = time.time()
    g = load_graph(path)
    print(f"{len(g)} троек за {time.time() - t0:.1f}с")

    if args.report is not None:
        md = generate_report(g, path)
        # Определяем путь для сохранения
        if args.report is True:
            out_path = path.with_suffix('.md')
        else:
            out_path = Path(args.report)
        out_path.write_text(md, encoding='utf-8')
        if not args.quiet:
            print(md)
        print(f"\n✓ Отчёт сохранён: {out_path}", file=sys.stderr)
        return

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

if __name__ == "__main__":
    main()
