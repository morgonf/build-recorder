# Отслеживание вендорированных зависимостей в C/C++ проектах

## Проблема

В C/C++ проектах широко распространена практика **вендоринга** — прямого копирования
исходного кода сторонних библиотек в репозиторий (`src/third_party/`, `vendor/`,
`external/` и т.д.). Типичный пример — civetweb:

| Путь | Компонент | Сложность обнаружения |
|---|---|---|
| `src/third_party/lfs.c` | LuaFileSystem 1.8.0 | Версия только в `#define` внутри файла |
| `src/third_party/sqlite3.c` | SQLite 3.x.y | `SQLITE_VERSION` в заголовке |
| `src/third_party/lua-5.3.6/` | Lua 5.3.6 | Версия в имени папки |
| `src/third_party/duktape-1.8.0/` | Duktape 1.8.0 | Версия в имени папки |
| `src/third_party/LuaXML_lib.c` | LuaXML | Нет явной версии |
| `src/third_party/lsqlite3.c` | lsqlite3 | Нет явной версии |

**Последствия**: стандартные сканеры уязвимостей не видят эти зависимости — они не
объявлены ни в `requirements.txt`, ни в `Cargo.toml`, ни в RPM-спеке. При публикации
CVE для SQLite или Lua ни `rpm -qi civetweb`, ни `trivy image` не предупредят об
уязвимости, встроенной в `libcivetweb.so`.

### Почему C/C++ сложнее всего

- Нет централизованного менеджера пакетов (как npm, pip, cargo)
- Зависимость может быть одним файлом без метаданных
- Одна версия библиотеки часто сопровождается патчами
- В репозитории могут лежать несколько версий одной библиотеки (все `lua-5.x.y/`
  в civetweb), но в сборку идёт только одна
- Бинарный анализ (`strings`) находит лишь то, что не оптимизировано прочь

---

## Ключевое преимущество build-recorder

Стандартные SCA-инструменты сканируют **весь исходный код** проекта.
build-recorder знает **какие именно файлы были реально прочитаны компилятором**:

```sparql
SELECT ?path WHERE {
    ?proc b:executable ?gcc . ?gcc b:abspath ?gcc_path .
    FILTER(CONTAINS(STR(?gcc_path), "gcc"))
    ?proc b:reads ?file . ?file b:abspath ?path ; b:dep_type "project_source" .
    FILTER(CONTAINS(STR(?path), "third_party"))
}
```

Это исключает мёртвый код: в civetweb лежат `lua-5.1.5`, `lua-5.2.4`, `lua-5.3.6`,
`lua-5.4.3`, `lua-5.5.0-beta` — но в сборку попадает ровно одна. build-recorder
точно знает какая.

---

## Ландшафт инструментов

### OSV determineversion API (Google)

Экспериментальный endpoint `POST /v1experimental/determineversion`. Принимает список
`(file_path, sha1_hash)` файлов из вендорированной директории, возвращает наиболее
вероятную библиотеку, версию и ближайший upstream-коммит через nearest-neighbor поиск
по всем известным коммитам OSS-Fuzz + NVD + 30+ источников.

**Ограничение**: ожидает plain SHA-1 (`sha1(content)`), а не git-format
(`sha1("blob SIZE\0" + content)`), который использует build-recorder.

### CVE Binary Tool (Intel / OSSF)

Сканирует скомпилированный бинарь через `strings`, имеет 350+ готовых checkers
включая sqlite, lua, openssl, libpng, expat. Работает без исходников. Запускается на
выходных `.so` и исполняемых файлах.

```bash
pip install cve-bin-tool
cve-bin-tool libcivetweb.so.1.16.0 --format json -o cvecheck.json
```

### OSV-Scanner (Google)

CLI-инструмент с поддержкой C/C++ vendored directories. Внутри использует тот же
determineversion API. Запускается на исходниках:

```bash
osv-scanner scan source --dir src/third_party/
```

### Syft + Grype (Anchore)

Генерирует SBOM в CycloneDX/SPDX, затем Grype сканирует на CVE. Для C/C++ vendored
кода возможности ограничены — нет поддержки version string extraction из произвольных
C-файлов.

### Сравнение

| Инструмент | Vendor dirs | Бинарный скан | SBOM output | CVE lookup | Офлайн |
|---|---|---|---|---|---|
| **`brec sbom`** (наш) | ✓ точно (только компилируемые) | — | CycloneDX | OSV API | Layer 1 |
| osv-scanner | ✓ (весь дир) | — | — | OSV | нет |
| cve-bin-tool | — | ✓ 350+ компонентов | CycloneDX | NVD | нет |
| Syft | частично | — | CycloneDX/SPDX | — | да |
| Grype | — | — | — | Grype DB | нет |

---

## Архитектура решения

```
build-recorder (.out)
       │
   brec enrich             ← пишет <build>.provenance.json рядом с трассой
       │
   brec sbom
    ├── Layer 1: path detection        (offline, всегда)
    │   ├── folder name pattern → version (lua-5.3.6 → Lua 5.3.6)
    │   └── known file triggers → component name
    │
    ├── Layer 2: version string extraction  (offline, если --source-dir)
    │   ├── #define LFS_VERSION "1.8.0"
    │   ├── #define SQLITE_VERSION "3.x.y"
    │   └── #define DUK_VERSION 10800  → 1.8.0
    │
    ├── Layer 3: OSV determineversion API   (online, если --source-dir)
    │   └── plain SHA-1 файлов → (repo, version, confidence)
    │
    ├── Layer 4: OSV CVE query              (online, если версия известна)
    │   └── /v1/query по name+version → список CVE
    │
    └── Output
        ├── sbom.json          (CycloneDX 1.6)
        └── sbom-report.md     (human-readable)
```

---

## Технические детали

### Layer 1 — Path-based detection

Паттерны vendor-директорий: `third_party`, `thirdparty`, `3rdparty`, `vendor`,
`external`, `extern`, `deps`, `contrib`, `bundled`, `embedded`.

Версия из имени папки:
```
lua-5.3.6/        → Lua 5.3.6
duktape-1.8.0/    → Duktape 1.8.0
sqlite-3.43.2/    → SQLite 3.43.2
```

### Layer 2 — Version string extraction

Для работы без исходников (только `.out`) извлечение невозможно — в RDF хранится
только hash. При наличии `--source-dir` скрипт читает файлы и ищет version defines:

```c
#define LFS_VERSION "1.8.0"           // luafilesystem
#define SQLITE_VERSION "3.43.2"       // sqlite
#define LUA_RELEASE "Lua 5.3.6"       // lua
#define DUK_VERSION 10800             // duktape → 1.8.0
```

### Layer 3 — OSV determineversion API

```
POST https://api.osv.dev/v1experimental/determineversion
Content-Type: application/json

{
  "name": "luafilesystem",
  "file_hashes": [
    {"file_path": "lfs.c", "hash": "<plain_sha1>"},
    {"file_path": "lfs.h", "hash": "<plain_sha1>"}
  ]
}
```

Ответ:
```json
{
  "matches": [
    {
      "score": 0.95,
      "repo_info": {
        "address": "https://github.com/lunarmodules/luafilesystem",
        "tag": "v1_8_0",
        "version": "1.8.0"
      }
    }
  ]
}
```

### Layer 4 — CVE query

```
POST https://api.osv.dev/v1/query
{"version": "1.8.0", "package": {"name": "luafilesystem", "ecosystem": "GitHub"}}
```

или по PURL:
```
{"package": {"purl": "pkg:github/lunarmodules/luafilesystem@1.8.0"}}
```

### CycloneDX SBOM format (1.6)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-30T19:00:00Z",
    "tools": [{"vendor": "build-recorder", "name": "brec sbom"}]
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "luafilesystem-1.8.0",
      "name": "LuaFileSystem",
      "version": "1.8.0",
      "purl": "pkg:github/lunarmodules/luafilesystem@1.8.0",
      "scope": "required",
      "evidence": {
        "identity": {
          "field": "version",
          "confidence": 1.0,
          "methods": [{"technique": "filename", "confidence": 1.0, "value": "lfs.c"}]
        }
      }
    }
  ],
  "vulnerabilities": [
    {
      "bom-ref": "CVE-2021-XXXXX",
      "id": "CVE-2021-XXXXX",
      "affects": [{"ref": "luafilesystem-1.8.0"}],
      "ratings": [{"severity": "high", "score": 7.5}]
    }
  ]
}
```

---

## Известные компоненты

База встроена в `brec sbom`. Покрывает типичный стек embedded C-проектов.

| Ключ | Дисплейное имя | Триггеры | OSV ecosystem |
|---|---|---|---|
| `luafilesystem` | LuaFileSystem | `lfs.c`, `lfs.h` | GitHub / lunarmodules |
| `sqlite` | SQLite | `sqlite3.c`, `sqlite3.h` | — (OSS-Fuzz) |
| `lua` | Lua | `lua.h`, `lualib.h` | GitHub / lua |
| `duktape` | Duktape | `duktape.c`, `duk_config.h` | GitHub / svaarala |
| `lsqlite3` | lsqlite3 | `lsqlite3.c` | GitHub / LuaDist |
| `luaxml` | LuaXML | `LuaXML_lib.c` | GitHub / LuaDist |
| `expat` | Expat | `expat.h`, `xmlparse.c` | SourceForge |
| `zlib` | zlib | `zlib.h`, `inflate.c` | GitHub / madler |
| `libpng` | libpng | `png.h`, `png.c` | SourceForge |
| `libjpeg` | libjpeg | `jpeglib.h`, `jdatadst.c` | — |
| `openssl` | OpenSSL | `openssl/ssl.h` | GitHub / openssl |
| `mbedtls` | Mbed TLS | `mbedtls/ssl.h` | GitHub / Mbed-TLS |
| `mongoose` | Mongoose | `mongoose.c`, `mongoose.h` | GitHub / cesanta |
| `cJSON` | cJSON | `cJSON.c`, `cJSON.h` | GitHub / DaveGamble |
| `jsmn` | jsmn | `jsmn.c`, `jsmn.h` | GitHub / zserge |

---

## Pipeline использования

```bash
# 1. Собрать пакет с записью сборки
docker run --rm \
  -e SRPM=/srpms/pkg.src.rpm \
  -v /srpms:/srpms:ro \
  -v /output:/output \
  build-recorder:latest

# 2. Обогатить RPM-пакетами
python3 -m brec enrich /output/pkg-build.out /output/rpm-dump.txt

# 3. Создать SBOM и CVE-отчёт (offline: только path detection)
python3 -m brec sbom /output/pkg-build.out -o /output/sbom.json

# 4. С извлечением версий из исходников и OSV API (если доступны исходники)
python3 -m brec sbom /output/pkg-build.out \
    --source-dir /path/to/src \
    --osv-api \
    -o /output/sbom.json

# 5. Дополнительно: CVE Binary Tool на скомпилированном бинаре
pip install cve-bin-tool
cve-bin-tool /output/build/libpkg.so --format json -o /output/cve-binary.json

# 6. Генерация отчёта
python3 -m brec report /output/pkg-build.out --query packages
```

---

## Ограничения

| Ситуация | Проблема | Workaround |
|---|---|---|
| Версия не указана нигде | Компонент идентифицирован, версия unknown | Запустить `--osv-api` + `--source-dir` |
| git-format хеши build-recorder ≠ plain SHA-1 для OSV | determineversion API не найдёт совпадений | При `--source-dir` пересчитываем plain SHA-1 |
| Компонент не в базе `KNOWN_COMPONENTS` | Не распознан | Добавить в базу или использовать osv-scanner отдельно |
| Изменённый upstream (с патчами) | OSV может дать неверную версию | Confidence < 0.8 → метка "modified" |
| CVE для embedded компонента не в OSV | Не найден | Crosscheck с cve-bin-tool |

---

## Файлы

| Файл | Назначение |
|---|---|
| `brec/commands/sbom.py` | Реализация pipeline |
| `brec/commands/enrich.py` | RPM-провенанс в sidecar (предшествующий шаг) |
| `brec/commands/report.py` | SPARQL-анализ + `--query packages` |
| `doc/sbom-vendored-deps.md` | Этот документ |
| `doc/build-recorder-schema.ttl` | RDF-схема с `b:rpm_package`, `b:dep_type` |
