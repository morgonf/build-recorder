# Универсальная идентификация провенанса зависимостей — архитектура и ТЗ

> Статус: проектное задание для реализации.
> Целевой исполнитель реализации: модель Sonnet, по фазам (см. §11).
> Документ описывает **что** строить и **с какими интерфейсами**, оставляя
> реализацию деталей исполнителю. Все имена предикатов RDF, полей и файлов
> привязаны к текущему коду (`src/tracer.c`, `enrich.py`, `verify-build.py`,
> `sbom.py`, `doc/build-recorder-schema.ttl`).

---

## 0. Контекст, цели, не-цели

### 0.1 Проблема

build-recorder перехватывает сборку через `ptrace` и пишет RDF-граф (`.out`,
Turtle): какие процессы какие файлы читали/писали, с git-blob SHA-1 каждого
файла. На этом графе нужно решить **две независимые задачи**:

1. **Привязка файла к пакету** — откуда в сборку попал каждый прочитанный файл
   (системный пакет ОС? объявленная зависимость? вручную встроенный код?).
2. **Привязка к версии upstream-проекта** — для вручную встроенного
   (вендорированного) и заимствованного кода определить, какой именно
   версии/коммиту какого upstream-проекта он соответствует, чтобы в дальнейшем
   отслеживать уязвимости (CVE).

### 0.2 Принципиальное требование: универсальность

Решение **не должно** опираться на курируемую вручную базу известных
компонентов как на ядро. Текущие `KNOWN_COMPONENTS` (`sbom.py`) и `UPSTREAM_DB`
(`verify-build.py`) — это анти-паттерн для универсального инструмента: они знают
только то, что в них внесли руками.

Универсальность раскладывается на две оси:

- **Языки программирования** — механизм идентификации не зависит от языка на
  уровне хеширования содержимого; парсеры манифестов добавляются по мере
  необходимости как плагины.
- **Дистрибутивы / системы пакетирования** — атрибуция к пакету ОС вынесена за
  абстракцию (`rpm` → `dpkg` → `apk` → …), добавляемую инкрементально.

### 0.3 Цели

- G1. Единая модель графа сборки, переиспользуемая всеми анализаторами.
- G2. Классификация каждого прочитанного файла по классу провенанса —
  language- и distro-agnostic в ядре, с расширяемыми бэкендами.
- G3. Идентификация вендорированного/заимствованного кода до
  `(проект, версия/коммит)` **без курируемой базы**, через глобальные
  индексы исходного кода по содержимому.
- G4. Сопоставление идентифицированных компонентов с уязвимостями (OSV/NVD).
- G5. Воспроизводимые, офлайн-способные отчёты (CycloneDX 1.6 + human-readable),
  с явной маркировкой источника и уверенности каждого утверждения.

### 0.4 Не-цели (в этой итерации)

- N1. Реализация собственного краулера GitHub-масштаба. Используем готовые
  индексы (Software Heritage, OSV).
- N2. Точная идентификация сильно изменённого вендоринга и заимствований-сниппетов
  в v1 — это отдельные поздние фазы (§11, фазы 5–6); ядро должно лишь оставлять
  для них точку расширения.
- N3. Поддержка не-Linux сборок.

---

## 1. Концептуальная модель: конвейер из 4 стадий

```
┌──────────┐   ┌────────────┐   ┌────────────┐   ┌──────────┐
│ CAPTURE  │ → │  CLASSIFY  │ → │  IDENTIFY  │ → │ MAP→CVE  │
└──────────┘   └────────────┘   └────────────┘   └──────────┘
 ptrace,        провенанс         содержимое →     версия →
 git-blob       каждого файла     (проект,         уязвимости
 SHA-1          (класс)           версия/коммит)
 (есть)         (обобщить)        (новое, ядро)    (новое)
```

| Стадия | Вход | Выход | Зависит от языка? | Зависит от дистрибутива? |
|---|---|---|---|---|
| CAPTURE | команда сборки | `.out` (RDF Turtle) | нет | нет |
| CLASSIFY | `.out` | граф с `dep_class` на каждом файле | частично (манифесты) | да (пакетный бэкенд) |
| IDENTIFY | файлы класса «кандидат» | список `Match` | нет (хеш) | нет |
| MAP→CVE | идентифицированные компоненты | список `Vulnerability` | нет | нет |

Ключевой инвариант: **каждая стадия читает и пишет версионированное
промежуточное представление (IR)**, сериализуемое в JSON. Стадии запускаются
независимо и тестируются на фикстурах без запуска предыдущих.

---

## 2. Целевая модульная архитектура

Текущее состояние: `enrich.py`, `sbom.py`, `verify-build.py`, `build-report.py`
— четыре скрипта, каждый **самостоятельно** парсит Turtle и держит свои
структуры. Это дублирование и источник расхождений (см. две разные базы
компонентов).

Целевое состояние — Python-пакет `brec/` с разделением на слои:

```
brec/
├── model.py            # G1: единый парсер .out → BuildGraph (IR)
├── ir.py               # dataclasses IR + (de)сериализация JSON
├── classify.py         # G2: роли процессов + dep_class файлов
│
├── provenance/         # G2: атрибуция к пакету ОС (плагины)
│   ├── base.py         #   ProvenanceBackend (Protocol)
│   ├── rpm.py          #   текущий rpm-dump подход
│   ├── dpkg.py         #   (фаза 4+)
│   └── registry.py     #   автоопределение доступных бэкендов
│
├── manifests/          # G2: объявленные зависимости по языкам (плагины)
│   ├── base.py         #   ManifestParser (Protocol)
│   ├── python.py       #   requirements.txt / poetry.lock / *.dist-info
│   ├── node.py         #   package-lock.json / yarn.lock
│   ├── go.py           #   go.mod / go.sum
│   └── rust.py         #   Cargo.lock
│
├── identify/           # G3: идентификация по содержимому (плагины)
│   ├── base.py         #   IdentificationBackend (Protocol)
│   ├── swh.py          #   Software Heritage known API (git-blob native)
│   ├── osv.py          #   OSV determineversion (пересчёт хеша)
│   ├── gitwalk.py      #   clone + commit-walk → точный коммит (из verify-build)
│   ├── cache.py        #   локальный кэш/оверрайды (бывш. UPSTREAM_DB, демотирован)
│   ├── fuzzy.py        #   (фаза 5) TLSH/MinHash для изменённых файлов
│   └── resolver.py     #   оркестрация бэкендов, приоритет, слияние, деградация
│
├── vuln/               # G4
│   └── osv_query.py    #   OSV /v1/query по purl/версии
│
├── report/             # G5
│   ├── cyclonedx.py    #   CycloneDX 1.6 SBOM
│   └── markdown.py     #   human-readable отчёт
│
└── cli.py              # единый entrypoint `brec`
```

Существующие скрипты сохраняются как тонкие обёртки над `brec/` ради обратной
совместимости команд из документации, либо заменяются подкомандами `brec`
(решается в фазе 0; см. §11).

---

## 3. Промежуточное представление (IR) и модель данных

Файл: `brec/ir.py`. Все структуры — `@dataclass`, с методами
`to_dict()/from_dict()` и общим конвертом:

```python
@dataclass
class IRDocument:
    schema_version: int          # = 1; бампается при несовместимых изменениях
    stage: str                   # "graph" | "classified" | "identified" | "vuln"
    source_out: str              # путь исходного .out (для трассируемости)
    payload: dict                # содержимое стадии
```

### 3.1 Граф сборки (выход CAPTURE-парсинга)

```python
@dataclass
class FileNode:
    uri: str                     # узел RDF (напр. ":f1639")
    abspath: str
    name: str
    size: int
    git_blob_sha1: str           # из b:hash — git-compatible blob SHA-1

@dataclass
class ProcessNode:
    uri: str
    pid: int
    cmd: str
    executable: Optional[str]    # uri FileNode
    start: Optional[str]
    end: Optional[str]
    reads:  list[str]            # uri FileNode
    writes: list[str]
    execs:  list[str]            # uri ProcessNode
    role: Optional[str] = None   # заполняется на CLASSIFY

@dataclass
class BuildGraph:
    files: dict[str, FileNode]
    procs: dict[str, ProcessNode]
```

`role` (из существующей логики `verify-build.py`, поле `self.role`):
`compiler | linker | assembler | archiver | other`.

### 3.2 Классифицированный файл (выход CLASSIFY)

```python
class DepClass(str, Enum):
    SYSTEM_STATIC  = "static"    # .h/.a, прочитан компилятором, в пакете ОС
    SYSTEM_DYNAMIC = "dynamic"   # .so, прочитан линкером, в пакете ОС
    DECLARED       = "declared"  # объявленная зависимость (манифест/lockfile)
    VENDORED       = "vendored"  # в дереве проекта, нет пакетного провенанса
    PROJECT        = "project"   # оригинальный код проекта
    TOOLCHAIN_TEMP = "temp"      # промежуточные/временные файлы тулчейна
    UNKNOWN        = "unknown"

@dataclass
class ClassifiedFile:
    file: FileNode
    dep_class: DepClass
    package: Optional["PackageRef"] = None    # если SYSTEM_*
    vendor_dir: Optional[str] = None          # вычисляется на CLASSIFY (не из RDF)
    read_by_roles: set[str] = field(default_factory=set)
```

**Связь с существующим `b:dep_type`.** Текущий enrich.py пишет более дробный
enum: `static_header | static_archive | dynamic_lib | build_tool |
project_source | system_runtime | unknown` (см. `enrich.py:classify_dep_type`
и `doc/build-recorder-schema.ttl`). А `verify-build.py` дополнительно вычисляет
`role` файла (`header | source | static_archive | dynamic_lib`) по тому, какой
процесс его читал. `DepClass` — это **более грубая прикладная классификация**
поверх них; задача T1.2 должна задать явный маппинг старых значений в `DepClass`
(напр. `static_header|static_archive → SYSTEM_STATIC`, `dynamic_lib →
SYSTEM_DYNAMIC`, `project_source → PROJECT|VENDORED` в зависимости от vendor-пути).
Категория `VENDORED` сейчас **отдельно не хранится** — она выводится из
`project_source` + отсутствия пакета + vendor-сегмента в пути; это надо
реализовать в CLASSIFY, а не ожидать готового предиката.

### 3.3 Пакетная ссылка

```python
@dataclass
class PackageRef:
    backend: str                 # "rpm" | "dpkg" | ...
    name: str
    version: str                 # NEVRA для rpm, deb-version для dpkg
    arch: Optional[str]
    source_package: Optional[str]
    purl: Optional[str]          # pkg:rpm/... | pkg:deb/...
```

### 3.4 Идентифицированный компонент (выход IDENTIFY)

```python
@dataclass
class Match:
    backend: str                 # "swh" | "osv" | "gitwalk" | "cache" | "fuzzy"
    repo_url: Optional[str]
    project: Optional[str]       # имя/координата проекта
    version: Optional[str]       # тег/релиз, если определён
    commit: Optional[str]        # точный коммит, если определён
    nearest_tag: Optional[str]
    commits_past_tag: int = 0
    confidence: float = 0.0      # 0..1
    method: str = "exact"        # exact | manifest | fuzzy | snippet
    files_matched: int = 0
    files_total: int = 0

@dataclass
class IdentifiedComponent:
    key: str                     # vendor_dir или координата манифеста
    files: list[str]             # uri FileNode
    candidates: list[Match]      # отсортированы по confidence
    best: Optional[Match]
    purl: Optional[str]          # каноничный PURL для запроса CVE
```

### 3.5 Уязвимость (выход MAP→CVE)

```python
@dataclass
class Vulnerability:
    id: str                      # CVE/GHSA/OSV id
    component_key: str
    severity: str                # none|low|medium|high|critical
    cvss_score: Optional[float]
    affected_range: Optional[str]
    fixed_version: Optional[str]
    source: str                  # "osv" | "nvd"
    url: Optional[str]
```

---

## 4. Расширение RDF-схемы (`doc/build-recorder-schema.ttl`)

Текущие enrichment-предикаты (по `doc/build-recorder-schema.ttl` и `enrich.py`):
`b:rpm_package` (NEVRA), `b:rpm_name` (имя без версии), `b:dep_type`
(значения: `static_header | static_archive | dynamic_lib | build_tool |
project_source | system_runtime | unknown`). Предиката `b:vendor_dir` **нет** —
вендоринг сейчас не материализуется в RDF. Добавить (обобщение от rpm к
произвольному провенансу + результаты идентификации):

```turtle
# Обобщённый провенанс пакета (вместо rpm-специфичного)
b:pkg_backend a rdf:Property .   # "rpm" | "dpkg" | ...
b:pkg_name    a rdf:Property .   # имя пакета
b:pkg_version a rdf:Property .   # версия (NEVRA/deb-version)
b:purl        a rdf:Property .   # Package URL

# Результаты идентификации вендоринга (IDENTIFY)
b:identified_project a rdf:Property .
b:identified_version a rdf:Property .
b:identified_commit  a rdf:Property .
b:identify_method    a rdf:Property .  # exact|manifest|fuzzy|snippet
b:identify_confidence a rdf:Property . # xsd:decimal 0..1
b:identify_source    a rdf:Property .  # swh|osv|gitwalk|cache
```

`b:rpm_name`/`b:rpm_package` сохраняются как deprecated-алиасы для обратной
совместимости с уже записанными `.out` (фаза 0, T0.4, добавляет миграцию
чтения: старые предикаты → `b:pkg_*`).

---

## 5. Интерфейсы расширяемости (это и есть «универсальность»)

### 5.1 ProvenanceBackend (`brec/provenance/base.py`)

```python
class ProvenanceBackend(Protocol):
    name: str
    def available(self) -> bool:
        """Применим ли в текущем окружении (есть rpm/dpkg db и т.п.)."""
    def build_index(self, env_dump: Path) -> None:
        """Подготовить индекс path|hash → пакет (напр. из rpm-dump.txt)."""
    def lookup(self, abspath: str, git_hash: str) -> Optional[PackageRef]:
        """Вернуть пакет-владелец файла или None."""
```

`registry.py`: `detect_backends() -> list[ProvenanceBackend]` —
автоопределение по окружению; CLI-флаг `--provenance rpm,dpkg` для явного
выбора. **Критично:** ядро не импортирует `rpm` напрямую — только через этот
интерфейс. Так дистрибутивы добавляются без правки CLASSIFY.

Нюанс канонизации путей (уже известная проблема): `/lib64`↔`/usr/lib64`
симлинки — индекс должен хранить оба варианта (как в текущем `enrich.py`).

### 5.2 ManifestParser (`brec/manifests/base.py`)

```python
class ManifestParser(Protocol):
    language: str                # "python" | "node" | "go" | "rust"
    manifest_globs: list[str]    # какие файлы это
    def parse(self, files_read: list[FileNode], source_dir: Path
              ) -> list["DeclaredDep"]:
        """Из реально прочитанных при сборке манифестов извлечь объявленные
        зависимости (имя, версия, экосистема, purl)."""
```

Важно: используем **только манифесты, реально прочитанные в графе** (build-recorder
видит, какой `Cargo.lock`/`go.sum` открывался) — это исключает мёртвые/неиспользованные.

### 5.3 IdentificationBackend (`brec/identify/base.py`)

```python
@dataclass
class FileHash:
    rel_path: str                # путь внутри vendor_dir
    git_blob_sha1: str           # уже есть в .out
    plain_sha1: Optional[str] = None   # лениво, для OSV
    other: dict[str, str] = field(default_factory=dict)

class IdentificationBackend(Protocol):
    name: str
    requires_network: bool
    def identify(self, files: list[FileHash]) -> list[Match]:
        ...
```

`resolver.py` оркестрирует:
1. Сортирует бэкенды по приоритету: `cache` (офлайн) → `swh` → `osv` → `gitwalk`.
2. Если офлайн (`--offline` или нет сети) — пропускает `requires_network`.
3. Сливает `Match` из разных бэкендов по `repo_url`, берёт максимум `confidence`.
4. `gitwalk` вызывается **с repo_url, полученным от swh/osv** (а не из
   курируемой базы), для уточнения точного коммита и ближайшего тега.
5. Всегда возвращает минимум Tier-0 результат: даже при нуле совпадений —
   `IdentifiedComponent` с файлами и их git-blob хешами и `best=None`.

---

## 6. Стадия CLASSIFY (детально)

Вход: `BuildGraph`. Выход: `list[ClassifiedFile]`.

Алгоритм (обобщение существующей логики `verify-build.py`):

1. **Роли процессов.** По `executable`/`cmd` пометить процессы:
   `compiler` (cc1/cc1plus/gcc/g++/clang/rustc/…), `linker` (ld/collect2/lld),
   `assembler` (as), `archiver` (ar). Таблица сигнатур — расширяемая, но НЕ
   привязана к конкретному пакету.
2. **Для каждого прочитанного файла** определить `dep_class`:
   - читал `linker` и это `.so*` → `SYSTEM_DYNAMIC` (если есть пакет) иначе кандидат.
   - читал `compiler` и это `.h`/`.a` → `SYSTEM_STATIC` (если есть пакет).
   - путь содержит vendor-сегмент (`VENDOR_DIRS`: `third_party`, `vendor`,
     `deps`, `external`, `contrib`, `bundled`, …) и нет пакета → `VENDORED`,
     проставить `vendor_dir`.
   - файл объявлен в распарсенном манифесте → `DECLARED`.
   - в дереве проекта, читал компилятор, нет пакета и не vendor → `PROJECT`.
   - временные файлы тулчейна (`/tmp/cc*`, `*.o` промежуточные) → `TOOLCHAIN_TEMP`.
   - иначе → `UNKNOWN`.
3. Провенанс (`PackageRef`) берётся **только** через `ProvenanceBackend.lookup`.

Группировка `VENDORED` по `vendor_dir` даёт единицы для стадии IDENTIFY.

---

## 7. Стадия IDENTIFY (детально) — ядро универсальности

Вход: единицы `VENDORED` (и при наличии — `UNKNOWN` в дереве проекта).
Выход: `list[IdentifiedComponent]`.

### 7.1 Software Heritage (`identify/swh.py`) — первичный бэкенд

- SWH архивирует GitHub/GitLab/PyPI/npm/Debian и индексирует контент по
  `sha1_git` = **тот же git-blob хеш, что уже в `.out`**. Пересчёт не нужен.
- `known` API: отправить список SWHID `swh:1:cnt:<git_blob_sha1>`, получить,
  какие известны. Существование файла в архиве → сильный сигнал «внешний код».
- **Ограничение:** `known` даёт факт наличия, не версию. Для версии —
  резолвинг origins/snapshots (доп. запросы) либо передача repo_url в `gitwalk`.
- Реализовать с кэшированием ответов на диск и батч-запросами.

### 7.2 OSV determineversion (`identify/osv.py`) — разрешение версии

- `POST /v1experimental/determineversion`, отдаёт `(repo, версия, score)`.
- Ожидает **свой** формат хеша (не git-blob) → требуется пересчёт из
  `--source-dir` (как уже частично сделано в `sbom.py`); при отсутствии
  исходников бэкенд недоступен. Зафиксировать это в `requires_network=True` и
  в предусловии «нужен source-dir».

### 7.3 gitwalk (`identify/gitwalk.py`) — точный коммит

- Обобщение существующего кода `verify-build.py` (`_ensure_clone`, `_tag_map`,
  commit-walk, `UpstreamMatch`). Отличие: `repo_url` приходит **из resolver**
  (от swh/osv), а не из `UPSTREAM_DB`.
- Клонирует bare-репо в кэш (`~/.cache/build-recorder/repos/`), идёт по истории,
  сравнивает git-blob хеши `key_files`, находит коммит с максимумом совпадений,
  определяет ближайший тег и `commits_past_tag`.
- Сохранить существующие поля `UpstreamMatch` → маппинг в `Match`.

### 7.4 cache / overrides (`identify/cache.py`) — демотированная база

- Бывшие `UPSTREAM_DB` + `KNOWN_COMPONENTS` переезжают сюда как **необязательный**
  локальный YAML-кэш `data/components.d/*.yaml` (файл-на-компонент).
- Назначение: (а) офлайн-фолбэк; (б) оверрайд, когда swh/osv ошибаются;
  (в) ускорение (пропустить обнаружение repo_url).
- Схема записи (унифицирует обе старые базы):
  ```yaml
  key: wslay
  upstream: { url: https://github.com/tatsuhiro-t/wslay.git, max_commits: 300 }
  key_files: [lib/wslay_event.c, lib/wslay_frame.c, ...]
  purl: { type: github, ns: tatsuhiro-t, name: wslay }
  ```
- Загрузчик с приоритетом: встроенный `data/` → `~/.config/build-recorder/` →
  `./.build-recorder/` → `--components-db`. Валидация через `jsonschema`.
- **Это НЕ ядро.** Пустой кэш = инструмент по-прежнему универсален через swh/osv.

### 7.5 fuzzy (`identify/fuzzy.py`) — фаза 5, только точка расширения в v1

- Для изменённого вендоринга точный хеш не сработает. Интерфейс
  `IdentificationBackend` уже это покрывает; реализация — позже (TLSH/MinHash,
  function-level fingerprints). В v1: заглушка, возвращающая `[]`.

---

## 8. Стадия MAP→CVE (`vuln/osv_query.py`)

- Вход: `IdentifiedComponent` с `purl` или `(project, version)`.
- `POST https://api.osv.dev/v1/query` по purl или name+version+ecosystem.
- Выход: `list[Vulnerability]`, прикреплённый к компоненту.
- Деградация: нет версии → пометить компонент «версия не определена, CVE-запрос
  пропущен»; не выдумывать.

---

## 9. Отчёты (`report/`)

- `cyclonedx.py` — CycloneDX 1.6 (сохранить текущий формат `sbom.py`), с полями
  `evidence.identity.methods` (technique: `hash-comparison`/`filename`/`manifest`,
  confidence из `Match`). Включить vulnerabilities из стадии MAP→CVE.
- `markdown.py` — human-readable; для каждого компонента: класс, провенанс,
  best-match (репо/версия/коммит/уверенность/источник), CVE.
- **Требование честности:** каждое утверждение помечено источником и
  уверенностью; «точно» только при exact-hash 100%. Пост-релизные снимки
  помечать как «снимок, +N коммитов после тега» (как сейчас в `verify-build.py`).

---

## 10. CLI (`brec/cli.py`)

```
brec analyze BUILD.out [опции]
  --source-dir DIR          исходники проекта (для OSV/манифестов)
  --provenance rpm[,dpkg]   бэкенды провенанса (по умолч. автоопределение)
  --identify swh,osv,gitwalk,cache   бэкенды идентификации (приоритет слева)
  --offline                 только офлайн-бэкенды (cache, gitwalk-из-кэша)
  --components-db PATH       доп. локальный кэш компонентов
  --emit graph|classified|identified|vuln   до какой стадии и что вывести (IR JSON)
  --sbom OUT.json           CycloneDX
  --report OUT.md           markdown
  --cache-dir DIR           кэш клонов/ответов API
```

Подкоманды для отладки стадий: `brec graph`, `brec classify`, `brec identify`,
`brec vuln` — каждая принимает IR предыдущей стадии (для тестируемости).

---

## 11. Фазы реализации и задачи для Sonnet

Каждая фаза независимо поставляема и тестируема. Формат задачи: **цель → файлы →
интерфейс → критерий приёмки**. Sonnet реализует по одной задаче за раз.

### Фаза 0 — Фундамент (рефакторинг, без новых фич)

> Цель: убрать дублирование парсинга, ввести IR. Поведение существующих
> скриптов не меняется (behavior-preserving).

- **T0.1** `brec/ir.py`: dataclasses из §3 + (де)сериализация JSON + `schema_version`.
  Приёмка: round-trip `to_dict→from_dict` идентичен; unit-тесты.
- **T0.2** `brec/model.py`: единый парсер `.out` (Turtle) → `BuildGraph`.
  Приёмка: на фикстуре `examples/`-сборки число процессов/файлов совпадает с
  тем, что сейчас выдаёт `verify-build.py`.
- **T0.3** Перевести `sbom.py` и `verify-build.py` на `brec/model.py` (удалить
  их собственные парсеры). Приёмка: вывод на civetweb/aria2 `.out` побайтово
  совпадает с до-рефакторингом (golden-тест).
- **T0.4** Миграция чтения старых предикатов (`b:rpm_name`→`b:pkg_name` и т.д.).

### Фаза 1 — Абстракция провенанса

- **T1.1** `brec/provenance/base.py` + `rpm.py` (вынести логику `enrich.py`,
  включая канонизацию `/lib64`↔`/usr/lib64`).
- **T1.2** `brec/classify.py`: роли процессов + `dep_class` (§6), через
  `ProvenanceBackend`. Приёмка: на civetweb классы static/dynamic/project/vendored
  совпадают с текущим выводом `verify-build.py`.
- **T1.3** `registry.py` + `--provenance` + автоопределение.

### Фаза 2 — Универсальная идентификация (exact) ← главный приоритет

- **T2.1** `brec/identify/base.py` + `resolver.py` (приоритет, слияние, офлайн).
- **T2.2** `identify/swh.py`: SWH `known` по git-blob, кэш ответов, батчи.
- **T2.3** `identify/gitwalk.py`: вынести commit-walk из `verify-build.py`,
  принимать `repo_url` от resolver.
- **T2.4** `identify/cache.py` + дамп старых `UPSTREAM_DB`/`KNOWN_COMPONENTS` в
  `data/components.d/*.yaml` + jsonschema.
- **T2.5** `identify/osv.py`: determineversion (требует `--source-dir`).
- **Критерий приёмки фазы (интеграционный):** на `.out` сборки aria2 **без любой
  записи в кэше** конвейер определяет вендоринг `deps/wslay` как снимок коммита
  `0e7d106ff89a` (2022-08-25), `nearest_tag=release-1.1.1`, `commits_past_tag=28`
  — воспроизводя результат из статьи `doc/article-build-provenance.md`, но через
  swh/osv-обнаружение, а не через `UPSTREAM_DB`.

### Фаза 3 — Сопоставление с уязвимостями

- **T3.1** `vuln/osv_query.py` + интеграция в IR и отчёты.
  Приёмка: для компонента с известной версией возвращается непустой список CVE
  (на известном уязвимом фикстуре), с корректной деградацией при unknown-версии.

### Фаза 4 — Языки и дистрибутивы (инкрементально)

- **T4.x** `manifests/python.py|node.py|go.py|rust.py` — по одному, каждый с
  фикстурой реального проекта. `dep_class=DECLARED`.
- **T4.y** `provenance/dpkg.py` — на Debian-фикстуре.

### Фаза 5 — Изменённый вендоринг (fuzzy)

- **T5.1** `identify/fuzzy.py`: TLSH/MinHash для файлов с частичным совпадением;
  `method="fuzzy"`, confidence < 1.0. Приёмка: пропатченный вендоринг
  (искусственная фикстура) идентифицируется с confidence в заданном диапазоне.

### Фаза 6 — Заимствования-сниппеты

- **T6.1** Sub-file clone detection (winnowing/Moss-фингерпринты), `method="snippet"`.
  Приёмка: скопированная функция из известного проекта детектируется в Python-фикстуре.

---

## 12. Тестирование и критерии приёмки

- **Юнит-тесты** на каждый модуль; бэкенды с сетью тестируются на **записанных
  ответах** (VCR-стиль) → детерминированно и офлайн в CI.
- **Golden-фикстуры:** маленькие `.out` (из `examples/`) + крупные
  интеграционные (civetweb, aria2) с известными ответами:
  - civetweb: vendored `src/third_party/` = sqlite3.c, lfs.c, lsqlite3.c,
    LuaXML_lib.c (нет RPM-провенанса).
  - aria2: vendored `deps/wslay` = коммит `0e7d106ff89a`, +28 после `release-1.1.1`.
- **Контракт-тесты** на интерфейсы Protocol: новый бэкенд проходит общий набор.
- **Критерий «универсальности» (регрессионный):** удаление всего
  `data/components.d/` НЕ ломает идентификацию aria2/civetweb при наличии сети
  (доказательство, что курируемая база — не ядро).

---

## 13. Риски и ограничения (честно)

| Риск | Влияние | Митигиция |
|---|---|---|
| SWH `known` даёт наличие, не версию | неполная идентификация | резолвинг origins или передача repo в gitwalk |
| OSV determineversion экспериментален, хеш-формат ≠ git-blob | пробелы покрытия, нужен source-dir | первичный — swh (git-blob native); osv опционален |
| Изменённый вендоринг ломает exact-hash (частый кейс) | заниженное покрытие в v1 | фаза 5 (fuzzy); в отчёте честно маркировать «exact-only» |
| Сниппет-заимствования (Python) — sub-file | не покрыто в v1 | фаза 6; не обещать раньше |
| Отправка хешей в внешние API раскрывает, что собирается | приватность | `--offline`; локальный кэш; хеши менее чувствительны, чем контент |
| Кросс-дистрибутивный провенанс требует доступной БД пакетов в окружении сборки | ограничение CAPTURE-среды | бэкенд `available()` + явная диагностика |
| Сетевые лимиты/недоступность | флапающие прогоны | кэш ответов на диск, ретраи, деградация в офлайн |

---

## 14. Совместимость и зависимости

- Python 3.11+ (используются современные аннотации, как в текущих скриптах).
- Новые внешние: `PyYAML`, `jsonschema` (кэш компонентов); `requests`/`urllib`
  (API). `rdflib` — опционально (текущие скрипты парсят плоский Turtle вручную;
  `brec/model.py` может сохранить тот же подход ради скорости).
- Обратная совместимость: команды из `doc/sbom-vendored-deps.md` продолжают
  работать (обёртки) либо документируется миграция на `brec`.
- Лицензия: LGPL-2.1-or-later (как у проекта).

---

## Приложение A. Соответствие старого кода новым модулям

| Сейчас | Куда переезжает |
|---|---|
| `enrich.py` (RPM-атрибуция) | `brec/provenance/rpm.py` + `brec/classify.py` |
| `sbom.py` парсер | `brec/model.py` |
| `sbom.py` `KNOWN_COMPONENTS` | `brec/components.py` (сделано; стадия `identify` снята) |
| `sbom.py` CycloneDX | `brec/report/cyclonedx.py` |
| `sbom.py` OSV-слои | `brec/identify/osv.py` + `brec/vuln/osv_query.py` |
| `verify-build.py` парсер | `brec/model.py` |
| `verify-build.py` классификация | `brec/classify.py` |
| `verify-build.py` `UPSTREAM_DB` | `brec/components.py`, слит с `KNOWN_COMPONENTS` (сделано) |
| `verify-build.py` commit-walk | `brec/identify/gitwalk.py` |
| `build-report.py` SPARQL | поверх `brec/model.py` (или сохранить) |
