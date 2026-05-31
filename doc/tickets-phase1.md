# Фаза 1 — тикеты для реализации (Sonnet)

> Родительский документ: `doc/architecture-universal-provenance.md` (§5.1, §6, §11 фаза 1).
> Предусловие: завершена фаза 0 (`doc/tickets-phase0.md`) — есть `brec/ir.py`,
> `brec/model.py`, `sbom.py`/`verify-build.py` уже читают граф через `brec.model`.
>
> Цель фазы: вынести атрибуцию к пакету ОС за абстракцию (`ProvenanceBackend`),
> вынести классификацию файлов (`brec/classify.py`) и перевести на них
> `enrich.py` и классификационную логику `verify-build.py` — **без изменения
> наблюдаемого вывода** (behavior-preserving). После фазы добавление нового
> дистрибутива = новый backend, без правок ядра.
>
> **Порядок строгий:** T1.1 → T1.2 → T1.3 → T1.4.
>
> **Общие правила для исполнителя:**
> - Python 3.11+, без тяжёлых зависимостей, парсер не трогаем (он из фазы 0).
> - Ядро (`classify.py`, `cli.py`) **не импортирует `rpm`/distro-специфику
>   напрямую** — только через `ProvenanceBackend`. Это и есть критерий
>   универсальности фазы.
> - Все «магические» множества имён (компиляторы, линкеры, vendor-директории)
>   берутся из существующего кода (ссылки в тикетах), а не выдумываются.
> - Каждый тикет завершается зелёными тестами и сохранением вывода старых команд.

---

## T1.1 — Абстракция провенанса: `brec/provenance/base.py` + `rpm.py`

**Зависит от:** фаза 0 (T0.2, T0.4)
**Размер:** M

### Контекст
Сейчас атрибуция к пакету зашита в `enrich.py`: `load_rpm_dump()` строит
`{abspath: (rpm_name, rpm_nevra)}` из `rpm-dump.txt` (формат
`путь<TAB>rpm_name<TAB>nevra`), с канонизацией симлинков `/lib64`↔`/usr/lib64`
(индексируются оба варианта пути). Нужно вынести это за интерфейс.

### Объём работ
1. Расширить `brec/ir.py` структурой (из архитектуры §3.3):
   ```python
   @dataclass
   class PackageRef:
       backend: str                 # "rpm" | "dpkg" | ...
       name: str
       version: str                 # NEVRA для rpm
       arch: Optional[str] = None
       source_package: Optional[str] = None
       purl: Optional[str] = None
   ```
   С `to_dict`/`from_dict` и round-trip-тестом (как в T0.1).

2. `brec/provenance/base.py`:
   ```python
   class ProvenanceBackend(Protocol):
       name: str
       def available(self) -> bool: ...
       def build_index(self, env_dump: Path) -> None: ...
       def lookup(self, abspath: str, git_hash: str) -> Optional[PackageRef]: ...
   ```

3. `brec/provenance/rpm.py` — `RpmBackend(ProvenanceBackend)`:
   - `build_index(rpm_dump_path)` — портировать `load_rpm_dump()` из `enrich.py`
     **дословно по поведению**, включая двойное индексирование `/lib64`↔
     `/usr/lib64`.
   - `lookup(abspath, git_hash)` — вернуть `PackageRef(backend="rpm",
     name=rpm_name, version=nevra, arch=…)` или `None`. `purl` — собрать
     `pkg:rpm/<name>@<version>` (если тривиально; иначе оставить `None`).
   - `available()` — наличие индекса/`rpm-dump.txt`.
   - На этой фазе `lookup` использует только `abspath` (хеш — для будущих
     бэкендов); сигнатура с `git_hash` фиксируется сразу.

### Вне объёма
Классификация (`dep_type`/`DepClass`) — это T1.2. Автоопределение бэкендов — T1.3.
dpkg и прочие — поздние фазы.

### Критерий приёмки
- На фикстуре `rpm-dump.txt` (взять реальную из прошлых прогонов или сделать
  мини): `RpmBackend.lookup()` для путей в `/lib64/...` и `/usr/lib64/...`
  возвращает один и тот же пакет (тест канонизации симлинков).
- Эквивалентность: множество `{abspath: (name, nevra)}`, построенное
  `RpmBackend`, **идентично** результату текущего `enrich.load_rpm_dump()` на том
  же дампе.
- `PackageRef` round-trip-тест.
- `tests/test_provenance_rpm.py`.

---

## T1.2 — Классификация: `brec/classify.py` (роли процессов + `DepClass`)

**Зависит от:** T1.1
**Размер:** L (ключевой тикет фазы)

### Контекст
Две существующие классификации нужно объединить в одну:
- **Роли процессов** — `verify-build.py`: `COMPILER_NAMES`, `LINKER_NAMES`,
  `ASSEMBLER_NAMES = {"as","x86_64-alt-linux-as"}`, `ARCHIVER_NAMES`, функция
  определения вида процесса → `compiler|linker|assembler|archiver`.
- **Тип файла** — `enrich.py:classify_dep_type(abspath, has_rpm)` →
  `static_header | static_archive | dynamic_lib | build_tool | project_source |
  system_runtime | unknown`; и `verify-build.py` `role` файла
  (`header|source|static_archive|dynamic_lib`) по тому, какой процесс его читал.

### Объём работ
1. Расширить `brec/ir.py` (из архитектуры §3.2):
   ```python
   class DepClass(str, Enum):
       SYSTEM_STATIC  = "static"
       SYSTEM_DYNAMIC = "dynamic"
       DECLARED       = "declared"
       VENDORED       = "vendored"
       PROJECT        = "project"
       TOOLCHAIN_TEMP = "temp"
       UNKNOWN        = "unknown"

   @dataclass
   class ClassifiedFile:
       file: FileNode
       dep_class: DepClass
       package: Optional[PackageRef] = None
       vendor_dir: Optional[str] = None
       read_by_roles: set[str] = field(default_factory=set)
   ```

2. `brec/classify.py`:
   ```python
   def classify_roles(graph: BuildGraph) -> None:
       """Проставить ProcessNode.role: compiler|linker|assembler|archiver|other."""

   def classify_files(graph: BuildGraph,
                      provenance: list[ProvenanceBackend],
                      source_dir: Optional[Path] = None
                      ) -> list[ClassifiedFile]:
       """Вернуть классификацию каждого прочитанного файла."""
   ```
   - Множества имён процессов — **импортировать/перенести** из `verify-build.py`
     (не дублировать значения вручную; вынести в `brec/classify.py` как
     единственный источник, verify-build.py начнёт брать оттуда в T1.4).
   - `VENDOR_DIRS` — перенести из `sbom.py` (`third_party`, `thirdparty`,
     `3rdparty`, `vendor(s)`, `external(s)`, `extern`, `deps`, `dependencies`,
     `contrib`, `bundled`, `embedded`).
   - Алгоритм `dep_class` (см. архитектуру §6): сочетание роли читавшего
     процесса + наличия `PackageRef` + vendor-сегмента в пути + расширения.
   - `DECLARED` на этой фазе **не определяется** (нет парсеров манифестов —
     фаза 4); ветку оставить, но она не срабатывает.

3. **Зафиксировать явный маппинг** старых значений в `DepClass` (в docstring и в
   тесте), отправная таблица:

   | enrich `dep_type` / verify `role` | `DepClass` |
   |---|---|
   | `static_header`, `static_archive` (read by compiler/assembler) | `SYSTEM_STATIC` |
   | `dynamic_lib` (`.so` read by linker, не артефакт сборки) | `SYSTEM_DYNAMIC` |
   | `build_tool` (исполняемый инструмент из пакета) | `SYSTEM_STATIC`* |
   | `project_source` + vendor-путь + нет пакета | `VENDORED` |
   | `project_source` без vendor-пути | `PROJECT` |
   | временные файлы тулчейна (`/tmp/cc*`, промежуточные `.o`) | `TOOLCHAIN_TEMP` |
   | прочее | `UNKNOWN` |

   \* точное место `build_tool` уточнить так, чтобы **итоговые бакеты
   `verify-build.py` не изменились** (см. приёмку); при необходимости ввести
   отдельную трактовку, но не ломая golden.

### Вне объёма
Идентификация вендоринга (фаза 2). Запись классификации обратно в `.out`
(остаётся за enrich-стороной, T1.4). Парсеры манифестов.

### Критерий приёмки
- **Эквивалентность с verify-build.py:** на эталонных `.out` (минимум `tiny.out`;
  при наличии — civetweb/aria2) бакеты, которые сейчас выдаёт `verify-build.py`
  (статические / динамические / артефакты / project), **полностью
  воспроизводятся** из `classify_files()` через заданный маппинг `DepClass`.
  Тест сравнивает множества путей в каждом бакете.
- **Эквивалентность с enrich.py:** для каждого файла значение, которое
  `enrich.classify_dep_type()` записал бы в `b:dep_type`, выводимо из
  `ClassifiedFile` (обратный маппинг детерминирован) — табличный тест.
- civetweb: файлы из `src/third_party/` без RPM → `VENDORED`; их `vendor_dir`
  заполнен.
- `tests/test_classify.py`.

---

## T1.3 — Реестр бэкендов + CLI-выбор: `brec/provenance/registry.py`

**Зависит от:** T1.1
**Размер:** S

### Контекст
Нужно автоматически определять применимые бэкенды провенанса и позволять
выбирать их явно, не привязывая ядро к конкретному дистрибутиву.

### Объём работ
1. `brec/provenance/registry.py`:
   ```python
   def all_backends() -> list[ProvenanceBackend]:
       """Все зарегистрированные классы бэкендов."""
   def detect_backends(env_dump: Optional[Path] = None) -> list[ProvenanceBackend]:
       """Те, у кого available() == True (по окружению/наличию дампа)."""
   def select_backends(names: Optional[list[str]]) -> list[ProvenanceBackend]:
       """По явному списку имён (из --provenance); валидация неизвестных имён."""
   ```
2. Регистрация через простую таблицу (имя → класс); `rpm` — пока единственный.
3. Заготовка флага `--provenance rpm[,dpkg]` для будущего `brec/cli.py`
   (сам единый CLI — поздняя задача; здесь только функция-парсер списка и её
   тесты, чтобы T1.4 могла её использовать).

### Вне объёма
Полный `brec/cli.py`. Реальные не-rpm бэкенды.

### Критерий приёмки
- `detect_backends()` в окружении с `rpm-dump.txt` возвращает `[RpmBackend]`.
- `select_backends(["rpm"])` → `[RpmBackend]`; `select_backends(["nope"])` →
  понятное исключение со списком доступных.
- `tests/test_registry.py`.

---

## T1.4 — Перевод `enrich.py` и классификации `verify-build.py` на `brec/`

**Зависит от:** T1.2, T1.3
**Размер:** L

### Контекст
Завершить фазу: старый код должен **использовать** новые модули, а не
дублировать логику. Поведение и вывод не меняются.

### Объём работ
1. Зафиксировать golden-выводы **до** изменений:
   - `enrich.py <out> <rpm-dump.txt>` → результирующий enriched `.out`
     (нормализовать недетерминированные поля, если есть);
   - `verify-build.py` со всеми флагами на тех же фикстурах.
2. `enrich.py`:
   - `load_rpm_dump()` → делегировать в `RpmBackend.build_index()/lookup()`.
   - `classify_dep_type()` → выводить значение `b:dep_type` из
     `ClassifiedFile.dep_class` через обратный маппинг (T1.2). Записываемые
     предикаты на этой фазе **не меняются** (всё ещё `b:rpm_name`/`b:rpm_package`/
     `b:dep_type`) — переход на `b:pkg_*` это отдельная задача, чтобы не ломать
     потребителей сейчас.
   - Сам `enrich.py` остаётся рабочей CLI-обёрткой.
3. `verify-build.py`:
   - Множества `COMPILER_NAMES`/`LINKER_NAMES`/… и определение роли процесса →
     импортировать из `brec/classify.py` (убрать локальные копии).
   - Классификацию файлов перевести на `brec.classify.classify_files()`,
     адаптировав внутренние структуры отчёта поверх `ClassifiedFile`.

### Вне объёма
Смена записываемых предикатов на `b:pkg_*`. Идентификация (фаза 2).

### Критерий приёмки
- **Golden:** enriched `.out` от нового `enrich.py` и весь вывод
  `verify-build.py` **побайтово** совпадают с зафиксированными до T1.4
  (с задокументированной нормализацией недетерминированных полей).
- В `verify-build.py` нет локальных копий `COMPILER_NAMES`/`LINKER_NAMES`/
  `ASSEMBLER_NAMES`/`ARCHIVER_NAMES` и нет собственной функции классификации
  файлов (grep пуст) — всё из `brec/classify.py`.
- В `enrich.py` нет собственного `load_rpm_dump`/`classify_dep_type` (логика в
  `brec/`); скрипт остаётся тонкой обёрткой.
- Команды pipeline из `doc/sbom-vendored-deps.md` работают без изменений.
- `tests/test_regression_enrich.py` + обновлённые регрессионные тесты verify.

---

## Definition of Done для фазы 1

- [ ] Атрибуция к пакету — только через `ProvenanceBackend`; ядро не знает про rpm.
- [ ] Единая классификация в `brec/classify.py`; `enrich.py` и `verify-build.py`
      используют её, своих копий логики не держат.
- [ ] `DepClass`/`ClassifiedFile`/`PackageRef` в IR, с round-trip-тестами.
- [ ] Реестр бэкендов + `select_backends`/`detect_backends`.
- [ ] Вывод `enrich.py` и `verify-build.py` не изменился (golden).
- [ ] Никаких новых тяжёлых зависимостей; ядро distro-agnostic.
- [ ] Готова почва для фазы 2: классы `VENDORED` с заполненным `vendor_dir` —
      это вход стадии IDENTIFY.
