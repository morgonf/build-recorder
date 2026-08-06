# Фаза 2 — тикеты для реализации (Sonnet)

> **Статус на 2026-08-06: фаза не реализована.** T2.1 (`brec/identify/base.py`,
> `resolver.py`, структуры `FileHash`/`Match`/`IdentifiedComponent` в `ir.py`,
> `tests/test_resolver.py`) был написан, но за ним так и не появилось ни одного
> бэкенда (T2.2–T2.4) и ни одного потребителя в CLI, поэтому код удалён как
> мёртвый. Восстанавливать из истории git вместе с первым реальным бэкендом;
> спецификации ниже остаются планом.
>
> Родительский документ: `doc/architecture-universal-provenance.md` (§5.3, §7, §11 фаза 2).
> Предусловие: завершены фазы 0–1 (`brec/model.py`, `brec/classify.py`,
> `ProvenanceBackend`). На входе фазы — файлы класса `VENDORED` с заполненным
> `vendor_dir` (выход `classify_files()`).
>
> **Это главная фаза проекта: универсальная идентификация вендорированного кода
> до `(проект, версия/коммит)` БЕЗ курируемой базы в ядре.** Курируемые данные
> (бывш. `UPSTREAM_DB`/`KNOWN_COMPONENTS`) допустимы только как опциональный
> офлайн-кэш/оверрайд — удаление кэша не должно ломать идентификацию при сети.
>
> **Рекомендуемый порядок:** T2.1 → T2.4 → T2.3 → T2.2 → T2.5 → T2.6.
> (`base`+`resolver` → кэш как офлайн-источник repo → gitwalk → swh → osv →
> интеграция и приёмка фазы.)
>
> **Общие правила:**
> - Сетевые бэкенды (`swh`, `osv`) тестируются на **записанных ответах**
>   (VCR-стиль/локальные JSON-фикстуры) — тесты офлайн и детерминированы.
> - Каждый бэкенд кэширует ответы на диск (`--cache-dir`), уважает rate-limit
>   (бэкофф/ретраи) и корректно деградирует при недоступности сети.
> - `b:hash` из `.out` — это `sha1_git` (git-blob). SWH индексирует контент тем
>   же хешем → **пересчёт для SWH не нужен**. OSV ожидает свой формат → пересчёт
>   из `--source-dir`.
> - Честность вывода: «точно» только при exact-hash 100%; пост-релизные снимки
>   маркировать «+N коммитов после тега» (как уже делает `verify-build.py`).

---

## T2.1 — Каркас идентификации: `brec/identify/base.py` + `resolver.py`

**Зависит от:** фаза 1
**Размер:** M

### Контекст
Нужен общий интерфейс бэкендов и оркестратор, который из единиц вендоринга
делает `IdentifiedComponent`, сливая результаты разных источников и деградируя
в офлайн.

### Объём работ
1. Расширить `brec/ir.py` (архитектура §3.4, §5.3):
   ```python
   @dataclass
   class FileHash:
       rel_path: str                # путь внутри vendor_dir
       git_blob_sha1: str
       plain_sha1: Optional[str] = None
       other: dict[str, str] = field(default_factory=dict)

   @dataclass
   class Match:
       backend: str                 # swh|osv|gitwalk|cache|fuzzy
       repo_url: Optional[str] = None
       project: Optional[str] = None
       version: Optional[str] = None
       commit: Optional[str] = None
       nearest_tag: Optional[str] = None
       commits_past_tag: int = 0
       confidence: float = 0.0      # 0..1
       method: str = "exact"        # exact|manifest|fuzzy|snippet
       files_matched: int = 0
       files_total: int = 0

   @dataclass
   class IdentifiedComponent:
       key: str                     # = vendor_dir
       files: list[str]             # uri FileNode
       candidates: list[Match]
       best: Optional[Match] = None
       purl: Optional[str] = None
   ```
   round-trip-тесты как в T0.1.

2. `brec/identify/base.py`:
   ```python
   @dataclass
   class VendoredUnit:
       key: str                     # vendor_dir
       files: list[FileHash]
       abs_root: Optional[str]      # абсолютный путь vendor_dir (если в дереве)

   class IdentificationBackend(Protocol):
       name: str
       requires_network: bool
       def discover(self, unit: VendoredUnit) -> list[Match]: ...
       # discover: вернуть кандидатов repo/version (может быть пусто)
       def refine(self, unit: VendoredUnit, repo_url: str) -> Optional[Match]: ...
       # refine: уточнить коммит/тег для известного repo_url (optional, может бросать NotImplemented)
   ```
   Бэкенд может реализовывать только `discover` (swh/osv/cache) или только
   `refine` (gitwalk) — оркестратор это учитывает.

3. `brec/identify/resolver.py`:
   ```python
   def build_units(classified: list[ClassifiedFile]) -> list[VendoredUnit]:
       """Сгруппировать VENDORED по vendor_dir в единицы с FileHash."""

   def resolve(unit: VendoredUnit,
               backends: list[IdentificationBackend],
               offline: bool = False) -> IdentifiedComponent:
       """1) discovery: собрать repo-кандидатов от discover-бэкендов;
          2) refinement: для каждого repo_url прогнать refine-бэкенды (gitwalk);
          3) слить Match по repo_url (max confidence), отсортировать, выбрать best;
          4) ВСЕГДА вернуть минимум Tier-0 (files+hashes, best=None при нуле)."""
   ```
   - При `offline=True` пропускать бэкенды с `requires_network`.
   - Слияние: ключ — нормализованный `repo_url`; при конфликте полей берётся
     `Match` с большим `confidence`, недостающие поля дополняются.

### Вне объёма
Реализация конкретных бэкендов (T2.2–T2.5). Отчёты (фаза будет потреблять IR).

### Критерий приёмки
- `build_units` на classified-фикстуре civetweb даёт по одной единице на
  vendor-директорию с корректным набором `FileHash`.
- `resolve` с **пустым** списком бэкендов возвращает Tier-0 `IdentifiedComponent`
  (files заполнены, `best is None`).
- `resolve` со стаб-бэкендами (discover → фикс. Match, refine → фикс. Match)
  корректно сливает и выбирает best по confidence.
- Round-trip-тесты IR. `tests/test_resolver.py`.

---

## T2.4 — Кэш/оверрайды компонентов: `brec/identify/cache.py` + `data/components.d/`

**Зависит от:** T2.1
**Размер:** M

### Контекст
Бывшие `UPSTREAM_DB` (`verify-build.py`, 8 записей) и `KNOWN_COMPONENTS`
(`sbom.py`, 14 записей) переезжают в **необязательный** локальный кэш (файл на
компонент). Назначение: офлайн-фолбэк, оверрайд ошибок swh/osv, ускорение
(пропуск discovery).

### Объём работ
1. Формат `data/components.d/<key>.yaml` (унифицирует обе старые схемы):
   ```yaml
   key: wslay
   display_name: wslay
   detect:
     file_triggers: [wslay.h, wslay_event.c]   # из ComponentSpec.file_triggers
     dir_regex: 'wslay[-_](\d[\d.]*)'           # опционально
   upstream:
     url: https://github.com/tatsuhiro-t/wslay.git
     max_commits: 300
     key_files: [lib/wslay_event.c, lib/wslay_frame.c, lib/includes/wslay/wslay.h]
   purl: { type: github, ns: tatsuhiro-t, name: wslay }
   ```
   Все поля кроме `key` опциональны (sqlite без osv-ecosystem, jsmn без version — ложатся без костылей).
2. `data/components.schema.json` — jsonschema; валидация при загрузке, ошибка с
   указанием файла.
3. `brec/identify/cache.py` — `CacheBackend(IdentificationBackend)`:
   - `requires_network = False`.
   - Загрузчик с приоритетом: встроенный `data/components.d/` →
     `~/.config/build-recorder/components.d/` → `./.build-recorder/components.d/`
     → путь из `--components-db`. Слияние по `key` (позднее переопределяет).
   - `discover(unit)`: сопоставить `unit.key`/`file_triggers` с записями →
     вернуть `Match(backend="cache", repo_url=…, project=…, confidence=0.5,
     files_total=…)` (низкая базовая уверенность; точный коммит даст gitwalk).
4. **Скрипт-дамп** `scripts/dump_legacy_db.py`: одноразово сгенерировать YAML из
   текущих `UPSTREAM_DB` + `KNOWN_COMPONENTS`, объединяя 5 пересекающихся ключей
   (zlib, lua, luafilesystem, duktape, expat). Результат — закоммитить в
   `data/components.d/`.

### Вне объёма
Сетевые бэкенды. `version_transform` как код — пока сохранить как именованный
трансформ (поле `version.transform: <name>` + реестр в коде; перенос `_duk_version`).

### Критерий приёмки
- Все 17 объединённых записей валидны по jsonschema; битая запись → понятная
  ошибка с именем файла.
- Приоритет загрузки: запись в `./.build-recorder/` переопределяет встроенную
  (тест).
- `CacheBackend.discover` для `unit.key="wslay"` возвращает Match с правильным
  `repo_url`.
- `tests/test_cache_backend.py`.

---

## T2.3 — Точный коммит: `brec/identify/gitwalk.py`

**Зависит от:** T2.1
**Размер:** L

### Контекст
Вынос существующего commit-walk из `verify-build.py` (`_ensure_clone`,
`_tag_map`, `_git`, обход истории, `UpstreamMatch`) в бэкенд, который принимает
`repo_url` **извне** (от resolver), а не из захардкоженной `UPSTREAM_DB`.

### Объём работ
1. `brec/identify/gitwalk.py` — `GitWalkBackend(IdentificationBackend)`:
   - `requires_network = True` (клон при первом обращении; затем кэш).
   - `discover()` → `[]` (gitwalk не обнаруживает repo сам).
   - `refine(unit, repo_url)`:
     - bare-clone в `--cache-dir` (`~/.cache/build-recorder/repos/`), портировать
       `_ensure_clone`;
     - обойти до `max_commits` коммитов (от новых к старым), сравнивая git-blob
       хеши `unit.files`/`key_files` с `git ls-tree -r COMMIT`;
     - найти коммит с максимумом совпадений; при 100% — остановиться;
     - определить ближайший тег и `commits_past_tag` (портировать `_tag_map`);
     - вернуть `Match(backend="gitwalk", repo_url, commit, nearest_tag,
       commits_past_tag, confidence = matched/total, files_matched, files_total,
       method="exact")`.
2. Сохранить семантику `UpstreamMatch.is_tagged_release`
   (`commits_past_tag == 0 and nearest_tag`) при маппинге в `Match`.
3. `key_files`: если в кэш-записи заданы — использовать их; иначе использовать
   все `unit.files` (как в текущем поведении при пустом `key_files`).

### Вне объёма
Обнаружение repo (это swh/osv/cache). Fuzzy.

### Критерий приёмки
- На предклонированном/закэшированном репозитории wslay `refine()` для файлов
  aria2-wslay возвращает `commit=0e7d106ff89a…`, `nearest_tag=release-1.1.1`,
  `commits_past_tag=28` — воспроизводя результат `verify-build.py` (тест может
  использовать локальную копию репо как фикстуру, чтобы быть офлайн).
- Эквивалентность: на тех же входах `Match` совпадает с тем, что выдавал
  `verify-build.py` `UpstreamMatch` (поля commit/tag/distance).
- `tests/test_gitwalk.py`.

---

## T2.2 — Software Heritage: `brec/identify/swh.py`

**Зависит от:** T2.1
**Размер:** M

### Контекст
SWH — крупнейший архив исходников, индексирует контент по `sha1_git` (= наш
`b:hash`). Используем как универсальный сигнал «этот файл существует в мировом
архиве ⇒ это не оригинальный код проекта» и (best-effort) для обнаружения origin.

### Объём работ
1. `brec/identify/swh.py` — `SwhBackend(IdentificationBackend)`:
   - `requires_network = True`.
   - `discover(unit)`:
     - сформировать SWHID контента `swh:1:cnt:<git_blob_sha1>` для файлов unit;
     - запрос к `known` API (`POST /api/1/known/`) батчами; кэш ответов на диск;
     - доля известных файлов → `Match(backend="swh", repo_url=None,
       confidence = known/total, method="exact", files_matched=known,
       files_total=total)` — **подтверждение внешности**, без repo.
     - **Best-effort origin:** если по API доступно сопоставление контента с
       origin/snapshot — попытаться заполнить `repo_url`; если нет —
       оставить `None` и не выдумывать. Зафиксировать ограничение в docstring.
   - `refine()` → `NotImplemented`/`None`.
2. Поддержка опционального токена SWH (env `SWH_TOKEN`) для лимитов; бэкофф на 429.

### Вне объёма
Резолвинг точной версии (это gitwalk поверх repo_url из osv/cache). Пересчёт
хешей (не нужен — git-blob нативен для SWH).

### Критерий приёмки
- На записанном ответе `known` для набора хешей: `discover` возвращает Match с
  `confidence = known/total` и корректными `files_matched/total`.
- Файл, заведомо отсутствующий в архиве (мок «unknown»), не повышает confidence.
- Кэш: повторный `discover` не делает повторных сетевых вызовов (мок считает
  обращения). `tests/test_swh.py`.

---

## T2.5 — OSV determineversion: `brec/identify/osv.py`

**Зависит от:** T2.1
**Размер:** M

### Контекст
OSV determineversion возвращает `(repo, версия, score)` по хешам файлов —
основной механизм **обнаружения repo+версии** без курирования. Ожидает свой
формат хеша → нужен пересчёт из `--source-dir` (логика частично есть в
`sbom.py`: `_plain_sha1`, `query_osv_determineversion`).

### Объём работ
1. `brec/identify/osv.py` — `OsvBackend(IdentificationBackend)`:
   - `requires_network = True`; предусловие — доступен `source_dir`
     (иначе `available`-подобная проверка возвращает «недоступен», бэкенд
     пропускается без ошибки).
   - `discover(unit)`:
     - досчитать `plain_sha1` для `unit.files` из исходников (портировать
       `_plain_sha1`);
     - запрос `POST /v1experimental/determineversion` (портировать
       `query_osv_determineversion`);
     - из ответа собрать `Match(backend="osv", repo_url=repo_info.address,
       project=…, version=repo_info.version, confidence=score, method="exact")`.
   - `refine()` → `None`.
2. Кэш ответов; бэкофф; деградация при недоступности.

### Вне объёма
CVE-запрос (это фаза 3, `vuln/osv_query.py`).

### Критерий приёмки
- На записанном ответе determineversion: `discover` возвращает Match с
  `repo_url`, `version`, `confidence=score`.
- Без `source_dir` бэкенд тихо пропускается (не падает).
- Пересчёт `plain_sha1` совпадает с текущим `sbom._plain_sha1` на тех же файлах.
- `tests/test_osv.py`.

---

## T2.6 — Интеграция и приёмка фазы

**Зависит от:** T2.2, T2.3, T2.4, T2.5
**Размер:** M

### Контекст
Связать бэкенды через resolver в рабочий путь идентификации и доказать
универсальность на aria2 без курируемой записи.

### Объём работ
1. Подключить `resolve()` к существующему потоку: для каждой `VENDORED`-единицы
   вызвать resolver с набором бэкендов `[cache, osv, swh] (discover) + [gitwalk]
   (refine)`. Записать результат в IR (`stage="identified"`) и/или дополнить
   `.out` предикатами `b:identified_*` (см. архитектура §4).
2. Заменить использование захардкоженной `UPSTREAM_DB` в `verify-build.py`
   `--upstream-verify` на путь через resolver (repo_url теперь приходит от
   cache/osv, уточняется gitwalk). Старый словарь оставить только как сидинг
   `data/components.d/` (из T2.4), из кода удалить.
3. Флаги: `--identify swh,osv,gitwalk,cache`, `--offline`, `--components-db`,
   `--source-dir`, `--cache-dir` (см. архитектура §10).

### Вне объёма
Fuzzy (фаза 5), CVE (фаза 3), полноценный `brec/cli.py` (минимально — точка
входа для identify).

### Критерий приёмки (приёмка всей фазы 2)
- **Главный интеграционный тест (universality):** на `.out` сборки aria2 с
  `--source-dir` (исходники aria2) и записанными ответами OSV/SWH, **при пустом
  `data/components.d/`** (или временно отключённом cache), resolver определяет
  вендоринг `deps/wslay` как: `repo=…/wslay.git` (через OSV discovery),
  `commit=0e7d106ff89a…`, `nearest_tag=release-1.1.1`, `commits_past_tag=28`
  (через gitwalk refine) — воспроизводя `doc/article-build-provenance.md` **без**
  курируемой записи. Это доказывает, что база не является ядром.
- **Офлайн-режим:** тот же aria2 с `--offline` и заполненным cache (wslay-запись)
  → resolver через `cache.discover` (repo_url) + `gitwalk.refine` (из
  предклонированного репо) даёт тот же commit/tag/distance.
- civetweb: для `src/third_party/` единиц SWH `discover` подтверждает внешность
  (confidence > 0), Tier-0 всегда заполнен даже без repo.
- В `verify-build.py` нет обращений к локальному `UPSTREAM_DB` (grep пуст).
- `tests/test_phase2_integration.py`.

---

## Definition of Done для фазы 2

- [ ] Идентификация работает через `resolver` + бэкенды; ядро не содержит
      курируемой базы как обязательной.
- [ ] `swh`/`osv`/`gitwalk`/`cache` реализованы, тестируются офлайн на записанных
      ответах, кэшируют и деградируют корректно.
- [ ] Бывшие `UPSTREAM_DB`/`KNOWN_COMPONENTS` — только в `data/components.d/`
      (опциональный кэш); из кода удалены.
- [ ] Universality-тест: aria2/wslay идентифицируется **без** записи в кэше при сети.
- [ ] Offline-тест: тот же результат через cache + предклонированный репо.
- [ ] Tier-0 всегда возвращается (files + git-blob hashes), даже при нуле совпадений.
- [ ] Выход — IR `stage="identified"` / предикаты `b:identified_*`, готовые для
      фазы 3 (MAP→CVE).
