# Фаза 3 — тикеты для реализации (Sonnet)

> Родительский документ: `doc/architecture-universal-provenance.md` (§3.5, §8, §9, §11 фаза 3).
> Предусловие: завершена фаза 2 — есть `IdentifiedComponent` (IR `stage="identified"`)
> с `best: Match` (repo/version/commit/confidence) и/или `purl`.
>
> Цель фазы: сопоставить идентифицированные компоненты с уязвимостями (OSV/NVD)
> и довести вывод до полноценного отчёта — CycloneDX 1.6 SBOM с разделом
> vulnerabilities и human-readable markdown. Это замыкает вторую цель проекта:
> контроль уязвимостей вендорированных и системных зависимостей.
>
> **Рекомендуемый порядок:** T3.1 → T3.2 → T3.3 → T3.4 → T3.5.
>
> **Общие правила:**
> - Сетевой бэкенд (OSV query) тестируется на **записанных ответах**
>   (VCR-стиль/локальные JSON) — тесты офлайн и детерминированы.
> - Кэш ответов на диск (`--cache-dir`), бэкофф на 429, деградация при
>   недоступности сети (без падения — пометить «CVE-запрос пропущен»).
> - **Честность вывода обязательна:** запрос CVE делается только при известной
>   версии; при unknown-версии компонент помечается «версия не определена,
>   CVE-запрос пропущен», уязвимости не выдумываются.
> - Версия идентификации поверх фазы 2: пост-релизный снимок (`commits_past_tag>0`)
>   — это **не** тег; для него запрос по точному тегу даст неполный/неверный
>   результат. Это поведение явно тестируется (см. T3.2, кейс wslay).

---

## T3.1 — Структура `Vulnerability` и PURL-резолвинг

**Зависит от:** фаза 2
**Размер:** S

### Контекст
Для запроса в OSV нужен канонический идентификатор пакета (PURL или
name+version+ecosystem), а для отчёта — единая структура уязвимости.

### Объём работ
1. Расширить `brec/ir.py` (архитектура §3.5):
   ```python
   @dataclass
   class Vulnerability:
       id: str                      # CVE / GHSA / OSV id
       component_key: str
       severity: str                # none|low|medium|high|critical
       cvss_score: Optional[float] = None
       affected_range: Optional[str] = None
       fixed_version: Optional[str] = None
       source: str = "osv"          # osv|nvd
       url: Optional[str] = None
   ```
   round-trip-тесты как в T0.1.
2. `brec/vuln/purl.py`:
   ```python
   def component_purl(comp: IdentifiedComponent) -> Optional[str]:
       """Собрать PURL из best.repo_url/version или из comp.purl (кэш-запись).
          Напр. github.com/madler/zlib + v1.3 → pkg:github/madler/zlib@1.3.
          Вернуть None, если версия не определена."""
   def package_purl(pkg: PackageRef) -> Optional[str]:
       """PURL для системного пакета: pkg:rpm/<name>@<version> и т.п."""
   ```
   - Нормализация тегов в версию (`v1_8_0`/`release-1.1.1`/`v1.3` → `1.8.0`/…)
     — вынести в чистую функцию с табличными тестами; покрыть формы из
     `data/components.d/` (фаза 2).

### Вне объёма
Сетевые запросы. NVD-источник (опционально, поздняя задача).

### Критерий приёмки
- `Vulnerability` round-trip-тест.
- `component_purl` на best-Match с версией → корректный PURL; без версии → None.
- Нормализация тегов: табличный тест на формы `v1_8_0`, `release-1.1.1`,
  `v1.3`, `1.2.11`.
- `tests/test_purl.py`.

---

## T3.2 — OSV query: `brec/vuln/osv_query.py`

**Зависит от:** T3.1
**Размер:** M

### Контекст
По PURL/версии получить список уязвимостей из OSV. Это основной механизм
MAP→CVE, покрывающий и вендоринг (через github/PyPI/… экосистемы), и системные
пакеты (где OSV их знает).

### Объём работ
1. `brec/vuln/osv_query.py`:
   ```python
   def query_component(comp: IdentifiedComponent) -> list[Vulnerability]:
       """POST https://api.osv.dev/v1/query по PURL или name+version+ecosystem.
          Если версия не определена → вернуть [] и пометить в IR причину."""
   def query_package(pkg: PackageRef) -> list[Vulnerability]:
       """То же для системного пакета (если есть PURL/ecosystem)."""
   def _parse_osv_vulns(resp: dict, component_key: str) -> list[Vulnerability]:
       """Разобрать ответ OSV: id, severity (из CVSS), affected ranges,
          fixed version, ссылку."""
   ```
   - Severity: извлечь из `severity`/`database_specific`/CVSS-вектора; маппинг
     score → `none|low|medium|high|critical` по CVSS-порогам — чистая функция
     с тестом (переиспользовать/портировать `_osv_severity` из `sbom.py`).
   - Кэш ответов на диск; бэкофф; деградация (нет сети → `[]` + пометка).
2. Семантика версии из фазы 2:
   - `is_tagged_release` (точный тег) → запрос по версии тега.
   - пост-релизный снимок (`commits_past_tag>0`) → запрос по ближайшему тегу
     **с явной пометкой** «снимок новее тега; диапазон affected может быть
     неточен» (в IR и отчёте). НЕ утверждать точное соответствие версии.

### Вне объёма
NVD-источник, бинарный скан (cve-bin-tool — внешний, упоминается в отчёте).

### Критерий приёмки
- На записанном ответе OSV для известной уязвимой версии (фикстура) →
  непустой `list[Vulnerability]` с корректной severity/id/range.
- Компонент без версии → `[]` + причина «версия не определена» в IR.
- wslay-снимок (`commits_past_tag=28`): запрос делается по `release-1.1.1`, но в
  результате/IR стоит пометка «снимок новее тега» (тест на наличие пометки).
- severity-маппинг: табличный тест по CVSS-порогам.
- Кэш: повторный запрос не ходит в сеть (мок считает обращения).
- `tests/test_osv_query.py`.

---

## T3.3 — Стадия MAP→CVE в IR и оркестрация

**Зависит от:** T3.2
**Размер:** S

### Контекст
Связать запросы в единую стадию, дополняющую IR `stage="vuln"`.

### Объём работ
1. `brec/vuln/__init__.py` (или `mapper.py`):
   ```python
   def map_vulnerabilities(identified: list[IdentifiedComponent],
                           packages: Optional[list[PackageRef]] = None,
                           offline: bool = False) -> list[Vulnerability]:
       """Прогнать query_component по всем компонентам (+опц. системные пакеты),
          собрать плоский список, прикрепить component_key."""
   ```
   - `offline=True` → пропустить сеть, вернуть `[]` с пометками причин.
   - Дедупликация по `(id, component_key)`.
2. Записать результат в IR `stage="vuln"` (payload: компоненты + их уязвимости).

### Вне объёма
Рендеринг отчётов (T3.4/T3.5).

### Критерий приёмки
- На identified-фикстуре (несколько компонентов, часть без версии) →
  уязвимости только для тех, у кого версия известна; для остальных — пометка.
- Дедупликация работает (один CVE на компонент не дублируется).
- IR `stage="vuln"` валиден (round-trip).
- `tests/test_vuln_mapper.py`.

---

## T3.4 — CycloneDX 1.6 c уязвимостями: `brec/report/cyclonedx.py`

**Зависит от:** T3.3
**Размер:** M

### Контекст
Существующий генератор CycloneDX в `sbom.py` нужно перенести в модуль и дополнить
секцией `vulnerabilities` из стадии MAP→CVE, с маркировкой источника/уверенности.

### Объём работ
1. `brec/report/cyclonedx.py` — `to_cyclonedx(identified, vulns, meta) -> dict`:
   - сохранить текущий формат `sbom.py` (CycloneDX 1.6, `components` с PURL,
     `evidence.identity.methods`);
   - `evidence.identity`: `technique` ∈ `hash-comparison|filename|manifest`,
     `confidence` из `Match.confidence`, `method` из `Match.method`;
   - добавить секцию `vulnerabilities` из `Vulnerability` (id, ratings/severity,
     `affects` → bom-ref компонента, source/url);
   - для пост-релизных снимков — отразить в `evidence`/`properties` пометку
     «snapshot +N past tag».
2. Детерминизм вывода (сортировка ключей/компонентов) для golden-тестов;
   timestamp генерации — нормализуемое поле.

### Вне объёма
Markdown (T3.5). Изменение схемы CycloneDX-версии.

### Критерий приёмки
- На vuln-фикстуре генерируется валидный CycloneDX 1.6 (проверка по JSON-схеме
  CycloneDX или структурный тест ключевых полей).
- Компонент с CVE имеет соответствующую запись в `vulnerabilities` с верным
  `affects`-ref.
- **Эквивалентность:** для входа без уязвимостей вывод структурно совпадает с
  текущим `sbom.py` CycloneDX (golden, с нормализацией timestamp).
- `tests/test_cyclonedx.py`.

---

## T3.5 — Human-readable отчёт: `brec/report/markdown.py`

**Зависит от:** T3.3
**Размер:** M

### Контекст
Markdown-отчёт для человека: по каждому компоненту — класс, провенанс,
идентификация (репо/версия/коммит/уверенность/источник) и уязвимости.

### Объём работ
1. `brec/report/markdown.py` — `to_markdown(classified, identified, vulns, meta) -> str`:
   - сводная таблица по `DepClass` (сколько static/dynamic/vendored/project) —
     в духе текущих отчётов `verify-build.py`/`build-report.py`;
   - на каждый вендорированный компонент: best-match (репо, версия/коммит,
     `confidence`, `источник`), статус (`✓ точный тег` / `⚠ снимок +N после тега`
     / `⚠ не идентифицирован`), список файлов с git-blob хешами;
   - секция уязвимостей: таблица CVE с severity, диапазоном, fixed-версией,
     ссылкой; для компонентов без версии — строка «версия не определена,
     CVE-запрос пропущен»;
   - упоминание внешней перекрёстной проверки (cve-bin-tool на бинаре) как
     рекомендации — как в `doc/sbom-vendored-deps.md`.
2. Каждое утверждение помечено источником/уверенностью; «точно» только при
   exact-hash 100%.

### Вне объёма
HTML/графовые визуализации.

### Критерий приёмки
- На vuln-фикстуре генерируется markdown со всеми секциями; снимок wslay
  отражён как «⚠ снимок +28 после release-1.1.1».
- Компонент без версии даёт строку-пометку, а не пустоту/выдуманный CVE.
- Детерминизм (golden-тест с нормализацией timestamp).
- `tests/test_markdown.py`.

---

## Definition of Done для фазы 3

- [ ] `Vulnerability` в IR; PURL-резолвинг с нормализацией тегов.
- [ ] OSV query по PURL/версии; severity-маппинг; кэш; деградация в офлайн.
- [ ] Стадия MAP→CVE (IR `stage="vuln"`) с дедупликацией и пометками причин.
- [ ] CycloneDX 1.6 с секцией vulnerabilities; эквивалентность старому SBOM без CVE.
- [ ] Markdown-отчёт со всеми секциями и честной маркировкой версий/источников.
- [ ] Компоненты без версии не порождают ложных CVE; снимки помечены «+N после тега».
- [ ] Сетевые тесты — на записанных ответах, офлайн и детерминированы.
