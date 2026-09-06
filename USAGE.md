# Build-recorder: руководство пользователя

Build-recorder — инструмент для записи полного графа сборки: какой процесс какие файлы
читал, записывал и порождал. Результат сохраняется в формате RDF Turtle и пригоден
для последующего SPARQL-анализа.

---

## Содержание

1. [Как это работает](#как-это-работает)
2. [Быстрый старт](#быстрый-старт)
3. [Сборка git-репозитория](#сборка-git-репозитория)
4. [Сборка SRPM-пакета](#сборка-srpm-пакета)
5. [Анализ результатов](#анализ-результатов)
6. [Настройка образа под пакет](#настройка-образа-под-пакет)
7. [Справочник переменных](#справочник-переменных)
8. [Диагностика](#диагностика)

---

## Как это работает

Build-recorder использует Linux `ptrace(2)` для перехвата системных вызовов
трассируемого процесса и всего его дерева потомков. Отслеживаются:

| Syscall | Что фиксируется |
|---------|-----------------|
| `open`, `openat`, `openat2`, `creat` | чтение и запись файлов |
| `close` | финальный git-blob хэш записанного файла |
| `execve`, `execveat` | запуск исполняемых файлов |
| `fork`, `vfork`, `clone` | создание дочерних процессов |
| `rename`, `renameat`, `renameat2` | переименование файлов |
| `link`, `linkat` | жёсткие ссылки (второе имя тому же содержимому) |
| `io_uring_setup`, `io_uring_enter` | отметка о разрыве покрытия (см. ниже) |

Последняя строка нужна потому, что io_uring выполняет операции с файлами через
кольцо, а в режиме SQPOLL вообще без системного вызова: перехватить их ptrace не
может. Такие операции в графе не появляются, поэтому процесс, применивший
io_uring, помечается предикатом `b:coverage_gap`, а анализ отказывается
утверждать полноту графа для него.

Сборка запускается в Docker-контейнере на базе ALT Linux p11, что обеспечивает
изолированное воспроизводимое окружение.

**Требования к хосту:** Docker 20+, Linux-ядро ≥ 5.3 (нужен `PTRACE_GET_SYSCALL_INFO`).

### Ключи самого трассировщика

```
build-recorder [-o outfile] [-2 | --sha256] команда
```

| Ключ | Что делает |
|------|-----------|
| `-o <файл>` | куда писать граф, по умолчанию `build-recorder.out` |
| `-2`, `--sha256` | считать `b:hash` как git-blob **SHA-256** вместо git-blob SHA-1 |

Ключи должны идти до команды: первый аргумент, не опознанный как ключ, начинает
записываемую командную строку.

По умолчанию хеш остаётся SHA-1, чтобы значения совпадали с git и с метаданными
пакетов (сверка вендоринга через `brec verify` опирается на это). Для
состязательной модели нужен `-2`: коллизия SHA-1 практически достижима, а
значит, злоумышленник мог бы подогнать прекомпилят под хеш файла, собранного из
исходников, и обойти вердикт. Инструменты анализа принимают оба варианта и сами
определяют, какой использован в трассе (по длине хеша).

Docker-обёртка (`docker/entrypoint.sh`) вызывает трассировщик только с `-o`,
поэтому для SHA-256 внутри контейнера нужно править вызов вручную. Подробное
описание ключей: `man 1 build-recorder`.

---

## Быстрый старт

### 1. Собрать Docker-образ

```bash
cd /home/user/claude/build-recorder

docker build \
  -f docker/Dockerfile \
  -t build-recorder:latest \
  .
```

Образ включает: gcc, g++, cmake, make, git, libssl-devel, libsystemd-devel и другие
общие зависимости. Пересборка нужна только при изменении `docker/Dockerfile`
или `docker/entrypoint.sh`.

### 2. Запустить сборку

```bash
# Git-репозиторий:
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v ~/build-recorder-out/myproject:/output \
  -e GIT_URL=https://github.com/redis/redis \
  -e OUTPUT_DIR=/output \
  build-recorder:latest

# SRPM-пакет:
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v /path/to/srpms:/srpms:ro \
  -v ~/build-recorder-out/mypackage:/output \
  -e SRPM=/srpms/mypackage.src.rpm \
  -e OUTPUT_DIR=/output \
  build-recorder:latest
```

Флаги `--cap-add=SYS_PTRACE` и `--security-opt seccomp:unconfined` **обязательны**:
без них `ptrace(2)` возвращает `EPERM`.

### 3. Проанализировать результат

```bash
python3 -m brec report \
  ~/build-recorder-out/myproject/myproject-build.out \
  --report
```

---

## Сборка git-репозитория

### Базовый запуск

```bash
mkdir -p ~/build-recorder-out/redis

docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v ~/build-recorder-out/redis:/output \
  -e GIT_URL=https://github.com/redis/redis \
  -e OUTPUT_DIR=/output \
  build-recorder:latest
```

Внутри контейнера entrypoint:
1. Клонирует репозиторий (`git clone --depth=1`)
2. Определяет систему сборки по файлам в корне
3. Запускает `build-recorder <build_cmd>`

### Автоопределение системы сборки

| Файл в корне репозитория | Команда сборки |
|--------------------------|---------------|
| `Makefile` | `make -j$(nproc)` |
| `CMakeLists.txt` | `cmake -B _build . && make -C _build -j$(nproc)` |
| `autogen.sh` | `./autogen.sh && ./configure && make -j$(nproc)` |
| `configure.ac` | `autoreconf -i && ./configure && make -j$(nproc)` |
| `configure` | `./configure && make -j$(nproc)` |
| `meson.build` | `meson setup _build && ninja -C _build` |

### Опциональные параметры

| Переменная | Назначение | Пример |
|-----------|-----------|--------|
| `GIT_REF` | Ветка, тег или коммит | `GIT_REF=8.6.1` |
| `GIT_BUILD_CMD` | Переопределить команду сборки | `GIT_BUILD_CMD="make BUILD_TLS=no -j4"` |

```bash
# Конкретный тег
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v ~/build-recorder-out/redis:/output \
  -e GIT_URL=https://github.com/redis/redis \
  -e GIT_REF=8.6.1 \
  -e OUTPUT_DIR=/output \
  build-recorder:latest

# Переопределение команды (без TLS)
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v ~/build-recorder-out/redis:/output \
  -e GIT_URL=https://github.com/redis/redis \
  -e GIT_BUILD_CMD="make BUILD_TLS=no -j4" \
  -e OUTPUT_DIR=/output \
  build-recorder:latest
```

---

## Сборка SRPM-пакета

SRPM-режим запускает `rpmbuild -bc` — только фазы `%prep` (распаковка, патчи)
и `%build` (компиляция). Тесты (`%check`) и упаковка (`%install`, `%files`)
пропускаются.

### Откуда взять SRPM

**Из репозитория ALT Linux Sisyphus:**

```bash
# Найти нужный пакет
wget "http://ftp.altlinux.org/pub/distributions/ALTLinux/Sisyphus/files/SRPMS/redis-8.6.1-alt1.src.rpm" \
  -P ~/srpms/
```

**Из локального hasher-репозитория** (если пакет уже собирался):

```bash
ls /home/user/hasher-repo/sisyphus/SRPMS.hasher/
```

### Запуск

```bash
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v ~/srpms:/srpms:ro \
  -v ~/build-recorder-out/redis:/output \
  -e SRPM=/srpms/redis-8.6.1-alt1.src.rpm \
  -e OUTPUT_DIR=/output \
  build-recorder:latest
```

Entrypoint автоматически:
- Устанавливает SRPM (`rpm -i --nodeps`)
- Находит `.spec` файл
- Вырезает секцию `%check` (rpm 4.13 не поддерживает `--nocheck`)
- Запускает `build-recorder rpmbuild --nodeps --define '_allow_root_build 1' -bc`

---

## Анализ результатов

Выходной файл `<pkgname>-build.out` содержит RDF Turtle с полным графом сборки.

### Единая точка входа: `brec`

Весь анализ живёт в пакете `brec` и вызывается одной командой с подкомандами
(из корня репозитория; после `pip3 install .` доступна просто как `brec`):

```bash
python3 -m brec --help
```

| Подкоманда | Что делает |
|---|---|
| `brec enrich` | приписывает файлам трассы пакет-владелец по `rpm-dump.txt` |
| `brec verify` | отчёт по зависимостям: статика, динамика, сверка с upstream |
| `brec sbom` | CycloneDX SBOM и CVE-отчёт по вендорированным компонентам |
| `brec verdict` | вердикт «собрано из исходников»: GREEN / RED / GREY |
| `brec buildreq` | объявленные BuildRequires против фактически прочитанных |
| `brec report` | сводка по сырой трассе: процессы, языки, артефакты |

Внешних зависимостей у CLI нет: все подкоманды читают трассу через
`brec.model`, разбирающий Turtle за один проход. rdflib нужен только для
ad-hoc SPARQL-запросов вручную (см. ниже).

### Формат файла

Каждая строка — тройка `субъект предикат объект .`:

```turtle
:p0   a         b:process .
:p0   b:cmd     "make -j6" .
:p0   b:start   "2026-05-30T10:13:51Z" .

:f0   a         b:file .
:f0   b:abspath "/build/src/src/server.c" .
:f0   b:hash    "a3f1c2..." .

:p42  b:reads   :f0 .
:p42  b:writes  :f1 .
:p0   b:creates :p42 .
```

**Предикаты:**

| Предикат | Тип | Описание |
|---------|-----|---------|
| `b:cmd` | строка | Командная строка процесса |
| `b:start` / `b:end` | datetime | Время запуска/завершения |
| `b:abspath` | строка | Абсолютный путь к файлу |
| `b:hash` | строка | SHA1 содержимого (git-совместимый) |
| `b:reads` | ссылка | Процесс читал файл |
| `b:writes` | ссылка | Процесс записал файл |
| `b:creates` | ссылка | Процесс породил подпроцесс |
| `b:executable` | ссылка | Исполняемый файл процесса |
| `b:rename` | ссылка | Переименование файла |
| `b:hardlink` | ссылка | Жёсткая ссылка (новое имя, то же содержимое и хеш) |
| `b:coverage_gap` | строка | Процесс применял I/O, недоступный наблюдению (`"io_uring"`) |

### Автономный анализатор: `brec report`

```bash
# Полный анализ в консоль (зависимостей нет)
python3 -m brec report file.out

# Конкретный запрос
python3 -m brec report file.out --query languages
python3 -m brec report file.out --query tools
python3 -m brec report file.out --query externals
python3 -m brec report file.out --query libs
python3 -m brec report file.out --query sources

# Markdown-отчёт (сохраняется рядом с .out)
python3 -m brec report file.out --report

# Отчёт в файл без вывода в консоль
python3 -m brec report file.out --report report.md --quiet
```

**Доступные запросы:**

| Запрос | Что показывает |
|--------|---------------|
| `stats` | Количество процессов, файлов, reads/writes |
| `timeline` | Временной диапазон, длительность сборки |
| `languages` | Компиляторы, исходники по расширениям |
| `tools` | Утилиты и пакеты с числом инвокаций |
| `externals` | Готовые бинари и .so, не собранные в этом билде |
| `sources` | Исходные файлы проекта (.c/.cpp) |
| `artifacts` | Все записанные артефакты по расширениям |
| `libs` | Собранные .so/.a с SHA1-хэшами |
| `tree` | Дерево процессов (2 уровня) |
| `headers` | Топ системных заголовков по числу включений |

### Вердикт «собрано из исходников» (`brec verdict`)

Отвечает на вопрос, ради которого инструмент и существует: собран ли пакет
полностью из исходных текстов, без инкорпорации ранее скомпилированных бинарных
файлов. Вердикт по каждому файлу: 🟢 GREEN (родословная упирается только в
исходники и файлы OS-пакетов), 🔴 RED (инкорпорирован чужой прекомпилят),
⚪ GREY (инструмент не может утверждать). Вердикт пакета GREEN только при нуле
RED и нуле GREY.

```bash
# Минимально: только по наблюдённым файлам
python3 -m brec verdict build.out

# Как надо: с атрибуцией пакетов и сверкой того, что реально уезжает
rpm -qa --qf '[%{FILENAMES}\t%{NAME}\t%{NEVRA}\n]' > rpm-dump.txt
python3 -m brec verdict build.out \
    --rpm-dump rpm-dump.txt \
    --payload ~/RPM/BUILDROOT/pkg-1.0-alt1.x86_64 \
    --json verdict.json
```

**Коды возврата:** `0` GREEN, `1` RED, `3` GREY, `2` ошибка аргументов.

**`--rpm-dump` обязателен на практике.** Без атрибуции пакетов системные
библиотеки (`libc.so.6` и подобные) выглядят как чужие прекомпиляты и дают
ложный RED. Альтернатива: заранее прогнать `python3 -m brec enrich <out> <rpm-dump>`, тогда
атрибуция уже вшита в `.out`.

**`--payload` определяет, о чём вообще утверждение.** Без него вердикт говорит
только про файлы, попавшие в граф: файл, записанный ненаблюдённым каналом, не
станет GREY, он просто отсутствует, и его молчание читается как «замечаний нет».
С `--payload` каждый поставляемый файл сверяется с графом **по хешу
содержимого**, поэтому сверка не зависит от путей: распакованный пакет или
перенесённый buildroot сходятся так же, как исходный.

Принимаются:

| Аргумент | Что делает |
|----------|-----------|
| каталог (buildroot, распакованный пакет) | обход дерева, сверка по содержимому |
| файл со списком путей (`rpm -qpl pkg.rpm > files.list`) | сверка по содержимому там, где файл доступен локально, иначе только по пути |

Что означают вердикты для поставляемого файла:

| Строка отчёта | Что произошло |
|---------------|---------------|
| `content is a build output flagged RED/GREY` | файл поставляется, но его источник в графе проблемный |
| `content matches a file the build only read, never wrote` | содержимое видели как вход, но копирование в payload не наблюдалось |
| `content differs from every observed version of this path` | файл правили после последней наблюдённой записи |
| `not present in the build graph` | файл уехал в пакет, а сборка его не записывала: ненаблюдённый канал |

Символические ссылки пропускаются (своего содержимого не имеют), их число
показано отдельно. Файлы из списка, недоступные локально, проверяются только по
пути и учитываются строкой `checked by path only`.

**Разрывы покрытия.** Если трасса содержит `b:coverage_gap` (io_uring), GREEN
недоступен в принципе: файловый слой заведомо неполон, и молчание графа
доказательством не является. Выходы такого процесса понижаются до GREY, а сам
разрыв печатается отдельным блоком с командной строкой виновного процесса.

Полная формулировка гарантии, допущения и перечень открытых путей:
`doc/threat-model.md`.

### Сверка BuildRequires с фактически прочитанным (`brec buildreq`)

Spec говорит, что пакету нужно для сборки; трасса говорит, что сборка открыла.
Инструмент сравнивает две стороны и печатает расхождения:

| Блок отчёта | Что значит |
|-------------|-----------|
| `USED, NOT DECLARED` | сборка читала файлы пакета, который не объявляла. Сработало потому, что пакет случайно оказался в этом окружении; на более скудном сборка сломается |
| `DECLARED, NOT READ` | пакет тянется в каждое сборочное окружение и ни разу не открывается |
| `DECLARED, SATISFIED INDIRECTLY` | сам объявленный пакет не открывался, но открывалась его зависимость. Так выглядит пакет-обёртка: на ALT объявлен `gcc`, а читается `gcc13` |
| `USED VIA CLOSURE` | пакет не объявлен, но входит в транзитивное замыкание объявленного. Сегодня законно, завтра ломается, если чужая зависимость исчезнет. В строке указано, какое объявление к нему ближе всего |
| `UNRESOLVED CAPABILITIES` | объявлено, но ничего установленного этого не предоставляет: в этом окружении такого пакета нет |

```bash
# Все три входа контейнер кладёт рядом с трассой в режиме SRPM
python3 -m brec buildreq build.out \
    --declared builddeps-declared.txt \
    --rpm-deps rpm-deps.txt \
    --rpm-dump rpm-dump.txt \
    --implicit rpm-build \
    --json buildreq.json
```

| Аргумент | Откуда берётся | Зачем |
|----------|----------------|-------|
| `--declared` | `rpm -qp --requires pkg.src.rpm` | объявленная сторона, одна возможность на строку |
| `--rpm-deps` | `rpm -qa --qf '[P\t%{PROVIDENAME}\t%{NAME}\n]'` плюс `[R\t%{NAME}\t%{REQUIRENAME}\n]` | транзитивное замыкание. Без него всё, что использовано косвенно, попадёт в `USED, NOT DECLARED` |
| `--rpm-dump` | `rpm -qa --qf '[%{FILENAMES}\t%{NAME}\t%{NEVRA}\n]'` | атрибуция файлов, если трасса не прогнана через `brec enrich`, и резолв файловых возможностей (`/bin/sh`) |
| `--implicit` | имя пакета, повторяемо | пакеты, которые есть в любом сборочном окружении. Для ALT передавать `rpm-build`: иначе `glibc-devel`, `gcc-common` и остальная база заполнят список недообъявленного |
| `--indirect-depth` | число, по умолчанию 1 | на сколько шагов зависимости объявлению засчитывается чужое чтение. Единица покрывает обёртки (`gcc` → `gcc13`). Больше ставить незачем: на второй-третий шаг любое `-devel` дотягивается до тулчейна, и тогда удовлетворённым выглядит всё подряд |

`--strict` возвращает код 1, когда что-то использовано без объявления (для CI).

**Атрибуция косвенного это подсказка, а не вердикт.** Строки
`SATISFIED INDIRECTLY` и `← объявление` в блоке замыкания говорят «читалась
зависимость объявленного пакета», а не «объявление было нужно». Твёрдые сигналы
дают два первых блока: использовано без объявления и объявлено без единого чтения.

**Что читать с оговорками.** Трасса `rpmbuild -bc` покрывает `%prep` и `%build`,
поэтому зависимости, нужные только в `%install` или `%check`, честно выглядят
неиспользованными. Контейнер собирает с `--nodeps`, то есть объявленные
зависимости в образ не доустанавливаются: отсюда содержательный блок
`UNRESOLVED CAPABILITIES`, он показывает разрыв между spec и образом. Пакет
может быть объявлен законно и не читаться, если он нужен собранному пакету во
время исполнения, а не при сборке.

### SPARQL через rdflib

Сам `brec report` больше не требует rdflib: он читает трассу через
`brec.model`. Но трасса остаётся RDF Turtle, и для разовых вопросов, на
которые нет готовой подкоманды, SPARQL по-прежнему уместен: поставьте
`pip3 install rdflib` и спрашивайте файл напрямую.

```python
import rdflib

g = rdflib.Graph()
g.parse("redis-build.out", format="turtle")

# Все скомпилированные .c файлы
results = g.query("""
PREFIX b: <http://build-recorder.org/rdf#>
SELECT DISTINCT ?path WHERE {
    ?proc a b:process ; b:reads ?file . ?file b:abspath ?path .
    FILTER(STRENDS(STR(?path), ".c"))
}
ORDER BY ?path
""")
for (path,) in results:
    print(path)
```

---

## Настройка образа под пакет

Если проект требует зависимостей, которых нет в базовом образе, добавьте их
в `docker/Dockerfile` и пересоберите образ.

### Добавление пакетов

Откройте `docker/Dockerfile`, найдите блок `apt-get install` и добавьте нужные пакеты:

```dockerfile
RUN apt-get update -q && \
    apt-get install -y -q \
        rpm-build cmake make gcc-c++ git \
        libssl-devel libsystemd-devel zlib-devel \
        # --- добавьте сюда ---
        libsqlite3-devel \
        libyaml-devel \
        python3-devel \
        # --------------------
        && apt-get clean
```

После изменения пересоберите образ:

```bash
docker build -f docker/Dockerfile -t build-recorder:latest .
```

### Пример: проект с Python-расширениями

```bash
# Добавить в Dockerfile: python3-devel python3-module-setuptools
# Затем:
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  -v ~/build-recorder-out/myproject:/output \
  -e GIT_URL=https://github.com/example/myproject \
  -e GIT_BUILD_CMD="python3 setup.py build_ext --inplace" \
  -e OUTPUT_DIR=/output \
  build-recorder:latest
```

---

## Справочник переменных

| Переменная | Режим | Описание |
|-----------|-------|---------|
| `GIT_URL` | git | URL репозитория (https или git://) |
| `GIT_REF` | git | Ветка, тег или коммит (по умолчанию HEAD) |
| `GIT_BUILD_CMD` | git | Команда сборки (переопределяет автоопределение) |
| `SRPM` | srpm | Путь к .src.rpm внутри контейнера |
| `OUTPUT_DIR` | оба | Директория для выходного файла (по умолчанию `/output`) |

---

## Диагностика

### `ptrace: Operation not permitted`

Не указан `--cap-add=SYS_PTRACE` или `--security-opt seccomp:unconfined`.

```bash
# Проверить, что флаги переданы:
docker run --rm \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp:unconfined \
  ...
```

### `Unknown build system`

Проект использует нестандартную структуру. Передайте команду явно:

```bash
-e GIT_BUILD_CMD="./build.sh --prefix=/usr"
```

### `E: Couldn't find package X`

Проекту нужна библиотека, которой нет в образе. Добавьте в `docker/Dockerfile`
и пересоберите.

### `BadSyntax` при анализе .out файла

Файл собран старой версией build-recorder (до исправления экранирования строк).
Пересоберите проект с актуальным образом.

### Образ не видит изменений в entrypoint.sh

Entrypoint копируется в образ при сборке. После изменения файла нужно пересобрать:

```bash
docker build -f docker/Dockerfile -t build-recorder:latest .
```

### Сборка Redis зависает на jemalloc

jemalloc требует `/proc`. Добавьте `--tmpfs /proc` или убедитесь, что `/proc`
примонтирован в контейнере (по умолчанию Docker монтирует его).

---

## Структура проекта

```
build-recorder/
├── src/
│   ├── main.c          # точка входа, разбор аргументов
│   ├── tracer.c        # ptrace-цикл, обработка syscall'ов
│   ├── record.c        # запись RDF-троек в файл
│   └── hash.c          # SHA1-хэш файлов через OpenSSL
├── doc/
│   ├── build-recorder-schema.ttl   # RDF-онтология (встраивается в .out)
│   └── output.md       # описание формата вывода
├── docker/
│   ├── Dockerfile      # multi-stage: сборка build-recorder + runtime
│   ├── entrypoint.sh   # логика запуска (git / srpm режимы)
│   └── docker-compose.yml
└── brec/               # анализ трассы: пакет и CLI `python3 -m brec`
    ├── cli.py          # диспетчер подкоманд
    └── commands/       # enrich, verify, sbom, verdict, buildreq, report
```
