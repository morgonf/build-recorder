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
| `open`, `openat`, `creat` | чтение и запись файлов |
| `close` | финальный SHA1-хэш записанного файла |
| `execve`, `execveat` | запуск исполняемых файлов |
| `fork`, `vfork`, `clone` | создание дочерних процессов |
| `rename`, `renameat` | переименование файлов |

Сборка запускается в Docker-контейнере на базе ALT Linux p11, что обеспечивает
изолированное воспроизводимое окружение.

**Требования к хосту:** Docker 20+, Linux-ядро ≥ 5.3 (нужен `PTRACE_GET_SYSCALL_INFO`).

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
python3 /home/user/claude/build-recorder/build-report.py \
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

### Автономный анализатор build-report.py

```bash
# Установить зависимость (один раз)
pip3 install rdflib

# Полный анализ в консоль
python3 build-report.py file.out

# Конкретный запрос
python3 build-report.py file.out --query languages
python3 build-report.py file.out --query tools
python3 build-report.py file.out --query externals
python3 build-report.py file.out --query libs
python3 build-report.py file.out --query sources

# Markdown-отчёт (сохраняется рядом с .out)
python3 build-report.py file.out --report

# Отчёт в файл без вывода в консоль
python3 build-report.py file.out --report report.md --quiet
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

### SPARQL через rdflib

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
└── build-report.py     # автономный SPARQL-анализатор
```
