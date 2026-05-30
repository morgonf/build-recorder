#!/bin/bash
set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-/output}"

# ── Определение режима ────────────────────────────────────────────────────────

if [[ -n "${GIT_URL:-}" ]]; then
    MODE="git"
elif [[ -n "${SRPM:-}" ]]; then
    MODE="srpm"
else
    echo "ERROR: укажите GIT_URL (git-репозиторий) или SRPM (путь к .src.rpm)" >&2
    echo ""
    echo "  Git:  docker run -e GIT_URL=https://github.com/user/repo ..."
    echo "  SRPM: docker run -e SRPM=/srpms/pkg.src.rpm ..."
    exit 1
fi

# ── Режим: git-репозиторий ────────────────────────────────────────────────────

build_from_git() {
    local url="${GIT_URL}"
    local ref="${GIT_REF:-}"
    local build_cmd="${GIT_BUILD_CMD:-}"

    local pkg_name
    pkg_name=$(basename "${url%.git}")
    local output_file="${OUTPUT_DIR}/${pkg_name}-build.out"

    echo "=== Клонирование: $url ==="
    local clone_args=(--depth=1)
    [[ -n "$ref" ]] && clone_args+=(--branch "$ref")
    git clone "${clone_args[@]}" "$url" /build/src
    cd /build/src

    # Автоопределение системы сборки
    if [[ -z "$build_cmd" ]]; then
        if [[ -f CMakeLists.txt ]]; then
            build_cmd="cmake -B _build -DCMAKE_BUILD_TYPE=Release . && make -C _build -j$(nproc)"
        elif [[ -f autogen.sh ]]; then
            build_cmd="./autogen.sh && ./configure && make -j$(nproc)"
        elif [[ -f configure.ac ]]; then
            build_cmd="autoreconf -i && ./configure && make -j$(nproc)"
        elif [[ -f configure ]]; then
            build_cmd="./configure && make -j$(nproc)"
        elif [[ -f Makefile ]]; then
            build_cmd="make -j$(nproc)"
        elif [[ -f meson.build ]]; then
            build_cmd="meson setup _build && ninja -C _build"
        else
            echo "ERROR: не удалось определить систему сборки" >&2
            echo "  Установите GIT_BUILD_CMD вручную" >&2
            exit 1
        fi
    fi

    echo "=== Starting build-recorder + build ==="
    echo "    Repo       : $url${ref:+ @ $ref}"
    echo "    Build cmd  : $build_cmd"
    echo "    Output     : $output_file"
    echo ""

    build-recorder -o "$output_file" sh -c "$build_cmd"

    echo ""
    echo "=== Build complete ==="
    echo "    Triples  : $(grep -c '\.' "$output_file" 2>/dev/null || echo 0)"
    echo "    Processes: $(grep -c 'a.*b:process' "$output_file" 2>/dev/null || echo 0)"
    echo "    Files    : $(grep -c 'a.*b:file' "$output_file" 2>/dev/null || echo 0)"
    echo "    Size     : $(du -sh "$output_file" | cut -f1)"
    echo ""
    echo "Output: $output_file"
}

# ── Режим: SRPM ───────────────────────────────────────────────────────────────

build_from_srpm() {
    if [[ ! -f "$SRPM" ]]; then
        echo "ERROR: SRPM не найден: $SRPM" >&2
        exit 1
    fi

    local pkg_name
    pkg_name=$(rpm -qp --qf '%{NAME}' "$SRPM" 2>/dev/null)
    local output_file="${OUTPUT_DIR}/${pkg_name}-build.out"

    echo "=== Installing SRPM: $(basename "$SRPM") ==="
    rpm -i --nodeps "$SRPM" 2>&1 | grep -v "does not exist - using root" || true

    local topdir
    topdir="$(rpm --eval '%_topdir')"
    local spec
    spec=$(find "$topdir/SPECS" -name '*.spec' | head -1)

    if [[ -z "$spec" ]]; then
        echo "ERROR: spec не найден в $topdir/SPECS" >&2
        exit 1
    fi

    # Вырезаем %check (rpm 4.13 не поддерживает --nocheck)
    awk '
        /^%check/ { print "%check"; print "exit 0"; skip=1; next }
        skip && /^%[a-zA-Z_]/ { skip=0; print; next }
        !skip { print }
    ' "$spec" > "${spec}.nocheck" && mv "${spec}.nocheck" "$spec"

    echo "=== Starting build-recorder + rpmbuild ==="
    echo "    Package  : $pkg_name"
    echo "    Spec     : $spec"
    echo "    Output   : $output_file"
    echo ""

    build-recorder -o "$output_file" \
        rpmbuild --nodeps --define '_allow_root_build 1' -bc "$spec"

    echo ""
    echo "=== Build complete ==="
    echo "    Triples  : $(grep -c '\.' "$output_file" 2>/dev/null || echo 0)"
    echo "    Processes: $(grep -c 'a.*b:process' "$output_file" 2>/dev/null || echo 0)"
    echo "    Files    : $(grep -c 'a.*b:file' "$output_file" 2>/dev/null || echo 0)"
    echo "    Size     : $(du -sh "$output_file" | cut -f1)"
    echo ""
    echo "Output: $output_file"
}

# ── Запуск ────────────────────────────────────────────────────────────────────

case "$MODE" in
    git)  build_from_git  ;;
    srpm) build_from_srpm ;;
esac
