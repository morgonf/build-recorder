# Stage 1: compile build-recorder
FROM registry.altlinux.org/alt/alt:p11 AS builder

RUN apt-get update -q && \
    apt-get install -y -q \
        gcc \
        make \
        autoconf \
        automake \
        xxd \
        libssl-devel

WORKDIR /src
COPY . .

RUN autoreconf -i && \
    ./configure && \
    make -C src

# Stage 2: demo environment — build under build-recorder
FROM registry.altlinux.org/alt/alt:p11

# Build tools: SRPM + CMake/autotools/meson + Bazel
RUN apt-get update -q && \
    apt-get install -y -q \
        rpm-build \
        cmake \
        make \
        gcc-c++ \
        git \
        libcheck-devel \
        zlib-devel \
        libssl-devel \
        libsystemd-devel \
        libduktape-devel \
        liblua5.3-devel \
        iproute2 \
        ctest \
        python3 \
        clang \
        curl \
        unzip \
        zip \
        patch \
        java-17-openjdk-headless && \
    apt-get clean

# Install Bazelisk — auto-downloads the correct Bazel version per .bazelversion
ARG BAZELISK_VERSION=1.29.0
RUN curl -fsSL \
      "https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-amd64" \
      -o /usr/local/bin/bazel && \
    chmod +x /usr/local/bin/bazel && \
    # Symlink for projects that call bazelisk explicitly
    ln -s /usr/local/bin/bazel /usr/local/bin/bazelisk

# Bazel cache location (can be bind-mounted for persistence across runs)
ENV BAZEL_CACHE_DIR=/bazel-cache
RUN mkdir -p /bazel-cache
VOLUME ["/bazel-cache"]

COPY --from=builder /src/build-recorder /usr/local/bin/build-recorder

RUN mkdir -p /output /srpms

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /root
ENTRYPOINT ["/entrypoint.sh"]
