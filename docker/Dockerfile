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

# Stage 2: demo environment — civetweb build under build-recorder
FROM registry.altlinux.org/alt/alt:p11

# Build tools: SRPM mode + git mode
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
        python3 && \
    apt-get clean

COPY --from=builder /src/build-recorder /usr/local/bin/build-recorder

RUN mkdir -p /output /srpms

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /root
ENTRYPOINT ["/entrypoint.sh"]
