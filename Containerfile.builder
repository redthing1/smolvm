FROM docker.io/library/rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1

ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_TOOLCHAIN=1.95.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bc \
        bison \
        build-essential \
        ca-certificates \
        clang \
        cpio \
        curl \
        dwarves \
        e2fsprogs \
        file \
        flex \
        git \
        kmod \
        libclang-dev \
        libdrm-dev \
        libelf-dev \
        libepoxy-dev \
        libgbm-dev \
        libncurses-dev \
        libssl-dev \
        libvirglrenderer-dev \
        pkg-config \
        python3 \
        python3-pyelftools \
        tar \
        xz-utils \
    && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/*
