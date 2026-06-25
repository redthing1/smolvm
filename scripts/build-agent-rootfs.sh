#!/bin/bash
# Build the agent VM rootfs
#
# This script creates an Alpine-based rootfs with:
# - crane (for OCI image operations)
# - crun (OCI container runtime)
# - smolvm-agent daemon
# - Required utilities (jq, e2fsprogs, util-linux)
#
# Usage: ./scripts/build-agent-rootfs.sh [--arch aarch64|x86_64] [--no-build-agent] [--install] [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Parse flags
INSTALL_ROOTFS=0
OVERRIDE_ARCH=""
NO_BUILD_AGENT=0
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --install) INSTALL_ROOTFS=1; shift ;;
        --arch)
            if [[ -z "${2:-}" ]]; then
                echo "Error: --arch requires a value (aarch64 or x86_64)"
                exit 1
            fi
            OVERRIDE_ARCH="$2"; shift 2 ;;
        --no-build-agent) NO_BUILD_AGENT=1; shift ;;
        *) POSITIONAL_ARGS+=("$1"); shift ;;
    esac
done
export INSTALL_ROOTFS

OUTPUT_DIR="${POSITIONAL_ARGS[0]:-$PROJECT_ROOT/target/agent-rootfs}"
CACHE_DIR="${SMOLVM_ROOTFS_CACHE:-$PROJECT_ROOT/target/rootfs-cache}"

# Pinned rootfs bootstrap inputs.
ALPINE_VERSION="3.23"
ALPINE_PATCH_VERSION="4"
APK_TOOLS_STATIC_VERSION="3.0.6-r0"
CRANE_VERSION="0.19.0"

# Detect or override architecture
DETECTED_ARCH="${OVERRIDE_ARCH:-$(uname -m)}"
case "$DETECTED_ARCH" in
    arm64|aarch64)
        ALPINE_ARCH="aarch64"
        CRANE_ARCH="arm64"
        RUST_TARGET="aarch64-unknown-linux-musl"
        ;;
    x86_64|amd64)
        ALPINE_ARCH="x86_64"
        CRANE_ARCH="x86_64"
        RUST_TARGET="x86_64-unknown-linux-musl"
        ;;
    *)
        echo "Unsupported architecture: $DETECTED_ARCH"
        exit 1
        ;;
esac

ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ALPINE_MINIROOTFS="alpine-minirootfs-${ALPINE_VERSION}.${ALPINE_PATCH_VERSION}-${ALPINE_ARCH}.tar.gz"
ALPINE_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ALPINE_ARCH}/${ALPINE_MINIROOTFS}"

CRANE_URL="https://github.com/google/go-containerregistry/releases/download/v${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz"

pinned_alpine_minirootfs_sha256() {
    case "$ALPINE_ARCH" in
        x86_64)  echo "85498865362aa7ebececa0d725a2f2e4db7ac4e4b2850b8df21645afa0d03ee3" ;;
        aarch64) echo "9250667a8affac8f1e98086392f80f43f086626701e9bce33398eb9b6c0bd64c" ;;
        *) echo "unsupported Alpine arch for minirootfs checksum: $ALPINE_ARCH" >&2; exit 1 ;;
    esac
}

pinned_crane_sha256() {
    case "$CRANE_ARCH" in
        x86_64) echo "daa629648e1d1d10fc8bde5e6ce4176cbc0cd48a32211b28c3fd806e0fa5f29b" ;;
        arm64)  echo "d439957c1a9d6bc0870be921e25753a7fa67bf2b2691b77ce48a6fc25bc719a0" ;;
        *) echo "unsupported crane arch for checksum: $CRANE_ARCH" >&2; exit 1 ;;
    esac
}

pinned_apk_static_sha256() {
    case "$1" in
        x86_64)  echo "a51144e51387e60900e1cad6b4e4ae04d48c8d87ac83c9a4190d2f113a07ce72" ;;
        aarch64) echo "1f3de9109eaba4a271c1b3a5fedee3b6442e6b3bf5695d5e5f8286aeece0461f" ;;
        *) echo "unsupported host arch for apk.static checksum: $1" >&2; exit 1 ;;
    esac
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "Error: sha256sum or shasum is required" >&2
        exit 1
    fi
}

verify_sha256() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(sha256_file "$path")"
    if [[ "$actual" != "$expected" ]]; then
        echo "Error: checksum mismatch for $path" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
}

download_pinned() {
    local url="$1"
    local path="$2"
    local expected_sha="$3"

    mkdir -p "$(dirname "$path")"
    if [[ -f "$path" ]]; then
        verify_sha256 "$path" "$expected_sha"
        return
    fi

    local tmp="${path}.tmp.$$"
    rm -f "$tmp"
    curl -fsSL -o "$tmp" "$url"
    verify_sha256 "$tmp" "$expected_sha"
    mv "$tmp" "$path"
}

echo "Building agent rootfs..."
echo "  Alpine: ${ALPINE_VERSION} (${ALPINE_ARCH})"
echo "  Crane: ${CRANE_VERSION}"
echo "  Output: ${OUTPUT_DIR}"
echo "  Cache: ${CACHE_DIR}"

# Create output directory
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Download Alpine minirootfs
echo "Downloading Alpine minirootfs..."
ALPINE_TAR="${CACHE_DIR}/${ALPINE_MINIROOTFS}"
download_pinned "$ALPINE_URL" "$ALPINE_TAR" "$(pinned_alpine_minirootfs_sha256)"

# Extract Alpine
echo "Extracting Alpine..."
tar -xzf "$ALPINE_TAR" -C "$OUTPUT_DIR"

# Download crane
echo "Downloading crane..."
CRANE_TAR="${CACHE_DIR}/go-containerregistry_Linux_${CRANE_ARCH}-${CRANE_VERSION}.tar.gz"
download_pinned "$CRANE_URL" "$CRANE_TAR" "$(pinned_crane_sha256)"

# Extract crane to rootfs
echo "Installing crane..."
mkdir -p "$OUTPUT_DIR/usr/local/bin"
tar -xzf "$CRANE_TAR" -C "$OUTPUT_DIR/usr/local/bin" crane

# Install additional Alpine packages into the rootfs.
echo "Installing additional packages..."
APK_PACKAGES=(
    "jq"
    "e2fsprogs"
    "e2fsprogs-extra"
    "crun"
    "util-linux"
    "libcap"
    "seatd"
)

# Determine if this is a cross-arch build
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64|aarch64) HOST_ALPINE_ARCH="aarch64" ;;
    amd64|x86_64)  HOST_ALPINE_ARCH="x86_64" ;;
    *)     HOST_ALPINE_ARCH="$HOST_ARCH" ;;
esac
CROSS_ARCH=0
if [[ "$ALPINE_ARCH" != "$HOST_ALPINE_ARCH" ]]; then
    CROSS_ARCH=1
fi

install_packages_apk_static() {
    echo "  Using apk.static..."
    local apk_static_pkg="apk-tools-static-${APK_TOOLS_STATIC_VERSION}.apk"
    local apk_static_url="${ALPINE_MIRROR}/v${ALPINE_VERSION}/main/${HOST_ALPINE_ARCH}/${apk_static_pkg}"
    local apk_static_apk="${CACHE_DIR}/${HOST_ALPINE_ARCH}-${apk_static_pkg}"
    local apk_static_dir="${CACHE_DIR}/apk-static-${HOST_ALPINE_ARCH}-${APK_TOOLS_STATIC_VERSION}"

    download_pinned "$apk_static_url" "$apk_static_apk" "$(pinned_apk_static_sha256 "$HOST_ALPINE_ARCH")"
    rm -rf "$apk_static_dir"
    mkdir -p "$apk_static_dir"
    if tar --version 2>/dev/null | grep -q "GNU tar"; then
        tar --warning=no-unknown-keyword -xzf "$apk_static_apk" -C "$apk_static_dir" sbin/apk.static
    else
        tar -xzf "$apk_static_apk" -C "$apk_static_dir" sbin/apk.static
    fi

    # Set up apk repositories in the rootfs
    mkdir -p "$OUTPUT_DIR/etc/apk"
    echo "${ALPINE_MIRROR}/v${ALPINE_VERSION}/main" > "$OUTPUT_DIR/etc/apk/repositories"
    echo "${ALPINE_MIRROR}/v${ALPINE_VERSION}/community" >> "$OUTPUT_DIR/etc/apk/repositories"

    local apk_cmd=("$apk_static_dir/sbin/apk.static")
    if command -v unshare >/dev/null 2>&1 && unshare -r true >/dev/null 2>&1; then
        apk_cmd=(unshare -r "$apk_static_dir/sbin/apk.static")
    fi

    local rootfs_world=()
    local package
    while IFS= read -r package; do
        if [[ -n "$package" ]]; then
            rootfs_world+=("$package")
        fi
    done < "$OUTPUT_DIR/etc/apk/world"

    # --no-scripts: skip pre/post-install scripts and triggers.
    # When cross-building (e.g. aarch64 rootfs on x86_64 host), those scripts
    # are aarch64 ELF binaries that the host kernel can't exec, causing exit
    # code 127. The minirootfs already ships busybox symlinks, and seatd runs
    # as root in the VM so the 'seat' group creation is not required.
    "${apk_cmd[@]}" \
        --root "$OUTPUT_DIR" \
        --no-cache \
        --allow-untrusted \
        --no-scripts \
        --arch "$ALPINE_ARCH" \
        add --upgrade --no-chown "${rootfs_world[@]}" "${APK_PACKAGES[@]}"
    echo "Packages installed successfully"
}

repair_executable_modes() {
    local rootfs_dir="$1"
    local dirs=(
        "$rootfs_dir/bin"
        "$rootfs_dir/sbin"
        "$rootfs_dir/usr/bin"
        "$rootfs_dir/usr/sbin"
        "$rootfs_dir/usr/local/bin"
        "$rootfs_dir/usr/local/sbin"
    )

    echo "Normalizing executable permissions..."
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            continue
        fi

        # On the macOS build path, apk install into the host-mounted rootfs can
        # strip execute bits from package-installed guest tools. We observed
        # this on crun, resize2fs, and e2fsck, and the failures only surfaced
        # later during packed/container execution. These directories are the
        # standard executable locations in the guest rootfs, so normalize their
        # contents before install/pack preserves the bad modes.
        find "$dir" -type d -exec chmod 755 {} +
        find "$dir" -type f -exec chmod 755 {} +
    done
}

print_words() {
    local sep=""
    local word
    for word in "$@"; do
        printf "%s%s" "$sep" "$word"
        sep=" "
    done
}

print_file_lines() {
    local path="$1"
    local sep=""
    local line

    if [[ ! -f "$path" ]]; then
        return
    fi

    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        printf "%s%s" "$sep" "$line"
        sep=" "
    done < "$path"
}

print_installed_apk_packages() {
    local db="$OUTPUT_DIR/lib/apk/db/installed"
    if [[ ! -f "$db" ]]; then
        return
    fi

    awk -F: '/^P:/ { package = $2 } /^V:/ { if (package != "") { print package "=" $2; package = "" } }' "$db" \
        | sort \
        | awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = " " }'
}

write_build_manifest() {
    local manifest="$OUTPUT_DIR/etc/smolvm-rootfs-build.txt"
    {
        echo "alpine_version=${ALPINE_VERSION}.${ALPINE_PATCH_VERSION}"
        echo "alpine_arch=${ALPINE_ARCH}"
        echo "alpine_minirootfs=${ALPINE_MINIROOTFS}"
        echo "alpine_minirootfs_sha256=$(pinned_alpine_minirootfs_sha256)"
        echo "apk_tools_static_version=${APK_TOOLS_STATIC_VERSION}"
        echo "apk_tools_static_host_arch=${HOST_ALPINE_ARCH}"
        echo "apk_tools_static_sha256=$(pinned_apk_static_sha256 "$HOST_ALPINE_ARCH")"
        echo "crane_version=${CRANE_VERSION}"
        echo "crane_arch=${CRANE_ARCH}"
        echo "crane_sha256=$(pinned_crane_sha256)"
        printf "apk_requested_packages="
        print_words "${APK_PACKAGES[@]}"
        echo
        printf "apk_world_packages="
        print_file_lines "$OUTPUT_DIR/etc/apk/world"
        echo
        printf "apk_installed_packages="
        print_installed_apk_packages
        echo
    } > "$manifest"
}

if [[ "$(uname -s)" == "Linux" ]]; then
    # On Linux, apk.static is preferred — it handles cross-arch correctly
    install_packages_apk_static
elif [[ "$CROSS_ARCH" == "1" ]]; then
    echo "Error: cross-arch rootfs builds (--arch $ALPINE_ARCH on $HOST_ALPINE_ARCH host)"
    echo "       are only supported on Linux (uses apk.static)."
    echo "       On macOS, omit --arch or use the same architecture as your host."
    exit 1
elif command -v smolvm &> /dev/null; then
    echo "  Using smolvm..."
    smolvm machine run --net -v "$OUTPUT_DIR:/rootfs" --image "alpine:${ALPINE_VERSION}" \
        -- sh -c 'apk add --root /rootfs --no-cache --no-scripts --upgrade --no-chown $(cat /rootfs/etc/apk/world) "$@"' \
        sh "${APK_PACKAGES[@]}"
    echo "Packages installed successfully"
else
    echo "Error: smolvm is required to build the agent rootfs on macOS"
    echo "Build and install this checkout first with: ./scripts/install.sh"
    exit 1
fi

repair_executable_modes "$OUTPUT_DIR"
write_build_manifest

# Create necessary directories
mkdir -p "$OUTPUT_DIR/storage"
mkdir -p "$OUTPUT_DIR/etc/init.d"
mkdir -p "$OUTPUT_DIR/run"

# Bake in the agent's /mnt mount points so the rootfs is self-sufficient.
#
# At boot, setup_persistent_rootfs() (crates/smolvm-agent/src/main.rs) mounts
# the overlay/storage disks and stages pivot_root under these paths BEFORE any
# writable overlay exists — its create_dir_all() calls run against the agent
# rootfs itself. On a read-only rootfs, or one built from scratch without the
# Alpine base's empty /mnt, those mkdirs fail, the mounts fail, and the VM
# boots without its persistent overlay. Pre-creating the dirs here makes those
# runtime create_dir_all() calls a no-op (the agent keeps them as a backstop
# and WARNs if a mount point is ever missing on a RO rootfs).
#
# Keep this list in sync with the agent's mount-point constants:
#   /mnt/overlay  OVERLAY_MOUNT       } setup_persistent_rootfs(), required at
#   /mnt/storage  STORAGE_TEMP_MOUNT  } boot before the overlay is writable
#   /mnt/newroot  NEWROOT             }
#   /mnt/rosetta  vm::rosetta::ROSETTA_GUEST_PATH  macOS Rosetta binfmt share
#   /run/smolvm/virtiofs paths::VIRTIOFS_MOUNT_ROOT  parent for per-tag virtiofs shares
for mnt_dir in overlay storage newroot rosetta; do
    mkdir -p "$OUTPUT_DIR/mnt/$mnt_dir"
done
mkdir -p "$OUTPUT_DIR/run/smolvm/virtiofs"

# Remove existing init (it's a symlink to busybox) and replace with
# symlink to the agent binary. The agent handles overlayfs setup +
# pivot_root internally before starting the vsock listener.
rm -f "$OUTPUT_DIR/sbin/init"
ln -sf /usr/local/bin/smolvm-agent "$OUTPUT_DIR/sbin/init"

# Create resolv.conf
echo "nameserver 1.1.1.1" > "$OUTPUT_DIR/etc/resolv.conf"

# Remove seatd socket if baked in during build (build artifact, not runtime state)
rm -f "$OUTPUT_DIR/run/seatd.sock"

PROFILE="release-small"

if [[ -n "${AGENT_BINARY:-}" ]] && [[ -f "${AGENT_BINARY}" ]]; then
    echo "Using agent binary: $AGENT_BINARY"
elif [[ "$NO_BUILD_AGENT" == "1" ]]; then
    echo "Skipping agent build (--no-build-agent)"
else
    AGENT_BINARY=""

    if command -v cargo &> /dev/null && rustup target list --installed 2>/dev/null | grep -q "$RUST_TARGET"; then
        echo "Building smolvm-agent for $RUST_TARGET..."
        cargo build --locked --profile "$PROFILE" -p smolvm-agent --target "$RUST_TARGET" \
            --manifest-path "$PROJECT_ROOT/Cargo.toml"
        AGENT_BINARY="$PROJECT_ROOT/target/$RUST_TARGET/$PROFILE/smolvm-agent"
    fi

    if [[ -z "$AGENT_BINARY" ]] || [[ ! -f "$AGENT_BINARY" ]]; then
        echo "Error: Cannot build smolvm-agent"
        echo "Linux source builds are run through the rootless Podman builder:"
        echo "  ./scripts/build.sh"
        echo "For this internal script, set AGENT_BINARY=/path/to/smolvm-agent or use"
        echo "a builder environment with the $RUST_TARGET Rust target installed."
        exit 1
    fi
fi

# Install the agent binary into the rootfs (if we have one)
if [[ -n "${AGENT_BINARY:-}" ]] && [[ -f "${AGENT_BINARY}" ]]; then
    echo "Installing smolvm-agent binary..."
    cp "$AGENT_BINARY" "$OUTPUT_DIR/usr/local/bin/smolvm-agent"
    chmod +x "$OUTPUT_DIR/usr/local/bin/smolvm-agent"
elif [[ "$NO_BUILD_AGENT" != "1" ]]; then
    echo "Error: smolvm-agent binary not found at ${AGENT_BINARY:-<unset>}"
    exit 1
fi

echo ""
echo "Agent rootfs created at: $OUTPUT_DIR"
if [[ -n "${AGENT_BINARY:-}" ]]; then
    echo "Agent binary: $AGENT_BINARY"
fi
echo "Rootfs size: $(du -sh "$OUTPUT_DIR" | cut -f1)"

# Install to runtime data directory if --install flag is passed
if [[ "${INSTALL_ROOTFS:-}" == "1" ]]; then
    if [[ "$(uname -s)" == "Darwin" ]]; then
        DATA_DIR="$HOME/Library/Application Support/smolvm"
    else
        DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi

    echo "Installing agent-rootfs to $DATA_DIR..."
    mkdir -p "$DATA_DIR"
    rm -rf "$DATA_DIR/agent-rootfs"
    cp -a "$OUTPUT_DIR" "$DATA_DIR/agent-rootfs"
    echo "Installed successfully."
fi
