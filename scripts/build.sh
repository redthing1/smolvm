#!/usr/bin/env bash
# Build the local smolvm CLI, runtime libraries, and guest agent rootfs.
#
# Linux builds are intentionally containerized. The host only needs rootless
# Podman; build-only toolchains and development headers live in the builder
# image, which starts from a digest-pinned Rust base.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

die() {
  echo "error: $*" >&2
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

require_cmd() {
  have "$1" || die "$1 not found"
}

usage() {
  echo "Usage: ./scripts/build.sh"
}

validate_env() {
  case "${SMOLVM_BUILD_GPU:-0}" in
    0|1|"") ;;
    *) die "SMOLVM_BUILD_GPU must be 0 or 1" ;;
  esac

  if [[ -n "${SMOLVM_BUILD_JOBS:-}" && ! "${SMOLVM_BUILD_JOBS}" =~ ^[1-9][0-9]*$ ]]; then
    die "SMOLVM_BUILD_JOBS must be a positive integer"
  fi
}

container_platform() {
  case "$(uname -m)" in
    arm64|aarch64) echo "linux/arm64" ;;
    amd64|x86_64) echo "linux/amd64" ;;
    *) die "unsupported host architecture: $(uname -m)" ;;
  esac
}

run_linux_builder() {
  require_cmd podman

  local rootless
  rootless="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
  [[ "$rootless" == "true" ]] || die "rootless Podman is required for Linux source builds"
  [[ -e /dev/kvm ]] || echo "warning: /dev/kvm not found on the host; build can finish, but VMs will not run" >&2

  local image="localhost/smolvm-builder:rust-1.95-bookworm"
  local platform
  platform="$(container_platform)"

  echo "building Linux source builder image..."
  podman build \
    --pull=missing \
    --platform "$platform" \
    -f "$ROOT/Containerfile.builder" \
    -t "$image" \
    "$ROOT"

  mkdir -p "$ROOT/target/container-cargo-home" "$ROOT/target/container-home"

  echo "building smolvm inside rootless Podman..."
  podman run --rm \
    --userns=keep-id \
    --security-opt label=disable \
    --platform "$platform" \
    -e CARGO_HOME=/work/target/container-cargo-home \
    -e HOME=/work/target/container-home \
    -e RUSTUP_TOOLCHAIN=1.95.0 \
    -e RUSTUP_HOME=/usr/local/rustup \
    -e SMOLVM_IN_BUILDER=1 \
    -e SMOLVM_BUILD_JOBS="${SMOLVM_BUILD_JOBS:-}" \
    -e SMOLVM_BUILD_GPU="${SMOLVM_BUILD_GPU:-0}" \
    -v "$ROOT:/work" \
    -w /work \
    "$image" \
    ./scripts/build-inside-container.sh
}

if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

validate_env

case "$(uname -s)" in
  Linux)
    run_linux_builder
    ;;
  Darwin)
    ./scripts/build-inside-container.sh
    ;;
  *)
    die "unsupported host OS: $(uname -s)"
    ;;
esac
