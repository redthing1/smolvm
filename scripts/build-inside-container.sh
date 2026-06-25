#!/usr/bin/env bash
# Internal build body. On Linux, run this through ./scripts/build.sh so the
# dependency environment is the repository's rootless Podman builder.

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

host_rust_target() {
  case "$(uname -m)" in
    arm64|aarch64) echo "aarch64-unknown-linux-musl" ;;
    amd64|x86_64) echo "x86_64-unknown-linux-musl" ;;
    *) die "unsupported host architecture: $(uname -m)" ;;
  esac
}

require_cmd() {
  have "$1" || die "$1 not found"
}

host_lib_dir() {
  case "$(uname -s)" in
    Linux) echo "$ROOT/lib/linux-$(uname -m)" ;;
    Darwin) echo "$ROOT/lib" ;;
    *) die "unsupported host OS: $(uname -s)" ;;
  esac
}

require_runtime_libs() {
  local lib_dir="$1"
  local libs

  case "$(uname -s)" in
    Linux) libs=(libkrun.so libkrunfw.so) ;;
    Darwin) libs=(libkrun.dylib libkrunfw.5.dylib) ;;
  esac

  for lib in "${libs[@]}"; do
    [[ -e "$lib_dir/$lib" ]] || die "$lib_dir/$lib not found after source build"
  done
}

require_cmd cargo
require_cmd curl
require_cmd tar

if [[ "$(uname -s)" == "Linux" ]]; then
  require_cmd mkfs.ext4
  require_cmd rustup
  RUST_TARGET="$(host_rust_target)"
  if ! rustup target list --installed | grep -q "^${RUST_TARGET}$"; then
    die "Rust musl target ${RUST_TARGET} missing from the builder image"
  fi
  if [[ -z "${SMOLVM_IN_BUILDER:-}" ]]; then
    [[ -e /dev/kvm ]] || echo "warning: /dev/kvm not found; build can finish, but VMs will not run" >&2
  fi
fi

LIB_DIR="$(host_lib_dir)"
./scripts/build-runtime-libs.sh
require_runtime_libs "$LIB_DIR"

echo "building smolvm..."
LIBKRUN_BUNDLE="$LIB_DIR" cargo build --locked --release --bin smolvm

echo "building agent rootfs..."
./scripts/build-agent-rootfs.sh

echo
echo "built:"
echo "  $ROOT/target/release/smolvm"
echo "  $ROOT/target/agent-rootfs"
echo
echo "try:"
echo "  ./scripts/run.sh machine run --net --image alpine -- echo hello"
