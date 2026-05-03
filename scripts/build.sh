#!/usr/bin/env bash
# Build the local smolvm CLI and guest agent rootfs for source development.

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

is_lfs_pointer() {
  local path="$1"
  if [[ -f "$path" ]] && head -n 1 "$path" 2>/dev/null | grep -aq '^version https://git-lfs.github.com/spec/v1$'; then
    return 0
  fi
  return 1
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

ensure_runtime_libs() {
  local lib_dir="$1"
  local libs

  case "$(uname -s)" in
    Linux) libs=(libkrun.so libkrunfw.so) ;;
    Darwin) libs=(libkrun.dylib libkrunfw.5.dylib) ;;
  esac

  for lib in "${libs[@]}"; do
    [[ -e "$lib_dir/$lib" ]] || die "$lib_dir/$lib not found; run git lfs pull or build libkrun/libkrunfw"
  done

  local needs_lfs=0
  for lib in "${libs[@]}"; do
    if is_lfs_pointer "$lib_dir/$lib"; then
      needs_lfs=1
    fi
  done

  if [[ "$needs_lfs" == "1" ]]; then
    require_cmd git-lfs
    echo "hydrating Git LFS runtime libraries..."
    git lfs pull
  fi

  for lib in "${libs[@]}"; do
    is_lfs_pointer "$lib_dir/$lib" && die "$lib_dir/$lib is still a Git LFS pointer"
  done

  return 0
}

require_cmd cargo
require_cmd curl
require_cmd tar

if [[ "$(uname -s)" == "Linux" ]]; then
  require_cmd mkfs.ext4
  if ! have rustup || ! rustup target list --installed | grep -q '^x86_64-unknown-linux-musl$'; then
    die "Rust musl target not installed; run: rustup target add x86_64-unknown-linux-musl"
  fi
  [[ -e /dev/kvm ]] || echo "warning: /dev/kvm not found; build can finish, but VMs will not run" >&2
fi

LIB_DIR="$(host_lib_dir)"
ensure_runtime_libs "$LIB_DIR"

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
