#!/usr/bin/env bash
# Build smolvm runtime libraries from the checked-out submodules.

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

require_pkg_config() {
  local module="$1"
  pkg-config --exists "$module" || die "pkg-config module '$module' not found"
}

host_lib_dir() {
  case "$(uname -s)" in
    Linux) echo "$ROOT/lib/linux-$(uname -m)" ;;
    Darwin) echo "$ROOT/lib" ;;
    *) die "unsupported host OS: $(uname -s)" ;;
  esac
}

kernel_config_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    riscv64) echo "riscv64" ;;
    *) die "unsupported host architecture: $(uname -m)" ;;
  esac
}

make_var() {
  local makefile="$1"
  local key="$2"
  awk -F= -v key="$key" '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      value = $2
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      print value
      exit
    }
  ' "$makefile"
}

require_submodule() {
  local path="$1"
  local sentinel="$2"
  [[ -e "$ROOT/$path/$sentinel" ]] || die "$path submodule is not initialized; run: git submodule update --init --recursive $path"
}

refresh_existing_libkrunfw_kernel_config() {
  local arch
  arch="$(kernel_config_arch)"
  local kernel_src
  kernel_src="$(make_var "$ROOT/libkrunfw/Makefile" KERNEL_VERSION)"
  local config="$ROOT/libkrunfw/config-libkrunfw_${arch}"

  [[ -f "$config" ]] || die "missing libkrunfw kernel config for $arch: $config"

  if [[ -d "$ROOT/libkrunfw/$kernel_src" ]]; then
    cp "$config" "$ROOT/libkrunfw/$kernel_src/.config"
    make -C "$ROOT/libkrunfw/$kernel_src" olddefconfig
    rm -f "$ROOT/libkrunfw/kernel.c"
  fi
}

write_source_manifest() {
  local lib_dir="$1"
  {
    printf 'built_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'host_os=%s\n' "$(uname -s)"
    printf 'host_arch=%s\n' "$(uname -m)"
    if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      printf 'smolvm_commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
      printf 'libkrun_commit=%s\n' "$(git -C "$ROOT/libkrun" rev-parse HEAD)"
      printf 'libkrunfw_commit=%s\n' "$(git -C "$ROOT/libkrunfw" rev-parse HEAD)"
    fi
  } > "$lib_dir/source-build.txt"
}

build_libkrunfw() {
  require_submodule libkrunfw Makefile
  require_cmd make
  require_cmd curl
  require_cmd tar
  require_cmd python3
  require_cmd flex
  require_cmd bison
  require_cmd bc

  refresh_existing_libkrunfw_kernel_config

  echo "building libkrunfw from submodule..."
  local make_jobs=()
  if [[ -n "${SMOLVM_BUILD_JOBS:-}" ]]; then
    [[ "$SMOLVM_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || die "SMOLVM_BUILD_JOBS must be a positive integer"
    make_jobs=(-j "$SMOLVM_BUILD_JOBS")
  fi
  make -C "$ROOT/libkrunfw" "${make_jobs[@]}"

  local lib_dir
  lib_dir="$(host_lib_dir)"
  mkdir -p "$lib_dir"

  local abi full
  abi="$(make_var "$ROOT/libkrunfw/Makefile" ABI_VERSION)"
  full="$(make_var "$ROOT/libkrunfw/Makefile" FULL_VERSION)"

  case "$(uname -s)" in
    Linux)
      local src="$ROOT/libkrunfw/libkrunfw.so.${full}"
      [[ -f "$src" ]] || die "libkrunfw build did not produce $src"
      rm -f "$lib_dir"/libkrunfw.so "$lib_dir"/libkrunfw.so.*
      cp "$src" "$lib_dir/libkrunfw.so.${full}"
      (
        cd "$lib_dir"
        ln -sf "libkrunfw.so.${full}" "libkrunfw.so.${abi}"
        ln -sf "libkrunfw.so.${abi}" libkrunfw.so
      )
      ;;
    Darwin)
      local src="$ROOT/libkrunfw/libkrunfw.${abi}.dylib"
      [[ -f "$src" ]] || die "libkrunfw build did not produce $src"
      rm -f "$lib_dir"/libkrunfw.dylib "$lib_dir"/libkrunfw.*.dylib
      cp "$src" "$lib_dir/libkrunfw.${abi}.dylib"
      (
        cd "$lib_dir"
        ln -sf "libkrunfw.${abi}.dylib" libkrunfw.dylib
      )
      ;;
  esac
}

build_libkrun() {
  require_submodule libkrun Makefile
  require_cmd make
  require_cmd cargo
  require_cmd clang
  require_cmd pkg-config
  require_pkg_config epoxy
  require_pkg_config libdrm
  require_pkg_config virglrenderer

  echo "building libkrun from submodule..."
  local make_jobs=()
  if [[ -n "${SMOLVM_BUILD_JOBS:-}" ]]; then
    [[ "$SMOLVM_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || die "SMOLVM_BUILD_JOBS must be a positive integer"
    make_jobs=(-j "$SMOLVM_BUILD_JOBS")
  fi
  make -C "$ROOT/libkrun" "${make_jobs[@]}" BLK=1 NET=1 GPU=1

  local lib_dir
  lib_dir="$(host_lib_dir)"
  mkdir -p "$lib_dir"

  local abi full
  abi="$(make_var "$ROOT/libkrun/Makefile" ABI_VERSION)"
  full="$(make_var "$ROOT/libkrun/Makefile" FULL_VERSION)"

  case "$(uname -s)" in
    Linux)
      local src="$ROOT/libkrun/target/release/libkrun.so.${full}"
      [[ -f "$src" ]] || die "libkrun build did not produce $src"
      rm -f "$lib_dir"/libkrun.so "$lib_dir"/libkrun.so.*
      cp "$src" "$lib_dir/libkrun.so.${full}"
      (
        cd "$lib_dir"
        ln -sf "libkrun.so.${full}" "libkrun.so.${abi}"
        ln -sf "libkrun.so.${abi}" libkrun.so
      )
      ;;
    Darwin)
      local src="$ROOT/libkrun/target/release/libkrun.${full}.dylib"
      [[ -f "$src" ]] || die "libkrun build did not produce $src"
      rm -f "$lib_dir"/libkrun.dylib "$lib_dir"/libkrun.*.dylib
      cp "$src" "$lib_dir/libkrun.${full}.dylib"
      (
        cd "$lib_dir"
        ln -sf "libkrun.${full}.dylib" "libkrun.${abi}.dylib"
        ln -sf "libkrun.${abi}.dylib" libkrun.dylib
      )
      ;;
  esac
}

usage() {
  cat <<EOF
Usage: ./scripts/build-runtime-libs.sh [all|libkrunfw|libkrun]

Build current-host libkrunfw and libkrun runtime libraries from the checked-out
submodules into the source-tree lib directory.

Environment:
  SMOLVM_BUILD_JOBS  Optional make parallelism, for example 8.
EOF
}

target="${1:-all}"
case "$target" in
  all)
    build_libkrunfw
    build_libkrun
    write_source_manifest "$(host_lib_dir)"
    ;;
  libkrunfw)
    build_libkrunfw
    write_source_manifest "$(host_lib_dir)"
    ;;
  libkrun)
    build_libkrun
    write_source_manifest "$(host_lib_dir)"
    ;;
  -h|--help)
    usage
    ;;
  *)
    die "unknown target: $target"
    ;;
esac

echo "runtime libraries built in $(host_lib_dir)"
