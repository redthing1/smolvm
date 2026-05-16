#!/usr/bin/env bash
# Build this checkout from source and install that exact build locally.
#
# Supported workflows:
#   ./scripts/build.sh                         # build for source-tree development
#   ./scripts/run.sh --help                    # run from the source tree
#   ./scripts/install.sh                       # build from source and install locally
#   ./scripts/install.sh --no-build            # install already-built local artifacts
#   ./scripts/install.sh --uninstall           # remove the local install

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_PREFIX="${SMOLVM_INSTALL_PREFIX:-$HOME/.smolvm}"
BIN_DIR="${SMOLVM_BIN_DIR:-$HOME/.local/bin}"
DO_BUILD=1
UNINSTALL=0

if [ -t 1 ]; then
  BLUE='\033[0;34m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  RED='\033[0;31m'
  BOLD='\033[1m'
  NC='\033[0m'
else
  BLUE='' GREEN='' YELLOW='' RED='' BOLD='' NC=''
fi

info() { printf '%binfo:%b %s\n' "$BLUE" "$NC" "$*"; }
success() { printf '%bsuccess:%b %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%bwarning:%b %s\n' "$YELLOW" "$NC" "$*" >&2; }
error() { printf '%berror:%b %s\n' "$RED" "$NC" "$*" >&2; }
die() { error "$*"; exit 1; }

usage() {
  cat <<EOF
Usage: ./scripts/install.sh [OPTIONS]

Build this checkout from source and install that exact build locally.

Options:
  --prefix DIR      Install runtime files to DIR (default: ~/.smolvm)
  --bin-dir DIR     Symlink smolvm into DIR (default: ~/.local/bin)
  --no-build        Install existing target/ artifacts without rebuilding
  --uninstall       Remove the local install
  -h, --help        Show this help

Environment:
  SMOLVM_INSTALL_PREFIX  Default install prefix override
  SMOLVM_BIN_DIR         Default bin-dir override
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ -n "${2:-}" ]] || die "--prefix requires a directory"
      INSTALL_PREFIX="$2"
      shift 2
      ;;
    --bin-dir)
      [[ -n "${2:-}" ]] || die "--bin-dir requires a directory"
      BIN_DIR="$2"
      shift 2
      ;;
    --no-build)
      DO_BUILD=0
      shift
      ;;
    --uninstall)
      UNINSTALL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

host_lib_dir() {
  case "$(uname -s)" in
    Linux) echo "$ROOT/lib/linux-$(uname -m)" ;;
    Darwin) echo "$ROOT/lib" ;;
    *) die "unsupported host OS: $(uname -s)" ;;
  esac
}

data_dir() {
  case "$(uname -s)" in
    Darwin) echo "$HOME/Library/Application Support/smolvm" ;;
    Linux) echo "${XDG_DATA_HOME:-$HOME/.local/share}/smolvm" ;;
    *) die "unsupported host OS: $(uname -s)" ;;
  esac
}

is_dangerous_prefix() {
  case "$1" in
    /|/usr|/usr/*|/bin|/sbin|/lib|/lib64|/etc|/var|/opt|/System|/System/*|/Library|/Library/*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

require_runtime_artifacts() {
  local bin="$ROOT/target/release/smolvm"
  local rootfs="$ROOT/target/agent-rootfs"
  local lib_dir
  lib_dir="$(host_lib_dir)"

  [[ -x "$bin" ]] || die "$bin not found or not executable; run ./scripts/build.sh"
  [[ -d "$rootfs" ]] || die "$rootfs not found; run ./scripts/build.sh"
  [[ -d "$lib_dir" ]] || die "$lib_dir not found; run ./scripts/build.sh"

  case "$(uname -s)" in
    Linux)
      [[ -e "$lib_dir/libkrun.so" ]] || die "$lib_dir/libkrun.so not found"
      [[ -e "$lib_dir/libkrunfw.so" || -e "$lib_dir/libkrunfw.so.5" ]] || die "$lib_dir/libkrunfw.so(.5) not found"
      ;;
    Darwin)
      [[ -e "$lib_dir/libkrun.dylib" ]] || die "$lib_dir/libkrun.dylib not found"
      [[ -e "$lib_dir/libkrunfw.5.dylib" ]] || die "$lib_dir/libkrunfw.5.dylib not found"
      ;;
  esac
}

copy_linux_lib_chain() {
  local src_dir="$1"
  local dst_dir="$2"
  local lib_prefix="$3"
  local required="$4"
  local entry="$src_dir/${lib_prefix}.so"

  if [[ ! -e "$entry" ]]; then
    if [[ "$required" == "required" ]]; then
      die "$entry not found"
    fi
    return
  fi

  local real_file
  real_file="$(readlink -f "$entry")"
  cp "$real_file" "$dst_dir/$(basename "$real_file")"

  local candidate
  for candidate in "$src_dir"/${lib_prefix}.so*; do
    if [[ -L "$candidate" && "$(readlink -f "$candidate")" == "$real_file" ]]; then
      cp -a "$candidate" "$dst_dir/"
    fi
  done
}

copy_runtime_libs() {
  local src_dir
  src_dir="$(host_lib_dir)"
  local dst_dir="$1"

  case "$(uname -s)" in
    Linux)
      copy_linux_lib_chain "$src_dir" "$dst_dir" libkrun required
      copy_linux_lib_chain "$src_dir" "$dst_dir" libkrunfw required
      copy_linux_lib_chain "$src_dir" "$dst_dir" libvirglrenderer optional
      copy_linux_lib_chain "$src_dir" "$dst_dir" libepoxy optional
      if [[ -f "$src_dir/virgl_render_server" ]]; then
        cp "$src_dir/virgl_render_server" "$dst_dir/"
        chmod +x "$dst_dir/virgl_render_server"
      fi
      ;;
    Darwin)
      cp "$src_dir/libkrun.dylib" "$dst_dir/"
      cp "$src_dir/libkrunfw.5.dylib" "$dst_dir/"
      if [[ -L "$src_dir/libkrunfw.dylib" ]]; then
        cp -a "$src_dir/libkrunfw.dylib" "$dst_dir/"
      else
        ln -sf libkrunfw.5.dylib "$dst_dir/libkrunfw.dylib"
      fi
      for gpu_lib in libvirglrenderer.1.dylib libMoltenVK.dylib libepoxy.0.dylib; do
        if [[ -f "$src_dir/$gpu_lib" ]]; then
          cp "$src_dir/$gpu_lib" "$dst_dir/"
        fi
      done
      ;;
  esac
}

source_stamp() {
  local version
  version="$(grep '^version' "$ROOT/Cargo.toml" | head -1 | cut -d'"' -f2)"
  {
    printf 'version=%s\n' "${version:-unknown}"
    if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      printf 'git_commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
      if ! git -C "$ROOT" diff --quiet || ! git -C "$ROOT" diff --cached --quiet; then
        printf 'git_dirty=true\n'
      else
        printf 'git_dirty=false\n'
      fi
    fi
    printf 'installed_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'source=%s\n' "$ROOT"
  }
}

install_rootfs() {
  local data
  data="$(data_dir)"
  local rootfs="$ROOT/target/agent-rootfs"
  local tmp
  mkdir -p "$data"
  tmp="$(mktemp -d "$data/agent-rootfs.tmp.XXXXXX")"

  rm -rf "$tmp"
  cp -a "$rootfs" "$tmp"

  rm -rf "$data/agent-rootfs.old"
  if [[ -e "$data/agent-rootfs" ]]; then
    mv "$data/agent-rootfs" "$data/agent-rootfs.old"
  fi
  mv "$tmp" "$data/agent-rootfs"
  rm -rf "$data/agent-rootfs.old"
  success "Installed agent rootfs to $data/agent-rootfs"
}

install_runtime() {
  local prefix="$INSTALL_PREFIX"
  local parent
  parent="$(dirname "$prefix")"
  mkdir -p "$parent"

  if is_dangerous_prefix "$prefix"; then
    die "refusing to install to system directory: $prefix"
  fi

  local staging
  staging="$(mktemp -d "$parent/.smolvm-install.XXXXXX")"
  mkdir -p "$staging/lib"

  cp "$ROOT/target/release/smolvm" "$staging/smolvm-bin"
  cp "$ROOT/scripts/smolvm-wrapper.sh" "$staging/smolvm"
  chmod +x "$staging/smolvm-bin" "$staging/smolvm"
  copy_runtime_libs "$staging/lib"
  source_stamp > "$staging/source-build.txt"

  rm -rf "$prefix.old"
  if [[ -e "$prefix" ]]; then
    mv "$prefix" "$prefix.old"
  fi
  mv "$staging" "$prefix"
  rm -rf "$prefix.old"

  mkdir -p "$BIN_DIR"
  ln -sf "$prefix/smolvm" "$BIN_DIR/smolvm"
  success "Installed smolvm runtime to $prefix"
  success "Linked $BIN_DIR/smolvm"
}

uninstall() {
  local data
  data="$(data_dir)"

  rm -rf "$INSTALL_PREFIX"
  if [[ -L "$BIN_DIR/smolvm" ]]; then
    local link_target
    link_target="$(readlink "$BIN_DIR/smolvm")"
    if [[ "$link_target" == "$INSTALL_PREFIX/smolvm" ]]; then
      rm -f "$BIN_DIR/smolvm"
    fi
  fi
  rm -rf "$data/agent-rootfs"
  rm -f "$data/init.krun"

  success "Removed smolvm install"
  info "Left VM/cache state intact. Remove ~/.cache/smolvm manually if desired."
}

main() {
  if [[ "$UNINSTALL" == "1" ]]; then
    uninstall
    return
  fi

  echo ""
  printf '%bsmolvm installer%b\n' "$BOLD" "$NC"
  echo ""

  if [[ "$(uname -s)" == "Linux" && ! -e /dev/kvm ]]; then
    warn "/dev/kvm not found. Install can finish, but VMs will not run until KVM is available."
  fi

  if [[ "$DO_BUILD" == "1" ]]; then
    info "Building current checkout from source..."
    "$ROOT/scripts/build.sh"
  fi

  require_runtime_artifacts
  install_rootfs
  install_runtime

  echo ""
  if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    warn "$BIN_DIR is not in PATH"
    echo "Add this to your shell profile:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    echo ""
  fi

  echo "Test:"
  echo "  smolvm --version"
  echo "  smolvm machine run --net --image alpine -- echo hello"
}

main
