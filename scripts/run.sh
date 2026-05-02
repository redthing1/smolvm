#!/usr/bin/env bash
# Run the local smolvm binary with source-tree runtime paths.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/smolvm"
ROOTFS="$ROOT/target/agent-rootfs"

die() {
  echo "error: $*" >&2
  exit 1
}

host_lib_dir() {
  case "$(uname -s)" in
    Linux) echo "$ROOT/lib/linux-$(uname -m)" ;;
    Darwin) echo "$ROOT/lib" ;;
    *) die "unsupported host OS: $(uname -s)" ;;
  esac
}

[[ -x "$BIN" ]] || die "$BIN not found; run ./scripts/build.sh"
[[ -d "$ROOTFS" ]] || die "$ROOTFS not found; run ./scripts/build.sh"

LIB_DIR="$(host_lib_dir)"
[[ -d "$LIB_DIR" ]] || die "$LIB_DIR not found; run git lfs pull or build libkrun/libkrunfw"

export SMOLVM_AGENT_ROOTFS="$ROOTFS"
export SMOLVM_LIB_DIR="$LIB_DIR"

case "$(uname -s)" in
  Linux) export LD_LIBRARY_PATH="$LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
  Darwin) export DYLD_LIBRARY_PATH="$LIB_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" ;;
esac

exec "$BIN" "$@"
