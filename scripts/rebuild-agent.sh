#!/usr/bin/env bash
# Rebuild the guest agent rootfs from pinned inputs.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLEAN=0

usage() {
  cat <<EOF
Usage: ./scripts/rebuild-agent.sh [--clean]

Options:
  --clean    Remove smolvm-agent build artifacts first
  -h, --help Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --clean)
      CLEAN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ "$CLEAN" == "1" ]]; then
  cargo clean -p smolvm-agent -p smolvm-protocol
fi

exec "$ROOT/scripts/build-agent-rootfs.sh"
