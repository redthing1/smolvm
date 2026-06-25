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

success() {
    echo -e "${GREEN}success:${NC} $1"
}

warn() {
    echo -e "${YELLOW}warning:${NC} $1"
}

error() {
    echo -e "${RED}error:${NC} $1" >&2
}

# Detect platform
detect_platform() {
    local os arch

    # Detect OS
    case "$(uname -s)" in
        Darwin)
            os="darwin"
            ;;
        Linux)
            os="linux"
            ;;
        *)
            error "Unsupported operating system: $(uname -s)"
            error "smolvm supports macOS and Linux only."
            exit 1
            ;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            arch="x86_64"
            ;;
        aarch64|arm64)
            arch="aarch64"
            ;;
        *)
            error "Unsupported architecture: $(uname -m)"
            error "smolvm supports x86_64 and arm64 only."
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Check system requirements
check_requirements() {
    local platform="$1"

    # Check for curl or wget
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        error "curl or wget is required to download smolvm."
        exit 1
    fi

    # Check for tar
    if ! command -v tar &> /dev/null; then
        error "tar is required to extract smolvm."
        exit 1
    fi

    # macOS-specific checks
    if [[ "$platform" == darwin-* ]]; then
        # Check macOS version (need 11.0+)
        local macos_version
        macos_version=$(sw_vers -productVersion 2>/dev/null || echo "0.0")
        local major_version
        major_version=$(echo "$macos_version" | cut -d. -f1)

        if [[ "$major_version" -lt 11 ]]; then
            error "smolvm requires macOS 11.0 or later (you have $macos_version)"
            exit 1
        fi
    fi

    # Linux-specific checks
    if [[ "$platform" == linux-* ]]; then
        # Check for KVM support
        if [[ ! -e /dev/kvm ]]; then
            warn "/dev/kvm not found. smolvm requires KVM support."
            warn ""
            warn "To enable KVM:"
            warn "  1. Ensure virtualization is enabled in your BIOS/UEFI"
            warn "  2. Load the KVM kernel module:"
            warn "     sudo modprobe kvm"
            warn "     sudo modprobe kvm_intel  # For Intel CPUs"
            warn "     sudo modprobe kvm_amd    # For AMD CPUs"
            warn ""
            warn "For persistent loading, add to /etc/modules-load.d/kvm.conf:"
            warn "     kvm"
            warn "     kvm_intel  # or kvm_amd"
        elif [[ ! -r /dev/kvm ]] || [[ ! -w /dev/kvm ]]; then
            warn "Cannot access /dev/kvm (permission denied)."
            warn ""
            warn "Add your user to the 'kvm' group:"
            warn "  sudo usermod -aG kvm $USER"
            warn ""
            warn "Then log out and log back in for the change to take effect."
        else
            info "KVM access verified"
        fi
    fi
}

# Get latest version from GitHub
get_latest_version() {
    local url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local version

    if command -v curl &> /dev/null; then
        version=$(curl -sSL "$url" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')
    else
        version=$(wget -qO- "$url" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"tag_name": *"v?([^"]+)".*/\1/')
    fi

    if [[ -z "$version" ]]; then
        # Fallback to a default version if GitHub API fails
        echo "0.1.1"
    else
        echo "$version"
    fi
}

# Download file
download() {
    local url="$1"
    local output="$2"

    info "Downloading $url"

    if command -v curl &> /dev/null; then
        curl -fSL --progress-bar "$url" -o "$output"
    else
        wget --show-progress -q "$url" -O "$output"
    fi
}

# Get download URL for a version and platform
get_download_url() {
    local version="$1"
    local platform="$2"

    # Convert platform format (darwin-aarch64 -> darwin-arm64 for compatibility)
    local download_platform="$platform"
    if [[ "$platform" == *-aarch64 ]]; then
        download_platform="${platform/aarch64/arm64}"
    fi

    echo "https://github.com/${GITHUB_REPO}/releases/download/v${version}/smolvm-${version}-${download_platform}.tar.gz"
}

# Get checksum URL for a version and platform
get_checksum_url() {
    local version="$1"
    echo "https://github.com/${GITHUB_REPO}/releases/download/v${version}/checksums.sha256"
}

# Verify file checksum
verify_checksum() {
    local file="$1"
    local checksums_file="$2"
    local filename
    filename=$(basename "$file")

    # Extract expected checksum for this file
    local expected
    expected=$(grep "$filename" "$checksums_file" 2>/dev/null | awk '{print $1}')

    if [[ -z "$expected" ]]; then
        warn "Checksum not found for $filename, skipping verification"
        return 0
    fi

    # Calculate actual checksum
    local actual
    if command -v sha256sum &> /dev/null; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum &> /dev/null; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        warn "sha256sum/shasum not found, skipping checksum verification"
        return 0
    fi

    if [[ "$expected" != "$actual" ]]; then
        error "Checksum verification failed!"
        error "  Expected: $expected"
        error "  Actual:   $actual"
        return 1
    fi

    info "Checksum verified"
    return 0
}

# Install smolvm
install_smolvm() {
    local version="$1"
    local platform="$2"
    local prefix="$3"

    local url
    url=$(get_download_url "$version" "$platform")
    local checksums_url
    checksums_url=$(get_checksum_url "$version")
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local archive_name
    archive_name=$(basename "$url")
    local archive="${tmp_dir}/${archive_name}"
    local checksums="${tmp_dir}/checksums.sha256"

    # Download archive
    download "$url" "$archive" || {
        error "Failed to download smolvm from $url"
        error "Please check if version $version exists for platform $platform"
        rm -rf "$tmp_dir"
        exit 1
    }

    # Download and verify checksums (optional - don't fail if checksums unavailable)
    if download "$checksums_url" "$checksums" 2>/dev/null; then
        verify_checksum "$archive" "$checksums" || {
            error "Archive failed checksum verification - aborting for security"
            rm -rf "$tmp_dir"
            exit 1
        }
    else
        warn "Checksums not available for this release, skipping verification"
    fi

    # Extract
    info "Extracting archive..."
    tar -xzf "$archive" -C "$tmp_dir" || {
        error "Failed to extract archive"
        rm -rf "$tmp_dir"
        exit 1
    }

    # Find extracted directory
    local extracted_dir
    extracted_dir=$(find "$tmp_dir" -maxdepth 1 -type d -name "smolvm-*" | head -1)

    if [[ -z "$extracted_dir" ]]; then
        error "Could not find extracted smolvm directory"
        rm -rf "$tmp_dir"
        exit 1
    fi

    # Safety: refuse to install to system directories
    case "$prefix" in
        /|/usr|/usr/*|/bin|/sbin|/lib|/lib64|/etc|/var|/opt|/tmp|/System|/System/*|/Library|/Library/*)
            error "Refusing to install to system directory: $prefix"
            error "Use a user-writable directory like ~/.smolvm (the default)"
            rm -rf "$tmp_dir"
            exit 1
            ;;
    esac

    # Safety: warn if installing outside home directory
    if [[ "$prefix" != "$HOME"* ]] && [[ "$prefix" != /tmp/* ]]; then
        warn "Installing outside of home directory: $prefix"
        warn "This will remove $prefix/lib/ and $prefix/smolvm if they exist."
        if [ -t 0 ]; then
            printf "Continue? [y/N] "
            read -r REPLY
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                error "Aborted."
                rm -rf "$tmp_dir"
                exit 1
            fi
        else
            error "Non-interactive install to non-home path. Aborting for safety."
            error "Use --prefix with a path under \$HOME, or run interactively."
            rm -rf "$tmp_dir"
            exit 1
        fi
    fi

    # Create installation directory
    info "Installing to $prefix..."
    mkdir -p "$prefix"

    # Remove old smolvm installation files only (not arbitrary lib/ directories)
    if [[ -d "$prefix/lib" ]] && [[ -f "$prefix/.version" ]]; then
        # Only remove lib/ if this looks like an existing smolvm installation
        rm -rf "$prefix/lib"
    elif [[ -d "$prefix/lib" ]]; then
        warn "$prefix/lib exists but no .version file found — skipping lib/ removal"
        warn "If this is a previous smolvm install, remove it manually first"
    fi
    if [[ -f "$prefix/smolvm" ]]; then
        rm -f "$prefix/smolvm"
    fi
    if [[ -f "$prefix/smolvm-bin" ]]; then
        rm -f "$prefix/smolvm-bin"
    fi
    if [[ -f "$prefix/smol" ]]; then
        rm -f "$prefix/smol"
    fi
    if [[ -f "$prefix/smol-bin" ]]; then
        rm -f "$prefix/smol-bin"
    fi
    if [[ -f "$prefix/smolvm-stub" ]]; then
        rm -f "$prefix/smolvm-stub"
    fi
    if [[ -f "$prefix/storage-template.ext4" ]]; then
        rm -f "$prefix/storage-template.ext4"
    fi
    if [[ -f "$prefix/overlay-template.ext4" ]]; then
        rm -f "$prefix/overlay-template.ext4"
    fi

    # Copy files
    cp -r "$extracted_dir/lib" "$prefix/"
    cp "$extracted_dir/smolvm" "$prefix/"
    cp "$extracted_dir/smolvm-bin" "$prefix/"
    chmod +x "$prefix/smolvm"
    chmod +x "$prefix/smolvm-bin"

    # Copy the unified `smol` CLI if the distribution includes it. Older
    # engine-only tarballs won't have it; newer ones ship both.
    local has_smol=false
    if [[ -f "$extracted_dir/smol" ]] && [[ -f "$extracted_dir/smol-bin" ]]; then
        cp "$extracted_dir/smol" "$prefix/"
        cp "$extracted_dir/smol-bin" "$prefix/"
        chmod +x "$prefix/smol"
        chmod +x "$prefix/smol-bin"
        has_smol=true
    fi

    # Copy disk templates if present
    if [[ -f "$extracted_dir/storage-template.ext4" ]]; then
        cp "$extracted_dir/storage-template.ext4" "$prefix/"
    fi
    if [[ -f "$extracted_dir/overlay-template.ext4" ]]; then
        cp "$extracted_dir/overlay-template.ext4" "$prefix/"
    fi

    # Size the disk templates to their default virtual size at install time, so
    # the runtime boots fresh VMs from an instant qcow2 copy-on-write overlay
    # (no per-boot template copy) instead of mutating a shared template lazily.
    # The ext4 inside stays 512 MiB; the guest grows it with resize2fs at boot.
    # Sparse, so it costs no real disk. Linux-only (the overlay path is gated to
    # Linux) and needs `truncate` (GNU coreutils); skipped otherwise, in which
    # case the runtime safely falls back to the copy path. The sizes mirror
    # DEFAULT_STORAGE_SIZE_GIB (20) and DEFAULT_OVERLAY_SIZE_GIB (10).
    if command -v truncate >/dev/null 2>&1; then
        [[ -f "$prefix/storage-template.ext4" ]] && truncate -s 20G "$prefix/storage-template.ext4"
        [[ -f "$prefix/overlay-template.ext4" ]] && truncate -s 10G "$prefix/overlay-template.ext4"
    fi

    # Install agent-rootfs to data directory
    local data_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        data_dir="$HOME/Library/Application Support/smolvm"
    else
        data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi

    if [[ -d "$extracted_dir/agent-rootfs" ]]; then
        info "Installing agent-rootfs to $data_dir..."
        mkdir -p "$data_dir"
        rm -rf "$data_dir/agent-rootfs"
        # Use cp -a to preserve symlinks (busybox creates many symlinks)
        cp -a "$extracted_dir/agent-rootfs" "$data_dir/"
    else
        warn "agent-rootfs not found in distribution - some features may not work"
    fi

    # Copy init.krun if present (Linux only, required by libkrunfw kernel)
    if [[ -f "$extracted_dir/init.krun" ]]; then
        info "Installing init.krun to $data_dir..."
        cp "$extracted_dir/init.krun" "$data_dir/init.krun"
        chmod +x "$data_dir/init.krun"
    fi

    # Store version info
    echo "$version" > "$prefix/.version"

    # Cleanup
    rm -rf "$tmp_dir"

    # macOS: files downloaded via curl carry a com.apple.quarantine attribute,
    # and Gatekeeper will refuse to run the binaries (which call the hypervisor)
    # until it's cleared. Strip it from the whole install tree, then check the
    # code signature so we can warn clearly instead of failing cryptically.
    if [[ "$(uname -s)" == "Darwin" ]]; then
        if command -v xattr &> /dev/null; then
            xattr -dr com.apple.quarantine "$prefix" 2>/dev/null || true
        fi
        if command -v codesign &> /dev/null; then
            local _sig_bin="$prefix/smolvm-bin"
            [[ "$has_smol" == true ]] && _sig_bin="$prefix/smol-bin"
            if ! codesign --verify --deep "$_sig_bin" 2>/dev/null; then
                warn "The installed binary is not validly code-signed."
                warn "It needs the com.apple.security.hypervisor entitlement to start VMs."
            elif command -v spctl &> /dev/null && ! spctl --assess --type execute "$_sig_bin" &> /dev/null; then
                warn "Binary is signed but not notarized by Apple."
                warn "It will run (quarantine was cleared), but Gatekeeper may warn on first launch."
            fi
        fi
    fi

    # Create symlinks in bin directory. `smol` is the primary, user-facing CLI;
    # `smolvm` remains available as the lower-level engine command.
    mkdir -p "$BIN_DIR"
    ln -sf "$prefix/smolvm" "$BIN_DIR/smolvm"
    if [[ "$has_smol" == true ]]; then
        ln -sf "$prefix/smol" "$BIN_DIR/smol"
        success "smol $version installed to $prefix (also installed: smolvm)"
    else
        success "smolvm $version installed to $prefix"
    fi
}

# Modify shell profile to add to PATH
modify_path() {
    local bin_dir="$1"
    local profile=""
    local export_line="export PATH=\"$bin_dir:\$PATH\""

    # Determine shell profile
    case "$SHELL" in
        */zsh)
            profile="$HOME/.zshrc"
            ;;
        */bash)
            if [[ -f "$HOME/.bash_profile" ]]; then
                profile="$HOME/.bash_profile"
            else
                profile="$HOME/.bashrc"
            fi
            ;;
        */fish)
            profile="$HOME/.config/fish/config.fish"
            export_line="set -gx PATH $bin_dir \$PATH"
            ;;
        *)
            profile="$HOME/.profile"
            ;;
    esac

    # Check if already in PATH
    if echo "$PATH" | grep -q "$bin_dir"; then
        info "$bin_dir is already in PATH"
        return
    fi

    # Check if already in profile
    if [[ -f "$profile" ]] && grep -q "$bin_dir" "$profile" 2>/dev/null; then
        info "PATH already configured in $profile"
        return
    fi

    # Add to profile
    info "Adding $bin_dir to PATH in $profile"
    echo "" >> "$profile"
    echo "# smolvm" >> "$profile"
    echo "$export_line" >> "$profile"

    warn "PATH updated. Run 'source $profile' or open a new terminal."
}

# Uninstall smolvm
uninstall_smolvm() {
    local prefix="$1"

    info "Uninstalling smolvm..."

    # Remove installation directory
    if [[ -d "$prefix" ]]; then
        rm -rf "$prefix"
        success "Removed $prefix"
    else
        warn "Installation directory not found: $prefix"
    fi

    # Remove symlink
    if [[ -L "$BIN_DIR/smolvm" ]]; then
        rm -f "$BIN_DIR/smolvm"
        success "Removed symlink $BIN_DIR/smolvm"
    fi

    # Remove data directory (agent-rootfs, storage)
    local data_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        data_dir="$HOME/Library/Application Support/smolvm"
    else
        data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/smolvm"
    fi
    if [[ -d "$data_dir" ]]; then
        rm -rf "$data_dir"
        success "Removed data directory $data_dir"
    fi

    # Remove cache directories
    local cache_dir cache_pack_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        cache_dir="$HOME/Library/Caches/smolvm"
        cache_pack_dir="$HOME/Library/Caches/smolvm-pack"
    else
        cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/smolvm"
        cache_pack_dir="${XDG_CACHE_HOME:-$HOME/.cache}/smolvm-pack"
    fi
    if [[ -d "$cache_dir" ]]; then
        rm -rf "$cache_dir"
        success "Removed cache directory $cache_dir"
    fi
    if [[ -d "$cache_pack_dir" ]]; then
        # On macOS, detach any hdiutil-mounted case-sensitive volumes
        # (layers-cs) before removing the directory. Without this, rm
        # fails with "Resource busy" on active mount points.
        if [[ "$(uname -s)" == "Darwin" ]]; then
            find "$cache_pack_dir" -name layers-cs -type d -exec hdiutil detach {} -force \; 2>/dev/null || true
        fi
        rm -rf "$cache_pack_dir"
        success "Removed pack cache directory $cache_pack_dir"
    fi

    # Remove libs extraction cache (from packed binary SMOLLIBS)
    local cache_libs_dir
    if [[ "$(uname -s)" == "Darwin" ]]; then
        cache_libs_dir="$HOME/Library/Caches/smolvm-libs"
    else
        cache_libs_dir="${XDG_CACHE_HOME:-$HOME/.cache}/smolvm-libs"
    fi
    if [[ -d "$cache_libs_dir" ]]; then
        rm -rf "$cache_libs_dir"
        success "Removed libs cache directory $cache_libs_dir"
    fi

    # Note about remaining files
    warn "You may want to remove the PATH entry from your shell profile."
    local config_dir="$HOME/.config/smolvm"
    if [[ -d "$config_dir" ]]; then
        warn "Registry credentials preserved at $config_dir"
        warn "Remove manually if no longer needed: rm -rf $config_dir"
    fi

    success "smolvm has been uninstalled"
}

# Print usage
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
