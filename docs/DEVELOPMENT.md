# Development

## Prerequisites

- Linux: rootless Podman and KVM access to run VMs
- macOS: Rust toolchain, C compiler, `make`, `curl`, `tar`, Python 3,
  `flex`, `bison`, `bc`, and e2fsprogs (`brew install e2fsprogs`)
- LLVM (macOS only, for building libkrun: `brew install llvm`)
- [cargo-make](https://github.com/sagiegurari/cargo-make) is optional

## Quick Start

For normal local source builds:

```bash
./scripts/build.sh
./scripts/run.sh --version
./scripts/run.sh machine run --net --image alpine -- echo hello
./scripts/run.sh machine ls
```

The wrappers build the local CLI and guest agent rootfs, then run `smolvm` with
the source-tree `libkrun`/`libkrunfw` and `target/agent-rootfs` paths.

On Linux, `./scripts/build.sh` uses the repository's rootless Podman builder
(`Containerfile.builder`); build-only toolchains and headers stay out of the
host environment.

You can also use [`cargo-make`](https://github.com/sagiegurari/cargo-make) if
you prefer task aliases. The tasks delegate to the repository scripts:

```bash
# Install cargo-make (optional)
cargo install cargo-make

# View all available tasks
cargo make --list-all-steps

# Build local artifacts
cargo make dev

# Run the local build
cargo make smolvm --version
cargo make smolvm machine run --net --image alpine -- echo hello
cargo make smolvm machine ls
```

**How it works:**
- `cargo make dev` runs `./scripts/build.sh`
- `cargo make smolvm <args>` runs `./scripts/run.sh <args>`
- On macOS, binary is automatically signed with hypervisor entitlements

## Installing From Source

```bash
# Build the current checkout and install it locally
./scripts/install.sh

# Install existing build artifacts without rebuilding
./scripts/install.sh --no-build

# Remove the local install
./scripts/install.sh --uninstall
```

The installer writes runtime files to `~/.smolvm`, installs the agent rootfs
under the platform data directory, and links `smolvm` into `~/.local/bin` by
default. Use `--prefix` and `--bin-dir` to override those paths.

## Running Tests

```bash
# Run all tests
cargo make test

# Run specific test suites
cargo make test-cli        # CLI tests only
cargo make test-sandbox    # Sandbox tests only
cargo make test-microvm    # MicroVM tests only
cargo make test-pack       # Pack tests only
cargo make test-lib        # Unit tests (no VM required)
```

## Agent Rootfs

The agent rootfs resolution order is:
1. `SMOLVM_AGENT_ROOTFS` env var (explicit override)
2. `./target/agent-rootfs` (local development)
3. Platform data directory (`~/.local/share/smolvm/` on Linux, `~/Library/Application Support/smolvm/` on macOS)

The rootfs builder verifies raw bootstrap asset checksums before extraction.
Alpine packages are resolved through the selected stable repository branch so
normal package updates are picked up on rebuild. Each built rootfs includes
`/etc/smolvm-rootfs-build.txt` with the bootstrap inputs and actual installed
APK package versions.

```bash
# Build agent rootfs
./scripts/build-agent-rootfs.sh

# Rebuild agent and update rootfs
./scripts/rebuild-agent.sh
```

## Code Quality

```bash
# Run clippy and fmt checks
cargo make lint

# Auto-fix linting issues
cargo make fix-lints
```

## Other Tasks

```bash
# Install locally from source
cargo make install
```

Other scripts:

```bash
./scripts/build-agent-rootfs.sh
./scripts/install.sh
```

## Runtime Libraries

`libkrunfw` and `libkrun` are built from the checked-out submodules for the
current host. The generated libraries are local build artifacts under `lib/`,
not source-controlled inputs.

`./scripts/build.sh` builds these automatically before building the CLI and
agent rootfs. On Linux this happens inside the rootless Podman builder. Set
`SMOLVM_BUILD_JOBS=8` if you want explicit make parallelism.

The default Linux source build leaves GPU support out of `libkrun` so non-GPU
hosts do not need virglrenderer at runtime. To build the GPU-enabled variant,
use `SMOLVM_BUILD_GPU=1 ./scripts/build.sh`; GPU runtime support remains a host
system dependency.

## Troubleshooting

**Database lock errors** ("Database already open"):
```bash
pkill -f "smolvm serve"
pkill -f "smolvm-bin machine start"
```

**Hung tests**: Check for stuck VM processes:
```bash
ps aux | grep smolvm
```
