//! Storage management for the helper daemon.
//!
//! This module handles:
//! - Storage disk initialization and formatting
//! - OCI image pulling via crane
//! - Layer extraction and deduplication
//! - Overlay filesystem management
//! - Container execution via crun OCI runtime
//! - Support for preloaded image data mounted from the host

use crate::crun::CrunCommand;
use crate::oci::{generate_container_id, OciSpec};
use crate::paths;
use crate::process::{WaitResult, TIMEOUT_EXIT_CODE};
use smolvm_network::guest_env;
use smolvm_protocol::{ImageInfo, OverlayInfo, RegistryAuth, StorageStatus};
use std::ffi::CString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

/// Storage root path (where the ext4 disk is mounted).
const STORAGE_ROOT: &str = "/storage";

/// Directory structure within storage.
const LAYERS_DIR: &str = "layers";
const CONFIGS_DIR: &str = "configs";
const MANIFESTS_DIR: &str = "manifests";
const OVERLAYS_DIR: &str = "overlays";
const IMAGE_METADATA_FILENAME: &str = ".smolvm-image.json";
const IMAGE_OCI_ARCHIVE_FILENAME: &str = ".smolvm-image.oci.tar";
const MATERIALIZED_IMAGE_ROOTFS_DIR: &str = "imported-rootfs";
const WORKSPACE_DIR: &str = "workspace";
const DOCKER_HUB_AUTH_CONFIG_KEY: &str = "https://index.docker.io/v1/";
const DOCKER_HUB_REGISTRY_ALIASES: &[&str] = &["docker.io", "index.docker.io"];

fn validate_storage_id(value: &str, context: &str) -> Result<()> {
    if value.is_empty() {
        return Err(StorageError::ValidationFailed {
            context: context.to_string(),
            reason: "cannot be empty".to_string(),
        });
    }

    if value.len() > 128 {
        return Err(StorageError::ValidationFailed {
            context: context.to_string(),
            reason: "too long (max 128 chars)".to_string(),
        });
    }

    if value.contains('/') || value.contains('\\') {
        return Err(StorageError::ValidationFailed {
            context: context.to_string(),
            reason: "path separators are not allowed".to_string(),
        });
    }

    let path = Path::new(value);
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                return Err(StorageError::ValidationFailed {
                    context: context.to_string(),
                    reason: "parent traversal is not allowed".to_string(),
                });
            }
            std::path::Component::CurDir => {
                return Err(StorageError::ValidationFailed {
                    context: context.to_string(),
                    reason: "dot segments are not allowed".to_string(),
                });
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err(StorageError::ValidationFailed {
                    context: context.to_string(),
                    reason: "path separators are not allowed".to_string(),
                });
            }
            std::path::Component::Normal(seg) => {
                let seg = seg.to_string_lossy();
                if !seg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                {
                    return Err(StorageError::ValidationFailed {
                        context: context.to_string(),
                        reason: format!("contains invalid character(s): {}", value),
                    });
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn ensure_shared_workspace_permissions(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).map_err(|e| StorageError::ReadFile {
        path: path.display().to_string(),
        cause: e.to_string(),
    })?;
    let current_mode = metadata.permissions().mode() & 0o7777;
    let desired_mode = 0o1777;
    if current_mode == desired_mode {
        return Ok(());
    }

    let mut permissions = metadata.permissions();
    permissions.set_mode(desired_mode);
    std::fs::set_permissions(path, permissions).map_err(|e| StorageError::WriteFile {
        path: path.display().to_string(),
        cause: e.to_string(),
    })
}

fn overlay_root_for_workload(workload_id: &str) -> Result<PathBuf> {
    validate_storage_id(workload_id, "workload_id")?;
    Ok(Path::new(STORAGE_ROOT).join(OVERLAYS_DIR).join(workload_id))
}

fn validate_container_destination_path(container_path: &str) -> Result<PathBuf> {
    if !container_path.starts_with('/') {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "must be an absolute path".to_string(),
        });
    }
    if container_path == "/" {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "mounting to '/' is not allowed".to_string(),
        });
    }

    let mut relative = PathBuf::new();
    for component in Path::new(container_path).components() {
        match component {
            std::path::Component::RootDir => {}
            std::path::Component::Normal(seg) => relative.push(seg),
            std::path::Component::ParentDir => {
                return Err(StorageError::ValidationFailed {
                    context: "mount destination".to_string(),
                    reason: "parent traversal is not allowed".to_string(),
                });
            }
            std::path::Component::CurDir => {
                return Err(StorageError::ValidationFailed {
                    context: "mount destination".to_string(),
                    reason: "dot segments are not allowed".to_string(),
                });
            }
            std::path::Component::Prefix(_) => {
                return Err(StorageError::ValidationFailed {
                    context: "mount destination".to_string(),
                    reason: "path prefixes are not allowed".to_string(),
                });
            }
        }
    }

    if relative.as_os_str().is_empty() {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "cannot resolve mount destination".to_string(),
        });
    }

    Ok(relative)
}

fn ensure_mount_target_under_root(rootfs: &Path, container_path: &str) -> Result<PathBuf> {
    let root_canon = rootfs.canonicalize().map_err(|e| StorageError::ReadFile {
        path: rootfs.display().to_string(),
        cause: format!("failed to canonicalize rootfs: {}", e),
    })?;

    let relative = validate_container_destination_path(container_path)?;
    let mut current = root_canon.clone();

    for component in relative.components() {
        let std::path::Component::Normal(seg) = component else {
            return Err(StorageError::ValidationFailed {
                context: "mount destination".to_string(),
                reason: "invalid destination component".to_string(),
            });
        };

        current.push(seg);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    let canon = current.canonicalize().map_err(|e| StorageError::ReadFile {
                        path: current.display().to_string(),
                        cause: format!("failed to canonicalize symlink target: {}", e),
                    })?;
                    if !canon.starts_with(&root_canon) {
                        return Err(StorageError::ValidationFailed {
                            context: "mount destination".to_string(),
                            reason: "resolved path escapes rootfs".to_string(),
                        });
                    }
                }

                if !meta.is_dir() {
                    return Err(StorageError::ValidationFailed {
                        context: "mount destination".to_string(),
                        reason: format!(
                            "destination component is not a directory: {}",
                            current.display()
                        ),
                    });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|err| StorageError::CreateDir {
                    path: current.display().to_string(),
                    cause: err.to_string(),
                })?;
            }
            Err(e) => {
                return Err(StorageError::ReadFile {
                    path: current.display().to_string(),
                    cause: e.to_string(),
                });
            }
        }
    }

    let final_canon = current.canonicalize().map_err(|e| StorageError::ReadFile {
        path: current.display().to_string(),
        cause: format!("failed to canonicalize mount destination: {}", e),
    })?;
    if !final_canon.starts_with(&root_canon) {
        return Err(StorageError::ValidationFailed {
            context: "mount destination".to_string(),
            reason: "resolved path escapes rootfs".to_string(),
        });
    }

    Ok(final_canon)
}

const PRELOADED_IMAGE_ENV: &str = "SMOLVM_PRELOADED_IMAGE";

/// Global state for preloaded image data mounted from the host.
static PRELOADED_IMAGE_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

/// Global state for boot-time volume mounts.
/// Set at startup if SMOLVM_MOUNT_COUNT env var is present.
static BOOT_VOLUME_MOUNTS: OnceLock<Vec<(String, String, bool)>> = OnceLock::new();

/// Initialize preloaded image data by checking the launcher-provided env var.
/// Format: "virtiofs_tag:mount_point" (e.g., "smolvm_image:/preloaded_image")
/// Returns the mount point path if successfully mounted.
pub fn init_preloaded_image_dir() -> Option<PathBuf> {
    let env_val = match std::env::var(PRELOADED_IMAGE_ENV) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let Some((tag, mount_point)) = env_val.split_once(':') else {
        warn!(env_val = %env_val, "invalid preloaded image env format, expected 'tag:mount_point'");
        return None;
    };
    let mount_point = PathBuf::from(mount_point);

    info!(tag = %tag, mount_point = %mount_point.display(), "setting up preloaded image data from virtiofs");

    // Create mount point
    if let Err(e) = std::fs::create_dir_all(&mount_point) {
        warn!(error = %e, mount_point = %mount_point.display(), "failed to create preloaded image mount point");
        return None;
    }

    // Mount virtiofs using direct syscall (avoids ~3-5ms fork+exec overhead)
    let src = std::ffi::CString::new(tag).ok()?;
    let dst = std::ffi::CString::new(mount_point.to_str()?).ok()?;
    let fstype = std::ffi::CString::new("virtiofs").unwrap();
    // SAFETY: mount virtiofs with valid CString arguments
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };

    if rc != 0 {
        let err = std::io::Error::last_os_error();
        warn!(error = %err, tag = %tag, "failed to mount preloaded image virtiofs");
        return None;
    }

    info!(mount_point = %mount_point.display(), "preloaded image data mounted successfully");

    // List contents for debugging (only at debug level to avoid boot overhead)
    if let Ok(entries) = std::fs::read_dir(&mount_point) {
        let entry_names: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        debug!(entry_count = entry_names.len(), entries = ?entry_names, "preloaded image data available");
    }

    Some(mount_point)
}

/// Get the preloaded image data directory if available.
pub fn get_preloaded_image_dir() -> Option<&'static PathBuf> {
    PRELOADED_IMAGE_DIR
        .get_or_init(init_preloaded_image_dir)
        .as_ref()
}

/// Initialize volume mounts at boot by reading SMOLVM_MOUNT_* env vars.
///
/// The host launcher sets:
///   SMOLVM_MOUNT_COUNT=N
///   SMOLVM_MOUNT_0=smolvm0:/data:rw
///   SMOLVM_MOUNT_1=smolvm1:/config:ro
///
/// This mounts each virtiofs device at its staging area and bind-mounts
/// to the guest target path, making volumes visible to all code paths
/// including VmExec.
pub fn init_volume_mounts() -> Result<&'static [(String, String, bool)]> {
    if let Some(mounts) = BOOT_VOLUME_MOUNTS.get() {
        return Ok(mounts);
    }

    let mounts = parse_boot_volume_mounts_from_env()?;

    // Mount using existing logic with empty rootfs prefix so bind mounts
    // go to absolute guest paths (e.g., "/data"), visible to VmExec.
    if !mounts.is_empty() {
        setup_volume_mounts("/", &mounts)?;
    }

    let _ = BOOT_VOLUME_MOUNTS.set(mounts);
    Ok(BOOT_VOLUME_MOUNTS
        .get()
        .expect("boot volume mounts were just initialized"))
}

fn parse_boot_volume_mounts_from_env() -> Result<Vec<(String, String, bool)>> {
    let count: usize = match std::env::var("SMOLVM_MOUNT_COUNT") {
        Ok(v) => v.parse().map_err(|_| StorageError::ValidationFailed {
            context: "SMOLVM_MOUNT_COUNT".to_string(),
            reason: format!("invalid count: {}", v),
        })?,
        Err(_) => return Ok(Vec::new()),
    };

    let mut mounts = Vec::with_capacity(count);
    for i in 0..count {
        let env_key = format!("SMOLVM_MOUNT_{}", i);
        let env_val = std::env::var(&env_key).map_err(|_| StorageError::ValidationFailed {
            context: env_key.clone(),
            reason: "missing mount environment variable".to_string(),
        })?;

        // Parse "tag:guest_path:ro|rw".
        let parts: Vec<&str> = env_val.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(StorageError::ValidationFailed {
                context: env_key,
                reason: format!("invalid mount format, expected tag:path:ro|rw: {}", env_val),
            });
        }

        let read_only = match parts[2] {
            "ro" => true,
            "rw" => false,
            mode => {
                return Err(StorageError::ValidationFailed {
                    context: env_key,
                    reason: format!("invalid mount mode: {}", mode),
                });
            }
        };

        let tag = parts[0].to_string();
        let guest_path = parts[1].to_string();
        info!(tag = %tag, guest_path = %guest_path, read_only = read_only, "boot volume mount");
        mounts.push((tag, guest_path, read_only));
    }

    Ok(mounts)
}

/// Create ImageInfo from preloaded image data.
fn create_preloaded_image_info(image: &str, image_dir: &Path) -> Result<ImageInfo> {
    if let Some(mut info) = read_preloaded_image_metadata(image_dir)? {
        info.reference = image.to_string();
        return Ok(info);
    }

    let mut layer_dirs: Vec<String> = Vec::new();

    let entries = std::fs::read_dir(image_dir)
        .map_err(|e| StorageError::read_error(image_dir.display().to_string(), e))?;

    for entry in entries {
        let entry: std::fs::DirEntry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Skip .tar files, only use directories
            if !name.ends_with(".tar") {
                // Store as sha256:{short_digest} for consistency
                layer_dirs.push(format!("sha256:{}", name));
            }
        }
    }

    // Sort for consistent ordering
    layer_dirs.sort();

    // Calculate approximate size
    let mut total_size = 0u64;
    for layer_digest in &layer_dirs {
        let short_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_path = image_dir.join(short_id);
        if let Ok(size) = dir_size(&layer_path) {
            total_size += size;
        }
    }

    // Determine architecture from environment or default
    #[cfg(target_arch = "aarch64")]
    let architecture = "arm64".to_string();
    #[cfg(target_arch = "x86_64")]
    let architecture = "amd64".to_string();
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let architecture = "unknown".to_string();

    Ok(ImageInfo {
        reference: image.to_string(),
        digest: "preloaded".to_string(),
        size: total_size,
        created: None,
        architecture,
        os: "linux".to_string(),
        layer_count: layer_dirs.len(),
        layers: layer_dirs,
        entrypoint: Vec::new(),
        cmd: Vec::new(),
        env: Vec::new(),
        workdir: None,
        user: None,
    })
}

fn read_preloaded_image_metadata(image_dir: &Path) -> Result<Option<ImageInfo>> {
    let metadata_path = image_dir.join(IMAGE_METADATA_FILENAME);
    if !metadata_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&metadata_path)
        .map_err(|e| StorageError::read_error(metadata_path.display().to_string(), e))?;
    let info = serde_json::from_str(&text)
        .map_err(|e| StorageError::parse_error(IMAGE_METADATA_FILENAME, e))?;
    Ok(Some(info))
}

/// Error type for storage operations.
#[derive(Debug)]
#[allow(dead_code)] // Some variants reserved for future use
pub enum StorageError {
    // ========================================================================
    // I/O Errors
    // ========================================================================
    /// Failed to create a directory.
    CreateDir { path: String, cause: String },
    /// Failed to remove a directory.
    RemoveDir { path: String, cause: String },
    /// Failed to read a file or directory.
    ReadFile { path: String, cause: String },
    /// Failed to write a file.
    WriteFile { path: String, cause: String },
    /// Failed to create a symlink.
    Symlink {
        source: String,
        target: String,
        cause: String,
    },
    /// Path conversion error.
    InvalidPath { path: String },

    // ========================================================================
    // Image Errors
    // ========================================================================
    /// Image not found locally.
    ImageNotFound { image: String },
    /// Failed to pull image from registry.
    ImagePullFailed { image: String, cause: String },
    /// Invalid image reference format.
    InvalidImageReference { reference: String, reason: String },

    // ========================================================================
    // Layer Errors
    // ========================================================================
    /// Layer not found.
    LayerNotFound { digest: String },
    /// Failed to extract layer.
    LayerExtractionFailed { digest: String, cause: String },
    /// Layer index out of bounds.
    LayerIndexOutOfBounds {
        image: String,
        index: usize,
        total: usize,
    },

    // ========================================================================
    // Manifest/Config Errors
    // ========================================================================
    /// Failed to parse manifest or config JSON.
    ParseError { context: String, cause: String },
    /// Missing required field in manifest/config.
    MissingField { context: String, field: String },
    /// Unsupported manifest format.
    UnsupportedManifest { media_type: String },

    // ========================================================================
    // Mount Errors
    // ========================================================================
    /// Failed to mount overlay filesystem.
    OverlayMountFailed { path: String, cause: String },
    /// Failed to mount a virtiofs device.
    VirtiofsMountFailed {
        tag: String,
        path: String,
        cause: String,
    },
    /// Failed to bind-mount a staged filesystem into a rootfs.
    BindMountFailed {
        source: String,
        target: String,
        cause: String,
    },
    /// Failed to remount a bind mount read-only.
    ReadonlyRemountFailed { path: String, cause: String },
    /// Failed to unmount filesystem.
    UnmountFailed { path: String, cause: String },

    // ========================================================================
    // Command Execution Errors
    // ========================================================================
    /// External command (crane, crun, etc.) failed.
    CommandFailed {
        command: String,
        exit_code: Option<i32>,
        stderr: String,
    },
    /// Failed to spawn external command.
    SpawnFailed { command: String, cause: String },

    // ========================================================================
    // Validation Errors
    // ========================================================================
    /// Input validation failed.
    ValidationFailed { context: String, reason: String },

    // ========================================================================
    // Storage State Errors
    // ========================================================================
    /// Storage not formatted/initialized.
    StorageNotReady { reason: String },
    /// No images found in storage.
    NoImagesFound,

    // ========================================================================
    // Generic
    // ========================================================================
    /// Internal error with message (fallback for complex cases).
    Internal { message: String },
}

#[allow(dead_code)] // Some helpers reserved for future use
impl StorageError {
    /// Create a new internal error with the given message.
    /// Use this as a fallback when no specific variant fits.
    pub fn new(message: impl Into<String>) -> Self {
        StorageError::Internal {
            message: message.into(),
        }
    }

    /// Create an I/O read error.
    pub fn read_error(path: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::ReadFile {
            path: path.into(),
            cause: cause.to_string(),
        }
    }

    /// Create an I/O write error.
    pub fn write_error(path: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::WriteFile {
            path: path.into(),
            cause: cause.to_string(),
        }
    }

    /// Create a directory creation error.
    pub fn create_dir_error(path: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::CreateDir {
            path: path.into(),
            cause: cause.to_string(),
        }
    }

    /// Create a parse error.
    pub fn parse_error(context: impl Into<String>, cause: impl std::fmt::Display) -> Self {
        StorageError::ParseError {
            context: context.into(),
            cause: cause.to_string(),
        }
    }

    /// Create a command failed error.
    pub fn command_failed(
        command: impl Into<String>,
        exit_code: Option<i32>,
        stderr: impl Into<String>,
    ) -> Self {
        StorageError::CommandFailed {
            command: command.into(),
            exit_code,
            stderr: stderr.into(),
        }
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // I/O errors
            StorageError::CreateDir { path, cause } => {
                write!(f, "failed to create directory '{}': {}", path, cause)
            }
            StorageError::RemoveDir { path, cause } => {
                write!(f, "failed to remove directory '{}': {}", path, cause)
            }
            StorageError::ReadFile { path, cause } => {
                write!(f, "failed to read '{}': {}", path, cause)
            }
            StorageError::WriteFile { path, cause } => {
                write!(f, "failed to write '{}': {}", path, cause)
            }
            StorageError::Symlink {
                source,
                target,
                cause,
            } => {
                write!(
                    f,
                    "failed to create symlink '{}' -> '{}': {}",
                    source, target, cause
                )
            }
            StorageError::InvalidPath { path } => {
                write!(f, "invalid path: {}", path)
            }

            // Image errors
            StorageError::ImageNotFound { image } => {
                write!(f, "image not found: {}", image)
            }
            StorageError::ImagePullFailed { image, cause } => {
                write!(f, "failed to pull image '{}': {}", image, cause)
            }
            StorageError::InvalidImageReference { reference, reason } => {
                write!(f, "invalid image reference '{}': {}", reference, reason)
            }

            // Layer errors
            StorageError::LayerNotFound { digest } => {
                write!(f, "layer not found: {}", digest)
            }
            StorageError::LayerExtractionFailed { digest, cause } => {
                write!(f, "failed to extract layer '{}': {}", digest, cause)
            }
            StorageError::LayerIndexOutOfBounds {
                image,
                index,
                total,
            } => {
                write!(
                    f,
                    "layer index {} out of bounds for image '{}' (has {} layers)",
                    index, image, total
                )
            }

            // Manifest/config errors
            StorageError::ParseError { context, cause } => {
                write!(f, "failed to parse {}: {}", context, cause)
            }
            StorageError::MissingField { context, field } => {
                write!(f, "missing '{}' in {}", field, context)
            }
            StorageError::UnsupportedManifest { media_type } => {
                write!(f, "unsupported manifest format: {}", media_type)
            }

            // Mount errors
            StorageError::OverlayMountFailed { path, cause } => {
                write!(f, "overlay mount failed at '{}': {}", path, cause)
            }
            StorageError::VirtiofsMountFailed { tag, path, cause } => {
                write!(
                    f,
                    "virtiofs mount '{}' failed at '{}': {}",
                    tag, path, cause
                )
            }
            StorageError::BindMountFailed {
                source,
                target,
                cause,
            } => {
                write!(
                    f,
                    "bind mount '{}' -> '{}' failed: {}",
                    source, target, cause
                )
            }
            StorageError::ReadonlyRemountFailed { path, cause } => {
                write!(f, "read-only bind remount failed at '{}': {}", path, cause)
            }
            StorageError::UnmountFailed { path, cause } => {
                write!(f, "failed to unmount '{}': {}", path, cause)
            }

            // Command errors
            StorageError::CommandFailed {
                command,
                exit_code,
                stderr,
            } => {
                if let Some(code) = exit_code {
                    write!(f, "{} failed (exit {}): {}", command, code, stderr)
                } else {
                    write!(f, "{} failed: {}", command, stderr)
                }
            }
            StorageError::SpawnFailed { command, cause } => {
                write!(f, "failed to spawn '{}': {}", command, cause)
            }

            // Validation errors
            StorageError::ValidationFailed { context, reason } => {
                write!(f, "{}: {}", context, reason)
            }

            // Storage state errors
            StorageError::StorageNotReady { reason } => {
                write!(f, "storage not ready: {}", reason)
            }
            StorageError::NoImagesFound => {
                write!(f, "no images found")
            }

            // Generic
            StorageError::Internal { message } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Internal {
            message: e.to_string(),
        }
    }
}

type Result<T> = std::result::Result<T, StorageError>;

/// Check if a layer directory is properly cached (exists and has content).
///
/// An empty layer directory indicates failed/incomplete extraction and should
/// be re-extracted. This prevents issues where layer_dir.exists() returns true
/// but the directory is empty due to interrupted extraction.
fn is_layer_cached(layer_dir: &Path) -> bool {
    if !layer_dir.exists() {
        return false;
    }
    // Check if the directory has any entries
    match std::fs::read_dir(layer_dir) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

/// Initialize storage directories.
///
/// This function ensures all required storage directories exist and are accessible.
/// Returns early (successfully) if storage hasn't been formatted yet.
///
/// Note: `mount_storage_disk()` already creates all directories, so this is
/// not called during boot. Kept for manual validation/repair use cases.
#[allow(dead_code)]
pub fn init() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);

    // Check if storage root exists or can be created
    if !root.exists() {
        info!(path = %root.display(), "creating storage root directory");
        std::fs::create_dir_all(root).map_err(|e| {
            StorageError::new(format!(
                "failed to create storage root '{}': {} (check permissions and disk space)",
                root.display(),
                e
            ))
        })?;
    }

    // Verify storage root is accessible
    if let Err(e) = std::fs::read_dir(root) {
        return Err(StorageError::new(format!(
            "storage root '{}' exists but is not accessible: {} (check permissions)",
            root.display(),
            e
        )));
    }

    // Create container runtime directories unconditionally — these are needed
    // as soon as containers are requested, regardless of storage format state.
    let container_dirs = [
        (paths::CONTAINERS_RUN_DIR, "container runtime state"),
        (paths::CONTAINERS_LOGS_DIR, "container logs"),
        (paths::CONTAINERS_EXIT_DIR, "container exit codes"),
        (paths::CRUN_ROOT_DIR, "crun state root"),
    ];

    let mut created_count = 0;
    for (dir, description) in &container_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            std::fs::create_dir_all(path).map_err(|e| {
                StorageError::new(format!(
                    "failed to create {} directory '{}': {}",
                    description,
                    path.display(),
                    e
                ))
            })?;
            debug!(path = %path.display(), description = %description, "created directory");
            created_count += 1;
        }
    }

    let workspace_path = root.join(WORKSPACE_DIR);
    if !workspace_path.exists() {
        std::fs::create_dir_all(&workspace_path).map_err(|e| {
            StorageError::new(format!(
                "failed to create shared workspace directory '{}': {}",
                workspace_path.display(),
                e
            ))
        })?;
        debug!(path = %workspace_path.display(), "created shared workspace directory");
        created_count += 1;
    }
    ensure_shared_workspace_permissions(&workspace_path)?;

    // Check for marker file to see if formatted
    let marker = root.join(".smolvm_formatted");
    if !marker.exists() {
        info!(path = %root.display(), "storage not formatted, waiting for format request");
        return Ok(());
    }

    // Create OCI storage directory structure
    let required_dirs = [
        (LAYERS_DIR, "OCI image layers"),
        (CONFIGS_DIR, "image configurations"),
        (MANIFESTS_DIR, "image manifests"),
        (OVERLAYS_DIR, "overlay filesystems"),
    ];

    for (dir, description) in &required_dirs {
        let path = root.join(dir);
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(|e| {
                StorageError::new(format!(
                    "failed to create {} directory '{}': {}",
                    description,
                    path.display(),
                    e
                ))
            })?;
            debug!(path = %path.display(), description = %description, "created directory");
            created_count += 1;
        }
    }

    info!(
        path = %root.display(),
        dirs_created = created_count,
        "storage initialized"
    );
    Ok(())
}

/// Format the storage disk.
///
/// Creates all required directories and writes the format marker file.
/// If directories already exist, they are left as-is.
pub fn format() -> Result<()> {
    let root = Path::new(STORAGE_ROOT);

    // Ensure storage root exists
    if !root.exists() {
        std::fs::create_dir_all(root).map_err(|e| {
            StorageError::new(format!(
                "failed to create storage root '{}': {}",
                root.display(),
                e
            ))
        })?;
    }

    // Create all storage directories
    let all_dirs = [
        (root.join(LAYERS_DIR), "layers"),
        (root.join(CONFIGS_DIR), "configs"),
        (root.join(MANIFESTS_DIR), "manifests"),
        (root.join(OVERLAYS_DIR), "overlays"),
        (root.join(WORKSPACE_DIR), "workspace"),
        (PathBuf::from(paths::CONTAINERS_RUN_DIR), "container run"),
        (PathBuf::from(paths::CONTAINERS_LOGS_DIR), "container logs"),
        (PathBuf::from(paths::CONTAINERS_EXIT_DIR), "container exit"),
        (PathBuf::from(paths::CRUN_ROOT_DIR), "crun state root"),
    ];

    for (path, name) in &all_dirs {
        std::fs::create_dir_all(path).map_err(|e| {
            StorageError::new(format!(
                "failed to create {} directory '{}': {}",
                name,
                path.display(),
                e
            ))
        })?;
    }
    ensure_shared_workspace_permissions(&root.join(WORKSPACE_DIR))?;

    // Create marker file
    let marker = root.join(".smolvm_formatted");
    std::fs::write(&marker, "1").map_err(|e| {
        StorageError::new(format!(
            "failed to write format marker '{}': {}",
            marker.display(),
            e
        ))
    })?;

    info!(path = %root.display(), "storage formatted");
    Ok(())
}

/// Get storage status.
pub fn status() -> Result<StorageStatus> {
    let root = Path::new(STORAGE_ROOT);
    let marker = root.join(".smolvm_formatted");

    let ready = marker.exists();

    // Get disk usage (simplified)
    let (total_bytes, used_bytes) = get_disk_usage(root)?;

    // Count layers and images
    let layer_count = count_entries(&root.join(LAYERS_DIR))?;
    let image_count = count_entries(&root.join(MANIFESTS_DIR))?;

    Ok(StorageStatus {
        ready,
        total_bytes,
        used_bytes,
        layer_count,
        image_count,
    })
}

/// Extract a JSON array of strings from a JSON value.
fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Pull an OCI image with progress callback and optional authentication.
///
/// The callback is called for each layer being pulled with (current, total, layer_id).
pub fn pull_image_with_progress_and_auth<F>(
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
    mut progress: F,
) -> Result<ImageInfo>
where
    F: FnMut(usize, usize, &str),
{
    // Validate image reference before any operations
    crate::oci::validate_image_reference(image).map_err(|e| {
        StorageError::InvalidImageReference {
            reference: image.to_string(),
            reason: e,
        }
    })?;

    if let Some(image_dir) = get_preloaded_image_dir() {
        info!(image = %image, "using preloaded image data, skipping network pull");
        return create_preloaded_image_info(image, image_dir);
    }

    // Determine OCI platform - default to current architecture
    // This must happen BEFORE the cache check so we can verify architecture
    let oci_platform = oci_platform.or({
        #[cfg(target_arch = "aarch64")]
        {
            Some("linux/arm64")
        }
        #[cfg(target_arch = "x86_64")]
        {
            Some("linux/amd64")
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            None
        }
    });

    // Check if already cached with correct architecture
    if let Ok(Some(info)) = query_image(image) {
        // Verify cached image architecture matches requested OCI platform
        let cached_arch = &info.architecture;
        let requested_arch = oci_platform
            .map(oci_platform_to_arch)
            .unwrap_or_else(|| cached_arch.clone());

        if cached_arch == &requested_arch {
            debug!(
                image = %image,
                architecture = %cached_arch,
                "image already cached with correct architecture, skipping pull"
            );
            return Ok(info);
        } else {
            // Architecture mismatch - need to re-pull
            info!(
                image = %image,
                cached_arch = %cached_arch,
                requested_arch = %requested_arch,
                "cached image has wrong architecture, will re-pull"
            );
            // Clean up the mismatched cached manifest
            let root = Path::new(STORAGE_ROOT);
            let manifest_path = root
                .join(MANIFESTS_DIR)
                .join(sanitize_image_name(image) + ".json");
            let _ = std::fs::remove_file(&manifest_path);
        }
    }

    let root = Path::new(STORAGE_ROOT);

    // Get manifest with OCI platform specified
    progress(0, 0, "fetching manifest");
    info!(image = %image, oci_platform = ?oci_platform, "fetching manifest");
    let manifest = crane_manifest(image, oci_platform, auth)?;

    // Parse manifest to get config and layers
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| StorageError::parse_error("manifest", e))?;

    // Handle manifest list (multi-arch)
    let config_digest = if manifest_json.get("config").is_some() {
        manifest_json["config"]["digest"]
            .as_str()
            .ok_or_else(|| StorageError::MissingField {
                context: "manifest".into(),
                field: "config digest".into(),
            })?
    } else if manifest_json.get("manifests").is_some() {
        return Err(StorageError::new(format!(
            "got manifest list instead of image manifest - platform may not be available. \
             manifests: {:?}",
            manifest_json["manifests"].as_array().map(|arr| arr
                .iter()
                .filter_map(|m| m["platform"]["architecture"].as_str())
                .collect::<Vec<_>>())
        )));
    } else {
        return Err(StorageError::UnsupportedManifest {
            media_type: "unknown".into(),
        });
    };

    let layers: Vec<String> = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| StorageError::MissingField {
            context: "manifest".into(),
            field: "layers".into(),
        })?
        .iter()
        .filter_map(|l| l["digest"].as_str().map(String::from))
        .collect();

    let total_layers = layers.len();

    // Save manifest
    let manifest_path = root
        .join(MANIFESTS_DIR)
        .join(sanitize_image_name(image) + ".json");
    std::fs::write(&manifest_path, &manifest)?;

    // Fetch and save config
    let config = crane_config(image, oci_platform, auth)?;
    let config_id = config_digest
        .strip_prefix("sha256:")
        .unwrap_or(config_digest);
    let config_path = root.join(CONFIGS_DIR).join(format!("{}.json", config_id));
    std::fs::write(&config_path, &config)?;

    // Parse config for metadata
    let config_json: serde_json::Value =
        serde_json::from_str(&config).map_err(|e| StorageError::parse_error("config", e))?;

    // Extract layers with progress updates
    let mut total_size = 0u64;
    for (i, layer_digest) in layers.iter().enumerate() {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);

        if is_layer_cached(&layer_dir) {
            info!(layer = %layer_id, "layer already cached");
            // Report progress after confirming cache hit
            progress(i + 1, total_layers, layer_id);
            continue;
        }

        // Clean up empty/incomplete layer directory if it exists
        if layer_dir.exists() {
            warn!(layer = %layer_id, "removing empty/incomplete layer directory");
            if let Err(e) = std::fs::remove_dir_all(&layer_dir) {
                warn!(layer = %layer_id, error = %e, "failed to remove incomplete layer directory");
            }
        }

        info!(
            layer = %layer_id,
            progress = format!("{}/{}", i + 1, total_layers),
            "extracting layer"
        );

        std::fs::create_dir_all(&layer_dir)?;

        // Stream layer directly to tar extraction using direct process piping
        // (no shell to avoid injection risks)

        // Set up auth if provided (temp_dir must stay alive until command completes)
        let temp_dir = setup_docker_auth(image, auth)?;

        // Build crane command
        let mut crane_cmd = Command::new("crane");
        crane_cmd.arg("blob");
        crane_cmd.arg(format!("{}@{}", blob_image_reference(image), layer_digest));
        if let Some(p) = oci_platform {
            crane_cmd.arg("--platform").arg(p);
        }
        crane_cmd.stdout(Stdio::piped());
        // Use null for stderr to avoid deadlock (pipe buffer can fill if not consumed)
        crane_cmd.stderr(Stdio::null());

        if let Some(ref td) = temp_dir {
            crane_cmd.env("DOCKER_CONFIG", td.path());
        }

        // Spawn crane process
        let mut crane = crane_cmd
            .spawn()
            .map_err(|e| StorageError::new(format!("failed to spawn crane: {}", e)))?;

        // Build tar command with crane's stdout as input
        let crane_stdout = crane
            .stdout
            .take()
            .ok_or_else(|| StorageError::new("failed to capture crane stdout".to_string()))?;

        let mut tar_cmd = Command::new("tar");
        tar_cmd.args(["-xzf", "-", "-C"]);
        tar_cmd.arg(&layer_dir);
        tar_cmd.stdin(crane_stdout);
        tar_cmd.stdout(Stdio::null());
        tar_cmd.stderr(Stdio::piped());

        // Run tar and wait for it
        let tar_output = tar_cmd
            .output()
            .map_err(|e| StorageError::new(format!("failed to run tar: {}", e)))?;

        // Wait for crane to finish and check its status
        let crane_status = crane
            .wait()
            .map_err(|e| StorageError::new(format!("failed to wait for crane: {}", e)))?;

        if !crane_status.success() {
            if let Err(e) = std::fs::remove_dir_all(&layer_dir) {
                warn!(layer = %layer_id, error = %e, "failed to clean up layer directory after crane failure");
            }
            return Err(StorageError::new(format!(
                "crane blob failed for layer {}",
                layer_digest
            )));
        }

        if !tar_output.status.success() {
            if let Err(e) = std::fs::remove_dir_all(&layer_dir) {
                warn!(layer = %layer_id, error = %e, "failed to clean up layer directory after tar failure");
            }
            let stderr = String::from_utf8_lossy(&tar_output.stderr);
            return Err(StorageError::new(format!(
                "tar extraction failed for layer {}: {}",
                layer_digest, stderr
            )));
        }

        if let Ok(size) = dir_size(&layer_dir) {
            total_size += size;
        }

        // Report progress after successful extraction
        progress(i + 1, total_layers, layer_id);
    }

    // Signal that layers are done and we're syncing — this can take a while
    // for large images (gigabytes flushed through virtio-blk).
    progress(total_layers, total_layers, "syncing");

    // Sync filesystem to ensure all layer data is persisted to the ext4 journal.
    // Defense in depth: even though shutdown waits for acknowledgment (which also
    // syncs), we sync here because:
    // 1. Commands may complete and VM may exit before shutdown is called
    // 2. Protects against ungraceful termination (SIGKILL, host crash)
    // 3. Empty layer directories cause "executable not found" errors that are
    //    hard to diagnose - better to be safe than sorry
    // SAFETY: sync() is always safe to call
    unsafe {
        libc::sync();
    }

    // Build ImageInfo
    let architecture = config_json["architecture"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let os = config_json["os"].as_str().unwrap_or("linux").to_string();
    let created = config_json["created"].as_str().map(String::from);

    // Extract OCI config fields (Entrypoint, Cmd, Env, WorkingDir, User)
    let oci_config = &config_json["config"];
    let entrypoint = json_string_array(oci_config, "Entrypoint");
    let cmd = json_string_array(oci_config, "Cmd");
    let env = json_string_array(oci_config, "Env");
    let workdir = oci_config["WorkingDir"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);
    let user = oci_config["User"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(ImageInfo {
        reference: image.to_string(),
        digest: config_digest.to_string(),
        size: total_size,
        created,
        architecture,
        os,
        layer_count: layers.len(),
        layers,
        entrypoint,
        cmd,
        env,
        workdir,
        user,
    })
}

/// Query if an image exists locally.
pub fn query_image(image: &str) -> Result<Option<ImageInfo>> {
    if let Some(image_dir) = get_preloaded_image_dir() {
        info!(image = %image, "using preloaded image data for image query");
        return create_preloaded_image_info(image, image_dir).map(Some);
    }

    let root = Path::new(STORAGE_ROOT);
    let manifest_path = root
        .join(MANIFESTS_DIR)
        .join(sanitize_image_name(image) + ".json");

    if !manifest_path.exists() {
        return Ok(None);
    }

    // Read and parse manifest
    let manifest = std::fs::read_to_string(&manifest_path)?;
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|e| StorageError::parse_error("manifest", e))?;

    let config_digest =
        manifest_json["config"]["digest"]
            .as_str()
            .ok_or_else(|| StorageError::MissingField {
                context: "manifest".into(),
                field: "config digest".into(),
            })?;

    let layers: Vec<String> = manifest_json["layers"]
        .as_array()
        .ok_or_else(|| StorageError::MissingField {
            context: "manifest".into(),
            field: "layers".into(),
        })?
        .iter()
        .filter_map(|l| l["digest"].as_str().map(String::from))
        .collect();

    // Read config
    let config_id = config_digest
        .strip_prefix("sha256:")
        .unwrap_or(config_digest);
    let config_path = root.join(CONFIGS_DIR).join(format!("{}.json", config_id));
    let config = std::fs::read_to_string(&config_path)?;
    let config_json: serde_json::Value =
        serde_json::from_str(&config).map_err(|e| StorageError::parse_error("config", e))?;

    let architecture = config_json["architecture"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let os = config_json["os"].as_str().unwrap_or("linux").to_string();
    let created = config_json["created"].as_str().map(String::from);

    // Verify all layers exist and calculate total size
    let mut total_size = 0u64;
    for layer_digest in &layers {
        let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
        let layer_dir = root.join(LAYERS_DIR).join(layer_id);
        if !layer_dir.exists() {
            // Layer missing - image is incomplete, needs re-pull
            // Clean up corrupt manifest to avoid repeated failures
            warn!(layer = %layer_id, image = %image, "cached image has missing layer, cleaning up and will re-pull");
            let _ = std::fs::remove_file(&manifest_path);
            return Ok(None);
        }
        if let Ok(size) = dir_size(&layer_dir) {
            total_size += size;
        }
    }

    // Extract OCI config fields
    let oci_config = &config_json["config"];
    let entrypoint = json_string_array(oci_config, "Entrypoint");
    let cmd = json_string_array(oci_config, "Cmd");
    let env = json_string_array(oci_config, "Env");
    let workdir = oci_config["WorkingDir"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);
    let user = oci_config["User"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);

    Ok(Some(ImageInfo {
        reference: image.to_string(),
        digest: config_digest.to_string(),
        size: total_size,
        created,
        architecture,
        os,
        layer_count: layers.len(),
        layers,
        entrypoint,
        cmd,
        env,
        workdir,
        user,
    }))
}

/// List all cached images.
pub fn list_images() -> Result<Vec<ImageInfo>> {
    let root = Path::new(STORAGE_ROOT);
    let manifests_dir = root.join(MANIFESTS_DIR);

    if !manifests_dir.exists() {
        return Ok(Vec::new());
    }

    let mut images = Vec::new();

    for entry in std::fs::read_dir(&manifests_dir)? {
        let entry: std::fs::DirEntry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            // Extract image name from filename
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(unsanitize_image_name)
                .unwrap_or_default();

            if let Ok(Some(info)) = query_image(&name) {
                images.push(info);
            }
        }
    }

    Ok(images)
}

/// Export a layer as a tar archive to a file.
///
/// Used by `smolvm pack` to extract layers for packaging.
/// Returns the path to the created tar file.
/// Find the directory path for a specific layer of an image.
///
/// Scans manifests to find the image by digest, then resolves the layer
/// directory. Used by the streaming export handler to pipe tar directly
/// without creating a temp file.
pub fn find_layer_path(image_digest: &str, layer_index: usize) -> Result<PathBuf> {
    let root = Path::new(STORAGE_ROOT);

    let manifests_dir = root.join(MANIFESTS_DIR);
    if !manifests_dir.exists() {
        return Err(StorageError::NoImagesFound);
    }

    let mut layers: Option<Vec<String>> = None;

    for entry in std::fs::read_dir(&manifests_dir)? {
        let entry = entry?;
        let content = std::fs::read_to_string(entry.path())?;
        if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
            if let Some(config) = manifest.get("config") {
                if let Some(digest) = config.get("digest").and_then(|d| d.as_str()) {
                    if digest == image_digest {
                        layers = manifest["layers"].as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|l| l["digest"].as_str().map(String::from))
                                .collect()
                        });
                        break;
                    }
                }
            }
        }
    }

    let layers = layers.ok_or_else(|| {
        StorageError::new(format!("image with digest {} not found", image_digest))
    })?;

    if layer_index >= layers.len() {
        return Err(StorageError::new(format!(
            "layer index {} out of bounds (image has {} layers)",
            layer_index,
            layers.len()
        )));
    }

    let layer_digest = &layers[layer_index];
    let layer_id = layer_digest.strip_prefix("sha256:").unwrap_or(layer_digest);
    let layer_dir = root.join(LAYERS_DIR).join(layer_id);

    if !layer_dir.exists() {
        return Err(StorageError::new(format!(
            "layer directory not found: {}",
            layer_dir.display()
        )));
    }

    Ok(layer_dir)
}

/// Run garbage collection.
pub fn garbage_collect(dry_run: bool) -> Result<u64> {
    let root = Path::new(STORAGE_ROOT);
    let layers_dir = root.join(LAYERS_DIR);
    let manifests_dir = root.join(MANIFESTS_DIR);

    // Collect all referenced layers
    let mut referenced_layers = std::collections::HashSet::new();

    if manifests_dir.exists() {
        for entry in std::fs::read_dir(&manifests_dir)? {
            let entry = entry?;
            let content = std::fs::read_to_string(entry.path())?;
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(layers) = manifest["layers"].as_array() {
                    for layer in layers {
                        if let Some(digest) = layer["digest"].as_str() {
                            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
                            referenced_layers.insert(id.to_string());
                        }
                    }
                }
            }
        }
    }

    // Find unreferenced layers
    let mut freed = 0u64;

    if layers_dir.exists() {
        for entry in std::fs::read_dir(&layers_dir)? {
            let entry = entry?;
            let layer_id = entry.file_name().to_string_lossy().to_string();

            if !referenced_layers.contains(&layer_id) {
                let size = dir_size(&entry.path()).unwrap_or(0);
                info!(layer = %layer_id, size = size, dry_run = dry_run, "unreferenced layer");

                if !dry_run {
                    std::fs::remove_dir_all(entry.path())?;
                }

                freed += size;
            }
        }
    }

    Ok(freed)
}

// ============================================================================
// Overlay Setup Helper
// ============================================================================

/// Helper for setting up overlay filesystems.
///
/// Encapsulates the common logic for preparing overlay directories,
/// mounting layers, and creating OCI bundles.
struct OverlaySetup {
    overlay_root: PathBuf,
    upper_path: PathBuf,
    work_path: PathBuf,
    merged_path: PathBuf,
    workload_id: String,
}

impl OverlaySetup {
    /// Create a new overlay setup for the given workload.
    fn new(workload_id: &str) -> Result<Self> {
        let overlay_root = overlay_root_for_workload(workload_id)?;
        Ok(Self {
            upper_path: overlay_root.join("upper"),
            work_path: overlay_root.join("work"),
            merged_path: overlay_root.join("merged"),
            overlay_root,
            workload_id: workload_id.to_string(),
        })
    }

    /// Prepare overlay directories, cleaning up any previous state.
    fn prepare_directories(&self) -> Result<()> {
        // Clean up any previous overlay state - workdir must be empty for overlay mount
        if self.overlay_root.exists() {
            // Try to unmount if previously mounted
            if let Err(e) = Command::new("umount").arg(&self.merged_path).output() {
                debug!(path = %self.merged_path.display(), error = %e, "failed to unmount previous overlay (may not have been mounted)");
            }
            // Remove old directories to ensure clean state
            if let Err(e) = std::fs::remove_dir_all(&self.overlay_root) {
                warn!(path = %self.overlay_root.display(), error = %e, "failed to remove old overlay directory");
            }
        }

        std::fs::create_dir_all(&self.upper_path)?;
        std::fs::create_dir_all(&self.work_path)?;
        std::fs::create_dir_all(&self.merged_path)?;

        Ok(())
    }

    /// Set up the upper layer with DNS resolution and /dev directory.
    fn setup_upper_layer(&self) -> Result<()> {
        // Set up DNS resolution BEFORE mounting. Image-backed workloads read
        // `/etc/resolv.conf` from the overlay upper layer, so this file must
        // match the active networking mode rather than always hardcoding
        // public resolvers.
        let upper_etc = self.upper_path.join("etc");
        std::fs::create_dir_all(&upper_etc)?;
        let resolv_path = upper_etc.join("resolv.conf");
        let resolv_contents = overlay_resolv_conf_contents();
        if let Err(e) = std::fs::write(&resolv_path, resolv_contents) {
            warn!(error = %e, "failed to write resolv.conf to upper layer");
        }

        // Create /dev directory in upper layer - we'll bind mount the real /dev later
        let upper_dev = self.upper_path.join("dev");
        std::fs::create_dir_all(&upper_dev)?;

        Ok(())
    }

    /// Verify that all layer paths exist and log warnings for empty layers.
    fn verify_layers(&self, lowerdirs: &[String]) -> Result<()> {
        for layer_path in lowerdirs {
            let path = Path::new(layer_path);
            if !path.exists() {
                return Err(StorageError::new(format!(
                    "layer path does not exist: {}",
                    layer_path
                )));
            }
            // Check if layer has contents
            let entry_count = std::fs::read_dir(path)
                .map(|entries| entries.count())
                .unwrap_or(0);
            if entry_count == 0 {
                warn!(layer = %layer_path, "layer directory is empty");
            }
        }
        Ok(())
    }

    /// Mount the overlay filesystem with fallback from multi-lowerdir to sequential.
    fn mount(&self, lowerdirs: &[String]) -> Result<()> {
        // Try multi-lowerdir mount first (efficient)
        let mount_result = try_mount_overlay_multi_lower(
            lowerdirs,
            &self.upper_path,
            &self.work_path,
            &self.merged_path,
        );

        if let Err(multi_err) = mount_result {
            if lowerdirs.len() > 1 {
                // Multi-lowerdir failed, try sequential approach
                warn!(
                    layer_count = lowerdirs.len(),
                    error = %multi_err,
                    "multi-lowerdir mount failed, trying sequential overlay construction"
                );

                mount_overlay_sequential(
                    lowerdirs,
                    &self.upper_path,
                    &self.work_path,
                    &self.merged_path,
                    &self.overlay_root,
                )?;
            } else {
                // Single layer, can't use sequential approach
                return Err(multi_err);
            }
        }

        Ok(())
    }

    /// Verify that the mount succeeded by checking merged directory contents.
    fn verify_mount(&self) -> usize {
        let entry_count = std::fs::read_dir(&self.merged_path)
            .map(|entries| entries.count())
            .unwrap_or(0);

        if entry_count == 0 {
            warn!(
                workload_id = %self.workload_id,
                merged_path = %self.merged_path.display(),
                "overlay mount returned success but merged directory is empty"
            );
            // Try to get more info about the mount state
            if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
                let merged_str = self.merged_path.to_string_lossy();
                let is_mounted = mounts.lines().any(|line| line.contains(&*merged_str));
                warn!(is_mounted = is_mounted, "mount point status");
            }
        }

        entry_count
    }

    /// Create OCI bundle directory structure.
    fn create_bundle(&self) -> Result<()> {
        let bundle_path = self.overlay_root.join("bundle");
        std::fs::create_dir_all(&bundle_path)?;

        // Create symlink: bundle/rootfs -> ../merged
        let rootfs_link = bundle_path.join("rootfs");
        if !rootfs_link.exists() {
            std::os::unix::fs::symlink("../merged", &rootfs_link).map_err(|e| {
                StorageError::new(format!("failed to create rootfs symlink: {}", e))
            })?;
        }

        debug!(bundle = %bundle_path.display(), "OCI bundle directory created");
        Ok(())
    }

    /// Convert to OverlayInfo result.
    fn into_overlay_info(self) -> OverlayInfo {
        OverlayInfo {
            rootfs_path: self.merged_path.display().to_string(),
            upper_path: self.upper_path.display().to_string(),
            work_path: self.work_path.display().to_string(),
        }
    }

    /// Execute the full overlay setup pipeline with the given lower directories.
    fn execute(self, lowerdirs: Vec<String>) -> Result<OverlayInfo> {
        self.prepare_directories()?;
        self.setup_upper_layer()?;
        self.verify_layers(&lowerdirs)?;
        self.mount(&lowerdirs)?;

        let entry_count = self.verify_mount();
        info!(workload_id = %self.workload_id, entry_count = entry_count, "overlay mounted");

        self.create_bundle()?;
        Ok(self.into_overlay_info())
    }

    /// Reuse an existing persistent overlay or create a new one.
    ///
    /// If the overlay is already mounted, returns it immediately.
    /// If the overlay directory exists but is not mounted (e.g. after VM restart),
    /// remounts it preserving the upper layer (which contains previous changes).
    /// If the overlay does not exist at all, creates it fresh.
    fn execute_or_remount(self, lowerdirs: Vec<String>) -> Result<OverlayInfo> {
        // Already mounted — just reuse it
        if self.merged_path.exists() && is_mountpoint(&self.merged_path) {
            info!(workload_id = %self.workload_id, "reusing existing persistent overlay");
            self.create_bundle()?;
            return Ok(self.into_overlay_info());
        }

        // Upper layer exists from a previous session — remount preserving it
        if self.upper_path.exists() {
            info!(workload_id = %self.workload_id, "remounting persistent overlay with existing upper layer");

            // overlayfs requires an empty work directory at mount time
            if self.work_path.exists() {
                let _ = std::fs::remove_dir_all(&self.work_path);
            }
            std::fs::create_dir_all(&self.work_path)?;
            std::fs::create_dir_all(&self.merged_path)?;

            self.verify_layers(&lowerdirs)?;
            self.mount(&lowerdirs)?;

            let entry_count = self.verify_mount();
            info!(workload_id = %self.workload_id, entry_count = entry_count, "persistent overlay remounted");

            self.create_bundle()?;
            return Ok(self.into_overlay_info());
        }

        // First time — full setup
        info!(workload_id = %self.workload_id, "creating new persistent overlay");
        self.execute(lowerdirs)
    }
}

fn overlay_resolv_conf_contents() -> String {
    if std::env::var(guest_env::BACKEND).as_deref() == Ok(guest_env::BACKEND_VIRTIO_NET) {
        if let Ok(dns_server) = std::env::var(guest_env::DNS) {
            if !dns_server.is_empty() {
                return format!("nameserver {}\n", dns_server);
            }
        }
    }

    "nameserver 8.8.8.8\nnameserver 1.1.1.1\n".to_string()
}

/// Prepare an overlay filesystem for a workload.
///
/// Reuses an existing overlay if already mounted, remounts if the upper
/// directory exists (preserving state from previous sessions), or creates
/// a fresh overlay. This idempotent behavior is critical for `machine cp`
/// which may call this before or after `machine exec`.
pub fn prepare_overlay(image: &str, workload_id: &str) -> Result<OverlayInfo> {
    if let Some(image_dir) = get_preloaded_image_dir() {
        info!(image = %image, image_dir = %image_dir.display(), "using preloaded image data");
        return prepare_overlay_from_preloaded_image(image, workload_id, image_dir);
    }

    // Ensure image exists
    let info = query_image(image)?
        .ok_or_else(|| StorageError::new(format!("image not found: {}", image)))?;

    // Build lowerdir from layers (reversed for overlay order - top layer first)
    let root = Path::new(STORAGE_ROOT);
    let lowerdirs: Vec<String> = info
        .layers
        .iter()
        .rev()
        .map(|digest| {
            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
            root.join(LAYERS_DIR).join(id).display().to_string()
        })
        .collect();

    OverlaySetup::new(workload_id)?.execute_or_remount(lowerdirs)
}

/// Prepare an overlay filesystem using preloaded image data.
fn prepare_overlay_from_preloaded_image(
    image: &str,
    workload_id: &str,
    image_dir: &Path,
) -> Result<OverlayInfo> {
    if image_dir.join(IMAGE_OCI_ARCHIVE_FILENAME).is_file() {
        let rootfs = materialize_preloaded_oci_archive(image_dir)?;
        return OverlaySetup::new(workload_id)?.execute(vec![rootfs.display().to_string()]);
    }

    let layer_dirs = preloaded_layer_dirs(image_dir)?;

    if layer_dirs.is_empty() {
        return Err(StorageError::new(format!(
            "no layer directories found in {}",
            image_dir.display()
        )));
    }

    info!(
        image = %image,
        layer_count = layer_dirs.len(),
        layers = ?layer_dirs.iter().map(|p| p.file_name().unwrap_or_default().to_string_lossy().to_string()).collect::<Vec<_>>(),
        "found preloaded layer directories"
    );

    // Build lowerdir from layers (reversed for overlay order - top layer first)
    let lowerdirs: Vec<String> = layer_dirs
        .iter()
        .rev()
        .map(|path| path.display().to_string())
        .collect();

    // Use shared overlay setup logic
    OverlaySetup::new(workload_id)?.execute(lowerdirs)
}

/// Build lowerdir list from a pulled OCI image's layers.
fn get_image_lowerdirs(image: &str) -> Result<Vec<String>> {
    let info = query_image(image)?
        .ok_or_else(|| StorageError::new(format!("image not found: {}", image)))?;

    let root = Path::new(STORAGE_ROOT);
    Ok(info
        .layers
        .iter()
        .rev()
        .map(|digest| {
            let id = digest.strip_prefix("sha256:").unwrap_or(digest);
            root.join(LAYERS_DIR).join(id).display().to_string()
        })
        .collect())
}

/// Build lowerdir list from preloaded image data.
fn get_preloaded_lowerdirs(image_dir: &Path) -> Result<Vec<String>> {
    if image_dir.join(IMAGE_OCI_ARCHIVE_FILENAME).is_file() {
        let rootfs = materialize_preloaded_oci_archive(image_dir)?;
        return Ok(vec![rootfs.display().to_string()]);
    }

    let layer_dirs = preloaded_layer_dirs(image_dir)?;
    if layer_dirs.is_empty() {
        return Err(StorageError::new(format!(
            "no layer directories found in {}",
            image_dir.display()
        )));
    }

    Ok(layer_dirs
        .iter()
        .rev()
        .map(|path| path.display().to_string())
        .collect())
}

fn materialize_preloaded_oci_archive(image_dir: &Path) -> Result<PathBuf> {
    let archive_path = image_dir.join(IMAGE_OCI_ARCHIVE_FILENAME);
    if !archive_path.is_file() {
        return Err(StorageError::new(format!(
            "preloaded OCI archive not found: {}",
            archive_path.display()
        )));
    }

    let info = read_preloaded_image_metadata(image_dir)?
        .ok_or_else(|| StorageError::new("preloaded OCI metadata not found".to_string()))?;
    let image_id = info
        .digest
        .strip_prefix("sha256:")
        .unwrap_or(&info.digest)
        .to_string();
    validate_storage_id(&image_id, "preloaded OCI image digest")?;

    let image_root = Path::new(STORAGE_ROOT)
        .join(MATERIALIZED_IMAGE_ROOTFS_DIR)
        .join(&image_id);
    let rootfs_path = image_root.join("rootfs");
    let marker_path = image_root.join(".complete");
    if marker_path.is_file() && rootfs_path.is_dir() {
        return Ok(rootfs_path);
    }

    info!(
        image = %info.reference,
        digest = %info.digest,
        "materializing preloaded OCI archive"
    );

    if image_root.exists() {
        std::fs::remove_dir_all(&image_root)?;
    }
    std::fs::create_dir_all(&image_root)?;

    let work_dir = image_root.join("work");
    let staging_rootfs = image_root.join("rootfs.tmp");
    let platform = format!("{}/{}", info.os, info.architecture);
    smolvm_pack::oci_archive::import_oci_archive_rootfs(
        &archive_path,
        &staging_rootfs,
        &work_dir,
        Some(&platform),
    )
    .map_err(|e| StorageError::new(format!("failed to materialize OCI archive: {}", e)))?;

    if rootfs_path.exists() {
        std::fs::remove_dir_all(&rootfs_path)?;
    }
    std::fs::rename(&staging_rootfs, &rootfs_path)?;
    if work_dir.exists() {
        std::fs::remove_dir_all(&work_dir)?;
    }
    std::fs::write(&marker_path, info.digest.as_bytes())?;

    Ok(rootfs_path)
}

fn preloaded_layer_dirs(image_dir: &Path) -> Result<Vec<PathBuf>> {
    if let Some(info) = read_preloaded_image_metadata(image_dir)? {
        let dirs = info
            .layers
            .iter()
            .map(|digest| {
                let id = digest.strip_prefix("sha256:").unwrap_or(digest);
                image_dir.join(id)
            })
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        if !dirs.is_empty() {
            return Ok(dirs);
        }
    }

    let mut layer_dirs: Vec<PathBuf> = Vec::new();

    let entries = std::fs::read_dir(image_dir)
        .map_err(|e| StorageError::read_error(image_dir.display().to_string(), e))?;

    for entry in entries {
        let entry: std::fs::DirEntry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".tar") {
                layer_dirs.push(path);
            }
        }
    }

    layer_dirs.sort();
    Ok(layer_dirs)
}

/// Clean up an overlay filesystem.
/// Log the error inside this function to skip the repetitive Err matching when unnecessary.
pub fn cleanup_overlay(workload_id: &str) -> Result<()> {
    let overlay_root = overlay_root_for_workload(workload_id)?;
    let merged_path = overlay_root.join("merged");

    // Unmount nested bind mounts inside the overlay rootfs first. Volume mounts
    // like /workspace are bind-mounted under merged/, and they keep the overlay
    // rootfs busy if we try to unmount merged directly.
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        let merged_prefix = format!("{}/", merged_path.display());
        let mut nested_mounts: Vec<PathBuf> = mounts
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 2 {
                    return None;
                }

                let mount_point = PathBuf::from(parts[1]);
                let mount_point_str = mount_point.to_string_lossy();
                if mount_point_str.starts_with(&merged_prefix) {
                    Some(mount_point)
                } else {
                    None
                }
            })
            .collect();

        nested_mounts.sort_by_key(|path| std::cmp::Reverse(path.components().count()));

        for mount_point in nested_mounts {
            if let Err(e) = Command::new("umount").arg(&mount_point).status() {
                debug!(
                    workload_id = %workload_id,
                    path = %mount_point.display(),
                    error = %e,
                    "failed to unmount nested overlay mount"
                );
            }
        }
    }

    // Unmount main merged path if mounted
    if merged_path.exists() {
        if let Err(e) = Command::new("umount").arg(&merged_path).status() {
            debug!(
                workload_id = %workload_id,
                path = %merged_path.display(),
                error = %e,
                "failed to unmount overlay (may not have been mounted)"
            );
        }
    }

    // Remove overlay directories (includes merged_layers, upper, work, etc.)
    if overlay_root.exists() {
        if let Err(cleanup_err) = std::fs::remove_dir_all(&overlay_root) {
            warn!(
                workload_id = %workload_id,
                error = %cleanup_err,
                "failed to clean up overlay."
            );
            return Err(cleanup_err.into());
        }
    }

    info!(workload_id = %workload_id, "overlay cleaned up");
    Ok(())
}

/// Result of running a command.
///
/// Uses `Vec<u8>` so binary output is preserved end-to-end.
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Prepared rootfs info for a single ephemeral run.
pub struct PreparedOverlayRootfs {
    pub workload_id: String,
    pub rootfs_path: String,
}

/// Inputs for one foreground container command.
pub struct RunCommandRequest<'a> {
    pub image: &'a str,
    pub command: &'a [String],
    pub env: &'a [(String, String)],
    pub workdir: Option<&'a str>,
    pub user: Option<&'a str>,
    pub mounts: &'a [(String, String, bool)],
    pub timeout_ms: Option<u64>,
    pub persistent_overlay_id: Option<&'a str>,
    pub client_fd: Option<std::os::unix::io::RawFd>,
}

fn prepare_rootfs_for_ephemeral_run(image: &str) -> Result<PreparedOverlayRootfs> {
    let workload_id = format!(
        "run-{}-{}",
        sanitize_image_name(image),
        generate_container_id()
    );
    let overlay = prepare_overlay(image, &workload_id)?;
    debug!(
        workload_id = %workload_id,
        rootfs = %overlay.rootfs_path,
        "prepared ephemeral overlay for command execution"
    );
    Ok(PreparedOverlayRootfs {
        workload_id,
        rootfs_path: overlay.rootfs_path,
    })
}

/// Run a command in an image's overlay rootfs using crun OCI runtime.
///
/// When `persistent_overlay_id` is `Some`, the overlay persists across runs
/// (filesystem changes accumulate). When `None`, an ephemeral overlay is
/// created and destroyed after the run.
pub fn run_command(request: RunCommandRequest<'_>) -> Result<RunResult> {
    // Validate inputs
    crate::oci::validate_image_reference(request.image).map_err(StorageError::new)?;
    crate::oci::validate_env_vars(request.env).map_err(StorageError::new)?;

    let prepared = match request.persistent_overlay_id {
        Some(id) => prepare_for_run_persistent(request.image, id)?,
        None => prepare_rootfs_for_ephemeral_run(request.image)?,
    };
    debug!(rootfs = %prepared.rootfs_path, persistent = request.persistent_overlay_id.is_some(), "using overlay for command execution");

    // Gather all steps to run a command in a single anon function
    let result = (|| {
        // Setup volume mounts (mount virtiofs to staging area)
        let mounted_paths = setup_volume_mounts(&prepared.rootfs_path, request.mounts)?;

        // Get bundle path
        let overlay_root = Path::new(STORAGE_ROOT)
            .join(OVERLAYS_DIR)
            .join(&prepared.workload_id);
        let bundle_path = overlay_root.join("bundle");

        // Create OCI spec
        let workdir_str = request.workdir.unwrap_or("/");
        let identity =
            crate::oci::resolve_process_identity(Path::new(&prepared.rootfs_path), request.user)
                .map_err(StorageError::new)?;
        let mut spec = OciSpec::new(request.command, request.env, workdir_str, false, &identity);
        spec.add_gpu_devices_if_available();

        // Add virtiofs bind mounts to OCI spec
        for (tag, container_path, read_only) in request.mounts {
            let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
            spec.add_bind_mount(
                &virtiofs_mount.to_string_lossy(),
                container_path,
                *read_only,
            );
        }

        // Shared workspace: /storage/workspace → /workspace inside container
        let workspace_src = Path::new(STORAGE_ROOT).join(WORKSPACE_DIR);
        if workspace_src.exists() {
            spec.add_bind_mount(&workspace_src.to_string_lossy(), "/workspace", false);
        }

        // Forward SSH agent into the container if enabled at boot.
        crate::ssh_agent::inject_into_container(&mut spec);

        // Write config.json to bundle
        spec.write_to(&bundle_path)
            .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;

        // Generate unique container ID for this execution
        let container_id = generate_container_id();

        // Run with crun
        let result = run_with_crun(
            &bundle_path,
            &container_id,
            request.timeout_ms,
            request.client_fd,
        );

        // Note: virtiofs mounts are left in place for reuse
        // They will be cleaned up when the overlay is cleaned up or the VM shuts down
        let _ = mounted_paths; // Suppress unused warning

        result
    })();

    // Only clean up ephemeral overlays; persistent ones survive across runs
    if request.persistent_overlay_id.is_none() {
        let _ = cleanup_overlay(&prepared.workload_id);
    }
    result
}

/// Spawn a command in an image's overlay rootfs and return the crun PID.
///
/// Unlike `run_command`, this does not wait for the container to exit. The
/// container runs detached under crun with stdout/stderr redirected to
/// /dev/null; the returned PID is the crun process, which stays alive as
/// long as the container init runs.
///
/// Requires a persistent overlay ID — ephemeral overlays would leak their
/// upper/work/merged directories because nothing is waiting to clean them
/// up after the container exits.
pub fn spawn_in_overlay(
    image: &str,
    command: &[String],
    env: &[(String, String)],
    workdir: Option<&str>,
    user: Option<&str>,
    mounts: &[(String, String, bool)],
    persistent_overlay_id: &str,
) -> Result<u32> {
    crate::oci::validate_image_reference(image).map_err(StorageError::new)?;
    crate::oci::validate_env_vars(env).map_err(StorageError::new)?;

    let prepared = prepare_for_run_persistent(image, persistent_overlay_id)?;
    debug!(rootfs = %prepared.rootfs_path, "using persistent overlay for background command");

    let mounted_paths = setup_volume_mounts(&prepared.rootfs_path, mounts)?;

    let overlay_root = Path::new(STORAGE_ROOT)
        .join(OVERLAYS_DIR)
        .join(&prepared.workload_id);
    let bundle_path = overlay_root.join("bundle");

    let workdir_str = workdir.unwrap_or("/");
    let identity = crate::oci::resolve_process_identity(Path::new(&prepared.rootfs_path), user)
        .map_err(StorageError::new)?;
    let mut spec = OciSpec::new(command, env, workdir_str, false, &identity);

    for (tag, container_path, read_only) in mounts {
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        spec.add_bind_mount(
            &virtiofs_mount.to_string_lossy(),
            container_path,
            *read_only,
        );
    }

    let workspace_src = Path::new(STORAGE_ROOT).join(WORKSPACE_DIR);
    if workspace_src.exists() {
        spec.add_bind_mount(&workspace_src.to_string_lossy(), "/workspace", false);
    }

    crate::ssh_agent::inject_into_container(&mut spec);

    spec.write_to(&bundle_path)
        .map_err(|e| StorageError::new(format!("failed to write OCI spec: {}", e)))?;

    let container_id = generate_container_id();

    let child = CrunCommand::run(&bundle_path, &container_id)
        .stdin_null()
        .discard_output()
        .spawn()
        .map_err(|e| {
            StorageError::new(format!(
                "failed to spawn crun: {}. Is crun installed at {}?",
                e,
                paths::CRUN_PATH
            ))
        })?;

    let pid = child.id();
    // Don't wait on the child; it reaps itself when the container exits.
    // reap_background_children() in the agent's accept loop collects the
    // eventual zombie.
    std::mem::forget(child);

    let _ = mounted_paths; // suppress unused warning; mounts persist with the overlay
    info!(container_id = %container_id, pid = pid, "background container started");
    Ok(pid)
}

/// Prepare for running a command - returns the rootfs path.
/// This is used by interactive mode which spawns the command separately.
pub fn prepare_for_run(image: &str) -> Result<PreparedOverlayRootfs> {
    prepare_rootfs_for_ephemeral_run(image)
}

/// Prepare a persistent overlay that survives across exec sessions.
///
/// Uses a deterministic workload ID derived from `overlay_id` (typically the
/// machine name). If the overlay already exists and is mounted, reuses it.
/// If it exists but is unmounted (e.g. after VM restart), remounts preserving
/// the upper layer that contains previous changes.
pub fn prepare_for_run_persistent(image: &str, overlay_id: &str) -> Result<PreparedOverlayRootfs> {
    validate_storage_id(overlay_id, "persistent overlay id")?;
    let workload_id = format!("persistent-{}", overlay_id);

    // Resolve image layers (same logic as prepare_overlay)
    let lowerdirs = if let Some(image_dir) = get_preloaded_image_dir() {
        get_preloaded_lowerdirs(image_dir)?
    } else {
        get_image_lowerdirs(image)?
    };

    let setup = OverlaySetup::new(&workload_id)?;
    let overlay = setup.execute_or_remount(lowerdirs)?;

    debug!(
        workload_id = %workload_id,
        rootfs = %overlay.rootfs_path,
        "prepared persistent overlay for command execution"
    );
    Ok(PreparedOverlayRootfs {
        workload_id,
        rootfs_path: overlay.rootfs_path,
    })
}

/// Setup volume mounts for a rootfs (public wrapper).
pub fn setup_mounts(rootfs: &str, mounts: &[(String, String, bool)]) -> Result<()> {
    let _mounted_paths = setup_volume_mounts(rootfs, mounts)?;
    Ok(())
}

/// Setup volume mounts by mounting virtiofs and bind-mounting into the rootfs.
fn setup_volume_mounts(rootfs: &str, mounts: &[(String, String, bool)]) -> Result<Vec<PathBuf>> {
    let mut mounted_paths = Vec::new();
    let rootfs_path = Path::new(rootfs);

    for (tag, container_path, read_only) in mounts {
        validate_storage_id(tag, "mount tag")?;
        debug!(tag = %tag, container_path = %container_path, read_only = %read_only, "setting up volume mount");

        // First, mount the virtiofs device at a staging location
        let virtiofs_mount = Path::new(paths::VIRTIOFS_MOUNT_ROOT).join(tag);
        std::fs::create_dir_all(&virtiofs_mount)?;

        // Check if already mounted
        if !is_mountpoint(&virtiofs_mount) {
            info!(tag = %tag, mount_point = %virtiofs_mount.display(), "mounting virtiofs");
            mount_virtiofs(tag, &virtiofs_mount)?;
        }

        // Now bind-mount into the container rootfs
        let target_path = ensure_mount_target_under_root(rootfs_path, container_path)?;

        // Check if already bind-mounted
        let created_bind_mount = if !is_mountpoint(&target_path) {
            info!(
                source = %virtiofs_mount.display(),
                target = %target_path.display(),
                read_only = %read_only,
                "bind-mounting into container"
            );

            bind_mount(&virtiofs_mount, &target_path)?;
            true
        } else {
            false
        };

        // Remount read-only if requested. If this setup just created the bind
        // mount, remove it before returning so the guest cannot keep a writable
        // mount after a failed read-only setup.
        if *read_only {
            if let Err(err) = remount_bind_readonly(&target_path) {
                if created_bind_mount {
                    if let Err(cleanup_err) = detach_unmount(&target_path) {
                        warn!(
                            error = %cleanup_err,
                            target = %target_path.display(),
                            "failed to clean up writable bind mount after read-only remount failure"
                        );
                    }
                }
                return Err(err);
            }
        }

        mounted_paths.push(target_path);
    }

    Ok(mounted_paths)
}

fn mount_virtiofs(tag: &str, target: &Path) -> Result<()> {
    // Use sync option to ensure writes are persisted immediately.
    let src = CString::new(tag).map_err(|e| StorageError::Internal {
        message: format!("invalid tag: {}", e),
    })?;
    let dst = path_to_cstring(target, "mount point")?;
    let fstype = CString::new("virtiofs").unwrap();
    let opts = CString::new("sync").unwrap();

    // SAFETY: mount virtiofs with valid CString arguments.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            0,
            opts.as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        return Err(StorageError::VirtiofsMountFailed {
            tag: tag.to_string(),
            path: target.display().to_string(),
            cause: std::io::Error::last_os_error().to_string(),
        });
    }

    Ok(())
}

fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    let bind_src = path_to_cstring(source, "bind mount source")?;
    let bind_dst = path_to_cstring(target, "bind mount target")?;

    // SAFETY: bind mount with MS_BIND flag and valid paths.
    let rc = unsafe {
        libc::mount(
            bind_src.as_ptr(),
            bind_dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(StorageError::BindMountFailed {
            source: source.display().to_string(),
            target: target.display().to_string(),
            cause: std::io::Error::last_os_error().to_string(),
        });
    }

    Ok(())
}

fn remount_bind_readonly(target: &Path) -> Result<()> {
    let bind_dst = path_to_cstring(target, "read-only bind mount target")?;

    // SAFETY: remount with MS_BIND|MS_RDONLY|MS_REMOUNT and a valid target.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            bind_dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(StorageError::ReadonlyRemountFailed {
            path: target.display().to_string(),
            cause: std::io::Error::last_os_error().to_string(),
        });
    }

    Ok(())
}

fn detach_unmount(target: &Path) -> Result<()> {
    let target_c = path_to_cstring(target, "unmount target")?;

    // SAFETY: unmount with a valid target path.
    let rc = unsafe { libc::umount2(target_c.as_ptr(), libc::MNT_DETACH) };
    if rc != 0 {
        return Err(StorageError::UnmountFailed {
            path: target.display().to_string(),
            cause: std::io::Error::last_os_error().to_string(),
        });
    }

    Ok(())
}

fn path_to_cstring(path: &Path, context: &str) -> Result<CString> {
    CString::new(path.to_string_lossy().as_ref()).map_err(|e| StorageError::InvalidPath {
        path: format!("{} '{}': {}", context, path.display(), e),
    })
}

/// Check if a path is a mountpoint.
/// Check if a path is a mountpoint (delegates to paths::is_mount_point).
fn is_mountpoint(path: &Path) -> bool {
    paths::is_mount_point(path)
}

/// Run a command using crun OCI runtime (one-shot execution).
///
/// This uses `crun run` which creates, starts, waits, and deletes the container
/// in a single operation. Stdout and stderr are captured.
fn run_with_crun(
    bundle_dir: &Path,
    container_id: &str,
    timeout_ms: Option<u64>,
    client_fd: Option<std::os::unix::io::RawFd>,
) -> Result<RunResult> {
    info!(
        container_id = %container_id,
        bundle = %bundle_dir.display(),
        timeout_ms = ?timeout_ms,
        "running container with crun"
    );

    // Spawn the container using CrunCommand.
    // stdin_null() is critical: without it, crun inherits the agent's vsock
    // stdin, and /bin/sh reads protocol bytes instead of user input, hanging.
    let mut child = CrunCommand::run(bundle_dir, container_id)
        .stdin_null()
        .capture_output()
        .spawn()
        .map_err(|e| {
            StorageError::new(format!(
                "failed to spawn crun: {}. Is crun installed at {}?",
                e,
                paths::CRUN_PATH
            ))
        })?;

    // Capture container_id for the cleanup closure
    let cid = container_id.to_string();

    // Wait with timeout + client liveness, cleaning up container on timeout.
    // If the client disconnects mid-exec, we kill the container so the agent's
    // accept loop is free to serve the next request.
    let result = crate::process::wait_with_timeout_cleanup_and_liveness(
        &mut child,
        timeout_ms,
        client_fd,
        || {
            // Kill and delete the container on timeout
            let _ = CrunCommand::kill(&cid, "SIGKILL").status();
            let _ = CrunCommand::delete(&cid, true).status();
        },
    )?;

    // Convert WaitResult to RunResult
    match result {
        WaitResult::Completed { exit_code, output } => {
            info!(
                container_id = %container_id,
                exit_code = exit_code,
                stdout_len = output.stdout.len(),
                stderr_len = output.stderr.len(),
                "container finished"
            );
            Ok(RunResult {
                exit_code,
                stdout: output.stdout,
                stderr: output.stderr,
            })
        }
        WaitResult::TimedOut { output, timeout_ms } => {
            warn!(
                container_id = %container_id,
                timeout_ms = timeout_ms,
                "container timed out"
            );
            let mut stderr = output.stderr;
            stderr.extend_from_slice(
                format!("\ncontainer timed out after {}ms", timeout_ms).as_bytes(),
            );
            Ok(RunResult {
                exit_code: TIMEOUT_EXIT_CODE,
                stdout: output.stdout,
                stderr,
            })
        }
        WaitResult::ClientDisconnected { output } => {
            // Client gave up before the container finished. Also clean up the
            // crun container state so the next exec starts fresh.
            let _ = CrunCommand::kill(container_id, "SIGKILL").status();
            let _ = CrunCommand::delete(container_id, true).status();
            warn!(
                container_id = %container_id,
                "container killed — client disconnected"
            );
            let mut stderr = output.stderr;
            stderr.extend_from_slice(b"\ncontainer killed: client disconnected");
            Ok(RunResult {
                exit_code: 129, // SIGHUP convention for disconnect
                stdout: output.stdout,
                stderr,
            })
        }
    }
}

// ============================================================================
// Overlay mounting helper functions
// ============================================================================

/// Try to mount overlay with multiple lowerdirs (efficient but requires kernel support).
fn try_mount_overlay_multi_lower(
    lowerdirs: &[String],
    upper_path: &Path,
    work_path: &Path,
    merged_path: &Path,
) -> Result<()> {
    let lowerdir = lowerdirs.join(":");

    // Mount overlay with index=off for compatibility
    // index=off disables inode index which requires more filesystem features
    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={},index=off",
        lowerdir,
        upper_path.display(),
        work_path.display()
    );

    info!(
        layer_count = lowerdirs.len(),
        mount_opts_len = mount_opts.len(),
        merged_path = %merged_path.display(),
        "attempting multi-lowerdir overlay mount"
    );
    debug!(mount_opts = %mount_opts, "overlay mount options");

    let output = Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(merged_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!(
            "multi-lowerdir overlay mount failed: {}",
            stderr
        )));
    }

    Ok(())
}

/// Mount overlay by merging layers into a single directory (most compatible).
///
/// This approach physically copies all layers into a single merged directory,
/// then creates a simple overlay on top of it. This works on all kernels with
/// basic overlay support, but uses more disk space and is slower for initial setup.
///
/// This is the fallback when multi-lowerdir overlay mounts fail.
fn mount_overlay_sequential(
    lowerdirs: &[String],
    upper_path: &Path,
    work_path: &Path,
    merged_path: &Path,
    overlay_root: &Path,
) -> Result<()> {
    info!(
        layer_count = lowerdirs.len(),
        "building overlay by merging layers"
    );

    // If only one layer, mount directly
    if lowerdirs.len() == 1 {
        let mount_opts = format!(
            "lowerdir={},upperdir={},workdir={},index=off",
            lowerdirs[0],
            upper_path.display(),
            work_path.display()
        );

        let output = Command::new("mount")
            .args(["-t", "overlay", "overlay", "-o", &mount_opts])
            .arg(merged_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(StorageError::new(format!(
                "overlay mount failed: {}",
                stderr
            )));
        }
        return Ok(());
    }

    // Create a directory to hold the physically merged layers
    let merged_layers_dir = overlay_root.join("merged_layers");
    std::fs::create_dir_all(&merged_layers_dir)?;

    // lowerdirs is in overlay order (topmost first)
    // We need to copy from bottom up so top layers overwrite bottom layers
    let layers: Vec<&String> = lowerdirs.iter().rev().collect();

    info!(
        layer_count = layers.len(),
        merged_dir = %merged_layers_dir.display(),
        "physically merging layers"
    );

    for (i, layer_path) in layers.iter().enumerate() {
        debug!(
            layer_index = i,
            layer_path = %layer_path,
            "copying layer to merged directory"
        );

        // Copy layer contents preserving all attributes.
        // cp -a preserves symlinks, permissions, etc.
        // Uses explicit args instead of shell to avoid injection risks.
        let layer_src = format!("{}/.", layer_path);
        let output = Command::new("cp")
            .arg("-a")
            .arg(&layer_src)
            .arg(merged_layers_dir.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        // Don't fail on cp errors - some layers might have special files
        // that can't be copied, but the overlay should still work
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                debug!(
                    layer_index = i,
                    stderr = %stderr,
                    "layer copy had warnings (non-fatal)"
                );
            }
        }
    }

    info!(
        merged_dir = %merged_layers_dir.display(),
        "layer merge complete, mounting overlay"
    );

    // Now mount a simple overlay with just the merged directory as lowerdir
    let mount_opts = format!(
        "lowerdir={},upperdir={},workdir={},index=off",
        merged_layers_dir.display(),
        upper_path.display(),
        work_path.display()
    );

    let output = Command::new("mount")
        .args(["-t", "overlay", "overlay", "-o", &mount_opts])
        .arg(merged_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!(
            "overlay mount on merged layers failed: {}",
            stderr
        )));
    }

    info!(
        layer_count = lowerdirs.len(),
        "overlay construction complete (merged layers approach)"
    );

    Ok(())
}

// ============================================================================
// Helper functions
// ============================================================================

/// Extract the registry hostname from an image reference.
/// e.g., "alpine:latest" -> "https://index.docker.io/v1/"
/// e.g., "ghcr.io/owner/repo" -> "ghcr.io"
fn extract_registry_from_image(image: &str) -> String {
    if let Some(slash_pos) = image.find('/') {
        let potential_registry = &image[..slash_pos];
        if potential_registry.contains('.') || potential_registry.contains(':') {
            return docker_config_registry_key(potential_registry).to_string();
        }
    }
    // Docker Hub uses this URL in config.json
    DOCKER_HUB_AUTH_CONFIG_KEY.to_string()
}

fn docker_config_registry_key(registry: &str) -> &str {
    if DOCKER_HUB_REGISTRY_ALIASES.contains(&registry) {
        DOCKER_HUB_AUTH_CONFIG_KEY
    } else {
        registry
    }
}

fn blob_image_reference(image: &str) -> &str {
    image.split_once('@').map_or(image, |(name, _)| name)
}

/// Simple base64 encoding for auth string.
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}

/// Set up Docker auth configuration for crane commands.
///
/// Creates a temporary directory with a Docker config.json file containing
/// registry credentials. The returned TempDir must be kept alive for the
/// duration of the command execution.
///
/// Returns `Ok(None)` if no auth is provided.
fn setup_docker_auth(
    image: &str,
    auth: Option<&RegistryAuth>,
) -> Result<Option<tempfile::TempDir>> {
    let Some(a) = auth else {
        return Ok(None);
    };

    let registry = extract_registry_from_image(image);

    let temp_dir = tempfile::TempDir::new().map_err(|e| {
        StorageError::new(format!("failed to create temp directory for auth: {}", e))
    })?;

    let auth_b64 = base64_encode(&format!("{}:{}", a.username, a.password));
    let config_json = format!(
        r#"{{"auths":{{"{}":{{"auth":"{}"}}}}}}"#,
        registry, auth_b64
    );

    let config_path = temp_dir.path().join("config.json");
    std::fs::write(&config_path, &config_json)
        .map_err(|e| StorageError::new(format!("failed to write docker auth config: {}", e)))?;

    debug!(
        registry = %registry,
        username = %a.username,
        "using registry credentials via docker config"
    );

    Ok(Some(temp_dir))
}

/// Run a crane command with the given operation.
///
/// If auth is provided, creates a temporary Docker config for crane to use.
/// Includes retry logic for transient network failures.
fn run_crane(
    operation: &str,
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
) -> Result<String> {
    use crate::retry::{
        is_permanent_error, is_transient_network_error, retry_with_backoff, RetryConfig,
    };

    let op_name = format!("crane {}", operation);

    retry_with_backoff(
        RetryConfig::for_network(),
        &op_name,
        || run_crane_once(operation, image, oci_platform, auth),
        |e| {
            let error_msg = e.to_string();
            // Don't retry permanent errors
            if is_permanent_error(&error_msg) {
                return false;
            }
            // Retry transient network errors
            is_transient_network_error(&error_msg)
        },
    )
}

/// Execute a single crane command attempt.
fn run_crane_once(
    operation: &str,
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
) -> Result<String> {
    let mut cmd = Command::new("crane");
    cmd.arg(operation).arg(image);

    if let Some(p) = oci_platform {
        cmd.arg("--platform").arg(p);
    }

    // Set up auth if provided (temp_dir must stay alive until command completes)
    let _temp_dir = setup_docker_auth(image, auth)?;
    if let Some(ref td) = _temp_dir {
        cmd.env("DOCKER_CONFIG", td.path());
    }

    let output = cmd.output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(StorageError::new(format!(
            "crane {} failed: {}",
            operation, stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Run crane manifest command.
fn crane_manifest(
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
) -> Result<String> {
    run_crane("manifest", image, oci_platform, auth)
}

/// Run crane config command.
fn crane_config(
    image: &str,
    oci_platform: Option<&str>,
    auth: Option<&RegistryAuth>,
) -> Result<String> {
    run_crane("config", image, oci_platform, auth)
}

/// Sanitize image name for use as filename.
fn sanitize_image_name(image: &str) -> String {
    image.replace(['/', ':', '@'], "_")
}

/// Reverse sanitization.
fn unsanitize_image_name(name: &str) -> String {
    // This is approximate - we lose some info
    name.replacen('_', "/", 1).replacen('_', ":", 1)
}

/// Get disk usage for a path.
#[allow(unused_variables)] // path is used only on Linux
fn get_disk_usage(path: &Path) -> Result<(u64, u64)> {
    // Use statvfs on Linux
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::mem::MaybeUninit;

        let path_cstr = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| {
            StorageError::InvalidPath {
                path: "overlay path".into(),
            }
        })?;

        unsafe {
            let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
            if libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let stat = stat.assume_init();
            let total = stat.f_blocks * stat.f_frsize;
            let free = stat.f_bfree * stat.f_frsize;
            let used = total - free;

            Ok((total, used))
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok((0, 0))
    }
}

/// Count entries in a directory.
fn count_entries(path: &Path) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }

    Ok(std::fs::read_dir(path)?.count())
}

/// Convert an OCI platform string to its architecture component.
///
/// # Examples
/// - "linux/arm64" -> "arm64"
/// - "linux/amd64" -> "amd64"
/// - "linux/arm64/v8" -> "arm64"
fn oci_platform_to_arch(oci_platform: &str) -> String {
    // OCI platform format is "os/arch" or "os/arch/variant"
    // We want just the arch part
    let parts: Vec<&str> = oci_platform.split('/').collect();
    if parts.len() >= 2 {
        parts[1].to_string()
    } else {
        // Fallback: return as-is if not in expected format
        oci_platform.to_string()
    }
}

/// Calculate directory size recursively.
fn dir_size(path: &Path) -> Result<u64> {
    let mut size = 0;

    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }

    for entry in std::fs::read_dir(path)? {
        let entry: std::fs::DirEntry = entry?;
        let path = entry.path();

        if path.is_file() {
            size += std::fs::metadata(&path)?.len();
        } else if path.is_dir() {
            size += dir_size(&path)?;
        }
    }

    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_mount_env() {
        std::env::remove_var("SMOLVM_MOUNT_COUNT");
        for i in 0..4 {
            std::env::remove_var(format!("SMOLVM_MOUNT_{}", i));
        }
    }

    #[test]
    fn test_oci_platform_to_arch_linux_arm64() {
        assert_eq!(oci_platform_to_arch("linux/arm64"), "arm64");
    }

    #[test]
    fn test_oci_platform_to_arch_linux_amd64() {
        assert_eq!(oci_platform_to_arch("linux/amd64"), "amd64");
    }

    #[test]
    fn test_oci_platform_to_arch_with_variant() {
        assert_eq!(oci_platform_to_arch("linux/arm64/v8"), "arm64");
        assert_eq!(oci_platform_to_arch("linux/arm/v7"), "arm");
    }

    #[test]
    fn test_oci_platform_to_arch_fallback() {
        // If not in expected format, return as-is
        assert_eq!(oci_platform_to_arch("arm64"), "arm64");
        assert_eq!(oci_platform_to_arch("unknown"), "unknown");
    }

    #[test]
    fn test_sanitize_image_name() {
        assert_eq!(sanitize_image_name("alpine:latest"), "alpine_latest");
        assert_eq!(
            sanitize_image_name("docker.io/library/alpine:3.18"),
            "docker.io_library_alpine_3.18"
        );
        assert_eq!(
            sanitize_image_name("ghcr.io/owner/repo@sha256:abc123"),
            "ghcr.io_owner_repo_sha256_abc123"
        );
    }

    #[test]
    fn test_blob_image_reference_strips_manifest_digest() {
        assert_eq!(blob_image_reference("alpine@sha256:abc123"), "alpine");
        assert_eq!(
            blob_image_reference("alpine:3.19@sha256:abc123"),
            "alpine:3.19"
        );
        assert_eq!(blob_image_reference("alpine:3.19"), "alpine:3.19");
    }

    #[test]
    fn test_extract_registry_from_image_normalizes_docker_hub() {
        assert_eq!(
            extract_registry_from_image("alpine:latest"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
        assert_eq!(
            extract_registry_from_image("library/alpine:latest"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
        assert_eq!(
            extract_registry_from_image("docker.io/nginxinc/nginx-unprivileged:stable-alpine"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
        assert_eq!(
            extract_registry_from_image("index.docker.io/library/alpine:latest"),
            DOCKER_HUB_AUTH_CONFIG_KEY
        );
    }

    #[test]
    fn test_extract_registry_from_image_preserves_non_docker_hub_registry() {
        assert_eq!(
            extract_registry_from_image("ghcr.io/owner/repo:tag"),
            "ghcr.io"
        );
        assert_eq!(
            extract_registry_from_image("registry.example.com:5000/image:tag"),
            "registry.example.com:5000"
        );
    }

    #[test]
    fn overlay_resolv_conf_uses_virtio_dns_server() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var(guest_env::BACKEND, guest_env::BACKEND_VIRTIO_NET);
        std::env::set_var(guest_env::DNS, "100.96.0.1");

        assert_eq!(overlay_resolv_conf_contents(), "nameserver 100.96.0.1\n");

        std::env::remove_var(guest_env::BACKEND);
        std::env::remove_var(guest_env::DNS);
    }

    #[test]
    fn overlay_resolv_conf_defaults_to_public_resolvers() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var(guest_env::BACKEND);
        std::env::remove_var(guest_env::DNS);

        assert_eq!(
            overlay_resolv_conf_contents(),
            "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"
        );
    }

    #[test]
    fn boot_volume_mount_env_absent_is_empty() {
        let _guard = env_lock().lock().unwrap();
        clear_mount_env();

        assert!(parse_boot_volume_mounts_from_env().unwrap().is_empty());
    }

    #[test]
    fn boot_volume_mount_env_parses_rw_and_ro() {
        let _guard = env_lock().lock().unwrap();
        clear_mount_env();
        std::env::set_var("SMOLVM_MOUNT_COUNT", "2");
        std::env::set_var("SMOLVM_MOUNT_0", "smolvm0:/workspace:rw");
        std::env::set_var("SMOLVM_MOUNT_1", "smolvm1:/config:ro");

        let mounts = parse_boot_volume_mounts_from_env().unwrap();

        assert_eq!(
            mounts,
            vec![
                ("smolvm0".to_string(), "/workspace".to_string(), false),
                ("smolvm1".to_string(), "/config".to_string(), true),
            ]
        );
        clear_mount_env();
    }

    #[test]
    fn boot_volume_mount_env_rejects_invalid_mode() {
        let _guard = env_lock().lock().unwrap();
        clear_mount_env();
        std::env::set_var("SMOLVM_MOUNT_COUNT", "1");
        std::env::set_var("SMOLVM_MOUNT_0", "smolvm0:/workspace:maybe");

        let err = parse_boot_volume_mounts_from_env().unwrap_err();

        assert!(err.to_string().contains("invalid mount mode"));
        clear_mount_env();
    }

    #[test]
    fn test_validate_storage_id_rejects_traversal() {
        assert!(validate_storage_id("../escape", "workload_id").is_err());
        assert!(validate_storage_id("foo/bar", "workload_id").is_err());
    }

    #[test]
    fn test_shared_workspace_permissions_are_world_writable_sticky() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o755)).unwrap();

        ensure_shared_workspace_permissions(&workspace).unwrap();

        let mode = std::fs::metadata(&workspace).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o1777);
    }

    #[test]
    fn test_validate_container_destination_path_requires_absolute() {
        assert!(validate_container_destination_path("var/data").is_err());
        assert!(validate_container_destination_path("/").is_err());
        assert!(validate_container_destination_path("/var/data").is_ok());
    }

    #[test]
    fn test_ensure_mount_target_under_root_rejects_parent_traversal() {
        let root = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        assert!(ensure_mount_target_under_root(&rootfs, "/../../escape").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_ensure_mount_target_under_root_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let rootfs = root.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        symlink(outside.path(), rootfs.join("link-out")).unwrap();
        assert!(ensure_mount_target_under_root(&rootfs, "/link-out/dir").is_err());
    }
}
