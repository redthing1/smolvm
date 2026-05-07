//! OCI archive import for `.smolmachine` packaging and local image imports.
//!
//! This module reads a standard OCI image archive, resolves the requested
//! platform, and applies image layers into a temporary root filesystem. Callers
//! can either write that root filesystem as a single merged layer tarball for a
//! portable `.smolmachine`, or keep it as a directory for local execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{PackError, Result};

const OCI_IMAGE_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_LAYER_TAR: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_TAR_GZIP: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
#[cfg(feature = "zstd")]
const OCI_LAYER_TAR_ZSTD: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const OCI_NONDIST_LAYER_TAR: &str = "application/vnd.oci.image.layer.nondistributable.v1.tar";
const OCI_NONDIST_LAYER_TAR_GZIP: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip";
#[cfg(feature = "zstd")]
const OCI_NONDIST_LAYER_TAR_ZSTD: &str =
    "application/vnd.oci.image.layer.nondistributable.v1.tar+zstd";
const DOCKER_LAYER_TAR_GZIP: &str = "application/vnd.docker.image.rootfs.diff.tar.gzip";

/// Image metadata and merged layer produced from an OCI archive.
#[derive(Debug, Clone)]
pub struct OciArchiveImage {
    /// Human-readable image reference from archive annotations.
    pub reference: String,
    /// Config digest (`sha256:...`) for the selected image manifest.
    pub digest: String,
    /// Target platform architecture, for example `amd64`.
    pub architecture: String,
    /// Target platform operating system, usually `linux`.
    pub os: String,
    /// Approximate extracted root filesystem size in bytes.
    pub size: u64,
    /// Image entrypoint from OCI config.
    pub entrypoint: Vec<String>,
    /// Image command from OCI config.
    pub cmd: Vec<String>,
    /// Image environment from OCI config.
    pub env: Vec<String>,
    /// Image working directory from OCI config.
    pub workdir: Option<String>,
    /// Image user from OCI config.
    pub user: Option<String>,
    /// Digest for the merged layer tarball.
    pub layer_digest: String,
    /// Path to the merged layer tarball.
    pub layer_path: PathBuf,
}

/// Image metadata and merged root filesystem produced from an OCI archive.
#[derive(Debug, Clone)]
pub struct OciArchiveRootfs {
    /// Human-readable image reference from archive annotations.
    pub reference: String,
    /// Config digest (`sha256:...`) for the selected image manifest.
    pub digest: String,
    /// Target platform architecture, for example `amd64`.
    pub architecture: String,
    /// Target platform operating system, usually `linux`.
    pub os: String,
    /// Approximate extracted root filesystem size in bytes.
    pub size: u64,
    /// Image entrypoint from OCI config.
    pub entrypoint: Vec<String>,
    /// Image command from OCI config.
    pub cmd: Vec<String>,
    /// Image environment from OCI config.
    pub env: Vec<String>,
    /// Image working directory from OCI config.
    pub workdir: Option<String>,
    /// Image user from OCI config.
    pub user: Option<String>,
    /// Stable digest for the merged layer directory.
    pub layer_digest: String,
    /// Path to the merged root filesystem directory.
    pub rootfs_path: PathBuf,
}

/// Image metadata read from an OCI archive without unpacking its rootfs.
#[derive(Debug, Clone)]
pub struct OciArchiveInspection {
    /// Human-readable image reference from archive annotations.
    pub reference: String,
    /// Config digest (`sha256:...`) for the selected image manifest.
    pub digest: String,
    /// Target platform architecture, for example `amd64`.
    pub architecture: String,
    /// Target platform operating system, usually `linux`.
    pub os: String,
    /// Total size of the selected layer blobs in bytes.
    pub size: u64,
    /// Image entrypoint from OCI config.
    pub entrypoint: Vec<String>,
    /// Image command from OCI config.
    pub cmd: Vec<String>,
    /// Image environment from OCI config.
    pub env: Vec<String>,
    /// Image working directory from OCI config.
    pub workdir: Option<String>,
    /// Image user from OCI config.
    pub user: Option<String>,
    /// Stable digest for the selected image contents.
    pub image_key: String,
    /// Selected layer descriptors in manifest order.
    pub layers: Vec<OciArchiveLayer>,
}

/// A selected layer descriptor from an OCI archive.
#[derive(Debug, Clone)]
pub struct OciArchiveLayer {
    /// Layer media type.
    pub media_type: String,
    /// Layer digest (`sha256:...`).
    pub digest: String,
    /// Layer blob size in bytes.
    pub size: u64,
}

/// Inspect an OCI archive without unpacking image layers.
pub fn inspect_oci_archive(
    archive_path: &Path,
    work_dir: &Path,
    platform: Option<&str>,
) -> Result<OciArchiveInspection> {
    let archive_dir = work_dir.join("oci-archive");
    fs::create_dir_all(&archive_dir)?;
    unpack_outer_archive(archive_path, &archive_dir)?;

    let selected = read_selected_image(&archive_dir, platform)?;

    let mut layers = Vec::with_capacity(selected.manifest.layers.len());
    let mut layer_digests = Vec::with_capacity(selected.manifest.layers.len());
    let mut total_size = 0_u64;
    for layer in &selected.manifest.layers {
        blob_path(&archive_dir, &layer.digest)?;
        total_size = total_size.saturating_add(layer.size);
        layer_digests.push(layer.digest.clone());
        layers.push(OciArchiveLayer {
            media_type: layer.media_type.clone(),
            digest: layer.digest.clone(),
            size: layer.size,
        });
    }

    let image_key = merged_layer_digest(
        &selected.digest,
        &layer_digests,
        &selected.os,
        &selected.architecture,
    );
    let runtime = selected.runtime;
    Ok(OciArchiveInspection {
        reference: selected.reference,
        digest: selected.digest,
        architecture: selected.architecture,
        os: selected.os,
        size: total_size,
        entrypoint: runtime.entrypoint,
        cmd: runtime.cmd,
        env: runtime.env,
        workdir: runtime.workdir,
        user: runtime.user,
        image_key,
        layers,
    })
}

/// Import an OCI archive and write a merged layer tarball under `work_dir`.
pub fn import_oci_archive(
    archive_path: &Path,
    work_dir: &Path,
    platform: Option<&str>,
) -> Result<OciArchiveImage> {
    let imported = apply_oci_archive(archive_path, work_dir, platform)?;

    let merged_layer_path = work_dir.join("merged-layer.tar");
    write_rootfs_tar(&imported.rootfs_dir, &merged_layer_path)?;
    let layer_digest = digest_file(&merged_layer_path)?;

    Ok(OciArchiveImage {
        reference: imported.reference,
        digest: imported.digest,
        architecture: imported.architecture,
        os: imported.os,
        size: imported.size,
        entrypoint: imported.entrypoint,
        cmd: imported.cmd,
        env: imported.env,
        workdir: imported.workdir,
        user: imported.user,
        layer_digest,
        layer_path: merged_layer_path,
    })
}

/// Import an OCI archive and move the merged root filesystem to `rootfs_path`.
pub fn import_oci_archive_rootfs(
    archive_path: &Path,
    rootfs_path: &Path,
    work_dir: &Path,
    platform: Option<&str>,
) -> Result<OciArchiveRootfs> {
    let imported = apply_oci_archive(archive_path, work_dir, platform)?;
    let layer_digest = merged_layer_digest(
        &imported.digest,
        &imported.source_layer_digests,
        &imported.os,
        &imported.architecture,
    );

    if rootfs_path.exists() {
        remove_path(rootfs_path, &mut DirectoryPermissions::default())?;
    }
    if let Some(parent) = rootfs_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::rename(&imported.rootfs_dir, rootfs_path)?;

    Ok(OciArchiveRootfs {
        reference: imported.reference,
        digest: imported.digest,
        architecture: imported.architecture,
        os: imported.os,
        size: imported.size,
        entrypoint: imported.entrypoint,
        cmd: imported.cmd,
        env: imported.env,
        workdir: imported.workdir,
        user: imported.user,
        layer_digest,
        rootfs_path: rootfs_path.to_path_buf(),
    })
}

struct AppliedOciArchive {
    reference: String,
    digest: String,
    architecture: String,
    os: String,
    size: u64,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<String>,
    workdir: Option<String>,
    user: Option<String>,
    source_layer_digests: Vec<String>,
    rootfs_dir: PathBuf,
}

fn apply_oci_archive(
    archive_path: &Path,
    work_dir: &Path,
    platform: Option<&str>,
) -> Result<AppliedOciArchive> {
    let archive_dir = work_dir.join("oci-archive");
    let rootfs_dir = work_dir.join("rootfs");
    fs::create_dir_all(&archive_dir)?;
    fs::create_dir_all(&rootfs_dir)?;

    unpack_outer_archive(archive_path, &archive_dir)?;

    let selected = read_selected_image(&archive_dir, platform)?;

    let mut directory_permissions = DirectoryPermissions::default();
    let apply_result = (|| {
        for layer in &selected.manifest.layers {
            let layer_path = blob_path(&archive_dir, &layer.digest)?;
            apply_layer(
                &layer_path,
                &layer.media_type,
                &rootfs_dir,
                &mut directory_permissions,
            )?;
        }
        dir_size(&rootfs_dir)
    })();
    let restore_result = directory_permissions.restore();
    let image_size = apply_result?;
    restore_result?;

    let runtime = selected.runtime;
    Ok(AppliedOciArchive {
        reference: selected.reference,
        digest: selected.digest,
        architecture: selected.architecture,
        os: selected.os,
        size: image_size,
        entrypoint: runtime.entrypoint,
        cmd: runtime.cmd,
        env: runtime.env,
        workdir: runtime.workdir,
        user: runtime.user,
        source_layer_digests: selected
            .manifest
            .layers
            .into_iter()
            .map(|layer| layer.digest)
            .collect(),
        rootfs_dir,
    })
}

fn merged_layer_digest(
    config_digest: &str,
    source_layer_digests: &[String],
    os: &str,
    architecture: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"smolvm-merged-rootfs-v1\0");
    hasher.update(config_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(os.as_bytes());
    hasher.update(b"\0");
    hasher.update(architecture.as_bytes());
    for digest in source_layer_digests {
        hasher.update(b"\0");
        hasher.update(digest.as_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn unpack_outer_archive(archive_path: &Path, dest: &Path) -> Result<()> {
    let file = File::open(archive_path)?;
    let mut archive = tar::Archive::new(file);
    for entry in archive
        .entries()
        .map_err(|e| PackError::Tar(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| PackError::Tar(e.to_string()))?;
        let path = safe_relative_path(&entry.path().map_err(|e| PackError::Tar(e.to_string()))?)?;
        if path.as_os_str().is_empty() {
            continue;
        }
        let entry_type = entry.header().entry_type();
        if !matches!(
            entry_type,
            tar::EntryType::Regular | tar::EntryType::GNUSparse | tar::EntryType::Directory
        ) {
            return Err(PackError::InvalidOciArchive(format!(
                "unsupported outer archive entry type for {}",
                path.display()
            )));
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(dest.join(parent))?;
        }
        let target = dest.join(&path);
        entry
            .unpack(&target)
            .map_err(|e| PackError::Tar(format!("unpack {}: {}", path.display(), e)))?;
    }
    Ok(())
}

struct SelectedOciImage {
    reference: String,
    digest: String,
    architecture: String,
    os: String,
    runtime: ImageRuntimeConfig,
    manifest: OciManifest,
}

#[derive(Default)]
struct ImageRuntimeConfig {
    entrypoint: Vec<String>,
    cmd: Vec<String>,
    env: Vec<String>,
    workdir: Option<String>,
    user: Option<String>,
}

fn read_selected_image(archive_dir: &Path, platform: Option<&str>) -> Result<SelectedOciImage> {
    let index: OciIndex = read_json(&archive_dir.join("index.json"))?;
    let selected = select_manifest(archive_dir, &index.manifests, platform)?;
    if selected
        .media_type
        .as_deref()
        .is_some_and(|mt| mt != OCI_IMAGE_MANIFEST)
    {
        return Err(PackError::InvalidOciArchive(format!(
            "unsupported manifest media type: {}",
            selected.media_type.as_deref().unwrap_or_default()
        )));
    }

    let reference = selected
        .annotations
        .as_ref()
        .and_then(|a| a.reference_name.clone())
        .unwrap_or_else(|| "local/archive:latest".to_string());
    let manifest: OciManifest = read_json(&blob_path(archive_dir, &selected.digest)?)?;
    let config_path = blob_path(archive_dir, &manifest.config.digest)?;
    let config: OciConfig = read_json(&config_path)?;
    let OciConfig {
        architecture,
        os,
        config,
    } = config;

    Ok(SelectedOciImage {
        reference,
        digest: manifest.config.digest.clone(),
        architecture,
        os,
        runtime: image_runtime_config(config),
        manifest,
    })
}

fn image_runtime_config(config: Option<OciConfigValues>) -> ImageRuntimeConfig {
    let config = config.unwrap_or_default();
    ImageRuntimeConfig {
        entrypoint: config.entrypoint.unwrap_or_default(),
        cmd: config.cmd.unwrap_or_default(),
        env: config.env.unwrap_or_default(),
        workdir: config.working_dir.filter(|s| !s.is_empty()),
        user: config.user.filter(|s| !s.is_empty()),
    }
}

fn select_manifest<'a>(
    archive_dir: &Path,
    manifests: &'a [OciDescriptor],
    platform: Option<&str>,
) -> Result<&'a OciDescriptor> {
    if manifests.is_empty() {
        return Err(PackError::InvalidOciArchive(
            "index.json has no manifests".to_string(),
        ));
    }

    let Some(platform) = platform else {
        return Ok(&manifests[0]);
    };
    let (wanted_os, wanted_arch) = platform.split_once('/').ok_or_else(|| {
        PackError::InvalidOciArchive(format!("invalid platform [{platform}], expected OS/ARCH"))
    })?;

    if let Some(manifest) = manifests.iter().find(|manifest| {
        manifest
            .platform
            .as_ref()
            .is_some_and(|p| p.os == wanted_os && p.architecture == wanted_arch)
    }) {
        return Ok(manifest);
    }

    for manifest in manifests {
        if manifest
            .media_type
            .as_deref()
            .is_some_and(|mt| mt != OCI_IMAGE_MANIFEST)
        {
            continue;
        }
        let Ok(manifest_path) = blob_path(archive_dir, &manifest.digest) else {
            continue;
        };
        let Ok(image_manifest) = read_json::<OciManifest>(&manifest_path) else {
            continue;
        };
        let Ok(config_path) = blob_path(archive_dir, &image_manifest.config.digest) else {
            continue;
        };
        let Ok(config) = read_json::<OciConfig>(&config_path) else {
            continue;
        };
        if config.os == wanted_os && config.architecture == wanted_arch {
            return Ok(manifest);
        }
    }

    Err(PackError::InvalidOciArchive(format!(
        "archive has no manifest for platform [{platform}]"
    )))
}

fn apply_layer(
    layer_path: &Path,
    media_type: &str,
    rootfs_dir: &Path,
    directory_permissions: &mut DirectoryPermissions,
) -> Result<()> {
    match media_type {
        OCI_LAYER_TAR | OCI_NONDIST_LAYER_TAR => {
            let file = File::open(layer_path)?;
            apply_layer_tar(file, rootfs_dir, directory_permissions)
        }
        OCI_LAYER_TAR_GZIP | OCI_NONDIST_LAYER_TAR_GZIP | DOCKER_LAYER_TAR_GZIP => {
            let file = File::open(layer_path)?;
            apply_layer_tar(GzDecoder::new(file), rootfs_dir, directory_permissions)
        }
        #[cfg(feature = "zstd")]
        OCI_LAYER_TAR_ZSTD | OCI_NONDIST_LAYER_TAR_ZSTD => {
            let file = File::open(layer_path)?;
            let decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|e| PackError::Compression(e.to_string()))?;
            apply_layer_tar(decoder, rootfs_dir, directory_permissions)
        }
        other => Err(PackError::UnsupportedLayer(other.to_string())),
    }
}

fn apply_layer_tar<R: Read>(
    reader: R,
    rootfs_dir: &Path,
    directory_permissions: &mut DirectoryPermissions,
) -> Result<()> {
    let mut archive = tar::Archive::new(reader);
    preserve_root_metadata_when_possible(&mut archive);
    let mut pending_hard_links = Vec::new();
    let mut created_paths = BTreeSet::new();
    for entry in archive
        .entries()
        .map_err(|e| PackError::Tar(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| PackError::Tar(e.to_string()))?;
        let path = safe_relative_path(&entry.path().map_err(|e| PackError::Tar(e.to_string()))?)?;
        if path.as_os_str().is_empty() {
            continue;
        }

        if apply_whiteout(rootfs_dir, &path, directory_permissions, &created_paths)? {
            resolve_pending_hard_links(
                rootfs_dir,
                &mut pending_hard_links,
                directory_permissions,
                false,
                &mut created_paths,
            )?;
            continue;
        }

        if entry.header().entry_type().is_hard_link() {
            let hard_link = pending_hard_link(&entry, path)?;
            if !try_apply_hard_link(rootfs_dir, &hard_link, directory_permissions)? {
                pending_hard_links.push(hard_link);
            } else {
                created_paths.insert(hard_link.target);
            }
            continue;
        }

        if let Some(parent) = path.parent() {
            ensure_directory(rootfs_dir, parent, directory_permissions)?;
        }
        let target = rootfs_dir.join(&path);
        validate_parent_inside(rootfs_dir, &target)?;
        remove_replaced_path(&target, entry.header().entry_type(), directory_permissions)?;
        entry
            .unpack(&target)
            .map_err(|e| PackError::Tar(format!("unpack {}: {}", path.display(), e)))?;
        if entry.header().entry_type().is_dir() {
            directory_permissions.make_writable(&target)?;
        }
        created_paths.insert(path);
        resolve_pending_hard_links(
            rootfs_dir,
            &mut pending_hard_links,
            directory_permissions,
            false,
            &mut created_paths,
        )?;
    }
    resolve_pending_hard_links(
        rootfs_dir,
        &mut pending_hard_links,
        directory_permissions,
        true,
        &mut created_paths,
    )?;
    Ok(())
}

fn preserve_root_metadata_when_possible<R: Read>(archive: &mut tar::Archive<R>) {
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            archive.set_preserve_permissions(true);
            archive.set_preserve_ownerships(true);
            archive.set_unpack_xattrs(true);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = archive;
    }
}

#[derive(Debug)]
struct PendingHardLink {
    source: PathBuf,
    target: PathBuf,
}

fn pending_hard_link(
    entry: &tar::Entry<'_, impl Read>,
    target: PathBuf,
) -> Result<PendingHardLink> {
    let source = entry
        .link_name()
        .map_err(|e| PackError::Tar(e.to_string()))?
        .ok_or_else(|| PackError::Tar(format!("hard link {} has no target", target.display())))?;
    Ok(PendingHardLink {
        source: safe_relative_path(&source)?,
        target,
    })
}

fn resolve_pending_hard_links(
    rootfs_dir: &Path,
    pending: &mut Vec<PendingHardLink>,
    directory_permissions: &mut DirectoryPermissions,
    final_pass: bool,
    created_paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let mut remaining = Vec::new();
    for hard_link in pending.drain(..) {
        if !try_apply_hard_link(rootfs_dir, &hard_link, directory_permissions)? {
            remaining.push(hard_link);
        } else {
            created_paths.insert(hard_link.target);
        }
    }

    if final_pass && !remaining.is_empty() {
        let hard_link = &remaining[0];
        return Err(PackError::Tar(format!(
            "hard link source missing: {} -> {}",
            hard_link.target.display(),
            hard_link.source.display()
        )));
    }

    *pending = remaining;
    Ok(())
}

fn try_apply_hard_link(
    rootfs_dir: &Path,
    hard_link: &PendingHardLink,
    directory_permissions: &mut DirectoryPermissions,
) -> Result<bool> {
    let source = rootfs_dir.join(&hard_link.source);
    match fs::symlink_metadata(&source) {
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err.into()),
    }
    validate_inside(rootfs_dir, &source)?;

    if let Some(parent) = hard_link.target.parent() {
        ensure_directory(rootfs_dir, parent, directory_permissions)?;
    }
    let target = rootfs_dir.join(&hard_link.target);
    validate_parent_inside(rootfs_dir, &target)?;
    remove_replaced_path(&target, tar::EntryType::Link, directory_permissions)?;
    fs::hard_link(&source, &target).map_err(|err| {
        PackError::Tar(format!(
            "{} when hard linking {} to {}",
            err,
            hard_link.source.display(),
            hard_link.target.display()
        ))
    })?;
    Ok(true)
}

fn ensure_directory(
    rootfs_dir: &Path,
    relative_path: &Path,
    directory_permissions: &mut DirectoryPermissions,
) -> Result<()> {
    directory_permissions.make_writable(rootfs_dir)?;
    let mut current = rootfs_dir.to_path_buf();
    for component in relative_path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => {
                current.push(part);
                match fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                        directory_permissions.make_writable(&current)?;
                    }
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        validate_inside(rootfs_dir, &current)?;
                    }
                    Ok(_) => {
                        return Err(PackError::Tar(format!(
                            "path component is not a directory: {}",
                            current.display()
                        )));
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        if let Some(parent) = current.parent() {
                            validate_inside(rootfs_dir, parent)?;
                        }
                        fs::create_dir(&current)?;
                        directory_permissions.make_writable(&current)?;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(PackError::InvalidOciArchive(format!(
                    "unsafe archive path: {}",
                    relative_path.display()
                )));
            }
        }
    }
    Ok(())
}

fn remove_replaced_path(
    path: &Path,
    entry_type: tar::EntryType,
    directory_permissions: &mut DirectoryPermissions,
) -> Result<()> {
    let Ok(existing) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if entry_type.is_dir() && existing.is_dir() && !existing.file_type().is_symlink() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        directory_permissions.make_writable(parent)?;
    }
    remove_path(path, directory_permissions)
}

fn validate_parent_inside(rootfs_dir: &Path, path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or(rootfs_dir);
    validate_inside(rootfs_dir, parent)
}

fn validate_inside(rootfs_dir: &Path, path: &Path) -> Result<()> {
    let root = rootfs_dir.canonicalize()?;
    let path = path.canonicalize()?;
    if !path.starts_with(&root) {
        return Err(PackError::InvalidOciArchive(format!(
            "archive path escapes rootfs: {}",
            path.display()
        )));
    }
    Ok(())
}

fn apply_whiteout(
    rootfs_dir: &Path,
    path: &Path,
    directory_permissions: &mut DirectoryPermissions,
    created_paths: &BTreeSet<PathBuf>,
) -> Result<bool> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return Ok(false);
    };
    let parent = path.parent().unwrap_or_else(|| Path::new(""));

    if name == ".wh..wh..opq" {
        let dir = rootfs_dir.join(parent);
        validate_parent_inside(rootfs_dir, &dir)?;
        clear_directory_preserving(&dir, parent, directory_permissions, created_paths)?;
        return Ok(true);
    }

    if let Some(removed) = name.strip_prefix(".wh.") {
        let removed_path = parent.join(removed);
        let target = rootfs_dir.join(parent).join(removed);
        if created_paths.contains(&removed_path) {
            return Ok(true);
        }
        if has_created_descendant(created_paths, &removed_path) {
            if target.is_dir() {
                clear_directory_preserving(
                    &target,
                    &removed_path,
                    directory_permissions,
                    created_paths,
                )?;
            }
            return Ok(true);
        }
        if let Some(parent) = target.parent() {
            if !parent.exists() {
                return Ok(true);
            }
            validate_inside(rootfs_dir, parent)?;
            directory_permissions.make_writable(parent)?;
        }
        remove_path(&target, directory_permissions)?;
        return Ok(true);
    }

    Ok(false)
}

fn clear_directory_preserving(
    dir: &Path,
    relative_dir: &Path,
    directory_permissions: &mut DirectoryPermissions,
    created_paths: &BTreeSet<PathBuf>,
) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        directory_permissions.make_writable(dir)?;
        return Ok(());
    }
    if fs::symlink_metadata(dir)?.file_type().is_symlink() {
        if let Some(parent) = dir.parent() {
            directory_permissions.make_writable(parent)?;
        }
        fs::remove_file(dir)?;
        fs::create_dir_all(dir)?;
        directory_permissions.make_writable(dir)?;
        return Ok(());
    }
    directory_permissions.make_writable(dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let entry_path = entry.path();
        let relative_entry = relative_dir.join(entry.file_name());
        if has_created_descendant(created_paths, &relative_entry) {
            let metadata = fs::symlink_metadata(&entry_path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                clear_directory_preserving(
                    &entry_path,
                    &relative_entry,
                    directory_permissions,
                    created_paths,
                )?;
            }
            continue;
        }
        remove_path(&entry_path, directory_permissions)?;
    }
    Ok(())
}

fn has_created_descendant(created_paths: &BTreeSet<PathBuf>, path: &Path) -> bool {
    created_paths
        .iter()
        .any(|created| created == path || created.starts_with(path))
}

fn remove_path(path: &Path, directory_permissions: &mut DirectoryPermissions) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            make_tree_writable(path, directory_permissions)?;
            fs::remove_dir_all(path)?;
        }
        Ok(_) => {
            fs::remove_file(path)?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(())
}

fn make_tree_writable(path: &Path, directory_permissions: &mut DirectoryPermissions) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(());
    }
    directory_permissions.make_writable(path)?;
    for entry in fs::read_dir(path)? {
        let child = entry?.path();
        let child_metadata = fs::symlink_metadata(&child)?;
        if child_metadata.is_dir() && !child_metadata.file_type().is_symlink() {
            make_tree_writable(&child, directory_permissions)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct DirectoryPermissions {
    #[cfg(unix)]
    modes: BTreeMap<PathBuf, u32>,
}

impl DirectoryPermissions {
    fn make_writable(&mut self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return Ok(());
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Ok(());
            }

            let mode = metadata.permissions().mode();
            if mode & 0o700 == 0o700 {
                return Ok(());
            }

            self.modes.entry(path.to_path_buf()).or_insert(mode);
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        }

        #[cfg(not(unix))]
        {
            let _ = path;
        }

        Ok(())
    }

    fn restore(self) -> Result<()> {
        #[cfg(unix)]
        {
            for (path, mode) in self.modes.into_iter().rev() {
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(())
    }
}

#[cfg(unix)]
type HardLinkMap = BTreeMap<(u64, u64), PathBuf>;
#[cfg(not(unix))]
type HardLinkMap = ();

#[derive(Default)]
struct FilePermissions {
    #[cfg(unix)]
    modes: BTreeMap<PathBuf, u32>,
}

impl FilePermissions {
    fn make_readable(&mut self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Ok(());
            }

            let mode = metadata.permissions().mode();
            if mode & 0o400 != 0 {
                return Ok(());
            }

            self.modes.entry(path.to_path_buf()).or_insert(mode);
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o400))?;
        }

        #[cfg(not(unix))]
        {
            let _ = path;
        }

        Ok(())
    }

    fn restore(self) -> Result<()> {
        #[cfg(unix)]
        {
            for (path, mode) in self.modes {
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => return Err(err.into()),
                }
            }
        }

        Ok(())
    }
}

fn write_rootfs_tar(rootfs_dir: &Path, dest: &Path) -> Result<()> {
    let file = File::create(dest)?;
    let mut builder = tar::Builder::new(file);
    builder.follow_symlinks(false);

    let mut file_permissions = FilePermissions::default();
    #[cfg(unix)]
    let mut hard_links = BTreeMap::new();
    #[cfg(not(unix))]
    let mut hard_links = ();

    let result = append_directory_contents(
        &mut builder,
        rootfs_dir,
        rootfs_dir,
        &mut file_permissions,
        &mut hard_links,
    )
    .and_then(|()| builder.finish().map_err(|e| PackError::Tar(e.to_string())));

    let restore_result = file_permissions.restore();
    result?;
    restore_result
}

fn append_directory_contents<W: Write>(
    builder: &mut tar::Builder<W>,
    rootfs_dir: &Path,
    dir: &Path,
    file_permissions: &mut FilePermissions,
    hard_links: &mut HardLinkMap,
) -> Result<()> {
    let mut entries = fs::read_dir(dir)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        append_path(
            builder,
            rootfs_dir,
            &entry.path(),
            file_permissions,
            hard_links,
        )?;
    }

    Ok(())
}

fn append_path<W: Write>(
    builder: &mut tar::Builder<W>,
    rootfs_dir: &Path,
    path: &Path,
    file_permissions: &mut FilePermissions,
    hard_links: &mut HardLinkMap,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let relative_path = path
        .strip_prefix(rootfs_dir)
        .map_err(|e| PackError::Tar(e.to_string()))?;

    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let mut header = tar_header(&metadata, tar::EntryType::Directory);
        builder
            .append_data(&mut header, relative_path, io::empty())
            .map_err(|e| PackError::Tar(e.to_string()))?;
        append_directory_contents(builder, rootfs_dir, path, file_permissions, hard_links)?;
        return Ok(());
    }

    if metadata.file_type().is_symlink() {
        let target = fs::read_link(path)?;
        let mut header = tar_header(&metadata, tar::EntryType::Symlink);
        builder
            .append_link(&mut header, relative_path, target)
            .map_err(|e| PackError::Tar(e.to_string()))?;
        return Ok(());
    }

    if metadata.is_file() {
        #[cfg(unix)]
        {
            let key = (metadata.dev(), metadata.ino());
            if metadata.nlink() > 1 {
                if let Some(first_path) = hard_links.get(&key) {
                    let mut header = tar_header(&metadata, tar::EntryType::Link);
                    builder
                        .append_link(&mut header, relative_path, first_path)
                        .map_err(|e| PackError::Tar(e.to_string()))?;
                    return Ok(());
                }
                hard_links.insert(key, relative_path.to_path_buf());
            }
        }

        file_permissions.make_readable(path)?;
        let mut file = File::open(path)?;
        let mut header = tar_header(&metadata, tar::EntryType::Regular);
        header.set_size(metadata.len());
        header.set_cksum();
        builder
            .append_data(&mut header, relative_path, &mut file)
            .map_err(|e| PackError::Tar(e.to_string()))?;
        return Ok(());
    }

    Err(PackError::Tar(format!(
        "unsupported rootfs entry type: {}",
        relative_path.display()
    )))
}

fn tar_header(metadata: &fs::Metadata, entry_type: tar::EntryType) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(entry_type);
    header.set_size(0);

    #[cfg(unix)]
    {
        header.set_mode(metadata.permissions().mode() & 0o7777);
        header.set_uid(metadata.uid() as u64);
        header.set_gid(metadata.gid() as u64);
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        header.set_mode(0o644);
    }

    if let Ok(modified) = metadata.modified() {
        if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
            header.set_mtime(duration.as_secs());
        }
    }

    header.set_cksum();
    header
}

fn safe_relative_path(path: &Path) -> Result<PathBuf> {
    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => safe.push(part),
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(PackError::InvalidOciArchive(format!(
                    "unsafe archive path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(safe)
}

fn blob_path(root: &Path, digest: &str) -> Result<PathBuf> {
    let (algorithm, value) = digest.split_once(':').ok_or_else(|| {
        PackError::InvalidOciArchive(format!("invalid digest [{digest}], expected ALGO:HEX"))
    })?;
    if algorithm != "sha256" {
        return Err(PackError::InvalidOciArchive(format!(
            "unsupported digest algorithm: {algorithm}"
        )));
    }
    validate_sha256_digest(value)?;
    let path = root.join("blobs").join("sha256").join(value);
    if !path.is_file() {
        return Err(PackError::InvalidOciArchive(format!(
            "missing blob: {digest}"
        )));
    }
    let expected_digest = format!("sha256:{}", value.to_ascii_lowercase());
    verify_file_digest(&path, &expected_digest)?;
    Ok(path)
}

fn validate_sha256_digest(value: &str) -> Result<()> {
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(PackError::InvalidOciArchive(
        "invalid sha256 digest".to_string(),
    ))
}

fn verify_file_digest(path: &Path, expected: &str) -> Result<()> {
    let actual = digest_file(path)?;
    if actual == expected {
        return Ok(());
    }
    Err(PackError::InvalidOciArchive(format!(
        "blob digest mismatch: expected {expected}, got {actual}"
    )))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let file = File::open(path)?;
    serde_json::from_reader(file).map_err(Into::into)
}

fn digest_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 64];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn dir_size(path: &Path) -> Result<u64> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(metadata.len());
    }
    let mut size = metadata.len();
    for entry in fs::read_dir(path)? {
        size += dir_size(&entry?.path())?;
    }
    Ok(size)
}

#[derive(Debug, Deserialize)]
struct OciIndex {
    manifests: Vec<OciDescriptor>,
}

#[derive(Debug, Deserialize)]
struct OciDescriptor {
    #[serde(rename = "mediaType")]
    media_type: Option<String>,
    digest: String,
    platform: Option<OciPlatform>,
    annotations: Option<OciAnnotations>,
}

#[derive(Debug, Deserialize)]
struct OciPlatform {
    architecture: String,
    os: String,
}

#[derive(Debug, Deserialize)]
struct OciAnnotations {
    #[serde(rename = "org.opencontainers.image.ref.name")]
    reference_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OciManifest {
    config: OciDescriptor,
    layers: Vec<OciLayer>,
}

#[derive(Debug, Deserialize)]
struct OciLayer {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    #[serde(default)]
    size: u64,
}

#[derive(Debug, Deserialize)]
struct OciConfig {
    architecture: String,
    os: String,
    config: Option<OciConfigValues>,
}

#[derive(Debug, Default, Deserialize)]
struct OciConfigValues {
    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,
    #[serde(rename = "Env")]
    env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
    #[serde(rename = "User")]
    user: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn imports_oci_archive_with_whiteouts() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("image.oci.tar");
        build_test_archive(&archive_path);

        let work_dir = temp.path().join("work");
        let image = import_oci_archive(&archive_path, &work_dir, Some("linux/amd64")).unwrap();

        assert_eq!(image.reference, "localhost/test:latest");
        assert_eq!(image.architecture, "amd64");
        assert_eq!(image.os, "linux");
        assert_eq!(image.entrypoint, ["/bin/app"]);
        assert_eq!(image.cmd, ["serve"]);
        assert_eq!(image.env, ["A=1"]);
        assert_eq!(image.workdir.as_deref(), Some("/app"));
        assert_eq!(image.user.as_deref(), Some("1000:1000"));
        assert!(image.layer_digest.starts_with("sha256:"));

        let unpacked = temp.path().join("unpacked");
        fs::create_dir_all(&unpacked).unwrap();
        let file = File::open(&image.layer_path).unwrap();
        tar::Archive::new(file).unpack(&unpacked).unwrap();

        assert!(unpacked.join("app/keep").exists());
        assert!(unpacked.join("app/new").exists());
        assert!(!unpacked.join("app/remove").exists());
        assert!(!unpacked.join("etc/old").exists());
        assert!(!unpacked.join("opaque/a").exists());
        assert!(unpacked.join("opaque/b").exists());
    }

    #[test]
    fn inspects_oci_archive_without_unpacking_rootfs() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("image.oci.tar");
        build_test_archive(&archive_path);

        let work_dir = temp.path().join("work");
        let image = inspect_oci_archive(&archive_path, &work_dir, Some("linux/amd64")).unwrap();

        assert_eq!(image.reference, "localhost/test:latest");
        assert_eq!(image.architecture, "amd64");
        assert_eq!(image.os, "linux");
        assert_eq!(image.entrypoint, ["/bin/app"]);
        assert_eq!(image.cmd, ["serve"]);
        assert_eq!(image.env, ["A=1"]);
        assert_eq!(image.workdir.as_deref(), Some("/app"));
        assert_eq!(image.user.as_deref(), Some("1000:1000"));
        assert_eq!(image.layers.len(), 2);
        assert!(image.image_key.starts_with("sha256:"));
        assert!(!work_dir.join("rootfs").exists());
    }

    #[test]
    fn imports_oci_archive_with_restrictive_directories() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("locked.oci.tar");
        build_restrictive_directory_archive(&archive_path);

        let work_dir = temp.path().join("work");
        let image = import_oci_archive(&archive_path, &work_dir, Some("linux/amd64")).unwrap();

        let file = File::open(&image.layer_path).unwrap();
        let mut archive = tar::Archive::new(file);
        let names = archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert!(names.iter().any(|name| name.ends_with("locked/new")));
    }

    #[test]
    fn applies_late_whiteouts_without_removing_same_layer_entries() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("late-whiteout.oci.tar");
        build_late_whiteout_archive(&archive_path);

        let work_dir = temp.path().join("work");
        import_oci_archive(&archive_path, &work_dir, Some("linux/amd64")).unwrap();

        assert!(!work_dir.join("rootfs/dir/old").exists());
        assert!(work_dir.join("rootfs/dir/new").exists());
        assert_eq!(
            fs::read_to_string(work_dir.join("rootfs/explicit/old")).unwrap(),
            "new"
        );
    }

    #[test]
    fn imports_oci_archive_to_rootfs_directory() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("image.oci.tar");
        build_test_archive(&archive_path);

        let rootfs = temp.path().join("cache/rootfs");
        let work_dir = temp.path().join("work");
        let image =
            import_oci_archive_rootfs(&archive_path, &rootfs, &work_dir, Some("linux/amd64"))
                .unwrap();

        assert_eq!(image.reference, "localhost/test:latest");
        assert_eq!(image.entrypoint, ["/bin/app"]);
        assert!(image.layer_digest.starts_with("sha256:"));
        assert!(rootfs.join("app/keep").exists());
        assert!(rootfs.join("app/new").exists());
        assert!(!rootfs.join("app/remove").exists());
        assert!(!work_dir.join("rootfs").exists());
    }

    #[cfg(unix)]
    #[test]
    fn imports_oci_archive_with_forward_hardlinks() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("hardlink.oci.tar");
        build_forward_hardlink_archive(&archive_path);

        let work_dir = temp.path().join("work");
        import_oci_archive(&archive_path, &work_dir, Some("linux/amd64")).unwrap();

        let source = fs::metadata(work_dir.join("rootfs/source")).unwrap();
        let linked = fs::metadata(work_dir.join("rootfs/linked")).unwrap();
        assert_eq!(source.ino(), linked.ino());
    }

    #[cfg(unix)]
    #[test]
    fn imports_oci_archive_with_unreadable_files() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("unreadable.oci.tar");
        build_unreadable_file_archive(&archive_path);

        let work_dir = temp.path().join("work");
        let image = import_oci_archive(&archive_path, &work_dir, Some("linux/amd64")).unwrap();

        let file = File::open(&image.layer_path).unwrap();
        let mut archive = tar::Archive::new(file);
        let mode = archive
            .entries()
            .unwrap()
            .find_map(|entry| {
                let entry = entry.unwrap();
                let path = entry.path().unwrap();
                (path.ends_with("secret")).then(|| entry.header().mode().unwrap())
            })
            .unwrap();
        assert_eq!(mode, 0o111);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_outer_archive_links() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("linked.oci.tar");
        let file = File::create(&archive_path).unwrap();
        let mut archive = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        archive
            .append_link(&mut header, "index.json", "/tmp/index.json")
            .unwrap();
        archive.finish().unwrap();

        let err = unpack_outer_archive(&archive_path, &temp.path().join("out")).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported outer archive entry type"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_layer_entries_that_escape_through_symlinked_parent() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        let archive_path = temp.path().join("escape.oci.tar");
        let layer1 = tar_bytes_with_symlink("escape", &outside);
        let layer2 = tar_bytes(&[("escape/pwn", "pwn")]);
        build_archive(
            &archive_path,
            &[(OCI_LAYER_TAR, layer1), (OCI_LAYER_TAR, layer2)],
        );

        let err = import_oci_archive(
            &archive_path,
            &temp.path().join("work"),
            Some("linux/amd64"),
        )
        .unwrap_err();

        assert!(err.to_string().contains("archive path escapes rootfs"));
        assert!(!outside.join("pwn").exists());
    }

    #[test]
    fn rejects_invalid_blob_digest_paths() {
        let temp = tempfile::tempdir().unwrap();

        let err = blob_path(temp.path(), "sha256:../outside").unwrap_err();

        assert!(err.to_string().contains("invalid sha256 digest"));
    }

    #[test]
    fn rejects_blob_digest_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let blobs = temp.path().join("blobs/sha256");
        fs::create_dir_all(&blobs).unwrap();
        let digest = "0".repeat(64);
        fs::write(blobs.join(&digest), "not the expected content").unwrap();

        let err = blob_path(temp.path(), &format!("sha256:{digest}")).unwrap_err();

        assert!(err.to_string().contains("blob digest mismatch"));
    }

    fn build_test_archive(path: &Path) {
        let temp = tempfile::tempdir().unwrap();
        let blobs = temp.path().join("blobs/sha256");
        fs::create_dir_all(&blobs).unwrap();

        let layer1 = tar_bytes(&[
            ("app/keep", "kept"),
            ("app/remove", "removed"),
            ("etc/old", "old"),
            ("opaque/a", "a"),
        ]);
        let layer1_digest = write_blob(&blobs, &layer1);

        let layer2 = tar_bytes(&[
            ("app/.wh.remove", ""),
            ("app/new", "new"),
            ("etc/.wh.old", ""),
            ("opaque/.wh..wh..opq", ""),
            ("opaque/b", "b"),
        ]);
        let layer2_digest = write_blob(&blobs, &layer2);

        let config = serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Entrypoint": ["/bin/app"],
                "Cmd": ["serve"],
                "Env": ["A=1"],
                "WorkingDir": "/app",
                "User": "1000:1000"
            }
        })
        .to_string()
        .into_bytes();
        let config_digest = write_blob(&blobs, &config);

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config.len()
            },
            "layers": [
                {
                    "mediaType": OCI_LAYER_TAR,
                    "digest": layer1_digest,
                    "size": layer1.len()
                },
                {
                    "mediaType": OCI_LAYER_TAR,
                    "digest": layer2_digest,
                    "size": layer2.len()
                }
            ]
        })
        .to_string()
        .into_bytes();
        let manifest_digest = write_blob(&blobs, &manifest);

        fs::write(
            temp.path().join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("index.json"),
            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": OCI_IMAGE_MANIFEST,
                    "digest": manifest_digest,
                    "platform": {"os": "linux", "architecture": "amd64"},
                    "annotations": {
                        "org.opencontainers.image.ref.name": "localhost/test:latest"
                    }
                }]
            })
            .to_string(),
        )
        .unwrap();

        let file = File::create(path).unwrap();
        let mut archive = tar::Builder::new(file);
        archive.append_dir_all(".", temp.path()).unwrap();
        archive.finish().unwrap();
    }

    fn build_restrictive_directory_archive(path: &Path) {
        let layer1 = tar_bytes_with_directory("locked", 0o555);
        let layer2 = tar_bytes(&[("locked/new", "new")]);
        build_archive(path, &[(OCI_LAYER_TAR, layer1), (OCI_LAYER_TAR, layer2)]);
    }

    fn build_forward_hardlink_archive(path: &Path) {
        let layer = tar_bytes_with_forward_hardlink();
        build_archive(path, &[(OCI_LAYER_TAR, layer)]);
    }

    fn build_unreadable_file_archive(path: &Path) {
        let layer = tar_bytes_with_file_mode("secret", "secret", 0o111);
        build_archive(path, &[(OCI_LAYER_TAR, layer)]);
    }

    fn build_late_whiteout_archive(path: &Path) {
        let layer1 = tar_bytes(&[("dir/old", "old"), ("explicit/old", "old")]);
        let layer2 = tar_bytes(&[
            ("dir/new", "new"),
            ("dir/.wh..wh..opq", ""),
            ("explicit/old", "new"),
            ("explicit/.wh.old", ""),
        ]);
        build_archive(path, &[(OCI_LAYER_TAR, layer1), (OCI_LAYER_TAR, layer2)]);
    }

    fn build_archive(path: &Path, layers: &[(&str, Vec<u8>)]) {
        let temp = tempfile::tempdir().unwrap();
        let blobs = temp.path().join("blobs/sha256");
        fs::create_dir_all(&blobs).unwrap();

        let layer_descriptors = layers
            .iter()
            .map(|(media_type, data)| {
                let digest = write_blob(&blobs, data);
                serde_json::json!({
                    "mediaType": media_type,
                    "digest": digest,
                    "size": data.len()
                })
            })
            .collect::<Vec<_>>();

        let config = serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {}
        })
        .to_string()
        .into_bytes();
        let config_digest = write_blob(&blobs, &config);

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_IMAGE_MANIFEST,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config.len()
            },
            "layers": layer_descriptors
        })
        .to_string()
        .into_bytes();
        let manifest_digest = write_blob(&blobs, &manifest);

        fs::write(
            temp.path().join("oci-layout"),
            r#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("index.json"),
            serde_json::json!({
                "schemaVersion": 2,
                "manifests": [{
                    "mediaType": OCI_IMAGE_MANIFEST,
                    "digest": manifest_digest,
                    "platform": {"os": "linux", "architecture": "amd64"},
                    "annotations": {
                        "org.opencontainers.image.ref.name": "localhost/locked:latest"
                    }
                }]
            })
            .to_string(),
        )
        .unwrap();

        let file = File::create(path).unwrap();
        let mut archive = tar::Builder::new(file);
        archive.append_dir_all(".", temp.path()).unwrap();
        archive.finish().unwrap();
    }

    fn tar_bytes(files: &[(&str, &str)]) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut data);
            for (path, content) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, *path, content.as_bytes())
                    .unwrap();
            }
            builder.finish().unwrap();
        }
        data
    }

    fn tar_bytes_with_directory(path: &str, mode: u32) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut data);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_mode(mode);
            header.set_cksum();
            builder.append_data(&mut header, path, io::empty()).unwrap();
            builder.finish().unwrap();
        }
        data
    }

    fn tar_bytes_with_forward_hardlink() -> Vec<u8> {
        let mut data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut data);

            let mut link_header = tar::Header::new_gnu();
            link_header.set_entry_type(tar::EntryType::Link);
            link_header.set_size(0);
            link_header.set_mode(0o644);
            builder
                .append_link(&mut link_header, "linked", "source")
                .unwrap();

            let content = b"data";
            let mut file_header = tar::Header::new_gnu();
            file_header.set_size(content.len() as u64);
            file_header.set_mode(0o644);
            file_header.set_cksum();
            builder
                .append_data(&mut file_header, "source", &content[..])
                .unwrap();

            builder.finish().unwrap();
        }
        data
    }

    fn tar_bytes_with_file_mode(path: &str, content: &str, mode: u32) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut data);
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(mode);
            header.set_cksum();
            builder
                .append_data(&mut header, path, content.as_bytes())
                .unwrap();
            builder.finish().unwrap();
        }
        data
    }

    #[cfg(unix)]
    fn tar_bytes_with_symlink(path: &str, target: &Path) -> Vec<u8> {
        let mut data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut data);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            builder.append_link(&mut header, path, target).unwrap();
            builder.finish().unwrap();
        }
        data
    }

    fn write_blob(blobs: &Path, data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        let hex = format!("{:x}", digest);
        let mut file = File::create(blobs.join(&hex)).unwrap();
        file.write_all(data).unwrap();
        format!("sha256:{hex}")
    }
}
