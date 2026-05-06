//! Local imported image store.
//!
//! Imported images are host-local, unpacked once into a smolvm-owned directory,
//! and then mounted into VMs as pre-extracted layers.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use smolvm_protocol::ImageInfo;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Metadata file the guest agent reads from mounted imported layers.
pub const PACKED_IMAGE_METADATA: &str = ".smolvm-image.json";

const STORE_VERSION: u32 = 1;

/// A reference to an imported local image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedImageRecord {
    /// Store record version.
    pub version: u32,
    /// Image reference used by callers.
    pub reference: String,
    /// Content key for the imported root filesystem.
    pub key: String,
    /// Optional external source identifier, such as a Podman image ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    /// OCI config digest.
    pub digest: String,
    /// Root filesystem size in bytes.
    pub size: u64,
    /// Creation timestamp.
    pub created_at: String,
    /// Last resolved timestamp.
    pub last_used_at: String,
    /// Platform architecture.
    pub architecture: String,
    /// Platform operating system.
    pub os: String,
    /// Merged layer digest.
    pub layer_digest: String,
    /// Image entrypoint.
    #[serde(default)]
    pub entrypoint: Vec<String>,
    /// Image default command.
    #[serde(default)]
    pub cmd: Vec<String>,
    /// Image environment variables.
    #[serde(default)]
    pub env: Vec<String>,
    /// Image working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// Image default user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl ImportedImageRecord {
    /// Convert this imported image record into guest-agent image metadata.
    pub fn image_info(&self) -> ImageInfo {
        ImageInfo {
            reference: self.reference.clone(),
            digest: self.digest.clone(),
            size: self.size,
            created: Some(self.created_at.clone()),
            architecture: self.architecture.clone(),
            os: self.os.clone(),
            layer_count: 1,
            layers: vec![self.layer_digest.clone()],
            entrypoint: self.entrypoint.clone(),
            cmd: self.cmd.clone(),
            env: self.env.clone(),
            workdir: self.workdir.clone(),
            user: self.user.clone(),
        }
    }
}

/// Result from pruning the imported-image store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImagePruneResult {
    /// Number of imported image references that were or would be removed.
    pub refs: usize,
    /// Number of imported image entries that were or would be removed.
    pub entries: usize,
    /// Number of temporary staging entries that were or would be removed.
    pub staging_entries: usize,
    /// Bytes that were or would be reclaimed.
    pub bytes_reclaimable: u64,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

/// Host-local imported image store.
#[derive(Debug, Clone)]
pub struct ImageStore {
    root: PathBuf,
}

impl ImageStore {
    /// Open the default imported-image store.
    pub fn open() -> Result<Self> {
        let data_dir = dirs::data_local_dir()
            .or_else(dirs::data_dir)
            .ok_or_else(|| {
                Error::storage("resolve image store", "could not determine data directory")
            })?;
        Ok(Self {
            root: data_dir.join("smolvm").join("images"),
        })
    }

    /// Import an OCI archive into the store and bind it to `reference`.
    pub fn import_oci_archive(
        &self,
        archive_path: &Path,
        reference: Option<&str>,
        platform: Option<&str>,
        source_id: Option<String>,
    ) -> Result<ImportedImageRecord> {
        if !archive_path.is_file() {
            return Err(Error::config(
                "import image",
                format!("OCI archive not found: {}", archive_path.display()),
            ));
        }

        fs::create_dir_all(self.entries_dir())?;
        fs::create_dir_all(self.refs_dir())?;
        fs::create_dir_all(self.tmp_dir())?;

        let staging = self.tmp_dir().join(unique_name("import"));
        let work_dir = staging.join("work");
        let staging_layers = staging.join("entry").join("layers");
        let staging_rootfs = staging_layers.join("rootfs");
        fs::create_dir_all(&staging_layers)?;

        let imported = smolvm_pack::oci_archive::import_oci_archive_rootfs(
            archive_path,
            &staging_rootfs,
            &work_dir,
            platform,
        )
        .map_err(|e| Error::storage("import OCI archive", e.to_string()))?;

        let reference = reference.unwrap_or(&imported.reference).to_string();
        let layer_id = imported
            .layer_digest
            .strip_prefix("sha256:")
            .unwrap_or(&imported.layer_digest)
            .to_string();
        let key = layer_id.clone();
        let final_rootfs = staging_layers.join(&layer_id);
        fs::rename(&imported.rootfs_path, &final_rootfs)?;

        let record = ImportedImageRecord {
            version: STORE_VERSION,
            reference,
            key: key.clone(),
            source_id,
            digest: imported.digest,
            size: imported.size,
            created_at: crate::util::current_timestamp(),
            last_used_at: crate::util::current_timestamp(),
            architecture: imported.architecture,
            os: imported.os,
            layer_digest: imported.layer_digest,
            entrypoint: imported.entrypoint,
            cmd: imported.cmd,
            env: imported.env,
            workdir: imported.workdir,
            user: imported.user,
        };

        let entry_dir = self.entry_dir(&key);
        if entry_dir.exists() && !entry_dir.join("layers").join(&layer_id).is_dir() {
            remove_dir_all_writable(&entry_dir)?;
        }
        if !entry_dir.exists() {
            fs::rename(staging.join("entry"), &entry_dir)?;
        }
        remove_dir_all_writable(&staging)?;

        self.write_agent_metadata(&record)?;
        self.write_ref(&record)?;
        Ok(record)
    }

    /// Resolve an imported image reference.
    pub fn resolve(&self, reference: &str) -> Result<Option<ImportedImageRecord>> {
        let path = self.ref_path(reference);
        if !path.is_file() {
            return Ok(None);
        }
        let mut record: ImportedImageRecord = read_json(&path)?;
        if record.version != STORE_VERSION {
            return Ok(None);
        }
        if !self.layers_dir(&record.key).is_dir() {
            return Ok(None);
        }
        record.last_used_at = crate::util::current_timestamp();
        self.write_ref(&record)?;
        Ok(Some(record))
    }

    /// List imported image references.
    pub fn list(&self) -> Result<Vec<ImportedImageRecord>> {
        let mut records = Vec::new();
        if !self.refs_dir().is_dir() {
            return Ok(records);
        }
        for entry in fs::read_dir(self.refs_dir())? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }
            let Ok(record) = read_json::<ImportedImageRecord>(&path) else {
                continue;
            };
            if record.version == STORE_VERSION && self.layers_dir(&record.key).is_dir() {
                records.push(record);
            }
        }
        records.sort_by(|a, b| a.reference.cmp(&b.reference));
        Ok(records)
    }

    /// Remove an image reference. The underlying entry is removed by prune.
    pub fn remove_ref(&self, reference: &str) -> Result<Option<ImportedImageRecord>> {
        let path = self.ref_path(reference);
        if !path.is_file() {
            return Ok(None);
        }
        let record = read_json(&path).ok();
        fs::remove_file(path)?;
        Ok(record)
    }

    /// Prune unreferenced imported image entries and temporary staging data.
    pub fn prune(
        &self,
        protected_keys: impl IntoIterator<Item = String>,
        prune_unused_refs: bool,
        dry_run: bool,
    ) -> Result<ImagePruneResult> {
        let mut protected = protected_keys.into_iter().collect::<BTreeSet<_>>();
        let mut refs = 0;

        let mut staging_entries = 0;
        let mut entries = 0;
        let mut bytes_reclaimable = 0;

        if self.refs_dir().is_dir() {
            for entry in fs::read_dir(self.refs_dir())? {
                let path = entry?.path();
                if !path.is_file() {
                    continue;
                }
                let Ok(record) = read_json::<ImportedImageRecord>(&path) else {
                    continue;
                };
                if record.version != STORE_VERSION || !self.layers_dir(&record.key).is_dir() {
                    continue;
                }
                if protected.contains(&record.key) {
                    continue;
                }
                if prune_unused_refs {
                    refs += 1;
                    if !dry_run {
                        fs::remove_file(path)?;
                    }
                } else {
                    protected.insert(record.key);
                }
            }
        }

        if self.tmp_dir().is_dir() {
            for entry in fs::read_dir(self.tmp_dir())? {
                let path = entry?.path();
                staging_entries += 1;
                bytes_reclaimable += path_size(&path);
                if !dry_run {
                    remove_path(&path)?;
                }
            }
        }

        if self.entries_dir().is_dir() {
            for entry in fs::read_dir(self.entries_dir())? {
                let path = entry?.path();
                if !path.is_dir() {
                    continue;
                }
                let Some(key) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                if protected.contains(key) {
                    continue;
                }
                entries += 1;
                bytes_reclaimable += path_size(&path);
                if !dry_run {
                    remove_dir_all_writable(&path)?;
                }
            }
        }

        Ok(ImagePruneResult {
            refs,
            entries,
            staging_entries,
            bytes_reclaimable,
            dry_run,
        })
    }

    /// Return the host directory that should be mounted as packed layers.
    pub fn layers_dir(&self, key: &str) -> PathBuf {
        self.entry_dir(key).join("layers")
    }

    fn write_ref(&self, record: &ImportedImageRecord) -> Result<()> {
        fs::create_dir_all(self.refs_dir())?;
        write_json_atomic(&self.ref_path(&record.reference), record)
    }

    fn write_agent_metadata(&self, record: &ImportedImageRecord) -> Result<()> {
        let entry_dir = self.entry_dir(&record.key);
        let layers_dir = entry_dir.join("layers");
        fs::create_dir_all(&layers_dir)?;
        write_json_atomic(&entry_dir.join("image.json"), record)?;
        write_json_atomic(
            &layers_dir.join(PACKED_IMAGE_METADATA),
            &record.image_info(),
        )
    }

    fn refs_dir(&self) -> PathBuf {
        self.root.join("refs")
    }

    fn entries_dir(&self) -> PathBuf {
        self.root.join("entries")
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    fn entry_dir(&self, key: &str) -> PathBuf {
        self.entries_dir().join(key)
    }

    fn ref_path(&self, reference: &str) -> PathBuf {
        self.refs_dir().join(format!("{}.json", ref_id(reference)))
    }
}

fn ref_id(reference: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn unique_name(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{}-{}-{}", prefix, std::process::id(), nanos)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| Error::storage("read image metadata", e.to_string()))
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(unique_name("tmp"));
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| Error::storage("serialize image metadata", e.to_string()))?;
    fs::write(&tmp, format!("{}\n", text))?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn path_size(path: &Path) -> u64 {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        let mut size = metadata.len();
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                size += path_size(&entry.path());
            }
        }
        size
    } else {
        metadata.len()
    }
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        remove_dir_all_writable(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn remove_dir_all_writable(path: &Path) -> Result<()> {
    make_tree_writable(path)?;
    fs::remove_dir_all(path)?;
    Ok(())
}

fn make_tree_writable(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o700 != 0o700 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode | 0o700))?;
        }
    }

    for entry in fs::read_dir(path)? {
        let child = entry?.path();
        let child_metadata = fs::symlink_metadata(&child)?;
        if child_metadata.is_dir() && !child_metadata.file_type().is_symlink() {
            make_tree_writable(&child)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_keeps_referenced_entries_by_default() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(temp.path());
        let record = add_record(&store, "local/test:latest", "key-default");

        let result = store.prune(Vec::new(), false, false).unwrap();

        assert_eq!(result.refs, 0);
        assert_eq!(result.entries, 0);
        assert!(store.ref_path(&record.reference).is_file());
        assert!(store.entry_dir(&record.key).is_dir());
    }

    #[test]
    fn prune_unused_removes_refs_and_entries_not_used_by_machines() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(temp.path());
        let record = add_record(&store, "local/test:latest", "key-unused");

        let result = store.prune(Vec::new(), true, false).unwrap();

        assert_eq!(result.refs, 1);
        assert_eq!(result.entries, 1);
        assert!(!store.ref_path(&record.reference).exists());
        assert!(!store.entry_dir(&record.key).exists());
        assert!(result.bytes_reclaimable > 0);
    }

    #[test]
    fn prune_unused_keeps_refs_and_entries_used_by_machines() {
        let temp = tempfile::tempdir().unwrap();
        let store = store_in(temp.path());
        let record = add_record(&store, "local/test:latest", "key-protected");

        let result = store.prune(vec![record.key.clone()], true, false).unwrap();

        assert_eq!(result.refs, 0);
        assert_eq!(result.entries, 0);
        assert!(store.ref_path(&record.reference).is_file());
        assert!(store.entry_dir(&record.key).is_dir());
    }

    fn store_in(root: &Path) -> ImageStore {
        ImageStore {
            root: root.join("images"),
        }
    }

    fn add_record(store: &ImageStore, reference: &str, key: &str) -> ImportedImageRecord {
        let record = ImportedImageRecord {
            version: STORE_VERSION,
            reference: reference.to_string(),
            key: key.to_string(),
            source_id: Some("source-id".to_string()),
            digest: "sha256:config".to_string(),
            size: 4,
            created_at: "1".to_string(),
            last_used_at: "1".to_string(),
            architecture: "amd64".to_string(),
            os: "linux".to_string(),
            layer_digest: format!("sha256:{key}"),
            entrypoint: Vec::new(),
            cmd: Vec::new(),
            env: Vec::new(),
            workdir: None,
            user: None,
        };
        let layer_dir = store.layers_dir(key).join(key);
        fs::create_dir_all(&layer_dir).unwrap();
        fs::write(layer_dir.join("file"), "data").unwrap();
        store.write_ref(&record).unwrap();
        record
    }
}
