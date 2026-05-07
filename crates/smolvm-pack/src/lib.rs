//! `.smolmachine` packaging for smolvm.
//!
//! This crate provides functionality to package an OCI image and all runtime assets
//! into a portable `.smolmachine` artifact that can be pushed to a registry,
//! distributed, and run without smolvm installed.
//!
//! See [`format`] for the full binary format specification.

#![deny(missing_docs)]

#[cfg(feature = "packaging")]
pub mod assets;
#[cfg(feature = "packaging")]
pub mod detect;
#[cfg(feature = "packaging")]
pub mod extract;
#[cfg(feature = "packaging")]
pub mod format;
#[cfg(all(feature = "packaging", target_os = "macos"))]
pub mod macho;
pub mod oci_archive;
#[cfg(feature = "packaging")]
pub mod packer;
#[cfg(feature = "packaging")]
pub mod signing;

#[cfg(feature = "packaging")]
pub use detect::{detect_packed_mode, PackedMode};
#[cfg(feature = "packaging")]
pub use format::{
    PackFooter, PackManifest, PackMode, SectionHeader, FOOTER_SIZE, MAGIC, SECTION_HEADER_SIZE,
    SECTION_MAGIC, SIDECAR_EXTENSION,
};
#[cfg(feature = "packaging")]
pub use packer::{
    read_footer, read_footer_from_sidecar, read_manifest, read_manifest_from_sidecar,
    sidecar_path_for, verify_sidecar_checksum, Packer,
};

use thiserror::Error;

/// Errors that can occur during pack operations.
#[derive(Debug, Error)]
pub enum PackError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid magic bytes in footer.
    #[error("invalid magic: expected SMOLPACK")]
    InvalidMagic,

    /// Unsupported format version.
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u32),

    /// Checksum mismatch.
    #[error("checksum mismatch: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch {
        /// Expected checksum.
        expected: u32,
        /// Actual checksum.
        actual: u32,
    },

    /// Asset not found.
    #[error("asset not found: {0}")]
    AssetNotFound(String),

    /// Compression error.
    #[error("compression error: {0}")]
    Compression(String),

    /// Signing error.
    #[error("signing error: {0}")]
    Signing(String),

    /// Tar archive error.
    #[error("tar error: {0}")]
    Tar(String),

    /// Invalid OCI archive.
    #[error("invalid OCI archive: {0}")]
    InvalidOciArchive(String),

    /// Unsupported OCI layer media type.
    #[error("unsupported OCI layer media type: {0}")]
    UnsupportedLayer(String),
}

/// Result type for pack operations.
pub type Result<T> = std::result::Result<T, PackError>;
