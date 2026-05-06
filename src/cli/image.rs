//! Local imported image commands.

use crate::cli::{format_bytes, truncate};
use clap::{Args, Subcommand};
use smolvm::image_store::{ImagePruneResult, ImageStore};
use smolvm::SmolvmConfig;
use std::path::PathBuf;

/// Manage imported local images.
#[derive(Subcommand, Debug)]
pub enum ImageCmd {
    /// Import a local OCI archive into smolvm's image store
    Import(ImageImportCmd),

    /// List imported images
    #[command(visible_alias = "list")]
    Ls(ImageLsCmd),

    /// Remove an imported image reference
    #[command(visible_alias = "delete")]
    Rm(ImageRmCmd),

    /// Remove unreferenced imported image data
    Prune(ImagePruneCmd),
}

impl ImageCmd {
    /// Run the selected image command.
    pub fn run(self) -> smolvm::Result<()> {
        match self {
            ImageCmd::Import(cmd) => cmd.run(),
            ImageCmd::Ls(cmd) => cmd.run(),
            ImageCmd::Rm(cmd) => cmd.run(),
            ImageCmd::Prune(cmd) => cmd.run(),
        }
    }
}

/// Import an OCI archive.
#[derive(Args, Debug)]
pub struct ImageImportCmd {
    /// OCI archive produced by `podman save --format oci-archive`
    #[arg(long = "oci-archive", value_name = "PATH")]
    pub oci_archive: PathBuf,

    /// Image reference to assign to the imported image
    #[arg(long, value_name = "REF")]
    pub tag: Option<String>,

    /// Target OCI platform, for example linux/amd64
    #[arg(long = "oci-platform", value_name = "OS/ARCH")]
    pub oci_platform: Option<String>,

    /// External source identifier used by build tools to detect unchanged images
    #[arg(long = "source-id", value_name = "ID")]
    pub source_id: Option<String>,

    /// Output JSON
    #[arg(long)]
    pub json: bool,
}

impl ImageImportCmd {
    fn run(self) -> smolvm::Result<()> {
        let store = ImageStore::open()?;
        let record = store.import_oci_archive(
            &self.oci_archive,
            self.tag.as_deref(),
            self.oci_platform.as_deref(),
            self.source_id,
        )?;
        if self.json {
            print_json(&record)?;
        } else {
            println!("Imported image: {}", record.reference);
            println!("  Key:      {}", record.key);
            println!("  Platform: {}/{}", record.os, record.architecture);
            println!("  Size:     {}", format_bytes(record.size));
        }
        Ok(())
    }
}

/// List imported images.
#[derive(Args, Debug)]
pub struct ImageLsCmd {
    /// Output JSON
    #[arg(long)]
    pub json: bool,
}

impl ImageLsCmd {
    fn run(self) -> smolvm::Result<()> {
        let images = ImageStore::open()?.list()?;
        if self.json {
            let output = serde_json::json!({ "images": images });
            print_json(&output)?;
            return Ok(());
        }

        if images.is_empty() {
            println!("No imported images.");
            return Ok(());
        }

        println!(
            "{:<40} {:<13} {:>10} {:<12}",
            "IMAGE", "PLATFORM", "SIZE", "SOURCE"
        );
        println!("{}", "-".repeat(80));
        for image in images {
            println!(
                "{:<40} {:<13} {:>10} {:<12}",
                truncate(&image.reference, 40),
                format!("{}/{}", image.os, image.architecture),
                format_bytes(image.size),
                truncate(image.source_id.as_deref().unwrap_or("-"), 12)
            );
        }
        Ok(())
    }
}

/// Remove an imported image reference.
#[derive(Args, Debug)]
pub struct ImageRmCmd {
    /// Image reference to remove
    #[arg(value_name = "REF")]
    pub reference: String,
}

impl ImageRmCmd {
    fn run(self) -> smolvm::Result<()> {
        match ImageStore::open()?.remove_ref(&self.reference)? {
            Some(record) => {
                println!("Removed image reference: {}", record.reference);
                println!("Run 'smolvm image prune' to remove unreferenced image data.");
            }
            None => println!("Image reference not found: {}", self.reference),
        }
        Ok(())
    }
}

/// Prune unreferenced imported images.
#[derive(Args, Debug)]
pub struct ImagePruneCmd {
    /// Also remove imported image references that are not used by any machine
    #[arg(long)]
    pub unused: bool,

    /// Show what would be removed without deleting anything
    #[arg(long)]
    pub dry_run: bool,

    /// Output JSON
    #[arg(long)]
    pub json: bool,
}

impl ImagePruneCmd {
    fn run(self) -> smolvm::Result<()> {
        let protected = protected_imported_image_keys()?;
        let result = ImageStore::open()?.prune(protected, self.unused, self.dry_run)?;
        if self.json {
            print_json(&result)?;
        } else {
            print_prune_result(&result);
        }
        Ok(())
    }
}

fn protected_imported_image_keys() -> smolvm::Result<Vec<String>> {
    let config = SmolvmConfig::load()?;
    Ok(config
        .list_vms()
        .filter_map(|(_, record)| record.source_imported_image.clone())
        .collect())
}

fn print_prune_result(result: &ImagePruneResult) {
    let action = if result.dry_run {
        "Would remove"
    } else {
        "Removed"
    };
    println!(
        "{} {} imported image ref{}, {} imported image entr{} and {} staging entr{}.",
        action,
        result.refs,
        if result.refs == 1 { "" } else { "s" },
        result.entries,
        if result.entries == 1 { "y" } else { "ies" },
        result.staging_entries,
        if result.staging_entries == 1 {
            "y"
        } else {
            "ies"
        },
    );
    let size_label = if result.dry_run {
        "Reclaimable"
    } else {
        "Reclaimed"
    };
    println!("{}: {}", size_label, format_bytes(result.bytes_reclaimable));
}

fn print_json<T: serde::Serialize>(value: &T) -> smolvm::Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|e| smolvm::Error::config("serialize json", e.to_string()))?;
    println!("{}", json);
    Ok(())
}
