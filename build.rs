//! Build script for smolvm.
//!
//! Handles macOS link setup for libkrun.
//!
//! Linux loads libkrun at runtime with `dlopen` so packed stubs can start
//! before runtime libraries are extracted.
//!
//! # Linking Options
//!
//! ## Source-Built Runtime Libraries
//! Build libkrun and libkrunfw from the checked-out submodules:
//! ```sh
//! ./scripts/build-runtime-libs.sh
//! LIBKRUN_BUNDLE=$PWD/lib cargo build --release
//! ```
//! The binary will use @rpath to find libraries in ./lib or ../lib.
//!
//! ## Static (libkrun only)
//! Statically link libkrun (still dynamically links libkrunfw):
//! ```sh
//! LIBKRUN_STATIC=/path/to/libkrun.a cargo build
//! ```

#[cfg(target_os = "macos")]
use std::process::Command;

/// Link libkrun for macOS.
///
/// Linux intentionally does not link libkrun at build time: packed stubs must
/// be able to start before runtime libraries are extracted, so Linux VM launch
/// paths use `dlopen` instead.
#[cfg(target_os = "macos")]
fn link_krun() {
    println!("cargo:rustc-link-arg=-Wl,-weak-lkrun");
}

fn main() {
    // On macOS, create a placeholder __SMOLVM,__smolvm Mach-O section.
    // This section is replaced with real data by `smolvm pack --single-file`.
    // The placeholder marker is NOT the SMOLSECT magic, so detect.rs won't
    // false-positive on a normal smolvm binary.
    #[cfg(target_os = "macos")]
    {
        use std::io::Write;
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let placeholder_path = format!("{}/smolvm_placeholder.bin", out_dir);
        let mut f = std::fs::File::create(&placeholder_path).unwrap();
        f.write_all(b"SMOLVM_SECTION_PLACEHOLDER_V1").unwrap();
        f.write_all(&[0u8; 4]).unwrap();
        println!(
            "cargo:rustc-link-arg=-Wl,-sectcreate,__SMOLVM,__smolvm,{}",
            placeholder_path
        );
    }

    #[cfg(target_os = "macos")]
    link_libkrun();
}

#[cfg(target_os = "macos")]
fn link_libkrun() {
    println!("cargo:rerun-if-env-changed=LIBKRUN_STATIC");
    println!("cargo:rerun-if-env-changed=LIBKRUN_BUNDLE");
    println!("cargo:rerun-if-env-changed=LIBKRUN_DIR");

    // Option 1: Explicit runtime library directory.
    if let Ok(bundle_path) = std::env::var("LIBKRUN_BUNDLE") {
        println!("cargo:rustc-link-search=native={}", bundle_path);
        link_krun();

        // Set rpath to find libraries relative to executable
        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../lib");

            // Change the library's install_name to use @rpath and re-sign
            let lib_path = std::path::Path::new(&bundle_path).join("libkrun.dylib");
            if lib_path.exists() {
                let _ = Command::new("install_name_tool")
                    .args(["-id", "@rpath/libkrun.dylib", lib_path.to_str().unwrap()])
                    .status();
                // Re-sign after modification (macOS requires valid signature)
                let _ = Command::new("codesign")
                    .args(["--force", "--sign", "-", lib_path.to_str().unwrap()])
                    .status();
            }
        }
        #[cfg(target_os = "linux")]
        {
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/lib");
            println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../lib");
        }
        return;
    }

    // Option 2: Static linking.
    if let Ok(static_path) = std::env::var("LIBKRUN_STATIC") {
        let path = std::path::Path::new(&static_path);

        if path.is_dir() {
            println!("cargo:rustc-link-search=native={}", static_path);
        } else if path.is_file() {
            if let Some(dir) = path.parent() {
                println!("cargo:rustc-link-search=native={}", dir.display());
            }
        } else {
            panic!("LIBKRUN_STATIC path does not exist: {}", static_path);
        }

        println!("cargo:rustc-link-lib=static=krun");

        // Static libkrun requires these frameworks on macOS
        #[cfg(target_os = "macos")]
        {
            println!("cargo:rustc-link-lib=framework=Hypervisor");
            println!("cargo:rustc-link-lib=framework=vmnet");
        }
        return;
    }

    // Option 3: Custom directory.
    if let Ok(dir) = std::env::var("LIBKRUN_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
        link_krun();
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let source_lib_dir = std::path::Path::new(&manifest_dir).join("lib");
    if source_lib_dir.join("libkrun.dylib").exists() {
        println!(
            "cargo:rustc-link-search=native={}",
            source_lib_dir.display()
        );
        link_krun();
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/lib");
        println!("cargo:rustc-link-arg=-Wl,-rpath,@executable_path/../lib");
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            source_lib_dir.display()
        );
        return;
    }

    panic!("libkrun.dylib not found; run ./scripts/build-runtime-libs.sh or set LIBKRUN_BUNDLE");
}
