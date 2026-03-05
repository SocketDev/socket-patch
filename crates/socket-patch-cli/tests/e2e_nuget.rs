#![cfg(feature = "nuget")]
//! End-to-end tests for the NuGet/.NET package patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with fake
//! NuGet package layouts.  They do **not** require network access or a real
//! .NET installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features nuget --test e2e_nuget
//! ```

use std::path::PathBuf;
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn run(args: &[&str], cwd: &std::path::Path, nuget_packages: &std::path::Path) -> Output {
    Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env("NUGET_PACKAGES", nuget_packages)
        .output()
        .expect("Failed to run socket-patch binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers packages in a fake global cache layout.
#[test]
fn scan_discovers_global_cache_packages() {
    let dir = tempfile::tempdir().unwrap();

    // Set up a fake global NuGet cache: <name>/<version>/ with .nuspec
    let nuget_cache = dir.path().join("nuget-cache");

    let nj_dir = nuget_cache.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(nj_dir.join("lib")).unwrap();
    std::fs::write(
        nj_dir.join("newtonsoft.json.nuspec"),
        r#"<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
    )
    .unwrap();

    let stj_dir = nuget_cache.join("system.text.json").join("8.0.0");
    std::fs::create_dir_all(&stj_dir).unwrap();
    std::fs::write(
        stj_dir.join("system.text.json.nuspec"),
        r#"<package><metadata><id>System.Text.Json</id><version>8.0.0</version></metadata></package>"#,
    )
    .unwrap();

    // Create a .csproj so it's recognized as a .NET project
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(project_dir.join("MyApp.csproj"), "<Project/>").unwrap();

    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &nuget_cache,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover NuGet packages, got:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers packages in a fake legacy packages/ layout.
#[test]
fn scan_discovers_legacy_packages() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create a .csproj
    std::fs::write(project_dir.join("MyApp.csproj"), "<Project/>").unwrap();

    // Set up legacy packages/ directory
    let packages_dir = project_dir.join("packages");

    let nj_dir = packages_dir.join("Newtonsoft.Json.13.0.3");
    std::fs::create_dir_all(nj_dir.join("lib")).unwrap();
    std::fs::write(
        nj_dir.join("Newtonsoft.Json.nuspec"),
        r#"<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
    )
    .unwrap();

    // Use the packages dir itself as NUGET_PACKAGES (though legacy is found via cwd)
    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &packages_dir,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover legacy NuGet packages, got:\n{combined}"
    );
}
