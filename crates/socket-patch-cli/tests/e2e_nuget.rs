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
        // The NuGet crawler is gated behind a runtime opt-in
        // (`nuget_runtime_enabled()` → `SOCKET_EXPERIMENTAL_NUGET`). Without
        // this, `scan` skips NuGet entirely and reports "No packages found.",
        // which would silently defeat any discovery assertion. Enabling it here
        // is what makes these tests actually exercise the NuGet code path.
        .env("SOCKET_EXPERIMENTAL_NUGET", "1")
        // Keep discovery deterministic: never reach a real ~/.nuget cache or a
        // populated public-proxy token from the developer's environment.
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("Failed to run socket-patch binary")
}

/// Extract the integer N from a `Found N packages` line in scan's stderr.
/// Panics if the line is absent — a missing "Found" line means scan reported
/// "No packages found." (zero discovery), which is exactly the regression
/// these tests must catch.
fn parse_found_count(combined: &str) -> usize {
    let line = combined
        .lines()
        .find(|l| l.contains("Found") && l.contains("packages"))
        .unwrap_or_else(|| {
            panic!("scan did not print a `Found N packages` line; output was:\n{combined}")
        });
    // Last "Found" segment, in case a progress carriage-return prefixes it.
    let after = line.rsplit("Found").next().unwrap();
    after
        .split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("could not parse package count from line: {line:?}"))
}

/// Assert scan reported EXACTLY `n` packages and that ALL of them were
/// attributed to the NuGet ecosystem, via the contiguous breakdown line
/// `Found <n> packages (<n> nuget)`.
///
/// This is deliberately stricter than checking the count and the substring
/// "nuget" independently: a split-ecosystem regression that mis-attributed a
/// planted package (e.g. `Found 2 packages (1 nuget, 1 npm)`) would satisfy
/// both a `count == n` check and a loose `contains("nuget")` check, yet is
/// exactly the kind of breakage we must catch. Requiring the whole
/// `(<n> nuget)` breakdown segment to match the total proves every counted
/// package is NuGet and nothing leaked in from another crawler.
fn assert_all_nuget(combined: &str, n: usize) {
    // Cross-check the bare count first for a clear error on mismatch.
    let found = parse_found_count(combined);
    assert_eq!(
        found, n,
        "expected exactly {n} discovered packages, got {found}:\n{combined}"
    );
    let needle = format!("Found {n} packages ({n} nuget)");
    assert!(
        combined.contains(&needle),
        "expected the contiguous breakdown line {needle:?} \
         (all {n} packages attributed to NuGet); output was:\n{combined}"
    );
}

/// Run `scan --json` and assert the machine-readable envelope independently
/// agrees that exactly `n` packages were scanned with overall success. This is
/// a separate output formatter from the human-readable `Found N packages` line,
/// so it guards against the human line and the JSON envelope drifting apart.
fn assert_json_scanned(
    cwd: &std::path::Path,
    nuget_packages: &std::path::Path,
    project_dir: &std::path::Path,
    n: usize,
) {
    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap(), "--json"],
        cwd,
        nuget_packages,
    );
    assert!(
        output.status.success(),
        "scan --json should exit 0 on clean discovery, got {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("\"scannedPackages\": {n}")),
        "scan --json envelope should report scannedPackages={n}:\n{stdout}"
    );
    assert!(
        stdout.contains("\"status\": \"success\""),
        "scan --json envelope should report status=success:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers packages in a fake global cache layout.
#[test]
#[ignore = "experimental ecosystem (nuget): not gating CI until the nuget backend is implemented; run with --ignored"]
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
        output.status.success(),
        "scan should exit 0 on a clean discovery, got {:?}:\n{combined}",
        output.status.code()
    );
    // The crawler must NOT fall through to the empty-result message — that is
    // the bug the old substring check ("packages" ⊂ "No packages found.")
    // masked.
    assert!(
        !combined.contains("No packages found") && !combined.contains("No global packages found"),
        "scan failed to discover the fake global cache:\n{combined}"
    );
    // Exactly the two packages we planted (Newtonsoft.Json, System.Text.Json),
    // ALL attributed to NuGet and nothing else — the temp project has no
    // node_modules/site-packages, so every counted package must come from the
    // fake NuGet cache. The contiguous `(2 nuget)` breakdown also rejects a
    // split-ecosystem regression that a separate count + loose substring check
    // would let through.
    assert_all_nuget(&combined, 2);
    // Independently confirm via the JSON envelope (a different output path).
    assert_json_scanned(&project_dir, &nuget_cache, &project_dir, 2);
}

/// Verify that `socket-patch scan` discovers packages in a fake legacy packages/ layout.
#[test]
#[ignore = "experimental ecosystem (nuget): not gating CI until the nuget backend is implemented; run with --ignored"]
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
        output.status.success(),
        "scan should exit 0 on a clean discovery, got {:?}:\n{combined}",
        output.status.code()
    );
    assert!(
        !combined.contains("No packages found") && !combined.contains("No global packages found"),
        "scan failed to discover the legacy packages/ layout:\n{combined}"
    );
    // Exactly the single legacy package we planted (Newtonsoft.Json.13.0.3),
    // attributed to NuGet via the contiguous `(1 nuget)` breakdown.
    assert_all_nuget(&combined, 1);
    // Independently confirm via the JSON envelope (a different output path).
    assert_json_scanned(&project_dir, &packages_dir, &project_dir, 1);
}
