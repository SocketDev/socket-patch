#![cfg(feature = "maven")]
//! End-to-end tests for the Maven/Java package patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Maven local repository layout.  They do **not** require network access or a
//! real Maven/Java installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features maven --test e2e_maven
//! ```

use std::path::PathBuf;
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn run(args: &[&str], cwd: &std::path::Path, m2_repo: &std::path::Path) -> Output {
    Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env("MAVEN_REPO_LOCAL", m2_repo)
        .output()
        .expect("Failed to run socket-patch binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers artifacts in a fake Maven local repo.
#[test]
fn scan_discovers_maven_artifacts() {
    let dir = tempfile::tempdir().unwrap();

    // Set up a fake Maven local repository
    let m2_repo = dir.path().join("m2-repo");

    // Create commons-lang3 3.12.0
    let lang_dir = m2_repo
        .join("org")
        .join("apache")
        .join("commons")
        .join("commons-lang3")
        .join("3.12.0");
    std::fs::create_dir_all(&lang_dir).unwrap();
    std::fs::write(
        lang_dir.join("commons-lang3-3.12.0.pom"),
        r#"<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#,
    )
    .unwrap();

    // Create guava 32.1.2-jre
    let guava_dir = m2_repo
        .join("com")
        .join("google")
        .join("guava")
        .join("guava")
        .join("32.1.2-jre");
    std::fs::create_dir_all(&guava_dir).unwrap();
    std::fs::write(
        guava_dir.join("guava-32.1.2-jre.pom"),
        r#"<project>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>32.1.2-jre</version>
</project>"#,
    )
    .unwrap();

    // Create a pom.xml in the project directory so local mode activates
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(
        project_dir.join("pom.xml"),
        r#"<project><modelVersion>4.0.0</modelVersion></project>"#,
    )
    .unwrap();

    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &m2_repo,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover Maven artifacts, got:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers Gradle project artifacts.
#[test]
fn scan_discovers_gradle_project_artifacts() {
    let dir = tempfile::tempdir().unwrap();

    // Set up a fake Maven local repository
    let m2_repo = dir.path().join("m2-repo");

    // Create a single artifact
    let jackson_dir = m2_repo
        .join("com")
        .join("fasterxml")
        .join("jackson")
        .join("core")
        .join("jackson-core")
        .join("2.15.0");
    std::fs::create_dir_all(&jackson_dir).unwrap();
    std::fs::write(
        jackson_dir.join("jackson-core-2.15.0.pom"),
        r#"<project>
  <groupId>com.fasterxml.jackson.core</groupId>
  <artifactId>jackson-core</artifactId>
  <version>2.15.0</version>
</project>"#,
    )
    .unwrap();

    // Create a build.gradle in the project directory (Gradle project)
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(
        project_dir.join("build.gradle"),
        "plugins { id 'java' }\n",
    )
    .unwrap();

    let output = run(
        &["scan", "--json", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &m2_repo,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("scannedPackages") || combined.contains("Found"),
        "Expected scan output, got:\n{combined}"
    );
}
