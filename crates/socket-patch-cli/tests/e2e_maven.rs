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
        // Point the crawler at the fake local repo.
        .env("MAVEN_REPO_LOCAL", m2_repo)
        // The Maven crawler is gated behind a runtime opt-in
        // (`maven_runtime_enabled` in ecosystem_dispatch.rs); without
        // this the crawl short-circuits to zero packages and the scan
        // prints "No packages found." These tests are named for Maven
        // *discovery*, so they must enable the real crawl path — otherwise
        // they only ever exercise the disabled stub and pass vacuously.
        .env("SOCKET_EXPERIMENTAL_MAVEN", "1")
        // Keep the run hermetic: no ambient token, no inherited repo path.
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("M2_HOME")
        .output()
        .expect("Failed to run socket-patch binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers artifacts in a fake Maven local repo.
#[test]
#[ignore = "experimental ecosystem (maven): not gating CI until the maven backend is implemented; run with --ignored"]
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

    // --- Human-readable run: proves the count AND the ecosystem ----------
    // The crawl summary line ("Found N packages (N maven)") is the
    // strongest discovery oracle: it pins both how many artifacts were
    // found and that they were attributed to the Maven ecosystem. We
    // created exactly two artifacts (commons-lang3, guava), so the
    // expected line is derived independently from the fixture, not copied
    // from the implementation's output.
    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &m2_repo,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "scan should exit 0; got {:?}\n{combined}",
        output.status.code()
    );
    // Must NOT have hit the empty-crawl path — that line *also* contains
    // the word "packages", which is exactly what let the old assertion
    // pass when discovery was disabled.
    assert!(
        !combined.contains("No packages found"),
        "scan reported zero packages — Maven discovery did not run:\n{combined}"
    );
    assert!(
        combined.contains("Found 2 packages"),
        "expected exactly 2 discovered packages, got:\n{combined}"
    );
    // Anchor the full parenthesized breakdown: `(2 maven)` forces Maven to
    // be the *sole* ecosystem with exactly 2 artifacts. A loose `2 maven`
    // substring would also match `12 maven` or `(2 maven, 1 npm)`.
    assert!(
        combined.contains("(2 maven)"),
        "expected all 2 artifacts attributed solely to the Maven ecosystem, got:\n{combined}"
    );

    // --- JSON run: locks the stable `scannedPackages` contract field -----
    let json_out = run(
        &["scan", "--json", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &m2_repo,
    );
    let json = String::from_utf8_lossy(&json_out.stdout);
    assert!(json_out.status.success(), "scan --json should exit 0:\n{json}");
    // Anchor on the trailing comma so this matches *exactly* 2, not any
    // number that merely starts with "2" (20, 25, 200, ...). Without the
    // comma, `contains("scannedPackages\": 2")` is satisfied by an
    // over-counting crawler reporting e.g. 25, masking a discovery bug.
    assert!(
        json.contains("\"scannedPackages\": 2,"),
        "expected scannedPackages == exactly 2 in JSON output, got:\n{json}"
    );
    assert!(
        json.contains("\"status\": \"success\""),
        "expected status == success in JSON output, got:\n{json}"
    );
}

/// Verify that `socket-patch scan` discovers Gradle project artifacts.
#[test]
#[ignore = "experimental ecosystem (maven): not gating CI until the maven backend is implemented; run with --ignored"]
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

    // --- JSON run: the `scannedPackages` count is the contract field -----
    // A single artifact lives in the repo. We assert the *value* (1), not
    // merely the presence of the key — the old `contains("scannedPackages")`
    // check passed even when the count was 0 (i.e. nothing discovered),
    // since the field is always emitted.
    let output = run(
        &["scan", "--json", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &m2_repo,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "scan --json should exit 0; got {:?}\n{stdout}{stderr}"
        , output.status.code()
    );
    // Anchor on the trailing comma: a bare `contains("scannedPackages\": 1")`
    // is also satisfied by 10..=19, 100, etc., so an over-counting crawler
    // would pass while claiming to find "1". The comma pins it to exactly 1.
    assert!(
        stdout.contains("\"scannedPackages\": 1,"),
        "expected exactly 1 artifact discovered via the build.gradle marker, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("\"scannedPackages\": 0,"),
        "scannedPackages was 0 — the Gradle project marker did not activate Maven discovery:\n{stdout}"
    );
    assert!(
        stdout.contains("\"status\": \"success\""),
        "expected status == success, got:\n{stdout}"
    );

    // --- Human run: confirm the artifact is attributed to Maven ----------
    // build.gradle (not pom.xml) is what must trigger local-mode Maven
    // discovery here; the eco summary proves the single package is Maven.
    let human = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &m2_repo,
    );
    let h_combined = format!(
        "{}{}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(
        h_combined.contains("Found 1 packages") && h_combined.contains("(1 maven)"),
        "expected the Gradle project to discover exactly 1 Maven artifact, got:\n{h_combined}"
    );
}
