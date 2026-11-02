//! Container plumbing shared by every `docker_e2e_*` suite. Include it with
//! `#[path = "docker_common/mod.rs"] mod docker_common;` (suites that also
//! include `docker_vendor_common` need both: that module builds on this one).
//!
//! `#![allow(dead_code)]`: each suite uses a different subset.

#![allow(dead_code)]

use std::process::{Command, Output};

/// Docker args that shadow the image's baked-in socket-patch. With
/// `SOCKET_PATCH_DOCKER_BIN` set, that host binary is mounted (a local Linux
/// build). Otherwise the CI coverage-docker job sets `SOCKET_PATCH_COV_BIN`
/// (an llvm-cov-instrumented binary) and `SOCKET_PATCH_COV_PROFRAW_DIR` (where
/// the in-container profraws land). Locally all are unset and this is empty.
pub fn cov_docker_args() -> Vec<String> {
    if let Ok(bin) = std::env::var("SOCKET_PATCH_DOCKER_BIN") {
        return vec!["-v".into(), format!("{bin}:/usr/local/bin/socket-patch:ro")];
    }
    let (Ok(bin), Ok(dir)) = (
        std::env::var("SOCKET_PATCH_COV_BIN"),
        std::env::var("SOCKET_PATCH_COV_PROFRAW_DIR"),
    ) else {
        return Vec::new();
    };
    vec![
        "-v".into(),
        format!("{bin}:/usr/local/bin/socket-patch:ro"),
        "-v".into(),
        format!("{dir}:/coverage"),
        "-e".into(),
        "LLVM_PROFILE_FILE=/coverage/docker-e2e-%p-%14m.profraw".into(),
    ]
}

/// Returns `true` when the test should skip: `docker` missing from PATH or
/// `image` not built. Prints a skip notice, because Rust integration tests
/// have no native "skipped" outcome and the test then reports `ok`. Build
/// locally with `docker build -f tests/docker/Dockerfile.base -t
/// socket-patch-test-base:latest .`, then `docker build -f
/// tests/docker/Dockerfile.<eco> -t socket-patch-test-<eco>:latest .`.
///
/// With `SOCKET_PATCH_DOCKER_E2E_REQUIRED=1` (a CI job that built the image
/// itself) a missing docker or image fails the test instead, so a tag
/// mismatch cannot pass the job with zero assertions.
#[must_use]
pub fn skip_if_no_image(image: &str) -> bool {
    skip_or_require_image(
        image,
        std::env::var("SOCKET_PATCH_DOCKER_E2E_REQUIRED").is_ok_and(|v| v == "1"),
    )
}

/// [`skip_if_no_image`] with the required switch passed in.
#[must_use]
pub fn skip_or_require_image(image: &str, required: bool) -> bool {
    let reason = match Command::new("docker")
        .args(["image", "inspect", image])
        .output()
    {
        Err(_) => "`docker` not on PATH".to_string(),
        Ok(out) if !out.status.success() => format!("docker image `{image}` not present"),
        Ok(_) => return false,
    };
    assert!(
        !required,
        "{reason}; SOCKET_PATCH_DOCKER_E2E_REQUIRED=1 forbids skipping"
    );
    eprintln!("skipping: {reason}");
    true
}

/// Run `script` (bash) in a throwaway `image` container that can reach a
/// host mock server at `host.docker.internal`.
pub fn run_container(image: &str, script: &str) -> Output {
    Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-i",
        ])
        .args(cov_docker_args())
        .args([image, "bash", "-c", script])
        .output()
        .expect("docker run")
}

/// Host-side oracle over the VEX document the container printed between
/// `===VEX DOC BEGIN===` and `===VEX DOC END===` (the agent suites keep the
/// workspace inside the container, so the doc comes from captured stdout).
/// Asserts exactly one `not_affected` statement for `ghsa` on the
/// `subcomponent_purl`, with a PLAIN impact statement: no `(vendored)` or
/// `(redirected)` marker, which is what distinguishes agent provenance.
pub fn assert_vex_agent_attested(stdout: &str, subcomponent_purl: &str, ghsa: &str) {
    const BEGIN: &str = "===VEX DOC BEGIN===";
    const END: &str = "===VEX DOC END===";
    let start = stdout
        .find(BEGIN)
        .unwrap_or_else(|| panic!("VEX DOC BEGIN marker missing from stdout:\n{stdout}"))
        + BEGIN.len();
    let stop = stdout[start..]
        .find(END)
        .unwrap_or_else(|| panic!("VEX DOC END marker missing from stdout:\n{stdout}"))
        + start;
    let doc: serde_json::Value = serde_json::from_str(stdout[start..stop].trim())
        .expect("emitted VEX document must be valid JSON");
    let stmts = doc["statements"]
        .as_array()
        .expect("VEX document must have a statements array");
    assert_eq!(stmts.len(), 1, "exactly one VEX statement expected: {doc}");
    let st = &stmts[0];
    assert_eq!(st["vulnerability"]["name"], ghsa, "attested GHSA mismatch");
    assert_eq!(st["status"], "not_affected");
    assert_eq!(
        st["products"][0]["subcomponents"][0]["@id"], subcomponent_purl,
        "subcomponent must be the patched package purl"
    );
    let impact = st["impact_statement"]
        .as_str()
        .expect("statement must carry an impact_statement");
    assert!(
        impact.contains("Patched via Socket patch")
            && !impact.contains("(vendored)")
            && !impact.contains("(redirected)"),
        "agent-mode attestation must carry a PLAIN impact statement (no vendored/redirected marker): {impact}"
    );
}
