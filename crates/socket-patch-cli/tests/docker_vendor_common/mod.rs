//! Shared harness for the Docker build-proof `vendor` capstone suites
//! (`docker_e2e_vendor_<eco>.rs`).
//!
//! Unlike the `docker_e2e_<eco>.rs` scan→apply suites (one self-contained
//! container run against a host wiremock), the vendor capstones drive a
//! MULTI-STAGE lifecycle where state must survive between containers:
//!
//!   stage 1 (networked):    real package-manager fixture install + staged
//!                           marker patch + `socket-patch vendor` + wiring
//!                           asserts
//!   stage 2 (--network none): fresh-checkout copy of ONLY the committable
//!                           files + strictest native install with cold
//!                           caches → patched bytes prove out
//!   stage 3 (offline-safe): idempotent re-vendor / `--revert` / re-vendor
//!
//! So instead of a throwaway container filesystem, every stage runs with the
//! same host tempdir bind-mounted at `/workspace`. The socket-patch binary
//! itself is the one BAKED INTO the image at `/usr/local/bin/socket-patch`
//! by `tests/docker/Dockerfile.base` (optionally shadowed by the
//! coverage-instrumented binary via `cov_docker_args`, same hook as the
//! other docker suites).
//!
//! Each test file pulls this in with
//! `#[path = "docker_vendor_common/mod.rs"] mod docker_vendor_common;`.
//!
//! `#![allow(dead_code)]`: each suite uses a different subset.

#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

/// Coverage instrumentation hook — identical contract to
/// `docker_e2e_pypi.rs::cov_docker_args`. The CI coverage-docker job sets
/// `SOCKET_PATCH_COV_BIN` (host path to an llvm-cov-instrumented
/// socket-patch) + `SOCKET_PATCH_COV_PROFRAW_DIR` (host dir for in-container
/// *.profraw output); locally both are unset and this is empty.
pub fn cov_docker_args() -> Vec<String> {
    let Ok(bin) = std::env::var("SOCKET_PATCH_COV_BIN") else {
        return Vec::new();
    };
    let Ok(dir) = std::env::var("SOCKET_PATCH_COV_PROFRAW_DIR") else {
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
/// the per-ecosystem image not built. Prints a skip notice — Rust
/// integration tests have no native "skipped" outcome, so the test then
/// reports `ok`. Build locally with
/// `docker build -f tests/docker/Dockerfile.<eco> -t <image> .`
/// (after `Dockerfile.base` → `socket-patch-test-base:latest`).
#[must_use]
pub fn skip_if_no_image(image: &str) -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", image])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `{image}` not present");
        return true;
    }
    false
}

fn docker_run(image: &str, host_dir: &Path, script: &str, extra: &[&str]) -> Output {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "-i"]);
    cmd.args(extra);
    cmd.args([
        "-v",
        &format!("{}:/workspace", host_dir.display()),
        "-w",
        "/workspace",
    ]);
    cmd.args(cov_docker_args());
    cmd.args([image, "bash", "-c", script]);
    cmd.output().expect("docker run")
}

/// Run `script` (bash) inside `image` with `host_dir` bind-mounted at
/// `/workspace` (the working dir). Network is the docker default — use this
/// for fixture-install stages that need the real registry.
pub fn run_in_image(image: &str, host_dir: &Path, script: &str) -> Output {
    docker_run(image, host_dir, script, &[])
}

/// `run_in_image` + `--network none`: the cold-cache fresh-checkout install
/// stage. Any code path that still wants the registry fails loudly in here.
pub fn run_in_image_network_none(image: &str, host_dir: &Path, script: &str) -> Output {
    docker_run(image, host_dir, script, &["--network", "none"])
}

/// Anti-vacuity stage gate: the container run must have exited 0 AND echoed
/// every `===<name> VERIFIED===` marker to stdout. Each marker sits directly
/// behind that stage's in-container asserts, so a script that short-circuits
/// (early `exit 0`, skipped block, copy-pasted tail) cannot pass — markers
/// it never reached are missing. Panics with full stdout+stderr context.
pub fn assert_stage_markers(label: &str, out: &Output, markers: &[&str]) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "{label}: container exited {:?}\nstdout=\n{stdout}\nstderr=\n{stderr}",
        out.status.code()
    );
    for m in markers {
        let gate = format!("==={m} VERIFIED===");
        assert!(
            stdout.contains(&gate),
            "{label}: missing stage gate `{gate}`\nstdout=\n{stdout}\nstderr=\n{stderr}"
        );
    }
}

/// Bash prelude shared by every stage script: strict-ish mode (no `-e`; the
/// scripts check exit codes explicitly so failures carry diagnostics), a
/// `fail` helper, and `git_blob_sha <file>` — the Git-blob SHA-256
/// (`sha256("blob <len>\0" ++ bytes)`) socket-patch records in manifests,
/// computed entirely in-container so before/after hashes come from the REAL
/// installed bytes.
pub fn bash_prelude() -> &'static str {
    r#"set -u
fail() { echo "FAIL: $*" >&2; exit 1; }
git_blob_sha() {
  # git blob sha256: sha256("blob <len>\0" + bytes)
  local f="$1"
  local len
  len=$(wc -c < "$f" | tr -d '[:space:]')
  { printf 'blob %s\0' "$len"; cat "$f"; } | sha256sum | cut -d' ' -f1
}
"#
}

/// Bash snippet defining `stage_patch <purl> <uuid> <file_key> <before_file>
/// <after_file> [<ghsa> <cve>]`: writes `.socket/manifest.json` + the
/// after-hash blob into `.socket/blobs/` (relative to the CURRENT directory —
/// call from the project root) so `socket-patch vendor --offline` runs with
/// zero network. The optional trailing `<ghsa> <cve>` pair records one
/// high-severity vulnerability so a generated VEX document has a statement
/// to emit; omitted, `vulnerabilities` stays empty. Shape mirrors
/// `e2e_vendor_npm_build.rs::stage_patch` / `stage_patch_with_vuln`.
/// Requires [`bash_prelude`] (uses `git_blob_sha`).
pub fn stage_patch_fn() -> &'static str {
    r#"stage_patch() {
  local purl="$1" uuid="$2" file_key="$3" before_file="$4" after_file="$5"
  local ghsa="${6:-}" cve="${7:-}"
  local before_hash after_hash vulns
  before_hash=$(git_blob_sha "$before_file") || fail "hashing $before_file"
  after_hash=$(git_blob_sha "$after_file") || fail "hashing $after_file"
  vulns="{}"
  if [ -n "$ghsa" ]; then
    vulns="{\"$ghsa\": {\"cves\": [\"$cve\"], \"summary\": \"capstone vex vuln\", \"severity\": \"high\", \"description\": \"d\"}}"
  fi
  mkdir -p .socket/blobs || fail "mkdir .socket/blobs"
  cp "$after_file" ".socket/blobs/$after_hash" || fail "staging blob"
  cat > .socket/manifest.json <<MANIFEST_EOF
{
  "patches": {
    "$purl": {
      "uuid": "$uuid",
      "exportedAt": "2026-01-01T00:00:00Z",
      "files": {
        "$file_key": {
          "beforeHash": "$before_hash",
          "afterHash": "$after_hash"
        }
      },
      "vulnerabilities": $vulns,
      "description": "docker vendor capstone marker patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}
MANIFEST_EOF
}
"#
}

/// Bash snippet defining envelope helpers for `socket-patch --json` output
/// files: `assert_json_field <file> <fixed-string>` (grep -F) and
/// `assert_summary <file> <key> <count>` (word-boundary so `"applied": 1`
/// can't be satisfied by `"applied": 10`). Requires [`bash_prelude`].
pub fn json_assert_fns() -> &'static str {
    r#"assert_json_field() {
  grep -qF "$2" "$1" || { echo "---- $1 ----" >&2; cat "$1" >&2; fail "$1 missing [$2]"; }
}
assert_summary() {
  grep -qE "\"$2\": $3([^0-9]|\$)" "$1" || {
    echo "---- $1 ----" >&2; cat "$1" >&2; fail "$1 does not report summary.$2 == $3"; }
}
"#
}
