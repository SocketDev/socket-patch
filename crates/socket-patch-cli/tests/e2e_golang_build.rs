#![cfg(unix)]
//! Full go-toolchain capstone for the Go `replace`-redirect: proves the patched
//! bytes are actually LINKED by `go build`, and that the read-only
//! `apply --check` redirect auditor detects drift in the committed copy.
//!
//! Go is the one ecosystem that still uses the project-local `replace`-redirect
//! (the module cache is `go.sum`-verified, so in-place patching can't build).
//! There is no longer a build-time guard or `setup` step for Go — the committed
//! `go.mod` `replace` + `.socket/go-patches/` copy is the whole mechanism, and
//! `go build` links it with no extra wiring.
//!
//! Hermetic + offline: a tiny upstream module is served from a local file
//! GOPROXY into a temp GOMODCACHE, so no network and no pre-cached module are
//! needed. Skips when `go`/`zip` aren't installed.

use std::path::Path;
use std::process::Command;

#[path = "common/mod.rs"]
mod common;

use common::{binary, git_sha256, has_command};

const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UPURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";

/// Env for every `go` invocation: hermetic file-proxy + temp cache, sums off.
/// `GOTOOLCHAIN=local` keeps the installed toolchain from trying to download
/// a different one — an ambient `GOTOOLCHAIN` pin would otherwise send every
/// `go` command chasing a toolchain the file proxy can't serve.
fn go_env<'a>(modcache: &'a str, proxy_url: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("GOMODCACHE", modcache),
        ("GOPROXY", proxy_url),
        ("GOSUMDB", "off"),
        ("GOFLAGS", "-mod=mod"),
        ("GOTOOLCHAIN", "local"),
    ]
}

/// Run socket-patch with ambient `SOCKET_*` scrubbed + the fixture GOMODCACHE
/// (the go crawler resolves installed modules through it). Every global flag
/// is env-backed (`SOCKET_DRY_RUN`, `SOCKET_GLOBAL`, `SOCKET_MANIFEST_PATH`,
/// …), so an unscrubbed ambient value would silently reconfigure `apply` /
/// `--check` out from under the assertions.
fn run_socket(cwd: &Path, args: &[&str], modcache: &Path) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") && k.to_string_lossy() != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&k);
        }
    }
    cmd.env("GOMODCACHE", modcache);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn go(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run go")
}

/// Build the upstream module into a file-proxy and `go mod download` it into a
/// temp GOMODCACHE. Returns (consumer_dir, modcache, proxy_url).
fn stage(tmp: &Path) -> (std::path::PathBuf, std::path::PathBuf, String) {
    // Staging dir holding `<mod>@<ver>/` for zipping.
    let stage = tmp.join("stage").join(format!("{UMOD}@{UVER}"));
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("go.mod"), format!("module {UMOD}\n\ngo 1.21\n")).unwrap();
    std::fs::write(stage.join("lib.go"), PRISTINE_LIB).unwrap();

    // File-proxy layout: proxy/<mod>/@v/<ver>.{info,mod,zip}.
    let pxv = tmp.join("proxy").join(UMOD).join("@v");
    std::fs::create_dir_all(&pxv).unwrap();
    std::fs::write(
        pxv.join(format!("{UVER}.info")),
        format!("{{\"Version\":\"{UVER}\"}}"),
    )
    .unwrap();
    std::fs::write(
        pxv.join(format!("{UVER}.mod")),
        format!("module {UMOD}\n\ngo 1.21\n"),
    )
    .unwrap();
    let zip_out = pxv.join(format!("{UVER}.zip"));
    let zip_status = Command::new("zip")
        .args([
            "-q",
            "-r",
            zip_out.to_str().unwrap(),
            &format!("{UMOD}@{UVER}"),
        ])
        .current_dir(tmp.join("stage"))
        .status()
        .expect("run zip");
    assert!(zip_status.success(), "zip failed");

    let modcache = tmp.join("modcache");
    std::fs::create_dir_all(&modcache).unwrap();
    let proxy_url = format!("file://{}", tmp.join("proxy").display());

    // Consumer module that calls the patched symbol.
    let consumer = tmp.join("consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("go.mod"),
        format!("module example.com/consumer\n\ngo 1.21\n\nrequire {UMOD} {UVER}\n"),
    )
    .unwrap();
    std::fs::write(
        consumer.join("main.go"),
        format!(
            "package main\n\nimport (\n\t\"fmt\"\n\t\"{UMOD}\"\n)\n\nfunc main() {{ fmt.Println(\"OUT:\", upstream.Greeting()) }}\n"
        ),
    )
    .unwrap();

    let env = go_env(modcache.to_str().unwrap(), &proxy_url);
    let dl = go(
        &consumer,
        &["mod", "download", &format!("{UMOD}@{UVER}")],
        &env,
    );
    assert!(
        dl.status.success(),
        "go mod download failed: {}",
        String::from_utf8_lossy(&dl.stderr)
    );

    (consumer, modcache, proxy_url)
}

/// Hand-build the patch manifest + blob (apply will read these offline).
fn write_patch(consumer: &Path) {
    let socket = consumer.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let before = git_sha256(PRISTINE_LIB.as_bytes());
    let after = git_sha256(PATCHED_LIB.as_bytes());
    let manifest = format!(
        "{{\"patches\":{{\"{UPURL}\":{{\"uuid\":\"u\",\"exportedAt\":\"t\",\"files\":{{\"lib.go\":{{\"beforeHash\":\"{before}\",\"afterHash\":\"{after}\"}}}},\"vulnerabilities\":{{}},\"description\":\"\",\"license\":\"\",\"tier\":\"\"}}}}}}"
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED_LIB).unwrap();
}

fn chmod_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    for e in walkdir(dir) {
        let _ = std::fs::set_permissions(&e, std::fs::Permissions::from_mode(0o755));
    }
}
fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![dir.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[test]
fn go_build_links_patch_via_replace_redirect() {
    if !has_command("go") || !has_command("zip") {
        eprintln!("skipping e2e_golang_build: `go`/`zip` not installed");
        return;
    }
    // RED guards for the hermeticity pins: bake the hostile ambient values in
    // so this suite fails deterministically if either leak returns.
    // `GOTOOLCHAIN` must lose to go_env's `local` pin (or every `go` command
    // chases a nonexistent toolchain through the file proxy); `SOCKET_DRY_RUN`
    // must be scrubbed by `run_socket` (or every apply is a no-op that still
    // exits 0 and the patched-symbol assert sees PRISTINE).
    std::env::set_var("GOTOOLCHAIN", "go1.99.99");
    std::env::set_var("SOCKET_DRY_RUN", "true");
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let cs = consumer.to_str().unwrap();
    let mc = modcache.to_str().unwrap();
    let goenv = go_env(mc, &proxy_url);

    // Baseline build links PRISTINE.
    let base = go(&consumer, &["run", "."], &goenv);
    assert!(
        base.status.success(),
        "baseline run failed: {}",
        String::from_utf8_lossy(&base.stderr)
    );
    assert!(String::from_utf8_lossy(&base.stdout).contains("OUT: PRISTINE"));

    // Patch + apply (socket-patch reads only the cache; no `go`). This writes the
    // project-local copy under `.socket/go-patches/` and the `go.mod` `replace`.
    write_patch(&consumer);
    let (code, so, se) = run_socket(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "apply failed.\n{so}\n{se}");

    // The patched bytes are now LINKED by `go build` via the `replace` redirect.
    let patched = go(&consumer, &["run", "."], &goenv);
    assert!(
        patched.status.success(),
        "patched run failed: {}",
        String::from_utf8_lossy(&patched.stderr)
    );
    assert!(
        String::from_utf8_lossy(&patched.stdout).contains("OUT: PATCHED"),
        "patched symbol not linked: {}",
        String::from_utf8_lossy(&patched.stdout)
    );

    // `apply --check` (read-only redirect auditor) reports the committed
    // redirect as in sync.
    let (code, _so, _se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "apply --check should be in sync after apply");

    // Corrupt the committed copy → `apply --check` must detect drift (exit !=0).
    let copy_file = consumer
        .join(".socket/go-patches/example.com")
        .join(format!("upstream@{UVER}"))
        .join("lib.go");
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&copy_file, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::write(
        &copy_file,
        "package upstream\n\nfunc Greeting() string { return \"DRIFT\" }\n",
    )
    .unwrap();
    let (code, _so, _se) = run_socket(
        &consumer,
        &["apply", "--check", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_ne!(
        code, 0,
        "apply --check must detect drift in the committed copy"
    );

    // A fresh `apply` re-materialises the copy and `go build` links PATCHED again.
    let (code, _so, _se) = run_socket(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "re-apply should heal the drifted copy");
    let healed = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&healed.stdout).contains("OUT: PATCHED"),
        "re-apply should restore the patched bytes: {}",
        String::from_utf8_lossy(&healed.stdout)
    );

    // Best-effort: relax perms so the temp cache cleans up.
    chmod_writable(tmp.path());
}
