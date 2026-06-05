#![cfg(all(unix, feature = "golang"))]
//! Full go-toolchain capstone for the Go `replace`-redirect guard: proves the
//! patched bytes are actually LINKED by `go build`, and that the committed guard
//! enforces drift at runtime (`init()`) and self-heals.
//!
//! Hermetic + offline: a tiny upstream module is served from a local file
//! GOPROXY into a temp GOMODCACHE, so no network and no pre-cached module are
//! needed. Skips when `go`/`zip` aren't installed.

use std::path::Path;
use std::process::Command;

#[path = "common/mod.rs"]
mod common;

use common::{binary, git_sha256, has_command, run_with_env};

const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UPURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";

/// Env for every `go` invocation: hermetic file-proxy + temp cache, sums off.
fn go_env<'a>(modcache: &'a str, proxy_url: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("GOMODCACHE", modcache),
        ("GOPROXY", proxy_url),
        ("GOSUMDB", "off"),
        ("GOFLAGS", "-mod=mod"),
    ]
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
    std::fs::write(pxv.join(format!("{UVER}.info")), format!("{{\"Version\":\"{UVER}\"}}")).unwrap();
    std::fs::write(pxv.join(format!("{UVER}.mod")), format!("module {UMOD}\n\ngo 1.21\n")).unwrap();
    let zip_out = pxv.join(format!("{UVER}.zip"));
    let zip_status = Command::new("zip")
        .args(["-q", "-r", zip_out.to_str().unwrap(), &format!("{UMOD}@{UVER}")])
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
    let dl = go(&consumer, &["mod", "download", &format!("{UMOD}@{UVER}")], &env);
    assert!(dl.status.success(), "go mod download failed: {}", String::from_utf8_lossy(&dl.stderr));

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
fn go_build_links_patch_and_guard_enforces_drift() {
    if !has_command("go") || !has_command("zip") {
        eprintln!("skipping e2e_golang_build: `go`/`zip` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let cs = consumer.to_str().unwrap();
    let mc = modcache.to_str().unwrap();
    let goenv = go_env(mc, &proxy_url);
    let bin = binary();
    let bin_s = bin.to_str().unwrap();

    // Baseline build links PRISTINE.
    let base = go(&consumer, &["run", "."], &goenv);
    assert!(base.status.success(), "baseline run failed: {}", String::from_utf8_lossy(&base.stderr));
    assert!(String::from_utf8_lossy(&base.stdout).contains("OUT: PRISTINE"));

    // Patch + apply (socket-patch reads only the cache; no `go`).
    write_patch(&consumer);
    let (code, so, se) = run_with_env(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &[("GOMODCACHE", mc)],
    );
    assert_eq!(code, 0, "apply failed.\n{so}\n{se}");

    // The patched bytes are now LINKED by go build.
    let patched = go(&consumer, &["run", "."], &goenv);
    assert!(patched.status.success(), "patched run failed: {}", String::from_utf8_lossy(&patched.stderr));
    assert!(
        String::from_utf8_lossy(&patched.stdout).contains("OUT: PATCHED"),
        "patched symbol not linked: {}",
        String::from_utf8_lossy(&patched.stdout)
    );

    // ── setup wires the guard; go test (cold) passes in sync ─────────
    let (code, so, se) = run_with_env(
        &consumer,
        &["setup", "--cwd", cs, "--yes"],
        &[("GOMODCACHE", mc), ("SOCKET_PATCH_BIN", bin_s)],
    );
    assert_eq!(code, 0, "setup failed.\n{so}\n{se}");
    assert!(consumer.join("internal/socketpatchguard/guard.go").exists());
    assert!(consumer.join("socket_patch_guard_import.go").exists());

    let test_env: Vec<(&str, &str)> = goenv.iter().cloned().chain([("SOCKET_PATCH_BIN", bin_s)]).collect();
    let t = go(&consumer, &["test", "-count=1", "./..."], &test_env);
    assert!(
        t.status.success(),
        "guard test should pass in sync:\n{}\n{}",
        String::from_utf8_lossy(&t.stdout),
        String::from_utf8_lossy(&t.stderr)
    );

    // ── warm-cache drift: `go test` (NO -count=1) must NOT serve a stale PASS ──
    // Prime the cache with a passing run, then corrupt the copy and run again
    // WITHOUT -count=1. The guard reads the patch state in-process, so the test
    // cache must re-run the gate and FAIL (this is the test-cache-masking fix).
    let warm = consumer.join(".socket/go-patches/example.com").join(format!("upstream@{UVER}")).join("lib.go");
    let _ = go(&consumer, &["test", "./internal/socketpatchguard/"], &test_env); // prime cache (no -count=1)
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&warm, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::write(&warm, "package upstream\n\nfunc Greeting() string { return \"WARM-DRIFT\" }\n").unwrap();
    let warm_test = go(&consumer, &["test", "./internal/socketpatchguard/"], &test_env); // NO -count=1
    assert!(
        !warm_test.status.success(),
        "WARM-CACHE go test must catch drift (not serve a cached PASS):\n{}\n{}",
        String::from_utf8_lossy(&warm_test.stdout),
        String::from_utf8_lossy(&warm_test.stderr)
    );
    // (heal happened during that run; restore is verified by the -count=1 block below)

    // ── drift: corrupt the committed copy → guard test fails closed ──
    let copy_file = consumer
        .join(".socket/go-patches/example.com")
        .join(format!("upstream@{UVER}"))
        .join("lib.go");
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&copy_file, std::fs::Permissions::from_mode(0o644));
    }
    std::fs::write(&copy_file, "package upstream\n\nfunc Greeting() string { return \"DRIFT\" }\n").unwrap();

    let t2 = go(&consumer, &["test", "-count=1", "./internal/socketpatchguard/"], &test_env);
    assert!(
        !t2.status.success(),
        "guard test must FAIL on drift (it self-heals + fails):\n{}\n{}",
        String::from_utf8_lossy(&t2.stdout),
        String::from_utf8_lossy(&t2.stderr)
    );

    // The heal restored the patched bytes; a re-run passes.
    let t3 = go(&consumer, &["test", "-count=1", "./internal/socketpatchguard/"], &test_env);
    assert!(
        t3.status.success(),
        "guard test should pass after self-heal:\n{}\n{}",
        String::from_utf8_lossy(&t3.stdout),
        String::from_utf8_lossy(&t3.stderr)
    );

    // Best-effort: relax perms so the temp cache cleans up.
    chmod_writable(tmp.path());
}

#[test]
fn guard_is_noop_outside_module_tree() {
    if !has_command("go") || !has_command("zip") {
        eprintln!("skipping e2e_golang_build: `go`/`zip` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy_url) = stage(tmp.path());
    let cs = consumer.to_str().unwrap();
    let mc = modcache.to_str().unwrap();
    let goenv = go_env(mc, &proxy_url);
    let bin = binary();

    // Patch + apply + wire the guard, then build a real binary.
    write_patch(&consumer);
    assert_eq!(
        run_with_env(&consumer, &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs], &[("GOMODCACHE", mc)]).0,
        0
    );
    run_with_env(
        &consumer,
        &["setup", "--cwd", cs, "--yes"],
        &[("GOMODCACHE", mc), ("SOCKET_PATCH_BIN", bin.to_str().unwrap())],
    );
    let build = go(&consumer, &["build", "-o", "app", "."], &goenv);
    assert!(build.status.success(), "go build failed: {}", String::from_utf8_lossy(&build.stderr));

    // Copy the binary OUT of the module tree (simulating a shipped binary with
    // no .socket/ alongside it) and run it from a dir with no go.mod ancestor.
    let outside = tmp.path().join("shipped");
    std::fs::create_dir_all(&outside).unwrap();
    let app = outside.join("app");
    std::fs::copy(consumer.join("app"), &app).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&app, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // The guard's init() must be a SILENT no-op here: the binary runs normally
    // even though socket-patch isn't on PATH and there is no .socket/manifest.
    let out = Command::new(&app)
        .current_dir(&outside)
        .env_remove("SOCKET_PATCH_BIN")
        .env("PATH", "/usr/bin:/bin") // ensure no socket-patch on PATH
        .output()
        .expect("run shipped binary");
    assert!(
        out.status.success(),
        "shipped binary outside the module tree must NOT be bricked by the guard:\nstdout:{}\nstderr:{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("OUT: PATCHED"),
        "the binary should still run its (patched) code: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    chmod_writable(tmp.path());
}
