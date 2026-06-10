#![cfg(all(unix, feature = "golang"))]
//! Real-go capstone e2e for `socket-patch vendor` — the committability proof
//! for the `go.mod` `replace`-directive vendoring, plus the apply↔vendor
//! interplay (takeover + yield).
//!
//! Hermetic and fully offline (the pattern proven by `e2e_golang_build.rs`):
//! a tiny upstream module is served from a local file GOPROXY into a private
//! GOMODCACHE by the REAL `go mod download`, so no network is ever needed —
//! the fresh-checkout proof then builds with `GOPROXY=off` + an EMPTY
//! GOMODCACHE (directory `replace` targets bypass the module cache, sumdb,
//! and `go.sum` entirely — spike claims 2/3).
//!
//! Skips (println) when `go`/`zip` are missing; everything else is hard.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

const UUID: &str = "3c4d5e6f-7081-4a1b-8c2d-0123456789ab";
const UMOD: &str = "example.com/upstream";
const UVER: &str = "v1.0.0";
const UPURL: &str = "pkg:golang/example.com/upstream@v1.0.0";
const PRISTINE_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PRISTINE\" }\n";
const PATCHED_LIB: &str = "package upstream\n\nfunc Greeting() string { return \"PATCHED\" }\n";

// ── self-contained helpers ────────────────────────────────────────────

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Run socket-patch with `SOCKET_*` scrubbed + the fixture GOMODCACHE (the
/// go crawler resolves installed modules through it).
fn run_socket(cwd: &Path, args: &[&str], modcache: &Path) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("GOMODCACHE", modcache);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Hermetic env for every `go` invocation. `GOTOOLCHAIN=local` keeps the
/// installed toolchain from trying to download a different one.
fn go_env<'a>(modcache: &'a str, proxy: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("GOMODCACHE", modcache),
        ("GOPROXY", proxy),
        ("GOSUMDB", "off"),
        ("GOFLAGS", "-mod=mod"),
        ("GOTOOLCHAIN", "local"),
    ]
}

fn go(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("go");
    cmd.args(args).current_dir(dir);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run go")
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Build the upstream module into a file proxy and `go mod download` it into
/// a private GOMODCACHE. Returns `(consumer, modcache, proxy_url)`.
fn stage(tmp: &Path) -> (PathBuf, PathBuf, String) {
    let stage = tmp.join("stage").join(format!("{UMOD}@{UVER}"));
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::write(stage.join("go.mod"), format!("module {UMOD}\n\ngo 1.21\n")).unwrap();
    std::fs::write(stage.join("lib.go"), PRISTINE_LIB).unwrap();

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
    assert!(
        dl.status.success(),
        "go mod download (file proxy) failed: {}",
        String::from_utf8_lossy(&dl.stderr)
    );
    (consumer, modcache, proxy_url)
}

fn write_patch(consumer: &Path) {
    let socket = consumer.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": { UPURL: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "lib.go": {
                "beforeHash": git_sha256(PRISTINE_LIB.as_bytes()),
                "afterHash": git_sha256(PATCHED_LIB.as_bytes()),
            }},
            "vulnerabilities": {},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        }}
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        socket.join("blobs").join(git_sha256(PATCHED_LIB.as_bytes())),
        PATCHED_LIB,
    )
    .unwrap();
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("--json output is not JSON: {e}\nstdout:\n{stdout}"))
}

fn find_event<'a>(
    env: &'a serde_json::Value,
    action: &str,
    error_code: &str,
) -> Option<&'a serde_json::Value> {
    env["events"]
        .as_array()?
        .iter()
        .find(|e| e["action"] == action && e["errorCode"] == error_code)
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// Best-effort: relax perms so tempdir cleanup can remove the (read-only)
/// module-cache extraction.
fn chmod_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                chmod_writable(&p);
            } else {
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644));
            }
        }
    }
}

// ── capstone 1: vendor → build → fresh checkout → revert ─────────────

#[test]
fn go_vendor_fresh_checkout_offline_build_and_revert() {
    if !has_command("go") || !has_command("zip") {
        println!("SKIP e2e_vendor_golang_build: `go`/`zip` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy) = stage(tmp.path());
    let goenv = go_env(modcache.to_str().unwrap(), &proxy);

    // Baseline links PRISTINE.
    let base = go(&consumer, &["run", "."], &goenv);
    assert!(
        base.status.success(),
        "baseline go run failed: {}",
        String::from_utf8_lossy(&base.stderr)
    );
    assert!(String::from_utf8_lossy(&base.stdout).contains("OUT: PRISTINE"));

    // Snapshot the committed manifests AFTER the baseline run settles them.
    let gomod_path = consumer.join("go.mod");
    let gomod_before = std::fs::read(&gomod_path).unwrap();

    write_patch(&consumer);
    let (code, stdout, stderr) = run_socket(
        &consumer,
        &["vendor", "--json", "--offline", "--cwd", consumer.to_str().unwrap()],
        &modcache,
    );
    assert_eq!(code, 0, "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(env["summary"]["failed"], 0, "no failures: {env}");
    // NOTE: summary.applied / the event action are pinned in the
    // `go_vendor_reports_applied_event` below — successful golang vendors
    // are currently misreported as skipped/`vendored` (shared
    // result_to_event bug). The wiring/build proofs here are unaffected.

    // The replace directive points at the uuid copy, with the mandatory
    // `./` prefix (a bare path fails go.mod parsing — spike claim 6).
    let expected_replace = format!(
        "replace {UMOD} {UVER} => ./.socket/vendor/golang/{UUID}/{UMOD}@{UVER}"
    );
    let gomod = std::fs::read_to_string(&gomod_path).unwrap();
    assert!(
        gomod.lines().any(|l| l.trim() == expected_replace),
        "go.mod must carry the vendor replace directive.\nwant: {expected_replace}\ngot:\n{gomod}"
    );

    // Patched copy + marker + ledger on disk; pristine cache untouched.
    let copy_dir = consumer.join(format!(".socket/vendor/golang/{UUID}/{UMOD}@{UVER}"));
    assert_eq!(
        std::fs::read(copy_dir.join("lib.go")).unwrap(),
        PATCHED_LIB.as_bytes(),
        "vendored copy must hold the patched bytes"
    );
    assert!(
        consumer
            .join(format!(".socket/vendor/golang/{UUID}/socket-patch.vendor.json"))
            .is_file(),
        "informational vendor marker missing"
    );
    assert!(consumer.join(".socket/vendor/state.json").is_file());
    assert_eq!(
        std::fs::read(modcache.join(format!("{UMOD}@{UVER}")).join("lib.go")).unwrap(),
        PRISTINE_LIB.as_bytes(),
        "module cache must stay pristine"
    );

    // In-place build links PATCHED.
    let patched_run = go(&consumer, &["run", "."], &goenv);
    assert!(
        patched_run.status.success(),
        "post-vendor go run failed: {}",
        String::from_utf8_lossy(&patched_run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&patched_run.stdout).contains("OUT: PATCHED"),
        "vendored bytes must be linked: {}",
        String::from_utf8_lossy(&patched_run.stdout)
    );

    // FRESH-CHECKOUT PROOF: go.mod + go.sum + main.go + .socket/ only, EMPTY
    // GOMODCACHE, GOPROXY=off (spike claim 2: directory replaces bypass the
    // cache and sumdb entirely).
    let fresh = tmp.path().join("fresh");
    std::fs::create_dir_all(&fresh).unwrap();
    std::fs::copy(&gomod_path, fresh.join("go.mod")).unwrap();
    if consumer.join("go.sum").exists() {
        std::fs::copy(consumer.join("go.sum"), fresh.join("go.sum")).unwrap();
    }
    std::fs::copy(consumer.join("main.go"), fresh.join("main.go")).unwrap();
    copy_dir_recursive(&consumer.join(".socket"), &fresh.join(".socket"));

    let fresh_mc = tmp.path().join("fresh-modcache");
    std::fs::create_dir_all(&fresh_mc).unwrap();
    let offline_env = go_env(fresh_mc.to_str().unwrap(), "off");
    let build = go(&fresh, &["build", "-o", "app", "."], &offline_env);
    assert!(
        build.status.success(),
        "fresh-checkout `go build` (GOPROXY=off, empty GOMODCACHE) must succeed.\nstderr:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let app = Command::new(fresh.join("app")).output().expect("run fresh app");
    assert!(
        String::from_utf8_lossy(&app.stdout).contains("OUT: PATCHED"),
        "fresh build must link the PATCHED module: {}",
        String::from_utf8_lossy(&app.stdout)
    );
    // The total-offline guarantee: the empty GOMODCACHE stayed empty.
    assert_eq!(
        std::fs::read_dir(&fresh_mc).unwrap().count(),
        0,
        "directory-replaced modules must write NOTHING to the module cache"
    );

    // REVERT PROOF.
    let (code, stdout, stderr) = run_socket(
        &consumer,
        &["vendor", "--revert", "--json", "--cwd", consumer.to_str().unwrap()],
        &modcache,
    );
    assert_eq!(code, 0, "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let renv = parse_envelope(&stdout);
    assert_eq!(renv["status"], "success", "revert envelope: {renv}");
    assert_eq!(renv["summary"]["removed"], 1, "one entry reverted: {renv}");
    assert_eq!(
        std::fs::read(&gomod_path).unwrap(),
        gomod_before,
        "revert must restore go.mod byte-identical to the pre-vendor snapshot"
    );
    assert!(
        !consumer.join(".socket/vendor").exists(),
        ".socket/vendor must be fully removed after revert"
    );
    // Reverted project builds PRISTINE again from the cache.
    let back = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&back.stdout).contains("OUT: PRISTINE"),
        "reverted project must link the pristine module: {}",
        String::from_utf8_lossy(&back.stdout)
    );

    chmod_writable(tmp.path());
}

// ── capstone 2: apply ↔ vendor interplay ──────────────────────────────

/// apply-then-vendor (takeover) and vendor-then-apply (yield), plus the
/// documented revert handoff (`takeover_not_restored` → re-run `apply`).
#[test]
fn go_apply_vendor_interplay_takeover_and_yield() {
    if !has_command("go") || !has_command("zip") {
        println!("SKIP e2e_vendor_golang_build: `go`/`zip` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, proxy) = stage(tmp.path());
    let goenv = go_env(modcache.to_str().unwrap(), &proxy);
    let cs = consumer.to_str().unwrap();
    write_patch(&consumer);

    // 1. `apply` first: the project-local go-patches redirect.
    let (code, stdout, stderr) = run_socket(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let go_patches_copy = consumer.join(format!(".socket/go-patches/{UMOD}@{UVER}"));
    assert_eq!(
        std::fs::read(go_patches_copy.join("lib.go")).unwrap(),
        PATCHED_LIB.as_bytes(),
        "apply must materialize the go-patches copy"
    );
    let gomod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    assert!(
        gomod.contains("=> ./.socket/go-patches/"),
        "apply must wire the go-patches replace:\n{gomod}"
    );

    // 2. `vendor` takes the redirect over in one atomic repoint.
    let (code, stdout, stderr) = run_socket(
        &consumer,
        &["vendor", "--json", "--offline", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env = parse_envelope(&stdout);
    assert_eq!(env["status"], "success", "takeover is a success: {env}");
    assert!(
        find_event(&env, "skipped", "vendor_takeover").is_some(),
        "the takeover must be surfaced as a `vendor_takeover` event: {env}"
    );

    let gomod = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    let expected_replace = format!(
        "replace {UMOD} {UVER} => ./.socket/vendor/golang/{UUID}/{UMOD}@{UVER}"
    );
    assert!(
        gomod.lines().any(|l| l.trim() == expected_replace),
        "takeover must repoint the replace at the vendor copy:\n{gomod}"
    );
    assert!(
        !gomod.contains("go-patches"),
        "exactly one socket directive after takeover (no go-patches leftover):\n{gomod}"
    );
    assert!(
        !go_patches_copy.exists(),
        "the stale go-patches module copy must be deleted on takeover"
    );

    // The ledger records the takeover so revert can warn about the handoff.
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(consumer.join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["entries"][UPURL]["tookOverGoPatches"], true,
        "state.json must record tookOverGoPatches: {state}"
    );

    // Still builds PATCHED via the vendor path.
    let run1 = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&run1.stdout).contains("OUT: PATCHED"),
        "vendor path must be linked after takeover: {}",
        String::from_utf8_lossy(&run1.stdout)
    );

    // 3. vendor-then-apply: apply yields ownership (skipped/`vendored`),
    //    never repointing the replace back at go-patches.
    let (code, stdout, stderr) = run_socket(
        &consumer,
        &["apply", "--json", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "apply on a vendored module must exit 0.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let aenv = parse_envelope(&stdout);
    assert_eq!(aenv["status"], "success", "apply envelope: {aenv}");
    let yielded = find_event(&aenv, "skipped", "vendored")
        .unwrap_or_else(|| panic!("apply must skip the vendored purl with errorCode `vendored`: {aenv}"));
    assert_eq!(yielded["purl"], UPURL, "the vendored purl is the one skipped: {aenv}");
    let gomod_after_apply = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    assert!(
        gomod_after_apply.lines().any(|l| l.trim() == expected_replace),
        "apply must leave the vendor replace untouched:\n{gomod_after_apply}"
    );
    assert!(
        !consumer.join(".socket/go-patches").join(format!("{UMOD}@{UVER}")).exists()
            && !gomod_after_apply.contains("go-patches"),
        "apply must not re-create the go-patches redirect for a vendored module"
    );

    // 4. Revert: the taken-over redirect is NOT restored — surfaced via
    //    `takeover_not_restored` — and a fresh `apply` restores it.
    let (code, stdout, stderr) =
        run_socket(&consumer, &["vendor", "--revert", "--json", "--cwd", cs], &modcache);
    assert_eq!(code, 0, "revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let renv = parse_envelope(&stdout);
    assert!(
        find_event(&renv, "skipped", "takeover_not_restored").is_some(),
        "revert must warn that the go-patches redirect was not restored: {renv}"
    );
    let gomod_reverted = std::fs::read_to_string(consumer.join("go.mod")).unwrap();
    assert!(
        !gomod_reverted.contains("replace "),
        "no socket replace directive after revert:\n{gomod_reverted}"
    );
    // Back on the pristine cache until apply is re-run…
    let run2 = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&run2.stdout).contains("OUT: PRISTINE"),
        "reverted module is pristine: {}",
        String::from_utf8_lossy(&run2.stdout)
    );
    // …and `apply` restores the go-patches redirect (the documented handoff).
    let (code, _stdout, _stderr) = run_socket(
        &consumer,
        &["apply", "--offline", "--ecosystems", "golang", "--cwd", cs],
        &modcache,
    );
    assert_eq!(code, 0, "post-revert apply must succeed");
    let run3 = go(&consumer, &["run", "."], &goenv);
    assert!(
        String::from_utf8_lossy(&run3.stdout).contains("OUT: PATCHED"),
        "re-applied go-patches redirect must link PATCHED again: {}",
        String::from_utf8_lossy(&run3.stdout)
    );

    chmod_writable(tmp.path());
}

/// Correct-behavior pin for the vendor envelope: a successful first-time
/// golang vendor must surface as an `applied` event with
/// `summary.applied == 1` (CLI_CONTRACT.md: vendor events are `Applied`
/// (= vendored)). See `cargo_vendor_reports_applied_event` in
/// `e2e_vendor_cargo_build.rs` for the root cause (shared `result_to_event`
/// misroutes results whose package_path is the `.socket/vendor/` copy dir).
#[test]
fn go_vendor_reports_applied_event() {
    if !has_command("go") || !has_command("zip") {
        println!("SKIP: `go`/`zip` not installed");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let (consumer, modcache, _proxy) = stage(tmp.path());
    write_patch(&consumer);

    let (code, stdout, stderr) = run_socket(
        &consumer,
        &["vendor", "--json", "--offline", "--cwd", consumer.to_str().unwrap()],
        &modcache,
    );
    assert_eq!(code, 0, "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let env = parse_envelope(&stdout);
    assert_eq!(
        env["summary"]["applied"], 1,
        "a successful first-time vendor must count as applied: {env}"
    );
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["purl"] == UPURL)
        .unwrap_or_else(|| panic!("expected an event for {UPURL}: {env}"));
    assert_eq!(
        event["action"], "applied",
        "vendor success must be an `applied` event, not skipped/`vendored`: {event}"
    );

    chmod_writable(tmp.path());
}
