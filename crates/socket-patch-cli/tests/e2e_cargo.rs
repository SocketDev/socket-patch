//! End-to-end tests for the Cargo/Rust crate patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Cargo registry layout.  They do **not** require network access or a real
//! Cargo installation: the scan's patch lookup is pinned to an in-test
//! [`wiremock`] public-proxy stand-in via `--proxy-url`. That pinning is
//! load-bearing, not cosmetic — an unreachable API is a hard scan failure (exit 1, `status: "error"`), so an
//! unpinned scan would phone home to the live proxy on every test run and go
//! red whenever the network (or an ambient `SOCKET_*` variable) misbehaved.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_cargo
//! ```

#[path = "common/mod.rs"]
mod common;
use common::{binary, git_sha256};

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Start a mock Socket public proxy answering the scan's `POST /patch/batch`
/// with an empty (no-patch) result, so no scan in this file ever leaves
/// localhost.
async fn start_proxy() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// Run the binary as a blocking subprocess (off the async runtime so the
/// in-test proxy can service its requests concurrently), pinned to `proxy_url`.
///
/// `SOCKET_API_TOKEN` is stripped so the binary deterministically takes the
/// public-proxy path (an ambient token would flip it onto the authenticated
/// API, bypassing `--proxy-url`), and every other variable that could
/// redirect the API elsewhere or disable it is scrubbed so an ambient value
/// can't quietly change what the scan reports.
async fn run(args: &[&str], cwd: &Path, proxy_url: &str) -> Output {
    let mut args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    args.extend(["--proxy-url".to_string(), proxy_url.to_string()]);
    let cwd = cwd.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        Command::new(binary())
            .args(&arg_refs)
            .current_dir(&cwd)
            .env("CARGO_HOME", cwd.join(".cargo"))
            .env_remove("SOCKET_API_TOKEN")
            .env_remove("SOCKET_CLI_API_TOKEN")
            .env_remove("SOCKET_API_URL")
            .env_remove("SOCKET_OFFLINE")
            .env_remove("SOCKET_PROXY_URL")
            .env_remove("SOCKET_BATCH_SIZE")
            .output()
            .expect("Failed to run socket-patch binary")
    })
    .await
    .expect("socket-patch subprocess task panicked")
}

/// Run `socket-patch scan --json ...`, assert the process succeeded, and
/// return the parsed JSON envelope from stdout.
///
/// Parsing (rather than substring matching) means a malformed or missing
/// envelope fails the test loudly instead of slipping past a `.contains()`
/// check. The package *count* is derived from the local crawl; the patch
/// lookup is served by the in-test proxy, so the exit-0 / status=success
/// assertions hold without live network access.
async fn scan_json(cwd: &Path, proxy_url: &str) -> serde_json::Value {
    let output = run(
        &["scan", "--json", "--cwd", cwd.to_str().unwrap()],
        cwd,
        proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "scan --json should exit 0, got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json must emit valid JSON ({e}), got:\n{stdout}"));
    // The discovery contract is "success" — guard the envelope shape so a
    // regression that swaps the status (or drops the field, yielding Null)
    // is caught here rather than slipping past the count assertion below.
    assert_eq!(
        value["status"], "success",
        "scan --json envelope must report status=success; got:\n{value:#}"
    );
    value
}

/// Hermeticity guard: every scan in a test must have routed its patch lookup
/// through the in-test proxy. Fewer recorded requests than scans means at
/// least one binary invocation talked to the live API (or skipped the lookup
/// outright) despite the pinning.
async fn assert_proxy_served_scans(server: &MockServer, scans: usize) {
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.len() >= scans,
        "expected all {scans} scan invocations to hit the in-test proxy; \
         recorded only {} request(s)",
        requests.len()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers crates in a registry-cache layout
/// (`$CARGO_HOME/registry/src/index.crates.io-*/<name>-<version>/`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_fake_registry_crates() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();

    // The crawler only falls back to scanning the global `$CARGO_HOME`
    // registry when the cwd actually looks like a Rust project (has a
    // `Cargo.toml` / `Cargo.lock`). Without this manifest the registry path
    // is never exercised and discovery silently returns zero (whose
    // "No packages found" message a loose `contains("packages")` check would
    // accept). Provide the manifest so the registry branch is genuinely taken.
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    // Set up a fake CARGO_HOME/registry/src/index.crates.io-xxx/ structure
    let index_dir = dir
        .path()
        .join(".cargo")
        .join("registry")
        .join("src")
        .join("index.crates.io-test");

    // Create serde-1.0.200
    let serde_dir = index_dir.join("serde-1.0.200");
    std::fs::create_dir_all(&serde_dir).unwrap();
    std::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();

    // Create tokio-1.38.0
    let tokio_dir = index_dir.join("tokio-1.38.0");
    std::fs::create_dir_all(&tokio_dir).unwrap();
    std::fs::write(
        tokio_dir.join("Cargo.toml"),
        "[package]\nname = \"tokio\"\nversion = \"1.38.0\"\n",
    )
    .unwrap();

    // --- JSON path: assert the exact discovered count, not just "non-zero".
    let json = scan_json(dir.path(), &proxy_url).await;
    assert_eq!(
        json["scannedPackages"], 2,
        "scan must discover exactly the two registry crates (serde + tokio); got:\n{json:#}"
    );

    // --- Human path: the count must be attributed to the *cargo* ecosystem,
    // proving the registry crawler (not some accidental npm/pypi pickup) is
    // what found them (a bare `contains("packages")` would also match the
    // "No packages found" failure message).
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &proxy_url,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    // Match the exact ecosystem summary, not two loose substrings. The old
    // `contains("Found 2 packages") && contains("cargo")` was satisfied by an
    // incidental "cargo" anywhere (the proxy banner, the
    // "npm/yarn/pnpm/pip/cargo" install hint, a PURL) and would NOT have
    // caught a stray non-cargo pickup, e.g. `Found 2 packages (1 cargo, 1
    // npm)`. Requiring `(2 cargo)` proves all of the count is attributed to
    // the registry crawler.
    assert!(
        combined.contains("Found 2 packages (2 cargo)"),
        "Expected human scan to report exactly 'Found 2 packages (2 cargo)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found") && !combined.contains("No packages found"),
        "scan reported no packages despite a populated registry:\n{combined}"
    );

    assert_proxy_served_scans(&server, 2).await;
}

/// Verify that `socket-patch scan` discovers crates in a vendor layout
/// (`<cwd>/vendor/<name>/`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_vendor_crates() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();

    // A bare `vendor/` dir is not cargo-specific; the crawler only treats it as
    // a crate source once the root is identified as a Cargo project. A vendored
    // project always carries a lockfile, so stage one as the project marker.
    std::fs::write(dir.path().join("Cargo.lock"), "version = 3\n").unwrap();

    // Set up vendor directory
    let vendor_dir = dir.path().join("vendor");

    let serde_dir = vendor_dir.join("serde");
    std::fs::create_dir_all(&serde_dir).unwrap();
    std::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();

    // --- JSON path: exactly one vendored crate must be discovered.
    let json = scan_json(dir.path(), &proxy_url).await;
    assert_eq!(
        json["scannedPackages"], 1,
        "scan must discover exactly the one vendored crate (serde); got:\n{json:#}"
    );

    // --- Human path: the discovery must be attributed to the cargo ecosystem,
    // and must NOT report "No packages found".
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    // Exact ecosystem summary — see the registry test for why the two-loose-
    // substring form was a loophole. `(1 cargo)` proves the single discovered
    // package is the vendored crate and not an accidental npm/pypi pickup.
    assert!(
        combined.contains("Found 1 package (1 cargo)"),
        "Expected human scan to report exactly 'Found 1 package (1 cargo)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found") && !combined.contains("No packages found"),
        "scan reported no packages despite a populated vendor dir:\n{combined}"
    );

    assert_proxy_served_scans(&server, 2).await;
}

/// Write `<registry>/<name>-<version>/` with a `Cargo.toml` and a
/// `src/lib.rs` holding `lib`.
fn fake_registry_crate(registry: &Path, name: &str, version: &str, lib: &[u8]) -> PathBuf {
    let dir = registry.join(format!("{name}-{version}"));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
    )
    .unwrap();
    std::fs::write(dir.join("src/lib.rs"), lib).unwrap();
    dir
}

/// One agent-mode manifest record patching `src/lib.rs` from `before` to
/// `after`, with both blobs staged under `.socket/blobs`.
fn manifest_record(socket: &Path, uuid: &str, before: &[u8], after: &[u8]) -> serde_json::Value {
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(git_sha256(before)), before).unwrap();
    std::fs::write(blobs.join(git_sha256(after)), after).unwrap();
    serde_json::json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "src/lib.rs": {
            "beforeHash": git_sha256(before),
            "afterHash": git_sha256(after),
        }},
        "vulnerabilities": {},
        "description": "shared-cache fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// #1278: the project crawl only looks up the crates `Cargo.lock`
/// resolves, so a patched crate the lock bumped away from is "not
/// crawled". `scan --sync` must not prune its manifest entry (and GC its
/// blobs) while its copy in the SHARED registry cache still carries the
/// agent-mode patch — that record is the only way to restore the copy,
/// which every other project on the machine builds. The entry is kept with
/// a `cargo_cache_patch_kept` warning; a dropped crate whose cache copy is
/// pristine is still pruned; and `rollback <purl>` then restores the
/// unlocked copy and drops the entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_keeps_entry_whose_shared_cache_copy_is_still_patched() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cwd = root.to_str().unwrap();

    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n\n[dependencies]\nitoa = \"=1.0.17\"\n",
    )
    .unwrap();
    // The lock after `cargo update` bumped itoa 1.0.11 -> 1.0.17 and
    // dropped ryu.
    std::fs::write(
        root.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"itoa\"\nversion = \"1.0.17\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n\
         [[package]]\nname = \"myapp\"\nversion = \"0.1.0\"\ndependencies = [\n \"itoa\",\n]\n",
    )
    .unwrap();

    let registry = root.join(".cargo/registry/src/index.crates.io-test");
    let orig: &[u8] = b"pub fn fmt() {}\n";
    let patched: &[u8] = b"pub fn fmt() {}\npub fn socket_patched() {}\n";
    // Still patched in the shared cache, no longer locked.
    let itoa_old = fake_registry_crate(&registry, "itoa", "1.0.11", patched);
    fake_registry_crate(&registry, "itoa", "1.0.17", orig);
    // No longer locked, cache copy pristine (rolled back or re-extracted).
    fake_registry_crate(&registry, "ryu", "1.0.0", orig);

    let socket = root.join(".socket");
    let itoa = "pkg:cargo/itoa@1.0.11";
    let ryu = "pkg:cargo/ryu@1.0.0";
    let manifest = serde_json::json!({ "patches": {
        itoa: manifest_record(&socket, "12780000-0000-4000-8000-000000000001", orig, patched),
        ryu: manifest_record(&socket, "12780000-0000-4000-8000-000000000002", orig, patched),
    }});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let read_manifest = || -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap()
    };

    // The preview prunes only the pristine one.
    let out = run(
        &[
            "scan",
            "--json",
            "--sync",
            "--dry-run",
            "--yes",
            "--cwd",
            cwd,
        ],
        root,
        &proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --dry-run --sync JSON ({e}):\n{stdout}"));
    assert_eq!(
        json["gc"]["prunableManifestEntries"],
        serde_json::json!([ryu]),
        "{json:#}"
    );

    let out = run(
        &["scan", "--json", "--sync", "--yes", "--cwd", cwd],
        root,
        &proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "scan --sync must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        json["gc"]["prunedManifestEntries"],
        serde_json::json!([ryu]),
        "only the pristine dropped crate is pruned: {json:#}"
    );
    let warnings = json["gc"]["warnings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        warnings
            .iter()
            .any(|w| w["code"] == "cargo_cache_patch_kept"
                && w["detail"].as_str().is_some_and(|d| d.contains(itoa))),
        "the kept entry must be explained: {json:#}"
    );
    let m = read_manifest();
    assert!(
        m["patches"].get(itoa).is_some(),
        "itoa entry dropped: {m:#}"
    );
    assert!(m["patches"].get(ryu).is_none(), "ryu entry kept: {m:#}");
    assert!(
        socket.join("blobs").join(git_sha256(patched)).exists(),
        "a kept entry's afterHash blob was swept"
    );
    assert_eq!(std::fs::read(itoa_old.join("src/lib.rs")).unwrap(), patched);

    // The prune sweep keeps afterHash blobs only (an online rollback
    // downloads originals on demand); stage the original as `repair` would
    // so the rollback below can run offline.
    std::fs::write(socket.join("blobs").join(git_sha256(orig)), orig).unwrap();

    // The kept record still restores the unlocked shared copy.
    let out = run(
        &["rollback", itoa, "--json", "--offline", "--cwd", cwd],
        root,
        &proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "rollback must exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        std::fs::read(itoa_old.join("src/lib.rs")).unwrap(),
        orig,
        "rollback must restore the shared cache copy"
    );
    let m = read_manifest();
    assert!(
        m["patches"].get(itoa).is_none(),
        "rolled-back entry kept: {m:#}"
    );
}

/// #1278 with a `cargo vendor` dir: the crawl then searches only
/// `vendor/`, but an apply from before `cargo vendor` patched the shared
/// registry copy, which must still keep its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sync_keeps_shared_cache_entry_behind_a_cargo_vendor_dir() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cwd = root.to_str().unwrap();

    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();
    let orig: &[u8] = b"pub fn fmt() {}\n";
    let patched: &[u8] = b"pub fn fmt() {}\npub fn socket_patched() {}\n";
    // The vendored (crawled) crate keeps the crawl non-empty.
    let vendored = root.join("vendor/itoa");
    std::fs::create_dir_all(&vendored).unwrap();
    std::fs::write(
        vendored.join("Cargo.toml"),
        "[package]\nname = \"itoa\"\nversion = \"1.0.17\"\n",
    )
    .unwrap();
    let registry = root.join(".cargo/registry/src/index.crates.io-test");
    let itoa_old = fake_registry_crate(&registry, "itoa", "1.0.11", patched);

    let socket = root.join(".socket");
    let itoa = "pkg:cargo/itoa@1.0.11";
    let manifest = serde_json::json!({ "patches": {
        itoa: manifest_record(&socket, "12780000-0000-4000-8000-000000000003", orig, patched),
    }});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let out = run(
        &["scan", "--json", "--sync", "--yes", "--cwd", cwd],
        root,
        &proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "scan --sync must exit 0:\n{stdout}");
    let json: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        json["gc"]["prunedManifestEntries"],
        serde_json::json!([]),
        "{json:#}"
    );
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert!(
        m["patches"].get(itoa).is_some(),
        "itoa entry dropped: {m:#}"
    );
    assert_eq!(std::fs::read(itoa_old.join("src/lib.rs")).unwrap(), patched);
}
