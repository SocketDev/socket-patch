//! A corrupt `.socket/vendor/state.json` must not defeat the vendored prune
//! safeguards. With the ledger unreadable, `vendored_ledger_supplement`
//! (discovery) and core's `vendored_purl_keys` prune exemption (fail-open
//! by contract) both see nothing, so the vendored set is recovered from the
//! committed ground truth: manifest entries whose patch uuid owns a live
//! `.socket/vendor/<eco>/<uuid>` artifact dir.
//!
//! Modeled on `scan_vendor_e2e.rs` (mock API + real fixture through the
//! built binary).

use crate::common::envelope::{parse_json_envelope, warning_codes};
use crate::common::{binary, git_sha256, hermetic_command};

use std::path::Path;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";
/// The vendored cargo patch: uuid + purl of the entry that must survive.
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const CARGO_PURL: &str = "pkg:cargo/foo@1.0.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";

/// One installed npm package so the crawl finds ≥1 package and scan does
/// not take the zero-package early return (which skips the GC entirely).
fn write_npm_fixture(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "corrupt-ledger-test", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// The committed state of a vendored cargo dependency: manifest entry +
/// referenced blob + the contract-path artifact dir — plus a corrupt
/// vendor ledger (a bad merge-conflict resolution / truncation).
fn seed_vendored_cargo_with_corrupt_ledger(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            CARGO_PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "src/lib.rs": {
                        "beforeHash": git_sha256(BEFORE),
                        "afterHash": git_sha256(AFTER),
                    }
                },
                "vulnerabilities": {},
                "description": "vendored cargo patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // The committed artifact at the contract path.
    let artifact = socket.join(format!("vendor/cargo/{UUID}/foo-1.0.0"));
    std::fs::create_dir_all(&artifact).unwrap();
    std::fs::write(artifact.join("Cargo.toml"), b"[package]\nname = \"foo\"\n").unwrap();

    // Truncated ledger: not valid JSON, so load_state errs (fail-closed).
    std::fs::write(socket.join("vendor/state.json"), b"{\"entries\": {").unwrap();
}

/// Spawn the built binary in `root` with the hermetic `SOCKET_*`
/// environment (ambient vars scrubbed, telemetry killed).
fn run_cli(root: &Path, argv: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.args(argv).current_dir(root);
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A batch endpoint reporting NO available patches for the scanned set.
async fn mount_empty_discovery(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// `scan --prune` on a fresh clone whose vendor ledger is corrupt: the
/// vendored package's manifest entry and blob must survive the GC while the
/// committed artifacts remain.
#[tokio::test]
async fn corrupt_ledger_scan_prune_keeps_vendored_manifest_entry() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_npm_fixture(tmp.path());
    seed_vendored_cargo_with_corrupt_ledger(tmp.path());

    let uri = mock.uri();
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &[
            "scan",
            "--json",
            "--prune",
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v = parse_json_envelope(stdout.trim());

    // The GC must not report the vendored entry as pruned…
    let events = v["events"].as_array().cloned().unwrap_or_default();
    assert!(
        !events.iter().any(|e| e["purl"] == CARGO_PURL),
        "corrupt ledger: the vendored entry must not be pruned; events={}",
        v["events"]
    );
    // …and it says that its vendored half did not run, and why, instead
    // of a clean pass.
    assert!(
        warning_codes(&v)
            .iter()
            .any(|code| code == "vendor_state_unreadable"),
        "the pass could not read the ledger and must say so; warnings={}",
        v["warnings"]
    );

    // …the manifest entry must survive on disk…
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(
        manifest["patches"][CARGO_PURL].is_object(),
        "vendored manifest entry deleted despite committed artifacts; manifest={manifest}"
    );

    // …and its blob must not be swept as an orphan.
    assert!(
        tmp.path()
            .join(".socket/blobs")
            .join(git_sha256(AFTER))
            .is_file(),
        "vendored entry's blob was swept"
    );
}

/// A project where the crawl finds nothing: the manifest half of the
/// prune is skipped there, and the vendored half runs only for the ledger
/// entries the lock no longer wires. A ledger that cannot be read names
/// none, and neither does a lost one whose artifact a lockfile still
/// installs from (nothing is installed, so the lock's `file:` entry is no
/// package of the crawl). The run still says what it could not reconcile,
/// read-only: no lock is taken and nothing is written.
#[tokio::test]
async fn scan_prune_of_an_empty_crawl_says_what_it_could_not_reconcile() {
    const ORPHAN: &str = "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d";
    let corrupt_ledger = |root: &Path| {
        let ledger = root.join(".socket/vendor/state.json");
        std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
        std::fs::write(&ledger, b"{\"entries\": {").unwrap();
    };
    let wired_orphan = |root: &Path| {
        let unit = root.join(format!(".socket/vendor/npm/{ORPHAN}"));
        std::fs::create_dir_all(&unit).unwrap();
        std::fs::write(unit.join("left-pad-1.3.0.tgz"), b"tgz").unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
        )
        .unwrap();
        let lock = serde_json::json!({
            "name": "app", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": format!("file:.socket/vendor/npm/{ORPHAN}/left-pad-1.3.0.tgz"),
                },
            },
        });
        std::fs::write(root.join("package-lock.json"), lock.to_string()).unwrap();
    };
    let cases: [(&dyn Fn(&Path), &str, String); 2] = [
        (
            &corrupt_ledger,
            "vendor_state_unreadable",
            "Warning: cannot read .socket/vendor/state.json: ".to_string(),
        ),
        (
            &wired_orphan,
            "vendor_orphan_still_wired",
            format!("Warning: a project lockfile still points at .socket/vendor/npm/{ORPHAN}, "),
        ),
    ];

    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let uri = mock.uri();
    let auth = [
        "--api-url",
        &uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ];
    for (seed, code, line) in cases {
        for dry_run in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            seed(tmp.path());
            let files_before = files_under(&tmp.path().join(".socket"));
            let case = format!("{code}, dry_run={dry_run}");
            let run = |flags: &[&'static str]| {
                let mut argv = vec!["scan", "--prune"];
                argv.extend(flags);
                if dry_run {
                    argv.push("--dry-run");
                }
                argv.extend(auth);
                run_cli(tmp.path(), &argv)
            };

            let (exit, stdout, stderr) = run(&["--json"]);
            assert_eq!(exit, 0, "{case}: stdout={stdout}; stderr={stderr}");
            let v = parse_json_envelope(stdout.trim());
            assert_eq!(v["scannedPackages"], 0, "{case}: {v:#}");
            assert_eq!(warning_codes(&v), [code], "{case}: {v:#}");

            let (exit, stdout, stderr) = run(&[]);
            assert_eq!(exit, 0, "{case}: stdout={stdout}; stderr={stderr}");
            assert!(
                stderr.contains(&line),
                "{case}: stdout={stdout}; stderr={stderr}"
            );

            let (exit, stdout, stderr) = run(&["--silent"]);
            assert_eq!(
                (exit, stdout.as_str(), stderr.as_str()),
                (0, "", ""),
                "{case}"
            );

            assert_eq!(
                files_under(&tmp.path().join(".socket")),
                files_before,
                "{case}: the report reads; it takes no lock and writes nothing"
            );
        }
    }
}

/// Every file under `dir` with its bytes, sorted by path.
fn files_under(dir: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                out.push((path, bytes));
            }
        }
    }
    out.sort();
    out
}
