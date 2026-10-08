//! Lock-only `scan` over a pip `requirements.txt` (a fresh checkout: no
//! virtualenv yet, the usual CI case). Discovery must read the pins the
//! way pip does, or the package never reaches the patch API and `scan`
//! reports "No patches available" while pip installs the unpatched
//! release:
//!
//! * #523: whitespace around `==` and the legacy `name (==X)` form;
//! * #412: pins reached through in-root `-r` includes;
//! * #994: include targets pip unquotes (`-r "dev reqs.txt"`,
//!   `--requirement="dev.txt"`, `-r dev\ reqs.txt`) or expands
//!   (`-r ${REQDIR}/dev.txt`);
//! * #1028: a `-r` that follows other options on the line
//!   (`--pre -r dev.txt`, `-i URL -r dev.txt`).
//!
//! Driven through the built binary against a mock patch API; the
//! assertion is what discovery sends to the batch endpoint and the
//! `lockfileOnlyPackages` count in the JSON envelope, in both hosted and
//! vendored mode. The package names are fixtures no interpreter on the
//! machine has installed, so every hit is a lock-only one.

use std::path::Path;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";

async fn mount_empty_batch(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

fn run_scan(
    root: &Path,
    mock_uri: &str,
    extra: &[&str],
    envs: &[(&str, &str)],
) -> (i32, serde_json::Value) {
    let mut argv = vec![
        "scan",
        "--json",
        "--yes",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ];
    argv.extend_from_slice(extra);
    let out = Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args(&argv)
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env_remove("VIRTUAL_ENV")
        .env_remove("CONDA_PREFIX")
        .envs(envs.iter().copied())
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON ({e}): stdout={stdout}; stderr={stderr}"));
    (out.status.code().unwrap_or(-1), v)
}

/// Every purl the scan sent to the batch endpoint.
async fn batch_purls(mock: &MockServer) -> Vec<String> {
    let mut purls: Vec<String> = Vec::new();
    for req in mock.received_requests().await.unwrap_or_default() {
        if !req.url.path().ends_with("/patches/batch") {
            continue;
        }
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let found = body["components"]
            .as_array()
            .or_else(|| body["purls"].as_array())
            .cloned()
            .unwrap_or_default();
        for c in found {
            let purl = c["purl"]
                .as_str()
                .or_else(|| c.as_str())
                .map(str::to_string);
            purls.extend(purl);
        }
    }
    purls.sort();
    purls.dedup();
    purls
}

async fn assert_lock_only_discovers(files: &[(&str, &str)], expected: &[&str]) {
    assert_lock_only_discovers_with_env(files, &[], expected).await;
}

async fn assert_lock_only_discovers_with_env(
    files: &[(&str, &str)],
    envs: &[(&str, &str)],
    expected: &[&str],
) {
    for mode in [&[][..], &["--vendor"][..]] {
        let mock = MockServer::start().await;
        mount_empty_batch(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        for (rel, content) in files {
            let p = tmp.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, content).unwrap();
        }
        let (code, v) = run_scan(tmp.path(), &mock.uri(), mode, envs);
        assert_eq!(code, 0, "mode={mode:?}: {v}");
        assert_eq!(
            v["lockfileOnlyPackages"].as_u64(),
            Some(expected.len() as u64),
            "mode={mode:?}: {v}"
        );
        let purls = batch_purls(&mock).await;
        for want in expected {
            assert!(
                purls.iter().any(|p| p == want),
                "mode={mode:?}: {want} must reach the patch API; sent {purls:?}; {v}"
            );
        }
    }
}

/// #523: spaced and parenthesised exact pins are discovered.
#[tokio::test]
async fn lock_only_scan_discovers_spaced_pins() {
    assert_lock_only_discovers(
        &[(
            "requirements.txt",
            "sp-fixture-a == 1.15.0\n\
             sp-fixture-b ==1.15.0\n\
             sp-fixture-c== 1.15.0\n\
             sp-fixture-d[x] == 1.15.0\n\
             sp-fixture-e (==1.15.0)\n",
        )],
        &[
            "pkg:pypi/sp-fixture-a@1.15.0",
            "pkg:pypi/sp-fixture-b@1.15.0",
            "pkg:pypi/sp-fixture-c@1.15.0",
            "pkg:pypi/sp-fixture-d@1.15.0",
            "pkg:pypi/sp-fixture-e@1.15.0",
        ],
    )
    .await;
}

/// #412: pins in an in-root `-r` include are discovered.
#[tokio::test]
async fn lock_only_scan_discovers_included_pins() {
    assert_lock_only_discovers(
        &[
            ("requirements.txt", "-r requirements/base.txt\n"),
            ("requirements/base.txt", "sp-fixture-six==1.16.0\n"),
        ],
        &["pkg:pypi/sp-fixture-six@1.16.0"],
    )
    .await;
}

/// #994: pip `shlex`-splits an include line's options, so a quoted or
/// backslash-escaped target names the file without its quotes, and a
/// target with a space is one path, not two words.
#[tokio::test]
async fn lock_only_scan_discovers_quoted_include_targets() {
    let cases: &[(&str, &str, &str)] = &[
        ("dq", "-r \"dev reqs.txt\"\n", "dev reqs.txt"),
        ("sq", "-r 'dev reqs.txt'\n", "dev reqs.txt"),
        ("dq_nospace", "-r \"dev.txt\"\n", "dev.txt"),
        ("bs", "-r dev\\ reqs.txt\n", "dev reqs.txt"),
        ("longq", "--requirement \"dev.txt\"\n", "dev.txt"),
        ("eqq", "--requirement=\"dev.txt\"\n", "dev.txt"),
        ("attached", "-r\"dev reqs.txt\"\n", "dev reqs.txt"),
    ];
    for (case, root, include) in cases {
        eprintln!("case {case}");
        assert_lock_only_discovers(
            &[
                ("requirements.txt", root),
                (include, "sp-fixture-quoted==1.0.0\n"),
            ],
            &["pkg:pypi/sp-fixture-quoted@1.0.0"],
        )
        .await;
    }
}

/// #994: pip expands `${NAME}` from the environment before it parses the
/// line, so `-r ${REQDIR}/dev.txt` follows `$REQDIR`.
#[tokio::test]
async fn lock_only_scan_discovers_env_var_include_target() {
    assert_lock_only_discovers_with_env(
        &[
            ("requirements.txt", "-r ${SP_TEST_REQDIR}/dev.txt\n"),
            ("sub/dev.txt", "sp-fixture-env==1.0.0\n"),
        ],
        &[("SP_TEST_REQDIR", "sub")],
        &["pkg:pypi/sp-fixture-env@1.0.0"],
    )
    .await;
}

/// #1028: pip runs optparse over every option word of a line, so a `-r`
/// that follows another option (`--pre`, `-i URL`, `-c FILE`) is still
/// an include pip follows.
#[tokio::test]
async fn lock_only_scan_discovers_include_after_other_options() {
    let cases: &[&str] = &[
        "--pre -r dev.txt\n",
        "-i https://pypi.org/simple -r dev.txt\n",
        "--index-url=https://pypi.org/simple -r dev.txt\n",
        "--prefer-binary -r dev.txt\n",
        "-c c.txt -r dev.txt\n",
        "--prefer-binary --requirement=dev.txt\n",
    ];
    for root in cases {
        eprintln!("case {root:?}");
        assert_lock_only_discovers(
            &[
                ("requirements.txt", root),
                ("dev.txt", "sp-fixture-optfirst==1.0.0\n"),
                ("c.txt", "\n"),
            ],
            &["pkg:pypi/sp-fixture-optfirst@1.0.0"],
        )
        .await;
    }
}
