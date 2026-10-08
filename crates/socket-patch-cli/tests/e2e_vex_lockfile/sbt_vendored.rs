//! Manifest-less `socket-patch vex` for VENDORED sbt: the generated
//! `socket-patch-vendor.sbt` pins over the committed `.socket/vendor/maven2`
//! tree (`docs/design/sbt-support.md` §4.3; extractor
//! `vex/discover/sbt.rs`).
//!
//! The suffixed tree path carries no full uuid, so the generated file is no
//! `.socket/vendor/<eco>/<uuid>/` reference: a vendored sbt pin is attested
//! through the vendor ledger `vendor` writes, and the extractor diagnoses
//! what would make that attestation a lie. Each cell vendors for real
//! (`vendor` over the sbt 1.13.0 probe build, the installed jar in an
//! isolated Coursier cache), drops `.socket/manifest.json`, and runs
//! `vex --offline` (the ledger embeds the record):
//!
//! | cell | state | expected |
//! |---|---|---|
//! | a | after `sbt update` (the evidence resolves the suffixed version from the tree) | attested, no sbt diagnostic |
//! | b | before `sbt update` (the evidence still resolves the base version) | `sbt_resolution_unverified` |
//! | c | a tree jar tampered | `vendored_tree_missing`, not attested |
//! | d | the generated file edited | `sbt_owned_file_modified` |
//! | e | no ledger | nothing attested; the tree check still runs |

use crate::common::git_sha256;

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::Value;

use super::sbt_common::{
    copy_evidence, record_pinned_resolution, write_coursier_artifact, Gav, SbtHome,
};

const UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const GSON: Gav<'static> = Gav {
    group: "com.google.code.gson",
    artifact: "gson",
    version: "2.8.9",
};
const SV: &str = "2.8.9-socket.1d3c1fd2";
const CENTRAL: &str = "repo1.maven.org/maven2";
const MEMBER: &str = "META-INF/NOTICE.txt";
const VULN: &str = "GHSA-sbtv-test-xxxx";
const VENDORED_FILE: &str = "socket-patch-vendor.sbt";

fn tree_jar(proj: &Path) -> PathBuf {
    proj.join(".socket/vendor/maven2/com/google/code/gson/gson")
        .join(SV)
        .join(format!("gson-{SV}.jar"))
}

fn jar(notice: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in [
        ("META-INF/MANIFEST.MF", &b"Manifest-Version: 1.0\n"[..]),
        (MEMBER, notice),
    ] {
        zw.start_file(name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// `root/proj`: the sbt 1.13.0 probe build (gson 2.8.9 resolved in `b`),
/// vendored for real; the manifest is then removed.
struct Fx {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    home: SbtHome,
}

impl Fx {
    fn vendored() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let proj = root.join("proj");
        copy_evidence("1.13.0", "test-compile", &proj);
        // The evidence postdates every build source (a copy dates files in
        // directory order).
        record_pinned_resolution(&proj, &[], SystemTime::now() + Duration::from_secs(60));
        let home = SbtHome::new(&root);
        let before = b"NOTICE gson\n".to_vec();
        let after = b"NOTICE gson\nPATCHED\n".to_vec();
        write_coursier_artifact(&home.coursier_cache(), CENTRAL, GSON, &jar(&before));
        let socket = proj.join(".socket");
        std::fs::create_dir_all(socket.join("blobs")).unwrap();
        std::fs::write(socket.join("blobs").join(git_sha256(&after)), &after).unwrap();
        let manifest = serde_json::json!({ "patches": { GSON.purl(): {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { MEMBER: {
                "beforeHash": git_sha256(&before),
                "afterHash": git_sha256(&after),
            } },
            "vulnerabilities": { VULN: {
                "cves": ["CVE-2026-0042"], "summary": "s", "severity": "high",
                "description": "d"
            } },
            "description": "sbt vendored vex fixture",
            "license": "MIT",
            "tier": "free",
        } } });
        std::fs::write(
            socket.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let fx = Fx {
            _tmp: tmp,
            proj,
            home,
        };
        let (code, env) = fx.run(&["vendor"]);
        assert_eq!(code, Some(0), "vendor: {env}");
        assert_eq!(env["summary"]["applied"], 1, "vendor: {env}");
        assert!(tree_jar(&fx.proj).is_file());
        std::fs::remove_file(fx.proj.join(".socket/manifest.json")).unwrap();
        fx
    }

    /// What `sbt update` records after vendoring.
    fn sbt_update(&self) {
        let changed = record_pinned_resolution(
            &self.proj,
            &[(GSON, SV.to_string(), tree_jar(&self.proj))],
            SystemTime::now() + Duration::from_secs(240),
        );
        assert!(changed > 0);
    }

    /// `socket-patch <args> --json --cwd <proj>` in the isolated home.
    fn run(&self, args: &[&str]) -> (Option<i32>, Value) {
        let mut cmd = super::hermetic::binary_command();
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy();
            if k.starts_with("COURSIER_") {
                cmd.env_remove(&*k);
            }
        }
        let repo = self.home.coursier_cache().join("https").join(CENTRAL);
        let _server = super::prebuilt_common::prepare_command(
            &mut cmd,
            &self.proj,
            args,
            &[("MAVEN_REPO_LOCAL", repo.to_str().unwrap())],
        );
        for (k, v) in self.home.isolated_env() {
            cmd.env(k, v);
        }
        let out = cmd
            .args(["--json", "--cwd", self.proj.to_str().unwrap()])
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env_remove("M2_HOME")
            .output()
            .expect("run socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let env = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: not JSON ({e})\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code(), env)
    }

    /// `vex --offline` into `vex.json`; `(exit, envelope, document)`.
    fn vex(&self) -> (Option<i32>, Value, Option<Value>) {
        let out = self.proj.join("vex.json");
        let _ = std::fs::remove_file(&out);
        let (code, env) = self.run(&[
            "vex",
            "--offline",
            "--output",
            out.to_str().unwrap(),
            "--product",
            "pkg:maven/dev.socket.test/app@1.0.0",
        ]);
        let doc = std::fs::read(&out)
            .ok()
            .map(|b| serde_json::from_slice(&b).unwrap());
        (code, env, doc)
    }
}

/// Every `code` / `errorCode` in an envelope.
fn codes(env: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, v) in m {
                    if k == "code" || k == "errorCode" {
                        if let Some(s) = v.as_str() {
                            out.push(s.to_string());
                        }
                    }
                    walk(v, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(env, &mut out);
    out
}

/// Whether `doc` attests gson `not_affected` under [`VULN`].
fn attested(doc: Option<&Value>) -> bool {
    doc.and_then(|d| d["statements"].as_array())
        .is_some_and(|sts| {
            sts.iter().any(|st| {
                st["vulnerability"]["name"] == VULN
                    && st["status"] == "not_affected"
                    && st.to_string().contains("gson")
            })
        })
}

const SBT_DIAGS: &[&str] = &[
    "sbt_resolution_unverified",
    "vendored_tree_missing",
    "sbt_owned_file_modified",
];

#[test]
fn sbt_vendored_vex_attests_after_sbt_update() {
    let fx = Fx::vendored();
    fx.sbt_update();
    let (code, env, doc) = fx.vex();
    assert_eq!(code, Some(0), "{env}");
    assert!(attested(doc.as_ref()), "{env}\n{doc:?}");
    let got = codes(&env);
    assert!(
        !SBT_DIAGS.iter().any(|d| got.iter().any(|c| c == d)),
        "{env}"
    );
}

#[test]
fn sbt_vendored_vex_before_sbt_update_is_unverified() {
    let fx = Fx::vendored();
    let (_, env, _) = fx.vex();
    assert!(
        codes(&env).contains(&"sbt_resolution_unverified".to_string()),
        "{env}"
    );
}

#[test]
fn sbt_vendored_vex_flags_a_tampered_tree() {
    let fx = Fx::vendored();
    fx.sbt_update();
    std::fs::write(tree_jar(&fx.proj), jar(b"EVIL\n")).unwrap();
    let (_, env, doc) = fx.vex();
    assert!(
        codes(&env).contains(&"vendored_tree_missing".to_string()),
        "{env}"
    );
    assert!(
        !attested(doc.as_ref()),
        "a tampered tree is never attested: {doc:?}"
    );
}

#[test]
fn sbt_vendored_vex_flags_an_edited_generated_file() {
    let fx = Fx::vendored();
    fx.sbt_update();
    let path = fx.proj.join(VENDORED_FILE);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replace("// socket-patch ", "// mine ")).unwrap();
    let (_, env, _) = fx.vex();
    assert!(
        codes(&env).contains(&"sbt_owned_file_modified".to_string()),
        "{env}"
    );
}

#[test]
fn sbt_vendored_vex_without_a_ledger_attests_nothing() {
    let fx = Fx::vendored();
    fx.sbt_update();
    std::fs::remove_file(fx.proj.join(".socket/vendor/state.json")).unwrap();
    let (code, env, doc) = fx.vex();
    assert_ne!(code, Some(0), "{env}");
    assert!(!attested(doc.as_ref()), "{doc:?}");
    // The tree check still runs on the generated file alone.
    std::fs::write(tree_jar(&fx.proj), jar(b"EVIL\n")).unwrap();
    let (_, env, _) = fx.vex();
    assert!(
        codes(&env).contains(&"vendored_tree_missing".to_string()),
        "{env}"
    );
}
