//! Real-sbt capstones for the vendored sbt backend (`vendor/jvm/sbt.rs`,
//! `docs/design/sbt-support.md` §5, §8.4).
//!
//! Each test writes a Java-only sbt build (`autoScalaLibrary := false`,
//! `crossPaths := false`) depending on `commons-text:1.10.0` (which pulls
//! `commons-lang3:3.12.0`), warms it with a real `sbt update` (the
//! installed packages are what sbt cached: the agent crawler finds them in
//! the test home's Coursier or Ivy cache), stages a marker patch on the
//! jar's `META-INF/NOTICE.txt` (manifest + blob), and runs the real
//! binary's `vendor --json --offline`. Then:
//!
//! * `offline_fresh_checkout` — a fresh copy of the committable files
//!   resolves the suffixed jar with the network blocked (an unreachable
//!   proxy), and the classpath jar carries the patched member;
//! * `tamper_fails_load` — a tampered tree jar fails the build at load with
//!   the generated file's `socket-patch:` message;
//! * `check_detects_drift` — `vendor --check` passes in sync and fails on an
//!   edited generated file;
//! * `two_patches_revert_any_order_byte_exact` — both GAs resolve patched;
//!   rolling back either leaves the other patched, and `vendor --revert`
//!   restores every committable byte, in both orders;
//! * `rerun_noop` — a re-run is `already_vendored` and writes nothing;
//! * `declared_bump_fails_closed` — declaring the vendored GA newer than
//!   the patch's base fails the load-time check, and a re-vendor refuses;
//! * `subproject_refused` — vendoring from a subproject is `not_build_root`;
//! * `gitignore_jar_fresh_clone` — a user `*.jar` ignore rule does not drop
//!   the vendored jars from a `git clone`, which builds patched offline.
//!
//! Gated like the other real-toolchain capstones: `#[ignore]` (network to
//! Maven Central for the warm-up), sbt via `SOCKET_PATCH_SBT_E2E_{SBT,
//! VERSION,REQUIRED,SEED}` (`sbt_vendor_build_common`). Scratch trees go
//! under `TMPDIR`.

#[path = "common/mod.rs"]
mod common;
use common::git_sha256;

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "maven_build_common/mod.rs"]
mod maven_build_common;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;
#[path = "sbt_vendor_build_common/mod.rs"]
mod sbt_vendor_build_common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use maven_build_common::{jar_member, patched_member, MARKER, MEMBER};
use sbt_vendor_build_common::{dump, ok, write_build, Sbt, SbtHome, BUILD_OUTPUT_DIRS};

const TEXT: (&str, &str, &str) = ("org.apache.commons", "commons-text", "1.10.0");
const LANG3: (&str, &str, &str) = ("org.apache.commons", "commons-lang3", "3.12.0");
const TEXT_UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const LANG3_UUID: &str = "9a8b7c6d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const TEXT_DEP: &str = "\"org.apache.commons\" % \"commons-text\" % \"1.10.0\"";
const VENDORED_FILE: &str = "socket-patch-vendor.sbt";
/// Every outbound connection of an sbt run fails (Coursier and Ivy honour
/// the JVM proxy properties).
const NO_NETWORK: &[&str] = &[
    "-Dhttp.proxyHost=127.0.0.1",
    "-Dhttp.proxyPort=9",
    "-Dhttps.proxyHost=127.0.0.1",
    "-Dhttps.proxyPort=9",
];

fn purl((g, a, v): (&str, &str, &str)) -> String {
    format!("pkg:maven/{g}/{a}@{v}")
}

fn hex8(uuid: &str) -> &str {
    &uuid[..8]
}

/// One warmed fixture: the build at `proj`, its isolated `home` (whose
/// Coursier / Ivy caches hold the installed packages, as sbt left them),
/// the download fixture's Maven2 `mirror`, and the patched member of each
/// GA.
struct Ctx {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    proj: PathBuf,
    home: SbtHome,
    mirror: PathBuf,
    sbt: Sbt,
    patched: BTreeMap<String, Vec<u8>>,
}

/// Write, warm and stage the fixture; `None` when skipped.
fn setup(
    suite: &str,
    project_dir: &str,
    subprojects: &[&str],
    patches: &[((&str, &str, &str), &str)],
) -> Option<Ctx> {
    let sbt = Sbt::detect(suite)?;
    let tmp = tempfile::tempdir().unwrap();
    // Canonical, in the spelling Java accepts (no Windows verbatim prefix).
    let root = sbt_vendor_build_common::shared::canonical(tmp.path());
    let proj = root.join("proj");
    write_build(&proj, &sbt.version, &[TEXT_DEP], subprojects);
    for sub in subprojects {
        std::fs::create_dir_all(proj.join(sub)).unwrap();
        std::fs::write(
            proj.join(sub).join("build.sbt"),
            format!("name := \"{sub}\"\n"),
        )
        .unwrap();
    }
    let mut home = SbtHome::new(&root);
    let out = sbt_vendor_build_common::warm_up(&sbt, &proj, &mut home);
    if !ok(&out) {
        let why = format!("warm-up `sbt update` failed:\n{}", dump(&out));
        sbt_vendor_build_common::skip(suite, &why);
        return None;
    }
    assert!(
        String::from_utf8_lossy(&out.stdout).contains(&sbt.version),
        "the build does not report sbt {}:\n{}",
        sbt.version,
        dump(&out)
    );
    // Only the download fixture serves from this Maven2 copy; vendoring
    // finds the installed copy in sbt's own cache (`HOME`'s Coursier
    // cache, or `~/.ivy2/cache` on 0.13 / 1.0–1.2) through the agent
    // crawler, with an empty `MAVEN_REPO_LOCAL`.
    let mirror = root.join("mirror");
    let manifest_root = if project_dir.is_empty() {
        proj.clone()
    } else {
        proj.join(project_dir)
    };
    let mut records = serde_json::Map::new();
    let mut patched = BTreeMap::new();
    std::fs::create_dir_all(manifest_root.join(".socket/blobs")).unwrap();
    for (gav @ (g, a, v), uuid) in patches {
        let (jar, pom) = home
            .cached(g, a, v)
            .unwrap_or_else(|| panic!("{g}:{a}:{v} is not in the sbt caches"));
        let dir = mirror.join(g.replace('.', "/")).join(a).join(v);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{a}-{v}.jar")), &jar).unwrap();
        std::fs::write(dir.join(format!("{a}-{v}.pom")), &pom).unwrap();
        let (before, after) = patched_member(&jar, a);
        std::fs::write(
            manifest_root.join(".socket/blobs").join(git_sha256(&after)),
            &after,
        )
        .unwrap();
        records.insert(
            purl(*gav),
            serde_json::json!({
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { MEMBER: {
                    "beforeHash": git_sha256(&before),
                    "afterHash": git_sha256(&after),
                } },
                "vulnerabilities": { "GHSA-vendor-sbt-real": {
                    "cves": ["CVE-2026-7204"], "summary": "s", "severity": "high",
                    "description": "d"
                } },
                "description": "sbt vendored capstone",
                "license": "Apache-2.0",
                "tier": "free",
            }),
        );
        patched.insert(a.to_string(), after);
    }
    std::fs::write(
        manifest_root.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": records })).unwrap(),
    )
    .unwrap();
    Some(Ctx {
        _tmp: tmp,
        root,
        proj,
        home,
        mirror,
        sbt,
        patched,
    })
}

impl Ctx {
    /// `socket-patch <args> --json --offline --cwd <dir>`; `(exit, envelope)`.
    fn socket(&self, dir: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value) {
        let mut cmd = hermetic::binary_command();
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("COURSIER_") {
                cmd.env_remove(&k);
            }
        }
        let full: Vec<&str> = args
            .iter()
            .copied()
            .chain(["--json", "--offline", "--cwd", dir.to_str().unwrap()])
            .collect();
        let _fixture = prebuilt_common::prepare_command(
            &mut cmd,
            dir,
            &full,
            &[("MAVEN_REPO_LOCAL", self.mirror.to_str().unwrap())],
        );
        let out = cmd
            .current_dir(dir)
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env("MAVEN_REPO_LOCAL", self.root.join("empty-m2"))
            .env("HOME", &self.home.root)
            .env("COURSIER_CACHE", self.home.coursier_cache())
            .env_remove("M2_HOME")
            .env_remove("SBT_OPTS")
            .env_remove("JAVA_OPTS")
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

    fn ok(&self, args: &[&str]) -> serde_json::Value {
        let (code, env) = self.socket(&self.proj, args);
        assert_eq!(code, Some(0), "{args:?}: {env}");
        let failed = env["summary"].get("failed").unwrap_or(&env["failed"]);
        assert_eq!(failed, 0, "{args:?}: {env}");
        env
    }

    /// The compile classpath of the build at `dir`; `offline` blocks every
    /// outbound connection. sbt 1.0–1.2 (Ivy) used to abort on the first
    /// unreachable repository listed before the vendored resolver; the
    /// generated file's installer now moves socket-patch's resolvers to the
    /// front on the 0.13 and 1.x lines (`docs/design/sbt-template-probe.md`,
    /// case o), so every line resolves the tree offline.
    fn classpath(&self, dir: &Path, offline: bool) -> Vec<PathBuf> {
        let extra = if offline { NO_NETWORK } else { &[] };
        let out = self.sbt.run(
            dir,
            &self.home,
            extra,
            &["update", &self.sbt.classpath_command(None)],
        );
        assert!(
            ok(&out),
            "sbt classpath in {}:\n{}",
            dir.display(),
            dump(&out)
        );
        let cp = Sbt::classpath(&out, dir, &self.home);
        assert!(!cp.is_empty(), "no classpath exported:\n{}", dump(&out));
        cp
    }

    /// Assert `cp` resolves `a` at its suffixed version, carrying the
    /// patched member (`patched`) or at the base version, pristine.
    fn assert_resolves(&self, cp: &[PathBuf], (_, a, v): (&str, &str, &str), uuid: Option<&str>) {
        let name = match uuid {
            Some(u) => format!("{a}-{v}-socket.{}.jar", hex8(u)),
            None => format!("{a}-{v}.jar"),
        };
        let jar = cp
            .iter()
            .find(|p| p.file_name().is_some_and(|n| n.to_string_lossy() == name))
            // `name` embeds the patch uuid: name it, never print it (CodeQL
            // rust/cleartext-logging).
            .unwrap_or_else(|| {
                let kind = if uuid.is_some() {
                    "patched"
                } else {
                    "pristine"
                };
                panic!("the {kind} {a}-{v} jar is not on the classpath: {cp:?}")
            });
        let member = jar_member(&std::fs::read(jar).unwrap(), MEMBER).expect("NOTICE");
        let marked = String::from_utf8_lossy(&member).contains(MARKER);
        assert_eq!(
            marked,
            uuid.is_some(),
            "{}: patched={marked}",
            jar.display()
        );
        if uuid.is_some() {
            assert_eq!(&member, &self.patched[a], "{}", jar.display());
        }
    }
}

/// Every committable file under `root` (build output, and the manifest and
/// blobs the tests stage, skipped).
fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type().unwrap().is_dir() {
                if !BUILD_OUTPUT_DIRS.contains(&name.as_str())
                    && !BUILD_OUTPUT_DIRS.contains(&rel.as_str())
                    && name != ".git"
                    && !rel.ends_with(".socket/blobs")
                {
                    walk(root, &path, out);
                }
                continue;
            }
            if !rel.ends_with(".socket/manifest.json") {
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// A copy of `proj`'s committable files at `dst`.
fn fresh_checkout(proj: &Path, dst: &Path) {
    for (rel, bytes) in snapshot(proj) {
        let path = dst.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

fn events(env: &serde_json::Value) -> Vec<(String, String, String)> {
    env["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
            (s("purl"), s("action"), s("errorCode"))
        })
        .collect()
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_offline_fresh_checkout() {
    let Some(ctx) = setup(
        "sbt_vendor_offline_fresh_checkout",
        "",
        &[],
        &[(TEXT, TEXT_UUID)],
    ) else {
        return;
    };
    let env = ctx.ok(&["vendor"]);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert!(ctx.proj.join(VENDORED_FILE).is_file());
    let fresh = ctx.root.join("fresh");
    fresh_checkout(&ctx.proj, &fresh);
    assert!(!fresh.join("target").exists());
    let cp = ctx.classpath(&fresh, true);
    ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
    ctx.assert_resolves(&cp, LANG3, None);
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_tamper_fails_load() {
    let Some(ctx) = setup(
        "sbt_vendor_tamper_fails_load",
        "",
        &[],
        &[(TEXT, TEXT_UUID)],
    ) else {
        return;
    };
    ctx.ok(&["vendor"]);
    let jar = ctx.proj.join(format!(
        ".socket/vendor/maven2/org/apache/commons/commons-text/1.10.0-socket.{h}/\
         commons-text-1.10.0-socket.{h}.jar",
        h = hex8(TEXT_UUID)
    ));
    let mut bytes = std::fs::read(&jar).unwrap();
    bytes.extend_from_slice(b"tampered");
    std::fs::write(&jar, bytes).unwrap();
    let out = ctx.sbt.run(&ctx.proj, &ctx.home, &[], &["update"]);
    assert!(
        !ok(&out),
        "a tampered tree jar must fail the build:\n{}",
        dump(&out)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        text.contains("socket-patch:") && text.contains("has sha256"),
        "{}",
        dump(&out)
    );
}

/// A build that now declares the vendored GA newer than the patch's base
/// fails `update` at the generated file's load-time check (the override
/// would otherwise force it back down), and a re-vendor refuses the pin.
#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_declared_bump_fails_closed() {
    let Some(ctx) = setup(
        "sbt_vendor_declared_bump_fails_closed",
        "",
        &[],
        &[(TEXT, TEXT_UUID)],
    ) else {
        return;
    };
    ctx.ok(&["vendor"]);
    let build_path = ctx.proj.join("build.sbt");
    let build = std::fs::read_to_string(&build_path).unwrap();
    let bumped = build.replace(
        "\"commons-text\" % \"1.10.0\"",
        "\"commons-text\" % \"1.11.0\"",
    );
    assert_ne!(bumped, build);
    std::fs::write(&build_path, &bumped).unwrap();
    let out = ctx.sbt.run(&ctx.proj, &ctx.home, &[], &["update"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !ok(&out) && text.contains("declares org.apache.commons:commons-text:1.11.0"),
        "{}",
        dump(&out)
    );
    let (code, env) = ctx.socket(&ctx.proj, &["vendor"]);
    assert_eq!(code, Some(1), "{env}");
    assert!(
        events(&env)
            .iter()
            .any(|(_, action, code)| action == "failed" && code == "vendor_sbt_pin_declared_newer"),
        "{env}"
    );
    std::fs::write(&build_path, &build).unwrap();
    let cp = ctx.classpath(&ctx.proj, false);
    ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_check_detects_drift() {
    let Some(ctx) = setup(
        "sbt_vendor_check_detects_drift",
        "",
        &[],
        &[(TEXT, TEXT_UUID)],
    ) else {
        return;
    };
    ctx.ok(&["vendor"]);
    let cp = ctx.classpath(&ctx.proj, false);
    ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
    let before = snapshot(&ctx.proj);
    ctx.ok(&["vendor", "--check"]);
    assert_eq!(snapshot(&ctx.proj), before, "--check wrote");
    let path = ctx.proj.join(VENDORED_FILE);
    let good = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, format!("{good}// mine\n")).unwrap();
    let (code, env) = ctx.socket(&ctx.proj, &["vendor", "--check"]);
    assert_eq!(code, Some(1), "{env}");
    std::fs::write(&path, good).unwrap();
    ctx.ok(&["vendor", "--check"]);
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_two_patches_revert_any_order_byte_exact() {
    let Some(ctx) = setup(
        "sbt_vendor_two_patches_revert_any_order_byte_exact",
        "",
        &[],
        &[(TEXT, TEXT_UUID), (LANG3, LANG3_UUID)],
    ) else {
        return;
    };
    let pristine = snapshot(&ctx.proj);
    // `rollback` drops the rolled-back record from the manifest: restore
    // the staged inputs before each order.
    let manifest_path = ctx.proj.join(".socket/manifest.json");
    let manifest = std::fs::read(&manifest_path).unwrap();
    let blobs: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(ctx.proj.join(".socket/blobs"))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            let bytes = std::fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    for (first, other, other_uuid) in [(TEXT, LANG3, LANG3_UUID), (LANG3, TEXT, TEXT_UUID)] {
        std::fs::write(&manifest_path, &manifest).unwrap();
        for (p, bytes) in &blobs {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        let env = ctx.ok(&["vendor"]);
        assert_eq!(env["summary"]["applied"], 2, "{env}");
        let cp = ctx.classpath(&ctx.proj, false);
        ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
        ctx.assert_resolves(&cp, LANG3, Some(LANG3_UUID));
        ctx.ok(&["rollback", &purl(first)]);
        let cp = ctx.classpath(&ctx.proj, false);
        ctx.assert_resolves(&cp, first, None);
        ctx.assert_resolves(&cp, other, Some(other_uuid));
        ctx.ok(&["vendor", "--revert"]);
        assert_eq!(snapshot(&ctx.proj), pristine, "first={}", first.1);
    }
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_rerun_noop() {
    let Some(ctx) = setup("sbt_vendor_rerun_noop", "", &[], &[(TEXT, TEXT_UUID)]) else {
        return;
    };
    ctx.ok(&["vendor"]);
    let cp = ctx.classpath(&ctx.proj, false);
    ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
    let before = snapshot(&ctx.proj);
    let env = ctx.ok(&["vendor"]);
    assert_eq!(
        events(&env),
        [(
            purl(TEXT),
            "skipped".to_string(),
            "already_vendored".to_string()
        )],
        "{env}"
    );
    assert_eq!(snapshot(&ctx.proj), before);
    let cp = ctx.classpath(&ctx.proj, true);
    ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_subproject_refused() {
    let Some(ctx) = setup(
        "sbt_vendor_subproject_refused",
        "sub",
        &["sub"],
        &[(TEXT, TEXT_UUID)],
    ) else {
        return;
    };
    let before = snapshot(&ctx.proj);
    let (code, env) = ctx.socket(&ctx.proj.join("sub"), &["vendor"]);
    assert_ne!(code, Some(0), "{env}");
    assert_eq!(
        env["events"][0]["errorCode"], "vendor_jvm_shape_unsupported",
        "{env}"
    );
    assert!(
        env["events"][0]["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("reason: not_build_root: run vendor from sbt build root"),
        "{env}"
    );
    assert_eq!(snapshot(&ctx.proj), before);
}

#[test]
#[ignore = "real sbt + network (SOCKET_PATCH_SBT_E2E_*)"]
fn sbt_vendor_gitignore_jar_fresh_clone() {
    let Some(ctx) = setup(
        "sbt_vendor_gitignore_jar_fresh_clone",
        "",
        &[],
        &[(TEXT, TEXT_UUID)],
    ) else {
        return;
    };
    std::fs::write(ctx.proj.join(".gitignore"), "*.jar\ntarget/\n").unwrap();
    ctx.ok(&["vendor"]);
    let git = |cwd: &Path, args: &[&str]| {
        let out = Command::new("git")
            .current_dir(cwd)
            .args(["-c", "user.email=t@example.com", "-c", "user.name=t"])
            .args(["-c", "init.defaultBranch=main", "-c", "core.autocrlf=false"])
            .args(args)
            .output()
            .expect("git");
        assert!(out.status.success(), "git {args:?}: {}", dump(&out));
    };
    git(&ctx.proj, &["init", "-q"]);
    git(&ctx.proj, &["add", "-A"]);
    git(&ctx.proj, &["commit", "-q", "-m", "vendored"]);
    let clone = ctx.root.join("clone");
    git(
        &ctx.root,
        &[
            "clone",
            "-q",
            ctx.proj.to_str().unwrap(),
            clone.to_str().unwrap(),
        ],
    );
    let jar = format!(
        ".socket/vendor/maven2/org/apache/commons/commons-text/1.10.0-socket.{h}/\
         commons-text-1.10.0-socket.{h}.jar",
        h = hex8(TEXT_UUID)
    );
    // `jar` embeds the patch uuid: name it, never print it (CodeQL
    // rust/cleartext-logging).
    assert!(
        clone.join(&jar).is_file(),
        "the clone lost the vendored commons-text jar"
    );
    let cp = ctx.classpath(&clone, true);
    ctx.assert_resolves(&cp, TEXT, Some(TEXT_UUID));
}
