//! #745: with `--manifest-path` into another project, every command reads
//! and writes the vendor ledger (`.socket/vendor/state.json`) of the
//! MANIFEST's project (`GlobalArgs::project_root`), never the `--cwd`
//! project's — so one run never interleaves two projects' state.
//!
//! Layout: `a/` is `--cwd`; `b/.socket/manifest.json` is the manifest
//! (`--manifest-path ../b/.socket/manifest.json`).

#[path = "common/hermetic.rs"]
mod hermetic;

use std::path::{Path, PathBuf};

const MANIFEST_ARG: &str = "../b/.socket/manifest.json";
const PURL: &str = "pkg:npm/__ledger_root_test__@1.0.0";
const UUID: &str = "33333333-3333-4333-8333-333333333333";

struct Fixture {
    _tmp: tempfile::TempDir,
    a: PathBuf,
    b: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(b.join(".socket")).unwrap();
    std::fs::write(b.join(".socket/manifest.json"), r#"{"patches":{}}"#).unwrap();
    Fixture { _tmp: tmp, a, b }
}

fn ledger(root: &Path) -> PathBuf {
    root.join(".socket/vendor/state.json")
}

fn corrupt_ledger(root: &Path) {
    std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
    std::fs::write(ledger(root), b"{ this is not json").unwrap();
}

/// One detached npm entry with empty wiring: its revert is a pure offline
/// artifact-dir delete plus a ledger write (the emptied ledger is deleted).
fn write_entry(root: &Path) {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(UUID);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").unwrap();
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{PURL}": {{
      "ecosystem": "npm",
      "basePurl": "{PURL}",
      "uuid": "{UUID}",
      "artifact": {{ "path": ".socket/vendor/npm/{UUID}/package.tgz" }},
      "detached": true,
      "wiring": []
    }}
  }}
}}"#
    );
    std::fs::write(ledger(root), state).unwrap();
}

struct Run {
    code: Option<i32>,
    out: String,
}

fn run(f: &Fixture, args: &[&str]) -> Run {
    let out = hermetic::binary_command()
        .args(args)
        .arg("--cwd")
        .arg(&f.a)
        .args(["--manifest-path", MANIFEST_ARG])
        .current_dir(&f.a)
        .output()
        .expect("run socket-patch");
    Run {
        code: out.status.code(),
        out: format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}

/// Whether a run's output reports an unreadable vendor ledger.
fn reports_ledger(r: &Run) -> bool {
    let o = &r.out;
    o.contains("state.json")
        || o.contains("vendor_state_unreadable")
        || o.contains("vendor_ledger_corrupt")
}

/// The ledger-reading commands, each as its own argv (`vex` writes into a
/// scratch file outside both projects).
fn commands(f: &Fixture) -> Vec<(&'static str, Vec<String>)> {
    let vex_out = f.a.parent().unwrap().join("vex.json");
    vec![
        ("list", vec!["list".into(), "--json".into()]),
        (
            "vex",
            vec![
                "vex".into(),
                "--json".into(),
                "--output".into(),
                vex_out.to_string_lossy().into_owned(),
            ],
        ),
        (
            "rollback",
            vec!["rollback".into(), "--json".into(), "--offline".into()],
        ),
        (
            "repair",
            vec!["repair".into(), "--json".into(), "--offline".into()],
        ),
    ]
    // `remove` reads the ledger only for the identifier it removes (an
    // unmatched identifier is `not_found` whatever the ledger holds); its
    // root is pinned both ways by `remove_never_modifies_the_cwd_ledger`.
}

fn run_named(f: &Fixture, argv: &[String]) -> Run {
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    run(f, &refs)
}

/// A corrupt ledger in `--cwd` is not the manifest project's ledger: every
/// command behaves exactly as with no corruption at all. The same
/// corruption in the manifest's project is reported.
#[test]
fn every_command_reads_the_manifest_projects_ledger() {
    let names: Vec<&str> = commands(&fixture()).iter().map(|(n, _)| *n).collect();
    for name in names {
        let control = {
            let f = fixture();
            let argv = commands(&f)
                .into_iter()
                .find(|(n, _)| *n == name)
                .unwrap()
                .1;
            run_named(&f, &argv)
        };
        assert!(
            !reports_ledger(&control),
            "{name}: the control run has no ledger anywhere\n{}",
            control.out
        );

        let f = fixture();
        corrupt_ledger(&f.a);
        let argv = commands(&f)
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1;
        let in_cwd = run_named(&f, &argv);
        assert_eq!(
            in_cwd.code, control.code,
            "{name}: a corrupt --cwd ledger must not change the exit code\n{}",
            in_cwd.out
        );
        assert!(
            !reports_ledger(&in_cwd),
            "{name}: the --cwd ledger is not this run's ledger\n{}",
            in_cwd.out
        );
        assert_eq!(
            std::fs::read(ledger(&f.a)).unwrap(),
            b"{ this is not json",
            "{name}: the --cwd ledger is never written"
        );

        let f = fixture();
        corrupt_ledger(&f.b);
        let argv = commands(&f)
            .into_iter()
            .find(|(n, _)| *n == name)
            .unwrap()
            .1;
        let in_manifest = run_named(&f, &argv);
        assert!(
            reports_ledger(&in_manifest),
            "{name}: the manifest project's corrupt ledger must be reported\n{}",
            in_manifest.out
        );
    }
}

/// `rollback` reverts the manifest project's vendored entries, under the
/// apply lock of that project's `.socket/`, and never touches `--cwd`'s.
#[test]
fn rollback_never_modifies_the_cwd_ledger() {
    let f = fixture();
    write_entry(&f.a);
    let before = std::fs::read(ledger(&f.a)).unwrap();
    let r = run(&f, &["rollback", "--json", "--offline"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(
        std::fs::read(ledger(&f.a)).unwrap(),
        before,
        "rollback --manifest-path ../b/... must not touch a's ledger\n{}",
        r.out
    );
    assert!(f.a.join(".socket/vendor/npm").join(UUID).exists());

    // The same entry in the manifest's project is reverted there.
    let f = fixture();
    write_entry(&f.b);
    let r = run(&f, &["rollback", "--json", "--offline"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        !ledger(&f.b).exists(),
        "b's only entry is reverted (emptied ledger deleted)\n{}",
        r.out
    );
    assert!(!f.b.join(".socket/vendor/npm").join(UUID).exists());
}

/// `remove` resolves the identifier against the manifest project's ledger.
#[test]
fn remove_never_modifies_the_cwd_ledger() {
    let f = fixture();
    write_entry(&f.a);
    let before = std::fs::read(ledger(&f.a)).unwrap();
    let r = run(&f, &["remove", PURL, "--json", "--offline", "--yes"]);
    assert_ne!(r.code, Some(0), "b holds no {PURL}\n{}", r.out);
    assert_eq!(std::fs::read(ledger(&f.a)).unwrap(), before, "{}", r.out);

    let f = fixture();
    write_entry(&f.b);
    let r = run(&f, &["remove", PURL, "--json", "--offline", "--yes"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(!ledger(&f.b).exists(), "{}", r.out);
}

/// A yarn.lock hosted-wired to the mock patch host `http://patch.test`.
fn write_hosted_pin(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\nleft-pad@1.2.3:\n  version \"1.2.3\"\n  resolved \
         \"http://patch.test/patch/npm/left-pad/1.2.3/66666666-6666-4666-8666-666666666666/\
         55555555-5555-4555-8555-555555555555/left-pad-1.2.3.tgz\"\n  integrity \
         sha512-PATCHEDpatched==\n",
    )
    .unwrap();
}

/// The hosted leg follows the same project: `rollback` and `remove` unwind
/// the manifest project's hosted pins, never `--cwd`'s.
#[test]
fn hosted_pins_come_from_the_manifest_project() {
    // `remove` echoes its identifier, so it is judged by status instead.
    let mentions = |argv: &[&str], r: &Run| {
        if argv[0] == "remove" {
            !r.out.contains("\"notFound\"")
        } else {
            r.out.contains("left-pad")
        }
    };
    for argv in [
        &["rollback", "--json", "--offline"][..],
        &[
            "remove",
            "pkg:npm/left-pad@1.2.3",
            "--json",
            "--offline",
            "--yes",
        ][..],
    ] {
        let mut full = argv.to_vec();
        full.extend(["--patch-server-url", "http://patch.test"]);

        let f = fixture();
        write_hosted_pin(&f.a);
        let before = std::fs::read(f.a.join("yarn.lock")).unwrap();
        let r = run(&f, &full);
        assert!(
            !mentions(argv, &r),
            "{argv:?}: a's hosted pin is not this run's\n{}",
            r.out
        );
        assert_eq!(std::fs::read(f.a.join("yarn.lock")).unwrap(), before);

        let f = fixture();
        write_hosted_pin(&f.b);
        let r = run(&f, &full);
        assert!(
            mentions(argv, &r),
            "{argv:?}: b's hosted pin is this run's\n{}",
            r.out
        );
    }
}

/// `vex` builds one project's document: with the manifest (and so the
/// ledgers and wiring) in `b`, the product is detected in `b` too, never
/// from `--cwd`'s package.json.
#[test]
fn vex_detects_the_product_in_the_manifest_project() {
    let f = fixture();
    let a64 = "a".repeat(64);
    let b64 = "b".repeat(64);
    std::fs::write(
        f.b.join(".socket/manifest.json"),
        format!(
            r#"{{"patches":{{"pkg:npm/lodash@4.17.20":{{
  "uuid":"{UUID}","exportedAt":"2024-01-01T00:00:00Z",
  "files":{{"package/index.js":{{"beforeHash":"{a64}","afterHash":"{b64}"}}}},
  "vulnerabilities":{{"GHSA-aaaa-bbbb-cccc":{{"cves":["CVE-2024-1111"],
    "summary":"s","severity":"high","description":"d"}}}},
  "description":"d","license":"MIT","tier":"free"}}}}}}"#
        ),
    )
    .unwrap();
    for (dir, name) in [(&f.a, "cwd-app"), (&f.b, "manifest-app")] {
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
        )
        .unwrap();
    }
    let out = f.a.parent().unwrap().join("vex.json");
    let r = run(
        &f,
        &[
            "vex",
            "--json",
            "--no-verify",
            "--output",
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(r.code, Some(0), "{}", r.out);
    let doc = std::fs::read_to_string(&out).unwrap();
    assert!(doc.contains("pkg:npm/manifest-app@1.0.0"), "{doc}");
    assert!(!doc.contains("cwd-app"), "{doc}");
}

/// A manifest file outside any `.socket/` directory relocates only the
/// manifest: the project, and so the ledger rollback reverts, stays `--cwd`.
#[test]
fn a_bare_manifest_file_keeps_the_cwd_project() {
    let f = fixture();
    write_entry(&f.a);
    std::fs::create_dir_all(f.a.join("state")).unwrap();
    let out = hermetic::binary_command()
        .args(["rollback", "--json", "--offline", "--cwd"])
        .arg(&f.a)
        .args(["--manifest-path", "state/patches.json"])
        .current_dir(&f.a)
        .output()
        .expect("run socket-patch");
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(!ledger(&f.a).exists(), "a's entry is reverted\n{text}");
}

/// Vendored and hosted modes write `--cwd`'s lockfiles: with a manifest in
/// another project there is no single project to write, so they refuse
/// before touching either (usage error, exit 2).
#[test]
fn lockfile_writing_modes_refuse_a_foreign_manifest() {
    for argv in [
        &["scan", "--mode", "vendored", "--json", "--offline"][..],
        &["scan", "--mode", "hosted", "--json", "--offline"][..],
        &["vendor", "--json", "--offline"][..],
        &["vendor", "--revert", "--json", "--offline"][..],
    ] {
        let f = fixture();
        write_entry(&f.a);
        let before = std::fs::read(ledger(&f.a)).unwrap();
        let r = run(&f, argv);
        assert_eq!(r.code, Some(2), "{argv:?}\n{}", r.out);
        assert!(
            r.out.contains("manifest_path_foreign_project"),
            "{argv:?}\n{}",
            r.out
        );
        assert_eq!(std::fs::read(ledger(&f.a)).unwrap(), before, "{argv:?}");
        assert!(!ledger(&f.b).exists(), "{argv:?}");
    }
}

/// The vendoring engine: it runs only where `--cwd` IS the manifest's
/// project — under `foreign_manifest_conflict` (`scan`/`get --mode
/// hosted|vendored`, `vendor` other than `--check`) or through the
/// re-rooted `VendoredBackend` / `run_vendor_gc` — so its `cwd` is that
/// project's root.
const ENGINE_FILES: &[&str] = &[
    "commands/vendor.rs",
    "commands/scan/vendor_flow.rs",
    "commands/scan/hosted.rs",
    "commands/bun_preflight.rs",
    "commands/vlt_heal.rs",
];

/// Architecture pin: every vendor-ledger load/save outside the vendoring
/// engine derives its root from `project_root()` — no call site passes a
/// `cwd`.
#[test]
fn every_ledger_access_is_rooted_at_project_root() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut stack = vec![src];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let rel = path.to_string_lossy().replace('\\', "/");
            if ENGINE_FILES.iter().any(|f| rel.ends_with(f)) {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Unit-test modules root their ledgers at a tempdir.
            let lines: Vec<&str> = text.lines().collect();
            let prod_end = (0..lines.len())
                .find(|&i| {
                    lines[i].trim() == "#[cfg(test)]"
                        && lines
                            .get(i + 1)
                            .is_some_and(|next| next.trim_start().starts_with("mod "))
                })
                .unwrap_or(lines.len());
            for (i, line) in lines[..prod_end].iter().enumerate() {
                for call in [
                    "load_state(",
                    "save_state(",
                    "save_state_shared(",
                    "LoadedLedgers::load(",
                    "vendored_purl_keys(",
                ] {
                    let Some(at) = line.find(call) else { continue };
                    // `core_update::load_state()` is the self-update state.
                    if line.contains("core_update::") || line.contains("fn ") {
                        continue;
                    }
                    let arg = &line[at + call.len()..];
                    if arg.contains("cwd") {
                        offenders.push(format!("{}:{}: {}", path.display(), i + 1, line.trim()));
                    }
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "vendor-ledger access rooted at a cwd instead of project_root():\n{}",
        offenders.join("\n")
    );
}

/// The embedded `--vex` of `apply` and agent-mode `scan`: the run patches
/// `--cwd`'s installed copies but the document's sources (product,
/// ledgers, lockfile wiring) belong to the manifest's project, so a foreign
/// manifest is refused before anything runs — no document is written.
#[test]
fn embedded_vex_refuses_a_foreign_manifest() {
    for argv in [
        &["apply", "--json", "--offline"][..],
        &["apply", "--json", "--offline", "--dry-run"][..],
        &["scan", "--mode", "agent", "--json", "--offline"][..],
        &["scan", "--sync", "--json", "--offline"][..],
    ] {
        let f = fixture();
        let vex = f.a.join("out.vex.json");
        let mut full: Vec<&str> = argv.to_vec();
        let vex_arg = vex.to_str().unwrap();
        full.extend(["--vex", vex_arg]);
        let r = run(&f, &full);
        assert_eq!(r.code, Some(2), "{argv:?}\n{}", r.out);
        assert!(
            r.out.contains("manifest_path_foreign_project") && r.out.contains("--vex"),
            "{argv:?}\n{}",
            r.out
        );
        assert!(!vex.exists(), "{argv:?}: no document is written");
    }
}

/// The refusal is only for a manifest in ANOTHER project: an explicit
/// path to `--cwd`'s own manifest — spelled as the default, with `./`, or
/// through a `..` detour back into `--cwd` — is the same project, and the
/// embedded `--vex` runs (an empty manifest attests nothing; not refused).
#[test]
fn embedded_vex_allows_the_cwd_projects_own_manifest() {
    for manifest in [
        ".socket/manifest.json",
        "./.socket/manifest.json",
        "../b/.socket/manifest.json",
    ] {
        for argv in [
            &["apply", "--json", "--offline"][..],
            &["scan", "--mode", "agent", "--json", "--offline"][..],
        ] {
            let f = fixture();
            let vex = f.b.join("out.vex.json");
            let out = hermetic::binary_command()
                .args(argv)
                .arg("--vex")
                .arg(&vex)
                .arg("--cwd")
                .arg(&f.b)
                .args(["--manifest-path", manifest])
                .current_dir(&f.b)
                .output()
                .expect("run socket-patch");
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(
                !text.contains("manifest_path_foreign_project")
                    && !text.contains("in another project"),
                "{manifest} {argv:?}\n{text}"
            );
            assert_ne!(out.status.code(), Some(2), "{manifest} {argv:?}\n{text}");
        }
    }
}
