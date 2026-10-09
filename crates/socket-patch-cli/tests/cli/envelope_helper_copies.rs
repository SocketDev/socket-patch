//! One set of `--json` envelope readers for every CLI test target (#1089).
//!
//! `common/envelope.rs` owns parsing stdout and reading `events[]`, their
//! `errorCode`s and the `warnings[]` codes. The self-tests below run every
//! shape the per-file copies took through it, on the inputs where those
//! copies differed; the ratchet keeps new private copies out.

use std::path::Path;

use serde_json::{json, Value};

use crate::common::envelope::{
    all_codes, codes_in, event_codes, event_triples, events, find_event, parse_json_envelope,
};

/// Files that still define a private envelope reader. Each is changed by an
/// open PR, is a shared module whose includers are, or keeps a rule of its
/// own (a stricter or wider read). Migrate a file onto `common::envelope`
/// and delete its entry; a stale entry is not an error, so a PR that
/// migrates one never turns another red.
const PENDING_PRIVATE_READERS: &[&str] = &[
    "covgap_commands_rollback.rs",
    "e2e_redirect_gradle_build.rs",
    "e2e_redirect_pnpm_build.rs",
    "e2e_socket_yml_policy.rs",
    "e2e_vendor_composer_build.rs",
    "e2e_vendor_npm_build.rs",
    "e2e_vendor_pnpm_build.rs",
    "e2e_vendor_pypi_build.rs",
    "e2e_vendor_vlt_build.rs",
    "e2e_vendor_yarn_berry_build.rs",
    "hosted_memory_engine.rs",
    "in_process_redirect.rs",
    "in_process_rollback_hosted.rs",
    "in_process_vendor.rs",
    "in_process_vendor_bun_takeover.rs",
    "in_process_vendor_npm_v1_takeover.rs",
    "in_process_vendor_pnpm_takeover.rs",
    "vendor_eject_bun_lockb.rs",
    "vendor_jvm_cli.rs",
    "e2e_vex_lockfile/cargo.rs",
    "in_process_vendor_bun_takeover/vlt.rs",
    "remove/covgap_commands_remove.rs",
    "scan/scan_paths_e2e.rs",
    "vlt_hosted_common/mod.rs",
    "vlt_vendor_common/mod.rs",
];

/// The top-level helper names the per-file copies used.
const READER_NAMES: &[&str] = &[
    "events",
    "find_event",
    "parse_envelope",
    "parse_json_envelope",
    "event_codes",
    "event_triples",
    "warning_codes",
    "codes",
    "all_codes",
    "codes_in",
];

/// Every `.rs` file under `tests/`, as (`/`-joined relative path, text).
fn test_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((rel, text));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out
}

/// Whether `text` defines a top-level envelope reader of its own.
fn defines_private_reader(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line
            .strip_prefix("pub(crate) ")
            .or_else(|| line.strip_prefix("pub "))
            .unwrap_or(line);
        line.strip_prefix("fn ").is_some_and(|rest| {
            READER_NAMES.iter().any(|name| {
                rest.strip_prefix(name)
                    .is_some_and(|after| after.starts_with('(') || after.starts_with('<'))
            })
        })
    })
}

#[test]
fn no_new_private_envelope_readers() {
    let unexpected: Vec<String> = test_sources()
        .into_iter()
        .filter(|(rel, text)| {
            !rel.starts_with("common/")
                && !PENDING_PRIVATE_READERS.contains(&rel.as_str())
                && defines_private_reader(text)
        })
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        unexpected.is_empty(),
        "these test files define their own --json envelope reader: {unexpected:?}. \
         Use `common::envelope` instead (`use common::envelope::..`, or \
         `#[path = \"common/envelope.rs\"] mod envelope;` in a file without \
         `mod common`). Do not add them to PENDING_PRIVATE_READERS."
    );
}

#[test]
fn the_detector_sees_every_former_copy_shape() {
    for copy in [
        "fn parse_envelope(stdout: &str) -> serde_json::Value {",
        "fn events(envelope: &Value) -> &Vec<Value> {",
        "fn events(stdout: &str) -> Vec<(String, String, String)> {",
        "fn find_event<'a>(env: &'a Value, action: &str, code: Option<&str>) -> &'a Value {",
        "fn find_event<'a>(",
        "pub fn codes(env: &Value) -> Vec<String> {",
        "fn warning_codes(doc: &Value) -> Vec<&str> {",
        "fn event_codes(v: &Value) -> Vec<String> {",
    ] {
        assert!(defines_private_reader(copy), "missed: {copy}");
    }
    for not_a_copy in [
        "use common::envelope::{events, find_event};",
        "    fn warning_codes(&self) -> Vec<String> {",
        "fn events_for_purl(env: &Value) -> Vec<Value> {",
        "fn codes_of_lock(lock: &str) -> Vec<String> {",
        "let codes = codes_in(&env[\"warnings\"]);",
    ] {
        assert!(
            !defines_private_reader(not_a_copy),
            "false positive: {not_a_copy}"
        );
    }
}

fn sample() -> Value {
    json!({
        "status": "partial_failure",
        "events": [
            {"action": "vendored", "purl": "pkg:npm/a@1.0.0"},
            {"action": "failed", "purl": "pkg:npm/b@1.0.0", "errorCode": "vendor_lock_drift"},
            {"action": "skipped", "errorCode": "vendored"},
        ],
        "warnings": [{"code": "w_top"}, {"code": 7}, {"message": "no code"}],
        "redirect": {"warnings": [{"code": "w_redirect"}]},
        "vex": {"warnings": [{"code": "w_vex", "errorCode": "e_vex"}]},
    })
}

#[test]
fn parse_json_envelope_reads_padded_stdout_and_panics_on_text() {
    // `vendor_group_commit_e2e` trimmed stdout before parsing; serde
    // already skips the surrounding whitespace.
    assert_eq!(
        parse_json_envelope("\n {\"events\": []}\n")["events"],
        json!([])
    );
    let err = std::panic::catch_unwind(|| parse_json_envelope("error: no manifest")).unwrap_err();
    let msg = err.downcast_ref::<String>().unwrap();
    assert!(msg.contains("error: no manifest"), "{msg}");
}

#[test]
fn events_is_strict_and_event_codes_is_lenient() {
    let env = sample();
    assert_eq!(events(&env).len(), 3);
    assert_eq!(event_codes(&env), ["vendor_lock_drift", "vendored"]);
    // The lenient copies (`mode_migration_bun`, `vlt_vendor_common`) read a
    // nested `vendor` envelope or none at all as "no codes".
    assert!(event_codes(&json!({"status": "error"})).is_empty());
    assert!(std::panic::catch_unwind(|| events(&json!({"status": "error"})).len()).is_err());
}

#[test]
fn find_event_matches_action_and_optional_code() {
    let env = sample();
    assert_eq!(
        find_event(&env, "vendored", None)["purl"],
        "pkg:npm/a@1.0.0"
    );
    assert_eq!(
        find_event(&env, "failed", Some("vendor_lock_drift"))["purl"],
        "pkg:npm/b@1.0.0"
    );
    // The golang copy required a code and returned `None`; a miss now panics
    // with the envelope.
    let env2 = env.clone();
    let err = std::panic::catch_unwind(move || {
        find_event(&env2, "failed", Some("other")).clone();
    })
    .unwrap_err();
    let msg = err.downcast_ref::<String>().unwrap();
    assert!(
        msg.contains("vendor_lock_drift"),
        "panic shows the envelope: {msg}"
    );
}

#[test]
fn event_triples_fill_absent_fields_with_empty_strings() {
    assert_eq!(
        event_triples(&sample()),
        [
            ("pkg:npm/a@1.0.0".into(), "vendored".into(), String::new()),
            (
                "pkg:npm/b@1.0.0".into(),
                "failed".into(),
                "vendor_lock_drift".into()
            ),
            (String::new(), "skipped".into(), "vendored".into()),
        ]
    );
}

#[test]
fn codes_in_reads_any_warnings_array_and_skips_non_strings() {
    let env = sample();
    assert_eq!(codes_in(&env["warnings"]), ["w_top"]);
    assert_eq!(codes_in(&env["redirect"]["warnings"]), ["w_redirect"]);
    // Missing arrays read as empty, as every former copy did.
    assert!(codes_in(&env["nope"]["warnings"]).is_empty());
    // The sbt agent and gradle agent copies chained two arrays.
    let both: Vec<String> = [&env["warnings"], &env["vex"]["warnings"]]
        .into_iter()
        .flat_map(codes_in)
        .collect();
    assert_eq!(both, ["w_top", "w_vex"]);
}

#[test]
fn all_codes_collects_code_and_error_code_at_any_depth() {
    let codes = all_codes(&sample());
    // `mode_migration_vlt` pushed `errorCode` before `code` per object; the
    // callers only ask membership, so order is not part of the contract.
    for want in [
        "vendor_lock_drift",
        "vendored",
        "w_top",
        "w_redirect",
        "w_vex",
        "e_vex",
    ] {
        assert!(codes.iter().any(|c| c == want), "{want} in {codes:?}");
    }
    assert_eq!(codes.len(), 6, "non-string codes are skipped: {codes:?}");
}
