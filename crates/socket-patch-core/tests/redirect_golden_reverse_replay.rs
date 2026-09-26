//! Reverse replay of the vlt redirect goldens: each `npm/vlt` case's
//! `expected-edits.json`, recorded as a hosted ledger over its `expected/`
//! tree, must unwind `vlt-lock.json` to the `input/` bytes. The same edits are
//! what the depscan server writes into its PR ledgers, so this is also the
//! proof that socket-patch reverts a server-written vlt redirect.
//!
//! Each case runs three ways: as written, after vlt's LF re-save of a CRLF
//! lock, and after a re-save that appended a sibling node (which moves the
//! trailing comma). Both the whole-ledger replay and the per-purl revert are
//! exercised.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::{
    revert_redirect_purl, revert_remaining_redirect_edits, FileEdit, RedirectState,
};

const VLT_LOCK: &str = "vlt-lock.json";
const KIND: &str = "redirect_vlt_lock_node";

fn cases_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect/npm/vlt")
}

struct Case {
    name: String,
    input: String,
    expected: String,
    edits: Vec<FileEdit>,
    purls: Vec<String>,
}

fn npm_purl(name: &str, namespace: Option<&str>, version: &str) -> String {
    match namespace {
        Some(ns) if !ns.is_empty() => format!("pkg:npm/%40{}/{name}@{version}", &ns[1..]),
        _ => format!("pkg:npm/{name}@{version}"),
    }
}

fn load_cases() -> Vec<Case> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(cases_root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("input").is_dir())
        .collect();
    dirs.sort();
    let mut cases = Vec::new();
    for dir in dirs {
        let edits: Vec<FileEdit> =
            serde_json::from_str(&fs::read_to_string(dir.join("expected-edits.json")).unwrap())
                .unwrap();
        let edits: Vec<FileEdit> = edits.into_iter().filter(|e| e.kind == KIND).collect();
        if edits.is_empty() {
            continue;
        }
        let overrides: Vec<serde_json::Value> =
            serde_json::from_str(&fs::read_to_string(dir.join("overrides.json")).unwrap()).unwrap();
        let purls = overrides
            .iter()
            .map(|o| {
                npm_purl(
                    o["name"].as_str().unwrap(),
                    o["namespace"].as_str(),
                    o["version"].as_str().unwrap(),
                )
            })
            .collect();
        cases.push(Case {
            name: dir.file_name().unwrap().to_string_lossy().into_owned(),
            input: fs::read_to_string(dir.join("input").join(VLT_LOCK)).unwrap(),
            expected: fs::read_to_string(dir.join("expected").join(VLT_LOCK)).unwrap(),
            edits,
            purls,
        });
    }
    cases
}

fn record(uuid: &str) -> PatchRecord {
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2026-09-25T00:00:00Z".to_string(),
        files: Default::default(),
        vulnerabilities: Default::default(),
        description: String::new(),
        license: String::new(),
        tier: "free".to_string(),
    }
}

fn ledger(case: &Case) -> RedirectState {
    let mut state = RedirectState::new();
    state.edits = case.edits.clone();
    for purl in &case.purls {
        state.records.insert(purl.clone(), record("u"));
    }
    state
}

/// The lock after vlt re-saved it with a node appended at the end of the
/// nodes section, so the formerly last entry gains a comma.
fn with_appended_node(text: &str) -> String {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    let open = lines
        .iter()
        .position(|l| l.trim_end_matches('\r') == "  \"nodes\": {")
        .expect("nodes section");
    let close = (open + 1..lines.len())
        .find(|&i| matches!(lines[i].trim_end_matches('\r'), "  }" | "  },"))
        .expect("nodes section end");
    let last = close - 1;
    let cr = if lines[last].ends_with('\r') {
        "\r"
    } else {
        ""
    };
    let body = lines[last].trim_end_matches('\r').to_string();
    assert!(!body.ends_with(','), "the last node has no comma");
    lines[last] = format!("{body},{cr}");
    lines.insert(
        close,
        format!("    \"~npm~zzz-appended@1.0.0\": [0,\"zzz-appended\",\"sha512-zz==\"]{cr}"),
    );
    lines.join("\n")
}

fn variants(case: &Case) -> Vec<(&'static str, String, String)> {
    let mut out = vec![("as-written", case.expected.clone(), case.input.clone())];
    if case.expected.contains('\r') {
        out.push((
            "lf-resave",
            case.expected.replace("\r\n", "\n"),
            case.input.replace("\r\n", "\n"),
        ));
    }
    out.push((
        "comma-moved",
        with_appended_node(&case.expected),
        with_appended_node(&case.input),
    ));
    out
}

fn stage(lock: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(VLT_LOCK), lock).unwrap();
    dir
}

#[tokio::test]
async fn vlt_goldens_replay_back_to_their_input() {
    let cases = load_cases();
    assert!(
        cases.len() >= 30,
        "only {} vlt cases with edits",
        cases.len()
    );
    for case in &cases {
        for (variant, on_disk, want) in variants(case) {
            let dir = stage(&on_disk);
            let mut state = ledger(case);
            let out = revert_remaining_redirect_edits(dir.path(), &mut state, false).await;
            assert!(
                out.fully_reverted(),
                "{} {variant}: {:?}",
                case.name,
                out.refusals
            );
            assert!(state.edits.is_empty(), "{} {variant}", case.name);
            assert!(state.records.is_empty(), "{} {variant}", case.name);
            assert_eq!(
                fs::read_to_string(dir.path().join(VLT_LOCK)).unwrap(),
                want,
                "{} {variant}: replay",
                case.name
            );

            let again = revert_remaining_redirect_edits(dir.path(), &mut ledger(case), false).await;
            assert!(again.fully_reverted(), "{} {variant}: rerun", case.name);
            assert_eq!(
                fs::read_to_string(dir.path().join(VLT_LOCK)).unwrap(),
                want,
                "{} {variant}: an already reverted lock stays put",
                case.name
            );
        }
    }
}

#[tokio::test]
async fn vlt_goldens_revert_per_purl_back_to_their_input() {
    for case in &load_cases() {
        for (variant, on_disk, want) in variants(case) {
            let dir = stage(&on_disk);
            let mut state = ledger(case);
            let mut touched: BTreeMap<String, usize> = BTreeMap::new();
            for purl in &case.purls {
                let out = revert_redirect_purl(dir.path(), &mut state, purl, false)
                    .await
                    .unwrap_or_else(|e| panic!("{} {variant} {purl}: {e}", case.name));
                *touched.entry(purl.clone()).or_default() += out.reverted_files.len();
            }
            assert!(
                state.edits.is_empty(),
                "{} {variant}: every vlt edit is claimed by its purl: {:?}",
                case.name,
                state.edits
            );
            assert_eq!(
                fs::read_to_string(dir.path().join(VLT_LOCK)).unwrap(),
                want,
                "{} {variant}: per-purl revert ({touched:?})",
                case.name
            );
        }
    }
}
