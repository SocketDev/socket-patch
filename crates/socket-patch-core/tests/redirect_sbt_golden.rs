//! Golden cases for the hosted sbt rewriter (`patch::redirect::sbt`), over
//! `tests/fixtures/sbt/redirect/<case>/`:
//!
//! - `input/`: the project's candidate files (UTF-8 text; a presence-only
//!   file such as `build.sbt.lock` or `build.mill` is an empty file, as the
//!   engine reads it);
//! - `resolution.json` (optional): the [`ResolutionDoc`] the engine's IO
//!   layer would distil from the build's `target/` evidence, carried under
//!   `SBT_RESOLUTION_KEY` exactly as the engine does;
//! - `overrides.json`: the granted overrides;
//! - `expected/`: the files the run writes (absent = writes nothing);
//! - `expected-edits.json`, `expected-warnings.json` (codes, in order) and
//!   `expected-confirmation.json` (`confirmed` / `refused` sbt uuids): all
//!   three required, so a refusal case proves WHY nothing changed.
//!
//! A case with `restore.json` (`[{purl, uuid}]`) instead runs the upstream
//! restore over `input/` and expects `expected/` to be the whole restored
//! `socket-patch.sbt` (absent = deleted).
//!
//! Every wiring case that creates `socket-patch.sbt` is also restored: its
//! confirmed pins out again must delete the file (no other bytes changed).
//!
//! This harness is separate from the TS-authored `redirect_golden.rs`; the
//! depscan port of these cases is a follow-up.
//!
//! `SOCKET_PATCH_BLESS_SBT_GOLDEN=1` rewrites every case's expectations
//! from the current output (review the diff before committing).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use socket_patch_core::formats::sbt::owned_file::HOSTED_FILE;
use socket_patch_core::patch::redirect::sbt::{ResolutionDoc, SBT_RESOLUTION_KEY};
use socket_patch_core::patch::redirect::upstream::{restore_upstream, HostedPin, RestoreOptions};
use socket_patch_core::patch::redirect::{rewrite_registry_redirect, DepOverride, RewriteResult};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbt/redirect")
}

fn bless() -> bool {
    std::env::var_os("SOCKET_PATCH_BLESS_SBT_GOLDEN").is_some()
}

fn tree(dir: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if !dir.is_dir() {
        return out;
    }
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let text = fs::read_to_string(entry.path()).unwrap_or_else(|e| {
                panic!("{}: inputs are UTF-8 only: {e}", entry.path().display())
            });
            out.insert(rel, text);
        }
    }
    out
}

fn write_tree(dir: &Path, files: &BTreeMap<String, String>) {
    let _ = fs::remove_dir_all(dir);
    for (rel, text) in files {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(
        &fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn write_json(path: &Path, value: &serde_json::Value) {
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
    )
    .unwrap();
}

/// Assert (or, blessing, record) `got` as `case/<name>`.
fn expect_json(case: &Path, name: &str, got: serde_json::Value) {
    let path = case.join(name);
    if bless() {
        write_json(&path, &got);
        return;
    }
    assert!(path.is_file(), "{}: missing {name}", case.display());
    assert_eq!(got, read_json(&path), "{}: {name} mismatch", case.display());
}

fn expect_tree(case: &Path, got: &BTreeMap<String, String>) {
    let dir = case.join("expected");
    if bless() {
        let _ = fs::remove_dir_all(&dir);
        if !got.is_empty() {
            write_tree(&dir, got);
        }
        return;
    }
    let want = tree(&dir);
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "{}: written-file set mismatch",
        case.display()
    );
    for (rel, text) in got {
        assert_eq!(
            text.as_str(),
            want[rel].as_str(),
            "{}: {rel} byte-mismatch",
            case.display()
        );
    }
}

fn input_files(case: &Path) -> BTreeMap<String, String> {
    let mut files = tree(&case.join("input"));
    let resolution = case.join("resolution.json");
    if resolution.is_file() {
        // Through the typed document, so a fixture's resolution.json is
        // checked against the contract the engine's IO layer writes.
        let text = fs::read_to_string(&resolution).unwrap();
        let doc = ResolutionDoc::parse(&text)
            .unwrap_or_else(|e| panic!("{}: bad resolution.json: {e}", case.display()));
        files.insert(SBT_RESOLUTION_KEY.to_string(), doc.to_json());
    }
    files
}

fn run(case: &Path) -> (BTreeMap<String, String>, RewriteResult) {
    let files = input_files(case);
    let overrides: Vec<DepOverride> =
        serde_json::from_value(read_json(&case.join("overrides.json")))
            .unwrap_or_else(|e| panic!("{}: bad overrides.json: {e}", case.display()));
    let result = rewrite_registry_redirect(&files, &overrides);
    (files, result)
}

async fn restore(input: &BTreeMap<String, String>, pins: &[HostedPin]) -> Option<String> {
    let tmp = tempfile::tempdir().unwrap();
    write_tree(tmp.path(), input);
    let out = restore_upstream(
        tmp.path(),
        pins,
        &RestoreOptions {
            offline: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(out.refused().count(), 0, "restore refused: {:?}", out.pins);
    let after = tree(tmp.path());
    for (rel, text) in input {
        if rel != HOSTED_FILE {
            assert_eq!(after.get(rel), Some(text), "restore touched {rel}");
        }
    }
    after.get(HOSTED_FILE).cloned()
}

async fn run_restore_case(case: &Path) {
    let input = tree(&case.join("input"));
    let pins: Vec<HostedPin> = read_json(&case.join("restore.json"))
        .as_array()
        .expect("restore.json is an array")
        .iter()
        .map(|p| HostedPin {
            purl: p["purl"].as_str().unwrap().to_string(),
            uuid: p["uuid"].as_str().unwrap().to_string(),
            files: vec![HOSTED_FILE.to_string()],
        })
        .collect();
    let left = restore(&input, &pins).await;
    let got: BTreeMap<String, String> = left
        .into_iter()
        .map(|t| (HOSTED_FILE.to_string(), t))
        .collect();
    expect_tree(case, &got);
}

#[tokio::test]
async fn redirect_sbt_golden_cases_match() {
    let mut cases: Vec<PathBuf> = fs::read_dir(root())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.join("input").is_dir())
        .collect();
    cases.sort();
    assert!(
        bless() || cases.len() >= 42,
        "sbt golden cases went missing: {cases:?}"
    );
    for case in &cases {
        if case.join("restore.json").is_file() {
            run_restore_case(case).await;
            continue;
        }
        let (files, result) = run(case);
        assert!(
            !result.files.keys().any(|k| k.starts_with("<socket-patch:")),
            "{}: wrote a synthetic key",
            case.display()
        );
        expect_tree(case, &result.files);
        expect_json(
            case,
            "expected-edits.json",
            serde_json::to_value(&result.edits).unwrap(),
        );
        expect_json(
            case,
            "expected-warnings.json",
            serde_json::to_value(
                result
                    .warnings
                    .iter()
                    .map(|w| w.code.as_str())
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        expect_json(
            case,
            "expected-confirmation.json",
            serde_json::json!({
                "confirmed": result.confirmed_sbt_uuids,
                "refused": result.refused_sbt_uuids,
            }),
        );
        // A confirmed uuid is never also refused.
        assert!(
            result
                .confirmed_sbt_uuids
                .intersection(&result.refused_sbt_uuids)
                .next()
                .is_none(),
            "{}: a uuid is both confirmed and refused",
            case.display()
        );
        // Deterministic.
        let again = rewrite_registry_redirect(
            &files,
            &serde_json::from_value::<Vec<DepOverride>>(read_json(&case.join("overrides.json")))
                .unwrap(),
        );
        assert_eq!(
            again.files,
            result.files,
            "{}: non-deterministic",
            case.display()
        );

        // Idempotent on its own output: re-run over the written file before
        // `sbt update` (the evidence predates the wiring), nothing more is
        // written or edited and the same uuids are confirmed.
        if !result.files.is_empty() {
            let mut wired = files.clone();
            wired.extend(result.files.clone());
            if let Some(text) = wired.get(SBT_RESOLUTION_KEY) {
                let mut doc = ResolutionDoc::parse(text).unwrap();
                doc.wiring_newer = true;
                wired.insert(SBT_RESOLUTION_KEY.to_string(), doc.to_json());
            }
            let overrides: Vec<DepOverride> =
                serde_json::from_value(read_json(&case.join("overrides.json"))).unwrap();
            let rerun = rewrite_registry_redirect(&wired, &overrides);
            assert!(
                rerun.files.is_empty() && rerun.edits.is_empty(),
                "{}: re-run over its own output changed {:?} / {:?}",
                case.display(),
                rerun.files.keys().collect::<Vec<_>>(),
                rerun.edits
            );
            assert_eq!(
                rerun.confirmed_sbt_uuids,
                result.confirmed_sbt_uuids,
                "{}: re-run confirms another set",
                case.display()
            );
        }

        // A run that created the file is undone by restoring its pins.
        if let (None, Some(_)) = (files.get(HOSTED_FILE), result.files.get(HOSTED_FILE)) {
            let mut wired = tree(&case.join("input"));
            wired.extend(result.files.clone());
            let overrides: Vec<DepOverride> =
                serde_json::from_value(read_json(&case.join("overrides.json"))).unwrap();
            let pins: Vec<HostedPin> = overrides
                .iter()
                .filter(|o| result.confirmed_sbt_uuids.contains(&o.patch_uuid))
                .map(|o| HostedPin {
                    purl: format!(
                        "pkg:maven/{}/{}@{}",
                        o.namespace.as_deref().unwrap_or_default(),
                        o.name,
                        o.version
                    ),
                    uuid: o.patch_uuid.clone(),
                    files: vec![HOSTED_FILE.to_string()],
                })
                .collect();
            assert_eq!(
                restore(&wired, &pins).await,
                None,
                "{}: restoring every pin must delete {HOSTED_FILE}",
                case.display()
            );
        }
    }
}

#[test]
fn every_case_ships_its_expectations() {
    for entry in fs::read_dir(root()).unwrap() {
        let case = entry.unwrap().path();
        if !case.join("input").is_dir() {
            continue;
        }
        let names: BTreeSet<&str> = if case.join("restore.json").is_file() {
            BTreeSet::from(["restore.json"])
        } else {
            BTreeSet::from([
                "overrides.json",
                "expected-edits.json",
                "expected-warnings.json",
                "expected-confirmation.json",
            ])
        };
        for name in names {
            assert!(
                case.join(name).is_file(),
                "{}: missing {name}",
                case.display()
            );
        }
    }
}
