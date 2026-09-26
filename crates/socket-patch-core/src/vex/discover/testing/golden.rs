//! Golden snapshot of [`discover_patched_refs`] over the committed fixture
//! projects — a compact regression pin for discovery and the lock readers it
//! shares with the rewriters and `vendor::lock_inventory`.
//!
//! The corpus is every project under `tests/fixtures/`: each redirect case's
//! `input/` and `expected/` tree, every real-package-manager capture
//! (`pnpm-hosted/<v>`, `poetry/<v>`, `pipenv/<v>`, `bun-lockb/<v>`, …), and
//! each `pdm-native/<v>.lock` staged as a project's `pdm.lock`, run through
//! the full orchestrator. [`render`] captures every field [`Discovery`]
//! exposes, plus the hosted / vendored ledger claims it answers.
//!
//! Goldens: one file per fixture family,
//! `tests/fixtures/vex-discover-golden/<family>.json` (`redirect-<eco>` for
//! the redirect cases, the top-level directory name otherwise), mapping each
//! fixture path to its rendered discovery. The set is self-maintaining: a
//! fixture without a golden entry fails, and an entry or family file
//! without a fixture fails (regeneration drops it).
//!
//! Regenerate after an INTENDED behavior change (and review the diff):
//!
//! ```text
//! SOCKET_PATCH_UPDATE_GOLDEN=1 cargo test -p socket-patch-core --lib vex::discover::testing::golden
//! ```
//!
//! Unix only: Windows checkouts convert some fixtures' line endings (only
//! `redirect/**`, `pdm-native/*.lock` and `pnpm-hosted/**` are `-text`),
//! and I/O error texts differ, so the snapshot would describe different
//! inputs. The Unix legs (Linux + macOS) pin the behavior.
//!
//! [`discover_patched_refs`]: crate::vex::discover::discover_patched_refs
#![cfg(not(windows))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::vex::discover::{
    Diag, Discovery, PatchedRef, Recognized, ResolvedElsewhere, UnlockedPin, WiringMode,
};

/// Set to `1` to (re)write the goldens instead of comparing against them.
const UPDATE_ENV: &str = "SOCKET_PATCH_UPDATE_GOLDEN";

fn updating() -> bool {
    std::env::var_os(UPDATE_ENV).is_some_and(|v| v == "1")
}

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// The golden directory (itself under `tests/fixtures/`, so the corpus
/// walker skips it).
const GOLDEN_DIR: &str = "vex-discover-golden";

// ── rendering ────────────────────────────────────────────────────────────

fn mode(m: WiringMode) -> &'static str {
    match m {
        WiringMode::Hosted => "hosted",
        WiringMode::Vendored => "vendored",
    }
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// `text` with every spelling of the project root replaced by `<root>` and
/// OS error numbers (which differ between Linux and macOS) dropped.
fn normalize(text: &str, roots: &[String]) -> String {
    let mut out = text.to_string();
    for root in roots {
        if !root.is_empty() {
            out = out.replace(root.as_str(), "<root>");
        }
    }
    // `… (os error 21)` → `… (os error)`.
    let mut normalized = String::with_capacity(out.len());
    let mut rest = out.as_str();
    while let Some(at) = rest.find("(os error ") {
        let after = &rest[at + "(os error ".len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 && after[digits..].starts_with(')') {
            normalized.push_str(&rest[..at]);
            normalized.push_str("(os error)");
            rest = &after[digits + 1..];
        } else {
            normalized.push_str(&rest[..at + 1]);
            rest = &rest[at + 1..];
        }
    }
    normalized.push_str(rest);
    normalized
}

/// Every spelling of `root` a detail string could carry.
fn root_spellings(root: &Path) -> Vec<String> {
    let mut spellings = vec![path_str(root)];
    if let Ok(canonical) = std::fs::canonicalize(root) {
        spellings.push(path_str(&canonical));
    }
    // Longest first, so `/private/var/…` is replaced before `/var/…`.
    spellings.sort_by_key(|s| std::cmp::Reverse(s.len()));
    spellings.dedup();
    spellings
}

/// A stable JSON rendering of everything `out` exposes. The destructuring
/// is exhaustive on purpose: a new field fails to compile here until the
/// golden covers it.
fn render(out: &Discovery, root: &Path) -> Value {
    let roots = root_spellings(root);
    let Discovery {
        refs,
        diagnostics,
        recognized,
        unlocked_pins,
        elsewhere,
    } = out;
    let refs: Vec<Value> = refs
        .iter()
        .map(|r| {
            let PatchedRef {
                purl,
                uuid,
                mode: m,
                source_file,
                artifact_rel,
                locked_integrity,
                integrity_required,
                url,
            } = r;
            json!({
                "purl": purl,
                "uuid": uuid,
                "mode": mode(*m),
                "source_file": path_str(source_file),
                "artifact_rel": artifact_rel,
                "locked_integrity": locked_integrity.as_ref().map(|i| format!("{i:?}")),
                "integrity_required": integrity_required,
                "url": url,
                "lockfile_basis_ok": r.lockfile_basis_ok(),
            })
        })
        .collect();
    let diagnostics: Vec<Value> = diagnostics
        .iter()
        .map(|d| {
            let Diag { code, file, detail } = d;
            json!({
                "code": code,
                "file": path_str(file),
                "detail": normalize(detail, &roots),
            })
        })
        .collect();
    let recognized_rendered: Vec<Value> = recognized
        .iter()
        .map(|r| {
            let Recognized {
                uuid,
                mode: m,
                file,
            } = r;
            json!({ "uuid": uuid, "mode": mode(*m), "file": path_str(file) })
        })
        .collect();
    let unlocked_pins: Vec<Value> = unlocked_pins
        .iter()
        .map(|p| {
            let UnlockedPin {
                ecosystem,
                name,
                uuid,
                file,
                version_reqs,
            } = p;
            json!({
                "ecosystem": ecosystem,
                "name": name,
                "uuid": uuid,
                "file": path_str(file),
                "version_reqs": version_reqs,
            })
        })
        .collect();
    let elsewhere_rendered: Vec<Value> = elsewhere
        .iter()
        .map(|e| {
            let ResolvedElsewhere { purl, file } = e;
            json!({ "purl": purl, "file": path_str(file) })
        })
        .collect();
    json!({
        "refs": refs,
        "diagnostics": diagnostics,
        "recognized": recognized_rendered,
        "unlocked_pins": unlocked_pins,
        "elsewhere": elsewhere_rendered,
        "live_claims": live_claims(out),
    })
}

/// The ledger claims discovery answers `Some(true)` for, over every
/// recognized uuid × every package any lock names (refs, non-Socket
/// entries, and each lockless pin's name at the versions the locks name).
/// A recognized uuid answers `Some(false)` for every other candidate, and
/// an unrecognized one `None`, so this list pins both claim methods.
fn live_claims(out: &Discovery) -> Vec<Value> {
    let mut purls: BTreeSet<String> = out.refs.iter().map(|r| r.purl.clone()).collect();
    purls.extend(out.elsewhere.iter().map(|e| e.purl.clone()));
    let versions: BTreeSet<String> = purls
        .iter()
        .filter_map(|p| p.rsplit_once('@').map(|(_, v)| v.to_string()))
        .collect();
    for pin in &out.unlocked_pins {
        for version in &versions {
            purls.insert(format!("pkg:{}/{}@{version}", pin.ecosystem, pin.name));
        }
    }
    let uuids: BTreeSet<(String, WiringMode)> = out
        .recognized
        .iter()
        .map(|r| (r.uuid.clone(), r.mode))
        .collect();
    let artifacts: BTreeSet<String> = out
        .refs
        .iter()
        .filter_map(|r| r.artifact_rel.clone())
        .collect();
    let mut claims = Vec::new();
    for (uuid, m) in &uuids {
        for purl in &purls {
            match m {
                WiringMode::Hosted => {
                    if out.hosted_claim(purl, uuid) == Some(true) {
                        claims.push(json!({ "mode": "hosted", "uuid": uuid, "purl": purl }));
                    }
                }
                WiringMode::Vendored => {
                    for artifact in &artifacts {
                        if out.vendored_claim(purl, uuid, artifact) == Some(true) {
                            claims.push(json!({
                                "mode": "vendored",
                                "uuid": uuid,
                                "purl": purl,
                                "artifact_rel": artifact,
                            }));
                        }
                    }
                }
            }
        }
    }
    claims
}

// ── the committed fixture corpus ──────────────────────────────────────────

/// `(fixture-relative name, project root, staged tempdir keeping it alive)`.
type CorpusEntry = (String, PathBuf, Option<tempfile::TempDir>);

/// Every project the committed fixtures describe (see the module docs).
fn corpus() -> Vec<CorpusEntry> {
    let root = fixtures_root();
    let mut out: Vec<CorpusEntry> = Vec::new();
    let mut tops: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("read fixtures root")
        .map(|e| e.expect("fixture entry").path())
        .filter(|p| p.is_dir())
        .collect();
    tops.sort();
    for top in tops {
        let name = top.file_name().unwrap().to_string_lossy().into_owned();
        match name.as_str() {
            GOLDEN_DIR => {}
            // Tables and store listings, not projects.
            "vlt" | "vlt-trees" | "vendor" => {}
            // Redirect cases: `<eco>/<flavor>/<case>/{input,expected}` —
            // each side is a project root (nested files included).
            "redirect" => {
                let mut dirs = Vec::new();
                collect_dirs(&top, &mut dirs);
                for dir in dirs {
                    let base = dir.file_name().unwrap().to_string_lossy().into_owned();
                    let is_case_side = (base == "input" || base == "expected")
                        && dir.parent().is_some_and(|c| c.join("input").is_dir());
                    if is_case_side {
                        out.push((rel(&root, &dir), dir, None));
                    }
                }
            }
            // Native PDM locks, named by version: each staged as a
            // project's `pdm.lock`.
            "pdm-native" => {
                let mut locks: Vec<PathBuf> = std::fs::read_dir(&top)
                    .expect("read pdm-native")
                    .map(|e| e.expect("pdm entry").path())
                    .filter(|p| p.extension().is_some_and(|x| x == "lock"))
                    .collect();
                locks.sort();
                for lock in locks {
                    let staged = tempfile::tempdir().expect("stage pdm project");
                    std::fs::copy(&lock, staged.path().join("pdm.lock")).expect("stage pdm.lock");
                    let name = rel(&root, &lock.with_extension(""));
                    out.push((name, staged.path().to_path_buf(), Some(staged)));
                }
            }
            // Real-package-manager captures: every directory holding a
            // file other than a README is one project.
            _ => {
                let mut dirs = vec![top.clone()];
                collect_dirs(&top, &mut dirs);
                for dir in dirs {
                    let has_input = std::fs::read_dir(&dir)
                        .expect("read fixture dir")
                        .filter_map(Result::ok)
                        .any(|e| {
                            e.path().is_file()
                                && !e.file_name().to_string_lossy().starts_with("README")
                        });
                    if has_input {
                        out.push((rel(&root, &dir), dir, None));
                    }
                }
            }
        }
    }
    out
}

/// The golden file a fixture's entry lives in: `redirect-<eco>` for a
/// redirect case, the top-level fixture directory otherwise.
fn family(name: &str) -> String {
    let mut parts = name.split('/');
    let top = parts.next().expect("fixture name");
    match (top, parts.next()) {
        ("redirect", Some(eco)) => format!("redirect-{eco}"),
        _ => top.to_string(),
    }
}

fn collect_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut subdirs: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read fixture dir")
        .map(|e| e.expect("fixture entry").path())
        .filter(|p| p.is_dir())
        .collect();
    subdirs.sort();
    for sub in subdirs {
        out.push(sub.clone());
        collect_dirs(&sub, out);
    }
}

fn rel(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .map(path_str)
        .expect("fixture-relative")
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).expect("render golden json");
    s.push('\n');
    s
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vex::discover::discover_patched_refs;

    /// Every committed fixture project's full discovery output matches its
    /// golden entry (see the module docs).
    #[tokio::test]
    async fn committed_fixture_corpus_matches_golden() {
        let golden_dir = fixtures_root().join(GOLDEN_DIR);
        let corpus = corpus();
        // A floor, not a count: losing a whole fixture family (bad rebase,
        // a walker bug) must fail, while adding fixtures must not.
        assert!(corpus.len() >= 150, "corpus shrank to {}", corpus.len());

        let mut families: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
        for (name, root, _staged) in &corpus {
            let out = discover_patched_refs(root).await;
            crate::vex::discover::testing::assert_recognition_covers_refs(
                &out,
                &out.recognized,
                "`recognized`",
                None,
            );
            families
                .entry(family(name))
                .or_default()
                .insert(name.clone(), render(&out, root));
        }

        let present: BTreeSet<PathBuf> = std::fs::read_dir(&golden_dir)
            .map(|entries| {
                entries
                    .map(|e| e.expect("golden entry").path())
                    .filter(|p| p.extension().is_some_and(|x| x == "json"))
                    .collect()
            })
            .unwrap_or_default();
        let update = updating();
        let mut expected_files = BTreeSet::new();
        let mut failures = Vec::new();
        for (fam, rendered) in &families {
            let file = golden_dir.join(format!("{fam}.json"));
            expected_files.insert(file.clone());
            if update {
                let text = pretty(&Value::Object(rendered.clone()));
                if std::fs::read_to_string(&file).ok().as_deref() != Some(text.as_str()) {
                    std::fs::create_dir_all(&golden_dir).expect("create golden dir");
                    std::fs::write(&file, text).expect("write golden");
                }
                continue;
            }
            let want: Map<String, Value> = match std::fs::read_to_string(&file) {
                Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                    panic!("{}: golden is not a JSON object: {e}", file.display())
                }),
                Err(_) => {
                    failures.push(format!("{fam}: no golden at {}", file.display()));
                    continue;
                }
            };
            for (name, actual) in rendered {
                match want.get(name) {
                    Some(w) if w == actual => {}
                    Some(w) => failures.push(format!(
                        "{name}: discovery output changed\n--- golden ({})\n{}--- actual\n{}",
                        file.display(),
                        pretty(w),
                        pretty(actual)
                    )),
                    None => failures.push(format!("{name}: no entry in {}", file.display())),
                }
            }
            for stale in want.keys().filter(|k| !rendered.contains_key(*k)) {
                failures.push(format!(
                    "{stale}: {} entry has no fixture project",
                    file.display()
                ));
            }
        }
        for stale in present.difference(&expected_files) {
            if update {
                std::fs::remove_file(stale).expect("remove stale golden");
            } else {
                failures.push(format!("{}: golden has no fixture family", stale.display()));
            }
        }
        assert!(
            failures.is_empty(),
            "{} mismatches over {} corpus projects:\n\n{}\n\nif the change is intended, \
             regenerate with `{UPDATE_ENV}=1 cargo test -p socket-patch-core --lib \
             vex::discover::testing::golden` and review the golden diff",
            failures.len(),
            corpus.len(),
            failures.join("\n\n"),
        );
    }

    #[test]
    fn normalize_drops_roots_and_os_error_numbers() {
        let roots = vec!["/private/tmp/x".to_string(), "/tmp/x".to_string()];
        assert_eq!(
            normalize(
                "cannot read /tmp/x/a: Is a directory (os error 21); /private/tmp/x/b (os error)",
                &roots
            ),
            "cannot read <root>/a: Is a directory (os error); <root>/b (os error)"
        );
    }

    #[test]
    fn table_fixture_dirs_are_not_corpus_projects() {
        let corpus = corpus();
        for skipped in ["vlt/", "vlt-trees/", "vendor/"] {
            assert!(
                corpus.iter().all(|(name, _, _)| !name.starts_with(skipped)),
                "{skipped} fixtures joined the corpus"
            );
        }
        assert!(fixtures_root().join("vlt/collation-golden.json").is_file());
    }

    #[test]
    fn families_group_redirect_cases_by_ecosystem() {
        assert_eq!(family("redirect/npm/bun/case/input"), "redirect-npm");
        assert_eq!(family("bun-lockb/1.2.23-extensions"), "bun-lockb");
        assert_eq!(family("pdm-native/2.20"), "pdm-native");
    }
}
