//! Shared golden-fixture test for the registry-redirect rewriters — the Rust
//! CLI half of the cross-language consistency contract. Consumes the SAME
//! `tests/fixtures/redirect/<eco>/<flavor>/<case>/` fixtures the depscan
//! backend's TS `golden.test.ts` consumes, and asserts this CLI produces the
//! byte-identical `expected/` files + `expected-edits.json`. A fixture's
//! `expected/` bytes were authored by the TS backend, so a match here proves a
//! customer gets the same lockfile whether Socket opens the PR (backend) or
//! they run `socket-patch scan --redirect` locally (this CLI).
//!
//! `RUST_IMPLEMENTED` lists the eco/flavor pairs this CLI rewrites today —
//! covering JSON round-trip (npm, nuget), text-line (requirements, yarn), the
//! multi-file per-dependency registry override (cargo, gem), and surgical XML
//! (nuget.config, maven pom). Any shared fixture not yet ported is skipped
//! here (logged) rather than silently ignored.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use socket_patch_core::patch::redirect::{rewrite_registry_redirect, DepOverride};

const RUST_IMPLEMENTED: &[&str] = &[
    "npm/package-lock-v3",
    "npm/pnpm",
    "npm/yarn-classic",
    "pypi/requirements",
    "pypi/uv",
    "cargo/cargo",
    "composer/composer-lock",
    "nuget/packages-lock",
    "gem/bundler",
    "maven/pom",
];

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn case_dirs(root: &Path) -> Vec<PathBuf> {
    fn recurse(dir: &Path, cases: &mut Vec<PathBuf>) {
        if dir.join("input").is_dir() {
            cases.push(dir.to_path_buf());
            return;
        }
        for entry in fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                recurse(&p, cases);
            }
        }
    }
    let mut cases = vec![];
    recurse(root, &mut cases);
    cases.sort();
    cases
}

fn rel_key(base: &Path, file: &Path) -> String {
    file.strip_prefix(base)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn redirect_golden_fixtures_match() {
    let root = fixtures_root();
    assert!(root.is_dir(), "fixtures root missing: {}", root.display());
    let cases = case_dirs(&root);
    assert!(
        !cases.is_empty(),
        "no golden cases found under {}",
        root.display()
    );

    let mut asserted = 0;
    for case in &cases {
        let rel = rel_key(&root, case);
        // rel = "<eco>/<flavor>/<case>"; eco_flavor = "<eco>/<flavor>".
        let eco_flavor = rel.rsplit_once('/').map(|(a, _)| a).unwrap_or(rel.as_str());
        if !RUST_IMPLEMENTED.contains(&eco_flavor) {
            eprintln!("skip (TS-only, not yet ported to CLI): {rel}");
            continue;
        }

        let input_dir = case.join("input");
        let mut input_files = vec![];
        walk(&input_dir, &mut input_files);
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        for f in &input_files {
            files.insert(rel_key(&input_dir, f), fs::read_to_string(f).unwrap());
        }

        let overrides: Vec<DepOverride> =
            serde_json::from_str(&fs::read_to_string(case.join("overrides.json")).unwrap())
                .unwrap_or_else(|e| panic!("{rel}: bad overrides.json: {e}"));

        let result = rewrite_registry_redirect(&files, &overrides);

        // Every expected file is produced byte-for-byte. A no-op case (e.g.
        // an idempotent re-run) changes no files and so has no `expected/`
        // dir — treat that as "zero expected files" rather than erroring.
        let expected_dir = case.join("expected");
        let mut expected_files = vec![];
        if expected_dir.is_dir() {
            walk(&expected_dir, &mut expected_files);
        }
        let mut expected_keys: Vec<String> = vec![];
        for f in &expected_files {
            let key = rel_key(&expected_dir, f);
            let want = fs::read_to_string(f).unwrap();
            assert_eq!(
                result.files.get(&key).map(String::as_str),
                Some(want.as_str()),
                "{rel}: {key} byte-mismatch"
            );
            expected_keys.push(key);
        }
        expected_keys.sort();
        let mut got_keys: Vec<String> = result.files.keys().cloned().collect();
        got_keys.sort();
        assert_eq!(got_keys, expected_keys, "{rel}: changed-file set mismatch");

        // Edits match the recorded ledger (map fields compare order-insensitive).
        let edits_path = case.join("expected-edits.json");
        if edits_path.is_file() {
            let expected: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&edits_path).unwrap()).unwrap();
            let got = serde_json::to_value(&result.edits).unwrap();
            assert_eq!(got, expected, "{rel}: edits mismatch");
        }

        // Determinism: a second run yields identical bytes.
        let again = rewrite_registry_redirect(&files, &overrides);
        assert_eq!(again.files, result.files, "{rel}: non-deterministic");

        asserted += 1;
    }
    assert!(
        asserted >= RUST_IMPLEMENTED.len(),
        "expected to assert all {} implemented ecosystems, got {asserted}",
        RUST_IMPLEMENTED.len()
    );
}
