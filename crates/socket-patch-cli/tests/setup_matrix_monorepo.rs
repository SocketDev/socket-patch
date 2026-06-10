//! setup-matrix: polyglot all-ecosystem monorepo.
//!
//! A single repo containing an npm workspace alongside
//! python/rust/go/php/ruby/nuget/deno manifests. Confirms `socket-patch
//! setup` works in this mixed environment — it must configure the npm
//! hooks and NOT choke on the foreign manifests; a root `npm install`
//! then applies the patch to the npm slice. Runs in the npm image (the
//! only one with the npm toolchain); the foreign manifests are present
//! to test setup's robustness, not installed.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_monorepo`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

use std::path::{Path, PathBuf};

/// The behavioral driver: scaffold the polyglot monorepo, run
/// `setup`/install/remove inside the npm image (or host), and assert each
/// matrix case meets its aspirational expectation plus the npm-family
/// check/remove round-trip. Soft-skips when docker/the image is absent.
#[test]
fn monorepo() {
    smc::run_monorepo();
}

// ---------------------------------------------------------------------------
// Static guards for the monorepo's DISTINCTIVE invariants.
//
// `run_monorepo()` reuses the generic harness, which treats `layout==monorepo`
// like any npm case and (a) soft-skips entirely when docker/the image is
// unavailable and (b) never inspects the polyglot fixture or the matrix spec.
// That makes the headline guarantee of THIS suite — "setup works in a mixed
// polyglot repo and does NOT choke on the foreign manifests" — completely
// unverified by the behavioral path whenever docker is missing, and even when
// present it would happily pass if the fixture were silently reduced to a plain
// npm project. These guards run with NO docker dependency and fail loudly if
// the polyglot scaffold, the matrix scenarios (incl. the negative controls), or
// the monorepo target wiring are ever hollowed out — i.e. they keep the
// behavioral test honestly *polyglot* rather than an npm test in disguise.
// ---------------------------------------------------------------------------

/// Workspace root = two levels up from this crate's manifest dir.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let p = workspace_root().join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// Extract the body of a `name() { ... }` bash function from the driver,
/// matched brace-for-brace so a refactor that moves/renames it is caught.
fn bash_fn_body<'a>(script: &'a str, name: &str) -> &'a str {
    let header = format!("{name}() {{");
    let start = script
        .find(&header)
        .unwrap_or_else(|| panic!("run-case.sh: function `{name}` not found"));
    let after = start + header.len();
    let rest = &script[after..];
    let mut depth = 1usize;
    for (i, c) in rest.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[..i];
                }
            }
            _ => {}
        }
    }
    panic!("run-case.sh: unbalanced braces in `{name}`");
}

/// The whole point of the monorepo case is exercising `setup` against a repo
/// that ALSO carries non-npm manifests. If the scaffold ever drops them, the
/// behavioral test silently becomes a plain npm test while still passing — so
/// pin that every foreign ecosystem manifest is created, plus the npm slice
/// `setup` is meant to patch.
#[test]
fn monorepo_scaffold_is_genuinely_polyglot() {
    let script = read("tests/setup_matrix/run-case.sh");
    let body = bash_fn_body(&script, "scaffold_monorepo");

    // The npm workspace slice — the surface `setup` actually patches.
    assert!(
        body.contains("package.json") && body.contains("workspaces"),
        "scaffold_monorepo no longer creates the npm workspace root — the patched \
         slice would not exist:\n{body}"
    );

    // One representative manifest per FOREIGN ecosystem named in the suite's
    // contract (python, rust, go, php, ruby, deno, nuget). `setup` must tolerate
    // each of these sitting next to the npm project; dropping any one quietly
    // narrows what "does not choke on foreign manifests" actually tests.
    let foreign: &[(&str, &str)] = &[
        ("python", "pyproject.toml"),
        ("rust", "Cargo.toml"),
        ("go", "go.mod"),
        ("php", "composer.json"),
        ("ruby", "Gemfile"),
        ("deno", "deno.json"),
        ("nuget", ".csproj"),
    ];
    let missing: Vec<&str> = foreign
        .iter()
        .filter(|(_, manifest)| !body.contains(manifest))
        .map(|(eco, _)| *eco)
        .collect();
    assert!(
        missing.is_empty(),
        "scaffold_monorepo is no longer polyglot — missing foreign manifest(s) for: {missing:?}. \
         The monorepo suite would degrade to a plain npm test and stop proving setup tolerates \
         foreign manifests.\n{body}"
    );

    // Foreign manifests must be REAL (non-npm) ecosystems, not more npm. Require
    // at least the distinctive non-JSON manifests so the fixture can't be faked
    // with a pile of package.json files.
    for distinctive in ["Cargo.toml", "go.mod", "Gemfile"] {
        assert!(
            body.contains(distinctive),
            "scaffold_monorepo dropped the `{distinctive}` manifest"
        );
    }
}

/// The harness only runs the check/remove round-trip + LEAK detection when
/// `is_npm_family()` is true, which for the monorepo hinges on
/// `layout == "monorepo"`. Pin that the wiring still routes monorepo through
/// that branch (npm image, baseline_supported) so the case can't silently fall
/// into the untested "foreign ecosystem, no round-trip" bucket.
#[test]
fn monorepo_target_routes_through_npm_round_trip() {
    let spec: serde_json::Value =
        serde_json::from_str(&read("tests/setup_matrix/matrix.json")).expect("parse matrix.json");

    let targets = spec["monorepo_targets"]
        .as_array()
        .expect("monorepo_targets array");
    assert_eq!(
        targets.len(),
        1,
        "expected exactly one monorepo target; got {}",
        targets.len()
    );
    let t = &targets[0];
    assert_eq!(
        t["ecosystem"], "monorepo",
        "monorepo target ecosystem changed"
    );
    assert_eq!(t["pm"], "mono", "monorepo target pm changed");
    assert_eq!(
        t["image"], "npm",
        "monorepo must run in the npm image (only toolchain that can install it)"
    );
    assert_eq!(
        t["baseline_supported"], true,
        "monorepo baseline_supported flipped to false — the npm slice IS supported today, so a \
         non-applying install must classify as a REGRESSION, not a tolerated BASELINE GAP"
    );
    // The patched slice must be the npm package (minimist), proving the npm
    // slice — not a foreign one — is what the round-trip exercises.
    assert_eq!(
        t["purl"], "pkg:npm/minimist@1.2.2",
        "monorepo target purl changed — the patched slice is no longer the npm dependency"
    );
    assert!(
        t["manifest_key"]
            .as_str()
            .unwrap_or("")
            .contains("index.js"),
        "monorepo manifest_key no longer points at the npm package file"
    );
    assert_eq!(
        t["apply_ecosystems"], "npm",
        "monorepo apply_ecosystems changed — should patch only the npm slice"
    );
}

/// The matrix's negative controls are what keep a "patch always applies" bug
/// honest: a no-setup ablation (hook absent ⇒ must NOT apply) and a
/// patch-missing ablation (hook present but no committed patchset ⇒ must NOT
/// apply). Pin that all three monorepo scenarios — the positive plus both
/// controls — are present with the expected `run_setup`/`expect_applied`
/// polarity, so dropping a control can't quietly remove the guard.
#[test]
fn monorepo_scenarios_keep_their_negative_controls() {
    let spec: serde_json::Value =
        serde_json::from_str(&read("tests/setup_matrix/matrix.json")).expect("parse matrix.json");

    let scenarios = spec["monorepo_scenarios"]
        .as_array()
        .expect("monorepo_scenarios array");

    // id -> (run_setup, expect_applied)
    let find = |id: &str| -> (bool, bool) {
        let s = scenarios
            .iter()
            .find(|s| s["id"] == id)
            .unwrap_or_else(|| panic!("monorepo scenario `{id}` missing from matrix.json"));
        (
            s["run_setup"]
                .as_bool()
                .unwrap_or_else(|| panic!("`{id}`.run_setup not a bool")),
            s["expect_applied"]
                .as_bool()
                .unwrap_or_else(|| panic!("`{id}`.expect_applied not a bool")),
        )
    };

    // Positive: setup runs, primary patchset, must apply.
    assert_eq!(
        find("monorepo_with_setup"),
        (true, true),
        "positive monorepo scenario must run setup AND expect the patch applied"
    );
    // Negative control #1: no setup ⇒ no hook ⇒ must NOT apply.
    assert_eq!(
        find("monorepo_no_setup"),
        (false, false),
        "no-setup ablation must NOT run setup and must expect NOT applied (proves the hook, not \
         install alone, is what applies the patch)"
    );
    // Negative control #2: setup runs but no committed patchset ⇒ must NOT apply.
    assert_eq!(
        find("monorepo_patch_missing"),
        (true, false),
        "patch-missing ablation must run setup yet expect NOT applied (proves the committed \
         patchset, not setup/install alone, is what changes the code)"
    );

    // Guard against a fourth scenario being added that quietly expects-applied
    // without a matching control; at minimum the two negative controls must
    // outnumber-or-equal the positives so the suite can't become all-positive.
    let positives = scenarios
        .iter()
        .filter(|s| s["expect_applied"].as_bool().unwrap_or(false))
        .count();
    let negatives = scenarios.len() - positives;
    assert!(
        negatives >= positives && negatives >= 2,
        "monorepo scenarios lost their negative controls (positives={positives}, \
         negatives={negatives}); a 'patch always applies' regression could pass"
    );
}

/// Defensive cross-check on the harness routing: `layout == "monorepo"` is the
/// ONLY thing that makes a non-npm-family `pm` (here `mono`) take the
/// round-trip + LEAK-detection path. If the driver's `is_npm_family` gate ever
/// stops honoring the monorepo layout, the behavioral guarantees silently
/// vanish. Pin the driver still gates on the monorepo layout.
#[test]
fn driver_round_trip_still_gated_on_monorepo_layout() {
    let script = read("tests/setup_matrix/run-case.sh");
    let body = bash_fn_body(&script, "is_npm_family");
    assert!(
        body.contains("SM_LAYOUT") && body.contains("monorepo"),
        "run-case.sh is_npm_family no longer treats the monorepo layout as round-trip-eligible — \
         the monorepo would skip the check/remove + LEAK assertions:\n{body}"
    );
}
