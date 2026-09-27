//! Static setup-matrix wiring guards that need neither docker nor the
//! `setup-e2e` feature, so the default test run keeps them honest.

use std::path::{Path, PathBuf};

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

/// The body of a `name() { ... }` bash function, matched brace for brace.
fn bash_fn_body<'a>(script: &'a str, name: &str) -> &'a str {
    let header = format!("{name}() {{");
    let start = script
        .find(&header)
        .unwrap_or_else(|| panic!("run-case.sh: function `{name}` not found"));
    let rest = &script[start + header.len()..];
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

/// vlt is an npm-family row of the matrix: it runs in the npm image, gets
/// npm's `npx` hook, takes the round-trip path, and its scaffolds carry the
/// vlt.json marker (with registry config) that `setup` detects vlt by.
/// The docker legs soft-skip, so this pins the wiring they would exercise.
#[test]
fn vlt_targets_route_through_the_npm_round_trip() {
    let spec: serde_json::Value =
        serde_json::from_str(&read("tests/setup_matrix/matrix.json")).expect("parse matrix.json");
    for section in ["targets", "workspace_targets"] {
        let vlt: Vec<&serde_json::Value> = spec[section]
            .as_array()
            .unwrap_or_else(|| panic!("{section} array"))
            .iter()
            .filter(|t| t["pm"] == "vlt")
            .collect();
        assert_eq!(vlt.len(), 1, "{section}: one vlt target");
        let t = vlt[0];
        assert_eq!(t["ecosystem"], "npm", "{section}");
        assert_eq!(t["image"], "npm", "{section}");
        assert_eq!(t["hook_family"], "npm", "{section}: vlt uses the npx hook");
        assert_eq!(t["baseline_supported"], true, "{section}");
    }

    let script = read("tests/setup_matrix/run-case.sh");
    assert!(
        bash_fn_body(&script, "is_npm_family").contains("vlt"),
        "vlt must take the check/remove round trip"
    );
    for scaffold in ["scaffold_project", "scaffold_workspace"] {
        let body = bash_fn_body(&script, scaffold);
        let arm = body
            .split("\n    vlt)")
            .nth(1)
            .unwrap_or_else(|| panic!("{scaffold} has no vlt arm"));
        let arm = &arm[..arm.find(";;").expect("vlt arm ends")];
        assert!(
            arm.contains("vlt_json"),
            "{scaffold}: vlt.json marker:\n{arm}"
        );
    }
    assert!(
        bash_fn_body(&script, "scaffold_workspace").contains("\"workspaces\""),
        "the vlt workspace is declared in vlt.json"
    );
    let vlt_json = bash_fn_body(&script, "vlt_json");
    assert!(
        vlt_json.contains("\"registries\"") && vlt_json.contains("\"registry\""),
        "vlt >= 1.0.0-rc.33 installs need a registry config:\n{vlt_json}"
    );
}
