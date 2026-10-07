//! Command modules do not import each other, except along the edges
//! allowlisted below, and the module graph under `src/commands/` has no
//! cycles (#894).
//!
//! A command module is one behind a subcommand (`get`, `scan`, …). Helper
//! modules (`agent_download`, `hosted_unwind`, `vlt_heal`, `lock_cli`, …)
//! hold code more than one command runs; any module may import a helper.
//! An import INTO a command module is the coupling #894 is removing, so
//! each surviving one is listed here with the reason it still exists, and
//! a new one fails this test until it is either moved into a helper (or
//! `ui/`, or core) or deliberately added to the list.
//!
//! The list must also stay tight: an allowlisted edge the code no longer
//! has fails the test, so the entry is deleted in the PR that removes it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use regex::Regex;

/// The modules behind a subcommand (see `Commands` in `src/lib.rs`).
const COMMAND_MODULES: &[&str] = &[
    "apply",
    "get",
    "hosted_bundle",
    "list",
    "remove",
    "repair",
    "rollback",
    "scan",
    "update",
    "vendor",
    "vex",
];

/// Imports into a command module that still exist, `(from, to, why)`.
const ALLOWED_COMMAND_IMPORTS: &[(&str, &str, &str)] = &[
    // `get` runs one patch through the same three modes `scan` runs.
    (
        "get",
        "scan",
        "get dispatches to scan's hosted and vendored pipelines",
    ),
    (
        "get",
        "apply",
        "agent-mode get reports through ApplyRunReport/ApplyFailure",
    ),
    (
        "get",
        "vex",
        "get's vendored leg reads VexEmbedArgs defaults",
    ),
    // The agent download engine's nested apply still builds ApplyArgs.
    (
        "agent_download",
        "apply",
        "nested apply via ApplyArgs; #894 child 3 (waits on #793)",
    ),
    (
        "agent_download",
        "vendor",
        "lock refusals reuse vendor's pristine-fetch verification",
    ),
    // Embedded `--vex` (decision #966 Q2 / E42).
    ("apply", "vex", "embedded --vex"),
    ("scan", "vex", "embedded --vex"),
    ("vendor", "vex", "embedded --vex"),
    (
        "scan",
        "vendor",
        "scan --mode vendored runs the vendor engine",
    ),
    (
        "vendor",
        "apply",
        "vendored staging reuses apply's variant matching",
    ),
    ("rollback", "vendor", "rollback's vendored leg"),
    (
        "remove",
        "rollback",
        "remove runs rollback's agent engine; #894",
    ),
    // `vendored_backend` is the vendor command's engine facade; it moves
    // out of the command with `vendor_records_reusing` (#894 child 4).
    (
        "vendored_backend",
        "vendor",
        "vendor engine facade; #894 child 4",
    ),
];

fn commands_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The direct children of `commands` (files and directories).
fn child_modules(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("read_dir")
        .filter_map(|e| {
            let path = e.expect("dir entry").path();
            let name = path.file_stem()?.to_str()?.to_string();
            (name != "mod").then_some(name)
        })
        .collect()
}

/// Every `commands::<x>` → `commands::<y>` reference in production code
/// (test modules and comments excluded), as `(x, y)`.
fn module_edges() -> BTreeSet<(String, String)> {
    let dir = commands_dir();
    let children = child_modules(&dir);
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    let absolute = Regex::new(r"crate::commands::([a-z_]+)").expect("regex");
    let relative = Regex::new(r"(?m)(^|[^\w:])((?:super::)+)([a-z_]+)").expect("regex");
    let test_mod = Regex::new(r"\n#\[cfg\(test\)\]\s*\n(pub(\(crate\))? )?mod ").expect("regex");
    let mut edges = BTreeSet::new();
    for file in files {
        let rel: Vec<String> = file
            .strip_prefix(&dir)
            .expect("under commands/")
            .iter()
            .map(|c| c.to_string_lossy().trim_end_matches(".rs").to_string())
            .collect();
        if rel == ["mod"] {
            continue;
        }
        let node = rel[0].clone();
        // The file's module path below `commands`: `x/mod.rs` is `x`.
        let mut module: Vec<String> = rel.clone();
        if module.last().is_some_and(|m| m == "mod") {
            module.pop();
        }
        let src = std::fs::read_to_string(&file).expect("read source");
        let src = match test_mod.find(&src) {
            Some(m) => &src[..m.start()],
            None => &src[..],
        };
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut add = |target: &str| {
            if children.contains(target) && target != node {
                edges.insert((node.clone(), target.to_string()));
            }
        };
        for cap in absolute.captures_iter(&code) {
            add(&cap[1]);
        }
        for cap in relative.captures_iter(&code) {
            // `super::` × n from `commands::<module…>` lands on `commands`
            // exactly when n equals the module depth.
            if cap[2].matches("super::").count() == module.len() {
                add(&cap[3]);
            }
        }
    }
    edges
}

#[test]
fn command_modules_import_each_other_only_along_allowlisted_edges() {
    let edges = module_edges();
    assert!(
        edges.iter().any(|(from, _)| from == "scan"),
        "the scan must see scan's imports; did src/commands move?"
    );
    let allowed: BTreeSet<(String, String)> = ALLOWED_COMMAND_IMPORTS
        .iter()
        .map(|(from, to, _)| (from.to_string(), to.to_string()))
        .collect();
    let into_commands: BTreeSet<(String, String)> = edges
        .iter()
        .filter(|(_, to)| COMMAND_MODULES.contains(&to.as_str()))
        .cloned()
        .collect();
    let new: Vec<_> = into_commands.difference(&allowed).collect();
    assert!(
        new.is_empty(),
        "these modules import a command module; move the shared code into a helper \
         module, ui/ or core instead (or allowlist the edge with a reason): {new:?}"
    );
    let stale: Vec<_> = allowed.difference(&into_commands).collect();
    assert!(
        stale.is_empty(),
        "these allowlisted edges no longer exist; delete them from \
         ALLOWED_COMMAND_IMPORTS: {stale:?}"
    );
}

#[test]
fn command_module_graph_has_no_cycles() {
    // `vendored_backend` is the vendor command's own engine facade
    // (#894 child 4); fold it into `vendor` so the pair is one node.
    let fold = |m: &str| -> String {
        if m == "vendored_backend" {
            "vendor".to_string()
        } else {
            m.to_string()
        }
    };
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (from, to) in module_edges() {
        let (from, to) = (fold(&from), fold(&to));
        if from != to {
            graph.entry(from).or_default().insert(to);
        }
    }
    // Depth-first search for a back edge; report the cycle it closes.
    fn visit(
        node: &str,
        graph: &BTreeMap<String, BTreeSet<String>>,
        state: &mut BTreeMap<String, u8>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        match state.get(node) {
            Some(2) => return None,
            Some(1) => {
                let start = stack.iter().position(|n| n == node).expect("on stack");
                let mut cycle = stack[start..].to_vec();
                cycle.push(node.to_string());
                return Some(cycle);
            }
            _ => {}
        }
        state.insert(node.to_string(), 1);
        stack.push(node.to_string());
        for next in graph.get(node).into_iter().flatten() {
            if let Some(cycle) = visit(next, graph, state, stack) {
                return Some(cycle);
            }
        }
        stack.pop();
        state.insert(node.to_string(), 2);
        None
    }
    let mut state = BTreeMap::new();
    for node in graph.keys() {
        let mut stack = Vec::new();
        if let Some(cycle) = visit(node, &graph, &mut state, &mut stack) {
            panic!(
                "command modules import each other in a cycle: {}",
                cycle.join(" -> ")
            );
        }
    }
}
