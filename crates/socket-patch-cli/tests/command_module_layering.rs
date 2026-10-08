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
    (
        "get",
        "vendor",
        "get's vendored dry run previews vendor's gem takeover refusals",
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

/// The first path segment of each top-level item in the `{…}` group that
/// opens just before `rest` (`rest` starts after the `{`):
/// `get, scan::x, rollback::{a, b} }` → `["get", "scan", "rollback"]`.
fn group_heads(rest: &str) -> Vec<String> {
    let mut heads = Vec::new();
    let mut depth = 1usize;
    let mut at_item_start = true;
    let mut chars = rest.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            ',' if depth == 1 => at_item_start = true,
            c if depth == 1 && at_item_start && (c.is_ascii_alphabetic() || c == '_') => {
                let mut ident = c.to_string();
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_alphanumeric() || n == '_' {
                        ident.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                heads.push(ident);
                at_item_start = false;
            }
            _ => {}
        }
    }
    heads
}

/// The `commands` children that `code` (production source of a module at
/// `depth` below `commands`, comments stripped) references: absolute
/// `crate::commands::x` paths, `super::`-relative paths that climb exactly
/// to `commands`, and the heads of a `{…}` group after either prefix.
fn referenced_children(code: &str, depth: usize) -> BTreeSet<String> {
    let absolute = Regex::new(r"crate::commands::(?:([a-z_]+)|\{)").expect("regex");
    let relative = Regex::new(r"(?m)(?:^|[^\w:])((?:super::)+)(?:([a-z_]+)|\{)").expect("regex");
    let mut out = BTreeSet::new();
    let mut take = |name: Option<regex::Match>, end: usize| match name {
        Some(m) => {
            out.insert(m.as_str().to_string());
        }
        None => out.extend(group_heads(&code[end..])),
    };
    for cap in absolute.captures_iter(code) {
        take(cap.get(1), cap.get(0).expect("match").end());
    }
    for cap in relative.captures_iter(code) {
        // `super::` × n from `commands::<module…>` lands on `commands`
        // exactly when n equals the module depth.
        if cap[1].matches("super::").count() == depth {
            take(cap.get(2), cap.get(0).expect("match").end());
        }
    }
    out
}

/// Every `commands::<x>` → `commands::<y>` reference in production code
/// (test modules and comments excluded), as `(x, y)`.
fn module_edges() -> BTreeSet<(String, String)> {
    let dir = commands_dir();
    let children = child_modules(&dir);
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
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
        for target in referenced_children(&code, module.len()) {
            if children.contains(&target) && target != node {
                edges.insert((node.clone(), target));
            }
        }
    }
    edges
}

#[test]
fn edge_scanner_sees_every_import_form() {
    let names = |code: &str, depth: usize| -> Vec<String> {
        referenced_children(code, depth).into_iter().collect()
    };
    // Absolute paths, plain and grouped (nested groups count only their head).
    assert_eq!(names("use crate::commands::get::run;", 1), ["get"]);
    assert_eq!(
        names(
            "use crate::commands::{get, scan::{a, b}, rollback as r};",
            2
        ),
        ["get", "rollback", "scan"]
    );
    assert_eq!(
        names(
            "use crate::commands::{\n    vendor::x,\n    apply::{y, z},\n};",
            1
        ),
        ["apply", "vendor"]
    );
    // `super::` counts only when it climbs exactly to `commands`.
    assert_eq!(names("use super::rollback::x;", 1), ["rollback"]);
    assert_eq!(
        names("use super::{rollback::x, get::y};", 1),
        ["get", "rollback"]
    );
    assert_eq!(names("use super::{a, b};", 2), Vec::<String>::new());
    assert_eq!(names("use super::super::{get, scan};", 2), ["get", "scan"]);
    assert_eq!(names("let x = super::vendor::f();", 1), ["vendor"]);
    // Not a path: `foo::super::x` is not matched as a relative import.
    assert_eq!(names("foo::super::get", 1), Vec::<String>::new());
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

/// Edges that close a cycle this PR does not break, left out of the cycle
/// check. Each is also in [`ALLOWED_COMMAND_IMPORTS`], whose stale check
/// fails once the edge is gone, so the entry is deleted with it.
///
/// `vendor` → `vendored_backend` → `vendor`: `vendored_backend` is the
/// vendor command's engine facade and still calls back into
/// `vendor_records_reusing` / `dispatch_revert_one_opts` (#894 child 4).
const KNOWN_CYCLE_EDGES: &[(&str, &str)] = &[("vendored_backend", "vendor")];

#[test]
fn command_module_graph_has_no_cycles() {
    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (from, to) in module_edges() {
        if KNOWN_CYCLE_EDGES.contains(&(from.as_str(), to.as_str())) {
            continue;
        }
        graph.entry(from).or_default().insert(to);
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
