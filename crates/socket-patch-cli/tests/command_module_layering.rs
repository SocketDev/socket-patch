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
//!
//! The second half is a source scan over `src/bazel_gate/*.rs`, the
//! command seams of the Bazel layer ([`seam_problems`]). A seam is written
//! once and a lane lands later behind it, so a seam must not build in
//! what a lane changes: it takes its contexts from the loader, hands
//! plans to the executor and names no file socket-patch owns. No type
//! enforces that, so this scan does, and it covers a seam file from the
//! day the file exists.

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

// ── The Bazel seam files ─────────────────────────────────────────────

/// The types a seam never matches on (revision 4, seam contract item 1):
/// the executor, `Code::withheld` and `Level::of_required_run` take them
/// whole. A match needs `Type::Variant`, so that spelling is what the
/// scan looks for.
const SEAM_OPAQUE_TYPES: [&str; 9] = [
    "WriteClass",
    "OwnedWrite",
    "HookKind",
    "TagOp",
    "RunKind",
    "Anchor",
    "AttestBasis",
    "StaleBehaviour",
    "WithholdKind",
];

/// The types a seam takes from the loader or builds by struct update
/// only, each with a rule of its own in [`seam_problems`].
const SEAM_CONTEXT_TYPES: [&str; 3] = ["LaneCx", "GateCx", "RunCx"];

/// What marks a string literal as a path socket-patch owns under a Bazel
/// root: the owned directory, and the names of the owned files that no
/// other file has. A seam takes such a path from `exec::touched` or from
/// the constants of `bazel::owned_index`, so that a change of the layout
/// edits no seam.
fn owned_path_marks() -> Vec<&'static str> {
    use socket_patch_core::bazel::owned_index::{
        OWNED_BZL_PATH, OWNED_DIR, OWNED_RC_PATH, OWNED_SEGMENT_PATH,
    };
    let name = |path: &'static str| path.rsplit('/').next().expect("a file name");
    let files = [OWNED_RC_PATH, OWNED_SEGMENT_PATH, OWNED_BZL_PATH].map(name);
    std::iter::once(OWNED_DIR).chain(files).collect()
}

/// The owned directory component by component (`.socket`, `bazel`): the
/// spelling of a path that is built with one `join` per level, which is
/// how most paths in this code base are built.
fn owned_dir_levels() -> Vec<&'static str> {
    socket_patch_core::bazel::owned_index::OWNED_DIR
        .split('/')
        .collect()
}

/// The owned files whose names other files have too: the index, and the
/// pins file reserved beside it. As one whole literal, such a name is an
/// owned path only where a path is being built: after the levels of the
/// owned directory, or as the argument of a `join` or a `push`.
/// (`apply.lock`, `patches` and `BUILD.bazel` are left out on purpose:
/// too many files that are nobody's carry those names.)
fn owned_file_names() -> [&'static str; 2] {
    let index = socket_patch_core::bazel::owned_index::INDEX_PATH;
    let index = index.rsplit('/').next().expect("a file name");
    [index, "pins.json"]
}

/// Rust source with what a scan must not read taken out: `masked` is the
/// source, byte for byte, with every comment and the content of every
/// string literal blanked, and `literals` are the content ranges of the
/// string literals in the source.
struct Lexed {
    masked: String,
    literals: Vec<std::ops::Range<usize>>,
}

/// A lexer for exactly that: line and (nested) block comments, plain,
/// byte and raw strings, and char literals, which may hold a `"` or a
/// brace. Delimiters are ASCII, so it runs over bytes and blanks whole
/// characters.
fn lex(src: &str) -> Lexed {
    let bytes = src.as_bytes();
    let mut masked = bytes.to_vec();
    let mut literals = Vec::new();
    let blank = |masked: &mut Vec<u8>, range: std::ops::Range<usize>| {
        for at in range {
            if masked[at] != b'\n' {
                masked[at] = b' ';
            }
        }
    };
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        let after_ident = at > 0 && ident(bytes[at - 1]);
        if rest.starts_with(b"//") {
            let end = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
            blank(&mut masked, at..at + end);
            at += end;
        } else if rest.starts_with(b"/*") {
            let (mut depth, mut end) = (0usize, 0usize);
            while end < rest.len() {
                if rest[end..].starts_with(b"/*") {
                    depth += 1;
                    end += 2;
                } else if rest[end..].starts_with(b"*/") {
                    depth -= 1;
                    end += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    end += 1;
                }
            }
            blank(&mut masked, at..at + end);
            at += end;
        } else if rest[0] == b'"' {
            let mut end = 1;
            while end < rest.len() && rest[end] != b'"' {
                end += if rest[end] == b'\\' { 2 } else { 1 };
            }
            let end = end.min(rest.len());
            literals.push(at + 1..at + end);
            blank(&mut masked, at + 1..at + end);
            at += end + 1;
        } else if rest[0] == b'r' && !after_ident && {
            let hashes = rest[1..].iter().take_while(|b| **b == b'#').count();
            rest.get(1 + hashes) == Some(&b'"')
        } {
            let hashes = rest[1..].iter().take_while(|b| **b == b'#').count();
            let open = 2 + hashes;
            let mut close = vec![b'"'];
            close.extend(std::iter::repeat_n(b'#', hashes));
            let body = &rest[open..];
            let len = body
                .windows(close.len())
                .position(|window| window == close.as_slice())
                .unwrap_or(body.len());
            literals.push(at + open..at + open + len);
            blank(&mut masked, at + open..at + open + len);
            at += open + len + close.len();
        } else if rest[0] == b'\'' {
            // A char literal, or a lifetime, which has no closing quote.
            // An escape closes at the first quote after the escaped
            // character; any other char literal is one character wide.
            let len = match rest.get(1).copied() {
                Some(b'\\') => {
                    let close = rest.iter().skip(3).position(|b| *b == b'\'');
                    close.map_or(1, |close| close + 4)
                }
                Some(first) => {
                    let wide = match first {
                        0..=0x7f => 1,
                        0xc0..=0xdf => 2,
                        0xe0..=0xef => 3,
                        _ => 4,
                    };
                    match rest.get(1 + wide) {
                        Some(b'\'') => wide + 2,
                        _ => 1,
                    }
                }
                None => 1,
            };
            if len > 1 {
                blank(&mut masked, at + 1..at + len - 1);
            }
            at += len;
        } else {
            at += 1;
        }
    }
    Lexed {
        masked: String::from_utf8(masked).expect("blanking keeps whole characters"),
        literals,
    }
}

/// The offset just past the brace that closes the one at `code[open]`,
/// in masked code, where no string or comment holds a brace.
fn closing_brace(code: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (at, byte) in code.bytes().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(at + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The byte ranges of the inline test modules of masked code
/// (`#[cfg(test)]` on a `mod name { .. }`). Anything else under a
/// `cfg(test)` is scanned as production code: stricter, never laxer.
fn test_modules(code: &str) -> Vec<std::ops::Range<usize>> {
    let start =
        Regex::new(r"#\[cfg\(test\)\]\s*(?:pub(?:\([a-z]+\))?\s+)?mod\s+\w+\s*\{").expect("regex");
    let mut ranges: Vec<std::ops::Range<usize>> = Vec::new();
    for found in start.find_iter(code) {
        if ranges.last().is_some_and(|last| found.start() < last.end) {
            continue;
        }
        if let Some(end) = closing_brace(code, found.end() - 1) {
            ranges.push(found.start()..end);
        }
    }
    ranges
}

/// `body` without what nested brackets hold: the members of a struct
/// literal, less the expressions inside them.
fn top_level(body: &str) -> String {
    let (mut out, mut depth) = (String::new(), 0usize);
    for c in body.chars() {
        match c {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => depth = depth.saturating_sub(1),
            c if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// The bodies of the `<name> { .. }` expressions and patterns of masked
/// code: every `<name> {` that is not the head of an item (`struct`,
/// `impl`, `impl .. for`, `enum`, `trait`, `mod`).
fn struct_bodies<'a>(code: &'a str, name: &str) -> Vec<&'a str> {
    let head = Regex::new(&format!(r"\b{name}\s*\{{")).expect("regex");
    let item = Regex::new(r"\b(?:struct|impl|for|enum|trait|mod)\s*$").expect("regex");
    let mut bodies = Vec::new();
    for found in head.find_iter(code) {
        if item.is_match(&code[..found.start()]) {
            continue;
        }
        let end = closing_brace(code, found.end() - 1).unwrap_or(code.len());
        bodies.push(&code[found.end()..end.saturating_sub(1).max(found.end())]);
    }
    bodies
}

/// What the production code of the Bazel seam file `file` (a name under
/// `src/bazel_gate/`) does that a seam must not (the module docs of
/// `bazel_gate` have the rules):
///
/// - a `LaneCx { .. }` outside `mod.rs`: the loader builds the one lane
///   context (`LoadedRoot::lane_cx`), from one read of the root;
/// - a `GateCx { .. }` that is not a struct update over `GateCx::new`,
///   which would stop compiling, or silently default, when the context
///   gains a member; or one that sets no `roots`: `GateCx::new` defaults
///   it to "one root", and a seam that leaves the root probe's answer
///   out judges nested roots as one;
/// - a `GateCx::new` anywhere else than as the base of such an update:
///   the value it returns, bound, passed on or assigned to afterwards,
///   is that same context with the default `roots`;
/// - a literal `Roots::One`: the default again, written out. A seam
///   passes what the probe found (`Roots::Probed`), which the gate reads
///   as one root where the probe found one;
/// - a `RunCx { .. }` with no `..`: the run context gains members too;
/// - a `Type::Variant` of a type the executor takes whole
///   ([`SEAM_OPAQUE_TYPES`]);
/// - another name for one of those types or for a context type (`use ..
///   as`, a `type` alias): every rule here looks for the type's own
///   name;
/// - a string literal that spells an owned path ([`owned_path_marks`]),
///   or string literals that spell one level by level
///   ([`owned_dir_levels`], [`owned_file_names`]).
fn seam_problems(file: &str, src: &str) -> Vec<String> {
    let lexed = lex(src);
    let tests = test_modules(&lexed.masked);
    let in_tests = |at: usize| tests.iter().any(|range| range.contains(&at));
    let mut code = lexed.masked.clone().into_bytes();
    for range in &tests {
        for at in range.clone() {
            if code[at] != b'\n' {
                code[at] = b' ';
            }
        }
    }
    let code = String::from_utf8(code).expect("blanking keeps whole characters");
    let mut problems = Vec::new();
    let mut say = |what: String| problems.push(format!("{file}: {what}"));

    if file != "mod.rs" && !struct_bodies(&code, "LaneCx").is_empty() {
        say("builds or takes apart a `LaneCx { .. }`; take it from `LoadedRoot::lane_cx`".into());
    }
    let update = Regex::new(r"\.\.\s*GateCx::new\s*$").expect("regex");
    let roots = Regex::new(r"(?:^|[\s,])roots\s*(?:[:,]|$)").expect("regex");
    for body in struct_bodies(&code, "GateCx") {
        // The call's arguments are nested, so the update ends the body.
        let members = top_level(body);
        if !update.is_match(members.trim_end()) {
            say("a `GateCx { .. }` that is not `GateCx { .., ..GateCx::new(..) }`".into());
        } else if !roots.is_match(&members) {
            say(
                "a `GateCx { .. }` that sets no `roots`: pass the root probe's answer, \
                 `GateCx::new` defaults it to one root"
                    .into(),
            );
        }
    }
    // Every `GateCx::new` is the base of an update: the two counts are
    // one. A call that is bound, passed on or assigned to afterwards
    // carries the default `roots` past the rule above.
    let constructor = Regex::new(r"\bGateCx\s*::\s*new\b").expect("regex");
    let as_base = Regex::new(r"\.\.\s*GateCx\s*::\s*new\b").expect("regex");
    if constructor.find_iter(&code).count() != as_base.find_iter(&code).count() {
        say(
            "a `GateCx::new` that is not the base of `GateCx { roots, .., ..GateCx::new(..) }`: \
             the context it returns judges nested roots as one"
                .into(),
        );
    }
    if Regex::new(r"\bRoots\s*::\s*One\b")
        .expect("regex")
        .is_match(&code)
    {
        say(
            "names `Roots::One`, the default of `GateCx::new`; pass what the root probe found \
             as `Roots::Probed`, which is one root where the probe found one"
                .into(),
        );
    }
    for body in struct_bodies(&code, "RunCx") {
        if !top_level(body).contains("..") {
            say("a `RunCx { .. }` literal with no `..`; build it by struct update".into());
        }
    }
    for name in SEAM_OPAQUE_TYPES {
        let variant = Regex::new(&format!(r"\b{name}\s*::")).expect("regex");
        if variant.is_match(&code) {
            say(format!(
                "names a variant of `{name}`; a seam hands it on whole and never matches on it"
            ));
        }
    }
    // Another name for a type hides it from every rule above.
    let imports = Regex::new(r"\buse\b[^;]*;").expect("regex");
    for name in SEAM_OPAQUE_TYPES.iter().chain(&SEAM_CONTEXT_TYPES) {
        let renamed = Regex::new(&format!(r"\b{name}\s+as\s+(\w+)")).expect("regex");
        let in_use = imports.find_iter(&code).any(|import| {
            let mut found = renamed.captures_iter(import.as_str());
            found.any(|import| &import[1] != "_")
        });
        let alias = Regex::new(&format!(r"\btype\s+\w+[^=;]*=[^;]*\b{name}\b")).expect("regex");
        if in_use || alias.is_match(&code) {
            say(format!(
                "gives `{name}` another name (`use .. as`, a `type` alias); name it as it is, \
                 so that this scan sees what is done with it"
            ));
        }
    }
    let marks = owned_path_marks();
    let (levels, names) = (owned_dir_levels(), owned_file_names());
    let joined = Regex::new(r"\b(?:join|push)\s*\(\s*&?\s*(?:b|br|r)?#*$").expect("regex");
    // The literals of production code, in order, each with the code up
    // to its opening quote.
    let mut before: Vec<&str> = Vec::new();
    for literal in &lexed.literals {
        if in_tests(literal.start) {
            continue;
        }
        let text = &src[literal.clone()];
        let after_levels = before.ends_with(&levels);
        before.push(text);
        if let Some(mark) = marks.iter().find(|mark| text.contains(**mark)) {
            say(format!(
                "the string literal {text:?} spells the owned path `{mark}`; take it from \
                 `exec::touched` or `bazel::owned_index`"
            ));
        } else if before.ends_with(&levels) {
            say(format!(
                "the string literals {levels:?} spell the owned path `{}` level by level; \
                 take it from `exec::touched` or `bazel::owned_index`",
                levels.join("/")
            ));
        } else if names.contains(&text)
            && (after_levels || joined.is_match(&code[..literal.start - 1]))
        {
            say(format!(
                "the string literal {text:?} names a file of the owned path as a path level; \
                 take it from `exec::touched` or `bazel::owned_index`"
            ));
        }
    }
    problems
}

/// The scan is only worth its rules if it finds what breaks each of them,
/// and leaves alone what merely looks like it.
#[test]
fn the_seam_scan_fails_on_a_planted_example_of_each_rule() {
    let caught = |file: &str, src: &str, needle: &str| {
        let problems = seam_problems(file, src);
        assert!(
            problems.iter().any(|problem| problem.contains(needle)),
            "{src}\nwas not caught for `{needle}`: {problems:?}"
        );
    };
    let clean = |file: &str, src: &str| {
        let problems = seam_problems(file, src);
        assert!(problems.is_empty(), "{src}\nis clean, yet: {problems:?}");
    };

    // 1. A lane context of a seam's own making.
    let lane = "fn f() { let cx = LaneCx { mode, files, ws, hub, index, run }; }";
    caught("hosted.rs", lane, "LaneCx");
    caught(
        "vex.rs",
        "fn f(cx: LaneCx<'_>) { let LaneCx { ws, .. } = cx; }",
        "LaneCx",
    );
    clean("mod.rs", lane);
    clean(
        "hosted.rs",
        "fn f(cx: &LaneCx<'_>) -> Option<LaneCx<'_>> { cx.ws; None }",
    );

    // 2. A gate context that names every member, or forgets the roots.
    let all = "let cx = GateCx { mode, ws, files, index, run, roots, host, \
               allow_patch_conflicts, patch_url };";
    caught("mod.rs", all, "GateCx::new");
    let no_roots = "let cx = GateCx { host, patch_url: Some(url), ..GateCx::new(mode, ws, f, i) };";
    caught("vendored.rs", no_roots, "sets no `roots`");
    // `roots` inside another member's expression is not the member.
    let hidden = "GateCx { host: pick(Thing { roots }), ..GateCx::new(mode, ws, f, i) }";
    caught("vendored.rs", hidden, "sets no `roots`");
    for good in [
        "GateCx { roots, host, ..GateCx::new(mode, ws, files, index) }",
        "GateCx {\n    roots: Roots::Probed { probe: &probe, read: models },\n    \
         ..GateCx::new(mode, ws, files, index)\n}",
        "GateCx { host, roots, ..GateCx::new(Mode::Hosted, ws, root.files(), index) }",
    ] {
        clean(
            "commands.rs",
            &format!("fn f() {{ gate(&{good}, lanes, req); }}"),
        );
    }
    // The constructor outside an update is the context with the default
    // roots: bound, handed straight to the gate, assigned to afterwards,
    // taken as a function, and beside an update that is in order.
    let bare = "a `GateCx::new` that is not the base";
    for call in [
        "let cx = GateCx::new(Mode::Hosted, ws, root.files(), index); gate(&cx, lanes, req);",
        "gate(&GateCx::new(mode, ws, files, index), lanes, req);",
        "let mut cx = GateCx::new(mode, ws, files, index); cx.host = host; \
         cx.patch_url = Some(url); gate(&cx, lanes, req);",
        "let make = GateCx::new; gate(&make(mode, ws, files, index), lanes, req);",
        "let cx = GateCx :: new(mode, ws, files, index);",
        "let a = GateCx { roots, ..GateCx::new(mode, ws, f, i) }; \
         let b = GateCx::new(mode, ws, f, i);",
    ] {
        caught("hosted.rs", &format!("fn f() {{ {call} }}"), bare);
    }
    // And the default written out is the default.
    let one = "GateCx { roots: Roots::One, host, ..GateCx::new(mode, ws, files, index) }";
    caught(
        "vex.rs",
        &format!("fn f() {{ gate(&{one}, l, r); }}"),
        "Roots::One",
    );
    caught(
        "vex.rs",
        "fn f() -> Roots<'static> { Roots :: One }",
        "Roots::One",
    );
    clean(
        "vex.rs",
        "fn f(roots: Roots<'_>) { let _ = MyRoots::Oneness; }",
    );

    // 3. A run context that names every member.
    caught(
        "agent.rs",
        "let run = RunCx { read_only: true, dry_run, offline };",
        "RunCx",
    );
    clean(
        "agent.rs",
        "let run = RunCx { read_only: true, ..RunCx::default() };",
    );
    clean("agent.rs", "let run = RunCx { dry_run, ..run };");
    clean(
        "mod.rs",
        "pub struct RunCx { pub read_only: bool }\nimpl RunCx { fn f() {} }",
    );
    clean(
        "mod.rs",
        "impl Default for RunCx { fn default() -> Self { todo() } }",
    );

    // 4. A match on a type the executor takes whole, each of the nine.
    for name in SEAM_OPAQUE_TYPES {
        let matched = format!("fn f(x: &Plan) -> u8 {{ match x.y {{ {name}::A => 1, _ => 0 }} }}");
        caught("hosted.rs", &matched, name);
        caught("mod.rs", &format!("use model::{name}::*;"), name);
        // Handing one on whole names no variant.
        clean(
            "vex.rs",
            &format!("fn f(kind: {name}) -> Code {{ Code::of(kind) }}"),
        );
    }
    clean(
        "vex.rs",
        "fn f() { let x = LaneAnchor::new(); let y = MyRunKindness::A; }",
    );
    // Under another name each of them, and each context type, would pass
    // every rule here: the new name is what gets reported.
    for name in SEAM_OPAQUE_TYPES.iter().chain(&SEAM_CONTEXT_TYPES) {
        let renamed = format!("gives `{name}` another name");
        for alias in [
            format!("use socket_patch_core::bazel::model::{name} as W;"),
            format!("use socket_patch_core::bazel::model::{{Plan, {name} as W, Lift}};"),
            format!("use model::{{\n    {name}\n        as W,\n}};"),
            format!("type W = {name};"),
            format!("pub(crate) type Cx<'a> = model::{name}<'a>;"),
        ] {
            let src =
                format!("{alias}\nfn f(x: &Plan) -> u8 {{ match x.y {{ W::A => 1, _ => 0 }} }}");
            caught("hosted.rs", &src, &renamed);
        }
        // An import under its own name, an anonymous one, a cast and a
        // qualified path are no other name.
        for own in [
            format!("use socket_patch_core::bazel::model::{{{name}, Plan as P}};"),
            format!("use socket_patch_core::bazel::model::{name} as _;"),
            format!("fn f(x: {name}) -> u8 {{ let _ = <{name} as Default>::default; x as u8 }}"),
            format!("type Kept = Vec<u8>; fn f(x: {name}) {{ let y: Kept = Vec::new(); }}"),
        ] {
            let problems = seam_problems("hosted.rs", &own);
            let renamed = problems.iter().any(|problem| problem.contains(&renamed));
            assert!(!renamed, "{own}: {problems:?}");
        }
    }

    // 5. An owned path as a literal, in every kind of string.
    for literal in [
        "\".socket/bazel/index.json\"",
        "r\".socket/bazel\"",
        "r#\"x/.socket/bazel/pins.json\"#",
        "b\"socket.bazelrc\"",
        "\"socket-patch.MODULE.bazel\"",
        "\"read socket_patch.bzl first\"",
    ] {
        caught(
            "commands.rs",
            &format!("fn f() {{ write({literal}, 1); }}"),
            "owned path",
        );
    }
    clean(
        "commands.rs",
        "fn f() { write(INDEX_PATH, \".socket/vendor\", \".bazelrc\"); }",
    );
    // The same path level by level, which is how a path is built here:
    // one `join` or `push` per level, an array of levels, a raw string.
    for built in [
        "root.join(\".socket\").join(\"bazel\").join(\"index.json\")",
        "root.join(\".socket\").join(\"bazel\")",
        "{ let mut p = root.to_path_buf(); p.push(\".socket\"); p.push(\"bazel\"); p }",
        "[\".socket\", \"bazel\", \"patches\"].iter().collect::<PathBuf>()",
        "root.join(r\".socket\").join(r#\"bazel\"#)",
        "root\n    .join(\".socket\") // the owned directory\n    .join(\"bazel\")",
    ] {
        caught(
            "commands.rs",
            &format!("fn f(root: &Path) -> PathBuf {{ {built} }}"),
            "level by level",
        );
    }
    // A file of the owned directory under a name other files have too,
    // where a path is built.
    for built in [
        "dir.join(\"pins.json\")",
        "dir.join(\"index.json\")",
        "{ let mut p = dir.to_path_buf(); p.push(\"index.json\"); p }",
        "dir.join(&\"pins.json\")",
        "dir.join( r\"index.json\" )",
        "[\".socket\", \"bazel\", \"pins.json\"].iter().collect::<PathBuf>()",
    ] {
        caught(
            "vendored.rs",
            &format!("fn f(dir: &Path) -> PathBuf {{ {built} }}"),
            "owned path",
        );
    }
    // The levels apart, the other directories under `.socket`, and the
    // shared names where no path is built.
    for apart in [
        "root.join(\".socket\").join(\"vendor\").join(\"bazel\")",
        "root.join(\"bazel\").join(\".socket\")",
        "root.join(\".socket\").join(\"manifest.json\")",
        "{ say(\"index.json was read\"); root.join(\"apply.lock\").join(\"patches\") }",
        "{ let name = \"index.json\"; let pins = [\"pins.json\"]; root.join(name) }",
        "root.join(\"BUILD.bazel\")",
    ] {
        clean(
            "commands.rs",
            &format!("fn f(root: &Path) -> PathBuf {{ {apart} }}"),
        );
    }

    // What only looks like one of them: comments, strings, test modules.
    let quiet = "//! A seam never writes `GateCx { mode }` or \".socket/bazel\".\n\
        /* RunCx { a } /* nested WriteClass::Owned */ LaneCx { b } */\n\
        fn f() -> &'static str { let _c = '{'; let _q = '\"'; \"RunCx { x } HookKind::Rc\" }\n\
        #[cfg(test)]\nmod tests {\n    fn g() { let run = RunCx { read_only: true };\n        \
        put(\".socket/bazel/index.json\", LaneCx { a }); let _ = TagOp::Set; }\n}\n";
    clean("hosted.rs", quiet);
    // Production code after a test module is production code.
    let after = format!("{quiet}fn h() {{ let run = RunCx {{ read_only: true }}; }}\n");
    caught("hosted.rs", &after, "RunCx");
    // And `cfg(test)` on anything but an inline module hides nothing.
    let item = "#[cfg(test)]\nfn g() { let _ = Anchor::Digest; }\n";
    caught("hosted.rs", item, "Anchor");
}

#[test]
fn the_bazel_seam_files_keep_the_seam_rules() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bazel_gate");
    let mut scanned = Vec::new();
    let mut problems = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read src/bazel_gate") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        // Flat on purpose: a seam in a subdirectory would not be scanned.
        assert!(
            !path.is_dir(),
            "src/bazel_gate/{name} is a directory; scan it too"
        );
        if !name.ends_with(".rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read a seam file");
        if name == "mod.rs" {
            // The scan reads this code: the loader's own lane context is
            // what it reports for any other file.
            let elsewhere = seam_problems("other.rs", &src);
            assert!(
                elsewhere.iter().any(|problem| problem.contains("LaneCx")),
                "the scan no longer sees the loader's `LaneCx {{ .. }}`: {elsewhere:?}"
            );
        }
        problems.extend(seam_problems(&name, &src));
        scanned.push(name);
    }
    assert!(
        scanned.len() >= 8 && scanned.iter().any(|name| name == "mod.rs"),
        "src/bazel_gate moved? scanned only {scanned:?}"
    );
    assert!(
        problems.is_empty(),
        "the Bazel seam files break the seam rules (see the module docs of \
         src/bazel_gate/mod.rs):\n{}",
        problems.join("\n")
    );
}
