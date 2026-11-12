//! Every Gradle / JVM code the source can emit is named in CLI_CONTRACT.md.
//!
//! The scan reads the non-test source of both crates and collects:
//!
//! * string literals with a Gradle or JVM code prefix (`redirect_gradle_`,
//!   `vex_gradle_`, `gradle_`, `jvm_agent_`, `jvm_jar_`, `vendor_jvm_`,
//!   `vendor_gradle_`), whole (`"code"`) or as a message prefix
//!   (`"code: …"`);
//! * the `Gradle*` variants of `SidecarAdvisoryCode` (serialized
//!   snake_case);
//! * the vendored Gradle planner's reasons (`degraded("…"`, `note("…"`,
//!   `shape_refusal("…"`, `reason: …:`) in `vendor/jvm/{gradle,mod,apply}.rs`
//!   and `vendor/maven_repo.rs`, minus the Maven-reactor-only ones.
//!
//! Each must appear in backticks in the contract. A new code fails here
//! until it is documented (the "Gradle builds (v5.0)" section).
//!
//! Bazel codes are not literals to collect: they are the variants of
//! `socket_patch_core::bazel::codes::Code`. `test_bazel_contract_codes`
//! holds that enum, the `TOKENS` lists of the Bazel modules and the "Bazel
//! builds" section to each other, and keeps the code strings out of every
//! other source file.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};

use socket_patch_core::bazel::codes::{Code, Kind};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Every `.rs` file under `dir`, minus test-only files.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "testing" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs") && name != "tests.rs" && !name.ends_with("_tests.rs") {
            out.push(path);
        }
    }
}

/// `text` (CRLF already folded to LF) up to its inline test module.
/// Only a `#[cfg(test)] mod name {` body ends the scan: a
/// `#[cfg(test)] mod name;` declaration names a separate file and
/// leaves the rest of this one in scope.
fn non_test(text: &str) -> &str {
    let inline =
        regex::Regex::new(r"(?m)^#\[cfg\(test\)\]\n(?:pub(?:\([a-z]+\))? )?mod \w+ \{").unwrap();
    inline.find(text).map_or(text, |m| &text[..m.start()])
}

fn snake(camel: &str) -> String {
    let mut out = String::new();
    for (i, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Files whose vendored `reason`s reach a Gradle build's `vendor --json`.
const VENDOR_REASON_FILES: &[&str] = &[
    "vendor/jvm/gradle.rs",
    "vendor/jvm/mod.rs",
    "vendor/jvm/apply.rs",
    "vendor/maven_repo.rs",
];

/// Reasons in `VENDOR_REASON_FILES` that only a Maven reactor reaches.
const MAVEN_ONLY_REASONS: &[&str] = &[
    // `--maven-config=none` over recorded `.mvn/maven.config` wiring.
    "maven_config_changed",
];

/// code -> the first file that emits it.
fn emitted_codes() -> BTreeMap<String, String> {
    let literal = regex::Regex::new(
        r#""((?:redirect_gradle|vex_gradle|gradle|jvm_agent|jvm_jar|vendor_jvm|vendor_gradle)_[a-z0-9_]+)(?:"|: )"#,
    )
    .unwrap();
    let reason = regex::Regex::new(
        r#"(?:degraded|note|shape_refusal)\(\s*"([a-z0-9_]+)"|reason: ([a-z0-9_]+):"#,
    )
    .unwrap();
    let advisory = regex::Regex::new(r"\b(Gradle[A-Za-z]+),").unwrap();
    let root = crates_dir();
    let mut files = Vec::new();
    for krate in ["socket-patch-core", "socket-patch-cli"] {
        sources(&root.join(krate).join("src"), &mut files);
    }
    let mut out = BTreeMap::new();
    for path in files {
        // A Windows checkout with core.autocrlf has CRLF files.
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replace("\r\n", "\n");
        let body = non_test(&text);
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let mut add = |code: &str| {
            out.entry(code.to_string()).or_insert_with(|| rel.clone());
        };
        for m in literal.captures_iter(body) {
            add(&m[1]);
        }
        if VENDOR_REASON_FILES.iter().any(|f| rel.ends_with(f)) {
            for m in reason.captures_iter(body) {
                let code = m.get(1).or(m.get(2)).unwrap().as_str();
                if !MAVEN_ONLY_REASONS.contains(&code) {
                    add(code);
                }
            }
        }
        if let Some(start) = body.find("pub enum SidecarAdvisoryCode {") {
            let block = &body[start..];
            let block = &block[..block.find("\n}").unwrap()];
            for m in advisory.captures_iter(block) {
                add(&snake(&m[1]));
            }
        }
    }
    out
}

#[test]
fn test_gradle_contract_codes() {
    let contract = std::fs::read_to_string(crates_dir().join("socket-patch-cli/CLI_CONTRACT.md"))
        .expect("read CLI_CONTRACT.md");
    let codes = emitted_codes();
    // The scan must keep finding the codes it was written for.
    for known in [
        "redirect_gradle_manual_snippet",
        "gradle_copy_unexpected_bytes",
        "gradle_refresh_reverts",
        "jvm_jar_backup_missing",
        "vex_gradle_derived_cache_unchecked",
        "classifier_unpatched_copy",
        // Only in patch/redirect/mod.rs, past its `#[cfg(test)] mod x;`
        // declarations.
        "gradle_uuids",
        // Vendored reasons emitted only from vendor/maven_repo.rs.
        "not_build_root",
        "legacy_maven_root",
        "ide_sources_unavailable",
    ] {
        assert!(
            codes.contains_key(known),
            "the scan lost {known}: {codes:?}"
        );
    }
    let missing: Vec<String> = codes
        .iter()
        .filter(|(code, _)| !contract.contains(&format!("`{code}`")))
        .map(|(code, file)| format!("{code} ({file})"))
        .collect();
    assert!(
        missing.is_empty(),
        "codes emitted by the source but not documented in CLI_CONTRACT.md \
         (add them to \"Gradle builds (v5.0)\"):\n  {}",
        missing.join("\n  ")
    );
}

// ── Bazel ────────────────────────────────────────────────────────────

/// The one file that spells the Bazel code strings.
const BAZEL_CODES_FILE: &str = "socket-patch-core/src/bazel/codes.rs";

/// `(crate-relative path, production text)` of every production source
/// file.
fn production_sources() -> Vec<(String, String)> {
    let root = crates_dir();
    let mut files = Vec::new();
    for krate in ["socket-patch-core", "socket-patch-cli"] {
        sources(&root.join(krate).join("src"), &mut files);
    }
    let read = |path: &PathBuf| {
        // A Windows checkout with core.autocrlf has CRLF files.
        let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let rel = path.strip_prefix(&root).unwrap().to_string_lossy();
        (rel.replace('\\', "/"), production(&text))
    };
    files.iter().map(read).collect()
}

/// `src` (CRLF already folded to LF) without its inline
/// `#[cfg(test)] mod name { … }` blocks.
///
/// Code after a test module is production code and stays: `non_test`
/// stops at the first one, which hides the rest of the file from a ban.
/// A `#[cfg(test)]` on anything else stays too. So does a module whose
/// closing brace is not found, or is not alone on a line at the module's
/// own indentation, where rustfmt puts it: a lexer miss must leave more
/// to scan, never less.
fn production(src: &str) -> String {
    let head = r"(?m)^([ \t]*)#\[cfg\(test\)\]\n[ \t]*(?:pub(?:\([a-z: ]+\))? )?mod \w+ \{[ \t]*$";
    let head = regex::Regex::new(head).unwrap();
    let (mut out, mut kept) = (String::new(), 0);
    for module in head.captures_iter(src) {
        let (whole, indent) = (module.get(0).unwrap(), &module[1]);
        // A test module inside one already removed.
        if whole.start() < kept {
            continue;
        }
        let open = whole.as_str().rfind('{').unwrap() + whole.start();
        let Some(end) = block_end(src, open) else {
            continue;
        };
        let closing_line = src[..end - 1].rsplit('\n').next().unwrap();
        let line_ends = src[end..].is_empty() || src[end..].starts_with('\n');
        if closing_line == indent && line_ends {
            out.push_str(&src[kept..whole.start()]);
            kept = end;
        }
    }
    out + &src[kept..]
}

/// The offset just past the `}` that closes the block opening at
/// `src[open]`. A brace in a comment, a string or a char literal does not
/// count.
fn block_end(src: &str, open: usize) -> Option<usize> {
    let (mut at, mut depth) = (open, 0usize);
    while at < src.len() {
        at += match (lexeme(src, at), src.as_bytes()[at]) {
            (Some((len, _)), _) => len,
            (None, b'{') => {
                depth += 1;
                1
            }
            (None, b'}') if depth <= 1 => return Some(at + 1),
            (None, b'}') => {
                depth -= 1;
                1
            }
            _ => 1,
        };
    }
    None
}

/// The length of the comment, char literal or string literal that starts
/// at `src[at]`, with the range of a string's body; `None` when none
/// starts there. One that is not closed runs to the end of `src`. A
/// lexer, because a line scan takes `'"'` for the start of a string,
/// misses a literal that continues on the next line and counts a code
/// named in a comment.
fn lexeme(src: &str, at: usize) -> Option<(usize, Option<Range<usize>>)> {
    let bytes = src.as_bytes();
    let rest = &bytes[at..];
    let found = match rest[0] {
        b'/' if rest.starts_with(b"//") => {
            let end = rest.iter().position(|b| *b == b'\n');
            (end.unwrap_or(rest.len()), None)
        }
        b'/' if rest.starts_with(b"/*") => (block_comment_len(rest), None),
        b'\'' => (char_literal_len(&src[at..]), None),
        b'"' => {
            // `r"…"`, `br#"…"#`: no escapes, closed by a quote and
            // the same hashes.
            let hashes = bytes[..at].iter().rev().take_while(|b| **b == b'#').count();
            let raw = bytes[..at - hashes].last() == Some(&b'r');
            let body = &src[at + 1..];
            let close = format!("\"{}", "#".repeat(hashes));
            let len = match raw {
                true => body.find(&close).unwrap_or(body.len()),
                false => escaped_len(body.as_bytes()),
            };
            let closed = 1 + len + if raw { close.len() } else { 1 };
            (closed.min(rest.len()), Some(at + 1..at + 1 + len))
        }
        _ => return None,
    };
    Some(found)
}

/// The contents of every string literal in Rust source.
fn string_literals(src: &str) -> Vec<&str> {
    let (mut out, mut at) = (Vec::new(), 0);
    while at < src.len() {
        let (len, body) = lexeme(src, at).unwrap_or((1, None));
        out.extend(body.map(|body| &src[body]));
        at += len;
    }
    out
}

/// `src` without its comments, string literals and char literals.
fn outside_literals(src: &str) -> String {
    let (mut out, mut at) = (String::new(), 0);
    while at < src.len() {
        let next = src[at..].chars().next().unwrap();
        match lexeme(src, at) {
            Some((len, _)) => at += len,
            None => {
                out.push(next);
                at += next.len_utf8();
            }
        }
    }
    out
}

/// The length of the block comment `rest` starts with. They nest.
fn block_comment_len(rest: &[u8]) -> usize {
    let (mut at, mut depth) = (0, 0usize);
    while at < rest.len() {
        let two = &rest[at..rest.len().min(at + 2)];
        match two {
            b"/*" => depth += 1,
            b"*/" if depth == 1 => return at + 2,
            b"*/" => depth -= 1,
            _ => {}
        }
        at += if matches!(two, b"/*" | b"*/") { 2 } else { 1 };
    }
    rest.len()
}

/// The length of a string body up to its closing quote.
fn escaped_len(body: &[u8]) -> usize {
    let mut at = 0;
    while at < body.len() && body[at] != b'"' {
        at += if body[at] == b'\\' { 2 } else { 1 };
    }
    at.min(body.len())
}

/// The length of the char literal `rest` starts with, or 1 when its quote
/// opens a lifetime or a label.
fn char_literal_len(rest: &str) -> usize {
    let mut chars = rest[1..].chars();
    match chars.next() {
        Some('\\') => {
            let close = rest[2..].char_indices().skip(1).find(|(_, c)| *c == '\'');
            close.map_or(rest.len(), |(i, _)| i + 3)
        }
        Some(c) if chars.next() == Some('\'') => c.len_utf8() + 2,
        _ => 1,
    }
}

/// The cells of every table row in `text`.
fn table_rows(text: &str) -> Vec<Vec<&str>> {
    let rows = text.lines().filter(|line| line.starts_with('|'));
    let cells = rows.map(|row| row.trim().trim_matches('|').split('|'));
    cells.map(|cells| cells.map(str::trim).collect()).collect()
}

/// The prefix of a Bazel code: one of the five families.
const BAZEL_FAMILY: &str = r"(?:(?:redirect|vendor|vex)_bazel|bazel_(?:workspace|agent))_";

/// What matches `pattern` inside the string literals of `production`.
fn spelled<'a>(production: &'a str, pattern: &str) -> BTreeSet<&'a str> {
    let pattern = regex::Regex::new(pattern).unwrap();
    let mut spelled = BTreeSet::new();
    for literal in string_literals(production) {
        spelled.extend(pattern.find_iter(literal).map(|found| found.as_str()));
    }
    spelled
}

/// Every Bazel code a string literal of `production` spells, whole or as
/// a bare family prefix. `format!("redirect_bazel_{}", reason)` builds a
/// code outside the enum as surely as a whole literal does, and
/// `starts_with("vex_bazel_")` matches one, so the name may be empty here.
fn spelled_bazel_codes(production: &str) -> BTreeSet<&str> {
    spelled(production, &format!("{BAZEL_FAMILY}[a-z0-9_]*"))
}

/// The word of the contract's Kind column for `kind`; the kinds a table
/// has no such column for have none.
fn kind_word(kind: Kind) -> Option<&'static str> {
    match kind {
        Kind::Advisory => Some("advisory"),
        Kind::Refusal => Some("refusal"),
        Kind::SidecarAdvisory => Some("sidecar advisory"),
        Kind::RunLevel | Kind::EngineWarning | Kind::Withheld => None,
    }
}

/// What the contract row of `code` gets wrong, cell by cell.
fn row_problems(code: Code, row: &[&str]) -> Vec<String> {
    let count = |cells: &[&str]| row.iter().filter(|cell| cells.contains(*cell)).count();
    let mut problems = Vec::new();
    if count(&["planned", "active"]) != 1 {
        problems.push(format!(
            "{code}: its row needs a `planned` or `active` cell"
        ));
    }
    // Only a run-level code or an advisory has a level cell: the prefix
    // of its line for a human.
    let (kind, level) = (code.kind(), format!("`{}`", code.level().as_str()));
    let leveled = usize::from(matches!(kind, Kind::RunLevel | Kind::Advisory));
    if (count(&["`info`", "`warn`"]), count(&[level.as_str()])) != (leveled, leveled) {
        let want = match leveled {
            1 => format!("the level cell {level}"),
            _ => "no level cell".to_string(),
        };
        problems.push(format!("{code} ({kind:?}): its row needs {want}"));
    }
    // A Kind column says where a script finds the code, so it is the
    // enum's kind. The agent table has one, and may not lose it.
    let words = ["advisory", "refusal", "sidecar advisory"];
    let said: Vec<&str> = row.iter().copied().filter(|c| words.contains(c)).collect();
    let (word, agent) = (kind_word(kind), code.as_str().starts_with("bazel_agent_"));
    let right = match said.as_slice() {
        [] => !agent,
        [said] => Some(*said) == word,
        _ => false,
    };
    if !right {
        let want = word.map_or("no kind cell".to_string(), |w| format!("the kind cell {w}"));
        problems.push(format!("{code} ({kind:?}): its row needs {want}"));
    }
    problems
}

/// What one Bazel source file says about tokens.
#[derive(Debug, Default, PartialEq)]
struct TokenScan {
    /// The items of its `TOKENS` lists.
    listed: Vec<String>,
    /// The constants it uses as `token: NAME`.
    named: Vec<String>,
    problems: Vec<String>,
}

/// The names declared as `const NAME: &str = TOKENS[<n>];` in `code`: a
/// constant that is an item of a list, whatever module declares the list.
fn token_constants(code: &str) -> Vec<&str> {
    let declared =
        r"\bconst\s+([A-Z][A-Z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*(?:\w+::)*TOKENS\[\d+\];";
    let declared = regex::Regex::new(declared).unwrap();
    let names = declared.captures_iter(code);
    names.map(|name| name.get(1).unwrap().as_str()).collect()
}

/// The token checks on `code`, the production text of the Bazel source
/// `file` with its comment lines removed. `documented` is the contract's
/// token table and `constants` is [`token_constants`] over every Bazel
/// file: a module imports another module's constant, so a name is
/// resolved across files.
///
/// A scan follows a token only as far as it is spelled. A token that
/// reaches a `Refusal`, a `Gap` or a `Bypass` through a variable, a
/// parameter or the field shorthand is not seen here; only a type for the
/// field would close that.
fn token_scan(file: &str, code: &str, documented: &[&str], constants: &[&str]) -> TokenScan {
    let token_list = regex::Regex::new(r"(?s)\bconst TOKENS: &\[&str\] = &\[(.*?)\];").unwrap();
    let token_item = r"\b(?:const|static)\s+(?:mut\s+)?(\w*TOKENS\w*)";
    let token_item = regex::Regex::new(token_item).unwrap();
    let token_field = regex::Regex::new(r#"\btoken: "([^"]*)""#).unwrap();
    let token_named = regex::Regex::new(r"\btoken:\s*(?:\w+::)*([A-Z][A-Z0-9_]+)\b").unwrap();
    let mut scan = TokenScan::default();
    for list in token_list.captures_iter(code) {
        let items = list.get(1).unwrap().as_str();
        scan.listed
            .extend(string_literals(items).into_iter().map(str::to_string));
        // A named constant in the list is a token this scan cannot read.
        let rest = outside_literals(items);
        if !rest.chars().all(|c| c == ',' || c.is_whitespace()) {
            scan.problems.push(format!(
                "{file}: every `TOKENS` item must be a string literal"
            ));
        }
    }
    for token in &scan.listed {
        if !documented.contains(&token.as_str()) {
            let problem = format!("{file}: token `{token}` has no token-table row");
            scan.problems.push(problem);
        }
    }
    // A list in any other spelling, or under any other name, would be
    // one this scan cannot read.
    if token_item.find_iter(code).count() != token_list.find_iter(code).count() {
        let names = token_item.captures_iter(code);
        let names: Vec<&str> = names.map(|name| name.get(1).unwrap().as_str()).collect();
        let form = "`const TOKENS: &[&str] = &[\"…\"];`";
        scan.problems.push(format!(
            "{file}: declare the token list as {form}, and name nothing else `*TOKENS*` \
             (found {names:?})"
        ));
    }
    for field in token_field.captures_iter(code) {
        if !scan.listed.iter().any(|token| *token == field[1]) {
            let token = &field[1];
            let problem = format!("{file}: \"{token}\" is not in the file's `TOKENS`");
            scan.problems.push(problem);
        }
    }
    for field in token_named.captures_iter(code) {
        let name = field.get(1).unwrap().as_str();
        scan.named.push(name.to_string());
        if name != "TOKENS" && !constants.contains(&name) {
            scan.problems.push(format!(
                "{file}: `token: {name}` is no item of a list; declare it as \
                 `const {name}: &str = TOKENS[<n>];`"
            ));
        }
    }
    scan
}

/// The scans read source text, so each is first shown the mistakes it
/// exists to report: a scan that reads them wrongly proves nothing.
fn the_scans_catch_what_they_were_written_for() {
    let tricky =
        "let q = ['\"', '\\'']; // \"vex_bazel_a\"\n/* \"vex_bazel_b\" */ f::<'a>(\"x \\\" \
                  bazel_agent_c\\\n  d\", br#\"e \"f\" g\"#, r\"h\\\");";
    let literals = ["x \\\" bazel_agent_c\\\n  d", "e \"f\" g", "h\\"];
    assert_eq!(string_literals(tricky), literals);
    assert_eq!(string_literals("/* a /* \"b\" */ \"c\" */ \"d\""), ["d"]);
    assert_eq!(
        outside_literals("\"a\", // b\n 'c' /* d */ E,"),
        ", \n   E,"
    );

    // Production code goes on after a test module, and the ban with it.
    // The module ends at its own brace, whatever its literals hold.
    let tests = "#[cfg(test)]\nmod tests {\n    const INSIDE: &str = \"vex_bazel_inside\";\n    \
                 const BRACES: (&str, &str, char) = (\"}\\\"{\", r#\"}\"}\"#, '}');\n    // }\n    \
                 mod nested {\n        fn f<'a>(s: &'a str) -> bool { s.contains('\\'') }\n    }\n}\n";
    let late = "fn late(reason: &str) -> String {\n    let _ = \"vendor_bazel_late\";\n    \
                format!(\"redirect_bazel_{}\", reason)\n}\n";
    let source = format!("fn early() {{}}\n{tests}{late}");
    let scanned = production(&source);
    assert_eq!(scanned, format!("fn early() {{}}\n\n{late}"));
    let banned = Vec::from_iter(spelled_bazel_codes(&scanned));
    assert_eq!(banned, ["redirect_bazel_", "vendor_bazel_late"]);
    assert_eq!(
        production(&format!("{tests}{tests}{late}")),
        format!("\n\n{late}")
    );
    // What is not an inline test module stays, and so does one whose end
    // is not found where rustfmt puts it.
    let indented = "mod outer {\n    #[cfg(test)]\n    pub(crate) mod tests {\n        \
                    const C: &str = \"vex_bazel_inside\";\n    }\n    fn f() {}\n}\n";
    assert_eq!(production(indented), "mod outer {\n\n    fn f() {}\n}\n");
    for kept in [
        "#[cfg(test)]\nuse a::B;\n#[cfg(test)]\nmod x;\nconst C: &str = \"vex_bazel_x\";\n",
        "#[cfg(test)]\nmod tests {\n    const C: &str = \"vex_bazel_x\";\n",
        "#[cfg(test)]\nmod tests {\n    const C: &str = \"vex_bazel_x\"; }\nfn f() {}\n",
        "#[cfg(test)]\nmod tests {\n    const C: &str = \"vex_bazel_x\";\n} // tests\n",
    ] {
        assert_eq!(production(kept), kept);
        assert_eq!(Vec::from_iter(spelled_bazel_codes(kept)), ["vex_bazel_x"]);
    }

    // A row is held to the enum's kind as well as to its level.
    let row = |cells: &str| row_problems(Code::AgentOutputTree, &table_rows(cells)[0]);
    assert_eq!(
        row("| `bazel_agent_output_tree` | planned | refusal | - |"),
        [""; 0]
    );
    for wrong in [
        "| `bazel_agent_output_tree` | planned | advisory | - |",
        "| `bazel_agent_output_tree` | planned | - |",
        "| `bazel_agent_output_tree` | planned | refusal | sidecar advisory | - |",
    ] {
        let problem = "bazel_agent_output_tree (Refusal): its row needs the kind cell refusal";
        assert_eq!(row(wrong), [problem], "{wrong}");
    }
    let run_level = "| `bazel_workspace_detected` | planned | advisory | `info` |";
    let problems = row_problems(Code::WorkspaceDetected, &table_rows(run_level)[0]);
    let problem = "bazel_workspace_detected (RunLevel): its row needs no kind cell";
    assert_eq!(problems, [problem]);

    // A token is read where it is listed and where a constant names it.
    let scan = |code: &str| {
        let constants = token_constants(code);
        let mut scan = token_scan("f.rs", code, &["documented"], &constants);
        assert_eq!(scan.problems.len(), 1, "{code}: {:?}", scan.problems);
        scan.problems.remove(0)
    };
    let list = "pub const TOKENS: &[&str] = &[\"documented\"];\n";
    let clean = format!(
        "{list}pub const FIRST: &str = TOKENS[0];\nfn f() -> Gap {{\n    Gap {{ token: FIRST }}\n}}\n\
         fn g() -> Gap {{\n    Gap {{ token: \"documented\" }}\n}}\n"
    );
    let constants = token_constants(&clean);
    assert_eq!(constants, ["FIRST"]);
    let expected = TokenScan {
        listed: vec!["documented".to_string()],
        named: vec!["FIRST".to_string()],
        problems: Vec::new(),
    };
    assert_eq!(
        token_scan("f.rs", &clean, &["documented"], &constants),
        expected
    );
    assert_eq!(
        scan("pub const TOKENS: &[&str] = &[\"documented\", \"other\"];\n"),
        "f.rs: token `other` has no token-table row"
    );
    assert_eq!(
        scan("const OTHER: &str = \"other\";\nconst TOKENS: &[&str] = &[OTHER, \"documented\"];\n"),
        "f.rs: every `TOKENS` item must be a string literal"
    );
    assert_eq!(
        scan(&format!(
            "{list}fn f() -> Gap {{\n    Gap {{ token: \"other\" }}\n}}\n"
        )),
        "f.rs: \"other\" is not in the file's `TOKENS`"
    );
    let named = "const OTHER: &str = \"other\";\nfn f() -> Gap {\n    Gap { token: OTHER }\n}\n";
    let problem = "f.rs: `token: OTHER` is no item of a list; declare it as \
                   `const OTHER: &str = TOKENS[<n>];`";
    assert_eq!(scan(&format!("{list}{named}")), problem);
    assert_eq!(
        scan(&named.replace("token: OTHER", "token: Self::OTHER")),
        problem
    );
    for other_list in [
        "pub const LANE_TOKENS: &[&str] = &[\"other\"];\n",
        "pub static TOKENS: &[&str] = &[\"other\"];\n",
        "pub const TOKENS: [&str; 1] = [\"other\"];\n",
    ] {
        let problem = scan(other_list);
        assert!(
            problem.starts_with("f.rs: declare the token list as"),
            "{problem}"
        );
    }
}

/// The Bazel half of the contract, in both directions:
///
/// * every `Code` has exactly one row in the "Bazel builds" section, with
///   a status (`planned` or `active`); for a run-level code or an
///   advisory, the level the enum gives it; and, where the table has a
///   Kind column (the agent table must), the enum's kind;
/// * the contract names no Bazel code the enum lacks;
/// * no production source outside `bazel/codes.rs` spells a Bazel code or
///   a bare family prefix in a string literal, so the enum is the only way
///   to emit one. Production source is the whole file but its inline test
///   modules;
/// * every token a Bazel module lists in its `TOKENS` const has a row in
///   the section's token table; the list has the one spelling this scan
///   reads and only string literals in it; a `token: "…"` literal is in
///   the `TOKENS` of its file, and a `token: NAME` constant is declared as
///   an item of a list. What reaches a `token` field any other way is not
///   seen (`token_scan`);
/// * a `Bazel*` variant of `SidecarAdvisoryCode`, which serde spells, is a
///   sidecar code of the enum.
#[test]
fn test_bazel_contract_codes() {
    the_scans_catch_what_they_were_written_for();

    // A bare prefix is no code: in the contract and in the enum's own
    // table a name follows it.
    let whole = format!("{BAZEL_FAMILY}[a-z0-9_]+");
    let family = regex::Regex::new(&whole).unwrap();
    let known: BTreeSet<&str> = Code::ALL.iter().map(|code| code.as_str()).collect();
    let contract = std::fs::read_to_string(crates_dir().join("socket-patch-cli/CLI_CONTRACT.md"))
        .expect("read CLI_CONTRACT.md")
        .replace("\r\n", "\n");
    let start = contract.find("\n## Bazel builds\n");
    let section = &contract[start.expect("CLI_CONTRACT.md has a `## Bazel builds` section") + 1..];
    let section = &section[..section[3..]
        .find("\n## ")
        .map_or(section.len(), |end| end + 3)];
    let rows = table_rows(section);
    let mut problems: BTreeSet<String> = BTreeSet::new();

    for code in Code::ALL {
        let cell = format!("`{code}`");
        let own: Vec<_> = rows.iter().filter(|row| row.contains(&&*cell)).collect();
        let [row] = own.as_slice() else {
            problems.insert(format!("{code}: {} rows in the section, not 1", own.len()));
            continue;
        };
        problems.extend(row_problems(*code, row));
    }
    for named in family.find_iter(&contract) {
        if !known.contains(named.as_str()) {
            let named = named.as_str();
            problems.insert(format!(
                "CLI_CONTRACT.md names `{named}`, which is no `Code`"
            ));
        }
    }

    let sources = production_sources();
    let mut table_seen = false;
    for (file, text) in &sources {
        if file == BAZEL_CODES_FILE {
            // The scan must keep finding the table it was written for.
            let table = spelled(text, &whole);
            assert_eq!(table, known, "the literals of {file} are not `Code::ALL`");
            table_seen = true;
            continue;
        }
        for code in spelled_bazel_codes(text) {
            let fix = "emit it through `bazel::codes::Code`";
            problems.insert(format!("{file} spells the Bazel code \"{code}\"; {fix}"));
        }
    }
    assert!(table_seen, "{BAZEL_CODES_FILE} was not scanned");

    let token_table = section.split_once("\n### Tokens\n");
    let token_rows = table_rows(token_table.expect("the section has a `### Tokens` table").1);
    let documented = token_rows.iter();
    let documented = documented.filter_map(|row| row[0].strip_prefix('`')?.strip_suffix('`'));
    let documented: Vec<&str> = documented.collect();
    for token in &documented {
        if documented.iter().filter(|other| *other == token).count() != 1 {
            problems.insert(format!("the token table lists `{token}` more than once"));
        }
    }
    // A doc comment may show a list or a field; only code declares one.
    let code_of = |text: &String| {
        let lines = text.lines();
        let code = lines.filter(|line| !line.trim_start().starts_with("//"));
        code.collect::<Vec<_>>().join("\n")
    };
    let bazel = sources.iter().filter(|(file, _)| file.contains("bazel"));
    let bazel = bazel.map(|(file, text)| (file, code_of(text)));
    let bazel: Vec<(&String, String)> = bazel.collect();
    let constants = bazel.iter().flat_map(|(_, code)| token_constants(code));
    let constants: Vec<&str> = constants.collect();
    let (mut first_list_seen, mut first_name_seen) = (false, false);
    for (file, code) in &bazel {
        let scan = token_scan(file, code, &documented, &constants);
        let lists = |token: &str| scan.listed.iter().any(|listed| listed == token);
        first_list_seen |= file.ends_with("/bazel/model.rs") && lists("lane_not_enabled");
        first_name_seen |= scan
            .named
            .iter()
            .any(|name| constants.contains(&name.as_str()));
        problems.extend(scan.problems);
    }
    // The scan must keep finding the list and the constant it was written
    // for.
    assert!(first_list_seen, "the scan lost `bazel::model::TOKENS`");
    assert!(
        first_name_seen,
        "the scan lost every `token: NAME` of a `TOKENS[<n>]` constant"
    );

    let sidecars = sources
        .iter()
        .find(|(file, _)| file.ends_with("patch/sidecars/types.rs"));
    let (_, sidecars) = sidecars.expect("patch/sidecars/types.rs is a source file");
    let variants = sidecars.split_once("pub enum SidecarAdvisoryCode {");
    let variants = variants.and_then(|(_, body)| body.split_once("\n}"));
    let (variants, _) = variants.expect("`SidecarAdvisoryCode` is declared in that file");
    assert!(variants.contains("GradleRefreshReverts,"), "{variants}");
    for variant in regex::Regex::new(r"\bBazel[A-Za-z]+")
        .unwrap()
        .find_iter(variants)
    {
        let name = snake(variant.as_str());
        let code = Code::ALL.iter().find(|code| code.as_str() == name);
        if code.is_none_or(|code| code.kind() != Kind::SidecarAdvisory) {
            problems.insert(format!("SidecarAdvisoryCode `{name}` is no sidecar `Code`"));
        }
    }

    let problems: Vec<String> = problems.into_iter().collect();
    assert!(
        problems.is_empty(),
        "Bazel codes, tokens and the \"Bazel builds\" section of CLI_CONTRACT.md disagree:\n  {}",
        problems.join("\n  ")
    );
}
