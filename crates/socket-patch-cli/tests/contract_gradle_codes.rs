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

/// `(crate-relative path, non-test text)` of every production source file.
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
        (rel.replace('\\', "/"), non_test(&text).to_string())
    };
    files.iter().map(read).collect()
}

/// The contents of every string literal in Rust source. A lexer, because a
/// line scan takes `'"'` for the start of a string, misses a literal that
/// continues on the next line and counts a code named in a comment.
fn string_literals(src: &str) -> Vec<&str> {
    let bytes = src.as_bytes();
    let (mut out, mut at) = (Vec::new(), 0);
    while at < bytes.len() {
        let rest = &bytes[at..];
        let end_of = |close: &[u8]| rest.windows(close.len()).position(|w| w == close);
        at += match rest[0] {
            b'/' if rest[1..].starts_with(b"/") => end_of(b"\n").unwrap_or(rest.len()),
            b'/' if rest[1..].starts_with(b"*") => end_of(b"*/").map_or(rest.len(), |i| i + 2),
            b'\'' => char_literal_len(&src[at..]),
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
                out.push(&body[..len]);
                1 + len + if raw { close.len() } else { 1 }
            }
            _ => 1,
        };
    }
    out
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

/// The Bazel half of the contract, in both directions:
///
/// * every `Code` has exactly one row in the "Bazel builds" section, with
///   a status (`planned` or `active`) and, for a run-level code or an
///   advisory, the level the enum gives it;
/// * the contract names no Bazel code the enum lacks;
/// * no production source outside `bazel/codes.rs` spells a Bazel code in
///   a string literal, so the enum is the only way to emit one;
/// * every token a Bazel module lists in its `TOKENS` const has a row in
///   the section's token table; the list has the one spelling this scan
///   reads, and a `token: "…"` literal is in the `TOKENS` of its file;
/// * a `Bazel*` variant of `SidecarAdvisoryCode`, which serde spells, is a
///   sidecar code of the enum.
#[test]
fn test_bazel_contract_codes() {
    // The lexer first: a scan that reads literals wrongly proves nothing.
    let tricky =
        "let q = ['\"', '\\'']; // \"vex_bazel_a\"\n/* \"vex_bazel_b\" */ f::<'a>(\"x \\\" \
                  bazel_agent_c\\\n  d\", br#\"e \"f\" g\"#, r\"h\\\");";
    let literals = ["x \\\" bazel_agent_c\\\n  d", "e \"f\" g", "h\\"];
    assert_eq!(string_literals(tricky), literals);

    let family = r"(?:(?:redirect|vendor|vex)_bazel|bazel_(?:workspace|agent))_[a-z0-9_]+";
    let family = regex::Regex::new(family).unwrap();
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
        let count = |cells: &[&str]| row.iter().filter(|cell| cells.contains(*cell)).count();
        if count(&["planned", "active"]) != 1 {
            problems.insert(format!(
                "{code}: its row needs a `planned` or `active` cell"
            ));
        }
        // Only a run-level entry or an advisory carries a `level`.
        let (kind, level) = (code.kind(), format!("`{}`", code.level().as_str()));
        let leveled = usize::from(matches!(kind, Kind::RunLevel | Kind::Advisory));
        if (count(&["`info`", "`warn`"]), count(&[level.as_str()])) != (leveled, leveled) {
            let want = match leveled {
                1 => format!("the level cell {level}"),
                _ => "no level cell".to_string(),
            };
            problems.insert(format!("{code} ({kind:?}): its row needs {want}"));
        }
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
        let literals = string_literals(text);
        let spelled = literals
            .iter()
            .flat_map(|literal| family.find_iter(literal));
        let spelled: BTreeSet<&str> = spelled.map(|found| found.as_str()).collect();
        if file == BAZEL_CODES_FILE {
            // The scan must keep finding the table it was written for.
            assert_eq!(spelled, known, "the literals of {file} are not `Code::ALL`");
            table_seen = true;
            continue;
        }
        for code in spelled {
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
    let token_list = regex::Regex::new(r"(?s)\bconst TOKENS: &\[&str\] = &\[(.*?)\];").unwrap();
    let token_item = regex::Regex::new(r"\b(?:const|static)\s+TOKENS\b").unwrap();
    let token_field = regex::Regex::new(r#"\btoken: "([^"]*)""#).unwrap();
    let mut first_list_seen = false;
    for (file, text) in sources.iter().filter(|(file, _)| file.contains("bazel")) {
        // A doc comment may show a list or a field; only code declares one.
        let code = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"));
        let code = code.collect::<Vec<_>>().join("\n");
        let lists = token_list.captures_iter(&code);
        let listed = lists.flat_map(|list| string_literals(list.get(1).unwrap().as_str()));
        let listed: Vec<&str> = listed.collect();
        for token in listed.iter().filter(|token| !documented.contains(token)) {
            problems.insert(format!("{file}: token `{token}` has no token-table row"));
        }
        // A list in any other spelling would be one this scan cannot read.
        if token_item.find_iter(&code).count() != token_list.find_iter(&code).count() {
            let form = "`const TOKENS: &[&str] = &[\"…\"];`";
            problems.insert(format!("{file}: declare the token list as {form}"));
        }
        for field in token_field.captures_iter(&code) {
            if !listed.contains(&&field[1]) {
                let token = &field[1];
                problems.insert(format!("{file}: \"{token}\" is not in the file's `TOKENS`"));
            }
        }
        let first = file.ends_with("/bazel/model.rs") && listed.contains(&"lane_not_enabled");
        first_list_seen |= first;
    }
    // The scan must keep finding the list it was written for.
    assert!(first_list_seen, "the scan lost `bazel::model::TOKENS`");

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
