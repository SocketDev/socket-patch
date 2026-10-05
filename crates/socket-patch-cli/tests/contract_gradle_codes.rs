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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
