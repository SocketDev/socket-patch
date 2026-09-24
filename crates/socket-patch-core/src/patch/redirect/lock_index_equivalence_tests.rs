//! Equivalence oracles for the npm package-lock and classic yarn.lock hosted
//! rewriters, which now derive each entry's identity once per lock instead
//! of once per entry per dep. The previous implementations are kept here
//! verbatim and the production rewriters must produce the identical output
//! bytes, FileEdit list, warnings and refusals on randomized locks.

use super::*;

type Snapshot = (
    BTreeMap<String, String>,
    Vec<FileEdit>,
    Vec<(String, String)>,
);

fn snapshot(r: &RewriteResult) -> Snapshot {
    (
        r.files.clone(),
        r.edits.clone(),
        r.warnings
            .iter()
            .map(|w| (w.code.clone(), w.detail.clone()))
            .collect(),
    )
}

fn assert_same(want: &RewriteResult, got: &RewriteResult, what: &str) {
    let (want, got) = (snapshot(want), snapshot(got));
    assert_eq!(got.0, want.0, "{what}: rewritten bytes");
    assert_eq!(got.1.len(), want.1.len(), "{what}: edit count");
    for (i, (g, w)) in got.1.iter().zip(&want.1).enumerate() {
        assert_eq!(g, w, "{what}: edit #{i}");
    }
    assert_eq!(got.2, want.2, "{what}: warnings (code, detail) in order");
}

/// Deterministic xorshift64* — no `rand` dev-dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn name(i: usize) -> String {
    match i % 4 {
        0 => format!("@scope/pkg-{i}"),
        _ => format!("pkg-{i}"),
    }
}

fn version(rng: &mut Rng) -> String {
    ["1.0.0", "1.2.3", "2.0.0", "0.1.0-beta.1"][rng.below(4)].to_string()
}

fn dep(name: &str, version: &str, uuid: usize, rng: &mut Rng) -> DepOverride {
    let (namespace, bare) = match name.split_once('/') {
        Some((ns, bare)) if name.starts_with('@') => (Some(ns.to_string()), bare.to_string()),
        _ => (None, name.to_string()),
    };
    let tag = ["a", "b"][rng.below(2)];
    DepOverride {
        ecosystem: "npm".into(),
        name: bare,
        namespace,
        version: version.to_string(),
        token: String::new(),
        patch_uuid: format!("00000000-0000-4000-8000-{uuid:012}"),
        artifact_url: format!("https://patch.socket.dev/{tag}/{name}-{version}.tgz"),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha512: (!rng.chance(5)).then(|| format!("sha512-P{}==", rng.below(3))),
            sha1: rng.chance(30).then(|| "0123456789abcdef".to_string()),
            ..Default::default()
        },
    }
}

/// Overrides drawn from `pool` (plus misses), with immediate duplicates of
/// one name@version so a later dep re-reads an already-rewritten entry.
fn overrides(pool: &[(String, String)], rng: &mut Rng) -> Vec<DepOverride> {
    let mut out = Vec::new();
    for i in 0..(1 + rng.below(12)) {
        let (n, v) = if rng.chance(10) || pool.is_empty() {
            (format!("absent-{i}"), "1.0.0".to_string())
        } else {
            pool[rng.below(pool.len())].clone()
        };
        out.push(dep(&n, &v, i, rng));
        if rng.chance(20) {
            out.push(dep(&n, &v, i + 100, rng));
        }
    }
    out
}

fn npm_lock(rng: &mut Rng, pool: &mut Vec<(String, String)>) -> String {
    let lock_version = 1 + rng.below(3) as u64;
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({ "name": "root", "version": "0.0.0" }));
    packages.insert(
        "packages/ws".into(),
        json!({ "name": "pkg-1", "version": "1.0.0" }),
    );
    for i in 0..(5 + rng.below(40)) {
        let n = name(rng.below(30));
        let v = version(rng);
        pool.push((n.clone(), v.clone()));
        let key = match rng.below(4) {
            0 => format!("node_modules/{}/node_modules/{n}", name(rng.below(30))),
            1 => format!("packages/ws/node_modules/{n}"),
            _ => format!("node_modules/{n}"),
        };
        let mut entry = serde_json::Map::new();
        if rng.chance(10) {
            // An alias install: keyed by the alias, `name` is the real one.
            entry.insert("name".into(), json!(name(rng.below(30))));
        }
        if !rng.chance(5) {
            entry.insert("version".into(), json!(v));
        }
        if rng.chance(80) {
            entry.insert(
                "resolved".into(),
                json!(format!("https://registry.npmjs.org/{n}/-/x-{v}.tgz")),
            );
            entry.insert("integrity".into(), json!(format!("sha512-UP{i}==")));
        }
        if rng.chance(5) {
            entry.insert("link".into(), json!(true));
        }
        if rng.chance(5) {
            entry.insert("inBundle".into(), json!(true));
        }
        let value = if rng.chance(3) {
            json!("not an object")
        } else {
            Value::Object(entry)
        };
        packages.insert(key, value);
    }
    let mut lock = json!({
        "name": "root",
        "version": "0.0.0",
        "lockfileVersion": lock_version,
        "requires": true,
    });
    if lock_version >= 2 {
        lock["packages"] = Value::Object(packages);
    }
    if lock_version <= 2 {
        let mut deps = serde_json::Map::new();
        for _ in 0..(2 + rng.below(10)) {
            let n = name(rng.below(30));
            let v = version(rng);
            pool.push((n.clone(), v.clone()));
            let mut entry = json!({
                "version": v,
                "resolved": format!("https://registry.npmjs.org/{n}/-/x-{v}.tgz"),
                "integrity": "sha512-UPV2==",
            });
            if rng.chance(10) {
                entry["bundled"] = json!(true);
            }
            if rng.chance(20) {
                entry["dependencies"] = json!({
                    n.clone(): { "version": v, "resolved": "https://registry.npmjs.org/x.tgz" }
                });
            }
            deps.insert(n, entry);
        }
        lock["dependencies"] = Value::Object(deps);
    }
    let mut text = serialize_json(&lock);
    if rng.chance(3) {
        text.truncate(text.len() / 2);
    }
    text
}

#[test]
fn indexed_npm_lock_rewrite_matches_oracle() {
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    for seed in 1..=400u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut pool = Vec::new();
        let text = npm_lock(&mut rng, &mut pool);
        let deps = overrides(&pool, &mut rng);
        let refs: Vec<&DepOverride> = deps.iter().collect();
        for lockfile in ["package-lock.json", "npm-shrinkwrap.json"] {
            let mut want = RewriteResult::default();
            rewrite_one_npm_lock_oracle(&text, lockfile, &refs, &mut want);
            let mut got = RewriteResult::default();
            rewrite_one_npm_lock(&text, lockfile, &refs, &mut got);
            assert_same(&want, &got, &format!("seed {seed} {lockfile}"));
            edits += got.edits.len();
            codes.extend(got.warnings.iter().map(|w| w.code.clone()));
        }
    }
    // The generator must actually reach every path.
    assert!(edits > 400, "edits: {edits}");
    for code in [
        "redirect_npm_missing_sha512",
        "redirect_npm_link_entry_skipped",
        "redirect_npm_bundled_instance_skipped",
        "redirect_npm_entry_not_found",
        "redirect_npm_legacy_client",
        "redirect_npm_lock_unparseable",
    ] {
        assert!(codes.contains(code), "missing {code}: {codes:?}");
    }
}

fn yarn_block(rng: &mut Rng, pool: &mut Vec<(String, String)>, i: usize) -> String {
    let n = name(rng.below(20));
    let v = version(rng);
    pool.push((n.clone(), v.clone()));
    let q = |p: String| {
        if p.starts_with('@') || p.contains(':') {
            format!("\"{p}\"")
        } else {
            p
        }
    };
    let mut patterns = vec![q(format!("{n}@^{v}"))];
    match rng.below(6) {
        0 => patterns.push(q(format!("{n}@~{v}"))),
        // An alias descriptor consuming the same package.
        1 => patterns.push(q(format!("alias-{i}@npm:{n}@^{v}"))),
        // Only reachable through an alias.
        2 => patterns = vec![q(format!("alias-{i}@npm:{n}@^{v}"))],
        // Fork substitution: the name is ours, the package is not.
        3 => patterns = vec![q(format!("{n}@npm:fork-{i}@^{v}"))],
        // Mixed real packages: never ours.
        4 => patterns.push(q(format!("{}@^1.0.0", name(rng.below(20))))),
        _ => {}
    }
    let mut block = String::new();
    if rng.chance(5) {
        block.push_str("# a comment\n");
    }
    block.push_str(&format!("{}:\n  version \"{v}\"\n", patterns.join(", ")));
    if rng.chance(90) {
        block.push_str(&format!(
            "  resolved \"https://registry.yarnpkg.com/{n}/-/x-{v}.tgz#abc{i}\"\n"
        ));
    }
    if rng.chance(70) {
        block.push_str(&format!("  integrity sha512-UP{i}==\n"));
    }
    if rng.chance(30) {
        block.push_str("  dependencies:\n    dep-a \"^1.0.0\"\n");
    }
    block
}

#[test]
fn indexed_yarn_classic_rewrite_matches_oracle() {
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    for seed in 1..=400u64 {
        let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
        let mut pool = Vec::new();
        let mut text = String::from(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n",
        );
        let count = 3 + rng.below(40);
        for i in 0..count {
            text.push('\n');
            text.push_str(&yarn_block(&mut rng, &mut pool, i));
        }
        match rng.below(20) {
            0 => text = text.replace('\n', "\r\n"),
            1 => text = text.replacen('\n', "\r", 1),
            _ => {}
        }
        let files = BTreeMap::from([("yarn.lock".to_string(), text)]);
        let deps = overrides(&pool, &mut rng);
        let mut want = RewriteResult::default();
        rewrite_yarn_classic_oracle(&files, &deps, &mut want);
        let mut got = RewriteResult::default();
        rewrite_yarn_classic(&files, &deps, &mut got);
        assert_same(&want, &got, &format!("seed {seed}"));
        edits += got.edits.len();
        codes.extend(got.warnings.iter().map(|w| w.code.clone()));
    }
    assert!(edits > 400, "edits: {edits}");
    for code in [
        "redirect_yarn_classic_missing_sha512",
        "redirect_yarn_classic_alias_skipped",
        "redirect_yarn_classic_entry_not_found",
        "redirect_yarn_classic_unsupported_line_endings",
    ] {
        assert!(codes.contains(code), "missing {code}: {codes:?}");
    }
}

// ── oracles: the pre-index implementations, verbatim ────────────────────────

fn rewrite_one_npm_lock_oracle(
    content: &str,
    lockfile: &str,
    npm: &[&DepOverride],
    result: &mut RewriteResult,
) {
    let Ok(mut lock) = serde_json::from_str::<Value>(content) else {
        // A corrupt lockfile is strictly worse than a missing one (which
        // warns in the caller) — never skip the whole npm redirect silently.
        result.warnings.push(RewriteWarning {
            code: "redirect_npm_lock_unparseable".into(),
            detail: format!("{lockfile} is not valid JSON; npm redirect skipped"),
        });
        return;
    };
    let mut changed = false;
    for dep in npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        let mut matched_any = false;
        if let Some(packages) = lock.get_mut("packages").and_then(Value::as_object_mut) {
            for (key, entry) in packages.iter_mut() {
                // Only `node_modules/` keys are installable dependencies:
                // "" is the project root and other bare keys are workspace
                // members — SOURCE dirs a resolved/integrity insert would
                // corrupt.
                let Some((_, key_name)) = key.rsplit_once("node_modules/") else {
                    continue;
                };
                // The package a lock entry stands for: the explicit `name`
                // field when present (npm writes it for aliases — `npm i
                // alias@npm:real` keys the entry by the ALIAS), else the
                // key's trailing path. Mirrors `vendor::npm_lock`'s
                // `entry_name`, so an alias install of the patched package
                // redirects and an entry that merely SHARES the key name
                // (`npm i <fname>@npm:other`) is never hijacked.
                let entry_nm = entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(key_name);
                let matches_ver =
                    entry.get("version").and_then(Value::as_str) == Some(dep.version.as_str());
                if entry_nm != fname || !matches_ver {
                    continue;
                }
                if entry.get("link").and_then(Value::as_bool) == Some(true) {
                    matched_any = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_npm_link_entry_skipped".into(),
                        detail: format!(
                            "lock entry `{key}` is a link (npm workspaces/file: dir); skipped"
                        ),
                    });
                    continue;
                }
                // npm reify extracts a bundled copy from its PARENT's tarball
                // and ignores the entry's resolved/integrity, so a rewrite
                // here would put the hosted URL in the lockfile (confirming
                // and VEX-attesting the patch) while the unpatched bundled
                // bytes keep installing. Mirrors the vendored backend's
                // `vendor_bundled_instance_skipped` refusal.
                if entry.get("inBundle").and_then(Value::as_bool) == Some(true) {
                    matched_any = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_npm_bundled_instance_skipped".into(),
                        detail: format!(
                            "lock entry `{key}` is bundled inside its parent's tarball and \
                             CANNOT be redirected — that copy stays UNPATCHED; vendor or \
                             update the bundling parent to cover it"
                        ),
                    });
                    continue;
                }
                matched_any = true;
                if let Some(edit) = rewrite_npm_entry(
                    entry,
                    dep,
                    &sha512,
                    lockfile,
                    "redirect_npm_lock_entry",
                    key,
                ) {
                    result.edits.push(edit);
                    changed = true;
                }
            }
        }
        // v2 legacy `dependencies` tree (keyed by name), recursive.
        if let Some(deps) = lock.get_mut("dependencies").and_then(Value::as_object_mut) {
            changed = rewrite_npm_v2_deps(
                deps,
                &fname,
                dep,
                &sha512,
                lockfile,
                result,
                &mut matched_any,
            ) || changed;
        }
        // Parity with the pnpm/berry/uv rewriters: a granted dep the
        // lockfile cannot pin must be SAID, not silently dropped from the
        // redirected count.
        if !matched_any {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_entry_not_found".into(),
                detail: format!("no {lockfile} entry for {fname}@{}", dep.version),
            });
        }
    }
    if changed {
        // npm <= 6 (the only writer of lockfileVersion 1) installs a registry
        // dependency from the CONFIGURED registry and ignores the entry's
        // `resolved` — verified against real npm 6.14.18, while npm 7 / 11
        // fetch the rewritten url from the same v1 lock. Under npm 6 the
        // redirected lock therefore fails EINTEGRITY against the patched
        // sha512 pin (fail-closed: the unpatched bytes never install). Say
        // so instead of letting an npm 6 CI discover it.
        if lock.get("lockfileVersion").and_then(Value::as_u64) == Some(1) {
            result.warnings.push(RewriteWarning {
                code: "redirect_npm_legacy_client".into(),
                detail: format!(
                    "{lockfile} is lockfileVersion 1 (written by npm <= 6). npm <= 6 installs \
                     registry dependencies from the configured registry and ignores the \
                     redirected `resolved` url, so its installs fail EINTEGRITY against the \
                     patched sha512 pin (the unpatched bytes are never installed); install \
                     with npm >= 7, which fetches the hosted patch (and upgrades the lock)"
                ),
            });
        }
        result.files.insert(lockfile.into(), serialize_json(&lock));
    }
}

fn rewrite_yarn_classic_oracle(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    use crate::vendor::yarn_classic_lock::{pattern_real_name, split_key_patterns, split_pattern};

    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    if npm.is_empty() || !files.contains_key("yarn.lock") {
        return;
    }
    let raw = &files["yarn.lock"];
    if is_berry_lock(raw) {
        return; // yarn-berry — not classic
    }
    // CRLF locks (core.autocrlf Windows checkouts — yarn v1 parses them fine)
    // are processed LF-normalized and re-expanded on output, so untouched
    // lines round-trip byte-identically. Without this, `split("\n\n")` never
    // splits a CRLF file: the whole lock becomes ONE block and the
    // leftmost-match replaces below would rewrite the FIRST entry in the
    // file, not the target's. Bare `\r`s outside a CRLF pair make the
    // round-trip lossy, so such a lock is refused untouched.
    let crlf = raw.contains('\r');
    let normalized: String;
    let content: &str = if crlf {
        normalized = raw.replace("\r\n", "\n");
        if normalized.contains('\r') {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_classic_unsupported_line_endings".into(),
                detail: "yarn.lock contains bare carriage returns (mixed line endings); \
                         leaving it untouched"
                    .into(),
            });
            return;
        }
        &normalized
    } else {
        raw
    };
    let mut blocks: Vec<String> = content.split("\n\n").map(String::from).collect();
    let resolved_re =
        Regex::new(r#"\n {2}resolved "[^"]*""#).expect("static resolved-line regex is valid");
    let integrity_re =
        Regex::new(r"\n {2}integrity [^\n]*").expect("static integrity-line regex is valid");
    let mut changed = false;
    for dep in &npm {
        let fname = full_name(dep);
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_classic_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        let version_re =
            Regex::new(&(String::from(r#"\n {2}version ""#) + &regex::escape(&dep.version) + "\""))
                .expect("version regex from the escaped version is valid");
        let mut matched_any = false;
        let mut alias_skipped = false;
        for block in blocks.iter_mut() {
            // The block's key line names its consumers; resolve every
            // comma-joined pattern to the REAL package it stands for
            // (`alias@npm:target@range` → target). A key like
            // `<fname>@npm:<other-pkg>@…` — yarn v1's fork-substitution
            // idiom — resolves to <other-pkg>, so it is NOT ours to touch:
            // matching on the alias name alone would hijack the fork.
            let Some(key_line) = block
                .lines()
                .find(|l| !l.is_empty() && !l.starts_with([' ', '\t', '#']))
            else {
                continue;
            };
            let Some(key) = key_line.strip_suffix(':') else {
                continue;
            };
            let patterns = split_key_patterns(key);
            if patterns.is_empty()
                || !patterns
                    .iter()
                    .all(|p| pattern_real_name(p) == Some(fname.as_str()))
            {
                continue;
            }
            if !version_re.is_match(block) {
                continue;
            }
            // A block reached only through `alias@npm:<fname>@range`
            // descriptors is left byte-identical (mirroring the berry
            // rewriter), but never silently: that copy keeps installing the
            // unpatched artifact.
            if !patterns
                .iter()
                .any(|p| split_pattern(p).is_some_and(|(n, _)| n == fname))
            {
                alias_skipped = true;
                result.warnings.push(RewriteWarning {
                    code: "redirect_yarn_classic_alias_skipped".into(),
                    detail: format!(
                        "lock entry `{key}` consumes {fname}@{} only through npm: alias \
                         descriptors; the hosted redirect does not rewrite alias entries, \
                         so this copy stays unpatched",
                        dep.version
                    ),
                });
                continue;
            }
            matched_any = true;
            let frag = dep
                .integrity
                .sha1
                .as_ref()
                .map(|s| format!("#{s}"))
                .unwrap_or_default();
            let mut rewritten = resolved_re
                .replace(
                    block,
                    format!("\n  resolved \"{}{frag}\"", dep.artifact_url).as_str(),
                )
                .to_string();
            if integrity_re.is_match(&rewritten) {
                rewritten = integrity_re
                    .replace(&rewritten, format!("\n  integrity {sha512}").as_str())
                    .to_string();
            } else {
                rewritten = resolved_re
                    .replace(
                        &rewritten,
                        // $0 re-inserts the matched resolved line, then add integrity.
                        format!(
                            "\n  resolved \"{}{frag}\"\n  integrity {sha512}",
                            dep.artifact_url
                        )
                        .as_str(),
                    )
                    .to_string();
            }
            if rewritten != *block {
                // Ledger originals record the on-disk byte form, so a future
                // revert of a CRLF lock can match what the file really held.
                let (edit_original, edit_new) = if crlf {
                    (block.replace('\n', "\r\n"), rewritten.replace('\n', "\r\n"))
                } else {
                    (block.clone(), rewritten.clone())
                };
                result.edits.push(FileEdit {
                    path: "yarn.lock".into(),
                    kind: "redirect_yarn_classic_entry".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}", dep.version)),
                    original: Some(Value::String(edit_original)),
                    new: Some(Value::String(edit_new)),
                });
                *block = rewritten;
                changed = true;
            }
        }
        if !matched_any && !alias_skipped {
            result.warnings.push(RewriteWarning {
                code: "redirect_yarn_classic_entry_not_found".into(),
                detail: format!("no yarn.lock entry resolving {fname}@{}", dep.version),
            });
        }
    }
    if changed {
        let mut out = blocks.join("\n\n");
        if crlf {
            out = out.replace('\n', "\r\n");
        }
        result.files.insert("yarn.lock".into(), out);
    }
}
