//! Seeded package-lock.json and classic yarn.lock sweeps for the indexed
//! hosted rewriters (each entry's identity derived once per lock). Every
//! output channel is pinned per case by `tests/equivalence/npm_lock_rewrite`
//! and `yarn_classic_rewrite.golden`, blessed while the pre-index rewriters
//! still ran beside them as oracles.

use super::*;
use crate::golden::{record, Golden, Sweep};
use crate::test_rng::Rng;

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
fn indexed_npm_lock_rewrite_matches_golden() {
    let sweep = Sweep::with(
        Golden::new(
            "npm_lock_rewrite",
            "One seeded package-lock.json / npm-shrinkwrap.json + overrides.",
        )
        .chunked(4),
    );
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    for seed in 1..=400u64 {
        let mut rng = Rng::new(seed);
        let mut pool = Vec::new();
        let text = npm_lock(&mut rng, &mut pool);
        let deps = overrides(&pool, &mut rng);
        let refs: Vec<&DepOverride> = deps.iter().collect();
        for lockfile in ["package-lock.json", "npm-shrinkwrap.json"] {
            let mut got = RewriteResult::default();
            rewrite_one_npm_lock(
                &text,
                parse_json_text(&text).ok(),
                lockfile,
                &refs,
                &NpmOverrides::default(),
                &mut got,
            );
            record(&(&text, lockfile, &deps), &got);
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
    sweep.finish();
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
fn indexed_yarn_classic_rewrite_matches_golden() {
    let sweep = Sweep::with(
        Golden::new(
            "yarn_classic_rewrite",
            "One seeded yarn.lock (v1) + overrides.",
        )
        .chunked(2),
    );
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
        let mut got = RewriteResult::default();
        rewrite_yarn_classic(&files, &deps, &mut got);
        record(&(&files, &deps), &got);
        edits += got.edits.len();
        codes.extend(got.warnings.iter().map(|w| w.code.clone()));
    }
    assert!(edits > 400, "edits: {edits}");
    for code in [
        "redirect_yarn_classic_missing_sha512",
        "redirect_yarn_classic_alias_skipped",
        "redirect_yarn_classic_entry_not_found",
        "redirect_yarn_classic_unresolved_entry_skipped",
        "redirect_yarn_classic_unsupported_line_endings",
    ] {
        assert!(codes.contains(code), "missing {code}: {codes:?}");
    }
    sweep.finish();
}
