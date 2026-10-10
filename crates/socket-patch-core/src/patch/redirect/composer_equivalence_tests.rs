//! Seeded composer.lock sweep for the hosted rewriter (the in-place,
//! byte-walking splice): output bytes, FileEdits and warnings are pinned per
//! case by `tests/equivalence/composer_*.golden`, blessed while the
//! pre-splice rewriter still ran beside it as an oracle.

use super::*;
use crate::formats::composer::hosted::*;
use crate::golden::Golden;
use crate::test_rng::Rng;

fn run(files: &BTreeMap<String, String>, overrides: &[DepOverride]) -> RewriteResult {
    let mut got = RewriteResult::default();
    rewrite_composer_lock(files, overrides, &mut got);
    got
}

fn pkg(i: usize, rng: &mut Rng) -> String {
    if rng.chance(15) {
        format!("Vendor{}/Pkg-{i}", i % 3)
    } else {
        format!("vendor{}/pkg-{i}", i % 3)
    }
}

fn version(rng: &mut Rng) -> &'static str {
    ["1.0.0", "v1.0.0", "2.3.4", "v2.3.4", "dev-main"][rng.below(5)]
}

const I: &str = "            ";

fn source_block(i: usize) -> String {
    format!(
        "\"source\": {{\n{I}    \"type\": \"git\",\n{I}    \"url\": \"https://github.com/v/p{i}.git\",\n{I}    \"reference\": \"abc{i}\"\n{I}}}"
    )
}

fn dist_block(i: usize, rng: &mut Rng) -> String {
    let url = match rng.below(8) {
        0 => format!("https://patch.socket.dev/composer/{i}.zip"),
        1 => format!("https:\\/\\/patch.socket.dev\\/composer\\/{i}.zip"),
        _ => format!("https://api.github.com/repos/v/p{i}/zipball/abc{i}"),
    };
    let mut fields = vec![format!(
        "\"type\": \"{}\"",
        ["zip", "tar", "path"][rng.below(3)]
    )];
    if !rng.chance(8) {
        fields.push(format!("\"url\": \"{url}\""));
    }
    fields.push(format!("\"reference\": \"abc{i}\""));
    match rng.below(4) {
        0 => {}
        1 => fields.push("\"shasum\": \"\"".into()),
        2 => fields.push("\"shasum\": \"0123456789abcdef0123456789abcdef01234567\"".into()),
        _ => fields.push("\"shasum\": \"ffffffffffffffffffffffffffffffffffffffff\"".into()),
    }
    // Mirrors after the url, before it (the mirror's own `url` then comes
    // first in the block), or as the dist's only url.
    let mirrors = "\"mirrors\": [{ \"url\": \"https://m/{x}\", \"preferred\": true }]";
    match rng.below(20) {
        0 | 1 => fields.push(mirrors.into()),
        2 => fields.insert(1, mirrors.into()),
        _ => {}
    }
    format!(
        "\"dist\": {{\n{I}    {}\n{I}}}",
        fields.join(&format!(",\n{I}    "))
    )
}

fn entry(i: usize, rng: &mut Rng) -> String {
    let mut fields = vec![
        format!("\"name\": \"{}\"", pkg(i, rng)),
        format!("\"version\": \"{}\"", version(rng)),
    ];
    let layout = rng.below(9);
    match layout {
        0 => fields.push(source_block(i)),
        // A key-sorted or hand-edited lock can put `source` before `name`.
        8 => {
            fields.insert(0, source_block(i));
            fields.push(dist_block(i, rng));
        }
        1 => fields.push(dist_block(i, rng)),
        2 => {
            fields.push(dist_block(i, rng));
            fields.push(source_block(i));
        }
        3 => {
            fields.push(source_block(i));
            fields.push("\"notification-url\": \"https://packagist.org/downloads/\"".into());
            fields.push(dist_block(i, rng));
        }
        _ => {
            fields.push(source_block(i));
            fields.push(dist_block(i, rng));
        }
    }
    // Origin-bound download options, which the rewrite drops with `source`
    // (chosen by index, not the rng, so every other case keeps its input).
    if i % 11 == 5 {
        fields.push(format!(
            "\"transport-options\": {{\n{I}    \"http\": {{ \"header\": [\"Authorization: Bearer t{i}\"] }}\n{I}}}"
        ));
    }
    if rng.chance(40) {
        fields.push(format!(
            "\"authors\": [\n{I}    {{\n{I}        \"name\": \"{}\",\n{I}        \"email\": \"a@b.c\"\n{I}    }}\n{I}]",
            if rng.chance(30) { pkg(rng.below(20), rng) } else { "Jane Dœ".to_string() }
        ));
    }
    if rng.chance(30) {
        fields.push(format!(
            "\"description\": \"braces {{ }} and \\\"quotes\\\" and é {}\"",
            if rng.chance(50) { "\\\\" } else { "" }
        ));
    }
    if rng.chance(15) {
        fields.push("\"support\": {\n                \"name\": \"x\", \"issues\": \"https://i\"\n            }".into());
    }
    format!(
        "        {{\n{I}{}\n        }}",
        fields.join(&format!(",\n{I}"))
    )
}

fn lock(rng: &mut Rng, pool: usize) -> String {
    let mut packages = Vec::new();
    let mut dev = Vec::new();
    for _ in 0..(2 + rng.below(14)) {
        let e = entry(rng.below(pool), rng);
        if rng.chance(25) {
            dev.push(e);
        } else {
            packages.push(e);
        }
    }
    let mut text = format!(
        "{{\n    \"_readme\": [\n        \"This file locks the dependencies\"\n    ],\n    \"content-hash\": \"abc\",\n    \"packages\": [\n{}\n    ],\n    \"packages-dev\": [\n{}\n    ],\n    \"aliases\": []\n}}\n",
        packages.join(",\n"),
        dev.join(",\n")
    );
    if rng.chance(10) {
        text = text.replace('\n', "\r\n");
    }
    if rng.chance(3) {
        text.truncate(text.len() * 2 / 3);
    }
    text
}

fn dep(rng: &mut Rng, pool: usize, n: usize) -> DepOverride {
    let name = pkg(rng.below(pool + 1), rng);
    let (namespace, bare) = match name.split_once('/') {
        Some((ns, bare)) if rng.chance(70) => (Some(ns.to_string()), bare.to_string()),
        _ => (None, name.clone()),
    };
    let url = match rng.below(6) {
        0 => format!("https://patch.socket.dev/composer/{}.zip", rng.below(pool)),
        1 => "https://patch.socket.dev/composer/with$1dollar.zip".to_string(),
        _ => format!("https://patch.socket.dev/composer/{n}/{bare}.zip"),
    };
    DepOverride {
        ecosystem: if rng.chance(5) { "npm" } else { "composer" }.into(),
        name: bare,
        namespace,
        // The bare, `v`-prefixed or padded spelling of the locked release.
        version: match rng.below(4) {
            0 => format!("{}.0", version(rng).trim_start_matches('v')),
            1 => version(rng).to_string(),
            _ => version(rng).trim_start_matches('v').to_string(),
        },
        token: String::new(),
        patch_uuid: format!("00000000-0000-4000-8000-{n:012}"),
        artifact_url: url,
        registry_override: None,
        integrity: Integrity {
            sha1: (!rng.chance(8)).then(|| {
                [
                    "0123456789abcdef0123456789abcdef01234567",
                    "1111111111111111111111111111111111111111",
                ][rng.below(2)]
                .to_string()
            }),
            ..Default::default()
        },
    }
}

#[test]
fn in_place_composer_rewrite_matches_golden() {
    let mut rewritten = 0;
    let mut edits = 0;
    let mut reverted = 0;
    let mut codes = std::collections::BTreeSet::new();
    let mut golden = crate::golden::Golden::new(
        "composer_lock_rewrite",
        "One seeded composer.lock + overrides; the output covers a re-run over the result.",
    )
    .chunked(10);
    for seed in 1..=3000u64 {
        let mut rng = Rng::new(seed);
        let pool = 3 + rng.below(12);
        let mut files = BTreeMap::new();
        if !rng.chance(3) {
            files.insert("composer.lock".to_string(), lock(&mut rng, pool));
        }
        let mut overrides: Vec<DepOverride> = (0..(1 + rng.below(8)))
            .map(|n| dep(&mut rng, pool, n))
            .collect();
        if rng.chance(20) {
            let mut again = overrides[rng.below(overrides.len())].clone();
            if rng.chance(50) {
                again.artifact_url.push_str("?v=2");
            }
            overrides.push(again);
        }
        let got = run(&files, &overrides);
        // The ledger's fragment revert: undoing every edit, newest first,
        // restores the input byte for byte (checked when each fragment is
        // unambiguous in the text it is undone from).
        if let (Some(out), Some(input)) =
            (got.files.get("composer.lock"), files.get("composer.lock"))
        {
            let mut text = out.clone();
            let mut unique = true;
            for edit in got.edits.iter().rev() {
                let (original, new) = (
                    edit.original.as_ref().and_then(Value::as_str).unwrap(),
                    edit.new.as_ref().and_then(Value::as_str).unwrap(),
                );
                unique &= text.matches(new).count() == 1;
                text = text.replacen(new, original, 1);
            }
            if unique {
                assert_eq!(&text, input, "seed {seed}: fragment revert");
                reverted += 1;
            }
        }
        let mut rerun = files.clone();
        rerun.extend(got.files.clone());
        let again = run(&rerun, &overrides);
        golden.case(seed, &(&files, &overrides), &(&got, &again));
        rewritten += got.files.len();
        edits += got.edits.len();
        codes.extend(got.warnings.iter().map(|w| w.code.clone()));
    }
    assert!(rewritten > 800, "only {rewritten} rewritten locks");
    assert!(edits > 1500, "only {edits} edits");
    assert!(reverted > 600, "only {reverted} locks revert-checked");
    for code in [
        "redirect_composer_no_lockfile",
        "redirect_composer_missing_sha1",
        "redirect_composer_version_mismatch",
        "redirect_composer_pkg_not_found",
        "redirect_composer_no_dist",
        "redirect_composer_no_dist_url",
        "redirect_composer_dist_mirrors_removed",
        "redirect_composer_transport_options_removed",
    ] {
        assert!(codes.contains(code), "no case reached {code}: {codes:?}");
    }
    golden.finish();
}

#[test]
fn json_object_end_matches_golden() {
    let texts = [
        r#"{"a": "}", "b": {"c": "\"}"}, "d": "é\é\\"}"#,
        "{\"x\": \"\\\u{e9}}\"}, \"y\": 1}",
        "\"unterminated {",
        "{{{}}}}",
    ];
    let mut golden = Golden::new(
        "composer_json_object_end",
        "One (text, start) pair: where its JSON object ends.",
    );
    for text in texts {
        for from in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
            golden.next(&(text, from), &json_object_end_from(text, from));
        }
    }
    golden.finish();
}
