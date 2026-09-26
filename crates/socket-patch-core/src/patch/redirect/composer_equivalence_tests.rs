//! Equivalence oracle for the hosted composer.lock rewriter, which now tests
//! each `"name"` occurrence's value before walking its object, walks objects
//! byte-wise, and splices each edit into the lock in place instead of
//! re-allocating the whole lock per edit. The previous implementation is kept
//! here verbatim and the production rewriter must produce the identical
//! output bytes, FileEdit list and warnings on randomized locks.

use super::*;

fn json_object_end_from_oracle(text: &str, from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, ch) in text[from..].char_indices() {
        if in_string {
            match ch {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' if depth == 0 => return Some(from + offset),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn find_composer_entry_oracle(content: &str, pkg: &str, version: &str) -> ComposerEntry {
    let mut mismatched: Option<String> = None;
    for (name_idx, _) in content.match_indices("\"name\": \"") {
        let Some(end) = json_object_end_from_oracle(content, name_idx) else {
            continue;
        };
        let entry = &content[name_idx..=end];
        if !json_string_field(entry, "name").is_some_and(|n| n.eq_ignore_ascii_case(pkg)) {
            continue;
        }
        // Every package entry carries `version`; an `authors[]`/`support`
        // object that happens to have a matching `name` does not.
        let Some(locked) = json_string_field(entry, "version") else {
            continue;
        };
        if normalize_version(locked) == normalize_version(version) {
            return ComposerEntry::Found(name_idx, end);
        }
        mismatched = Some(locked.to_string());
    }
    match mismatched {
        Some(locked) => ComposerEntry::VersionMismatch(locked),
        None => ComposerEntry::NotFound,
    }
}

fn composer_source_before_dist_oracle(
    content: &str,
    entry_start: usize,
    dist_start: usize,
) -> Option<usize> {
    const SOURCE_KEY: &str = "\"source\": {";
    let source_start = entry_start + content[entry_start..dist_start].rfind(SOURCE_KEY)?;
    let source_end = json_object_end_from_oracle(content, source_start + SOURCE_KEY.len())?;
    (source_end < dist_start && content[source_end + 1..dist_start].trim() == ",")
        .then_some(source_start)
}

fn rewrite_composer_lock_oracle(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let composer: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "composer")
        .collect();
    if composer.is_empty() {
        return;
    }
    // Parity with `redirect_npm_no_lockfile`: a granted dep the project has
    // no lock to pin must be SAID, not silently dropped from the redirected
    // count (a composer.json + installed vendor tree without a lock is
    // discovered and granted like any other).
    if !files.contains_key("composer.lock") {
        result.warnings.push(RewriteWarning {
            code: "redirect_composer_no_lockfile".into(),
            detail: "no composer.lock present; composer redirect skipped".into(),
        });
        return;
    }
    const DIST_KEY: &str = "\"dist\": {";
    let mut content = files["composer.lock"].clone();
    let type_re: &Regex = &COMPOSER_DIST_TYPE_RE;
    let url_re: &Regex = &COMPOSER_DIST_URL_RE;
    let shasum_re: &Regex = &COMPOSER_DIST_SHASUM_RE;
    let mut changed = false;
    for dep in &composer {
        let composer_name = full_name(dep);
        let Some(sha1) = dep.integrity.sha1.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_missing_sha1".into(),
                detail: format!("{composer_name} has no sha1 (dist.shasum) integrity"),
            });
            continue;
        };
        let (entry_start, entry_end) =
            match find_composer_entry_oracle(&content, &composer_name, &dep.version) {
                ComposerEntry::Found(start, end) => (start, end),
                ComposerEntry::VersionMismatch(locked) => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_composer_version_mismatch".into(),
                        detail: format!(
                            "composer.lock pins {composer_name}@{locked}, not the patched {}",
                            dep.version
                        ),
                    });
                    continue;
                }
                ComposerEntry::NotFound => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_composer_pkg_not_found".into(),
                        detail: format!(
                            "no composer.lock package named {composer_name}@{}",
                            dep.version
                        ),
                    });
                    continue;
                }
            };
        // The dist block MUST belong to the located entry. Scanning forward
        // from the name for the next `"dist": {` walked into the FOLLOWING
        // package whenever the target was installed from source, repointing a
        // bystander's url + shasum — a checksum-clean install of the wrong
        // code. A target with no dist of its own pins nothing: fail closed.
        let Some(dist_start) = content[entry_start..=entry_end]
            .find(DIST_KEY)
            .map(|offset| entry_start + offset)
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist".into(),
                detail: format!("{composer_name} has no dist block"),
            });
            continue;
        };
        let Some(dist_end) = json_object_end_from_oracle(&content, dist_start + DIST_KEY.len())
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_lock_malformed".into(),
                detail: format!("{composer_name}'s dist block is unterminated"),
            });
            continue;
        };
        let block = content[dist_start..=dist_end].to_string();
        // Already redirected (either slash spelling): recording an edit whose
        // `original` IS the hosted url would grow the ledger on every re-run
        // and poison a future revert.
        if artifact_url_present(&block, &dep.artifact_url) && block.contains(&sha1) {
            continue;
        }
        if !block.contains("\"url\": \"") {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist_url".into(),
                detail: format!("{composer_name}'s dist block has no url to redirect"),
            });
            continue;
        }
        let mut rewritten = type_re.replace(&block, "${1}zip${2}").to_string();
        rewritten = url_re
            .replace(
                &rewritten,
                format!("${{1}}{}${{2}}", dep.artifact_url).as_str(),
            )
            .to_string();
        rewritten = if rewritten.contains("\"shasum\": \"") {
            shasum_re
                .replace(&rewritten, format!("${{1}}{sha1}${{2}}").as_str())
                .to_string()
        } else {
            append_composer_shasum(&rewritten, &sha1)
        };
        // Drop the entry's `source` (the vendored backend does the same):
        // when the dist download fails — checksum mismatch, an expired grant
        // token, a patch-server outage — composer 1 and composer 2 before its
        // source-fallback cutoff (2.2 LTS included) print "Now trying to
        // download from source" and silently install the PRISTINE upstream
        // commit from git, and `--prefer-source` / `preferred-install:
        // source` always does. With the source gone the hosted archive is
        // the only way to install the package, so a failed fetch fails the
        // install instead of shipping the vulnerable code. The edit then
        // spans `"source": {…},\n<indent>"dist": {…}`, so the ledger's
        // fragment revert puts both blocks back byte-for-byte.
        let (edit_start, original) =
            match composer_source_before_dist_oracle(&content, entry_start, dist_start) {
                Some(source_start) => (source_start, content[source_start..=dist_end].to_string()),
                None => {
                    if content[entry_start..=entry_end].contains("\"source\": {") {
                        result.warnings.push(RewriteWarning {
                            code: "redirect_composer_source_kept".into(),
                            detail: format!(
                                "{composer_name}'s source block does not directly precede its \
                                 dist and was left in place; a failed hosted download may fall \
                                 back to it"
                            ),
                        });
                    }
                    (dist_start, block.clone())
                }
            };
        if rewritten != original {
            content = format!(
                "{}{}{}",
                &content[..edit_start],
                rewritten,
                &content[dist_end + 1..]
            );
            changed = true;
            result.edits.push(FileEdit {
                path: "composer.lock".into(),
                kind: "redirect_composer_dist".into(),
                action: "rewritten".into(),
                key: Some(composer_name),
                original: Some(Value::String(original)),
                new: Some(Value::String(rewritten)),
            });
        }
    }
    if changed {
        result.files.insert("composer.lock".into(), content);
    }
}

fn assert_same(want: &RewriteResult, got: &RewriteResult, what: &str) {
    assert_eq!(got.files, want.files, "{what}: rewritten bytes");
    assert_eq!(got.edits.len(), want.edits.len(), "{what}: edit count");
    for (i, (g, w)) in got.edits.iter().zip(&want.edits).enumerate() {
        assert_eq!(g, w, "{what}: edit #{i}");
    }
    let warnings = |r: &RewriteResult| {
        r.warnings
            .iter()
            .map(|w| (w.code.clone(), w.detail.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(warnings(got), warnings(want), "{what}: warnings in order");
}

fn run_both(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    what: &str,
) -> RewriteResult {
    let mut want = RewriteResult::default();
    rewrite_composer_lock_oracle(files, overrides, &mut want);
    let mut got = RewriteResult::default();
    rewrite_composer_lock(files, overrides, &mut got);
    assert_same(&want, &got, what);
    got
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
    if rng.chance(10) {
        fields.push("\"mirrors\": [{ \"url\": \"https://m/{x}\", \"preferred\": true }]".into());
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
    let layout = rng.below(8);
    match layout {
        0 => fields.push(source_block(i)),
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
        version: version(rng).trim_start_matches('v').to_string(),
        token: String::new(),
        patch_uuid: format!("00000000-0000-4000-8000-{n:012}"),
        artifact_url: url,
        berry_zip_url: None,
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
fn in_place_composer_rewrite_matches_oracle() {
    let mut rewritten = 0;
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    for seed in 1..=3000u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
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
        let got = run_both(&files, &overrides, &format!("seed {seed}"));
        let mut rerun = files.clone();
        rerun.extend(got.files.clone());
        run_both(&rerun, &overrides, &format!("seed {seed} re-run"));
        rewritten += got.files.len();
        edits += got.edits.len();
        codes.extend(got.warnings.iter().map(|w| w.code.clone()));
    }
    assert!(rewritten > 800, "only {rewritten} rewritten locks");
    assert!(edits > 1500, "only {edits} edits");
    for code in [
        "redirect_composer_no_lockfile",
        "redirect_composer_missing_sha1",
        "redirect_composer_version_mismatch",
        "redirect_composer_pkg_not_found",
        "redirect_composer_no_dist",
        "redirect_composer_no_dist_url",
        "redirect_composer_source_kept",
    ] {
        assert!(codes.contains(code), "no case reached {code}: {codes:?}");
    }
}

#[test]
fn byte_walk_matches_the_char_walk() {
    let texts = [
        r#"{"a": "}", "b": {"c": "\"}"}, "d": "é\é\\"}"#,
        "{\"x\": \"\\\u{e9}}\"}, \"y\": 1}",
        "\"unterminated {",
        "{{{}}}}",
    ];
    for text in texts {
        for from in (0..=text.len()).filter(|&i| text.is_char_boundary(i)) {
            assert_eq!(
                json_object_end_from(text, from),
                json_object_end_from_oracle(text, from),
                "{text:?} from {from}"
            );
        }
    }
}

/// Runs the oracle over the Phase 3 benchmark composer.lock (too large to
/// commit) when `SOCKET_PATCH_COMPOSER_FIXTURE` names it, redirecting every
/// package; a no-op otherwise.
#[test]
fn in_place_composer_rewrite_matches_oracle_on_fixture() {
    let Some(path) = std::env::var_os("SOCKET_PATCH_COMPOSER_FIXTURE") else {
        return;
    };
    let text = std::fs::read_to_string(path).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    let overrides: Vec<DepOverride> = ["packages", "packages-dev"]
        .iter()
        .flat_map(|k| doc[k].as_array().cloned().unwrap_or_default())
        .enumerate()
        .map(|(n, p)| DepOverride {
            ecosystem: "composer".into(),
            name: p["name"].as_str().unwrap().to_string(),
            namespace: None,
            version: p["version"].as_str().unwrap().to_string(),
            token: String::new(),
            patch_uuid: format!("00000000-0000-4000-8000-{n:012}"),
            artifact_url: format!("https://patch.socket.dev/composer/{n}.zip"),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha1: Some("0123456789abcdef0123456789abcdef01234567".into()),
                ..Default::default()
            },
        })
        .collect();
    let mut files = BTreeMap::new();
    files.insert("composer.lock".to_string(), text);
    let got = run_both(&files, &overrides, "fixture");
    assert!(!got.edits.is_empty());
}
