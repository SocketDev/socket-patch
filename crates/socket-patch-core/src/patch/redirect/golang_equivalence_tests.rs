//! Seeded go.mod / go.sum sweep for the hosted golang rewriter (one go.mod
//! walk per dep, directives appended in place, go.sum edited as lines):
//! CRLF and mixed endings, unclosed blocks, socket-owned and user-authored
//! replaces, stale pins, malformed integrity and duplicate deps. Output
//! bytes, FileEdits and warnings are pinned per case by
//! `tests/equivalence/golang_rewrite.golden`, blessed while the previous
//! rewriter still ran beside it as an oracle.

use super::*;
use crate::golden::Golden;
use crate::test_rng::Rng;

fn run(g: &mut Golden, files: &BTreeMap<String, String>, overrides: &[DepOverride]) -> RewriteResult {
    let mut got = RewriteResult::default();
    rewrite_golang(files, overrides, &mut got);
    g.next(&(files, overrides), &got);
    got
}

const H1_A: &str = "h1:0000000000000000000000000000000000000000000=";
const H1_B: &str = "h1:1111111111111111111111111111111111111111111=";

fn module(i: usize) -> String {
    format!("github.com/org{}/mod{i}", i % 3)
}

fn version(rng: &mut Rng) -> &'static str {
    [
        "v1.0.0",
        "v1.0.0",
        "v1.2.3",
        "v0.0.0-20210101000000-abcdef123456",
    ][rng.below(4)]
}

fn uuid(n: usize) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

fn hosted(n: usize) -> String {
    format!("patch.socket.dev/gopatch/{}", uuid(n))
}

fn replace_body(rng: &mut Rng, pool: usize) -> String {
    let m = module(rng.below(pool));
    let lhs = if rng.chance(70) {
        format!("{m} {}", version(rng))
    } else {
        m.clone()
    };
    let rhs = match rng.below(6) {
        0 => format!("{} v1.0.0-socketpatch.1", hosted(rng.below(4))),
        1 => format!("./.socket/vendor/golang/{}/{m}@v1.0.0", uuid(rng.below(4))),
        2 => format!("./.socket/go-patches/{m}@v1.0.0"),
        3 => "../local-fork".to_string(),
        _ => format!("example.com/fork{} v1.1.0", rng.below(3)),
    };
    format!("{lhs} => {rhs}")
}

fn go_mod(rng: &mut Rng, pool: usize) -> String {
    let mut out = String::from("module example.com/app\n\ngo 1.21\n");
    if rng.chance(30) {
        out.push_str("\n// a comment about replace example.com/x => y\n");
    }
    for _ in 0..rng.below(3) {
        let sep = if rng.chance(20) { "\t" } else { " " };
        out.push_str(&format!("\nreplace{sep}{}\n", replace_body(rng, pool)));
    }
    out.push_str("\nrequire (\n");
    for i in 0..pool {
        if rng.chance(85) {
            let comment = if rng.chance(20) { " // indirect" } else { "" };
            out.push_str(&format!("\t{} {}{comment}\n", module(i), version(rng)));
        }
    }
    if !rng.chance(5) {
        out.push_str(")\n");
    }
    if rng.chance(40) {
        out.push_str(&format!("\nrequire {} v1.0.0\n", module(rng.below(pool))));
    }
    match rng.below(5) {
        0 => out.push_str("\nreplace ()\n"),
        1 | 2 => {
            out.push_str("\nreplace (\n");
            for _ in 0..(1 + rng.below(3)) {
                out.push_str(&format!("\t{}\n", replace_body(rng, pool)));
            }
            if !rng.chance(10) {
                out.push_str(")\n");
            }
        }
        _ => {}
    }
    for _ in 0..rng.below(2) {
        out.push_str(&format!("replace {}\n", replace_body(rng, pool)));
    }
    if rng.chance(15) {
        out.push_str("\n\n");
    }
    if rng.chance(10) {
        out.pop();
    }
    out
}

fn go_sum(rng: &mut Rng, pool: usize) -> String {
    let mut lines = Vec::new();
    for i in 0..pool {
        if rng.chance(80) {
            let v = version(rng);
            lines.push(format!("{} {v} {H1_A}", module(i)));
            lines.push(format!("{} {v}/go.mod {H1_B}", module(i)));
        }
    }
    for n in 0..rng.below(3) {
        let v = if rng.chance(50) {
            "v1.0.0-socketpatch.1"
        } else {
            "v1.2.3-socketpatch.1"
        };
        let h = if rng.chance(30) { H1_B } else { H1_A };
        lines.push(format!("{} {v} {h}", hosted(n)));
        if rng.chance(70) {
            lines.push(format!("{} {v}/go.mod {H1_B}", hosted(n)));
        }
    }
    if rng.chance(20) {
        let i = rng.below(lines.len().max(1));
        lines.insert(i.min(lines.len()), String::new());
    }
    if rng.chance(20) && lines.len() > 2 {
        let a = rng.below(lines.len());
        let b = rng.below(lines.len());
        lines.swap(a, b);
    }
    if rng.chance(10) && !lines.is_empty() {
        let dup = lines[rng.below(lines.len())].clone();
        lines.push(dup);
    }
    let mut out = lines.join("\n");
    match rng.below(10) {
        0 => {}
        1 => out.push('\r'),
        _ => out.push('\n'),
    }
    out
}

fn line_endings(text: String, rng: &mut Rng) -> String {
    match rng.below(5) {
        0 => text.replace('\n', "\r\n"),
        1 => text
            .split_inclusive('\n')
            .enumerate()
            .map(|(i, l)| {
                if i % 4 == 1 {
                    l.replace('\n', "\r\n")
                } else {
                    l.to_string()
                }
            })
            .collect(),
        _ => text,
    }
}

fn dep(rng: &mut Rng, pool: usize, n: usize) -> DepOverride {
    let i = rng.below(pool + 1);
    let v = version(rng);
    let socket = rng.below(4);
    let (go_module_path, go_module_version) = match rng.below(20) {
        0 => (None, Some("v1.0.0-socketpatch.1".to_string())),
        1 => (
            Some(format!("example.com/evil/{n}")),
            Some("v1".to_string()),
        ),
        2 => (Some(hosted(socket)), Some("v1 bad".to_string())),
        _ => (
            Some(hosted(socket)),
            Some(
                if rng.chance(50) {
                    "v1.0.0-socketpatch.1"
                } else {
                    "v1.2.3-socketpatch.1"
                }
                .to_string(),
            ),
        ),
    };
    let registry_override = (!rng.chance(8)).then(|| RegistryOverride {
        kind: if rng.chance(5) { "npm" } else { "goproxy" }.into(),
        index_url: "https://patch.socket.dev/patch-registry/golang".into(),
        identifiers: RegistryOverrideIdentifiers {
            name: module(i),
            version: v.into(),
            go_module_path,
            go_module_version,
            ..Default::default()
        },
    });
    let h1 = |rng: &mut Rng| match rng.below(12) {
        0 => None,
        1 => Some("sha256:nope".to_string()),
        _ => Some(if rng.chance(50) { H1_A } else { H1_B }.to_string()),
    };
    DepOverride {
        ecosystem: if rng.chance(5) { "npm" } else { "golang" }.into(),
        name: module(i),
        namespace: None,
        version: v.into(),
        token: String::new(),
        patch_uuid: uuid(n),
        artifact_url: String::new(),
        registry_override,
        integrity: Integrity {
            dirhash_h1: h1(rng),
            go_mod_h1: h1(rng),
            ..Default::default()
        },
    }
}

#[test]
fn single_walk_golang_rewrite_matches_golden() {
    let mut rewritten = 0;
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    let mut kinds = std::collections::BTreeSet::new();
    let mut g = Golden::new(
        "golang_rewrite",
        "One seeded go.mod / go.sum pair + overrides, or the re-run over its output.",
    )
    .chunked(20);
    for seed in 1..=3000u64 {
        let mut rng = Rng::new(seed);
        let pool = 3 + rng.below(12);
        let mut files = BTreeMap::new();
        if !rng.chance(3) {
            let m = go_mod(&mut rng, pool);
            files.insert("go.mod".to_string(), line_endings(m, &mut rng));
        }
        if rng.chance(85) {
            let s = go_sum(&mut rng, pool);
            files.insert("go.sum".to_string(), line_endings(s, &mut rng));
        }
        let mut overrides: Vec<DepOverride> = (0..(1 + rng.below(8)))
            .map(|n| dep(&mut rng, pool, n))
            .collect();
        if rng.chance(15) {
            let again = overrides[rng.below(overrides.len())].clone();
            overrides.push(again);
        }
        let got = run(&mut g, &files, &overrides);
        // A second pass over the output: the idempotent re-run.
        let mut rerun = files.clone();
        rerun.extend(got.files.clone());
        run(&mut g, &rerun, &overrides);
        rewritten += got.files.len();
        edits += got.edits.len();
        codes.extend(got.warnings.iter().map(|w| w.code.clone()));
        kinds.extend(got.edits.iter().map(|e| e.kind.clone()));
    }
    assert!(rewritten > 1000, "only {rewritten} rewritten files");
    assert!(edits > 3000, "only {edits} edits");
    for code in [
        "redirect_golang_no_go_mod",
        "redirect_golang_unsupported",
        "redirect_golang_missing_module",
        "redirect_golang_untrusted_module_path",
        "redirect_golang_unsafe_coords",
        "redirect_golang_missing_integrity",
        "redirect_golang_version_mismatch",
        "redirect_golang_replace_conflict",
    ] {
        assert!(codes.contains(code), "no case reached {code}: {codes:?}");
    }
    for kind in [
        "redirect_golang_replace",
        "redirect_golang_gosum",
        "redirect_golang_gosum_prune",
        "redirect_golang_stale_replace_removed",
        "redirect_golang_stale_gosum_removed",
    ] {
        assert!(kinds.contains(kind), "no case reached {kind}: {kinds:?}");
    }
    g.finish();
}
