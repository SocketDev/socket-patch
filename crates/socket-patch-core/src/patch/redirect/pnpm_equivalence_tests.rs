//! Equivalence oracle for the indexed pnpm hosted rewriter: the previous
//! implementation (re-parse every lock per dep, splice per dep) is kept here
//! verbatim as `rewrite_pnpm_lock_oracle`, and the production
//! `rewrite_pnpm_lock` must produce the identical `RewriteResult` — output
//! bytes, the FileEdit list (order and `original` fragments), warnings and
//! refusals — on depscan-sized synthetic locks and on randomized mixes of
//! every lock flavor the grammar handles.

use super::rewrite_oracle_support::{assert_same, Rng};
use super::*;

/// Run both implementations and assert they agree; returns the result.
fn assert_equivalent(files: &BTreeMap<String, String>, overrides: &[DepOverride]) -> RewriteResult {
    let mut want = RewriteResult::default();
    rewrite_pnpm_lock_oracle(files, overrides, &mut want);
    let mut got = RewriteResult::default();
    rewrite_pnpm_lock(files, overrides, &mut got);
    assert_same(&want, &got, "pnpm");
    got
}

#[derive(Clone, Copy, PartialEq)]
enum Flavor {
    /// lockfileVersion 9: bare `name@ver` packages keys, flow resolutions,
    /// peer contexts only in `snapshots:`.
    V9,
    /// lockfileVersion 6: `/name@ver(peer@x)` packages keys.
    V6,
    /// lockfileVersion 5.4: `/name/ver_peer@x` keys, flow resolutions.
    V54,
    /// lockfileVersion 5.1: `/name/ver` keys, BLOCK resolutions.
    V51,
    /// Early pnpm 1: shrinkwrapVersion 3 with no minor — refused.
    EarlyShrinkwrap,
}

#[derive(Clone)]
struct Pkg {
    name: String,
    version: String,
}

fn pkg_name(i: usize) -> String {
    match i % 5 {
        0 => format!("@scope{}/pkg-{i}", i % 7),
        _ => format!("pkg-{i}"),
    }
}

fn sri(tag: &str) -> String {
    format!("sha512-{tag}==")
}

/// Render one lock. `extra` lines are appended verbatim to `packages:` (for
/// hand-placed residual / vendored / already-hosted instances).
fn render_lock(
    flavor: Flavor,
    pkgs: &[Pkg],
    rng: &mut Rng,
    extra: &[String],
    crlf: bool,
) -> String {
    let mut out = String::new();
    match flavor {
        Flavor::V9 => {
            out.push_str("lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\n")
        }
        Flavor::V6 => out.push_str("lockfileVersion: '6.0'\n\n"),
        Flavor::V54 => out.push_str("lockfileVersion: 5.4\n\n"),
        Flavor::V51 => out.push_str("lockfileVersion: 5.1\n\n"),
        Flavor::EarlyShrinkwrap => out.push_str("shrinkwrapVersion: 3\n\n"),
    }
    out.push_str("importers:\n  .:\n    dependencies:\n");
    for p in pkgs.iter().take(20) {
        let q = if p.name.starts_with('@') { "'" } else { "" };
        out.push_str(&format!(
            "      {q}{}{q}:\n        specifier: ^{}\n        version: {}\n",
            p.name, p.version, p.version
        ));
    }
    out.push_str("\npackages:\n\n");
    let key = |p: &Pkg, suffix: &str| -> String {
        let raw = match flavor {
            Flavor::V9 => format!("{}@{}{suffix}", p.name, p.version),
            Flavor::V6 => format!("/{}@{}{suffix}", p.name, p.version),
            Flavor::V54 | Flavor::V51 | Flavor::EarlyShrinkwrap => {
                format!("/{}/{}{suffix}", p.name, p.version)
            }
        };
        if raw.starts_with('@') || (raw.contains('(') && rng_quote(&raw)) {
            format!("'{raw}'")
        } else {
            raw
        }
    };
    for (i, p) in pkgs.iter().enumerate() {
        // Peer-suffixed multi-instance keys where the flavor encodes them.
        let suffixes: Vec<String> = match flavor {
            Flavor::V6 if rng.chance(15) => {
                let mut s = vec![String::new(), "(react@18.2.0)".to_string()];
                if rng.chance(50) {
                    s.push("(react@18.2.0(scheduler@0.23.2))(typescript@5.4.5)".into());
                }
                s
            }
            Flavor::V54 if rng.chance(15) => {
                vec![
                    "_react@18.2.0".into(),
                    "_react@17.0.2+typescript@5.4.5".into(),
                ]
            }
            _ => vec![String::new()],
        };
        for suffix in suffixes {
            out.push_str(&format!("  {}:\n", key(p, &suffix)));
            let integrity = sri(&format!("UP{i}"));
            let tarball = rng.chance(5);
            match flavor {
                Flavor::V51 | Flavor::EarlyShrinkwrap => {
                    out.push_str(&format!("    resolution:\n      integrity: {integrity}\n"));
                    if tarball {
                        out.push_str(&format!(
                            "      tarball: https://registry.npmjs.org/{}/-/x-{}.tgz\n",
                            p.name, p.version
                        ));
                    }
                }
                _ => {
                    if tarball {
                        out.push_str(&format!(
                            "    resolution: {{integrity: {integrity}, tarball: https://registry.npmjs.org/{}/-/x-{}.tgz}}\n",
                            p.name, p.version
                        ));
                    } else {
                        out.push_str(&format!("    resolution: {{integrity: {integrity}}}\n"));
                    }
                }
            }
            if rng.chance(30) {
                out.push_str("    engines: {node: '>=12'}\n");
            }
            if rng.chance(30) {
                out.push_str("    dependencies:\n      dep-a: 1.0.0\n      dep-b: 2.0.0\n");
            }
            if matches!(flavor, Flavor::V6 | Flavor::V54 | Flavor::V51) {
                out.push_str("    dev: false\n");
            }
            out.push('\n');
        }
    }
    for line in extra {
        out.push_str(line);
        out.push('\n');
    }
    if flavor == Flavor::V9 {
        out.push_str("snapshots:\n\n");
        for p in pkgs {
            let q = if p.name.starts_with('@') { "'" } else { "" };
            out.push_str(&format!("  {q}{}@{}{q}: {{}}\n\n", p.name, p.version));
            if rng.chance(10) {
                out.push_str(&format!(
                    "  {}@{}(react@18.2.0):\n    dependencies:\n      react: 18.2.0\n\n",
                    p.name, p.version
                ));
            }
        }
    }
    if crlf {
        out = out.replace('\n', "\r\n");
    }
    out
}

/// pnpm quotes keys carrying flow delimiters inconsistently across
/// releases; exercise both spellings deterministically.
fn rng_quote(raw: &str) -> bool {
    raw.len().is_multiple_of(2)
}

fn dep(p: &Pkg, uuid: usize, url_tag: &str, sha512: Option<&str>) -> DepOverride {
    let (namespace, name) = match p.name.split_once('/') {
        Some((ns, name)) if p.name.starts_with('@') => (Some(ns.to_string()), name.to_string()),
        _ => (None, p.name.clone()),
    };
    DepOverride {
        ecosystem: "npm".into(),
        name,
        namespace,
        version: p.version.clone(),
        token: String::new(),
        patch_uuid: format!("00000000-0000-4000-8000-{uuid:012}"),
        artifact_url: format!(
            "https://patch.socket.dev/{url_tag}/{}-{}.tgz",
            p.name, p.version
        ),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha512: sha512.map(str::to_string),
            ..Default::default()
        },
    }
}

fn packages(n: usize, rng: &mut Rng) -> Vec<Pkg> {
    (0..n)
        .map(|i| Pkg {
            name: pkg_name(i),
            version: format!("{}.{}.{}", rng.below(20), rng.below(20), rng.below(20)),
        })
        .collect()
}

/// A depscan-sized lock set (~5.5k instances across a root v9 lock plus a
/// nested v6 lock and a nested block-resolution v5.1 lock) with ~110 overrides
/// covering every outcome: rewritten single and peer-suffixed multi-instance
/// deps, duplicate overrides of one name@version (same and different URL),
/// already-hosted, residual (unbalanced peer suffix), vendored, not-found and
/// missing-sha512 deps, plus a non-npm override the rewriter must ignore.
#[test]
fn indexed_pnpm_rewrite_matches_oracle_on_depscan_sized_lock_set() {
    let mut rng = Rng(0x5eed_cafe_f00d_0001);
    let root = packages(4000, &mut rng);
    let nested = packages(1200, &mut rng);
    let legacy = packages(300, &mut rng);
    let already = &root[7];
    let residual = &nested[11];
    let vendored = Pkg {
        name: "vendored-pkg".into(),
        version: "1.0.0".into(),
    };
    let root_extra = vec![
        format!(
            "  vendored-pkg@file:.socket/vendor/npm/vendored-pkg-1.0.0.tgz:\n    resolution: {{tarball: file:.socket/vendor/npm/vendored-pkg-1.0.0.tgz}}\n"
        ),
        // A second copy of an entry that already points at the hosted
        // artifact (a re-run): rebuilt == original, no edit.
        format!(
            "  {}@{}(zzz@1.0.0):\n    resolution: {{integrity: sha512-ALREADY==, tarball: https://patch.socket.dev/a/{}-{}.tgz}}\n",
            already.name, already.version, already.name, already.version
        ),
    ];
    let nested_extra = vec![format!(
        "  /{}@{}(react@18.2.0:\n    resolution: {{integrity: sha512-UNBALANCED==}}\n",
        residual.name, residual.version
    )];
    let mut files = BTreeMap::new();
    files.insert(
        "pnpm-lock.yaml".to_string(),
        render_lock(Flavor::V9, &root, &mut rng, &root_extra, false),
    );
    files.insert(
        "packages/app/pnpm-lock.yaml".to_string(),
        render_lock(Flavor::V6, &nested, &mut rng, &nested_extra, false),
    );
    files.insert(
        "legacy/shrinkwrap.yaml".to_string(),
        render_lock(Flavor::V51, &legacy, &mut rng, &[], true),
    );
    // Not a lock: never read.
    files.insert("package.json".to_string(), "{}\n".to_string());

    let mut overrides = Vec::new();
    let mut uuid = 0;
    for i in 0..90 {
        let p = match i % 3 {
            0 => &root[rng.below(root.len())],
            1 => &nested[rng.below(nested.len())],
            _ => &legacy[rng.below(legacy.len())],
        };
        uuid += 1;
        overrides.push(dep(p, uuid, "a", Some(&sri(&format!("P{i}")))));
    }
    // Duplicate overrides of one name@version: different URL (the second
    // must see the first's rewritten text) and identical URL (no-op).
    for (i, p) in [&root[100], &nested[200], &legacy[30]]
        .into_iter()
        .enumerate()
    {
        uuid += 1;
        overrides.push(dep(p, uuid, "a", Some(&sri(&format!("D{i}")))));
        uuid += 1;
        overrides.push(dep(p, uuid, "b", Some(&sri(&format!("E{i}")))));
        uuid += 1;
        overrides.push(dep(p, uuid, "b", Some(&sri(&format!("E{i}")))));
    }
    uuid += 1;
    overrides.push(dep(already, uuid, "a", Some(&sri("A"))));
    uuid += 1;
    overrides.push(dep(residual, uuid, "a", Some(&sri("R"))));
    uuid += 1;
    overrides.push(dep(&vendored, uuid, "a", Some(&sri("V"))));
    for i in 0..5 {
        uuid += 1;
        let absent = Pkg {
            name: format!("absent-{i}"),
            version: "9.9.9".into(),
        };
        overrides.push(dep(&absent, uuid, "a", Some(&sri("N"))));
    }
    uuid += 1;
    overrides.push(dep(&root[50], uuid, "a", None));
    uuid += 1;
    let mut pypi = dep(&root[60], uuid, "a", Some(&sri("Y")));
    pypi.ecosystem = "pypi".into();
    overrides.push(pypi);
    // Interleave so duplicate / residual / not-found deps land between
    // ordinary rewrites (pending splices exist when they are processed).
    let mut shuffled = Vec::with_capacity(overrides.len());
    while !overrides.is_empty() {
        let i = rng.below(overrides.len());
        shuffled.push(overrides.remove(i));
    }

    let r = assert_equivalent(&files, &shuffled);
    // The fixture must actually exercise the interesting paths.
    assert!(r.edits.len() > 90, "edits: {}", r.edits.len());
    assert_eq!(r.files.len(), 3, "{:?}", r.files.keys());
    let codes: Vec<&str> = r.warnings.iter().map(|w| w.code.as_str()).collect();
    for code in [
        "redirect_pnpm_unsupported_lock_key",
        "redirect_pnpm_entry_vendored",
        "redirect_pnpm_entry_not_found",
        "redirect_pnpm_missing_sha512",
    ] {
        assert!(codes.contains(&code), "missing {code}: {codes:?}");
    }
}

/// Two overrides of the SAME name@version with different artifacts: the
/// second re-reads the first's rewritten resolution (its edit's `original`
/// is the first's `new`), exactly as the per-dep re-parse did.
#[test]
fn duplicate_override_sees_the_prior_rewrite() {
    let p = Pkg {
        name: "left-pad".into(),
        version: "1.3.0".into(),
    };
    let lock = "lockfileVersion: '6.0'\n\npackages:\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-UP==}\n    dev: false\n\n  /left-pad@1.3.0(react@18.2.0):\n    resolution: {integrity: sha512-UP==}\n    dev: false\n";
    let files = BTreeMap::from([("pnpm-lock.yaml".to_string(), lock.to_string())]);
    let first = dep(&p, 1, "a", Some("sha512-FIRST=="));
    let second = dep(&p, 2, "b", Some("sha512-SECOND=="));
    let r = assert_equivalent(&files, &[first.clone(), second.clone()]);
    assert_eq!(r.edits.len(), 4, "{:#?}", r.edits);
    for i in 0..2 {
        assert_eq!(r.edits[i + 2].original, r.edits[i].new, "edit {i}");
    }
    let out = &r.files["pnpm-lock.yaml"];
    assert_eq!(
        out.matches(second.artifact_url.as_str()).count(),
        2,
        "{out}"
    );
    assert!(!out.contains(first.artifact_url.as_str()), "{out}");
    // The same pair with identical artifacts: the second is a no-op.
    let r = assert_equivalent(&files, &[second.clone(), second]);
    assert_eq!(r.edits.len(), 2, "{:#?}", r.edits);
}

/// Every peer-suffixed instance gets its own edit, in file order, keyed by
/// the canonical instance key — across a quoted scoped v6 key, nested peer
/// contexts and a v5 `_` suffix in a second lock.
#[test]
fn peer_suffixed_instances_rewrite_in_file_order() {
    let lock_v6 = "lockfileVersion: '6.0'\n\npackages:\n\n  '/@s/p@1.0.0(react@18.2.0(scheduler@0.23.2))':\n    resolution: {integrity: sha512-UP==}\n\n  /@s/p@1.0.0:\n    resolution: {integrity: sha512-UP==}\n\n  /@s/p@1.0.0(react@17.0.2):\n    resolution: {integrity: sha512-UP==}\n\n  /@s/p@1.0.01:\n    resolution: {integrity: sha512-OTHER==}\n";
    let lock_v5 = "lockfileVersion: 5.4\n\npackages:\n\n  /@s/p/1.0.0_react@18.2.0:\n    resolution: {integrity: sha512-UP==}\n";
    let files = BTreeMap::from([
        ("a/pnpm-lock.yaml".to_string(), lock_v6.to_string()),
        ("b/pnpm-lock.yaml".to_string(), lock_v5.to_string()),
    ]);
    let p = Pkg {
        name: "@s/p".into(),
        version: "1.0.0".into(),
    };
    let r = assert_equivalent(&files, &[dep(&p, 1, "a", Some("sha512-P=="))]);
    let keys: Vec<(&str, &str)> = r
        .edits
        .iter()
        .map(|e| (e.path.as_str(), e.key.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(
        keys,
        vec![
            (
                "a/pnpm-lock.yaml",
                "@s/p@1.0.0(react@18.2.0(scheduler@0.23.2))"
            ),
            ("a/pnpm-lock.yaml", "@s/p@1.0.0"),
            ("a/pnpm-lock.yaml", "@s/p@1.0.0(react@17.0.2)"),
            ("b/pnpm-lock.yaml", "@s/p@1.0.0_react@18.2.0"),
        ]
    );
    assert!(r.files["a/pnpm-lock.yaml"].contains("sha512-OTHER=="));
}

/// Randomized small lock sets over every flavor (including the refused
/// early shrinkwrap and CRLF), with overrides drawn so hits, duplicates,
/// residuals and misses all interleave.
#[test]
fn indexed_pnpm_rewrite_matches_oracle_on_random_lock_sets() {
    let flavors = [
        Flavor::V9,
        Flavor::V6,
        Flavor::V54,
        Flavor::V51,
        Flavor::EarlyShrinkwrap,
    ];
    // Which outcomes the sweep actually reached, so a generator change that
    // stops producing the refusal / residual / duplicate shapes fails here
    // instead of quietly testing only the plain rewrite path.
    let mut outcomes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for seed in 1..=300u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let lock_count = 1 + rng.below(3);
        let mut files = BTreeMap::new();
        let mut all: Vec<Pkg> = Vec::new();
        for l in 0..lock_count {
            let flavor = if rng.chance(8) {
                Flavor::EarlyShrinkwrap
            } else {
                flavors[rng.below(4)]
            };
            // Overlapping name pools across locks, so one dep spans locks.
            let mut pkgs = packages(4 + rng.below(12), &mut rng);
            for p in pkgs.iter_mut() {
                if rng.chance(40) {
                    p.version = "1.0.0".into();
                }
            }
            let mut extra = Vec::new();
            if rng.chance(20) {
                let p = &pkgs[rng.below(pkgs.len())];
                extra.push(match flavor {
                    Flavor::V9 => format!(
                        "  {}@{}(x@1:\n    resolution: {{integrity: sha512-BAD==}}\n",
                        p.name, p.version
                    ),
                    Flavor::V6 => format!(
                        "  /{}@{}(x@1:\n    resolution: {{integrity: sha512-BAD==}}\n",
                        p.name, p.version
                    ),
                    _ => format!(
                        "  /{}/{}_x@1)(:\n    resolution: {{integrity: sha512-BAD==}}\n",
                        p.name, p.version
                    ),
                });
            }
            if rng.chance(20) {
                let p = &pkgs[rng.below(pkgs.len())];
                extra.push(format!(
                    "  {}@{}:\n    resolution: {{integrity: sha512-X==, tarball: https://patch.socket.dev/a/{}-{}.tgz}}\n",
                    p.name, p.version, p.name, p.version
                ));
            }
            if rng.chance(10) {
                let p = &pkgs[rng.below(pkgs.len())];
                // A malformed resolution (nested value) — refused, residual.
                extra.push(format!(
                    "  /{}@{}(y@2.0.0):\n    resolution: {{integrity: {{nested: 1}}}}\n",
                    p.name, p.version
                ));
            }
            let crlf = rng.chance(15);
            let path = match l {
                0 => "pnpm-lock.yaml".to_string(),
                1 => "packages/x/pnpm-lock.yaml".to_string(),
                _ => "common/config/rush/shrinkwrap.yaml".to_string(),
            };
            files.insert(path, render_lock(flavor, &pkgs, &mut rng, &extra, crlf));
            all.extend(pkgs);
        }
        let mut overrides = Vec::new();
        for i in 0..(1 + rng.below(10)) {
            let p = if rng.chance(15) {
                Pkg {
                    name: format!("missing-{i}"),
                    version: "1.0.0".into(),
                }
            } else {
                all[rng.below(all.len())].clone()
            };
            let tag = ["a", "b"][rng.below(2)];
            let sha = if rng.chance(5) {
                None
            } else {
                Some(sri(&format!("S{}", rng.below(3))))
            };
            overrides.push(dep(&p, i, tag, sha.as_deref()));
            if rng.chance(15) {
                // Immediate duplicate of the same name@version.
                let tag = ["a", "b"][rng.below(2)];
                overrides.push(dep(&p, i + 100, tag, Some(&sri("DUP"))));
            }
        }
        let r = assert_equivalent(&files, &overrides);
        if !r.edits.is_empty() {
            outcomes.insert("edit".into());
        }
        if !r.refused_pnpm_uuids.is_empty() {
            outcomes.insert("refused".into());
        }
        outcomes.extend(r.warnings.iter().map(|w| w.code.clone()));
        if r.edits.iter().enumerate().any(|(i, e)| {
            r.edits[..i]
                .iter()
                .any(|prior| prior.path == e.path && prior.key == e.key && prior.new == e.original)
        }) {
            outcomes.insert("duplicate_sees_prior".into());
        }
    }
    // (`redirect_pnpm_entry_vendored` is not generated here; the
    // depscan-sized sweep above requires it.)
    for want in [
        "edit",
        "refused",
        "duplicate_sees_prior",
        "redirect_pnpm_entry_not_found",
        "redirect_pnpm_legacy_lockfile_unsupported",
        "redirect_pnpm_missing_sha512",
        "redirect_pnpm_unsupported_lock_key",
    ] {
        assert!(
            outcomes.contains(want),
            "sweep never reached {want}: {outcomes:?}"
        );
    }
}

// ── oracle: the pre-index implementation, verbatim ──────────────────────────

fn rewrite_pnpm_lock_oracle(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let npm: Vec<&DepOverride> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    // A pnpm lock lives at the project root or at any nested path (e.g. Rush
    // repos keep them under `common/config/rush/`); every such files-map key
    // is rewritten under the same grammar. Deterministic order: BTreeMap
    // iterates keys sorted, so goldens are stable across every lock in the set.
    let lock_keys: Vec<&String> = files
        .keys()
        .filter(|k| {
            matches!(
                k.rsplit('/').next(),
                Some("pnpm-lock.yaml" | "shrinkwrap.yaml")
            )
        })
        .collect();
    if npm.is_empty() || lock_keys.is_empty() {
        return;
    }
    let mut contents: Vec<(&String, String, bool)> = lock_keys
        .iter()
        .map(|k| (*k, files[*k].clone(), false))
        .collect();
    for dep in &npm {
        let fname = full_name(dep);
        let unsafe_locks: Vec<_> = contents
            .iter()
            .filter(|(_, content, _)| {
                pnpm::unsupported_early_shrinkwrap(content)
                    && pnpm::entries(content)
                        .iter()
                        .any(|e| pnpm::suffix(e.key, &fname, &dep.version).is_some())
            })
            .map(|(path, _, _)| path.as_str())
            .collect();
        if !unsafe_locks.is_empty() {
            result.refused_pnpm_uuids.insert(dep.patch_uuid.clone());
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_legacy_lockfile_unsupported".into(),
                detail: format!("{} uses early pnpm 1 shrinkwrapVersion 3 without a supported minor version. Those installers discard hosted tarball URLs; {fname}@{} was left unchanged in every lock. Upgrade to a tested pnpm release (1.43.1 or newer) and regenerate the lock, or use `scan --mode agent` for installed-file patching.", unsafe_locks.join(", "), dep.version),
            });
            continue;
        }
        let Some(sha512) = dep.integrity.sha512.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_pnpm_missing_sha512".into(),
                detail: format!("{fname}@{} has no sha512 integrity", dep.version),
            });
            continue;
        };
        // Every peer instance must be redirected, including nested peer
        // contexts and the block resolutions emitted by pnpm 1–5.
        let mut matched_any = false;
        // Per-lock rewrites are PLANNED first and committed only after the
        // residual gate below proves no instance of this dep escaped the
        // splice grammar in ANY lock — committing lock-by-lock as we go
        // would ship exactly the partial rewrite the gate exists to refuse.
        let mut planned: Vec<(usize, String, Vec<FileEdit>)> = Vec::new();
        let mut residuals: Vec<(&str, Vec<String>)> = Vec::new();
        for (idx, (lock_key, content, _)) in contents.iter().enumerate() {
            // (byte range to replace, replacement text) per instance, plus
            // one FileEdit per instance keyed by the canonical instance key —
            // per-instance edits keep the revert ledger lossless when several
            // instances of one dep live in the same lock.
            let mut splices: Vec<(std::ops::Range<usize>, String)> = Vec::new();
            let mut instance_edits: Vec<FileEdit> = Vec::new();
            for entry in pnpm::entries(content) {
                let Some(suffix) = pnpm::suffix(entry.key, &fname, &dep.version) else {
                    continue;
                };
                if !pnpm::supported_suffix(suffix) {
                    continue;
                }
                let Some(resolution) = pnpm::resolution(&entry) else {
                    continue;
                };
                matched_any = true;
                let original = &content[resolution.range.clone()];
                let rebuilt = resolution.rewrite(&sha512, &dep.artifact_url);
                if rebuilt == original {
                    continue;
                }
                splices.push((resolution.range, rebuilt.clone()));
                instance_edits.push(FileEdit {
                    path: (*lock_key).clone(),
                    kind: "redirect_pnpm_resolution".into(),
                    action: "rewritten".into(),
                    key: Some(format!("{fname}@{}{suffix}", dep.version)),
                    original: Some(Value::String(original.to_string())),
                    new: Some(Value::String(rebuilt)),
                });
            }
            // Splice by byte range (package blocks are disjoint and ordered) — a string replace could hit the wrong
            // instance when two entries share identical surrounding bytes.
            let candidate: Option<String> = if splices.is_empty() {
                None
            } else {
                let mut out = String::with_capacity(content.len());
                let mut cursor = 0usize;
                for (range, replacement) in splices {
                    out.push_str(&content[cursor..range.start]);
                    out.push_str(&replacement);
                    cursor = range.end;
                }
                out.push_str(&content[cursor..]);
                Some(out)
            };
            // Residual gate, run over the POST-splice text: any instance of
            // this exact name@version still resolving somewhere other than
            // the hosted artifact — in a spelling the splice grammar cannot
            // parse (e.g. an unbalanced peer suffix) — makes this a partial
            // rewrite. Shipping it would confirm and VEX-attest the dep while
            // dependents through the unmatched instance keep installing the
            // unpatched upstream tarball, so the dep is refused instead.
            let leftover = pnpm_unrewritten_instances(
                candidate.as_deref().unwrap_or(content),
                &fname,
                &dep.version,
                &dep.artifact_url,
            );
            if !leftover.is_empty() {
                residuals.push(((*lock_key).as_str(), leftover));
                continue;
            }
            if let Some(out) = candidate {
                planned.push((idx, out, instance_edits));
            }
        }
        // ANY residual anywhere refuses the dep across the WHOLE lock set —
        // nothing rewritten, nothing recorded, nothing confirmed (the same
        // fail-closed contract the pre-splice v5/v6 refusal had): a rewrite
        // committed in one lock while another still resolves the dep
        // upstream would confirm the dep set-wide.
        if !residuals.is_empty() {
            result.refused_pnpm_uuids.insert(dep.patch_uuid.clone());
            for (lock_key, keys) in &residuals {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_unsupported_lock_key".into(),
                    detail: format!(
                        "{fname}@{} still resolves through pnpm lock key(s) whose \
                         resolution the redirect grammar cannot repoint: {} in \
                         {lock_key}; the dep is left unredirected in EVERY lock \
                         (nothing rewritten, nothing confirmed) — regenerate the \
                         lock with a current pnpm (lockfileVersion 9) and re-run",
                        dep.version,
                        keys.join(", ")
                    ),
                });
            }
            continue;
        }
        for (idx, out, mut instance_edits) in planned {
            let (_, content, changed) = &mut contents[idx];
            *content = out;
            *changed = true;
            result.edits.append(&mut instance_edits);
        }
        // The entry-not-found warning fires only when the dep matched in NO
        // pnpm lock across the whole set, not once per lock. A VENDORED dep
        // is named as such: `socket-patch vendor` removes the registry
        // resolution this grammar looks for (v9 respells the packages key
        // `<name>@file:.socket/vendor/…`; v5/v6 rekey it to a bare `file:`
        // key but keep the `<name>@<version>: file:…` overrides line), so
        // the generic not-locked wording would send users on a wild-goose
        // `pnpm install` when the real path is a mode switch. Fail-closed
        // either way: nothing is rewritten for the dep.
        if !matched_any {
            let v9_vendored_key = format!("{fname}@file:");
            let override_key = format!("{fname}@{}", dep.version);
            let vendored = contents.iter().any(|(_, content, _)| {
                content.lines().any(|line| {
                    let t = line.trim_start();
                    let t = t.strip_prefix('\'').unwrap_or(t);
                    // v9 packages/snapshots key (leading `/` in v6 spelling).
                    // The vendor backend always writes the RELATIVE
                    // `file:.socket/vendor/…` spelling here, so anchoring on
                    // it keeps a user's own `file:` dep of the same name
                    // from being misreported as vendored.
                    let key = t.strip_prefix('/').unwrap_or(t);
                    if key
                        .strip_prefix(&v9_vendored_key)
                        .is_some_and(|rest| rest.starts_with(".socket/vendor/"))
                    {
                        return true;
                    }
                    // overrides / root-dep line: `<name>@<version>: file:…`
                    // (pnpm <=8 absolutizes the value, so only the
                    // `.socket/vendor/` tail is stable enough to match).
                    t.strip_prefix(&override_key)
                        .map(|rest| rest.strip_prefix('\'').unwrap_or(rest))
                        .and_then(|rest| rest.strip_prefix(':'))
                        .is_some_and(|rest| {
                            rest.contains("file:") && rest.contains(".socket/vendor/")
                        })
                })
            });
            if vendored {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_entry_vendored".into(),
                    detail: format!(
                        "{fname}@{} has no registry resolution because it is \
                         VENDORED (the lock resolves it to a \
                         file:.socket/vendor/… tarball); the hosted redirect \
                         does not apply — run `socket-patch vendor --revert` to \
                         restore the registry resolution, then re-run `scan \
                         --mode hosted`",
                        dep.version
                    ),
                });
            } else {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pnpm_entry_not_found".into(),
                    detail: format!("no resolution for {fname}@{}", dep.version),
                });
            }
        }
    }
    for (key, content, changed) in contents {
        if changed {
            result.files.insert(key.clone(), content);
        }
    }
}
