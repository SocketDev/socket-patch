//! Equivalence oracle for the hosted golang rewriter, which now reads go.mod
//! once per dep (one walk for the prior directive, the required version and
//! the upsert scan), appends its directives in place, and edits go.sum as
//! lines, joining it once at the end. The previous implementation is kept
//! here verbatim over the text transforms, and the production rewriter must
//! produce the identical output bytes, FileEdit list and warnings on
//! randomized go.mod / go.sum pairs — CRLF and mixed endings, unclosed
//! blocks, socket-owned and user-authored replaces, stale pins, malformed
//! integrity and duplicate deps.

use super::*;

fn rewrite_golang_oracle(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    use crate::vendor::go_mod_edit::{self, HOSTED_GO_MODULE_PREFIX};
    use crate::vendor::go_sum_edit;

    let golang: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "golang")
        .collect();
    if golang.is_empty() {
        return;
    }
    // The replace directive can only live in the MAIN module's go.mod.
    let Some(orig_go_mod) = files.get("go.mod") else {
        result.warnings.push(RewriteWarning {
            code: "redirect_golang_no_go_mod".into(),
            detail: "no go.mod present; golang redirect skipped".into(),
        });
        return;
    };
    let mut go_mod = orig_go_mod.clone();
    // An absent go.sum starts empty: the fully-replaced original needs no
    // lines of its own, so the two socket lines alone are a complete pin.
    let mut go_sum = files.get("go.sum").cloned().unwrap_or_default();
    let (mut mod_changed, mut sum_changed) = (false, false);

    for dep in &golang {
        let fname = full_name(dep);
        let Some(ov) = registry_override_of_kind(dep, "goproxy") else {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_unsupported".into(),
                detail: format!(
                    "{fname}@{}: no hosted Go module is published for this patch; run \
                     `socket-patch vendor` (committable, offline-verified) instead",
                    dep.version
                ),
            });
            continue;
        };
        let (Some(rhs_module), Some(rhs_version)) = (
            &ov.identifiers.go_module_path,
            &ov.identifiers.go_module_version,
        ) else {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_missing_module".into(),
                detail: format!(
                    "{fname}@{} goproxy override lacks goModulePath/goModuleVersion",
                    dep.version
                ),
            });
            continue;
        };
        // Fail closed on a module path outside the socket namespace: the
        // prefix is the ONLY ownership signal — a directive we couldn't
        // recognize later would be unremovable, and go.sum removal keys on it.
        if !go_mod_edit::is_hosted_module_path(rhs_module) {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_untrusted_module_path".into(),
                detail: format!(
                    "{fname}@{}: refusing hosted module path `{rhs_module}`: not \
                     `{HOSTED_GO_MODULE_PREFIX}<patch uuid>`",
                    dep.version
                ),
            });
            continue;
        }
        // Every string interpolated into go.mod/go.sum must be a single clean
        // token — whitespace or control characters would inject directives.
        if [fname.as_str(), &dep.version, rhs_module, rhs_version]
            .iter()
            .any(|s| !go_token_safe(s))
        {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_unsafe_coords".into(),
                detail: format!(
                    "{fname}@{}: module/version tokens contain whitespace or control \
                     characters; refusing to write them into go.mod/go.sum",
                    dep.version
                ),
            });
            continue;
        }
        // BOTH go.sum hashes must be pinnable up front — a replace without
        // them (or with a malformed hash) bricks every `-mod=readonly` build.
        let (Some(zip_h1), Some(gomod_h1)) = (&dep.integrity.dirhash_h1, &dep.integrity.go_mod_h1)
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_missing_integrity".into(),
                detail: format!(
                    "{fname}@{} has no dirhashH1/goModH1 integrity pair",
                    dep.version
                ),
            });
            continue;
        };
        if !go_sum_edit::is_h1_dirhash(zip_h1) || !go_sum_edit::is_h1_dirhash(gomod_h1) {
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_missing_integrity".into(),
                detail: format!(
                    "{fname}@{}: integrity hashes must be `h1:` + 44-char base64 dirhashes",
                    dep.version
                ),
            });
            continue;
        }
        // Any pre-existing socket-owned directive for the module (this run is
        // a refresh, or a takeover of a local/vendored redirect): capture its
        // text — the ledger's `original` is the only pre-redirect record.
        let prior = go_mod_edit::parse_replace_entries(&go_mod)
            .into_iter()
            .find(|e| e.module == fname && e.socket_owned());
        let prior_text = prior.as_ref().map(|e| {
            let target = e.path.clone().unwrap_or_else(|| match &e.rhs_version {
                Some(v) => format!("{} {v}", e.rhs_module.as_deref().unwrap_or_default()),
                None => e.rhs_module.clone().unwrap_or_default(),
            });
            let ver = e
                .version
                .as_deref()
                .map(|v| format!(" {v}"))
                .unwrap_or_default();
            format!("replace {}{ver} => {target}", e.module)
        });

        // Stale-pin cross-check: `replace` is keyed on module+version, and a
        // pin the graph no longer selects is SILENTLY inert (the build links
        // the unpatched module with zero warning) — refuse to write one, and
        // reconcile away OUR OWN inert directive if one is already committed:
        // left in place, its module path keeps confirming the dep as
        // redirected (ledger + VEX attestation) while go links the unpatched
        // version.
        let required = go_mod_edit::parse_required_versions(&go_mod);
        if let Some(required) = required.get(&fname) {
            if required != &dep.version {
                result.warnings.push(RewriteWarning {
                    code: "redirect_golang_version_mismatch".into(),
                    detail: format!(
                        "{fname}: go.mod requires {required} but the patch targets {} — \
                         a version-pinned replace would be silently ignored",
                        dep.version
                    ),
                });
                let stale_hosted = prior
                    .as_ref()
                    .filter(|e| e.owner == Some(go_mod_edit::ReplaceOwner::Hosted));
                if let Some(stale) = stale_hosted {
                    if let Ok(Some(new)) = go_mod_edit::remove_replace_entry(
                        &go_mod,
                        &fname,
                        go_mod_edit::ReplaceOwner::Hosted,
                    ) {
                        go_mod = new;
                        mod_changed = true;
                        result.edits.push(FileEdit {
                            path: "go.mod".into(),
                            kind: "redirect_golang_stale_replace_removed".into(),
                            action: "removed".into(),
                            key: Some(fname.clone()),
                            original: prior_text.clone().map(Value::String),
                            new: None,
                        });
                    }
                    if let Some(stale_rhs) = stale.rhs_module.as_deref() {
                        if let Some(new) =
                            go_sum_edit::remove_module_prefix_lines(&go_sum, stale_rhs)
                        {
                            go_sum = new;
                            sum_changed = true;
                            result.edits.push(FileEdit {
                                path: "go.sum".into(),
                                kind: "redirect_golang_stale_gosum_removed".into(),
                                action: "removed".into(),
                                key: Some(stale_rhs.to_string()),
                                original: None,
                                new: None,
                            });
                        }
                    }
                }
                continue;
            }
        } else if !go_sum_edit::has_module_version(&go_sum, &fname, &dep.version)
            && prior
                .as_ref()
                .is_none_or(|e| e.version.as_deref() != Some(dep.version.as_str()))
        {
            // Not required, not in go.sum at this version, and not already
            // redirected by us: the module is outside this project's graph
            // (local discovery crawls the whole module cache). Its replace
            // would be inert, and confirming it would attest a patch no
            // build links.
            result.warnings.push(RewriteWarning {
                code: "redirect_golang_not_in_module_graph".into(),
                detail: format!(
                    "{fname}@{}: not required by go.mod and absent from go.sum — the \
                     module is not in this project's build graph; nothing redirected",
                    dep.version
                ),
            });
            continue;
        }

        match go_mod_edit::upsert_hosted_replace_entry(
            &go_mod,
            &fname,
            &dep.version,
            rhs_module,
            rhs_version,
        ) {
            Err(e) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_golang_replace_conflict".into(),
                    detail: format!("{fname}@{}: {e}", dep.version),
                });
                continue;
            }
            // Re-run over an already-redirected go.mod: nothing to record.
            Ok(None) => {}
            Ok(Some(new)) => {
                go_mod = new;
                mod_changed = true;
                result.edits.push(FileEdit {
                    path: "go.mod".into(),
                    kind: "redirect_golang_replace".into(),
                    // A takeover/refresh of an existing socket directive must
                    // keep its text in `original` — the ledger is the only
                    // pre-redirect record a future revert can restore from.
                    action: if prior_text.is_some() {
                        "updated".into()
                    } else {
                        "added".into()
                    },
                    key: Some(fname.clone()),
                    original: prior_text.map(Value::String),
                    new: Some(Value::String(format!(
                        "replace {fname} {} => {rhs_module} {rhs_version}",
                        dep.version
                    ))),
                });
            }
        }
        if let Some(new) =
            go_sum_edit::upsert_module_lines(&go_sum, rhs_module, rhs_version, zip_h1, gomod_h1)
        {
            go_sum = new;
            sum_changed = true;
            result.edits.push(FileEdit {
                path: "go.sum".into(),
                kind: "redirect_golang_gosum".into(),
                action: "added".into(),
                key: Some(format!("{rhs_module}@{rhs_version}")),
                original: None,
                new: Some(Value::String(format!(
                    "{rhs_module} {rhs_version} {zip_h1}\n{rhs_module} {rhs_version}/go.mod {gomod_h1}"
                ))),
            });
        }
        // Prune the replaced original's lines: with the pinned replace in
        // force go never fetches or verifies the original, and `go mod tidy`
        // prunes exactly these — writing the tidy-stable state up front keeps
        // the first day-2 tidy a byte-level no-op. The removed lines ride in
        // `original` so the ledger can restore them on revert.
        if let Some((new, removed)) =
            go_sum_edit::remove_exact_module_version_lines(&go_sum, &fname, &dep.version)
        {
            go_sum = new;
            sum_changed = true;
            result.edits.push(FileEdit {
                path: "go.sum".into(),
                kind: "redirect_golang_gosum_prune".into(),
                action: "removed".into(),
                key: Some(format!("{fname}@{}", dep.version)),
                original: Some(Value::String(removed.join("\n"))),
                new: None,
            });
        }
        result.confirmed_golang_uuids.insert(dep.patch_uuid.clone());
    }

    if mod_changed {
        result.files.insert("go.mod".into(), go_mod);
    }
    if sum_changed {
        result.files.insert("go.sum".into(), go_sum);
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
    rewrite_golang_oracle(files, overrides, &mut want);
    let mut got = RewriteResult::default();
    rewrite_golang(files, overrides, &mut got);
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
        berry_zip_url: None,
        registry_override,
        integrity: Integrity {
            dirhash_h1: h1(rng),
            go_mod_h1: h1(rng),
            ..Default::default()
        },
    }
}

#[test]
fn single_walk_golang_rewrite_matches_oracle() {
    let mut rewritten = 0;
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    let mut kinds = std::collections::BTreeSet::new();
    for seed in 1..=3000u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
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
        let got = run_both(&files, &overrides, &format!("seed {seed}"));
        // A second pass over the output (the idempotent re-run) must agree too.
        let mut rerun = files.clone();
        rerun.extend(got.files.clone());
        run_both(&rerun, &overrides, &format!("seed {seed} re-run"));
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
}

/// Runs the oracle over the Phase 3 benchmark go.mod / go.sum pairs (too
/// large to commit) when `SOCKET_PATCH_GO_FIXTURES` names their directory,
/// redirecting every required module; a no-op otherwise.
#[test]
fn single_walk_golang_rewrite_matches_oracle_on_fixtures() {
    let Some(root) = std::env::var_os("SOCKET_PATCH_GO_FIXTURES") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    for dir in ["go-grafana", "go-cache", "go-k8s"] {
        let read = |name: &str| std::fs::read_to_string(root.join(dir).join(name)).unwrap();
        let go_mod = read("go.mod");
        let mut required: Vec<(String, String)> =
            crate::vendor::go_mod_edit::parse_required_versions(&go_mod)
                .into_iter()
                .collect();
        required.sort();
        let overrides: Vec<DepOverride> = required
            .iter()
            .enumerate()
            .map(|(n, (m, v))| DepOverride {
                ecosystem: "golang".into(),
                name: m.clone(),
                namespace: None,
                version: v.clone(),
                token: String::new(),
                patch_uuid: uuid(n),
                artifact_url: String::new(),
                berry_zip_url: None,
                registry_override: Some(RegistryOverride {
                    kind: "goproxy".into(),
                    index_url: "https://patch.socket.dev/patch-registry/golang".into(),
                    identifiers: RegistryOverrideIdentifiers {
                        name: m.clone(),
                        version: v.clone(),
                        go_module_path: Some(hosted(n)),
                        go_module_version: Some("v1.0.0-socketpatch.1".into()),
                        ..Default::default()
                    },
                }),
                integrity: Integrity {
                    dirhash_h1: Some(H1_A.into()),
                    go_mod_h1: Some(H1_B.into()),
                    ..Default::default()
                },
            })
            .collect();
        for crlf in [false, true] {
            let conv = |s: String| if crlf { s.replace('\n', "\r\n") } else { s };
            let mut files = BTreeMap::new();
            files.insert("go.mod".to_string(), conv(go_mod.clone()));
            files.insert("go.sum".to_string(), conv(read("go.sum")));
            let got = run_both(&files, &overrides, &format!("{dir} crlf={crlf}"));
            // k8s pins every staging module with a user-authored replace, so
            // there every dep is a refused conflict.
            assert!(
                !got.edits.is_empty() || !got.warnings.is_empty(),
                "{dir}: nothing happened"
            );
            let mut rerun = files.clone();
            rerun.extend(got.files.clone());
            run_both(&rerun, &overrides, &format!("{dir} crlf={crlf} re-run"));
        }
    }
}
