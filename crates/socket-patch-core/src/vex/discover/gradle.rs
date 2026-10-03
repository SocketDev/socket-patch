//! Gradle (hosted) — `.socket/gradle/hosted-index.tsv` and the wiring
//! around it (`patch::redirect::gradle`).
//!
//! A hosted Gradle pin lives in the owned index: one row per GA,
//! `g:a:base<TAB>suffixed<TAB>index_url<TAB>jar_sha256<TAB>pom_sha256<TAB>uuid`.
//! The row is a ref (purl `pkg:maven/<g>/<a>@<base>`, the version the pin
//! REPLACES) only while the build actually consumes it:
//!
//! - the owned script is socket-patch's (line-ending blind, #429);
//! - every build's settings (root, `buildSrc`, each literal included
//!   build) carries the live apply line with the digest of the CURRENT
//!   index — a stale digest means the configuration cache may still hold
//!   the earlier pin set;
//! - the row's url is Socket-hosted and names the row's uuid (rule 4: the
//!   uuid comes from [`DiscoverCtx::hosted_uuid`]), and the suffix grammar
//!   holds (`<base>-socket.<uuid[..8]>`, checked by the row parser);
//! - every lock entry of the GA in every build's lock files is the
//!   suffixed version or above the base (a lock still at the base fails
//!   the build), and no settings-classpath lock
//!   (`settings-gradle.lockfile`) names the GA at all: that classpath
//!   resolves before the script runs, so the pin cannot reach it;
//! - no build script sets a custom lock-file location (`lockFile`), which
//!   would hide a lock from the check above;
//! - none of the hosted planner's build- or GA-level refusals holds now
//!   (`pinned_row_refusal`: a settings-classpath declaration, a
//!   non-literal `includeBuild`, an Android / KMP plugin, a classifier
//!   request, a user `exclusiveContent` claiming the group, …): a build
//!   changed after the scan in a way the pin cannot reach stops attesting.
//!
//! Anything else is a [`DIAG_REF_INVALID`] naming the index, and no ref.
//!
//! A lock entry above the base is a newer upstream release the script lets
//! resolve, and the planner confirms that wiring: the row is still a ref
//! (rollback, remove and list must find what the scan wired), but that
//! build consumes no patch, so the ref is also [`Discovery::unattested`]
//! and `vex` omits it.
//!
//! Integrity: `locked_integrity` is `None` and `integrity_required` is
//! TRUE, so a Gradle ref never takes the not-installed lockfile basis.
//! The script lets a version ABOVE the base resolve (a newer upstream
//! fix), so the wiring alone does not prove which jar a build consumes;
//! only the installed suffixed copies are evidence (`vex_consumed`).
//!
//! Reads: the index goes through [`DiscoverCtx::read_text`] (it carries
//! the Socket identity and is swept, rule 11). The scripts, catalogs and
//! lock files the script graph reaches carry none, and are read through
//! the ctx's own view without the sweep, so a snippet pasted into a build
//! script (no index row) is never taken for hosted wiring.

use std::collections::BTreeMap;

use super::{
    maven_purl, DiscoverCtx, Discovery, PatchedRef, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID,
};
use crate::gradle::eol::eol_eq;
use crate::gradle::locks;
use crate::patch::redirect::gradle::{
    apply_line_digest, graph_of, index_digest, is_settings_lock, lockfile_paths, parse_index,
    pinned_row_refusal, settings_targets, GradleFiles, HOSTED_INDEX_REL, HOSTED_SCRIPT,
    HOSTED_SCRIPT_REL, MAX_ROUNDS,
};

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(index) = ctx.read_text(HOSTED_INDEX_REL, out).await else {
        return;
    };
    let rows = match parse_index(&index) {
        Ok(rows) => rows,
        Err(why) => {
            out.diag(DIAG_LOCKFILE_UNPARSEABLE, HOSTED_INDEX_REL, why);
            return;
        }
    };
    if rows.is_empty() {
        return;
    }
    let files = read_build(ctx).await;
    let graph = graph_of(&files);
    let digest = index_digest(&index);
    let wiring = if !files
        .get(HOSTED_SCRIPT_REL)
        .is_some_and(|t| eol_eq(t.as_bytes(), HOSTED_SCRIPT.as_bytes()))
    {
        Some(format!(
            "{HOSTED_SCRIPT_REL} is missing or not socket-patch's"
        ))
    } else {
        settings_targets(&graph).into_iter().find_map(|t| {
            let live = files
                .get(&t.rel)
                .and_then(|text| apply_line_digest(text, t.dsl, &t.prefix()));
            match live {
                Some(d) if d == digest => None,
                Some(d) => Some(format!(
                    "{} applies the hosted script for index digest {d}, not the current {digest}",
                    t.rel
                )),
                None => Some(format!("{} does not apply {HOSTED_SCRIPT_REL}", t.rel)),
            }
        })
    }
    .or_else(|| {
        graph
            .custom_lock_file()
            .map(|rel| format!("{rel} sets a custom dependency-lock file (`lockFile`)"))
    });
    let locks: Vec<(String, locks::LockState)> = lockfile_paths(&graph, &files)
        .into_iter()
        .filter_map(|rel| {
            let state = locks::parse(files.get(&rel)?);
            Some((rel, state))
        })
        .collect();
    for row in rows {
        let ga = row.ga();
        let problem = wiring.clone().or_else(|| match ctx.hosted_uuid(&row.url) {
            Some(uuid) if uuid == row.uuid => None,
            _ => Some(format!(
                "{} is not the Socket-hosted repository of patch {}",
                row.url, row.uuid
            )),
        });
        // A lock above the base is a newer upstream release the script
        // lets resolve (the planner confirms such a pin): the wiring stands
        // — rollback, remove and list must find it — but that build
        // consumes no patch, so the ref is not attested.
        let above_base =
            |v: &str| crate::gradle::selector::gradle_version_cmp(v, &row.base).is_gt();
        let problem = problem.or_else(|| {
            locks.iter().find_map(|(rel, state)| {
                let settings = is_settings_lock(rel);
                state
                    .entries_of(&row.group, &row.artifact)
                    .find(|e| settings || (e.version != row.suffixed && !above_base(&e.version)))
                    .map(|e| {
                        if settings {
                            format!(
                                "{rel}:{} locks {ga} on the settings classpath, which resolves \
                                 before the hosted script runs",
                                e.line
                            )
                        } else {
                            format!(
                                "{rel}:{} locks {ga} at {}, not the pinned {}",
                                e.line, e.version, row.suffixed
                            )
                        }
                    })
            })
        });
        let bypass = locks.iter().find_map(|(rel, state)| {
            state
                .entries_of(&row.group, &row.artifact)
                .find(|e| above_base(&e.version))
                .map(|e| {
                    (
                        rel.clone(),
                        format!(
                            "{rel}:{} locks {ga} at {}, above the patched {}: that build \
                             resolves an upstream release, not the pinned {}",
                            e.line, e.version, row.base, row.suffixed
                        ),
                    )
                })
        });
        // The planner's own build- and GA-level refusals, re-run over the
        // build as it is now: a settings classpath or a non-literal
        // `includeBuild` added after the scan resolves the upstream jar
        // where the pin never reaches.
        let problem = problem.or_else(|| {
            pinned_row_refusal(&files, &graph, &row).map(|(code, detail)| {
                format!("the hosted planner would refuse it now ({code}): {detail}")
            })
        });
        if let Some(problem) = problem {
            out.diag(
                DIAG_REF_INVALID,
                HOSTED_INDEX_REL,
                format!("{HOSTED_INDEX_REL}: {ga} ({}): {problem}", row.uuid),
            );
            continue;
        }
        let Some(purl) = maven_purl(&row.group, &row.artifact, &row.base) else {
            out.diag(
                DIAG_REF_INVALID,
                HOSTED_INDEX_REL,
                format!(
                    "{HOSTED_INDEX_REL}: {ga}:{} is not a usable Maven coordinate",
                    row.base
                ),
            );
            continue;
        };
        if let Some((rel, detail)) = bypass {
            out.unattested(&purl, &row.uuid, &rel, detail);
        }
        out.push(PatchedRef::hosted(
            purl,
            row.uuid.clone(),
            HOSTED_INDEX_REL,
            Some(&row.url),
            None,
            true,
        ));
    }
}

/// The build's scripts, catalogs and lock files (see the module docs).
async fn read_build(ctx: &DiscoverCtx<'_>) -> BTreeMap<String, String> {
    let mut gradle = GradleFiles::default();
    for _ in 0..MAX_ROUNDS {
        let (reads, lists) = gradle.misses();
        if reads.is_empty() && lists.is_empty() {
            break;
        }
        for rel in reads {
            match ctx.view.read_text(&rel).await {
                Ok(text) => gradle.found(&rel, text),
                Err(_) => gradle.absent(&rel),
            }
        }
        for dir in lists {
            let children = ctx
                .view
                .list_dir(&dir)
                .await
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| {
                            if e.is_dir {
                                format!("{}/", e.name)
                            } else {
                                e.name
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            gradle.listed(&dir, children);
        }
    }
    gradle.files
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::testing::{assert_refs, Project};
    use super::super::{Discovery, WiringMode, DIAG_REF_INVALID};
    use super::*;
    use crate::patch::redirect::{
        rewrite_registry_redirect, DepOverride, Integrity, RegistryOverride,
        RegistryOverrideIdentifiers,
    };

    const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";
    const TOKEN: &str = "22222222-3333-4444-8555-666666666666";
    const PURL: &str = "pkg:maven/com.socketfixture/victim@1.10.0";
    const SFX: &str = "1.10.0-socket.4d5e6f70";

    fn dep() -> DepOverride {
        DepOverride {
            ecosystem: "maven".into(),
            name: "victim".into(),
            namespace: Some("com.socketfixture".into()),
            version: "1.10.0".into(),
            token: TOKEN.into(),
            patch_uuid: UUID.into(),
            artifact_url: "https://patch.socket.dev/patch/maven/x.jar".into(),
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: format!(
                    "https://patch.socket.dev/patch-registry/maven/{TOKEN}/{UUID}/maven2"
                ),
                identifiers: RegistryOverrideIdentifiers {
                    name: "com.socketfixture/victim".into(),
                    version: "1.10.0".into(),
                    maven_group_id: Some("com.socketfixture".into()),
                    maven_artifact_id: Some("victim".into()),
                    maven_suffixed_version: Some(SFX.into()),
                    maven_pom_sha256: Some("b".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha256: Some("a".repeat(64)),
                ..Default::default()
            },
        }
    }

    /// A project the hosted planner wired from `input`.
    fn wired(input: &[(&str, &str)]) -> (Project, BTreeMap<String, String>) {
        let mut files: BTreeMap<String, String> = input
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let r = rewrite_registry_redirect(&files, &[dep()]);
        assert!(r.confirmed_gradle_uuids.contains(UUID), "{:?}", r.warnings);
        files.extend(r.files);
        let p = Project::new();
        for (rel, text) in &files {
            p.write(rel, text);
        }
        (p, files)
    }

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(extract(c, o))).await
    }

    fn diag_details(out: &Discovery) -> Vec<String> {
        out.diagnostics
            .iter()
            .map(|d| format!("{}: {}", d.code, d.detail))
            .collect()
    }

    const BUILD: &[(&str, &str)] = &[
        ("settings.gradle", "include 'app'\n"),
        ("build.gradle", ""),
        (
            "app/build.gradle",
            "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
        ),
        (
            "app/gradle.lockfile",
            "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
        ),
    ];

    #[tokio::test]
    async fn planner_output_is_a_hosted_ref_never_lockfile_basis() {
        let (p, _) = wired(BUILD);
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID, WiringMode::Hosted)]);
        assert!(out.diagnostics.is_empty(), "{:?}", diag_details(&out));
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from(HOSTED_INDEX_REL));
        assert!(r.locked_integrity.is_none() && r.integrity_required);
        assert!(
            !r.lockfile_basis_ok(),
            "a Gradle pin needs installed evidence"
        );
        // The grant token in the url is not a second patch.
        assert_eq!(out.hosted_claim(PURL, UUID), Some(true));
    }

    #[tokio::test]
    async fn a_crlf_checkout_still_wires() {
        let (p, files) = wired(BUILD);
        for rel in ["settings.gradle", "app/gradle.lockfile", HOSTED_SCRIPT_REL] {
            p.write(rel, files[rel].replace('\n', "\r\n"));
        }
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID, WiringMode::Hosted)]);
    }

    #[tokio::test]
    async fn broken_wiring_is_an_invalid_ref() {
        type BreakIt = Box<dyn Fn(&Project, &BTreeMap<String, String>)>;
        let cases: Vec<(&str, BreakIt)> = vec![
            (
                "a lock at the base",
                Box::new(|p, _| {
                    p.write(
                        "app/gradle.lockfile",
                        "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
                    );
                }),
            ),
            (
                "a settings-classpath lock, even at the suffix",
                Box::new(|p, _| {
                    p.write(
                        "settings-gradle.lockfile",
                        format!("com.socketfixture:victim:{SFX}=classpath\nempty=\n"),
                    );
                }),
            ),
            (
                "a settings-classpath declaration added after the scan",
                Box::new(|p, f| {
                    p.write(
                        "settings.gradle",
                        format!(
                            "buildscript {{ dependencies {{ classpath 'com.socketfixture:victim:1.10.0' }} }}\n{}",
                            f["settings.gradle"]
                        ),
                    );
                }),
            ),
            (
                "a non-literal includeBuild added after the scan",
                Box::new(|p, f| {
                    p.write(
                        "settings.gradle",
                        format!(
                            "{}includeBuild(\"$rootDir/../logic\")\n",
                            f["settings.gradle"]
                        ),
                    );
                }),
            ),
            (
                "a custom lock location",
                Box::new(|p, _| {
                    p.write(
                        "app/build.gradle",
                        "dependencyLocking { lockFile = file('locks/x.lockfile') }\n",
                    );
                }),
            ),
            (
                "a stale digest",
                Box::new(|p, f| {
                    let text = f["settings.gradle"].clone();
                    let (head, _) = text.rsplit_once("socket-patch-hosted ").unwrap();
                    p.write(
                        "settings.gradle",
                        format!("{head}socket-patch-hosted 0000000000000000\n"),
                    );
                }),
            ),
            (
                "no apply line",
                Box::new(|p, _| {
                    p.write("settings.gradle", "include 'app'\n");
                }),
            ),
            (
                "an edited script",
                Box::new(|p, f| {
                    p.write(
                        HOSTED_SCRIPT_REL,
                        format!("{}// edited\n", f[HOSTED_SCRIPT_REL]),
                    );
                }),
            ),
            (
                "a url off the Socket host",
                Box::new(|p, f| {
                    let index = f[HOSTED_INDEX_REL].replace("patch.socket.dev", "evil.example");
                    p.write(HOSTED_INDEX_REL, &index);
                    // Keep the digest current so only the url is wrong.
                    let digest = index_digest(&index);
                    let text = f["settings.gradle"].clone();
                    let (head, _) = text.rsplit_once("socket-patch-hosted ").unwrap();
                    p.write(
                        "settings.gradle",
                        format!("{head}socket-patch-hosted {digest}\n"),
                    );
                }),
            ),
        ];
        for (what, break_it) in cases {
            let (p, files) = wired(BUILD);
            break_it(&p, &files);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                out.diagnostics.iter().map(|d| d.code).collect::<Vec<_>>(),
                vec![DIAG_REF_INVALID],
                "{what}: {:?}",
                diag_details(&out)
            );
        }
    }

    /// #646 review: a lock above the base is a newer upstream release the
    /// planner confirms the pin over. The row stays a ref (rollback, remove
    /// and list find the wiring), and is unattested: that build consumes
    /// no patch.
    #[tokio::test]
    async fn a_lock_above_the_base_is_a_ref_but_unattested() {
        let (p, _) = wired(&[
            ("settings.gradle", "include 'a', 'b'\n"),
            ("build.gradle", ""),
            (
                "a/build.gradle",
                "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
            ),
            (
                "a/gradle.lockfile",
                "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
            ),
            (
                "b/gradle.lockfile",
                "com.socketfixture:victim:1.11.0=runtimeClasspath\nempty=\n",
            ),
        ]);
        let out = run(&p).await;
        assert_refs(&out, &[(PURL, UUID, WiringMode::Hosted)]);
        assert!(out.diagnostics.is_empty(), "{:?}", diag_details(&out));
        assert_eq!(out.hosted_claim(PURL, UUID), Some(true));
        assert_eq!(out.unattested.len(), 1, "{:?}", out.unattested);
        let u = &out.unattested[0];
        assert_eq!((u.purl.as_str(), u.uuid.as_str()), (PURL, UUID));
        assert_eq!(u.file, std::path::PathBuf::from("b/gradle.lockfile"));
        assert!(
            u.detail.contains("above the patched 1.10.0"),
            "{}",
            u.detail
        );
        // Pinned locks everywhere: attested as usual.
        let (p, _) = wired(BUILD);
        assert!(run(&p).await.unattested.is_empty());
    }

    #[tokio::test]
    async fn no_index_no_refs_and_a_pasted_snippet_is_not_wiring() {
        let p = Project::new();
        p.write("settings.gradle", "");
        p.write(
            "build.gradle",
            format!(
                "repositories {{ exclusiveContent {{ forRepository {{ maven {{ url 'https://patch.socket.dev/patch-registry/maven/{TOKEN}/{UUID}/maven2' }} }}\n filter {{ includeVersion('com.socketfixture', 'victim', '{SFX}') }} }} }}\n"
            ),
        );
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty());
        assert!(out.recognized.is_empty(), "build scripts are not swept");
    }
}
