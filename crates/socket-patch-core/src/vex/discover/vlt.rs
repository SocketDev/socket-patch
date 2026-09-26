//! vlt: the root `vlt-lock.json` (lockfileVersion absent, `0` or `1`; legacy
//! `·` and tilde `~` DepIDs alike), read through the lock inventory's entry
//! model ([`vlt_lock_model`]).
//!
//! ## Shapes recognized
//!
//! | shape | written by | recognized node | ref |
//! |---|---|---|---|
//! | hosted | `patch::redirect::vlt` (`scan --mode hosted`, the depscan twin) | a registry node (any segment) whose slot [3] is a Socket-hosted URL whose leaf is `<bare>-<version>.tgz` of the DepID's `name@version`, slot [1] == name, slot [2] a `sha512-` SRI | `Hosted { purl, uuid, integrity: slot [2] }` |
//! | vendored | `vendor::vlt_lock` (`vendor`, `scan --mode vendored`) | a `file` node whose decoded path is `.socket/vendor/npm/<uuid>/[@s/]<bare>-<version>/node_modules/[@s/]<bare>`, slot [1] == name, slot [3] (when a string) == the path | `Vendored { purl, uuid, path }` |
//! | vendored (read-only) | a user's `vlt install` of an npm-flavor artifact | a `file` node whose decoded path is `.socket/vendor/npm/<uuid>/[@s/]<bare>-<version>.tgz`, same slot rules | `Vendored { purl, uuid, path }` |
//!
//! Anything else is not a ref: git, remote and workspace nodes, a registry
//! node on any other host (a look-alike host or an uppercase uuid
//! included), and a Socket-shaped node whose name, version, path or
//! integrity disagree, which is diagnosed ([`DIAG_REF_INVALID`]).
//!
//! The version comes from the DepID for a hosted node and from the path's
//! `<bare>-<version>` leaf for a vendored one (a committed `file` node
//! carries no version). A vendored ref carries no lock integrity (slot [2]
//! is `null`): the committed directory is hashed, with the vlt manifest
//! exemption for its `package.json`.
//!
//! ## Integrity (`integrity_required`)
//!
//! The hosted rewriter refuses a dependency without a sha512
//! (`redirect_vlt_missing_sha512`) and always writes the patched artifact's
//! sha512 into slot [2], so a hosted node with a missing or non-sha512
//! slot [2] is not Socket-written and is no ref at all.
//!
//! ## One lock, several instances
//!
//! vlt keeps one node per instance: peer and modifier variants of one
//! `name@version` share the purl, and the hosted rewriter rewrites every
//! default-registry instance. An instance of the same `name@version` that
//! still resolves from a registry (a named alias or scoped registry the
//! rewriter skips with `redirect_vlt_custom_registry_skipped`) installs the
//! unpatched package for its dependents:
//!
//! * a hosted ref beside it keeps no lock pin, so the not-installed
//!   lockfile basis never attests it (every installed copy must verify
//!   instead);
//! * a vendored ref beside it is diagnosed ([`DIAG_REF_UNATTRIBUTABLE`])
//!   and not emitted, since only the committed directory would be hashed.
//!
//! Every other registry instance is evidence against another lock's wiring
//! of the same package ([`Discovery::resolved_elsewhere`]).
//!
//! ## Parsing
//!
//! A BOM-prefixed (never stripped), non-object or unknown-`lockfileVersion`
//! lock is one vlt cannot read: [`DIAG_LOCKFILE_UNPARSEABLE`], no refs, and
//! whatever it mentions is recognized as unwired (rule 11). The canonical
//! one-entry-per-line layout is not required here (the writers check it).
//!
//! Non-goals: nested `*/vlt-lock.json` (a separate project, DESIGN D3), the
//! hidden `node_modules/.vlt-lock.json` (install state, not wiring) and
//! `vlt.json` (registry definitions only).

use std::collections::BTreeSet;

use super::{
    npm_purl, vendor_ref, DiscoverCtx, Discovery, PatchedRef, DIAG_LOCKFILE_UNPARSEABLE,
    DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::constants::npm_family::VLT_LOCK;
use crate::patch::redirect::hosted_url_names;
use crate::utils::digest::is_sri_pin;
use crate::vendor::lock_inventory::vlt::{vlt_lock_model, VltLockNode};
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::vlt_lock_text::{parse_vendored_path, DepIdKind};

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(text) = ctx.read_text(VLT_LOCK, out).await else {
        return;
    };
    let lock = match vlt_lock_model(&text) {
        Ok(lock) => lock,
        Err(why) => {
            out.diag(
                DIAG_LOCKFILE_UNPARSEABLE,
                VLT_LOCK,
                format!("{VLT_LOCK} {why}; vlt cannot read it, so nothing in it is wired"),
            );
            return;
        }
    };
    let classified: Vec<Classified> = lock.nodes.iter().map(|n| classify(ctx, n)).collect();
    let registry: BTreeSet<&str> = classified
        .iter()
        .filter_map(|c| match c {
            Classified::Registry(purl) => Some(purl.as_str()),
            _ => None,
        })
        .collect();
    for (node, found) in lock.nodes.iter().zip(&classified) {
        match found {
            Classified::Registry(purl) => out.resolved_elsewhere(VLT_LOCK, Some(purl.clone())),
            Classified::Hosted {
                purl,
                uuid,
                url,
                integrity,
            } => {
                let pin = (!registry.contains(purl.as_str()))
                    .then(|| LockIntegrity::Sri(integrity.clone()));
                out.push(PatchedRef::hosted(
                    purl.clone(),
                    uuid.clone(),
                    VLT_LOCK,
                    Some(url),
                    pin,
                    true,
                ));
            }
            Classified::Vendored { purl, path } if registry.contains(purl.as_str()) => {
                out.diag(
                    DIAG_REF_UNATTRIBUTABLE,
                    VLT_LOCK,
                    format!(
                        "{VLT_LOCK}: {}: {purl} is wired to {path}, but the lock also resolves \
                         the same version from a registry for other dependents, so the \
                         vendored patch is not attested; re-run `socket-patch vendor` or \
                         `vlt install`",
                        node.key
                    ),
                );
            }
            Classified::Vendored { purl, path } => {
                if let Some(vref) = vendor_ref(path) {
                    out.push(PatchedRef::vendored(purl.clone(), &vref, VLT_LOCK, None));
                }
            }
            Classified::Invalid(why) => {
                out.diag(DIAG_REF_INVALID, VLT_LOCK, format!("{VLT_LOCK}: {why}"));
            }
            Classified::Other => {}
        }
    }
}

/// What one node is, before the lock-wide instance rule applies.
enum Classified {
    /// A registry instance not wired to a Socket patch.
    Registry(String),
    Hosted {
        purl: String,
        uuid: String,
        url: String,
        integrity: String,
    },
    Vendored {
        purl: String,
        path: String,
    },
    /// Socket-shaped, but not what a Socket writer produces.
    Invalid(String),
    /// Git, remote, workspace and non-Socket file nodes.
    Other,
}

fn classify(ctx: &DiscoverCtx<'_>, node: &VltLockNode) -> Classified {
    match node.dep_id.kind {
        DepIdKind::Registry => classify_registry(ctx, node),
        DepIdKind::File => classify_file(node),
        DepIdKind::Git | DepIdKind::Remote | DepIdKind::Workspace => Classified::Other,
    }
}

fn classify_registry(ctx: &DiscoverCtx<'_>, node: &VltLockNode) -> Classified {
    let key = &node.key;
    let Some((name, version)) = node.dep_id.registry_identity() else {
        return Classified::Other;
    };
    let hosted = node.location.as_deref().and_then(|url| {
        let uuid = ctx.hosted_uuid(url)?;
        Some((url, uuid))
    });
    let Some((url, uuid)) = hosted else {
        return match npm_purl(name, version) {
            Some(purl) if node.name == name => Classified::Registry(purl),
            _ => Classified::Other,
        };
    };
    if node.name != name {
        return Classified::Invalid(format!(
            "{key}: names {:?} in slot [1] but its DepID is {name}@{version}; it is ignored",
            node.name
        ));
    }
    if !hosted_url_names(url, name, version) {
        return Classified::Invalid(format!(
            "{key}: {url:?} is not an artifact of {name}@{version} (its leaf must be the \
             package's own <name>-<version>.tgz); it is ignored"
        ));
    }
    let Some(integrity) = node
        .integrity
        .as_deref()
        .filter(|sri| sri.starts_with("sha512-") && is_sri_pin(sri))
    else {
        return Classified::Invalid(format!(
            "{key}: is wired to {url:?} without the sha512 the hosted rewriter always writes; \
             it is ignored"
        ));
    };
    let Some(purl) = npm_purl(name, version) else {
        return Classified::Invalid(format!(
            "{key}: Socket-wired node {name:?}@{version:?} has unsafe coordinates"
        ));
    };
    Classified::Hosted {
        purl,
        uuid,
        url: url.to_string(),
        integrity: integrity.to_string(),
    }
}

fn classify_file(node: &VltLockNode) -> Classified {
    let key = &node.key;
    let path = node.dep_id.first.as_str();
    if !path.starts_with(".socket/vendor/") {
        return Classified::Other;
    }
    let Some(vendored) = parse_vendored_path(path, &node.name) else {
        return Classified::Invalid(format!(
            "{key}: {path:?} is not a vendored vlt artifact of {:?} (.socket/vendor/npm/<uuid>/\
             <name>-<version>/node_modules/<name>); it is ignored",
            node.name
        ));
    };
    if node.location.as_deref().is_some_and(|slot| slot != path) {
        return Classified::Invalid(format!(
            "{key}: records location {:?} for the vendored path {path:?}; it is ignored",
            node.location.as_deref().unwrap_or_default()
        ));
    }
    let Some(purl) = npm_purl(&vendored.name, &vendored.version) else {
        return Classified::Invalid(format!(
            "{key}: vendored node {:?}@{:?} has unsafe coordinates",
            vendored.name, vendored.version
        ));
    };
    if vendor_ref(path).is_none() {
        return Classified::Invalid(format!("{key}: {path:?} is not a safe vendored path"));
    }
    Classified::Vendored {
        purl,
        path: path.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{testing::*, *};

    const SRI: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    const UPSTREAM: &str = "sha512-UPSTREAMupstreamUPSTREAMupstream==";
    /// The patch uuid the `redirect/npm/vlt` fixtures wire.
    const FIXTURE_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    /// The uuid the `vendor/npm/vlt` fixtures and `vendored-entry` wire.
    const VENDOR_UUID: &str = "11111111-2222-4333-8444-555555555555";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";

    fn lock(version: Option<u64>, nodes: &[String]) -> String {
        let version = version
            .map(|v| format!("  \"lockfileVersion\": {v},\n"))
            .unwrap_or_default();
        format!(
            "{{\n{version}  \"options\": {{}},\n  \"nodes\": {{\n{}\n  }},\n  \"edges\": {{}}\n}}\n",
            nodes
                .iter()
                .map(|n| format!("    {n}"))
                .collect::<Vec<_>>()
                .join(",\n")
        )
    }

    fn node(id: &str, name: &str, sri: Option<&str>, location: Option<&str>) -> String {
        let q = |v: Option<&str>| v.map_or("null".to_string(), |s| format!("{s:?}"));
        format!("{id:?}: [0,{name:?},{},{}]", q(sri), q(location))
    }

    fn url(uuid: &str, leaf: &str) -> String {
        hosted_url("npm", "left-pad", "1.3.0", uuid, leaf)
    }

    fn dir_path(uuid: &str) -> String {
        format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0/node_modules/left-pad")
    }

    fn file_id(path: &str) -> String {
        format!("file~{}", path.replace('_', "__").replace('/', "+"))
    }

    async fn discover(text: &str) -> Discovery {
        let p = Project::new();
        p.write("vlt-lock.json", text);
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    #[tokio::test]
    async fn hosted_nodes_of_every_era_are_refs_with_their_sha512() {
        let hosted = url(UUID_A, "left-pad-1.3.0.tgz");
        for (version, id) in [
            (Some(1), "~npm~left-pad@1.3.0"),
            (Some(1), "~npm~left-pad@1.3.0~peer.0df72515a50372ba"),
            (Some(0), "·npm·left-pad@1.3.0"),
            (None, "··left-pad@1.3.0"),
            (Some(1), "~acme~left-pad@1.3.0"),
        ] {
            let out = discover(&lock(
                version,
                &[node(id, "left-pad", Some(SRI), Some(&hosted))],
            ))
            .await;
            assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
            let r = &out.refs[0];
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sri(SRI.into())),
                "{id}"
            );
            assert!(r.integrity_required && r.lockfile_basis_ok(), "{id}");
            assert_eq!(r.url.as_deref(), Some(hosted.as_str()));
            assert!(out.diagnostics.is_empty(), "{id}: {:?}", out.diagnostics);
        }
    }

    #[tokio::test]
    async fn committed_hosted_and_vendored_fixtures_are_refs() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/vlt/basic/expected");
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        assert_refs(&out, &[(PURL, FIXTURE_UUID, WiringMode::Hosted)]);
        assert!(out.elsewhere.iter().any(|e| e.purl == "pkg:npm/ms@2.1.3"));

        let p = Project::new();
        p.copy_fixture("redirect/npm/vlt/scoped-package/expected");
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        assert_refs(
            &out,
            &[(
                "pkg:npm/@a/b@1.0.0",
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                WiringMode::Hosted,
            )],
        );

        for case in ["vendored-entry", "vendored-entry-tgz"] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/npm/vlt/{case}/input"));
            let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
            assert_refs(&out, &[(PURL, VENDOR_UUID, WiringMode::Vendored)]);
            let want = if case == "vendored-entry" {
                dir_path(VENDOR_UUID)
            } else {
                format!(".socket/vendor/npm/{VENDOR_UUID}/left-pad-1.3.0.tgz")
            };
            assert_eq!(out.refs[0].artifact_rel.as_deref(), Some(want.as_str()));
            assert_eq!(out.refs[0].locked_integrity, None);
        }

        let p = Project::new();
        p.copy_fixture("vendor/npm/vlt/1.2.0/cases/scoped/expected");
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        let vendored: Vec<_> = ref_triples(&out)
            .into_iter()
            .filter(|(_, _, m)| *m == WiringMode::Vendored)
            .collect();
        assert_eq!(vendored.len(), 1, "{:?}", out.refs);
        assert!(vendored[0].0.starts_with("pkg:npm/@"), "{vendored:?}");
    }

    #[tokio::test]
    async fn every_vendored_capture_wires_its_case_purl() {
        let root = fixture_path("vendor/npm/vlt");
        let mut checked = 0;
        for version in ["1.2.0", "1.0.10", "1.0.0-rc.14"] {
            let cases = root.join(version).join("cases");
            for case in std::fs::read_dir(&cases).unwrap() {
                let dir = case.unwrap().path();
                let meta: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(dir.join("case.json")).unwrap())
                        .unwrap();
                if !meta["refusal"].is_null() {
                    continue;
                }
                let rel = dir
                    .join("expected")
                    .strip_prefix(fixture_path(""))
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let p = Project::new();
                p.copy_fixture(&rel);
                let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
                let purl = meta["purl"].as_str().unwrap();
                let uuid = meta["uuid"].as_str().unwrap();
                assert!(
                    out.wires(purl, uuid, WiringMode::Vendored),
                    "{rel}: {:?} {:?}",
                    out.refs,
                    out.diagnostics
                );
                assert!(out.diagnostics.is_empty(), "{rel}: {:?}", out.diagnostics);
                checked += 1;
            }
        }
        assert!(checked >= 20, "only {checked} vendored captures checked");
    }

    #[tokio::test]
    async fn non_socket_and_mismatched_hosted_nodes_are_never_refs() {
        let id = "~npm~left-pad@1.3.0";
        let good = url(UUID_A, "left-pad-1.3.0.tgz");
        let cases: Vec<(&str, String, bool)> = vec![
            (
                "look-alike host",
                node(
                    id,
                    "left-pad",
                    Some(SRI),
                    Some(&good.replace("patch.socket.dev", "patch.socket.dev.evil.test")),
                ),
                false,
            ),
            (
                "foreign host with a uuid",
                node(
                    id,
                    "left-pad",
                    Some(SRI),
                    Some(&format!(
                        "https://evil.example/patch/npm/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz"
                    )),
                ),
                false,
            ),
            (
                "uppercase uuid",
                node(
                    id,
                    "left-pad",
                    Some(SRI),
                    Some(&format!(
                        "https://patch.socket.dev/patch/npm/tok/{}/left-pad-1.3.0.tgz",
                        UUID_A.to_uppercase()
                    )),
                ),
                false,
            ),
            (
                "slot [1] names another package",
                node(id, "right-pad", Some(SRI), Some(&good)),
                true,
            ),
            (
                "leaf names another version",
                node(
                    id,
                    "left-pad",
                    Some(SRI),
                    Some(&url(UUID_A, "left-pad-1.4.0.tgz")),
                ),
                true,
            ),
            (
                "leaf names another package",
                node(
                    id,
                    "left-pad",
                    Some(SRI),
                    Some(&url(UUID_A, "right-pad-1.3.0.tgz")),
                ),
                true,
            ),
            (
                "missing sha512",
                node(id, "left-pad", None, Some(&good)),
                true,
            ),
            (
                "sha1 integrity",
                node(
                    id,
                    "left-pad",
                    Some("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA="),
                    Some(&good),
                ),
                true,
            ),
        ];
        for (what, n, diagnosed) in cases {
            let out = discover(&lock(Some(1), &[n])).await;
            assert!(out.refs.is_empty(), "{what}: {:?}", out.refs);
            assert_eq!(
                diag_codes(&out),
                if diagnosed {
                    vec![DIAG_REF_INVALID]
                } else {
                    vec![]
                },
                "{what}: {:?}",
                out.diagnostics
            );
        }
    }

    #[tokio::test]
    async fn git_remote_workspace_and_user_file_nodes_are_not_refs() {
        let nodes = [
            node("git~github_c:a+b~abc", "b", None, None),
            node(
                "remote~https_c++example.com+x.tgz",
                "x",
                Some(SRI),
                Some("https://example.com/x.tgz"),
            ),
            node("workspace~packages+a", "a", None, None),
            node(
                "file~vendor+left-pad",
                "left-pad",
                None,
                Some("vendor/left-pad"),
            ),
        ];
        let out = discover(&lock(Some(1), &nodes)).await;
        assert!(out.refs.is_empty(), "{:?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        assert!(out.elsewhere.is_empty(), "{:?}", out.elsewhere);
    }

    #[tokio::test]
    async fn vendored_nodes_must_match_the_path_rule_name_and_location() {
        let path = dir_path(UUID_B);
        let id = file_id(&path);
        let out = discover(&lock(Some(1), &[node(&id, "left-pad", None, Some(&path))])).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
        let out = discover(&lock(Some(1), &[node(&id, "left-pad", None, None)])).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);

        let traversal =
            format!(".socket/vendor/npm/{UUID_B}/../left-pad-1.3.0/node_modules/left-pad");
        let cases = [
            (
                "slot [1] names another package",
                node(&id, "right-pad", None, Some(&path)),
            ),
            (
                "slot [3] names another path",
                node(&id, "left-pad", None, Some(&dir_path(UUID_A))),
            ),
            ("node_modules segment names another package", {
                let other =
                    format!(".socket/vendor/npm/{UUID_B}/left-pad-1.3.0/node_modules/right-pad");
                node(&file_id(&other), "left-pad", None, Some(&other))
            }),
            ("non-semver version", {
                let other =
                    format!(".socket/vendor/npm/{UUID_B}/left-pad-1.3/node_modules/left-pad");
                node(&file_id(&other), "left-pad", None, Some(&other))
            }),
            ("non-canonical uuid", {
                let other = dir_path(&UUID_B.to_uppercase());
                node(&file_id(&other), "left-pad", None, Some(&other))
            }),
            (
                "path traversal",
                node(&file_id(&traversal), "left-pad", None, Some(&traversal)),
            ),
            ("tgz of another package", {
                let other = format!(".socket/vendor/npm/{UUID_B}/right-pad-1.3.0.tgz");
                node(&file_id(&other), "left-pad", None, Some(&other))
            }),
        ];
        for (what, n) in cases {
            let out = discover(&lock(Some(1), &[n])).await;
            assert!(out.refs.is_empty(), "{what}: {:?}", out.refs);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_REF_INVALID],
                "{what}: {:?}",
                out.diagnostics
            );
        }
    }

    #[tokio::test]
    async fn a_legacy_encoded_vendored_node_is_a_ref() {
        let path = dir_path(UUID_B);
        let id = format!("file·{}", path.replace('/', "§"));
        let out = discover(&lock(Some(0), &[node(&id, "left-pad", None, Some(&path))])).await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
    }

    #[tokio::test]
    async fn a_same_version_registry_instance_withholds_the_lock_basis() {
        let hosted = url(UUID_A, "left-pad-1.3.0.tgz");
        let foreign = "https://npm.acme.example/left-pad/-/left-pad-1.3.0.tgz";
        let out = discover(&lock(
            Some(1),
            &[
                node("~npm~left-pad@1.3.0", "left-pad", Some(SRI), Some(&hosted)),
                node(
                    "~acme~left-pad@1.3.0",
                    "left-pad",
                    Some(UPSTREAM),
                    Some(foreign),
                ),
            ],
        ))
        .await;
        assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(!out.refs[0].lockfile_basis_ok());
        assert!(out.hosted_claim(PURL, UUID_A) == Some(true));

        let path = dir_path(UUID_B);
        let out = discover(&lock(
            Some(1),
            &[
                node(&file_id(&path), "left-pad", None, Some(&path)),
                node("~npm~left-pad@1.3.0", "left-pad", Some(UPSTREAM), None),
            ],
        ))
        .await;
        assert!(out.refs.is_empty(), "{:?}", out.refs);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_UNATTRIBUTABLE]);
        assert_eq!(out.vendored_claim(PURL, UUID_B, &path), Some(false));

        let out = discover(&lock(
            Some(1),
            &[
                node(&file_id(&path), "left-pad", None, Some(&path)),
                node("~npm~left-pad@1.4.0", "left-pad", Some(UPSTREAM), None),
            ],
        ))
        .await;
        assert_refs(&out, &[(PURL, UUID_B, WiringMode::Vendored)]);
    }

    #[tokio::test]
    async fn unreadable_locks_are_no_wiring_source_but_are_recognized() {
        let good = lock(
            Some(1),
            &[node(
                "~npm~left-pad@1.3.0",
                "left-pad",
                Some(SRI),
                Some(&url(UUID_A, "left-pad-1.3.0.tgz")),
            )],
        );
        for (what, text) in [
            ("BOM", format!("\u{feff}{good}")),
            (
                "version 2",
                good.replace("\"lockfileVersion\": 1", "\"lockfileVersion\": 2"),
            ),
            (
                "version 1.0",
                good.replace("\"lockfileVersion\": 1", "\"lockfileVersion\": 1.0"),
            ),
            ("not an object", format!("[{good}]")),
            ("truncated", good[..good.len() - 12].to_string()),
        ] {
            let out = discover(&text).await;
            assert!(out.refs.is_empty(), "{what}: {:?}", out.refs);
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{what}");
            assert!(out.recognizes(UUID_A, WiringMode::Hosted), "{what}");
            assert_eq!(out.hosted_claim(PURL, UUID_A), Some(false), "{what}");
        }
    }

    #[tokio::test]
    async fn only_the_root_lock_is_read() {
        let p = Project::new();
        p.write(
            "packages/a/vlt-lock.json",
            lock(
                Some(1),
                &[node(
                    "~npm~left-pad@1.3.0",
                    "left-pad",
                    Some(SRI),
                    Some(&url(UUID_A, "left-pad-1.3.0.tgz")),
                )],
            ),
        );
        let out = p.discover().await;
        assert!(
            out.refs.is_empty() && out.recognized.is_empty(),
            "{:?}",
            out.refs
        );
    }

    #[tokio::test]
    async fn a_registry_vlt_lock_contests_a_hosted_package_lock_and_vice_versa() {
        let p = Project::new();
        p.copy_fixture("redirect/npm/vlt/sibling-package-lock/input");
        p.write(
            "package-lock.json",
            serde_json::json!({
                "lockfileVersion": 3,
                "packages": { "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": url(UUID_A, "left-pad-1.3.0.tgz"),
                    "integrity": SRI,
                } }
            })
            .to_string(),
        );
        let out = p.discover().await;
        assert!(
            !out.wires(PURL, UUID_A, WiringMode::Hosted),
            "{:?}",
            out.refs
        );
        assert!(
            diag_codes(&out).contains(&DIAG_REF_UNATTRIBUTABLE),
            "{:?}",
            out.diagnostics
        );

        let p = Project::new();
        p.copy_fixture("redirect/npm/vlt/sibling-package-lock/expected");
        let out = p.discover().await;
        assert!(out.wires(
            PURL,
            "11111111-1111-4111-8111-111111111111",
            WiringMode::Hosted
        ));
        assert!(
            !diag_codes(&out).contains(&DIAG_REF_UNATTRIBUTABLE),
            "both locks rewritten: {:?}",
            out.diagnostics
        );
    }

    #[tokio::test]
    async fn a_configured_patch_server_origin_counts() {
        let origin = "http://127.0.0.1:4026";
        let local =
            format!("{origin}/patch/npm/left-pad/1.3.0/{TOKEN}/{UUID_A}/left-pad-1.3.0.tgz");
        let text = lock(
            Some(1),
            &[node(
                "~npm~left-pad@1.3.0",
                "left-pad",
                Some(SRI),
                Some(&local),
            )],
        );
        let p = Project::new().with_origin(origin);
        p.write("vlt-lock.json", &text);
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        assert_refs(&out, &[(PURL, UUID_A, WiringMode::Hosted)]);
        let out = discover(&text).await;
        assert!(out.refs.is_empty());
        assert_eq!(out.elsewhere.len(), 1, "{:?}", out.elsewhere);
    }
}
