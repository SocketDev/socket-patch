//! Composer — the root `composer.lock`, both `packages[]` and
//! `packages-dev[]` (composer installs both by default; `--no-dev` is an
//! install-time choice the lock cannot record, so a dev entry's wiring is as
//! real as a prod one's).
//!
//! The lock is parsed as JSON, so the `\/`-escaped slashes older composer
//! versions write (fixture `escaped-slash-lock`; the hosted rewriter's
//! [`crate::patch::redirect::artifact_url_present`] accepts both spellings)
//! arrive unescaped. Each entry's identity is its own `name` (lowercased by
//! [`composer_purl`], the way packagist canonicalizes and both backends
//! match — fixture `mixed-case-v-prefix`) and its `version` through
//! composer's leading-`v` normalization
//! ([`crate::crawlers::composer_crawler::normalize_version`]: locks carry the
//! pretty `v6.4.1`, purls the bare `6.4.1`). Only `dist` is read: it is what
//! composer's default `--prefer-dist` install consumes and the only block
//! either backend rewrites.
//!
//! * **Hosted** (`patch::redirect::rewrite_composer_lock`): `dist.url` on
//!   the patch server → [`DiscoverCtx::hosted_uuid`] (last canonical-uuid
//!   segment, so the uuid-shaped grant token before it is skipped). The
//!   rewriter sets `dist.type` to `zip`, repoints `url`, and ALWAYS writes
//!   the patched archive's sha1 into `dist.shasum` — replacing an empty
//!   `""`, APPENDING the key when the dist had none (fixture
//!   `no-shasum-key`), and refusing a dep whose patch carries no sha1
//!   (`redirect_composer_missing_sha1`). So `integrity_required` is set: a
//!   hosted entry with no usable 40-hex shasum was not Socket-written and
//!   cannot use the not-installed lockfile basis. `dist.reference` keeps the
//!   upstream commit and is not checked. A `path`-type dist never downloads
//!   its url, so a Socket url there wires nothing and is diagnosed. The
//!   rewriter also drops the entry's git `source` (fixture
//!   `source-and-dist`): composer 1 and 2.2 LTS fall back to it when the
//!   hosted dist fails, installing the pristine upstream commit. A `source`
//!   is NOT a reason to reject the ref (locks redirected before that fix
//!   still carry one); an installed tree that came from the fallback is
//!   pristine and fails hash verification (`not_applied`).
//! * **Vendored** (`vendor::composer_lock::rewrite_lock_entry`): `dist:
//!   {"type": "path", "url": ".socket/vendor/composer/<uuid>/<vendor>/<name>@<version>",
//!   "reference": "<uuid>"}` with `source` removed and
//!   `transport-options: {symlink: false}` added. The artifact comes from
//!   [`vendor_ref`] (root-anchored; an escaping or traversing path is
//!   diagnosed, never trusted), and the entry must be exactly what the
//!   backend writes for THIS package: `type` `path` (composer copies only a
//!   path dist from a local dir), the leaf naming the entry's own package
//!   (the backend keys the dir `<vendor>/<name>@<purl version>`, lowercase),
//!   and `reference` equal to the path's uuid (the backend has written the
//!   uuid there since vendoring shipped; composer carries it verbatim into
//!   `vendor/composer/installed.json`). `transport-options` and a leftover
//!   `source` are NOT required — composer still consumes the vendored bytes
//!   without them (symlinked instead of mirrored; `--prefer-source` aside).
//!   A path dist pins no content hash, so `locked_integrity` is `None`; the
//!   committed artifact is hashed instead.
//!
//! Out of scope: `vendor/composer/installed.json` (an install artifact, not a
//! root lock — the installed tree is verified by the crawler instead) and
//! `COMPOSER=<other>.json` renamed locks.

use serde_json::Value;

use super::{
    canonical_base_purl, composer_purl, names_vendor_dir, parse_json, vendored_leaf_purl,
    DiscoverCtx, Discovery, LocateOpts, PatchedRef, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID,
};
use crate::crawlers::composer_crawler::normalize_version;
use crate::utils::composer_version::composer_purls_equivalent;
use crate::vendor::lock_inventory::{composer_lock_packages, ComposerLockPackage};

/// The lock both backends rewrite (root-relative).
const COMPOSER_LOCK: &str = "composer.lock";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let file = COMPOSER_LOCK;
    let Some(bytes) = ctx.read_bytes(file, out).await else {
        return;
    };
    let doc: Value = match parse_json(file, &bytes) {
        Ok(doc) => doc,
        Err(detail) => {
            out.diag(DIAG_LOCKFILE_UNPARSEABLE, file, detail);
            return;
        }
    };
    if !doc.is_object() {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            file,
            format!("{file} is not a composer lock (top level is not a JSON object)"),
        );
        return;
    }
    // The inventory's own walk: `packages` then `packages-dev` (a missing
    // or non-array section — composer writes `"packages-dev": []`, older /
    // hand-trimmed locks may omit it — is simply empty).
    for entry in composer_lock_packages(&doc) {
        entry_ref(ctx, file, &entry, out);
    }
}

/// Classify one lock entry and push its ref, if any. Ordinary registry /
/// VCS entries return silently; Socket-shaped ones that fail validation are
/// diagnosed.
fn entry_ref(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    entry: &ComposerLockPackage<'_>,
    out: &mut Discovery,
) {
    let section = entry.section;
    let Some(url) = entry.dist_str("url") else {
        return;
    };
    let located = ctx.locate(url, LocateOpts::LITERAL);
    let vendored = located.vendored;
    let hosted_uuid = if vendored.is_none() {
        located.hosted
    } else {
        None
    };
    let dist_type = entry.dist_str("type");
    let label = entry.name.unwrap_or("<unnamed>");
    if vendored.is_none() && hosted_uuid.is_none() {
        // A path dist that NAMES our vendor dir but fails the root-anchored,
        // traversal-safe grammar is a wired patch being ignored: say so.
        // Everything else (packagist zipballs, a user's own path repos) is
        // not ours.
        if dist_type == Some("path") && names_vendor_dir(url) {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {section} entry {label:?} is wired to {url:?}, which is not a \
                     .socket/vendor/composer/<uuid>/<vendor>/<name>@<version> path inside \
                     this project"
                ),
            );
        }
        return;
    }

    let (Some(name), Some(version)) = (entry.name, entry.version) else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: Socket-wired {section} entry {label:?} has no name or version"),
        );
        return;
    };
    let Some(purl) = composer_purl(name, normalize_version(version)) else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: Socket-wired {section} entry {name:?}@{version:?} has unsafe coordinates"
            ),
        );
        return;
    };

    if let Some(vref) = vendored {
        // The leaf carries the patch purl's spelling (`@3.0.2.0`), the lock
        // its own (`3.0.2`): the same release either way.
        let leaf_matches = vendored_leaf_purl("composer", &vref.leaf).is_some_and(|leaf| {
            leaf == canonical_base_purl(&purl) || composer_purls_equivalent(&leaf, &purl)
        });
        if vref.eco != "composer" || !leaf_matches {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {purl} is wired to {url:?}, which is not that package's vendored \
                     composer copy"
                ),
            );
            return;
        }
        if dist_type != Some("path") {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {purl}'s vendored dist has type {dist_type:?}, not \"path\" — \
                     composer does not install it from the committed copy"
                ),
            );
            return;
        }
        let reference = entry.dist_str("reference");
        if reference != Some(vref.uuid.as_str()) {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {purl}'s vendored dist.reference {reference:?} does not carry the \
                     patch uuid {} its path names",
                    vref.uuid
                ),
            );
            return;
        }
        out.push(PatchedRef::vendored(purl, &vref, file, None));
    } else if let Some(uuid) = hosted_uuid {
        if dist_type == Some("path") {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {purl}'s dist is a \"path\" dist, so composer never downloads its \
                     Socket url {url:?}"
                ),
            );
            return;
        }
        out.push(PatchedRef::hosted(
            purl,
            uuid,
            file,
            Some(url),
            entry.dist_sha1(),
            true,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;
    use serde_json::{json, Value};

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    /// The golden fixtures' patch uuid (their grant token
    /// `11111111-1111-1111-1111-111111111111` is uuid-shaped too).
    const GOLDEN_UUID: &str = "44444444-4444-4444-4444-444444444444";
    const GOLDEN_SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";
    const SHA1: &str = "0123456789abcdef0123456789abcdef01234567";

    /// Composer-shaped lock text (4-space indent, like composer's writer).
    fn lock(packages: Value, packages_dev: Value) -> String {
        serde_json::to_string_pretty(&json!({
            "_readme": ["This file locks the dependencies of your project to a known state"],
            "content-hash": "7a59d114f58e9b02546b21d7e57430d3",
            "packages": packages,
            "packages-dev": packages_dev,
            "minimum-stability": "stable",
            "plugin-api-version": "2.6.0"
        }))
        .unwrap()
    }

    /// A registry (packagist/GitHub zipball) entry with an upstream source.
    fn registry_entry(name: &str, version: &str) -> Value {
        json!({
            "name": name,
            "version": version,
            "source": {"type": "git", "url": format!("https://github.com/{name}.git"), "reference": "f16e1d5"},
            "dist": {
                "type": "zip",
                "url": format!("https://api.github.com/repos/{name}/zipball/f16e1d5"),
                "reference": "f16e1d5",
                "shasum": ""
            },
            "type": "library"
        })
    }

    /// `name@version`'s entry exactly as the VENDOR BACKEND rewrites it
    /// (its own `rewrite_lock_entry`, so this reader cannot drift from the
    /// writer): dir keyed by the lowercase name and the bare purl version.
    fn vendored_entry(name: &str, version: &str, uuid: &str) -> Value {
        let purl_version = crate::crawlers::composer_crawler::normalize_version(version);
        let copy_rel = format!(
            ".socket/vendor/composer/{uuid}/{}@{purl_version}",
            name.to_lowercase()
        );
        let original = registry_entry(name, version);
        Value::Object(crate::vendor::composer_lock::rewrite_lock_entry(
            original.as_object().unwrap(),
            &copy_rel,
            uuid,
        ))
    }

    fn hosted_entry(name: &str, version: &str, url: &str, shasum: Option<&str>) -> Value {
        let mut dist = json!({"type": "zip", "url": url, "reference": "f16e1d5"});
        if let Some(sha1) = shasum {
            dist["shasum"] = json!(sha1);
        }
        json!({"name": name, "version": version, "dist": dist, "type": "library"})
    }

    // ── hosted: the committed golden fixtures ────────────────────────────

    /// Every hosted golden (`basic`, `escaped-slash-lock` — the bystander
    /// keeps its `\/` zipball url —, `no-shasum-key` — the rewriter appended
    /// the pin —, `mixed-case-v-prefix` — `Monolog/MonoLog` @ `v2.0.0`)
    /// yields exactly the one patched package, keyed by the PATCH uuid (not
    /// the uuid-shaped grant token before it), lockfile-attestable.
    #[tokio::test]
    async fn golden_hosted_fixtures_yield_the_patch_uuid_not_the_token() {
        for case in [
            "basic",
            "escaped-slash-lock",
            "no-shasum-key",
            "mixed-case-v-prefix",
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/composer/composer-lock/{case}/expected"));
            let out = run(&p).await;
            assert_refs(
                &out,
                &[(
                    "pkg:composer/monolog/monolog@2.0.0",
                    GOLDEN_UUID,
                    WiringMode::Hosted,
                )],
            );
            let r = &out.refs[0];
            assert_eq!(r.source_file, std::path::PathBuf::from("composer.lock"));
            assert_eq!(
                r.locked_integrity,
                Some(LockIntegrity::Sha1Hex(GOLDEN_SHA1.to_string())),
                "{case}"
            );
            assert!(r.integrity_required, "{case}");
            assert!(r.lockfile_basis_ok(), "{case}");
            assert!(r
                .url
                .as_deref()
                .unwrap()
                .starts_with("https://patch.socket.dev/patch/composer/"));
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// The rewriter's INPUTS (and the cases it declines — `version-mismatch`,
    /// `source-only-bystander`) are plain registry / VCS locks: nothing.
    #[tokio::test]
    async fn unrewritten_fixture_inputs_discover_nothing() {
        for case in [
            "basic",
            "escaped-slash-lock",
            "no-shasum-key",
            "mixed-case-v-prefix",
            "source-only-bystander",
            "version-mismatch",
        ] {
            let p = Project::new();
            p.copy_fixture(&format!("redirect/composer/composer-lock/{case}/input"));
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{case}: {:#?}", out.refs);
            assert!(out.diagnostics.is_empty(), "{case}: {:?}", out.diagnostics);
        }
    }

    /// Hand-written `\/`-escaped Socket url (an older composer re-writing the
    /// lock after the redirect) is the same ref.
    #[tokio::test]
    async fn escaped_slash_socket_url_is_unescaped() {
        let url = hosted_url("composer", "acme/lib", "1.2.0", UUID_A, "lib-1.2.0.zip");
        let entry =
            serde_json::to_string_pretty(&hosted_entry("acme/lib", "1.2.0", &url, Some(SHA1)))
                .unwrap()
                .replace('/', "\\/");
        let p = Project::new();
        p.write(
            "composer.lock",
            format!("{{\n    \"packages\": [\n{entry}\n    ],\n    \"packages-dev\": []\n}}\n"),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:composer/acme/lib@1.2.0", UUID_A, WiringMode::Hosted)],
        );
        assert_eq!(out.refs[0].url.as_deref(), Some(url.as_str()));
    }

    // ── vendored ─────────────────────────────────────────────────────────

    /// The backend's exact output — in `packages[]` and `packages-dev[]`, a
    /// `v`-prefixed mixed-case lock entry included — beside a hosted entry
    /// and a registry bystander.
    #[tokio::test]
    async fn vendored_backend_output_in_both_sections() {
        let hosted = hosted_url("composer", "acme/lib", "1.2.0", UUID_A, "lib-1.2.0.zip");
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(
                json!([
                    vendored_entry("psr/log", "3.0.2", UUID_B),
                    hosted_entry("acme/lib", "1.2.0", &hosted, Some(SHA1)),
                    registry_entry("monolog/monolog", "2.9.1"),
                ]),
                json!([vendored_entry("Symfony/Console", "v6.4.1", UUID_A)]),
            ),
        );
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:composer/psr/log@3.0.2", UUID_B, WiringMode::Vendored),
                (
                    "pkg:composer/symfony/console@6.4.1",
                    UUID_A,
                    WiringMode::Vendored,
                ),
                ("pkg:composer/acme/lib@1.2.0", UUID_A, WiringMode::Hosted),
            ],
        );
        let psr = out
            .refs
            .iter()
            .find(|r| r.purl == "pkg:composer/psr/log@3.0.2")
            .unwrap();
        assert_eq!(
            psr.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/composer/{UUID_B}/psr/log@3.0.2").as_str())
        );
        assert_eq!(psr.locked_integrity, None, "a path dist pins no hash");
        let console = out
            .refs
            .iter()
            .find(|r| r.purl == "pkg:composer/symfony/console@6.4.1")
            .unwrap();
        assert_eq!(
            console.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/composer/{UUID_A}/symfony/console@6.4.1").as_str())
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// Hand-edit tolerance: `./`-prefixed and backslashed spellings of the
    /// same root-anchored path, and an entry missing `transport-options`
    /// (composer symlinks instead of mirroring — still the vendored bytes).
    #[tokio::test]
    async fn vendored_spelling_variants_are_accepted() {
        let mut dot = vendored_entry("psr/log", "3.0.2", UUID_B);
        dot["dist"]["url"] = json!(format!("./.socket/vendor/composer/{UUID_B}/psr/log@3.0.2"));
        dot.as_object_mut().unwrap().remove("transport-options");
        let mut backslash = vendored_entry("psr/container", "2.0.0", UUID_A);
        backslash["dist"]["url"] = json!(format!(
            ".socket\\vendor\\composer\\{UUID_A}\\psr\\container@2.0.0"
        ));
        let p = Project::new();
        p.write("composer.lock", lock(json!([dot, backslash]), json!([])));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:composer/psr/log@3.0.2", UUID_B, WiringMode::Vendored),
                (
                    "pkg:composer/psr/container@2.0.0",
                    UUID_A,
                    WiringMode::Vendored,
                ),
            ],
        );
    }

    /// The backend keys the leaf by the PATCH purl's version, which may be
    /// composer's padded spelling (`@3.0.2.0`, `@1.0.0.0-RC1`) of the release
    /// the lock records (`3.0.2`, `v1.0-rc1`): the same release, accepted and
    /// keyed by the lock's own spelling. A leaf for another release is not.
    #[tokio::test]
    async fn vendored_leaf_in_an_equivalent_version_spelling_is_accepted() {
        let wired = |name: &str, version: &str, uuid: &str, leaf: &str| {
            Value::Object(crate::vendor::composer_lock::rewrite_lock_entry(
                registry_entry(name, version).as_object().unwrap(),
                &format!(".socket/vendor/composer/{uuid}/{leaf}"),
                uuid,
            ))
        };
        let padded = wired("psr/log", "3.0.2", UUID_B, "psr/log@3.0.2.0");
        let rc = wired("Acme/Lib", "v1.0-rc1", UUID_A, "acme/lib@1.0.0.0-RC1");
        let other = wired("psr/cache", "3.0.2", UUID_B, "psr/cache@3.0.2.1");
        let p = Project::new();
        p.write("composer.lock", lock(json!([padded, rc, other]), json!([])));
        let out = run(&p).await;
        assert_refs(
            &out,
            &[
                ("pkg:composer/psr/log@3.0.2", UUID_B, WiringMode::Vendored),
                (
                    "pkg:composer/acme/lib@1.0-rc1",
                    UUID_A,
                    WiringMode::Vendored,
                ),
            ],
        );
        let psr = out
            .refs
            .iter()
            .find(|r| r.purl == "pkg:composer/psr/log@3.0.2")
            .unwrap();
        assert_eq!(
            psr.artifact_rel.as_deref(),
            Some(format!(".socket/vendor/composer/{UUID_B}/psr/log@3.0.2.0").as_str())
        );
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID],
            "{:#?}",
            out.diagnostics
        );
    }

    /// Vendored entries that are not what the backend writes for THIS
    /// package are diagnosed, never trusted.
    #[tokio::test]
    async fn invalid_vendored_entries_are_diagnosed() {
        // Leaf names another package than the entry.
        let mut other_pkg = vendored_entry("psr/log", "3.0.2", UUID_B);
        other_pkg["name"] = json!("acme/evil");
        // Leaf names another version.
        let mut other_ver = vendored_entry("psr/cache", "3.0.0", UUID_B);
        other_ver["version"] = json!("2.0.0");
        // `reference` does not carry the path's uuid (null, another uuid).
        let mut null_ref = vendored_entry("psr/clock", "1.0.0", UUID_B);
        null_ref["dist"]["reference"] = Value::Null;
        let mut wrong_ref = vendored_entry("psr/link", "2.0.0", UUID_B);
        wrong_ref["dist"]["reference"] = json!(UUID_A);
        // Not a path dist.
        let mut zip = vendored_entry("psr/event-dispatcher", "1.0.0", UUID_B);
        zip["dist"]["type"] = json!("zip");
        // Another ecosystem's vendor dir.
        let mut npm_dir = vendored_entry("psr/http-message", "2.0.0", UUID_B);
        npm_dir["dist"]["url"] = json!(format!(
            ".socket/vendor/npm/{UUID_B}/psr/http-message@2.0.0"
        ));
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(
                json!([other_pkg, other_ver, null_ref, wrong_ref, zip, npm_dir]),
                json!([]),
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 6],
            "{:#?}",
            out.diagnostics
        );
        assert!(out
            .diagnostics
            .iter()
            .all(|d| d.detail.starts_with("composer.lock: ")));
        // Every rejected entry's patch is RECOGNIZED: a vendor ledger entry
        // for it is dead, never kept alive by the lock text naming its dir.
        assert_eq!(
            out.vendored_claim(
                "pkg:composer/psr/clock@1.0.0",
                UUID_B,
                &format!(".socket/vendor/composer/{UUID_B}/psr/clock@1.0.0"),
            ),
            Some(false)
        );
    }

    /// Path traversal: an escaping (`../`), absolute, or traversing vendored
    /// path, and a traversing package name, never become refs — each is
    /// diagnosed as a wired patch being ignored.
    #[tokio::test]
    async fn path_traversal_is_rejected() {
        let path_dist = |name: &str, url: String| {
            json!({
                "name": name,
                "version": "1.0.0",
                "dist": {"type": "path", "url": url, "reference": UUID_B}
            })
        };
        let hosted = hosted_url("composer", "acme/lib", "1.0.0", UUID_A, "lib-1.0.0.zip");
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(
                json!([
                    path_dist(
                        "acme/a",
                        format!("../.socket/vendor/composer/{UUID_B}/acme/a@1.0.0")
                    ),
                    path_dist(
                        "acme/b",
                        format!("/abs/.socket/vendor/composer/{UUID_B}/acme/b@1.0.0")
                    ),
                    path_dist(
                        "acme/c",
                        format!(".socket/vendor/composer/{UUID_B}/../../../etc/c@1.0.0")
                    ),
                    // Traversing lock NAME behind a well-formed Socket url.
                    hosted_entry("../../etc", "1.0.0", &hosted, Some(SHA1)),
                    hosted_entry("acme/../x", "1.0.0", &hosted, Some(SHA1)),
                ]),
                json!([]),
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID; 5],
            "{:#?}",
            out.diagnostics
        );
    }

    // ── hosted negatives / integrity ─────────────────────────────────────

    /// A uuid on a foreign host, placeholder tokens, a user's own path repo,
    /// source-only and dist-less entries: all silent non-refs.
    #[tokio::test]
    async fn non_socket_entries_are_silent() {
        let foreign =
            format!("https://evil.example/patch/composer/acme/a/1.0.0/{TOKEN}/{UUID_A}/a.zip");
        let lookalike =
            format!("https://patch.socket.dev.evil.example/patch/composer/acme/b/1.0.0/{TOKEN}/{UUID_A}/b.zip");
        let userinfo = format!(
            "https://user:pw@patch.socket.dev/patch/composer/acme/u/1.0.0/{TOKEN}/{UUID_A}/u.zip"
        );
        let placeholder = "https://patch.socket.dev/patch/composer/acme/c/1.0.0/tok/uuid/c.zip";
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(
                json!([
                    hosted_entry("acme/a", "1.0.0", &foreign, Some(SHA1)),
                    hosted_entry("acme/b", "1.0.0", &lookalike, Some(SHA1)),
                    hosted_entry("acme/u", "1.0.0", &userinfo, Some(SHA1)),
                    hosted_entry("acme/c", "1.0.0", placeholder, Some(SHA1)),
                    {"name": "acme/local", "version": "dev-main",
                     "dist": {"type": "path", "url": "packages/local", "reference": "abc"}},
                    {"name": "acme/src", "version": "1.0.0",
                     "source": {"type": "git", "url": format!("https://github.com/acme/{UUID_A}.git"), "reference": UUID_A}},
                    {"name": "acme/nodist", "version": "1.0.0"},
                    {"name": "acme/nourl", "version": "1.0.0", "dist": {"type": "zip"}},
                    "not an object",
                    registry_entry("psr/log", "3.0.2"),
                ]),
                json!([registry_entry("phpunit/phpunit", "10.0.0")]),
            ),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A hosted entry whose pin was lost or mangled (hand-edited): still a
    /// ref — an installed tree can verify it — but not lockfile-attestable,
    /// since the rewriter always writes a 40-hex sha1. An uppercase pin is
    /// normalized.
    #[tokio::test]
    async fn hosted_pin_handling() {
        let url = |n: &str| hosted_url("composer", &format!("acme/{n}"), "1.0.0", UUID_A, "x.zip");
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(
                json!([
                    hosted_entry("acme/none", "1.0.0", &url("none"), None),
                    hosted_entry("acme/empty", "1.0.0", &url("empty"), Some("")),
                    hosted_entry("acme/short", "1.0.0", &url("short"), Some("abc123")),
                    hosted_entry(
                        "acme/upper",
                        "1.0.0",
                        &url("upper"),
                        Some(&SHA1.to_uppercase())
                    ),
                ]),
                json!([]),
            ),
        );
        let out = run(&p).await;
        assert_eq!(out.refs.len(), 4, "{:#?}", out.refs);
        for r in &out.refs {
            assert!(r.integrity_required);
            let pinned = r.purl == "pkg:composer/acme/upper@1.0.0";
            assert_eq!(r.lockfile_basis_ok(), pinned, "{}", r.purl);
            if pinned {
                assert_eq!(
                    r.locked_integrity,
                    Some(LockIntegrity::Sha1Hex(SHA1.to_string()))
                );
            }
        }
    }

    /// A Socket url that composer would never download (a `path` dist), and
    /// a Socket-wired entry without a version, are diagnosed.
    #[tokio::test]
    async fn invalid_hosted_entries_are_diagnosed() {
        let url = hosted_url("composer", "acme/lib", "1.0.0", UUID_A, "lib-1.0.0.zip");
        let mut path_typed = hosted_entry("acme/lib", "1.0.0", &url, Some(SHA1));
        path_typed["dist"]["type"] = json!("path");
        let mut no_version = hosted_entry("acme/other", "1.0.0", &url, Some(SHA1));
        no_version.as_object_mut().unwrap().remove("version");
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(json!([path_typed, no_version]), json!([])),
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty(), "{:#?}", out.refs);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID; 2]);
    }

    /// `--patch-server-url` deployments count only when configured.
    #[tokio::test]
    async fn configured_patch_server_origin_is_accepted() {
        let url =
            format!("http://127.0.0.1:4545/patch/composer/acme/lib/1.0.0/{TOKEN}/{UUID_A}/lib.zip");
        let text = lock(
            json!([hosted_entry("acme/lib", "1.0.0", &url, Some(SHA1))]),
            json!([]),
        );
        let without = Project::new();
        without.write("composer.lock", &text);
        assert!(run(&without).await.refs.is_empty());
        let with = Project::new().with_origin("http://127.0.0.1:4545");
        with.write("composer.lock", &text);
        assert_refs(
            &run(&with).await,
            &[("pkg:composer/acme/lib@1.0.0", UUID_A, WiringMode::Hosted)],
        );
    }

    /// Two entries wiring one package to different patches are BOTH emitted
    /// (the CLI gates the conflict as `wiring_conflict`; this reader never
    /// picks a winner).
    #[tokio::test]
    async fn conflicting_entries_are_all_emitted() {
        let hosted = hosted_url("composer", "psr/log", "3.0.2", UUID_A, "log-3.0.2.zip");
        let p = Project::new();
        p.write(
            "composer.lock",
            lock(
                json!([hosted_entry("psr/log", "3.0.2", &hosted, Some(SHA1))]),
                json!([vendored_entry("psr/log", "3.0.2", UUID_B)]),
            ),
        );
        assert_refs(
            &run(&p).await,
            &[
                ("pkg:composer/psr/log@3.0.2", UUID_A, WiringMode::Hosted),
                ("pkg:composer/psr/log@3.0.2", UUID_B, WiringMode::Vendored),
            ],
        );
    }

    // ── file-level failures ──────────────────────────────────────────────

    #[tokio::test]
    async fn malformed_lock_is_diagnosed_not_fatal() {
        for text in ["{ not json", "[1, 2, 3]", "\"packages\""] {
            let p = Project::new();
            p.write("composer.lock", text);
            let out = run(&p).await;
            assert!(out.refs.is_empty(), "{text}");
            assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNPARSEABLE], "{text}");
            assert!(out.diagnostics[0].detail.contains("composer.lock"));
        }
        // Non-array sections are just empty.
        let p = Project::new();
        p.write(
            "composer.lock",
            r#"{"packages": {"a": 1}, "packages-dev": null}"#,
        );
        let out = run(&p).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
    }

    #[tokio::test]
    async fn missing_lock_is_silent() {
        let p = Project::new();
        p.write("composer.json", r#"{"require": {"psr/log": "^3"}}"#);
        let out = run(&p).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
    }

    /// A FIFO squatting the lock name fails fast (guarded read).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_is_unreadable_not_a_hang() {
        let p = Project::new();
        let path = p.root().join("composer.lock");
        let c = std::ffi::CString::new(path.to_string_lossy().as_bytes()).unwrap();
        // SAFETY: plain mkfifo(3) on a NUL-terminated path we own.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = tokio::time::timeout(std::time::Duration::from_secs(10), run(&p))
            .await
            .expect("discovery must not block on a FIFO");
        assert!(out.refs.is_empty());
        assert_eq!(diag_codes(&out), vec![DIAG_LOCKFILE_UNREADABLE]);
    }

    /// The orchestrator runs this extractor.
    #[tokio::test]
    async fn orchestrator_includes_composer() {
        let p = Project::new();
        p.copy_fixture("redirect/composer/composer-lock/basic/expected");
        assert_refs(
            &p.discover().await,
            &[(
                "pkg:composer/monolog/monolog@2.0.0",
                GOLDEN_UUID,
                WiringMode::Hosted,
            )],
        );
    }
}
