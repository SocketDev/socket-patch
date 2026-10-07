//! Deno — deliberately always empty.
//!
//! Neither mode exists for Deno: there is no hosted rewriter (no rewriter
//! edits `deno.lock`; `commands/scan/hosted.rs` leaves it out of the
//! rewriter's input files on purpose) and no vendored
//! backend (`vendor::path::ecosystem_dir_for_purl` maps `pkg:jsr/…` to
//! `None` — there is no `.socket/vendor/jsr/`). A `deno.lock` can therefore
//! never carry a Socket patch reference, and a Socket-looking url in one is
//! a user's own import. The extractor exists so the per-ecosystem coverage is
//! explicit and a future backend has an obvious home; Deno patches attest
//! only through the manifest + installed tree (agent mode, `setup.manual`).
//!
//! It still reads `deno.lock`'s npm section as evidence AGAINST an
//! npm-family wiring: `deno install` installs a `package.json` project's
//! npm dependencies from `deno.lock` and never reads `package-lock.json` /
//! `pnpm-lock.yaml` / `yarn.lock`, so a Socket pin there does not reach
//! the copy Deno installs (#406). Every `name@version` of that section is
//! an [`UnwiredCopy`]: a ref of the same version in any lock is marked
//! [`Unattested`](super::Unattested) (`vex` omits it) but stays a ref.
//! Whether Deno or another package manager populates `node_modules`
//! (`nodeModulesDir: "manual"` allows either) is not in the files, so
//! this is a missed attestation at worst; and since re-running `scan` /
//! `vendor` cannot clear it, the ledgers' liveness gates (`vendor
//! --check`, `scan`) are left alone. The npm section is the top-level
//! `npm` map in lockfile versions 4 and 5, `npm.packages` in version 2
//! and `packages.npm` in version 3; a key may carry Deno's peer suffix
//! (`name@1.0.0_peer@2.0.0`). The read is advisory: an unreadable or
//! unparseable `deno.lock` marks nothing.

use serde_json::Value;

use std::path::PathBuf;

use super::{
    canonical_base_purl, npm_purl, parse_json, CopyTarget, DiscoverCtx, Discovery, UnattestedKind,
    UnwiredCopy,
};

const DENO_LOCK: &str = "deno.lock";

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let Some(text) = ctx.read_advisory_text(DENO_LOCK).await else {
        return;
    };
    let Ok(lock) = parse_json(DENO_LOCK, text.as_bytes()) else {
        return;
    };
    for purl in deno_npm_keys(&lock).into_iter().filter_map(deno_npm_purl) {
        out.unwired_copy(UnwiredCopy {
            scope: None,
            target: CopyTarget::Purl(canonical_base_purl(&purl)),
            file: PathBuf::from(DENO_LOCK),
            detail: format!(
                "{DENO_LOCK} also locks it, and `deno install` installs this project's npm \
                 dependencies from {DENO_LOCK}, where no Socket wiring reaches"
            ),
            kind: UnattestedKind::DenoLock,
        });
    }
}

/// The keys of `deno.lock`'s npm package map, in any lockfile version.
fn deno_npm_keys(lock: &Value) -> Vec<&str> {
    let npm = lock.get("npm");
    let map = npm
        .and_then(|n| n.get("packages"))
        .or(npm)
        .or_else(|| lock.get("packages").and_then(|p| p.get("npm")))
        .and_then(Value::as_object);
    map.map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// The purl of one npm package key (`name@version`, `@scope/name@version`,
/// either with Deno's `_peer@x` suffix).
fn deno_npm_purl(key: &str) -> Option<String> {
    let at = key.get(1..)?.find('@')? + 1;
    let (name, version) = (&key[..at], &key[at + 1..]);
    let version = version.split('_').next()?;
    npm_purl(name, version)
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::WiringMode;

    const SRI: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";

    /// Even a lock that names a patch-server url yields nothing.
    #[tokio::test]
    async fn deno_lock_never_yields_refs() {
        let p = Project::new();
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        p.write(
            "deno.lock",
            format!(r#"{{"version":"4","remote":{{"{url}":"abc"}}}}"#),
        );
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        assert!(out.refs.is_empty() && out.diagnostics.is_empty());
        // And the full orchestrator agrees (no other extractor claims it).
        let all = p.discover().await;
        assert!(all.refs.is_empty(), "{:?}", all.refs);
    }

    #[test]
    fn deno_npm_keys_cover_every_lock_version() {
        let keys = |text: &str| {
            let lock: serde_json::Value = serde_json::from_str(text).unwrap();
            super::deno_npm_keys(&lock)
                .into_iter()
                .filter_map(super::deno_npm_purl)
                .collect::<Vec<_>>()
        };
        let want = vec!["pkg:npm/left-pad@1.3.0".to_string()];
        // v4 / v5 (deno 2.9 writes this), v3, v2.
        assert_eq!(keys(r#"{"version":"5","npm":{"left-pad@1.3.0":{}}}"#), want);
        assert_eq!(
            keys(r#"{"version":"3","packages":{"npm":{"left-pad@1.3.0":{}}}}"#),
            want
        );
        assert_eq!(
            keys(r#"{"version":"2","npm":{"specifiers":{},"packages":{"left-pad@1.3.0":{}}}}"#),
            want
        );
        assert_eq!(keys(r#"{"version":"5"}"#), Vec::<String>::new());
        assert_eq!(
            super::deno_npm_purl("@types/node@20.0.0"),
            super::super::npm_purl("@types/node", "20.0.0")
        );
        assert_eq!(
            super::deno_npm_purl("left-pad@1.3.0_react@18.2.0"),
            super::super::npm_purl("left-pad", "1.3.0")
        );
        assert_eq!(super::deno_npm_purl("nonsense"), None);
    }

    /// REGRESSION (#406): `deno install` installs a `package.json`
    /// project's npm deps from `deno.lock` and never reads
    /// `package-lock.json`, so a hosted pin in the npm lock beside a
    /// deno.lock entry of the same version is marked unattested — but stays
    /// a ref with a live claim (no rewire could clear it). Another version
    /// in deno.lock marks nothing.
    #[tokio::test]
    async fn deno_lock_marks_an_npm_lock_pin_of_the_same_version_unattested() {
        let url = hosted_url("npm", "left-pad", "1.3.0", UUID_A, "left-pad-1.3.0.tgz");
        let npm_lock = format!(
            r#"{{"name":"m","lockfileVersion":3,"packages":{{"":{{"name":"m"}},
            "node_modules/left-pad":{{"version":"1.3.0","resolved":"{url}","integrity":"{SRI}"}}}}}}"#
        );
        for (deno_version, marked) in [("1.3.0", true), ("1.2.0", false)] {
            let p = Project::new();
            p.write("package-lock.json", npm_lock.clone());
            p.write(
                "deno.lock",
                format!(
                    r#"{{"version":"5","npm":{{"left-pad@{deno_version}":{{"integrity":"sha512-X=="}}}}}}"#
                ),
            );
            let out = p.discover().await;
            assert_refs(
                &out,
                &[("pkg:npm/left-pad@1.3.0", UUID_A, WiringMode::Hosted)],
            );
            assert_eq!(
                out.hosted_claim("pkg:npm/left-pad@1.3.0", UUID_A),
                Some(true),
                "{deno_version}"
            );
            assert!(out.contested.is_empty(), "{:#?}", out.contested);
            assert_eq!(
                out.unattested.len(),
                usize::from(marked),
                "{deno_version}: {:#?}",
                out.unattested
            );
            if marked {
                let u = &out.unattested[0];
                assert_eq!(u.kind, super::super::UnattestedKind::DenoLock);
                assert_eq!(u.uuid, UUID_A);
                assert_eq!(u.file, std::path::Path::new("deno.lock"));
                assert!(u.detail.contains("deno.lock"), "{}", u.detail);
            }
        }
    }
}
