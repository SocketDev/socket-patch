//! bun.lockb upstream restore: every package record whose remote-tarball
//! resolution is a hosted URL naming an in-scope patch uuid is rebuilt as
//! Bun's npm registry record for the pin's `name@version` — the registry's
//! `dist.tarball` and `dist.integrity` (via the `SOCKET_NPM_REGISTRY`-aware
//! [`super::UpstreamClient`]), through the native codec
//! ([`BunLockb::set_registry_package`], which also re-derives the metadata
//! hash Bun's frozen install checks). Every other byte is the file's own.
//!
//! Only reached under [`super::RestoreOptions::bun_lockb`]: see there for
//! why `rollback` keeps refusing a binary lock.

use std::collections::BTreeSet;

use super::npm::{by_uuid, fetch_dists, refuse_all_in};
use super::{Ctx, FormatResult, HostedPin, View};
use crate::vendor::bun_lockb::BunLockb;

pub(super) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let bytes = match view.read_bytes(rel).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                refuse_all_in(&pins, rel, &mut result, format!("{rel} no longer exists"));
                continue;
            }
            Err(e) => {
                refuse_all_in(&pins, rel, &mut result, e);
                continue;
            }
        };
        let mut lock = match BunLockb::parse(&bytes).and_then(|lock| {
            lock.validate_mutation()?;
            Ok(lock)
        }) {
            Ok(lock) => lock,
            Err(e) => {
                refuse_all_in(&pins, rel, &mut result, e);
                continue;
            }
        };
        let packages = match lock.packages() {
            Ok(packages) => packages,
            Err(e) => {
                refuse_all_in(&pins, rel, &mut result, e);
                continue;
            }
        };
        // (package id, uuid, name, version) per hosted record.
        let mut hits: Vec<(usize, String, String, String)> = Vec::new();
        for p in &packages {
            // Registry records carry a version; a hosted record is a
            // remote tarball, which the codec reports without one.
            if p.version.is_some() {
                continue;
            }
            let Some(uuid) = ctx.hosted_uuid(&p.resolution) else {
                continue;
            };
            let Some(pin) = pins.get(uuid.as_str()) else {
                continue;
            };
            match pin.name_version() {
                Some((name, version)) if name == p.name => {
                    hits.push((p.id, uuid, name, version));
                }
                _ => result.refuse(
                    &uuid,
                    format!(
                        "the {rel} package #{} ({}) wiring it is not {}",
                        p.id, p.name, pin.purl
                    ),
                ),
            }
        }
        let wanted: BTreeSet<(String, String, String)> = hits
            .iter()
            .map(|(_, u, n, v)| (u.clone(), n.clone(), v.clone()))
            .collect();
        let dists = fetch_dists(&wanted, ctx, &mut result).await;
        let mut changed = false;
        for (id, uuid, name, version) in hits {
            if result.refused.contains_key(&uuid) {
                continue;
            }
            let Some(dist) = dists.get(&(name.clone(), version.clone())) else {
                continue;
            };
            let Some(integrity) = dist.integrity.as_deref() else {
                result.refuse(
                    &uuid,
                    format!("the registry records no integrity for {name}@{version}"),
                );
                continue;
            };
            // Transactional per record: a failed rebuild leaves `lock` as is.
            match lock.set_registry_package(id, &version, &dist.tarball, integrity) {
                Ok(()) => {
                    result.handled.insert(uuid);
                    changed = true;
                }
                Err(e) => result.refuse(&uuid, format!("{rel} package #{id}: {e}")),
            }
        }
        if changed {
            view.write_bytes(rel, lock.bytes());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::{restore_upstream, PinStatus, RestoreOptions, RestoreOutcome};
    use super::*;
    use crate::patch::redirect::{rewrite_bun_binary, DepOverride, Integrity, RewriteResult};
    use base64::Engine;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const UUID: &str = "77777777-7777-4777-8777-777777777777";
    const TOKEN: &str = "11111111-1111-4111-8111-111111111111";
    const UPSTREAM_URL: &str = "https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz";

    fn fixture(dir: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/bun-lockb")
                .join(dir)
                .join("bun.lockb"),
        )
        .unwrap()
    }

    /// `original` as `scan --mode hosted` leaves it: minimist@1.2.2 on the
    /// patch server.
    fn hosted(original: &[u8]) -> Vec<u8> {
        let dep = DepOverride {
            ecosystem: "npm".into(),
            name: "minimist".into(),
            namespace: None,
            version: "1.2.2".into(),
            token: TOKEN.into(),
            patch_uuid: UUID.into(),
            artifact_url: format!(
                "https://patch.socket.dev/patch/npm/{TOKEN}/{UUID}/minimist-1.2.2.tgz"
            ),
            berry_zip_url: None,
            registry_override: None,
            integrity: Integrity {
                sha512: Some(format!(
                    "sha512-{}",
                    base64::engine::general_purpose::STANDARD.encode([42; 64])
                )),
                ..Default::default()
            },
        };
        let mut result = RewriteResult::default();
        rewrite_bun_binary(original, &[dep], &mut result);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        result.binary_files.remove("bun.lockb").expect("rewritten")
    }

    fn minimist(bytes: &[u8]) -> crate::vendor::bun_lockb::BinaryPackage {
        BunLockb::parse_packages(bytes)
            .unwrap()
            .into_iter()
            .find(|p| p.name == "minimist" && p.version.as_deref() == Some("1.2.2"))
            .expect("the registry record")
    }

    /// An npm registry answering minimist@1.2.2 with the fixture's digest.
    async fn registry(integrity: &str) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/minimist/1.2.2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dist": { "tarball": UPSTREAM_URL, "integrity": integrity }
            })))
            .mount(&server)
            .await;
        server
    }

    /// Discover the hosted pin in `lock` and restore it.
    async fn run(lock: &[u8], opts: &RestoreOptions) -> (RestoreOutcome, Vec<u8>) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), lock).unwrap();
        let discovery = crate::vex::discover_patched_refs(tmp.path()).await;
        let pins = HostedPin::all(&discovery);
        assert_eq!(pins.len(), 1, "{pins:?}");
        assert_eq!(pins[0].purl, "pkg:npm/minimist@1.2.2");
        assert_eq!(pins[0].files, ["bun.lockb"]);
        let outcome = restore_upstream(tmp.path(), &pins, opts).await;
        assert!(outcome.flush_error.is_none(), "{:?}", outcome.flush_error);
        (
            outcome,
            std::fs::read(tmp.path().join("bun.lockb")).unwrap(),
        )
    }

    fn vendor_opts() -> RestoreOptions {
        RestoreOptions {
            bun_lockb: true,
            ..RestoreOptions::default()
        }
    }

    /// Every binary writer whose lock the hosted rewrite leaves in the
    /// format it found gets its exact pre-hosted bytes back — including the
    /// uninitialized padding early writers leave in registry records.
    #[tokio::test]
    #[serial_test::serial]
    async fn hosted_record_restores_byte_exact_on_every_writer() {
        for dir in [
            "0.1.7",
            "0.5.9",
            "0.6.7",
            "0.6.8",
            "0.8.1",
            "0.8.1-production",
            "0.8.1-production-complex",
            "1.0.0",
            "1.0.0-production",
            "1.0.36",
            "1.1.0",
            "1.1.38",
            "1.1.45",
            "1.2.0",
            "1.2.23",
            "1.3.0",
            "1.3.14",
            "1.4.2",
            "two-versions",
        ] {
            let original = fixture(dir);
            let upstream = minimist(&original);
            assert_eq!(upstream.resolution, UPSTREAM_URL, "{dir}");
            let server = registry(upstream.integrity.as_deref().unwrap()).await;
            std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
            let lock = hosted(&original);
            let (outcome, after) = run(&lock, &vendor_opts()).await;
            std::env::remove_var("SOCKET_NPM_REGISTRY");
            assert_eq!(outcome.pins[0].status, PinStatus::Restored, "{dir}");
            assert_eq!(outcome.reverted_files, ["bun.lockb"], "{dir}");
            assert!(after == original, "{dir}: not byte-exact");
        }
    }

    /// Where the hosted rewrite had to normalize the lock (format 1 promoted
    /// to format 2; workspace dependency behaviors), the restore is the
    /// registry record, not the original bytes.
    #[tokio::test]
    #[serial_test::serial]
    async fn normalized_locks_restore_the_registry_record() {
        for dir in [
            "0.1.1",
            "0.1.6",
            "1.1.45-extensions",
            "1.2.23-extensions",
            "1.4.2-extensions",
        ] {
            let original = fixture(dir);
            let upstream = minimist(&original);
            let server = registry(upstream.integrity.as_deref().unwrap()).await;
            std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
            let (outcome, after) = run(&hosted(&original), &vendor_opts()).await;
            std::env::remove_var("SOCKET_NPM_REGISTRY");
            assert_eq!(outcome.pins[0].status, PinStatus::Restored, "{dir}");
            let restored = minimist(&after);
            assert_eq!(restored.resolution, UPSTREAM_URL, "{dir}");
            assert_eq!(restored.integrity, upstream.integrity, "{dir}");
            BunLockb::parse(&after)
                .unwrap()
                .validate_mutation()
                .unwrap();
            assert!(
                !after.windows(16).any(|w| w == b"patch.socket.dev"),
                "{dir}"
            );
        }
    }

    /// Without the vendor opt-in (the `rollback` posture), or offline,
    /// nothing is written and the refusal names the checkout remedy; a dry
    /// run resolves the restore and writes nothing.
    #[tokio::test]
    #[serial_test::serial]
    async fn refusals_and_dry_run_leave_the_lock_untouched() {
        let original = fixture("1.1.38");
        let upstream = minimist(&original);
        let server = registry(upstream.integrity.as_deref().unwrap()).await;
        std::env::set_var("SOCKET_NPM_REGISTRY", server.uri());
        let lock = hosted(&original);
        let rollback = RestoreOptions::default();
        let offline = RestoreOptions {
            offline: true,
            ..vendor_opts()
        };
        for opts in [&rollback, &offline] {
            let (outcome, after) = run(&lock, opts).await;
            let why: Vec<&str> = outcome.refused().map(|(_, why)| why).collect();
            assert_eq!(why.len(), 1, "{why:?}");
            assert!(why[0].contains("git checkout -- bun.lockb"), "{why:?}");
            assert!(outcome.reverted_files.is_empty());
            assert!(after == lock);
        }
        let dry = RestoreOptions {
            dry_run: true,
            ..vendor_opts()
        };
        let (outcome, after) = run(&lock, &dry).await;
        std::env::remove_var("SOCKET_NPM_REGISTRY");
        assert_eq!(outcome.pins[0].status, PinStatus::Restored);
        assert_eq!(outcome.reverted_files, ["bun.lockb"]);
        assert!(after == lock);
    }
}
