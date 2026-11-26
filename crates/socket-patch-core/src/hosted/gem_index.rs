//! What the patch registry a Bundler lock is on lists: its compact-index
//! `info/<gem>` document, one
//! `<version>[-<platform>] <deps>|checksum:<sha256>` line per gem it serves.
//!
//! A lock that takes a gem as platform builds from the registry of one
//! patch is moved to the registry of another patch of the gem only when no
//! locked build would turn from a patched build that registry still
//! serves into upstream's own gem. A `CHECKSUMS` entry says what the lock
//! pins for a build, not whether the registry still serves it (a
//! withdrawn build is refused under the snapshot the lock names), and a
//! lock without one says nothing. So the registry the lock is on is asked
//! wherever the move would put a build on upstream's gem that the lock
//! does not pin there already: one document per such gem
//! ([`engine::gem_index_targets`]), handed to the gem rewriter
//! ([`engine::record_gem_index`]). A document that cannot be read leaves
//! the gem on the patch it is on.
//!
//! The same document serves two more ends. A lock that leaves one snapshot
//! of a patch's registry for another, with no `CHECKSUMS` entry to say
//! what a build was, is told by the snapshot it names which builds the
//! move patches. And a lock that stays on a patch whose registry no longer
//! serves a build the lock pins is brought to that patch's current
//! snapshot: the patch service is asked for that patch's reference
//! ([`read_gem_refreshes`]), which lists upstream's gem for the withdrawn
//! build.

use std::collections::{BTreeMap, HashMap};

use super::engine::{self, Candidate, CandidateFiles, MirrorSources};
use crate::api::client::PatchApi;
use crate::api::types::PackageVendorResult;

/// Bound on one document. A gem version's line is a few hundred bytes and
/// a patch registry lists the gems of one version: anything near this is
/// not one.
pub const MAX_GEM_INDEX_BYTES: u64 = 1024 * 1024;

/// The document as text, or why it is not one (too large, not UTF-8).
pub fn decode_gem_index(bytes: Vec<u8>) -> Result<String, String> {
    if bytes.len() as u64 > MAX_GEM_INDEX_BYTES {
        return Err(format!(
            "its index document is {} bytes, more than a patch registry's",
            bytes.len()
        ));
    }
    String::from_utf8(bytes).map_err(|_| "its index document is not UTF-8 text".to_string())
}

/// Read the compact-index document at `url`
/// ([`crate::patch::redirect::gem_index_info_url`]). The error is safe to
/// print: the URL carries a grant token, which is redacted from it.
pub async fn fetch_gem_index(client: &dyn PatchApi, url: &str) -> Result<String, String> {
    let bytes = client
        .download_artifact(url, MAX_GEM_INDEX_BYTES)
        .await
        .map_err(|error| crate::utils::redact::redact_urls_in(&error.to_string()).into_owned())?;
    decode_gem_index(bytes)
}

/// Read the documents the gem rewriter asks for over `read`
/// ([`engine::gem_index_targets`]) and hand them to it
/// ([`engine::record_gem_index`]): what a host does before every
/// [`engine::rewrite`]. `held` keeps what the run has read, so a document
/// is asked for once however often the run rewrites.
///
/// A lock written through a patch mirror names its registry on the
/// mirror, which may ask for credentials the run was never given: the
/// document is read where the patch server serves it
/// ([`MirrorSources::fetch_url`]), and handed in under the URL the lock
/// names.
pub async fn read_gem_indexes(
    client: &dyn PatchApi,
    sources: &MirrorSources,
    candidates: &[Candidate],
    read: &mut CandidateFiles,
    held: &mut BTreeMap<String, Result<String, String>>,
) {
    let mut documents = Vec::new();
    for url in engine::gem_index_targets(candidates, &read.files) {
        let document = match held.get(&url) {
            Some(document) => document.clone(),
            None => {
                let document = fetch_gem_index(client, &sources.fetch_url(&url)).await;
                held.insert(url.clone(), document.clone());
                document
            }
        };
        documents.push((url, document));
    }
    engine::record_gem_index(read, &documents);
}

/// The candidates that bring the locks of `read` which stay on a patch to
/// what that patch serves today ([`engine::gem_refresh_targets`]), to
/// rewrite beside `candidates`: what a host adds once the documents of
/// [`read_gem_indexes`] are in `read`.
///
/// The reference of each such patch is taken from `known` (the answers the
/// run already holds, by uuid) and else asked of the patch service, all of
/// them in one request. That request is made only where a withdrawal was
/// detected while a lock stays; a run that detects none asks nothing. An
/// answer that is not usable, and a request that fails, add no candidate
/// ([`engine::gem_refresh_candidates`]): the lock stays as it is.
pub async fn read_gem_refreshes(
    client: &dyn PatchApi,
    candidates: &[Candidate],
    read: &CandidateFiles,
    known: &HashMap<String, PackageVendorResult>,
    patch_server_origins: &[String],
) -> Vec<Candidate> {
    let targets = engine::gem_refresh_targets(candidates, &read.files);
    let mut references: HashMap<String, PackageVendorResult> = HashMap::new();
    let mut unknown: Vec<String> = Vec::new();
    for target in &targets {
        match known.get(&target.uuid) {
            Some(reference) => {
                references.insert(target.uuid.clone(), reference.clone());
            }
            None => unknown.push(target.uuid.clone()),
        }
    }
    if !unknown.is_empty() {
        // A request that fails answers for none of them.
        let asked = client.fetch_registry_references(&unknown).await;
        references.extend(asked.unwrap_or_default());
    }
    engine::gem_refresh_candidates(&targets, &references, patch_server_origins, &read.files)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::api::client::{ApiError, ApiFuture};
    use crate::api::types::{BatchSearchResponse, PackageVendorResult, SearchResponse};
    use crate::patch::redirect::{
        DepOverride, GemPlatformChecksum, Integrity, RegistryOverride, RegistryOverrideIdentifiers,
        GEM_INDEX_KEY,
    };

    #[test]
    fn a_document_is_utf8_text_of_a_bounded_size() {
        assert_eq!(
            decode_gem_index(b"---\n1.0.0 |checksum:abc\n".to_vec()).as_deref(),
            Ok("---\n1.0.0 |checksum:abc\n")
        );
        assert!(decode_gem_index(vec![0xff, 0xfe]).is_err());
        assert!(decode_gem_index(vec![b'a'; MAX_GEM_INDEX_BYTES as usize + 1]).is_err());
    }

    const REGISTRY: &str = "https://patch.test/patch-registry/gem/grant";
    /// The patch the lock is on, and the patch on offer.
    const EARLIER: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
    const NEWER: &str = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";

    /// A patch server that answers every artifact URL with `body` (or
    /// fails it) and a reference request with `references` (or fails
    /// it), and records what it was asked for.
    struct Server {
        body: Option<Vec<u8>>,
        references: Option<HashMap<String, PackageVendorResult>>,
        asked: Mutex<Vec<String>>,
        asked_references: Mutex<Vec<Vec<String>>>,
    }

    impl Server {
        fn answering(body: Option<&[u8]>) -> Self {
            Server {
                body: body.map(<[u8]>::to_vec),
                references: None,
                asked: Mutex::new(Vec::new()),
                asked_references: Mutex::new(Vec::new()),
            }
        }

        /// A server whose reference requests answer `references`.
        fn granting(references: HashMap<String, PackageVendorResult>) -> Self {
            Server {
                references: Some(references),
                ..Server::answering(None)
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }

        fn asked_references(&self) -> Vec<Vec<String>> {
            self.asked_references.lock().unwrap().clone()
        }
    }

    impl PatchApi for Server {
        fn uses_public_proxy(&self) -> bool {
            false
        }
        fn search_patches_batch<'a>(
            &'a self,
            _: &'a [String],
        ) -> ApiFuture<'a, BatchSearchResponse> {
            Box::pin(async { Err(ApiError::Other("unused".into())) })
        }
        fn search_patches_by_package<'a>(&'a self, _: &'a str) -> ApiFuture<'a, SearchResponse> {
            Box::pin(async { Err(ApiError::Other("unused".into())) })
        }
        fn fetch_registry_references<'a>(
            &'a self,
            uuids: &'a [String],
        ) -> ApiFuture<'a, HashMap<String, PackageVendorResult>> {
            self.asked_references.lock().unwrap().push(uuids.to_vec());
            let references = self.references.clone();
            Box::pin(async move {
                references.ok_or_else(|| ApiError::Other("the patch service is down".into()))
            })
        }
        fn download_artifact<'a>(&'a self, url: &'a str, _: u64) -> ApiFuture<'a, Vec<u8>> {
            self.asked.lock().unwrap().push(url.to_string());
            let body = self.body.clone();
            Box::pin(async move {
                body.ok_or_else(|| ApiError::Other(format!("GET {url} failed with status 503")))
            })
        }
    }

    /// The patch [`NEWER`] of `rails 7.0.0`, whose registry serves
    /// upstream's own gem for `x86_64-linux-gnu`.
    fn candidate() -> Candidate {
        Candidate {
            purl: "pkg:gem/rails@7.0.0".into(),
            dep: DepOverride {
                ecosystem: "gem".into(),
                name: "rails".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: "grant".into(),
                patch_uuid: NEWER.into(),
                artifact_url: format!("{REGISTRY}/{NEWER}/gems/rails-7.0.0.gem"),
                npm_registry_url: None,
                registry_override: Some(RegistryOverride {
                    kind: "rubygems-compact-index".into(),
                    index_url: format!("{REGISTRY}/{NEWER}/s/c4/"),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "rails".into(),
                        version: "7.0.0".into(),
                        gem_builds: Some(vec![GemPlatformChecksum {
                            platform: "x86_64-linux-gnu".into(),
                            gem_checksum_sha256: "2".repeat(64),
                            patch_uuid: None,
                        }]),
                        ..Default::default()
                    },
                }),
                integrity: Integrity::default(),
            },
        }
    }

    /// The candidate files of a project whose lock takes the gem as a
    /// platform build from `remote`, with no `CHECKSUMS`.
    fn read_with_lock_on(remote: &str) -> CandidateFiles {
        let lock = format!(
            "GEM\n  remote: {remote}\n  specs:\n    rails (7.0.0-x86_64-linux-gnu)\n\nPLATFORMS\n  \
             x86_64-linux-gnu\n\nDEPENDENCIES\n  rails (= 7.0.0)!\n\nBUNDLED WITH\n  4.0.15\n"
        );
        let mut read = CandidateFiles::default();
        read.files.insert("Gemfile.lock".to_string(), lock);
        read
    }

    /// A run asks the registry a lock is on once, however often it
    /// rewrites, and hands each rewrite the answer. A document that could
    /// not be read is not asked for again and is not handed in, and a
    /// lock that asks nothing costs no request.
    #[tokio::test]
    async fn a_registry_is_asked_once_a_run_and_its_answer_handed_to_each_rewrite() {
        let candidates = [candidate()];
        let direct = MirrorSources::default();
        let on_earlier = format!("{REGISTRY}/{EARLIER}/s/1a/");
        let url = format!("{REGISTRY}/{EARLIER}/s/1a/info/rails");
        let document = "---\n7.0.0-x86_64-linux-gnu |checksum:abc\n";

        let server = Server::answering(Some(document.as_bytes()));
        let mut held = BTreeMap::new();
        let mut first = read_with_lock_on(&on_earlier);
        read_gem_indexes(&server, &direct, &candidates, &mut first, &mut held).await;
        assert_eq!(server.asked(), [url.clone()]);
        let handed: BTreeMap<String, String> =
            serde_json::from_str(&first.files[GEM_INDEX_KEY]).expect("the documents");
        assert_eq!(
            handed,
            BTreeMap::from([(url.clone(), document.to_string())])
        );
        let mut second = read_with_lock_on(&on_earlier);
        read_gem_indexes(&server, &direct, &candidates, &mut second, &mut held).await;
        assert_eq!(server.asked().len(), 1, "asked once a run");
        assert_eq!(
            second.files.get(GEM_INDEX_KEY),
            first.files.get(GEM_INDEX_KEY)
        );

        // The lock is on the candidate's own registry, or on its upstream
        // registry: nothing is asked, nothing is handed in.
        for remote in [
            format!("{REGISTRY}/{NEWER}/s/c4/"),
            "https://rubygems.org/".into(),
        ] {
            let mut read = read_with_lock_on(&remote);
            read_gem_indexes(&server, &direct, &candidates, &mut read, &mut held).await;
            assert!(!read.files.contains_key(GEM_INDEX_KEY), "{remote}");
        }
        assert_eq!(server.asked().len(), 1);

        // A registry that does not answer, or answers with no text.
        for body in [None, Some(&[0xff_u8, 0xfe][..])] {
            let server = Server::answering(body);
            let mut held = BTreeMap::new();
            for _ in 0..2 {
                let mut read = read_with_lock_on(&on_earlier);
                read_gem_indexes(&server, &direct, &candidates, &mut read, &mut held).await;
                assert!(!read.files.contains_key(GEM_INDEX_KEY));
            }
            assert_eq!(server.asked(), [url.clone()]);
            let why = held[&url].as_ref().expect_err("unread");
            assert!(!why.contains("grant"), "the grant token is redacted: {why}");
        }
    }

    /// A lock written through a patch mirror is on the mirror, which may
    /// ask for credentials the run does not hold. The document of its
    /// registry is read at the same path of the patch server, where the
    /// grant token in the path is all it takes, and handed to the rewrite
    /// under the URL the lock names.
    #[tokio::test]
    async fn a_registry_on_a_patch_mirror_is_read_from_the_patch_server() {
        use crate::patch::redirect::mirror::PatchMirror;
        let mirror = PatchMirror::parse("https://repo.example/artifactory/socket-patch").unwrap();
        let origins = vec![mirror.base().to_string()];
        let (mut skipped, mut warnings) = (Vec::new(), Vec::new());
        let (candidates, sources) = engine::mirror_candidates(
            vec![candidate()],
            &mirror,
            &origins,
            &mut skipped,
            &mut warnings,
        );
        assert_eq!(candidates.len(), 1, "{warnings:?}");

        let on_mirror = format!("{}/patch-registry/gem/grant/{EARLIER}/s/1a/", mirror.base());
        let document = "---\n7.0.0-x86_64-linux-gnu |checksum:abc\n";
        let server = Server::answering(Some(document.as_bytes()));
        let mut held = BTreeMap::new();
        let mut read = read_with_lock_on(&on_mirror);
        read_gem_indexes(&server, &sources, &candidates, &mut read, &mut held).await;
        assert_eq!(
            server.asked(),
            [format!("{REGISTRY}/{EARLIER}/s/1a/info/rails")],
            "asked of the patch server, never of the mirror"
        );
        let handed: BTreeMap<String, String> =
            serde_json::from_str(&read.files[GEM_INDEX_KEY]).expect("the documents");
        assert_eq!(
            handed,
            BTreeMap::from([(format!("{on_mirror}info/rails"), document.to_string())])
        );
    }

    /// The reference of [`EARLIER`] as the patch service has it once its
    /// `x86_64-linux-gnu` build was withdrawn: its registry at the
    /// snapshot `2b`, with upstream's gem for that platform.
    fn earlier_reference_now() -> HashMap<String, PackageVendorResult> {
        let registry = format!("{REGISTRY}/{EARLIER}/");
        let reference = serde_json::json!({
            "status": "granted",
            "url": format!("{registry}gems/rails-7.0.0.gem"),
            "purl": "pkg:gem/rails@7.0.0",
            "artifacts": [{"kind": "tarball", "url": null, "integrity": {
                "sha256": "f".repeat(64)
            }}],
            "registryOverride": {
                "kind": "rubygems-compact-index",
                "indexUrl": format!("{registry}s/2b/"),
                "identifiers": {
                    "name": "rails", "version": "7.0.0",
                    "gemChecksumSha256": "f".repeat(64),
                    "gemBuilds": [
                        {"platform": "ruby", "gemChecksumSha256": "f".repeat(64),
                         "patchUuid": EARLIER},
                        {"platform": "x86_64-linux-gnu", "gemChecksumSha256": "2".repeat(64),
                         "patchUuid": null},
                    ],
                },
            },
        });
        let reference = serde_json::from_value(reference).expect("a reference");
        HashMap::from([(EARLIER.to_string(), reference)])
    }

    /// A lock that stays on a patch (the patch on offer does not list its
    /// platform) while that patch's registry no longer lists the build it
    /// pins: the reference of the patch the lock is on is asked for,
    /// once, and its candidate comes back to rewrite beside the patch on
    /// offer. An answer the run already holds costs no request. A request
    /// that fails, and a lock whose registry shows no withdrawal (or was
    /// not read), add no candidate, and the latter ask nothing.
    #[tokio::test]
    async fn the_reference_of_the_patch_a_lock_stays_on_is_asked_for_after_a_withdrawal() {
        // The patch on offer lists another platform than the lock names.
        let mut offered = candidate();
        let ids = &mut offered.dep.registry_override.as_mut().unwrap().identifiers;
        ids.gem_builds.as_mut().unwrap()[0].platform = "arm64-darwin".into();
        let candidates = [offered];
        let on_earlier = format!("{REGISTRY}/{EARLIER}/s/1a/");
        let url = format!("{on_earlier}info/rails");
        let read_with = |document: Option<&str>| {
            let mut read = read_with_lock_on(&on_earlier);
            let documents: Vec<(String, Result<String, String>)> = document
                .map(|text| (url.clone(), Ok(text.to_string())))
                .into_iter()
                .collect();
            engine::record_gem_index(&mut read, &documents);
            read
        };
        // The registry lists the ruby gem, and no linux build any more.
        let withdrawn = format!("---\n7.0.0 |checksum:{}\n", "f".repeat(64));
        let read = read_with(Some(&withdrawn));
        assert_eq!(
            engine::gem_index_targets(&candidates, &read.files),
            [url.clone()]
        );
        let none = HashMap::new();

        let server = Server::granting(earlier_reference_now());
        let refreshed = read_gem_refreshes(&server, &candidates, &read, &none, &[]).await;
        assert_eq!(server.asked_references(), [[EARLIER.to_string()]]);
        let [current] = refreshed.as_slice() else {
            panic!("one candidate: {refreshed:?}");
        };
        assert_eq!(
            (current.purl.as_str(), current.dep.patch_uuid.as_str()),
            ("pkg:gem/rails@7.0.0", EARLIER)
        );

        // An answer the run holds already: no request.
        let server = Server::granting(HashMap::new());
        let known = earlier_reference_now();
        let refreshed = read_gem_refreshes(&server, &candidates, &read, &known, &[]).await;
        assert_eq!(refreshed.len(), 1);
        assert_eq!(server.asked_references(), Vec::<Vec<String>>::new());

        // The request fails, or answers nothing for the patch.
        for server in [Server::answering(None), Server::granting(HashMap::new())] {
            let refreshed = read_gem_refreshes(&server, &candidates, &read, &none, &[]).await;
            assert!(refreshed.is_empty(), "{refreshed:?}");
            assert_eq!(server.asked_references(), [[EARLIER.to_string()]]);
        }

        // No withdrawal shown: the registry lists the build, or was not
        // read. Nothing is asked.
        let served = format!(
            "---\n7.0.0 |checksum:{}\n7.0.0-x86_64-linux-gnu |checksum:{}\n",
            "f".repeat(64),
            "b".repeat(64)
        );
        for read in [read_with(Some(&served)), read_with(None)] {
            let server = Server::granting(earlier_reference_now());
            let refreshed = read_gem_refreshes(&server, &candidates, &read, &none, &[]).await;
            assert!(refreshed.is_empty(), "{refreshed:?}");
            assert_eq!(server.asked_references(), Vec::<Vec<String>>::new());
        }
    }
}
