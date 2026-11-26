//! What the patch registry a Bundler lock is on lists: its compact-index
//! `info/<gem>` document, one
//! `<version>[-<platform>] <deps>|checksum:<sha256>` line per gem it serves.
//!
//! A lock that takes a gem as platform builds from the registry of one
//! patch is moved to the registry of another patch of the gem only when no
//! locked build would turn from a patched build into upstream's own gem. A
//! lock with a `CHECKSUMS` entry for a build says what it installs; one
//! without says nothing, and then the registry the lock is on is asked:
//! one document per such gem ([`engine::gem_index_targets`]), handed to the
//! gem rewriter ([`engine::record_gem_index`]). A document that cannot be
//! read leaves the gem on the patch it is on.

use std::collections::BTreeMap;

use super::engine::{self, Candidate, CandidateFiles, MirrorSources};
use crate::api::client::PatchApi;

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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
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
    /// fails it), and records what it was asked for.
    struct Server {
        body: Option<Vec<u8>>,
        asked: Mutex<Vec<String>>,
    }

    impl Server {
        fn answering(body: Option<&[u8]>) -> Self {
            Server {
                body: body.map(<[u8]>::to_vec),
                asked: Mutex::new(Vec::new()),
            }
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
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
            _: &'a [String],
        ) -> ApiFuture<'a, HashMap<String, PackageVendorResult>> {
            Box::pin(async { Err(ApiError::Other("unused".into())) })
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
}
