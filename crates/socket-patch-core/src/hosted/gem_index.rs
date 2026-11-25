//! What a gem patch registry lists: its compact-index `info/<gem>` document.
//!
//! Each platform gem of a fix has a patch of its own, and the registry of
//! any of them lists and serves every one: one
//! `<version>[-<platform>] <deps>|checksum:<sha256>` line per gem. A lock
//! of platform builds takes one such registry as the gem's source and pins
//! each build to a sha256, so before it does the run reads the document
//! once per gem ([`engine::gem_index_targets`]) and the gem rewriter holds
//! the lock's builds against it.
//!
//! [`engine::gem_index_targets`]: super::engine::gem_index_targets

use crate::api::client::ApiClient;

/// Bound on one document. A gem version's line is a few hundred bytes and
/// a patch registry lists one version: anything near this is not one.
const MAX_GEM_INDEX_BYTES: usize = 1024 * 1024;

/// The document as text, or why it is not one (too large, not UTF-8).
pub fn decode_gem_index(bytes: Vec<u8>) -> Result<String, String> {
    if bytes.len() > MAX_GEM_INDEX_BYTES {
        return Err(format!(
            "its index document is {} bytes, more than a patch registry's",
            bytes.len()
        ));
    }
    String::from_utf8(bytes).map_err(|_| "its index document is not UTF-8 text".to_string())
}

/// Read the compact-index document at `url`
/// ([`crate::patch::redirect::gem_index_info_url`]) from the patch server.
/// The error is safe to print: the URL carries a grant token, which is
/// redacted from it.
pub async fn fetch_gem_index(client: &ApiClient, url: &str) -> Result<String, String> {
    let bytes = client
        .download_artifact(url)
        .await
        .map_err(|error| crate::utils::redact::redact_urls_in(&error.to_string()).into_owned())?;
    decode_gem_index(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_is_utf8_text_of_a_bounded_size() {
        assert_eq!(
            decode_gem_index(b"---\n1.0.0 |checksum:abc\n".to_vec()).as_deref(),
            Ok("---\n1.0.0 |checksum:abc\n")
        );
        assert!(decode_gem_index(vec![0xff, 0xfe]).is_err());
        assert!(decode_gem_index(vec![b'a'; MAX_GEM_INDEX_BYTES + 1]).is_err());
    }
}
