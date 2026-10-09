//! The served npm tarball's own `package.json`, for the yarn berry hosted
//! pin: yarn builds a tarball entry's `bin:` from that manifest, not from
//! the registry metadata the locked `npm:` entry came from (#718). The disk
//! flow fetches it with [`fetch_hosted_npm_manifest`]; the in-memory engine
//! downloads through its provider and decodes with
//! [`decode_hosted_npm_manifest`].

use crate::api::client::ApiClient;

/// The served tarball's `package.json` text, checked against the grant's
/// sha512 when it carries one. Yarn verifies the installed bytes through
/// the pin's own cache checksum, so the manifest only decides what the pin
/// writes, never what gets installed.
pub fn decode_hosted_npm_manifest(bytes: &[u8], sha512: Option<&str>) -> Result<String, String> {
    if let Some(sri) = sha512 {
        crate::vendor::registry_fetch::verify_sri(bytes, sri)
            .map_err(|_| "hosted tarball does not match its published sha512".to_string())?;
    }
    let members = crate::patch::package::read_archive_bytes_to_map(bytes)
        .map_err(|error| format!("hosted tarball is not a readable npm package: {error}"))?;
    let manifest = members
        .get("package.json")
        .ok_or_else(|| "hosted tarball has no package/package.json".to_string())?;
    let text = std::str::from_utf8(manifest)
        .map_err(|_| "hosted tarball package.json is not UTF-8".to_string())?;
    let text = crate::formats::text::strip_bom(text);
    if !serde_json::from_str::<serde_json::Value>(text).is_ok_and(|v| v.is_object()) {
        return Err("hosted tarball package.json is not a JSON object".to_string());
    }
    Ok(text.to_string())
}

/// Download the served tarball and decode its `package.json`.
pub async fn fetch_hosted_npm_manifest(
    client: &ApiClient,
    url: &str,
    sha512: Option<&str>,
) -> Result<String, String> {
    let bytes = client
        .download_artifact(url)
        .await
        .map_err(|error| format!("cannot fetch the hosted tarball: {error}"))?;
    decode_hosted_npm_manifest(&bytes, sha512)
}

/// The sha1 (hex) of a served npm tarball, for the yarn classic hosted
/// pin's `resolved "<url>#<sha1>"` fragment when the grant carries no sha1
/// (#558). Yarn 1 names its cache slot after that fragment, so a
/// fragmentless URL shares the slot of any fragmentless upstream copy of the
/// same version and installs its bytes. The bytes must match the grant's
/// sha512: that is what the pin's `integrity` line names, and a sha1 taken
/// from any other bytes would pin a tarball yarn then refuses.
pub fn decode_hosted_npm_sha1(bytes: &[u8], sha512: &str) -> Result<String, String> {
    crate::vendor::registry_fetch::verify_sri(bytes, sha512)
        .map_err(|_| "hosted tarball does not match its published sha512".to_string())?;
    Ok(crate::utils::digest::sha1_hex_of(bytes))
}

/// Download the served tarball and take its sha1 ([`decode_hosted_npm_sha1`]).
pub async fn fetch_hosted_npm_sha1(
    client: &ApiClient,
    url: &str,
    sha512: &str,
) -> Result<String, String> {
    let bytes = client
        .download_artifact(url)
        .await
        .map_err(|error| format!("cannot fetch the hosted tarball: {error}"))?;
    decode_hosted_npm_sha1(&bytes, sha512)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::digest::sha512_sri_of;

    fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn sha1_is_taken_from_bytes_matching_the_sha512() {
        let bytes = tgz(&[("package/package.json", br#"{"name":"left-pad"}"#)]);
        let sri = sha512_sri_of(&bytes);
        assert_eq!(
            decode_hosted_npm_sha1(&bytes, &sri).unwrap(),
            crate::utils::digest::sha1_hex_of(&bytes)
        );
        let other = sha512_sri_of(b"other bytes");
        assert!(decode_hosted_npm_sha1(&bytes, &other).is_err());
    }

    #[test]
    fn decodes_the_manifest_and_checks_the_sha512() {
        let manifest = br#"{"name":"uuid","bin":{"uuid":"./dist/bin/uuid"}}"#;
        let bytes = tgz(&[("package/package.json", manifest)]);
        let sri = sha512_sri_of(&bytes);
        assert_eq!(
            decode_hosted_npm_manifest(&bytes, Some(&sri))
                .unwrap()
                .as_bytes(),
            manifest
        );
        assert_eq!(
            decode_hosted_npm_manifest(&bytes, None).unwrap().as_bytes(),
            manifest
        );
        let other = sha512_sri_of(b"other");
        assert!(decode_hosted_npm_manifest(&bytes, Some(&other))
            .unwrap_err()
            .contains("sha512"));
    }

    #[test]
    fn refuses_a_tarball_without_a_usable_manifest() {
        let none = tgz(&[("package/index.js", b"x")]);
        assert!(decode_hosted_npm_manifest(&none, None)
            .unwrap_err()
            .contains("no package/package.json"));
        let array = tgz(&[("package/package.json", b"[]")]);
        assert!(decode_hosted_npm_manifest(&array, None)
            .unwrap_err()
            .contains("not a JSON object"));
        assert!(decode_hosted_npm_manifest(b"not gzip", None).is_err());
    }

    /// One leading BOM is encoding (npm strips it); a second is content
    /// and leaves the manifest unparseable, as for every `formats::text`
    /// reader.
    #[test]
    fn reads_past_one_bom_only() {
        let one = tgz(&[(
            "package/package.json",
            "\u{feff}{\"name\":\"uuid\"}".as_bytes(),
        )]);
        assert_eq!(
            decode_hosted_npm_manifest(&one, None).unwrap(),
            "{\"name\":\"uuid\"}"
        );
        let two = tgz(&[(
            "package/package.json",
            "\u{feff}\u{feff}{\"name\":\"uuid\"}".as_bytes(),
        )]);
        assert!(decode_hosted_npm_manifest(&two, None)
            .unwrap_err()
            .contains("not a JSON object"));
    }
}
