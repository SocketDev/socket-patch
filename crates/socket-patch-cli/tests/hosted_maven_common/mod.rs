//! The hosted (`scan --mode hosted`) Socket API + `maven2` repository fake
//! shared by the real-build hosted capstones (`e2e_redirect_maven_build`
//! and the Gradle hosted suites).
//!
//! A [`Hosted`] names one patched GAV and its grant coordinates; the
//! served repository is the production-shaped
//! `…/patch-registry/maven/<token>/<uuid>/maven2` path carrying the
//! SUFFIXED version (`<base>-socket.<first 8 hex of the patch uuid>`).

#![allow(dead_code)]

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// One hosted patch: the GAV it patches and the grant around it.
pub struct Hosted {
    pub org: &'static str,
    /// Canonical lowercase patch uuid; its first 8 hex are the suffix.
    pub uuid: &'static str,
    pub hex8: &'static str,
    /// Grant-token path level of the hosted urls (uuid-shaped, like prod).
    pub token: &'static str,
    pub ghsa: &'static str,
    pub cve: &'static str,
    pub group: &'static str,
    pub artifact: &'static str,
    pub version: &'static str,
    /// The batch listing's `title`.
    pub title: &'static str,
}

impl Hosted {
    pub fn purl(&self) -> String {
        format!(
            "pkg:maven/{}/{}@{}",
            self.group, self.artifact, self.version
        )
    }

    pub fn group_path(&self) -> String {
        self.group.replace('.', "/")
    }

    pub fn suffixed(&self) -> String {
        format!("{}-socket.{}", self.version, self.hex8)
    }

    /// The Socket repository path (mirror target and index url path).
    pub fn repo_path(&self) -> String {
        format!("/patch-registry/maven/{}/{}/maven2", self.token, self.uuid)
    }

    pub fn prod_index_url(&self) -> String {
        format!("https://patch.socket.dev{}", self.repo_path())
    }

    /// `<repo>/<g>/<a>/<sfx>/<a>-<sfx>.<ext>` under the Socket repository.
    pub fn served_path(&self, ext: &str) -> String {
        let sfx = self.suffixed();
        format!(
            "{}/{}/{}/{sfx}/{}-{sfx}.{ext}",
            self.repo_path(),
            self.group_path(),
            self.artifact,
            self.artifact
        )
    }

    /// The upstream pom re-versioned to the suffixed version (the project's
    /// own `<version>` right after `</parent>`; the parent and the
    /// dependencies — the transitive — are untouched).
    pub fn served_pom(&self, upstream: &[u8]) -> Vec<u8> {
        let text = String::from_utf8(upstream.to_vec()).expect("utf-8 pom");
        let after_parent = text
            .find("</parent>")
            .expect("the fixture pom has a parent")
            + 9;
        let needle = format!("<version>{}</version>", self.version);
        let at = after_parent + text[after_parent..].find(&needle).expect("project version");
        let mut out = text.clone();
        out.replace_range(
            at..at + needle.len(),
            &format!("<version>{}</version>", self.suffixed()),
        );
        out.into_bytes()
    }
}

pub fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// A wiremock server with its own runtime (the CLI and the build tool run
/// as blocking child processes on the test thread).
pub struct Server {
    pub server: MockServer,
    pub rt: tokio::runtime::Runtime,
}

impl Server {
    pub fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        Server { server, rt }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    pub fn get(&self, route: &str, status: u16, body: Vec<u8>) {
        self.rt.block_on(
            Mock::given(method("GET"))
                .and(path(route.to_string()))
                .respond_with(ResponseTemplate::new(status).set_body_bytes(body))
                .mount(&self.server),
        );
    }

    /// Serve `jar` + `pom` (and `.sha1` sidecars: `jar_sha1` overrides the
    /// jar's) as the Socket repository's suffixed GAV.
    pub fn serve_repo(&self, h: &Hosted, jar: &[u8], pom: &[u8], jar_sha1: Option<String>) {
        self.get(&h.served_path("jar"), 200, jar.to_vec());
        self.get(
            &format!("{}.sha1", h.served_path("jar")),
            200,
            jar_sha1.unwrap_or_else(|| sha1_hex(jar)).into_bytes(),
        );
        self.get(&h.served_path("pom"), 200, pom.to_vec());
        self.get(
            &format!("{}.sha1", h.served_path("pom")),
            200,
            sha1_hex(pom).into_bytes(),
        );
    }

    /// Every request path the server has seen, in order.
    pub fn paths(&self) -> Vec<String> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }
}

/// The API `scan --mode hosted` drives: batch discovery, the by-package
/// listing, the reference grant (maven2 override, production-shaped urls)
/// and the patch view.
pub fn mount_api(s: &Server, h: &Hosted, jar: &[u8], pom: &[u8], view: &serde_json::Value) {
    let purl = h.purl();
    let org = h.org;
    let uuid = h.uuid;
    let artifact_url = format!(
        "https://patch.socket.dev/patch/maven/{}/{}/{}/{}/{uuid}/{}-{}.jar",
        h.group,
        h.artifact,
        h.version,
        h.token,
        h.artifact,
        h.suffixed()
    );
    let mounts = [
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{org}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [{ "purl": purl, "patches": [{
                    "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [h.cve],
                    "ghsaIds": [h.ghsa], "severity": "high", "title": h.title
                }] }],
                "canAccessPaidPatches": false,
            }))),
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{org}/patches/by-package/.+$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": uuid, "purl": purl, "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "d", "license": "MIT", "tier": "free",
                    "vulnerabilities": view["vulnerabilities"].clone()
                }],
                "canAccessPaidPatches": false,
            }))),
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{org}/patches/package")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { uuid: {
                    "status": "granted",
                    "url": artifact_url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": artifact_url,
                        "integrity": { "sha1": sha1_hex(jar), "sha256": sha256_hex(jar) }
                    }],
                    "registryOverride": {
                        "kind": "maven2",
                        "indexUrl": h.prod_index_url(),
                        "identifiers": {
                            "name": format!("{}/{}", h.group, h.artifact),
                            "version": h.version,
                            "mavenGroupId": h.group,
                            "mavenArtifactId": h.artifact,
                            "mavenSuffixedVersion": h.suffixed(),
                            "mavenPomSha256": sha256_hex(pom),
                        }
                    }
                } }
            }))),
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{org}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view.clone())),
    ];
    for m in mounts {
        s.rt.block_on(m.mount(&s.server));
    }
}
