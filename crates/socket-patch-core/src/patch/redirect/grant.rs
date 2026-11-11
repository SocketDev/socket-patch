//! The shape gate between a reference grant and the rewriters.
//!
//! A grant is whatever the patch API answered: Socket's, a `--api-url`
//! server's, or a proxy's in between. The rewriters splice its fields into
//! files the user commits and their package manager then trusts — unquoted
//! line grammars (`yarn.lock`, `Gemfile.lock`, `go.sum`,
//! `requirements.txt`), quoted strings (TOML, JSON, YAML, Ruby, Groovy,
//! Scala) and XML element text (`pom.xml`) — and into the snippets a
//! refusal asks the user to paste. [`check`] holds every field of the
//! override built from a grant to a shape all of those take verbatim, so no
//! rewriter has to ask whether a value can end the string, line or element
//! it lands in. The hosted engine runs it before a grant becomes a
//! candidate (`hosted::engine::build_candidates`); a grant that fails is
//! never handed to a rewriter.
//!
//! A digest is held to the shape its lockfile writes: hex of the
//! algorithm's length, one SRI token, an `h1:` hash. A Maven grant's sha256
//! digests are only held to the digest alphabet: the pom, Gradle and sbt
//! planners each accept a `sha256-` / `sha256:` spelling and write no
//! checksum pin for anything else.

use crate::formats::gem::is_plain_gem_token;
use crate::origin::on_configured_origin;
use crate::patch::path_safety::{
    is_canonical_uuid, is_safe_multi_segment, is_safe_name_version, is_safe_single_segment,
};
use crate::utils::digest::is_hex;
use crate::vendor::go_sum_edit::is_h1_dirhash;
use crate::vendor::jvm::layout::safe_coordinates;
use crate::vendor::nuget_feed::is_plain_nuget_token;

use super::{DepOverride, Integrity, RegistryOverride};

/// Why [`check`] refuses a grant. Each carries the sentence fragment that
/// names the field (`its sha1 is not 40 hex digits`), never the field's
/// value: that is the server's text, and a URL carries the grant token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Flaw {
    /// A field is not in the shape the project's files take verbatim.
    Malformed(String),
    /// A URL is plain `http` on an origin that is neither loopback nor a
    /// configured patch server.
    InsecureUrl(String),
}

/// The refusal of a field that is not `shape`.
fn bad(what: &str, shape: &str) -> Flaw {
    Flaw::Malformed(format!("its {what} is not {shape}"))
}

/// Bound on a coordinate (a name, a version, a module path).
const MAX_COORDINATE: usize = 512;
/// Bound on a digest in any spelling (an SRI sha512 is 95 bytes).
const MAX_DIGEST: usize = 256;
/// Bound on a URL.
const MAX_URL: usize = 2048;

/// `s` is non-empty and holds only ASCII letters, digits and `extra`.
fn plain(s: &str, extra: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_COORDINATE
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

/// One token of the digest alphabet (hex, base64, an `algo-` / `algo:`
/// prefix): the bound on a digest no rewriter writes verbatim.
fn is_digest_token(s: &str) -> bool {
    s.len() <= MAX_DIGEST && plain(s, "+/=:_-")
}

/// Exactly one SRI `sha512-<base64>` token (either base64 alphabet). An SRI
/// string may list several hashes separated by whitespace, and the tarball
/// check reads the first it knows, so anything after one would be written
/// unverified.
fn is_sha512_sri(s: &str) -> bool {
    s.len() <= MAX_DIGEST
        && s.strip_prefix("sha512-").is_some_and(|b64| {
            let digits = b64.trim_end_matches('=');
            b64.len() - digits.len() <= 2 && plain(digits, "+/-_")
        })
}

/// A yarn berry checksum in either lock spelling: `<cache key>/<sha512
/// hex>` or the bare hex.
fn is_berry_checksum(s: &str) -> bool {
    let hex = match s.split_once('/') {
        Some((key, hex)) if plain(key, "") => hex,
        Some(_) => return false,
        None => s,
    };
    is_hex(hex, 128)
}

/// The characters a URL may hold: the RFC 3986 set less the ones that end
/// or reopen a string, line or element somewhere a URL is written — quotes
/// and the backslash, `$` `{` `}` (interpolation in Groovy, Kotlin, Scala,
/// Ruby and `.npmrc`), `<` `>` `&` (XML), `#` (a fragment: the locks append
/// their own `#<sha1>` / `#sha256=`), and `;` `|` `^`. Whitespace, control
/// characters and anything outside ASCII are never URL characters.
fn is_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-._~:/?[]@!()*+,=%".contains(c)
}

/// Whether `url`'s host is the local machine, where a plain-`http` request
/// never crosses a network.
fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host == "localhost"
        || host.ends_with(".localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `url` (the grant's `what`) as a lockfile takes it: an `https` URL of
/// [`is_url_char`]s with a host. Plain `http` is taken only from the local
/// machine or from one of `origins`, the operator's own patch servers
/// (`--patch-server-url`): anywhere else every later install would send
/// the grant token in the URL in clear text.
fn check_url(what: &str, url: &str, origins: &[String]) -> Result<(), Flaw> {
    let malformed = || bad(what, "a plain http(s) URL");
    if url.len() > MAX_URL
        || !(url.starts_with("https://") || url.starts_with("http://"))
        || !url.chars().all(is_url_char)
    {
        return Err(malformed());
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| malformed())?;
    let Some(host) = parsed.host_str() else {
        return Err(malformed());
    };
    if parsed.scheme() == "https" || is_loopback(&parsed) || on_configured_origin(&parsed, origins)
    {
        return Ok(());
    }
    let host = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Err(Flaw::InsecureUrl(format!(
        "its {what} is plain http on {host}, which is neither the configured patch server \
         (`--patch-server-url`) nor a loopback address"
    )))
}

/// Whether `name` and `version` are in `ecosystem`'s coordinate grammar:
/// what its lockfiles, manifests and registry paths spell without quoting.
/// Each arm is the ecosystem's own path guard plus its character set.
fn coordinates_ok(ecosystem: &str, name: &str, version: &str) -> bool {
    match ecosystem {
        "npm" => {
            crate::vendor::is_safe_npm_name(name)
                && plain(name.strip_prefix('@').unwrap_or(name), "/._~-")
                && is_safe_single_segment(version)
                && plain(version, ".+-")
        }
        // A PEP 440 version may carry an epoch (`1!2.0`) and a local
        // segment (`+cu118`).
        "pypi" => {
            is_safe_name_version(name, version) && plain(name, "._-") && plain(version, ".+!_-")
        }
        "gem" => {
            is_safe_name_version(name, version)
                && is_plain_gem_token(name)
                && is_plain_gem_token(version)
        }
        "cargo" => {
            is_safe_name_version(name, version) && plain(name, "_-") && plain(version, ".+-")
        }
        "nuget" => {
            is_safe_name_version(name, version)
                && is_plain_nuget_token(name)
                && is_plain_nuget_token(version)
        }
        "golang" => go_module_ok(name, version),
        "composer" => name.split_once('/').is_some_and(|(vendor, package)| {
            is_safe_name_version(vendor, package)
                && plain(vendor, "._-")
                && plain(package, "._-")
                && is_safe_single_segment(version)
                && plain(version, ".+_-")
        }),
        "maven" => name
            .split_once('/')
            .is_some_and(|(group, artifact)| safe_coordinates(group, artifact, version)),
        // No rewriter takes any other ecosystem; the bound is the union.
        _ => {
            is_safe_multi_segment(name)
                && plain(name.strip_prefix('@').unwrap_or(name), "/._~-")
                && is_safe_single_segment(version)
                && plain(version, ".+!_-")
        }
    }
}

/// A Go module path and version: the two tokens of a `go.mod` / `go.sum`
/// line.
fn go_module_ok(module: &str, version: &str) -> bool {
    is_safe_multi_segment(module)
        && plain(module, "/._~-")
        && is_safe_single_segment(version)
        && plain(version, ".+-")
}

/// A present, non-empty optional field. An empty string is what the
/// rewriters already read as "not served".
fn served(field: &Option<String>) -> Option<&str> {
    field.as_deref().filter(|s| !s.is_empty())
}

fn check_integrity(integrity: &Integrity, ecosystem: &str) -> Result<(), Flaw> {
    let Integrity {
        sha512,
        sha256,
        sha1,
        md5,
        dirhash_h1,
        go_mod_h1,
        yarn_berry10c0,
    } = integrity;
    if served(sha512).is_some_and(|s| !is_sha512_sri(s)) {
        return Err(bad("sha512", "one `sha512-<base64>` token"));
    }
    match (served(sha256), ecosystem) {
        (Some(s), "maven") if !is_digest_token(s) => return Err(bad("sha256", "a sha256 digest")),
        (Some(s), eco) if eco != "maven" && !is_hex(s, 64) => {
            return Err(bad("sha256", "64 hex digits"))
        }
        _ => {}
    }
    if served(sha1).is_some_and(|s| !is_hex(s, 40)) {
        return Err(bad("sha1", "40 hex digits"));
    }
    if served(md5).is_some_and(|s| !is_digest_token(s)) {
        return Err(bad("md5", "a digest"));
    }
    for (what, hash) in [("dirhash", dirhash_h1), ("go.mod hash", go_mod_h1)] {
        if served(hash).is_some_and(|s| !is_h1_dirhash(s)) {
            return Err(bad(what, "an `h1:` hash"));
        }
    }
    if served(yarn_berry10c0).is_some_and(|s| !is_berry_checksum(s)) {
        return Err(bad("yarn berry checksum", "a `10c0/<sha512 hex>` checksum"));
    }
    Ok(())
}

fn check_registry_override(ov: &RegistryOverride, origins: &[String]) -> Result<(), Flaw> {
    if !plain(&ov.kind, "-_") {
        return Err(bad("registry kind", "a plain word"));
    }
    // Cargo names its sparse index `sparse+<url>`.
    let index_url = match ov.kind.as_str() {
        "cargo-sparse" => ov
            .index_url
            .strip_prefix("sparse+")
            .unwrap_or(&ov.index_url),
        _ => &ov.index_url,
    };
    check_url("registry index URL", index_url, origins)?;

    let ids = &ov.identifiers;
    // The package's own spelling in its registry; no rewriter writes it.
    if !ids.name.is_empty() && !plain(&ids.name, "@/:._~+-") {
        return Err(bad("registry name", "a plain package name"));
    }
    if !ids.version.is_empty() && !plain(&ids.version, ".+!_~-") {
        return Err(bad("registry version", "a plain version"));
    }
    for (what, digest) in [
        ("cargo checksum", &ids.cargo_cksum_sha256),
        ("gem checksum", &ids.gem_checksum_sha256),
    ] {
        if served(digest).is_some_and(|s| !is_hex(s, 64)) {
            return Err(bad(what, "64 hex digits"));
        }
    }
    for (what, digest) in [
        ("Maven pom sha256", &ids.maven_pom_sha256),
        ("Maven module sha256", &ids.maven_module_sha256),
    ] {
        if served(digest).is_some_and(|s| !is_digest_token(s)) {
            return Err(bad(what, "a sha256 digest"));
        }
    }
    for (what, hash) in [
        ("Go zip hash", &ids.go_zip_dirhash_h1),
        ("go.mod hash", &ids.go_mod_h1),
    ] {
        if served(hash).is_some_and(|s| !is_h1_dirhash(s)) {
            return Err(bad(what, "an `h1:` hash"));
        }
    }
    if served(&ids.go_module_path).is_some_and(|s| !go_module_ok(s, "v0"))
        || served(&ids.go_module_version).is_some_and(|s| !go_module_ok("m", s))
    {
        return Err(bad("Go module", "a plain module path and version"));
    }
    if served(&ids.nuget_id_lower).is_some_and(|s| !is_plain_nuget_token(s))
        || served(&ids.nuget_version_norm).is_some_and(|s| !is_plain_nuget_token(s))
    {
        return Err(bad("NuGet id or version", "a plain NuGet token"));
    }
    // Each Maven coordinate on its own, against the JVM backends' grammar.
    for (what, ok) in [
        (
            "Maven group id",
            served(&ids.maven_group_id).is_none_or(|g| safe_coordinates(g, "a", "1")),
        ),
        (
            "Maven artifact id",
            served(&ids.maven_artifact_id).is_none_or(|a| safe_coordinates("g", a, "1")),
        ),
        (
            "Maven suffixed version",
            served(&ids.maven_suffixed_version).is_none_or(|v| safe_coordinates("g", "a", v)),
        ),
    ] {
        if !ok {
            return Err(bad(what, "a plain Maven coordinate"));
        }
    }
    Ok(())
}

/// Whether every field of `dep`, the override built from one grant, has
/// the shape the rewriters write verbatim. `patch_server_origins` are the
/// operator's own patch servers, whose plain-`http` URLs are accepted.
pub(crate) fn check(dep: &DepOverride, patch_server_origins: &[String]) -> Result<(), Flaw> {
    // The uuid names the Socket registry, repository and source a pin is
    // written under (`socket-patch-<uuid>`).
    if !is_canonical_uuid(&dep.patch_uuid) {
        return Err(bad("patch uuid", "a canonical lowercase uuid"));
    }
    if !plain(&dep.ecosystem, "-_.") {
        return Err(bad("package type", "a plain word"));
    }
    if !coordinates_ok(&dep.ecosystem, &dep.name, &dep.version) {
        return Err(bad(
            "package name or version",
            &format!("a plain {} name and version", dep.ecosystem),
        ));
    }
    check_url("artifact URL", &dep.artifact_url, patch_server_origins)?;
    check_integrity(&dep.integrity, &dep.ecosystem)?;
    if let Some(ov) = &dep.registry_override {
        check_registry_override(ov, patch_server_origins)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::redirect::RegistryOverrideIdentifiers;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const SRI: &str =
        "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==";

    /// A well-formed npm grant.
    fn npm() -> DepOverride {
        DepOverride {
            ecosystem: "npm".into(),
            name: "left-pad".into(),
            namespace: None,
            version: "1.3.0".into(),
            token: "tok".into(),
            patch_uuid: UUID.into(),
            artifact_url: format!(
                "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/{UUID}/left-pad-1.3.0.tgz"
            ),
            registry_override: None,
            integrity: Integrity {
                sha512: Some(SRI.into()),
                sha256: Some("a".repeat(64)),
                sha1: Some("b".repeat(40)),
                md5: Some("c".repeat(32)),
                yarn_berry10c0: Some(format!("10c0/{}", "d".repeat(128))),
                ..Default::default()
            },
        }
    }

    /// A well-formed maven grant with its `maven2` override.
    fn maven() -> DepOverride {
        DepOverride {
            ecosystem: "maven".into(),
            name: "org.apache.commons/commons-lang3".into(),
            version: "3.12.0".into(),
            artifact_url: format!(
                "https://patch.socket.dev/patch/maven/org.apache.commons/commons-lang3/3.12.0/tok/{UUID}/commons-lang3-3.12.0-socket.9f6b2c4e.jar"
            ),
            registry_override: Some(RegistryOverride {
                kind: "maven2".into(),
                index_url: format!(
                    "https://patch.socket.dev/patch-registry/maven/tok/{UUID}/maven2"
                ),
                identifiers: RegistryOverrideIdentifiers {
                    name: "org.apache.commons/commons-lang3".into(),
                    version: "3.12.0".into(),
                    maven_group_id: Some("org.apache.commons".into()),
                    maven_artifact_id: Some("commons-lang3".into()),
                    maven_suffixed_version: Some("3.12.0-socket.9f6b2c4e".into()),
                    maven_pom_sha256: Some("e".repeat(64)),
                    ..Default::default()
                },
            }),
            integrity: Integrity {
                sha256: Some("f".repeat(64)),
                ..Default::default()
            },
            ..npm()
        }
    }

    fn malformed(dep: &DepOverride) -> String {
        match check(dep, &[]) {
            Err(Flaw::Malformed(reason)) => reason,
            other => panic!("expected a malformed grant, got {other:?}"),
        }
    }

    #[test]
    fn well_formed_grants_pass() {
        assert_eq!(check(&npm(), &[]), Ok(()));
        assert_eq!(check(&maven(), &[]), Ok(()));
        let scoped = DepOverride {
            name: "@scope/pkg".into(),
            version: "2.0.0-rc.1+build.5".into(),
            artifact_url: "https://patch.socket.dev/patch/npm/@scope/pkg/2.0.0/t/u/pkg-2.0.0.tgz"
                .into(),
            ..npm()
        };
        assert_eq!(check(&scoped, &[]), Ok(()));
        for (ecosystem, name, version) in [
            ("pypi", "Flask_Cors", "1!2.0.post1+cu118"),
            ("gem", "nokogiri", "1.16.5-x86_64-linux"),
            ("cargo", "serde_json", "1.0.190+wasi-0.2"),
            ("nuget", "Newtonsoft.Json", "13.0.3"),
            (
                "golang",
                "github.com/BurntSushi/toml",
                "v0.0.0-20240101000000-abcdef012345",
            ),
            ("composer", "monolog/monolog", "v3.5.0"),
        ] {
            let dep = DepOverride {
                ecosystem: ecosystem.into(),
                name: name.into(),
                version: version.into(),
                ..npm()
            };
            assert_eq!(check(&dep, &[]), Ok(()), "{ecosystem} {name}@{version}");
        }
    }

    /// The fields the server may leave out, or send empty, are not held to
    /// a shape they do not have.
    #[test]
    fn absent_and_empty_fields_pass() {
        let mut dep = npm();
        dep.integrity = Integrity {
            sha512: Some(SRI.into()),
            sha256: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(check(&dep, &[]), Ok(()));
        let mut dep = maven();
        let ids = &mut dep.registry_override.as_mut().unwrap().identifiers;
        ids.maven_suffixed_version = None;
        ids.maven_pom_sha256 = Some(String::new());
        ids.name = String::new();
        assert_eq!(check(&dep, &[]), Ok(()));
    }

    /// Every injection the audit reproduced, at the field it rode in on.
    #[test]
    fn injected_fields_are_named() {
        type Edit = fn(&mut DepOverride);
        let cases: [(&str, Edit); 13] = [
            ("sha1", |d| {
                d.integrity.sha1 = Some(format!(
                    "{}\"\n  evil-injected-field \"pwned",
                    "b".repeat(40)
                ))
            }),
            ("sha512", |d| {
                d.integrity.sha512 = Some(format!("{SRI}\n  injected-by-integrity \"x\""))
            }),
            ("sha512", |d| {
                d.integrity.sha512 = Some(format!("{SRI} {SRI}"))
            }),
            ("sha256", |d| {
                d.integrity.sha256 = Some(format!("{} --index-url=x", "a".repeat(64)))
            }),
            ("yarn berry checksum", |d| {
                d.integrity.yarn_berry10c0 = Some("10c0/abc\n  bin: evil".into())
            }),
            ("artifact URL", |d| d.artifact_url.push_str("?x=${1}y")),
            ("artifact URL", |d| d.artifact_url.push_str("\"\n")),
            ("artifact URL", |d| {
                d.artifact_url = "file:///etc/passwd".into()
            }),
            ("artifact URL", |d| {
                d.artifact_url = d.artifact_url.replace("https://", "HTTPS://")
            }),
            ("patch uuid", |d| d.patch_uuid = "u1".into()),
            ("patch uuid", |d| d.patch_uuid = UUID.to_uppercase()),
            ("package name or version", |d| {
                d.name = "left-pad\n  evil".into()
            }),
            ("package name or version", |d| {
                d.version = "1.3.0\" x=\"".into()
            }),
        ];
        for (field, edit) in cases {
            let mut dep = npm();
            edit(&mut dep);
            let reason = malformed(&dep);
            assert!(reason.starts_with(&format!("its {field} ")), "{reason}");
            assert!(
                !reason.chars().any(char::is_control) && !reason.contains("pwned"),
                "the reason never echoes the value: {reason:?}"
            );
        }
    }

    #[test]
    fn registry_override_fields_are_named() {
        type Edit = fn(&mut RegistryOverride);
        let cases: [(&str, Edit); 9] = [
            ("Maven suffixed version", |ov| {
                ov.identifiers.maven_suffixed_version =
                    Some("3.12.0-socket.9f6b2c4e</version><scope>system</scope><version>x".into())
            }),
            ("Maven group id", |ov| {
                ov.identifiers.maven_group_id = Some("org.other</dependency>".into())
            }),
            ("Maven artifact id", |ov| {
                ov.identifiers.maven_artifact_id = Some("commons-lang3'\n".into())
            }),
            ("registry index URL", |ov| {
                ov.index_url.push_str("?a=1&b=2</url><!-- injected -->")
            }),
            ("registry index URL", |ov| ov.index_url = String::new()),
            ("registry index URL", |ov| {
                ov.index_url = format!("sparse+{}", ov.index_url)
            }),
            ("Maven pom sha256", |ov| {
                ov.identifiers.maven_pom_sha256 = Some("e e".into())
            }),
            ("gem checksum", |ov| {
                ov.identifiers.gem_checksum_sha256 = Some(format!(
                    "dead${{1}}beef\n  evilgem (6.6.6) sha256={}",
                    "f".repeat(64)
                ))
            }),
            ("registry kind", |ov| ov.kind = "maven2\n".into()),
        ];
        for (field, edit) in cases {
            let mut dep = maven();
            edit(dep.registry_override.as_mut().unwrap());
            let reason = malformed(&dep);
            assert!(reason.starts_with(&format!("its {field} ")), "{reason}");
        }
        // The sparse prefix is cargo's.
        let mut cargo = DepOverride {
            ecosystem: "cargo".into(),
            name: "serde".into(),
            version: "1.0.190".into(),
            ..maven()
        };
        let ov = cargo.registry_override.as_mut().unwrap();
        ov.kind = "cargo-sparse".into();
        ov.index_url = format!("sparse+https://patch.socket.dev/patch-registry/cargo/{UUID}/");
        ov.identifiers = RegistryOverrideIdentifiers {
            cargo_cksum_sha256: Some("1".repeat(64)),
            ..Default::default()
        };
        assert_eq!(check(&cargo, &[]), Ok(()));
    }

    /// The Maven planners decide what a sha256 in another spelling means
    /// (no checksum pin); every other ecosystem writes it as it comes.
    #[test]
    fn only_maven_takes_a_sha256_in_another_spelling() {
        for spelling in [
            format!("sha256-{}", "f".repeat(64)),
            "sha256-q83vEjRWeJA=".to_string(),
        ] {
            let mut dep = maven();
            dep.integrity.sha256 = Some(spelling.clone());
            assert_eq!(check(&dep, &[]), Ok(()), "{spelling}");
            let mut dep = npm();
            dep.integrity.sha256 = Some(spelling.clone());
            assert!(malformed(&dep).starts_with("its sha256 "), "{spelling}");
        }
    }

    #[test]
    fn plain_http_is_taken_from_loopback_and_configured_origins_only() {
        let at = |origin: &str| DepOverride {
            artifact_url: format!(
                "{origin}/patch/npm/left-pad/1.3.0/tok/{UUID}/left-pad-1.3.0.tgz"
            ),
            ..npm()
        };
        for loopback in [
            "http://127.0.0.1:39217",
            "http://localhost:8080",
            "http://[::1]:8080",
            "http://alice:s3cret@127.0.0.1:1",
        ] {
            assert_eq!(check(&at(loopback), &[]), Ok(()), "{loopback}");
        }
        let configured = ["http://patch.internal:8080".to_string()];
        assert_eq!(
            check(&at("http://patch.internal:8080"), &configured),
            Ok(())
        );

        for (origin, host) in [
            ("http://patch.test", "patch.test"),
            ("http://patch.internal:8081", "patch.internal:8081"),
            // The host after the userinfo is the one that counts.
            ("http://127.0.0.1@evil.example", "evil.example"),
            ("http://localhost.evil.example", "localhost.evil.example"),
        ] {
            let Err(Flaw::InsecureUrl(reason)) = check(&at(origin), &configured) else {
                panic!("{origin} must be refused as insecure");
            };
            assert!(
                reason.starts_with(&format!("its artifact URL is plain http on {host},")),
                "{reason}"
            );
            assert!(!reason.contains("tok"), "no token: {reason}");
        }

        // The index URL is held to the same rule.
        let mut dep = maven();
        let ov = dep.registry_override.as_mut().unwrap();
        ov.index_url = ov.index_url.replace("https://", "http://");
        assert!(matches!(check(&dep, &[]), Err(Flaw::InsecureUrl(reason))
                if reason.starts_with("its registry index URL is plain http on patch.socket.dev,")),);
    }
}
