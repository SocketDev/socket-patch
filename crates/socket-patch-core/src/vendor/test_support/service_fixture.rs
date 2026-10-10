//! Archive fixtures for tests of download, verification, wiring and rollback.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, PatchSources};
use crate::utils::purl::{
    parse_cargo_purl, parse_gem_purl, parse_golang_purl, parse_maven_purl, parse_nuget_purl,
    parse_pypi_purl,
};
use crate::vendor::source::PackageSource;
use crate::vendor::{VendorServiceConfig, VendorSource};

pub struct Fixture {
    _server: MockServer,
    maven_registry: Option<Option<std::ffi::OsString>>,
    pub cfg: VendorServiceConfig,
}

impl Fixture {
    pub async fn new(
        purl: &str,
        source: PackageSource<'_>,
        record: &PatchRecord,
        sources: &PatchSources<'_>,
    ) -> Self {
        let server = MockServer::start().await;
        let maven_registry = if let Some((g, a, v)) = parse_maven_purl(purl) {
            for ext in ["jar", "pom", "module"] {
                if let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(
                    &source.path().join(format!("{a}-{v}.{ext}")),
                )
                .await
                {
                    let url = format!("/{}/{a}/{v}/{a}-{v}.{ext}", g.replace('.', "/"));
                    Mock::given(method("GET"))
                        .and(path(format!("{url}.sha1")))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .set_body_string(hex::encode(sha1::Sha1::digest(&bytes))),
                        )
                        .mount(&server)
                        .await;
                    Mock::given(method("GET"))
                        .and(path(format!("{url}.sha256")))
                        .respond_with(
                            ResponseTemplate::new(200)
                                .set_body_string(hex::encode(Sha256::digest(&bytes))),
                        )
                        .mount(&server)
                        .await;
                    Mock::given(method("GET"))
                        .and(path(url))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                        .mount(&server)
                        .await;
                }
            }
            let old = std::env::var_os("SOCKET_MAVEN_REGISTRY");
            std::env::set_var("SOCKET_MAVEN_REGISTRY", server.uri());
            Some(old)
        } else {
            None
        };
        match archive(purl, source.path(), record, sources).await {
            Ok((leaf, bytes, secondary)) => {
                let uri = server.uri();
                let url = format!("{uri}/archive/{leaf}");
                let mut artifacts = vec![
                    serde_json::json!({"kind":"tarball", "url":url, "integrity":{"sha512":super::sri(&bytes)}}),
                ];
                if purl.starts_with("pkg:npm/") {
                    let name = crate::vendor::npm_common::parse_npm_purl(purl)
                        .map(|p| p.0)
                        .unwrap_or_default();
                    if let Ok(checksum) =
                        crate::vendor::berry_zip::berry_cache_checksum_10c0(&bytes, &name)
                    {
                        artifacts.push(serde_json::json!({"kind":"yarn-berry-zip", "integrity":{"yarnBerry10c0":checksum}}));
                    }
                }
                for (kind, name, bytes) in secondary {
                    artifacts.push(serde_json::json!({"kind":kind,"url":format!("{uri}/archive/{name}"),"integrity":{"sha512":super::sri(&bytes)}}));
                    Mock::given(method("GET"))
                        .and(path(format!("/archive/{name}")))
                        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                        .mount(&server)
                        .await;
                }
                Mock::given(method("POST")).and(path(super::PACKAGE_PATH)).respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"results":{ &record.uuid: {"status":"granted", "purl":purl, "url":url, "artifacts":artifacts}}}))).mount(&server).await;
                Mock::given(method("GET"))
                    .and(path(format!("/archive/{leaf}")))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                    .mount(&server)
                    .await;
            }
            Err(_) => super::mount_no_results(&server).await,
        }
        Self {
            cfg: super::service_cfg(&server.uri(), VendorSource::Service, false),
            _server: server,
            maven_registry,
        }
    }
}

pub type Secondary = Vec<(&'static str, String, Vec<u8>)>;

pub async fn archive(
    purl: &str,
    dir: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
) -> Result<(String, Vec<u8>, Secondary), String> {
    if purl.contains("..") || purl.contains('\\') {
        return Err("unsafe fixture coordinate".into());
    }
    let mut members = BTreeMap::new();
    if let Some((_, artifact, version)) = parse_maven_purl(purl) {
        let bytes =
            crate::utils::fs::read_regular_to_bytes(&dir.join(format!("{artifact}-{version}.jar")))
                .await
                .map_err(|e| e.to_string())?;
        members.extend(crate::vendor::verify::read_zip_bytes_to_map(&bytes)?);
    } else if let Some((name, version)) = parse_nuget_purl(purl) {
        let bytes = crate::utils::fs::read_regular_to_bytes(&dir.join(format!(
            "{}.{}.nupkg",
            name.to_lowercase(),
            version
        )))
        .await
        .map_err(|e| e.to_string())?;
        members.extend(crate::vendor::verify::read_zip_bytes_to_map(&bytes)?);
    } else {
        for entry in walkdir::WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| e.file_name() != "node_modules" && e.file_name() != ".git")
        {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().is_file() {
                let path = entry
                    .path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                members.insert(
                    path,
                    tokio::fs::read(entry.path())
                        .await
                        .map_err(|e| e.to_string())?,
                );
            }
        }
    }
    for (path, info) in &record.files {
        let bytes = match sources
            .mem_blobs
            .and_then(|blobs| blobs.get(&info.after_hash))
            .cloned()
        {
            Some(bytes) => bytes,
            None => tokio::fs::read(sources.blobs_path.join(&info.after_hash))
                .await
                .map_err(|e| e.to_string())?,
        };
        members.insert(normalize_file_path(path).to_string(), bytes);
    }
    if let Some((name, version)) = parse_pypi_purl(purl) {
        let name = crate::crawlers::python_crawler::canonicalize_pypi_name(&name).replace('-', "_");
        let version = crate::vendor::pypi_wheel::escape_wheel_version(&version);
        let dist_info = members
            .keys()
            .find(|k| k.ends_with(".dist-info/WHEEL") && k.starts_with(&format!("{name}-")))
            .and_then(|k| k.rsplit_once('/'))
            .map(|(d, _)| d.to_string())
            .unwrap_or_else(|| format!("{name}-{version}.dist-info"));
        if let Some(installed_record) = members.get(&format!("{dist_info}/RECORD")) {
            let mut package_files: std::collections::BTreeSet<String> =
                String::from_utf8_lossy(installed_record)
                    .lines()
                    .filter_map(|line| line.split(',').next())
                    .map(str::to_string)
                    .collect();
            package_files.extend(
                record
                    .files
                    .keys()
                    .map(|path| normalize_file_path(path).to_string()),
            );
            members.retain(|path, _| {
                package_files.contains(path) || path.starts_with(&format!("{dist_info}/"))
            });
        }
        let wheel = members
            .get(&format!("{dist_info}/WHEEL"))
            .ok_or("fixture has no WHEEL")?;
        let mut tags: [std::collections::BTreeSet<&str>; 3] = Default::default();
        for tag in std::str::from_utf8(wheel)
            .map_err(|e| e.to_string())?
            .lines()
            .filter_map(|l| l.strip_prefix("Tag: "))
        {
            for (i, value) in tag.trim().split('-').take(3).enumerate() {
                tags[i].insert(value);
            }
        }
        let tag = tags
            .map(|values| values.into_iter().collect::<Vec<_>>().join("."))
            .join("-");
        let record = format!("{dist_info}/RECORD");
        members.remove(&record);
        let mut rows = String::new();
        for (path, bytes) in &members {
            rows.push_str(&format!(
                "{path},sha256={},{}\n",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
                bytes.len()
            ));
        }
        rows.push_str(&format!("{record},,\n"));
        members.insert(record, rows.into_bytes());
        return Ok((
            format!("{name}-{version}-{tag}.whl"),
            zip(&members, ""),
            Vec::new(),
        ));
    }
    if let Some((name, version)) = crate::vendor::npm_common::parse_npm_purl(purl) {
        return Ok((
            format!("{}-{version}.tgz", name.replace('/', "-")),
            tgz(&members, "package/"),
            Vec::new(),
        ));
    }
    if let Some((name, version)) = parse_cargo_purl(purl) {
        return Ok((
            format!("{name}-{version}.crate"),
            tgz(&members, &format!("{name}-{version}/")),
            Vec::new(),
        ));
    }
    if let Some((module, version)) = parse_golang_purl(purl) {
        return Ok((
            format!("{version}.zip"),
            zip(&members, &format!("{module}@{version}/")),
            Vec::new(),
        ));
    }
    if let Some((name, version)) = parse_gem_purl(purl) {
        let stub = dir.parent().and_then(Path::parent).map(|home| {
            home.join("specifications")
                .join(format!("{name}-{version}.gemspec"))
        });
        let stub = match stub { Some(path) => tokio::fs::read(path).await.ok(), None => None }.unwrap_or_else(||format!("Gem::Specification.new do |s|\n  s.name = {name:?}\n  s.version = {version:?}\n  s.summary = 'fixture'\n  s.authors = ['fixture']\nend\n").into_bytes());
        let outer = BTreeMap::from([("data.tar.gz".into(), tgz(&members, ""))]);
        return Ok((
            format!("{name}-{version}.gem"),
            tar(&outer, ""),
            vec![("gem-stub-gemspec", format!("{name}.gemspec"), stub)],
        ));
    }
    if let Some((_, artifact, version)) = parse_maven_purl(purl) {
        members.retain(|name, _| !crate::vendor::jvm::is_signature(name));
        return Ok((
            format!("{artifact}-{version}.jar"),
            zip(&members, ""),
            Vec::new(),
        ));
    }
    if let Some((name, version)) = parse_nuget_purl(purl) {
        members.retain(|name, _| {
            !name.ends_with(".nupkg")
                && !name.eq_ignore_ascii_case(".signature.p7s")
                && name != ".nupkg.metadata"
        });
        return Ok((
            format!("{name}.{version}.nupkg"),
            zip(&members, ""),
            Vec::new(),
        ));
    }
    Ok(("dist.zip".into(), zip(&members, "package/"), Vec::new()))
}

fn zip(members: &BTreeMap<String, Vec<u8>>, prefix: &str) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, bytes) in members {
        archive
            .start_file(
                format!("{prefix}{name}"),
                zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(0o644),
            )
            .unwrap();
        archive.write_all(bytes).unwrap();
    }
    archive.finish().unwrap().into_inner()
}

fn tar(members: &BTreeMap<String, Vec<u8>>, prefix: &str) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    for (name, bytes) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, format!("{prefix}{name}"), bytes.as_slice())
            .unwrap();
    }
    archive.into_inner().unwrap()
}

fn tgz(members: &BTreeMap<String, Vec<u8>>, prefix: &str) -> Vec<u8> {
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar(members, prefix)).unwrap();
    gzip.finish().unwrap()
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(old) = &self.maven_registry {
            match old {
                Some(value) => std::env::set_var("SOCKET_MAVEN_REGISTRY", value),
                None => std::env::remove_var("SOCKET_MAVEN_REGISTRY"),
            }
        }
    }
}

/// Test oracle only; production vendoring consumes the server checksum.
pub fn berry_checksum(bytes: &[u8], name: &str) -> Option<String> {
    crate::vendor::berry_zip::berry_cache_checksum_10c0(bytes, name).ok()
}
