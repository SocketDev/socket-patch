//! Emulation of `files.pythonhosted.org`: the wheels and sdists of a
//! committed tree (`<tree>/<project>/<file>`), each served under a
//! production-shaped URL, so a requirements file or a `uv.lock` in a
//! fixture names the host a real project names.
//!
//! The bytes are committed, never built by the test: a hashed lock pins
//! their digest, and a wheel rebuilt by another zip library would not
//! reproduce it.

use std::path::Path;

use sha2::{Digest, Sha256};

use super::super::fixture_server::FixtureServer;

pub const HOST: &str = "files.pythonhosted.org";

/// One wheel or sdist of the tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Distribution {
    /// The PEP 503 normalized project name.
    pub project: String,
    pub file: String,
    /// Hex sha256 of `bytes`: what `--hash=sha256:` and a `uv.lock` pin.
    pub sha256: String,
    pub bytes: Vec<u8>,
}

impl Distribution {
    /// `Err` for a file name that is not a wheel or an sdist: the index
    /// could not say which project it belongs to.
    pub fn new(file: &str, bytes: Vec<u8>) -> Result<Distribution, String> {
        let project =
            project_of(file).ok_or_else(|| format!("{file}: not a wheel or sdist file name"))?;
        Ok(Distribution {
            project,
            file: file.to_string(),
            sha256: hex::encode(Sha256::digest(&bytes)),
            bytes,
        })
    }

    /// Where the file lives, in the layout of the real host:
    /// `packages/<2 hex>/<2 hex>/<60 hex>/<file>`. PyPI derives the three
    /// segments from a BLAKE2b digest; the sha256 stands in for it here,
    /// and no client reads a meaning into them.
    pub fn url(&self) -> String {
        let (a, rest) = self.sha256.split_at(2);
        let (b, c) = rest.split_at(2);
        format!("https://{HOST}/packages/{a}/{b}/{c}/{}", self.file)
    }
}

/// PEP 503: lower case, every run of `-`, `_` and `.` is one `-`.
pub fn normalize(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !out.ends_with('-') {
                out.push('-');
            }
        } else {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The normalized project a distribution file belongs to. A wheel name is
/// `<name>-<version>(-<build>)?-<python>-<abi>-<platform>.whl` and its
/// name part holds no `-`; an sdist is `<name>-<version>.tar.gz` (or
/// `.zip`), where only the last `-` separates the version.
fn project_of(file: &str) -> Option<String> {
    let name = if let Some(stem) = file.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        (parts.len() == 5 || parts.len() == 6).then_some(parts[0])?
    } else {
        let stem = file
            .strip_suffix(".tar.gz")
            .or_else(|| file.strip_suffix(".zip"))?;
        stem.rsplit_once('-')?.0
    };
    (!name.is_empty()).then(|| normalize(name))
}

/// Every distribution under `tree`, sorted by project and file name.
/// `Err` (nothing is served) for a file in the wrong project directory or
/// a file that is no distribution: a tree that drifted must not be half
/// mounted.
pub fn read_tree(tree: &Path) -> Result<Vec<Distribution>, String> {
    let list = |dir: &Path| -> Result<Vec<std::path::PathBuf>, String> {
        let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
        paths.sort();
        Ok(paths)
    };
    let mut distributions = Vec::new();
    for project_dir in list(tree)? {
        let project = project_dir.file_name().unwrap().to_string_lossy();
        for path in list(&project_dir)? {
            let file = path.file_name().unwrap().to_string_lossy();
            let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let distribution = Distribution::new(&file, bytes)?;
            if distribution.project != project {
                return Err(format!(
                    "{}: a file of project {} under {project}/",
                    path.display(),
                    distribution.project
                ));
            }
            distributions.push(distribution);
        }
    }
    Ok(distributions)
}

/// Serve every distribution at its [`Distribution::url`]; returns those
/// URLs, which is what a narrow downloader rewrite lists.
pub fn mount(server: &FixtureServer, distributions: &[Distribution]) -> Vec<String> {
    let serve = |d: &Distribution| {
        server.serve(&d.url(), d.bytes.clone());
        d.url()
    };
    distributions.iter().map(serve).collect()
}

/// `bytes` with one byte in the middle flipped. A tamper never appends:
/// a zip reader stops at the central directory, and gazelle accepted a
/// module zip with a byte added after it.
pub fn tampered(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let middle = out.len() / 2;
    out[middle] ^= 0x01;
    out
}

/// Serve `distribution` with [`tampered`] bytes at its URL, for a tamper
/// twin: the lock still pins the committed digest.
pub fn tamper(server: &FixtureServer, distribution: &Distribution) {
    server.serve(&distribution.url(), tampered(&distribution.bytes));
}

/// One `GET` for `url` (written as a lock writes it, or as a path on the
/// server) the way the downloader rewrite sends it, as (status, body). The
/// registry modules test their routes with it; no HTTP client is needed
/// for a server that answers one request per connection.
pub fn fetch(server: &FixtureServer, url: &str) -> (u16, Vec<u8>) {
    use std::io::{Read, Write};
    let origin = format!("{}/", server.loopback_origin());
    let target = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix(origin.as_str()))
        .unwrap_or(url);
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", server.port())).unwrap();
    write!(stream, "GET /{target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n");
    let split = split.expect("a header block");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = head.split(' ').nth(1).and_then(|code| code.parse().ok());
    (
        status.expect("a status line"),
        response[split + 4..].to_vec(),
    )
}

#[test]
fn pypi_file_names_map_to_normalized_projects() {
    let project = |file: &str| Distribution::new(file, Vec::new()).map(|d| d.project);
    assert_eq!(
        project("spvictim-1.0.0-py3-none-any.whl").unwrap(),
        "spvictim"
    );
    // A wheel escapes `-` in its name to `_`; an sdist may keep it.
    assert_eq!(
        project("Typing_Extensions-4.0-1-py3-none-any.whl").unwrap(),
        "typing-extensions"
    );
    assert_eq!(
        project("python-dateutil-2.9.0.post0.tar.gz").unwrap(),
        "python-dateutil"
    );
    assert_eq!(project("zope.interface-6.0.zip").unwrap(), "zope-interface");
    for bad in ["spvictim.whl", "a-b-c.whl", "README.md", "-1.0.tar.gz"] {
        assert!(project(bad).is_err(), "{bad} was taken for a distribution");
    }
}

#[test]
fn pypi_files_are_served_under_production_urls_and_a_tamper_keeps_the_length() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("spvictim");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("spvictim-1.0.0-py3-none-any.whl"),
        b"wheel bytes",
    )
    .unwrap();
    let tree = read_tree(dir.path()).unwrap();
    let [wheel] = &tree[..] else {
        panic!("one distribution expected: {tree:?}")
    };
    let digest = hex::encode(Sha256::digest(b"wheel bytes"));
    assert_eq!(wheel.sha256, digest);
    let url = format!(
        "https://files.pythonhosted.org/packages/{}/{}/{}/spvictim-1.0.0-py3-none-any.whl",
        &digest[..2],
        &digest[2..4],
        &digest[4..]
    );
    assert_eq!(wheel.url(), url);

    let server = FixtureServer::start();
    assert_eq!(mount(&server, &tree), vec![url.clone()]);
    assert_eq!(fetch(&server, &url), (200, b"wheel bytes".to_vec()));
    tamper(&server, wheel);
    let (status, served) = fetch(&server, &url);
    assert_eq!((status, served.len()), (200, wheel.bytes.len()));
    assert_ne!(served, wheel.bytes);

    // A file filed under another project refuses the whole tree.
    std::fs::write(project.join("spdep-2.0.0-py3-none-any.whl"), b"x").unwrap();
    let refused = read_tree(dir.path()).unwrap_err();
    assert!(refused.contains("a file of project spdep"), "{refused}");
}
