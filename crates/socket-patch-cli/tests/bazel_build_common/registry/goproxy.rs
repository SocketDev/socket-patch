//! Emulation of `proxy.golang.org` behind `--repo_env=GOPROXY=`, and the
//! checksum-database lookup socket-patch reads through
//! `SOCKET_GOSUMDB_URL`.
//!
//! Go modules never pass through Bazel's downloader: gazelle runs `go mod
//! download`, which reads `GOPROXY`. The proxy is a committed tree in the
//! layout of the GOPROXY protocol (`<module>/@v/{list,<v>.info,<v>.mod,
//! <v>.zip}`, module paths case-escaped as on disk), served byte for byte:
//! a fixture's `go.sum` pins the `h1:` of those bytes.
//!
//! An unknown module is a 404 from a live server, which makes `go` try the
//! next proxy of the list. The go-list generation of `go_deps` asks the
//! first proxy for about 1,700 files, and a stub that drops connections
//! fails the whole extension, so the fixture server answers every request
//! on a thread of its own.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use super::super::fixture_server::FixtureServer;

pub const HOST: &str = "proxy.golang.org";
pub const SUMDB_HOST: &str = "sum.golang.org";

/// One module version of the tree, with the two hashes `go.sum` holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module {
    /// The module path, unescaped (`github.com/BurntSushi/toml`).
    pub path: String,
    pub version: String,
    /// `h1:` of the module zip: the `<module> <version>` line of `go.sum`.
    pub zip_h1: String,
    /// `h1:` of the `.mod` file: the `<module> <version>/go.mod` line.
    pub mod_h1: String,
    /// The proxy URL of the zip.
    pub zip_url: String,
    zip: Vec<u8>,
}

impl Module {
    /// The two lines a `go.sum` holds for this module version.
    pub fn go_sum_lines(&self) -> [String; 2] {
        let (path, version) = (&self.path, &self.version);
        [
            format!("{path} {version} {}", self.zip_h1),
            format!("{path} {version}/go.mod {}", self.mod_h1),
        ]
    }
}

/// Go's `h1:` directory hash over (name, content) pairs: the sha256 of
/// one `<hex sha256>  <name>\n` line per file, names sorted.
fn h1(files: &BTreeMap<String, Vec<u8>>) -> String {
    let mut summary = String::new();
    for (name, bytes) in files {
        summary.push_str(&format!("{}  {name}\n", hex::encode(Sha256::digest(bytes))));
    }
    let digest = Sha256::digest(summary.as_bytes());
    format!(
        "h1:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// The files of a module zip, name to content. `Err` for bytes that are
/// no zip, or a zip with an entry outside `<module>@<version>/`, which
/// `go` rejects.
fn zip_files(zip: &[u8], module: &str, version: &str) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut archive =
        zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(|e| format!("not a zip: {e}"))?;
    let prefix = format!("{module}@{version}/");
    let mut files = BTreeMap::new();
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|e| e.to_string())?;
        let name = entry.name().to_string();
        if !name.starts_with(&prefix) {
            return Err(format!("zip entry {name} is outside {prefix}"));
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| format!("{name}: {e}"))?;
        files.insert(name, bytes);
    }
    Ok(files)
}

/// The `h1:` of a module zip, as `go mod download` computes it. `Err`
/// as for [`zip_files`].
pub fn h1_of_zip(zip: &[u8], module: &str, version: &str) -> Result<String, String> {
    Ok(h1(&zip_files(zip, module, version)?))
}

/// The `h1:` of a `.mod` file: the directory hash of one file named `go.mod`.
pub fn h1_of_mod(go_mod: &[u8]) -> String {
    h1(&BTreeMap::from([("go.mod".to_string(), go_mod.to_vec())]))
}

/// `!x` to `X`: the inverse of the case escaping module paths and versions
/// carry in proxy URLs and on disk.
fn unescape(escaped: &str) -> String {
    let mut out = String::new();
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        match c {
            '!' => out.extend(chars.next().map(|c| c.to_ascii_uppercase())),
            c => out.push(c),
        }
    }
    out
}

/// The `@v` directories under `dir`, as (path relative to the tree with
/// `/` separators, directory).
fn version_dirs(
    dir: &Path,
    rel: &str,
    out: &mut Vec<(String, std::path::PathBuf)>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths.into_iter().filter(|path| path.is_dir()) {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name == "@v" {
            out.push((rel.to_string(), path));
        } else {
            let below = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            version_dirs(&path, &below, out)?;
        }
    }
    Ok(())
}

/// Serve every module of `tree` under `https://proxy.golang.org/` and its
/// checksum-database lookup under `https://sum.golang.org/lookup/`.
/// Returns the module versions. `Err` (nothing served) for a version that
/// lacks its `.info` or `.mod`, is missing from `list`, or whose zip `go`
/// would reject: a half-served module fails a build far from its cause.
pub fn mount(server: &FixtureServer, tree: &Path) -> Result<Vec<Module>, String> {
    let mut dirs = Vec::new();
    version_dirs(tree, "", &mut dirs)?;
    let mut routes: Vec<(String, Vec<u8>)> = Vec::new();
    let mut modules = Vec::new();
    for (escaped, dir) in dirs {
        let read = |name: &str| {
            let path = dir.join(name);
            std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))
        };
        let base = format!("https://{HOST}/{escaped}/@v");
        let list = String::from_utf8(read("list")?).map_err(|e| format!("{escaped}: list: {e}"))?;
        routes.push((format!("{base}/list"), list.clone().into_bytes()));
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for stem in names.iter().filter_map(|name| name.strip_suffix(".zip")) {
            let (path, version) = (unescape(&escaped), unescape(stem));
            if !list.lines().any(|line| line == version) {
                return Err(format!("{path}: {version} is not in @v/list"));
            }
            let (info, go_mod, zip) = (
                read(&format!("{stem}.info"))?,
                read(&format!("{stem}.mod"))?,
                read(&format!("{stem}.zip"))?,
            );
            let zip_h1 = h1_of_zip(&zip, &path, &version)
                .map_err(|why| format!("{path}@{version}: {why}"))?;
            let module = Module {
                mod_h1: h1_of_mod(&go_mod),
                zip_h1,
                zip_url: format!("{base}/{stem}.zip"),
                zip: zip.clone(),
                path,
                version,
            };
            routes.push((format!("{base}/{stem}.info"), info));
            routes.push((format!("{base}/{stem}.mod"), go_mod));
            routes.push((module.zip_url.clone(), zip));
            // The lookup of the real database: a record number, the two
            // go.sum lines, then a signed tree head. Socket-patch reads the
            // two lines; the tree head is left out, so a `go` command
            // pointed here as GOSUMDB rejects the answer instead of
            // trusting an unsigned one.
            let lookup = format!("0\n{}\n", module.go_sum_lines().join("\n"));
            routes.push((
                format!("https://{SUMDB_HOST}/lookup/{escaped}@{stem}"),
                lookup.into_bytes(),
            ));
            modules.push(module);
        }
    }
    for (url, bytes) in routes {
        server.serve(&url, bytes);
    }
    Ok(modules)
}

/// One entry of a `GOPROXY` list: this server as `proxy.golang.org`.
pub fn goproxy(server: &FixtureServer) -> String {
    format!("{}/{HOST}", server.loopback_origin())
}

/// The value of `SOCKET_GOSUMDB_URL`: without it a hosted Go `rollback` of
/// a module only this proxy knows ends in `hosted_restore_refused`.
pub fn sumdb(server: &FixtureServer) -> String {
    format!("{}/{SUMDB_HOST}", server.loopback_origin())
}

/// The module's zip with one byte of one file changed: still a module zip
/// `go` unpacks, with the same file names, whose `h1:` is no longer the
/// one `go.sum` pins.
///
/// The archive is rebuilt from its files, never edited as bytes. Go's
/// `h1:` covers the names and contents of the files, not the bytes of the
/// zip. With go 1.26.3 and the committed zip, a flipped byte in a
/// compressed stream gives `zip: not a valid zip file` before any
/// checksum is compared, so the fetch fails whether or not a digest is
/// enforced; a byte appended after the central directory is accepted with
/// the pinned `h1:` (it changes no name and no content); and the zip this
/// returns gives `checksum mismatch ... SECURITY ERROR`. `go.mod` is left
/// alone: its own `h1:` is a separate `go.sum` line. `Err` when there is
/// no other file to change.
pub fn tampered_zip(module: &Module) -> Result<Vec<u8>, String> {
    use std::io::Write;

    let (path, version) = (&module.path, &module.version);
    let mut files = zip_files(&module.zip, path, version)?;
    let go_mod = format!("{path}@{version}/go.mod");
    let mut victims = files.iter_mut();
    let victim = victims.find(|(name, bytes)| **name != go_mod && !bytes.is_empty());
    let (_, bytes) =
        victim.ok_or_else(|| format!("{path}@{version}: no file beside go.mod to tamper with"))?;
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;

    let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (name, bytes) in &files {
        let written = archive
            .start_file(name.as_str(), options)
            .map_err(|e| e.to_string())
            .and_then(|()| archive.write_all(bytes).map_err(|e| e.to_string()));
        written.map_err(|why| format!("{name}: {why}"))?;
    }
    let tampered = archive.finish().map_err(|e| e.to_string())?.into_inner();
    // What `go` will compute for it: a real hash, and another one.
    let h1 = h1_of_zip(&tampered, path, version)?;
    if h1 == module.zip_h1 {
        return Err(format!("{path}@{version}: the tampered zip still has {h1}"));
    }
    Ok(tampered)
}

/// Serve [`tampered_zip`] at the module's URL, for a tamper twin: `go`
/// then fails with its checksum mismatch against `go.sum`. `Err` (the
/// route keeps the committed zip) when no such zip can be built.
pub fn tamper(server: &FixtureServer, module: &Module) -> Result<(), String> {
    server.serve(&module.zip_url, tampered_zip(module)?);
    Ok(())
}

#[test]
fn the_committed_go_proxy_serves_what_go_sum_pins() {
    use super::pypi_files::fetch;

    let fixtures = super::super::workspace::fixtures_root().join("heavy");
    let server = FixtureServer::start();
    let modules = mount(&server, &fixtures.join("registry/goproxy")).unwrap();
    let upstream = modules
        .iter()
        .find(|m| m.path == "example.com/upstream" && m.version == "v1.0.0")
        .expect("example.com/upstream v1.0.0 in the tree");
    // The oracle is a go.sum the real `go` wrote for these bytes (probe
    // gazelle-go, `template/go.sum`), which every gazelle fixture carries.
    let go_sum = std::fs::read_to_string(fixtures.join("gazelle/bzlmod/e9/go.sum")).unwrap();
    for line in upstream.go_sum_lines() {
        assert!(
            go_sum.lines().any(|l| l == line),
            "{line} is not in go.sum:\n{go_sum}"
        );
    }

    let proxy = goproxy(&server);
    assert_eq!(
        proxy,
        format!("{}/proxy.golang.org", server.loopback_origin())
    );
    let get = |rest: &str| fetch(&server, &format!("{proxy}/{rest}"));
    assert_eq!(
        get("example.com/upstream/@v/list"),
        (200, b"v1.0.0\n".to_vec())
    );
    let (status, zip) = get("example.com/upstream/@v/v1.0.0.zip");
    assert_eq!(status, 200);
    assert_eq!(
        h1_of_zip(&zip, "example.com/upstream", "v1.0.0").unwrap(),
        upstream.zip_h1
    );
    assert_eq!(get("example.com/upstream/@v/v1.0.0.mod").0, 200);
    assert_eq!(get("example.com/upstream/@v/v1.0.0.info").0, 200);
    // An unknown module and an unknown version are misses, not hangs.
    assert_eq!(get("example.com/unknown/@v/list").0, 404);
    assert_eq!(get("example.com/upstream/@v/v9.9.9.zip").0, 404);

    let lookup = fetch(
        &server,
        &format!("{}/lookup/example.com/upstream@v1.0.0", sumdb(&server)),
    );
    let text = String::from_utf8(lookup.1).unwrap();
    assert_eq!(lookup.0, 200);
    for line in upstream.go_sum_lines() {
        assert!(
            text.lines().any(|l| l == line),
            "{line} is not in the lookup:\n{text}"
        );
    }

    tamper(&server, upstream).unwrap();
    let (_, tampered) = get("example.com/upstream/@v/v1.0.0.zip");
    // What a tamper twin needs `go` to reach is the comparison with
    // go.sum: the served bytes are a module zip with another `h1:`. The
    // length of the zip says nothing (a byte appended to it is accepted).
    let h1 = h1_of_zip(&tampered, "example.com/upstream", "v1.0.0");
    assert_ne!(h1.expect("a module zip go unpacks"), upstream.zip_h1);
    // Same files, one of them changed by one byte, and not go.mod, whose
    // hash is the other go.sum line.
    let files = |zip: &[u8]| zip_files(zip, "example.com/upstream", "v1.0.0").unwrap();
    let (before, after) = (files(&zip), files(&tampered));
    assert!(before.keys().eq(after.keys()));
    let changed: Vec<&String> = before
        .iter()
        .filter(|(name, bytes)| after[*name] != **bytes)
        .map(|(name, _)| name)
        .collect();
    let [name] = changed[..] else {
        panic!("one changed file expected: {changed:?}")
    };
    assert!(!name.ends_with("/go.mod"), "{name}");
    let differing = before[name]
        .iter()
        .zip(&after[name])
        .filter(|(a, b)| a != b);
    assert_eq!(
        (differing.count(), after[name].len()),
        (1, before[name].len())
    );
    assert_eq!(
        h1_of_mod(&after["example.com/upstream@v1.0.0/go.mod"]),
        upstream.mod_h1
    );
}

#[test]
fn a_go_proxy_tree_that_go_would_reject_is_not_mounted() {
    let zip_of = |entry: &str| {
        use std::io::Write;
        let mut archive = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file(entry, options).unwrap();
        archive.write_all(b"module example.com/Mixed\n").unwrap();
        archive.finish().unwrap().into_inner()
    };
    let tree = tempfile::tempdir().unwrap();
    // On disk and in URLs an upper-case letter is `!` and its lower case.
    let dir = tree.path().join("example.com/!mixed/@v");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("list"), "v1.0.0\n").unwrap();
    std::fs::write(dir.join("v1.0.0.info"), "{}").unwrap();
    std::fs::write(
        dir.join("v1.0.0.zip"),
        zip_of("example.com/Mixed@v1.0.0/go.mod"),
    )
    .unwrap();
    let server = FixtureServer::start();

    let no_mod = mount(&server, tree.path()).unwrap_err();
    assert!(no_mod.contains("v1.0.0.mod"), "{no_mod}");
    std::fs::write(dir.join("v1.0.0.mod"), "module example.com/Mixed\n").unwrap();
    let [module] = &mount(&server, tree.path()).unwrap()[..] else {
        panic!("one module expected")
    };
    assert_eq!(
        (module.path.as_str(), module.version.as_str()),
        ("example.com/Mixed", "v1.0.0")
    );
    assert_eq!(
        module.zip_url,
        "https://proxy.golang.org/example.com/!mixed/@v/v1.0.0.zip"
    );
    // A zip that holds go.mod alone has no file a tamper may change: the
    // helper says so and the committed zip stays served.
    let refused = tamper(&server, module).unwrap_err();
    assert!(refused.contains("no file beside go.mod"), "{refused}");
    let served = super::pypi_files::fetch(&server, &module.zip_url);
    let committed = std::fs::read(dir.join("v1.0.0.zip")).unwrap();
    assert_eq!(served, (200, committed));

    std::fs::write(dir.join("list"), "v2.0.0\n").unwrap();
    let unlisted = mount(&server, tree.path()).unwrap_err();
    assert!(unlisted.contains("not in @v/list"), "{unlisted}");
    std::fs::write(dir.join("list"), "v1.0.0\n").unwrap();
    std::fs::write(dir.join("v1.0.0.zip"), zip_of("elsewhere/go.mod")).unwrap();
    let outside = mount(&server, tree.path()).unwrap_err();
    assert!(
        outside.contains("is outside example.com/Mixed@v1.0.0/"),
        "{outside}"
    );
    std::fs::write(dir.join("v1.0.0.zip"), b"not a zip").unwrap();
    assert!(mount(&server, tree.path())
        .unwrap_err()
        .contains("not a zip"));
}
