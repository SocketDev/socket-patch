//! Hermetic, vendorable two-package projects for every ecosystem the vendor
//! engine wires: installed (pristine) copies in a per-test store, the
//! project's own lockfiles / manifests, and a `.socket/manifest.json` plus
//! after-blobs so `vendor --offline` needs no network. Shared by the
//! group-commit equivalence and crash tests and the ledger-schema tests.
//!
//! Two packages per project on purpose: a run then commits the same
//! lockfile / config twice, which is what the group commit collapses and
//! what makes whole-file ledger snapshots chain.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

pub fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Every ecosystem fixture, by name.
pub const ALL: &[&str] = &[
    "npm",
    "pnpm",
    "cargo",
    "golang",
    "pypi-requirements",
    "pylock",
    "gem",
    "composer",
    "maven",
    "nuget",
];

/// One patch of a fixture: the purl, its uuid, and the one file it patches
/// (manifest key, pristine bytes, patched bytes).
pub struct Patch {
    pub purl: String,
    pub uuid: String,
    pub file: String,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

fn patch(purl: &str, uuid: &str, file: &str, before: &[u8], after: &[u8]) -> Patch {
    Patch {
        purl: purl.to_string(),
        uuid: uuid.to_string(),
        file: file.to_string(),
        before: before.to_vec(),
        after: after.to_vec(),
    }
}

/// A built fixture: the project root, the store holding the installed
/// copies, the environment the binary needs to find them, and the patches.
pub struct Fixture {
    _tmp: tempfile::TempDir,
    pub root: PathBuf,
    pub store: PathBuf,
    pub env: Vec<(String, String)>,
    pub patches: Vec<Patch>,
}

impl Fixture {
    /// Build ecosystem `name` (one of [`ALL`]).
    pub fn new(name: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("proj");
        let store = tmp.path().join("store");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&store).unwrap();
        let (env, patches) = match name {
            "npm" => npm(&root),
            "pnpm" => pnpm(&root),
            "cargo" => cargo(&root, &store),
            "golang" => golang(&root, &store),
            "pypi-requirements" => pypi_requirements(&root),
            "pylock" => pylock(&root),
            "gem" => gem(&root),
            "composer" => composer(&root),
            "maven" => maven(&root, &store),
            "nuget" => nuget(&root, &store),
            other => panic!("no fixture named {other}"),
        };
        write_manifest(&root, &patches);
        Fixture {
            _tmp: tmp,
            root,
            store,
            env,
            patches,
        }
    }

    /// Run the built binary in the project with the fixture's environment,
    /// every ambient `SOCKET_*` scrubbed and `extra_env` on top. Returns
    /// the exit code, stdout and stderr.
    pub fn run(&self, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
        cmd.args(args).current_dir(&self.root);
        for (key, _) in std::env::vars() {
            if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
                cmd.env_remove(key);
            }
        }
        for var in ["VIRTUAL_ENV", "CONDA_PREFIX", "BUNDLE_PATH", "GEM_HOME"] {
            cmd.env_remove(var);
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("HOME", self.store.join("home"))
            .env("CARGO_HOME", self.store.join("cargo-home"))
            .env("GOMODCACHE", self.store.join("modcache"))
            .env("MAVEN_REPO_LOCAL", self.store.join("m2"))
            .env("NUGET_PACKAGES", self.store.join("nuget"));
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("run socket-patch");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// `vendor --json --offline [extra]`.
    pub fn vendor(&self, extra: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
        let mut args = vec!["vendor", "--json", "--offline"];
        args.extend_from_slice(extra);
        self.run(&args, extra_env)
    }

    /// Every regular file of the project except the transient lock file and
    /// the fixture's inputs under `.socket/` (manifest, blobs), relative
    /// path → bytes, sorted.
    pub fn tree(&self) -> Vec<(String, Vec<u8>)> {
        tree(&self.root)
    }
}

/// Every regular file under `root` except `.socket/apply.lock`,
/// `.socket/manifest.json` and `.socket/blobs/`, sorted.
pub fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            let ft = entry.file_type().unwrap();
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if ft.is_dir() {
                if rel != ".socket/blobs" {
                    stack.push(path);
                }
            } else if ft.is_file() && rel != ".socket/apply.lock" && rel != ".socket/manifest.json"
            {
                out.push((rel, std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// [`tree`] with every vendoring timestamp masked (ledger and markers carry
/// the run's clock), for comparing two runs.
pub fn masked_tree(root: &Path) -> Vec<(String, String)> {
    tree(root)
        .into_iter()
        .map(|(rel, bytes)| {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let masked = if rel.ends_with("state.json") || rel.ends_with("socket-patch.vendor.json")
            {
                mask_timestamps(&text)
            } else {
                text
            };
            (rel, masked)
        })
        .collect()
}

fn mask_timestamps(text: &str) -> String {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(text) else {
        return text.to_string();
    };
    fn walk(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    if k == "vendoredAt" {
                        *val = serde_json::Value::Null;
                    } else {
                        walk(val);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut v);
    serde_json::to_string_pretty(&v).unwrap()
}

fn put(path: &Path, bytes: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, bytes).unwrap();
}

fn write_manifest(root: &Path, patches: &[Patch]) {
    let mut map = serde_json::Map::new();
    for p in patches {
        map.insert(
            p.purl.clone(),
            serde_json::json!({
                "uuid": p.uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { p.file.clone(): {
                    "beforeHash": git_sha256(&p.before),
                    "afterHash": git_sha256(&p.after),
                }},
                "vulnerabilities": {
                    "GHSA-aaaa-bbbb-cccc": {
                        "cves": ["CVE-2026-0001"], "summary": "s",
                        "severity": "high", "description": "d"
                    }
                },
                "description": "fixture patch",
                "license": "MIT",
                "tier": "free"
            }),
        );
        put(
            &root.join(".socket/blobs").join(git_sha256(&p.after)),
            &p.after,
        );
    }
    put(
        &root.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "patches": map })).unwrap(),
    );
}

fn zip_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write as _;
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in members {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

type Built = (Vec<(String, String)>, Vec<Patch>);

// ── npm (package-lock) ─────────────────────────────────────────────────

const U1: &str = "11111111-1111-4111-8111-000000000001";
const U2: &str = "11111111-1111-4111-8111-000000000002";

fn npm_install(root: &Path, name: &str, index: &[u8]) {
    let pkg = root.join("node_modules").join(name);
    put(
        &pkg.join("package.json"),
        format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
    );
    put(&pkg.join("index.js"), index);
}

fn npm(root: &Path) -> Built {
    npm_install(root, "alpha", b"module.exports = 'a';\n");
    npm_install(root, "beta", b"module.exports = 'b';\n");
    put(
        &root.join("package.json"),
        r#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"alpha":"1.0.0","beta":"1.0.0"}}"#,
    );
    let entry = |name: &str| {
        serde_json::json!({
            "version": "1.0.0",
            "resolved": format!("https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"),
            "integrity": "sha512-orig==",
        })
    };
    let lock = serde_json::json!({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": { "name": "fixture", "version": "1.0.0",
                  "dependencies": { "alpha": "1.0.0", "beta": "1.0.0" } },
            "node_modules/alpha": entry("alpha"),
            "node_modules/beta": entry("beta"),
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&lock).unwrap();
    bytes.push(b'\n');
    put(&root.join("package-lock.json"), bytes);
    (
        Vec::new(),
        vec![
            patch(
                "pkg:npm/alpha@1.0.0",
                U1,
                "package/index.js",
                b"module.exports = 'a';\n",
                b"module.exports = 'A';\n",
            ),
            patch(
                "pkg:npm/beta@1.0.0",
                U2,
                "package/index.js",
                b"module.exports = 'b';\n",
                b"module.exports = 'B';\n",
            ),
        ],
    )
}

// ── pnpm (lockfile v9, pnpm >= 11 workspace mirror) ─────────────────────

fn pnpm(root: &Path) -> Built {
    npm_install(root, "alpha", b"module.exports = 'a';\n");
    npm_install(root, "beta", b"module.exports = 'b';\n");
    put(
        &root.join("package.json"),
        r#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"alpha":"1.0.0","beta":"1.0.0"}}"#,
    );
    put(
        &root.join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      alpha:
        specifier: 1.0.0
        version: 1.0.0
      beta:
        specifier: 1.0.0
        version: 1.0.0

packages:
  alpha@1.0.0:
    resolution: {integrity: sha512-orig==}

  beta@1.0.0:
    resolution: {integrity: sha512-orig==}

snapshots:
  alpha@1.0.0: {}

  beta@1.0.0: {}
",
    );
    let (_, patches) = npm_patches();
    (Vec::new(), patches)
}

fn npm_patches() -> Built {
    (
        Vec::new(),
        vec![
            patch(
                "pkg:npm/alpha@1.0.0",
                U1,
                "package/index.js",
                b"module.exports = 'a';\n",
                b"module.exports = 'A';\n",
            ),
            patch(
                "pkg:npm/beta@1.0.0",
                U2,
                "package/index.js",
                b"module.exports = 'b';\n",
                b"module.exports = 'B';\n",
            ),
        ],
    )
}

// ── cargo ───────────────────────────────────────────────────────────────

fn cargo(root: &Path, store: &Path) -> Built {
    let reg = store.join("cargo-home/registry/src/index.crates.io-6f17d22bba15001f");
    for name in ["alpha", "beta"] {
        let krate = reg.join(format!("{name}-1.0.0"));
        put(
            &krate.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"1.0.0\"\n"),
        );
        put(&krate.join("src/lib.rs"), format!("pub fn {name}() {{}}\n"));
        put(&krate.join(".cargo-checksum.json"), "{\"files\":{}}");
    }
    put(
        &root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\nalpha = \"1\"\nbeta = \"1\"\n",
    );
    let pkg = |name: &str, sum: char| {
        format!(
            "[[package]]\nname = \"{name}\"\nversion = \"1.0.0\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"{}\"\n",
            sum.to_string().repeat(64)
        )
    };
    put(
        &root.join("Cargo.lock"),
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\nversion = 4\n\n\
             {}\n{}\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"alpha\",\n \"beta\",\n]\n",
            pkg("alpha", 'a'),
            pkg("beta", 'b')
        ),
    );
    (
        Vec::new(),
        vec![
            patch(
                "pkg:cargo/alpha@1.0.0",
                U1,
                "package/src/lib.rs",
                b"pub fn alpha() {}\n",
                b"pub fn alpha() { /* patched */ }\n",
            ),
            patch(
                "pkg:cargo/beta@1.0.0",
                U2,
                "package/src/lib.rs",
                b"pub fn beta() {}\n",
                b"pub fn beta() { /* patched */ }\n",
            ),
        ],
    )
}

// ── golang ──────────────────────────────────────────────────────────────

fn golang(root: &Path, store: &Path) -> Built {
    for name in ["alpha", "beta"] {
        let dir = store.join(format!("modcache/github.com/fx/{name}@v1.0.0"));
        put(
            &dir.join("go.mod"),
            format!("module github.com/fx/{name}\n\ngo 1.21\n"),
        );
        put(
            &dir.join(format!("{name}.go")),
            format!("package {name}\n\nfunc Hello() string {{ return \"hi\" }}\n"),
        );
    }
    put(
        &root.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/fx/alpha v1.0.0\n\tgithub.com/fx/beta v1.0.0\n)\n",
    );
    let p = |name: &str| {
        patch(
            &format!("pkg:golang/github.com/fx/{name}@v1.0.0"),
            if name == "alpha" { U1 } else { U2 },
            &format!("package/{name}.go"),
            format!("package {name}\n\nfunc Hello() string {{ return \"hi\" }}\n").as_bytes(),
            format!("package {name}\n\nfunc Hello() string {{ return \"patched\" }}\n").as_bytes(),
        )
    };
    (Vec::new(), vec![p("alpha"), p("beta")])
}

// ── pypi ────────────────────────────────────────────────────────────────

fn site_packages(root: &Path) -> PathBuf {
    if cfg!(windows) {
        root.join(".venv/Lib/site-packages")
    } else {
        root.join(".venv/lib/python3.12/site-packages")
    }
}

fn pypi_install(root: &Path, name: &str) {
    let sp = site_packages(root);
    let di = sp.join(format!("{name}-1.0.0.dist-info"));
    put(
        &di.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n\nbody\n"),
    );
    put(
        &di.join("WHEEL"),
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    );
    put(
        &di.join("RECORD"),
        format!(
            "{name}.py,sha256=AAAA,20\n{name}-1.0.0.dist-info/METADATA,,\n\
             {name}-1.0.0.dist-info/WHEEL,,\n{name}-1.0.0.dist-info/RECORD,,\n"
        ),
    );
    put(&sp.join(format!("{name}.py")), format!("# {name}\nX = 1\n"));
}

fn pypi_patches() -> Vec<Patch> {
    ["alpha", "beta"]
        .iter()
        .map(|name| {
            patch(
                &format!("pkg:pypi/{name}@1.0.0"),
                if *name == "alpha" { U1 } else { U2 },
                &format!("{name}.py"),
                format!("# {name}\nX = 1\n").as_bytes(),
                format!("# {name}\nX = 2\n").as_bytes(),
            )
        })
        .collect()
}

fn pypi_requirements(root: &Path) -> Built {
    pypi_install(root, "alpha");
    pypi_install(root, "beta");
    put(
        &root.join("requirements.txt"),
        "alpha==1.0.0\nbeta==1.0.0\n",
    );
    (Vec::new(), pypi_patches())
}

fn pylock(root: &Path) -> Built {
    pypi_install(root, "alpha");
    pypi_install(root, "beta");
    // Enough unrelated packages that the lock is not a toy: whole-file
    // ledger snapshots are what the ledger schema compacts.
    let mut lock = String::from("lock-version = \"1.0\"\ncreated-by = \"fixture\"\n");
    for i in 0..40 {
        lock.push_str(&format!(
            "\n[[packages]]\nname = \"filler{i:02}\"\nversion = \"1.0.{i}\"\n\
             wheels = [{{ url = \"https://files.example/filler{i:02}-1.0.{i}-py3-none-any.whl\", \
             hashes = {{ sha256 = \"{}\" }} }}]\n",
            format!("{i:02}").repeat(32)
        ));
    }
    for name in ["alpha", "beta"] {
        lock.push_str(&format!(
            "\n[[packages]]\nname = \"{name}\"\nversion = \"1.0.0\"\n\
             wheels = [{{ url = \"https://files.example/{name}-1.0.0-py3-none-any.whl\", \
             hashes = {{ sha256 = \"{}\" }} }}]\n",
            "c".repeat(64)
        ));
    }
    put(&root.join("pylock.toml"), lock);
    (Vec::new(), pypi_patches())
}

// ── gem ─────────────────────────────────────────────────────────────────

fn gem(root: &Path) -> Built {
    let bundle = root.join("vendor/bundle");
    for name in ["alpha", "beta"] {
        let leaf = format!("{name}-1.0.0");
        put(
            &bundle
                .join("gems")
                .join(&leaf)
                .join(format!("lib/{name}.rb")),
            format!("module {}; end\n", name.to_uppercase()),
        );
        put(
            &bundle
                .join("specifications")
                .join(format!("{leaf}.gemspec")),
            format!(
                "Gem::Specification.new do |s|\n  s.name = \"{name}\"\n  \
                 s.version = \"1.0.0\"\n  s.summary = \"fixture\"\n  \
                 s.authors = [\"Socket\"]\n  s.require_paths = [\"lib\"]\nend\n"
            ),
        );
    }
    put(
        &root.join("Gemfile"),
        "source \"https://rubygems.org\"\ngem \"alpha\"\ngem \"beta\"\n",
    );
    put(
        &root.join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    alpha (1.0.0)\n    beta (1.0.0)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  alpha\n  beta\n\nBUNDLED WITH\n   2.5.3\n",
    );
    let p = |name: &str| {
        patch(
            &format!("pkg:gem/{name}@1.0.0"),
            if name == "alpha" { U1 } else { U2 },
            &format!("lib/{name}.rb"),
            format!("module {}; end\n", name.to_uppercase()).as_bytes(),
            format!("module {}; SAFE = true; end\n", name.to_uppercase()).as_bytes(),
        )
    };
    (Vec::new(), vec![p("alpha"), p("beta")])
}

// ── composer ────────────────────────────────────────────────────────────

fn composer(root: &Path) -> Built {
    let mut installed = Vec::new();
    let mut locked = Vec::new();
    for name in ["alpha", "beta"] {
        let dir = root.join(format!("vendor/fx/{name}"));
        put(
            &dir.join("composer.json"),
            format!("{{\"name\": \"fx/{name}\"}}\n"),
        );
        put(&dir.join("src/Lib.php"), format!("<?php\n// {name}\n"));
        installed.push(serde_json::json!({
            "name": format!("fx/{name}"), "version": "1.0.0", "version_normalized": "1.0.0.0",
            "install-path": format!("../fx/{name}"),
        }));
        locked.push(serde_json::json!({
            "name": format!("fx/{name}"),
            "version": "1.0.0",
            "source": {"type": "git", "url": format!("https://github.com/fx/{name}.git"), "reference": "aaaa"},
            "dist": {"type": "zip", "url": format!("https://api.github.com/repos/fx/{name}/zipball/aaaa"), "reference": "aaaa", "shasum": ""},
            "type": "library"
        }));
    }
    put(
        &root.join("vendor/composer/installed.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "packages": installed })).unwrap(),
    );
    put(&root.join("composer.json"), "{ \"name\": \"t/t\" }\n");
    let lock = serde_json::json!({
        "_readme": ["This file locks the dependencies of your project to a known state"],
        "content-hash": "7a59d114f58e9b02546b21d7e57430d3",
        "packages": locked,
        "packages-dev": [],
        "minimum-stability": "stable",
        "plugin-api-version": "2.6.0"
    });
    // composer's own layout: 4-space indent, trailing newline.
    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut bytes, formatter);
    serde::Serialize::serialize(&lock, &mut ser).unwrap();
    bytes.push(b'\n');
    put(&root.join("composer.lock"), bytes);
    let p = |name: &str| {
        patch(
            &format!("pkg:composer/fx/{name}@1.0.0"),
            if name == "alpha" { U1 } else { U2 },
            "src/Lib.php",
            format!("<?php\n// {name}\n").as_bytes(),
            format!("<?php\n// {name} patched\n").as_bytes(),
        )
    };
    (Vec::new(), vec![p("alpha"), p("beta")])
}

// ── maven ───────────────────────────────────────────────────────────────

fn maven(root: &Path, store: &Path) -> Built {
    let mut deps = String::new();
    for name in ["alpha", "beta"] {
        let dir = store.join(format!("m2/org/fx/{name}/1.0.0"));
        put(
            &dir.join(format!("{name}-1.0.0.pom")),
            format!(
                "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
                 <modelVersion>4.0.0</modelVersion>\n  <groupId>org.fx</groupId>\n  \
                 <artifactId>{name}</artifactId>\n  <version>1.0.0</version>\n</project>\n"
            ),
        );
        put(
            &dir.join(format!("{name}-1.0.0.jar")),
            zip_bytes(&[
                ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                ("META-INF/NOTICE.txt", format!("{name} notice\n").as_bytes()),
                ("org/fx/Main.class", b"\xca\xfe\xba\xbe"),
            ]),
        );
        deps.push_str(&format!(
            "    <dependency>\n      <groupId>org.fx</groupId>\n      \
             <artifactId>{name}</artifactId>\n      <version>1.0.0</version>\n    </dependency>\n"
        ));
    }
    // A realistic-size project pom: whole-file ledger snapshots of it are
    // what the ledger schema compacts.
    let mut filler = String::new();
    for i in 0..60 {
        filler.push_str(&format!(
            "    <dependency>\n      <groupId>org.filler</groupId>\n      \
             <artifactId>filler{i:02}</artifactId>\n      <version>1.0.{i}</version>\n    \
             </dependency>\n"
        ));
    }
    put(
        &root.join("pom.xml"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
             <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
             <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  \
             <dependencies>\n{deps}{filler}  </dependencies>\n</project>\n"
        ),
    );
    let p = |name: &str| {
        patch(
            &format!("pkg:maven/org.fx/{name}@1.0.0"),
            if name == "alpha" { U1 } else { U2 },
            "META-INF/NOTICE.txt",
            format!("{name} notice\n").as_bytes(),
            format!("{name} notice (patched)\n").as_bytes(),
        )
    };
    (Vec::new(), vec![p("alpha"), p("beta")])
}

// ── nuget ───────────────────────────────────────────────────────────────

fn nupkg_content_hash(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
}

fn nuget(root: &Path, store: &Path) -> Built {
    let mut refs = String::new();
    let mut deps = serde_json::Map::new();
    for name in ["Fx.Alpha", "Fx.Beta"] {
        let lower = name.to_lowercase();
        let dir = store.join(format!("nuget/{lower}/1.0.0"));
        let nuspec = format!(
            "<?xml version=\"1.0\"?><package><metadata><id>{name}</id>\
             <version>1.0.0</version></metadata></package>"
        );
        let member = format!("{name} license\n");
        let nupkg = zip_bytes(&[
            (&format!("{name}.nuspec"), nuspec.as_bytes()),
            ("LICENSE.md", member.as_bytes()),
            ("lib/net8.0/Fx.dll", b"MZ dll"),
        ]);
        put(&dir.join(format!("{lower}.1.0.0.nupkg")), &nupkg);
        put(
            &dir.join(format!("{lower}.1.0.0.nupkg.sha512")),
            nupkg_content_hash(&nupkg),
        );
        put(&dir.join(format!("{lower}.nuspec")), &nuspec);
        put(&dir.join("LICENSE.md"), &member);
        put(&dir.join("lib/net8.0/Fx.dll"), b"MZ dll");
        refs.push_str(&format!(
            "<PackageReference Include=\"{name}\" Version=\"1.0.0\" />"
        ));
        deps.insert(
            name.to_string(),
            serde_json::json!({
                "type": "Direct", "requested": "[1.0.0, )", "resolved": "1.0.0",
                "contentHash": nupkg_content_hash(&nupkg)
            }),
        );
    }
    put(
        &root.join("app.csproj"),
        format!(
            "<Project Sdk=\"Microsoft.NET.Sdk\"><PropertyGroup><TargetFramework>net8.0\
             </TargetFramework><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\
             </PropertyGroup><ItemGroup>{refs}</ItemGroup></Project>"
        ),
    );
    let lock = serde_json::json!({
        "version": 1,
        "dependencies": { "net8.0": deps }
    });
    put(
        &root.join("packages.lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    );
    let mut config = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
         <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
         </packageSources>\n",
    );
    // A realistic-size config: whole-file ledger snapshots of it are what
    // the ledger schema compacts.
    config.push_str("  <config>\n");
    for i in 0..40 {
        config.push_str(&format!(
            "    <add key=\"fixtureSetting{i:02}\" value=\"value-{i:02}\" />\n"
        ));
    }
    config.push_str("  </config>\n</configuration>\n");
    put(&root.join("nuget.config"), config);
    let p = |name: &str| {
        patch(
            &format!("pkg:nuget/{name}@1.0.0"),
            if name == "Fx.Alpha" { U1 } else { U2 },
            "LICENSE.md",
            format!("{name} license\n").as_bytes(),
            format!("{name} license (patched)\n").as_bytes(),
        )
    };
    (Vec::new(), vec![p("Fx.Alpha"), p("Fx.Beta")])
}
