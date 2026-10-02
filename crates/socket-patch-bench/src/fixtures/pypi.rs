//! PyPI projects: one installed virtualenv, locked by each Python tool.
//!
//! Every fixture has a project-local `.venv` (as `uv`, `poetry` with
//! in-project venvs, `pipenv` with `PIPENV_VENV_IN_PROJECT` and `pdm`
//! create): without one the crawler falls back to asking `python3` for the
//! machine's global site-packages, which would time the runner's Python
//! install instead of socket-patch.

use std::fmt::Write as _;
use std::io::Write as _;

use serde_json::json;

use super::gen::{self, Rng, Tree};
use super::{Expect, Fixture, Served, Size, PATCH_HOST};
use crate::mock::PatchSpec;

const SITE: &str = "project/.venv/lib/python3.12/site-packages";

#[derive(Debug, Clone)]
pub struct Dist {
    /// PEP 503-normalized project name (`py-foo12`).
    pub name: String,
    pub version: String,
    pub deps: Vec<usize>,
    pub direct: bool,
    pub patched: bool,
}

impl Dist {
    /// The wheel/dist-info spelling (`py_foo12`).
    pub fn dist(&self) -> String {
        self.name.replace('-', "_")
    }

    pub fn purl(&self) -> String {
        format!("pkg:pypi/{}@{}", self.name, self.version)
    }

    pub fn wheel(&self) -> String {
        format!("{}-{}-py3-none-any.whl", self.dist(), self.version)
    }

    pub fn sdist(&self) -> String {
        format!("{}-{}.tar.gz", self.dist(), self.version)
    }

    pub fn hash(&self, what: &str) -> String {
        gen::sha256_hex(&format!("pypi:{what}:{}@{}", self.name, self.version))
    }

    pub fn summary(&self) -> String {
        format!("Synthetic distribution {}", self.name)
    }
}

pub fn dists(seed: &str, size: Size) -> Vec<Dist> {
    let mut rng = Rng::new(seed);
    let n = size.packages;
    let mut out: Vec<Dist> = (0..n)
        .map(|i| Dist {
            name: format!("py-{}", gen::ident(&mut rng, i)),
            version: gen::version(&mut rng),
            deps: Vec::new(),
            direct: i < (n / 6).max(1),
            patched: size.is_patched(i),
        })
        .collect();
    for (i, d) in out.iter_mut().enumerate() {
        for _ in 0..rng.below(4) {
            if i + 1 < n {
                let j = i + 1 + rng.below((n - i - 1).min(80));
                if !d.deps.contains(&j) {
                    d.deps.push(j);
                }
            }
        }
        d.deps.sort_unstable();
    }
    out
}

/// A virtualenv holding every distribution: dist-info (`METADATA`,
/// `RECORD`, `INSTALLER`, `WHEEL`) plus the importable package.
pub fn install_venv(t: &mut Tree, ds: &[Dist]) -> std::io::Result<()> {
    t.write(
        "project/.venv/pyvenv.cfg",
        "home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.3\n",
    )?;
    let mut rng = Rng::new("venv");
    for d in ds {
        let di = format!("{SITE}/{}-{}.dist-info", d.dist(), d.version);
        let mut meta = format!(
            "Metadata-Version: 2.1\nName: {}\nVersion: {}\nSummary: {}\nLicense: MIT\nRequires-Python: >=3.8\n",
            d.name,
            d.version,
            d.summary()
        );
        for &j in &d.deps {
            let _ = writeln!(meta, "Requires-Dist: {}>={}", ds[j].name, ds[j].version);
        }
        meta.push_str("\nSynthetic long description.\n");
        t.write(&format!("{di}/METADATA"), meta)?;
        t.write(&format!("{di}/INSTALLER"), "uv\n")?;
        t.write(
            &format!("{di}/WHEEL"),
            "Wheel-Version: 1.0\nGenerator: bench\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )?;
        let init = format!(
            "\"\"\"{}\"\"\"\n__version__ = \"{}\"\n{}",
            d.name,
            d.version,
            gen::js_source(&d.name, &mut rng).replace("//", "#")
        );
        t.write(&format!("{SITE}/{}/__init__.py", d.dist()), &init)?;
        t.write(
            &format!("{di}/RECORD"),
            format!(
                "{0}/__init__.py,sha256={1},{2}\n{0}-{3}.dist-info/METADATA,,\n{0}-{3}.dist-info/RECORD,,\n",
                d.dist(),
                gen::sha256_base64(&init).trim_end_matches('='),
                init.len(),
                d.version
            ),
        )?;
    }
    Ok(())
}

/// A minimal but real wheel: uv's rewrite reads the patched wheel's
/// `METADATA`, so the mock serves this and the reference pins its sha256.
pub fn wheel_bytes(d: &Dist) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let di = format!("{}-{}.dist-info", d.dist(), d.version);
    w.start_file(format!("{}/__init__.py", d.dist()), opts)
        .unwrap();
    w.write_all(b"# patched\n").unwrap();
    w.start_file(format!("{di}/METADATA"), opts).unwrap();
    write!(
        w,
        "Metadata-Version: 2.1\nName: {}\nVersion: {}\nSummary: patched\n\n",
        d.name, d.version
    )
    .unwrap();
    w.start_file(format!("{di}/WHEEL"), opts).unwrap();
    w.write_all(
        b"Wheel-Version: 1.0\nGenerator: bench\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    )
    .unwrap();
    w.start_file(format!("{di}/RECORD"), opts).unwrap();
    w.write_all(b"").unwrap();
    w.finish().unwrap().into_inner()
}

/// One patch per patched distribution, with the canonical hosted wheel URL
/// `…/patch/pypi/<name>/<ver>/<token>/<uuid>/<wheel>`. Returns the specs and
/// the wheel bodies the artifact host serves.
pub fn patches(ds: &[Dist]) -> (Vec<PatchSpec>, Served) {
    let mut specs = Vec::new();
    let mut files = Vec::new();
    for d in ds.iter().filter(|d| d.patched) {
        let uuid = gen::uuid(&format!("patch:{}", d.purl()));
        let token = gen::uuid(&format!("grant:{uuid}"));
        let path = format!(
            "/patch/pypi/{}/{}/{token}/{uuid}/{}",
            d.name,
            d.version,
            d.wheel()
        );
        let url = format!("{PATCH_HOST}{path}");
        let wheel = wheel_bytes(d);
        let sha256 = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(&wheel))
        };
        files.push((path, wheel, "application/zip"));
        let file = format!("{}/__init__.py", d.dist());
        specs.push(PatchSpec {
            purl: d.purl(),
            view: super::npm::view_json(&uuid, &d.purl(), &file),
            reference: json!({
                "status": "granted",
                "url": url,
                "purl": d.purl(),
                "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": sha256 } }],
                "registryOverride": null,
            }),
            uuid,
            tier: "free",
            severity: "high",
        });
    }
    (specs, files)
}

fn fixture(ds: &[Dist], rewritten: &[&str], warnings: &[&'static str]) -> Fixture {
    let (patches, files) = patches(ds);
    Fixture {
        project: "project",
        expect: Expect {
            scanned: ds.len(),
            lockfile_only: 0,
            redirected: patches.len(),
            rewritten: rewritten.iter().map(|s| s.to_string()).collect(),
            // The venv still holds the unpatched files after a hosted scan
            // (a reinstall picks the patch up), and the wet run says so.
            allowed_warnings: [&["redirect_pypi_stale_install"][..], warnings].concat(),
            ..Expect::default()
        },
        patches,
        files,
        env_paths: Vec::new(),
        env: Vec::new(),
    }
}

fn pyproject(ds: &[Dist], extra: &str) -> String {
    let mut s = String::from("[project]\nname = \"bench-app\"\nversion = \"1.0.0\"\nrequires-python = \">=3.9\"\ndependencies = [\n");
    for d in ds.iter().filter(|d| d.direct) {
        let _ = writeln!(s, "    \"{}=={}\",", d.name, d.version);
    }
    s.push_str("]\n");
    s.push_str(extra);
    s
}

// ── pip / requirements.txt ─────────────────────────────────────────────

/// A `pip-compile --generate-hashes` style lock.
pub fn build_requirements(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let ds = dists("pip", size);
    let mut s = String::from("#\n# This file is autogenerated by pip-compile with Python 3.12\n# by the following command:\n#\n#    pip-compile --generate-hashes requirements.in\n#\n");
    for (i, d) in ds.iter().enumerate() {
        let _ = write!(
            s,
            "{}=={} \\\n    --hash=sha256:{} \\\n    --hash=sha256:{}\n",
            d.name,
            d.version,
            d.hash("whl"),
            d.hash("sdist")
        );
        let via: Vec<&str> = ds[..i]
            .iter()
            .filter(|p| p.deps.contains(&i))
            .map(|p| p.name.as_str())
            .take(3)
            .collect();
        if via.is_empty() {
            s.push_str("    # via -r requirements.in\n");
        } else {
            let _ = writeln!(s, "    # via {}", via.join(", "));
        }
    }
    t.write("project/requirements.txt", s)?;
    let direct: String = ds
        .iter()
        .filter(|d| d.direct)
        .map(|d| format!("{}\n", d.name))
        .collect();
    t.write("project/requirements.in", direct)?;
    install_venv(t, &ds)?;
    t.mkdir("home")?;
    Ok(fixture(&ds, &["requirements.txt"], &[]))
}

// ── uv ─────────────────────────────────────────────────────────────────

pub fn build_uv(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let ds = dists("uv", size);
    t.write("project/pyproject.toml", pyproject(&ds, ""))?;
    let mut s = String::from("version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"bench-app\"\nversion = \"1.0.0\"\nsource = { virtual = \".\" }\ndependencies = [\n");
    for d in ds.iter().filter(|d| d.direct) {
        let _ = writeln!(s, "    {{ name = \"{}\" }},", d.name);
    }
    s.push_str("]\n\n[package.metadata]\nrequires-dist = [");
    let reqs: Vec<String> = ds
        .iter()
        .filter(|d| d.direct)
        .map(|d| {
            format!(
                "{{ name = \"{}\", specifier = \"=={}\" }}",
                d.name, d.version
            )
        })
        .collect();
    s.push_str(&reqs.join(", "));
    s.push_str("]\n");
    let mut sorted: Vec<&Dist> = ds.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for d in sorted {
        let _ = write!(
            s,
            "\n[[package]]\nname = \"{}\"\nversion = \"{}\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n",
            d.name, d.version
        );
        if !d.deps.is_empty() {
            s.push_str("dependencies = [\n");
            for &j in &d.deps {
                let _ = writeln!(s, "    {{ name = \"{}\" }},", ds[j].name);
            }
            s.push_str("]\n");
        }
        let _ = write!(
            s,
            "sdist = {{ url = \"https://files.pythonhosted.org/packages/source/{0}/{1}\", hash = \"sha256:{2}\", size = 48213 }}\nwheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/py3/{0}/{3}\", hash = \"sha256:{4}\", size = 21877 }},\n]\n",
            &d.name[..4],
            d.sdist(),
            d.hash("sdist"),
            d.wheel(),
            d.hash("whl")
        );
    }
    t.write("project/uv.lock", s)?;
    install_venv(t, &ds)?;
    t.mkdir("home")?;
    Ok(fixture(&ds, &["pyproject.toml", "uv.lock"], &[]))
}

// ── PEP 751 pylock.toml ────────────────────────────────────────────────

pub fn build_pylock(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let ds = dists("pylock", size);
    t.write("project/pyproject.toml", pyproject(&ds, ""))?;
    let mut s =
        String::from("lock-version = \"1.0\"\ncreated-by = \"uv\"\nrequires-python = \">=3.9\"\n");
    for d in &ds {
        let _ = write!(
            s,
            "\n[[packages]]\nname = \"{0}\"\nversion = \"{1}\"\nindex = \"https://pypi.org/simple\"\nsdist = {{ url = \"https://files.pythonhosted.org/packages/source/{2}\", upload-time = 2024-05-01T00:00:00Z, size = 48213, hashes = {{ sha256 = \"{3}\" }} }}\nwheels = [{{ url = \"https://files.pythonhosted.org/packages/py3/{4}\", upload-time = 2024-05-01T00:00:00Z, size = 21877, hashes = {{ sha256 = \"{5}\" }} }}]\n",
            d.name,
            d.version,
            d.sdist(),
            d.hash("sdist"),
            d.wheel(),
            d.hash("whl")
        );
    }
    t.write("project/pylock.toml", s)?;
    install_venv(t, &ds)?;
    t.mkdir("home")?;
    Ok(fixture(&ds, &["pylock.toml"], &[]))
}

// ── poetry ─────────────────────────────────────────────────────────────

pub fn build_poetry(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let ds = dists("poetry", size);
    let mut py = String::from("[tool.poetry]\nname = \"bench-app\"\nversion = \"1.0.0\"\ndescription = \"\"\nauthors = []\npackage-mode = false\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n");
    for d in ds.iter().filter(|d| d.direct) {
        let _ = writeln!(py, "{} = \"{}\"", d.name, d.version);
    }
    py.push_str("\n[build-system]\nrequires = [\"poetry-core>=2.0.0\"]\nbuild-backend = \"poetry.core.masonry.api\"\n");
    t.write("project/pyproject.toml", py)?;
    t.write("project/poetry.toml", "[virtualenvs]\nin-project = true\n")?;
    let mut s = String::from("# This file is automatically @generated by Poetry 2.1.3 and should not be changed by hand.\n");
    let mut sorted: Vec<&Dist> = ds.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for d in sorted {
        let _ = write!(
            s,
            "\n[[package]]\nname = \"{}\"\nversion = \"{}\"\ndescription = \"{}\"\noptional = false\npython-versions = \">=3.8\"\ngroups = [\"main\"]\nfiles = [\n    {{file = \"{}\", hash = \"sha256:{}\"}},\n    {{file = \"{}\", hash = \"sha256:{}\"}},\n]\n",
            d.name,
            d.version,
            d.summary(),
            d.wheel(),
            d.hash("whl"),
            d.sdist(),
            d.hash("sdist")
        );
        if !d.deps.is_empty() {
            s.push_str("\n[package.dependencies]\n");
            for &j in &d.deps {
                let _ = writeln!(s, "{} = \">={}\"", ds[j].name, ds[j].version);
            }
        }
    }
    let _ = write!(
        s,
        "\n[metadata]\nlock-version = \"2.1\"\npython-versions = \"^3.9\"\ncontent-hash = \"{}\"\n",
        gen::sha256_hex("poetry-content")
    );
    t.write("project/poetry.lock", s)?;
    install_venv(t, &ds)?;
    t.mkdir("home")?;
    Ok(fixture(&ds, &["poetry.lock"], &[]))
}

// ── pipenv ─────────────────────────────────────────────────────────────

pub fn build_pipenv(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let ds = dists("pipenv", size);
    let mut pipfile = String::from("[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n[packages]\n");
    for d in ds.iter().filter(|d| d.direct) {
        let _ = writeln!(pipfile, "{} = \"=={}\"", d.name, d.version);
    }
    pipfile.push_str("\n[dev-packages]\n\n[requires]\npython_version = \"3.12\"\n");
    t.write("project/Pipfile", pipfile)?;
    let mut default = serde_json::Map::new();
    for d in &ds {
        default.insert(
            d.name.clone(),
            json!({
                "hashes": [format!("sha256:{}", d.hash("whl")), format!("sha256:{}", d.hash("sdist"))],
                "index": "pypi",
                "markers": "python_version >= '3.8'",
                "version": format!("=={}", d.version),
            }),
        );
    }
    let lock = json!({
        "_meta": {
            "hash": { "sha256": gen::sha256_hex("pipfile") },
            "pipfile-spec": 6,
            "requires": { "python_version": "3.12" },
            "sources": [{ "name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true }],
        },
        "default": default,
        "develop": {},
    });
    t.write("project/Pipfile.lock", pretty4(&lock) + "\n")?;
    install_venv(t, &ds)?;
    t.mkdir("home")?;
    let mut f = fixture(&ds, &["Pipfile.lock"], &[]);
    // Names the installer generation instead of spawning `pipenv
    // --version` (a Python start-up per scan that would time the runner's
    // pipenv, not socket-patch).
    f.env.push(("SOCKET_PIPENV_MAJOR", "2026".into()));
    Ok(f)
}

/// JSON with four-space indentation (Pipenv's and Composer's spelling).
pub fn pretty4(v: &serde_json::Value) -> String {
    use serde::Serialize as _;
    let mut out = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut out, fmt);
    v.serialize(&mut ser).unwrap();
    String::from_utf8(out).unwrap()
}

// ── pdm ────────────────────────────────────────────────────────────────

pub fn build_pdm(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let ds = dists("pdm", size);
    t.write(
        "project/pyproject.toml",
        pyproject(&ds, "\n[tool.pdm]\ndistribution = false\n"),
    )?;
    let mut s = format!(
        "# This file is @generated by PDM.\n# It is not intended for manual editing.\n\n[metadata]\ngroups = [\"default\"]\nstrategy = [\"inherit_metadata\"]\nlock_version = \"4.5.1\"\ncontent_hash = \"sha256:{}\"\n\n[[metadata.targets]]\nrequires_python = \">=3.9\"\n",
        gen::sha256_hex("pdm-content")
    );
    let mut sorted: Vec<&Dist> = ds.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    for d in sorted {
        let _ = write!(
            s,
            "\n[[package]]\nname = \"{}\"\nversion = \"{}\"\nrequires_python = \">=3.8\"\nsummary = \"{}\"\ngroups = [\"default\"]\n",
            d.name,
            d.version,
            d.summary()
        );
        if !d.deps.is_empty() {
            s.push_str("dependencies = [\n");
            for &j in &d.deps {
                let _ = writeln!(s, "    \"{}>={}\",", ds[j].name, ds[j].version);
            }
            s.push_str("]\n");
        }
        let _ = write!(
            s,
            "files = [\n    {{file = \"{}\", hash = \"sha256:{}\"}},\n    {{file = \"{}\", hash = \"sha256:{}\"}},\n]\n",
            d.wheel(),
            d.hash("whl"),
            d.sdist(),
            d.hash("sdist")
        );
    }
    t.write("project/pdm.lock", s)?;
    install_venv(t, &ds)?;
    t.mkdir("home")?;
    Ok(fixture(&ds, &["pdm.lock"], &[]))
}
