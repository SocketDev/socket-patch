//! Equivalence oracle for the hosted uv.lock / pylock / PEP 723 rewriter,
//! which now parses each lock once and plans, applies and completes every
//! dep against that one document. The previous implementation (three parses
//! and two renders per dep) is kept here verbatim, over the verbatim text
//! rewriters in `utils::python_lock::oracle`, and the production rewriter
//! must produce the identical output bytes, FileEdit list, warnings and
//! confirmed / refused sets on randomized locks — including CRLF and
//! mixed-ending locks, refusals in the middle of the dep list, duplicate
//! overrides and metadata completion.

use super::*;
use crate::utils::python_lock::oracle;

/// `rewrite_uv_lock` before the single-parse session, verbatim except for
/// the two text rewriters, which are their verbatim oracles.
fn rewrite_uv_lock_oracle(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    python_metadata: &BTreeMap<String, String>,
    result: &mut RewriteResult,
) {
    use crate::utils::python_lock::{is_python_lock_name, ArtifactSource};
    use oracle::{complete_python_lock_metadata, rewrite_python_lock};

    let locks: Vec<(&String, &String)> = files
        .iter()
        .filter(|(path, _)| is_python_lock_name(path))
        .collect();
    if locks.is_empty() {
        return;
    }
    let mut usable: Vec<(&DepOverride, &str)> = Vec::new();
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        result.python_lock_uuids.insert(dep.patch_uuid.clone());
        match dep.integrity.sha256.as_deref() {
            Some(sha256) => usable.push((dep, sha256)),
            None => result.warnings.push(RewriteWarning {
                code: "redirect_uv_missing_sha256".into(),
                detail: format!("{} has no sha256 integrity", dep.name),
            }),
        }
    }
    for (path, original) in locks {
        let mut content = original.clone();
        for &(dep, sha256) in &usable {
            let rewritten = match rewrite_python_lock(
                &content,
                &dep.name,
                &dep.version,
                ArtifactSource::Url(&dep.artifact_url),
                sha256,
            ) {
                Ok(Some(rewritten)) => rewritten,
                Ok(None) => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_uv_entry_not_found".into(),
                        detail: format!("no {path} archive entry for {}@{}", dep.name, dep.version),
                    });
                    continue;
                }
                Err(detail) => {
                    result
                        .refused_python_lock_uuids
                        .insert(dep.patch_uuid.clone());
                    result.warnings.push(RewriteWarning {
                        code: "redirect_uv_lock_unsupported".into(),
                        detail: format!("{path}: {detail}"),
                    });
                    continue;
                }
            };
            let (metadata_edit, project) =
                match plan_python_metadata(path, &content, files, dep, result) {
                    Ok(plan) => plan,
                    Err(warning) => {
                        result
                            .refused_python_lock_uuids
                            .insert(dep.patch_uuid.clone());
                        result.warnings.push(warning);
                        continue;
                    }
                };
            let rewritten = match complete_python_lock_metadata(
                &rewritten,
                project.as_deref(),
                &dep.name,
                &dep.version,
                ArtifactSource::Url(&dep.artifact_url),
                python_metadata.get(&dep.artifact_url).map(String::as_str),
            ) {
                Ok(rewritten) => rewritten,
                Err(detail) => {
                    result
                        .refused_python_lock_uuids
                        .insert(dep.patch_uuid.clone());
                    result.warnings.push(RewriteWarning {
                        code: "redirect_uv_metadata_unsupported".into(),
                        detail: format!("{path}: {detail}"),
                    });
                    continue;
                }
            };
            result
                .confirmed_python_lock_uuids
                .insert(dep.patch_uuid.clone());
            if let Some(edit) = metadata_edit {
                record_python_metadata_edit(edit, dep, result);
            }
            if rewritten != content {
                record_python_lock_edits(path, dep, &content, &rewritten, result);
                content = rewritten;
            }
        }
        if content != *original {
            result.files.insert(path.clone(), content);
        }
    }
}

fn assert_same(want: &RewriteResult, got: &RewriteResult, what: &str) {
    assert_eq!(got.files, want.files, "{what}: rewritten bytes");
    assert_eq!(got.edits.len(), want.edits.len(), "{what}: edit count");
    for (i, (g, w)) in got.edits.iter().zip(&want.edits).enumerate() {
        assert_eq!(g, w, "{what}: edit #{i}");
    }
    let warnings = |r: &RewriteResult| {
        r.warnings
            .iter()
            .map(|w| (w.code.clone(), w.detail.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(warnings(got), warnings(want), "{what}: warnings in order");
    assert_eq!(got.python_lock_uuids, want.python_lock_uuids, "{what}");
    assert_eq!(
        got.confirmed_python_lock_uuids, want.confirmed_python_lock_uuids,
        "{what}: confirmed"
    );
    assert_eq!(
        got.refused_python_lock_uuids, want.refused_python_lock_uuids,
        "{what}: refused"
    );
}

fn run_both(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    metadata: &BTreeMap<String, String>,
    what: &str,
) -> RewriteResult {
    let mut want = RewriteResult::default();
    rewrite_uv_lock_oracle(files, overrides, metadata, &mut want);
    let mut got = RewriteResult::default();
    rewrite_uv_lock(files, overrides, metadata, &mut got);
    assert_same(&want, &got, what);
    got
}

/// Deterministic xorshift64* — no `rand` dev-dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

const HEX: &str = "ccc9a9e0b18a5efc7038c504cfc580e47d2e02e5390f2e29cad833cbccb956b6";

/// A spelling of `pkg-<i>` that canonicalizes back to it.
fn spelling(i: usize, rng: &mut Rng) -> String {
    match rng.below(6) {
        0 => format!("Pkg_{i}"),
        1 => format!("pkg.{i}"),
        _ => format!("pkg-{i}"),
    }
}

fn version(rng: &mut Rng) -> &'static str {
    rng.pick(&["1.0.0", "1.0.0", "2.0.0", "0.9"])
}

fn registry_source(rng: &mut Rng) -> String {
    match rng.below(10) {
        0 => "{registry='https://pypi.org/simple'}".into(),
        1 => r#"{ git = "https://github.com/x/y?rev=1#abc" }"#.into(),
        2 => r#"{ url = "https://files.example/x-1.0.0.tar.gz" }"#.into(),
        _ => r#"{ registry = "https://pypi.org/simple" }"#.into(),
    }
}

fn dependencies(rng: &mut Rng, packages: &[(usize, &str)]) -> String {
    if packages.is_empty() || rng.chance(30) {
        return String::new();
    }
    let mut out = String::from("dependencies = [\n");
    for _ in 0..(1 + rng.below(4)) {
        let (i, v) = packages[rng.below(packages.len())];
        if rng.chance(50) {
            out.push_str(&format!(
                "    {{ name = \"{}\", version = \"{v}\", source = {} }},\n",
                spelling(i, rng),
                registry_source(rng)
            ));
        } else {
            out.push_str(&format!("    {{ name = \"pkg-{i}\" }},\n"));
        }
    }
    out.push_str("]\n");
    out
}

fn requirement_array(rng: &mut Rng, key: &str, pool: usize) -> String {
    let mut out = format!("{key} = [");
    for n in 0..(1 + rng.below(3)) {
        if n > 0 {
            out.push_str(", ");
        }
        let i = rng.below(pool);
        match rng.below(3) {
            0 => out.push_str(&format!("{{ name = \"pkg-{i}\" }}")),
            1 => out.push_str(&format!(
                "{{ name = \"{}\", specifier = \">=1\" }}",
                spelling(i, rng)
            )),
            _ => out.push_str(&format!(
                "{{ name = \"pkg-{i}\", specifier = \"==1.0.0\", marker = \"sys_platform == 'linux'\" }}"
            )),
        }
    }
    out.push_str("]\n");
    out
}

/// A native uv lock (`version = 1`, `[[package]]`), with an optional
/// manifest, a virtual/editable root carrying requirement metadata, and
/// registry / git / url / path entries.
fn native_lock(rng: &mut Rng, pool: usize, script: bool) -> String {
    let mut out = String::new();
    out.push_str(if rng.chance(5) {
        "version = 2\n"
    } else {
        "version = 1\n"
    });
    out.push_str("revision = 3\nrequires-python = \">=3.11\"\n");
    if script || rng.chance(40) {
        out.push_str("\n[manifest]\n");
        if script || rng.chance(30) {
            out.push_str(&requirement_array(rng, "requirements", pool));
        }
        if rng.chance(40) {
            out.push_str(&requirement_array(rng, "constraints", pool));
        }
        if rng.chance(20) {
            out.push_str(&requirement_array(rng, "build-constraints", pool));
        }
        match rng.below(6) {
            0 => out.push_str(&requirement_array(rng, "overrides", pool)),
            1 => out.push_str("overrides = \"not an array\"\n"),
            _ => {}
        }
    } else if rng.chance(3) {
        out.push_str("manifest = 1\n");
    }
    let mut packages: Vec<(usize, &str)> = Vec::new();
    for _ in 0..(3 + rng.below(12)) {
        packages.push((rng.below(pool), version(rng)));
    }
    if !script && rng.chance(80) {
        out.push_str("\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n");
        out.push_str(if rng.chance(70) {
            "source = { virtual = \".\" }\n"
        } else {
            "source = { editable = \".\" }\n"
        });
        out.push_str(&dependencies(rng, &packages));
        if rng.chance(80) {
            out.push_str("\n[package.metadata]\n");
            out.push_str(&requirement_array(rng, "requires-dist", pool));
            if rng.chance(50) {
                out.push_str("\n[package.metadata.requires-dev]\n");
                out.push_str(&requirement_array(rng, "dev", pool));
            }
        }
    }
    for &(i, v) in &packages.clone() {
        out.push_str(&format!(
            "\n[[package]]\nname = \"{}\"\nversion = \"{v}\"\n",
            spelling(i, rng)
        ));
        match rng.below(12) {
            0 => out.push_str("source = { git = \"https://github.com/x/y?rev=1#abc\" }\n"),
            1 => out.push_str("source = { path = \"vendor/x-1.0.0-py3-none-any.whl\" }\n"),
            2 => out.push_str("source = { url = \"https://files.example/x.tar.gz\" }\n"),
            3 => out.push_str("source = \"registry+https://pypi.org/simple\"\n"),
            4 => {}
            _ => out.push_str("source = { registry = \"https://pypi.org/simple\" }\n"),
        }
        out.push_str(&dependencies(rng, &packages));
        if rng.chance(70) {
            out.push_str(&format!(
                "sdist = {{ url = \"https://files.pythonhosted.org/pkg-{i}-{v}.tar.gz\", hash = \"sha256:{HEX}\", size = 12, upload-time = \"2024-01-01T00:00:00Z\" }}\n"
            ));
        }
        if rng.chance(80) {
            out.push_str(&format!(
                "wheels = [\n    {{ url = \"https://files.pythonhosted.org/pkg-{i}-{v}-py3-none-any.whl\", hash = \"sha256:{HEX}\", size = 10 }},\n]\n"
            ));
        }
        if rng.chance(15) {
            out.push_str("\n[package.optional-dependencies]\n");
            out.push_str(&format!(
                "extra = [{{ name = \"pkg-{}\" }}]\n",
                rng.below(pool)
            ));
        }
        if rng.chance(10) {
            out.push_str("\n[package.metadata]\nrequires-dist = [{ name = \"pkg-1\" }]\n");
        }
    }
    out
}

/// A PEP 751 pylock (`[[packages]]`).
fn pylock(rng: &mut Rng, pool: usize) -> String {
    let mut out = String::from(match rng.below(10) {
        0 => "lock-version = \"2.0\"\n",
        _ => "lock-version = \"1.0\"\n",
    });
    out.push_str("created-by = \"uv\"\nrequires-python = \">=3.11\"\n");
    for _ in 0..(3 + rng.below(10)) {
        let i = rng.below(pool);
        let v = version(rng);
        out.push_str(&format!(
            "\n[[packages]]\nname = \"{}\"\nversion = \"{v}\"\n",
            spelling(i, rng)
        ));
        match rng.below(10) {
            0 => out.push_str(
                "vcs = { type = \"git\", url = \"https://github.com/x/y\", commit-id = \"abc\" }\n",
            ),
            1 => out.push_str("directory = { path = \"libs/x\" }\n"),
            _ => out.push_str("index = \"https://pypi.org/simple\"\n"),
        }
        if rng.chance(60) {
            out.push_str(&format!(
                "sdist = {{ url = \"https://files.pythonhosted.org/pkg-{i}.tar.gz\", upload-time = 2024-01-01T00:00:00Z, size = 1, hashes = {{ sha256 = \"{HEX}\" }} }}\n"
            ));
        }
        out.push_str(&format!(
            "wheels = [{{ url = \"https://files.pythonhosted.org/pkg-{i}-py3-none-any.whl\", size = 1, hashes = {{ sha256 = \"{HEX}\" }} }}]\n"
        ));
    }
    out
}

/// A pre-0.2.35 `[[distribution]]` lock, in the string-source table shape
/// (`[[distribution.wheel]]` / `[distribution.sdist]`), the string-source
/// inline shape, or the inline-source shape.
fn distribution_lock(rng: &mut Rng, pool: usize) -> String {
    let mut out = String::from("version = 1\nrequires-python = \">=3.8\"\n");
    let shape = rng.below(3);
    for _ in 0..(3 + rng.below(8)) {
        let i = rng.below(pool);
        let v = version(rng);
        out.push_str(&format!(
            "\n[[distribution]]\nname = \"{}\"\nversion = \"{v}\"\n",
            spelling(i, rng)
        ));
        match shape {
            0 => {
                out.push_str("source = \"registry+https://pypi.org/simple\"\n");
                if rng.chance(50) {
                    out.push_str(&format!(
                        "\n[distribution.sdist]\nurl = \"https://files.pythonhosted.org/pkg-{i}.tar.gz\"\nhash = \"sha256:{HEX}\"\n"
                    ));
                }
                if rng.chance(70) {
                    out.push_str(&format!(
                        "\n[[distribution.wheel]]\nurl = \"https://files.pythonhosted.org/pkg-{i}-py3-none-any.whl\"\nhash = \"sha256:{HEX}\"\n"
                    ));
                }
            }
            1 => {
                out.push_str("source = \"registry+https://pypi.org/simple\"\n");
                out.push_str(&format!(
                    "wheels = [{{ url = \"https://files.pythonhosted.org/pkg-{i}-py3-none-any.whl\", hash = \"sha256:{HEX}\" }}]\n"
                ));
            }
            _ => {
                out.push_str("source = { registry = \"https://pypi.org/simple\" }\n");
                out.push_str(&format!(
                    "dependencies = [{{ name = \"pkg-{}\" }}]\n",
                    rng.below(pool)
                ));
                out.push_str(&format!(
                    "wheels = [{{ url = \"https://files.pythonhosted.org/pkg-{i}-py3-none-any.whl\", hash = \"sha256:{HEX}\" }}]\n"
                ));
            }
        }
    }
    out
}

fn pyproject(rng: &mut Rng, pool: usize) -> String {
    if rng.chance(4) {
        return "[project\n".into();
    }
    let mut out = String::from("[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [");
    for n in 0..(1 + rng.below(4)) {
        if n > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("\"pkg-{}>=1\"", rng.below(pool)));
    }
    out.push_str("]\n");
    if rng.chance(50) {
        out.push_str("\n[tool.uv]\noverride-dependencies = [");
        for n in 0..(1 + rng.below(3)) {
            if n > 0 {
                out.push_str(", ");
            }
            out.push_str(&format!("\"{}==1.0.0\"", spelling(rng.below(pool), rng)));
        }
        out.push_str("]\n");
    }
    if rng.chance(20) {
        out.push_str("\n[tool.uv.sources]\npkg-1 = { url = \"https://example.com/pkg-1.whl\" }\n");
    }
    out
}

fn script(rng: &mut Rng, pool: usize) -> String {
    if rng.chance(5) {
        return "print(1)\n".into();
    }
    format!(
        "# /// script\n# requires-python = \">=3.11\"\n# dependencies = [\"pkg-{}\", \"pkg-{}\"]\n# ///\nimport sys\n",
        rng.below(pool),
        rng.below(pool)
    )
}

/// CRLF everywhere, CRLF on some lines only (mixed), or LF.
fn line_endings(text: String, rng: &mut Rng) -> String {
    match rng.below(4) {
        0 => text.replace('\n', "\r\n"),
        1 => text
            .split_inclusive('\n')
            .enumerate()
            .map(|(i, line)| {
                if i % 3 == 0 {
                    line.replace('\n', "\r\n")
                } else {
                    line.to_string()
                }
            })
            .collect(),
        _ => text,
    }
}

fn dep(i: usize, v: &str, uuid: usize, rng: &mut Rng) -> DepOverride {
    let ext = match rng.below(12) {
        0 => ".tar.gz",
        1 => ".txt",
        _ => "-py3-none-any.whl",
    };
    DepOverride {
        ecosystem: if rng.chance(3) { "npm" } else { "pypi" }.into(),
        name: spelling(i, rng),
        namespace: None,
        version: v.to_string(),
        token: String::new(),
        patch_uuid: format!("00000000-0000-4000-8000-{uuid:012}"),
        artifact_url: format!(
            "https://patch.socket.dev/patch/{uuid}/pkg-{i}-{v}{ext}{}",
            if rng.chance(10) { "?token=x#frag" } else { "" }
        ),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha256: (!rng.chance(5)).then(|| HEX.to_string()),
            ..Default::default()
        },
    }
}

fn wheel_metadata(rng: &mut Rng, pool: usize) -> String {
    match rng.below(8) {
        0 => "[package.metadata\n".into(),
        1 => "[tool]\nx = 1\n".into(),
        2 => "[package.metadata]\nrequires-dist = []".into(),
        _ => format!(
            "[package.metadata]\nrequires-dist = [\n    {{ name = \"pkg-{}\", specifier = \">=1\" }},\n    {{ name = \"pkg-{}\", marker = \"extra == 'x'\" }},\n]\nprovides-extras = [\"x\"]",
            rng.below(pool),
            rng.below(pool)
        ),
    }
}

type Case = (
    BTreeMap<String, String>,
    Vec<DepOverride>,
    BTreeMap<String, String>,
);

fn case(seed: u64) -> Case {
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let pool = 4 + rng.below(10);
    let mut files = BTreeMap::new();
    let mut any = false;
    if rng.chance(70) {
        let mut lock = native_lock(&mut rng, pool, false);
        if rng.chance(3) {
            lock.push_str("\n[[package]\nbroken");
        }
        files.insert("uv.lock".to_string(), line_endings(lock, &mut rng));
        if rng.chance(80) {
            let project = pyproject(&mut rng, pool);
            files.insert("pyproject.toml".into(), line_endings(project, &mut rng));
        }
        any = true;
    }
    if rng.chance(30) || !any {
        let lock = match rng.below(3) {
            0 => distribution_lock(&mut rng, pool),
            _ => pylock(&mut rng, pool),
        };
        let name = if rng.chance(70) {
            "pylock.toml"
        } else {
            "pylock.dev.toml"
        };
        files.insert(name.to_string(), line_endings(lock, &mut rng));
    }
    if rng.chance(30) {
        let lock = native_lock(&mut rng, pool, true);
        files.insert("tool.py.lock".into(), line_endings(lock, &mut rng));
        if rng.chance(85) {
            let script = script(&mut rng, pool);
            files.insert("tool.py".into(), line_endings(script, &mut rng));
        }
    }
    if rng.chance(20) {
        let lock = distribution_lock(&mut rng, pool);
        files.insert("old.py.lock".into(), line_endings(lock, &mut rng));
    }
    let mut overrides = Vec::new();
    let mut metadata = BTreeMap::new();
    for n in 0..(1 + rng.below(10)) {
        let i = rng.below(pool + 2);
        let v = version(&mut rng);
        let d = dep(i, v, n, &mut rng);
        if rng.chance(50) {
            metadata.insert(d.artifact_url.clone(), wheel_metadata(&mut rng, pool));
        }
        if rng.chance(15) {
            // The same name@version again under another uuid: a later dep
            // re-reads an entry an earlier dep already rewrote.
            let mut again = d.clone();
            again.patch_uuid = format!("00000000-0000-4000-8000-{:012}", n + 100);
            overrides.push(d);
            overrides.push(again);
        } else {
            overrides.push(d);
        }
    }
    (files, overrides, metadata)
}

#[test]
fn single_parse_uv_rewrite_matches_oracle() {
    let mut rewritten = 0;
    let mut edits = 0;
    let mut codes = std::collections::BTreeSet::new();
    for seed in 1..=1500u64 {
        let (files, overrides, metadata) = case(seed);
        let got = run_both(&files, &overrides, &metadata, &format!("seed {seed}"));
        rewritten += got.files.len();
        edits += got.edits.len();
        codes.extend(got.warnings.iter().map(|w| w.code.clone()));
    }
    // The generator must actually reach the rewrite paths and every refusal,
    // or the oracle compares nothing.
    assert!(rewritten > 300, "only {rewritten} rewritten files");
    assert!(edits > 1000, "only {edits} edits");
    for code in [
        "redirect_uv_missing_sha256",
        "redirect_uv_entry_not_found",
        "redirect_uv_lock_unsupported",
        "redirect_uv_metadata_unsupported",
        "redirect_uv_project_unsupported",
        "redirect_uv_script_unsupported",
        "redirect_uv_script_missing",
    ] {
        assert!(codes.contains(code), "no case reached {code}: {codes:?}");
    }
}

/// A refusal between two rewritten deps must leave the lock exactly as the
/// first dep left it — the session decides every refusal before mutating.
#[test]
fn refusal_in_the_middle_leaves_the_prior_rewrite_intact() {
    let lock = "version = 1\nrevision = 3\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [{ name = \"a\" }, { name = \"b\" }, { name = \"c\" }]\n\n[package.metadata]\nrequires-dist = [{ name = \"a\" }, { name = \"b\" }, { name = \"c\" }]\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [{ url = \"https://files.pythonhosted.org/a-1.0.0-py3-none-any.whl\", hash = \"sha256:00\" }]\n\n[[package]]\nname = \"b\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [{ url = \"https://files.pythonhosted.org/b-1.0.0-py3-none-any.whl\", hash = \"sha256:00\" }]\n\n[[package]]\nname = \"c\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nwheels = [{ url = \"https://files.pythonhosted.org/c-1.0.0-py3-none-any.whl\", hash = \"sha256:00\" }]\n";
    let project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"a\", \"b\", \"c\"]\n\n[tool.uv]\noverride-dependencies = [\"b==1.0.0\"]\n";
    let mk = |name: &str, n: usize| DepOverride {
        ecosystem: "pypi".into(),
        name: name.into(),
        namespace: None,
        version: "1.0.0".into(),
        token: String::new(),
        patch_uuid: format!("00000000-0000-4000-8000-{n:012}"),
        artifact_url: format!("https://patch.socket.dev/{name}-1.0.0-py3-none-any.whl"),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha256: Some(HEX.into()),
            ..Default::default()
        },
    };
    let overrides = vec![mk("a", 1), mk("b", 2), mk("c", 3)];
    for (lock, project) in [
        (lock.to_string(), project.to_string()),
        (lock.replace('\n', "\r\n"), project.replace('\n', "\r\n")),
    ] {
        let mut files = BTreeMap::new();
        files.insert("uv.lock".to_string(), lock.clone());
        files.insert("pyproject.toml".to_string(), project);
        // b's wheel metadata is unparseable: b is refused after a is applied.
        let mut metadata = BTreeMap::new();
        metadata.insert(overrides[1].artifact_url.clone(), "[broken".to_string());
        let got = run_both(&files, &overrides, &metadata, "b refused");
        assert!(got
            .refused_python_lock_uuids
            .contains(&overrides[1].patch_uuid));
        assert_eq!(got.confirmed_python_lock_uuids.len(), 2);
        let out = &got.files["uv.lock"];
        assert!(out.contains("https://patch.socket.dev/a-1.0.0"), "{out}");
        assert!(!out.contains("https://patch.socket.dev/b-1.0.0"), "{out}");
        assert!(out.contains("https://patch.socket.dev/c-1.0.0"), "{out}");
        // b's manifest override (the refused completion's only other write)
        // never landed.
        assert!(!out.contains("[manifest]"), "{out}");
        assert_eq!(lock.contains('\r'), out.contains('\r'));

        // An existing non-array `overrides` refuses b the same way.
        let mut files = files.clone();
        let with_manifest = lock.replacen(
            "revision = 3",
            "revision = 3\n\n[manifest]\noverrides = 1",
            1,
        );
        files.insert("uv.lock".to_string(), with_manifest);
        let got = run_both(&files, &overrides, &BTreeMap::new(), "bad overrides");
        assert!(got
            .refused_python_lock_uuids
            .contains(&overrides[1].patch_uuid));
    }
}

/// Runs the oracle over the Phase 3 benchmark fixtures (real ~1.9 MB uv,
/// pylock and PEP 723 locks, too large to commit) when
/// `SOCKET_PATCH_PY_LOCK_FIXTURES` names their directory; a no-op otherwise.
#[test]
fn single_parse_uv_rewrite_matches_oracle_on_fixture_locks() {
    let Some(root) = std::env::var_os("SOCKET_PATCH_PY_LOCK_FIXTURES") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    for (dir, lock, metadata_file) in [
        ("uv-big", "uv.lock", Some("pyproject.toml")),
        ("pylock-big", "pylock.toml", None),
        ("script-big", "tool.py.lock", Some("tool.py")),
    ] {
        let read = |name: &str| std::fs::read_to_string(root.join(dir).join(name)).unwrap();
        let text = read(lock);
        let names: Vec<(String, String)> = {
            let doc: toml_edit::DocumentMut = text.parse().unwrap();
            let collection = if lock == "pylock.toml" {
                "packages"
            } else {
                "package"
            };
            doc[collection]
                .as_array_of_tables()
                .unwrap()
                .iter()
                .filter_map(|t| {
                    Some((
                        t.get("name")?.as_str()?.to_string(),
                        t.get("version")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        };
        for crlf in [false, true] {
            let conv = |s: String| if crlf { s.replace('\n', "\r\n") } else { s };
            let mut files = BTreeMap::new();
            files.insert(lock.to_string(), conv(text.clone()));
            if let Some(m) = metadata_file {
                files.insert(m.to_string(), conv(read(m)));
            }
            let mut rng = Rng(0x5eed + crlf as u64);
            let mut overrides = Vec::new();
            let mut metadata = BTreeMap::new();
            for (n, (name, version)) in names.iter().step_by(29).enumerate() {
                let mut d = dep(0, version, n, &mut rng);
                d.ecosystem = "pypi".into();
                d.name = name.clone();
                d.artifact_url =
                    format!("https://patch.socket.dev/patch/{n}/{name}-{version}-py3-none-any.whl");
                if n % 3 == 0 {
                    metadata.insert(d.artifact_url.clone(), wheel_metadata(&mut rng, 5));
                }
                overrides.push(d);
            }
            let got = run_both(&files, &overrides, &metadata, &format!("{dir} crlf={crlf}"));
            assert!(!got.edits.is_empty(), "{dir}: nothing rewritten");
        }
    }
}
