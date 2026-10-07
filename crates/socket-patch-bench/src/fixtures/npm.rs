//! npm-family projects. One deterministic dependency graph is written out
//! as each package manager's lockfile and install layout, so the seven
//! scenarios differ only in what each package manager puts on disk.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{json, Value};

use super::gen::{self, Rng, Tree};
use super::{Expect, Fixture, Size, PATCH_HOST};
use crate::mock::PatchSpec;

/// One installed npm package.
#[derive(Debug, Clone)]
pub struct Pkg {
    /// `name` or `@scope/name`.
    pub name: String,
    pub version: String,
    /// Hoisted install path (`node_modules/a`), or nested under its only
    /// dependent (`node_modules/p/node_modules/a`) for a second version.
    pub path: String,
    /// The package's dependencies, by name, each resolving to another
    /// package of the graph at that version.
    pub deps: BTreeMap<String, String>,
    pub patched: bool,
}

impl Pkg {
    /// The crawler's spelling: a scope stays a literal `@`.
    pub fn purl(&self) -> String {
        format!("pkg:npm/{}@{}", self.name, self.version)
    }

    pub fn basename(&self) -> &str {
        self.name.rsplit('/').next().unwrap()
    }

    pub fn is_nested(&self) -> bool {
        self.path.matches("node_modules/").count() > 1
    }

    /// The hoisted parent's name for a nested package.
    pub fn parent_name(&self) -> Option<&str> {
        let inner = self.path.strip_prefix("node_modules/")?;
        let (parent, _) = inner.split_once("/node_modules/")?;
        Some(parent)
    }

    pub fn registry_tarball(&self, registry: &str) -> String {
        format!(
            "{registry}/{}/-/{}-{}.tgz",
            self.name,
            self.basename(),
            self.version
        )
    }

    pub fn integrity(&self) -> String {
        gen::sri_sha512(&format!("npm:{}@{}", self.name, self.version))
    }

    pub fn sha1(&self) -> String {
        gen::sha1_hex(&format!("npm:{}@{}", self.name, self.version))
    }

    /// `<name>@<version>` with pnpm's `+` for the scope slash, as pnpm and
    /// vlt spell store directories.
    pub fn store_key(&self) -> String {
        format!("{}@{}", self.name.replace('/', "+"), self.version)
    }
}

/// The project graph.
pub struct Graph {
    pub pkgs: Vec<Pkg>,
}

/// A deterministic graph of `size.packages` installed packages: about one
/// in fifteen scoped, one in twenty a second version of a hoisted package
/// installed nested under its dependent (the layout a version conflict
/// produces), and each package depending on up to four later packages (an
/// acyclic graph, like most real trees). The first tenth are the root's
/// direct dependencies.
pub fn graph(seed: &str, size: Size) -> Graph {
    let mut rng = Rng::new(seed);
    let n = size.packages;
    let dups = n / 20;
    let hoisted = n - dups;
    let mut pkgs: Vec<Pkg> = Vec::with_capacity(n);
    for i in 0..hoisted {
        let base = gen::ident(&mut rng, i);
        let name = if rng.chance(1.0 / 15.0) {
            format!("@{}/{base}", gen::ident(&mut rng, i))
        } else {
            base
        };
        pkgs.push(Pkg {
            path: format!("node_modules/{name}"),
            name,
            version: gen::version(&mut rng),
            deps: BTreeMap::new(),
            patched: false,
        });
    }
    for i in 0..hoisted {
        for _ in 0..rng.below(5) {
            if i + 1 >= hoisted {
                break;
            }
            let j = i + 1 + rng.below((hoisted - i - 1).min(200));
            let (name, version) = (pkgs[j].name.clone(), pkgs[j].version.clone());
            pkgs[i].deps.entry(name).or_insert(version);
        }
    }
    // Second versions: the copy of a later package that one earlier
    // package needs at a different version, nested under that package.
    for k in 0..dups {
        let target = hoisted / 2 + (k * (hoisted / 2)) / dups.max(1);
        let parent = rng.below(target.max(1));
        let mut version = gen::version(&mut rng);
        if version == pkgs[target].version {
            version.push_str("-next.1");
        }
        if pkgs[parent].deps.contains_key(&pkgs[target].name)
            || pkgs[hoisted..].iter().any(|d| d.name == pkgs[target].name)
        {
            // Keep one nested copy per name and parent; fill the slot with
            // another unique package instead.
            let name = format!("{}-alt{k}", pkgs[target].name);
            pkgs.push(Pkg {
                path: format!("{}/node_modules/{name}", pkgs[parent].path),
                name: name.clone(),
                version: version.clone(),
                deps: BTreeMap::new(),
                patched: false,
            });
            pkgs[parent].deps.insert(name, version);
            continue;
        }
        let name = pkgs[target].name.clone();
        pkgs.push(Pkg {
            path: format!("{}/node_modules/{name}", pkgs[parent].path),
            name: name.clone(),
            version: version.clone(),
            deps: BTreeMap::new(),
            patched: false,
        });
        pkgs[parent].deps.insert(name, version);
    }
    for (i, p) in pkgs.iter_mut().enumerate() {
        p.patched = size.is_patched(i);
    }
    Graph { pkgs }
}

impl Graph {
    fn direct(&self) -> impl Iterator<Item = &Pkg> {
        let n = (self.pkgs.len() / 10).max(1);
        self.pkgs[..n].iter().filter(|p| !p.is_nested())
    }

    pub fn root_deps(&self) -> BTreeMap<String, String> {
        self.direct()
            .map(|p| (p.name.clone(), format!("^{}", p.version)))
            .collect()
    }

    pub fn package_json(&self) -> String {
        let v = json!({
            "name": "bench-app",
            "version": "1.0.0",
            "private": true,
            "dependencies": self.root_deps(),
        });
        serde_json::to_string_pretty(&v).unwrap() + "\n"
    }

    /// Lay every package down at its npm path under `prefix`.
    pub fn install_hoisted(&self, t: &mut Tree, prefix: &str) -> std::io::Result<()> {
        let mut rng = Rng::new("npm-install");
        for p in &self.pkgs {
            write_package(t, &format!("{prefix}{}", p.path), p, &mut rng)?;
        }
        Ok(())
    }

    /// Patches with npm-style artifact URLs.
    pub fn patches(&self, berry: bool) -> Vec<PatchSpec> {
        self.pkgs
            .iter()
            .filter(|p| p.patched)
            .map(|p| npm_patch(p, berry))
            .collect()
    }

    /// The package `name` resolves to from `from` (its nested copy if it
    /// has one, else the hoisted one).
    fn resolve<'a>(&'a self, from: &Pkg, name: &str, version: &str) -> Option<&'a Pkg> {
        self.pkgs.iter().find(|p| {
            p.name == name
                && p.version == version
                && (p.parent_name() == Some(&from.name) || !p.is_nested())
        })
    }
}

pub fn write_package(t: &mut Tree, dir: &str, p: &Pkg, rng: &mut Rng) -> std::io::Result<()> {
    let manifest = json!({
        "name": p.name,
        "version": p.version,
        "description": format!("synthetic package {}", p.name),
        "main": "index.js",
        "license": "MIT",
        "dependencies": p.deps.iter().map(|(k, v)| (k.clone(), format!("^{v}"))).collect::<BTreeMap<_, _>>(),
    });
    t.write(
        &format!("{dir}/package.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )?;
    t.write(&format!("{dir}/index.js"), gen::js_source(&p.name, rng))?;
    if rng.chance(0.5) {
        t.write(
            &format!("{dir}/README.md"),
            format!("# {}\n\nSynthetic.\n", p.name),
        )?;
    }
    Ok(())
}

/// The bytes the artifact host serves for a patched package (only vlt's
/// preflight downloads them; the hash is what matters).
pub fn artifact_bytes(p: &Pkg) -> Vec<u8> {
    format!("patched tarball for {}@{}\n", p.name, p.version).into_bytes()
}

fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
    )
}

/// A patch for `p`, served at the canonical hosted URL shape
/// `…/patch/npm/<name>/<version>/<token>/<uuid>/<basename>-<version>.tgz`.
pub fn npm_patch(p: &Pkg, berry: bool) -> PatchSpec {
    let uuid = gen::uuid(&format!("patch:{}", p.purl()));
    let token = gen::uuid(&format!("grant:{uuid}"));
    let url = format!("{PATCH_HOST}{}", artifact_path(p, &token, &uuid));
    let seed = format!("patched:{}@{}", p.name, p.version);
    let mut artifacts = vec![json!({
        "kind": "tarball",
        "url": url,
        "integrity": {
            "sha512": sri_of(&artifact_bytes(p)),
            "sha1": gen::sha1_hex(&seed),
            "sha256": gen::sha256_hex(&seed),
        },
    })];
    if berry {
        artifacts.push(json!({
            "kind": "yarn-berry-zip",
            "url": null,
            "integrity": { "yarnBerry10c0": format!("10c0/{}", gen::sha512_hex(&seed)) },
        }));
    }
    PatchSpec {
        purl: p.purl(),
        view: view_json(&uuid, &p.purl(), "package/index.js"),
        reference: json!({
            "status": "granted",
            "url": url,
            "purl": p.purl(),
            "artifacts": artifacts,
            "registryOverride": null,
        }),
        uuid,
        tier: "free",
        severity: "high",
    }
}

pub fn artifact_path(p: &Pkg, token: &str, uuid: &str) -> String {
    format!(
        "/patch/npm/{}/{}/{token}/{uuid}/{}-{}.tgz",
        p.name,
        p.version,
        p.basename(),
        p.version
    )
}

/// A `PatchResponse` for the view endpoint (one patched file).
pub fn view_json(uuid: &str, purl: &str, file: &str) -> Value {
    json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2024-06-01T00:00:00Z",
        "files": {
            file: {
                "beforeHash": gen::sha256_hex(&format!("before:{purl}")),
                "afterHash": gen::sha256_hex(&format!("after:{purl}")),
            }
        },
        "vulnerabilities": {
            format!("GHSA-{}", &gen::sha1_hex(purl)[..14]): {
                "cves": ["CVE-2024-0001"],
                "summary": "synthetic vulnerability",
                "severity": "high",
                "description": "synthetic",
            }
        },
        "description": "synthetic patch",
        "license": "MIT",
        "tier": "free",
    })
}

fn fixture(
    g: &Graph,
    patches: Vec<PatchSpec>,
    rewritten: &[&str],
    warnings: &[&'static str],
) -> Fixture {
    Fixture {
        project: "project",
        expect: Expect {
            scanned: g.pkgs.len(),
            lockfile_only: 0,
            redirected: patches.len(),
            rewritten: rewritten.iter().map(|s| s.to_string()).collect(),
            allowed_warnings: warnings.to_vec(),
            rescan_lockfile_only: 0,
            rescan_extra_scanned: 0,
        },
        patches,
        files: Vec::new(),
        env_paths: Vec::new(),
        env: Vec::new(),
    }
}

// ── npm ────────────────────────────────────────────────────────────────

/// `package-lock.json` (lockfileVersion 3).
pub fn package_lock(g: &Graph) -> String {
    let mut packages = serde_json::Map::new();
    packages.insert(
        String::new(),
        json!({ "name": "bench-app", "version": "1.0.0", "dependencies": g.root_deps() }),
    );
    let mut sorted: Vec<&Pkg> = g.pkgs.iter().collect();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    for p in sorted {
        let mut e = json!({
            "version": p.version,
            "resolved": p.registry_tarball("https://registry.npmjs.org"),
            "integrity": p.integrity(),
            "license": "MIT",
        });
        if !p.deps.is_empty() {
            e["dependencies"] = json!(p
                .deps
                .iter()
                .map(|(k, v)| (k.clone(), format!("^{v}")))
                .collect::<BTreeMap<_, _>>());
        }
        packages.insert(p.path.clone(), e);
    }
    let lock = json!({
        "name": "bench-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": packages,
    });
    serde_json::to_string_pretty(&lock).unwrap() + "\n"
}

pub fn build_npm(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("npm", size);
    t.write("project/package.json", g.package_json())?;
    let lock = package_lock(&g);
    t.write("project/package-lock.json", &lock)?;
    // npm's hidden lockfile, as `npm install` leaves it.
    t.write("project/node_modules/.package-lock.json", &lock)?;
    g.install_hoisted(t, "project/")?;
    t.mkdir("home")?;
    Ok(fixture(
        &g,
        g.patches(false),
        &["package-lock.json", ".npmrc"],
        &["redirect_npm_allow_remote"],
    ))
}

// ── pnpm ───────────────────────────────────────────────────────────────

fn yaml_key(s: &str) -> String {
    if s.starts_with('@') {
        format!("'{s}'")
    } else {
        s.to_string()
    }
}

/// `pnpm-lock.yaml` (lockfileVersion 9.0, pnpm 9-10).
pub fn pnpm_lock(g: &Graph) -> String {
    let mut s = String::from(
        "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n",
    );
    for p in g.direct() {
        let _ = write!(
            s,
            "      {}:\n        specifier: ^{}\n        version: {}\n",
            yaml_key(&p.name),
            p.version,
            p.version
        );
    }
    let mut sorted: Vec<&Pkg> = g.pkgs.iter().collect();
    sorted.sort_by_key(|p| format!("{}@{}", p.name, p.version));
    s.push_str("\npackages:\n");
    for p in &sorted {
        let _ = write!(
            s,
            "\n  {}:\n    resolution: {{integrity: {}}}\n",
            yaml_key(&format!("{}@{}", p.name, p.version)),
            p.integrity()
        );
        if p.version.starts_with('0') {
            s.push_str("    engines: {node: '>=12'}\n");
        }
    }
    s.push_str("\nsnapshots:\n");
    for p in &sorted {
        let key = yaml_key(&format!("{}@{}", p.name, p.version));
        if p.deps.is_empty() {
            let _ = writeln!(s, "\n  {key}: {{}}");
        } else {
            let _ = write!(s, "\n  {key}:\n    dependencies:\n");
            for (d, v) in &p.deps {
                let _ = writeln!(s, "      {}: {v}", yaml_key(d));
            }
        }
    }
    s
}

/// pnpm's isolated layout: every package is a real directory in the
/// virtual store, its dependencies are symlinks beside it, and only the
/// root's direct dependencies are linked into `node_modules/`.
pub fn build_pnpm(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("pnpm", size);
    t.write("project/package.json", g.package_json())?;
    t.write("project/pnpm-lock.yaml", pnpm_lock(&g))?;
    let mut rng = Rng::new("pnpm-install");
    let mut lock_yaml = String::from("lockfileVersion: '9.0'\n");
    for p in &g.pkgs {
        let entry = format!("project/node_modules/.pnpm/{}/node_modules", p.store_key());
        write_package(t, &format!("{entry}/{}", p.name), p, &mut rng)?;
        for (d, v) in &p.deps {
            let Some(dep) = g.resolve(p, d, v) else {
                continue;
            };
            let up = "../".repeat(1 + d.matches('/').count());
            let target = format!("{up}../{}/node_modules/{d}", dep.store_key());
            t.symlink(&target, &format!("{entry}/{d}"))?;
        }
        let _ = writeln!(lock_yaml, "# {}", p.store_key());
    }
    for p in g.direct() {
        let up = "../".repeat(p.name.matches('/').count());
        t.symlink(
            &format!("{up}.pnpm/{}/node_modules/{}", p.store_key(), p.name),
            &format!("project/node_modules/{}", p.name),
        )?;
    }
    t.write(
        "project/node_modules/.modules.yaml",
        "layoutVersion: 5\nnodeLinker: isolated\npackageManager: pnpm@9.15.0\n",
    )?;
    t.write("project/node_modules/.pnpm/lock.yaml", pnpm_lock(&g))?;
    t.mkdir("home")?;
    Ok(fixture(
        &g,
        g.patches(false),
        &["pnpm-lock.yaml", "pnpm-workspace.yaml"],
        &["redirect_pnpm_trust_lockfile"],
    ))
}

// ── yarn classic ───────────────────────────────────────────────────────

fn yarn_key(name: &str, range: &str) -> String {
    let k = format!("{name}@{range}");
    if name.starts_with('@') {
        format!("\"{k}\"")
    } else {
        k
    }
}

/// `yarn.lock` v1.
pub fn yarn_classic_lock(g: &Graph) -> String {
    let mut s = String::from(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1\n\n",
    );
    let mut sorted: Vec<&Pkg> = g.pkgs.iter().collect();
    sorted.sort_by_key(|p| format!("{}@{}", p.name, p.version));
    for p in sorted {
        let _ = write!(
            s,
            "\n{}:\n  version \"{}\"\n  resolved \"{}#{}\"\n  integrity {}\n",
            yarn_key(&p.name, &format!("^{}", p.version)),
            p.version,
            p.registry_tarball("https://registry.yarnpkg.com"),
            p.sha1(),
            p.integrity()
        );
        if !p.deps.is_empty() {
            s.push_str("  dependencies:\n");
            for (d, v) in &p.deps {
                let d = if d.starts_with('@') {
                    format!("\"{d}\"")
                } else {
                    d.clone()
                };
                let _ = writeln!(s, "    {d} \"^{v}\"");
            }
        }
    }
    s
}

pub fn build_yarn_classic(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("yarn-classic", size);
    // Pin yarn 1 as a real classic project does: without the pin a hosted
    // scan rightly warns `redirect_yarn_classic_berry_migration_risk`
    // (#907), which the scenario would count as an unexpected warning.
    t.write(
        "project/package.json",
        g.package_json().replacen(
            "\"private\": true",
            "\"private\": true,\n  \"packageManager\": \"yarn@1.22.22\"",
            1,
        ),
    )?;
    t.write("project/yarn.lock", yarn_classic_lock(&g))?;
    t.write(
        "project/node_modules/.yarn-integrity",
        "{\n  \"systemParams\": \"linux-x64-127\",\n  \"modulesFolders\": [\"node_modules\"]\n}\n",
    )?;
    g.install_hoisted(t, "project/")?;
    t.mkdir("home")?;
    Ok(fixture(&g, g.patches(false), &["yarn.lock"], &[]))
}

// ── yarn berry ─────────────────────────────────────────────────────────

/// `yarn.lock` for yarn 4 (`__metadata` version 8, cacheKey 10c0).
pub fn yarn_berry_lock(g: &Graph) -> String {
    let mut s = String::from(
        "# This file is generated by running \"yarn install\" inside your project.\n# Manual changes might be lost - proceed with caution!\n\n__metadata:\n  version: 8\n  cacheKey: 10c0\n",
    );
    let mut entries: Vec<(String, String)> = Vec::new();
    for p in &g.pkgs {
        let mut e = format!(
            "  version: {}\n  resolution: \"{}@npm:{}\"\n",
            p.version, p.name, p.version
        );
        if !p.deps.is_empty() {
            e.push_str("  dependencies:\n");
            for (d, v) in &p.deps {
                let _ = writeln!(
                    e,
                    "    {}: \"npm:^{v}\"",
                    if d.starts_with('@') {
                        format!("\"{d}\"")
                    } else {
                        d.clone()
                    }
                );
            }
        }
        let _ = write!(
            e,
            "  checksum: 10c0/{}\n  languageName: node\n  linkType: hard\n",
            gen::sha512_hex(&format!("berry:{}@{}", p.name, p.version))
        );
        entries.push((format!("\"{}@npm:^{}\"", p.name, p.version), e));
    }
    let mut root = String::from(
        "  version: 0.0.0-use.local\n  resolution: \"bench-app@workspace:.\"\n  dependencies:\n",
    );
    for (d, r) in g.root_deps() {
        let _ = writeln!(
            root,
            "    {}: \"npm:{r}\"",
            if d.starts_with('@') {
                format!("\"{d}\"")
            } else {
                d
            }
        );
    }
    root.push_str("  languageName: unknown\n  linkType: soft\n");
    entries.push(("\"bench-app@workspace:.\"".into(), root));
    entries.sort();
    for (k, e) in entries {
        let _ = write!(s, "\n{k}:\n{e}");
    }
    s
}

pub fn build_yarn_berry(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("yarn-berry", size);
    t.write(
        "project/package.json",
        g.package_json().replacen(
            "\"private\": true",
            "\"private\": true,\n  \"packageManager\": \"yarn@4.5.0\"",
            1,
        ),
    )?;
    t.write("project/yarn.lock", yarn_berry_lock(&g))?;
    t.write(
        "project/.yarnrc.yml",
        "nodeLinker: node-modules\nenableGlobalCache: false\n",
    )?;
    t.write("project/node_modules/.yarn-state.yml", "# Warning: This file is automatically generated. Removing it is fine, but will\n# cause your node_modules installation to become invalidated.\n\n__metadata:\n  version: 1\n  nmMode: classic\n")?;
    g.install_hoisted(t, "project/")?;
    t.mkdir("home")?;
    // Hosted Berry pins both descriptor resolutions and their lock entries.
    Ok(fixture(
        &g,
        g.patches(true),
        &["package.json", "yarn.lock"],
        &[],
    ))
}

// ── bun ────────────────────────────────────────────────────────────────

/// Text `bun.lock` (lockfileVersion 1, bun 1.2): JSONC with trailing
/// commas, one line per package, a blank line between packages.
pub fn bun_lock(g: &Graph) -> String {
    let mut s = String::from(
        "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"bench-app\",\n      \"dependencies\": {\n",
    );
    for (d, r) in g.root_deps() {
        let _ = writeln!(s, "        \"{d}\": \"{r}\",");
    }
    s.push_str("      },\n    },\n  },\n  \"packages\": {\n");
    let mut entries: Vec<(String, String)> = g
        .pkgs
        .iter()
        .map(|p| {
            let key = match p.parent_name() {
                Some(parent) => format!("{parent}/{}", p.name),
                None => p.name.clone(),
            };
            let meta = if p.deps.is_empty() {
                "{}".to_string()
            } else {
                let deps: Vec<String> = p
                    .deps
                    .iter()
                    .map(|(d, v)| format!("\"{d}\": \"^{v}\""))
                    .collect();
                format!("{{ \"dependencies\": {{ {} }} }}", deps.join(", "))
            };
            (
                key.clone(),
                format!(
                    "    \"{key}\": [\"{}@{}\", \"\", {meta}, \"{}\"],\n",
                    p.name,
                    p.version,
                    p.integrity()
                ),
            )
        })
        .collect();
    entries.sort();
    let lines: Vec<String> = entries.into_iter().map(|(_, l)| l).collect();
    s.push_str(&lines.join("\n"));
    s.push_str("  }\n}\n");
    s
}

pub fn build_bun(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("bun", size);
    t.write("project/package.json", g.package_json())?;
    t.write("project/bun.lock", bun_lock(&g))?;
    g.install_hoisted(t, "project/")?;
    t.mkdir("home")?;
    Ok(fixture(&g, g.patches(false), &["bun.lock"], &[]))
}

/// Bun's isolated linker (the default since Bun 1.3.2): the same text
/// `bun.lock`, but every package lives only in the pnpm-shaped store
/// `node_modules/.bun/<name>@<version>/node_modules/<name>` (scoped
/// `@scope+leaf@…`), its dependencies linked beside it, the root linking
/// direct dependencies only, and `.bun/node_modules` holding Bun's hoist
/// links.
pub fn build_bun_isolated(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("bun-isolated", size);
    t.write("project/package.json", g.package_json())?;
    t.write("project/bun.lock", bun_lock(&g))?;
    let mut rng = Rng::new("bun-isolated-install");
    for p in &g.pkgs {
        let entry = format!("project/node_modules/.bun/{}/node_modules", p.store_key());
        write_package(t, &format!("{entry}/{}", p.name), p, &mut rng)?;
        for (d, v) in &p.deps {
            let Some(dep) = g.resolve(p, d, v) else {
                continue;
            };
            let up = "../".repeat(1 + d.matches('/').count());
            let target = format!("{up}../{}/node_modules/{d}", dep.store_key());
            t.symlink(&target, &format!("{entry}/{d}"))?;
        }
        if !p.is_nested() {
            let up = "../".repeat(1 + p.name.matches('/').count());
            t.symlink(
                &format!("{up}{}/node_modules/{}", p.store_key(), p.name),
                &format!("project/node_modules/.bun/node_modules/{}", p.name),
            )?;
        }
    }
    for p in g.direct() {
        let up = "../".repeat(p.name.matches('/').count());
        t.symlink(
            &format!("{up}.bun/{}/node_modules/{}", p.store_key(), p.name),
            &format!("project/node_modules/{}", p.name),
        )?;
    }
    t.mkdir("home")?;
    Ok(fixture(&g, g.patches(false), &["bun.lock"], &[]))
}

// ── vlt ────────────────────────────────────────────────────────────────

fn vlt_id(p: &Pkg) -> String {
    format!("~npm~{}", p.store_key())
}

/// `vlt-lock.json` (lockfileVersion 1): one line per node, no spaces
/// between tuple elements.
pub fn vlt_lock(g: &Graph) -> String {
    let mut nodes: Vec<String> = g
        .pkgs
        .iter()
        .map(|p| {
            format!(
                "    \"{}\": [0,\"{}\",\"{}\",\"{}\"]",
                vlt_id(p),
                p.name,
                p.integrity(),
                p.registry_tarball("https://registry.npmjs.org")
            )
        })
        .collect();
    nodes.sort();
    let mut edges: Vec<String> = Vec::new();
    for p in g.direct() {
        edges.push(format!(
            "    \"file~_d {}\": \"prod ^{} {}\"",
            p.name,
            p.version,
            vlt_id(p)
        ));
    }
    for p in &g.pkgs {
        for (d, v) in &p.deps {
            if let Some(dep) = g.resolve(p, d, v) {
                edges.push(format!(
                    "    \"{} {d}\": \"prod ^{v} {}\"",
                    vlt_id(p),
                    vlt_id(dep)
                ));
            }
        }
    }
    edges.sort();
    format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\n    \"registries\": {{\n      \"npm\": \"https://registry.npmjs.org/\"\n    }}\n  }},\n  \"nodes\": {{\n{}\n  }},\n  \"edges\": {{\n{}\n  }}\n}}\n",
        nodes.join(",\n"),
        edges.join(",\n")
    )
}

/// vlt's store layout: every package is a real directory under
/// `node_modules/.vlt/<DepID>/node_modules/<name>`, dependencies are
/// symlinks beside it, the root's direct dependencies are linked into
/// `node_modules/`, and `node_modules/.vlt-lock.json` records the install.
pub fn build_vlt(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let g = graph("vlt", size);
    t.write("project/package.json", g.package_json())?;
    t.write("project/vlt.json", "{}\n")?;
    let lock = vlt_lock(&g);
    t.write("project/vlt-lock.json", &lock)?;
    t.write("project/node_modules/.vlt-lock.json", &lock)?;
    let mut rng = Rng::new("vlt-install");
    for p in &g.pkgs {
        let entry = format!("project/node_modules/.vlt/{}/node_modules", vlt_id(p));
        write_package(t, &format!("{entry}/{}", p.name), p, &mut rng)?;
        for (d, v) in &p.deps {
            let Some(dep) = g.resolve(p, d, v) else {
                continue;
            };
            let up = "../".repeat(1 + d.matches('/').count());
            t.symlink(
                &format!("{up}../{}/node_modules/{d}", vlt_id(dep)),
                &format!("{entry}/{d}"),
            )?;
        }
    }
    for p in g.direct() {
        let up = "../".repeat(p.name.matches('/').count());
        t.symlink(
            &format!("{up}.vlt/{}/node_modules/{}", vlt_id(p), p.name),
            &format!("project/node_modules/{}", p.name),
        )?;
    }
    t.mkdir("home")?;
    let patches = g.patches(false);
    let mut f = fixture(
        &g,
        patches,
        &["vlt-lock.json"],
        &["redirect_vlt_reinstall_required"],
    );
    // The wet scan removes the patched packages' store entries (and the
    // hidden lock) so the next `vlt install` fetches the patches; until
    // then a rescan sees them in the lock only.
    f.expect.rescan_lockfile_only = f.patches.len();
    // vlt's preflight downloads each artifact and checks its sha512.
    for p in g.pkgs.iter().filter(|p| p.patched) {
        let uuid = gen::uuid(&format!("patch:{}", p.purl()));
        let token = gen::uuid(&format!("grant:{uuid}"));
        f.files.push((
            artifact_path(p, &token, &uuid),
            artifact_bytes(p),
            "application/octet-stream",
        ));
    }
    Ok(f)
}
