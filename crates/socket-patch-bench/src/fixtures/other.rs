//! RubyGems, Composer, Cargo, Go, NuGet and Maven projects.
//!
//! Ecosystems that install into a per-user cache (Cargo, Go, NuGet, Maven)
//! get that cache under the fixture's `home/`, which is the run's `HOME`:
//! the crawlers find it exactly where they would find a developer's, and
//! never the CI runner's.

use std::fmt::Write as _;

use serde_json::json;

use super::gen::{self, Rng, Tree};
use super::npm::view_json;
use super::pypi::pretty4;
use super::{Expect, Fixture, Size, PATCH_HOST};
use crate::mock::PatchSpec;

/// A generic package of a non-npm ecosystem.
#[derive(Debug, Clone)]
struct Pkg {
    name: String,
    version: String,
    deps: Vec<usize>,
    direct: bool,
    patched: bool,
}

/// `size.packages` packages, the first `direct_share` of them direct.
/// Patched packages are always direct dependencies that nothing else
/// depends on: Cargo and Maven hosted mode only redirect direct
/// dependencies (a transitive one is refused, by design), and the other
/// ecosystems do not care.
fn universe(
    seed: &str,
    size: Size,
    direct_share: f64,
    mut name: impl FnMut(&mut Rng, usize) -> String,
    mut version: impl FnMut(&mut Rng) -> String,
) -> Vec<Pkg> {
    let mut rng = Rng::new(seed);
    let n = size.packages;
    let direct = ((n as f64 * direct_share) as usize)
        .max(size.patched * 2)
        .min(n);
    let patched_size = Size {
        packages: direct,
        patched: size.patched,
    };
    let mut out: Vec<Pkg> = (0..n)
        .map(|i| Pkg {
            name: name(&mut rng, i),
            version: version(&mut rng),
            deps: Vec::new(),
            direct: i < direct,
            patched: i < direct && patched_size.is_patched(i),
        })
        .collect();
    for i in 0..n {
        for _ in 0..rng.below(4) {
            if i + 1 < n {
                let j = i + 1 + rng.below((n - i - 1).min(120));
                if !out[j].patched && !out[i].deps.contains(&j) {
                    out[i].deps.push(j);
                }
            }
        }
        out[i].deps.sort_unstable();
    }
    out
}

fn grant(purl: &str) -> (String, String) {
    let uuid = gen::uuid(&format!("patch:{purl}"));
    let token = gen::uuid(&format!("grant:{uuid}"));
    (uuid, token)
}

fn spec(purl: String, uuid: String, view_file: &str, reference: serde_json::Value) -> PatchSpec {
    PatchSpec {
        view: view_json(&uuid, &purl, view_file),
        purl,
        uuid,
        tier: "free",
        severity: "high",
        reference,
    }
}

fn fixture(
    scanned: usize,
    patches: Vec<PatchSpec>,
    rewritten: &[&str],
    warnings: &[&'static str],
) -> Fixture {
    Fixture {
        project: "project",
        expect: Expect {
            scanned,
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

// ── RubyGems (bundler) ─────────────────────────────────────────────────

pub fn build_gem(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let gems = universe(
        "gem",
        size,
        0.2,
        |r, i| {
            let a = gen::ident(r, i);
            if r.chance(0.3) {
                format!("{a}-{}", &gen::ident(r, i)[..4])
            } else {
                a
            }
        },
        gen::version,
    );
    let mut gemfile = String::from("source \"https://rubygems.org\"\n\nruby \"~> 3.3\"\n\n");
    for g in gems.iter().filter(|g| g.direct) {
        let _ = writeln!(gemfile, "gem \"{}\", \"~> {}\"", g.name, g.version);
    }
    t.write("project/Gemfile", gemfile)?;
    let mut sorted: Vec<&Pkg> = gems.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut lock = String::from("GEM\n  remote: https://rubygems.org/\n  specs:\n");
    for g in &sorted {
        let _ = writeln!(lock, "    {} ({})", g.name, g.version);
        for &j in &g.deps {
            let _ = writeln!(lock, "      {} (>= {})", gems[j].name, gems[j].version);
        }
    }
    lock.push_str("\nPLATFORMS\n  ruby\n  x86_64-linux\n\nDEPENDENCIES\n");
    let mut direct: Vec<&Pkg> = gems.iter().filter(|g| g.direct).collect();
    direct.sort_by(|a, b| a.name.cmp(&b.name));
    for g in direct {
        let _ = writeln!(lock, "  {} (~> {})", g.name, g.version);
    }
    lock.push_str("\nCHECKSUMS\n");
    for g in &sorted {
        let _ = writeln!(
            lock,
            "  {} ({}) sha256={}",
            g.name,
            g.version,
            gen::sha256_hex(&format!("gem:{}", g.name))
        );
    }
    lock.push_str("\nRUBY VERSION\n   ruby 3.3.5p100\n\nBUNDLED WITH\n   2.6.2\n");
    t.write("project/Gemfile.lock", lock)?;
    t.write(
        "project/.bundle/config",
        "---\nBUNDLE_PATH: \"vendor/bundle\"\n",
    )?;
    let root = "project/vendor/bundle/ruby/3.3.0";
    let mut rng = Rng::new("gem-install");
    for g in &gems {
        let dir = format!("{root}/gems/{}-{}", g.name, g.version);
        let module = g.name.replace('-', "_");
        t.write(
            &format!("{dir}/lib/{module}.rb"),
            gen::js_source(&g.name, &mut rng).replace("//", "#"),
        )?;
        t.write(
            &format!("{dir}/lib/{module}/version.rb"),
            format!("module X\n  VERSION = \"{}\"\nend\n", g.version),
        )?;
        t.write(&format!("{dir}/README.md"), format!("# {}\n", g.name))?;
        t.write(
            &format!("{root}/specifications/{}-{}.gemspec", g.name, g.version),
            format!("Gem::Specification.new do |s|\n  s.name = \"{}\"\n  s.version = \"{}\"\n  s.files = [\"lib/{module}.rb\"]\nend\n", g.name, g.version),
        )?;
    }
    t.mkdir("home")?;
    let patches = gems
        .iter()
        .filter(|g| g.patched)
        .map(|g| {
            let purl = format!("pkg:gem/{}@{}", g.name, g.version);
            let (uuid, token) = grant(&purl);
            let url = format!("{PATCH_HOST}/patch/gem/{}/{}/{token}/{uuid}/{}-{}.gem", g.name, g.version, g.name, g.version);
            let sha = gen::sha256_hex(&format!("patched-gem:{}", g.name));
            spec(
                purl.clone(),
                uuid.clone(),
                &format!("package/lib/{}.rb", g.name.replace('-', "_")),
                json!({
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": sha } }],
                    "registryOverride": {
                        "kind": "rubygems-compact-index",
                        "indexUrl": format!("{PATCH_HOST}/patch-registry/gem/{token}/{uuid}/"),
                        "identifiers": { "name": g.name, "version": g.version, "gemChecksumSha256": sha },
                    },
                }),
            )
        })
        .collect();
    Ok(fixture(
        gems.len(),
        patches,
        &["Gemfile", "Gemfile.lock"],
        &["redirect_gem_stale_install"],
    ))
}

// ── Composer ───────────────────────────────────────────────────────────

pub fn build_composer(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let pkgs = universe(
        "composer",
        size,
        0.2,
        |r, i| {
            format!(
                "{}/{}",
                &gen::ident(r, i)[..5].trim_end_matches(char::is_numeric),
                gen::ident(r, i)
            )
        },
        gen::version,
    );
    let entry = |p: &Pkg, installed: bool| {
        let reference = gen::sha1_hex(&format!("composer:{}", p.name));
        let mut e = json!({
            "name": p.name,
            "version": p.version,
            "source": { "type": "git", "url": format!("https://github.com/{}.git", p.name), "reference": reference },
            "dist": {
                "type": "zip",
                "url": format!("https://api.github.com/repos/{}/zipball/{reference}", p.name),
                "reference": reference,
                "shasum": "",
            },
            "require": serde_json::Map::from_iter(p.deps.iter().map(|&j| (pkgs[j].name.clone(), json!(format!("^{}", pkgs[j].version))))),
            "type": "library",
            "autoload": { "psr-4": { format!("Bench\\{}\\", p.name.split('/').next_back().unwrap()): "src/" } },
            "license": ["MIT"],
            "description": format!("Synthetic package {}", p.name),
            "time": "2024-05-01T00:00:00+00:00",
        });
        if installed {
            e["install-path"] = json!(format!("../{}", p.name));
        }
        e
    };
    let mut sorted: Vec<&Pkg> = pkgs.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let lock = json!({
        "_readme": [
            "This file locks the dependencies of your project to a known state",
            "Read more about it at https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies",
            "This file is @generated automatically",
        ],
        "content-hash": gen::sha256_hex("composer-content")[..32],
        "packages": sorted.iter().map(|p| entry(p, false)).collect::<Vec<_>>(),
        "packages-dev": [],
        "aliases": [],
        "minimum-stability": "stable",
        "stability-flags": {},
        "prefer-stable": false,
        "prefer-lowest": false,
        "platform": { "php": ">=8.1" },
        "platform-dev": {},
        "plugin-api-version": "2.6.0",
    });
    t.write("project/composer.lock", pretty4(&lock) + "\n")?;
    let mut require = serde_json::Map::new();
    require.insert("php".into(), json!(">=8.1"));
    for p in pkgs.iter().filter(|p| p.direct) {
        require.insert(p.name.clone(), json!(format!("^{}", p.version)));
    }
    t.write(
        "project/composer.json",
        pretty4(&json!({ "name": "bench/app", "type": "project", "require": require })) + "\n",
    )?;
    let installed = json!({
        "packages": sorted.iter().map(|p| entry(p, true)).collect::<Vec<_>>(),
        "dev": true,
        "dev-package-names": [],
    });
    t.write(
        "project/vendor/composer/installed.json",
        pretty4(&installed) + "\n",
    )?;
    t.write(
        "project/vendor/autoload.php",
        "<?php\nreturn require __DIR__ . '/composer/autoload_real.php';\n",
    )?;
    let mut rng = Rng::new("composer-install");
    for p in &pkgs {
        let dir = format!("project/vendor/{}", p.name);
        t.write(
            &format!("{dir}/composer.json"),
            pretty4(&json!({ "name": p.name, "type": "library" })),
        )?;
        t.write(
            &format!("{dir}/src/Client.php"),
            format!("<?php\n{}", gen::js_source(&p.name, &mut rng)),
        )?;
    }
    t.mkdir("home")?;
    let patches = pkgs
        .iter()
        .filter(|p| p.patched)
        .map(|p| {
            let purl = format!("pkg:composer/{}@{}", p.name, p.version);
            let (uuid, token) = grant(&purl);
            let leaf = p.name.split('/').next_back().unwrap();
            let url = format!("{PATCH_HOST}/patch/composer/{}/{}/{token}/{uuid}/{leaf}-{}.zip", p.name, p.version, p.version);
            spec(
                purl.clone(),
                uuid,
                "package/src/Client.php",
                json!({
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha1": gen::sha1_hex(&format!("patched:{}", p.name)) } }],
                    "registryOverride": null,
                }),
            )
        })
        .collect();
    Ok(fixture(pkgs.len(), patches, &["composer.lock"], &[]))
}

// ── Cargo ──────────────────────────────────────────────────────────────

pub fn build_cargo(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let crates = universe(
        "cargo",
        size,
        0.12,
        |r, i| {
            let a = gen::ident(r, i);
            if r.chance(0.4) {
                format!(
                    "{a}-{}",
                    ["core", "sys", "derive", "macros", "impl", "util"][r.below(6)]
                )
            } else {
                a
            }
        },
        gen::version,
    );
    let mut toml = String::from("[package]\nname = \"bench-app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n");
    for c in crates.iter().filter(|c| c.direct) {
        if c.name.len() % 3 == 0 {
            let _ = writeln!(
                toml,
                "{} = {{ version = \"{}\", default-features = false }}",
                c.name, c.version
            );
        } else {
            let _ = writeln!(toml, "{} = \"{}\"", c.name, c.version);
        }
    }
    t.write("project/Cargo.toml", toml)?;
    t.write("project/src/main.rs", "fn main() {}\n")?;
    let mut lock = String::from("# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n");
    let mut entries: Vec<(String, String)> = crates
        .iter()
        .map(|c| {
            let mut e = format!(
                "\n[[package]]\nname = \"{}\"\nversion = \"{}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
                c.name,
                c.version,
                gen::sha256_hex(&format!("crate:{}", c.name))
            );
            if !c.deps.is_empty() {
                let mut names: Vec<&str> = c.deps.iter().map(|&j| crates[j].name.as_str()).collect();
                names.sort_unstable();
                e.push_str("dependencies = [\n");
                for n in names {
                    let _ = writeln!(e, " \"{n}\",");
                }
                e.push_str("]\n");
            }
            (c.name.clone(), e)
        })
        .collect();
    let mut root = String::from(
        "\n[[package]]\nname = \"bench-app\"\nversion = \"0.1.0\"\ndependencies = [\n",
    );
    let mut direct: Vec<&str> = crates
        .iter()
        .filter(|c| c.direct)
        .map(|c| c.name.as_str())
        .collect();
    direct.sort_unstable();
    for n in direct {
        let _ = writeln!(root, " \"{n}\",");
    }
    root.push_str("]\n");
    entries.push(("bench-app".into(), root));
    entries.sort();
    for (_, e) in entries {
        lock.push_str(&e);
    }
    t.write("project/Cargo.lock", lock)?;
    let src = "home/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
    let mut rng = Rng::new("cargo-install");
    for c in &crates {
        let dir = format!("{src}/{}-{}", c.name, c.version);
        t.write(
            &format!("{dir}/Cargo.toml"),
            format!("[package]\nedition = \"2021\"\nname = \"{}\"\nversion = \"{}\"\nlicense = \"MIT\"\ndescription = \"synthetic\"\n", c.name, c.version),
        )?;
        t.write(
            &format!("{dir}/src/lib.rs"),
            gen::js_source(&c.name, &mut rng).replace("'use strict';", "//!"),
        )?;
        t.write(&format!("{dir}/.cargo-ok"), "{\"v\":1}")?;
    }
    let patches = crates
        .iter()
        .filter(|c| c.patched)
        .map(|c| {
            let purl = format!("pkg:cargo/{}@{}", c.name, c.version);
            let (uuid, token) = grant(&purl);
            let url = format!("{PATCH_HOST}/patch/cargo/{}/{}/{token}/{uuid}/{}-{}.crate", c.name, c.version, c.name, c.version);
            let cksum = gen::sha256_hex(&format!("patched-crate:{}", c.name));
            spec(
                purl.clone(),
                uuid.clone(),
                "package/src/lib.rs",
                json!({
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": cksum } }],
                    "registryOverride": {
                        "kind": "cargo-sparse",
                        "indexUrl": format!("sparse+{PATCH_HOST}/patch-registry/cargo/{token}/{uuid}/index/"),
                        "identifiers": { "name": c.name, "version": c.version, "cargoCksumSha256": cksum },
                    },
                }),
            )
        })
        .collect();
    Ok(fixture(
        crates.len(),
        patches,
        &["Cargo.toml", "Cargo.lock", ".cargo/config.toml"],
        &[],
    ))
}

// ── Go modules ─────────────────────────────────────────────────────────

/// The module cache's case encoding (`Foo` → `!foo`).
fn go_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn h1(seed: &str) -> String {
    format!("h1:{}", gen::sha256_base64(seed))
}

pub fn build_golang(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let mods = universe(
        "golang",
        size,
        0.15,
        |r, i| {
            let org = gen::ident(r, i);
            let repo = gen::ident(r, i);
            match r.below(10) {
                0 => format!("golang.org/x/{repo}"),
                1 => format!("go.uber.org/{repo}"),
                // Mixed-case paths exercise the cache's `!` decoding.
                2 => {
                    let mut o = org.clone();
                    o[..1].make_ascii_uppercase();
                    format!("github.com/{o}/{repo}")
                }
                _ => format!("github.com/{org}/{repo}"),
            }
        },
        |r| format!("v{}.{}.{}", r.below(2), r.below(30), r.below(12)),
    );
    let mut gomod = String::from("module example.com/bench/app\n\ngo 1.22\n\nrequire (\n");
    for m in mods.iter().filter(|m| m.direct) {
        let _ = writeln!(gomod, "\t{} {}", m.name, m.version);
    }
    gomod.push_str(")\n\nrequire (\n");
    for m in mods.iter().filter(|m| !m.direct) {
        let _ = writeln!(gomod, "\t{} {} // indirect", m.name, m.version);
    }
    gomod.push_str(")\n");
    t.write("project/go.mod", gomod)?;
    let mut sum: Vec<String> = Vec::new();
    for m in &mods {
        sum.push(format!(
            "{} {} {}",
            m.name,
            m.version,
            h1(&format!("zip:{}", m.name))
        ));
        sum.push(format!(
            "{} {}/go.mod {}",
            m.name,
            m.version,
            h1(&format!("mod:{}", m.name))
        ));
    }
    sum.sort();
    t.write("project/go.sum", sum.join("\n") + "\n")?;
    t.write("project/main.go", "package main\n\nfunc main() {}\n")?;
    let mut rng = Rng::new("go-install");
    for m in &mods {
        let dir = format!("home/go/pkg/mod/{}@{}", go_escape(&m.name), m.version);
        t.write(
            &format!("{dir}/go.mod"),
            format!("module {}\n\ngo 1.20\n", m.name),
        )?;
        let pkg = m.name.rsplit('/').next().unwrap().replace('-', "_");
        t.write(
            &format!("{dir}/{pkg}.go"),
            format!(
                "package {pkg}\n\n{}",
                gen::js_source(&m.name, &mut rng).replace("'use strict';", "")
            ),
        )?;
        t.write(&format!("{dir}/LICENSE"), "MIT\n")?;
    }
    let patches = mods
        .iter()
        .filter(|m| m.patched)
        .map(|m| {
            let purl = format!("pkg:golang/{}@{}", m.name, m.version);
            let (uuid, _) = grant(&purl);
            let smod = format!("patch.socket.dev/gopatch/{uuid}");
            let sver = format!("{}-socketpatch.1", m.version);
            let url = format!("{PATCH_HOST}/patch-registry/golang/{smod}/@v/{sver}.zip");
            spec(
                purl.clone(),
                uuid.clone(),
                "package/patched.go",
                json!({
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": {} }],
                    "registryOverride": {
                        "kind": "goproxy",
                        "indexUrl": PATCH_HOST,
                        "identifiers": {
                            "name": m.name,
                            "version": m.version,
                            "goModulePath": smod,
                            "goModuleVersion": sver,
                            "goZipDirhashH1": h1(&format!("patched-zip:{}", m.name)),
                            "goModH1": h1(&format!("patched-mod:{}", m.name)),
                        },
                    },
                }),
            )
        })
        .collect();
    let mut f = fixture(mods.len(), patches, &["go.mod", "go.sum"], &[]);
    // The rewrite adds each Socket module's go.sum lines, which a rescan's
    // go.sum inventory reports as more (lockfile-only) modules.
    f.expect.rescan_extra_scanned = f.patches.len();
    f.expect.rescan_lockfile_only = f.patches.len();
    Ok(f)
}

// ── NuGet ──────────────────────────────────────────────────────────────

pub fn build_nuget(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let pkgs = universe(
        "nuget",
        size,
        0.25,
        |r, i| {
            let mut a = gen::ident(r, i);
            a[..1].make_ascii_uppercase();
            let mut b = gen::ident(r, i + 7);
            b[..1].make_ascii_uppercase();
            match r.below(3) {
                0 => format!("{a}.{b}"),
                1 => format!("{a}.{b}.Abstractions"),
                _ => a,
            }
        },
        gen::version,
    );
    let mut csproj = String::from("<Project Sdk=\"Microsoft.NET.Sdk\">\n\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net8.0</TargetFramework>\n    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n  </PropertyGroup>\n\n  <ItemGroup>\n");
    for p in pkgs.iter().filter(|p| p.direct) {
        let _ = writeln!(
            csproj,
            "    <PackageReference Include=\"{}\" Version=\"{}\" />",
            p.name, p.version
        );
    }
    csproj.push_str("  </ItemGroup>\n\n</Project>\n");
    t.write("project/Bench.App.csproj", csproj)?;
    t.write(
        "project/nuget.config",
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <clear />\n    <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" protocolVersion=\"3\" />\n  </packageSources>\n</configuration>\n",
    )?;
    let mut deps = serde_json::Map::new();
    let mut sorted: Vec<&Pkg> = pkgs.iter().collect();
    sorted.sort_by_key(|p| p.name.to_ascii_lowercase());
    for p in sorted {
        let mut e = serde_json::Map::new();
        e.insert(
            "type".into(),
            json!(if p.direct { "Direct" } else { "Transitive" }),
        );
        if p.direct {
            e.insert("requested".into(), json!(format!("[{}, )", p.version)));
        }
        e.insert("resolved".into(), json!(p.version));
        e.insert(
            "contentHash".into(),
            json!(gen::sri_sha512(&format!("nupkg:{}", p.name))[7..]),
        );
        if !p.deps.is_empty() {
            e.insert(
                "dependencies".into(),
                json!(serde_json::Map::from_iter(
                    p.deps
                        .iter()
                        .map(|&j| (pkgs[j].name.clone(), json!(pkgs[j].version)))
                )),
            );
        }
        deps.insert(p.name.clone(), serde_json::Value::Object(e));
    }
    let lock = json!({ "version": 1, "dependencies": { "net8.0": deps } });
    t.write(
        "project/packages.lock.json",
        serde_json::to_string_pretty(&lock).unwrap(),
    )?;
    t.write(
        "project/Program.cs",
        "System.Console.WriteLine(\"bench\");\n",
    )?;
    for p in &pkgs {
        let id = p.name.to_ascii_lowercase();
        let dir = format!("home/.nuget/packages/{id}/{}", p.version);
        t.write(
            &format!("{dir}/{id}.nuspec"),
            format!("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<package xmlns=\"http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd\">\n  <metadata>\n    <id>{}</id>\n    <version>{}</version>\n    <authors>bench</authors>\n  </metadata>\n</package>\n", p.name, p.version),
        )?;
        t.write(
            &format!("{dir}/{id}.{}.nupkg.sha512", p.version),
            &gen::sri_sha512(&format!("nupkg:{}", p.name))[7..],
        )?;
        t.write(&format!("{dir}/.nupkg.metadata"), "{\n  \"version\": 2,\n  \"contentHash\": \"x\",\n  \"source\": \"https://api.nuget.org/v3/index.json\"\n}")?;
        t.write(&format!("{dir}/lib/net8.0/{}.dll", p.name), b"MZ synthetic")?;
    }
    let patches = pkgs
        .iter()
        .filter(|p| p.patched)
        .map(|p| {
            let id = p.name.to_ascii_lowercase();
            let purl = format!("pkg:nuget/{id}@{}", p.version);
            let (uuid, token) = grant(&purl);
            let url = format!("{PATCH_HOST}/patch-registry/nuget/{token}/{uuid}/flat/{id}/{}/{id}.{}.nupkg", p.version, p.version);
            spec(
                purl,
                uuid.clone(),
                &format!("package/lib/net8.0/{}.dll", p.name),
                json!({
                    "status": "granted",
                    "url": url,
                    "purl": format!("pkg:nuget/{}@{}", p.name, p.version),
                    "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha512": gen::sri_sha512(&format!("patched-nupkg:{}", p.name)) } }],
                    "registryOverride": {
                        "kind": "nuget-v3",
                        "indexUrl": format!("{PATCH_HOST}/patch-registry/nuget/{token}/{uuid}/index.json"),
                        "identifiers": { "name": p.name, "version": p.version, "nugetIdLower": id, "nugetVersionNorm": p.version },
                    },
                }),
            )
        })
        .collect();
    Ok(fixture(
        pkgs.len(),
        patches,
        &["nuget.config", "packages.lock.json"],
        &[],
    ))
}

// ── Maven ──────────────────────────────────────────────────────────────

/// The Maven-coordinate universe the Maven and Gradle fixtures share
/// (`group:artifact` names).
fn jvm_universe(seed: &str, size: Size) -> Vec<Pkg> {
    universe(
        seed,
        size,
        0.2,
        |r, i| {
            let g = match r.below(3) {
                0 => format!("org.{}", gen::ident(r, i)),
                1 => format!("com.{}.{}", gen::ident(r, i), gen::ident(r, i + 3)),
                _ => format!("io.{}", gen::ident(r, i)),
            };
            let a = format!(
                "{}-{}",
                gen::ident(r, i),
                ["core", "api", "client", "common"][r.below(4)]
            );
            format!("{g}:{a}")
        },
        gen::version,
    )
}

fn ga(p: &Pkg) -> (String, String) {
    let (g, a) = p.name.split_once(':').unwrap();
    (g.to_string(), a.to_string())
}

/// A dependency's pom, listing its own dependencies.
fn jvm_pom(arts: &[Pkg], p: &Pkg) -> String {
    let (g, a) = ga(p);
    let mut deps = String::new();
    for &j in &p.deps {
        let (dg, da) = ga(&arts[j]);
        let _ = write!(deps, "    <dependency>\n      <groupId>{dg}</groupId>\n      <artifactId>{da}</artifactId>\n      <version>{}</version>\n    </dependency>\n", arts[j].version);
    }
    format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>{g}</groupId>\n  <artifactId>{a}</artifactId>\n  <version>{}</version>\n  <dependencies>\n{deps}  </dependencies>\n</project>\n", p.version)
}

pub fn build_maven(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let arts = jvm_universe("maven", size);
    let mut pom = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd\">\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>dev.socket.bench</groupId>\n  <artifactId>bench-app</artifactId>\n  <version>1.0.0</version>\n  <packaging>jar</packaging>\n\n  <properties>\n    <maven.compiler.release>17</maven.compiler.release>\n  </properties>\n\n  <dependencies>\n");
    for p in arts.iter().filter(|p| p.direct) {
        let (g, a) = ga(p);
        let _ = write!(pom, "    <dependency>\n      <groupId>{g}</groupId>\n      <artifactId>{a}</artifactId>\n      <version>{}</version>\n    </dependency>\n", p.version);
    }
    pom.push_str("  </dependencies>\n</project>\n");
    t.write("project/pom.xml", pom)?;
    t.write(
        "project/src/main/java/App.java",
        "public class App { public static void main(String[] a) {} }\n",
    )?;
    for p in &arts {
        let (g, a) = ga(p);
        let dir = format!(
            "home/.m2/repository/{}/{a}/{}",
            g.replace('.', "/"),
            p.version
        );
        let pom = jvm_pom(&arts, p);
        t.write(
            &format!("{dir}/{a}-{}.pom.sha1", p.version),
            gen::sha1_hex(&pom),
        )?;
        t.write(&format!("{dir}/{a}-{}.pom", p.version), pom)?;
        t.write(&format!("{dir}/{a}-{}.jar", p.version), b"PK synthetic")?;
        t.write(
            &format!("{dir}/_remote.repositories"),
            format!(
                "{a}-{}.jar>central=\n{a}-{}.pom>central=\n",
                p.version, p.version
            ),
        )?;
    }
    let patches = arts
        .iter()
        .filter(|p| p.patched)
        .map(|p| {
            jvm_patch(
                p,
                |token, uuid| format!("{PATCH_HOST}/patch-registry/maven/{token}/{uuid}/maven2"),
                false,
            )
        })
        .collect();
    Ok(fixture(
        arts.len(),
        patches,
        &[
            "pom.xml",
            ".mvn/maven.config",
            ".mvn/checksums/checksums.sha256",
        ],
        &[],
    ))
}

/// The mock's patch for one Maven coordinate: a suffixed-version maven2
/// registry override. `index_url` builds the override's repository URL
/// from the grant token and patch uuid.
fn jvm_patch(p: &Pkg, index_url: impl Fn(&str, &str) -> String, module_sha: bool) -> PatchSpec {
    let (g, a) = ga(p);
    let purl = format!("pkg:maven/{g}/{a}@{}", p.version);
    let (uuid, token) = grant(&purl);
    let suffixed = format!("{}-socket.{}", p.version, &uuid[..8]);
    let url = format!(
        "{PATCH_HOST}/patch/maven/{g}/{a}/{}/{token}/{uuid}/{a}-{suffixed}.jar",
        p.version
    );
    let mut identifiers = json!({
        "name": format!("{g}/{a}"),
        "version": p.version,
        "mavenGroupId": g,
        "mavenArtifactId": a,
        "mavenSuffixedVersion": suffixed,
        "mavenPomSha256": gen::sha256_hex(&format!("patched-pom:{}", p.name)),
    });
    if module_sha {
        identifiers["mavenModuleSha256"] =
            json!(gen::sha256_hex(&format!("patched-module:{}", p.name)));
    }
    spec(
        purl.clone(),
        uuid.clone(),
        &format!("package/{a}.class"),
        json!({
            "status": "granted",
            "url": url,
            "purl": purl,
            "artifacts": [{ "kind": "tarball", "url": url, "integrity": {
                "sha256": gen::sha256_hex(&format!("patched-jar:{}", p.name)),
                "sha1": gen::sha1_hex(&format!("patched-jar:{}", p.name)),
            } }],
            "registryOverride": {
                "kind": "maven2",
                "indexUrl": index_url(&token, &uuid),
                "identifiers": identifiers,
            },
        }),
    )
}

// ── Gradle ─────────────────────────────────────────────────────────────

/// A single-project Groovy-DSL build with dependency locking, its
/// dependencies in Gradle's own cache (`modules-2/files-2.1`, jar and pom
/// in separate sha1 dirs). Hosted mode wires the build through an owned
/// settings script and index under `.socket/gradle/` and pins the
/// suffixed versions in `gradle.lockfile`.
pub fn build_gradle(t: &mut Tree, size: Size) -> std::io::Result<Fixture> {
    let arts = jvm_universe("gradle", size);
    t.write(
        "project/settings.gradle",
        "rootProject.name = 'bench-app'\n",
    )?;
    let mut build = String::from(
        "plugins {\n    id 'java'\n}\n\nrepositories {\n    mavenCentral()\n}\n\ndependencyLocking {\n    lockAllConfigurations()\n}\n\ndependencies {\n",
    );
    for p in arts.iter().filter(|p| p.direct) {
        let _ = writeln!(build, "    implementation '{}:{}'", p.name, p.version);
    }
    build.push_str("}\n");
    t.write("project/build.gradle", build)?;
    let mut sorted: Vec<&Pkg> = arts.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut lock = String::from(
        "# This is a Gradle generated file for dependency locking.\n# Manual edits can break the build and are not advised.\n# This file is expected to be part of source control.\n",
    );
    for p in &sorted {
        let _ = writeln!(
            lock,
            "{}:{}=compileClasspath,runtimeClasspath",
            p.name, p.version
        );
    }
    lock.push_str("empty=annotationProcessor,testAnnotationProcessor\n");
    t.write("project/gradle.lockfile", lock)?;
    t.write(
        "project/gradle/wrapper/gradle-wrapper.properties",
        "distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.10.2-bin.zip\nzipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n",
    )?;
    t.write(
        "project/src/main/java/App.java",
        "public class App { public static void main(String[] a) {} }\n",
    )?;
    for p in &arts {
        let (g, a) = ga(p);
        let dir = format!(
            "home/.gradle/caches/modules-2/files-2.1/{g}/{a}/{}",
            p.version
        );
        let pom = jvm_pom(&arts, p);
        let jar = format!("PK synthetic {}", p.name);
        t.write(
            &format!("{dir}/{}/{a}-{}.pom", gen::sha1_hex(&pom), p.version),
            pom,
        )?;
        t.write(
            &format!("{dir}/{}/{a}-{}.jar", gen::sha1_hex(&jar), p.version),
            jar,
        )?;
    }
    // Gradle's planner only takes https repositories; the CLI never
    // fetches the index during a scan, so it need not be the mock.
    let patches = arts
        .iter()
        .filter(|p| p.patched)
        .map(|p| {
            jvm_patch(
                p,
                |token, uuid| {
                    format!("https://patch.socket.dev/patch-registry/maven/{token}/{uuid}/maven2")
                },
                true,
            )
        })
        .collect();
    let mut f = fixture(
        arts.len(),
        patches,
        &[
            ".socket/gradle/.gitattributes",
            ".socket/gradle/hosted-index.tsv",
            ".socket/gradle/socket-patch.hosted.settings.gradle",
            "gradle.lockfile",
            "settings.gradle",
        ],
        &["redirect_gradle_detached_configs_unguarded"],
    );
    f.env_paths = vec![("GRADLE_USER_HOME", "home/.gradle")];
    Ok(f)
}
