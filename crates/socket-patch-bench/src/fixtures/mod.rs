//! Synthetic projects, one generator per package manager.
//!
//! Each generator lays down what a real project of that kind has on disk
//! after an install — manifest, lockfile, installed package tree (and, for
//! ecosystems that install into a shared cache, that cache under the
//! fixture's own `home/`) — and returns what the mock API must serve for
//! it plus what a correct scan of it reports. The expectations are what
//! make a timing meaningful: a run that scans fewer packages, redirects
//! fewer patches or rewrites different files than expected is a failed
//! run, never a fast one.

pub mod gen;

use crate::mock::PatchSpec;

/// Package counts for one fixture.
#[derive(Debug, Clone, Copy)]
pub struct Size {
    /// Installed (or locked) packages the scan should report.
    pub packages: usize,
    /// How many of them have a patch.
    pub patched: usize,
}

impl Size {
    pub fn scaled(packages: usize, patched: usize, scale: f64) -> Self {
        let packages = ((packages as f64 * scale).round() as usize).max(4);
        let patched = ((patched as f64 * scale).round() as usize).clamp(1, packages / 2);
        Self { packages, patched }
    }

    /// Spread the patched packages evenly over the index range, so they are
    /// not all clustered at the start of a lockfile.
    pub fn is_patched(&self, index: usize) -> bool {
        let stride = (self.packages / self.patched).max(1);
        index % stride == stride / 2 && index / stride < self.patched
    }
}

/// What a correct scan of a fixture reports.
#[derive(Debug, Clone, Default)]
pub struct Expect {
    /// `scannedPackages`.
    pub scanned: usize,
    /// `lockfileOnlyPackages`.
    pub lockfile_only: usize,
    /// `redirect.redirected` for a hosted run from the pristine fixture.
    pub redirected: usize,
    /// `redirect.rewrittenFiles` for that run (project-relative).
    pub rewritten: Vec<String>,
    /// Warning codes a correct run may emit (`redirect.warnings[].code`,
    /// top-level `warnings[].code`). Any other code fails the run.
    pub allowed_warnings: Vec<&'static str>,
    /// `lockfileOnlyPackages` on a rescan, when the first scan's install
    /// cleanup removes installed copies (vlt drops the patched store
    /// entries so the next install fetches the patch).
    pub rescan_lockfile_only: usize,
    /// Extra `scannedPackages` on a rescan (a redirect that adds locked
    /// entries: Go's `go.sum` gains the Socket module's lines).
    pub rescan_extra_scanned: usize,
}

/// Bodies the artifact host serves: `(URL path, bytes, content type)`.
pub type Served = Vec<(String, Vec<u8>, &'static str)>;

/// A generated project.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// The project directory (`--cwd`), relative to the fixture root.
    pub project: &'static str,
    pub patches: Vec<PatchSpec>,
    /// Bodies the artifact host serves, by URL path.
    pub files: Served,
    /// Environment variables whose values are paths relative to the
    /// fixture root (caches the ecosystem would otherwise find in the
    /// runner's real home).
    pub env_paths: Vec<(&'static str, &'static str)>,
    /// Other environment variables the ecosystem's real users have set.
    pub env: Vec<(&'static str, String)>,
    pub expect: Expect,
}

/// The artifact host's base URL inside fixtures. The CLI is pointed at the
/// mock with `SOCKET_PATCH_SERVER_URL`; references carry absolute URLs, so
/// a fixture writes this placeholder and the engine rewrites it to the
/// mock's address when it builds the catalog.
pub const PATCH_HOST: &str = "http://socket-patch-bench.invalid";

pub mod npm;
pub mod other;
pub mod pypi;

use crate::scenarios::Pm;

/// Every package manager, in run order. Sizes are a large-but-ordinary
/// project for each ecosystem, and big enough that a scan takes ~100 ms or
/// more: shorter runs are dominated by process start-up and scheduler
/// noise.
pub static ALL: &[Pm] = &[
    Pm {
        name: "npm",
        description: "npm (package-lock.json v3, hoisted node_modules)",
        packages: 3000,
        patched: 60,
        build: npm::build_npm,
    },
    Pm {
        name: "pnpm",
        description: "pnpm (pnpm-lock.yaml 9.0, isolated .pnpm store)",
        packages: 3000,
        patched: 60,
        build: npm::build_pnpm,
    },
    Pm {
        name: "yarn-classic",
        description: "yarn classic (yarn.lock v1, hoisted node_modules)",
        packages: 3000,
        patched: 60,
        build: npm::build_yarn_classic,
    },
    Pm {
        name: "yarn-berry",
        description: "yarn berry (yarn.lock v8, node-modules linker)",
        packages: 3000,
        patched: 60,
        build: npm::build_yarn_berry,
    },
    Pm {
        name: "bun",
        description: "bun (text bun.lock v1, hoisted node_modules)",
        packages: 3000,
        patched: 60,
        build: npm::build_bun,
    },
    Pm {
        name: "vlt",
        description: "vlt (vlt-lock.json v1, node_modules/.vlt store)",
        packages: 1500,
        patched: 30,
        build: npm::build_vlt,
    },
    Pm {
        name: "pip",
        description: "pip (hash-pinned requirements.txt, .venv)",
        packages: 1000,
        patched: 25,
        build: pypi::build_requirements,
    },
    Pm {
        name: "uv",
        description: "uv (uv.lock + pyproject.toml, .venv)",
        packages: 400,
        patched: 12,
        build: pypi::build_uv,
    },
    Pm {
        name: "pylock",
        description: "PEP 751 pylock.toml, .venv",
        packages: 400,
        patched: 12,
        build: pypi::build_pylock,
    },
    Pm {
        name: "poetry",
        description: "poetry (poetry.lock 2.1, in-project .venv)",
        packages: 400,
        patched: 12,
        build: pypi::build_poetry,
    },
    Pm {
        name: "pipenv",
        description: "pipenv (Pipfile.lock spec 6, in-project .venv)",
        packages: 400,
        patched: 12,
        build: pypi::build_pipenv,
    },
    Pm {
        name: "pdm",
        description: "pdm (pdm.lock 4.5.1, .venv)",
        packages: 400,
        patched: 12,
        build: pypi::build_pdm,
    },
    Pm {
        name: "bundler",
        description: "RubyGems (Gemfile.lock with CHECKSUMS, vendor/bundle)",
        packages: 800,
        patched: 20,
        build: other::build_gem,
    },
    Pm {
        name: "composer",
        description: "Composer (composer.lock, vendor/)",
        packages: 800,
        patched: 20,
        build: other::build_composer,
    },
    Pm {
        name: "cargo",
        description: "Cargo (Cargo.lock v4, ~/.cargo/registry/src)",
        packages: 600,
        patched: 15,
        build: other::build_cargo,
    },
    Pm {
        name: "golang",
        description: "Go modules (go.mod + go.sum, ~/go/pkg/mod)",
        packages: 1200,
        patched: 30,
        build: other::build_golang,
    },
    Pm {
        name: "nuget",
        description: "NuGet (packages.lock.json + nuget.config, ~/.nuget/packages)",
        packages: 900,
        patched: 25,
        build: other::build_nuget,
    },
    Pm {
        name: "maven",
        description: "Maven (pom.xml, ~/.m2/repository)",
        packages: 1000,
        patched: 25,
        build: other::build_maven,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every file under `root` with its bytes (symlinks by target).
    fn contents(root: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
        fn walk(
            root: &std::path::Path,
            dir: &std::path::Path,
            out: &mut std::collections::BTreeMap<String, Vec<u8>>,
        ) {
            for e in std::fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let rel = e.path().strip_prefix(root).unwrap().display().to_string();
                let ty = e.file_type().unwrap();
                if ty.is_symlink() {
                    out.insert(
                        rel,
                        std::fs::read_link(e.path())
                            .unwrap()
                            .display()
                            .to_string()
                            .into_bytes(),
                    );
                } else if ty.is_dir() {
                    walk(root, &e.path(), out);
                } else {
                    out.insert(rel, std::fs::read(e.path()).unwrap());
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    #[test]
    fn every_fixture_is_deterministic_and_expects_real_work() {
        let size = Size::scaled(60, 4, 1.0);
        for pm in ALL {
            let tmp = tempfile::tempdir().unwrap();
            let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
            let fa = (pm.build)(&mut gen::Tree::new(&a).unwrap(), size).unwrap();
            let fb = (pm.build)(&mut gen::Tree::new(&b).unwrap(), size).unwrap();
            assert_eq!(
                contents(&a),
                contents(&b),
                "{}: same seed, different bytes",
                pm.name
            );
            let uuids = |f: &Fixture| f.patches.iter().map(|p| p.uuid.clone()).collect::<Vec<_>>();
            assert_eq!(uuids(&fa), uuids(&fb), "{}", pm.name);
            assert_eq!(fa.expect.scanned, size.packages, "{}", pm.name);
            assert_eq!(fa.patches.len(), size.patched, "{}", pm.name);
            assert_eq!(fa.expect.redirected, size.patched, "{}", pm.name);
            assert!(!fa.expect.rewritten.is_empty(), "{}", pm.name);
            assert!(a.join(fa.project).is_dir(), "{}", pm.name);
            for p in &fa.patches {
                assert_eq!(p.reference["status"], "granted", "{}", pm.name);
                assert!(
                    p.reference["url"].as_str().unwrap().starts_with(PATCH_HOST),
                    "{}",
                    pm.name
                );
            }
        }
    }

    #[test]
    fn patched_indices_are_spread_and_counted_exactly() {
        for (n, k) in [(3000, 60), (400, 12), (60, 4), (7, 3)] {
            let s = Size {
                packages: n,
                patched: k,
            };
            let hits: Vec<usize> = (0..n).filter(|&i| s.is_patched(i)).collect();
            assert_eq!(hits.len(), k, "{n}/{k}");
            assert!(hits.last().unwrap() - hits[0] >= n / 2, "{n}/{k}: {hits:?}");
        }
    }
}
