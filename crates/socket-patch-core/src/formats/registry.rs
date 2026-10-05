//! Which project files carry a lock or its wiring, per ecosystem, and in
//! which roles — the ONE table the hosted planners' candidate reads, the
//! vendored planners' wiring search, lockfile discovery's vendored-liveness
//! probe, the in-memory engine's root detection and the npm-family flavor
//! probes all filter.
//!
//! The roles intentionally diverge per file (a binary Bun lock has a native
//! reader and is never text-scanned for wiring; `pnpm-lock.yml` is only a
//! package-manager marker; Gradle build scripts are read but never edited);
//! each divergence is one flag on one row. Paths are root-relative with `/`
//! separators. Dynamic sets — PEP 751 / PEP 723 Python locks, vlt importer
//! manifests, requirements `-r` includes, Rush's nested pnpm locks, the
//! Gradle script graph and its lock files — are enumerated by their
//! callers.

/// Read by the hosted planners (`scan --mode hosted`, the in-memory
/// engine's candidate reads).
pub const HOSTED: u8 = 1 << 0;
/// Rewired by a vendored planner: the search space for
/// `.socket/vendor/<eco>/<uuid>/<leaf>` references when the vendor ledger
/// is gone (`repair`).
pub const VENDORED: u8 = 1 << 1;
/// A lock (or wiring config) a vendored artifact is consumed through — the
/// liveness probe of a ledger entry whose recorded wiring files are gone
/// (`vex::discover`), and the npm-family flavor probe's lock family.
pub const PROBE: u8 = 1 << 2;
/// Makes its directory a project root (the in-memory hosted engine).
pub const ROOT: u8 = 1 << 3;
/// Marks a pnpm project for package-manager detection.
pub const PNPM_MARKER: u8 = 1 << 4;
/// Read by the hosted planners for its presence (or as advisory input)
/// only: no hosted rewriter edits it, so it names no ecosystem for the
/// symlinked-read refusal.
pub const PRESENCE_ONLY: u8 = 1 << 5;

/// One row of the [`registry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatFile {
    /// Root-relative path.
    pub path: &'static str,
    /// Vendor-ecosystem tag (`npm`, `pypi`, `cargo`, …).
    pub ecosystem: &'static str,
    /// The roles, a mask of [`HOSTED`], [`VENDORED`], [`PROBE`], [`ROOT`],
    /// [`PNPM_MARKER`] and [`PRESENCE_ONLY`].
    pub roles: u8,
}

impl FormatFile {
    pub fn has(&self, role: u8) -> bool {
        self.roles & role != 0
    }

    /// The path's last segment.
    pub fn basename(&self) -> &'static str {
        self.path.rsplit('/').next().unwrap_or(self.path)
    }
}

const fn row(path: &'static str, ecosystem: &'static str, roles: u8) -> FormatFile {
    FormatFile {
        path,
        ecosystem,
        roles,
    }
}

/// In the hosted planners' read order.
const REGISTRY: &[FormatFile] = &[
    // ── npm family ──
    row("package-lock.json", "npm", HOSTED | VENDORED | PROBE | ROOT),
    row("npm-shrinkwrap.json", "npm", HOSTED | VENDORED | PROBE | ROOT),
    row(
        "pnpm-lock.yaml",
        "npm",
        HOSTED | VENDORED | PROBE | ROOT | PNPM_MARKER,
    ),
    // Package-manager detection only: the vendor probe and the hosted
    // planners have never accepted these spellings.
    row("pnpm-lock.yml", "npm", PNPM_MARKER),
    row("pnpm-workspace.yaml", "npm", PNPM_MARKER),
    // pnpm <= 2 uses the same package identities under the old filename.
    row("shrinkwrap.yaml", "npm", HOSTED),
    row("node_modules/.modules.yaml", "npm", HOSTED),
    row("yarn.lock", "npm", HOSTED | VENDORED | PROBE | ROOT),
    // A berry lock's cache-config gate: read by the hosted planners only.
    row(".yarnrc.yml", "npm", HOSTED),
    row("bun.lock", "npm", HOSTED | VENDORED | PROBE | ROOT),
    // Binary Bun locks are read and rewritten natively, never text-scanned
    // for wiring.
    row("bun.lockb", "npm", HOSTED | PROBE | ROOT),
    row("vlt-lock.json", "npm", HOSTED | VENDORED | PROBE | ROOT),
    // vlt's config: a read-only hosted input (the old-lockfile advisory).
    row("vlt.json", "npm", HOSTED),
    // The hidden lock is only stat'ed as the install-state sentinel.
    row("node_modules/.vlt-lock.json", "npm", HOSTED),
    // The vendored planners' override surface; manifests never make a root.
    row("package.json", "npm", VENDORED),
    row("rush.json", "npm", ROOT),
    // ── pypi ──
    row("requirements.txt", "pypi", HOSTED | VENDORED | PROBE | ROOT),
    row("uv.lock", "pypi", HOSTED | VENDORED | PROBE | ROOT),
    row("poetry.lock", "pypi", HOSTED | VENDORED | PROBE | ROOT),
    row("pdm.lock", "pypi", HOSTED | VENDORED | PROBE | ROOT),
    row("Pipfile.lock", "pypi", HOSTED | VENDORED | PROBE | ROOT),
    // Never edited — its presence tells the Pipenv planner a Pipfile.lock is
    // live (a conflict there vetoes the sibling Python rewriters) rather
    // than abandoned.
    row("Pipfile", "pypi", HOSTED | PRESENCE_ONLY),
    row("pyproject.toml", "pypi", HOSTED | VENDORED | PROBE),
    row("hatch.toml", "pypi", HOSTED | PROBE),
    // ── cargo ──
    row("Cargo.toml", "cargo", HOSTED | VENDORED | PROBE),
    row("Cargo.lock", "cargo", HOSTED | VENDORED | ROOT),
    row(".cargo/config.toml", "cargo", HOSTED | VENDORED | PROBE),
    // The LEGACY extensionless spelling: cargo reads `.cargo/config` in
    // preference to `config.toml` when both exist, so the hosted planner
    // must see it (it wires the managed registry into whichever one is
    // present); vendored wiring before v5 lived there too.
    row(".cargo/config", "cargo", HOSTED | VENDORED | PROBE),
    // ── composer ──
    row("composer.json", "composer", VENDORED),
    row("composer.lock", "composer", HOSTED | VENDORED | PROBE | ROOT),
    // ── nuget ──
    row("nuget.config", "nuget", HOSTED | PROBE),
    row("NuGet.config", "nuget", HOSTED | PROBE),
    row("NuGet.Config", "nuget", HOSTED | PROBE),
    row("packages.lock.json", "nuget", HOSTED),
    // ── gem ──
    row("Gemfile", "gem", HOSTED | VENDORED),
    row("Gemfile.lock", "gem", HOSTED | VENDORED | PROBE | ROOT),
    // Bundler's modern manifest spelling — preferred over Gemfile when both
    // exist (the gem planner picks the pair bundler reads and fails closed
    // on diverging spellings).
    row("gems.rb", "gem", HOSTED),
    row("gems.locked", "gem", HOSTED | ROOT),
    // ── golang ──
    // The hosted planner edits the main module's go.mod (fork-style
    // `replace`) and go.sum (the socket module's two h1: lines); go.sum may
    // legitimately be absent — the planner creates it then.
    row("go.mod", "golang", HOSTED | VENDORED | PROBE | ROOT),
    row("go.sum", "golang", HOSTED | ROOT),
    // ── maven ──
    row("pom.xml", "maven", HOSTED | PROBE),
    // Maven Trusted Checksums files the fail-closed maven planner merges
    // into (read so an existing user config / checksum set is preserved).
    row(".mvn/maven.config", "maven", HOSTED),
    row(".mvn/checksums/checksums.sha256", "maven", HOSTED),
    // Never edited: its `distributionUrl` names the project's Maven, which
    // the maven planner checks against the Trusted Checksums floor (3.9.4)
    // to warn when the `.mvn/*` pin above would be inert.
    row(
        ".mvn/wrapper/maven-wrapper.properties",
        "maven",
        HOSTED | PRESENCE_ONLY,
    ),
    // ── gradle (the maven ecosystem's Gradle builds) ──
    // Settings files carry the apply line of the hosted and the vendored
    // owned scripts. Build scripts are never edited: their presence makes
    // the root a Gradle build, and the hosted planner reads them (with the
    // rest of the script graph, which the engine walks dynamically).
    row("settings.gradle", "maven", HOSTED | VENDORED),
    row("settings.gradle.kts", "maven", HOSTED | VENDORED),
    row("build.gradle", "maven", HOSTED | PRESENCE_ONLY),
    row("build.gradle.kts", "maven", HOSTED | PRESENCE_ONLY),
    // The root project's lock files; every other project's are walked
    // through the script graph. Never ROOT: the in-memory engine would
    // take them for maven roots (`ecosystem_unsupported_in_memory`).
    row("gradle.lockfile", "maven", HOSTED | PROBE),
    row("buildscript-gradle.lockfile", "maven", HOSTED | PROBE),
    row("settings-gradle.lockfile", "maven", HOSTED | PROBE),
    // Never created; an existing one gets the suffixed component.
    row("gradle/verification-metadata.xml", "maven", HOSTED),
    // Read for the wrapper's Gradle version (hosted patches need 6.8+).
    row(
        "gradle/wrapper/gradle-wrapper.properties",
        "maven",
        HOSTED | PRESENCE_ONLY,
    ),
    // The hosted planner's owned index and script.
    row(".socket/gradle/hosted-index.tsv", "maven", HOSTED | PROBE),
    row(
        ".socket/gradle/socket-patch.hosted.settings.gradle",
        "maven",
        HOSTED | PROBE,
    ),
    // The vendored Gradle index: ledger-less repair finds its rows.
    row(".socket/vendor/gradle-index.tsv", "maven", VENDORED | PROBE),
    // deno.lock is deliberately absent: deno is its own ecosystem
    // (JSR-crawled) and no planner edits its integrity entries.
];

/// Every row, in the hosted planners' read order.
pub fn registry() -> &'static [FormatFile] {
    REGISTRY
}

/// The paths of every row carrying `role`, in registry order.
pub fn paths_with(role: u8) -> Vec<&'static str> {
    REGISTRY
        .iter()
        .filter(|f| f.has(role))
        .map(|f| f.path)
        .collect()
}

/// The [`PROBE`] paths of `ecosystem`, in registry order.
pub fn probe_paths(ecosystem: &str) -> Vec<&'static str> {
    REGISTRY
        .iter()
        .filter(|f| f.ecosystem == ecosystem && f.has(PROBE))
        .map(|f| f.path)
        .collect()
}

/// The ecosystem whose hosted planner edits a candidate file, by basename
/// (`rel` may be nested, e.g. a Rush lock or a workspace member's
/// `Cargo.toml`); `None` for files no hosted rewriter edits.
pub fn hosted_file_ecosystem(rel: &str) -> Option<&'static str> {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    REGISTRY
        .iter()
        .find(|f| f.has(HOSTED) && !f.has(PRESENCE_ONLY) && f.basename() == base)
        .map(|f| f.ecosystem)
}

/// Files a vendored run writes that carry no [`VENDORED`] role (that role
/// also scopes `repair`'s fingerprint): pnpm's workspace file, NuGet's
/// config and lock (the vendored feed), the root `pom.xml` and
/// `.mvn/maven.config` (vendored Maven), and `hatch.toml` (vendored Hatch).
const VENDORED_WRITES_UNMARKED: &[&str] = &[
    "pnpm-workspace.yaml",
    "nuget.config",
    "NuGet.config",
    "NuGet.Config",
    "packages.lock.json",
    "pom.xml",
    ".mvn/maven.config",
    "hatch.toml",
];

/// The project-relative paths of `ecosystem` that a vendored run may
/// rewrite: the files a vendored dry run checks for symbolic links, since
/// the wet run's commit refuses to rename over one. Files a vendored run
/// only reads (`.yarnrc.yml`, `vlt.json`, `node_modules/.modules.yaml`, …)
/// are left out.
pub fn wiring_paths(ecosystem: &str) -> Vec<&'static str> {
    REGISTRY
        .iter()
        .filter(|f| {
            f.ecosystem == ecosystem
                && (f.has(VENDORED) || VENDORED_WRITES_UNMARKED.contains(&f.path))
        })
        .map(|f| f.path)
        .collect()
}

/// The [`ROOT`] row a basename names.
pub fn root_marker(base: &str) -> Option<&'static FormatFile> {
    REGISTRY.iter().find(|f| f.has(ROOT) && f.path == base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_unique_and_root_markers_are_root_level() {
        let mut paths: Vec<&str> = REGISTRY.iter().map(|f| f.path).collect();
        paths.sort_unstable();
        let before = paths.len();
        paths.dedup();
        assert_eq!(before, paths.len(), "duplicate registry path");
        for f in REGISTRY.iter().filter(|f| f.has(ROOT)) {
            assert!(!f.path.contains('/'), "{}: a root marker is a basename", f.path);
        }
    }

    #[test]
    fn wiring_paths_name_every_rewritable_file_of_the_ecosystem() {
        let npm = wiring_paths("npm");
        for p in [
            "package-lock.json",
            "yarn.lock",
            "package.json",
            "pnpm-workspace.yaml",
        ] {
            assert!(npm.contains(&p), "{p}");
        }
        let nuget = wiring_paths("nuget");
        assert!(nuget.contains(&"nuget.config") && nuget.contains(&"packages.lock.json"));
        assert!(
            !wiring_paths("maven").contains(&"build.gradle"),
            "presence only"
        );
        assert!(!npm.contains(&"uv.lock"));
        let maven = wiring_paths("maven");
        assert!(maven.contains(&"pom.xml") && maven.contains(&".mvn/maven.config"));
        assert!(wiring_paths("pypi").contains(&"hatch.toml"));
        // Read-only for a vendored run: never captured, never refused.
        for p in [
            ".yarnrc.yml",
            "vlt.json",
            "node_modules/.modules.yaml",
            "shrinkwrap.yaml",
        ] {
            assert!(!npm.contains(&p), "{p}");
        }
    }

    #[test]
    fn hosted_file_ecosystem_matches_basenames_of_edited_files_only() {
        assert_eq!(hosted_file_ecosystem("package-lock.json"), Some("npm"));
        assert_eq!(
            hosted_file_ecosystem("common/config/rush/pnpm-lock.yaml"),
            Some("npm")
        );
        assert_eq!(hosted_file_ecosystem(".modules.yaml"), Some("npm"));
        assert_eq!(hosted_file_ecosystem("crates/a/Cargo.toml"), Some("cargo"));
        assert_eq!(hosted_file_ecosystem(".cargo/config"), Some("cargo"));
        assert_eq!(hosted_file_ecosystem("checksums.sha256"), Some("maven"));
        assert_eq!(hosted_file_ecosystem("build.gradle"), None);
        assert_eq!(hosted_file_ecosystem("settings.gradle.kts"), Some("maven"));
        assert_eq!(hosted_file_ecosystem("sub/gradle.lockfile"), Some("maven"));
        assert_eq!(hosted_file_ecosystem("hosted-index.tsv"), Some("maven"));
        assert_eq!(
            hosted_file_ecosystem("gradle/verification-metadata.xml"),
            Some("maven")
        );
        assert_eq!(hosted_file_ecosystem("gradle-wrapper.properties"), None);
        assert_eq!(hosted_file_ecosystem("gradle-index.tsv"), None);
        assert_eq!(hosted_file_ecosystem("Pipfile"), None);
        assert_eq!(hosted_file_ecosystem("package.json"), None);
        assert_eq!(hosted_file_ecosystem("NuGet.Config"), Some("nuget"));
    }
}
