//! Goldens: the cross test of the workspace reader over every fixture
//! workspace (design 2.2, 2.7, 2.9, 4.2).
//!
//! Two sets of workspaces are read from disk, through the same
//! `DiskView` a run uses:
//!
//! - the fixture workspaces the real-Bazel cells build
//!   (`socket-patch-cli/tests/fixtures/bazel/{core,light,heavy}`), each
//!   pinned to the Bazel release its era names. What Bazel builds there is
//!   what the model must say is live, so they are held to that rule and
//!   to no committed listing: a package that adds a fixture workspace
//!   gets it checked without touching a file of this one;
//! - the shapes no cell builds (`tests/fixtures/bazel/workspaces/*.txt`):
//!   the refused rows of design 4.2, the `WORKSPACE` signatures of design
//!   2.7 and the dynamic declarations. Each is one text file holding the
//!   files of a workspace, staged into a temporary directory. No file
//!   under that directory has a Bazel file's name, so the fixture tree is
//!   not itself a Bazel workspace. Their models are rendered into
//!   `expected.golden` (`SOCKET_PATCH_BLESS_GOLDEN=1` rewrites it; review
//!   the diff).
//!
//! The tables below state what must hold whatever the golden says: each
//! signature of design 2.7 is found on its workspace, each row of design
//! 4.2 has a workspace whose hub is of that row's shape, and a dynamic
//! declaration leaves the model incomplete and its ecosystem undetermined.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use socket_patch_core::bazel::govern::governance;
use socket_patch_core::bazel::model::{
    BazelWorkspace, Completeness, DeclSystem, FileText, FileView, Gap, Governance, Hub, HubId,
    HubShape, Liveness, RootRef, Ruleset,
};
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::crawlers::types::Ecosystem;

const BLESS: &str = "SOCKET_PATCH_BLESS_GOLDEN";

fn core_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel/workspaces")
}

fn cli_fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../socket-patch-cli/tests/fixtures/bazel")
}

fn root_at(dir: &Path, project: &str) -> RootRef {
    RootRef {
        root: std::fs::canonicalize(dir).expect("resolve a fixture directory"),
        project_rel: project.to_string(),
        boundary_levels: 0,
    }
}

/// One fixture workspace: its model as read for the root, and the view to
/// read it again for another project. A model answers for the project it
/// was read for (`govern::governance`), and one view per root reads each
/// file once however many projects are asked about.
struct Fixture {
    ws: BazelWorkspace,
    dir: PathBuf,
    disk: DiskView,
    /// The Bazel release a cell fixture is built with.
    version: Option<&'static str>,
    /// What keeps a staged shape workspace on disk.
    _staged: Option<tempfile::TempDir>,
}

impl std::ops::Deref for Fixture {
    type Target = BazelWorkspace;

    fn deref(&self) -> &BazelWorkspace {
        &self.ws
    }
}

impl Fixture {
    fn open(
        name: &str,
        dir: &Path,
        version: Option<&'static str>,
        staged: Option<tempfile::TempDir>,
    ) -> Self {
        let disk = DiskView::new(&root_at(dir, ""));
        let ws = Self::read(dir, &disk, version, "");
        Self {
            ws: ws.unwrap_or_else(|gap| panic!("{name}: {gap:?}")),
            dir: dir.to_path_buf(),
            disk,
            version,
            _staged: staged,
        }
    }

    fn read(
        dir: &Path,
        disk: &DiskView,
        version: Option<&'static str>,
        project: &str,
    ) -> Result<BazelWorkspace, Gap> {
        let root = root_at(dir, project);
        match version {
            Some(version) => socket_patch_core::bazel::detect(&root, &Pinned { disk, version }),
            None => read_workspace(&root, disk),
        }
    }

    /// Governance of `ecosystem` at `project`, asked of the model read
    /// for that project.
    fn governance(&self, ecosystem: Ecosystem, project: &str) -> Governance {
        if project.is_empty() {
            return governance(&self.ws, ecosystem, project);
        }
        let ws = Self::read(&self.dir, &self.disk, self.version, project);
        let ws = ws.unwrap_or_else(|gap| panic!("{}: {gap:?}", self.dir.display()));
        // Whatever the project, the root holds the same declarations.
        assert_eq!(ws.hubs.len(), self.ws.hubs.len());
        governance(&ws, ecosystem, project)
    }
}

/// A fixture the real-Bazel cells build, with the Bazel release of its
/// era pinned: the cells pass the version to the launcher, and only the
/// toy fixtures commit a `.bazelversion`.
struct Pinned<'a> {
    disk: &'a DiskView,
    version: &'a str,
}

impl FileView for Pinned<'_> {
    fn read(&self, rel: &str) -> FileText {
        match (rel, self.disk.read(rel)) {
            (".bazelversion", FileText::Absent) => {
                FileText::Bytes(self.version.as_bytes().to_vec())
            }
            (_, read) => read,
        }
    }

    fn list(&self, dir: &str) -> Option<Vec<String>> {
        self.disk.list(dir)
    }
}

/// The Bazel release a fixture directory `e<major>[-<variant>]` is built
/// with (`MATRIX.json` of each fixture group).
fn era_version(name: &str) -> &'static str {
    match name.split('-').next().unwrap_or_default() {
        "e5" => "5.4.1",
        "e6" => "6.6.0",
        "e7" => "7.7.2",
        "e8" => "8.8.2",
        "e9" => "9.3.2",
        other => panic!("{name}: `{other}` names no era"),
    }
}

/// Every workspace of the real-Bazel fixture tree, by its path below it:
/// `<group>/[<ruleset>/]<system>/<era>`.
fn cell_workspaces() -> BTreeMap<String, Fixture> {
    fn walk(dir: &Path, top: &Path, out: &mut Vec<PathBuf>) {
        let boundary = ["MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"];
        if boundary.iter().any(|name| dir.join(name).is_file()) {
            return out.push(dir.strip_prefix(top).expect("below the tree").to_path_buf());
        }
        for entry in std::fs::read_dir(dir).expect("read a fixture directory") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, top, out);
            }
        }
    }
    let top = cli_fixtures();
    let mut dirs = Vec::new();
    for group in ["core", "light", "heavy"] {
        walk(&top.join(group), &top, &mut dirs);
    }
    let mut read = BTreeMap::new();
    for rel in dirs {
        let name = rel.to_string_lossy().replace('\\', "/");
        let era = name.rsplit('/').next().expect("an era directory");
        let version = Some(era_version(era));
        let fixture = Fixture::open(&name, &top.join(&rel), version, None);
        read.insert(name, fixture);
    }
    read
}

/// The files of one `workspaces/<name>.txt`: the lines after each
/// `=== <path>` line, up to the next one. What stands before the first
/// is a comment.
fn bundle(text: &str) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = Vec::new();
    for line in text.split_inclusive('\n') {
        match (line.strip_prefix("=== "), files.last_mut()) {
            (Some(path), _) => files.push((path.trim_end().to_string(), String::new())),
            (None, Some((_, content))) => content.push_str(line),
            (None, None) => {}
        }
    }
    files
}

/// Every workspace of `workspaces/*.txt`, staged on disk and read.
fn shape_workspaces() -> BTreeMap<String, Fixture> {
    let mut read = BTreeMap::new();
    for entry in std::fs::read_dir(core_fixtures()).expect("read the workspaces directory") {
        let path = entry.expect("a directory entry").path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str()?.strip_suffix(".txt"))
        else {
            continue;
        };
        let text = std::fs::read_to_string(&path).expect("read a workspace");
        let files = bundle(&text.replace("\r\n", "\n"));
        assert!(!files.is_empty(), "{name}: no `=== <path>` line");
        let staged = tempfile::tempdir().expect("a temporary directory");
        for (rel, content) in &files {
            let file = staged.path().join(rel);
            std::fs::create_dir_all(file.parent().expect("a parent")).expect("stage a directory");
            std::fs::write(&file, content).expect("stage a file");
        }
        let dir = staged.path().to_path_buf();
        let fixture = Fixture::open(name, &dir, None, Some(staged));
        read.insert(name.to_string(), fixture);
    }
    read
}

fn system_name(system: DeclSystem) -> &'static str {
    match system {
        DeclSystem::Bzlmod => "bzlmod",
        DeclSystem::Workspace => "workspace",
    }
}

fn liveness_name(liveness: &Liveness) -> &'static str {
    match liveness {
        Liveness::Live => "live",
        Liveness::Shadowed { .. } => "shadowed",
        Liveness::Dead { .. } => "dead",
        Liveness::NotImported => "not-imported",
        Liveness::NotRootModule => "not-root-module",
        Liveness::DevDependencyDropped => "dev-dependency-dropped",
        Liveness::Undecided { .. } => "undecided",
    }
}

fn governance_text(found: &Governance) -> String {
    let ids = |hubs: &[socket_patch_core::bazel::model::HubId]| {
        let ids: Vec<String> = hubs.iter().map(|hub| hub.0.to_string()).collect();
        ids.join(",")
    };
    match found {
        Governance::NotGoverned => "not-governed".to_string(),
        Governance::Governed(hubs) => format!("governed by {}", ids(hubs)),
        Governance::Inactive(hub, why) => {
            format!("inactive: hub {} is {}", hub.0, liveness_name(why))
        }
        Governance::Ambiguous(sites) => {
            let files: BTreeSet<&str> = sites.iter().map(|site| site.file.as_str()).collect();
            format!(
                "ambiguous: {}",
                files.into_iter().collect::<Vec<_>>().join(", ")
            )
        }
        Governance::Undetermined(gaps) => {
            let tokens: BTreeSet<&str> = gaps.iter().map(|gap| gap.token).collect();
            format!(
                "undetermined: {}",
                tokens.into_iter().collect::<Vec<_>>().join(", ")
            )
        }
    }
}

/// The ecosystems a ruleset can build, and the projects of a workspace a
/// hub names a file in (the root always).
fn questions(ws: &BazelWorkspace) -> Vec<(Ecosystem, String)> {
    let built = |ecosystem: &&Ecosystem| {
        Ruleset::ALL
            .iter()
            .any(|r| r.ecosystem() == Some(**ecosystem))
    };
    let dir = |path: &String| path.rsplit_once('/').map_or("", |(dir, _)| dir).to_string();
    let locks = ws.hubs.iter().flat_map(|hub| &hub.locks);
    let mut projects: BTreeSet<String> = locks
        .filter_map(|lock| lock.path.as_ref().map(dir))
        .collect();
    projects.insert(String::new());
    let mut out = Vec::new();
    for ecosystem in Ecosystem::all().iter().filter(built) {
        out.extend(projects.iter().map(|project| (*ecosystem, project.clone())));
    }
    out
}

fn render(name: &str, fixture: &Fixture) -> String {
    let ws = &fixture.ws;
    let mut out = format!("== {name}\n");
    let complete = match &ws.completeness {
        Completeness::Exact => "exact".to_string(),
        Completeness::Incomplete(gaps) => {
            let tokens: BTreeSet<&str> = gaps.iter().map(|gap| gap.token).collect();
            format!(
                "incomplete ({})",
                tokens.into_iter().collect::<Vec<_>>().join(", ")
            )
        }
    };
    let _ = writeln!(
        out,
        "bazel {} as {:?}, tier {:?}, read {complete}",
        ws.line, ws.system, ws.tier
    );
    for (id, hub) in ws.hubs.iter().enumerate() {
        let version = &hub.ruleset_version;
        let bound = |side: &Option<socket_patch_core::bazel::ruleset_version::Bound>| {
            side.as_ref()
                .map_or("?", |bound| bound.version.as_str())
                .to_string()
        };
        let _ = writeln!(
            out,
            "hub {id}: {} {:?} ({}) `{}` in {} [{}], {}{}, ruleset {}..{}",
            hub.ruleset.name(),
            hub.shape,
            hub.ecosystem.cli_name(),
            hub.decl.apparent_name,
            hub.decl.site.file,
            system_name(hub.decl.site.system),
            liveness_name(&hub.liveness),
            if hub.decl.literal {
                ""
            } else {
                ", not literal"
            },
            bound(&version.lo),
            bound(&version.hi),
        );
        for lock in &hub.locks {
            let path = lock.path.as_deref().unwrap_or("<unresolved>");
            let _ = writeln!(out, "  {:?} {} -> {path}", lock.role, lock.label);
        }
    }
    for signal in &ws.signals {
        let _ = writeln!(
            out,
            "signal: {} in {}",
            signal.ruleset.name(),
            signal.site.file
        );
    }
    for (ecosystem, project) in questions(ws) {
        let found = fixture.governance(ecosystem, &project);
        if found != Governance::NotGoverned {
            let _ = writeln!(
                out,
                "{} at `{project}`: {}",
                ecosystem.cli_name(),
                governance_text(&found)
            );
        }
    }
    out
}

/// The whole model of every shape workspace, as one reviewed text.
#[test]
fn every_shape_workspace_reads_to_its_golden() {
    let mut got = String::new();
    for (name, ws) in &shape_workspaces() {
        got.push_str(&render(name, ws));
    }
    let golden = core_fixtures().join("expected.golden");
    if std::env::var_os(BLESS).is_some() {
        std::fs::write(&golden, &got).expect("write the golden");
    }
    let want = std::fs::read_to_string(&golden)
        .unwrap_or_default()
        .replace("\r\n", "\n");
    assert!(
        got == want,
        "the workspace models differ from {}; rerun with {BLESS}=1 and review the diff",
        golden.display()
    );
}

fn all_workspaces() -> BTreeMap<String, Fixture> {
    let mut all = cell_workspaces();
    all.extend(shape_workspaces());
    all
}

use DeclSystem::{Bzlmod, Workspace};
use HubShape as S;

/// One declaration a fixture workspace must hold: the workspace, the
/// shape of the hub and the file family that declares it. The shape names
/// the ruleset whose recognizer must find it.
type Found = (&'static str, HubShape, DeclSystem);

/// Design 2.7, both signature columns: every way a ruleset declares a hub
/// under Bzlmod and in a `WORKSPACE`, on the workspace that has it.
const SIGNATURES: &[Found] = &[
    // rules_js: `npm.npm_translate_lock`, and the rule in a WORKSPACE.
    ("light/rules_js/bzlmod/e9", S::PnpmLock, Bzlmod),
    ("light/rules_js/workspace/e7", S::PnpmLock, Workspace),
    // rules_nodejs: `npm_install` and `yarn_install`.
    ("row05-rules_nodejs-install", S::NodeInstall, Workspace),
    // rules_python: `pip.parse`, `uv_lock`; `pip_parse`, `multi_pip_parse`
    // (also under `maybe` in a macro body) and legacy `pip_install`.
    ("heavy/rules_python/bzlmod/e9", S::PipParse, Bzlmod),
    ("heavy/rules_python_uv/bzlmod/e9", S::PipParseUvLock, Bzlmod),
    (
        "heavy/rules_python/workspace/e7",
        S::PipParseWorkspace,
        Workspace,
    ),
    (
        "row07-rules_python-multi-pip-parse",
        S::PipParseWorkspace,
        Workspace,
    ),
    ("row08-rules_python-pip-install", S::PipInstall, Workspace),
    // aspect_rules_py: `uv.project` and `uv.lockfile`.
    ("heavy/aspect_rules_py/bzlmod/e9", S::UvProject, Bzlmod),
    (
        "heavy/aspect_rules_py/bzlmod/e8-canary",
        S::UvLockfile,
        Bzlmod,
    ),
    // rules_pycross: the 0.x and the 2.0 tag APIs, pdm and a generated
    // `.bzl`, and `pycross_lock_repo` in a WORKSPACE.
    (
        "heavy/rules_pycross/bzlmod/e9-0.8.3",
        S::PycrossLockImport,
        Bzlmod,
    ),
    (
        "heavy/rules_pycross/bzlmod/e9",
        S::PycrossLockImport,
        Bzlmod,
    ),
    (
        "row13-rules_pycross-unsupported",
        S::PycrossUnsupported,
        Bzlmod,
    ),
    ("dynamic-workspace", S::PycrossUnsupported, Workspace),
    // rules_jvm_external: `maven.install` and `maven_install`.
    ("light/rules_jvm_external/bzlmod/e9", S::MavenPinned, Bzlmod),
    (
        "light/rules_jvm_external/bzlmod/e9-unpinned",
        S::MavenUnpinned,
        Bzlmod,
    ),
    (
        "row14-rules_jvm_external-workspace",
        S::MavenPinned,
        Workspace,
    ),
    (
        "row14-rules_jvm_external-workspace",
        S::MavenUnpinned,
        Workspace,
    ),
    // gazelle: `go_deps.from_file`; `go_repository` in the WORKSPACE and
    // in the file of `# gazelle:repository_macro`.
    ("heavy/gazelle/bzlmod/e9", S::GoDeps, Bzlmod),
    (
        "heavy/gazelle_workspace/workspace/e7",
        S::GoRepository,
        Workspace,
    ),
    (
        "heavy/gazelle_workspace/workspace/e7-macro",
        S::GoRepository,
        Workspace,
    ),
    // rules_rust: `crate.from_cargo`, `crate.from_specs`, `crates_vendor`
    // (a BUILD rule) and `crates_repository`.
    ("heavy/rules_rust/bzlmod/e9", S::CrateUniverseLocked, Bzlmod),
    (
        "heavy/rules_rust/bzlmod/e9-nolock",
        S::CrateUniverseUnlocked,
        Bzlmod,
    ),
    (
        "row22-rules_rust-from-specs-and-vendor",
        S::FromSpecs,
        Bzlmod,
    ),
    (
        "row22-rules_rust-from-specs-and-vendor",
        S::CratesVendor,
        Bzlmod,
    ),
    (
        "row20-rules_rust-workspace",
        S::CratesRepositoryUnlocked,
        Workspace,
    ),
    (
        "row20-rules_rust-workspace",
        S::CrateUniverseLocked,
        Workspace,
    ),
    ("heavy/rules_rs/bzlmod/e9", S::RulesRsHub, Bzlmod),
    // rules_ruby: `ruby.bundle_fetch`, `rb_bundle_fetch`, and the legacy
    // `rb_bundle` and bazelruby `ruby_bundle`.
    ("light/rules_ruby/bzlmod/e9", S::BundleFetch, Bzlmod),
    ("light/rules_ruby/workspace/e7", S::BundleFetch, Workspace),
    ("row27-rules_ruby-legacy", S::LegacyBundle, Workspace),
    // rules_dotnet: the generated extension of both header generations,
    // the per-group file in a WORKSPACE, and the single `paket.bzl`.
    ("light/rules_dotnet/bzlmod/e9", S::PaketGroup, Bzlmod),
    ("light/rules_dotnet/bzlmod/e7", S::PaketGroup, Bzlmod),
    ("row28-rules_dotnet-workspace", S::PaketGroup, Workspace),
    ("row29-rules_dotnet-single-file", S::PaketSingle, Workspace),
    ("light/rules_csharp/bzlmod/e9", S::NugetFromLock, Bzlmod),
    // Report-only: rules_req_compile, `http_jar` and another module's hub;
    // rules_poetry, bazel-deps and `jvm_maven_import_external`; cargo-raze.
    ("row31-report-only-bzlmod", S::ReportOnly, Bzlmod),
    ("row31-report-only-workspace", S::ReportOnly, Workspace),
    ("row24-cargo-raze", S::ReportOnly, Workspace),
];

/// Design 4.2: each row of the outcome table, the workspace that has the
/// shape and the `HubShape` the gate decides it by. Row 18 (a committed
/// Go `vendor/` with no hub for the module) is the absence of a hub.
const ROWS: &[(u8, &str, HubShape)] = &[
    (1, "light/rules_js/bzlmod/e9", S::PnpmLock),
    (2, "light/rules_js/bzlmod/e7-lock54", S::PnpmLock),
    (
        3,
        "light/rules_js/bzlmod/e9-upl-pnpm10",
        S::PnpmLockHashFile,
    ),
    (4, "row04-rules_js-import-mode", S::ImportMode),
    (5, "row05-rules_nodejs-install", S::NodeInstall),
    (6, "heavy/rules_python/bzlmod/e9", S::PipParse),
    (7, "heavy/rules_python/workspace/e7", S::PipParseWorkspace),
    (8, "row08-rules_python-pip-install", S::PipInstall),
    (9, "heavy/rules_python_uv/bzlmod/e9", S::PipParseUvLock),
    (10, "heavy/aspect_rules_py/bzlmod/e9", S::UvProject),
    (11, "heavy/aspect_rules_py/bzlmod/e8-canary", S::UvLockfile),
    (12, "heavy/rules_pycross/bzlmod/e9", S::PycrossLockImport),
    (13, "row13-rules_pycross-unsupported", S::PycrossUnsupported),
    (14, "light/rules_jvm_external/bzlmod/e9", S::MavenPinned),
    (
        15,
        "light/rules_jvm_external/bzlmod/e9-unpinned",
        S::MavenUnpinned,
    ),
    (16, "heavy/gazelle/bzlmod/e9", S::GoDeps),
    (17, "heavy/gazelle_workspace/workspace/e7", S::GoRepository),
    (19, "heavy/rules_rust/bzlmod/e9", S::CrateUniverseLocked),
    (
        20,
        "row20-rules_rust-workspace",
        S::CratesRepositoryUnlocked,
    ),
    (
        21,
        "heavy/rules_rust/bzlmod/e9-nolock",
        S::CrateUniverseUnlocked,
    ),
    (22, "row22-rules_rust-from-specs-and-vendor", S::FromSpecs),
    (
        23,
        "row22-rules_rust-from-specs-and-vendor",
        S::CratesVendor,
    ),
    (24, "row24-cargo-raze", S::ReportOnly),
    (25, "heavy/rules_rs/bzlmod/e9", S::RulesRsHub),
    (26, "light/rules_ruby/bzlmod/e9", S::BundleFetch),
    (27, "row27-rules_ruby-legacy", S::LegacyBundle),
    (28, "light/rules_dotnet/bzlmod/e9", S::PaketGroup),
    (29, "row29-rules_dotnet-single-file", S::PaketSingle),
    (30, "light/rules_csharp/bzlmod/e9", S::NugetFromLock),
    (31, "row31-report-only-bzlmod", S::ReportOnly),
];

fn workspace<'a>(all: &'a BTreeMap<String, Fixture>, name: &str) -> &'a Fixture {
    all.get(name)
        .unwrap_or_else(|| panic!("no fixture workspace {name}"))
}

/// Acceptance: every signature of design 2.7 is found on its fixture
/// workspace, by the recognizer of its ruleset, in its own file family.
#[test]
fn every_signature_of_design_2_7_is_found_on_its_workspace() {
    let all = all_workspaces();
    for (name, shape, system) in SIGNATURES {
        let ws = workspace(&all, name);
        let is = |hub: &&Hub| (hub.shape, hub.decl.site.system) == (*shape, *system);
        let found = ws.hubs.iter().find(is);
        let hub = found.unwrap_or_else(|| panic!("{name}: no {shape:?} hub in {system:?}"));
        assert_eq!(hub.ruleset, shape.ruleset(), "{name}");
        // A registry ruleset's hub is of that ruleset's ecosystem.
        let ecosystem = hub.ruleset.ecosystem();
        assert!(ecosystem.is_none_or(|e| e == hub.ecosystem), "{name}");
    }
    // Every ruleset with a recognizer has a signature here.
    let covered: BTreeSet<Ruleset> = SIGNATURES.iter().map(|found| found.1.ruleset()).collect();
    assert_eq!(covered.into_iter().collect::<Vec<_>>(), Ruleset::ALL);
}

/// Acceptance: every shape of design 4.2 maps to its row. Each row has a
/// workspace whose hub is of the row's shape, and no `HubShape` is left
/// without a row.
#[test]
fn every_row_of_design_4_2_has_a_workspace_of_its_shape() {
    let all = all_workspaces();
    for (row, name, shape) in ROWS {
        let hubs = &workspace(&all, name).hubs;
        assert!(
            hubs.iter().any(|hub| hub.shape == *shape),
            "row {row}: {name} has no {shape:?}"
        );
    }
    let rows: Vec<u8> = ROWS.iter().map(|row| row.0).collect();
    let table: Vec<u8> = (1..=31).filter(|row| *row != 18).collect();
    assert_eq!(rows, table);
    let shapes: BTreeSet<HubShape> = ROWS.iter().map(|row| row.2).collect();
    assert_eq!(shapes.into_iter().collect::<Vec<_>>(), HubShape::ALL);
}

/// Acceptance: dynamic shapes are incomplete. A computed lock label, a
/// computed hub name, a hub behind a function of another repository and
/// a computed extension label each leave the model incomplete and the
/// ecosystem undetermined, and never ungoverned.
#[test]
fn a_dynamic_declaration_is_incomplete_and_undetermined() {
    use Ecosystem::{Cargo, Golang, Maven, Npm, Pypi};
    let all = all_workspaces();
    for (name, undetermined) in [
        ("dynamic-bzlmod", &[Npm, Maven][..]),
        ("dynamic-workspace", &[Pypi, Maven]),
        (
            "dynamic-extension-label",
            &[Npm, Pypi, Maven, Golang, Cargo],
        ),
    ] {
        let ws = workspace(&all, name);
        assert!(
            matches!(ws.completeness, Completeness::Incomplete(_)),
            "{name}"
        );
        for ecosystem in undetermined {
            for project in ["", "web", "any/other"] {
                let found = ws.governance(*ecosystem, project);
                let Governance::Undetermined(gaps) = &found else {
                    panic!("{name}: {ecosystem:?} at `{project}` is {found:?}");
                };
                assert!(
                    gaps.iter().all(|gap| !gap.detail.is_empty()),
                    "{name}: {gaps:?}"
                );
            }
        }
        // What was not followed is on the model: a hub marked as not
        // literal, which no lane edits, or the ruleset as a signal.
        let unread = ws.hubs.iter().any(|hub| !hub.decl.literal);
        assert!(unread || !ws.signals.is_empty(), "{name}: {:?}", ws.hubs);
    }
    // Every other fixture is read in full.
    for (name, ws) in all.iter().filter(|(name, _)| !name.starts_with("dynamic-")) {
        assert_eq!(ws.completeness, Completeness::Exact, "{name}");
        assert!(
            ws.signals.is_empty() && ws.ruleset_gaps.is_empty(),
            "{name}"
        );
    }
}

/// The cross test: on each workspace a real-Bazel cell builds, the hub
/// the cell consumes is live under the Bazel release of its era, and its
/// lock's project is governed by it. The one exception is stated: Bazel 6
/// reads `MODULE.bazel` only under `--enable_bzlmod`, which the 6.x cells
/// pass on the command line and no tracked file of the fixture sets.
///
/// A fixture added later is held to the same rule. One that is meant to
/// be dead, or not literal, is a shape for `workspaces/` or an exception
/// to state here.
#[test]
fn the_hub_a_cell_builds_from_is_live_and_governs_its_lock() {
    let cells = cell_workspaces();
    let mut checked = 0;
    for (name, ws) in &cells {
        let parts: Vec<&str> = name.split('/').collect();
        let [_, dir, system, era] = parts[..] else {
            // The toy fixtures use no ruleset: nothing is recognized.
            assert!(name.starts_with("core/") && ws.hubs.is_empty(), "{name}");
            continue;
        };
        // `rules_python_uv` and `gazelle_workspace` are fixture sets of
        // the ruleset whose name they start with.
        let named = Ruleset::ALL.iter().filter(|r| dir.starts_with(r.name()));
        let ruleset = named.max_by_key(|r| r.name().len());
        let ruleset = *ruleset.unwrap_or_else(|| panic!("{name}: `{dir}` is no ruleset"));
        let system = match system {
            "bzlmod" => Bzlmod,
            "workspace" => Workspace,
            other => panic!("{name}: `{other}` is no dependency system"),
        };
        let own = |hub: &&Hub| hub.ruleset == ruleset && hub.decl.site.system == system;
        let id = ws.hubs.iter().position(|hub| own(&hub));
        let id = id.unwrap_or_else(|| panic!("{name}: no {ruleset:?} hub in {system:?}"));
        let hub = &ws.hubs[id];
        assert!(hub.decl.literal, "{name}");
        let project = hub.locks.first().and_then(|lock| lock.path.as_deref());
        let project = project
            .and_then(|path| path.rsplit_once('/'))
            .map_or("", |(dir, _)| dir);
        let found = ws.governance(hub.ecosystem, project);
        if system == Bzlmod && era.starts_with("e6") {
            assert!(
                matches!(hub.liveness, Liveness::Dead { .. }),
                "{name}: {:?}",
                hub.liveness
            );
            assert!(
                matches!(found, Governance::Inactive(..)),
                "{name}: {found:?}"
            );
        } else {
            assert_eq!(hub.liveness, Liveness::Live, "{name}");
            let Governance::Governed(hubs) = &found else {
                panic!("{name}: {found:?}");
            };
            assert!(hubs.contains(&HubId(id)), "{name}: {hubs:?}");
            // Each cell pins its ruleset, so the version is known.
            assert!(
                hub.ruleset_version.lo.is_some(),
                "{name}: {:?}",
                hub.ruleset_version
            );
        }
        checked += 1;
    }
    assert!(checked >= 50, "only {checked} ruleset fixtures were found");
}
