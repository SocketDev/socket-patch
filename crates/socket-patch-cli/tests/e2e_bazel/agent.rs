//! Hermetic CLI tests: agent mode in a Bazel workspace (design 3, hazards
//! HZ-01, HZ-19 and HZ-23; revision 4, sections 8.1, 8.4, 8.5 and 8.7 of
//! the architecture).
//!
//! `apply`, `apply --check` and `scan --mode agent` (with the apply it
//! ends with, or with none) work on an installed tree. Where a ruleset
//! builds a package from its lock, the built binary must say so once per
//! run, mark the package in `--json`, and otherwise do exactly what it
//! does in the same checkout without the Bazel files: the same events,
//! the same bytes on disk, the same exit code. Every test here has that
//! twin.
//!
//! What a test expects of a governed package is computed from the lane
//! table (`lanes::admits`), never from "agent mode writes nothing": the
//! advisory is over the patches the build does not consume, and a lane
//! that serves the cell takes its package out of it.
//!
//! No Bazel and no network: a fake Socket API serves the one scan that
//! applies, and nothing here writes outside an installed tree.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_cli::bazel_gate::{agent, Loader, RunCx};
use socket_patch_core::bazel::codes::Code;
use socket_patch_core::bazel::lanes::{self, Cell};
use socket_patch_core::bazel::model::{Governance, Mode};
use socket_patch_core::crawlers::types::Ecosystem;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::bazel_common::{changes, snapshot};
use crate::common::envelope::{event_for, events, parse_json_envelope, warning_codes};
use crate::common::hermetic;
use crate::common::jvm_env;
use crate::common::{binary, git_sha256, hermetic_command, write_blob};

const ORG: &str = "test-org";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const OTHER_UUID: &str = "0b5e1c1e-5f0a-4c8e-9a51-6d1f3c2b7a90";
const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
const IS_ODD: &str = "pkg:npm/is-odd@3.0.1";
const PRISTINE: &[u8] = b"module.exports = 'upstream'\n";
const PATCHED: &[u8] = b"patched\n";
/// [`PATCHED`], as the API sends a blob.
const PATCHED_BASE64: &str = "cGF0Y2hlZAo=";

/// rules_js over `//:pnpm-lock.yaml`: Bazel builds the npm packages of
/// the workspace root from that lock.
const RULES_JS: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
    npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
    npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
    use_repo(npm, \"npm\")\n";

/// A scratch checkout, canonical: the binary prints resolved paths. The
/// `.git` directory bounds every upward read, so the Bazel roots of a
/// test are the ones it writes.
struct Checkout {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Checkout {
    fn new() -> Self {
        Self::below("")
    }

    /// A checkout `dir` levels below the scratch directory, so that a
    /// test can write above the repository.
    fn below(dir: &str) -> Self {
        let tmp = tempfile::tempdir().expect("a temporary directory");
        let root = at(&tmp.path().canonicalize().expect("its real path"), dir);
        std::fs::create_dir_all(root.join(".git")).expect("mkdir");
        Self { _tmp: tmp, root }
    }

    /// One of the light fixture workspaces, copied.
    fn fixture(rel: &str) -> Self {
        let checkout = Self::new();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel/light");
        crate::common::fs_tree::copy_tree(&at(&fixtures, rel), &checkout.root);
        checkout
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let file = at(&self.root, rel);
        std::fs::create_dir_all(file.parent().expect("a parent")).expect("mkdir");
        std::fs::write(&file, bytes).expect("write");
    }

    fn remove(&self, rel: &str) {
        std::fs::remove_file(at(&self.root, rel)).expect("remove");
    }

    fn read(&self, rel: &str) -> Vec<u8> {
        std::fs::read(at(&self.root, rel)).expect("read")
    }

    /// The rules_js workspace at the root, with `left-pad` installed.
    fn rules_js() -> Self {
        let checkout = Self::new();
        checkout.put("MODULE.bazel", RULES_JS);
        checkout.put(".bazelversion", "9.3.2\n");
        checkout.put("pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        checkout.npm_project("");
        checkout
    }

    /// The same checkout with no Bazel file: the twin of a run.
    fn without_bazel(self) -> Self {
        self.remove("MODULE.bazel");
        self.remove(".bazelversion");
        self
    }

    /// The rules_js workspace before any scan: no manifest, a lock that
    /// resolves each of `locked`, and `left-pad` installed or not.
    fn rules_js_unscanned(locked: &[(&str, &str)], installed: bool) -> Self {
        let checkout = Self::rules_js();
        std::fs::remove_dir_all(checkout.root.join(".socket")).expect("no manifest yet");
        if !installed {
            std::fs::remove_dir_all(checkout.root.join("node_modules")).expect("no install");
        }
        let wanted = |(name, version): &(&str, &str)| format!("\"{name}\": \"{version}\"");
        let wanted: Vec<String> = locked.iter().map(wanted).collect();
        let manifest = format!(
            "{{\"name\": \"app\", \"version\": \"0.0.0\", \"dependencies\": {{{}}}}}",
            wanted.join(", ")
        );
        checkout.put("package.json", manifest);
        checkout.put("pnpm-lock.yaml", pnpm_lock(locked));
        checkout
    }

    /// A vendor ledger that owns each of `purls`.
    fn vendor_ledger(&self, purls: &[&str]) {
        let entry = |purl: &&str| {
            let artifact = json!({ "path": format!(".socket/vendor/npm/{UUID}/pkg.tgz") });
            let entry = json!({
                "ecosystem": "npm", "basePurl": purl, "uuid": UUID,
                "artifact": artifact, "wiring": [],
            });
            (purl.to_string(), entry)
        };
        let entries: serde_json::Map<String, Value> = purls.iter().map(entry).collect();
        let state = json!({ "version": 1, "entries": entries });
        let text = serde_json::to_string_pretty(&state).expect("JSON");
        self.put(".socket/vendor/state.json", text);
    }

    /// An npm project at `dir` with `left-pad` installed and its patch
    /// in the manifest and the blob store.
    fn npm_project(&self, dir: &str) {
        let file = |name: &str| match dir {
            "" => name.to_string(),
            dir => format!("{dir}/{name}"),
        };
        self.put(
            &file("package.json"),
            r#"{"name": "app", "version": "0.0.0"}"#,
        );
        let installed = file("node_modules/left-pad");
        let manifest = r#"{"name": "left-pad", "version": "1.3.0"}"#;
        self.put(&format!("{installed}/package.json"), manifest);
        self.put(&format!("{installed}/index.js"), PRISTINE);
        self.manifest(dir, &[LEFT_PAD]);
    }

    /// A manifest at `dir` with one record per purl, each patching
    /// `package/index.js`, and the patched blob beside it.
    fn manifest(&self, dir: &str, purls: &[&str]) {
        let files = json!({ "package/index.js": {
            "beforeHash": git_sha256(PRISTINE), "afterHash": git_sha256(PATCHED),
        }});
        let record = |purl: &&str| {
            let record = json!({
                "uuid": UUID, "exportedAt": "2026-01-01T00:00:00Z", "files": files,
                "vulnerabilities": {}, "description": "synthetic test patch",
                "license": "MIT", "tier": "free",
            });
            (purl.to_string(), record)
        };
        let patches: serde_json::Map<String, Value> = purls.iter().map(record).collect();
        let text = serde_json::to_string_pretty(&json!({ "patches": patches })).expect("JSON");
        let file = match dir {
            "" => ".socket/manifest.json".to_string(),
            dir => format!("{dir}/.socket/manifest.json"),
        };
        self.put(&file, text);
        let socket = at(&self.root, file.trim_end_matches("manifest.json"));
        write_blob(&socket, &git_sha256(PATCHED), PATCHED);
    }
}

/// A pnpm lock (version 9) whose root importer resolves each
/// `(name, version)`.
fn pnpm_lock(packages: &[(&str, &str)]) -> String {
    let integrity = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bzwSnBRgV8t4CeXpKdn\
                     bCeKyqmYLYzmDaVQ==";
    let mut lock = "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  \
                    excludeLinksFromLockfile: false\n\nimporters:\n\n  .:\n    dependencies:\n"
        .to_string();
    for (name, version) in packages {
        lock.push_str(&format!(
            "      {name}:\n        specifier: {version}\n        version: {version}\n"
        ));
    }
    lock.push_str("\npackages:\n");
    for (name, version) in packages {
        lock.push_str(&format!(
            "\n  {name}@{version}:\n    resolution: {{integrity: {integrity}}}\n"
        ));
    }
    lock.push_str("\nsnapshots:\n");
    for (name, version) in packages {
        lock.push_str(&format!("\n  {name}@{version}: {{}}\n"));
    }
    lock
}

/// `rel` below `root`, level by level.
fn at(root: &Path, rel: &str) -> PathBuf {
    let levels = rel.split('/').filter(|level| !level.is_empty());
    levels.fold(root.to_path_buf(), |dir, level| dir.join(level))
}

/// The binary in `cwd`: `(exit code, stdout, stderr)`. No host virtualenv,
/// bundler setting, Go cache or JVM cache reaches the crawlers.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    hermetic::scrub_crawler_inputs(&mut cmd);
    jvm_env::isolate_cli(&mut cmd);
    cmd.args(args).current_dir(cwd);
    let out = cmd.output().expect("run socket-patch");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        out.status.code().unwrap_or(-1),
        text(&out.stdout),
        text(&out.stderr),
    )
}

/// A command that prints an envelope: the exit code and the envelope.
fn json_run(cwd: &Path, args: &[&str]) -> (i32, Value) {
    let (code, stdout, stderr) = run(cwd, &[args, &["--json"]].concat());
    assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
    (code, parse_json_envelope(&stdout))
}

/// The entries of `warnings[]` whose code is a code of the Bazel
/// section, as `(code, detail)`.
fn bazel_warnings(envelope: &Value) -> Vec<(String, String)> {
    let known = |code: &str| Code::ALL.iter().any(|known| known.as_str() == code);
    let text = |entry: &Value, key: &str| entry[key].as_str().unwrap_or_default().to_string();
    let warnings = envelope["warnings"].as_array().cloned().unwrap_or_default();
    let ours = warnings.iter().filter(|w| known(&text(w, "code")));
    ours.map(|w| (text(w, "code"), text(w, "detail"))).collect()
}

/// The details of the entries of `code`.
fn said(envelope: &Value, code: Code) -> Vec<String> {
    let of = bazel_warnings(envelope).into_iter();
    let of = of.filter(|(found, _)| found == code.as_str());
    of.map(|(_, detail)| detail).collect()
}

/// `envelope` as the same run prints it where Bazel has nothing to say:
/// no entry of a Bazel code, and no `details.bazel`.
fn without_bazel(envelope: &Value) -> Value {
    let mut plain = envelope.clone();
    let known = |w: &Value| Code::ALL.iter().any(|code| w["code"] == code.as_str());
    if let Some(warnings) = plain["warnings"].as_array_mut() {
        warnings.retain(|w| !known(w));
    }
    if plain["warnings"].as_array().is_some_and(Vec::is_empty) {
        plain.as_object_mut().expect("an object").remove("warnings");
    }
    for event in plain["events"].as_array_mut().into_iter().flatten() {
        let members = event.as_object_mut().expect("an event");
        let mut details = members.remove("details").unwrap_or(Value::Null);
        if let Some(of) = details.as_object_mut() {
            of.remove("bazel");
            if !of.is_empty() {
                members.insert("details".to_string(), details);
            }
        }
    }
    plain
}

/// What the lane table of this release says about the hubs that govern
/// `ecosystem` in the project at `project`: whether an enabled agent lane
/// serves any of them, and the mode the advisory names for each
/// (`agent::remedy`, computed again here from `lanes::admits`).
fn cells(project: &Path, ecosystem: Ecosystem) -> (bool, Vec<Option<Mode>>) {
    let loaded = Loader::new(RunCx::default()).load(project);
    let Governance::Governed(hubs) = loaded.governance(ecosystem) else {
        panic!(
            "{} is not governed at {}",
            ecosystem.cli_name(),
            project.display()
        );
    };
    let ws = loaded.models()[0].as_ref().expect("a model");
    let admits = |hub, mode| {
        let cell = Cell::of(ws, hub, mode).expect("a hub of the model");
        lanes::admits(&lanes::PRODUCTION, &cell)
    };
    let served = hubs.iter().any(|hub| admits(*hub, Mode::Agent));
    let remedy = |hub: &_| {
        let mut modes = [Mode::Vendored, Mode::Hosted].into_iter();
        let named = modes.find(|mode| admits(*hub, *mode));
        assert_eq!(agent::remedy(&lanes::PRODUCTION, ws, *hub), named);
        named
    };
    (served, hubs.iter().map(remedy).collect())
}

/// Holds an advisory to what the lane table says: the command of the
/// mode a lane serves the hub in, and no command where none does.
fn assert_remedy(detail: &str, remedies: &[Option<Mode>]) {
    for remedy in remedies {
        match remedy {
            Some(Mode::Vendored) => assert!(detail.contains("`socket-patch scan --mode vendored`")),
            Some(Mode::Hosted) => assert!(detail.contains("`socket-patch scan --mode hosted`")),
            Some(Mode::Agent) => panic!("agent mode is no remedy for agent mode"),
            None => assert!(
                detail.contains("no socket-patch release patches this Bazel shape yet"),
                "{detail}"
            ),
        }
    }
    if remedies.iter().all(Option::is_none) {
        assert!(!detail.contains("socket-patch scan"), "{detail}");
    }
}

/// The advisory of a run over a package that hubs govern, held to the
/// lane table: there is exactly one where no agent lane serves a hub, and
/// none where one does. Returns its detail.
fn advisory(envelope: &Value, served: bool) -> Option<String> {
    let advised = said(envelope, Code::AgentNotConsumed);
    assert_eq!(advised.len(), usize::from(!served), "{envelope:#}");
    advised.into_iter().next()
}

/// Every `details.bazel` of `envelope`, each held to its shape: an object
/// whose one member is `state`.
fn states(envelope: &Value) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for event in events(envelope) {
        let Some(bazel) = event
            .get("details")
            .and_then(|details| details.get("bazel"))
        else {
            continue;
        };
        let members = bazel.as_object();
        let members = members.unwrap_or_else(|| panic!("`details.bazel` is no object: {event}"));
        let names: Vec<&String> = members.keys().collect();
        assert_eq!(names, ["state"], "{event}");
        let state = members["state"].as_str().expect("a string").to_string();
        assert!(["not_consumed", "consumed"].contains(&&*state), "{event}");
        found.push((event["purl"].as_str().expect("a purl").to_string(), state));
    }
    found
}

// ── HZ-01: the advisory ──────────────────────────────────────────────

/// `apply` patches the installed copy as it always did, says once that
/// the Bazel build does not get the patch, and keeps its exit code. The
/// same checkout without the Bazel files is the oracle for everything
/// else the run prints.
#[test]
fn apply_says_once_what_the_bazel_build_does_not_get() {
    let ws = Checkout::rules_js();
    let (served, remedies) = cells(&ws.root, Ecosystem::Npm);
    let before = snapshot(&ws.root);

    // A dry run says the same and writes nothing.
    let (code, dry) = json_run(&ws.root, &["apply", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "{dry:#}");
    advisory(&dry, served);
    assert!(changes(&before, &snapshot(&ws.root)).is_empty());

    let (code, first) = json_run(&ws.root, &["apply", "--offline"]);
    assert_eq!(code, 0, "{first:#}");
    assert_eq!(event_for(&first, LEFT_PAD)["action"], "applied");
    assert_eq!(ws.read("node_modules/left-pad/index.js"), PATCHED);
    if let Some(detail) = advisory(&first, served) {
        assert!(detail.contains(LEFT_PAD), "{detail}");
        assert!(detail.contains("rules_js hub `npm` builds npm packages from pnpm-lock.yaml"));
        assert!(detail.contains("the exit code is unchanged"), "{detail}");
        assert_remedy(&detail, &remedies);
        let marked = [(LEFT_PAD.to_string(), "not_consumed".to_string())];
        assert_eq!(states(&first), marked);
    }
    // The workspace is named once, as a note.
    assert_eq!(said(&first, Code::WorkspaceDetected).len(), 1, "{first:#}");
    // Nothing Bazel reads was written: the installed copy alone changed.
    let changed = changes(&before, &snapshot(&ws.root));
    let paths: Vec<&str> = changed.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, ["node_modules/left-pad/index.js"]);

    // A second run finds the copy patched and says the same once more.
    let (code, again) = json_run(&ws.root, &["apply", "--offline"]);
    assert_eq!(code, 0, "{again:#}");
    assert_eq!(event_for(&again, LEFT_PAD)["errorCode"], "already_patched");
    assert_eq!(advisory(&again, served), advisory(&first, served));

    // For a person: the advisory is one `Warning:` line and the notes
    // are `Note:` lines. Everything else the run prints, and all of it
    // under `--silent`, is what the twin prints: the same checkout with
    // no Bazel file.
    let plain = Checkout::rules_js();
    plain.remove("MODULE.bazel");
    plain.remove(".bazelversion");
    let (code, twin) = json_run(&plain.root, &["apply", "--offline"]);
    assert_eq!(code, 0, "{twin:#}");
    assert_eq!(bazel_warnings(&twin), []);
    assert_eq!(states(&twin), []);
    assert_eq!(twin, without_bazel(&first));
    let (code, twin) = json_run(&plain.root, &["apply", "--offline"]);
    assert_eq!((code, &twin), (0, &without_bazel(&again)));

    let (code, stdout, stderr) = run(&ws.root, &["apply", "--offline"]);
    let (twin_code, twin_stdout, twin_stderr) = run(&plain.root, &["apply", "--offline"]);
    assert_eq!((code, &stdout), (twin_code, &twin_stdout), "{stderr}");
    let advised = |line: &&str| line.starts_with("Warning: 1 patch is for a package");
    let noted = |line: &&str| line.starts_with("Note: Bazel workspace ");
    assert_eq!(stderr.lines().filter(advised).count(), usize::from(!served));
    assert_eq!(stderr.lines().filter(noted).count(), 2, "{stderr}");
    let rest = stderr.lines().filter(|line| !advised(line) && !noted(line));
    let rest: Vec<&str> = rest.collect();
    assert_eq!(rest, twin_stderr.lines().collect::<Vec<_>>());
    assert!(!twin_stderr.contains("Bazel"), "{twin_stderr}");
    let silent = ["apply", "--offline", "--silent"];
    assert_eq!(run(&ws.root, &silent), run(&plain.root, &silent));
    assert!(!run(&ws.root, &silent).2.contains("Bazel"));
}

/// HZ-01, revision 3: the gem crawler falls back to the host as the
/// Python one does, so a governed Ruby root with no bundle is where a
/// patch reaches only a tree Bazel never builds. The lock gems are not
/// installed at all here; the run ends as it does without Bazel and says
/// what Bazel builds them from.
#[test]
fn a_governed_ruby_root_with_no_bundle_is_advised() {
    let gem = "pkg:gem/sp-victim@1.0.0";
    let lay = || {
        let ws = Checkout::fixture("rules_ruby/bzlmod/e9");
        ws.manifest("", &[gem]);
        ws
    };
    let ws = lay();
    let (served, remedies) = cells(&ws.root, Ecosystem::Gem);
    let plain = lay();
    plain.remove("MODULE.bazel");
    for args in [
        &["apply", "--offline"][..],
        &["apply", "--offline", "--dry-run"],
        &["apply", "--offline", "--check"],
    ] {
        let before = snapshot(&ws.root);
        let (code, envelope) = json_run(&ws.root, args);
        let (plain_code, twin) = json_run(&plain.root, args);
        assert_eq!(code, plain_code, "{args:?}: {envelope:#}");
        assert_eq!(without_bazel(&envelope), twin, "{args:?}");
        assert_eq!(bazel_warnings(&twin), [], "{args:?}");
        assert!(changes(&before, &snapshot(&ws.root)).is_empty(), "{args:?}");
        // The lock resolves the gem, so it is a calm skip either way.
        assert_eq!(
            event_for(&envelope, gem)["errorCode"],
            "package_not_installed"
        );
        let Some(detail) = advisory(&envelope, served) else {
            continue;
        };
        assert!(detail.contains(gem), "{detail}");
        let hub = "rules_ruby hub `bundle` builds ruby packages from Gemfile.lock";
        assert!(detail.contains(hub), "{detail}");
        assert_remedy(&detail, &remedies);
        // Nothing is installed, so no run is said to have patched a
        // copy; and no reader lists a `Gemfile.lock` under rules_ruby, so
        // nothing is asserted about what Bazel builds.
        let did = match args.contains(&"--check") {
            true => "Installed copies are checked as before",
            false => "No installed copy was patched in this run",
        };
        assert!(detail.contains(did), "{args:?}: {detail}");
        assert!(!detail.contains("are patched"), "{args:?}: {detail}");
        assert!(detail.contains("nothing committed proves"), "{detail}");
        assert_eq!(
            states(&envelope),
            [(gem.to_string(), "not_consumed".to_string())]
        );
    }
}

/// Revision 4, 8.5: `details.bazel` is an object with a `state` member
/// wherever an agent command prints it, never a bare word.
#[test]
fn details_bazel_is_an_object() {
    let ws = Checkout::rules_js();
    let plain = Checkout::rules_js().without_bazel();
    let (served, _) = cells(&ws.root, Ecosystem::Npm);
    let mut seen = 0;
    for args in [
        &["apply", "--offline", "--check"][..],
        &["apply", "--offline", "--dry-run"],
        &["apply", "--offline"],
        &["apply", "--offline", "--check"],
    ] {
        // The first check finds drift and the last finds none: each run
        // exits as its twin does, and prints what the twin prints.
        let (code, envelope) = json_run(&ws.root, args);
        let (twin_code, twin) = json_run(&plain.root, args);
        assert_eq!(code, twin_code, "{args:?}: {envelope:#}");
        assert_eq!(without_bazel(&envelope), twin, "{args:?}");
        let found = states(&envelope);
        // Every event of the governed package carries it.
        let of_package = events(&envelope).iter().filter(|e| e["purl"] == LEFT_PAD);
        assert_eq!(found.len(), of_package.count(), "{args:?}: {envelope:#}");
        if !served {
            assert!(found.iter().all(|(_, state)| state == "not_consumed"));
        }
        seen += found.len();
    }
    assert!(seen >= 4, "no event carried `details.bazel`");
    // The raw text holds the member as an object, on every line it is on.
    let (_, stdout, _) = run(&ws.root, &["apply", "--offline", "--check", "--json"]);
    assert!(stdout.contains("\"bazel\": {"), "{stdout}");
    assert!(!stdout.contains("\"bazel\": \""), "{stdout}");

    // A local Go patch that is in sync has no event of its own in
    // `apply --check`: the check audits the committed copy and the
    // `replace`, and says nothing per package. Under a gazelle hub that
    // reads the project's `go.mod` the record is governed, and its state
    // needs an event to ride on. The redirect is written before the hub
    // is declared, as a release without the Go gate left it.
    let lay = |hub: Option<&str>| {
        let (ws, cache) = go_project();
        let (code, _, stderr) = go_run(&ws, &cache, &["apply", "--offline"]);
        assert_eq!(code, 0, "{stderr}");
        match hub {
            Some(module) => ws.put("MODULE.bazel", module),
            None => ws.remove("MODULE.bazel"),
        }
        let (code, stdout, stderr) = go_run(&ws, &cache, &["apply", "--check", "--json"]);
        (code, parse_json_envelope(&stdout), stderr)
    };
    let gazelle = "bazel_dep(name = \"gazelle\", version = \"0.45.0\")\n\
        go_deps = use_extension(\"@gazelle//:extensions.bzl\", \"go_deps\")\n\
        go_deps.from_file(go_mod = \"//:go.mod\")\n\
        use_repo(go_deps, \"com_example_m\")\n";
    let (code, envelope, stderr) = lay(Some(gazelle));
    let (twin_code, twin, _) = lay(None);
    assert_eq!((code, twin_code), (0, 0), "{envelope:#}\n{stderr}");
    assert_eq!(events(&twin), [] as [Value; 0], "{twin:#}");
    let [event] = events(&envelope) else {
        panic!("one event for the governed record: {envelope:#}");
    };
    assert_eq!(event["purl"], GO_PURL);
    assert_eq!(
        (&event["action"], &event["errorCode"]),
        (&json!("skipped"), &json!("already_patched"))
    );
    let marked = [(GO_PURL.to_string(), "not_consumed".to_string())];
    assert_eq!(states(&envelope), marked);
    // The hub reads the `go.mod` that carries the `replace`, and no lane
    // of this release vouches for what gazelle makes of it: the advisory
    // does not say that the build goes without the patch.
    let [detail] = &said(&envelope, Code::AgentNotConsumed)[..] else {
        panic!("{envelope:#}");
    };
    assert!(detail.contains("nothing committed proves"), "{detail}");
    assert!(!detail.contains("does not get"), "{detail}");
    assert!(detail.contains("Installed copies are checked as before"));
}

// ── Revision 4, 8.1: the governed set ────────────────────────────────

/// A manifest record that the hub's lock lists in full and does not
/// resolve is not in the advisory; a record of a hub nobody can list is.
/// `apply --check` also holds a project that no hub governs to the hub
/// lock elsewhere in the workspace; `apply` does not.
#[test]
fn governed_set() {
    let cases = [
        (
            "rules_jvm_external/bzlmod/e9",
            Ecosystem::Maven,
            "pkg:maven/com.google.code.gson/gson@2.10.1",
            "pkg:maven/com.example/absent@1.0.0",
            "rules_jvm_external hub `maven` builds maven packages from maven_install.json",
        ),
        (
            "rules_dotnet/bzlmod/e9",
            Ecosystem::Nuget,
            "pkg:nuget/SP.Victim@1.0.0",
            "pkg:nuget/SP.Absent@1.0.0",
            "rules_dotnet hub `paket.main` builds nuget packages from deps/paket.main.bzl",
        ),
    ];
    for (fixture, ecosystem, listed, absent, hub) in cases {
        let ws = Checkout::fixture(fixture);
        ws.manifest("", &[listed, absent]);
        let (served, remedies) = cells(&ws.root, ecosystem);
        // The twin: the same records in a checkout Bazel builds nothing
        // in. The exit code of each run is the twin's.
        let plain = Checkout::new();
        plain.manifest("", &[listed, absent]);
        plain.manifest("service-a", &[listed, absent]);
        for args in [
            &["apply", "--offline", "--check"][..],
            &["apply", "--offline"],
        ] {
            let (code, envelope) = json_run(&ws.root, args);
            let (twin_code, twin) = json_run(&plain.root, args);
            assert_eq!(code, twin_code, "{fixture} {args:?}: {envelope:#}");
            assert_eq!(without_bazel(&envelope), twin, "{fixture} {args:?}");
            let Some(detail) = advisory(&envelope, served) else {
                continue;
            };
            assert!(detail.starts_with("1 patch is for a package"), "{detail}");
            assert!(
                detail.contains(listed) && !detail.contains(absent),
                "{detail}"
            );
            assert!(detail.contains(hub), "{detail}");
            // The lock was listed, it resolves the release and nothing
            // pins the patch: this much is known.
            assert!(detail.contains("so the Bazel build does not get it"));
            assert_remedy(&detail, &remedies);
            let marked = [(listed.to_string(), "not_consumed".to_string())];
            assert_eq!(states(&envelope), marked, "{fixture} {args:?}");
        }

        // A project of the workspace that the hub does not govern: its
        // own `apply` is as it is without Bazel, and the check says that
        // a patched copy there is not what the hub builds. The hub builds
        // for another project, so no command run here is named.
        ws.manifest("service-a", &[listed, absent]);
        let (project, twin) = (ws.root.join("service-a"), plain.root.join("service-a"));
        let (code, applied) = json_run(&project, &["apply", "--offline"]);
        assert_eq!(code, json_run(&twin, &["apply", "--offline"]).0);
        assert_eq!(said(&applied, Code::AgentNotConsumed), [] as [String; 0]);
        assert_eq!(states(&applied), []);
        let (code, check) = json_run(&project, &["apply", "--offline", "--check"]);
        assert_eq!(code, json_run(&twin, &["apply", "--offline", "--check"]).0);
        let detail = advisory(&check, served).unwrap_or_default();
        assert_eq!(detail.contains(listed), !served, "{check:#}");
        assert!(!detail.contains(absent), "{detail}");
        assert_eq!(detail.contains("for another project"), !served, "{detail}");
        assert!(!detail.contains("socket-patch scan"), "{detail}");
    }

    // A lock nobody can list rules nothing out. The Maven lock, edited by
    // hand, no longer reproduces its hash; and no reader of this release
    // lists what a `Gemfile.lock` under rules_ruby resolves.
    let (fixture, _, listed, absent, _) = cases[0];
    let ws = Checkout::fixture(fixture);
    let lock = String::from_utf8(ws.read("maven_install.json")).expect("text");
    let edited = lock.replace("\"2.10.1\"", "\"2.10.2\"");
    assert_ne!(edited, lock);
    ws.put("maven_install.json", edited);
    ws.manifest("", &[listed, absent]);
    let (served, _) = cells(&ws.root, Ecosystem::Maven);
    let (_, envelope) = json_run(&ws.root, &["apply", "--offline", "--check"]);
    if let Some(detail) = advisory(&envelope, served) {
        assert!(
            detail.contains(listed) && detail.contains(absent),
            "{detail}"
        );
        // What the lock resolves is not known, and the text says no more.
        assert!(detail.contains("nothing committed proves"), "{detail}");
        assert!(!detail.contains("does not get"), "{detail}");
    }
    let ws = Checkout::fixture("rules_ruby/bzlmod/e9");
    let unlocked = "pkg:gem/sp-nowhere@9.9.9";
    ws.manifest("", &[unlocked]);
    let (served, _) = cells(&ws.root, Ecosystem::Gem);
    let (_, envelope) = json_run(&ws.root, &["apply", "--offline", "--check"]);
    if let Some(detail) = advisory(&envelope, served) {
        assert!(detail.contains(unlocked), "{detail}");
    }
}

// ── HZ-19: roots above the repository, and nested roots ──────────────

/// A workspace file above the repository is reported, and only a
/// confirmed one changes anything: its hubs were not read, so what it
/// may build is not known. Nested roots each build the project.
#[test]
fn a_workspace_above_the_repository_and_nested_roots_are_reported() {
    let ws = Checkout::below("outer/repo");
    ws.npm_project("");
    let outer = ws.root.parent().expect("the directory above").to_path_buf();
    std::fs::write(outer.join("MODULE.bazel"), "module(name = \"outer\")\n").expect("write");
    // A stray file: said, and nothing else changes.
    let (code, stray) = json_run(&ws.root, &["apply", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "{stray:#}");
    let above = said(&stray, Code::WorkspaceAboveRepo);
    assert_eq!(above.len(), 1, "{stray:#}");
    assert!(above[0].contains("it changes nothing"), "{above:?}");
    assert_eq!(said(&stray, Code::AgentNotConsumed), [] as [String; 0]);
    assert_eq!(states(&stray), []);

    // A second sign of Bazel beside it: somebody builds there.
    std::fs::write(outer.join(".bazelversion"), "9.3.2\n").expect("write");
    let (code, confirmed) = json_run(&ws.root, &["apply", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "{confirmed:#}");
    assert_eq!(said(&confirmed, Code::WorkspaceAboveRepo).len(), 1);
    // No hub was read, so no lane can serve one: the patch is advised.
    let [detail] = &said(&confirmed, Code::AgentNotConsumed)[..] else {
        panic!("{confirmed:#}");
    };
    let unknown = "which lock files Bazel builds npm packages from is not known";
    assert!(detail.contains(unknown), "{detail}");
    let marked = [(LEFT_PAD.to_string(), "not_consumed".to_string())];
    assert_eq!(states(&confirmed), marked);
    assert_eq!(without_bazel(&confirmed), without_bazel(&stray));

    // Nested roots: the outer one builds the project `sub` from its lock,
    // and `sub` is a Bazel root of its own.
    let ws = Checkout::new();
    let nested = RULES_JS.replace("//:pnpm-lock.yaml", "//sub:pnpm-lock.yaml");
    ws.put("MODULE.bazel", nested);
    ws.put(".bazelversion", "9.3.2\n");
    ws.put("sub/MODULE.bazel", "module(name = \"sub\")\n");
    ws.put("sub/BUILD.bazel", "");
    ws.put("sub/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    ws.npm_project("sub");
    let (code, envelope) = json_run(&ws.root.join("sub"), &["apply", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "{envelope:#}");
    let [detected] = &said(&envelope, Code::WorkspaceDetected)[..] else {
        panic!("{envelope:#}");
    };
    assert!(
        detected.contains("rules_js builds npm packages"),
        "{detected}"
    );
    // Each root builds the project and they are not one build: no lane
    // serves that, whatever the table holds.
    let [detail] = &said(&envelope, Code::AgentNotConsumed)[..] else {
        panic!("{envelope:#}");
    };
    assert!(detail.contains("rules_js hub `npm`"), "{detail}");
    // And so no command is named: another mode would be refused too.
    assert!(!detail.contains("socket-patch scan"), "{detail}");
    assert_eq!(states(&envelope), marked);
}

// ── A project with a local Go patch ──────────────────────────────────

const GO_PURL: &str = "pkg:golang/example.com/m@v1.0.0";

/// A Bazel root (`ws`, one level below the scratch directory) whose
/// `go.mod` requires the module of [`GO_PURL`], with the patch in the
/// manifest and the blob store, and a module cache beside the checkout
/// that holds the pristine module. No ruleset builds Go here.
fn go_project() -> (Checkout, PathBuf) {
    let (pristine, patched) = (
        &b"package m\n\nfunc V() int { return 1 }\n"[..],
        &b"package m\n\nfunc V() int { return 2 }\n"[..],
    );
    let ws = Checkout::below("ws");
    let cache = ws.root.parent().expect("above").join("modcache");
    let module = cache.join("example.com").join("m@v1.0.0");
    std::fs::create_dir_all(&module).expect("mkdir");
    std::fs::write(module.join("m.go"), pristine).expect("write");
    std::fs::write(module.join("go.mod"), "module example.com/m\n\ngo 1.21\n").expect("write");
    ws.put("MODULE.bazel", "module(name = \"ws\")\n");
    ws.put(
        "go.mod",
        "module example.com/app\n\ngo 1.21\n\nrequire example.com/m v1.0.0\n",
    );
    let files = json!({ "m.go": {
        "beforeHash": git_sha256(pristine), "afterHash": git_sha256(patched),
    }});
    let manifest = json!({ "patches": { GO_PURL: {
        "uuid": UUID, "exportedAt": "2026-01-01T00:00:00Z", "files": files,
        "vulnerabilities": {}, "description": "synthetic test patch",
        "license": "MIT", "tier": "free",
    }}});
    ws.put(".socket/manifest.json", manifest.to_string());
    write_blob(&ws.root.join(".socket"), &git_sha256(patched), patched);
    (ws, cache)
}

/// The binary in the Go project `ws`, over its module cache and the Go
/// patches alone: `(exit code, stdout, stderr)`.
fn go_run(ws: &Checkout, cache: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    hermetic::scrub_crawler_inputs(&mut cmd);
    jvm_env::isolate_cli(&mut cmd);
    cmd.env("GOMODCACHE", cache)
        .env("GOFLAGS", "")
        .env("GOWORK", "off");
    cmd.args([args, &["--ecosystems", "golang"]].concat());
    let out = cmd
        .current_dir(&ws.root)
        .output()
        .expect("run socket-patch");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    (
        out.status.code().unwrap_or(-1),
        text(&out.stdout),
        text(&out.stderr),
    )
}

// ── HZ-23, and the level of a run-level line ─────────────────────────

/// The counts of what Socket patches do not cover are one note. A root
/// with a `WORKSPACE` and a `WORKSPACE.bzlmod` counts the declarations of
/// both, and Bazel evaluates one of them, so the line says "declares"
/// (ROUTED R-094). `scan` says it too, once however many projects of the
/// run lie in the workspace.
#[tokio::test]
async fn the_out_of_scope_counts_are_one_note_that_says_declares() {
    let archive = |name: &str| {
        format!(
            "load(\"@bazel_tools//tools/build_defs/repo:http.bzl\", \"http_archive\")\n\
             http_archive(name = \"{name}\", urls = [\"https://example.com/{name}.tar.gz\"])\n"
        )
    };
    let ws = Checkout::new();
    ws.put(
        "MODULE.bazel",
        "module(name = \"ws\")\nbazel_dep(name = \"rules_cc\", version = \"0.1.1\")\n",
    );
    ws.put("WORKSPACE", archive("one"));
    ws.put("WORKSPACE.bzlmod", archive("two"));
    ws.put(".bazelversion", "7.7.2\n");
    ws.npm_project("");
    ws.npm_project("web");
    // A lock makes each a project that a bare scan finds.
    let lock = r#"{"name": "app", "version": "0.0.0", "lockfileVersion": 3,
        "packages": {"": {"name": "app", "version": "0.0.0"}}}"#;
    ws.put("package-lock.json", lock);
    ws.put("web/package-lock.json", lock);
    let (code, envelope) = json_run(&ws.root, &["apply", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "{envelope:#}");
    let [note] = &said(&envelope, Code::WorkspaceOutOfScope)[..] else {
        panic!("{envelope:#}");
    };
    assert!(note.starts_with("Bazel workspace "), "{note}");
    let counts = " declares 1 Bazel module, 2 source archives. ";
    assert!(note.contains(counts), "{note}");
    // No ruleset builds a registry package here: nothing is governed.
    assert_eq!(said(&envelope, Code::AgentNotConsumed), [] as [String; 0]);
    assert_eq!(states(&envelope), []);

    // For a person it is a note, which `--silent` hides.
    let (_, _, stderr) = run(&ws.root, &["apply", "--offline", "--dry-run"]);
    let line = format!("Note: {note}");
    assert_eq!(stderr.lines().filter(|l| *l == line).count(), 1, "{stderr}");
    assert!(!stderr.contains("Warning: Bazel workspace"), "{stderr}");
    let (_, _, stderr) = run(&ws.root, &["apply", "--offline", "--dry-run", "--silent"]);
    assert!(!stderr.contains("Bazel workspace"), "{stderr}");

    // A scan says it in every mode, and a bare scan over the two
    // projects of the workspace says it once.
    let api = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&api)
        .await;
    let uri = api.uri();
    let scan = |args: &[&str]| {
        let fixed = [
            "scan",
            "--api-url",
            &uri,
            "--api-token",
            "fake",
            "--org",
            ORG,
        ];
        run(&ws.root, &[&fixed[..], args].concat())
    };
    for mode in ["agent", "hosted", "vendored"] {
        let (code, stdout, stderr) = scan(&["--mode", mode, "--json", "--dry-run"]);
        assert_eq!(code, 0, "{mode}: {stdout}\n{stderr}");
        let envelope = parse_json_envelope(&stdout);
        assert_eq!(
            said(&envelope, Code::WorkspaceOutOfScope),
            [note.clone()],
            "{mode}"
        );
    }
    let (code, stdout, stderr) = scan(&["--mode", "hosted", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("== web =="),
        "two projects were scanned:\n{stdout}"
    );
    assert_eq!(stderr.lines().filter(|l| *l == line).count(), 1, "{stderr}");
}

/// ROUTED R-023: a run-level line carries the prefix its code's level
/// gives it. The `.bazelignore` line an agent Go patch adds is a note,
/// `Note:` for a person and nothing under `--silent`.
#[test]
fn the_ignore_line_of_an_agent_go_patch_is_a_note() {
    let apply = |ws: &Checkout, cache: &Path, extra: &[&str]| {
        let (code, _, stderr) = go_run(ws, cache, &[&["apply", "--offline"], extra].concat());
        (code, stderr)
    };
    let lay = go_project;
    let (ws, cache) = lay();
    let (code, stderr) = apply(&ws, &cache, &[]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(ws.read(".bazelignore"), b".socket/go-patches\n");
    let about: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains(".bazelignore"))
        .collect();
    let [line] = about.as_slice() else {
        panic!("one line about the ignore file expected:\n{stderr}");
    };
    // It was a `Warning:` line before the level of its code was asked.
    assert!(line.starts_with("Note: "), "{line}");
    assert!(agent::is_note(Code::WorkspaceIgnoreLineAdded.as_str()));

    let (ws, cache) = lay();
    let (code, stderr) = apply(&ws, &cache, &["--silent"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains(".bazelignore"), "{stderr}");
    assert_eq!(ws.read(".bazelignore"), b".socket/go-patches\n");
}

// ── The apply a scan ends with ───────────────────────────────────────

/// A fake Socket API that offers one patch for each `(purl, uuid)`: the
/// patched `index.js` of the package.
async fn api_offering(offers: &[(&str, &str)]) -> MockServer {
    let api = MockServer::start().await;
    let listed = |(purl, uuid): &(&str, &str)| {
        let patch = json!({
            "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [], "ghsaIds": [],
            "severity": "high", "title": "fixture",
        });
        json!({ "purl": purl, "patches": [patch] })
    };
    let packages: Vec<Value> = offers.iter().map(listed).collect();
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": packages, "canAccessPaidPatches": false,
        })))
        .mount(&api)
        .await;
    for (purl, uuid) in offers {
        let record = json!({
            "uuid": uuid, "purl": purl, "publishedAt": "2024-01-01T00:00:00Z",
            "description": "x", "license": "MIT", "tier": "free", "vulnerabilities": {},
        });
        // The request names the package by its purl, percent-encoded:
        // its name is in the path as it is written.
        let name = purl
            .rsplit('/')
            .next()
            .and_then(|rest| rest.split('@').next());
        let name = regex::escape(name.expect("a name"));
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{name}.*$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [record], "canAccessPaidPatches": false,
            })))
            .mount(&api)
            .await;
        let mut view = record;
        view["files"] = json!({ "package/index.js": {
            "beforeHash": git_sha256(PRISTINE), "afterHash": git_sha256(PATCHED),
            "blobContent": PATCHED_BASE64,
        }});
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view))
            .mount(&api)
            .await;
    }
    api
}

/// `scan --mode agent --yes` against `api` in `ws`, with `extra` flags.
fn scan_agent(ws: &Checkout, api: &MockServer, extra: &[&str]) -> (i32, String, String) {
    let uri = api.uri();
    let fixed = ["scan", "--mode", "agent", "--yes", "--api-url", &uri];
    let auth = ["--api-token", "fake", "--org", ORG];
    run(&ws.root, &[&fixed[..], &auth[..], extra].concat())
}

/// The scan's envelope, and its exit code.
fn scan_agent_json(ws: &Checkout, api: &MockServer, extra: &[&str]) -> (i32, Value) {
    let (code, stdout, stderr) = scan_agent(ws, api, &[extra, &["--json"]].concat());
    assert!(!stdout.is_empty(), "no envelope (exit {code}):\n{stderr}");
    (code, parse_json_envelope(&stdout))
}

/// Holds a scan to its twin, the same scan in the same checkout without
/// the Bazel files: the exit code, the events and every warning that is
/// not Bazel's.
fn assert_scan_twin(run: &(i32, Value), twin: &(i32, Value)) {
    let ((code, envelope), (twin_code, twin)) = (run, twin);
    assert_eq!(code, twin_code, "{envelope:#}");
    assert_eq!(bazel_warnings(twin), [], "{twin:#}");
    assert_eq!(
        warning_codes(twin),
        warning_codes(&without_bazel(envelope)),
        "{envelope:#}"
    );
    assert_eq!(twin["events"], envelope["events"], "{envelope:#}");
}

/// `scan --mode agent` ends with an apply, and carries its advisory: one
/// entry, beside the notes the scan itself made once. Without the Bazel
/// files the same scan prints the same envelope less those entries.
#[tokio::test]
async fn a_scan_in_agent_mode_carries_the_advisory_of_its_apply() {
    let lay = || {
        let ws = Checkout::rules_js();
        std::fs::remove_dir_all(ws.root.join(".socket")).expect("no manifest yet");
        ws
    };
    let api = api_offering(&[(LEFT_PAD, UUID)]).await;
    let scan = |ws: &Checkout, extra: &[&str]| scan_agent(ws, &api, extra);
    let ws = lay();
    let (served, remedies) = cells(&ws.root, Ecosystem::Npm);
    let (code, stdout, stderr) = scan(&ws, &["--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let envelope = parse_json_envelope(&stdout);
    assert_eq!(ws.read("node_modules/left-pad/index.js"), PATCHED);
    if let Some(detail) = advisory(&envelope, served) {
        assert!(detail.contains(LEFT_PAD), "{detail}");
        assert_remedy(&detail, &remedies);
    }
    for code in [Code::WorkspaceDetected, Code::WorkspaceOutOfScope] {
        assert_eq!(said(&envelope, code).len(), 1, "{code}: {envelope:#}");
    }

    let plain = lay();
    plain.remove("MODULE.bazel");
    plain.remove(".bazelversion");
    let (code, stdout, stderr) = scan(&plain, &["--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let twin = parse_json_envelope(&stdout);
    assert_eq!(bazel_warnings(&twin), []);
    assert_eq!(
        warning_codes(&twin),
        warning_codes(&without_bazel(&envelope))
    );
    assert_eq!(twin["events"], envelope["events"]);

    // For a person: each note once, and the advisory once.
    let ws = lay();
    let (code, stdout, stderr) = scan(&ws, &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let count = |prefix: &str| stderr.lines().filter(|l| l.starts_with(prefix)).count();
    assert_eq!(count("Note: Bazel workspace "), 2, "{stderr}");
    assert_eq!(
        count("Warning: 1 patch is for a package"),
        usize::from(!served)
    );
}

// ── HZ-01: a scan that hands its patches to no apply ─────────────────

/// A scan in agent mode finds patches it applies nowhere: a package with
/// no installed copy is skipped before the download, and a preview
/// applies nothing at all. Where Bazel builds those packages from a lock,
/// a run that ends "No patches selected." with exit 0 must still say so
/// (HZ-01: "finds nothing and exits 0"). One advisory per run, with the
/// computed remedy, and it never says that a copy was patched.
#[tokio::test]
async fn a_scan_says_what_bazel_builds_of_the_patches_no_apply_takes() {
    let nothing_patched = "No installed copy was patched in this run";

    // The lock resolves the package, and nothing is installed.
    let api = api_offering(&[(LEFT_PAD, UUID)]).await;
    let lay = || Checkout::rules_js_unscanned(&[("left-pad", "1.3.0")], false);
    let ws = lay();
    let (served, remedies) = cells(&ws.root, Ecosystem::Npm);
    let before = snapshot(&ws.root);
    let scanned = scan_agent_json(&ws, &api, &[]);
    assert_eq!(scanned.0, 0, "{:#}", scanned.1);
    assert_scan_twin(
        &scanned,
        &scan_agent_json(&lay().without_bazel(), &api, &[]),
    );
    let envelope = &scanned.1;
    assert_eq!(
        event_for(envelope, LEFT_PAD)["errorCode"],
        "package_not_installed"
    );
    if let Some(detail) = advisory(envelope, served) {
        assert!(detail.starts_with("1 patch is for a package"), "{detail}");
        assert!(detail.contains(LEFT_PAD), "{detail}");
        assert!(detail.contains("rules_js hub `npm` builds npm packages from pnpm-lock.yaml"));
        assert!(detail.contains(nothing_patched), "{detail}");
        assert_remedy(&detail, &remedies);
    }
    for code in [Code::WorkspaceDetected, Code::WorkspaceOutOfScope] {
        assert_eq!(said(envelope, code).len(), 1, "{code}: {envelope:#}");
    }
    assert!(changes(&before, &snapshot(&ws.root)).is_empty());
    // For a person: one `Warning:` line beside "No patches selected.",
    // and nothing under `--silent`.
    let (code, stdout, stderr) = scan_agent(&ws, &api, &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("No patches selected."), "{stdout}");
    let advised = |line: &&str| line.starts_with("Warning: 1 patch is for a package");
    assert_eq!(stderr.lines().filter(advised).count(), usize::from(!served));
    let (code, _, stderr) = scan_agent(&ws, &api, &["--silent"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(!stderr.contains("Bazel"), "{stderr}");

    // A preview of an installed package: `apply --dry-run` says it, and
    // so does the scan that would run that apply.
    let lay = || Checkout::rules_js_unscanned(&[("left-pad", "1.3.0")], true);
    let ws = lay();
    let before = snapshot(&ws.root);
    let scanned = scan_agent_json(&ws, &api, &["--dry-run"]);
    assert_eq!(scanned.0, 0, "{:#}", scanned.1);
    let twin = scan_agent_json(&lay().without_bazel(), &api, &["--dry-run"]);
    assert_scan_twin(&scanned, &twin);
    let envelope = &scanned.1;
    assert_eq!(event_for(envelope, LEFT_PAD)["action"], "verified");
    if let Some(detail) = advisory(envelope, served) {
        assert!(detail.contains(LEFT_PAD), "{detail}");
        assert!(detail.contains(nothing_patched), "{detail}");
        assert_remedy(&detail, &remedies);
    }
    assert!(changes(&before, &snapshot(&ws.root)).is_empty());
    let (code, _, stderr) = scan_agent(&ws, &api, &["--dry-run"]);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stderr.lines().filter(advised).count(), usize::from(!served));

    // HZ-01, revision 3: a governed Ruby root with no bundle. The patch
    // is offered for a gem of the lock, which is installed nowhere.
    let gem = "pkg:gem/sp-victim@1.0.0";
    let api = api_offering(&[(gem, UUID)]).await;
    let ws = Checkout::fixture("rules_ruby/bzlmod/e9");
    let (served, remedies) = cells(&ws.root, Ecosystem::Gem);
    let scanned = scan_agent_json(&ws, &api, &[]);
    let plain = Checkout::fixture("rules_ruby/bzlmod/e9");
    plain.remove("MODULE.bazel");
    assert_scan_twin(&scanned, &scan_agent_json(&plain, &api, &[]));
    let envelope = &scanned.1;
    assert_eq!(
        event_for(envelope, gem)["errorCode"],
        "package_not_installed"
    );
    if let Some(detail) = advisory(envelope, served) {
        assert!(detail.contains(gem), "{detail}");
        let hub = "rules_ruby hub `bundle` builds ruby packages from Gemfile.lock";
        assert!(detail.contains(hub), "{detail}");
        assert!(detail.contains(nothing_patched), "{detail}");
        assert_remedy(&detail, &remedies);
    }
}

/// One advisory per run: where the scan ends with an apply, that apply
/// speaks for its own records and for the patches the scan gave to no
/// apply, in one entry that names both.
#[tokio::test]
async fn a_scan_and_its_apply_say_it_in_one_advisory() {
    let api = api_offering(&[(LEFT_PAD, UUID), (IS_ODD, OTHER_UUID)]).await;
    let locked = [("left-pad", "1.3.0"), ("is-odd", "3.0.1")];
    let lay = || Checkout::rules_js_unscanned(&locked, true);
    let ws = lay();
    let (served, remedies) = cells(&ws.root, Ecosystem::Npm);
    let scanned = scan_agent_json(&ws, &api, &[]);
    assert_eq!(scanned.0, 0, "{:#}", scanned.1);
    assert_scan_twin(
        &scanned,
        &scan_agent_json(&lay().without_bazel(), &api, &[]),
    );
    let envelope = &scanned.1;
    assert_eq!(ws.read("node_modules/left-pad/index.js"), PATCHED);
    assert_eq!(
        event_for(envelope, IS_ODD)["errorCode"],
        "package_not_installed"
    );
    if let Some(detail) = advisory(envelope, served) {
        assert!(detail.starts_with("Patches are for packages"), "{detail}");
        assert!(
            detail.contains(LEFT_PAD) && detail.contains(IS_ODD),
            "{detail}"
        );
        assert!(detail.contains("Installed copies are patched and checked as before"));
        assert_remedy(&detail, &remedies);
    }
    // A person reads it once, too.
    let ws = lay();
    let (code, stdout, stderr) = scan_agent(&ws, &api, &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let advised = |line: &&str| line.starts_with("Warning: Patches are for packages");
    assert_eq!(stderr.lines().filter(advised).count(), usize::from(!served));
    let any = |line: &&str| line.contains("that Bazel builds");
    assert_eq!(stderr.lines().filter(any).count(), usize::from(!served));
}

/// Owner decision O57: a root where only Bazel knows the packages (a
/// `maven_install.json` and no `pom.xml`) gives a scan nothing to find,
/// in a cell no lane serves. The scan says what it says about the
/// workspace and no more: there is no patch to advise about, and no
/// request is made.
#[tokio::test]
async fn a_scan_of_a_root_only_bazel_resolves_says_the_notes_and_no_advisory() {
    let api = api_offering(&[("pkg:maven/com.google.code.gson/gson@2.10.1", UUID)]).await;
    let ws = Checkout::fixture("rules_jvm_external/bzlmod/e9");
    let (code, envelope) = scan_agent_json(&ws, &api, &[]);
    assert_eq!(code, 0, "{envelope:#}");
    assert_eq!(envelope["scannedPackages"], 0, "{envelope:#}");
    assert_eq!(events(&envelope), [] as [Value; 0]);
    assert_eq!(said(&envelope, Code::AgentNotConsumed), [] as [String; 0]);
    let [detected] = &said(&envelope, Code::WorkspaceDetected)[..] else {
        panic!("{envelope:#}");
    };
    let hub = "rules_jvm_external builds maven packages from maven_install.json";
    assert!(detected.contains(hub), "{detected}");
    let requests = api.received_requests().await.unwrap_or_default();
    assert!(requests.is_empty(), "{} requests", requests.len());
    // The same without Bazel: the same nothing.
    let plain = Checkout::fixture("rules_jvm_external/bzlmod/e9");
    plain.remove("MODULE.bazel");
    let (twin_code, twin) = scan_agent_json(&plain, &api, &[]);
    assert_eq!((twin_code, bazel_warnings(&twin)), (code, Vec::new()));
}

// ── What the advisory leaves out, and what it does not claim ─────────

/// A package `vendor` owns is the vendored mode's to speak for, by the
/// ledger: on a run that patched, on a check, and on a run that could
/// not stage its sources and never reached the loop. That last run
/// patched nothing, and the advisory does not say it did.
#[test]
fn what_vendor_owns_is_left_out_and_a_run_that_patched_nothing_says_so() {
    let lay = || {
        let ws = Checkout::rules_js();
        ws.manifest("", &[LEFT_PAD, IS_ODD]);
        ws.vendor_ledger(&[IS_ODD]);
        ws
    };
    let ws = lay();
    let (served, _) = cells(&ws.root, Ecosystem::Npm);
    let plain = lay().without_bazel();
    for args in [
        &["apply", "--offline", "--check"][..],
        &["apply", "--offline"],
        &["apply", "--offline", "--check"],
    ] {
        let (code, envelope) = json_run(&ws.root, args);
        let (twin_code, twin) = json_run(&plain.root, args);
        assert_eq!(code, twin_code, "{args:?}: {envelope:#}");
        assert_eq!(without_bazel(&envelope), twin, "{args:?}");
        let marked: Vec<String> = states(&envelope)
            .into_iter()
            .map(|(purl, _)| purl)
            .collect();
        assert!(
            !marked.contains(&IS_ODD.to_string()),
            "{args:?}: {envelope:#}"
        );
        if let Some(detail) = advisory(&envelope, served) {
            assert!(detail.starts_with("1 patch is for a package"), "{detail}");
            assert!(
                detail.contains(LEFT_PAD) && !detail.contains(IS_ODD),
                "{detail}"
            );
        }
    }

    // The blob is gone and the run is offline: nothing can be staged.
    let lay = || {
        let ws = lay();
        std::fs::remove_dir_all(ws.root.join(".socket").join("blobs")).expect("no blob");
        ws
    };
    let (ws, plain) = (lay(), lay().without_bazel());
    let (code, envelope) = json_run(&ws.root, &["apply", "--offline"]);
    let (twin_code, twin) = json_run(&plain.root, &["apply", "--offline"]);
    assert_eq!((code, twin_code), (1, 1), "{envelope:#}");
    assert_eq!(without_bazel(&envelope), twin);
    assert!(warning_codes(&envelope).contains(&"offline_missing_sources".to_string()));
    assert_eq!(events(&envelope), [] as [Value; 0]);
    if let Some(detail) = advisory(&envelope, served) {
        assert!(
            detail.contains(LEFT_PAD) && !detail.contains(IS_ODD),
            "{detail}"
        );
        assert!(detail.contains("No installed copy was patched in this run"));
        assert!(!detail.contains("are patched"), "{detail}");
    }
    assert_eq!(ws.read("node_modules/left-pad/index.js"), PRISTINE);
}

/// A run on the global installs patches another tree, and a record
/// outside `--ecosystems` is not this run's: neither says anything about
/// Bazel. A check before the first apply reports the drift with the
/// twin's exit code, and the advisory beside it.
#[test]
fn a_global_run_and_a_record_out_of_scope_say_nothing_about_bazel() {
    let (ws, plain) = (Checkout::rules_js(), Checkout::rules_js().without_bazel());
    let (served, _) = cells(&ws.root, Ecosystem::Npm);
    let prefix = tempfile::tempdir().expect("an empty prefix");
    let prefix = prefix.path().to_str().expect("a UTF-8 path");
    for args in [
        &["apply", "--offline", "--ecosystems", "pypi"][..],
        &["apply", "--offline", "--ecosystems", "pypi", "--check"],
        &["apply", "--offline", "--global-prefix", prefix],
        &["apply", "--offline", "--global-prefix", prefix, "--check"],
    ] {
        let (code, envelope) = json_run(&ws.root, args);
        let (twin_code, twin) = json_run(&plain.root, args);
        assert_eq!(code, twin_code, "{args:?}: {envelope:#}");
        assert_eq!(bazel_warnings(&envelope), [], "{args:?}");
        assert_eq!(states(&envelope), [], "{args:?}");
        assert_eq!(envelope, twin, "{args:?}");
    }
    assert_eq!(ws.read("node_modules/left-pad/index.js"), PRISTINE);

    let check = ["apply", "--offline", "--check"];
    let (code, envelope) = json_run(&ws.root, &check);
    let (twin_code, twin) = json_run(&plain.root, &check);
    assert_eq!((code, twin_code), (1, 1), "{envelope:#}");
    assert_eq!(without_bazel(&envelope), twin);
    assert_eq!(event_for(&envelope, LEFT_PAD)["action"], "failed");
    if let Some(detail) = advisory(&envelope, served) {
        assert!(detail.contains(LEFT_PAD), "{detail}");
        assert!(detail.contains("Installed copies are checked as before"));
        let marked = [(LEFT_PAD.to_string(), "not_consumed".to_string())];
        assert_eq!(states(&envelope), marked);
    }
}
