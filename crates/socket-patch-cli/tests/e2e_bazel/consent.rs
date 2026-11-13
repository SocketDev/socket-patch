//! Hermetic CLI tests: a patch or a replacement a user wrote into a
//! ruleset's own hook is evidence for the consent gate (hazard HZ-17, the
//! consent part).
//!
//! A project's own patch of a package protects the package: a Socket
//! patch beside it installs with the user's diff stacked on it, or fails,
//! so every command leaves such a package alone until the user passes
//! `--allow-patch-conflicts`. The gate read pnpm, yarn, patch-package,
//! Composer, Cargo and Go declarations and no Bazel file, so the
//! `patches` of an `npm_translate_lock`, a `pip.override` or a replacement
//! tag was invisible to it (probe P4).
//!
//! Each case runs the built binary over a copy of the rules_js fixture
//! workspace with an installed tree beside it, as a repository has it that
//! builds with Bazel and keeps `node_modules` for its editors and scripts.
//! `apply` is the command: it is the one every install runs, and what it
//! does to an installed copy depends on no lane. The last case is the
//! same tree with no workspace file, where the gate answers as it always
//! did.
//!
//! What `vex` says of a pin written under consent is `bazel::attest`'s to
//! decide (`user_patch_hook`). No lane writes a Bazel pin in this build,
//! so the first case asserts the input instead: on the tree the command
//! just read, the declaration it skipped for is the user patch hook that
//! `attest` withholds for, found by the same reader.

use std::path::{Path, PathBuf};

use serde_json::Value;
use socket_patch_core::bazel::consent;
use socket_patch_core::bazel::model::{BazelWorkspace, HubId, Site};
use socket_patch_core::crawlers::bazel_root::RootProbe;
use socket_patch_core::crawlers::bazel_workspace::{read_workspace, DiskView};
use socket_patch_core::crawlers::types::Ecosystem;
use socket_patch_core::utils::repo_root::{ReadBoundary, ReadScope};

use crate::bazel_common::{
    assert_same_tree, assert_write_policy, changes, snapshot, Snapshot, WriteClass,
};
use crate::common::hermetic::{self, Extra};
use crate::common::{binary, envelope, git_sha256, hermetic_command, jvm_env, parse_json_envelope};

const CONFLICT: &str = "user_patch_conflict";
const OVERRIDE: &str = "user_patch_override";
const LEFT_PAD: &str = "pkg:npm/left-pad@1.3.0";
const ONCE: &str = "pkg:npm/@tootallnate/once@2.0.0";
const BOTH: [&str; 2] = ["@tootallnate/once", "left-pad"];
const UPSTREAM: &[u8] = b"module.exports = 'upstream';\n";
const PATCHED: &[u8] = b"module.exports = 'patched';\n";

/// The hub call of the fixture's `MODULE.bazel`, up to where an attribute
/// can be added.
const HUB_CALL: &str = "    pnpm_lock = \"//:pnpm-lock.yaml\",\n";
/// The `patches` entry of the acceptance line, on `left-pad@1.3.0`.
const PATCHES_ENTRY: &str = "    patches = {\"left-pad@1.3.0\": [\"//:left-pad.patch\"]},\n";

/// A copy of the rules_js fixture workspace as its own git checkout, at
/// its resolved path. The checkout bounds every upward read, so the
/// workspace of a case is the one it writes.
struct Workspace {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Workspace {
    /// The fixture with `attrs` added to its `npm_translate_lock` tag and
    /// `tags` after it, both packages of its lock installed, and a
    /// manifest with a patch for each (of `index.js`, from [`UPSTREAM`]
    /// to [`PATCHED`]) and their blob: all `apply --offline` needs.
    fn new(attrs: &str, tags: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap().join("ws");
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bazel/light/rules_js/bzlmod/e9");
        crate::common::fs_tree::copy_tree(&fixture, &root);
        let ws = Self { _tmp: tmp, root };
        ws.put(".git/HEAD", "ref: refs/heads/main\n");
        let module = std::fs::read_to_string(ws.at("MODULE.bazel")).unwrap();
        assert!(module.contains(HUB_CALL), "{module}");
        let module = module.replace(HUB_CALL, &format!("{HUB_CALL}{attrs}"));
        ws.put("MODULE.bazel", format!("{module}{tags}"));
        let (before, after) = (git_sha256(UPSTREAM), git_sha256(PATCHED));
        let mut records = serde_json::Map::new();
        for (at, (purl, package)) in [ONCE, LEFT_PAD].into_iter().zip(BOTH).enumerate() {
            let version = purl.rsplit('@').next().unwrap();
            let manifest = format!(r#"{{ "name": "{package}", "version": "{version}" }}"#);
            ws.put(&format!("node_modules/{package}/package.json"), manifest);
            ws.put(&format!("node_modules/{package}/index.js"), UPSTREAM);
            let record = serde_json::json!({
                "uuid": format!("9c1f4a52-7d3e-4b8a-a6f0-2e5d8c7b1a9{at}"),
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "package/index.js": { "beforeHash": before, "afterHash": after } },
                "vulnerabilities": {},
                "description": "synthetic test patch",
                "license": "MIT",
                "tier": "free",
            });
            records.insert(purl.to_string(), record);
        }
        let manifest = serde_json::json!({ "patches": records });
        ws.put(".socket/manifest.json", manifest.to_string());
        crate::common::write_blob(&ws.at(".socket"), &after, PATCHED);
        ws
    }

    /// `rel` below the root, level by level.
    fn at(&self, rel: &str) -> PathBuf {
        let levels = rel.split('/').filter(|level| !level.is_empty());
        levels.fold(self.root.clone(), |at, level| at.join(level))
    }

    fn put(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = self.at(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    /// Whether the installed copy of `package` holds the patched file.
    fn patched(&self, package: &str) -> bool {
        let bytes = std::fs::read(self.at(&format!("node_modules/{package}/index.js"))).unwrap();
        assert!(bytes == UPSTREAM || bytes == PATCHED, "{package}");
        bytes == PATCHED
    }

    /// The binary in the workspace: `(exit code, stdout, stderr)`.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let mut cmd = hermetic_command(&binary());
        // No host virtualenv and no host JVM caches: an agent scan would
        // crawl them and ask the API about this machine's packages.
        hermetic::scrub_extra(&mut cmd, &[Extra::Venv]);
        jvm_env::isolate_cli(&mut cmd);
        cmd.args(args).arg("--cwd").arg(&self.root);
        let out = cmd.current_dir(&self.root).output().expect("run");
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        let code = out.status.code().unwrap_or(-1);
        (code, text(&out.stdout), text(&out.stderr))
    }

    /// `apply --json --offline <args>`, which never fails over a
    /// protected package: its envelope.
    fn apply(&self, args: &[&str]) -> Value {
        let fixed = ["apply", "--json", "--offline"];
        let (code, stdout, stderr) = self.run(&[&fixed[..], args].concat());
        assert_eq!(code, 0, "apply {args:?}\n{stdout}\n{stderr}");
        parse_json_envelope(&stdout)
    }

    /// The model of the workspace, read as a command reads it.
    fn model(&self) -> BazelWorkspace {
        let boundary = ReadBoundary::upward(ReadScope::Workspace, &self.root);
        let survey = RootProbe::new().survey(&self.root, &boundary);
        let [found] = &survey.roots[..] else {
            panic!("one Bazel root: {survey:?}");
        };
        read_workspace(found, &DiskView::new(found)).expect("a workspace")
    }
}

/// The `detail` of the one top-level warning with `code`.
fn warning<'a>(envelope: &'a Value, code: &str) -> &'a str {
    let list = envelope["warnings"].as_array();
    let of_code = list.into_iter().flatten().filter(|w| w["code"] == code);
    let details: Vec<&str> = of_code.filter_map(|w| w["detail"].as_str()).collect();
    let [detail] = details[..] else {
        panic!("one `{code}` warning: {envelope:#}");
    };
    detail
}

/// The `reason` of the `skipped` event that holds `purl` back for the
/// user's own patch.
fn held_back<'a>(envelope: &'a Value, purl: &str) -> &'a str {
    let held = |e: &&Value| e["action"] == "skipped" && e["purl"] == purl;
    let event = envelope::events(envelope).iter().find(held);
    let event = event.unwrap_or_else(|| panic!("{purl}: {envelope:#}"));
    assert_eq!(event["errorCode"], CONFLICT, "{envelope:#}");
    event["reason"].as_str().expect("a reason")
}

fn has_code(envelope: &Value, code: &str) -> bool {
    envelope::all_codes(envelope).iter().any(|c| c == code)
}

/// Asserts what a run changed. Of the installed copies: exactly the file
/// of each package in `patched`. In the repository: nothing but state
/// under `.socket`, and nothing there that is not a write socket-patch
/// may make in a Bazel workspace (the oracle panics on any other path).
fn assert_wrote(before: &Snapshot, ws: &Workspace, patched: &[&str], what: &str) {
    let after = snapshot(&ws.root);
    let installed = |path: &str| path == "node_modules" || path.starts_with("node_modules/");
    let repository = |tree: &Snapshot| -> Snapshot {
        let kept = tree.iter().filter(|(path, _)| !installed(path));
        kept.map(|(path, entry)| (path.clone(), entry.clone()))
            .collect()
    };
    let writes = assert_write_policy(&repository(before), &repository(&after));
    let state = |(_, class): &(String, WriteClass)| *class == WriteClass::SocketState;
    assert!(writes.iter().all(state), "{what}: {writes:?}");
    let changed = changes(before, &after).into_iter().map(|(path, _)| path);
    let changed: Vec<String> = changed.filter(|path| installed(path)).collect();
    let files = patched.iter().map(|p| format!("node_modules/{p}/index.js"));
    assert_eq!(changed, files.collect::<Vec<_>>(), "{what}");
}

/// The filter of a workspace socket-patch wired nothing into.
fn the_users(_: &Site, _: Option<&str>) -> bool {
    false
}

/// The acceptance line. A `patches` entry of `npm_translate_lock` is the
/// user's own patch of the package. An explicit `vendor` refuses it. By
/// default `apply` leaves the package out, with the code every project
/// patch has and the file named, and patches the other; `--force` is no
/// consent. With `--allow-patch-conflicts` the package is patched and the
/// run says under whose patch.
#[test]
fn a_starlark_patches_entry_is_skipped_by_default_and_written_with_consent() {
    let ws = Workspace::new(PATCHES_ENTRY, "");
    ws.put("left-pad.patch", "the user's diff\n");
    let before = snapshot(&ws.root);
    let (code, stdout, stderr) = ws.run(&["vendor", "--json", "--offline"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let refused = parse_json_envelope(&stdout);
    assert_eq!(envelope::envelope_error_code(&refused), Some(CONFLICT));
    let message = envelope::envelope_error_message(&refused).expect("a message");
    assert!(message.starts_with(&format!("{LEFT_PAD}: ")), "{message}");
    assert!(message.contains("MODULE.bazel") && !message.contains(ONCE));
    assert_same_tree(&before, &snapshot(&ws.root));

    for (args, wrote) in [(&[][..], &BOTH[..1]), (&["--force"][..], &[][..])] {
        let before = snapshot(&ws.root);
        let run = ws.apply(args);
        let reason = held_back(&run, LEFT_PAD);
        assert!(reason.contains("MODULE.bazel"), "{reason}");
        assert!(reason.contains("--allow-patch-conflicts"), "{reason}");
        // One line for the one package, as for any project patch.
        assert_eq!(warning(&run, CONFLICT), reason);
        assert!(!has_code(&run, OVERRIDE), "{run:#}");
        assert!(!ws.patched("left-pad") && ws.patched("@tootallnate/once"));
        assert_wrote(&before, &ws, wrote, "by default");
    }

    let before = snapshot(&ws.root);
    let run = ws.apply(&["--allow-patch-conflicts"]);
    let line = warning(&run, OVERRIDE);
    assert!(line.starts_with(&format!("{LEFT_PAD}: ")), "{line}");
    assert!(line.contains("MODULE.bazel"), "{line}");
    assert!(!has_code(&run, CONFLICT), "{run:#}");
    assert!(ws.patched("left-pad"));
    // The user's patch and its declaration are theirs: never touched.
    assert_wrote(&before, &ws, &BOTH[1..], "with consent");

    // What `vex` may say of a pin written under that consent is
    // `attest`'s to decide, from the same list: on the tree as the run
    // left it, the entry is the user patch hook `attest` withholds for
    // (`user_patch_hook`), for this release alone, and for as long as the
    // entry stands.
    let hooks = |name: &str, version: &str| {
        consent::user_patch_hooks(&ws.model(), &the_users, Ecosystem::Npm, name, version)
    };
    let found = hooks("left-pad", "1.3.0");
    let [hook] = &found[..] else {
        panic!("{found:?}");
    };
    assert!(hook.host_patch && !hook.replacement && hook.file == "MODULE.bazel");
    assert!(hooks("left-pad", "1.2.0").is_empty());
    assert!(hooks("@tootallnate/once", "2.0.0").is_empty());
    let module = std::fs::read_to_string(ws.at("MODULE.bazel")).unwrap();
    ws.put("MODULE.bazel", module.replace(PATCHES_ENTRY, ""));
    assert!(hooks("left-pad", "1.3.0").is_empty());
}

/// `scan` reads the same evidence before it selects anything: the
/// package the workspace patches itself is held back with the code and
/// never reaches the API, and the other one is asked about.
#[tokio::test]
async fn scan_leaves_a_package_the_workspace_patches_out_of_its_query() {
    let api = wiremock::MockServer::start().await;
    let none = serde_json::json!({ "packages": [], "canAccessPaidPatches": false });
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/v0/orgs/test-org/patches/batch"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(none))
        .mount(&api)
        .await;
    let ws = Workspace::new(PATCHES_ENTRY, "");
    let uri = api.uri();
    let online = [
        "--api-url",
        &uri,
        "--api-token",
        "fake",
        "--org",
        "test-org",
    ];
    let (code, stdout, stderr) = ws.run(&[&["scan", "--json"][..], &online].concat());
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let run = parse_json_envelope(&stdout);
    assert!(
        held_back(&run, LEFT_PAD).contains("MODULE.bazel"),
        "{run:#}"
    );
    let mut asked = String::new();
    for request in api.received_requests().await.unwrap_or_default() {
        asked.push_str(&String::from_utf8_lossy(&request.body));
    }
    assert!(asked.contains("tootallnate/once@2.0.0"), "{asked}");
    assert!(!asked.contains("left-pad"), "{asked}");
}

/// A replacement tag is evidence like a patch: the package is held back
/// by default, and the run says that Bazel builds something else in its
/// place. Consent lifts the check for the installed copy as for any
/// project patch. It lifts nothing for a patch Bazel would have to build
/// from: the same declaration is the bypass the lane gate refuses a pin
/// for, whatever the consent.
#[test]
fn a_replacement_tag_is_evidence_and_stays_a_bypass_of_a_pin() {
    let tag =
        "npm.npm_replace_package(package = \"left-pad@1.3.0\", replacement = \"//:left_pad\")\n";
    let ws = Workspace::new("", tag);
    let before = snapshot(&ws.root);
    let reason = held_back(&ws.apply(&[]), LEFT_PAD).to_string();
    assert!(reason.contains("MODULE.bazel (replaces the package in the Bazel build"));
    assert_wrote(&before, &ws, &BOTH[..1], "by default");

    let run = ws.apply(&["--allow-patch-conflicts"]);
    let line = warning(&run, OVERRIDE);
    let stays = "refused with or without --allow-patch-conflicts";
    assert!(line.contains(stays) && ws.patched("left-pad"), "{line}");

    let model = ws.model();
    let npm = model
        .hubs
        .iter()
        .position(|hub| hub.ecosystem == Ecosystem::Npm);
    let hub = HubId(npm.expect("the npm hub"));
    let bypasses = |version: &str| consent::bypasses(&model, &the_users, hub, "left-pad", version);
    assert!(bypasses("1.3.0").len() == 1 && bypasses("1.2.0").is_empty());
    // A replacement is no patch hook: consent lifts nothing of it.
    let hooks = consent::user_patch_hooks(&model, &the_users, Ecosystem::Npm, "left-pad", "1.3.0");
    assert!(hooks.is_empty(), "{hooks:?}");
}

/// ROUTED R-144. A computed `patches` argument may patch any npm package,
/// so every one is held back. The run says so once, for the ecosystem,
/// with the file and what was not read in it, and not once per package;
/// each package still has its own `skipped` event. With consent the run
/// says once what it was allowed.
#[test]
fn a_computed_patches_argument_says_one_line_for_the_ecosystem_and_skips_its_packages() {
    let ws = Workspace::new("    patches = PATCHES,\n", "");
    let before = snapshot(&ws.root);
    let run = ws.apply(&[]);
    let line = warning(&run, CONFLICT);
    assert!(line.starts_with("every npm package: "), "{line}");
    assert!(line.contains("MODULE.bazel"), "{line}");
    let unread = "`patches` of `npm.npm_translate_lock` is not read";
    assert!(line.contains(unread), "{line}");
    assert!(line.contains("--allow-patch-conflicts"), "{line}");
    for purl in [LEFT_PAD, ONCE] {
        assert!(!line.contains(purl), "{line}");
        let reason = held_back(&run, purl);
        assert!(reason.starts_with(&format!("{purl}: ")), "{reason}");
        assert!(reason.contains("MODULE.bazel"), "{reason}");
    }

    // The same for a person at a terminal: one line on stderr, and no
    // line of a package's own.
    let (code, stdout, stderr) = ws.run(&["apply", "--offline"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let of_the_gate = |line: &&str| {
        line.contains("every npm package: ") || line.contains("project patch/replacement metadata")
    };
    let lines: Vec<&str> = stderr.lines().filter(of_the_gate).collect();
    let [line] = lines[..] else {
        panic!("one line: {stderr}");
    };
    assert!(line.starts_with("Warning: every npm package: "), "{line}");
    assert!(!line.contains(LEFT_PAD) && !line.contains(ONCE), "{line}");
    assert_same_tree(&before, &snapshot(&ws.root));

    let run = ws.apply(&["--allow-patch-conflicts"]);
    let line = warning(&run, OVERRIDE);
    assert!(line.starts_with("every npm package: "), "{line}");
    assert!(!has_code(&run, CONFLICT), "{run:#}");
    assert_wrote(&before, &ws, &BOTH, "with consent");
}

/// With no Bazel workspace at or above the project the gate answers as
/// it did before it read one: the tree of the acceptance case with its
/// workspace file gone is an npm project like any other, and `apply`
/// patches both packages and says nothing.
#[test]
fn without_a_bazel_workspace_nothing_is_held_back() {
    let ws = Workspace::new(PATCHES_ENTRY, "");
    std::fs::remove_file(ws.at("MODULE.bazel")).unwrap();
    let before = snapshot(&ws.root);
    let run = ws.apply(&[]);
    assert_eq!(envelope::warning_codes(&run), [""; 0], "{run:#}");
    let applied = |purl: &str| (purl.to_string(), "applied".to_string(), String::new());
    let events = envelope::event_triples(&run);
    assert_eq!(events, [applied(ONCE), applied(LEFT_PAD)], "{run:#}");
    assert_wrote(&before, &ws, &BOTH, "no workspace");
}
