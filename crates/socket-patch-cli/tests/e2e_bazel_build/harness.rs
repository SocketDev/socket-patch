//! What every real-Bazel test shares: the variables that configure a run,
//! the Bazel a run is given and the fixture files that go with its release,
//! the scratch root that holds everything one Bazel writes, the Bazel
//! command line and the environment of its children, the `socket-patch`
//! child that runs in the workspace copy, the loopback server that stands
//! in for the hosts of a flow, and the steps every flow is made of.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use socket_patch_core::utils::purl::normalize_purl;
use socket_patch_core::vex::NOT_VERIFIED_SUFFIX;

use crate::envelope::{codes_in, event_for, events};
use crate::fs_tree;
use crate::hosted_memory_common::hermetic::{self, Extra};
use crate::hosted_memory_common::{mount_api, read_tree, Patch, ORG};

/// The Bazel binary or launcher to run, by absolute path: every child runs
/// in the workspace copy. Unset: `bazel` on `PATH`. A test runs on the
/// release this Bazel says it is.
pub const BAZEL: &str = "SOCKET_PATCH_BAZEL_E2E_BAZEL";
/// The release that Bazel must be (`9.3.2`), so that a workflow leg cannot
/// pass on another one: a test fails when `bazel --version` says otherwise.
/// Unset: any release.
pub const VERSION: &str = "SOCKET_PATCH_BAZEL_E2E_VERSION";
/// Non-empty: a test fails when no Bazel runs here. Unset: it prints
/// `SKIP <why>` and passes.
pub const REQUIRED: &str = "SOCKET_PATCH_BAZEL_E2E_REQUIRED";
/// A repository cache shared by the tests of a run, so that only the first
/// downloads the rulesets and the toolchain. Unset: an empty one per test.
pub const REPO_CACHE: &str = "SOCKET_PATCH_BAZEL_E2E_REPO_CACHE";
/// Another `socket-patch` binary to hold the same tests against (a
/// release), by absolute path. Unset: the binary cargo built for this run.
pub const SOCKET_BIN: &str = "SOCKET_PATCH_BAZEL_E2E_SOCKET_BIN";

/// Removed from every Bazel child, so that a test does the same in every
/// shell. What a child keeps reaches the repository rules, the tools they
/// start and the binary `bazel run` starts.
const REMOVED: &[&str] = &[
    // Bazel: `TEST_TMPDIR` puts a server in test mode, where a failing
    // module extension on 7.x is a crash (exit 37) instead of an error.
    "TEST_TMPDIR",
    // Bazel's `http_archive` and downloader, and rules_csharp for every
    // package: the credentials file of the shell. A path that names no
    // file fails the first fetch, and a file's login for loopback, or its
    // `default` one, goes to a stand-in with every download sent there.
    "NETRC",
    // Any tool: an `XDG_*_HOME` directory would move what it keeps out of
    // the scratch home: a cache, or on Linux the telemetry counters of a Go
    // SDK command that a ruleset starts, which Go puts under
    // `XDG_CONFIG_HOME` and no variable turns off. Without them a tool
    // falls back to a directory under `HOME`.
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    // Rulesets: the CI markers change what some of them do, and a test
    // must do the same on a runner and on a developer's machine.
    "CI",
    "GITHUB_ACTIONS",
    // Composer: another `composer.json` than the project's, for the
    // Composer a repository rule starts.
    "COMPOSER",
    // Ruby and RubyGems: where gems are installed and looked up. rvm,
    // chruby and direnv export them for the Ruby of the shell, which is
    // not the Ruby a ruleset downloads.
    "GEM_HOME",
    "GEM_PATH",
    // Node: options and a module search path for every `node`, the
    // consumer that `bazel run` starts included.
    "NODE_OPTIONS",
    "NODE_PATH",
    // Python: another standard library, more module directories, and a
    // file to run at start, for every interpreter.
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    // Maven: `hermetic::command` gives the socket-patch binary a
    // `MAVEN_ARGS` that names an empty settings file, so the machine's
    // mirrors decide nothing. It is that process's alone: a Maven a
    // ruleset started would take those settings over its own.
    "MAVEN_ARGS",
    // rules_rust: its switch for a repin of a crate hub, which it reads
    // under this name and under `CARGO_BAZEL_REPIN` (a prefix below).
    "REPIN",
];

/// Removed from every Bazel child under every name that starts so.
const REMOVED_PREFIXES: &[&str] = &[
    // A bazelisk: what it does around a command (`BAZELISK_CLEAN`) and
    // where it gets a release from. `BAZELISK_HOME` is set again, to
    // [`launcher_cache`].
    "BAZELISK_",
    // Composer: any of its settings (`COMPOSER_AUTH`,
    // `COMPOSER_DISABLE_NETWORK`, a vendor directory), which the Composer
    // a repository rule starts reads from the client's environment. A flow
    // sets the ones it needs after this ([`Cell::repo_env`]).
    "COMPOSER_",
    // pip: any option of its command line (an index, a proxy, a cache).
    "PIP_",
    // uv: the same.
    "UV_",
    // The cargo a ruleset starts (rules_rust's, for a crate hub): its home
    // and every setting of its config (`CARGO_NET_OFFLINE`,
    // `CARGO_SOURCE_*`, `CARGO_REGISTRIES_*`, `CARGO_HTTP_*`), and what
    // `cargo test` sets for this process. And rules_rust itself: its
    // `CARGO_BAZEL_*` switches, the repin among them. A flow sets what it
    // needs of these through [`Cell::repo_env`], after this scrub.
    "CARGO_",
];

/// The scrubs of `hermetic` that every Bazel child gets, for the tools a
/// ruleset starts: `go` (its module cache, flags and `go env -w` file),
/// Bundler and Ruby (`BUNDLE_*`, and the `RUBYOPT` and `RUBYLIB` of a shell
/// under `bundle exec`), npm and pnpm (`npm_config_*`, which outranks an
/// rc file, and `PNPM_*`) and Python (the `VIRTUAL_ENV` of an activated
/// environment).
const EXTRAS: &[Extra] = &[Extra::Go, Extra::Bundle, Extra::Pnpm, Extra::Venv];

/// The hosts a proxy is never asked for: a stand-in listens on loopback.
const LOOPBACK: [&str; 2] = ["127.0.0.1", "localhost"];

/// The label every fixture builds: a binary that prints one `OUT: ...` line
/// from the package under test.
pub const CONSUMER: &str = "//:consumer";

/// Nothing listens there: a request the `socket-patch` child sends anywhere
/// but loopback fails at once.
const CLOSED_PORT: &str = "http://127.0.0.1:9";

/// The files of a workspace copy: `/`-separated relative path to bytes.
pub type Tree = BTreeMap<String, Vec<u8>>;

/// What [`changed`] gives for two equal trees.
pub const NOTHING: [&str; 0] = [];

/// The product the forms of `vex` are told, so that the documents of every
/// flow name one, whatever its fixture lets `socket-patch` detect: the PyPI
/// and the RubyGems fixture have no project file. One run per flow goes
/// without it ([`Cell::detects_product`]).
const PRODUCT: &str = "pkg:generic/socket-fixture@0.0.0";

/// The advisory of every patch record a flow is served: the one of the
/// shared API stand-in, and of the records a flow writes itself.
const ADVISORY: &str = "GHSA-test-aaaa-bbbb";

/// The code of the warning with which `socket-patch` says that Bazel does
/// not build the patched copy of a package, so that its document says the
/// package is affected.
pub const NOT_IN_BUILD: &str = "vex_bazel_not_in_build";

/// The mode a flow patched its package in, which a document says after the
/// patch id. Or [`How::Unbuilt`]: the patch is in a copy that Bazel does
/// not build, and a document says the package is affected.
#[derive(Clone, Copy)]
pub enum How {
    Hosted,
    Vendored,
    Agent,
    Unbuilt,
}

impl How {
    fn words(self) -> &'static str {
        match self {
            How::Hosted => " (redirected)",
            How::Vendored => " (vendored)",
            How::Agent | How::Unbuilt => "",
        }
    }
}

/// What a document has to say: the package `purl` is not affected, through
/// the patch `uuid` of this run. The id is new for every run, so no
/// document of an earlier run says it. Or, for [`Claim::unbuilt`], that the
/// package is affected, and what to do about it.
pub struct Claim<'a> {
    pub purl: &'a str,
    pub uuid: &'a str,
    pub how: How,
    /// What the action statement of an affected package names, and the
    /// warning of its run: the call's file and line, the file Bazel builds
    /// the package from, what to run.
    names: &'a [String],
}

impl<'a> Claim<'a> {
    pub fn new(purl: &'a str, uuid: &'a str, how: How) -> Claim<'a> {
        let names = &[];
        Claim {
            purl,
            uuid,
            how,
            names,
        }
    }

    /// The package is affected: its patch `uuid` is in a copy that Bazel
    /// does not build, and `names` is what the document has to name.
    pub fn unbuilt(purl: &'a str, uuid: &'a str, names: &'a [String]) -> Claim<'a> {
        Claim {
            names,
            ..Claim::new(purl, uuid, How::Unbuilt)
        }
    }

    fn affected(&self) -> bool {
        matches!(self.how, How::Unbuilt)
    }
}

/// `path` as an argument of `socket-patch`.
fn argument(path: &Path) -> &str {
    path.to_str().expect("a UTF-8 path")
}

/// The stand-alone `vex` that writes its document to `path`.
fn vex(path: &Path) -> [&str; 5] {
    ["vex", "--output", argument(path), "--product", PRODUCT]
}

/// What the document at `path` holds.
fn document_at(test: &str, path: &Path) -> (String, Value) {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{test}: no document {}: {e}", path.display()));
    let document =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{test}: no JSON ({e}):\n{text}"));
    (text, document)
}

/// `document` without what each run and each form writes for itself: the
/// id of the document, its times and those of its statements, and the mark
/// of `vex --no-verify` at the end of an impact statement. What is left is
/// what a document says and the strings it says it with: the product, the
/// package, the advisory and its aliases, the status, the justification
/// and the patch, or for an affected package what to do.
fn wording(mut document: Value) -> Value {
    fn without(of: &mut Value, fields: &[&str]) {
        let Some(object) = of.as_object_mut() else {
            return;
        };
        for field in fields {
            object.remove(*field);
        }
    }
    without(&mut document, &["@id", "timestamp", "last_updated"]);
    let statements = document["statements"].as_array_mut();
    for statement in statements.into_iter().flatten() {
        without(statement, &["timestamp", "last_updated"]);
        let Some(impact) = statement["impact_statement"].as_str() else {
            continue;
        };
        let unmarked = impact.strip_suffix(NOT_VERIFIED_SUFFIX).unwrap_or(impact);
        statement["impact_statement"] = unmarked.to_string().into();
    }
    document
}

/// What a `scan` or an `apply` is given to write the document of its own
/// run to `path`.
pub fn with_vex(path: &Path) -> [&str; 4] {
    ["--vex", argument(path), "--vex-product", PRODUCT]
}

/// `name`'s value when it is set and non-empty.
fn var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

/// The program `name` names, which must be an absolute path: a relative
/// one names nothing in the workspace copy a child runs in. A wrong
/// setting is a mistake, not a missing tool, so it fails and never skips.
fn program(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(var(name)?);
    assert!(
        path.is_absolute(),
        "{name}={} must be an absolute path: the tests run it from a workspace copy",
        path.display()
    );
    Some(path)
}

/// A Bazel release as three numbers: `9.3.2` is `(9, 3, 2)`.
pub type Release = (u32, u32, u32);

/// The three numbers `release` starts with, whatever a build adds after
/// them: `9.3.2` and `9.3.2-homebrew` are `(9, 3, 2)`. `None` for anything
/// else.
fn numbers(release: &str) -> Option<Release> {
    let mut parts = release.splitn(3, '.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?;
    let digits = patch
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(patch.len());
    Some((major, minor, patch[..digits].parse().ok()?))
}

/// One line of a fixture's table: the Bazel releases of the range (its end
/// is the first release after it) build the workspace with the files of
/// the directory of that name.
pub type Era = (Range<Release>, &'static str);

/// A fixture workspace. Its directory `common` holds the files every Bazel
/// release builds, and one directory per era holds the rest: the
/// `MODULE.bazel` that pins the rulesets of that era. A test copies both
/// into one workspace, so Bazel never meets two `MODULE.bazel` in a tree.
/// A new era is one such directory and one line of `eras`.
pub struct Fixture {
    /// Where the constant is written (`go::FIXTURE`), for the failure of a
    /// release its table does not hold.
    pub name: &'static str,
    /// The directory under `tests/fixtures/bazel/`.
    pub dir: &'static str,
    /// The file under `.github/workflows/` that says on which Bazel
    /// releases the ecosystem's tests run.
    pub workflow: &'static str,
    /// The one place that says which release builds which era.
    pub eras: &'static [Era],
}

impl Fixture {
    /// The era directory for `release`.
    fn era(&self, release: &str) -> Option<&'static str> {
        let numbers = numbers(release)?;
        let line = self.eras.iter().find(|(range, _)| range.contains(&numbers));
        line.map(|(_, era)| *era)
    }

    /// Without a Bazel: the directories of the fixture are `common` and the
    /// eras of the table, and each era holds a `MODULE.bazel`, which
    /// `common` does not. The workflow names this fixture, and for every
    /// Bazel release it runs the era the table gives that release: a leg's
    /// repository cache is the one of its era.
    pub fn check(&self) {
        let root = fixture_path(self.dir);
        let mut found: Vec<String> = std::fs::read_dir(&root)
            .unwrap_or_else(|e| panic!("read {}: {e}", root.display()))
            .map(|entry| entry.expect("a directory entry").path())
            .filter(|path| path.is_dir())
            .filter_map(|path| Some(path.file_name()?.to_string_lossy().into_owned()))
            .collect();
        found.sort();
        let mut named: Vec<&str> = self.eras.iter().map(|(_, era)| *era).collect();
        named.push("common");
        named.sort_unstable();
        named.dedup();
        assert_eq!(found, named, "{}: {}", self.name, root.display());
        assert!(!root.join("common/MODULE.bazel").exists(), "{}", self.name);
        for era in named.iter().filter(|era| **era != "common") {
            let module = root.join(era).join("MODULE.bazel");
            assert!(module.is_file(), "{}: no {}", self.name, module.display());
        }

        let workflow = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.github/workflows")
            .join(self.workflow);
        let said = format!("{}: {}", self.name, workflow.display());
        let text = std::fs::read_to_string(&workflow).unwrap_or_else(|e| panic!("{said}: {e}"));
        let fixtures = format!("fixtures: {}", self.dir);
        let named = text.lines().any(|line| line.trim() == fixtures);
        assert!(named, "{said}: no `{fixtures}`");
        let leg = regex::Regex::new(r#"\{"bazel": "([^"]+)", "era": "([^"]+)"\}"#).expect("a leg");
        let legs: Vec<[&str; 2]> = leg.captures_iter(&text).map(|c| c.extract().1).collect();
        // Every leg is written the one way the pattern reads.
        assert!(
            !legs.is_empty() && legs.len() == text.matches("\"bazel\":").count(),
            "{said}: a leg is not written as {{\"bazel\": \"9.3.2\", \"era\": \"e9\"}}"
        );
        for [release, era] in legs {
            assert_eq!(self.era(release), Some(era), "{said}: Bazel {release}");
        }
    }
}

/// The path `rel` under `tests/fixtures/bazel/`.
pub fn fixture_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bazel")
        .join(rel)
}

/// The marker file of a vendored copy, in the directory of its patch.
const MARKER: &str = "/socket-patch.vendor.json";

/// `tree` with every [`MARKER`] as its JSON value without `vendoredAt`,
/// the one field that holds a time: two runs that vendor the same patch
/// of the same package write markers that are equal in this, and a marker
/// that names another package, patch or advisory is not. A marker that is
/// no JSON object stays as it is.
fn undated(tree: &Tree) -> Tree {
    let mut tree = tree.clone();
    for (file, bytes) in &mut tree {
        if !file.ends_with(MARKER) {
            continue;
        }
        if let Ok(Value::Object(mut fields)) = serde_json::from_slice(bytes) {
            fields.remove("vendoredAt");
            *bytes = Value::Object(fields).to_string().into_bytes();
        }
    }
    tree
}

/// The names under which `before` and `after` differ.
pub fn changed(before: &Tree, after: &Tree) -> Vec<String> {
    let names = before.keys().chain(after.keys());
    let mut differing: Vec<String> = names
        .filter(|name| before.get(*name) != after.get(*name))
        .cloned()
        .collect();
    differing.sort();
    differing.dedup();
    differing
}

/// No Bazel runs on this machine for `test`: a failure under [`REQUIRED`],
/// else a `SKIP` line.
fn unavailable(test: &str, why: &str) {
    assert!(
        var(REQUIRED).is_none(),
        "{test}: {REQUIRED} is set and {why}"
    );
    println!("SKIP {test}: {why}");
}

/// The temp root of one workspace copy, with a fixed place for everything a
/// Bazel run writes. Nothing lands in the developer's `~/.cache/bazel`, the
/// shared temp directory or the real home, but for the one cache of a
/// launcher ([`launcher_cache`]).
struct Scratch {
    /// The workspace copy Bazel and `socket-patch` run in.
    workspace: PathBuf,
    /// `--output_user_root`: one output base, so one Bazel server.
    output_user_root: PathBuf,
    /// `java.io.tmpdir` of the server and `TMPDIR` of every child.
    tmp: PathBuf,
    /// `HOME` of every child.
    home: PathBuf,
    /// `--repository_cache`.
    repository_cache: PathBuf,
    /// `--repo_contents_cache` on Bazel 9, where that cache is on by
    /// default.
    contents_cache: PathBuf,
    /// The downloader config, which only [`Cell::route_downloads`] writes.
    /// Beside the workspace copy, so it is no file of the checkout.
    downloads: PathBuf,
    /// The VEX documents of a flow ([`Cell::document`]), beside the
    /// workspace copy for the same reason.
    documents: PathBuf,
    /// Removed on drop, after [`Scratch::drop`] made it removable.
    dir: tempfile::TempDir,
}

impl Scratch {
    /// A new temp root. `repository_cache` is one that outlives it; `None`
    /// gives it an empty one of its own.
    fn new(repository_cache: Option<PathBuf>) -> Scratch {
        let dir = tempfile::Builder::new()
            .prefix("sp-bazel-")
            .tempdir()
            .expect("create the scratch root");
        // Canonical: macOS temp directories sit behind a symlink, and a
        // directory named by the environment may be relative, which Bazel
        // would resolve against the workspace copy.
        let made = |dir: PathBuf| {
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
            dir.canonicalize().expect("a canonical directory")
        };
        let root = made(dir.path().to_path_buf());
        Scratch {
            workspace: made(root.join("ws")),
            output_user_root: made(root.join("root")),
            tmp: made(root.join("tmp")),
            home: made(root.join("home")),
            repository_cache: made(repository_cache.unwrap_or_else(|| root.join("cache"))),
            contents_cache: made(root.join("contents")),
            downloads: root.join("downloader.cfg"),
            documents: made(root.join("vex")),
            dir,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Bazel marks its install base and the repositories it fetched
        // read-only, which would leave the temp root behind. Silent: this
        // also runs while a failed test unwinds.
        fn make_writable(path: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return;
            };
            if meta.file_type().is_symlink() {
                return;
            }
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o700);
            let _ = std::fs::set_permissions(path, perms);
            if meta.is_dir() {
                for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
                    make_writable(&entry.path());
                }
            }
        }
        make_writable(self.dir.path());
    }
}

/// Where a launcher (bazelisk) keeps the Bazel releases it downloads: the
/// caller's own `BAZELISK_HOME`, or the directory bazelisk picks for the
/// caller without one (Go's `os.UserCacheDir()`, then `bazelisk`). Every
/// child gets it as `BAZELISK_HOME`: with the scratch `HOME` alone, a
/// launcher would download a whole release for every cell and every twin.
/// A release there is the caller's tool, like the `bazel` on `PATH`, and
/// nothing a workspace under test or a package manager wrote; a temp
/// directory of the test process would cost a download per run instead.
fn launcher_cache() -> Option<PathBuf> {
    if let Some(home) = var("BAZELISK_HOME") {
        return Some(PathBuf::from(home));
    }
    let macos = cfg!(target_os = "macos");
    let caches = match var("XDG_CACHE_HOME") {
        Some(dir) if !macos => PathBuf::from(dir),
        _ => PathBuf::from(var("HOME")?).join(if macos { "Library/Caches" } else { ".cache" }),
    };
    Some(caches.join("bazelisk"))
}

/// What every Bazel child gets as `no_proxy` and as `NO_PROXY`: the entries
/// the caller has under either name, and [`LOOPBACK`].
///
/// The proxy settings of the machine stay as they are: where a proxy is the
/// way to the Bazel registry and the ruleset archives, a build without it
/// fetches nothing. Loopback must not go through it, because a flow sends
/// Bazel's downloader and the tools of a ruleset to a stand-in there, which
/// a proxy on another machine cannot reach. A tool may read either name
/// first (Bazel's downloader reads `no_proxy`, and `NO_PROXY` only when
/// that one is empty), so both get the one list.
fn no_proxy() -> String {
    let own = ["no_proxy", "NO_PROXY"].map(|name| var(name).unwrap_or_default());
    let own = own.each_ref().map(|list| list.to_string_lossy());
    let named = own.iter().flat_map(|list| list.split(',')).map(str::trim);
    let mut hosts: Vec<&str> = Vec::new();
    for host in named.chain(LOOPBACK) {
        if !host.is_empty() && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts.join(",")
}

/// `program` in the workspace copy, with the environment of every Bazel
/// child and no arguments. Built on `hermetic::command`, the one way this
/// crate's tests spawn a child; what is set here lands after its scrub.
fn child(program: &OsStr, scratch: &Scratch) -> Command {
    let mut cmd = hermetic::command(Path::new(program));
    for name in REMOVED {
        cmd.env_remove(name);
    }
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if REMOVED_PREFIXES
            .iter()
            .any(|prefix| text.starts_with(prefix))
        {
            cmd.env_remove(&name);
        }
    }
    if let Some(cache) = launcher_cache() {
        cmd.env("BAZELISK_HOME", cache);
    }
    hermetic::scrub_extra(&mut cmd, EXTRAS);
    let no_proxy = no_proxy();
    cmd.env("no_proxy", &no_proxy)
        .env("NO_PROXY", &no_proxy)
        .env("HOME", &scratch.home)
        .env("TMPDIR", &scratch.tmp)
        .current_dir(&scratch.workspace);
    cmd
}

/// The Bazel a test runs.
#[derive(Clone)]
struct Bazel {
    /// A release binary, or a launcher that reads `USE_BAZEL_VERSION`.
    program: OsString,
    /// What `--version` printed after `bazel `.
    release: String,
}

impl Bazel {
    /// `program` (`bazel` on `PATH` without one) and the release it says
    /// it is. `bazel --version` is answered by the client: no server
    /// starts. A launcher answers for the release the caller's own
    /// `USE_BAZEL_VERSION` picks. `Err` says why no Bazel runs here.
    fn detect(scratch: &Scratch, program: Option<PathBuf>) -> Result<Bazel, String> {
        let program = program.map_or_else(|| "bazel".into(), PathBuf::into_os_string);
        let shown = program.to_string_lossy().into_owned();
        let out = child(&program, scratch)
            .arg("--version")
            .output()
            .map_err(|e| format!("`{shown}` did not run: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let release = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("bazel "));
        match release {
            Some(release) => Ok(Bazel {
                program,
                release: release.to_string(),
            }),
            None => Err(format!(
                "`{shown} --version` printed no `bazel <release>` line:\n{stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            )),
        }
    }

    /// `bazel <startup options> <command>` in the workspace copy. The
    /// startup options never vary within a test: another set restarts the
    /// server. They keep the rc files of the machine out and every write
    /// inside the scratch root; without the two JVM options the server
    /// writes `hsperfdata_<user>` and its native libraries into the shared
    /// temp directory. A launcher is held to the release it answered for.
    fn command(&self, scratch: &Scratch, command: &str) -> Command {
        let joined = |flag: &str, path: &Path| {
            let mut arg = OsString::from(flag);
            arg.push(path);
            arg
        };
        let mut cmd = child(&self.program, scratch);
        cmd.env("USE_BAZEL_VERSION", &self.release)
            .arg("--nohome_rc")
            .arg("--nosystem_rc")
            .arg(joined("--output_user_root=", &scratch.output_user_root))
            .arg("--max_idle_secs=15")
            .arg(joined("--host_jvm_args=-Djava.io.tmpdir=", &scratch.tmp))
            .arg("--host_jvm_args=-XX:-UsePerfData")
            .arg(command);
        cmd
    }
}

/// One finished Bazel command.
pub struct Run {
    /// The command line, for failure messages.
    line: String,
    output: Output,
}

impl Run {
    fn of(mut cmd: Command) -> Result<Run, String> {
        let line = format!("{cmd:?}");
        let output = cmd.output().map_err(|e| format!("spawn {line}: {e}"))?;
        Ok(Run { line, output })
    }

    pub fn ok(&self) -> bool {
        self.output.status.success()
    }

    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    pub fn dump(&self) -> String {
        format!(
            "{}\nexit {:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.line,
            self.output.status.code(),
            self.stdout(),
            self.stderr()
        )
    }
}

/// One run of `socket-patch` in a workspace copy.
pub struct Ran {
    pub code: i32,
    /// stdout, parsed: the `--json` envelope.
    pub envelope: Value,
    /// The command line, the exit code and both streams, for failure
    /// messages.
    pub dump: String,
}

/// The loopback server that stands in for the hosts of a flow: the Socket
/// API at its own paths ([`StandIn::api`]), and whatever else a flow serves
/// under a route prefix per host (the registry of the package under test,
/// the patch host).
pub struct StandIn {
    // Dropped before the runtime it runs on.
    server: MockServer,
    runtime: tokio::runtime::Runtime,
}

impl StandIn {
    pub fn start() -> StandIn {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime for the stand-in");
        // A server of its own, not one of wiremock's pool: it stops when
        // the stand-in is dropped.
        let server = runtime.block_on(MockServer::builder().start());
        StandIn { server, runtime }
    }

    /// Stops the server: nothing answers at its origin any more, which is
    /// what this gives.
    pub fn stop(self) -> String {
        let origin = self.origin();
        drop(self);
        let address = origin.trim_start_matches("http://").to_string();
        let answers = || std::net::TcpStream::connect(&address).is_ok();
        for _ in 0..100 {
            if !answers() {
                return origin;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("the stand-in still answers at {origin}");
    }

    /// `http://127.0.0.1:<port>`.
    pub fn origin(&self) -> String {
        self.server.uri()
    }

    /// Answer `GET <route>` with `body`. A route nobody serves is a 404.
    /// wiremock asks the mocks of the lowest `priority` number first, so a
    /// number below the one of an earlier answer replaces that answer. The
    /// routes of [`StandIn::api`] have 5.
    pub fn serve(&self, priority: u8, route: &str, body: &[u8]) {
        let mock = Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .with_priority(priority);
        self.runtime.block_on(mock.mount(&self.server));
    }

    /// The Socket API for `patches`: what a `scan` asks about the packages
    /// of a checkout, with each patch free for every caller and granted as
    /// its `reference` says.
    pub fn api(&self, patches: &[Patch]) {
        self.runtime.block_on(mount_api(&self.server, patches));
    }

    /// The path of every request the server has received, in order.
    pub fn requests(&self) -> Vec<String> {
        let received = self.runtime.block_on(self.server.received_requests());
        let received = received.expect("wiremock records requests");
        received.iter().map(|r| r.url.path().to_string()).collect()
    }

    /// How many requests for `route` the server has received.
    pub fn asked(&self, route: &str) -> usize {
        self.requests().iter().filter(|path| *path == route).count()
    }
}

/// The line of a downloader config ([`Cell::route_downloads`]) that sends
/// every URL starting with `prefix`, a host and the start of a path, to the
/// stand-in at `origin`, which plays a host under the route prefix of its
/// name: `https://<prefix><rest>` is fetched from `<origin>/<prefix><rest>`.
/// Bazel reads the pattern as a regular expression over the whole URL after
/// its scheme, so the prefix is quoted: a `.` or a `+` in a file name or a
/// version stands for itself.
pub fn rewrite(prefix: &str, origin: &str) -> String {
    // `\E` would end the quote, and a config line is split at white space.
    assert!(
        !prefix.contains(|c: char| c == '\\' || c.is_whitespace()),
        "{prefix:?} is no URL"
    );
    format!("rewrite (\\Q{prefix}\\E.*) {origin}/$1")
}

/// The option that names a downloader config on the release `numbers`.
/// Bazel 8.2.0 gave it this name; before, it is the experimental option of
/// the same meaning, which 8.2.0 and later still take, with a warning.
fn downloader_option(numbers: Release) -> &'static str {
    if numbers < (8, 2, 0) {
        "--experimental_downloader_config="
    } else {
        "--downloader_config="
    }
}

/// One test's checkout of a fixture workspace, with a Bazel server and an
/// output base of its own.
pub struct Cell {
    pub test: String,
    /// What every repository rule must read in place of the caller's own
    /// setting (`GOPROXY`): each pair is a variable of every Bazel command
    /// and its `--repo_env=NAME=VALUE`. On Bazel 7, 8 and 9 a rule reads the
    /// client's environment with `--repo_env` on top, and under
    /// `--experimental_strict_repo_env` the flag alone.
    pub repo_env: Vec<(String, String)>,
    bazel: Bazel,
    numbers: Release,
    /// [`SOCKET_BIN`].
    socket_bin: Option<PathBuf>,
    /// The rules of the downloader config, once a flow has asked for one.
    downloads: Option<Vec<String>>,
    /// The [`wording`] of the first document [`Cell::attests`] read in
    /// this checkout, which every later one is held to: of the first that
    /// says not affected, and of the first that says affected.
    wording: [OnceLock<Value>; 2],
    // Dropped after `Cell::drop` has stopped the server.
    scratch: Scratch,
}

impl Cell {
    /// The checkout of `fixture` for `test`, on the Bazel of [`BAZEL`]:
    /// the files of the fixture's `common` and of the era its table names
    /// for that Bazel's release. `None` after a `SKIP` line when no Bazel
    /// runs here; a panic instead under [`REQUIRED`]. A panic always for a
    /// relative [`BAZEL`] or [`SOCKET_BIN`], a release that is not
    /// [`VERSION`], and a release the table does not hold.
    pub fn open(test: &str, fixture: &Fixture) -> Option<Cell> {
        let (program, socket_bin) = (program(BAZEL), program(SOCKET_BIN));
        let shared = var(REPO_CACHE).map(PathBuf::from);
        let scratch = Scratch::new(shared);
        let bazel = match Bazel::detect(&scratch, program) {
            Ok(bazel) => bazel,
            Err(why) => {
                unavailable(test, &why);
                return None;
            }
        };
        let release = &bazel.release;
        let shown = bazel.program.to_string_lossy().into_owned();
        if let Some(wanted) = var(VERSION) {
            assert!(
                wanted.to_string_lossy() == *release,
                "{test}: {VERSION}={} but `{shown}` is Bazel {release}",
                wanted.to_string_lossy()
            );
        }
        let (Some(numbers), Some(era)) = (numbers(release), fixture.era(release)) else {
            panic!(
                "{test}: `{shown}` is Bazel {release}, which no line of the era table of {} \
                 holds ({:?}): add its line, and its directory under {}",
                fixture.name,
                fixture.eras,
                fixture_path(fixture.dir).display()
            );
        };
        for part in ["common", era] {
            let source = fixture_path(fixture.dir).join(part);
            assert!(source.is_dir(), "{test}: no fixture {}", source.display());
            fs_tree::copy_tree(&source, &scratch.workspace);
        }
        // The checkout is its own repository: `socket-patch` looks no
        // higher for a `socket.yml` or a project root.
        std::fs::create_dir(scratch.workspace.join(".git")).expect("create .git");
        println!("{test}: Bazel {release} ({shown}), {}/{era}", fixture.dir);
        Some(Cell {
            test: test.to_string(),
            repo_env: Vec::new(),
            bazel,
            numbers,
            socket_bin,
            downloads: None,
            wording: Default::default(),
            scratch,
        })
    }

    /// The release of this cell's Bazel, as its `--version` prints it.
    pub fn release(&self) -> &str {
        &self.bazel.release
    }

    /// That release as three numbers, for what one release does and
    /// another does not: `cell.numbers() >= (8, 5, 0)`.
    pub fn numbers(&self) -> Release {
        self.numbers
    }

    /// A second machine with the same checkout: the files of this one, in
    /// a workspace copy with an output base and a contents cache of its
    /// own, so nothing a build here fetched or built is there. Only the
    /// repository cache is shared, and the settings of this cell go along:
    /// its `repo_env` and its downloader config. This cell's server is
    /// stopped first, so one runs at a time.
    pub fn twin(&self) -> Cell {
        if let Err(why) = self.shutdown() {
            panic!("{}: {why}", self.test);
        }
        self.unbuilt(&self.tree())
    }

    /// A checkout that no Bazel has built in: `files` in a workspace copy
    /// of its own, which has no output base and none of Bazel's `bazel-*`
    /// links, with the settings of this cell. Nothing but `socket-patch`
    /// runs in it unless the caller builds there ([`Cell::twin`]), so this
    /// cell's server keeps running.
    pub fn unbuilt(&self, files: &Tree) -> Cell {
        let mut copy = Cell {
            test: self.test.clone(),
            repo_env: self.repo_env.clone(),
            bazel: self.bazel.clone(),
            numbers: self.numbers,
            socket_bin: self.socket_bin.clone(),
            downloads: None,
            wording: Default::default(),
            scratch: Scratch::new(Some(self.scratch.repository_cache.clone())),
        };
        for (rel, bytes) in files {
            copy.write(rel, bytes);
        }
        std::fs::create_dir(copy.scratch.workspace.join(".git")).expect("create .git");
        if let Some(rules) = &self.downloads {
            copy.route_downloads(rules);
        }
        copy
    }

    /// Send the downloads of Bazel's own downloader where `rules` say: the
    /// lines of a downloader config ([`rewrite`] makes the usual one), which
    /// every Bazel command of this cell names from now on, by the option of
    /// its release. A flow asks for it before its first build, as a machine
    /// behind a mirror has the option in an rc file, so no step of the flow
    /// changes a flag. A second call replaces the rules of the first.
    pub fn route_downloads(&mut self, rules: &[String]) {
        let file = &self.scratch.downloads;
        std::fs::write(file, rules.join("\n") + "\n")
            .unwrap_or_else(|e| panic!("write {}: {e}", file.display()));
        self.downloads = Some(rules.to_vec());
    }

    /// Whether the repository cache of this cell, which its twins share,
    /// holds a download with the sha256 `sha256`: what Bazel's downloader
    /// keeps of a file it fetched under a checksum.
    pub fn cached(&self, sha256: &str) -> bool {
        let files = self.scratch.repository_cache.join("content_addressable");
        files.join("sha256").join(sha256).exists()
    }

    /// Write a file of the workspace copy.
    pub fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = self.scratch.workspace.join(rel);
        std::fs::create_dir_all(path.parent().expect("a file path")).expect("create the parent");
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }

    /// The path of `rel` in the workspace copy.
    pub fn path(&self, rel: &str) -> PathBuf {
        self.scratch.workspace.join(rel)
    }

    /// Every regular file of the workspace copy. Bazel's `bazel-*` links
    /// into the output base are links, so they are not followed.
    pub fn tree(&self) -> Tree {
        read_tree(&self.scratch.workspace)
    }

    /// `bazel <command> <options> <args>` in the workspace copy.
    pub fn bazel(&self, command: &str, args: &[&str]) -> Run {
        self.bazel_with("update", command, args)
    }

    /// [`Cell::bazel`] with variables of the one command: the `REPIN=1` of
    /// a ruleset's relock. Bazel's client hands its environment to the
    /// repository rules and to what `bazel run` starts.
    pub fn bazel_env(&self, command: &str, args: &[&str], env: &[(&str, &str)]) -> Run {
        let mut cmd = self.command("update", command, args);
        cmd.envs(env.iter().copied());
        Run::of(cmd).unwrap_or_else(|why| panic!("{}: {why}", self.test))
    }

    /// `bazel build --lockfile_mode=error <targets>`: passes only when
    /// `MODULE.bazel.lock` already holds what the build resolves.
    fn frozen_build(&self, targets: &[&str]) -> Run {
        self.bazel_with("error", "build", targets)
    }

    fn bazel_with(&self, lockfile_mode: &str, command: &str, args: &[&str]) -> Run {
        let cmd = self.command(lockfile_mode, command, args);
        Run::of(cmd).unwrap_or_else(|why| panic!("{}: {why}", self.test))
    }

    /// `bazel <command> <options> <args>`, not started yet.
    fn command(&self, lockfile_mode: &str, command: &str, args: &[&str]) -> Command {
        let scratch = &self.scratch;
        let mut cmd = self.bazel.command(scratch, command);
        cmd.envs(self.repo_env.iter().map(|(name, value)| (name, value)));
        let mut joined = |flag: &str, value: &OsStr| {
            let mut arg = OsString::from(flag);
            arg.push(value);
            cmd.arg(arg);
        };
        joined("--repository_cache=", scratch.repository_cache.as_os_str());
        let mut home = OsString::from("HOME=");
        home.push(&scratch.home);
        joined("--repo_env=", &home);
        for (name, value) in &self.repo_env {
            joined("--repo_env=", format!("{name}={value}").as_ref());
        }
        // Stated, so no test depends on a release's default.
        joined("--lockfile_mode=", lockfile_mode.as_ref());
        if self.numbers() >= (9, 0, 0) {
            // Bazel 9 keeps the repositories it fetched in a contents cache,
            // by default under the repository cache, and hands them to the
            // next workspace copy without a fetch. The cache stays on, as a
            // user has it, in a place of this copy's own: a twin starts
            // with an empty one and has to fetch. Bazel 8 has the cache
            // off by default, Bazel 7 has none.
            joined("--repo_contents_cache=", scratch.contents_cache.as_os_str());
        }
        if self.downloads.is_some() {
            let option = downloader_option(self.numbers());
            joined(option, scratch.downloads.as_os_str());
        }
        cmd.args(["--color=no", "--curses=no"]);
        cmd.args(args);
        cmd
    }

    /// The build a user runs, and what it built: `bazel build //:consumer`
    /// passes, and `bazel run //:consumer` prints the line `marker`.
    pub fn builds(&self, marker: &str) {
        let built = self.bazel("build", &[CONSUMER]);
        assert!(built.ok(), "{}: {}", self.test, built.dump());
        let ran = self.bazel("run", &[CONSUMER]);
        assert!(
            ran.ok() && ran.stdout().lines().any(|line| line == marker),
            "{}: {CONSUMER} did not print {marker:?}:\n{}",
            self.test,
            ran.dump()
        );
    }

    /// [`Cell::builds`] on a second machine ([`Cell::twin`]) that has no
    /// lock of Bazel's either: its Bazel has fetched and built nothing and
    /// holds no record of a hub, so it evaluates every hub anew, with the
    /// `repo_env` of this cell. A warm rebuild here proves nothing of what
    /// lies outside the checkout: Bazel does not look there again. This
    /// cell goes before the second one builds, unless it holds the
    /// repository cache (no [`REPO_CACHE`]): a flow keeps one output base
    /// at a time.
    pub fn builds_anew(self, marker: &str) {
        let twin = self.twin();
        let _first = var(REPO_CACHE).is_none().then_some(self);
        std::fs::remove_file(twin.path("MODULE.bazel.lock")).expect("Bazel's lock");
        twin.builds(marker);
    }

    /// Step (a) of a flow: the build prints `marker`, and Bazel wrote its
    /// lock. Gives the files of the checkout, that lock among them.
    pub fn builds_unpatched(&self, marker: &str) -> Tree {
        self.builds(marker);
        let before = self.tree();
        let locked = before.contains_key("MODULE.bazel.lock");
        assert!(locked, "{}: Bazel wrote no lock", self.test);
        before
    }

    /// Step (b) of a hosted flow, for its finished `scan --mode hosted
    /// --yes`: the command applied the one patch `uuid` of `purl`, it names
    /// `files` as what it rewrote, and those are the files of the checkout
    /// that differ from `before`, and no other. Gives the files of the
    /// checkout as the command left them.
    pub fn pinned_by(
        &self,
        scan: &Ran,
        purl: &str,
        uuid: &str,
        before: &Tree,
        files: &[&str],
    ) -> Tree {
        let (test, said) = (&self.test, &scan.dump);
        assert_eq!(scan.code, 0, "{test}: {said}");
        assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
        assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
        let event = event_for(&scan.envelope, purl);
        assert_eq!(event["action"], "applied", "{test}: {said}");
        assert_eq!(event["uuid"], uuid, "{test}: {said}");
        let rewritten = &scan.envelope["redirect"]["rewrittenFiles"];
        assert_eq!(*rewritten, json!(files), "{test}: {said}");
        let pinned = self.tree();
        assert_eq!(changed(before, &pinned), files, "{test}: {said}");
        pinned
    }

    /// Step (c) of a flow whose build writes no file of the checkout: the
    /// build prints `marker`, Bazel changed no file of `pinned`, its own
    /// lock included, and that lock still stands when Bazel may not update
    /// it.
    pub fn builds_patched(&self, pinned: &Tree, marker: &str) {
        self.builds(marker);
        assert_eq!(changed(pinned, &self.tree()), NOTHING, "{}", self.test);
        let frozen = self.frozen_build(&[CONSUMER]);
        assert!(frozen.ok(), "{}: {}", self.test, frozen.dump());
    }

    /// Step (d) of such a flow, for its finished undo (`rollback --yes`, or
    /// `vendor --revert`): the command counts one package under `counted`
    /// of its summary, every file of the checkout is the one of `before`,
    /// and so is the build, which prints `marker` and changes no file.
    pub fn undone(&self, undo: &Ran, counted: &str, before: &Tree, marker: &str) {
        let (test, said) = (&self.test, &undo.dump);
        assert_eq!(undo.code, 0, "{test}: {said}");
        assert_eq!(undo.envelope["summary"][counted], 1, "{test}: {said}");
        assert_eq!(changed(before, &self.tree()), NOTHING, "{test}: {said}");
        self.builds(marker);
        assert_eq!(changed(before, &self.tree()), NOTHING, "{test}");
    }

    /// `socket-patch <args>` in the workspace copy, as a user in that
    /// directory runs it, against the Socket API at `api`. Its home and
    /// temp directory are the cell's, and every proxy is a closed port, so
    /// it reaches no host but loopback.
    fn socket_patch_command(&self, api: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut cmd = match &self.socket_bin {
            Some(bin) => hermetic::command(bin),
            None => hermetic::binary_command(),
        };
        cmd.current_dir(&self.scratch.workspace)
            .args(args)
            .args(["--api-url", api, "--org", ORG])
            .args(["--api-token", "fake-token"]);
        hermetic::scrub_crawler_inputs(&mut cmd);
        cmd.env("HOME", &self.scratch.home)
            .env("TMPDIR", &self.scratch.tmp);
        for proxy in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            cmd.env(proxy, CLOSED_PORT);
            cmd.env(proxy.to_ascii_lowercase(), CLOSED_PORT);
        }
        cmd.env("NO_PROXY", LOOPBACK.join(","));
        cmd.env("no_proxy", LOOPBACK.join(","));
        cmd.envs(env.iter().copied());
        cmd
    }

    /// [`Cell::socket_patch_command`] with `--json`: the run and its
    /// envelope.
    pub fn socket_patch(&self, api: &str, args: &[&str], env: &[(&str, &str)]) -> Ran {
        let mut cmd = self.socket_patch_command(api, args, env);
        cmd.arg("--json");
        let line = format!("{cmd:?}");
        let out = cmd.output().unwrap_or_else(|e| panic!("spawn {line}: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let code = out.status.code().unwrap_or(-1);
        let dump = format!("{line}\nexit {code}\n--- stdout\n{stdout}\n--- stderr\n{stderr}");
        let envelope = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{}: stdout is no JSON envelope ({e}):\n{dump}", self.test));
        Ran {
            code,
            envelope,
            dump,
        }
    }

    /// [`Cell::socket_patch_command`] as a person runs it, without
    /// `--json`: what it printed on stdout and on stderr.
    pub fn socket_patch_person(
        &self,
        api: &str,
        args: &[&str],
        env: &[(&str, &str)],
    ) -> [String; 2] {
        let mut cmd = self.socket_patch_command(api, args, env);
        let out = cmd.output().expect("spawn socket-patch");
        [out.stdout, out.stderr].map(|stream| String::from_utf8_lossy(&stream).into_owned())
    }

    /// [`Cell::socket_patch_person`] for a command that is given
    /// [`with_vex`] for `path` among `args`, in a checkout where Bazel does
    /// not build the patched copy of the one package the run attests. The
    /// command passes and writes the document, which says `claim`: the
    /// package is affected. It prints the line `warned` on stderr and no
    /// error, and says that it wrote a document with one statement, which
    /// says affected (a hosted scan on stderr, with a note after it). With
    /// `--silent` among `args` it prints nothing at all.
    pub fn tells_a_person(
        &self,
        api: &str,
        args: &[&str],
        env: &[(&str, &str)],
        path: &Path,
        claim: &Claim,
        warned: &str,
    ) {
        let _ = std::fs::remove_file(path);
        let mut cmd = self.socket_patch_command(api, args, env);
        let out = cmd.output().expect("spawn socket-patch");
        let code = out.status.code();
        let [stdout, stderr] =
            [out.stdout, out.stderr].map(|stream| String::from_utf8_lossy(&stream).into_owned());
        let test = &self.test;
        let said =
            format!("{test}: {args:?}\nexit {code:?}\n--- stdout\n{stdout}\n--- stderr\n{stderr}");
        assert_eq!(code, Some(0), "{said}");
        self.attests(path, claim, true);
        if args.contains(&"--silent") {
            assert_eq!([stdout.as_str(), stderr.as_str()], ["", ""], "{said}");
            return;
        }
        let wrote = format!(
            "Wrote OpenVEX document with 1 statement (1 affected) to {}",
            path.display()
        );
        let mut lines = stdout.lines().chain(stderr.lines());
        assert!(lines.any(|line| line.starts_with(&wrote)), "{said}");
        let printed = stderr.lines().any(|line| line == warned);
        assert!(printed, "no {warned:?}:\n{said}");
        assert!(!stderr.contains("Error"), "{said}");
    }

    /// What `socket-patch <args>`, a command that is to write its document
    /// to `path`, gives a script and a person: of a run with `--json` and
    /// of one without, the exit code, all it printed on stdout and on
    /// stderr, and what the document it wrote says ([`wording`]: all but
    /// its id and its times), null when it left none. Two commands that
    /// give the same differ in nothing a script or a person sees.
    pub fn gives(&self, api: &str, args: &[&str], env: &[(&str, &str)], path: &Path) -> Value {
        let run = |form: &[&str]| {
            let _ = std::fs::remove_file(path);
            let mut cmd = self.socket_patch_command(api, &[args, form].concat(), env);
            let out = cmd.output().expect("spawn socket-patch");
            let [stdout, stderr] = [out.stdout, out.stderr]
                .map(|stream| String::from_utf8_lossy(&stream).into_owned());
            let written = path
                .exists()
                .then(|| wording(document_at(&self.test, path).1));
            json!({ "code": out.status.code(), "stdout": stdout, "stderr": stderr, "document": written })
        };
        json!([run(&["--json"]), run(&[])])
    }

    /// What of the workspace copy its regular files ([`Cell::tree`]) do not
    /// make anew, each by its path from the copy: a link, a directory that
    /// holds nothing, a file with a permission bit to run it, and whatever
    /// is neither a file nor a directory.
    fn not_made_by_its_files(&self) -> Vec<String> {
        use std::os::unix::fs::PermissionsExt;
        fn walk(dir: &Path, odd: &mut Vec<PathBuf>) {
            let entries = std::fs::read_dir(dir).expect("a directory of the copy");
            let entries: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
            if entries.is_empty() {
                odd.push(dir.to_path_buf());
            }
            for path in entries {
                let meta = std::fs::symlink_metadata(&path).expect("an entry of the copy");
                if meta.is_dir() {
                    walk(&path, odd);
                } else if !meta.is_file() || meta.permissions().mode() & 0o111 != 0 {
                    odd.push(path);
                }
            }
        }
        let (base, mut odd) = (&self.scratch.workspace, Vec::new());
        walk(base, &mut odd);
        odd.retain(|path| path != base);
        let shown = |path: &PathBuf| match path.strip_prefix(base) {
            Ok(from) => from.display().to_string(),
            Err(_) => path.display().to_string(),
        };
        let mut odd: Vec<String> = odd.iter().map(shown).collect();
        odd.sort();
        odd
    }

    /// The workspace copy with the files `files` and nothing else: every
    /// file as a new one, with the permission bits of any new file, and no
    /// directory but those the files are in.
    fn remake(&self, files: &Tree) {
        let entries = std::fs::read_dir(&self.scratch.workspace).expect("the workspace copy");
        for entry in entries.flatten() {
            let path = entry.path();
            let gone = match entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                true => std::fs::remove_dir_all(&path),
                false => std::fs::remove_file(&path),
            };
            gone.unwrap_or_else(|e| panic!("remove {}: {e}", path.display()));
        }
        for (rel, bytes) in files {
            self.write(rel, bytes);
        }
    }

    /// `SOCKET_NO_BAZEL=1` makes `socket-patch <args>` in this checkout the
    /// run of the same checkout without its Bazel files `bazel`, to a
    /// script (`--json`) and to a person: the exit code, both streams byte
    /// for byte, and every file the run left but those ([`undated`]). Each
    /// run starts in the checkout as it is now, made anew from its regular
    /// files, and the checkout is left so. A checkout that those files do
    /// not make anew is refused, with what it holds beside them
    /// ([`Cell::not_made_by_its_files`]): a link, an empty directory or an
    /// executable file would be gone from the second run on, and the runs
    /// would not start alike. The run without the Bazel files passes.
    /// Without the variable the same command gives something else in the
    /// workspace, which is what this gives: the comparison is of a run that
    /// the workspace changes.
    pub fn off_is_without_bazel(
        &self,
        api: &str,
        args: &[&str],
        env: &[(&str, &str)],
        bazel: &[&str],
    ) -> Value {
        self.without_and_beside(api, args, env, bazel).1
    }

    /// [`Cell::off_is_without_bazel`], with what the run without the Bazel
    /// files gave before what the run beside them gave: for a test that
    /// also holds what the run with the variable did, which is the first.
    pub fn without_and_beside(
        &self,
        api: &str,
        args: &[&str],
        env: &[(&str, &str)],
        bazel: &[&str],
    ) -> (Value, Value) {
        let odd = self.not_made_by_its_files();
        assert_eq!(
            odd,
            Vec::<String>::new(),
            "{}: the regular files of this checkout do not make it anew",
            self.test
        );
        let files = self.tree();
        let mut plain = files.clone();
        plain.retain(|rel, _| !bazel.contains(&rel.as_str()));
        let gives = |start: &Tree, env: &[(&str, &str)]| {
            let run = |form: &[&str]| {
                self.remake(start);
                let mut cmd = self.socket_patch_command(api, &[args, form].concat(), env);
                let out = cmd.output().expect("spawn socket-patch");
                let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
                let mut left = undated(&self.tree());
                left.retain(|rel, _| !bazel.contains(&rel.as_str()));
                let left: BTreeMap<String, String> = left
                    .into_iter()
                    .map(|(rel, bytes)| (rel, text(bytes)))
                    .collect();
                json!({
                    "code": out.status.code(),
                    "stdout": text(out.stdout),
                    "stderr": text(out.stderr),
                    "files": left,
                })
            };
            json!([run(&["--json"]), run(&[])])
        };
        let off = [env, &[("SOCKET_NO_BAZEL", "1")]].concat();
        let without = gives(&plain, env);
        let (switched, beside) = (gives(&files, &off), gives(&files, env));
        self.remake(&files);
        let test = &self.test;
        let codes = [&without[0]["code"], &without[1]["code"]];
        assert_eq!(
            codes,
            [&json!(0), &json!(0)],
            "{test}: {args:?}: {without:#}"
        );
        assert_eq!(switched, without, "{test}: {args:?} with SOCKET_NO_BAZEL=1");
        assert_ne!(
            beside, without,
            "{test}: {args:?} is no other run in the workspace"
        );
        (without, beside)
    }

    /// Where a flow has `socket-patch` write the VEX document `name`:
    /// beside the workspace copy, so it is no file of the checkout, and no
    /// comparison of the checkout's files sees it.
    pub fn document(&self, name: &str) -> PathBuf {
        self.scratch.documents.join(format!("{name}.vex.json"))
    }

    /// The document at `path` says `claim` and nothing else: one statement,
    /// `not_affected` for the one advisory, with the package as the one
    /// subcomponent of the one product and the patch of this run in its
    /// impact statement, which ends with `; not verified on disk` exactly
    /// when the run did not check the files (`verified` is false). For
    /// [`Claim::unbuilt`] the one statement is `affected` for that
    /// advisory, product and package, with no justification and no impact
    /// statement, and an action statement that holds the patch and each
    /// name of the claim. And it says so in the words of every other
    /// document of that status read in this checkout: the forms spell the
    /// product, the package, the advisory and the status alike, and differ
    /// in nothing but what [`wording`] leaves out.
    fn attests(&self, path: &Path, claim: &Claim, verified: bool) {
        let test = &self.test;
        let (text, document) = document_at(test, path);
        let context = "https://openvex.dev/ns/v0.2.0";
        assert_eq!(document["@context"], context, "{test}: {text}");
        let statements = document["statements"].as_array();
        let Some([statement]) = statements.map(Vec::as_slice) else {
            panic!("{test}: not one statement:\n{text}");
        };
        let advisory = &statement["vulnerability"]["name"];
        assert_eq!(*advisory, ADVISORY, "{test}: {text}");
        // The package is named as its record names it: with `%40` or with
        // `@` for the scope of an npm name.
        let named = statement["products"][0]["subcomponents"][0]["@id"].as_str();
        let named = named.unwrap_or_default();
        let purl = normalize_purl(claim.purl);
        assert_eq!(normalize_purl(named), purl, "{test}: {text}");
        let products = json!([{ "@id": PRODUCT, "subcomponents": [{ "@id": named }] }]);
        assert_eq!(statement["products"], products, "{test}: {text}");
        let (uuid, how) = (claim.uuid, claim.how.words());
        if claim.affected() {
            assert_eq!(statement["status"], "affected", "{test}: {text}");
            let reserved = ["justification", "impact_statement"];
            let reserved = reserved.map(|key| statement.get(key).is_some());
            assert_eq!(reserved, [false, false], "{test}: {text}");
            let action = statement["action_statement"].as_str().unwrap_or_default();
            for name in claim.names.iter().map(String::as_str).chain([uuid]) {
                assert!(action.contains(name), "{test}: no {name:?} in {action:?}");
            }
        } else {
            assert_eq!(statement["status"], "not_affected", "{test}: {text}");
            let justification = "inline_mitigations_already_exist";
            assert_eq!(statement["justification"], justification, "{test}: {text}");
            let mut impact = format!("Patched via Socket patch {uuid}{how}");
            if !verified {
                impact += NOT_VERIFIED_SUFFIX;
            }
            assert_eq!(statement["impact_statement"], impact, "{test}: {text}");
        }
        let said = wording(document);
        let first = self.wording[usize::from(claim.affected())].get_or_init(|| said.clone());
        assert_eq!(
            said, *first,
            "{test}: not the words of the first document of this checkout:\n{text}"
        );
    }

    /// The stand-alone `vex` of this checkout, through `run`, the flow's way
    /// to run `socket-patch` in a cell. It attests `claim` and nothing
    /// else, in its envelope and in the document it writes, which is not
    /// the one of an earlier call. `verified` is false for
    /// `vex --no-verify`, which says in a warning, and in the document,
    /// that it checked no file. Of an affected package it says the same
    /// with and without that option, and does not report it as verified:
    /// its one event is `skipped` with the code [`NOT_IN_BUILD`] and the
    /// status `affected`, the run is a partial failure that exits 0, and
    /// its one warning names what the claim names.
    pub fn stands_alone(&self, run: impl Fn(&Cell, &[&str]) -> Ran, claim: &Claim, verified: bool) {
        let path = self.document("stand-alone");
        let _ = std::fs::remove_file(&path);
        let unchecked: &[&str] = if verified { &[] } else { &["--no-verify"] };
        let ran = run(self, &[&vex(&path), unchecked].concat());
        let (test, said) = (&self.test, &ran.dump);
        assert_eq!(ran.code, 0, "{test}: {said}");
        let [event] = events(&ran.envelope) else {
            panic!("{test}: not one event: {said}");
        };
        let affected = usize::from(claim.affected());
        let [status, action, state] = [
            ["success", "verified", "not_affected"],
            ["partialFailure", "skipped", "affected"],
        ][affected];
        assert_eq!(ran.envelope["status"], status, "{test}: {said}");
        assert_eq!(event["action"], action, "{test}: {said}");
        let code = [Value::Null, json!(NOT_IN_BUILD)][affected].clone();
        assert_eq!(event["errorCode"], code, "{test}: {said}");
        let summary = &ran.envelope["summary"];
        let counted = [&summary["verified"], &summary["skipped"]].map(Value::as_u64);
        let expected = [[Some(1), Some(0)], [Some(0), Some(1)]][affected];
        assert_eq!(counted, expected, "{test}: {said}");
        let purl = normalize_purl(event["purl"].as_str().unwrap_or_default());
        assert_eq!(purl, normalize_purl(claim.purl), "{test}: {said}");
        let details = &event["details"];
        assert_eq!(details["status"], state, "{test}: {said}");
        assert_eq!(details["vulnerability"], ADVISORY, "{test}: {said}");
        let warned: &[&str] = match (claim.affected(), verified) {
            (true, _) => &[NOT_IN_BUILD],
            (false, true) => &[],
            (false, false) => &["vex_not_verified"],
        };
        let warnings = &ran.envelope["warnings"];
        assert_eq!(codes_in(warnings), warned, "{test}: {said}");
        self.names_the_build(warnings, claim, said);
        self.attests(&path, claim, verified);
    }

    /// `vex --output <file>` as a user types it, with no `--product`,
    /// through `run`, in this checkout that Bazel has built in: beside the
    /// project's own files are Bazel's links, and behind them those files
    /// again. `product` is what `vex` reads from the project file of the
    /// checkout: it writes the document every other form wrote here, for
    /// that product, and warns of nothing. With `None` the checkout has no
    /// file `vex` reads a product from: it exits 2 with
    /// `product_undetected` and writes no document.
    pub fn detects_product(&self, run: impl Fn(&Cell, &[&str]) -> Ran, product: Option<&str>) {
        let path = self.document("no-product");
        let ran = run(self, &["vex", "--output", argument(&path)]);
        let (test, said) = (&self.test, &ran.dump);
        let Some(product) = product else {
            assert_eq!(ran.code, 2, "{test}: {said}");
            let error = &ran.envelope["error"]["code"];
            assert_eq!(*error, "product_undetected", "{test}: {said}");
            assert!(!path.exists(), "{test}: a document is left: {said}");
            return;
        };
        assert_eq!(ran.code, 0, "{test}: {said}");
        assert_eq!(
            codes_in(&ran.envelope["warnings"]),
            NOTHING,
            "{test}: {said}"
        );
        let (text, document) = document_at(test, &path);
        let mut named = self.wording[0].get().cloned().expect("a document here");
        named["statements"][0]["products"][0]["@id"] = product.into();
        assert_eq!(wording(document), named, "{test}: {said}\n{text}");
    }

    /// For a finished command that was given [`with_vex`] for `path`: it
    /// passed, and wrote the document of its own run, which attests
    /// `claim` and nothing else. A hosted scan says of its document that
    /// no file was hashed for it: the lock names the patch, and the bytes
    /// come with the next build. A run whose document says the package is
    /// affected counts that statement as such, warns of it once, and names
    /// what the claim names.
    pub fn wrote_in_run(&self, ran: &Ran, path: &Path, claim: &Claim) {
        let (test, said) = (&self.test, &ran.dump);
        assert_eq!(ran.code, 0, "{test}: {said}");
        let vex = &ran.envelope["vex"];
        assert_eq!(vex["statements"], 1, "{test}: {said}");
        let affected = [Value::Null, json!(1)][usize::from(claim.affected())].clone();
        assert_eq!(vex["affected"], affected, "{test}: {said}");
        assert_eq!(vex["format"], "openvex-0.2.0", "{test}: {said}");
        assert_eq!(vex["path"], argument(path), "{test}: {said}");
        let warned: &[&str] = match claim.how {
            How::Hosted => &["vex_hosted_unverified"],
            How::Vendored | How::Agent => &[],
            How::Unbuilt => &[NOT_IN_BUILD],
        };
        assert_eq!(codes_in(&vex["warnings"]), warned, "{test}: {said}");
        self.names_the_build(&vex["warnings"], claim, said);
        self.attests(path, claim, true);
    }

    /// The same two documents from a checkout that no Bazel has built in:
    /// one with the files `before`, where `command`, the command of the
    /// mode, applies the patch and writes the document of its run, and the
    /// stand-alone `vex` writes its own, both in the words of this
    /// checkout's documents. The command leaves the files `patched`, those
    /// the patched build started from, so both checkouts attest the same
    /// files. One field of one file is left out: `vendoredAt`, the time of
    /// its run in the marker of a vendored copy.
    pub fn attests_unbuilt(
        &self,
        run: impl Fn(&Cell, &[&str]) -> Ran,
        command: &[&str],
        before: &Tree,
        patched: &Tree,
        claim: &Claim,
    ) {
        let fresh = self.unbuilt(before);
        let in_run = fresh.document("in-run");
        let ran = run(&fresh, &[command, &with_vex(&in_run)].concat());
        let (test, said) = (&self.test, &ran.dump);
        assert_eq!(ran.envelope["summary"]["applied"], 1, "{test}: {said}");
        fresh.wrote_in_run(&ran, &in_run, claim);
        let differ = changed(&undated(patched), &undated(&fresh.tree()));
        assert_eq!(differ, NOTHING, "{test}: {said}");
        fresh.stands_alone(run, claim, true);
        let (here, there) = (self.wording[0].get(), fresh.wording[0].get());
        assert_eq!(there, here, "{test}: the two checkouts word it apart");
    }

    /// Agent mode in this checkout, through `run`, for a package that its
    /// package manager keeps outside the checkout, where `installed` is a
    /// file of that copy: `scan --mode agent --yes` gives the file the text
    /// `patched`, from the record of the patch, and writes nothing into the
    /// checkout but its own `.socket` directory, and the `apply` of a later
    /// run passes. Then what the two say with `--vex`, and what `vex` and
    /// `vex --no-verify` say: all four pass and write one document, which
    /// says `claim`. Gives the files of the checkout.
    pub fn patches_outside(
        &self,
        run: impl Fn(&Cell, &[&str]) -> Ran,
        installed: &Path,
        patched: &str,
        claim: &Claim,
    ) -> Tree {
        let test = &self.test;
        let before = self.tree();
        let in_run = self.document("in-run");
        let agent = ["scan", "--mode", "agent", "--yes"];
        let scan = run(self, &[&agent[..], &with_vex(&in_run)].concat());
        let said = &scan.dump;
        assert_eq!(scan.code, 0, "{test}: {said}");
        assert_eq!(scan.envelope["status"], "success", "{test}: {said}");
        assert_eq!(scan.envelope["summary"]["applied"], 1, "{test}: {said}");
        let left = self.tree();
        let mut wrote = changed(&before, &left);
        wrote.retain(|file| !file.starts_with(".socket/"));
        assert_eq!(wrote, NOTHING, "{test}: {said}");
        let holds = std::fs::read_to_string(installed).unwrap_or_default();
        assert_eq!(holds, patched, "{test}: {}", installed.display());

        let again = self.document("apply");
        let apply = run(self, &[&["apply"][..], &with_vex(&again)].concat());
        let status = &apply.envelope["status"];
        assert_eq!(*status, "success", "{test}: {}", apply.dump);
        self.wrote_in_run(&scan, &in_run, claim);
        self.wrote_in_run(&apply, &again, claim);
        self.stands_alone(&run, claim, true);
        self.stands_alone(&run, claim, false);
        assert_eq!(changed(&left, &self.tree()), NOTHING, "{test}");
        left
    }

    /// What stays the statement of a project without Bazel in this
    /// checkout, after [`Cell::patches_outside`] under a hub that builds
    /// the package from the project's lock. With `--no-bazel`, and with
    /// each of `undecided` as its `MODULE.bazel`, whose files do not show
    /// such a hub, `vex` attests the package as `installed` says, through
    /// the patch. And what it gives a script and a person is what it gives
    /// in the same checkout without its `MODULE.bazel`: the exit code,
    /// both streams and the document. `gives` is [`Cell::gives`] of this
    /// cell with the Socket API and the environment of `run`.
    pub fn keeps_its_statement(
        &self,
        run: impl Fn(&Cell, &[&str]) -> Ran,
        gives: impl Fn(&[&str], &Path) -> Value,
        installed: &Claim,
        undecided: &[String],
    ) {
        let shipped = |cell: &Cell, args: &[&str]| run(cell, &[args, &["--no-bazel"]].concat());
        self.stands_alone(shipped, installed, true);
        let document = self.document("undecided");
        let vex = vex(&document);
        let mut given = vec![gives(&[&vex[..], &["--no-bazel"]].concat(), &document)];
        let module = self.path("MODULE.bazel");
        let hub = std::fs::read_to_string(&module).expect("MODULE.bazel");
        for other in undecided {
            assert_ne!(*other, hub, "{}", self.test);
            self.write("MODULE.bazel", other);
            self.stands_alone(&run, installed, true);
            given.push(gives(&vex, &document));
        }
        std::fs::remove_file(&module).expect("MODULE.bazel");
        self.stands_alone(&run, installed, true);
        let without_bazel = gives(&vex, &document);
        for (at, given) in given.iter().enumerate() {
            assert_eq!(*given, without_bazel, "{}: the run {at}", self.test);
        }
        println!("`vex` in a checkout without MODULE.bazel:\n{without_bazel:#}");
    }

    /// The stand-alone `vex` of a checkout that holds no patch any more,
    /// through `run`: it exits `code` with the error `error` and leaves no
    /// document, and says that it removed the one [`Cell::stands_alone`]
    /// left.
    pub fn attests_nothing(&self, run: impl Fn(&Cell, &[&str]) -> Ran, code: i32, error: &str) {
        let path = self.document("stand-alone");
        let ran = run(self, &vex(&path));
        let (test, said) = (&self.test, &ran.dump);
        assert_eq!(ran.code, code, "{test}: {said}");
        assert_eq!(ran.envelope["error"]["code"], error, "{test}: {said}");
        assert!(!path.exists(), "{test}: a document is left: {said}");
        let warned = codes_in(&ran.envelope["warnings"]);
        let removed = warned.iter().any(|code| code == "vex_stale_doc_removed");
        assert!(removed, "{test}: {said}");
    }

    /// For [`Claim::unbuilt`], the one [`NOT_IN_BUILD`] warning of
    /// `warnings` is about the package of `claim`, says that the document
    /// says affected, and holds each name of the claim. For every other
    /// claim there is no such warning.
    fn names_the_build(&self, warnings: &Value, claim: &Claim, said: &str) {
        let test = &self.test;
        let ours = |warning: &&Value| warning["code"] == NOT_IN_BUILD;
        let ours: Vec<&Value> = warnings
            .as_array()
            .into_iter()
            .flatten()
            .filter(ours)
            .collect();
        if !claim.affected() {
            assert!(ours.is_empty(), "{test}: {said}");
            return;
        }
        let [warning] = ours[..] else {
            panic!("{test}: not one {NOT_IN_BUILD} warning: {said}");
        };
        let detail = warning["detail"].as_str().unwrap_or_default();
        let (about, rest) = detail.split_once(": ").unwrap_or_default();
        assert_eq!(
            normalize_purl(about),
            normalize_purl(claim.purl),
            "{test}: {said}"
        );
        let affected = "the VEX document says affected. ";
        assert!(rest.starts_with(affected), "{test}: {detail:?}");
        for name in claim.names {
            assert!(
                rest.contains(name.as_str()),
                "{test}: no {name:?} in {detail:?}"
            );
        }
    }

    /// `bazel shutdown`, when the pid file of a server is there. No command
    /// options: the startup options are what address the server.
    fn shutdown(&self) -> Result<(), String> {
        let bases = std::fs::read_dir(&self.scratch.output_user_root);
        let mut bases = bases.into_iter().flatten().flatten();
        if !bases.any(|base| base.path().join("server/server.pid.txt").exists()) {
            return Ok(());
        }
        let run = Run::of(self.bazel.command(&self.scratch, "shutdown"))?;
        if run.ok() {
            Ok(())
        } else {
            Err(format!("`bazel shutdown` failed:\n{}", run.dump()))
        }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        // Never panic here: this also runs while a failed test unwinds. If
        // the shutdown fails, the idle timeout ends the server.
        if let Err(why) = self.shutdown() {
            eprintln!("{}: leaving a Bazel server behind: {why}", self.test);
        }
    }
}

#[test]
fn a_release_is_read_as_three_numbers() {
    assert_eq!(numbers("9.3.2"), Some((9, 3, 2)));
    assert_eq!(numbers("7.7.2"), Some((7, 7, 2)));
    assert_eq!(numbers("9.3.2-homebrew"), Some((9, 3, 2)));
    assert_eq!(numbers("10.0.0rc3"), Some((10, 0, 0)));
    for unreadable in ["9.3", "9.x.2", "no_version", ""] {
        assert_eq!(numbers(unreadable), None, "{unreadable:?}");
    }
}

#[test]
fn a_release_builds_the_era_whose_range_holds_it() {
    let fixture = Fixture {
        name: "a table",
        dir: "none",
        workflow: "none",
        eras: &[
            ((7, 0, 0)..(8, 0, 0), "old"),
            ((8, 0, 0)..(10, 0, 0), "new"),
        ],
    };
    for (release, era) in [
        ("7.0.0", Some("old")),
        ("7.7.2", Some("old")),
        ("8.0.0", Some("new")),
        ("9.3.2-homebrew", Some("new")),
        ("6.5.0", None),
        ("10.0.0", None),
        ("no_version", None),
    ] {
        assert_eq!(fixture.era(release), era, "{release}");
    }
}

/// A cell no Bazel stands behind, for what is decided without one: the
/// command line of the release `release`, and what `socket-patch` writes
/// in a checkout. Its workspace copy is empty.
pub fn cell_without_bazel(release: &str) -> Cell {
    Cell {
        test: "a test".to_string(),
        repo_env: Vec::new(),
        bazel: Bazel {
            program: "bazel".into(),
            release: release.to_string(),
        },
        numbers: numbers(release).expect("a release"),
        socket_bin: None,
        downloads: None,
        wording: Default::default(),
        scratch: Scratch::new(None),
    }
}

/// Bazel 8.1.1 has the experimental option alone and 8.2.0 has both names
/// (`RepositoryOptions.java` at Bazel's two tags), so 8.2.0 is where the
/// name changes. A cell names its config on every command once a flow has
/// asked for one, never before, and its twin names a config of its own.
#[test]
fn a_downloader_config_is_named_by_the_option_of_the_release() {
    let rule = rewrite("registry.example/a+b/-/a+b-1.0.0.tgz", "http://127.0.0.1:1");
    assert_eq!(
        rule,
        r"rewrite (\Qregistry.example/a+b/-/a+b-1.0.0.tgz\E.*) http://127.0.0.1:1/$1"
    );
    let rules = [rule, "block patch.example".to_string()];
    // The arguments of a build that name a downloader config.
    let named = |cell: &Cell| -> Vec<String> {
        let build = cell.command("update", "build", &[CONSUMER]);
        let args = build
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned());
        args.filter(|arg| arg.contains("downloader_config"))
            .collect()
    };
    for (release, option) in [
        ("7.7.2", "--experimental_downloader_config="),
        ("8.1.1", "--experimental_downloader_config="),
        ("8.2.0", "--downloader_config="),
        ("8.8.2", "--downloader_config="),
        ("9.3.2-homebrew", "--downloader_config="),
    ] {
        let mut cell = cell_without_bazel(release);
        assert_eq!(named(&cell), NOTHING, "{release}");
        cell.route_downloads(&rules);
        let twin = cell.twin();
        for cell in [&cell, &twin] {
            let file = &cell.scratch.downloads;
            assert_eq!(named(cell), [format!("{option}{}", file.display())]);
            let config = std::fs::read_to_string(file).expect("the downloader config");
            assert_eq!(config, format!("{}\nblock patch.example\n", rules[0]));
            assert!(!file.starts_with(&cell.scratch.workspace), "{release}");
        }
        assert_ne!(cell.scratch.downloads, twin.scratch.downloads, "{release}");
    }
}

/// Without a Bazel: the comparison of a run with the switch
/// ([`Cell::off_is_without_bazel`]) makes the checkout anew from its
/// regular files before each run, so it refuses a checkout that holds
/// what those files do not carry. A link, an empty directory and an
/// executable file are each named, and no run is started.
#[test]
fn a_checkout_its_files_do_not_make_anew_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let cell = cell_without_bazel("9.3.2");
    cell.write("MODULE.bazel", "");
    cell.write("dir/file", "x");
    assert_eq!(cell.not_made_by_its_files(), NOTHING);
    std::os::unix::fs::symlink("file", cell.path("dir/link")).expect("a link");
    std::fs::create_dir(cell.path("empty")).expect("a directory");
    cell.write("run.sh", "#!/bin/sh\n");
    let runs = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(cell.path("run.sh"), runs).expect("the permission bits");
    let odd = ["dir/link", "empty", "run.sh"];
    assert_eq!(cell.not_made_by_its_files(), odd);
    let compare = || cell.off_is_without_bazel("http://127.0.0.1:9", &["list"], &[], &[]);
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(compare));
    assert!(refused.is_err(), "it ran in a checkout it cannot make anew");
    // Nothing was made anew: the three are where they were.
    assert_eq!(cell.not_made_by_its_files(), odd);
    // Each one alone is enough.
    for (keep, gone) in [(0, [1, 2]), (1, [0, 2]), (2, [0, 1])] {
        let other = cell_without_bazel("9.3.2");
        other.write("dir/file", "x");
        std::os::unix::fs::symlink("file", other.path("dir/link")).expect("a link");
        std::fs::create_dir(other.path("empty")).expect("a directory");
        other.write("run.sh", "#!/bin/sh\n");
        let runs = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(other.path("run.sh"), runs).expect("the permission bits");
        for at in gone {
            let path = other.path(odd[at]);
            let removed = match path.is_dir() && !path.is_symlink() {
                true => std::fs::remove_dir(&path),
                false => std::fs::remove_file(&path),
            };
            removed.expect("remove it");
        }
        assert_eq!(other.not_made_by_its_files(), [odd[keep]]);
    }
}

/// Without a Bazel: a document is no file of the checkout it is about, nor
/// of a checkout made from it, which has documents of its own.
#[test]
fn a_document_is_no_file_of_the_checkout() {
    let cell = cell_without_bazel("9.3.2");
    cell.write("MODULE.bazel", "");
    let fresh = cell.unbuilt(&cell.tree());
    assert_eq!(changed(&cell.tree(), &fresh.tree()), NOTHING);
    let documents = [cell.document("one"), fresh.document("one")];
    assert_ne!(documents[0], documents[1]);
    for document in &documents {
        assert!(document.parent().is_some_and(Path::is_dir), "{document:?}");
        for copy in [&cell, &fresh] {
            assert!(!document.starts_with(&copy.scratch.workspace));
        }
    }
}

/// Without a Bazel: two documents are held to each other in every string
/// but the id, the times and the mark of `--no-verify`, so the two
/// spellings of an npm scope are two wordings; and two trees in every
/// byte but the `vendoredAt` of a marker.
#[test]
fn documents_and_markers_are_compared_but_for_their_ids_and_times() {
    let (escaped, plain) = ("pkg:npm/%40scope/name@1.0.0", "pkg:npm/@scope/name@1.0.0");
    let document = |n: u32, package: &str, impact: &str| {
        let time = format!("2026-01-0{n}T00:00:00Z");
        wording(json!({
            "@id": format!("urn:uuid:{n}"),
            "timestamp": time,
            "statements": [{
                "timestamp": time,
                "products": [{ "@id": PRODUCT, "subcomponents": [{ "@id": package }] }],
                "impact_statement": impact,
            }],
        }))
    };
    let patched = "Patched via Socket patch one (vendored)";
    let first = document(1, escaped, patched);
    let unchecked = format!("{patched}{NOT_VERIFIED_SUFFIX}");
    assert_eq!(document(2, escaped, &unchecked), first);
    assert_ne!(document(1, plain, patched), first);
    assert_ne!(document(1, escaped, "Patched via Socket patch two"), first);

    let tree = |file: &str, purl: &str, n: u32| {
        let marker = json!({ "purl": purl, "vendoredAt": format!("2026-01-0{n}T00:00:00Z") });
        undated(&Tree::from([(
            file.to_string(),
            marker.to_string().into_bytes(),
        )]))
    };
    let marker = format!(".socket/vendor/npm/one{MARKER}");
    let first = tree(&marker, escaped, 1);
    assert_eq!(changed(&first, &tree(&marker, escaped, 2)), NOTHING);
    assert_eq!(changed(&first, &tree(&marker, plain, 1)), [marker.as_str()]);
    // No other file is read for a time.
    let ledger = ".socket/vendor/state.json";
    let other = changed(&tree(ledger, escaped, 1), &tree(ledger, escaped, 2));
    assert_eq!(other, [ledger]);
}

/// Set in the copy of this test binary that the next test starts, which
/// then plays the shell of a developer.
const PLAYS_THE_SHELL: &str = "SOCKET_PATCH_BAZEL_E2E_PLAYS_THE_SHELL";

/// What such a shell has set that must not reach a Bazel child. Written
/// out, not read from [`REMOVED`] and [`REMOVED_PREFIXES`]: a name dropped
/// from either list, or from a scrub of [`EXTRAS`], fails the test.
fn settings_of_a_shell() -> Vec<String> {
    let names = [
        // `REMOVED`.
        "TEST_TMPDIR",
        "NETRC",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "CI",
        "GITHUB_ACTIONS",
        "COMPOSER",
        "GEM_HOME",
        "GEM_PATH",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        // (Also what `hermetic::command` itself sets for the socket-patch
        // binary: neither the shell's value nor that one reaches a child.)
        "MAVEN_ARGS",
        "REPIN",
        // One name under each of `REMOVED_PREFIXES`.
        "BAZELISK_SETTING",
        "COMPOSER_SETTING",
        "PIP_SETTING",
        "UV_SETTING",
        "CARGO_SETTING",
        // `Extra::Go`.
        "GOFLAGS",
        "GOWORK",
        "GOPATH",
        "GOMODCACHE",
        // `Extra::Bundle`.
        "BUNDLE_GEMFILE",
        "RUBYOPT",
        "RUBYLIB",
        // `Extra::Pnpm`.
        "npm_config_registry",
        "NPM_CONFIG_USERCONFIG",
        "PNPM_HOME",
        // `Extra::Venv`.
        "VIRTUAL_ENV",
    ];
    // The other direction: a name added to a list is added here too.
    for name in REMOVED {
        assert!(names.contains(name), "{name} is removed and not tested");
    }
    for prefix in REMOVED_PREFIXES {
        let tested = names.iter().any(|name| name.starts_with(prefix));
        assert!(tested, "{prefix}* is removed and not tested");
    }
    names.iter().map(|name| name.to_string()).collect()
}

/// A child of [`child`] sees none of the tool settings of the process that
/// spawns it. It keeps that process's proxy, and gets loopback beside the
/// hosts the process already reaches without one, under both names of the
/// list. The environment is one per process and the tests of this binary
/// share theirs, so the test starts the binary again with the settings,
/// and that copy looks at a child of its own.
#[test]
fn a_bazel_child_sees_no_tool_setting_of_the_shell() {
    const PROXY: &str = "http://proxy.example:3128";
    if var(PLAYS_THE_SHELL).is_none() {
        let mut copy = Command::new(std::env::current_exe().expect("the test binary"));
        let this = "harness::a_bazel_child_sees_no_tool_setting_of_the_shell";
        copy.args(["--exact", this, "--nocapture"])
            .env(PLAYS_THE_SHELL, "1")
            .envs(
                settings_of_a_shell()
                    .iter()
                    .map(|name| (name, "of-the-shell")),
            )
            .env("http_proxy", PROXY)
            .env("HTTPS_PROXY", PROXY)
            .env("no_proxy", "corp.example, 127.0.0.1")
            .env("NO_PROXY", "other.example");
        let out = copy.output().expect("start the test binary again");
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && said.contains("test result: ok. 1 passed"),
            "{said}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let scratch = Scratch::new(None);
    let out = child(OsStr::new("env"), &scratch).output().expect("env");
    let printed = String::from_utf8_lossy(&out.stdout);
    let seen: BTreeMap<&str, &str> = printed.lines().filter_map(|l| l.split_once('=')).collect();
    for name in settings_of_a_shell() {
        assert!(std::env::var_os(&name).is_some(), "{name} is not set here");
        assert!(!seen.contains_key(name.as_str()), "a child sees {name}");
    }
    assert_eq!(seen.get("GOENV"), Some(&"off"));
    assert_eq!(
        seen.get("HOME").map(Path::new),
        Some(scratch.home.as_path())
    );
    assert_eq!(seen.get("http_proxy"), Some(&PROXY));
    assert_eq!(seen.get("HTTPS_PROXY"), Some(&PROXY));
    let direct = "corp.example,127.0.0.1,other.example,localhost";
    assert_eq!(seen.get("no_proxy"), Some(&direct));
    assert_eq!(seen.get("NO_PROXY"), Some(&direct));
}
