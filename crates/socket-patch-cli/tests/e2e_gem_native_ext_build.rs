//! Agent-mode patches to a gem's C extension (#1996).
//!
//! Ruby loads the extension RubyGems compiled at install time, never the
//! `ext/**/*.c` beside it, so `apply` must rebuild the extension from the
//! patched sources (or refuse, writing nothing), `apply --check` / `vex`
//! must not attest patched sources over a stale build, and `rollback` must
//! put the original build back.
//!
//! The capstones build a tiny C-extension gem (`sp_native`, whose
//! `SpNative.value` the patch changes from 1 to 2) with the host's real
//! `gem`, install it into a Bundler-style `vendor/bundle/ruby/<abi>` home,
//! and run the real binary over it. They need ruby, its headers and a C
//! compiler: `#[ignore]`-gated, run by the pinned-Ruby CI leg, which sets
//! `SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1` so a missing toolchain fails
//! instead of skipping. The refusal tests lay a native gem down by hand
//! and need no Ruby.

use std::path::{Path, PathBuf};
use std::process::Command;

#[path = "common/mod.rs"]
mod common;
use common::{git_sha256, parse_json_envelope, write_blob, write_minimal_manifest, PatchEntry};

const PURL: &str = "pkg:gem/sp_native@1.0.0";
const UUID: &str = "19961996-1996-4996-8996-199619961996";
const FULL_NAME: &str = "sp_native-1.0.0";
const C_KEY: &str = "ext/sp_native/sp_native.c";

const EXTCONF: &str = "require \"mkmf\"\ncreate_makefile(\"sp_native/sp_native\")\n";
const LIB_RB: &str = "require \"sp_native/sp_native\"\n";
const GEMSPEC: &str = "Gem::Specification.new do |s|\n  s.name = \"sp_native\"\n  \
                       s.version = \"1.0.0\"\n  s.summary = \"t\"\n  s.authors = [\"t\"]\n  \
                       s.files = Dir[\"lib/**/*.rb\", \"ext/**/*.{c,rb}\"]\n  \
                       s.extensions = [\"ext/sp_native/extconf.rb\"]\nend\n";

fn c_source(value: u32) -> String {
    format!(
        "#include \"ruby.h\"\n\
         static VALUE sp_value(VALUE self) {{ return INT2NUM({value}); }}\n\
         void Init_sp_native(void) {{\n  \
         VALUE m = rb_define_module(\"SpNative\");\n  \
         rb_define_singleton_method(m, \"value\", sp_value, 0);\n}}\n"
    )
}

/// A source that does not compile.
fn broken_source() -> String {
    format!("{}this is not C\n", c_source(2))
}

fn required() -> bool {
    std::env::var("SOCKET_PATCH_BUNDLER_E2E_REQUIRED").is_ok_and(|v| v == "1")
}

fn tool_works(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The ruby ABI dir name (`3.4.0`), or `None` (skip) when ruby, gem or a C
/// compiler is missing. Panics instead under the CI gate.
fn toolchain() -> Option<String> {
    let have = tool_works("ruby", &["-v"])
        && tool_works("gem", &["--version"])
        && (tool_works("cc", &["--version"]) || tool_works("gcc", &["--version"]));
    let abi = have
        .then(|| {
            Command::new("ruby")
                .args(["-e", "print RbConfig::CONFIG['ruby_version']"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .flatten();
    if abi.is_none() {
        assert!(
            !required(),
            "SOCKET_PATCH_BUNDLER_E2E_REQUIRED=1 but ruby, gem or a C compiler is missing"
        );
        eprintln!("SKIP: ruby, gem or a C compiler is not available");
    }
    abi
}

/// A project with `sp_native` installed into `vendor/bundle/ruby/<abi>` by
/// the real `gem`, and the patch's manifest + blobs (`patched` is the
/// patched C source).
struct Fixture {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    home: PathBuf,
    gem_dir: PathBuf,
}

impl Fixture {
    fn new(abi: &str, patched: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("ext/sp_native")).unwrap();
        std::fs::create_dir_all(src.join("lib")).unwrap();
        std::fs::write(src.join("ext/sp_native/extconf.rb"), EXTCONF).unwrap();
        std::fs::write(src.join(C_KEY), c_source(1)).unwrap();
        std::fs::write(src.join("lib/sp_native.rb"), LIB_RB).unwrap();
        std::fs::write(src.join("sp_native.gemspec"), GEMSPEC).unwrap();
        let gem_home_scratch = tmp.path().join("gem-user-home");
        std::fs::create_dir_all(&gem_home_scratch).unwrap();
        let run = |cmd: &mut Command, what: &str| {
            let out = cmd
                .env("HOME", &gem_home_scratch)
                .output()
                .unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(
                out.status.success(),
                "{what} failed:\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(
            Command::new("gem")
                .args(["build", "sp_native.gemspec"])
                .current_dir(&src),
            "gem build",
        );
        let proj = tmp.path().join("proj");
        let home = proj.join("vendor/bundle/ruby").join(abi);
        std::fs::create_dir_all(&home).unwrap();
        run(
            Command::new("gem")
                .args(["install", "--local", "--no-document", "--install-dir"])
                .arg(&home)
                .arg(src.join("sp_native-1.0.0.gem")),
            "gem install",
        );
        std::fs::write(
            proj.join("Gemfile"),
            "source \"https://rubygems.org\"\ngem \"sp_native\"\n",
        )
        .unwrap();
        let socket = proj.join(".socket");
        let before = c_source(1);
        write_manifest(&socket, &before, patched);
        let gem_dir = home.join("gems").join(FULL_NAME);
        Fixture {
            _tmp: tmp,
            proj,
            home,
            gem_dir,
        }
    }

    /// `SpNative.value` as the installed gem's Ruby loads it.
    fn value(&self) -> String {
        let out = Command::new("ruby")
            .args(["-e", "require 'sp_native'; print SpNative.value"])
            .env("GEM_PATH", &self.home)
            .env_remove("GEM_HOME")
            .env_remove("RUBYOPT")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "loading sp_native failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn c_file(&self) -> String {
        std::fs::read_to_string(self.gem_dir.join(C_KEY)).unwrap()
    }

    fn marker(&self) -> PathBuf {
        self.gem_dir.join(".socket-patch-native-build.json")
    }

    fn backup(&self) -> PathBuf {
        self.gem_dir.join(".socket-patch-native-orig")
    }

    /// Run the CLI in the project. `gem install` left the gem's archive in
    /// the home's `cache/`, so no test here needs a gem registry: the one
    /// they are given answers nothing.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        common::run_with_env(&self.proj, args, &[("SOCKET_RUBYGEMS_URL", NO_REGISTRY)])
    }
}

fn write_manifest(socket: &Path, before: &str, after: &str) {
    let before_hash = git_sha256(before.as_bytes());
    let after_hash = git_sha256(after.as_bytes());
    write_minimal_manifest(
        socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: C_KEY,
            before_hash: &before_hash,
            after_hash: &after_hash,
        }],
    );
    write_blob(socket, &before_hash, before.as_bytes());
    write_blob(socket, &after_hash, after.as_bytes());
}

/// The detail of the envelope's `native_extension_not_rebuilt` warning:
/// what a run says of a record it wrote without a build of it.
fn not_rebuilt_warning(stdout: &str) -> String {
    let env = parse_json_envelope(stdout);
    env["warnings"]
        .as_array()
        .and_then(|warnings| {
            warnings
                .iter()
                .find(|w| w["code"] == "native_extension_not_rebuilt")
        })
        .and_then(|w| w["detail"].as_str())
        .unwrap_or_default()
        .to_string()
}

/// The event of a patch that is INCOMPLETE in an `apply --json` envelope,
/// after checking the shape the contract gives it: the run is a partial
/// failure, and the patch's event is `failed` with the
/// `native_extension_not_rebuilt` code (never a clean `applied`), beside
/// the warning of the same code and text.
fn incomplete_event(stdout: &str, purl: &str) -> serde_json::Value {
    let env = parse_json_envelope(stdout);
    assert_eq!(env["status"], "partialFailure", "{stdout}");
    let event = common::envelope::event_for(&env, purl).clone();
    assert_eq!(event["action"], "failed", "{stdout}");
    assert_eq!(
        event["errorCode"], "native_extension_not_rebuilt",
        "{stdout}"
    );
    let error = event["error"].as_str().unwrap_or_default();
    assert_eq!(
        not_rebuilt_warning(stdout),
        format!("{purl}: {error}"),
        "the warning says what the event says: {stdout}"
    );
    event
}

/// The paths an event lists in `files`, sorted.
fn event_files(event: &serde_json::Value) -> Vec<String> {
    let mut files: Vec<String> = event["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|file| file["path"].as_str().map(str::to_string))
        .collect();
    files.sort();
    files
}

/// `tree` with the file `rel` holding `bytes`.
fn tree_with(tree: &[(String, Vec<u8>)], rel: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = tree.iter().filter(|(r, _)| r != rel).cloned().collect();
    out.push((rel.to_string(), bytes.to_vec()));
    out.sort();
    out
}

fn event_action(stdout: &str) -> String {
    let env = parse_json_envelope(stdout);
    common::envelope::event_for(&env, PURL)["action"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn native_patch_is_rebuilt_attested_and_rolled_back() {
    let Some(abi) = toolchain() else {
        return;
    };
    let patched = c_source(2);
    let fx = Fixture::new(&abi, &patched);
    assert_eq!(fx.value(), "1");

    let (code, _, _) = fx.run(&["apply", "--check"]);
    assert_ne!(code, 0, "an unapplied patch must not check clean");

    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(fx.c_file(), patched);
    assert_eq!(fx.value(), "2", "Ruby must load the rebuilt extension");
    assert!(fx.marker().is_file(), "the build marker is recorded");
    assert!(fx.backup().is_dir(), "the install-time build is backed up");

    let (code, stdout, stderr) = fx.run(&["apply", "--check"]);
    assert_eq!(code, 0, "a rebuilt patch checks clean:\n{stdout}\n{stderr}");

    // Idempotent: nothing to write, nothing to build.
    let marker_before = std::fs::read(fx.marker()).unwrap();
    let (code, stdout, _) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(event_action(&stdout), "skipped", "{stdout}");
    assert_eq!(std::fs::read(fx.marker()).unwrap(), marker_before);

    let (code, stdout, stderr) = fx.run(&["rollback", "--json"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.c_file(), c_source(1));
    assert_eq!(fx.value(), "1", "the original build is back");
    assert!(!fx.marker().exists());
    assert!(!fx.backup().exists());

    // A release before #1996 patched the sources and never rebuilt: the
    // check refuses to attest it, and apply rebuilds it. (`rollback` drops
    // the record, so it is written again.)
    write_manifest(&fx.proj.join(".socket"), &c_source(1), &patched);
    std::fs::write(fx.gem_dir.join(C_KEY), &patched).unwrap();
    let (code, stdout, stderr) = fx.run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "stale build must not check clean:\n{stdout}");
    assert!(
        stdout.contains("native_extension_not_rebuilt")
            || stderr.contains("native_extension_not_rebuilt")
            || stdout.contains("not compiled into the extension"),
        "{stdout}\n{stderr}"
    );
    // A dry run says the rebuild is still to do, and does it not.
    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("apply would rebuild it"), "{stdout}");
    assert_eq!(fx.value(), "1");
    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extension_rebuilt"), "{stdout}");
    assert_eq!(fx.value(), "2");
}

#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn native_patch_that_does_not_build_is_put_back() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = Fixture::new(&abi, &broken_source());
    let ext_dir = fx.home.join("extensions");
    let built_before: Vec<_> = walk_files(&ext_dir);

    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extension_build_failed"), "{stdout}");
    assert!(
        stdout.contains("this is not C"),
        "the compiler error is shown: {stdout}"
    );
    assert_eq!(fx.c_file(), c_source(1), "the original source is back");
    assert_eq!(fx.value(), "1", "the original build is back");
    assert!(!fx.marker().exists());
    assert!(!fx.backup().exists());
    assert_eq!(walk_files(&ext_dir), built_before);
}

/// The installed gemspec is a Ruby program, and a committed `vendor/bundle`
/// lets the scanned repository supply it. It is read as text to decide
/// whether a record needs a rebuild and only loaded by the build itself,
/// after the record's files verified: never by a dry run, and never for a
/// record that does not match the installed copy.
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn the_installed_gemspec_is_not_evaluated_before_the_record_verifies() {
    let Some(abi) = toolchain() else {
        return;
    };
    let patched = c_source(2);
    let fx = Fixture::new(&abi, &patched);
    let spec = fx
        .home
        .join("specifications")
        .join(format!("{FULL_NAME}.gemspec"));
    let evaluated = fx.home.join("gemspec-was-evaluated");
    // The spec must stay the value of the file, and its stub lines first.
    let text = std::fs::read_to_string(&spec).unwrap();
    let planted = text.replacen(
        "Gem::Specification.new do |s|",
        &format!(
            "File.write({:?}, \"x\")\nGem::Specification.new do |s|",
            evaluated.display().to_string()
        ),
        1,
    );
    assert_ne!(planted, text, "the installed spec has the to_ruby shape");
    std::fs::write(&spec, planted).unwrap();

    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(!evaluated.exists(), "a dry run evaluated the gemspec");
    assert!(stdout.contains("apply would"), "{stdout}");
    assert_eq!(fx.c_file(), c_source(1));

    // A copy that matches neither side of the record.
    std::fs::write(fx.gem_dir.join(C_KEY), c_source(7)).unwrap();
    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        !evaluated.exists(),
        "the gemspec was evaluated for a record that does not verify"
    );
    std::fs::write(fx.gem_dir.join(C_KEY), c_source(1)).unwrap();

    // The extension is rebuilt from the source gem RubyGems left in the
    // home's `cache/`, with the gemspec that archive carries: the installed
    // one is not evaluated at all.
    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert!(
        !evaluated.exists(),
        "a rebuild from the source gem evaluated the installed gemspec"
    );
    assert_eq!(fx.value(), "2", "Ruby must load the rebuilt extension");
    // Reading the value loaded the gem, which is RubyGems evaluating its
    // gemspec: the trace of that is not the CLI's.
    std::fs::remove_file(&evaluated).unwrap();

    // Without that archive the copy's own tree is built, by RubyGems'
    // builder, which loads the installed gemspec: now, and only now.
    let (code, stdout, stderr) = fx.run(&["rollback", "--json"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert!(!evaluated.exists(), "rollback evaluated the gemspec");
    assert_eq!(fx.value(), "1");
    std::fs::remove_file(&evaluated).unwrap();
    std::fs::remove_file(fx.home.join("cache").join(format!("{FULL_NAME}.gem"))).unwrap();
    write_manifest(&fx.proj.join(".socket"), &c_source(1), &patched);
    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(!evaluated.exists(), "a dry run evaluated the gemspec");
    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert!(evaluated.exists(), "the in-place build loads the gemspec");
    assert_eq!(fx.value(), "2", "Ruby must load the rebuilt extension");
}

/// An `extconf.rb` that, like nokogiri's (which activates `mini_portile2`),
/// loads a helper gem installed beside the copy in the same home.
const EXTCONF_WITH_HELPER: &str = "gem \"sp_helper\"\nrequire \"sp_helper\"\n\
                                   require \"mkmf\"\ncreate_makefile(\"sp_native/sp_native\")\n";

/// Build the pure-Ruby `sp_helper` gem in `scratch` (outside the project)
/// and install it into `home`.
fn install_helper_gem(scratch: &Path, home: &Path) {
    let src = scratch.join("sp_helper-src");
    let user_home = scratch.join("gem-user-home");
    std::fs::create_dir_all(src.join("lib")).unwrap();
    std::fs::write(src.join("lib/sp_helper.rb"), "module SpHelper; end\n").unwrap();
    std::fs::write(
        src.join("sp_helper.gemspec"),
        "Gem::Specification.new do |s|\n  s.name = \"sp_helper\"\n  s.version = \"1.0.0\"\n  \
         s.summary = \"t\"\n  s.authors = [\"t\"]\n  s.files = [\"lib/sp_helper.rb\"]\nend\n",
    )
    .unwrap();
    for (args, dir) in [
        (vec!["build", "sp_helper.gemspec"], src.clone()),
        (
            vec![
                "install",
                "--local",
                "--no-document",
                "--install-dir",
                home.to_str().unwrap(),
                "sp_helper-1.0.0.gem",
            ],
            src.clone(),
        ),
    ] {
        let out = Command::new("gem")
            .args(&args)
            .current_dir(&dir)
            .env("HOME", &user_home)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "gem {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A crawl root spelled relative (`--cwd proj`, or the default `.`) used
/// to reach the build as a relative spec path and `GEM_PATH`, which Ruby
/// resolves from the project dir and `extconf.rb` from the ext dir: the
/// build could not load a gem from the copy's own home, so nokogiri
/// (`mini_portile2`) failed with `native_extension_build_failed`.
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn native_patch_builds_from_a_relative_crawl_root() {
    let Some(abi) = toolchain() else {
        return;
    };
    let patched = c_source(2);
    let fx = Fixture::new(&abi, &patched);
    install_helper_gem(fx._tmp.path(), &fx.home);
    let socket = fx.proj.join(".socket");
    let entries = [
        ("ext/sp_native/extconf.rb", EXTCONF, EXTCONF_WITH_HELPER),
        (C_KEY, &c_source(1) as &str, &patched as &str),
    ];
    let hashes: Vec<(String, String)> = entries
        .iter()
        .map(|(_, b, a)| (git_sha256(b.as_bytes()), git_sha256(a.as_bytes())))
        .collect();
    let files: Vec<PatchEntry<'_>> = entries
        .iter()
        .zip(&hashes)
        .map(|((key, _, _), (b, a))| PatchEntry {
            file_name: key,
            before_hash: b,
            after_hash: a,
        })
        .collect();
    // `rollback` drops the record and frees its blobs, so this runs twice.
    let record = || {
        write_minimal_manifest(&socket, PURL, UUID, &files);
        for ((_, b, a), (bh, ah)) in entries.iter().zip(&hashes) {
            write_blob(&socket, bh, b.as_bytes());
            write_blob(&socket, ah, a.as_bytes());
        }
    };
    record();

    // `--cwd proj` from the project's parent.
    let parent = fx.proj.parent().unwrap();
    let (code, stdout, stderr) = common::run(parent, &["apply", "--cwd", "proj", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(fx.value(), "2", "Ruby must load the rebuilt extension");

    let (code, stdout, stderr) = common::run(parent, &["rollback", "--cwd", "proj", "--json"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "1");

    // The default `.` crawl root, run from inside the project.
    record();
    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(fx.value(), "2", "Ruby must load the rebuilt extension");
    let (code, stdout, stderr) = fx.run(&["apply", "--check"]);
    assert_eq!(code, 0, "a rebuilt patch checks clean:\n{stdout}\n{stderr}");
    let (code, stdout, stderr) = fx.run(&["rollback", "--json"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "1", "the original build is back");
    assert!(!fx.marker().exists());
}

/// The paths that differ between two [`walk_files`] trees: `+` added, `-`
/// removed, `~` changed. A failed comparison prints these, not the bytes
/// of every shared object.
fn tree_diff(before: &[(String, Vec<u8>)], after: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, bytes) in before {
        match after.iter().find(|(p, _)| p == path) {
            None => out.push(format!("-{path}")),
            Some((_, now)) if now != bytes => out.push(format!("~{path}")),
            Some(_) => {}
        }
    }
    for (path, _) in after {
        if !before.iter().any(|(p, _)| p == path) {
            out.push(format!("+{path}"));
        }
    }
    out
}

/// Assert that the tree under `dir` holds exactly the files of `before`,
/// byte for byte.
fn assert_tree(dir: &Path, before: &[(String, Vec<u8>)], what: &str) {
    assert_eq!(
        tree_diff(before, &walk_files(dir)),
        Vec::<String>::new(),
        "{} differs {what}",
        dir.display()
    );
}

/// `(relative path, bytes)` of every file under `dir`.
fn walk_files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(dir).unwrap().display().to_string();
                out.push((rel, std::fs::read(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

// ── hermetic refusals (no Ruby needed) ────────────────────────────────

/// A hand-laid native gem: `ext/` source, the install-time build, and an
/// installed spec that does (or doesn't) declare extensions.
fn fake_native_gem(declares_extensions: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().to_path_buf();
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    let gem_dir = home.join("gems").join(FULL_NAME);
    std::fs::create_dir_all(gem_dir.join("ext/sp_native")).unwrap();
    std::fs::create_dir_all(gem_dir.join("lib/sp_native")).unwrap();
    std::fs::write(gem_dir.join(C_KEY), c_source(1)).unwrap();
    std::fs::write(gem_dir.join("lib/sp_native.rb"), LIB_RB).unwrap();
    std::fs::write(
        gem_dir.join("lib/sp_native/sp_native.so"),
        b"\x7fELF original",
    )
    .unwrap();
    let ext = home.join("extensions/x86_64-linux/3.4.0").join(FULL_NAME);
    std::fs::create_dir_all(ext.join("sp_native")).unwrap();
    std::fs::write(ext.join("sp_native/sp_native.so"), b"\x7fELF original").unwrap();
    std::fs::write(ext.join("gem.build_complete"), b"").unwrap();
    let extensions = if declares_extensions {
        "  s.extensions = [\"ext/sp_native/extconf.rb\".freeze]\n"
    } else {
        ""
    };
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join("specifications")
            .join(format!("{FULL_NAME}.gemspec")),
        format!(
            "Gem::Specification.new do |s|\n  s.name = \"sp_native\".freeze\n  \
             s.version = \"1.0.0\"\n{extensions}end\n"
        ),
    )
    .unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\ngem \"sp_native\"\n",
    )
    .unwrap();
    (tmp, proj, gem_dir)
}

/// A gem registry that answers nothing (nothing listens on the discard
/// port): the stand-in for rubygems.org in every test that serves none, so
/// no test reaches the network.
const NO_REGISTRY: &str = "http://127.0.0.1:9";

/// Run the CLI with a `PATH` holding no `ruby`.
fn run_without_ruby(proj: &Path, args: &[&str]) -> (i32, String, String) {
    let empty = proj.join(".empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    let path = empty.display().to_string();
    common::run_with_env(
        proj,
        args,
        &[
            ("PATH", path.as_str()),
            ("SOCKET_RUBYGEMS_URL", NO_REGISTRY),
        ],
    )
}

/// A stand-in `ruby`, alone on the `PATH` the CLI is run with: a shell
/// script that says it builds extensions into [`fake_native_gem`]'s
/// `extensions/x86_64-linux/3.4.0` and "builds" one by writing a new shared
/// object and its `lib/` copy. Each run appends its mode to `<state>/calls`
/// and writes the environment it saw to `<state>/env.<mode>`.
///
/// After [`FakeRuby::hang_builds`] a build never finishes instead: it
/// starts a "compiler" (a `sleep` of its own), records both pids and waits,
/// like a real build caught mid-compile.
#[cfg(unix)]
struct FakeRuby {
    _tmp: tempfile::TempDir,
    bin: PathBuf,
    state: PathBuf,
}

#[cfg(unix)]
impl FakeRuby {
    fn new() -> FakeRuby {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&state).unwrap();
        // argv: -e <program> extensions_dir <gem home> [<platform>]
        //       -e <program> build <gemspec> <extension dir> <require path>
        //       -e <program> unpack <archive> <stage home> <full name>
        //       -e <program> missing_deps <staged gemspec>
        //       -e <program> stage_build <staged gemspec> <stage home> <home> [<full name>]
        let script = format!(
            r#"#!/bin/sh
PATH=/usr/bin:/bin
state='{state}'
mode="$3"
echo "$mode" >> "$state/calls"
env > "$state/env.$mode"
hang() {{
  echo $$ > "$state/build.pid"
  sleep 600 &
  echo $! > "$state/compiler.pid"
  : > "$state/building"
  wait
  exit 1
}}
# What RubyGems prints when a gem's extconf.rb gives up on a missing
# library, building into the extension dir $1: the cause, mkmf's list of
# configuration options, and where it left mkmf.log.
extconf_failure() {{
  echo "ERROR: Failed to build gem native extension."
  echo
  echo "checking for libsp.h... no"
  echo "Can't find the 'libsp.h header"
  echo "Please install libsp like so:"
  echo "  sudo apt install libsp-dev"
  echo "*** extconf.rb failed ***"
  echo "Could not create Makefile due to some reason, probably lack of necessary"
  echo "libraries and/or headers.  Check the mkmf.log file for more details.  You may"
  echo "need configuration options."
  echo
  echo "Provided configuration options:"
  i=0
  while [ $i -lt 40 ]; do
    printf '\t--with-opt-%s\n' $i
    i=$((i+1))
  done
  echo
  echo "To see why this extension failed to compile, please check the mkmf.log which can be found here:"
  echo
  echo "  $1/mkmf.log"
  echo
  echo "extconf failed, exit code 1"
  echo
  echo "Gem files will remain installed in /somewhere for inspection."
  echo "Results logged to $1/gem_make.out"
}}
# The Ruby this stands in for: 3.4, or 3.3 once the test says so.
version=3.4.1
abi=3.4.0
if [ -e "$state/ruby-3.3" ]; then
  version=3.3.6
  abi=3.3.0
fi
case "$mode" in
extensions_dir)
  printf 'sp_extensions_dir\t%s\n' "$4/extensions/x86_64-linux/$abi"
  runs=''
  if [ -n "$5" ]; then
    runs=yes
    [ -e "$state/other-platform" ] && runs=no
    printf '%s\n' "$5" > "$state/platform-asked"
  fi
  printf 'sp_ruby\t%s\t3.6.2\tso\tx86_64-linux\t%s\n' "$version" "$runs"
  ;;
unpack)
  # The "archive" is the tree the test laid in <state>/source.
  if [ ! -d "$state/source" ]; then
    echo "the archive holds other-9.9.9, not $6" >&2
    exit 1
  fi
  mkdir -p "$5/gems/$6" "$5/specifications"
  cp -R "$state/source/." "$5/gems/$6/"
  : > "$5/specifications/$6.gemspec"
  printf 'sp_unpacked\t%s\tlib\n' "$6"
  ;;
missing_deps)
  echo sp_deps_checked
  ;;
stage_build)
  full=$(basename "$4" .gemspec)
  ext="$5/extensions/x86_64-linux/$abi/$full"
  # The installed copy whose recorded build arguments the build is given.
  printf '%s\n' "$7" > "$state/stage-build-args-of"
  [ -e "$state/hang" ] && hang
  if [ -e "$state/fail-extconf" ]; then
    extconf_failure "$ext" >&2
    exit 1
  fi
  if [ -e "$state/fail-stage-build" ]; then
    echo "sp_native.c:7: error: this is not C (in the stage)" >&2
    exit 1
  fi
  # A gem whose extension script downloads the binary it runs compiles
  # nothing: it reads its sources (the script is one of them), leaves a
  # finished, empty extension dir, and puts the binary where Ruby does
  # not load from.
  if [ -e "$state/builds-nothing" ]; then
    cat "$5/gems/$full/ext/sp_native/sp_native.c" > /dev/null 2>&1
    mkdir -p "$ext" "$5/gems/$full/buildout"
    printf 'a downloaded agent' > "$5/gems/$full/buildout/agent"
    : > "$ext/gem.build_complete"
    printf 'sp_built\t%s\n' "$ext"
    exit 0
  fi
  mkdir -p "$ext/sp_native" "$5/gems/$full/lib/sp_native"
  # A build that applies the patch files the gem packs reads them; one set
  # up to link the system's copy of that library never opens them.
  if [ -e "$state/applies-patches" ]; then
    find "$5/gems/$full/patches" -type f -exec cat {{}} + > /dev/null 2>&1
  fi
  # What was "compiled": the staged source, so a test can tell the build
  # came from the patched tree.
  {{ printf 'rebuilt from: '; cat "$5/gems/$full/ext/sp_native/sp_native.c"; }} > "$ext/sp_native/sp_native.so"
  [ -e "$state/ruby-3.3" ] && printf ' (by Ruby 3.3)' >> "$ext/sp_native/sp_native.so"
  cp "$ext/sp_native/sp_native.so" "$5/gems/$full/lib/sp_native/sp_native.so"
  : > "$ext/gem.build_complete"
  printf 'sp_built\t%s\n' "$ext"
  ;;
build)
  home=$(dirname "$(dirname "$4")")
  full=$(basename "$4" .gemspec)
  ext="$5"
  lib="$home/gems/$full/$6"
  if [ -e "$state/hang" ]; then
    if [ -e "$state/hang-half-built" ]; then
      mkdir -p "$ext/sp_native"
      printf 'half-built' > "$ext/sp_native/sp_native.so"
      printf 'half-built' > "$lib/sp_native/sp_native.so"
    fi
    echo $$ > "$state/build.pid"
    sleep 600 &
    echo $! > "$state/compiler.pid"
    : > "$state/building"
    wait
    exit 1
  fi
  if [ -e "$state/fail-extconf" ]; then
    extconf_failure "$ext" >&2
    exit 1
  fi
  if [ -e "$state/fail-build" ]; then
    echo "sp_native.c:7: error: this is not C (in place)" >&2
    exit 1
  fi
  mkdir -p "$ext/sp_native" "$lib/sp_native"
  # A compiler reads what it compiles.
  cat "$home/gems/$full/ext/sp_native/sp_native.c" > /dev/null 2>&1
  printf 'rebuilt' > "$ext/sp_native/sp_native.so"
  cp "$ext/sp_native/sp_native.so" "$lib/sp_native/sp_native.so"
  : > "$ext/gem.build_complete"
  ;;
*)
  echo "fake ruby: unexpected mode $mode" >&2
  exit 1
  ;;
esac
"#,
            state = state.display()
        );
        let ruby = bin.join("ruby");
        std::fs::write(&ruby, script).unwrap();
        std::fs::set_permissions(&ruby, std::fs::Permissions::from_mode(0o755)).unwrap();
        FakeRuby {
            _tmp: tmp,
            bin,
            state,
        }
    }

    /// Run the CLI in `proj` with this Ruby as the only program on `PATH`.
    /// The gem registry is one that answers nothing ([`NO_REGISTRY`]): a
    /// copy whose source gem is not in its home's `cache/` has none.
    fn run(&self, proj: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
        let path = self.bin.display().to_string();
        let mut all = vec![
            ("PATH", path.as_str()),
            ("SOCKET_RUBYGEMS_URL", NO_REGISTRY),
        ];
        all.extend_from_slice(env);
        common::run_with_env(proj, args, &all)
    }

    /// The tree this Ruby "unpacks" a source gem into: the files of
    /// `sp_native-1.0.0.gem`, with `c` as its C source.
    fn serve_source_gem(&self, c: &str) {
        let source = self.state.join("source");
        std::fs::create_dir_all(source.join("ext/sp_native")).unwrap();
        std::fs::create_dir_all(source.join("lib")).unwrap();
        std::fs::create_dir_all(source.join("patches")).unwrap();
        std::fs::write(source.join(C_KEY), c).unwrap();
        std::fs::write(source.join("lib/sp_native.rb"), LIB_RB).unwrap();
        std::fs::write(source.join("patches/0001-base.patch"), "base\n").unwrap();
    }

    /// Make every later build fail, staged or in place, as a compile error
    /// does.
    fn fail_builds(&self) {
        self.fail_staged_builds();
        std::fs::write(self.state.join("fail-build"), b"").unwrap();
    }

    /// Make every later build fail, staged or in place, the way a gem's
    /// `extconf.rb` does when a library it builds against is missing.
    fn fail_extconf(&self) {
        std::fs::write(self.state.join("fail-extconf"), b"").unwrap();
    }

    /// From now on a staged build applies the patch files the gem packs,
    /// as the build of a gem that compiles its packed library does.
    fn apply_patch_files(&self) {
        std::fs::write(self.state.join("applies-patches"), b"").unwrap();
    }

    /// From now on a staged build compiles nothing, as the build of a gem
    /// whose extension script downloads the binary it runs.
    fn build_nothing(&self) {
        std::fs::write(self.state.join("builds-nothing"), b"").unwrap();
    }

    /// Stand in for Ruby 3.3 from now on (3.4 until then).
    fn become_ruby_33(&self) {
        std::fs::write(self.state.join("ruby-3.3"), b"").unwrap();
    }

    /// Make every later build in a stage fail, and none in place.
    fn fail_staged_builds(&self) {
        std::fs::write(self.state.join("fail-stage-build"), b"").unwrap();
    }

    /// The modes this Ruby was run in, in order.
    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.state.join("calls"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The environment the `mode` run saw, as `env` printed it.
    fn env_seen(&self, mode: &str) -> String {
        std::fs::read_to_string(self.state.join(format!("env.{mode}"))).unwrap()
    }

    /// The installed copy whose recorded build arguments the last staged
    /// build was given; empty when it was given none.
    fn stage_build_args_of(&self) -> String {
        std::fs::read_to_string(self.state.join("stage-build-args-of"))
            .unwrap()
            .trim_end()
            .to_string()
    }

    /// Make every later build hang. With `half_built` it first leaves a
    /// partial extension dir and a replaced `lib/` copy, as a build
    /// interrupted late does; without, it has written nothing yet.
    fn hang_builds(&self, half_built: bool) {
        std::fs::write(self.state.join("hang"), b"").unwrap();
        if half_built {
            std::fs::write(self.state.join("hang-half-built"), b"").unwrap();
        }
    }

    /// Let later builds finish again.
    fn finish_builds(&self) {
        for flag in ["hang", "hang-half-built", "building"] {
            let _ = std::fs::remove_file(self.state.join(flag));
        }
    }

    /// Start the CLI in `proj` (this Ruby alone on `PATH`) and wait until
    /// its build hangs. Returns the CLI and the build's process group.
    fn spawn_until_building(
        &self,
        proj: &Path,
        args: &[&str],
    ) -> (std::process::Child, BuildGroup) {
        use std::time::{Duration, Instant};
        let mut cmd = common::hermetic_command(&common::binary());
        common::jvm_env::isolate_cli(&mut cmd);
        cmd.args(args)
            .current_dir(proj)
            .env("PATH", &self.bin)
            .env("SOCKET_RUBYGEMS_URL", NO_REGISTRY)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = cmd.spawn().expect("spawn socket-patch");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.state.join("building").exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("the CLI exited ({status}) before its build started");
            }
            assert!(Instant::now() < deadline, "the build never started");
            std::thread::sleep(Duration::from_millis(20));
        }
        let pid = |file: &str| -> i32 {
            std::fs::read_to_string(self.state.join(file))
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        let group = BuildGroup {
            leader: pid("build.pid"),
            compiler: pid("compiler.pid"),
        };
        (child, group)
    }
}

/// The stand-in build's processes: `ruby` leads its own process group and
/// the "compiler" it started is in it. Dropping this kills whatever is
/// left, so a failing test leaves no `sleep` behind.
#[cfg(unix)]
struct BuildGroup {
    leader: i32,
    compiler: i32,
}

#[cfg(unix)]
impl BuildGroup {
    /// Whether any process of the build is still there. Polls briefly: a
    /// killed process is a zombie until its (new) parent reaps it.
    fn outlives_the_cli(&self) -> bool {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            // SAFETY: signal 0 only checks for the group and the pid.
            let alive =
                unsafe { libc::kill(-self.leader, 0) == 0 || libc::kill(self.compiler, 0) == 0 };
            if !alive || Instant::now() >= deadline {
                return alive;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
impl Drop for BuildGroup {
    fn drop(&mut self) {
        // SAFETY: SIGKILL to the process group this test's CLI started.
        unsafe {
            libc::kill(-self.leader, libc::SIGKILL);
        }
    }
}

/// The Ruby that rebuilds an extension runs the gem's own build scripts and
/// the compiler: none of that is handed the Socket token the run was given,
/// while a package manager's own registry auth still reaches it.
#[cfg(unix)]
#[test]
fn the_rebuild_does_not_hand_the_socket_token_to_ruby() {
    const SECRET: &str = "sktsec_e2e_child_env_marker";
    let (_tmp, proj, _gem_dir) = fake_native_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();

    let (code, stdout, stderr) = ruby.run(
        &proj,
        &["apply", "--json", "--offline"],
        &[
            ("SOCKET_API_TOKEN", SECRET),
            ("SOCKET_CLI_API_TOKEN", SECRET),
            ("SOCKET_SECURITY_API_TOKEN", SECRET),
            ("NPM_TOKEN", "registry-auth"),
        ],
    );
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    let calls = ruby.calls();
    assert_eq!(calls.last().map(String::as_str), Some("build"), "{calls:?}");
    for mode in &calls {
        let seen = ruby.env_seen(mode);
        assert!(
            !seen.contains(SECRET),
            "`ruby` ({mode}) was handed the Socket token:\n{seen}"
        );
        for gone in [
            "SOCKET_API_TOKEN=",
            "SOCKET_CLI_API_TOKEN=",
            "SOCKET_SECURITY_API_TOKEN=",
            "SOCKET_OFFLINE=",
        ] {
            assert!(
                !seen.lines().any(|line| line.starts_with(gone)),
                "`ruby` ({mode}) inherited {gone}:\n{seen}"
            );
        }
        assert!(
            seen.lines().any(|line| line == "NPM_TOKEN=registry-auth"),
            "`ruby` ({mode}) lost the registry auth:\n{seen}"
        );
    }
}

/// What an interrupted rebuild is followed by.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum Next {
    Apply,
    Rollback,
}

/// Ctrl-C or a CI cancel (SIGTERM) during a native rebuild: the build runs
/// in its own process group, so nothing but the CLI can end it. The build
/// is gone by the time the CLI is, the lock is not left behind, and the
/// copy stays one the next run puts right: `apply` moves the parked
/// install-time build back and completes the rebuild, `rollback` restores
/// the original sources and build. That holds whether the interrupt lands
/// before the build wrote anything (the extension dir does not exist) or
/// with the extension dir and a `lib/` copy half replaced.
#[cfg(unix)]
#[test]
fn an_interrupted_rebuild_is_ended_with_the_cli_and_the_next_run_recovers() {
    use std::os::unix::process::ExitStatusExt;
    const ORIGINAL: &[u8] = b"\x7fELF original";

    for (signal, half_built, next) in [
        (libc::SIGTERM, true, Next::Apply),
        (libc::SIGINT, false, Next::Apply),
        (libc::SIGTERM, true, Next::Rollback),
        (libc::SIGINT, false, Next::Rollback),
    ] {
        let case = format!("signal {signal}, half built {half_built}, then {next:?}");
        let (_tmp, proj, gem_dir) = fake_native_gem(true);
        write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
        let ext_root = proj.join("vendor/bundle/ruby/3.4.0/extensions/x86_64-linux/3.4.0");
        let ext = ext_root.join(FULL_NAME);
        let parked = ext_root.join(format!(".{FULL_NAME}.socket-patch-old"));
        let ext_so = ext.join("sp_native/sp_native.so");
        let lib_so = gem_dir.join("lib/sp_native/sp_native.so");
        let lock = proj.join(".socket/apply.lock");
        let ruby = FakeRuby::new();
        ruby.hang_builds(half_built);

        let (mut cli, build) = ruby.spawn_until_building(&proj, &["apply", "--json"]);
        assert!(
            lock.is_file(),
            "{case}: the rebuilding apply holds the lock"
        );
        assert!(parked.is_dir(), "{case}: the install-time build is parked");
        // SAFETY: plain kill(2) on our own child's pid.
        assert_eq!(unsafe { libc::kill(cli.id() as libc::pid_t, signal) }, 0);
        let status = cli.wait().unwrap();
        assert_eq!(status.signal(), Some(signal), "{case}: got {status}");
        assert!(
            !build.outlives_the_cli(),
            "{case}: the build kept running after the interrupted CLI was gone"
        );
        assert!(!lock.exists(), "{case}: apply.lock was left behind");

        ruby.finish_builds();
        match next {
            Next::Apply => {
                let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json"], &[]);
                assert_eq!(
                    code, 0,
                    "{case}: apply after the interrupt:\n{stdout}\n{stderr}"
                );
                assert_eq!(std::fs::read(&ext_so).unwrap(), b"rebuilt", "{case}");
                assert_eq!(std::fs::read(&lib_so).unwrap(), b"rebuilt", "{case}");
                assert!(ext.join("gem.build_complete").is_file(), "{case}");
                assert!(
                    gem_dir.join(".socket-patch-native-build.json").is_file(),
                    "{case}: the completed build is recorded"
                );
                assert!(!parked.exists(), "{case}: the parked build is gone");
                let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
                assert_eq!(code, 0, "{case}: {stdout}\n{stderr}");
                // And the install-time build is still what rollback restores.
                let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json"], &[]);
                assert_eq!(code, 0, "{case}: rollback:\n{stdout}\n{stderr}");
            }
            Next::Rollback => {
                let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json"], &[]);
                assert_eq!(
                    code, 0,
                    "{case}: rollback after the interrupt:\n{stdout}\n{stderr}"
                );
            }
        }
        assert_eq!(std::fs::read(&ext_so).unwrap(), ORIGINAL, "{case}");
        assert_eq!(std::fs::read(&lib_so).unwrap(), ORIGINAL, "{case}");
        assert!(ext.join("gem.build_complete").is_file(), "{case}");
        assert_eq!(
            std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
            c_source(1),
            "{case}"
        );
        for leftover in [
            parked.clone(),
            gem_dir.join(".socket-patch-native-build.json"),
            gem_dir.join(".socket-patch-native-orig"),
        ] {
            assert!(!leftover.exists(), "{case}: {} is left", leftover.display());
        }
    }
}

/// A dry run starts no Ruby at all: it verifies the record against the
/// installed copy, says the extension would be rebuilt, and changes nothing.
#[cfg(unix)]
#[test]
fn a_dry_run_starts_no_ruby_and_reports_the_rebuild() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();
    let tree_before = walk_files(&proj.join("vendor"));

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--dry-run"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(ruby.calls(), Vec::<String>::new(), "a dry run ran Ruby");
    assert!(
        stdout.contains("native_extension_rebuilt") && stdout.contains("apply would"),
        "the dry run must say a rebuild is pending: {stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(1)
    );
    assert_eq!(walk_files(&proj.join("vendor")), tree_before);
}

/// No Ruby runs for a record whose files do not verify against the
/// installed copy: until they match, nothing says this is the package the
/// patch is for.
#[cfg(unix)]
#[test]
fn ruby_does_not_run_for_a_record_that_does_not_verify() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    // Neither the record's beforeHash nor its afterHash.
    std::fs::write(gem_dir.join(C_KEY), c_source(7)).unwrap();
    let ruby = FakeRuby::new();
    let tree_before = walk_files(&proj.join("vendor"));

    for args in [&["apply", "--json"][..], &["apply", "--json", "--dry-run"]] {
        let (code, stdout, stderr) = ruby.run(&proj, args, &[]);
        assert_eq!(code, 1, "{args:?}: {stdout}\n{stderr}");
        assert_eq!(event_action(&stdout), "failed", "{args:?}: {stdout}");
        assert_eq!(
            ruby.calls(),
            Vec::<String>::new(),
            "{args:?}: Ruby ran before the record verified"
        );
        assert_eq!(walk_files(&proj.join("vendor")), tree_before, "{args:?}");
    }
}

/// A real run asks the host Ruby where it builds extensions (a question
/// that loads nothing of the gem), then builds: the installed gemspec is
/// only loaded by the build itself.
#[cfg(unix)]
#[test]
fn a_real_run_asks_ruby_for_its_extension_dir_then_builds() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(ruby.calls(), ["extensions_dir", "build"]);
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(2)
    );
    assert_eq!(
        std::fs::read(gem_dir.join("lib/sp_native/sp_native.so")).unwrap(),
        b"rebuilt"
    );
    assert!(gem_dir.join(".socket-patch-native-build.json").is_file());
    assert!(gem_dir.join(".socket-patch-native-orig").is_dir());

    // Built from these sources: nothing more to run.
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(ruby.calls(), ["extensions_dir", "build"]);
}

#[test]
fn native_patch_without_a_ruby_is_refused_and_writes_nothing() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));

    let (code, stdout, stderr) = run_without_ruby(&proj, &["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let env = parse_json_envelope(&stdout);
    let event = common::envelope::event_for(&env, PURL);
    assert_eq!(event["action"], "failed", "{stdout}");
    assert!(
        event["error"]
            .as_str()
            .is_some_and(|e| e.starts_with("native_extensions_unsupported:")),
        "{stdout}"
    );
    assert!(stdout.contains("no `ruby` was found"), "{stdout}");
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(1)
    );
    assert!(!gem_dir.join(".socket-patch-native-build.json").exists());
    assert!(!gem_dir.join(".socket-patch-native-orig").exists());

    // Dry run reports the same refusal.
    let (code, stdout, _) = run_without_ruby(&proj, &["apply", "--json", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}");
    assert!(stdout.contains("native_extensions_unsupported"), "{stdout}");
}

#[test]
fn native_patch_to_a_gem_without_extensions_is_refused() {
    let (_tmp, proj, gem_dir) = fake_native_gem(false);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));

    let (code, stdout, stderr) = common::run(&proj, &["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extensions_unsupported"), "{stdout}");
    assert!(stdout.contains("builds no extension"), "{stdout}");
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(1)
    );
}

#[test]
fn ruby_only_patch_to_a_native_gem_needs_no_ruby() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    let before = LIB_RB;
    let after = "require \"sp_native/sp_native\"\n# patched\n";
    let (bh, ah) = (git_sha256(before.as_bytes()), git_sha256(after.as_bytes()));
    let socket = proj.join(".socket");
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "lib/sp_native.rb",
            before_hash: &bh,
            after_hash: &ah,
        }],
    );
    write_blob(&socket, &ah, after.as_bytes());

    let (code, stdout, stderr) = run_without_ruby(&proj, &["apply", "--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/sp_native.rb")).unwrap(),
        after
    );
}

#[test]
fn patched_sources_over_the_install_time_build_do_not_check_clean() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    // What a release before #1996 left: the source patched, the build not.
    std::fs::write(gem_dir.join(C_KEY), c_source(2)).unwrap();

    let (code, stdout, stderr) = run_without_ruby(&proj, &["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("native_extension_not_rebuilt")
            || stdout.contains("not compiled into the extension"),
        "{stdout}\n{stderr}"
    );
}

/// `--no-gem-native-rebuild` / `SOCKET_NO_GEM_NATIVE_REBUILD` (a caller
/// that compiles the extension itself, such as the patches evaluation
/// harness): the sources are written with no Ruby involved, the run
/// succeeds with a `native_extension_not_rebuilt` warning, and nothing of
/// socket-patch's build is left behind.
#[test]
fn opted_out_native_patch_writes_sources_without_a_build() {
    for opt_out in [
        &["apply", "--json", "--no-gem-native-rebuild"][..],
        &["apply", "--json"][..],
    ] {
        let (_tmp, proj, gem_dir) = fake_native_gem(true);
        write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
        let empty = proj.join(".empty-path");
        std::fs::create_dir_all(&empty).unwrap();
        let path = empty.display().to_string();
        let mut env = vec![("PATH", path.as_str())];
        if opt_out.len() == 2 {
            env.push(("SOCKET_NO_GEM_NATIVE_REBUILD", "1"));
        }
        let (code, stdout, stderr) = common::run_with_env(&proj, opt_out, &env);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        assert_eq!(event_action(&stdout), "applied", "{stdout}");
        assert!(stdout.contains("native_extension_not_rebuilt"), "{stdout}");
        assert_eq!(
            std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
            c_source(2)
        );
        assert!(!gem_dir.join(".socket-patch-native-build.json").exists());
        assert!(!gem_dir.join(".socket-patch-native-orig").exists());
        // The build Ruby loads is still the old one: no attestation.
        let (code, stdout, _) = run_without_ruby(&proj, &["apply", "--check", "--json"]);
        assert_ne!(code, 0, "{stdout}");

        // A dry run writes nothing, and says what apply would do.
        let (_tmp, proj, gem_dir) = fake_native_gem(true);
        write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
        let dry: Vec<&str> = opt_out.iter().copied().chain(["--dry-run"]).collect();
        let (code, stdout, stderr) = common::run_with_env(&proj, &dry, &env);
        assert_eq!(code, 0, "{stdout}\n{stderr}");
        let warning = not_rebuilt_warning(&stdout);
        assert!(
            warning.contains("dry run")
                && warning.contains("apply would write them without rebuilding the extension")
                && !warning.contains(", written "),
            "{warning}"
        );
        assert_eq!(
            std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
            c_source(1)
        );
    }
}

// ── the opt-out through `scan` / `get --mode agent` (#2069) ───────────

#[cfg(unix)]
const ORG: &str = "test-org";

/// A patch API that serves the `sp_native` patch (1 → 2) to `scan`'s
/// discovery and to the record download of `scan` and `get`.
#[cfg(unix)]
async fn mount_native_patch_api(mock: &wiremock::MockServer) {
    use base64::Engine;
    use serde_json::json;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, ResponseTemplate};

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "sp_native",
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.*sp_native(%40|@)1\\.0\\.0$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "sp_native", "license": "MIT", "tier": "free",
                "vulnerabilities": {},
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    let after = c_source(2);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
            "files": { C_KEY: {
                "beforeHash": git_sha256(c_source(1).as_bytes()),
                "afterHash": git_sha256(after.as_bytes()),
                "blobContent": base64::engine::general_purpose::STANDARD.encode(&after),
            }},
            "vulnerabilities": {},
            "description": "sp_native", "license": "MIT", "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// The opt-out reaches the apply that `scan --mode agent` and
/// `get --mode agent` run after they record the patch, as a flag and as
/// `SOCKET_NO_GEM_NATIVE_REBUILD`: the sources are written, no Ruby
/// starts, the run warns `native_extension_not_rebuilt`, and `apply
/// --check` does not attest the patch. The first case is the control: the
/// same `scan` without the opt-out does build.
#[cfg(unix)]
#[tokio::test]
async fn the_opt_out_reaches_the_apply_that_scan_and_get_run() {
    let mock = wiremock::MockServer::start().await;
    mount_native_patch_api(&mock).await;
    let uri = mock.uri();
    let api = ["--api-url", &uri, "--api-token", "fake-token", "--org", ORG];
    let scan = ["scan", "--mode", "agent", "--yes", "--json"];
    let scan_human = ["scan", "--mode", "agent", "--yes"];
    // By purl: `get <uuid>` hands its own flags to the apply and never
    // went through the engine that dropped this one.
    let get = ["get", PURL, "--mode", "agent", "--yes", "--json"];
    let flag = ["--no-gem-native-rebuild"];
    let env = [("SOCKET_NO_GEM_NATIVE_REBUILD", "1")];
    let (no_flag, no_env) = (&[][..], &[][..]);
    // (name, command, extra flags, env)
    let cases = [
        ("scan, no opt-out", &scan[..], no_flag, no_env),
        ("scan, flag", &scan, &flag[..], no_env),
        ("scan, env", &scan, no_flag, &env[..]),
        ("scan, flag, human output", &scan_human, &flag, no_env),
        ("get, flag", &get, &flag, no_env),
        ("get, env", &get, no_flag, &env),
    ];
    for (case, command, extra, env) in cases {
        let opted_out = !extra.is_empty() || !env.is_empty();
        let (_tmp, proj, gem_dir) = fake_native_gem(true);
        let ruby = FakeRuby::new();
        let args = [command, extra, &api[..]].concat();
        let (code, stdout, stderr) = ruby.run(&proj, &args, env);
        assert_eq!(code, 0, "{case}:\n{stdout}\n{stderr}");
        assert_eq!(
            std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
            c_source(2),
            "{case}: the patched source was not written\n{stdout}\n{stderr}"
        );
        let built = std::fs::read(gem_dir.join("lib/sp_native/sp_native.so")).unwrap();
        let marker = gem_dir.join(".socket-patch-native-build.json");
        let backup = gem_dir.join(".socket-patch-native-orig");
        let (check, check_out, _) = ruby.run(&proj, &["apply", "--check", "--json"], &[]);
        if !opted_out {
            assert_eq!(ruby.calls(), ["extensions_dir", "build"], "{case}");
            assert_eq!(built, b"rebuilt", "{case}");
            assert!(marker.is_file(), "{case}");
            assert_eq!(check, 0, "{case}: {check_out}");
            continue;
        }
        assert_eq!(
            ruby.calls(),
            Vec::<String>::new(),
            "{case}: Ruby ran despite the opt-out\n{stdout}\n{stderr}"
        );
        assert_eq!(built, b"\x7fELF original", "{case}: the build was replaced");
        assert!(!marker.exists(), "{case}: a build marker was written");
        assert!(!backup.exists(), "{case}: a build backup was written");
        // JSON names the code; the human line names the flag.
        let warned = if command.contains(&"--json") {
            stdout.contains("native_extension_not_rebuilt")
        } else {
            stderr.contains("without rebuilding the extension (--no-gem-native-rebuild)")
        };
        assert!(warned, "{case}: no warning\n{stdout}\n{stderr}");
        // The build Ruby loads is still the old one: no attestation.
        assert_ne!(check, 0, "{case}: {check_out}");
        assert!(
            check_out.contains("native_extension_not_rebuilt"),
            "{case}: {check_out}"
        );
    }
}

/// An incomplete patch through the apply that `scan --mode agent` and
/// `get --mode agent` run: they report it and exit 1 as for any package
/// whose apply failed, under the patch's own code, and the patch stays
/// recorded in the manifest with its files written, so `rollback` undoes
/// it. (The build here leaves no compiled file, as a gem whose extension
/// script downloads the binary it runs.)
#[cfg(unix)]
#[tokio::test]
async fn an_incomplete_patch_fails_scan_and_get_and_stays_recorded() {
    let mock = wiremock::MockServer::start().await;
    mount_native_patch_api(&mock).await;
    let uri = mock.uri();
    let api = ["--api-url", &uri, "--api-token", "fake-token", "--org", ORG];
    let cases = [
        ("scan", &["scan", "--mode", "agent", "--yes", "--json"][..]),
        ("scan, human output", &["scan", "--mode", "agent", "--yes"]),
        ("get", &["get", PURL, "--mode", "agent", "--yes", "--json"]),
        (
            "get, human output",
            &["get", PURL, "--mode", "agent", "--yes"],
        ),
    ];
    for (case, command) in cases {
        let (_tmp, proj, gem_dir, _home) = built_gem_with_its_archive();
        let ruby = FakeRuby::new();
        ruby.serve_source_gem(&c_source(1));
        ruby.build_nothing();
        let tree_before = walk_files(&proj.join("vendor"));
        let args = [command, &api[..]].concat();
        let (code, stdout, stderr) = ruby.run(&proj, &args, &[]);
        assert_eq!(code, 1, "{case}:\n{stdout}\n{stderr}");

        // The patch's file is written and stays written; the compiled
        // code is as it was installed, with no marker beside it.
        assert_eq!(
            std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
            c_source(2),
            "{case}: the patched source was not left written\n{stdout}\n{stderr}"
        );
        assert_eq!(
            std::fs::read(gem_dir.join("lib/sp_native/sp_native.so")).unwrap(),
            b"\x7fELF original",
            "{case}"
        );
        assert!(
            !gem_dir.join(".socket-patch-native-build.json").exists(),
            "{case}"
        );

        if command.contains(&"--json") {
            let env = parse_json_envelope(&stdout);
            assert_eq!(env["status"], "partialFailure", "{case}: {stdout}");
            let events: Vec<&serde_json::Value> = env["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["purl"] == PURL)
                .collect();
            let failed = events
                .iter()
                .find(|e| e["action"] == "failed")
                .unwrap_or_else(|| panic!("{case}: no failed event:\n{stdout}"));
            assert_eq!(
                failed["errorCode"], "native_extension_not_rebuilt",
                "{case}: {stdout}"
            );
            let error = failed["error"].as_str().unwrap_or_default();
            assert!(
                error.contains("the patch's files were written")
                    && error.contains("left no compiled file"),
                "{case}: {error}"
            );
            assert!(
                !events.iter().any(|e| e["action"] == "applied"),
                "{case}: the patch reads as applied:\n{stdout}"
            );
            assert!(
                common::envelope::warning_codes(&env)
                    .iter()
                    .any(|code| code == "native_extension_not_rebuilt"),
                "{case}: {stdout}"
            );
        } else {
            let error_line =
                format!("Error: Patch of {PURL} is incomplete: the patch's files were written");
            assert!(stderr.contains(&error_line), "{case}:\n{stderr}");
            assert!(
                stderr.contains("Error: Some patches could not be applied."),
                "{case}:\n{stderr}"
            );
        }

        // The patch stays recorded, so the installed copy is still known
        // as patched by it: out of sync, and there to roll back.
        let manifest = std::fs::read_to_string(proj.join(".socket/manifest.json"))
            .unwrap_or_else(|e| panic!("{case}: the manifest is gone: {e}"));
        assert!(
            manifest.contains(PURL) && manifest.contains(UUID),
            "{case}: the patch was dropped from the manifest:\n{manifest}"
        );

        // A second run finds the file written and the patch still
        // incomplete: it fails the same way, and nothing reads as applied
        // or already in place.
        let (code, stdout, stderr) = ruby.run(&proj, &args, &[]);
        assert_eq!(code, 1, "{case}, second run:\n{stdout}\n{stderr}");
        if command.contains(&"--json") {
            let env = parse_json_envelope(&stdout);
            assert_eq!(env["status"], "partialFailure", "{case}: {stdout}");
            let of_patch: Vec<(String, String)> = env["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["purl"] == PURL)
                .map(|e| {
                    let field = |key: &str| e[key].as_str().unwrap_or_default().to_string();
                    (field("action"), field("errorCode"))
                })
                .collect();
            assert!(
                of_patch.contains(&(
                    "failed".to_string(),
                    "native_extension_not_rebuilt".to_string()
                )),
                "{case}, second run: {of_patch:?}"
            );
            assert!(
                !of_patch
                    .iter()
                    .any(|(action, code)| action == "applied" || code == "already_patched"),
                "{case}, second run: {of_patch:?}"
            );
        } else {
            assert!(
                stderr.contains(&format!("Error: Patch of {PURL} is incomplete:")),
                "{case}, second run:\n{stderr}"
            );
        }
        let (check, check_out, _) = ruby.run(&proj, &["apply", "--check", "--json"], &[]);
        assert_ne!(check, 0, "{case}: {check_out}");
        assert!(
            check_out.contains("native_extension_not_rebuilt"),
            "{case}: {check_out}"
        );
        // `rollback` restores from the patch's before-blob, which it would
        // fetch on demand: here it is put where the download puts it.
        let before = c_source(1);
        write_blob(
            &proj.join(".socket"),
            &git_sha256(before.as_bytes()),
            before.as_bytes(),
        );
        let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
        assert_eq!(code, 0, "{case}: rollback failed:\n{stdout}\n{stderr}");
        assert_tree(&proj.join("vendor"), &tree_before, case);
    }
}

// ── rebuilds from the source gem ──────────────────────────────────────
//
// An installed gem does not hold everything its extension was built from:
// a build deletes what it is done with (nokogiri's `ports/`), and a
// precompiled platform gem never shipped the build's inputs (`patches/`)
// nor has a build of its own. `apply` rebuilds from the ruby-platform
// source gem (the gem home's `cache/`, else the gem's source), in a stage
// inside the gem home, and puts the result in the installed copy's place:
// the extension dir of a gem RubyGems built, the prebuilt binary Ruby loads
// of a precompiled one.

/// One file of a record: its key, the content it replaces (`None`: the
/// patch adds the file) and the content it writes.
type RecordFile<'a> = (&'a str, Option<&'a str>, &'a str);

/// Write `.socket/manifest.json` and the blobs of a record for `purl` that
/// fixes one advisory (so `vex` has a statement to make).
fn write_record(socket: &Path, purl: &str, entries: &[RecordFile<'_>]) {
    std::fs::create_dir_all(socket).unwrap();
    let mut files = serde_json::Map::new();
    for (key, before, after) in entries {
        let before_hash = before.map(|b| git_sha256(b.as_bytes())).unwrap_or_default();
        let after_hash = git_sha256(after.as_bytes());
        if let Some(before) = before {
            write_blob(socket, &before_hash, before.as_bytes());
        }
        write_blob(socket, &after_hash, after.as_bytes());
        files.insert(
            key.to_string(),
            serde_json::json!({ "beforeHash": before_hash, "afterHash": after_hash }),
        );
    }
    let manifest = serde_json::json!({
        "patches": {
            purl: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": files,
                "vulnerabilities": {
                    "GHSA-aaaa-bbbb-cccc": {
                        "cves": ["CVE-2026-0001"],
                        "summary": "s",
                        "severity": "HIGH",
                        "description": "d",
                    }
                },
                "description": "synthetic test patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Whether `vex` attests the project's patch (`not_affected`).
fn vex_attests(run: impl Fn(&[&str]) -> (i32, String, String)) -> bool {
    let (_, stdout, _) = run(&["vex", "--product", "pkg:generic/app@1"]);
    stdout.contains("\"not_affected\"")
}

/// The `vex` document of the project (`None` when the command writes
/// none), for a test that reads a statement.
fn vex_document(run: impl Fn(&[&str]) -> (i32, String, String)) -> Option<serde_json::Value> {
    let (_, stdout, _) = run(&["vex", "--product", "pkg:generic/app@1"]);
    serde_json::from_str(&stdout).ok()
}

/// The `@id` of every subcomponent a `vex` document attests.
fn vex_subcomponents(document: &serde_json::Value) -> Vec<String> {
    let mut ids: Vec<String> = document["statements"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|statement| statement["products"].as_array().into_iter().flatten())
        .flat_map(|product| product["subcomponents"].as_array().into_iter().flatten())
        .filter_map(|sub| sub["@id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

const PRE_FULL_NAME: &str = "sp_native-1.0.0-x86_64-linux";
const BASE_PATCH: &str = "base\n";

/// A hand-laid precompiled platform copy of `sp_native`: no extension dir
/// of its own, a prebuilt binary per Ruby minor in the rake-compiler
/// layout, the C source of that binary, and none of the build's other
/// inputs (`patches/`). `source_gem_cached`: the ruby-platform archive sits
/// in the home's `cache/`.
fn fake_precompiled_gem(source_gem_cached: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().to_path_buf();
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    let gem_dir = home.join("gems").join(PRE_FULL_NAME);
    std::fs::create_dir_all(gem_dir.join("ext/sp_native")).unwrap();
    std::fs::write(gem_dir.join(C_KEY), c_source(1)).unwrap();
    for minor in ["3.3", "3.4"] {
        let dir = gem_dir.join("lib/sp_native").join(minor);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sp_native.so"), prebuilt(minor)).unwrap();
    }
    std::fs::write(gem_dir.join("lib/sp_native.rb"), LIB_RB).unwrap();
    // Another gem's extension dir: where the Ruby that owns this home
    // builds.
    let racc = home.join("extensions/x86_64-linux/3.4.0/racc-1.8.1");
    std::fs::create_dir_all(&racc).unwrap();
    std::fs::write(racc.join("gem.build_complete"), b"").unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join("specifications")
            .join(format!("{PRE_FULL_NAME}.gemspec")),
        "Gem::Specification.new do |s|\n  s.name = \"sp_native\".freeze\n  \
         s.version = \"1.0.0\".freeze\n  s.platform = \"x86_64-linux\".freeze\n  \
         s.require_paths = [\"lib\".freeze]\nend\n",
    )
    .unwrap();
    if source_gem_cached {
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(home.join("cache/sp_native-1.0.0.gem"), b"the source gem").unwrap();
    }
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\ngem \"sp_native\"\n",
    )
    .unwrap();
    (tmp, proj, gem_dir)
}

fn prebuilt(minor: &str) -> String {
    format!("\x7fELF prebuilt for {minor}")
}

/// What the stand-in Ruby "compiles" a staged tree whose C source is `c`
/// into.
fn built_from(c: &str) -> String {
    format!("rebuilt from: {c}")
}

/// The record the precompiled tests apply: a C source the copy ships, a
/// build input only the source gem packs, and one the patch adds.
fn write_precompiled_record(proj: &Path) {
    let (before, after) = (c_source(1), c_source(2));
    write_record(
        &proj.join(".socket"),
        PURL,
        &[
            (C_KEY, Some(&before), &after),
            ("patches/0001-base.patch", Some(BASE_PATCH), "base, fixed\n"),
            ("patches/0100-CVE-test.patch", None, "the fix\n"),
        ],
    );
}

/// A precompiled platform gem is patched, not refused: its extension is
/// built from the source gem with the record laid over it, and the build
/// takes the place of the prebuilt binary the owning Ruby loads. `apply
/// --check` and `vex` attest it while that binary is the built one, and
/// `rollback` gives the copy back byte for byte. No Ruby runs for a dry
/// run, a check or `vex`, and none is handed the Socket token.
#[cfg(unix)]
#[test]
fn a_precompiled_copy_gets_the_build_of_its_source_gem() {
    const SECRET: &str = "sktsec_e2e_child_env_marker";
    let (_tmp, proj, gem_dir) = fake_precompiled_gem(true);
    write_precompiled_record(&proj);
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    let loaded = gem_dir.join("lib/sp_native/3.4/sp_native.so");
    let tree_before = walk_files(&proj.join("vendor"));
    let run = |args: &[&str]| ruby.run(&proj, args, &[("SOCKET_API_TOKEN", SECRET)]);

    let (code, stdout, stderr) = run(&["apply", "--check", "--json"]);
    assert_ne!(
        code, 0,
        "an unapplied patch checks clean:\n{stdout}\n{stderr}"
    );
    let (code, stdout, stderr) = run(&["apply", "--json", "--dry-run", "--offline"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("native_extension_rebuilt")
            && stdout.contains("replace the gem's prebuilt binary"),
        "the dry run must say what apply would do: {stdout}"
    );
    assert_eq!(ruby.calls(), Vec::<String>::new(), "a dry run ran Ruby");
    assert_tree(&proj.join("vendor"), &tree_before, "");

    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    let built = ["extensions_dir", "unpack", "missing_deps", "stage_build"];
    assert_eq!(ruby.calls(), built);
    assert_eq!(
        std::fs::read_to_string(ruby.state.join("platform-asked")).unwrap(),
        "x86_64-linux\n",
        "the Ruby is asked whether it runs the copy's platform"
    );
    assert_eq!(
        std::fs::read_to_string(&loaded).unwrap(),
        built_from(&c_source(2)),
        "the binary Ruby 3.4 loads is the build of the patched source gem"
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/sp_native/3.3/sp_native.so")).unwrap(),
        prebuilt("3.3"),
        "another Ruby's binary is not this build's to replace"
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(2)
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("patches/0001-base.patch")).unwrap(),
        "base, fixed\n",
        "a build input only the source gem packs is written into the copy"
    );
    assert!(gem_dir.join("patches/0100-CVE-test.patch").is_file());
    let marker = std::fs::read_to_string(gem_dir.join(".socket-patch-native-build.json")).unwrap();
    assert!(marker.contains("\"grafted\": true"), "{marker}");
    assert!(gem_dir.join(".socket-patch-native-orig").is_dir());
    assert!(
        !home.join(".socket-patch-build").exists(),
        "the stage is removed"
    );
    assert!(
        !home.join("gems/sp_native-1.0.0").exists(),
        "nothing is installed into the user's gem home"
    );
    for mode in ruby.calls() {
        let seen = ruby.env_seen(&mode);
        assert!(
            !seen.contains(SECRET),
            "`ruby` ({mode}) was handed the Socket token"
        );
    }

    // Attested from files alone.
    let (code, stdout, stderr) = run(&["apply", "--check"]);
    assert_eq!(code, 0, "a grafted patch checks clean:\n{stdout}\n{stderr}");
    assert!(vex_attests(run), "vex attests the grafted copy");
    let (code, stdout, _) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(event_action(&stdout), "skipped", "{stdout}");
    assert_eq!(ruby.calls(), built, "nothing more to run");

    // A binary that is no longer the built one (the gem was reinstalled).
    std::fs::write(&loaded, prebuilt("3.4")).unwrap();
    let (code, stdout, _) = run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");
    assert!(stdout.contains("native_extension_not_rebuilt"), "{stdout}");
    assert!(!vex_attests(run), "vex attested a prebuilt binary");
    std::fs::write(&loaded, built_from(&c_source(2))).unwrap();

    let (code, stdout, stderr) = run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(
        &proj.join("vendor"),
        &tree_before,
        "rollback gives the copy back byte for byte",
    );
    assert_eq!(ruby.calls(), built, "rollback restores from the backup");
}

/// A precompiled copy was built by its publisher, not on this machine:
/// build arguments RubyGems recorded for it were never used to build it,
/// and its rebuild takes none. Bundler records its `build.<gem>` setting
/// for a platform gem too, and a project that kept `build.nokogiri
/// --use-system-libraries` from the years before nokogiri shipped
/// precompiled gems had `apply` replace the libxml2 2.13 the gem ships with
/// the system's 2.9. A gem RubyGems built is given its recorded arguments
/// again.
#[cfg(unix)]
#[test]
fn a_precompiled_copy_is_rebuilt_without_the_build_arguments_recorded_for_it() {
    let (_tmp, proj, gem_dir) = fake_precompiled_gem(true);
    write_precompiled_record(&proj);
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    std::fs::create_dir_all(home.join("build_info")).unwrap();
    std::fs::write(
        home.join("build_info")
            .join(format!("{PRE_FULL_NAME}.info")),
        "--use-system-libraries\n",
    )
    .unwrap();
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(
        ruby.stage_build_args_of(),
        "",
        "the build was given the arguments recorded for the platform gem"
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/sp_native/3.4/sp_native.so")).unwrap(),
        built_from(&c_source(2))
    );

    // A copy RubyGems built: its recorded arguments are the build's.
    let (_tmp, proj, _gem_dir, home) = built_gem_with_its_archive();
    std::fs::write(
        home.join("build_info").join(format!("{FULL_NAME}.info")),
        "--with-cflags=-O2\n",
    )
    .unwrap();
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(ruby.stage_build_args_of(), FULL_NAME);
}

/// [`fake_native_gem`] with its source gem in the home's `cache/`, and its
/// gem home.
#[cfg(unix)]
fn built_gem_with_its_archive() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let (tmp, proj, gem_dir) = fake_native_gem(true);
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    std::fs::create_dir_all(home.join("cache")).unwrap();
    std::fs::write(home.join("cache/sp_native-1.0.0.gem"), b"the source gem").unwrap();
    std::fs::create_dir_all(home.join("build_info")).unwrap();
    (tmp, proj, gem_dir, home)
}

/// Whether the CLI can tell that a build read a file under `dir`: always
/// on Linux, where the kernel says which files were opened; elsewhere when
/// a read shows in a file's access time, which a filesystem mounted
/// `noatime` does not record. Without either the check under test cannot
/// run.
#[cfg(unix)]
fn records_reads(dir: &Path) -> bool {
    if cfg!(target_os = "linux") {
        return true;
    }
    let probe = dir.join("read-probe");
    std::fs::write(&probe, b"probe").unwrap();
    let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000_000);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&probe)
        .unwrap();
    file.set_times(std::fs::FileTimes::new().set_accessed(old))
        .unwrap();
    drop(file);
    std::fs::read(&probe).unwrap();
    let recorded = std::fs::metadata(&probe).unwrap().accessed().unwrap() != old;
    std::fs::remove_file(&probe).unwrap();
    recorded
}

/// A build that exits cleanly has not always built the patch: a gem set up
/// to link the system's copy of a library it packs never opens the packed
/// copy's sources. A record that changes only those (a third of the
/// published nokogiri patches add one `patches/libxml2/*.patch`) was
/// written, "rebuilt" and attested on such an install, with nothing of it
/// in what Ruby loads. The CLI knows no gem's switches: it marks the
/// record's build inputs unread, and a build that read none of them is not
/// a build of the patch. The record's files are written and stay written,
/// the compiled code stays what it was, and the patch is incomplete: the
/// run fails (exit 1) and says what was written and what is not in
/// effect, and nothing attests the copy (#2144). `rollback` still takes
/// the file out. The same record is built by a build that applies the
/// patch file.
#[cfg(unix)]
#[test]
fn a_build_that_reads_nothing_of_the_patch_writes_it_and_fails_as_incomplete() {
    const PATCH_REL: &str = "patches/libsp/0100-CVE-test.patch";
    let library_patch: [RecordFile<'_>; 1] = [(PATCH_REL, None, "fix\n")];
    let (_tmp, proj, gem_dir, home) = built_gem_with_its_archive();
    if !records_reads(&home) {
        eprintln!("SKIP: no way to tell here whether a build read a file");
        return;
    }
    write_record(&proj.join(".socket"), PURL, &library_patch);
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let tree_before = walk_files(&proj.join("vendor"));
    let written = tree_with(
        &tree_before,
        &format!("bundle/ruby/3.4.0/gems/{FULL_NAME}/{PATCH_REL}"),
        b"fix\n",
    );

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 1, "ruby ran {:?}\n{stdout}\n{stderr}", ruby.calls());
    let event = incomplete_event(&stdout, PURL);
    let error = event["error"].as_str().unwrap_or_default();
    for needle in [
        "the patch's files were written",
        "without reading any of those files",
        PATCH_REL,
        "vex does not attest the patch",
    ] {
        assert!(error.contains(needle), "no {needle:?} in {error:?}");
    }
    assert!(
        !error.contains("  "),
        "the message has a gap in it: {error}"
    );
    // The event lists what this run wrote.
    assert_eq!(event_files(&event), [PATCH_REL], "{stdout}");
    assert_eq!(
        ruby.calls(),
        ["extensions_dir", "unpack", "missing_deps", "stage_build"],
        "one build in the stage, and none of the installed tree after it"
    );
    // The patch file is in the gem, and nothing else moved: the build the
    // install made is the one Ruby still loads, with no marker beside it.
    assert_tree(&proj.join("vendor"), &written, "after the apply");
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
    assert_ne!(code, 0, "{stdout}\n{stderr}");
    assert!(
        !vex_attests(|args| ruby.run(&proj, args, &[])),
        "vex attested a patch that is compiled into nothing"
    );

    // Applying again says the same and changes nothing: the patch is as
    // incomplete as it was, and this run wrote no file.
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let event = incomplete_event(&stdout, PURL);
    assert!(
        event["error"]
            .as_str()
            .is_some_and(|e| e.contains("without reading any of those files")),
        "{stdout}"
    );
    assert_eq!(event_files(&event), Vec::<String>::new(), "{stdout}");
    assert!(!stdout.contains("already_patched"), "{stdout}");
    assert_tree(&proj.join("vendor"), &written, "after a second apply");

    // The human path says it once, as the package's error (also under
    // `--silent`), and the summary does not count the patch as applied.
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--offline"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let error_line =
        format!("Error: Patch of {PURL} is incomplete: the patch's files were written");
    assert!(stderr.contains(&error_line), "{stdout}\n{stderr}");
    assert_eq!(
        stderr.matches("vex does not attest the patch").count(),
        1,
        "the error is not repeated as a warning:\n{stderr}"
    );
    assert!(
        stdout.contains("0 of 1 targeted patch applied") && stdout.contains("1 not in effect"),
        "{stdout}"
    );
    assert!(!stdout.contains("Patched packages:"), "{stdout}");
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--offline", "--silent"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains(&error_line), "{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &written, "after the human runs");

    // Rollback takes the file out again.
    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "after rollback");

    // A build that applies the gem's patch files reads this one.
    write_record(&proj.join(".socket"), PURL, &library_patch);
    ruby.apply_patch_files();
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(not_rebuilt_warning(&stdout), "", "{stdout}");
    assert!(gem_dir.join(PATCH_REL).is_file());
    assert!(vex_attests(|args| ruby.run(&proj, args, &[])));

    // One input read is enough: a record carries files no build opens (a
    // manifest that lists what it adds) beside the ones it compiles.
    let (_tmp, proj, _gem_dir, _home) = built_gem_with_its_archive();
    let (before, after) = (c_source(1), c_source(2));
    write_record(
        &proj.join(".socket"),
        PURL,
        &[(C_KEY, Some(&before), &after), (PATCH_REL, None, "fix\n")],
    );
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(not_rebuilt_warning(&stdout), "", "{stdout}");
}

/// The rebuild of an installed tree (no source gem to stage) is held to the
/// same: after a build that read nothing of the patch, the previous build
/// is put back, the record's files stay written, the run fails with the
/// patch incomplete, and nothing attests the copy.
#[cfg(unix)]
#[test]
fn an_in_place_build_that_reads_nothing_of_the_patch_keeps_the_previous_build() {
    const PATCH_REL: &str = "patches/libsp/0001-base.patch";
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    if !records_reads(&home) {
        eprintln!("SKIP: no way to tell here whether a build read a file");
        return;
    }
    // A build input the installed tree holds and the stand-in build never
    // opens.
    std::fs::create_dir_all(gem_dir.join("patches/libsp")).unwrap();
    std::fs::write(gem_dir.join(PATCH_REL), "base\n").unwrap();
    write_record(
        &proj.join(".socket"),
        PURL,
        &[(PATCH_REL, Some("base\n"), "base, fixed\n")],
    );
    let ruby = FakeRuby::new();
    let tree_before = walk_files(&proj.join("vendor"));
    let written = tree_with(
        &tree_before,
        &format!("bundle/ruby/3.4.0/gems/{FULL_NAME}/{PATCH_REL}"),
        b"base, fixed\n",
    );

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let event = incomplete_event(&stdout, PURL);
    let error = event["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("the patch's files were written")
            && error.contains("without reading any of those files")
            && error.contains("vex does not attest the patch"),
        "{stdout}"
    );
    assert_eq!(event_files(&event), [PATCH_REL], "{stdout}");
    assert_eq!(ruby.calls(), ["extensions_dir", "build"]);
    assert_tree(&proj.join("vendor"), &written, "after the apply");
    assert!(!vex_attests(|args| ruby.run(&proj, args, &[])));

    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "after rollback");
}

/// A gem whose extension script downloads the binary it runs (passenger's
/// agent) has a build that compiles nothing: a clean exit, a finished and
/// empty extension dir, and the binary somewhere Ruby does not load from.
/// Moving that dir in passed for a build of the patch: the run said
/// "applied" and `vex` attested it while the code the gem runs was
/// byte-for-byte unchanged (#2144). The record's files are written and
/// stay written (the gem's own Ruby is what compiles such a binary later),
/// the run fails with the patch incomplete and says that the compiled code
/// is not the patch's, and nothing attests the copy.
#[cfg(unix)]
#[test]
fn a_build_that_leaves_no_compiled_file_writes_the_patch_and_fails_as_incomplete() {
    let (_tmp, proj, gem_dir, home) = built_gem_with_its_archive();
    let (before, after) = (c_source(1), c_source(2));
    write_record(
        &proj.join(".socket"),
        PURL,
        &[(C_KEY, Some(&before), &after)],
    );
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    ruby.build_nothing();
    let tree_before = walk_files(&proj.join("vendor"));
    let written = tree_with(
        &tree_before,
        &format!("bundle/ruby/3.4.0/gems/{FULL_NAME}/{C_KEY}"),
        after.as_bytes(),
    );

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 1, "ruby ran {:?}\n{stdout}\n{stderr}", ruby.calls());
    let event = incomplete_event(&stdout, PURL);
    let error = event["error"].as_str().unwrap_or_default();
    for needle in [
        "the patch's files were written",
        C_KEY,
        "left no compiled file",
        "vex does not attest the patch",
    ] {
        assert!(error.contains(needle), "no {needle:?} in {error:?}");
    }
    assert!(
        !error.contains("  "),
        "the message has a gap in it: {error}"
    );
    assert_eq!(event_files(&event), [C_KEY], "{stdout}");
    assert_eq!(
        ruby.calls(),
        ["extensions_dir", "unpack", "missing_deps", "stage_build"]
    );
    // The source is patched; the build the install made, its extension dir
    // and everything else are as they were, and the stage is gone.
    assert_tree(&proj.join("vendor"), &written, "after the apply");
    assert!(!home.join(".socket-patch-build").exists());
    assert!(!gem_dir.join(".socket-patch-native-build.json").exists());
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
    assert_ne!(code, 0, "{stdout}\n{stderr}");
    assert!(
        !vex_attests(|args| ruby.run(&proj, args, &[])),
        "vex attested a patch whose build installed nothing"
    );

    // A second run finds the source written and the patch as incomplete
    // as it was: it fails again, and never reads as already patched.
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let event = incomplete_event(&stdout, PURL);
    assert_eq!(event_files(&event), Vec::<String>::new(), "{stdout}");
    assert!(!stdout.contains("already_patched"), "{stdout}");
    assert_tree(&proj.join("vendor"), &written, "after a second apply");

    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "after rollback");
}

/// A build can take many minutes, and a run that printed nothing until its
/// summary looked hung (#2144): each build says when it starts and how it
/// ended, on stderr. The machine channel stays as it was.
#[cfg(unix)]
#[test]
fn a_rebuild_says_when_it_starts_and_how_it_ended() {
    let record = |proj: &Path| {
        let (before, after) = (c_source(1), c_source(2));
        write_record(
            &proj.join(".socket"),
            PURL,
            &[(C_KEY, Some(&before), &after)],
        );
    };
    // A staged build that fails, then the build of the installed tree.
    let (_tmp, proj, _gem_dir, _home) = built_gem_with_its_archive();
    record(&proj);
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    ruby.fail_staged_builds();
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--offline"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let said: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains(FULL_NAME))
        .collect();
    let expected = [
        "Rebuilding the native extension of sp_native-1.0.0 from its source gem with the patch \
         applied; this can take several minutes.",
        "The build of sp_native-1.0.0 failed after ",
        "Rebuilding the native extension of sp_native-1.0.0 from the patched sources in the \
         installed gem; this can take several minutes.",
        "The build of sp_native-1.0.0 finished after ",
    ];
    assert_eq!(said.len(), expected.len(), "{stderr}");
    for (line, start) in said.iter().zip(expected) {
        assert!(line.starts_with(start), "{line:?} does not start {start:?}");
    }

    for quiet in ["--json", "--silent"] {
        let (_tmp, proj, _gem_dir, _home) = built_gem_with_its_archive();
        record(&proj);
        let ruby = FakeRuby::new();
        ruby.serve_source_gem(&c_source(1));
        let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--offline", quiet], &[]);
        assert_eq!(code, 0, "{quiet}: {stdout}\n{stderr}");
        assert_eq!(ruby.calls().last().map(String::as_str), Some("stage_build"));
        assert!(
            !stderr.contains("Rebuilding") && !stderr.contains("The build of"),
            "{quiet}: {stderr}"
        );
    }
}

/// Without the source gem there is nothing to build from: offline and not
/// cached, the copy is refused from files alone, with what is needed (not
/// "use hosted mode", which refuses platform gems); with a registry that
/// does not serve it, after the probe. Nothing is written either way.
#[cfg(unix)]
#[test]
fn a_precompiled_copy_without_its_source_gem_is_refused() {
    let (_tmp, proj, _gem_dir) = fake_precompiled_gem(false);
    write_precompiled_record(&proj);
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let tree_before = walk_files(&proj.join("vendor"));

    for args in [
        &["apply", "--json", "--offline"][..],
        &["apply", "--json", "--offline", "--dry-run"],
    ] {
        let (code, stdout, stderr) = ruby.run(&proj, args, &[]);
        assert_eq!(code, 1, "{args:?}: {stdout}\n{stderr}");
        let env = parse_json_envelope(&stdout);
        let error = common::envelope::event_for(&env, PURL)["error"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            error.starts_with("native_extensions_unsupported:"),
            "{args:?}: {stdout}"
        );
        for needle in [
            "sp_native-1.0.0.gem",
            "this run is offline",
            "with network access to",
            "cache",
        ] {
            assert!(error.contains(needle), "{args:?}: no {needle:?} in {error}");
        }
        assert!(!error.contains("--mode hosted"), "{args:?}: {error}");
        assert_eq!(ruby.calls(), Vec::<String>::new(), "{args:?}: Ruby ran");
        assert_tree(&proj.join("vendor"), &tree_before, &format!("{args:?}"));
    }

    // Online, from a registry that does not have it.
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extensions_unsupported"), "{stdout}");
    assert!(stdout.contains("could not be downloaded"), "{stdout}");
    assert_eq!(ruby.calls(), ["extensions_dir"]);
    assert_tree(&proj.join("vendor"), &tree_before, "");

    // Online, with a registry reached over plain http that is not this
    // machine: whoever sits on the path would choose the archive and the
    // checksum it is verified against, and the archive's build scripts
    // would run. It is not asked, in a dry run either, and the refusal
    // says to use https.
    let ruby = FakeRuby::new();
    for args in [&["apply", "--json"][..], &["apply", "--json", "--dry-run"]] {
        let (code, stdout, stderr) = ruby.run(
            &proj,
            args,
            &[("SOCKET_RUBYGEMS_URL", "http://gems.example.test/mirror")],
        );
        assert_eq!(code, 1, "{args:?}: {stdout}\n{stderr}");
        let env = parse_json_envelope(&stdout);
        let error = common::envelope::event_for(&env, PURL)["error"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            error.starts_with("native_extensions_unsupported:"),
            "{args:?}: {stdout}"
        );
        for needle in [
            "sp_native-1.0.0.gem",
            "SOCKET_RUBYGEMS_URL",
            "`http://gems.example.test/mirror` is not an https URL",
            "set it to an https URL",
            "nothing was written",
        ] {
            assert!(error.contains(needle), "{args:?}: no {needle:?} in {error}");
        }
        assert_eq!(ruby.calls(), Vec::<String>::new(), "{args:?}: Ruby ran");
        assert_tree(&proj.join("vendor"), &tree_before, &format!("{args:?}"));
    }

    // Online, for a gem the lock resolves from another source: the
    // registry's gem of that name is not this gem, and the lock's remote
    // is not a place the run downloads from. Nothing is asked of anyone.
    std::fs::write(
        proj.join("Gemfile.lock"),
        "GEM\n  remote: https://gems.example.test/private/\n  specs:\n    \
         sp_native (1.0.0-x86_64-linux)\n\nPLATFORMS\n  x86_64-linux\n\n\
         DEPENDENCIES\n  sp_native\n\nCHECKSUMS\n  \
         sp_native (1.0.0) sha256=0000000000000000000000000000000000000000000000000000000000000000\n",
    )
    .unwrap();
    let ruby = FakeRuby::new();
    for args in [&["apply", "--json"][..], &["apply", "--json", "--dry-run"]] {
        let (code, stdout, stderr) = ruby.run(&proj, args, &[]);
        assert_eq!(code, 1, "{args:?}: {stdout}\n{stderr}");
        let env = parse_json_envelope(&stdout);
        let error = common::envelope::event_for(&env, PURL)["error"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            error.starts_with("native_extensions_unsupported:"),
            "{args:?}: {stdout}"
        );
        assert!(
            error.contains("resolves sp_native from https://gems.example.test/private")
                && error.contains("is not downloaded"),
            "{args:?}: {error}"
        );
        assert!(
            error.contains("Put sp_native-1.0.0.gem in") && !error.contains("network access"),
            "{args:?}: {error}"
        );
        assert_eq!(ruby.calls(), Vec::<String>::new(), "{args:?}: Ruby ran");
        assert_tree(&proj.join("vendor"), &tree_before, &format!("{args:?}"));
    }
}

/// An archive is built only when it is the installed gem's own source and
/// the record applies to it: both are checked on the unpacked tree before
/// anything of it runs. An archive whose files are not the installed
/// copy's (another gem of that name), and one whose build input is not
/// what the patch was written for, stop a precompiled copy's run with
/// nothing written.
#[cfg(unix)]
#[test]
fn an_archive_that_is_not_the_gems_own_source_is_not_built() {
    // (what the "source gem" holds, the reason it is not used)
    let cases: [(&str, &str, &str); 2] = [
        // Another C source than the installed copy's.
        (
            "another source",
            "is not the installed gem's own source",
            "ext/sp_native/sp_native.c differs",
        ),
        // The copy's own files, but another libxml2-style patch file than
        // the record replaces (the copy never shipped it: only the strict
        // apply to the source gem can tell).
        (
            "another build input",
            "the patch does not apply to the source gem",
            "0001-base.patch",
        ),
    ];
    for (case, reason, names) in cases {
        let (_tmp, proj, _gem_dir) = fake_precompiled_gem(true);
        write_precompiled_record(&proj);
        let ruby = FakeRuby::new();
        if case == "another source" {
            ruby.serve_source_gem(&c_source(7));
        } else {
            ruby.serve_source_gem(&c_source(1));
            let other = ruby.state.join("source/patches/0001-base.patch");
            std::fs::write(other, "not the base\n").unwrap();
        }
        let tree_before = walk_files(&proj.join("vendor"));

        let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
        assert_eq!(code, 1, "{case}: {stdout}\n{stderr}");
        assert!(
            stdout.contains("native_extensions_unsupported"),
            "{case}: {stdout}"
        );
        assert!(
            stdout.contains(reason) && stdout.contains(names),
            "{case}: {stdout}"
        );
        assert_eq!(
            ruby.calls(),
            ["extensions_dir", "unpack"],
            "{case}: nothing was built"
        );
        assert_tree(&proj.join("vendor"), &tree_before, case);
    }
}

/// A build that fails in the stage never touched the installed copy. A
/// precompiled gem has nothing else to build from: it keeps its prebuilt
/// binary. A gem RubyGems built is then built where it is installed, as it
/// was before there was a stage; when that fails too the copy is put back
/// as it was, and the error names both failures.
#[cfg(unix)]
#[test]
fn a_failed_staged_build_changes_nothing() {
    for precompiled in [true, false] {
        let (_tmp, proj, _gem_dir) = if precompiled {
            fake_precompiled_gem(true)
        } else {
            let fixture = fake_native_gem(true);
            let cache = fixture.1.join("vendor/bundle/ruby/3.4.0/cache");
            std::fs::create_dir_all(&cache).unwrap();
            std::fs::write(cache.join("sp_native-1.0.0.gem"), b"the source gem").unwrap();
            fixture
        };
        write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
        let ruby = FakeRuby::new();
        ruby.serve_source_gem(&c_source(1));
        ruby.fail_builds();
        let tree_before = walk_files(&proj.join("vendor"));

        let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
        assert_eq!(code, 1, "precompiled {precompiled}: {stdout}\n{stderr}");
        assert!(
            stdout.contains("native_extension_build_failed"),
            "precompiled {precompiled}: {stdout}"
        );
        assert!(
            stdout.contains("this is not C (in the stage)"),
            "the compiler error is shown: {stdout}"
        );
        let staged = ["extensions_dir", "unpack", "missing_deps", "stage_build"];
        if precompiled {
            assert!(
                stdout.contains("nothing of the installed gem was changed"),
                "{stdout}"
            );
            assert_eq!(ruby.calls(), staged);
        } else {
            assert!(
                stdout.contains("this is not C (in place)")
                    && stdout.contains("the sources and the previous build were put back"),
                "both failures are named: {stdout}"
            );
            assert_eq!(ruby.calls(), [&staged[..], &["build"]].concat());
        }
        assert_tree(
            &proj.join("vendor"),
            &tree_before,
            &format!("precompiled {precompiled}"),
        );
    }
}

/// A build that fails because the gem's `extconf.rb` misses a library
/// (#2117: a precompiled `pg` on a machine without `libpq-dev`) says so.
/// The error keeps the lines that name the cause and not mkmf's list of
/// configuration options that follows them, does not point at a log in the
/// stage (or the extension dir) the failed build was removed with, names
/// what the rebuild of a precompiled gem needs, and is printed once.
#[cfg(unix)]
#[test]
fn a_failed_extconf_shows_its_cause_once() {
    for precompiled in [true, false] {
        let case = format!("precompiled {precompiled}");
        let (_tmp, proj, _gem_dir) = if precompiled {
            fake_precompiled_gem(true)
        } else {
            let fixture = fake_native_gem(true);
            let cache = fixture.1.join("vendor/bundle/ruby/3.4.0/cache");
            std::fs::create_dir_all(&cache).unwrap();
            std::fs::write(cache.join("sp_native-1.0.0.gem"), b"the source gem").unwrap();
            fixture
        };
        write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
        let ruby = FakeRuby::new();
        ruby.serve_source_gem(&c_source(1));
        ruby.fail_extconf();
        let tree_before = walk_files(&proj.join("vendor"));

        let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--offline"], &[]);
        assert_eq!(code, 1, "{case}: {stdout}\n{stderr}");
        assert!(
            stderr.contains(
                "Error: Failed to patch pkg:gem/sp_native@1.0.0: native_extension_build_failed:"
            ),
            "{case}: {stderr}"
        );
        assert!(
            stderr.contains("Can't find the 'libsp.h header")
                && stderr.contains("sudo apt install libsp-dev"),
            "{case}: the cause is shown: {stderr}"
        );
        assert!(
            !stderr.contains("--with-opt-") && !stderr.contains("Provided configuration options"),
            "{case}: mkmf's option list is not: {stderr}"
        );
        assert!(
            !stderr.contains("mkmf.log which can be found")
                && !stderr.contains("/mkmf.log")
                && !stderr.contains("gem_make.out"),
            "{case}: no pointer to a log that was removed: {stderr}"
        );
        assert!(
            !stderr.contains("Install a compiler toolchain and the Ruby headers and apply again"),
            "{case}: the remedy does not assume the compiler is what is missing: {stderr}"
        );
        if precompiled {
            assert!(
                stderr.contains("`gem install sp_native -v 1.0.0 --platform ruby`")
                    && stderr.contains("the libraries the gem builds against"),
                "{case}: the remedy says what a precompiled gem's rebuild needs: {stderr}"
            );
        } else {
            assert!(
                stderr.contains("a library the gem builds against")
                    && stderr.contains("socket-patch scan --mode hosted"),
                "{case}: {stderr}"
            );
        }
        assert_eq!(
            stderr
                .matches("did not build from the patched sources")
                .count(),
            1,
            "{case}: the failure is printed once: {stderr}"
        );
        // Nor is a copy that was put back advised about what reverts its
        // patch.
        assert!(!stderr.contains("Warning:"), "{case}: {stderr}");
        assert_tree(&proj.join("vendor"), &tree_before, &case);

        // The machine channel keeps the failure as the package's error and
        // as a coded warning.
        let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
        assert_eq!(code, 1, "{case}: {stdout}\n{stderr}");
        let envelope = parse_json_envelope(&stdout);
        let warnings = envelope["warnings"].as_array().expect("warnings[]");
        assert!(
            warnings.iter().any(|w| {
                w["code"] == "native_extension_build_failed"
                    && w["detail"]
                        .as_str()
                        .is_some_and(|d| d.contains("Can't find the 'libsp.h header"))
            }),
            "{case}: {stdout}"
        );
        assert!(!stdout.contains("--redownload"), "{case}: {stdout}");
        assert_tree(&proj.join("vendor"), &tree_before, &case);
    }
}

/// A failed build puts back what this run wrote, and no more: a file an
/// earlier run left patched stays patched, so the copy is still advised
/// that `bundle install --redownload` reverts it.
#[cfg(unix)]
#[test]
fn a_failed_build_keeps_the_advisory_of_a_file_patched_before() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    let (before, after) = (c_source(1), c_source(2));
    let lib_after = format!("{LIB_RB}# patched\n");
    write_record(
        &proj.join(".socket"),
        PURL,
        &[
            (C_KEY, Some(&before), &after),
            ("lib/sp_native.rb", Some(LIB_RB), &lib_after),
        ],
    );
    std::fs::write(gem_dir.join("lib/sp_native.rb"), &lib_after).unwrap();
    let ruby = FakeRuby::new();
    ruby.fail_builds();
    let tree_before = walk_files(&proj.join("vendor"));

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--offline"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("native_extension_build_failed:"),
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("bundle install --redownload").count(),
        1,
        "{stderr}"
    );
    assert_tree(&proj.join("vendor"), &tree_before, "after the failed build");
}

/// Whatever keeps a gem RubyGems built from being rebuilt from its source
/// gem, before anything of the installed copy is written, leaves it the
/// rebuild it had before there was a stage: from its own tree, in place.
/// The cached archive not being its own source (a patched archive a hosted
/// install left there), a record that does not apply to it, a stage that
/// cannot be opened, a build that fails in the stage, no cached archive
/// and a registry that is not asked because it is reached over plain http.
#[cfg(unix)]
#[test]
fn a_built_gem_falls_back_to_its_own_tree() {
    for case in [
        "not its own source",
        "record does not apply",
        "no stage",
        "staged build fails",
        "registry over plain http",
    ] {
        let (_tmp, proj, gem_dir) = fake_native_gem(true);
        let home = proj.join("vendor/bundle/ruby/3.4.0");
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(home.join("cache/sp_native-1.0.0.gem"), b"the source gem").unwrap();
        let ruby = FakeRuby::new();
        ruby.serve_source_gem(&c_source(1));
        let (before, after) = (c_source(1), c_source(2));
        let mut record: Vec<RecordFile<'_>> = vec![(C_KEY, Some(&before), &after)];
        let mut staged_steps = vec!["unpack"];
        match case {
            "not its own source" => {
                let lib = ruby.state.join("source/lib/sp_native.rb");
                std::fs::write(lib, "# another gem's\n").unwrap();
            }
            "record does not apply" => {
                // A file the source gem alone holds, with other content
                // than the record replaces.
                record.push((
                    "patches/0001-base.patch",
                    Some("not the base\n"),
                    "the fix\n",
                ));
            }
            "no stage" => {
                // Something that is no directory where the stage goes.
                std::fs::write(home.join(".socket-patch-build"), b"").unwrap();
                staged_steps.clear();
            }
            "registry over plain http" => {
                std::fs::remove_file(home.join("cache/sp_native-1.0.0.gem")).unwrap();
                staged_steps.clear();
            }
            _ => {
                ruby.fail_staged_builds();
                staged_steps.extend(["missing_deps", "stage_build"]);
            }
        }
        write_record(&proj.join(".socket"), PURL, &record);

        // Online for the registry case: nothing is asked of a registry
        // that is neither https nor this machine.
        let (args, env): (&[&str], &[(&str, &str)]) = if case == "registry over plain http" {
            (
                &["apply", "--json"],
                &[("SOCKET_RUBYGEMS_URL", "http://gems.example.test/mirror")],
            )
        } else {
            (&["apply", "--json", "--offline"], &[])
        };
        let (code, stdout, stderr) = ruby.run(&proj, args, env);
        if case == "record does not apply" {
            // The record changes a file the copy does not hold: only the
            // source gem could have vouched for it, so there is nothing to
            // fall back to.
            assert_eq!(code, 1, "{case}: {stdout}\n{stderr}");
            assert!(
                stdout.contains("native_extensions_unsupported")
                    && stdout.contains("the patch does not apply to the source gem"),
                "{case}: {stdout}"
            );
            assert_eq!(
                std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
                c_source(1),
                "{case}"
            );
            continue;
        }
        assert_eq!(code, 0, "{case}: apply failed:\n{stdout}\n{stderr}");
        assert_eq!(event_action(&stdout), "applied", "{case}: {stdout}");
        let expected = [&["extensions_dir"][..], &staged_steps[..], &["build"]].concat();
        assert_eq!(ruby.calls(), expected, "{case}");
        assert_eq!(
            std::fs::read(gem_dir.join("lib/sp_native/sp_native.so")).unwrap(),
            b"rebuilt",
            "{case}: the in-place build"
        );
        assert_eq!(
            std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
            c_source(2),
            "{case}"
        );
        if case != "no stage" {
            assert!(!home.join(".socket-patch-build").exists(), "{case}");
        }
        let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
        assert_eq!(code, 0, "{case}: {stdout}\n{stderr}");
    }
}

/// A record written for a platform gem's own platform is the one applied
/// to that gem's copy, and the only one: the `ruby` platform's record of
/// the same version matches the copy too (its C source is the one the
/// copy ships) and is not applied on top.
#[cfg(unix)]
#[test]
fn a_platform_copy_takes_its_own_platforms_record_alone() {
    let (_tmp, proj, gem_dir) = fake_precompiled_gem(true);
    let socket = proj.join(".socket");
    let ruby_key = format!("{PURL}?platform=ruby");
    let own_key = format!("{PURL}?platform=x86_64-linux");
    let (c_before, c_after) = (c_source(1), c_source(2));
    let rb_after = "require \"sp_native/sp_native\"\n# patched for x86_64-linux\n";
    let record = |uuid: &str, key: &str, before: &str, after: &str| {
        write_blob(&socket, &git_sha256(before.as_bytes()), before.as_bytes());
        write_blob(&socket, &git_sha256(after.as_bytes()), after.as_bytes());
        serde_json::json!({
            "uuid": uuid,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { key: {
                "beforeHash": git_sha256(before.as_bytes()),
                "afterHash": git_sha256(after.as_bytes()),
            }},
            "vulnerabilities": {},
            "description": "synthetic test patch",
            "license": "MIT",
            "tier": "free",
        })
    };
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = serde_json::json!({ "patches": {
        ruby_key.as_str(): record(UUID, C_KEY, &c_before, &c_after),
        own_key.as_str(): record(
            "29962996-2996-4996-8996-299629962996",
            "lib/sp_native.rb",
            LIB_RB,
            rb_after,
        ),
    }});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/sp_native.rb")).unwrap(),
        rb_after,
        "the copy's own platform's record is applied"
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(1),
        "the ruby-platform record was applied on top"
    );
    assert_eq!(ruby.calls(), Vec::<String>::new(), "nothing was rebuilt");
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/sp_native/3.4/sp_native.so")).unwrap(),
        prebuilt("3.4")
    );
}

/// A gem RubyGems built, with its archive still in the home's `cache/`
/// (where RubyGems and Bundler leave it), is rebuilt from that archive in
/// a stage: no network, the installed gemspec is not loaded, and the copy
/// ends as an in-place rebuild would leave it. An archive RubyGems cannot
/// use as that gem leaves the copy's own tree to build.
#[cfg(unix)]
#[test]
fn a_built_gem_with_its_archive_cached_is_rebuilt_in_a_stage() {
    let (_tmp, proj, gem_dir) = fake_native_gem(true);
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    std::fs::create_dir_all(home.join("cache")).unwrap();
    std::fs::write(home.join("cache/sp_native-1.0.0.gem"), b"the source gem").unwrap();
    let ext_so = home
        .join("extensions/x86_64-linux/3.4.0")
        .join(FULL_NAME)
        .join("sp_native/sp_native.so");
    let lib_so = gem_dir.join("lib/sp_native/sp_native.so");
    let tree_before = walk_files(&proj.join("vendor"));

    // The archive is another gem: the in-place rebuild is what is left.
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(ruby.calls(), ["extensions_dir", "unpack", "build"]);
    assert_eq!(std::fs::read(&lib_so).unwrap(), b"rebuilt");
    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "");

    // The archive is the gem: built in a stage, moved into place.
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(
        ruby.calls(),
        ["extensions_dir", "unpack", "missing_deps", "stage_build"],
        "the installed gemspec is not loaded by a build"
    );
    for built in [&ext_so, &lib_so] {
        assert_eq!(
            std::fs::read_to_string(built).unwrap(),
            built_from(&c_source(2)),
            "{}",
            built.display()
        );
    }
    assert!(ext_so
        .parent()
        .and_then(Path::parent)
        .is_some_and(|ext| ext.join("gem.build_complete").is_file()));
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(2)
    );
    let marker = std::fs::read_to_string(gem_dir.join(".socket-patch-native-build.json")).unwrap();
    assert!(marker.contains("\"schema\": 1"), "{marker}");
    assert!(!home.join(".socket-patch-build").exists());
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");

    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "");
}

/// An interrupt during a staged build ends the build with the CLI, and
/// leaves an installed copy that was never touched. The stage it leaves in
/// the gem home is only disk space: the next run of the copy drops it.
#[cfg(unix)]
#[test]
fn an_interrupted_staged_build_leaves_the_copy_as_it_was() {
    use std::os::unix::process::ExitStatusExt;
    let (_tmp, proj, gem_dir) = fake_precompiled_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    let stage = home.join(".socket-patch-build").join(PRE_FULL_NAME);
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    ruby.hang_builds(false);
    let copy_before = walk_files(&gem_dir);

    let (mut cli, build) = ruby.spawn_until_building(&proj, &["apply", "--json", "--offline"]);
    assert!(stage.is_dir(), "the build is staged inside the gem home");
    assert_tree(&gem_dir, &copy_before, "the copy is not touched");
    // SAFETY: plain kill(2) on our own child's pid.
    assert_eq!(
        unsafe { libc::kill(cli.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let status = cli.wait().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGTERM), "got {status}");
    assert!(
        !build.outlives_the_cli(),
        "the build kept running after the interrupted CLI was gone"
    );
    assert!(!proj.join(".socket/apply.lock").exists());
    assert_tree(&gem_dir, &copy_before, "the copy is as it was");
    assert!(stage.is_dir(), "the stage is left behind");

    // The copy still checks as unpatched, and the next apply completes.
    let (code, _, _) = ruby.run(&proj, &["apply", "--check"], &[]);
    assert_ne!(code, 0);
    ruby.finish_builds();
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "apply after the interrupt:\n{stdout}\n{stderr}");
    assert!(
        !home.join(".socket-patch-build").exists(),
        "the stale stage is swept"
    );
    assert_eq!(
        std::fs::read_to_string(gem_dir.join("lib/sp_native/3.4/sp_native.so")).unwrap(),
        built_from(&c_source(2))
    );
    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "rollback:\n{stdout}\n{stderr}");
    assert_tree(&gem_dir, &copy_before, "");
}

/// A Ruby that does not run the copy's platform does not own it: nothing
/// is unpacked, built or written.
#[cfg(unix)]
#[test]
fn a_ruby_of_another_platform_does_not_rebuild_a_precompiled_copy() {
    let (_tmp, proj, _gem_dir) = fake_precompiled_gem(true);
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    std::fs::write(ruby.state.join("other-platform"), b"").unwrap();
    let tree_before = walk_files(&proj.join("vendor"));

    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json", "--offline"], &[]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extensions_unsupported"), "{stdout}");
    assert!(
        stdout.contains("does not run x86_64-linux gems"),
        "{stdout}"
    );
    assert_eq!(ruby.calls(), ["extensions_dir"]);
    assert_tree(&proj.join("vendor"), &tree_before, "");
}

// ── the JRuby build of a gem ──────────────────────────────────────────
//
// JRuby installs a gem's `java` platform build, whose compiled code is
// jars. The patch records are written for the `ruby` platform gem, and
// such a copy takes of one what is part of its own build: the files it
// holds, and the files the patch adds that are not inputs of a C build.
// Nothing is built and no Ruby is started. Only a record that changes what
// the jars were built from (their sources, not a jar replaced whole) is
// never attested. A record qualified for a platform is applied whole, and
// a `java` gem that declares extensions is rebuilt like any built gem.

/// The record of the `ruby` platform gem, as the patch service keys it.
const RUBY_PLATFORM_PURL: &str = "pkg:gem/sp_native@1.0.0?platform=ruby";
/// A record written for the `java` platform gem itself.
const JAVA_PLATFORM_PURL: &str = "pkg:gem/sp_native@1.0.0?platform=java";
const JAVA_KEY: &str = "ext/java/sp/SpNative.java";
const JAVA_SOURCE: &str = "class SpNative { int v = 1; }\n";
const PATCHED_JAVA_SOURCE: &str = "class SpNative { int v = 2; }\n";
const PATCHED_RB: &str = "require \"sp_native/sp_native\"\n# patched\n";
/// A patch to a library the `ruby` platform gem packs and compiles.
const LIBRARY_PATCH_KEY: &str = "patches/libxml2/0100-fix.patch";

/// A project with a hand-laid JRuby copy of `sp_native`: its Ruby file,
/// the jar it runs, the Java source of that jar, and the C source of the
/// `ruby` platform gem, which the `java` gem ships too and nothing on
/// JRuby compiles. It has no `patches/` dir.
struct JavaGem {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    gem_dir: PathBuf,
    /// The only `ruby` on the `PATH` the CLI is run with: it records every
    /// call, and none may be made for a JRuby gem.
    #[cfg(unix)]
    ruby: FakeRuby,
    /// `vendor/` as it was laid down.
    pristine: Vec<(String, Vec<u8>)>,
}

impl JavaGem {
    fn new() -> JavaGem {
        let tmp = tempfile::tempdir().unwrap();
        let proj = tmp.path().to_path_buf();
        let home = proj.join("vendor/bundle/jruby/3.1.0");
        let gem_dir = home.join("gems/sp_native-1.0.0-java");
        for (rel, bytes) in [
            (JAVA_KEY, JAVA_SOURCE.as_bytes()),
            (C_KEY, c_source(1).as_bytes()),
            ("lib/sp_native.rb", LIB_RB.as_bytes()),
            ("lib/sp_native/sp_native.jar", b"PK jar"),
        ] {
            let path = gem_dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications/sp_native-1.0.0-java.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"sp_native\".freeze\n  \
             s.version = \"1.0.0\".freeze\n  s.platform = \"java\".freeze\n  \
             s.require_paths = [\"lib\".freeze]\nend\n",
        )
        .unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            "source \"https://rubygems.org\"\ngem \"sp_native\"\n",
        )
        .unwrap();
        let pristine = walk_files(&proj.join("vendor"));
        JavaGem {
            _tmp: tmp,
            proj,
            gem_dir,
            #[cfg(unix)]
            ruby: FakeRuby::new(),
            pristine,
        }
    }

    fn record(&self, purl: &str, entries: &[RecordFile<'_>]) {
        write_record(&self.proj.join(".socket"), purl, entries);
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        #[cfg(unix)]
        let out = self.ruby.run(&self.proj, args, &[]);
        #[cfg(not(unix))]
        let out = run_without_ruby(&self.proj, args);
        out
    }

    fn read(&self, rel: &str) -> String {
        std::fs::read_to_string(self.gem_dir.join(rel)).unwrap()
    }

    /// The gem file `file` as [`walk_files`] of `vendor/` names it.
    fn vendor_rel(&self, file: &str) -> String {
        // Component by component: `gem_dir` was joined from `/` strings,
        // and Windows would keep those separators where the walk has `\`.
        let rel = self.gem_dir.strip_prefix(self.proj.join("vendor")).unwrap();
        let mut path: PathBuf = rel.components().collect();
        path.extend(file.split('/'));
        path.display().to_string()
    }

    /// The event of the gem's record in a `--json` run: its action and
    /// reason code.
    fn event(&self, stdout: &str, purl: &str) -> (String, String) {
        let env = parse_json_envelope(stdout);
        let event = common::envelope::event_for(&env, purl);
        let field = |key: &str| event[key].as_str().unwrap_or_default().to_string();
        (field("action"), field("errorCode"))
    }

    fn attested(&self) -> bool {
        vex_attests(|args| self.run(args))
    }

    /// `vendor/` holds exactly the files of `expected`, and nothing of a
    /// build: no marker, no backup, no stage.
    fn assert_vendor(&self, expected: &[(String, Vec<u8>)], what: &str) {
        assert_tree(&self.proj.join("vendor"), expected, what);
    }

    /// `rollback` succeeds and leaves the install byte for byte as it was
    /// laid down.
    fn assert_rolls_back(&self) {
        let (code, stdout, stderr) = self.run(&["rollback", "--json"]);
        assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
        self.assert_vendor(&self.pristine, "after rollback");
    }

    /// No Ruby was started by any run so far.
    fn assert_no_ruby_ran(&self) {
        #[cfg(unix)]
        assert_eq!(
            self.ruby.calls(),
            Vec::<String>::new(),
            "a Ruby was started for a JRuby gem"
        );
    }
}

/// A patch with a Ruby half and a C half, on a JRuby gem that ships both
/// files: both are written (the C source is dead code there), the copy is
/// in sync and attested with no build and no marker, and `rollback` puts
/// every byte back.
#[test]
fn a_java_gem_takes_the_ruby_and_c_files_it_ships() {
    let gem = JavaGem::new();
    let (c_before, c_after) = (c_source(1), c_source(2));
    gem.record(
        RUBY_PLATFORM_PURL,
        &[
            ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
            (C_KEY, Some(&c_before), &c_after),
        ],
    );
    let patched = tree_with(
        &tree_with(
            &gem.pristine,
            &gem.vendor_rel("lib/sp_native.rb"),
            PATCHED_RB.as_bytes(),
        ),
        &gem.vendor_rel("ext/sp_native/sp_native.c"),
        c_after.as_bytes(),
    );

    let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "an unapplied patch must not check clean: {stdout}");
    assert!(!gem.attested(), "vex attested an unapplied patch");

    let (code, stdout, stderr) = gem.run(&["apply", "--json", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, RUBY_PLATFORM_PURL).0,
        "verified",
        "{stdout}"
    );
    gem.assert_vendor(&gem.pristine, "after a dry run");

    let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, RUBY_PLATFORM_PURL).0,
        "applied",
        "{stdout}"
    );
    let env = parse_json_envelope(&stdout);
    let native: Vec<String> = common::envelope::warning_codes(&env)
        .into_iter()
        .filter(|code| code.starts_with("native_extension"))
        .collect();
    assert_eq!(native, Vec::<String>::new(), "{stdout}");
    gem.assert_vendor(&patched, "after apply");

    let (code, stdout, stderr) = gem.run(&["apply", "--check"]);
    assert_eq!(
        code, 0,
        "the patched copy checks clean:\n{stdout}\n{stderr}"
    );
    assert!(gem.attested(), "vex did not attest the patched copy");

    // Idempotent: nothing left to write.
    let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, RUBY_PLATFORM_PURL),
        ("skipped".to_string(), "already_patched".to_string()),
        "{stdout}"
    );
    gem.assert_vendor(&patched, "after a second apply");

    gem.assert_rolls_back();
    gem.assert_no_ruby_ran();
}

/// A file the patch replaces that the JRuby gem does not ship, and a file
/// it adds that only a C build reads, are not part of that platform's gem:
/// neither is written or missed, and the patch is applied with the rest.
#[test]
fn a_java_gem_skips_the_files_it_has_no_use_for() {
    for purl in [PURL, RUBY_PLATFORM_PURL] {
        let gem = JavaGem::new();
        gem.record(
            purl,
            &[
                ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
                (
                    "ext/sp_native/only_in_the_ruby_gem.c",
                    Some("int before;\n"),
                    "int after;\n",
                ),
                (LIBRARY_PATCH_KEY, None, "a patch to the packed library\n"),
                ("ext/sp_native/new_source.c", None, "int added;\n"),
                // A Ruby file the patch adds is created as on any gem.
                (
                    "lib/sp_native/helper.rb",
                    None,
                    "module SpNativeHelper; end\n",
                ),
            ],
        );
        let patched = tree_with(
            &tree_with(
                &gem.pristine,
                &gem.vendor_rel("lib/sp_native.rb"),
                PATCHED_RB.as_bytes(),
            ),
            &gem.vendor_rel("lib/sp_native/helper.rb"),
            b"module SpNativeHelper; end\n",
        );

        let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
        assert_ne!(code, 0, "{purl}: {stdout}");

        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 0, "{purl}: apply failed:\n{stdout}\n{stderr}");
        assert_eq!(gem.event(&stdout, purl).0, "applied", "{purl}: {stdout}");
        let env = parse_json_envelope(&stdout);
        let mut written: Vec<&str> = common::envelope::event_for(&env, purl)["files"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|file| file["path"].as_str())
            .collect();
        written.sort_unstable();
        assert_eq!(
            written,
            ["lib/sp_native.rb", "lib/sp_native/helper.rb"],
            "{purl}"
        );
        gem.assert_vendor(&patched, purl);

        let (code, stdout, stderr) = gem.run(&["apply", "--check"]);
        assert_eq!(code, 0, "{purl}: {stdout}\n{stderr}");
        assert!(
            gem.attested(),
            "{purl}: vex did not attest the patched copy"
        );
        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 0, "{purl}: {stdout}\n{stderr}");
        assert_eq!(
            gem.event(&stdout, purl),
            ("skipped".to_string(), "already_patched".to_string()),
            "{purl}: {stdout}"
        );

        gem.assert_rolls_back();
        gem.assert_no_ruby_ran();
    }
}

/// A patch that changes nothing but the C build (a new patch to a packed
/// library, a C source the JRuby gem does not ship) has no file in the
/// JRuby build: the run succeeds, writes nothing and says so, and the copy
/// is in sync and attested, because the code the patch fixes is not in it.
#[test]
fn a_patch_of_the_c_build_alone_has_nothing_to_do_on_a_java_gem() {
    for purl in [PURL, RUBY_PLATFORM_PURL] {
        let gem = JavaGem::new();
        gem.record(
            purl,
            &[
                (LIBRARY_PATCH_KEY, None, "a patch to the packed library\n"),
                (
                    "ext/sp_native/only_in_the_ruby_gem.c",
                    Some("int before;\n"),
                    "int after;\n",
                ),
            ],
        );

        for args in [&["apply", "--json", "--dry-run"][..], &["apply", "--json"]] {
            let (code, stdout, stderr) = gem.run(args);
            assert_eq!(code, 0, "{purl} {args:?}: {stdout}\n{stderr}");
            let env = parse_json_envelope(&stdout);
            assert_eq!(env["status"], "success", "{purl} {args:?}: {stdout}");
            assert_eq!(
                gem.event(&stdout, purl),
                ("skipped".to_string(), "not_in_platform_build".to_string()),
                "{purl} {args:?}: {stdout}"
            );
            let reason = common::envelope::event_for(&env, purl)["reason"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(
                reason.contains("none of the patch's files are part of the JRuby build")
                    && reason.contains("sp_native-1.0.0-java"),
                "{purl} {args:?}: {reason}"
            );
            assert_eq!(
                common::envelope::warning_codes(&env),
                Vec::<String>::new(),
                "{purl} {args:?}: {stdout}"
            );
            gem.assert_vendor(&gem.pristine, &format!("{purl} {args:?}"));
        }

        // In plain words for a person, and counted in the summary.
        let (code, stdout, stderr) = gem.run(&["apply"]);
        assert_eq!(code, 0, "{purl}: {stdout}\n{stderr}");
        assert!(
            stderr.contains("none of the patch's files are part of the JRuby build"),
            "{purl}: {stderr}"
        );
        assert!(
            stdout.contains("0 of 1 targeted patch applied") && stdout.contains("1 not applicable"),
            "{purl}: {stdout}"
        );
        assert!(!stderr.contains("Error"), "{purl}: {stderr}");

        let (code, stdout, stderr) = gem.run(&["apply", "--check"]);
        assert_eq!(code, 0, "{purl}: {stdout}\n{stderr}");
        assert!(gem.attested(), "{purl}: vex did not attest the copy");
        gem.assert_vendor(&gem.pristine, purl);

        // The statement is truthful about why: nothing was patched here.
        // The code is not in this build.
        let document = vex_document(|args| gem.run(args)).expect("a vex document");
        let statement = &document["statements"][0];
        assert_eq!(statement["status"], "not_affected", "{document:#}");
        assert_eq!(
            statement["justification"], "vulnerable_code_not_present",
            "{purl}: {document:#}"
        );
        let impact = statement["impact_statement"].as_str().unwrap_or_default();
        assert!(
            impact.contains("is not in the installed build of the package")
                && impact.contains(UUID)
                && !impact.contains("Patched via"),
            "{purl}: {impact}"
        );

        // `rollback` says what is true too: nothing of the patch was
        // applied to this build, so there is nothing to restore. Not that
        // the record lists no files.
        for args in [
            &["rollback", "--json", "--dry-run"][..],
            &["rollback", "--json"],
        ] {
            let (code, stdout, stderr) = gem.run(args);
            assert_eq!(code, 0, "{purl} {args:?}:\n{stdout}\n{stderr}");
            let env = parse_json_envelope(&stdout);
            let event = env["events"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|e| e["purl"] == purl && e["action"] == "skipped")
                .unwrap_or_else(|| panic!("{purl} {args:?}: no skip:\n{stdout}"));
            assert_eq!(
                event["errorCode"], "not_in_platform_build",
                "{purl} {args:?}: {stdout}"
            );
            assert!(
                event["reason"]
                    .as_str()
                    .is_some_and(|reason| reason.contains("there is nothing to restore")),
                "{purl} {args:?}: {stdout}"
            );
            assert!(!stdout.contains("no_files"), "{purl} {args:?}: {stdout}");
            gem.assert_vendor(&gem.pristine, &format!("{purl} {args:?}"));
        }
        gem.assert_no_ruby_ran();
    }
}

/// A Ruby file is part of every build of a gem. One that the patch
/// replaces and the JRuby copy does not hold (it was deleted) is the usual
/// missing file: the patch fails, and the copy is neither in sync nor
/// attested. It is never taken for a patch with nothing to do there.
#[test]
fn a_ruby_file_missing_from_a_java_gem_is_a_missing_file() {
    for purl in [PURL, RUBY_PLATFORM_PURL] {
        let gem = JavaGem::new();
        std::fs::remove_file(gem.gem_dir.join("lib/sp_native.rb")).unwrap();
        let without = walk_files(&gem.proj.join("vendor"));
        gem.record(purl, &[("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB)]);

        for args in [&["apply", "--json"][..], &["apply", "--json", "--dry-run"]] {
            let (code, stdout, stderr) = gem.run(args);
            assert_eq!(code, 1, "{purl} {args:?}: {stdout}\n{stderr}");
            assert!(
                !stdout.contains("not_in_platform_build"),
                "{purl} {args:?}: {stdout}"
            );
            let env = parse_json_envelope(&stdout);
            assert_eq!(env["summary"]["applied"], 0, "{purl} {args:?}: {stdout}");
            gem.assert_vendor(&without, &format!("{purl} {args:?}"));
        }
        let (_, stdout, _) = gem.run(&["apply", "--json"]);
        let env = parse_json_envelope(&stdout);
        let event = common::envelope::event_for(&env, purl);
        if purl == PURL {
            // The unqualified record reaches the apply, which names the file.
            assert_eq!(event["action"], "failed", "{stdout}");
            assert!(
                event["error"].as_str().is_some_and(
                    |e| e.contains("lib/sp_native.rb") && e.contains("File not found")
                ),
                "{stdout}"
            );
        } else {
            // A qualified record is matched to a copy by the files it
            // replaces: with its one file gone, the copy is not one this
            // record can be told to belong to.
            assert_eq!(event["errorCode"], "package_not_installed", "{stdout}");
        }
        let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
        assert_ne!(code, 0, "{purl}: {stdout}");
        assert!(!gem.attested(), "{purl}: vex attested a missing file");
        gem.assert_no_ruby_ran();
    }
}

/// A record that brings the compiled code is the patch, whatever source
/// it changes beside it: the record written for the `java` gem itself (the
/// rebuilt jar and the source it was rebuilt from, or the gem's own diff
/// of a source), and a ruby-platform record that replaces the jar. Its
/// files are written, the copy is in sync and attested, and a second run
/// has nothing to do. It is not held up as a patch whose jars were not
/// rebuilt.
#[test]
fn a_record_that_brings_the_jar_is_not_held_up_by_its_source() {
    const JAR_KEY: &str = "lib/sp_native/sp_native.jar";
    let jar: RecordFile<'_> = (JAR_KEY, Some("PK jar"), "PK patched jar");
    let source: RecordFile<'_> = (JAVA_KEY, Some(JAVA_SOURCE), PATCHED_JAVA_SOURCE);
    let cases: [(&str, &str, &[RecordFile<'_>]); 3] = [
        (
            "the java gem's jar and source",
            JAVA_PLATFORM_PURL,
            &[jar, source],
        ),
        ("the java gem's own source", JAVA_PLATFORM_PURL, &[source]),
        (
            "a ruby record with the jar",
            RUBY_PLATFORM_PURL,
            &[jar, source],
        ),
    ];
    for (case, purl, entries) in cases {
        let gem = JavaGem::new();
        gem.record(purl, entries);
        let mut patched = gem.pristine.clone();
        for (key, _, after) in entries {
            patched = tree_with(&patched, &gem.vendor_rel(key), after.as_bytes());
        }

        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 0, "{case}: apply failed:\n{stdout}\n{stderr}");
        assert_eq!(gem.event(&stdout, purl).0, "applied", "{case}: {stdout}");
        assert!(
            !stdout.contains("native_extension"),
            "{case}: the record brings its compiled code: {stdout}"
        );
        gem.assert_vendor(&patched, case);

        let (code, stdout, stderr) = gem.run(&["apply", "--check"]);
        assert_eq!(code, 0, "{case}: {stdout}\n{stderr}");
        assert!(gem.attested(), "{case}: vex did not attest the patch");
        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 0, "{case}: {stdout}\n{stderr}");
        assert_eq!(
            gem.event(&stdout, purl),
            ("skipped".to_string(), "already_patched".to_string()),
            "{case}: {stdout}"
        );

        gem.assert_rolls_back();
        gem.assert_no_ruby_ran();
    }
}

/// With a record for the copy's own platform in the manifest, that record
/// is the copy's, and the ruby-platform record of the same version is not
/// the copy's for any reader: `apply` does not apply it there and reports
/// it as not installed, `apply --check` does not count it as in sync, and
/// `vex` does not attest it.
#[test]
fn the_copys_own_record_is_its_only_record_for_every_reader() {
    const JAR_KEY: &str = "lib/sp_native/sp_native.jar";
    const OWN_UUID: &str = "29962996-2996-4996-8996-299629962996";
    let gem = JavaGem::new();
    let socket = gem.proj.join(".socket");
    let record = |uuid: &str, key: &str, before: Option<&str>, after: &str| {
        let before_hash = before.map(|b| git_sha256(b.as_bytes())).unwrap_or_default();
        if let Some(before) = before {
            write_blob(&socket, &before_hash, before.as_bytes());
        }
        write_blob(&socket, &git_sha256(after.as_bytes()), after.as_bytes());
        serde_json::json!({
            "uuid": uuid,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { key: {
                "beforeHash": before_hash,
                "afterHash": git_sha256(after.as_bytes()),
            }},
            "vulnerabilities": { "GHSA-aaaa-bbbb-cccc": {
                "cves": ["CVE-2026-0001"], "summary": "s", "severity": "HIGH",
                "description": "d",
            }},
            "description": "synthetic test patch",
            "license": "MIT",
            "tier": "free",
        })
    };
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = serde_json::json!({ "patches": {
        RUBY_PLATFORM_PURL: record(UUID, LIBRARY_PATCH_KEY, None, "a patch to the packed library\n"),
        JAVA_PLATFORM_PURL: record(OWN_UUID, JAR_KEY, Some("PK jar"), "PK patched jar"),
    }});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let patched = tree_with(&gem.pristine, &gem.vendor_rel(JAR_KEY), b"PK patched jar");

    let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, JAVA_PLATFORM_PURL).0,
        "applied",
        "{stdout}"
    );
    assert_eq!(
        gem.event(&stdout, RUBY_PLATFORM_PURL),
        ("skipped".to_string(), "package_not_installed".to_string()),
        "{stdout}"
    );
    gem.assert_vendor(&patched, "after apply");

    // `apply --check`: the copy's record is in sync, and the ruby record
    // is no patch of this copy, exactly as `apply` reported it.
    let (code, stdout, stderr) = gem.run(&["apply", "--check", "--json"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, JAVA_PLATFORM_PURL),
        ("skipped".to_string(), "already_patched".to_string()),
        "{stdout}"
    );
    assert_eq!(
        gem.event(&stdout, RUBY_PLATFORM_PURL),
        ("skipped".to_string(), "package_not_installed".to_string()),
        "{stdout}"
    );

    // `vex` attests the copy's record, and not the ruby one.
    let document = vex_document(|args| gem.run(args)).expect("a vex document");
    assert_eq!(
        vex_subcomponents(&document),
        [JAVA_PLATFORM_PURL],
        "{document:#}"
    );
    let impact = document["statements"][0]["impact_statement"]
        .as_str()
        .unwrap_or_default();
    assert!(
        impact.contains(OWN_UUID) && !impact.contains(UUID),
        "{impact}"
    );
    gem.assert_no_ruby_ran();
}

/// A package with one copy that applied and one whose patch is incomplete
/// is not in effect: the run fails, each copy has its own event, and the
/// package is neither listed as patched nor counted as applied.
#[test]
fn a_package_with_a_patched_and_an_incomplete_copy_is_not_in_effect() {
    let gem = JavaGem::new();
    // The same gem as a plain `ruby` platform install in another store of
    // the project: no extension, no jar, so the record is plain files.
    let home = gem.proj.join("vendor/bundle/ruby/3.4.0");
    let plain = home.join("gems").join(FULL_NAME);
    for (rel, bytes) in [
        (JAVA_KEY, JAVA_SOURCE.as_bytes()),
        ("lib/sp_native.rb", LIB_RB.as_bytes()),
    ] {
        let path = plain.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join("specifications")
            .join(format!("{FULL_NAME}.gemspec")),
        "Gem::Specification.new do |s|\n  s.name = \"sp_native\".freeze\n  \
         s.version = \"1.0.0\".freeze\n  s.require_paths = [\"lib\".freeze]\nend\n",
    )
    .unwrap();
    gem.record(
        PURL,
        &[
            (JAVA_KEY, Some(JAVA_SOURCE), PATCHED_JAVA_SOURCE),
            ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
        ],
    );

    let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(env["status"], "partialFailure", "{stdout}");
    let mut actions: Vec<(String, String)> = env["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["purl"] == PURL)
        .map(|e| {
            let field = |key: &str| e[key].as_str().unwrap_or_default().to_string();
            (field("action"), field("errorCode"))
        })
        .collect();
    actions.sort();
    assert_eq!(
        actions,
        [
            ("applied".to_string(), String::new()),
            (
                "failed".to_string(),
                "native_extension_not_rebuilt".to_string()
            ),
        ],
        "each copy has its own event: {stdout}"
    );
    // Both copies hold the patch's files.
    for dir in [&plain, &gem.gem_dir] {
        assert_eq!(
            std::fs::read_to_string(dir.join("lib/sp_native.rb")).unwrap(),
            PATCHED_RB,
            "{}",
            dir.display()
        );
    }

    // A second run: one copy already patched, one still incomplete. The
    // package is not in effect, and never listed or counted as patched.
    let (code, stdout, stderr) = gem.run(&["apply"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert_eq!(
        stderr
            .matches(&format!("Error: Patch of {PURL} is incomplete:"))
            .count(),
        1,
        "{stderr}"
    );
    assert!(!stdout.contains("Patched packages:"), "{stdout}");
    assert!(
        stdout.contains("0 of 1 targeted patch applied, 0 already patched, 1 not in effect"),
        "{stdout}"
    );
    let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");
    assert!(
        !gem.attested(),
        "vex attested a package that is not in effect"
    );
    gem.assert_no_ruby_ran();
}

/// The jars a JRuby gem runs were built from its Java sources, and nothing
/// here rebuilds a jar: a patch that changes one has its files written and
/// is incomplete. The run fails (exit 1) and says that the jars are not
/// the patch's, the files stay written, and neither `apply --check` nor
/// `vex` ever takes the copy for patched. `rollback` restores the tree.
#[test]
fn a_patch_to_a_java_gems_sources_is_written_and_fails_as_incomplete() {
    let jars_not_rebuilt = "the gem's jars were built from Java sources the patch changes";
    for purl in [PURL, RUBY_PLATFORM_PURL] {
        let gem = JavaGem::new();
        gem.record(
            purl,
            &[
                (JAVA_KEY, Some(JAVA_SOURCE), PATCHED_JAVA_SOURCE),
                ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
                (LIBRARY_PATCH_KEY, None, "a patch to the packed library\n"),
            ],
        );
        let patched = tree_with(
            &tree_with(
                &gem.pristine,
                &gem.vendor_rel("lib/sp_native.rb"),
                PATCHED_RB.as_bytes(),
            ),
            &gem.vendor_rel("ext/java/sp/SpNative.java"),
            PATCHED_JAVA_SOURCE.as_bytes(),
        );

        // Files alone show what a real run comes to, so a dry run fails
        // the same way, says what apply would leave undone, and writes
        // nothing.
        let (code, stdout, stderr) = gem.run(&["apply", "--json", "--dry-run"]);
        assert_eq!(code, 1, "{purl}: {stdout}\n{stderr}");
        let event = incomplete_event(&stdout, purl);
        let error = event["error"].as_str().unwrap_or_default();
        assert!(
            error.starts_with("dry run: apply would write the patch's files")
                && error.contains(jars_not_rebuilt),
            "{purl}: {stdout}"
        );
        assert_eq!(event_files(&event), Vec::<String>::new(), "{purl}");
        gem.assert_vendor(&gem.pristine, &format!("{purl} after a dry run"));

        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 1, "{purl}: {stdout}\n{stderr}");
        let event = incomplete_event(&stdout, purl);
        let error = event["error"].as_str().unwrap_or_default();
        assert!(
            error.starts_with("the patch's files were written")
                && error.contains(jars_not_rebuilt)
                && error.contains(JAVA_KEY),
            "{purl}: {stdout}"
        );
        // The files it takes are written and stay written.
        assert_eq!(
            event_files(&event),
            [JAVA_KEY, "lib/sp_native.rb"],
            "{purl}: {stdout}"
        );
        gem.assert_vendor(&patched, purl);
        assert_eq!(gem.read("lib/sp_native/sp_native.jar"), "PK jar");

        // The patched source beside the old jar is not a patched gem.
        let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
        assert_ne!(code, 0, "{purl}: {stdout}");
        assert!(
            stdout.contains("native_extension_not_rebuilt"),
            "{purl}: {stdout}"
        );
        assert!(
            !gem.attested(),
            "{purl}: vex attested a jar that was not rebuilt"
        );

        // A second run has nothing to write, and the patch is as
        // incomplete as it was.
        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 1, "{purl}: {stdout}\n{stderr}");
        let event = incomplete_event(&stdout, purl);
        assert_eq!(event_files(&event), Vec::<String>::new(), "{purl}");
        assert!(!stdout.contains("already_patched"), "{purl}: {stdout}");
        gem.assert_vendor(&patched, &format!("{purl} after a second apply"));

        gem.assert_rolls_back();
        gem.assert_no_ruby_ran();
    }

    // A Java source the gem does not even ship: nothing to write, and the
    // jar may still hold the code, so the patch is incomplete as well.
    let gem = JavaGem::new();
    gem.record(
        RUBY_PLATFORM_PURL,
        &[(
            "ext/java/sp/NotShipped.java",
            Some("class NotShipped { int v = 1; }\n"),
            "class NotShipped { int v = 2; }\n",
        )],
    );
    let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let event = incomplete_event(&stdout, RUBY_PLATFORM_PURL);
    let error = event["error"].as_str().unwrap_or_default();
    assert!(
        error.contains(jars_not_rebuilt) && error.contains("Nothing was written"),
        "{stdout}"
    );
    assert_eq!(event_files(&event), Vec::<String>::new(), "{stdout}");
    gem.assert_vendor(&gem.pristine, "a record of a Java source it does not ship");
    // For a person: one error line, and a summary that does not read as
    // done.
    let (code, stdout, stderr) = gem.run(&["apply"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        stderr.contains(&format!(
            "Error: Patch of {RUBY_PLATFORM_PURL} is incomplete:"
        )) && stderr.contains(jars_not_rebuilt),
        "{stderr}"
    );
    assert_eq!(stderr.matches(jars_not_rebuilt).count(), 1, "{stderr}");
    assert!(
        stdout.contains("1 not in effect") && !stdout.contains("not applicable"),
        "{stdout}"
    );
    let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");
    assert!(!gem.attested(), "vex attested a jar that was not rebuilt");
    gem.assert_rolls_back();
    gem.assert_no_ruby_ran();
}

/// `--no-gem-native-rebuild` leaves compiling to the caller, on JRuby as
/// anywhere: a patch to a Java source the gem ships is written, the run
/// succeeds with the `native_extension_not_rebuilt` warning that names the
/// flag, and nothing attests the copy until the caller's build is one
/// `apply` knows of.
#[test]
fn the_opt_out_leaves_a_java_gems_jars_to_the_caller() {
    let gem = JavaGem::new();
    gem.record(
        RUBY_PLATFORM_PURL,
        &[
            (JAVA_KEY, Some(JAVA_SOURCE), PATCHED_JAVA_SOURCE),
            ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
        ],
    );
    let patched = tree_with(
        &tree_with(
            &gem.pristine,
            &gem.vendor_rel("lib/sp_native.rb"),
            PATCHED_RB.as_bytes(),
        ),
        &gem.vendor_rel("ext/java/sp/SpNative.java"),
        PATCHED_JAVA_SOURCE.as_bytes(),
    );
    // A dry run writes nothing, and says what apply would do.
    let (code, stdout, stderr) =
        gem.run(&["apply", "--json", "--dry-run", "--no-gem-native-rebuild"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let warning = not_rebuilt_warning(&stdout);
    assert!(
        warning.contains("dry run")
            && warning.contains("apply would write them without rebuilding the jars")
            && warning.contains("(--no-gem-native-rebuild)")
            && !warning.contains(", written "),
        "{warning}"
    );
    gem.assert_vendor(&gem.pristine, "after a dry run with the opt-out");

    let (code, stdout, stderr) = gem.run(&["apply", "--json", "--no-gem-native-rebuild"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, RUBY_PLATFORM_PURL).0,
        "applied",
        "{stdout}"
    );
    let warning = not_rebuilt_warning(&stdout);
    assert!(
        warning.contains("written without rebuilding them (--no-gem-native-rebuild)")
            && warning.contains(JAVA_KEY),
        "{stdout}"
    );
    gem.assert_vendor(&patched, "with the opt-out");
    let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");
    assert!(!gem.attested(), "vex attested a jar that was not rebuilt");
    gem.assert_rolls_back();
    gem.assert_no_ruby_ran();
}

/// A jar the record replaces whole is the code JRuby loads: it is written
/// like any file of the patch, with no warning, and the copy is in sync
/// and attested. Only the sources of a jar cannot take effect here.
#[test]
fn a_jar_the_patch_replaces_whole_is_written_and_attested() {
    const JAR_KEY: &str = "lib/sp_native/sp_native.jar";
    for purl in [PURL, RUBY_PLATFORM_PURL] {
        let gem = JavaGem::new();
        gem.record(
            purl,
            &[
                (JAR_KEY, Some("PK jar"), "PK patched jar"),
                ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
            ],
        );
        let patched = tree_with(
            &tree_with(
                &gem.pristine,
                &gem.vendor_rel("lib/sp_native.rb"),
                PATCHED_RB.as_bytes(),
            ),
            &gem.vendor_rel(JAR_KEY),
            b"PK patched jar",
        );

        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 0, "{purl}: apply failed:\n{stdout}\n{stderr}");
        assert_eq!(gem.event(&stdout, purl).0, "applied", "{purl}: {stdout}");
        assert!(
            !stdout.contains("native_extension"),
            "{purl}: a replaced jar is no build input: {stdout}"
        );
        gem.assert_vendor(&patched, purl);

        let (code, stdout, stderr) = gem.run(&["apply", "--check"]);
        assert_eq!(code, 0, "{purl}: {stdout}\n{stderr}");
        assert!(gem.attested(), "{purl}: vex did not attest the patched jar");
        let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
        assert_eq!(code, 0, "{purl}: {stdout}\n{stderr}");
        assert_eq!(
            gem.event(&stdout, purl),
            ("skipped".to_string(), "already_patched".to_string()),
            "{purl}: {stdout}"
        );

        gem.assert_rolls_back();
        gem.assert_no_ruby_ran();
    }
}

/// The per-file rule is for the record of the `ruby` platform gem. A
/// record qualified for a platform names the archive it was written for,
/// the copy's own `java` included: every file of it is required, so a file
/// the copy lacks fails the patch like any missing file, and a file it
/// adds is created wherever it goes.
#[test]
fn a_record_qualified_for_a_platform_is_applied_whole_on_a_java_gem() {
    // A file the copy does not hold: the usual failure, nothing written.
    for purl in [
        JAVA_PLATFORM_PURL,
        "pkg:gem/sp_native@1.0.0?platform=x86_64-linux",
    ] {
        let gem = JavaGem::new();
        gem.record(
            purl,
            &[
                ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
                (
                    "lib/sp_native/zz_not_in_this_gem.rb",
                    Some("before\n"),
                    "after\n",
                ),
            ],
        );
        for args in [&["apply", "--json"][..], &["apply", "--json", "--dry-run"]] {
            let (code, stdout, stderr) = gem.run(args);
            assert_eq!(code, 1, "{purl} {args:?}: {stdout}\n{stderr}");
            assert_eq!(gem.event(&stdout, purl).0, "failed", "{purl}: {stdout}");
            assert!(
                stdout.contains("zz_not_in_this_gem.rb"),
                "{purl} {args:?}: the missing file is named: {stdout}"
            );
            gem.assert_vendor(&gem.pristine, &format!("{purl} {args:?}"));
        }
        let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
        assert_ne!(code, 0, "{purl}: {stdout}");
        assert!(!gem.attested(), "{purl}: vex attested a failed patch");
        gem.assert_no_ruby_ran();
    }

    // A file it adds under `patches/` is part of that record's gem.
    let gem = JavaGem::new();
    gem.record(
        JAVA_PLATFORM_PURL,
        &[
            ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
            (LIBRARY_PATCH_KEY, None, "a file of the java gem's record\n"),
        ],
    );
    let patched = tree_with(
        &tree_with(
            &gem.pristine,
            &gem.vendor_rel("lib/sp_native.rb"),
            PATCHED_RB.as_bytes(),
        ),
        &gem.vendor_rel(LIBRARY_PATCH_KEY),
        b"a file of the java gem's record\n",
    );
    let (code, stdout, stderr) = gem.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        gem.event(&stdout, JAVA_PLATFORM_PURL).0,
        "applied",
        "{stdout}"
    );
    gem.assert_vendor(&patched, "the java record");
    let (code, stdout, stderr) = gem.run(&["apply", "--check"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(gem.attested(), "vex did not attest the java record");
    gem.assert_rolls_back();
    gem.assert_no_ruby_ran();
}

/// A `java` gem whose gemspec declares extensions is no JRuby build of a
/// gem in this sense: RubyGems compiled something for it when it was
/// installed (jruby-launcher builds a native launcher), so a patch to that
/// source is rebuilt like any built gem's. Without a Ruby it is refused
/// with nothing written; it is never written and attested without a build.
#[cfg(unix)]
#[test]
fn a_java_gem_that_declares_extensions_keeps_the_native_rebuild() {
    const BUILT_JAVA: &str = "sp_native-1.0.0-java";
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().to_path_buf();
    let home = proj.join("vendor/bundle/jruby/3.4.0");
    let gem_dir = home.join("gems").join(BUILT_JAVA);
    std::fs::create_dir_all(gem_dir.join("ext/sp_native")).unwrap();
    std::fs::create_dir_all(gem_dir.join("lib/sp_native")).unwrap();
    std::fs::write(gem_dir.join(C_KEY), c_source(1)).unwrap();
    std::fs::write(gem_dir.join("lib/sp_native.rb"), LIB_RB).unwrap();
    std::fs::write(
        gem_dir.join("lib/sp_native/sp_native.so"),
        b"\x7fELF original",
    )
    .unwrap();
    let ext = home.join("extensions/x86_64-linux/3.4.0").join(BUILT_JAVA);
    std::fs::create_dir_all(ext.join("sp_native")).unwrap();
    std::fs::write(ext.join("sp_native/sp_native.so"), b"\x7fELF original").unwrap();
    std::fs::write(ext.join("gem.build_complete"), b"").unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join("specifications")
            .join(format!("{BUILT_JAVA}.gemspec")),
        "Gem::Specification.new do |s|\n  s.name = \"sp_native\".freeze\n  \
         s.version = \"1.0.0\".freeze\n  s.platform = \"java\".freeze\n  \
         s.require_paths = [\"lib\".freeze]\n  \
         s.extensions = [\"ext/sp_native/extconf.rb\".freeze]\nend\n",
    )
    .unwrap();
    std::fs::write(
        proj.join("Gemfile"),
        "source \"https://rubygems.org\"\ngem \"sp_native\"\n",
    )
    .unwrap();
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    let tree_before = walk_files(&proj.join("vendor"));

    // No Ruby to build with: refused, and nothing is written.
    let (code, stdout, stderr) = run_without_ruby(&proj, &["apply", "--json"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extensions_unsupported"), "{stdout}");
    assert_tree(&proj.join("vendor"), &tree_before, "without a Ruby");
    let (code, stdout, _) = run_without_ruby(&proj, &["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");

    // With the Ruby that owns the install: built by RubyGems' builder.
    let ruby = FakeRuby::new();
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--json"], &[]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(ruby.calls(), ["extensions_dir", "build"]);
    assert_eq!(
        std::fs::read_to_string(gem_dir.join(C_KEY)).unwrap(),
        c_source(2)
    );
    assert_eq!(
        std::fs::read(gem_dir.join("lib/sp_native/sp_native.so")).unwrap(),
        b"rebuilt"
    );
    assert!(gem_dir.join(".socket-patch-native-build.json").is_file());
    let (code, stdout, stderr) = ruby.run(&proj, &["apply", "--check"], &[]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");

    // The patched source over the install-time build is not a patched gem.
    let (code, stdout, stderr) = ruby.run(&proj, &["rollback", "--json"], &[]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "after rollback");
    write_manifest(&proj.join(".socket"), &c_source(1), &c_source(2));
    std::fs::write(gem_dir.join(C_KEY), c_source(2)).unwrap();
    let (code, stdout, _) = run_without_ruby(&proj, &["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");
    assert!(stdout.contains("native_extension_not_rebuilt"), "{stdout}");
}

/// A file the JRuby gem ships is held to the record like any patch file:
/// content that is neither the record's original nor its patched bytes
/// fails the patch, and nothing of it is written.
#[test]
fn a_mismatching_file_of_a_java_gem_still_fails() {
    for purl in [PURL, RUBY_PLATFORM_PURL] {
        let gem = JavaGem::new();
        std::fs::write(gem.gem_dir.join(C_KEY), c_source(7)).unwrap();
        let modified = walk_files(&gem.proj.join("vendor"));
        let (c_before, c_after) = (c_source(1), c_source(2));
        gem.record(
            purl,
            &[
                ("lib/sp_native.rb", Some(LIB_RB), PATCHED_RB),
                (C_KEY, Some(&c_before), &c_after),
                (LIBRARY_PATCH_KEY, None, "a patch to the packed library\n"),
            ],
        );

        for args in [&["apply", "--json"][..], &["apply", "--json", "--dry-run"]] {
            let (code, stdout, stderr) = gem.run(args);
            assert_eq!(code, 1, "{purl} {args:?}: {stdout}\n{stderr}");
            assert!(
                !stdout.contains("native_extension"),
                "{purl} {args:?}: a mismatch is no build refusal: {stdout}"
            );
            gem.assert_vendor(&modified, &format!("{purl} {args:?}"));
        }
        let (code, stdout, _) = gem.run(&["apply", "--check", "--json"]);
        assert_ne!(code, 0, "{purl}: {stdout}");
        assert!(!gem.attested(), "{purl}: vex attested a mismatching copy");
        gem.assert_no_ruby_ran();
    }
}

// ── the capstones: a real build from a real source gem ────────────────

/// `sp_archive`: a C-extension gem shaped like nokogiri. Its `extconf.rb`
/// builds from files outside `ext/` (`ports/value.txt`, the names under
/// `patches/`), needs a helper gem (`sp_portile`, as nokogiri needs
/// `mini_portile2`) and deletes `ports/` once it has read it, so an
/// installed copy cannot be rebuilt in place. What it compiled in is read
/// back through `SpArchive.describe`.
const ARCHIVE_PURL: &str = "pkg:gem/sp_archive@1.0.0";
const ARCHIVE_EXTCONF: &str = r##"require "mkmf"
require "fileutils"
gem "sp_portile", "~> 1.0"
require "sp_portile"
root = File.expand_path("../..", __dir__)
ports = File.join(root, "ports")
value = File.join(ports, "value.txt")
unless File.file?(value)
  abort "ports/value.txt is not there: the build of an installed copy removed it"
end
patches = Dir[File.join(root, "patches", "*.patch")].map { |p| File.basename(p) }.sort
File.write("sp_config.h", <<~HEADER)
  #define SP_VALUE #{Integer(File.read(value).strip)}
  #define SP_PATCHES "#{patches.join(",")}"
  #define SP_PORTILE "#{SpPortile::VERSION}"
HEADER
create_makefile("sp_archive/sp_archive")
FileUtils.rm_rf(ports)
"##;
const ARCHIVE_LIB: &str =
    "begin\n  require \"sp_archive/#{RUBY_VERSION[/\\d+\\.\\d+/]}/sp_archive\"\n\
                           rescue LoadError\n  require \"sp_archive/sp_archive\"\nend\n";
const ARCHIVE_GEMSPEC: &str = "Gem::Specification.new do |s|\n  s.name = \"sp_archive\"\n  \
    s.version = \"1.0.0\"\n  s.summary = \"t\"\n  s.authors = [\"t\"]\n  \
    s.files = Dir[\"lib/**/*.rb\", \"ext/**/*.{c,rb}\", \"patches/*\", \"ports/*\"]\n  \
    s.extensions = [\"ext/sp_archive/extconf.rb\"]\n  \
    s.add_runtime_dependency \"sp_portile\", \"~> 1.0\"\nend\n";
const ARCHIVE_C_KEY: &str = "ext/sp_archive/sp_archive.c";
const ORIGINAL_BUILD: &str = "base=1 value=40 patches=0001-base.patch portile=1.0.2";
const PATCHED_BUILD: &str =
    "base=2 value=41 patches=0001-base.patch,0100-CVE-test.patch portile=1.0.2";

fn archive_c(base: u32) -> String {
    format!(
        "#include \"ruby.h\"\n#include \"sp_config.h\"\n#define SP_BASE {base}\n\
         static VALUE sp_describe(VALUE self) {{\n  \
         return rb_sprintf(\"base=%d value=%d patches=%s portile=%s\", SP_BASE, SP_VALUE, \
         SP_PATCHES, SP_PORTILE);\n}}\n\
         void Init_sp_archive(void) {{\n  \
         VALUE m = rb_define_module(\"SpArchive\");\n  \
         rb_define_singleton_method(m, \"describe\", sp_describe, 0);\n}}\n"
    )
}

/// Run `gem <args>` in `dir`, with a scratch `HOME` and `env` on top.
fn gem(scratch: &Path, dir: &Path, args: &[&str], env: &[(&str, &Path)]) {
    let user_home = scratch.join("gem-user-home");
    std::fs::create_dir_all(&user_home).unwrap();
    let mut cmd = Command::new("gem");
    cmd.args(args).current_dir(dir).env("HOME", &user_home);
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("gem {args:?}: {e}"));
    assert!(
        out.status.success(),
        "gem {args:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// One line of the host Ruby's output for `program`.
fn ruby_says(program: &str) -> String {
    let out = Command::new("ruby")
        .args(["-e", program])
        .env_remove("RUBYOPT")
        .output()
        .unwrap();
    assert!(out.status.success(), "ruby -e {program:?} failed");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// The built `sp_archive-1.0.0.gem` and `sp_portile-1.0.2.gem`, and a
/// project whose `vendor/bundle/ruby/<abi>` home holds one installed copy.
struct ArchiveFixture {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    home: PathBuf,
    /// The installed copy: `gems/sp_archive-1.0.0[-<platform>]`.
    gem_dir: PathBuf,
    /// `sp_archive-1.0.0.gem`, outside the project.
    source_gem: PathBuf,
    /// `sp_portile-1.0.2.gem`, outside the project.
    portile_gem: PathBuf,
}

impl ArchiveFixture {
    /// Build both gems, and install `sp_archive` into the project's home:
    /// from source with RubyGems' own build (`precompiled: false`), or as
    /// the platform gem a gem author would publish, built from that
    /// compiled extension in the rake-compiler layout and installed with
    /// no `sp_portile` and no source archive beside it.
    fn new(abi: &str, precompiled: bool) -> ArchiveFixture {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = tmp.path().to_path_buf();
        let portile = scratch.join("sp_portile");
        std::fs::create_dir_all(portile.join("lib")).unwrap();
        std::fs::write(
            portile.join("lib/sp_portile.rb"),
            "module SpPortile; VERSION = \"1.0.2\"; end\n",
        )
        .unwrap();
        std::fs::write(
            portile.join("sp_portile.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"sp_portile\"\n  s.version = \"1.0.2\"\n  \
             s.summary = \"t\"\n  s.authors = [\"t\"]\n  s.files = [\"lib/sp_portile.rb\"]\nend\n",
        )
        .unwrap();
        gem(&scratch, &portile, &["build", "sp_portile.gemspec"], &[]);
        let portile_gem = portile.join("sp_portile-1.0.2.gem");

        let src = scratch.join("sp_archive");
        std::fs::create_dir_all(src.join("ext/sp_archive")).unwrap();
        std::fs::create_dir_all(src.join("lib")).unwrap();
        std::fs::create_dir_all(src.join("patches")).unwrap();
        std::fs::create_dir_all(src.join("ports")).unwrap();
        std::fs::write(src.join("ext/sp_archive/extconf.rb"), ARCHIVE_EXTCONF).unwrap();
        std::fs::write(src.join(ARCHIVE_C_KEY), archive_c(1)).unwrap();
        std::fs::write(src.join("lib/sp_archive.rb"), ARCHIVE_LIB).unwrap();
        std::fs::write(src.join("patches/0001-base.patch"), BASE_PATCH).unwrap();
        std::fs::write(src.join("ports/value.txt"), "40\n").unwrap();
        std::fs::write(src.join("sp_archive.gemspec"), ARCHIVE_GEMSPEC).unwrap();
        gem(&scratch, &src, &["build", "sp_archive.gemspec"], &[]);
        let source_gem = src.join("sp_archive-1.0.0.gem");

        let proj = scratch.join("proj");
        let home = proj.join("vendor/bundle/ruby").join(abi);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            "source \"https://rubygems.org\"\ngem \"sp_archive\"\n",
        )
        .unwrap();
        // RubyGems' own install: `sp_portile`, then `sp_archive`, whose
        // `extconf.rb` finds it in the home it is installed into.
        let install_from_source = |into: &Path| {
            let install = [
                "install",
                "--local",
                "--no-document",
                "--ignore-dependencies",
                "--install-dir",
            ];
            let into_str = into.to_str().unwrap();
            for archive in [&portile_gem, &source_gem] {
                let args = [&install[..], &[into_str, archive.to_str().unwrap()]].concat();
                gem(
                    &scratch,
                    &scratch,
                    &args,
                    &[("GEM_HOME", into), ("GEM_PATH", into)],
                );
            }
        };
        if !precompiled {
            install_from_source(&home);
            let gem_dir = home.join("gems/sp_archive-1.0.0");
            assert!(
                !gem_dir.join("ports").exists(),
                "the fixture's build removes ports/"
            );
            return ArchiveFixture {
                _tmp: tmp,
                proj,
                home,
                gem_dir,
                source_gem,
                portile_gem,
            };
        }

        // The compiled extension, from a build outside the project.
        let build_home = scratch.join("build-home");
        std::fs::create_dir_all(&build_home).unwrap();
        install_from_source(&build_home);
        let dlext = ruby_says("print RbConfig::CONFIG['DLEXT']");
        let minor = ruby_says("print RUBY_VERSION[/\\d+\\.\\d+/]");
        let platform = ruby_says("p = Gem::Platform.local; print \"#{p.cpu}-#{p.os}\"");
        let binary = format!("sp_archive.{dlext}");
        let pre = scratch.join("sp_archive-pre");
        let prebuilt_dir = pre.join("lib/sp_archive").join(&minor);
        std::fs::create_dir_all(&prebuilt_dir).unwrap();
        std::fs::create_dir_all(pre.join("ext/sp_archive")).unwrap();
        std::fs::copy(
            build_home
                .join("gems/sp_archive-1.0.0/lib/sp_archive")
                .join(&binary),
            prebuilt_dir.join(&binary),
        )
        .unwrap();
        std::fs::write(pre.join("lib/sp_archive.rb"), ARCHIVE_LIB).unwrap();
        std::fs::write(pre.join(ARCHIVE_C_KEY), archive_c(1)).unwrap();
        std::fs::write(
            pre.join("sp_archive.gemspec"),
            format!(
                "Gem::Specification.new do |s|\n  s.name = \"sp_archive\"\n  \
                 s.version = \"1.0.0\"\n  s.platform = \"{platform}\"\n  s.summary = \"t\"\n  \
                 s.authors = [\"t\"]\n  s.files = Dir[\"lib/**/*\", \"ext/**/*.c\"]\nend\n"
            ),
        )
        .unwrap();
        gem(&scratch, &pre, &["build", "sp_archive.gemspec"], &[]);
        let platform_gem = std::fs::read_dir(&pre)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == "gem"))
            .expect("the platform gem was built");
        gem(
            &scratch,
            &scratch,
            &[
                "install",
                "--local",
                "--no-document",
                "--ignore-dependencies",
                "--install-dir",
                home.to_str().unwrap(),
                platform_gem.to_str().unwrap(),
            ],
            &[],
        );
        let gem_dir = std::fs::read_dir(home.join("gems"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("sp_archive-1.0.0-"))
            })
            .expect("the platform gem was installed");
        assert!(gem_dir
            .join("lib/sp_archive")
            .join(&minor)
            .join(&binary)
            .is_file());
        ArchiveFixture {
            _tmp: tmp,
            proj,
            home,
            gem_dir,
            source_gem,
            portile_gem,
        }
    }

    /// What Ruby loads: `SpArchive.describe`, and the extension's path
    /// relative to the gem dir.
    fn loaded(&self) -> (String, String) {
        let out = Command::new("ruby")
            .args([
                "-e",
                "require 'sp_archive'; puts SpArchive.describe; \
                 puts $LOADED_FEATURES.grep(/sp_archive\\.(so|bundle|dll)\\z/).first",
            ])
            .env("GEM_PATH", &self.home)
            .env_remove("GEM_HOME")
            .env_remove("RUBYOPT")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "loading sp_archive failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut lines = text.lines();
        let describe = lines.next().unwrap_or_default().to_string();
        let feature = PathBuf::from(lines.next().unwrap_or_default());
        // Ruby may name the gem dir through a symlink (`/tmp`).
        let gem_dir = self.gem_dir.canonicalize().unwrap();
        let feature = feature.canonicalize().unwrap_or(feature);
        let rel = feature
            .strip_prefix(&gem_dir)
            .unwrap_or(&feature)
            .display()
            .to_string();
        (describe, rel)
    }

    /// The record: a C source every copy ships, a build input no installed
    /// copy holds (the build deleted it; a platform gem never packed it),
    /// and a patch file it adds, as nokogiri's libxml2 patches are added.
    fn write_full_record(&self) {
        let (before, after) = (archive_c(1), archive_c(2));
        write_record(
            &self.proj.join(".socket"),
            ARCHIVE_PURL,
            &[
                (ARCHIVE_C_KEY, Some(&before), &after),
                ("ports/value.txt", Some("40\n"), "41\n"),
                ("patches/0100-CVE-test.patch", None, "the fix\n"),
            ],
        );
    }

    fn run(&self, args: &[&str], registry: &str) -> (i32, String, String) {
        common::run_with_env(&self.proj, args, &[("SOCKET_RUBYGEMS_URL", registry)])
    }
}

fn archive_event_action(stdout: &str) -> String {
    let env = parse_json_envelope(stdout);
    common::envelope::event_for(&env, ARCHIVE_PURL)["action"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// A gem built from source whose build removed one of its inputs, as
/// nokogiri's removes `ports/`: the in-place rebuild cannot work, and the
/// rebuild from the archive RubyGems left in the home's `cache/` does,
/// with no network. A record that only adds a file `extconf.rb` builds
/// from (nokogiri's `patches/libxml2/*.patch`) changes what Ruby loads.
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn a_source_built_gem_is_rebuilt_from_its_cached_source_gem() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = ArchiveFixture::new(&abi, false);
    let run = |args: &[&str]| fx.run(args, NO_REGISTRY);
    let cached = fx.home.join("cache/sp_archive-1.0.0.gem");
    assert!(cached.is_file(), "RubyGems keeps the archive it installed");
    let (describe, feature) = fx.loaded();
    assert_eq!(describe, ORIGINAL_BUILD);
    assert_eq!(
        feature,
        format!("lib/sp_archive/{}", feature_leaf(&feature))
    );
    let tree_before = walk_files(&fx.proj.join("vendor"));

    // Without the archive: the copy's own tree is what is left to build,
    // and its `extconf.rb` no longer has what it builds from.
    let parked = fx.proj.join("sp_archive-1.0.0.gem.parked");
    std::fs::rename(&cached, &parked).unwrap();
    let without_archive = walk_files(&fx.proj.join("vendor"));
    write_record(
        &fx.proj.join(".socket"),
        ARCHIVE_PURL,
        &[("patches/0100-CVE-test.patch", None, "the fix\n")],
    );
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("native_extension_build_failed"), "{stdout}");
    assert!(stdout.contains("ports/value.txt is not there"), "{stdout}");
    assert_tree(
        &fx.proj.join("vendor"),
        &without_archive,
        "after a failed in-place build",
    );
    // A record that changes the removed input itself has nothing in the
    // copy to be checked against: refused from files alone.
    fx.write_full_record();
    for args in [
        &["apply", "--json", "--offline"][..],
        &["apply", "--json", "--offline", "--dry-run"],
    ] {
        let (code, stdout, stderr) = run(args);
        assert_eq!(code, 1, "{args:?}: {stdout}\n{stderr}");
        assert!(
            stdout.contains("native_extensions_unsupported")
                && stdout.contains("can only be rebuilt from the source gem"),
            "{args:?}: {stdout}"
        );
        assert_tree(
            &fx.proj.join("vendor"),
            &without_archive,
            &format!("{args:?}"),
        );
    }
    std::fs::rename(&parked, &cached).unwrap();

    // With it: built in a stage from the archive, offline.
    let (code, _, _) = run(&["apply", "--check"]);
    assert_ne!(code, 0, "an unapplied patch must not check clean");
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(archive_event_action(&stdout), "applied", "{stdout}");
    assert_eq!(
        fx.loaded().0,
        PATCHED_BUILD,
        "Ruby loads the rebuilt extension"
    );
    assert_eq!(
        std::fs::read_to_string(fx.gem_dir.join(ARCHIVE_C_KEY)).unwrap(),
        archive_c(2)
    );
    assert_eq!(
        std::fs::read_to_string(fx.gem_dir.join("ports/value.txt")).unwrap(),
        "41\n"
    );
    assert!(!fx.home.join(".socket-patch-build").exists());
    let (code, stdout, stderr) = run(&["apply", "--check"]);
    assert_eq!(code, 0, "a rebuilt patch checks clean:\n{stdout}\n{stderr}");
    assert!(vex_attests(run), "vex attests the rebuilt copy");
    let (code, stdout, _) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(archive_event_action(&stdout), "skipped", "{stdout}");

    let (code, stdout, stderr) = run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.loaded().0, ORIGINAL_BUILD, "the original build is back");
    assert_tree(
        &fx.proj.join("vendor"),
        &tree_before,
        "rollback gives the install back byte for byte",
    );
}

/// The file name of a loaded extension's path.
fn feature_leaf(feature: &str) -> &str {
    feature.rsplit('/').next().unwrap_or(feature)
}

/// A precompiled platform gem, the way nokogiri installs by default: the
/// source gem is downloaded from the gem's source and verified against its
/// compact index, the gem its build needs and the install lacks is staged
/// beside it (never installed into the user's home), and the build takes
/// the place of the prebuilt binary Ruby loads. `rollback` gives the
/// prebuilt binary back byte for byte.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
async fn a_precompiled_gem_is_rebuilt_from_its_source_gem_and_grafted() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = ArchiveFixture::new(&abi, true);
    let (source, portile) = (
        std::fs::read(&fx.source_gem).unwrap(),
        std::fs::read(&fx.portile_gem).unwrap(),
    );
    // The gem source: both gems' compact index entries and archives. Only
    // `sp_portile` 1.0.2 can be downloaded: it is the newest `~> 1.0`.
    let server = MockServer::start().await;
    let other = "0".repeat(64);
    for (route, body) in [
        (
            "/info/sp_archive".to_string(),
            format!(
                "---\n1.0.0 sp_portile:~> 1.0|checksum:{}\n",
                common::sha256_hex(&source)
            ),
        ),
        (
            "/info/sp_portile".to_string(),
            format!(
                "---\n1.0.0 |checksum:{other}\n1.0.2 |checksum:{}\n2.0.0 |checksum:{other}\n\
                 1.0.3.rc1 |checksum:{other}\n1.0.9 |checksum:{other},ruby:>= 99.0\n",
                common::sha256_hex(&portile)
            ),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
    }
    for (route, bytes) in [
        ("/gems/sp_archive-1.0.0.gem", source),
        ("/gems/sp_portile-1.0.2.gem", portile),
    ] {
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(bytes, "application/octet-stream"),
            )
            .mount(&server)
            .await;
    }
    let registry = server.uri();
    let run = |args: &[&str]| fx.run(args, &registry);

    let (describe, feature) = fx.loaded();
    assert_eq!(describe, ORIGINAL_BUILD);
    let minor = ruby_says("print RUBY_VERSION[/\\d+\\.\\d+/]");
    assert_eq!(
        feature,
        format!("lib/sp_archive/{minor}/{}", feature_leaf(&feature)),
        "Ruby loads the prebuilt binary kept for its minor"
    );
    assert!(!fx.gem_dir.join("patches").exists());
    fx.write_full_record();
    let tree_before = walk_files(&fx.proj.join("vendor"));

    // Offline, with no source gem in the home's cache: a clear refusal.
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("native_extensions_unsupported")
            && stdout.contains("this run is offline")
            && stdout.contains("sp_archive-1.0.0.gem"),
        "{stdout}"
    );
    assert_tree(&fx.proj.join("vendor"), &tree_before, "");
    assert!(server.received_requests().await.unwrap().is_empty());

    let (code, _, _) = run(&["apply", "--check"]);
    assert_ne!(code, 0, "an unapplied patch must not check clean");
    let (code, stdout, stderr) = run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(archive_event_action(&stdout), "applied", "{stdout}");
    let (describe, patched_feature) = fx.loaded();
    assert_eq!(describe, PATCHED_BUILD, "Ruby loads the grafted build");
    assert_eq!(patched_feature, feature, "from where the prebuilt one was");
    assert_eq!(
        std::fs::read_to_string(fx.gem_dir.join("patches/0100-CVE-test.patch")).unwrap(),
        "the fix\n"
    );
    for leftover in [
        fx.home.join(".socket-patch-build"),
        fx.home.join("gems/sp_portile-1.0.2"),
        fx.home.join("gems/sp_archive-1.0.0"),
        fx.home.join("cache/sp_archive-1.0.0.gem"),
        fx.home.join("cache/sp_portile-1.0.2.gem"),
    ] {
        assert!(
            !leftover.exists(),
            "{} was put into the user's gem home",
            leftover.display()
        );
    }
    let (code, stdout, stderr) = run(&["apply", "--check"]);
    assert_eq!(code, 0, "a grafted patch checks clean:\n{stdout}\n{stderr}");
    assert!(vex_attests(run), "vex attests the grafted copy");
    let requests = server.received_requests().await.unwrap().len();
    let (code, stdout, _) = run(&["apply", "--json"]);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(archive_event_action(&stdout), "skipped", "{stdout}");
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        requests,
        "an applied patch asks the gem source for nothing"
    );

    let (code, stdout, stderr) = run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.loaded().0, ORIGINAL_BUILD, "the prebuilt binary is back");
    assert_tree(
        &fx.proj.join("vendor"),
        &tree_before,
        "rollback gives the install back byte for byte",
    );

    // The source gem in the home's cache, as the refusal asks: found with
    // no network. The gem its build needs is still not there to stage.
    std::fs::copy(&fx.source_gem, fx.home.join("cache/sp_archive-1.0.0.gem")).unwrap();
    fx.write_full_record();
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("its build needs the gem sp_portile (~> 1.0)")
            && stdout.contains("this run is offline"),
        "{stdout}"
    );
    assert_eq!(fx.loaded().0, ORIGINAL_BUILD);
    let (code, stdout, stderr) = run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.loaded().0, PATCHED_BUILD);
}

/// The source gem of a precompiled copy, when the home's `cache/` does not
/// hold it, is downloaded from the registry and used only when it has the
/// sha256 the registry's compact index records for the ruby-platform gem.
/// (The stand-in Ruby builds; the download and its check are the CLI's.)
///
/// The registry here is on this machine, reached over plain http, which is
/// taken only because such a request crosses no network. So it is sent
/// straight there: with `HTTP_PROXY` / `ALL_PROXY` set and no `NO_PROXY`,
/// nothing of it goes to the proxy, which would carry it in clear text to
/// another host.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn the_source_gem_is_downloaded_and_checked_against_the_registry_index() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    const ARCHIVE: &[u8] = b"the source gem, as the registry serves it";

    // (the sha256 the index records, whether the archive is the indexed one)
    for (indexed, genuine) in [
        (common::sha256_hex(ARCHIVE), true),
        (common::sha256_hex(b"another archive"), false),
    ] {
        let server = MockServer::start().await;
        // A proxy that answers nothing (404): a request sent through it
        // fails, and is counted.
        let proxy = MockServer::start().await;
        // The platform gem's line comes first: it is not the source gem's.
        let info = format!(
            "---\n1.0.0-x86_64-linux |checksum:{}\n1.0.0 |checksum:{indexed}\n",
            "0".repeat(64)
        );
        Mock::given(method("GET"))
            .and(path("/info/sp_native"))
            .respond_with(ResponseTemplate::new(200).set_body_string(info))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/gems/sp_native-1.0.0.gem"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(ARCHIVE, "application/octet-stream"),
            )
            .mount(&server)
            .await;
        let registry = server.uri();
        let (_tmp, proj, gem_dir) = fake_precompiled_gem(false);
        write_precompiled_record(&proj);
        let ruby = FakeRuby::new();
        ruby.serve_source_gem(&c_source(1));
        let home = proj.join("vendor/bundle/ruby/3.4.0");
        let tree_before = walk_files(&proj.join("vendor"));

        let proxied = proxy.uri();
        let (code, stdout, stderr) = ruby.run(
            &proj,
            &["apply", "--json"],
            &[
                ("SOCKET_RUBYGEMS_URL", registry.as_str()),
                ("HTTP_PROXY", proxied.as_str()),
                ("http_proxy", proxied.as_str()),
                ("ALL_PROXY", proxied.as_str()),
                ("all_proxy", proxied.as_str()),
                ("NO_PROXY", ""),
                ("no_proxy", ""),
            ],
        );
        let through_proxy: Vec<String> = proxy
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.to_string())
            .collect();
        assert_eq!(
            through_proxy,
            Vec::<String>::new(),
            "a loopback request went through the proxy"
        );
        let asked: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_string())
            .collect();
        assert_eq!(asked, ["/info/sp_native", "/gems/sp_native-1.0.0.gem"]);
        if !genuine {
            assert_eq!(code, 1, "{stdout}\n{stderr}");
            assert!(stdout.contains("native_extensions_unsupported"), "{stdout}");
            assert!(
                stdout.contains("does not have the sha256 the registry's index records"),
                "{stdout}"
            );
            assert_eq!(ruby.calls(), ["extensions_dir"], "nothing was unpacked");
            assert_tree(
                &proj.join("vendor"),
                &tree_before,
                "after a refused download",
            );
            continue;
        }
        assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
        assert_eq!(event_action(&stdout), "applied", "{stdout}");
        assert_eq!(
            ruby.calls(),
            ["extensions_dir", "unpack", "missing_deps", "stage_build"]
        );
        assert_eq!(
            std::fs::read_to_string(gem_dir.join("lib/sp_native/3.4/sp_native.so")).unwrap(),
            built_from(&c_source(2))
        );
        assert!(
            !home.join("cache/sp_native-1.0.0.gem").exists(),
            "the download is not put into the user's gem home"
        );
        assert!(!home.join(".socket-patch-build").exists());
    }
}

/// `sp_wrap`: a gem whose build leaves its library in the gem's own tree
/// and loads it from there, as an FFI gem does (argon2's
/// `ext/argon2_wrap/libargon2_wrap.so`). Its `extconf.rb` compiles the
/// library itself and writes a Makefile with nothing to do, so RubyGems'
/// extension dir holds no artifact at all.
const WRAP_PURL: &str = "pkg:gem/sp_wrap@1.0.0";
const WRAP_C_KEY: &str = "ext/sp_wrap/wrap.c";
const WRAP_EXTCONF: &str = r##"require "rbconfig"
Dir.chdir(__dir__)
name = RbConfig::CONFIG["host_os"] =~ /darwin/ ? "libsp_wrap.dylib" : "libsp_wrap.so"
cc = RbConfig::CONFIG["CC"].split
abort "could not build #{name}" unless system(*cc, "-shared", "-fPIC", "-o", name, "wrap.c")
File.write("Makefile", "all:\n\ninstall:\n\nclean:\n\n")
"##;
const WRAP_LIB: &str = r##"require "fiddle"
module SpWrap
  def self.value
    path = Dir[File.expand_path("../ext/sp_wrap/libsp_wrap.{so,dylib}", __dir__)].first
    Fiddle::Function.new(Fiddle.dlopen(path)["sp_wrap_value"], [], Fiddle::TYPE_INT).call
  end
end
"##;

fn wrap_c(value: u32) -> String {
    format!("int sp_wrap_value(void) {{ return {value}; }}\n")
}

/// `sp_wrap` with a build that takes a library it finds for current, as a
/// Rakefile whose library task does not depend on the C sources does
/// (digest-crc): run again over an installed tree, it compiles nothing.
const STALE_EXTCONF: &str = r##"require "rbconfig"
Dir.chdir(__dir__)
name = RbConfig::CONFIG["host_os"] =~ /darwin/ ? "libsp_wrap.dylib" : "libsp_wrap.so"
cc = RbConfig::CONFIG["CC"].split
unless File.exist?(name)
  abort "could not build #{name}" unless system(*cc, "-shared", "-fPIC", "-o", name, "wrap.c")
end
File.write("Makefile", "all:\n\ninstall:\n\nclean:\n\n")
"##;

/// `sp_wrap` with a build script that uses up a file the gem ships, as
/// argon2's does (`File.rename('Makefile.real', 'Makefile')`): the
/// installed tree holds no `Makefile.real`, and the script cannot run
/// there a second time.
const ONE_SHOT_EXTCONF: &str = r##"require "rbconfig"
Dir.chdir(__dir__)
name = RbConfig::CONFIG["host_os"] =~ /darwin/ ? "libsp_wrap.dylib" : "libsp_wrap.so"
cc = RbConfig::CONFIG["CC"].split
abort "could not build #{name}" unless system(*cc, "-shared", "-fPIC", "-o", name, "wrap.c")
File.rename("Makefile.real", "Makefile")
"##;
/// [`ONE_SHOT_EXTCONF`] with a build that only a fresh tree lets finish:
/// run over an installed one it compiles the library, uses the shipped
/// file up and then fails.
const ONCE_ONLY_EXTCONF: &str = r##"require "rbconfig"
Dir.chdir(__dir__)
name = RbConfig::CONFIG["host_os"] =~ /darwin/ ? "libsp_wrap.dylib" : "libsp_wrap.so"
cc = RbConfig::CONFIG["CC"].split
installed = File.exist?("Makefile")
abort "could not build #{name}" unless system(*cc, "-shared", "-fPIC", "-o", name, "wrap.c")
File.rename("Makefile.real", "Makefile")
abort "this tree was built before" if installed
"##;
/// The file [`ONE_SHOT_EXTCONF`] uses up, relative to the gem dir.
const ONE_SHOT_FILE: &str = "ext/sp_wrap/Makefile.real";

/// A project with `sp_wrap` (built by `extconf`) installed into
/// `vendor/bundle/ruby/<abi>` by the real `gem`, its archive in the home's
/// `cache/`, and a record that changes `SpWrap.value` from 1 to 2.
struct WrapGem {
    _tmp: tempfile::TempDir,
    proj: PathBuf,
    home: PathBuf,
    gem_dir: PathBuf,
}

impl WrapGem {
    fn new(abi: &str, extconf: &str) -> WrapGem {
        let tmp = tempfile::tempdir().unwrap();
        let scratch = tmp.path().to_path_buf();
        let src = scratch.join("sp_wrap");
        std::fs::create_dir_all(src.join("ext/sp_wrap")).unwrap();
        std::fs::create_dir_all(src.join("lib")).unwrap();
        std::fs::write(src.join("ext/sp_wrap/extconf.rb"), extconf).unwrap();
        std::fs::write(src.join(WRAP_C_KEY), wrap_c(1)).unwrap();
        std::fs::write(src.join("lib/sp_wrap.rb"), WRAP_LIB).unwrap();
        // Shipped with every variant; only `ONE_SHOT_EXTCONF` touches it.
        std::fs::write(src.join(ONE_SHOT_FILE), "all:\n\ninstall:\n\nclean:\n\n").unwrap();
        std::fs::write(
            src.join("sp_wrap.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"sp_wrap\"\n  s.version = \"1.0.0\"\n  \
             s.summary = \"t\"\n  s.authors = [\"t\"]\n  \
             s.files = Dir[\"lib/**/*.rb\", \"ext/**/*.{c,rb,real}\"]\n  \
             s.extensions = [\"ext/sp_wrap/extconf.rb\"]\nend\n",
        )
        .unwrap();
        gem(&scratch, &src, &["build", "sp_wrap.gemspec"], &[]);
        let proj = scratch.join("proj");
        let home = proj.join("vendor/bundle/ruby").join(abi);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            proj.join("Gemfile"),
            "source \"https://rubygems.org\"\ngem \"sp_wrap\"\n",
        )
        .unwrap();
        gem(
            &scratch,
            &scratch,
            &[
                "install",
                "--local",
                "--no-document",
                "--install-dir",
                home.to_str().unwrap(),
                src.join("sp_wrap-1.0.0.gem").to_str().unwrap(),
            ],
            &[],
        );
        assert!(home.join("cache/sp_wrap-1.0.0.gem").is_file());
        write_record(
            &proj.join(".socket"),
            WRAP_PURL,
            &[(WRAP_C_KEY, Some(&wrap_c(1)), &wrap_c(2))],
        );
        let gem_dir = home.join("gems/sp_wrap-1.0.0");
        WrapGem {
            _tmp: tmp,
            proj,
            home,
            gem_dir,
        }
    }

    /// `SpWrap.value` as the installed gem's Ruby loads it.
    fn value(&self) -> String {
        let out = Command::new("ruby")
            .args(["-W0", "-e", "require 'sp_wrap'; print SpWrap.value"])
            .env("GEM_PATH", &self.home)
            .env_remove("GEM_HOME")
            .env_remove("RUBYOPT")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "loading sp_wrap failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn c_file(&self) -> String {
        std::fs::read_to_string(self.gem_dir.join(WRAP_C_KEY)).unwrap()
    }

    /// The library the gem loads, relative to the gem dir.
    fn library(&self) -> String {
        ["libsp_wrap.so", "libsp_wrap.dylib"]
            .iter()
            .map(|name| format!("ext/sp_wrap/{name}"))
            .find(|rel| self.gem_dir.join(rel).is_file())
            .expect("the gem's library is in its own tree")
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        common::run_with_env(&self.proj, args, &[("SOCKET_RUBYGEMS_URL", NO_REGISTRY)])
    }
}

/// A gem that loads its library from its own tree is not left running the
/// old one: a build staged elsewhere cannot stand in for a library the
/// installed copy loads from where it was built, so the staged build is
/// set aside and the gem is rebuilt where it is installed. The library
/// that build replaces is backed up and recorded like one in the extension
/// dir: `apply --check` notices it changing, and `rollback` gives the
/// original back byte for byte (#2104).
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn a_gem_that_loads_its_library_from_its_own_tree_is_rebuilt_in_place() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = WrapGem::new(&abi, WRAP_EXTCONF);
    assert_eq!(fx.value(), "1");
    let installed = walk_files(&fx.gem_dir);
    let extensions = walk_files(&fx.home.join("extensions"));
    let library = fx.library();

    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        fx.value(),
        "2",
        "Ruby must load the library built from the patched source:\n{stdout}"
    );
    assert_eq!(fx.c_file(), wrap_c(2));
    assert!(!fx.home.join(".socket-patch-build").exists());
    let marker: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(fx.gem_dir.join(".socket-patch-native-build.json")).unwrap(),
    )
    .unwrap();
    assert!(
        marker["libArtifacts"][&library].is_string(),
        "the build record names the library built in the gem's tree: {marker}"
    );
    let (code, stdout, stderr) = fx.run(&["apply", "--check"]);
    assert_eq!(code, 0, "a rebuilt patch checks clean:\n{stdout}\n{stderr}");
    assert!(vex_attests(|args| fx.run(args)));

    // A library that is no longer the one that was built is not attested.
    let built = std::fs::read(fx.gem_dir.join(&library)).unwrap();
    std::fs::write(fx.gem_dir.join(&library), b"not the build").unwrap();
    let (code, stdout, stderr) = fx.run(&["apply", "--check"]);
    assert_ne!(
        code, 0,
        "a replaced library must not check clean:\n{stdout}\n{stderr}"
    );
    assert!(!vex_attests(|args| fx.run(args)));
    std::fs::write(fx.gem_dir.join(&library), built).unwrap();

    let (code, stdout, stderr) = fx.run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "1", "Ruby must load the original library again");
    assert_tree(&fx.gem_dir, &installed, "after rollback");
    assert_tree(&fx.home.join("extensions"), &extensions, "after rollback");
}

/// A build that takes the library it finds in the gem's tree for current
/// compiles nothing when it runs over an installed copy. The products the
/// source gem's build was seen to make are removed first, as a fresh
/// install starts without them, so the library is built from the patched
/// source (#2105).
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn a_build_that_keeps_a_stale_library_is_made_to_rebuild_it() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = WrapGem::new(&abi, STALE_EXTCONF);
    assert_eq!(fx.value(), "1");
    let installed = walk_files(&fx.gem_dir);

    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        fx.value(),
        "2",
        "Ruby must load the library built from the patched source:\n{stdout}"
    );
    let (code, stdout, stderr) = fx.run(&["apply", "--check"]);
    assert_eq!(code, 0, "a rebuilt patch checks clean:\n{stdout}\n{stderr}");
    assert!(vex_attests(|args| fx.run(args)));

    let (code, stdout, stderr) = fx.run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "1", "Ruby must load the original library again");
    assert_tree(&fx.gem_dir, &installed, "after rollback");

    // A rollback that has lost the backup rebuilds from the restored
    // source, and that build must not take the patched library for
    // current either. (The first rollback dropped the record.)
    write_record(
        &fx.proj.join(".socket"),
        WRAP_PURL,
        &[(WRAP_C_KEY, Some(&wrap_c(1)), &wrap_c(2))],
    );
    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "2");
    std::fs::remove_dir_all(fx.gem_dir.join(".socket-patch-native-orig")).unwrap();
    let (code, stdout, stderr) = fx.run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(
        fx.value(),
        "1",
        "the library is rebuilt from the restored source:\n{stdout}"
    );
    assert_eq!(fx.c_file(), wrap_c(1));
}

/// A build script that uses up a file the gem ships cannot run a second
/// time over the installed tree (argon2's renames `Makefile.real`). The
/// source gem still holds the file, so it is put back for the in-place
/// build: the patch is built, and nothing is left in the tree that the
/// build did not leave there itself. `rollback` gives the installed tree
/// back, with or without the backup of the original build (#2106).
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn a_build_script_that_uses_up_a_shipped_file_is_given_it_back() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = WrapGem::new(&abi, ONE_SHOT_EXTCONF);
    assert_eq!(fx.value(), "1");
    assert!(
        !fx.gem_dir.join(ONE_SHOT_FILE).exists(),
        "the install-time build used the file up"
    );
    let installed = walk_files(&fx.gem_dir);
    let extensions = walk_files(&fx.home.join("extensions"));

    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(
        fx.value(),
        "2",
        "Ruby must load the library built from the patched source:\n{stdout}"
    );
    let mut changed: Vec<String> = tree_diff(&installed, &walk_files(&fx.gem_dir))
        .into_iter()
        .filter(|line| !line.contains(".socket-patch-native-"))
        .collect();
    changed.sort();
    assert_eq!(
        changed,
        [format!("~{}", fx.library()), format!("~{WRAP_C_KEY}")],
        "the patched source and the library built from it are all that changed"
    );
    let (code, stdout, stderr) = fx.run(&["apply", "--check"]);
    assert_eq!(code, 0, "a rebuilt patch checks clean:\n{stdout}\n{stderr}");
    assert!(vex_attests(|args| fx.run(args)));

    let (code, stdout, stderr) = fx.run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "1", "Ruby must load the original library again");
    assert_tree(&fx.gem_dir, &installed, "after rollback");
    assert_tree(&fx.home.join("extensions"), &extensions, "after rollback");

    // A rollback that has lost the backup rebuilds from the restored
    // source, with the same script. (The first rollback dropped the
    // record.)
    write_record(
        &fx.proj.join(".socket"),
        WRAP_PURL,
        &[(WRAP_C_KEY, Some(&wrap_c(1)), &wrap_c(2))],
    );
    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(fx.value(), "2");
    std::fs::remove_dir_all(fx.gem_dir.join(".socket-patch-native-orig")).unwrap();
    let (code, stdout, stderr) = fx.run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_eq!(
        fx.value(),
        "1",
        "the library is rebuilt from the restored source:\n{stdout}"
    );
    assert_eq!(fx.c_file(), wrap_c(1));
    assert!(
        !fx.gem_dir.join(ONE_SHOT_FILE).exists(),
        "the file put back for the build is not left behind"
    );
}

/// A build that fails in the installed tree after it was given the
/// shipped file back, and after it compiled the patched library and used
/// the file up: the undo takes everything the build did with it, and the
/// gem is exactly as installed (#2106).
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn a_failed_build_takes_the_shipped_file_it_was_given_away_again() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = WrapGem::new(&abi, ONCE_ONLY_EXTCONF);
    let installed = walk_files(&fx.gem_dir);
    let extensions = walk_files(&fx.home.join("extensions"));

    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_ne!(code, 0, "the in-place build fails:\n{stdout}\n{stderr}");
    let env = parse_json_envelope(&stdout);
    let event = common::envelope::event_for(&env, WRAP_PURL);
    assert!(
        event["error"].as_str().is_some_and(|e| {
            e.starts_with("native_extension_build_failed:")
                && e.contains("this tree was built before")
        }),
        "the build got as far as the script's last line, so it was given the file:\n{stdout}"
    );
    assert_eq!(fx.value(), "1");
    assert_tree(&fx.gem_dir, &installed, "after the failed apply");
    assert_tree(
        &fx.home.join("extensions"),
        &extensions,
        "after the failed apply",
    );
    assert!(!fx.home.join(".socket-patch-build").exists());
    assert!(!vex_attests(|args| fx.run(args)));
}

/// Without the source gem nothing says which files the build makes, so
/// none can be removed for it. A build that then exits cleanly and leaves
/// every library as it was has not built the patched source: the patch is
/// refused, the gem is left exactly as it was, and nothing attests it
/// (#2105).
#[test]
#[ignore = "host capstone: compiles a C extension with the real ruby/gem toolchain; \
            the unpinned `test` job skips it, the pinned-Ruby e2e leg runs it via --ignored"]
fn a_build_that_compiles_nothing_is_refused_and_not_attested() {
    let Some(abi) = toolchain() else {
        return;
    };
    let fx = WrapGem::new(&abi, STALE_EXTCONF);
    std::fs::remove_file(fx.home.join("cache/sp_wrap-1.0.0.gem")).unwrap();
    let installed = walk_files(&fx.gem_dir);
    let extensions = walk_files(&fx.home.join("extensions"));

    let (code, stdout, stderr) = fx.run(&["apply", "--json", "--offline"]);
    assert_ne!(
        code, 0,
        "a build that compiled nothing must not pass for a rebuild:\n{stdout}\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    let event = common::envelope::event_for(&env, WRAP_PURL);
    assert!(
        event["error"].as_str().is_some_and(|e| {
            e.starts_with("native_extension_build_failed:") && e.contains("compiled nothing")
        }),
        "the refusal says the build compiled nothing:\n{stdout}"
    );
    assert_eq!(fx.value(), "1");
    assert_eq!(fx.c_file(), wrap_c(1), "the source is put back");
    assert_tree(&fx.gem_dir, &installed, "after the refused apply");
    assert_tree(
        &fx.home.join("extensions"),
        &extensions,
        "after the refused apply",
    );
    assert!(!vex_attests(|args| fx.run(args)));
}

/// A precompiled gem ships one binary per Ruby minor, and a graft replaces
/// the one of the Ruby that ran `apply`, as `gem install` builds for the
/// Ruby that runs it. The copy is attested from that first graft on, in a
/// gem home two Rubies build into too. `apply` under the other Ruby grafts
/// its binary beside the first; `apply` under a Ruby already grafted builds
/// nothing. A grafted binary that is no longer the built one fails the
/// check, and rollback gives both binaries back.
#[cfg(unix)]
#[test]
fn a_home_of_two_rubies_is_attested_from_the_first_graft() {
    let (_tmp, proj, gem_dir) = fake_precompiled_gem(true);
    // A second Ruby built a gem into this home.
    let home = proj.join("vendor/bundle/ruby/3.4.0");
    let other = home.join("extensions/x86_64-linux/3.3.0/racc-1.8.1");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(other.join("gem.build_complete"), b"").unwrap();
    let (before, after) = (c_source(1), c_source(2));
    write_record(
        &proj.join(".socket"),
        PURL,
        &[(C_KEY, Some(&before), &after)],
    );
    let ruby = FakeRuby::new();
    ruby.serve_source_gem(&c_source(1));
    let (for_33, for_34) = (
        gem_dir.join("lib/sp_native/3.3/sp_native.so"),
        gem_dir.join("lib/sp_native/3.4/sp_native.so"),
    );
    let tree_before = walk_files(&proj.join("vendor"));
    let run = |args: &[&str]| ruby.run(&proj, args, &[]);
    let built = ["extensions_dir", "unpack", "missing_deps", "stage_build"];

    // Ruby 3.4 applies: its binary is the build, and the copy is attested.
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert_eq!(ruby.calls(), built);
    assert_eq!(
        std::fs::read_to_string(&for_34).unwrap(),
        built_from(&c_source(2))
    );
    assert_eq!(std::fs::read_to_string(&for_33).unwrap(), prebuilt("3.3"));
    assert!(
        !stdout.contains("native_extension_not_rebuilt"),
        "a graft for the Ruby that ran apply is the whole install: {stdout}"
    );
    let (code, stdout, stderr) = run(&["apply", "--check", "--json"]);
    assert_eq!(code, 0, "the first graft checks clean:\n{stdout}\n{stderr}");
    assert!(!stdout.contains("native_extension_not_rebuilt"), "{stdout}");
    assert!(vex_attests(run), "vex attests from the first graft");
    let (code, stdout, stderr) = run(&["apply", "--json", "--dry-run", "--offline"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        !stdout.contains("native_extension_rebuilt"),
        "a dry run of a built copy promises no rebuild: {stdout}"
    );
    assert_eq!(ruby.calls(), built, "a check, vex or dry run ran Ruby");

    // Again under 3.4: asked which Ruby it is, then nothing left to build,
    // with or without a source gem within reach.
    let cached = home.join("cache/sp_native-1.0.0.gem");
    let parked = proj.join("sp_native-1.0.0.gem.parked");
    std::fs::rename(&cached, &parked).unwrap();
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "skipped", "{stdout}");
    assert!(!stdout.contains("native_extension_not_rebuilt"), "{stdout}");
    let asked = [&built[..], &["extensions_dir"]].concat();
    assert_eq!(ruby.calls(), asked);
    assert_eq!(
        std::fs::read_to_string(&for_34).unwrap(),
        built_from(&c_source(2))
    );
    std::fs::rename(&parked, &cached).unwrap();

    // Ruby 3.3 applies: it grafts its own binary beside the other.
    ruby.become_ruby_33();
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "apply under 3.3 failed:\n{stdout}\n{stderr}");
    assert!(!stdout.contains("native_extension_not_rebuilt"), "{stdout}");
    assert!(
        stdout.contains("native_extension_rebuilt"),
        "a rebuild of sources already patched says so: {stdout}"
    );
    let both = [&asked[..], &built[..]].concat();
    assert_eq!(ruby.calls(), both);
    assert_eq!(
        std::fs::read_to_string(&for_33).unwrap(),
        format!("{} (by Ruby 3.3)", built_from(&c_source(2)))
    );
    assert_eq!(
        std::fs::read_to_string(&for_34).unwrap(),
        built_from(&c_source(2)),
        "the other Ruby's graft is kept"
    );
    let (code, stdout, stderr) = run(&["apply", "--check"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(vex_attests(run), "vex attests both grafts");
    // Every binary the gem ships is grafted: no Ruby is left to ask.
    let (code, stdout, stderr) = run(&["apply", "--json", "--offline"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "skipped", "{stdout}");
    assert_eq!(ruby.calls(), both, "nothing more to run");

    // A grafted binary that is no longer the built one (the gem was
    // reinstalled over it): neither `apply --check` nor `vex` attests.
    let grafted = std::fs::read_to_string(&for_33).unwrap();
    std::fs::write(&for_33, prebuilt("3.3")).unwrap();
    let (code, stdout, _) = run(&["apply", "--check", "--json"]);
    assert_ne!(code, 0, "{stdout}");
    assert!(stdout.contains("native_extension_not_rebuilt"), "{stdout}");
    assert!(!vex_attests(run), "vex attested a prebuilt binary");
    std::fs::write(&for_33, grafted).unwrap();
    let (code, stdout, stderr) = run(&["apply", "--check"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");

    let (code, stdout, stderr) = run(&["rollback", "--json", "--offline"]);
    assert_eq!(code, 0, "rollback failed:\n{stdout}\n{stderr}");
    assert_tree(&proj.join("vendor"), &tree_before, "after rollback");
}
