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

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        common::run(&self.proj, args)
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

/// `(relative path, bytes)` of every file under `dir`.
/// An `extconf.rb` that, like nokogiri's (which activates `mini_portile2`),
/// loads a helper gem installed beside the copy in the same home.
const EXTCONF_WITH_HELPER: &str = "gem \"sp_helper\"\nrequire \"sp_helper\"\n\
                                   require \"mkmf\"\ncreate_makefile(\"sp_native/sp_native\")\n";

/// Build the pure-Ruby `sp_helper` gem and install it into `home`.
fn install_helper_gem(home: &Path) {
    let src = home.parent().unwrap().join("sp_helper-src");
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
            .env("HOME", home.parent().unwrap())
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
    install_helper_gem(&fx.home);
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
}

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

/// Run the CLI with a `PATH` holding no `ruby`.
fn run_without_ruby(proj: &Path, args: &[&str]) -> (i32, String, String) {
    let empty = proj.join(".empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    let path = empty.display().to_string();
    common::run_with_env(proj, args, &[("PATH", path.as_str())])
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
    }
}
