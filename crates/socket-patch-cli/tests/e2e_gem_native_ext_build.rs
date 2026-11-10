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

    let (code, stdout, stderr) = fx.run(&["apply", "--json"]);
    assert_eq!(code, 0, "apply failed:\n{stdout}\n{stderr}");
    assert_eq!(event_action(&stdout), "applied", "{stdout}");
    assert!(evaluated.exists(), "the build loads the gemspec");
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

/// Run the CLI with a `PATH` holding no `ruby`.
fn run_without_ruby(proj: &Path, args: &[&str]) -> (i32, String, String) {
    let empty = proj.join(".empty-path");
    std::fs::create_dir_all(&empty).unwrap();
    let path = empty.display().to_string();
    common::run_with_env(proj, args, &[("PATH", path.as_str())])
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
        // argv: -e <program> extensions_dir <gem home>
        //       -e <program> build <gemspec> <extension dir> <require path>
        let script = format!(
            r#"#!/bin/sh
PATH=/usr/bin:/bin
state='{state}'
mode="$3"
echo "$mode" >> "$state/calls"
env > "$state/env.$mode"
case "$mode" in
extensions_dir)
  printf 'sp_extensions_dir\t%s\n' "$4/extensions/x86_64-linux/3.4.0"
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
  mkdir -p "$ext/sp_native" "$lib/sp_native"
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
    fn run(&self, proj: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
        let path = self.bin.display().to_string();
        let mut all = vec![("PATH", path.as_str())];
        all.extend_from_slice(env);
        common::run_with_env(proj, args, &all)
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
    }
}
