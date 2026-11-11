//! Agent-mode patches to a gem's native extension (#1996).
//!
//! Ruby loads the shared object RubyGems compiled when it installed the gem
//! (`extensions/<platform>/<abi>/<gem>-<version>/…` and, with
//! `Gem.install_extension_in_lib`, its copy under the gem's `lib/`), never
//! the `ext/**/*.c` sources beside it. A patch that rewrites only those
//! sources in place leaves the vulnerable compiled code running. So when a
//! gem patch changes a native-extension build input, `apply` rebuilds the
//! extension from the patched sources with RubyGems' own builder, the step
//! `gem pristine --extensions` runs (`extconf.rb` + `make`, a Rakefile, a
//! CMake or Cargo build), against the Ruby that owns the install:
//!
//! 1. Preflight: the copy must be a RubyGems install (a `specifications/`
//!    entry beside `gems/`) that declares extensions, with an extension dir
//!    on disk and a Ruby to try. Otherwise the purl is refused with
//!    [`UNSUPPORTED_CODE`] and nothing is written.
//! 2. The record's files are verified against the copy, and a Ruby whose
//!    extension dir for the gem is the one on disk is found (or the purl is
//!    refused as in 1).
//! 3. The patched sources are written ([`apply_package_patch`]).
//! 4. The current build is moved aside (and, the first time, copied to a
//!    backup of the original build inside the gem dir, [`BACKUP_DIR`]), and
//!    RubyGems builds the extension into a fresh extension dir.
//! 5. A failed build puts the old build and the original sources back and
//!    fails the purl with [`BUILD_FAILED_CODE`]. A successful one records a
//!    marker ([`MARKER_FILE`]) naming the source hashes it was built from
//!    and the hash of every artifact it produced.
//!
//! `vex` and `apply --check` attest such a copy only when that marker
//! matches the record's patched sources and every recorded artifact still
//! hashes as built ([`verify_native_build`]). `rollback` puts the backed-up
//! original build back ([`restore_original_build`]).
//!
//! # What is executed, and when
//!
//! A gem tree can be supplied by the repository being scanned (a committed
//! `vendor/bundle`), and its installed gemspec is a Ruby program. So
//! whether a record needs a rebuild is decided without running anything:
//! the gemspec is read as text (it is `Gem::Specification#to_ruby` output)
//! for its `extensions` (`parse_extensions`) and its require path
//! (`parse_require_path`), never evaluated. `--dry-run`, `apply --check`
//! and `vex` stop there. They start no Ruby.
//!
//! A real run starts a program only after the record's files verified
//! against the installed copy (each holds its `beforeHash` or `afterHash`
//! content, or a mismatch the caller's policy overwrites), and then, in
//! this order:
//!
//! 1. The host Ruby alone, asked where it builds extensions for the copy's
//!    gem home (`RubyRun::ExtensionsDir`). That loads RubyGems and nothing
//!    of the gem.
//! 2. With the patched sources written, RubyGems' extension builder
//!    (`RubyRun::Build`). It loads the installed gemspec and runs the
//!    gem's own build scripts (`extconf.rb`, a Rakefile, `make`, the
//!    compiler), as `gem install` ran them. It refuses to build when the
//!    loaded gemspec does not describe the layout its text was read for.
//!
//! The Ruby is the one installed beside the gem home, else the `ruby` on
//! `PATH`; one inside the project is never run (`ruby_candidates`). Both
//! runs go without the Socket credentials
//! ([`CHILD_ENV_SCRUB`](crate::utils::process::CHILD_ENV_SCRUB)),
//! `RUBYOPT`, `RUBYLIB` and `BUNDLE*`.
//!
//! The hosted stale-install refresh ([`crate::patch::gem_refresh`]) builds
//! a native gem a third way (`install_staged`, `RubyRun::Install`): the
//! same Ruby, found by the same probe, installs a `.gem` archive whose
//! sha256 the lock pins into an empty stage home. RubyGems reads the spec
//! from the archive's own metadata and runs the archive's build scripts,
//! so nothing the project's tree holds is evaluated, and nothing of the
//! installed copy is touched until the finished gem and extension are
//! swapped in together.
//!
//! # A rebuild that does not finish
//!
//! A build takes minutes, and the run can be interrupted or killed in the
//! middle of it. The build leads its own process group; the CLI's interrupt
//! handler ends that group before it releases the apply lock
//! ([`kill_builds_on_interrupt`](crate::utils::process::kill_builds_on_interrupt)),
//! so no compiler is left writing into the gem. What the run leaves on
//! disk is enough to put the copy right: while a build runs the previous
//! build is parked beside the extension dir (`parked_build_path`), under
//! an advisory lock that goes when its process does, and the previous
//! marker stays in the gem dir until a finished build's replaces it. The
//! next `apply` or `rollback` of the copy starts by moving the parked
//! build back (`recover_interrupted_rebuild`). The sources stay patched,
//! which is the state `apply` completes with a rebuild and `rollback`
//! undoes. A parked build that a rebuild still running in another process
//! holds (a gem home shared between projects) is left alone, and the purl
//! is refused.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::manifest::schema::PatchFileInfo;
use crate::patch::apply::{
    apply_file_patch_at, apply_package_patch, is_safe_relative_subpath, normalize_file_path,
    ApplyResult, MismatchPolicy, PatchSources,
};
use crate::patch::file_hash::compute_file_git_sha256_sync;
use crate::utils::fs::read_regular_to_bytes_sync;

/// The refusal when a native-extension patch cannot be rebuilt in place
/// (the vendored backend's code for the same limitation).
pub const UNSUPPORTED_CODE: &str = "native_extensions_unsupported";
/// The extension failed to build from the patched sources; the old build
/// and the original sources were put back.
pub const BUILD_FAILED_CODE: &str = "native_extension_build_failed";
/// Advisory: sources an earlier run patched were rebuilt into the extension
/// (a release before #1996 patched them without a rebuild).
pub const REBUILT_CODE: &str = "native_extension_rebuilt";
/// `rollback` restored the sources but could not put the original compiled
/// extension back.
pub const RESTORE_FAILED_CODE: &str = "native_extension_restore_failed";
/// The `vex` / `apply --check` routing tag of a copy whose sources carry
/// the patch while its compiled extension was not built from them.
pub const NOT_REBUILT_REASON: &str = "native_extension_not_rebuilt";

/// The build marker, in the gem dir (see [`BuildMarker`]).
pub const MARKER_FILE: &str = ".socket-patch-native-build.json";
/// The original build's backup, in the gem dir (see [`restore_original_build`]).
pub const BACKUP_DIR: &str = ".socket-patch-native-orig";
/// The backup's description file, inside [`BACKUP_DIR`].
const BACKUP_INFO: &str = "backup.json";

/// How long one Ruby probe may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long one extension build may take (nokogiri's vendored libxml2 build
/// takes minutes).
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// The file RubyGems leaves in an extension dir once every extension of
/// the gem is built: without it the gem counts as not built, and RubyGems
/// ignores it.
const BUILD_COMPLETE: &str = "gem.build_complete";

/// Files RubyGems writes into an extension dir that are not build products.
const EXT_DIR_METADATA: &[&str] = &[BUILD_COMPLETE, "gem_make.out", "mkmf.log"];

/// Source and build-script extensions a native extension compiles.
const NATIVE_SOURCE_EXTENSIONS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "hh", "hpp", "hxx", "m", "y", "rl",
];

/// Grammar sources a gem ships already generated (racc / ragel output is a
/// `.rb` or `.c` file the gem packs): in a gem that builds no extension they
/// compile nothing at install time.
const GENERATED_GRAMMAR_EXTENSIONS: &[&str] = &["y", "rl"];

/// The probe/build program run by the gem's Ruby ([`RubyRun`] names its
/// two modes and their arguments). One line: `-e` with an embedded newline
/// is fragile through a Windows command line. Ruby 1.8 does not load
/// RubyGems by default (and `RUBYOPT` is cleared), so it is required
/// explicitly; a RubyGems older than 2.2 (no per-gem extension dir, no
/// `raw_require_paths`) is refused by name. The probe line carries an
/// `sp_` key so stray output (an `operating_system.rb`, a shim) is skipped.
///
/// `extensions_dir <home>` evaluates nothing of the gem: it is
/// `Gem::BasicSpecification#extensions_dir` for a spec in `<home>`, a
/// function of this Ruby's platform and ABI (and a packager's
/// `default_ext_dir_for`) alone.
///
/// `build <gemspec> <extension dir> <require path>` loads the gemspec,
/// which evaluates it, and builds only when it describes the layout its
/// text was read for: the extension dir the probe was matched to, the
/// require path the lib copies were located by, and at least one extension.
/// Otherwise RubyGems would build into a dir that was not set aside.
///
/// `install <archive> <stage home> <installed home>` installs a `.gem` into
/// an empty stage home with RubyGems' own installer, as Bundler would
/// (no dependency resolution, no documentation), building its extensions
/// with the build arguments RubyGems recorded for the installed copy
/// (`<installed home>/build_info/`). It evaluates nothing of the project:
/// the spec is the archive's own metadata and the build scripts are the
/// archive's.
const RUBY_SCRIPT: &str = "require 'rubygems'; mode, a, b, c = ARGV; \
unless Gem::Specification.respond_to?(:load) && \
Gem::Specification.method_defined?(:extension_dir) && \
Gem::Specification.method_defined?(:raw_require_paths) then \
abort(\"RubyGems #{defined?(Gem::VERSION) ? Gem::VERSION : Gem::RubyGemsVersion} is older than 2.2, \
which has no per-gem extension dir to rebuild into\"); \
end; \
if mode == 'extensions_dir' then \
dir = (Gem.respond_to?(:default_ext_dir_for) && Gem.default_ext_dir_for(a)) || \
File.join(a, 'extensions', Gem::Platform.local.to_s, Gem.extension_api_version); \
puts \"sp_extensions_dir\\t#{File.expand_path(dir)}\"; \
elsif mode == 'install' then \
require 'rubygems/installer'; \
abort(\"RubyGems #{Gem::VERSION} is older than 2.5, whose installer cannot stage a gem\") \
unless Gem::Installer.respond_to?(:at); \
Gem::DefaultUserInteraction.ui = Gem::SilentUI.new; \
full = File.basename(a, '.gem'); \
info = File.join(c, 'build_info', \"#{full}.info\"); \
args = File.file?(info) ? File.readlines(info).map { |l| l.chomp } : []; \
inst = Gem::Installer.at(a, :install_dir => b, :ignore_dependencies => true, :wrappers => true, \
:env_shebang => true, :document => [], :post_install_message => false, :build_args => args); \
inst.install; \
puts \"sp_installed\\t#{inst.spec.full_name}\\t#{File.expand_path(inst.spec.extension_dir)}\"; \
else \
spec = Gem::Specification.load(a) or abort(\"cannot load #{a}\"); \
unless File.expand_path(spec.extension_dir) == File.expand_path(b) then \
abort(\"#{a} builds into #{spec.extension_dir}, not #{b}\"); \
end; \
unless spec.raw_require_paths.first.to_s == c then \
abort(\"#{a} requires from #{spec.raw_require_paths.first.inspect}, not #{c.inspect}\"); \
end; \
abort(\"#{a} declares no extensions\") if spec.extensions.empty?; \
require 'rubygems/ext'; \
Gem::DefaultUserInteraction.ui = Gem::SilentUI.new; \
Gem::Ext::Builder.new(spec, spec.build_args).build_extensions; \
end";

/// One installed RubyGems copy: `<home>/gems/<full_name>` with its
/// `<home>/specifications/<full_name>.gemspec`.
#[derive(Debug, Clone)]
struct GemCopy {
    home: PathBuf,
    full_name: String,
    gem_dir: PathBuf,
    spec_path: PathBuf,
}

impl GemCopy {
    /// The copy at `pkg_path`, when it sits in a RubyGems `gems/` dir.
    /// Whether its spec exists is checked by the caller.
    fn of(pkg_path: &Path) -> Option<GemCopy> {
        // Absolute, because a build runs Ruby from the project dir and
        // `extconf.rb` from the ext dir: a relative crawl root (`--cwd .`,
        // `--cwd proj`) would leave the spec path and `GEM_PATH` pointing
        // nowhere, and an `extconf.rb` that loads `mini_portile2` (nokogiri)
        // from the copy's own home would fail to build. `..` is dropped
        // lexically, as Ruby's `File.expand_path` drops it from the spec
        // path, so both name the same gem dir. A rooted path is kept as is.
        let pkg_path = if pkg_path.has_root() {
            pkg_path.to_path_buf()
        } else {
            crate::utils::relpath::absolute_lexically(pkg_path)
        };
        let pkg_path = pkg_path.as_path();
        let full_name = pkg_path.file_name()?.to_str()?.to_string();
        let gems = pkg_path.parent()?;
        if gems.file_name()? != "gems" {
            return None;
        }
        let home = gems.parent()?.to_path_buf();
        let spec_path = home
            .join("specifications")
            .join(format!("{full_name}.gemspec"));
        Some(GemCopy {
            home,
            full_name,
            gem_dir: pkg_path.to_path_buf(),
            spec_path,
        })
    }
}

/// What the installed gemspec says about extensions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExtensionDecl {
    /// The spec assigns `extensions`.
    declared: bool,
    /// The declared build scripts (`ext/foo/extconf.rb`), when the
    /// assignment lists them as string literals.
    entries: Vec<String>,
}

/// Parse `s.extensions = ["ext/foo/extconf.rb".freeze, …]` out of an
/// installed gemspec (the `Specification#to_ruby` shape RubyGems writes).
/// Whether extensions are declared is the vendored backend's test
/// ([`gemspec_declares_extensions`](crate::vendor::gem::gemspec_declares_extensions)),
/// so both modes agree on which gems are native; the build scripts are the
/// string literals those assignments list. Comments are stripped per line;
/// an assignment whose entries are not string literals is `declared` with
/// no `entries`.
fn parse_extensions(spec_text: &str) -> ExtensionDecl {
    let mut entries = Vec::new();
    for raw in spec_text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        let Some(idx) = line.find(".extensions") else {
            continue;
        };
        let after = &line[idx + ".extensions".len()..];
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let after = after.trim_start();
        let rhs = ["+=", "<<", ".push", ".concat"]
            .iter()
            .find_map(|op| after.strip_prefix(op))
            .or_else(|| after.strip_prefix('=').filter(|r| !r.starts_with('=')));
        if let Some(rhs) = rhs {
            entries.extend(string_literals(rhs));
        }
    }
    ExtensionDecl {
        declared: crate::vendor::gem::gemspec_declares_extensions(spec_text),
        entries,
    }
}

/// The gem's first require path (`lib`), parsed out of an installed
/// gemspec's `s.require_paths = ["lib".freeze]` (`Specification#to_ruby`
/// always writes the assignment). RubyGems installs the built extension's
/// copies under it. A spec that assigns none has RubyGems' default, `lib`;
/// an assignment whose first entry is not a string literal is `None`.
fn parse_require_path(spec_text: &str) -> Option<String> {
    for raw in spec_text.lines() {
        let line = raw.split('#').next().unwrap_or("");
        let Some(idx) = line.find(".require_paths") else {
            continue;
        };
        let after = &line[idx + ".require_paths".len()..];
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            continue;
        }
        let assigned = after.trim_start().strip_prefix('=');
        if let Some(rhs) = assigned.filter(|r| !r.starts_with('=')) {
            return string_literals(rhs).into_iter().next();
        }
    }
    Some("lib".to_string())
}

/// The double- and single-quoted string literals in `text`, in order.
fn string_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '"' && c != '\'' {
            continue;
        }
        let mut lit = String::new();
        let mut escaped = false;
        for d in chars.by_ref() {
            if escaped {
                lit.push(d);
                escaped = false;
            } else if d == '\\' {
                escaped = true;
            } else if d == c {
                break;
            } else {
                lit.push(d);
            }
        }
        out.push(lit);
    }
    out
}

/// Whether a (normalized) gem file path is a native-extension build input by
/// its name alone: a C/C++/Objective-C source or header, a racc/ragel
/// grammar, an `extconf.rb`, or a `depend` file under `ext/`.
fn is_native_by_name(path: &str) -> bool {
    let leaf = path.rsplit('/').next().unwrap_or(path);
    if leaf == "extconf.rb" || (leaf == "depend" && path.starts_with("ext/")) {
        return true;
    }
    leaf.rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty() && NATIVE_SOURCE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
    })
}

fn is_generated_grammar(path: &str) -> bool {
    path.rsplit_once('.').is_some_and(|(_, ext)| {
        GENERATED_GRAMMAR_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
    })
}

/// A gem record's native-extension build inputs on one installed copy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NativeScope {
    /// The record's keys that are build inputs, sorted.
    inputs: Vec<String>,
    /// The installed spec declares extensions (RubyGems builds them at
    /// install time). `false` with inputs left: the gem's compiled code, if
    /// any, ships precompiled.
    builds_extensions: bool,
}

/// Classify `files` against the extension declaration `decl`.
///
/// In a gem that declares extensions, a key is a build input by name
/// ([`is_native_by_name`]) or by living under the dir of a declared build
/// script (a Rust extension's `.rs` sources, a `Rakefile`-built tree); a
/// script at the gem root (`extensions = ["extconf.rb"]`) makes the files
/// beside it inputs, the ones mkmf compiles, not every file of the gem. A
/// declaration whose scripts are unknown makes everything under `ext/` an
/// input.
///
/// In a gem that declares none, only a name-matched source under `ext/`
/// counts: that is where a precompiled platform gem keeps the sources of
/// the binary it ships. C or Objective-C files elsewhere (a template, a
/// test fixture) compile nothing, and neither do grammar sources, whose
/// generated output the gem packs.
fn classify(decl: &ExtensionDecl, files: &HashMap<String, PatchFileInfo>) -> NativeScope {
    // `None`: a script at the gem root.
    let dirs: Vec<Option<String>> = decl
        .entries
        .iter()
        .map(|e| {
            e.trim_start_matches("./")
                .rsplit_once('/')
                .map(|(dir, _)| format!("{dir}/"))
        })
        .collect();
    let under_script_dir = |path: &str| {
        dirs.iter().any(|d| match d {
            Some(d) => path.starts_with(d.as_str()),
            None => !path.contains('/'),
        })
    };
    let unknown_scripts = decl.declared && decl.entries.is_empty();
    let mut inputs: Vec<String> = files
        .keys()
        .filter(|key| {
            let path = normalize_file_path(key);
            if decl.declared {
                is_native_by_name(path)
                    || under_script_dir(path)
                    || (unknown_scripts && path.starts_with("ext/"))
            } else {
                path.starts_with("ext/") && is_native_by_name(path) && !is_generated_grammar(path)
            }
        })
        .cloned()
        .collect();
    inputs.sort();
    NativeScope {
        inputs,
        builds_extensions: decl.declared,
    }
}

/// The record's native scope on the copy at `pkg_path`, and the copy when it
/// is a RubyGems install whose spec could be read. `None` scope inputs mean
/// the record is plain Ruby for this copy.
async fn scope_of(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> (NativeScope, Option<GemCopy>) {
    let copy = GemCopy::of(pkg_path);
    let spec_text = match &copy {
        Some(c) => crate::utils::fs::read_regular_to_string(&c.spec_path)
            .await
            .ok(),
        None => None,
    };
    let decl = spec_text
        .as_deref()
        .map(parse_extensions)
        .unwrap_or_default();
    let scope = classify(&decl, files);
    // Without a readable spec nothing proves which scripts the gem builds;
    // name-matched inputs still count, and the copy is unusable for a build.
    (scope, copy.filter(|_| spec_text.is_some()))
}

/// The build marker written into the gem dir after a rebuild.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildMarker {
    pub schema: u32,
    /// Native input (normalized path) → its git-sha256 when it was built.
    pub sources: BTreeMap<String, String>,
    /// The extension dir built into, relative to the gem home:
    /// `extensions/<platform>/<abi>/<full_name>` (see [`confined_ext_dir`]).
    pub extension_dir: String,
    /// Artifact path relative to the extension dir → git-sha256.
    pub ext_artifacts: BTreeMap<String, String>,
    /// The artifacts' copies RubyGems put under the gem's require dir:
    /// path relative to the gem dir → git-sha256.
    pub lib_artifacts: BTreeMap<String, String>,
}

const MARKER_SCHEMA: u32 = 1;

/// The extension dir a marker or backup names, only when it is
/// `extensions/<platform>/<abi>/<full_name>` under the copy's home: those
/// files sit in the gem dir, where a checkout could plant them, so the path
/// they hold is never trusted further than the one dir RubyGems builds this
/// gem into.
fn confined_ext_dir(copy: &GemCopy, label: &str) -> Option<PathBuf> {
    let parts: Vec<&str> = label.split('/').collect();
    let confined = parts.len() == 4
        && parts[0] == "extensions"
        && parts[3] == copy.full_name
        && is_safe_relative_subpath(label);
    confined.then(|| copy.home.join(label))
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

fn read_marker_sync(gem_dir: &Path) -> Option<BuildMarker> {
    let text = crate::utils::fs::read_regular_to_string_sync(&gem_dir.join(MARKER_FILE)).ok()?;
    serde_json::from_str::<BuildMarker>(&text)
        .ok()
        .filter(|m| m.schema == MARKER_SCHEMA)
}

/// Whether `marker` was built from exactly the record's patched native
/// inputs, and every artifact it recorded is still on disk with the bytes it
/// was built with. An artifact path that escapes its dir never verifies.
fn marker_holds(
    marker: &BuildMarker,
    copy: &GemCopy,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    let sources_match = scope.inputs.iter().all(|key| {
        marker.sources.get(normalize_file_path(key)) == files.get(key).map(|i| &i.after_hash)
    });
    if !sources_match || marker.sources.len() != scope.inputs.len() {
        return false;
    }
    let Some(ext_dir) = confined_ext_dir(copy, &marker.extension_dir) else {
        return false;
    };
    let artifact_ok = |base: &Path, rel: &str, hash: &str| {
        is_safe_relative_subpath(rel)
            && compute_file_git_sha256_sync(&base.join(rel)).is_ok_and(|h| h == hash)
    };
    marker
        .ext_artifacts
        .iter()
        .all(|(rel, hash)| artifact_ok(&ext_dir, rel, hash))
        && marker
            .lib_artifacts
            .iter()
            .all(|(rel, hash)| artifact_ok(&copy.gem_dir, rel, hash))
}

/// `vex` / `apply --check`: the installed gem copy at `pkg_path`, whose
/// record files already verify, runs code built from them. A record with no
/// native input on this copy passes; one with native inputs passes only when
/// the copy's build marker holds ([`BuildMarker`]). Errors carry
/// [`NOT_REBUILT_REASON`].
pub async fn verify_native_build(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Result<(), String> {
    let (scope, copy) = scope_of(pkg_path, files).await;
    if scope.inputs.is_empty() {
        return Ok(());
    }
    let Some(copy) = copy.filter(|_| scope.builds_extensions) else {
        return Err(NOT_REBUILT_REASON.to_string());
    };
    let files = files.clone();
    let holds = crate::utils::fs::run_blocking(move || {
        read_marker_sync(&copy.gem_dir).is_some_and(|m| marker_holds(&m, &copy, &scope, &files))
    })
    .await;
    if holds {
        Ok(())
    } else {
        Err(NOT_REBUILT_REASON.to_string())
    }
}

/// [`apply_gem_package_patch`]'s outcome: the copy's result, and a run
/// warning `(code, detail)` the caller surfaces next to it.
#[derive(Debug, Clone)]
pub struct GemApplied {
    pub result: ApplyResult,
    pub warning: Option<(String, String)>,
}

/// Where the Ruby that builds a copy's extension is looked for and run.
#[derive(Debug, Clone)]
pub struct RubyEnv {
    /// The project dir the Ruby on `PATH` runs from (a version manager's
    /// `.ruby-version` there picks the project's Ruby).
    pub cwd: PathBuf,
    /// Rebuild native extensions. `false` (`--no-gem-native-rebuild`): the
    /// caller compiles them itself, so patched sources are written without
    /// a build, as before #1996, with a [`NOT_REBUILT_REASON`] warning.
    pub rebuild: bool,
}

/// The Ruby that builds a gem copy's extension, and where the build lands.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Probe {
    ruby: PathBuf,
    gem_dir: PathBuf,
    /// Where `ruby` builds the gem's extension, as it spells the path: one
    /// of the copy's installed extension dirs.
    extension_dir: PathBuf,
    /// The gem's first require path as its gemspec spells it (`lib`).
    require_path: String,
    /// `gem_dir` / `require_path`: where RubyGems copies the artifacts.
    lib_dir: PathBuf,
}

/// The `sp_extensions_dir` line of a [`RubyRun::ExtensionsDir`] run.
fn parse_extensions_dir(stdout: &str) -> Option<PathBuf> {
    stdout.lines().find_map(|line| {
        let (key, value) = line.split_once('\t')?;
        (key == "sp_extensions_dir" && !value.is_empty()).then(|| PathBuf::from(value))
    })
}

/// The Rubies that may own `copy`, best first: the one installed beside a
/// `<prefix>/lib/ruby/gems/<abi>` home (rbenv, asdf, rvm, a system Ruby),
/// then the `ruby` on `PATH`. A prefix inside the project (`project`) is
/// never one: the scanned repository does not choose the program run.
fn ruby_candidates(copy: &GemCopy, project: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let exe = if cfg!(windows) { "ruby.exe" } else { "ruby" };
    let mut parts = copy.home.ancestors();
    parts.next(); // <abi>
    if let (Some(gems), Some(ruby), Some(lib), Some(prefix)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    {
        if gems.file_name().is_some_and(|n| n == "gems")
            && ruby.file_name().is_some_and(|n| n == "ruby")
            && lib.file_name().is_some_and(|n| n == "lib")
        {
            let candidate = prefix.join("bin").join(exe);
            let in_project = match (canonical(prefix), canonical(project)) {
                (Some(prefix), Some(project)) => prefix.starts_with(project),
                _ => prefix.starts_with(project),
            };
            if !in_project && candidate.is_file() {
                out.push(candidate);
            }
        }
    }
    if let Some(on_path) = crate::utils::process::resolve_tool("ruby") {
        if !out.contains(&on_path) {
            out.push(on_path);
        }
    }
    out
}

/// The `GEM_PATH` a build runs with: the copy's home first (an `extconf.rb`
/// requiring `mini_portile2` or `rb_sys` finds the copy installed beside
/// it), then the caller's, then RubyGems' defaults (the trailing separator).
fn gem_path_for(home: &Path) -> Option<OsString> {
    let mut paths = vec![home.to_path_buf()];
    if let Some(existing) = std::env::var_os("GEM_PATH") {
        paths.extend(std::env::split_paths(&existing).filter(|p| !p.as_os_str().is_empty()));
    }
    let mut joined = std::env::join_paths(paths).ok()?;
    joined.push(if cfg!(windows) { ";" } else { ":" });
    Some(joined)
}

/// What a run of [`RUBY_SCRIPT`] is for.
enum RubyRun<'a> {
    /// Ask where this Ruby builds extensions for the copy's gem home. Loads
    /// RubyGems and nothing of the gem.
    ExtensionsDir,
    /// Build the copy's extensions into `probe.extension_dir`: loads the
    /// installed gemspec and runs the gem's build scripts.
    Build(&'a Probe),
    /// Install the `.gem` at `archive` into the empty `stage_home`, building
    /// its extensions there: runs the archive's own build scripts.
    Install {
        archive: &'a Path,
        stage_home: &'a Path,
    },
}

/// Run the Ruby program for `run` on `copy`, bounded by `budget` through
/// [`build_output_within`](crate::utils::process::build_output_within)
/// (a timeout kills the build's whole process group). `Ok` carries stdout;
/// `Err` a short reason (stderr's tail on a failed exit).
async fn run_ruby(
    ruby: &Path,
    run: RubyRun<'_>,
    copy: &GemCopy,
    env: &RubyEnv,
    budget: Duration,
) -> Result<String, String> {
    use crate::utils::process::{build_output_within, command_for, BoundedError};
    let mut command = command_for(ruby);
    command.arg("-e").arg(RUBY_SCRIPT).current_dir(&env.cwd);
    let mode = match run {
        RubyRun::ExtensionsDir => {
            command.arg("extensions_dir").arg(&copy.home);
            "extensions_dir"
        }
        RubyRun::Build(probe) => {
            command
                .arg("build")
                .arg(&copy.spec_path)
                .arg(&probe.extension_dir)
                .arg(&probe.require_path);
            if let Some(gem_path) = gem_path_for(&copy.home) {
                command.env("GEM_PATH", gem_path);
            }
            "build"
        }
        RubyRun::Install {
            archive,
            stage_home,
        } => {
            command
                .arg("install")
                .arg(archive)
                .arg(stage_home)
                .arg(&copy.home);
            // The installed copy's home, where the gems its build scripts
            // require were installed beside it.
            if let Some(gem_path) = gem_path_for(&copy.home) {
                command.env("GEM_PATH", gem_path);
            }
            "install"
        }
    };
    // A Bundler-run parent (`bundle exec`, the Bundler plugin) must not
    // load the project's bundle into this Ruby.
    for (key, _) in std::env::vars_os() {
        let key_str = key.to_string_lossy();
        if key_str == "RUBYOPT" || key_str == "RUBYLIB" || key_str.starts_with("BUNDLE") {
            command.env_remove(&key);
        }
    }
    let output = crate::utils::fs::run_blocking(move || build_output_within(command, budget)).await;
    let output = match output {
        Err(BoundedError::TimedOut) => {
            return Err(format!(
                "{} {mode} did not finish within {} minutes",
                ruby.display(),
                budget.as_secs() / 60
            ))
        }
        Err(BoundedError::Spawn(e)) => {
            return Err(format!("could not run {}: {e}", ruby.display()))
        }
        Ok(output) => output,
    };
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(stderr_tail(&String::from_utf8_lossy(&output.stderr)))
    }
}

/// The useful end of a failed build's stderr: RubyGems' trailing
/// "Gem files will remain installed" boilerplate dropped, at most 20 lines.
fn stderr_tail(stderr: &str) -> String {
    let text = stderr
        .split("\nGem files will remain installed")
        .next()
        .unwrap_or(stderr);
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty())
        .collect();
    let start = lines.len().saturating_sub(20);
    let tail = lines[start..].join("\n");
    if tail.is_empty() {
        "the build exited with an error and no output".to_string()
    } else {
        tail
    }
}

/// `<home>/extensions/<platform>/<abi>/<full_name>` for every platform and
/// ABI dir of the home, whether or not the gem has a build there.
fn extension_dir_slots(copy: &GemCopy) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(platforms) = std::fs::read_dir(copy.home.join("extensions")) else {
        return out;
    };
    for platform in platforms.flatten() {
        let Ok(abis) = std::fs::read_dir(platform.path()) else {
            continue;
        };
        for abi in abis.flatten() {
            out.push(abi.path().join(&copy.full_name));
        }
    }
    out.sort();
    out
}

/// A directory, not a symlink to one.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// The extension dirs of `full_name` under `home/extensions/*/*/`: a build
/// that is there, or one an unfinished rebuild left parked beside its
/// place ([`parked_build_path`]). A real run moves that one back before it
/// gets here ([`recover_interrupted_rebuild`]); a dry run only reads.
fn installed_extension_dirs(copy: &GemCopy) -> Vec<PathBuf> {
    extension_dir_slots(copy)
        .into_iter()
        .filter(|dir| is_real_dir(dir) || is_real_dir(&parked_build_path(dir)))
        .collect()
}

/// Where a rebuild parks the previous build of the extension dir `ext`:
/// beside it, so moving it there and back is a rename.
fn parked_build_path(ext: &Path) -> PathBuf {
    let leaf = ext
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    ext.with_file_name(format!(".{leaf}.socket-patch-old"))
}

/// Take the rebuild lock of a build dir (an extension dir about to be
/// parked, or a parked one): an exclusive advisory lock on the directory
/// itself. It follows the directory through its renames and goes when the
/// holder's process ends, however that happens, so a parked build that can
/// be locked belongs to no rebuild that is still running. The apply lock
/// does not say that: it is per project, and a gem home can be shared.
///
/// `Ok(None)` where a directory cannot be locked (Windows, a filesystem
/// without advisory locks): the caller goes ahead unguarded. `Err` of kind
/// `WouldBlock`: another process is rebuilding this gem right now. `Err`
/// of kind `NotFound`: `dir` is gone, or is no longer the directory that
/// was locked (its rebuild finished in between).
fn lock_build_dir(dir: &Path) -> std::io::Result<Option<std::fs::File>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let handle = std::fs::File::open(dir)?;
        // A lock this process dropped a moment ago can linger for the time
        // a child being spawned on another thread takes to exec: it holds
        // a copy of the descriptor until then. A live rebuild holds on.
        let mut attempts = 0;
        loop {
            match handle.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if attempts < 5 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "another socket-patch run is rebuilding this gem's extension",
                    ));
                }
                Err(std::fs::TryLockError::Error(_)) => return Ok(None),
            }
        }
        let (locked, named) = (handle.metadata()?, std::fs::symlink_metadata(dir)?);
        if (locked.dev(), locked.ino()) != (named.dev(), named.ino()) {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        Ok(Some(handle))
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(None)
    }
}

/// Put `copy` back together after a rebuild of it that never finished: its
/// process was interrupted, or killed, between parking the previous build
/// and recording the new one. `Ok(true)` when something was put right.
///
/// The sign is a parked build ([`parked_build_path`]) that no live process
/// holds. When the extension dir beside it is a finished build
/// (`gem.build_complete`: the interrupted build got that far, or `gem
/// pristine` ran since), that build stands and the parked one goes.
/// Otherwise whatever the build left is dropped, the parked build is moved
/// back, and the `lib/` copies of its artifacts are brought back in line
/// with it ([`realign_lib_copies`]). The build marker never left the gem
/// dir during the build, so it describes the build that is back.
///
/// The sources stay as the unfinished run left them, patched: with the
/// previous build back that is the state of a copy whose sources were
/// patched without a rebuild, which `apply` completes and `rollback`
/// undoes.
fn recover_interrupted_rebuild_sync(
    copy: &GemCopy,
    require_path: Option<&str>,
) -> std::io::Result<bool> {
    let mut recovered = false;
    for ext in extension_dir_slots(copy) {
        let parked = parked_build_path(&ext);
        if !is_real_dir(&parked) {
            continue;
        }
        let _lock = match lock_build_dir(&parked) {
            Ok(lock) => lock,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if is_symlink(&ext) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is a symlink, not an extension dir", ext.display()),
            ));
        }
        if ext.join(BUILD_COMPLETE).is_file() {
            remove_dir_if_exists(&parked)?;
        } else {
            remove_dir_if_exists(&ext)?;
            std::fs::rename(&parked, &ext)?;
            if let Some(require_path) = require_path {
                realign_lib_copies(copy, &ext, require_path);
            }
        }
        recovered = true;
    }
    Ok(recovered)
}

/// Bring the `lib/` copies of `ext`'s artifacts back in line with it:
/// RubyGems installs them as copies of the extension dir's files, and a
/// build stopped late has already replaced some. Only a copy that is there
/// is rewritten. Best effort, as RubyGems loads the extension dir first.
fn realign_lib_copies(copy: &GemCopy, ext: &Path, require_path: &str) {
    for rel in artifact_rels(ext) {
        let (built, lib) = (ext.join(&rel), copy.gem_dir.join(require_path).join(&rel));
        let (Ok(bytes), Ok(current)) = (
            read_regular_to_bytes_sync(&built),
            read_regular_to_bytes_sync(&lib),
        ) else {
            continue;
        };
        if bytes == current {
            continue;
        }
        let perms = std::fs::metadata(&built).map(|m| m.permissions());
        let _ = replace_file(&lib, |stage| {
            std::fs::write(stage, &bytes)?;
            match &perms {
                Ok(perms) => std::fs::set_permissions(stage, perms.clone()),
                Err(_) => Ok(()),
            }
        });
    }
}

/// [`recover_interrupted_rebuild_sync`] for `copy`, with the require path
/// its gemspec's text names.
async fn recover_interrupted_rebuild(copy: &GemCopy) -> std::io::Result<bool> {
    let require_path = require_path_of(copy).await;
    let copy = copy.clone();
    crate::utils::fs::run_blocking(move || {
        recover_interrupted_rebuild_sync(&copy, require_path.as_deref())
    })
    .await
}

/// Why an unfinished rebuild of `copy` could not be put right, as the
/// reason of a refusal.
fn recovery_refusal(copy: &GemCopy, error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        "another socket-patch run is rebuilding this gem's extension right now; run again \
         when it has finished"
            .to_string()
    } else {
        format!(
            "a rebuild of this gem's extension that an earlier run did not finish could not \
             be undone ({error}); run `gem pristine {} --extensions`",
            gem_name_of(&copy.full_name)
        )
    }
}

/// The copy's first require path, from its gemspec's text: `None` when the
/// spec cannot be read or names none inside the gem.
async fn require_path_of(copy: &GemCopy) -> Option<String> {
    crate::utils::fs::read_regular_to_string(&copy.spec_path)
        .await
        .ok()
        .as_deref()
        .and_then(parse_require_path)
        .filter(|path| is_safe_relative_subpath(path))
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (canonical(a), canonical(b)) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

fn canonical(p: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(p).ok()
}

/// What a rebuild of a copy needs that files alone tell: nothing is run to
/// learn it, so a dry run can refuse on it too.
#[derive(Debug, Clone)]
struct Preflight {
    /// The copy's extension dirs under `<home>/extensions/<platform>/<abi>/`.
    installed: Vec<PathBuf>,
    /// The Rubies that may own the install, best first.
    candidates: Vec<PathBuf>,
    /// The gem's first require path, from its gemspec's text.
    require_path: String,
}

/// The [`Preflight`] of `copy`. A gem with no extension dir (installed by a
/// RubyGems older than 2.2, or its build removed) has no build a Ruby can
/// be matched to. `Err` names why the copy cannot be rebuilt.
async fn rebuild_preflight(copy: &GemCopy, env: &RubyEnv) -> Result<Preflight, String> {
    let installed = {
        let copy = copy.clone();
        crate::utils::fs::run_blocking(move || installed_extension_dirs(&copy)).await
    };
    if installed.is_empty() {
        return Err(format!(
            "the gem has no compiled extension dir under {} (it was installed by a \
             RubyGems older than 2.2, or its build is missing)",
            copy.home.join("extensions").display()
        ));
    }
    let require_path = require_path_of(copy).await.ok_or_else(|| {
        format!(
            "{} does not name a require path inside the gem",
            copy.spec_path.display()
        )
    })?;
    let candidates = ruby_candidates(copy, &env.cwd);
    if candidates.is_empty() {
        return Err("no `ruby` was found on PATH to rebuild it with".to_string());
    }
    Ok(Preflight {
        installed,
        candidates,
        require_path,
    })
}

/// Find the Ruby that owns `copy`'s install: the one whose extension dir
/// for this gem is the installed `<home>/extensions/<platform>/<abi>/` one
/// (its platform and ABI). Each candidate is asked where it builds
/// extensions for the gem home ([`RubyRun::ExtensionsDir`]), which loads
/// nothing of the gem. `Err` names why none qualifies.
async fn find_ruby(copy: &GemCopy, env: &RubyEnv, preflight: Preflight) -> Result<Probe, String> {
    let Preflight {
        installed,
        candidates,
        require_path,
    } = preflight;
    let mut reasons = Vec::new();
    for ruby in candidates {
        let stdout = match run_ruby(&ruby, RubyRun::ExtensionsDir, copy, env, PROBE_TIMEOUT).await {
            Ok(s) => s,
            Err(e) => {
                reasons.push(format!("{}: {e}", ruby.display()));
                continue;
            }
        };
        let Some(extensions_dir) = parse_extensions_dir(&stdout) else {
            reasons.push(format!("{}: unreadable probe output", ruby.display()));
            continue;
        };
        let extension_dir = extensions_dir.join(&copy.full_name);
        if !installed.iter().any(|d| same_path(d, &extension_dir)) {
            reasons.push(format!(
                "{} builds into {}, but the installed extension is {} (another Ruby's)",
                ruby.display(),
                extension_dir.display(),
                installed
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            continue;
        }
        return Ok(Probe {
            ruby,
            gem_dir: copy.gem_dir.clone(),
            extension_dir,
            lib_dir: copy.gem_dir.join(&require_path),
            require_path,
        });
    }
    Err(format!(
        "no Ruby owning this install was found ({})",
        reasons.join("; ")
    ))
}

/// A `.gem` RubyGems installed into a stage home ([`install_staged`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StagedInstall {
    /// `<stage home>/gems/<full_name>`: the extracted gem, with the built
    /// artifacts' copies under its require dir.
    pub gem_dir: PathBuf,
    /// The extension dir the build left in the stage home.
    pub extension_dir: PathBuf,
    /// The installed copy's extension dir, which the staged one replaces:
    /// the same `extensions/<platform>/<abi>/<full_name>` under its home.
    pub installed_extension_dir: PathBuf,
}

/// The `sp_installed` line of a [`RubyRun::Install`] run: the installed
/// gem's full name and its extension dir.
fn parse_installed(stdout: &str) -> Option<(String, PathBuf)> {
    stdout.lines().find_map(|line| {
        let mut fields = line.split('\t');
        (fields.next()? == "sp_installed").then_some(())?;
        let (full_name, ext) = (fields.next()?, fields.next()?);
        (!full_name.is_empty() && !ext.is_empty())
            .then(|| (full_name.to_string(), PathBuf::from(ext)))
    })
}

/// Install the verified `.gem` at `archive` into the empty `stage_home`
/// with the Ruby that owns the installed copy at `installed`, so the gem
/// and the extension RubyGems compiles from it can replace that copy's
/// (the hosted stale-install refresh, [`crate::patch::gem_refresh`]).
/// Nothing of the installed copy is changed. The Ruby is found as for a
/// rebuild ([`find_ruby`]): the one whose extension dir for the gem is the
/// installed one, so the staged build has the installed build's platform
/// and ABI. `Err` says why there is no staged install to use.
pub(crate) async fn install_staged(
    installed: &Path,
    archive: &Path,
    stage_home: &Path,
    env: &RubyEnv,
) -> Result<StagedInstall, String> {
    let copy = GemCopy::of(installed)
        .ok_or_else(|| format!("{} is not a RubyGems install", installed.display()))?;
    if let Err(e) = recover_interrupted_rebuild(&copy).await {
        return Err(recovery_refusal(&copy, &e));
    }
    let preflight = rebuild_preflight(&copy, env).await?;
    let probe = find_ruby(&copy, env, preflight).await?;
    let label = ext_dir_label(&copy.home, &probe.extension_dir);
    if confined_ext_dir(&copy, &label).is_none() {
        return Err(format!(
            "its extension is built into {}, outside its gem home",
            probe.extension_dir.display()
        ));
    }
    let run = RubyRun::Install {
        archive,
        stage_home,
    };
    let stdout = run_ruby(&probe.ruby, run, &copy, env, BUILD_TIMEOUT).await?;
    let (full_name, built) = parse_installed(&stdout)
        .ok_or_else(|| format!("{}: unreadable install output", probe.ruby.display()))?;
    let staged = StagedInstall {
        gem_dir: stage_home.join("gems").join(&copy.full_name),
        extension_dir: stage_home.join(&label),
        installed_extension_dir: probe.extension_dir,
    };
    if full_name != copy.full_name || !same_path(&built, &staged.extension_dir) {
        return Err(format!(
            "RubyGems installed {full_name} with its extension in {}, not {} in {}",
            built.display(),
            copy.full_name,
            staged.extension_dir.display()
        ));
    }
    if !is_real_dir(&staged.gem_dir) || !staged.extension_dir.join(BUILD_COMPLETE).is_file() {
        return Err("the build exited cleanly but left no finished extension".to_string());
    }
    Ok(staged)
}

/// Every regular file under `dir`, relative, `/`-separated, sorted;
/// RubyGems' metadata files at the top level and the stage dirs a build
/// leaves are skipped.
fn artifact_rels(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .flatten()
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(dir) else {
            continue;
        };
        let rel = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if EXT_DIR_METADATA.contains(&rel.as_str()) || rel == MARKER_FILE {
            continue;
        }
        out.push(rel);
    }
    out
}

/// An extension-dir artifact's copy in the gem's require dir, relative to
/// the gem dir (`a/a.so` → `lib/a/a.so`). `None` when the require dir is
/// not inside the gem dir.
fn lib_rel(probe: &Probe, rel: &str) -> Option<String> {
    let lib = probe.lib_dir.strip_prefix(&probe.gem_dir).ok()?;
    let s = lib
        .join(rel)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");
    is_safe_relative_subpath(&s).then_some(s)
}

/// A fresh copy of the tree `from` at `to` (replacing it).
fn copy_tree_sync(from: &Path, to: &Path) -> std::io::Result<()> {
    crate::patch::copy_tree::copy_tree_blocking(from, to, None)
}

/// Replace `dst` through a stage beside it and a rename, never rewriting
/// its inode: a running Ruby may have the old `.so` / `.bundle` mapped, and
/// rewriting those pages under it crashes it. `fill` writes the stage.
fn replace_file(
    dst: &Path,
    fill: impl FnOnce(&Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let leaf = dst
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let stage = dst.with_file_name(format!(".{leaf}.socket-patch-stage"));
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _ = std::fs::remove_file(&stage);
    let filled = fill(&stage).and_then(|()| std::fs::rename(&stage, dst));
    if filled.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
    filled
}

fn remove_dir_if_exists(dir: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => crate::patch::copy_tree::force_remove_dir_all(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The backup's description.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupInfo {
    /// As [`BuildMarker::extension_dir`].
    extension_dir: String,
    /// The extension dir existed (its tree is under `ext/`).
    had_extension_dir: bool,
    /// The lib copies backed up under `lib/` (paths relative to the gem dir).
    lib_files: Vec<String>,
}

/// [`BuildMarker::extension_dir`] for `ext_dir` (one of the copy's
/// installed extension dirs, [`find_ruby`]): relative to `home`, compared
/// canonically too (Ruby and the crawler may spell the same dir
/// differently through a symlink: `/tmp` vs `/private/tmp`), so the
/// record survives the project moving.
fn ext_dir_label(home: &Path, ext_dir: &Path) -> String {
    let canonical_rel = || {
        let (home, ext) = (canonical(home)?, canonical(ext_dir)?);
        ext.strip_prefix(&home).ok().map(Path::to_path_buf)
    };
    let rel = ext_dir
        .strip_prefix(home)
        .ok()
        .map(Path::to_path_buf)
        .or_else(canonical_rel);
    match rel.as_deref().ok_or(()) {
        Ok(rel) => rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
        Err(_) => ext_dir.display().to_string(),
    }
}

/// Back up the original build of `copy` (its extension dir and the lib
/// copies of its artifacts) to [`BACKUP_DIR`], unless a backup exists or the
/// current build is one socket-patch made (a marker exists: its original is
/// gone). Staged and renamed into place, so a backup dir is always whole.
/// `Ok(true)` when this call made the backup.
fn back_up_original(copy: &GemCopy, probe: &Probe) -> std::io::Result<bool> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    if std::fs::symlink_metadata(&backup).is_ok()
        || std::fs::symlink_metadata(copy.gem_dir.join(MARKER_FILE)).is_ok()
    {
        return Ok(false);
    }
    let stage = copy.gem_dir.join(format!("{BACKUP_DIR}.tmp"));
    remove_dir_if_exists(&stage)?;
    std::fs::create_dir_all(&stage)?;
    let had_extension_dir = probe.extension_dir.is_dir();
    let mut lib_files = Vec::new();
    if had_extension_dir {
        copy_tree_sync(&probe.extension_dir, &stage.join("ext"))?;
        for rel in artifact_rels(&probe.extension_dir) {
            let Some(lib) = lib_rel(probe, &rel) else {
                continue;
            };
            // Only a regular file: a FIFO there would block the read.
            if let Ok(bytes) = read_regular_to_bytes_sync(&copy.gem_dir.join(&lib)) {
                let dst = stage.join("lib").join(&lib);
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dst, bytes)?;
                lib_files.push(lib);
            }
        }
    }
    let info = BackupInfo {
        extension_dir: ext_dir_label(&copy.home, &probe.extension_dir),
        had_extension_dir,
        lib_files,
    };
    std::fs::write(
        stage.join(BACKUP_INFO),
        serde_json::to_vec_pretty(&info).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&stage, &backup)?;
    Ok(true)
}

/// One lib copy read into memory: gem-dir-relative path, bytes, mode.
type LibSnapshot = (String, Vec<u8>, std::fs::Permissions);

/// The lib copies of an extension dir's artifacts, read into memory.
fn snapshot_lib_copies(copy: &GemCopy, probe: &Probe, rels: &[String]) -> Vec<LibSnapshot> {
    rels.iter()
        .filter_map(|rel| lib_rel(probe, rel))
        .filter_map(|lib| {
            let path = copy.gem_dir.join(&lib);
            let perms = std::fs::metadata(&path).ok()?.permissions();
            let bytes = read_regular_to_bytes_sync(&path).ok()?;
            Some((lib, bytes, perms))
        })
        .collect()
}

/// State a build moved aside, to put back if it fails.
struct Aside {
    /// The previous extension dir, parked beside itself
    /// ([`parked_build_path`]).
    old_ext: Option<PathBuf>,
    /// The previous build's lib copies.
    lib: Vec<LibSnapshot>,
    /// The rebuild lock on the parked dir ([`lock_build_dir`]), held until
    /// the build is committed or put back.
    _lock: Option<std::fs::File>,
}

/// Move the current build out of the way of a fresh one.
///
/// Everything a run that dies mid-build needs put right stays on disk:
/// the previous build is parked, not deleted, and its marker (if it had
/// one) is left where it is until a finished build's marker replaces it,
/// so [`recover_interrupted_rebuild`] can put the copy back together.
fn set_aside(copy: &GemCopy, probe: &Probe) -> std::io::Result<Aside> {
    let ext = &probe.extension_dir;
    let rels = if ext.is_dir() {
        artifact_rels(ext)
    } else {
        Vec::new()
    };
    let lib = snapshot_lib_copies(copy, probe, &rels);
    let (old_ext, lock) = if ext.is_dir() {
        // Locked before it is parked: from the moment the parked dir is
        // there, another run sees a rebuild that is still alive.
        let lock = lock_build_dir(ext)?;
        let parked = parked_build_path(ext);
        remove_dir_if_exists(&parked)?;
        std::fs::rename(ext, &parked)?;
        (Some(parked), lock)
    } else {
        (None, None)
    };
    Ok(Aside {
        old_ext,
        lib,
        _lock: lock,
    })
}

/// Undo a failed build: drop what it produced (its extension dir and any lib
/// copy it created), and put the previous build back. Its marker never left.
fn put_back(copy: &GemCopy, probe: &Probe, aside: Aside) -> std::io::Result<()> {
    let ext = &probe.extension_dir;
    let produced = if ext.is_dir() {
        artifact_rels(ext)
    } else {
        Vec::new()
    };
    let kept: Vec<&str> = aside.lib.iter().map(|(p, _, _)| p.as_str()).collect();
    for rel in &produced {
        if let Some(lib) = lib_rel(probe, rel) {
            if !kept.contains(&lib.as_str()) {
                let _ = std::fs::remove_file(copy.gem_dir.join(&lib));
            }
        }
    }
    remove_dir_if_exists(ext)?;
    if let Some(old) = &aside.old_ext {
        std::fs::rename(old, ext)?;
    }
    for (lib, bytes, perms) in &aside.lib {
        replace_file(&copy.gem_dir.join(lib), |stage| {
            std::fs::write(stage, bytes)?;
            std::fs::set_permissions(stage, perms.clone())
        })?;
    }
    Ok(())
}

/// After a successful build: record the marker, drop the old build.
fn commit_build(
    copy: &GemCopy,
    probe: &Probe,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
    aside: &Aside,
) -> std::io::Result<()> {
    let ext = &probe.extension_dir;
    let mut marker = BuildMarker {
        schema: MARKER_SCHEMA,
        extension_dir: ext_dir_label(&copy.home, ext),
        ..BuildMarker::default()
    };
    for key in &scope.inputs {
        if let Some(info) = files.get(key) {
            marker.sources.insert(
                normalize_file_path(key).to_string(),
                info.after_hash.clone(),
            );
        }
    }
    for rel in artifact_rels(ext) {
        let hash = compute_file_git_sha256_sync(&ext.join(&rel))?;
        if let Some(lib) = lib_rel(probe, &rel) {
            if let Ok(lib_hash) = compute_file_git_sha256_sync(&copy.gem_dir.join(&lib)) {
                marker.lib_artifacts.insert(lib, lib_hash);
            }
        }
        marker.ext_artifacts.insert(rel, hash);
    }
    let bytes = serde_json::to_vec_pretty(&marker).map_err(std::io::Error::other)?;
    let marker_path = copy.gem_dir.join(MARKER_FILE);
    let stage = copy.gem_dir.join(format!("{MARKER_FILE}.tmp"));
    if let Err(e) =
        std::fs::write(&stage, bytes).and_then(|()| std::fs::rename(&stage, &marker_path))
    {
        let _ = std::fs::remove_file(&stage);
        return Err(e);
    }
    if let Some(old) = &aside.old_ext {
        let _ = remove_dir_if_exists(old);
    }
    Ok(())
}

/// Rebuild `copy`'s extension from the sources on disk with `probe.ruby`.
/// On failure every build product is put back as it was; `Err` is the
/// build's diagnostic.
async fn rebuild(
    copy: &GemCopy,
    probe: &Probe,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
    env: &RubyEnv,
    back_up: bool,
) -> Result<(), String> {
    // A backup this rebuild made is dropped again when the build does not
    // land: the install-time build is back in place, so the copy is as it
    // was before the run.
    let drop_new_backup = |copy: &GemCopy, made: bool| {
        if made {
            let _ = remove_dir_if_exists(&copy.gem_dir.join(BACKUP_DIR));
        }
    };
    let (aside, made_backup) = {
        let (copy, probe) = (copy.clone(), probe.clone());
        crate::utils::fs::run_blocking(move || {
            let made = if back_up {
                back_up_original(&copy, &probe)
                    .map_err(|e| format!("could not back up the original extension build: {e}"))?
            } else {
                false
            };
            match set_aside(&copy, &probe) {
                Ok(aside) => Ok((aside, made)),
                Err(e) => {
                    drop_new_backup(&copy, made);
                    Err(format!(
                        "could not move the current extension build aside: {e}"
                    ))
                }
            }
        })
        .await?
    };
    let built = run_ruby(&probe.ruby, RubyRun::Build(probe), copy, env, BUILD_TIMEOUT).await;
    let (copy, probe, scope, files) = (copy.clone(), probe.clone(), scope.clone(), files.clone());
    crate::utils::fs::run_blocking(move || {
        // A build whose record cannot be written is undone like a failed
        // one: an unrecorded build would never be attested, and the caller
        // puts the original sources back. So is one that exits cleanly
        // without an extension dir: the old one was moved aside for it.
        let diagnostic = match built {
            Ok(_) if !probe.extension_dir.is_dir() => format!(
                "the build exited cleanly but left no extension in {}",
                probe.extension_dir.display()
            ),
            Ok(_) => match commit_build(&copy, &probe, &scope, &files, &aside) {
                Ok(()) => return Ok(()),
                Err(e) => format!("the extension built, but its build record could not be written: {e}"),
            },
            Err(diagnostic) => diagnostic,
        };
        match put_back(&copy, &probe, aside) {
            Ok(()) => {
                drop_new_backup(&copy, made_backup);
                Err(diagnostic)
            }
            Err(e) => Err(format!(
                "{diagnostic}\n(the previous build could not be put back: {e}; run `gem pristine {} \
                 --extensions` to rebuild it)",
                gem_name_of(&copy.full_name)
            )),
        }
    })
    .await
}

/// `name` of a `name-version[-platform]` dir, for the `gem pristine` hint:
/// the first `-` followed by a digit starts the version (gem names rarely
/// hold one).
fn gem_name_of(full_name: &str) -> &str {
    let bytes = full_name.as_bytes();
    (0..bytes.len())
        .find(|&i| bytes[i] == b'-' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
        .map_or(full_name, |i| &full_name[..i])
}

fn refusal(package_key: &str, pkg_path: &Path, code: &str, detail: String) -> GemApplied {
    GemApplied {
        result: ApplyResult {
            package_key: package_key.to_string(),
            package_path: pkg_path.display().to_string(),
            success: false,
            files_verified: Vec::new(),
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: Some(format!("{code}: {detail}")),
            sidecar: None,
        },
        warning: Some((code.to_string(), detail)),
    }
}

fn list_inputs(scope: &NativeScope) -> String {
    let shown: Vec<&str> = scope
        .inputs
        .iter()
        .take(3)
        .map(|k| normalize_file_path(k))
        .collect();
    let more = scope.inputs.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// [`apply_package_patch`] for one installed gem copy, rebuilding its
/// native extension when the record changes a build input (see the module
/// docs). A record without native inputs is applied exactly as
/// [`apply_package_patch`] applies it.
#[allow(clippy::too_many_arguments)]
pub async fn apply_gem_package_patch(
    read_scope: crate::utils::repo_root::ReadScope,
    package_key: &str,
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
    dry_run: bool,
    policy: MismatchPolicy,
    env: &RubyEnv,
) -> GemApplied {
    let (scope, copy) = scope_of(pkg_path, files).await;
    let plain = || async {
        GemApplied {
            result: apply_package_patch(
                read_scope,
                package_key,
                pkg_path,
                files,
                sources,
                dry_run,
                policy,
            )
            .await,
            warning: None,
        }
    };
    if scope.inputs.is_empty() {
        return plain().await;
    }
    let inputs = list_inputs(&scope);
    // A rebuild of this copy that an earlier run started and did not finish
    // (it was interrupted, or killed) left the previous build parked: the
    // copy is put back together before anything else, so what follows
    // sees a whole gem. A dry run changes nothing and reads the parked
    // build where it is.
    if let (false, Some(copy)) = (dry_run, &copy) {
        if let Err(e) = recover_interrupted_rebuild(copy).await {
            return refusal(
                package_key,
                pkg_path,
                UNSUPPORTED_CODE,
                format!(
                    "the patch changes native-extension sources ({inputs}), and {}; nothing \
                     was written",
                    recovery_refusal(copy, &e)
                ),
            );
        }
    }
    // `--no-gem-native-rebuild`: the caller compiles the extension itself
    // (the patches evaluation harness does), so the sources are written as
    // before #1996, and the warning says the build is the caller's.
    if !env.rebuild {
        let mut applied = plain().await;
        if applied.result.success {
            applied.warning = Some((
                NOT_REBUILT_REASON.to_string(),
                format!(
                    "{package_key}: the patch changes native-extension sources ({inputs}), \
                     written without rebuilding the extension (--no-gem-native-rebuild); Ruby \
                     loads the old build until it is recompiled, and vex does not attest it"
                ),
            ));
        }
        return applied;
    }
    let hosted_hint = "Use `socket-patch scan --mode hosted`, which installs the patched gem \
                       through Bundler so RubyGems compiles it.";
    let Some(copy) = copy else {
        return refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), but {} is not a \
                 RubyGems install with a specification to rebuild the extension from; \
                 nothing was written. {hosted_hint}",
                pkg_path.display()
            ),
        );
    };
    if !scope.builds_extensions {
        return refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), but the installed gem \
                 builds no extension at install time (a precompiled platform gem ships its \
                 compiled code), so they cannot take effect; nothing was written. Install the \
                 `ruby` platform gem and use `socket-patch scan --mode hosted`."
            ),
        );
    }

    // Already patched and built from these sources: nothing to do.
    let built = {
        let (copy, scope, files) = (copy.clone(), scope.clone(), files.clone());
        crate::utils::fs::run_blocking(move || {
            read_marker_sync(&copy.gem_dir).is_some_and(|m| marker_holds(&m, &copy, &scope, &files))
        })
        .await
    };
    if built {
        return plain().await;
    }

    let unbuildable = |why: String| {
        refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), which only take \
                 effect once the extension is rebuilt, and it cannot be rebuilt here: \
                 {why}; nothing was written. {hosted_hint}"
            ),
        )
    };
    // What files alone tell: a build to replace and a Ruby to try.
    let preflight = match rebuild_preflight(&copy, env).await {
        Ok(p) => p,
        Err(why) => return unbuildable(why),
    };

    // No program runs until the record's files verify against this copy:
    // until then nothing says the tree is the package the patch is for.
    // The pass writes nothing, and a dry run ends with it.
    let verified = apply_package_patch(
        read_scope,
        package_key,
        pkg_path,
        files,
        sources,
        true,
        policy,
    )
    .await;
    if !verified.success {
        return GemApplied {
            result: verified,
            warning: None,
        };
    }
    if dry_run {
        // The build is not one made from these sources (the marker check
        // above), so a real run rebuilds it: the warning says what `apply`
        // would still do (with every source already patched, where the
        // event reads `already_patched`, its `native_extension_rebuilt`).
        // Whether a Ruby here can build it is left to that run.
        let all_patched = !verified.files_verified.is_empty()
            && verified
                .files_verified
                .iter()
                .all(|v| v.status == crate::patch::apply::VerifyStatus::AlreadyPatched);
        let parked = preflight
            .installed
            .iter()
            .any(|dir| is_real_dir(&parked_build_path(dir)));
        let unfinished = if parked {
            "; an earlier rebuild did not finish, and apply first puts back the build it parked"
        } else {
            ""
        };
        let detail = if all_patched {
            format!(
                "{package_key}: dry run: its sources are already patched, but its native \
                 extension was not built from them ({inputs}); apply would rebuild \
                 it{unfinished}"
            )
        } else {
            format!(
                "{package_key}: dry run: apply would write its patched sources and rebuild \
                 its native extension from them ({inputs}); no Ruby was run to check that \
                 it can{unfinished}"
            )
        };
        return GemApplied {
            result: verified,
            warning: Some((REBUILT_CODE.to_string(), detail)),
        };
    }

    let probe = match find_ruby(&copy, env, preflight).await {
        Ok(p) => p,
        Err(why) => return unbuildable(why),
    };

    // The bytes each file holds now, to put back if the build fails.
    let originals: Vec<(String, Option<Vec<u8>>)> = {
        let keys: Vec<String> = files.keys().cloned().collect();
        let dir = pkg_path.to_path_buf();
        crate::utils::fs::run_blocking(move || {
            keys.into_iter()
                .filter(|k| is_safe_relative_subpath(normalize_file_path(k)))
                .map(|k| {
                    let bytes = read_regular_to_bytes_sync(&dir.join(normalize_file_path(&k))).ok();
                    (k, bytes)
                })
                .collect()
        })
        .await
    };

    let mut result = apply_package_patch(
        read_scope,
        package_key,
        pkg_path,
        files,
        sources,
        false,
        policy,
    )
    .await;
    if !result.success {
        revert_sources(pkg_path, &originals, &result.files_patched).await;
        result.files_patched.clear();
        result.applied_via.clear();
        return GemApplied {
            result,
            warning: None,
        };
    }

    match rebuild(&copy, &probe, &scope, files, env, true).await {
        Ok(()) => {
            let warning = result.files_patched.is_empty().then(|| {
                (
                    REBUILT_CODE.to_string(),
                    format!(
                        "{}: its native extension was rebuilt from sources an earlier run \
                         patched without rebuilding ({inputs})",
                        package_key
                    ),
                )
            });
            GemApplied { result, warning }
        }
        Err(diagnostic) => {
            revert_sources(pkg_path, &originals, &result.files_patched).await;
            let detail = format!(
                "the native extension did not build from the patched sources ({inputs}); the \
                 sources and the previous build were put back. Install a compiler toolchain \
                 and the Ruby headers and apply again, or use `socket-patch scan --mode \
                 hosted`.\n{diagnostic}"
            );
            result.success = false;
            result.files_patched.clear();
            result.applied_via.clear();
            result.error = Some(format!("{BUILD_FAILED_CODE}: {detail}"));
            GemApplied {
                result,
                warning: Some((BUILD_FAILED_CODE.to_string(), detail)),
            }
        }
    }
}

/// Put the files a failed gem apply wrote back to the bytes they held
/// before it (a file it created is removed). Best effort: the apply already
/// fails.
async fn revert_sources(
    pkg_path: &Path,
    originals: &[(String, Option<Vec<u8>>)],
    written: &[String],
) {
    for key in written {
        let Some((_, before)) = originals.iter().find(|(k, _)| k == key) else {
            continue;
        };
        match before {
            Some(bytes) => {
                let hash = compute_git_sha256_from_bytes(bytes);
                let _ = apply_file_patch_at(pkg_path, key, bytes, &hash).await;
            }
            None => {
                let _ =
                    crate::utils::fs::remove_file(&pkg_path.join(normalize_file_path(key))).await;
            }
        }
    }
}

/// After `rollback` put a gem copy's sources back: put its original compiled
/// extension back too. The backup [`apply_gem_package_patch`] took is
/// restored whenever it exists: it is this gem version's install-time build,
/// right whether the current build is socket-patch's (marker present) or one
/// whose marker never got written. Without a backup, a copy carrying a
/// socket-patch build (a marker) is rebuilt from the restored sources.
/// A rebuild an earlier run did not finish is put right first
/// ([`recover_interrupted_rebuild`]), so the build parked by it is back
/// before any of that. `Ok(true)` when a build was restored, `Ok(false)`
/// when the copy carries neither.
pub async fn restore_original_build(pkg_path: &Path, env: &RubyEnv) -> Result<bool, String> {
    let Some(copy) = GemCopy::of(pkg_path) else {
        return Ok(false);
    };
    let recovered = recover_interrupted_rebuild(&copy)
        .await
        .map_err(|e| recovery_refusal(&copy, &e))?;
    let marker = {
        let gem_dir = copy.gem_dir.clone();
        crate::utils::fs::run_blocking(move || read_marker_sync(&gem_dir)).await
    };
    let backup = copy.gem_dir.join(BACKUP_DIR);
    let pristine_hint = format!(
        "run `gem pristine {} --extensions`",
        gem_name_of(&copy.full_name)
    );
    if is_symlink(&backup) {
        return Err(format!(
            "{} is a symlink, not a backup this tool made; left as it is, {pristine_hint}",
            backup.display()
        ));
    }
    let has_backup = tokio::fs::metadata(backup.join(BACKUP_INFO)).await.is_ok();
    if has_backup {
        let c = copy.clone();
        return crate::utils::fs::run_blocking(move || restore_backup(&c, marker.as_ref()))
            .await
            .map(|()| true)
            .map_err(|e| {
                format!(
                    "could not put the original native extension build back ({e}); run `gem \
                     pristine {} --extensions` to rebuild it",
                    gem_name_of(&copy.full_name)
                )
            });
    }
    if marker.is_none() {
        return Ok(recovered);
    }
    if !env.rebuild {
        return Err(format!(
            "the compiled extension still holds the patched build, and no backup of the \
             original is left to restore without a rebuild (--no-gem-native-rebuild); \
             {pristine_hint}"
        ));
    }
    // No backup: rebuild from the restored sources.
    let found = match rebuild_preflight(&copy, env).await {
        Ok(preflight) => find_ruby(&copy, env, preflight).await,
        Err(why) => Err(why),
    };
    let probe = found.map_err(|why| {
        format!(
            "the compiled extension still holds the patched build and cannot be rebuilt here \
             ({why}); run `gem pristine {} --extensions`",
            gem_name_of(&copy.full_name)
        )
    })?;
    let scope = NativeScope::default();
    rebuild(&copy, &probe, &scope, &HashMap::new(), env, false)
        .await
        .map_err(|diagnostic| {
            format!(
                "the extension did not rebuild from the restored sources; run `gem pristine \
                 {} --extensions`.\n{diagnostic}",
                gem_name_of(&copy.full_name)
            )
        })?;
    let _ = tokio::fs::remove_file(copy.gem_dir.join(MARKER_FILE)).await;
    Ok(true)
}

/// Put the backed-up original build back over socket-patch's build, then
/// drop the marker and the backup. The extension dir the backup names must
/// be this gem's under the home ([`confined_ext_dir`]) and no symlink, or
/// nothing is touched.
fn restore_backup(copy: &GemCopy, marker: Option<&BuildMarker>) -> std::io::Result<()> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    let info: BackupInfo =
        serde_json::from_slice(&read_regular_to_bytes_sync(&backup.join(BACKUP_INFO))?)
            .map_err(std::io::Error::other)?;
    let ext_dir = confined_ext_dir(copy, &info.extension_dir)
        .filter(|dir| !is_symlink(dir))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the backup names {:?}, which is not this gem's extension dir under {}",
                    info.extension_dir,
                    copy.home.display()
                ),
            )
        })?;
    // socket-patch's lib copies go; the originals come back.
    for lib in marker.iter().flat_map(|m| m.lib_artifacts.keys()) {
        if is_safe_relative_subpath(lib) && !info.lib_files.contains(lib) {
            let _ = std::fs::remove_file(copy.gem_dir.join(lib));
        }
    }
    remove_dir_if_exists(&ext_dir)?;
    if info.had_extension_dir {
        copy_tree_sync(&backup.join("ext"), &ext_dir)?;
    }
    for lib in &info.lib_files {
        if !is_safe_relative_subpath(lib) {
            continue;
        }
        let bytes = read_regular_to_bytes_sync(&backup.join("lib").join(lib))?;
        replace_file(&copy.gem_dir.join(lib), |stage| {
            std::fs::write(stage, &bytes)
        })?;
    }
    match std::fs::remove_file(copy.gem_dir.join(MARKER_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    remove_dir_if_exists(&backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(after: &str) -> PatchFileInfo {
        PatchFileInfo {
            before_hash: "b".repeat(64),
            after_hash: after.to_string(),
        }
    }

    fn files(keys: &[&str]) -> HashMap<String, PatchFileInfo> {
        keys.iter()
            .map(|k| (k.to_string(), info(&"a".repeat(64))))
            .collect()
    }

    #[test]
    fn parses_to_ruby_extensions() {
        let spec = "Gem::Specification.new do |s|\n  s.name = \"json\".freeze\n  \
                    s.extensions = [\"ext/json/ext/generator/extconf.rb\".freeze, \
                    \"ext/json/ext/parser/extconf.rb\".freeze]\nend\n";
        let decl = parse_extensions(spec);
        assert!(decl.declared);
        assert_eq!(
            decl.entries,
            vec![
                "ext/json/ext/generator/extconf.rb",
                "ext/json/ext/parser/extconf.rb"
            ]
        );
    }

    #[test]
    fn ignores_comments_comparisons_and_empty_lists() {
        for spec in [
            "# s.extensions = [\"ext/a/extconf.rb\"]\n",
            "raise if s.extensions == [\"e\"]\n",
            "s.extensions_dir = \"x\"\n",
        ] {
            assert!(!parse_extensions(spec).declared, "{spec}");
        }
        // The vendored backend's test, `.push` / `.concat` included.
        let pushed = parse_extensions("s.extensions.push(\"ext/a/extconf.rb\")\n");
        assert!(pushed.declared);
        assert_eq!(pushed.entries, vec!["ext/a/extconf.rb"]);
        let decl = parse_extensions("s.extensions = EXTS\n");
        assert!(decl.declared);
        assert!(decl.entries.is_empty());
    }

    #[test]
    fn native_by_name_follows_the_issue_list() {
        for path in [
            "ext/json/ext/parser/parser.c",
            "ext/a/a.h",
            "src/x.CPP",
            "ext/a/a.hh",
            "ext/a/a.m",
            "lib/parser.y",
            "ext/a/lexer.rl",
            "ext/a/extconf.rb",
            "extconf.rb",
            "ext/a/depend",
        ] {
            assert!(is_native_by_name(path), "{path}");
        }
        for path in ["lib/a.rb", "depend", "README.md", "ext/a/.c", "lib/c"] {
            assert!(!is_native_by_name(path), "{path}");
        }
    }

    #[test]
    fn classify_counts_files_under_declared_script_dirs() {
        let decl = ExtensionDecl {
            declared: true,
            entries: vec!["ext/foo/Cargo.toml".into()],
        };
        let scope = classify(
            &decl,
            &files(&["ext/foo/src/lib.rs", "lib/foo.rb", "package/ext/foo/x.c"]),
        );
        assert_eq!(
            scope.inputs,
            vec!["ext/foo/src/lib.rs", "package/ext/foo/x.c"]
        );
        assert!(scope.builds_extensions);
    }

    #[test]
    fn classify_without_extensions_keeps_c_but_drops_grammars() {
        let scope = classify(
            &ExtensionDecl::default(),
            &files(&["lib/parser.y", "lib/parser.rb", "ext/x.c"]),
        );
        assert_eq!(scope.inputs, vec!["ext/x.c"]);
        assert!(!scope.builds_extensions);
        let ruby_only = classify(&ExtensionDecl::default(), &files(&["lib/parser.y"]));
        assert!(ruby_only.inputs.is_empty());
    }

    /// Non-compiled C / Objective-C files outside `ext/` in a gem that builds
    /// nothing (templates, fixtures) are plain files.
    #[test]
    fn classify_without_extensions_ignores_c_outside_ext() {
        let scope = classify(
            &ExtensionDecl::default(),
            &files(&["lib/templates/App.m", "test/fixtures/a.c", "lib/a.h"]),
        );
        assert!(scope.inputs.is_empty());
    }

    /// A root-level script makes the files beside it inputs, not `lib/`.
    #[test]
    fn classify_root_level_script_counts_top_level_files_only() {
        let decl = ExtensionDecl {
            declared: true,
            entries: vec!["extconf.rb".into()],
        };
        let scope = classify(&decl, &files(&["extconf.rb", "foo.c", "lib/foo.rb"]));
        assert_eq!(scope.inputs, vec!["extconf.rb", "foo.c"]);
    }

    #[test]
    fn confined_ext_dir_only_names_this_gems_dir_under_home() {
        let copy = GemCopy::of(Path::new("/h/gems/a-1")).unwrap();
        assert_eq!(
            confined_ext_dir(&copy, "extensions/p/3.4.0/a-1"),
            Some(PathBuf::from("/h/extensions/p/3.4.0/a-1"))
        );
        for bad in [
            "/home/ci",
            "../../../..",
            "extensions/p/3.4.0/other-1",
            "extensions/../../x/a-1",
            "extensions/p/a-1",
            "gems/p/3.4.0/a-1",
        ] {
            assert_eq!(confined_ext_dir(&copy, bad), None, "{bad}");
        }
    }

    #[test]
    fn unknown_scripts_make_ext_tree_native() {
        let decl = ExtensionDecl {
            declared: true,
            entries: Vec::new(),
        };
        let scope = classify(&decl, &files(&["ext/foo/build.rs", "lib/a.rb"]));
        assert_eq!(scope.inputs, vec!["ext/foo/build.rs"]);
    }

    #[test]
    fn gem_copy_needs_a_gems_dir() {
        let copy = GemCopy::of(Path::new("/h/gems/json-2.10.1")).unwrap();
        assert_eq!(copy.home, Path::new("/h"));
        assert_eq!(
            copy.spec_path,
            Path::new("/h/specifications/json-2.10.1.gemspec")
        );
        assert!(GemCopy::of(Path::new("/h/bundler/gems2/json-abc")).is_none());
    }

    /// A relative crawl root reaches Ruby (run from the project dir) and
    /// `extconf.rb` (run from the ext dir) as absolute paths, `..` dropped
    /// the way Ruby's `File.expand_path` drops it.
    #[test]
    fn gem_copy_of_a_relative_path_is_absolute() {
        let copy = GemCopy::of(Path::new("proj/../vendor/ruby/3.4.0/gems/json-2.10.1")).unwrap();
        let expected = std::env::current_dir().unwrap().join("vendor/ruby/3.4.0");
        assert_eq!(copy.home, expected);
        assert!(copy.spec_path.is_absolute());
        assert!(copy.gem_dir.is_absolute());
        assert!(!copy
            .gem_dir
            .components()
            .any(|c| c == std::path::Component::ParentDir));
    }

    #[test]
    fn gem_name_strips_version_and_platform() {
        assert_eq!(gem_name_of("json-2.10.1"), "json");
        assert_eq!(gem_name_of("ruby-prof-1.7.0"), "ruby-prof");
        assert_eq!(gem_name_of("nokogiri-1.16.0-x86_64-linux"), "nokogiri");
        assert_eq!(gem_name_of("weird"), "weird");
    }

    #[test]
    fn stderr_tail_drops_boilerplate_and_caps_lines() {
        let mut text: String = (0..30).map(|i| format!("line {i}\n")).collect();
        text.push_str("\nGem files will remain installed in /x for inspection.\n");
        let tail = stderr_tail(&text);
        assert!(tail.starts_with("line 10"));
        assert!(tail.ends_with("line 29"));
        assert_eq!(
            stderr_tail(""),
            "the build exited with an error and no output"
        );
    }

    #[test]
    fn probe_output_parses() {
        assert_eq!(
            parse_extensions_dir(
                "warning: a shim talking\nother\tline\nsp_extensions_dir\t/h/extensions/p/3.4.0\n"
            ),
            Some(PathBuf::from("/h/extensions/p/3.4.0"))
        );
        for unreadable in ["", "sp_gem_dir\t/x\n", "sp_extensions_dir\t\n"] {
            assert_eq!(parse_extensions_dir(unreadable), None, "{unreadable:?}");
        }
    }

    /// The require path is read from the `to_ruby` text RubyGems installs,
    /// stub comment and all, and defaults to RubyGems' `lib`.
    #[test]
    fn require_path_is_read_from_the_gemspec_text() {
        let to_ruby = "# -*- encoding: utf-8 -*-\n# stub: a 1 ruby other\n\n\
                       Gem::Specification.new do |s|\n  s.name = \"a\".freeze\n  \
                       s.require_paths = [\"ext/lib\".freeze, \"lib\".freeze]\nend\n";
        assert_eq!(parse_require_path(to_ruby).as_deref(), Some("ext/lib"));
        for (spec, expected) in [
            ("s.require_paths = ['lib']\n", Some("lib")),
            ("s.name = \"a\"\n", Some("lib")),
            ("# s.require_paths = [\"x\"]\n", Some("lib")),
            ("raise if s.require_paths == [\"x\"]\n", Some("lib")),
            ("s.require_paths_extra = [\"x\"]\n", Some("lib")),
            ("s.require_paths = PATHS\n", None),
        ] {
            assert_eq!(parse_require_path(spec).as_deref(), expected, "{spec}");
        }
    }

    /// A gem copy with an installed extension dir and a to_ruby gemspec.
    fn installed_gem(home: &Path, require_path: &str) -> GemCopy {
        let gem_dir = home.join("gems/a-1");
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::create_dir_all(home.join("extensions/p/3.4.0/a-1")).unwrap();
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications/a-1.gemspec"),
            format!(
                "Gem::Specification.new do |s|\n  s.name = \"a\".freeze\n  \
                 s.require_paths = [\"{require_path}\".freeze]\n  \
                 s.extensions = [\"ext/a/extconf.rb\".freeze]\nend\n"
            ),
        )
        .unwrap();
        GemCopy::of(&gem_dir).unwrap()
    }

    /// A stand-in `ruby` that answers the extensions-dir question with
    /// `<home>/extensions/<platform>/3.4.0` and records its arguments.
    #[cfg(unix)]
    fn fake_ruby(dir: &Path, platform: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let ruby = dir.join("ruby");
        std::fs::write(
            &ruby,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$3 $4\" >> '{}'\n\
                 printf 'sp_extensions_dir\\t%s\\n' \"$4/extensions/{platform}/3.4.0\"\n",
                dir.join("calls").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&ruby, std::fs::Permissions::from_mode(0o755)).unwrap();
        ruby
    }

    /// [`find_ruby`] over a script written a moment ago: a sibling test
    /// forking in between holds its write fd until it execs, and the spawn
    /// fails with ETXTBSY (os error 26) for that long.
    #[cfg(unix)]
    async fn find_fresh_ruby(
        copy: &GemCopy,
        env: &RubyEnv,
        preflight: &Preflight,
    ) -> Result<Probe, String> {
        loop {
            match find_ruby(copy, env, preflight.clone()).await {
                Err(why) if why.contains("os error 26") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                found => return found,
            }
        }
    }

    /// The Ruby is matched to the install by where it builds extensions for
    /// the gem home, a question that names no file of the gem, and the lib
    /// dir comes from the gemspec's text.
    #[cfg(unix)]
    #[tokio::test]
    async fn find_ruby_asks_only_for_the_extensions_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = installed_gem(&home, "lib");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let ruby = fake_ruby(&bin, "p");
        let env = RubyEnv {
            cwd: tmp.path().to_path_buf(),
            rebuild: true,
        };
        let mut preflight = Preflight {
            installed: installed_extension_dirs(&copy),
            candidates: vec![ruby.clone()],
            require_path: "lib".to_string(),
        };
        assert_eq!(preflight.installed, [home.join("extensions/p/3.4.0/a-1")]);

        let probe = find_fresh_ruby(&copy, &env, &preflight).await.unwrap();
        assert_eq!(probe.ruby, ruby);
        assert_eq!(probe.extension_dir, home.join("extensions/p/3.4.0/a-1"));
        assert_eq!(probe.lib_dir, copy.gem_dir.join("lib"));
        assert_eq!(lib_rel(&probe, "a/a.so").as_deref(), Some("lib/a/a.so"));
        assert_eq!(
            std::fs::read_to_string(bin.join("calls")).unwrap(),
            format!("extensions_dir {}\n", home.display()),
            "the probe names the gem home, not the gemspec"
        );

        // A Ruby of another platform builds elsewhere: not the owner.
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&other).unwrap();
        preflight.candidates = vec![fake_ruby(&other, "q")];
        let why = find_fresh_ruby(&copy, &env, &preflight).await.unwrap_err();
        assert!(why.contains("another Ruby's"), "{why}");
    }

    /// A gem with no extension dir, or whose require path leaves the gem
    /// dir (lib copies are only ever written inside the gem), is refused
    /// from its files, before a Ruby is looked for.
    #[tokio::test]
    async fn preflight_refuses_from_files_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let env = RubyEnv {
            cwd: tmp.path().to_path_buf(),
            rebuild: true,
        };
        for require_path in ["../../elsewhere", "/abs"] {
            let home = tmp.path().join(require_path.replace(['/', '.'], "_"));
            let copy = installed_gem(&home, require_path);
            let why = rebuild_preflight(&copy, &env).await.unwrap_err();
            assert!(why.contains("require path"), "{require_path}: {why}");
        }
        let home = tmp.path().join("unbuilt");
        let copy = installed_gem(&home, "lib");
        std::fs::remove_dir_all(home.join("extensions")).unwrap();
        let why = rebuild_preflight(&copy, &env).await.unwrap_err();
        assert!(why.contains("no compiled extension dir"), "{why}");
    }

    /// A rebuild interrupted before RubyGems created the new extension dir
    /// leaves the install-time build parked beside where it was. That gem
    /// is not one "installed by a RubyGems older than 2.2": its build is
    /// there to put back.
    #[tokio::test]
    async fn a_parked_build_is_not_a_missing_one() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = installed_gem(&home, "lib");
        let ext = home.join("extensions/p/3.4.0/a-1");
        std::fs::rename(&ext, ext.with_file_name(".a-1.socket-patch-old")).unwrap();
        let env = RubyEnv {
            cwd: tmp.path().to_path_buf(),
            rebuild: true,
        };
        // Without a `ruby` on PATH the preflight still refuses, for that.
        match rebuild_preflight(&copy, &env).await {
            Ok(preflight) => assert_eq!(preflight.installed, [ext]),
            Err(why) => assert!(why.contains("no `ruby` was found"), "{why}"),
        }
    }

    /// A gem whose rebuild was cut short: the install-time build parked
    /// beside the extension dir, and whatever `left` says the build got to
    /// in the extension dir and the `lib/` copy.
    fn interrupted_gem(home: &Path, left: Option<(&str, bool)>) -> (GemCopy, PathBuf, PathBuf) {
        let copy = installed_gem(home, "lib");
        let ext = home.join("extensions/p/3.4.0/a-1");
        let parked = ext.with_file_name(".a-1.socket-patch-old");
        std::fs::create_dir_all(ext.join("a")).unwrap();
        std::fs::write(ext.join("a/a.so"), b"original").unwrap();
        std::fs::write(ext.join(BUILD_COMPLETE), b"").unwrap();
        std::fs::create_dir_all(copy.gem_dir.join("lib/a")).unwrap();
        std::fs::write(copy.gem_dir.join("lib/a/a.so"), b"original").unwrap();
        std::fs::rename(&ext, &parked).unwrap();
        if let Some((bytes, complete)) = left {
            std::fs::create_dir_all(ext.join("a")).unwrap();
            std::fs::write(ext.join("a/a.so"), bytes).unwrap();
            std::fs::write(copy.gem_dir.join("lib/a/a.so"), bytes).unwrap();
            if complete {
                std::fs::write(ext.join(BUILD_COMPLETE), b"").unwrap();
            }
        }
        (copy, ext, parked)
    }

    /// The parked build goes back where it was, with the `lib/` copy the
    /// interrupted build replaced, whether that build had created the
    /// extension dir yet or not. A second call finds nothing to do.
    #[test]
    fn an_interrupted_rebuild_is_put_back() {
        for left in [None, Some(("half-built", false))] {
            let tmp = tempfile::tempdir().unwrap();
            let (copy, ext, parked) = interrupted_gem(tmp.path(), left);
            assert!(
                recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap(),
                "{left:?}"
            );
            assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"original");
            assert!(ext.join(BUILD_COMPLETE).is_file(), "{left:?}");
            assert_eq!(
                std::fs::read(copy.gem_dir.join("lib/a/a.so")).unwrap(),
                b"original",
                "{left:?}"
            );
            assert!(!parked.exists(), "{left:?}");
            assert!(!recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap());
        }
    }

    /// A build that finished (the run died before recording it, or `gem
    /// pristine` ran since) is not traded for the older parked one.
    #[test]
    fn a_finished_build_stands_over_a_parked_one() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, ext, parked) = interrupted_gem(tmp.path(), Some(("rebuilt", true)));
        assert!(recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap());
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"rebuilt");
        assert_eq!(
            std::fs::read(copy.gem_dir.join("lib/a/a.so")).unwrap(),
            b"rebuilt"
        );
        assert!(!parked.exists());
    }

    /// A parked build another process still holds belongs to a rebuild
    /// that is running, not to an interrupted one: it is left alone.
    #[cfg(unix)]
    #[test]
    fn a_rebuild_still_running_elsewhere_is_left_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, ext, parked) = interrupted_gem(tmp.path(), Some(("half-built", false)));
        let held = lock_build_dir(&parked).unwrap();
        assert!(held.is_some(), "a directory can be locked here");
        let refused = recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::WouldBlock);
        assert!(recovery_refusal(&copy, &refused).contains("right now"));
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"half-built");
        assert_eq!(std::fs::read(parked.join("a/a.so")).unwrap(), b"original");

        // The holder gone (its process ended), the build is put back. A
        // sibling test forking right now keeps a copy of the descriptor,
        // and the lock with it, until it execs.
        drop(held);
        let recovered = loop {
            match recover_interrupted_rebuild_sync(&copy, Some("lib")) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                recovered => break recovered.unwrap(),
            }
        };
        assert!(recovered);
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"original");
    }

    /// Parking a build keeps what a run that dies mid-build needs: the
    /// build itself (locked while the rebuild lives) and its marker. A
    /// failed build puts the copy back as it was.
    #[test]
    fn a_parked_build_keeps_its_marker_and_goes_back_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = installed_gem(tmp.path(), "lib");
        let ext = tmp.path().join("extensions/p/3.4.0/a-1");
        std::fs::create_dir_all(ext.join("a")).unwrap();
        std::fs::write(ext.join("a/a.so"), b"previous").unwrap();
        std::fs::create_dir_all(copy.gem_dir.join("lib/a")).unwrap();
        std::fs::write(copy.gem_dir.join("lib/a/a.so"), b"previous").unwrap();
        std::fs::write(copy.gem_dir.join(MARKER_FILE), b"{}").unwrap();
        let probe = Probe {
            ruby: PathBuf::from("/r"),
            gem_dir: copy.gem_dir.clone(),
            extension_dir: ext.clone(),
            require_path: "lib".to_string(),
            lib_dir: copy.gem_dir.join("lib"),
        };

        let aside = set_aside(&copy, &probe).unwrap();
        let parked = parked_build_path(&ext);
        assert_eq!(aside.old_ext.as_deref(), Some(parked.as_path()));
        assert!(!ext.exists() && parked.join("a/a.so").is_file());
        assert_eq!(
            std::fs::read(copy.gem_dir.join(MARKER_FILE)).unwrap(),
            b"{}"
        );
        #[cfg(unix)]
        assert_eq!(
            lock_build_dir(&parked).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the rebuild holds its parked build"
        );

        // What a failed build leaves, then the way back.
        std::fs::create_dir_all(ext.join("a")).unwrap();
        std::fs::write(ext.join("a/a.so"), b"broken").unwrap();
        std::fs::write(copy.gem_dir.join("lib/a/a.so"), b"broken").unwrap();
        put_back(&copy, &probe, aside).unwrap();
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"previous");
        assert_eq!(
            std::fs::read(copy.gem_dir.join("lib/a/a.so")).unwrap(),
            b"previous"
        );
        assert_eq!(
            std::fs::read(copy.gem_dir.join(MARKER_FILE)).unwrap(),
            b"{}"
        );
        assert!(!parked.exists());
    }

    #[test]
    fn ruby_candidates_include_the_prefix_ruby() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path();
        let home = prefix.join("lib/ruby/gems/3.4.0");
        std::fs::create_dir_all(home.join("gems/a-1")).unwrap();
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        let exe = if cfg!(windows) { "ruby.exe" } else { "ruby" };
        std::fs::write(prefix.join("bin").join(exe), "").unwrap();
        let copy = GemCopy::of(&home.join("gems/a-1")).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        assert_eq!(
            ruby_candidates(&copy, elsewhere.path())[0],
            prefix.join("bin").join(exe)
        );
        // A prefix inside the scanned project is never run.
        assert!(!ruby_candidates(&copy, prefix).contains(&prefix.join("bin").join(exe)));
    }

    /// Lay down a gem whose socket-patch build replaced the backed-up
    /// install-time build (`with_marker`: the marker was written).
    fn rebuilt_gem(home: &Path, with_marker: bool) -> PathBuf {
        let gem_dir = home.join("gems/a-1");
        let ext = home.join("extensions/p/3.4.0/a-1");
        std::fs::create_dir_all(ext.join("a")).unwrap();
        std::fs::create_dir_all(gem_dir.join("lib/a")).unwrap();
        std::fs::write(ext.join("a/a.so"), b"patched").unwrap();
        std::fs::write(ext.join("a/extra.so"), b"patched").unwrap();
        std::fs::write(gem_dir.join("lib/a/a.so"), b"patched").unwrap();
        std::fs::write(gem_dir.join("lib/a/extra.so"), b"patched").unwrap();
        let backup = gem_dir.join(BACKUP_DIR);
        std::fs::create_dir_all(backup.join("ext/a")).unwrap();
        std::fs::create_dir_all(backup.join("lib/lib/a")).unwrap();
        std::fs::write(backup.join("ext/a/a.so"), b"original").unwrap();
        std::fs::write(backup.join("ext/gem.build_complete"), b"").unwrap();
        std::fs::write(backup.join("lib/lib/a/a.so"), b"original").unwrap();
        let info = BackupInfo {
            extension_dir: "extensions/p/3.4.0/a-1".into(),
            had_extension_dir: true,
            lib_files: vec!["lib/a/a.so".into()],
        };
        std::fs::write(backup.join(BACKUP_INFO), serde_json::to_vec(&info).unwrap()).unwrap();
        if with_marker {
            let marker = BuildMarker {
                schema: MARKER_SCHEMA,
                extension_dir: "extensions/p/3.4.0/a-1".into(),
                lib_artifacts: [
                    ("lib/a/a.so".to_string(), String::new()),
                    ("lib/a/extra.so".to_string(), String::new()),
                ]
                .into(),
                ..BuildMarker::default()
            };
            std::fs::write(
                gem_dir.join(MARKER_FILE),
                serde_json::to_vec(&marker).unwrap(),
            )
            .unwrap();
        }
        gem_dir
    }

    /// A planted backup naming a dir outside this gem's extension dir is
    /// refused before anything is deleted.
    #[tokio::test]
    async fn rollback_refuses_a_backup_naming_another_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let victim = tmp.path().join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("keep"), b"x").unwrap();
        let gem_dir = rebuilt_gem(&home, true);
        for label in [victim.display().to_string(), "../../victim".to_string()] {
            let info = BackupInfo {
                extension_dir: label,
                had_extension_dir: true,
                lib_files: Vec::new(),
            };
            std::fs::write(
                gem_dir.join(BACKUP_DIR).join(BACKUP_INFO),
                serde_json::to_vec(&info).unwrap(),
            )
            .unwrap();
            let env = RubyEnv {
                cwd: home.clone(),
                rebuild: true,
            };
            assert!(restore_original_build(&gem_dir, &env).await.is_err());
            assert!(
                victim.join("keep").is_file(),
                "nothing outside the gem home goes"
            );
            assert!(home.join("extensions/p/3.4.0/a-1/a/a.so").is_file());
        }
    }

    /// A FIFO planted where the backup's description goes fails the
    /// rollback fast instead of blocking in open(2).
    #[cfg(unix)]
    #[tokio::test]
    async fn rollback_does_not_block_on_a_planted_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let gem_dir = rebuilt_gem(&home, true);
        let info = gem_dir.join(BACKUP_DIR).join(BACKUP_INFO);
        std::fs::remove_file(&info).unwrap();
        let c_path = std::ffi::CString::new(info.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: mkfifo on a NUL-terminated path this test owns.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);
        let env = RubyEnv {
            cwd: home.clone(),
            rebuild: true,
        };
        let restored = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            restore_original_build(&gem_dir, &env),
        )
        .await
        .expect("rollback blocked on a FIFO");
        assert!(restored.is_err());
        assert_eq!(
            std::fs::read(home.join("extensions/p/3.4.0/a-1/a/a.so")).unwrap(),
            b"patched",
            "nothing was changed"
        );
    }

    #[tokio::test]
    async fn rollback_restores_the_backed_up_build() {
        for with_marker in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let home = tmp.path();
            let gem_dir = rebuilt_gem(home, with_marker);
            let env = RubyEnv {
                cwd: home.to_path_buf(),
                rebuild: true,
            };
            assert_eq!(restore_original_build(&gem_dir, &env).await, Ok(true));
            let ext = home.join("extensions/p/3.4.0/a-1");
            assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"original");
            assert!(ext.join("gem.build_complete").is_file());
            assert!(
                !ext.join("a/extra.so").exists(),
                "socket-patch's build is gone"
            );
            assert_eq!(
                std::fs::read(gem_dir.join("lib/a/a.so")).unwrap(),
                b"original"
            );
            // Only the marker names socket-patch's extra lib copy.
            assert_eq!(gem_dir.join("lib/a/extra.so").exists(), !with_marker);
            assert!(!gem_dir.join(MARKER_FILE).exists());
            assert!(!gem_dir.join(BACKUP_DIR).exists());
            // Nothing left to restore.
            assert_eq!(restore_original_build(&gem_dir, &env).await, Ok(false));
        }
    }

    /// A marker holds only for the record's own patched sources and the
    /// artifacts' recorded bytes.
    #[test]
    fn marker_holds_checks_sources_and_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let gem_dir = home.join("gems/a-1");
        let ext = home.join("extensions/p/3.4.0/a-1/a");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::create_dir_all(gem_dir.join("lib/a")).unwrap();
        std::fs::write(ext.join("a.so"), b"built").unwrap();
        std::fs::write(gem_dir.join("lib/a/a.so"), b"built").unwrap();
        let copy = GemCopy::of(&gem_dir).unwrap();
        let hash = compute_git_sha256_from_bytes(b"built");
        let after = "c".repeat(64);
        let record: HashMap<String, PatchFileInfo> =
            [("ext/a/a.c".to_string(), info(&after))].into();
        let scope = NativeScope {
            inputs: vec!["ext/a/a.c".into()],
            builds_extensions: true,
        };
        let marker = BuildMarker {
            schema: MARKER_SCHEMA,
            sources: [("ext/a/a.c".to_string(), after.clone())].into(),
            extension_dir: "extensions/p/3.4.0/a-1".into(),
            ext_artifacts: [("a/a.so".to_string(), hash.clone())].into(),
            lib_artifacts: [("lib/a/a.so".to_string(), hash.clone())].into(),
        };
        assert!(marker_holds(&marker, &copy, &scope, &record));

        let other: HashMap<String, PatchFileInfo> =
            [("ext/a/a.c".to_string(), info(&"d".repeat(64)))].into();
        assert!(!marker_holds(&marker, &copy, &scope, &other));

        std::fs::write(gem_dir.join("lib/a/a.so"), b"stale").unwrap();
        assert!(!marker_holds(&marker, &copy, &scope, &record));

        let mut escaping = marker.clone();
        escaping.lib_artifacts = [("../x".to_string(), hash)].into();
        assert!(!marker_holds(&escaping, &copy, &scope, &record));
    }
}
