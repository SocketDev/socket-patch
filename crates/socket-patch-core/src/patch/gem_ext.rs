//! Agent-mode patches to a gem's native extension (#1996).
//!
//! Ruby loads compiled code, never the sources beside it: the shared object
//! RubyGems compiled when it installed the gem
//! (`extensions/<platform>/<abi>/<gem>-<version>/…` and, with
//! `Gem.install_extension_in_lib`, its copy under the gem's `lib/`), or,
//! for a precompiled platform gem (`nokogiri-1.18.3-arm64-darwin`), the
//! binary the gem ships for the running Ruby
//! (`lib/nokogiri/3.4/nokogiri.bundle`). A patch that rewrites only the
//! sources in place leaves the vulnerable compiled code running. So when a
//! gem patch changes a native-extension build input, `apply` rebuilds the
//! extension with RubyGems' own builder, the step `gem install` runs
//! (`extconf.rb` + `make`, a Rakefile, a CMake or Cargo build), with the
//! Ruby that owns the install, and puts the build where Ruby loads it.
//!
//! # What is a build input
//!
//! A gem is native when its installed gemspec declares extensions, or its
//! platform is not `ruby` (a precompiled gem). In a native gem every
//! patched file is a build input unless it clearly is not one (`classify`):
//! `extconf.rb` builds from whatever the gem packs. nokogiri's builds its
//! vendored libxml2 from `patches/libxml2/*.patch`, `ports/**` and
//! `dependencies.yml`, so a record whose only file is an added
//! `patches/libxml2/<n>.patch` changes the compiled library. A gem that is
//! not native has no build inputs but a C source under `ext/`.
//!
//! # What it is built from
//!
//! The source gem, `<name>-<version>.gem`, when it can be had
//! ([`crate::patch::gem_source`]): from the gem home's `cache/`, where
//! RubyGems and Bundler keep it, else downloaded from the gem's source and
//! verified against the sha256 the lock or that source's index pins. An
//! installed copy does not hold everything its extension was built from: a
//! build deletes what it is done with (nokogiri's `ports/`), and a
//! precompiled gem never shipped the build's inputs. The rebuild:
//!
//! 1. Preflight, from files alone: the copy must be a RubyGems install (a
//!    `specifications/` entry beside `gems/`) of a native gem, with a Ruby
//!    to try; a gem RubyGems built must have its extension dir on disk; a
//!    precompiled one must have a way to its source gem (the cached
//!    archive, or a run that is not offline). Otherwise the purl is refused
//!    with [`UNSUPPORTED_CODE`] and nothing is written. So is the JRuby
//!    build of a gem, whose jars no source gem's build scripts produce.
//! 2. The record's files are verified against the copy, and the Ruby that
//!    owns the install is found (or the purl is refused as in 1).
//! 3. The source gem is unpacked into a stage inside the gem home
//!    (`<home>/.socket-patch-build/<gem>`), and the record is laid over it
//!    with [`apply_package_patch`]: every `beforeHash` must hold in the
//!    pristine gem, or the archive is not the gem the patch was written for
//!    and the run stops.
//! 4. RubyGems builds the staged gem's extension in the stage, with the
//!    build arguments it recorded for the installed copy. A gem the build
//!    needs and the install lacks (a precompiled nokogiri has no
//!    `mini_portile2`) is installed into the stage home, never into the
//!    user's. Until the build has finished, nothing of the installed copy
//!    is touched: a failed build fails the purl with [`BUILD_FAILED_CODE`]
//!    and leaves the copy as it was.
//! 5. The record's files are written into the installed copy, and the
//!    build takes the place of the compiled code Ruby loads. For a gem
//!    RubyGems built, the staged extension dir replaces the installed one
//!    (parked while it moves in) and its artifacts replace the `lib/`
//!    copies. For a precompiled gem, each prebuilt binary the owning Ruby
//!    loads is replaced by the build's (`plan_graft`): no counterpart, or
//!    more than one, is refused with nothing written. The first time, the
//!    original build (the prebuilt binaries) is copied to a backup inside
//!    the gem dir ([`BACKUP_DIR`]).
//! 6. A marker ([`MARKER_FILE`]) records the source hashes the build was
//!    made from and the hash of every artifact put in place.
//!
//! When the source gem cannot be had, a gem RubyGems built is rebuilt in
//! place, from its own tree (`rebuild`): the patched sources are written,
//! the current build is moved aside, and RubyGems builds into a fresh
//! extension dir; a failed build puts the old build and the original
//! sources back. A precompiled gem has no such fallback and is refused,
//! with what it needs: network access to the gem's source once, or the
//! source gem in the home's `cache/`.
//!
//! `vex` and `apply --check` attest a copy only when its marker matches the
//! record's patched sources and every recorded artifact still hashes as
//! built ([`verify_native_build`]), whichever way it was built. `rollback`
//! puts the backed-up original build back ([`restore_original_build`]),
//! prebuilt binaries byte for byte.
//!
//! # What is executed, and when
//!
//! A gem tree can be supplied by the repository being scanned (a committed
//! `vendor/bundle`), and its installed gemspec is a Ruby program. So
//! whether a record needs a rebuild is decided without running anything:
//! the gemspec is read as text (it is `Gem::Specification#to_ruby` output)
//! for its `extensions`, its platform and its require paths (`SpecFacts`),
//! never evaluated. `--dry-run`, `apply --check` and `vex` stop there. They
//! start no Ruby and download nothing.
//!
//! A real run starts a program only after the record's files verified
//! against the installed copy (each holds its `beforeHash` or `afterHash`
//! content, or a mismatch the caller's policy overwrites; a build input
//! the copy does not hold is checked in step 3 instead), and then, in this
//! order:
//!
//! 1. The host Ruby alone, asked where it builds extensions for the copy's
//!    gem home and what it is (`RubyRun::ExtensionsDir`). That loads
//!    RubyGems and nothing of the gem.
//! 2. RubyGems, unpacking the source gem into the stage
//!    (`RubyRun::Unpack`) and naming the gems its build depends on that are
//!    not installed (`RubyRun::MissingDeps`). The archive's metadata is
//!    read as data; none of its code runs. A missing gem is downloaded,
//!    verified against its source's index and installed into the stage
//!    home (`RubyRun::Install`), which runs that gem's build scripts if it
//!    has any.
//! 3. With the record laid over the staged gem, RubyGems' extension builder
//!    (`RubyRun::StageBuild`). It runs the archive's own build scripts
//!    (`extconf.rb`, a Rakefile, `make`, the compiler), as `gem install`
//!    ran them, and loads the gemspec `unpack` wrote from the archive. The
//!    installed gemspec is not evaluated at all.
//!
//! The in-place fallback runs RubyGems' builder on the installed copy
//! instead (`RubyRun::Build`), with the patched sources written: it loads
//! the installed gemspec and runs the copy's own build scripts, and
//! refuses to build when the loaded gemspec does not describe the layout
//! its text was read for.
//!
//! The Ruby is the one installed beside the gem home, else the `ruby` on
//! `PATH`; one inside the project is never run (`ruby_candidates`). For a
//! gem RubyGems built it is the Ruby whose extension dir for the gem is the
//! installed one (`find_ruby`); for a precompiled gem, the Ruby that runs
//! the gem's platform and builds its extensions where the home has its
//! other gems' (`find_platform_ruby`). Every run goes without the Socket
//! credentials ([`CHILD_ENV_SCRUB`](crate::utils::process::CHILD_ENV_SCRUB)),
//! `RUBYOPT`, `RUBYLIB` and `BUNDLE*`.
//!
//! The hosted stale-install refresh ([`crate::patch::gem_refresh`]) builds
//! a native gem another way (`install_staged`, `RubyRun::Install`): the
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
//! so no compiler is left writing into the gem.
//!
//! A build in the stage leaves the installed copy untouched, so an
//! interrupted one leaves only the stage dir, under an advisory lock that
//! went with its process. The next `apply` or `rollback` of the copy drops
//! it (`sweep_stale_stage`). A stage a run in another process still holds
//! (a gem home shared between projects) is left alone, and the purl is
//! refused.
//!
//! While a finished build moves in, and for the whole of an in-place
//! build, the previous build is parked beside the extension dir
//! (`parked_build_path`), under the same kind of lock, and the previous
//! marker stays in the gem dir until the new build's replaces it. The next
//! `apply` or `rollback` of the copy starts by moving a parked build back
//! (`recover_interrupted_rebuild`), unless the extension dir holds a
//! finished build. The sources stay patched, which is the state `apply`
//! completes with a rebuild and `rollback` undoes. A graft that stops
//! between two binaries leaves the backup of the originals in the gem dir
//! and no marker: `apply` grafts again, and `rollback` restores them.

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
use crate::patch::gem_source::{GemId, GemSource, RubyVersions};
use crate::utils::fs::read_regular_to_bytes_sync;

/// The refusal when a native-extension patch cannot be rebuilt here (the
/// vendored backend's code for the same limitation).
pub const UNSUPPORTED_CODE: &str = "native_extensions_unsupported";
/// The extension failed to build from the patched sources; the installed
/// copy is as it was before the run.
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

/// The stage a rebuild from the source gem builds in, inside the gem home
/// (the same filesystem as the build it replaces, so the finished extension
/// dir is renamed into place): `<home>/.socket-patch-build/<full_name>`.
const BUILD_STAGE_DIR: &str = ".socket-patch-build";

/// How long one Ruby probe may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(60);
/// How long unpacking one source gem into the stage may take.
const UNPACK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// How many gems one build may need staged beside it before the run gives
/// up on it (a build needs one or two: `mini_portile2`, `rb_sys`).
const MAX_STAGED_DEPENDENCIES: usize = 12;
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

/// Sources a native gem compiles that are not C-family: a JRuby gem's Java,
/// a Rust extension's crate.
const NATIVE_BUILD_EXTENSIONS: &[&str] = &["java", "rs"];

/// Build-system manifests, which are build inputs of a native gem wherever
/// they sit (a `CMakeLists.txt` at the gem root is no document).
const NATIVE_BUILD_FILES: &[&str] = &[
    "CMakeLists.txt",
    "Makefile",
    "GNUmakefile",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
];

/// Top-level dirs of a gem that take no part in building its extension:
/// executables, tests and documentation.
const NOT_BUILT_DIRS: &[&str] = &[
    "bin", "exe", "test", "spec", "features", "doc", "docs", "man",
];

/// Grammar sources a gem ships already generated (racc / ragel output is a
/// `.rb` or `.c` file the gem packs): in a gem that builds no extension they
/// compile nothing at install time.
const GENERATED_GRAMMAR_EXTENSIONS: &[&str] = &["y", "rl"];

/// The probe/build program run by the gem's Ruby ([`RubyRun`] names its
/// modes and their arguments). One line: `-e` with an embedded newline
/// is fragile through a Windows command line. Ruby 1.8 does not load
/// RubyGems by default (and `RUBYOPT` is cleared), so it is required
/// explicitly; a RubyGems older than 2.2 (no per-gem extension dir, no
/// `raw_require_paths`) is refused by name. Every line the program answers
/// with carries an `sp_` key so stray output (an `operating_system.rb`, a
/// shim) is skipped.
///
/// `extensions_dir <home> [<platform>]` evaluates nothing of the gem: it is
/// `Gem::BasicSpecification#extensions_dir` for a spec in `<home>`, a
/// function of this Ruby's platform and ABI (and a packager's
/// `default_ext_dir_for`) alone. A second line names this Ruby: its
/// version, its RubyGems, the suffix of the extensions it loads, its
/// platform, and whether a gem of `<platform>` runs on it.
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
///
/// `unpack <archive> <stage home> <full name>` extracts a `.gem` into
/// `<stage home>/gems/<full name>` and writes its gemspec beside it, as
/// the installer does, without building anything: the archive must be the
/// gem `<full name>` and declare extensions. Nothing of it is evaluated
/// (its metadata is YAML, loaded as data).
///
/// `missing_deps <staged gemspec>` names the runtime dependencies of the
/// staged gem, and of the gems that meet them, that no gem on `GEM_PATH`
/// meets: what its build scripts may `require` and would not find.
///
/// `stage_build <staged gemspec> <stage home> <installed home> <installed
/// full name>` builds the staged gem's extensions inside the stage home,
/// with the build arguments RubyGems recorded for the installed copy. It
/// loads the gemspec `unpack` wrote and runs the archive's build scripts
/// over the staged tree.
const RUBY_SCRIPT: &str = "require 'rubygems'; mode, a, b, c, d = ARGV; \
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
runs = b ? (Gem::Platform.new(b) === Gem::Platform.local ? 'yes' : 'no') : ''; \
puts \"sp_ruby\\t#{RUBY_VERSION}\\t#{Gem::VERSION}\\t#{RbConfig::CONFIG['DLEXT']}\\t\
#{Gem::Platform.local}\\t#{runs}\"; \
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
elsif mode == 'unpack' then \
require 'rubygems/package'; require 'fileutils'; \
pkg = Gem::Package.new(a); spec = pkg.spec; \
abort(\"the archive holds #{spec.full_name}, not #{c}\") unless spec.full_name == c; \
abort(\"#{spec.full_name} declares no extensions to build\") if spec.extensions.empty?; \
dir = File.join(b, 'gems', spec.full_name); FileUtils.mkdir_p(dir); \
pkg.extract_files(dir); \
specs = File.join(b, 'specifications'); FileUtils.mkdir_p(specs); \
File.open(File.join(specs, \"#{spec.full_name}.gemspec\"), 'wb') { |f| f.write(spec.to_ruby_for_cache) }; \
puts \"sp_unpacked\\t#{spec.full_name}\\t#{spec.raw_require_paths.first}\"; \
elsif mode == 'missing_deps' then \
spec = Gem::Specification.load(a) or abort(\"cannot load #{a}\"); \
seen = {}; todo = [spec]; \
until todo.empty? do \
todo.shift.runtime_dependencies.each do |dep| \
next if seen[dep.name]; \
seen[dep.name] = true; \
found = dep.matching_specs; \
if found.empty? then \
puts \"sp_missing\\t#{dep.name}\\t#{dep.requirement.as_list.join(',')}\"; \
else \
todo << found.sort_by { |s| s.version }.last; \
end; \
end; \
end; \
puts 'sp_deps_checked'; \
elsif mode == 'stage_build' then \
spec = Gem::Specification.load(a) or abort(\"cannot load #{a}\"); \
unless File.expand_path(spec.base_dir) == File.expand_path(b) then \
abort(\"#{a} is not a gem of #{b}\"); \
end; \
abort(\"#{a} declares no extensions\") if spec.extensions.empty?; \
require 'rubygems/ext'; \
Gem::DefaultUserInteraction.ui = Gem::SilentUI.new; \
info = File.join(c, 'build_info', \"#{d}.info\"); \
args = File.file?(info) ? File.readlines(info).map { |l| l.chomp } : []; \
Gem::Ext::Builder.new(spec, args).build_extensions; \
puts \"sp_built\\t#{File.expand_path(spec.extension_dir)}\"; \
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

/// The right-hand side of every `<receiver>.<attr> = …` line of an
/// installed gemspec (`Specification#to_ruby` writes one assignment per
/// attribute), comments stripped. A comparison (`==`) or a longer attribute
/// name (`require_paths_extra`) is not one.
fn assignments<'t>(spec_text: &'t str, attr: &'t str) -> impl Iterator<Item = &'t str> + 't {
    spec_text.lines().filter_map(move |raw| {
        let line = raw.split('#').next().unwrap_or("");
        let needle = line
            .match_indices(attr)
            .find(|(at, _)| line[..*at].ends_with('.'))?;
        let after = &line[needle.0 + attr.len()..];
        if after
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return None;
        }
        after
            .trim_start()
            .strip_prefix('=')
            .filter(|rhs| !rhs.starts_with('='))
    })
}

/// The gem's require paths (`lib`), parsed out of an installed gemspec's
/// `s.require_paths = ["lib".freeze]` (`Specification#to_ruby` always
/// writes the assignment). RubyGems installs the built extension's copies
/// under the first. A spec that assigns none has RubyGems' default, `lib`;
/// an assignment that lists no string literal is `None`.
fn parse_require_paths(spec_text: &str) -> Option<Vec<String>> {
    match assignments(spec_text, "require_paths").next() {
        Some(rhs) => Some(string_literals(rhs)).filter(|paths| !paths.is_empty()),
        None => Some(vec!["lib".to_string()]),
    }
}

/// The gem's first require path ([`parse_require_paths`]).
fn parse_require_path(spec_text: &str) -> Option<String> {
    parse_require_paths(spec_text).and_then(|paths| paths.into_iter().next())
}

/// The string an installed gemspec assigns to `attr` (`s.name =
/// "nokogiri".freeze`): `None` when it assigns none, or something that is
/// not a string literal (`s.platform = Gem::Platform::RUBY`).
fn parse_string_attr(spec_text: &str, attr: &str) -> Option<String> {
    assignments(spec_text, attr)
        .next()
        .and_then(|rhs| string_literals(rhs).into_iter().next())
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

/// What an installed gemspec's text says about the gem's compiled code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SpecFacts {
    extensions: ExtensionDecl,
    /// The platform of a platform gem (`arm64-darwin`, `x86_64-linux-gnu`,
    /// `java`): the gem's dir name carries it after `<name>-<version>-`,
    /// and its gemspec assigns it. `None` for the `ruby` platform.
    platform: Option<String>,
    /// Every require path the gemspec names (`lib`).
    require_paths: Vec<String>,
    /// The release the copy was installed from, when the gemspec names it
    /// and the dir name agrees: what its source archive is called.
    release: Option<GemId>,
}

impl SpecFacts {
    /// Read the gemspec text of the copy whose gem dir is `full_name`.
    fn of(spec_text: &str, full_name: &str) -> SpecFacts {
        let name = parse_string_attr(spec_text, "name");
        let version = parse_string_attr(spec_text, "version");
        // `<name>-<version>` is the ruby platform; `<name>-<version>-<p>` is
        // the platform gem `p`.
        let suffix = match (&name, &version) {
            (Some(name), Some(version)) => full_name
                .strip_prefix(&format!("{name}-{version}"))
                .filter(|rest| rest.is_empty() || rest.starts_with('-')),
            _ => None,
        };
        let from_dir = suffix.and_then(|rest| rest.strip_prefix('-'));
        let assigned = parse_string_attr(spec_text, "platform").filter(|p| p != "ruby");
        let platform = from_dir
            .map(str::to_string)
            .or(assigned)
            .filter(|p| !p.is_empty());
        let release = match (name, version, suffix) {
            (Some(name), Some(version), Some(_)) => Some(GemId {
                name,
                version,
                platform: from_dir.map(str::to_string),
            }),
            _ => None,
        };
        SpecFacts {
            extensions: parse_extensions(spec_text),
            platform,
            require_paths: parse_require_paths(spec_text).unwrap_or_default(),
            release,
        }
    }
}

/// Whether `platform` is JRuby's: a `java` gem ships its compiled code as
/// jars built from Java sources, which no source gem's `extconf.rb` builds.
fn is_java_platform(platform: &str) -> bool {
    platform
        .split('-')
        .any(|part| part.eq_ignore_ascii_case("java") || part.eq_ignore_ascii_case("jruby"))
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

/// Whether a file of a native gem is a build file by its name, wherever it
/// sits: a Java or Rust source, or the manifest of a build system.
fn is_build_file_by_name(path: &str) -> bool {
    let leaf = path.rsplit('/').next().unwrap_or(path);
    NATIVE_BUILD_FILES.contains(&leaf)
        || leaf.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty() && NATIVE_BUILD_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        })
}

/// Whether a file of a native gem clearly takes no part in its build: a
/// file under a require path (Ruby loads it as it is), an executable, a
/// test, documentation, or the gem's own packaging files.
fn is_clearly_not_built(path: &str, require_paths: &[String]) -> bool {
    let under_require_path = require_paths.iter().any(|require_path| {
        let dir = require_path.trim_start_matches("./").trim_end_matches('/');
        // A gem that requires from its root says nothing about a file.
        !dir.is_empty()
            && dir != "."
            && path
                .strip_prefix(dir)
                .is_some_and(|rest| rest.starts_with('/'))
    });
    if under_require_path {
        return true;
    }
    match path.split_once('/') {
        Some((top, _)) => NOT_BUILT_DIRS.contains(&top),
        None => {
            let upper = path.to_ascii_uppercase();
            ["README", "LICENSE", "LICENCE", "CHANGELOG", "GEMFILE"]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
                || [".MD", ".TXT", ".GEMSPEC"]
                    .iter()
                    .any(|suffix| upper.ends_with(suffix))
        }
    }
}

/// A gem record's native-extension build inputs on one installed copy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NativeScope {
    /// The record's keys that are build inputs, sorted.
    inputs: Vec<String>,
    /// The installed spec declares extensions (RubyGems builds them at
    /// install time).
    builds_extensions: bool,
    /// The platform of a precompiled platform gem: its spec declares no
    /// extensions and its platform is not `ruby`, so the compiled code it
    /// runs was built from the ruby-platform source gem before it was
    /// packed.
    precompiled: Option<String>,
    /// The release the copy was installed from ([`SpecFacts::release`]).
    release: Option<GemId>,
}

impl NativeScope {
    /// The archive the copy's extension is rebuilt from: its own for a gem
    /// RubyGems built at install time, the ruby-platform source gem of the
    /// same version for a precompiled one.
    fn source_gem(&self) -> Option<GemId> {
        let release = self.release.clone()?;
        Some(match &self.precompiled {
            Some(_) => GemId {
                platform: None,
                ..release
            },
            None => release,
        })
    }
}

/// Classify `files` against what the installed gemspec says (`facts`).
///
/// A gem is native when its gemspec declares extensions or its platform is
/// not `ruby` (a precompiled platform gem). In a native gem every patched
/// file is a build input unless it clearly is not one
/// ([`is_clearly_not_built`]): `extconf.rb` builds from whatever the gem
/// packs (nokogiri's reads `patches/**`, `ports/**` and
/// `dependencies.yml`), so only a file known to take no part counts as
/// plain. A source by name ([`is_native_by_name`], [`is_build_file_by_name`])
/// and anything under `ext/` or the dir of a declared build script is
/// always an input; a script at the gem root (`extensions =
/// ["extconf.rb"]`) makes the files beside it inputs. A grammar under a
/// require path of a precompiled gem is not one: its generated output is
/// what the gem packs and Ruby loads.
///
/// In a gem that is not native (no extensions, the `ruby` platform), only a
/// name-matched source under `ext/` counts. C or Objective-C files
/// elsewhere (a template, a test fixture) compile nothing, and neither do
/// grammar sources, whose generated output the gem packs.
fn classify(facts: &SpecFacts, files: &HashMap<String, PatchFileInfo>) -> NativeScope {
    let decl = &facts.extensions;
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
    let precompiled = facts.platform.clone().filter(|_| !decl.declared);
    let native = decl.declared || precompiled.is_some();
    let mut inputs: Vec<String> = files
        .keys()
        .filter(|key| {
            let path = normalize_file_path(key);
            if !native {
                return path.starts_with("ext/")
                    && is_native_by_name(path)
                    && !is_generated_grammar(path);
            }
            let plain = is_clearly_not_built(path, &facts.require_paths);
            if precompiled.is_some() && plain && is_generated_grammar(path) {
                return false;
            }
            is_native_by_name(path)
                || is_build_file_by_name(path)
                || under_script_dir(path)
                || path.starts_with("ext/")
                || !plain
        })
        .cloned()
        .collect();
    inputs.sort();
    NativeScope {
        inputs,
        builds_extensions: decl.declared,
        precompiled,
        release: facts.release.clone(),
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
    let facts = match (&copy, &spec_text) {
        (Some(copy), Some(text)) => SpecFacts::of(text, &copy.full_name),
        _ => SpecFacts::default(),
    };
    let scope = classify(&facts, files);
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
    /// Empty for a grafted build.
    pub extension_dir: String,
    /// Artifact path relative to the extension dir → git-sha256.
    pub ext_artifacts: BTreeMap<String, String>,
    /// The artifacts' copies RubyGems put under the gem's require dir:
    /// path relative to the gem dir → git-sha256. For a grafted build, the
    /// prebuilt binaries the build replaced.
    pub lib_artifacts: BTreeMap<String, String>,
    /// The copy is a precompiled platform gem, and `lib_artifacts` are its
    /// prebuilt binaries replaced by a build of the source gem (schema
    /// [`GRAFT_MARKER_SCHEMA`]).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub grafted: bool,
}

/// The marker of an extension dir RubyGems' builder filled.
const MARKER_SCHEMA: u32 = 1;
/// The marker of a precompiled copy whose prebuilt binaries were replaced
/// ([`BuildMarker::grafted`]). A release that only knows schema 1 reads it
/// as no marker, and so attests nothing it does not understand.
const GRAFT_MARKER_SCHEMA: u32 = 2;

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
        .filter(|m| match m.schema {
            MARKER_SCHEMA => !m.grafted,
            GRAFT_MARKER_SCHEMA => m.grafted,
            _ => false,
        })
}

/// Whether `marker` was built from exactly the record's patched native
/// inputs, and every artifact it recorded is still on disk with the bytes it
/// was built with. An artifact path that escapes its dir never verifies.
///
/// A marker speaks for the kind of copy it was written for: one of an
/// extension dir for a gem that builds its extensions, a grafted one for a
/// precompiled gem, which must name at least one replaced binary.
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
    let artifact_ok = |base: &Path, rel: &str, hash: &str| {
        is_safe_relative_subpath(rel)
            && compute_file_git_sha256_sync(&base.join(rel)).is_ok_and(|h| h == hash)
    };
    let lib_ok = || {
        marker
            .lib_artifacts
            .iter()
            .all(|(rel, hash)| artifact_ok(&copy.gem_dir, rel, hash))
    };
    if marker.grafted {
        return scope.precompiled.is_some()
            && !scope.builds_extensions
            && marker.ext_artifacts.is_empty()
            && !marker.lib_artifacts.is_empty()
            && lib_ok();
    }
    if !scope.builds_extensions {
        return false;
    }
    let Some(ext_dir) = confined_ext_dir(copy, &marker.extension_dir) else {
        return false;
    };
    marker
        .ext_artifacts
        .iter()
        .all(|(rel, hash)| artifact_ok(&ext_dir, rel, hash))
        && lib_ok()
}

/// `vex` / `apply --check`: the installed gem copy at `pkg_path`, whose
/// record files already verify, runs code built from them. A record with no
/// native input on this copy passes; one with native inputs passes only when
/// the copy's build marker holds ([`BuildMarker`]): for a gem RubyGems built
/// at install time, the marker of its rebuilt extension dir; for a
/// precompiled platform gem, the marker of the prebuilt binaries replaced
/// by a build of the source gem. Errors carry [`NOT_REBUILT_REASON`].
pub async fn verify_native_build(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Result<(), String> {
    let (scope, copy) = scope_of(pkg_path, files).await;
    if scope.inputs.is_empty() {
        return Ok(());
    }
    let Some(copy) = copy else {
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
    /// `--offline`: a source gem that is not in the gem home's `cache/` is
    /// not downloaded, and neither is a gem its build needs.
    pub offline: bool,
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
    /// What `ruby` said of itself, when it did.
    facts: Option<RubyFacts>,
}

/// What a Ruby says of itself in a [`RubyRun::ExtensionsDir`] run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RubyFacts {
    /// `RUBY_VERSION` (`3.4.10`).
    ruby_version: String,
    /// `Gem::VERSION`.
    rubygems_version: String,
    /// The suffix of the extensions it loads (`so`, `bundle`).
    dlext: String,
    /// `Gem::Platform.local` (`arm64-darwin-25`).
    platform: String,
    /// Whether a gem of the platform the run named runs on it; `None` when
    /// the run named none.
    runs_platform: Option<bool>,
}

impl RubyFacts {
    /// `RUBY_VERSION[/\d+\.\d+/]`: the dir a precompiled gem keeps the
    /// binary for this Ruby in (`3.4`).
    fn minor(&self) -> Option<String> {
        let mut parts = self.ruby_version.split('.');
        let (major, minor) = (parts.next()?, parts.next()?);
        let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
        (numeric(major) && numeric(minor)).then(|| format!("{major}.{minor}"))
    }

    fn versions(&self) -> RubyVersions {
        RubyVersions {
            ruby: Some(self.ruby_version.clone()),
            rubygems: Some(self.rubygems_version.clone()),
        }
    }
}

/// The `sp_extensions_dir` line of a [`RubyRun::ExtensionsDir`] run.
fn parse_extensions_dir(stdout: &str) -> Option<PathBuf> {
    stdout.lines().find_map(|line| {
        let (key, value) = line.split_once('\t')?;
        (key == "sp_extensions_dir" && !value.is_empty()).then(|| PathBuf::from(value))
    })
}

/// The `sp_ruby` line of a [`RubyRun::ExtensionsDir`] run.
fn parse_ruby_facts(stdout: &str) -> Option<RubyFacts> {
    stdout.lines().find_map(|line| {
        let mut fields = line.split('\t');
        (fields.next()? == "sp_ruby").then_some(())?;
        let (ruby_version, rubygems_version) = (fields.next()?, fields.next()?);
        let (dlext, platform) = (fields.next()?, fields.next()?);
        let runs_platform = match fields.next() {
            Some("yes") => Some(true),
            Some("no") => Some(false),
            _ => None,
        };
        (!ruby_version.is_empty() && !dlext.is_empty()).then(|| RubyFacts {
            ruby_version: ruby_version.to_string(),
            rubygems_version: rubygems_version.to_string(),
            dlext: dlext.to_string(),
            platform: platform.to_string(),
            runs_platform,
        })
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

/// The `GEM_PATH` a build runs with: `homes` first (the copy's own, so an
/// `extconf.rb` requiring `mini_portile2` or `rb_sys` finds the copy
/// installed beside it; before it, a stage home holding the gems the build
/// needs and the install lacks), then the caller's, then RubyGems'
/// defaults (the trailing separator).
fn gem_path_for(homes: &[&Path]) -> Option<OsString> {
    let mut paths: Vec<PathBuf> = homes.iter().map(|home| home.to_path_buf()).collect();
    if let Some(existing) = std::env::var_os("GEM_PATH") {
        paths.extend(std::env::split_paths(&existing).filter(|p| !p.as_os_str().is_empty()));
    }
    let mut joined = std::env::join_paths(paths).ok()?;
    joined.push(if cfg!(windows) { ";" } else { ":" });
    Some(joined)
}

/// What a run of [`RUBY_SCRIPT`] is for.
enum RubyRun<'a> {
    /// Ask where this Ruby builds extensions for the copy's gem home, and
    /// what it is. Loads RubyGems and nothing of the gem. With `platform`
    /// it also says whether a gem of that platform runs on it.
    ExtensionsDir { platform: Option<&'a str> },
    /// Build the copy's extensions into `probe.extension_dir`: loads the
    /// installed gemspec and runs the gem's build scripts.
    Build(&'a Probe),
    /// Install the `.gem` at `archive` into the empty `stage_home`, building
    /// its extensions there: runs the archive's own build scripts.
    Install {
        archive: &'a Path,
        stage_home: &'a Path,
    },
    /// Extract the `.gem` at `archive`, which must be the gem `full_name`
    /// and declare extensions, into `stage_home`. Runs nothing of it.
    Unpack {
        archive: &'a Path,
        stage_home: &'a Path,
        full_name: &'a str,
    },
    /// Name the gems the staged gem at `spec` depends on that neither the
    /// stage home nor the copy's home (nor the caller's `GEM_PATH`) holds.
    MissingDeps {
        spec: &'a Path,
        stage_home: &'a Path,
    },
    /// Build the extensions of the staged gem at `spec` inside
    /// `stage_home`: runs the staged tree's build scripts.
    StageBuild {
        spec: &'a Path,
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
        RubyRun::ExtensionsDir { platform } => {
            command.arg("extensions_dir").arg(&copy.home);
            if let Some(platform) = platform {
                command.arg(platform);
            }
            "extensions_dir"
        }
        RubyRun::Build(probe) => {
            command
                .arg("build")
                .arg(&copy.spec_path)
                .arg(&probe.extension_dir)
                .arg(&probe.require_path);
            if let Some(gem_path) = gem_path_for(&[&copy.home]) {
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
            if let Some(gem_path) = gem_path_for(&[&copy.home]) {
                command.env("GEM_PATH", gem_path);
            }
            "install"
        }
        RubyRun::Unpack {
            archive,
            stage_home,
            full_name,
        } => {
            command
                .arg("unpack")
                .arg(archive)
                .arg(stage_home)
                .arg(full_name);
            "unpack"
        }
        RubyRun::MissingDeps { spec, stage_home } => {
            command.arg("missing_deps").arg(spec);
            if let Some(gem_path) = gem_path_for(&[stage_home, &copy.home]) {
                command.env("GEM_PATH", gem_path);
            }
            "missing_deps"
        }
        RubyRun::StageBuild { spec, stage_home } => {
            command
                .arg("stage_build")
                .arg(spec)
                .arg(stage_home)
                .arg(&copy.home)
                .arg(&copy.full_name);
            // The stage home first: the gems the build needs and the
            // install lacks were put there, and nowhere else.
            if let Some(gem_path) = gem_path_for(&[stage_home, &copy.home]) {
                command.env("GEM_PATH", gem_path);
            }
            "stage_build"
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
    // The stage of a rebuild from the source gem that never finished is
    // dropped too: nothing of the copy is in it. One a live run holds is
    // that run's (`WouldBlock`).
    sweep_stale_stage(copy)?;
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

/// What a rebuild of a precompiled copy needs that files alone tell
/// ([`rebuild_preflight`] for a gem RubyGems built): a require path its
/// prebuilt binaries sit under and a Ruby to try. It has no extension dir;
/// `installed` are the home's `extensions/<platform>/<abi>` dirs, where the
/// Ruby that owns the home built its other gems.
async fn graft_preflight(copy: &GemCopy, env: &RubyEnv) -> Result<Preflight, String> {
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
    let installed = {
        let copy = copy.clone();
        crate::utils::fs::run_blocking(move || {
            let mut dirs: Vec<PathBuf> = extension_dir_slots(&copy)
                .iter()
                .filter_map(|slot| slot.parent().map(Path::to_path_buf))
                .filter(|abi| is_real_dir(abi))
                .collect();
            dirs.dedup();
            dirs
        })
        .await
    };
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
        let run = RubyRun::ExtensionsDir { platform: None };
        let stdout = match run_ruby(&ruby, run, copy, env, PROBE_TIMEOUT).await {
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
            facts: parse_ruby_facts(&stdout),
        });
    }
    Err(format!(
        "no Ruby owning this install was found ({})",
        reasons.join("; ")
    ))
}

/// Whether a gem home's leaf dir names a Ruby ABI (`3.4.0`), as the homes
/// RubyGems and Bundler lay out do (`<prefix>/lib/ruby/gems/3.4.0`,
/// `vendor/bundle/ruby/3.4.0`, `~/.gem/ruby/3.4.0`).
fn abi_of_home(home: &Path) -> Option<String> {
    let leaf = home.file_name()?.to_str()?;
    let versioned = leaf.starts_with(|c: char| c.is_ascii_digit())
        && leaf.contains('.')
        && leaf.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    versioned.then(|| leaf.to_string())
}

/// [`find_ruby`] for a precompiled copy of the platform `platform`, which
/// has no extension dir to match a Ruby to. The Ruby that owns it:
///
/// * runs gems of that platform (`Gem::Platform#===`, as RubyGems picks a
///   platform gem), and
/// * builds its extensions where this gem home has some (the home's
///   `extensions/<platform>/<abi>` dirs, from its other native gems); in a
///   home with none, its ABI is the one the home's dir name carries
///   (`…/ruby/3.4.0`), when it carries one.
///
/// Its facts are part of the answer: the build is grafted over the binary
/// the gem keeps for that Ruby's `major.minor`.
async fn find_platform_ruby(
    copy: &GemCopy,
    env: &RubyEnv,
    preflight: Preflight,
    platform: &str,
) -> Result<Probe, String> {
    let Preflight {
        installed,
        candidates,
        require_path,
    } = preflight;
    let mut reasons = Vec::new();
    for ruby in candidates {
        let run = RubyRun::ExtensionsDir {
            platform: Some(platform),
        };
        let stdout = match run_ruby(&ruby, run, copy, env, PROBE_TIMEOUT).await {
            Ok(s) => s,
            Err(e) => {
                reasons.push(format!("{}: {e}", ruby.display()));
                continue;
            }
        };
        let (Some(extensions_dir), Some(facts)) =
            (parse_extensions_dir(&stdout), parse_ruby_facts(&stdout))
        else {
            reasons.push(format!("{}: unreadable probe output", ruby.display()));
            continue;
        };
        if facts.runs_platform != Some(true) {
            reasons.push(format!(
                "{} is a {} Ruby, which does not run {platform} gems",
                ruby.display(),
                facts.platform
            ));
            continue;
        }
        let abi = extensions_dir
            .file_name()
            .map(|n| n.to_string_lossy().trim_end_matches("-static").to_string())
            .unwrap_or_default();
        let owns = if !installed.is_empty() {
            installed.iter().any(|dir| same_path(dir, &extensions_dir))
        } else {
            abi_of_home(&copy.home).is_none_or(|home_abi| home_abi == abi)
        };
        if !owns {
            reasons.push(format!(
                "{} builds extensions into {}, which is not where this gem home has its own \
                 (another Ruby's)",
                ruby.display(),
                extensions_dir.display()
            ));
            continue;
        }
        return Ok(Probe {
            ruby,
            gem_dir: copy.gem_dir.clone(),
            extension_dir: extensions_dir.join(&copy.full_name),
            lib_dir: copy.gem_dir.join(&require_path),
            require_path,
            facts: Some(facts),
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
    /// The backup is of a precompiled copy: `lib_files` are the prebuilt
    /// binaries a build of the source gem replaced, and there is no
    /// extension dir.
    #[serde(default)]
    grafted: bool,
    /// Build inputs of the record that the installed copy did not hold and
    /// the patch wrote into it (normalized paths): `rollback` removes them
    /// instead of restoring content the copy never held
    /// ([`rollback_files`]).
    #[serde(default)]
    absent_files: Vec<String>,
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
/// The backup also lists `absent`, the record's files the copy did not hold
/// ([`files_as_installed`]); one that exists learns of those it does not
/// list. `Ok(true)` when this call made the backup.
fn back_up_original(copy: &GemCopy, probe: &Probe, absent: &[String]) -> std::io::Result<bool> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    if std::fs::symlink_metadata(&backup).is_ok() {
        note_absent_files(&backup, absent)?;
        return Ok(false);
    }
    if std::fs::symlink_metadata(copy.gem_dir.join(MARKER_FILE)).is_ok() {
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
            let src = copy.gem_dir.join(&lib);
            if let Ok(bytes) = read_regular_to_bytes_sync(&src) {
                let dst = stage.join("lib").join(&lib);
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&dst, bytes)?;
                // The copy's mode too (RubyGems installs a shared object
                // executable), so the restore gives back the file as it was.
                if let Ok(meta) = std::fs::metadata(&src) {
                    let _ = std::fs::set_permissions(&dst, meta.permissions());
                }
                lib_files.push(lib);
            }
        }
    }
    let info = BackupInfo {
        extension_dir: ext_dir_label(&copy.home, &probe.extension_dir),
        had_extension_dir,
        lib_files,
        absent_files: absent.to_vec(),
        ..BackupInfo::default()
    };
    write_backup_info(&stage, &info)?;
    std::fs::rename(&stage, &backup)?;
    Ok(true)
}

/// Write a backup's description into `dir`: staged beside its place and
/// renamed, so it is always whole.
fn write_backup_info(dir: &Path, info: &BackupInfo) -> std::io::Result<()> {
    let stage = dir.join(format!("{BACKUP_INFO}.tmp"));
    std::fs::write(
        &stage,
        serde_json::to_vec_pretty(info).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(&stage, dir.join(BACKUP_INFO))
}

/// Add `absent` (files a later apply writes into a copy that did not hold
/// them) to an existing backup's list, so `rollback` removes them too. A
/// backup that is not a dir this tool wrote is left as it is.
fn note_absent_files(backup: &Path, absent: &[String]) -> std::io::Result<()> {
    if absent.is_empty() || !is_real_dir(backup) {
        return Ok(());
    }
    let known = read_regular_to_bytes_sync(&backup.join(BACKUP_INFO))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<BackupInfo>(&bytes).ok());
    let Some(mut info) = known else {
        return Ok(());
    };
    let before = info.absent_files.len();
    for path in absent {
        if !info.absent_files.contains(path) {
            info.absent_files.push(path.clone());
        }
    }
    if info.absent_files.len() != before {
        write_backup_info(backup, &info)?;
    }
    Ok(())
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
    write_marker(copy, &marker)?;
    if let Some(old) = &aside.old_ext {
        let _ = remove_dir_if_exists(old);
    }
    Ok(())
}

/// Record `marker` in the gem dir: staged beside its place and renamed, so
/// a marker is always whole.
fn write_marker(copy: &GemCopy, marker: &BuildMarker) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(marker).map_err(std::io::Error::other)?;
    let marker_path = copy.gem_dir.join(MARKER_FILE);
    let stage = copy.gem_dir.join(format!("{MARKER_FILE}.tmp"));
    let written =
        std::fs::write(&stage, bytes).and_then(|()| std::fs::rename(&stage, &marker_path));
    if written.is_err() {
        let _ = std::fs::remove_file(&stage);
    }
    written
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
                back_up_original(&copy, &probe, &[])
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

/// `<home>/.socket-patch-build/<full_name>`: where a rebuild of `copy` from
/// its source gem is staged.
fn stage_root(copy: &GemCopy) -> PathBuf {
    copy.home.join(BUILD_STAGE_DIR).join(&copy.full_name)
}

/// Drop the stage a rebuild of `copy` left behind when its process was
/// interrupted or killed. Nothing of the installed copy is in a stage, so
/// one that is left is only disk space. `Err` of kind `WouldBlock`: a run
/// that is still alive holds it ([`lock_build_dir`]).
fn sweep_stale_stage(copy: &GemCopy) -> std::io::Result<()> {
    let root = stage_root(copy);
    if is_real_dir(&root) {
        match lock_build_dir(&root) {
            Ok(_lock) => crate::patch::copy_tree::force_remove_dir_all(&root)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    // Gone with its last stage; a dir that still holds one stays.
    let _ = std::fs::remove_dir(copy.home.join(BUILD_STAGE_DIR));
    Ok(())
}

/// The stage of one rebuild from a source gem, held (an advisory lock on
/// its dir) for as long as the value lives.
struct Stage {
    root: PathBuf,
    /// The stage gem home, `<root>/home`: RubyGems unpacks, builds and
    /// installs the build's missing dependencies here, and nowhere else.
    home: PathBuf,
    _lock: Option<std::fs::File>,
}

/// Open an empty stage for `copy` inside its gem home. `Err` says why the
/// build cannot be staged there.
fn open_stage(copy: &GemCopy) -> Result<Stage, String> {
    let parent = copy.home.join(BUILD_STAGE_DIR);
    let root = stage_root(copy);
    // The stage is emptied and written under the gem home. A link planted
    // where it goes would move both somewhere else.
    for dir in [&parent, &root] {
        if std::fs::symlink_metadata(dir).is_ok_and(|meta| !meta.is_dir()) {
            return Err(format!(
                "its stage directory {} is not a directory",
                dir.display()
            ));
        }
    }
    let failed = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            recovery_refusal(copy, &e)
        } else {
            format!("a build could not be staged in {}: {e}", parent.display())
        }
    };
    sweep_stale_stage(copy).map_err(failed)?;
    let home = root.join("home");
    std::fs::create_dir_all(&home).map_err(failed)?;
    let lock = lock_build_dir(&root).map_err(failed)?;
    Ok(Stage {
        root,
        home,
        _lock: lock,
    })
}

/// Remove `stage`, and the stage dir of the gem home when that left it
/// empty. Best effort: a stage that stays is swept by the next run.
async fn close_stage(stage: Stage, copy: &GemCopy) {
    let parent = copy.home.join(BUILD_STAGE_DIR);
    crate::utils::fs::run_blocking(move || {
        let _ = crate::patch::copy_tree::force_remove_dir_all(&stage.root);
        let _ = std::fs::remove_dir(parent);
    })
    .await;
}

/// The fields after the key of every `<key>\t…` line of a Ruby run's
/// output.
fn tagged_lines<'s>(stdout: &'s str, key: &str) -> Vec<Vec<&'s str>> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            (fields.next()? == key).then(|| fields.collect())
        })
        .collect()
}

/// A source gem unpacked into a stage home.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedGem {
    /// `<stage home>/gems/<full name>`: the gem's files, as the archive
    /// packs them.
    gem_dir: PathBuf,
    /// `<stage home>/specifications/<full name>.gemspec`.
    spec_path: PathBuf,
}

/// A staged gem whose extensions RubyGems built in the stage home.
#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedBuild {
    gem: StagedGem,
    /// The extension dir the build filled:
    /// `<stage home>/extensions/<platform>/<abi>/<full name>`.
    extension_dir: PathBuf,
    /// That dir relative to the stage home.
    label: String,
}

/// Why a staged gem did not build.
#[derive(Debug)]
enum StageFailure {
    /// A gem its build scripts depend on is not installed and could not be
    /// staged beside it.
    Dependencies(String),
    /// RubyGems' builder failed: the build's diagnostic.
    Build(String),
}

/// Unpack `archive` (the source gem `source`) into `stage` with the Ruby
/// that owns the copy. The archive must be that gem and declare
/// extensions; nothing of it is run. `Err` says why it cannot be the
/// source of a rebuild.
async fn unpack_in_stage(
    copy: &GemCopy,
    probe: &Probe,
    source: &GemId,
    archive: Vec<u8>,
    stage: &Stage,
    env: &RubyEnv,
) -> Result<StagedGem, String> {
    let full_name = source.full_name();
    let path = stage.root.join(format!("{full_name}.gem"));
    {
        let path = path.clone();
        crate::utils::fs::run_blocking(move || std::fs::write(path, archive))
            .await
            .map_err(|e| format!("it could not be staged: {e}"))?;
    }
    let run = RubyRun::Unpack {
        archive: &path,
        stage_home: &stage.home,
        full_name: &full_name,
    };
    let stdout = run_ruby(&probe.ruby, run, copy, env, UNPACK_TIMEOUT).await?;
    let unpacked = tagged_lines(&stdout, "sp_unpacked")
        .into_iter()
        .any(|fields| fields.first() == Some(&full_name.as_str()));
    let staged = StagedGem {
        gem_dir: stage.home.join("gems").join(&full_name),
        spec_path: stage
            .home
            .join("specifications")
            .join(format!("{full_name}.gemspec")),
    };
    if !unpacked || !is_real_dir(&staged.gem_dir) || !staged.spec_path.is_file() {
        return Err(format!(
            "{}: unreadable unpack output",
            probe.ruby.display()
        ));
    }
    Ok(staged)
}

/// Lay the record's files over the staged source gem, with the engine that
/// patches an installed copy. Every `beforeHash` is checked against the
/// pristine gem (`Strict`, whatever the run's policy for the installed
/// copy): a mismatch means the archive is not the gem the patch was written
/// for. A file the record changes and the source gem does not pack is left
/// out when it is no build input (a platform gem's own file). `Err` is the
/// engine's reason.
async fn patch_staged_gem(
    read_scope: crate::utils::repo_root::ReadScope,
    package_key: &str,
    staged: &StagedGem,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
) -> Result<(), String> {
    let mut staged_files = files.clone();
    for (key, info) in files {
        if info.before_hash.is_empty() || scope.inputs.contains(key) {
            continue;
        }
        let path = normalize_file_path(key);
        let missing = is_safe_relative_subpath(path)
            && matches!(
                tokio::fs::symlink_metadata(staged.gem_dir.join(path)).await,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            );
        if missing {
            staged_files.remove(key);
        }
    }
    let applied = apply_package_patch(
        read_scope,
        package_key,
        &staged.gem_dir,
        &staged_files,
        sources,
        false,
        MismatchPolicy::Strict,
    )
    .await;
    if applied.success {
        Ok(())
    } else {
        Err(applied
            .error
            .unwrap_or_else(|| "the patch did not apply".to_string()))
    }
}

/// The patched content the stage is built from: the caller's in-memory
/// blobs for the record, and the bytes of every record file the installed
/// copy already holds patched. A copy whose sources an earlier run patched
/// is rebuilt from them even when their blobs are no longer on disk.
async fn stage_blobs(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    for (key, info) in files {
        if let Some(bytes) = sources.mem_blobs.and_then(|m| m.get(&info.after_hash)) {
            out.insert(info.after_hash.clone(), bytes.clone());
            continue;
        }
        let path = normalize_file_path(key);
        if !is_safe_relative_subpath(path) {
            continue;
        }
        if let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&pkg_path.join(path)).await {
            if compute_git_sha256_from_bytes(&bytes) == info.after_hash {
                out.insert(info.after_hash.clone(), bytes);
            }
        }
    }
    out
}

/// Put the gems the staged gem's build depends on, and no gem on the
/// build's `GEM_PATH` provides, into the stage home: each is the newest
/// release its requirement allows, downloaded from the gem's source and
/// verified against that source's index, then installed there by RubyGems.
/// The user's gem home is never written. `Err` names what is missing.
async fn stage_dependencies(
    copy: &GemCopy,
    probe: &Probe,
    source: &GemId,
    staged: &StagedGem,
    stage: &Stage,
    gems: &GemSource,
    env: &RubyEnv,
) -> Result<(), String> {
    let versions = probe
        .facts
        .as_ref()
        .map(RubyFacts::versions)
        .unwrap_or_default();
    let mut bases = gems.bases(source);
    let default = crate::patch::redirect::upstream::rubygems_base();
    if !bases.contains(&default) {
        bases.push(default);
    }
    let mut staged_names: Vec<String> = Vec::new();
    loop {
        let run = RubyRun::MissingDeps {
            spec: &staged.spec_path,
            stage_home: &stage.home,
        };
        let stdout = run_ruby(&probe.ruby, run, copy, env, PROBE_TIMEOUT).await?;
        if !stdout
            .lines()
            .any(|line| line.trim_end() == "sp_deps_checked")
        {
            return Err(format!(
                "{}: unreadable dependency output",
                probe.ruby.display()
            ));
        }
        let missing: Vec<(String, String)> = tagged_lines(&stdout, "sp_missing")
            .into_iter()
            .filter_map(|fields| Some((fields.first()?.to_string(), fields.get(1)?.to_string())))
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        for (name, requirement) in missing {
            let needed =
                format!("its build needs the gem {name} ({requirement}), which is not installed");
            if gems.offline() {
                return Err(format!("{needed}, and this run is offline"));
            }
            // Staged a moment ago and still missing: installing it again
            // would loop.
            if staged_names.contains(&name) || staged_names.len() >= MAX_STAGED_DEPENDENCIES {
                return Err(format!("{needed} and could not be staged for the build"));
            }
            let (id, bytes) = gems
                .dependency(&bases, &name, &requirement, &versions)
                .await
                .map_err(|why| format!("{needed} and could not be downloaded ({why})"))?;
            let archive = stage.root.join(format!("{}.gem", id.full_name()));
            {
                let archive = archive.clone();
                crate::utils::fs::run_blocking(move || std::fs::write(archive, bytes))
                    .await
                    .map_err(|e| format!("{needed} and could not be staged ({e})"))?;
            }
            let run = RubyRun::Install {
                archive: &archive,
                stage_home: &stage.home,
            };
            let stdout = run_ruby(&probe.ruby, run, copy, env, BUILD_TIMEOUT)
                .await
                .map_err(|why| format!("{needed} and did not install into the stage:\n{why}"))?;
            if parse_installed(&stdout).is_none_or(|(full_name, _)| full_name != id.full_name()) {
                return Err(format!("{needed} and did not install into the stage"));
            }
            staged_names.push(name);
        }
    }
}

/// Build the staged gem's extensions inside the stage home, with the Ruby
/// that owns the copy and the build arguments RubyGems recorded for it.
/// Nothing of the installed copy is touched.
async fn build_staged(
    copy: &GemCopy,
    probe: &Probe,
    source: &GemId,
    staged: StagedGem,
    stage: &Stage,
    gems: &GemSource,
    env: &RubyEnv,
) -> Result<StagedBuild, StageFailure> {
    stage_dependencies(copy, probe, source, &staged, stage, gems, env)
        .await
        .map_err(StageFailure::Dependencies)?;
    let run = RubyRun::StageBuild {
        spec: &staged.spec_path,
        stage_home: &stage.home,
    };
    let stdout = run_ruby(&probe.ruby, run, copy, env, BUILD_TIMEOUT)
        .await
        .map_err(StageFailure::Build)?;
    let built = tagged_lines(&stdout, "sp_built")
        .into_iter()
        .find_map(|fields| fields.first().map(PathBuf::from))
        .ok_or_else(|| {
            StageFailure::Build(format!("{}: unreadable build output", probe.ruby.display()))
        })?;
    // The one dir RubyGems builds this gem into, inside the stage home.
    let label = ext_dir_label(&stage.home, &built);
    let parts: Vec<&str> = label.split('/').collect();
    let confined = parts.len() == 4
        && parts[0] == "extensions"
        && parts[3] == source.full_name()
        && is_safe_relative_subpath(&label);
    let extension_dir = stage.home.join(&label);
    if !confined || !extension_dir.join(BUILD_COMPLETE).is_file() {
        return Err(StageFailure::Build(format!(
            "the build exited cleanly but left no finished extension in the stage ({})",
            built.display()
        )));
    }
    Ok(StagedBuild {
        gem: staged,
        extension_dir,
        label,
    })
}

/// Move the tree `from` to `to` (which is not there): a rename on one
/// filesystem, a copy across two.
fn move_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => copy_tree_sync(from, to),
    }
}

/// A regular file, not a symlink to one.
fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Replace `dst` with the bytes of the regular file `src` ([`replace_file`]),
/// with `mode`'s permissions, or `src`'s when there is none to keep.
fn replace_with_file(
    src: &Path,
    dst: &Path,
    mode: Option<std::fs::Permissions>,
) -> std::io::Result<()> {
    let bytes = read_regular_to_bytes_sync(src)?;
    let perms = match mode {
        Some(perms) => perms,
        None => std::fs::metadata(src)?.permissions(),
    };
    replace_file(dst, |stage| {
        std::fs::write(stage, &bytes)?;
        std::fs::set_permissions(stage, perms)
    })
}

/// Put a staged build in the place of the installed copy's: the staged
/// extension dir becomes the copy's, and the `lib/` copies RubyGems made of
/// its artifacts in the stage replace the installed ones. The original
/// build is backed up first (`back_up`: with the record's files the copy
/// did not hold), the current one is parked while the new one moves in, and
/// the marker records the result, exactly as an in-place [`rebuild`] leaves
/// them. On failure the previous build is put back.
fn install_staged_build(
    copy: &GemCopy,
    probe: &Probe,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
    staged: &StagedBuild,
    back_up: Option<&[String]>,
) -> Result<(), String> {
    // The stage was built by the Ruby that owns the copy, so both name the
    // same `extensions/<platform>/<abi>/<full_name>`.
    if staged.label != ext_dir_label(&copy.home, &probe.extension_dir) {
        return Err(format!(
            "the staged build is in {}, not the installed extension's {}",
            staged.label,
            probe.extension_dir.display()
        ));
    }
    let made_backup = match back_up {
        Some(absent) => back_up_original(copy, probe, absent)
            .map_err(|e| format!("could not back up the original extension build: {e}"))?,
        None => false,
    };
    let drop_new_backup = || {
        if made_backup {
            let _ = remove_dir_if_exists(&copy.gem_dir.join(BACKUP_DIR));
        }
    };
    let aside = match set_aside(copy, probe) {
        Ok(aside) => aside,
        Err(e) => {
            drop_new_backup();
            return Err(format!(
                "could not move the current extension build aside: {e}"
            ));
        }
    };
    let moved_in = (|| -> std::io::Result<()> {
        move_tree(&staged.extension_dir, &probe.extension_dir)?;
        for rel in artifact_rels(&probe.extension_dir) {
            let Some(lib) = lib_rel(probe, &rel) else {
                continue;
            };
            // RubyGems copies an artifact under the require dir unless
            // `Gem.install_extension_in_lib` is off: the staged gem shows
            // which it did.
            if is_real_file(&staged.gem.gem_dir.join(&lib)) {
                replace_with_file(
                    &probe.extension_dir.join(&rel),
                    &copy.gem_dir.join(&lib),
                    None,
                )?;
            }
        }
        commit_build(copy, probe, scope, files, &aside)
    })();
    let Err(error) = moved_in else {
        return Ok(());
    };
    match put_back(copy, probe, aside) {
        Ok(()) => {
            drop_new_backup();
            Err(format!(
                "the rebuilt extension could not be moved into place: {error}"
            ))
        }
        Err(e) => Err(format!(
            "the rebuilt extension could not be moved into place: {error}\n(the previous build \
             could not be put back: {e}; run `gem pristine {} --extensions` to rebuild it)",
            gem_name_of(&copy.full_name)
        )),
    }
}

/// One prebuilt binary of a precompiled copy, and the staged artifact that
/// replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Graft {
    staged: PathBuf,
    /// The prebuilt binary, relative to the gem dir
    /// (`lib/nokogiri/3.4/nokogiri.bundle`).
    target: String,
}

/// Every regular file named `leaf` under `dir`, as paths relative to
/// `base`, `/`-separated. Symlinks are not followed.
fn files_named(dir: &Path, leaf: &str, base: &Path) -> Vec<String> {
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .flatten()
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == leaf)
        .filter_map(|entry| {
            let rel = entry.path().strip_prefix(base).ok()?;
            Some(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        })
        .collect()
}

/// Match every extension the staged build produced to the prebuilt binary
/// of `copy` that Ruby loads in its place.
///
/// A precompiled gem keeps one binary per Ruby minor in the rake-compiler
/// layout, `<require path>/<dir>/<major.minor>/<file>` (nokogiri's
/// `lib/nokogiri/3.4/nokogiri.bundle`, sqlite3's
/// `lib/sqlite3/3.3/sqlite3_native.so`), where a source build has
/// `<dir>/<file>`; the building Ruby's minor picks the one. A gem that
/// keeps a single binary elsewhere is matched by its file name when exactly
/// one file under the require path has it. `Err` when an extension has no
/// counterpart, or more than one: grafting on a guess would leave Ruby
/// loading the old code.
fn plan_graft(copy: &GemCopy, probe: &Probe, staged: &StagedBuild) -> Result<Vec<Graft>, String> {
    let facts = probe
        .facts
        .as_ref()
        .ok_or_else(|| format!("{} did not say which Ruby it is", probe.ruby.display()))?;
    let minor = facts.minor().ok_or_else(|| {
        format!(
            "{} reports the Ruby version {:?}",
            probe.ruby.display(),
            facts.ruby_version
        )
    })?;
    let built: Vec<String> = artifact_rels(&staged.extension_dir)
        .into_iter()
        .filter(|rel| {
            rel.rsplit_once('.')
                .is_some_and(|(_, ext)| ext == facts.dlext)
        })
        .collect();
    if built.is_empty() {
        return Err(format!(
            "the source gem's build left no .{} extension to replace a prebuilt one with",
            facts.dlext
        ));
    }
    let gem_root = canonical(&copy.gem_dir);
    let mut grafts: Vec<Graft> = Vec::new();
    for rel in built {
        let (dir, leaf) = match rel.rsplit_once('/') {
            Some((dir, leaf)) => (format!("{dir}/"), leaf),
            None => (String::new(), rel.as_str()),
        };
        let exact = format!("{}/{dir}{minor}/{leaf}", probe.require_path);
        let target = if is_real_file(&copy.gem_dir.join(&exact)) {
            exact
        } else {
            let mut named = files_named(&probe.lib_dir, leaf, &copy.gem_dir);
            match named.len() {
                1 => named.remove(0),
                0 => {
                    return Err(format!(
                        "the gem ships no prebuilt {leaf} for Ruby {minor} ({exact} is not there)"
                    ))
                }
                _ => {
                    return Err(format!(
                        "the gem ships no prebuilt {leaf} for Ruby {minor} ({exact} is not \
                         there), only {}",
                        named.join(", ")
                    ))
                }
            }
        };
        // Inside the gem dir, whatever links its tree holds.
        let confined = is_safe_relative_subpath(&target)
            && match (&gem_root, canonical(&copy.gem_dir.join(&target))) {
                (Some(root), Some(path)) => path.starts_with(root),
                _ => false,
            };
        if !confined || grafts.iter().any(|g| g.target == target) {
            return Err(format!(
                "the prebuilt binary {target} cannot be told apart from another file to replace"
            ));
        }
        grafts.push(Graft {
            staged: staged.extension_dir.join(&rel),
            target,
        });
    }
    Ok(grafts)
}

/// Back up the prebuilt binaries a graft is about to replace to
/// [`BACKUP_DIR`], with the record's files the copy never shipped
/// (`absent`), unless a backup exists or the current binaries are
/// socket-patch's (a marker exists). An existing backup learns of `absent`
/// files it does not list. `Ok(true)` when this call made the backup.
fn back_up_prebuilt(copy: &GemCopy, grafts: &[Graft], absent: &[String]) -> std::io::Result<bool> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    if std::fs::symlink_metadata(&backup).is_ok() {
        note_absent_files(&backup, absent)?;
        return Ok(false);
    }
    if std::fs::symlink_metadata(copy.gem_dir.join(MARKER_FILE)).is_ok() {
        return Ok(false);
    }
    let stage = copy.gem_dir.join(format!("{BACKUP_DIR}.tmp"));
    remove_dir_if_exists(&stage)?;
    std::fs::create_dir_all(&stage)?;
    let mut lib_files = Vec::new();
    for graft in grafts {
        let src = copy.gem_dir.join(&graft.target);
        let dst = stage.join("lib").join(&graft.target);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dst, read_regular_to_bytes_sync(&src)?)?;
        std::fs::set_permissions(&dst, std::fs::symlink_metadata(&src)?.permissions())?;
        lib_files.push(graft.target.clone());
    }
    let info = BackupInfo {
        lib_files,
        grafted: true,
        absent_files: absent.to_vec(),
        ..BackupInfo::default()
    };
    write_backup_info(&stage, &info)?;
    std::fs::rename(&stage, &backup)?;
    Ok(true)
}

/// Replace each prebuilt binary with the staged build's ([`replace_file`]:
/// a Ruby that has the old one mapped keeps its pages), then record the
/// marker that attests them. A step that fails puts every binary back as
/// it was.
fn graft_binaries(
    copy: &GemCopy,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
    grafts: &[Graft],
) -> std::io::Result<()> {
    let mut previous: Vec<LibSnapshot> = Vec::new();
    for graft in grafts {
        let path = copy.gem_dir.join(&graft.target);
        let perms = std::fs::symlink_metadata(&path)?.permissions();
        previous.push((
            graft.target.clone(),
            read_regular_to_bytes_sync(&path)?,
            perms,
        ));
    }
    let grafted = (|| -> std::io::Result<()> {
        let mut marker = BuildMarker {
            schema: GRAFT_MARKER_SCHEMA,
            grafted: true,
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
        for (graft, (_, _, perms)) in grafts.iter().zip(&previous) {
            let path = copy.gem_dir.join(&graft.target);
            replace_with_file(&graft.staged, &path, Some(perms.clone()))?;
            marker
                .lib_artifacts
                .insert(graft.target.clone(), compute_file_git_sha256_sync(&path)?);
        }
        write_marker(copy, &marker)
    })();
    if grafted.is_err() {
        for (target, bytes, perms) in &previous {
            let _ = replace_file(&copy.gem_dir.join(target), |stage| {
                std::fs::write(stage, bytes)?;
                std::fs::set_permissions(stage, perms.clone())
            });
        }
    }
    grafted
}

/// The record as the installed copy takes it. A build input the copy does
/// not hold is added to it, whatever content the record says it replaces:
/// the source gem packs files an installed copy lacks (a precompiled gem
/// never shipped nokogiri's `patches/**`; a build deletes its `ports/**`
/// once it is done). That content is checked where it exists, in the
/// source gem the extension is rebuilt from ([`patch_staged_gem`]), so the
/// result is only used for a rebuild from that gem. Returns the record so
/// adjusted and the (normalized) paths it adds.
async fn files_as_installed(
    copy: &GemCopy,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
) -> (HashMap<String, PatchFileInfo>, Vec<String>) {
    let mut out = files.clone();
    let mut absent = Vec::new();
    for key in &scope.inputs {
        let Some(info) = out.get_mut(key).filter(|i| !i.before_hash.is_empty()) else {
            continue;
        };
        let path = normalize_file_path(key);
        let missing = is_safe_relative_subpath(path)
            && matches!(
                tokio::fs::symlink_metadata(copy.gem_dir.join(path)).await,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            );
        if missing {
            info.before_hash.clear();
            absent.push(path.to_string());
        }
    }
    (out, absent)
}

/// The record's files as `rollback` undoes them on the gem copy at
/// `pkg_path`. A build input `apply` added to a copy that did not hold it
/// ([`files_as_installed`]; the copy's backup lists them) is removed, not
/// restored to the content it has in the source gem. Any other copy:
/// `files` as they are.
pub async fn rollback_files(
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> HashMap<String, PatchFileInfo> {
    let mut out = files.clone();
    let Some(copy) = GemCopy::of(pkg_path) else {
        return out;
    };
    let info = crate::utils::fs::run_blocking(move || {
        let backup = copy.gem_dir.join(BACKUP_DIR);
        if is_symlink(&backup) {
            return None;
        }
        let bytes = read_regular_to_bytes_sync(&backup.join(BACKUP_INFO)).ok()?;
        serde_json::from_slice::<BackupInfo>(&bytes).ok()
    })
    .await;
    let Some(info) = info else {
        return out;
    };
    for (key, file) in out.iter_mut() {
        if info
            .absent_files
            .iter()
            .any(|path| path == normalize_file_path(key))
        {
            file.before_hash.clear();
        }
    }
    out
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

/// [`apply_package_patch`] over a gem copy, with no warning of its own.
async fn plain_apply(
    read_scope: crate::utils::repo_root::ReadScope,
    package_key: &str,
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
    sources: &PatchSources<'_>,
    dry_run: bool,
    policy: MismatchPolicy,
) -> GemApplied {
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
}

/// One gem copy's record, verified against the copy and about to be built.
struct Job<'a> {
    read_scope: crate::utils::repo_root::ReadScope,
    package_key: &'a str,
    pkg_path: &'a Path,
    /// The record's files.
    files: &'a HashMap<String, PatchFileInfo>,
    /// The record as the installed copy takes it
    /// ([`files_as_installed`]).
    installed_files: &'a HashMap<String, PatchFileInfo>,
    sources: &'a PatchSources<'a>,
    policy: MismatchPolicy,
    env: &'a RubyEnv,
    copy: &'a GemCopy,
    scope: &'a NativeScope,
    /// [`list_inputs`] of the scope, for the messages.
    inputs: &'a str,
}

impl Job<'_> {
    fn refuse(&self, code: &str, detail: String) -> GemApplied {
        refusal(self.package_key, self.pkg_path, code, detail)
    }

    /// The bytes each record file holds now, to put back if what follows
    /// fails.
    async fn originals(&self) -> Vec<(String, Option<Vec<u8>>)> {
        let keys: Vec<String> = self.files.keys().cloned().collect();
        let dir = self.pkg_path.to_path_buf();
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
    }

    /// Write the record's patched files into the installed copy. A write
    /// that fails is undone here: the result then lists nothing as patched.
    async fn write_sources(&self, originals: &[(String, Option<Vec<u8>>)]) -> ApplyResult {
        let mut result = apply_package_patch(
            self.read_scope,
            self.package_key,
            self.pkg_path,
            self.installed_files,
            self.sources,
            false,
            self.policy,
        )
        .await;
        if !result.success {
            revert_sources(self.pkg_path, originals, &result.files_patched).await;
            result.files_patched.clear();
            result.applied_via.clear();
        }
        result
    }

    /// The outcome of a copy whose sources are written and whose compiled
    /// code was built from them.
    fn built(&self, result: ApplyResult) -> GemApplied {
        let warning = result.files_patched.is_empty().then(|| {
            (
                REBUILT_CODE.to_string(),
                format!(
                    "{}: its native extension was rebuilt from sources an earlier run \
                     patched without rebuilding ({})",
                    self.package_key, self.inputs
                ),
            )
        });
        GemApplied { result, warning }
    }

    /// The outcome of a copy that is as it was before the run, because
    /// `detail` (a [`BUILD_FAILED_CODE`] failure).
    async fn not_built(
        &self,
        mut result: ApplyResult,
        originals: &[(String, Option<Vec<u8>>)],
        detail: String,
    ) -> GemApplied {
        revert_sources(self.pkg_path, originals, &result.files_patched).await;
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

/// The remedy a refusal names for a gem RubyGems built at install time:
/// hosted mode installs the patched ruby-platform gem.
const HOSTED_HINT: &str = "Use `socket-patch scan --mode hosted`, which installs the patched gem \
                           through Bundler so RubyGems compiles it.";

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
    if scope.inputs.is_empty() {
        return plain_apply(
            read_scope,
            package_key,
            pkg_path,
            files,
            sources,
            dry_run,
            policy,
        )
        .await;
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
        let mut applied = plain_apply(
            read_scope,
            package_key,
            pkg_path,
            files,
            sources,
            dry_run,
            policy,
        )
        .await;
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
    let Some(copy) = copy else {
        return refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), but {} is not a \
                 RubyGems install with a specification to rebuild the extension from; \
                 nothing was written. {HOSTED_HINT}",
                pkg_path.display()
            ),
        );
    };
    if !scope.builds_extensions && scope.precompiled.is_none() {
        return refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), but the installed gem \
                 builds no extension at install time and is not a precompiled platform gem, \
                 so nothing here compiles them and they cannot take effect; nothing was \
                 written."
            ),
        );
    }
    if let Some(platform) = scope.precompiled.as_deref().filter(|p| is_java_platform(p)) {
        return refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), but the installed gem \
                 is the JRuby build ({platform}), whose compiled code ships as jars built from \
                 Java sources; they cannot be rebuilt from the source gem here, so the patch \
                 cannot take effect; nothing was written."
            ),
        );
    }
    let precompiled = scope.precompiled.is_some();
    let (installed_files, absent) = files_as_installed(&copy, &scope, files).await;

    // Already patched and built from these sources: nothing to do.
    let built = {
        let (copy, scope, files) = (copy.clone(), scope.clone(), files.clone());
        crate::utils::fs::run_blocking(move || {
            read_marker_sync(&copy.gem_dir).is_some_and(|m| marker_holds(&m, &copy, &scope, &files))
        })
        .await
    };
    if built {
        return plain_apply(
            read_scope,
            package_key,
            pkg_path,
            &installed_files,
            sources,
            dry_run,
            policy,
        )
        .await;
    }

    // A gem RubyGems built can also be installed patched through hosted
    // mode; a precompiled one cannot (hosted mode refuses platform gems).
    let hint = if precompiled {
        String::new()
    } else {
        format!(" {HOSTED_HINT}")
    };
    let unbuildable = |why: String| {
        refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), which only take \
                 effect once the extension is rebuilt, and it cannot be rebuilt here: \
                 {why}; nothing was written.{hint}"
            ),
        )
    };
    // What files alone tell: a build to replace and a Ruby to try.
    let preflight = if precompiled {
        graft_preflight(&copy, env).await
    } else {
        rebuild_preflight(&copy, env).await
    };
    let preflight = match preflight {
        Ok(p) => p,
        Err(why) => return unbuildable(why),
    };
    // A precompiled gem's extension can only be rebuilt from the source gem
    // of its version. Without that archive in the gem home's cache and
    // without the network, files alone tell there is no way to it.
    let gems = GemSource::of(&env.cwd, env.offline).await;
    let source = scope.source_gem();
    let needs_source_gem = |source: Option<&GemId>, why: String, missing: bool| {
        let archive = match source {
            Some(source) => format!("{}.gem", source.full_name()),
            None => "its ruby-platform gem".to_string(),
        };
        let remedy = if missing {
            format!(
                " Run `socket-patch apply` once with network access to the gem's source, or \
                 put {archive} in {}.",
                copy.home.join("cache").display()
            )
        } else {
            String::new()
        };
        refusal(
            package_key,
            pkg_path,
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}) of the precompiled gem \
                 {}, which only take effect once its extension is rebuilt from the source gem \
                 ({archive}), and that cannot be done here: {why}; nothing was written.{remedy}",
                copy.full_name
            ),
        )
    };
    if precompiled {
        let Some(source) = &source else {
            return needs_source_gem(
                None,
                format!(
                    "{} does not name the gem and version it was installed from",
                    copy.spec_path.display()
                ),
                false,
            );
        };
        if !gems.may_have(&copy.home, source).await {
            return needs_source_gem(
                Some(source),
                format!(
                    "{} is not there and this run is offline",
                    crate::patch::gem_source::cache_path(&copy.home, source).display()
                ),
                true,
            );
        }
    }

    // So can a gem RubyGems built, when the record changes an input its
    // build removed from the installed copy.
    if !precompiled && !absent.is_empty() {
        let reachable = match &source {
            Some(source) => gems.may_have(&copy.home, source).await,
            None => false,
        };
        if !reachable {
            let why = "its archive is not in the gem home's cache and this run is offline";
            return refusal(
                package_key,
                pkg_path,
                UNSUPPORTED_CODE,
                absent_inputs_detail(&inputs, &absent, &copy, why),
            );
        }
    }

    // No program runs until the record's files verify against this copy:
    // until then nothing says the tree is the package the patch is for.
    // The pass writes nothing, and a dry run ends with it.
    let verified = apply_package_patch(
        read_scope,
        package_key,
        pkg_path,
        &installed_files,
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
        let parked = !precompiled
            && preflight
                .installed
                .iter()
                .any(|dir| is_real_dir(&parked_build_path(dir)));
        let unfinished = if parked {
            "; an earlier rebuild did not finish, and apply first puts back the build it parked"
        } else {
            ""
        };
        let detail = match (all_patched, precompiled) {
            (true, false) => format!(
                "{package_key}: dry run: its sources are already patched, but its native \
                 extension was not built from them ({inputs}); apply would rebuild \
                 it{unfinished}"
            ),
            (false, false) => format!(
                "{package_key}: dry run: apply would write its patched sources and rebuild \
                 its native extension from them ({inputs}); no Ruby was run to check that \
                 it can{unfinished}"
            ),
            (true, true) => format!(
                "{package_key}: dry run: its sources are already patched, but the gem's \
                 precompiled extension was not built from them ({inputs}); apply would \
                 rebuild it from the source gem and replace the prebuilt binary with that \
                 build"
            ),
            (false, true) => format!(
                "{package_key}: dry run: apply would write its patched sources, rebuild its \
                 native extension from the source gem and replace the gem's prebuilt binary \
                 with that build ({inputs}); no Ruby was run and nothing was downloaded to \
                 check that it can"
            ),
        };
        return GemApplied {
            result: verified,
            warning: Some((REBUILT_CODE.to_string(), detail)),
        };
    }

    let found = match &scope.precompiled {
        Some(platform) => find_platform_ruby(&copy, env, preflight, platform).await,
        None => find_ruby(&copy, env, preflight).await,
    };
    let probe = match found {
        Ok(p) => p,
        Err(why) => return unbuildable(why),
    };
    let job = Job {
        read_scope,
        package_key,
        pkg_path,
        files,
        installed_files: &installed_files,
        sources,
        policy,
        env,
        copy: &copy,
        scope: &scope,
        inputs: &inputs,
    };

    // The source gem holds every build input, where the installed copy may
    // not (a build deletes what it no longer needs; a precompiled gem never
    // shipped them): the extension is rebuilt from it when it can be had.
    let archive = match &source {
        Some(source) => gems.archive(&copy.home, source).await,
        None => Err(format!(
            "{} does not name the gem and version it was installed from",
            copy.spec_path.display()
        )),
    };
    match (archive, &source) {
        (Ok(archive), Some(source)) => {
            match rebuild_from_source_gem(&job, &probe, source, archive, &gems, &absent).await {
                Ok(applied) => applied,
                Err(why) if precompiled => needs_source_gem(Some(source), why, false),
                // Not an archive this copy can be rebuilt from: its own
                // tree is what is left to build.
                Err(why) => rebuild_in_place(&job, &probe, &absent, &why).await,
            }
        }
        (Err(why), _) if precompiled => needs_source_gem(source.as_ref(), why, true),
        (Err(why), _) => rebuild_in_place(&job, &probe, &absent, &why).await,
        (Ok(_), None) => {
            let why = "its gemspec does not name the gem it was installed from";
            rebuild_in_place(&job, &probe, &absent, why).await
        }
    }
}

/// The refusal of a record that changes build inputs the installed copy of
/// a gem RubyGems built no longer holds (`absent`), when the source gem
/// that packs them cannot be had (`why`).
fn absent_inputs_detail(inputs: &str, absent: &[String], copy: &GemCopy, why: &str) -> String {
    format!(
        "the patch changes native-extension sources ({inputs}), and the installed gem does not \
         hold {} (a build removes what it is done with), so the extension can only be rebuilt \
         from the source gem, which could not be had: {why}; nothing was written. Run \
         `socket-patch apply` once with network access to the gem's source, or put the gem's \
         archive in {}.",
        absent.join(", "),
        copy.home.join("cache").display()
    )
}

/// Write the patched sources and rebuild the extension from the installed
/// copy's own tree ([`rebuild`]): what is left when its source gem cannot
/// be had (`no_source_gem` says why). A failed build puts the sources and
/// the previous build back. A record that changes a build input the copy
/// no longer holds (`absent`) cannot be built this way: nothing here has
/// the file's content to check the record against.
async fn rebuild_in_place(
    job: &Job<'_>,
    probe: &Probe,
    absent: &[String],
    no_source_gem: &str,
) -> GemApplied {
    if !absent.is_empty() {
        return job.refuse(
            UNSUPPORTED_CODE,
            absent_inputs_detail(job.inputs, absent, job.copy, no_source_gem),
        );
    }
    let originals = job.originals().await;
    let result = job.write_sources(&originals).await;
    if !result.success {
        return GemApplied {
            result,
            warning: None,
        };
    }
    match rebuild(job.copy, probe, job.scope, job.files, job.env, true).await {
        Ok(()) => job.built(result),
        Err(diagnostic) => {
            let detail = format!(
                "the native extension did not build from the patched sources ({}); the \
                 sources and the previous build were put back. Install a compiler toolchain \
                 and the Ruby headers and apply again, or use `socket-patch scan --mode \
                 hosted`.\n{diagnostic}",
                job.inputs
            );
            job.not_built(result, &originals, detail).await
        }
    }
}

/// Rebuild the copy's extension from its source gem (`archive`, the gem
/// `source`), with the record's files laid over it in a stage, and put the
/// build in the installed copy's place. The installed copy is not touched
/// until the build has finished. `Err` when the archive is not one the
/// copy can be rebuilt from (it is another gem, or declares no
/// extensions): nothing was built or written.
async fn rebuild_from_source_gem(
    job: &Job<'_>,
    probe: &Probe,
    source: &GemId,
    archive: Vec<u8>,
    gems: &GemSource,
    absent: &[String],
) -> Result<GemApplied, String> {
    let stage = {
        let copy = job.copy.clone();
        crate::utils::fs::run_blocking(move || open_stage(&copy)).await
    };
    let stage = match stage {
        Ok(stage) => stage,
        Err(why) => {
            return Ok(job.refuse(
                UNSUPPORTED_CODE,
                format!(
                    "the patch changes native-extension sources ({}), which only take effect \
                     once the extension is rebuilt, and it cannot be rebuilt here: {why}; \
                     nothing was written.",
                    job.inputs
                ),
            ))
        }
    };
    let outcome = rebuild_in_stage(job, probe, source, archive, gems, absent, &stage).await;
    close_stage(stage, job.copy).await;
    outcome
}

/// [`rebuild_from_source_gem`], inside its open stage.
async fn rebuild_in_stage(
    job: &Job<'_>,
    probe: &Probe,
    source: &GemId,
    archive: Vec<u8>,
    gems: &GemSource,
    absent: &[String],
    stage: &Stage,
) -> Result<GemApplied, String> {
    let (copy, inputs) = (job.copy, job.inputs);
    let staged = unpack_in_stage(copy, probe, source, archive, stage, job.env).await?;
    // The record over the pristine source gem, before anything runs.
    let blobs = stage_blobs(job.pkg_path, job.files, job.sources).await;
    let staged_sources = PatchSources {
        blobs_path: job.sources.blobs_path,
        mem_blobs: Some(&blobs),
    };
    let patched = patch_staged_gem(
        job.read_scope,
        job.package_key,
        &staged,
        job.scope,
        job.files,
        &staged_sources,
    )
    .await;
    if let Err(why) = patched {
        return Ok(job.refuse(
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}), which only take \
                 effect once the extension is rebuilt from the source gem ({}.gem), and the \
                 patch does not apply to that gem: {why}; nothing was written.",
                source.full_name()
            ),
        ));
    }
    let built = match build_staged(copy, probe, source, staged, stage, gems, job.env).await {
        Ok(built) => built,
        Err(StageFailure::Dependencies(why)) => {
            return Ok(job.refuse(
                UNSUPPORTED_CODE,
                format!(
                    "the patch changes native-extension sources ({inputs}), which only take \
                     effect once the extension is rebuilt, and it cannot be rebuilt here: \
                     {why}; nothing was written."
                ),
            ))
        }
        Err(StageFailure::Build(diagnostic)) => {
            let detail = format!(
                "the native extension did not build from the patched sources ({inputs}); \
                 nothing of the installed gem was changed. Install a compiler toolchain and \
                 the Ruby headers and apply again.\n{diagnostic}"
            );
            return Ok(job.refuse(BUILD_FAILED_CODE, detail));
        }
    };

    if job.scope.precompiled.is_some() {
        return Ok(graft_into_copy(job, probe, &built, absent).await);
    }
    // A gem RubyGems built: its sources are written in place, and the
    // staged build takes the place of its extension dir.
    let originals = job.originals().await;
    let result = job.write_sources(&originals).await;
    if !result.success {
        return Ok(GemApplied {
            result,
            warning: None,
        });
    }
    let installed = {
        let (copy, probe, scope) = (copy.clone(), probe.clone(), job.scope.clone());
        let (files, built, absent) = (job.files.clone(), built.clone(), absent.to_vec());
        crate::utils::fs::run_blocking(move || {
            install_staged_build(&copy, &probe, &scope, &files, &built, Some(&absent))
        })
        .await
    };
    Ok(match installed {
        Ok(()) => job.built(result),
        Err(why) => {
            let detail = format!(
                "the native extension was rebuilt from the patched sources ({inputs}), but \
                 {why}; the sources and the previous build were put back."
            );
            job.not_built(result, &originals, detail).await
        }
    })
}

/// Put a staged build into a precompiled copy: the record's files are
/// written into the copy, and each prebuilt binary Ruby loads is replaced
/// by the build's ([`plan_graft`]), after the originals are backed up. A
/// step that fails leaves the copy as it was.
async fn graft_into_copy(
    job: &Job<'_>,
    probe: &Probe,
    built: &StagedBuild,
    absent: &[String],
) -> GemApplied {
    let (copy, inputs) = (job.copy, job.inputs);
    let planned = {
        let (copy, probe, built) = (copy.clone(), probe.clone(), built.clone());
        crate::utils::fs::run_blocking(move || plan_graft(&copy, &probe, &built)).await
    };
    let unplaceable = |why: String| {
        job.refuse(
            UNSUPPORTED_CODE,
            format!(
                "the patch changes native-extension sources ({inputs}) of the precompiled gem \
                 {}, and its extension was rebuilt from the source gem, but the build cannot \
                 take the place of the gem's prebuilt binary: {why}; nothing was written.",
                copy.full_name
            ),
        )
    };
    let grafts = match planned {
        Ok(grafts) => grafts,
        Err(why) => return unplaceable(why),
    };
    let made_backup = {
        let (copy, grafts, absent) = (copy.clone(), grafts.clone(), absent.to_vec());
        crate::utils::fs::run_blocking(move || back_up_prebuilt(&copy, &grafts, &absent)).await
    };
    let made_backup = match made_backup {
        Ok(made) => made,
        Err(e) => {
            let stage = copy.gem_dir.join(format!("{BACKUP_DIR}.tmp"));
            let _ = crate::utils::fs::run_blocking(move || remove_dir_if_exists(&stage)).await;
            return unplaceable(format!("the prebuilt binary could not be backed up ({e})"));
        }
    };
    let drop_new_backup = || async {
        if made_backup {
            let backup = copy.gem_dir.join(BACKUP_DIR);
            let _ = crate::utils::fs::run_blocking(move || remove_dir_if_exists(&backup)).await;
        }
    };
    let originals = job.originals().await;
    let result = job.write_sources(&originals).await;
    if !result.success {
        drop_new_backup().await;
        return GemApplied {
            result,
            warning: None,
        };
    }
    let grafted = {
        let (copy, scope) = (copy.clone(), job.scope.clone());
        let (files, grafts) = (job.files.clone(), grafts.clone());
        crate::utils::fs::run_blocking(move || graft_binaries(&copy, &scope, &files, &grafts)).await
    };
    match grafted {
        Ok(()) => job.built(result),
        Err(e) => {
            drop_new_backup().await;
            let detail = format!(
                "the native extension was rebuilt from the patched sources ({inputs}), but \
                 the build could not replace the gem's prebuilt binary ({e}); the sources and \
                 the prebuilt binary were put back."
            );
            job.not_built(result, &originals, detail).await
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
/// restored whenever it exists: it is this gem version's install-time build
/// (for a precompiled copy, the prebuilt binaries the gem shipped), right
/// whether the current build is socket-patch's (marker present) or one
/// whose marker never got written. Without a backup, a copy carrying a
/// socket-patch build (a marker) is rebuilt from the restored sources: from
/// its source gem when that can be had, else in place. A precompiled copy
/// without its backup is not rebuilt (that would not give the prebuilt
/// binaries back): the error names `gem pristine`, which reinstalls them.
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
    let Some(marker) = marker else {
        return Ok(recovered);
    };
    if marker.grafted {
        return Err(format!(
            "the gem's prebuilt binary still holds the patched build, and the backup of the \
             original is gone; run `gem pristine {}` to reinstall the gem as it shipped",
            gem_name_of(&copy.full_name)
        ));
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
    let rebuilt = match rebuild_unpatched_from_source_gem(&copy, &probe, env).await {
        Some(rebuilt) => rebuilt,
        None => {
            let scope = NativeScope::default();
            rebuild(&copy, &probe, &scope, &HashMap::new(), env, false).await
        }
    };
    rebuilt.map_err(|diagnostic| {
        format!(
            "the extension did not rebuild from the restored sources; run `gem pristine \
             {} --extensions`.\n{diagnostic}",
            gem_name_of(&copy.full_name)
        )
    })?;
    let _ = tokio::fs::remove_file(copy.gem_dir.join(MARKER_FILE)).await;
    Ok(true)
}

/// Rebuild `copy`'s extension from its source gem as it shipped (no record
/// over it), for a rollback that has no backup of the original build.
/// `None` when the source gem cannot be had or used: the in-place rebuild
/// is what is left.
async fn rebuild_unpatched_from_source_gem(
    copy: &GemCopy,
    probe: &Probe,
    env: &RubyEnv,
) -> Option<Result<(), String>> {
    let spec_text = crate::utils::fs::read_regular_to_string(&copy.spec_path)
        .await
        .ok()?;
    let facts = SpecFacts::of(&spec_text, &copy.full_name);
    let source = facts.release.filter(|_| facts.extensions.declared)?;
    let gems = GemSource::of(&env.cwd, env.offline).await;
    let archive = gems.archive(&copy.home, &source).await.ok()?;
    let stage = {
        let copy = copy.clone();
        crate::utils::fs::run_blocking(move || open_stage(&copy)).await
    };
    let stage = match stage {
        Ok(stage) => stage,
        Err(why) => return Some(Err(why)),
    };
    let outcome = async {
        let staged = unpack_in_stage(copy, probe, &source, archive, &stage, env)
            .await
            .ok()?;
        let built = match build_staged(copy, probe, &source, staged, &stage, &gems, env).await {
            Ok(built) => built,
            Err(StageFailure::Dependencies(why) | StageFailure::Build(why)) => {
                return Some(Err(why))
            }
        };
        let (copy, probe) = (copy.clone(), probe.clone());
        Some(
            crate::utils::fs::run_blocking(move || {
                let scope = NativeScope::default();
                install_staged_build(&copy, &probe, &scope, &HashMap::new(), &built, None)
            })
            .await,
        )
    }
    .await;
    close_stage(stage, copy).await;
    outcome
}

/// Put the backed-up original build back over socket-patch's build, then
/// drop the marker and the backup. For a gem RubyGems built, the extension
/// dir the backup names must be this gem's under the home
/// ([`confined_ext_dir`]) and no symlink, or nothing is touched. For a
/// precompiled copy the backup holds its prebuilt binaries, which go back
/// where they were under the gem dir, bytes and mode.
fn restore_backup(copy: &GemCopy, marker: Option<&BuildMarker>) -> std::io::Result<()> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    let info: BackupInfo =
        serde_json::from_slice(&read_regular_to_bytes_sync(&backup.join(BACKUP_INFO))?)
            .map_err(std::io::Error::other)?;
    let restore_lib_files = || -> std::io::Result<()> {
        for lib in &info.lib_files {
            if !is_safe_relative_subpath(lib) {
                continue;
            }
            let saved = backup.join("lib").join(lib);
            let bytes = read_regular_to_bytes_sync(&saved)?;
            let perms = std::fs::symlink_metadata(&saved)?.permissions();
            // With the mode the backup kept.
            replace_file(&copy.gem_dir.join(lib), |stage| {
                std::fs::write(stage, &bytes)?;
                std::fs::set_permissions(stage, perms)
            })?;
        }
        Ok(())
    };
    if info.grafted {
        restore_lib_files()?;
    } else {
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
        restore_lib_files()?;
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

    /// What the gemspec of a gem RubyGems builds says: the `ruby` platform,
    /// `lib` as its require path, and `scripts` as its extensions.
    fn built_gem(scripts: &[&str]) -> SpecFacts {
        SpecFacts {
            extensions: ExtensionDecl {
                declared: true,
                entries: scripts.iter().map(|s| s.to_string()).collect(),
            },
            require_paths: vec!["lib".to_string()],
            ..SpecFacts::default()
        }
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
        let decl = built_gem(&["ext/foo/Cargo.toml"]);
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
            &SpecFacts::default(),
            &files(&["lib/parser.y", "lib/parser.rb", "ext/x.c"]),
        );
        assert_eq!(scope.inputs, vec!["ext/x.c"]);
        assert!(!scope.builds_extensions);
        let ruby_only = classify(&SpecFacts::default(), &files(&["lib/parser.y"]));
        assert!(ruby_only.inputs.is_empty());
    }

    /// Non-compiled C / Objective-C files outside `ext/` in a gem that builds
    /// nothing (templates, fixtures) are plain files.
    #[test]
    fn classify_without_extensions_ignores_c_outside_ext() {
        let scope = classify(
            &SpecFacts::default(),
            &files(&["lib/templates/App.m", "test/fixtures/a.c", "lib/a.h"]),
        );
        assert!(scope.inputs.is_empty());
    }

    /// A root-level script makes the files beside it inputs, not `lib/`.
    #[test]
    fn classify_root_level_script_counts_top_level_files_only() {
        let decl = built_gem(&["extconf.rb"]);
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
        let decl = built_gem(&[]);
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
            offline: true,
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
            offline: true,
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
            offline: true,
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
            facts: None,
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
            ..BackupInfo::default()
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
                ..BackupInfo::default()
            };
            std::fs::write(
                gem_dir.join(BACKUP_DIR).join(BACKUP_INFO),
                serde_json::to_vec(&info).unwrap(),
            )
            .unwrap();
            let env = RubyEnv {
                cwd: home.clone(),
                rebuild: true,
                offline: true,
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
            offline: true,
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
                offline: true,
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
            ..NativeScope::default()
        };
        let marker = BuildMarker {
            schema: MARKER_SCHEMA,
            sources: [("ext/a/a.c".to_string(), after.clone())].into(),
            extension_dir: "extensions/p/3.4.0/a-1".into(),
            ext_artifacts: [("a/a.so".to_string(), hash.clone())].into(),
            lib_artifacts: [("lib/a/a.so".to_string(), hash.clone())].into(),
            grafted: false,
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

    // ── native gems: what is a build input ──────────────────────────────

    /// The gemspec RubyGems writes for an installed gem, as `to_ruby`
    /// shapes it. `platform` is `None` for the `ruby` platform.
    fn to_ruby(name: &str, platform: Option<&str>, extensions: &[&str]) -> String {
        let mut text = format!(
            "# -*- encoding: utf-8 -*-\n# stub: {name} 1.18.3 {} lib\n",
            platform.unwrap_or("ruby")
        );
        text.push_str("\nGem::Specification.new do |s|\n");
        text.push_str(&format!("  s.name = \"{name}\".freeze\n"));
        text.push_str("  s.version = \"1.18.3\".freeze\n");
        if let Some(platform) = platform {
            text.push_str(&format!("  s.platform = \"{platform}\".freeze\n"));
        }
        text.push_str(
            "\n  s.required_rubygems_version = Gem::Requirement.new(\">= 0\".freeze) if \
             s.respond_to? :required_rubygems_version=\n  s.require_paths = [\"lib\".freeze]\n",
        );
        if !extensions.is_empty() {
            let list: Vec<String> = extensions
                .iter()
                .map(|e| format!("\"{e}\".freeze"))
                .collect();
            text.push_str(&format!("  s.extensions = [{}]\n", list.join(", ")));
        }
        text.push_str("  s.rubygems_version = \"3.3.26\".freeze\n");
        text.push_str("  s.installed_by_version = \"4.0.15\".freeze\nend\n");
        text
    }

    /// Files a nokogiri record may change that take part in its build:
    /// the C sources, and what `extconf.rb` builds the vendored libxml2 and
    /// libgumbo from.
    const NOKOGIRI_BUILT: &[&str] = &[
        "Cargo.lock",
        "Cargo.toml",
        "dependencies.yml",
        "ext/java/nokogiri/XmlNode.java",
        "ext/nokogiri/depend",
        "ext/nokogiri/extconf.rb",
        "ext/nokogiri/xml_node.c",
        "gumbo-parser/src/parser.c",
        "gumbo-parser/src/tag_lookup.gperf",
        "patches/libxml2/0100-CVE-2025-0000.patch",
        "patches/libxslt/0001-update-config.guess.patch",
        "ports/archives/libxml2-2.13.6.tar.xz",
        "vendor/libfoo/foo.c",
    ];

    /// Files of the same gem that Ruby loads as they are, or that nothing
    /// loads.
    const NOKOGIRI_PLAIN: &[&str] = &[
        "CHANGELOG.md",
        "Gemfile",
        "LICENSE-DEPENDENCIES.md",
        "LICENSE.md",
        "README.md",
        "bin/nokogiri",
        "doc/guide.md",
        "lib/nokogiri/3.4/nokogiri.bundle",
        "lib/nokogiri/version/constant.rb",
        "lib/nokogiri/xml/node.rb",
        "nokogiri.gemspec",
        "spec/node_spec.rb",
        "test/xml/test_node.rb",
    ];

    fn nokogiri_files(extra: &[&str]) -> HashMap<String, PatchFileInfo> {
        let all: Vec<&str> = NOKOGIRI_BUILT
            .iter()
            .chain(NOKOGIRI_PLAIN)
            .chain(extra)
            .copied()
            .collect();
        files(&all)
    }

    /// In the source-built gem (its gemspec declares the extension)
    /// everything `extconf.rb` may build from is an input, not just the C
    /// files under the script's dir: a record that only adds
    /// `patches/libxml2/<n>.patch` changes the compiled library.
    #[test]
    fn classify_nokogiri_built_from_source() {
        let spec = to_ruby("nokogiri", None, &["ext/nokogiri/extconf.rb"]);
        let facts = SpecFacts::of(&spec, "nokogiri-1.18.3");
        assert_eq!(facts.platform, None);
        let scope = classify(&facts, &nokogiri_files(&["lib/nokogiri/css/parser.y"]));
        let mut expected: Vec<&str> = NOKOGIRI_BUILT.to_vec();
        // A grammar counts in a gem that builds, as before.
        expected.push("lib/nokogiri/css/parser.y");
        expected.sort();
        assert_eq!(scope.inputs, expected);
        assert!(scope.builds_extensions);
        assert_eq!(scope.precompiled, None);
        assert_eq!(
            scope.source_gem().map(|g| g.full_name()).as_deref(),
            Some("nokogiri-1.18.3")
        );

        let only_a_patch = classify(
            &facts,
            &files(&["patches/libxml2/0100-CVE-2025-0000.patch"]),
        );
        assert_eq!(
            only_a_patch.inputs,
            ["patches/libxml2/0100-CVE-2025-0000.patch"]
        );
    }

    /// The precompiled platform gem declares no extensions and still runs
    /// compiled code: the same files are inputs, rebuilt from the
    /// ruby-platform gem of its version. A grammar under `lib/` is not one
    /// (the gem packs its generated parser, which Ruby loads).
    #[test]
    fn classify_nokogiri_precompiled() {
        let spec = to_ruby("nokogiri", Some("arm64-darwin"), &[]);
        let facts = SpecFacts::of(&spec, "nokogiri-1.18.3-arm64-darwin");
        assert_eq!(facts.platform.as_deref(), Some("arm64-darwin"));
        let scope = classify(&facts, &nokogiri_files(&["lib/nokogiri/css/parser.y"]));
        assert_eq!(scope.inputs, NOKOGIRI_BUILT);
        assert!(!scope.builds_extensions);
        assert_eq!(scope.precompiled.as_deref(), Some("arm64-darwin"));
        let source = scope.source_gem().unwrap();
        assert_eq!(source.full_name(), "nokogiri-1.18.3");
        assert_eq!(source.platform, None, "the ruby-platform source gem");

        let ruby_only = classify(&facts, &files(NOKOGIRI_PLAIN));
        assert!(ruby_only.inputs.is_empty(), "{:?}", ruby_only.inputs);
    }

    /// A pure-Ruby gem (no extensions, the `ruby` platform) is classified
    /// as before: whatever its files are called, only a C source under
    /// `ext/` is taken for one, and nothing else needs a build.
    #[test]
    fn classify_pure_ruby_gem_is_unchanged() {
        let spec = to_ruby("rack", None, &[]);
        let facts = SpecFacts::of(&spec, "rack-1.18.3");
        assert_eq!(facts.platform, None);
        let scope = classify(
            &facts,
            &files(&[
                "data/x.yml",
                "lib/rack.rb",
                "patches/a.patch",
                "ports/archives/a.tar.xz",
                "dependencies.yml",
                "Cargo.toml",
                "vendor/x.c",
                "gumbo-parser/src/parser.c",
            ]),
        );
        assert!(scope.inputs.is_empty(), "{:?}", scope.inputs);
        assert!(!scope.builds_extensions);
        assert_eq!(scope.precompiled, None);
        let with_ext = classify(&facts, &files(&["data/x.yml", "ext/x.c"]));
        assert_eq!(with_ext.inputs, ["ext/x.c"]);
    }

    /// The JRuby build of a gem ships jars: its Java sources are inputs
    /// (nothing here rebuilds them, so the patch is refused, never called
    /// applied), while its Ruby files and a jar replaced whole are plain.
    #[test]
    fn classify_java_gem() {
        let spec = to_ruby("nokogiri", Some("java"), &[]);
        let facts = SpecFacts::of(&spec, "nokogiri-1.18.3-java");
        let scope = classify(
            &facts,
            &files(&[
                "ext/java/nokogiri/XmlNode.java",
                "lib/nokogiri/xml/node.rb",
                "lib/nokogiri/nokogiri.jar",
                "lib/nokogiri/internals/Helper.java",
            ]),
        );
        assert_eq!(
            scope.inputs,
            [
                "ext/java/nokogiri/XmlNode.java",
                "lib/nokogiri/internals/Helper.java"
            ]
        );
        assert_eq!(scope.precompiled.as_deref(), Some("java"));
        assert!(is_java_platform("java"));
        assert!(is_java_platform("universal-java-17"));
        for platform in ["arm64-darwin", "x86_64-linux-gnu", "x64-mingw-ucrt"] {
            assert!(!is_java_platform(platform), "{platform}");
        }
    }

    /// A build system's manifest is an input wherever it sits, and a gem
    /// that requires from its root says nothing about any file.
    #[test]
    fn classify_native_gem_edges() {
        let facts = built_gem(&["ext/a/extconf.rb"]);
        let scope = classify(
            &facts,
            &files(&["CMakeLists.txt", "NOTES.txt", "Rakefile", "lib/a.rb"]),
        );
        assert_eq!(scope.inputs, ["CMakeLists.txt", "Rakefile"]);
        let rooted = SpecFacts {
            require_paths: vec![".".to_string()],
            ..built_gem(&["ext/a/extconf.rb"])
        };
        assert_eq!(classify(&rooted, &files(&["a.rb"])).inputs, ["a.rb"]);
    }

    /// The platform is the dir name's suffix after `<name>-<version>`, or
    /// what the gemspec assigns; the release names the archive.
    #[test]
    fn spec_facts_read_the_release_and_platform() {
        let ruby = SpecFacts::of(
            &to_ruby("ruby-prof", None, &["ext/a/extconf.rb"]),
            "ruby-prof-1.18.3",
        );
        assert_eq!(ruby.platform, None);
        assert_eq!(
            ruby.release.as_ref().map(GemId::full_name).as_deref(),
            Some("ruby-prof-1.18.3")
        );
        assert!(ruby.extensions.declared);
        assert_eq!(ruby.require_paths, ["lib"]);

        // The gemspec's own spelling of the platform may differ from the
        // dir's (an older RubyGems drops `-gnu`): the dir names the archive.
        let linux = SpecFacts::of(
            &to_ruby("nokogiri", Some("x86_64-linux-gnu"), &[]),
            "nokogiri-1.18.3-x86_64-linux",
        );
        assert_eq!(linux.platform.as_deref(), Some("x86_64-linux"));
        assert_eq!(
            linux.release.as_ref().map(GemId::full_name).as_deref(),
            Some("nokogiri-1.18.3-x86_64-linux")
        );

        // A dir that is not this gemspec's release: the assigned platform
        // still marks a platform gem, and there is no archive to name.
        let moved = SpecFacts::of(&to_ruby("nokogiri", Some("java"), &[]), "something-else");
        assert_eq!(moved.platform.as_deref(), Some("java"));
        assert_eq!(moved.release, None);
        // `nokogiri-1.18.30` is not `nokogiri-1.18.3` plus a platform.
        let longer = SpecFacts::of(&to_ruby("nokogiri", None, &[]), "nokogiri-1.18.30");
        assert_eq!((longer.platform, longer.release), (None, None));
        // `s.platform = Gem::Platform::RUBY` assigns no string.
        let explicit = "Gem::Specification.new do |s|\n  s.name = \"a\"\n  s.version = \"1\"\n  \
                        s.platform = Gem::Platform::RUBY\nend\n";
        assert_eq!(SpecFacts::of(explicit, "a-1").platform, None);
    }

    #[test]
    fn ruby_facts_parse() {
        let facts = parse_ruby_facts(
            "noise\nsp_extensions_dir\t/h/extensions/arm64-darwin-25/3.4.0\n\
             sp_ruby\t3.4.10\t4.0.15\tbundle\tarm64-darwin-25\tyes\n",
        )
        .unwrap();
        assert_eq!(facts.minor().as_deref(), Some("3.4"));
        assert_eq!(facts.dlext, "bundle");
        assert_eq!(facts.runs_platform, Some(true));
        assert_eq!(facts.versions().ruby.as_deref(), Some("3.4.10"));
        let unasked = parse_ruby_facts("sp_ruby\t3.3.0\t3.5.3\tso\tx86_64-linux\t\n").unwrap();
        assert_eq!(unasked.runs_platform, None);
        let other = parse_ruby_facts("sp_ruby\t3.3.0\t3.5.3\tso\tx86_64-linux\tno\n").unwrap();
        assert_eq!(other.runs_platform, Some(false));
        for unreadable in ["", "sp_ruby\t3.4.10\n", "sp_extensions_dir\t/x\n"] {
            assert_eq!(parse_ruby_facts(unreadable), None, "{unreadable:?}");
        }
        assert_eq!(
            tagged_lines(
                "sp_missing\ta\t~> 1.0\nx\nsp_missing\tb\t>= 0,< 2\n",
                "sp_missing"
            ),
            [vec!["a", "~> 1.0"], vec!["b", ">= 0,< 2"]]
        );
        assert_eq!(
            abi_of_home(Path::new("/p/vendor/bundle/ruby/3.4.0")).as_deref(),
            Some("3.4.0")
        );
        assert_eq!(abi_of_home(Path::new("/opt/gems")), None);
    }

    // ── a precompiled copy ──────────────────────────────────────────────

    const PREBUILT: &[u8] = b"\xcf\xfa\xed\xfe prebuilt";

    /// A precompiled `a-1-arm64-darwin` copy in `home`, with a prebuilt
    /// binary for Ruby 3.3 and 3.4 in the rake-compiler layout.
    fn precompiled_gem(home: &Path) -> GemCopy {
        let gem_dir = home.join("gems/a-1-arm64-darwin");
        for minor in ["3.3", "3.4"] {
            let dir = gem_dir.join("lib/a").join(minor);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("a.bundle"), PREBUILT).unwrap();
        }
        std::fs::create_dir_all(gem_dir.join("ext/a")).unwrap();
        std::fs::write(gem_dir.join("ext/a/a.c"), b"int a;").unwrap();
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications/a-1-arm64-darwin.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"a\".freeze\n  \
             s.version = \"1\".freeze\n  s.platform = \"arm64-darwin\".freeze\n  \
             s.require_paths = [\"lib\".freeze]\nend\n",
        )
        .unwrap();
        GemCopy::of(&gem_dir).unwrap()
    }

    fn probe_for(copy: &GemCopy, ruby_version: &str) -> Probe {
        Probe {
            ruby: PathBuf::from("/r"),
            gem_dir: copy.gem_dir.clone(),
            extension_dir: copy.home.join("extensions/p/3.4.0").join(&copy.full_name),
            require_path: "lib".to_string(),
            lib_dir: copy.gem_dir.join("lib"),
            facts: Some(RubyFacts {
                ruby_version: ruby_version.to_string(),
                rubygems_version: "3.6.9".to_string(),
                dlext: "bundle".to_string(),
                platform: "arm64-darwin-25".to_string(),
                runs_platform: Some(true),
            }),
        }
    }

    /// A build of the source gem `a-1` in the stage home `stage`: its
    /// extension dir holds `rels`, each with the bytes `built`.
    fn staged_build(stage: &Path, rels: &[&str], built: &[u8]) -> StagedBuild {
        let label = "extensions/arm64-darwin-25/3.4.0/a-1".to_string();
        let extension_dir = stage.join(&label);
        let gem_dir = stage.join("gems/a-1");
        for rel in rels {
            for base in [&extension_dir, &gem_dir.join("lib")] {
                let path = base.join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, built).unwrap();
            }
        }
        std::fs::write(extension_dir.join(BUILD_COMPLETE), b"").unwrap();
        std::fs::write(extension_dir.join("gem_make.out"), b"log").unwrap();
        StagedBuild {
            gem: StagedGem {
                gem_dir,
                spec_path: stage.join("specifications/a-1.gemspec"),
            },
            extension_dir,
            label,
        }
    }

    /// The build is matched to the binary the gem keeps for the building
    /// Ruby's minor; a single binary kept elsewhere is matched by name; no
    /// counterpart, or several, is refused.
    #[test]
    fn a_graft_replaces_the_binary_ruby_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = precompiled_gem(&tmp.path().join("home"));
        let staged = staged_build(&tmp.path().join("stage"), &["a/a.bundle", "a/a.rb"], b"new");

        let grafts = plan_graft(&copy, &probe_for(&copy, "3.4.10"), &staged).unwrap();
        assert_eq!(grafts.len(), 1, "only the loadable extension is grafted");
        assert_eq!(grafts[0].target, "lib/a/3.4/a.bundle");
        assert_eq!(grafts[0].staged, staged.extension_dir.join("a/a.bundle"));
        let older = plan_graft(&copy, &probe_for(&copy, "3.3.6"), &staged).unwrap();
        assert_eq!(older[0].target, "lib/a/3.3/a.bundle");

        // No binary for this Ruby, and two that share the name.
        let why = plan_graft(&copy, &probe_for(&copy, "3.5.0"), &staged).unwrap_err();
        assert!(why.contains("no prebuilt a.bundle for Ruby 3.5"), "{why}");
        assert!(
            why.contains("lib/a/3.3/a.bundle, lib/a/3.4/a.bundle"),
            "{why}"
        );

        // One binary, wherever the gem keeps it.
        std::fs::remove_dir_all(copy.gem_dir.join("lib/a/3.3")).unwrap();
        std::fs::rename(
            copy.gem_dir.join("lib/a/3.4/a.bundle"),
            copy.gem_dir.join("lib/a.bundle"),
        )
        .unwrap();
        let single = plan_graft(&copy, &probe_for(&copy, "3.5.0"), &staged).unwrap();
        assert_eq!(single[0].target, "lib/a.bundle");

        std::fs::remove_file(copy.gem_dir.join("lib/a.bundle")).unwrap();
        let why = plan_graft(&copy, &probe_for(&copy, "3.4.10"), &staged).unwrap_err();
        assert!(why.contains("no prebuilt a.bundle"), "{why}");

        // A build that left no loadable extension has nothing to graft.
        let empty = staged_build(&tmp.path().join("stage2"), &["a/a.rb"], b"new");
        let why = plan_graft(&copy, &probe_for(&copy, "3.4.10"), &empty).unwrap_err();
        assert!(why.contains("no .bundle extension"), "{why}");
    }

    /// A graft is attested like a rebuilt extension dir: only while the
    /// marker's sources are the record's and the replaced binary still has
    /// the built bytes. Rollback puts the prebuilt binary back, bytes and
    /// mode, and removes what the patch added to the copy.
    #[tokio::test]
    async fn a_grafted_copy_is_attested_and_rolled_back() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = precompiled_gem(&home);
        let target = copy.gem_dir.join("lib/a/3.4/a.bundle");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let before_c = compute_git_sha256_from_bytes(b"int a;");
        let record: HashMap<String, PatchFileInfo> = [
            (
                "ext/a/a.c".to_string(),
                PatchFileInfo {
                    before_hash: before_c,
                    after_hash: "c".repeat(64),
                },
            ),
            // In the source gem alone: the precompiled copy never had it.
            (
                "patches/0001.patch".to_string(),
                PatchFileInfo {
                    before_hash: "b".repeat(64),
                    after_hash: "d".repeat(64),
                },
            ),
        ]
        .into();
        let (scope, found) = scope_of(&copy.gem_dir, &record).await;
        assert!(found.is_some());
        assert_eq!(scope.inputs, ["ext/a/a.c", "patches/0001.patch"]);
        assert_eq!(scope.precompiled.as_deref(), Some("arm64-darwin"));
        assert_eq!(
            verify_native_build(&copy.gem_dir, &record).await,
            Err(NOT_REBUILT_REASON.to_string()),
            "patched sources over the prebuilt binary attest nothing"
        );

        // The copy takes the file it never shipped as an addition.
        let (installed, absent) = files_as_installed(&copy, &scope, &record).await;
        assert_eq!(absent, ["patches/0001.patch"]);
        assert_eq!(installed["patches/0001.patch"].before_hash, "");
        assert_eq!(installed["ext/a/a.c"], record["ext/a/a.c"]);

        let staged = staged_build(&tmp.path().join("stage"), &["a/a.bundle"], b"rebuilt");
        let grafts = plan_graft(&copy, &probe_for(&copy, "3.4.10"), &staged).unwrap();
        assert!(back_up_prebuilt(&copy, &grafts, &absent).unwrap());
        assert!(
            !back_up_prebuilt(&copy, &grafts, &["patches/0002.patch".to_string()]).unwrap(),
            "the original is backed up once"
        );
        graft_binaries(&copy, &scope, &record, &grafts).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"rebuilt");
        assert_eq!(
            std::fs::read(copy.gem_dir.join("lib/a/3.3/a.bundle")).unwrap(),
            PREBUILT,
            "another Ruby's binary is not this build's to replace"
        );
        let marker = read_marker_sync(&copy.gem_dir).unwrap();
        assert!(marker.grafted);
        assert_eq!(marker.schema, GRAFT_MARKER_SCHEMA);
        assert_eq!(
            marker.lib_artifacts.keys().collect::<Vec<_>>(),
            ["lib/a/3.4/a.bundle"]
        );
        assert_eq!(verify_native_build(&copy.gem_dir, &record).await, Ok(()));

        // Another record, or a binary that is no longer the built one.
        let mut other = record.clone();
        other.get_mut("ext/a/a.c").unwrap().after_hash = "e".repeat(64);
        assert!(verify_native_build(&copy.gem_dir, &other).await.is_err());
        std::fs::write(&target, b"reinstalled").unwrap();
        assert!(verify_native_build(&copy.gem_dir, &record).await.is_err());
        std::fs::write(&target, b"rebuilt").unwrap();

        // Rollback: the added file is removed (an empty `beforeHash`), the
        // one the copy shipped is restored.
        let undo = rollback_files(&copy.gem_dir, &record).await;
        assert_eq!(undo["patches/0001.patch"].before_hash, "");
        assert_eq!(undo["ext/a/a.c"], record["ext/a/a.c"]);
        let env = RubyEnv {
            cwd: home.clone(),
            rebuild: true,
            offline: true,
        };
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(true));
        assert_eq!(std::fs::read(&target).unwrap(), PREBUILT);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "the binary keeps its mode");
        }
        assert!(!copy.gem_dir.join(MARKER_FILE).exists());
        assert!(!copy.gem_dir.join(BACKUP_DIR).exists());
        assert_eq!(rollback_files(&copy.gem_dir, &record).await, record);
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(false));
    }

    /// A marker speaks for the kind of copy it was written for, and a
    /// grafted one must name what it replaced.
    #[test]
    fn a_marker_of_the_wrong_kind_attests_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = precompiled_gem(&tmp.path().join("home"));
        let after = "c".repeat(64);
        let record: HashMap<String, PatchFileInfo> =
            [("ext/a/a.c".to_string(), info(&after))].into();
        let scope = NativeScope {
            inputs: vec!["ext/a/a.c".into()],
            precompiled: Some("arm64-darwin".into()),
            ..NativeScope::default()
        };
        let grafted = BuildMarker {
            schema: GRAFT_MARKER_SCHEMA,
            sources: [("ext/a/a.c".to_string(), after.clone())].into(),
            lib_artifacts: [(
                "lib/a/3.4/a.bundle".to_string(),
                compute_git_sha256_from_bytes(PREBUILT),
            )]
            .into(),
            grafted: true,
            ..BuildMarker::default()
        };
        assert!(marker_holds(&grafted, &copy, &scope, &record));
        // Nothing replaced: nothing attested.
        let empty = BuildMarker {
            lib_artifacts: BTreeMap::new(),
            ..grafted.clone()
        };
        assert!(!marker_holds(&empty, &copy, &scope, &record));
        // A gem RubyGems builds is not attested by a graft, nor a
        // precompiled one by an extension dir's marker.
        let built = NativeScope {
            builds_extensions: true,
            precompiled: None,
            ..scope.clone()
        };
        assert!(!marker_holds(&grafted, &copy, &built, &record));
        let dir_marker = BuildMarker {
            schema: MARKER_SCHEMA,
            grafted: false,
            extension_dir: "extensions/p/3.4.0/a-1-arm64-darwin".into(),
            ..grafted.clone()
        };
        assert!(!marker_holds(&dir_marker, &copy, &scope, &record));

        // On disk: each schema is read only in its own shape.
        let write = |marker: &BuildMarker| {
            std::fs::write(
                copy.gem_dir.join(MARKER_FILE),
                serde_json::to_vec(marker).unwrap(),
            )
            .unwrap();
            read_marker_sync(&copy.gem_dir)
        };
        assert_eq!(write(&grafted), Some(grafted.clone()));
        assert_eq!(write(&dir_marker), Some(dir_marker.clone()));
        for (schema, is_graft) in [
            (MARKER_SCHEMA, true),
            (GRAFT_MARKER_SCHEMA, false),
            (3, true),
        ] {
            let odd = BuildMarker {
                schema,
                grafted: is_graft,
                ..grafted.clone()
            };
            assert_eq!(write(&odd), None, "schema {schema}, grafted {is_graft}");
        }
        // The marker a release before the graft wrote still reads.
        std::fs::write(
            copy.gem_dir.join(MARKER_FILE),
            "{\"schema\":1,\"sources\":{},\"extensionDir\":\"extensions/p/3.4.0/a-1\",\
             \"extArtifacts\":{},\"libArtifacts\":{}}",
        )
        .unwrap();
        assert!(read_marker_sync(&copy.gem_dir).is_some_and(|m| !m.grafted));
    }

    // ── a build staged from the source gem ──────────────────────────────

    /// A staged build takes the place of the installed extension dir and
    /// its `lib/` copies, with the original backed up and the marker
    /// written, as an in-place rebuild leaves them; rollback restores it.
    #[tokio::test]
    async fn a_staged_build_replaces_the_installed_one() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = installed_gem(&home, "lib");
        let ext = home.join("extensions/p/3.4.0/a-1");
        std::fs::create_dir_all(ext.join("a")).unwrap();
        std::fs::write(ext.join("a/a.so"), b"original").unwrap();
        std::fs::write(ext.join(BUILD_COMPLETE), b"").unwrap();
        std::fs::create_dir_all(copy.gem_dir.join("lib/a")).unwrap();
        std::fs::write(copy.gem_dir.join("lib/a/a.so"), b"original").unwrap();
        let probe = Probe {
            ruby: PathBuf::from("/r"),
            gem_dir: copy.gem_dir.clone(),
            extension_dir: ext.clone(),
            require_path: "lib".to_string(),
            lib_dir: copy.gem_dir.join("lib"),
            facts: None,
        };
        let stage = open_stage(&copy).unwrap();
        assert!(stage.home.starts_with(&home), "staged inside the gem home");
        let label = "extensions/p/3.4.0/a-1".to_string();
        let staged_ext = stage.home.join(&label);
        let staged_gem = stage.home.join("gems/a-1");
        std::fs::create_dir_all(staged_ext.join("a")).unwrap();
        std::fs::create_dir_all(staged_gem.join("lib/a")).unwrap();
        std::fs::write(staged_ext.join("a/a.so"), b"rebuilt").unwrap();
        std::fs::write(staged_ext.join(BUILD_COMPLETE), b"").unwrap();
        std::fs::write(staged_gem.join("lib/a/a.so"), b"rebuilt").unwrap();
        let built = StagedBuild {
            gem: StagedGem {
                gem_dir: staged_gem,
                spec_path: stage.home.join("specifications/a-1.gemspec"),
            },
            extension_dir: staged_ext,
            label,
        };
        let after = "c".repeat(64);
        let record: HashMap<String, PatchFileInfo> =
            [("ext/a/a.c".to_string(), info(&after))].into();
        let scope = NativeScope {
            inputs: vec!["ext/a/a.c".into()],
            builds_extensions: true,
            ..NativeScope::default()
        };

        // A build for another ABI is not this copy's.
        let foreign = StagedBuild {
            label: "extensions/p/3.3.0/a-1".to_string(),
            ..built.clone()
        };
        let why = install_staged_build(&copy, &probe, &scope, &record, &foreign, Some(&[]));
        assert!(why.unwrap_err().contains("not the installed extension's"));
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"original");
        assert!(!copy.gem_dir.join(BACKUP_DIR).exists());

        install_staged_build(&copy, &probe, &scope, &record, &built, Some(&[])).unwrap();
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"rebuilt");
        assert!(ext.join(BUILD_COMPLETE).is_file());
        assert_eq!(
            std::fs::read(copy.gem_dir.join("lib/a/a.so")).unwrap(),
            b"rebuilt"
        );
        assert!(!parked_build_path(&ext).exists());
        let marker = read_marker_sync(&copy.gem_dir).unwrap();
        assert_eq!(marker.schema, MARKER_SCHEMA);
        assert!(marker_holds(&marker, &copy, &scope, &record));
        close_stage(stage, &copy).await;
        assert!(!home.join(BUILD_STAGE_DIR).exists(), "the stage is gone");

        let env = RubyEnv {
            cwd: home.clone(),
            rebuild: true,
            offline: true,
        };
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(true));
        assert_eq!(std::fs::read(ext.join("a/a.so")).unwrap(), b"original");
        assert_eq!(
            std::fs::read(copy.gem_dir.join("lib/a/a.so")).unwrap(),
            b"original"
        );
    }

    /// A stage an interrupted run left is only disk space: the next run of
    /// the copy drops it. One a live run holds is left to that run.
    #[cfg(unix)]
    #[test]
    fn a_stale_stage_is_swept_and_a_live_one_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = installed_gem(&home, "lib");
        let root = stage_root(&copy);
        std::fs::create_dir_all(root.join("home/gems/a-1")).unwrap();
        std::fs::write(root.join("home/gems/a-1/half"), b"x").unwrap();

        // Left behind: recovery (the start of `apply` and `rollback`)
        // removes it and the dir that held it.
        assert!(!recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap());
        assert!(!home.join(BUILD_STAGE_DIR).exists());

        // Held by a run that is still building.
        let stage = open_stage(&copy).unwrap();
        let refused = sweep_stale_stage(&copy).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::WouldBlock);
        let why = open_stage(&copy).err().unwrap();
        assert!(why.contains("right now"), "{why}");
        assert!(stage.home.is_dir());
        drop(stage);
        // The holder gone: a sibling test forking right now keeps a copy
        // of the descriptor, and the lock with it, until it execs.
        loop {
            match sweep_stale_stage(&copy) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                swept => break swept.unwrap(),
            }
        }
        assert!(!root.exists());

        // A link planted where the stage goes is not written through.
        let elsewhere = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, home.join(BUILD_STAGE_DIR)).unwrap();
        let why = open_stage(&copy).err().unwrap();
        assert!(why.contains("is not a directory"), "{why}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }
}
