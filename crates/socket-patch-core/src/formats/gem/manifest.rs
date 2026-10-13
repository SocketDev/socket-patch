//! Which manifest Bundler loads for a project: the ONE answer shared by the
//! hosted rewriter's caller and the vendored backend, so neither can wire a
//! file Bundler ignores.
//!
//! Bundler's own order (`Bundler::Settings` priority — local app config
//! over ENV — read by `Bundler::CLI#initialize`, which re-exports the
//! winning `gemfile` setting into `BUNDLE_GEMFILE`):
//!
//! 1. `BUNDLE_GEMFILE:` in the app config file, `$BUNDLE_APP_CONFIG/config`
//!    else `<root>/.bundle/config` (what `bundle config set --local gemfile
//!    Gemfile.next` writes; relative to the project root);
//! 2. `BUNDLE_GEMFILE` from the environment (a relative value is read
//!    against the project root: bundler expands it against the directory
//!    `bundle` runs in, which is the project, not socket-patch's own
//!    cwd when it runs with `--cwd`). An environment value naming a file in
//!    ANOTHER directory moves `Bundler.root` there, and bundler then reads
//!    that root's app config, never this project's — so it decides alone;
//! 3. `BUNDLE_GEMFILE:` in the global config file (`bundle config set
//!    --global gemfile …`: `$BUNDLE_CONFIG`, `$BUNDLE_USER_CONFIG`,
//!    `$BUNDLE_USER_HOME/config` or `~/.bundle/config`, see
//!    [`crate::crawlers::ruby_crawler::bundler_global_config_file`]), read
//!    against the project root like the app config value;
//! 4. otherwise `gems.rb` when present, else `Gemfile` (bundler >= 2; 1.x
//!    reads a `Gemfile` first, so callers treat a twin as ambiguous or
//!    follow the >= 2 order, as the hosted rewriter does).
//!
//! A configured value that names the root's own `Gemfile` or `gems.rb` is
//! that spelling; anything else (`Gemfile.next`, a file in another
//! directory, a missing file) is [`LoadedManifest::Unsupported`]: the
//! rewriters and the lock readers only know the two default pairs, so the
//! callers fail closed rather than wire a manifest Bundler never reads.
//! Bundler 4's custom lockfile (`BUNDLE_LOCKFILE` from the environment,
//! else `BUNDLE_LOCKFILE:` in the app config, else in the global config —
//! `Bundler::CLI` checks the environment before `Bundler.settings`) is
//! layered on by [`LoadedManifest::with_lockfile`]: a value naming the lock of the pair bundler loads anyway changes nothing,
//! and anything else is [`LoadedManifest::UnsupportedLockfile`] — the
//! rewriters only edit the default lock of each pair, so wiring a project
//! whose lock lives elsewhere would leave the lock bundler reads unpinned
//! (#749).
//!
//! A `Gemfile` + `gems.rb` twin under default discovery is ambiguous across
//! bundler majors (1.x loads the `Gemfile`, >= 2 loads `gems.rb`), and
//! nothing on disk says which bundler runs: callers refuse it with
//! [`twin_manifest_refusal`] (#751).
//!
//! A configured path names a root file when its file name matches and its
//! directory is the root's, compared lexically and, failing that, by the
//! directories' resolved identity: bundler expands the setting lexically
//! and opens it through the OS, so a symlinked spelling of the project
//! directory (macOS `/tmp` → `/private/tmp`) names the same file (#896).
//! That directory lookup is the model's only disk read; the other disk and
//! environment reads live in
//! [`crate::crawlers::ruby_crawler::bundler_loaded_manifest`].

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::crawlers::ruby_crawler::bundle_config_setting_including_empty;
use crate::utils::relpath::normalize_lexically;

/// Where a configured `BUNDLE_GEMFILE` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemfileSetting {
    /// The `BUNDLE_GEMFILE` environment variable.
    Env,
    /// `BUNDLE_GEMFILE:` in the project's bundler app config file.
    AppConfig,
    /// `BUNDLE_GEMFILE:` in the user's global bundler config file.
    GlobalConfig,
    /// A `lockfile "<path>"` call in the loaded manifest itself (bundler 4's
    /// Gemfile DSL). Only ever names a lockfile.
    GemfileCall,
}

impl GemfileSetting {
    /// How the setting is named in warnings and refusals.
    pub fn describe(self) -> &'static str {
        match self {
            GemfileSetting::Env => "the BUNDLE_GEMFILE environment variable",
            GemfileSetting::AppConfig => {
                "BUNDLE_GEMFILE in the bundler app config (.bundle/config)"
            }
            GemfileSetting::GlobalConfig => {
                "BUNDLE_GEMFILE in the global bundler config (~/.bundle/config)"
            }
            GemfileSetting::GemfileCall => "the `lockfile` call in the Gemfile",
        }
    }
}

/// The manifest Bundler loads for a project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedManifest {
    /// No `BUNDLE_GEMFILE`: Bundler's default discovery (bundler >= 2: `gems.rb` first,
    /// then `Gemfile`), which callers apply to the files they see.
    Default,
    /// `BUNDLE_GEMFILE` names the root's own `Gemfile` or `gems.rb`.
    Configured {
        manifest: &'static str,
        by: GemfileSetting,
    },
    /// `BUNDLE_GEMFILE` names any other file.
    Unsupported { value: String, by: GemfileSetting },
    /// Bundler 4's `BUNDLE_LOCKFILE` names a lock other than the default
    /// lock of the pair bundler loads.
    UnsupportedLockfile { value: String, by: GemfileSetting },
}

impl LoadedManifest {
    /// The manifest/lock pair Bundler loads, given whether the root holds a
    /// `gems.rb`. `None` for [`LoadedManifest::Unsupported`].
    pub fn pair(&self, gems_rb_present: bool) -> Option<(&'static str, &'static str)> {
        let manifest = match self {
            LoadedManifest::Default if gems_rb_present => "gems.rb",
            LoadedManifest::Default => "Gemfile",
            LoadedManifest::Configured { manifest, .. } => manifest,
            LoadedManifest::Unsupported { .. } | LoadedManifest::UnsupportedLockfile { .. } => {
                return None
            }
        };
        Some(if manifest == "gems.rb" {
            ("gems.rb", "gems.locked")
        } else {
            ("Gemfile", "Gemfile.lock")
        })
    }

    /// The detail line for a caller that refuses an unsupported manifest.
    pub fn unsupported_detail(&self) -> Option<String> {
        match self {
            LoadedManifest::Unsupported { value, by } => {
                let remedy = match by {
                    GemfileSetting::Env => {
                        "unset BUNDLE_GEMFILE, or point it at the project's Gemfile"
                    }
                    GemfileSetting::AppConfig => {
                        "run `bundle config unset --local gemfile`, or point it at the \
                         project's Gemfile"
                    }
                    GemfileSetting::GlobalConfig => {
                        "run `bundle config unset --global gemfile`, or point it at the \
                         project's Gemfile"
                    }
                    GemfileSetting::GemfileCall => "remove the `lockfile` call from the Gemfile",
                };
                Some(format!(
                    "bundler loads `{value}` ({}), not the project's Gemfile or gems.rb; \
                     socket-patch only wires those, so it left the gem manifests untouched \
                     ({remedy}, and re-run)",
                    by.describe()
                ))
            }
            LoadedManifest::UnsupportedLockfile { value, by } => {
                let (knob, remedy) = match by {
                    GemfileSetting::Env => (
                        "the BUNDLE_LOCKFILE environment variable",
                        "unset BUNDLE_LOCKFILE",
                    ),
                    GemfileSetting::AppConfig => (
                        "BUNDLE_LOCKFILE in the bundler app config (.bundle/config)",
                        "run `bundle config unset --local lockfile`",
                    ),
                    GemfileSetting::GlobalConfig => (
                        "BUNDLE_LOCKFILE in the global bundler config (~/.bundle/config)",
                        "run `bundle config unset --global lockfile`",
                    ),
                    GemfileSetting::GemfileCall => (
                        "the `lockfile` call in the Gemfile",
                        "remove the `lockfile` call from the Gemfile",
                    ),
                };
                Some(format!(
                    "bundler reads the lockfile `{value}` ({knob}), not the Gemfile.lock or \
                     gems.locked socket-patch pins; wiring the manifest alone would leave that \
                     lock unpinned and break frozen installs, so it left the gem manifests \
                     untouched ({remedy} to use the default lock, and re-run)"
                ))
            }
            _ => None,
        }
    }

    /// Layer Bundler 4's configured lockfile onto `self`: `lockfile_env`
    /// (`BUNDLE_LOCKFILE`) first, else `lockfile_config` (the app config's
    /// `BUNDLE_LOCKFILE:`), else `lockfile_global` (the global config's), as
    /// `Bundler::CLI` resolves it. A relative value
    /// is read against `root`, like `BUNDLE_GEMFILE`. A value naming the
    /// default lock of the pair bundler loads (given whether the root holds
    /// a `gems.rb`) leaves `self` unchanged; any other value is
    /// [`LoadedManifest::UnsupportedLockfile`]. An unsupported manifest
    /// stays the answer: it is refused either way.
    pub fn with_lockfile(
        self,
        root: &Path,
        lockfile_env: Option<&OsStr>,
        lockfile_config: Option<&str>,
        lockfile_global: Option<&str>,
        gems_rb_present: bool,
    ) -> LoadedManifest {
        self.with_lockfile_by(
            root,
            lockfile_env,
            lockfile_config,
            lockfile_global,
            gems_rb_present,
            same_dir_on_disk,
        )
    }

    /// [`LoadedManifest::with_lockfile`] for a `root` that only stands in
    /// for a project not on this disk (an in-memory view): paths compare
    /// lexically, never through this host's directories, and an absolute
    /// value never names the stand-in root's lock (bundler opens it as is).
    pub(crate) fn with_lockfile_lexical(
        self,
        root: &Path,
        lockfile_config: Option<&str>,
        gems_rb_present: bool,
    ) -> LoadedManifest {
        if let Some(value) = lockfile_config.filter(|v| Path::new(v).has_root()) {
            if self.pair(gems_rb_present).is_some() {
                return LoadedManifest::UnsupportedLockfile {
                    value: value.to_string(),
                    by: GemfileSetting::AppConfig,
                };
            }
        }
        self.with_lockfile_by(
            root,
            None,
            lockfile_config,
            None,
            gems_rb_present,
            |a, b| a == b,
        )
    }

    fn with_lockfile_by(
        self,
        root: &Path,
        lockfile_env: Option<&OsStr>,
        lockfile_config: Option<&str>,
        lockfile_global: Option<&str>,
        gems_rb_present: bool,
        same_dir: SameDir,
    ) -> LoadedManifest {
        let Some((_, lock)) = self.pair(gems_rb_present) else {
            return self;
        };
        // The first tier that holds the key wins, as in `Settings#[]`: a
        // present empty value shadows the tiers below and means the
        // default lock.
        let (value, by) = match (lockfile_env, lockfile_config, lockfile_global) {
            (Some(env), _, _) => (PathBuf::from(env), GemfileSetting::Env),
            (None, Some(config), _) => (PathBuf::from(config), GemfileSetting::AppConfig),
            (None, None, Some(global)) => (PathBuf::from(global), GemfileSetting::GlobalConfig),
            (None, None, None) => return self,
        };
        if value.as_os_str().is_empty() {
            return self;
        }
        self.lockfile_against(root, &value, by, lock, same_dir)
    }

    /// Layer a `lockfile` call read from the manifest bundler loads
    /// ([`gemfile_lockfile`]) onto `self`, in place of
    /// [`LoadedManifest::with_lockfile`]: bundler 4's `Dsl#to_definition`
    /// uses the call's value over the lockfile `Bundler::CLI` picked from
    /// `BUNDLE_LOCKFILE` and the config files, so the call decides alone. A
    /// literal path is read against `root` like the settings; one naming the
    /// pair's own lock leaves `self` unchanged. Any other call (another
    /// lock, `lockfile false`, a computed value) is
    /// [`LoadedManifest::UnsupportedLockfile`] (#1477).
    pub fn with_gemfile_lockfile(
        self,
        root: &Path,
        call: &GemfileLockfile,
        gems_rb_present: bool,
    ) -> LoadedManifest {
        self.with_gemfile_lockfile_by(root, call, gems_rb_present, same_dir_on_disk)
    }

    /// [`LoadedManifest::with_gemfile_lockfile`] for a `root` that only
    /// stands in for a project not on this disk, as
    /// [`LoadedManifest::with_lockfile_lexical`] compares.
    pub(crate) fn with_gemfile_lockfile_lexical(
        self,
        root: &Path,
        call: &GemfileLockfile,
        gems_rb_present: bool,
    ) -> LoadedManifest {
        if let GemfileLockfile::Path(value) = call {
            if Path::new(value).has_root() && self.pair(gems_rb_present).is_some() {
                return LoadedManifest::UnsupportedLockfile {
                    value: value.clone(),
                    by: GemfileSetting::GemfileCall,
                };
            }
        }
        self.with_gemfile_lockfile_by(root, call, gems_rb_present, |a, b| a == b)
    }

    fn with_gemfile_lockfile_by(
        self,
        root: &Path,
        call: &GemfileLockfile,
        gems_rb_present: bool,
        same_dir: SameDir,
    ) -> LoadedManifest {
        let Some((_, lock)) = self.pair(gems_rb_present) else {
            return self;
        };
        match call {
            GemfileLockfile::Path(value) if !value.is_empty() => self.lockfile_against(
                root,
                Path::new(value),
                GemfileSetting::GemfileCall,
                lock,
                same_dir,
            ),
            GemfileLockfile::Path(value) | GemfileLockfile::Other(value) => {
                LoadedManifest::UnsupportedLockfile {
                    value: value.clone(),
                    by: GemfileSetting::GemfileCall,
                }
            }
        }
    }

    /// `self` when `value` (read against `root`) names `lock`, the pair's
    /// own lock, else [`LoadedManifest::UnsupportedLockfile`].
    fn lockfile_against(
        self,
        root: &Path,
        value: &Path,
        by: GemfileSetting,
        lock: &str,
        same_dir: SameDir,
    ) -> LoadedManifest {
        let target = resolve_against(root, value);
        let expected = resolve_against(root, Path::new(lock));
        if let (Some(target), Some(expected)) = (target, expected) {
            if same_entry(&target, &expected, same_dir) {
                return self;
            }
        }
        LoadedManifest::UnsupportedLockfile {
            value: value.display().to_string(),
            by,
        }
    }
}

/// A `lockfile` call in a Gemfile / `gems.rb` (bundler 4's DSL), as
/// [`gemfile_lockfile`] reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GemfileLockfile {
    /// `lockfile "<path>"`: one plain string literal.
    Path(String),
    /// Any call whose lock cannot be read statically: `lockfile false` or
    /// `lockfile nil` (bundler then reads and writes no lock), a computed
    /// or interpolated value, a modifier (`lockfile "x" if …`), a call
    /// that is not the first thing on its line, or two calls that
    /// disagree. The call's line.
    Other(String),
}

impl GemfileLockfile {
    /// The answer for two calls bundler evaluates in turn: one when they
    /// agree, else [`GemfileLockfile::Other`] (which one wins depends on
    /// control flow a line scan cannot follow).
    pub fn merge(self, later: GemfileLockfile) -> GemfileLockfile {
        match (self, later) {
            (a, b) if a == b => a,
            (_, GemfileLockfile::Other(line)) | (GemfileLockfile::Other(line), _) => {
                GemfileLockfile::Other(line)
            }
            (_, GemfileLockfile::Path(value)) => {
                GemfileLockfile::Other(format!("lockfile \"{value}\""))
            }
        }
    }
}

/// The `lockfile` call of a Gemfile / `gems.rb`, if it makes one. Bundler
/// evaluates the DSL anywhere in the file (inside `group`/`platforms`
/// blocks and conditionals too), so every `lockfile` call in code counts.
/// One that starts its statement with a plain string literal is a
/// [`GemfileLockfile::Path`]; every other call is
/// [`GemfileLockfile::Other`], so callers fail closed rather than pin a
/// lock bundler may not read. Comments, strings, heredoc bodies,
/// `=begin`/`=end` blocks, the `__END__` data section, a longer name, a
/// symbol or method of that name, and a local variable used at the start
/// of a line (`lockfile = …`, `lockfile ||= …`, `lockfile.foo`) are not
/// calls. `eval_gemfile`d files are the caller's to read
/// ([`eval_gemfile_paths`]).
pub fn gemfile_lockfile(contents: &str) -> Option<GemfileLockfile> {
    let mut found: Option<GemfileLockfile> = None;
    for_each_code_line(contents, |line, code| {
        let lead = code.len() - code.trim_start().len();
        for at in ident_positions(code, "lockfile") {
            let this = if at == lead {
                match statement_call(&code[at + "lockfile".len()..]) {
                    Some(this) => this,
                    None => continue,
                }
            } else {
                GemfileLockfile::Other(line.trim().to_string())
            };
            found = Some(match found.take() {
                None => this,
                Some(prev) => prev.merge(this),
            });
        }
    });
    found
}

/// The literal paths a Gemfile hands to `eval_gemfile`, as written
/// (bundler reads a relative one against the evaluating file's directory).
/// A computed path is left out.
pub fn eval_gemfile_paths(contents: &str) -> Vec<String> {
    use crate::formats::gem::gemfile::leading_quoted;
    let mut out = Vec::new();
    for_each_code_line(contents, |_, code| {
        for at in ident_positions(code, "eval_gemfile") {
            let arg = code[at + "eval_gemfile".len()..].trim_start();
            let arg = arg.strip_prefix('(').map(str::trim_start).unwrap_or(arg);
            if let Some((value, _)) = leading_quoted(arg) {
                if !value.contains('\\') && !(arg.starts_with('"') && value.contains("#{")) {
                    out.push(value.to_string());
                }
            }
        }
    });
    out
}

/// What follows a `lockfile` that starts its statement: the call it makes,
/// or `None` when the name is a local variable here (assigned, compared,
/// or a method receiver).
fn statement_call(rest: &str) -> Option<GemfileLockfile> {
    use crate::formats::gem::gemfile::leading_quoted;
    let arg = rest.trim_start();
    let spaced = arg.len() != rest.len();
    let operator = |c: char| "=|&+-*/<>!%?^~.".contains(c);
    if arg.starts_with(['.', '=']) || (spaced && arg.starts_with(operator)) {
        return None;
    }
    let call = format!("lockfile{}", rest.trim_end());
    let inner = arg
        .strip_prefix('(')
        .and_then(|c| c.strip_suffix(')'))
        .map(str::trim)
        .unwrap_or(arg);
    Some(match leading_quoted(inner) {
        Some((value, after))
            if after.trim().is_empty()
                && !value.contains('\\')
                && !(inner.starts_with('"') && value.contains("#{")) =>
        {
            GemfileLockfile::Path(value.to_string())
        }
        _ => GemfileLockfile::Other(call),
    })
}

/// Run `f(line, code)` over each line of Ruby source that holds code:
/// `code` is the line before any `#` comment. Skips `=begin`/`=end`
/// blocks and heredoc bodies, and stops at `__END__`. A leading BOM is
/// dropped, as Ruby does.
fn for_each_code_line(contents: &str, mut f: impl FnMut(&str, &str)) {
    use crate::formats::gem::gemfile::code_of;
    let contents = contents.strip_prefix('\u{feff}').unwrap_or(contents);
    let mut in_comment_block = false;
    let mut heredocs: Vec<String> = Vec::new();
    for line in contents.lines() {
        if let Some(id) = heredocs.first() {
            if line.trim() == id {
                heredocs.remove(0);
            }
            continue;
        }
        if in_comment_block {
            in_comment_block = !line.starts_with("=end");
            continue;
        }
        if line.starts_with("=begin") {
            in_comment_block = true;
            continue;
        }
        if line.trim_end() == "__END__" {
            break;
        }
        let code = code_of(line).unwrap_or(line);
        heredocs.extend(heredoc_ids(code));
        f(line, code);
    }
}

/// The byte offsets in `code` where `name` appears as a bare identifier
/// outside strings: not part of a longer name, a symbol (`:name`), an
/// instance/global variable, or a method called on a receiver
/// (`x.name`).
fn ident_positions(code: &str, name: &str) -> Vec<usize> {
    let bytes = code.as_bytes();
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut out = Vec::new();
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if ident(b) {
            let start = i;
            while i < bytes.len() && ident(bytes[i]) {
                i += 1;
            }
            let prev = start.checked_sub(1).map(|p| bytes[p]);
            let next = bytes.get(i).copied();
            if &code[start..i] == name
                && !matches!(prev, Some(b'.' | b':' | b'@' | b'$'))
                && !matches!(next, Some(b'?' | b'!' | b':'))
            {
                out.push(start);
            }
            continue;
        }
        i += 1;
    }
    out
}

/// The terminators of the heredocs a line of code opens (`<<~ID`, `<<-ID`,
/// `<<ID`, with or without quotes around `ID`), outside strings.
fn heredoc_ids(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut chars = code.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '<' if code[i..].starts_with("<<") => {
                let rest = &code[i + 2..];
                let rest = rest.strip_prefix(['~', '-']).unwrap_or(rest);
                let (rest, close) = match rest.chars().next() {
                    Some(q @ ('"' | '\'' | '`')) => (&rest[1..], Some(q)),
                    _ => (rest, None),
                };
                let len = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                let id = &rest[..len];
                let starts_ident = id
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
                if starts_ident && close.is_none_or(|q| rest[len..].starts_with(q)) {
                    out.push(id.to_string());
                }
                chars.next();
            }
            _ => {}
        }
    }
    out
}

/// The `BUNDLE_LOCKFILE:` value of a bundler config file (bundler 4's
/// `bundle config set lockfile <path>`). An empty value is still returned:
/// it shadows the tiers below it ([`LoadedManifest::with_lockfile`]).
pub fn config_lockfile(contents: &str) -> Option<String> {
    bundle_config_setting_including_empty(contents, "BUNDLE_LOCKFILE")
}

/// Why a `Gemfile` + `gems.rb` twin under DEFAULT discovery is never
/// wired: bundler 1.x loads the `Gemfile` and bundler >= 2 loads `gems.rb`,
/// and only the bundler that runs decides. A lock's `BUNDLED WITH` records
/// who wrote it, not who installs it (bundler >= 2 installs a 1.x lock and
/// 1.x installs a 2.x one, each from its own spelling), so nothing a scan
/// can read picks the pair and attesting either could leave the installed
/// one unpatched (#751). Vendored mode refuses the twin the same way.
pub fn twin_manifest_refusal() -> String {
    "both Gemfile and gems.rb are present; bundler 1.x loads the Gemfile while bundler >= 2 \
     loads gems.rb, and socket-patch cannot tell which bundler installs the project, so it \
     left the gem manifests untouched (remove the spelling you don't use, or set \
     BUNDLE_GEMFILE to the one you do, and re-run)"
        .to_string()
}

/// The `BUNDLE_GEMFILE:` value of a bundler app config file (flat YAML that
/// bundler writes itself). An empty string still shadows the global tier;
/// it does not replace a non-empty `BUNDLE_GEMFILE` already in the environment.
pub fn config_gemfile(contents: &str) -> Option<String> {
    bundle_config_setting_including_empty(contents, "BUNDLE_GEMFILE")
}

/// `value` resolved against `root` (an absolute value stands alone), made
/// absolute and lexically normalized; `None` when that is impossible.
fn resolve_against(root: &Path, value: &Path) -> Option<PathBuf> {
    let joined = if value.is_absolute() {
        value.to_path_buf()
    } else {
        root.join(value)
    };
    std::path::absolute(joined)
        .ok()
        .and_then(|p| normalize_lexically(&p))
}

/// How two resolved directories are judged the same directory.
type SameDir = fn(&Path, &Path) -> bool;

/// Whether two resolved directories are the same directory on this disk:
/// equal, or the same directory by file identity (a symlinked spelling, a
/// bind mount, a Windows junction).
fn same_dir_on_disk(a: &Path, b: &Path) -> bool {
    a == b || same_file::is_same_file(a, b).unwrap_or(false)
}

/// Whether two resolved paths name the same directory entry: the same file
/// name in the `same_dir` directory. Only the directory is resolved, so a
/// root `Gemfile` that is itself a symlink to another manifest stays
/// distinct from that manifest, as bundler's root follows the spelled
/// directory.
fn same_entry(a: &Path, b: &Path, same_dir: SameDir) -> bool {
    a == b
        || (a.file_name() == b.file_name()
            && matches!((a.parent(), b.parent()), (Some(a), Some(b)) if same_dir(a, b)))
}

/// Classify the configured `BUNDLE_GEMFILE` against `root`, which also
/// anchors a relative value: the app config value first, then the
/// environment — unless the environment names a manifest outside `root`,
/// which moves bundler's root (and with it the app config bundler reads)
/// away from this project — then the global config value. See the module
/// doc.
pub fn classify(
    root: &Path,
    gemfile_env: Option<&OsStr>,
    config_value: Option<&str>,
    global_value: Option<&str>,
) -> LoadedManifest {
    classify_by(
        root,
        gemfile_env,
        config_value,
        global_value,
        same_dir_on_disk,
    )
}

/// [`classify`] of an app config value for a `root` that only stands in
/// for a project not on this disk (an in-memory view): paths compare
/// lexically, never through this host's directories.
pub(crate) fn classify_lexical(root: &Path, config_value: Option<&str>) -> LoadedManifest {
    classify_by(root, None, config_value, None, |a, b| a == b)
}

fn classify_by(
    root: &Path,
    gemfile_env: Option<&OsStr>,
    config_value: Option<&str>,
    global_value: Option<&str>,
    same_dir: SameDir,
) -> LoadedManifest {
    let env = gemfile_env.filter(|v| !v.is_empty()).map(PathBuf::from);
    let config = config_value.filter(|v| !v.is_empty()).map(PathBuf::from);
    let global = global_value.filter(|v| !v.is_empty()).map(PathBuf::from);
    let env_keeps_root = |env: &Path| {
        let dir = resolve_against(root, env).and_then(|p| p.parent().map(Path::to_path_buf));
        match (dir, resolve_against(root, Path::new(""))) {
            (Some(dir), Some(root)) => same_dir(&dir, &root),
            _ => false,
        }
    };
    let (value, by) = match (env, config) {
        (Some(env), Some(config)) if env_keeps_root(&env) => (config, GemfileSetting::AppConfig),
        (Some(env), _) => (env, GemfileSetting::Env),
        (None, Some(config)) => (config, GemfileSetting::AppConfig),
        // Settings#[] stops at a present empty value, so the global tier
        // is shadowed. configure_custom_gemfile only exports non-empty
        // values, leaving an existing non-empty env value in force above.
        (None, None) if gemfile_env.is_some() || config_value.is_some() => {
            return LoadedManifest::Default;
        }
        (None, None) => match global {
            Some(global) => (global, GemfileSetting::GlobalConfig),
            None => return LoadedManifest::Default,
        },
    };
    let display = value.display().to_string();
    let target = resolve_against(root, &value);
    let root = resolve_against(root, Path::new(""));
    if let (Some(target), Some(root)) = (target, root) {
        let manifest = ["Gemfile", "gems.rb"]
            .into_iter()
            .find(|m| target.file_name() == Some(OsStr::new(m)));
        if let Some(manifest) = manifest {
            if same_entry(&target, &root.join(manifest), same_dir) {
                return LoadedManifest::Configured { manifest, by };
            }
        }
    }
    LoadedManifest::Unsupported { value: display, by }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1477: bundler 4's Gemfile `lockfile` call, in every spelling a
    /// Gemfile uses; anything not a plain literal fails closed.
    #[test]
    fn gemfile_lockfile_reads_the_dsl_call() {
        let path = |v: &str| Some(GemfileLockfile::Path(v.into()));
        let other = |v: &str| Some(GemfileLockfile::Other(v.into()));
        assert_eq!(
            gemfile_lockfile("source \"https://rubygems.org\"\ngem \"rack\"\n"),
            None
        );
        assert_eq!(
            gemfile_lockfile("lockfile \"custom.lock\"\nsource \"https://rubygems.org\"\n"),
            path("custom.lock")
        );
        assert_eq!(
            gemfile_lockfile("lockfile 'custom.lock' # why\n"),
            path("custom.lock")
        );
        assert_eq!(
            gemfile_lockfile("lockfile(\"custom.lock\")\r\n"),
            path("custom.lock")
        );
        assert_eq!(
            gemfile_lockfile("lockfile( 'a/b.lock' )\n"),
            path("a/b.lock")
        );
        assert_eq!(
            gemfile_lockfile("group :dev do\n  lockfile \"x.lock\"\nend\n"),
            path("x.lock")
        );
        // Two identical calls are one answer; disagreeing ones are not.
        assert_eq!(
            gemfile_lockfile("lockfile \"a\"\nlockfile \"a\"\n"),
            path("a")
        );
        assert_eq!(
            gemfile_lockfile("lockfile \"a\"\nlockfile \"b\"\n"),
            other("lockfile \"b\"")
        );
        // Bundler reads and writes no lock, or the value is not static.
        assert_eq!(
            gemfile_lockfile("lockfile false\n"),
            other("lockfile false")
        );
        assert_eq!(
            gemfile_lockfile("lockfile ENV.fetch(\"L\")\n"),
            other("lockfile ENV.fetch(\"L\")")
        );
        assert_eq!(
            gemfile_lockfile("lockfile \"#{x}.lock\"\n"),
            other("lockfile \"#{x}.lock\"")
        );
        assert_eq!(
            gemfile_lockfile("lockfile \"x.lock\" if ENV[\"CI\"]\n"),
            other("lockfile \"x.lock\" if ENV[\"CI\"]")
        );
        // `lockfile nil` replaces the CLI's lock with none at all (bundler
        // 4's `Dsl.evaluate` seeds `@lockfile` with it first).
        assert_eq!(gemfile_lockfile("lockfile nil\n"), other("lockfile nil"));
        // A call later in a line, which a statement read cannot pin down.
        for text in [
            "group(:ci) { lockfile \"ci.lock\" }\n",
            "source \"https://rubygems.org\"; lockfile \"custom.lock\"\n",
            "ENV[\"CI\"] && lockfile(\"ci.lock\")\n",
            "if ENV[\"CI\"] then lockfile \"a\" end\n",
        ] {
            assert!(
                matches!(gemfile_lockfile(text), Some(GemfileLockfile::Other(_))),
                "{text:?}"
            );
        }
        // Ruby skips a leading BOM.
        assert_eq!(
            gemfile_lockfile("\u{feff}lockfile \"custom.lock\"\n"),
            path("custom.lock")
        );
        // Not calls: comments, strings, heredoc bodies, the data section, a
        // variable (assigned, compared, a receiver), a symbol or method of
        // that name, a longer name.
        for text in [
            "# lockfile \"x\"\n",
            "=begin\nlockfile \"x\"\n=end\n",
            "lockfile = \"x\"\n",
            "lockfile=\"x\"\n",
            "lockfile ||= \"x\"\n",
            "lockfile += \"x\"\n",
            "lockfile == other\n",
            "lockfile.freeze\n",
            "lockfiles \"x\"\n",
            "gem \"lockfile\"\n",
            "gem \"x\", require: \"lockfile\" # lockfile \"y\"\n",
            "x = :lockfile\n",
            "Bundler.lockfile\n",
            "puts <<~TXT\n  lockfile \"x\"\nTXT\n",
            "puts <<-'TXT'\nlockfile \"x\"\n  TXT\n",
            "gem \"rack\"\n__END__\nlockfile \"x\"\n",
        ] {
            assert_eq!(gemfile_lockfile(text), None, "{text:?}");
        }
        // Code after a heredoc closes is read again.
        assert_eq!(
            gemfile_lockfile("puts <<~TXT\n  hi\nTXT\nlockfile \"x\"\n"),
            path("x")
        );
    }

    #[test]
    fn eval_gemfile_paths_reads_literal_paths() {
        assert_eq!(
            eval_gemfile_paths(
                "eval_gemfile \"Gemfile.common\"\neval_gemfile('a/b.rb')\n\
                 eval_gemfile File.join(x)\n# eval_gemfile \"c\"\n"
            ),
            vec!["Gemfile.common".to_string(), "a/b.rb".to_string()]
        );
    }

    /// #1477: the Gemfile call outranks the `BUNDLE_LOCKFILE` tiers, as
    /// bundler 4's `Dsl#to_definition` does; naming the pair's own lock is a
    /// no-op and anything else is refused with the call's own remedy.
    #[test]
    fn with_gemfile_lockfile_accepts_only_the_pairs_own_lock() {
        let call = |v: &str| GemfileLockfile::Path(v.into());
        let m = LoadedManifest::Default.with_gemfile_lockfile(&root(), &call("custom.lock"), false);
        assert_eq!(
            m,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::GemfileCall,
            }
        );
        assert_eq!(m.pair(false), None);
        let detail = m.unsupported_detail().unwrap();
        assert!(detail.contains("custom.lock"), "{detail}");
        assert!(detail.contains("remove the `lockfile` call"), "{detail}");
        for own in ["Gemfile.lock", "./Gemfile.lock", "/proj/Gemfile.lock"] {
            assert_eq!(
                LoadedManifest::Default.with_gemfile_lockfile(&root(), &call(own), false),
                LoadedManifest::Default,
                "{own}"
            );
        }
        // With a gems.rb the pair's lock is gems.locked.
        assert!(matches!(
            LoadedManifest::Default.with_gemfile_lockfile(&root(), &call("Gemfile.lock"), true),
            LoadedManifest::UnsupportedLockfile { .. }
        ));
        assert_eq!(
            LoadedManifest::Default.with_gemfile_lockfile(&root(), &call("gems.locked"), true),
            LoadedManifest::Default
        );
        let off = GemfileLockfile::Other("lockfile false".into());
        assert_eq!(
            LoadedManifest::Default.with_gemfile_lockfile(&root(), &off, false),
            LoadedManifest::UnsupportedLockfile {
                value: "lockfile false".into(),
                by: GemfileSetting::GemfileCall,
            }
        );
        // An unsupported manifest stays the answer.
        let unsupported = classify(&root(), None, Some("Gemfile.next"), None);
        assert_eq!(
            unsupported
                .clone()
                .with_gemfile_lockfile(&root(), &call("custom.lock"), false),
            unsupported
        );
    }

    fn root() -> PathBuf {
        std::path::absolute("/proj").unwrap()
    }

    #[test]
    fn no_setting_is_bundlers_default_discovery() {
        let m = classify(&root(), None, None, None);
        assert_eq!(m, LoadedManifest::Default);
        assert_eq!(m.pair(true), Some(("gems.rb", "gems.locked")));
        assert_eq!(m.pair(false), Some(("Gemfile", "Gemfile.lock")));
        // An empty value is unset, as in bundler.
        assert_eq!(
            classify(&root(), Some(OsStr::new("")), Some(""), None),
            LoadedManifest::Default
        );
    }

    #[test]
    fn empty_higher_tiers_shadow_global_but_preserve_a_nonempty_environment() {
        for (env, config) in [(Some(""), None), (None, Some("")), (Some(""), Some(""))] {
            assert_eq!(
                classify(&root(), env.map(OsStr::new), config, Some("Gemfile.next")),
                LoadedManifest::Default
            );
        }
        // configure_custom_gemfile does not export the empty local value.
        assert_eq!(
            classify(
                &root(),
                Some(OsStr::new("Gemfile")),
                Some(""),
                Some("Gemfile.next")
            ),
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
        for env in ["Gemfile.next", "../other/Gemfile"] {
            assert_eq!(
                classify(&root(), Some(OsStr::new(env)), Some(""), Some("gems.rb")),
                LoadedManifest::Unsupported {
                    value: env.into(),
                    by: GemfileSetting::Env
                }
            );
        }
        // A non-empty local setting still wins over an empty environment.
        assert_eq!(
            classify(
                &root(),
                Some(OsStr::new("")),
                Some("gems.rb"),
                Some("Gemfile.next")
            ),
            LoadedManifest::Configured {
                manifest: "gems.rb",
                by: GemfileSetting::AppConfig
            }
        );
    }

    #[test]
    fn config_naming_another_manifest_is_unsupported() {
        let m = classify(&root(), None, Some("Gemfile.next"), None);
        assert_eq!(
            m,
            LoadedManifest::Unsupported {
                value: "Gemfile.next".into(),
                by: GemfileSetting::AppConfig
            }
        );
        assert_eq!(m.pair(false), None);
        assert!(m.unsupported_detail().unwrap().contains("Gemfile.next"));
    }

    #[test]
    fn config_naming_the_default_spellings_selects_that_pair() {
        // `bundle config set --local gemfile Gemfile` beside a gems.rb:
        // bundler loads Gemfile + Gemfile.lock, not gems.rb.
        let m = classify(&root(), None, Some("Gemfile"), None);
        assert_eq!(m.pair(true), Some(("Gemfile", "Gemfile.lock")));
        let m = classify(&root(), None, Some("./gems.rb"), None);
        assert_eq!(m.pair(false), Some(("gems.rb", "gems.locked")));
        let abs = root().join("Gemfile");
        let m = classify(&root(), None, Some(abs.to_str().unwrap()), None);
        assert_eq!(m.pair(true), Some(("Gemfile", "Gemfile.lock")));
    }

    /// The app config wins over the environment, as in `Bundler::Settings`
    /// (local config has a higher priority than ENV, and `Bundler::CLI`
    /// re-exports the winning `gemfile` setting into `BUNDLE_GEMFILE`):
    /// `bundle config set --local gemfile Gemfile.next` plus an exported
    /// `BUNDLE_GEMFILE=Gemfile` makes bundler load `Gemfile.next` (#507).
    #[test]
    fn config_wins_over_env_like_bundler_settings() {
        let m = classify(
            &root(),
            Some(OsStr::new("Gemfile")),
            Some("Gemfile.next"),
            None,
        );
        assert_eq!(
            m,
            LoadedManifest::Unsupported {
                value: "Gemfile.next".into(),
                by: GemfileSetting::AppConfig
            }
        );
        // The remedy names the setting bundler actually uses.
        let detail = m.unsupported_detail().unwrap();
        assert!(
            detail.contains("bundle config unset --local gemfile"),
            "{detail}"
        );
        // Both naming supported spellings: the config's pair is wired.
        let m = classify(&root(), Some(OsStr::new("gems.rb")), Some("Gemfile"), None);
        assert_eq!(
            m,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::AppConfig
            }
        );
        let m = classify(&root(), Some(OsStr::new("Gemfile")), Some("gems.rb"), None);
        assert_eq!(m.pair(false), Some(("gems.rb", "gems.locked")));
    }

    /// The environment applies when the app config sets nothing, and a
    /// relative value is read against the project root even when
    /// socket-patch runs elsewhere with `--cwd` (Bugbot on #431:
    /// `BUNDLE_GEMFILE=Gemfile` must select the project's Gemfile, not a
    /// file under the process cwd).
    #[test]
    fn env_applies_without_config_and_is_anchored_at_the_project_root() {
        let m = classify(&root(), Some(OsStr::new("Gemfile")), None, None);
        assert_eq!(
            m,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
        let m = classify(&root(), Some(OsStr::new("Gemfile.next")), None, None);
        assert!(matches!(
            m,
            LoadedManifest::Unsupported {
                by: GemfileSetting::Env,
                ..
            }
        ));
    }

    /// An environment `BUNDLE_GEMFILE` in ANOTHER directory moves bundler's
    /// root there (`Bundler.root` is the Gemfile's directory), so bundler
    /// reads that root's app config, never this project's: the project's
    /// `.bundle/config` cannot win, and the run refuses on the env value.
    #[test]
    fn env_gemfile_in_another_directory_is_never_overridden_by_project_config() {
        for env in ["../other/Gemfile", "sub/Gemfile", "/elsewhere/Gemfile"] {
            let m = classify(&root(), Some(OsStr::new(env)), Some("Gemfile"), None);
            assert_eq!(
                m,
                LoadedManifest::Unsupported {
                    value: env.into(),
                    by: GemfileSetting::Env
                },
                "{env}"
            );
        }
        // An absolute env value naming the root's own directory is the
        // same root: the config still wins.
        let abs = root().join("Gemfile.next");
        let m = classify(&root(), Some(abs.as_os_str()), Some("Gemfile"), None);
        assert_eq!(m.pair(false), Some(("Gemfile", "Gemfile.lock")));
    }

    /// The refusal names the remedy for the knob that set it: unsetting the
    /// environment variable does nothing to a `.bundle/config` setting.
    #[test]
    fn unsupported_detail_names_the_knob_that_set_it() {
        let env = classify(&root(), Some(OsStr::new("Gemfile.next")), None, None);
        let env = env.unsupported_detail().unwrap();
        assert!(env.contains("unset BUNDLE_GEMFILE"), "{env}");
        let config = classify(&root(), None, Some("Gemfile.next"), None);
        let config = config.unsupported_detail().unwrap();
        assert!(
            config.contains("bundle config unset --local gemfile"),
            "{config}"
        );
        assert!(!config.contains("unset BUNDLE_GEMFILE"), "{config}");
    }

    #[test]
    fn a_manifest_in_another_directory_is_unsupported() {
        let m = classify(&root(), None, Some("../other/Gemfile"), None);
        assert!(matches!(m, LoadedManifest::Unsupported { .. }));
        let m = classify(&root(), None, Some("sub/Gemfile"), None);
        assert!(matches!(m, LoadedManifest::Unsupported { .. }));
    }

    /// #749: a configured lockfile is judged against the pair bundler
    /// loads; a manifest refusal stays the answer.
    #[test]
    fn with_lockfile_accepts_only_the_pairs_own_lock() {
        let unset =
            classify(&root(), None, None, None).with_lockfile(&root(), None, None, None, false);
        assert_eq!(unset, LoadedManifest::Default);
        let own = classify(&root(), None, None, None).with_lockfile(
            &root(),
            Some(OsStr::new("Gemfile.lock")),
            None,
            None,
            false,
        );
        assert_eq!(own, LoadedManifest::Default);
        let custom = classify(&root(), None, None, None).with_lockfile(
            &root(),
            None,
            Some("custom.lock"),
            None,
            false,
        );
        assert_eq!(
            custom,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::AppConfig
            }
        );
        let detail = custom.unsupported_detail().unwrap();
        assert!(detail.contains("custom.lock"), "{detail}");
        assert!(
            detail.contains("bundle config unset --local lockfile"),
            "{detail}"
        );
        // The other pair's lock is not what bundler loads with this manifest.
        let configured = classify(&root(), None, Some("Gemfile"), None).with_lockfile(
            &root(),
            Some(OsStr::new("gems.locked")),
            None,
            None,
            true,
        );
        assert!(matches!(
            configured,
            LoadedManifest::UnsupportedLockfile {
                by: GemfileSetting::Env,
                ..
            }
        ));
        assert!(configured
            .unsupported_detail()
            .unwrap()
            .contains("unset BUNDLE_LOCKFILE"));
        // An unsupported manifest keeps its own refusal.
        let manifest = classify(&root(), None, Some("Gemfile.next"), None).with_lockfile(
            &root(),
            Some(OsStr::new("custom.lock")),
            None,
            None,
            false,
        );
        assert!(matches!(manifest, LoadedManifest::Unsupported { .. }));
        // `bundle config set --global lockfile` is the lowest tier (#577's
        // global file feeds `Bundler.settings[:lockfile]` too).
        let global = classify(&root(), None, None, None).with_lockfile(
            &root(),
            None,
            None,
            Some("custom.lock"),
            false,
        );
        assert_eq!(
            global,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::GlobalConfig
            }
        );
        assert!(global
            .unsupported_detail()
            .unwrap()
            .contains("bundle config unset --global lockfile"));
        let shadowed = classify(&root(), None, None, None).with_lockfile(
            &root(),
            None,
            Some("Gemfile.lock"),
            Some("custom.lock"),
            false,
        );
        assert_eq!(shadowed, LoadedManifest::Default);
        // A present empty value stops at its tier like `Settings#[]`: the
        // global custom lock is shadowed and bundler uses the default one.
        for (env, config) in [(Some(OsStr::new("")), None), (None, Some(""))] {
            let cleared = classify(&root(), None, None, None).with_lockfile(
                &root(),
                env,
                config,
                Some("custom.lock"),
                false,
            );
            assert_eq!(cleared, LoadedManifest::Default, "{env:?} {config:?}");
        }
    }

    /// A project directory reached through a symlink (macOS `/tmp` →
    /// `/private/tmp`, a symlinked workspace): bundler expands
    /// `BUNDLE_GEMFILE` lexically and opens it through the OS, so a value
    /// spelling the root's own `Gemfile` through the link is that Gemfile,
    /// whichever side (the setting or `--cwd`) uses the link (#896).
    #[cfg(unix)]
    #[test]
    fn a_symlinked_spelling_of_the_root_is_the_roots_own_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real/app");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("Gemfile"), "").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();
        let link = tmp.path().join("link/app");
        let configured = |by| LoadedManifest::Configured {
            manifest: "Gemfile",
            by,
        };
        for (root, spelled) in [(&real, &link), (&link, &real)] {
            let value = spelled.join("Gemfile");
            // `BUNDLE_GEMFILE=$PWD/Gemfile` with a logical `$PWD`.
            assert_eq!(
                classify(root, Some(value.as_os_str()), None, None),
                configured(GemfileSetting::Env),
                "{root:?} {value:?}"
            );
            // `bundle config set --local gemfile "$PWD/Gemfile"`.
            assert_eq!(
                classify(root, None, value.to_str(), None),
                configured(GemfileSetting::AppConfig)
            );
            assert_eq!(
                classify(root, None, None, value.to_str()),
                configured(GemfileSetting::GlobalConfig)
            );
            // The env value keeps bundler's root (same directory), so the
            // app config still wins over it.
            let next = spelled.join("Gemfile.next");
            assert_eq!(
                classify(root, Some(next.as_os_str()), Some("Gemfile"), None),
                configured(GemfileSetting::AppConfig)
            );
            // `BUNDLE_LOCKFILE` naming the pair's own lock the same way.
            let lock = spelled.join("Gemfile.lock");
            assert_eq!(
                classify(root, None, None, None).with_lockfile(
                    root,
                    Some(lock.as_os_str()),
                    None,
                    None,
                    false
                ),
                LoadedManifest::Default
            );
            // Another file in the same directory is still another manifest.
            assert!(matches!(
                classify(root, Some(next.as_os_str()), None, None),
                LoadedManifest::Unsupported { .. }
            ));
        }
    }

    /// An in-memory view's root only stands in for a project that is not on
    /// this disk, so its paths never resolve through this host's
    /// directories: a symlinked spelling stays another manifest there.
    #[cfg(unix)]
    #[test]
    fn the_lexical_variants_never_read_this_hosts_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real/app");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("link")).unwrap();
        let link = tmp.path().join("link/app");
        let value = link.join("Gemfile");
        assert_eq!(
            classify_lexical(&real, value.to_str()),
            LoadedManifest::Unsupported {
                value: value.display().to_string(),
                by: GemfileSetting::AppConfig
            }
        );
        assert_eq!(
            classify_lexical(&real, Some("Gemfile")),
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::AppConfig
            }
        );
        let lock = link.join("Gemfile.lock");
        assert!(matches!(
            LoadedManifest::Default.with_lockfile_lexical(&real, lock.to_str(), false),
            LoadedManifest::UnsupportedLockfile { .. }
        ));
    }

    /// Only the DIRECTORY is resolved: a root `Gemfile` that is itself a
    /// symlink to a manifest elsewhere does not make that manifest the
    /// project's, since bundler's root (and its lock) follow the spelled
    /// directory, not the link target.
    #[cfg(unix)]
    #[test]
    fn a_manifest_the_roots_gemfile_links_to_is_still_another_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("app");
        let other = tmp.path().join("other");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("Gemfile"), "").unwrap();
        std::os::unix::fs::symlink(other.join("Gemfile"), root.join("Gemfile")).unwrap();
        let value = other.join("Gemfile");
        assert_eq!(
            classify(&root, Some(value.as_os_str()), None, None),
            LoadedManifest::Unsupported {
                value: value.display().to_string(),
                by: GemfileSetting::Env
            }
        );
    }

    #[test]
    fn config_lockfile_reads_bundlers_own_spelling() {
        assert_eq!(
            config_lockfile("---\nBUNDLE_LOCKFILE: \"custom.lock\"\n"),
            Some("custom.lock".into())
        );
        assert_eq!(
            config_lockfile("---\nBUNDLE_LOCKFILE: \"\"\n"),
            Some(String::new())
        );
        assert_eq!(config_lockfile("---\nBUNDLE_GEMFILE: \"x\"\n"), None);
    }

    #[test]
    fn config_gemfile_reads_bundlers_own_spelling() {
        assert_eq!(
            config_gemfile(
                "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_GEMFILE: \"Gemfile.next\"\n"
            ),
            Some("Gemfile.next".into())
        );
        assert_eq!(
            config_gemfile("---\nBUNDLE_GEMFILE: \"\"\n"),
            Some("".into())
        );
        assert_eq!(config_gemfile("---\nBUNDLE_PATH: \"x\"\n"), None);
    }
}
