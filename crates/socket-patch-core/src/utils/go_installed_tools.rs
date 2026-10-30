//! Go tools already built from a module a global apply patched in place
//! (#422).
//!
//! `--global` / `--global-prefix` patches `$GOMODCACHE/<module>@<version>/`
//! in place. That changes what the NEXT build compiles; a tool installed
//! earlier with `go install pkg@version` is a statically linked binary that
//! keeps the vulnerable code until it is rebuilt. Go records the module
//! versions a binary was built from in its build info, so
//! `go version -m <dir>` names every installed tool that embeds a patched
//! `module@version`. A binary older than the patched files was built from
//! the unpatched bytes; `go install` of the same version rebuilds it from
//! the patched cache (Go's build cache keys on source content).
//!
//! Only the directories `go install` writes to are searched: `$GOBIN`, else
//! `bin/` of every `GOPATH` entry (default `~/go`), plus `<root>/bin` for a
//! module cache at `<root>/pkg/mod` (a `--global-prefix` tree). A binary
//! copied elsewhere is out of reach; the warning says so.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Run-warning code, and the VEX omission reason for the same condition.
pub const STALE_WARNING: &str = "go_installed_tool_stale";

/// A `go version -m` budget per directory: it only reads files.
const VERSION_BUDGET: Duration = Duration::from_secs(60);

/// One Go binary's build info, as `go version -m` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoBinary {
    pub path: PathBuf,
    /// The main package path (`path` line), e.g. `example.com/tool/cmd/x`.
    pub main_package: Option<String>,
    /// The main module's version (`mod` line); `(devel)` for a local build.
    pub main_version: Option<String>,
    /// Every `(module, version)` the binary compiled from the module cache:
    /// the main module and each dependency, after `=>` replacements.
    pub modules: Vec<(String, String)>,
}

/// A module whose cache copy a global apply rewrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchedModule {
    pub module: String,
    pub version: String,
    /// When the patched files were written: a binary older than this was
    /// built from the unpatched bytes.
    pub patched_at: SystemTime,
}

/// An installed tool still running the unpatched module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleTool {
    pub binary: PathBuf,
    pub module: String,
    pub version: String,
    /// `go install <pkg>@<version>`, or `None` for a binary built from a
    /// local checkout (no version to reinstall).
    pub reinstall: Option<String>,
}

impl StaleTool {
    /// The warning detail: which tool, why, and the remedy.
    pub fn detail(&self) -> String {
        let remedy = match &self.reinstall {
            Some(cmd) => format!("run `{cmd}` to rebuild it"),
            None => "rebuild it from its source".to_string(),
        };
        format!(
            "{} was built with `go install` from the unpatched {}@{} and keeps running that \
             code; patching the module cache only changes future builds: {remedy}",
            self.binary.display(),
            self.module,
            self.version
        )
    }
}

/// The warning detail for `dirs` whose tools `go version -m` could not
/// list (`go` not on `PATH`, or the run failed or timed out).
pub fn unchecked_detail(patched: &[PatchedModule], dirs: &[PathBuf]) -> String {
    let modules: Vec<String> = patched
        .iter()
        .map(|p| format!("{}@{}", p.module, p.version))
        .collect();
    let dirs: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
    format!(
        "could not run `go version -m` to check the tools installed in {} for {}; a tool \
         built with `go install` before this patch keeps running the unpatched code until \
         you rebuild it with `go install <pkg>@<version>`",
        dirs.join(", "),
        modules.join(", ")
    )
}

impl PatchedModule {
    /// The patched module of `purl` whose files this run writes (or, in a
    /// dry run, would write) now: every tool already built from it is
    /// stale. `None` for a non-Go purl.
    pub fn written_now(purl: &str) -> Option<Self> {
        let (module, version) = crate::utils::purl::parse_golang_purl(purl)?;
        Some(Self {
            module: module.into_owned(),
            version: version.into_owned(),
            patched_at: SystemTime::now(),
        })
    }

    /// The patched module of `purl` whose cache copy is `dir`, dated by the
    /// newest of the patch record's `files` there (keys may carry the
    /// API's `package/` prefix), or `None` for a non-Go purl or when no
    /// patched file can be read.
    pub fn of_copy<'a>(
        purl: &str,
        dir: &Path,
        files: impl IntoIterator<Item = &'a str>,
    ) -> Option<Self> {
        let (module, version) = crate::utils::purl::parse_golang_purl(purl)?;
        let patched_at = files
            .into_iter()
            .map(crate::patch::apply::normalize_file_path)
            .filter_map(|f| std::fs::metadata(dir.join(f)).ok()?.modified().ok())
            .max()?;
        Some(Self {
            module: module.into_owned(),
            version: version.into_owned(),
            patched_at,
        })
    }
}

/// Where to look for the tools built from a set of module cache copies.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BinDirs {
    /// The directories `go install` writes to, deduplicated.
    pub dirs: Vec<PathBuf>,
    /// Copies in a cache that is neither the user's own nor at
    /// `<root>/pkg/mod` (a bare `--global-prefix` module cache): no
    /// `go install` directory is known for them.
    pub unlocated: Vec<PathBuf>,
}

/// The directories `go install` writes to, for module cache copies at
/// `module_dirs`, reading the process environment.
pub fn bin_dirs(module_dirs: &[&Path]) -> BinDirs {
    // A relative `--global-prefix` resolves against the working directory.
    let module_dirs: Vec<PathBuf> = module_dirs
        .iter()
        .map(|d| std::path::absolute(d).unwrap_or_else(|_| d.to_path_buf()))
        .collect();
    let module_dirs: Vec<&Path> = module_dirs.iter().map(PathBuf::as_path).collect();
    bin_dirs_with(
        &module_dirs,
        &crate::utils::go_env::go_env,
        crate::utils::fs::home_dir(),
    )
}

/// [`bin_dirs`] with an injected Go setting lookup and home directory.
///
/// The user's own `$GOBIN` / `GOPATH` bin directories are searched only
/// for copies in the user's own module cache: a `--global-prefix` tree is
/// some other cache, which the user's tools were never built from.
pub fn bin_dirs_with(
    module_dirs: &[&Path],
    go_env: &dyn Fn(&str) -> Option<String>,
    home: Option<PathBuf>,
) -> BinDirs {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut unlocated: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if p.is_absolute() && !dirs.contains(&p) {
            dirs.push(p);
        }
    };
    let user_cache = crate::utils::go_env::gomodcache(go_env, home.as_deref());
    let gopaths: Vec<PathBuf> = crate::utils::go_env::gopath_entries(go_env, home.as_deref())
        .into_iter()
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    let in_user_cache = |d: &Path| user_cache.as_ref().is_some_and(|c| d.starts_with(c));
    if module_dirs.iter().any(|d| in_user_cache(d)) {
        match go_env("GOBIN") {
            Some(gobin) => push(PathBuf::from(gobin)),
            None => gopaths.iter().for_each(|g| push(g.join("bin"))),
        }
    }
    // A cache at `<root>/pkg/mod/<module>@<version>`: `<root>` is the
    // GOPATH that `go install` used with it. The outermost `pkg/mod`: a
    // module path may itself contain one.
    for dir in module_dirs {
        if let Some(root) = dir
            .ancestors()
            .filter(|a| a.ends_with(Path::new("pkg").join("mod")))
            .last()
            .and_then(|m| m.parent()?.parent())
        {
            if root.is_absolute() {
                push(root.join("bin"));
            } else if !in_user_cache(dir) {
                unlocated.push(dir.to_path_buf());
            }
        } else if !in_user_cache(dir) {
            unlocated.push(dir.to_path_buf());
        }
    }
    BinDirs { dirs, unlocated }
}

/// The warning detail for cache copies no `go install` directory is known
/// for.
pub fn unlocated_detail(dirs: &[PathBuf]) -> String {
    let dirs: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
    format!(
        "no `go install` directory is known for the module cache copies at {} (not under \
         your GOMODCACHE or a `<root>/pkg/mod`), so the tools built from them were not \
         checked; a tool built with `go install` before this patch keeps running the \
         unpatched code until you rebuild it with `go install <pkg>@<version>`",
        dirs.join(", ")
    )
}

/// Parse `go version -m` output: one `<path>: <go version>` header per
/// binary, then tab-indented `path` / `mod` / `dep` / `=>` / `build` lines.
pub fn parse_version_m(output: &str) -> Vec<GoBinary> {
    let mut out: Vec<GoBinary> = Vec::new();
    for line in output.lines() {
        let Some(rest) = line.strip_prefix('\t') else {
            // `<path>: go1.x` — the path itself may contain `: `, the Go
            // version never does.
            if let Some((path, _go)) = line.rsplit_once(": ") {
                out.push(GoBinary {
                    path: PathBuf::from(path),
                    main_package: None,
                    main_version: None,
                    modules: Vec::new(),
                });
            }
            continue;
        };
        let Some(bin) = out.last_mut() else {
            continue;
        };
        let fields: Vec<&str> = rest.split('\t').collect();
        match fields.as_slice() {
            ["path", pkg, ..] => bin.main_package = Some(pkg.to_string()),
            ["mod", module, version, ..] => {
                bin.main_version = Some(version.to_string());
                bin.modules.push((module.to_string(), version.to_string()));
            }
            ["dep", module, version, ..] => {
                bin.modules.push((module.to_string(), version.to_string()))
            }
            // The module on the line before was replaced: the binary
            // compiled the replacement, never the original. A directory
            // replacement (empty version) never matches a patched module.
            ["=>", module, version, ..] => {
                bin.modules.pop();
                bin.modules.push((module.to_string(), version.to_string()));
            }
            ["=>", ..] => {
                bin.modules.pop();
            }
            _ => {}
        }
    }
    out
}

/// What `go version -m` found under a set of directories.
#[derive(Debug, Default)]
pub struct Inspection {
    pub binaries: Vec<GoBinary>,
    /// Directories holding files whose tools could not be listed: `go` is
    /// not on `PATH`, or its run failed or timed out.
    pub unchecked: Vec<PathBuf>,
}

/// The installed Go binaries under `dirs`. Missing and empty directories
/// are skipped. Blocking.
pub fn installed_binaries(dirs: &[PathBuf]) -> Inspection {
    let mut out = Inspection::default();
    let go = crate::utils::process::resolve_tool("go");
    for dir in dirs.iter().filter(|d| dir_has_entries(d)) {
        let Some(go) = &go else {
            out.unchecked.push(dir.clone());
            continue;
        };
        let mut cmd = crate::utils::process::command_for(go);
        // `go version` reads files only; keep a `toolchain` line in an
        // ambient go.mod or GOTOOLCHAIN from fetching another toolchain.
        cmd.arg("version")
            .arg("-m")
            .arg(dir)
            .current_dir(dir)
            .env("GOTOOLCHAIN", "local");
        match crate::utils::process::output_within(cmd, VERSION_BUDGET) {
            Ok(output) if output.status.success() => out
                .binaries
                .extend(parse_version_m(&String::from_utf8_lossy(&output.stdout))),
            _ => out.unchecked.push(dir.clone()),
        }
    }
    out
}

/// Every installed tool in `binaries` built from one of `patched` before it
/// was patched.
pub fn stale_tools(binaries: &[GoBinary], patched: &[PatchedModule]) -> Vec<StaleTool> {
    stale_tools_with(binaries, patched, &|p| {
        std::fs::metadata(p).ok()?.modified().ok()
    })
}

/// [`stale_tools`] with an injected binary mtime lookup.
pub fn stale_tools_with(
    binaries: &[GoBinary],
    patched: &[PatchedModule],
    built_at: &dyn Fn(&Path) -> Option<SystemTime>,
) -> Vec<StaleTool> {
    let mut out: Vec<StaleTool> = Vec::new();
    for bin in binaries {
        for p in patched {
            if !bin
                .modules
                .iter()
                .any(|(m, v)| *m == p.module && *v == p.version)
            {
                continue;
            }
            // An unreadable mtime is no evidence of a rebuild.
            if built_at(&bin.path).is_some_and(|t| t > p.patched_at) {
                continue;
            }
            // A local build has no version to reinstall: `(devel)`, or
            // (Go 1.24+) a VCS-stamped `+dirty` one.
            let reinstall = match (&bin.main_package, &bin.main_version) {
                (Some(pkg), Some(ver)) if ver.starts_with('v') && !ver.ends_with("+dirty") => {
                    Some(format!("go install {pkg}@{ver}"))
                }
                _ => None,
            };
            let tool = StaleTool {
                binary: bin.path.clone(),
                module: p.module.clone(),
                version: p.version.clone(),
                reinstall,
            };
            // Two cache copies of one module@version: one tool, one line.
            if !out.contains(&tool) {
                out.push(tool);
            }
        }
    }
    out
}

/// Check the installed tools for every patched module, whose cache copies
/// are `module_dirs`: the run warnings `(code, detail)` to report, and the
/// stale tools themselves.
pub async fn audit(
    patched: Vec<PatchedModule>,
    module_dirs: Vec<PathBuf>,
) -> (Vec<(String, String)>, Vec<StaleTool>) {
    if patched.is_empty() {
        return (Vec::new(), Vec::new());
    }
    crate::utils::fs::run_blocking(move || {
        let dirs: Vec<&Path> = module_dirs.iter().map(PathBuf::as_path).collect();
        let bins = bin_dirs(&dirs);
        let (mut warnings, stale) = audit_sync(&patched, &bins.dirs);
        if !bins.unlocated.is_empty() {
            warnings.push((STALE_WARNING.to_string(), unlocated_detail(&bins.unlocated)));
        }
        (warnings, stale)
    })
    .await
}

/// [`audit`] over the given `go install` directories. Blocking.
pub fn audit_sync(
    patched: &[PatchedModule],
    dirs: &[PathBuf],
) -> (Vec<(String, String)>, Vec<StaleTool>) {
    let inspection = installed_binaries(dirs);
    let stale = stale_tools(&inspection.binaries, patched);
    let mut warnings: Vec<(String, String)> = stale
        .iter()
        .map(|t| (STALE_WARNING.to_string(), t.detail()))
        .collect();
    if !inspection.unchecked.is_empty() {
        warnings.push((
            STALE_WARNING.to_string(),
            unchecked_detail(patched, &inspection.unchecked),
        ));
    }
    (warnings, stale)
}

fn dir_has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|mut rd| rd.next().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTPUT: &str = "\
/home/u/go/bin/tool: go1.24.7
\tpath\texample.com/tool
\tmod\texample.com/tool\tv1.0.0\th1:abc=
\tdep\texample.com/upstream\tv1.0.0\th1:def=
\tdep\texample.com/other\tv0.3.0\th1:ghi=
\t=>\texample.com/fork\tv0.3.1\th1:jkl=
\tdep\texample.com/local\tv1.2.0\t
\t=>\t../local\t\t
\tbuild\t-compiler=gc
/home/u/go/bin/dev: go1.24.7
\tpath\texample.com/dev/cmd/dev
\tmod\texample.com/dev\t(devel)\t
\tdep\texample.com/upstream\tv1.0.0\th1:def=
";

    fn bins() -> Vec<GoBinary> {
        parse_version_m(OUTPUT)
    }

    fn patched(module: &str, version: &str, at: u64) -> PatchedModule {
        PatchedModule {
            module: module.into(),
            version: version.into(),
            patched_at: SystemTime::UNIX_EPOCH + Duration::from_secs(at),
        }
    }

    #[test]
    fn parses_build_info_with_replacements() {
        let b = bins();
        assert_eq!(b.len(), 2);
        assert_eq!(b[0].path, PathBuf::from("/home/u/go/bin/tool"));
        assert_eq!(b[0].main_package.as_deref(), Some("example.com/tool"));
        assert_eq!(b[0].main_version.as_deref(), Some("v1.0.0"));
        assert_eq!(
            b[0].modules,
            vec![
                ("example.com/tool".into(), "v1.0.0".into()),
                ("example.com/upstream".into(), "v1.0.0".into()),
                ("example.com/fork".into(), "v0.3.1".into()),
                ("../local".into(), "".into()),
            ]
        );
        assert_eq!(b[1].main_version.as_deref(), Some("(devel)"));
    }

    #[test]
    fn a_tool_built_before_the_patch_is_stale_with_its_reinstall_command() {
        let at = |_: &Path| Some(SystemTime::UNIX_EPOCH + Duration::from_secs(100));
        let stale = stale_tools_with(
            &bins(),
            &[patched("example.com/upstream", "v1.0.0", 200)],
            &at,
        );
        assert_eq!(stale.len(), 2);
        assert_eq!(
            stale[0].reinstall.as_deref(),
            Some("go install example.com/tool@v1.0.0")
        );
        assert!(stale[0]
            .detail()
            .contains("run `go install example.com/tool@v1.0.0`"));
        // A local build has no version to reinstall.
        assert_eq!(stale[1].reinstall, None);
        assert!(stale[1].detail().contains("rebuild it from its source"));
    }

    #[test]
    fn a_tool_rebuilt_after_the_patch_is_not_stale() {
        let at = |_: &Path| Some(SystemTime::UNIX_EPOCH + Duration::from_secs(300));
        assert!(stale_tools_with(
            &bins(),
            &[patched("example.com/upstream", "v1.0.0", 200)],
            &at
        )
        .is_empty());
    }

    #[test]
    fn only_the_patched_version_and_unreplaced_modules_match() {
        let at = |_: &Path| None;
        let b = bins();
        assert!(
            stale_tools_with(&b, &[patched("example.com/upstream", "v1.0.1", 1)], &at).is_empty()
        );
        // Replaced away: the binary never compiled example.com/other.
        assert!(stale_tools_with(&b, &[patched("example.com/other", "v0.3.0", 1)], &at).is_empty());
        assert_eq!(
            stale_tools_with(&b, &[patched("example.com/fork", "v0.3.1", 1)], &at).len(),
            1
        );
        // The main module itself.
        assert_eq!(
            stale_tools_with(&b, &[patched("example.com/tool", "v1.0.0", 1)], &at).len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn bin_dirs_follow_gobin_then_gopath_then_home_and_the_cache_root() {
        let home = Some(PathBuf::from("/home/u"));
        let env = |vars: Vec<(&'static str, &'static str)>| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let user = Path::new("/home/u/go/pkg/mod/example.com/upstream@v1.0.0");
        assert_eq!(
            bin_dirs_with(&[user], &env(vec![("GOBIN", "/gobin")]), home.clone()).dirs,
            vec![PathBuf::from("/gobin"), PathBuf::from("/home/u/go/bin")]
        );
        assert_eq!(
            bin_dirs_with(
                &[Path::new("/a/pkg/mod/x@v1.0.0")],
                &env(vec![("GOPATH", "/a:/b")]),
                home.clone()
            )
            .dirs,
            vec![PathBuf::from("/a/bin"), PathBuf::from("/b/bin")]
        );
        assert_eq!(
            bin_dirs_with(&[user], &env(Vec::new()), home.clone()).dirs,
            vec![PathBuf::from("/home/u/go/bin")]
        );
        // A GOMODCACHE outside GOPATH: the user's tools, not `<root>/bin`.
        assert_eq!(
            bin_dirs_with(
                &[Path::new("/cache/x@v1.0.0")],
                &env(vec![("GOMODCACHE", "/cache")]),
                home.clone()
            )
            .dirs,
            vec![PathBuf::from("/home/u/go/bin")]
        );
        // An empty first GOPATH entry leaves go no module cache, so a
        // copy under a later entry is not in the user's cache: no GOBIN
        // (#1834).
        assert_eq!(
            bin_dirs_with(
                &[Path::new("/b/pkg/mod/x@v1.0.0")],
                &env(vec![("GOPATH", ":/b"), ("GOBIN", "/gobin")]),
                home.clone()
            )
            .dirs,
            vec![PathBuf::from("/b/bin")]
        );
        // A --global-prefix tree: never the user's own tools.
        assert_eq!(
            bin_dirs_with(
                &[Path::new("/img/gp/pkg/mod/x@v1.0.0")],
                &env(vec![("GOBIN", "/gobin")]),
                home.clone()
            )
            .dirs,
            vec![PathBuf::from("/img/gp/bin")]
        );
        // A module path that itself contains `pkg/mod`: the outermost one.
        assert_eq!(
            bin_dirs_with(
                &[Path::new("/img/gp/pkg/mod/github.com/foo/pkg/mod/x@v1.0.0")],
                &env(Vec::new()),
                home.clone()
            )
            .dirs,
            vec![PathBuf::from("/img/gp/bin")]
        );
        // A bare --global-prefix module cache: nowhere known to look.
        let bare = Path::new("/img/cache/x@v1.0.0");
        let found = bin_dirs_with(&[bare], &env(vec![("GOBIN", "/gobin")]), home.clone());
        assert_eq!(found.dirs, Vec::<PathBuf>::new());
        assert_eq!(found.unlocated, vec![bare.to_path_buf()]);
        assert!(unlocated_detail(&found.unlocated).contains("/img/cache/x@v1.0.0"));
        // A relative root has no usable bin directory: reported, not dropped.
        let rel = Path::new("gp/pkg/mod/x@v1.0.0");
        let found = bin_dirs_with(&[rel], &env(Vec::new()), home.clone());
        assert_eq!(found.dirs, Vec::<PathBuf>::new());
        assert_eq!(found.unlocated, vec![rel.to_path_buf()]);
        // bin_dirs itself resolves it against the working directory.
        let cwd = std::env::current_dir().unwrap();
        assert!(bin_dirs(&[rel]).dirs.contains(&cwd.join("gp").join("bin")));
    }

    #[test]
    fn a_dirty_local_build_gets_no_reinstall_command() {
        let mut b = bins();
        b[0].main_version = Some("v1.2.4-0.20240101120000-abcdef123456+dirty".into());
        let stale = stale_tools_with(
            &b[..1],
            &[patched("example.com/upstream", "v1.0.0", 1)],
            &|_| None,
        );
        assert_eq!(stale[0].reinstall, None);
    }

    #[test]
    fn a_copy_is_dated_by_its_patched_files_with_or_without_the_package_prefix() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("lib.go"), "x").unwrap();
        let purl = "pkg:golang/example.com/upstream@v1.0.0";
        for key in ["lib.go", "package/lib.go"] {
            let p = PatchedModule::of_copy(purl, dir.path(), [key]).expect(key);
            assert_eq!(
                (p.module.as_str(), p.version.as_str()),
                ("example.com/upstream", "v1.0.0")
            );
        }
        assert_eq!(PatchedModule::of_copy(purl, dir.path(), ["gone.go"]), None);
        assert_eq!(
            PatchedModule::of_copy("pkg:npm/x@1.0.0", dir.path(), ["lib.go"]),
            None
        );
    }

    #[test]
    fn an_unlistable_directory_is_reported_unchecked() {
        let dir = tempfile::tempdir().unwrap();
        // Not a Go binary: `go version -m` on the directory lists nothing,
        // which is a clean check; a missing `go` is not.
        std::fs::write(dir.path().join("tool"), "#!/bin/sh\n").unwrap();
        let (warnings, stale) = audit_sync(
            &[patched("example.com/upstream", "v1.0.0", 1)],
            &[dir.path().to_path_buf(), dir.path().join("missing")],
        );
        assert!(stale.is_empty());
        let go_on_path = crate::utils::process::resolve_tool("go").is_some();
        assert_eq!(warnings.len(), usize::from(!go_on_path), "{warnings:?}");
    }

    #[test]
    fn unchecked_detail_names_dirs_modules_and_remedy() {
        let d = unchecked_detail(
            &[patched("example.com/upstream", "v1.0.0", 1)],
            &[PathBuf::from("/home/u/go/bin")],
        );
        assert!(d.contains("/home/u/go/bin"));
        assert!(d.contains("example.com/upstream@v1.0.0"));
        assert!(d.contains("go install <pkg>@<version>"));
    }
}
