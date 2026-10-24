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

/// The warning detail when `go` itself can't be run to inspect `dirs`.
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

/// The newest modification time among `files` under `dir` (the patched
/// files of a module cache copy), or `None` when none can be read.
pub fn patched_at<'a>(dir: &Path, files: impl IntoIterator<Item = &'a str>) -> Option<SystemTime> {
    files
        .into_iter()
        .filter_map(|f| std::fs::metadata(dir.join(f)).ok()?.modified().ok())
        .max()
}

/// The directories `go install` writes to, for module cache copies at
/// `module_dirs`, reading the process environment.
pub fn bin_dirs(module_dirs: &[&Path]) -> Vec<PathBuf> {
    bin_dirs_with(
        module_dirs,
        &crate::utils::go_env::go_env,
        crate::utils::fs::home_dir(),
    )
}

/// [`bin_dirs`] with an injected Go setting lookup and home directory.
pub fn bin_dirs_with(
    module_dirs: &[&Path],
    go_env: &dyn Fn(&str) -> Option<String>,
    home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if p.is_absolute() && !dirs.contains(&p) {
            dirs.push(p);
        }
    };
    if let Some(gobin) = go_env("GOBIN").filter(|v| !v.is_empty()) {
        push(PathBuf::from(gobin));
    } else {
        match go_env("GOPATH").filter(|v| !v.is_empty()) {
            Some(gopath) => std::env::split_paths(&gopath)
                .filter(|p| !p.as_os_str().is_empty())
                .for_each(|p| push(p.join("bin"))),
            None => {
                if let Some(home) = home {
                    push(home.join("go").join("bin"));
                }
            }
        }
    }
    // A cache at `<root>/pkg/mod/<module>@<version>`: `<root>` is the
    // GOPATH that `go install` used with it.
    for dir in module_dirs {
        if let Some(root) = dir
            .ancestors()
            .find(|a| a.ends_with(Path::new("pkg").join("mod")))
            .and_then(|m| m.parent()?.parent())
        {
            push(root.join("bin"));
        }
    }
    dirs
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

/// The installed Go binaries under `dirs`, or `None` when `go` is not on
/// `PATH` (nothing can be checked). Missing directories are skipped.
/// Blocking.
pub fn installed_binaries(dirs: &[PathBuf]) -> Option<Vec<GoBinary>> {
    let go = crate::utils::process::resolve_tool("go")?;
    let mut out = Vec::new();
    for dir in dirs.iter().filter(|d| d.is_dir()) {
        let mut cmd = crate::utils::process::command_for(&go);
        // `go version` reads files only; keep a `toolchain` line in an
        // ambient go.mod or GOTOOLCHAIN from fetching another toolchain.
        cmd.arg("version")
            .arg("-m")
            .arg(dir)
            .current_dir(dir)
            .env("GOTOOLCHAIN", "local");
        let Ok(output) = crate::utils::process::output_within(cmd, VERSION_BUDGET) else {
            continue;
        };
        out.extend(parse_version_m(&String::from_utf8_lossy(&output.stdout)));
    }
    Some(out)
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
    let mut out = Vec::new();
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
            let reinstall = match (&bin.main_package, &bin.main_version) {
                (Some(pkg), Some(ver)) if ver.starts_with('v') => {
                    Some(format!("go install {pkg}@{ver}"))
                }
                _ => None,
            };
            out.push(StaleTool {
                binary: bin.path.clone(),
                module: p.module.clone(),
                version: p.version.clone(),
                reinstall,
            });
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
        audit_sync(&patched, &bin_dirs(&dirs))
    })
    .await
}

/// [`audit`] over the given `go install` directories. Blocking.
pub fn audit_sync(
    patched: &[PatchedModule],
    dirs: &[PathBuf],
) -> (Vec<(String, String)>, Vec<StaleTool>) {
    match installed_binaries(dirs) {
        Some(binaries) => {
            let stale = stale_tools(&binaries, patched);
            let warnings = stale
                .iter()
                .map(|t| (STALE_WARNING.to_string(), t.detail()))
                .collect();
            (warnings, stale)
        }
        None if dirs.iter().any(|d| dir_has_entries(d)) => (
            vec![(STALE_WARNING.to_string(), unchecked_detail(patched, dirs))],
            Vec::new(),
        ),
        None => (Vec::new(), Vec::new()),
    }
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
        let cache = PathBuf::from("/opt/gp/pkg/mod/example.com/upstream@v1.0.0");
        let env = |vars: Vec<(&'static str, &'static str)>| {
            move |k: &str| {
                vars.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(
            bin_dirs_with(&[&cache], &env(vec![("GOBIN", "/gobin")]), home.clone()),
            vec![PathBuf::from("/gobin"), PathBuf::from("/opt/gp/bin")]
        );
        assert_eq!(
            bin_dirs_with(&[], &env(vec![("GOPATH", "/a:/b")]), home.clone()),
            vec![PathBuf::from("/a/bin"), PathBuf::from("/b/bin")]
        );
        assert_eq!(
            bin_dirs_with(
                &[Path::new("/home/u/go/pkg/mod/x@v1.0.0")],
                &env(Vec::new()),
                home
            ),
            vec![PathBuf::from("/home/u/go/bin")]
        );
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
