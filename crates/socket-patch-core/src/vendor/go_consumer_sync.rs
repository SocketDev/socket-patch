//! Does the consumer project still build after a socket `replace` was wired
//! in or removed? (#343, #618)
//!
//! Every Go mode (`apply`, `vendor`, `scan --mode hosted`) redirects a module
//! by editing the consumer's `go.mod` `replace` directives. Two pieces of the
//! consumer's state are derived from `go.mod` and the module graph, and the
//! go command refuses to build when they disagree with it:
//!
//! * **`vendor/modules.txt`** (#343). With a committed `vendor/` directory
//!   (`go mod vendor`, or `go work vendor` for a workspace) go builds with
//!   `-mod=vendor` and checks that `modules.txt` records every `go.mod`
//!   `replace`: "is replaced in go.mod, but not marked as replaced in
//!   vendor/modules.txt" after a redirect, and "is marked as replaced in
//!   vendor/modules.txt, but not replaced in go.mod" after a rollback.
//!   Re-running `go mod vendor` copies the patched tree into `vendor/` and
//!   records the replacement.
//! * **Requirements raised by the patched module's own `go.mod`** (#618). A
//!   security fix often bumps a dependency of the patched module. go reads
//!   the replacement's `go.mod`, so the selected version of that dependency
//!   rises above what the consumer's `go.mod` lists, and the default
//!   `-mod=readonly` build fails with "updates to go.mod needed" (or
//!   "missing go.sum entry" for an added requirement) until `go mod tidy`
//!   updates `go.mod` and `go.sum`.
//!
//! socket-patch does not regenerate either file itself: `go mod vendor` and
//! `go mod tidy` need the go toolchain and every module in the graph, and
//! rewrite files the user owns. Instead [`audit`] reports each disagreement
//! with the command that fixes it; the commands surface the result as a run
//! warning, and `apply --check` treats it as drift.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::utils::fs::read_regular_to_string;
use crate::vendor::go_mod_edit::{self, ReplaceEntry};

/// Warning code for a `vendor/modules.txt` that disagrees with a socket
/// `replace` in `go.mod`.
pub const VENDOR_MODULES_TXT_CODE: &str = "go_vendor_modules_txt_out_of_sync";
/// Warning code for a patched module whose `go.mod` requires a newer (or a
/// new) dependency than the consumer's `go.mod` lists.
pub const REQUIREMENTS_CODE: &str = "go_requirements_out_of_sync";

/// One way the consumer's derived Go state disagrees with the socket
/// `replace` directives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GoSyncIssue {
    /// `modules.txt` lacks the replacement a socket `replace` in `go.mod`
    /// declares (`stale: false`), or records a socket replacement `go.mod`
    /// no longer has (`stale: true`).
    VendorModulesTxt {
        module: String,
        /// Project-relative path of the `modules.txt` go checks.
        modules_txt: String,
        /// `go mod vendor` or `go work vendor`.
        command: &'static str,
        stale: bool,
    },
    /// The patched copy of `module` requires `dep` at `required`, above the
    /// `listed` version in the consumer's `go.mod` (`None`: not listed).
    Requirement {
        module: String,
        dep: String,
        required: String,
        listed: Option<String>,
    },
}

impl GoSyncIssue {
    /// The stable warning / drift code.
    pub fn code(&self) -> &'static str {
        match self {
            GoSyncIssue::VendorModulesTxt { .. } => VENDOR_MODULES_TXT_CODE,
            GoSyncIssue::Requirement { .. } => REQUIREMENTS_CODE,
        }
    }

    /// The module the issue is about (the replaced module).
    pub fn module(&self) -> &str {
        match self {
            GoSyncIssue::VendorModulesTxt { module, .. }
            | GoSyncIssue::Requirement { module, .. } => module,
        }
    }
}

impl std::fmt::Display for GoSyncIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoSyncIssue::VendorModulesTxt {
                module,
                modules_txt,
                command,
                stale: false,
            } => write!(
                f,
                "{modules_txt} does not record the go.mod `replace` for {module}, so every \
                 build using the committed vendor directory fails with \"inconsistent \
                 vendoring\"; run `{command}` to copy the patched module into vendor/, then \
                 commit it"
            ),
            GoSyncIssue::VendorModulesTxt {
                module,
                modules_txt,
                command,
                stale: true,
            } => write!(
                f,
                "{modules_txt} still records a socket-patch replacement for {module} that \
                 go.mod no longer has, so every build using the committed vendor directory \
                 fails with \"inconsistent vendoring\"; run `{command}` to restore the \
                 unpatched module in vendor/, then commit it"
            ),
            GoSyncIssue::Requirement {
                module,
                dep,
                required,
                listed,
            } => {
                let listed = match listed {
                    Some(v) => format!("go.mod lists {v}"),
                    None => "go.mod does not require it".to_string(),
                };
                write!(
                    f,
                    "the patched {module} requires {dep} {required} but {listed}, so a \
                     default (-mod=readonly) go build fails until go.mod and go.sum are \
                     updated; run `go mod tidy`, then commit go.mod and go.sum"
                )
            }
        }
    }
}

/// Every [`GoSyncIssue`] in the project at `project_root` (the directory
/// holding the consumer `go.mod`). Read-only and offline: reads `go.mod`,
/// the socket copies it points at, and `vendor/modules.txt`.
///
/// `pristine_go_mods` maps a replaced module to its unpatched `go.mod`
/// (the module-cache copy a run just patched). With it, a requirement the
/// patch ADDED (or raised) that the consumer does not list at all is
/// reported too; without it (`apply --check`, no module cache) only a
/// requirement the consumer lists at a lower version is, since an upstream
/// `go.mod` routinely requires modules a pruned consumer graph never lists.
pub async fn audit(
    project_root: &Path,
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let Ok(go_mod) = read_regular_to_string(&project_root.join("go.mod")).await else {
        return Vec::new();
    };
    let replaces = go_mod_edit::parse_replace_entries(&go_mod);
    let mut issues = vendor_modules_txt_issues(project_root, &replaces).await;
    issues.extend(requirement_issues(project_root, &go_mod, &replaces, pristine_go_mods).await);
    issues
}

/// [`audit`] as `(code, detail)` warning pairs, for the commands' warning
/// channels.
pub async fn audit_warnings(
    project_root: &Path,
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<(String, String)> {
    audit(project_root, pristine_go_mods)
        .await
        .into_iter()
        .map(|issue| (issue.code().to_string(), issue.to_string()))
        .collect()
}

/// Where go looks for the vendor directory's `modules.txt`, and the command
/// that regenerates it: the workspace root's `vendor/` (`go work vendor`)
/// when a `go.work` is in effect, else the module's own (`go mod vendor`).
fn modules_txt_location(project_root: &Path) -> (PathBuf, &'static str) {
    if let Some(work_dir) = workspace_root(project_root) {
        return (
            work_dir.join("vendor").join("modules.txt"),
            "go work vendor",
        );
    }
    (
        project_root.join("vendor").join("modules.txt"),
        "go mod vendor",
    )
}

/// The directory of the `go.work` go would use for `project_root`: `GOWORK`
/// when it names a file (`off` disables workspaces), else the nearest
/// `go.work` at or above the project.
fn workspace_root(project_root: &Path) -> Option<PathBuf> {
    match std::env::var("GOWORK") {
        Ok(v) if v == "off" => return None,
        Ok(v) if !v.is_empty() => return Path::new(&v).parent().map(Path::to_path_buf),
        _ => {}
    }
    let base = std::env::current_dir()
        .unwrap_or_default()
        .join(project_root);
    base.ancestors()
        .find(|dir| dir.join("go.work").is_file())
        .map(Path::to_path_buf)
}

async fn vendor_modules_txt_issues(
    project_root: &Path,
    replaces: &[ReplaceEntry],
) -> Vec<GoSyncIssue> {
    let (path, command) = modules_txt_location(project_root);
    let Ok(text) = read_regular_to_string(&path).await else {
        return Vec::new();
    };
    let workspace = command == "go work vendor";
    let display = {
        let base = std::env::current_dir()
            .unwrap_or_default()
            .join(project_root);
        path.strip_prefix(&base)
            .map(|rel| rel.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| path.display().to_string())
    };
    let recorded: Vec<ReplaceEntry> = text
        .lines()
        .filter_map(|line| line.strip_prefix("# "))
        .filter(|body| body.contains("=>"))
        .filter_map(go_mod_edit::parse_replace_body)
        .collect();

    let mut issues = Vec::new();
    for entry in replaces.iter().filter(|e| e.socket_owned()) {
        if !recorded
            .iter()
            .any(|r| same_replacement(entry, r, workspace))
        {
            issues.push(GoSyncIssue::VendorModulesTxt {
                module: entry.module.clone(),
                modules_txt: display.clone(),
                command,
                stale: false,
            });
        }
    }
    for rec in recorded.iter().filter(|r| r.socket_owned()) {
        if !replaces.iter().any(|e| same_replacement(e, rec, workspace)) {
            issues.push(GoSyncIssue::VendorModulesTxt {
                module: rec.module.clone(),
                modules_txt: display.clone(),
                command,
                stale: true,
            });
        }
    }
    issues
}

/// Whether a `modules.txt` replacement records the `go.mod` one. go writes
/// the target verbatim from `go.mod`; a workspace vendor directory may
/// record a module's directory replacement relative to the workspace root,
/// so there the recorded path only has to end with the module's.
fn same_replacement(go_mod: &ReplaceEntry, recorded: &ReplaceEntry, workspace: bool) -> bool {
    let norm = |p: &str| {
        let p = p.replace('\\', "/");
        p.strip_prefix("./").unwrap_or(&p).to_string()
    };
    go_mod.module == recorded.module
        && go_mod.version == recorded.version
        && match (&go_mod.path, &recorded.path) {
            (Some(a), Some(b)) => {
                let (a, b) = (norm(a), norm(b));
                a == b || (workspace && b.ends_with(&format!("/{a}")))
            }
            (None, None) => {
                go_mod.rhs_module == recorded.rhs_module
                    && go_mod.rhs_version == recorded.rhs_version
            }
            _ => false,
        }
}

async fn requirement_issues(
    project_root: &Path,
    consumer_go_mod: &str,
    replaces: &[ReplaceEntry],
    pristine_go_mods: &HashMap<String, PathBuf>,
) -> Vec<GoSyncIssue> {
    let consumer =
        go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(consumer_go_mod));
    let mut issues = Vec::new();
    for entry in replaces.iter().filter(|e| e.socket_owned()) {
        // Only a directory copy socket-patch wrote can be read here: a
        // hosted (module-to-module) replacement's go.mod lives in the
        // module cache, not the project.
        let Some(rel) = entry.path.as_deref() else {
            continue;
        };
        let rel = rel.replace('\\', "/");
        let rel = rel.strip_prefix("./").unwrap_or(&rel);
        if !crate::patch::path_safety::is_safe_multi_segment(rel) {
            continue;
        }
        let Ok(copy) = read_regular_to_string(&project_root.join(rel).join("go.mod")).await else {
            continue;
        };
        let patched = requirements_of(&copy);
        let pristine = match pristine_go_mods.get(&entry.module) {
            Some(path) => match read_regular_to_string(path).await {
                Ok(text) => Some(requirements_of(&text)),
                // A pre-modules package: its copy's go.mod is synthesized
                // and requires nothing.
                Err(_) => Some(HashMap::new()),
            },
            None => None,
        };
        let mut deps: Vec<(&String, &String)> = patched.iter().collect();
        deps.sort();
        for (dep, required) in deps {
            if *dep == entry.module {
                continue;
            }
            let listed = consumer.get(dep);
            let behind = match listed {
                Some(listed) => go_semver_cmp(listed, required).is_lt(),
                // Unlisted: only a requirement the patch added or raised
                // is known to matter.
                None => pristine.as_ref().is_some_and(|p| {
                    p.get(dep)
                        .is_none_or(|before| go_semver_cmp(before, required).is_lt())
                }),
            };
            if behind {
                issues.push(GoSyncIssue::Requirement {
                    module: entry.module.clone(),
                    dep: dep.clone(),
                    required: required.clone(),
                    listed: listed.cloned(),
                });
            }
        }
    }
    issues
}

fn requirements_of(go_mod: &str) -> HashMap<String, String> {
    go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(go_mod))
}

fn go_semver_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    crate::vendor::go_sum_edit::go_semver_cmp(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COPY: &str = ".socket/go-patches/example.com/upstream@v1.0.0";

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn consumer(root: &Path, extra: &str) {
        write(
            root,
            "go.mod",
            &format!(
                "module example.com/c\n\ngo 1.21\n\nrequire example.com/upstream v1.0.0\n\n\
                 require example.com/dep v1.0.0 // indirect\n{extra}"
            ),
        );
    }

    const REPLACE: &str = "\nreplace example.com/upstream v1.0.0 => \
                           ./.socket/go-patches/example.com/upstream@v1.0.0\n";

    /// #343: `go mod vendor` before the redirect leaves a modules.txt that
    /// does not record the socket replace; after `go mod vendor` it does;
    /// after a rollback the recorded one is stale.
    #[tokio::test]
    async fn vendor_modules_txt_must_record_socket_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        consumer(root, REPLACE);
        write(
            root,
            &format!("{COPY}/go.mod"),
            "module example.com/upstream\n",
        );
        let none = HashMap::new();

        // No vendor directory: nothing to sync.
        assert_eq!(audit(root, &none).await, vec![]);

        write(
            root,
            "vendor/modules.txt",
            "# example.com/dep v1.0.0\n## explicit; go 1.21\nexample.com/dep\n\
             # example.com/upstream v1.0.0\n## explicit; go 1.21\nexample.com/upstream\n",
        );
        let issues = audit(root, &none).await;
        assert_eq!(
            issues,
            vec![GoSyncIssue::VendorModulesTxt {
                module: "example.com/upstream".into(),
                modules_txt: "vendor/modules.txt".into(),
                command: "go mod vendor",
                stale: false,
            }]
        );
        assert_eq!(issues[0].code(), VENDOR_MODULES_TXT_CODE);
        assert!(issues[0].to_string().contains("run `go mod vendor`"));

        // What `go mod vendor` writes after the redirect.
        write(
            root,
            "vendor/modules.txt",
            &format!(
                "# example.com/dep v1.0.0\n## explicit; go 1.21\nexample.com/dep\n\
                 # example.com/upstream v1.0.0 => ./{COPY}\n## explicit; go 1.21\n\
                 example.com/upstream\n"
            ),
        );
        assert_eq!(audit(root, &none).await, vec![]);

        // Rolled back: go.mod lost the replace, modules.txt still has it.
        consumer(root, "");
        let issues = audit(root, &none).await;
        assert!(
            matches!(
                &issues[..],
                [GoSyncIssue::VendorModulesTxt { stale: true, .. }]
            ),
            "{issues:?}"
        );
        assert!(issues[0].to_string().contains("no longer has"));
    }

    /// A user-authored replace is never ours to report, and a hosted
    /// (module-to-module) replace is checked by module + version.
    #[tokio::test]
    async fn only_socket_replaces_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let hosted = "\nreplace example.com/upstream v1.0.0 => \
                      patch.socket.dev/gopatch/11111111-2222-4333-8444-555555555555 \
                      v1.0.0-socketpatch.1\nreplace example.com/mine => ../mine\n";
        consumer(root, hosted);
        write(
            root,
            "vendor/modules.txt",
            "# example.com/upstream v1.0.0\n",
        );
        let issues = audit(root, &HashMap::new()).await;
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].module(), "example.com/upstream");

        write(
            root,
            "vendor/modules.txt",
            "# example.com/upstream v1.0.0 => \
             patch.socket.dev/gopatch/11111111-2222-4333-8444-555555555555 \
             v1.0.0-socketpatch.1\n# example.com/mine => ../mine\n",
        );
        assert_eq!(audit(root, &HashMap::new()).await, vec![]);
    }

    /// #618: the patched copy's go.mod raising a requirement the consumer
    /// lists lower is always reported; one it adds is reported when the
    /// pristine go.mod shows it is new.
    #[tokio::test]
    async fn patched_go_mod_requirements_must_be_in_the_consumer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        consumer(root, REPLACE);
        write(
            root,
            "cache/go.mod",
            "module example.com/upstream\n\ngo 1.21\n\nrequire (\n\texample.com/dep v1.0.0\n\
             \texample.com/testonly v0.1.0\n)\n",
        );
        write(
            root,
            &format!("{COPY}/go.mod"),
            "module example.com/upstream\n\ngo 1.21\n\nrequire (\n\texample.com/dep v1.1.0\n\
             \texample.com/testonly v0.1.0\n\texample.com/added v0.2.0\n)\n",
        );
        let pristine = HashMap::from([(
            "example.com/upstream".to_string(),
            root.join("cache/go.mod"),
        )]);

        let raised = GoSyncIssue::Requirement {
            module: "example.com/upstream".into(),
            dep: "example.com/dep".into(),
            required: "v1.1.0".into(),
            listed: Some("v1.0.0".into()),
        };
        let added = GoSyncIssue::Requirement {
            module: "example.com/upstream".into(),
            dep: "example.com/added".into(),
            required: "v0.2.0".into(),
            listed: None,
        };
        // Without the pristine go.mod (apply --check) only the raised one;
        // the unlisted, unchanged `testonly` is never reported.
        assert_eq!(audit(root, &HashMap::new()).await, vec![raised.clone()]);
        assert_eq!(audit(root, &pristine).await, vec![added, raised.clone()]);
        assert!(raised.to_string().contains("run `go mod tidy`"));
        assert_eq!(raised.code(), REQUIREMENTS_CODE);

        // After `go mod tidy` the consumer lists both: in sync.
        consumer(
            root,
            &format!(
                "{REPLACE}\nrequire (\n\texample.com/dep v1.1.0 // indirect\n\
                 \texample.com/added v0.2.0 // indirect\n)\n"
            ),
        );
        assert_eq!(audit(root, &pristine).await, vec![]);
    }
}
