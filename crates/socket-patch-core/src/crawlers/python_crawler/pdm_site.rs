//! Resolve the implicit macOS site config with PDM's own Python runtime.
//!
//! platformdirs distinguishes Homebrew from other Python installations via
//! `sys.base_prefix`. Neither the crawler's platform nor which directories
//! exist tells us which one PDM uses. Unknown launchers yield no site layer;
//! we never run PDM itself, which would load project and installed plugins.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::utils::fs::open_regular_file;
use crate::utils::process::{command_for, resolve_tool_with};

const HEADER_LIMIT: u64 = 8192;
const OUTPUT_LIMIT: u64 = 4096;
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE: &str =
    "import json, platformdirs; print(json.dumps(str(platformdirs.site_config_path('pdm'))))";

/// `None` is unknown, not a guess at `/Library` or a Homebrew prefix.
/// Only a PDM launcher on an absolute PATH entry identifies the runtime.
pub(super) async fn implicit_site_config_dir(
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    let launcher = resolve_tool_with("pdm", &|name| var(name).map(Into::into))?;
    // The regular-file opener follows normal pipx/uv launcher symlinks,
    // but refuses a FIFO/device. Read only a bounded script header.
    let (file, _) = open_regular_file(&launcher).await.ok()?;
    let mut header = Vec::new();
    file.take(HEADER_LIMIT)
        .read_to_end(&mut header)
        .await
        .ok()?;
    let interpreter = launcher_interpreter(std::str::from_utf8(&header).ok()?)?;
    probe_runtime_site_dir(&interpreter, var, PROBE_TIMEOUT).await
}

/// Recognize ordinary Python console scripts and the exact shell trampoline
/// pip/distlib and uv write for long or space-containing interpreter paths.
/// This is not a shell parser: env shims, arguments and arbitrary wrappers
/// are unknown. In particular, an absolute non-Python shebang is not enough.
fn launcher_interpreter(header: &str) -> Option<PathBuf> {
    let mut lines = header.lines();
    let shebang = lines.next()?.strip_prefix("#!")?.trim();
    let interpreter = if shebang == "/bin/sh" {
        let command = lines
            .next()?
            .strip_prefix("'''exec' ")?
            .strip_suffix(" \"$0\" \"$@\"")?;
        if lines.next()? != "' '''" {
            return None;
        }
        if let Some(single) = command.strip_prefix('\'') {
            let path = single.strip_suffix('\'')?;
            (!path.contains('\'')).then_some(path)?
        } else if let Some(double) = command.strip_prefix('"') {
            let path = double.strip_suffix('"')?;
            // No expansions or shell escapes: pass the literal path as one
            // argv entry rather than evaluating a shell command.
            (!path.contains(['"', '$', '`', '\\'])).then_some(path)?
        } else {
            (!command.contains(|c: char| c.is_whitespace() || "'\"\\$`;|&<>()*?[]{}".contains(c)))
                .then_some(command)?
        }
    } else {
        // Kernel shebangs cannot encode a space-containing executable path;
        // installers use the trampoline above instead.
        (!shebang.contains(char::is_whitespace)).then_some(shebang)?
    };
    if interpreter.chars().any(char::is_control) {
        return None;
    }
    let path = Path::new(interpreter);
    let name = path.file_name()?.to_str()?;
    let version = name
        .strip_prefix("python")
        .or_else(|| name.strip_prefix("pypy"))?;
    if version == "t" {
        return None;
    }
    let version = version.strip_suffix('t').unwrap_or(version);
    if !version.is_empty()
        && !version
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    path.is_absolute().then(|| path.to_path_buf())
}

async fn probe_runtime_site_dir(
    interpreter: &Path,
    var: &impl Fn(&str) -> Option<String>,
    timeout: Duration,
) -> Option<PathBuf> {
    let cwd = tempfile::Builder::new()
        .prefix("socket-pdm-site-")
        .tempdir()
        .ok()?;
    let child = runtime_probe_command(interpreter, var, cwd.path())
        .spawn()
        .ok()?;
    read_runtime_site_dir(child, timeout).await
}

fn runtime_probe_command(
    interpreter: &Path,
    var: &impl Fn(&str) -> Option<String>,
    cwd: &Path,
) -> tokio::process::Command {
    // Preserve the interpreter's lexical venv path. Canonicalizing bin/python
    // could launch its base Python and lose PDM's installed platformdirs.
    let mut command = tokio::process::Command::from(command_for(interpreter));
    command
        // Unlike -I, -E keeps normal user-site pip installs available.
        // Do not use -S: Homebrew's normal site initialization affects the
        // sys.base_prefix that platformdirs uses for its default site path.
        .args(["-E", "-B", "-c", PROBE])
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // -E alone is insufficient: site.py/Homebrew's sitecustomize read
    // PYTHONUSERBASE/PYTHONHOME directly, and macOS startup can honor
    // PYTHONEXECUTABLE despite it. Copy only non-Python ambient variables
    // so neither imports nor interpreter identity can be redirected.
    command
        .env_clear()
        .envs(std::env::vars_os().filter(|(name, _)| {
            !name.as_encoded_bytes().starts_with(b"PYTHON")
                && !name.as_encoded_bytes().starts_with(b"_PYTHON")
                && name != "__PYVENV_LAUNCHER__"
        }));
    // Keep the probe and the caller's injected environment in agreement;
    // in particular, do not inherit an unrelated XDG override in tests.
    for name in ["PATH", "HOME", "XDG_CONFIG_DIRS"] {
        if let Some(value) = var(name) {
            command.env(name, value);
        } else {
            command.env_remove(name);
        }
    }
    command
}

async fn read_runtime_site_dir(
    mut child: tokio::process::Child,
    timeout: Duration,
) -> Option<PathBuf> {
    let stdout = child.stdout.take()?;
    tokio::time::timeout(timeout, async {
        let mut output = Vec::new();
        stdout
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut output)
            .await
            .ok()?;
        if output.len() > OUTPUT_LIMIT as usize || !child.wait().await.ok()?.success() {
            return None;
        }
        // Exactly one JSON string, not a guessed line in mixed diagnostics.
        let path = PathBuf::from(serde_json::from_slice::<String>(&output).ok()?);
        path.is_absolute().then_some(path)
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn executable(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn recognizes_python_launchers_without_resolving_interpreter_symlinks() {
        for name in ["python", "python3", "python3.13", "python3.13t", "pypy3"] {
            let interpreter = format!("/a/venv/bin/{name}");
            assert_eq!(
                launcher_interpreter(&format!("#!{interpreter}\nfrom pdm.core import main\n")),
                Some(PathBuf::from(&interpreter))
            );
        }
        for command in [
            "'/a path/bin/python'",
            "\"/a path/bin/python\"",
            "/a/bin/python",
        ] {
            let expected = command.trim_matches(['\'', '"']);
            assert_eq!(
                launcher_interpreter(&format!(
                    "#!/bin/sh\n'''exec' {command} \"$0\" \"$@\"\n' '''\n"
                )),
                Some(PathBuf::from(expected))
            );
        }
    }

    #[test]
    fn refuses_env_shell_arguments_and_unrecognized_trampolines() {
        for header in [
            "#!/usr/bin/env python3\n",
            "#!/bin/sh\necho injected\n",
            "#!/bin/zsh\n",
            "#!/a/bin/python -S\n",
            "#!relative/python\n",
            "#!/a path/bin/python\n",
            "#!/a/bin/python-config\n",
            "#!/a/bin/pythont\n",
            "#!/bin/sh\n'''exec' /a/python; /a/evil \"$0\" \"$@\"\n' '''\n",
            "#!/bin/sh\n'''exec' \"/a/$HOME/python\" \"$0\" \"$@\"\n' '''\n",
            "#!/bin/sh\n'''exec' '/a/python' \"$0\" \"$@\"; evil\n' '''\n",
            "#!/bin/sh\n'''exec' '/a/python' \"$0\" \"$@\"\nwrong\n",
        ] {
            assert_eq!(launcher_interpreter(header), None, "{header}");
        }
    }

    #[tokio::test]
    async fn absolute_path_launcher_symlink_selects_runtime_without_executing_pdm() {
        let tmp = tempfile::tempdir().unwrap();
        let python = tmp.path().join("python");
        executable(&python, "#!/bin/sh\nprintf '\"/runtime/site/pdm\"\\n'\n");
        let launcher = tmp.path().join("real-pdm");
        executable(
            &launcher,
            &format!(
                "#!{}\nraise RuntimeError('PDM must not run')\n",
                python.display()
            ),
        );
        symlink(&launcher, tmp.path().join("pdm")).unwrap();
        let env = |name: &str| (name == "PATH").then(|| format!(".:{}", tmp.path().display()));
        assert_eq!(
            implicit_site_config_dir(&env).await,
            Some(PathBuf::from("/runtime/site/pdm"))
        );
        assert_eq!(
            implicit_site_config_dir(&|_: &str| Some(".".into())).await,
            None
        );
        executable(&launcher, "#!/bin/sh\nexit 99\n");
        assert_eq!(implicit_site_config_dir(&env).await, None);
    }

    #[tokio::test]
    async fn probe_bounds_and_validates_output_and_process_status() {
        let tmp = tempfile::tempdir().unwrap();
        let python = tmp.path().join("python");
        for script in [
            "printf 'not json\\n'",
            "printf '\"relative/pdm\"\\n'",
            "printf '\"/one\"\\n\"/two\"\\n'",
            "printf '\"/valid\"\\n'; exit 1",
            // A valid absolute JSON path that would be accepted if the
            // output limit were accidentally removed.
            "printf '\"/%4096s\"\\n' ''",
        ] {
            executable(&python, &format!("#!/bin/sh\n{script}\n"));
            assert_eq!(
                probe_runtime_site_dir(&python, &|_: &str| None, PROBE_TIMEOUT).await,
                None,
                "{script}"
            );
        }
    }

    #[tokio::test]
    async fn probe_uses_private_cwd_null_stdin_exact_args_and_injected_env() {
        let tmp = tempfile::tempdir().unwrap();
        let python = tmp.path().join("python");
        let recorded = tmp.path().join("cwd");
        executable(&python, &format!(
            "#!/bin/sh\n[ \"$1 $2 $3\" = '-E -B -c' ] || exit 1\n[ \"${{XDG_CONFIG_DIRS-unset}}\" = unset ] || exit 2\nread input && exit 3\nprintf '%s' \"$PWD\" > '{}'\nprintf '\"/site/pdm\"\\n'\n",
            recorded.display()
        ));
        assert_eq!(
            probe_runtime_site_dir(&python, &|_: &str| None, PROBE_TIMEOUT).await,
            Some(PathBuf::from("/site/pdm"))
        );
        let cwd = PathBuf::from(std::fs::read_to_string(recorded).unwrap());
        assert!(cwd
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("socket-pdm-site-"));
        assert!(
            !cwd.exists(),
            "the private probe directory is removed on return"
        );
    }

    #[tokio::test]
    async fn probe_removes_python_overrides_without_changing_the_parent_environment() {
        const CHILD: &str = "SOCKET_PATCH_PDM_SITE_ENV_TEST_CHILD";
        let overrides = [
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONUSERBASE",
            "PYTHONEXECUTABLE",
            "PYTHON_FUTURE_OVERRIDE",
            "_PYTHON_SYSCONFIGDATA_PATH",
            "__PYVENV_LAUNCHER__",
        ];
        if std::env::var_os(CHILD).is_none() {
            // Set overrides only in a separate test process. Other tests and
            // the caller must never observe a temporary global environment.
            let test_name = concat!(
                "crawlers::python_crawler::pdm_site::tests::",
                "probe_removes_python_overrides_without_changing_the_parent_environment"
            );
            let mut child = tokio::process::Command::new(std::env::current_exe().unwrap());
            child
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD, "1")
                .envs(overrides.map(|name| (name, "/untrusted/project")))
                .stdin(Stdio::null())
                .kill_on_drop(true);
            let result = tokio::time::timeout(Duration::from_secs(15), child.output())
                .await
                .expect("environment control timed out")
                .unwrap();
            assert!(
                result.status.success(),
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let python = tmp.path().join("python");
        executable(&python, "#!/bin/sh\n[ -z \"${PYTHONPATH+x}${PYTHONHOME+x}${PYTHONUSERBASE+x}${PYTHONEXECUTABLE+x}${PYTHON_FUTURE_OVERRIDE+x}${_PYTHON_SYSCONFIGDATA_PATH+x}${__PYVENV_LAUNCHER__+x}\" ] || exit 1\nprintf '\"/safe/site/pdm\"\\n'\n");
        assert_eq!(
            probe_runtime_site_dir(&python, &|_: &str| None, PROBE_TIMEOUT).await,
            Some(PathBuf::from("/safe/site/pdm"))
        );
        for name in overrides {
            assert_eq!(std::env::var(name).unwrap(), "/untrusted/project");
        }
    }

    #[tokio::test]
    async fn probe_timeout_kills_its_child() {
        let tmp = tempfile::tempdir().unwrap();
        let python = tmp.path().join("python");
        executable(&python, "#!/bin/sh\nexec /bin/sleep 30\n");
        let child = runtime_probe_command(&python, &|_: &str| None, tmp.path())
            .spawn()
            .unwrap();
        // Capture the actual OS child identity before awaiting its timeout;
        // do not assume a newly spawned shell has written a PID file yet.
        let pid = child.id().unwrap() as i32;
        let timeout = Duration::from_millis(100);
        let started = std::time::Instant::now();
        assert_eq!(read_runtime_site_dir(child, timeout).await, None);
        assert!(
            started.elapsed() >= timeout,
            "the child failed before the deadline"
        );
        tokio::time::timeout(PROBE_TIMEOUT, async {
            // Signal zero only checks existence; kill_on_drop must terminate
            // and Tokio must reap this exact child, without a shell grandchild.
            while unsafe { libc::kill(pid, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed-out probe was left running");
    }
}
