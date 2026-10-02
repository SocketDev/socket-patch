//! Spawn one CLI run and measure it.
//!
//! Wall time is taken around spawn → reap, so it includes process start
//! and exit the way a user's shell sees them. CPU time and peak RSS come
//! from `wait4`'s rusage for exactly that child: unlike `RUSAGE_CHILDREN`
//! it is not polluted by other children, and unlike sampling `/proc` it
//! sees the whole lifetime.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct Usage {
    pub wall: Duration,
    /// User + system CPU time (`None` where `wait4` is unavailable).
    pub cpu: Option<Duration>,
    /// Peak resident set size in KiB.
    pub max_rss_kib: Option<u64>,
}

pub struct Outcome {
    pub code: Option<i32>,
    pub usage: Usage,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run `cmd` to completion with stdout/stderr captured to files under
/// `capture_dir` (files, not pipes: a pipe the harness does not drain
/// would stall a chatty child and bill the stall to the CLI).
pub fn run(mut cmd: Command, capture_dir: &Path) -> std::io::Result<Outcome> {
    let out_path = capture_dir.join("stdout");
    let err_path = capture_dir.join("stderr");
    cmd.stdin(Stdio::null())
        .stdout(std::fs::File::create(&out_path)?)
        .stderr(std::fs::File::create(&err_path)?);
    let start = Instant::now();
    let child = cmd.spawn()?;
    let (code, cpu, max_rss_kib) = reap(child)?;
    let wall = start.elapsed();
    Ok(Outcome {
        code,
        usage: Usage {
            wall,
            cpu,
            max_rss_kib,
        },
        stdout: std::fs::read(&out_path)?,
        stderr: std::fs::read(&err_path)?,
    })
}

#[cfg(unix)]
fn reap(
    child: std::process::Child,
) -> std::io::Result<(Option<i32>, Option<Duration>, Option<u64>)> {
    let pid = child.id() as libc::pid_t;
    // `wait4` reaps the child itself; `child` is only dropped afterwards
    // (dropping a `Child` neither waits nor kills).
    let mut status: libc::c_int = 0;
    // SAFETY: an all-zero rusage is a valid value; wait4 fills it in.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: valid out-pointers to locals, and `pid` is our own
        // unreaped child.
        let r = unsafe { libc::wait4(pid, &mut status, 0, &mut ru) };
        if r == pid {
            break;
        }
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
    drop(child);
    let code = if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    };
    let tv = |t: libc::timeval| {
        Duration::from_secs(t.tv_sec as u64) + Duration::from_micros(t.tv_usec as u64)
    };
    let cpu = tv(ru.ru_utime) + tv(ru.ru_stime);
    // Linux reports KiB, macOS bytes.
    let rss = if cfg!(target_os = "macos") {
        ru.ru_maxrss as u64 / 1024
    } else {
        ru.ru_maxrss as u64
    };
    Ok((code, Some(cpu), Some(rss)))
}

#[cfg(not(unix))]
fn reap(
    mut child: std::process::Child,
) -> std::io::Result<(Option<i32>, Option<Duration>, Option<u64>)> {
    let status = child.wait()?;
    Ok((status.code(), None, None))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn measures_a_child_and_captures_its_output() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err >&2; exit 3"]);
        let o = run(cmd, tmp.path()).unwrap();
        assert_eq!(o.code, Some(3));
        assert_eq!(o.stdout, b"out\n");
        assert_eq!(o.stderr, b"err\n");
        assert!(o.usage.cpu.is_some());
        assert!(o.usage.max_rss_kib.unwrap() > 0);
    }

    #[test]
    fn cpu_time_counts_the_child_only() {
        let tmp = tempfile::tempdir().unwrap();
        // A busy child burns CPU; the harness's own CPU must not leak in.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "i=0; while [ $i -lt 200000 ]; do i=$((i+1)); done"]);
        let o = run(cmd, tmp.path()).unwrap();
        let cpu = o.usage.cpu.unwrap();
        assert!(cpu > Duration::from_millis(5), "{cpu:?}");
        assert!(
            cpu <= o.usage.wall + Duration::from_millis(50),
            "{cpu:?} vs {:?}",
            o.usage.wall
        );
    }
}
