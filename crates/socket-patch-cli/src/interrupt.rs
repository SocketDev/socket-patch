//! Interrupt handling: an interrupted run must not leave `.socket/apply.lock`
//! behind, nor a build of its own still running.
//!
//! The default disposition of SIGINT, SIGTERM and SIGHUP (and of Ctrl-C,
//! Ctrl-Break and console close on Windows) ends the process without
//! running any destructor, so a lock-taking command killed that way never
//! reaches `LockGuard`'s drop. [`install`] puts a handler in front of the
//! default one that removes the held lock file
//! ([`cleanup_held_lock_on_interrupt`]) and then lets the signal end the
//! process exactly as before: same death-by-signal status (130 for Ctrl-C
//! in a shell), same exit code on Windows.
//!
//! Before the lock goes, the handler ends any native build the run started
//! ([`kill_builds_on_interrupt`]). A gem's extension build leads its own
//! process group, so neither the terminal's Ctrl-C nor the CLI's death
//! reaches it: left alone it would keep compiling into a gem the next run
//! is free to lock and patch. The lock is released only once the build's
//! processes are gone.
//!
//! Only an uncatchable kill (SIGKILL, power loss) can still leave the file,
//! and the next lock-taking command reclaims and removes it.
//!
//! A closed stdout or stderr pipe (`socket-patch apply | head -1`) is not an
//! interrupt and must not end the run: killed at a `println!`, a mutating
//! command would stop between two of its writes with the lock still on
//! disk. [`install`] therefore keeps SIGPIPE ignored (on Unix) and turns a
//! broken pipe into "stop printing" for every print macro in both crates
//! (`socket_patch_core::utils::stdio`), so the command finishes, drops its
//! lock and exits with its own code. Spawned children still get the default
//! disposition: std resets it when it execs them.

use socket_patch_core::patch::apply_lock::cleanup_held_lock_on_interrupt;
use socket_patch_core::utils::process::kill_builds_on_interrupt;

/// Install the interrupt handlers and make a closed output pipe harmless.
/// Call once, first thing in `main`, before any output.
///
/// Unix: a signal the process started with ignored (`nohup`, a launcher
/// that ignores Ctrl-C) keeps being ignored. The prompt's cursor guard
/// (`ui::prompt`) chains in front of this handler for SIGINT while a menu
/// is up and re-raises into it, so the cursor is restored first and the
/// lock removed second.
pub fn install() {
    imp::install();
    socket_patch_core::utils::stdio::tolerate_broken_pipes();
}

#[cfg(unix)]
mod imp {
    use super::{cleanup_held_lock_on_interrupt, kill_builds_on_interrupt};

    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    extern "C" fn on_signal(sig: libc::c_int) {
        // Builds first: the lock must outlive every process of them.
        kill_builds_on_interrupt();
        cleanup_held_lock_on_interrupt();
        // SAFETY: signal and raise are async-signal-safe. `sig` is blocked
        // while this handler runs, so the re-raised signal is delivered
        // once it returns, to the default disposition: the process dies by
        // the same signal it would have without this handler.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
            // As a container's PID 1 this process is shielded from every
            // signal it does not handle, so the re-raise above is dropped
            // and the run would carry on, deaf to the stop it was just
            // sent (and `hot-patch` would go on to start a command that
            // never hears it). End it here, with the status a death by
            // this signal reports.
            if libc::getpid() == 1 {
                libc::_exit(128 + sig);
            }
        }
    }

    pub(super) fn install() {
        // The Rust runtime already ignores SIGPIPE; said here because the
        // broken-pipe handling above depends on the write returning EPIPE
        // rather than the signal ending the process.
        // SAFETY: SIG_IGN is a valid disposition for SIGPIPE.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        for sig in SIGNALS {
            // SAFETY: plain sigaction calls with zeroed, then filled,
            // structs; the handler only calls async-signal-safe code.
            unsafe {
                let mut old: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(sig, std::ptr::null(), &mut old) != 0
                    || old.sa_sigaction == libc::SIG_IGN
                {
                    continue;
                }
                let mut new: libc::sigaction = std::mem::zeroed();
                new.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
                new.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut new.sa_mask);
                libc::sigaction(sig, &new, std::ptr::null_mut());
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{cleanup_held_lock_on_interrupt, kill_builds_on_interrupt};
    use windows_sys::Win32::Foundation::{BOOL, FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
    };

    /// Runs on a thread the console creates. Returning FALSE hands the
    /// event on to the default handler, which ends the process.
    unsafe extern "system" fn on_ctrl(ctrl: u32) -> BOOL {
        if matches!(ctrl, CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT) {
            // The console delivers the event to a running build itself;
            // this only stops the run from starting another.
            kill_builds_on_interrupt();
            cleanup_held_lock_on_interrupt();
        }
        FALSE
    }

    pub(super) fn install() {
        // SAFETY: registers a handler with the documented signature.
        unsafe {
            SetConsoleCtrlHandler(Some(on_ctrl), TRUE);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod imp {
    pub(super) fn install() {}
}
