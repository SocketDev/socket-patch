//! Interrupt handling: an interrupted run must not leave `.socket/apply.lock`
//! behind.
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
//! Only an uncatchable kill (SIGKILL, power loss) can still leave the file,
//! and the next lock-taking command reclaims and removes it.

use socket_patch_core::patch::apply_lock::cleanup_held_lock_on_interrupt;

/// Install the interrupt handlers. Call once, first thing in `main`.
///
/// Unix: a signal the process started with ignored (`nohup`, a launcher
/// that ignores Ctrl-C) keeps being ignored. The prompt's cursor guard
/// (`ui::prompt`) chains in front of this handler for SIGINT while a menu
/// is up and re-raises into it, so the cursor is restored first and the
/// lock removed second.
pub fn install() {
    imp::install();
}

#[cfg(unix)]
mod imp {
    use super::cleanup_held_lock_on_interrupt;

    const SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    extern "C" fn on_signal(sig: libc::c_int) {
        cleanup_held_lock_on_interrupt();
        // SAFETY: signal and raise are async-signal-safe. `sig` is blocked
        // while this handler runs, so the re-raised signal is delivered
        // once it returns, to the default disposition: the process dies by
        // the same signal it would have without this handler.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }

    pub(super) fn install() {
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
    use super::cleanup_held_lock_on_interrupt;
    use windows_sys::Win32::Foundation::{BOOL, FALSE, TRUE};
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
    };

    /// Runs on a thread the console creates. Returning FALSE hands the
    /// event on to the default handler, which ends the process.
    unsafe extern "system" fn on_ctrl(ctrl: u32) -> BOOL {
        if matches!(ctrl, CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT) {
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
