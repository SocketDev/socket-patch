//! Printing that survives a reader who went away.
//!
//! `println!` and `eprintln!` panic when the write fails, and the default
//! SIGPIPE disposition kills the process before the write even returns.
//! Either way `socket-patch apply | head -1` would stop at whatever line it
//! is printing when `head` exits: for a mutating command that is between
//! two of its writes, with `.socket/apply.lock` still on disk and the steps
//! after that line (the manifest cleanup, the VEX document, the other legs)
//! never run.
//!
//! So a broken pipe ends the PRINTING, never the run. The binary keeps
//! SIGPIPE ignored and opts in with [`tolerate_broken_pipes`]; both crates
//! shadow the four print macros (see each `lib.rs`), which routes every
//! `println!` / `eprintln!` / `print!` / `eprint!` call site through
//! [`print`]. The first `BrokenPipe` on a stream closes it for the rest of
//! the process, and the command goes on to finish its work, release its
//! lock and exit with the code that work earned.
//!
//! Until the binary opts in (unit tests, in-process integration tests, the
//! Node binding) the macros are std's own: same output, same capture by the
//! test harness, same panic on a failed write.

use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static TOLERANT: AtomicBool = AtomicBool::new(false);
static STDOUT_CLOSED: AtomicBool = AtomicBool::new(false);
static STDERR_CLOSED: AtomicBool = AtomicBool::new(false);

/// Which standard stream a print macro writes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// From now on a write to a closed stdout or stderr stops the printing to
/// that stream instead of panicking. Call once, first thing in `main`, in a
/// process that also ignores SIGPIPE (the Rust runtime's default, which the
/// CLI's `interrupt::install` asserts).
pub fn tolerate_broken_pipes() {
    TOLERANT.store(true, Ordering::Relaxed);
}

/// What the shadowed print macros expand to: write `args` (and a newline,
/// for the `ln` forms) to `stream`.
pub fn print(stream: Stream, newline: bool, args: fmt::Arguments<'_>) {
    if !TOLERANT.load(Ordering::Relaxed) {
        match (stream, newline) {
            (Stream::Stdout, true) => ::std::println!("{args}"),
            (Stream::Stdout, false) => ::std::print!("{args}"),
            (Stream::Stderr, true) => ::std::eprintln!("{args}"),
            (Stream::Stderr, false) => ::std::eprint!("{args}"),
        }
        return;
    }
    let (closed, label) = match stream {
        Stream::Stdout => (&STDOUT_CLOSED, "stdout"),
        Stream::Stderr => (&STDERR_CLOSED, "stderr"),
    };
    if closed.load(Ordering::Relaxed) {
        return;
    }
    let written = match stream {
        Stream::Stdout => write_to(&mut io::stdout().lock(), newline, args),
        Stream::Stderr => write_to(&mut io::stderr().lock(), newline, args),
    };
    if let Err(e) = settle(written, closed) {
        // Any other failure (a full disk behind a redirect, EIO) keeps
        // std's behavior: it is not a reader going away.
        panic!("failed printing to {label}: {e}");
    }
}

fn write_to(out: &mut impl Write, newline: bool, args: fmt::Arguments<'_>) -> io::Result<()> {
    out.write_fmt(args)?;
    if newline {
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// A `BrokenPipe` marks the stream closed and is swallowed; every other
/// result passes through.
fn settle(written: io::Result<()>, closed: &AtomicBool) -> io::Result<()> {
    match written {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => {
            closed.store(true, Ordering::Relaxed);
            Ok(())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that fails every write with `kind`.
    struct Failing(io::ErrorKind);

    impl Write for Failing {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.0, "write failed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writes_the_text_and_the_newline_only_for_the_ln_forms() {
        let mut out = Vec::new();
        write_to(&mut out, true, format_args!("a {}", 1)).unwrap();
        write_to(&mut out, false, format_args!("b")).unwrap();
        write_to(&mut out, true, format_args!("")).unwrap();
        assert_eq!(out, b"a 1\nb\n");
    }

    /// A reader that went away closes the stream and is not an error; a
    /// full disk is still one.
    #[test]
    fn only_a_broken_pipe_closes_the_stream() {
        let closed = AtomicBool::new(false);
        let written = write_to(
            &mut Failing(io::ErrorKind::BrokenPipe),
            true,
            format_args!("x"),
        );
        assert!(settle(written, &closed).is_ok());
        assert!(closed.load(Ordering::Relaxed));

        let closed = AtomicBool::new(false);
        let written = write_to(
            &mut Failing(io::ErrorKind::StorageFull),
            true,
            format_args!("x"),
        );
        let err = settle(written, &closed).expect_err("a full disk is not a closed pipe");
        assert_eq!(err.kind(), io::ErrorKind::StorageFull);
        assert!(!closed.load(Ordering::Relaxed));

        let closed = AtomicBool::new(false);
        assert!(settle(Ok(()), &closed).is_ok());
        assert!(!closed.load(Ordering::Relaxed));
    }
}
