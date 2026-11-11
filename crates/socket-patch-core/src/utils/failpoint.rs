//! Crash and failure injection for the crash-safety tests, compiled into
//! debug builds (and test builds with the `failpoints` feature) only.
//!
//! `SOCKET_PATCH_FAILPOINT=<name>[@<n>][,…]` makes the process exit
//! (status 86, no destructors, no further writes) at the `n`-th time
//! (default: the first) it reaches [`hit`] with that name — the observable
//! effect of a crash at that point: whatever was written before is on disk,
//! nothing after it is.
//!
//! `<name>[@<n>]~pause` parks the process there instead, forever, so a test
//! can signal it at a known point (the interrupt tests do this with the
//! apply lock held). Before parking it prints a `failpoint … paused` line
//! to stderr and, when `SOCKET_PATCH_FAILPOINT_READY=<file>` is set,
//! creates that file as the test's ready marker.
//!
//! `<name>[@<n>]~fail` makes [`fails`] answer `true` there and the process
//! go on: the call site returns the error a real fault at that point would
//! (a write that fails), so a test can drive the code that handles it.
//!
//! [`hit_or_error`] is the same point for an I/O step, with the failure
//! already an `io::Error`.
//!
//! Release builds compile [`hit`] and [`fails`] to nothing, so no
//! environment variable can make a shipped binary stop or fail half-way;
//! the same goes for [`switched_off`]. The `failpoints` feature compiles
//! them into an optimized build as well; only the CLI's dev-dependencies
//! enable it, so it reaches the optimized test binaries
//! (`cargo test --release`) and never a `cargo build`/`cargo install` one.

/// A named crash point (see the module docs).
pub fn hit(name: &str) {
    let _ = fails(name);
}

/// A named failure point: whether the caller is asked to fail here (see
/// the module docs). It is a crash point as well, so the same name takes
/// the exit and `~pause` forms.
pub fn fails(name: &str) -> bool {
    #[cfg(any(debug_assertions, feature = "failpoints"))]
    {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static HITS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);
        let Ok(spec) = std::env::var("SOCKET_PATCH_FAILPOINT") else {
            return false;
        };
        let mut hits = HITS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = {
            let map = hits.get_or_insert_with(HashMap::new);
            let count = map.entry(name.to_string()).or_insert(0);
            *count += 1;
            *count
        };
        for point in spec.split(',') {
            let point = point.trim();
            let (point, fail) = match point.strip_suffix("~fail") {
                Some(point) => (point, true),
                None => (point, false),
            };
            let (point, pause) = match point.strip_suffix("~pause") {
                Some(point) => (point, true),
                None => (point, false),
            };
            let (point, at) = match point.split_once('@') {
                Some((p, n)) => (p, n.parse::<usize>().unwrap_or(1)),
                None => (point, 1),
            };
            if point != name || at != count {
                continue;
            }
            if fail {
                return true;
            }
            if pause {
                drop(hits);
                eprintln!("socket-patch: failpoint `{name}` #{count} paused");
                if let Some(ready) = std::env::var_os("SOCKET_PATCH_FAILPOINT_READY") {
                    let _ = std::fs::write(ready, b"");
                }
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                }
            }
            eprintln!("socket-patch: failpoint `{name}` #{count} hit; exiting");
            std::process::exit(86);
        }
        false
    }
    #[cfg(not(any(debug_assertions, feature = "failpoints")))]
    {
        let _ = name;
        false
    }
}

/// A named failure point for an I/O step: the injected failure comes back
/// as the `Err` the step itself would return (see [`fails`]).
pub fn hit_or_error(name: &str) -> std::io::Result<()> {
    if fails(name) {
        return Err(std::io::Error::other(format!(
            "failpoint `{name}` injected an error"
        )));
    }
    Ok(())
}

/// Whether a debug build was asked to switch the named mechanism off
/// (`SOCKET_PATCH_SWITCH_OFF=<name>[,…]`) — how the equivalence tests run
/// the pre-change code path as their oracle. Always `false` in release
/// builds.
pub fn switched_off(name: &str) -> bool {
    #[cfg(any(debug_assertions, feature = "failpoints"))]
    {
        std::env::var("SOCKET_PATCH_SWITCH_OFF")
            .is_ok_and(|spec| spec.split(',').any(|p| p.trim() == name))
    }
    #[cfg(not(any(debug_assertions, feature = "failpoints")))]
    {
        let _ = name;
        false
    }
}
