//! Crash injection for the crash-safety tests, compiled into debug builds
//! (and test builds with the `failpoints` feature) only.
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
//! `<name>[@<n>]~error` makes [`hit_or_error`] return an I/O error there
//! instead of ending the process: the observable effect of the operation
//! behind that point failing (a refused rename, a full disk), which the
//! caller must then unwind like the real thing.
//!
//! Release builds compile [`hit`] to nothing, so no environment variable
//! can make a shipped binary stop half-way; the same
//! goes for [`hit_or_error`] and [`switched_off`]. The `failpoints` feature compiles them into an
//! optimized build as well; only the CLI's dev-dependencies enable it, so
//! it reaches the optimized test binaries (`cargo test --release`) and
//! never a `cargo build`/`cargo install` one.

/// A named crash point (see the module docs).
pub fn hit(name: &str) {
    // An `~error` spec has no caller to hand its error to here.
    let _ = hit_or_error(name);
}

/// A named crash point that can also be told to fail (`~error`, see the
/// module docs): `Err` is the injected failure of the operation the caller
/// is about to make.
pub fn hit_or_error(name: &str) -> std::io::Result<()> {
    #[cfg(any(debug_assertions, feature = "failpoints"))]
    {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static HITS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);
        let Ok(spec) = std::env::var("SOCKET_PATCH_FAILPOINT") else {
            return Ok(());
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
            let (point, action) = match point.split_once('~') {
                Some((point, action)) => (point, action),
                None => (point, ""),
            };
            let (point, at) = match point.split_once('@') {
                Some((p, n)) => (p, n.parse::<usize>().unwrap_or(1)),
                None => (point, 1),
            };
            if point != name || at != count {
                continue;
            }
            match action {
                "" => {
                    eprintln!("socket-patch: failpoint `{name}` #{count} hit; exiting");
                    std::process::exit(86);
                }
                "error" => {
                    return Err(std::io::Error::other(format!(
                        "failpoint `{name}` #{count} injected an error"
                    )));
                }
                "pause" => {
                    drop(hits);
                    eprintln!("socket-patch: failpoint `{name}` #{count} paused");
                    if let Some(ready) = std::env::var_os("SOCKET_PATCH_FAILPOINT_READY") {
                        let _ = std::fs::write(ready, b"");
                    }
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(3600));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
    #[cfg(not(any(debug_assertions, feature = "failpoints")))]
    {
        let _ = name;
        Ok(())
    }
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
