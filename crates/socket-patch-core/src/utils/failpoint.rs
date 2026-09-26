//! Crash injection for the crash-safety tests, compiled into debug builds
//! (and test builds with the `failpoints` feature) only.
//!
//! `SOCKET_PATCH_FAILPOINT=<name>[@<n>][,…]` makes the process exit
//! (status 86, no destructors, no further writes) at the `n`-th time
//! (default: the first) it reaches [`hit`] with that name — the observable
//! effect of a crash at that point: whatever was written before is on disk,
//! nothing after it is. Release builds compile [`hit`] to nothing, so no
//! environment variable can make a shipped binary stop half-way; the same
//! goes for [`switched_off`]. The `failpoints` feature compiles them into an
//! optimized build as well; only the CLI's dev-dependencies enable it, so
//! it reaches the optimized test binaries (`cargo test --release`) and
//! never a `cargo build`/`cargo install` one.

/// A named crash point (see the module docs).
pub fn hit(name: &str) {
    #[cfg(any(debug_assertions, feature = "failpoints"))]
    {
        use std::collections::HashMap;
        use std::sync::Mutex;
        static HITS: Mutex<Option<HashMap<String, usize>>> = Mutex::new(None);
        let Ok(spec) = std::env::var("SOCKET_PATCH_FAILPOINT") else {
            return;
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
            let (point, at) = match point.trim().split_once('@') {
                Some((p, n)) => (p, n.parse::<usize>().unwrap_or(1)),
                None => (point.trim(), 1),
            };
            if point == name && at == count {
                eprintln!("socket-patch: failpoint `{name}` #{count} hit; exiting");
                std::process::exit(86);
            }
        }
    }
    #[cfg(not(any(debug_assertions, feature = "failpoints")))]
    let _ = name;
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
