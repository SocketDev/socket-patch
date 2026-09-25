//! Crash injection for the crash-safety tests, compiled into debug builds
//! only.
//!
//! `SOCKET_PATCH_FAILPOINT=<name>[@<n>][,…]` makes the process exit
//! (status 86, no destructors, no further writes) at the `n`-th time
//! (default: the first) it reaches [`hit`] with that name — the observable
//! effect of a crash at that point: whatever was written before is on disk,
//! nothing after it is. Release builds compile [`hit`] to nothing, so no
//! environment variable can make a shipped binary stop half-way.

/// A named crash point (see the module docs).
pub fn hit(name: &str) {
    #[cfg(debug_assertions)]
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
    #[cfg(not(debug_assertions))]
    let _ = name;
}

