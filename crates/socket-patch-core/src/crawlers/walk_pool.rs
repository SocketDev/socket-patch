//! The dedicated thread pool the npm crawler's parallel walks run on, and
//! the file-descriptor budget that sizes it.
//!
//! Two properties of the old one-`spawn_blocking`-per-call async walk must
//! survive the move to parallel sync walks:
//!
//! - **Stack depth.** The async walk recursed through `Box::pin` futures
//!   polled on the `#[tokio::main]` thread (8 MiB on Unix, and on Windows
//!   via the `/STACK` link flag in `.cargo/config.toml`). Rayon's and
//!   tokio's worker threads default to 2 MiB, so the recursive gather runs
//!   on pool threads built with the same 8 MiB ([`WALK_STACK_SIZE`]).
//! - **Descriptor headroom.** The sequential walk held at most one
//!   directory stream (or package.json) open at a time, and the nine
//!   ecosystem crawlers ran one after another. Every walker treats a failed
//!   `read_dir`/open — `EMFILE` included — as "absent", so a process that
//!   needs more descriptors than the old one would silently drop packages
//!   under a tight `RLIMIT_NOFILE` the old one handled. Under such a limit
//!   ([`fd_limit_is_tight`]) the pool gets ONE thread and the crawlers run
//!   serially (the old descriptor profile); otherwise the thread count is
//!   capped so the extra descriptors stay well inside the limit.

use std::sync::OnceLock;

use crate::utils::fs::run_blocking;

/// Stack size of each walk thread: the main thread's (see module docs).
const WALK_STACK_SIZE: usize = 8 * 1024 * 1024;

/// A soft `RLIMIT_NOFILE` below this runs the crawl with the sequential
/// walk's descriptor profile: one walk thread, crawlers one at a time.
/// (macOS's default soft limit is 256, Linux's 1024.)
const TIGHT_NOFILE_LIMIT: u64 = 128;

/// Descriptors left to the rest of the process (stdio, the runtime, the
/// other crawlers' walks and subprocess pipes) when sizing the pool above
/// the tight limit; each walk thread holds at most one descriptor, and
/// the pool takes at most half of what remains.
const RESERVED_FDS: u64 = 64;

/// The process's soft `RLIMIT_NOFILE`, read once. `None` when unlimited
/// or unknown (and on Windows, whose handle table has no comparable
/// per-process cap).
fn soft_nofile_limit() -> Option<u64> {
    static LIMIT: OnceLock<Option<u64>> = OnceLock::new();
    *LIMIT.get_or_init(read_soft_nofile_limit)
}

#[cfg(unix)]
fn read_soft_nofile_limit() -> Option<u64> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit only writes the struct we pass it.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return None;
    }
    if limit.rlim_cur == libc::RLIM_INFINITY {
        return None;
    }
    #[allow(clippy::unnecessary_cast)] // rlim_t is u32 on some targets
    Some(limit.rlim_cur as u64)
}

#[cfg(not(unix))]
fn read_soft_nofile_limit() -> Option<u64> {
    None
}

/// Whether the descriptor limit is too tight for concurrent crawling (see
/// the module docs). The ecosystem dispatch then runs the crawlers one at
/// a time, and the walk pool has a single thread.
pub fn fd_limit_is_tight() -> bool {
    is_tight(soft_nofile_limit())
}

fn is_tight(soft_limit: Option<u64>) -> bool {
    soft_limit.is_some_and(|limit| limit < TIGHT_NOFILE_LIMIT)
}

/// Walk threads for `cpus` logical CPUs under `soft_limit`.
fn walk_threads(cpus: usize, soft_limit: Option<u64>) -> usize {
    if is_tight(soft_limit) {
        return 1;
    }
    let cpus = cpus.max(1);
    match soft_limit {
        Some(limit) => {
            let budget =
                usize::try_from(limit.saturating_sub(RESERVED_FDS) / 2).unwrap_or(usize::MAX);
            cpus.min(budget).max(1)
        }
        None => cpus,
    }
}

/// Logical CPUs, honoring `RAYON_NUM_THREADS` like rayon's global pool.
fn default_cpus() -> usize {
    std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1)
}

/// The walk pool, built on first use. `None` if its threads could not be
/// spawned; the walk then runs on the calling thread (rayon falls back to
/// its global pool for the parallel parts).
fn walk_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(walk_threads(default_cpus(), soft_nofile_limit()))
            .stack_size(WALK_STACK_SIZE)
            .thread_name(|i| format!("socket-patch-walk-{i}"))
            .build()
            .ok()
    })
    .as_ref()
}

/// Run a blocking walk on the walk pool, from a blocking-pool thread so
/// the async runtime is never stalled, and hand back its value. A panic
/// inside `f` is re-raised on the awaiting task (see [`run_blocking`]).
pub(crate) async fn run_walk<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    run_blocking(move || match walk_pool() {
        Some(pool) => pool.install(f),
        None => f(),
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tight_limit_means_one_thread() {
        assert!(is_tight(Some(20)));
        assert!(is_tight(Some(TIGHT_NOFILE_LIMIT - 1)));
        assert!(!is_tight(Some(TIGHT_NOFILE_LIMIT)));
        assert!(!is_tight(None));
        for limit in [0, 1, 20, 64, TIGHT_NOFILE_LIMIT - 1] {
            assert_eq!(walk_threads(64, Some(limit)), 1, "limit {limit}");
        }
    }

    #[test]
    fn thread_count_stays_inside_the_descriptor_budget() {
        assert_eq!(walk_threads(14, Some(256)), 14);
        assert_eq!(walk_threads(14, Some(1024)), 14);
        assert_eq!(walk_threads(14, None), 14);
        assert_eq!(walk_threads(0, None), 1);
        assert_eq!(walk_threads(256, Some(TIGHT_NOFILE_LIMIT)), 32);
        assert_eq!(walk_threads(256, Some(1024)), 256);
        assert_eq!(walk_threads(1024, Some(1024)), 480);
        for limit in [TIGHT_NOFILE_LIMIT, 200, 256, 1024, 4096] {
            let threads = walk_threads(1024, Some(limit)) as u64;
            assert!(threads >= 1 && threads + RESERVED_FDS <= limit, "{limit}");
        }
    }

    /// The walk runs on a pool thread with the main thread's stack, not
    /// the 2 MiB default of rayon/tokio workers: a 4 MiB stack frame fits.
    #[tokio::test]
    async fn walk_runs_on_a_main_sized_stack() {
        #[inline(never)]
        fn big_frame() -> u8 {
            let mut buf = [0u8; 4 << 20];
            std::hint::black_box(&mut buf);
            buf[(4 << 20) - 1]
        }
        assert_eq!(run_walk(big_frame).await, 0);
    }
}
