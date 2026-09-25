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
//!   When not even one walk thread could be spawned the walk falls back to
//!   the blocking-pool thread and its 2 MiB: only `node_modules` nesting
//!   depth is exposed there, since the workspace-roots walk (the one that
//!   sees arbitrary project trees) is iterative.
//! - **Descriptor headroom.** The sequential walk held at most one
//!   directory stream (or package.json) open at a time, and the nine
//!   ecosystem crawlers ran one after another. Every walker treats a failed
//!   `read_dir`/open — `EMFILE` included — as "absent", so a process that
//!   needs more descriptors than the old one would silently drop packages
//!   under a tight `RLIMIT_NOFILE` the old one handled. Under such a limit
//!   ([`fd_limit_is_tight`]) the pool gets ONE thread and the crawlers run
//!   serially (the old descriptor profile); otherwise the thread count is
//!   capped so the extra descriptors stay well inside the limit.
//!
//! Peak MEMORY has no such budget, and does not survive the move: the walk
//! holds up to one package.json per walk thread at once (each read sizes
//! its buffer from the file, with no cap), where the sequential walk held
//! one. Real trees barely notice — package.json files are kilobytes — but
//! one outsized file in an untrusted tree now costs [`walk_threads`]
//! copies instead of one. Capping the read would change what the crawler
//! inventories, so the trade is deliberate, not an oversight. What the
//! thread count itself costs — those buffers and a [`WALK_STACK_SIZE`]
//! stack each — is why it has a ceiling ([`MAX_WALK_THREADS`]) as well as
//! a floor: the walk is I/O-bound and flat well below it, so a bigger
//! machine would buy nothing and reserve hundreds of megabytes for it.

use std::sync::OnceLock;

use rayon::iter::{IntoParallelIterator, ParallelIterator};

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

/// Ceiling on the pool, whatever the machine's parallelism. The walk is
/// descriptor- and page-cache-bound, not CPU-bound: it flattens well below
/// this, while every thread costs a [`WALK_STACK_SIZE`] stack and another
/// package.json buffer (see the module docs). Without it a 96-core CI
/// runner built 96 threads and 768 MiB of reserved stack to walk one
/// project's node_modules. The descriptor budget below can only lower it —
/// above [`TIGHT_NOFILE_LIMIT`] the budget is never the binding term, and
/// below it the pool is one thread.
const MAX_WALK_THREADS: usize = 16;

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

/// Walk threads for `cpus` logical CPUs under `soft_limit`: what the
/// descriptors leave room for, under the I/O-bound ceiling.
fn walk_threads(cpus: usize, soft_limit: Option<u64>) -> usize {
    descriptor_budget(cpus, soft_limit).min(MAX_WALK_THREADS)
}

/// The most walk threads `soft_limit` leaves room for, before
/// [`MAX_WALK_THREADS`] applies.
fn descriptor_budget(cpus: usize, soft_limit: Option<u64>) -> usize {
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

/// Logical CPUs. `RAYON_NUM_THREADS` can lower the count (like rayon's
/// global pool) but never raise it past the machine's parallelism.
fn default_cpus() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    std::env::var("RAYON_NUM_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .map_or(cpus, |n| n.min(cpus))
}

/// The walk pool, built on first use. `None` if not even one walk thread
/// could be spawned; the walk then runs on the calling thread (see
/// [`par_map`]).
fn walk_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        build_with_fallback(
            walk_threads(default_cpus(), soft_nofile_limit()),
            |threads| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .stack_size(WALK_STACK_SIZE)
                    .thread_name(|i| format!("socket-patch-walk-{i}"))
                    .build()
            },
        )
    })
    .as_ref()
}

/// Build a pool of `threads` threads, halving the count on every failure
/// (the OS refusing threads: `RLIMIT_NPROC`, a cgroup `pids.max`, memory
/// for the stacks) down to one. `None` once even one thread fails.
fn build_with_fallback<P, E>(threads: usize, build: impl Fn(usize) -> Result<P, E>) -> Option<P> {
    let mut threads = threads.max(1);
    loop {
        match build(threads) {
            Ok(pool) => return Some(pool),
            Err(_) if threads > 1 => threads /= 2,
            Err(_) => return None,
        }
    }
}

/// `items.map(f)` in order: in parallel on the walk pool's threads, and
/// sequentially on any thread outside a rayon pool — the calling thread
/// [`run_walk`] falls back to when no walk thread could be spawned. A
/// parallel iterator there would instead build rayon's global pool, which
/// needs the very threads the OS just refused, and panic when it cannot.
pub(crate) fn par_map<I, F, T>(items: I, f: F) -> Vec<T>
where
    I: IntoParallelIterator + IntoIterator<Item = <I as IntoParallelIterator>::Item>,
    F: Fn(<I as IntoParallelIterator>::Item) -> T + Sync + Send,
    T: Send,
{
    if rayon::current_thread_index().is_some() {
        items.into_par_iter().map(f).collect()
    } else {
        items.into_iter().map(f).collect()
    }
}

/// Run a blocking walk on the walk pool, from a blocking-pool thread so
/// the async runtime is never stalled, and hand back its value. A panic
/// inside `f` is re-raised on the awaiting task (see [`run_blocking`]).
pub(crate) async fn run_walk<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let pool_disabled = test_hooks::pool_disabled();
    run_blocking(move || match walk_pool().filter(|_| !pool_disabled) {
        Some(pool) => pool.install(f),
        None => f(),
    })
    .await
}

/// Lets a test drive [`run_walk`]'s no-pool fallback (walk on the calling
/// thread) without actually exhausting the OS's threads. The switch is
/// per calling thread (read before the hop to the blocking pool), so it
/// never leaks into concurrently running tests.
pub(crate) mod test_hooks {
    #[cfg(test)]
    thread_local! {
        static POOL_DISABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    #[cfg(test)]
    pub(crate) fn pool_disabled() -> bool {
        POOL_DISABLED.with(|d| d.get())
    }

    #[cfg(not(test))]
    pub(crate) fn pool_disabled() -> bool {
        false
    }

    /// Runs walks started from this thread without the walk pool until
    /// the guard drops.
    #[cfg(test)]
    pub(crate) struct DisablePool(());

    #[cfg(test)]
    impl DisablePool {
        pub(crate) fn new() -> Self {
            POOL_DISABLED.with(|d| d.set(true));
            Self(())
        }
    }

    #[cfg(test)]
    impl Drop for DisablePool {
        fn drop(&mut self) {
            POOL_DISABLED.with(|d| d.set(false));
        }
    }
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
            assert_eq!(descriptor_budget(64, Some(limit)), 1, "limit {limit}");
        }
    }

    #[test]
    fn thread_count_stays_inside_the_descriptor_budget() {
        assert_eq!(descriptor_budget(14, Some(256)), 14);
        assert_eq!(descriptor_budget(14, Some(1024)), 14);
        assert_eq!(descriptor_budget(14, None), 14);
        assert_eq!(descriptor_budget(0, None), 1);
        assert_eq!(descriptor_budget(256, Some(TIGHT_NOFILE_LIMIT)), 32);
        assert_eq!(descriptor_budget(256, Some(1024)), 256);
        assert_eq!(descriptor_budget(1024, Some(1024)), 480);
        for limit in [TIGHT_NOFILE_LIMIT, 200, 256, 1024, 4096] {
            let threads = walk_threads(1024, Some(limit)) as u64;
            assert!(threads >= 1 && threads + RESERVED_FDS <= limit, "{limit}");
        }
    }

    /// The walk is I/O-bound, so a bigger machine stops buying threads:
    /// the pool is capped however many CPUs and descriptors there are.
    /// Below the cap, the machine and the descriptor budget still decide.
    #[test]
    fn thread_count_is_capped_however_big_the_machine_is() {
        assert_eq!(walk_threads(96, Some(1024)), MAX_WALK_THREADS);
        assert_eq!(walk_threads(1024, Some(1024)), MAX_WALK_THREADS);
        assert_eq!(walk_threads(1024, None), MAX_WALK_THREADS);
        assert_eq!(
            walk_threads(256, Some(TIGHT_NOFILE_LIMIT)),
            MAX_WALK_THREADS
        );
        // Under the cap nothing changed: the CPU count still binds.
        assert_eq!(walk_threads(4, Some(1024)), 4);
        assert_eq!(walk_threads(MAX_WALK_THREADS, None), MAX_WALK_THREADS);
        assert_eq!(
            walk_threads(MAX_WALK_THREADS - 1, None),
            MAX_WALK_THREADS - 1
        );
    }

    #[test]
    fn pool_build_halves_the_thread_count_until_it_succeeds() {
        let tried = std::sync::Mutex::new(Vec::new());
        let built = build_with_fallback(14, |n| {
            tried.lock().unwrap().push(n);
            if n <= 3 {
                Ok(n)
            } else {
                Err(())
            }
        });
        assert_eq!(built, Some(3));
        assert_eq!(*tried.lock().unwrap(), [14, 7, 3]);

        tried.lock().unwrap().clear();
        let none = build_with_fallback(5, |n| {
            tried.lock().unwrap().push(n);
            Err::<usize, ()>(())
        });
        assert_eq!(none, None);
        assert_eq!(*tried.lock().unwrap(), [5, 2, 1]);
        assert_eq!(build_with_fallback(0, Ok::<usize, ()>), Some(1));
    }

    /// Outside a rayon pool (the no-walk-pool fallback) `par_map` runs
    /// every item on the calling thread and never touches rayon's global
    /// pool; inside one it fans out. Both keep input order.
    #[test]
    fn par_map_is_sequential_outside_a_pool_and_ordered_everywhere() {
        let out = std::thread::spawn(|| {
            assert!(rayon::current_thread_index().is_none());
            let caller = std::thread::current().id();
            par_map((0..1000).collect::<Vec<usize>>(), move |i| {
                assert_eq!(std::thread::current().id(), caller);
                i * 2
            })
        })
        .join()
        .unwrap();
        assert_eq!(out, (0..1000).map(|i| i * 2).collect::<Vec<_>>());

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let items: Vec<usize> = (0..1000).collect();
        let out = pool.install(|| par_map(&items, |&i| i + 1));
        assert_eq!(out, (1..=1000).collect::<Vec<_>>());
    }

    /// [`par_map`] is the crate's ONLY rayon parallel iterator. A bare one
    /// anywhere else runs on rayon's global pool whenever its caller is
    /// off-pool — the no-walk-pool fallback, where building that pool needs
    /// the very threads the OS just refused and panics when it cannot get
    /// them. Checked against the sources, because the escape is invisible
    /// on a machine that can still spawn threads (a crawler's equivalence
    /// oracle passes either way). A future parallel map belongs in
    /// `par_map` too, even one written inside a `pool.install`.
    #[test]
    fn par_map_is_the_crates_only_rayon_iterator() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let (mut offenders, mut scanned) = (Vec::new(), 0);
        for entry in walkdir::WalkDir::new(&src)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "rs") || path.ends_with("walk_pool.rs") {
                continue;
            }
            let text = std::fs::read_to_string(path).expect("crate source is readable");
            scanned += 1;
            for (line_no, line) in text.lines().enumerate() {
                if line.contains("par_iter()") || line.contains("par_bridge()") {
                    offenders.push(format!("{}:{}", path.display(), line_no + 1));
                }
            }
        }
        assert!(scanned > 50, "the crate sources were not found: {scanned}");
        assert!(
            offenders.is_empty(),
            "bare rayon iterators (use walk_pool::par_map): {offenders:?}"
        );
    }

    /// With no walk pool the walk runs off-pool (so `par_map` stays
    /// sequential); otherwise on a walk-pool thread.
    #[tokio::test]
    async fn walk_without_a_pool_runs_outside_rayon() {
        {
            let _off = test_hooks::DisablePool::new();
            assert_eq!(run_walk(rayon::current_thread_index).await, None);
        }
        assert!(run_walk(rayon::current_thread_index).await.is_some());
    }

    /// The walk runs on a pool thread with the main thread's stack, not
    /// the 2 MiB default of rayon/tokio workers: a 4 MiB stack frame fits.
    ///
    /// The 8 MiB belongs to the POOL's threads. With no pool [`run_walk`]
    /// falls back to the blocking-pool thread, whose stack is the
    /// runtime's 2 MiB default — the frame below would overflow it, and a
    /// stack overflow aborts the whole test binary rather than failing one
    /// test. So there is nothing to pin on a machine that could not spawn
    /// a walk thread; skip instead of aborting 4,000 other tests.
    #[tokio::test]
    async fn walk_runs_on_a_main_sized_stack() {
        if walk_pool().is_none() {
            return;
        }
        #[inline(never)]
        fn big_frame() -> u8 {
            let mut buf = [0u8; 4 << 20];
            std::hint::black_box(&mut buf);
            buf[(4 << 20) - 1]
        }
        assert_eq!(run_walk(big_frame).await, 0);
    }
}
