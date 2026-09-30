//! Vendor-service downloads fetched ahead of the serial vendor loop.
//!
//! The vendor engine wires one package at a time (lockfile and ledger
//! writes stay serial, in sorted order), and each package's service path
//! makes two round trips — the package-reference POST and the archive GET
//! ([`ApiClient::fetch_vendor_package`]). A run that downloads many
//! prebuilt archives paid those round trips back to back. A
//! [`VendorPrefetch`] plan names the uuids the loop is expected to
//! download, in loop order; a background task fetches them ahead of the
//! loop and the loop's own call for a planned uuid takes the fetched
//! outcome instead of making the requests.
//!
//! Nothing observable may change, so the plan is advisory and every
//! decision stays at consumption time, in loop order:
//!
//! * The run-level circuit breaker is evaluated exactly as before — the
//!   prefetch never touches its counter. A call the breaker skips never
//!   consults the plan (its fetched outcome, if any, is discarded along
//!   with its debug lines), and a consumed outcome updates the counter as
//!   the live request would have. Outage messages therefore match the
//!   serial loop package for package.
//! * A call for a uuid the plan does not hold (or holds only behind the
//!   point already consumed) makes the live requests. Planned uuids the
//!   loop never asks for (a flavor refused the package first) are dropped
//!   when a later one is taken.
//! * Each prefetched request's `--debug` lines are held back and printed
//!   when the loop takes its outcome, where the serial request would have
//!   printed them.
//!
//! ## What the plan may cost
//!
//! A download grant is a real request against the service — it can start
//! a server-side build and counts against quota — so the plan is EXACT:
//! the CLI names only the packages the loop will ask the service for. It
//! evaluates every refusal a backend raises before its first service call
//! with the backend's own gates — for every ecosystem
//! ([`crate::vendor::service_preflight`], npm's
//! [`crate::vendor::npm_flavor::preflight_packages`]) — and leaves out the
//! re-runs a backend answers without the service, so a package the loop
//! refuses is never granted on its behalf (on a depscan vendored run, 71
//! grants — the serial loop's own count). The task is still bounded in
//! requests, not just in time, as a second line of defence should a plan
//! ever name a position the loop then passes over:
//!
//! * It only ever requests plan positions in `[at, at + reach)`, where
//!   `at` is the position the loop has reached and `reach` is one until
//!   the service has answered once, then slow-starts: [`SLOW_START`] (4)
//!   after the first answer, one more per good answer up to `window` (the
//!   API's in-flight cap), and back to [`SLOW_START`] on an availability
//!   failure. So it never runs more than `window` requests ahead of the
//!   loop — and only as far as the service's recent answers earned — a
//!   run that stops
//!   consulting the plan (every remaining package refused, or the loop
//!   finishing) leaves at most `window` requests outstanding, and a plan
//!   the loop never consults makes no request at all.
//! * It never requests a position the loop has already passed, and starts
//!   nothing more once it has seen
//!   [`super::client::VENDOR_BREAKER_THRESHOLD`] consecutive availability
//!   failures of its own — so a service that is down from the first
//!   package costs exactly the retry ladders the serial loop paid before
//!   its own breaker opened, not a window of them. What is already in
//!   flight when it stops is still drained and delivered: the loop needs
//!   those packages, and abandoning them would make it re-issue requests
//!   the plan has already paid for.
//! * It never requests PAST a position whose own fetch was an
//!   availability failure until the loop has consumed that position. So
//!   an outage part-way down a list the window has already widened over
//!   costs what the serial loop paid, as long as the task is running
//!   ahead of the loop (the usual case: the loop stops to write between
//!   packages). Only when the loop has caught up with the window — every
//!   package up to it granted, and the first failure the whole window's —
//!   can it spend up to `reach - 1` retry ladders the serial loop, one
//!   failure from opening its own breaker, would not have spent; `reach`
//!   is at most `window`, and reaches it only after that many good
//!   answers in a row.
//!
//! Memory is bounded too: at most `window` downloads are in flight, and
//! while the fetched archives waiting for the loop add up to the plan's
//! byte budget, only the position the loop is at may start. The budget
//! gates STARTING a download, not its bytes: the downloads already in
//! flight when it is reached still land, so the held bytes can exceed it
//! by up to `window - 1` archives (whatever their size: the budget bounds
//! new downloads, not the ones already running). Trees a [`PrestageRecipe`] extracts from those archives land
//! on disk, not in memory, and are not counted against the budget at all —
//! they are bounded by the plan (one per planned directory-shaped
//! download, removed as soon as their package is passed over or the loop
//! ends) and by the [`crate::vendor::prestage`] pool, not by size.
//!
//! The package-reference half is batched: the plan's first call sends
//! one request naming the planned uuids from its own position on (see
//! [`VendorPrefetch::reference`]) in place of its own, and later calls
//! take their granted reference from it. That request grants the rest of
//! the plan up front, which the plan's exactness makes safe: a position
//! the loop passes over is granted only if the loop passes it after the
//! batch was sent. The bounds
//! above then limit the archive downloads. A package the batch reports
//! still building, or leaves out, makes its own request at its turn, as
//! before.
//!
//! A planned download may name a secondary artifact (the gem stub
//! gemspec) its backend fetches right after a verified archive; the task
//! fetches it along with the archive, under the backend's own conditions,
//! and the backend's call takes it (see
//! [`super::client::PlannedDownload`]).
//!
//! Outcomes are delivered as they finish, not in plan order: a passed-over
//! download must never hold up the package the loop is actually waiting
//! for (that would make the loop slower than serial, on a request serial
//! never made). `take` puts an early outcome aside until its own call.
//! Dropping the [`VendorPrefetchGuard`] detaches the plan and aborts the
//! task.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use futures_util::StreamExt;

use super::client::{
    hold_back_debug, ApiClient, HeldBack, PlannedDownload, PrefetchedSecondary,
    VendorServiceOutcome, MAX_REFERENCE_BATCH, VENDOR_BREAKER_THRESHOLD,
};
use super::types::PackageVendorResult;
use crate::api::client::ApiError;
use crate::vendor::lock_inventory::LockIntegrity;
use crate::vendor::prestage::PrestageRecipe;
use crate::vendor::registry_fetch::{artifact_matches_integrity, verify_go_h1};

/// Where the task's reach opens once the service has answered, and where
/// it falls back to after an availability failure (see
/// [`Lookahead::grow`]).
const SLOW_START: usize = 4;

/// The reach after one more good answer: [`SLOW_START`] at first, then one
/// more per answer, never past `window`.
fn next_reach(reach: usize, window: usize) -> usize {
    let window = window.max(1);
    if reach < SLOW_START {
        SLOW_START.min(window)
    } else {
        (reach + 1).min(window)
    }
}

/// One fetched outcome: `(outcome, retryable failure)` as
/// `fetch_vendor_package_once` returned it, debug lines held back.
type Fetched = HeldBack<(VendorServiceOutcome, bool)>;

/// A planned run of vendor-service downloads; see the module docs.
#[derive(Debug)]
pub(crate) struct VendorPrefetch {
    /// The request parameters every planned call must match.
    free_only: bool,
    vendor_url: Option<String>,
    patch_server_url: Option<String>,
    /// Planned uuids, in the order the vendor loop consumes them.
    planned: Vec<String>,
    /// Per planned uuid, what rides its download (see [`PlannedDownload`]):
    /// the served secondary artifact the loop's backend downloads right
    /// after a verified archive (the gem stub gemspec), and the recipe
    /// that stages the archive ahead of the backend.
    riders: Vec<Riders>,
    /// Most downloads in flight at once, and the most the task may run
    /// ahead of the loop.
    window: usize,
    /// What the task is allowed to request, shared with it.
    look: Arc<Lookahead>,
    state: tokio::sync::Mutex<PrefetchState>,
    /// The plan's package references, resolved in one batch by the first
    /// planned call (see [`Self::reference`]) and taken uuid by uuid.
    references: tokio::sync::OnceCell<std::sync::Mutex<HashMap<String, PackageVendorResult>>>,
}

/// The window of plan positions the task may request: `[at, at + reach)`,
/// and never past `barrier`. All three move — `at` as the loop consumes,
/// `reach` once the service has answered, `barrier` as the service fails
/// and as the loop consumes the failure — so the speculation is bounded in
/// REQUESTS both by what the loop has actually reached and by what the
/// service is actually answering (see the module docs). Gating on the
/// position rather than on a count of permits keeps the order
/// deterministic: the futures are polled in whatever order the unordered
/// pool likes, so a counter would hand the opening request to an arbitrary
/// position.
#[derive(Debug)]
struct Lookahead {
    /// The plan position the loop is at; everything below it was passed
    /// over and must never be requested.
    at: AtomicUsize,
    /// How far past `at` the task may run: one until the service has
    /// answered once, then [`SLOW_START`], growing by one per good answer
    /// up to the whole window and falling back on availability failures.
    reach: AtomicUsize,
    /// Lowest position whose own fetch was an availability failure and
    /// that the loop has not consumed yet; nothing past it is started
    /// (see [`Self::failed`]). `usize::MAX` while the service is healthy.
    barrier: AtomicUsize,
    /// Consecutive retryable failures the TASK has seen, in the order its
    /// own requests answered. Purely a stop signal for the speculation —
    /// the observable breaker is the client's, folded at consumption time.
    failures: AtomicU32,
    /// Archive bytes fetched and not yet taken (or passed over) by the loop.
    held: AtomicUsize,
    /// While `held` is at or above this, only the position the loop is at
    /// may start: the window bounds how many archives are in flight, this
    /// bounds how many finished ones wait in memory for the loop.
    budget: usize,
    /// Set once `failures` reached the threshold: nothing more is STARTED.
    /// Sticky, unlike `failures` itself — a success draining out from
    /// behind the failures resets the count, and must not let the
    /// speculation resume against a service the loop is giving up on.
    stopped: AtomicBool,
    /// Woken whenever any of the four above moves.
    moved: tokio::sync::Notify,
}

impl Lookahead {
    fn new(budget: usize) -> Self {
        Self {
            held: AtomicUsize::new(0),
            budget,
            at: AtomicUsize::new(0),
            // Opens at one request: a service that is down from the first
            // package then costs what the serial loop cost.
            reach: AtomicUsize::new(1),
            barrier: AtomicUsize::new(usize::MAX),
            failures: AtomicU32::new(0),
            stopped: AtomicBool::new(false),
            moved: tokio::sync::Notify::new(),
        }
    }

    /// The loop has reached plan position `position`.
    fn arrive(&self, position: usize) {
        // Past the failure the barrier stands at: the loop consumed that
        // package and went on, so its breaker did not end the run and the
        // task may speculate again. (A failure landing concurrently just
        // re-sets the line; all of this is advisory, and every outcome is
        // still decided at the loop's own call.)
        if position > self.barrier.load(Ordering::Relaxed) {
            self.barrier.store(usize::MAX, Ordering::Relaxed);
        }
        self.at.store(position, Ordering::Relaxed);
        self.moved.notify_waiters();
    }

    /// The service answered: the task may run further ahead — slow start.
    /// The first answer opens the reach to [`SLOW_START`]; every later one
    /// adds a position, up to the full `window` (so the reach roughly
    /// doubles per round of answers, as a TCP congestion window does). A
    /// service that stops answering well only ever faces a reach its own
    /// recent answers earned.
    fn grow(&self, window: usize) {
        let _ = self
            .reach
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reach| {
                Some(next_reach(reach, window))
            });
        self.moved.notify_waiters();
    }

    /// An availability failure: the reach falls back to [`SLOW_START`]
    /// (never below one), and grows again only with fresh answers.
    fn shrink(&self) {
        let _ = self
            .reach
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |reach| {
                Some(reach.clamp(1, SLOW_START))
            });
        self.moved.notify_waiters();
    }

    /// Plan position `index` failed to reach the service: nothing past it
    /// is started until the loop has consumed it. The loop is about to
    /// meet a failing service at that package and one more failure stops
    /// the task, so speculating past it aims retry ladders at a struggling
    /// host for packages the serial loop — one failure from opening its
    /// own breaker — asked nothing for.
    ///
    /// Lowest failure wins: a later position's failure must not move the
    /// line past an earlier one the loop has yet to reach.
    fn failed(&self, index: usize) {
        self.barrier.fetch_min(index, Ordering::Relaxed);
        self.moved.notify_waiters();
    }

    /// `bytes` of fetched archive left memory (taken or passed over).
    fn drained(&self, bytes: usize) {
        self.held.fetch_sub(bytes, Ordering::Relaxed);
        self.moved.notify_waiters();
    }

    /// The task's own breaker opened: start nothing more, for good.
    fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.moved.notify_waiters();
    }

    /// Wait until plan position `index` may be requested; `false` when it
    /// never may be (the loop passed it, or the task's breaker opened).
    async fn admits(&self, index: usize) -> bool {
        loop {
            let notified = self.moved.notified();
            tokio::pin!(notified);
            // Armed before the check, so a move between the two is not lost.
            notified.as_mut().enable();
            if index < self.at.load(Ordering::Relaxed) || self.stopped.load(Ordering::Relaxed) {
                return false;
            }
            let at = self.at.load(Ordering::Relaxed);
            if index <= self.barrier.load(Ordering::Relaxed)
                && index < at + self.reach.load(Ordering::Relaxed)
                && (index == at || self.held.load(Ordering::Relaxed) < self.budget)
            {
                return true;
            }
            notified.await;
        }
    }
}

#[derive(Debug, Default)]
struct PrefetchState {
    /// First plan position not yet consumed or passed over — where the
    /// next lookup starts, so a repeated call never waits on an outcome
    /// already taken.
    next: usize,
    /// Outcomes from the task, tagged with their plan position, as they
    /// finish. `None` until the loop's first planned call starts the task.
    rx: Option<tokio::sync::mpsc::Receiver<(usize, Fetched)>>,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Outcomes that answered before the loop asked for them, by position.
    ready: HashMap<usize, Fetched>,
}

impl Drop for PrefetchState {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

impl VendorPrefetch {
    pub(crate) fn new(
        planned: Vec<PlannedDownload>,
        free_only: bool,
        vendor_url: Option<&str>,
        patch_server_url: Option<&str>,
        window: usize,
        byte_budget: usize,
    ) -> Self {
        let (planned, riders) = planned
            .into_iter()
            .map(|d| {
                (
                    d.uuid,
                    Riders {
                        secondary: d.secondary,
                        stage: d.stage,
                    },
                )
            })
            .unzip();
        Self {
            free_only,
            vendor_url: vendor_url.map(str::to_string),
            patch_server_url: patch_server_url.map(str::to_string),
            planned,
            riders,
            window: window.max(1),
            look: Arc::new(Lookahead::new(byte_budget)),
            state: tokio::sync::Mutex::new(PrefetchState::default()),
            references: tokio::sync::OnceCell::new(),
        }
    }

    /// Step 1 (the package-reference request) for a planned `uuid`, or
    /// `None` to make the live request (not planned, other parameters, or
    /// the batch did not answer it).
    ///
    /// The first planned call sends ONE request naming the plan from its
    /// own position on, its own uuid first, in place of its single-uuid request and with the
    /// same retry ladder: the endpoint takes up to [`MAX_REFERENCE_BATCH`]
    /// uuids, and one request per package paid a round trip and a quota
    /// unit each. Its failure is that call's own failure, so an outage
    /// costs what the serial loop paid, and every later call makes its
    /// live request. A package still building (`pending_build`) is asked
    /// again at its own turn, as the serial loop did, since it may be
    /// ready by then; every other answer is final and is reused.
    pub(crate) async fn reference(
        &self,
        client: &ApiClient,
        uuid: &str,
        free_only: bool,
        vendor_url: Option<&str>,
    ) -> Option<Result<PackageVendorResult, (ApiError, bool)>> {
        if free_only != self.free_only || vendor_url != self.vendor_url.as_deref() {
            return None;
        }
        let at = self.planned.iter().position(|planned| planned == uuid)?;
        let mut own = None;
        let cache = self
            .references
            .get_or_init(|| async {
                // Positions before this call's were passed over: the loop
                // never asks for them, so they are never granted.
                let mut order = vec![uuid.to_string()];
                for planned in &self.planned[at..] {
                    if !order.contains(planned) {
                        order.push(planned.clone());
                    }
                }
                let mut kept = HashMap::new();
                for (i, chunk) in order.chunks(MAX_REFERENCE_BATCH).enumerate() {
                    match client
                        .request_vendor_references(chunk, free_only, vendor_url)
                        .await
                    {
                        Ok(mut results) => {
                            if i == 0 {
                                own = Some(results.remove(uuid).ok_or_else(|| {
                                    (
                                        ApiError::Other(format!(
                                            "package response missing a result for {uuid}"
                                        )),
                                        false,
                                    )
                                }));
                            }
                            kept.extend(
                                results
                                    .into_iter()
                                    .filter(|(_, r)| r.status != "pending_build"),
                            );
                        }
                        Err(e) if i == 0 => {
                            own = Some(Err(e));
                            break;
                        }
                        // The chunk's uuids make their live requests.
                        Err(_) => break,
                    }
                }
                std::sync::Mutex::new(kept)
            })
            .await;
        if own.is_some() {
            return own;
        }
        cache.lock().ok()?.remove(uuid).map(Ok)
    }

    /// The prefetched outcome of the loop's call for `uuid`, or `None` to
    /// make the live requests. Plan positions before `uuid`'s are passed
    /// over (their outcomes discarded unreleased).
    pub(crate) async fn take(
        &self,
        client: &ApiClient,
        uuid: &str,
        free_only: bool,
        vendor_url: Option<&str>,
        patch_server_url: Option<&str>,
    ) -> Option<Fetched> {
        if free_only != self.free_only
            || vendor_url != self.vendor_url.as_deref()
            || patch_server_url != self.patch_server_url.as_deref()
        {
            return None;
        }
        let mut state = self.state.lock().await;
        let from = state.next;
        let position = from
            + self.planned[from..]
                .iter()
                .position(|planned| planned == uuid)?;
        // Pass over every position before this one: the task must not
        // request them, anything they already answered is dropped
        // (unreleased, with its debug lines), and the loop's arrival here
        // is what lets the task run one position further.
        state.next = position + 1;
        // Everything BELOW this position was passed over; this position's
        // own outcome, if it already answered, is the one being taken.
        let look = &self.look;
        state.ready.retain(|index, fetched| {
            let keep = *index >= position;
            if !keep {
                look.drained(archive_bytes(fetched));
            }
            keep
        });
        self.look.arrive(position);
        if state.task.is_none() {
            self.start(&mut state, client, position);
        }
        let PrefetchState { rx, ready, .. } = &mut *state;
        if let Some(fetched) = ready.remove(&position) {
            self.look.drained(archive_bytes(&fetched));
            return Some(fetched);
        }
        let rx = rx.as_mut()?;
        loop {
            match rx.recv().await {
                Some((index, fetched)) if index == position => {
                    self.look.drained(archive_bytes(&fetched));
                    return Some(fetched);
                }
                // A later position answered first: keep it for its own
                // call. An earlier one was passed over — drop it here.
                Some((index, fetched)) => {
                    if index > position {
                        ready.insert(index, fetched);
                    } else {
                        self.look.drained(archive_bytes(&fetched));
                    }
                }
                // The task stopped (its breaker, or the plan ran out) and
                // this position never came: fetch live from here on.
                _ => break,
            }
        }
        state.rx = None;
        state.next = self.planned.len();
        self.look.arrive(self.planned.len());
        None
    }

    /// Spawn the task fetching `planned[from..]`, at most `window` at once.
    fn start(&self, state: &mut PrefetchState, client: &ApiClient, from: usize) {
        let (tx, rx) = tokio::sync::mpsc::channel(self.window);
        let client = client.clone();
        let planned: Vec<(String, Riders)> = self.planned[from..]
            .iter()
            .cloned()
            .zip(self.riders[from..].iter().cloned())
            .collect();
        let (free_only, window) = (self.free_only, self.window);
        let vendor_url = self.vendor_url.clone();
        let patch_server_url = self.patch_server_url.clone();
        let look = Arc::clone(&self.look);
        state.task = Some(tokio::spawn(async move {
            let (client, vendor_url, patch_server_url) =
                (&client, vendor_url.as_deref(), patch_server_url.as_deref());
            let look = &look;
            // UNORDERED on purpose, unlike every folding loop in the CLI:
            // nothing observable is folded here, and a passed-over
            // download must not delay the one the loop is waiting for.
            // `take` puts each outcome back on its own call.
            let mut fetched =
                std::pin::pin!(futures_util::stream::iter(planned.into_iter().enumerate())
                    .map(
                        move |(offset, (uuid, riders)): (usize, (String, Riders))| async move {
                            let index = from + offset;
                            if !look.admits(index).await {
                                return None;
                            }
                            let mut held = hold_back_debug(client.fetch_vendor_package_once(
                                &uuid,
                                free_only,
                                vendor_url,
                                patch_server_url,
                            ))
                            .await;
                            ride_along(client, &mut held, riders).await;
                            Some((index, held))
                        }
                    )
                    .buffer_unordered(window));
            while let Some(item) = fetched.next().await {
                let Some((index, held)) = item else { continue };
                // Counted before the send, released by `take`.
                look.held.fetch_add(archive_bytes(&held), Ordering::Relaxed);
                let availability_failure =
                    matches!(held.peek(), (VendorServiceOutcome::Failed(_), true));
                if availability_failure {
                    look.failures.fetch_add(1, Ordering::Relaxed);
                    // Set BEFORE the send below, which can yield: the next
                    // poll of the stream is what pulls a new position in,
                    // and it must already see the line.
                    look.shrink();
                    look.failed(index);
                } else {
                    if !matches!(held.peek(), (VendorServiceOutcome::Failed(_), false)) {
                        // Anything but a failure proves the service is up. A
                        // NON-retryable failure (auth, parse) says nothing
                        // about availability either way, so it neither counts
                        // nor resets — exactly the client breaker's rule.
                        look.failures.store(0, Ordering::Relaxed);
                    }
                    look.grow(window);
                }
                if look.failures.load(Ordering::Relaxed) >= VENDOR_BREAKER_THRESHOLD {
                    // Start nothing more — but keep draining. The requests
                    // already in flight are for packages BEHIND the
                    // failures, which the loop has yet to reach and will
                    // otherwise re-issue live; dropping the stream here
                    // would make the outage cost the service each of them
                    // twice. Positions not yet started cost nothing:
                    // `admits` refuses them without a request.
                    look.stop();
                }
                if tx.send((index, held)).await.is_err() {
                    return;
                }
            }
        }));
        state.rx = Some(rx);
    }
}

/// The archive bytes a fetched outcome holds in memory.
fn archive_bytes(fetched: &Fetched) -> usize {
    match fetched.peek() {
        (VendorServiceOutcome::Ready(pkg), _) => pkg.tarball.len(),
        _ => 0,
    }
}

/// What rides one planned download (see [`PlannedDownload`]).
#[derive(Debug, Clone)]
struct Riders {
    secondary: Option<String>,
    stage: Option<PrestageRecipe>,
}

/// Do what rides a planned download — exactly when the loop's backend
/// would get that far: the archive is ready and passes the integrity checks
/// `fetch_verified_archive` runs before handing it over.
///
/// * The secondary artifact of `kind`, when the service served one (the
///   first, as `fetch_verified_secondary` picks), is downloaded with its
///   debug lines held on the artifact for `fetch_verified_secondary` to
///   take.
/// * The stage recipe runs on the bytes (see [`crate::vendor::prestage`]);
///   what it produced rides the archive to the backend.
async fn ride_along(client: &ApiClient, held: &mut Fetched, riders: Riders) {
    let Riders { secondary, stage } = riders;
    if secondary.is_none() && stage.is_none() {
        return;
    }
    let (VendorServiceOutcome::Ready(pkg), _) = held.peek_mut() else {
        return;
    };
    let intact = artifact_matches_integrity(
        &pkg.tarball,
        "",
        &LockIntegrity::Sri(pkg.integrity_sri.clone()),
    )
    .is_ok()
        && pkg
            .dirhash_h1
            .as_deref()
            .is_none_or(|h1| verify_go_h1(&pkg.tarball, h1).is_ok());
    if !intact {
        return;
    }
    if let Some(kind) = secondary {
        if let Some(artifact) = pkg.secondary_artifacts.iter_mut().find(|a| a.kind == kind) {
            let downloaded = hold_back_debug(client.download_artifact(&artifact.url)).await;
            artifact.prefetched = Some(PrefetchedSecondary::new(downloaded));
        }
    }
    if let Some(recipe) = stage {
        let (bytes, prestaged) =
            crate::vendor::prestage::run(&recipe, std::mem::take(&mut pkg.tarball)).await;
        pkg.tarball = bytes;
        pkg.prestaged = prestaged;
    }
}

/// Keeps a [`VendorPrefetch`] plan attached to its client; dropping it
/// detaches the plan and aborts any downloads still in flight.
#[must_use = "the plan is detached when the guard drops"]
#[derive(Debug)]
pub struct VendorPrefetchGuard {
    pub(crate) slot: Arc<std::sync::Mutex<Option<Arc<VendorPrefetch>>>>,
    /// The plan this guard attached. Only that one is detached on drop, so
    /// a guard outliving a plan attached after it cannot take the newer
    /// plan down with it.
    pub(crate) plan: Arc<VendorPrefetch>,
}

impl Drop for VendorPrefetchGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.lock() {
            if slot
                .as_ref()
                .is_some_and(|attached| Arc::ptr_eq(attached, &self.plan))
            {
                slot.take();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Oracle tests: every call sequence yields, call for call, exactly the
    //! outcomes (and final breaker count) of the same sequence with no plan
    //! attached — the serial loop.
    use super::*;
    use crate::api::client::{ApiClientOptions, VendorRetryPolicy};
    use base64::Engine as _;
    use sha2::{Digest as _, Sha512};
    use std::time::Duration;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const POST_PATH: &str = "/v0/orgs/acme/patches/package";

    /// How the service answers one uuid.
    #[derive(Clone, Copy)]
    enum Script {
        /// Granted, with this delay on the POST.
        Granted(u64),
        /// 503 on every POST attempt (a retryable availability failure).
        Down,
        /// 403 (a non-retryable failure: says nothing about availability).
        Forbidden,
        Pending,
        NotFound,
    }

    fn uuid(i: usize) -> String {
        format!("{i:08x}-0000-4000-8000-{i:012x}")
    }

    fn client(uri: &str) -> ApiClient {
        ApiClient::new(ApiClientOptions {
            api_url: uri.to_string(),
            api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
            use_public_proxy: false,
            org_slug: Some("acme".into()),
        })
        .with_vendor_retry(VendorRetryPolicy {
            attempts: 3,
            base: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            ..VendorRetryPolicy::default()
        })
    }

    async fn serve(scripts: &[Script]) -> MockServer {
        let server = MockServer::start().await;
        for (i, script) in scripts.iter().enumerate() {
            let u = uuid(i);
            let serve_path = format!("/serve/{u}.tgz");
            let bytes = u.as_bytes().to_vec();
            let post = |resp: ResponseTemplate| {
                Mock::given(method("POST"))
                    .and(path(POST_PATH))
                    .and(body_partial_json(
                        serde_json::json!({ "uuids": [u.clone()] }),
                    ))
                    .respond_with(resp)
            };
            let status_body = |status: &str| {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { u.clone(): { "status": status, "url": null, "artifacts": [] } }
                }))
            };
            let resp = match *script {
                Script::Granted(delay) => {
                    let url = format!("{}{serve_path}", server.uri());
                    let sri = format!(
                        "sha512-{}",
                        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&bytes))
                    );
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({
                            "results": { u.clone(): { "status": "granted", "url": url,
                                "artifacts": [{ "kind": "tarball", "url": url,
                                                "integrity": { "sha512": sri } }] } }
                        }))
                        .set_delay(Duration::from_millis(delay))
                }
                Script::Down => ResponseTemplate::new(503),
                Script::Forbidden => ResponseTemplate::new(403),
                Script::Pending => status_body("pending_build"),
                Script::NotFound => status_body("not_found"),
            };
            post(resp).mount(&server).await;
            Mock::given(method("GET"))
                .and(path(serve_path))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
                .mount(&server)
                .await;
        }
        server
    }

    fn summary(outcome: &VendorServiceOutcome) -> String {
        match outcome {
            VendorServiceOutcome::Ready(pkg) => format!(
                "ready {} {} {}",
                String::from_utf8_lossy(&pkg.tarball),
                pkg.integrity_sri,
                pkg.source_url
            ),
            VendorServiceOutcome::Pending => "pending".to_string(),
            VendorServiceOutcome::Unavailable(reason) => format!("unavailable {reason}"),
            VendorServiceOutcome::Failed(e) => format!("failed {e}"),
        }
    }

    /// Requests the mock server saw, as `"METHOD /path"`.
    async fn request_log(server: &MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect()
    }

    /// Run `calls` (indices into the scripted uuids) one at a time, with
    /// `plan` attached when given; the per-call outcomes and final count.
    async fn run(
        server: &MockServer,
        plan: Option<&[usize]>,
        calls: &[usize],
    ) -> (Vec<String>, u32) {
        let c = client(&server.uri());
        let _guard = plan.map(|plan| {
            c.prefetch_vendor_packages(
                plan.iter().map(|&i| uuid(i)).collect(),
                false,
                None,
                None,
                4,
            )
        });
        let mut out = Vec::new();
        for &i in calls {
            out.push(summary(
                &c.fetch_vendor_package(&uuid(i), false, None, None).await,
            ));
        }
        (out, c.vendor_outage_count())
    }

    async fn assert_matches_serial(scripts: &[Script], plan: &[usize], calls: &[usize]) {
        let server = serve(scripts).await;
        let serial = run(&server, None, calls).await;
        let planned = run(&server, Some(plan), calls).await;
        assert_eq!(planned, serial);
    }

    /// Later packages answer first (reversed latencies); every outcome
    /// still lands on its own call.
    #[tokio::test]
    async fn outcomes_land_on_their_own_calls_under_reversed_latencies() {
        let scripts: Vec<Script> = (0..8).map(|i| Script::Granted(20 * (8 - i))).collect();
        let all: Vec<usize> = (0..8).collect();
        assert_matches_serial(&scripts, &all, &all).await;
    }

    /// An outage from the 4th package on: the breaker opens after two
    /// failures at consumption time, so every later package reports the
    /// same "not attempted" failure the serial loop does, even the ones
    /// whose download the prefetch had already started.
    ///
    /// And it costs the service the same REQUESTS, not only the same
    /// outcomes. The task here is running ahead of a loop still on the
    /// granted packages, so nothing past the failure is ever started, and
    /// what was in flight when the task stopped is delivered instead of
    /// being dropped and re-issued live by the loop.
    #[tokio::test]
    async fn an_outage_mid_list_opens_the_breaker_at_the_same_package() {
        use Script::*;
        let scripts = [
            Granted(30),
            Granted(20),
            Granted(10),
            Down,
            Down,
            Down,
            Down,
            Down,
            Granted(0),
            Granted(0),
        ];
        let all: Vec<usize> = (0..scripts.len()).collect();
        // One server for both runs — the outcomes carry its address — so
        // the request counts are read as deltas of its cumulative log.
        let server = serve(&scripts).await;
        let (serial, count) = run(&server, None, &all).await;
        assert!(serial[5].contains("not attempted"), "{serial:?}");
        assert!(serial[9].contains("not attempted"), "{serial:?}");
        assert_eq!(count, 2);
        let serial_requests = request_log(&server).await.len();

        assert_eq!(run(&server, Some(&all), &all).await, (serial, count));
        assert_eq!(
            request_log(&server).await.len() - serial_requests,
            serial_requests,
            "a mid-list outage must not be amplified by the plan either"
        );
    }

    /// The one case the plan cannot make free: the loop has caught up with
    /// the window (every package so far granted instantly, so `at` is at
    /// the window's own edge) and the whole window then fails at once.
    /// Those positions were started before any failure landed, so the
    /// barrier cannot hold them back and they cost retry ladders the
    /// serial loop — one failure from opening its breaker — never paid.
    /// The cost is bounded by the window, and the outcomes are unchanged;
    /// pinned here so the bound is measured rather than reasoned about.
    #[tokio::test]
    async fn a_window_the_loop_caught_up_with_costs_at_most_a_window_of_ladders() {
        use Script::*;
        let scripts = [
            Granted(0),
            Granted(0),
            Granted(0),
            Down,
            Down,
            Down,
            Down,
            Down,
        ];
        let all: Vec<usize> = (0..scripts.len()).collect();
        let server = serve(&scripts).await;
        let (serial, count) = run(&server, None, &all).await;
        let serial_requests = request_log(&server).await.len();

        assert_eq!(run(&server, Some(&all), &all).await, (serial, count));
        let planned_requests = request_log(&server).await.len() - serial_requests;
        // `window` (4) ladders at most, where serial paid two: the two the
        // loop consumes plus at most `window - 1` started alongside them.
        let ladder = (serial_requests - 3 * 2) / 2;
        assert!(
            planned_requests <= serial_requests + (4 - 1) * ladder,
            "planned {planned_requests} vs serial {serial_requests} (ladder {ladder})"
        );
    }

    /// A service that is down from the first package costs the plan
    /// exactly what it costs the serial loop: the speculation opens at one
    /// request and stops itself at the breaker's threshold, so it never
    /// aims a window of retry ladders at a service answering none.
    #[tokio::test]
    async fn a_service_that_is_down_costs_no_more_than_the_serial_loop() {
        let scripts: Vec<Script> = (0..8).map(|_| Script::Down).collect();
        let all: Vec<usize> = (0..scripts.len()).collect();

        let serial_server = serve(&scripts).await;
        let serial = run(&serial_server, None, &all).await;
        let serial_posts = request_log(&serial_server).await.len();

        let planned_server = serve(&scripts).await;
        assert_eq!(run(&planned_server, Some(&all), &all).await, serial);
        let planned_posts = request_log(&planned_server).await.len();
        assert_eq!(
            planned_posts, serial_posts,
            "an outage must not be amplified by the plan"
        );
    }

    /// Isolated failures, non-retryable failures (which neither count nor
    /// reset) and answers that prove the service is up (which reset), in
    /// one sequence.
    #[tokio::test]
    async fn mixed_answers_fold_the_breaker_like_the_serial_loop() {
        use Script::*;
        let scripts = [
            Down,
            Granted(0),
            Down,
            Forbidden,
            Down,
            Pending,
            Down,
            NotFound,
            Down,
            Forbidden,
            Down,
            Granted(0),
        ];
        let all: Vec<usize> = (0..scripts.len()).collect();
        assert_matches_serial(&scripts, &all, &all).await;
    }

    /// The loop skips planned packages (a flavor refused them first),
    /// calls one the plan never named, and asks for one twice: skipped
    /// entries are passed over, the rest fetch live.
    #[tokio::test]
    async fn skipped_unplanned_and_repeated_calls_fall_back_to_live_requests() {
        let scripts: Vec<Script> = (0..8).map(|i| Script::Granted(10 * (8 - i))).collect();
        let plan = [0, 1, 2, 3, 4, 5];
        let calls = [1, 7, 3, 3, 5, 0, 6];
        assert_matches_serial(&scripts, &plan, &calls).await;
    }

    /// A planned package the loop never asks for must not hold up the one
    /// it does: the passed-over download is still in flight (30 s of
    /// grant) when the next consumed package answers, and the call
    /// returns anyway.
    #[tokio::test]
    async fn a_passed_over_download_never_blocks_the_next_call() {
        let scripts = [
            Script::Granted(0),
            Script::Granted(30_000),
            Script::Granted(0),
        ];
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages((0..3).map(uuid).collect(), false, None, None, 4);
        // Position 0 widens the window, so position 1 (the stalled one) is
        // in flight before the loop passes it over for position 2.
        assert!(
            summary(&c.fetch_vendor_package(&uuid(0), false, None, None).await)
                .starts_with("ready")
        );
        tokio::time::timeout(
            Duration::from_secs(20),
            c.fetch_vendor_package(&uuid(2), false, None, None),
        )
        .await
        .expect("a skipped package's download must not gate the next one");
    }

    /// The plan actually runs ahead: while the second package's grant is
    /// still unanswered, the third and fourth have already downloaded
    /// their archives — where the serial loop reaches those GETs only
    /// after the second package's. (The first package opens the window on
    /// its own, so the overlap starts at the second.)
    #[tokio::test]
    async fn planned_downloads_overlap_the_loop() {
        let scripts = [
            Script::Granted(0),
            Script::Granted(300),
            Script::Granted(0),
            Script::Granted(0),
        ];
        let server = serve(&scripts).await;
        let all = [0, 1, 2, 3];
        run(&server, Some(&all), &all).await;
        let log = request_log(&server).await;
        let get_at = |i: usize| {
            log.iter()
                .position(|r| *r == format!("GET /serve/{}.tgz", uuid(i)))
                .unwrap_or_else(|| panic!("no archive GET for {i}: {log:?}"))
        };
        let slow = get_at(1);
        assert!(get_at(2) < slow && get_at(3) < slow, "{log:?}");
    }

    /// The task starts at the loop's first planned call: a plan the loop
    /// never consults makes no request at all.
    #[tokio::test]
    async fn an_unconsulted_plan_makes_no_request() {
        let scripts: Vec<Script> = (0..4).map(|_| Script::Granted(0)).collect();
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let guard = c.prefetch_vendor_packages((0..4).map(uuid).collect(), false, None, None, 4);
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(guard);
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The speculation is bounded in REQUESTS, not just in time: once the
    /// loop stops consulting the plan (here after one package, the rest
    /// refused before the service), at most `window` more downloads are
    /// ever issued — not the whole remaining plan.
    #[tokio::test]
    async fn the_task_runs_at_most_a_window_past_the_loop() {
        let window = 4;
        let scripts: Vec<Script> = (0..40).map(|_| Script::Granted(0)).collect();
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let guard = c.prefetch_vendor_packages(
            (0..scripts.len()).map(uuid).collect(),
            false,
            None,
            None,
            window,
        );
        c.fetch_vendor_package(&uuid(0), false, None, None).await;
        // Whatever the task does from here, the loop never asks again.
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(guard);
        let posts = request_log(&server)
            .await
            .iter()
            .filter(|r| r.starts_with("POST"))
            .count();
        assert!(posts <= window, "{posts} grants for one consumed package");
    }

    /// The plan the CLI builds is exact — a package the loop refuses before
    /// the service is never planned (its gates are the loop's own; see the
    /// CLI's `a_package_the_loop_refuses_costs_zero_grants`), so the loop
    /// never passes over a planned position in practice. Should a plan
    /// ever fall out of step with the loop, the request bound still holds,
    /// pinned here: the loop consults the plan at position 0 and then again
    /// at 5, so the task may request `[0, 1)`, then `[0, window)` once the
    /// service has answered, then `[5, 5 + window)` — four grants for a
    /// plan of seven, and never a retry ladder for a passed-over one.
    /// Without the bound it would work through the whole plan.
    #[tokio::test]
    async fn a_planned_position_the_loop_passes_over_costs_at_most_one_grant() {
        let window = 2;
        let scripts: Vec<Script> = (0..7).map(|_| Script::Granted(0)).collect();
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let plain = client(&server.uri());
        let _guard =
            c.prefetch_vendor_packages((0..7).map(uuid).collect(), false, None, None, window);
        for i in [0, 5] {
            assert_eq!(
                summary(&c.fetch_vendor_package(&uuid(i), false, None, None).await),
                summary(
                    &plain
                        .fetch_vendor_package(&uuid(i), false, None, None)
                        .await
                ),
            );
        }
        let posts = request_log(&server)
            .await
            .iter()
            .filter(|r| r.starts_with("POST"))
            .count();
        // Two of them are the plain client's own comparison calls.
        assert!(posts <= 2 + 2 * window, "{posts} grants for two packages");
    }

    /// The reach slow-starts: one position until the service answers,
    /// [`SLOW_START`] after the first answer, one more per good answer up
    /// to the window, and back to [`SLOW_START`] on an availability failure.
    #[test]
    fn the_reach_slow_starts_and_falls_back() {
        let look = Lookahead::new(usize::MAX);
        let reach = || look.reach.load(Ordering::Relaxed);
        assert_eq!(reach(), 1);
        look.grow(32);
        assert_eq!(reach(), SLOW_START);
        for expected in SLOW_START + 1..=32 {
            look.grow(32);
            assert_eq!(reach(), expected);
        }
        look.grow(32);
        assert_eq!(reach(), 32, "never past the window");
        look.shrink();
        assert_eq!(reach(), SLOW_START);
        look.grow(32);
        assert_eq!(reach(), SLOW_START + 1);
        // A window below the slow start caps it, and a shrink never
        // widens.
        let small = Lookahead::new(usize::MAX);
        small.grow(2);
        assert_eq!(small.reach.load(Ordering::Relaxed), 2);
        small.shrink();
        assert_eq!(small.reach.load(Ordering::Relaxed), 2);
        assert_eq!(next_reach(0, 0), 1);
    }

    /// POSTs the server has seen, once they stop changing for `settle`.
    async fn posts_when_quiet(server: &MockServer, settle: Duration) -> usize {
        let count = |log: Vec<String>| log.iter().filter(|r| r.starts_with("POST")).count();
        let mut last = count(request_log(server).await);
        loop {
            tokio::time::sleep(settle).await;
            let now = count(request_log(server).await);
            if now == last {
                return now;
            }
            last = now;
        }
    }

    /// However wide the window (the API's in-flight cap), the first answer
    /// only opens [`SLOW_START`] positions: while those are unanswered, a
    /// struggling service faces four requests, not the whole window.
    #[tokio::test]
    async fn the_speculation_opens_at_the_slow_start_not_the_window() {
        let window = 32;
        let mut scripts = vec![Script::Granted(0)];
        scripts.extend((1..40).map(|_| Script::Granted(2_000)));
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages(
            (0..scripts.len()).map(uuid).collect(),
            false,
            None,
            None,
            window,
        );
        c.fetch_vendor_package(&uuid(0), false, None, None).await;
        assert_eq!(
            posts_when_quiet(&server, Duration::from_millis(150)).await,
            SLOW_START,
            "position 0 plus the three the first answer opened"
        );
    }

    /// Good answers grow the reach to the full window — and no further.
    #[tokio::test]
    async fn good_answers_grow_the_speculation_to_the_window() {
        let window = 12;
        let scripts: Vec<Script> = (0..30).map(|_| Script::Granted(0)).collect();
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages(
            (0..scripts.len()).map(uuid).collect(),
            false,
            None,
            None,
            window,
        );
        c.fetch_vendor_package(&uuid(0), false, None, None).await;
        assert_eq!(
            posts_when_quiet(&server, Duration::from_millis(200)).await,
            window
        );
    }

    /// A call with other request parameters than the plan's never takes a
    /// planned outcome.
    #[tokio::test]
    async fn a_call_with_other_parameters_fetches_live() {
        let scripts = [Script::Granted(0), Script::Granted(0)];
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages(vec![uuid(0), uuid(1)], true, None, None, 4);
        let plain = client(&server.uri());
        for i in 0..2 {
            assert_eq!(
                summary(&c.fetch_vendor_package(&uuid(i), false, None, None).await),
                summary(
                    &plain
                        .fetch_vendor_package(&uuid(i), false, None, None)
                        .await
                ),
            );
        }
        // Nothing was prefetched: two live POSTs per client.
        let posts = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .count();
        assert_eq!(posts, 4);
    }

    /// A uuid the live path refuses without any I/O is never speculated on
    /// either: the plan drops malformed ones as it is attached.
    #[tokio::test]
    async fn a_malformed_uuid_is_never_planned() {
        let scripts = [Script::Granted(0)];
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages(
            vec!["not-a-uuid".to_string(), uuid(0)],
            false,
            None,
            None,
            4,
        );
        let refused = summary(
            &c.fetch_vendor_package("not-a-uuid", false, None, None)
                .await,
        );
        assert!(refused.contains("Invalid patch UUID"), "{refused}");
        assert!(
            !request_log(&server)
                .await
                .iter()
                .any(|r| r.starts_with("POST")),
            "a malformed uuid must cost no request"
        );
    }

    /// Dropping a guard detaches only the plan it attached: a plan
    /// attached later keeps serving its own calls.
    #[tokio::test]
    async fn a_guard_detaches_only_its_own_plan() {
        let scripts: Vec<Script> = (0..2).map(|_| Script::Granted(0)).collect();
        let server = serve(&scripts).await;
        let c = client(&server.uri());
        let outer = c.prefetch_vendor_packages(vec![uuid(0)], false, None, None, 4);
        let _inner = c.prefetch_vendor_packages(vec![uuid(1)], false, None, None, 4);
        drop(outer);
        assert!(
            summary(&c.fetch_vendor_package(&uuid(1), false, None, None).await)
                .starts_with("ready")
        );
        // One grant + one archive: the inner plan served the call, so the
        // live path never repeated them.
        assert_eq!(request_log(&server).await.len(), 2);
    }

    /// A tiny byte budget only holds the speculation back: every call
    /// still gets exactly the serial loop's outcome, at the serial loop's
    /// request cost.
    #[tokio::test]
    async fn a_byte_budget_holds_back_speculation_without_changing_outcomes() {
        let scripts: Vec<Script> = (0..6).map(|i| Script::Granted(5 * (6 - i))).collect();
        let all: Vec<usize> = (0..6).collect();
        let server = serve(&scripts).await;
        let serial = run(&server, None, &all).await;
        let serial_requests = request_log(&server).await.len();

        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_downloads(
            all.iter()
                .map(|&i| PlannedDownload::archive(uuid(i)))
                .collect(),
            false,
            None,
            None,
            4,
            1,
        );
        let mut out = Vec::new();
        for &i in &all {
            out.push(summary(
                &c.fetch_vendor_package(&uuid(i), false, None, None).await,
            ));
        }
        assert_eq!((out, c.vendor_outage_count()), serial);
        assert_eq!(
            request_log(&server).await.len() - serial_requests,
            serial_requests
        );
    }

    /// A planned secondary artifact (the gem stub gemspec) rides its
    /// archive's download and is taken by the backend's own
    /// `fetch_verified_secondary` in place of the live request: the same
    /// outcomes, the same requests — and none for the archive whose bytes
    /// fail integrity verification, which the backend never gets past.
    #[tokio::test]
    async fn a_planned_secondary_rides_its_archive_and_is_taken_in_its_place() {
        use crate::vendor::service_fetch::{
            fetch_verified_archive, fetch_verified_secondary, SecondaryArtifactResult,
            ServiceArtifact,
        };
        const KIND: &str = "gem-stub-gemspec";
        let server = MockServer::start().await;
        for i in 0..3 {
            let u = uuid(i);
            let archive = format!("archive {i}").into_bytes();
            let stub = format!("stub {i}").into_bytes();
            let sri = |b: &[u8]| {
                format!(
                    "sha512-{}",
                    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(b))
                )
            };
            // The last archive is served with an SRI its bytes do not match.
            let archive_sri = if i == 2 { sri(b"other") } else { sri(&archive) };
            let archive_url = format!("{}/serve/{u}.gem", server.uri());
            let stub_url = format!("{}/serve/{u}.gemspec", server.uri());
            Mock::given(method("POST"))
                .and(path(POST_PATH))
                .and(body_partial_json(
                    serde_json::json!({ "uuids": [u.clone()] }),
                ))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "results": { u.clone(): { "status": "granted", "url": archive_url,
                        "artifacts": [
                            { "kind": "tarball", "url": archive_url,
                              "integrity": { "sha512": archive_sri } },
                            { "kind": KIND, "url": stub_url,
                              "integrity": { "sha512": sri(&stub) } }
                        ] } }
                })))
                .mount(&server)
                .await;
            for (p, body) in [
                (format!("/serve/{u}.gem"), archive),
                (format!("/serve/{u}.gemspec"), stub),
            ] {
                Mock::given(method("GET"))
                    .and(path(p))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
                    .mount(&server)
                    .await;
            }
        }
        async fn vendor_like(
            cfg: &crate::vendor::VendorServiceConfig,
            planned: bool,
        ) -> Vec<String> {
            let _guard = planned.then(|| {
                cfg.client.as_ref().unwrap().prefetch_vendor_downloads(
                    (0..3)
                        .map(|i| PlannedDownload {
                            secondary: Some(KIND.to_string()),
                            ..PlannedDownload::archive(uuid(i))
                        })
                        .collect(),
                    false,
                    None,
                    None,
                    4,
                    usize::MAX,
                )
            });
            let mut out = Vec::new();
            for i in 0..3 {
                match fetch_verified_archive(cfg, &uuid(i)).await {
                    ServiceArtifact::Ready(archive) => {
                        out.push(format!("ready {}", String::from_utf8_lossy(&archive.bytes)));
                        out.push(match fetch_verified_secondary(cfg, &archive, KIND).await {
                            SecondaryArtifactResult::Ready(b) => {
                                format!("stub {}", String::from_utf8_lossy(&b))
                            }
                            _ => "stub miss".to_string(),
                        });
                    }
                    ServiceArtifact::IntegrityMismatch(_) => out.push("tampered".to_string()),
                    _ => out.push("other".to_string()),
                }
            }
            out
        }
        let cfg = crate::vendor::VendorServiceConfig {
            maven_config: None,
            source: crate::vendor::VendorSource::Auto,
            client: Some(client(&server.uri())),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        };
        let serial = vendor_like(&cfg, false).await;
        assert_eq!(
            serial,
            [
                "ready archive 0",
                "stub stub 0",
                "ready archive 1",
                "stub stub 1",
                "tampered"
            ]
        );
        let mut serial_requests = request_log(&server).await;
        let before = serial_requests.len();
        assert_eq!(vendor_like(&cfg, true).await, serial);
        let mut planned_requests = request_log(&server).await.split_off(before);
        serial_requests.sort();
        planned_requests.sort();
        assert_eq!(planned_requests, serial_requests);
    }

    /// A service that answers every uuid a package-reference request names,
    /// as the real endpoint does: the request's first uuid decides a
    /// whole-request failure (503 / 403), and the others it cannot grant
    /// are left out of the results.
    struct BatchService {
        base: String,
        scripts: HashMap<String, Script>,
    }

    impl wiremock::Respond for BatchService {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let uuids: Vec<String> = body["uuids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u.as_str().unwrap().to_string())
                .collect();
            match self.scripts.get(&uuids[0]) {
                Some(Script::Down) => return ResponseTemplate::new(503),
                Some(Script::Forbidden) => return ResponseTemplate::new(403),
                _ => {}
            }
            let mut results = serde_json::Map::new();
            for u in uuids {
                let status = match self.scripts.get(&u) {
                    Some(Script::Granted(_)) => "granted",
                    Some(Script::Pending) => "pending_build",
                    Some(Script::NotFound) => "not_found",
                    _ => continue,
                };
                let url = format!("{}/serve/{u}.tgz", self.base);
                let sri = format!(
                    "sha512-{}",
                    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(u.as_bytes()))
                );
                let artifacts = if status == "granted" {
                    serde_json::json!([{ "kind": "tarball", "url": url,
                                         "integrity": { "sha512": sri } }])
                } else {
                    serde_json::json!([])
                };
                results.insert(
                    u.clone(),
                    serde_json::json!({ "status": status, "url": url, "artifacts": artifacts }),
                );
            }
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results }))
        }
    }

    async fn serve_batches(scripts: &[Script]) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(POST_PATH))
            .respond_with(BatchService {
                base: server.uri(),
                scripts: scripts
                    .iter()
                    .enumerate()
                    .map(|(i, s)| (uuid(i), *s))
                    .collect(),
            })
            .mount(&server)
            .await;
        for i in 0..scripts.len() {
            let u = uuid(i);
            Mock::given(method("GET"))
                .and(path(format!("/serve/{u}.tgz")))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(u.into_bytes()))
                .mount(&server)
                .await;
        }
        server
    }

    /// The `(POSTs, GETs)` the server has seen.
    async fn request_counts(server: &MockServer) -> (usize, usize) {
        let log = request_log(server).await;
        let posts = log.iter().filter(|r| r.starts_with("POST")).count();
        (posts, log.len() - posts)
    }

    /// One package-reference request resolves the whole plan: the serial
    /// loop's outcomes, one POST instead of one per package, and the same
    /// downloads.
    #[tokio::test]
    async fn one_reference_request_serves_the_whole_plan() {
        let scripts: Vec<Script> = (0..6).map(|_| Script::Granted(0)).collect();
        let all: Vec<usize> = (0..scripts.len()).collect();
        let server = serve_batches(&scripts).await;
        let serial = run(&server, None, &all).await;
        assert_eq!(request_counts(&server).await, (6, 6));
        assert_eq!(run(&server, Some(&all), &all).await, serial);
        assert_eq!(request_counts(&server).await, (6 + 1, 6 + 6));
    }

    /// The batch replaces the first package's own request, so a service
    /// that is down costs the same ladders, outcomes and breaker count as
    /// the serial loop.
    #[tokio::test]
    async fn a_failed_reference_batch_costs_what_the_serial_loop_paid() {
        let scripts: Vec<Script> = (0..8).map(|_| Script::Down).collect();
        let all: Vec<usize> = (0..scripts.len()).collect();
        let server = serve_batches(&scripts).await;
        let serial = run(&server, None, &all).await;
        let (serial_posts, serial_gets) = request_counts(&server).await;
        assert_eq!(run(&server, Some(&all), &all).await, serial);
        assert_eq!(
            request_counts(&server).await,
            (2 * serial_posts, 2 * serial_gets)
        );
    }

    /// Final answers are reused: a package still building is asked again
    /// at its own turn, as the serial loop did, and one the batch left out
    /// makes its live request.
    #[tokio::test]
    async fn a_building_package_is_asked_again_at_its_turn() {
        use Script::*;
        let scripts = [Granted(0), Pending, Granted(0), NotFound, Down, Granted(0)];
        let all: Vec<usize> = (0..scripts.len()).collect();
        let server = serve_batches(&scripts).await;
        let serial = run(&server, None, &all).await;
        let (serial_posts, _) = request_counts(&server).await;
        assert_eq!(run(&server, Some(&all), &all).await, serial);
        let (posts, _) = request_counts(&server).await;
        // The down package's three attempts, one retry-policy ladder.
        let down_ladder = 3;
        assert_eq!(serial_posts, 5 + down_ladder);
        assert_eq!(
            posts - serial_posts,
            1 + 1 + down_ladder,
            "the batch, then the pending and the down package live"
        );
    }

    /// Plans past the endpoint's cap go out in requests of at most
    /// [`MAX_REFERENCE_BATCH`] uuids.
    #[tokio::test]
    async fn a_plan_past_the_cap_is_resolved_in_capped_requests() {
        let n = MAX_REFERENCE_BATCH + 1;
        let scripts: Vec<Script> = (0..n).map(|_| Script::Granted(0)).collect();
        let server = serve_batches(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages((0..n).map(uuid).collect(), false, None, None, 1);
        for i in [0, n - 1] {
            assert!(
                summary(&c.fetch_vendor_package(&uuid(i), false, None, None).await)
                    .starts_with("ready")
            );
        }
        let sizes: Vec<usize> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .map(|r| {
                let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
                body["uuids"].as_array().unwrap().len()
            })
            .collect();
        assert_eq!(sizes, [MAX_REFERENCE_BATCH, 1]);
    }

    /// The batch names the plan from the first call's position on: a
    /// position the loop passed over before it is never granted.
    #[tokio::test]
    async fn the_reference_batch_starts_at_the_first_call() {
        let scripts: Vec<Script> = (0..4).map(|_| Script::Granted(0)).collect();
        let server = serve_batches(&scripts).await;
        let c = client(&server.uri());
        let _guard = c.prefetch_vendor_packages((0..4).map(uuid).collect(), false, None, None, 1);
        assert!(
            summary(&c.fetch_vendor_package(&uuid(2), false, None, None).await)
                .starts_with("ready")
        );
        let bodies: Vec<Vec<String>> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method == wiremock::http::Method::POST)
            .map(|r| {
                let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
                body["uuids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|u| u.as_str().unwrap().to_string())
                    .collect()
            })
            .collect();
        assert_eq!(bodies, [vec![uuid(2), uuid(3)]]);
    }
}
