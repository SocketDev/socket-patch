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
//! ## What the speculation can cost
//!
//! The plan is built from the gates the CLI can see, so a package each
//! backend refuses in its own pre-flight (an unsupported lockfile entry,
//! an override conflict) can still be planned, and the loop then never
//! asks for it. That is a real request against the service — on a
//! depscan vendored run, 74 download grants where the serial loop made
//! 71 — so the task is bounded in requests, not just in time:
//!
//! * It only ever requests plan positions in `[at, at + reach)`, where
//!   `at` is the position the loop has reached and `reach` is one until
//!   the service has answered once and `window` after. So it never runs
//!   more than `window` requests ahead of the loop, a run that stops
//!   consulting the plan (every remaining package refused, or the loop
//!   finishing) leaves at most `window` requests outstanding, and a plan
//!   the loop never consults makes no request at all.
//! * It never requests a position the loop has already passed, and stops
//!   entirely once it has seen
//!   [`super::client::VENDOR_BREAKER_THRESHOLD`] consecutive availability
//!   failures of its own — so a service that is down from the first
//!   package costs exactly the retry ladders the serial loop paid before
//!   its own breaker opened, not a window of them.
//!
//! Outcomes are delivered as they finish, not in plan order: a passed-over
//! download must never hold up the package the loop is actually waiting
//! for (that would make the loop slower than serial, on a request serial
//! never made). `take` puts an early outcome aside until its own call.
//! Dropping the [`VendorPrefetchGuard`] detaches the plan and aborts the
//! task.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;

use futures_util::StreamExt;

use super::client::{
    hold_back_debug, ApiClient, HeldBack, VendorServiceOutcome, VENDOR_BREAKER_THRESHOLD,
};

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
    /// Most downloads in flight at once, and the most the task may run
    /// ahead of the loop.
    window: usize,
    /// What the task is allowed to request, shared with it.
    look: Arc<Lookahead>,
    state: tokio::sync::Mutex<PrefetchState>,
}

/// The window of plan positions the task may request: `[at, at + reach)`.
/// Both ends move — `at` as the loop consumes, `reach` once the service has
/// answered — so the speculation is bounded in REQUESTS by what the loop
/// has actually reached (see the module docs). Gating on the position
/// rather than on a count of permits keeps the order deterministic: the
/// futures are polled in whatever order the unordered pool likes, so a
/// counter would hand the opening request to an arbitrary position.
#[derive(Debug)]
struct Lookahead {
    /// The plan position the loop is at; everything below it was passed
    /// over and must never be requested.
    at: AtomicUsize,
    /// How far past `at` the task may run: one until the service has
    /// answered once, then the whole window.
    reach: AtomicUsize,
    /// Consecutive retryable failures the TASK has seen, in the order its
    /// own requests answered. Purely a stop signal for the speculation —
    /// the observable breaker is the client's, folded at consumption time.
    failures: AtomicU32,
    /// Woken whenever `at` or `reach` moves.
    moved: tokio::sync::Notify,
}

impl Lookahead {
    fn new() -> Self {
        Self {
            at: AtomicUsize::new(0),
            // Opens at one request: a service that is down from the first
            // package then costs what the serial loop cost.
            reach: AtomicUsize::new(1),
            failures: AtomicU32::new(0),
            moved: tokio::sync::Notify::new(),
        }
    }

    /// The loop has reached plan position `position`.
    fn arrive(&self, position: usize) {
        self.at.store(position, Ordering::Relaxed);
        self.moved.notify_waiters();
    }

    /// The service answered: the task may now run the full window ahead.
    fn widen(&self, window: usize) {
        self.reach.store(window, Ordering::Relaxed);
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
            if index < self.at.load(Ordering::Relaxed)
                || self.failures.load(Ordering::Relaxed) >= VENDOR_BREAKER_THRESHOLD
            {
                return false;
            }
            if index < self.at.load(Ordering::Relaxed) + self.reach.load(Ordering::Relaxed) {
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
        planned: Vec<String>,
        free_only: bool,
        vendor_url: Option<&str>,
        patch_server_url: Option<&str>,
        window: usize,
    ) -> Self {
        Self {
            free_only,
            vendor_url: vendor_url.map(str::to_string),
            patch_server_url: patch_server_url.map(str::to_string),
            planned,
            window: window.max(1),
            look: Arc::new(Lookahead::new()),
            state: tokio::sync::Mutex::new(PrefetchState::default()),
        }
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
        state.ready.retain(|index, _| *index >= position);
        self.look.arrive(position);
        if state.task.is_none() {
            self.start(&mut state, client, position);
        }
        let PrefetchState { rx, ready, .. } = &mut *state;
        if let Some(fetched) = ready.remove(&position) {
            return Some(fetched);
        }
        let rx = rx.as_mut()?;
        loop {
            match rx.recv().await {
                Some((index, fetched)) if index == position => return Some(fetched),
                // A later position answered first: keep it for its own
                // call. An earlier one was passed over — drop it here.
                Some((index, fetched)) => {
                    if index > position {
                        ready.insert(index, fetched);
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
        let planned: Vec<String> = self.planned[from..].to_vec();
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
                    .map(move |(offset, uuid): (usize, String)| async move {
                        let index = from + offset;
                        if !look.admits(index).await {
                            return None;
                        }
                        let held = hold_back_debug(client.fetch_vendor_package_once(
                            &uuid,
                            free_only,
                            vendor_url,
                            patch_server_url,
                        ))
                        .await;
                        Some((index, held))
                    })
                    .buffer_unordered(window));
            while let Some(item) = fetched.next().await {
                let Some((index, held)) = item else { continue };
                let availability_failure =
                    matches!(held.peek(), (VendorServiceOutcome::Failed(_), true));
                if availability_failure {
                    look.failures.fetch_add(1, Ordering::Relaxed);
                } else if !matches!(held.peek(), (VendorServiceOutcome::Failed(_), false)) {
                    // Anything but a failure proves the service is up. A
                    // NON-retryable failure (auth, parse) says nothing
                    // about availability either way, so it neither counts
                    // nor resets — exactly the client breaker's rule.
                    look.failures.store(0, Ordering::Relaxed);
                }
                if !availability_failure {
                    look.widen(window);
                }
                if tx.send((index, held)).await.is_err() {
                    return;
                }
                if look.failures.load(Ordering::Relaxed) >= VENDOR_BREAKER_THRESHOLD {
                    return;
                }
            }
        }));
        state.rx = Some(rx);
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
        let server = serve(&scripts).await;
        let (serial, count) = run(&server, None, &all).await;
        assert!(serial[5].contains("not attempted"), "{serial:?}");
        assert!(serial[9].contains("not attempted"), "{serial:?}");
        assert_eq!(count, 2);
        assert_eq!(run(&server, Some(&all), &all).await, (serial, count));
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

    /// What a package the loop refuses before the service costs, pinned:
    /// the loop consults the plan at position 0 and then again at 5, so
    /// the task may request `[0, 1)`, then `[0, window)` once the service
    /// has answered, then `[5, 5 + window)` — four grants for a plan of
    /// seven, and never a retry ladder for a passed-over one. Without a
    /// bound it would work through the whole plan.
    #[tokio::test]
    async fn a_package_the_loop_refuses_costs_at_most_one_grant() {
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
}
