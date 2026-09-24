//! Vendor-service downloads fetched ahead of the serial vendor loop.
//!
//! The vendor engine wires one package at a time (lockfile and ledger
//! writes stay serial, in sorted order), and each package's service path
//! makes two round trips — the package-reference POST and the archive GET
//! ([`ApiClient::fetch_vendor_package`]). A run that downloads many
//! prebuilt archives paid those round trips back to back. A
//! [`VendorPrefetch`] plan names the uuids the loop is expected to
//! download, in loop order; a background task fetches them ahead of the
//! loop, at most `window` in flight, and the loop's own call for a planned
//! uuid takes the fetched outcome instead of making the requests.
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
//! The task only starts at the loop's first planned call (a run whose
//! packages all refuse before the service makes no speculative request),
//! and it stops speculating after [`super::client::VENDOR_BREAKER_THRESHOLD`]
//! consecutive availability failures of its own. Dropping the
//! [`VendorPrefetchGuard`] detaches the plan and aborts the task.

use std::sync::Arc;

use futures_util::StreamExt;

use super::client::{
    with_deferred_debug, ApiClient, HeldBack, VendorServiceOutcome, VENDOR_BREAKER_THRESHOLD,
};
use crate::utils::concurrent::ordered_concurrent;

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
    /// Most downloads in flight (and queued unconsumed) at once.
    window: usize,
    state: tokio::sync::Mutex<PrefetchState>,
}

#[derive(Debug, Default)]
struct PrefetchState {
    /// First plan position not yet consumed or passed over.
    cursor: usize,
    /// Outcomes from the task, tagged with their plan position, in order.
    /// `None` until the loop's first planned call starts the task.
    rx: Option<tokio::sync::mpsc::Receiver<(usize, Fetched)>>,
    task: Option<tokio::task::JoinHandle<()>>,
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
        let position = state.cursor
            + self.planned[state.cursor..]
                .iter()
                .position(|planned| planned == uuid)?;
        state.cursor = position + 1;
        if state.rx.is_none() {
            self.start(&mut state, client, position);
        }
        let rx = state.rx.as_mut()?;
        loop {
            match rx.recv().await {
                Some((index, fetched)) if index == position => return Some(fetched),
                Some((index, _)) if index < position => continue,
                // Past the position (never sent out of order) or the task
                // stopped: fetch live from here on.
                _ => {
                    state.rx = None;
                    state.cursor = self.planned.len();
                    return None;
                }
            }
        }
    }

    /// Spawn the task fetching `planned[from..]` in order.
    fn start(&self, state: &mut PrefetchState, client: &ApiClient, from: usize) {
        let (tx, rx) = tokio::sync::mpsc::channel(self.window);
        let client = client.clone();
        let planned: Vec<String> = self.planned[from..].to_vec();
        let (free_only, window) = (self.free_only, self.window);
        let vendor_url = self.vendor_url.clone();
        let patch_server_url = self.patch_server_url.clone();
        state.task = Some(tokio::spawn(async move {
            let (client, vendor_url, patch_server_url) =
                (&client, vendor_url.as_deref(), patch_server_url.as_deref());
            let mut fetched = std::pin::pin!(ordered_concurrent(
                planned.into_iter().enumerate(),
                window,
                move |(offset, uuid): (usize, String)| async move {
                    let (outcome, debug) = with_deferred_debug(client.fetch_vendor_package_once(
                        &uuid,
                        free_only,
                        vendor_url,
                        patch_server_url,
                    ))
                    .await;
                    (from + offset, HeldBack::new(outcome, debug))
                },
            ));
            let mut consecutive_failures = 0;
            while let Some((index, held)) = fetched.next().await {
                match held.peek() {
                    (VendorServiceOutcome::Failed(_), true) => consecutive_failures += 1,
                    (VendorServiceOutcome::Failed(_), false) => {}
                    _ => consecutive_failures = 0,
                }
                if tx.send((index, held)).await.is_err() {
                    return;
                }
                // The breaker would skip the service from here on unless a
                // package in between succeeds; stop speculating (later
                // calls fetch live, through the breaker).
                if consecutive_failures >= VENDOR_BREAKER_THRESHOLD {
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
}

impl Drop for VendorPrefetchGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.lock() {
            slot.take();
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

    /// The plan actually runs ahead: the second package's POST goes out
    /// before the first package's (slow) grant has even been answered,
    /// where the serial loop sends it only after the first archive GET.
    #[tokio::test]
    async fn planned_downloads_overlap_the_loop() {
        let scripts = [Script::Granted(300), Script::Granted(0), Script::Granted(0)];
        let server = serve(&scripts).await;
        let all = [0, 1, 2];
        run(&server, Some(&all), &all).await;
        let log: Vec<String> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect();
        let first_get = log.iter().position(|r| r.starts_with("GET")).unwrap();
        let posts_before = log[..first_get]
            .iter()
            .filter(|r| r.starts_with("POST"))
            .count();
        assert!(posts_before >= 2, "{log:?}");
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
}
