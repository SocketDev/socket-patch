//! Patch discovery across every project root with one provider lookup per
//! purl / uuid / url: the union of the roots' purls is batch-searched in
//! sorted, deterministic chunks; packages with patches get their details
//! fetched with bounded concurrency; each root then takes the disk JSON
//! flow's selection (accessible patches only, top-ranked per purl through
//! [`cmp_search_results`]).

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::Duration;

use crate::api::client::{ApiError, ApiFuture, PatchApi};
use crate::api::ranking::cmp_search_results;
use crate::api::types::{
    BatchPackagePatches, PackageVendorResult, PatchResponse, SearchResponse,
};
use crate::utils::purl::{normalize_purl, strip_purl_qualifiers};

use super::types::MAX_REFERENCE_BATCH;

/// A boxed future the bounded joiner drives.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Drive `futures` with at most `limit` in flight, returning their outputs
/// in input order. Futures are polled in place (no task spawning), so
/// dropping the returned future cancels every one of them.
pub(crate) async fn join_bounded<'a, T>(futures: Vec<BoxFuture<'a, T>>, limit: usize) -> Vec<T> {
    let limit = limit.max(1);
    let total = futures.len();
    let mut queued: VecDeque<(usize, BoxFuture<'a, T>)> = futures.into_iter().enumerate().collect();
    let mut active: Vec<(usize, BoxFuture<'a, T>)> = Vec::new();
    let mut out: Vec<Option<T>> = (0..total).map(|_| None).collect();
    let mut done = 0usize;
    std::future::poll_fn(|cx| loop {
        while active.len() < limit {
            match queued.pop_front() {
                Some(next) => active.push(next),
                None => break,
            }
        }
        let mut progressed = false;
        let mut i = 0;
        while i < active.len() {
            if let Poll::Ready(value) = active[i].1.as_mut().poll(cx) {
                let (index, _) = active.swap_remove(i);
                out[index] = Some(value);
                done += 1;
                progressed = true;
            } else {
                i += 1;
            }
        }
        if done == total {
            return Poll::Ready(());
        }
        if !progressed || queued.is_empty() {
            return Poll::Pending;
        }
    })
    .await;
    out.into_iter().flatten().collect()
}

/// The host's [`PatchApi`] behind per-call timeouts and call counting.
pub(crate) struct Provider {
    api: Arc<dyn PatchApi>,
    timeout: Duration,
    pub(crate) concurrency: usize,
    calls: Mutex<BTreeMap<String, u64>>,
}

impl Provider {
    pub(crate) fn new(api: Arc<dyn PatchApi>, timeout: Duration, concurrency: usize) -> Self {
        Self {
            api,
            timeout,
            concurrency,
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn calls(&self) -> BTreeMap<String, u64> {
        self.calls.lock().map(|c| c.clone()).unwrap_or_default()
    }

    async fn call<T>(&self, method: &'static str, fut: ApiFuture<'_, T>) -> Result<T, ApiError> {
        if let Ok(mut calls) = self.calls.lock() {
            *calls.entry(method.to_string()).or_insert(0) += 1;
        }
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(result) => result,
            Err(_) => Err(ApiError::Network(format!(
                "{method} timed out after {} ms",
                self.timeout.as_millis()
            ))),
        }
    }

    pub(crate) async fn search_patches_batch(
        &self,
        purls: &[String],
    ) -> Result<crate::api::types::BatchSearchResponse, ApiError> {
        let mut response = self
            .call("searchPatchesBatch", self.api.search_patches_batch(purls))
            .await?;
        crate::api::client::sort_batch_response(&mut response);
        Ok(response)
    }

    pub(crate) async fn search_patches_by_package(
        &self,
        purl: &str,
    ) -> Result<SearchResponse, ApiError> {
        let mut response = self
            .call(
                "searchPatchesByPackage",
                self.api.search_patches_by_package(purl),
            )
            .await?;
        response.patches.sort_by(cmp_search_results);
        Ok(response)
    }

    pub(crate) async fn fetch_registry_references(
        &self,
        uuids: &[String],
    ) -> Result<HashMap<String, PackageVendorResult>, ApiError> {
        self.call(
            "fetchRegistryReferences",
            self.api.fetch_registry_references(uuids),
        )
        .await
    }

    pub(crate) async fn fetch_patch(&self, uuid: &str) -> Result<Option<PatchResponse>, ApiError> {
        self.call("fetchPatch", self.api.fetch_patch(uuid)).await
    }

    pub(crate) async fn download_artifact(
        &self,
        url: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, ApiError> {
        let bytes = self
            .call(
                "downloadArtifact",
                self.api.download_artifact(url, max_bytes),
            )
            .await?;
        if bytes.len() as u64 > max_bytes {
            return Err(ApiError::Other(format!(
                "artifact exceeds the {max_bytes}-byte limit"
            )));
        }
        Ok(bytes)
    }
}

/// The literal, qualifier-free purl the disk flow's lockfile supplement
/// queries for an inventory entry (`crawled_from_purl`'s shape rule), or
/// `None` for a purl it drops.
pub(crate) fn supplement_purl(purl: &str) -> Option<String> {
    let decoded = normalize_purl(strip_purl_qualifiers(purl)).into_owned();
    let rest = decoded.strip_prefix("pkg:")?;
    let (_eco, rest) = rest.split_once('/')?;
    rest.rfind('@').filter(|&i| i > 0)?;
    Some(decoded)
}

/// One root's batch-search outcome.
#[derive(Debug, Default)]
pub(crate) struct RootBatch {
    /// Packages with at least one patch, purl-sorted.
    pub(crate) packages: Vec<BatchPackagePatches>,
    /// How many of the root's purls sat in a failed chunk.
    pub(crate) failed_purls: usize,
    pub(crate) last_error: Option<String>,
}

/// The run-level batch outcome.
#[derive(Debug, Default)]
pub(crate) struct BatchOutcome {
    pub(crate) roots: BTreeMap<String, RootBatch>,
    pub(crate) can_access_paid_patches: bool,
}

/// Batch-search the union of every root's purls (`root_purls` values are
/// sorted, deduplicated supplement purls). A response package is credited
/// to every root that asked for it; one whose purl matches no request
/// spelling goes to every root that had a purl in its chunk.
pub(crate) async fn batch_search(
    provider: &Provider,
    root_purls: &BTreeMap<String, Vec<String>>,
    batch_size: usize,
) -> BatchOutcome {
    let mut owners: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (root, purls) in root_purls {
        for purl in purls {
            owners.entry(purl.as_str()).or_default().push(root.as_str());
        }
    }
    let union: Vec<String> = owners.keys().map(|p| p.to_string()).collect();
    let chunks: Vec<Vec<String>> = union
        .chunks(batch_size.max(1))
        .map(<[String]>::to_vec)
        .collect();
    let futures: Vec<BoxFuture<'_, _>> = chunks
        .iter()
        .map(|chunk| -> BoxFuture<'_, _> { Box::pin(provider.search_patches_batch(chunk)) })
        .collect();
    let results = join_bounded(futures, provider.concurrency).await;

    let mut outcome = BatchOutcome::default();
    for root in root_purls.keys() {
        outcome.roots.insert(root.clone(), RootBatch::default());
    }
    for (chunk, result) in chunks.iter().zip(results) {
        let chunk_roots: BTreeSet<&str> = chunk
            .iter()
            .flat_map(|p| owners.get(p.as_str()).into_iter().flatten().copied())
            .collect();
        match result {
            Ok(response) => {
                if response.can_access_paid_patches {
                    outcome.can_access_paid_patches = true;
                }
                for pkg in response.packages {
                    if pkg.patches.is_empty() {
                        continue;
                    }
                    let key = normalize_purl(strip_purl_qualifiers(&pkg.purl)).into_owned();
                    let targets: Vec<&str> = match owners.get(key.as_str()) {
                        Some(roots) => roots.clone(),
                        None => chunk_roots.iter().copied().collect(),
                    };
                    for root in targets {
                        if let Some(entry) = outcome.roots.get_mut(root) {
                            entry.packages.push(pkg.clone());
                        }
                    }
                }
            }
            Err(error) => {
                let message = error.to_string();
                for purl in chunk {
                    for root in owners.get(purl.as_str()).into_iter().flatten() {
                        if let Some(entry) = outcome.roots.get_mut(*root) {
                            entry.failed_purls += 1;
                            entry.last_error = Some(message.clone());
                        }
                    }
                }
            }
        }
    }
    for entry in outcome.roots.values_mut() {
        entry.packages.sort_by(|a, b| a.purl.cmp(&b.purl));
    }
    outcome
}

/// `search_patches_by_package` once per distinct purl.
pub(crate) async fn fetch_details(
    provider: &Provider,
    purls: &BTreeSet<String>,
) -> BTreeMap<String, Result<SearchResponse, String>> {
    let ordered: Vec<&String> = purls.iter().collect();
    let futures: Vec<BoxFuture<'_, _>> = ordered
        .iter()
        .map(|purl| -> BoxFuture<'_, _> { Box::pin(provider.search_patches_by_package(purl)) })
        .collect();
    let results = join_bounded(futures, provider.concurrency).await;
    ordered
        .into_iter()
        .cloned()
        .zip(results.into_iter().map(|r| r.map_err(|e| e.to_string())))
        .collect()
}

/// Reference grants for every distinct uuid (`MAX_REFERENCE_BATCH` per
/// request): the merged results, plus the uuids whose request failed.
pub(crate) async fn fetch_references(
    provider: &Provider,
    uuids: &BTreeSet<String>,
) -> (
    HashMap<String, PackageVendorResult>,
    BTreeMap<String, String>,
) {
    let ordered: Vec<String> = uuids.iter().cloned().collect();
    let chunks: Vec<Vec<String>> = ordered
        .chunks(MAX_REFERENCE_BATCH)
        .map(<[String]>::to_vec)
        .collect();
    let futures: Vec<BoxFuture<'_, _>> = chunks
        .iter()
        .map(|chunk| -> BoxFuture<'_, _> { Box::pin(provider.fetch_registry_references(chunk)) })
        .collect();
    let results = join_bounded(futures, provider.concurrency).await;
    let mut merged: HashMap<String, PackageVendorResult> = HashMap::new();
    let mut failed: BTreeMap<String, String> = BTreeMap::new();
    for (chunk, result) in chunks.iter().zip(results) {
        match result {
            Ok(map) => merged.extend(map),
            Err(error) => {
                let message = error.to_string();
                for uuid in chunk {
                    failed.insert(uuid.clone(), message.clone());
                }
            }
        }
    }
    (merged, failed)
}

/// Hosted wheel metadata once per distinct `(url, sha256)`: the disk
/// flow's `fetch_hosted_wheel_metadata` over the provider.
pub(crate) async fn fetch_wheel_metadata(
    provider: &Provider,
    wanted: &BTreeSet<(String, String)>,
    max_bytes: u64,
) -> BTreeMap<String, Result<Option<String>, String>> {
    let ordered: Vec<&(String, String)> = wanted.iter().collect();
    let futures: Vec<BoxFuture<'_, _>> = ordered
        .iter()
        .map(
            |(url, sha256)| -> BoxFuture<'_, Result<Option<String>, String>> {
                Box::pin(async move {
                    let bytes = provider
                        .download_artifact(url, max_bytes)
                        .await
                        .map_err(|error| format!("cannot fetch hosted wheel metadata: {error}"))?;
                    crate::vendor::pypi::decode_hosted_wheel_metadata(&bytes, sha256)
                })
            },
        )
        .collect();
    let results = join_bounded(futures, provider.concurrency).await;
    ordered
        .into_iter()
        .map(|(url, _)| url.clone())
        .zip(results)
        .collect()
}

/// Served npm tarballs' own package.json once per distinct `(url,
/// sha512)`, for the yarn berry pin's `bin:` map: the disk flow's
/// `fetch_hosted_npm_manifest` over the provider.
pub(crate) async fn fetch_npm_manifests(
    provider: &Provider,
    wanted: &BTreeSet<(String, Option<String>)>,
    max_bytes: u64,
) -> BTreeMap<String, Result<Option<String>, String>> {
    let ordered: Vec<&(String, Option<String>)> = wanted.iter().collect();
    let futures: Vec<BoxFuture<'_, _>> = ordered
        .iter()
        .map(
            |(url, sha512)| -> BoxFuture<'_, Result<Option<String>, String>> {
                Box::pin(async move {
                    let bytes = provider
                        .download_artifact(url, max_bytes)
                        .await
                        .map_err(|error| format!("cannot fetch the hosted tarball: {error}"))?;
                    crate::hosted::npm_manifest::decode_hosted_npm_manifest(
                        &bytes,
                        sha512.as_deref(),
                    )
                    .map(Some)
                })
            },
        )
        .collect();
    let results = join_bounded(futures, provider.concurrency).await;
    ordered
        .into_iter()
        .map(|(url, _)| url.clone())
        .zip(results)
        .collect()
}

/// Patch views for every distinct confirmed uuid (wet runs only).
pub(crate) async fn fetch_records(
    provider: &Provider,
    uuids: &BTreeSet<String>,
) -> BTreeMap<String, Option<PatchResponse>> {
    let ordered: Vec<&String> = uuids.iter().collect();
    let futures: Vec<BoxFuture<'_, _>> = ordered
        .iter()
        .map(|uuid| -> BoxFuture<'_, _> { Box::pin(provider.fetch_patch(uuid)) })
        .collect();
    let results = join_bounded(futures, provider.concurrency).await;
    ordered
        .into_iter()
        .cloned()
        .zip(results.into_iter().map(|r| r.ok().flatten()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::PatchSearchResult;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn join_bounded_keeps_order_and_caps_concurrency() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let futures: Vec<BoxFuture<'static, usize>> = (0..20usize)
            .map(|i| -> BoxFuture<'static, usize> {
                let in_flight = in_flight.clone();
                let peak = peak.clone();
                Box::pin(async move {
                    let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis((20 - i as u64) % 7)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    i
                })
            })
            .collect();
        let out = join_bounded(futures, 3).await;
        assert_eq!(out, (0..20).collect::<Vec<_>>());
        assert!(peak.load(Ordering::SeqCst) <= 3);
    }

    #[test]
    fn supplement_purl_matches_the_disk_shape_rule() {
        assert_eq!(
            supplement_purl("pkg:npm/%40scope/x@1.0.0?arch=x").as_deref(),
            Some("pkg:npm/@scope/x@1.0.0")
        );
        assert_eq!(supplement_purl("pkg:npm/x"), None);
        assert_eq!(supplement_purl("npm/x@1"), None);
    }

    fn result(purl: &str, uuid: &str, tier: &str, severity: &str) -> PatchSearchResult {
        serde_json::from_value(serde_json::json!({
            "uuid": uuid, "purl": purl, "publishedAt": "2024-01-01T00:00:00Z",
            "description": "", "license": "MIT", "tier": tier,
            "vulnerabilities": {"GHSA-x": {"cves": [], "summary": "", "severity": severity, "description": ""}}
        }))
        .unwrap()
    }

    #[test]
    fn selection_filters_paid_and_takes_the_top_ranked() {
        let results = vec![
            result("pkg:npm/b@1", "b-low", "free", "low"),
            result("pkg:npm/b@1", "b-crit", "free", "critical"),
            result("pkg:npm/a@1", "a-paid", "paid", "critical"),
            result("pkg:npm/a@1", "a-free", "free", "low"),
        ];
        // The engine selects through the disk flow's own seam.
        let pairs = |paid: bool| -> Vec<(String, String)> {
            crate::rollout::stage::offers_from_results(&results, paid)
                .selected
                .into_iter()
                .map(|(purl, p)| (purl, p.uuid))
                .collect()
        };
        assert_eq!(
            pairs(false),
            vec![
                ("pkg:npm/a@1".to_string(), "a-free".to_string()),
                ("pkg:npm/b@1".to_string(), "b-crit".to_string())
            ]
        );
        assert_eq!(pairs(true)[0].1, "a-paid");
    }
}
