//! `GET /patch/view/<uuid>` on a patch proxy: the record the CLI's
//! free-proxy client reads a patch's files and hashes from. The production
//! suites and their fixtures read it to check what a run delivered.
//!
//! Files that don't need the rest of `common` pull this in on its own with
//! `#[path = "common/patch_view.rs"] mod patch_view;`.

#![allow(dead_code)]

/// The record `proxy` serves for `uuid`, or what went wrong (transport, a
/// non-2xx status with its body, or a body that is not JSON).
pub async fn record(proxy: &str, uuid: &str) -> Result<serde_json::Value, String> {
    let url = format!("{proxy}/patch/view/{uuid}");
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("GET {url}: reading body: {e}"))?;
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}\n{body}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("GET {url}: bad JSON ({e}):\n{body}"))
}

/// [`record`] on a private runtime, for tests that are not async. Panics
/// with [`record`]'s error.
pub fn record_blocking(proxy: &str, uuid: &str) -> serde_json::Value {
    tokio::runtime::Runtime::new()
        .expect("tokio runtime")
        .block_on(record(proxy, uuid))
        .unwrap_or_else(|e| panic!("{e}"))
}

/// The files a record touches, as `(path, beforeHash, afterHash)`. The
/// hashes are git-blob sha256; `None` for a pure addition or deletion
/// respectively.
pub fn files(record: &serde_json::Value) -> Vec<(String, Option<String>, Option<String>)> {
    record["files"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(path, file)| {
            (
                path.clone(),
                file["beforeHash"].as_str().map(str::to_string),
                file["afterHash"].as_str().map(str::to_string),
            )
        })
        .collect()
}
