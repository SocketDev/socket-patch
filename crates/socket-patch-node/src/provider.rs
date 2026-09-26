//! [`PatchApi`] served by the host's JavaScript `PatchProvider`.
//!
//! Each provider method crosses as a threadsafe function. The JSON methods
//! take the api-v0 request body as a JSON string and resolve with a
//! `ProviderResult` envelope as a JSON string; `downloadArtifact` resolves
//! with a [`NativeDownload`] so the bytes stay a `Buffer`. The loader
//! (npm/index.js) wraps every provider method so these promises always
//! resolve: a rejected promise would carry a reference to a JS value into
//! Rust, which is exactly what the envelopes avoid.

use std::collections::HashMap;

use napi::bindgen_prelude::{Buffer, FunctionRef, Promise};
use napi::threadsafe_function::ThreadsafeFunction;
use napi::{Env, Status};
use napi_derive::napi;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use socket_patch_core::api::client::{sort_batch_response, ApiError, ApiFuture, PatchApi};
use socket_patch_core::api::types::{
    BatchSearchResponse, PackageVendorResult, PatchResponse, SearchResponse,
};

type JsonCall = ThreadsafeFunction<String, Promise<String>, String, Status, false>;
type DownloadCall = ThreadsafeFunction<String, Promise<NativeDownload>, String, Status, false>;

pub(crate) type JsonRef = FunctionRef<String, Promise<String>>;
pub(crate) type DownloadRef = FunctionRef<String, Promise<NativeDownload>>;

/// `downloadArtifact`'s reply as the loader flattens it.
#[napi(object)]
pub struct NativeDownload {
    pub ok: bool,
    pub value: Option<Buffer>,
    pub kind: Option<String>,
    pub message: Option<String>,
}

/// The provider's functions, held on the JS thread until `finish()` turns
/// them into threadsafe functions.
pub(crate) struct ProviderRefs {
    pub(crate) search_patches_batch: JsonRef,
    pub(crate) search_patches_by_package: JsonRef,
    pub(crate) fetch_registry_references: JsonRef,
    pub(crate) fetch_patch: JsonRef,
    pub(crate) download_artifact: DownloadRef,
}

pub(crate) struct JsPatchApi {
    search_patches_batch: JsonCall,
    search_patches_by_package: JsonCall,
    fetch_registry_references: JsonCall,
    fetch_patch: JsonCall,
    download_artifact: DownloadCall,
}

fn json_call(env: &Env, function: &JsonRef) -> napi::Result<JsonCall> {
    function
        .borrow_back(env)?
        .build_threadsafe_function::<String>()
        .callee_handled::<false>()
        .build()
}

impl JsPatchApi {
    /// Must run on the JS thread. The threadsafe functions keep the event
    /// loop alive until this value is dropped, which happens when the
    /// engine future completes or is cancelled.
    pub(crate) fn new(env: &Env, refs: &ProviderRefs) -> napi::Result<Self> {
        Ok(Self {
            search_patches_batch: json_call(env, &refs.search_patches_batch)?,
            search_patches_by_package: json_call(env, &refs.search_patches_by_package)?,
            fetch_registry_references: json_call(env, &refs.fetch_registry_references)?,
            fetch_patch: json_call(env, &refs.fetch_patch)?,
            download_artifact: refs
                .download_artifact
                .borrow_back(env)?
                .build_threadsafe_function::<String>()
                .callee_handled::<false>()
                .build()?,
        })
    }
}

#[derive(Deserialize)]
struct ProviderFailure {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    ok: bool,
    #[serde(default = "none")]
    value: Option<T>,
    #[serde(default)]
    error: Option<ProviderFailure>,
}

fn none<T>() -> Option<T> {
    None
}

#[derive(Deserialize)]
struct ReferencesBody {
    #[serde(default)]
    results: HashMap<String, PackageVendorResult>,
}

fn provider_error(method: &str, kind: &str, message: &str) -> ApiError {
    let detail = if message.is_empty() {
        format!("patch provider {method} failed ({kind})")
    } else {
        format!("patch provider {method} failed ({kind}): {message}")
    };
    match kind {
        "unauthorized" => ApiError::Unauthorized(detail),
        "forbidden" => ApiError::Forbidden(detail),
        "rate_limited" => ApiError::RateLimited(detail),
        "network" => ApiError::Network(detail),
        "parse" => ApiError::Parse(detail),
        _ => ApiError::Other(detail),
    }
}

fn transport_error(method: &str, error: &napi::Error) -> ApiError {
    ApiError::Network(format!(
        "patch provider {method} unavailable: {}",
        error.reason
    ))
}

enum Reply<T> {
    /// A successful reply; `None` when its value is `null` (a missing patch).
    Value(Option<T>),
    /// A `not_found` failure, which each method maps the way the HTTP client
    /// maps that route's 404.
    NotFound(String),
}

async fn call_json<T: DeserializeOwned>(
    method: &str,
    function: &JsonCall,
    request: String,
) -> Result<Reply<T>, ApiError> {
    let promise = function
        .call_async_catch(request)
        .await
        .map_err(|e| transport_error(method, &e))?;
    let reply = promise.await.map_err(|e| transport_error(method, &e))?;
    let envelope: Envelope<T> = serde_json::from_str(&reply).map_err(|e| {
        ApiError::Parse(format!(
            "patch provider {method} returned an unusable result: {e}"
        ))
    })?;
    if envelope.ok {
        return Ok(Reply::Value(envelope.value));
    }
    let failure = envelope.error.unwrap_or(ProviderFailure {
        kind: "other".to_string(),
        message: String::new(),
    });
    if failure.kind == "not_found" {
        return Ok(Reply::NotFound(failure.message));
    }
    Err(provider_error(method, &failure.kind, &failure.message))
}

fn missing_value(method: &str) -> ApiError {
    ApiError::Parse(format!(
        "patch provider {method} resolved ok without a value"
    ))
}

fn request_json(value: serde_json::Value) -> String {
    value.to_string()
}

impl PatchApi for JsPatchApi {
    fn uses_public_proxy(&self) -> bool {
        false
    }

    fn search_patches_batch<'a>(
        &'a self,
        purls: &'a [String],
    ) -> ApiFuture<'a, BatchSearchResponse> {
        Box::pin(async move {
            let components: Vec<serde_json::Value> = purls
                .iter()
                .map(|purl| serde_json::json!({ "purl": purl }))
                .collect();
            let request = request_json(serde_json::json!({ "components": components }));
            let method = "searchPatchesBatch";
            // Like the HTTP collection-route 404: "no patches" is an empty
            // success, so a miss is a misconfiguration, not zero patches.
            let mut response: BatchSearchResponse =
                match call_json(method, &self.search_patches_batch, request).await? {
                    Reply::Value(value) => value.ok_or_else(|| missing_value(method))?,
                    Reply::NotFound(message) => {
                        return Err(provider_error(method, "not_found", &message))
                    }
                };
            sort_batch_response(&mut response);
            Ok(response)
        })
    }

    fn search_patches_by_package<'a>(&'a self, purl: &'a str) -> ApiFuture<'a, SearchResponse> {
        Box::pin(async move {
            let method = "searchPatchesByPackage";
            let request = request_json(serde_json::json!({ "purl": purl }));
            match call_json(method, &self.search_patches_by_package, request).await? {
                Reply::Value(value) => value.ok_or_else(|| missing_value(method)),
                Reply::NotFound(_) => Ok(SearchResponse {
                    patches: Vec::new(),
                    can_access_paid_patches: false,
                }),
            }
        })
    }

    fn fetch_registry_references<'a>(
        &'a self,
        uuids: &'a [String],
    ) -> ApiFuture<'a, HashMap<String, PackageVendorResult>> {
        Box::pin(async move {
            if uuids.is_empty() {
                return Ok(HashMap::new());
            }
            let method = "fetchRegistryReferences";
            let request = request_json(serde_json::json!({ "uuids": uuids }));
            match call_json::<ReferencesBody>(method, &self.fetch_registry_references, request)
                .await?
            {
                Reply::Value(value) => Ok(value.ok_or_else(|| missing_value(method))?.results),
                Reply::NotFound(_) => Ok(HashMap::new()),
            }
        })
    }

    fn fetch_patch<'a>(&'a self, uuid: &'a str) -> ApiFuture<'a, Option<PatchResponse>> {
        Box::pin(async move {
            let request = request_json(serde_json::json!({ "uuid": uuid }));
            match call_json("fetchPatch", &self.fetch_patch, request).await? {
                Reply::Value(value) => Ok(value),
                Reply::NotFound(_) => Ok(None),
            }
        })
    }

    fn download_artifact<'a>(&'a self, url: &'a str, max_bytes: u64) -> ApiFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let method = "downloadArtifact";
            let request = request_json(serde_json::json!({ "url": url, "maxBytes": max_bytes }));
            let promise = self
                .download_artifact
                .call_async_catch(request)
                .await
                .map_err(|e| transport_error(method, &e))?;
            let reply = promise.await.map_err(|e| transport_error(method, &e))?;
            if !reply.ok {
                return Err(provider_error(
                    method,
                    reply.kind.as_deref().unwrap_or("other"),
                    reply.message.as_deref().unwrap_or(""),
                ));
            }
            let buffer = reply.value.ok_or_else(|| missing_value(method))?;
            if buffer.len() as u64 > max_bytes {
                return Err(ApiError::Other(format!(
                    "patch provider {method} returned more than {max_bytes} bytes"
                )));
            }
            Ok(buffer.to_vec())
        })
    }
}
