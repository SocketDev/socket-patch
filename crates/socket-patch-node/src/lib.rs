//! Node addon for the in-memory hosted redirect engine
//! (`socket_patch_core::hosted::memory`).
//!
//! This is the private native half of `@socketsecurity/socket-patch-node`;
//! npm/index.js is the public surface (npm/index.d.ts). Options, tree
//! entries and results cross as JSON strings so the engine's serde types
//! are the single definition of every shape; bytes cross as `Buffer`s.

mod provider;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use napi::bindgen_prelude::{Buffer, External, Function, JsObjectValue, Object, PromiseRaw};
use napi::{Env, Status};
use napi_derive::napi;
use socket_patch_core::hosted::memory::{
    self as hosted_memory, EngineError, HostedScanOptions, HostedScanOutput, PresentKind, SelectOptions,
    SessionBuilder, TreeEntryInput,
};
use socket_patch_core::api::client::PatchApi;
use tokio_util::sync::CancellationToken;

use provider::{JsPatchApi, ProviderRefs};

/// Every error the addon throws carries `{code, kind, message}` as a JSON
/// reason; the loader rethrows it as an `Error` with those properties.
fn js_error(code: &str, kind: &str, message: impl Into<String>) -> napi::Error {
    let reason = serde_json::json!({ "code": code, "kind": kind, "message": message.into() });
    napi::Error::new(Status::GenericFailure, reason.to_string())
}

fn engine_js_error(error: &EngineError) -> napi::Error {
    js_error(error.code(), error.kind(), error.to_string())
}

fn invalid_input(code: &str, message: impl Into<String>) -> napi::Error {
    js_error(code, "invalid_input", message)
}

fn napi_js_error(error: napi::Error) -> napi::Error {
    js_error("addon_internal", "internal", error.reason.clone())
}

#[napi(js_name = "selectHostedScanPathsJson")]
pub fn select_hosted_scan_paths_json(
    entries_json: String,
    options_json: Option<String>,
) -> napi::Result<String> {
    let entries: Vec<TreeEntryInput> = serde_json::from_str(&entries_json)
        .map_err(|e| invalid_input("invalid_entries", format!("tree entries: {e}")))?;
    let options: SelectOptions = match options_json.as_deref() {
        None => SelectOptions::default(),
        Some(text) => serde_json::from_str(text)
            .map_err(|e| invalid_input("invalid_options", format!("selection options: {e}")))?,
    };
    let selection = hosted_memory::select_paths(&entries, &options);
    serde_json::to_string(&selection)
        .map_err(|e| js_error("addon_internal", "internal", e.to_string()))
}

#[napi(js_name = "hostedScanCandidateFiles")]
pub fn hosted_scan_candidate_files() -> Vec<String> {
    hosted_memory::candidate_files()
}

#[napi(js_name = "engineVersion")]
pub fn engine_version() -> String {
    hosted_memory::engine_version()
}

#[napi(object)]
pub struct NativeBinaryFile {
    pub path: String,
    pub content: Buffer,
}

/// `finish()`'s settlement. The loader turns a failure into a rejected
/// promise whose error carries `code` and `kind`, so the native promise
/// itself always resolves.
#[napi(object)]
pub struct NativeFinishOutcome {
    pub ok: bool,
    /// `HostedScanResult` with `changedBinaryFiles` left empty.
    pub result_json: Option<String>,
    pub binary_files: Option<Vec<NativeBinaryFile>>,
    pub error_code: Option<String>,
    pub error_kind: Option<String>,
    pub error_message: Option<String>,
}

impl NativeFinishOutcome {
    fn failure(code: &str, kind: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            result_json: None,
            binary_files: None,
            error_code: Some(code.to_string()),
            error_kind: Some(kind.to_string()),
            error_message: Some(message.into()),
        }
    }

    fn engine_failure(error: &EngineError) -> Self {
        Self::failure(error.code(), error.kind(), error.to_string())
    }

    fn success(mut output: HostedScanOutput) -> Self {
        let binaries = std::mem::take(&mut output.changed_binary_files);
        match serde_json::to_string(&output) {
            Ok(json) => Self {
                ok: true,
                result_json: Some(json),
                binary_files: Some(
                    binaries
                        .into_iter()
                        .map(|file| NativeBinaryFile {
                            path: file.path,
                            content: Buffer::from(file.content),
                        })
                        .collect(),
                ),
                error_code: None,
                error_kind: None,
                error_message: None,
            },
            Err(e) => Self::failure(
                "engine_internal",
                "internal",
                format!("serializing the result failed: {e}"),
            ),
        }
    }
}

enum SessionState {
    Open(Box<SessionBuilder>),
    Failed(EngineError),
    Finished,
}

type OutcomeFuture = Pin<Box<dyn Future<Output = NativeFinishOutcome> + Send>>;

async fn run_engine(
    input: hosted_memory::HostedScanInput,
    provider: Arc<dyn PatchApi>,
    cancel: CancellationToken,
) -> NativeFinishOutcome {
    let engine_cancel = cancel.child_token();
    let _stop_engine_if_dropped = engine_cancel.clone().drop_guard();
    let mut task = tokio::spawn(hosted_memory::run_in_memory(input, provider, engine_cancel));
    // The engine only observes cancellation between synchronous phases, so
    // racing the join settles finish() without waiting out a long parse.
    let joined = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            return NativeFinishOutcome::engine_failure(&EngineError::Cancelled);
        }
        joined = &mut task => joined,
    };
    match joined {
        Ok(Ok(output)) => NativeFinishOutcome::success(output),
        Ok(Err(error)) => NativeFinishOutcome::engine_failure(&error),
        Err(join) if join.is_panic() => NativeFinishOutcome::failure(
            "engine_panic",
            "internal",
            "the hosted scan engine panicked",
        ),
        Err(_) => NativeFinishOutcome::failure(
            "engine_internal",
            "internal",
            "the hosted scan engine task was aborted",
        ),
    }
}

fn ready(outcome: NativeFinishOutcome) -> OutcomeFuture {
    Box::pin(async move { outcome })
}

pub struct NativeHostedScanSession {
    state: SessionState,
    provider: Option<ProviderRefs>,
    cancel: CancellationToken,
}

fn provider_function<'a, Return>(
    provider: &Object<'a>,
    name: &str,
) -> napi::Result<Function<'a, String, Return>>
where
    Return: napi::bindgen_prelude::FromNapiValue,
{
    provider
        .get_named_property::<Function<'a, String, Return>>(name)
        .map_err(|_| {
            invalid_input(
                "invalid_provider",
                format!("provider.{name} must be a function"),
            )
        })
}

impl NativeHostedScanSession {
    pub fn new(options_json: String, provider: Object<'_>) -> napi::Result<Self> {
        let options: HostedScanOptions = serde_json::from_str(&options_json)
            .map_err(|e| invalid_input("invalid_options", format!("session options: {e}")))?;
        let builder = SessionBuilder::new(options).map_err(|e| engine_js_error(&e))?;
        let refs = ProviderRefs {
            search_patches_batch: provider_function(&provider, "searchPatchesBatch")?
                .create_ref()
                .map_err(napi_js_error)?,
            search_patches_by_package: provider_function(&provider, "searchPatchesByPackage")?
                .create_ref()
                .map_err(napi_js_error)?,
            fetch_registry_references: provider_function(&provider, "fetchRegistryReferences")?
                .create_ref()
                .map_err(napi_js_error)?,
            fetch_patch: provider_function(&provider, "fetchPatch")?
                .create_ref()
                .map_err(napi_js_error)?,
            download_artifact: provider_function(&provider, "downloadArtifact")?
                .create_ref()
                .map_err(napi_js_error)?,
        };
        Ok(Self {
            state: SessionState::Open(Box::new(builder)),
            provider: Some(refs),
            cancel: CancellationToken::new(),
        })
    }

    fn with_builder(
        &mut self,
        step: impl FnOnce(&mut SessionBuilder) -> Result<(), EngineError>,
    ) -> napi::Result<()> {
        if self.cancel.is_cancelled() {
            return Err(engine_js_error(&EngineError::Cancelled));
        }
        let builder = match &mut self.state {
            SessionState::Open(builder) => builder,
            SessionState::Failed(error) => return Err(engine_js_error(error)),
            SessionState::Finished => {
                return Err(invalid_input(
                    "session_finished",
                    "the session has already finished",
                ))
            }
        };
        match step(builder) {
            Ok(()) => Ok(()),
            Err(error) => {
                let thrown = engine_js_error(&error);
                self.state = SessionState::Failed(error);
                self.provider = None;
                Err(thrown)
            }
        }
    }

    pub fn push_chunk(&mut self, path: String, chunk: Buffer) -> napi::Result<()> {
        self.with_builder(|builder| builder.push_chunk(&path, &chunk))
    }

    pub fn end_file(&mut self, path: String) -> napi::Result<()> {
        self.with_builder(|builder| builder.end_file(&path))
    }

    pub fn mark_present(&mut self, path: String, kind: String) -> napi::Result<()> {
        let Some(mark) = PresentKind::parse(&kind) else {
            return Err(invalid_input(
                "invalid_mark_kind",
                format!("`{kind}` is not a markPresent kind"),
            ));
        };
        self.with_builder(|builder| builder.mark_present(&path, mark))
    }

    pub fn finish<'env>(
        &mut self,
        env: &'env Env,
    ) -> napi::Result<PromiseRaw<'env, NativeFinishOutcome>> {
        let state = std::mem::replace(&mut self.state, SessionState::Finished);
        let refs = self.provider.take();
        let outcome: OutcomeFuture = match state {
            _ if self.cancel.is_cancelled() => {
                ready(NativeFinishOutcome::engine_failure(&EngineError::Cancelled))
            }
            SessionState::Finished => ready(NativeFinishOutcome::failure(
                "session_finished",
                "invalid_input",
                "the session has already finished",
            )),
            SessionState::Failed(error) => ready(NativeFinishOutcome::engine_failure(&error)),
            SessionState::Open(builder) => match (builder.finish(), refs) {
                (Err(error), _) => ready(NativeFinishOutcome::engine_failure(&error)),
                (Ok(_), None) => ready(NativeFinishOutcome::failure(
                    "engine_internal",
                    "internal",
                    "the session has no provider",
                )),
                (Ok(input), Some(refs)) => {
                    let api = JsPatchApi::new(env, &refs).map_err(napi_js_error)?;
                    let provider: Arc<dyn PatchApi> = Arc::new(api);
                    Box::pin(run_engine(input, provider, self.cancel.clone()))
                }
            },
        };
        env.spawn_future(async move { Ok(outcome.await) })
    }

    pub fn cancel(&mut self) {
        self.cancel.cancel();
        // Buffered chunks are native memory V8 does not see, so waiting for
        // the wrapper's finalizer could hold up to maxTotalBytes per session.
        if matches!(self.state, SessionState::Open(_)) {
            self.state = SessionState::Failed(EngineError::Cancelled);
        }
        self.provider = None;
    }
}

#[napi(js_name = "createHostedScanSession")]
pub fn create_hosted_scan_session(
    options_json: String,
    provider: Object<'_>,
) -> napi::Result<External<NativeHostedScanSession>> {
    NativeHostedScanSession::new(options_json, provider).map(External::new)
}

#[napi(js_name = "hostedScanSessionPushChunk")]
pub fn hosted_scan_session_push_chunk(
    session: &mut External<NativeHostedScanSession>,
    path: String,
    chunk: Buffer,
) -> napi::Result<()> {
    session.push_chunk(path, chunk)
}

#[napi(js_name = "hostedScanSessionEndFile")]
pub fn hosted_scan_session_end_file(
    session: &mut External<NativeHostedScanSession>,
    path: String,
) -> napi::Result<()> {
    session.end_file(path)
}

#[napi(js_name = "hostedScanSessionMarkPresent")]
pub fn hosted_scan_session_mark_present(
    session: &mut External<NativeHostedScanSession>,
    path: String,
    kind: String,
) -> napi::Result<()> {
    session.mark_present(path, kind)
}

#[napi(js_name = "hostedScanSessionFinish")]
pub fn hosted_scan_session_finish<'env>(
    env: &'env Env,
    session: &mut External<NativeHostedScanSession>,
) -> napi::Result<PromiseRaw<'env, NativeFinishOutcome>> {
    session.finish(env)
}

#[napi(js_name = "hostedScanSessionCancel")]
pub fn hosted_scan_session_cancel(session: &mut External<NativeHostedScanSession>) {
    session.cancel();
}
