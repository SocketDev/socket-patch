//! Option validation and the streaming session builder: every size and
//! count limit on what a host may hand the engine is enforced here, before
//! any parser sees a byte.

use std::collections::BTreeMap;

use super::select::{is_binary_candidate, safe_repo_path, safe_root_path};
use super::types::{
    EngineError, EngineWarning, HostedScanInput, HostedScanOptions, InputFile, MarkKind,
    PresentKind, ResolvedLimits, DEFAULT_BATCH_SIZE, DEFAULT_PROVIDER_CONCURRENCY,
    DEFAULT_REQUEST_TIMEOUT_MS, ECOSYSTEMS, MAX_BATCH_SIZE,
};

/// Upper bound on concurrent provider calls, whatever the host asks for.
const MAX_PROVIDER_CONCURRENCY: u32 = 64;

/// The options every engine entry point validates, with defaults applied.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedOptions {
    pub(crate) ecosystems: Option<Vec<String>>,
    pub(crate) batch_size: usize,
    pub(crate) dry_run: bool,
    pub(crate) pipenv_major: Option<u32>,
    pub(crate) trust_lockfile_config: bool,
    pub(crate) npm_allow_remote_config: bool,
    pub(crate) project_roots: Option<Vec<String>>,
    pub(crate) provider_concurrency: usize,
    pub(crate) request_timeout: std::time::Duration,
    pub(crate) limits: ResolvedLimits,
    /// `maxNewPatches` (`Some(None)` is `"none"`); see [`Self::max_new`].
    max_new_patches: Option<Option<u32>>,
    max_new_patches_cap: Option<u32>,
    /// `inFlightPatches` as canonical base purls.
    pub(crate) in_flight: std::collections::BTreeSet<String>,
    pub(crate) policy_overrides: socket_patch_core::policy::PolicyOverrides,
    pub(crate) policy_paths: Vec<String>,
    pub(crate) policy_sha256: Option<String>,
}

impl ResolvedOptions {
    /// The run-wide cap on NEW patches: the `maxNewPatches` option (reported
    /// as `flag`), then the socket.yml `patches.maxNewPatches`, then
    /// unlimited; `maxNewPatchesCap` only tightens it.
    pub(crate) fn max_new(&self, file: Option<u32>) -> socket_patch_core::rollout::MaxNew {
        socket_patch_core::rollout::resolve_max_new(
            self.max_new_patches,
            None,
            file,
            self.max_new_patches_cap,
        )
    }
}

pub(crate) fn resolve_options(options: &HostedScanOptions) -> Result<ResolvedOptions, EngineError> {
    if options.org_slug.trim().is_empty() {
        return Err(EngineError::invalid(
            "invalid_org_slug",
            "orgSlug must be a non-empty string",
        ));
    }
    let batch_size = options.batch_size.unwrap_or(DEFAULT_BATCH_SIZE);
    if !(1..=MAX_BATCH_SIZE).contains(&batch_size) {
        return Err(EngineError::invalid(
            "invalid_batch_size",
            format!("batchSize must be between 1 and {MAX_BATCH_SIZE}"),
        ));
    }
    if let Some(ecosystems) = &options.ecosystems {
        if let Some(bad) = ecosystems
            .iter()
            .find(|e| !ECOSYSTEMS.contains(&e.as_str()))
        {
            return Err(EngineError::invalid(
                "invalid_ecosystem",
                format!("unknown ecosystem `{bad}`"),
            ));
        }
    }
    let min_severity = match options.min_severity.as_deref() {
        None => None,
        Some(value) => Some((
            socket_patch_core::policy::parse_min_severity(value)
                .map_err(|e| EngineError::invalid("invalid_min_severity", format!("minSeverity: {e}")))?,
            socket_patch_core::policy::OverrideSource::Flag,
        )),
    };
    let policy_overrides = socket_patch_core::policy::PolicyOverrides {
        bypass: options.no_socket_yml.unwrap_or(false),
        min_severity,
    };
    let mut policy_paths: Vec<String> = Vec::new();
    for path in options.policy_paths.iter().flatten() {
        if !socket_patch_core::policy::POLICY_FILE_NAMES.contains(&path.as_str()) {
            return Err(EngineError::invalid(
                "invalid_policy_path",
                format!("policyPaths entry `{path}` is not a root socket.yml or socket.yaml"),
            ));
        }
        policy_paths.push(path.clone());
    }
    let project_roots = match &options.project_roots {
        Some(roots) => {
            let mut out: Vec<String> = Vec::with_capacity(roots.len());
            for root in roots {
                let normalized = safe_root_path(root).ok_or_else(|| {
                    EngineError::invalid(
                        "invalid_project_root",
                        format!(
                            "projectRoots entry `{root}` is not a safe repo-relative directory"
                        ),
                    )
                })?;
                out.push(normalized);
            }
            out.sort();
            out.dedup();
            Some(out)
        }
        None => None,
    };
    let provider_concurrency = options
        .provider_concurrency
        .unwrap_or(DEFAULT_PROVIDER_CONCURRENCY);
    if provider_concurrency == 0 {
        return Err(EngineError::invalid(
            "invalid_provider_concurrency",
            "providerConcurrency must be at least 1",
        ));
    }
    let timeout_ms = options
        .request_timeout_ms
        .unwrap_or(DEFAULT_REQUEST_TIMEOUT_MS);
    if timeout_ms == 0 {
        return Err(EngineError::invalid(
            "invalid_request_timeout",
            "requestTimeoutMs must be at least 1",
        ));
    }
    Ok(ResolvedOptions {
        ecosystems: options.ecosystems.clone(),
        batch_size: batch_size as usize,
        dry_run: options.dry_run,
        pipenv_major: options.pipenv_major,
        trust_lockfile_config: options.trust_lockfile_config.unwrap_or(true),
        npm_allow_remote_config: options.npm_allow_remote_config.unwrap_or(true),
        project_roots,
        provider_concurrency: provider_concurrency.min(MAX_PROVIDER_CONCURRENCY) as usize,
        request_timeout: std::time::Duration::from_millis(timeout_ms),
        limits: options.limits.clone().unwrap_or_default().resolve(),
        max_new_patches: options.max_new_patches.map(|v| v.0),
        max_new_patches_cap: options.max_new_patches_cap,
        in_flight: options
            .in_flight_patches
            .iter()
            .flatten()
            .map(|p| socket_patch_core::rollout::canonical_base_purl(p))
            .collect(),
        policy_overrides,
        policy_paths,
        policy_sha256: options.policy_sha256.clone(),
    })
}

/// Accumulates a host's streamed files into a [`HostedScanInput`],
/// enforcing `maxFiles`, `maxFileBytes` and `maxTotalBytes` on every chunk.
/// `bun.lockb` is kept as bytes; every other file must be UTF-8 (a file
/// that is not is kept as present-but-unreadable with an `invalid_utf8`
/// warning, exactly like an unreadable file on disk).
#[derive(Debug)]
pub struct SessionBuilder {
    options: HostedScanOptions,
    limits: ResolvedLimits,
    open: BTreeMap<String, Vec<u8>>,
    files: BTreeMap<String, InputFile>,
    total_bytes: u64,
    warnings: Vec<EngineWarning>,
}

impl SessionBuilder {
    pub fn new(options: HostedScanOptions) -> Result<Self, EngineError> {
        let resolved = resolve_options(&options)?;
        Ok(Self {
            options,
            limits: resolved.limits,
            open: BTreeMap::new(),
            files: BTreeMap::new(),
            total_bytes: 0,
            warnings: Vec::new(),
        })
    }

    pub fn options(&self) -> &HostedScanOptions {
        &self.options
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    fn checked_path(&self, path: &str) -> Result<String, EngineError> {
        let normalized = safe_repo_path(path).ok_or_else(|| {
            EngineError::invalid(
                "invalid_path",
                format!("`{path}` is not a safe repo-relative path"),
            )
        })?;
        if self.files.contains_key(&normalized) {
            return Err(EngineError::invalid(
                "duplicate_path",
                format!("`{normalized}` was already provided"),
            ));
        }
        Ok(normalized)
    }

    fn check_file_count(&self, adding_new: bool) -> Result<(), EngineError> {
        let count = (self.files.len() + self.open.len() + usize::from(adding_new)) as u64;
        if count > self.limits.max_files {
            return Err(EngineError::limit(
                "max_files",
                format!("more than {} files were provided", self.limits.max_files),
            ));
        }
        Ok(())
    }

    /// Append `chunk` to `path`'s content.
    pub fn push_chunk(&mut self, path: &str, chunk: &[u8]) -> Result<(), EngineError> {
        let path = self.checked_path(path)?;
        let is_new = !self.open.contains_key(&path);
        self.check_file_count(is_new)?;
        let current = self.open.get(&path).map_or(0, Vec::len) as u64;
        let len = chunk.len() as u64;
        if current + len > self.limits.max_file_bytes {
            return Err(EngineError::limit(
                "max_file_bytes",
                format!(
                    "`{path}` exceeds the {}-byte per-file limit",
                    self.limits.max_file_bytes
                ),
            ));
        }
        if self.total_bytes + len > self.limits.max_total_bytes {
            return Err(EngineError::limit(
                "max_total_bytes",
                format!(
                    "the session exceeds the {}-byte total limit",
                    self.limits.max_total_bytes
                ),
            ));
        }
        self.total_bytes += len;
        self.open.entry(path).or_default().extend_from_slice(chunk);
        Ok(())
    }

    /// Complete `path` (a path with no chunks is an empty file).
    pub fn end_file(&mut self, path: &str) -> Result<(), EngineError> {
        let path = self.checked_path(path)?;
        let bytes = match self.open.remove(&path) {
            Some(bytes) => bytes,
            None => {
                self.check_file_count(true)?;
                Vec::new()
            }
        };
        let file = if is_binary_candidate(&path) {
            InputFile::Binary(bytes)
        } else {
            match String::from_utf8(bytes) {
                Ok(text) => InputFile::Text(text),
                Err(_) => {
                    self.warnings.push(EngineWarning::new(
                        "invalid_utf8",
                        format!("{path} is not valid UTF-8 and was treated as unreadable"),
                        None,
                    ));
                    InputFile::Present(PresentKind::BinarySkipped)
                }
            }
        };
        self.files.insert(path, file);
        Ok(())
    }

    /// Record that `path` exists without providing its content.
    pub fn mark_present(&mut self, path: &str, kind: MarkKind) -> Result<(), EngineError> {
        let path = self.checked_path(path)?;
        if self.open.contains_key(&path) {
            return Err(EngineError::invalid(
                "duplicate_path",
                format!("`{path}` already has streamed content"),
            ));
        }
        self.check_file_count(true)?;
        let file = match kind {
            MarkKind::Symlink => InputFile::Symlink,
            MarkKind::Present(kind) => {
                let code = match kind {
                    PresentKind::Present => None,
                    PresentKind::BinarySkipped => Some("binary_skipped"),
                    PresentKind::Oversize => Some("file_oversize"),
                    PresentKind::LfsPointer => Some("lfs_pointer"),
                };
                if let Some(code) = code {
                    self.warnings.push(EngineWarning::new(
                        code,
                        format!("{path} was not provided ({code}) and was treated as unreadable"),
                        None,
                    ));
                }
                InputFile::Present(kind)
            }
        };
        self.files.insert(path, file);
        Ok(())
    }

    /// Whole-file convenience over [`Self::push_chunk`] + [`Self::end_file`].
    pub fn add_text(&mut self, path: &str, text: &str) -> Result<(), EngineError> {
        self.push_chunk(path, text.as_bytes())?;
        self.end_file(path)
    }

    /// Whole-file convenience for binary content.
    pub fn add_binary(&mut self, path: &str, bytes: &[u8]) -> Result<(), EngineError> {
        let normalized = self.checked_path(path)?;
        self.push_chunk(&normalized, bytes)?;
        let bytes = self.open.remove(&normalized).unwrap_or_default();
        self.files.insert(normalized, InputFile::Binary(bytes));
        Ok(())
    }

    /// The finished input. Fails when a streamed file was never ended.
    pub fn finish(self) -> Result<HostedScanInput, EngineError> {
        if let Some(path) = self.open.keys().next() {
            return Err(EngineError::invalid(
                "unterminated_file",
                format!("`{path}` received chunks but endFile was never called"),
            ));
        }
        Ok(HostedScanInput {
            options: self.options,
            files: self.files,
            warnings: self.warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosted_memory::types::HostedScanLimits;

    fn options(limits: HostedScanLimits) -> HostedScanOptions {
        HostedScanOptions {
            org_slug: "org".into(),
            limits: Some(limits),
            ..HostedScanOptions::default()
        }
    }

    #[test]
    fn rejects_bad_options() {
        let mut o = options(HostedScanLimits::default());
        o.batch_size = Some(0);
        assert_eq!(
            resolve_options(&o).unwrap_err().code(),
            "invalid_batch_size"
        );
        o.batch_size = Some(501);
        assert_eq!(
            resolve_options(&o).unwrap_err().code(),
            "invalid_batch_size"
        );
        o.batch_size = None;
        o.ecosystems = Some(vec!["deno".into()]);
        assert_eq!(resolve_options(&o).unwrap_err().code(), "invalid_ecosystem");
        o.ecosystems = None;
        o.project_roots = Some(vec!["../x".into()]);
        assert_eq!(
            resolve_options(&o).unwrap_err().code(),
            "invalid_project_root"
        );
        o.project_roots = None;
        o.org_slug = " ".into();
        assert_eq!(resolve_options(&o).unwrap_err().code(), "invalid_org_slug");
    }

    #[test]
    fn enforces_session_limits() {
        let mut b = SessionBuilder::new(options(HostedScanLimits {
            max_file_bytes: Some(4),
            max_total_bytes: Some(6),
            max_files: Some(2),
            ..HostedScanLimits::default()
        }))
        .unwrap();
        b.push_chunk("a", b"12").unwrap();
        b.push_chunk("a", b"34").unwrap();
        assert_eq!(
            b.push_chunk("a", b"5").unwrap_err().code(),
            "max_file_bytes"
        );
        b.end_file("a").unwrap();
        b.push_chunk("b", b"12").unwrap();
        assert_eq!(
            b.push_chunk("b", b"3").unwrap_err().code(),
            "max_total_bytes"
        );
        b.end_file("b").unwrap();
        assert_eq!(b.end_file("c").unwrap_err().code(), "max_files");
        assert_eq!(
            b.push_chunk("a", b"x").unwrap_err().code(),
            "duplicate_path"
        );
        assert_eq!(
            b.push_chunk("../evil", b"x").unwrap_err().code(),
            "invalid_path"
        );
    }

    #[test]
    fn classifies_finished_files() {
        let mut b = SessionBuilder::new(options(HostedScanLimits::default())).unwrap();
        b.add_text("package-lock.json", "{}").unwrap();
        b.push_chunk("bun.lockb", &[0xff, 0x00]).unwrap();
        b.end_file("bun.lockb").unwrap();
        b.push_chunk("yarn.lock", &[0xff, 0xfe]).unwrap();
        b.end_file("yarn.lock").unwrap();
        b.mark_present(".pnp.cjs", MarkKind::Present(PresentKind::Present))
            .unwrap();
        b.mark_present(".npmrc", MarkKind::Symlink).unwrap();
        b.push_chunk("open.txt", b"x").unwrap();
        assert_eq!(b.finish().unwrap_err().code(), "unterminated_file");
    }

    #[test]
    fn finished_input_keeps_every_kind() {
        let mut b = SessionBuilder::new(options(HostedScanLimits::default())).unwrap();
        b.add_text("package-lock.json", "{}").unwrap();
        b.push_chunk("bun.lockb", &[0xff, 0x00]).unwrap();
        b.end_file("bun.lockb").unwrap();
        b.push_chunk("yarn.lock", &[0xff, 0xfe]).unwrap();
        b.end_file("yarn.lock").unwrap();
        b.mark_present(".npmrc", MarkKind::Symlink).unwrap();
        let input = b.finish().unwrap();
        assert_eq!(
            input.files.get("package-lock.json"),
            Some(&InputFile::Text("{}".into()))
        );
        assert_eq!(
            input.files.get("bun.lockb"),
            Some(&InputFile::Binary(vec![0xff, 0x00]))
        );
        assert_eq!(
            input.files.get("yarn.lock"),
            Some(&InputFile::Present(PresentKind::BinarySkipped))
        );
        assert_eq!(input.files.get(".npmrc"), Some(&InputFile::Symlink));
        assert_eq!(input.warnings.len(), 1);
        assert_eq!(input.warnings[0].code, "invalid_utf8");
    }
}
