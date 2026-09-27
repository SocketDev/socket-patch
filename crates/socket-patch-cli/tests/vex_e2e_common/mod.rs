//! Shared steps for manifest-less VEX end-to-end tests (hosted + vendored
//! patches, one suite per package manager).
//!
//! A hosted (`scan --mode hosted`) or vendored (`scan --vendor`,
//! `vendor --detached`, a depscan-opened PR) checkout has NO
//! `.socket/manifest.json`: the patches live in the lockfiles/configs, the
//! committed `.socket/vendor/` artifacts and (optionally) the two ledgers.
//! These helpers take a project a real package manager produced, strip it
//! down to that shape, run VEX, and assert what was (and was not) attested.
//!
//! Pull it in with
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! use vex_e2e_common::*;
//! ```
//!
//! Typical flow (a hosted npm patch whose record comes from the patch API):
//!
//! ```ignore
//! let api = PatchApi::start(vec![(
//!     UUID.into(),
//!     patch_view(UUID, "pkg:npm/left-pad@1.3.0",
//!                &[("package/index.js", &git_sha256(b"patched\n"))],
//!                &[("GHSA-xxxx-yyyy-zzzz", &["CVE-2026-1"])]),
//! )]);
//! // ... `socket-patch scan --mode hosted` + `npm ci` in `project` ...
//! strip_manifest(project);          // the depscan / lockfile-only shape
//! strip_ledgers(project);           // optional: lockfile wiring alone
//!
//! // Offline first: zero network, the record is unavailable.
//! let out = run_vex(&binary(), project, &VexRun { offline: true, ..VexRun::default() });
//! assert_eq!(out.code, Some(1), "{out}");
//! assert_not_attested(&out.envelope, "pkg:npm/left-pad@1.3.0", "record_unavailable");
//! api.assert_no_requests();
//!
//! // Online: the record is fetched and the installed tree hash-verifies.
//! let out = run_vex(&binary(), project, &VexRun::online(&api));
//! assert_eq!(out.code, Some(0), "{out}");
//! assert_attested(out.doc(), "pkg:npm/left-pad@1.3.0", UUID, Marker::Redirected,
//!                 &[("GHSA-xxxx-yyyy-zzzz", &["CVE-2026-1"])]);
//! assert!(api.view_requests(UUID) >= 1);
//!
//! // Embedded: the same attestation through `apply --vex`.
//! let out = run_vex(&binary(), project,
//!                   &VexRun { via: VexVia::Apply, ..VexRun::online(&api) });
//! assert_eq!(out.envelope["vex"]["statements"], 1, "{out}");
//! ```
//!
//! Notes:
//! - Every run is hermetic: ambient `SOCKET_*` is scrubbed, telemetry and
//!   the socket-cli config are off, ambient API tokens are vetoed (only
//!   [`VexRun::api_token`] authenticates) and `VIRTUAL_ENV` is removed.
//!   Package-manager homes/caches the installed-tree lookups need go in
//!   [`VexRun::envs`].
//! - `--json` is the default ([`VexRun::human`] opts out), so
//!   [`VexOutcome::envelope`] is always the parsed stdout object.
//! - [`assert_not_attested`] needs the STANDALONE `vex` envelope
//!   ([`VexVia::Vex`]): only it carries a per-purl `skipped` event with the
//!   omission `errorCode`. For embedded runs assert on the document
//!   ([`assert_absent`]) and the envelope's `error.code`.
//! - The patch API stand-in answers both the public-proxy route
//!   (`/patch/view/<uuid>`, used without a token) and the org-scoped route
//!   (`/v0/orgs/<org>/patches/view/<uuid>`, used with `--api-token`), and
//!   records every request so `--offline` runs can prove zero network.

#![allow(dead_code)]

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Product id the helpers pass by default (a PURL, so the document is
/// valid without filesystem product auto-detection).
pub const DEFAULT_PRODUCT: &str = "pkg:npm/app@1.0.0";

/// Default document path, relative to the project.
pub const DEFAULT_OUTPUT: &str = "out.vex.json";

/// Absolute path of the `socket-patch` binary under test.
pub fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Git-style sha256 of `bytes` — the `afterHash` a patch view carries for a
/// patched file (what installed-tree verification recomputes).
pub fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

// ── Project shaping ───────────────────────────────────────────────────

/// Delete `.socket/manifest.json` (if present): the shape a hosted /
/// vendored / depscan checkout has (both modes are manifest-free, so this
/// only removes a manifest a test seeded or an agent-mode run left).
/// Everything else under `.socket/` (vendored artifacts, ledgers) is kept.
pub fn strip_manifest(project: &Path) {
    remove_if_present(&project.join(".socket/manifest.json"));
}

/// Write the `.socket/manifest.json` a pre-5.0 vendored run left beside its
/// ledger: every vendor-ledger entry's embedded `record`, keyed by the
/// ledger key (vendored mode is manifest-free now, so only a legacy
/// checkout still carries one). Returns how many records were seeded —
/// callers assert it is non-zero, so the step can never pass vacuously.
pub fn seed_legacy_manifest(project: &Path) -> usize {
    let state_path = project.join(socket_patch_core::vendor::VENDOR_STATE_REL);
    let state: Value = serde_json::from_str(
        &std::fs::read_to_string(&state_path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", state_path.display())),
    )
    .expect("the vendor ledger is JSON");
    let mut patches = serde_json::Map::new();
    for (key, entry) in state["entries"].as_object().into_iter().flatten() {
        if let Some(record) = entry.get("record").filter(|r| r.is_object()) {
            patches.insert(key.clone(), record.clone());
        }
    }
    let seeded = patches.len();
    std::fs::write(
        project.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({ "patches": patches }))
            .expect("manifest serializes"),
    )
    .expect("write the legacy manifest");
    seeded
}

/// Delete both ledgers — `.socket/vendor/state.json` (vendor) and
/// `.socket/vendor/redirect-state.json` (hosted) — so the lockfile wiring
/// (+ committed `.socket/vendor/<eco>/<uuid>/` artifacts) is the ONLY
/// evidence left. Artifacts are kept.
pub fn strip_ledgers(project: &Path) {
    remove_if_present(&project.join(socket_patch_core::vendor::VENDOR_STATE_REL));
    remove_if_present(&project.join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL));
}

fn remove_if_present(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("removing {}: {e}", path.display()),
    }
    assert!(!path.exists(), "{} still exists", path.display());
}

// ── Running VEX ───────────────────────────────────────────────────────

/// Which command produces the document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VexVia {
    /// `socket-patch vex --output <doc>` (standalone; per-purl envelope).
    #[default]
    Vex,
    /// `socket-patch apply --vex <doc>` (embedded).
    Apply,
    /// `socket-patch vendor --vex <doc>` (embedded).
    Vendor,
    /// `socket-patch scan --vex <doc>` (embedded; put `--mode …` etc. in
    /// [`VexRun::extra_args`]). Scan also queries the patch API's search
    /// routes, which [`PatchApi`] answers 404.
    Scan,
}

/// Options for one [`run_vex`] invocation. `VexRun::default()` is a
/// standalone, online-by-default (but with no API configured), `--json`
/// run writing `<project>/out.vex.json` for [`DEFAULT_PRODUCT`].
#[derive(Clone, Debug, Default)]
pub struct VexRun {
    pub via: VexVia,
    /// `--api-url` (with [`Self::api_token`]: the org-scoped routes).
    pub api_url: Option<String>,
    /// `--proxy-url` (the public-proxy routes an unauthenticated run uses).
    pub proxy_url: Option<String>,
    /// `--api-token` (the only token the run sees; ambient ones are vetoed).
    pub api_token: Option<String>,
    /// `--org`.
    pub org: Option<String>,
    /// `--patch-server-url` (hosted references on this origin count).
    pub patch_server_url: Option<String>,
    /// `--offline`.
    pub offline: bool,
    /// `--no-verify` (standalone) / `--vex-no-verify` (embedded).
    pub no_verify: bool,
    /// `--dry-run` (embedded commands skip VEX generation under it).
    pub dry_run: bool,
    /// Human output instead of `--json` (then `envelope` is `Null`).
    pub human: bool,
    /// Product override; `None` => [`DEFAULT_PRODUCT`].
    pub product: Option<String>,
    /// Document path; `None` => `<project>/out.vex.json`. Relative paths
    /// resolve against the project.
    pub output: Option<PathBuf>,
    /// Appended after the generated arguments.
    pub extra_args: Vec<String>,
    /// Extra child environment (package-manager homes, caches, ...).
    pub envs: Vec<(String, OsString)>,
}

impl VexRun {
    /// Standalone run whose patch-API traffic goes to `api` via the public
    /// proxy route (no token).
    pub fn online(api: &PatchApi) -> Self {
        Self {
            proxy_url: Some(api.uri()),
            ..Self::default()
        }
    }

    /// Standalone `--offline` run.
    pub fn offline() -> Self {
        Self {
            offline: true,
            ..Self::default()
        }
    }

    /// Standalone run authenticated against `api`'s org-scoped routes.
    pub fn org_scoped(api: &PatchApi, org: &str) -> Self {
        Self {
            api_url: Some(api.uri()),
            api_token: Some("sktsec_test_token_for_vex_e2e".to_string()),
            org: Some(org.to_string()),
            ..Self::default()
        }
    }

    pub fn via(mut self, via: VexVia) -> Self {
        self.via = via;
        self
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.extra_args.push(arg.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<OsString>) -> Self {
        self.envs.push((key.into(), value.into()));
        self
    }
}

/// What one [`run_vex`] produced.
#[derive(Debug)]
pub struct VexOutcome {
    /// Process exit code (`None` when killed by a signal).
    pub code: Option<i32>,
    /// The OpenVEX document at the output path after the run, if any (a
    /// failed run removes a stale one).
    pub doc: Option<Value>,
    /// Parsed stdout JSON (`Null` for human runs).
    pub envelope: Value,
    pub stdout: String,
    pub stderr: String,
    /// Absolute document path used.
    pub output: PathBuf,
}

impl VexOutcome {
    /// The document; panics (with the run's output) when none was written.
    pub fn doc(&self) -> &Value {
        self.doc
            .as_ref()
            .unwrap_or_else(|| panic!("no OpenVEX document was written:\n{self}"))
    }
}

impl fmt::Display for VexOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exit {:?}\n--- stdout\n{}\n--- stderr\n{}\n--- doc\n{}",
            self.code,
            self.stdout,
            self.stderr,
            self.doc
                .as_ref()
                .map(|d| serde_json::to_string_pretty(d).unwrap())
                .unwrap_or_else(|| "(none)".to_string())
        )
    }
}

/// Run VEX over `project` (`--cwd project`) with `bin` and return the exit
/// code, the document left at the output path, and the parsed envelope.
pub fn run_vex(bin: &Path, project: &Path, run: &VexRun) -> VexOutcome {
    let output = match &run.output {
        Some(p) if p.is_absolute() => p.clone(),
        Some(p) => project.join(p),
        None => project.join(DEFAULT_OUTPUT),
    };
    let product = run.product.as_deref().unwrap_or(DEFAULT_PRODUCT);
    let embedded = run.via != VexVia::Vex;
    let mut args: Vec<OsString> = vec![match run.via {
        VexVia::Vex => "vex",
        VexVia::Apply => "apply",
        VexVia::Vendor => "vendor",
        VexVia::Scan => "scan",
    }
    .into()];
    args.push("--cwd".into());
    args.push(project.as_os_str().to_owned());
    if !run.human {
        args.push("--json".into());
    }
    args.push(if embedded { "--vex" } else { "--output" }.into());
    args.push(output.as_os_str().to_owned());
    args.push(
        if embedded {
            "--vex-product"
        } else {
            "--product"
        }
        .into(),
    );
    args.push(product.into());
    if run.no_verify {
        args.push(
            if embedded {
                "--vex-no-verify"
            } else {
                "--no-verify"
            }
            .into(),
        );
    }
    let flag_value = [
        ("--api-url", &run.api_url),
        ("--proxy-url", &run.proxy_url),
        ("--api-token", &run.api_token),
        ("--org", &run.org),
        ("--patch-server-url", &run.patch_server_url),
    ];
    for (flag, value) in flag_value {
        if let Some(v) = value {
            args.push(flag.into());
            args.push(v.into());
        }
    }
    if run.offline {
        args.push("--offline".into());
    }
    if run.dry_run {
        args.push("--dry-run".into());
    }
    args.extend(run.extra_args.iter().map(OsString::from));

    let mut cmd = Command::new(bin);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_API_TOKEN", "1")
        .env_remove("VIRTUAL_ENV");
    for (key, value) in &run.envs {
        cmd.env(key, value);
    }
    let out = cmd
        .args(&args)
        .output()
        .unwrap_or_else(|e| panic!("spawning {}: {e}", bin.display()));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let envelope = if run.human {
        Value::Null
    } else {
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("--json stdout is not one JSON object ({e})\nargs {args:?}\n--- stdout\n{stdout}\n--- stderr\n{stderr}")
        })
    };
    let doc = std::fs::read(&output).ok().map(|bytes| {
        serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!(
                "{} is not JSON ({e}):\n{}",
                output.display(),
                String::from_utf8_lossy(&bytes)
            )
        })
    });
    VexOutcome {
        code: out.status.code(),
        doc,
        envelope,
        stdout,
        stderr,
        output,
    }
}

// ── Assertions ────────────────────────────────────────────────────────

/// Provenance marker in a statement's impact statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    /// "Patched via Socket patch <uuid> (redirected)" — hosted patches.
    Redirected,
    /// "Patched via Socket patch <uuid> (vendored)" — vendored patches.
    Vendored,
    /// "Patched via Socket patch <uuid>" — manifest (agent-mode) patches.
    Applied,
}

impl Marker {
    fn impact_part(self, uuid: &str) -> String {
        match self {
            Marker::Redirected => format!("Patched via Socket patch {uuid} (redirected)"),
            Marker::Vendored => format!("Patched via Socket patch {uuid} (vendored)"),
            Marker::Applied => format!("Patched via Socket patch {uuid}"),
        }
    }
}

/// `id` names `purl` (exactly, or with PURL qualifiers appended).
pub fn purl_matches(id: &str, purl: &str) -> bool {
    id == purl || id.split_once('?').map(|(base, _)| base) == Some(purl)
}

fn subcomponent_ids(statement: &Value) -> Vec<&str> {
    statement["products"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|p| p["subcomponents"].as_array().into_iter().flatten())
        .filter_map(|s| s["@id"].as_str())
        .collect()
}

/// Every statement in `doc` whose subcomponents name `purl`.
pub fn statements_for<'a>(doc: &'a Value, purl: &str) -> Vec<&'a Value> {
    doc["statements"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|st| subcomponent_ids(st).iter().any(|id| purl_matches(id, purl)))
        .collect()
}

/// Assert `doc` attests `purl` as `not_affected` via patch `uuid` with the
/// given provenance `marker`, for EXACTLY the vulnerability ids in `vulns`
/// (each with at least the listed aliases). Returns the matching statements.
pub fn assert_attested<'a>(
    doc: &'a Value,
    purl: &str,
    uuid: &str,
    marker: Marker,
    vulns: &[(&str, &[&str])],
) -> Vec<&'a Value> {
    assert_eq!(
        doc["@context"].as_str().map(|c| c.contains("openvex.dev")),
        Some(true),
        "not an OpenVEX document: {doc}"
    );
    let statements = statements_for(doc, purl);
    let mut got: Vec<&str> = statements
        .iter()
        .filter_map(|st| st["vulnerability"]["name"].as_str())
        .collect();
    got.sort_unstable();
    let mut want: Vec<&str> = vulns.iter().map(|(id, _)| *id).collect();
    want.sort_unstable();
    assert_eq!(got, want, "vulnerabilities attested for {purl}: {doc:#}");
    let part = marker.impact_part(uuid);
    for (id, aliases) in vulns {
        let st = statements
            .iter()
            .find(|st| st["vulnerability"]["name"] == *id)
            .expect("present: checked above");
        assert_eq!(st["status"], "not_affected", "{purl} {id}: {st:#}");
        assert_eq!(
            st["justification"], "inline_mitigations_already_exist",
            "{purl} {id}: {st:#}"
        );
        let have: Vec<&str> = st["vulnerability"]["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        for alias in *aliases {
            assert!(
                have.contains(alias),
                "{purl} {id}: alias {alias} missing: {st:#}"
            );
        }
        let impact = st["impact_statement"].as_str().unwrap_or_default();
        assert!(
            impact.split("; ").any(|p| p == part),
            "{purl} {id}: impact statement {impact:?} lacks {part:?}"
        );
    }
    statements
}

/// Assert `doc` (if any was written) makes no statement about `purl`.
pub fn assert_absent(doc: Option<&Value>, purl: &str) {
    if let Some(doc) = doc {
        let st = statements_for(doc, purl);
        assert!(st.is_empty(), "{purl} must not be attested: {st:#?}");
    }
}

/// Assert the STANDALONE `vex --json` envelope omitted `purl` with omission
/// code `reason` (`redirect_unwired`, `vendor_unwired`, `hash_mismatch`,
/// `record_unavailable`, `package_not_found`, `wiring_conflict`, ...) and
/// did not also record it as verified. Returns the skipped event.
pub fn assert_not_attested<'a>(envelope: &'a Value, purl: &str, reason: &str) -> &'a Value {
    let events = envelope["events"]
        .as_array()
        .unwrap_or_else(|| panic!("envelope has no events[]: {envelope:#}"));
    let verified = events.iter().any(|e| {
        e["action"] == "verified" && e["purl"].as_str().is_some_and(|p| purl_matches(p, purl))
    });
    assert!(!verified, "{purl} was attested: {envelope:#}");
    let skipped: Vec<&Value> = events
        .iter()
        .filter(|e| {
            e["action"] == "skipped" && e["purl"].as_str().is_some_and(|p| purl_matches(p, purl))
        })
        .collect();
    skipped
        .iter()
        .copied()
        .find(|e| e["errorCode"] == reason)
        .unwrap_or_else(|| {
            panic!("expected {purl} skipped with {reason:?}; skipped events {skipped:#?}; envelope {envelope:#}")
        })
}

/// [`purl_matches`], ignoring ASCII case: an OMITTED reference is reported
/// under the spelling discovery found (a nuget id lowercased by the
/// extractor), an attested one under the record's.
pub fn purl_matches_ignoring_case(id: &str, purl: &str) -> bool {
    purl_matches(&id.to_ascii_lowercase(), &purl.to_ascii_lowercase())
}

/// The omission code of `purl`'s skipped event in a standalone `vex --json`
/// envelope (purl compared qualifier- and case-insensitively); panics with
/// the envelope when there is none.
pub fn skipped_reason(envelope: &Value, purl: &str) -> String {
    envelope["events"]
        .as_array()
        .and_then(|events| {
            events.iter().find(|e| {
                e["action"] == "skipped"
                    && e["purl"]
                        .as_str()
                        .is_some_and(|p| purl_matches_ignoring_case(p, purl))
            })
        })
        .and_then(|e| e["errorCode"].as_str())
        .unwrap_or_else(|| panic!("expected a skipped event for {purl}: {envelope}"))
        .to_string()
}

/// The OpenVEX document at `path`, if a run left one.
pub fn read_doc(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    Some(serde_json::from_slice(&bytes).expect("the VEX document is JSON"))
}

/// THE omission oracle every manifest-less VEX suite shares (the per-PM
/// helpers delegate here, so one fix reaches every package manager): the
/// standalone run exited 1 with `no_applicable_patches`, recorded NO
/// `verified` event, skipped `purl` EXACTLY once with `reason`, and — when
/// the caller has the post-run document path's contents (`doc`) — wrote no
/// document. `doc` is `None` both for "nothing at the path" and for callers
/// that do not track the path; `no_applicable_patches` already means no
/// statement was built.
pub fn assert_omitted_parts(
    code: Option<i32>,
    envelope: &Value,
    doc: Option<&Value>,
    purl: &str,
    reason: &str,
    what: &str,
) {
    assert_eq!(code, Some(1), "{what}: {envelope}");
    assert_eq!(
        envelope["error"]["code"], "no_applicable_patches",
        "{what}: {envelope}"
    );
    let events = envelope["events"]
        .as_array()
        .unwrap_or_else(|| panic!("{what}: envelope has no events[]: {envelope}"));
    assert!(
        !events.iter().any(|e| e["action"] == "verified"),
        "{what}: nothing may be verified: {envelope}"
    );
    let skips: Vec<&Value> = events
        .iter()
        .filter(|e| {
            e["action"] == "skipped"
                && e["purl"]
                    .as_str()
                    .is_some_and(|p| purl_matches_ignoring_case(p, purl))
        })
        .collect();
    assert_eq!(
        skips.len(),
        1,
        "{what}: exactly one skip for {purl}: {envelope}"
    );
    assert_eq!(skips[0]["errorCode"], reason, "{what}: {envelope}");
    assert!(
        doc.is_none(),
        "{what}: a failed run leaves no document: {doc:?}"
    );
}

/// [`assert_omitted_parts`] for a [`run_vex`] outcome.
pub fn assert_omitted(out: &VexOutcome, purl: &str, reason: &str, what: &str) {
    assert_omitted_parts(
        out.code,
        &out.envelope,
        out.doc.as_ref(),
        purl,
        reason,
        what,
    );
}

// ── Synthetic fixture (self-test / smoke) ────────────────────────────

/// Grant-token segment of the synthetic hosted URL (uuid-shaped, like
/// production tokens; the patch uuid is the LAST uuid segment).
pub const HOSTED_TOKEN: &str = "11111111-2222-4333-8444-555555555555";

/// Write a lockfile-only hosted npm checkout: `package-lock.json` resolving
/// `name@version` from its hosted Socket patch with the patched tarball's
/// integrity pin (what `scan --mode hosted` writes) — nothing installed, no
/// `.socket/`. The pinned wiring attests `(redirected)` until an install
/// exists. Returns the PURL. Per-PM suites should build projects with the
/// real package manager instead; this is the minimal smoke shape.
pub fn write_hosted_npm_lock(project: &Path, name: &str, version: &str, uuid: &str) -> String {
    let lock = serde_json::json!({
        "name": "app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "app", "version": "1.0.0" },
            format!("node_modules/{name}"): {
                "version": version,
                "resolved": format!(
                    "https://patch.socket.dev/patch/npm/{name}/{version}/{HOSTED_TOKEN}/{uuid}/{name}-{version}.tgz"
                ),
                "integrity": "sha512-UEFUQ0hFRHBhdGNoZWRQQVRDSEVEcGF0Y2hlZA==",
            }
        }
    });
    std::fs::write(project.join("package-lock.json"), lock.to_string()).unwrap();
    format!("pkg:npm/{name}@{version}")
}

// ── Patch API stand-in ────────────────────────────────────────────────

/// The patch view (`GET …/view/<uuid>`) the API returns: `files` are
/// `(file key, afterHash)` (keys as the ecosystem's patch records spell them,
/// e.g. `package/index.js` for npm), `vulns` are `(id, CVE aliases)`.
pub fn patch_view(
    uuid: &str,
    purl: &str,
    files: &[(&str, &str)],
    vulns: &[(&str, &[&str])],
) -> Value {
    let files: serde_json::Map<String, Value> = files
        .iter()
        .map(|(key, after)| {
            (
                key.to_string(),
                serde_json::json!({ "beforeHash": "a".repeat(64), "afterHash": after }),
            )
        })
        .collect();
    let vulns: serde_json::Map<String, Value> = vulns
        .iter()
        .map(|(id, cves)| {
            (
                id.to_string(),
                serde_json::json!({
                    "cves": cves, "summary": "s", "severity": "high", "description": "d"
                }),
            )
        })
        .collect();
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "Fri, 27 Mar 2026 00:00:00 GMT",
        "files": files,
        "vulnerabilities": vulns,
        "description": "vex e2e patch",
        "license": "MIT",
        "tier": "free",
    })
}

/// A wiremock patch API serving patch views on both the public-proxy and
/// org-scoped routes, recording every request. Anything unmounted is 404.
/// Keep it alive for the whole CLI invocation.
pub struct PatchApi {
    // Declared before `rt` so the server drops while its runtime lives.
    server: wiremock::MockServer,
    rt: tokio::runtime::Runtime,
}

impl PatchApi {
    /// Start serving `(uuid, view body)` pairs.
    pub fn start(views: Vec<(String, Value)>) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("tokio runtime");
        let server = rt.block_on(wiremock::MockServer::start());
        let api = Self { server, rt };
        for (uuid, body) in views {
            api.add_view(&uuid, body);
        }
        api
    }

    /// A server with no views (every request 404s) — for asserting a run
    /// made no requests at all.
    pub fn empty() -> Self {
        Self::start(Vec::new())
    }

    /// Serve `body` for `uuid` on both view routes.
    pub fn add_view(&self, uuid: &str, body: Value) {
        self.respond(
            uuid,
            wiremock::ResponseTemplate::new(200).set_body_json(body),
        );
    }

    /// Answer `uuid`'s view routes with a bare `status` (e.g. 403 for a paid
    /// patch without entitlement, 500 for an outage).
    pub fn fail_view(&self, uuid: &str, status: u16) {
        self.respond(uuid, wiremock::ResponseTemplate::new(status));
    }

    fn respond(&self, uuid: &str, response: wiremock::ResponseTemplate) {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::Mock;
        let uuid_re = regex_escape(uuid);
        self.rt.block_on(async {
            Mock::given(method("GET"))
                .and(path(format!("/patch/view/{uuid}")))
                .respond_with(response.clone())
                .mount(&self.server)
                .await;
            Mock::given(method("GET"))
                .and(path_regex(format!(
                    "^/v0/orgs/[^/]+/patches/view/{uuid_re}$"
                )))
                .respond_with(response)
                .mount(&self.server)
                .await;
        });
    }

    /// Base URL (`--proxy-url` / `--api-url` / `--patch-server-url`).
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Paths of every request received so far, in arrival order.
    pub fn requests(&self) -> Vec<String> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .into_iter()
            .map(|r| r.url.path().to_string())
            .collect()
    }

    pub fn request_count(&self) -> usize {
        self.requests().len()
    }

    /// Requests for `uuid`'s view, on either route.
    pub fn view_requests(&self, uuid: &str) -> usize {
        self.requests()
            .iter()
            .filter(|p| {
                let org_scoped = p
                    .strip_prefix("/v0/orgs/")
                    .and_then(|rest| rest.split_once('/'))
                    .is_some_and(|(org, tail)| {
                        !org.is_empty() && tail == format!("patches/view/{uuid}")
                    });
                org_scoped || p.as_str() == format!("/patch/view/{uuid}")
            })
            .count()
    }

    /// Panic unless the server has received no request at all.
    pub fn assert_no_requests(&self) {
        let seen = self.requests();
        assert!(seen.is_empty(), "expected zero network, saw {seen:?}");
    }
}

fn regex_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            let special = "\\.+*?()|[]{}^$".contains(c);
            special
                .then_some('\\')
                .into_iter()
                .chain(std::iter::once(c))
        })
        .collect()
}
