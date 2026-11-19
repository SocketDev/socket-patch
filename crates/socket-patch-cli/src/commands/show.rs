//! `socket-patch show`: look inside one patch before (or after) applying
//! it. Read-only: it asks the patch service and prints, and never touches
//! the project.
//!
//! What it shows: the package and patch, the advisories the patch fixes,
//! what Socket measured about it (exploits blocked, tests passing, size,
//! run-time cost), the files it changes with their line counts, and the
//! unified diff of each file.
//!
//! There is one way a patch is read ([`Source`], [`Shown::read`]) and one
//! screen it is read on: on a terminal `show` opens the patch as a page of the
//! full-screen browser ([`ui::browser`]), the same page a row of `list`
//! opens ([`load_page`]). Anywhere else (a pipe, `--no-pager`, `--yes`)
//! the same text is printed at once, like `git show`.

use std::io::IsTerminal;

use base64::Engine as _;
use clap::Args;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate, ApiClient,
    ApiClientEnvOverrides, ApiError,
};
use socket_patch_core::api::ranking::{cmp_search_results, severity_order};
use socket_patch_core::api::types::{PatchFileResponse, PatchResponse, PatchSearchResult};
use socket_patch_core::utils::concurrent::{api_concurrency_for, ordered_concurrent};
use socket_patch_core::utils::purl::normalize_purl;
use socket_patch_core::utils::target::{Target, TargetKind};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::ecosystem_dispatch::{crawl_ecosystems, installed_target_matches};
use crate::ui::diff::{file_diff, FileDiff};
use crate::ui::{self, plural, select_one, Style};

/// The largest file content read for a diff. A larger file is listed with
/// its hashes, undiffed.
const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
/// Most installed packages a name may match before `show` asks for a purl.
const MAX_NAME_MATCHES: usize = 8;

#[derive(Args)]
pub struct ShowArgs {
    /// The patch to show: a patch UUID, or a PURL, package name, CVE ID
    /// or GHSA ID that has one.
    pub identifier: String,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Show the diff of these files only (a path of the patch, or the end
    /// of one). Repeat for several
    #[arg(long = "file", value_name = "PATH")]
    pub files: Vec<String>,

    /// Show the summary and the list of changed files, without the diffs
    #[arg(long, default_value_t = false)]
    pub stat: bool,

    /// Print everything at once instead of opening the patch full-screen
    /// (what a pipe gets)
    #[arg(long = "no-pager", default_value_t = false)]
    pub no_pager: bool,
}

/// One file of the patch, with what the patch does to it.
struct ShownFile {
    path: String,
    before_hash: String,
    after_hash: String,
    /// `None`: a side's content could not be read (the reason).
    diff: Result<FileDiff, String>,
}

/// Report a failure: the coded error on stdout under `--json`,
/// `Error: ...` on stderr otherwise. Returns the exit code, 1.
fn fail(common: &GlobalArgs, code: &str, message: &str) -> i32 {
    if common.json {
        ui::print_json(&serde_json::json!({
            "command": "show",
            "status": "error",
            "error": { "code": code, "message": message },
        }));
    } else {
        eprintln!("Error: {message}");
    }
    1
}

/// `publishedAt` as a date: the service sends an HTTP date (`Fri, 27 Mar
/// 2026 19:12:42 GMT`), fixtures an RFC 3339 one. Anything else is shown
/// as it came.
pub(crate) fn short_date(published_at: &str) -> String {
    let s = published_at.trim();
    if let Some((_, rest)) = s.split_once(", ") {
        let words: Vec<&str> = rest.split_whitespace().take(3).collect();
        if words.len() == 3 {
            return words.join(" ");
        }
    }
    match s.split_once('T') {
        Some((date, _)) if date.len() == 10 => date.to_string(),
        _ => s.to_string(),
    }
}

/// A file's content from its base64 field of the view, when it is there
/// and decodes.
fn decoded(content: Option<&String>) -> Option<Vec<u8>> {
    let content = content.filter(|c| !c.is_empty())?;
    base64::engine::general_purpose::STANDARD
        .decode(content)
        .ok()
}

/// Read blob `hash` whole, up to [`MAX_FILE_BYTES`].
async fn read_blob(client: &ApiClient, hash: &str) -> Result<Vec<u8>, String> {
    let mut body = client
        .fetch_blob(hash)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the patch service does not have its content".to_string())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = body.chunk().await.map_err(|e| e.to_string())? {
        bytes.extend_from_slice(chunk.as_ref());
        if bytes.len() > MAX_FILE_BYTES {
            return Err("the file is too large to diff".to_string());
        }
    }
    Ok(bytes)
}

/// One side of a file: from the view when it carries it, else by hash.
/// `Ok(None)` for a side that does not exist (a file the patch adds).
async fn side(
    client: &ApiClient,
    inline: Option<&String>,
    hash: Option<&String>,
) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = decoded(inline) {
        return Ok(Some(bytes));
    }
    match hash.filter(|h| !h.is_empty()) {
        Some(hash) => read_blob(client, hash).await.map(Some),
        None => Ok(None),
    }
}

/// Every file of `patch` with its diff, by path. Content the view does not
/// carry is read by hash, a few files at a time.
async fn shown_files(client: &ApiClient, patch: &PatchResponse, style: Style) -> Vec<ShownFile> {
    let mut files: Vec<(&String, &PatchFileResponse)> = patch.files.iter().collect();
    files.sort_by(|a, b| a.0.cmp(b.0));
    let mut out = Vec::with_capacity(files.len());
    let mut diffs = std::pin::pin!(ordered_concurrent(
        files,
        api_concurrency_for(client.uses_public_proxy(), patch.files.len()),
        |(path, file)| async move {
            let before = side(
                client,
                file.before_blob_content.as_ref(),
                file.before_hash.as_ref(),
            );
            let after = side(client, file.blob_content.as_ref(), file.after_hash.as_ref());
            let diff = match (before.await, after.await) {
                (Ok(before), Ok(Some(after))) => {
                    Ok(file_diff(path, before.as_deref(), &after, style))
                }
                (Ok(_), Ok(None)) => Err("the patch carries no content for it".to_string()),
                (Err(e), _) | (_, Err(e)) => Err(e),
            };
            ShownFile {
                path: path.clone(),
                before_hash: file.before_hash.clone().unwrap_or_default(),
                after_hash: file.after_hash.clone().unwrap_or_default(),
                diff,
            }
        },
    ));
    use futures_util::StreamExt;
    while let Some(file) = diffs.next().await {
        out.push(file);
    }
    out
}

/// `+12 -3`, `binary`, or why there is no diff.
fn change_label(file: &ShownFile, color: bool) -> String {
    match &file.diff {
        Ok(diff) if diff.binary => "binary".to_string(),
        Ok(diff) => format!(
            "{} {}",
            ui::paint(&format!("+{}", diff.added), "32", color),
            ui::paint(&format!("-{}", diff.removed), "31", color)
        ),
        Err(why) => format!("({why})"),
    }
}

/// The summary above the diffs: the package and patch, what it fixes,
/// what was measured about it, and the files it changes.
///
/// ```text
/// pkg:npm/undici@8.10.0  HIGH  [PAID]
/// Patch 8be53d06-7bd4-40cc-ab8f-36dc6248985a, published 03 Aug 2026, MIT
///
/// Fixes:
///   HIGH      CVE-2026-84961  undici vulnerable to TLS certificate validation bypass...
///
/// Measured by Socket:
///   Verified: 2 of 2 exploits blocked (2 of 2 worked before the patch), ...
///
/// Files changed (2): +9 -2
///   lib/dispatcher/client.js  +5 -2
/// ```
fn summary(patch: &PatchResponse, files: &[ShownFile], style: Style) -> Vec<String> {
    let color = style.color;
    let mut vulns: Vec<_> = patch.vulnerabilities.iter().collect();
    vulns.sort_by(|a, b| {
        severity_order(Some(&a.1.severity))
            .cmp(&severity_order(Some(&b.1.severity)))
            .then_with(|| a.0.cmp(b.0))
    });
    // The worst severity, as the row of `list` and the patch menu have it.
    let (worst, _) = ui::worst_and_ids(
        vulns
            .iter()
            .map(|(id, v)| (id.as_str(), v.severity.as_str(), v.cves.as_slice())),
    );
    let mut head = ui::bold(&normalize_purl(&patch.purl), color);
    if !worst.is_empty() {
        head.push_str(&format!("  {}", ui::severity(&worst, color)));
    }
    head.push_str(&format!("  [{}]", patch.tier.to_uppercase()));
    let mut about = format!("Patch {}", patch.uuid);
    if !patch.published_at.trim().is_empty() {
        about.push_str(&format!(", published {}", short_date(&patch.published_at)));
    }
    if !patch.license.trim().is_empty() {
        about.push_str(&format!(", {}", patch.license.trim()));
    }
    let mut lines = vec![head, ui::dim(&about, color)];
    let description = ui::truncate(&patch.description, 200);
    if !description.is_empty() {
        lines.push(description);
    }

    if !vulns.is_empty() {
        lines.push(String::new());
        lines.push("Fixes:".to_string());
        let labels: Vec<String> = vulns
            .iter()
            .map(|(id, vuln)| {
                if vuln.cves.is_empty() {
                    (*id).clone()
                } else {
                    let mut cves = vuln.cves.clone();
                    cves.sort();
                    cves.join(", ")
                }
            })
            .collect();
        let severity_w = vulns
            .iter()
            .map(|(_, v)| v.severity.chars().count())
            .max()
            .unwrap_or(0);
        let label_w = labels.iter().map(|l| l.chars().count()).max().unwrap_or(0);
        for ((_, vuln), label) in vulns.iter().zip(&labels) {
            let line = format!(
                "  {}  {}  {}",
                ui::pad(
                    &ui::severity(&vuln.severity.to_uppercase(), color),
                    severity_w
                ),
                ui::pad(label, label_w),
                ui::truncate(&vuln.summary, 100),
            );
            lines.push(line.trim_end().to_string());
        }
    }

    let measured = patch
        .statistics
        .as_ref()
        .map(|stats| super::measured::lines_with(stats, true))
        .unwrap_or_default();
    if !measured.is_empty() {
        lines.push(String::new());
        lines.push("Measured by Socket:".to_string());
        lines.extend(measured.iter().map(|line| format!("  {line}")));
    }

    let (added, removed) = files
        .iter()
        .filter_map(|f| f.diff.as_ref().ok())
        .fold((0, 0), |(a, r), d| (a + d.added, r + d.removed));
    lines.push(String::new());
    lines.push(format!(
        "{} changed: {} {}",
        plural(files.len(), "file", "files"),
        ui::paint(&format!("+{added}"), "32", color),
        ui::paint(&format!("-{removed}"), "31", color),
    ));
    let path_w = files
        .iter()
        .map(|f| f.path.chars().count())
        .max()
        .unwrap_or(0);
    for file in files {
        lines.push(format!(
            "  {}  {}",
            ui::pad(&file.path, path_w),
            change_label(file, color)
        ));
    }
    lines
}

/// The diff of one file as text: its lines, or why there is none.
fn diff_text(file: &ShownFile) -> String {
    match &file.diff {
        Ok(diff) => diff.lines.join("\n"),
        Err(why) => format!(
            "--- a/{}\n+++ b/{}\nNo diff: {why} (before {}, after {}).",
            file.path, file.path, file.before_hash, file.after_hash
        ),
    }
}

/// The patch service as one run reads patches from it: the run's own
/// client and, for a read the service refuses that client's token (401 /
/// 403), the public service, which has the free patches. The public
/// client is built once, on the first refusal.
pub(crate) struct Source {
    client: ApiClient,
    overrides: ApiClientEnvOverrides,
    public: std::sync::OnceLock<ApiClient>,
}

impl Source {
    pub(crate) fn new(client: ApiClient, overrides: ApiClientEnvOverrides) -> Source {
        Source {
            client,
            overrides,
            public: std::sync::OnceLock::new(),
        }
    }

    /// The run's own client.
    pub(crate) fn client(&self) -> &ApiClient {
        &self.client
    }

    /// Ask the service with `read`: the client that answered, and its
    /// answer. A refusal the public service cannot make good (it has no
    /// such patch, or cannot be reached) stays the answer: it is the
    /// cause, and the public service's "no such patch" would hide it.
    pub(crate) async fn ask<'s, T, F, Fut>(
        &'s self,
        read: F,
    ) -> (&'s ApiClient, Result<Option<T>, ApiError>)
    where
        F: Fn(&'s ApiClient) -> Fut,
        Fut: std::future::Future<Output = Result<Option<T>, ApiError>>,
    {
        let answer = read(&self.client).await;
        let refused = matches!(&answer, Err(e) if is_fallback_candidate(e));
        if refused && !self.client.uses_public_proxy() {
            let public = self
                .public
                .get_or_init(|| build_proxy_fallback_client(&self.overrides));
            if let Ok(Some(found)) = read(public).await {
                return (public, Ok(Some(found)));
            }
        }
        (&self.client, answer)
    }
}

/// A patch as the patch service has it, with the diff of each file it
/// changes: everything `show` prints and everything the page shows.
struct Shown {
    patch: PatchResponse,
    files: Vec<ShownFile>,
}

/// Why a patch could not be read: the code `--json` reports it under, and
/// the reason as the end of a sentence (`Error: <message>`).
struct Unread {
    code: &'static str,
    message: String,
}

impl Shown {
    /// Read patch `uuid` and the content of its files from the patch
    /// service ([`Source::ask`]): the one way a patch is read, for `show`
    /// and for the page a `list` row opens. `style` colors the diff
    /// lines.
    async fn read(source: &Source, uuid: &str, style: Style) -> Result<Shown, Unread> {
        let (client, view) = source
            .ask(|client| client.fetch_patch_with_sources(uuid))
            .await;
        let patch = match view {
            Ok(Some(patch)) => patch,
            Ok(None) => {
                return Err(Unread {
                    code: "patch_not_found",
                    message: format!("no patch found with UUID {uuid}"),
                })
            }
            Err(e) => {
                let message = match &e {
                    ApiError::Forbidden(_) => format!(
                        "patch {uuid} needs a paid Socket plan, or access this token does not \
                         have ({e})"
                    ),
                    _ => e.to_string(),
                };
                return Err(Unread {
                    code: "patch_fetch_failed",
                    message,
                });
            }
        };
        let files = shown_files(client, &patch, style).await;
        Ok(Shown { patch, files })
    }

    /// The patch as a page of the full-screen browser: under the package
    /// as its title, what the patch fixes and what was measured about it
    /// (the summary), then the diff of each of `selected`, with a mark at
    /// each so the reader can step from file to file.
    fn page(&self, selected: &[&ShownFile], style: Style) -> ui::browser::Page {
        let summary = summary(&self.patch, &self.files, style);
        let title = summary.first().map(|head| ui::strip_ansi(head));
        let mut lines: Vec<String> = summary.into_iter().skip(1).collect();
        let mut marks = Vec::new();
        for file in selected {
            lines.push(String::new());
            marks.push((lines.len(), file.path.clone()));
            lines.extend(diff_text(file).lines().map(str::to_string));
        }
        ui::browser::Page {
            title: title.unwrap_or_default(),
            lines,
            marks,
        }
    }
}

/// Patch `uuid` as the page `show` opens for it, every file's diff
/// included ([`Shown::read`], [`Shown::page`]): what a row of `list`
/// opens. `Err` is why there is none, as the end of a sentence. Nothing
/// is printed: the caller has the screen.
pub(crate) async fn load_page(
    source: &Source,
    uuid: &str,
    style: Style,
) -> Result<ui::browser::Page, String> {
    let shown = Shown::read(source, uuid, style)
        .await
        .map_err(|unread| unread.message)?;
    let all: Vec<&ShownFile> = shown.files.iter().collect();
    Ok(shown.page(&all, style))
}

/// The files `--file` selects: each spec names a path of the patch, or
/// the end of one at a `/`. `Err` names the first spec that selects none.
fn select_files<'a>(
    files: &'a [ShownFile],
    specs: &[String],
) -> Result<Vec<&'a ShownFile>, String> {
    if specs.is_empty() {
        return Ok(files.iter().collect());
    }
    let matches = |path: &str, spec: &str| {
        let spec = spec.trim_start_matches("./");
        path == spec || path.ends_with(&format!("/{spec}"))
    };
    for spec in specs {
        if !files.iter().any(|f| matches(&f.path, spec)) {
            return Err(format!(
                "`{spec}` is not a file of this patch; it changes: {}",
                files
                    .iter()
                    .map(|f| f.path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    Ok(files
        .iter()
        .filter(|f| specs.iter().any(|spec| matches(&f.path, spec)))
        .collect())
}

/// One line of the patch menu: `8be53d06  pkg:npm/undici@8.10.0  HIGH
/// CVE-2026-84961, CVE-2026-85024`.
fn candidate_label(patch: &PatchSearchResult) -> String {
    let (severity, ids) = ui::worst_and_ids(
        patch
            .vulnerabilities
            .iter()
            .map(|(id, vuln)| (id.as_str(), vuln.severity.as_str(), vuln.cves.as_slice())),
    );
    format!(
        "{}  {}  {severity}  {}",
        ui::short_uuid(&patch.uuid),
        normalize_purl(&patch.purl),
        ids.join(", ")
    )
}

/// The patches `target` names, best first: an advisory's or a purl's by
/// search, a name's by searching each installed package it matches.
async fn candidates(
    args: &ShowArgs,
    target: &Target,
    client: &ApiClient,
) -> Result<Vec<PatchSearchResult>, String> {
    let searched = match target.kind() {
        TargetKind::Cve => client.search_patches_by_cve(target.as_str()).await,
        TargetKind::Ghsa => client.search_patches_by_ghsa(target.as_str()).await,
        TargetKind::Purl => client.search_patches_by_package(target.as_str()).await,
        TargetKind::Uuid | TargetKind::Name => {
            let only = args.common.ecosystems.as_deref().filter(|l| !l.is_empty());
            let (packages, _, _) = crawl_ecosystems(&args.common.crawler_options(), only).await;
            let matched = installed_target_matches(target, &packages);
            if matched.is_empty() {
                return Err(format!(
                    "no installed package is named `{target}`; pass a PURL (pkg:npm/{target}@1.2.3) \
                     or a patch UUID"
                ));
            }
            if matched.len() > MAX_NAME_MATCHES {
                return Err(format!(
                    "`{target}` names {} installed packages; pass the PURL of one",
                    matched.len()
                ));
            }
            let mut patches = Vec::new();
            for purl in &matched {
                match client.search_patches_by_package(purl).await {
                    Ok(found) => patches.extend(found.patches),
                    Err(e) => return Err(e.to_string()),
                }
            }
            patches.sort_by(cmp_search_results);
            return Ok(patches);
        }
    };
    searched
        .map(|found| found.patches)
        .map_err(|e| e.to_string())
}

pub async fn run(args: ShowArgs) -> i32 {
    apply_env_toggles(&args.common);
    let common = &args.common;
    if common.offline {
        return fail(
            common,
            "offline_unsupported",
            "show reads the patch from the patch service and cannot run with \
             --offline/SOCKET_OFFLINE",
        );
    }
    let target = Target::parse(&args.identifier);
    let overrides = common.api_client_overrides();
    let (mut client, _) = get_api_client_with_overrides(overrides.clone()).await;
    let mut status = ui::StatusLine::stderr(common.json, common.silent);

    // Which patch: the UUID given, or the pick among the ones found.
    let uuid = if target.kind() == TargetKind::Uuid {
        args.identifier.clone()
    } else {
        status.set(format!("Finding patches for {target}..."));
        let mut found = candidates(&args, &target, &client).await;
        if let (Err(_), false) = (&found, client.uses_public_proxy()) {
            // A refused token still reaches the free patches.
            let proxy = build_proxy_fallback_client(&overrides);
            if let Ok(free) = candidates(&args, &target, &proxy).await {
                (client, found) = (proxy, Ok(free));
            }
        }
        status.finish();
        let found = match found {
            Ok(found) => found,
            Err(message) => return fail(common, "patch_lookup_failed", &message),
        };
        match found.as_slice() {
            [] => {
                return fail(
                    common,
                    "no_patches",
                    &format!("no patches found for {} {target}", target.kind()),
                )
            }
            [only] => only.uuid.clone(),
            many => {
                let menu = !common.json
                    && !common.silent
                    && !common.yes
                    && std::io::stdin().is_terminal()
                    && std::io::stderr().is_terminal();
                let labels: Vec<String> = many.iter().map(candidate_label).collect();
                if menu {
                    match select_one("Which patch?", &labels, common) {
                        Ok(picked) => many[picked].uuid.clone(),
                        Err(_) => return 0,
                    }
                } else {
                    if !common.json && !common.silent {
                        eprintln!(
                            "{} match {target}; showing the best ranked. The others:",
                            plural(many.len(), "patch", "patches")
                        );
                        for label in &labels[1..] {
                            eprintln!("  {label}");
                        }
                    }
                    many[0].uuid.clone()
                }
            }
        }
    };

    status.set(format!("Reading patch {}...", ui::short_uuid(&uuid)));
    let style = if common.json {
        Style::PLAIN
    } else {
        Style::stdout()
    };
    let source = Source::new(client, overrides);
    let shown = Shown::read(&source, &uuid, style).await;
    status.finish();
    let shown = match shown {
        Ok(shown) => shown,
        Err(unread) => return fail(common, unread.code, &unread.message),
    };
    let (patch, files) = (&shown.patch, &shown.files);

    if common.json {
        ui::print_json(&serde_json::json!({
            "command": "show",
            "status": "success",
            "patch": {
                "uuid": patch.uuid,
                "purl": patch.purl,
                "tier": patch.tier,
                "publishedAt": patch.published_at,
                "license": patch.license,
                "description": patch.description,
                "vulnerabilities": patch.vulnerabilities,
                "statistics": patch.statistics,
                "files": files.iter().map(|file| serde_json::json!({
                    "path": file.path,
                    "beforeHash": file.before_hash,
                    "afterHash": file.after_hash,
                    "added": file.diff.as_ref().ok().map(|d| d.added),
                    "removed": file.diff.as_ref().ok().map(|d| d.removed),
                    "binary": file.diff.as_ref().is_ok_and(|d| d.binary),
                })).collect::<Vec<_>>(),
            },
        }));
        return 0;
    }
    if common.silent {
        return 0;
    }

    let selected = match select_files(files, &args.files) {
        Ok(selected) => selected,
        Err(message) => return fail(common, "file_not_in_patch", &message),
    };
    // Someone at a terminal reads the patch on the page a row of `list`
    // opens: the summary and every selected diff, which scrolls, steps
    // from file to file and follows the terminal's size. Where there is
    // no such screen (a pipe, `--no-pager`, `--yes`, a terminal that
    // shows no escape sequences or cannot be set up), the same text
    // prints below.
    let reads =
        !args.stat && !args.no_pager && !common.yes && !selected.is_empty() && ui::full_screen();
    let read = reads && ui::browser::read(shown.page(&selected, style));
    // The summary is what stays on the terminal either way.
    for line in summary(patch, files, style) {
        println!("{line}");
    }
    if args.stat || selected.is_empty() || read {
        return 0;
    }
    println!();
    for file in &selected {
        println!("{}", diff_text(file));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::measured::tests::stats;
    use socket_patch_core::api::types::VulnerabilityResponse;
    use std::collections::HashMap;

    fn file(path: &str, before: Option<&str>, after: &str) -> ShownFile {
        ShownFile {
            path: path.to_string(),
            before_hash: "b".repeat(64),
            after_hash: "a".repeat(64),
            diff: Ok(file_diff(
                path,
                before.map(str::as_bytes),
                after.as_bytes(),
                Style::PLAIN,
            )),
        }
    }

    fn patch() -> PatchResponse {
        let vuln = |cves: &[&str], severity: &str, summary: &str| VulnerabilityResponse {
            cves: cves.iter().map(|c| c.to_string()).collect(),
            summary: summary.to_string(),
            severity: severity.to_string(),
            description: String::new(),
        };
        PatchResponse {
            uuid: "8be53d06-7bd4-40cc-ab8f-36dc6248985a".to_string(),
            purl: "pkg:npm/%40scope/undici@8.10.0".to_string(),
            published_at: "Mon, 03 Aug 2026 19:12:42 GMT".to_string(),
            files: HashMap::new(),
            vulnerabilities: [
                (
                    "GHSA-b".to_string(),
                    vuln(&["CVE-2026-85024"], "MODERATE", "DoS in WebSocket"),
                ),
                (
                    "GHSA-a".to_string(),
                    vuln(&["CVE-2026-84961"], "HIGH", "TLS validation bypass"),
                ),
                ("GHSA-c".to_string(), vuln(&[], "low", "")),
            ]
            .into(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "paid".to_string(),
            statistics: Some(stats(2, 35, 35)),
        }
    }

    #[test]
    fn summary_names_the_patch_its_fixes_measurements_and_files() {
        let files = vec![
            file("lib/a.js", Some("one\ntwo\n"), "one\nTWO\nthree\n"),
            file("lib/new.js", None, "x\n"),
            ShownFile {
                path: "big.bin".to_string(),
                before_hash: String::new(),
                after_hash: String::new(),
                diff: Err("the file is too large to diff".to_string()),
            },
        ];
        assert_eq!(
            summary(&patch(), &files, Style::PLAIN),
            vec![
                "pkg:npm/@scope/undici@8.10.0  HIGH  [PAID]",
                "Patch 8be53d06-7bd4-40cc-ab8f-36dc6248985a, published 03 Aug 2026, MIT",
                "",
                "Fixes:",
                "  HIGH      CVE-2026-84961  TLS validation bypass",
                "  MODERATE  CVE-2026-85024  DoS in WebSocket",
                "  LOW       GHSA-c",
                "",
                "Measured by Socket:",
                "  Verified: 2 of 2 exploits blocked, 35 of 35 tests passing",
                "",
                "3 files changed: +3 -1",
                "  lib/a.js    +2 -1",
                "  lib/new.js  +1 -0",
                "  big.bin     (the file is too large to diff)",
            ]
        );
        // An advisory that names no severity leaves none in the title:
        // the same rule as the row of `list` this page opens from.
        let blank = PatchResponse {
            vulnerabilities: [(
                "GHSA-c".to_string(),
                VulnerabilityResponse {
                    cves: Vec::new(),
                    summary: String::new(),
                    severity: " ".to_string(),
                    description: String::new(),
                },
            )]
            .into(),
            ..patch()
        };
        assert_eq!(
            summary(&blank, &files[..1], Style::PLAIN)[0],
            "pkg:npm/@scope/undici@8.10.0  [PAID]"
        );
        // No advisories, no measurements: those sections are left out.
        let bare = PatchResponse {
            vulnerabilities: HashMap::new(),
            statistics: None,
            published_at: String::new(),
            license: String::new(),
            ..patch()
        };
        assert_eq!(
            summary(&bare, &files[..1], Style::PLAIN),
            vec![
                "pkg:npm/@scope/undici@8.10.0  [PAID]",
                "Patch 8be53d06-7bd4-40cc-ab8f-36dc6248985a",
                "",
                "1 file changed: +2 -1",
                "  lib/a.js  +2 -1",
            ]
        );
    }

    #[test]
    fn file_specs_select_by_path_or_its_end() {
        let files = vec![
            file("lib/a.js", Some("a\n"), "b\n"),
            file("lib/web/a.js", Some("a\n"), "b\n"),
            file("README.md", Some("a\n"), "b\n"),
        ];
        let paths = |specs: &[&str]| {
            let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
            select_files(&files, &specs)
                .map(|fs| fs.iter().map(|f| f.path.clone()).collect::<Vec<_>>())
        };
        assert_eq!(paths(&[]).unwrap().len(), 3);
        assert_eq!(paths(&["README.md"]).unwrap(), ["README.md"]);
        assert_eq!(paths(&["./lib/a.js"]).unwrap(), ["lib/a.js"]);
        // The end of a path, at a `/`: both `a.js`, never `xa.js`.
        assert_eq!(paths(&["a.js"]).unwrap(), ["lib/a.js", "lib/web/a.js"]);
        assert_eq!(paths(&["web/a.js", "README.md"]).unwrap().len(), 2);
        let err = paths(&["b.js"]).unwrap_err();
        assert!(
            err.starts_with("`b.js` is not a file of this patch; it changes: lib/a.js, "),
            "{err}"
        );
        assert!(paths(&["js"]).is_err());
    }

    #[test]
    fn diff_text_says_why_a_file_has_no_diff() {
        let unread = ShownFile {
            path: "lib/a.js".to_string(),
            before_hash: "bb".to_string(),
            after_hash: "aa".to_string(),
            diff: Err("the file is too large to diff".to_string()),
        };
        assert_eq!(
            diff_text(&unread),
            "--- a/lib/a.js\n+++ b/lib/a.js\nNo diff: the file is too large to diff \
             (before bb, after aa)."
        );
        assert_eq!(
            diff_text(&file("f", Some("a\n"), "b\n")),
            "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-a\n+b"
        );
    }

    #[test]
    fn short_date_reads_both_timestamp_shapes() {
        assert_eq!(short_date("Fri, 27 Mar 2026 19:12:42 GMT"), "27 Mar 2026");
        assert_eq!(short_date("2024-01-01T00:00:00Z"), "2024-01-01");
        assert_eq!(short_date("yesterday"), "yesterday");
    }

    #[test]
    fn candidate_label_names_the_patch_in_one_line() {
        let found = PatchSearchResult {
            uuid: "8be53d06-7bd4-40cc-ab8f-36dc6248985a".to_string(),
            purl: "pkg:npm/undici@8.10.0".to_string(),
            published_at: String::new(),
            description: String::new(),
            license: String::new(),
            tier: "paid".to_string(),
            vulnerabilities: patch().vulnerabilities,
        };
        assert_eq!(
            candidate_label(&found),
            "8be53d06  pkg:npm/undici@8.10.0  HIGH  CVE-2026-84961, CVE-2026-85024, GHSA-c"
        );
    }
}
