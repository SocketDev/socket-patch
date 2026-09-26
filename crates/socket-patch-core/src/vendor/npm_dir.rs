//! Directory artifacts for the vlt backend (DESIGN §4.2–§4.4).
//!
//! vlt installs a `file:` directory dependency by linking it, so the vendored
//! artifact is the patched package directory itself, laid out as
//! `.socket/vendor/npm/<uuid>/[@s/]<bare>-<version>/node_modules/<name>/`:
//! Node resolves a package's `require('<own name>')` by walking up from its
//! realpath, and only a `node_modules/<name>` ancestor makes that work for
//! root, workspace-member and alias edges alike. The `<bare>-<version>`
//! level keeps the version in the path, because a committed `file` node
//! records none. vlt writes the dependency links under the package's own
//! `node_modules/`, which socket-patch never inventories, reads or creates.
//!
//! `<uuid>/.gitignore` re-includes the payload against the user's ignores
//! (JS repos routinely ignore `dist/`, `lib/` and `*.map`, exactly what
//! packages publish) while keeping vlt's links out, and `<uuid>/.gitattributes`
//! stops EOL conversion from rewriting the payload on a Windows checkout.
//!
//! Two deterministic transforms run on every tree, service-built or local:
//! the top-level `devDependencies` member is cut out of `package.json` (vlt
//! installs a `file` node's devDependencies), and nothing else changes. The
//! verifiers then apply the vlt manifest exemption ([`super::verify`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::utils::fs::atomic_write_bytes;

use super::common::{already_patched_result, refused, service_offline_conflict};
use super::npm_common::{
    declares_bundled_deps, done_failure, done_failure_unstage, guard_coordinates,
};
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::VENDOR_MARKER_FILE;
use super::vlt_lock_text::vendored_dir_rel;
use super::{VendorOutcome, VendorServiceConfig, VendorWarning};

/// `<uuid>/.gitignore`, exactly.
pub(crate) const UUID_GITIGNORE: &str =
    "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n";
/// `<uuid>/.gitattributes`, exactly.
pub(crate) const UUID_GITATTRIBUTES: &str = "* -text\n";

const GITIGNORE: &str = ".gitignore";
const GITATTRIBUTES: &str = ".gitattributes";
const NODE_MODULES: &str = "node_modules";

/// The staged directory artifact the vlt wiring consumes.
pub(super) struct NpmStagedDir {
    /// `.socket/vendor/npm/<uuid>/<leaf>/node_modules/<name>`.
    pub rel_dir: String,
    /// Every regular file under `rel_dir` but its `node_modules/`.
    pub inventory: BTreeMap<String, String>,
    /// The uuid dir existed before this run wrote into it.
    pub uuid_dir_preexisted: bool,
    /// The patched manifest, when the patch rewrote `package.json`.
    pub staged_pkg_json: Option<Value>,
    /// The committed dir passed the reuse check; nothing was written.
    pub reused: bool,
    /// A rebuild discarded the old dir's `node_modules/` (it held more
    /// than vlt's links), so the package needs `vlt install` to re-link.
    pub links_dropped: bool,
}

// ── package.json spans ───────────────────────────────────────────────────

/// One member of a JSON object: its decoded key and byte offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonMember {
    pub(crate) key: String,
    pub(crate) key_start: usize,
    pub(crate) value_start: usize,
    pub(crate) value_end: usize,
    /// The comma right after the value, when one follows.
    pub(crate) comma: Option<usize>,
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// The index just past the string token starting at `i`.
fn scan_string(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// The index just past the value starting at `i`.
fn scan_value(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => scan_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = scan_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The members of the object whose `{` is at `open`.
fn object_members(text: &str, open: usize) -> Option<Vec<JsonMember>> {
    let b = text.as_bytes();
    if b.get(open) != Some(&b'{') {
        return None;
    }
    let mut members = Vec::new();
    let mut i = skip_ws(b, open + 1);
    if b.get(i) == Some(&b'}') {
        return Some(members);
    }
    loop {
        let key_start = i;
        let key_end = scan_string(b, key_start)?;
        let key: String = serde_json::from_str(&text[key_start..key_end]).ok()?;
        i = skip_ws(b, key_end);
        if b.get(i) != Some(&b':') {
            return None;
        }
        let value_start = skip_ws(b, i + 1);
        let value_end = scan_value(b, value_start)?;
        i = skip_ws(b, value_end);
        let comma = (b.get(i) == Some(&b',')).then_some(i);
        members.push(JsonMember {
            key,
            key_start,
            value_start,
            value_end,
            comma,
        });
        match b.get(i)? {
            b',' => i = skip_ws(b, i + 1),
            b'}' => return Some(members),
            _ => return None,
        }
    }
}

/// The top-level members of a JSON object document (a leading BOM is kept
/// out of the offsets' way, never stripped from the text).
pub(crate) fn root_members(text: &str) -> Option<Vec<JsonMember>> {
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    serde_json::from_str::<serde_json::Map<String, Value>>(body).ok()?;
    let open = skip_ws(text.as_bytes(), text.len() - body.len());
    object_members(text, open)
}

/// The one member named `key`; `Err` when it appears more than once.
fn unique_member<'m>(members: &'m [JsonMember], key: &str) -> Result<Option<&'m JsonMember>, ()> {
    let mut found = members.iter().filter(|m| m.key == key);
    let first = found.next();
    if found.next().is_some() {
        return Err(());
    }
    Ok(first)
}

/// Why a package.json span edit could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SpanError {
    NotJson,
    Duplicate(String),
    Missing,
    NotString,
}

/// DESIGN §4.4: `package.json` with its top-level `devDependencies` member
/// cut out as a byte span (key, colon, value and the whitespace between
/// them, plus the following comma and the run up to the next token, else
/// the preceding comma). `Ok(None)` when the member is absent.
pub(crate) fn strip_dev_dependencies(text: &str) -> Result<Option<String>, SpanError> {
    let members = root_members(text).ok_or(SpanError::NotJson)?;
    let member = match unique_member(&members, "devDependencies") {
        Ok(Some(member)) => member,
        Ok(None) => return Ok(None),
        Err(()) => return Err(SpanError::Duplicate("devDependencies".into())),
    };
    let index = members.iter().position(|m| m == member).unwrap_or_default();
    let (start, end) = match member.comma {
        Some(comma) => (
            member.key_start,
            skip_ws(text.as_bytes(), comma + 1).min(
                members
                    .get(index + 1)
                    .map_or(text.len(), |next| next.key_start),
            ),
        ),
        None => match index.checked_sub(1).and_then(|i| members[i].comma) {
            Some(prev_comma) => (prev_comma, member.value_end),
            None => (member.key_start, member.value_end),
        },
    };
    Ok(Some(format!("{}{}", &text[..start], &text[end..])))
}

/// The raw string token at `[field][name]` of a package.json and its byte
/// span.
fn dependency_span(text: &str, field: &str, name: &str) -> Result<(usize, usize), SpanError> {
    let members = root_members(text).ok_or(SpanError::NotJson)?;
    let table = unique_member(&members, field)
        .map_err(|()| SpanError::Duplicate(field.into()))?
        .ok_or(SpanError::Missing)?;
    let inner = object_members(text, table.value_start).ok_or(SpanError::Missing)?;
    let dep = unique_member(&inner, name)
        .map_err(|()| SpanError::Duplicate(format!("{field}.{name}")))?
        .ok_or(SpanError::Missing)?;
    if text.as_bytes()[dep.value_start] != b'"' {
        return Err(SpanError::NotString);
    }
    Ok((dep.value_start, dep.value_end))
}

/// The raw JSON token of `[field][name]` (quotes included).
pub(crate) fn dependency_token(text: &str, field: &str, name: &str) -> Result<String, SpanError> {
    let (start, end) = dependency_span(text, field, name)?;
    Ok(text[start..end].to_string())
}

/// `text` with the string token at `[field][name]` replaced by `raw` (a JSON
/// string token), nothing else re-serialized.
pub(crate) fn replace_dependency_token(
    text: &str,
    field: &str,
    name: &str,
    raw: &str,
) -> Result<String, SpanError> {
    let (start, end) = dependency_span(text, field, name)?;
    Ok(format!("{}{raw}{}", &text[..start], &text[end..]))
}

/// The §4.4 transform on a staged tree's `package.json`. A refusal is the
/// ready outcome.
async fn apply_transforms(
    stage: &Path,
    name: &str,
    version: &str,
) -> Result<(), Box<VendorOutcome>> {
    let path = stage.join("package.json");
    let Ok(text) = crate::utils::fs::read_regular_to_string(&path).await else {
        return Ok(());
    };
    match strip_dev_dependencies(&text) {
        Ok(None) => Ok(()),
        Ok(Some(stripped)) => tokio::fs::write(&path, stripped).await.map_err(|e| {
            Box::new(done_failure(
                &format!("pkg:npm/{name}@{version}"),
                format!("cannot write the staged package.json: {e}"),
            ))
        }),
        Err(SpanError::Duplicate(_)) => Err(Box::new(refused(
            "vendor_lock_entry_unsupported",
            format!("{name}@{version}'s package.json declares duplicate devDependencies"),
        ))),
        Err(_) => Err(Box::new(refused(
            "vendor_lock_entry_unsupported",
            format!("{name}@{version}'s package.json is not a JSON object"),
        ))),
    }
}

// ── tree checks ──────────────────────────────────────────────────────────

/// DESIGN §4.2 structure rule: `<uuid>/<leaf>/node_modules/` holds exactly
/// the package dir (for a scoped name, exactly `@scope/` holding exactly
/// `<bare>`). `rel_abs` is the package dir.
pub(crate) async fn structure_rule_holds(rel_abs: &Path, name: &str) -> bool {
    let levels: Vec<&str> = name.split('/').collect();
    let mut dir = rel_abs.to_path_buf();
    for _ in &levels {
        dir.pop();
    }
    for level in levels {
        let entries = crate::utils::fs::list_dir_entries(&dir).await;
        if entries.len() != 1 || entries[0].file_name().to_str() != Some(level) {
            return false;
        }
        match tokio::fs::symlink_metadata(entries[0].path()).await {
            Ok(meta) if meta.is_dir() => {}
            _ => return false,
        }
        dir.push(level);
    }
    true
}

/// vlt's `node_modules/` inside the package dir holds only links, dirs and
/// `.bin/` scripts; anything else there was planted.
pub(crate) async fn node_modules_holds_only_links(rel_abs: &Path) -> bool {
    let root = rel_abs.join(NODE_MODULES);
    tokio::task::spawn_blocking(move || {
        let Ok(meta) = std::fs::symlink_metadata(&root) else {
            return true;
        };
        if !meta.is_dir() {
            return false;
        }
        let mut stack = vec![(root.clone(), false)];
        while let Some((dir, in_bin)) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    return false;
                };
                let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                    return false;
                };
                let ty = meta.file_type();
                if ty.is_symlink() {
                    continue;
                }
                if ty.is_dir() {
                    let bin = in_bin || (dir == root && entry.file_name() == ".bin");
                    stack.push((entry.path(), bin));
                    continue;
                }
                if !(ty.is_file() && in_bin) {
                    return false;
                }
            }
        }
        true
    })
    .await
    .unwrap_or(false)
}

/// Rewrite `<uuid>/.gitignore` and `<uuid>/.gitattributes` when absent or
/// different; neither is part of the artifact.
pub(crate) async fn restore_uuid_metadata(uuid_dir: &Path) -> std::io::Result<()> {
    for (name, want) in [
        (GITIGNORE, UUID_GITIGNORE),
        (GITATTRIBUTES, UUID_GITATTRIBUTES),
    ] {
        let path = uuid_dir.join(name);
        let current = crate::utils::fs::read_regular_to_bytes(&path).await.ok();
        if current.as_deref() != Some(want.as_bytes()) {
            atomic_write_bytes(&path, want.as_bytes()).await?;
        }
    }
    Ok(())
}

// ── gitignore probe ──────────────────────────────────────────────────────

async fn git_output(
    git: &Path,
    root: &Path,
    args: &[&str],
    stdin: Option<String>,
) -> Option<(i32, String)> {
    use tokio::io::AsyncWriteExt as _;
    let mut child = tokio::process::Command::new(git)
        .arg("-C")
        .arg(root)
        .args(args)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes()).await.ok()?;
    }
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
        .await
        .ok()?
        .ok()?;
    Some((
        output.status.code()?,
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

/// DESIGN §4.2 probe: `git check-ignore -v --no-index` over `paths`
/// (project-relative). `Some(rules)` names what ignores them; `None` when
/// nothing is ignored, git is absent or the root is not a work tree.
pub(crate) async fn gitignored(project_root: &Path, paths: &[String]) -> Option<String> {
    let git = crate::utils::process::resolve_tool("git")?;
    let (_, inside) = git_output(
        &git,
        project_root,
        &["rev-parse", "--is-inside-work-tree"],
        None,
    )
    .await?;
    if inside.trim() != "true" {
        return None;
    }
    let input: String = paths.iter().map(|p| format!("{p}\0")).collect();
    let (code, out) = git_output(
        &git,
        project_root,
        &["check-ignore", "-v", "-z", "--no-index", "--stdin"],
        Some(input),
    )
    .await?;
    let lines = ignoring_rules(&out);
    (code == 0 && !lines.is_empty()).then(|| {
        let shown: Vec<&str> = lines.iter().take(3).map(String::as_str).collect();
        let more = lines.len().saturating_sub(shown.len());
        let mut detail = shown.join("; ");
        if more > 0 {
            detail.push_str(&format!("; and {more} more"));
        }
        detail
    })
}

/// The non-negated matches of `git check-ignore -v -z` output
/// (`<source> NUL <linenum> NUL <pattern> NUL <pathname> NUL` per path), as
/// `<source>:<linenum>:<pattern>\t<pathname>`. A source may hold a colon
/// (a Windows drive letter), so the fields are split on NUL only.
fn ignoring_rules(out: &str) -> Vec<String> {
    let fields: Vec<&str> = out.split('\0').collect();
    fields
        .chunks_exact(4)
        .filter(|f| !f[2].is_empty() && !f[2].starts_with('!'))
        .map(|f| format!("{}:{}:{}\t{}", f[0], f[1], f[2], f[3]))
        .collect()
}

fn gitignored_refusal(rel_dir: &str, rules: &str) -> VendorOutcome {
    refused(GITIGNORED, gitignored_detail(rel_dir, rules))
}

pub(crate) const GITIGNORED: &str = "vendor_artifact_gitignored";

pub(crate) fn gitignored_detail(rel: &str, rules: &str) -> String {
    format!(
        "git would not commit the vendored artifact at {rel} ({rules}); remove the rule that \
         ignores .socket/ (or .socket/vendor/) and vendor again"
    )
}

// ── pipeline ─────────────────────────────────────────────────────────────

/// DESIGN §4.3: reuse the committed dir, else build it from the patch
/// service or the installed copy, then write it into place. Same result
/// shape as [`super::npm_common::stage_patch_pack`]: `Err` is a refusal or
/// a failure with the project untouched, `Ok((None, _))` a failed patch or
/// a dry run, `Ok((Some(dir), _))` the artifact on disk.
#[allow(clippy::too_many_arguments)]
pub(super) async fn stage_patch_dir(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
    service: Option<&VendorServiceConfig>,
) -> Result<(Option<NpmStagedDir>, ApplyResult), Box<VendorOutcome>> {
    let coords = guard_coordinates(purl, record)?;
    let rel_dir = vendored_dir_rel(&record.uuid, &coords.name, &coords.version);
    let uuid_dir = project_root.join(&coords.uuid_dir_rel);
    let rel_abs = project_root.join(&rel_dir);
    let touches_manifest = record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json");

    let mut reusable = false;
    match super::reuse::reusable_committed_dir(project_root, record, &rel_dir).await {
        Ok(inventory) => {
            if !dry_run {
                if let Err(e) = restore_uuid_metadata(&uuid_dir).await {
                    return Err(Box::new(done_failure(
                        purl,
                        format!("cannot restore {}/.gitignore: {e}", coords.uuid_dir_rel),
                    )));
                }
                let staged_pkg_json = if touches_manifest {
                    read_manifest(&rel_abs).await.ok()
                } else {
                    None
                };
                let result = already_patched_result(purl, &rel_abs, &record.files);
                return Ok((
                    Some(NpmStagedDir {
                        rel_dir,
                        inventory,
                        uuid_dir_preexisted: true,
                        staged_pkg_json,
                        reused: true,
                        links_dropped: false,
                    }),
                    result,
                ));
            }
            reusable = true;
        }
        Err(miss) => super::reuse::log_miss(purl, &miss),
    }

    if let Some(refusal) = service_offline_conflict(service).filter(|_| !reusable) {
        return Err(Box::new(refusal));
    }

    let stage_tmp = tempfile::tempdir().map_err(|e| {
        Box::new(done_failure(
            purl,
            format!("cannot create staging tempdir: {e}"),
        ))
    })?;
    let stage = stage_tmp.path().join("stage");
    let mut result = None;
    if let Some(cfg) = service.filter(|cfg| cfg.service_enabled() && !dry_run) {
        match try_service_dir(
            purl,
            record,
            cfg,
            &stage,
            &coords.name,
            &coords.version,
            warnings,
        )
        .await
        {
            ServiceDir::Used => {
                result = Some(already_patched_result(purl, &rel_abs, &record.files));
            }
            ServiceDir::HardFail(outcome) => return Err(outcome),
            ServiceDir::FallBack => {}
        }
    }
    let result = match result {
        Some(result) => {
            prune_staged_node_modules(purl, &stage, &coords.name, &coords.version).await?;
            apply_transforms(&stage, &coords.name, &coords.version).await?;
            result
        }
        None => {
            if let Err(e) = fresh_copy(installed_dir, &stage, None).await {
                return Err(Box::new(done_failure(
                    purl,
                    format!("cannot stage a copy of the installed package: {e}"),
                )));
            }
            prune_staged_node_modules(purl, &stage, &coords.name, &coords.version).await?;
            let result = super::force_apply_staged(
                purl,
                &stage,
                record,
                sources,
                dry_run,
                force,
                &coords.name,
                &coords.version,
                warnings,
            )
            .await;
            if !result.success {
                return Ok((None, result));
            }
            apply_transforms(&stage, &coords.name, &coords.version).await?;
            result
        }
    };
    if dry_run {
        return Ok((None, result));
    }

    let uuid_dir_preexisted = tokio::fs::metadata(&uuid_dir).await.is_ok();
    let unstage = |error: String| {
        done_failure_unstage(
            purl,
            error,
            project_root,
            &coords.uuid_dir_rel,
            uuid_dir_preexisted,
        )
    };
    let links_dropped = match write_into_place(&stage, &uuid_dir, &rel_abs, &coords.name).await {
        Ok(dropped) => dropped,
        Err(e) => {
            return Err(Box::new(
                unstage(format!("cannot write {rel_dir}: {e}")).await,
            ))
        }
    };
    if let Err(e) = restore_uuid_metadata(&uuid_dir).await {
        return Err(Box::new(
            unstage(format!(
                "cannot write {}/.gitignore: {e}",
                coords.uuid_dir_rel
            ))
            .await,
        ));
    }
    let inventory = match super::verify::compute_package_dir_inventory(&rel_abs).await {
        Ok(inventory) => inventory,
        Err(e) => {
            return Err(Box::new(
                unstage(format!("cannot inventory {rel_dir}: {e}")).await,
            ))
        }
    };
    let mut probe: Vec<String> = inventory.keys().map(|k| format!("{rel_dir}/{k}")).collect();
    for name in [VENDOR_MARKER_FILE, GITIGNORE, GITATTRIBUTES] {
        probe.push(format!("{}/{name}", coords.uuid_dir_rel));
    }
    if let Some(rules) = gitignored(project_root, &probe).await {
        let _ = unstage(String::new()).await;
        return Err(Box::new(gitignored_refusal(&rel_dir, &rules)));
    }
    let staged_pkg_json = if touches_manifest {
        match read_manifest(&rel_abs).await {
            Ok(pkg) => Some(pkg),
            Err(e) => return Err(Box::new(unstage(e).await)),
        }
    } else {
        None
    };
    Ok((
        Some(NpmStagedDir {
            rel_dir,
            inventory,
            uuid_dir_preexisted,
            staged_pkg_json,
            reused: false,
            links_dropped,
        }),
        result,
    ))
}

/// DESIGN §4.3 step 5 on any staged tree: prune its `node_modules/` and
/// refuse a package that bundles dependencies.
async fn prune_staged_node_modules(
    purl: &str,
    stage: &Path,
    name: &str,
    version: &str,
) -> Result<(), Box<VendorOutcome>> {
    if let Err(e) = remove_tree(&stage.join(NODE_MODULES)).await {
        return Err(Box::new(done_failure(
            purl,
            format!("cannot prune staged node_modules: {e}"),
        )));
    }
    if let Ok(pkg) = read_manifest(stage).await {
        if declares_bundled_deps(&pkg) {
            return Err(Box::new(refused(
                "vendor_bundled_deps_unsupported",
                format!(
                    "{name}@{version} declares bundleDependencies; vendoring would drop its \
                     bundled node_modules and break installs"
                ),
            )));
        }
    }
    Ok(())
}

async fn read_manifest(dir: &Path) -> Result<Value, String> {
    let text = crate::utils::fs::read_regular_to_string(&dir.join("package.json"))
        .await
        .map_err(|e| format!("package.json unreadable: {e}"))?;
    serde_json::from_str(crate::package_json::detect::strip_bom(&text))
        .map_err(|e| format!("package.json is not parseable JSON: {e}"))
}

/// Build the whole `<leaf>` level in `<uuid>/.tmp-*` and rename it over
/// the old one, so nothing but the package dir survives beside it. The old
/// dir's `node_modules/` moves along when it holds only vlt's links;
/// `Ok(true)` when it held anything else and was discarded.
async fn write_into_place(
    stage: &Path,
    uuid_dir: &Path,
    rel_abs: &Path,
    name: &str,
) -> std::io::Result<bool> {
    let mut leaf_abs = rel_abs.to_path_buf();
    for _ in name.split('/') {
        leaf_abs.pop();
    }
    leaf_abs.pop();
    let parent: PathBuf = leaf_abs
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("artifact path has no parent"))?;
    tokio::fs::create_dir_all(uuid_dir).await?;
    tokio::fs::create_dir_all(&parent).await?;
    let tmp = tempfile::Builder::new()
        .prefix(".tmp-")
        .tempdir_in(uuid_dir)?
        .keep();
    let tmp_pkg = tmp.join(NODE_MODULES).join(name);
    if let Err(e) = fresh_copy(stage, &tmp_pkg, None).await {
        let _ = remove_tree(&tmp).await;
        return Err(e);
    }
    let old_links = rel_abs.join(NODE_MODULES);
    let mut dropped = false;
    if tokio::fs::symlink_metadata(&old_links).await.is_ok() {
        if node_modules_holds_only_links(rel_abs).await {
            if let Err(e) = tokio::fs::rename(&old_links, tmp_pkg.join(NODE_MODULES)).await {
                let _ = remove_tree(&tmp).await;
                return Err(e);
            }
        } else {
            dropped = true;
        }
    }
    if tokio::fs::symlink_metadata(&leaf_abs).await.is_ok() {
        remove_tree(&leaf_abs).await?;
    }
    if let Err(e) = tokio::fs::rename(&tmp, &leaf_abs).await {
        let _ = remove_tree(&tmp).await;
        return Err(e);
    }
    Ok(dropped)
}

/// Every record file of the extracted tree hashes to its afterHash (the
/// archive check, run on the tree the first-component strip produced).
async fn tree_matches_after_hashes(stage: &Path, record: &PatchRecord) -> bool {
    for (file_name, info) in &record.files {
        let rel = normalize_file_path(file_name);
        if !crate::patch::path_safety::is_safe_multi_segment(rel) {
            return false;
        }
        let Ok(bytes) = crate::utils::fs::read_regular_to_bytes(&stage.join(rel)).await else {
            return false;
        };
        if !crate::hash::git_sha256::compute_git_sha256_from_bytes(&bytes)
            .eq_ignore_ascii_case(&info.after_hash)
        {
            return false;
        }
    }
    true
}

enum ServiceDir {
    Used,
    HardFail(Box<VendorOutcome>),
    FallBack,
}

/// The service fast path: the prebuilt tarball, integrity- and
/// afterHash-verified, extracted into `stage` with its first path component
/// stripped whatever it is called. The fallback policy is the tarball
/// backends' (`try_service_pack`).
async fn try_service_dir(
    purl: &str,
    record: &PatchRecord,
    cfg: &VendorServiceConfig,
    stage: &Path,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> ServiceDir {
    let hard_fail = |detail: String| ServiceDir::HardFail(Box::new(done_failure(purl, detail)));
    let fallback_or_fail =
        |reason: String, code: &'static str, warnings: &mut Vec<VendorWarning>| {
            if cfg.source.requires_service() {
                hard_fail(reason)
            } else {
                warnings.push(VendorWarning::new(
                    code,
                    format!("{reason}; building locally instead"),
                ));
                ServiceDir::FallBack
            }
        };
    match fetch_verified_archive(cfg, &record.uuid).await {
        ServiceArtifact::Ready(archive) => {
            let (bytes, dest) = (archive.bytes, stage.to_path_buf());
            let extracted = tokio::task::spawn_blocking(move || {
                super::registry_fetch::extract_tgz_strict(&bytes, &dest)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            if let Err(e) = extracted {
                return hard_fail(format!(
                    "prebuilt tarball for {name}@{version} is unsafe: {e}"
                ));
            }
            if !tree_matches_after_hashes(stage, record).await {
                let _ = remove_tree(stage).await;
                return fallback_or_fail(
                    format!(
                        "prebuilt tarball for {name}@{version} does not carry the patched files \
                         at their recorded paths"
                    ),
                    "vendor_prebuilt_layout_mismatch",
                    warnings,
                );
            }
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {name}@{version} from the patch service ({})",
                    archive.source_url
                ),
            ));
            ServiceDir::Used
        }
        ServiceArtifact::IntegrityMismatch(reason) => hard_fail(format!(
            "prebuilt artifact failed integrity verification ({reason}); refusing to fall back \
             to a local build on tampered bytes"
        )),
        ServiceArtifact::Pending => fallback_or_fail(
            "prebuilt artifact is still building".to_string(),
            "vendor_prebuilt_pending",
            warnings,
        ),
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard_fail(format!("prebuilt artifact unavailable: {reason}"))
            } else {
                ServiceDir::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => fallback_or_fail(
            format!("patch service request failed ({reason})"),
            "vendor_prebuilt_unavailable",
            warnings,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_dependencies_are_cut_out_as_one_span() {
        let cases = [
            (
                "{\n  \"name\": \"x\",\n  \"devDependencies\": {\n    \"a\": \"1\"\n  },\n  \"main\": \"i.js\"\n}\n",
                Some("{\n  \"name\": \"x\",\n  \"main\": \"i.js\"\n}\n"),
            ),
            (
                "{\n  \"name\": \"x\",\n  \"devDependencies\": {}\n}\n",
                Some("{\n  \"name\": \"x\"\n}\n"),
            ),
            ("{\"devDependencies\": {\"a\": \"1\"}}", Some("{}")),
            (
                "\u{feff}{\"devDependencies\":{},\"main\":\"i\"}",
                Some("\u{feff}{\"main\":\"i\"}"),
            ),
            (
                "{\"name\":\"x\",\"scripts\":{\"devDependencies\":\"y\"}}",
                None,
            ),
            ("{\"name\":\"x\"}", None),
        ];
        for (input, want) in cases {
            assert_eq!(
                strip_dev_dependencies(input).unwrap().as_deref(),
                want,
                "{input}"
            );
        }
        assert_eq!(
            strip_dev_dependencies("{\"devDependencies\":{},\"devDependencies\":{}}"),
            Err(SpanError::Duplicate("devDependencies".into()))
        );
        assert_eq!(strip_dev_dependencies("[1]"), Err(SpanError::NotJson));
    }

    #[test]
    fn dependency_tokens_are_replaced_in_place() {
        let text = "{\n  \"dependencies\": {\n    \"a\": \"1\",\n    \"@s/b\" :  \"^2\"\n  },\n  \"x\": [\"dependencies\"]\n}\n";
        assert_eq!(
            dependency_token(text, "dependencies", "@s/b").unwrap(),
            "\"^2\""
        );
        assert_eq!(
            replace_dependency_token(text, "dependencies", "@s/b", "\"file:./v\"").unwrap(),
            text.replace("\"^2\"", "\"file:./v\"")
        );
        assert_eq!(
            dependency_token(text, "devDependencies", "a"),
            Err(SpanError::Missing)
        );
        assert_eq!(
            dependency_token("{\"dependencies\":{\"a\":1}}", "dependencies", "a"),
            Err(SpanError::NotString)
        );
        assert_eq!(
            dependency_token(
                "{\"dependencies\":{\"a\":\"1\",\"a\":\"2\"}}",
                "dependencies",
                "a"
            ),
            Err(SpanError::Duplicate("dependencies.a".into()))
        );
    }

    #[tokio::test]
    async fn the_structure_rule_admits_exactly_the_package_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let leaf = tmp.path().join("@s/b-1.0.0/node_modules");
        let pkg = leaf.join("@s/b");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        assert!(structure_rule_holds(&pkg, "@s/b").await);
        tokio::fs::create_dir_all(leaf.join("@s/c")).await.unwrap();
        assert!(!structure_rule_holds(&pkg, "@s/b").await);

        let pkg = tmp.path().join("a-1.0.0/node_modules/a");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        assert!(structure_rule_holds(&pkg, "a").await);
        tokio::fs::write(tmp.path().join("a-1.0.0/node_modules/.x"), b"")
            .await
            .unwrap();
        assert!(!structure_rule_holds(&pkg, "a").await);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn only_links_dirs_and_bin_scripts_live_under_the_package_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg = tmp.path();
        assert!(node_modules_holds_only_links(pkg).await, "absent is fine");
        let nm = pkg.join("node_modules");
        tokio::fs::create_dir_all(nm.join(".bin")).await.unwrap();
        tokio::fs::create_dir_all(nm.join("@s")).await.unwrap();
        std::os::unix::fs::symlink("/elsewhere", nm.join("dep")).unwrap();
        std::os::unix::fs::symlink("/elsewhere", nm.join("@s/dep")).unwrap();
        tokio::fs::write(nm.join(".bin/tool"), b"#!/bin/sh\n")
            .await
            .unwrap();
        assert!(node_modules_holds_only_links(pkg).await);
        tokio::fs::write(nm.join("@s/planted.js"), b"x")
            .await
            .unwrap();
        assert!(!node_modules_holds_only_links(pkg).await);
    }

    #[tokio::test]
    async fn uuid_metadata_is_written_with_its_exact_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join(GITIGNORE), b"*\n")
            .await
            .unwrap();
        restore_uuid_metadata(tmp.path()).await.unwrap();
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(GITIGNORE)).unwrap(),
            "!*\n**/node_modules/*/node_modules/\n**/node_modules/@*/*/node_modules/\n"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(GITATTRIBUTES)).unwrap(),
            "* -text\n"
        );
    }

    fn tgz(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            if !kind.is_file() && !kind.is_dir() {
                header.set_link_name("target").unwrap();
            }
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn the_service_extract_strips_any_first_component_and_refuses_links() {
        use tar::EntryType;
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("stage");
        let ok = tgz(&[
            ("left-pad/", EntryType::Directory, b""),
            ("left-pad/index.js", EntryType::Regular, b"x"),
        ]);
        super::super::registry_fetch::extract_tgz_strict(&ok, &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("index.js")).unwrap(), b"x");
        for kind in [
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Char,
            EntryType::Fifo,
        ] {
            let bad = tgz(&[
                ("package/index.js", EntryType::Regular, b"x"),
                ("package/evil", kind, b""),
            ]);
            let err =
                super::super::registry_fetch::extract_tgz_strict(&bad, &tmp.path().join("s2"))
                    .unwrap_err();
            assert!(err.contains("not a regular file"), "{kind:?}: {err}");
        }
    }

    #[test]
    fn check_ignore_records_split_on_nul_so_a_drive_letter_source_parses() {
        let out = "C:/Users/u/.gitignore_global\x003\x00!dist/\x00.socket/p/dist/i.js\x00\
                   C:/Users/u/.gitignore_global\x004\x00*.map\x00.socket/p/i.js.map\x00\
                   .gitignore\x001\x00.socket/\x00.socket/p/a.js\x00";
        assert_eq!(
            ignoring_rules(out),
            [
                "C:/Users/u/.gitignore_global:4:*.map\t.socket/p/i.js.map",
                ".gitignore:1:.socket/\t.socket/p/a.js",
            ]
        );
        assert!(ignoring_rules("").is_empty());
        assert!(ignoring_rules("C:/g\x002\x00!x\x00x\x00").is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_gitignore_probe_ignores_tracked_state_and_names_the_rule() {
        let Some(git) = crate::utils::process::resolve_tool("git") else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let status = std::process::Command::new(&git)
            .args(["init", "-q"])
            .current_dir(root)
            .status()
            .unwrap();
        assert!(status.success());
        let paths = vec![".socket/vendor/npm/u/a-1.0.0/node_modules/a/dist/i.js".to_string()];
        assert_eq!(gitignored(root, &paths).await, None);
        std::fs::write(root.join(".gitignore"), "dist/\n").unwrap();
        let uuid = root.join(".socket/vendor/npm/u");
        std::fs::create_dir_all(&uuid).unwrap();
        assert!(
            gitignored(root, &paths).await.is_some(),
            "a root dist/ rule"
        );
        restore_uuid_metadata(&uuid).await.unwrap();
        assert_eq!(
            gitignored(root, &paths).await,
            None,
            "the uuid .gitignore re-includes it"
        );
        std::fs::write(root.join(".gitignore"), ".socket/\n").unwrap();
        let rules = gitignored(root, &paths).await.unwrap();
        assert!(rules.contains(".gitignore:1:.socket/"), "{rules}");
        assert!(gitignored(&tmp.path().join("missing"), &paths)
            .await
            .is_none());
    }
}
