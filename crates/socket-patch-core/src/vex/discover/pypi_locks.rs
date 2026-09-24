//! Python TOML locks — `uv.lock`, PEP 723 script locks (`<script>.py.lock`),
//! PEP 751 `pylock.toml` / `pylock.<name>.toml`
//! (`utils::python_lock::python_lock_paths`), `poetry.lock` and `pdm.lock`.
//!
//! EVERY present lock is read (rule 1) — not `lock_inventory`'s poetry → pdm
//! precedence chain, and not the redirect engine's "pdm only without
//! uv/poetry" gate: the hosted rewriter edits every candidate it finds, so a
//! lock another lock "shadows" may still wire a patch.
//!
//! A lock entry is a ref when the location it installs from is a
//! Socket-HOSTED url ([`DiscoverCtx::hosted_uuid`]) or a root-anchored
//! `.socket/vendor/pypi/<uuid>/<wheel>` path ([`vendor_ref`]). The purl is
//! the ENTRY's `name` + `version` (PEP 503-canonical, [`pypi_purl`]); a
//! vendored wheel leaf, and a hosted url's wheel leaf, must name that same
//! distribution (every writer derives the wheel from the entry it rewires),
//! otherwise the entry is not Socket-written and is diagnosed. A string that
//! names `.socket/vendor/` but fails [`vendor_ref`] (absolute, `../`-prefixed,
//! traversal in the leaf) is diagnosed too — the installer would consume a
//! file outside this project's vendored artifact.
//!
//! Every hosted rewriter below refuses a dep without a sha256 and always
//! writes the patched wheel's digest next to the url, so
//! `integrity_required` is set for EVERY format here: a pin-less Socket url
//! was not written by socket-patch and must not attest from the lockfile
//! alone. Pins are `LockIntegrity::Sha256Hex` (lowercased), or
//! `Sha256AnyOf` for a Poetry 0.x `[metadata.hashes]` list.
//!
//! ## uv.lock and script locks (`utils::python_lock::rewrite_python_lock`)
//!
//! `[[package]]` (uv ≥ 0.2.35 and script locks) or `[[distribution]]` (uv
//! 0.2.x) tables. The location is `source`:
//!
//! * hosted — `source = { url = <artifact> }`, or the uv ≤ 0.2.17 string
//!   grammar `source = "direct+<artifact>"`; the pin is the artifact entry
//!   whose url carries the same uuid: `wheels = [{ url, hash = "sha256:…" }]`,
//!   `sdist = { url, hash }`, or the uv ≤ 0.2.5 `[[distribution.wheel]]` /
//!   `[distribution.sdist]` tables;
//! * vendored — `source = { path = ".socket/vendor/pypi/<uuid>/<wheel>" }`
//!   with `wheels = [{ filename = "<wheel>", hash }]` (`vendor::pypi_uv`'s
//!   text surgery and `vendor::pypi_lock` write the same shape).
//!
//! Registry / git / editable / virtual sources are not ours. An artifact
//! entry naming a DIFFERENT Socket patch than the source is contradictory
//! and diagnosed.
//!
//! uv also re-resolves a lock that disagrees with its project metadata (a
//! plain `uv sync` rewrites a path-source lock without the matching
//! `[tool.uv.sources]` entry back to the registry — `vendor::pypi_uv`'s
//! pairing note), and both our writers ALWAYS edit the pair: `uv.lock` with
//! a root `pyproject.toml`, and a script lock with its `<script>.py` PEP 723
//! block. So when the paired metadata exists, a lock entry is a ref only if
//! its `[tool.uv.sources]` entry routes the package to the SAME patch (same
//! hosted uuid / same vendored artifact); a half-reverted pair is diagnosed,
//! not attested. A script lock whose script is missing wires nothing (uv
//! cannot run it). A `uv.lock` with no `pyproject.toml` beside it (a
//! lock-only checkout — the hosted rewriter then edits the lock alone) needs
//! no confirmation. `[tool.uv.sources]` alone never makes a ref: it carries
//! no version and no pin, and `--frozen` installs what the lock says.
//!
//! ## pylock.toml (PEP 751)
//!
//! `[[packages]]`. The hosted rewriter writes `archive = { url, hashes = {
//! sha256 } }`, the vendored one `archive = { path, hashes }`. Hand-written
//! `wheels = [...]` / `sdist` artifacts are accepted when EVERY artifact of
//! the package is the same Socket patch; a package mixing Socket and other
//! artifacts is diagnosed (the installer may pick the unpatched one). No
//! paired metadata: installers read pylock files on their own.
//!
//! ## poetry.lock (`utils::poetry_lock::rewrite_poetry_lock`)
//!
//! `[[package]]` + `[package.source]`: hosted `type = "url"`, `url =
//! <artifact>` (lock 1.0 appends `#sha256=<hex>&`, which
//! [`DiscoverCtx::hosted_uuid`] ignores); vendored `type = "file"`, `url =
//! ".socket/vendor/pypi/<uuid>/<wheel>"` (`vendor::pypi_poetry`). Any other
//! source type naming a Socket artifact is not something Poetry installs as
//! that artifact and is diagnosed, as is a hosted url in a format-`"0"`
//! lock: Poetry 0.12 ignores url sources. Pins, first found: the package's
//! own `files = [{file, hash}]` (2.x; also written into 1.0/1.1), `[metadata.
//! files]` (1.0/1.1), the 1.0 url fragment, `[metadata.hashes]` (0.x).
//!
//! ## pdm.lock (`utils::pdm_lock::rewrite_pdm_lock`)
//!
//! `[[package]]` `url = <artifact>` (hosted) or `path =
//! "./.socket/vendor/pypi/<uuid>/<wheel>"` (vendored, `vendor::pypi_pdm`;
//! PDM on Windows writes backslashes). A Socket location under the other key
//! is diagnosed. Extras variants (`extras = [...]`, one `[[package]]` each)
//! wire the same package and dedupe. Pins: the matching `files` entry, inline
//! or in `[metadata.files]` (`utils::pdm_lock::files_for`). lock_version
//! 3.1 / 4.0 / 4.1 / 4.2 (PDM 1.15 and 2.0–2.7) lose url/path candidate
//! identity before dependency lookup — those installers do not reliably
//! install the wired artifact, the rewriters refuse them, and a Socket
//! location found there is diagnosed.
//!
//! Fixtures: `tests/fixtures/redirect/pypi/uv/*/expected/`,
//! `tests/fixtures/poetry/<0.12.17..2.4.3>/`, `tests/fixtures/pdm-native/`.
//! The native (registry) fixtures are rewired in the tests through the SAME
//! rewriter functions the hosted and vendored backends call.

use toml_edit::{DocumentMut, Item, Table, TableLike, Value};

use super::{
    mentions_vendor_dir, pypi_purl, toml_or_diag, vendored_leaf_purl, DiscoverCtx, Discovery,
    LocateOpts, PatchedRef, TomlDiag, Wired, DIAG_LOCKFILE_UNPARSEABLE, DIAG_REF_INVALID,
};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::digest::{sha256_hex, sha256_prefixed};
use crate::utils::python_lock::{
    is_script_lock_name, lock_package_collection, package_artifacts, paired_metadata_rel,
    script_of_lock, uv_source_location, LockArtifact, UvSource,
};
use crate::utils::requirements::url_sha256_fragment;
use crate::vendor::lock_inventory::LockIntegrity;

const UV_LOCK: &str = "uv.lock";
const POETRY_LOCK: &str = "poetry.lock";
const PDM_LOCK: &str = "pdm.lock";
const PYPROJECT: &str = "pyproject.toml";

/// pdm.lock formats whose installers drop url/path candidate identity (see
/// the module docs; `pdm-native/README.md`).
const PDM_IDENTITY_LOSING_FORMATS: [&str; 4] = ["3.1", "4.0", "4.1", "4.2"];

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    // `uv.lock` is tried explicitly so a non-regular file squatting the name
    // (which the directory listing skips) still diagnoses as unreadable.
    let mut python_locks = vec![UV_LOCK.to_string()];
    for path in crate::utils::python_lock::python_lock_paths(ctx.root).unwrap_or_default() {
        if !python_locks.contains(&path) {
            python_locks.push(path);
        }
    }
    for lock in &python_locks {
        extract_python_lock(ctx, lock, out).await;
    }
    extract_poetry(ctx, out).await;
    extract_pdm(ctx, out).await;
}

// ── shared classification ────────────────────────────────────────────────

/// `Ok(Some)` for a Socket location, `Ok(None)` for anything else, `Err` for
/// a string that names `.socket/vendor/` without being a root-anchored,
/// traversal-safe vendored artifact path.
fn classify(ctx: &DiscoverCtx<'_>, location: &str) -> Result<Option<Wired>, ()> {
    let located = ctx.locate(location, LocateOpts::LITERAL);
    if let Some(vref) = located.vendored {
        return Ok(Some(Wired::Vendored(vref)));
    }
    if mentions_vendor_dir(location) {
        return Err(());
    }
    Ok(located.hosted.map(Wired::Hosted))
}

fn bad_vendor_path(out: &mut Discovery, file: &str, name: Option<&str>, location: &str) {
    out.diag(
        DIAG_REF_INVALID,
        file,
        format!(
            "{file}: {} installs from {location:?}, which is not a root-anchored \
             .socket/vendor/pypi/<uuid>/<wheel> artifact of this project",
            name.unwrap_or("an entry")
        ),
    );
}

/// One Socket-wired lock entry, ready for [`emit`].
struct Candidate<'a> {
    name: Option<&'a str>,
    version: Option<&'a str>,
    location: String,
    wired: Wired,
    integrity: Option<LockIntegrity>,
}

/// Validate a candidate's coordinates and artifact leaf, then push its ref.
fn emit(out: &mut Discovery, file: &str, c: Candidate<'_>) {
    let location = c.location.as_str();
    let (Some(name), Some(version)) = (c.name, c.version) else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: Socket-wired entry {:?} (from {location:?}) has no name or version",
                c.name.unwrap_or("")
            ),
        );
        return;
    };
    let Some(purl) = pypi_purl(name, version) else {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!("{file}: Socket-wired entry {name:?}@{version:?} has unsafe coordinates"),
        );
        return;
    };
    match c.wired {
        Wired::Vendored(vref) => {
            if vref.eco != "pypi"
                || vendored_leaf_purl("pypi", &vref.leaf).as_deref() != Some(purl.as_str())
            {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: {purl} is wired to {location:?}, which is not that package's \
                         vendored pypi wheel"
                    ),
                );
                return;
            }
            out.push(PatchedRef::vendored(purl, &vref, file, c.integrity));
        }
        Wired::Hosted(uuid) => {
            let leaf_purl = url_leaf(location).and_then(|leaf| vendored_leaf_purl("pypi", &leaf));
            if leaf_purl.as_ref().is_some_and(|leaf| leaf != &purl) {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: {purl} is wired to {location:?}, whose wheel is a different \
                         distribution"
                    ),
                );
                return;
            }
            out.push(PatchedRef::hosted(
                purl,
                uuid,
                file,
                Some(location),
                c.integrity,
                true,
            ));
        }
    }
}

/// The percent-decoded last path segment of a url (query and fragment cut).
fn url_leaf(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next()?;
    let leaf = path.rsplit('/').next().filter(|leaf| !leaf.is_empty())?;
    Some(crate::utils::purl::percent_decode_purl_component(leaf).into_owned())
}

/// The file name an artifact location ends in (`/` or `\` separated).
fn basename(location: &str) -> &str {
    let path = location.split(['?', '#']).next().unwrap_or(location);
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// The single pin all `digests` agree on, if any.
fn agreed_pin(digests: impl IntoIterator<Item = String>) -> Option<LockIntegrity> {
    let mut digests: Vec<String> = digests.into_iter().collect();
    digests.sort();
    digests.dedup();
    match digests.as_slice() {
        [one] => Some(LockIntegrity::Sha256Hex(one.clone())),
        _ => None,
    }
}

/// The file name `wired`'s artifact at `location` goes by in a lock's
/// `files` lists: a hosted url's leaf, a vendored wheel's basename.
fn artifact_filename(wired: &Wired, location: &str) -> String {
    match wired {
        Wired::Hosted(_) => url_leaf(location).unwrap_or_default(),
        Wired::Vendored(vref) => basename(&vref.leaf).to_string(),
    }
}

/// The pin every `{ file = <filename>, hash = "sha256:…" }` entry of a
/// Poetry / PDM `files` list agrees on.
fn files_pin<'t>(
    files: impl IntoIterator<Item = &'t dyn TableLike>,
    filename: &str,
) -> Option<LockIntegrity> {
    agreed_pin(
        files
            .into_iter()
            .filter(|f| str_of(*f, "file") == Some(filename))
            .filter_map(|f| str_of(f, "hash").and_then(sha256_prefixed)),
    )
}

fn str_of<'t>(table: &'t dyn TableLike, key: &str) -> Option<&'t str> {
    table.get(key).and_then(Item::as_str)
}

/// The `[[<collection>]]` tables of a lock: `None` (nothing to read) when
/// absent, a diagnostic when present with the wrong shape.
fn package_tables<'d>(
    out: &mut Discovery,
    file: &str,
    doc: &'d DocumentMut,
    collection: &str,
) -> Option<&'d toml_edit::ArrayOfTables> {
    let item = doc.get(collection)?;
    let tables = item.as_array_of_tables();
    if tables.is_none() {
        out.diag(
            DIAG_LOCKFILE_UNPARSEABLE,
            file,
            format!("{file}: `{collection}` is not an array of [[{collection}]] tables"),
        );
    }
    tables
}

// ── uv.lock / script locks / pylock.toml ─────────────────────────────────
//
// Read with the lock inventory's own model (`utils::python_lock`: the
// package array, artifact tables, uv source locations).

/// Whether `artifact` is the artifact `wired` installs (same hosted uuid /
/// same vendored file).
fn artifact_matches(ctx: &DiscoverCtx<'_>, artifact: &LockArtifact<'_>, wired: &Wired) -> bool {
    if let Some(Ok(Some(w))) = artifact.location().map(|l| classify(ctx, l)) {
        return w.same_artifact(wired);
    }
    match wired {
        Wired::Vendored(vref) => {
            artifact.location().is_none() && artifact.filename == Some(basename(&vref.leaf))
        }
        Wired::Hosted(_) => false,
    }
}

async fn extract_python_lock(ctx: &DiscoverCtx<'_>, file: &str, out: &mut Discovery) {
    let Some(text) = ctx.read_text(file, out).await else {
        return;
    };
    let Some(doc) = toml_or_diag(file, &text, TomlDiag::Raw, out) else {
        return;
    };
    let (collection, pep751) = lock_package_collection(&doc);
    let Some(packages) = package_tables(out, file, &doc, collection) else {
        return;
    };
    let mut candidates = Vec::new();
    // A PEP 723 script lock is scoped to its script's own install: it is not
    // evidence against the project's locks (see `contest_across_locks`).
    let script_lock = is_script_lock_name(file);
    for package in packages.iter() {
        if pep751 {
            pylock_candidates(ctx, file, package, out, &mut candidates);
        } else if let Some(c) = uv_candidate(ctx, file, package, out) {
            candidates.push(c);
        } else if !script_lock && uv_resolves_elsewhere(ctx, package) {
            out.resolved_elsewhere(file, package_purl(package));
        }
    }
    if candidates.is_empty() {
        // A lock with no Socket entry can still sit beside paired metadata
        // that names a patch — the half-reverted pair (the lock re-locked or
        // reverted to the registry, the `[tool.uv.sources]` edit left
        // behind). That half wires nothing uv installs `--frozen`, so sweep
        // the metadata for the identities it mentions: discovery is then
        // authoritative for them (rule 11) and a leftover ledger claim is
        // dead instead of being resurrected by the CLI's raw-text fallback
        // from that same metadata file.
        if !pep751 {
            if let Some(meta) = paired_metadata_rel(file) {
                ctx.recognize_ignored(meta).await;
            }
        }
        return;
    }
    let pairing = if pep751 {
        Pairing::LockOnly
    } else {
        load_pairing(ctx, file, out).await
    };
    for c in candidates {
        match &pairing {
            Pairing::LockOnly => emit(out, file, c),
            Pairing::Sources { file: meta, doc } => {
                let canon = canonicalize_pypi_name(c.name.unwrap_or(""));
                if sources_confirm(ctx, doc, &canon, &c.wired) {
                    emit(out, file, c);
                } else {
                    out.diag(
                        DIAG_REF_INVALID,
                        file,
                        format!(
                            "{file}: {} is wired to {:?}, but {meta} [tool.uv.sources] does not \
                             route it to the same patch — uv re-resolves a lock that disagrees \
                             with its project metadata, so this wiring is not trusted",
                            c.name.unwrap_or("an entry"),
                            c.location
                        ),
                    );
                }
            }
            Pairing::Unusable { file: meta, why } => {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: {} is wired to {:?}, but its paired {meta} {why}, so the \
                         wiring cannot be confirmed",
                        c.name.unwrap_or("an entry"),
                        c.location
                    ),
                );
            }
        }
    }
}

/// The `pypi_purl` of a lock table's `name` + `version`.
fn package_purl(package: &Table) -> Option<String> {
    pypi_purl(
        package.get("name").and_then(Item::as_str)?,
        package.get("version").and_then(Item::as_str)?,
    )
}

/// Whether a uv entry installs from a non-Socket REMOTE: a registry (other
/// than a Socket-hosted index), or a direct url that is not Socket's.
/// Local (virtual / editable / directory / path) and git sources are not
/// counted.
fn uv_resolves_elsewhere(ctx: &DiscoverCtx<'_>, package: &Table) -> bool {
    let Some(source) = UvSource::of(package) else {
        return false;
    };
    if let Some(index) = source.registry() {
        return ctx.hosted_uuid(index).is_none();
    }
    source
        .url()
        .is_some_and(|url| matches!(classify(ctx, url), Ok(None)))
}

/// A uv `[[package]]` / `[[distribution]]` entry's Socket wiring, if any.
fn uv_candidate<'t>(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    package: &'t Table,
    out: &mut Discovery,
) -> Option<Candidate<'t>> {
    let name = package.get("name").and_then(Item::as_str);
    let location = uv_source_location(package)?;
    let wired = match classify(ctx, location) {
        Ok(Some(wired)) => wired,
        Ok(None) => return None,
        Err(()) => {
            bad_vendor_path(out, file, name, location);
            return None;
        }
    };
    let artifacts = package_artifacts(package, &["wheels", "wheel", "sdist"]);
    let contradicting =
        artifacts
            .iter()
            .find_map(|a| match a.location().map(|l| classify(ctx, l)) {
                Some(Ok(Some(other))) if !other.same_artifact(&wired) => a.location(),
                Some(Err(())) => a.location(),
                _ => None,
            });
    if let Some(other) = contradicting {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: {} installs from {location:?} but also lists the artifact {other:?} \
                 of a different Socket patch",
                name.unwrap_or("an entry")
            ),
        );
        return None;
    }
    let integrity = agreed_pin(
        artifacts
            .iter()
            .filter(|a| artifact_matches(ctx, a, &wired))
            .filter_map(|a| a.sha256.clone()),
    );
    Some(Candidate {
        name,
        version: package.get("version").and_then(Item::as_str),
        location: location.to_string(),
        wired,
        integrity,
    })
}

/// A PEP 751 `[[packages]]` entry's Socket wiring(s): its `archive`, else
/// every `wheels[]` / `sdist` artifact, all of which must be the same patch.
fn pylock_candidates<'t>(
    ctx: &DiscoverCtx<'_>,
    file: &str,
    package: &'t Table,
    out: &mut Discovery,
    candidates: &mut Vec<Candidate<'t>>,
) {
    let name = package.get("name").and_then(Item::as_str);
    let version = package.get("version").and_then(Item::as_str);
    let artifacts = if package.contains_key("archive") {
        package_artifacts(package, &["archive"])
    } else {
        package_artifacts(package, &["wheels", "sdist"])
    };
    let mut socket: Vec<(&LockArtifact<'_>, &str, Wired)> = Vec::new();
    let mut foreign = false;
    for artifact in &artifacts {
        let Some(location) = artifact.location() else {
            foreign = true;
            continue;
        };
        match classify(ctx, location) {
            Ok(Some(wired)) => socket.push((artifact, location, wired)),
            Ok(None) => foreign = true,
            Err(()) => {
                bad_vendor_path(out, file, name, location);
                return;
            }
        }
    }
    let Some((first_location, first)) = socket
        .first()
        .map(|(_, location, wired)| (location.to_string(), wired.clone()))
    else {
        if foreign {
            out.resolved_elsewhere(file, name.zip(version).and_then(|(n, v)| pypi_purl(n, v)));
        }
        return;
    };
    if foreign || socket.iter().any(|(_, _, w)| w.uuid() != first.uuid()) {
        out.diag(
            DIAG_REF_INVALID,
            file,
            format!(
                "{file}: {} mixes the Socket artifact {first_location:?} with artifacts of \
                 another origin or patch; an installer may pick an unpatched one",
                name.unwrap_or("an entry")
            ),
        );
        return;
    }
    if matches!(first, Wired::Hosted(_)) {
        let integrity = agreed_pin(socket.iter().filter_map(|(a, _, _)| a.sha256.clone()));
        candidates.push(Candidate {
            name,
            version,
            location: first_location,
            wired: first,
            integrity,
        });
    } else {
        // Several vendored wheels are several artifacts: one ref each.
        for (artifact, location, wired) in socket {
            candidates.push(Candidate {
                name,
                version,
                location: location.to_string(),
                wired,
                integrity: agreed_pin(artifact.sha256.clone()),
            });
        }
    }
}

/// What confirms a uv / script lock entry (see the module docs).
enum Pairing {
    /// No paired metadata: the lock alone is what the installer reads.
    LockOnly,
    /// The paired metadata document (`pyproject.toml`, or a script's PEP
    /// 723 block) whose `[tool.uv.sources]` must agree.
    Sources { file: String, doc: DocumentMut },
    /// The paired metadata exists (or, for a script lock, must exist) but
    /// cannot be used.
    Unusable { file: String, why: String },
}

async fn load_pairing(ctx: &DiscoverCtx<'_>, lock: &str, out: &mut Discovery) -> Pairing {
    if lock == UV_LOCK {
        if !ctx.exists(PYPROJECT).await {
            return Pairing::LockOnly;
        }
        return match ctx.read_text(PYPROJECT, out).await {
            None => unusable(PYPROJECT, "is unreadable"),
            Some(text) => match text.parse::<DocumentMut>() {
                Ok(doc) => Pairing::Sources {
                    file: PYPROJECT.to_string(),
                    doc,
                },
                Err(e) => unusable(PYPROJECT, &format!("is not valid TOML ({e})")),
            },
        };
    }
    let Some(script) = script_of_lock(lock) else {
        return Pairing::LockOnly;
    };
    let Some(text) = ctx.read_text(script, out).await else {
        return unusable(
            script,
            "is missing or unreadable (uv runs a script lock only with its script)",
        );
    };
    match crate::utils::python_script::script_metadata(&text) {
        Ok((_, metadata)) => match metadata.parse::<DocumentMut>() {
            Ok(doc) => Pairing::Sources {
                file: format!("{script} (PEP 723 block)"),
                doc,
            },
            Err(e) => unusable(script, &format!("has invalid PEP 723 metadata ({e})")),
        },
        Err(e) => unusable(script, &format!("has no usable PEP 723 metadata ({e})")),
    }
}

fn unusable(file: &str, why: &str) -> Pairing {
    Pairing::Unusable {
        file: file.to_string(),
        why: why.to_string(),
    }
}

/// Whether `doc`'s `[tool.uv.sources]` routes canonical package `canon` to
/// exactly `wired`'s patch: a single unconditional `{ url | path }` source
/// (our writers' shape; a marker / extra / group split applies only to some
/// installs, and an array of sources is such a split).
fn sources_confirm(ctx: &DiscoverCtx<'_>, doc: &DocumentMut, canon: &str, wired: &Wired) -> bool {
    let Some(sources) = doc
        .get("tool")
        .and_then(Item::as_table_like)
        .and_then(|tool| tool.get("uv"))
        .and_then(Item::as_table_like)
        .and_then(|uv| uv.get("sources"))
        .and_then(Item::as_table_like)
    else {
        return false;
    };
    let Some(source) = sources
        .iter()
        .find(|(key, _)| canonicalize_pypi_name(key) == canon)
        .and_then(|(_, item)| item.as_table_like())
    else {
        return false;
    };
    if ["marker", "extra", "group"]
        .iter()
        .any(|key| source.contains_key(key))
    {
        return false;
    }
    let Some(location) = str_of(source, "url").or_else(|| str_of(source, "path")) else {
        return false;
    };
    matches!(classify(ctx, location), Ok(Some(declared)) if declared.same_artifact(wired))
}

// ── poetry.lock ──────────────────────────────────────────────────────────

async fn extract_poetry(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let file = POETRY_LOCK;
    let Some(text) = ctx.read_text(file, out).await else {
        return;
    };
    let Some(doc) = toml_or_diag(file, &text, TomlDiag::Raw, out) else {
        return;
    };
    let format = crate::utils::poetry_lock::lock_version(&doc)
        .ok()
        .map(str::to_string);
    let Some(packages) = package_tables(out, file, &doc, "package") else {
        return;
    };
    for package in packages.iter() {
        let name = package.get("name").and_then(Item::as_str);
        let Some(source) = package.get("source").and_then(Item::as_table_like) else {
            // No `[package.source]`: resolved from PyPI.
            out.resolved_elsewhere(file, package_purl(package));
            continue;
        };
        let Some(url) = str_of(source, "url") else {
            continue;
        };
        let wired = match classify(ctx, url) {
            Ok(Some(wired)) => wired,
            Ok(None) => {
                out.resolved_elsewhere(file, package_purl(package));
                continue;
            }
            Err(()) => {
                bad_vendor_path(out, file, name, url);
                continue;
            }
        };
        let expected = match wired {
            Wired::Hosted(_) => "url",
            Wired::Vendored(_) => "file",
        };
        let source_type = str_of(source, "type");
        if source_type != Some(expected) {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {} names the Socket artifact {url:?} under a `type = {:?}` source; \
                     Poetry installs it as that artifact only from a `type = \"{expected}\"` \
                     source",
                    name.unwrap_or("an entry"),
                    source_type.unwrap_or("")
                ),
            );
            continue;
        }
        if matches!(wired, Wired::Hosted(_)) && format.as_deref() == Some("0") {
            out.diag(
                DIAG_REF_INVALID,
                file,
                format!(
                    "{file}: {} has a Socket url source, which Poetry 0.x (lock format \"0\") \
                     ignores",
                    name.unwrap_or("an entry")
                ),
            );
            continue;
        }
        let filename = artifact_filename(&wired, url);
        let integrity = poetry_pin(&doc, package, name.unwrap_or(""), &filename, url);
        emit(
            out,
            file,
            Candidate {
                name,
                version: package.get("version").and_then(Item::as_str),
                location: url.to_string(),
                wired,
                integrity,
            },
        );
    }
}

/// The pin Poetry verifies `filename` against (see the module docs).
fn poetry_pin(
    doc: &DocumentMut,
    package: &Table,
    name: &str,
    filename: &str,
    url: &str,
) -> Option<LockIntegrity> {
    let canon = canonicalize_pypi_name(name);
    if let Some(pin) = files_pin(crate::utils::poetry_lock::package_files(package), filename) {
        return Some(pin);
    }
    if let Some(pin) = files_pin(
        crate::utils::poetry_lock::metadata_files(doc, name),
        filename,
    ) {
        return Some(pin);
    }
    // Lock 1.0 hosted: `<url>#sha256=<hex>&`.
    if let Some(pin) = url_sha256_fragment(url) {
        return Some(LockIntegrity::Sha256Hex(pin));
    }
    // Poetry 0.x: `[metadata.hashes] name = ["<hex>", …]`.
    let mut hashes: Vec<String> = doc
        .get("metadata")
        .and_then(Item::as_table_like)
        .and_then(|metadata| metadata.get("hashes"))
        .and_then(Item::as_table_like)
        .and_then(|table| {
            table
                .iter()
                .find(|(key, _)| canonicalize_pypi_name(key) == canon)
                .map(|(_, item)| item)
        })
        .and_then(Item::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(sha256_hex)
                .collect()
        })
        .unwrap_or_default();
    hashes.sort();
    hashes.dedup();
    match hashes.len() {
        0 => None,
        1 => hashes.pop().map(LockIntegrity::Sha256Hex),
        _ => Some(LockIntegrity::Sha256AnyOf(hashes)),
    }
}

// ── pdm.lock ─────────────────────────────────────────────────────────────

async fn extract_pdm(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let file = PDM_LOCK;
    let Some(text) = ctx.read_text(file, out).await else {
        return;
    };
    let Some(doc) = toml_or_diag(file, &text, TomlDiag::Raw, out) else {
        return;
    };
    let lock_version = doc
        .get("metadata")
        .and_then(Item::as_table_like)
        .and_then(|metadata| str_of(metadata, "lock_version"))
        .map(str::to_string);
    let Some(packages) = package_tables(out, file, &doc, "package") else {
        return;
    };
    for package in packages.iter() {
        let name = package.get("name").and_then(Item::as_str);
        // Neither location is Socket's (none at all = the index).
        if ["url", "path"].iter().all(|key| {
            package
                .get(key)
                .and_then(Item::as_str)
                .is_none_or(|location| matches!(classify(ctx, location), Ok(None)))
        }) {
            out.resolved_elsewhere(file, package_purl(package));
        }
        for key in ["url", "path"] {
            let Some(location) = package.get(key).and_then(Item::as_str) else {
                continue;
            };
            let wired = match classify(ctx, location) {
                Ok(Some(wired)) => wired,
                Ok(None) => continue,
                Err(()) => {
                    bad_vendor_path(out, file, name, location);
                    continue;
                }
            };
            let expected = match wired {
                Wired::Hosted(_) => "url",
                Wired::Vendored(_) => "path",
            };
            if key != expected {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: {} names the Socket artifact {location:?} under `{key}`; PDM \
                         installs it only from `{expected}`",
                        name.unwrap_or("an entry")
                    ),
                );
                continue;
            }
            if let Some(v) = lock_version
                .as_deref()
                .filter(|v| PDM_IDENTITY_LOSING_FORMATS.contains(v))
            {
                out.diag(
                    DIAG_REF_INVALID,
                    file,
                    format!(
                        "{file}: {} is wired to {location:?}, but lock_version {v} (PDM 1.15 / \
                         2.0–2.7) loses url/path candidate identity at install time",
                        name.unwrap_or("an entry")
                    ),
                );
                continue;
            }
            let filename = artifact_filename(&wired, location);
            let integrity = crate::utils::pdm_lock::files_for(&doc, package).and_then(|files| {
                let files = files.iter().filter_map(Value::as_inline_table);
                files_pin(files.map(|f| f as &dyn TableLike), &filename)
            });
            emit(
                out,
                file,
                Candidate {
                    name,
                    version: package.get("version").and_then(Item::as_str),
                    location: location.to_string(),
                    wired,
                    integrity,
                },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::*;
    use crate::utils::python_lock::{rewrite_python_lock, ArtifactSource};

    async fn run(p: &Project) -> Discovery {
        p.run(|c, o| Box::pin(super::extract(c, o))).await
    }

    const SHA: &str = "abababababababababababababababababababababababababababababababab";

    fn sha_pin() -> Option<LockIntegrity> {
        Some(LockIntegrity::Sha256Hex(SHA.to_string()))
    }

    // ── uv fixtures ──────────────────────────────────────────────────────

    const CLICK_WHEEL: &str = "click-8.1.7-py3-none-any.whl";
    const CLICK: &str = "pkg:pypi/click@8.1.7";

    fn uv_registry_lock() -> String {
        std::fs::read_to_string(fixture_path("redirect/pypi/uv/basic/input/uv.lock"))
            .expect("uv input fixture")
    }

    const CLICK_PYPROJECT: &str =
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"click==8.1.7\"]\n";

    fn click_url(uuid: &str) -> String {
        hosted_url("pypi", "click", "8.1.7", uuid, CLICK_WHEEL)
    }

    fn click_vendored(uuid: &str) -> String {
        format!(".socket/vendor/pypi/{uuid}/{CLICK_WHEEL}")
    }

    /// `uv.lock` + `pyproject.toml` exactly as the hosted rewriter leaves
    /// them (`rewrite_python_lock` + `rewrite_project_metadata`).
    fn uv_pair(artifact: ArtifactSource<'_>) -> (String, String) {
        let lock = rewrite_python_lock(&uv_registry_lock(), "click", "8.1.7", artifact, SHA)
            .expect("rewrite uv.lock")
            .expect("click entry");
        let pyproject = crate::utils::python_script::rewrite_project_metadata(
            CLICK_PYPROJECT,
            "click",
            "8.1.7",
            artifact,
        )
        .expect("rewrite pyproject")
        .expect("pyproject changed");
        (lock, pyproject)
    }

    /// The committed golden fixture: the patch uuid, never the token, pinned.
    #[tokio::test]
    async fn uv_golden_hosted_fixture() {
        let p = Project::new();
        p.copy_fixture("redirect/pypi/uv/basic/expected");
        let out = run(&p).await;
        assert_refs(
            &out,
            &[(
                CLICK,
                "88888888-8888-8888-8888-888888888888",
                WiringMode::Hosted,
            )],
        );
        let r = &out.refs[0];
        assert_eq!(r.source_file, std::path::PathBuf::from("uv.lock"));
        assert!(r.integrity_required && r.lockfile_basis_ok());
        assert_eq!(
            r.locked_integrity,
            Some(LockIntegrity::Sha256Hex("deadbeef".repeat(8)))
        );
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);

        // The registry lock it was rewritten from wires nothing.
        let p = Project::new();
        p.copy_fixture("redirect/pypi/uv/basic/input");
        p.write("pyproject.toml", CLICK_PYPROJECT);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    #[tokio::test]
    async fn uv_hosted_pair_is_confirmed_by_tool_uv_sources() {
        let url = click_url(UUID_A);
        let (lock, pyproject) = uv_pair(ArtifactSource::Url(&url));
        // LF and a git-autocrlf CRLF checkout read the same.
        for ending in ["\n", "\r\n"] {
            let p = Project::new();
            p.write("uv.lock", lock.replace('\n', ending))
                .write("pyproject.toml", pyproject.replace('\n', ending));
            let out = run(&p).await;
            assert_refs(&out, &[(CLICK, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.refs[0].locked_integrity, sha_pin());
            assert_eq!(out.refs[0].url.as_deref(), Some(url.as_str()));
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        }
    }

    #[tokio::test]
    async fn uv_vendored_pair_is_discovered_with_its_pin() {
        let rel = click_vendored(UUID_B);
        let (lock, pyproject) = uv_pair(ArtifactSource::Path(&rel));
        let p = Project::new();
        p.write("uv.lock", &lock)
            .write("pyproject.toml", &pyproject);
        let out = run(&p).await;
        assert_refs(&out, &[(CLICK, UUID_B, WiringMode::Vendored)]);
        assert_eq!(out.refs[0].artifact_rel.as_deref(), Some(rel.as_str()));
        assert_eq!(out.refs[0].locked_integrity, sha_pin());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// `vendor::pypi_uv`'s own text-surgery shape (multi-line `wheels`
    /// array, `./` spelled source) for a transitive dep wired through
    /// `override-dependencies` — plus a registry neighbour that yields
    /// nothing.
    #[tokio::test]
    async fn uv_vendored_text_surgery_shape_and_registry_neighbour() {
        let rel = format!(".socket/vendor/pypi/{UUID_A}/six-1.16.0-py2.py3-none-any.whl");
        let lock = format!(
            "version = 1\nrevision = 3\nrequires-python = \">=3.8\"\n\n\
             [manifest]\noverrides = [{{ name = \"six\", path = \"{rel}\" }}]\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = {{ virtual = \".\" }}\n\n\
             [[package]]\nname = \"idna\"\nversion = \"3.7\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n\
             wheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/idna-3.7-py3-none-any.whl\", hash = \"sha256:{}\" }},\n]\n\n\
             [[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ path = \"./{rel}\" }}\n\
             wheels = [\n    {{ filename = \"six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{SHA}\" }},\n]\n",
            "0".repeat(64)
        );
        let pyproject = format!(
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"idna\"]\n\n\
             [tool.uv]\noverride-dependencies = [\"six==1.16.0\"]\n\n\
             [tool.uv.sources]\nsix = {{ path = \"{rel}\" }}\n"
        );
        let p = Project::new();
        p.write("uv.lock", &lock)
            .write("pyproject.toml", &pyproject);
        let out = run(&p).await;
        assert_refs(
            &out,
            &[("pkg:pypi/six@1.16.0", UUID_A, WiringMode::Vendored)],
        );
        assert_eq!(out.refs[0].locked_integrity, sha_pin());
        assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
    }

    /// A half-reverted pair: uv would re-resolve the lock from the pyproject
    /// on a plain `uv sync`, so the lock alone is not trusted.
    #[tokio::test]
    async fn uv_lock_disagreeing_with_pyproject_is_diagnosed_not_discovered() {
        let url = click_url(UUID_A);
        let (lock, pyproject) = uv_pair(ArtifactSource::Url(&url));
        for (label, meta) in [
            ("reverted pyproject", CLICK_PYPROJECT.to_string()),
            ("other patch", pyproject.replace(UUID_A, UUID_B)),
            (
                "marker-split source",
                pyproject.replace("\" }", "\", marker = \"sys_platform == 'linux'\" }"),
            ),
        ] {
            let p = Project::new();
            p.write("uv.lock", &lock).write("pyproject.toml", &meta);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{label}");
            assert!(
                out.diagnostics[0].detail.contains("pyproject.toml"),
                "{label}"
            );
            // The unconfirmed lock's patch is RECOGNIZED: a redirect ledger
            // record for it is dead, not revived from uv.lock's text.
            assert_eq!(out.hosted_claim(CLICK, UUID_A), Some(false), "{label}");
        }
        // An unparseable pyproject confirms nothing either.
        let p = Project::new();
        p.write("uv.lock", &lock)
            .write("pyproject.toml", "[project");
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    /// A lock-only checkout (no pyproject): the hosted rewriter edits the
    /// lock alone, so nothing needs confirming.
    #[tokio::test]
    async fn uv_lock_without_pyproject_needs_no_confirmation() {
        let url = click_url(UUID_A);
        let (lock, _) = uv_pair(ArtifactSource::Url(&url));
        let p = Project::new();
        p.write("uv.lock", &lock);
        assert_refs(&run(&p).await, &[(CLICK, UUID_A, WiringMode::Hosted)]);
    }

    /// uv 0.2.x `[[distribution]]` grammars the rewriter follows: the
    /// string `direct+` source with `[[distribution.wheel]]` tables (≤0.2.5),
    /// with inline `wheels` (0.2.6–0.2.17), and inline-table sources
    /// (0.2.18–0.2.34).
    #[tokio::test]
    async fn uv_legacy_distribution_grammars() {
        let registry = format!("https://files.pythonhosted.org/packages/{CLICK_WHEEL}");
        let zero = "0".repeat(64);
        let inputs = [
            format!(
                "version = 1\n\n[[distribution]]\nname = \"click\"\nversion = \"8.1.7\"\n\
                 source = \"registry+https://pypi.org/simple\"\n\n[[distribution.wheel]]\n\
                 url = \"{registry}\"\nhash = \"sha256:{zero}\"\n"
            ),
            format!(
                "version = 1\n\n[[distribution]]\nname = \"click\"\nversion = \"8.1.7\"\n\
                 source = \"registry+https://pypi.org/simple\"\n\
                 wheels = [{{ url = \"{registry}\", hash = \"sha256:{zero}\" }}]\n"
            ),
            format!(
                "version = 1\n\n[[distribution]]\nname = \"click\"\nversion = \"8.1.7\"\n\
                 source = {{ registry = \"https://pypi.org/simple\" }}\n\
                 wheels = [{{ url = \"{registry}\", hash = \"sha256:{zero}\" }}]\n"
            ),
        ];
        let url = click_url(UUID_A);
        for input in inputs {
            let lock =
                rewrite_python_lock(&input, "click", "8.1.7", ArtifactSource::Url(&url), SHA)
                    .expect("rewrite legacy")
                    .expect("entry");
            let p = Project::new();
            p.write("uv.lock", &lock);
            let out = run(&p).await;
            assert_refs(&out, &[(CLICK, UUID_A, WiringMode::Hosted)]);
            assert_eq!(out.refs[0].locked_integrity, sha_pin(), "{lock}");
        }
    }

    /// PEP 723 script lock + its script, both rewritten as the backends do.
    #[tokio::test]
    async fn script_lock_is_confirmed_by_its_pep723_block() {
        let script = "# /// script\n# dependencies = [\"click==8.1.7\"]\n# ///\nprint('hi')\n";
        let rel = click_vendored(UUID_A);
        let artifact = ArtifactSource::Path(&rel);
        let lock = rewrite_python_lock(&uv_registry_lock(), "click", "8.1.7", artifact, SHA)
            .unwrap()
            .unwrap();
        let wired_script = crate::utils::python_script::rewrite_script_metadata(
            script, "click", "8.1.7", artifact,
        )
        .unwrap()
        .unwrap();
        let p = Project::new();
        p.write("tool.py.lock", &lock)
            .write("tool.py", &wired_script);
        let out = run(&p).await;
        assert_refs(&out, &[(CLICK, UUID_A, WiringMode::Vendored)]);
        assert_eq!(
            out.refs[0].source_file,
            std::path::PathBuf::from("tool.py.lock")
        );

        // The unwired script, or no script at all, confirms nothing.
        for script_text in [Some(script), None] {
            let p = Project::new();
            p.write("tool.py.lock", &lock);
            if let Some(text) = script_text {
                p.write("tool.py", text);
            }
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
            assert!(out.diagnostics[0].detail.contains("tool.py"));
        }
    }

    /// A half-reverted pair — the lock back on the registry, the paired
    /// metadata (`pyproject.toml` / the script's PEP 723 block) still
    /// routing the package to a patch — wires nothing, and the metadata's
    /// mention is RECOGNIZED so discovery, not the CLI's raw-text fallback
    /// over the ledger's recorded wiring files, decides the ledger claim:
    /// dead (rule 11). The script case was missed before: nothing read the
    /// script once its lock carried no Socket entry, so a leftover vendor
    /// ledger attested a script whose lock `uv run --frozen` installs the
    /// registry wheel from.
    #[tokio::test]
    async fn half_reverted_pair_metadata_is_recognized_not_wired() {
        let script = "# /// script\n# dependencies = [\"click==8.1.7\"]\n# ///\nprint('hi')\n";
        for mode in [WiringMode::Vendored, WiringMode::Hosted] {
            let location = match mode {
                WiringMode::Vendored => click_vendored(UUID_A),
                WiringMode::Hosted => click_url(UUID_A),
            };
            let artifact = match mode {
                WiringMode::Vendored => ArtifactSource::Path(&location),
                WiringMode::Hosted => ArtifactSource::Url(&location),
            };
            let wired_script = crate::utils::python_script::rewrite_script_metadata(
                script, "click", "8.1.7", artifact,
            )
            .unwrap()
            .unwrap();
            let (_, wired_pyproject) = uv_pair(artifact);
            for (lock, meta, meta_text) in [
                ("tool.py.lock", "tool.py", wired_script.as_str()),
                ("uv.lock", "pyproject.toml", wired_pyproject.as_str()),
            ] {
                let p = Project::new();
                p.write(lock, uv_registry_lock()).write(meta, meta_text);
                let out = run(&p).await;
                assert_refs(&out, &[]);
                assert!(
                    out.recognizes(UUID_A, mode),
                    "{lock} {mode:?}: {meta}'s mention must be recognized: {:?}",
                    out.recognized
                );
                let claim = match mode {
                    WiringMode::Vendored => out.vendored_claim(CLICK, UUID_A, &location),
                    WiringMode::Hosted => out.hosted_claim(CLICK, UUID_A),
                };
                assert_eq!(
                    claim,
                    Some(false),
                    "{lock} {mode:?}: the ledger claim is dead"
                );
            }
        }
    }

    // ── pylock ───────────────────────────────────────────────────────────

    fn pylock_registry() -> String {
        format!(
            "lock-version = \"1.0\"\ncreated-by = \"uv\"\n\n[[packages]]\nname = \"click\"\n\
             version = \"8.1.7\"\nindex = \"https://pypi.org/simple\"\n\
             wheels = [{{ url = \"https://files.pythonhosted.org/packages/{CLICK_WHEEL}\", \
             hashes = {{ sha256 = \"{}\" }} }}]\n",
            "0".repeat(64)
        )
    }

    #[tokio::test]
    async fn pylock_archive_hosted_and_vendored() {
        let url = click_url(UUID_A);
        let rel = click_vendored(UUID_B);
        for (name, artifact, uuid, mode) in [
            (
                "pylock.toml",
                ArtifactSource::Url(&url),
                UUID_A,
                WiringMode::Hosted,
            ),
            (
                "pylock.dev.toml",
                ArtifactSource::Path(&rel),
                UUID_B,
                WiringMode::Vendored,
            ),
        ] {
            let lock = rewrite_python_lock(&pylock_registry(), "click", "8.1.7", artifact, SHA)
                .unwrap()
                .unwrap();
            let p = Project::new();
            // A pyproject WITHOUT sources beside it: pylock is not paired.
            p.write(name, &lock)
                .write("pyproject.toml", CLICK_PYPROJECT);
            let out = run(&p).await;
            assert_refs(&out, &[(CLICK, uuid, mode)]);
            assert_eq!(out.refs[0].locked_integrity, sha_pin(), "{lock}");
            assert!(out.diagnostics.is_empty(), "{:?}", out.diagnostics);
        }
    }

    /// Hand-written `wheels` lists: all-Socket is a ref; a Socket wheel
    /// beside a registry wheel is ambiguous and diagnosed.
    #[tokio::test]
    async fn pylock_wheel_lists_must_be_all_socket() {
        let a = click_url(UUID_A);
        let entry = |wheels: &str| {
            format!(
                "lock-version = \"1.0\"\n\n[[packages]]\nname = \"click\"\nversion = \"8.1.7\"\n\
                 wheels = [{wheels}]\n"
            )
        };
        let socket = format!("{{ url = \"{a}\", hashes = {{ sha256 = \"{SHA}\" }} }}");
        let other = format!(
            "{{ url = \"https://files.pythonhosted.org/click-8.1.7-py2-none-any.whl\", hashes = {{ sha256 = \"{}\" }} }}",
            "0".repeat(64)
        );
        let p = Project::new();
        p.write("pylock.toml", entry(&socket));
        let out = run(&p).await;
        assert_refs(&out, &[(CLICK, UUID_A, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, sha_pin());

        let p = Project::new();
        p.write("pylock.toml", entry(&format!("{socket}, {other}")));
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    // ── poetry ───────────────────────────────────────────────────────────

    const POETRY_VERSIONS: [&str; 15] = [
        "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1",
        "1.8.5", "2.0.1", "2.1.4", "2.2.1", "2.3.4", "2.4.3",
    ];
    const URLLIB3: &str = "pkg:pypi/urllib3@1.26.18";
    const URLLIB3_WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";

    fn poetry_fixture(version: &str) -> String {
        std::fs::read_to_string(fixture_path(&format!("poetry/{version}/poetry.lock")))
            .expect("poetry fixture")
    }

    fn poetry_rewired(version: &str, source_type: &str, location: &str) -> String {
        crate::utils::poetry_lock::rewrite_poetry_lock(
            &poetry_fixture(version),
            "urllib3",
            "1.26.18",
            source_type,
            location,
            URLLIB3_WHEEL,
            SHA,
        )
        .unwrap_or_else(|e| panic!("poetry {version} {source_type}: {e}"))
        .expect("urllib3 entry")
    }

    /// Every native Poetry lock generation, rewired hosted (1.0+) and
    /// vendored (every format) by the shared rewriter; the native lock
    /// itself yields nothing.
    #[tokio::test]
    async fn poetry_every_lock_generation_hosted_and_vendored() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let rel = format!(".socket/vendor/pypi/{UUID_B}/{URLLIB3_WHEEL}");
        for version in POETRY_VERSIONS {
            let p = Project::new();
            p.copy_fixture(&format!("poetry/{version}"));
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(
                out.diagnostics.is_empty(),
                "{version}: {:?}",
                out.diagnostics
            );

            let mut cases = vec![("file", rel.as_str(), UUID_B, WiringMode::Vendored)];
            if version != "0.12.17" {
                cases.push(("url", url.as_str(), UUID_A, WiringMode::Hosted));
            }
            for (source_type, location, uuid, mode) in cases {
                let p = Project::new();
                p.write(
                    "poetry.lock",
                    poetry_rewired(version, source_type, location),
                );
                let out = run(&p).await;
                assert_refs(&out, &[(URLLIB3, uuid, mode)]);
                assert_eq!(
                    out.refs[0].locked_integrity,
                    sha_pin(),
                    "{version} {source_type}"
                );
                assert!(
                    out.diagnostics.is_empty(),
                    "{version}: {:?}",
                    out.diagnostics
                );
                if mode == WiringMode::Hosted {
                    assert!(out.refs[0].lockfile_basis_ok());
                }
            }
        }
    }

    #[tokio::test]
    async fn poetry_sources_poetry_would_not_install_as_the_artifact() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let rel = format!(".socket/vendor/pypi/{UUID_B}/{URLLIB3_WHEEL}");
        // A hand-made hosted url in a format-0 lock (Poetry 0.12 ignores it).
        let zero = poetry_rewired("0.12.17", "file", &rel)
            .replace("type = \"file\"", "type = \"url\"")
            .replace(&rel, &url);
        // A Socket index declared as a `legacy` source; a vendored wheel as `url`.
        let legacy = poetry_rewired("2.1.4", "url", &url).replace("\"url\"", "\"legacy\"");
        let file_as_url = poetry_rewired("2.1.4", "file", &rel).replace("\"file\"", "\"url\"");
        for (label, lock) in [
            ("format 0", zero),
            ("legacy", legacy),
            ("file as url", file_as_url),
        ] {
            let p = Project::new();
            p.write("poetry.lock", &lock);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{label}: {lock}");
        }
    }

    // ── pdm ──────────────────────────────────────────────────────────────

    fn pdm_fixture(name: &str) -> String {
        std::fs::read_to_string(fixture_path(&format!("pdm-native/{name}.lock")))
            .expect("pdm fixture")
    }

    /// Every supported native PDM format (incl. separate extras entries and
    /// legacy `[metadata.files]`), rewired by the shared rewriter: hosted
    /// url, POSIX and Windows vendored paths.
    #[tokio::test]
    async fn pdm_every_supported_format_hosted_and_vendored() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let posix = format!("./.socket/vendor/pypi/{UUID_B}/{URLLIB3_WHEEL}");
        let windows = posix.replace('/', "\\");
        for version in [
            "0.12.3",
            "0.12.3-extras",
            "2.8.2",
            "2.9.3",
            "2.10.4",
            "2.11.2",
            "2.17.3",
            "2.29.2",
            "2.29.2-extras",
        ] {
            let native = pdm_fixture(version);
            let p = Project::new();
            p.write("pdm.lock", &native);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(
                out.diagnostics.is_empty(),
                "{version}: {:?}",
                out.diagnostics
            );
            for (kind, location, uuid, mode) in [
                ("url", url.as_str(), UUID_A, WiringMode::Hosted),
                ("path", posix.as_str(), UUID_B, WiringMode::Vendored),
                ("path", windows.as_str(), UUID_B, WiringMode::Vendored),
            ] {
                let lock = crate::utils::pdm_lock::rewrite_pdm_lock(
                    &native,
                    "urllib3",
                    "1.26.18",
                    (kind, location),
                    URLLIB3_WHEEL,
                    SHA,
                )
                .unwrap_or_else(|e| panic!("pdm {version} {kind}: {e}"));
                let p = Project::new();
                p.write("pdm.lock", &lock);
                let out = run(&p).await;
                assert_refs(&out, &[(URLLIB3, uuid, mode)]);
                assert_eq!(out.refs.len(), 1, "{version}: extras variants dedupe");
                assert_eq!(out.refs[0].locked_integrity, sha_pin(), "{version} {kind}");
                assert!(
                    out.diagnostics.is_empty(),
                    "{version}: {:?}",
                    out.diagnostics
                );
                if mode == WiringMode::Vendored {
                    assert_eq!(
                        out.refs[0].artifact_rel.as_deref(),
                        Some(format!(".socket/vendor/pypi/{UUID_B}/{URLLIB3_WHEEL}").as_str())
                    );
                }
            }
        }
    }

    /// PDM 1.15 / 2.0–2.7 formats lose url/path identity: a hand-inserted
    /// Socket url there is diagnosed. A Socket url under `path` too.
    #[tokio::test]
    async fn pdm_identity_losing_formats_and_wrong_keys_are_diagnosed() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let insert = |text: &str, key: &str| {
            text.replacen(
                "name = \"urllib3\"\nversion = \"1.26.18\"\n",
                &format!("name = \"urllib3\"\nversion = \"1.26.18\"\n{key} = \"{url}\"\n"),
                1,
            )
        };
        for version in ["1.15.5", "2.0.3", "2.1.5", "2.3.4", "2.6.1", "2.7.4"] {
            let lock = insert(&pdm_fixture(version), "url");
            assert!(lock.contains(&url), "{version}: inserted");
            let p = Project::new();
            p.write("pdm.lock", &lock);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{version}");
        }
        let lock = insert(&pdm_fixture("2.29.2"), "path");
        let p = Project::new();
        p.write("pdm.lock", &lock);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);
    }

    // ── cross-format and negative cases ──────────────────────────────────

    /// Every lock present is read — no poetry → pdm → uv precedence.
    #[tokio::test]
    async fn every_present_lock_is_read() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let rel = format!(".socket/vendor/pypi/{UUID_B}/{URLLIB3_WHEEL}");
        let click = click_url(UUID_B);
        let p = Project::new();
        p.write("poetry.lock", poetry_rewired("2.1.4", "url", &url));
        p.write(
            "pdm.lock",
            crate::utils::pdm_lock::rewrite_pdm_lock(
                &pdm_fixture("2.29.2"),
                "urllib3",
                "1.26.18",
                ("path", &format!("./{rel}")),
                URLLIB3_WHEEL,
                SHA,
            )
            .unwrap(),
        );
        p.write("uv.lock", uv_pair(ArtifactSource::Url(&click)).0);
        let out = p.discover().await;
        assert_refs(
            &out,
            &[
                (URLLIB3, UUID_A, WiringMode::Hosted),
                (URLLIB3, UUID_B, WiringMode::Vendored),
                (CLICK, UUID_B, WiringMode::Hosted),
            ],
        );
        let files: Vec<_> = out.refs.iter().map(|r| r.source_file.clone()).collect();
        assert_eq!(files.len(), 3, "{files:?}");
    }

    /// A non-Socket host carrying a uuid, a placeholder token with no patch
    /// uuid, a userinfo'd Socket url: none are refs, none diagnose. A
    /// uuid-shaped grant token BEFORE the patch uuid never wins.
    #[tokio::test]
    async fn only_socket_hosted_urls_count_and_the_patch_uuid_wins() {
        let foreign =
            format!("https://evil.example/patch/pypi/click/8.1.7/{TOKEN}/{UUID_A}/{CLICK_WHEEL}");
        let placeholder = format!(
            "https://patch.socket.dev/patch/pypi/click/8.1.7/${{SOCKET_TOKEN}}/{CLICK_WHEEL}"
        );
        let userinfo = click_url(UUID_A).replace("https://", "https://user:pw@");
        for url in [foreign, placeholder, userinfo] {
            let lock = rewrite_python_lock(
                &uv_registry_lock(),
                "click",
                "8.1.7",
                ArtifactSource::Url(&url),
                SHA,
            )
            .unwrap()
            .unwrap();
            let p = Project::new();
            p.write("uv.lock", &lock);
            p.write(
                "pylock.toml",
                rewrite_python_lock(
                    &pylock_registry(),
                    "click",
                    "8.1.7",
                    ArtifactSource::Url(&url),
                    SHA,
                )
                .unwrap()
                .unwrap(),
            );
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert!(out.diagnostics.is_empty(), "{url}: {:?}", out.diagnostics);
        }
        let p = Project::new();
        p.write(
            "uv.lock",
            uv_pair(ArtifactSource::Url(&click_url(UUID_A))).0,
        );
        let out = run(&p).await;
        assert_eq!(out.refs[0].uuid, UUID_A, "never the grant token {TOKEN}");
    }

    /// `--patch-server-url` origins count like the public host.
    #[tokio::test]
    async fn configured_patch_server_origin_counts() {
        let url = format!(
            "http://127.0.0.1:4545/patch/pypi/urllib3/1.26.18/{TOKEN}/{UUID_A}/{URLLIB3_WHEEL}"
        );
        let lock = poetry_rewired("2.1.4", "url", &url);
        let p = Project::new();
        p.write("poetry.lock", &lock);
        assert_refs(&run(&p).await, &[]);
        let p = Project::new().with_origin("http://127.0.0.1:4545");
        p.write("poetry.lock", &lock);
        assert_refs(&run(&p).await, &[(URLLIB3, UUID_A, WiringMode::Hosted)]);
    }

    /// Malformed files diagnose (never panic) and yield nothing.
    #[tokio::test]
    async fn malformed_locks_are_diagnosed() {
        for (file, text) in [
            ("uv.lock", "[[package]\nname ="),
            ("uv.lock", "version = 1\npackage = \"nope\"\n"),
            ("pylock.toml", "lock-version = \"1.0\"\npackages = 3\n"),
            ("poetry.lock", "[[package]]\nname = \"x\"\n[[package"),
            ("poetry.lock", "package = [1, 2]\n"),
            ("pdm.lock", "\u{0}\u{1}"),
            ("pdm.lock", "[package]\nname = \"x\"\n"),
        ] {
            let p = Project::new();
            p.write(file, text);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(
                diag_codes(&out),
                vec![DIAG_LOCKFILE_UNPARSEABLE],
                "{file}: {text:?}"
            );
            assert!(out.diagnostics[0].detail.contains(file));
        }
    }

    /// Vendored paths that escape the project, traverse, or name another
    /// package; unsafe entry names; a missing version.
    #[tokio::test]
    async fn unsafe_vendored_paths_and_coordinates_are_rejected() {
        let good = click_vendored(UUID_A);
        let lock_with = |name: &str, version: &str, path: &str| {
            format!(
                "version = 1\n\n[[package]]\nname = \"{name}\"\n{version}\
                 source = {{ path = \"{path}\" }}\n\
                 wheels = [{{ filename = \"{CLICK_WHEEL}\", hash = \"sha256:{SHA}\" }}]\n"
            )
        };
        let v = "version = \"8.1.7\"\n";
        for (label, lock) in [
            (
                "traversal leaf",
                lock_with(
                    "click",
                    v,
                    &format!(".socket/vendor/pypi/{UUID_A}/../../../etc/{CLICK_WHEEL}"),
                ),
            ),
            (
                "outside the root",
                lock_with("click", v, &format!("../{good}")),
            ),
            (
                "absolute",
                lock_with("click", v, &format!("/abs/proj/{good}")),
            ),
            (
                "other package's wheel",
                lock_with(
                    "click",
                    v,
                    &format!(".socket/vendor/pypi/{UUID_A}/six-1.16.0-py3-none-any.whl"),
                ),
            ),
            (
                "wrong ecosystem dir",
                lock_with(
                    "click",
                    v,
                    &format!(".socket/vendor/npm/{UUID_A}/{CLICK_WHEEL}"),
                ),
            ),
            ("unsafe name", lock_with("../click", v, &good)),
            ("no version", lock_with("click", "", &good)),
        ] {
            let p = Project::new();
            p.write("uv.lock", &lock);
            let out = run(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{label}: {lock}");
        }
    }

    /// A hosted wheel leaf naming another distribution, and a wheel entry of
    /// a different patch than the source, are not Socket-written.
    #[tokio::test]
    async fn contradictory_hosted_entries_are_rejected() {
        let six = hosted_url(
            "pypi",
            "six",
            "1.16.0",
            UUID_A,
            "six-1.16.0-py2.py3-none-any.whl",
        );
        let lock = rewrite_python_lock(
            &uv_registry_lock(),
            "click",
            "8.1.7",
            ArtifactSource::Url(&six),
            SHA,
        )
        .unwrap()
        .unwrap();
        let p = Project::new();
        p.write("uv.lock", &lock);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID]);

        let (lock, _) = uv_pair(ArtifactSource::Url(&click_url(UUID_A)));
        let first = lock.find(UUID_A).unwrap();
        let rewired = format!(
            "{}{}",
            &lock[..first + 1],
            lock[first + 1..].replacen(UUID_A, UUID_B, 1)
        );
        let p = Project::new();
        p.write("uv.lock", &rewired);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), vec![DIAG_REF_INVALID], "{rewired}");
    }

    /// A Socket hosted entry whose pin was stripped is still a ref (the
    /// ledger liveness proof), but not attestable from the lockfile alone.
    #[tokio::test]
    async fn pinless_hosted_entry_cannot_use_the_lockfile_basis() {
        let (lock, _) = uv_pair(ArtifactSource::Url(&click_url(UUID_A)));
        let stripped = lock.replace(&format!(", hash = \"sha256:{SHA}\""), "");
        assert_ne!(stripped, lock);
        let p = Project::new();
        p.write("uv.lock", &stripped);
        let out = run(&p).await;
        assert_refs(&out, &[(CLICK, UUID_A, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, None);
        assert!(!out.refs[0].lockfile_basis_ok());
    }

    // ── edge shapes no other test reaches ────────────────────────────────

    /// A Poetry lock-1.0 hosted source pins its artifact through the url's
    /// `#sha256=<hex>` fragment (lowercased) when no file hash names it.
    #[tokio::test]
    async fn poetry_hosted_url_fragment_pin() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let upper = SHA.to_ascii_uppercase();
        let lock = format!(
            "[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\ndescription = \"\"\n\
             category = \"main\"\noptional = false\npython-versions = \"*\"\n\n\
             [package.source]\ntype = \"url\"\nurl = \"{url}#sha256={upper}\"\n\n\
             [metadata]\nlock-version = \"1.0\"\npython-versions = \"*\"\ncontent-hash = \"x\"\n\n\
             [metadata.files]\nurllib3 = []\n"
        );
        let p = Project::new();
        p.write("poetry.lock", &lock);
        let out = run(&p).await;
        assert_refs(&out, &[(URLLIB3, UUID_A, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, sha_pin());
    }

    /// A uv entry installing from a vendored wheel while listing a HOSTED
    /// Socket artifact is contradictory (different wiring kinds never name
    /// the same artifact): diagnosed, not a ref.
    #[tokio::test]
    async fn uv_vendored_source_listing_a_hosted_artifact_is_rejected() {
        let lock = format!(
            "version = 1\nrequires-python = \">=3.8\"\n\n[[package]]\nname = \"click\"\n\
             version = \"8.1.7\"\nsource = {{ path = \"{}\" }}\nwheels = [\n    \
             {{ url = \"{}\", hash = \"sha256:{SHA}\" }},\n]\n",
            click_vendored(UUID_B),
            click_url(UUID_A),
        );
        let p = Project::new();
        p.write("uv.lock", &lock);
        let out = run(&p).await;
        assert_refs(&out, &[]);
        assert_eq!(
            diag_codes(&out),
            vec![DIAG_REF_INVALID],
            "{:#?}",
            out.diagnostics
        );
    }

    /// uv 0.2.x string sources (`"<kind>+<value>"`, `[[distribution]]`): a
    /// Socket `direct+` url is a ref; a registry and a foreign direct url are
    /// resolved-elsewhere evidence; git / editable sources, a missing source
    /// and a non-string, non-table source are neither.
    #[tokio::test]
    async fn uv_string_sources_classify_every_kind() {
        let url = hosted_url("pypi", "urllib3", "1.26.18", UUID_A, URLLIB3_WHEEL);
        let lock = format!(
            "version = 1\nrequires-python = \">=3.8\"\n\n\
             [[distribution]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = \"editable+.\"\n\n\
             [[distribution]]\nname = \"click\"\nversion = \"8.1.7\"\n\
             source = \"registry+https://pypi.org/simple\"\n\n\
             [[distribution]]\nname = \"idna\"\nversion = \"3.6\"\n\
             source = \"direct+https://files.example.test/idna-3.6-py3-none-any.whl\"\n\n\
             [[distribution]]\nname = \"six\"\nversion = \"1.16.0\"\n\
             source = \"git+https://github.com/benjaminp/six?rev=1#abc\"\n\n\
             [[distribution]]\nname = \"sourceless\"\nversion = \"1.0\"\n\n\
             [[distribution]]\nname = \"odd\"\nversion = \"1.0\"\nsource = 7\n\n\
             [[distribution]]\nname = \"urllib3\"\nversion = \"1.26.18\"\n\
             source = \"direct+{url}\"\nwheels = [{{ url = \"{url}\", hash = \"sha256:{SHA}\" }}]\n"
        );
        let p = Project::new();
        p.write("uv.lock", &lock);
        let out = run(&p).await;
        assert_refs(&out, &[(URLLIB3, UUID_A, WiringMode::Hosted)]);
        assert_eq!(out.refs[0].locked_integrity, sha_pin());
        let elsewhere: Vec<&str> = out.elsewhere.iter().map(|e| e.purl.as_str()).collect();
        assert_eq!(elsewhere, ["pkg:pypi/click@8.1.7", "pkg:pypi/idna@3.6"]);
        assert!(out.diagnostics.is_empty(), "{:#?}", out.diagnostics);
    }
}
