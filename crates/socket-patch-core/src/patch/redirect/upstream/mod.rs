//! Hosted → upstream restore: the v5 unwind of a hosted redirect.
//!
//! v5 hosted mode keeps no ledger (`scan`/`get --mode hosted` write only
//! lockfile edits), so an unwind cannot replay recorded fragments. Instead,
//! for every hosted pin the lockfiles carry (`vex::discover`'s hosted refs:
//! purl + patch uuid + the files wiring it), this module rewrites the lock
//! entry back to the DEFAULT UPSTREAM registry entry for `name@version`,
//! re-resolving whatever the entry pins (tarball URL, integrity, checksum)
//! from the public registry: the npm registry's version document, the
//! crates.io sparse index, the Go module proxy, and so on.
//!
//! Where that is impossible — a format whose entry carries fields only the
//! package manager can compute, a binary lockfile, an offline run, a
//! registry that does not answer — the pin is REFUSED with a message naming
//! the remedy (`git checkout -- <lockfile>`). A refusal is all-or-nothing
//! per pin: a pin refused in one of its files is restored in none of them,
//! so no pin is ever left half hosted.
//!
//! Nothing reaches disk until every pin resolved (the staged view below),
//! and a dry run resolves everything exactly like a wet run — network
//! lookups included — and skips only the flush.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::vex::discover::{Discovery, PatchedRef, WiringMode};

mod cargo;
mod client;
mod composer;
mod gem;
mod golang;
mod npm;

pub(crate) use client::UpstreamClient;

use super::staged::{flush_staged, read_rel, Staged, StagedBytes};

/// One hosted pin to restore: a `(purl, patch uuid)` pair and the
/// root-relative files lockfile discovery found it wired in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedPin {
    /// Canonical base purl (no qualifiers), as discovery spells it.
    pub purl: String,
    /// The hosted patch uuid.
    pub uuid: String,
    /// Root-relative files that wire this pin, sorted and deduplicated.
    pub files: Vec<String>,
}

impl HostedPin {
    /// Group a discovery's HOSTED refs into pins, one per `(purl, uuid)`.
    pub fn from_refs<'a>(refs: impl IntoIterator<Item = &'a PatchedRef>) -> Vec<HostedPin> {
        let mut grouped: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for r in refs {
            if r.mode != WiringMode::Hosted {
                continue;
            }
            grouped
                .entry((r.purl.clone(), r.uuid.clone()))
                .or_default()
                .insert(r.source_file.to_string_lossy().replace('\\', "/"));
        }
        grouped
            .into_iter()
            .map(|((purl, uuid), files)| HostedPin {
                purl,
                uuid,
                files: files.into_iter().collect(),
            })
            .collect()
    }

    /// Every hosted pin a discovery holds.
    pub fn all(discovery: &Discovery) -> Vec<HostedPin> {
        Self::from_refs(&discovery.refs)
    }

    /// `(name, version)` of the purl, percent-decoded.
    pub(crate) fn name_version(&self) -> Option<(String, String)> {
        let (_, name, version) = crate::utils::purl::purl_parts(&self.purl)?;
        Some((name, version))
    }
}

/// Knobs for [`restore_upstream`].
#[derive(Debug, Clone, Default)]
pub struct RestoreOptions {
    /// Resolve everything, write nothing.
    pub dry_run: bool,
    /// No network: every pin whose restore needs a registry lookup is
    /// refused with the checkout remedy.
    pub offline: bool,
    /// Extra patch-server origins whose URLs count as hosted (the
    /// operator's `--patch-server-url`), exactly as discovery takes them.
    pub patch_server_origins: Vec<String>,
}

/// What happened to one pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// Every file wiring the pin now resolves the upstream registry entry
    /// (or would, on a dry run).
    Restored,
    /// Nothing was changed for this pin. The message names the remedy.
    Refused(String),
}

/// One pin's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinResult {
    pub purl: String,
    pub uuid: String,
    pub status: PinStatus,
    /// The files that wired the pin.
    pub files: Vec<String>,
}

/// What [`restore_upstream`] did.
#[derive(Debug, Default)]
pub struct RestoreOutcome {
    /// One entry per input pin, in input order.
    pub pins: Vec<PinResult>,
    /// Root-relative files rewritten or removed (or that would be, on a
    /// dry run), sorted.
    pub reverted_files: Vec<String>,
    /// Advisory `(code, detail)` pairs.
    pub warnings: Vec<(&'static str, String)>,
    /// A write failure after every pin resolved: some files may have
    /// landed. `None` on a clean flush (and always on a dry run).
    pub flush_error: Option<String>,
}

impl RestoreOutcome {
    pub fn restored(&self) -> impl Iterator<Item = &PinResult> {
        self.pins
            .iter()
            .filter(|p| p.status == PinStatus::Restored)
    }

    pub fn refused(&self) -> impl Iterator<Item = (&PinResult, &str)> {
        self.pins.iter().filter_map(|p| match &p.status {
            PinStatus::Refused(why) => Some((p, why.as_str())),
            PinStatus::Restored => None,
        })
    }
}

/// The remedy every refusal names: restore the file from version control.
pub fn checkout_remedy(files: &[String]) -> String {
    if files.is_empty() {
        return "restore the lockfile from version control (`git checkout -- <lockfile>`)"
            .to_string();
    }
    format!(
        "restore it from version control instead (`git checkout -- {}`)",
        files.join(" ")
    )
}

/// The staged project view the restorers work over: reads fall through to
/// disk, writes stay in memory until [`restore_upstream`] flushes them.
pub(crate) struct View<'a> {
    root: &'a Path,
    staged: Staged,
    /// Original on-disk text of every file read, so a write that restores
    /// the exact original bytes is not reported as a change.
    originals: BTreeMap<String, Option<String>>,
}

impl<'a> View<'a> {
    fn new(root: &'a Path) -> Self {
        View {
            root,
            staged: Staged::new(),
            originals: BTreeMap::new(),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        self.root
    }

    /// The current (staged) text of `rel`; `Ok(None)` when absent.
    pub(crate) async fn read(&mut self, rel: &str) -> Result<Option<String>, String> {
        if let Some(pending) = self.staged.get(rel) {
            return Ok(pending.clone());
        }
        if let Some(original) = self.originals.get(rel) {
            return Ok(original.clone());
        }
        let text = read_rel(self.root, rel).await?;
        self.originals.insert(rel.to_string(), text.clone());
        Ok(text)
    }

    pub(crate) fn write(&mut self, rel: &str, content: String) {
        self.staged.insert(rel.to_string(), Some(content));
    }

    pub(crate) fn remove(&mut self, rel: &str) {
        self.staged.insert(rel.to_string(), None);
    }

    /// Files whose staged state differs from what was read from disk.
    fn changed(&self) -> Staged {
        self.staged
            .iter()
            .filter(|(rel, pending)| self.originals.get(*rel) != Some(*pending))
            .map(|(rel, pending)| (rel.clone(), pending.clone()))
            .collect()
    }
}

/// Per-format restore result, merged across formats by the driver.
#[derive(Debug, Default)]
pub(crate) struct FormatResult {
    /// Pins (by uuid) this format refused, with the reason (the driver
    /// appends the remedy).
    pub refused: BTreeMap<String, String>,
    /// Pins (by uuid) this format found wired and restored in the view.
    pub handled: BTreeSet<String>,
    pub warnings: Vec<(&'static str, String)>,
}

impl FormatResult {
    pub(crate) fn refuse(&mut self, uuid: &str, why: impl Into<String>) {
        self.refused
            .entry(uuid.to_string())
            .or_insert_with(|| why.into());
    }

    fn merge(&mut self, other: FormatResult) {
        for (uuid, why) in other.refused {
            self.refused.entry(uuid).or_insert(why);
        }
        self.handled.extend(other.handled);
        self.warnings.extend(other.warnings);
    }
}

/// Shared context handed to every format restorer.
pub(crate) struct Ctx<'a> {
    pub client: &'a UpstreamClient,
    pub origins: &'a [String],
}

impl Ctx<'_> {
    /// The hosted patch uuid `url` names, under the same host allowlist
    /// discovery applies.
    pub(crate) fn hosted_uuid(&self, url: &str) -> Option<String> {
        super::hosted_patch_uuid(url, self.origins)
    }
}

/// The lock formats a pin's files belong to. One restorer per format sees
/// every in-scope pin wired in that format's files at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Format {
    NpmLock,
    YarnLock,
    PnpmLock,
    BunLock,
    Cargo,
    Golang,
    Gem,
    Composer,
    Unsupported,
}

fn format_of(rel: &str) -> Format {
    let leaf = rel.rsplit('/').next().unwrap_or(rel);
    match leaf {
        "package-lock.json" | "npm-shrinkwrap.json" => Format::NpmLock,
        "yarn.lock" => Format::YarnLock,
        "pnpm-lock.yaml" | "shrinkwrap.yaml" => Format::PnpmLock,
        "bun.lock" => Format::BunLock,
        "Cargo.toml" | "Cargo.lock" | "config.toml" | "config" => Format::Cargo,
        "go.mod" | "go.sum" | "go.work" => Format::Golang,
        "Gemfile.lock" | "gems.locked" | "Gemfile" | "gems.rb" => Format::Gem,
        "composer.lock" => Format::Composer,
        _ => Format::Unsupported,
    }
}

/// Restore every pin in `pins` to its default upstream registry entry.
/// See the module docs for the contract.
pub async fn restore_upstream(
    root: &Path,
    pins: &[HostedPin],
    opts: &RestoreOptions,
) -> RestoreOutcome {
    let client = UpstreamClient::new(opts.offline);
    let ctx = Ctx {
        client: &client,
        origins: &opts.patch_server_origins,
    };

    // Pins refused so far (uuid → reason). Each pass restores the pins not
    // yet refused over a FRESH view; a pass that refuses a new pin is rerun
    // without it, so the final view restores exactly the surviving set.
    let mut refused: BTreeMap<String, String> = BTreeMap::new();
    let (view, result) = loop {
        let active: Vec<&HostedPin> = pins
            .iter()
            .filter(|p| !refused.contains_key(&p.uuid))
            .collect();
        let mut view = View::new(root);
        let result = restore_pass(&mut view, &active, &ctx).await;
        let mut grew = false;
        for (uuid, why) in &result.refused {
            if !refused.contains_key(uuid) {
                refused.insert(uuid.clone(), why.clone());
                grew = true;
            }
        }
        // A pin no restorer claimed has wiring nothing here can unwind.
        for pin in &active {
            if !result.handled.contains(&pin.uuid) && !refused.contains_key(&pin.uuid) {
                refused.insert(
                    pin.uuid.clone(),
                    format!(
                        "no hosted wiring for {} was found in {} that socket-patch can \
                         restore to the upstream registry entry",
                        pin.purl,
                        if pin.files.is_empty() {
                            "the lockfiles".to_string()
                        } else {
                            pin.files.join(", ")
                        }
                    ),
                );
                grew = true;
            }
        }
        if !grew {
            break (view, result);
        }
    };

    let changed = view.changed();
    let reverted_files: BTreeSet<String> = changed.keys().cloned().collect();
    let flush_error = if opts.dry_run || changed.is_empty() {
        None
    } else {
        flush_staged(root, &changed, &StagedBytes::new()).await.err()
    };

    let pins_out = pins
        .iter()
        .map(|pin| PinResult {
            purl: pin.purl.clone(),
            uuid: pin.uuid.clone(),
            status: match refused.get(&pin.uuid) {
                Some(why) => PinStatus::Refused(format!(
                    "cannot restore {} to its upstream registry entry: {why}; {}",
                    pin.purl,
                    checkout_remedy(&pin.files)
                )),
                None => PinStatus::Restored,
            },
            files: pin.files.clone(),
        })
        .collect();

    RestoreOutcome {
        pins: pins_out,
        reverted_files: reverted_files.into_iter().collect(),
        warnings: result.warnings,
        flush_error,
    }
}

/// One restore pass over `view` for the `active` pins.
async fn restore_pass(view: &mut View<'_>, active: &[&HostedPin], ctx: &Ctx<'_>) -> FormatResult {
    let mut by_format: BTreeMap<Format, (Vec<&HostedPin>, BTreeSet<String>)> = BTreeMap::new();
    for pin in active {
        for file in &pin.files {
            let slot = by_format.entry(format_of(file)).or_default();
            if !slot.0.iter().any(|p| p.uuid == pin.uuid) {
                slot.0.push(pin);
            }
            slot.1.insert(file.clone());
        }
    }
    let mut out = FormatResult::default();
    for (format, (pins, files)) in by_format {
        let files: Vec<String> = files.into_iter().collect();
        let result = match format {
            Format::NpmLock => npm::restore_npm_locks(view, &pins, &files, ctx).await,
            Format::YarnLock => npm::restore_yarn_locks(view, &pins, &files, ctx).await,
            Format::PnpmLock => npm::restore_pnpm_locks(view, &pins, &files, ctx).await,
            Format::BunLock => npm::restore_bun_locks(view, &pins, &files, ctx).await,
            Format::Cargo => cargo::restore(view, &pins, &files, ctx).await,
            Format::Golang => golang::restore(view, &pins, &files, ctx).await,
            Format::Gem => gem::restore(view, &pins, &files, ctx).await,
            Format::Composer => composer::restore(view, &pins, &files, ctx).await,
            Format::Unsupported => {
                let mut r = FormatResult::default();
                for pin in &pins {
                    let unsupported: Vec<&str> = pin
                        .files
                        .iter()
                        .filter(|f| format_of(f) == Format::Unsupported)
                        .map(String::as_str)
                        .collect();
                    r.refuse(
                        &pin.uuid,
                        format!(
                            "socket-patch cannot re-derive the upstream entry in {}",
                            unsupported.join(", ")
                        ),
                    );
                }
                r
            }
        };
        out.merge(result);
    }
    // The npm-family side settings a hosted run may have written, once no
    // npm-family lock entry needs them any more.
    npm::cleanup_side_config(view, ctx, &mut out).await;
    out
}
