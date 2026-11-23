use clap::Args;
use socket_patch_core::ledgers::Store;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::redirect::upstream::HostedPin;
use socket_patch_core::patch::redirect::RedirectState;
use socket_patch_core::telemetry::track_patch_listed;
use socket_patch_core::vendor::state::{VendorState, VENDOR_STATE_REL};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile, RunWarning,
};
use crate::ui::browser::{Cell, Column, Page, Table, Update};

#[derive(Args)]
pub struct ListArgs {
    #[command(flatten)]
    pub common: GlobalArgs,
}

/// The display order of one purl's copies: manifest, hosted, vendored.
fn display_rank(source: Store) -> u8 {
    match source {
        Store::Manifest => 0,
        Store::Hosted => 1,
        Store::Vendored => 2,
    }
}

/// The `(mode, ledger)` label pair for a vendor-ledger record — the shared
/// constant label, never a ledger's own opaque `mode` string (see
/// `HOSTED_MODE_LABEL`'s docs) — or `None` for a manifest entry or a hosted
/// pin (which has no ledger; see [`ListEntry::lockfiles`]). Shared by the
/// JSON `details` and the human `Mode:` line.
fn ledger_label(source: Store) -> Option<(&'static str, &'static str)> {
    match source {
        Store::Manifest | Store::Hosted => None,
        Store::Vendored => Some((crate::commands::VENDORED_MODE_LABEL, VENDOR_STATE_REL)),
    }
}

/// One listable patch record with its provenance.
struct ListEntry<'a> {
    purl: &'a str,
    record: &'a PatchRecord,
    source: Store,
    /// The lockfiles wiring a hosted pin (empty for the other sources).
    lockfiles: &'a [String],
}

/// A hosted pin as `list` shows it: the lockfiles wiring it, and its
/// record — from a pre-v5 redirect ledger when one still describes this
/// exact pin (read for migration only), else just the uuid (the details
/// live on the API; `vex` fetches them).
pub(crate) struct HostedListing {
    pub purl: String,
    pub record: PatchRecord,
    pub lockfiles: Vec<String>,
}

impl HostedListing {
    /// One listing per hosted pin in `pins`, detailed from `legacy` where
    /// it records the same purl and uuid.
    pub(crate) fn from_pins(pins: &[HostedPin], legacy: Option<&RedirectState>) -> Vec<Self> {
        use socket_patch_core::utils::purl_key::PurlKey;
        pins.iter()
            .map(|pin| {
                let record = legacy
                    .and_then(|l| {
                        l.records
                            .iter()
                            .find(|(k, r)| PurlKey::same(k, &pin.purl) && r.uuid == pin.uuid)
                            .map(|(_, r)| r.clone())
                    })
                    .unwrap_or_else(|| socket_patch_core::ledgers::uuid_only_record(&pin.uuid));
                HostedListing {
                    purl: pin.purl.clone(),
                    record,
                    lockfiles: pin.files.clone(),
                }
            })
            .collect()
    }
}

/// Every listable record, in a stable order: by PURL, then
/// [`display_rank`] when one purl appears in more than one store. The
/// manifest and the vendor ledger go through the shared owner rule
/// ([`socket_patch_core::ledgers::Ledgers::listed`]: coexisting copies are
/// real state, shown labeled apart; a claimed fallback copy and a legacy
/// entry with no embedded record never list); every hosted pin lists as
/// its own copy (the lockfiles are the only hosted record). The record
/// maps never impose an order shared consumers could diff, so the sort
/// here is the contract.
fn combined_entries<'a>(
    manifest: Option<&'a PatchManifest>,
    hosted: &'a [HostedListing],
    vendor: Option<&'a VendorState>,
) -> Vec<ListEntry<'a>> {
    let ledgers = socket_patch_core::ledgers::Ledgers {
        manifest,
        vendor,
        redirect: None,
    };
    let mut entries: Vec<ListEntry<'a>> = ledgers
        .listed()
        .into_iter()
        .map(|l| ListEntry {
            purl: l.key,
            record: l.record,
            source: l.store,
            lockfiles: &[],
        })
        .collect();
    entries.extend(hosted.iter().map(|h| ListEntry {
        purl: &h.purl,
        record: &h.record,
        source: Store::Hosted,
        lockfiles: &h.lockfiles,
    }));
    entries.sort_by(|a, b| {
        a.purl
            .cmp(b.purl)
            .then(display_rank(a.source).cmp(&display_rank(b.source)))
    });
    entries
}

/// Build the `list --json` envelope: one `Discovered` event per entry, with
/// the rich metadata (vulnerabilities, tier, license, description,
/// exportedAt) under `details` per the per-command extension convention.
/// Ledger records additionally carry `details.mode` (the constants
/// [`crate::commands::HOSTED_MODE_LABEL`] /
/// [`crate::commands::VENDORED_MODE_LABEL`]) and `details.ledger` naming
/// the ledger they came from (additive keys, absent on manifest entries),
/// so consumers can tell the stores apart.
///
/// Events are emitted in the entries' given order — [`combined_entries`]
/// owns the by-PURL event sort; this builder sorts each event's
/// vulnerabilities (by advisory ID) and files (by path) so the output is
/// stable across runs (`HashMap` iteration is not).
fn build_list_envelope(entries: &[ListEntry<'_>]) -> Envelope {
    let mut env = Envelope::new(Command::List);

    for entry in entries {
        let patch = entry.record;
        let mut file_paths: Vec<_> = patch.files.keys().cloned().collect();
        file_paths.sort();
        let files = file_paths
            .into_iter()
            .map(|path| PatchEventFile {
                path,
                verified: false,
                applied_via: None,
            })
            .collect();

        let mut vuln_entries: Vec<_> = patch.vulnerabilities.iter().collect();
        vuln_entries.sort_by(|a, b| a.0.cmp(b.0));
        let vulnerabilities: Vec<_> = vuln_entries
            .iter()
            .map(|(id, vuln)| {
                serde_json::json!({
                    "id": id,
                    "cves": vuln.cves,
                    "summary": vuln.summary,
                    "severity": vuln.severity,
                    "description": vuln.description,
                })
            })
            .collect();

        let mut details = serde_json::json!({
            "exportedAt": patch.exported_at,
            "tier": patch.tier,
            "license": patch.license,
            "description": patch.description,
            "vulnerabilities": vulnerabilities,
        });
        if let Some((mode, ledger)) = ledger_label(entry.source) {
            details["mode"] = serde_json::json!(mode);
            details["ledger"] = serde_json::json!(ledger);
        }
        if entry.source == Store::Hosted {
            details["mode"] = serde_json::json!(crate::commands::HOSTED_MODE_LABEL);
            details["lockfiles"] = serde_json::json!(entry.lockfiles);
        }

        env.record(
            PatchEvent::new(PatchAction::Discovered, entry.purl.to_string())
                .with_uuid(patch.uuid.clone())
                .with_files(files)
                .with_details(details),
        );
    }

    env
}

/// One project's listing, gathered and not yet on stdout: [`run`] prints
/// it, alone or under its heading among the project directories below
/// `--cwd`. The warnings and errors of a human run are already on stderr.
struct Listed {
    /// The exit code of a run over this project alone.
    code: i32,
    /// The `--json` document (a `--json` run only): the listing, or the
    /// error.
    envelope: Option<Envelope>,
    /// The human listing (a human run that did not fail).
    text: Option<String>,
    /// How many patches it lists.
    patches: usize,
    /// How many of them are manifest records (what telemetry counts).
    manifest_patches: usize,
    /// The patches as an interactive run's table shows and opens them
    /// (empty otherwise).
    rows: Vec<Browse>,
    /// What reading the project had to say on stderr (`Warning: ...`, or
    /// the `Error: ...` of a project that could not be listed), held back
    /// so it prints once the status line is down.
    notes: Vec<String>,
}

impl Listed {
    /// Print the held-back stderr lines.
    fn print_notes(&mut self) {
        for note in self.notes.drain(..) {
            eprintln!("{note}");
        }
    }
}

/// One listed patch, as an interactive run shows it: a row of its table,
/// and what opening it falls back to.
#[derive(Clone)]
struct Browse {
    purl: String,
    uuid: String,
    /// The worst severity among the advisories it fixes, upper-cased;
    /// empty when the project's records name none (a hosted pin carries
    /// only its uuid: the details are the patch service's).
    severity: String,
    /// The ids to show for what it fixes: each advisory's CVEs, or its own
    /// id when it has none.
    ids: Vec<String>,
    /// `agent`, `hosted` or `vendored`.
    mode: &'static str,
    /// The entry as the full listing prints it: what opening the patch
    /// shows when the patch service cannot be asked.
    detail: String,
}

/// The worst severity and the ids to show for a set of advisories
/// ([`crate::ui::worst_and_ids`]), cleaned of control characters: they
/// may come from the project's own files.
fn fixes<'a>(
    advisories: impl Iterator<Item = (&'a String, &'a str, &'a [String])>,
) -> (String, Vec<String>) {
    let (worst, ids) = crate::ui::worst_and_ids(
        advisories.map(|(id, severity, cves)| (id.as_str(), severity, cves)),
    );
    // Two ids that differ only in what is cleaned off are one id.
    let mut ids: Vec<String> = ids.iter().map(|id| sanitize(id)).collect();
    ids.sort();
    ids.dedup();
    (sanitize(&worst), ids)
}

impl Browse {
    fn of(entry: &ListEntry<'_>, color: bool) -> Self {
        let (severity, ids) = fixes(
            entry
                .record
                .vulnerabilities
                .iter()
                .map(|(id, v)| (id, v.severity.as_str(), v.cves.as_slice())),
        );
        Browse {
            purl: sanitize(entry.purl),
            uuid: entry.record.uuid.clone(),
            severity,
            ids,
            mode: match entry.source {
                Store::Manifest => "agent",
                Store::Hosted => crate::commands::HOSTED_MODE_LABEL,
                Store::Vendored => crate::commands::VENDORED_MODE_LABEL,
            },
            detail: format_entry(entry, color),
        }
    }

    /// The row's cells, in [`columns`]' order. `name` is how the table
    /// names the package ([`names`]). `detail` is the patch as the patch
    /// service describes it, once that has arrived: it fills in what was
    /// measured about the patch and when it was published, and names the
    /// advisories of a patch the project records by uuid alone.
    fn cells(
        &self,
        name: &str,
        project: Option<&str>,
        detail: Option<&socket_patch_core::api::types::PatchResponse>,
    ) -> Vec<Cell> {
        use crate::commands::measured::percent;
        let (mut severity, mut ids) = (self.severity.clone(), self.ids.clone());
        if let Some(detail) = detail.filter(|_| ids.is_empty()) {
            (severity, ids) = fixes(
                detail
                    .vulnerabilities
                    .iter()
                    .map(|(id, v)| (id, v.severity.as_str(), v.cves.as_slice())),
            );
        }
        let ids = if ids.len() > IDS_SHOWN {
            format!(
                "{} (+{})",
                ids[..IDS_SHOWN].join(", "),
                ids.len() - IDS_SHOWN
            )
        } else {
            ids.join(", ")
        };
        // Green when every exploit is blocked / every test passes; yellow
        // when some are not.
        let ratio = |ratio: socket_patch_core::api::types::PatchRatio| {
            Cell::painted(
                format!("{}/{}", ratio.count, ratio.total),
                Some(if ratio.is_all() { "32" } else { "33" }),
            )
        };
        let stats = detail.and_then(|d| d.statistics);
        let exploits = stats
            .and_then(|s| s.pocs)
            .map(|pocs| ratio(pocs.blocked_after))
            .unwrap_or_default();
        let tests = stats
            .and_then(|s| s.tests)
            .map(|tests| ratio(tests.after))
            .unwrap_or_default();
        let change = stats
            .and_then(|s| s.diff)
            .map(|diff| format!("+{} -{}", diff.lines_added, diff.lines_removed))
            .unwrap_or_default();
        // The cost of the code the patch touches, or of the package's
        // general workload where only that was measured.
        let perf = stats
            .and_then(|s| s.performance)
            .and_then(|p| p.hot_wall_change.or(p.general_wall_change))
            .map(percent)
            .unwrap_or_default();
        let published = detail
            .map(|d| crate::commands::show::short_date(&d.published_at))
            .unwrap_or_default();
        let mut cells = vec![
            Cell::painted(severity.clone(), crate::ui::severity_code(&severity)),
            Cell::plain(name),
            Cell::plain(ids),
            exploits,
            tests,
            Cell::plain(change),
            Cell::plain(perf),
            Cell::plain(published),
            Cell::plain(self.mode),
        ];
        if let Some(project) = project {
            cells.push(Cell::plain(project));
        }
        cells
    }

    /// The patch as a page of the browser from what the project records
    /// about it, under `why` the patch service's own account is missing
    /// (the end of a sentence: an error's text, which may run over
    /// several lines or end in a period of its own).
    fn local_page(&self, why: Option<&str>) -> Page {
        let mut lines: Vec<String> = why
            .map(|why| {
                let why = sanitize(why)
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                vec![
                    format!(
                        "The patch could not be read: {}.",
                        why.trim_end_matches('.')
                    ),
                    String::new(),
                    "What this project records:".to_string(),
                    String::new(),
                ]
            })
            .unwrap_or_default();
        lines.extend(self.detail.lines().map(str::to_string));
        Page {
            title: self.purl.clone(),
            lines,
            marks: Vec::new(),
        }
    }
}

/// How many advisory ids a row names before it counts the rest.
const IDS_SHOWN: usize = 2;

/// The columns of the interactive table, with what each gives way to on
/// a narrow terminal (the highest number first): the mode and the dates
/// before the measurements, the measurements before the advisories.
/// `projects`: the rows come from several project directories, so each
/// says whose it is.
fn columns(projects: bool) -> Vec<Column> {
    let mut columns: Vec<Column> = [
        ("SEVERITY", 0),
        ("PACKAGE", 0),
        ("FIXES", 1),
        ("EXPLOITS", 4),
        ("TESTS", 3),
        ("CHANGE", 5),
        ("PERF", 6),
        ("PUBLISHED", 7),
        ("MODE", 8),
    ]
    .into_iter()
    .map(|(title, gives_way)| Column { title, gives_way })
    .collect();
    if projects {
        columns.push(Column {
            title: "PROJECT",
            gives_way: 2,
        });
    }
    columns
}

/// How the table names each of `rows`' packages
/// ([`crate::ui::package_names`]).
fn names(rows: &[&Browse]) -> Vec<String> {
    crate::ui::package_names(&rows.iter().map(|row| row.purl.as_str()).collect::<Vec<_>>())
}

/// The table an interactive run opens with: what the project's own
/// records say about each patch. The patch service's account of them
/// fills in afterwards ([`Browse::cells`]).
fn table_of(rows: &[(Browse, Option<String>)]) -> Table {
    let patches: Vec<&Browse> = rows.iter().map(|(row, _)| row).collect();
    let projects = rows.iter().any(|(_, project)| project.is_some());
    let names = names(&patches);
    Table {
        title: format!(
            "{} in this project",
            crate::ui::plural(rows.len(), "patch", "patches")
        ),
        columns: columns(projects),
        rows: rows
            .iter()
            .zip(&names)
            .map(|((row, project), name)| row.cells(name, project.as_deref(), None))
            .collect(),
    }
}

/// Whether this run is someone at a terminal who can be shown a table to
/// browse: a human run on a terminal that can show the full-screen
/// browser ([`crate::ui::full_screen`]), that `--yes` did not ask to run
/// unattended. `--verbose` keeps the full listing.
fn interactive(common: &GlobalArgs) -> bool {
    !common.json && !common.silent && !common.yes && !common.verbose && crate::ui::full_screen()
}

/// Browse `rows` full-screen: the table goes up at once with what the
/// project records, the patch service's account of each patch (what it
/// fixes, what was measured about it, when it was published) fills in as
/// it arrives, and Enter opens a patch as a page: its summary and the
/// diff of every file it changes. Nothing is changed by any of it.
///
/// Returns the table as it stood when the user left, for the listing
/// that stays on the terminal. `--offline` asks the patch service
/// nothing: the rows keep what the project records, and a patch opens as
/// the project's own entry for it.
async fn browse(rows: Vec<(Browse, Option<String>)>, common: &GlobalArgs) -> Table {
    use futures_util::StreamExt as _;
    use socket_patch_core::utils::concurrent::api_concurrency_for;

    let table = table_of(&rows);
    let names = names(&rows.iter().map(|(row, _)| row).collect::<Vec<_>>());
    // The patch service's client is built once the table is up, by
    // whichever read needs it first: building it can mean a request (a
    // token with no organization named has its organization looked up),
    // and the listing itself needs none, so it never waits for one.
    // While the browser has the screen, core's advisories are muted: a
    // line printed under it would land in the middle of the table. The
    // one that explains what the table shows is printed after.
    // Both reads go through `show`'s source of patches, so a row and the
    // page it opens are read the same way, a refused token included.
    let connection = tokio::sync::OnceCell::<crate::commands::show::Source>::new();
    let connect = || async {
        if common.offline {
            return None;
        }
        Some(
            connection
                .get_or_init(|| async {
                    let overrides = common.api_client_overrides();
                    let client = socket_patch_core::api::client::get_api_client_with_overrides(
                        overrides.clone(),
                    )
                    .await
                    .0;
                    crate::commands::show::Source::new(client, overrides)
                })
                .await,
        )
    };
    socket_patch_core::utils::notice::set_output_mode(true, common.json);
    let (updates, received) = std::sync::mpsc::channel::<Update>();
    let (opened, mut opening) = tokio::sync::mpsc::unbounded_channel::<usize>();

    // The browser blocks on the keyboard, so it runs off the runtime's
    // threads. What it shows beyond the project's own records is read
    // here, beside it: the patch service's account of each patch, a few at
    // a time, and the page of each patch that is opened.
    let mut browser = tokio::task::spawn_blocking(move || {
        crate::ui::browser::run(table, received, move |row| {
            let _ = opened.send(row);
        })
    });
    let details = async {
        let Some(source) = connect().await else {
            return;
        };
        // What the project records as a patch's uuid comes from its own
        // files (a manifest anyone can write): only one that is a UUID
        // goes into a request to the patch service.
        let mut uuids: Vec<String> = rows
            .iter()
            .map(|(row, _)| row.uuid.clone())
            .filter(|uuid| socket_patch_core::utils::target::is_uuid_shaped(uuid))
            .collect();
        uuids.sort_unstable();
        uuids.dedup();
        if uuids.is_empty() {
            return;
        }
        let total = uuids.len();
        let _ = updates.send(Update::Note(format!("loading details 0/{total}")));
        let mut answers = futures_util::stream::iter(uuids)
            .map(|uuid| async move {
                let (_, answer) = source.ask(|client| client.fetch_patch_summary(&uuid)).await;
                (uuid, answer)
            })
            .buffer_unordered(api_concurrency_for(
                source.client().uses_public_proxy(),
                total,
            ));
        let mut done = 0;
        while let Some((uuid, answer)) = answers.next().await {
            done += 1;
            // A patch that could not be read keeps its row as it is.
            if let Ok(Some(detail)) = answer {
                for (index, ((row, project), name)) in rows.iter().zip(&names).enumerate() {
                    if row.uuid == uuid {
                        let cells = row.cells(name, project.as_deref(), Some(&detail));
                        let _ = updates.send(Update::Row(index, cells));
                    }
                }
            }
            let note = if done < total {
                format!("loading details {done}/{total}")
            } else {
                String::new()
            };
            let _ = updates.send(Update::Note(note));
        }
    };
    // A row opens as the page `show` opens for its patch, read the way
    // `show` reads it; only a patch the service cannot be asked about
    // opens as the project's own record.
    let style = crate::ui::Style::stderr();
    let page = |index: usize| {
        let (rows, connect, updates) = (&rows, &connect, &updates);
        async move {
            let Some((row, _)) = rows.get(index) else {
                return;
            };
            let page = match connect().await {
                Some(source) => {
                    match crate::commands::show::load_page(source, &row.uuid, style).await {
                        Ok(page) => page,
                        Err(why) => row.local_page(Some(&why)),
                    }
                }
                None => row.local_page(None),
            };
            let _ = updates.send(Update::Page(index, Ok(page)));
        }
    };
    let mut details = std::pin::pin!(details);
    let mut detailed = false;
    let mut pages = futures_util::stream::FuturesUnordered::new();
    let left = loop {
        tokio::select! {
            left = &mut browser => break left,
            () = &mut details, if !detailed => detailed = true,
            Some(index) = opening.recv() => pages.push(page(index)),
            Some(()) = pages.next(), if !pages.is_empty() => {}
        }
    };
    drop(pages);
    // The screen is the terminal's again: advisories print as before,
    // and the one the browser withheld that explains its rows is said
    // now (a token whose organization could not be found reads the
    // public service, which knows free patches only).
    socket_patch_core::utils::notice::set_output_mode(common.silent, common.json);
    if let Some(reason) = connection
        .get()
        .and_then(|source| source.client().org_unresolved())
    {
        eprintln!("Warning: {reason}");
    }
    match left {
        Ok(Ok(table)) => table,
        // No full-screen browser here (the terminal could not be set up
        // for one, or this is not Unix): the inline menu does the job.
        Ok(Err(table)) => {
            for line in listing_lines(&table) {
                println!("{line}");
            }
            println!();
            browse_inline(&rows, &table, common).await;
            Table {
                rows: Vec::new(),
                ..table
            }
        }
        // The browser's thread panicked: the terminal is restored by its
        // guard, and the listing is still owed.
        Err(_) => table_of(&rows),
    }
}

/// The inline stand-in for the full-screen browser: an arrow-key menu of
/// the rows under the printed listing; a pick prints `show`'s summary of
/// the patch (`show --stat`: its fixes, measurements and files, without
/// the diffs, which would push the menu off the screen) and comes back
/// to the menu.
async fn browse_inline(rows: &[(Browse, Option<String>)], table: &Table, common: &GlobalArgs) {
    let options: Vec<String> =
        crate::ui::browser::table_lines(table, usize::MAX, crate::ui::Style::PLAIN)
            .into_iter()
            .skip(1)
            .map(|line| line.trim_start().to_string())
            .collect();
    let mut at = 0;
    while let Ok(picked) =
        crate::ui::select_from("Open a patch (Esc to leave)", &options, at, common)
    {
        at = picked;
        let patch = &rows[picked].0;
        // A recorded uuid that is not one is no identifier to look up.
        let shown = !common.offline
            && socket_patch_core::utils::target::is_uuid_shaped(&patch.uuid)
            && crate::commands::show::run(crate::commands::show::ShowArgs {
                identifier: patch.uuid.clone(),
                common: common.clone(),
                files: Vec::new(),
                stat: true,
                no_pager: false,
            })
            .await
                == 0;
        if !shown {
            println!("{}", patch.detail);
        }
        println!();
    }
}

/// The listing an interactive run leaves on the terminal: the count,
/// then the table's rows as they stood ([`table_lines`]), cut to the
/// terminal's width.
///
/// [`table_lines`]: crate::ui::browser::table_lines
fn listing_lines(table: &Table) -> Vec<String> {
    let mut lines = vec![format!(
        "Found {}:",
        crate::ui::plural(table.rows.len(), "patch", "patches")
    )];
    lines.extend(crate::ui::browser::table_lines(
        table,
        crate::ui::stdout_width().saturating_sub(1),
        crate::ui::Style::stdout(),
    ));
    lines
}

/// The listing of a project in an error state. Used for the "manifest not
/// found" and "manifest unreadable" paths so they share the same JSON
/// shape as a successful list. `warnings` gathered before the error (a
/// corrupt redirect ledger) ride the error envelope too, so a JSON
/// consumer sees them on every exit path.
fn failed_listing(
    args: &ListArgs,
    code: &str,
    message: String,
    warnings: Vec<RunWarning>,
) -> Listed {
    // Errors print even under --silent; `--json` carries them instead.
    let mut notes = Vec::new();
    let envelope = if args.common.json {
        let mut env = Envelope::new(Command::List);
        env.mark_error(EnvelopeError::new(code, message));
        env.warnings = warnings;
        Some(env)
    } else {
        notes.push(format!("Error: {message}"));
        None
    };
    Listed {
        code: 1,
        notes,
        envelope,
        text: None,
        patches: 0,
        manifest_patches: 0,
        rows: Vec::new(),
    }
}

/// Manifest/ledger text is free-form (API-sourced descriptions): drop
/// control characters that would rewrite the terminal (ESC, a stray
/// `\r`), keeping newlines and tabs, and normalize `\r\n`.
fn sanitize(s: &str) -> String {
    s.replace("\r\n", "\n")
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
        .collect()
}

/// `"{indent}{label}: {value}"`, or `None` when the value is blank (no
/// dangling `License: ` line). Continuation lines of a multi-line value
/// are indented two past the label so they stay inside the entry.
fn field(indent: &str, label: &str, value: &str) -> Option<String> {
    let value = sanitize(value);
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let continuation = format!("\n{indent}  ");
    let body = value
        .lines()
        .map(str::trim_end)
        .collect::<Vec<_>>()
        .join(&continuation);
    Some(format!("{indent}{label}: {body}"))
}

/// One entry of the human listing (no trailing newline).
fn format_entry(entry: &ListEntry<'_>, color: bool) -> String {
    let patch = entry.record;
    let mut lines = vec![format!("Package: {}", sanitize(entry.purl))];
    lines.extend(field("  ", "UUID", &patch.uuid));
    if let Some((mode, ledger)) = ledger_label(entry.source) {
        // Same labeling rule as the JSON details.
        lines.push(format!("  Mode: {mode} (recorded in {ledger})"));
    }
    if entry.source == Store::Hosted {
        lines.push(format!(
            "  Mode: {} (wired in {})",
            crate::commands::HOSTED_MODE_LABEL,
            sanitize(&entry.lockfiles.join(", "))
        ));
    }
    lines.extend(field("  ", "Tier", &patch.tier));
    lines.extend(field("  ", "License", &patch.license));
    lines.extend(field("  ", "Exported", &patch.exported_at));
    lines.extend(field("  ", "Description", &patch.description));

    let mut vuln_entries: Vec<_> = patch.vulnerabilities.iter().collect();
    vuln_entries.sort_by(|a, b| a.0.cmp(b.0));
    if !vuln_entries.is_empty() {
        lines.push(format!("  Vulnerabilities ({}):", vuln_entries.len()));
        for (id, vuln) in &vuln_entries {
            let cve_list = if vuln.cves.is_empty() {
                String::new()
            } else {
                format!(" ({})", sanitize(&vuln.cves.join(", ")))
            };
            lines.push(format!("    - {}{cve_list}", sanitize(id)));
            // Upper-cased like scan's table, and colored by tier on a
            // color terminal.
            let severity = sanitize(vuln.severity.trim()).to_uppercase();
            if !severity.is_empty() {
                lines.push(format!(
                    "      Severity: {}",
                    crate::ui::severity(&severity, color)
                ));
            }
            lines.extend(field("      ", "Summary", &vuln.summary));
        }
    }

    let mut file_list: Vec<_> = patch.files.keys().collect();
    file_list.sort();
    if !file_list.is_empty() {
        lines.push(format!("  Files patched ({}):", file_list.len()));
        for file_path in &file_list {
            lines.push(format!("    - {}", sanitize(file_path)));
        }
    }
    lines.join("\n")
}

/// The human line for a project with nothing to list (an empty manifest, or
/// no manifest and no ledger records at all).
const NO_PATCHES: &str = "No patches in this project. Run `socket-patch scan`.";

/// The whole human listing for stdout: a count header, then the entries
/// separated by one blank line (none after the last).
fn format_listing(entries: &[ListEntry<'_>], color: bool) -> String {
    if entries.is_empty() {
        return NO_PATCHES.to_string();
    }
    let mut out = format!(
        "Found {}:\n\n",
        crate::ui::plural(entries.len(), "patch", "patches")
    );
    let blocks: Vec<String> = entries.iter().map(|e| format_entry(e, color)).collect();
    out.push_str(&blocks.join("\n\n"));
    out
}

pub async fn run(args: ListArgs) -> i32 {
    use crate::commands::projects_below::{self, CWD_NAME};
    apply_env_toggles(&args.common);
    // Someone at a terminal browses the patches; everyone else gets them
    // printed.
    let browsing = interactive(&args.common);
    if !browsing && !args.common.yes && !args.common.verbose {
        // On a terminal this would have been the table: say why not.
        crate::ui::note_agent_terminal(&args.common);
    }
    // Finding and reading the projects walks the checkout and parses its
    // lockfiles: the status line says so while it lasts. What a project
    // has to say on stderr is held back until the line is down.
    let mut status = crate::ui::StatusLine::stderr(args.common.json, args.common.silent);
    status.set("Finding patched projects");
    // What `scan` patched from this directory is listed from it: the
    // project at `--cwd`, then the patched project directories below it.
    let below = projects_below::patched(&args.common, projects_below::Depth::All).await;
    let here_patched =
        !below.projects.is_empty() && projects_below::cwd_is_patched(&args.common).await;
    status.finish();
    let loud = !args.common.json && !args.common.silent;
    if loud {
        below.print_notes();
    }
    // With nothing patched below, the project at `--cwd` is the plain
    // listing it always was. Above patched directories it is one of them
    // when it holds patches itself: listed first, under the heading scan
    // gives `--cwd`. A project's warnings and errors go to stderr as it is
    // read, so its heading goes out before it is.
    let mut here = here_patched;
    // The headings belong to the printed listing: a browsed one names each
    // row's project in a column.
    let headed = loud && !browsing;
    if here && headed {
        println!("{}", projects_below::heading(CWD_NAME));
    }
    status.set("Reading patches");
    let mut own = list_project(&args, browsing).await;
    status.finish();
    own.print_notes();
    // The listing has the last word on what `--cwd` holds.
    if !here && !below.projects.is_empty() && (own.patches > 0 || own.code != 0) {
        here = true;
        if headed {
            println!("{}", projects_below::heading(CWD_NAME));
        }
    }
    if here {
        if let Some(text) = &own.text {
            println!("{text}");
        }
    }
    let mut listed: Vec<(&str, Listed)> = Vec::new();
    for project in &below.projects {
        let child = ListArgs {
            common: project.common(&args.common),
        };
        if headed {
            println!("{}", projects_below::heading(&project.shown));
        }
        status.set(format!("Reading patches in {}", project.shown));
        let mut listing = list_project(&child, browsing).await;
        status.finish();
        listing.print_notes();
        if let Some(text) = &listing.text {
            println!("{text}");
        }
        listed.push((&project.shown, listing));
    }

    // Telemetry: `patch_listed`'s `patches_count` means "manifest patches"
    // to its consumers, so it counts the manifest records ONLY (0 on a
    // ledger-only project) rather than the listed entries.
    if own.code == 0 {
        let manifest_patches = own.manifest_patches
            + listed
                .iter()
                .map(|(_, listing)| listing.manifest_patches)
                .sum::<usize>();
        track_patch_listed(manifest_patches, &args.common.telemetry_auth()).await;
    }

    let below_failed = listed.iter().any(|(_, listing)| listing.code != 0);
    if let Some(env) = own.envelope.as_mut() {
        // One document: the envelope for `--cwd`, and beside it the one
        // each project's own `list --json` prints, with its directory.
        if !listed.is_empty() {
            let projects: Vec<serde_json::Value> = listed
                .iter()
                .filter_map(|(shown, listing)| {
                    let mut value = listing.envelope.as_ref()?.to_value();
                    value.as_object_mut()?.shift_insert(
                        0,
                        "path".to_string(),
                        serde_json::json!(shown),
                    );
                    Some(value)
                })
                .collect();
            env.set_extra("projects", serde_json::Value::Array(projects));
        }
        // The run's status goes with its exit code: a directory that could
        // not be listed carries its own error in `projects[]`.
        if below_failed {
            env.mark_partial_failure();
        }
        env.warnings.extend(
            below
                .notes
                .iter()
                .map(|note| RunWarning::new(projects_below::PROJECTS_BELOW_NOT_SEARCHED, note)),
        );
        println!("{}", env.to_pretty_json());
    } else if listed.is_empty() {
        if let Some(text) = &own.text {
            println!("{text}");
        }
    } else {
        if headed {
            let patches: usize = listed.iter().map(|(_, listing)| listing.patches).sum();
            println!(
                "\n{} in {}.",
                crate::ui::plural(
                    patches + if here { own.patches } else { 0 },
                    "patch",
                    "patches"
                ),
                below.covered(here)
            );
        }
        // Errors print even under --silent.
        let failed: Vec<&str> = (own.code != 0)
            .then_some(CWD_NAME)
            .into_iter()
            .chain(
                listed
                    .iter()
                    .filter(|(_, listing)| listing.code != 0)
                    .map(|(shown, _)| *shown),
            )
            .collect();
        if !failed.is_empty() {
            eprintln!(
                "Error: {} could not be listed: {}",
                crate::ui::plural(failed.len(), "project directory", "project directories"),
                failed.join(", ")
            );
        }
    }
    // Someone at a terminal browses every patch found, in one table, and
    // what it showed when they left is the listing that stays.
    let shown_own = here || listed.is_empty();
    let several = !listed.is_empty();
    let rows: Vec<(Browse, Option<String>)> = own
        .rows
        .drain(..)
        .filter(|_| shown_own)
        .map(|row| (row, several.then(|| CWD_NAME.to_string())))
        .chain(listed.iter_mut().flat_map(|(shown, listing)| {
            let shown = shown.to_string();
            listing
                .rows
                .drain(..)
                .map(move |row| (row, Some(shown.clone())))
        }))
        .collect();
    if !rows.is_empty() {
        let table = browse(rows, &args.common).await;
        if !table.rows.is_empty() {
            for line in listing_lines(&table) {
                println!("{line}");
            }
        }
    }
    listed
        .iter()
        .fold(own.code, |code, (_, listing)| code.max(listing.code))
}

/// Read the patches of the project at `args.common.cwd`: the manifest's,
/// the vendor ledger's and the hosted pins its lockfiles wire.
///
/// `browsing`: the run shows its patches in the full-screen table, so the
/// listing comes back as rows for it instead of text to print (a project
/// with nothing to list still says so in text).
async fn list_project(args: &ListArgs, browsing: bool) -> Listed {
    let manifest_path = args.common.resolved_manifest_path();

    // One load of the three stores, all from the SAME project as the
    // manifest (see below); each keeps list's own posture.
    let ctx = crate::commands::context::ProjectContext::new(&args.common);
    let loaded = ctx.loaded().await;
    let manifest = match &loaded.manifest {
        Ok(manifest) => manifest.as_ref(),
        Err(e) => {
            // Ledger records never mask a present-but-broken manifest: it
            // is an error state.
            let err = crate::json_envelope::manifest_load_error(&manifest_path, e);
            return failed_listing(args, &err.code, err.message, Vec::new());
        }
    };

    // Hosted-mode patches live ONLY in the lockfiles (v5 keeps no hosted
    // ledger) and vendored-mode patches ONLY in the vendor ledger, so
    // `list` consults both alongside the manifest — always from the SAME
    // project as the manifest (`project_root` steps out of the manifest's
    // `.socket/`): with `--manifest-path` pointing at another project,
    // reading the LOCAL cwd's state would interleave two projects' patches.
    //
    // A pre-v5 redirect ledger is read (never written) only to detail the
    // hosted pins it still describes; a malformed one degrades to "nothing
    // to consult", surfaced on stderr unless --silent, or in the envelope's
    // `warnings[]` under --json.
    let mut warnings: Vec<RunWarning> = Vec::new();
    // The human copies of those warnings: printed by the caller.
    let mut notes: Vec<String> = Vec::new();
    let legacy_redirect = match &loaded.redirect {
        Ok(state) => state.as_ref(),
        Err(corrupt) => {
            if args.common.json {
                warnings.push(RunWarning::new(
                    "redirect_ledger_corrupt",
                    corrupt.to_string(),
                ));
            } else if !args.common.silent {
                notes.push(format!("Warning: {corrupt}"));
            }
            None
        }
    };
    let inventory = crate::commands::hosted_inventory(&args.common, &ctx.root).await;
    let hosted = HostedListing::from_pins(&inventory.pins, legacy_redirect);
    // Contested hosted wiring cannot be listed as patches, but it is hosted
    // state: surface it (stderr / `warnings[]`), never hide it.
    let contested = inventory.contested_refusal();
    if let Some(detail) = &contested {
        if args.common.json {
            warnings.push(RunWarning::new("hosted_wiring_contested", detail.clone()));
        } else if !args.common.silent {
            notes.push(format!("Warning: {}", crate::ui::sentence_case(detail)));
        }
    }
    // A hosted `resolutions` selector (#1203) or uv override pin (#1445)
    // no lock installs any more is no patch either: say how to retire it.
    for pin in &inventory.stale {
        // Named by file and purl, as the contested refusal names files: a
        // hosted URL carries its grant token, which output never prints.
        // A uv pin lives in the lock's paired metadata (and the lock's
        // `[manifest]` record of it).
        let uv_metadata: Vec<String> = pin
            .files
            .iter()
            .filter_map(|f| socket_patch_core::utils::python_lock::paired_metadata_path(f))
            .collect();
        let detail = if uv_metadata.is_empty() {
            format!(
                "{} keeps a hosted `resolutions` entry for {} that no lockfile installs any \
                 more; `socket-patch remove {}` removes that entry alone",
                pin.files.join(", "),
                pin.purl,
                crate::ui::shell_word(&pin.purl)
            )
        } else {
            format!(
                "{} keeps a hosted `override-dependencies` pin and `[tool.uv.sources]` URL for \
                 {} that {} no longer installs; `socket-patch remove {}` removes that pin alone",
                uv_metadata.join(", "),
                pin.purl,
                pin.files.join(", "),
                crate::ui::shell_word(&pin.purl)
            )
        };
        if args.common.json {
            warnings.push(RunWarning::new("hosted_resolution_orphaned", detail));
        } else if !args.common.silent {
            notes.push(format!("Warning: {}", crate::ui::sentence_case(&detail)));
        }
    }
    // A broken vendor ledger degrades to nothing-to-list here (every path
    // that writes or attests from it fails closed instead), but says so:
    // on stderr, or in `warnings[]` under --json, where a `success`
    // envelope would otherwise read as "no vendored patches".
    let vendor_state = match &loaded.vendor {
        Ok(state) => Some(state),
        Err(e) => {
            let detail =
                format!("unreadable vendor ledger ({e}); its vendored patches are not listed");
            if args.common.json {
                warnings.push(RunWarning::new("vendor_state_unreadable", detail));
            } else if !args.common.silent {
                notes.push(format!("Warning: {detail}"));
            }
            None
        }
    };

    // `combined_entries` folds only real records in (a record-less legacy
    // vendor entry asserts no patch), so entry emptiness is the whole exit
    // predicate.
    let entries = combined_entries(manifest, &hosted, vendor_state);
    if manifest.is_none() && entries.is_empty() {
        if let Some(detail) = contested {
            let mut failed = failed_listing(args, "hosted_wiring_contested", detail, warnings);
            // The warnings read before the error come before it.
            failed.notes.splice(0..0, notes);
            return failed;
        }
    }

    // A successful list, exit 0, with or without records. No manifest
    // and no ledger record is just an empty project (normal for hosted
    // mode, which writes no manifest); only an unreadable or invalid
    // manifest or contested hosted wiring fails.
    let mut listed = Listed {
        code: 0,
        envelope: None,
        text: None,
        patches: entries.len(),
        manifest_patches: manifest.map_or(0, |m| m.patches.len()),
        rows: Vec::new(),
        notes,
    };
    if args.common.json {
        let mut env = build_list_envelope(&entries);
        env.warnings = warnings;
        listed.envelope = Some(env);
    } else if args.common.silent {
        // `--silent` is "errors only" (CLI_CONTRACT.md).
    } else if browsing && !entries.is_empty() {
        // Someone at a terminal browses the patches in a table; a pipe, a
        // log and `--verbose` get every entry in full.
        let color = crate::ui::stderr_color();
        listed.rows = entries
            .iter()
            .map(|entry| Browse::of(entry, color))
            .collect();
    } else {
        listed.text = Some(format_listing(&entries, crate::ui::stdout_color()));
    }
    listed
}

#[cfg(test)]
mod tests {
    //! Inline tests for `list` output. Pin the envelope shape so downstream
    //! consumers (PR bots, dashboards) can rely on it.
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
    use socket_patch_core::vendor::state::VendorEntry;
    use std::collections::HashMap;

    /// Envelope for a manifest-only listing (no hosted pins, no vendor
    /// ledger) — the shape most tests below need.
    fn manifest_envelope(manifest: &PatchManifest) -> Envelope {
        build_list_envelope(&combined_entries(Some(manifest), &[], None))
    }

    fn sample_manifest() -> PatchManifest {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "b".repeat(64),
                after_hash: "a".repeat(64),
            },
        );

        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-xyz-1234".to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2024-12345".to_string()],
                summary: "Prototype Pollution".to_string(),
                severity: "high".to_string(),
                description: "Some description".to_string(),
            },
        );

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            PatchRecord {
                uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: vulns,
                description: "Fixes prototype pollution".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );

        PatchManifest {
            patches,
            setup: None,
        }
    }

    fn browse_row(purl: &str, severity: &str, ids: &[&str], mode: &'static str) -> Browse {
        Browse {
            purl: purl.to_string(),
            uuid: format!("{:08x}-1111-4111-8111-111111111111", purl.len()),
            severity: severity.to_string(),
            ids: ids.iter().map(|id| id.to_string()).collect(),
            mode,
            detail: format!("Package: {purl}\n  UUID: 1234"),
        }
    }

    fn text(cells: &[Cell]) -> Vec<&str> {
        cells.iter().map(|cell| cell.text.as_str()).collect()
    }

    /// The table someone at a terminal browses opens with what the project
    /// records: a row per patch with its worst severity (painted), the
    /// advisories it fixes and the mode it is patched in.
    #[test]
    fn the_browsed_table_opens_with_what_the_project_records() {
        let manifest = sample_manifest();
        let entries = combined_entries(Some(&manifest), &[], None);
        let row = Browse::of(&entries[0], false);
        assert_eq!(row.purl, "pkg:npm/minimist@1.2.2");
        assert_eq!(row.severity, "HIGH");
        assert_eq!(row.ids, ["CVE-2024-12345"]);
        assert_eq!(row.mode, "agent");
        assert!(row.detail.starts_with("Package: pkg:npm/minimist@1.2.2"));

        let rows = vec![
            (row, None),
            (
                browse_row(
                    "pkg:npm/%40scope/a-much-longer-name@10.0.0",
                    "CRITICAL",
                    &["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"],
                    "vendored",
                ),
                None,
            ),
            // A hosted pin records only its uuid: no severity, no ids.
            (browse_row("pkg:npm/undici@6.27.0", "", &[], "hosted"), None),
        ];
        let table = table_of(&rows);
        assert_eq!(table.title, "3 patches in this project");
        assert_eq!(
            table.columns.iter().map(|c| c.title).collect::<Vec<_>>(),
            [
                "SEVERITY",
                "PACKAGE",
                "FIXES",
                "EXPLOITS",
                "TESTS",
                "CHANGE",
                "PERF",
                "PUBLISHED",
                "MODE"
            ]
        );
        assert_eq!(
            text(&table.rows[0]),
            [
                "HIGH",
                "minimist@1.2.2",
                "CVE-2024-12345",
                "",
                "",
                "",
                "",
                "",
                "agent"
            ]
        );
        assert_eq!(table.rows[0][0].paint, Some("31"));
        assert_eq!(
            text(&table.rows[1])[..3],
            [
                "CRITICAL",
                "@scope/a-much-longer-name@10.0.0",
                "CVE-2026-1, CVE-2026-2 (+1)"
            ]
        );
        assert_eq!(table.rows[1][0].paint, Some("91"));
        assert_eq!(text(&table.rows[2])[..3], ["", "undici@6.27.0", ""]);
        assert_eq!(table.rows[2][0].paint, None);
        // The listing that stays on the terminal is those rows in columns;
        // the ones nothing is known for yet take no room.
        assert_eq!(
            crate::ui::browser::table_lines(&table, 200, crate::ui::Style::PLAIN),
            [
                "  SEVERITY  PACKAGE                           FIXES                        MODE",
                "  HIGH      minimist@1.2.2                    CVE-2024-12345               agent",
                "  CRITICAL  @scope/a-much-longer-name@10.0.0  CVE-2026-1, CVE-2026-2 (+1)  vendored",
                "            undici@6.27.0                                                  hosted",
            ]
        );

        // Rows of several project directories say whose they are, and
        // packages of two ecosystems are named by purl.
        let mixed = vec![
            (
                browse_row("pkg:npm/undici@6.27.0", "", &[], "hosted"),
                Some(".".to_string()),
            ),
            (
                browse_row("pkg:pypi/requests@2.31.0", "", &[], "hosted"),
                Some("services/worker".to_string()),
            ),
        ];
        let table = table_of(&mixed);
        assert_eq!(table.columns.last().map(|c| c.title), Some("PROJECT"));
        assert_eq!(
            text(&table.rows[1])[1..],
            [
                "pkg:pypi/requests@2.31.0",
                "",
                "",
                "",
                "",
                "",
                "",
                "hosted",
                "services/worker"
            ]
        );
    }

    /// The patch service's account of a patch fills its row in: what was
    /// measured about it (green when every exploit is blocked and every
    /// test passes, yellow when not), the size and cost of the change and
    /// when it was published. It also names the advisories of a patch the
    /// project records by uuid alone.
    #[test]
    fn a_row_fills_in_from_the_patch_service() {
        use socket_patch_core::api::types::{
            PatchDiffSize, PatchPerformance, PatchResponse, PatchStatistics, VulnerabilityResponse,
        };
        let detail = |statistics: Option<PatchStatistics>| PatchResponse {
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            purl: "pkg:npm/undici@6.27.0".to_string(),
            published_at: "Fri, 14 Nov 2026 07:13:44 GMT".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::from([
                (
                    "GHSA-aaaa-bbbb-cccc".to_string(),
                    VulnerabilityResponse {
                        cves: vec!["CVE-2026-84961".to_string()],
                        summary: "A summary".to_string(),
                        severity: "high".to_string(),
                        description: String::new(),
                    },
                ),
                (
                    "GHSA-dddd-eeee-ffff".to_string(),
                    VulnerabilityResponse {
                        cves: Vec::new(),
                        summary: "Another".to_string(),
                        severity: "critical".to_string(),
                        description: String::new(),
                    },
                ),
            ]),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
            statistics,
        };
        let measured = PatchStatistics {
            diff: Some(PatchDiffSize {
                lines_added: 26,
                lines_removed: 22,
                files_changed: 2,
            }),
            performance: Some(PatchPerformance {
                general_wall_change: Some(0.2),
                hot_wall_change: Some(0.008),
                peak_mem_change: None,
            }),
            ..crate::commands::measured::tests::stats(2, 34, 35)
        };

        // A hosted pin: everything comes from the patch service.
        let pin = browse_row("pkg:npm/undici@6.27.0", "", &[], "hosted");
        let cells = pin.cells("undici@6.27.0", None, Some(&detail(Some(measured))));
        assert_eq!(
            text(&cells),
            [
                "CRITICAL",
                "undici@6.27.0",
                "CVE-2026-84961, GHSA-dddd-eeee-ffff",
                "2/2",
                "34/35",
                "+26 -22",
                "+0.8%",
                "14 Nov 2026",
                "hosted"
            ]
        );
        assert_eq!(cells[0].paint, Some("91"));
        assert_eq!(cells[3].paint, Some("32"), "every exploit blocked");
        assert_eq!(cells[4].paint, Some("33"), "a test still failing");

        // What the project records about a patch stays: the service only
        // adds to it. A patch that was never measured shows its date.
        let recorded = browse_row("pkg:npm/undici@6.27.0", "LOW", &["CVE-2020-1"], "agent");
        assert_eq!(
            text(&recorded.cells("undici@6.27.0", Some("."), Some(&detail(None)))),
            [
                "LOW",
                "undici@6.27.0",
                "CVE-2020-1",
                "",
                "",
                "",
                "",
                "14 Nov 2026",
                "agent",
                "."
            ]
        );
    }

    /// With the patch service out of reach (or `--offline`) a patch opens
    /// as what the project records about it, under the reason.
    #[test]
    fn a_patch_opens_as_the_projects_record_when_the_service_cannot_be_asked() {
        let row = browse_row("pkg:npm/undici@6.27.0", "", &[], "hosted");
        let page = row.local_page(None);
        assert_eq!(page.title, "pkg:npm/undici@6.27.0");
        assert_eq!(
            page.lines,
            ["Package: pkg:npm/undici@6.27.0", "  UUID: 1234"]
        );
        assert!(page.marks.is_empty());
        assert_eq!(
            row.local_page(Some("timed out")).lines,
            [
                "The patch could not be read: timed out.",
                "",
                "What this project records:",
                "",
                "Package: pkg:npm/undici@6.27.0",
                "  UUID: 1234"
            ]
        );
        // An error's text is one line of the page whatever its shape: a
        // period of its own is not doubled, and a body that runs over
        // several lines, or carries an escape sequence, cannot break the
        // frame.
        for (why, line) in [
            (
                "Rate limit exceeded. Please try again later.",
                "The patch could not be read: Rate limit exceeded. Please try again later.",
            ),
            (
                "status 500:\n  upstream\tfailed\r\n",
                "The patch could not be read: status 500: upstream failed.",
            ),
            (
                "bad \u{1b}[31mbody",
                "The patch could not be read: bad [31mbody.",
            ),
        ] {
            assert_eq!(row.local_page(Some(why)).lines[0], line);
        }
    }

    /// A manifest with several patches, each carrying multiple
    /// vulnerabilities and files, all inserted in deliberately
    /// non-alphabetical order. Used to pin the stable sort order the
    /// envelope must impose regardless of HashMap iteration.
    fn multi_entry_manifest() -> PatchManifest {
        fn record(uuid: &str, vuln_ids: &[&str], file_paths: &[&str]) -> PatchRecord {
            let mut files = HashMap::new();
            for fp in file_paths {
                files.insert(
                    fp.to_string(),
                    PatchFileInfo {
                        before_hash: "b".repeat(64),
                        after_hash: "a".repeat(64),
                    },
                );
            }
            let mut vulns = HashMap::new();
            for id in vuln_ids {
                vulns.insert(
                    id.to_string(),
                    VulnerabilityInfo {
                        cves: vec![],
                        summary: "s".to_string(),
                        severity: "high".to_string(),
                        description: "d".to_string(),
                    },
                );
            }
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: vulns,
                description: "desc".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            }
        }

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/zeta@1.0.0".to_string(),
            record(
                "uuid-z",
                &["GHSA-zzzz-2222-3333", "GHSA-aaaa-2222-3333"],
                &["z/b.js", "z/a.js"],
            ),
        );
        patches.insert(
            "pkg:npm/alpha@1.0.0".to_string(),
            record("uuid-a", &["GHSA-mmmm-2222-3333"], &["a/zz.js", "a/aa.js"]),
        );
        patches.insert(
            "pkg:npm/mid@1.0.0".to_string(),
            record("uuid-m", &["GHSA-cccc-2222-3333"], &["m/x.js"]),
        );
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn list_emits_discovered_event_per_patch() {
        let env = manifest_envelope(&sample_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["command"], "list");
        assert_eq!(v["status"], "success");
        assert_eq!(v["summary"]["discovered"], 1);
        let events = v["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], "discovered");
        assert_eq!(events[0]["purl"], "pkg:npm/minimist@1.2.2");
        assert_eq!(events[0]["uuid"], "11111111-1111-4111-8111-111111111111");
    }

    #[test]
    fn list_event_carries_vulnerability_details() {
        let env = manifest_envelope(&sample_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let event = &v["events"][0];
        assert_eq!(event["details"]["tier"], "free");
        assert_eq!(event["details"]["license"], "MIT");
        let vulns = event["details"]["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0]["id"], "GHSA-xyz-1234");
        assert_eq!(vulns[0]["severity"], "high");
        assert_eq!(vulns[0]["cves"][0], "CVE-2024-12345");
    }

    #[test]
    fn empty_manifest_emits_empty_events() {
        let env = manifest_envelope(&PatchManifest::new());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
        assert_eq!(v["summary"]["discovered"], 0);
    }

    // -- Stable ordering -------------------------------------------------
    // Pin the sorted events / vulnerabilities / files contract so consumers
    // can diff `list --json` output.

    #[test]
    fn events_are_sorted_by_purl() {
        let env = manifest_envelope(&multi_entry_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let purls: Vec<&str> = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["purl"].as_str().unwrap())
            .collect();
        assert_eq!(
            purls,
            vec![
                "pkg:npm/alpha@1.0.0",
                "pkg:npm/mid@1.0.0",
                "pkg:npm/zeta@1.0.0",
            ]
        );
    }

    #[test]
    fn vulnerabilities_are_sorted_by_id() {
        let env = manifest_envelope(&multi_entry_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        // The zeta entry carries two advisories inserted out of order.
        let zeta = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["purl"] == "pkg:npm/zeta@1.0.0")
            .unwrap();
        let ids: Vec<&str> = zeta["details"]["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|vuln| vuln["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["GHSA-aaaa-2222-3333", "GHSA-zzzz-2222-3333"]);
    }

    #[test]
    fn files_are_sorted_by_path() {
        let env = manifest_envelope(&multi_entry_manifest());
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let zeta = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["purl"] == "pkg:npm/zeta@1.0.0")
            .unwrap();
        let paths: Vec<&str> = zeta["files"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap())
            .collect();
        assert_eq!(paths, vec!["z/a.js", "z/b.js"]);
    }

    fn hosted(purl: &str, record: PatchRecord) -> HostedListing {
        HostedListing {
            purl: purl.to_string(),
            record,
            lockfiles: vec!["package-lock.json".to_string()],
        }
    }

    /// Hosted pins fold into the envelope labeled apart from manifest
    /// entries: `details.mode` / `details.lockfiles` ride the hosted events
    /// ONLY (additive keys), and the global purl sort holds with the
    /// manifest entry first when one purl appears in both stores.
    #[test]
    fn hosted_pins_are_labeled_and_interleaved() {
        let manifest = sample_manifest();
        let mut hosted_record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        hosted_record.uuid = "22222222-2222-4222-8222-222222222222".to_string();
        // Same purl as the manifest entry (coexistence) + a distinct one.
        let pins = vec![
            hosted("pkg:npm/minimist@1.2.2", hosted_record.clone()),
            hosted("pkg:npm/aaa-hosted@1.0.0", hosted_record),
        ];

        let env = build_list_envelope(&combined_entries(Some(&manifest), &pins, None));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["summary"]["discovered"], 3);
        let events = v["events"].as_array().unwrap();
        let listed: Vec<(&str, bool)> = events
            .iter()
            .map(|e| {
                (
                    e["purl"].as_str().unwrap(),
                    e["details"]["mode"] == "hosted",
                )
            })
            .collect();
        assert_eq!(
            listed,
            vec![
                ("pkg:npm/aaa-hosted@1.0.0", true),
                ("pkg:npm/minimist@1.2.2", false),
                ("pkg:npm/minimist@1.2.2", true),
            ],
            "purl-sorted, manifest before hosted on a tie: {v}"
        );
        assert!(
            events[1]["details"].get("mode").is_none()
                && events[1]["details"].get("ledger").is_none(),
            "manifest entries must NOT carry the hosted labels: {v}"
        );
        assert_eq!(
            events[0]["details"]["lockfiles"],
            serde_json::json!(["package-lock.json"])
        );
        assert!(
            events[0]["details"].get("ledger").is_none(),
            "a hosted pin names no ledger: {v}"
        );
    }

    /// A pre-v5 redirect ledger details only the pins it records with the
    /// same uuid; any other pin lists with its uuid alone.
    #[test]
    fn legacy_ledger_details_only_matching_pins() {
        let manifest = sample_manifest();
        let record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        let mut legacy = RedirectState::new();
        legacy
            .records
            .insert("pkg:npm/minimist@1.2.2".to_string(), record.clone());
        let pin = |purl: &str, uuid: &str| HostedPin {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            files: vec!["yarn.lock".to_string()],
        };
        let listings = HostedListing::from_pins(
            &[
                pin("pkg:npm/minimist@1.2.2", &record.uuid),
                pin(
                    "pkg:npm/other@1.0.0",
                    "33333333-3333-4333-8333-333333333333",
                ),
            ],
            Some(&legacy),
        );
        assert_eq!(listings[0].record, record);
        assert_eq!(
            listings[1].record.uuid,
            "33333333-3333-4333-8333-333333333333"
        );
        assert!(listings[1].record.vulnerabilities.is_empty());
        assert_eq!(listings[1].lockfiles, vec!["yarn.lock".to_string()]);
    }

    /// A hosted-only listing (no manifest at all) — the shape a purely
    /// hosted-wired project produces.
    #[test]
    fn hosted_only_entries_build_a_success_envelope() {
        let manifest = sample_manifest();
        let pins = vec![hosted(
            "pkg:npm/minimist@1.2.2",
            manifest.patches["pkg:npm/minimist@1.2.2"].clone(),
        )];
        let env = build_list_envelope(&combined_entries(None, &pins, None));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success");
        assert_eq!(v["summary"]["discovered"], 1);
        assert_eq!(v["events"][0]["details"]["mode"], "hosted");
    }

    fn as_state(entries: &HashMap<String, VendorEntry>) -> VendorState {
        VendorState {
            entries: entries.clone(),
            ..VendorState::new()
        }
    }

    /// A vendor-ledger entry: `detached` with the embedded record when
    /// `record` is given (the manifest-free vendored posture), a legacy
    /// manifest-tracked entry (no record of its own) otherwise. Built from
    /// the on-disk JSON shape so the fixture follows the ledger schema.
    fn vendor_entry(purl: &str, record: Option<PatchRecord>) -> VendorEntry {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "basePurl": purl,
            "uuid": record
                .as_ref()
                .map_or("legacy-uuid", |r| r.uuid.as_str()),
            "artifact": { "path": ".socket/vendor/npm/x/pkg.tgz" },
            "wiring": [],
            "detached": record.is_some(),
            "record": record,
        }))
        .expect("vendor entry fixture deserializes")
    }

    /// Vendor-ledger records fold in labeled `vendored` with their ledger,
    /// sort after the hosted record on a purl tie, and a legacy
    /// manifest-tracked entry (no embedded record) never double-lists its
    /// manifest purl. A vendored-only listing is a success envelope — the
    /// hosted-only rule applied to the manifest-free vendored mode.
    #[test]
    fn vendored_ledger_records_are_labeled_and_sorted_last() {
        let manifest = sample_manifest();
        let record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        let pins = vec![hosted("pkg:npm/minimist@1.2.2", record.clone())];
        let mut detached = record.clone();
        detached.uuid = "44444444-4444-4444-8444-444444444444".to_string();
        let mut vendor = HashMap::new();
        vendor.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            vendor_entry("pkg:npm/minimist@1.2.2", Some(detached)),
        );
        vendor.insert(
            "pkg:npm/zzz-vendored@1.0.0".to_string(),
            vendor_entry("pkg:npm/zzz-vendored@1.0.0", Some(record)),
        );
        // Legacy manifest-tracked vendoring: the manifest holds the record.
        vendor.insert(
            "pkg:npm/minimist@1.2.2#legacy".to_string(),
            vendor_entry("pkg:npm/minimist@1.2.2", None),
        );

        let env = build_list_envelope(&combined_entries(
            Some(&manifest),
            &pins,
            Some(&as_state(&vendor)),
        ));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let listed: Vec<(&str, &str)> = v["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["purl"].as_str().unwrap(),
                    e["details"]["mode"].as_str().unwrap_or("manifest"),
                )
            })
            .collect();
        assert_eq!(
            listed,
            vec![
                ("pkg:npm/minimist@1.2.2", "manifest"),
                ("pkg:npm/minimist@1.2.2", "hosted"),
                ("pkg:npm/minimist@1.2.2", "vendored"),
                ("pkg:npm/zzz-vendored@1.0.0", "vendored"),
            ],
            "purl-sorted, manifest < hosted < vendored on a tie, record-less entries skipped: {v}"
        );
        let events = v["events"].as_array().unwrap();
        assert_eq!(
            events[2]["details"]["ledger"], ".socket/vendor/state.json",
            "{v}"
        );
        assert_eq!(
            events[2]["uuid"], "44444444-4444-4444-8444-444444444444",
            "the ledger's embedded record is the one listed: {v}"
        );

        let only = build_list_envelope(&combined_entries(None, &[], Some(&as_state(&vendor))));
        let v: serde_json::Value = serde_json::from_str(&only.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "success", "{v}");
        assert_eq!(v["summary"]["discovered"], 2, "{v}");
    }

    /// The ledger entry the manifest-driven standalone `vendor` writes: NOT
    /// detached, with the record embedded as a fallback copy.
    fn standalone_vendor_entry(base_purl: &str, record: PatchRecord) -> VendorEntry {
        let mut entry = vendor_entry(base_purl, Some(record));
        entry.detached = false;
        entry
    }

    /// A standalone `vendor` entry's embedded fallback record lists exactly
    /// when `vex` would attest from it — no manifest entry covers the entry
    /// (by ledger key or base purl). With no manifest at all it lists
    /// labeled `vendored`, so a manifest-less checkout never reads "no
    /// patches" while its VEX document attests the patch; while the manifest
    /// covers it, the manifest's record IS its record (no double listing).
    #[test]
    fn standalone_vendor_fallback_record_lists_only_when_the_manifest_does_not_cover_it() {
        let manifest = sample_manifest();
        let record = manifest.patches["pkg:npm/minimist@1.2.2"].clone();
        let mut other = record.clone();
        other.uuid = "55555555-5555-4555-8555-555555555555".to_string();
        let mut vendor = HashMap::new();
        // Covered by the manifest's exact key.
        vendor.insert(
            "pkg:npm/minimist@1.2.2".to_string(),
            standalone_vendor_entry("pkg:npm/minimist@1.2.2", record.clone()),
        );
        // Covered through its base purl (a qualified ledger key).
        vendor.insert(
            "pkg:npm/minimist@1.2.2?variant=x".to_string(),
            standalone_vendor_entry("pkg:npm/minimist@1.2.2", record.clone()),
        );
        // Dropped from the manifest while the ledger still holds it.
        vendor.insert(
            "pkg:npm/left-pad@1.3.0".to_string(),
            standalone_vendor_entry("pkg:npm/left-pad@1.3.0", other),
        );

        let listed = |entries: &[ListEntry<'_>]| -> Vec<(String, String, String)> {
            let env = build_list_envelope(entries);
            let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
            v["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["purl"].as_str().unwrap().to_string(),
                        e["details"]["mode"]
                            .as_str()
                            .unwrap_or("manifest")
                            .to_string(),
                        e["uuid"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        };

        assert_eq!(
            listed(&combined_entries(
                Some(&manifest),
                &[],
                Some(&as_state(&vendor))
            )),
            vec![
                (
                    "pkg:npm/left-pad@1.3.0".to_string(),
                    "vendored".to_string(),
                    "55555555-5555-4555-8555-555555555555".to_string(),
                ),
                (
                    "pkg:npm/minimist@1.2.2".to_string(),
                    "manifest".to_string(),
                    "11111111-1111-4111-8111-111111111111".to_string(),
                ),
            ],
            "covered fallback copies stay behind the manifest record; the uncovered one lists"
        );

        // No manifest at all: every fallback copy stands on its own.
        let only = listed(&combined_entries(None, &[], Some(&as_state(&vendor))));
        assert_eq!(only.len(), 3, "{only:?}");
        assert!(
            only.iter().all(|(_, mode, _)| mode == "vendored"),
            "{only:?}"
        );
    }

    fn record_with(description: &str, license: &str, severity: &str, summary: &str) -> PatchRecord {
        let mut rec = sample_manifest().patches["pkg:npm/minimist@1.2.2"].clone();
        rec.description = description.to_string();
        rec.license = license.to_string();
        let vuln = rec.vulnerabilities.get_mut("GHSA-xyz-1234").unwrap();
        vuln.severity = severity.to_string();
        vuln.summary = summary.to_string();
        rec
    }

    fn entry<'a>(purl: &'a str, record: &'a PatchRecord) -> ListEntry<'a> {
        ListEntry {
            purl,
            record,
            source: Store::Manifest,
            lockfiles: &[],
        }
    }

    #[test]
    fn format_entry_exact_layout() {
        let rec = record_with("Some fix", "MIT", "high", "Prototype Pollution");
        assert_eq!(
            format_entry(&entry("pkg:npm/minimist@1.2.2", &rec), false),
            "Package: pkg:npm/minimist@1.2.2\n\
             \x20 UUID: 11111111-1111-4111-8111-111111111111\n\
             \x20 Tier: free\n\
             \x20 License: MIT\n\
             \x20 Exported: 2024-01-01T00:00:00Z\n\
             \x20 Description: Some fix\n\
             \x20 Vulnerabilities (1):\n\
             \x20   - GHSA-xyz-1234 (CVE-2024-12345)\n\
             \x20     Severity: HIGH\n\
             \x20     Summary: Prototype Pollution\n\
             \x20 Files patched (1):\n\
             \x20   - package/index.js"
        );
    }

    #[test]
    fn format_entry_indents_multiline_and_skips_blank_fields() {
        let rec = record_with("Multi\r\nline  \ndescription", "", "", "");
        let out = format_entry(&entry("pkg:npm/x@1", &rec), false);
        assert!(
            out.contains("  Description: Multi\n    line\n    description\n"),
            "{out}"
        );
        for gone in ["License:", "Severity:", "Summary:"] {
            assert!(!out.contains(gone), "blank {gone} must be skipped: {out}");
        }
        assert!(
            !out.lines().any(|l| l.ends_with(' ')),
            "no trailing spaces: {out:?}"
        );
    }

    #[test]
    fn format_entry_strips_terminal_control_sequences() {
        let rec = record_with("evil\x1b[2J\x07 text\rmore", "MIT", "low", "s\x1b]0;t\x07");
        let out = format_entry(&entry("pkg:npm/x@1", &rec), false);
        assert!(
            !out.contains('\x1b') && !out.contains('\x07') && !out.contains('\r'),
            "{out:?}"
        );
        assert!(out.contains("  Description: evil[2J textmore"), "{out}");
    }

    #[test]
    fn format_entry_colors_severity_only_when_asked() {
        let rec = record_with("d", "MIT", "critical", "s");
        let plain = format_entry(&entry("pkg:npm/x@1", &rec), false);
        assert!(!plain.contains('\x1b'));
        let colored = format_entry(&entry("pkg:npm/x@1", &rec), true);
        assert!(
            colored.contains("Severity: \x1b[91mCRITICAL\x1b[0m"),
            "{colored:?}"
        );
    }

    #[test]
    fn format_entry_multibyte_passes_through() {
        let rec = record_with("修复 — é", "MIT", "medium", "漏洞");
        let out = format_entry(&entry("pkg:npm/日本@1", &rec), false);
        assert!(out.starts_with("Package: pkg:npm/日本@1\n"), "{out}");
        assert!(out.contains("  Description: 修复 — é\n"), "{out}");
        assert!(out.contains("      Summary: 漏洞\n"), "{out}");
    }

    #[test]
    fn format_listing_counts_and_separates_entries() {
        assert_eq!(format_listing(&[], false), NO_PATCHES);
        let manifest = sample_manifest();
        let one = combined_entries(Some(&manifest), &[], None);
        let out = format_listing(&one, false);
        assert!(out.starts_with("Found 1 patch:\n\nPackage: "), "{out}");
        assert!(!out.ends_with('\n'), "no trailing blank line: {out:?}");

        let multi = multi_entry_manifest();
        let many = combined_entries(Some(&multi), &[], None);
        let out = format_listing(&many, false);
        assert!(
            out.starts_with(&format!("Found {} patches:\n\n", many.len())),
            "{out}"
        );
        // Exactly one blank line between entries, none doubled.
        assert_eq!(out.matches("\n\nPackage: ").count(), many.len());
        assert!(!out.contains("\n\n\n"), "{out:?}");
    }
}
