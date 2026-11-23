//! `socket-patch report`: tell Socket that a patch broke something.
//!
//! The report names each patch by UUID with its ecosystem and patch mode,
//! the reason, and the message the user typed. It changes nothing in the
//! project: it reads which patches the project holds (to turn a package
//! name into a patch) and sends one request.

use clap::Args;
use socket_patch_core::telemetry::{
    fitted_report_message, send_patch_report, PatchOutcome, ReportReason, MAX_REPORT_MESSAGE_CHARS,
    MODE_AGENT, MODE_HOSTED, MODE_UNKNOWN, MODE_VENDORED, OUTCOME_REPORTED,
};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::utils::target::{Target, TargetKind};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::context::ProjectContext;
use crate::telemetry_outcomes::ecosystem_of;
use crate::ui;

#[derive(Args)]
pub struct ReportArgs {
    /// Patches that broke something: UUIDs, PURLs or package names.
    ///
    /// A PURL or a package name selects the patches this project holds for
    /// that package (the ones `list` shows). A UUID names a patch whether
    /// or not the project still holds it, so a patch can be reported after
    /// it was rolled back.
    #[arg(required = true, value_name = "PATCH")]
    pub targets: Vec<String>,

    /// What the patch broke.
    #[arg(long, value_enum, value_name = "REASON", default_value_t = Reason::Other)]
    pub reason: Reason,

    /// What went wrong, in your own words.
    ///
    /// Sent on one line, with the credentials of any URL and your home
    /// directory redacted, and cut to 1000 characters. `--dry-run` shows
    /// the message as it would be sent.
    // No `-m`: that letter is kept free (it was `--manifest-path`).
    #[arg(long, value_name = "TEXT")]
    pub message: Option<String>,

    #[command(flatten)]
    pub common: GlobalArgs,
}

// The help text above promises the cap core applies.
const _: () = assert!(MAX_REPORT_MESSAGE_CHARS == 1000);

/// What a reported patch broke (`--reason`).
// The `///` docs on the variants are user-facing `--help` text; keep
// implementation notes in `//` comments.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The project no longer installs, compiles or builds
    Build,
    /// The project's tests fail
    Tests,
    /// The project misbehaves when it runs
    Runtime,
    /// Something else (say what with --message)
    Other,
}

impl Reason {
    /// The reason as the report carries it.
    fn core(self) -> ReportReason {
        match self {
            Reason::Build => ReportReason::BreaksBuild,
            Reason::Tests => ReportReason::BreaksTests,
            Reason::Runtime => ReportReason::BreaksRuntime,
            Reason::Other => ReportReason::Other,
        }
    }

    /// The word the user typed, as `--json` output echoes it.
    fn word(self) -> &'static str {
        match self {
            Reason::Build => "build",
            Reason::Tests => "tests",
            Reason::Runtime => "runtime",
            Reason::Other => "other",
        }
    }

    /// The reason as the end of "Reported 1 patch to Socket as …".
    fn phrase(self) -> &'static str {
        match self {
            Reason::Build => "breaking the build",
            Reason::Tests => "breaking tests",
            Reason::Runtime => "breaking at run time",
            Reason::Other => "broken",
        }
    }
}

/// One patch the project holds, in one mode.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    /// The purl its store records it under.
    purl: String,
    /// A vendor ledger entry's base purl: its key may be qualified or
    /// case-encoded, and the base is the spelling a user types.
    base: Option<String>,
    uuid: String,
    mode: &'static str,
}

impl Held {
    fn matches(&self, target: &Target) -> bool {
        target.matches_patch(&self.purl, &self.uuid)
            || self
                .base
                .as_deref()
                .is_some_and(|base| target.matches_patch(base, &self.uuid))
    }

    /// The purl that names this patch's package.
    fn package(&self) -> &str {
        self.base.as_deref().unwrap_or(&self.purl)
    }

    /// Which copy of a package the build consumes when the project holds
    /// patches for it in several modes (lower wins): a vendored artifact
    /// or a hosted pin is what the lockfile installs, whatever the agent
    /// manifest also records.
    fn rank(&self) -> u8 {
        match self.mode {
            MODE_VENDORED => 0,
            MODE_HOSTED => 1,
            _ => 2,
        }
    }
}

/// The patches of the project at `--cwd`, and why a store that could not
/// be read is missing from them.
struct Project {
    held: Vec<Held>,
    /// `(code, message)` of the first store that could not be read.
    unreadable: Option<(String, String)>,
}

/// Every patch the project at `--cwd` holds: the vendor ledger's entries
/// (each under its own UUID, with or without an embedded record), the
/// manifest's (agent mode) and the hosted pins of its lockfiles. A store
/// that cannot be read holds nothing here, and says so in `unreadable`:
/// a report by UUID must not need a healthy project.
async fn held_patches(common: &GlobalArgs) -> Project {
    let ctx = ProjectContext::new(common);
    let loaded = ctx.loaded().await;
    let mut unreadable: Option<(String, String)> = None;
    let mut held: Vec<Held> = Vec::new();
    match &loaded.vendor {
        Ok(vendor) => held.extend(vendor.entries.iter().map(|(key, entry)| Held {
            purl: key.clone(),
            base: Some(entry.base_purl.clone()),
            uuid: entry.uuid.clone(),
            mode: MODE_VENDORED,
        })),
        Err(e) => {
            unreadable = Some((
                "vendor_state_unreadable".to_string(),
                format!("Could not read the vendor ledger: {e}"),
            ));
        }
    }
    match &loaded.manifest {
        Ok(manifest) => held.extend(manifest.iter().flat_map(|m| &m.patches).map(
            |(purl, record)| Held {
                purl: purl.clone(),
                base: None,
                uuid: record.uuid.clone(),
                mode: MODE_AGENT,
            },
        )),
        Err(e) => {
            // The manifest's error comes first: it is the store a name
            // most often means.
            let err =
                crate::json_envelope::manifest_load_error(&common.resolved_manifest_path(), e);
            unreadable = Some((err.code, err.message));
        }
    }
    let inventory = crate::commands::hosted_inventory(common, &ctx.root).await;
    held.extend(inventory.pins.iter().map(|pin| Held {
        purl: pin.purl.clone(),
        base: None,
        uuid: pin.uuid.clone(),
        mode: MODE_HOSTED,
    }));
    held.sort_by(|a, b| (a.package(), a.rank(), &a.uuid).cmp(&(b.package(), b.rank(), &b.uuid)));
    Project { held, unreadable }
}

/// The patches `targets` name among `held`, each once, in the order the
/// targets first reach them.
///
/// Where the project holds patches for one package in several modes, the
/// report names the one the build consumes ([`Held::rank`]): a vendored
/// patch is not reported as an agent one because the manifest records it
/// too, and a manifest record the vendored artifact has replaced is not
/// reported at all.
///
/// `Err((code, message))` when a target names no patch (a UUID always
/// names one) or a package name reaches several packages.
fn select(targets: &[String], held: &[Held]) -> Result<Vec<Named>, (&'static str, String)> {
    let mut named: Vec<Named> = Vec::new();
    let mut add = |patch: Named| {
        let seen = named
            .iter()
            .any(|have| have.uuid.eq_ignore_ascii_case(&patch.uuid));
        if !seen {
            named.push(patch);
        }
    };
    for token in targets {
        let parsed = Target::parse(token);
        // One purl per patch for the ambiguity check: the spelling the
        // target reaches it by.
        let target = parsed
            .settle(held.iter().map(|patch| match &patch.base {
                Some(base) if parsed.matches_patch(base, &patch.uuid) => base.as_str(),
                _ => patch.purl.as_str(),
            }))
            .map_err(|message| ("ambiguous_target", message))?;
        let matches: Vec<&Held> = held.iter().filter(|patch| patch.matches(&target)).collect();
        for patch in &matches {
            let consumed = matches
                .iter()
                .filter(|other| PurlKey::same(other.package(), patch.package()))
                .map(|other| other.rank())
                .min();
            if consumed == Some(patch.rank()) {
                add(Named {
                    uuid: patch.uuid.clone(),
                    purl: Some(patch.package().to_string()),
                    mode: patch.mode,
                });
            }
        }
        if !matches.is_empty() {
            continue;
        }
        if target.kind() != TargetKind::Uuid {
            return Err((
                "patch_not_found",
                format!(
                    "No patch of this project matches {token}. To report a patch the project \
                     no longer holds, name it by its UUID"
                ),
            ));
        }
        add(Named {
            uuid: token.clone(),
            purl: None,
            mode: MODE_UNKNOWN,
        });
    }
    Ok(named)
}

/// One patch a report names. `purl` is the package the project holds it
/// for; a patch named by UUID alone has none.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Named {
    uuid: String,
    purl: Option<String>,
    mode: &'static str,
}

impl Named {
    /// The patch as the report names it: by UUID, with the ecosystem and
    /// the mode it was patched in. Never the package name or a path.
    fn outcome(&self) -> PatchOutcome {
        PatchOutcome {
            uuid: self.uuid.to_ascii_lowercase(),
            ecosystem: self.purl.as_deref().map(ecosystem_of).unwrap_or_default(),
            mode: self.mode,
            outcome: OUTCOME_REPORTED,
            code: None,
        }
    }
}

/// Report a failure: the coded error on stdout under `--json`,
/// `Error: ...` on stderr otherwise (even under `--silent`). Returns the
/// exit code, 1.
fn fail(common: &GlobalArgs, code: &str, message: &str) -> i32 {
    if common.json {
        ui::print_json(&serde_json::json!({
            "command": "report",
            "status": "error",
            "error": { "code": code, "message": message },
        }));
    } else {
        eprintln!("Error: {message}");
    }
    1
}

/// The `--json` document of a report that was sent (or, on a dry run,
/// would be).
fn report_json(
    dry_run: bool,
    reason: Reason,
    message: Option<&str>,
    named: &[Named],
) -> serde_json::Value {
    let patches: Vec<serde_json::Value> = named
        .iter()
        .map(|patch| {
            let outcome = patch.outcome();
            let mut entry = serde_json::json!({
                "uuid": outcome.uuid,
                "ecosystem": outcome.ecosystem,
                "mode": outcome.mode,
            });
            if let Some(purl) = &patch.purl {
                entry["purl"] = serde_json::json!(purl);
            }
            entry
        })
        .collect();
    let mut document = serde_json::json!({
        "command": "report",
        "status": "success",
        "dryRun": dry_run,
        "reason": reason.word(),
        "patches": patches,
    });
    if let Some(message) = message {
        document["message"] = serde_json::json!(message);
    }
    document
}

/// The lines a human run prints for a report that was sent (or would
/// be): everything the report says, so a dry run shows it whole. Each
/// patch with the mode it is reported under, and the message as sent.
fn report_lines(
    dry_run: bool,
    reason: Reason,
    message: Option<&str>,
    named: &[Named],
) -> Vec<String> {
    let mut lines = vec![format!(
        "{} {} to Socket as {}:",
        if dry_run { "Would report" } else { "Reported" },
        ui::plural(named.len(), "patch", "patches"),
        reason.phrase()
    )];
    lines.extend(named.iter().map(|patch| match &patch.purl {
        Some(purl) => format!("  {purl} ({}, {} mode)", patch.uuid, patch.mode),
        None => format!("  {}", patch.uuid),
    }));
    if let Some(message) = message {
        lines.push(format!("  Message: {message}"));
    }
    lines
}

pub async fn run(args: ReportArgs) -> i32 {
    apply_env_toggles(&args.common);
    let common = &args.common;
    let project = held_patches(common).await;
    // The store that could not be read may hold the patch a name meant,
    // or the copy the build consumes in place of one the readable stores
    // still hold: its error is the cause, and a name is not resolved
    // against what is left (that could report the wrong patch). A UUID
    // names its patch without any store.
    if let Some((code, why)) = &project.unreadable {
        let by_name = args
            .targets
            .iter()
            .any(|token| Target::parse(token).kind() != TargetKind::Uuid);
        if by_name {
            return fail(
                common,
                code,
                &format!("{why}. To report a patch anyway, name it by its UUID"),
            );
        }
    }
    let named = match select(&args.targets, &project.held) {
        Ok(named) => named,
        Err((code, message)) => return fail(common, code, &message),
    };
    let patches: Vec<PatchOutcome> = named.iter().map(Named::outcome).collect();
    let reason = args.reason.core();
    // The message as it is sent, which is also what the run prints.
    let message = match fitted_report_message("report", reason, args.message.as_deref(), &patches) {
        Ok(message) => message,
        Err(not_sent) => {
            return fail(
                common,
                not_sent.code(),
                &format!("The report was not sent: {not_sent}"),
            )
        }
    };
    if !common.dry_run {
        let sent = send_patch_report(
            "report",
            reason,
            message.as_deref(),
            &patches,
            &common.telemetry_auth(),
        )
        .await;
        if let Err(not_sent) = sent {
            return fail(
                common,
                not_sent.code(),
                &format!("The report was not sent: {not_sent}"),
            );
        }
    }
    if common.json {
        ui::print_json(&report_json(
            common.dry_run,
            args.reason,
            message.as_deref(),
            &named,
        ));
    } else if !common.silent {
        for line in report_lines(common.dry_run, args.reason, message.as_deref(), &named) {
            println!("{line}");
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
    const UUID_B: &str = "22222222-2222-4222-8222-222222222222";
    const UUID_C: &str = "33333333-3333-4333-8333-333333333333";

    fn held(purl: &str, uuid: &str, mode: &'static str) -> Held {
        Held {
            purl: purl.to_string(),
            base: None,
            uuid: uuid.to_string(),
            mode,
        }
    }

    /// A vendor ledger entry: its key, and the base purl it resolves to.
    fn vendored(key: &str, base: &str, uuid: &str) -> Held {
        Held {
            base: Some(base.to_string()),
            ..held(key, uuid, MODE_VENDORED)
        }
    }

    fn project() -> Vec<Held> {
        vec![
            held("pkg:npm/lodash@4.17.20", UUID_A, MODE_AGENT),
            held("pkg:npm/%40types/lodash@4.14.0", UUID_B, MODE_AGENT),
        ]
    }

    fn targets(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    fn named(uuid: &str, purl: Option<&str>, mode: &'static str) -> Named {
        Named {
            uuid: uuid.to_string(),
            purl: purl.map(str::to_string),
            mode,
        }
    }

    /// A package name names the project's patch of that package, and not
    /// one of a package it only shares a last segment with. A patch named
    /// twice is reported once.
    #[test]
    fn a_name_selects_the_projects_patches_of_that_package() {
        let selected = select(&targets(&["lodash", UUID_A]), &project()).unwrap();
        assert_eq!(
            selected,
            [named(UUID_A, Some("pkg:npm/lodash@4.17.20"), MODE_AGENT)]
        );
        let outcome = selected[0].outcome();
        assert_eq!(outcome.ecosystem, "npm");
        assert_eq!(outcome.outcome, "reported");
    }

    /// Where the project holds patches for one package in several modes,
    /// the report names the one the build consumes: the vendored artifact
    /// over a hosted pin, either over the agent manifest's record, each
    /// under its own UUID. A vendor entry is found by its base purl, with
    /// or without a manifest record beside it.
    #[test]
    fn the_patch_the_build_consumes_is_the_one_reported() {
        // `get --save-only` then `vendor`: one patch, in both stores.
        let both = vec![
            held("pkg:npm/lodash@4.17.20", UUID_A, MODE_AGENT),
            vendored(
                "pkg:npm/lodash@4.17.20?artifact_id=x",
                "pkg:npm/lodash@4.17.20",
                UUID_A,
            ),
        ];
        let vendored_lodash = [named(UUID_A, Some("pkg:npm/lodash@4.17.20"), MODE_VENDORED)];
        assert_eq!(
            select(&targets(&["lodash"]), &both).unwrap(),
            vendored_lodash
        );
        assert_eq!(select(&targets(&[UUID_A]), &both).unwrap(), vendored_lodash);

        // The manifest moved on to a newer patch the vendored artifact
        // does not carry: the build still consumes the vendored one.
        let moved_on = vec![
            held("pkg:npm/lodash@4.17.20", UUID_B, MODE_AGENT),
            both[1].clone(),
        ];
        assert_eq!(
            select(&targets(&["pkg:npm/lodash@4.17.20"]), &moved_on).unwrap(),
            vendored_lodash
        );

        // A ledger entry alone (a pre-v5 one carries no record).
        assert_eq!(
            select(&targets(&["lodash"]), &both[1..]).unwrap(),
            vendored_lodash
        );

        // A hosted pin over the manifest; another package is untouched.
        let hosted = vec![
            held("pkg:npm/lodash@4.17.20", UUID_A, MODE_AGENT),
            held("pkg:npm/lodash@4.17.20", UUID_B, MODE_HOSTED),
            held("pkg:npm/left-pad@1.3.0", UUID_C, MODE_AGENT),
        ];
        assert_eq!(
            select(&targets(&["lodash", "left-pad"]), &hosted).unwrap(),
            [
                named(UUID_B, Some("pkg:npm/lodash@4.17.20"), MODE_HOSTED),
                named(UUID_C, Some("pkg:npm/left-pad@1.3.0"), MODE_AGENT),
            ]
        );
    }

    /// A UUID the project does not hold is still a patch to report: it
    /// may have been rolled back already. Its mode is not known.
    #[test]
    fn a_uuid_the_project_does_not_hold_is_reported_as_given() {
        let upper = UUID_C.to_uppercase();
        let selected = select(&targets(&[upper.as_str(), UUID_C]), &project()).unwrap();
        assert_eq!(selected, [named(&upper, None, MODE_UNKNOWN)]);
        let outcome = selected[0].outcome();
        assert_eq!(outcome.uuid, UUID_C, "sent in the canonical lower case");
        assert_eq!(outcome.ecosystem, "");
    }

    /// A name or purl that matches nothing is an error, never a report
    /// about no patch; so is a name that reaches several packages.
    #[test]
    fn a_target_that_names_no_single_package_is_refused() {
        let (code, message) = select(&targets(&["left-pad"]), &project()).unwrap_err();
        assert_eq!(code, "patch_not_found");
        assert!(
            message.contains("left-pad") && message.contains("UUID"),
            "{message}"
        );

        let (code, _) = select(&targets(&["pkg:npm/left-pad@1.0.0"]), &project()).unwrap_err();
        assert_eq!(code, "patch_not_found");

        let both = vec![
            held("pkg:npm/%40angular/core@1.0.0", UUID_A, MODE_AGENT),
            held("pkg:npm/%40babel/core@1.0.0", UUID_B, MODE_AGENT),
        ];
        let (code, message) = select(&targets(&["core"]), &both).unwrap_err();
        assert_eq!(code, "ambiguous_target");
        assert!(message.contains("ambiguous"), "{message}");
    }

    /// Each reason the user can type has its own wire reason, and
    /// `--json` echoes the typed word.
    #[test]
    fn every_reason_has_its_own_wire_reason() {
        use clap::ValueEnum;
        let typed: Vec<String> = Reason::value_variants()
            .iter()
            .map(|r| r.to_possible_value().unwrap().get_name().to_string())
            .collect();
        assert_eq!(typed, ["build", "tests", "runtime", "other"]);
        let words: Vec<&str> = Reason::value_variants().iter().map(|r| r.word()).collect();
        assert_eq!(words, typed);
        let wire: Vec<&str> = Reason::value_variants()
            .iter()
            .map(|r| r.core().as_str())
            .collect();
        let all: Vec<&str> = ReportReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(wire, all);
    }

    /// The human lines say everything the report does: each patch with
    /// its mode, and the message as it is sent.
    #[test]
    fn the_human_lines_show_the_whole_report() {
        let selected = select(&targets(&["lodash", UUID_C]), &project()).unwrap();
        assert_eq!(
            report_lines(false, Reason::Tests, Some("jest fails"), &selected),
            [
                "Reported 2 patches to Socket as breaking tests:".to_string(),
                format!("  pkg:npm/lodash@4.17.20 ({UUID_A}, agent mode)"),
                format!("  {UUID_C}"),
                "  Message: jest fails".to_string(),
            ]
        );
        assert_eq!(
            report_lines(true, Reason::Other, None, &selected[1..]),
            [
                "Would report 1 patch to Socket as broken:".to_string(),
                format!("  {UUID_C}"),
            ]
        );
    }

    #[test]
    fn the_json_document_echoes_what_was_sent() {
        let selected = select(&targets(&[UUID_B, UUID_C]), &project()).unwrap();
        assert_eq!(
            report_json(false, Reason::Build, Some("npm ci fails"), &selected),
            serde_json::json!({
                "command": "report",
                "status": "success",
                "dryRun": false,
                "reason": "build",
                "message": "npm ci fails",
                "patches": [
                    {
                        "uuid": UUID_B,
                        "purl": "pkg:npm/%40types/lodash@4.14.0",
                        "ecosystem": "npm",
                        "mode": "agent",
                    },
                    { "uuid": UUID_C, "ecosystem": "", "mode": "unknown" },
                ],
            })
        );
        let dry = report_json(true, Reason::Other, None, &selected);
        assert_eq!(dry["dryRun"], true);
        assert!(dry.get("message").is_none());
    }
}
