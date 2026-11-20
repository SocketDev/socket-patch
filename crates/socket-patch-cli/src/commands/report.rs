//! `socket-patch report`: tell Socket that a patch broke something.
//!
//! The report names each patch by UUID with its ecosystem and patch mode,
//! the reason, and the message the user typed. It changes nothing in the
//! project: it reads which patches the project holds (to turn a package
//! name into a patch) and sends one request.

use clap::Args;
use socket_patch_core::ledgers::{Ledgers, Store};
use socket_patch_core::telemetry::{
    report_message, send_patch_report, PatchOutcome, ReportReason, MAX_REPORT_MESSAGE_CHARS,
    MODE_AGENT, MODE_HOSTED, MODE_UNKNOWN, MODE_VENDORED, OUTCOME_REPORTED,
};
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
    /// Sent to Socket as written, on one line and cut to 1000 characters.
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
    purl: String,
    uuid: String,
    mode: &'static str,
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

/// Every patch the project at `--cwd` holds, as `list` reads them: the
/// manifest's (agent mode), the vendor ledger's and the hosted pins of
/// its lockfiles. A store that cannot be read holds nothing here: a
/// report by UUID must not need a healthy project.
async fn held_patches(common: &GlobalArgs) -> Vec<Held> {
    let ctx = ProjectContext::new(common);
    let loaded = ctx.loaded().await;
    let ledgers = Ledgers {
        manifest: loaded.manifest.as_ref().ok().and_then(Option::as_ref),
        vendor: loaded.vendor.as_ref().ok(),
        redirect: None,
    };
    let mut held: Vec<Held> = ledgers
        .listed()
        .into_iter()
        .map(|listed| Held {
            purl: listed.key.to_string(),
            uuid: listed.record.uuid.clone(),
            mode: match listed.store {
                Store::Manifest => MODE_AGENT,
                Store::Vendored => MODE_VENDORED,
                Store::Hosted => MODE_HOSTED,
            },
        })
        .collect();
    let inventory = crate::commands::hosted_inventory(common, &ctx.root).await;
    held.extend(inventory.pins.iter().map(|pin| Held {
        purl: pin.purl.clone(),
        uuid: pin.uuid.clone(),
        mode: MODE_HOSTED,
    }));
    held.sort_by(|a, b| (&a.purl, a.mode).cmp(&(&b.purl, b.mode)));
    held
}

/// The patches `targets` name among `held`, each once, in the order the
/// targets first reach them. A patch the project holds in two modes is
/// reported under the first (`held` lists agent, hosted, then vendored):
/// one report counts a patch once. `Err((code, message))` when a target
/// names no patch (a UUID always names one) or a package name reaches
/// several packages.
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
        let target = Target::parse(token)
            .settle(held.iter().map(|patch| patch.purl.as_str()))
            .map_err(|message| ("ambiguous_target", message))?;
        let mut matched = false;
        for patch in held
            .iter()
            .filter(|patch| target.matches_patch(&patch.purl, &patch.uuid))
        {
            matched = true;
            add(Named {
                uuid: patch.uuid.clone(),
                purl: Some(patch.purl.clone()),
                mode: patch.mode,
            });
        }
        if matched {
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

/// The lines a human run prints for a report that was sent (or would be).
fn report_lines(dry_run: bool, reason: Reason, named: &[Named]) -> Vec<String> {
    let mut lines = vec![format!(
        "{} {} to Socket as {}:",
        if dry_run { "Would report" } else { "Reported" },
        ui::plural(named.len(), "patch", "patches"),
        reason.phrase()
    )];
    lines.extend(named.iter().map(|patch| match &patch.purl {
        Some(purl) => format!("  {purl} ({})", patch.uuid),
        None => format!("  {}", patch.uuid),
    }));
    lines
}

pub async fn run(args: ReportArgs) -> i32 {
    apply_env_toggles(&args.common);
    let common = &args.common;
    let held = held_patches(common).await;
    let named = match select(&args.targets, &held) {
        Ok(named) => named,
        Err((code, message)) => return fail(common, code, &message),
    };
    let message = args.message.as_deref().and_then(report_message);
    if !common.dry_run {
        let patches: Vec<PatchOutcome> = named.iter().map(Named::outcome).collect();
        let sent = send_patch_report(
            "report",
            args.reason.core(),
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
        for line in report_lines(common.dry_run, args.reason, &named) {
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
            uuid: uuid.to_string(),
            mode,
        }
    }

    fn project() -> Vec<Held> {
        vec![
            held("pkg:npm/lodash@4.17.20", UUID_A, MODE_AGENT),
            held("pkg:npm/lodash@4.17.20", UUID_A, MODE_HOSTED),
            held("pkg:npm/%40types/lodash@4.14.0", UUID_B, MODE_VENDORED),
        ]
    }

    fn targets(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    /// A package name names the project's patch of that package, and not
    /// one of a package it only shares a last segment with. A patch held
    /// in two modes, or named twice, is reported once.
    #[test]
    fn a_name_selects_the_projects_patches_of_that_package() {
        let named = select(&targets(&["lodash", UUID_A]), &project()).unwrap();
        assert_eq!(
            named,
            [Named {
                uuid: UUID_A.to_string(),
                purl: Some("pkg:npm/lodash@4.17.20".to_string()),
                mode: MODE_AGENT,
            }]
        );
        let outcomes: Vec<PatchOutcome> = named.iter().map(Named::outcome).collect();
        assert_eq!(outcomes[0].ecosystem, "npm");
        assert_eq!(outcomes[0].outcome, "reported");
    }

    /// A UUID the project does not hold is still a patch to report: it
    /// may have been rolled back already. Its mode is not known.
    #[test]
    fn a_uuid_the_project_does_not_hold_is_reported_as_given() {
        let upper = UUID_C.to_uppercase();
        let named = select(&targets(&[upper.as_str(), UUID_C]), &project()).unwrap();
        assert_eq!(
            named,
            [Named {
                uuid: upper,
                purl: None,
                mode: MODE_UNKNOWN,
            }]
        );
        let outcome = named[0].outcome();
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

    #[test]
    fn the_human_lines_name_each_patch() {
        let named = select(&targets(&["lodash", UUID_C]), &project()).unwrap();
        assert_eq!(
            report_lines(false, Reason::Tests, &named),
            [
                "Reported 2 patches to Socket as breaking tests:".to_string(),
                format!("  pkg:npm/lodash@4.17.20 ({UUID_A})"),
                format!("  {UUID_C}"),
            ]
        );
        assert_eq!(
            report_lines(true, Reason::Other, &named[1..])[0],
            "Would report 1 patch to Socket as broken:"
        );
    }

    #[test]
    fn the_json_document_echoes_what_was_sent() {
        let named = select(&targets(&[UUID_B, UUID_C]), &project()).unwrap();
        assert_eq!(
            report_json(false, Reason::Build, Some("npm ci fails"), &named),
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
                        "mode": "vendored",
                    },
                    { "uuid": UUID_C, "ecosystem": "", "mode": "unknown" },
                ],
            })
        );
        let dry = report_json(true, Reason::Other, None, &named);
        assert_eq!(dry["dryRun"], true);
        assert!(dry.get("message").is_none());
    }
}
