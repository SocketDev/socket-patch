//! Every code the Bazel layer reports (design 6), spelled in this file
//! and nowhere else.
//!
//! A code is a contract identifier: CI scripts match on the string. So
//! each one is written once, in the table below, and reaches output only
//! through [`Code::as_str`]. `test_bazel_contract_codes` (the CLI crate's
//! `tests/contract_gradle_codes.rs`) fails when
//!
//! - a [`Code::ALL`] string has no row in the "Bazel builds" section of
//!   `CLI_CONTRACT.md`, or that document names a Bazel code this enum
//!   does not have;
//! - a string literal of one of the five families (`bazel_workspace_`,
//!   `bazel_agent_`, `redirect_bazel_`, `vendor_bazel_`, `vex_bazel_`) is
//!   in production source outside this file: a whole code, or the bare
//!   prefix that `format!` or `starts_with` would build or match one
//!   from. Production source is a whole file but its inline test modules.
//!   There is no bare `bazel_` family, so `"bazel_dep"` in a reader is
//!   not a code.
//!
//! Hosted and vendored refusals share one [`Reason`]: the code is the
//! mode's prefix plus the reason ([`Code::refusal`]), and the refusal's
//! `details.token` names the case.
//!
//! # Tokens
//!
//! A token is machine-readable output too, so it is a contract identifier
//! like a code. The convention: a module that puts a token in a `Refusal`,
//! a `Gap` or a `Bypass` declares
//!
//! ```text
//! pub const TOKENS: &[&str] = &["lane_not_enabled", "hub_shadowed"];
//! ```
//!
//! with every token it emits as a string literal (`model::TOKENS` is the
//! first such list). The contract test finds the lists by source scan, so
//! the declaration is spelled exactly like this, every item is a string
//! literal and nothing else in a Bazel file is named `*TOKENS*`. The test
//! requires each token in the token table of the contract section. An
//! emission site names a token in one of two ways, and both are checked:
//! a `token: "..."` literal must be in its file's list, and a constant in
//! `token: NAME` must be declared as an item of a list,
//!
//! ```text
//! pub const LANE_NOT_ENABLED: &str = TOKENS[0];
//! ```
//!
//! in any Bazel module. The table starts with the whole list of design 6,
//! so a lane's tokens are documented before the lane lands. A token that
//! is not in the table is a contract change and goes through the wave's
//! steward, like a new code.
//!
//! The scan reads spellings, so it does not see a token that reaches a
//! `token` field through a variable, a parameter or the field shorthand.
//! Only a type closes that: the fields are `&'static str` (design 2.3),
//! and a `Token` type declared here beside [`Code`] is a change to the
//! model for a wave's steward to decide.
//!
//! # Levels
//!
//! A [`Level`] is the prefix of a code's line for a human: `Note:` or
//! `Warning:`. It is not a JSON field. Design 6 heads the run-level table
//! "`warnings[]`, with `level`", but the v5.0 envelope has no such field:
//! a run-level warning is `{code, detail}` (the CLI crate's `RunWarning`),
//! and v5.0 removed the `level` the Gradle discovery notes once carried.
//! The contract section therefore documents the Level column as the
//! human prefix, and gives the run-required advisory no `details` object:
//! its detail text names the command and the platforms. The first codes
//! became `active` with the early hazard fixes (the output-tree and
//! `.bazelignore` guards), and they are emitted under this reading, which
//! settles it: a run-level warning is `{code, detail}`. A code that needs
//! structured fields later carries them in an event's `details`, as the
//! run-required row of the contract says, and not on `RunWarning`.

use std::fmt;

use super::model::{Mode, Reason, RunKind, WithholdKind};

/// How loud a code is: the prefix of its line for a human, and the Level
/// column of the contract. A `warnings[]` entry does not carry it (module
/// docs, "Levels").
///
/// The level in the table below is a floor. A caller may raise `Info` to
/// `Warn` and never lowers a `Warn`: evidence only escalates. The one
/// raise the contract names is the run-required advisory's
/// ([`Level::of_required_run`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// Nothing to do. Printed as `Note:`, which `--silent` hides.
    Info,
    /// The Bazel build does not get a patch, or stops getting it, until
    /// the user acts. Printed as `Warning:`.
    Warn,
}

impl Level {
    /// The word in the contract's Level column.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
        }
    }

    /// The level of a `*_bazel_run_required` advisory whose command is of
    /// `kind`. `builds_fail` says that builds fail until the command has
    /// run, as after a restoring edit under `--lockfile_mode=error`.
    ///
    /// It is a note only while Bazel heals the state by itself: an
    /// ordinary build refreshes `MODULE.bazel.lock`, and the command only
    /// makes the committed lock current. The advisory that does not gate
    /// `vex` (lockfile facts that may be stale) is of that kind. It is a
    /// warning when builds fail, and for the two kinds that no build
    /// refreshes: until the user runs `update-repos` Bazel keeps building
    /// from the old `go_repository` rule, so the build does not get the
    /// patch, and until a repin the crate lock digest fails the build.
    /// The two kinds of revision 4 are warnings for the same reason: no
    /// build runs a ruleset's pin target or `bazel vendor`, so until the
    /// command has run Bazel builds from the lock or the vendor directory
    /// as it was.
    pub const fn of_required_run(kind: RunKind, builds_fail: bool) -> Level {
        match kind {
            RunKind::Lockfile if !builds_fail => Self::Info,
            RunKind::Lockfile
            | RunKind::UpdateRepos
            | RunKind::Repin
            | RunKind::Pin
            | RunKind::Vendor => Self::Warn,
        }
    }
}

/// Where a code appears in output, which is what a script that looks for
/// it has to know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// One `warnings[]` entry about the workspace as a whole.
    RunLevel,
    /// A warning of the in-memory hosted engine, which prints no line for
    /// a human: the contract gives it no level.
    EngineWarning,
    /// Rides a run that went on: what the run does not cover, or the one
    /// command to run next.
    Advisory,
    /// On the sidecar record of one patched package.
    SidecarAdvisory,
    /// Nothing was written for the package.
    Refusal,
    /// `vex` made no statement for the package.
    Withheld,
}

/// Declares [`Code`] from one table, so a code cannot have a string and
/// lack a kind or a level, or be missing from [`Code::ALL`].
macro_rules! codes {
    ($($(#[$doc:meta])* $variant:ident = $text:literal, $kind:ident, $level:ident;)+) => {
        /// A code of the "Bazel builds" section of `CLI_CONTRACT.md`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Code { $($(#[$doc])* $variant),+ }

        impl Code {
            /// Every code, in the order of the contract's tables.
            pub const ALL: &'static [Code] = &[$(Code::$variant),+];

            /// The string in output. It never changes once released.
            pub const fn as_str(self) -> &'static str {
                match self { $(Code::$variant => $text),+ }
            }

            /// Where the code appears.
            pub const fn kind(self) -> Kind {
                match self { $(Code::$variant => Kind::$kind),+ }
            }

            /// The lowest level the code is reported at. The contract
            /// has a level cell only for a run-level code or an advisory;
            /// for the other kinds it is `Warn`, so none is ever printed
            /// as a note.
            pub const fn level(self) -> Level {
                match self { $(Code::$variant => Level::$level),+ }
            }
        }
    };
}

codes! {
    // ── Run level ────────────────────────────────────────────────────
    /// A workspace with at least one hub or ruleset signal. Names the
    /// root, the Bazel line and tier, the dependency system and each
    /// governed ecosystem with its ruleset and lock.
    WorkspaceDetected = "bazel_workspace_detected", RunLevel, Info;
    /// Bazel modules, source archives or report-only pins exist. Socket
    /// patches cover registry packages, so these are counted, not examined.
    WorkspaceOutOfScope = "bazel_workspace_out_of_scope", RunLevel, Info;
    /// A Bazel file exists and cannot be read or parsed. Unreadable is not
    /// absent: what it declares may govern the build.
    WorkspaceUnreadable = "bazel_workspace_unreadable", RunLevel, Warn;
    /// Bazel 4 or older, or 5.x with Bzlmod.
    WorkspaceVersionUnsupported = "bazel_workspace_version_unsupported", RunLevel, Warn;
    /// A floating, unknown or newer-than-audited Bazel or ruleset.
    WorkspaceVersionUntested = "bazel_workspace_version_untested", RunLevel, Info;
    /// A boundary file exists above the checkout, where nothing is read.
    WorkspaceAboveRepo = "bazel_workspace_above_repo", RunLevel, Warn;
    /// A directory classified as a Bazel tree was pruned from a walk.
    WorkspaceOutputTreeSkipped = "bazel_workspace_output_tree_skipped", RunLevel, Info;
    /// `apply` ran with its working directory inside a Bazel tree. Nothing
    /// was patched and the exit code stays 0: a legacy ruleset runs
    /// `apply` from a lifecycle hook there, and a failure would fail the
    /// repository rule and every target behind it.
    WorkspaceInsideOutputTree = "bazel_workspace_inside_output_tree", RunLevel, Warn;
    /// An rc import could not be followed, or a `tools/bazel` wrapper
    /// exists: flags may apply that no static read sees.
    WorkspaceRcUnread = "bazel_workspace_rc_unread", RunLevel, Info;
    /// A `.bazelignore` line was written to keep a `.socket` tree out of
    /// `//...`.
    WorkspaceIgnoreLineAdded = "bazel_workspace_ignore_line_added", RunLevel, Info;
    /// A `.socket` tree is visible to `//...` and the line cannot be
    /// written.
    WorkspaceIgnoreLineNeeded = "bazel_workspace_ignore_line_needed", RunLevel, Warn;
    /// A marked hook unit was written into a user file (`.bazelrc`,
    /// `MODULE.bazel` or a WORKSPACE file) so that Bazel reads the owned
    /// file under `.socket/bazel/` (revision 4, write class `Hook`).
    WorkspaceHookAdded = "bazel_workspace_hook_added", RunLevel, Info;
    /// Owned wiring exists and the hook that makes Bazel read it is
    /// missing or cannot be written, so the wiring is off.
    WorkspaceHookNeeded = "bazel_workspace_hook_needed", RunLevel, Warn;
    /// `--prune` could not enumerate a hub lock, so the records that lock
    /// may resolve were kept.
    WorkspacePruneSkipped = "bazel_workspace_prune_skipped", RunLevel, Warn;
    /// The in-memory engine met an ecosystem Bazel governs and skipped it.
    WorkspaceUnsupportedInMemory = "bazel_workspace_unsupported_in_memory", EngineWarning, Warn;

    // ── Agent ────────────────────────────────────────────────────────
    /// An agent command touched an ecosystem a ruleset governs or may
    /// govern: the Bazel build fetches from the lock, not from the
    /// installed tree. The host tree is still patched and the exit code is
    /// unchanged.
    AgentNotConsumed = "bazel_agent_not_consumed", Advisory, Warn;
    /// The scope root or a package path is a Bazel tree or a link into
    /// one: never written, never crawled.
    AgentOutputTree = "bazel_agent_output_tree", Refusal, Warn;
    /// A Go directory `replace` this workspace cannot consume safely. It
    /// is the code of every reason the gate gives for that write; the
    /// token is the one the vendored refusal would carry.
    AgentGoUnsupported = "bazel_agent_go_unsupported", Refusal, Warn;
    /// An agent-patched Coursier or `~/.m2` jar that a later
    /// `@<hub>//:pin` would write into the lock as if it were upstream.
    AgentCoursierPinHazard = "bazel_agent_coursier_pin_hazard", SidecarAdvisory, Warn;

    // ── Hosted refusals: `redirect_bazel_` plus the reason ───────────
    /// The ruleset is present and its hub or lock label is not a literal,
    /// or a file it needs is unreadable: which lock Bazel reads is unknown.
    RedirectConsumerUndetermined = "redirect_bazel_consumer_undetermined", Refusal, Warn;
    /// Bzlmod and WORKSPACE may both be live, or the candidate
    /// declarations name different locks.
    RedirectModeAmbiguous = "redirect_bazel_mode_ambiguous", Refusal, Warn;
    /// The only declaration naming the lock is dead, shadowed, not
    /// imported or in another module: a rewrite would be a silent no-op.
    RedirectDeclarationInactive = "redirect_bazel_declaration_inactive", Refusal, Warn;
    /// No lane for this shape, or the lane is not enabled.
    RedirectRulesetUnsupported = "redirect_bazel_ruleset_unsupported", Refusal, Warn;
    /// A version gate is not proven, or the Bazel line is outside the
    /// lane's claim.
    RedirectRulesetVersionUnsupported = "redirect_bazel_ruleset_version_unsupported", Refusal, Warn;
    /// The edit stales `MODULE.bazel.lock` under `--lockfile_mode=error`,
    /// which would fail every build.
    RedirectLockfileFrozen = "redirect_bazel_lockfile_frozen", Refusal, Warn;
    /// An override, a vendor directory, `--nofetch` or a replacement tag
    /// makes Bazel take the package from where the pin does not reach.
    RedirectPinBypassed = "redirect_bazel_pin_bypassed", Refusal, Warn;
    /// The downloader config or the Go proxy settings keep Bazel from the
    /// patch host. Hosted only: vendored mode fetches nothing.
    RedirectFetchBlocked = "redirect_bazel_fetch_blocked", Refusal, Warn;
    /// A value derived from the lock cannot be recomputed, or was already
    /// inconsistent before the edit.
    RedirectDerivedUnrepairable = "redirect_bazel_derived_unrepairable", Refusal, Warn;
    /// A lock check target would go red after the rewrite, and its update
    /// command would erase the pin. Hosted only: no vendored lane edits a
    /// checked lock.
    RedirectLockCheckPresent = "redirect_bazel_lock_check_present", Refusal, Warn;
    /// A Go pin with no proof that Bazel selects the pinned version.
    RedirectSelectionUnproven = "redirect_bazel_selection_unproven", Refusal, Warn;
    /// One of several lock files of a hub, or one of several hubs pinning
    /// the package, cannot be rewritten: all or none.
    RedirectLockSetPartial = "redirect_bazel_lock_set_partial", Refusal, Warn;
    /// The owned index fails the strict parse, so someone else edited it.
    RedirectOwnedFileModified = "redirect_bazel_owned_file_modified", Refusal, Warn;

    // ── Vendored refusals: `vendor_bazel_` plus the same reason ──────
    /// Vendored twin of [`Code::RedirectConsumerUndetermined`].
    VendorConsumerUndetermined = "vendor_bazel_consumer_undetermined", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectModeAmbiguous`].
    VendorModeAmbiguous = "vendor_bazel_mode_ambiguous", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectDeclarationInactive`].
    VendorDeclarationInactive = "vendor_bazel_declaration_inactive", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectRulesetUnsupported`].
    VendorRulesetUnsupported = "vendor_bazel_ruleset_unsupported", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectRulesetVersionUnsupported`].
    VendorRulesetVersionUnsupported = "vendor_bazel_ruleset_version_unsupported", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectLockfileFrozen`].
    VendorLockfileFrozen = "vendor_bazel_lockfile_frozen", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectPinBypassed`].
    VendorPinBypassed = "vendor_bazel_pin_bypassed", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectDerivedUnrepairable`].
    VendorDerivedUnrepairable = "vendor_bazel_derived_unrepairable", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectSelectionUnproven`].
    VendorSelectionUnproven = "vendor_bazel_selection_unproven", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectLockSetPartial`].
    VendorLockSetPartial = "vendor_bazel_lock_set_partial", Refusal, Warn;
    /// Vendored twin of [`Code::RedirectOwnedFileModified`].
    VendorOwnedFileModified = "vendor_bazel_owned_file_modified", Refusal, Warn;

    // ── Advisories ───────────────────────────────────────────────────
    /// Wired, and one named command refreshes committed Bazel state; also
    /// after a restoring edit that stales state socket-patch cannot
    /// repair, and, without gating `vex`, for lockfile facts that may be
    /// stale. `Info` is the floor: [`Level::of_required_run`] raises it
    /// to `Warn` when, until the command has run, builds fail or the
    /// Bazel build does not get the patch.
    RedirectRunRequired = "redirect_bazel_run_required", Advisory, Info;
    /// Vendored twin of [`Code::RedirectRunRequired`].
    VendorRunRequired = "vendor_bazel_run_required", Advisory, Info;
    /// socket-patch ran the one tool a lane names, inside the transaction,
    /// because the build would not pass between the write and the run
    /// (revision 4, 2.5). Names the command and the files it rewrote.
    RedirectToolRan = "redirect_bazel_tool_ran", Advisory, Info;
    /// Vendored twin of [`Code::RedirectToolRan`].
    VendorToolRan = "vendor_bazel_tool_ran", Advisory, Info;
    /// The withdrawn-pin sweep kept a pin, because restoring it would fail
    /// every build: under `--lockfile_mode=error`, or under any mode
    /// where the restore stales a crate lock digest that only a repin
    /// refreshes (design 7). A warning: the withdrawn pin itself fails
    /// every cold fetch.
    RedirectWithdrawnPinKept = "redirect_bazel_withdrawn_pin_kept", Advisory, Warn;
    /// Cold repository fetches now need the patch host beyond the package
    /// itself: its NuGet service index (`H-NET1`) or its registry
    /// `config.json` (`H-RSR1`).
    RedirectFetchDependency = "redirect_bazel_fetch_dependency", Advisory, Info;
    /// Follows a refusal that has a manual procedure.
    RedirectManualSnippet = "redirect_bazel_manual_snippet", Advisory, Info;
    /// The pinned URL, grant token included, is repeated in a file the
    /// ruleset generates or in the refreshed `MODULE.bazel.lock`.
    RedirectTokenSurface = "redirect_bazel_token_surface", Advisory, Info;
    /// An index row whose pin is gone: a repin or an install rewrote the
    /// lock, so the patch is no longer wired.
    RedirectPinErased = "redirect_bazel_pin_erased", Advisory, Warn;
    /// A same-ecosystem lock that no hub reads was left as found, and no
    /// `.npmrc` was created beside the governed lock.
    RedirectSideFileSkipped = "redirect_bazel_side_file_skipped", Advisory, Info;
    /// `rollback` or `remove` could not undo a pin and undid nothing of
    /// it: a user file still carries the pin in a form the record does
    /// not match, or a row is of a kind this release cannot restore
    /// (revision 4, 2.8 item 4). Nothing the file still names was
    /// deleted, so the build keeps passing, patched. An advisory, because
    /// the run goes on with the other pins; a warning, because the patch
    /// the user asked to remove is still built.
    RedirectRevertIncomplete = "redirect_bazel_revert_incomplete", Advisory, Warn;
    /// Vendored twin of [`Code::RedirectRevertIncomplete`]: the vendored
    /// artifact the pin names is kept as well.
    VendorRevertIncomplete = "vendor_bazel_revert_incomplete", Advisory, Warn;

    // ── VEX: `vex_bazel_` plus the withhold kind ─────────────────────
    /// The candidate rests on a host tree, or on a lock no live hub reads.
    VexNotConsumed = "vex_bazel_not_consumed", Withheld, Warn;
    /// Governance is undetermined or ambiguous, or a version gate is no
    /// longer proven.
    VexConsumerUndetermined = "vex_bazel_consumer_undetermined", Withheld, Warn;
    /// A bypass holds now, or a user patch hook exists that can reverse
    /// the fix.
    VexPinBypassed = "vex_bazel_pin_bypassed", Withheld, Warn;
    /// A derived value disagrees with the pin, or a recorded lock entry
    /// with a fresh digest lacks it.
    VexDerivedStale = "vex_bazel_derived_stale", Withheld, Warn;
    /// A works-after lane without committed evidence that its command ran.
    VexRunPending = "vex_bazel_run_pending", Withheld, Warn;
    /// A Go pin without a selection proof.
    VexSelectionUnproven = "vex_bazel_selection_unproven", Withheld, Warn;
    /// No digest the build enforces anchors the pin.
    VexIntegrityUnanchored = "vex_bazel_integrity_unanchored", Withheld, Warn;
}

impl Code {
    /// The code of a refusal for `reason` in `mode`: the mode's prefix
    /// plus the reason.
    ///
    /// `None` is a cell design 6 leaves empty, and the caller must still
    /// refuse. Vendored mode has no code for the two hosted-only reasons.
    /// Agent mode has no per-reason codes at all: a refused agent cell
    /// still patches the host tree and reports
    /// [`Code::AgentNotConsumed`], and the one agent write the gate can
    /// stop, the Go directory replace, is [`Code::AgentGoUnsupported`]
    /// whatever the reason. Which of the two applies is the caller's
    /// knowledge, not the reason's.
    pub const fn refusal(mode: Mode, reason: Reason) -> Option<Code> {
        match mode {
            Mode::Hosted => Some(Self::redirect(reason)),
            Mode::Vendored => Self::vendor(reason),
            Mode::Agent => None,
        }
    }

    const fn redirect(reason: Reason) -> Code {
        match reason {
            Reason::ConsumerUndetermined => Self::RedirectConsumerUndetermined,
            Reason::ModeAmbiguous => Self::RedirectModeAmbiguous,
            Reason::DeclarationInactive => Self::RedirectDeclarationInactive,
            Reason::RulesetUnsupported => Self::RedirectRulesetUnsupported,
            Reason::RulesetVersionUnsupported => Self::RedirectRulesetVersionUnsupported,
            Reason::LockfileFrozen => Self::RedirectLockfileFrozen,
            Reason::PinBypassed => Self::RedirectPinBypassed,
            Reason::FetchBlocked => Self::RedirectFetchBlocked,
            Reason::DerivedUnrepairable => Self::RedirectDerivedUnrepairable,
            Reason::LockCheckPresent => Self::RedirectLockCheckPresent,
            Reason::SelectionUnproven => Self::RedirectSelectionUnproven,
            Reason::LockSetPartial => Self::RedirectLockSetPartial,
            Reason::OwnedFileModified => Self::RedirectOwnedFileModified,
        }
    }

    const fn vendor(reason: Reason) -> Option<Code> {
        Some(match reason {
            Reason::ConsumerUndetermined => Self::VendorConsumerUndetermined,
            Reason::ModeAmbiguous => Self::VendorModeAmbiguous,
            Reason::DeclarationInactive => Self::VendorDeclarationInactive,
            Reason::RulesetUnsupported => Self::VendorRulesetUnsupported,
            Reason::RulesetVersionUnsupported => Self::VendorRulesetVersionUnsupported,
            Reason::LockfileFrozen => Self::VendorLockfileFrozen,
            Reason::PinBypassed => Self::VendorPinBypassed,
            Reason::DerivedUnrepairable => Self::VendorDerivedUnrepairable,
            Reason::SelectionUnproven => Self::VendorSelectionUnproven,
            Reason::LockSetPartial => Self::VendorLockSetPartial,
            Reason::OwnedFileModified => Self::VendorOwnedFileModified,
            Reason::FetchBlocked | Reason::LockCheckPresent => return None,
        })
    }

    /// The code of an undo that left a pin in place in `mode`: what a
    /// seam reports for each pin that `exec::revert` kept
    /// (`Kept::Pin`, `Kept::PinOfUnhandled`), with the file the entry
    /// names. `None` in agent mode, which records no pin to undo.
    pub const fn revert_incomplete(mode: Mode) -> Option<Code> {
        match mode {
            Mode::Hosted => Some(Self::RedirectRevertIncomplete),
            Mode::Vendored => Some(Self::VendorRevertIncomplete),
            Mode::Agent => None,
        }
    }

    /// The code `vex` reports when it withholds a statement for `kind`.
    pub const fn withheld(kind: WithholdKind) -> Code {
        match kind {
            WithholdKind::NotConsumed => Self::VexNotConsumed,
            WithholdKind::ConsumerUndetermined => Self::VexConsumerUndetermined,
            WithholdKind::PinBypassed => Self::VexPinBypassed,
            WithholdKind::DerivedStale => Self::VexDerivedStale,
            WithholdKind::RunPending => Self::VexRunPending,
            WithholdKind::SelectionUnproven => Self::VexSelectionUnproven,
            WithholdKind::IntegrityUnanchored => Self::VexIntegrityUnanchored,
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// `ConsumerUndetermined` to `consumer_undetermined`.
    fn snake(camel: &str) -> String {
        let mut out = String::new();
        for c in camel.chars() {
            if c.is_ascii_uppercase() && !out.is_empty() {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        }
        out
    }

    /// The string a variant's name stands for. The first word of the name
    /// is the family; `bazel` goes after it, or before it for the two
    /// families that are not a mode's prefix.
    fn named(code: Code) -> String {
        let name = snake(&format!("{code:?}"));
        let (family, rest) = name.split_once('_').expect("a family and a name");
        match family {
            "workspace" | "agent" => format!("bazel_{family}_{rest}"),
            "redirect" | "vendor" | "vex" => format!("{family}_bazel_{rest}"),
            other => panic!("{code:?}: `{other}` is not a code family"),
        }
    }

    fn of_kind(kind: Kind) -> BTreeSet<Code> {
        let codes = Code::ALL.iter().copied();
        codes.filter(|code| code.kind() == kind).collect()
    }

    fn family(prefix: &str) -> BTreeSet<Code> {
        let codes = Code::ALL.iter().copied();
        codes
            .filter(|code| code.as_str().starts_with(prefix))
            .collect()
    }

    /// A typo in one string of the table would ship as a contract
    /// identifier. Each string is rebuilt from its variant's name instead,
    /// and the totals are the 56 of design 6 plus the six of revision 4
    /// (two hook codes, two tool-run advisories and the two
    /// `revert_incomplete` advisories).
    #[test]
    fn every_string_is_its_variant_name_in_one_of_the_five_families() {
        for code in Code::ALL {
            assert_eq!(code.as_str(), named(*code));
            assert_eq!(code.to_string(), code.as_str());
        }
        let strings: BTreeSet<&str> = Code::ALL.iter().map(|code| code.as_str()).collect();
        assert_eq!(strings.len(), Code::ALL.len(), "two codes share a string");
        assert_eq!(Code::ALL.len(), 62);
        let sizes = [
            "bazel_workspace_",
            "bazel_agent_",
            "redirect_bazel_",
            "vendor_bazel_",
            "vex_bazel_",
        ]
        .map(|prefix| family(prefix).len());
        assert_eq!(sizes, [15, 4, 22, 14, 7]);
    }

    /// Hosted and vendored refusals differ in the prefix alone, so a
    /// script that handles one reason handles it in both modes.
    #[test]
    fn a_refusal_code_is_the_mode_prefix_plus_the_reason() {
        let hosted_only = [Reason::FetchBlocked, Reason::LockCheckPresent];
        let mut mapped = BTreeSet::new();
        for reason in Reason::ALL {
            let name = snake(&format!("{reason:?}"));
            let hosted = Code::refusal(Mode::Hosted, *reason).expect("every reason refuses hosted");
            assert_eq!(hosted.as_str(), format!("redirect_bazel_{name}"));
            mapped.insert(hosted);
            let vendored = Code::refusal(Mode::Vendored, *reason);
            assert_eq!(vendored.is_none(), hosted_only.contains(reason));
            if let Some(vendored) = vendored {
                assert_eq!(vendored.as_str(), format!("vendor_bazel_{name}"));
                mapped.insert(vendored);
            }
            assert_eq!(Code::refusal(Mode::Agent, *reason), None, "{reason:?}");
        }
        // No refusal code is unreachable: a reason maps to each, bar the
        // two an agent caller picks by what it was writing.
        mapped.extend([Code::AgentOutputTree, Code::AgentGoUnsupported]);
        assert_eq!(mapped, of_kind(Kind::Refusal));
    }

    #[test]
    fn a_withheld_code_is_the_vex_prefix_plus_the_kind() {
        let mut mapped = BTreeSet::new();
        for kind in WithholdKind::ALL {
            let code = Code::withheld(*kind);
            let name = snake(&format!("{kind:?}"));
            assert_eq!(code.as_str(), format!("vex_bazel_{name}"));
            mapped.insert(code);
        }
        assert_eq!(mapped, of_kind(Kind::Withheld));
        assert_eq!(mapped, family("vex_bazel_"));
    }

    /// `--silent` hides a note. A code that says a patch did not reach the
    /// build, or that a statement was withheld, must not be hidden.
    #[test]
    fn a_code_that_stops_a_patch_is_never_a_note() {
        for code in Code::ALL {
            let stops = !matches!(code.kind(), Kind::RunLevel | Kind::Advisory);
            assert!(!stops || code.level() == Level::Warn, "{code} is a note");
        }
        // A caller escalates with `max`; the words are the contract's.
        assert_eq!(Level::Info.max(Level::Warn), Level::Warn);
        let levels = [Level::Info, Level::Warn].map(Level::as_str);
        assert_eq!(levels, ["info", "warn"]);
    }

    /// The run-required advisory is the one advisory whose level depends
    /// on the run, so the loop above cannot hold it to the rule. It is a
    /// note only while an ordinary build heals the state by itself. Where
    /// builds fail, or Bazel keeps building upstream until the user runs
    /// the command (a WORKSPACE `go_repository` hub), `--silent` must not
    /// hide it.
    #[test]
    fn a_required_run_the_build_waits_for_is_never_a_note() {
        let floor = Code::RedirectRunRequired.level();
        assert_eq!(floor, Level::Info);
        assert_eq!(Code::VendorRunRequired.level(), floor);
        // Only a stale `MODULE.bazel.lock` heals: no build runs
        // `update-repos`, a repin, a ruleset's pin target or `bazel vendor`.
        for kind in RunKind::ALL {
            let heals = *kind == RunKind::Lockfile;
            let passing = Level::of_required_run(*kind, false);
            assert_eq!(passing == Level::Info, heals, "{kind:?}");
            assert_eq!(Level::of_required_run(*kind, true), Level::Warn);
            assert!(passing >= floor, "{kind:?} is below the code's floor");
        }
    }

    /// A code's kind is where a script finds it, so the split is pinned to
    /// the one of design 6 as revision 4 extends it (two hook codes at
    /// run level, two tool-run advisories, two `revert_incomplete`
    /// advisories): every workspace code is run-level bar the engine's
    /// one, and there are thirteen advisories, 26 refusals, seven withheld
    /// statements and one sidecar advisory.
    #[test]
    fn kinds_split_the_codes_as_the_design_does() {
        let mut run_level = of_kind(Kind::RunLevel);
        run_level.extend(of_kind(Kind::EngineWarning));
        assert_eq!(run_level, family("bazel_workspace_"));
        let only = |kind| Vec::from_iter(of_kind(kind));
        let in_memory = Code::WorkspaceUnsupportedInMemory;
        assert_eq!(only(Kind::EngineWarning), [in_memory]);
        assert_eq!(only(Kind::SidecarAdvisory), [Code::AgentCoursierPinHazard]);
        let sizes = [Kind::Advisory, Kind::Refusal, Kind::Withheld].map(|kind| of_kind(kind).len());
        assert_eq!(sizes, [13, 26, 7]);
    }

    /// An undo that kept a pin has a code in each mode that records pins,
    /// the mode's prefix and one name, and none in agent mode.
    #[test]
    fn an_incomplete_revert_has_a_code_per_mode_that_pins() {
        let hosted = Code::revert_incomplete(Mode::Hosted).expect("hosted");
        let vendored = Code::revert_incomplete(Mode::Vendored).expect("vendored");
        assert_eq!(hosted.as_str(), "redirect_bazel_revert_incomplete");
        assert_eq!(vendored.as_str(), "vendor_bazel_revert_incomplete");
        assert_eq!(Code::revert_incomplete(Mode::Agent), None);
        for code in [hosted, vendored] {
            assert_eq!((code.kind(), code.level()), (Kind::Advisory, Level::Warn));
        }
    }
}
