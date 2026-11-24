//! Cleanup of hosted mode's pnpm registry route: the entries of it that no
//! lockfile uses any more (the registry of a patch, the `overrides` entry
//! of pnpm-workspace.yaml that routes its release, that override's record
//! in a lock). A helper module, not a command.
//!
//! A hosted scan takes them out as part of its rewrite and reports them
//! through [`record`]. `repair`'s cleanup phase and the `--prune` pass of a
//! scan in another mode reconcile with [`sweep`], from the project's files
//! alone: no patch service or registry is asked.

use socket_patch_core::hosted::guidance::RegistryEntry;
use socket_patch_core::patch::redirect::upstream::{sweep_pnpm_registry_route, RestoreOptions};

use crate::args::GlobalArgs;
use crate::json_envelope::{Envelope, PatchAction, PatchEvent};

/// `errorCode` of the `removed` (`verified` on a dry run) event of each
/// entry taken out.
pub(crate) const REGISTRY_ENTRY_UNUSED: &str = "registry_entry_unused";

/// Warning: the project's pnpm locks or its workspace file could not be
/// read to tell what still uses the route; nothing was removed.
pub(crate) const REGISTRY_CLEANUP_SKIPPED: &str = "registry_cleanup_skipped";

/// Warning: the cleaned files could not be written; they are as they were
/// (or the detail names each one that is not).
pub(crate) const REGISTRY_CLEANUP_FAILED: &str = "registry_cleanup_failed";

/// Warning: the workspace file declares registries in the shape of a
/// patch's registry on a host the run was not given as a patch server.
/// They were left alone, so nothing of them was tidied; the detail names
/// the host and the setting that lets the command tidy them.
pub(crate) const REGISTRY_CLEANUP_UNKNOWN_HOST: &str = "registry_cleanup_unknown_host";

/// The [`REGISTRY_CLEANUP_UNKNOWN_HOST`] detail for `count` registries on
/// `origin` (`http(s)://host[:port]`). The origin is all of an address
/// that is ever shown: the rest holds a grant's token.
fn unknown_host_detail(origin: &str, count: usize) -> String {
    let (registries, were, those, them) = match count {
        1 => (
            "1 pnpm registry of a hosted patch".to_string(),
            "was",
            "that registry",
            "it",
        ),
        count => (
            format!("{count} pnpm registries of hosted patches"),
            "were",
            "those registries",
            "them",
        ),
    };
    format!(
        "{registries} on {origin} {were} left alone: this run was not given that host as a \
         patch server, so it cannot tell {those} from the project's own; pass \
         `--patch-server-url {origin}` (or set SOCKET_PATCH_SERVER_URL) to let this command \
         tidy what no lockfile uses of {them}"
    )
}

/// What a [`sweep`] did.
#[derive(Debug, Default)]
pub(crate) struct RegistryGc {
    /// The entries removed (on a dry run: that would be). Empty when the
    /// files could not be written.
    pub(crate) entries: Vec<RegistryEntry>,
    /// Root-relative files rewritten or deleted (or that would be).
    pub(crate) files: Vec<String>,
    pub(crate) warnings: Vec<(&'static str, String)>,
}

/// Whether the project holds anything of a registry route: asked before a
/// lock is taken for a [`sweep`], so a project without one never gains a
/// `.socket/`.
pub(crate) async fn route_present(common: &GlobalArgs) -> bool {
    !common.is_global()
        && socket_patch_core::hosted::engine::pnpm_route_present(&common.project_root()).await
}

/// [`route_present`], asked at most once by the pass that holds it. The
/// question lists the members of a workspace and reads their locks, and
/// its answer does not change between the check that keeps a project
/// without a route free of a `.socket/` and the sweep the check is for.
#[derive(Debug, Default)]
pub(crate) struct RouteProbe(Option<bool>);

impl RouteProbe {
    pub(crate) async fn present(&mut self, common: &GlobalArgs) -> bool {
        match self.0 {
            Some(known) => known,
            None => *self.0.insert(route_present(common).await),
        }
    }
}

/// Take the unused entries of the project's registry route out of its
/// pnpm-workspace.yaml and pnpm locks (`dry_run`: say what would go).
/// A wet sweep runs under the caller's apply lock. A global-scope run has
/// no project lockfiles to judge by and sweeps nothing.
pub(crate) async fn sweep(common: &GlobalArgs, dry_run: bool) -> RegistryGc {
    if common.is_global() {
        return RegistryGc::default();
    }
    let opts = RestoreOptions {
        dry_run,
        offline: true,
        patch_server_origins: crate::commands::hosted_unwind::patch_server_origins(common),
        bun_lockb: false,
    };
    let swept = sweep_pnpm_registry_route(&common.project_root(), &opts).await;
    let mut out = RegistryGc::default();
    if let Some(why) = swept.unread {
        out.warnings.push((
            REGISTRY_CLEANUP_SKIPPED,
            format!(
                "the pnpm registry entries of hosted patches were not checked for unused \
                 ones: {why}"
            ),
        ));
        return out;
    }
    out.warnings
        .extend(swept.unknown_hosts.iter().map(|(origin, count)| {
            (
                REGISTRY_CLEANUP_UNKNOWN_HOST,
                unknown_host_detail(origin, *count),
            )
        }));
    if let Some(why) = swept.flush_error {
        out.warnings.push((
            REGISTRY_CLEANUP_FAILED,
            format!("unused pnpm registry entries of hosted patches were not removed: {why}"),
        ));
        out.files = swept.half_applied;
        return out;
    }
    out.entries = socket_patch_core::hosted::guidance::pnpm_registry_entries_removed(&swept.edits);
    out.files = swept.files;
    out
}

/// The event of one removed entry: artifact-level (no `purl`), `removed`
/// or, on a dry run, `verified`. A registry's address carries its grant's
/// token, so it is not in the event.
fn event(entry: &RegistryEntry, dry_run: bool) -> PatchEvent {
    let mut details = serde_json::json!({
        "mode": crate::commands::HOSTED_MODE_LABEL,
        "file": entry.file,
        "entry": entry.kind.as_str(),
        "key": entry.key,
    });
    if let Some(value) = entry.shown_value() {
        details["value"] = value.into();
    }
    let action = if dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Removed
    };
    PatchEvent::artifact(action)
        .with_reason(
            REGISTRY_ENTRY_UNUSED,
            format!("{}: no lockfile uses it any more", entry.describe()),
        )
        .with_details(details)
}

/// Report the removed entries in `env`, one event each. Pushed directly,
/// as the GC carrier event is: the `summary` counters count patches.
pub(crate) fn record(env: &mut Envelope, entries: &[RegistryEntry], dry_run: bool) {
    env.events
        .extend(entries.iter().map(|entry| event(entry, dry_run)));
}

/// The human lines for the removed entries: a headline, then one line per
/// entry. Empty when nothing was removed.
pub(crate) fn lines(entries: &[RegistryEntry], dry_run: bool) -> Vec<String> {
    if entries.is_empty() {
        return Vec::new();
    }
    let count = crate::ui::plural(
        entries.len(),
        "pnpm registry entry",
        "pnpm registry entries",
    );
    let headline = if dry_run {
        format!("Would remove {count} that no lockfile uses any more:")
    } else {
        format!("Removed {count} that no lockfile uses any more:")
    };
    std::iter::once(headline)
        .chain(
            entries
                .iter()
                .map(|entry| format!("  - {}", entry.describe())),
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::hosted::guidance::RegistryEntryKind;

    fn entry(kind: RegistryEntryKind, key: &str, value: &str) -> RegistryEntry {
        RegistryEntry {
            file: "pnpm-workspace.yaml".into(),
            kind,
            key: key.into(),
            value: value.into(),
        }
    }

    /// A registry's address carries the token of its grant: it reaches
    /// neither the envelope nor the terminal.
    #[test]
    fn a_registry_address_is_never_shown() {
        const TOKEN: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
        let address = format!(
            "https://patch.test/patch/npm/left-pad/1.3.0/{TOKEN}/11111111-1111-4111-8111-111111111111/"
        );
        let entries = [
            entry(RegistryEntryKind::Registry, "socket-11111111", &address),
            entry(
                RegistryEntryKind::Override,
                "left-pad@1.3.0",
                "socket-11111111:1.3.0",
            ),
        ];
        let mut env = Envelope::new(crate::json_envelope::Command::Repair);
        record(&mut env, &entries, false);
        let json = env.to_pretty_json();
        assert!(!json.contains(TOKEN), "{json}");
        let shown = lines(&entries, false).join("\n");
        assert!(!shown.contains(TOKEN), "{shown}");
        assert_eq!(
            shown,
            "Removed 2 pnpm registry entries that no lockfile uses any more:\n  \
             - namedRegistries entry `socket-11111111` of pnpm-workspace.yaml\n  \
             - overrides entry `left-pad@1.3.0` of pnpm-workspace.yaml"
        );
        // One artifact-level event per entry, counted by no summary field.
        let value = env.to_value();
        assert_eq!(value["summary"]["removed"], 0);
        assert_eq!(
            value["events"][1],
            serde_json::json!({
                "action": "removed",
                "errorCode": "registry_entry_unused",
                "reason": "overrides entry `left-pad@1.3.0` of pnpm-workspace.yaml: \
                           no lockfile uses it any more",
                "details": {
                    "mode": "hosted",
                    "file": "pnpm-workspace.yaml",
                    "entry": "override",
                    "key": "left-pad@1.3.0",
                    "value": "socket-11111111:1.3.0",
                },
            })
        );
        assert_eq!(
            value["events"][0]["details"],
            serde_json::json!({
                "mode": "hosted",
                "file": "pnpm-workspace.yaml",
                "entry": "registry",
                "key": "socket-11111111",
            })
        );
    }

    /// The notice for registries passed over on a host the run was not
    /// told of names the host by its origin, how many there are, and the
    /// setting that lets the command tidy them, in one sentence that
    /// reads right for one registry and for several.
    #[test]
    fn the_unknown_host_notice_names_the_origin_and_the_setting() {
        const ORIGIN: &str = "https://patch.staging.example:8443";
        let one = unknown_host_detail(ORIGIN, 1);
        assert_eq!(
            one,
            "1 pnpm registry of a hosted patch on https://patch.staging.example:8443 was left \
             alone: this run was not given that host as a patch server, so it cannot tell that \
             registry from the project's own; pass `--patch-server-url \
             https://patch.staging.example:8443` (or set SOCKET_PATCH_SERVER_URL) to let this \
             command tidy what no lockfile uses of it"
        );
        let several = unknown_host_detail(ORIGIN, 3);
        assert!(
            several.starts_with(
                "3 pnpm registries of hosted patches on https://patch.staging.example:8443 were \
                 left alone:"
            ) && several.contains("those registries")
                && several.ends_with("of them"),
            "{several}"
        );
        for detail in [one, several] {
            assert!(!detail.contains('\n') && !detail.ends_with('.'), "{detail}");
        }
    }

    #[test]
    fn a_dry_run_says_what_would_go() {
        let entries = [entry(
            RegistryEntryKind::Override,
            "left-pad@1.3.0",
            "socket-11111111:1.3.0",
        )];
        let mut env = Envelope::new(crate::json_envelope::Command::Repair);
        record(&mut env, &entries, true);
        assert_eq!(env.to_value()["events"][0]["action"], "verified");
        assert_eq!(
            lines(&entries, true)[0],
            "Would remove 1 pnpm registry entry that no lockfile uses any more:"
        );
        assert!(lines(&[], true).is_empty());
    }
}
