//! The block that hosted and vendored mode keep in the root `MODULE.bazel`
//! of a Bazel workspace ([`crate::bazel::maven`]): each of its entries puts
//! a patched jar in the place of the one a rules_jvm_external hub fetches.
//! An entry with the URL of that jar is a hosted pin of the jar's package.
//! One that names a directory of the checkout is vendored wiring: its
//! artifact is the jar committed there, `.socket/vendor/maven/<patch
//! id>/file/<artifact>-<version>.jar`, which is hashed like any vendored
//! artifact.
//!
//! - An entry whose jar a pinned hub still fetches at the entry's version
//!   is a ref: a build takes the patched jar, at the sha256 of the entry,
//!   or fails.
//! - An entry whose version no lock of a hub holds any more (Bazel stops
//!   at it), whose hub cannot be read, or which an rc file switches off,
//!   on whatever line, or may switch off because it cannot be read, is
//!   withheld from attestation ([`Discovery::shadow`]): `rollback`,
//!   `remove` and `list` still see it.
//! - A block that was changed by hand yields nothing: its patch ids are
//!   recognized and contested.
//!
//! A `MODULE.bazel` without the block's first line wires nothing and is
//! not read as a lock; one whose first line was touched is a block that
//! was changed by hand. The hubs and their locks are read from the checkout
//! on disk; over an in-memory project, which has no hub lane, nothing is
//! read at all.

use super::{
    vendor_ref, DiscoverCtx, Discovery, PatchedRef, DIAG_REF_INVALID, DIAG_REF_UNATTRIBUTABLE,
};
use crate::bazel::maven::{begins, pins, Pin, FILE};
use crate::utils::purl::maven_purl;
use crate::vendor::lock_inventory::LockIntegrity;

pub(crate) async fn extract(ctx: &DiscoverCtx<'_>, out: &mut Discovery) {
    let block = |text: &String| text.lines().any(begins);
    if !ctx
        .read_advisory_text(FILE)
        .await
        .is_some_and(|text| block(&text))
    {
        return;
    }
    let Some(root) = ctx.disk_root().map(std::path::Path::to_path_buf) else {
        return;
    };
    let Some(module) = ctx.read_text(FILE, out).await else {
        return;
    };
    let read = crate::utils::fs::run_blocking(move || pins(&root, &module)).await;
    let pins = match read {
        Ok(pins) => pins,
        Err(why) => return out.diag(DIAG_REF_INVALID, FILE, why),
    };
    for Pin { patch, unbuilt } in pins {
        // The patch an entry is for is the one its URL names on a patch
        // host, or the one whose directory it names, and nothing else
        // says so.
        let purl = maven_purl(&patch.group, &patch.artifact, &patch.version);
        let vendored = patch.jar().map(|jar| vendor_ref(&jar));
        let wired = match (purl, vendored) {
            (Some(purl), Some(Some(jar))) if jar.uuid == patch.uuid => {
                Some(PatchedRef::vendored(purl, &jar, FILE, None))
            }
            (Some(purl), None) if ctx.hosted_uuid(&patch.url).as_ref() == Some(&patch.uuid) => {
                let sum = LockIntegrity::Sha256Hex(patch.sha256.clone());
                let (uuid, url) = (patch.uuid.clone(), Some(&*patch.url));
                Some(PatchedRef::hosted(purl, uuid, FILE, url, Some(sum), true))
            }
            _ => None,
        };
        let Some(wired) = wired else {
            let detail = format!("the entry of patch {} names no jar of it", patch.uuid);
            out.diag(DIAG_REF_INVALID, FILE, detail);
            continue;
        };
        match unbuilt {
            None => out.push(wired),
            Some(why) => {
                let detail = format!("{}: patch {}: {why}", wired.purl, wired.uuid);
                out.diag(DIAG_REF_UNATTRIBUTABLE, FILE, detail);
                out.shadow(wired);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::*;
    use super::super::WiringMode::Hosted;
    use super::*;
    use crate::bazel::maven::tests::sample;
    use crate::bazel::maven::BEGIN;
    use crate::patch::redirect::upstream::HostedInventory;

    const PURL: &str = "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final";

    /// A project whose hub is pinned, with `module` and `lock`.
    fn project(module: &str, lock: &str) -> Project {
        let p = Project::new();
        p.write(FILE, module).write("maven_install.json", lock);
        p
    }

    async fn extracted(p: &Project) -> Discovery {
        let out = p.run(|c, o| Box::pin(super::extract(c, o))).await;
        // The orchestrator finds the same, and no other extractor reads
        // the file.
        let all = p.discover().await;
        assert_eq!((&all.refs, &all.shadowed), (&out.refs, &out.shadowed));
        assert_eq!(all.diagnostics, out.diagnostics);
        out
    }

    #[tokio::test]
    async fn an_entry_whose_jar_a_pinned_hub_fetches_is_a_hosted_pin() {
        let [_, lock, ours] = sample(UUID_A);
        let out = extracted(&project(&ours, &lock)).await;
        assert_refs(&out, &[(PURL, UUID_A, Hosted)]);
        assert_eq!(out.diagnostics, []);
        let wired = &out.refs[0];
        let sum = LockIntegrity::Sha256Hex("5".repeat(64));
        assert_eq!(wired.source_file, std::path::Path::new(FILE));
        assert_eq!(wired.locked_integrity, Some(sum));
        assert!(wired.integrity_required && wired.lockfile_basis_ok());
        // What the management commands read: one pin, nothing contested.
        let inventory = HostedInventory::of(&out);
        let pins: Vec<_> = inventory
            .pins
            .iter()
            .map(|pin| (&*pin.purl, &*pin.uuid))
            .collect();
        assert_eq!(pins, [(PURL, UUID_A)]);
        assert_eq!((inventory.contested, inventory.stale), (vec![], vec![]));
        assert_eq!(inventory.pins[0].files, [FILE]);
    }

    /// The entry of vendored mode is vendored wiring: its artifact is the
    /// jar committed in the directory it names, which a ledger entry of
    /// that jar is live by. It is no hosted pin. One whose jar the hub no
    /// longer fetches is withheld like a hosted one.
    #[tokio::test]
    async fn an_entry_that_names_a_directory_is_vendored_wiring() {
        use crate::bazel::maven::{with_patch, Patch};
        let [plain, lock, _] = sample(UUID_A);
        let patch = Patch {
            group: "io.netty".to_string(),
            artifact: "netty-tcnative-classes".to_string(),
            version: "2.0.61.Final".to_string(),
            uuid: UUID_A.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let jar = patch.jar().expect("a vendored entry");
        let label = "@rules_jvm_external//:extensions.bzl";
        let ours = with_patch(&plain, label, patch).expect("a block");
        let out = extracted(&project(&ours, &lock)).await;
        assert_refs(&out, &[(PURL, UUID_A, super::super::WiringMode::Vendored)]);
        assert_eq!(out.diagnostics, []);
        assert_eq!(out.refs[0].artifact_rel.as_deref(), Some(jar.as_str()));
        assert_eq!(out.vendored_claim(PURL, UUID_A, &jar), Some(true));
        assert_eq!(HostedInventory::of(&out).pins.len(), 0);
        let moved = lock.replace("2.0.61.Final", "2.0.62.Final");
        let out = extracted(&project(&ours, &moved)).await;
        assert_refs(&out, &[]);
        assert_eq!(diag_codes(&out), [DIAG_REF_UNATTRIBUTABLE]);
        assert_eq!(out.vendored_claim(PURL, UUID_A, &jar), Some(false));
    }

    /// An entry that a build may pass without (the lock moved on, a hub
    /// cannot be read, an rc file switches it off below an option that
    /// does not, or cannot be read) attests nothing, and is still a pin
    /// of one package version that the undo takes out.
    #[tokio::test]
    async fn an_entry_bazel_may_not_build_is_withheld_and_still_a_pin() {
        let [_, lock, ours] = sample(UUID_A);
        let moved = lock.replace("2.0.61.Final", "2.0.62.Final");
        let empty = String::new();
        for (lock, rc, why) in [
            (
                &moved,
                "",
                "no pinned hub takes io.netty:netty-tcnative-classes at 2.0.61.Final",
            ),
            (
                &empty,
                "",
                "maven_install.json: it is empty: the hub is not pinned yet",
            ),
            (
                &lock,
                "common --ignore_dev_dependency\n",
                ".bazelrc:1 names `--ignore_dev_dependency`",
            ),
            (
                &lock,
                "build --repository_disable_download\ncommon --noenable_bzlmod\n",
                ".bazelrc:2 names `--noenable_bzlmod`, which switches off the file",
            ),
            (
                &lock,
                "common --lockfile_mode=error\nimport %workspace%/ci.bazelrc\n",
                "the rc file ci.bazelrc cannot be read, and may switch an entry off",
            ),
        ] {
            let p = project(&ours, lock);
            // An rc file that is a directory cannot be read.
            p.write(".bazelrc", rc).write("ci.bazelrc/a", "");
            let out = extracted(&p).await;
            assert_refs(&out, &[]);
            assert_eq!(diag_codes(&out), [DIAG_REF_UNATTRIBUTABLE], "{why}");
            let detail = &out.diagnostics[0].detail;
            let named = format!("{PURL}: patch {UUID_A}: ");
            assert!(
                detail.starts_with(&named) && detail.contains(why),
                "{detail}"
            );
            let shadowed: Vec<_> = out.shadowed.iter().map(|r| (&*r.purl, &*r.uuid)).collect();
            assert_eq!(shadowed, [(PURL, UUID_A)], "{why}");
            let inventory = HostedInventory::of(&out);
            assert_eq!(inventory.pins.len(), 1, "{why}");
            assert_eq!(inventory.contested, [], "{why}");
        }
    }

    /// A block that is not as socket-patch wrote it, and an entry whose
    /// URL is on no patch host or names another patch, are no pin: the
    /// patch ids the file mentions are contested, and nothing is undone.
    #[tokio::test]
    async fn a_block_that_was_changed_by_hand_is_no_pin() {
        let [_, lock, ours] = sample(UUID_A);
        let moved = ours.replace(
            &format!("/{TOKEN_LIKE}/{UUID_A}/"),
            &format!("/{UUID_A}/{UUID_B}/"),
        );
        for (module, why) in [
            (
                ours.replace("# Do not change", "# Do change"),
                "was changed by hand",
            ),
            // Its first line with a blank after it: still a block.
            (
                ours.replace(BEGIN, &format!("{BEGIN} ")),
                "was changed by hand",
            ),
            (moved, "names no jar of it"),
            (
                ours.replace("https://patch.socket.dev/", "https://mirror.example/"),
                "names no jar of it",
            ),
        ] {
            assert_ne!(module, ours, "{why}");
            let out = extracted(&project(&module, &lock)).await;
            assert_refs(&out, &[]);
            assert_eq!(
                (out.shadowed.len(), diag_codes(&out)),
                (0, vec![DIAG_REF_INVALID]),
                "{why}"
            );
            assert!(
                out.diagnostics[0].detail.contains(why),
                "{:?}",
                out.diagnostics
            );
            let inventory = HostedInventory::of(&out);
            // The ids its URLs still name on a patch host are contested.
            let hosted = module.contains("https://patch.socket.dev/");
            assert_eq!(inventory.pins.len(), 0, "{why}");
            assert_eq!(inventory.contested.is_empty(), !hosted, "{why}");
        }
    }

    /// A `MODULE.bazel` without the block is not read as a lock, whatever
    /// it mentions, and an in-memory project, which has no hub lane, is
    /// not read at all.
    #[tokio::test]
    async fn without_the_block_nothing_is_read() {
        let [plain, lock, ours] = sample(UUID_A);
        let url = ours
            .lines()
            .find(|line| line.contains("urls = "))
            .expect("the URL");
        let pasted = format!("{plain}# {url}\n# {}\n", BEGIN.replace(">>>", ">>"));
        let out = extracted(&project(&pasted, &lock)).await;
        assert_eq!((out.refs.len(), out.diagnostics.len()), (0, 0));
        assert_eq!((out.recognized.len(), out.read.len()), (0, 0));

        let mut memory = crate::vendor::lock_inventory::MemoryProject::default();
        memory.insert(
            FILE,
            crate::vendor::lock_inventory::MemoryEntry::Text(ours.into()),
        );
        let view = crate::vendor::lock_inventory::ProjectView::Memory(&memory);
        let out = super::super::discover_patched_refs_view(view, &Default::default()).await;
        assert_eq!(
            (out.refs.len(), out.recognized.len(), out.read.len()),
            (0, 0, 0)
        );
    }

    /// The token of the sample's URL.
    const TOKEN_LIKE: &str = "token";
}
