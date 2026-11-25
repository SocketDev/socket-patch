//! The upstream restore of a Maven patch that a rules_jvm_external hub of
//! a Bazel workspace builds: the inverse of [`crate::bazel::maven::rewrite`],
//! no network. Its entry is taken out of the block in the root
//! `MODULE.bazel`; with the last entry the block goes, and the file is
//! byte for byte what it was before its first patch. The hub then fetches
//! the jar its lock pins again. A block that was changed by hand is
//! refused: nothing of it is socket-patch's to rewrite.

use super::{FormatResult, HostedPin, View};
use crate::bazel::maven::{without, Patch, FILE};

pub(crate) async fn restore(view: &mut View<'_>, pins: &[&HostedPin]) -> FormatResult {
    let mut result = FormatResult::default();
    let wired = |pin: &&&HostedPin| pin.files.iter().any(|file| file == FILE);
    let pins: Vec<&HostedPin> = pins.iter().filter(wired).copied().collect();
    let module = match view.read(FILE).await {
        Ok(Some(module)) => Ok(module),
        Ok(None) => Err(format!("{FILE} is gone")),
        Err(why) => Err(why),
    };
    // The entries of exactly these pins: a patch id for the package the
    // entry names, in an entry of hosted mode. A vendored one is no pin.
    let mut gone = Vec::new();
    let mut named = |patch: &Patch| {
        let hosted = patch.unit().is_none();
        let pin = pins
            .iter()
            .find(|pin| hosted && pin.uuid == patch.uuid && pin.purl == patch.purl());
        gone.extend(pin.map(|pin| pin.uuid.clone()));
        pin.is_some()
    };
    let restored = module.and_then(|module| {
        let why = format!("the block in {FILE} is not as socket-patch wrote it");
        without(&module, &mut named).ok_or(why)
    });
    for pin in &pins {
        match &restored {
            Ok(_) if gone.contains(&pin.uuid) => drop(result.handled.insert(pin.uuid.clone())),
            Ok(_) => result.refuse(&pin.uuid, format!("{FILE} holds no entry of this patch")),
            Err(why) => result.refuse(&pin.uuid, why.clone()),
        }
    }
    if let (Ok(module), false) = (restored, gone.is_empty()) {
        view.write(FILE, module);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::{restore_upstream, RestoreOptions};
    use super::*;
    use crate::bazel::maven::tests::sample;

    const PURL: &str = "pkg:maven/io.netty/netty-tcnative-classes@2.0.61.Final";
    const UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";

    fn pin(purl: &str, uuid: &str) -> HostedPin {
        HostedPin {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            files: vec![FILE.to_string()],
        }
    }

    /// A checkout with `module`, and what a restore of `pins` there does:
    /// the reason of each pin it refuses, and the file as it is left.
    async fn restored(module: &str, pins: &[HostedPin], dry_run: bool) -> (Vec<String>, String) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(FILE);
        std::fs::write(&file, module).unwrap();
        let options = RestoreOptions {
            offline: true,
            dry_run,
            ..Default::default()
        };
        let out = restore_upstream(dir.path(), pins, &options).await;
        assert_eq!(out.flush_error, None);
        let refused = out.refused().map(|(_, why)| why.to_string()).collect();
        (refused, std::fs::read_to_string(&file).unwrap())
    }

    #[tokio::test]
    async fn the_last_entry_out_leaves_the_file_as_it_was() {
        let [plain, _, ours] = sample(UUID);
        let none: [String; 0] = [];
        let pins = [pin(PURL, UUID)];
        assert_eq!(
            restored(&ours, &pins, false).await,
            (none.to_vec(), plain.clone())
        );
        // A dry run says the same and writes nothing.
        assert_eq!(
            restored(&ours, &pins, true).await,
            (none.to_vec(), ours.clone())
        );
        // The same in a file of CRLF lines without a last line break.
        let crlf = plain.trim_end().replace('\n', "\r\n");
        let block = ours.strip_prefix(&plain).expect("the block").trim();
        let patched = format!("{crlf}\r\n\r\n{}", block.replace('\n', "\r\n"));
        assert_eq!(
            restored(&patched, &pins, false).await,
            (none.to_vec(), crlf)
        );
    }

    /// A checkout that Maven builds too holds the patch in its `pom.xml`
    /// as well: one pin, wired in two files. Each restorer takes the pin
    /// out of its own file, and both are as they were before.
    #[tokio::test]
    async fn a_pin_that_a_pom_holds_too_is_taken_out_of_both_files() {
        let [plain, lock, ours] = sample(UUID);
        // The golden pom of the Maven rewriter, for the sample's jar.
        let pom = |side: &str| {
            let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
            let path = format!("{fixtures}/redirect/maven/pom/basic/{side}/pom.xml");
            std::fs::read_to_string(path)
                .unwrap()
                .replace("org.slf4j", "io.netty")
                .replace("slf4j-api", "netty-tcnative-classes")
                .replace("77777777-7777-7777-7777-777777777777", UUID)
                .replace("1.7.36-socket.77777777", "2.0.61.Final-socket.7c8d9e0f")
                .replace("1.7.36", "2.0.61.Final")
        };
        let dir = tempfile::tempdir().unwrap();
        let files = [
            (FILE, &ours),
            ("maven_install.json", &lock),
            ("pom.xml", &pom("expected")),
        ];
        for (rel, text) in files {
            std::fs::write(dir.path().join(rel), text).unwrap();
        }
        let disk = crate::vendor::lock_inventory::ProjectView::Disk(dir.path());
        let pins = HostedPin::discover(disk, &[]).await;
        let both = HostedPin {
            files: vec![FILE.to_string(), "pom.xml".to_string()],
            ..pin(PURL, UUID)
        };
        assert_eq!(pins, [both]);
        let options = RestoreOptions {
            offline: true,
            ..Default::default()
        };
        let out = restore_upstream(dir.path(), &pins, &options).await;
        assert_eq!((out.refused().count(), &out.flush_error), (0, &None));
        let left = |rel: &str| std::fs::read_to_string(dir.path().join(rel)).unwrap();
        assert_eq!((left(FILE), left("pom.xml")), (plain, pom("input")));
    }

    #[tokio::test]
    async fn what_is_not_an_entry_of_the_pin_is_refused_and_nothing_is_written() {
        let [plain, _, ours] = sample(UUID);
        let other = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let edited = ours.replace("# Do not change", "# Do change");
        // The entry of vendored mode for the same patch is no hosted pin.
        let label = "@rules_jvm_external//:extensions.bzl";
        let [group, artifact, version] =
            ["io.netty", "netty-tcnative-classes", "2.0.61.Final"].map(String::from);
        let vendored = Patch {
            group,
            artifact,
            version,
            uuid: UUID.to_string(),
            sha256: String::new(),
            url: String::new(),
        };
        let vendored = crate::bazel::maven::with_patch(&plain, label, vendored).unwrap();
        for (module, pins, why) in [
            (
                &vendored,
                vec![pin(PURL, UUID)],
                "MODULE.bazel holds no entry of this patch",
            ),
            (
                &ours,
                vec![pin(PURL, other)],
                "MODULE.bazel holds no entry of this patch",
            ),
            (
                &ours,
                vec![pin(
                    "pkg:maven/io.netty/netty-tcnative-classes@2.0.62.Final",
                    UUID,
                )],
                "MODULE.bazel holds no entry of this patch",
            ),
            (
                &edited,
                vec![pin(PURL, UUID)],
                "the block in MODULE.bazel is not as socket-patch wrote it",
            ),
            (
                &plain,
                vec![pin(PURL, UUID)],
                "the block in MODULE.bazel is not as socket-patch wrote it",
            ),
        ] {
            let (refused, left) = restored(module, &pins, false).await;
            assert_eq!(&left, module, "{why}");
            assert_eq!(refused.len(), 1, "{refused:?}");
            assert!(refused[0].contains(why), "{refused:?}");
            assert!(
                refused[0].contains("`git checkout -- MODULE.bazel`"),
                "{refused:?}"
            );
        }
    }
}
