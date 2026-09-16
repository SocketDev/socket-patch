//! Captured package-manager output and grammar boundary regressions. Real
//! install/hash/VEX/rollback proofs live in e2e_redirect_pnpm_build.
use socket_patch_core::patch::redirect::{rewrite_registry_redirect, DepOverride, Integrity};
use std::collections::BTreeMap;

fn dep(name: &str) -> DepOverride {
    let (namespace, name) = name
        .rsplit_once('/')
        .map_or((None, name), |(ns, n)| (Some(ns.to_string()), n));
    DepOverride {
        ecosystem: "npm".into(),
        name: name.into(),
        namespace,
        version: "1.3.0".into(),
        token: "token".into(),
        patch_uuid: "patch-id".into(),
        artifact_url: "https://patch.example/left-pad-1.3.0.tgz".into(),
        berry_zip_url: None,
        registry_override: None,
        integrity: Integrity {
            sha512: Some("sha512-PATCHED==".into()),
            ..Default::default()
        },
    }
}

fn roundtrip(path: &str, lock: &str, target: &DepOverride, instances: usize) {
    let files = BTreeMap::from([(path.to_string(), lock.to_string())]);
    let first = rewrite_registry_redirect(&files, std::slice::from_ref(target));
    assert!(first.warnings.is_empty(), "{path}: {:?}", first.warnings);
    assert_eq!(first.edits.len(), instances, "{path}");
    let output = &first.files[path];
    assert_eq!(output.matches(&target.artifact_url).count(), instances);
    // Every recorded inverse must restore exactly the captured upstream bytes.
    let mut restored = output.clone();
    for edit in first.edits.iter().rev() {
        restored = restored.replacen(
            edit.new.as_ref().unwrap().as_str().unwrap(),
            edit.original.as_ref().unwrap().as_str().unwrap(),
            1,
        );
    }
    assert_eq!(restored, lock, "{path}: lossless rollback fragments");
    let again = rewrite_registry_redirect(&first.files, std::slice::from_ref(target));
    assert!(
        again.files.is_empty() && again.edits.is_empty(),
        "{path}: rerun must be stable"
    );
    assert!(again.warnings.is_empty(), "{path}: {:?}", again.warnings);
}

#[test]
fn captured_locks_from_every_pnpm_major_roundtrip_in_lf_and_crlf() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pnpm-hosted");
    let mut cases = 0;
    for dir in std::fs::read_dir(root).unwrap() {
        let dir = dir.unwrap().path();
        if !dir.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(dir).unwrap() {
            let path = file.unwrap().path();
            let lock = std::fs::read_to_string(&path).unwrap();
            let name = path.file_name().unwrap().to_str().unwrap();
            for lock in [&lock, &lock.replace('\n', "\r\n")] {
                roundtrip(name, lock, &dep("left-pad"), 1);
            }
            cases += 1;
        }
    }
    assert_eq!(cases, 12, "every pinned major needs a real captured lock");
}

#[test]
fn scoped_peers_aliases_workspaces_and_bystanders_preserve_the_graph() {
    for key in [
        "/@scope/left-pad/1.3.0_peer@2.0.0",
        "/@scope/left-pad@1.3.0(peer@2.0.0(child@3.0.0))",
        "@scope/left-pad@1.3.0",
    ] {
        for quote in ["", "'", "\""] {
            if key.starts_with('@') && quote.is_empty() {
                continue;
            }
            let lock = format!("lockfileVersion: '6.0'\nimporters:\n  packages/app:\n    dependencies:\n      alias:\n        specifier: npm:@scope/left-pad@1.3.0\n        version: {key}\npackages:\n  {quote}{key}{quote}:\n    resolution: {{integrity: sha512-UPSTREAM==}}\n    dependencies:\n      child: 3.0.0\n  /left-pad@1.3.0:\n    resolution: {{integrity: sha512-BYSTANDER==}}\n  /@scope/left-pad@1.3.0-beta.1:\n    resolution: {{integrity: sha512-BYSTANDER==}}\nsnapshots:\n  '@scope/left-pad@1.3.0(peer@2.0.0)': {{}}\n");
            roundtrip("pnpm-lock.yaml", &lock, &dep("@scope/left-pad"), 1);
        }
    }
}

#[test]
fn malformed_resolution_refuses_the_dependency_across_all_locks() {
    for bad in [
        "*shared",
        "{integrity: one, integrity: two}",
        "{integrity: one, tarball: two, tarball: three}",
        "{integrity: one, extra: [nested]}",
        "\n      integrity: one\n\n      tarball: https://unpatched.example/file.tgz",
        "\n      integrity: one\n      nested:\n        field: value",
    ] {
        let files = BTreeMap::from([
            (
                "pnpm-lock.yaml".into(),
                "packages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n"
                    .into(),
            ),
            (
                "common/config/rush/pnpm-lock.yaml".into(),
                format!("packages:\n  /left-pad@1.3.0(peer@2.0.0):\n    resolution: {bad}\n"),
            ),
        ]);
        let result = rewrite_registry_redirect(&files, &[dep("left-pad")]);
        assert!(
            result.files.is_empty() && result.edits.is_empty(),
            "{bad}: partial rewrite"
        );
        assert!(result
            .warnings
            .iter()
            .any(|w| w.code == "redirect_pnpm_unsupported_lock_key"));
    }
}

#[test]
fn quoted_flow_values_keep_commas_and_extra_fields() {
    let lock = "packages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-UPSTREAM==, tarball: 'https://registry.example/a,b.tgz', note: 'keep,a,b'}\n";
    let mut target = dep("left-pad");
    target.artifact_url = "https://patch.example/a,b.tgz".into();
    roundtrip("pnpm-lock.yaml", lock, &target, 1);
}

#[test]
fn mixed_newlines_preserve_unrelated_bytes() {
    let lock = "# comment\npackages:\r\n  left-pad@1.3.0:\r\n    resolution:\r\n      integrity: sha512-UPSTREAM==\r\n\nsnapshots:\n  left-pad@1.3.0: {}\n";
    roundtrip("pnpm-lock.yaml", lock, &dep("left-pad"), 1);
}

#[test]
fn early_pnpm1_refuses_non_durable_shrinkwrap_across_all_locks() {
    let old = "shrinkwrapVersion: 3\npackages:\n  /left-pad/1.3.0:\n    resolution:\n      integrity: sha1-UPSTREAM=\n";
    let newer = "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n";
    let files = BTreeMap::from([
        ("shrinkwrap.yaml".into(), old.into()),
        ("pnpm-lock.yaml".into(), newer.into()),
    ]);
    let result = rewrite_registry_redirect(&files, &[dep("left-pad")]);
    assert!(result.files.is_empty() && result.edits.is_empty());
    assert!(result.refused_pnpm_uuids.contains("patch-id"));
    assert_eq!(
        result.warnings[0].code,
        "redirect_pnpm_legacy_lockfile_unsupported"
    );
}
