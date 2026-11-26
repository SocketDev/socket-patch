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
        npm_registry_url: None,
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

/// A v9 lock in which `left-pad@1.3.0` depends on `leaf`, resolved as
/// `resolution` and reached through the snapshot value `leaf`.
fn lock_with_dependency(resolution: &str, leaf: &str) -> String {
    format!(
        "lockfileVersion: '9.0'\n\npackages:\n\n  left-pad@1.3.0:\n    resolution: {resolution}\n\n  \
         other@1.0.0:\n    resolution: {{integrity: sha512-OTHER==}}\n\nsnapshots:\n\n  \
         left-pad@1.3.0(peer@2.0.0):\n    dependencies:\n      leaf: {leaf}\n      peer: 2.0.0\n\n  \
         other@1.0.0:\n    dependencies:\n      leaf: 1.0.0\n"
    )
}

/// pnpm 12.23 refuses a lock in which a package fetched from a tarball
/// URL depends on a local file (#2263), so the pin that would take such a
/// package off the default registry is refused in every lock.
#[test]
fn a_package_with_a_local_dependency_is_not_taken_off_the_registry() {
    const UPSTREAM: &str = "{integrity: sha512-UPSTREAM==}";
    for local in [
        "file:.socket/vendor/npm/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/leaf-1.0.0.tgz",
        "'file:.socket/vendor/npm/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/leaf-1.0.0.tgz'",
        "link:../leaf",
    ] {
        let files = BTreeMap::from([
            (
                "pnpm-lock.yaml".to_string(),
                lock_with_dependency(UPSTREAM, local),
            ),
            (
                "common/config/rush/pnpm-lock.yaml".to_string(),
                lock_with_dependency(UPSTREAM, "1.0.0"),
            ),
        ]);
        let result = rewrite_registry_redirect(&files, &[dep("left-pad")]);
        assert!(
            result.files.is_empty() && result.edits.is_empty(),
            "{local}: partial rewrite"
        );
        assert!(result.refused_pnpm_uuids.contains("patch-id"), "{local}");
        let warnings: Vec<_> = result
            .warnings
            .iter()
            .filter(|w| w.code == "redirect_pnpm_local_dependency")
            .collect();
        let [warning] = warnings.as_slice() else {
            panic!("{local}: one refusal, for the lock that has the dependency: {warnings:?}");
        };
        let unquoted = local.trim_matches('\'');
        assert!(
            warning.detail.contains(&format!("`leaf: {unquoted}`"))
                && warning.detail.contains("in pnpm-lock.yaml")
                && warning.detail.contains("ERR_PNPM_LOCAL_SUBDEP_NOT_ALLOWED"),
            "{}",
            warning.detail
        );
    }
}

/// The refusal is for the package the pin moves, and only when the pin
/// moves it: a registry dependency, another package's local dependency and
/// a package that already names a tarball are all pinned as before.
#[test]
fn the_local_dependency_refusal_is_scoped_to_the_new_pin() {
    const LOCAL: &str =
        "file:.socket/vendor/npm/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/leaf-1.0.0.tgz";
    let other_has_it = lock_with_dependency("{integrity: sha512-UPSTREAM==}", "1.0.0").replace(
        "  other@1.0.0:\n    dependencies:\n      leaf: 1.0.0\n",
        &format!("  other@1.0.0:\n    dependencies:\n      leaf: {LOCAL}\n"),
    );
    assert!(other_has_it.contains(LOCAL));
    for (what, lock) in [
        (
            "a registry dependency",
            lock_with_dependency("{integrity: sha512-UPSTREAM==}", "1.0.0"),
        ),
        ("another package's local dependency", other_has_it),
        (
            "a package that already names a tarball",
            lock_with_dependency(
                "{integrity: sha512-STALE==, tarball: https://patch.example/stale/left-pad-1.3.0.tgz}",
                LOCAL,
            ),
        ),
    ] {
        let files = BTreeMap::from([("pnpm-lock.yaml".to_string(), lock)]);
        let result = rewrite_registry_redirect(&files, &[dep("left-pad")]);
        assert!(result.warnings.is_empty(), "{what}: {:?}", result.warnings);
        assert!(result.refused_pnpm_uuids.is_empty(), "{what}");
        assert_eq!(result.edits.len(), 1, "{what}");
        assert!(
            result.files["pnpm-lock.yaml"].contains("https://patch.example/left-pad-1.3.0.tgz"),
            "{what}"
        );
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

/// pnpm 1's early shrinkwrap (`shrinkwrapVersion: 3`) is no durable
/// lock: a lone one refuses the dependency. Beside a `pnpm-lock.yaml` it
/// is shadowed (N11: pnpm >= 3 never reads it), so it refuses nothing and
/// only the governing lock is rewritten.
#[test]
fn early_pnpm1_shrinkwrap_refuses_only_when_it_governs() {
    let old = "shrinkwrapVersion: 3\npackages:\n  /left-pad/1.3.0:\n    resolution:\n      integrity: sha1-UPSTREAM=\n";
    let newer = "lockfileVersion: '9.0'\npackages:\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-UPSTREAM==}\n";
    let alone = BTreeMap::from([("shrinkwrap.yaml".into(), old.into())]);
    let result = rewrite_registry_redirect(&alone, &[dep("left-pad")]);
    assert!(result.files.is_empty() && result.edits.is_empty());
    assert!(result.refused_pnpm_uuids.contains("patch-id"));
    assert_eq!(
        result.warnings[0].code,
        "redirect_pnpm_legacy_lockfile_unsupported"
    );

    let both = BTreeMap::from([
        ("shrinkwrap.yaml".into(), old.into()),
        ("pnpm-lock.yaml".into(), newer.into()),
    ]);
    let result = rewrite_registry_redirect(&both, &[dep("left-pad")]);
    assert!(
        result.refused_pnpm_uuids.is_empty(),
        "{:?}",
        result.warnings
    );
    assert_eq!(
        result.files.keys().map(String::as_str).collect::<Vec<_>>(),
        ["pnpm-lock.yaml"]
    );
}
