use super::*;

async fn write(root: &Path, name: &str, content: &str) {
    tokio::fs::write(root.join(name), content).await.unwrap();
}

fn entry<'a>(entries: &'a [LockfileEntry], name: &str) -> &'a LockfileEntry {
    entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no entry for {name}: {entries:?}"))
}

// ── package-lock ──────────────────────────────────────────────────────

const PACKAGE_LOCK: &str = r#"{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "fixture", "version": "1.0.0" },
    "packages/member": { "name": "member", "version": "0.0.1" },
    "node_modules/member": { "resolved": "packages/member", "link": true },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-XI5MPz=="
    },
    "node_modules/@scope/pkg": {
      "version": "2.0.0",
      "resolved": "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
      "integrity": "sha512-scoped=="
    },
    "node_modules/bundled-dep": {
      "version": "1.0.0",
      "inBundle": true
    },
    "node_modules/git-dep": {
      "version": "0.5.0",
      "resolved": "git+ssh://git@github.com/x/git-dep.git#abc"
    },
    "node_modules/vendored": {
      "version": "3.0.0",
      "resolved": "file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz",
      "integrity": "sha512-ours=="
    },
    "node_modules/evil": {
      "version": "../../escape",
      "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
      "integrity": "sha512-evil=="
    },
    "node_modules/no-version": {
      "resolved": "https://registry.npmjs.org/no-version/-/no-version-1.0.0.tgz"
    }
  }
}
"#;

#[tokio::test]
async fn package_lock_inventories_registry_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::PackageLock);

    let lp = entry(&entries, "left-pad");
    assert_eq!(lp.version, "1.3.0");
    assert_eq!(lp.purl, "pkg:npm/left-pad@1.3.0");
    assert_eq!(
        lp.resolved.as_deref(),
        Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")
    );
    assert_eq!(lp.integrity, LockIntegrity::Sri("sha512-XI5MPz==".into()));

    let scoped = entry(&entries, "@scope/pkg");
    assert_eq!(scoped.purl, "pkg:npm/@scope/pkg@2.0.0");

    // git deps stay listed (discovery) but carry no fetchable URL.
    let git = entry(&entries, "git-dep");
    assert_eq!(git.resolved, None);
    assert_eq!(git.integrity, LockIntegrity::None);

    // Workspace members, links, bundled deps, our vendored spec, the
    // unsafe-version entry, and the version-less node are all absent.
    for absent in [
        "member",
        "fixture",
        "bundled-dep",
        "vendored",
        "evil",
        "no-version",
    ] {
        assert!(
            !entries.iter().any(|e| e.name == absent),
            "{absent} must not be inventoried: {entries:?}"
        );
    }
}

#[tokio::test]
async fn shrinkwrap_wins_over_package_lock() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;
    write(
        tmp.path(),
        "npm-shrinkwrap.json",
        r#"{ "lockfileVersion": 3, "packages": {
                 "node_modules/only-in-shrinkwrap": { "version": "9.9.9" } } }"#,
    )
    .await;

    let (_, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert!(entries.iter().any(|e| e.name == "only-in-shrinkwrap"));
    assert!(!entries.iter().any(|e| e.name == "left-pad"));
}

#[tokio::test]
async fn legacy_v1_lock_without_packages_map_yields_none() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "package-lock.json",
        r#"{ "lockfileVersion": 1, "dependencies": { "left-pad": { "version": "1.3.0" } } }"#,
    )
    .await;
    assert!(inventory_npm_lock(tmp.path()).await.unwrap().is_none());
}

// ── pnpm ──────────────────────────────────────────────────────────────

const PNPM_LOCK: &str = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPz==}

  '@scope/pkg@2.0.0':
    resolution: {integrity: sha512-scoped==}

  peer-user@4.0.0(left-pad@1.3.0):
    resolution: {integrity: sha512-peer==}

  local-thing@file:packages/local:
    resolution: {directory: packages/local, type: directory}

  vendored@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz:
    resolution: {integrity: sha512-ours==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz}

snapshots:

  left-pad@1.3.0: {}
";

#[tokio::test]
async fn pnpm_v9_keys_parse_with_peer_suffix_and_scoped_quoting() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Pnpm);

    assert_eq!(
        entry(&entries, "left-pad").integrity,
        LockIntegrity::Sri("sha512-XI5MPz==".into())
    );
    assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
    assert_eq!(entry(&entries, "peer-user").version, "4.0.0");
    // registry entries carry no URL in v9 — constructed at fetch time.
    assert_eq!(entry(&entries, "left-pad").resolved, None);
    // Exact set: the legacy v5/v6 grammars must not add or reshape v9
    // entries (local-thing and vendored stay skipped).
    assert_eq!(
        sorted_pairs(&entries),
        vec![
            ("@scope/pkg".into(), "2.0.0".into()),
            ("left-pad".into(), "1.3.0".into()),
            ("peer-user".into(), "4.0.0".into()),
        ]
    );
}

/// A CRLF checkout of the same lock inventories identically: the
/// hosted rewriter's pnpm grammar (the one reader) is CRLF-blind, where
/// an exact `packages:` line match used to see no section at all.
#[tokio::test]
async fn pnpm_crlf_lock_inventories_like_its_lf_twin() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "pnpm-lock.yaml",
        &PNPM_LOCK.replace('\n', "\r\n"),
    )
    .await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Pnpm);
    assert_eq!(
        entry(&entries, "left-pad").integrity,
        LockIntegrity::Sri("sha512-XI5MPz==".into()),
        "no stray \\r rides into the verifier"
    );
    assert_eq!(
        sorted_pairs(&entries),
        vec![
            ("@scope/pkg".into(), "2.0.0".into()),
            ("left-pad".into(), "1.3.0".into()),
            ("peer-user".into(), "4.0.0".into()),
        ]
    );
}

fn sorted_pairs(entries: &[LockfileEntry]) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.name.clone(), e.version.clone()))
        .collect();
    pairs.sort();
    pairs
}

// Real pnpm 7 shapes (lockfileVersion 5.4, captured from a pnpm 7.33.5
// install: slash-separated `/name/version` keys, no `@` at all), plus
// synthetic keys in the same grammar: scoped, `_peer@x`-suffixed,
// `_<hash>`-suffixed, and a non-default-registry key (no leading `/`)
// that must stay out fail-closed.
const PNPM_LOCK_V5: &str = "lockfileVersion: 5.4

specifiers:
  mkdirp: 0.5.5

dependencies:
  mkdirp: 0.5.5

packages:

  /minimist/1.2.8:
    resolution: {integrity: sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==}
    dev: false

  /mkdirp/0.5.5:
    resolution: {integrity: sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==}
    hasBin: true
    dependencies:
      minimist: 1.2.8
    dev: false

  /@scope/pkg/2.0.0:
    resolution: {integrity: sha512-scoped==}
    dev: false

  /styled-thing/5.3.3_react@17.0.2:
    resolution: {integrity: sha512-peered==}
    dev: false

  /hashed-thing/1.0.0_abc123deadbeef:
    resolution: {integrity: sha512-hashed==}
    dev: false

  example.com/private-pkg/1.0.0:
    resolution: {integrity: sha512-registry==}
    dev: false
";

#[tokio::test]
async fn pnpm_v5_slash_keys_inventory_with_peer_and_hash_suffixes() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V5).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    // The legacy grammars route to the PnpmLegacy wiring flavor now
    // (they used to reach here through the version-refusal fallback);
    // the inventory content is identical either way.
    assert_eq!(flavor, NpmLockFlavor::PnpmLegacy);
    assert_eq!(
        sorted_pairs(&entries),
        vec![
            ("@scope/pkg".into(), "2.0.0".into()),
            ("hashed-thing".into(), "1.0.0".into()),
            ("minimist".into(), "1.2.8".into()),
            ("mkdirp".into(), "0.5.5".into()),
            ("styled-thing".into(), "5.3.3".into()),
        ]
    );
    assert_eq!(
        entry(&entries, "minimist").integrity,
        LockIntegrity::Sri(
            "sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA=="
                .into()
        )
    );
    assert_eq!(entry(&entries, "minimist").purl, "pkg:npm/minimist@1.2.8");
}

// Real pnpm 8 shapes (lockfileVersion 6.0, captured from a pnpm 8.15.9
// install: v9's `name@version` behind a leading `/`), plus synthetic
// scoped and peer-parenthesized keys in the same grammar.
const PNPM_LOCK_V6: &str = "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  mkdirp:
    specifier: 0.5.5
    version: 0.5.5

packages:

  /minimist@1.2.8:
    resolution: {integrity: sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==}
    dev: false

  /mkdirp@0.5.5:
    resolution: {integrity: sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==}
    hasBin: true
    dependencies:
      minimist: 1.2.8
    dev: false

  /@scope/pkg@2.0.0:
    resolution: {integrity: sha512-scoped==}
    dev: false

  /peer-user@4.0.0(left-pad@1.3.0):
    resolution: {integrity: sha512-peer==}
    dev: false
";

#[tokio::test]
async fn pnpm_v6_leading_slash_keys_inventory_with_peer_parens() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V6).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    // The legacy grammars route to the PnpmLegacy wiring flavor now
    // (they used to reach here through the version-refusal fallback);
    // the inventory content is identical either way.
    assert_eq!(flavor, NpmLockFlavor::PnpmLegacy);
    assert_eq!(
        sorted_pairs(&entries),
        vec![
            ("@scope/pkg".into(), "2.0.0".into()),
            ("minimist".into(), "1.2.8".into()),
            ("mkdirp".into(), "0.5.5".into()),
            ("peer-user".into(), "4.0.0".into()),
        ]
    );
    assert_eq!(
        entry(&entries, "mkdirp").integrity,
        LockIntegrity::Sri(
            "sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ=="
                .into()
        )
    );
    assert_eq!(
        entry(&entries, "@scope/pkg").purl,
        "pkg:npm/@scope/pkg@2.0.0"
    );
}

/// A pnpm→yarn-berry migration leaves a stale root pnpm-lock.yaml behind
/// a `.pnp.cjs` loader. The probe's refusal there is a yarn refusal, not
/// a pnpm one — the legacy-lock fallback must NOT inventory the stale
/// lock as the live dependency set; the yarn-PnP diagnosis propagates
/// instead.
#[tokio::test]
async fn stale_pnpm_lock_behind_yarn_berry_pnp_marker_is_not_inventoried() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;
    write(tmp.path(), ".pnp.cjs", "/* yarn berry PnP loader */").await;
    let diag = inventory_npm_lock(tmp.path()).await.unwrap_err();
    assert_eq!(
        diag.code, "vendor_yarn_berry_unsupported",
        "a stale pnpm-lock.yaml behind a yarn-berry PnP marker must not be inventoried"
    );
}

/// A malformed binary lock fails closed with format context, including
/// beside a different package manager's lock. A text Bun lock wins.
#[tokio::test]
async fn malformed_bun_lockb_yields_a_diagnosis_without_inventorying_siblings() {
    for sibling in [
        None,
        Some(("pnpm-lock.yaml", PNPM_LOCK)),
        Some(("yarn.lock", YARN_CLASSIC)),
        Some(("package-lock.json", PACKAGE_LOCK)),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        if let Some((name, content)) = sibling {
            write(tmp.path(), name, content).await;
        }
        write(tmp.path(), "bun.lockb", "\0binary").await;
        let diag = inventory_npm_lock(tmp.path()).await.unwrap_err();
        assert_eq!(diag.code, "bun_lockb_invalid");
        assert!(diag.detail.contains("bun.lockb"), "{}", diag.detail);
        let (entries, unsupported) = inventory_project_diagnosed(tmp.path()).await;
        assert!(entries.is_empty(), "{entries:?}");
        assert_eq!(unsupported, vec![diag]);

        write(tmp.path(), "bun.lock", BUN_LOCK).await;
        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
        assert_eq!(flavor, NpmLockFlavor::Bun);
        assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
        assert!(inventory_project_diagnosed(tmp.path()).await.1.is_empty());
    }
}

#[tokio::test]
async fn bun_binary_inventory_works_without_an_install_or_runtime() {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bun-lockb");
    for version in [
        "0.1.1", "0.6.7", "0.6.8", "0.8.1", "1.0.0", "1.0.36", "1.1.0", "1.1.38", "1.1.45",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let bytes = std::fs::read(fixtures.join(version).join("bun.lockb")).unwrap();
        tokio::fs::write(tmp.path().join("bun.lockb"), &bytes)
            .await
            .unwrap();
        let (entries, diagnoses) = inventory_project_diagnosed(tmp.path()).await;
        assert!(diagnoses.is_empty(), "Bun {version}: {diagnoses:?}");
        assert_eq!(
            sorted_pairs(&entries),
            vec![
                ("is-number".into(), "7.0.0".into()),
                ("minimist".into(), "1.2.2".into())
            ],
            "Bun {version}"
        );
        let minimist = entry(&entries, "minimist");
        assert!(
            minimist
                .resolved
                .as_deref()
                .is_some_and(|url| url.ends_with("minimist-1.2.2.tgz")),
            "Bun {version}: {minimist:?}"
        );
        assert!(
            super::super::bun_lock::preflight_vendor(tmp.path())
                .await
                .is_ok(),
            "Bun {version}"
        );
        assert_eq!(
            tokio::fs::read(tmp.path().join("bun.lockb")).await.unwrap(),
            bytes,
            "discovery/preflight must preserve Bun {version} bytes"
        );
        assert!(!tmp.path().join("bun.lock").exists());
        assert!(!tmp.path().join("node_modules").exists());
    }
}

#[tokio::test]
async fn bun_binary_vendor_integrity_follows_live_package_records() {
    let bytes = include_bytes!("../../../tests/fixtures/bun-lockb/1.1.45/bun.lockb");
    let mut lock = super::super::bun_lockb::BunLockb::parse(bytes).unwrap();
    let package = lock
        .packages()
        .unwrap()
        .into_iter()
        .find(|package| package.name == "minimist")
        .unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let rel = ".socket/vendor/npm/11111111-1111-4111-8111-111111111111/minimist-1.2.2.tgz";
    let first = format!("sha512-{}", "A".repeat(86) + "==");
    lock.set_package(package.id, rel, &first).unwrap();
    tokio::fs::write(tmp.path().join("bun.lockb"), lock.bytes())
        .await
        .unwrap();
    assert_eq!(
        wired_vendor_integrity(tmp.path(), rel).await,
        Some(LockIntegrity::Sri(first))
    );
    let next = rel.replace(
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    );
    lock.set_package(
        package.id,
        &next,
        &format!("sha512-{}", "A".repeat(86) + "=="),
    )
    .unwrap();
    tokio::fs::write(tmp.path().join("bun.lockb"), lock.bytes())
        .await
        .unwrap();
    assert_eq!(
        wired_vendor_integrity(tmp.path(), rel).await,
        None,
        "retired strings are not active resolutions"
    );
    assert!(wired_vendor_integrity(tmp.path(), &next).await.is_some());
    write(tmp.path(), "bun.lock", BUN_LOCK).await;
    assert_eq!(
        wired_vendor_integrity(tmp.path(), &next).await,
        None,
        "text lock takes precedence"
    );
}

/// A pnpm-lock.yaml whose lockfileVersion the probe refuses — pnpm 6
/// wrote 5.3; only 5.4/6.0/9.0 route to a backend. This is the shape
/// that reaches the version-refusal discovery fallback, where a live
/// sibling lock may be sitting beside it after a migration.
const PNPM_LOCK_V53_STALE: &str = "lockfileVersion: 5.3

packages:

  /dead-pnpm-dep/1.0.0:
    resolution: {integrity: sha512-dead==}
";

/// A pnpm→yarn migration leaves a version-refused pnpm-lock.yaml beside
/// the live yarn.lock. The probe checks pnpm-lock.yaml BEFORE yarn.lock,
/// so its refusal says nothing about the sibling — the fallback must
/// surface the LIVE yarn resolutions, not the dead pnpm ones.
#[tokio::test]
async fn stale_pnpm_lock_beside_live_yarn_classic_yields_yarn_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V53_STALE).await;
    write(tmp.path(), "yarn.lock", YARN_CLASSIC).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::YarnClassic);
    assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
    assert!(
        !entries.iter().any(|e| e.name == "dead-pnpm-dep"),
        "dead pnpm resolutions must not pose as the live set: {entries:?}"
    );
}

/// Same migration hazard toward yarn berry (node-modules linker: no PnP
/// marker, so the pnpm version refusal is what fires).
#[tokio::test]
async fn stale_pnpm_lock_beside_live_yarn_berry_yields_berry_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V53_STALE).await;
    write(tmp.path(), "yarn.lock", YARN_BERRY).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::YarnBerry);
    assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
    assert!(
        !entries.iter().any(|e| e.name == "dead-pnpm-dep"),
        "dead pnpm resolutions must not pose as the live set: {entries:?}"
    );
}

/// Same migration hazard toward npm: the live package-lock.json wins
/// over the version-refused pnpm lock.
#[tokio::test]
async fn stale_pnpm_lock_beside_live_package_lock_yields_npm_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V53_STALE).await;
    write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::PackageLock);
    assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
    assert!(
        !entries.iter().any(|e| e.name == "dead-pnpm-dep"),
        "dead pnpm resolutions must not pose as the live set: {entries:?}"
    );
}

/// A version-refused pnpm lock ALONE is a genuine old-pnpm project (no
/// migration happened) — the discovery fallback must still read it.
#[tokio::test]
async fn unsupported_pnpm_lock_alone_is_still_inventoried() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V53_STALE).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Pnpm);
    assert_eq!(entry(&entries, "dead-pnpm-dep").version, "1.0.0");
}

/// pnpm→bun migration with the TEXT bun.lock: the router routes Bun at
/// its bun step, which runs BEFORE the pnpm sniff, so no refusal (and no
/// fallback) ever fires — bun's entries are the inventory. Pinned here
/// because it is the router-precedence twin of the sibling checks above.
#[tokio::test]
async fn stale_pnpm_lock_beside_bun_lock_routes_to_bun() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V53_STALE).await;
    write(tmp.path(), "bun.lock", BUN_LOCK).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Bun);
    assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
    assert!(
        !entries.iter().any(|e| e.name == "dead-pnpm-dep"),
        "dead pnpm resolutions must not pose as the live set: {entries:?}"
    );
}

/// A live sibling lock FILE that yields no entries (here: an empty
/// package-lock, as a fresh dep-less `npm install` writes) still proves
/// the migration happened — the dead pnpm resolutions must stay out even
/// though there is nothing live to return.
#[tokio::test]
async fn stale_pnpm_lock_beside_empty_live_lock_yields_none() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK_V53_STALE).await;
    write(
        tmp.path(),
        "package-lock.json",
        r#"{ "lockfileVersion": 3, "packages": { "": {} } }"#,
    )
    .await;
    assert!(
        inventory_npm_lock(tmp.path()).await.unwrap().is_none(),
        "an empty live sibling must not resurrect the dead pnpm resolutions"
    );
}

// ── shrinkwrap.yaml (pnpm 1/2) ──────────────────────────────────────────

/// The exact grammar the 2026-08-18 legacy matrix captured from a real
/// pnpm 2 install (shrinkwrapVersion 3): v5-style `/name/version` keys,
/// BLOCK-mapped `resolution:` (integrity nested on its own line — every
/// pnpm-lock.yaml generation writes the inline `{…}` flow map instead),
/// quoted top-level `registry:`, and a transitive dep (`minimist`)
/// listed only under `packages:`.
const SHRINKWRAP_YAML: &str = "dependencies:
  left-pad: 1.3.0
  mkdirp: 0.5.5
packages:
  /left-pad/1.3.0:
    deprecated: use String.prototype.padStart()
    dev: false
    resolution:
      integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==
  /minimist/1.2.8:
    dev: false
    resolution:
      integrity: sha512-2yyAR8qBkN3YuheJanUpWC5U3bb5osDywNB8RzDVlDwDHbocAJveqqj1u8+SVD7jkWT4yvsHCpWqqWqAxb0zCA==
  /mkdirp/0.5.5:
    dependencies:
      minimist: 1.2.8
    dev: false
    hasBin: true
    resolution:
      integrity: sha512-NKmAlESf6jMGym1++R0Ra7wvhV+wFW63FaSOFPwRahvea0gMUcGUhVeAg/0BC0wiv9ih5NYPB1Wn1UEI1/L+xQ==
registry: 'https://registry.npmjs.org/'
shrinkwrapMinorVersion: 9
shrinkwrapVersion: 3
specifiers:
  left-pad: 1.3.0
  mkdirp: 0.5.5
";

/// A pnpm <=2 project (shrinkwrap.yaml, no pnpm-lock.yaml, no other
/// lock) must be inventoried through the shrinkwrap fallback: same v5
/// key grammar, integrity read from the BLOCK-mapped resolution —
/// without it such projects report lockfileOnlyPackages=0 despite the
/// lock listing everything.
#[tokio::test]
async fn shrinkwrap_yaml_inventories_pnpm_legacy_project() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "shrinkwrap.yaml", SHRINKWRAP_YAML).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path())
        .await
        .unwrap()
        .expect("shrinkwrap.yaml must be inventoried");
    assert_eq!(flavor, NpmLockFlavor::PnpmLegacy);
    assert_eq!(entries.len(), 3, "all three packages entries: {entries:?}");

    let lp = entry(&entries, "left-pad");
    assert_eq!(lp.version, "1.3.0");
    assert_eq!(lp.purl, "pkg:npm/left-pad@1.3.0");
    assert_eq!(
        lp.integrity,
        LockIntegrity::Sri(
            "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/\
                 aVx2HrNcqQGsdot8ghrjyrvMCoEA=="
                .into()
        ),
        "block-mapped resolution integrity must be captured"
    );
    assert_eq!(lp.resolved, None, "no tarball recorded → registry URL");

    // The transitive dep (a dependencies: child inside mkdirp's entry
    // must not shadow it) and the binary-carrying dep both inventory.
    assert_eq!(entry(&entries, "minimist").version, "1.2.8");
    assert_eq!(entry(&entries, "mkdirp").version, "0.5.5");
}

/// A root pnpm-lock.yaml wins over shrinkwrap.yaml: the flavor probe
/// recognizes the modern lock, so the legacy fallback never runs — a
/// leftover shrinkwrap.yaml from a long-ago pnpm upgrade must not
/// inject dead resolutions.
#[tokio::test]
async fn pnpm_lock_wins_over_stale_shrinkwrap_yaml() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;
    write(tmp.path(), "shrinkwrap.yaml", SHRINKWRAP_YAML).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Pnpm);
    assert!(
        !entries.iter().any(|e| e.name == "mkdirp"),
        "shrinkwrap-only entries must not leak in: {entries:?}"
    );
}

/// Same stale-lock hazard as the pnpm-lock fallbacks: a shrinkwrap.yaml
/// behind another family's marker (yarn-berry PnP here — the probe
/// refuses with a NON-missing code) is migration debris, not the live
/// dependency set; the yarn-PnP diagnosis propagates instead.
#[tokio::test]
async fn stale_shrinkwrap_behind_yarn_berry_pnp_marker_is_not_inventoried() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "shrinkwrap.yaml", SHRINKWRAP_YAML).await;
    write(tmp.path(), ".pnp.cjs", "/* yarn berry PnP loader */").await;
    let diag = inventory_npm_lock(tmp.path()).await.unwrap_err();
    assert_eq!(
        diag.code, "vendor_yarn_berry_unsupported",
        "a shrinkwrap.yaml behind a yarn-berry PnP marker must not be inventoried"
    );
}

/// pnpm's own `node-linker=pnp` layout (`.pnp.cjs` + pnpm store + lock,
/// no yarn.lock) refuses with the pnpm-specific PnP code, which
/// PROPAGATES as the layout diagnosis rather than falling back to the
/// lock read — under PnP the installed-tree crawl is also structurally
/// empty, so the honest answer is the refusal, not a lock-only
/// inventory posing as a served project (see
/// `pnp_layouts_propagate_the_diagnosis_instead_of_yielding_none`).
#[tokio::test]
async fn pnpm_pnp_layout_propagates_the_diagnosis() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;
    write(tmp.path(), ".pnp.cjs", "/* pnpm node-linker=pnp loader */").await;
    write_nested(tmp.path(), "node_modules/.modules.yaml", "").await;

    let diag = inventory_npm_lock(tmp.path()).await.unwrap_err();
    assert_eq!(diag.code, "vendor_pnpm_pnp_unsupported");
}

// ── Rush monorepo ───────────────────────────────────────────────────────

/// Write `content` to `rel` under `root`, creating parent dirs.
async fn write_nested(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(path, content).await.unwrap();
}

#[tokio::test]
async fn rush_monorepo_inventories_common_and_subspace_locks() {
    // No root package.json/lock — only rush.json plus the generated
    // source-of-truth lock under common/config and one subspace lock.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
    write_nested(tmp.path(), "common/config/rush/pnpm-lock.yaml", PNPM_LOCK).await;
    write_nested(
        tmp.path(),
        "common/config/subspaces/frontend/pnpm-lock.yaml",
        "lockfileVersion: '9.0'

packages:

  only-in-subspace@9.9.9:
    resolution: {integrity: sha512-sub==}
",
    )
    .await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Pnpm);
    // Union across the common lock and the subspace lock.
    assert_eq!(entry(&entries, "left-pad").version, "1.3.0");
    assert_eq!(entry(&entries, "only-in-subspace").version, "9.9.9");
}

#[tokio::test]
async fn rush_json_without_any_lock_yields_none() {
    // rush.json but no common/subspace lock at all: nothing to inventory.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
    assert!(inventory_npm_lock(tmp.path()).await.unwrap().is_none());
}

#[tokio::test]
async fn root_pnpm_lock_wins_over_rush_fallback() {
    // A plain pnpm project that also happens to carry a stray rush.json
    // must route through the normal root-lock path, never the fallback.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "rush.json", r#"{"rushVersion":"5.0.0"}"#).await;
    write(tmp.path(), "pnpm-lock.yaml", PNPM_LOCK).await;
    write_nested(
        tmp.path(),
        "common/config/rush/pnpm-lock.yaml",
        "lockfileVersion: '9.0'

packages:

  only-in-common@1.0.0:
    resolution: {integrity: sha512-common==}
",
    )
    .await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Pnpm);
    assert!(entries.iter().any(|e| e.name == "left-pad"));
    assert!(
        !entries.iter().any(|e| e.name == "only-in-common"),
        "the root lock must win; the rush fallback must not run: {entries:?}"
    );
}

// ── yarn classic ──────────────────────────────────────────────────────

const YARN_CLASSIC: &str = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


\"@scope/pkg@^2.0.0\":
  version \"2.0.0\"
  resolved \"https://registry.yarnpkg.com/@scope/pkg/-/pkg-2.0.0.tgz#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"
  integrity sha512-scoped==

left-pad@1.3.0, left-pad@^1.3.0:
  version \"1.3.0\"
  resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"
  integrity sha512-XI5MPz==

old-school@0.1.0:
  version \"0.1.0\"
  resolved \"https://registry.yarnpkg.com/old-school/-/old-school-0.1.0.tgz#cccccccccccccccccccccccccccccccccccccccc\"

aliased@npm:real-name@^3.0.0:
  version \"3.0.0\"
  resolved \"https://registry.yarnpkg.com/real-name/-/real-name-3.0.0.tgz#dddddddddddddddddddddddddddddddddddddddd\"
  integrity sha512-alias==
";

#[tokio::test]
async fn yarn_classic_blocks_yield_resolved_sha1_and_integrity() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "yarn.lock", YARN_CLASSIC).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::YarnClassic);

    let lp = entry(&entries, "left-pad");
    assert_eq!(
        lp.resolved.as_deref(),
        Some("https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"),
        "the #sha1 fragment is split off the URL"
    );
    assert_eq!(lp.integrity, LockIntegrity::Sri("sha512-XI5MPz==".into()));

    // Integrity-less old locks fall back to the sha1 fragment.
    assert_eq!(
        entry(&entries, "old-school").integrity,
        LockIntegrity::Sha1Hex("c".repeat(40))
    );

    // `alias@npm:real@range` resolves to the real name.
    assert!(entries.iter().any(|e| e.name == "real-name"));
    assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
}

// ── yarn berry ────────────────────────────────────────────────────────

const YARN_BERRY: &str = "# This file is generated by running \"yarn install\" inside your project.
# Manifest files (package.json) are also used.

__metadata:
  version: 8
  cacheKey: 10c0

\"fixture@workspace:.\":
  version: 0.0.0-use.local
  resolution: \"fixture@workspace:.\"
  languageName: unknown
  linkType: soft

\"left-pad@npm:1.3.0\":
  version: 1.3.0
  resolution: \"left-pad@npm:1.3.0\"
  checksum: 10c0/deadbeefcafe==
  languageName: node
  linkType: hard

\"@scope/pkg@npm:^2.0.0\":
  version: 2.0.0
  resolution: \"@scope/pkg@npm:2.0.0\"
  checksum: 10c0/scopedchecksum==
  languageName: node
  linkType: hard
";

#[tokio::test]
async fn yarn_berry_registry_resolutions_inventory_with_checksums() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "yarn.lock", YARN_BERRY).await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::YarnBerry);

    let lp = entry(&entries, "left-pad");
    assert_eq!(lp.version, "1.3.0");
    assert_eq!(
        lp.integrity,
        LockIntegrity::BerryChecksum("10c0/deadbeefcafe==".into())
    );
    assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
    // The workspace root is not a registry package.
    assert!(!entries.iter().any(|e| e.name == "fixture"), "{entries:?}");
}

/// yarn berry writes a CRLF `yarn.lock` on Windows (a new lockfile gets
/// `os.EOL`), and editors add a BOM: the Windows spellings — header-less
/// too — inventory exactly like the LF lock, with no stray `\r` riding into
/// a checksum pin.
#[tokio::test]
async fn yarn_berry_crlf_and_bom_locks_inventory_like_their_lf_twin() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "yarn.lock", YARN_BERRY).await;
    let (_, lf) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    let headerless = YARN_BERRY.trim_start_matches(|c| c != '_');
    for lock in [
        YARN_BERRY.replace('\n', "\r\n"),
        format!("\u{feff}{}", YARN_BERRY.replace('\n', "\r\n")),
        format!("\u{feff}{}", headerless.replace('\n', "\r\n")),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "yarn.lock", &lock).await;
        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
        assert_eq!(flavor, NpmLockFlavor::YarnBerry, "{lock:?}");
        assert_eq!(sorted_pairs(&entries), sorted_pairs(&lf), "{lock:?}");
        assert_eq!(
            entry(&entries, "left-pad").integrity,
            LockIntegrity::BerryChecksum("10c0/deadbeefcafe==".into()),
            "no stray \\r in the pin: {lock:?}"
        );
    }
}

// ── bun ───────────────────────────────────────────────────────────────

const BUN_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "fixture", "dependencies": { "left-pad": "1.3.0" } },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPz=="],
    "@scope/pkg": ["@scope/pkg@2.0.0", "", {}, "sha512-scoped=="],
    "vendored": ["vendored@file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored-3.0.0.tgz", {}],
    "linked": ["linked@workspace:packages/linked", {}],
    "consumer": ["consumer@workspace:packages/consumer", { "dependencies": { "left-pad": "1.3.0" } }],
  }
}
"#;

#[tokio::test]
async fn bun_registry_tuples_parse_and_locals_are_skipped() {
    // lockfileVersion 0 (bun 1.1.39–1.1.45 text opt-in), 1 (bun 1.2/1.3)
    // and 2 (bun 1.4) share one registry-tuple grammar, so inventory
    // must read all three identically. The workspace entries carry the
    // real v0 spelling — a 2-tuple with the member's deps object
    // (`{}` when dep-less) — and are skipped like every non-registry
    // shape.
    for version in [0u64, 1, 2] {
        let lock = BUN_LOCK.replace(
            "\"lockfileVersion\": 1,",
            &format!("\"lockfileVersion\": {version},"),
        );
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "bun.lock", &lock).await;

        let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
        assert_eq!(flavor, NpmLockFlavor::Bun);

        assert_eq!(
            entry(&entries, "left-pad").integrity,
            LockIntegrity::Sri("sha512-XI5MPz==".into()),
            "lockfileVersion {version}"
        );
        assert_eq!(entry(&entries, "left-pad").resolved, None);
        assert_eq!(entry(&entries, "@scope/pkg").version, "2.0.0");
        for absent in ["vendored", "linked", "consumer"] {
            assert!(
                !entries.iter().any(|e| e.name == absent),
                "lockfileVersion {version}: `{absent}` must be skipped: {entries:?}"
            );
        }
        assert_eq!(entries.len(), 2, "lockfileVersion {version}: {entries:?}");
    }

    // An unsupported lockfileVersion (a future 3) yields no inventory at
    // all — fail closed, same posture as the vendor/redirect gates.
    let lock = BUN_LOCK.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 3,");
    assert_ne!(lock, BUN_LOCK, "replacement must hit");
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "bun.lock", &lock).await;
    assert!(
        inventory_npm_lock(tmp.path()).await.unwrap().is_none(),
        "a lockfileVersion-3 bun.lock must not be inventoried"
    );
}

// ── shared semantics ──────────────────────────────────────────────────

#[tokio::test]
async fn lookup_bridges_percent_encoded_purls() {
    let entries = vec![
        LockfileEntry::npm("@scope/pkg", "2.0.0", None, LockIntegrity::None),
        LockfileEntry::npm("left-pad", "1.3.0", None, LockIntegrity::None),
    ];
    assert!(lookup(&entries, "pkg:npm/%40scope/pkg@2.0.0").is_some());
    assert!(lookup(&entries, "pkg:npm/@scope/pkg@2.0.0").is_some());
    assert!(lookup(&entries, "pkg:npm/left-pad@1.3.0?artifact_id=x").is_some());
    assert!(lookup(&entries, "pkg:npm/left-pad@9.9.9").is_none());
    assert!(lookup(&entries, "pkg:pypi/left-pad@1.3.0").is_none());
}

#[tokio::test]
async fn dedup_prefers_integrity_bearing_instance() {
    let raw = vec![
        LockfileEntry::npm("dup", "1.0.0", None, LockIntegrity::None),
        LockfileEntry::npm(
            "dup",
            "1.0.0",
            None,
            LockIntegrity::Sri("sha512-x==".into()),
        ),
        LockfileEntry::npm("dup", "1.0.0", None, LockIntegrity::None),
    ];
    let out = finalize_npm(raw);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].integrity, LockIntegrity::Sri("sha512-x==".into()));
}

#[tokio::test]
async fn cargo_lock_inventories_crates_io_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Cargo.lock",
        r#"# This file is automatically @generated by Cargo.
version = 4

[[package]]
name = "fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f"

[[package]]
name = "git-dep"
version = "0.5.0"
source = "git+https://github.com/x/git-dep?rev=abc#abc"

[[package]]
name = "sparse-crate"
version = "2.0.0"
source = "sparse+https://index.crates.io/"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
    )
    .await;

    let entries = inventory_cargo_lock(tmp.path()).await.unwrap();
    let serde_entry = entry(&entries, "serde");
    assert_eq!(serde_entry.version, "1.0.200");
    assert_eq!(serde_entry.purl, "pkg:cargo/serde@1.0.200");
    assert_eq!(
        serde_entry.integrity,
        LockIntegrity::Sha256Hex(
            "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f".into()
        )
    );
    assert!(matches!(
        entry(&entries, "sparse-crate").integrity,
        LockIntegrity::Sha256Hex(_)
    ));
    // Workspace member (no source) excluded; git source unverifiable.
    assert!(!entries.iter().any(|e| e.name == "fixture"));
    assert_eq!(entry(&entries, "git-dep").integrity, LockIntegrity::None);
}

/// A sourced entry carrying a Socket tag (hand-edited / foreign: vendoring
/// writes tagged entries SOURCELESS, which are skipped) is listed under its
/// purl version with no verifier; the sourceless tagged copy is not listed.
#[tokio::test]
async fn cargo_lock_strips_a_socket_tag_and_drops_its_verifier() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Cargo.lock",
        r#"version = 4

[[package]]
name = "cfg-if"
version = "1.0.4+socket.9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f"

[[package]]
name = "zstd-sys"
version = "2.0.1+zstd.1.5.2.socket.9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"

[[package]]
name = "keep-meta"
version = "2.0.1+zstd.1.5.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#,
    )
    .await;
    let entries = inventory_cargo_lock(tmp.path()).await.unwrap();
    let cfg_if = entry(&entries, "cfg-if");
    assert_eq!(cfg_if.version, "1.0.4");
    assert_eq!(cfg_if.purl, "pkg:cargo/cfg-if@1.0.4");
    assert_eq!(cfg_if.integrity, LockIntegrity::None);
    assert!(!entries.iter().any(|e| e.name == "zstd-sys"), "{entries:?}");
    let meta = entry(&entries, "keep-meta");
    assert_eq!(
        meta.version, "2.0.1+zstd.1.5.2",
        "non-Socket build metadata stays"
    );
    assert!(matches!(meta.integrity, LockIntegrity::Sha256Hex(_)));
}

#[tokio::test]
async fn go_sum_inventories_module_zip_lines() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "go.sum",
        "github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n\
             github.com/gin-gonic/gin v1.9.1/go.mod h1:hPrL7YrpYKXt5YId3A/Tnip5kqbEAP+KLuI3SUcPTeU=\n\
             golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\n",
    )
    .await;

    let entries = inventory_go_sum(tmp.path()).await.unwrap();
    assert_eq!(entries.len(), 2, "the /go.mod line is skipped: {entries:?}");
    let gin = entry(&entries, "github.com/gin-gonic/gin");
    assert_eq!(gin.version, "v1.9.1");
    assert_eq!(gin.purl, "pkg:golang/github.com/gin-gonic/gin@v1.9.1");
    assert_eq!(
        gin.integrity,
        LockIntegrity::GoH1("h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=".into())
    );
}

#[tokio::test]
async fn lookup_matches_cargo_and_golang_purls() {
    let entries = vec![
        LockfileEntry {
            ecosystem: "cargo",
            source_kind: SourceKind::Unspecified,
            name: "serde".into(),
            version: "1.0.200".into(),
            purl: "pkg:cargo/serde@1.0.200".into(),
            resolved: None,
            integrity: LockIntegrity::None,
        },
        LockfileEntry {
            ecosystem: "golang",
            source_kind: SourceKind::Unspecified,
            name: "github.com/x/y".into(),
            version: "v1.0.0".into(),
            purl: "pkg:golang/github.com/x/y@v1.0.0".into(),
            resolved: None,
            integrity: LockIntegrity::None,
        },
    ];
    assert!(lookup(&entries, "pkg:cargo/serde@1.0.200").is_some());
    assert!(lookup(&entries, "pkg:golang/github.com/x/y@v1.0.0").is_some());
    assert!(lookup(&entries, "pkg:cargo/serde@9.9.9").is_none());
    assert!(
        lookup(&entries, "pkg:npm/serde@1.0.200").is_none(),
        "ecosystem tags must match, not just name@version"
    );
}

#[tokio::test]
async fn composer_lock_inventories_dist_entries() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "composer.lock",
        r#"{
  "packages": [
    {
      "name": "Monolog/Monolog",
      "version": "v3.5.0",
      "dist": {
        "type": "zip",
        "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
        "shasum": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      }
    },
    {
      "name": "vendored/pkg",
      "version": "1.0.0",
      "dist": { "type": "path", "url": ".socket/vendor/composer/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/vendored/pkg@1.0.0" }
    }
  ],
  "packages-dev": [
    {
      "name": "symfony/console",
      "version": "v6.4.1",
      "dist": { "type": "zip", "url": "https://example.com/console.zip", "shasum": "" }
    }
  ]
}"#,
    )
    .await;

    let entries = inventory_composer_lock(tmp.path()).await.unwrap();
    let monolog = entry(&entries, "monolog/monolog");
    assert_eq!(
        monolog.version, "3.5.0",
        "leading v dropped, name lowercased"
    );
    assert_eq!(monolog.purl, "pkg:composer/monolog/monolog@3.5.0");
    assert!(matches!(monolog.integrity, LockIntegrity::Sha1Hex(_)));
    assert!(monolog.resolved.as_deref().unwrap().contains("zipball"));
    // Empty shasum → discovery-only; path dist (ours) excluded.
    assert_eq!(
        entry(&entries, "symfony/console").integrity,
        LockIntegrity::None
    );
    assert!(!entries.iter().any(|e| e.name == "vendored/pkg"));
}

#[tokio::test]
async fn gemfile_lock_inventories_specs_and_checksums() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      \
             actionpack (= 7.1.0)\n    rack (3.0.8)\n    nokogiri (1.16.5-arm64-darwin)\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails\n\nCHECKSUMS\n  \
             rails (7.1.0) sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\n\
             BUNDLED WITH\n   2.6.0\n",
    )
    .await;

    let entries = inventory_gemfile_lock(tmp.path()).await.unwrap();
    let rails = entry(&entries, "rails");
    assert_eq!(rails.version, "7.1.0");
    assert_eq!(rails.purl, "pkg:gem/rails@7.1.0");
    assert!(matches!(rails.integrity, LockIntegrity::Sha256Hex(_)));
    assert_eq!(
        rails.resolved.as_deref(),
        Some("https://rubygems.org/downloads/rails-7.1.0.gem")
    );
    // No CHECKSUMS entry → discovery-only; platform gem skipped;
    // dependency range lines never parse as specs.
    assert_eq!(entry(&entries, "rack").integrity, LockIntegrity::None);
    assert!(!entries.iter().any(|e| e.name == "nokogiri"));
    assert!(!entries.iter().any(|e| e.name == "actionpack"));
}

/// Multi-source lock (two GEM sections, the exact shape bundler 4.0.15
/// writes for a Gemfile `source … do` block — fixture mirrors a real
/// `bundle lock --add-checksums` run): each spec must resolve against
/// its OWN section's remote, never the first remote in the file.
#[tokio::test]
async fn gemfile_lock_multi_source_resolves_each_spec_against_its_own_remote() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Gemfile.lock",
        &format!(
            "GEM\n  remote: https://gems.corp.example/\n  specs:\n    private-gem (1.0.0)\n\n\
                 GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.2.6)\n\n\
                 PLATFORMS\n  ruby\n\nDEPENDENCIES\n  private-gem (= 1.0.0)!\n  rack (= 3.2.6)\n\n\
                 CHECKSUMS\n  private-gem (1.0.0) sha256={}\n  rack (3.2.6) sha256={}\n\n\
                 BUNDLED WITH\n   4.0.15\n",
            "a".repeat(64),
            "b".repeat(64),
        ),
    )
    .await;

    let entries = inventory_gemfile_lock(tmp.path()).await.unwrap();
    assert_eq!(
        entry(&entries, "private-gem").resolved.as_deref(),
        Some("https://gems.corp.example/downloads/private-gem-1.0.0.gem"),
        "first section's spec resolves against its own remote"
    );
    assert_eq!(
        entry(&entries, "rack").resolved.as_deref(),
        Some("https://rubygems.org/downloads/rack-3.2.6.gem"),
        "second section's spec must NOT inherit the first section's remote"
    );
    // Both keep their CHECKSUMS integrity.
    assert_eq!(
        entry(&entries, "rack").integrity,
        LockIntegrity::Sha256Hex("b".repeat(64))
    );
}

/// A GEM section with SEVERAL `remote:` lines is a legacy bundler 1.x
/// multisource lock (bundler ≥ 2 hard-errors on multiple global
/// sources — verified against 4.0.15): per-spec origin is ambiguous,
/// so its specs stay discovery-only — no guessed download URL, which
/// would leak private gem names to the public registry.
#[tokio::test]
async fn gemfile_lock_legacy_multi_remote_section_is_discovery_only() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Gemfile.lock",
        &format!(
            "GEM\n  remote: https://rubygems.org/\n  remote: https://gems.corp.example/\n  \
                 specs:\n    rack (3.0.8)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  rack\n\n\
                 CHECKSUMS\n  rack (3.0.8) sha256={}\n",
            "c".repeat(64),
        ),
    )
    .await;

    let entries = inventory_gemfile_lock(tmp.path()).await.unwrap();
    let rack = entry(&entries, "rack");
    assert_eq!(
        rack.resolved, None,
        "ambiguous origin must never guess a remote: {rack:?}"
    );
    // Discovery + integrity survive; only the URL is withheld.
    assert_eq!(rack.purl, "pkg:gem/rack@3.0.8");
    assert_eq!(rack.integrity, LockIntegrity::Sha256Hex("c".repeat(64)));
}

#[tokio::test]
async fn inventories_script_and_pylock_files_without_installed_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let sha = "a".repeat(64);
    write(tmp.path(), "example.py.lock", &format!("version=1\n[[package]]\nname='alpha'\nversion='1'\nsource={{registry='https://pypi.org/simple'}}\nwheels=[{{url='https://pypi.org/alpha-1-py3-none-any.whl',hash='sha256:{sha}'}}]\n")).await;
    write(tmp.path(), "pylock.dev.toml", &format!("lock-version='1.0'\n[[packages]]\nname='bravo'\nversion='2'\narchive={{url='https://pypi.org/bravo-2-py3-none-any.whl',hashes={{sha256='{sha}'}}}}\n[[packages]]\nname='local'\nversion='1'\narchive={{path='.socket/vendor/pypi/uuid/local-1-py3-none-any.whl',hashes={{sha256='{sha}'}}}}\n")).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entry(&entries, "alpha").integrity,
        LockIntegrity::Sha256Hex(sha.clone())
    );
    assert_eq!(
        entry(&entries, "bravo").integrity,
        LockIntegrity::Sha256Hex(sha)
    );
    assert!(!entries.iter().any(|entry| entry.name == "local"));
}

#[tokio::test]
async fn pylock_repair_uses_the_exact_artifact_hash_and_refuses_conflicts() {
    let tmp = tempfile::tempdir().unwrap();
    let path = ".socket/vendor/pypi/uuid/alpha-1-py3-none-any.whl";
    let sha = "a".repeat(64);
    let pylock = format!("lock-version='1.0'\n[[packages]]\nname='alpha'\nversion='1'\narchive={{path='{path}',hashes={{sha256='{sha}'}}}}\n");
    write(tmp.path(), "pylock.toml", &pylock).await;
    assert_eq!(
        wired_vendor_integrity(tmp.path(), path).await,
        Some(LockIntegrity::Sha256Hex(sha.clone()))
    );
    assert_eq!(
        wired_vendor_integrity(tmp.path(), &format!("{path}.other")).await,
        None
    );
    write(tmp.path(), "example.py.lock", &format!("version=1\n[[package]]\nname='alpha'\nversion='1'\nsource={{path='{path}'}}\nwheels=[{{filename='alpha-1-py3-none-any.whl',hash='sha256:{sha}'}}]\n")).await;
    assert_eq!(
        wired_vendor_integrity(tmp.path(), path).await,
        Some(LockIntegrity::Sha256Hex(sha.clone()))
    );
    write(
        tmp.path(),
        "pylock.toml",
        &pylock.replace(&sha, &"b".repeat(64)),
    )
    .await;
    assert_eq!(wired_vendor_integrity(tmp.path(), path).await, None);
}

#[test]
fn legacy_and_pep751_archive_hashes_stay_with_their_own_wheels() {
    let sha = "b".repeat(64);
    let legacy = format!("version=1\n[[distribution]]\nname='alpha'\nversion='1'\nsource='registry+https://pypi.org/simple'\n[[distribution.wheel]]\nurl='https://pypi.org/alpha-1-py3-none-any.whl'\nhash='sha256:{sha}'\n");
    assert_eq!(
        python_lock_inventory(&legacy).unwrap()[0].integrity,
        LockIntegrity::Sha256Hex(sha.clone())
    );
    let lock = format!("lock-version='1.0'\n[[packages]]\nname='alpha'\nversion='1'\nwheels=[{{url='https://pypi.org/alpha-1-py3-none-any.whl'}},{{url='https://pypi.org/alpha-1-cp312-cp312-macosx.whl',hashes={{sha256='{sha}'}}}}]\n");
    let entries = python_lock_inventory(&lock).unwrap();
    assert_eq!(entries[0].integrity, LockIntegrity::None);
    assert_eq!(entries[0].resolved, None);
    assert!(python_lock_inventory("version=2\n[[package]]\nname='x'\nversion='1'").is_none());
}

#[tokio::test]
async fn uv_lock_inventories_pure_wheels() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "uv.lock",
        r#"version = 1

[[package]]
name = "Requests"
version = "2.28.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/aa/requests-2.28.0-py3-none-any.whl", hash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
]

[[package]]
name = "native-only"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/bb/native_only-1.0.0-cp312-macosx.whl", hash = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
]

[[package]]
name = "local-proj"
version = "0.0.1"
source = { editable = "." }
"#,
    )
    .await;

    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    let requests = entry(&entries, "requests");
    assert_eq!(requests.purl, "pkg:pypi/requests@2.28.0", "PEP 503 name");
    assert!(matches!(requests.integrity, LockIntegrity::Sha256Hex(_)));
    assert!(requests
        .resolved
        .as_deref()
        .unwrap()
        .ends_with("py3-none-any.whl"));
    // Platform-only wheels → discovery-only; editable sources excluded.
    assert_eq!(
        entry(&entries, "native-only").integrity,
        LockIntegrity::None
    );
    assert!(!entries.iter().any(|e| e.name == "local-proj"));
}

#[tokio::test]
async fn uv_lock_one_line_wheels_array_pairs_the_pure_wheel_with_its_own_hash() {
    // A one-line `wheels = […]` array (valid TOML — hand-maintained or
    // formatter-collapsed locks) listing a platform wheel BEFORE the
    // pure one: the entry must carry the pure wheel's url+hash, never
    // the first url/hash on the line.
    let tmp = tempfile::tempdir().unwrap();
    let platform_sha = "a".repeat(64);
    let pure_sha = "b".repeat(64);
    write(
        tmp.path(),
        "uv.lock",
        &format!(
            "version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\
                 source = {{ registry = \"https://pypi.org/simple\" }}\n\
                 wheels = [{{ url = \"https://files.pythonhosted.org/packages/aa/six-1.16.0-cp312-cp312-macosx_11_0_arm64.whl\", hash = \"sha256:{platform_sha}\" }}, {{ url = \"https://files.pythonhosted.org/packages/bb/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{pure_sha}\" }}]\n"
        ),
    )
    .await;

    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    let six = entry(&entries, "six");
    assert!(
        six.resolved.as_deref().unwrap().ends_with("-none-any.whl"),
        "the platform wheel must never be resolved as pure: {six:?}"
    );
    assert_eq!(six.integrity, LockIntegrity::Sha256Hex(pure_sha));
}

#[tokio::test]
async fn poetry_and_requirements_are_discovery_only() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "poetry.lock",
        "[[package]]\nname = \"Flask_Login\"\nversion = \"0.6.3\"\n\n[metadata]\nlock-version = \"2.0\"\n",
    )
    .await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    let fl = entry(&entries, "flask-login");
    assert_eq!(fl.purl, "pkg:pypi/flask-login@0.6.3");
    assert_eq!(fl.integrity, LockIntegrity::None);

    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "requirements.txt",
        "# pinned\nrequests[security]==2.28.0 --hash=sha256:abc \\\n    --hash=sha256:def\nflask>=2.0\n-e .\n",
    )
    .await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].purl, "pkg:pypi/requests@2.28.0");
}

/// Pipfile.lock: every category is read, registry pins carry the lock's
/// digest SET (lowercased), non-registry sources / range pins / a user's
/// file references are skipped while our own vendored reference stays
/// discoverable, the same package in two categories yields one entry,
/// requirements.txt is read alongside it, and a parseable uv.lock
/// outranks both.
#[tokio::test]
async fn pipfile_lock_inventory_reads_every_category_with_its_digest_set() {
    let wheel = "a".repeat(64);
    let sdist = "B".repeat(64);
    let lock = format!(
        r#"{{
    "_meta": {{"hash": {{"sha256": "x"}}, "pipfile-spec": 6, "requires": {{}}, "sources": []}},
    "default": {{
        "URLlib3": {{"hashes": ["sha256:{wheel}", "sha256:{sdist}"], "index": "pypi", "version": "==1.26.18", "markers": "python_version < '4'"}},
        "requests": {{"git": "https://example.org/requests", "ref": "abc", "version": "==2.31.0"}},
        "loose": {{"version": "*"}},
        "wired": {{"file": "./.socket/vendor/pypi/00000000-0000-4000-8000-000000000000/wired-1.0-py3-none-any.whl", "hashes": ["sha256:{wheel}"]}}
    }},
    "develop": {{
        "Six": {{"hashes": ["sha256:{sdist}"], "version": "==1.16.0"}}
    }},
    "tests": {{
        "urllib3": {{"hashes": ["sha256:{wheel}"], "version": "==1.26.18"}}
    }}
}}
"#
    );
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "Pipfile.lock", &lock).await;
    write(tmp.path(), "requirements.txt", "flask==3.0.0\n").await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    // requirements.txt is read alongside the Pipfile.lock, not hidden by
    // it; our own vendored reference stays discoverable (discovery-only).
    assert_eq!(
        names,
        vec!["flask", "six", "urllib3", "wired"],
        "{entries:?}"
    );
    assert_eq!(entry(&entries, "wired").integrity, LockIntegrity::None);
    assert_eq!(entry(&entries, "wired").purl, "pkg:pypi/wired@1.0");
    let urllib3 = entry(&entries, "urllib3");
    assert_eq!(urllib3.purl, "pkg:pypi/urllib3@1.26.18");
    assert_eq!(urllib3.resolved, None);
    assert_eq!(
        urllib3.integrity,
        LockIntegrity::Sha256AnyOf(vec![wheel.clone(), sdist.to_ascii_lowercase()]),
        "every recorded digest, lowercased, first category wins"
    );
    assert_eq!(
        entry(&entries, "six").integrity,
        LockIntegrity::Sha256AnyOf(vec![sdist.to_ascii_lowercase()])
    );

    // A parseable uv.lock stays the exclusive inventory.
    write(
        tmp.path(),
        "uv.lock",
        "version = 1\n\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
    )
    .await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert!(entries.iter().all(|e| e.name == "other"), "{entries:?}");

    // Unparseable lock → nothing from it, requirements.txt read instead.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "Pipfile.lock", "{ not json").await;
    write(tmp.path(), "requirements.txt", "flask==3.0.0\n").await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "flask");

    // No hashes at all → discovery-only entry.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Pipfile.lock",
        r#"{"_meta": {"pipfile-spec": 6}, "default": {"urllib3": {"version": "==1.26.18"}}}"#,
    )
    .await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(entry(&entries, "urllib3").integrity, LockIntegrity::None);
}

/// One hosted pypi url grammar (`hosted_artifact_url`, the one lockfile
/// discovery reads): a hosted SDIST, an `http://` configured origin and a
/// path-prefixed origin are Socket references too, so the package stays
/// discoverable instead of vanishing from the inventory (the old
/// `https://` + exactly-7-segments + `.whl` rule dropped them).
#[tokio::test]
async fn pipfile_lock_inventory_reads_hosted_refs_with_the_shared_url_grammar() {
    let uuid = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
    let tmp = tempfile::tempdir().unwrap();
    let lock = serde_json::json!({
        "_meta": {"pipfile-spec": 6, "sources": []},
        "default": {
            "six": {"file": format!("https://patch.socket.dev/patch/pypi/six/1.16.0/g/{uuid}/six-1.16.0.tar.gz")},
            "idna": {"file": format!("http://127.0.0.1:4545/patch/pypi/idna/3.7/g/{uuid}/idna-3.7-py3-none-any.whl")},
            "attrs": {"file": format!("https://patches.example/prefix/patch/pypi/attrs/23.1.0/g/{uuid}/attrs-23.1.0-py3-none-any.whl#sha256=00")},
            "user": {"file": "https://example.org/wheels/user-1.0-py3-none-any.whl"},
            "bad": {"file": format!("https://patch.socket.dev/patch/pypi/bad/1.0/g/{uuid}/other-2.0-py3-none-any.whl")},
        }
    });
    write(tmp.path(), "Pipfile.lock", &lock.to_string()).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        sorted_pairs(&entries),
        vec![
            ("attrs".into(), "23.1.0".into()),
            ("idna".into(), "3.7".into()),
            ("six".into(), "1.16.0".into()),
        ],
        "a user's own url and a url whose artifact disagrees with its coordinates are not ours"
    );
    assert!(entries.iter().all(|e| e.integrity == LockIntegrity::None));
}

/// Socket's own references in a Pipfile.lock (a hosted URL, a vendored
/// path) keep the package discoverable on a lock-only re-scan; a lock
/// whose sources are private indexes only never carries a fetchable
/// digest set (no pypi.org lookups for it).
#[tokio::test]
async fn pipfile_lock_inventory_keeps_socket_references_discoverable_and_respects_private_indexes()
{
    let hosted = r#"{"_meta": {"pipfile-spec": 6, "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]},
"default": {
 "urllib3": {"file": "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/grant/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl#sha256=cc", "hashes": ["sha256:cc"], "markers": "x"},
 "Six": {"file": "./.socket/vendor/pypi/00000000-0000-4000-8000-000000000000/six-1.16.0-py2.py3-none-any.whl", "hashes": ["sha256:dd"]},
 "fork": {"file": "./forks/fork-1.0-py3-none-any.whl"},
 "requests": {"version": "==2.31.0", "hashes": ["sha256:%s"]}
}}"#.replace("%s", &"a".repeat(64));
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "Pipfile.lock", &hosted).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, vec!["requests", "six", "urllib3"], "{entries:?}");
    assert_eq!(entry(&entries, "urllib3").purl, "pkg:pypi/urllib3@1.26.18");
    assert_eq!(
        entry(&entries, "urllib3").integrity,
        LockIntegrity::None,
        "a hosted reference is discovery-only"
    );
    assert_eq!(entry(&entries, "six").purl, "pkg:pypi/six@1.16.0");
    assert_eq!(entry(&entries, "six").integrity, LockIntegrity::None);
    assert!(matches!(
        entry(&entries, "requests").integrity,
        LockIntegrity::Sha256AnyOf(_)
    ));

    // Private index only → the registry pin is discovery-only.
    let private = hosted.replace(
        "https://pypi.org/simple",
        "https://pypi.internal.example/simple",
    );
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "Pipfile.lock", &private).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        entry(&entries, "requests").integrity,
        LockIntegrity::None,
        "no pypi.org lookup for a private-index lock"
    );
    // A mirror listed next to PyPI keeps the digest set.
    let mixed = hosted.replace(r#"[{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]"#, r#"[{"name": "mirror", "url": "https://mirror.example/simple", "verify_ssl": true}, {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]"#);
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "Pipfile.lock", &mixed).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert!(matches!(
        entry(&entries, "requests").integrity,
        LockIntegrity::Sha256AnyOf(_)
    ));
    assert!(is_public_pypi_url("https://user:tok@pypi.org/simple"));
    assert!(!is_public_pypi_url("https://pypi.org.evil.example/simple"));
    assert_eq!(
        socket_reference_coords("./forks/fork-1.0-py3-none-any.whl"),
        None
    );
    assert_eq!(
        socket_reference_coords("https://example.org/patch/pypi/a/1/g/u/a-1-py3-none-any.whl"),
        Some(("a".into(), "1".into()))
    );
    assert_eq!(
        socket_reference_coords("https://h/pre/patch/pypi/My.Pkg/1/g/u/my_pkg-1.tar.gz"),
        Some(("my-pkg".into(), "1".into()))
    );
    assert_eq!(
        socket_reference_coords("https://h/patch/pypi/a/1/g/u/b-1-py3-none-any.whl"),
        None,
        "coordinates disagreeing with the artifact"
    );
    assert_eq!(
        socket_reference_coords("https://h/wheels/a-1-py3-none-any.whl"),
        None,
        "no patch-server tail"
    );
}

/// A lock that lists a pure-Python wheel carries its sha256 (lock 2.x
/// `files`, lock 1.x `[metadata.files]`), so a lock-only checkout can
/// vendor like uv does; platform wheels only, or 0.12's bare
/// `[metadata.hashes]`, stay discovery-only.
#[tokio::test]
async fn poetry_lock_carries_the_pure_wheel_sha256_when_listed() {
    let sha = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";
    let lock2 = format!(
        "[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\nfiles = [\n    {{file = \"urllib3-1.26.18.tar.gz\", hash = \"sha256:{}\"}},\n    {{file = \"urllib3-1.26.18-py2.py3-none-any.whl\", hash = \"sha256:{sha}\"}},\n]\n\n[[package]]\nname = \"numpy\"\nversion = \"2.0.0\"\nfiles = [\n    {{file = \"numpy-2.0.0-cp312-cp312-macosx_11_0_arm64.whl\", hash = \"sha256:{}\"}},\n]\n\n[metadata]\nlock-version = \"2.1\"\n",
        "f".repeat(64),
        "e".repeat(64)
    );
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "poetry.lock", &lock2).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        entry(&entries, "urllib3").integrity,
        LockIntegrity::Sha256Hex(sha.into())
    );
    assert_eq!(entry(&entries, "urllib3").resolved, None);
    assert_eq!(entry(&entries, "numpy").integrity, LockIntegrity::None);

    let lock1 = format!(
        "[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\n\n[metadata]\nlock-version = \"1.1\"\n\n[metadata.files]\nurllib3 = [\n    {{file = \"urllib3-1.26.18-py2.py3-none-any.whl\", hash = \"sha256:{}\"}},\n]\n",
        sha.to_uppercase()
    );
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "poetry.lock", &lock1).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        entry(&entries, "urllib3").integrity,
        LockIntegrity::Sha256Hex(sha.into()),
        "lowercased"
    );

    let lock0 = format!(
        "[[package]]\nname = \"urllib3\"\nversion = \"1.26.18\"\n\n[metadata]\ncontent-hash = \"x\"\n\n[metadata.hashes]\nurllib3 = [\"{sha}\"]\n"
    );
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "poetry.lock", &lock0).await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        entry(&entries, "urllib3").integrity,
        LockIntegrity::None,
        "bare digests name no wheel"
    );
}

#[tokio::test]
async fn pnp_layouts_propagate_the_diagnosis_instead_of_yielding_none() {
    // PnP marker wins over any lockfile — and the diagnosis must
    // PROPAGATE, not collapse into the calm no-lockfile `None`. Under
    // yarn PnP the installed-tree crawl is also structurally empty, so
    // swallowing this here made `scan` a silent success-0 no-op in
    // every mode (the P0 this pins).
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), ".pnp.cjs", "/* pnp */").await;
    write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;
    let diag = inventory_npm_lock(tmp.path()).await.unwrap_err();
    assert_eq!(diag.code, "vendor_yarn_berry_unsupported");
    assert!(diag.detail.contains("Plug'n'Play"), "{}", diag.detail);
    assert!(diag.detail.contains("yarn patch"), "{}", diag.detail);

    // pnpm's own `node-linker=pnp` twin (same loader, pnpm store):
    // same channel, pnpm diagnosis.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), ".pnp.cjs", "/* pnp */").await;
    write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'\n").await;
    tokio::fs::create_dir_all(tmp.path().join("node_modules/.pnpm"))
        .await
        .unwrap();
    write(&tmp.path().join("node_modules"), ".modules.yaml", "").await;
    let diag = inventory_npm_lock(tmp.path()).await.unwrap_err();
    assert_eq!(diag.code, "vendor_pnpm_pnp_unsupported");
    assert!(diag.detail.contains("node-linker=pnp"), "{}", diag.detail);

    // And the project-level union surfaces the same diagnosis while
    // still serving the OTHER ecosystems' lockfiles.
    let (entries, unsupported) = inventory_project_diagnosed(tmp.path()).await;
    assert!(entries.is_empty(), "{entries:?}");
    assert_eq!(unsupported.len(), 1, "{unsupported:?}");
    assert_eq!(unsupported[0].code, "vendor_pnpm_pnp_unsupported");
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    assert_eq!(
        rc,
        0,
        "mkfifo(2) failed: {}",
        std::io::Error::last_os_error()
    );
}

/// A FIFO planted as any inventoried lockfile must fail fast instead of
/// wedging every consumer — scan's lockfile supplement, vendor's
/// auto-fetch, and repair's no-ledger reconstruction all read these
/// files — forever in an `open(2)` that waits for a writer that never
/// comes. Same `open_regular_file` guard class as the vendor siblings
/// (cargo_lock.rs, composer_lock.rs, gem.rs, common.rs). Inventories
/// stay fail-soft: a non-regular lockfile reads as absent.
#[cfg(unix)]
#[tokio::test]
async fn fifo_lockfiles_fail_fast_instead_of_wedging() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    // Every filename this module opens: the per-ecosystem inventories,
    // the npm-family readers (reached without the flavor probe touching
    // the same file via the shrinkwrap/sibling/rush fallbacks), and
    // wired_vendor_integrity (no probe at all).
    let names = [
        "Cargo.lock",
        "go.sum",
        "composer.lock",
        "Gemfile.lock",
        "uv.lock",
        "poetry.lock",
        "requirements.txt",
        "npm-shrinkwrap.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "shrinkwrap.yaml",
    ];
    for name in names {
        mkfifo(&root.join(name));
    }

    // On timeout the open is wedged in a `spawn_blocking` thread that
    // the runtime waits for on shutdown; connect a non-blocking writer
    // to release it so the test can FAIL instead of hanging the suite.
    let deadline = std::time::Duration::from_secs(5);
    let all = async {
        (
            inventory_cargo_lock(&root).await,
            inventory_go_sum(&root).await,
            inventory_composer_lock(&root).await,
            inventory_gemfile_lock(&root).await,
            inventory_pypi_locks(&root).await,
            inventory_package_lock(&root).await,
            inventory_pnpm_lock(&root).await,
            inventory_yarn_classic(&root).await,
            inventory_yarn_berry(&root).await,
            inventory_bun(&root).await,
            inventory_pnpm_lock_at(&root.join("shrinkwrap.yaml")).await,
            gem_remotes(&root).await,
            wired_vendor_integrity(&root, ".socket/vendor/npm/x/x.tgz").await,
        )
    };
    let Ok(results) = tokio::time::timeout(deadline, all).await else {
        for name in names {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(root.join(name));
        }
        panic!("lockfile inventories must fail fast on FIFO lockfiles");
    };
    let (cargo, go, composer, gem, pypi, npm, pnpm, yarn_c, yarn_b, bun, legacy, remotes, wired) =
        results;
    for (label, opt) in [
        ("cargo", cargo),
        ("go", go),
        ("composer", composer),
        ("gem", gem),
        ("pypi", pypi),
        ("npm", npm),
        ("pnpm", pnpm),
        ("yarn classic", yarn_c),
        ("yarn berry", yarn_b),
        ("bun", bun),
        ("pnpm legacy", legacy),
    ] {
        assert!(
            opt.is_none(),
            "{label}: a FIFO lockfile must read as absent"
        );
    }
    assert!(remotes.is_empty(), "{remotes:?}");
    assert!(wired.is_none(), "{wired:?}");
}

#[tokio::test]
async fn unsupported_flavors_yield_none() {
    // pnpm v6.0: the probe passes it (the 6.0 grammar has a wiring
    // backend), and a dep-less lock inventories to nothing — the calm
    // None, not a refusal.
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: '6.0'\n").await;
    assert!(inventory_npm_lock(tmp.path()).await.unwrap().is_none());

    // No lockfile at all.
    let tmp = tempfile::tempdir().unwrap();
    assert!(inventory_npm_lock(tmp.path()).await.unwrap().is_none());
    let (entries, unsupported) = inventory_project_diagnosed(tmp.path()).await;
    assert!(entries.is_empty());
    assert!(unsupported.is_empty(), "{unsupported:?}");
}

/// A version-refused pnpm lock (pnpm 6 wrote 5.3) with NO live sibling
/// and NO dependencies at all: the direct read yields nothing, and the
/// fall-through past it must land on the calm `Ok(None)` via the rush
/// check — never a phantom inventory and never an error.
#[tokio::test]
async fn version_refused_depless_pnpm_lock_yields_calm_none() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "pnpm-lock.yaml", "lockfileVersion: 5.3\n").await;
    assert!(
        inventory_npm_lock(tmp.path()).await.unwrap().is_none(),
        "a dep-less version-refused pnpm lock must inventory to the calm None"
    );
}

/// The union entrypoint reads EVERY ecosystem's lock out of one polyglot
/// root — each per-ecosystem reader is unit-covered, but the union arms
/// (go.sum, pypi, …) only execute here. `lookup` bridges one purl per
/// ecosystem, and an unknown purl type (nuget has no lock inventory)
/// yields None instead of a cross-ecosystem false match.
#[tokio::test]
async fn inventory_project_unions_every_ecosystem_lock() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), "package-lock.json", PACKAGE_LOCK).await;
    write(
        tmp.path(),
        "Cargo.lock",
        "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
             checksum = \"ddc6f9cc94d67c0e21aaf7eda3a010fd3af78ebf6e096aa6e2e13c79749cce4f\"\n",
    )
    .await;
    write(
        tmp.path(),
        "go.sum",
        "github.com/gin-gonic/gin v1.9.1 h1:4idEAncQnU5cB7BeOkPtxjfCSye0AAm1R0RVIqJ+Jmg=\n",
    )
    .await;
    write(
        tmp.path(),
        "composer.lock",
        r#"{ "packages": [ { "name": "Monolog/Monolog", "version": "v3.5.0",
                 "dist": { "type": "zip", "url": "https://example.com/monolog.zip",
                           "shasum": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" } } ] }"#,
    )
    .await;
    write(
        tmp.path(),
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n",
    )
    .await;
    write(tmp.path(), "requirements.txt", "requests==2.31.0\n").await;

    let (entries, unsupported) = inventory_project_diagnosed(tmp.path()).await;
    assert!(unsupported.is_empty(), "{unsupported:?}");
    for purl in [
        "pkg:npm/left-pad@1.3.0",
        "pkg:cargo/serde@1.0.200",
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
        "pkg:composer/monolog/monolog@3.5.0",
        "pkg:gem/rails@7.1.0",
        "pkg:pypi/requests@2.31.0",
    ] {
        assert!(
            lookup(&entries, purl).is_some(),
            "the union must serve {purl}: {entries:?}"
        );
    }
    // Unknown purl type: no inventory ever answers for nuget.
    assert!(
        lookup(&entries, "pkg:nuget/Newtonsoft.Json@13.0.1").is_none(),
        "an unrecognized purl type must never match: {entries:?}"
    );
}

/// The `[metadata]` tail of a v1-era Cargo.lock flushes the in-flight
/// block (its key=value lines must not bleed a foreign checksum into the
/// LAST package), and an unsafe name is dropped fail-closed — the
/// lockfile is committed, tamperable input feeding paths/URLs.
#[tokio::test]
async fn cargo_lock_metadata_section_flushes_and_unsafe_name_drops() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Cargo.lock",
        &format!(
            "version = 3\n\n\
                 [[package]]\nname = \"../evil\"\nversion = \"1.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n\n\
                 [[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n\n\
                 [metadata]\n\
                 \"checksum foo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)\" = \"{}\"\n",
            "a".repeat(64),
            "d".repeat(64),
            "b".repeat(64),
        ),
    )
    .await;

    let entries = inventory_cargo_lock(tmp.path()).await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "only the safe crates.io package inventories: {entries:?}"
    );
    let serde_entry = entry(&entries, "serde");
    assert_eq!(
        serde_entry.integrity,
        LockIntegrity::Sha256Hex("d".repeat(64)),
        "the [metadata] line's checksum must not bleed into the last block"
    );
    assert!(
        !entries.iter().any(|e| e.name.contains("..")),
        "{entries:?}"
    );
    assert!(!entries.iter().any(|e| e.name == "foo"), "{entries:?}");
}

/// go.sum lines with fewer than 3 fields are skipped, and unsafe module
/// paths / versions are dropped fail-closed (SECURITY: both feed
/// filesystem paths and download URLs).
#[tokio::test]
async fn go_sum_skips_short_and_unsafe_lines() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "go.sum",
        "lonely\n\
             example.com/../up v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
             example.com/mod v1.0.0/../x h1:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n\
             golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=\n",
    )
    .await;

    let entries = inventory_go_sum(tmp.path()).await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "short and unsafe lines must be skipped: {entries:?}"
    );
    assert_eq!(entries[0].name, "golang.org/x/text");
    assert!(
        !entries
            .iter()
            .any(|e| e.name.contains("..") || e.version.contains("..")),
        "{entries:?}"
    );
}

/// shrinkwrap.yaml BLOCK-mapped `resolution:` with a `tarball:` child
/// AND a following shallower-indented field: the mapping must terminate
/// at the shallower line (the SHRINKWRAP_YAML fixture happens to put
/// resolution last in every entry, so the terminator never ran) and the
/// tarball child must be captured as the resolved URL.
#[tokio::test]
async fn shrinkwrap_block_mapped_tarball_reads_and_stops_at_shallower_indent() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "shrinkwrap.yaml",
        "dependencies:
  left-pad: 1.3.0
packages:
  /left-pad/1.3.0:
    resolution:
      integrity: sha512-blockmapped==
      tarball: https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz
    dev: false
registry: 'https://registry.npmjs.org/'
shrinkwrapVersion: 3
",
    )
    .await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::PnpmLegacy);
    let lp = entry(&entries, "left-pad");
    assert_eq!(
        lp.resolved.as_deref(),
        Some("https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"),
        "the block-mapped tarball child must be captured"
    );
    assert_eq!(
        lp.integrity,
        LockIntegrity::Sri("sha512-blockmapped==".into()),
        "the shallower `dev:` line must terminate the mapping without eating fields"
    );
}

/// A registry-shaped pnpm key (digit version) whose resolution tarball
/// points into `.socket/vendor/` is OUR OWN vendored artifact, not a
/// registry dependency — self-exclusion fail-closed. (Rewired v9 locks
/// are keyed `name@file:…` and die at the digit check instead, but a
/// crafted or v5.4-era lock can present exactly this shape.)
#[tokio::test]
async fn pnpm_registry_keyed_entry_with_vendored_tarball_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "pnpm-lock.yaml",
        "lockfileVersion: '6.0'

packages:

  /left-pad@1.3.0:
    resolution: {integrity: sha512-x==, tarball: file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz}

  /other@2.0.0:
    resolution: {integrity: sha512-y==}
",
    )
    .await;

    let (_, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert!(
        !entries.iter().any(|e| e.name == "left-pad"),
        "a vendored tarball must self-exclude even behind a registry key: {entries:?}"
    );
    assert_eq!(
        entry(&entries, "other").integrity,
        LockIntegrity::Sri("sha512-y==".into())
    );
}

/// Real classic-lock degenerations: a `resolved` URL without the legacy
/// `#sha1` fragment (registries that strip fragments) and a block with
/// no `resolved` at all (offline-pruned locks). Both stay listed for
/// discovery with no verifier — never dropped, never guessed.
#[tokio::test]
async fn yarn_classic_fragmentless_and_resolvedless_blocks_stay_discovery_only() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "yarn.lock",
        "# yarn lockfile v1\n\n\
             no-fragment@^1.0.0:\n  version \"1.0.0\"\n  \
             resolved \"https://registry.npmjs.org/no-fragment/-/no-fragment-1.0.0.tgz\"\n\n\
             no-resolved@^2.0.0:\n  version \"2.0.0\"\n",
    )
    .await;

    let entries = inventory_yarn_classic(tmp.path()).await.unwrap();
    let nf = entry(&entries, "no-fragment");
    assert_eq!(
        nf.resolved.as_deref(),
        Some("https://registry.npmjs.org/no-fragment/-/no-fragment-1.0.0.tgz"),
        "a fragmentless URL is still a usable artifact URL"
    );
    assert_eq!(nf.integrity, LockIntegrity::None);
    let nr = entry(&entries, "no-resolved");
    assert_eq!(nr.resolved, None);
    assert_eq!(nr.integrity, LockIntegrity::None);
}

/// bun.lock is attacker-shaped committed input; each malformed 4-tuple
/// (undecodable spec/registry/integrity elements, unsplittable spec,
/// non-registry version) is skipped fail-soft — the well-formed entry
/// still inventories and no malformed one leaks through.
#[tokio::test]
async fn bun_malformed_tuples_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "bun.lock",
        r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "fixture", "dependencies": { "left-pad": "1.3.0" } },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPz=="],
    "bad-elem0": [123, "", {}, "sha512-a=="],
    "noat": ["noatsign", "", {}, "sha512-b=="],
    "wsdep": ["wsdep@workspace:*", "", {}, "sha512-c=="],
    "badreg": ["badreg@1.0.0", 42, {}, "sha512-d=="],
    "badint": ["badint@1.0.0", "", {}, 99],
  }
}
"#,
    )
    .await;

    let (flavor, entries) = inventory_npm_lock(tmp.path()).await.unwrap().unwrap();
    assert_eq!(flavor, NpmLockFlavor::Bun);
    assert_eq!(
        sorted_pairs(&entries),
        vec![("left-pad".into(), "1.3.0".into())],
        "every malformed tuple must be skipped, the good one kept"
    );
}

/// composer.lock packages missing a name or version are skipped, and
/// names that are unsafe or not `vendor/pkg`-shaped are dropped
/// fail-closed (SECURITY: they feed paths and download URLs).
#[tokio::test]
async fn composer_lock_drops_nameless_versionless_and_unsafe_packages() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "composer.lock",
        r#"{
  "packages": [
    { "version": "1.0.0" },
    { "name": "nameless/partner" },
    { "name": "singleseg", "version": "1.0.0" },
    { "name": "a/../b", "version": "1.0.0" },
    { "name": "good/pkg", "version": "1.0.0" }
  ]
}"#,
    )
    .await;

    let entries = inventory_composer_lock(tmp.path()).await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "only the well-formed safe package inventories: {entries:?}"
    );
    assert_eq!(entries[0].purl, "pkg:composer/good/pkg@1.0.0");
}

/// The pre-multisource Gemfile.lock shape: ONE remote-less GEM section
/// defaults to rubygems.org. Rides along: an unsafe spec name is dropped
/// fail-closed, and a CHECKSUMS value that is not 64-hex is ignored (the
/// entry stays discovery-fetchable but unverified — LockIntegrity::None).
#[tokio::test]
async fn gemfile_lock_remoteless_single_section_defaults_to_rubygems() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "Gemfile.lock",
        "GEM\n  specs:\n    rake (13.0.6)\n    ../evil (1.0.0)\n\n\
             CHECKSUMS\n  rake (13.0.6) sha256=zznothexzznothexzznothexzznothex\n",
    )
    .await;

    let entries = inventory_gemfile_lock(tmp.path()).await.unwrap();
    assert_eq!(
        entries.len(),
        1,
        "the unsafe spec name must be dropped: {entries:?}"
    );
    let rake = entry(&entries, "rake");
    assert_eq!(
        rake.resolved.as_deref(),
        Some("https://rubygems.org/downloads/rake-13.0.6.gem"),
        "a lone remote-less GEM section defaults to rubygems.org"
    );
    assert_eq!(
        rake.integrity,
        LockIntegrity::None,
        "a non-64-hex CHECKSUMS value must be ignored"
    );
}

/// A poetry.lock with zero `[[package]]` blocks yields None, which
/// routes `inventory_pypi_locks` onward to requirements.txt — where a
/// non-digit-version pin is guard-dropped; and a requirements.txt with
/// no `==` pin at all yields None.
#[tokio::test]
async fn depless_poetry_lock_falls_through_to_requirements() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "poetry.lock",
        "[metadata]\nlock-version = \"2.0\"\n",
    )
    .await;
    write(
        tmp.path(),
        "requirements.txt",
        "requests==2.31.0\nbad==vNaN\n",
    )
    .await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        sorted_pairs(&entries),
        vec![("requests".into(), "2.31.0".into())],
        "a package-less poetry.lock must route onward; the vNaN pin is dropped"
    );

    // No exact pin anywhere: the calm None, not an empty inventory.
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "requirements.txt",
        "# comment\n-r other.txt\nflask>=2.0\n",
    )
    .await;
    assert!(inventory_pypi_locks(tmp.path()).await.is_none());
}

/// requirements.txt pins read with the shared exact-pin rule
/// (`utils::requirements::exact_pin`, the one lockfile discovery uses): a
/// wildcard or arbitrary-equality pin is no exact version, so it is not
/// inventoried as one (it used to emit `pkg:pypi/six@1.*`).
#[tokio::test]
async fn requirements_wildcard_pins_are_not_exact_versions() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        tmp.path(),
        "requirements.txt",
        "six==1.*\nattrs===23.1.0\nidna==3.*  # wildcard\nrequests[socks]==2.31.0 ; python_version >= \"3.8\"\n",
    )
    .await;
    let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
    assert_eq!(
        sorted_pairs(&entries),
        vec![("requests".into(), "2.31.0".into())]
    );
}

/// `pure_wheel_from_uv_unit` rejection fall-throughs: a pure wheel whose
/// hash is not 64-hex, one with no hash at all, and one whose URL is not
/// http(s) all yield None — fail-closed, never a guessed pairing.
#[tokio::test]
async fn pure_wheel_rejects_short_hash_missing_hash_and_non_http_url() {
    let short = "wheels = [{ url = \"https://h/x-1.0-py3-none-any.whl\", hash = \"sha256:abcd\" }]";
    assert_eq!(pure_wheel_from_uv_unit(short), None, "short hash");

    let hashless = "wheels = [{ url = \"https://h/x-1.0-py3-none-any.whl\" }]";
    assert_eq!(pure_wheel_from_uv_unit(hashless), None, "no hash");

    let ftp = format!(
        "wheels = [{{ url = \"ftp://h/x-1.0-py3-none-any.whl\", hash = \"sha256:{}\" }}]",
        "a".repeat(64)
    );
    assert_eq!(pure_wheel_from_uv_unit(&ftp), None, "non-http url");
}

/// The yarn-classic `integrity <sri>` branch of `wired_vendor_integrity`
/// — the trust anchor for repair's no-ledger reconstruction on
/// yarn-classic projects (rewired classic locks carry exactly this
/// line). Rides along fail-soft: an unparseable JSON lock and a v1 lock
/// without a `packages` map are both skipped, not fatal.
#[tokio::test]
async fn wired_vendor_integrity_reads_rewired_yarn_classic_and_skips_bad_json_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let rel = ".socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
    // Unparseable JSON lock: skipped fail-soft.
    write(tmp.path(), "npm-shrinkwrap.json", "not json").await;
    // v1 lock without a packages map: skipped fail-soft.
    write(
        tmp.path(),
        "package-lock.json",
        r#"{"lockfileVersion":1,"dependencies":{}}"#,
    )
    .await;
    // The rewired classic block, exactly as yarn_classic_lock rewires it.
    write(
        tmp.path(),
        "yarn.lock",
        &format!(
            "# yarn lockfile v1\n\n\
                 \"left-pad@file:./{rel}\":\n  \
                 version \"1.3.0\"\n  \
                 resolved \"file:./{rel}#0000000000000000000000000000000000000000\"\n  \
                 integrity sha512-ours==\n"
        ),
    )
    .await;

    assert_eq!(
        wired_vendor_integrity(tmp.path(), rel).await,
        Some(LockIntegrity::Sri("sha512-ours==".into())),
        "the classic `integrity <sri>` line is the wired trust anchor"
    );
}

/// `PnpmPackage::resolution_tokens` exposes the raw `resolution:` value the
/// grammar refused (a nested map, a duplicate key, a wrapped flow map), so
/// lockfile discovery can still tell a Socket-shaped entry from anything
/// else without locating resolution lines itself.
#[test]
fn pnpm_resolution_tokens_cover_maps_the_grammar_refuses() {
    let url = "https://patch.socket.dev/patch/npm/x/1.0.0/g/u/x-1.0.0.tgz";
    let lock = format!(
        "lockfileVersion: '9.0'\n\npackages:\n\n  x@1.0.0:\n    resolution:\n      tarball: {url}\n      nested:\n        a: b\n\n  y@1.0.0:\n    resolution: {{integrity: sha512-a}}\n    resolution: {{tarball: '{url}'}}\n\n  z@1.0.0:\n    resolution: {{integrity: sha512-z,\n      tarball: \"{url}\"}}\n\n  ok@1.0.0:\n    resolution: {{integrity: sha512-ok}}\n"
    );
    let packages = super::pnpm::pnpm_packages(&lock);
    let by_key = |key: &str| packages.iter().find(|p| p.key == key).unwrap();
    for key in ["x@1.0.0", "y@1.0.0", "z@1.0.0"] {
        let package = by_key(key);
        assert!(
            package.resolution.is_none(),
            "{key}: the grammar refuses it"
        );
        assert!(
            package.resolution_tokens().contains(&url),
            "{key}: the resolution URL is not among the entry's resolution values"
        );
    }
    let ok = by_key("ok@1.0.0");
    assert!(ok.resolution.is_some());
    assert_eq!(ok.resolution_tokens(), vec!["integrity:", "sha512-ok"]);
}
