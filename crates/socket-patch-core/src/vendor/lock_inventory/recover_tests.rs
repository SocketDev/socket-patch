use super::super::state::WiringAction;
use super::super::state::{CargoLockOriginal, VendorArtifact, VendorEntry, WiringRecord};
use super::*;

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

fn entry(eco: &str, base_purl: &str, wiring: Vec<WiringRecord>) -> VendorEntry {
    VendorEntry {
        ecosystem: eco.into(),
        base_purl: base_purl.into(),
        uuid: UUID.into(),
        artifact: VendorArtifact {
            path: format!(".socket/vendor/{eco}/{UUID}/x"),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    }
}

fn rec(kind: &str, original: serde_json::Value) -> WiringRecord {
    WiringRecord {
        file: "lock".into(),
        kind: kind.into(),
        action: WiringAction::Rewritten,
        key: Some("k".into()),
        original: Some(original),
        new: None,
    }
}

#[tokio::test]
async fn python_document_recovery_selects_the_requested_package() {
    let tmp = tempfile::tempdir().unwrap();
    let sha = "c".repeat(64);
    let lock = format!("lock-version='1.0'\n[[packages]]\nname='other'\nversion='1'\narchive={{url='https://pypi.org/other-1-py3-none-any.whl',hashes={{sha256='{}'}}}}\n[[packages]]\nname='target'\nversion='2'\narchive={{url='https://pypi.org/target-2-py3-none-any.whl',hashes={{sha256='{sha}'}}}}\n", "d".repeat(64));
    let record = rec("python_lock_document", serde_json::json!(lock));
    let ledger = entry("pypi", "pkg:pypi/target@2", vec![record.clone()]);
    let recovered = recover_lock_entry(tmp.path(), &ledger).await.unwrap();
    assert_eq!(
        recovered.resolved.as_deref(),
        Some("https://pypi.org/target-2-py3-none-any.whl")
    );
    assert_eq!(recovered.integrity, LockIntegrity::Sha256Hex(sha));
    let absent = entry("pypi", "pkg:pypi/target@3", vec![record]);
    assert!(recover_lock_entry(tmp.path(), &absent).await.is_err());
}

#[tokio::test]
async fn npm_lock_entry_fragment_recovers_sri_and_url() {
    let tmp = tempfile::tempdir().unwrap();
    let e = entry(
        "npm",
        "pkg:npm/@scope/x@1.2.3",
        vec![rec(
            "npm_lock_entry",
            serde_json::json!({
                "resolved": "https://registry.npmjs.org/@scope/x/-/x-1.2.3.tgz",
                "integrity": "sha512-AAAA",
            }),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
    assert_eq!(got.ecosystem, "npm");
    assert_eq!(got.name, "@scope/x");
    assert_eq!(got.version, "1.2.3");
    assert_eq!(
        got.resolved.as_deref(),
        Some("https://registry.npmjs.org/@scope/x/-/x-1.2.3.tgz")
    );
    assert_eq!(got.integrity, LockIntegrity::Sri("sha512-AAAA".into()));
}

#[tokio::test]
async fn vlt_lock_node_original_recovers_sri_and_url() {
    let tmp = tempfile::tempdir().unwrap();
    let node = |tuple: &str| {
        entry(
            "npm",
            "pkg:npm/%40scope/x@1.2.3",
            vec![rec(
                "vlt_lock_node",
                serde_json::Value::String(format!("\"~npm~@scope+x@1.2.3\": {tuple}")),
            )],
        )
    };
    let got = recover_lock_entry(
        tmp.path(),
        &node(
            r#"[0,"@scope/x","sha512-AAAA","https://registry.npmjs.org/@scope/x/-/x-1.2.3.tgz"]"#,
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        (got.name.as_str(), got.version.as_str()),
        ("@scope/x", "1.2.3")
    );
    assert_eq!(
        got.resolved.as_deref(),
        Some("https://registry.npmjs.org/@scope/x/-/x-1.2.3.tgz")
    );
    assert_eq!(got.integrity, LockIntegrity::Sri("sha512-AAAA".into()));

    let got = recover_lock_entry(tmp.path(), &node(r#"[0,"@scope/x","sha512-AAAA"]"#))
        .await
        .unwrap();
    assert_eq!(
        got.resolved, None,
        "a 3-tuple leaves the URL to the fetcher"
    );
    assert!(
        recover_lock_entry(tmp.path(), &node(r#"[0,"@scope/x",null,"file:x"]"#))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bun_binary_snapshot_recovers_registry_metadata_and_checks_coordinates() {
    let tmp = tempfile::tempdir().unwrap();
    let original = serde_json::json!({
        "name": "@scope/x", "version": "1.2.3",
        "resolution": "https://registry.example/@scope/x/-/x-1.2.3.tgz",
        "integrity": "sha512-AAAA",
    });
    let good = entry(
        "npm",
        "pkg:npm/@scope/x@1.2.3",
        vec![rec("bun_lockb_package", original.clone())],
    );
    let recovered = recover_lock_entry(tmp.path(), &good).await.unwrap();
    assert_eq!(
        recovered.resolved.as_deref(),
        Some("https://registry.example/@scope/x/-/x-1.2.3.tgz")
    );
    assert_eq!(
        recovered.integrity,
        LockIntegrity::Sri("sha512-AAAA".into())
    );
    let mismatched = entry(
        "npm",
        "pkg:npm/@scope/x@2.0.0",
        vec![rec("bun_lockb_package", original)],
    );
    assert!(recover_lock_entry(tmp.path(), &mismatched).await.is_err());
}

#[tokio::test]
async fn pnpm_package_lines_recover_integrity_and_tarball() {
    let tmp = tempfile::tempdir().unwrap();
    let e = entry(
        "npm",
        "pkg:npm/left-pad@1.3.0",
        vec![rec(
            "pnpm_lock_package",
            serde_json::json!([
                "  left-pad@1.3.0:",
                "    resolution: {integrity: sha512-BBBB, tarball: https://npm.corp/left-pad-1.3.0.tgz}",
            ]),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
    assert_eq!(got.integrity, LockIntegrity::Sri("sha512-BBBB".into()));
    assert_eq!(
        got.resolved.as_deref(),
        Some("https://npm.corp/left-pad-1.3.0.tgz")
    );
}

#[tokio::test]
async fn yarn_classic_block_prefers_sri_else_sha1() {
    let tmp = tempfile::tempdir().unwrap();
    let sha1 = "a".repeat(40);
    let with_both = entry(
        "npm",
        "pkg:npm/x@1.0.0",
        vec![rec(
            "yarn_lock_block",
            serde_json::json!([
                "x@^1.0.0:",
                "  version \"1.0.0\"",
                format!("  resolved \"https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#{sha1}\""),
                "  integrity sha512-CCCC",
            ]),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &with_both).await.unwrap();
    assert_eq!(got.integrity, LockIntegrity::Sri("sha512-CCCC".into()));
    assert_eq!(
        got.resolved.as_deref(),
        Some("https://registry.yarnpkg.com/x/-/x-1.0.0.tgz")
    );

    let sha1_only = entry(
        "npm",
        "pkg:npm/x@1.0.0",
        vec![rec(
            "yarn_lock_block",
            serde_json::json!([format!(
                "  resolved \"https://registry.yarnpkg.com/x/-/x-1.0.0.tgz#{sha1}\""
            )]),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &sha1_only).await.unwrap();
    assert_eq!(got.integrity, LockIntegrity::Sha1Hex(sha1));
}

#[tokio::test]
async fn berry_checksum_and_bun_tuple_recover() {
    let tmp = tempfile::tempdir().unwrap();
    let berry = entry(
        "npm",
        "pkg:npm/x@1.0.0",
        vec![rec(
            "yarn_berry_lock_entry",
            serde_json::json!(["x@npm:1.0.0:", "  checksum: 10c0/abcdef"]),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &berry).await.unwrap();
    assert_eq!(
        got.integrity,
        LockIntegrity::BerryChecksum("10c0/abcdef".into())
    );
    assert_eq!(got.resolved, None);

    let bun = entry(
        "npm",
        "pkg:npm/x@1.0.0",
        vec![rec(
            "bun_lock_package",
            serde_json::json!("    \"x\": [\"x@1.0.0\", \"\", {}, \"sha512-DDDD\"],"),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &bun).await.unwrap();
    assert_eq!(got.integrity, LockIntegrity::Sri("sha512-DDDD".into()));
}

#[tokio::test]
async fn cargo_recovers_from_entry_lock_checksum() {
    let tmp = tempfile::tempdir().unwrap();
    let sha = "b".repeat(64);
    let mut e = entry("cargo", "pkg:cargo/serde@1.0.0", vec![]);
    e.lock = Some(CargoLockOriginal {
        source: "registry+https://github.com/rust-lang/crates.io-index".into(),
        checksum: Some(sha.clone()),
    });
    let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
    assert_eq!(got.ecosystem, "cargo");
    assert_eq!(got.integrity, LockIntegrity::Sha256Hex(sha));
    assert_eq!(got.resolved, None);

    // No checksum recorded → unrecoverable, never an unverified fetch.
    let mut bare = entry("cargo", "pkg:cargo/serde@1.0.0", vec![]);
    bare.lock = None;
    assert!(recover_lock_entry(tmp.path(), &bare).await.is_err());
}

#[tokio::test]
async fn composer_gem_uv_fragments_recover() {
    let tmp = tempfile::tempdir().unwrap();
    let sha1 = "c".repeat(40);
    let composer = entry(
        "composer",
        "pkg:composer/monolog/monolog@2.9.1",
        vec![rec(
            "composer_lock_package",
            serde_json::json!({
                "name": "monolog/monolog",
                "dist": {
                    "type": "zip",
                    "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
                    "shasum": sha1,
                },
            }),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &composer).await.unwrap();
    assert_eq!(got.name, "monolog/monolog");
    assert_eq!(got.integrity, LockIntegrity::Sha1Hex(sha1));

    // gem: checksum line + remote read from the unrewired Gemfile.lock.
    let sha256 = "d".repeat(64);
    tokio::fs::write(
        tmp.path().join("Gemfile.lock"),
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.0)\n",
    )
    .await
    .unwrap();
    let gem = entry(
        "gem",
        "pkg:gem/rack@3.0.0",
        vec![rec(
            "gemfile_lock_checksum",
            serde_json::json!(format!("  rack (3.0.0) sha256={sha256}")),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &gem).await.unwrap();
    assert_eq!(got.integrity, LockIntegrity::Sha256Hex(sha256.clone()));
    assert_eq!(
        got.resolved.as_deref(),
        Some("https://rubygems.org/downloads/rack-3.0.0.gem")
    );

    // uv: the original [[package]] unit lists wheels; only the PURE one
    // is recoverable.
    let wheel_sha = "e".repeat(64);
    let unit = format!(
        "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nwheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/six-1.16.0-cp39-cp39-linux_x86_64.whl\", hash = \"sha256:{}\" }},\n    {{ url = \"https://files.pythonhosted.org/packages/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{wheel_sha}\" }},\n]\n",
        "f".repeat(64)
    );
    let uv = entry(
        "pypi",
        "pkg:pypi/six@1.16.0",
        vec![rec("uv_lock_package", serde_json::json!(unit))],
    );
    let got = recover_lock_entry(tmp.path(), &uv).await.unwrap();
    assert_eq!(got.integrity, LockIntegrity::Sha256Hex(wheel_sha));
    assert!(got.resolved.unwrap().ends_with("py2.py3-none-any.whl"));

    // platform-locked wheels are explicitly unrepairable from the registry.
    let mut locked = entry("pypi", "pkg:pypi/six@1.16.0", vec![]);
    locked.artifact.platform_locked = Some(true);
    assert!(recover_lock_entry(tmp.path(), &locked).await.is_err());
}

// A pdm.lock produced with the `static_urls` strategy inlines the wheel
// URL exactly like uv.lock, but records it under the `pdm_lock_package`
// wiring kind. Recovery used to look only at `uv_lock_package`, so it was
// blind to pdm/poetry/pipenv projects; it now accepts every pypi kind.
#[tokio::test]
async fn recover_pypi_pdm_static_urls_recovers_pure_wheel() {
    let tmp = tempfile::tempdir().unwrap();
    let wheel_sha = "a".repeat(64);
    let unit = format!(
        "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nfiles = [\n    {{url = \"https://files.pythonhosted.org/packages/71/39/six-1.16.0.tar.gz\", hash = \"sha256:{}\"}},\n    {{url = \"https://files.pythonhosted.org/packages/d9/5a/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{wheel_sha}\"}},\n]\n",
        "b".repeat(64)
    );
    let pdm = entry(
        "pypi",
        "pkg:pypi/six@1.16.0",
        vec![rec("pdm_lock_package", serde_json::json!(unit))],
    );
    let got = recover_lock_entry(tmp.path(), &pdm).await.unwrap();
    assert_eq!(got.ecosystem, "pypi");
    assert_eq!(got.name, "six");
    assert_eq!(got.integrity, LockIntegrity::Sha256Hex(wheel_sha));
    assert!(got.resolved.unwrap().ends_with("py2.py3-none-any.whl"));
}

// Default pdm/poetry (`file = …`), pipenv (`hashes` only) and pip
// (`--hash=`) locks record the wheel hash but no fetchable URL. Recovery
// now RECOGNIZES those fragments (previously they fell through to the
// uv-specific "no uv.lock fragment recorded" error) and returns an
// accurate, actionable message instead of the false "not installed / no
// recoverable fragment".
#[tokio::test]
async fn recover_pypi_urlless_locks_report_no_fetchable_url() {
    let tmp = tempfile::tempdir().unwrap();

    // poetry / default-pdm shape: `files = [{file = …, hash = …}]`.
    let poetry_unit = format!(
        "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nfiles = [\n    {{file = \"six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{}\"}},\n]\n",
        "a".repeat(64)
    );
    for kind in ["poetry_lock_package", "pdm_lock_package"] {
        let e = entry(
            "pypi",
            "pkg:pypi/six@1.16.0",
            vec![rec(kind, serde_json::json!(poetry_unit))],
        );
        let err = recover_lock_entry(tmp.path(), &e).await.unwrap_err();
        assert!(err.contains("no fetchable registry URL"), "{kind}: {err}");
        assert!(!err.contains("uv.lock fragment recorded"), "{kind}: {err}");
    }

    // pipenv records a JSON object (hashes + version), not a string unit:
    // its digest set IS fetchable (PyPI JSON API lookup by digest), so a
    // lock-only checkout of an already-vendored project recovers.
    let pipenv = entry(
        "pypi",
        "pkg:pypi/six@1.16.0",
        vec![rec(
            "pipenv_lock_entry",
            serde_json::json!({
                "hashes": [format!("sha256:{}", "a".repeat(64)), format!("sha256:{}", "B".repeat(64))],
                "version": "==1.16.0",
            }),
        )],
    );
    let recovered = recover_lock_entry(tmp.path(), &pipenv).await.unwrap();
    assert_eq!(recovered.purl, "pkg:pypi/six@1.16.0");
    assert_eq!(recovered.resolved, None);
    assert_eq!(
        recovered.integrity,
        LockIntegrity::Sha256AnyOf(vec!["a".repeat(64), "b".repeat(64)]),
        "lowercased digest set"
    );
    // …but a pipenv fragment without digests has nothing to fetch by.
    let digestless = entry(
        "pypi",
        "pkg:pypi/six@1.16.0",
        vec![rec(
            "pipenv_lock_entry",
            serde_json::json!({"version": "==1.16.0"}),
        )],
    );
    let err = recover_lock_entry(tmp.path(), &digestless)
        .await
        .unwrap_err();
    assert!(err.contains("no sha256 digests"), "pipenv: {err}");

    // A ledger with no pypi fragment at all is still a hard error.
    let bare = entry("pypi", "pkg:pypi/six@1.16.0", vec![]);
    assert!(recover_lock_entry(tmp.path(), &bare).await.is_err());
}

/// Ledger recovery cannot know which GEM section a vendored gem came
/// from (its spec moved into the PATH section), so a multi-source lock
/// makes the download origin ambiguous: refuse rather than guess (a
/// wrong remote 404s at best and leaks a private gem name at worst).
/// Sections that AGREE on one remote stay recoverable.
#[tokio::test]
async fn gem_recovery_refuses_ambiguous_multi_source_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let sha256 = "d".repeat(64);
    let gem = entry(
        "gem",
        "pkg:gem/rack@3.0.0",
        vec![rec(
            "gemfile_lock_checksum",
            serde_json::json!(format!("  rack (3.0.0) sha256={sha256}")),
        )],
    );

    // Two GEM sections, two different remotes → ambiguous, fail closed.
    tokio::fs::write(
        tmp.path().join("Gemfile.lock"),
        "GEM\n  remote: https://gems.corp.example/\n  specs:\n    private-gem (1.0.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n",
    )
    .await
    .unwrap();
    let err = recover_lock_entry(tmp.path(), &gem).await.unwrap_err();
    assert!(
        err.contains("multiple GEM sources"),
        "ambiguity must be named: {err}"
    );

    // Two GEM sections agreeing on ONE remote (dedup) → recoverable.
    tokio::fs::write(
        tmp.path().join("Gemfile.lock"),
        "GEM\n  remote: https://gems.corp.example/\n  specs:\n    other (1.0.0)\n\n\
             GEM\n  remote: https://gems.corp.example/\n  specs:\n",
    )
    .await
    .unwrap();
    let got = recover_lock_entry(tmp.path(), &gem).await.unwrap();
    assert_eq!(
        got.resolved.as_deref(),
        Some("https://gems.corp.example/downloads/rack-3.0.0.gem"),
        "the agreed remote is used, not a rubygems.org guess"
    );
    assert_eq!(got.integrity, LockIntegrity::Sha256Hex(sha256));
}

/// The ambiguity count must see NON-http remotes too (a `source
/// "file://…" do` block locks its own GEM section with a `file:///`
/// remote — real bundler 4.0.15 output). Filtering to http(s) first
/// would collapse a mixed http+file lock to one "agreed" remote and
/// send a possibly-file-sourced gem's name to the http registry — the
/// same leak class the multi-http refusal closes. A lock whose ONLY
/// remote is non-http must refuse too, never default to rubygems.org.
#[tokio::test]
async fn gem_recovery_counts_non_http_remotes_as_ambiguity() {
    let tmp = tempfile::tempdir().unwrap();
    let gem = entry(
        "gem",
        "pkg:gem/rack@3.0.0",
        vec![rec(
            "gemfile_lock_checksum",
            serde_json::json!(format!("  rack (3.0.0) sha256={}", "d".repeat(64))),
        )],
    );

    // Mixed schemes: one file:// section + one https section → ambiguous.
    tokio::fs::write(
        tmp.path().join("Gemfile.lock"),
        "GEM\n  remote: file:///srv/gems/\n  specs:\n    private-gem (1.0.0)\n\n\
             GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.3.1)\n",
    )
    .await
    .unwrap();
    let err = recover_lock_entry(tmp.path(), &gem).await.unwrap_err();
    assert!(
        err.contains("multiple GEM sources"),
        "a file:// section must count toward the ambiguity refusal: {err}"
    );

    // A single file:// remote: not fetchable, and never a rubygems.org
    // fallback (that would leak the private repo's gem name off-site).
    tokio::fs::write(
        tmp.path().join("Gemfile.lock"),
        "GEM\n  remote: file:///srv/gems/\n  specs:\n    private-gem (1.0.0)\n",
    )
    .await
    .unwrap();
    let err = recover_lock_entry(tmp.path(), &gem).await.unwrap_err();
    assert!(
        err.contains("file:///srv/gems") && err.contains("not an http(s) registry"),
        "a lone non-http remote must refuse, not guess: {err}"
    );
}

#[tokio::test]
async fn recover_decodes_percent_encoded_base_purl() {
    // The ledger stores base_purl verbatim as the manifest spelled it —
    // often percent-encoded (`pkg:npm/%40scope/x@1.2.3`). The recovered
    // entry must carry literal coordinates: the name feeds the registry
    // tarball URL and the berry cache-zip recipe (which embeds it in
    // member paths), so an encoded name fails every checksum rebuild.
    let tmp = tempfile::tempdir().unwrap();
    let e = entry(
        "npm",
        "pkg:npm/%40scope/x@1.2.3",
        vec![rec(
            "yarn_berry_lock_entry",
            serde_json::json!(["\"@scope/x@npm:1.2.3\":", "  checksum: 10c0/abcdef"]),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
    assert_eq!(got.name, "@scope/x");
    assert_eq!(got.purl, "pkg:npm/@scope/x@1.2.3");

    // Version components decode too (`1.0.0%2Bbuild` → `1.0.0+build`).
    let e = entry(
        "npm",
        "pkg:npm/x@1.0.0%2Bbuild",
        vec![rec(
            "npm_lock_entry",
            serde_json::json!({
                "resolved": "https://registry.npmjs.org/x/-/x-1.0.0+build.tgz",
                "integrity": "sha512-AAAA",
            }),
        )],
    );
    let got = recover_lock_entry(tmp.path(), &e).await.unwrap();
    assert_eq!(got.version, "1.0.0+build");
}

#[tokio::test]
async fn unrecoverable_fragments_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    // No wiring at all.
    let bare = entry("npm", "pkg:npm/x@1.0.0", vec![]);
    assert!(recover_lock_entry(tmp.path(), &bare).await.is_err());
    // golang routes through go.sum, never the ledger.
    let go = entry("golang", "pkg:golang/golang.org/x/text@v0.14.0", vec![]);
    assert!(recover_lock_entry(tmp.path(), &go).await.is_err());
    // Poisoned integrity shapes are rejected.
    let bad = entry(
        "npm",
        "pkg:npm/x@1.0.0",
        vec![rec(
            "npm_lock_entry",
            serde_json::json!({"resolved": "https://x/", "integrity": "lol"}),
        )],
    );
    assert!(recover_lock_entry(tmp.path(), &bad).await.is_err());
}

/// composer dists FREQUENTLY record `shasum: ""` — that common recovery
/// outcome refuses the unverifiable fetch; the gem twin refuses when the
/// recorded checksum line carries no extractable 64-hex sha256.
#[tokio::test]
async fn recover_composer_empty_shasum_and_gem_hexless_checksum_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let composer = entry(
        "composer",
        "pkg:composer/monolog/monolog@2.9.1",
        vec![rec(
            "composer_lock_package",
            serde_json::json!({
                "dist": { "type": "zip", "url": "https://example.com/a.zip", "shasum": "" },
            }),
        )],
    );
    let err = recover_lock_entry(tmp.path(), &composer).await.unwrap_err();
    assert!(
        err.contains("records no shasum"),
        "an empty shasum must refuse the fetch: {err}"
    );

    // The sha256 check precedes gem_remotes, so no Gemfile.lock needed.
    let gem = entry(
        "gem",
        "pkg:gem/rake@13.0.6",
        vec![rec(
            "gemfile_lock_checksum",
            serde_json::json!("  rake (13.0.6) sha256=zz"),
        )],
    );
    let err = recover_lock_entry(tmp.path(), &gem).await.unwrap_err();
    assert!(
        err.contains("has no sha256"),
        "a hex-less checksum line must refuse the fetch: {err}"
    );
}

/// Fragments PRESENT but invalid (non-SRI pnpm integrity, a yarn block
/// with neither SRI nor 40-hex fragment, a malformed berry checksum, a
/// bun tuple without an SRI token) must all fall through to the final
/// fail-closed error — only the no-fragment-at-all path was tested. An
/// empty-name base purl is unparseable outright.
#[tokio::test]
async fn recover_present_but_invalid_npm_fragments_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let nameless = entry("npm", "pkg:npm/@1.0.0", vec![]);
    let err = recover_lock_entry(tmp.path(), &nameless).await.unwrap_err();
    assert!(
        err.contains("unparseable base purl"),
        "an empty-name purl must be rejected: {err}"
    );

    let all_invalid = entry(
        "npm",
        "pkg:npm/x@1.0.0",
        vec![
            rec(
                "pnpm_lock_package",
                serde_json::json!(["    resolution: {integrity: garbage}"]),
            ),
            rec(
                "yarn_lock_block",
                serde_json::json!(["  resolved \"https://x/y.tgz\""]),
            ),
            rec(
                "yarn_berry_lock_entry",
                serde_json::json!(["  checksum: malformed"]),
            ),
            rec(
                "bun_lock_package",
                serde_json::json!("    \"x\": [\"x@1.0.0\", \"\", {}, \"notsri\"],"),
            ),
        ],
    );
    let err = recover_lock_entry(tmp.path(), &all_invalid)
        .await
        .unwrap_err();
    assert!(
        err.contains("no pre-vendor npm registry fragment"),
        "every invalid fragment must fall through to the fail-closed error: {err}"
    );
}
