//! Manifest-less `socket-patch vex` for PDM (`pdm.lock` + `[tool.pdm]`
//! pyproject), HOSTED and VENDORED, over every lock format the PDM rewriters
//! support — one committed native lock per PDM release
//! (`crates/socket-patch-core/tests/fixtures/pdm-native/<release>.lock`,
//! re-targeted at the fictitious `vexdemo`):
//!
//! | fixture | PDM major | `lock_version` |
//! | --- | --- | --- |
//! | `0.12.3`, `0.12.3-extras` | 0.12 – 1.4 (PDM 1.0 – 1.4 write the same grammar) | 2 (legacy `[metadata.files]`) |
//! | `2.8.2` | 2.8.1 – 2.9 | 4.3 |
//! | `2.10.4` | 2.10 | 4.4 |
//! | `2.11.2` | 2.11 – 2.16 | 4.4.1 |
//! | `2.17.3` | 2.17 – 2.28 | 4.5.0 |
//! | `2.29.2`, `2.29.2-extras` | 2.29+ | 4.5.1 |
//!
//! The identity-losing formats (PDM 1.8 – 1.15 = 3.1, 2.0 – 2.7 = 4.0 – 4.2)
//! are refused by both rewriters and by discovery:
//! [`pdm_identity_losing_lock_formats_never_attest`].
//!
//! The cells (see `vex_pdm_hatch_common`) run for every (release, mode):
//! a) wiring-only checkout attests online; b) `record_unavailable` offline /
//! unreachable / 404 with zero requests offline; c) ledger without manifest
//! attests offline; d) reverted lock is unwired even with `--no-verify`;
//! e) tampered installed tree / wheel member omitted; f) foreign host,
//! root-escaping path and mismatched records never attest; g) hosted
//! installed-tree states (not installed → pin, patched → hashed, pristine →
//! `not_applied`), pinless hosted needs an install, vendored over a pristine
//! venv warns; plus the embedded `scan --redirect|--vendor --vex`,
//! `scan --vendor --detached --vex`, `apply --vex` and `vendor --vex`.
//!
//! The real-PDM counterpart (real `pdm lock` / `pdm sync`, per PDM release)
//! is `e2e_vex_build/pdm.rs`.

use crate::vex_e2e_common;
use crate::vex_pdm_hatch_common;

use std::path::Path;

use vex_e2e_common::VexRun;
use vex_pdm_hatch_common::*;

/// Every lock format the PDM rewriters support (see the module table).
const PDM_RELEASES: [&str; 8] = [
    "0.12.3",
    "0.12.3-extras",
    "2.8.2",
    "2.10.4",
    "2.11.2",
    "2.17.3",
    "2.29.2",
    "2.29.2-extras",
];

/// The PDM releases whose lock format loses url/path candidate identity
/// (`1.15.5` = 3.1, `2.0.3`/`2.1.5` = 4.0, `2.3.4` = 4.1, `2.6.1`/`2.7.4` =
/// 4.2).
const PDM_REFUSED_RELEASES: [&str; 6] = ["1.15.5", "2.0.3", "2.1.5", "2.3.4", "2.6.1", "2.7.4"];

const PYPROJECT: &str = "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.8\"\ndependencies = [\"vexdemo==1.2.3\"]\n\n[tool.pdm]\ndistribution = false\n";

/// The committed native lock PDM `release` generated for urllib3 1.26.18,
/// re-targeted at `vexdemo 1.2.3` (name, version, wheel tag and every
/// integrity-table key follow; the lock grammar is untouched).
fn pdm_lock(release: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../socket-patch-core/tests/fixtures/pdm-native")
        .join(format!("{release}.lock"));
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let lock = raw
        .replace("py2.py3-none-any", "py3-none-any")
        .replace("urllib3", NAME)
        .replace("1.26.18", VERSION);
    assert!(lock.contains(WHEEL), "{release}: {lock}");
    lock
}

fn pdm_pyproject(release: &str) -> String {
    let requirement = if release.ends_with("-extras") {
        "vexdemo[socks]==1.2.3"
    } else {
        "vexdemo==1.2.3"
    };
    PYPROJECT.replace("vexdemo==1.2.3", requirement)
}

fn flavor(release: &str) -> Flavor {
    Flavor {
        label: format!("pdm-{release}"),
        native: vec![
            ("pyproject.toml".into(), pdm_pyproject(release)),
            ("pdm.lock".into(), pdm_lock(release)),
        ],
        hosted: true,
        vendored: true,
    }
}

fn flavors() -> Vec<Flavor> {
    PDM_RELEASES.into_iter().map(flavor).collect()
}

#[test]
fn a_lockfile_only_checkout_attests_online() {
    a_wiring_only_checkout_attests_online(&flavors());
}

#[test]
fn b_no_local_record_offline_is_record_unavailable_without_network() {
    b_no_local_record_is_record_unavailable(&flavors());
}

#[test]
fn c_ledger_or_committed_socket_dir_attests_offline() {
    c_ledger_without_manifest_attests_offline(&flavors());
}

#[test]
fn d_reverted_lockfile_is_unwired_even_with_no_verify() {
    d_reverted_wiring_is_unwired_even_with_no_verify(&flavors());
}

#[test]
fn e_tampered_installed_tree_or_wheel_member_is_omitted() {
    e_tampered_evidence_is_omitted(&flavors());
}

#[test]
fn f_hosted_uuid_on_a_foreign_host_is_not_a_patch_reference() {
    f_hosted_uuid_on_a_foreign_host_is_not_a_reference(&flavors());
}

#[test]
fn f_vendored_path_escaping_the_root_is_not_a_patch_reference() {
    f_vendored_path_escaping_the_root_is_not_a_reference(&flavors());
}

#[test]
fn f_record_disagreeing_with_the_lock_is_a_mismatch() {
    f_record_disagreeing_with_the_wiring_is_a_mismatch(&flavors());
}

#[test]
fn g_hosted_installed_tree_states_decide_once_installed() {
    g_hosted_installed_tree_states(&flavors());
}

#[test]
fn g_hosted_pinless_lock_needs_an_installed_tree() {
    g_hosted_pinless_reference_needs_an_installed_tree(&flavors());
}

#[test]
fn g_vendored_wheel_attests_over_a_pristine_venv_with_a_warning() {
    vex_pdm_hatch_common::g_vendored_attests_over_a_pristine_venv_with_a_warning(&flavors());
}

#[test]
fn embedded_detached_vendor_scan_never_writes_a_manifest() {
    embedded_detached_vendor_scan_attests_without_a_manifest(&flavors());
}

#[test]
fn embedded_rescan_of_a_manifest_less_wired_checkout_attests() {
    embedded_rescan_of_a_manifest_less_checkout(&flavors(), None);
}

#[test]
fn embedded_apply_vex_and_vendor_vex_attest_without_a_manifest() {
    embedded_apply_and_vendor_vex_attest_a_manifest_less_checkout(&flavors());
}

/// PDM 1.8 – 1.15 (3.1) and 2.0 – 2.7 (4.0 – 4.2) lose url/path candidate
/// identity before install: both scans REFUSE (lock byte-identical, no
/// ledger), and a Socket reference hand-spliced into such a lock (the exact
/// fragment the rewriter writes for a supported format) is diagnosed, never
/// attested — the lock is not evidence the installer consumed the patch.
#[test]
fn pdm_identity_losing_lock_formats_never_attest() {
    let supported = wired(&flavor("2.29.2"), Mode::Hosted);
    let hosted_lock = text(&supported.files["pdm.lock"]);
    for release in PDM_REFUSED_RELEASES {
        let refused = flavor(release);
        for mode in [Mode::Hosted, Mode::Vendored] {
            let what = format!("{release}/{mode:?}");
            let (_tmp, cwd) = fresh();
            for (rel, native) in &refused.native {
                put(&cwd, rel, native.as_bytes());
            }
            if mode == Mode::Vendored {
                install(&cwd, ".venv", PRISTINE);
            }
            let api = ScanApi::start(mode.uuid());
            let vex_out = cwd.join("scan.vex.json");
            let (_code, env, stderr) = run_scan(
                &cwd,
                &api,
                mode,
                &["--vex", vex_out.to_str().unwrap(), "--vex-product", PRODUCT],
            );
            assert_eq!(
                text(&std::fs::read(cwd.join("pdm.lock")).unwrap()),
                refused.native[1].1,
                "{what}: a refused format is never rewritten: {env}\n{stderr}"
            );
            assert!(
                !cwd.join(mode.ledger()).exists() || {
                    let ledger: serde_json::Value =
                        serde_json::from_slice(&std::fs::read(cwd.join(mode.ledger())).unwrap())
                            .unwrap();
                    ledger["records"].as_object().is_none_or(|r| r.is_empty())
                        && ledger["entries"].as_object().is_none_or(|e| e.is_empty())
                },
                "{what}: no ledger claim for a refused lock"
            );
            // Nothing was wired, so the same-run VEX (if the scan got that
            // far) attests nothing for the package.
            let doc = std::fs::read(&vex_out)
                .ok()
                .map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).unwrap());
            vex_e2e_common::assert_absent(doc.as_ref(), PURL);
        }

        // The supported format's hosted package unit spliced into the
        // refused lock (only `lock_version` differs).
        let target = refused.native[1]
            .1
            .lines()
            .find(|l| l.starts_with("lock_version"))
            .expect("lock_version line")
            .to_string();
        let spliced = hosted_lock
            .lines()
            .map(|l| {
                if l.starts_with("lock_version") {
                    target.as_str()
                } else {
                    l
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert!(spliced.contains(&hosted_url()), "{release}");
        let (_tmp, cwd) = fresh();
        put(&cwd, "pyproject.toml", refused.native[0].1.as_bytes());
        put(&cwd, "pdm.lock", spliced.as_bytes());
        let api = api_with(HOSTED_UUID, PURL);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_nothing_discovered(&out, &format!("{release} spliced"));
        let warned = out.envelope["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|w| {
                w["code"] == "patched_ref_invalid"
                    && w["detail"].as_str().unwrap_or("").contains(&format!(
                        "lock_version {}",
                        target.split('"').nth(1).unwrap()
                    ))
            });
        assert!(
            warned,
            "{release}: the rejected reference is diagnosed: {out}"
        );
        api.assert_no_requests();
        let out = vex(
            &cwd,
            &VexRun {
                no_verify: true,
                ..vex_run(Some(&api))
            },
        );
        assert_nothing_discovered(&out, &format!("{release} spliced --no-verify"));
    }
}
