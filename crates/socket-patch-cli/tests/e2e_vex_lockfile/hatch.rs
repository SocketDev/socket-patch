//! Manifest-less `socket-patch vex` for Hatch 1.x projects, HOSTED and
//! VENDORED. Hatch has no lockfile: the wiring is an exact PEP 508 direct
//! reference (`vexdemo @ <url>#sha256=<hex>`, vendored `vexdemo @
//! {root:uri}/.socket/vendor/pypi/<uuid>/<wheel>#sha256=<hex>`) written by
//! `utils::hatch` into one of the declaration tables Hatch installs from:
//!
//! | flavor | declaration | hosted | vendored |
//! | --- | --- | --- | --- |
//! | `project` | `[project].dependencies` (hatchling backend, `allow-direct-references`) | yes | yes |
//! | `optional` | `[project.optional-dependencies]` + an env `features` selection | yes | yes |
//! | `hatch-toml-env` | `hatch.toml` `[envs.default].dependencies` | yes | yes (needs `hatch` >= 1.2 on PATH) |
//! | `pyproject-env` | `pyproject.toml` `[tool.hatch.envs.default].extra-dependencies` | yes | yes (same) |
//! | `dependency-groups` | PEP 735 `[dependency-groups]` | yes | refused (Hatch does not expand `{root:uri}` there) |
//!
//! Every cell of `vex_pdm_hatch_common` runs per (flavor, mode) — see that
//! module and `e2e_vex_lockfile/pdm.rs` for the list. The vendored re-scan
//! of a LEDGERLESS checkout is the documented Hatch refusal
//! (`pypi_hatch_unsupported`: "Ledgerless direct references and drifted
//! sources are refused", docs/testing/hatch.md): scan exits 1 and so
//! generates no embedded VEX, while standalone `vex` attests that checkout.
//!
//! The real-Hatch counterpart (real `hatch env create`, per Hatch release)
//! is `e2e_vex_build/hatch.rs`.

use crate::vex_pdm_hatch_common;

use vex_pdm_hatch_common::*;

const BUILD: &str =
    "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n";

fn flavors() -> Vec<Flavor> {
    let project = |deps: &str| {
        format!("{BUILD}[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = {deps}\n")
    };
    vec![
        Flavor {
            label: "hatch-project".into(),
            native: vec![("pyproject.toml".into(), project("[\"vexdemo==1.2.3\"]"))],
            hosted: true,
            vendored: true,
        },
        Flavor {
            label: "hatch-optional".into(),
            native: vec![(
                "pyproject.toml".into(),
                format!(
                    "{}\n[project.optional-dependencies]\nfast = [\"vexdemo==1.2.3\"]\n\n\
                     [tool.hatch.envs.default]\nfeatures = [\"fast\"]\n",
                    project("[]")
                ),
            )],
            hosted: true,
            vendored: true,
        },
        Flavor {
            label: "hatch-toml-env".into(),
            native: vec![
                ("pyproject.toml".into(), project("[]")),
                (
                    "hatch.toml".into(),
                    "[envs.default]\ndependencies = [\"vexdemo==1.2.3\"]\n".into(),
                ),
            ],
            hosted: true,
            vendored: true,
        },
        Flavor {
            label: "pyproject-env".into(),
            native: vec![(
                "pyproject.toml".into(),
                format!(
                    "{}\n[tool.hatch.envs.default]\nextra-dependencies = [\"vexdemo==1.2.3\"]\n",
                    project("[]")
                ),
            )],
            hosted: true,
            vendored: true,
        },
        Flavor {
            label: "dependency-groups".into(),
            native: vec![(
                "pyproject.toml".into(),
                format!(
                    "{}\n[dependency-groups]\ndev = [\"vexdemo==1.2.3\"]\n",
                    project("[]")
                ),
            )],
            hosted: true,
            vendored: false,
        },
    ]
}

#[test]
fn a_reference_only_checkout_attests_online() {
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
fn d_reverted_reference_is_unwired_even_with_no_verify() {
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
fn f_record_disagreeing_with_the_reference_is_a_mismatch() {
    f_record_disagreeing_with_the_wiring_is_a_mismatch(&flavors());
}

#[test]
fn g_hosted_installed_tree_states_decide_once_installed() {
    g_hosted_installed_tree_states(&flavors());
}

#[test]
fn g_hosted_pinless_reference_needs_an_installed_tree_to_attest() {
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
fn embedded_rescan_of_a_manifest_less_wired_checkout() {
    embedded_rescan_of_a_manifest_less_checkout(&flavors(), Some("pypi_hatch_unsupported"));
}

#[test]
fn embedded_apply_vex_and_vendor_vex_attest_without_a_manifest() {
    embedded_apply_and_vendor_vex_attest_a_manifest_less_checkout(&flavors());
}

/// Vendored PEP 735 groups are refused before any write (Hatch does not
/// expand `{root:uri}` inside `[dependency-groups]`): the scan fails with
/// `pypi_hatch_unsupported`, the pyproject is byte-identical, and neither
/// the same-run nor a later standalone VEX attests anything.
#[test]
fn vendored_dependency_group_is_refused_and_never_attested() {
    let groups = flavors()
        .into_iter()
        .find(|f| f.label == "dependency-groups")
        .unwrap();
    let (_tmp, cwd) = fresh();
    for (rel, native) in &groups.native {
        put(&cwd, rel, native.as_bytes());
    }
    install(&cwd, ".venv", PRISTINE);
    let api = ScanApi::start(VENDORED_UUID);
    let vex_out = cwd.join("scan.vex.json");
    let (code, env, stderr) = run_scan(
        &cwd,
        &api,
        Mode::Vendored,
        &["--vex", vex_out.to_str().unwrap(), "--vex-product", PRODUCT],
    );
    assert_ne!(code, Some(0), "{env}\n{stderr}");
    let codes: Vec<&str> = env["vendor"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["errorCode"].as_str())
        .collect();
    assert!(codes.contains(&"pypi_hatch_unsupported"), "{env}");
    assert_eq!(
        text(&std::fs::read(cwd.join("pyproject.toml")).unwrap()),
        groups.native[0].1,
        "refused before any write"
    );
    assert!(!vex_out.exists(), "{env}");
    assert!(
        !cwd.join(vendored_wheel_rel()).exists(),
        "no artifact committed"
    );
    std::fs::remove_dir_all(cwd.join(".venv")).unwrap();
    let patch_api = api_with(VENDORED_UUID, PURL);
    let out = vex(&cwd, &vex_run(Some(&patch_api)));
    assert_ne!(out.code, Some(0), "{out}");
    assert_no_statement(&out, "refused group");
}
