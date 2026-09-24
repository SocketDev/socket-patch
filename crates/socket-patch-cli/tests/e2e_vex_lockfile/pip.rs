//! Manifest-less `socket-patch vex` for pip `requirements.txt` projects,
//! HOSTED and VENDORED:
//!
//! | flavor | native pin | hosted | vendored |
//! | --- | --- | --- | --- |
//! | `requirements` | root `vexdemo==1.2.3` | yes | yes |
//! | `requirements-hashes` | `pip-compile --generate-hashes` style (`\` continued `--hash` lines) | yes | yes |
//! | `requirements-marker` | `… ; python_version >= "3.8"` | yes | yes |
//! | `requirements-extras` | `vexdemo[socks]==1.2.3` | yes | refused (`pypi_extras_unsupported`) |
//! | `requirements-crlf` | CRLF file | yes | yes |
//! | `requirements-include` | pin in an in-root `-r requirements/base.txt` | no (root-only rewriter) | yes |
//! | `requirements-include-long` | `--requirement` long form, two levels deep | no | yes |
//!
//! Every cell of `vex_pipenv_pip_common` runs per (flavor, mode) — see that
//! module and `e2e_vex_lockfile/pipenv.rs` for the list. pip-specific cells
//! below: the hosted rewriter's documented root-only limit (an include pin
//! stays on the registry: nothing to attest, never a false attestation),
//! a hand-wired hosted include IS discovered, a sibling
//! `requirements-dev.txt` the root never includes is not read, a
//! commented-out wired line is not wiring, and the vendored extras refusal
//! leaves nothing to attest.
//!
//! The real-pip counterpart (pip 22 / 23 / 24 / 25, real `pip install -r`
//! of the hosted / vendored wheel) is `e2e_vex_build/pip.rs`.

use crate::vex_e2e_common;
use crate::vex_pipenv_pip_common;

use vex_e2e_common::VexRun;
use vex_pipenv_pip_common::*;

fn flavor(label: &str, files: &[(&str, &str)], hosted: bool, vendored: bool) -> Flavor {
    Flavor {
        label: label.into(),
        native: files
            .iter()
            .map(|(rel, body)| (rel.to_string(), body.to_string()))
            .collect(),
        hosted,
        vendored,
        pipenv_major: "2026",
    }
}

fn hashed_pin() -> String {
    format!(
        "vexdemo==1.2.3 \\\n    --hash=sha256:{} \\\n    --hash=sha256:{}\n",
        "a".repeat(64),
        "b".repeat(64)
    )
}

fn flavors() -> Vec<Flavor> {
    let hashed = hashed_pin();
    vec![
        flavor(
            "requirements",
            &[("requirements.txt", "vexdemo==1.2.3\n")],
            true,
            true,
        ),
        flavor(
            "requirements-hashes",
            &[("requirements.txt", &hashed)],
            true,
            true,
        ),
        flavor(
            "requirements-marker",
            &[(
                "requirements.txt",
                "vexdemo==1.2.3 ; python_version >= \"3.8\"\n",
            )],
            true,
            true,
        ),
        flavor(
            "requirements-extras",
            &[("requirements.txt", "vexdemo[socks]==1.2.3\n")],
            true,
            false,
        ),
        flavor(
            "requirements-crlf",
            &[("requirements.txt", "# app deps\r\nvexdemo==1.2.3\r\n")],
            true,
            true,
        ),
        flavor(
            "requirements-include",
            &[
                ("requirements.txt", "-r requirements/base.txt\n"),
                ("requirements/base.txt", "vexdemo==1.2.3\n"),
            ],
            false,
            true,
        ),
        flavor(
            "requirements-include-long",
            &[
                ("requirements.txt", "--requirement requirements/prod.txt\n"),
                ("requirements/prod.txt", "-r base.txt\n"),
                ("requirements/base.txt", "vexdemo==1.2.3\n"),
            ],
            false,
            true,
        ),
    ]
}

#[test]
fn a_wiring_only_checkout_attests_online() {
    vex_pipenv_pip_common::a_wiring_only_checkout_attests_online(&flavors());
}

#[test]
fn b_no_local_record_is_record_unavailable() {
    vex_pipenv_pip_common::b_no_local_record_is_record_unavailable(&flavors());
}

#[test]
fn c_ledger_without_manifest_attests_offline() {
    vex_pipenv_pip_common::c_ledger_without_manifest_attests_offline(&flavors());
}

#[test]
fn d_reverted_wiring_is_unwired_even_with_no_verify() {
    vex_pipenv_pip_common::d_reverted_wiring_is_unwired_even_with_no_verify(&flavors());
}

#[test]
fn e_tampered_evidence_is_omitted() {
    vex_pipenv_pip_common::e_tampered_evidence_is_omitted(&flavors());
}

#[test]
fn f_hosted_uuid_on_a_foreign_host_is_not_a_reference() {
    vex_pipenv_pip_common::f_hosted_uuid_on_a_foreign_host_is_not_a_reference(&flavors());
}

#[test]
fn f_vendored_path_escaping_the_root_is_not_a_reference() {
    vex_pipenv_pip_common::f_vendored_path_escaping_the_root_is_not_a_reference(&flavors());
}

#[test]
fn f_record_disagreeing_with_the_wiring_is_a_mismatch() {
    vex_pipenv_pip_common::f_record_disagreeing_with_the_wiring_is_a_mismatch(&flavors());
}

#[test]
fn g_hosted_installed_tree_states() {
    vex_pipenv_pip_common::g_hosted_installed_tree_states(&flavors());
}

#[test]
fn g_hosted_pinless_reference_needs_an_installed_tree() {
    vex_pipenv_pip_common::g_hosted_pinless_reference_needs_an_installed_tree(&flavors());
}

#[test]
fn g_vendored_attests_over_a_pristine_venv_with_a_warning() {
    vex_pipenv_pip_common::g_vendored_attests_over_a_pristine_venv_with_a_warning(&flavors());
}

#[test]
fn embedded_detached_vendor_scan_attests_without_a_manifest() {
    vex_pipenv_pip_common::embedded_detached_vendor_scan_attests_without_a_manifest(&flavors());
}

#[test]
fn embedded_rescan_of_a_manifest_less_checkout() {
    vex_pipenv_pip_common::embedded_rescan_of_a_manifest_less_checkout(&flavors());
}

#[test]
fn embedded_apply_and_vendor_vex_attest_a_manifest_less_checkout() {
    vex_pipenv_pip_common::embedded_apply_and_vendor_vex_attest_a_manifest_less_checkout(&flavors());
}

// ── pip-specific ──────────────────────────────────────────────────────

/// The hosted requirements rewriter edits only the ROOT `requirements.txt`
/// (`patch::redirect::requirements`), so a pin that lives in an `-r`
/// include is left on the registry and `vex` has nothing to attest — a
/// missed attestation, never a false one. A HAND-wired hosted line inside
/// the include (the rewriter's own grammar) IS discovered: discovery reads
/// the same include walk the vendored planner edits.
#[test]
fn hosted_scan_leaves_a_requirements_include_pin_on_the_registry() {
    for flavor in flavors().into_iter().filter(|f| !f.hosted) {
        let what = &flavor.label;
        let (_tmp, cwd) = fresh();
        for (rel, native) in &flavor.native {
            put(&cwd, rel, native.as_bytes());
        }
        let api = ScanApi::start(HOSTED_UUID);
        let (code, env, stderr) = run_scan(&cwd, &api, &flavor, Mode::Hosted, &[]);
        assert!(
            matches!(code, Some(0) | Some(1)),
            "{what}: scan must not crash: {env}\n{stderr}"
        );
        for (rel, native) in &flavor.native {
            assert_eq!(
                &text(&std::fs::read(cwd.join(rel)).unwrap()),
                native,
                "{what}: {rel} must be untouched by the hosted rewriter"
            );
        }
        let patch_api = api_with(HOSTED_UUID, PURL);
        let out = vex(&cwd, &vex_run(Some(&patch_api)));
        assert_ne!(out.code, Some(0), "{what}: {out}");
        assert_no_statement(&out, what);

        // The deepest include hand-wired in the hosted rewriter's grammar.
        let (_tmp2, cwd2) = fresh();
        for (rel, native) in &flavor.native {
            let body = if native.contains("vexdemo==1.2.3") {
                format!(
                    "vexdemo @ {} --hash=sha256:{}\n",
                    hosted_url(),
                    hosted_sha256()
                )
            } else {
                native.clone()
            };
            put(&cwd2, rel, body.as_bytes());
        }
        assert_ok_attested(
            &vex(&cwd2, &vex_run(Some(&patch_api))),
            Mode::Hosted,
            &format!("{what} hand-wired include"),
        );
    }
}

/// A sibling `requirements-dev.txt` the root never includes is not read:
/// neither writer touches it, pip never installs it from `-r
/// requirements.txt`. A wired line there is not evidence, and it does not
/// gate the live root wiring either.
#[test]
fn sibling_requirements_file_the_root_never_includes_is_not_read() {
    let root = &flavors()[0];
    for mode in [Mode::Hosted, Mode::Vendored] {
        let wired = wired(root, mode);
        let wired_line = text(&wired.files["requirements.txt"]);
        let what = wired.what();

        // Only the sibling carries the wiring: nothing discovered.
        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        put(&cwd, "requirements.txt", b"vexdemo==1.2.3\n");
        put(&cwd, "requirements-dev.txt", wired_line.as_bytes());
        let api = api_with(mode.uuid(), PURL);
        let out = vex(&cwd, &vex_run(Some(&api)));
        assert_nothing_discovered(&out, &format!("{what} sibling only"));

        // Root wired, stale sibling beside it: the root attests.
        put(&cwd, "requirements.txt", wired_line.as_bytes());
        put(&cwd, "requirements-dev.txt", b"vexdemo==1.2.3\n");
        assert_ok_attested(
            &vex(&cwd, &vex_run(Some(&api))),
            mode,
            &format!("{what} root + stale sibling"),
        );
    }
}

/// A wired line commented out (`# vexdemo @ …` / `# ./.socket/vendor/…`)
/// is not something pip installs: not wiring, and with the ledger kept the
/// ledger claim is dead (`redirect_unwired` / `vendor_unwired`), even
/// under `--no-verify`.
#[test]
fn commented_out_wiring_is_not_a_reference() {
    let root = &flavors()[0];
    for mode in [Mode::Hosted, Mode::Vendored] {
        let wired = wired(root, mode);
        let commented: String = text(&wired.files["requirements.txt"])
            .lines()
            .map(|l| format!("# {l}\n"))
            .collect::<String>()
            + "vexdemo==1.2.3\n";
        for keep in [NOTHING, LEDGERS_ONLY] {
            let what = format!("{} commented ledgers={}", wired.what(), keep.ledgers);
            let (_tmp, cwd) = fresh();
            wired.restore(&cwd, keep);
            put(&cwd, "requirements.txt", commented.as_bytes());
            let api = api_with(mode.uuid(), PURL);
            if keep.ledgers {
                for no_verify in [false, true] {
                    let run = VexRun {
                        offline: true,
                        no_verify,
                        ..vex_run(Some(&api))
                    };
                    assert_omitted(&vex(&cwd, &run), mode.unwired(), &what);
                }
            } else {
                assert_nothing_discovered(&vex(&cwd, &vex_run(Some(&api))), &what);
            }
            api.assert_no_requests();
        }
    }
}

/// A vendored wheel path line cannot carry extras: the backend refuses the
/// pin (`pypi_extras_unsupported`), leaves `requirements.txt` untouched and
/// writes no artifact — `vex` has nothing to attest.
#[test]
fn vendored_extras_pin_is_refused_and_nothing_is_attested() {
    let extras = flavors()
        .into_iter()
        .find(|f| f.label == "requirements-extras")
        .unwrap();
    let (_tmp, cwd) = fresh();
    for (rel, native) in &extras.native {
        put(&cwd, rel, native.as_bytes());
    }
    install(&cwd, ".venv", PRISTINE);
    let api = ScanApi::start(VENDORED_UUID);
    let (code, env, stderr) = run_scan(&cwd, &api, &extras, Mode::Vendored, &[]);
    assert_ne!(code, Some(0), "{env}\n{stderr}");
    assert_eq!(
        env["vendor"]["events"][0]["errorCode"], "pypi_extras_unsupported",
        "{env}"
    );
    for (rel, native) in &extras.native {
        assert_eq!(
            &text(&std::fs::read(cwd.join(rel)).unwrap()),
            native,
            "{rel}"
        );
    }
    assert!(!cwd.join(vendored_wheel_rel()).exists());
    std::fs::remove_dir_all(cwd.join(".venv")).unwrap();
    let patch_api = api_with(VENDORED_UUID, PURL);
    let out = vex(&cwd, &vex_run(Some(&patch_api)));
    assert_ne!(out.code, Some(0), "{out}");
    assert_no_statement(&out, "vendored extras");
}
