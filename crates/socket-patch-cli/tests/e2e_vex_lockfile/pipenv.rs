//! Manifest-less `socket-patch vex` for Pipenv projects (`Pipfile` +
//! `Pipfile.lock`), HOSTED and VENDORED, every reference shape the writers
//! emit:
//!
//! | flavor | lock shape | hosted | vendored |
//! | --- | --- | --- | --- |
//! | `pipenv` | `default` entry (Pipenv 2018+ installer: `file`) | yes | yes (`file`) |
//! | `pipenv-develop` | `develop` entry (`[dev-packages]`) | yes | yes |
//! | `pipenv-category` | custom Pipfile category (Pipenv 2022+) | yes | yes |
//! | `pipenv-extras` | entry with `extras` | yes | yes (`path`: Pipenv drops extras on `file`) |
//! | `pipenv-crlf` | CRLF Pipfile + lock | yes | yes |
//! | `pipenv-legacy-11` | Pipenv 7–11 installer (`SOCKET_PIPENV_MAJOR=11`) | yes (`path`) | refused |
//!
//! Every cell of `vex_pipenv_pip_common` runs per (flavor, mode): wiring
//! alone attests online; `--offline` / unreachable / 404 / 403 with no
//! local record is `record_unavailable` (zero requests offline); ledger-only
//! attests offline; a reverted lock is `redirect_unwired` /
//! `vendor_unwired` under `--no-verify` too; tampered installed tree /
//! wheel member is omitted; foreign-host, root-escaping and
//! record-mismatched references never attest; hosted not-installed attests
//! from the pin, a pristine install is `not_applied`, pinless needs an
//! install; a vendored wheel over a pristine venv warns; and the embedded
//! forms (`scan --redirect --vex` / `scan --vendor --vex` re-runs,
//! `scan --vendor --detached --vex`, `apply --vex`, `vendor --vex`).
//!
//! Pipenv-specific cells below: a relock that re-serializes AROUND our
//! reference (Pipenv 2023+ restores `version` / `index` / registry
//! `hashes`) still attests unless the restored version disagrees, in which
//! case even the ledger claim is dead; an entry carrying both `file` and
//! `path` is ambiguous; and the vendored backend refusing a legacy installer
//! leaves nothing to attest.
//!
//! The real-Pipenv counterpart (every calendar major 2022..2026, real
//! `pipenv install --deploy` of the hosted / vendored wheel) is
//! `e2e_vex_build/pipenv.rs`.

use crate::vex_e2e_common;
use crate::vex_pipenv_pip_common;

use serde_json::Value;
use vex_e2e_common::VexRun;
use vex_pipenv_pip_common::*;

fn flavor(
    label: &str,
    pipfile: String,
    lock: String,
    vendored: bool,
    major: &'static str,
) -> Flavor {
    Flavor {
        label: label.into(),
        native: vec![("Pipfile".into(), pipfile), ("Pipfile.lock".into(), lock)],
        hosted: true,
        vendored,
        pipenv_major: major,
    }
}

fn flavors() -> Vec<Flavor> {
    let crlf = |s: &str| s.replace('\n', "\r\n");
    vec![
        flavor(
            "pipenv",
            PIPFILE.into(),
            pipfile_lock("default", None),
            true,
            "2026",
        ),
        flavor(
            "pipenv-develop",
            PIPFILE.replace(
                "[packages]\nvexdemo = \"==1.2.3\"\n\n[dev-packages]\n",
                "[packages]\n\n[dev-packages]\nvexdemo = \"==1.2.3\"\n",
            ),
            pipfile_lock("develop", None),
            true,
            "2026",
        ),
        flavor(
            "pipenv-category",
            PIPFILE.replace(
                "[packages]\nvexdemo = \"==1.2.3\"\n",
                "[packages]\n\n[tests]\nvexdemo = \"==1.2.3\"\n",
            ),
            pipfile_lock("tests", None),
            true,
            "2026",
        ),
        flavor(
            "pipenv-extras",
            PIPFILE.replace(
                "vexdemo = \"==1.2.3\"",
                "vexdemo = {version = \"==1.2.3\", extras = [\"socks\"]}",
            ),
            pipfile_lock("default", Some(&["socks"])),
            true,
            "2026",
        ),
        flavor(
            "pipenv-crlf",
            crlf(PIPFILE),
            crlf(&pipfile_lock("default", None)),
            true,
            "2026",
        ),
        flavor(
            "pipenv-legacy-11",
            PIPFILE.into(),
            pipfile_lock("default", None),
            false,
            "11",
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

// ── Pipenv-specific ───────────────────────────────────────────────────

/// Rewrite the `vexdemo` entry of every lock category through `edit`.
fn edit_entry(lock: &str, edit: impl Fn(&mut serde_json::Map<String, Value>)) -> String {
    let crlf = lock.contains("\r\n");
    let mut json: Value = serde_json::from_str(lock).unwrap();
    let mut edited = false;
    for (key, section) in json.as_object_mut().unwrap() {
        if key == "_meta" {
            continue;
        }
        if let Some(entry) = section.get_mut(NAME).and_then(Value::as_object_mut) {
            edit(entry);
            edited = true;
        }
    }
    assert!(edited, "no {NAME} entry in {lock}");
    let out = format!("{}\n", serde_json::to_string_pretty(&json).unwrap());
    if crlf {
        out.replace('\n', "\r\n")
    } else {
        out
    }
}

/// A Pipenv 2023+ relock of a redirected lock keeps our `file` reference
/// but restores the registry `version` / `index` / `hashes` around it
/// (`reserialized_around_reference`). Pipenv still installs the reference,
/// so it is still wired: attested with no ledger. When the restored
/// `version` names ANOTHER release the entry is diagnosed, and the stale
/// ledger claim dies with it (discover rule 11: a recognized-but-rejected
/// mention is authoritative), `--no-verify` included.
#[test]
fn relock_reserialized_around_the_reference_attests_unless_the_version_disagrees() {
    for flavor in flavors().into_iter().filter(|f| f.pipenv_major == "2026") {
        let wired = wired(&flavor, Mode::Hosted);
        let what = wired.what();
        let lock = text(&wired.files["Pipfile.lock"]);
        let hybrid = |version: &'static str| {
            edit_entry(&lock, move |entry| {
                entry.insert("version".into(), Value::String(format!("=={version}")));
                entry.insert("index".into(), Value::String("pypi".into()));
                entry.insert(
                    "hashes".into(),
                    serde_json::json!([
                        format!("sha256:{}", "a".repeat(64)),
                        format!("sha256:{}", "b".repeat(64))
                    ]),
                );
            })
        };

        let (_tmp, cwd) = fresh();
        wired.restore(&cwd, NOTHING);
        put(&cwd, "Pipfile.lock", hybrid(VERSION).as_bytes());
        let api = api_with(HOSTED_UUID, PURL);
        assert_ok_attested(
            &vex(&cwd, &vex_run(Some(&api))),
            Mode::Hosted,
            &format!("{what} hybrid"),
        );

        for keep in [NOTHING, LEDGERS_ONLY] {
            let (_tmp, cwd) = fresh();
            wired.restore(&cwd, keep);
            put(&cwd, "Pipfile.lock", hybrid("9.9.9").as_bytes());
            for no_verify in [false, true] {
                let run = VexRun {
                    no_verify,
                    offline: keep.ledgers,
                    ..vex_run(Some(&api))
                };
                let out = vex(&cwd, &run);
                let what = format!(
                    "{what} hybrid@9.9.9 ledgers={} no_verify={no_verify}",
                    keep.ledgers
                );
                assert_ne!(out.code, Some(0), "{what}: {out}");
                assert_no_statement(&out, &what);
                if keep.ledgers {
                    assert_omitted(&out, "redirect_unwired", &what);
                }
            }
        }
    }
}

/// An entry carrying BOTH `file` and `path` (neither writer produces one)
/// is ambiguous — which one Pipenv reads depends on its release — so it is
/// diagnosed, never attested, and it kills the stale ledger claim.
#[test]
fn entry_with_both_file_and_path_is_ambiguous() {
    let flavor = &flavors()[0];
    for mode in [Mode::Hosted, Mode::Vendored] {
        let wired = wired(flavor, mode);
        let lock = text(&wired.files["Pipfile.lock"]);
        let both = edit_entry(&lock, |entry| {
            let (have, add) = if entry.contains_key("file") {
                ("file", "path")
            } else {
                ("path", "file")
            };
            let value = entry[have].clone();
            entry.insert(add.into(), value);
        });
        for keep in [NOTHING, LEDGERS_ONLY] {
            let what = format!("{} both keys ledgers={}", wired.what(), keep.ledgers);
            let (_tmp, cwd) = fresh();
            wired.restore(&cwd, keep);
            put(&cwd, "Pipfile.lock", both.as_bytes());
            let api = api_with(mode.uuid(), PURL);
            for no_verify in [false, true] {
                let run = VexRun {
                    no_verify,
                    ..vex_run(Some(&api))
                };
                let out = vex(&cwd, &run);
                assert_ne!(out.code, Some(0), "{what}: {out}");
                assert_no_statement(&out, &what);
                if keep.ledgers {
                    assert_omitted(&out, mode.unwired(), &what);
                }
            }
        }
    }
}

/// Vendored wheel references need Pipenv 2018+: against a 7–11 installer
/// the backend refuses (`pypi_pipenv_installer_unsupported`), leaves the
/// lock untouched, writes no artifact — and `vex` has nothing to attest.
#[test]
fn vendored_legacy_installer_is_refused_and_nothing_is_attested() {
    let legacy = flavors()
        .into_iter()
        .find(|f| f.pipenv_major == "11")
        .unwrap();
    let (_tmp, cwd) = fresh();
    for (rel, native) in &legacy.native {
        put(&cwd, rel, native.as_bytes());
    }
    install(&cwd, ".venv", PRISTINE);
    let api = ScanApi::start(VENDORED_UUID);
    let vex_out = cwd.join("scan.vex.json");
    let (code, env, stderr) = run_scan(
        &cwd,
        &api,
        &legacy,
        Mode::Vendored,
        &["--vex", vex_out.to_str().unwrap(), "--vex-product", PRODUCT],
    );
    assert_ne!(code, Some(0), "{env}\n{stderr}");
    assert!(
        env.to_string()
            .contains("pypi_pipenv_installer_unsupported"),
        "{env}"
    );
    assert!(!vex_out.exists(), "no VEX on a refused scan: {env}");
    for (rel, native) in &legacy.native {
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
    assert_no_statement(&out, "legacy vendored");
}
