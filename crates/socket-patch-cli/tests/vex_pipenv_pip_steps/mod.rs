//! The manifest-less VEX steps the Pipenv / pip hosted and vendored flows
//! END with (the in-process redirect suites, the real-tool capstones, the
//! production suites): given the committed state a flow produced (and,
//! where the flow installs, the installed tree), each step runs on its own
//! copy of the project:
//!
//! 1. `manifest-deleted`: no `.socket/manifest.json`, ledgers kept, online
//!    → attested with the mode's marker + vuln ids, never a manifest written;
//! 2. `ledgers-deleted`: no manifest, no ledgers → attested from lockfile
//!    discovery + the API record;
//! 3. `offline`: no manifest, no ledgers, `--offline` →
//!    `record_unavailable` (and, against the mock, ZERO requests);
//! 4. `reverted`: the wiring back on the registry, ledgers + artifacts kept
//!    → NOT attested (`redirect_unwired` / `vendor_unwired`), offline and
//!    online, with and without `--no-verify`;
//! 5. `apply-vex`: `apply --vex` on the manifest-less checkout, ledgers
//!    kept, offline → attested.
//!
//! Every step runs on a scoped OS thread, so the helper is callable from
//! `#[tokio::test]`s (the mock patch API owns its own runtime).
//!
//! Pull it in after `vex_e2e_common`:
//!
//! ```ignore
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! #[path = "vex_pipenv_pip_steps/mod.rs"]
//! mod vex_pipenv_pip_steps;
//! ```

#![allow(dead_code)]

use std::path::Path;

use serde_json::Value;

use crate::vex_e2e_common::{
    assert_absent, assert_attested, assert_not_attested, binary, run_vex, strip_ledgers,
    strip_manifest, Marker, PatchApi, VexOutcome, VexRun, VexVia,
};

/// A per-step verdict sink: `(step, passed)`.
pub type StepSink<'a> = &'a (dyn Fn(&str, bool) + Sync);

/// Where the online steps get the patch record from.
pub enum Records {
    /// A mock patch API serving these `(uuid, view)` pairs (the offline
    /// step then also proves zero requests).
    Mock(Vec<(String, Value)>),
    /// A live public proxy (`--proxy-url`), e.g. production.
    Live(String),
}

pub struct Steps<'a> {
    /// Assertion context.
    pub what: String,
    /// The flow's committed (and, where it installs, installed) project.
    pub project: &'a Path,
    pub purl: &'a str,
    pub uuid: &'a str,
    pub marker: Marker,
    /// `(vuln id, aliases)` the document must attest — exactly this set.
    /// `None`: whatever the record carries (live records drift), at least
    /// one statement.
    pub vulns: Option<&'a [(&'a str, &'a [&'a str])]>,
    pub records: Records,
    /// `--patch-server-url` (a mock patch server's hosted references).
    pub patch_server_url: Option<String>,
    pub product: &'a str,
    /// Put the wiring files back to their registry bytes.
    pub revert: &'a (dyn Fn(&Path) + Sync),
    /// Extra child env (crawler inputs such as WORKON_HOME).
    pub envs: Vec<(String, String)>,
    /// Per-step verdict sink (`(step, passed)`), e.g. a results file.
    pub on_step: Option<StepSink<'a>>,
    /// The standalone runs must report exactly one `verified` event (the
    /// installed tree / committed artifact was hash-checked for the purl).
    pub expect_verified: bool,
}

impl Steps<'_> {
    fn unwired(&self) -> &'static str {
        match self.marker {
            Marker::Vendored => "vendor_unwired",
            _ => "redirect_unwired",
        }
    }

    fn run(&self, cwd: &Path, run: VexRun) -> VexOutcome {
        let mut run = VexRun {
            product: Some(self.product.to_string()),
            patch_server_url: self.patch_server_url.clone(),
            ..run
        };
        for (k, v) in &self.envs {
            run = run.env(k.clone(), v.clone());
        }
        run_vex(&binary(), cwd, &run)
    }

    fn assert_attested(&self, out: &VexOutcome, step: &str) {
        assert_eq!(out.code, Some(0), "{} {step}: {out}", self.what);
        let doc = out.doc();
        match self.vulns {
            Some(vulns) => {
                assert_attested(doc, self.purl, self.uuid, self.marker, vulns);
            }
            None => {
                let ids: Vec<(String, Vec<String>)> =
                    crate::vex_e2e_common::statements_for(doc, self.purl)
                        .iter()
                        .map(|st| {
                            (
                                st["vulnerability"]["name"]
                                    .as_str()
                                    .unwrap_or_default()
                                    .to_string(),
                                Vec::new(),
                            )
                        })
                        .collect();
                assert!(
                    !ids.is_empty(),
                    "{} {step}: nothing attested: {out}",
                    self.what
                );
                let borrowed: Vec<(&str, &[&str])> =
                    ids.iter().map(|(id, _)| (id.as_str(), &[][..])).collect();
                assert_attested(doc, self.purl, self.uuid, self.marker, &borrowed);
            }
        }
    }

    fn step(&self, name: &str, f: impl FnOnce()) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        if let Some(sink) = self.on_step {
            sink(name, result.is_ok());
        }
        eprintln!(
            "RESULT {} {name}: {}",
            self.what,
            if result.is_ok() { "pass" } else { "FAIL" }
        );
        if let Err(e) = result {
            std::panic::resume_unwind(e);
        }
    }
}

/// Run every step (see the module docs). Panics on the first failure.
pub fn run_manifestless_steps(s: &Steps<'_>) {
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| steps_inner(s));
        if let Err(e) = handle.join() {
            std::panic::resume_unwind(e);
        }
    });
}

fn steps_inner(s: &Steps<'_>) {
    let scratch = tempfile::tempdir().unwrap();
    let copy = |name: &str| {
        let dir = scratch.path().join(name);
        copy_tree(s.project, &dir);
        dir
    };
    let mock = match &s.records {
        Records::Mock(views) => Some(PatchApi::start(views.clone())),
        Records::Live(_) => None,
    };
    let online = || match (&s.records, &mock) {
        (_, Some(api)) => VexRun::online(api),
        (Records::Live(url), None) => VexRun {
            proxy_url: Some(url.clone()),
            ..VexRun::default()
        },
        _ => unreachable!(),
    };

    s.step("manifest-deleted", || {
        let p = copy("manifest-deleted");
        strip_manifest(&p);
        let out = s.run(&p, online());
        s.assert_attested(&out, "manifest-deleted");
        if s.expect_verified {
            let verified = out.envelope["events"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|e| e["action"] == "verified")
                .count();
            assert_eq!(verified, 1, "{}: {out}", s.what);
        }
        assert!(!p.join(".socket/manifest.json").exists(), "{}", s.what);
    });

    s.step("ledgers-deleted", || {
        let p = copy("ledgers-deleted");
        strip_manifest(&p);
        strip_ledgers(&p);
        let before = mock.as_ref().map(|m| m.view_requests(s.uuid));
        let out = s.run(&p, online());
        s.assert_attested(&out, "ledgers-deleted");
        if let (Some(m), Some(before)) = (&mock, before) {
            assert!(
                m.view_requests(s.uuid) > before,
                "{}: the record must come from the API",
                s.what
            );
        }
    });

    s.step("offline", || {
        let p = copy("offline");
        strip_manifest(&p);
        strip_ledgers(&p);
        let silent = PatchApi::empty();
        let out = s.run(
            &p,
            VexRun {
                offline: true,
                ..VexRun::online(&silent)
            },
        );
        assert_eq!(out.code, Some(1), "{} offline: {out}", s.what);
        assert!(out.doc.is_none(), "{} offline: {out}", s.what);
        assert_not_attested(&out.envelope, s.purl, "record_unavailable");
        silent.assert_no_requests();
    });

    s.step("reverted", || {
        let p = copy("reverted");
        strip_manifest(&p);
        (s.revert)(&p);
        for (offline, no_verify) in [(true, false), (true, true), (false, false), (false, true)] {
            let out = s.run(
                &p,
                VexRun {
                    offline,
                    no_verify,
                    ..online()
                },
            );
            let what = format!(
                "{} reverted offline={offline} no_verify={no_verify}",
                s.what
            );
            assert_eq!(out.code, Some(1), "{what}: {out}");
            assert_absent(out.doc.as_ref(), s.purl);
            assert_not_attested(&out.envelope, s.purl, s.unwired());
        }
    });

    s.step("apply-vex", || {
        let p = copy("apply-vex");
        strip_manifest(&p);
        let silent = PatchApi::empty();
        let out = s.run(
            &p,
            VexRun {
                offline: true,
                ..VexRun::online(&silent)
            }
            .via(VexVia::Apply),
        );
        assert_eq!(out.code, Some(0), "{} apply --vex: {out}", s.what);
        s.assert_attested(&out, "apply-vex");
        assert!(!p.join(".socket/manifest.json").exists(), "{}", s.what);
        silent.assert_no_requests();
    });
}

/// Copy `from` into `to` recursively (symlinks copied as the files they
/// point at; a venv's interpreter links are not needed by VEX).
pub fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        let target = to.join(entry.file_name());
        let meta = std::fs::metadata(&path);
        match meta {
            Ok(m) if m.is_dir() => copy_tree(&path, &target),
            Ok(_) => {
                std::fs::copy(&path, &target).unwrap();
            }
            // A dangling link (a venv's interpreter elsewhere): skip.
            Err(_) => {}
        }
    }
}
