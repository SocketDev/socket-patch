//! Run scenarios: build each fixture once, start its mock API, then time
//! the binaries on it with every run starting from the pristine tree.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::fixtures::{Fixture, PATCH_HOST};
use crate::mock::{Catalog, MockApi, Stats};
use crate::report::{BinaryResult, Sample, ScenarioResult};
use crate::scenarios::{Auth, Kind, Scenario};
use crate::tree::{self, Snapshot};

/// A binary under test.
#[derive(Debug, Clone)]
pub struct Binary {
    pub label: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub warmup: usize,
    /// Measured runs per binary.
    pub runs: usize,
    pub scale: f64,
    pub work: PathBuf,
    /// Log every run.
    pub verbose: bool,
}

/// One prepared scenario: fixture on disk, mock running.
pub struct Prepared<'a> {
    pub scenario: &'a Scenario,
    pub fixture: Fixture,
    root: PathBuf,
    pristine: PathBuf,
    work: PathBuf,
    snapshot: Snapshot,
    mock: MockApi,
    capture: PathBuf,
}

pub const TOKEN: &str = "sktsec_benchbenchbenchbenchbenchbenchbenchbenchbenc_api";

impl<'a> Prepared<'a> {
    pub fn new(scenario: &'a Scenario, opts: &Options) -> Result<Self, String> {
        let root = opts.work.join(scenario.slug());
        if root.exists() {
            std::fs::remove_dir_all(&root)
                .map_err(|e| format!("clearing {}: {e}", root.display()))?;
        }
        let pristine = root.join("pristine");
        let work = root.join("work");
        let capture = root.join("capture");
        let tmp = root.join("tmp");
        for d in [&capture, &tmp] {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let size = scenario.size(opts.scale);
        let mut t = crate::fixtures::gen::Tree::new(&pristine).map_err(|e| e.to_string())?;
        let mut fixture = (scenario.pm.build)(&mut t, size)
            .map_err(|e| format!("building the {} fixture: {e}", scenario.pm.name))?;
        // A checkout, like every real project: the repository root (and so
        // the socket.yml lookup) is the project itself.
        t.mkdir(&format!("{}/.git", fixture.project))
            .map_err(|e| e.to_string())?;

        // Artifact URLs embed the mock's address, known only once it
        // listens: rewrite the placeholder in the fixture and the catalog.
        let mock =
            MockApi::start(scenario.latency).map_err(|e| format!("starting the mock API: {e}"))?;
        let host = mock.patch.uri();
        substitute(&pristine, PATCH_HOST, &host).map_err(|e| e.to_string())?;
        for p in &mut fixture.patches {
            replace_in_json(&mut p.reference, PATCH_HOST, &host);
            replace_in_json(&mut p.view, PATCH_HOST, &host);
        }
        let mut catalog = Catalog::new(&fixture.patches, scenario.auth == Auth::Token);
        for (path, body, ty) in &fixture.files {
            catalog.serve_file(path, body.clone(), ty);
        }
        mock.set_catalog(catalog);

        tree::copy_tree(&pristine, &work).map_err(|e| e.to_string())?;
        let snapshot = Snapshot::take(&work).map_err(|e| e.to_string())?;
        Ok(Self {
            scenario,
            fixture,
            root,
            pristine,
            work,
            snapshot,
            mock,
            capture,
        })
    }

    /// Stop the mock and delete the scenario's directory.
    pub fn discard(self) {
        let root = self.root.clone();
        drop(self);
        let _ = std::fs::remove_dir_all(root);
    }

    pub fn project_dir(&self) -> PathBuf {
        self.work.join(self.fixture.project)
    }

    /// The exact command a run executes (also printed by `serve`).
    pub fn command(&self, bin: &Path, dry_run: bool) -> Command {
        let mut cmd = Command::new(bin);
        let project = self.project_dir();
        cmd.current_dir(&project);
        cmd.env_clear();
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        cmd.args(self.args(dry_run));
        cmd.arg("--cwd").arg(&project);
        cmd
    }

    pub fn args(&self, dry_run: bool) -> Vec<String> {
        let mut args: Vec<String> = vec!["scan".into(), "--json".into()];
        if dry_run {
            args.push("--dry-run".into());
        }
        args.extend(self.scenario.extra_args.iter().map(|s| s.to_string()));
        args
    }

    pub fn env(&self) -> Vec<(String, String)> {
        let home = self.work.join("home");
        let tmp = self.root.join("tmp");
        let mut env: Vec<(String, String)> = vec![
            // Only the variables below: nothing from the runner's
            // environment (a stray SOCKET_*, npm_config_*, VIRTUAL_ENV,
            // GOFLAGS, ...) can change what the CLI does.
            ("PATH".into(), std::env::var("PATH").unwrap_or_default()),
            ("HOME".into(), home.display().to_string()),
            ("USERPROFILE".into(), home.display().to_string()),
            (
                "XDG_CONFIG_HOME".into(),
                home.join(".config").display().to_string(),
            ),
            (
                "XDG_CACHE_HOME".into(),
                home.join(".cache").display().to_string(),
            ),
            (
                "XDG_DATA_HOME".into(),
                home.join(".local/share").display().to_string(),
            ),
            ("TMPDIR".into(), tmp.display().to_string()),
            // The policy lookup never walks out of the fixture (into a
            // checkout the work dir happens to sit in).
            (
                "GIT_CEILING_DIRECTORIES".into(),
                self.work.display().to_string(),
            ),
            ("LANG".into(), "C.UTF-8".into()),
            ("SOCKET_API_URL".into(), self.mock.api.uri()),
            ("SOCKET_PROXY_URL".into(), self.mock.proxy.uri()),
            ("SOCKET_PATCH_SERVER_URL".into(), self.mock.patch.uri()),
            ("SOCKET_NO_CONFIG".into(), "1".into()),
            ("SOCKET_NO_UPDATE_CHECK".into(), "1".into()),
            ("SOCKET_TELEMETRY_DISABLED".into(), "1".into()),
            // Anything that is not the mock goes to a closed port, so a
            // run that reaches for the real network fails (and fails
            // validation) instead of timing the internet.
            ("HTTP_PROXY".into(), "http://127.0.0.1:9".into()),
            ("HTTPS_PROXY".into(), "http://127.0.0.1:9".into()),
            ("ALL_PROXY".into(), "http://127.0.0.1:9".into()),
            ("NO_PROXY".into(), "127.0.0.1,localhost".into()),
        ];
        if let Auth::Token = self.scenario.auth {
            env.push(("SOCKET_API_TOKEN".into(), TOKEN.into()));
            env.push(("SOCKET_ORG_SLUG".into(), crate::ORG.into()));
        }
        for (k, rel) in &self.fixture.env_paths {
            env.push((k.to_string(), self.work.join(rel).display().to_string()));
        }
        for (k, v) in &self.fixture.env {
            env.push((k.to_string(), v.clone()));
        }
        env
    }

    /// One measured run of `bin`, from the pristine tree. Untimed
    /// preparation (a rescan's first scan) and the restore afterwards are
    /// outside the measurement.
    pub fn run_once(&mut self, bin: &Path) -> Result<(Sample, Stats, Vec<String>), String> {
        if self.scenario.kind == Kind::Rescan {
            let prep = crate::process::run(self.command(bin, false), &self.capture)
                .map_err(|e| format!("spawning {}: {e}", bin.display()))?;
            let stats = self.mock.take_stats();
            validate(self, &prep, &stats, Kind::Hosted)
                .map_err(|e| format!("the rescan's preparatory scan failed validation: {e}"))?;
        }
        self.mock.take_stats();
        let dry = self.scenario.kind == Kind::DryRun;
        let outcome = crate::process::run(self.command(bin, dry), &self.capture)
            .map_err(|e| format!("spawning {}: {e}", bin.display()))?;
        let stats = self.mock.take_stats();
        let checked = validate(self, &outcome, &stats, self.scenario.kind);
        let drift = tree::restore(&self.work, &self.pristine, &mut self.snapshot)
            .map_err(|e| format!("restoring the fixture: {e}"))?;
        let codes = checked?;
        check_drift(self, &drift)?;
        let u = outcome.usage;
        Ok((
            Sample {
                wall_ms: u.wall.as_secs_f64() * 1000.0,
                cpu_ms: u.cpu.map(|c| c.as_secs_f64() * 1000.0),
                max_rss_kib: u.max_rss_kib,
            },
            stats,
            codes,
        ))
    }
}

/// Rewrite `from` → `to` in every regular file under `root`.
fn substitute(root: &Path, from: &str, to: &str) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            substitute(&entry.path(), from, to)?;
        } else if ty.is_file() {
            let bytes = std::fs::read(entry.path())?;
            if let Ok(s) = std::str::from_utf8(&bytes) {
                if s.contains(from) {
                    std::fs::write(entry.path(), s.replace(from, to))?;
                }
            }
        }
    }
    Ok(())
}

fn replace_in_json(v: &mut Value, from: &str, to: &str) {
    match v {
        Value::String(s) if s.contains(from) => *s = s.replace(from, to),
        Value::Array(a) => a.iter_mut().for_each(|x| replace_in_json(x, from, to)),
        Value::Object(o) => o.values_mut().for_each(|x| replace_in_json(x, from, to)),
        _ => {}
    }
}

fn warning_codes(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Check that a run did the work the fixture calls for. Any mismatch makes
/// the sample meaningless, so it is an error, not a footnote.
fn validate(
    p: &Prepared<'_>,
    o: &crate::process::Outcome,
    stats: &Stats,
    kind: Kind,
) -> Result<Vec<String>, String> {
    let stderr = String::from_utf8_lossy(&o.stderr);
    let tail = |s: &str| -> String {
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(15)..].join("\n")
    };
    if !stats.unexpected.is_empty() {
        let shown: Vec<&String> = stats.unexpected.iter().take(3).collect();
        return Err(format!(
            "the CLI made {} request(s) the mock does not serve, e.g. {shown:?}",
            stats.unexpected.len()
        ));
    }
    if o.code != Some(0) {
        return Err(format!(
            "exit code {:?}\nstderr:\n{}\nstdout:\n{}",
            o.code,
            tail(&stderr),
            tail(&String::from_utf8_lossy(&o.stdout))
        ));
    }
    let v: Value = serde_json::from_slice(&o.stdout).map_err(|e| {
        format!(
            "stdout is not one JSON document ({e})\nstderr:\n{}",
            tail(&stderr)
        )
    })?;
    let e = &p.fixture.expect;
    let want_patched: std::collections::BTreeSet<&str> =
        p.fixture.patches.iter().map(|x| x.purl.as_str()).collect();
    let (scanned, lockfile_only) = if kind == Kind::Rescan {
        (e.scanned + e.rescan_extra_scanned, e.rescan_lockfile_only)
    } else {
        (e.scanned, e.lockfile_only)
    };
    let checks: [(&str, Value, Value); 5] = [
        ("status", v["status"].clone(), "success".into()),
        (
            "scannedPackages",
            v["scannedPackages"].clone(),
            scanned.into(),
        ),
        (
            "lockfileOnlyPackages",
            v["lockfileOnlyPackages"].clone(),
            lockfile_only.into(),
        ),
        (
            "packagesWithPatches",
            v["packagesWithPatches"].clone(),
            want_patched.len().into(),
        ),
        (
            "totalPatches",
            v["totalPatches"].clone(),
            p.fixture.patches.len().into(),
        ),
    ];
    for (field, got, want) in checks {
        if got != want {
            return Err(format!("{field}: got {got}, want {want}"));
        }
    }
    let mut codes = warning_codes(&v["warnings"]);
    let redirect = &v["redirect"];
    codes.extend(warning_codes(&redirect["warnings"]));
    let unexpected: Vec<&String> = codes
        .iter()
        .filter(|c| !e.allowed_warnings.contains(&c.as_str()))
        .collect();
    if !unexpected.is_empty() {
        return Err(format!(
            "unexpected warnings {unexpected:?}: {}",
            serde_json::to_string(&v["warnings"]).unwrap_or_default()
                + &serde_json::to_string(&redirect["warnings"]).unwrap_or_default()
        ));
    }
    let skipped = redirect["skipped"].as_array().map(Vec::len).unwrap_or(0);
    if skipped > 0 {
        return Err(format!(
            "redirect skipped packages: {}",
            redirect["skipped"]
        ));
    }
    let rewritten: Vec<String> = {
        let mut r: Vec<String> = redirect["rewrittenFiles"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        r.sort();
        r
    };
    let mut want_rewritten = e.rewritten.clone();
    want_rewritten.sort();
    match kind {
        Kind::Hosted | Kind::DryRun => {
            if redirect["redirected"] != e.redirected {
                return Err(format!(
                    "redirect.redirected: got {}, want {}",
                    redirect["redirected"], e.redirected
                ));
            }
            if rewritten != want_rewritten {
                return Err(format!(
                    "redirect.rewrittenFiles: got {rewritten:?}, want {want_rewritten:?}"
                ));
            }
        }
        Kind::Rescan => {
            // Everything is already pinned: a second scan finds the same
            // patches and has nothing left to rewrite.
            if !rewritten.is_empty() {
                return Err(format!("a rescan rewrote {rewritten:?}"));
            }
            let already = &v["rollout"]["counts"]["already"];
            if *already != want_patched.len() {
                return Err(format!(
                    "rollout.counts.already: got {already}, want {}",
                    want_patched.len()
                ));
            }
        }
    }
    codes.sort();
    codes.dedup();
    Ok(codes)
}

/// A dry run must not write; a hosted run must write exactly where it says.
fn check_drift(p: &Prepared<'_>, drift: &tree::Drift) -> Result<(), String> {
    let project = Path::new(p.fixture.project);
    let touched = drift.touched();
    match p.scenario.kind {
        Kind::DryRun if !drift.is_empty() => Err(format!("a --dry-run changed {touched:?}")),
        Kind::Hosted => {
            for f in &p.fixture.expect.rewritten {
                let rel = project.join(f);
                if !touched.contains(&rel) {
                    return Err(format!(
                        "{} was reported rewritten but is unchanged",
                        rel.display()
                    ));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Run every binary on one scenario, interleaved, and collect results.
pub fn run_scenario(
    scenario: &Scenario,
    bins: &[Binary],
    opts: &Options,
    log: &mut dyn FnMut(&str),
) -> Result<ScenarioResult, String> {
    let setup = std::time::Instant::now();
    let mut p = Prepared::new(scenario, opts)?;
    log(&format!(
        "{}: {} packages, {} patched (fixture built in {:.1}s)",
        scenario.name,
        p.fixture.expect.scanned,
        p.fixture.patches.len(),
        setup.elapsed().as_secs_f64()
    ));
    let mut results: BTreeMap<String, BinaryResult> = bins
        .iter()
        .map(|b| (b.label.clone(), BinaryResult::default()))
        .collect();

    for _ in 0..opts.warmup {
        for b in bins {
            let r = results.get_mut(&b.label).unwrap();
            if r.invalid.is_some() {
                continue;
            }
            if let Err(e) = p.run_once(&b.path) {
                r.invalid = Some(e);
            }
        }
    }
    for i in 0..opts.runs {
        // Alternate the order (ABBA...) so slow drift of the machine does
        // not always favor whichever binary runs first.
        let order: Vec<&Binary> = if i % 2 == 0 {
            bins.iter().collect()
        } else {
            bins.iter().rev().collect()
        };
        for b in order {
            let r = results.get_mut(&b.label).unwrap();
            if r.invalid.is_some() {
                continue;
            }
            match p.run_once(&b.path) {
                Ok((sample, stats, codes)) => {
                    if r.samples.is_empty() {
                        r.requests = stats.by_kind.clone();
                        r.max_inflight = stats.max_inflight;
                        if opts.verbose {
                            log(&format!(
                                "  {:<5} requests {:?}, warnings {codes:?}",
                                b.label, stats.by_kind
                            ));
                        }
                    } else if r.requests != stats.by_kind {
                        r.invalid = Some(format!(
                            "request counts changed between runs: {:?} then {:?}",
                            r.requests, stats.by_kind
                        ));
                        continue;
                    }
                    if opts.verbose {
                        log(&format!(
                            "  {:<5} run {:>2}: {:8.1} ms wall, {:8.1} ms cpu, {} requests",
                            b.label,
                            r.samples.len() + 1,
                            sample.wall_ms,
                            sample.cpu_ms.unwrap_or(f64::NAN),
                            stats.total()
                        ));
                    }
                    r.samples.push(sample);
                }
                Err(e) => r.invalid = Some(e),
            }
        }
    }
    let mut keep = false;
    for (label, r) in &results {
        if let Some(why) = &r.invalid {
            log(&format!(
                "  {label}: INVALID: {}",
                why.lines().next().unwrap_or("")
            ));
            keep = true;
        }
    }
    let args = p.args(scenario.kind == Kind::DryRun);
    let (packages, patched) = (p.fixture.expect.scanned, p.fixture.patches.len());
    // A finished scenario's tree is ~10^4 files; only a failed one is worth
    // keeping (to rerun the logged command by hand).
    if keep {
        log(&format!(
            "  fixture kept for inspection: {}",
            p.project_dir().display()
        ));
    } else {
        p.discard();
    }
    Ok(ScenarioResult {
        name: scenario.name.clone(),
        description: scenario.description(),
        packages,
        patched,
        args,
        latency_ms: scenario.latency.as_millis() as u64,
        binaries: results,
        comparison: None,
    })
}
