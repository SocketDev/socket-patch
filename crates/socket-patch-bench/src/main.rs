//! `socket-patch-bench`: benchmark `socket-patch scan` on synthetic
//! projects against a local patch API, and compare two builds.
//!
//! ```text
//! socket-patch-bench list
//! socket-patch-bench run     --bin target/perf/socket-patch
//! socket-patch-bench compare --base /tmp/base/socket-patch --head target/perf/socket-patch
//! socket-patch-bench serve   npm/hosted --bin target/perf/socket-patch
//! ```
//!
//! See README.md for what is measured and how a regression is decided.

mod engine;
mod fixtures;
mod mock;
mod process;
mod report;
mod scenarios;
mod stats;
mod tree;

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use engine::{Binary, Options};
use report::{Report, ScenarioComparison, ScenarioResult};
use stats::{Gate, Verdict};

/// The org slug every authenticated scenario uses.
pub const ORG: &str = "bench-org";

#[derive(Parser)]
#[command(name = "socket-patch-bench", about = "Benchmark `socket-patch scan`")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List the scenarios.
    List,
    /// Time one binary on every selected scenario.
    Run {
        /// The `socket-patch` binary to measure.
        #[arg(long)]
        bin: PathBuf,
        #[command(flatten)]
        common: Common,
    },
    /// Compare two binaries, interleaved on the same machine, and exit 1 on
    /// a regression or a failed validation.
    Compare {
        /// The baseline binary (e.g. built from the PR's base commit).
        #[arg(long)]
        base: PathBuf,
        /// The candidate binary.
        #[arg(long)]
        head: PathBuf,
        /// Relative slowdown that counts as a regression (0.10 = 10%).
        #[arg(long, default_value_t = 0.10)]
        threshold: f64,
        /// Relative peak-RSS growth that counts as a regression.
        #[arg(long, default_value_t = 0.15)]
        rss_threshold: f64,
        /// Extra pairs to run for a scenario that first looks regressed,
        /// before the verdict stands (0 disables the confirmation round).
        #[arg(long, default_value_t = 10)]
        confirm_runs: usize,
        /// Report regressions but exit 0.
        #[arg(long)]
        no_fail: bool,
        #[command(flatten)]
        common: Common,
    },
    /// Build one scenario's fixture, start its mock API, print the command
    /// that scans it, and wait (for profiling a run by hand).
    Serve {
        /// Scenario name (see `list`).
        scenario: String,
        /// Binary named in the printed command.
        #[arg(long, default_value = "target/perf/socket-patch")]
        bin: PathBuf,
        #[arg(long, default_value_t = 1.0)]
        scale: f64,
        /// Where to build the fixture (default: a temp dir).
        #[arg(long)]
        work_dir: Option<PathBuf>,
    },
}

#[derive(Args)]
struct Common {
    /// Only scenarios whose name matches this regex (repeatable).
    #[arg(long = "filter", short = 'f')]
    filters: Vec<String>,
    /// Untimed runs per binary before measuring (warm the page cache).
    #[arg(long, default_value_t = 2)]
    warmup: usize,
    /// Measured runs per binary (`compare` pairs one base run with one
    /// head run).
    #[arg(long, default_value_t = 15)]
    runs: usize,
    /// Multiply every fixture's package count.
    #[arg(long, default_value_t = 1.0)]
    scale: f64,
    /// Where fixtures are built (default: a temp dir, removed at exit).
    #[arg(long)]
    work_dir: Option<PathBuf>,
    /// Write `results.json` and `summary.md` here.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Print every run.
    #[arg(long, short)]
    verbose: bool,
}

fn select(filters: &[String]) -> Result<Vec<scenarios::Scenario>, String> {
    let res: Vec<regex::Regex> = filters
        .iter()
        .map(|f| regex::Regex::new(f).map_err(|e| format!("--filter {f}: {e}")))
        .collect::<Result<_, _>>()?;
    let all = scenarios::all();
    let picked: Vec<_> = all
        .into_iter()
        .filter(|s| res.is_empty() || res.iter().any(|r| r.is_match(&s.name)))
        .collect();
    if picked.is_empty() {
        return Err("no scenario matches the filters (see `socket-patch-bench list`)".into());
    }
    Ok(picked)
}

fn absolute(p: &PathBuf) -> Result<PathBuf, String> {
    std::fs::canonicalize(p).map_err(|e| format!("{}: {e}", p.display()))
}

struct WorkDir {
    path: PathBuf,
    _temp: Option<tempfile::TempDir>,
}

fn work_dir(given: Option<&PathBuf>) -> Result<WorkDir, String> {
    match given {
        Some(p) => {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
            Ok(WorkDir {
                path: absolute(p)?,
                _temp: None,
            })
        }
        None => {
            let t = tempfile::Builder::new()
                .prefix("socket-patch-bench-")
                .tempdir()
                .map_err(|e| e.to_string())?;
            Ok(WorkDir {
                path: absolute(&t.path().to_path_buf())?,
                _temp: Some(t),
            })
        }
    }
}

fn log(line: &str) {
    eprintln!("{line}");
}

fn write_outputs(report: &Report, out: Option<&PathBuf>) -> Result<(), String> {
    let md = report.markdown();
    println!("{md}");
    if let Some(dir) = out {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let json = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("results.json"), json).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("summary.md"), md).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn compare_result(s: &ScenarioResult, gate: Gate, rss_gate: Gate) -> Option<ScenarioComparison> {
    let base = s.binaries.get("base")?;
    let head = s.binaries.get("head")?;
    if base.invalid.is_some() || head.invalid.is_some() || base.samples.len() != head.samples.len()
    {
        return None;
    }
    let wall = stats::compare_paired(&base.wall(), &head.wall(), gate);
    let cpu = match (base.cpu(), head.cpu()) {
        (Some(b), Some(h)) => Some(stats::compare_paired(&b, &h, gate)),
        _ => None,
    };
    let rss = match (base.rss(), head.rss()) {
        (Some(b), Some(h)) => Some(stats::compare_paired(&b, &h, rss_gate)),
        _ => None,
    };
    let request_delta = head.total_requests() as i64 - base.total_requests() as i64;
    let mut reasons = Vec::new();
    if wall.verdict == Verdict::Regression {
        reasons.push(format!("wall time {:+.1}%", (wall.ratio - 1.0) * 100.0));
    }
    if let Some(c) = cpu.as_ref().filter(|c| c.verdict == Verdict::Regression) {
        reasons.push(format!("CPU time {:+.1}%", (c.ratio - 1.0) * 100.0));
    }
    if let Some(c) = rss.as_ref().filter(|c| c.verdict == Verdict::Regression) {
        reasons.push(format!("peak RSS {:+.1}%", (c.ratio - 1.0) * 100.0));
    }
    if request_delta > 0 {
        let mut by_kind = Vec::new();
        let kinds: std::collections::BTreeSet<&String> =
            base.requests.keys().chain(head.requests.keys()).collect();
        for k in kinds {
            let b = base.requests.get(k).copied().unwrap_or(0);
            let h = head.requests.get(k).copied().unwrap_or(0);
            if b != h {
                by_kind.push(format!("{k} {b}→{h}"));
            }
        }
        reasons.push(format!(
            "{request_delta:+} API requests ({})",
            by_kind.join(", ")
        ));
    }
    let verdict = if !reasons.is_empty() {
        Verdict::Regression
    } else if wall.verdict == Verdict::Improvement {
        Verdict::Improvement
    } else if wall.verdict == Verdict::Inconclusive {
        Verdict::Inconclusive
    } else {
        Verdict::Unchanged
    };
    Some(ScenarioComparison {
        wall,
        cpu,
        rss,
        request_delta,
        verdict,
        reasons,
    })
}

fn main_inner() -> Result<i32, String> {
    let cli = Cli::parse();
    match cli.command {
        Cmd::List => {
            for s in scenarios::all() {
                let size = s.size(1.0);
                println!(
                    "{:<22} {:>5} pkgs {:>3} patched  {}",
                    s.name,
                    size.packages,
                    size.patched,
                    s.description()
                );
            }
            Ok(0)
        }
        Cmd::Run { bin, common } => {
            let picked = select(&common.filters)?;
            let work = work_dir(common.work_dir.as_ref())?;
            let opts = Options {
                warmup: common.warmup,
                runs: common.runs,
                scale: common.scale,
                work: work.path.clone(),
                verbose: common.verbose,
            };
            let bins = [Binary {
                label: "bin".into(),
                path: absolute(&bin)?,
            }];
            let mut results = Vec::new();
            for s in &picked {
                results.push(engine::run_scenario(s, &bins, &opts, &mut log)?);
            }
            let report = Report {
                schema: 1,
                mode: "run",
                scale: common.scale,
                threshold: None,
                binaries: BTreeMap::from([("bin".to_string(), bins[0].path.display().to_string())]),
                scenarios: results,
            };
            write_outputs(&report, common.out.as_ref())?;
            Ok(if report.invalid().is_empty() { 0 } else { 1 })
        }
        Cmd::Compare {
            base,
            head,
            threshold,
            rss_threshold,
            confirm_runs,
            no_fail,
            common,
        } => {
            let picked = select(&common.filters)?;
            let work = work_dir(common.work_dir.as_ref())?;
            let mut opts = Options {
                warmup: common.warmup,
                runs: common.runs,
                scale: common.scale,
                work: work.path.clone(),
                verbose: common.verbose,
            };
            let bins = [
                Binary {
                    label: "base".into(),
                    path: absolute(&base)?,
                },
                Binary {
                    label: "head".into(),
                    path: absolute(&head)?,
                },
            ];
            let gate = Gate {
                threshold,
                min_abs_delta: 3.0,
                confidence: 0.95,
            };
            let rss_gate = Gate {
                threshold: rss_threshold,
                min_abs_delta: 1024.0,
                confidence: 0.95,
            };
            let mut results = Vec::new();
            for s in &picked {
                let mut r = engine::run_scenario(s, &bins, &opts, &mut log)?;
                r.comparison = compare_result(&r, gate, rss_gate);
                // A first-round regression gets a second round, and the
                // verdict is taken on all pairs together: one noisy burst
                // on a shared runner must not fail a PR on its own.
                let timing_only = r
                    .comparison
                    .as_ref()
                    .is_some_and(|c| c.verdict == Verdict::Regression && c.request_delta <= 0);
                if timing_only && confirm_runs > 0 {
                    log(&format!(
                        "  {}: looks regressed; confirming with {confirm_runs} more pairs",
                        s.name
                    ));
                    opts.runs = confirm_runs;
                    let more = engine::run_scenario(
                        s,
                        &bins,
                        &Options {
                            warmup: 1,
                            ..opts.clone()
                        },
                        &mut log,
                    )?;
                    opts.runs = common.runs;
                    for (label, extra) in more.binaries {
                        let entry = r.binaries.get_mut(&label).unwrap();
                        if entry.invalid.is_none() {
                            entry.invalid = extra.invalid;
                        }
                        entry.samples.extend(extra.samples);
                    }
                    r.comparison = compare_result(&r, gate, rss_gate);
                }
                if let Some(c) = &r.comparison {
                    log(&format!(
                        "  {}: wall {:+.1}% (base {:.1} ms, head {:.1} ms) → {:?}",
                        s.name,
                        (c.wall.ratio - 1.0) * 100.0,
                        c.wall.base_median,
                        c.wall.head_median,
                        c.verdict
                    ));
                }
                results.push(r);
            }
            let report = Report {
                schema: 1,
                mode: "compare",
                scale: common.scale,
                threshold: Some(threshold),
                binaries: bins
                    .iter()
                    .map(|b| (b.label.clone(), b.path.display().to_string()))
                    .collect(),
                scenarios: results,
            };
            write_outputs(&report, common.out.as_ref())?;
            // A head that fails validation is a broken scan (or a scenario
            // the PR must update); a base that fails it only loses that
            // scenario's comparison.
            let head_invalid = report.invalid().iter().any(|(_, bin, _)| *bin == "head");
            let regressed = !report.regressions().is_empty();
            if head_invalid {
                log("FAIL: the head binary failed scenario validation (see summary)");
            }
            if regressed {
                log(&format!(
                    "{}: {} scenario(s) regressed",
                    if no_fail { "WARN" } else { "FAIL" },
                    report.regressions().len()
                ));
            }
            Ok(if head_invalid || (regressed && !no_fail) {
                1
            } else {
                0
            })
        }
        Cmd::Serve {
            scenario,
            bin,
            scale,
            work_dir: given,
        } => {
            let all = scenarios::all();
            let s = all
                .iter()
                .find(|s| s.name == scenario)
                .ok_or_else(|| format!("no scenario named {scenario} (see `list`)"))?;
            let work = work_dir(given.as_ref())?;
            let opts = Options {
                warmup: 0,
                runs: 0,
                scale,
                work: work.path.clone(),
                verbose: false,
            };
            let p = engine::Prepared::new(s, &opts)?;
            let cmd = p.command(&bin, s.kind == scenarios::Kind::DryRun);
            println!("# {}", s.description());
            println!("# fixture: {}", p.project_dir().display());
            println!("# the mock API serves until Ctrl-C; a wet scan edits the fixture in place.");
            print!("env -i");
            for (k, v) in cmd.get_envs() {
                if let Some(v) = v {
                    print!(
                        " {}={}",
                        k.to_string_lossy(),
                        shell_quote(&v.to_string_lossy())
                    );
                }
            }
            print!(" {}", shell_quote(&cmd.get_program().to_string_lossy()));
            for a in cmd.get_args() {
                print!(" {}", shell_quote(&a.to_string_lossy()));
            }
            println!();
            // Serve until interrupted (Ctrl-C ends the process).
            loop {
                std::thread::park();
            }
        }
    }
}

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || "/._-=:,+@".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn main() {
    let code = match main_inner() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use report::{BinaryResult, Sample};

    const GATE: Gate = Gate {
        threshold: 0.10,
        min_abs_delta: 3.0,
        confidence: 0.95,
    };
    const RSS_GATE: Gate = Gate {
        threshold: 0.15,
        min_abs_delta: 1024.0,
        confidence: 0.95,
    };

    fn binary(wall: &[f64], rss_kib: u64, requests: u64) -> BinaryResult {
        BinaryResult {
            samples: wall
                .iter()
                .map(|w| Sample {
                    wall_ms: *w,
                    cpu_ms: Some(*w * 0.9),
                    max_rss_kib: Some(rss_kib),
                })
                .collect(),
            requests: BTreeMap::from([("batch".to_string(), requests)]),
            max_inflight: 1,
            invalid: None,
        }
    }

    fn scenario(base: BinaryResult, head: BinaryResult) -> ScenarioResult {
        ScenarioResult {
            name: "npm/hosted".into(),
            description: String::new(),
            packages: 1,
            patched: 1,
            args: Vec::new(),
            latency_ms: 0,
            binaries: BTreeMap::from([("base".to_string(), base), ("head".to_string(), head)]),
            comparison: None,
        }
    }

    fn noisy(center: f64) -> Vec<f64> {
        (0..15).map(|i| center + f64::from(i % 5) - 2.0).collect()
    }

    #[test]
    fn identical_timings_are_unchanged() {
        let s = scenario(
            binary(&noisy(200.0), 40_000, 6),
            binary(&noisy(200.0), 40_000, 6),
        );
        let c = compare_result(&s, GATE, RSS_GATE).unwrap();
        assert_eq!(c.verdict, Verdict::Unchanged);
        assert!(c.reasons.is_empty());
    }

    #[test]
    fn a_slower_head_regresses_on_wall_and_cpu() {
        let s = scenario(
            binary(&noisy(200.0), 40_000, 6),
            binary(&noisy(260.0), 40_000, 6),
        );
        let c = compare_result(&s, GATE, RSS_GATE).unwrap();
        assert_eq!(c.verdict, Verdict::Regression);
        assert!(
            c.reasons.iter().any(|r| r.starts_with("wall time +")),
            "{:?}",
            c.reasons
        );
        assert!(
            c.reasons.iter().any(|r| r.starts_with("CPU time +")),
            "{:?}",
            c.reasons
        );
    }

    #[test]
    fn more_requests_regress_even_when_timings_hold() {
        let s = scenario(
            binary(&noisy(200.0), 40_000, 6),
            binary(&noisy(200.0), 40_000, 9),
        );
        let c = compare_result(&s, GATE, RSS_GATE).unwrap();
        assert_eq!(c.verdict, Verdict::Regression);
        assert_eq!(c.request_delta, 3);
        assert_eq!(c.reasons, vec!["+3 API requests (batch 6→9)".to_string()]);
    }

    #[test]
    fn memory_growth_past_its_threshold_regresses() {
        let s = scenario(
            binary(&noisy(200.0), 40_000, 6),
            binary(&noisy(200.0), 52_000, 6),
        );
        let c = compare_result(&s, GATE, RSS_GATE).unwrap();
        assert_eq!(c.verdict, Verdict::Regression);
        assert!(c.reasons[0].starts_with("peak RSS +"), "{:?}", c.reasons);
    }

    #[test]
    fn a_faster_head_is_an_improvement() {
        let s = scenario(
            binary(&noisy(200.0), 40_000, 6),
            binary(&noisy(150.0), 40_000, 5),
        );
        assert_eq!(
            compare_result(&s, GATE, RSS_GATE).unwrap().verdict,
            Verdict::Improvement
        );
    }

    #[test]
    fn an_invalid_side_has_no_comparison() {
        let mut head = binary(&noisy(200.0), 40_000, 6);
        head.invalid = Some("scannedPackages: got 1, want 2".into());
        assert!(compare_result(
            &scenario(binary(&noisy(200.0), 40_000, 6), head),
            GATE,
            RSS_GATE
        )
        .is_none());
    }

    #[test]
    fn every_scenario_has_a_unique_filesystem_safe_name() {
        let all = scenarios::all();
        let mut slugs: Vec<String> = all.iter().map(|s| s.slug()).collect();
        slugs.sort();
        slugs.dedup();
        assert_eq!(slugs.len(), all.len());
        assert!(slugs.iter().all(|s| !s.contains('/')));
        // Every package manager runs a fresh and an already-redirected scan.
        for pm in scenarios::package_managers() {
            for kind in ["hosted", "rescan"] {
                assert!(
                    all.iter().any(|s| s.name == format!("{}/{kind}", pm.name)),
                    "{} {kind}",
                    pm.name
                );
            }
        }
    }
}
