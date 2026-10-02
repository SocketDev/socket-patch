//! Result files: `results.json` (everything, for artifacts and tooling)
//! and `summary.md` (the table CI writes to the job summary).

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::stats::{Comparison, Verdict};

/// One run of one binary on one scenario.
#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub wall_ms: f64,
    pub cpu_ms: Option<f64>,
    pub max_rss_kib: Option<u64>,
}

/// Everything measured for one binary on one scenario.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BinaryResult {
    pub samples: Vec<Sample>,
    /// Mock-API requests per endpoint for one run (identical across runs;
    /// a run that disagrees is a validation failure).
    pub requests: BTreeMap<String, u64>,
    /// Most requests the mock was answering at once (one run).
    pub max_inflight: usize,
    /// The first validation failure, if any (the samples are then not
    /// comparable).
    pub invalid: Option<String>,
}

impl BinaryResult {
    pub fn wall(&self) -> Vec<f64> {
        self.samples.iter().map(|s| s.wall_ms).collect()
    }

    pub fn cpu(&self) -> Option<Vec<f64>> {
        self.samples.iter().map(|s| s.cpu_ms).collect()
    }

    pub fn rss(&self) -> Option<Vec<f64>> {
        self.samples
            .iter()
            .map(|s| s.max_rss_kib.map(|k| k as f64))
            .collect()
    }

    pub fn total_requests(&self) -> u64 {
        self.requests.values().sum()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub name: String,
    pub description: String,
    pub packages: usize,
    pub patched: usize,
    pub args: Vec<String>,
    pub latency_ms: u64,
    /// Keyed `base`/`head` for `compare`, `bin` for `run`.
    pub binaries: BTreeMap<String, BinaryResult>,
    pub comparison: Option<ScenarioComparison>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioComparison {
    pub wall: Comparison,
    pub cpu: Option<Comparison>,
    pub rss: Option<Comparison>,
    /// Requests head made beyond base (positive) or saved (negative).
    pub request_delta: i64,
    pub verdict: Verdict,
    /// Why the verdict is a regression, for the summary.
    pub reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub mode: &'static str,
    pub scale: f64,
    pub threshold: Option<f64>,
    pub binaries: BTreeMap<String, String>,
    pub scenarios: Vec<ScenarioResult>,
}

fn fmt_ms(ms: f64) -> String {
    if ms >= 1000.0 {
        format!("{:.2} s", ms / 1000.0)
    } else {
        format!("{ms:.1} ms")
    }
}

fn fmt_ratio(c: &Comparison) -> String {
    let pct = (c.ratio - 1.0) * 100.0;
    match c.ci {
        Some((lo, hi)) => format!(
            "{pct:+.1}% [{:+.1}, {:+.1}]",
            (lo - 1.0) * 100.0,
            (hi - 1.0) * 100.0
        ),
        None => format!("{pct:+.1}%"),
    }
}

fn verdict_cell(v: Verdict) -> &'static str {
    match v {
        Verdict::Regression => "❌ regression",
        Verdict::Improvement => "✅ faster",
        Verdict::Unchanged => "≈",
        Verdict::Inconclusive => "? inconclusive",
    }
}

impl Report {
    pub fn regressions(&self) -> Vec<&ScenarioResult> {
        self.scenarios
            .iter()
            .filter(|s| {
                s.comparison
                    .as_ref()
                    .is_some_and(|c| c.verdict == Verdict::Regression)
            })
            .collect()
    }

    pub fn invalid(&self) -> Vec<(&ScenarioResult, &str, &str)> {
        let mut out = Vec::new();
        for s in &self.scenarios {
            for (bin, r) in &s.binaries {
                if let Some(why) = &r.invalid {
                    out.push((s, bin.as_str(), why.as_str()));
                }
            }
        }
        out
    }

    pub fn markdown(&self) -> String {
        let mut md = String::new();
        let _ = writeln!(md, "## `socket-patch scan` benchmarks\n");
        for (label, path) in &self.binaries {
            let _ = writeln!(md, "- **{label}**: `{path}`");
        }
        let _ = writeln!(md, "- scale: {}", self.scale);
        if let Some(t) = self.threshold {
            let _ = writeln!(
                md,
                "- gate: median of paired head/base ratios > +{:.0}% with its 95% interval above zero",
                t * 100.0
            );
        }
        md.push('\n');
        if self.mode == "compare" {
            md.push_str(
                "| scenario | pkgs | base wall | head wall | Δ wall [95% CI] | Δ CPU | Δ peak RSS | requests | verdict |\n\
                 |---|---:|---:|---:|---:|---:|---:|---:|---|\n",
            );
            for s in &self.scenarios {
                let (Some(base), Some(head)) = (s.binaries.get("base"), s.binaries.get("head"))
                else {
                    continue;
                };
                let Some(c) = &s.comparison else {
                    let why = head
                        .invalid
                        .as_deref()
                        .or(base.invalid.as_deref())
                        .unwrap_or("");
                    let _ = writeln!(
                        md,
                        "| `{}` | {} | | | | | | | ⚠️ invalid: {} |",
                        s.name,
                        s.packages,
                        why.lines().next().unwrap_or("").replace('|', "\\|")
                    );
                    continue;
                };
                let reqs = if c.request_delta == 0 {
                    format!("{}", head.total_requests())
                } else {
                    format!(
                        "{} → {} ({:+})",
                        base.total_requests(),
                        head.total_requests(),
                        c.request_delta
                    )
                };
                let _ = writeln!(
                    md,
                    "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |",
                    s.name,
                    s.packages,
                    fmt_ms(c.wall.base_median),
                    fmt_ms(c.wall.head_median),
                    fmt_ratio(&c.wall),
                    c.cpu
                        .as_ref()
                        .map(|c| format!("{:+.1}%", (c.ratio - 1.0) * 100.0))
                        .unwrap_or_default(),
                    c.rss
                        .as_ref()
                        .map(|c| format!("{:+.1}%", (c.ratio - 1.0) * 100.0))
                        .unwrap_or_default(),
                    reqs,
                    verdict_cell(c.verdict),
                );
            }
            let regressions = self.regressions();
            if !regressions.is_empty() {
                md.push_str("\n### Regressions\n\n");
                for s in regressions {
                    let reasons = s
                        .comparison
                        .as_ref()
                        .map(|c| c.reasons.join("; "))
                        .unwrap_or_default();
                    let _ = writeln!(md, "- `{}`: {reasons}", s.name);
                }
            }
        } else {
            md.push_str(
                "| scenario | pkgs | patched | median wall | min | max | median CPU | peak RSS | requests |\n\
                 |---|---:|---:|---:|---:|---:|---:|---:|---:|\n",
            );
            for s in &self.scenarios {
                let Some(r) = s.binaries.values().next() else {
                    continue;
                };
                if let Some(why) = &r.invalid {
                    let _ = writeln!(
                        md,
                        "| `{}` | {} | {} | ⚠️ invalid: {} | | | | | |",
                        s.name,
                        s.packages,
                        s.patched,
                        why.lines().next().unwrap_or("").replace('|', "\\|")
                    );
                    continue;
                }
                let wall = r.wall();
                let min = wall.iter().copied().fold(f64::INFINITY, f64::min);
                let max = wall.iter().copied().fold(0.0, f64::max);
                let _ = writeln!(
                    md,
                    "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |",
                    s.name,
                    s.packages,
                    s.patched,
                    fmt_ms(crate::stats::median(&wall)),
                    fmt_ms(min),
                    fmt_ms(max),
                    r.cpu()
                        .map(|c| fmt_ms(crate::stats::median(&c)))
                        .unwrap_or_default(),
                    r.rss()
                        .map(|c| format!("{:.1} MiB", crate::stats::median(&c) / 1024.0))
                        .unwrap_or_default(),
                    r.total_requests(),
                );
            }
        }
        let invalid = self.invalid();
        if !invalid.is_empty() {
            md.push_str("\n### Invalid runs\n\n");
            for (s, bin, why) in invalid {
                let _ = writeln!(
                    md,
                    "- `{}` ({bin}):\n\n```\n{}\n```",
                    s.name,
                    why.trim_end()
                );
            }
        }
        md
    }
}
