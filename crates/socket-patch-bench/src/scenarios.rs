//! The benchmark catalog: which projects are scanned, how.
//!
//! Every package manager gets two scenarios on the default (hosted) mode,
//! the one `socket-patch scan` runs with no flags:
//!
//! - `<pm>/hosted` — a fresh project: crawl, lockfile inventory, batch
//!   query, reference resolution, patch views, and the lockfile rewrite.
//! - `<pm>/rescan` — the same project after a first scan pinned its
//!   patches (the steady state of a CI job that scans on every build):
//!   hosted-pin discovery, update detection, and a no-op redirect.
//!
//! The largest npm project additionally runs as a `--dry-run` (planning
//! without writes), through the public proxy (no token: the free-tier
//! path most users hit, with its own batch size and concurrency), and
//! with simulated network latency (where request concurrency, not local
//! work, decides the wall time).

use std::time::Duration;

use crate::fixtures::{Fixture, Size};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `scan` (hosted, wet) from the pristine project.
    Hosted,
    /// `scan --dry-run` from the pristine project.
    DryRun,
    /// `scan` on a project a previous `scan` already redirected.
    Rescan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// `SOCKET_API_TOKEN` + org: the authenticated API.
    Token,
    /// No token: the public proxy.
    PublicProxy,
}

/// A package manager's fixture generator.
pub struct Pm {
    pub name: &'static str,
    pub description: &'static str,
    /// Packages / patched packages at scale 1.0.
    pub packages: usize,
    pub patched: usize,
    pub build: fn(&mut crate::fixtures::gen::Tree, Size) -> std::io::Result<Fixture>,
}

pub struct Scenario {
    pub name: String,
    pub pm: &'static Pm,
    pub kind: Kind,
    pub auth: Auth,
    pub latency: Duration,
    pub extra_args: Vec<&'static str>,
}

impl Scenario {
    pub fn size(&self, scale: f64) -> Size {
        Size::scaled(self.pm.packages, self.pm.patched, scale)
    }

    /// A filesystem-safe name.
    pub fn slug(&self) -> String {
        self.name.replace('/', "-")
    }

    pub fn description(&self) -> String {
        let what = match self.kind {
            Kind::Hosted => "hosted scan of a fresh project",
            Kind::DryRun => "hosted --dry-run",
            Kind::Rescan => "rescan of an already-redirected project",
        };
        let mut d = format!("{}: {what}", self.pm.description);
        if self.auth == Auth::PublicProxy {
            d.push_str(", public proxy (no token)");
        }
        if !self.latency.is_zero() {
            d.push_str(&format!(
                ", {} ms simulated latency",
                self.latency.as_millis()
            ));
        }
        d
    }
}

pub fn package_managers() -> &'static [Pm] {
    crate::fixtures::ALL
}

/// Every scenario, in run order.
pub fn all() -> Vec<Scenario> {
    let mut out = Vec::new();
    for pm in package_managers() {
        for kind in [Kind::Hosted, Kind::Rescan] {
            let suffix = if kind == Kind::Hosted {
                "hosted"
            } else {
                "rescan"
            };
            out.push(Scenario {
                name: format!("{}/{suffix}", pm.name),
                pm,
                kind,
                auth: Auth::Token,
                latency: Duration::ZERO,
                extra_args: Vec::new(),
            });
        }
    }
    let npm = package_managers()
        .iter()
        .find(|p| p.name == "npm")
        .expect("the npm fixture");
    out.push(Scenario {
        name: "npm/dry-run".into(),
        pm: npm,
        kind: Kind::DryRun,
        auth: Auth::Token,
        latency: Duration::ZERO,
        extra_args: Vec::new(),
    });
    out.push(Scenario {
        name: "npm/public-proxy".into(),
        pm: npm,
        kind: Kind::Hosted,
        auth: Auth::PublicProxy,
        latency: Duration::ZERO,
        extra_args: Vec::new(),
    });
    out.push(Scenario {
        name: "npm/latency".into(),
        pm: npm,
        kind: Kind::Hosted,
        auth: Auth::Token,
        latency: Duration::from_millis(40),
        extra_args: Vec::new(),
    });
    out
}
