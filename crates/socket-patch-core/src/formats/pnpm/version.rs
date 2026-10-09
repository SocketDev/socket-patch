//! Which pnpm a project runs, as far as its files say, and whether that
//! pnpm breaks on a root-only `pnpm-workspace.yaml` (#734).
//!
//! pnpm 9.0.0 through 10.4.x treat any pnpm-workspace.yaml as a workspace
//! whose root is the workspace dir, so after one is created for a
//! single-package project, `pnpm add <pkg>` refuses with
//! ERR_PNPM_ADDING_TO_ROOT unless it is given `-w`. 10.5.0 is the first
//! release that adds at the root of a root-only workspace (measured on
//! 9.0.0, 9.7.1, 9.15.9, 10.0.0–10.4.1 failing and 10.5.0+ passing). Those
//! versions also read nothing the modes would write there: `trustLockfile`
//! is a pnpm >= 11 setting, and `overrides:` in pnpm-workspace.yaml is read
//! from 10.5 on (older ones read package.json `pnpm.overrides`).
//!
//! The evidence is read conservatively, because a wrong "skip" loses a
//! setting pnpm >= 11 needs: every present source must pin pnpm inside
//! 9.0–10.4. A source that names a later pnpm, a range reaching past 10.4,
//! one that does not parse, or no source at all keeps the file. The sources
//! are the installed `node_modules/.modules.yaml` `packageManager` (the pnpm
//! that last installed) and package.json `packageManager`,
//! `devEngines.packageManager` and `engines.pnpm`; a pin for another tool
//! is no evidence either way.

use crate::formats::text::strip_bom;
use crate::utils::package_manager::pinned_version;

/// `(major, minor)`; patch levels never matter here.
type MajorMinor = (u64, u64);

/// The pnpm releases that refuse `pnpm add` in a root-only workspace.
fn breaks_root_only_workspace((lo, hi): (MajorMinor, MajorMinor)) -> bool {
    lo >= (9, 0) && hi < (10, 5)
}

/// The inclusive `(major, minor)` span a version spec admits: an exact
/// version (`9.15.9`, `=9.15.9`, `v9.15.9`, a prerelease), `^X.Y.Z`,
/// `~X.Y.Z`, or a wildcard (`9`, `9.x`, `10.4.x`, `9.*`). `None` for
/// anything else (comparators, unions, hyphen ranges, junk).
fn version_span(spec: &str) -> Option<(MajorMinor, MajorMinor)> {
    let spec = spec.trim();
    let (op, rest) = match spec.as_bytes().first()? {
        b'^' => ('^', &spec[1..]),
        b'~' => ('~', &spec[1..]),
        b'=' => ('=', &spec[1..]),
        _ => ('=', spec),
    };
    let rest = rest.strip_prefix('v').unwrap_or(rest);
    let core = rest.split(['-', '+']).next()?;
    let wild = |part: &str| matches!(part, "x" | "X" | "*");
    let mut parts = core.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor = match parts.next() {
        None => None,
        Some(part) if wild(part) => None,
        Some(part) => Some(part.parse::<u64>().ok()?),
    };
    if let Some(patch) = parts.next() {
        if !(wild(patch) || patch.parse::<u64>().is_ok()) {
            return None;
        }
    }
    if parts.next().is_some() {
        return None;
    }
    Some(match (op, minor) {
        (_, None) => ((major, 0), (major, u64::MAX)),
        ('^', Some(minor)) if major > 0 => ((major, minor), (major, u64::MAX)),
        (_, Some(minor)) => ((major, minor), (major, minor)),
    })
}

/// The `packageManager` value of a `.modules.yaml`: JSON on pnpm 10+,
/// YAML before (a top-level scalar, maybe quoted).
fn modules_yaml_package_manager(text: &str) -> Option<String> {
    let text = strip_bom(text);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        return value.get("packageManager")?.as_str().map(str::to_string);
    }
    text.split('\n').find_map(|line| {
        let (key, value) = super::workspace::top_level_key(line)?;
        (key == "packageManager").then(|| value.trim_matches(|c| c == '\'' || c == '"').to_string())
    })
}

/// Every pnpm version pin the project's files carry, as `(where, spec)`.
fn pnpm_pins(
    package_json: Option<&str>,
    modules_yaml: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut pins = Vec::new();
    if let Some(spec) = modules_yaml.and_then(modules_yaml_package_manager) {
        if let Some(version) = pinned_version(&spec, "pnpm") {
            pins.push(("node_modules/.modules.yaml", version.to_string()));
        }
    }
    let Some(pkg) = package_json
        .and_then(|text| serde_json::from_str::<serde_json::Value>(strip_bom(text)).ok())
    else {
        return pins;
    };
    if let Some(version) = pkg
        .get("packageManager")
        .and_then(|v| v.as_str())
        .and_then(|spec| pinned_version(spec, "pnpm"))
    {
        pins.push(("package.json packageManager", version.to_string()));
    }
    let dev_engines = pkg.get("devEngines").and_then(|d| d.get("packageManager"));
    let entries: Vec<&serde_json::Value> = match dev_engines {
        Some(serde_json::Value::Array(items)) => items.iter().collect(),
        Some(entry) => vec![entry],
        None => Vec::new(),
    };
    for entry in entries {
        if entry.get("name").and_then(|n| n.as_str()) == Some("pnpm") {
            // No version admits every pnpm: kept as an unparseable pin.
            let version = entry.get("version").and_then(|v| v.as_str()).unwrap_or("");
            pins.push(("package.json devEngines", version.to_string()));
        }
    }
    if let Some(range) = pkg.get("engines").and_then(|e| e.get("pnpm")) {
        pins.push((
            "package.json engines.pnpm",
            range.as_str().unwrap_or("").to_string(),
        ));
    }
    pins
}

/// When every pnpm pin the project carries (at least one) is a release that
/// refuses `pnpm add` in a root-only workspace, the pins as prose
/// (``pnpm@9.15.9 (node_modules/.modules.yaml)``): creating a
/// pnpm-workspace.yaml would then turn the single-package project into a
/// workspace that pnpm reads nothing from. `None` keeps today's scaffold.
pub fn root_only_workspace_breaks_add(
    package_json: Option<&str>,
    modules_yaml: Option<&str>,
) -> Option<String> {
    let pins = pnpm_pins(package_json, modules_yaml);
    let all_break = !pins.is_empty()
        && pins
            .iter()
            .all(|(_, spec)| version_span(spec).is_some_and(breaks_root_only_workspace));
    all_break.then(|| {
        pins.iter()
            .map(|(source, spec)| format!("pnpm@{spec} ({source})"))
            .collect::<Vec<_>>()
            .join(", ")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_span_reads_exact_caret_tilde_and_wildcards() {
        for (spec, span) in [
            ("9.15.9", Some(((9, 15), (9, 15)))),
            ("=10.4.1", Some(((10, 4), (10, 4)))),
            ("v10.0.0-rc.3", Some(((10, 0), (10, 0)))),
            ("^9.15.0", Some(((9, 15), (9, u64::MAX)))),
            ("~10.4.1", Some(((10, 4), (10, 4)))),
            ("9.x", Some(((9, 0), (9, u64::MAX)))),
            ("9", Some(((9, 0), (9, u64::MAX)))),
            ("10.4.x", Some(((10, 4), (10, 4)))),
            (">=9", None),
            ("9 || 10", None),
            ("9.0.0 - 10.4.0", None),
            ("", None),
            ("latest", None),
        ] {
            assert_eq!(version_span(spec), span, "{spec}");
        }
    }

    #[test]
    fn breaks_root_only_workspace_on_9_0_through_10_4() {
        let at = |major, minor| breaks_root_only_workspace(((major, minor), (major, minor)));
        assert!(!at(8, 15));
        assert!(at(9, 0));
        assert!(at(10, 4));
        assert!(!at(10, 5));
        assert!(!at(11, 0));
        // `^10.2.0` reaches 10.5+, `^9.0.0` stays below 10.
        assert!(!breaks_root_only_workspace(
            version_span("^10.2.0").unwrap()
        ));
        assert!(breaks_root_only_workspace(version_span("^9.0.0").unwrap()));
    }

    #[test]
    fn every_source_is_read() {
        let breaks = |pkg: Option<&str>, modules: Option<&str>| {
            root_only_workspace_breaks_add(pkg, modules).is_some()
        };
        // .modules.yaml, YAML (pnpm 9) and JSON (pnpm 10) spellings.
        let yaml = "hoistPattern:\n  - '*'\nlayoutVersion: 5\npackageManager: pnpm@9.15.9\n";
        assert_eq!(
            root_only_workspace_breaks_add(None, Some(yaml)).as_deref(),
            Some("pnpm@9.15.9 (node_modules/.modules.yaml)")
        );
        assert!(breaks(None, Some("packageManager: 'pnpm@9.0.0'\r\n")));
        assert!(breaks(
            None,
            Some(r#"{"layoutVersion":5,"packageManager":"pnpm@10.4.1"}"#)
        ));
        assert!(!breaks(None, Some(r#"{"packageManager":"pnpm@10.5.0"}"#)));
        // package.json packageManager, with Corepack's hash suffix and a BOM.
        assert!(breaks(
            Some("\u{feff}{\"packageManager\":\"pnpm@10.4.1+sha512.abc==\"}"),
            None
        ));
        assert!(!breaks(Some(r#"{"packageManager":"pnpm@11.0.0"}"#), None));
        // devEngines, object and array forms.
        assert!(breaks(
            Some(r#"{"devEngines":{"packageManager":{"name":"pnpm","version":"^9.15.0"}}}"#),
            None
        ));
        assert!(breaks(
            Some(
                r#"{"devEngines":{"packageManager":[{"name":"npm","version":"11"},{"name":"pnpm","version":"10.4.x"}]}}"#
            ),
            None
        ));
        // `10.x` reaches 10.5+, which reads the file.
        assert!(!breaks(
            Some(r#"{"devEngines":{"packageManager":{"name":"pnpm","version":"10.x"}}}"#),
            None
        ));
        assert!(!breaks(
            Some(r#"{"devEngines":{"packageManager":{"name":"pnpm"}}}"#),
            None
        ));
        // engines.pnpm.
        assert!(breaks(Some(r#"{"engines":{"pnpm":"~9.15.0"}}"#), None));
        assert!(!breaks(Some(r#"{"engines":{"pnpm":">=9"}}"#), None));
    }

    #[test]
    fn any_disagreeing_unparseable_or_missing_pin_keeps_the_scaffold() {
        let modules_9 = Some("packageManager: pnpm@9.15.9\n");
        // A stale install record after an upgrade the pin names.
        assert!(root_only_workspace_breaks_add(
            Some(r#"{"packageManager":"pnpm@11.1.0"}"#),
            modules_9
        )
        .is_none());
        assert!(
            root_only_workspace_breaks_add(Some(r#"{"engines":{"pnpm":">=9"}}"#), modules_9)
                .is_none()
        );
        // Agreeing sources: both named.
        assert_eq!(
            root_only_workspace_breaks_add(Some(r#"{"packageManager":"pnpm@9.15.9"}"#), modules_9)
                .as_deref(),
            Some(
                "pnpm@9.15.9 (node_modules/.modules.yaml), \
                 pnpm@9.15.9 (package.json packageManager)"
            )
        );
        // No pnpm pin at all: unknown, so the scaffold stays.
        for (pkg, modules) in [
            (None, None),
            (Some(r#"{"name":"app"}"#), None),
            (Some(r#"{"packageManager":"yarn@1.22.22"}"#), None),
            (Some("not json"), Some("layoutVersion: 5\n")),
        ] {
            assert!(
                root_only_workspace_breaks_add(pkg, modules).is_none(),
                "{pkg:?}"
            );
        }
    }
}
