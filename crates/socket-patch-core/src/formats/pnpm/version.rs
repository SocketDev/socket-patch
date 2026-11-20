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

/// `(major, minor, patch)`.
type Release = (u64, u64, u64);

/// Whether pnpm `release` matches a build decision (`allowBuilds`,
/// `onlyBuiltDependencies`) against a `file:` tarball's own id
/// (`name@file:<spec>`), which is also the first release that accepts such
/// a key at all. The change landed in 11.5.3 and was backported to
/// 10.34.2: older releases match the package name, and from at least 10.20
/// on refuse a `file:` key with ERR_PNPM_INVALID_VERSION_UNION (#1597;
/// measured on 9.15.9, 10.0.0, 10.20.0, 10.30.0, 10.34.1, 10.34.2, 10.34.7,
/// 11.5.2, 11.5.3, 11.28.7 and 12.15.0).
fn matches_file_ids(release: Release) -> bool {
    match release.0 {
        ..=9 => false,
        10 => release >= (10, 34, 2),
        11 => release >= (11, 5, 3),
        _ => true,
    }
}

/// The inclusive `(major, minor)` span a version spec admits: an exact
/// version (`9.15.9`, `=9.15.9`, `v9.15.9`, a prerelease), `^X.Y.Z`,
/// `~X.Y.Z`, or a wildcard (`9`, `9.x`, `10.4.x`, `9.*`). `None` for
/// anything else (comparators, unions, hyphen ranges, junk).
fn version_span(spec: &str) -> Option<(MajorMinor, MajorMinor)> {
    version_bounds(spec).map(|(lo, hi)| ((lo.0, lo.1), (hi.0, hi.1)))
}

/// [`version_span`] at patch precision. A prerelease counts as its
/// release.
fn version_bounds(spec: &str) -> Option<(Release, Release)> {
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
    let patch = match parts.next() {
        None => None,
        Some(part) if wild(part) => None,
        Some(part) => Some(part.parse::<u64>().ok()?),
    };
    if parts.next().is_some() {
        return None;
    }
    const MAX: u64 = u64::MAX;
    Some(match (op, minor, patch) {
        (_, None, _) => ((major, 0, 0), (major, MAX, MAX)),
        ('^', Some(minor), patch) if major > 0 => {
            ((major, minor, patch.unwrap_or(0)), (major, MAX, MAX))
        }
        ('=', Some(minor), Some(patch)) => ((major, minor, patch), (major, minor, patch)),
        (_, Some(minor), patch) => ((major, minor, patch.unwrap_or(0)), (major, minor, MAX)),
    })
}

/// Every pnpm version pin the project's files carry, as `(where, spec)`.
fn pnpm_pins(
    package_json: Option<&str>,
    modules_yaml: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut pins = Vec::new();
    if let Some(spec) =
        modules_yaml.and_then(|text| super::modules_yaml::field(text, "packageManager"))
    {
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

/// What a project's pnpm pins say about pnpm 12, the first major hosted
/// mode declares its named registries for ([`pnpm_12_pins`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pnpm12Pins {
    /// Every pin the project carries (at least one) admits only pnpm 12 or
    /// newer.
    Proven,
    /// The project carries no pnpm pin: nothing says which pnpm installs
    /// it.
    Unpinned,
    /// A pin admits an older pnpm, or does not parse.
    NotProven,
}

/// Whether the project's pnpm pins prove that every pnpm that installs it
/// is 12 or newer.
///
/// pnpm verifies a lock entry against a named registry from 11.10 on, but
/// what `pnpm add` then does to a hosted entry differs by release
/// (measured on a lock with three hosted entries and `pnpm add
/// is-odd@3.0.1`): 11.10.0, 11.20.0 and 11.25.0 re-resolve it to the
/// upstream tarball under either setting, 11.28.13 keeps it under
/// `trustLockfile: true` but re-resolves it under a named registry, and
/// 12.0.0, 12.4.2, 12.10.0 and 12.22.0 keep it under both. So a named
/// registry costs nothing only from pnpm 12 on, and anything short of
/// proof leaves the project on `trustLockfile`.
///
/// The evidence is every pin [`root_only_workspace_breaks_add`] reads. A
/// pin proves pnpm 12 when the lowest version it admits is 12.0 or higher
/// ([`range_floor`]): an exact version, `^12`, `>=12.4`, `12 || 13`. A
/// range that reaches below 12 (`>=11`), one that does not parse, or pins
/// that disagree prove nothing.
pub fn pnpm_12_pins(package_json: Option<&str>, modules_yaml: Option<&str>) -> Pnpm12Pins {
    let pins = pnpm_pins(package_json, modules_yaml);
    if pins.is_empty() {
        Pnpm12Pins::Unpinned
    } else if pins
        .iter()
        .all(|(_, spec)| range_floor(spec).is_some_and(|floor| floor >= (12, 0)))
    {
        Pnpm12Pins::Proven
    } else {
        Pnpm12Pins::NotProven
    }
}

/// The lowest `(major, minor)` a version range admits: the lowest floor of
/// its `||` alternatives. `None` for a range this reader cannot follow,
/// which a caller must not take for a floor.
fn range_floor(spec: &str) -> Option<MajorMinor> {
    spec.split("||")
        .map(alternative_floor)
        .try_fold(None::<MajorMinor>, |lowest, floor| {
            let floor = floor?;
            Some(Some(lowest.map_or(floor, |lowest| lowest.min(floor))))
        })
        .flatten()
}

/// The floor of one `||` alternative: its comparators all hold, so the
/// highest of their floors. A version ([`version_span`]: exact, `^`, `~`,
/// wildcard), `>=` and `>` give one (`>` is read as `>=`, which is never
/// too high), `<` and `<=` give none, and `A - B` starts at `A`.
fn alternative_floor(alternative: &str) -> Option<MajorMinor> {
    // An operator may stand apart from its version (`>= 12`).
    let mut tokens: Vec<String> = Vec::new();
    let mut operator = "";
    for word in alternative.split_whitespace() {
        if matches!(word, ">=" | ">" | "<=" | "<" | "=" | "^" | "~") {
            if !operator.is_empty() {
                return None;
            }
            operator = word;
        } else {
            tokens.push(format!("{operator}{word}"));
            operator = "";
        }
    }
    if !operator.is_empty() || tokens.is_empty() {
        return None;
    }
    if let [low, dash, high] = tokens.as_slice() {
        if dash == "-" {
            version_span(high)?;
            return version_span(low).map(|(floor, _)| floor);
        }
    }
    let mut floor = (0, 0);
    for token in &tokens {
        let lower = token.strip_prefix(">=").or_else(|| token.strip_prefix('>'));
        let upper = token.strip_prefix("<=").or_else(|| token.strip_prefix('<'));
        let (this, _) = version_span(lower.or(upper).unwrap_or(token))?;
        if upper.is_none() {
            floor = floor.max(this);
        }
    }
    Some(floor)
}

/// Whether the pnpm the project runs matches build decisions against a
/// vendored `file:` id (see [`matches_file_ids`]): `Some(true)` when every
/// pin that parses admits only such a release, `Some(false)` when every one
/// admits only older ones, `None` without a parseable pin or when they
/// disagree.
pub fn matches_file_id_build_keys(
    package_json: Option<&str>,
    modules_yaml: Option<&str>,
) -> Option<bool> {
    // A span decides when both ends agree within one major (the answer is
    // monotonic inside a major, not across the 10 → 11 boundary).
    let decided = |(lo, hi): (Release, Release)| {
        (lo.0 == hi.0 && matches_file_ids(lo) == matches_file_ids(hi)).then(|| matches_file_ids(lo))
    };
    let mut answers = pnpm_pins(package_json, modules_yaml)
        .iter()
        .filter_map(|(_, spec)| version_bounds(spec))
        .map(decided)
        .collect::<Vec<_>>()
        .into_iter();
    let first = answers.next()??;
    answers.all(|a| a == Some(first)).then_some(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #1918: a YAML `.modules.yaml` is read like every other pnpm settings
    /// file: the last top-level key wins, comments are not part of the value.
    #[test]
    fn modules_yaml_pin_reads_the_last_key() {
        let pins = |text: &str| pnpm_pins(None, Some(text));
        let text = "packageManager: pnpm@9.0.0\npackageManager: pnpm@11.0.0 # newer\n";
        let want = vec![("node_modules/.modules.yaml", "11.0.0".to_string())];
        assert_eq!(pins(text), want);
        assert_eq!(pins("packageManager: 'pnpm@11.0.0'\n"), want);
        assert_eq!(pins("{\"packageManager\":\"pnpm@11.0.0\"}"), want);
    }

    #[test]
    fn file_id_build_keys_start_at_10_34_2_and_11_5_3() {
        let pm = |spec: &str| format!("{{\"packageManager\":\"pnpm@{spec}\"}}");
        for (spec, want) in [
            ("10.34.2", Some(true)),
            ("10.34.7+sha512.abc", Some(true)),
            ("11.28.7", Some(true)),
            ("11.5.3", Some(true)),
            ("11.5.2", Some(false)),
            ("11.2.0", Some(false)),
            ("11.0.0", Some(false)),
            ("12.0.0-rc.1", Some(true)),
            ("10.34.1", Some(false)),
            ("10.20.0", Some(false)),
            ("9.15.9", Some(false)),
        ] {
            assert_eq!(
                matches_file_id_build_keys(Some(&pm(spec)), None),
                want,
                "{spec}"
            );
        }
        // Ranges admitting both sides, or no pin, decide nothing.
        let engines = |range: &str| format!("{{\"engines\":{{\"pnpm\":\"{range}\"}}}}");
        assert_eq!(
            matches_file_id_build_keys(Some(&engines("^10.30.0")), None),
            None
        );
        assert_eq!(
            matches_file_id_build_keys(Some(&engines("^10.34.2")), None),
            Some(true)
        );
        assert_eq!(
            matches_file_id_build_keys(Some(&engines("~10.34.1")), None),
            None
        );
        // 11.0–11.5.2 predate the change despite sorting after 10.34.2.
        assert_eq!(
            matches_file_id_build_keys(Some(&engines("^11.0.0")), None),
            None
        );
        assert_eq!(
            matches_file_id_build_keys(Some(&engines("^11.5.3")), None),
            Some(true)
        );
        assert_eq!(
            matches_file_id_build_keys(Some(&engines("~11.4.0")), None),
            Some(false)
        );
        assert_eq!(
            matches_file_id_build_keys(Some(&engines(">=10")), None),
            None
        );
        assert_eq!(matches_file_id_build_keys(Some("{}"), None), None);
        // The pnpm that last installed counts; a disagreeing pin undoes it.
        let modules = r#"{"packageManager":"pnpm@11.28.7"}"#;
        assert_eq!(matches_file_id_build_keys(None, Some(modules)), Some(true));
        assert_eq!(
            matches_file_id_build_keys(Some(&pm("10.20.0")), Some(modules)),
            None
        );
    }

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

    /// Named registries are declared only on proof of pnpm 12 or newer:
    /// every pin present (at least one) admits nothing older. No pin at
    /// all is told apart from a pin that proves nothing.
    #[test]
    fn pnpm_12_is_proven_only_by_every_pin() {
        for pkg in [
            r#"{"packageManager":"pnpm@12.0.0"}"#,
            r#"{"packageManager":"pnpm@12.22.0+sha512.abc=="}"#,
            r#"{"packageManager":"pnpm@13.0.1"}"#,
            r#"{"engines":{"pnpm":"^12.4.0"}}"#,
            r#"{"engines":{"pnpm":"12"}}"#,
            r#"{"engines":{"pnpm":">=12"}}"#,
            r#"{"engines":{"pnpm":">=12.4.0"}}"#,
            r#"{"engines":{"pnpm":">12"}}"#,
            r#"{"engines":{"pnpm":">=12 <14"}}"#,
            r#"{"engines":{"pnpm":">= 12.4.0 <14"}}"#,
            r#"{"engines":{"pnpm":"12 || 13"}}"#,
            r#"{"engines":{"pnpm":"^12.0.0 || >=13.2"}}"#,
            r#"{"engines":{"pnpm":"12.0.0 - 13.5.0"}}"#,
            r#"{"devEngines":{"packageManager":{"name":"pnpm","version":"~12.4.2"}}}"#,
        ] {
            assert_eq!(pnpm_12_pins(Some(pkg), None), Pnpm12Pins::Proven, "{pkg}");
        }
        assert_eq!(
            pnpm_12_pins(None, Some("packageManager: pnpm@12.22.0\n")),
            Pnpm12Pins::Proven
        );
        assert_eq!(
            pnpm_12_pins(
                Some(r#"{"packageManager":"pnpm@12.4.2"}"#),
                Some(r#"{"packageManager":"pnpm@12.22.0"}"#)
            ),
            Pnpm12Pins::Proven
        );
        // No pin: nothing says which pnpm installs the project.
        for pkg in [
            None,
            Some(r#"{"name":"app"}"#),
            Some(r#"{"packageManager":"yarn@4.5.0"}"#),
            Some("not json"),
        ] {
            assert_eq!(pnpm_12_pins(pkg, None), Pnpm12Pins::Unpinned, "{pkg:?}");
        }
        for (pkg, modules) in [
            // An older pnpm, or a range that reaches one.
            (Some(r#"{"packageManager":"pnpm@11.28.13"}"#), None),
            (Some(r#"{"packageManager":"pnpm@10.34.6"}"#), None),
            (Some(r#"{"engines":{"pnpm":">=11"}}"#), None),
            // `>11` is read as `>=11`: never too high a floor.
            (Some(r#"{"engines":{"pnpm":">11"}}"#), None),
            (Some(r#"{"engines":{"pnpm":">=11.28 <13"}}"#), None),
            (Some(r#"{"engines":{"pnpm":"11 || 12"}}"#), None),
            (Some(r#"{"engines":{"pnpm":"<13"}}"#), None),
            (Some(r#"{"engines":{"pnpm":"11.0.0 - 12.5.0"}}"#), None),
            // A range this reader cannot follow.
            (Some(r#"{"engines":{"pnpm":"*"}}"#), None),
            (Some(r#"{"engines":{"pnpm":"latest"}}"#), None),
            (Some(r#"{"engines":{"pnpm":">= >=12"}}"#), None),
            (Some(r#"{"engines":{"pnpm":"12 ||"}}"#), None),
            (
                Some(r#"{"devEngines":{"packageManager":{"name":"pnpm"}}}"#),
                None,
            ),
            // Pins that disagree: the install record lags the manifest, or
            // the manifest's own pins differ.
            (
                Some(r#"{"packageManager":"pnpm@12.4.2"}"#),
                Some("packageManager: pnpm@11.28.13\n"),
            ),
            (
                Some(r#"{"packageManager":"pnpm@12.4.2","engines":{"pnpm":"^11.0.0"}}"#),
                None,
            ),
            (None, Some("packageManager: pnpm@11.28.13\n")),
        ] {
            assert_eq!(
                pnpm_12_pins(pkg, modules),
                Pnpm12Pins::NotProven,
                "{pkg:?} {modules:?}"
            );
        }
    }

    #[test]
    fn range_floor_is_the_lowest_version_a_range_admits() {
        for (spec, floor) in [
            ("12.4.2", Some((12, 4))),
            ("^12.4.0", Some((12, 4))),
            ("12", Some((12, 0))),
            (">=12", Some((12, 0))),
            (">12.3.0", Some((12, 3))),
            (">=12.4 <14", Some((12, 4))),
            (">=11 >=12.1", Some((12, 1))),
            ("^12 || ^11.28", Some((11, 28))),
            ("11.5.0 - 12", Some((11, 5))),
            ("<13", Some((0, 0))),
            ("<=12.4.0 >=12", Some((12, 0))),
            ("", None),
            ("*", None),
            (">=", None),
            ("12 - ", None),
            ("12 - x - 13", None),
            (">=12 || nope", None),
        ] {
            assert_eq!(range_floor(spec), floor, "{spec:?}");
        }
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
