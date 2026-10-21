//! npm 12's `package.json#allowScripts` install-script policy (#1595).
//!
//! npm >= 12 blocks dependency install scripts unless the root
//! `package.json` approves them, and `npm approve-scripts` writes a
//! version-pinned key (`"esbuild@0.19.12": true`). npm matches a pinned
//! key only against the trusted version it reads from a registry-shaped
//! `resolved` URL (`…/<name>/-/<leaf>-<ver>.tgz`, arborist's
//! `script-allowed.js` / `versionFromTgz`). A hosted redirect (patch
//! server URL) and a vendored rewire (`file:.socket/vendor/…`) both leave
//! that shape, so the trusted version becomes unknown: a pinned allow
//! stops matching, a pinned deny fails closed (it matches whatever its
//! version), and name-only keys (`pkg`, `pkg@*`) match as before. An
//! approved script then silently stops running (or, under
//! `strict-allow-scripts`, every install fails). Neither mode can keep the
//! approval valid without widening the policy or writing a
//! machine-specific key, so both warn.

use std::cmp::Ordering;

use semver::Version;
use serde_json::Value;

/// Hosted-mode warning code (`warnings[]`).
pub const HOSTED_WARNING: &str = "redirect_npm_allow_scripts";
/// Vendored-mode advisory code (`skipped` event).
pub const VENDOR_WARNING: &str = "vendor_npm_allow_scripts";

/// The only npm lock npm >= 12 reads (it never reads npm-shrinkwrap.json),
/// so the only one whose rewired entries can lose an approval.
pub const NPM12_LOCK: &str = "package-lock.json";

/// How an `allowScripts` key can match a registry package, mirroring
/// arborist's `matchRegistry` for the key types that name one.
enum KeyKind {
    /// A bare name or `name@*`: matches whatever the lock resolves to.
    NameOnly,
    /// An exact version or `||`-joined exact versions: matches only when
    /// npm reads a covered version from a registry-shaped `resolved`.
    Pinned(Vec<Version>),
}

/// The approval npm 12 gives one package under the policy.
#[derive(PartialEq)]
enum Verdict {
    Allowed,
    Denied,
    Unreviewed,
}

/// The parsed root `allowScripts` policy: `(key, name, kind, allow)` for
/// every key that can name a registry package. Aliases, ranges npm
/// rejects (`^1`, `latest`) and git / file / remote specs never match a
/// registry package, before or after the rewrite, and are dropped.
pub struct AllowScripts {
    entries: Vec<(String, String, KeyKind, bool)>,
}

/// What the rewrite of one package costs under the policy: the pinned
/// allows that stop matching and the pinned denies that start to.
pub struct LostApproval {
    pub allows: Vec<String>,
    pub denies: Vec<String>,
}

/// Split an npm package-arg key into `(name, spec)`; `spec` is `None` for
/// a bare name. A scoped name's leading `@` is part of the name.
fn split_key(key: &str) -> (&str, Option<&str>) {
    let search_from = usize::from(key.starts_with('@'));
    match key[search_from..].find('@') {
        Some(at) => {
            let at = at + search_from;
            (&key[..at], Some(&key[at + 1..]))
        }
        None => (key, None),
    }
}

/// `semver.valid(v, { loose: true })` for the exact-version spellings npm
/// accepts in a pin: surrounding whitespace and a leading `=` / `v`.
fn loose_version(text: &str) -> Option<Version> {
    let text = text.trim();
    let text = text.strip_prefix('=').unwrap_or(text).trim_start();
    let text = text
        .strip_prefix('v')
        .or_else(|| text.strip_prefix('V'))
        .unwrap_or(text);
    Version::parse(text).ok()
}

impl AllowScripts {
    /// The policy in the root `package.json` text, or `None` when it has
    /// no `allowScripts` key that could name a registry package (or the
    /// file is unreadable): nothing can be lost.
    pub fn parse(package_json: &str) -> Option<Self> {
        let manifest: Value =
            serde_json::from_str(crate::formats::text::strip_bom(package_json)).ok()?;
        let policy = manifest.get("allowScripts")?.as_object()?;
        let entries: Vec<_> = policy
            .iter()
            .filter_map(|(key, value)| {
                let allow = value.as_bool()?;
                let (name, spec) = split_key(key);
                let kind = match spec.map(str::trim) {
                    None | Some("") | Some("*") => KeyKind::NameOnly,
                    Some(spec) => KeyKind::Pinned(
                        spec.split("||")
                            .map(loose_version)
                            .collect::<Option<Vec<_>>>()?,
                    ),
                };
                Some((key.clone(), name.to_string(), kind, allow))
            })
            .collect();
        (!entries.is_empty()).then_some(Self { entries })
    }

    /// npm's verdict for `name`, at `version` when npm can read one from a
    /// registry `resolved`, or `None` once it cannot (deny wins).
    fn verdict(&self, name: &str, version: Option<&Version>) -> Verdict {
        let mut allowed = false;
        for (_, key_name, kind, allow) in &self.entries {
            if key_name != name {
                continue;
            }
            let matches = match (kind, version) {
                (KeyKind::NameOnly, _) => true,
                (KeyKind::Pinned(pins), Some(v)) => pins
                    .iter()
                    .any(|pin| pin.cmp_precedence(v) == Ordering::Equal),
                // Unverifiable version: a deny fails closed, an allow is
                // refused.
                (KeyKind::Pinned(_), None) => !allow,
            };
            if matches && !allow {
                return Verdict::Denied;
            }
            allowed |= matches;
        }
        if allowed {
            Verdict::Allowed
        } else {
            Verdict::Unreviewed
        }
    }

    /// The approval `name@version`'s install scripts lose once its lock
    /// entries resolve outside the registry, or `None` when npm 12 runs
    /// them as before (or never did: denied or unreviewed already).
    pub fn lost(&self, name: &str, version: &str) -> Option<LostApproval> {
        let version = loose_version(version)?;
        if self.verdict(name, Some(&version)) != Verdict::Allowed
            || self.verdict(name, None) == Verdict::Allowed
        {
            return None;
        }
        let pinned = |allow: bool| -> Vec<String> {
            self.entries
                .iter()
                .filter(|(_, key_name, kind, a)| {
                    key_name == name && *a == allow && matches!(kind, KeyKind::Pinned(_))
                })
                .filter(|(_, _, kind, _)| match kind {
                    // Every pinned deny matches after the rewrite; only the
                    // allows that covered this version were lost.
                    KeyKind::Pinned(pins) => {
                        !allow
                            || pins
                                .iter()
                                .any(|pin| pin.cmp_precedence(&version) == Ordering::Equal)
                    }
                    KeyKind::NameOnly => false,
                })
                .map(|(key, ..)| key.clone())
                .collect()
        };
        Some(LostApproval {
            allows: pinned(true),
            denies: pinned(false),
        })
    }
}

/// Does a rewired `package-lock.json` entry for `name@version` run an
/// install script? `is_rewired(key, entry)` picks the entries the run
/// points outside the registry. lockfileVersion 2/3 entries say so with
/// `hasInstallScript`; a lockfileVersion 1 lock never records it, so a
/// rewired v1 entry counts as having one. Bundled copies never run
/// scripts.
pub fn rewired_runs_install_script(
    lock: &Value,
    name: &str,
    version: &str,
    is_rewired: impl Fn(&str, &Value) -> bool,
) -> bool {
    if let Some(packages) = lock.get("packages").and_then(Value::as_object) {
        return packages.iter().any(|(key, entry)| {
            let Some(idx) = key.rfind("node_modules/") else {
                return false;
            };
            let folder = &key[idx + "node_modules/".len()..];
            entry.get("name").and_then(Value::as_str).unwrap_or(folder) == name
                && entry.get("version").and_then(Value::as_str) == Some(version)
                && entry.get("hasInstallScript").and_then(Value::as_bool) == Some(true)
                && entry.get("inBundle").and_then(Value::as_bool) != Some(true)
                && is_rewired(key, entry)
        });
    }
    fn walk_v1(
        deps: Option<&Value>,
        name: &str,
        version: &str,
        is_rewired: &dyn Fn(&str, &Value) -> bool,
    ) -> bool {
        let Some(deps) = deps.and_then(Value::as_object) else {
            return false;
        };
        deps.iter().any(|(key, entry)| {
            (key == name
                && entry.get("version").and_then(Value::as_str) == Some(version)
                && entry.get("bundled").and_then(Value::as_bool) != Some(true)
                && is_rewired(key, entry))
                || walk_v1(entry.get("dependencies"), name, version, is_rewired)
        })
    }
    walk_v1(lock.get("dependencies"), name, version, &is_rewired)
}

/// The warning detail for `name@version`, whose approval is `lost` once
/// its lock entries point at `target` (the hosted patch server or the
/// vendored `file:` tarball).
pub fn lost_detail(name: &str, version: &str, lost: &LostApproval, target: &str) -> String {
    let quote = |keys: &[String], value: bool| {
        keys.iter()
            .map(|key| format!("`\"{key}\": {value}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut why = Vec::new();
    if !lost.allows.is_empty() {
        why.push(format!(
            "package.json `allowScripts` approves it only by version ({}), which npm matches \
             only against a registry tarball URL",
            quote(&lost.allows, true)
        ));
    }
    if !lost.denies.is_empty() {
        why.push(format!(
            "npm applies its version-pinned deny ({}) to every version it cannot read from a \
             registry tarball URL",
            quote(&lost.denies, false)
        ));
    }
    let remedy = if lost.denies.is_empty() {
        format!("approve the package by name (`\"{name}\": true`) in package.json `allowScripts`")
    } else {
        format!(
            "remove its version-pinned deny entries and approve the package by name \
             (`\"{name}\": true`) in package.json `allowScripts`"
        )
    };
    format!(
        "npm >= 12 stops running {name}@{version}'s approved install scripts once the lock \
         resolves it to {target}: {}. The next `npm ci` installs the patched files but blocks \
         the install script (with `strict-allow-scripts=true` every install fails). To keep it \
         running, {remedy}; npm <= 11 is unaffected",
        why.join("; and ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lost_for(policy: &str, name: &str, version: &str) -> Option<LostApproval> {
        let text = format!(r#"{{ "name": "app", "allowScripts": {policy} }}"#);
        AllowScripts::parse(&text)?.lost(name, version)
    }

    #[test]
    fn exact_pin_is_lost() {
        let lost = lost_for(r#"{"esbuild@0.19.12": true}"#, "esbuild", "0.19.12").unwrap();
        assert_eq!(lost.allows, vec!["esbuild@0.19.12".to_string()]);
        assert!(lost.denies.is_empty());
    }

    #[test]
    fn scoped_pin_disjunction_loose_spellings_and_build_metadata_are_lost() {
        let policy = r#"{"@img/sharp@0.33.0 || 0.33.5": true, "@img/sharp@v0.33.5": true,
            "@img/sharp@=0.33.5": true, "@img/sharp@0.33.5+b": true}"#;
        let lost = lost_for(policy, "@img/sharp", "0.33.5").unwrap();
        assert_eq!(lost.allows.len(), 4);
    }

    #[test]
    fn name_only_approval_still_covers_it() {
        for policy in [
            r#"{"esbuild@0.19.12": true, "esbuild": true}"#,
            r#"{"esbuild@0.19.12": true, "esbuild@*": true}"#,
            r#"{"esbuild": true}"#,
        ] {
            assert!(lost_for(policy, "esbuild", "0.19.12").is_none(), "{policy}");
        }
    }

    /// npm fails a pinned deny closed on an unknown version, so a deny for
    /// ANOTHER version starts matching the rewired copy, even beside a
    /// name-only allow.
    #[test]
    fn other_version_deny_starts_matching() {
        let lost = lost_for(
            r#"{"esbuild": true, "esbuild@0.18.0": false}"#,
            "esbuild",
            "0.19.12",
        )
        .unwrap();
        assert!(lost.allows.is_empty());
        assert_eq!(lost.denies, vec!["esbuild@0.18.0".to_string()]);
        let detail = lost_detail("esbuild", "0.19.12", &lost, "x");
        assert!(
            detail.contains("remove its version-pinned deny"),
            "{detail}"
        );

        let lost = lost_for(
            r#"{"esbuild@0.19.12": true, "esbuild@0.18.0": false}"#,
            "esbuild",
            "0.19.12",
        )
        .unwrap();
        assert_eq!(lost.allows, vec!["esbuild@0.19.12".to_string()]);
        assert_eq!(lost.denies, vec!["esbuild@0.18.0".to_string()]);
    }

    #[test]
    fn denied_unreviewed_or_unrelated_lose_nothing() {
        for policy in [
            r#"{"esbuild@0.19.12": true, "esbuild": false}"#,
            r#"{"esbuild@0.19.12": false}"#,
            r#"{"esbuild@0.19.11": true}"#,
            r#"{"esbuild@^0.19.0": true}"#,
            r#"{"esbuild-wasm@0.19.12": true}"#,
            r#"{"alias@npm:esbuild@0.19.12": true}"#,
            r#"{"esbuild@0.19.12": "yes"}"#,
            r#"{"esbuild": true, "esbuild@^0.18": false}"#,
            r#"[]"#,
        ] {
            assert!(lost_for(policy, "esbuild", "0.19.12").is_none(), "{policy}");
        }
        assert!(AllowScripts::parse("not json").is_none());
        assert!(AllowScripts::parse(r#"{"name": "app"}"#).is_none());
        assert!(AllowScripts::parse(r#"{"allowScripts": {}}"#).is_none());
    }

    #[test]
    fn bom_prefixed_package_json_is_read() {
        let text = "\u{feff}{\"allowScripts\": {\"esbuild@0.19.12\": true}}";
        assert!(AllowScripts::parse(text)
            .unwrap()
            .lost("esbuild", "0.19.12")
            .is_some());
    }

    #[test]
    fn install_script_read_from_rewired_v3_entries_only() {
        let lock: Value = serde_json::from_str(
            r#"{"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/esbuild": {"version": "0.19.12", "resolved": "R", "hasInstallScript": true},
            "node_modules/x/node_modules/esbuild": {"version": "0.19.12", "resolved": "U", "hasInstallScript": true},
            "node_modules/plain": {"version": "1.0.0", "resolved": "R"},
            "node_modules/p/node_modules/bundled": {"version": "1.0.0", "resolved": "R", "hasInstallScript": true, "inBundle": true},
            "node_modules/al": {"name": "aliased", "version": "2.0.0", "resolved": "R", "hasInstallScript": true}
        }}"#,
        )
        .unwrap();
        let rewired = |_: &str, e: &Value| e["resolved"] == "R";
        assert!(rewired_runs_install_script(
            &lock, "esbuild", "0.19.12", rewired
        ));
        // Only a copy the run left on the registry has a script: no loss.
        assert!(!rewired_runs_install_script(
            &lock,
            "esbuild",
            "0.19.12",
            |k, _| { k == "node_modules/plain" }
        ));
        assert!(!rewired_runs_install_script(
            &lock, "esbuild", "0.19.11", rewired
        ));
        assert!(!rewired_runs_install_script(
            &lock, "plain", "1.0.0", rewired
        ));
        assert!(!rewired_runs_install_script(
            &lock, "bundled", "1.0.0", rewired
        ));
        assert!(rewired_runs_install_script(
            &lock, "aliased", "2.0.0", rewired
        ));
        assert!(!rewired_runs_install_script(&lock, "app", "1.0.0", rewired));
    }

    #[test]
    fn rewired_v1_entry_counts_as_running_a_script() {
        let lock: Value = serde_json::from_str(
            r#"{"lockfileVersion": 1, "dependencies": {
            "a": {"version": "1.0.0", "resolved": "U", "dependencies": {
                "esbuild": {"version": "0.19.12", "resolved": "R"}}},
            "b": {"version": "1.0.0", "resolved": "R", "bundled": true}
        }}"#,
        )
        .unwrap();
        let rewired = |_: &str, e: &Value| e["resolved"] == "R";
        assert!(rewired_runs_install_script(
            &lock, "esbuild", "0.19.12", rewired
        ));
        assert!(!rewired_runs_install_script(&lock, "a", "1.0.0", rewired));
        assert!(!rewired_runs_install_script(&lock, "b", "1.0.0", rewired));
    }
}
