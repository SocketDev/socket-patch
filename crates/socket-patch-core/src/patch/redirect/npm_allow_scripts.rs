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
//! stops matching, while a name-only allow (`pkg`, `pkg@*`) and every
//! deny keep matching. The approved script then silently stops running
//! (or, under `strict-allow-scripts`, every install fails). Neither side
//! can keep the pin valid without weakening the policy or writing a
//! machine-specific key, so both runs warn.

use semver::Version;
use serde_json::Value;

/// Hosted-mode warning code (`warnings[]`).
pub const HOSTED_WARNING: &str = "redirect_npm_allow_scripts";
/// Vendored-mode advisory code (`skipped` event).
pub const VENDOR_WARNING: &str = "vendor_npm_allow_scripts";

/// How an `allowScripts` key matches a registry package, mirroring
/// arborist's `matchRegistry` for the key types that can name one.
enum KeyMatch {
    /// The key does not name this registry package (another name, an
    /// alias, a git / file / remote spec, a range npm rejects).
    No,
    /// A bare name or `name@*`: matches whatever the lock resolves to.
    NameOnly,
    /// An exact version or `||`-joined exact versions covering the
    /// package's version: matches only while npm can read that version
    /// from a registry-shaped `resolved`.
    Pinned,
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

fn key_match(key: &str, name: &str, version: &Version) -> KeyMatch {
    let (key_name, spec) = split_key(key);
    if key_name != name {
        return KeyMatch::No;
    }
    let spec = match spec.map(str::trim) {
        None | Some("") | Some("*") => return KeyMatch::NameOnly,
        Some(spec) => spec,
    };
    // `name@npm:other@1` is an alias, which npm never matches; anything
    // else that is not exact versions (`^1`, `latest`, a URL) is rejected
    // or matched as a non-registry spec.
    let pins: Option<Vec<Version>> = spec.split("||").map(loose_version).collect();
    match pins {
        Some(pins) if pins.iter().any(|pin| pin == version) => KeyMatch::Pinned,
        _ => KeyMatch::No,
    }
}

/// The `allowScripts` keys in the root `package.json` text that approve
/// `name@version`'s install scripts today but stop matching once its lock
/// entries resolve outside the registry. Empty when nothing is lost: no
/// pinned approval covers it, a name-only approval still does, a deny
/// already blocks it, or the policy (or the file) is unreadable.
pub fn pinned_approvals_lost(package_json: &str, name: &str, version: &str) -> Vec<String> {
    let Some(version) = loose_version(version) else {
        return Vec::new();
    };
    let Ok(manifest) = serde_json::from_str::<Value>(package_json.trim_start_matches('\u{feff}'))
    else {
        return Vec::new();
    };
    let Some(policy) = manifest.get("allowScripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut pinned = Vec::new();
    for (key, value) in policy {
        match (key_match(key, name, &version), value) {
            (KeyMatch::No, _) => {}
            // A matching deny wins before and after the rewrite (npm fails
            // a pinned deny closed on an unknown version): nothing changes.
            (_, Value::Bool(false)) => return Vec::new(),
            (KeyMatch::NameOnly, Value::Bool(true)) => return Vec::new(),
            (KeyMatch::Pinned, Value::Bool(true)) => pinned.push(key.clone()),
            _ => {}
        }
    }
    pinned
}

/// Does any `package-lock.json` / `npm-shrinkwrap.json` entry for
/// `name@version` record an install script (`hasInstallScript: true`)?
/// Only such a package has a script for npm's policy to block. Bundled
/// copies are skipped: npm never runs their scripts, approved or not.
pub fn lock_has_install_script(lock_text: &str, name: &str, version: &str) -> bool {
    let Ok(lock) = serde_json::from_str::<Value>(lock_text.trim_start_matches('\u{feff}')) else {
        return false;
    };
    let Some(packages) = lock.get("packages").and_then(Value::as_object) else {
        return false;
    };
    packages.iter().any(|(key, entry)| {
        let folder = key.rsplit("node_modules/").next().unwrap_or_default();
        let entry_name = entry.get("name").and_then(Value::as_str).unwrap_or(folder);
        key.contains("node_modules/")
            && entry_name == name
            && entry.get("version").and_then(Value::as_str) == Some(version)
            && entry.get("hasInstallScript").and_then(Value::as_bool) == Some(true)
            && entry.get("inBundle").and_then(Value::as_bool) != Some(true)
    })
}

/// The warning detail for `name@version`, whose pinned `keys` no longer
/// match once its lock entries point at `target` (the hosted patch server
/// or the vendored `file:` tarball).
pub fn lost_detail(name: &str, version: &str, keys: &[String], target: &str) -> String {
    let keys = keys
        .iter()
        .map(|key| format!("`\"{key}\": true`"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "npm >= 12 stops running {name}@{version}'s approved install scripts: package.json \
         `allowScripts` approves it only by version ({keys}), and npm matches a version pin \
         only against a registry tarball URL, while the lock now resolves it to {target}. The \
         next `npm ci` installs the patched files but blocks the install script (with \
         `strict-allow-scripts=true` every install fails). To keep it running, approve the \
         package by name (`\"{name}\": true`) in package.json `allowScripts`; npm <= 11 is \
         unaffected"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(policy: &str) -> String {
        format!(r#"{{ "name": "app", "allowScripts": {policy} }}"#)
    }

    #[test]
    fn exact_pin_is_lost() {
        let lost =
            pinned_approvals_lost(&pkg(r#"{"esbuild@0.19.12": true}"#), "esbuild", "0.19.12");
        assert_eq!(lost, vec!["esbuild@0.19.12".to_string()]);
    }

    #[test]
    fn scoped_pin_and_disjunction_and_loose_spellings_are_lost() {
        let text = pkg(
            r#"{"@img/sharp@0.33.0 || 0.33.5": true, "@img/sharp@v0.33.5": true, "@img/sharp@=0.33.5": true}"#,
        );
        assert_eq!(
            pinned_approvals_lost(&text, "@img/sharp", "0.33.5").len(),
            3
        );
    }

    #[test]
    fn name_only_approval_still_covers_it() {
        for policy in [
            r#"{"esbuild@0.19.12": true, "esbuild": true}"#,
            r#"{"esbuild@0.19.12": true, "esbuild@*": true}"#,
        ] {
            assert!(
                pinned_approvals_lost(&pkg(policy), "esbuild", "0.19.12").is_empty(),
                "{policy}"
            );
        }
    }

    #[test]
    fn deny_or_unrelated_keys_lose_nothing() {
        for policy in [
            r#"{"esbuild@0.19.12": true, "esbuild": false}"#,
            r#"{"esbuild@0.19.11": true}"#,
            r#"{"esbuild@^0.19.0": true}"#,
            r#"{"esbuild-wasm@0.19.12": true}"#,
            r#"{"alias@npm:esbuild@0.19.12": true}"#,
            r#"{"esbuild@0.19.12": "yes"}"#,
            r#"[]"#,
        ] {
            assert!(
                pinned_approvals_lost(&pkg(policy), "esbuild", "0.19.12").is_empty(),
                "{policy}"
            );
        }
        assert!(pinned_approvals_lost("not json", "esbuild", "0.19.12").is_empty());
        assert!(pinned_approvals_lost(r#"{"name": "app"}"#, "esbuild", "0.19.12").is_empty());
    }

    #[test]
    fn bom_prefixed_package_json_is_read() {
        let text = format!("\u{feff}{}", pkg(r#"{"esbuild@0.19.12": true}"#));
        assert_eq!(pinned_approvals_lost(&text, "esbuild", "0.19.12").len(), 1);
    }

    #[test]
    fn install_script_flag_is_read_from_lock_entries() {
        let lock = r#"{"lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/esbuild": {"version": "0.19.12", "hasInstallScript": true},
            "node_modules/plain": {"version": "1.0.0"},
            "node_modules/p/node_modules/bundled": {"version": "1.0.0", "hasInstallScript": true, "inBundle": true},
            "node_modules/al": {"name": "aliased", "version": "2.0.0", "hasInstallScript": true}
        }}"#;
        assert!(lock_has_install_script(lock, "esbuild", "0.19.12"));
        assert!(!lock_has_install_script(lock, "esbuild", "0.19.11"));
        assert!(!lock_has_install_script(lock, "plain", "1.0.0"));
        assert!(!lock_has_install_script(lock, "bundled", "1.0.0"));
        assert!(lock_has_install_script(lock, "aliased", "2.0.0"));
        assert!(!lock_has_install_script(lock, "app", "1.0.0"));
    }
}
