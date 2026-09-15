use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde_json::Value;

use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::purl::percent_decode_purl_component;

struct LogicalRequirement {
    original: String,
    text: String,
    ending: String,
    unterminated: bool,
}

fn logical_requirements(content: &str) -> Vec<LogicalRequirement> {
    let physical: Vec<&str> = content.split_inclusive('\n').collect();
    let mut requirements = Vec::new();
    let mut index = 0;
    while index < physical.len() {
        let start = index;
        let mut original = String::new();
        let mut text = String::new();
        loop {
            let physical_line = physical[index];
            let (body, ending) = if let Some(body) = physical_line.strip_suffix("\r\n") {
                (body, "\r\n")
            } else if let Some(body) = physical_line.strip_suffix('\n') {
                (body, "\n")
            } else {
                (physical_line, "")
            };
            let parsed_body = if index == 0 {
                body.strip_prefix('\u{feff}').unwrap_or(body)
            } else {
                body
            };
            let continued =
                !parsed_body.trim_start().starts_with('#') && body.trim_end().ends_with('\\');
            if continued && index + 1 < physical.len() {
                original.push_str(physical_line);
                text.push_str(body.trim_end().strip_suffix('\\').unwrap_or(body));
                index += 1;
                continue;
            }
            original.push_str(body);
            text.push_str(body);
            if start == 0 {
                text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned();
            }
            requirements.push(LogicalRequirement {
                original,
                text,
                ending: ending.to_owned(),
                unterminated: continued,
            });
            index += 1;
            break;
        }
    }
    requirements
}

fn unquoted_index(text: &str, target: char, after_whitespace: bool) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    let mut previous = None;
    for (index, character) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if quote == Some(character) {
            quote = None;
        } else if quote.is_none() {
            if character == '\'' || character == '"' {
                quote = Some(character);
            } else if character == target
                && (!after_whitespace || previous.is_none_or(char::is_whitespace))
            {
                return Some(index);
            }
        }
        previous = Some(character);
    }
    None
}

fn requirement_tokens(text: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in text.char_indices() {
        if quote.is_none() && character.is_whitespace() {
            if let Some(start) = start.take() {
                tokens.push(&text[start..index]);
            }
            continue;
        }
        start.get_or_insert(index);
        if escaped {
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if quote == Some(character) {
            quote = None;
        } else if quote.is_none() && (character == '\'' || character == '"') {
            quote = Some(character);
        }
    }
    if let Some(start) = start {
        tokens.push(&text[start..]);
    }
    tokens
}

fn without_hashes(text: &str) -> String {
    let mut kept = Vec::new();
    let mut tokens = requirement_tokens(text).into_iter();
    while let Some(token) = tokens.next() {
        if token == "--hash" {
            tokens.next();
        } else if !token.starts_with("--hash=") {
            kept.push(token);
        }
    }
    kept.join(" ")
}

enum RequirementVersion {
    Exact(String),
    Unpinned,
    Ambiguous,
}

fn archive_version(location: &str, name: &str) -> Option<String> {
    let url = reqwest::Url::parse(location).ok()?;
    let filename = percent_decode_purl_component(url.path().rsplit('/').next()?);
    let (distribution, version) = if let Some(stem) = filename.strip_suffix(".whl") {
        let mut parts = stem.splitn(3, '-');
        let distribution = parts.next()?;
        let version = parts.next()?;
        parts.next()?;
        (distribution, version)
    } else {
        let stem = [".tar.gz", ".zip", ".tar.bz2", ".tar.xz"]
            .into_iter()
            .find_map(|suffix| filename.strip_suffix(suffix))?;
        stem.rsplit_once('-')?
    };
    (canonicalize_pypi_name(distribution) == name && !version.is_empty())
        .then(|| version.to_string())
}

fn requirement_version(specifier: &str, name_re: &Regex, name: &str) -> RequirementVersion {
    let Some(captures) = name_re.captures(specifier.trim()) else {
        return RequirementVersion::Ambiguous;
    };
    let end = captures.get(2).or_else(|| captures.get(1)).unwrap().end();
    let tail = &specifier.trim()[end..];
    let tail = requirement_tokens(tail)
        .into_iter()
        .take_while(|token| !token.starts_with("--"))
        .collect::<Vec<_>>()
        .join(" ");
    let tail = tail.trim();
    let tail = tail
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(tail)
        .trim();
    if tail.is_empty() {
        return RequirementVersion::Unpinned;
    }
    if let Some(location) = tail.strip_prefix('@') {
        return archive_version(location.trim(), name)
            .map_or(RequirementVersion::Ambiguous, RequirementVersion::Exact);
    }
    if let Some(version) = tail.strip_prefix("===").or_else(|| tail.strip_prefix("==")) {
        let version = version.trim();
        if !version.is_empty()
            && !version
                .chars()
                .any(|character| character.is_whitespace() || ",*<>=~".contains(character))
        {
            return RequirementVersion::Exact(version.to_string());
        }
    }
    RequirementVersion::Ambiguous
}

pub(super) fn rewrite(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let Some(content) = files.get("requirements.txt") else {
        return;
    };
    let name_re = Regex::new(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)(\s*\[[^\]\r\n]*\])?\s*(?:[=<>~!]=?|@|;|\(|\s|$)",
    )
    .expect("static requirements-name regex is valid");
    let mut requirements = logical_requirements(content);
    let mut row_counts = BTreeMap::<String, usize>::new();
    for requirement in &requirements {
        if let Some(captures) = name_re.captures(requirement.text.trim()) {
            *row_counts
                .entry(canonicalize_pypi_name(&captures[1]))
                .or_default() += 1;
        }
    }
    let mut override_versions = BTreeMap::<String, BTreeSet<&str>>::new();
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        override_versions
            .entry(canonicalize_pypi_name(&dep.name))
            .or_default()
            .insert(&dep.version);
    }
    let mut changed = false;
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        let Some(sha256) = &dep.integrity.sha256 else {
            result.warnings.push(RewriteWarning {
                code: "redirect_requirements_missing_sha256".into(),
                detail: format!("{} has no sha256 integrity", dep.name),
            });
            continue;
        };
        let target = canonicalize_pypi_name(&dep.name);
        let mut matched = false;
        for requirement in &mut requirements {
            let text = requirement.text.trim();
            let Some(captures) = name_re.captures(text) else {
                continue;
            };
            if canonicalize_pypi_name(&captures[1]) != target {
                continue;
            }
            if requirement.unterminated {
                matched = true;
                result.warnings.push(RewriteWarning {
                    code: "redirect_requirements_continuation".into(),
                    detail: format!(
                        "{}@{} has an unterminated continuation; not rewritten",
                        dep.name, dep.version
                    ),
                });
                continue;
            }
            let (body, comment) = unquoted_index(text, '#', true)
                .map_or((text, ""), |index| (&text[..index], &text[index..]));
            let cleaned = without_hashes(body);
            let (specifier, marker) = unquoted_index(&cleaned, ';', false)
                .map_or((cleaned.as_str(), ""), |index| {
                    (&cleaned[..index], &cleaned[index..])
                });
            match requirement_version(specifier, &name_re, &target) {
                RequirementVersion::Exact(version) if version != dep.version => continue,
                RequirementVersion::Exact(_) => {}
                RequirementVersion::Unpinned
                    if row_counts.get(&target) == Some(&1)
                        && override_versions
                            .get(&target)
                            .is_some_and(|versions| versions.len() == 1) => {}
                _ => {
                    matched = true;
                    result.warnings.push(RewriteWarning {
                        code: "redirect_requirements_version_ambiguous".into(),
                        detail: format!(
                            "requirements.txt does not uniquely pin {}@{}; not rewritten",
                            dep.name, dep.version
                        ),
                    });
                    continue;
                }
            }
            matched = true;
            let options = requirement_tokens(specifier)
                .into_iter()
                .skip_while(|token| !token.starts_with("--"))
                .collect::<Vec<_>>()
                .join(" ");
            let extras = captures
                .get(2)
                .map_or("", |capture| capture.as_str().trim());
            let prefix_body = requirement
                .original
                .strip_prefix('\u{feff}')
                .unwrap_or(&requirement.original);
            let indent = &prefix_body
                [..prefix_body.len() - prefix_body.trim_start_matches([' ', '\t']).len()];
            let bom = if requirement.original.starts_with('\u{feff}') {
                "\u{feff}"
            } else {
                ""
            };
            let mut rewritten = format!("{bom}{indent}{}{extras} @ {}", dep.name, dep.artifact_url);
            for suffix in [marker.trim(), options.as_str()] {
                if !suffix.is_empty() {
                    rewritten.push(' ');
                    rewritten.push_str(suffix);
                }
            }
            rewritten.push_str(&format!(" --hash=sha256:{sha256}"));
            if !comment.is_empty() {
                rewritten.push(' ');
                rewritten.push_str(comment);
            }
            if rewritten != requirement.original {
                result.edits.push(FileEdit {
                    path: "requirements.txt".into(),
                    kind: "redirect_requirements_line".into(),
                    action: "rewritten".into(),
                    key: Some(dep.name.clone()),
                    original: Some(Value::String(requirement.original.clone())),
                    new: Some(Value::String(rewritten.clone())),
                });
                requirement.text = rewritten
                    .strip_prefix('\u{feff}')
                    .unwrap_or(&rewritten)
                    .to_owned();
                requirement.original = rewritten;
                changed = true;
            }
        }
        if !matched {
            result.warnings.push(RewriteWarning {
                code: "redirect_requirements_entry_not_found".into(),
                detail: format!("no requirements.txt entry for {}@{}", dep.name, dep.version),
            });
        }
    }
    if changed {
        let output = requirements
            .into_iter()
            .map(|requirement| requirement.original + &requirement.ending)
            .collect();
        result.files.insert("requirements.txt".into(), output);
    }
}

#[cfg(test)]
mod tests {
    use super::super::{rewrite_registry_redirect, Integrity};
    use super::*;

    const URL: &str = "https://patch.socket.dev/patch/pypi/requests/2.28.1/11111111-1111-1111-1111-111111111111/33333333-3333-3333-3333-333333333333/requests-2.28.1-py3-none-any.whl";
    const HASH: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn patch() -> DepOverride {
        DepOverride {
            ecosystem: "pypi".into(),
            name: "requests".into(),
            namespace: None,
            version: "2.28.1".into(),
            token: "11111111-1111-1111-1111-111111111111".into(),
            patch_uuid: "33333333-3333-3333-3333-333333333333".into(),
            artifact_url: URL.into(),
            integrity: Integrity {
                sha256: Some(HASH.into()),
                ..Default::default()
            },
            berry_zip_url: None,
            registry_override: None,
        }
    }

    fn input(text: &str) -> BTreeMap<String, String> {
        BTreeMap::from([("requirements.txt".into(), text.into())])
    }

    #[test]
    fn continued_hashes_extras_and_markers_are_rewritten_together() {
        let source = "flask==2.0.1\nrequests[security,socks]==2.28.1 ; python_version >= \"3.7\" \\\n    --hash=sha256:OLD_ONE \\\n    --hash sha256:OLD_TWO # via application\ncertifi==2024.2.2\n";
        let result = rewrite_registry_redirect(&input(source), &[patch()]);
        let expected = format!("flask==2.0.1\nrequests[security,socks] @ {URL} ; python_version >= \"3.7\" --hash=sha256:{HASH} # via application\ncertifi==2024.2.2\n");
        assert_eq!(result.files.get("requirements.txt"), Some(&expected));
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.edits.len(), 1);
        assert_eq!(
            result.edits[0].original,
            Some(Value::String(
                source
                    .split_once('\n')
                    .unwrap()
                    .1
                    .rsplit_once('\n')
                    .unwrap()
                    .0
                    .rsplit_once('\n')
                    .unwrap()
                    .0
                    .to_owned()
            ))
        );
        let rerun = rewrite_registry_redirect(&input(&expected), &[patch()]);
        assert!(rerun.files.is_empty() && rerun.edits.is_empty());
        assert!(rerun.warnings.is_empty());
    }

    #[test]
    fn markers_after_hashes_and_hash_text_in_quoted_markers_are_preserved() {
        let source = "requests==2.28.1 --hash=sha256:OLD ; platform_version != \"text --hash=keep # retained\"\n";
        let result = rewrite_registry_redirect(&input(source), &[patch()]);
        assert_eq!(
            result.files["requirements.txt"],
            format!("requests @ {URL} ; platform_version != \"text --hash=keep # retained\" --hash=sha256:{HASH}\n")
        );
    }

    #[test]
    fn line_endings_bom_indentation_and_unrelated_bytes_are_preserved() {
        for ending in ["\n", "\r\n"] {
            let source = format!("\u{feff}  requests==2.28.1 \\{ending}\t--hash=sha256:OLD{ending}# unchanged{ending}flask==2.0.1");
            let result = rewrite_registry_redirect(&input(&source), &[patch()]);
            assert_eq!(
                result.files["requirements.txt"],
                format!("\u{feff}  requests @ {URL} --hash=sha256:{HASH}{ending}# unchanged{ending}flask==2.0.1")
            );
            assert!(result.edits[0]
                .original
                .as_ref()
                .unwrap()
                .as_str()
                .unwrap()
                .contains(ending));
        }
        let result = rewrite_registry_redirect(&input("requests==2.28.1"), &[patch()]);
        assert!(!result.files["requirements.txt"].ends_with('\n'));
    }

    #[test]
    fn full_line_comments_do_not_continue_into_requirements() {
        for prefix in ["", "\u{feff}"] {
            let source = format!("{prefix}# documentation \\\nrequests==2.28.1\n");
            let result = rewrite_registry_redirect(&input(&source), &[patch()]);
            assert_eq!(
                result.files["requirements.txt"],
                format!("{prefix}# documentation \\\nrequests @ {URL} --hash=sha256:{HASH}\n")
            );
        }
    }

    #[test]
    fn non_hash_options_are_preserved() {
        let source = "requests==2.28.1 --config-settings=key=value --hash=sha256:OLD ; python_version >= \"3.7\"\n";
        let result = rewrite_registry_redirect(&input(source), &[patch()]);
        assert_eq!(result.files["requirements.txt"], format!("requests @ {URL} ; python_version >= \"3.7\" --config-settings=key=value --hash=sha256:{HASH}\n"));
    }

    #[test]
    fn unterminated_continuation_is_unchanged_and_warned() {
        for source in ["requests==2.28.1 \\", "requests==2.28.1 \\\n"] {
            let result = rewrite_registry_redirect(&input(source), &[patch()]);
            assert!(result.files.is_empty() && result.edits.is_empty());
            assert_eq!(result.warnings.len(), 1);
            assert_eq!(
                result.warnings[0].code,
                "redirect_requirements_continuation"
            );
        }
    }

    #[test]
    fn absent_package_retains_entry_not_found_warning() {
        let result = rewrite_registry_redirect(&input("flask==2.0.1\n"), &[patch()]);
        assert!(result.files.is_empty() && result.edits.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].code,
            "redirect_requirements_entry_not_found"
        );
    }

    #[test]
    fn conditional_versions_keep_their_own_artifacts_and_hashes() {
        let unchanged = "requests==2.32.0 ; python_version >= '3.10' \\\n    --hash=sha256:OTHER_ONE \\\n    --hash=sha256:OTHER_TWO\n";
        let source = format!(
            "requests[socks]==2.28.1 ; python_version < '3.10' \\\n    --hash=sha256:OLD\n{unchanged}"
        );
        let result = rewrite_registry_redirect(&input(&source), &[patch()]);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.edits.len(), 1);
        assert_eq!(
            result.files["requirements.txt"],
            format!("requests[socks] @ {URL} ; python_version < '3.10' --hash=sha256:{HASH}\n{unchanged}")
        );
    }

    #[test]
    fn multiple_version_overrides_are_independent_of_order() {
        let source = "requests==2.28.1 ; python_version < '3.10'\nrequests==2.32.0 ; python_version >= '3.10'\n";
        let mut other = patch();
        other.version = "2.32.0".into();
        other.artifact_url = URL.replace("2.28.1", "2.32.0");
        other.integrity.sha256 = Some("d".repeat(64));
        let expected = format!(
            "requests @ {URL} ; python_version < '3.10' --hash=sha256:{HASH}\nrequests @ {} ; python_version >= '3.10' --hash=sha256:{}\n",
            other.artifact_url,
            "d".repeat(64)
        );
        for overrides in [vec![patch(), other.clone()], vec![other.clone(), patch()]] {
            let result = rewrite_registry_redirect(&input(source), &overrides);
            assert!(result.warnings.is_empty(), "{:?}", result.warnings);
            assert_eq!(result.edits.len(), 2);
            assert_eq!(result.files["requirements.txt"], expected);
            let rerun = rewrite_registry_redirect(&input(&expected), &overrides);
            assert!(rerun.files.is_empty() && rerun.edits.is_empty());
            assert!(rerun.warnings.is_empty(), "{:?}", rerun.warnings);
        }
    }

    #[test]
    fn archive_urls_select_the_matching_distribution_version() {
        let other = URL.replace("2.28.1", "2.32.0");
        let previous = URL.replace("11111111", "22222222");
        let source = format!(
            "requests @ {previous} --hash=sha256:OLD\nrequests @ {other} --hash=sha256:OTHER\n"
        );
        let result = rewrite_registry_redirect(&input(&source), &[patch()]);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(
            result.files["requirements.txt"],
            format!(
                "requests @ {URL} --hash=sha256:{HASH}\nrequests @ {other} --hash=sha256:OTHER\n"
            )
        );
        assert_eq!(result.edits.len(), 1);
        for source in [
            "requests @ https://files.pythonhosted.org/requests-2.28.1.tar.gz#sha256=old",
            "requests ( == 2.28.1 )",
            "requests===2.28.1",
        ] {
            let result = rewrite_registry_redirect(&input(source), &[patch()]);
            assert_eq!(
                result.files["requirements.txt"],
                format!("requests @ {URL} --hash=sha256:{HASH}")
            );
        }
    }

    #[test]
    fn ambiguous_versions_are_preserved_and_reported() {
        for source in [
            "requests ; python_version < '3.10'\nrequests ; python_version >= '3.10'\n",
            "requests>=2.0\n",
            "requests==2.*\n",
            "requests @ https://example.test/download\n",
        ] {
            let result = rewrite_registry_redirect(&input(source), &[patch()]);
            assert!(result.files.is_empty() && result.edits.is_empty());
            assert!(!result.warnings.is_empty());
            assert!(result
                .warnings
                .iter()
                .all(|warning| warning.code == "redirect_requirements_version_ambiguous"));
        }
        let result = rewrite_registry_redirect(&input("requests\n"), &[patch()]);
        assert_eq!(
            result.files["requirements.txt"],
            format!("requests @ {URL} --hash=sha256:{HASH}\n")
        );
        let mut other = patch();
        other.version = "2.32.0".into();
        other.artifact_url = URL.replace("2.28.1", "2.32.0");
        let result = rewrite_registry_redirect(&input("requests\n"), &[patch(), other]);
        assert!(result.files.is_empty() && result.edits.is_empty());
        assert_eq!(result.warnings.len(), 2);
    }
}
