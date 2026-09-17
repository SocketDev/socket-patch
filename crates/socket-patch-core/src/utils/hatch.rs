use std::collections::BTreeMap;

use toml_edit::{DocumentMut, Item, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::preserve_line_endings;
use crate::vendor::common::pep508_name;

pub fn is_hatch(files: &BTreeMap<String, String>) -> bool {
    files.contains_key("hatch.toml")
        || files.get("pyproject.toml").is_some_and(|text| {
            text.parse::<DocumentMut>().is_ok_and(|document| {
                document
                    .get("tool")
                    .and_then(|tool| tool.get("hatch"))
                    .is_some()
                    || document
                        .get("build-system")
                        .and_then(|build| build.get("build-backend"))
                        .and_then(Item::as_str)
                        == Some("hatchling.build")
            })
        })
}

pub fn has_environment_dependency(files: &BTreeMap<String, String>, name: &str) -> bool {
    let external = files
        .get("hatch.toml")
        .and_then(|text| text.parse::<DocumentMut>().ok());
    let project = files
        .get("pyproject.toml")
        .and_then(|text| text.parse::<DocumentMut>().ok());
    let environments = external
        .as_ref()
        .and_then(|document| document.get("envs"))
        .or_else(|| {
            project
                .as_ref()
                .and_then(|document| document.get("tool"))
                .and_then(|tool| tool.get("hatch"))
                .and_then(|hatch| hatch.get("envs"))
        });
    environments
        .and_then(Item::as_table_like)
        .is_some_and(|environments| {
            environments.iter().any(|(_, environment)| {
                ["dependencies", "extra-dependencies"].iter().any(|key| {
                    environment
                        .get(key)
                        .and_then(Item::as_array)
                        .is_some_and(|dependencies| {
                            dependencies.iter().filter_map(Value::as_str).any(|spec| {
                                canonicalize_pypi_name(pep508_name(spec))
                                    == canonicalize_pypi_name(name)
                            })
                        })
                })
            })
        })
}

fn replacement(spec: &str, name: &str, version: &str, url: &str) -> Result<Option<String>, String> {
    let declared = pep508_name(spec);
    if canonicalize_pypi_name(declared) != name {
        return Ok(None);
    }
    if spec.contains(['\r', '\n']) {
        return Err(format!("{name}: multiline requirements are unsupported"));
    }
    let mut rest = spec.trim_start()[declared.len()..].trim_start();
    let extras = if rest.starts_with('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("{name}: invalid extras"))?;
        let extras = &rest[..=end];
        rest = rest[end + 1..].trim_start();
        extras
    } else {
        ""
    };
    let (constraint, marker) = rest
        .split_once(';')
        .map_or((rest, ""), |(left, right)| (left, right));
    let constraint: String = constraint
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if constraint.starts_with('@') {
        let existing = constraint.trim_start_matches('@');
        if existing == url {
            return Ok(Some(spec.to_owned()));
        }
        return Err(format!(
            "{name}: an existing direct source must be reverted before patching"
        ));
    }
    if constraint != format!("=={version}") {
        return Err(format!(
            "{name}: Hatch patching requires an exact =={version} declaration"
        ));
    }
    let suffix = if marker.trim().is_empty() {
        String::new()
    } else {
        format!(" ; {}", marker.trim())
    };
    Ok(Some(format!("{declared}{extras} @ {url}{suffix}")))
}

fn rewrite_array(item: &mut Item, name: &str, version: &str, url: &str) -> Result<usize, String> {
    let array = item
        .as_array_mut()
        .ok_or("dependency declarations must be arrays")?;
    let mut matched = 0;
    for entry in array.iter_mut() {
        if entry.is_inline_table() {
            continue;
        }
        let text = entry
            .as_str()
            .ok_or("dependency declarations must contain strings")?;
        if let Some(rewritten) = replacement(text, name, version, url)? {
            matched += 1;
            if rewritten != text {
                let decoration = entry.decor().clone();
                *entry = Value::from(rewritten);
                *entry.decor_mut() = decoration;
            }
        }
    }
    Ok(matched)
}

fn rewrite_project(
    document: &mut DocumentMut,
    name: &str,
    version: &str,
    url: &str,
) -> Result<usize, String> {
    let mut matched = 0;
    if let Some(project) = document.get_mut("project") {
        if project
            .get("dynamic")
            .and_then(Item::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|v| matches!(v.as_str(), Some("dependencies" | "optional-dependencies")))
            })
        {
            return Err("dynamic project dependencies require the install hook".into());
        }
        if let Some(dependencies) = project
            .as_table_like_mut()
            .and_then(|table| table.get_mut("dependencies"))
        {
            matched += rewrite_array(dependencies, name, version, url)?;
        }
        if let Some(groups) = project
            .as_table_like_mut()
            .and_then(|table| table.get_mut("optional-dependencies"))
        {
            for (_, dependencies) in groups
                .as_table_like_mut()
                .ok_or("optional dependencies must be a table")?
                .iter_mut()
            {
                matched += rewrite_array(dependencies, name, version, url)?;
            }
        }
    }
    if let Some(groups) = document.get_mut("dependency-groups") {
        for (_, dependencies) in groups
            .as_table_like_mut()
            .ok_or("dependency groups must be a table")?
            .iter_mut()
        {
            let group_matches = rewrite_array(dependencies, name, version, url)?;
            if group_matches > 0 && url.starts_with("{root:uri}") {
                return Err("Hatch does not expand root placeholders in dependency groups; use environment dependencies or the install hook".into());
            }
            matched += group_matches;
        }
    }
    Ok(matched)
}

fn rewrite_environments(
    hatch: &mut Item,
    name: &str,
    version: &str,
    url: &str,
) -> Result<usize, String> {
    if hatch.get("sources").is_some() || hatch.get("env").is_some() {
        return Err("Hatch sources and environment plugins require the install hook".into());
    }
    let mut matched = 0;
    if let Some(environments) = hatch
        .as_table_like_mut()
        .and_then(|table| table.get_mut("envs"))
    {
        for (_, environment) in environments
            .as_table_like_mut()
            .ok_or("Hatch environments must be a table")?
            .iter_mut()
        {
            if environment.get("sources").is_some()
                || environment.get("overrides").is_some()
                || environment
                    .get("type")
                    .and_then(Item::as_str)
                    .is_some_and(|kind| kind != "virtual")
            {
                return Err(
                    "Hatch sources, overrides and custom environments require the install hook"
                        .into(),
                );
            }
            for key in ["dependencies", "extra-dependencies"] {
                if let Some(dependencies) = environment
                    .as_table_like_mut()
                    .and_then(|table| table.get_mut(key))
                {
                    matched += rewrite_array(dependencies, name, version, url)?;
                }
            }
        }
    }
    Ok(matched)
}

pub struct HatchPermission {
    pub file: String,
    pub original: String,
    pub new: String,
}

pub struct HatchPlan {
    pub files: BTreeMap<String, String>,
    pub permission: Option<HatchPermission>,
}

pub fn rewrite(
    files: &BTreeMap<String, String>,
    name: &str,
    version: &str,
    url: &str,
) -> Result<BTreeMap<String, String>, String> {
    plan(files, name, version, url).map(|plan| plan.files)
}

fn enable_permission(document: &mut DocumentMut, external: bool) -> Result<(), String> {
    let keys: &[&str] = if external {
        &["metadata"]
    } else {
        &["tool", "hatch", "metadata"]
    };
    let mut table: &mut dyn toml_edit::TableLike = document.as_table_mut();
    for key in keys {
        if !table.contains_key(key) {
            table.insert(key, Item::Table(toml_edit::Table::new()));
        }
        table = table
            .get_mut(key)
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| format!("{key} must be a TOML table"))?;
    }
    if table
        .get("allow-direct-references")
        .is_some_and(|item| !item.is_bool())
    {
        return Err("allow-direct-references must be a boolean".into());
    }
    table.insert("allow-direct-references", toml_edit::value(true));
    Ok(())
}

pub fn has_project_direct_references(files: &BTreeMap<String, String>) -> bool {
    let Some(document) = files
        .get("pyproject.toml")
        .and_then(|text| text.parse::<DocumentMut>().ok())
    else {
        return false;
    };
    let project = document.get("project");
    let mut arrays = Vec::new();
    if let Some(dependencies) = project
        .and_then(|project| project.get("dependencies"))
        .and_then(Item::as_array)
    {
        arrays.push(dependencies);
    }
    for groups in [
        project.and_then(|project| project.get("optional-dependencies")),
        document.get("dependency-groups"),
    ] {
        if let Some(groups) = groups.and_then(Item::as_table_like) {
            arrays.extend(groups.iter().filter_map(|(_, value)| value.as_array()));
        }
    }
    arrays.iter().any(|array| {
        array.iter().filter_map(Value::as_str).any(|spec| {
            spec.split(';')
                .next()
                .is_some_and(|requirement| requirement.contains('@'))
        })
    })
}

pub fn plan(
    files: &BTreeMap<String, String>,
    name: &str,
    version: &str,
    url: &str,
) -> Result<HatchPlan, String> {
    let name = canonicalize_pypi_name(name);
    let mut documents = BTreeMap::new();
    for file in ["pyproject.toml", "hatch.toml"] {
        if let Some(text) = files.get(file) {
            documents.insert(
                file,
                text.parse::<DocumentMut>()
                    .map_err(|error| format!("{file}: {error}"))?,
            );
        }
    }
    if url.starts_with("{root:uri}") {
        for document in documents.values() {
            let hatch = document
                .get("tool")
                .and_then(|tool| tool.get("hatch"))
                .unwrap_or(document.as_item());
            if hatch
                .get("envs")
                .and_then(Item::as_table_like)
                .is_some_and(|envs| {
                    envs.iter().any(|(_, env)| {
                        env.get("installer").and_then(Item::as_str) == Some("uv")
                            || env
                                .get("uv-path")
                                .and_then(Item::as_str)
                                .is_some_and(|path| !path.is_empty())
                    })
                })
            {
                return Err("vendored Hatch wheels require the pip installer: uv does not enforce local wheel fragment hashes".into());
            }
        }
    }
    let mut matched = 0;
    let mut project_matched = 0;
    if let Some(project) = documents.get_mut("pyproject.toml") {
        project_matched = rewrite_project(project, &name, version, url)?;
        matched += project_matched;
    }
    // Hatch merges external configuration by top-level key, not recursively.
    let external_keys: Vec<String> = documents
        .get("hatch.toml")
        .map(|d| d.iter().map(|(k, _)| k.to_owned()).collect())
        .unwrap_or_default();
    if let Some(document) = documents.get_mut("pyproject.toml") {
        if let Some(hatch) = document.get_mut("tool").and_then(|tool| {
            tool.as_table_like_mut()
                .and_then(|table| table.get_mut("hatch"))
        }) {
            let mut effective = hatch.clone();
            if let Some(table) = effective.as_table_like_mut() {
                for key in &external_keys {
                    table.remove(key);
                }
            }
            matched += rewrite_environments(&mut effective, &name, version, url)?;
            if let Some(table) = effective.as_table_like() {
                for (key, item) in table.iter() {
                    hatch[key] = item.clone();
                }
            }
        }
    }
    if let Some(document) = documents.get_mut("hatch.toml") {
        let mut hatch = Item::Table(document.as_table().clone());
        matched += rewrite_environments(&mut hatch, &name, version, url)?;
        *document.as_table_mut() = hatch
            .as_table()
            .ok_or("invalid Hatch configuration")?
            .clone();
    }
    if matched == 0 {
        return Err(format!("{name}=={version} has no explicit Hatch declaration; transitive-only dependencies require the install hook"));
    }
    let permission = if project_matched > 0 {
        let external = external_keys.iter().any(|key| key == "metadata");
        let file = if external {
            "hatch.toml"
        } else {
            "pyproject.toml"
        };
        let document = documents
            .get_mut(file)
            .ok_or("missing Hatch configuration")?;
        enable_permission(document, external)?;
        let original = files[file].clone();
        let mut permission_only = original
            .parse::<DocumentMut>()
            .map_err(|error| error.to_string())?;
        enable_permission(&mut permission_only, external)?;
        Some(HatchPermission {
            file: file.into(),
            new: preserve_line_endings(&original, permission_only.to_string()),
            original,
        })
    } else {
        None
    };
    let files = documents
        .into_iter()
        .filter_map(|(name, document)| {
            let original = &files[name];
            let new = preserve_line_endings(original, document.to_string());
            (new != *original).then_some((name.to_owned(), new))
        })
        .collect();
    Ok(HatchPlan { files, permission })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(text: &str) -> BTreeMap<String, String> {
        [("pyproject.toml".into(), text.into())]
            .into_iter()
            .collect()
    }

    #[test]
    fn exact_sources_extras_markers_and_newlines() {
        for newline in ["\n", "\r\n"] {
            let original = "[project]\ndependencies = [\"Urllib3[socks]==1.26.18 ; sys_platform == 'win32'\"] # keep\n[tool.hatch.envs.default]\ndependencies = [\"urllib3==1.26.18\"]\n".replace('\n', newline);
            let inputs = files(&original);
            let result = rewrite(
                &inputs,
                "urllib3",
                "1.26.18",
                "https://patch.test/one.whl#sha256=abc",
            )
            .unwrap();
            let patched = &result["pyproject.toml"];
            assert!(patched.contains(
                "Urllib3[socks] @ https://patch.test/one.whl#sha256=abc ; sys_platform == 'win32'"
            ));
            assert!(patched.contains("# keep"));
            assert!(patched.contains("allow-direct-references = true"));
            assert!(rewrite(
                &result,
                "urllib3",
                "1.26.18",
                "https://patch.test/one.whl#sha256=abc"
            )
            .unwrap()
            .is_empty());
            if newline == "\r\n" {
                assert!(!patched.replace("\r\n", "").contains('\n'));
            }
            let (restored, drifted) = crate::vendor::restore_python_document(
                &patched.replace("\r\n", "\n").replace('\n', "\r\n"),
                &original,
                patched,
            )
            .unwrap();
            assert!(!drifted);
            assert_eq!(
                restored.replace("\r\n", "\n"),
                original.replace("\r\n", "\n")
            );
        }
    }

    #[test]
    fn external_tables_override_inline_and_metadata_permissions() {
        let mut inputs = files("[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\ndependencies=[\"urllib3>=0\"]\n");
        inputs.insert("hatch.toml".into(), "[metadata]\nallow-direct-references=false\n[envs.default]\ndependencies=[\"urllib3==1.26.18\"]\n".into());
        let result = rewrite(&inputs, "urllib3", "1.26.18", "https://patch.test/a.whl").unwrap();
        assert!(result["pyproject.toml"].contains("urllib3>=0"));
        assert!(!result["pyproject.toml"].contains("allow-direct-references"));
        let document = result["hatch.toml"].parse::<DocumentMut>().unwrap();
        assert_eq!(
            document["metadata"]["allow-direct-references"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn unsupported_shapes_never_return_partial_edits() {
        for text in [
            "[project]\ndependencies=[\"urllib3>=1\"]",
            "[project]\ndependencies=[\"urllib3==1.26.18\", \"urllib3==2.0.0\"]",
            "[project]\ndynamic=[\"dependencies\"]",
            "[project]\ndependencies=[\"urllib3 @ https://foreign.test/x.whl\"]",
            "[tool.hatch.envs.default]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default.overrides]\nplatform.windows.dependencies=[\"urllib3==1.26.18\"]",
            "[tool.hatch.envs.default]\ndependencies=[\"requests==2.31.0\"]",
            "[project]\ndependencies=[false]",
            "[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch]\nmetadata=false",
            "[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool]\nhatch=false",
            "[project]\ndependencies=[\"urllib3==1.26.18\\nidna==3.6\"]",
        ] {
            assert!(rewrite(&files(text), "urllib3", "1.26.18", "https://patch.test/a.whl").is_err(), "{text}");
        }
    }

    #[test]
    fn uv_installer_and_explicit_path_refuse_local_wheels() {
        for setting in ["installer='uv'", "uv-path='uv'"] {
            let inputs = files(&format!("[project]\ndependencies=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\n{setting}\n"));
            assert!(rewrite(&inputs, "urllib3", "1.26.18", "https://patch.test/a.whl").is_ok());
            assert!(rewrite(
                &inputs,
                "urllib3",
                "1.26.18",
                "{root:uri}/.socket/vendor/a.whl"
            )
            .unwrap_err()
            .contains("pip installer"));
        }
    }

    #[test]
    fn groups_accept_hosted_and_refuse_unexpanded_vendor_context() {
        let inputs = files("[dependency-groups]\nqa=[\"urllib3==1.26.18\"]\n[tool.hatch.envs.default]\ndependency-groups=[\"qa\"]");
        assert!(rewrite(&inputs, "urllib3", "1.26.18", "https://patch.test/a.whl").is_ok());
        assert!(rewrite(
            &inputs,
            "urllib3",
            "1.26.18",
            "{root:uri}/.socket/vendor/a.whl"
        )
        .unwrap_err()
        .contains("does not expand"));
    }
}
