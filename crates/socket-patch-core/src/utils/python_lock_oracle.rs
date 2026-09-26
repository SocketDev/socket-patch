//! The pre-single-parse text rewriters, kept verbatim as `#[cfg(test)]`
//! oracles for the hosted uv / pylock / PEP 723 rewriter, which now plans,
//! applies and completes every dep against one parsed document
//! ([`super::PythonLockSession`]).

use super::*;

pub(crate) fn complete_python_lock_metadata(
    text: &str,
    project: Option<&str>,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    wheel_metadata: Option<&str>,
) -> Result<String, String> {
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid Python lock: {error}"))?;
    if document
        .get("package")
        .and_then(Item::as_array_of_tables)
        .is_none()
    {
        return Ok(text.to_string());
    }
    let name = canonicalize_pypi_name(name);
    if let Some(project) = project {
        let project: DocumentMut = project
            .parse()
            .map_err(|error| format!("invalid pyproject.toml: {error}"))?;
        let packages = document
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
            .expect("package collection checked");
        for package in packages.iter_mut() {
            let root = package
                .get("source")
                .and_then(Item::as_table_like)
                .is_some_and(|source| {
                    ["virtual", "editable"]
                        .into_iter()
                        .any(|key| source.get(key).and_then(Item::as_str) == Some("."))
                });
            if root {
                if let Some(metadata) = package
                    .get_mut("metadata")
                    .and_then(Item::as_table_like_mut)
                {
                    for key in ["requires-dist", "requires-dev"] {
                        if let Some(requirements) = metadata.get_mut(key) {
                            rewrite_requirement_sources(requirements, &name, artifact);
                        }
                    }
                }
            }
        }
        let overridden = project
            .get("tool")
            .and_then(Item::as_table_like)
            .and_then(|tool| tool.get("uv"))
            .and_then(Item::as_table_like)
            .and_then(|uv| uv.get("override-dependencies"))
            .and_then(Item::as_array)
            .is_some_and(|overrides| {
                overrides.iter().filter_map(Value::as_str).any(|specifier| {
                    canonicalize_pypi_name(
                        specifier
                            .split(|ch: char| {
                                !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.'
                            })
                            .next()
                            .unwrap_or_default(),
                    ) == name
                })
            });
        if overridden {
            let manifest = document
                .entry("manifest")
                .or_insert(Item::Table(Table::new()))
                .as_table_like_mut()
                .ok_or("uv manifest must be a table")?;
            let overrides = manifest
                .entry("overrides")
                .or_insert(Item::Value(Value::Array(Array::new())));
            let exists = overrides.as_array().is_some_and(|overrides| {
                overrides
                    .iter()
                    .filter_map(Value::as_inline_table)
                    .any(|requirement| {
                        requirement
                            .get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|value| canonicalize_pypi_name(value) == name)
                    })
            });
            if exists {
                rewrite_requirement_sources(overrides, &name, artifact);
            } else {
                overrides
                    .as_array_mut()
                    .ok_or("uv manifest overrides must be an array")?
                    .push_formatted(inline(&[
                        ("name", Value::from(name.as_str())),
                        (artifact.key(), Value::from(artifact.location())),
                    ]));
            }
        }
    }
    if let Some(metadata) = wheel_metadata {
        let metadata: DocumentMut = metadata
            .parse()
            .map_err(|error| format!("invalid wheel metadata: {error}"))?;
        let metadata = metadata
            .get("package")
            .and_then(Item::as_table_like)
            .and_then(|package| package.get("metadata"))
            .and_then(Item::as_table)
            .ok_or("wheel metadata has no package metadata table")?;
        for package in document
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
            .expect("package collection checked")
            .iter_mut()
        {
            if matching_package(package, &name, version) {
                let mut metadata = metadata.clone();
                metadata.set_position(None);
                package.insert("metadata", Item::Table(metadata));
            }
        }
    }
    Ok(preserve_line_endings(text, document.to_string()))
}

pub(crate) fn rewrite_python_lock(
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    sha256: &str,
) -> Result<Option<String>, String> {
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid Python lock: {error}"))?;
    let Some(PythonLockPlan {
        pep751,
        legacy,
        collection,
        index,
        name,
        original_source,
        legacy_strings,
        legacy_artifact_tables,
    }) = plan_python_lock_rewrite(&document, text, name, version, artifact)?
    else {
        return Ok(None);
    };
    let package = document
        .get_mut(collection)
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|packages| packages.get_mut(index))
        .expect("planned package index exists");
    let location = artifact.location();
    let filename = location
        .split(['?', '#'])
        .next()
        .unwrap_or(&location)
        .rsplit('/')
        .next()
        .unwrap_or(&location);
    let wheel = filename.ends_with(".whl");
    for key in ["sdist", "wheel", "wheels", "archive"] {
        package.remove(key);
    }
    if pep751 {
        package.remove("index");
        let hashes = inline(&[("sha256", Value::from(sha256))]);
        package.insert(
            "archive",
            Item::Value(inline(&[
                (artifact.key(), Value::from(location)),
                ("hashes", hashes),
            ])),
        );
    } else {
        let source = if legacy_strings {
            Item::Value(Value::from(format!("direct+{location}")))
        } else {
            Item::Value(inline(&[(artifact.key(), Value::from(location.clone()))]))
        };
        package.insert("source", source.clone());
        let artifact_key = if matches!(artifact, ArtifactSource::Path(_)) && wheel {
            "filename"
        } else {
            "url"
        };
        let artifact_location = if artifact_key == "filename" {
            filename
        } else {
            &location
        };
        let entry = inline(&[
            (artifact_key, Value::from(artifact_location)),
            ("hash", Value::from(format!("sha256:{sha256}"))),
        ]);
        if legacy_artifact_tables && wheel {
            let mut table = Table::new();
            table["url"] = toml_edit::value(artifact_location);
            table["hash"] = toml_edit::value(format!("sha256:{sha256}"));
            let mut array = ArrayOfTables::new();
            array.push(table);
            package.insert("wheel", Item::ArrayOfTables(array));
        } else if wheel {
            let mut array = Array::new();
            array.push_formatted(entry);
            package.insert("wheels", Item::Value(Value::Array(array)));
        } else if legacy_artifact_tables {
            let mut table = Table::new();
            table["url"] = toml_edit::value(artifact_location);
            table["hash"] = toml_edit::value(format!("sha256:{sha256}"));
            package.insert("sdist", Item::Table(table));
        } else {
            package.insert("sdist", Item::Value(entry));
        }
        if let Some(original_source) = original_source {
            rewrite_references(
                document.as_item_mut(),
                &name,
                version,
                &original_source,
                &source,
            );
        }
    }
    if !pep751 && !legacy {
        rewrite_manifest(&mut document, &name, artifact);
    }
    Ok(Some(preserve_line_endings(text, document.to_string())))
}
