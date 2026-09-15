use std::ops::Range;

use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::ArtifactSource;

pub(crate) fn script_metadata(text: &str) -> Result<(Range<usize>, String), String> {
    let mut offset = 0;
    let mut start = None;
    let mut metadata = String::new();
    let mut block = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "# /// script" {
            if start.is_some() || block.is_some() {
                return Err("multiple PEP 723 script metadata blocks".to_string());
            }
            start = Some(offset + line.len());
        } else if let Some(begin) = start {
            if trimmed == "# ///" {
                block = Some((begin..offset, metadata.clone()));
                start = None;
            } else {
                let content = trimmed
                    .strip_prefix("# ")
                    .or_else(|| trimmed.strip_prefix('#'))
                    .ok_or_else(|| "invalid PEP 723 metadata comment".to_string())?;
                metadata.push_str(content);
                metadata.push('\n');
            }
        }
        offset += line.len();
    }
    if start.is_some() {
        return Err("unclosed PEP 723 script metadata block".to_string());
    }
    block.ok_or_else(|| "script has no PEP 723 metadata block".to_string())
}

pub(crate) fn replace_script_metadata(text: &str, metadata: &str) -> Result<String, String> {
    let (span, _) = script_metadata(text)?;
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut replacement = String::new();
    for line in metadata.lines() {
        replacement.push('#');
        if !line.is_empty() {
            replacement.push(' ');
            replacement.push_str(line);
        }
        replacement.push_str(newline);
    }
    let mut output = text.to_string();
    output.replace_range(span, &replacement);
    Ok(output)
}

fn dependency_name(specifier: &str) -> String {
    canonicalize_pypi_name(
        specifier
            .trim()
            .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '-' && ch != '_' && ch != '.')
            .next()
            .unwrap_or_default(),
    )
}

fn same_hosted_artifact(previous: &str, current: &str) -> bool {
    let (Ok(previous), Ok(current)) = (reqwest::Url::parse(previous), reqwest::Url::parse(current))
    else {
        return false;
    };
    if previous.origin() != current.origin()
        || previous.username() != current.username()
        || previous.password() != current.password()
        || previous.query() != current.query()
        || previous.fragment() != current.fragment()
    {
        return false;
    }
    let previous_path: Vec<_> = previous.path_segments().into_iter().flatten().collect();
    let current_path: Vec<_> = current.path_segments().into_iter().flatten().collect();
    if previous_path.len() != current_path.len() || current_path.len() < 3 {
        return false;
    }
    let grant_index = current_path.len() - 3;
    previous_path[..grant_index] == current_path[..grant_index]
        && previous_path[grant_index + 1..] == current_path[grant_index + 1..]
        && uuid::Uuid::parse_str(previous_path[grant_index]).is_ok()
        && uuid::Uuid::parse_str(current_path[grant_index]).is_ok()
        && uuid::Uuid::parse_str(current_path[grant_index + 1]).is_ok()
}

/// How a freshly created `[tool.uv.sources]` is laid out.
///
/// A PEP 723 script block is reverted by DOCUMENT restore
/// (`vendor::pypi_lock::restore_document`), which can only converge on the
/// exact pre-vendor bytes after an out-of-order multi-package revert when
/// the tables we created vanish once empty. Only DOTTED keys do that after a
/// parse round trip (dotted-ness is syntax; `implicit` is not), so the script
/// block keeps `tool.uv.sources.x = { … }` right after `dependencies`, where
/// placement was never a problem.
///
/// A `pyproject.toml` is reverted by exact text replay of the recorded
/// original, so it can use uv's own layout: header-less `[tool]` / `[tool.uv]`
/// parents and a real `[tool.uv.sources]` table AFTER `[project]`. (Dotted
/// keys rendered as `tool.uv.sources.x = …` in the ROOT body — i.e. ABOVE
/// `[project]` — whenever the pyproject had no `[tool]` header yet.)
#[derive(Clone, Copy)]
enum SourcesLayout {
    Dotted,
    Tables,
}

impl SourcesLayout {
    fn parent(self) -> Item {
        let mut table = Table::new();
        match self {
            Self::Dotted => table.set_dotted(true),
            Self::Tables => table.set_implicit(true),
        }
        Item::Table(table)
    }

    fn leaf(self) -> Item {
        let mut table = Table::new();
        if matches!(self, Self::Dotted) {
            table.set_dotted(true);
        }
        Item::Table(table)
    }
}

fn rewrite_sources(
    document: &mut DocumentMut,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
    direct: bool,
    layout: SourcesLayout,
) -> Result<(), String> {
    let (key, location) = match artifact {
        ArtifactSource::Url(location) => ("url", location),
        ArtifactSource::Path(location) => ("path", location),
    };
    let tool = document.entry("tool").or_insert(layout.parent());
    let uv = tool
        .as_table_like_mut()
        .ok_or("Python tool metadata must be a table")?
        .entry("uv")
        .or_insert(layout.parent());
    let uv = uv
        .as_table_like_mut()
        .ok_or("Python tool.uv metadata must be a table")?;
    let sources = uv.entry("sources").or_insert(layout.leaf());
    let sources = sources
        .as_table_like_mut()
        .ok_or("Python tool.uv.sources must be a table")?;
    let existing = sources
        .iter()
        .find(|(candidate, _)| canonicalize_pypi_name(candidate) == name)
        .map(|(key, value)| (key.to_string(), value.clone()));
    if let Some((existing_name, existing)) = existing {
        let previous = existing
            .as_table_like()
            .filter(|table| table.len() == 1)
            .and_then(|table| table.get(key))
            .and_then(Item::as_str);
        let same = previous.is_some_and(|previous| {
            previous == location || (key == "url" && same_hosted_artifact(previous, location))
        });
        if !same {
            return Err(format!("Python project already declares a source for {existing_name}; revert it before applying a different patch"));
        }
        if previous != Some(location) {
            let mut source = InlineTable::new();
            source.insert(key, Value::from(location));
            source.fmt();
            sources.insert(&existing_name, Item::Value(Value::InlineTable(source)));
        }
    } else {
        let mut source = InlineTable::new();
        source.insert(key, Value::from(location));
        source.fmt();
        sources.insert(name, Item::Value(Value::InlineTable(source)));
    }
    if !direct {
        let specifier = format!("{name}=={version}");
        let overrides = uv
            .entry("override-dependencies")
            .or_insert(Item::Value(Value::Array(Array::new())));
        let overrides = overrides
            .as_array_mut()
            .ok_or("Python override-dependencies must be an array")?;
        let existing = overrides
            .iter()
            .filter_map(Value::as_str)
            .find(|spec| dependency_name(spec) == name)
            .map(str::to_string);
        if let Some(existing) = existing {
            if existing != specifier {
                return Err(format!(
                    "Python project already overrides {name}; revert it before applying a patch"
                ));
            }
        } else {
            overrides.push(specifier);
        }
    }
    Ok(())
}

fn contains_dependency(item: Option<&Item>, name: &str) -> bool {
    item.and_then(Item::as_array).is_some_and(|dependencies| {
        dependencies
            .iter()
            .filter_map(Value::as_str)
            .any(|specifier| dependency_name(specifier) == name)
    })
}

pub fn rewrite_project_metadata(
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
) -> Result<Option<String>, String> {
    let mut document: DocumentMut = text
        .parse()
        .map_err(|error| format!("invalid pyproject.toml: {error}"))?;
    let name = canonicalize_pypi_name(name);
    let project = document
        .get("project")
        .and_then(Item::as_table_like)
        .ok_or("pyproject.toml has no project table")?;
    let direct = contains_dependency(project.get("dependencies"), &name)
        || project
            .get("optional-dependencies")
            .and_then(Item::as_table_like)
            .is_some_and(|groups| {
                groups
                    .iter()
                    .any(|(_, group)| contains_dependency(Some(group), &name))
            })
        || document
            .get("dependency-groups")
            .and_then(Item::as_table_like)
            .is_some_and(|groups| {
                groups
                    .iter()
                    .any(|(_, group)| contains_dependency(Some(group), &name))
            });
    if document
        .get("tool")
        .and_then(Item::as_table_like)
        .and_then(|tool| tool.get("uv"))
        .and_then(Item::as_table_like)
        .is_some_and(|uv| uv.contains_key("workspace"))
    {
        return Err(
            "hosted sources for uv workspaces require a package-scoped source mapping".to_string(),
        );
    }
    rewrite_sources(
        &mut document,
        &name,
        version,
        artifact,
        direct,
        SourcesLayout::Tables,
    )?;
    let output = crate::utils::python_lock::preserve_line_endings(text, document.to_string());
    Ok((output != text).then_some(output))
}

pub fn rewrite_script_metadata(
    text: &str,
    name: &str,
    version: &str,
    artifact: ArtifactSource<'_>,
) -> Result<Option<String>, String> {
    let (_, metadata) = script_metadata(text)?;
    let mut document: DocumentMut = metadata
        .parse()
        .map_err(|error| format!("invalid script metadata: {error}"))?;
    let name = canonicalize_pypi_name(name);
    let direct = document
        .get("dependencies")
        .and_then(Item::as_array)
        .is_some_and(|deps| {
            deps.iter()
                .filter_map(Value::as_str)
                .any(|spec| dependency_name(spec) == name)
        });
    rewrite_sources(
        &mut document,
        &name,
        version,
        artifact,
        direct,
        SourcesLayout::Dotted,
    )?;
    let output = replace_script_metadata(text, &document.to_string())?;
    Ok((output != text).then_some(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_are_paired_without_changing_the_script() {
        let script = "#!/usr/bin/env python3\n# /// script\n# dependencies = [\"urllib3==1.26.18\"]\n# ///\nprint('preserved')\n";
        let output = rewrite_script_metadata(
            script,
            "urllib3",
            "1.26.18",
            ArtifactSource::Path(".socket/vendor/pypi/patched.whl"),
        )
        .unwrap()
        .unwrap();
        assert!(output.starts_with("#!/usr/bin/env python3\n# /// script\n"));
        assert!(output.ends_with("# ///\nprint('preserved')\n"));
        let (_, metadata) = script_metadata(&output).unwrap();
        let document: DocumentMut = metadata.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["urllib3"]["path"].as_str(),
            Some(".socket/vendor/pypi/patched.whl")
        );
        assert!(rewrite_script_metadata(
            &output,
            "urllib3",
            "1.26.18",
            ArtifactSource::Path(".socket/vendor/pypi/patched.whl")
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn hosted_grant_refresh_preserves_patch_identity() {
        let previous = "https://patch.socket.dev/pkg/pypi/11111111-1111-4111-8111-111111111111/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
        let current = previous.replace(
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
        );
        let script = "# /// script\n# dependencies = [\"urllib3==1.26.18\"]\n# ///\n";
        let old =
            rewrite_script_metadata(script, "urllib3", "1.26.18", ArtifactSource::Url(previous))
                .unwrap()
                .unwrap();
        let new =
            rewrite_script_metadata(&old, "urllib3", "1.26.18", ArtifactSource::Url(&current))
                .unwrap()
                .unwrap();
        assert!(new.contains(&current));
        assert!(!new.contains(previous));
        let different_patch = current.replace(
            "e828efa5-5c6d-43f3-9909-03f5ac232b98",
            "33333333-3333-4333-8333-333333333333",
        );
        assert!(rewrite_script_metadata(
            &old,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(&different_patch)
        )
        .is_err());
        let different_host = current.replace("patch.socket.dev", "example.test");
        assert!(rewrite_script_metadata(
            &old,
            "urllib3",
            "1.26.18",
            ArtifactSource::Url(&different_host)
        )
        .is_err());
    }

    #[test]
    fn transitive_sources_are_bound_to_an_override() {
        let output = rewrite_script_metadata(
            "# /// script\n# dependencies = [\"requests\"]\n# ///\n",
            "urllib3",
            "1.26.18",
            ArtifactSource::Url("https://example.test/patch.whl"),
        )
        .unwrap()
        .unwrap();
        let (_, metadata) = script_metadata(&output).unwrap();
        let document: DocumentMut = metadata.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["override-dependencies"][0].as_str(),
            Some("urllib3==1.26.18")
        );
    }
}

#[cfg(test)]
mod rendering_tests {
    use super::*;

    const URL: &str = "https://patch.socket.dev/alpha-1.0.0-py3-none-any.whl";

    /// Byte-level shape of a pyproject edit: uv's own layout — a
    /// `[tool.uv.sources]` header AFTER `[project]`, never dotted keys at the
    /// top of the file; a transitive dep adds `[tool.uv]` with its override.
    #[test]
    fn project_sources_render_as_uv_style_headers_after_project() {
        let direct = rewrite_project_metadata(
            "[project]\nname = \"p\"\nversion = \"0.1.0\"\ndependencies = [\"alpha==1.0.0\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            direct,
            format!("[project]\nname = \"p\"\nversion = \"0.1.0\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n")
        );
        let transitive = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"requests\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            transitive,
            format!("[project]\nname = \"p\"\ndependencies = [\"requests\"]\n\n[tool.uv]\noverride-dependencies = [\"alpha==1.0.0\"]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n")
        );
        // An existing `[tool.uv]` header gains the sources as its own
        // sub-table; a CRLF pyproject stays CRLF.
        let existing = rewrite_project_metadata(
            "[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[tool.uv]\r\ndev-dependencies = [\"pytest\"]\r\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            existing,
            format!("[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[tool.uv]\r\ndev-dependencies = [\"pytest\"]\r\n\r\n[tool.uv.sources]\r\nalpha = {{ url = \"{URL}\" }}\r\n")
        );
        // An existing `[tool.uv.sources]` header is reused as-is.
        let header = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"beta\"]\n\n[tool.uv.sources]\nbeta = { git = \"https://example.test/beta\" }\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            header,
            format!("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"beta\"]\n\n[tool.uv.sources]\nbeta = {{ git = \"https://example.test/beta\" }}\nalpha = {{ url = \"{URL}\" }}\n")
        );
    }

    /// The PEP 723 block keeps the fully dotted shape so that document
    /// restore can drop it without a trace once every source is reverted.
    #[test]
    fn script_sources_stay_dotted_inside_the_metadata_block() {
        let script = "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n# ///\nprint('x')\n";
        let out = rewrite_script_metadata(script, "alpha", "1.0.0", ArtifactSource::Url(URL))
            .unwrap()
            .unwrap();
        assert_eq!(
            out,
            format!("# /// script\n# dependencies = [\"alpha==1.0.0\"]\n# tool.uv.sources.alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n")
        );
    }
}
