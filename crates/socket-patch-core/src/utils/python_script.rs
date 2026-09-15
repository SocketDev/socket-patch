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
/// exact pre-vendor bytes after an out-of-order multi-package revert of
/// DIRECT dependencies (one `sources.<name>` key each) when the tables we
/// created vanish once empty. Only DOTTED keys do that after a parse round
/// trip (dotted-ness is syntax; `implicit` is not), so the script block
/// keeps `tool.uv.sources.x = { … }` right after `dependencies`, where
/// placement was never a problem. TRANSITIVE pairs are different: they share
/// one `override-dependencies` array, and `restore_value`'s array branch
/// flags drift as soon as the entries stop lining up, so their revert stays
/// order-dependent whatever the layout.
///
/// A `pyproject.toml` is reverted by exact text replay of the recorded
/// original, so it can use uv's own layout: header-less `[tool]` / `[tool.uv]`
/// parents and a real `[tool.uv.sources]` table. Where that header lands is
/// toml_edit's choice, not ours: a new table is rendered right after the
/// last PRE-EXISTING table visited before it in depth-first key order —
/// directly after an existing `[tool.uv]`, after `[tool.ruff]` when that is
/// the only `[tool.*]` table (even when that puts it BEFORE `[project]`),
/// and at the very end of the document — after a trailing `[build-system]` —
/// when there is no `[tool]` block yet. (Dotted keys would instead render as
/// `tool.uv.sources.x = …` in the ROOT body — i.e. ABOVE `[project]` —
/// whenever the pyproject had no `[tool]` header yet; an older CLI wrote
/// exactly that, and `rewrite_sources` keeps extending such a dotted table
/// rather than adding a second, conflicting header.)
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
    let tool_uv = document
        .get("tool")
        .and_then(Item::as_table_like)
        .and_then(|tool| tool.get("uv"))
        .and_then(Item::as_table_like);
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
            })
        // The legacy `[tool.uv] dev-dependencies` array (still honoured by uv
        // with a deprecation warning) is a direct declaration too: uv records
        // it under `[package.metadata.requires-dev]`, so an override here
        // would be redundant — and ignored by uv < 0.5.6, which does not
        // apply `[tool.uv.sources]` to `override-dependencies`.
        || tool_uv
            .is_some_and(|uv| contains_dependency(uv.get("dev-dependencies"), &name));
    if tool_uv.is_some_and(|uv| uv.contains_key("workspace")) {
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

    /// A package declared only in the legacy `[tool.uv] dev-dependencies`
    /// array is a DIRECT dependency for hosted wiring: uv tracks it under
    /// `[package.metadata.requires-dev]`, so the source alone redirects it and
    /// no `override-dependencies` entry may be added (uv < 0.5.6 ignores
    /// sources on overrides and would reinstall the registry wheel).
    #[test]
    fn tool_uv_dev_dependencies_count_as_direct_for_hosted_sources() {
        let out = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = []\n\n[tool.uv]\ndev-dependencies = [\"alpha==1.0.0\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert!(!out.contains("override-dependencies"), "{out}");
        assert!(
            out.contains(&format!("[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}")),
            "{out}"
        );
        assert!(
            rewrite_project_metadata(&out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_none()
        );
    }

    /// A second pass over a rendering must be a no-op: the source is
    /// recognised as already present and nothing is re-emitted.
    fn assert_settled(out: &str) {
        assert!(
            rewrite_project_metadata(out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_none(),
            "second rewrite must be a no-op over:\n{out}"
        );
    }

    /// Byte-level shape of a pyproject edit: uv's own layout — a
    /// `[tool.uv.sources]` header AFTER `[project]` when `[project]` is the
    /// last table, never dotted keys at the top of the file; a transitive
    /// dep adds `[tool.uv]` with its override. (The sibling tests below pin
    /// where the header lands when other tables follow or precede.)
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
        assert_settled(&direct);
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
        assert_settled(&transitive);
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
        assert_settled(&existing);
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
        assert_settled(&header);
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
        assert!(
            rewrite_script_metadata(&out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .is_none()
        );
    }

    /// No `[tool]` block yet and a `[build-system]` after `[project]`:
    /// toml_edit appends the new header after the LAST existing table, so
    /// `[tool.uv.sources]` follows `[build-system]`, not `[project]`. CRLF
    /// input stays CRLF.
    #[test]
    fn project_sources_follow_a_trailing_build_system_table() {
        let lf = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            lf,
            format!("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n")
        );
        assert_settled(&lf);
        let crlf = rewrite_project_metadata(
            "[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[build-system]\r\nrequires = [\"hatchling\"]\r\nbuild-backend = \"hatchling.build\"\r\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            crlf,
            format!("[project]\r\nname = \"p\"\r\ndependencies = [\"alpha==1.0.0\"]\r\n\r\n[build-system]\r\nrequires = [\"hatchling\"]\r\nbuild-backend = \"hatchling.build\"\r\n\r\n[tool.uv.sources]\r\nalpha = {{ url = \"{URL}\" }}\r\n")
        );
        assert_eq!(crlf.matches("\r\n").count(), crlf.matches('\n').count());
        assert_settled(&crlf);
    }

    /// `[tool]` with `uv = { … }` as an INLINE table: there is no `[tool.uv]`
    /// header to hang a `[tool.uv.sources]` table off, so the source has to
    /// live inside the inline table. toml_edit renders it as a dotted
    /// `sources.alpha = { … }` key on the `uv = { … }` line; whatever the
    /// exact spelling, it must parse back to the source and settle on the
    /// second pass. A transitive dep adds its override to the same table.
    #[test]
    fn project_sources_join_an_inline_tool_uv_table() {
        let direct = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool]\nuv = { dev-dependencies = [\"pytest\"] }\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        let document: DocumentMut = direct.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(URL)
        );
        assert_eq!(
            document["tool"]["uv"]["dev-dependencies"][0].as_str(),
            Some("pytest")
        );
        assert!(document["tool"]["uv"].is_inline_table(), "{direct}");
        assert_eq!(direct.matches("[tool]").count(), 1, "{direct}");
        assert!(!direct.contains("[tool.uv"), "{direct}");
        let uv_line = direct
            .lines()
            .find(|line| line.starts_with("uv = {"))
            .unwrap_or_else(|| panic!("uv stays an inline table:\n{direct}"));
        assert!(
            uv_line.contains(&format!("sources.alpha = {{ url = \"{URL}\" }}")),
            "{direct}"
        );
        assert!(uv_line.ends_with('}'), "{direct}");
        assert!(direct.starts_with("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool]\n"), "{direct}");
        assert_settled(&direct);

        let transitive = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"requests\"]\n\n[tool]\nuv = { dev-dependencies = [\"pytest\"] }\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        let document: DocumentMut = transitive.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(URL)
        );
        assert_eq!(
            document["tool"]["uv"]["override-dependencies"][0].as_str(),
            Some("alpha==1.0.0")
        );
        assert!(document["tool"]["uv"].is_inline_table(), "{transitive}");
        assert!(!transitive.contains("[tool.uv"), "{transitive}");
        assert_settled(&transitive);
    }

    /// The header follows the tool block, not `[project]`: with `[tool.ruff]`
    /// as the only `[tool.*]` table and `[project]` after it, the new
    /// `[tool.uv.sources]` (and a transitive dep's `[tool.uv]`) land inside
    /// the tool block BEFORE `[project]`. With `[tool.uv]` followed by
    /// `[tool.ruff]`, the sources header goes right after `[tool.uv]`.
    #[test]
    fn project_sources_land_in_a_tool_block_that_precedes_project() {
        let direct = rewrite_project_metadata(
            "[tool.ruff]\nline-length = 100\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            direct,
            format!("[tool.ruff]\nline-length = 100\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n")
        );
        assert_settled(&direct);

        let transitive = rewrite_project_metadata(
            "[tool.ruff]\nline-length = 100\n\n[project]\nname = \"p\"\ndependencies = [\"requests\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            transitive,
            format!("[tool.ruff]\nline-length = 100\n\n[tool.uv]\noverride-dependencies = [\"alpha==1.0.0\"]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n\n[project]\nname = \"p\"\ndependencies = [\"requests\"]\n")
        );
        assert_settled(&transitive);

        let after_uv = rewrite_project_metadata(
            "[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool.uv]\ndev-dependencies = [\"pytest\"]\n\n[tool.ruff]\nline-length = 100\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            after_uv,
            format!("[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\"]\n\n[tool.uv]\ndev-dependencies = [\"pytest\"]\n\n[tool.uv.sources]\nalpha = {{ url = \"{URL}\" }}\n\n[tool.ruff]\nline-length = 100\n")
        );
        assert_settled(&after_uv);
    }

    /// Upgrade path: an older CLI wrote the source as a dotted
    /// `tool.uv.sources.other = { … }` key in the ROOT body (above
    /// `[project]`). The new source must extend that dotted table — one more
    /// dotted line, no second `[tool.uv.sources]` header that would make the
    /// document invalid — and a transitive dep's override joins it the same
    /// way.
    #[test]
    fn project_sources_extend_a_dotted_root_body_table_from_an_older_cli() {
        let direct = rewrite_project_metadata(
            "tool.uv.sources.other = { git = \"https://example.test/other\" }\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"other\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            direct,
            format!("tool.uv.sources.other = {{ git = \"https://example.test/other\" }}\ntool.uv.sources.alpha = {{ url = \"{URL}\" }}\n\n[project]\nname = \"p\"\ndependencies = [\"alpha==1.0.0\", \"other\"]\n")
        );
        let document: DocumentMut = direct.parse().unwrap();
        assert_eq!(
            document["tool"]["uv"]["sources"]["other"]["git"].as_str(),
            Some("https://example.test/other")
        );
        assert_eq!(
            document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
            Some(URL)
        );
        assert_settled(&direct);

        let transitive = rewrite_project_metadata(
            "tool.uv.sources.other = { git = \"https://example.test/other\" }\n\n[project]\nname = \"p\"\ndependencies = [\"other\"]\n",
            "alpha",
            "1.0.0",
            ArtifactSource::Url(URL),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            transitive,
            format!("tool.uv.sources.other = {{ git = \"https://example.test/other\" }}\ntool.uv.sources.alpha = {{ url = \"{URL}\" }}\ntool.uv.override-dependencies = [\"alpha==1.0.0\"]\n\n[project]\nname = \"p\"\ndependencies = [\"other\"]\n")
        );
        assert_settled(&transitive);
    }

    /// A user-authored `# [tool.uv.sources]` (or `# [tool.uv]`) header inside
    /// the PEP 723 block coexists with our insertion: the source joins the
    /// existing table, the extracted block still parses, and
    /// `replace_script_metadata` re-comments every line so the block stays a
    /// valid PEP 723 comment block.
    #[test]
    fn script_block_with_user_sources_header_stays_parseable_and_commented() {
        fn block_lines(script: &str) -> Vec<&str> {
            let start = script.find("# /// script\n").unwrap() + "# /// script\n".len();
            let end = script.find("\n# ///\n").unwrap();
            script[start..end].lines().collect()
        }
        let cases = [
            (
                "# /// script\n# dependencies = [\"alpha==1.0.0\", \"beta\"]\n#\n# [tool.uv.sources]\n# beta = { git = \"https://example.test/beta\" }\n# ///\nprint('x')\n",
                format!("# /// script\n# dependencies = [\"alpha==1.0.0\", \"beta\"]\n#\n# [tool.uv.sources]\n# beta = {{ git = \"https://example.test/beta\" }}\n# alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n"),
            ),
            (
                "# /// script\n# dependencies = [\"alpha==1.0.0\"]\n#\n# [tool.uv]\n# exclude-newer = \"2024-01-01T00:00:00Z\"\n# ///\nprint('x')\n",
                format!("# /// script\n# dependencies = [\"alpha==1.0.0\"]\n#\n# [tool.uv]\n# exclude-newer = \"2024-01-01T00:00:00Z\"\n# sources.alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n"),
            ),
            (
                "# /// script\n# dependencies = [\"requests\", \"beta\"]\n#\n# [tool.uv.sources]\n# beta = { git = \"https://example.test/beta\" }\n# ///\nprint('x')\n",
                format!("# /// script\n# dependencies = [\"requests\", \"beta\"]\n#\n# [tool.uv]\n# override-dependencies = [\"alpha==1.0.0\"]\n#\n# [tool.uv.sources]\n# beta = {{ git = \"https://example.test/beta\" }}\n# alpha = {{ url = \"{URL}\" }}\n# ///\nprint('x')\n"),
            ),
        ];
        for (script, expected) in cases {
            let out = rewrite_script_metadata(script, "alpha", "1.0.0", ArtifactSource::Url(URL))
                .unwrap()
                .unwrap();
            assert_eq!(out, expected);
            for line in block_lines(&out) {
                assert!(
                    line == "#" || line.starts_with("# "),
                    "every block line must stay a comment: {line:?} in\n{out}"
                );
            }
            let (_, metadata) = script_metadata(&out).unwrap();
            let document: DocumentMut = metadata.parse().unwrap();
            assert_eq!(
                document["tool"]["uv"]["sources"]["alpha"]["url"].as_str(),
                Some(URL)
            );
            if script.contains("beta") {
                assert_eq!(
                    document["tool"]["uv"]["sources"]["beta"]["git"].as_str(),
                    Some("https://example.test/beta")
                );
            }
            if !script.contains("alpha==") {
                assert_eq!(
                    document["tool"]["uv"]["override-dependencies"][0].as_str(),
                    Some("alpha==1.0.0")
                );
            }
            assert!(
                rewrite_script_metadata(&out, "alpha", "1.0.0", ArtifactSource::Url(URL))
                    .unwrap()
                    .is_none(),
                "{out}"
            );
        }
    }
}
