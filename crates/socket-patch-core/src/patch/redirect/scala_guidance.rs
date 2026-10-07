//! Hosted guidance for Mill and scala-cli builds. Neither tool loads a
//! generated file that could force a version build-wide (Mill has no
//! global override hook; scala-cli adds repositories but cannot override a
//! transitive version), so hosted mode never edits them: [`warn`] emits a
//! paste-able snippet per Maven patch (`redirect_mill_manual_snippet`,
//! `redirect_scala_cli_manual_snippet`) naming the hosted repository and the
//! pinned `<base>-socket.<hex8>` version. Like the Gradle snippet, a
//! guided patch is never confirmed: nothing socket-patch wrote pins it.

use std::collections::BTreeMap;

use super::{
    full_name, no_maven_or_gradle, registry_override_of_kind, DepOverride, RewriteResult,
    RewriteWarning,
};

/// Mill build files.
pub const MILL_MARKERS: &[&str] = &["build.mill", "build.mill.yaml", "build.sc", ".mill-version"];
/// scala-cli directory-build markers.
pub const SCALA_CLI_MARKERS: &[&str] = &["project.scala"];

/// The pin a snippet names: the Socket repository and the version to force.
struct Pin {
    index_url: String,
    group: String,
    artifact: String,
    version: String,
    /// The version is the fail-closed suffixed one.
    suffixed: bool,
}

fn pin_of(dep: &DepOverride) -> Option<Pin> {
    let ov = registry_override_of_kind(dep, "maven2")?;
    let suffixed = ov.identifiers.maven_suffixed_version.clone();
    Some(Pin {
        index_url: ov.index_url.clone(),
        group: ov
            .identifiers
            .maven_group_id
            .clone()
            .or_else(|| dep.namespace.clone())
            .unwrap_or_default(),
        artifact: ov
            .identifiers
            .maven_artifact_id
            .clone()
            .unwrap_or_else(|| dep.name.clone()),
        suffixed: suffixed.is_some(),
        version: suffixed.unwrap_or_else(|| dep.version.clone()),
    })
}

/// The tail every snippet carries for the legacy same-GAV grant.
fn same_gav_note(p: &Pin) -> &'static str {
    if p.suffixed {
        ""
    } else {
        "\n(this grant is served at its original version, so a repository failure falls back to \
         the unpatched artifact: not fail-closed)"
    }
}

/// The Mill snippet (1.x, then 0.11 / 0.12 spellings) for one pin.
fn mill_snippet(p: &Pin) -> String {
    let Pin {
        index_url,
        group,
        artifact,
        version,
        ..
    } = p;
    format!(
        "Mill does not load a generated file; add the Socket repository and force \
         {group}:{artifact}:{version} in every module that resolves it.\n\
         Mill 1.x:\n  def repositories = Task {{ Seq(\"{index_url}\") ++ super.repositories() }}\n  \
         def depManagement = Task {{ super.depManagement() ++ Seq(mvn\"{group}:{artifact}:{version}\") }}\n\
         Mill 0.11 / 0.12:\n  def repositoriesTask = T.task {{ super.repositoriesTask() ++ \
         Seq(coursier.maven.MavenRepository(\"{index_url}\")) }}\n  \
         def ivyDeps = super.ivyDeps() ++ Agg(ivy\"{group}:{artifact}:{version}\".forceVersion())\
         {}",
        same_gav_note(p)
    )
}

/// The scala-cli snippet for one pin.
fn scala_cli_snippet(p: &Pin) -> String {
    let Pin {
        index_url,
        group,
        artifact,
        version,
        ..
    } = p;
    format!(
        "scala-cli does not force transitive versions; add to project.scala:\n  \
         //> using repository {index_url}\n  //> using dep {group}:{artifact}:{version}\n\
         and add `,exclude={group}%{artifact}` to the `//> using dep` that pulls in \
         {group}:{artifact} transitively{}",
        same_gav_note(p)
    )
}

/// Emit the snippets for the Maven `overrides` when Mill or scala-cli
/// markers are among `files`.
pub fn warn(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let mill = MILL_MARKERS.iter().any(|m| files.contains_key(*m));
    let scala_cli = SCALA_CLI_MARKERS.iter().any(|m| files.contains_key(*m));
    if !mill && !scala_cli {
        return;
    }
    // A pure Mill / scala-cli root has no other maven planner to say why
    // nothing landed (`rewrite_maven_pom` defers to this module).
    let sole = owns_maven_root(files) && !crate::patch::redirect::sbt::owns_maven_root(files);
    for dep in overrides.iter().filter(|o| o.ecosystem == "maven") {
        let Some(pin) = pin_of(dep) else {
            if sole {
                result.warnings.push(RewriteWarning {
                    code: "redirect_maven_missing_override".into(),
                    detail: format!("{} has no maven2 registry override", full_name(dep)),
                });
            }
            continue;
        };
        if mill {
            result.warnings.push(RewriteWarning {
                code: "redirect_mill_manual_snippet".into(),
                detail: mill_snippet(&pin),
            });
        }
        if scala_cli {
            result.warnings.push(RewriteWarning {
                code: "redirect_scala_cli_manual_snippet".into(),
                detail: scala_cli_snippet(&pin),
            });
        }
    }
}

/// The root is a Mill or scala-cli build with no `pom.xml` and no Gradle
/// script beside it: the pom rewriter's `missing_override` / `no_pom`
/// warnings would only duplicate the snippets.
pub fn owns_maven_root(files: &BTreeMap<String, String>) -> bool {
    MILL_MARKERS
        .iter()
        .chain(SCALA_CLI_MARKERS)
        .any(|m| files.contains_key(*m))
        && no_maven_or_gradle(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(names: &[&str]) -> BTreeMap<String, String> {
        names
            .iter()
            .map(|n| (n.to_string(), String::new()))
            .collect()
    }

    fn dep(suffixed: bool) -> DepOverride {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "maven",
            "name": "commons-lang3",
            "namespace": "org.apache.commons",
            "version": "3.11",
            "token": "t",
            "patchUuid": "abcdef12-3456-4789-8abc-def012345678",
            "artifactUrl": "https://patch.socket.dev/x.jar",
            "registryOverride": {
                "kind": "maven2",
                "indexUrl": "https://patch.socket.dev/patch-registry/maven/t/abcdef12-3456-4789-8abc-def012345678/maven2",
                "identifiers": {
                    "name": "org.apache.commons/commons-lang3",
                    "version": "3.11",
                    "mavenGroupId": "org.apache.commons",
                    "mavenArtifactId": "commons-lang3",
                    "mavenSuffixedVersion": suffixed.then_some("3.11-socket.abcdef12"),
                }
            },
            "integrity": {}
        }))
        .unwrap()
    }

    #[test]
    fn owns_mill_and_scala_cli_roots_without_pom_or_gradle() {
        assert!(owns_maven_root(&files(&["build.mill"])));
        assert!(owns_maven_root(&files(&["project.scala"])));
        assert!(!owns_maven_root(&files(&["build.sc", "pom.xml"])));
        assert!(!owns_maven_root(&files(&["build.sc", "build.gradle"])));
        assert!(!owns_maven_root(&files(&["build.sbt"])));
    }

    #[test]
    fn snippets_name_the_repository_and_the_pinned_version() {
        let mut result = RewriteResult::default();
        warn(
            &files(&["build.mill", "project.scala"]),
            &[dep(true)],
            &mut result,
        );
        let codes: Vec<&str> = result.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes,
            [
                "redirect_mill_manual_snippet",
                "redirect_scala_cli_manual_snippet"
            ]
        );
        for w in &result.warnings {
            assert!(w.detail.contains("3.11-socket.abcdef12"), "{}", w.detail);
            assert!(w.detail.contains("/maven2"), "{}", w.detail);
            assert!(!w.detail.contains("not fail-closed"), "{}", w.detail);
        }
        assert!(result.warnings[0]
            .detail
            .contains("mvn\"org.apache.commons:commons-lang3:"));
        assert!(result.warnings[0].detail.contains(".forceVersion()"));
        // Both Mill 1.x lines append to what the module already has.
        assert!(result.warnings[0]
            .detail
            .contains("def depManagement = Task { super.depManagement() ++ Seq(mvn\""));
        assert!(result.warnings[0]
            .detail
            .contains("def repositories = Task { Seq(\""));
        assert!(result.warnings[1]
            .detail
            .contains(",exclude=org.apache.commons%commons-lang3"));
        assert!(result.files.is_empty() && result.confirmed_sbt_uuids.is_empty());
    }

    #[test]
    fn same_gav_grant_says_it_is_not_fail_closed() {
        let mut result = RewriteResult::default();
        warn(&files(&["build.sc"]), &[dep(false)], &mut result);
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].detail.contains("commons-lang3:3.11\""));
        assert!(result.warnings[0].detail.contains("not fail-closed"));
    }

    #[test]
    fn no_marker_no_snippet_and_missing_override_only_when_sole() {
        let mut result = RewriteResult::default();
        warn(&files(&["pom.xml"]), &[dep(true)], &mut result);
        assert!(result.warnings.is_empty());
        let mut bare = dep(true);
        bare.registry_override = None;
        warn(&files(&["build.mill"]), &[bare.clone()], &mut result);
        assert_eq!(result.warnings[0].code, "redirect_maven_missing_override");
        let mut result = RewriteResult::default();
        warn(&files(&["build.mill", "pom.xml"]), &[bare], &mut result);
        assert!(result.warnings.is_empty(), "the pom rewriter says it");
    }
}
