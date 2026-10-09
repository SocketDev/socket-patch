//! The hosted Maven rewriter's view of `pom.xml`: every `<dependency>`, live
//! `<repository>` and section anchor it reads, located once through
//! [`PomScope`] (comments, CDATA, `<build>`, `<reporting>`,
//! `<pluginRepositories>`, `<distributionManagement>` and `<profiles>` are
//! never anchors) and then kept in step with the rewriter's own edits by
//! shifting offsets, so a pom with many patched dependencies is scanned once,
//! not once per dependency.

use crate::formats::maven::PomScope;
use crate::formats::xml::{child_text, children, elements, Element};

/// One `<dependency>` outside ignored sections.
#[derive(Debug, Clone)]
pub(super) struct IndexedDep {
    pub(super) group: Option<String>,
    pub(super) artifact: Option<String>,
    /// Inner-text byte range of the literal `<version>`.
    pub(super) version_inner: Option<(usize, usize)>,
    pub(super) version_text: Option<String>,
    pub(super) type_text: Option<String>,
    pub(super) classifier: Option<String>,
    pub(super) in_profile: bool,
}

/// One live `<repository>`.
#[derive(Debug, Clone)]
struct IndexedRepo {
    id: Option<String>,
    /// Inner-text byte range of its `<url>`.
    url_inner: Option<(usize, usize)>,
}

/// A section the rewriter inserts into.
#[derive(Debug, Clone, Copy)]
enum Anchor {
    Repositories,
    Dm,
    DmDeps,
}

#[derive(Debug, Clone)]
pub(super) struct PomIndex {
    deps: Vec<IndexedDep>,
    repos: Vec<IndexedRepo>,
    /// The project's own `<repositories>`.
    repositories: Option<Element>,
    /// The project's own `<dependencyManagement>` and its `<dependencies>`.
    dm: Option<Element>,
    dm_deps: Option<Element>,
    /// The `<` of `</project>`.
    project_close: usize,
}

/// The `<repository>` block the rewriter inserts (releases enabled with
/// `checksumPolicy=fail` for the transport check against the served
/// `.jar.sha1`; snapshots disabled).
fn repository_block(id: &str, url: &str) -> String {
    format!(
        "    <repository>\n      <id>{id}</id>\n      <url>{url}</url>\n      <releases>\n        <enabled>true</enabled>\n        <checksumPolicy>fail</checksumPolicy>\n      </releases>\n      <snapshots>\n        <enabled>false</enabled>\n      </snapshots>\n    </repository>"
    )
}

/// The `<dependencyManagement>` entry the rewriter inserts.
fn managed_block(group: &str, artifact: &str, version: &str) -> String {
    format!(
        "      <dependency>\n        <groupId>{group}</groupId>\n        <artifactId>{artifact}</artifactId>\n        <version>{version}</version>\n      </dependency>"
    )
}

fn shift_pos(pos: &mut usize, at: usize, delta: isize) {
    if *pos >= at {
        *pos = pos
            .checked_add_signed(delta)
            .expect("offsets stay in the pom");
    }
}

fn shift_element(e: &mut Element, at: usize, delta: isize) {
    for pos in [
        &mut e.start,
        &mut e.inner_start,
        &mut e.inner_end,
        &mut e.end,
    ] {
        shift_pos(pos, at, delta);
    }
}

/// The element `<name>…</name>` whose open tag starts `text[at..]`, with
/// offsets into `text` (the rewriter's own markup: no attributes, no
/// comments).
fn authored_element(text: &str, at: usize, name: &str) -> Element {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    debug_assert!(text[at..].starts_with(&open));
    let inner_start = at + open.len();
    let inner_end = inner_start
        + text[inner_start..]
            .find(&close)
            .expect("authored markup closes");
    Element {
        start: at,
        inner_start,
        inner_end,
        end: inner_end + close.len(),
    }
}

impl PomIndex {
    /// Fails (fail-closed) when the pom is not readable as one.
    pub(super) fn build(pom: &str) -> Result<PomIndex, String> {
        let scope = PomScope::new(pom)?;
        let masked = &scope.masked;
        let deps = scope
            .dependencies()?
            .into_iter()
            .map(|d| IndexedDep {
                group: d.group,
                artifact: d.artifact,
                version_inner: d.version_inner,
                version_text: d.version_text,
                type_text: d.type_text,
                classifier: d.classifier,
                in_profile: d.in_profile,
            })
            .collect();
        let mut repos = Vec::new();
        for repo in scope.live("repository")? {
            let url = children(masked, &repo, "url")?
                .first()
                .map(|u| (u.inner_start, u.inner_end));
            repos.push(IndexedRepo {
                id: child_text(repo.inner(masked), "id")?,
                url_inner: url,
            });
        }
        let dm = scope.live("dependencyManagement")?.first().copied();
        let dm_deps = match &dm {
            Some(dm) => children(masked, dm, "dependencies")?.first().copied(),
            None => None,
        };
        Ok(PomIndex {
            deps,
            repos,
            repositories: scope.live("repositories")?.first().copied(),
            dm,
            dm_deps,
            project_close: scope.project_close().ok_or("no </project> tag")?,
        })
    }

    /// The indices of the `<dependency>` elements naming `group:artifact`.
    pub(super) fn matches(&self, group: &str, artifact: &str) -> Vec<usize> {
        (0..self.deps.len())
            .filter(|&i| {
                self.deps[i].group.as_deref() == Some(group)
                    && self.deps[i].artifact.as_deref() == Some(artifact)
            })
            .collect()
    }

    pub(super) fn dep(&self, i: usize) -> &IndexedDep {
        &self.deps[i]
    }

    /// `(id, url)` of each live repository that has an `<id>`.
    pub(super) fn repository_ids_and_urls(&self, pom: &str) -> Vec<(String, Option<String>)> {
        self.repos
            .iter()
            .filter_map(|r| {
                let id = r.id.clone()?;
                let url = r.url_inner.map(|(s, e)| pom[s..e].trim().to_string());
                Some((id, url))
            })
            .collect()
    }

    /// Whether a live repository has the `<id>` `id`.
    pub(super) fn has_repository(&self, id: &str) -> bool {
        self.repos.iter().any(|r| r.id.as_deref() == Some(id))
    }

    /// Every offset at or past `at` moves by `delta`.
    fn shift(&mut self, at: usize, delta: isize) {
        for d in &mut self.deps {
            if let Some((s, e)) = &mut d.version_inner {
                shift_pos(s, at, delta);
                shift_pos(e, at, delta);
            }
        }
        for r in &mut self.repos {
            if let Some((s, e)) = &mut r.url_inner {
                shift_pos(s, at, delta);
                shift_pos(e, at, delta);
            }
        }
        for e in [&mut self.repositories, &mut self.dm, &mut self.dm_deps]
            .into_iter()
            .flatten()
        {
            shift_element(e, at, delta);
        }
        shift_pos(&mut self.project_close, at, delta);
    }

    /// `pom[start..end]` replaced by `text`, offsets kept in step.
    fn splice(&mut self, pom: &mut String, start: usize, end: usize, text: &str) {
        pom.replace_range(start..end, text);
        let delta = text.len() as isize - (end - start) as isize;
        if start == end {
            self.shift(start, delta);
        } else {
            self.shift(end, delta);
        }
    }

    fn anchor_mut(&mut self, anchor: Anchor) -> &mut Option<Element> {
        match anchor {
            Anchor::Repositories => &mut self.repositories,
            Anchor::Dm => &mut self.dm,
            Anchor::DmDeps => &mut self.dm_deps,
        }
    }

    /// `text` inserted at the inner start of `anchor` (its first content),
    /// which keeps its inner start.
    fn insert_first(&mut self, pom: &mut String, anchor: Anchor, text: &str) -> usize {
        let at = self.anchor_mut(anchor).expect("anchor present").inner_start;
        self.splice(pom, at, at, text);
        if let Some(e) = self.anchor_mut(anchor).as_mut() {
            e.inner_start = at;
        }
        at
    }

    /// Rewrite dependency `i`'s literal version to `version`.
    pub(super) fn set_version(&mut self, pom: &mut String, i: usize, version: &str) {
        let (s, e) = self.deps[i].version_inner.expect("a literal version");
        self.splice(pom, s, e, version);
        self.deps[i].version_inner = Some((s, s + version.len()));
        self.deps[i].version_text = Some(version.to_string());
    }

    /// Register the repository element the rewriter placed at `at`.
    fn add_repo(&mut self, pom: &str, at: usize) {
        let repo = authored_element(pom, at, "repository");
        let body = repo.inner(pom);
        let url = elements(body, "url")
            .ok()
            .and_then(|u| u.first().copied())
            .map(|u| {
                (
                    repo.inner_start + u.inner_start,
                    repo.inner_start + u.inner_end,
                )
            });
        self.repos.push(IndexedRepo {
            id: child_text(body, "id").ok().flatten(),
            url_inner: url,
        });
    }

    /// Insert the socket-patch `<repository>`: first in the project's own
    /// `<repositories>` (so it is consulted before the project's other
    /// repositories; a self-closed `<repositories/>` is expanded in place),
    /// else in a new `<repositories>` section right before `</project>`.
    pub(super) fn insert_repository(&mut self, pom: &mut String, id: &str, url: &str) {
        let block = repository_block(id, url);
        match self.repositories {
            Some(repos) if repos.inner_start == repos.end => {
                let text = format!("<repositories>\n{block}\n  </repositories>");
                self.splice(pom, repos.start, repos.end, &text);
                self.repositories = Some(authored_element(pom, repos.start, "repositories"));
                self.add_repo(pom, repos.start + "<repositories>\n".len() + 4);
            }
            Some(_) => {
                let at = self.insert_first(pom, Anchor::Repositories, &format!("\n{block}"));
                self.add_repo(pom, at + 1 + 4);
            }
            None => {
                let at = self.project_close;
                let text = format!("  <repositories>\n{block}\n  </repositories>\n");
                self.splice(pom, at, at, &text);
                self.repositories = Some(authored_element(pom, at + 2, "repositories"));
                self.add_repo(pom, at + "  <repositories>\n".len() + 4);
            }
        }
    }

    /// Register the managed `<dependency>` inserted at `at`.
    fn add_managed(&mut self, pom: &str, at: usize, group: &str, artifact: &str, version: &str) {
        let dep = authored_element(pom, at, "dependency");
        let v = dep.inner_start
            + dep.inner(pom).find("<version>").expect("authored")
            + "<version>".len();
        self.deps.push(IndexedDep {
            group: Some(group.to_string()),
            artifact: Some(artifact.to_string()),
            version_inner: Some((v, v + version.len())),
            version_text: Some(version.to_string()),
            type_text: None,
            classifier: None,
            in_profile: false,
        });
    }

    /// Add a `<dependencyManagement>` version pin: right after the opening
    /// `<dependencies>` of the project's own `<dependencyManagement>`
    /// (expanding a self-closed `<dependencyManagement/>` or
    /// `<dependencies/>`, adding `<dependencies>` when the section has
    /// none), else in a new section right before `</project>`.
    pub(super) fn insert_dependency_management(
        &mut self,
        pom: &mut String,
        group: &str,
        artifact: &str,
        version: &str,
    ) {
        let block = managed_block(group, artifact, version);
        let dependencies = format!("<dependencies>\n{block}\n    </dependencies>");
        // The `<dependency>` sits this far into `<dependencies>…`.
        let entry = "<dependencies>\n".len() + 6;
        let Some(dm) = self.dm else {
            let at = self.project_close;
            let text = format!(
                "  <dependencyManagement>\n    {dependencies}\n  </dependencyManagement>\n"
            );
            self.splice(pom, at, at, &text);
            self.dm = Some(authored_element(pom, at + 2, "dependencyManagement"));
            let deps_at = at + "  <dependencyManagement>\n    ".len();
            self.dm_deps = Some(authored_element(pom, deps_at, "dependencies"));
            self.add_managed(pom, deps_at + entry, group, artifact, version);
            return;
        };
        if dm.inner_start == dm.end {
            let text =
                format!("<dependencyManagement>\n    {dependencies}\n  </dependencyManagement>");
            self.splice(pom, dm.start, dm.end, &text);
            self.dm = Some(authored_element(pom, dm.start, "dependencyManagement"));
            let deps_at = dm.start + "<dependencyManagement>\n    ".len();
            self.dm_deps = Some(authored_element(pom, deps_at, "dependencies"));
            self.add_managed(pom, deps_at + entry, group, artifact, version);
            return;
        }
        match self.dm_deps {
            Some(deps) if deps.inner_start == deps.end => {
                self.splice(pom, deps.start, deps.end, &dependencies);
                self.dm_deps = Some(authored_element(pom, deps.start, "dependencies"));
                self.add_managed(pom, deps.start + entry, group, artifact, version);
            }
            Some(_) => {
                let at = self.insert_first(pom, Anchor::DmDeps, &format!("\n{block}"));
                self.add_managed(pom, at + 1 + 6, group, artifact, version);
            }
            None => {
                let at = self.insert_first(pom, Anchor::Dm, &format!("\n    {dependencies}"));
                let deps_at = at + "\n    ".len();
                self.dm_deps = Some(authored_element(pom, deps_at, "dependencies"));
                self.add_managed(pom, deps_at + entry, group, artifact, version);
            }
        }
    }

    /// Remove the rewriter's `<repository>` with `<id>` `id` (see
    /// [`super::remove_maven_repository`]); `false` when it is not there on
    /// lines of its own.
    pub(super) fn remove_repository(&mut self, pom: &mut String, id: &str) -> bool {
        let Some((cut, end)) = super::maven_repository_removal(pom, id) else {
            return false;
        };
        self.repos.retain(|r| {
            r.url_inner.is_none_or(|(s, _)| s < cut || s >= end) && r.id.as_deref() != Some(id)
        });
        self.splice(pom, cut, end, "");
        true
    }

    /// Point the one live repository with `<id>` `id` at `url`; `false`
    /// when there is no such single repository, it has no `<url>`, or it
    /// already points there.
    pub(super) fn refresh_repository_url(&mut self, pom: &mut String, id: &str, url: &str) -> bool {
        let mut ours = self
            .repos
            .iter()
            .enumerate()
            .filter(|(_, r)| r.id.as_deref() == Some(id));
        let (Some((i, repo)), None) = (ours.next(), ours.next()) else {
            return false;
        };
        let Some((s, e)) = repo.url_inner else {
            return false;
        };
        if pom[s..e].trim() == url {
            return false;
        }
        self.splice(pom, s, e, url);
        self.repos[i].url_inner = Some((s, s + url.len()));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// After any sequence of the rewriter's edits, the kept index is the
    /// index a fresh build of the edited pom reads.
    fn assert_in_step(index: &PomIndex, pom: &str) {
        let fresh = PomIndex::build(pom).expect("the edited pom reads");
        let key = |i: &PomIndex| {
            let mut deps: Vec<_> = i
                .deps
                .iter()
                .map(|d| {
                    (
                        d.group.clone(),
                        d.artifact.clone(),
                        d.version_inner,
                        d.version_text.clone(),
                    )
                })
                .collect();
            deps.sort();
            let mut repos: Vec<_> = i
                .repos
                .iter()
                .map(|r| (r.id.clone(), r.url_inner))
                .collect();
            repos.sort();
            let el = |e: &Option<Element>| e.map(|e| (e.start, e.inner_start, e.inner_end, e.end));
            (
                deps,
                repos,
                el(&i.repositories),
                el(&i.dm),
                el(&i.dm_deps),
                i.project_close,
            )
        };
        assert_eq!(key(index), key(&fresh), "{pom}");
    }

    #[test]
    fn edits_keep_the_index_in_step() {
        for pom in [
            "<project>\n  <dependencies>\n    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>\n  </dependencies>\n</project>\n",
            "<project>\n  <repositories/>\n  <dependencyManagement/>\n  <dependencies>\n    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>\n  </dependencies>\n</project>\n",
            "<project>\n  <dependencyManagement>\n    <!-- c -->\n    <dependencies/>\n  </dependencyManagement>\n  <repositories>\n    <repository><id>x</id><url>u</url></repository>\n  </repositories>\n  <dependencies>\n    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>\n  </dependencies>\n</project>\n",
            "<project>\n  <dependencyManagement>\n  </dependencyManagement>\n  <dependencies>\n    <dependency><groupId>g</groupId><artifactId>a</artifactId><version>1</version></dependency>\n  </dependencies>\n</project>\n",
        ] {
            let mut pom = pom.to_string();
            let mut index = PomIndex::build(&pom).unwrap();
            let [i] = index.matches("g", "a")[..] else {
                panic!("one match");
            };
            index.set_version(&mut pom, i, "1-socket.12345678");
            assert_in_step(&index, &pom);
            for n in 0..2 {
                index.insert_repository(&mut pom, &format!("r{n}"), &format!("https://h/{n}"));
                assert_in_step(&index, &pom);
                index.insert_dependency_management(&mut pom, "t", &format!("m{n}"), "2");
                assert_in_step(&index, &pom);
            }
            assert!(index.refresh_repository_url(&mut pom, "r0", "https://h/rotated"));
            assert_in_step(&index, &pom);
            assert!(!index.refresh_repository_url(&mut pom, "r0", "https://h/rotated"));
            assert_eq!(pom.matches("<repositories").count(), 1, "{pom}");
            assert_eq!(pom.matches("<dependencyManagement").count(), 1, "{pom}");
        }
    }
}
