//! The project-mode scope of the Maven local repository (#265, the Maven
//! child of #595).
//!
//! A local repository is shared by every project on the machine, so in
//! project mode its contents are not this project's packages: a hosted scan
//! would pin, and VEX attest, whatever some other build cached. Maven has no
//! lockfile, so the scope is the dependency graph the project's poms
//! declare, walked through the poms the local repository already holds
//! (Maven caches the pom of every artifact, parent and BOM it resolves):
//!
//! - **Seeds**: every `<dependency>` of the reactor (the root `pom.xml`,
//!   its `<modules>` / `<subprojects>` recursively, every profile, and the
//!   `<dependencies>` each inherits from its parents), any scope.
//! - **Edges**: an artifact's own non-optional `compile` / `runtime`
//!   dependencies (and those its parents declare), which is what Maven
//!   resolves transitively.
//! - **Versions**: the literal, interpolated through the pom's properties
//!   and its parent chain; a version-less declaration takes the managed
//!   version (the pom's parent chain, then its imported BOMs), and a
//!   management entry of the reactor applies to transitives as Maven
//!   applies it. A version this cannot determine (an undefined property, a
//!   range, a pom not in the repository) admits every cached version of
//!   that artifact instead: the scope over-approximates within an artifact
//!   the project names, never across artifacts it does not.
//!
//! Exclusions and mediation are not modelled (both only narrow what Maven
//! resolves), so the scope is a superset of the resolved graph.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::vendor::jvm::maven_reactor::{pom_model, PomDecl, PomModel};

/// `(groupId, artifactId, version)`.
type Gav = (String, String, String);

/// Most artifacts one walk visits; a bigger graph is left unscoped.
const MAX_NODES: usize = 50_000;
/// Deepest parent chain / BOM import nesting followed.
const MAX_DEPTH: usize = 32;
/// Property interpolation depth cap.
const MAX_INTERPOLATION: usize = 16;
/// Most reactor poms read.
const MAX_REACTOR: usize = 4_096;

/// The coordinates a project-mode crawl of the local repository keeps.
#[derive(Debug, Default)]
pub(crate) struct ProjectScope {
    gavs: HashSet<Gav>,
    /// Artifacts admitted at every cached version.
    any_version: HashSet<(String, String)>,
}

impl ProjectScope {
    pub(crate) fn admits(&self, group: &str, artifact: &str, version: &str) -> bool {
        let ga = (group.to_string(), artifact.to_string());
        self.any_version.contains(&ga) || self.gavs.contains(&(ga.0, ga.1, version.to_string()))
    }
}

/// The scope of the Maven project at `cwd` over the local repository
/// `repo`; `None` when `cwd/pom.xml` is not a readable pom or the graph is
/// too big to walk (the crawl then stays unscoped).
pub(crate) fn project_scope(cwd: &Path, repo: &Path) -> Option<ProjectScope> {
    let mut walk = Walk {
        cwd,
        repo,
        models: HashMap::new(),
        scope: ProjectScope::default(),
        queue: VecDeque::new(),
        queued: HashSet::new(),
        reactor_chains: Vec::new(),
        reactor_managed: HashMap::new(),
    };
    walk.reactor()?;
    walk.run()?;
    Some(walk.scope)
}

/// A pom and where it was read from.
#[derive(Clone)]
struct Node {
    model: Rc<PomModel>,
    /// The pom's file (for relative parent paths of reactor poms).
    path: PathBuf,
    /// Read from the checkout (a reactor pom or a local parent).
    local: bool,
}

/// A pom and its parents, nearest first.
type Chain = Vec<Node>;

struct Walk<'w> {
    cwd: &'w Path,
    repo: &'w Path,
    /// Parsed poms by path (`None`: missing or unreadable).
    models: HashMap<PathBuf, Option<Rc<PomModel>>>,
    scope: ProjectScope,
    queue: VecDeque<Gav>,
    queued: HashSet<Gav>,
    /// The reactor poms' chains: their management applies to transitives.
    reactor_chains: Vec<Chain>,
    /// [`Walk::managed_version`] of each reactor chain, by artifact.
    reactor_managed: HashMap<(usize, String, String), Option<Option<String>>>,
}

impl Walk<'_> {
    fn model(&mut self, path: &Path, include_profiles: bool) -> Option<Rc<PomModel>> {
        if let Some(found) = self.models.get(path) {
            return found.clone();
        }
        let parsed = crate::utils::fs::read_regular_to_bytes_sync(path)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|text| pom_model(&text, include_profiles).ok())
            .map(Rc::new);
        self.models.insert(path.to_path_buf(), parsed.clone());
        parsed
    }

    fn repo_pom(&self, (g, a, v): &Gav) -> Option<PathBuf> {
        let safe = |s: &str| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.contains(['/', '\\', '$', '{', '}'])
                && !s.contains("..")
        };
        if !(safe(g) && safe(a) && safe(v)) {
            return None;
        }
        Some(
            self.repo
                .join(g.replace('.', "/"))
                .join(a)
                .join(v)
                .join(format!("{a}-{v}.pom")),
        )
    }

    /// `node` and its parents: a reactor pom's local parent by
    /// `relativePath` (default `../pom.xml`) when that pom is the declared
    /// one, else the parent's pom in the repository.
    fn chain(&mut self, node: Node) -> Chain {
        let mut chain = vec![node];
        while chain.len() < MAX_DEPTH {
            let cur = chain.last().expect("non-empty").clone();
            let Some((pg, pa, pv, rel)) = cur.model.parent.clone() else {
                break;
            };
            let props = chain.clone();
            let resolve = |v: &Option<String>| v.as_deref().and_then(|v| interpolate(v, &props));
            let (pg, pa, pv) = (resolve(&pg), resolve(&pa), resolve(&pv));
            let local = if cur.local && rel.as_deref() != Some("") {
                let rel = rel.unwrap_or_else(|| "../pom.xml".to_string());
                let dir = cur.path.parent().unwrap_or(self.cwd);
                let mut path = dir.join(&rel);
                if !rel.ends_with(".xml") {
                    path = path.join("pom.xml");
                }
                let inside = normalize(&path).is_some_and(|p| p.starts_with(self.cwd));
                inside
                    .then(|| self.model(&path, true).map(|m| (m, path)))
                    .flatten()
                    .filter(|(m, _)| m.artifact.is_some() && m.artifact == pa)
            } else {
                None
            };
            let next = match local {
                Some((model, path)) => Node {
                    model,
                    path,
                    local: true,
                },
                None => {
                    let (Some(pg), Some(pa), Some(pv)) = (pg, pa, pv) else {
                        break;
                    };
                    let gav = (pg, pa, pv);
                    self.admit(&gav);
                    let Some(path) = self.repo_pom(&gav) else {
                        break;
                    };
                    let Some(model) = self.model(&path, false) else {
                        break;
                    };
                    Node {
                        model,
                        path,
                        local: false,
                    }
                }
            };
            chain.push(next);
        }
        chain
    }

    /// Read the reactor and queue every declaration it makes.
    fn reactor(&mut self) -> Option<()> {
        let root = self.cwd.join("pom.xml");
        let model = self.model(&root, true)?;
        let mut pending = vec![Node {
            model,
            path: root.clone(),
            local: true,
        }];
        let mut seen: HashSet<PathBuf> = HashSet::from([root]);
        while let Some(node) = pending.pop() {
            if seen.len() > MAX_REACTOR {
                return None;
            }
            let dir = node.path.parent().unwrap_or(self.cwd).to_path_buf();
            for module in node.model.modules.clone() {
                if module.is_empty() || module.contains("${") {
                    continue;
                }
                let mut path = dir.join(&module);
                if !module.ends_with(".xml") {
                    path = path.join("pom.xml");
                }
                if !normalize(&path).is_some_and(|p| p.starts_with(self.cwd))
                    || !seen.insert(path.clone())
                {
                    continue;
                }
                if let Some(model) = self.model(&path, true) {
                    pending.push(Node {
                        model,
                        path,
                        local: true,
                    });
                }
            }
            let chain = self.chain(node);
            self.reactor_chains.push(chain);
        }
        let chains = std::mem::take(&mut self.reactor_chains);
        for chain in &chains {
            for decl in chain.iter().flat_map(|n| n.model.deps.clone()) {
                self.declare(&decl, chain, true);
            }
            // Imported BOMs and parents are part of the build too.
            for decl in chain.iter().flat_map(|n| n.model.managed.clone()) {
                if is_import(&decl) {
                    if let Some(gav) = decl_gav(&decl, chain) {
                        self.admit(&gav);
                    }
                }
            }
        }
        self.reactor_chains = chains;
        Some(())
    }

    /// Queue `decl` read in `chain`'s context. A transitive edge also takes
    /// any version the reactor's management assigns its artifact.
    fn declare(&mut self, decl: &PomDecl, chain: &Chain, direct: bool) {
        if !direct {
            let reactor = std::mem::take(&mut self.reactor_chains);
            for (i, rc) in reactor.iter().enumerate() {
                let key = (i, decl.group.clone(), decl.artifact.clone());
                let managed = match self.reactor_managed.get(&key) {
                    Some(found) => found.clone(),
                    None => {
                        let found = self.managed_version(rc, &decl.group, &decl.artifact, 0);
                        self.reactor_managed.insert(key, found.clone());
                        found
                    }
                };
                if let Some(version) = managed {
                    self.enqueue(&decl.group, &decl.artifact, version);
                }
            }
            self.reactor_chains = reactor;
        }
        let version = match &decl.version {
            Some(raw) => Some(interpolate(raw, chain)),
            None => self
                .managed_version(chain, &decl.group, &decl.artifact, 0)
                .or(Some(None)),
        };
        self.enqueue(&decl.group, &decl.artifact, version.flatten());
    }

    /// The version `chain` manages `g:a` at: its parent chain's management,
    /// then its imported BOMs'. `None`: not managed; `Some(None)`: managed
    /// at a version this cannot determine.
    fn managed_version(
        &mut self,
        chain: &Chain,
        g: &str,
        a: &str,
        depth: usize,
    ) -> Option<Option<String>> {
        let is_ga = |d: &PomDecl| d.group == g && d.artifact == a && !is_import(d);
        for node in chain {
            if let Some(decl) = node.model.managed.iter().find(|d| is_ga(d)) {
                return Some(decl.version.as_deref().and_then(|v| interpolate(v, chain)));
            }
        }
        if depth >= MAX_DEPTH {
            return Some(None);
        }
        let imports: Vec<PomDecl> = chain
            .iter()
            .flat_map(|n| n.model.managed.iter().filter(|d| is_import(d)).cloned())
            .collect();
        for decl in imports {
            let Some(gav) = decl_gav(&decl, chain) else {
                continue;
            };
            let Some(path) = self.repo_pom(&gav) else {
                continue;
            };
            let Some(model) = self.model(&path, false) else {
                continue;
            };
            let bom = self.chain(Node {
                model,
                path,
                local: false,
            });
            if let Some(found) = self.managed_version(&bom, g, a, depth + 1) {
                return Some(found);
            }
        }
        None
    }

    /// Queue `g:a` at `version` (every cached version when unknown).
    fn enqueue(&mut self, g: &str, a: &str, version: Option<String>) {
        match version.filter(|v| !is_range(v)) {
            Some(v) => {
                let gav = (g.to_string(), a.to_string(), v);
                if self.queued.insert(gav.clone()) {
                    self.queue.push_back(gav);
                }
            }
            None => {
                if !self
                    .scope
                    .any_version
                    .insert((g.to_string(), a.to_string()))
                {
                    return;
                }
                let dir = self.repo.join(g.replace('.', "/")).join(a);
                let Ok(entries) = std::fs::read_dir(&dir) else {
                    return;
                };
                for entry in entries.flatten() {
                    if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                        continue;
                    }
                    let v = entry.file_name().to_string_lossy().into_owned();
                    let gav = (g.to_string(), a.to_string(), v);
                    if self.queued.insert(gav.clone()) {
                        self.queue.push_back(gav);
                    }
                }
            }
        }
    }

    fn admit(&mut self, gav: &Gav) {
        self.scope.gavs.insert(gav.clone());
    }

    /// Walk the queued artifacts' own dependencies.
    fn run(&mut self) -> Option<()> {
        while let Some(gav) = self.queue.pop_front() {
            if self.scope.gavs.len() > MAX_NODES {
                return None;
            }
            self.admit(&gav);
            let Some(path) = self.repo_pom(&gav) else {
                continue;
            };
            let Some(model) = self.model(&path, false) else {
                continue;
            };
            let chain = self.chain(Node {
                model,
                path,
                local: false,
            });
            let deps: Vec<PomDecl> = chain.iter().flat_map(|n| n.model.deps.clone()).collect();
            for decl in deps {
                let transitive =
                    matches!(decl.scope.as_deref(), None | Some("compile" | "runtime"));
                if transitive && !decl.optional {
                    self.declare(&decl, &chain, false);
                }
            }
        }
        Some(())
    }
}

fn is_import(decl: &PomDecl) -> bool {
    decl.scope.as_deref() == Some("import") && decl.kind.as_deref() == Some("pom")
}

fn decl_gav(decl: &PomDecl, chain: &Chain) -> Option<Gav> {
    Some((
        interpolate(&decl.group, chain)?,
        interpolate(&decl.artifact, chain)?,
        interpolate(decl.version.as_deref()?, chain)?,
    ))
}

fn is_range(version: &str) -> bool {
    version.starts_with(['[', '(']) || version.contains(',')
}

/// `${name}` interpolation in `chain`'s context: the model's own version
/// expressions, then `<properties>` up the chain (nearest first).
fn interpolate(value: &str, chain: &Chain) -> Option<String> {
    interpolate_at(value, chain, 0)
}

fn interpolate_at(value: &str, chain: &Chain, depth: usize) -> Option<String> {
    if !value.contains("${") {
        return Some(value.to_string());
    }
    if depth > MAX_INTERPOLATION {
        return None;
    }
    let own = &chain.first()?.model;
    let parent_field = |i: usize| -> Option<String> {
        let (g, a, v, _) = own.parent.as_ref()?;
        [g, a, v][i].clone()
    };
    let lookup = |name: &str| -> Option<String> {
        match name {
            "project.version" | "pom.version" | "version" => {
                own.version.clone().or_else(|| parent_field(2))
            }
            "project.groupId" | "pom.groupId" | "groupId" => {
                own.group.clone().or_else(|| parent_field(0))
            }
            "project.artifactId" | "pom.artifactId" | "artifactId" => own.artifact.clone(),
            "project.parent.version" | "parent.version" => parent_field(2),
            "project.parent.groupId" | "parent.groupId" => parent_field(0),
            _ => chain.iter().find_map(|n| n.model.props.get(name).cloned()),
        }
    };
    let mut out = String::new();
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let close = after.find('}')?;
        let raw = lookup(&after[..close])?;
        out.push_str(&interpolate_at(&raw, chain, depth + 1)?);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

/// `path` with `.` / `..` components folded (no filesystem access);
/// `None` when it climbs above its root.
fn normalize(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    fn dep(g: &str, a: &str, v: Option<&str>, extra: &str) -> String {
        let v = v.map_or(String::new(), |v| format!("<version>{v}</version>"));
        format!(
            "<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>{v}{extra}</dependency>"
        )
    }

    fn pom(g: &str, a: &str, v: &str, body: &str) -> String {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><groupId>{g}</groupId>\
             <artifactId>{a}</artifactId><version>{v}</version>{body}</project>"
        )
    }

    /// Cache `g:a:v` in `repo` with `body` as its pom's extra content.
    fn cache(repo: &Path, g: &str, a: &str, v: &str, body: &str) {
        write(
            repo,
            &format!("{}/{a}/{v}/{a}-{v}.pom", g.replace('.', "/")),
            &pom(g, a, v, body),
        );
    }

    fn deps(list: &[String]) -> String {
        format!("<dependencies>{}</dependencies>", list.concat())
    }

    #[test]
    fn the_scope_is_the_declared_graph_not_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let (cwd, repo) = (dir.path().join("p"), dir.path().join("m2"));
        write(
            &cwd,
            "pom.xml",
            &pom(
                "com.example",
                "app",
                "1",
                &deps(&[
                    dep("junit", "junit", Some("4.13.2"), "<scope>test</scope>"),
                    dep("org.apache.commons", "commons-text", Some("${ct}"), ""),
                ])
                .replace(
                    "<dependencies>",
                    "<properties><ct>1.10.0</ct></properties><dependencies>",
                ),
            ),
        );
        cache(
            &repo,
            "junit",
            "junit",
            "4.13.2",
            &deps(&[dep("org.hamcrest", "hamcrest-core", Some("1.3"), "")]),
        );
        cache(&repo, "org.hamcrest", "hamcrest-core", "1.3", "");
        cache(
            &repo,
            "org.apache.commons",
            "commons-text",
            "1.10.0",
            &deps(&[
                dep("org.apache.commons", "commons-lang3", Some("3.12.0"), ""),
                dep("org.example", "test-only", Some("1"), "<scope>test</scope>"),
                dep(
                    "org.example",
                    "optional",
                    Some("1"),
                    "<optional>true</optional>",
                ),
            ]),
        );
        cache(&repo, "org.apache.commons", "commons-lang3", "3.12.0", "");
        // Cached by some other project.
        cache(&repo, "org.apache.commons", "commons-lang3", "3.11", "");
        cache(&repo, "com.unrelated", "lib", "2.0", "");
        let scope = project_scope(&cwd, &repo).unwrap();
        for (g, a, v) in [
            ("junit", "junit", "4.13.2"),
            ("org.hamcrest", "hamcrest-core", "1.3"),
            ("org.apache.commons", "commons-text", "1.10.0"),
            ("org.apache.commons", "commons-lang3", "3.12.0"),
        ] {
            assert!(scope.admits(g, a, v), "{g}:{a}:{v}");
        }
        for (g, a, v) in [
            ("org.apache.commons", "commons-lang3", "3.11"),
            ("com.unrelated", "lib", "2.0"),
            ("org.example", "test-only", "1"),
            ("org.example", "optional", "1"),
        ] {
            assert!(!scope.admits(g, a, v), "{g}:{a}:{v}");
        }
    }

    #[test]
    fn modules_parents_boms_and_management_are_followed() {
        let dir = tempfile::tempdir().unwrap();
        let (cwd, repo) = (dir.path().join("p"), dir.path().join("m2"));
        // Root: an external parent, a BOM import and reactor management of
        // a transitive.
        write(
            &cwd,
            "pom.xml",
            &format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.corp</groupId>\
                 <artifactId>corp-parent</artifactId><version>3</version><relativePath/></parent>\
                 <artifactId>root</artifactId><packaging>pom</packaging>\
                 <modules><module>a</module></modules>\
                 <dependencyManagement><dependencies>{}{}</dependencies></dependencyManagement>\
                 </project>",
                dep(
                    "com.corp",
                    "corp-bom",
                    Some("${project.version}"),
                    "<type>pom</type><scope>import</scope>"
                ),
                dep("org.example", "managed-transitive", Some("9"), ""),
            ),
        );
        write(
            &cwd,
            "a/pom.xml",
            &format!(
                "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.corp</groupId>\
                 <artifactId>root</artifactId><version>3</version></parent>\
                 <artifactId>a</artifactId>{}</project>",
                deps(&[
                    dep("org.example", "from-bom", None, ""),
                    dep("org.example", "from-parent", None, ""),
                ])
            ),
        );
        cache(
            &repo,
            "com.corp",
            "corp-parent",
            "3",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dep("org.example", "from-parent", Some("2"), "")
            ),
        );
        cache(
            &repo,
            "com.corp",
            "corp-bom",
            "3",
            &format!(
                "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
                dep("org.example", "from-bom", Some("1"), "")
            ),
        );
        cache(
            &repo,
            "org.example",
            "from-bom",
            "1",
            &deps(&[dep("org.example", "managed-transitive", Some("8"), "")]),
        );
        cache(&repo, "org.example", "from-parent", "2", "");
        cache(&repo, "org.example", "from-parent", "1", "");
        cache(&repo, "org.example", "managed-transitive", "9", "");
        let scope = project_scope(&cwd, &repo).unwrap();
        for (g, a, v) in [
            ("com.corp", "corp-parent", "3"),
            ("com.corp", "corp-bom", "3"),
            ("org.example", "from-bom", "1"),
            ("org.example", "from-parent", "2"),
            ("org.example", "managed-transitive", "9"),
        ] {
            assert!(scope.admits(g, a, v), "{g}:{a}:{v}");
        }
        assert!(!scope.admits("org.example", "from-parent", "1"));
    }

    #[test]
    fn an_undeterminable_version_admits_every_cached_version_of_that_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let (cwd, repo) = (dir.path().join("p"), dir.path().join("m2"));
        write(
            &cwd,
            "pom.xml",
            &pom(
                "com.example",
                "app",
                "1",
                &deps(&[
                    dep("org.example", "undefined", Some("${nowhere}"), ""),
                    dep("org.example", "ranged", Some("[1,2)"), ""),
                ]),
            ),
        );
        for (a, v) in [("undefined", "1"), ("undefined", "2"), ("ranged", "1.5")] {
            cache(&repo, "org.example", a, v, "");
        }
        cache(&repo, "org.example", "other", "1", "");
        let scope = project_scope(&cwd, &repo).unwrap();
        assert!(scope.admits("org.example", "undefined", "1"));
        assert!(scope.admits("org.example", "undefined", "2"));
        assert!(scope.admits("org.example", "ranged", "1.5"));
        assert!(!scope.admits("org.example", "other", "1"));
    }

    #[test]
    fn no_readable_root_pom_is_unscoped() {
        let dir = tempfile::tempdir().unwrap();
        assert!(project_scope(dir.path(), dir.path()).is_none());
        write(dir.path(), "pom.xml", "<project><unclosed></project>");
        assert!(project_scope(dir.path(), dir.path()).is_none());
    }
}
