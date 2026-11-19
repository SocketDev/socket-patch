//! Reads the files of a reactor for a caller that reads a project its own
//! way (a disk, a snapshot of it, an in-memory project).
//!
//! The reactor planner reads through a synchronous function, and stops at
//! the first module pom it cannot find. A caller that learns from it which
//! files to fetch therefore learns one module at a time. [`read_reactor`]
//! walks the same files by itself instead: every pom is parsed once, each
//! pom's modules, parent and (for Maven 4) discovered subprojects are asked
//! for together, and a file that is not there stops nothing. The hosted
//! rewriter, its discovery and its restore all read a reactor through it,
//! so what one of them plans over is what the others find.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use super::{
    cli_properties, discovery_on, module_refs, normalize, pom_candidates, subprojects_in, Pom,
    MAVEN_CONFIG, NESTED_MVN_FILES,
};
use crate::vendor::jvm::layout::POM_FILE;
use crate::vendor::lock_inventory::ProjectView;

/// How many files one reactor is read for: far more than any reactor
/// holds, so only a walk gone wrong stops here (the planner then refuses
/// the reactor for the module it cannot find).
const MAX_FILES: usize = 200_000;

/// One thing the walk asks its caller for.
enum Wanted {
    /// The text of a file.
    File(String),
    /// The subprojects Maven 4 discovers under a directory.
    Subprojects(String),
}

/// The walk: what was read so far, and what to read next.
struct Walk {
    texts: BTreeMap<String, String>,
    /// Every path asked for, answered or not.
    asked: BTreeSet<String>,
    /// The paths that are poms when they are there.
    poms: BTreeSet<String>,
    /// `<dir>/pom.xml` → `<dir>`: a `<module>` or `<relativePath>` may name
    /// the pom file itself, which is tried once its directory reading has
    /// no `pom.xml`.
    named_file: BTreeMap<String, String>,
    wanted: Vec<Wanted>,
    /// Maven 4 subproject discovery is on (`.mvn/maven.config` may turn it
    /// off).
    discovery: bool,
    listed: BTreeSet<String>,
}

impl Walk {
    fn new(root_pom: &str, maven_config: Option<&str>) -> Walk {
        let mut walk = Walk {
            texts: BTreeMap::new(),
            asked: BTreeSet::from([POM_FILE.to_string(), MAVEN_CONFIG.to_string()]),
            poms: BTreeSet::from([POM_FILE.to_string()]),
            named_file: BTreeMap::new(),
            wanted: Vec::new(),
            discovery: discovery_on(&maven_config.map(cli_properties).unwrap_or_default()),
            listed: BTreeSet::new(),
        };
        if let Some(config) = maven_config {
            walk.texts
                .insert(MAVEN_CONFIG.to_string(), config.to_string());
        }
        walk.supply(POM_FILE.to_string(), Some(root_pom.to_string()));
        walk
    }

    fn want(&mut self, rel: String) {
        if self.asked.len() < MAX_FILES && self.asked.insert(rel.clone()) {
            self.wanted.push(Wanted::File(rel));
        }
    }

    /// Ask for the pom the normalized `path` names: `<path>/pom.xml`, else
    /// the file `path` itself.
    fn want_pom(&mut self, path: String) {
        let mut candidates = pom_candidates(path).into_iter();
        let Some(first) = candidates.next() else {
            return;
        };
        if let Some(file) = candidates.next() {
            self.named_file.insert(first.clone(), file);
        }
        self.poms.insert(first.clone());
        self.want(first);
    }

    /// The answer for `rel`: its text, or `None` when it is not there (or
    /// cannot be read).
    fn supply(&mut self, rel: String, text: Option<String>) {
        let Some(text) = text else {
            if let Some(file) = self.named_file.remove(&rel) {
                self.poms.insert(file.clone());
                self.want(file);
            }
            return;
        };
        if self.poms.contains(&rel) {
            self.follow(&rel, &text);
        }
        self.texts.insert(rel, text);
    }

    /// Ask for what the pom at `rel` leads the planner to: its modules,
    /// its parent in the checkout, the subprojects Maven 4 discovers under
    /// it, and whether its directory has a `.mvn` of its own. A pom that
    /// does not parse leads nowhere; the planner says so.
    fn follow(&mut self, rel: &str, text: &str) {
        let Ok(pom) = Pom::parse(rel, text.as_bytes().to_vec()) else {
            return;
        };
        for module in module_refs(&pom.doc) {
            if module.is_empty() || module.contains("${") {
                continue;
            }
            if let Some(path) = normalize(&pom.dir, &module) {
                self.want_pom(path);
            }
        }
        if self.discovery && pom.discovers_subprojects && self.listed.insert(pom.dir.clone()) {
            self.wanted.push(Wanted::Subprojects(pom.dir.clone()));
        }
        if !pom.dir.is_empty() {
            for file in NESTED_MVN_FILES {
                self.want(format!("{}/.mvn/{file}", pom.dir));
            }
        }
        let relative = match &pom.parent {
            None => None,
            Some(parent) => match parent.relative_path.as_deref() {
                Some("") => None,
                Some(path) => Some(path),
                None => Some("../pom.xml"),
            },
        };
        if let Some(path) = relative.and_then(|path| normalize(&pom.dir, path)) {
            self.want_pom(path);
        }
    }
}

/// Every file the reactor planner reads for the project whose root pom is
/// `root_pom` (with `.mvn/maven.config` as `maven_config`), by
/// root-relative path: the root pom and the config themselves, the pom of
/// each module (theirs in turn), each parent pom a module inherits from
/// inside the checkout, the subprojects Maven 4 discovers, and the `.mvn`
/// files of a module directory (the planner asks whether they are there).
///
/// `read` fetches one file as text, `None` when it is missing or not
/// readable; a path the walk asks for may be a directory. A file that is a
/// symbolic link is never read: hosted mode would replace the link with a
/// copy when it rewrote it, and the planner must not plan over a pom it
/// may not write. Its module then reads as missing, and the planner
/// refuses the reactor with nothing written. A subproject Maven 4
/// discovers whose pom cannot be read is kept, empty, so the reactor is
/// refused the same way and not planned without it.
pub async fn read_reactor<F, Fut>(
    view: &ProjectView<'_>,
    root_pom: &str,
    maven_config: Option<&str>,
    mut read: F,
) -> BTreeMap<String, String>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Option<String>>,
{
    let mut walk = Walk::new(root_pom, maven_config);
    while let Some(wanted) = walk.wanted.pop() {
        match wanted {
            Wanted::File(rel) => {
                let text = match view.is_symlink(&rel) {
                    true => None,
                    false => read(rel.clone()).await,
                };
                walk.supply(rel, text);
            }
            Wanted::Subprojects(dir) => {
                for name in subprojects_in(view, &dir).await {
                    let rel = match dir.as_str() {
                        "" => format!("{name}/{POM_FILE}"),
                        dir => format!("{dir}/{name}/{POM_FILE}"),
                    };
                    if !walk.asked.insert(rel.clone()) {
                        continue;
                    }
                    let text = match view.is_symlink(&rel) {
                        true => None,
                        false => read(rel.clone()).await,
                    };
                    walk.poms.insert(rel.clone());
                    walk.supply(rel, Some(text.unwrap_or_default()));
                }
            }
        }
    }
    walk.texts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject};

    fn pom(artifact: &str, body: &str) -> String {
        format!(
            "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>t</groupId>\n  \
             <artifactId>{artifact}</artifactId>\n  <version>1</version>\n{body}</project>\n"
        )
    }

    fn modules(names: &[String]) -> String {
        let list: String = names
            .iter()
            .map(|name| format!("    <module>{name}</module>\n"))
            .collect();
        format!("  <packaging>pom</packaging>\n  <modules>\n{list}  </modules>\n")
    }

    /// Read the reactor of `project`, with every path `read` was asked.
    async fn read(project: &MemoryProject) -> (BTreeMap<String, String>, Vec<String>) {
        let view = ProjectView::Memory(project);
        let root = match project.get("pom.xml") {
            Some(MemoryEntry::Text(text)) => text.to_string(),
            _ => panic!("no root pom"),
        };
        let asked = std::cell::RefCell::new(Vec::new());
        let texts = read_reactor(&view, &root, None, |rel| {
            asked.borrow_mut().push(rel.clone());
            let text = match project.get(&rel) {
                Some(MemoryEntry::Text(text)) => Some(text.to_string()),
                _ => None,
            };
            async move { text }
        })
        .await;
        (texts, asked.into_inner())
    }

    /// A reactor of hundreds of modules, groups of them under their own
    /// aggregator, is read whole, each file asked for once: the number of
    /// modules bounds nothing, and no pom is fetched or parsed twice.
    #[tokio::test]
    async fn a_large_reactor_is_read_whole_and_each_file_once() {
        let mut project = MemoryProject::new();
        let groups: Vec<String> = (0..20).map(|g| format!("group-{g}")).collect();
        project.insert_text("pom.xml", pom("root", &modules(&groups)).as_str());
        let mut poms = vec!["pom.xml".to_string()];
        for group in &groups {
            let members: Vec<String> = (0..10).map(|m| format!("module-{m}")).collect();
            project.insert_text(
                format!("{group}/pom.xml"),
                pom(group, &modules(&members)).as_str(),
            );
            poms.push(format!("{group}/pom.xml"));
            for member in &members {
                project.insert_text(
                    format!("{group}/{member}/pom.xml"),
                    pom(&format!("{group}-{member}"), "").as_str(),
                );
                poms.push(format!("{group}/{member}/pom.xml"));
            }
        }
        let (texts, asked) = read(&project).await;
        assert_eq!(poms.len(), 221);
        for rel in &poms {
            assert!(texts.contains_key(rel), "{rel} was not read");
        }
        let mut once = asked.clone();
        once.sort();
        once.dedup();
        assert_eq!(asked.len(), once.len(), "a path was asked for twice");
        // What the planner then reads from these files is the whole reactor.
        let read = |rel: &str| texts.get(rel).map(|text| text.clone().into_bytes());
        let list = |dir: &str| crate::patch::redirect::gradle::key_list(&texts, dir);
        let reactor = super::super::HostedReactor::read(&read, &list).expect("a reactor");
        assert_eq!(reactor.modules().len(), 221);
    }

    /// A file that is not there stops nothing: its siblings are read all
    /// the same. A module named by its pom file is read; a module pom that
    /// is a symbolic link is not; a parent pom outside the module list is.
    #[tokio::test]
    async fn a_missing_or_linked_module_stops_nothing() {
        let mut project = MemoryProject::new();
        let names: Vec<String> = ["gone", "linked", "named/custom.xml", "kept"]
            .map(str::to_string)
            .into();
        project.insert_text("pom.xml", pom("root", &modules(&names)).as_str());
        project.insert("linked/pom.xml", MemoryEntry::Symlink);
        project.insert_text("named/custom.xml", pom("named", "").as_str());
        project.insert_text(
            "kept/pom.xml",
            pom(
                "kept",
                "  <parent>\n    <groupId>t</groupId>\n    <artifactId>base</artifactId>\n    \
                 <version>1</version>\n    <relativePath>../base/pom.xml</relativePath>\n  \
                 </parent>\n",
            )
            .as_str(),
        );
        project.insert_text("base/pom.xml", pom("base", "").as_str());
        let (texts, _) = read(&project).await;
        let read: Vec<&str> = texts.keys().map(String::as_str).collect();
        assert_eq!(
            read,
            [
                "base/pom.xml",
                "kept/pom.xml",
                "named/custom.xml",
                "pom.xml"
            ]
        );
    }
}
