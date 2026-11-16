//! Which version of each artifact Maven puts on the classpath of each
//! module of a project, read from the project's poms and the poms the
//! Maven local repository already holds (Maven caches the pom of every
//! artifact, parent and BOM it reads). Nothing is executed.
//!
//! A `<dependencyManagement>` pin makes every occurrence of an artifact
//! one version, so a pin of `g:a:v` is only safe in a module where Maven
//! selects `v` already: anywhere else it changes what the build resolves.
//! Hosted and vendored mode ask this model before they pin.
//!
//! The model follows Maven 3's resolver:
//!
//! - **The graph**: a module's `<dependencies>` (its own and its parents',
//!   a child's declaration first), then each artifact's own `compile` /
//!   `runtime`, non-optional dependencies. An `<exclusion>` removes an
//!   artifact below the declaration that carries it. A dependency on a
//!   module of the reactor reads that module's pom.
//! - **Versions**: a declared version, else the managed one (the pom's
//!   parent chain, then its imported BOMs, first declared first). The
//!   module's own management also overrides the version of every
//!   transitive dependency. A range is every version in it that the
//!   `maven-metadata-*.xml` files beside the artifact list.
//! - **Mediation**: artifacts are settled parents first; among the
//!   surviving declarations of one artifact the nearest wins, the first
//!   declared on a tie, the highest of one range. What a losing version
//!   depends on leaves the graph. Ranges are hard requirements: a winner
//!   outside one gives way to the nearest version every range admits.
//!
//! Every answer says whether it is certain. It is not when something the
//! selection depends on could not be read: a pom missing from the local
//! repository (the project was never resolved), a version or coordinate
//! through a property that is undefined or that a profile redefines, a
//! profile that declares dependencies or management, a relocation, or a
//! dependency cycle. A caller never pins on an uncertain answer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use super::maven_scope::{is_import, normalize, Chain, Node, Walk};
use crate::formats::maven::version::{MavenVersion, VersionRange};
use crate::formats::maven::{
    interpolate_strict, lookup_property, maven_config_properties, split_socket_version, PomLayer,
};
use crate::vendor::jvm::maven_reactor::MAVEN_CONFIG;

/// Most distinct nodes one module's graph may hold; a bigger one is left
/// undetermined.
const MAX_GRAPH: usize = 50_000;
/// Deepest BOM import nesting followed.
const MAX_IMPORT_DEPTH: usize = 32;
/// The Maven Wrapper's settings file.
const WRAPPER_PROPERTIES: &str = ".mvn/wrapper/maven-wrapper.properties";

type Ga = (String, String);
type Gav = (String, String, String);

/// What Maven selects for one artifact in one module, as far as a patch
/// of `base` is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The module resolves the artifact at the patch's base version.
    Selected,
    /// The module resolves the artifact at this other version.
    Other(String),
    /// The module does not resolve the artifact.
    Absent,
    /// The model cannot tell, and why.
    Undetermined(String),
}

/// A patch's standing across every module of the build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// At least one module selects the base version.
    Selected,
    /// No module selects it, and each one's answer is certain: the other
    /// versions the modules select instead (none when no module resolves
    /// the artifact at all).
    NotSelected(Vec<String>),
    /// No module is known to select it and some cannot be told, and why.
    Undetermined(String),
}

/// The versions Maven selects in each module of a project.
#[derive(Debug, Clone, Default)]
pub struct MavenSelection {
    modules: Vec<Module>,
    /// Why nothing could be modelled.
    unavailable: Option<String>,
    /// Why some module of the build was not read: no answer covers the
    /// whole build then.
    incomplete: Option<String>,
}

#[derive(Debug, Clone)]
struct Module {
    /// The module's pom, relative to the project root (`pom.xml`,
    /// `core/pom.xml`).
    pom: String,
    /// The main jar of each artifact the module resolves.
    picks: HashMap<Ga, Pick>,
    /// The depth from which the module's graph may hold artifacts that
    /// were not read, and why.
    unknown: Option<(usize, String)>,
}

#[derive(Debug, Clone)]
struct Pick {
    /// `None`: declared, at a version that cannot be told.
    version: Option<String>,
    depth: usize,
    /// Why another version may be the one selected.
    doubt: Option<String>,
    /// Selected as the highest version of a range.
    ranged: bool,
}

impl MavenSelection {
    /// A selection that answers [`Verdict::Undetermined`] everywhere.
    pub fn unavailable(why: impl Into<String>) -> Self {
        MavenSelection {
            modules: Vec::new(),
            unavailable: Some(why.into()),
            incomplete: None,
        }
    }

    /// The selection of the project at `project_root` over the Maven local
    /// repository this process resolves against.
    pub fn for_project(project_root: &Path) -> Self {
        Self::for_project_in(project_root, None)
    }

    /// [`Self::for_project`] over the local repository `repo` when one is
    /// given.
    pub fn for_project_in(project_root: &Path, repo: Option<&Path>) -> Self {
        let repo = match repo {
            Some(repo) => Some(repo.to_path_buf()),
            None => super::maven_crawler::JvmEnv::from_process().m2_repo,
        };
        match repo {
            Some(repo) => Self::of(project_root, &repo),
            None => Self::unavailable("no Maven local repository is configured"),
        }
    }

    /// The selection of the project at `project_root` over the local
    /// repository `repo`. One run asks for it once per patch and command
    /// stage, so the last answer is kept and reused while every file it
    /// was read from (the project's poms and configuration, each pom
    /// looked up in the repository, each version list) is as it was: a
    /// few hundred `stat`s in place of as many parses. What a run writes
    /// itself (a pin, a rewritten declaration) changes a pom and is read
    /// again.
    pub fn of(project_root: &Path, repo: &Path) -> Self {
        static LAST: std::sync::Mutex<Option<Kept>> = std::sync::Mutex::new(None);
        let key = (project_root.to_path_buf(), repo.to_path_buf());
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(kept) = last.as_ref() {
            if kept.key == key && kept.sources.iter().all(|(path, was)| stamp(path) == *was) {
                return kept.selection.clone();
            }
        }
        let (selection, sources) = select(project_root, repo);
        *last = Some(Kept {
            key,
            sources: sources
                .into_iter()
                .map(|p| (stamp(&p), p))
                .map(|(s, p)| (p, s))
                .collect::<Vec<_>>(),
            selection: selection.clone(),
        });
        selection
    }

    /// The poms of the modules that were modelled.
    pub fn modules(&self) -> impl Iterator<Item = &str> {
        self.modules.iter().map(|m| m.pom.as_str())
    }

    /// What the module whose pom is `pom` (project-relative, forward
    /// slashes) resolves `group:artifact` at, for a patch of `base`. A
    /// `<base>-socket.<hex8>` version, which an earlier pin wrote, is the
    /// base version.
    pub fn verdict(&self, pom: &str, group: &str, artifact: &str, base: &str) -> Verdict {
        if let Some(why) = &self.unavailable {
            return Verdict::Undetermined(why.clone());
        }
        let Some(module) = self.modules.iter().find(|m| m.pom == pom) else {
            return Verdict::Undetermined(format!("{pom} was not read as a module of the build"));
        };
        let unread = |depth: usize| {
            module
                .unknown
                .as_ref()
                .filter(|(from, _)| *from <= depth)
                .map(|(_, why)| why.clone())
        };
        let Some(pick) = module.picks.get(&(group.to_string(), artifact.to_string())) else {
            return match unread(usize::MAX) {
                Some(why) => Verdict::Undetermined(why),
                None => Verdict::Absent,
            };
        };
        if let Some(why) = pick.doubt.clone().or_else(|| unread(pick.depth)) {
            return Verdict::Undetermined(why);
        }
        let Some(version) = &pick.version else {
            return Verdict::Undetermined(format!(
                "the version {pom} declares for {group}:{artifact} cannot be read"
            ));
        };
        let selected =
            version == base || split_socket_version(version).is_some_and(|(of, _)| of == base);
        match (selected, pick.ranged) {
            (false, _) => Verdict::Other(version.clone()),
            (true, false) => Verdict::Selected,
            // A pin would turn the range into one version for good.
            (true, true) => Verdict::Undetermined(format!(
                "{pom} selects {group}:{artifact} {base} as the highest version of a version \
                 range, which a pin would freeze"
            )),
        }
    }

    /// The first module whose selection of `group:artifact` cannot be
    /// told, and why.
    pub fn undetermined_in(
        &self,
        group: &str,
        artifact: &str,
        base: &str,
    ) -> Option<(String, String)> {
        if let Some(why) = &self.unavailable {
            return Some(("pom.xml".to_string(), why.clone()));
        }
        self.modules.iter().find_map(|module| {
            match self.verdict(&module.pom, group, artifact, base) {
                Verdict::Undetermined(why) => Some((module.pom.clone(), why)),
                _ => None,
            }
        })
    }

    /// [`Self::verdict`] over every module.
    pub fn standing(&self, group: &str, artifact: &str, base: &str) -> Standing {
        if let Some(why) = &self.unavailable {
            return Standing::Undetermined(why.clone());
        }
        let mut others = BTreeSet::new();
        let mut undetermined = None;
        for module in &self.modules {
            match self.verdict(&module.pom, group, artifact, base) {
                Verdict::Selected => return Standing::Selected,
                Verdict::Other(version) => {
                    others.insert(version);
                }
                Verdict::Absent => {}
                Verdict::Undetermined(why) => {
                    undetermined.get_or_insert(why);
                }
            }
        }
        match undetermined.or_else(|| self.incomplete.clone()) {
            Some(why) => Standing::Undetermined(why),
            None => {
                let mut others: Vec<String> = others.into_iter().collect();
                others.sort_by_key(|v| MavenVersion::parse(v));
                Standing::NotSelected(others)
            }
        }
    }
}

#[cfg(test)]
impl MavenSelection {
    /// A selection of `modules` that answers with `picks`: `(pom, group,
    /// artifact, version or why it cannot be told)`. A module resolves no
    /// artifact it has no pick for.
    pub(crate) fn answering(
        modules: &[&str],
        picks: &[(&str, &str, &str, Result<&str, &str>)],
    ) -> Self {
        let modules = modules
            .iter()
            .map(|pom| Module {
                pom: pom.to_string(),
                picks: picks
                    .iter()
                    .filter(|(of, ..)| of == pom)
                    .map(|(_, g, a, version)| {
                        let pick = Pick {
                            version: version.ok().map(str::to_string),
                            depth: 2,
                            doubt: version.err().map(str::to_string),
                            ranged: false,
                        };
                        ((g.to_string(), a.to_string()), pick)
                    })
                    .collect(),
                unknown: None,
            })
            .collect();
        MavenSelection {
            modules,
            unavailable: None,
            incomplete: None,
        }
    }
}

/// The last selection [`MavenSelection::of`] read, and the project files
/// it was read from as they were.
struct Kept {
    key: (PathBuf, PathBuf),
    sources: Vec<(PathBuf, Stamp)>,
    selection: MavenSelection,
}

/// A file's length and modification time (`None`: not there).
type Stamp = Option<(u64, Option<std::time::SystemTime>)>;

fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().ok()))
}

/// The one line that says a patch's base version is not part of the
/// build: which versions Maven selects instead.
pub fn not_selected_detail(group: &str, artifact: &str, base: &str, others: &[String]) -> String {
    if others.is_empty() {
        format!(
            "no module of this build resolves {group}:{artifact}, so the patch for {base} has \
             nothing to patch here"
        )
    } else {
        format!(
            "Maven selects {group}:{artifact} {} in this build, not {base}, so the patch for \
             {base} has nothing to patch here",
            others.join(" and ")
        )
    }
}

/// What every "not cached" cause names: resolving the project fills it.
const NOT_CACHED: &str = "the local Maven repository";

/// The one line that says the selection of an artifact could not be told,
/// with the remedy that can work for `why`. Resolving the project helps
/// only when a pom or version list is missing from the local repository;
/// anything else (a profile that may change the graph, Maven 4, a cycle, a
/// relocation, a range a pin would freeze, an undefined property) stays as
/// it is however often the project is resolved, and a declaration of the
/// artifact at the base version, which is patched where it stands, is the
/// way through.
pub fn undetermined_detail(group: &str, artifact: &str, base: &str, why: &str) -> String {
    let declare = format!(
        "declare {group}:{artifact} {base} in the pom of each module that should take the \
         patch (a declaration that names the version is patched where it stands)"
    );
    let remedy = if why.contains(NOT_CACHED) {
        format!("resolve the project once (`mvn -q dependency:resolve`) and re-run, or {declare}")
    } else {
        format!("resolving the project again will not change that: {declare}")
    };
    format!(
        "which version of {group}:{artifact} Maven selects cannot be told ({why}), so nothing \
         was pinned for {base}: {remedy}"
    )
}

// ── the model ───────────────────────────────────────────────────────

/// One conflict group: Maven mediates the versions of a
/// `group:artifact:extension:classifier`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Key {
    group: String,
    artifact: String,
    extension: String,
    classifier: String,
}

impl Key {
    fn new(group: String, artifact: String, kind: Option<&str>, classifier: Option<&str>) -> Key {
        // Maven's default artifact handlers.
        let (extension, implied) = match kind.filter(|k| !k.is_empty()).unwrap_or("jar") {
            "jar" | "ejb" | "maven-plugin" => ("jar", ""),
            "test-jar" => ("jar", "tests"),
            "ejb-client" => ("jar", "client"),
            "java-source" => ("jar", "sources"),
            "javadoc" => ("jar", "javadoc"),
            other => (other, ""),
        };
        Key {
            group,
            artifact,
            extension: extension.to_string(),
            classifier: classifier
                .filter(|c| !c.is_empty())
                .unwrap_or(implied)
                .to_string(),
        }
    }

    fn is_main_jar(&self) -> bool {
        self.extension == "jar" && self.classifier.is_empty()
    }

    /// An archive that bundles its dependencies: Maven does not follow
    /// them.
    fn bundles_dependencies(&self) -> bool {
        matches!(self.extension.as_str(), "war" | "ear" | "rar")
    }
}

/// A declared version, or why it cannot be read.
#[derive(Debug, Clone)]
enum Ver {
    Known(String),
    Unknown(String),
}

/// One `<dependencyManagement>` entry of an effective model.
#[derive(Debug, Clone)]
struct Managed {
    version: Ver,
    scope: Option<String>,
    exclusions: Vec<Ga>,
}

/// The effective `<dependencyManagement>` of a pom: its parent chain's
/// entries, then its imported BOMs'.
#[derive(Debug, Default)]
struct Management {
    entries: HashMap<Key, Managed>,
    /// Why entries may be missing or different.
    incomplete: Option<String>,
    /// What a profile manages: its version depends on the active profiles.
    profile_keys: HashSet<Key>,
}

/// One effective `<dependency>` of a pom, its own management applied.
#[derive(Debug)]
struct Dep {
    key: Key,
    version: Ver,
    scope: String,
    optional: bool,
    exclusions: Vec<Ga>,
}

/// The effective `<dependencies>` of a pom.
#[derive(Debug, Default)]
struct Deps {
    deps: Vec<Dep>,
    /// Why the pom may declare dependencies that were not read.
    unknown: Option<String>,
    /// The same for declarations Maven follows only from the module that
    /// makes them (optional, `test` or `provided`).
    unknown_own: Option<String>,
}

/// A hard version requirement, as written.
#[derive(Debug)]
struct Range {
    raw: String,
    set: VersionRange,
}

/// One edge of a module's graph: a dependency of a node, resolved to a
/// version (one edge per version of a range).
#[derive(Debug, Clone)]
struct Edge {
    /// The declaration's place among its pom's dependencies, then the
    /// version's place in its range: the order Maven visits children in.
    slot: (u32, u32),
    key: u32,
    version: Ver,
    range: Option<Rc<Range>>,
    /// The exclusions in force below this dependency.
    exclusions: u32,
    /// A `system` dependency: a file on the machine, with no pom to follow.
    leaf: bool,
}

/// A node's dependencies.
#[derive(Debug, Default)]
struct Expanded {
    edges: Vec<Edge>,
    /// Why the node may bring in artifacts that were not read, and how far
    /// below it they start (0: the node itself may be another artifact).
    unknown: Option<(usize, String)>,
}

/// One surviving declaration of an artifact.
#[derive(Debug, Clone)]
struct Item {
    /// The slots from the module down to this declaration.
    path: Vec<(u32, u32)>,
    version: Ver,
    range: Option<Rc<Range>>,
    exclusions: u32,
    leaf: bool,
}

impl Item {
    fn below(path: &[(u32, u32)], edge: &Edge) -> Item {
        let mut path = path.to_vec();
        path.push(edge.slot);
        Item {
            path,
            version: edge.version.clone(),
            range: edge.range.clone(),
            exclusions: edge.exclusions,
            leaf: edge.leaf,
        }
    }
}

struct Selector<'w> {
    walk: Walk<'w>,
    /// `-D` user properties of `.mvn/maven.config`.
    user: BTreeMap<String, String>,
    /// The reactor's modules by their own coordinates.
    reactor: HashMap<Gav, Node>,
    management: HashMap<PathBuf, Rc<Management>>,
    managing: HashSet<PathBuf>,
    deps: HashMap<PathBuf, Rc<Deps>>,
    keys: Vec<Key>,
    key_ids: HashMap<Key, u32>,
    exclusion_sets: Vec<BTreeSet<Ga>>,
    exclusion_ids: HashMap<BTreeSet<Ga>, u32>,
    /// The versions each artifact's cached metadata lists for the module
    /// being read.
    listed: HashMap<Ga, Result<Option<Vec<String>>, String>>,
    /// The repositories the module being read resolves from, by id.
    repositories: BTreeSet<String>,
    /// The directories whose version lists were read.
    listings: BTreeSet<PathBuf>,
}

/// The selection, and the project files it was read from.
fn select(cwd: &Path, repo: &Path) -> (MavenSelection, Vec<PathBuf>) {
    let mut sources: Vec<PathBuf> = ["pom.xml", MAVEN_CONFIG, WRAPPER_PROPERTIES]
        .iter()
        .map(|rel| cwd.join(rel))
        .collect();
    let selection = select_from(cwd, repo, &mut sources);
    (selection, sources)
}

fn select_from(cwd: &Path, repo: &Path, sources: &mut Vec<PathBuf>) -> MavenSelection {
    let read = |rel: &str| {
        crate::utils::fs::read_regular_to_bytes_sync(&cwd.join(rel))
            .ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
    };
    // Maven 4 also applies the management of each dependency's own pom to
    // what that dependency brings in, which this model does not follow.
    let wrapper = read(WRAPPER_PROPERTIES).and_then(|props| {
        super::gradle_cache::wrapper_distribution_version(props.as_bytes(), "maven")
    });
    if wrapper.is_some_and(|(major, _, _)| major >= 4)
        || read("pom.xml").is_some_and(|pom| pom.contains("maven.apache.org/POM/4.1.0"))
    {
        return MavenSelection::unavailable(
            "the project builds with Maven 4, whose dependency management is not modelled",
        );
    }
    let mut selector = Selector {
        walk: Walk::new(cwd, repo),
        user: read(MAVEN_CONFIG)
            .map(|config| maven_config_properties(&config))
            .unwrap_or_default(),
        reactor: HashMap::new(),
        management: HashMap::new(),
        managing: HashSet::new(),
        deps: HashMap::new(),
        keys: Vec::new(),
        key_ids: HashMap::new(),
        exclusion_sets: Vec::new(),
        exclusion_ids: HashMap::new(),
        listed: HashMap::new(),
        repositories: BTreeSet::new(),
        listings: BTreeSet::new(),
    };
    let Some(chains) = selector.walk.reactor_poms() else {
        return MavenSelection::unavailable("the project's pom.xml could not be read");
    };
    for chain in &chains {
        sources.extend(chain.iter().filter(|n| n.local).map(|n| n.path.clone()));
        if let Some(gav) = selector.own_gav(chain) {
            selector.reactor.entry(gav).or_insert(chain[0].clone());
        }
    }
    let root = normalize(cwd);
    let mut modules = Vec::new();
    for chain in &chains {
        let rel = normalize(&chain[0].path)
            .zip(root.as_ref())
            .and_then(|(path, root)| {
                let rel = path.strip_prefix(root).ok()?;
                let parts: Option<Vec<&str>> =
                    rel.components().map(|c| c.as_os_str().to_str()).collect();
                Some(parts?.join("/"))
            });
        let Some(pom) = rel else { continue };
        let module = selector.module(pom, chain);
        if selector.walk.work.spent() {
            return MavenSelection::unavailable(
                "the project's poms interpolate more than their size allows",
            );
        }
        modules.push(module);
    }
    // Every pom looked at (cached or not) and every version list read: the
    // answer holds for as long as they are what they were.
    sources.extend(selector.walk.looked_at().cloned());
    sources.extend(selector.listings.iter().cloned());
    modules.sort_by(|a, b| a.pom.cmp(&b.pom));
    MavenSelection {
        modules,
        unavailable: None,
        incomplete: selector.walk.unread_modules.first().cloned(),
    }
}

impl Selector<'_> {
    fn key_id(&mut self, key: &Key) -> u32 {
        if let Some(id) = self.key_ids.get(key) {
            return *id;
        }
        let id = self.keys.len() as u32;
        self.keys.push(key.clone());
        self.key_ids.insert(key.clone(), id);
        id
    }

    fn exclusions_id(&mut self, set: BTreeSet<Ga>) -> u32 {
        if let Some(id) = self.exclusion_ids.get(&set) {
            return *id;
        }
        let id = self.exclusion_sets.len() as u32;
        self.exclusion_sets.push(set.clone());
        self.exclusion_ids.insert(set, id);
        id
    }

    /// `${name}` interpolation of `text` as `chain`'s head reads it, in
    /// Maven's order ([`lookup_property`]): a `project.*` reference, the
    /// command line's properties, the `<properties>` up the chain, then a
    /// deprecated bare model reference (`${version}`). Or why its value
    /// cannot be told: a name nothing defines, or one a profile on the
    /// chain redefines (its value then depends on which profiles are
    /// active).
    fn interpolate(&self, text: &str, chain: &Chain) -> Result<String, String> {
        if !text.contains("${") {
            return Ok(text.to_string());
        }
        let Some(head) = chain.first() else {
            return Err(format!("{text} is not defined"));
        };
        let own = &head.model;
        let parent_field = |i: usize| -> Option<String> {
            let (g, a, v, _) = own.parent.as_ref()?;
            [g, a, v][i].clone()
        };
        let model = |name: &str| -> Option<String> {
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
                _ => None,
            }
        };
        let moved = std::cell::RefCell::new(None::<String>);
        let no_user = BTreeMap::new();
        let lookup = |name: &str| -> Option<String> {
            if !self.walk.work.spend() {
                return None;
            }
            let layers = || {
                chain.iter().map(|n| PomLayer {
                    own: &n.model.props,
                    profiles: Vec::new(),
                })
            };
            let prefixed = name.starts_with("project.") || name.starts_with("pom.");
            if !(prefixed && model(name).is_some())
                && chain.iter().any(|n| n.model.profiles.props.contains(name))
            {
                moved.borrow_mut().get_or_insert(name.to_string());
            }
            // The command line's properties win in the project's own poms;
            // a dependency's pom reads them after its own.
            if head.local {
                lookup_property(name, &model, &self.user, layers())
            } else {
                lookup_property(name, &model, &no_user, layers())
                    .or_else(|| self.user.get(name).cloned())
            }
        };
        let value = interpolate_strict(text, &lookup);
        if let Some(name) = moved.into_inner() {
            return Err(format!("a profile redefines ${{{name}}}"));
        }
        value.ok_or_else(|| format!("{text} is not defined"))
    }

    fn version_of(&self, raw: Option<&str>, chain: &Chain) -> Option<Ver> {
        Some(match self.interpolate(raw?, chain) {
            Ok(version) => Ver::Known(version),
            Err(why) => Ver::Unknown(why),
        })
    }

    /// The coordinates the head of `chain` is published at.
    fn own_gav(&self, chain: &Chain) -> Option<Gav> {
        let own = &chain.first()?.model;
        let parent = own.parent.as_ref();
        let group = own.group.clone().or_else(|| parent?.0.clone())?;
        let version = own.version.clone().or_else(|| parent?.2.clone())?;
        Some((
            self.interpolate(&group, chain).ok()?,
            self.interpolate(own.artifact.as_deref()?, chain).ok()?,
            self.interpolate(&version, chain).ok()?,
        ))
    }

    /// The pom of `gav`: a module of the reactor, else the local
    /// repository's copy. A `<base>-socket.<hex8>` version no repository
    /// holds reads its base version's pom, which it is a copy of.
    fn pom_of(&mut self, gav: &Gav) -> Option<Node> {
        if let Some(node) = self.reactor.get(gav) {
            return Some(node.clone());
        }
        let found = self.walk.repo_pom(gav).and_then(|path| {
            let model = self.walk.model(&path, false)?;
            Some(Node {
                model,
                path,
                local: false,
            })
        });
        if found.is_some() {
            return found;
        }
        let (base, _) = split_socket_version(&gav.2)?;
        let base = (gav.0.clone(), gav.1.clone(), base.to_string());
        self.pom_of(&base)
    }

    /// Why `chain` is not the whole parent chain of its head.
    fn chain_gap(chain: &Chain) -> Option<String> {
        let last = chain.last()?;
        let (g, a, v, _) = last.model.parent.as_ref()?;
        let part = |p: &Option<String>| p.clone().unwrap_or_else(|| "?".to_string());
        Some(format!(
            "the parent pom {}:{}:{} is not in the local Maven repository",
            part(g),
            part(a),
            part(v)
        ))
    }

    fn key_of(
        &self,
        decl: &crate::vendor::jvm::maven_reactor::PomDecl,
        chain: &Chain,
    ) -> Result<Key, String> {
        let part = |text: &Option<String>| -> Result<Option<String>, String> {
            text.as_deref()
                .map(|t| self.interpolate(t, chain))
                .transpose()
        };
        Ok(Key::new(
            self.interpolate(&decl.group, chain)?,
            self.interpolate(&decl.artifact, chain)?,
            part(&decl.kind)?.as_deref(),
            part(&decl.classifier)?.as_deref(),
        ))
    }

    fn exclusions_of(
        &self,
        decl: &crate::vendor::jvm::maven_reactor::PomDecl,
        chain: &Chain,
    ) -> Vec<Ga> {
        let read = |text: &str| {
            self.interpolate(text, chain)
                .unwrap_or_else(|_| text.to_string())
        };
        decl.exclusions
            .iter()
            .map(|(g, a)| (read(g), read(a)))
            .collect()
    }

    /// The effective `<dependencyManagement>` of `chain`'s head.
    fn management(&mut self, chain: &Chain, depth: usize) -> Rc<Management> {
        let Some(head) = chain.first() else {
            return Rc::default();
        };
        let path = head.path.clone();
        if let Some(found) = self.management.get(&path) {
            return Rc::clone(found);
        }
        let mut out = Management {
            incomplete: Self::chain_gap(chain),
            ..Management::default()
        };
        // A BOM that imports itself, or imports nested too deep.
        if depth > MAX_IMPORT_DEPTH || !self.managing.insert(path.clone()) {
            out.incomplete = Some("its BOM imports nest too deep".to_string());
            return Rc::new(out);
        }
        let mut imports = Vec::new();
        for node in chain {
            for decl in node.model.own_managed() {
                // A pin vendoring wrote is not the project's management:
                // the question is what Maven selects without it.
                if decl.pinned {
                    continue;
                }
                if is_import(decl) {
                    imports.push(decl.clone());
                    continue;
                }
                match self.key_of(decl, chain) {
                    Ok(key) => {
                        let managed = Managed {
                            version: self
                                .version_of(decl.version.as_deref(), chain)
                                .unwrap_or_else(|| Ver::Unknown("it manages no version".into())),
                            scope: decl.scope.clone(),
                            exclusions: self.exclusions_of(decl, chain),
                        };
                        out.entries.entry(key).or_insert(managed);
                    }
                    Err(why) => out.incomplete = Some(why),
                }
            }
            for decl in &node.model.profiles.managed {
                if is_import(decl) {
                    out.incomplete = Some("a profile imports a BOM".to_string());
                    continue;
                }
                match self.key_of(decl, chain) {
                    Ok(key) => {
                        out.profile_keys.insert(key);
                    }
                    Err(why) => out.incomplete = Some(why),
                }
            }
        }
        for decl in imports {
            let gav = self
                .interpolate(&decl.group, chain)
                .and_then(|g| Ok((g, self.interpolate(&decl.artifact, chain)?)))
                .and_then(|(g, a)| {
                    let version = decl.version.as_deref().unwrap_or_default();
                    Ok((g, a, self.interpolate(version, chain)?))
                });
            let gav = match gav {
                Ok(gav) => gav,
                Err(why) => {
                    out.incomplete = Some(why);
                    continue;
                }
            };
            let Some(node) = self.pom_of(&gav) else {
                out.incomplete = Some(format!(
                    "the BOM {}:{}:{} is not in the local Maven repository",
                    gav.0, gav.1, gav.2
                ));
                continue;
            };
            let bom = self.walk.chain(node);
            let imported = self.management(&bom, depth + 1);
            for (key, managed) in &imported.entries {
                out.entries
                    .entry(key.clone())
                    .or_insert_with(|| managed.clone());
            }
            out.profile_keys
                .extend(imported.profile_keys.iter().cloned());
            if out.incomplete.is_none() {
                out.incomplete = imported.incomplete.clone();
            }
        }
        self.managing.remove(&path);
        let out = Rc::new(out);
        self.management.insert(path, Rc::clone(&out));
        out
    }

    /// The effective `<dependencies>` of `chain`'s head: its own first,
    /// then each parent's that it does not redeclare, with the versions,
    /// scopes and exclusions its own management supplies.
    fn dependencies(&mut self, chain: &Chain) -> Rc<Deps> {
        let Some(head) = chain.first() else {
            return Rc::default();
        };
        let path = head.path.clone();
        if let Some(found) = self.deps.get(&path) {
            return Rc::clone(found);
        }
        let management = self.management(chain, 0);
        let mut out = Deps {
            deps: Vec::new(),
            unknown: Self::chain_gap(chain),
            unknown_own: None,
        };
        let mut seen = HashSet::new();
        for node in chain {
            if node.model.profiles.deps {
                out.unknown = Some(format!(
                    "a profile of {} declares dependencies",
                    describe(node)
                ));
            }
            // Where this pom's own declarations stand: Maven reads a pom
            // that declares one dependency twice as its last declaration,
            // in the place of the first.
            let mut own: HashMap<Key, usize> = HashMap::new();
            for decl in node.model.own_deps() {
                let key = match self.key_of(decl, chain) {
                    Ok(key) => key,
                    Err(why) => {
                        let own_only = decl.optional
                            || matches!(decl.scope.as_deref(), Some("test" | "provided"));
                        match own_only {
                            true => out.unknown_own = Some(why),
                            false => out.unknown = Some(why),
                        }
                        continue;
                    }
                };
                if seen.contains(&key) {
                    continue;
                }
                let managed = management.entries.get(&key);
                let by_profile = management.profile_keys.contains(&key);
                let version = self
                    .version_of(decl.version.as_deref(), chain)
                    .unwrap_or_else(|| match managed {
                        _ if by_profile => Ver::Unknown("a profile manages its version".into()),
                        Some(managed) => managed.version.clone(),
                        None => Ver::Unknown(
                            management
                                .incomplete
                                .clone()
                                .unwrap_or_else(|| "it declares no version".to_string()),
                        ),
                    });
                let scope = decl
                    .scope
                    .clone()
                    .or_else(|| managed.and_then(|m| m.scope.clone()))
                    .map(|s| self.interpolate(&s, chain).unwrap_or(s))
                    .unwrap_or_else(|| "compile".to_string());
                let mut exclusions = self.exclusions_of(decl, chain);
                if exclusions.is_empty() {
                    exclusions = managed.map(|m| m.exclusions.clone()).unwrap_or_default();
                }
                let dep = Dep {
                    key: key.clone(),
                    version,
                    scope,
                    optional: decl.optional,
                    exclusions,
                };
                match own.get(&key) {
                    Some(&at) => out.deps[at] = dep,
                    None => {
                        own.insert(key, out.deps.len());
                        out.deps.push(dep);
                    }
                }
            }
            seen.extend(own.into_keys());
        }
        let out = Rc::new(out);
        self.deps.insert(path, Rc::clone(&out));
        out
    }

    /// The versions Maven lists for `ga` when it resolves a range in the
    /// module being read: those of the `maven-metadata-<id>.xml` files the
    /// local repository caches for the repositories the module's poms
    /// declare (and Maven's own `central` and `local`), and the reactor's
    /// own. `Ok(None)` when none is cached; `Err` when a file is cached
    /// for a repository the module does not declare (another project's,
    /// or a mirror from the user settings, which are not read): Maven may
    /// or may not consult it, so the list cannot be told.
    fn listed_versions(&mut self, ga: &Ga) -> Result<Option<Vec<String>>, String> {
        if let Some(found) = self.listed.get(ga) {
            return found.clone();
        }
        let safe =
            |s: &str| !s.is_empty() && !s.contains(['/', '\\', '$', '{', '}']) && !s.contains("..");
        let mut versions: Option<Vec<String>> = None;
        let mut foreign: Vec<String> = Vec::new();
        if safe(&ga.0) && safe(&ga.1) {
            let dir = self.walk.repo.join(ga.0.replace('.', "/")).join(&ga.1);
            self.listings.insert(dir.clone());
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Some(id) = name
                    .strip_prefix("maven-metadata")
                    .and_then(|rest| rest.strip_suffix(".xml"))
                else {
                    continue;
                };
                let id = id.strip_prefix('-').unwrap_or(id);
                if !self.repositories.contains(id) {
                    foreign.push(id.to_string());
                    continue;
                }
                let Ok(bytes) = crate::utils::fs::read_regular_to_bytes_sync(&entry.path()) else {
                    continue;
                };
                versions
                    .get_or_insert_with(Vec::new)
                    .extend(metadata_versions(&String::from_utf8_lossy(&bytes)));
            }
        }
        let listed = if foreign.is_empty() {
            if let Some(versions) = versions.as_mut() {
                versions.extend(
                    self.reactor
                        .keys()
                        .filter(|(g, a, _)| *g == ga.0 && *a == ga.1)
                        .map(|(_, _, v)| v.clone()),
                );
                versions.sort_by_key(|v| MavenVersion::parse(v));
                versions.dedup();
            }
            Ok(versions)
        } else {
            foreign.sort();
            Err(format!(
                "versions of {}:{} are cached for repositories this build does not declare ({})",
                ga.0,
                ga.1,
                foreign.join(", ")
            ))
        };
        self.listed.insert(ga.clone(), listed.clone());
        listed
    }

    /// The edges a declaration of `key` at `version` makes: one, or one
    /// per version of a range.
    fn edges(&mut self, slot: u32, dep: &Dep, version: Ver, exclusions: u32) -> Vec<Edge> {
        let key = &dep.key;
        let id = self.key_id(key);
        let leaf = dep.scope == "system";
        let edge = |at: u32, version: Ver, range: Option<Rc<Range>>| Edge {
            slot: (slot, at),
            key: id,
            version,
            range,
            exclusions,
            leaf,
        };
        let raw = match version {
            Ver::Unknown(why) => return vec![edge(0, Ver::Unknown(why), None)],
            Ver::Known(raw) => raw,
        };
        if matches!(raw.as_str(), "LATEST" | "RELEASE") {
            let why = format!("{}:{} is declared at {raw}", key.group, key.artifact);
            return vec![edge(0, Ver::Unknown(why), None)];
        }
        let Some(set) = VersionRange::parse(&raw) else {
            if raw.starts_with(['[', '(']) || raw.contains(',') {
                let why = format!("the version range {raw} cannot be read");
                return vec![edge(0, Ver::Unknown(why), None)];
            }
            return vec![edge(0, Ver::Known(raw), None)];
        };
        if let Some(exact) = set.exact() {
            let exact = exact.to_string();
            let range = Rc::new(Range { raw, set });
            return vec![edge(0, Ver::Known(exact), Some(range))];
        }
        let ga = (key.group.clone(), key.artifact.clone());
        let listed = match self.listed_versions(&ga) {
            Ok(Some(listed)) => listed,
            Ok(None) => {
                let why = format!(
                    "{}:{} is declared as the range {raw} and the local Maven repository lists \
                     no versions of it",
                    ga.0, ga.1
                );
                return vec![edge(0, Ver::Unknown(why), None)];
            }
            Err(why) => {
                let why = format!("{why}, so the range {raw} cannot be resolved");
                return vec![edge(0, Ver::Unknown(why), None)];
            }
        };
        let range = Rc::new(Range { raw, set });
        let within: Vec<String> = listed
            .into_iter()
            .filter(|v| range.set.contains(v))
            .collect();
        if within.is_empty() {
            let why = format!(
                "no version of {}:{} the local Maven repository lists is in the range {}",
                ga.0, ga.1, range.raw
            );
            return vec![edge(0, Ver::Unknown(why), None)];
        }
        within
            .into_iter()
            .enumerate()
            .map(|(at, v)| edge(at as u32, Ver::Known(v), Some(Rc::clone(&range))))
            .collect()
    }

    /// The dependencies of the module itself: every scope, optional ones
    /// too, each with the exclusions it declares.
    fn direct(&mut self, chain: &Chain, root: &Management) -> Expanded {
        let deps = self.dependencies(chain);
        let mut out = Expanded {
            edges: Vec::new(),
            unknown: deps
                .unknown
                .clone()
                .or_else(|| deps.unknown_own.clone())
                .or_else(|| root.incomplete.clone())
                .map(|why| (1, why)),
        };
        for (slot, dep) in deps.deps.iter().enumerate() {
            let mut exclusions: BTreeSet<Ga> = dep.exclusions.iter().cloned().collect();
            if let Some(managed) = root.entries.get(&dep.key) {
                exclusions.extend(managed.exclusions.iter().cloned());
            }
            let exclusions = self.exclusions_id(exclusions);
            out.edges
                .extend(self.edges(slot as u32, dep, dep.version.clone(), exclusions));
        }
        out
    }

    /// The dependencies of `key` at `version` that Maven follows below a
    /// module managing `root`, with `exclusions` in force.
    fn expand(&mut self, key: u32, version: &str, exclusions: u32, root: &Management) -> Expanded {
        let key = self.keys[key as usize].clone();
        if key.bundles_dependencies() {
            return Expanded::default();
        }
        let gav = (key.group.clone(), key.artifact.clone(), version.to_string());
        let Some(node) = self.pom_of(&gav) else {
            return Expanded {
                edges: Vec::new(),
                unknown: Some((
                    1,
                    format!(
                        "the pom of {}:{}:{version} is not in the local Maven repository",
                        key.group, key.artifact
                    ),
                )),
            };
        };
        // Maven builds the artifact the stub names in its place.
        if node.model.relocation.is_some() {
            return Expanded {
                edges: Vec::new(),
                unknown: Some((
                    0,
                    format!(
                        "{}:{}:{version} is relocated to other coordinates",
                        key.group, key.artifact
                    ),
                )),
            };
        }
        let chain = self.walk.chain(node);
        let deps = self.dependencies(&chain);
        let in_force = self.exclusion_sets[exclusions as usize].clone();
        let excluded = |dep: &Dep| {
            in_force.iter().any(|(g, a)| {
                (g == "*" || *g == dep.key.group) && (a == "*" || *a == dep.key.artifact)
            })
        };
        let mut out = Expanded {
            edges: Vec::new(),
            unknown: deps.unknown.clone().map(|why| (1, why)),
        };
        for (slot, dep) in deps.deps.iter().enumerate() {
            if matches!(dep.scope.as_str(), "test" | "provided") || dep.optional || excluded(dep) {
                continue;
            }
            let managed = root.entries.get(&dep.key);
            let version = if root.profile_keys.contains(&dep.key) {
                Ver::Unknown("a profile manages its version".to_string())
            } else {
                managed.map_or_else(|| dep.version.clone(), |m| m.version.clone())
            };
            let mut below = in_force.clone();
            below.extend(dep.exclusions.iter().cloned());
            if let Some(managed) = managed {
                below.extend(managed.exclusions.iter().cloned());
            }
            let below = self.exclusions_id(below);
            out.edges
                .extend(self.edges(slot as u32, dep, version, below));
        }
        out
    }

    /// What Maven selects in the module whose pom heads `chain`.
    fn module(&mut self, pom: String, chain: &Chain) -> Module {
        // Maven's own repositories, then the ones the module's poms name.
        self.repositories = ["central", "local"]
            .into_iter()
            .map(str::to_string)
            .chain(chain.iter().flat_map(|n| n.model.repositories.clone()))
            .collect();
        self.listed.clear();
        let root = self.management(chain, 0);
        let direct = self.direct(chain, &root);
        let mut module = Module {
            pom,
            picks: HashMap::new(),
            unknown: direct.unknown.clone(),
        };

        // Every distinct node, for the order artifacts are settled in: an
        // artifact after every artifact that may depend on it.
        let mut graph = Graph::default();
        for edge in &direct.edges {
            graph.reach(edge, None);
        }
        while let Some(node) = graph.queue.pop_front() {
            if graph.expanded.len() >= MAX_GRAPH || self.walk.work.spent() {
                module.unknown = Some((1, "its dependency graph is too large to read".into()));
                return module;
            }
            let children = Rc::new(self.expand(node.0, &node.1, node.2, &root));
            for edge in &children.edges {
                graph.reach(edge, Some(node.0));
            }
            graph.expanded.insert(node, children);
        }

        let mut pending: HashMap<u32, Vec<Item>> = HashMap::new();
        for edge in &direct.edges {
            pending
                .entry(edge.key)
                .or_default()
                .push(Item::below(&[], edge));
        }
        let (sorted, mut held) = graph.parents_first();
        for key in sorted {
            self.settle(key, None, &graph, &root, &mut pending, &mut module);
        }
        // What a cycle holds back has no parents-first order: settled as
        // its declarations turn up, and in doubt.
        while let Some(at) = held.iter().position(|key| pending.contains_key(key)) {
            let key = held.remove(at);
            let named = &self.keys[key as usize];
            let why = format!(
                "{}:{} is part of a dependency cycle",
                named.group, named.artifact
            );
            self.settle(key, Some(why), &graph, &root, &mut pending, &mut module);
        }
        for key in held {
            let key = &self.keys[key as usize];
            if key.is_main_jar() {
                module.picks.insert(
                    (key.group.clone(), key.artifact.clone()),
                    Pick {
                        version: None,
                        depth: 1,
                        doubt: Some(format!(
                            "{}:{} is part of a dependency cycle",
                            key.group, key.artifact
                        )),
                        ranged: false,
                    },
                );
            }
        }
        module
    }

    /// Choose among the surviving declarations of `key` and put what the
    /// winner depends on in line; `doubt` is why the choice is not certain
    /// already.
    fn settle(
        &mut self,
        key: u32,
        mut doubt: Option<String>,
        graph: &Graph,
        root: &Management,
        pending: &mut HashMap<u32, Vec<Item>>,
        module: &mut Module,
    ) {
        let mut items = pending.remove(&key).unwrap_or_default();
        if items.is_empty() {
            return;
        }
        items.sort_by(|a, b| a.path.cmp(&b.path));
        let note = |module: &mut Module, depth: usize, why: &str| {
            if module.unknown.as_ref().is_none_or(|(at, _)| depth < *at) {
                module.unknown = Some((depth, why.to_string()));
            }
        };
        // A declaration at a version that cannot be read may be the one
        // Maven selects, and brings in whatever that version depends on.
        let mut unread: Option<(usize, String)> = None;
        for item in &items {
            if let Ver::Unknown(why) = &item.version {
                note(module, item.path.len() + 1, why);
                if unread.as_ref().is_none_or(|(at, _)| item.path.len() < *at) {
                    unread = Some((item.path.len(), why.clone()));
                }
            }
        }
        let readable: Vec<(&Item, &str)> = items
            .iter()
            .filter_map(|item| match &item.version {
                Ver::Known(version) => Some((item, version.as_str())),
                Ver::Unknown(_) => None,
            })
            .collect();
        let pick = match nearest(&readable) {
            Ok(Some(at)) => {
                let (item, version) = readable[at];
                let depth = item.path.len();
                if let Some((unread_depth, why)) = &unread {
                    if *unread_depth <= depth {
                        doubt.get_or_insert_with(|| why.clone());
                    }
                }
                let node = (key, version.to_string(), item.exclusions);
                let below = match graph.expanded.get(&node) {
                    _ if item.leaf => Rc::default(),
                    Some(found) => Rc::clone(found),
                    None => Rc::new(self.expand(key, version, item.exclusions, root)),
                };
                if let Some((offset, why)) = &below.unknown {
                    note(module, depth + offset, why);
                }
                for edge in &below.edges {
                    pending
                        .entry(edge.key)
                        .or_default()
                        .push(Item::below(&item.path, edge));
                }
                Pick {
                    version: Some(version.to_string()),
                    depth,
                    doubt,
                    ranged: item.range.as_ref().is_some_and(|r| r.set.exact().is_none()),
                }
            }
            Ok(None) => {
                let (depth, why) = unread.unwrap_or((1, "its version cannot be read".into()));
                Pick {
                    version: None,
                    depth,
                    doubt: Some(why),
                    ranged: false,
                }
            }
            Err(()) => Pick {
                version: None,
                depth: 1,
                doubt: Some("its version ranges admit no common version".to_string()),
                ranged: false,
            },
        };
        let key = &self.keys[key as usize];
        if key.is_main_jar() {
            module
                .picks
                .insert((key.group.clone(), key.artifact.clone()), pick);
        }
    }
}

/// One node of a module's graph: an artifact at a version, with the
/// exclusions in force below it.
type GraphNode = (u32, String, u32);

/// Every distinct node a module's declarations reach, before mediation.
#[derive(Default)]
struct Graph {
    expanded: HashMap<GraphNode, Rc<Expanded>>,
    seen: HashSet<GraphNode>,
    queue: VecDeque<GraphNode>,
    /// The artifacts, in the order they were first reached.
    order: Vec<u32>,
    known: HashSet<u32>,
    /// `(a, b)`: some version of `a` depends on `b`.
    below: BTreeSet<(u32, u32)>,
}

impl Graph {
    fn reach(&mut self, edge: &Edge, from: Option<u32>) {
        if self.known.insert(edge.key) {
            self.order.push(edge.key);
        }
        if let Some(from) = from {
            self.below.insert((from, edge.key));
        }
        if let (Ver::Known(version), false) = (&edge.version, edge.leaf) {
            let node = (edge.key, version.clone(), edge.exclusions);
            if self.seen.insert(node.clone()) {
                self.queue.push_back(node);
            }
        }
    }

    /// The artifacts ordered so that each comes after every artifact that
    /// may depend on it, and those a dependency cycle keeps from any such
    /// order (the cycle's own and everything below it).
    fn parents_first(&self) -> (Vec<u32>, Vec<u32>) {
        let mut waiting: HashMap<u32, usize> = self.order.iter().map(|k| (*k, 0)).collect();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (from, to) in &self.below {
            *waiting.entry(*to).or_default() += 1;
            children.entry(*from).or_default().push(*to);
        }
        let mut ready: VecDeque<u32> = self
            .order
            .iter()
            .copied()
            .filter(|k| waiting[k] == 0)
            .collect();
        let mut sorted = Vec::new();
        while let Some(key) = ready.pop_front() {
            sorted.push(key);
            for to in children.get(&key).into_iter().flatten() {
                let left = waiting.get_mut(to).expect("counted above");
                *left -= 1;
                if *left == 0 {
                    ready.push_back(*to);
                }
            }
        }
        let settled: HashSet<u32> = sorted.iter().copied().collect();
        let held = self
            .order
            .iter()
            .copied()
            .filter(|k| !settled.contains(k))
            .collect();
        (sorted, held)
    }
}

/// Maven's nearest-wins choice among the declarations of one artifact, in
/// the order it visits them: the nearest wins, the first on a tie, the
/// highest among the versions of one range. A range is a hard requirement:
/// once a winner falls outside one, the nearest declaration every range
/// admits takes over. `Ok(None)` for no declaration, `Err` when the ranges
/// admit none (Maven fails the build).
fn nearest(items: &[(&Item, &str)]) -> Result<Option<usize>, ()> {
    let parsed: Vec<MavenVersion> = items.iter().map(|(_, v)| MavenVersion::parse(v)).collect();
    let nearer = |a: usize, b: usize| {
        let (pa, pb) = (&items[a].0.path, &items[b].0.path);
        if pa.len() == pb.len() && pa[..pa.len() - 1] == pb[..pb.len() - 1] {
            parsed[a] > parsed[b]
        } else {
            pa.len() < pb.len()
        }
    };
    let mut ranges: Vec<&Rc<Range>> = Vec::new();
    let mut candidates: Vec<usize> = Vec::new();
    let mut winner: Option<usize> = None;
    for (at, (item, version)) in items.iter().enumerate() {
        let mut backtrack = false;
        if let Some(range) = &item.range {
            if !ranges.iter().any(|r| r.raw == range.raw) {
                ranges.push(range);
                backtrack = winner.is_some_and(|w| !range.set.contains(items[w].1));
            }
        }
        let acceptable = ranges.iter().all(|r| r.set.contains(version));
        if acceptable {
            candidates.push(at);
        }
        if backtrack {
            winner = None;
            candidates.retain(|c| ranges.iter().all(|r| r.set.contains(items[*c].1)));
            for &candidate in &candidates {
                if winner.is_none_or(|w| nearer(candidate, w)) {
                    winner = Some(candidate);
                }
            }
            if winner.is_none() {
                return Err(());
            }
        } else if acceptable && winner.is_none_or(|w| nearer(at, w)) {
            winner = Some(at);
        }
    }
    Ok(winner)
}

/// The `<version>` entries of a `maven-metadata*.xml`.
fn metadata_versions(text: &str) -> Vec<String> {
    let Some(start) = text.find("<versions>") else {
        return Vec::new();
    };
    let end = text[start..]
        .find("</versions>")
        .map_or(text.len(), |n| start + n);
    let mut out = Vec::new();
    let mut rest = &text[start..end];
    while let Some(at) = rest.find("<version>") {
        rest = &rest[at + "<version>".len()..];
        let Some(close) = rest.find("</version>") else {
            break;
        };
        let version = rest[..close].trim();
        if !version.is_empty() {
            out.push(version.to_string());
        }
        rest = &rest[close..];
    }
    out
}

/// A pom as a message names it.
fn describe(node: &Node) -> String {
    match (&node.model.artifact, node.local) {
        (_, true) => node
            .path
            .file_name()
            .map(|_| node.path.display().to_string())
            .unwrap_or_default(),
        (Some(artifact), false) => artifact.clone(),
        (None, false) => node.path.display().to_string(),
    }
}

#[cfg(test)]
mod tests;
