//! Hosted mode over a Maven reactor: which poms are edited and how, and how
//! the edits are read back and undone from the poms alone.
//!
//! Hosted mode keeps no ledger, so every edit made here says what it
//! replaced by its own text:
//!
//! - a declaration that names the base version literally is rewritten to
//!   `<base>-socket.<hex8>`; the base is the suffix's prefix;
//! - a `<dependencyManagement>` pin is the entry vendored mode writes, with
//!   its `<!-- socket-patch <uuid>: g:a:v -->` comment, in the poms
//!   [`place_pins`] picks (where every module at or below selects the base
//!   version already, or does not resolve the artifact). A later scan
//!   keeps every pin where it is, and adds one only for a module nothing
//!   reaches yet that is certain to select the base version;
//! - a declaration whose version is one `${property}` the reactor's own
//!   poms define, with nothing else reading that property, has the
//!   property's value rewritten instead: the declaration keeps its text;
//! - any other `${...}` version is replaced by the literal suffixed
//!   version, and the text it replaced is recorded in a comment right
//!   after the element ([`ORIGINAL_TAG`]);
//! - the `<repository>` that serves the suffixed version is declared in
//!   the local root of every pom that names it, through the hosted
//!   rewriter's own edits ([`HostedRepository`]).
//!
//! # The invariant
//!
//! A plan is whole or it is nothing ([`HostedReactor::plan`]). Once it is
//! written:
//!
//! - no pom names the suffixed version unless the repository that serves
//!   it is declared in that pom's local root, and a declaration Maven
//!   always reads resolves to it, so discovery ([`HostedReactor::sites`])
//!   finds the patch and every pom that carries part of it;
//! - a rollback returns every pom the plan first wired to the bytes it had
//!   ([`HostedRepository::restored`], the restore itself, run over the
//!   planned text before anything is written);
//! - when the plan leaves no pom naming the suffixed version (a pin that
//!   came to move a module was taken out), the repository goes with it,
//!   and the caller drops its checksum lines ([`HostedPlan::unnamed`]); an
//!   earlier patch's repository and checksum lines go only once no pom of
//!   the reactor names that patch's suffix any more
//!   ([`HostedPlan::superseded`]).
//!
//! A plan that cannot keep these is refused ([`HostedPlan::refused`]) and
//! the reactor stays as it was read.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use super::{
    apply_edits, coords_patch, degraded, forget_other_versions, is_base_like, line_span, pin_edit,
    pin_moves, pin_of, pin_update, place_pins, safe_coordinates, unattestable_in,
    undetermined_note, unwired_in, Doc, Edit, Pin, Placing, Pom, Reactor, Role,
};
use crate::crawlers::maven_selection::{MavenSelection, Standing, Verdict};
use crate::formats::maven::split_socket_version;
use crate::vendor::jvm::{Coords, JvmRefusal, ListFn, ReadFn};

/// The start of the comment that records what a declaration's `<version>`
/// read before hosted mode replaced it with a literal suffixed version:
/// `<version>1.2-socket.0a1b2c3d</version><!-- socket-patch:version ${x} -->`.
pub const ORIGINAL_TAG: &str = "<!-- socket-patch:version ";
const COMMENT_CLOSE: &str = " -->";

/// What one edit of a [`HostedPlan`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedEditKind {
    /// A declaration's `<version>` now reads the suffixed version.
    Version,
    /// A property's value now is the suffixed version.
    Property,
    /// A `<dependencyManagement>` pin was added.
    Pin,
    /// The pin of an earlier patch of this version moved to this patch.
    PinMoved,
    /// A pin that would move a module to another version was taken out.
    PinRemoved,
    /// The patch's `<repository>` was declared.
    Repository,
    /// The patch's `<repository>` took its current URL.
    RepositoryUrl,
    /// A `<repository>` nothing names any more was taken out: the patch's
    /// own, or an earlier patch's.
    RepositoryRemoved,
}

/// One edit of a [`HostedPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedEdit {
    /// The pom edited.
    pub rel: String,
    pub kind: HostedEditKind,
    /// The text replaced: a version, a property's value (`None` for a pin
    /// or a repository, and for a version an earlier patch had suffixed).
    pub original: Option<String>,
    /// The property a [`HostedEditKind::Property`] edit rewrote.
    pub property: Option<String>,
    /// The patch uuid whose repository a repository edit concerns.
    pub repository: Option<String>,
}

impl HostedEdit {
    fn of(rel: &str, kind: HostedEditKind) -> HostedEdit {
        HostedEdit {
            rel: rel.to_string(),
            kind,
            original: None,
            property: None,
            repository: None,
        }
    }
}

/// A pom with the patch's repository declared.
pub enum RepositoryEdit {
    /// The repository was added.
    Added(String),
    /// It was there, pointing elsewhere (a rotated grant).
    Refreshed(String),
}

/// The hosted rewriter's own edits of a pom's `<repositories>`, and its
/// restore: the planner decides where the repository goes, and holds
/// every pom it plans to what a rollback makes of it.
pub struct HostedRepository<'a> {
    /// `pom` with the patch's repository declared; `Ok(None)` when it is
    /// there as it should be, `Err` when it cannot be declared in it.
    pub ensure: &'a dyn Fn(&str) -> Result<Option<RepositoryEdit>, String>,
    /// `pom` without the hosted repository of the patch `uuid`; `None`
    /// when it declares none that can be taken out.
    pub remove: &'a dyn Fn(&str, &str) -> Option<String>,
    /// The patch uuids whose hosted repository `pom` declares.
    pub declared: &'a dyn Fn(&str) -> Vec<String>,
    /// The pom at the first path, holding the second as its text, as a
    /// rollback of the patch leaves it.
    pub restored: &'a dyn Fn(&str, &str) -> Result<String, String>,
}

/// What hosted mode does to a reactor's poms for one patch.
#[derive(Debug, Default)]
pub struct HostedPlan {
    /// The poms that change, with their new text: all of them are written,
    /// or (a refused plan holds none) nothing is.
    pub poms: BTreeMap<String, String>,
    pub edits: Vec<HostedEdit>,
    /// Why a declaration or a pom was left as it is: the vendored
    /// planner's reason word, and the line.
    pub notes: Vec<(String, String)>,
    /// Whether the poms wire the patch once the plan is written (or did
    /// before): a declaration Maven always reads resolves to the suffixed
    /// version, and its repository is declared.
    pub wired: bool,
    /// The patch's suffixed version was named before the plan and no pom
    /// names it after: its repository was taken out, and its checksum
    /// lines are the caller's to drop.
    pub unnamed: bool,
    /// The suffixed versions of earlier patches of this version that no
    /// pom of the reactor names any more: their checksum lines go.
    pub superseded: Vec<String>,
    /// The module directories with a `.mvn` of their own.
    pub nested_mvn: Vec<String>,
    /// No module selects the base version, and every answer is certain:
    /// the versions selected instead. Nothing is planned then.
    pub not_selected: Option<Vec<String>>,
    /// Why nothing was planned: the plan could not be written whole
    /// without breaking the invariant (the module docs).
    pub refused: Option<(String, String)>,
}

/// One artifact some pom of a reactor builds at a Socket suffixed version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedSite {
    pub group: String,
    pub artifact: String,
    /// `<base>-socket.<hex8>`.
    pub suffixed: String,
    /// The patch uuid a pin's comment names, when a pin carries it.
    pub uuid: Option<String>,
    /// Every pom that names the suffixed version outside comments: a
    /// declaration, a pin, or a property a declaration reads.
    pub rels: BTreeSet<String>,
}

/// A reactor read once for hosted mode (a single pom is a reactor of
/// one, with the parent poms it inherits from inside the checkout): the
/// rewriter plans every patch of a run over it, and discovery reads every
/// pin from it, each pom parsed once. A plan rewrites it in place, so the
/// next patch is planned over what the last one wrote.
pub struct HostedReactor {
    reactor: Reactor,
}

/// Why a plan is refused: the reason word, and the line.
type Refused = (String, String);

fn refused(reason: &str, detail: impl Into<String>) -> Refused {
    (reason.to_string(), detail.into())
}

impl HostedReactor {
    /// Read the reactor rooted at `pom.xml`. Unlike vendored mode, a
    /// module with a `.mvn` of its own is no refusal.
    pub fn read(read: ReadFn<'_>, list: ListFn<'_>) -> Result<HostedReactor, JvmRefusal> {
        Reactor::discover_for(read, list, true).map(|reactor| HostedReactor { reactor })
    }

    /// [`Self::read`] for finding the wiring a reactor carries, never for
    /// planning over it: a module or a parent pom that cannot be found or
    /// parsed is left out, and named in the second value. A reactor
    /// discovery could not read whole still shows the pins of the poms it
    /// could, so they can be listed and rolled back.
    pub fn read_what_is_there(
        read: ReadFn<'_>,
        list: ListFn<'_>,
    ) -> Result<(HostedReactor, Vec<String>), JvmRefusal> {
        let mut unread = Vec::new();
        let reactor = Reactor::discover_with(read, list, true, Some(&mut unread))?;
        Ok((HostedReactor { reactor }, unread))
    }

    /// Every pom read: the reactor's modules, and each parent pom one
    /// inherits from inside the checkout.
    pub fn scope(&self) -> &[String] {
        &self.reactor.scope
    }

    /// The reactor's modules, the root first.
    pub fn modules(&self) -> &[String] {
        &self.reactor.reactor
    }

    /// The text of the pom at `rel` as it reads now.
    pub fn text(&self, rel: &str) -> Option<&str> {
        self.reactor.poms.get(rel).map(|pom| pom.doc.text.as_str())
    }

    /// Take `text` for the pom at `rel` (a pom of the scope): what another
    /// rewriter made of it since it was read.
    pub fn set_text(&mut self, rel: &str, text: &str) -> Result<(), JvmRefusal> {
        let pom = Pom::parse(rel, text.as_bytes().to_vec())?;
        self.reactor.poms.insert(rel.to_string(), pom);
        Ok(())
    }

    /// The artifacts the poms build at a Socket suffixed version, read as
    /// Maven reads them (a `${...}` through the properties of the
    /// declaring pom's chain), with the poms that name each. Declarations
    /// inside `<profiles>` are not read: Maven reads those only while
    /// their profile is active.
    pub fn sites(&self) -> Vec<HostedSite> {
        let reactor = &self.reactor;
        let mut sites: BTreeMap<(String, String, String), Option<String>> = BTreeMap::new();
        for rel in &reactor.scope {
            let doc = &reactor.poms[rel].doc;
            let resolve = |v: &str| reactor.interpolate(rel, v);
            for dep in doc.declarations() {
                if doc.section_of(dep).starts_with("profile:") || !doc.is_main_jar(dep) {
                    continue;
                }
                let (Some(group), Some(artifact), Some(version)) = (
                    doc.coordinate(dep, "groupId", &resolve),
                    doc.coordinate(dep, "artifactId", &resolve),
                    doc.coordinate(dep, "version", &resolve),
                ) else {
                    continue;
                };
                if split_socket_version(&version).is_none() {
                    continue;
                }
                let uuid = doc.pin_at(dep).map(|pin| pin.uuid);
                let tagged = sites.entry((group, artifact, version)).or_default();
                if tagged.is_none() {
                    *tagged = uuid;
                }
            }
        }
        sites
            .into_iter()
            .map(|((group, artifact, suffixed), uuid)| HostedSite {
                rels: self.naming(&suffixed).into_iter().collect(),
                group,
                artifact,
                suffixed,
                uuid,
            })
            .collect()
    }

    /// Why `vex` must not attest the hosted patch `c` although the poms
    /// wire it, as vendored mode weighs its own wiring: a declaration that
    /// may still build the base version ([`unattestable_in`]), or a module
    /// that resolves it (or may, by `selection`) and no pin or declaration
    /// reaches ([`unwired_in`]). `None` when nothing does.
    pub fn unattestable(&self, c: &Coords<'_>, selection: &MavenSelection) -> Option<String> {
        unattestable_in(&self.reactor, c).or_else(|| unwired_in(&self.reactor, c, selection))
    }

    /// The poms that name `version` outside comments.
    fn naming(&self, version: &str) -> Vec<String> {
        let reactor = &self.reactor;
        reactor
            .scope
            .iter()
            .filter(|rel| reactor.poms[*rel].doc.masked.contains(version))
            .cloned()
            .collect()
    }

    /// Every `<base>-socket.<hex8>` the poms name outside comments.
    fn generations(&self, base: &str) -> BTreeSet<String> {
        let prefix = format!("{base}-socket.");
        let mut found = BTreeSet::new();
        for rel in &self.reactor.scope {
            let masked = &self.reactor.poms[rel].doc.masked;
            for (at, _) in masked.match_indices(&prefix) {
                let hex8 = masked.get(at + prefix.len()..at + prefix.len() + 8);
                if let Some(hex8) = hex8.filter(|h| {
                    h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                }) {
                    found.insert(format!("{prefix}{hex8}"));
                }
            }
        }
        found
    }

    /// Take `text` for `rel`, keeping what it held when the plan began.
    fn replace(
        &mut self,
        rel: &str,
        text: String,
        before: &mut BTreeMap<String, String>,
    ) -> Result<(), Refused> {
        let pom = Pom::parse(rel, text.into_bytes()).map_err(|refusal| {
            refused(
                "edit_not_reversible",
                format!("{rel} would no longer read as a pom ({})", refusal.detail),
            )
        })?;
        if let Some(was) = self.reactor.poms.insert(rel.to_string(), pom) {
            before.entry(rel.to_string()).or_insert(was.doc.text);
        }
        Ok(())
    }

    /// Plan the hosted wiring of the patch `c`, whole or not at all (the
    /// module docs), and take it: the reactor then reads as the plan
    /// leaves it. `selection` is what Maven selects in each module; `None`
    /// reads as "cannot be told", which rewrites the declarations that
    /// name the base version and pins nothing. A refused plan
    /// ([`HostedPlan::refused`]) leaves the reactor as it was.
    pub fn plan(
        &mut self,
        c: &Coords<'_>,
        selection: Option<&MavenSelection>,
        repository: &HostedRepository<'_>,
    ) -> HostedPlan {
        let mut plan = HostedPlan {
            nested_mvn: self.reactor.nested_mvn.clone(),
            ..HostedPlan::default()
        };
        let mut before: BTreeMap<String, String> = BTreeMap::new();
        if let Err(why) = self.plan_into(c, selection, repository, &mut plan, &mut before) {
            for (rel, text) in &before {
                // It was read from this text.
                let _ = self.set_text(rel, text);
            }
            return HostedPlan {
                refused: Some(why),
                notes: plan.notes,
                nested_mvn: plan.nested_mvn,
                ..HostedPlan::default()
            };
        }
        plan.poms = before
            .iter()
            .filter_map(|(rel, was)| {
                let now = &self.reactor.poms[rel].doc.text;
                (now != was).then(|| (rel.clone(), now.clone()))
            })
            .collect();
        plan.edits.retain(|edit| plan.poms.contains_key(&edit.rel));
        plan
    }

    fn plan_into(
        &mut self,
        c: &Coords<'_>,
        selection: Option<&MavenSelection>,
        repository: &HostedRepository<'_>,
        plan: &mut HostedPlan,
        before: &mut BTreeMap<String, String>,
    ) -> Result<(), Refused> {
        let (g, a, base) = (c.group_id, c.artifact_id, c.version);
        if !safe_coordinates(g, a, base) {
            return Err(refused(
                "unsafe_coordinates",
                format!("unsafe maven coordinates `{g}:{a}:{base}`"),
            ));
        }
        let patch = coords_patch(c);
        let sv = c.suffixed_version();
        let unread;
        let selection = match selection {
            Some(selection) => selection,
            None => {
                unread = MavenSelection::unavailable("what Maven selects was not read");
                &unread
            }
        };
        // What the poms held before this plan rewrote anything.
        let was_wired = self.reactor.wired_before(&patch);
        let named_before = self.generations(base);
        if let Standing::NotSelected(others) = selection.standing(g, a, base) {
            if !was_wired {
                plan.not_selected = Some(others);
                return Ok(());
            }
        }

        // The declarations that name the base version.
        let mut warnings = Vec::new();
        let mut unpinned = BTreeSet::new();
        let mut managed_roots = BTreeSet::new();
        let rewritten: Vec<(String, String)> = {
            let reactor = &self.reactor;
            let mut edits: BTreeMap<String, Vec<Edit>> = BTreeMap::new();
            let told = |rel: &str, dep: usize| {
                reactor
                    .readers_select(rel, dep, selection, c)
                    .then(|| base.to_string())
            };
            for rel in &reactor.scope {
                reactor.rewrite_declarations(
                    rel,
                    &patch,
                    &sv,
                    &mut edits,
                    &mut warnings,
                    &mut unpinned,
                    &mut managed_roots,
                    &mut BTreeSet::new(),
                    &told,
                );
            }
            forget_other_versions(&mut warnings, &reactor.under(selection, &patch, &|_| false));
            reactor
                .settle_properties(edits, c, &mut plan.edits, &mut plan.notes)
                .into_iter()
                .filter(|(_, edits)| !edits.is_empty())
                .map(|(rel, edits)| {
                    let text = apply_edits(&reactor.poms[&rel].doc.text, edits);
                    (rel, text)
                })
                .collect()
        };
        for (rel, text) in rewritten {
            self.replace(&rel, text, before)?;
        }

        // The pins: where a module selects the base version and no
        // declaration wires it yet.
        let pinned: Vec<(String, String, HostedEditKind)> = {
            let reactor = &self.reactor;
            let under = reactor.under(selection, &patch, &|module| {
                reactor.wired_without_pin(module, c)
            });
            let closed = |rel: &String| unpinned.contains(rel) || managed_roots.contains(rel);
            let kept = was_wired && !pin_moves(reactor, &patch, Some(&under));
            let (mut pins, mut held) =
                place_pins(reactor, &patch, Some(&under), &closed, kept, &mut warnings);
            // A patch the poms already wire keeps its pins where they are,
            // and a module nothing reaches yet that is certain to select
            // the base version is pinned all the same: a scan over a cold
            // local repository wires what it can tell, and the next one,
            // once the project was resolved, completes it. Nothing a pom
            // already holds is moved by this.
            if kept {
                let unreached =
                    reactor.under(selection, &patch, &|module| reactor.covers(module, c));
                let (mut more, mut ignored, mut stranded) =
                    (BTreeSet::new(), BTreeSet::new(), Vec::new());
                for root in reactor.wired_roots() {
                    let mut placing = Placing {
                        under: &unreached,
                        patch: &patch,
                        pins: &mut more,
                        held: &mut ignored,
                        stranded: &mut stranded,
                    };
                    reactor.place(&root, !closed(&root), &mut placing, 0);
                }
                held.retain(|rel| !more.contains(rel));
                pins.extend(more);
                warnings.extend(
                    stranded
                        .into_iter()
                        .map(|detail| degraded("pin_would_move_module", detail)),
                );
                warnings.extend(undetermined_note(&patch, &unreached));
            }
            let mut pinned = Vec::new();
            for rel in &reactor.scope {
                let doc = &reactor.poms[rel].doc;
                let (wanted, held) = (pins.contains(rel), held.contains(rel));
                let (text, kind) = match pin_of(doc, &patch) {
                    Some(pin) if !wanted && !held => {
                        let gav = pin.gav.clone();
                        let Some(text) = cut_pins(&doc.text, &|pin| pin.gav == gav) else {
                            continue;
                        };
                        (text, HostedEditKind::PinRemoved)
                    }
                    Some(pin) if pin.uuid == c.uuid => continue,
                    Some(pin) => (
                        apply_edits(&doc.text, vec![pin_update(doc, &pin, &patch)]),
                        HostedEditKind::PinMoved,
                    ),
                    None if wanted && !held => (
                        apply_edits(&doc.text, vec![pin_edit(doc, &patch, &sv).0]),
                        HostedEditKind::Pin,
                    ),
                    None => continue,
                };
                pinned.push((rel.clone(), text, kind));
            }
            pinned
        };
        for (rel, text, kind) in pinned {
            self.replace(&rel, text, before)?;
            plan.edits.push(HostedEdit::of(&rel, kind));
        }

        // No edit of a pom that the pom alone could not take back: such a
        // pom is left as it was (its modules stay unpatched, and are named).
        for (rel, was) in before.clone() {
            let now = &self.reactor.poms[&rel].doc.text;
            let undone = unwire_hosted(now, c, true, true);
            if undone.is_ok() && undone == unwire_hosted(&was, c, true, true) {
                continue;
            }
            // It was read from this text.
            let _ = self.set_text(&rel, &was);
            plan.edits.retain(|edit| edit.rel != rel);
            plan.notes.push((
                "edit_not_reversible".to_string(),
                format!(
                    "{rel}: the pin of {g}:{a}:{base} could not be removed again without a \
                     trace (an empty or one-line <dependencyManagement>, or a version that \
                     cannot be recorded); {rel} was left as it is"
                ),
            ));
        }

        // The repository follows the wiring: declared in the local root of
        // every pom that names the suffixed version, and gone once none
        // does.
        let named = self.naming(&sv);
        let mut removed: BTreeSet<String> = BTreeSet::new();
        if named.is_empty() {
            if named_before.contains(&sv) {
                plan.unnamed = true;
                removed.insert(c.uuid.to_string());
            }
        } else {
            let mut roots: Vec<String> = Vec::new();
            for rel in &named {
                let root = self.reactor.local_root(rel);
                if !roots.contains(&root) {
                    roots.push(root);
                }
            }
            for root in roots {
                let text = self.reactor.poms[&root].doc.text.clone();
                let (text, kind) = match (repository.ensure)(&text) {
                    Ok(None) => continue,
                    Ok(Some(RepositoryEdit::Added(text))) => (text, HostedEditKind::Repository),
                    Ok(Some(RepositoryEdit::Refreshed(text))) => {
                        (text, HostedEditKind::RepositoryUrl)
                    }
                    Err(why) => {
                        return Err(refused(
                            "repository_unwritable",
                            format!(
                                "{root} cannot take the <repository> that serves {g}:{a}:{sv} \
                                 ({why}), and the poms below it would name a version nothing \
                                 serves"
                            ),
                        ))
                    }
                };
                self.replace(&root, text, before)?;
                plan.edits.push(HostedEdit {
                    repository: Some(c.uuid.to_string()),
                    ..HostedEdit::of(&root, kind)
                });
            }
        }
        // An earlier patch of this version is gone once no pom of the
        // reactor names its suffix: any pom, changed by this plan or not.
        let named_after = self.generations(base);
        plan.superseded = named_before
            .difference(&named_after)
            .filter(|old| **old != sv)
            .cloned()
            .collect();
        let suffix_named = |this: &HostedReactor, hex8: &str| {
            let suffix = format!("-socket.{hex8}");
            this.reactor
                .scope
                .iter()
                .any(|rel| this.reactor.poms[rel].doc.masked.contains(&suffix))
        };
        let mut gone: Vec<&str> = plan
            .superseded
            .iter()
            .filter_map(|old| split_socket_version(old).map(|(_, hex8)| hex8))
            .filter(|hex8| !suffix_named(self, hex8))
            .collect();
        gone.dedup();
        for rel in self.reactor.scope.clone() {
            let mut text = self.reactor.poms[&rel].doc.text.clone();
            let mut taken = Vec::new();
            for uuid in (repository.declared)(&text) {
                let superseded = uuid != c.uuid && gone.iter().any(|hex8| uuid.starts_with(hex8));
                if !superseded && !removed.contains(&uuid) {
                    continue;
                }
                match (repository.remove)(&text, &uuid) {
                    Some(next) => {
                        text = next;
                        taken.push(uuid);
                    }
                    None if uuid == c.uuid => {
                        return Err(refused(
                            "repository_unwritable",
                            format!(
                                "{rel} declares the <repository> of {g}:{a}:{sv}, which no pom \
                                 names any more, in a form that cannot be taken out"
                            ),
                        ))
                    }
                    None => {}
                }
            }
            if taken.is_empty() {
                continue;
            }
            self.replace(&rel, text, before)?;
            for uuid in taken {
                removed.insert(uuid.clone());
                plan.edits.push(HostedEdit {
                    repository: Some(uuid),
                    ..HostedEdit::of(&rel, HostedEditKind::RepositoryRemoved)
                });
            }
        }

        // The plan as a whole: what names the patch is served and found,
        // and what it first wired a rollback takes back exactly.
        let wired = !named.is_empty() && self.reactor.wires(c);
        if !named.is_empty() {
            let found = self
                .sites()
                .into_iter()
                .any(|site| site.group == g && site.artifact == a && site.suffixed == sv);
            if !wired || !found {
                return Err(refused(
                    "nothing_wired",
                    format!(
                        "{} would name {g}:{a}:{sv} only where Maven does not always read it \
                         (inside <profiles>), so no build is certain to resolve it and a \
                         rollback could not find it",
                        named.join(", ")
                    ),
                ));
            }
            for rel in &named {
                let root = self.reactor.local_root(rel);
                let declared = (repository.declared)(&self.reactor.poms[&root].doc.text);
                if !declared.iter().any(|uuid| uuid == c.uuid) {
                    return Err(refused(
                        "repository_unwritable",
                        format!(
                            "{rel} would name {g}:{a}:{sv} with no <repository> for it in {root}"
                        ),
                    ));
                }
            }
        }
        for (rel, was) in before.iter() {
            let now = &self.reactor.poms[rel].doc.text;
            if now == was {
                continue;
            }
            let back = (repository.restored)(rel, now).map_err(|why| {
                refused(
                    "edit_not_reversible",
                    format!("{rel} could not be rolled back once written ({why})"),
                )
            })?;
            // A pom this plan is the first to wire returns to its bytes.
            let fresh = unwire_hosted(was, c, true, true).as_deref() == Ok(was.as_str())
                && !(repository.declared)(was)
                    .iter()
                    .any(|uuid| uuid == c.uuid || removed.contains(uuid));
            if fresh && back != *was {
                return Err(refused(
                    "edit_not_reversible",
                    format!(
                        "a rollback would not return {rel} to the bytes it has now (a \
                         <repositories> or <dependencyManagement> section in a shape that \
                         cannot be told from the one written)"
                    ),
                ));
            }
        }
        plan.wired = wired;
        plan.notes
            .extend(warnings.into_iter().filter_map(|warning| {
                let (reason, detail) = warning.detail.strip_prefix("reason: ")?.split_once(": ")?;
                Some((reason.to_string(), detail.to_string()))
            }));
        Ok(())
    }
}

/// `text` when it is one `${name}` reference and nothing else: the name.
fn sole_reference(text: &str) -> Option<&str> {
    let name = text.trim().strip_prefix("${")?.strip_suffix('}')?;
    (!name.is_empty() && !name.contains(['$', '{', '}'])).then_some(name)
}

/// Whether `text` can be recorded in an XML comment and read back as it
/// is: no `--`, no markup, on one line.
fn recordable(text: &str) -> bool {
    !text.is_empty()
        && text.trim() == text
        && !text.contains("--")
        && !text.ends_with('-')
        && !text.contains(['<', '>', '\n', '\r'])
}

impl Reactor {
    /// Whether `module` builds `c`'s suffixed version with no pin: from a
    /// declaration it makes or inherits, or from the project's own
    /// management nearest on its chain. A pin changes nothing for such a
    /// module, so it has no say in where the pins go; one that a pin alone
    /// wires still has, or a pin that came to move it would never be seen.
    fn wired_without_pin(&self, module: &str, c: &Coords<'_>) -> bool {
        let sv = c.suffixed_version();
        let resolve = |v: &str| self.interpolate(module, v);
        let names = |doc: &Doc, dep: usize| {
            doc.is_main_jar(dep)
                && doc.pin_at(dep).is_none()
                && doc.coordinate(dep, "groupId", &resolve).as_deref() == Some(c.group_id)
                && doc.coordinate(dep, "artifactId", &resolve).as_deref() == Some(c.artifact_id)
        };
        let reads = |doc: &Doc, dep: usize| doc.coordinate(dep, "version", &resolve);
        let declared = self.chain(module).any(|p| {
            let doc = &self.poms[p].doc;
            doc.declarations().into_iter().any(|dep| {
                doc.section_of(dep) == "dependencies"
                    && names(doc, dep)
                    && reads(doc, dep).as_deref() == Some(sv.as_str())
            })
        });
        declared
            || self
                .chain(module)
                .find_map(|p| {
                    let doc = &self.poms[p].doc;
                    doc.declarations()
                        .into_iter()
                        .find(|&dep| doc.is_top_level_managed(dep) && names(doc, dep))
                        .map(|dep| reads(doc, dep))
                })
                .flatten()
                .as_deref()
                == Some(sv.as_str())
    }

    /// Whether every reactor module that reads the declaration `dep` of
    /// `rel` (the module itself, and each module inheriting its pom)
    /// selects the base version of `c`: the declaration then reads it in
    /// each, whatever defines its `${...}` version outside the checkout.
    /// Only a declaration Maven always reads as the module's own direct
    /// dependency is told this way: a managed entry, or one in a profile,
    /// decides nothing on its own.
    fn readers_select(
        &self,
        rel: &str,
        dep: usize,
        selection: &MavenSelection,
        c: &Coords<'_>,
    ) -> bool {
        if self.poms[rel].doc.section_of(dep) != "dependencies" {
            return false;
        }
        let mut readers = std::iter::once(rel)
            .chain(self.inheritors(rel))
            .filter(|reader| self.reactor.iter().any(|module| module == reader))
            .peekable();
        readers.peek().is_some()
            && readers.all(|reader| {
                selection.verdict(reader, c.group_id, c.artifact_id, c.version) == Verdict::Selected
            })
    }

    /// The one top-level `<properties>` entry of the scope that defines
    /// `name`, when rewriting its value reaches the declarations that read
    /// it and nothing else can redefine it: its pom, the span of its value
    /// and the value (the base version, or an earlier patch's suffixed
    /// one). `None` when a profile, the command line or the project model
    /// defines the name too, or two poms do.
    fn property_site(&self, name: &str, base: &str) -> Option<(String, Range<usize>)> {
        if self.cli_props.contains_key(name) {
            return None;
        }
        let mut site = None;
        for rel in &self.scope {
            let pom = &self.poms[rel];
            let in_profile = pom
                .profile_props
                .iter()
                .any(|(_, props)| props.contains_key(name));
            if in_profile || self.model_ref(rel, name).is_some() {
                return None;
            }
            let doc = &pom.doc;
            let Some(properties) = doc.child(doc.project, "properties") else {
                continue;
            };
            let mut defined = doc.nodes[properties]
                .children
                .iter()
                .copied()
                .filter(|&n| doc.nodes[n].name == name);
            let Some(node) = defined.next() else {
                continue;
            };
            let span = doc.value_span(node);
            let literal = doc.text[span.clone()] == doc.text_of(node);
            if defined.next().is_some()
                || site.is_some()
                || !literal
                || !is_base_like(&doc.text[span.clone()], base)
            {
                return None;
            }
            site = Some((rel.clone(), span));
        }
        site
    }

    /// Decide how each `${...}` version among the planned version `edits`
    /// is wired (the module docs): the property's own value where every
    /// reference to it is one of these declarations, else the literal
    /// suffixed version with the replaced text recorded beside it. The
    /// edits to write, with what was done in `made` and what was not in
    /// `notes`.
    fn settle_properties(
        &self,
        mut edits: BTreeMap<String, Vec<Edit>>,
        c: &Coords<'_>,
        made: &mut Vec<HostedEdit>,
        notes: &mut Vec<(String, String)>,
    ) -> BTreeMap<String, Vec<Edit>> {
        let sv = c.suffixed_version();
        let ga = format!("{}:{}", c.group_id, c.artifact_id);
        // The versions that are one property reference, by its name.
        let mut by_name: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
        for (rel, file_edits) in &edits {
            let text = &self.poms[rel].doc.text;
            for edit in file_edits {
                if let Some(name) = sole_reference(&text[edit.start..edit.end]) {
                    *by_name
                        .entry(name.to_string())
                        .or_default()
                        .entry(rel.clone())
                        .or_default() += 1;
                }
            }
        }
        // A property only these declarations read is rewritten itself.
        let mut rewritten: BTreeSet<String> = BTreeSet::new();
        for (name, uses) in &by_name {
            let reference = format!("${{{name}}}");
            let only_these = self.scope.iter().all(|rel| {
                self.poms[rel].doc.text.matches(&reference).count()
                    == uses.get(rel).copied().unwrap_or(0)
            });
            let Some((rel, span)) = self.property_site(name, c.version).filter(|_| only_these)
            else {
                continue;
            };
            let was = self.poms[&rel].doc.text[span.clone()].to_string();
            edits
                .entry(rel.clone())
                .or_default()
                .push(Edit::plain(span.start, span.end, &sv));
            made.push(HostedEdit {
                rel,
                kind: HostedEditKind::Property,
                original: (was == c.version).then_some(was),
                property: Some(name.clone()),
                repository: None,
            });
            rewritten.insert(name.clone());
        }
        for (rel, file_edits) in edits.iter_mut() {
            let doc = &self.poms[rel].doc;
            let mut kept = Vec::new();
            for edit in std::mem::take(file_edits) {
                let Role::Version { original, .. } = &edit.role else {
                    kept.push(edit);
                    continue;
                };
                let was = &doc.text[edit.start..edit.end];
                if sole_reference(was).is_some_and(|name| rewritten.contains(name)) {
                    continue;
                }
                let at = format!("{rel}:{}", doc.line_of(edit.start));
                if !was.contains("${") {
                    made.push(HostedEdit {
                        rel: rel.clone(),
                        kind: HostedEditKind::Version,
                        original: original.clone(),
                        property: None,
                        repository: None,
                    });
                    kept.push(edit);
                    continue;
                }
                // The literal, with the text it replaces recorded right
                // after the element.
                let rest = &doc.masked[edit.end..];
                let close = rest.len() - rest.trim_start().len();
                let after = edit.end + close + "</version>".len();
                let recorded = doc.text[after.min(doc.text.len())..].starts_with(ORIGINAL_TAG);
                if original.is_none()
                    || !recordable(was)
                    || !rest[close..].starts_with("</version>")
                    || recorded
                {
                    notes.push((
                        "property_unresolved".to_string(),
                        format!(
                            "{at}: {ga} version {was} cannot be replaced and recorded; left as \
                             is, probably unpatched"
                        ),
                    ));
                    continue;
                }
                made.push(HostedEdit {
                    rel: rel.clone(),
                    kind: HostedEditKind::Version,
                    original: Some(was.to_string()),
                    property: None,
                    repository: None,
                });
                kept.push(Edit::plain(
                    after,
                    after,
                    &format!("{ORIGINAL_TAG}{was}{COMMENT_CLOSE}"),
                ));
                kept.push(edit);
            }
            *file_edits = kept;
        }
        edits
    }
}

/// `text` without the pins `mine` accepts, each cut by its lines, and
/// without the `<dependencyManagement>` section once those pins were all
/// it held; `None` when there is no such pin or `text` is not a pom.
fn cut_pins(text: &str, mine: &dyn Fn(&Pin) -> bool) -> Option<String> {
    let doc = Doc::parse(text.to_string()).ok()?;
    let mut pins: Vec<Pin> = doc
        .declarations()
        .into_iter()
        .filter_map(|dep| doc.pin_at(dep))
        .filter(|pin| mine(pin))
        .collect();
    if pins.is_empty() {
        return None;
    }
    pins.sort_by_key(|pin| std::cmp::Reverse(pin.start));
    let mut out = text.to_string();
    for pin in pins {
        out.replace_range(pin.start..pin.end, "");
    }
    Some(without_empty_management(&out).unwrap_or(out))
}

/// `text` without its top-level `<dependencyManagement>` when that holds
/// one `<dependencies>` and no entry, comment or text at all: the section
/// a pin created, once the pin is cut.
fn without_empty_management(text: &str) -> Option<String> {
    let doc = Doc::parse(text.to_string()).ok()?;
    let dm = doc.child(doc.project, "dependencyManagement")?;
    let [deps] = doc.nodes[dm].children[..] else {
        return None;
    };
    let (dm, deps) = (&doc.nodes[dm], &doc.nodes[deps]);
    let blank = |range: Range<usize>| text[range].trim().is_empty();
    if deps.name != "dependencies"
        || deps.inner_start == deps.end
        || !deps.children.is_empty()
        || !blank(deps.inner_start..deps.inner_end)
        || !blank(dm.inner_start..deps.start)
        || !blank(deps.end..dm.inner_end)
    {
        return None;
    }
    let (start, end) = line_span(text, dm.start, dm.end);
    Some(format!("{}{}", &text[..start], &text[end..]))
}

/// `text` (one pom) without the hosted wiring of the patch `c` that
/// [`plan_hosted`] writes: its pin, a `${...}` version put back from the
/// comment that records it, and a property holding the suffixed version
/// back at the base version. `literals` also puts every other declaration
/// of the artifact at the suffixed version back at the base version: the
/// caller leaves them out for a pom an earlier release may have pinned,
/// whose own entry is told from a rewritten one by other means.
/// `any_patch` takes out the wiring of every patch of `c`'s version, not
/// `c`'s alone. The `<repository>` is not touched.
pub fn unwire_hosted(
    text: &str,
    c: &Coords<'_>,
    any_patch: bool,
    literals: bool,
) -> Result<String, String> {
    let gav = format!("{}:{}:{}", c.group_id, c.artifact_id, c.version);
    let sv = c.suffixed_version();
    let ours = |version: &str| match any_patch {
        true => version != c.version && is_base_like(version, c.version),
        false => version == sv,
    };
    let with_pins = cut_pins(text, &|pin| {
        pin.gav == gav && (any_patch || pin.uuid == c.uuid)
    });
    let text = with_pins.as_deref().unwrap_or(text);
    let doc = Doc::parse(text.to_string())?;
    let mut edits = Vec::new();
    for dep in doc.declarations() {
        let Some(version) = doc.child(dep, "version") else {
            continue;
        };
        let named = |name: &str, want: &str| {
            doc.child_text(dep, name)
                .is_some_and(|text| text == want || text.contains("${"))
        };
        if !ours(&doc.text_of(version))
            || !named("groupId", c.group_id)
            || !named("artifactId", c.artifact_id)
        {
            continue;
        }
        let span = doc.value_span(version);
        let after = doc.nodes[version].end;
        let recorded = text[after..].strip_prefix(ORIGINAL_TAG).and_then(|rest| {
            let len = rest.find(COMMENT_CLOSE)?;
            Some((
                &rest[..len],
                after + ORIGINAL_TAG.len() + len + COMMENT_CLOSE.len(),
            ))
        });
        match recorded {
            Some((was, end)) => {
                edits.push(Edit::plain(span.start, span.end, was));
                edits.push(Edit::plain(after, end, ""));
            }
            None if literals => edits.push(Edit::plain(span.start, span.end, c.version)),
            None => {}
        }
    }
    let models =
        std::iter::once(doc.project).chain((0..doc.nodes.len()).filter(|&n| doc.is_profile(n)));
    for model in models {
        let Some(properties) = doc.child(model, "properties") else {
            continue;
        };
        for &property in &doc.nodes[properties].children {
            let span = doc.value_span(property);
            if ours(&doc.text[span.clone()]) {
                edits.push(Edit::plain(span.start, span.end, c.version));
            }
        }
    }
    Ok(apply_edits(text, edits))
}

#[cfg(test)]
mod tests;
