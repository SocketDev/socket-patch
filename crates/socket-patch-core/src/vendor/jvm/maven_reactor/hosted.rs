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
//!   after the element ([`ORIGINAL_TAG`]).
//!
//! [`unwire_hosted`] is the inverse, and [`plan_hosted`] makes no edit it
//! does not undo exactly: each pom it would change is unwired again before
//! the plan is returned, and left alone when that is not the text it had.
//! The `<repository>` and the `.mvn` files are the hosted rewriter's.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use super::{
    apply_edits, coords_patch, degraded, forget_other_versions, is_base_like, keeps_placement,
    line_span, pin_edit, pin_of, pin_update, place_pins, safe_coordinates, unattestable_in,
    undetermined_note, unwired_in, Doc, Edit, Pin, Placing, Reactor, Role,
};
use crate::crawlers::maven_selection::{MavenSelection, Standing, Verdict};
use crate::formats::maven::split_socket_version;
use crate::vendor::jvm::{Coords, JvmRefusal, ListFn, ReadFn};

/// The start of the comment that records what a declaration's `<version>`
/// read before hosted mode replaced it with a literal suffixed version:
/// `<version>1.2-socket.0a1b2c3d</version><!-- socket-patch:version ${x} -->`.
pub const ORIGINAL_TAG: &str = "<!-- socket-patch:version ";
const COMMENT_CLOSE: &str = " -->";

/// What one edit of [`plan_hosted`] is.
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
}

/// One edit of [`plan_hosted`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedEdit {
    /// The pom edited.
    pub rel: String,
    pub kind: HostedEditKind,
    /// The text replaced: a version, a property's value (`None` for a pin,
    /// and for a version an earlier patch had suffixed).
    pub original: Option<String>,
    /// The property a [`HostedEditKind::Property`] edit rewrote.
    pub property: Option<String>,
}

/// What hosted mode does to a reactor's poms for one patch.
#[derive(Debug, Default)]
pub struct HostedPlan {
    /// The poms that change, with their new text.
    pub poms: BTreeMap<String, String>,
    pub edits: Vec<HostedEdit>,
    /// Why a declaration or a pom was left as it is: the vendored
    /// planner's reason word, and the line.
    pub notes: Vec<(String, String)>,
    /// Whether a pom wires the patch once the plan is written (or did
    /// before).
    pub wired: bool,
    /// The local roots under which a pom names the suffixed version: where
    /// the `<repository>` goes, for every pom below to inherit.
    pub roots: Vec<String>,
    /// The module directories with a `.mvn` of their own.
    pub nested_mvn: Vec<String>,
    /// No module selects the base version, and every answer is certain:
    /// the versions selected instead. Nothing is planned then.
    pub not_selected: Option<Vec<String>>,
}

/// Plan the hosted wiring of the patch `c` in the reactor rooted at
/// `pom.xml` (a single pom is a reactor of one). `selection` is what Maven
/// selects in each module; `None` reads as "cannot be told", which rewrites
/// the declarations that name the base version and pins nothing.
pub fn plan_hosted(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
    selection: Option<&MavenSelection>,
) -> Result<HostedPlan, JvmRefusal> {
    let (g, a, base) = (c.group_id, c.artifact_id, c.version);
    if !safe_coordinates(g, a, base) {
        return Err(JvmRefusal {
            code: "unsafe_coordinates",
            detail: format!("unsafe maven coordinates `{g}:{a}:{base}`"),
        });
    }
    let patch = coords_patch(c);
    let sv = c.suffixed_version();
    let reactor = Reactor::discover_for(read, list, true)?;
    let unread;
    let selection = match selection {
        Some(selection) => selection,
        None => {
            unread = MavenSelection::unavailable("what Maven selects was not read");
            &unread
        }
    };
    let mut plan = HostedPlan {
        nested_mvn: reactor.nested_mvn.clone(),
        ..HostedPlan::default()
    };
    if let Standing::NotSelected(others) = selection.standing(g, a, base) {
        if !reactor.wired_before(&patch) {
            plan.not_selected = Some(others);
            return Ok(plan);
        }
    }

    // The declarations that name the base version.
    let mut edits: BTreeMap<String, Vec<Edit>> = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut unpinned = BTreeSet::new();
    let mut managed_roots = BTreeSet::new();
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
    let mut made: Vec<HostedEdit> = Vec::new();
    let edits = reactor.settle_properties(edits, c, &mut made, &mut plan.notes);
    let mut texts: BTreeMap<String, String> = edits
        .into_iter()
        .filter(|(_, edits)| !edits.is_empty())
        .map(|(rel, edits)| {
            let text = apply_edits(&reactor.poms[&rel].doc.text, edits);
            (rel, text)
        })
        .collect();

    // The pins: where a module selects the base version and no declaration
    // wires it yet.
    let rewritten = Reactor::discover_for(&reading(&texts, read), list, true)?;
    let under = rewritten.under(selection, &patch, &|module| {
        rewritten.wired_without_pin(module, c)
    });
    let closed = |rel: &String| unpinned.contains(rel) || managed_roots.contains(rel);
    let (mut pins, mut held) = place_pins(&reactor, &patch, Some(&under), &closed, &mut warnings);
    // A patch the poms already wire keeps its pins where they are, and a
    // module nothing reaches yet that is certain to select the base version
    // is pinned all the same: a scan over a cold local repository wires
    // what it can tell, and the next one, once the project was resolved,
    // completes it. Nothing a pom already holds is moved by this.
    if keeps_placement(&reactor, &patch, Some(&under)) {
        let unreached = rewritten.under(selection, &patch, &|module| rewritten.covers(module, c));
        let (mut more, mut ignored, mut stranded) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
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
    for rel in &rewritten.scope {
        let doc = &rewritten.poms[rel].doc;
        let (pinned, held) = (pins.contains(rel), held.contains(rel));
        let (text, kind) = match pin_of(doc, &patch) {
            Some(pin) if !pinned && !held => {
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
            None if pinned && !held => (
                apply_edits(&doc.text, vec![pin_edit(doc, &patch, &sv).0]),
                HostedEditKind::Pin,
            ),
            None => continue,
        };
        texts.insert(rel.clone(), text);
        made.push(HostedEdit {
            rel: rel.clone(),
            kind,
            original: None,
            property: None,
        });
    }

    // No edit that could not be taken back exactly.
    for (rel, text) in std::mem::take(&mut texts) {
        let before = &reactor.poms[&rel].doc.text;
        let undone = unwire_hosted(&text, c, true, true);
        if undone.is_ok() && undone == unwire_hosted(before, c, true, true) {
            texts.insert(rel, text);
            continue;
        }
        made.retain(|edit| edit.rel != rel);
        plan.notes.push((
            "edit_not_reversible".to_string(),
            format!(
                "{rel}: the pin of {g}:{a}:{base} could not be removed again without a trace \
                 (an empty or one-line <dependencyManagement>, or a version that cannot be \
                 recorded); {rel} was left as it is"
            ),
        ));
    }

    let wired = Reactor::discover_for(&reading(&texts, read), list, true)?;
    plan.wired = wired.wires(c);
    for rel in &wired.scope {
        let root = wired.local_root(rel);
        if wired.poms[rel].doc.masked.contains(&sv) && !plan.roots.contains(&root) {
            plan.roots.push(root);
        }
    }
    plan.notes
        .extend(warnings.into_iter().filter_map(|warning| {
            let (reason, detail) = warning.detail.strip_prefix("reason: ")?.split_once(": ")?;
            Some((reason.to_string(), detail.to_string()))
        }));
    plan.poms = texts
        .into_iter()
        .filter(|(rel, text)| *text != reactor.poms[rel].doc.text)
        .collect();
    plan.edits = made
        .into_iter()
        .filter(|edit| plan.poms.contains_key(&edit.rel))
        .collect();
    Ok(plan)
}

/// `texts` over `read`: the project as it reads once `texts` are written.
fn reading<'a>(
    texts: &'a BTreeMap<String, String>,
    read: ReadFn<'a>,
) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
    move |rel| match texts.get(rel) {
        Some(text) => Some(text.clone().into_bytes()),
        None => read(rel),
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

/// Read the reactor as [`plan_hosted`] reads it; `false` when it cannot be
/// read from what `read` returned. For a caller that learns from `read`
/// which files the planner takes.
pub fn readable_for_hosted(read: ReadFn<'_>, list: ListFn<'_>) -> bool {
    Reactor::discover_for(read, list, true).is_ok()
}

/// Why `vex` must not attest the hosted patch `c` although the reactor's
/// poms wire it, as vendored mode weighs its own wiring: a declaration
/// that may still build the base version ([`unattestable_in`]), or a
/// module that resolves it (or may, by `selection`) and no pin or
/// declaration reaches ([`unwired_in`]). `None` when nothing does.
pub fn hosted_unattestable(
    read: ReadFn<'_>,
    list: ListFn<'_>,
    c: &Coords<'_>,
    selection: &MavenSelection,
) -> Result<Option<String>, JvmRefusal> {
    let reactor = Reactor::discover_for(read, list, true)?;
    Ok(unattestable_in(&reactor, c).or_else(|| unwired_in(&reactor, c, selection)))
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

/// The artifacts the reactor's poms build at a Socket suffixed version,
/// read as Maven reads them (a `${...}` through the properties of the
/// declaring pom's chain), with the poms that name each. Declarations
/// inside `<profiles>` are not read: Maven reads those only while their
/// profile is active.
pub fn hosted_sites(read: ReadFn<'_>, list: ListFn<'_>) -> Result<Vec<HostedSite>, JvmRefusal> {
    let reactor = Reactor::discover_for(read, list, true)?;
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
    Ok(sites
        .into_iter()
        .map(|((group, artifact, suffixed), uuid)| HostedSite {
            rels: reactor
                .scope
                .iter()
                .filter(|rel| reactor.poms[*rel].doc.masked.contains(&suffixed))
                .cloned()
                .collect(),
            group,
            artifact,
            suffixed,
            uuid,
        })
        .collect())
}

#[cfg(test)]
mod tests;
