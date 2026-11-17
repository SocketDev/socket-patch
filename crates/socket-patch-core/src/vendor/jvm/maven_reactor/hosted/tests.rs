use super::*;

const G: &str = "org.x";
const A: &str = "victim";
const BASE: &str = "1.10.0";
const UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";
const SV: &str = "1.10.0-socket.4d5e6f70";
const TAG: &str = "<!-- socket-patch 4d5e6f70-8192-4a3b-9c4d-5e6f708192a3: org.x:victim:1.10.0 -->";

type Fs = BTreeMap<String, String>;

fn coords() -> Coords<'static> {
    Coords {
        group_id: G,
        artifact_id: A,
        version: BASE,
        uuid: UUID,
    }
}

fn fs(files: &[(&str, &str)]) -> Fs {
    files
        .iter()
        .map(|(rel, text)| (rel.to_string(), text.to_string()))
        .collect()
}

fn dep(artifact: &str, version: Option<&str>) -> String {
    let version = version.map_or(String::new(), |v| format!("\n      <version>{v}</version>"));
    format!(
        "    <dependency>\n      <groupId>{G}</groupId>\n      \
         <artifactId>{artifact}</artifactId>{version}\n    </dependency>\n"
    )
}

/// The reactor root `t:root:1` over the modules `a` and `b`, with `body`.
fn root(body: &str) -> String {
    format!(
        "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>t</groupId>\n  \
         <artifactId>root</artifactId>\n  <version>1</version>\n  \
         <packaging>pom</packaging>\n  <modules>\n    <module>a</module>\n    \
         <module>b</module>\n  </modules>\n{body}</project>\n"
    )
}

/// The module `name` of [`root`], declaring `deps`.
fn module(name: &str, deps: &str) -> String {
    format!(
        "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
         <groupId>t</groupId>\n    <artifactId>root</artifactId>\n    \
         <version>1</version>\n  </parent>\n  <artifactId>{name}</artifactId>\n  \
         <dependencies>\n{deps}  </dependencies>\n</project>\n"
    )
}

/// A pom on its own (no modules, no parent in the checkout), with `body`.
fn single(body: &str) -> String {
    format!(
        "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>t</groupId>\n  \
         <artifactId>app</artifactId>\n  <version>1</version>\n{body}</project>\n"
    )
}

fn deps(list: &str) -> String {
    format!("  <dependencies>\n{list}  </dependencies>\n")
}

fn properties(list: &[(&str, &str)]) -> String {
    let entries: String = list
        .iter()
        .map(|(name, value)| format!("    <{name}>{value}</{name}>\n"))
        .collect();
    format!("  <properties>\n{entries}  </properties>\n")
}

/// What each module of `files` selects for the victim: its base version,
/// another one, or why it cannot be told; a module left out does not
/// resolve it.
fn selecting(files: &Fs, picks: &[(&str, Result<&str, &str>)]) -> MavenSelection {
    let modules: Vec<&str> = files
        .keys()
        .map(String::as_str)
        .filter(|rel| rel.ends_with("pom.xml"))
        .collect();
    let picks: Vec<_> = picks
        .iter()
        .map(|(pom, pick)| (*pom, G, A, *pick))
        .collect();
    MavenSelection::answering(&modules, &picks)
}

/// Where the grant serves the patch from.
const INDEX_URL: &str =
    "https://patch.socket.dev/patch-registry/maven/tok/4d5e6f70-8192-4a3b-9c4d-5e6f708192a3/maven2";

fn reactor(files: &Fs) -> HostedReactor {
    let read = |rel: &str| files.get(rel).map(|text| text.clone().into_bytes());
    let list = |dir: &str| {
        let bytes: BTreeMap<String, Vec<u8>> = files
            .iter()
            .map(|(rel, text)| (rel.clone(), text.clone().into_bytes()))
            .collect();
        crate::vendor::jvm::testing::list_of(&bytes, dir)
    };
    HostedReactor::read(&read, &list).expect("a reactor")
}

/// Whether `files` head a reactor, which is how a rollback reads them.
fn heads_reactor(files: &Fs) -> bool {
    files.keys().filter(|rel| rel.ends_with("pom.xml")).count() > 1
}

/// The plan for `c` over `files`, with the hosted rewriter's own
/// repository edits and restore.
fn planned_for(files: &Fs, c: &Coords<'_>, selection: Option<&MavenSelection>) -> HostedPlan {
    let index_url = INDEX_URL.replace(UUID, c.uuid);
    crate::patch::redirect::with_hosted_repository(
        c,
        &index_url,
        &BTreeMap::new(),
        heads_reactor(files),
        |repository| reactor(files).plan(c, selection, repository),
    )
}

fn planned(files: &Fs, selection: Option<&MavenSelection>) -> HostedPlan {
    planned_for(files, &coords(), selection)
}

fn written(files: &Fs, plan: &HostedPlan) -> Fs {
    let mut out = files.clone();
    out.extend(plan.poms.clone());
    out
}

/// `files` as a rollback of the patch `c` leaves them: every pom through
/// the restore `rollback` runs.
fn rolled_back_for(files: &Fs, c: &Coords<'_>) -> Fs {
    let index_url = INDEX_URL.replace(UUID, c.uuid);
    let pin = crate::patch::redirect::upstream::maven::PinIn {
        group: c.group_id,
        artifact: c.artifact_id,
        base: c.version,
        uuid: c.uuid,
        reactor: heads_reactor(files),
    };
    let hosted_uuid = |url: &str| (url == index_url).then(|| c.uuid.to_string());
    files
        .iter()
        .map(|(rel, text)| {
            let done = crate::patch::redirect::upstream::maven::restore_pom(
                rel,
                text,
                &BTreeMap::new(),
                &pin,
                &hosted_uuid,
            )
            .unwrap_or_else(|why| panic!("{rel}: {why}"));
            (rel.clone(), done.text)
        })
        .collect()
}

/// Every pom of `after` rolled back, which must be `before`.
fn assert_unwires_to(after: &Fs, before: &Fs) {
    assert_eq!(&rolled_back_for(after, &coords()), before);
}

/// THE INVARIANT, on poms as written: a pom names a `-socket.<hex8>`
/// version only when a declaration Maven always reads resolves to it (so
/// discovery finds it, in every pom that names it) and its local root
/// declares the repository that serves it; and no pom declares a hosted
/// repository whose suffix no pom names.
fn assert_invariant(files: &Fs) {
    let reactor = reactor(files);
    let sites = reactor.sites();
    let repositories = |text: &str| -> Vec<String> {
        crate::patch::redirect::generation::named_generations(text)
            .into_iter()
            .collect()
    };
    for (rel, text) in files {
        let (masked, _) = super::super::mask(text);
        for (at, _) in masked.match_indices("-socket.") {
            let hex8 = &masked[at + 8..at + 16];
            let site = sites
                .iter()
                .find(|site| site.suffixed.ends_with(hex8) && site.rels.contains(rel))
                .unwrap_or_else(|| panic!("{rel} names -socket.{hex8}, which discovery cannot find: {sites:?}\n{text}"));
            // The root of the chain: the last pom a child inherits from.
            let served = files.iter().any(|(_, other)| {
                repositories(other)
                    .iter()
                    .any(|uuid| uuid.starts_with(hex8))
            });
            assert!(
                served,
                "{rel} names {} with no repository for it",
                site.suffixed
            );
        }
        for uuid in repositories(text) {
            assert!(
                sites.iter().any(|site| site.suffixed.ends_with(&uuid[..8])),
                "{rel} declares the repository of {uuid}, which no pom names: {text}"
            );
        }
    }
}

fn is_repository(kind: HostedEditKind) -> bool {
    matches!(
        kind,
        HostedEditKind::Repository
            | HostedEditKind::RepositoryUrl
            | HostedEditKind::RepositoryRemoved
    )
}

/// The pom edits of `plan`, the repository's apart ([`repositories`]).
fn kinds(plan: &HostedPlan) -> Vec<(&str, HostedEditKind)> {
    plan.edits
        .iter()
        .filter(|edit| !is_repository(edit.kind))
        .map(|edit| (edit.rel.as_str(), edit.kind))
        .collect()
}

fn repositories(plan: &HostedPlan) -> Vec<(&str, HostedEditKind)> {
    plan.edits
        .iter()
        .filter(|edit| is_repository(edit.kind))
        .map(|edit| (edit.rel.as_str(), edit.kind))
        .collect()
}

fn reasons(plan: &HostedPlan) -> Vec<&str> {
    plan.notes
        .iter()
        .map(|(reason, _)| reason.as_str())
        .collect()
}

/// Two modules reach the victim through other libraries: `a` resolves the
/// patch's version, `b` a newer one. The pin goes in `a` alone, so `b`
/// keeps what it resolves, and the repository goes in the root both
/// inherit.
#[test]
fn a_pin_goes_in_the_module_that_selects_the_version_and_no_other() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let selection = selecting(
        &files,
        &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok("1.11.0"))],
    );
    let plan = planned(&files, Some(&selection));
    assert_eq!(kinds(&plan), [("a/pom.xml", HostedEditKind::Pin)]);
    assert!(plan.wired);
    assert_eq!(
        repositories(&plan),
        [("pom.xml", HostedEditKind::Repository)]
    );
    let a = &plan.poms["a/pom.xml"];
    assert!(
        a.contains(&format!(
            "  <dependencyManagement>\n    <dependencies>\n      {TAG}\n      <dependency>\n        \
             <groupId>{G}</groupId>\n        <artifactId>{A}</artifactId>\n        \
             <version>{SV}</version>\n      </dependency>\n    </dependencies>\n  \
             </dependencyManagement>\n  <dependencies>"
        )),
        "{a}"
    );
    let after = written(&files, &plan);
    assert_unwires_to(&after, &files);
    // A second run changes nothing, whatever it is told.
    for told in [Some(&selection), None] {
        let again = planned(&after, told);
        assert!(
            again.poms.is_empty() && again.edits.is_empty(),
            "{:?}",
            again.edits
        );
        assert!(again.wired);
    }
}

/// Every module selects the version: one pin in the pom they all inherit.
#[test]
fn modules_that_all_select_the_version_are_pinned_in_their_parent() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let selection = selecting(&files, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let plan = planned(&files, Some(&selection));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::Pin)]);
    assert_unwires_to(&written(&files, &plan), &files);
}

/// A declaration that names the version is rewritten where it stands, and
/// a module it wires needs no pin: nothing but that one version changes.
#[test]
fn a_declaration_of_the_version_is_rewritten_and_needs_no_pin() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep(A, Some(BASE)))),
        ("b/pom.xml", &module("b", &dep(A, Some("1.11.0")))),
    ]);
    let selection = selecting(
        &files,
        &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok("1.11.0"))],
    );
    let plan = planned(&files, Some(&selection));
    assert_eq!(kinds(&plan), [("a/pom.xml", HostedEditKind::Version)]);
    assert_eq!(plan.edits[0].original.as_deref(), Some(BASE));
    assert_eq!(
        plan.poms["a/pom.xml"],
        files["a/pom.xml"].replace(BASE, SV),
        "only the version text changes"
    );
    assert_eq!(
        repositories(&plan),
        [("pom.xml", HostedEditKind::Repository)]
    );
    assert!(reasons(&plan).is_empty(), "{:?}", plan.notes);
    assert_unwires_to(&written(&files, &plan), &files);
    // The declaration is rewritten whatever Maven selects elsewhere, since
    // that replaces a version where it stands.
    let unread = planned(&files, None);
    assert_eq!(kinds(&unread), [("a/pom.xml", HostedEditKind::Version)]);
}

/// A property only the patched artifact's declarations read is rewritten
/// itself: the declarations keep their `${...}` text.
#[test]
fn a_property_only_the_artifact_reads_is_rewritten_itself() {
    let files = fs(&[
        ("pom.xml", &root(&properties(&[("victim.version", BASE)]))),
        (
            "a/pom.xml",
            &module("a", &dep(A, Some("${victim.version}"))),
        ),
        (
            "b/pom.xml",
            &module("b", &dep(A, Some("${victim.version}"))),
        ),
    ]);
    let selection = selecting(&files, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let plan = planned(&files, Some(&selection));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::Property)]);
    assert_eq!(plan.edits[0].property.as_deref(), Some("victim.version"));
    assert_eq!(plan.edits[0].original.as_deref(), Some(BASE));
    assert!(
        plan.poms["pom.xml"].contains(&format!("<victim.version>{SV}</victim.version>"))
            && !plan.poms.contains_key("a/pom.xml"),
        "the property takes the version, the declarations keep their text"
    );
    assert!(plan.wired);
    let after = written(&files, &plan);
    assert_unwires_to(&after, &files);
    let again = planned(&after, Some(&selection));
    assert!(again.poms.is_empty() && again.wired, "{:?}", again.edits);
}

/// A property a sibling artifact reads too is left alone: the one
/// declaration takes the literal, and the text it replaced is recorded
/// right after it.
#[test]
fn a_property_a_sibling_reads_is_left_alone() {
    let shared = format!(
        "{}{}",
        dep(A, Some("${lib.version}")),
        dep("sibling", Some("${lib.version}"))
    );
    let files = fs(&[(
        "pom.xml",
        &single(&format!(
            "{}{}",
            properties(&[("lib.version", BASE)]),
            deps(&shared)
        )),
    )]);
    let selection = selecting(&files, &[("pom.xml", Ok(BASE))]);
    let plan = planned(&files, Some(&selection));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::Version)]);
    assert_eq!(plan.edits[0].original.as_deref(), Some("${lib.version}"));
    let pom = &plan.poms["pom.xml"];
    assert!(
        pom.starts_with(
            files["pom.xml"]
                .replacen(
                    "<version>${lib.version}</version>",
                    &format!(
                        "<version>{SV}</version><!-- socket-patch:version ${{lib.version}} -->"
                    ),
                    1
                )
                .trim_end_matches("</project>\n")
        ),
        "{pom}"
    );
    assert!(
        pom.contains("<lib.version>1.10.0</lib.version>")
            && pom.contains(
                "<artifactId>sibling</artifactId>\n      <version>${lib.version}</version>"
            ),
        "the property and the sibling are untouched: {pom}"
    );
    let after = written(&files, &plan);
    assert_unwires_to(&after, &files);
    let again = planned(&after, Some(&selection));
    assert!(again.poms.is_empty() && again.wired, "{:?}", again.edits);
}

/// A property no pom of the checkout defines (a parent resolved from a
/// repository does): what it reads is what Maven selects for the module
/// that declares it. Certain, the declaration takes the literal with its
/// text recorded; not certain, it is left as it is.
#[test]
fn a_property_of_a_parent_outside_the_checkout_follows_the_selection() {
    let parent =
        "  <parent>\n    <groupId>corp</groupId>\n    <artifactId>parent</artifactId>\n    \
                  <version>7</version>\n    <relativePath/>\n  </parent>\n";
    let files = fs(&[(
        "pom.xml",
        &single(&format!(
            "{parent}{}",
            deps(&dep(A, Some("${corp.victim.version}")))
        )),
    )]);
    let plan = planned(&files, Some(&selecting(&files, &[("pom.xml", Ok(BASE))])));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::Version)]);
    assert!(
        plan.poms["pom.xml"].contains(&format!(
            "<version>{SV}</version><!-- socket-patch:version ${{corp.victim.version}} -->"
        )),
        "{}",
        plan.poms["pom.xml"]
    );
    assert_unwires_to(&written(&files, &plan), &files);

    for doubt in [
        Some(selecting(
            &files,
            &[("pom.xml", Err("a pom is not cached"))],
        )),
        Some(selecting(&files, &[("pom.xml", Ok("1.11.0"))])),
        None,
    ] {
        let plan = planned(&files, doubt.as_ref());
        assert!(plan.poms.is_empty() && !plan.wired, "{:?}", plan.edits);
        if plan.not_selected.is_none() {
            assert!(
                reasons(&plan).contains(&"property_unresolved"),
                "{:?}",
                plan.notes
            );
        }
    }
}

/// A version-less declaration a parent outside the checkout manages (the
/// usual Spring Boot shape): no declaration is touched, the pin goes in
/// the project's own management.
#[test]
fn a_version_managed_outside_the_checkout_is_pinned_not_rewritten() {
    let files = fs(&[("pom.xml", &single(&deps(&dep(A, None))))]);
    let plan = planned(&files, Some(&selecting(&files, &[("pom.xml", Ok(BASE))])));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::Pin)]);
    assert!(plan.wired);
    assert_unwires_to(&written(&files, &plan), &files);
}

/// No module of the build selects the version: nothing is planned, and
/// the plan says what is selected instead.
#[test]
fn a_version_no_module_selects_is_not_planned() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let selection = selecting(
        &files,
        &[("a/pom.xml", Ok("1.11.0")), ("b/pom.xml", Ok("1.9"))],
    );
    let plan = planned(&files, Some(&selection));
    assert_eq!(
        plan.not_selected,
        Some(vec!["1.9".to_string(), "1.11.0".to_string()])
    );
    assert!(plan.poms.is_empty() && plan.edits.is_empty() && !plan.wired);
}

/// A module whose selection cannot be told gets no pin (a pin there would
/// be a guess), and the one beside it that is certain still gets its own.
#[test]
fn an_undetermined_module_is_not_pinned_and_its_sibling_is() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let selection = selecting(
        &files,
        &[
            ("a/pom.xml", Ok(BASE)),
            ("b/pom.xml", Err("lib-y:1.0 is not cached")),
        ],
    );
    let plan = planned(&files, Some(&selection));
    assert_eq!(kinds(&plan), [("a/pom.xml", HostedEditKind::Pin)]);
    assert_eq!(reasons(&plan), ["selection_undetermined"]);

    // Told nothing at all, nothing is pinned.
    let unread = planned(&files, None);
    assert!(
        unread.poms.is_empty() && !unread.wired,
        "{:?}",
        unread.edits
    );
    assert_eq!(reasons(&unread), ["selection_undetermined"]);
}

/// A scan over a cold local repository wires what it can tell; the next
/// one, once Maven has resolved the project, pins the module the first
/// could not, and moves nothing the first wrote. Told nothing new, it
/// writes nothing.
#[test]
fn a_later_scan_completes_what_an_earlier_one_could_not_tell() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        ("b/pom.xml", &module("b", &dep(A, Some(BASE)))),
    ]);
    let cold = selecting(
        &files,
        &[
            ("a/pom.xml", Err("lib-x:1.0 is not cached")),
            ("b/pom.xml", Ok(BASE)),
        ],
    );
    let first = planned(&files, Some(&cold));
    assert_eq!(kinds(&first), [("b/pom.xml", HostedEditKind::Version)]);
    assert_eq!(reasons(&first), ["selection_undetermined"]);
    let after = written(&files, &first);
    let again = planned(
        &after,
        Some(&selecting(
            &after,
            &[("a/pom.xml", Err("still")), ("b/pom.xml", Ok(BASE))],
        )),
    );
    assert!(again.poms.is_empty(), "{:?}", again.edits);
    assert_eq!(reasons(&again), ["selection_undetermined"]);

    let warm = selecting(&after, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let second = planned(&after, Some(&warm));
    // (In the root: both modules select the version now.)
    assert_eq!(kinds(&second), [("pom.xml", HostedEditKind::Pin)]);
    assert!(reasons(&second).is_empty(), "{:?}", second.notes);
    let done = written(&after, &second);
    assert_unwires_to(&done, &files);
    let third = planned(&done, Some(&warm));
    assert!(third.poms.is_empty() && third.wired, "{:?}", third.edits);
}

/// A pin that now reaches a module resolving another version is taken out
/// again (it would hold that module back), leaving the pom as it was
/// before the pin.
#[test]
fn a_pin_that_would_move_a_module_is_taken_out() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let both = selecting(&files, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let pinned = written(&files, &planned(&files, Some(&both)));
    assert!(pinned["pom.xml"].contains(TAG));

    let moved = selecting(
        &pinned,
        &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok("1.11.0"))],
    );
    let plan = planned(&pinned, Some(&moved));
    assert_eq!(
        kinds(&plan),
        [
            ("pom.xml", HostedEditKind::PinRemoved),
            ("a/pom.xml", HostedEditKind::Pin)
        ]
    );
    assert!(
        !plan.poms["pom.xml"].contains(SV) && plan.poms["pom.xml"].contains("<repository>"),
        "the pin goes from the root, the repository a still needs stays"
    );
    let after = written(&pinned, &plan);
    assert_invariant(&after);
    assert_unwires_to(&after, &files);

    // No module selects the version any more: the last pin goes, and the
    // repository with it, so nothing of the patch is left to roll back.
    let none = selecting(
        &after,
        &[("a/pom.xml", Ok("1.11.0")), ("b/pom.xml", Ok("1.11.0"))],
    );
    let plan = planned(&after, Some(&none));
    assert_eq!(kinds(&plan), [("a/pom.xml", HostedEditKind::PinRemoved)]);
    assert_eq!(
        repositories(&plan),
        [("pom.xml", HostedEditKind::RepositoryRemoved)]
    );
    assert!(plan.unnamed && !plan.wired);
    assert_eq!(written(&after, &plan), files, "as before the first scan");
}

/// A pin of an earlier patch of the same version moves to this patch
/// where it stands.
#[test]
fn a_pin_of_an_earlier_patch_moves_to_this_one() {
    let files = fs(&[("pom.xml", &single(&deps(&dep(A, None))))]);
    let selection = selecting(&files, &[("pom.xml", Ok(BASE))]);
    let pinned = written(&files, &planned(&files, Some(&selection)));
    let earlier = fs(&[(
        "pom.xml",
        &pinned["pom.xml"]
            .replace(UUID, "0a1b2c3d-8192-4a3b-9c4d-5e6f708192a3")
            .replace(SV, "1.10.0-socket.0a1b2c3d"),
    )]);
    let plan = planned(&earlier, Some(&selection));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::PinMoved)]);
    assert_eq!(
        repositories(&plan),
        [
            ("pom.xml", HostedEditKind::Repository),
            ("pom.xml", HostedEditKind::RepositoryRemoved)
        ]
    );
    assert_eq!(plan.superseded, ["1.10.0-socket.0a1b2c3d"]);
    assert_eq!(plan.poms["pom.xml"], pinned["pom.xml"]);
}

/// An edit that could not be taken back exactly is not made: a pin in a
/// `<dependencyManagement>` that holds nothing would leave the section
/// changed (or gone) once removed.
#[test]
fn a_pin_that_could_not_be_removed_without_a_trace_is_not_written() {
    for management in [
        "  <dependencyManagement/>\n",
        "  <dependencyManagement><dependencies/></dependencyManagement>\n",
        "  <dependencyManagement>\n    <dependencies>\n    </dependencies>\n  \
         </dependencyManagement>\n",
    ] {
        let files = fs(&[(
            "pom.xml",
            &single(&format!("{management}{}", deps(&dep(A, None)))),
        )]);
        let plan = planned(&files, Some(&selecting(&files, &[("pom.xml", Ok(BASE))])));
        assert!(
            plan.poms.is_empty() && !plan.wired,
            "{management}: {:?}",
            plan.poms
        );
        assert_eq!(reasons(&plan), ["edit_not_reversible"], "{management}");
    }
}

/// Unwiring takes out one patch's wiring and leaves another's, and leaves
/// a plain suffixed declaration to the caller when asked to.
#[test]
fn unwiring_takes_out_only_what_it_is_asked_for() {
    let files = fs(&[(
        "pom.xml",
        &single(&format!(
            "{}{}",
            properties(&[("lib.version", BASE)]),
            deps(&format!(
                "{}{}",
                dep(A, Some("${lib.version}")),
                dep("sibling", Some("${lib.version}"))
            ))
        )),
    )]);
    let selection = selecting(&files, &[("pom.xml", Ok(BASE))]);
    let after = written(&files, &planned(&files, Some(&selection)));
    let other = Coords {
        uuid: "0a1b2c3d-8192-4a3b-9c4d-5e6f708192a3",
        ..coords()
    };
    assert_eq!(
        unwire_hosted(&after["pom.xml"], &other, false, true).as_deref(),
        Ok(after["pom.xml"].as_str())
    );
    let unwired = unwire_hosted(&after["pom.xml"], &other, true, true).unwrap();
    assert!(
        !unwired.contains(SV)
            && !unwired.contains(ORIGINAL_TAG)
            && unwired.matches("<version>${lib.version}</version>").count() == 2,
        "{unwired}"
    );

    let literal = single(&deps(&dep(A, Some(SV))));
    assert_eq!(
        unwire_hosted(&literal, &coords(), false, false).as_deref(),
        Ok(literal.as_str())
    );
    assert_eq!(
        unwire_hosted(&literal, &coords(), false, true),
        Ok(literal.replace(SV, BASE))
    );
}

/// What the poms build at a suffixed version is found wherever it is
/// wired: a declaration, a property a declaration of another pom reads,
/// or a pin, which names its patch.
#[test]
fn the_wiring_of_a_reactor_is_found_in_every_pom_that_carries_it() {
    let files = fs(&[
        ("pom.xml", &root(&properties(&[("victim.version", BASE)]))),
        (
            "a/pom.xml",
            &module("a", &dep(A, Some("${victim.version}"))),
        ),
        ("b/pom.xml", &module("b", &dep(A, Some(BASE)))),
    ]);
    let selection = selecting(&files, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let after = written(&files, &planned(&files, Some(&selection)));
    let sites = |files: &Fs| reactor(files).sites();
    let site = |uuid: Option<&str>, rels: &[&str]| HostedSite {
        group: G.to_string(),
        artifact: A.to_string(),
        suffixed: SV.to_string(),
        uuid: uuid.map(str::to_string),
        rels: rels.iter().map(|rel| rel.to_string()).collect(),
    };
    assert_eq!(
        sites(&after),
        [site(None, &["b/pom.xml", "pom.xml"])],
        "the property in the root, the declaration in b: {after:#?}"
    );
    assert!(sites(&files).is_empty());

    let pinned = fs(&[("pom.xml", &single(&deps(&dep(A, None))))]);
    let selection = selecting(&pinned, &[("pom.xml", Ok(BASE))]);
    let pinned = written(&pinned, &planned(&pinned, Some(&selection)));
    assert_eq!(sites(&pinned), [site(Some(UUID), &["pom.xml"])]);
}

/// A declaration Maven reads only while a profile is active wires
/// nothing on its own: rewriting it would name a version no build is
/// certain to resolve and no discovery reads, with no repository to serve
/// it. The plan is refused whole, and the reactor is as it was read.
#[test]
fn a_declaration_only_a_profile_holds_is_not_rewritten_alone() {
    let profiled = format!(
        "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <parent>\n    <groupId>t</groupId>\n    \
         <artifactId>root</artifactId>\n    <version>1</version>\n  </parent>\n  \
         <artifactId>a</artifactId>\n  <profiles>\n    <profile>\n      <id>extra</id>\n      \
         <dependencies>\n    {}      </dependencies>\n    </profile>\n  </profiles>\n</project>\n",
        dep(A, Some(BASE))
    );
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &profiled),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    for selection in [None, Some(selecting(&files, &[("b/pom.xml", Err("cold"))]))] {
        let mut reactor = reactor(&files);
        let plan = crate::patch::redirect::with_hosted_repository(
            &coords(),
            INDEX_URL,
            &BTreeMap::new(),
            true,
            |repository| reactor.plan(&coords(), selection.as_ref(), repository),
        );
        assert_eq!(
            plan.refused.as_ref().map(|(reason, _)| reason.as_str()),
            Some("nothing_wired"),
            "{:?}",
            plan.notes
        );
        assert!(plan.poms.is_empty() && plan.edits.is_empty() && !plan.wired);
        for (rel, text) in &files {
            assert_eq!(
                reactor.text(rel),
                Some(text.as_str()),
                "{rel} is as it was read"
            );
        }
    }
    // Beside a declaration Maven always reads, the profile's one is
    // rewritten with it: the repository then serves both.
    let both = fs(&[
        ("pom.xml", &root("")),
        (
            "a/pom.xml",
            &profiled.replace(
                "  <profiles>",
                &format!("{}  <profiles>", deps(&dep(A, Some(BASE)))),
            ),
        ),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let plan = planned(&both, None);
    assert!(plan.wired && plan.refused.is_none(), "{:?}", plan.refused);
    assert_eq!(plan.poms["a/pom.xml"].matches(SV).count(), 2);
    let after = written(&both, &plan);
    assert_invariant(&after);
    assert_unwires_to(&after, &both);
}

/// A plan is written whole or not at all. When the pom that must declare
/// the repository cannot take it, nothing is written: not the pin in the
/// module below, which would name a version nothing serves.
#[test]
fn a_plan_whose_repository_cannot_be_declared_writes_nothing() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep(A, Some(BASE)))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let selection = selecting(&files, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let mut reactor = reactor(&files);
    let plan = crate::patch::redirect::with_hosted_repository(
        &coords(),
        INDEX_URL,
        &BTreeMap::new(),
        true,
        |real| {
            let unreadable = HostedRepository {
                ensure: &|_| Err("not readable as a pom".to_string()),
                remove: real.remove,
                declared: real.declared,
                restored: real.restored,
            };
            reactor.plan(&coords(), Some(&selection), &unreadable)
        },
    );
    assert_eq!(
        plan.refused.as_ref().map(|(reason, _)| reason.as_str()),
        Some("repository_unwritable")
    );
    assert!(plan.poms.is_empty() && plan.edits.is_empty() && !plan.wired);
    for (rel, text) in &files {
        assert_eq!(
            reactor.text(rel),
            Some(text.as_str()),
            "{rel} is as it was read"
        );
    }

    // A `<repositories>` in a shape a rollback could not put back (a
    // self-closed one is expanded to take the repository) refuses the
    // plan the same way.
    let self_closed = fs(&[
        ("pom.xml", &root("  <repositories/>\n")),
        ("a/pom.xml", &module("a", &dep(A, Some(BASE)))),
        ("b/pom.xml", &module("b", &dep("lib-y", Some("1.0")))),
    ]);
    let plan = planned(&self_closed, Some(&selection));
    assert_eq!(
        plan.refused.as_ref().map(|(reason, _)| reason.as_str()),
        Some("edit_not_reversible"),
        "{:?}",
        plan.poms
    );
    assert!(plan.poms.is_empty());
}

/// An earlier patch's repository goes only once no pom of the reactor
/// names that patch's suffix: a pom this plan did not change counts. Here
/// module b still reads the earlier suffix through a property a profile
/// may redefine, which this plan leaves alone, while the pin moves on.
#[test]
fn an_earlier_patch_keeps_its_repository_while_any_pom_names_it() {
    const EARLIER: &str = "0a1b2c3d-8192-4a3b-9c4d-5e6f708192a3";
    const EARLIER_SV: &str = "1.10.0-socket.0a1b2c3d";
    let earlier = Coords {
        uuid: EARLIER,
        ..coords()
    };
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep("lib-x", Some("1.0")))),
        (
            "b/pom.xml",
            &module("b", &dep(A, Some("${victim.version}"))).replace(
                "  <dependencies>",
                &format!(
                    "{}  <dependencies>",
                    properties(&[("victim.version", BASE)])
                ),
            ),
        ),
    ]);
    let selection = selecting(&files, &[("a/pom.xml", Ok(BASE)), ("b/pom.xml", Ok(BASE))]);
    let first = planned_for(&files, &earlier, Some(&selection));
    assert!(first.wired, "{:?}", first.refused);
    let mut wired = written(&files, &first);
    assert!(wired["b/pom.xml"].contains(&format!("<victim.version>{EARLIER_SV}<")));
    assert!(
        wired["pom.xml"].contains(EARLIER_SV),
        "a is pinned, through the root: {:?}",
        first.edits
    );
    // b's property comes to be redefined by a profile: no later plan may
    // rewrite it, since the profile's build must keep its own version.
    let b = wired["b/pom.xml"].replace(
        "</project>",
        "  <profiles>\n    <profile>\n      <id>old</id>\n      <properties>\n        \
         <victim.version>1.9</victim.version>\n      </properties>\n    </profile>\n  \
         </profiles>\n</project>",
    );
    wired.insert("b/pom.xml".to_string(), b);

    // (b's declaration now rules the root out, so the pin is written
    // afresh below it; what matters here is what becomes of the earlier
    // patch's repository.)
    let plan = planned(&wired, Some(&selection));
    assert!(plan.wired, "{:?}", plan.refused);
    assert_eq!(
        repositories(&plan),
        [("pom.xml", HostedEditKind::Repository)]
    );
    assert!(
        plan.superseded.is_empty(),
        "b still names it: {:?}",
        plan.superseded
    );
    let after = written(&wired, &plan);
    assert!(
        after["pom.xml"].contains(&format!("socket-patch-{EARLIER}"))
            && after["pom.xml"].contains(&format!("socket-patch-{UUID}")),
        "both repositories serve a pom: {}",
        after["pom.xml"]
    );
    assert!(
        after["b/pom.xml"].contains(&format!("<victim.version>{EARLIER_SV}<"))
            && after["a/pom.xml"].contains(SV),
        "b keeps the version it reads, a moves on: {after:#?}"
    );
    assert_invariant(&after);

    // Once b moves on too, the earlier repository goes with its last use.
    let mut moved = after.clone();
    let b = moved["b/pom.xml"].replace(EARLIER_SV, SV);
    moved.insert("b/pom.xml".to_string(), b);
    moved.insert("pom.xml".to_string(), wired["pom.xml"].clone());
    let plan = planned(&moved, Some(&selection));
    assert_eq!(kinds(&plan), [("pom.xml", HostedEditKind::PinMoved)]);
    assert_eq!(plan.superseded, [EARLIER_SV]);
    let after = written(&moved, &plan);
    assert!(!after["pom.xml"].contains(EARLIER), "{}", after["pom.xml"]);
    assert_invariant(&after);
}

/// One reactor is read once and planned over for every patch of a run:
/// the second patch is planned over what the first wrote.
#[test]
fn every_patch_of_a_run_is_planned_over_one_reactor() {
    let files = fs(&[
        ("pom.xml", &root("")),
        ("a/pom.xml", &module("a", &dep(A, Some(BASE)))),
        ("b/pom.xml", &module("b", &dep("other", Some("2.0")))),
    ]);
    let other = Coords {
        group_id: G,
        artifact_id: "other",
        version: "2.0",
        uuid: "0a1b2c3d-8192-4a3b-9c4d-5e6f708192a3",
    };
    let mut reactor = reactor(&files);
    let mut all = files.clone();
    for c in [coords(), other] {
        let index_url = INDEX_URL.replace(UUID, c.uuid);
        let plan = crate::patch::redirect::with_hosted_repository(
            &c,
            &index_url,
            &BTreeMap::new(),
            true,
            |repository| reactor.plan(&c, None, repository),
        );
        assert!(plan.wired, "{:?}", plan.refused);
        all.extend(plan.poms);
    }
    for (rel, text) in &all {
        assert_eq!(reactor.text(rel), Some(text.as_str()), "{rel}");
    }
    assert!(
        all["pom.xml"].matches("<repository>").count() == 2
            && all["b/pom.xml"].contains("2.0-socket.0a1b2c3d")
    );
    assert_invariant(&all);
}
