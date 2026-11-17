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

fn planned(files: &Fs, selection: Option<&MavenSelection>) -> HostedPlan {
    let read = |rel: &str| files.get(rel).map(|text| text.clone().into_bytes());
    let list = |dir: &str| {
        let bytes: BTreeMap<String, Vec<u8>> = files
            .iter()
            .map(|(rel, text)| (rel.clone(), text.clone().into_bytes()))
            .collect();
        crate::vendor::jvm::testing::list_of(&bytes, dir)
    };
    plan_hosted(&read, &list, &coords(), selection).expect("a plan")
}

fn written(files: &Fs, plan: &HostedPlan) -> Fs {
    let mut out = files.clone();
    out.extend(plan.poms.clone());
    out
}

/// Every pom of `after` unwired again, which must be `before`.
fn assert_unwires_to(after: &Fs, before: &Fs) {
    for (rel, text) in after {
        assert_eq!(
            unwire_hosted(text, &coords(), false, true).as_deref(),
            Ok(before[rel].as_str()),
            "{rel}"
        );
    }
}

fn kinds(plan: &HostedPlan) -> Vec<(&str, HostedEditKind)> {
    plan.edits
        .iter()
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
    assert_eq!(plan.roots, ["pom.xml"]);
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
    assert_eq!(
        plan.poms["pom.xml"],
        files["pom.xml"].replace(
            "<victim.version>1.10.0</victim.version>",
            &format!("<victim.version>{SV}</victim.version>")
        )
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
    assert_eq!(
        *pom,
        files["pom.xml"].replacen(
            "<version>${lib.version}</version>",
            &format!("<version>{SV}</version><!-- socket-patch:version ${{lib.version}} -->"),
            1
        )
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
    assert_eq!(plan.poms["pom.xml"], files["pom.xml"]);
    assert_unwires_to(&written(&pinned, &plan), &files);
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
    assert_eq!(
        unwire_hosted(&after["pom.xml"], &other, true, true).as_deref(),
        Ok(files["pom.xml"].as_str())
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
    let sites = |files: &Fs| {
        let read = |rel: &str| files.get(rel).map(|text| text.clone().into_bytes());
        hosted_sites(&read, &|_| Vec::new()).unwrap()
    };
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
