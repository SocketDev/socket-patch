use super::*;

const G: &str = "org.x";
const A: &str = "victim";

fn write(root: &Path, rel: &str, body: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

fn dep(g: &str, a: &str, v: Option<&str>, extra: &str) -> String {
    let v = v.map_or(String::new(), |v| format!("<version>{v}</version>"));
    format!("<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>{v}{extra}</dependency>")
}

/// `org.x:<a>:<v>`.
fn x(a: &str, v: &str) -> String {
    dep(G, a, Some(v), "")
}

fn pom(g: &str, a: &str, v: &str, body: &str) -> String {
    format!(
        "<project><modelVersion>4.0.0</modelVersion><groupId>{g}</groupId>\
         <artifactId>{a}</artifactId><version>{v}</version>{body}</project>"
    )
}

fn deps(list: &[String]) -> String {
    format!("<dependencies>{}</dependencies>", list.concat())
}

fn managed(list: &[String]) -> String {
    format!(
        "<dependencyManagement><dependencies>{}</dependencies></dependencyManagement>",
        list.concat()
    )
}

/// Cache `org.x:<a>:<v>` in `repo` with `body` as its pom's extra content.
fn cache(repo: &Path, a: &str, v: &str, body: &str) {
    write(
        repo,
        &format!("org/x/{a}/{v}/{a}-{v}.pom"),
        &pom(G, a, v, body),
    );
}

/// The versions the repository's metadata lists for `org.x:<a>`.
fn list(repo: &Path, a: &str, versions: &[&str]) {
    let versions: String = versions
        .iter()
        .map(|v| format!("<version>{v}</version>"))
        .collect();
    write(
        repo,
        &format!("org/x/{a}/maven-metadata-central.xml"),
        &format!(
            "<metadata><groupId>{G}</groupId><artifactId>{a}</artifactId><versioning>\
             <versions>{versions}</versions></versioning></metadata>"
        ),
    );
}

struct Fixture {
    _dir: tempfile::TempDir,
    cwd: PathBuf,
    repo: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let (cwd, repo) = (dir.path().join("p"), dir.path().join("m2"));
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::create_dir_all(&repo).unwrap();
        Fixture {
            _dir: dir,
            cwd,
            repo,
        }
    }

    /// The single-module project `com.example:app:1` with `body`.
    fn app(&self, body: &str) -> &Fixture {
        write(&self.cwd, "pom.xml", &pom("com.example", "app", "1", body));
        self
    }

    fn cache(&self, a: &str, v: &str, list: &[String]) -> &Fixture {
        cache(&self.repo, a, v, &deps(list));
        self
    }

    fn select(&self) -> MavenSelection {
        MavenSelection::of(&self.cwd, &self.repo)
    }

    /// The verdict of the root module on the victim at `base`.
    fn verdict(&self, base: &str) -> Verdict {
        self.select().verdict("pom.xml", G, A, base)
    }
}

fn other(version: &str) -> Verdict {
    Verdict::Other(version.to_string())
}

fn undetermined(verdict: &Verdict) -> &str {
    match verdict {
        Verdict::Undetermined(why) => why,
        other => panic!("expected an undetermined verdict, got {other:?}"),
    }
}

/// The table's V1 and V2: the nearer declaration wins, older or newer.
#[test]
fn the_nearest_declaration_wins_whatever_its_version() {
    for nearer in ["2.9.10", "2.6.0"] {
        let f = Fixture::new();
        f.app(&deps(&[x("lib-x", "1.0"), x("lib-y", "1.0")]))
            .cache("lib-x", "1.0", &[x(A, nearer)])
            .cache("lib-y", "1.0", &[x("lib-a", "1.0")])
            .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
            .cache(A, nearer, &[])
            .cache(A, "2.7.9.2", &[]);
        assert_eq!(f.verdict("2.7.9.2"), other(nearer));
        assert_eq!(f.verdict(nearer), Verdict::Selected);
        assert_eq!(
            f.select().standing(G, A, "2.7.9.2"),
            Standing::NotSelected(vec![nearer.to_string()])
        );
    }
}

#[test]
fn the_first_declaration_wins_a_tie() {
    for (first, second, wins) in [("lib-x", "lib-a", "2.9.10"), ("lib-a", "lib-x", "2.7.9.2")] {
        let f = Fixture::new();
        f.app(&deps(&[x(first, "1.0"), x(second, "1.0")]))
            .cache("lib-x", "1.0", &[x(A, "2.9.10")])
            .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
            .cache(A, "2.9.10", &[])
            .cache(A, "2.7.9.2", &[]);
        assert_eq!(f.verdict(wins), Verdict::Selected, "{first} first");
    }
}

/// The table's V4: a direct declaration is the nearest there is, and
/// management does not override it.
#[test]
fn a_direct_declaration_beats_management_and_transitives() {
    let f = Fixture::new();
    f.app(&format!(
        "{}{}",
        managed(&[x(A, "2.8.0")]),
        deps(&[x("lib-a", "1.0"), x(A, "2.9.10")])
    ))
    .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
    .cache(A, "2.9.10", &[])
    .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.9.10"), Verdict::Selected);
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));
}

#[test]
fn management_sets_a_versionless_declaration_and_every_transitive() {
    // The module's own management.
    let f = Fixture::new();
    f.app(&format!(
        "{}{}",
        managed(&[x(A, "2.9.10")]),
        deps(&[x("lib-a", "1.0")])
    ))
    .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
    .cache(A, "2.9.10", &[]);
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));

    // A version-less direct declaration.
    let f = Fixture::new();
    f.app(&format!(
        "{}{}",
        managed(&[x(A, "2.7.9.2")]),
        deps(&[dep(G, A, None, "")])
    ))
    .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected);

    // An imported BOM, and a parent from the repository; the parent's own
    // entry beats the import.
    let f = Fixture::new();
    write(
        &f.cwd,
        "pom.xml",
        &format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>{G}</groupId>\
             <artifactId>corp-parent</artifactId><version>3</version><relativePath/></parent>\
             <artifactId>app</artifactId>{}{}</project>",
            managed(&[dep(
                G,
                "bom",
                Some("1"),
                "<type>pom</type><scope>import</scope>"
            )]),
            deps(&[x("lib-a", "1.0"), x("lib-b", "1.0")])
        ),
    );
    cache(&f.repo, "corp-parent", "3", &managed(&[x(A, "2.9.10")]));
    cache(
        &f.repo,
        "bom",
        "1",
        &managed(&[x(A, "2.8.0"), x("other", "5")]),
    );
    f.cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
        .cache("lib-b", "1.0", &[x("other", "4")])
        .cache(A, "2.9.10", &[])
        .cache("other", "5", &[]);
    let selection = f.select();
    assert_eq!(
        selection.verdict("pom.xml", G, A, "2.7.9.2"),
        other("2.9.10")
    );
    assert_eq!(
        selection.verdict("pom.xml", G, "other", "5"),
        Verdict::Selected
    );
}

/// The table's V6: what an `<exclusion>` removes is not a declaration.
#[test]
fn an_excluded_declaration_does_not_count() {
    for exclusion in [
        format!("<exclusion><groupId>{G}</groupId><artifactId>{A}</artifactId></exclusion>"),
        "<exclusion><groupId>*</groupId><artifactId>*</artifactId></exclusion>".to_string(),
    ] {
        let excluded = dep(
            G,
            "lib-y",
            Some("1.0"),
            &format!("<exclusions>{exclusion}</exclusions>"),
        );
        // Another path still brings the artifact in, deeper.
        let f = Fixture::new();
        f.app(&deps(&[excluded.clone(), x("lib-w", "1.0")]))
            .cache("lib-y", "1.0", &[x(A, "2.7.9.2")])
            .cache("lib-w", "1.0", &[x("lib-x", "1.0")])
            .cache("lib-x", "1.0", &[x(A, "2.9.10")])
            .cache(A, "2.9.10", &[])
            .cache(A, "2.7.9.2", &[]);
        assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));

        // No other path: the module does not resolve it at all.
        let f = Fixture::new();
        f.app(&deps(&[excluded]))
            .cache("lib-y", "1.0", &[x(A, "2.7.9.2")]);
        assert_eq!(f.verdict("2.7.9.2"), Verdict::Absent);
        assert_eq!(
            f.select().standing(G, A, "2.7.9.2"),
            Standing::NotSelected(Vec::new())
        );
    }
}

#[test]
fn an_exclusion_holds_for_everything_below_its_declaration() {
    let f = Fixture::new();
    f.app(&deps(&[dep(
        G,
        "lib-y",
        Some("1.0"),
        &format!(
            "<exclusions><exclusion><groupId>{G}</groupId><artifactId>{A}</artifactId>\
             </exclusion></exclusions>"
        ),
    )]))
    .cache("lib-y", "1.0", &[x("lib-a", "1.0")])
    .cache("lib-a", "1.0", &[x("lib-b", "1.0"), x(A, "2.7.9.2")])
    .cache("lib-b", "1.0", &[x(A, "2.7.9.2")]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Absent);
}

#[test]
fn optional_test_and_provided_transitives_are_not_followed() {
    for extra in [
        "<optional>true</optional>",
        "<scope>test</scope>",
        "<scope>provided</scope>",
    ] {
        let f = Fixture::new();
        f.app(&deps(&[x("lib-a", "1.0")])).cache(
            "lib-a",
            "1.0",
            &[dep(G, A, Some("2.7.9.2"), extra)],
        );
        assert_eq!(f.verdict("2.7.9.2"), Verdict::Absent, "{extra}");

        // The module's own declaration of any scope is resolved.
        let f = Fixture::new();
        f.app(&deps(&[dep(G, A, Some("2.7.9.2"), extra)]))
            .cache(A, "2.7.9.2", &[]);
        assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected, "{extra}");
    }
    // A scope the artifact's own management gives a version-less
    // declaration counts too.
    let f = Fixture::new();
    f.app(&deps(&[x("lib-a", "1.0")]));
    cache(
        &f.repo,
        "lib-a",
        "1.0",
        &format!(
            "{}{}",
            managed(&[dep(G, A, Some("2.7.9.2"), "<scope>test</scope>")]),
            deps(&[dep(G, A, None, "")])
        ),
    );
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Absent);
}

/// What a losing version depends on is not part of the graph: `lib-c`
/// 1.0 sits nearer, but under the `lib-b` version that lost.
#[test]
fn what_a_losing_version_depends_on_leaves_the_graph() {
    let f = Fixture::new();
    f.app(&deps(&[
        x("lib-a", "1.0"),
        x("lib-b", "2.0"),
        x("lib-e", "1.0"),
    ]))
    .cache("lib-a", "1.0", &[x("lib-b", "1.0")])
    .cache("lib-b", "1.0", &[x(A, "2.7.9.2")])
    .cache("lib-b", "2.0", &[])
    .cache("lib-e", "1.0", &[x("lib-f", "1.0")])
    .cache("lib-f", "1.0", &[x("lib-g", "1.0")])
    .cache("lib-g", "1.0", &[x(A, "2.9.10")])
    .cache(A, "2.9.10", &[])
    .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));
    assert_eq!(f.verdict("2.9.10"), Verdict::Selected);
}

/// The table's V7: a range selects the highest version in it the cached
/// metadata lists, whatever else the local repository holds.
#[test]
fn a_range_selects_the_highest_listed_version_in_it() {
    let f = Fixture::new();
    f.app(&deps(&[x("lib-r", "1.0")]))
        .cache("lib-r", "1.0", &[x(A, "[2.9.0,2.9.10]")])
        .cache(A, "2.7.9.2", &[])
        .cache(A, "2.9.0", &[])
        .cache(A, "2.9.10", &[]);
    // No metadata: the range cannot be resolved.
    undetermined(&f.verdict("2.7.9.2"));
    list(&f.repo, A, &["2.7.9.2", "2.9.0", "2.9.10", "2.10.0"]);
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));
    assert_eq!(f.verdict("2.9.0"), other("2.9.10"));
    // A pin of the selected version would freeze the range: never certain.
    assert!(undetermined(&f.verdict("2.9.10")).contains("version range"));
}

#[test]
fn an_exact_requirement_is_one_version() {
    let f = Fixture::new();
    f.app(&deps(&[x("lib-r", "1.0")]))
        .cache("lib-r", "1.0", &[x(A, "[2.7.9.2]")])
        .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected);
}

/// A range is a hard requirement: the nearer plain version outside it
/// gives way to the nearest version every range admits.
#[test]
fn a_range_overrules_a_nearer_version_outside_it() {
    let f = Fixture::new();
    f.app(&deps(&[x("lib-a", "1.0"), x("lib-y", "1.0")]))
        .cache("lib-a", "1.0", &[x(A, "1.0")])
        .cache("lib-y", "1.0", &[x("lib-r", "1.0")])
        .cache("lib-r", "1.0", &[x(A, "[2.0,3.0)")])
        .cache(A, "1.0", &[])
        .cache(A, "2.5", &[]);
    list(&f.repo, A, &["1.0", "2.5", "3.0"]);
    assert_eq!(f.verdict("1.0"), other("2.5"));

    // Two ranges with nothing in common: Maven fails the build.
    let f = Fixture::new();
    f.app(&deps(&[x("lib-a", "1.0"), x("lib-r", "1.0")]))
        .cache("lib-a", "1.0", &[x(A, "[1.0]")])
        .cache("lib-r", "1.0", &[x(A, "[2.0,3.0)")])
        .cache(A, "1.0", &[])
        .cache(A, "2.5", &[]);
    list(&f.repo, A, &["1.0", "2.5"]);
    undetermined(&f.verdict("1.0"));
}

/// The table's V5 for a project that was never resolved: a pom missing
/// from the local repository leaves everything at its depth or deeper
/// undetermined, and nothing nearer.
#[test]
fn a_missing_pom_leaves_only_what_it_could_change_undetermined() {
    let f = Fixture::new();
    f.app(&deps(&[
        x("lib-x", "1.0"),
        x("never-resolved", "1.0"),
        x("direct", "1.0"),
    ]))
    .cache("lib-x", "1.0", &[x(A, "2.9.10")])
    .cache(A, "2.9.10", &[])
    .cache("direct", "1.0", &[]);
    let why = f.verdict("2.9.10");
    assert!(
        undetermined(&why).contains("never-resolved"),
        "names the missing pom: {why:?}"
    );
    let selection = f.select();
    assert_eq!(
        selection.verdict("pom.xml", G, "direct", "1.0"),
        Verdict::Selected
    );
    undetermined(&selection.verdict("pom.xml", G, "absent", "1.0"));
    assert!(matches!(
        selection.standing(G, A, "2.7.9.2"),
        Standing::Undetermined(_)
    ));
}

#[test]
fn a_version_the_poms_do_not_define_is_undetermined() {
    // The nearest declaration reads an undefined property.
    let f = Fixture::new();
    f.app(&deps(&[x("lib-a", "1.0")]))
        .cache("lib-a", "1.0", &[x(A, "${nowhere}")]);
    assert!(undetermined(&f.verdict("2.7.9.2")).contains("${nowhere}"));

    // A nearer declaration at a known version is certain all the same.
    let f = Fixture::new();
    f.app(&deps(&[x(A, "2.9.10"), x("lib-a", "1.0")]))
        .cache("lib-a", "1.0", &[x(A, "${nowhere}")])
        .cache(A, "2.9.10", &[]);
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));
}

#[test]
fn what_a_profile_may_change_is_undetermined() {
    // A profile redefines the property the version reads.
    let f = Fixture::new();
    f.app(&format!(
        "<properties><v>2.7.9.2</v></properties>{}<profiles><profile><id>p</id>\
         <properties><v>2.9.10</v></properties></profile></profiles>",
        deps(&[x(A, "${v}")])
    ))
    .cache(A, "2.7.9.2", &[]);
    assert!(undetermined(&f.verdict("2.7.9.2")).contains("profile"));

    // A profile declares dependencies of its own.
    let f = Fixture::new();
    f.app(&format!(
        "{}<profiles><profile><id>p</id>{}</profile></profiles>",
        deps(&[x("lib-a", "1.0")]),
        deps(&[x("lib-x", "1.0")])
    ))
    .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
    .cache(A, "2.7.9.2", &[]);
    assert!(undetermined(&f.verdict("2.7.9.2")).contains("profile"));

    // A profile manages the artifact.
    let f = Fixture::new();
    f.app(&format!(
        "{}<profiles><profile><id>p</id>{}</profile></profiles>",
        deps(&[x("lib-a", "1.0"), x("lib-b", "1.0")]),
        managed(&[x(A, "2.9.10")])
    ))
    .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
    .cache("lib-b", "1.0", &[x("other", "1")])
    .cache(A, "2.7.9.2", &[])
    .cache("other", "1", &[]);
    let selection = f.select();
    undetermined(&selection.verdict("pom.xml", G, A, "2.7.9.2"));
    assert_eq!(
        selection.verdict("pom.xml", G, "other", "1"),
        Verdict::Selected
    );
}

/// The table's V3: each module of a reactor has its own answer, and a
/// dependency on a sibling module reads the sibling's pom.
#[test]
fn each_module_of_a_reactor_has_its_own_selection() {
    let f = Fixture::new();
    write(
        &f.cwd,
        "pom.xml",
        &pom(
            "com.example",
            "parent",
            "1",
            "<packaging>pom</packaging><modules><module>a</module><module>b</module>\
             <module>c</module></modules>",
        ),
    );
    let module = |name: &str, list: &[String]| {
        format!(
            "<project><modelVersion>4.0.0</modelVersion><parent><groupId>com.example</groupId>\
             <artifactId>parent</artifactId><version>1</version></parent>\
             <artifactId>{name}</artifactId>{}</project>",
            deps(list)
        )
    };
    write(&f.cwd, "a/pom.xml", &module("a", &[x(A, "2.7.9.2")]));
    write(&f.cwd, "b/pom.xml", &module("b", &[x("lib-x", "1.0")]));
    write(
        &f.cwd,
        "c/pom.xml",
        &module(
            "c",
            &[
                dep("com.example", "a", Some("${project.version}"), ""),
                x("lib-w", "1.0"),
            ],
        ),
    );
    f.cache("lib-x", "1.0", &[x(A, "2.9.10")])
        .cache("lib-w", "1.0", &[x("lib-x", "1.0")])
        .cache(A, "2.9.10", &[])
        .cache(A, "2.7.9.2", &[]);
    let selection = f.select();
    assert_eq!(
        selection.modules().collect::<Vec<_>>(),
        ["a/pom.xml", "b/pom.xml", "c/pom.xml", "pom.xml"]
    );
    assert_eq!(
        selection.verdict("a/pom.xml", G, A, "2.7.9.2"),
        Verdict::Selected
    );
    assert_eq!(
        selection.verdict("b/pom.xml", G, A, "2.7.9.2"),
        other("2.9.10")
    );
    // Through the sibling module, nearer than lib-w's path.
    assert_eq!(
        selection.verdict("c/pom.xml", G, A, "2.7.9.2"),
        Verdict::Selected
    );
    assert_eq!(
        selection.verdict("pom.xml", G, A, "2.7.9.2"),
        Verdict::Absent
    );
    assert_eq!(selection.standing(G, A, "2.7.9.2"), Standing::Selected);
    assert_eq!(selection.standing(G, A, "2.9.10"), Standing::Selected);
    undetermined(&selection.verdict("d/pom.xml", G, A, "2.7.9.2"));
}

/// An earlier run's wiring reads as the version it replaced: a suffixed
/// literal is its base version (its pom is the base's), and a pin
/// vendoring wrote is not the project's management.
#[test]
fn earlier_wiring_reads_as_the_project_without_it() {
    let f = Fixture::new();
    f.app(&deps(&[x(A, "2.7.9.2-socket.8e82692a")]))
        .cache(A, "2.7.9.2", &[x("below", "1")])
        .cache("below", "1", &[]);
    let selection = f.select();
    assert_eq!(
        selection.verdict("pom.xml", G, A, "2.7.9.2"),
        Verdict::Selected
    );
    assert_eq!(
        selection.verdict("pom.xml", G, "below", "1"),
        Verdict::Selected
    );

    let f = Fixture::new();
    f.app(&format!(
        "<dependencyManagement><dependencies>\n\
         <!-- socket-patch 8e82692a-a5bd-40ac-97a7-4f1483449fd6: {G}:{A}:2.7.9.2 -->\n\
         {}</dependencies></dependencyManagement>{}",
        x(A, "2.7.9.2-socket.8e82692a"),
        deps(&[x("lib-x", "1.0"), x("lib-y", "1.0")])
    ))
    .cache("lib-x", "1.0", &[x(A, "2.9.10")])
    .cache("lib-y", "1.0", &[x("lib-a", "1.0")])
    .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
    .cache(A, "2.9.10", &[])
    .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));
}

#[test]
fn a_dependency_cycle_is_undetermined_and_only_below_it() {
    let f = Fixture::new();
    f.app(&deps(&[x("free", "1"), x("lib-a", "1.0")]))
        .cache("free", "1", &[])
        .cache("lib-a", "1.0", &[x("lib-b", "1.0")])
        .cache("lib-b", "1.0", &[x("lib-a", "2.0"), x(A, "2.7.9.2")])
        .cache("lib-a", "2.0", &[])
        .cache(A, "2.7.9.2", &[]);
    let selection = f.select();
    assert!(undetermined(&selection.verdict("pom.xml", G, A, "2.7.9.2")).contains("cycle"));
    assert_eq!(
        selection.verdict("pom.xml", G, "free", "1"),
        Verdict::Selected
    );
}

#[test]
fn a_relocated_artifact_is_undetermined() {
    let f = Fixture::new();
    f.app(&deps(&[x(A, "2.7.9.2")]));
    cache(
        &f.repo,
        A,
        "2.7.9.2",
        "<distributionManagement><relocation><artifactId>victim-ng</artifactId></relocation>\
         </distributionManagement>",
    );
    assert!(undetermined(&f.verdict("2.7.9.2")).contains("relocated"));
}

#[test]
fn command_line_properties_win_in_the_projects_own_poms() {
    let f = Fixture::new();
    f.app(&format!(
        "<properties><v>2.7.9.2</v></properties>{}",
        deps(&[x(A, "${v}")])
    ))
    .cache(A, "2.9.10", &[])
    .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected);
    write(&f.cwd, ".mvn/maven.config", "-Dv=2.9.10\n");
    assert_eq!(f.verdict("2.7.9.2"), other("2.9.10"));
}

#[test]
fn a_project_that_cannot_be_modelled_is_undetermined_everywhere() {
    // No readable root pom.
    let f = Fixture::new();
    undetermined(&f.verdict("2.7.9.2"));
    assert!(matches!(
        f.select().standing(G, A, "2.7.9.2"),
        Standing::Undetermined(_)
    ));

    // A Maven 4 build.
    let f = Fixture::new();
    f.app(&deps(&[x(A, "2.7.9.2")])).cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected);
    write(
        &f.cwd,
        ".mvn/wrapper/maven-wrapper.properties",
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/4.0.0/apache-maven-4.0.0-bin.zip\n",
    );
    assert!(undetermined(&f.verdict("2.7.9.2")).contains("Maven 4"));

    assert!(matches!(
        MavenSelection::unavailable("why").verdict("pom.xml", G, A, "1"),
        Verdict::Undetermined(why) if why == "why"
    ));
}

#[test]
fn the_lines_name_what_maven_selects() {
    assert_eq!(
        not_selected_detail(G, A, "2.7.9.2", &["2.9.10".to_string()]),
        "Maven selects org.x:victim 2.9.10 in this build, not 2.7.9.2, so the patch for 2.7.9.2 \
         has nothing to patch here"
    );
    assert!(not_selected_detail(G, A, "2.7.9.2", &[]).starts_with("no module of this build"));
    assert!(undetermined_detail(G, A, "2.7.9.2", "why").contains("mvn -q dependency:resolve"));
}

#[test]
fn metadata_lists_its_versions() {
    assert_eq!(
        metadata_versions(
            "<metadata><version>9</version><versioning><latest>2</latest><versions>\n\
             <version>1.0</version>\n<version> 2 </version></versions></versioning></metadata>"
        ),
        ["1.0", "2"]
    );
    assert!(metadata_versions("<metadata/>").is_empty());
}

/// A `system` dependency is a file on the machine: Maven reads no pom for
/// it, so its missing pom leaves nothing undetermined.
#[test]
fn a_system_dependency_has_nothing_below_it() {
    let f = Fixture::new();
    f.app(&deps(&[
        dep(
            "com.sun",
            "tools",
            Some("1.8"),
            "<scope>system</scope><systemPath>${java.home}/../lib/tools.jar</systemPath>",
        ),
        x("lib-a", "1.0"),
    ]))
    .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
    .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected);
}

/// A declaration Maven follows only from the module that makes it (an
/// optional or test one) says nothing about a build that merely depends on
/// that artifact, even when its coordinates cannot be read.
#[test]
fn an_unreadable_optional_declaration_matters_only_to_its_own_module() {
    let unreadable = dep(
        G,
        "native",
        Some("1"),
        "<classifier>${os.detected.classifier}</classifier><optional>true</optional>",
    );
    let f = Fixture::new();
    f.app(&deps(&[x("lib-a", "1.0")]))
        .cache("lib-a", "1.0", &[unreadable.clone(), x(A, "2.7.9.2")])
        .cache(A, "2.7.9.2", &[]);
    assert_eq!(f.verdict("2.7.9.2"), Verdict::Selected);

    let f = Fixture::new();
    f.app(&deps(&[unreadable, x("lib-a", "1.0")]))
        .cache("lib-a", "1.0", &[x(A, "2.7.9.2")])
        .cache(A, "2.7.9.2", &[]);
    undetermined(&f.verdict("2.7.9.2"));
}

/// A module the reactor names and that cannot be read is a part of the
/// build nothing is known about: the modules that were read keep their
/// answers, and no answer covers the whole build.
#[test]
fn a_module_that_cannot_be_read_leaves_the_build_undetermined() {
    let f = Fixture::new();
    write(
        &f.cwd,
        "pom.xml",
        &pom(
            "com.example",
            "parent",
            "1",
            "<packaging>pom</packaging><modules><module>a</module><module>gone</module></modules>",
        ),
    );
    write(
        &f.cwd,
        "a/pom.xml",
        &pom("com.example", "a", "1", &deps(&[x("lib-x", "1.0")])),
    );
    f.cache("lib-x", "1.0", &[x(A, "2.9.10")])
        .cache(A, "2.9.10", &[]);
    let selection = f.select();
    assert_eq!(
        selection.verdict("a/pom.xml", G, A, "2.7.9.2"),
        other("2.9.10")
    );
    assert_eq!(selection.standing(G, A, "2.9.10"), Standing::Selected);
    match selection.standing(G, A, "2.7.9.2") {
        Standing::Undetermined(why) => assert!(why.contains("gone"), "{why}"),
        other => panic!("{other:?}"),
    }
}
