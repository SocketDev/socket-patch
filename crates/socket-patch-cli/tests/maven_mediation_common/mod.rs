//! The dependency graphs the mediation capstones build with a real Maven
//! (`e2e_redirect_maven_build` hosted, `e2e_vendor_maven_build` vendored
//! and agent): a pin must follow the version Maven selects, never move it.
//!
//! Every artifact is generated here and served by the test's own wiremock
//! server as a plain maven2 repository the project pom names (`fixture`),
//! so no shape needs Maven Central for anything but the dependency plugin
//! the suites already fetch:
//!
//! * `victim:{1.9,1.10.0,1.11.0}`: the patched artifact; the patch is for
//!   [`BASE`] and rewrites [`MEMBER`].
//! * `lib-base:1.0` → `victim:1.10.0`, `lib-new:1.0` → `victim:1.11.0`,
//!   `lib-old:1.0` → `victim:1.9`, `lib-deep:1.0` → `lib-base:1.0`,
//!   `lib-range:1.0` → `victim:[1.10.5,1.11.0]`.
//! * the artifact-level `maven-metadata.xml` of `victim`, which resolves
//!   the range.
//!
//! One [`Shape`] per row of the bug: which version Maven selects for the
//! victim, with the base version somewhere else in the graph (deeper,
//! excluded, or only in the local repository).

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::Path;
use std::process::Output;

use crate::hosted_maven_common::{sha1_hex, Server};
use crate::maven_build_common::{
    dump, ok, with_central_fallback, write_settings, Mvn, DEPENDENCY_PLUGIN,
};

pub const GROUP: &str = "com.socketfixture.mediation";
pub const GROUP_PATH: &str = "com/socketfixture/mediation";
pub const VICTIM: &str = "victim";
/// The version the patch is for.
pub const BASE: &str = "1.10.0";
pub const OLDER: &str = "1.9";
pub const NEWER: &str = "1.11.0";
/// The jar member the patch rewrites.
pub const MEMBER: &str = "META-INF/NOTICE.txt";
pub const MARKER: &str = "SOCKET-PATCH-MEDIATION-MARKER";
/// Where the server serves the fixture repository.
const REPO_ROUTE: &str = "/fixture-repo";

pub fn purl() -> String {
    format!("pkg:maven/{GROUP}/{VICTIM}@{BASE}")
}

/// How a project reaches the victim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// The base version is the only one in the graph, two levels down.
    Selected,
    /// V1: a newer version is nearer the root, the base version deeper.
    NearerNewer,
    /// V2: an older version is nearer the root, the base version deeper.
    NearerOlder,
    /// V4: the project declares another version itself.
    DirectOther,
    /// V6: the only path to the base version is excluded.
    Excluded,
    /// V7: no pom of the build names the base version; a range selects
    /// another one, and the base is merely in the local repository.
    Ranged,
}

impl Shape {
    pub fn name(self) -> &'static str {
        match self {
            Shape::Selected => "selected",
            Shape::NearerNewer => "nearer-newer",
            Shape::NearerOlder => "nearer-older",
            Shape::DirectOther => "direct-other",
            Shape::Excluded => "excluded",
            Shape::Ranged => "ranged",
        }
    }

    /// The victim version Maven selects.
    pub fn selects(self) -> &'static str {
        match self {
            Shape::Selected => BASE,
            Shape::NearerOlder => OLDER,
            _ => NEWER,
        }
    }

    fn dependencies(self) -> String {
        let exclusion = format!(
            "\n      <exclusions>\n        <exclusion>\n          <groupId>{GROUP}</groupId>\n          \
             <artifactId>{VICTIM}</artifactId>\n        </exclusion>\n      </exclusions>"
        );
        match self {
            Shape::Selected => dependency("lib-deep", "1.0", ""),
            Shape::NearerNewer => [
                dependency("lib-new", "1.0", ""),
                dependency("lib-deep", "1.0", ""),
            ]
            .concat(),
            Shape::NearerOlder => [
                dependency("lib-old", "1.0", ""),
                dependency("lib-deep", "1.0", ""),
            ]
            .concat(),
            Shape::DirectOther => [
                dependency("lib-base", "1.0", ""),
                dependency(VICTIM, NEWER, ""),
            ]
            .concat(),
            // Declared first: without the exclusion the base version would
            // win the tie with lib-new's.
            Shape::Excluded => [
                dependency("lib-base", "1.0", &exclusion),
                dependency("lib-new", "1.0", ""),
            ]
            .concat(),
            Shape::Ranged => dependency("lib-range", "1.0", ""),
        }
    }
}

/// One `<dependency>` on a fixture artifact, as the project poms write it.
pub fn dependency(artifact: &str, version: &str, extra: &str) -> String {
    format!(
        "    <dependency>\n      <groupId>{GROUP}</groupId>\n      \
         <artifactId>{artifact}</artifactId>\n      <version>{version}</version>{extra}\n    \
         </dependency>\n"
    )
}

/// The pom of fixture artifact `artifact:version` depending on `deps`.
fn fixture_pom(artifact: &str, version: &str, deps: &[(&str, &str)]) -> String {
    let deps: String = deps.iter().map(|(a, v)| dependency(a, v, "")).collect();
    let deps = match deps.is_empty() {
        true => String::new(),
        false => format!("  <dependencies>\n{deps}  </dependencies>\n"),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>{GROUP}</groupId>\n  \
         <artifactId>{artifact}</artifactId>\n  <version>{version}</version>\n{deps}</project>\n"
    )
}

/// The upstream pom of the victim at `version`.
pub fn victim_pom(version: &str) -> String {
    fixture_pom(VICTIM, version, &[])
}

/// The pom the Socket repository serves for the patched victim: the
/// upstream pom at the suffixed version.
pub fn served_victim_pom(suffixed: &str) -> String {
    victim_pom(BASE).replace(
        &format!("<version>{BASE}</version>"),
        &format!("<version>{suffixed}</version>"),
    )
}

/// What [`MEMBER`] holds in the pristine jar of `artifact:version`.
pub fn pristine_member(artifact: &str, version: &str) -> Vec<u8> {
    format!("Socket mediation fixture: {GROUP}:{artifact}:{version}\n").into_bytes()
}

/// What the patch makes of the base victim's [`MEMBER`].
pub fn patched_member() -> Vec<u8> {
    patched_member_of(BASE)
}

/// What a patch of the victim at `version` makes of its [`MEMBER`].
pub fn patched_member_of(version: &str) -> Vec<u8> {
    let mut out = pristine_member(VICTIM, version);
    out.extend_from_slice(format!("{MARKER}\n").as_bytes());
    out
}

/// A jar holding [`MEMBER`] with `member` (stored, fixed timestamp).
pub fn jar(member: &[u8]) -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut out);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).unwrap());
        writer.start_file(MEMBER, opts).unwrap();
        writer.write_all(member).unwrap();
        writer.finish().unwrap();
    }
    out.into_inner()
}

/// The pristine jar of the victim at `version`.
pub fn victim_jar(version: &str) -> Vec<u8> {
    jar(&pristine_member(VICTIM, version))
}

/// The patched jar of the base victim.
pub fn patched_victim_jar() -> Vec<u8> {
    jar(&patched_member())
}

fn serve(server: &Server, rel: &str, bytes: &[u8]) {
    let route = format!("{REPO_ROUTE}/{rel}");
    server.get(&route, 200, bytes.to_vec());
    server.get(&format!("{route}.sha1"), 200, sha1_hex(bytes).into_bytes());
}

/// Serve the fixture repository from `server`.
pub fn publish(server: &Server) {
    let artifacts: [(&str, &str, &[(&str, &str)]); 8] = [
        (VICTIM, OLDER, &[]),
        (VICTIM, BASE, &[]),
        (VICTIM, NEWER, &[]),
        ("lib-base", "1.0", &[(VICTIM, BASE)]),
        ("lib-new", "1.0", &[(VICTIM, NEWER)]),
        ("lib-old", "1.0", &[(VICTIM, OLDER)]),
        ("lib-deep", "1.0", &[("lib-base", "1.0")]),
        ("lib-range", "1.0", &[(VICTIM, "[1.10.5,1.11.0]")]),
    ];
    for (artifact, version, deps) in artifacts {
        let dir = format!("{GROUP_PATH}/{artifact}/{version}");
        serve(
            server,
            &format!("{dir}/{artifact}-{version}.pom"),
            fixture_pom(artifact, version, deps).as_bytes(),
        );
        serve(
            server,
            &format!("{dir}/{artifact}-{version}.jar"),
            &jar(&pristine_member(artifact, version)),
        );
    }
    // A parent pom a project inherits from the repository.
    serve(
        server,
        &format!("{GROUP_PATH}/{PARENT}/1.0/{PARENT}-1.0.pom"),
        fixture_pom(PARENT, "1.0", &[])
            .replace(
                "<version>1.0</version>\n",
                "<version>1.0</version>\n  <packaging>pom</packaging>\n",
            )
            .as_bytes(),
    );
    let versions: String = [OLDER, BASE, NEWER]
        .iter()
        .map(|v| format!("      <version>{v}</version>\n"))
        .collect();
    serve(
        server,
        &format!("{GROUP_PATH}/{VICTIM}/maven-metadata.xml"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>{GROUP}</groupId>\n  \
             <artifactId>{VICTIM}</artifactId>\n  <versioning>\n    <latest>{NEWER}</latest>\n    \
             <release>{NEWER}</release>\n    <versions>\n{versions}    </versions>\n    \
             <lastUpdated>20260101000000</lastUpdated>\n  </versioning>\n</metadata>\n"
        )
        .as_bytes(),
    );
}

/// The `pom.xml` of a project of `shape` resolving from `server`.
pub fn project_pom(shape: Shape, server: &Server) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
         <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  <packaging>jar</packaging>\n  \
         <repositories>\n    <repository>\n      <id>fixture</id>\n      \
         <url>{}{REPO_ROUTE}</url>\n    </repository>\n  </repositories>\n  \
         <dependencies>\n{}  </dependencies>\n</project>\n",
        server.uri(),
        shape.dependencies()
    )
}

/// The modules of [`write_reactor`], and the victim version each selects.
pub const REACTOR_MODULES: [(&str, &str); 3] = [("a", BASE), ("b", NEWER), ("c", BASE)];

/// Write a reactor into `dir` (the table's V3): a parent pom that three
/// modules inherit, `a` reaching the base version two levels down, `b` a
/// newer version through another artifact, `c` declaring the base version
/// itself.
pub fn write_reactor(dir: &Path, server: &Server) {
    let modules: String = REACTOR_MODULES
        .iter()
        .map(|(name, _)| format!("    <module>{name}</module>\n"))
        .collect();
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("pom.xml"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
             <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
             <artifactId>parent</artifactId>\n  <version>1.0.0</version>\n  \
             <packaging>pom</packaging>\n  <modules>\n{modules}  </modules>\n  \
             <repositories>\n    <repository>\n      <id>fixture</id>\n      \
             <url>{}{REPO_ROUTE}</url>\n    </repository>\n  </repositories>\n</project>\n",
            server.uri()
        ),
    )
    .unwrap();
    for (name, deps) in [
        ("a", dependency("lib-deep", "1.0", "")),
        ("b", dependency("lib-new", "1.0", "")),
        ("c", dependency(VICTIM, BASE, "")),
    ] {
        std::fs::create_dir_all(dir.join(name)).unwrap();
        std::fs::write(
            dir.join(name).join("pom.xml"),
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
                 <modelVersion>4.0.0</modelVersion>\n  <parent>\n    \
                 <groupId>com.example</groupId>\n    <artifactId>parent</artifactId>\n    \
                 <version>1.0.0</version>\n  </parent>\n  <artifactId>{name}</artifactId>\n  \
                 <dependencies>\n{deps}  </dependencies>\n</project>\n"
            ),
        )
        .unwrap();
    }
}

/// The jars Maven resolves for each module of the reactor at `proj`
/// (see [`resolve`]), by module name.
pub fn resolve_reactor(
    suite: &str,
    mvn: &Mvn,
    proj: &Path,
    m2: &Path,
    settings: &Path,
    out_rel: &str,
) -> Option<BTreeMap<String, BTreeMap<String, Vec<u8>>>> {
    for (module, _) in REACTOR_MODULES {
        let _ = std::fs::remove_dir_all(proj.join(module).join(out_rel));
    }
    let out = with_central_fallback(suite, "reactor resolution", settings, |s, extra| {
        copy_dependencies(mvn, proj, m2, s, out_rel, extra)
    });
    if !ok(&out) {
        crate::maven_build_common::skip(
            suite,
            &format!("resolving {} failed:\n{}", proj.display(), dump(&out)),
        );
        return None;
    }
    Some(
        REACTOR_MODULES
            .iter()
            .map(|(module, _)| (module.to_string(), copied(&proj.join(module), out_rel)))
            .collect(),
    )
}

/// A parent pom the fixture repository serves.
pub const PARENT: &str = "lib-parent";

/// The `pom.xml` of a project that inherits [`PARENT`] from the repository
/// and declares the base victim itself.
pub fn parented_pom(server: &Server) -> String {
    project_pom(Shape::Selected, server)
        .replace(
            "  <groupId>com.example</groupId>\n",
            &format!(
                "  <parent>\n    <groupId>{GROUP}</groupId>\n    \
                 <artifactId>{PARENT}</artifactId>\n    <version>1.0</version>\n    \
                 <relativePath/>\n  </parent>\n  <groupId>com.example</groupId>\n"
            ),
        )
        .replace(
            &dependency("lib-deep", "1.0", ""),
            &dependency(VICTIM, BASE, ""),
        )
}

/// Write the project of `shape` into `dir`.
pub fn write_project(dir: &Path, shape: Shape, server: &Server) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("pom.xml"), project_pom(shape, server)).unwrap();
}

fn copy_dependencies(
    mvn: &Mvn,
    proj: &Path,
    m2: &Path,
    settings: &Path,
    out_rel: &str,
    extra: &[&str],
) -> Output {
    let _ = std::fs::remove_dir_all(proj.join(out_rel));
    let goal = format!("{DEPENDENCY_PLUGIN}:copy-dependencies");
    let out_dir = format!("-DoutputDirectory={out_rel}");
    let mut args = vec![goal.as_str(), out_dir.as_str()];
    args.extend_from_slice(extra);
    mvn.run(proj, m2, settings, &args)
}

/// The jars Maven resolves for the project at `proj`, by file name
/// (`<artifact>-<version>.jar`). `None` when Maven Central, which holds the
/// dependency plugin, cannot be reached (skip printed; a failure on a
/// required leg). `settings` must hold no mirror.
pub fn resolve(
    suite: &str,
    mvn: &Mvn,
    proj: &Path,
    m2: &Path,
    settings: &Path,
    out_rel: &str,
) -> Option<BTreeMap<String, Vec<u8>>> {
    let out = with_central_fallback(suite, "dependency resolution", settings, |s, extra| {
        copy_dependencies(mvn, proj, m2, s, out_rel, extra)
    });
    if !ok(&out) {
        crate::maven_build_common::skip(
            suite,
            &format!("resolving {} failed:\n{}", proj.display(), dump(&out)),
        );
        return None;
    }
    Some(copied(proj, out_rel))
}

/// [`resolve`] once the local repository is warm, with any `settings`
/// (a mirror for the Socket repository) and extra Maven flags.
pub fn resolve_warm(
    mvn: &Mvn,
    proj: &Path,
    m2: &Path,
    settings: &Path,
    out_rel: &str,
    extra: &[&str],
) -> BTreeMap<String, Vec<u8>> {
    let out = copy_dependencies(mvn, proj, m2, settings, out_rel, extra);
    assert!(ok(&out), "{}:\n{}", proj.display(), dump(&out));
    copied(proj, out_rel)
}

fn copied(proj: &Path, out_rel: &str) -> BTreeMap<String, Vec<u8>> {
    let dir = proj.join(out_rel);
    let jars = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    let _ = std::fs::remove_dir_all(proj.join("target"));
    jars
}

/// `names` with every `-socket.<hex8>` version suffix dropped: the
/// artifacts a build resolves, whether or not a patched build replaced
/// one.
pub fn unsuffixed<'a>(names: impl IntoIterator<Item = &'a String>) -> BTreeSet<String> {
    names
        .into_iter()
        .map(|name| match name.find("-socket.") {
            Some(at)
                if name[at + 8..]
                    .chars()
                    .take(8)
                    .all(|c| c.is_ascii_hexdigit()) =>
            {
                format!("{}{}", &name[..at], &name[at + 16..])
            }
            _ => name.clone(),
        })
        .collect()
}

/// A batch lookup that does not ask about `needle`.
struct Lacks(String);

impl wiremock::Match for Lacks {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !String::from_utf8_lossy(&request.body).contains(&self.0)
    }
}

/// Make the patch lookup of `org` on `server` answer like the service: a
/// patch only for a package the scan asked about. (The shared hosted mock
/// answers every lookup with its one patch, so a package the crawl left
/// out would still come back patched.)
pub fn answer_lookups_only_for(server: &Server, org: &str, needle: &str) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    server.rt.block_on(
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{org}/patches/batch")))
            .and(Lacks(needle.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": [],
                "canAccessPaidPatches": false,
            })))
            .with_priority(1)
            .mount(&server.server),
    );
}

/// The victim's jar name at `version`.
pub fn victim_jar_name(version: &str) -> String {
    format!("{VICTIM}-{version}.jar")
}

/// `<m2>/<group>/victim/<version>/`.
pub fn victim_dir(m2: &Path, version: &str) -> std::path::PathBuf {
    m2.join(GROUP_PATH).join(VICTIM).join(version)
}

/// A settings file that shields the run from `~/.m2` and mirrors nothing.
pub fn plain_settings(path: &Path) {
    write_settings(path, &[]);
}

/// Every file under `dir` (relative, forward slashes) with its bytes.
pub fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().to_string_lossy();
                out.insert(rel.replace('\\', "/"), std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}
