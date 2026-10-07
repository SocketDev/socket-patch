//! Manifest-less `socket-patch vex` for HOSTED sbt: the generated
//! `socket-patch.sbt` pins, attested only against the build's local
//! resolution evidence (lane L3 fills this suite; see
//! `docs/design/sbt-support.md`). Until then it holds the shared fixture
//! helpers' self-tests.

use super::sbt_common::{copy_evidence, write_coursier_artifact, write_ivy_artifact, Gav, SbtHome};

const LANG3: Gav<'static> = Gav {
    group: "org.apache.commons",
    artifact: "commons-lang3",
    version: "3.11",
};

#[test]
fn sbt_common_writes_the_cache_layouts() {
    let tmp = tempfile::tempdir().unwrap();
    let home = SbtHome::new(tmp.path());
    let dir = write_coursier_artifact(
        &home.coursier_cache(),
        "repo1.maven.org/maven2",
        LANG3,
        b"jar",
    );
    assert!(dir.ends_with("https/repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.11"));
    assert!(dir.join("commons-lang3-3.11.jar").is_file());
    assert_eq!(
        std::fs::read_to_string(dir.join(".commons-lang3-3.11.jar__sha1"))
            .unwrap()
            .len(),
        40
    );
    let jars = write_ivy_artifact(&home.ivy_home(), LANG3, b"jar");
    assert!(jars.join("commons-lang3-3.11.jar").is_file());
    assert!(jars
        .parent()
        .unwrap()
        .join("ivy-3.11.xml.original")
        .is_file());
    let env = home.isolated_env();
    assert!(env
        .iter()
        .any(|(k, v)| k == "COURSIER_CACHE" && v.starts_with(&*tmp.path().to_string_lossy())));
}

#[test]
fn sbt_common_copies_an_evidence_fixture() {
    let tmp = tempfile::tempdir().unwrap();
    copy_evidence("1.9.9", "test-compile", tmp.path());
    assert!(tmp.path().join("build.sbt").is_file());
    assert!(tmp
        .path()
        .join("a/target/scala-2.12/update/update_cache_2.12/output")
        .is_file());
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("project/build.properties")).unwrap(),
        "sbt.version=1.9.9\n"
    );
}
