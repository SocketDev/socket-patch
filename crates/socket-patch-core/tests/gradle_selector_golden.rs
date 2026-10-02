//! Checks the `gradle::selector` golden tables (and the Rust port itself)
//! against real Gradle's own version comparator and selector scheme.
//!
//! The hosted settings script ships a Groovy port of the selector logic and
//! is tested against the same tables, so a table entry that real Gradle
//! disagrees with would make both ports wrong together. This suite asks
//! Gradle directly, through its internal `VersionParser`,
//! `DefaultVersionComparator` and `DefaultVersionSelectorScheme` (stable
//! from 6.9 through 9.x).
//!
//! It runs only when `SOCKET_PATCH_GRADLE_E2E_GRADLE` names a Gradle
//! launcher (the JDK comes from the ambient `JAVA_HOME`);
//! `SOCKET_PATCH_GRADLE_E2E_REQUIRED` turns the skip into a failure and
//! `SOCKET_PATCH_GRADLE_E2E_VERSION` pins the version the launcher must
//! report.

use std::process::Command;

use socket_patch_core::gradle::selector::{
    admits_for, gradle_version_cmp_for, parse_selector, GOLDEN_ADMITS, GOLDEN_ADMITS_BY_MAJOR,
    GOLDEN_ORDERING, GOLDEN_ORDERING_BY_MAJOR,
};

const GRADLE_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_GRADLE";
const GRADLE_VERSION_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_VERSION";
const GRADLE_REQUIRED_ENV: &str = "SOCKET_PATCH_GRADLE_E2E_REQUIRED";

fn flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn groovy_str(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// A build script printing Gradle's answer for every table row.
fn probe_script() -> String {
    let mut ords: Vec<(&str, &str)> = GOLDEN_ORDERING.iter().map(|(a, b, _)| (*a, *b)).collect();
    ords.extend(GOLDEN_ORDERING_BY_MAJOR.iter().map(|(a, b, _, _)| (*a, *b)));
    let mut adm: Vec<(&str, &str)> = GOLDEN_ADMITS.iter().map(|(s, v, _)| (*s, *v)).collect();
    adm.extend(GOLDEN_ADMITS_BY_MAJOR.iter().map(|(s, v, _, _)| (*s, *v)));
    let list = |rows: &[(&str, &str)]| {
        rows.iter()
            .map(|(a, b)| format!("  [{}, {}],", groovy_str(a), groovy_str(b)))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        r#"import org.gradle.api.internal.artifacts.ivyservice.ivyresolve.strategy.*
def parser = new VersionParser()
def cmp = new DefaultVersionComparator()
def scheme = new DefaultVersionSelectorScheme(cmp, parser)
def ords = [
{}
]
def adm = [
{}
]
println "VER\t${{gradle.gradleVersion}}"
for (r in ords) {{
  int c = Integer.signum(cmp.asVersionComparator().compare(parser.transform(r[0]), parser.transform(r[1])))
  println "ORD\t${{r[0]}}\t${{r[1]}}\t${{c}}"
}}
for (r in adm) {{
  def sel = scheme.parseSelector(r[0])
  def got = sel.requiresMetadata() ? 'None' : String.valueOf(sel.accept(r[1]))
  println "ADM\t${{r[0]}}\t${{r[1]}}\t${{got}}"
}}
"#,
        list(&ords),
        list(&adm)
    )
}

#[test]
fn gradle_hosted_selector_golden_tables_match_real_gradle() {
    let Some(program) = std::env::var_os(GRADLE_ENV).filter(|v| !v.is_empty()) else {
        assert!(
            !flag(GRADLE_REQUIRED_ENV),
            "{GRADLE_REQUIRED_ENV} is set but {GRADLE_ENV} names no Gradle launcher"
        );
        println!("SKIP: {GRADLE_ENV} is not set");
        return;
    };
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("probe");
    std::fs::create_dir_all(&project).expect("mkdir");
    std::fs::write(
        project.join("settings.gradle"),
        "rootProject.name = 'probe'\n",
    )
    .expect("settings");
    std::fs::write(project.join("build.gradle"), probe_script()).expect("build");
    let mut cmd = Command::new(&program);
    for key in ["GRADLE_OPTS", "JAVA_OPTS"] {
        cmd.env_remove(key);
    }
    let out = cmd
        .env("GRADLE_USER_HOME", tmp.path().join("home"))
        .current_dir(&project)
        .args(["--no-daemon", "--console=plain", "-q", "help"])
        .output()
        .expect("spawn gradle");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "gradle failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let version = stdout
        .lines()
        .find_map(|l| l.strip_prefix("VER\t"))
        .expect("version line")
        .trim()
        .to_string();
    if let Some(pin) = std::env::var(GRADLE_VERSION_ENV)
        .ok()
        .filter(|v| !v.is_empty())
    {
        assert_eq!(version, pin, "{GRADLE_VERSION_ENV} pins {pin}");
    }
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .expect("major");
    println!("checking the golden tables against Gradle {version}");

    let mut mismatches = Vec::new();
    let mut ord_rows = 0;
    let mut adm_rows = 0;
    for line in stdout.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        match cols.as_slice() {
            ["ORD", a, b, c] => {
                ord_rows += 1;
                let gradle = c.parse::<i32>().expect("signum").cmp(&0);
                let table = GOLDEN_ORDERING
                    .iter()
                    .find(|(x, y, _)| x == a && y == b)
                    .map(|(_, _, o)| *o)
                    .or_else(|| {
                        GOLDEN_ORDERING_BY_MAJOR
                            .iter()
                            .find(|(x, y, _, _)| x == a && y == b)
                            .map(|(_, _, six, later)| if major < 7 { *six } else { *later })
                    })
                    .expect("row");
                let port = gradle_version_cmp_for(a, b, major);
                if gradle != table || gradle != port {
                    mismatches.push(format!(
                        "order {a} vs {b}: gradle {gradle:?}, table {table:?}, port {port:?}"
                    ));
                }
            }
            ["ADM", sel, v, got] => {
                adm_rows += 1;
                let gradle = match *got {
                    "None" => None,
                    "true" => Some(true),
                    _ => Some(false),
                };
                let table = GOLDEN_ADMITS
                    .iter()
                    .find(|(s, x, _)| s == sel && x == v)
                    .map(|(_, _, w)| *w)
                    .or_else(|| {
                        GOLDEN_ADMITS_BY_MAJOR
                            .iter()
                            .find(|(s, x, _, _)| s == sel && x == v)
                            .map(|(_, _, six, later)| if major < 7 { *six } else { *later })
                    })
                    .expect("row");
                let port = admits_for(&parse_selector(sel), v, major);
                if gradle != table || gradle != port {
                    mismatches.push(format!(
                        "{sel:?} admits {v}: gradle {gradle:?}, table {table:?}, port {port:?}"
                    ));
                }
            }
            _ => {}
        }
    }
    assert_eq!(
        ord_rows,
        GOLDEN_ORDERING.len() + GOLDEN_ORDERING_BY_MAJOR.len()
    );
    assert_eq!(adm_rows, GOLDEN_ADMITS.len() + GOLDEN_ADMITS_BY_MAJOR.len());
    assert!(
        mismatches.is_empty(),
        "Gradle {version} disagrees:\n{}",
        mismatches.join("\n")
    );
}
