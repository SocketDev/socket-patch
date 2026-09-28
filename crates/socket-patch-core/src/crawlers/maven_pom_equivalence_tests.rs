//! Seeded POM documents for the coordinate parser, which uses static tag
//! needles, borrows comment-free lines, skips tag-free lines and stops once
//! the project's own coordinates are complete. Each sweep is pinned by a
//! golden (see `crate::golden`) blessed when #257's verbatim previous
//! parser and this one agreed on every document.

use super::maven_crawler::parse_pom_group_artifact_version;
use crate::test_rng::Rng;

/// Line fragments covering every branch of the parser: coordinates (plain,
/// empty, `${…}`, split across lines), skip-section opens/closes in every
/// spelling (attributes, self-closing, `</x >`, prefix decoys, compact
/// same-line blocks), `<parent>` blocks, and comments that open, close or
/// span tags mid-line.
const FRAGMENTS: &[&str] = &[
    "<groupId>org.example</groupId>",
    "<groupId>com.acme.tools</groupId>",
    "<groupId>${project.parent.groupId}</groupId>",
    "<groupId></groupId>",
    "<groupId> spaced.group </groupId>",
    "<groupId>",
    "</groupId>",
    "<artifactId>demo</artifactId>",
    "<artifactId>other-lib</artifactId>",
    "<artifactId>${name}</artifactId>",
    "<artifactId></artifactId>",
    "<version>1.0.0</version>",
    "<version>2.3.4-SNAPSHOT</version>",
    "<version>${revision}</version>",
    "<version></version>",
    "<parent>",
    "</parent>",
    "<parent/>",
    "<parent >",
    "<parent><groupId>org.parent</groupId></parent>",
    "<dependencies>",
    "</dependencies>",
    "<dependencies/>",
    "<dependencies foo=\"x\">",
    "<dependencies></dependencies>",
    "<dependencies><dependency><version>9.9</version></dependency></dependencies>",
    "<version>9.9</version></dependencies>",
    "<build>",
    "</build>",
    "</build >",
    "<build",
    "attr=\"x\">",
    "<buildtools>",
    "</buildtools>",
    "<buildtools/> <build>",
    "<properties>",
    "</properties>",
    "<properties><version>7</version></properties>",
    "<profiles>",
    "</profiles>",
    "<modules></modules>",
    "<modulesInfo>x</modulesInfo>",
    "<dependencyManagement>",
    "</dependencyManagement>",
    "<pluginManagement>",
    "</pluginManagement>",
    "<reporting>",
    "</reporting>",
    "<distributionManagement>",
    "</distributionManagement>",
    "<repositories>",
    "</repositories>",
    "<pluginRepositories>",
    "</pluginRepositories>",
    "<!--",
    "-->",
    "<!-- </build> -->",
    "<!-- <groupId>commented</groupId> -->",
    "<!-- <dependencies>",
    "</dependencies> -->",
    "a <!-- b --> c <!-- d",
    "<project>",
    "</project>",
    "<modelVersion>4.0.0</modelVersion>",
    "<name>Demo</name>",
    "plain text with no tags",
    "",
    "   ",
    "\t",
    "é<version>1.0-é</version>",
];

fn synth_pom(rng: &mut Rng) -> String {
    let mut out = String::new();
    for _ in 0..rng.below(24) {
        // One to three fragments per line, so opens, closes, comments and
        // values share lines in every combination.
        for _ in 0..=rng.below(3) {
            out.push_str(rng.pick(&["", " ", "  ", "\t"]));
            out.push_str(rng.pick(FRAGMENTS));
        }
        out.push_str(rng.pick(&["\n", "\n", "\n", "\r\n"]));
    }
    out
}

#[test]
fn parser_matches_golden_on_random_poms() {
    let mut g = crate::golden::Golden::new(
        "maven_pom_random",
        "One seeded POM fragment soup, parsed for its coordinates.",
    )
    .chunked(100);
    let mut rng = Rng(0xA076_1D64_78BD_642F);
    for _ in 0..20_000 {
        let pom = synth_pom(&mut rng);
        g.next(&pom, &parse_pom_group_artifact_version(&pom));
    }
    g.finish();
}

/// Well-formed project poms with the coordinates placed before, between and
/// after the noisy sections — the shapes the early exit stops on.
#[test]
fn parser_matches_golden_on_project_shaped_poms() {
    let mut g = crate::golden::Golden::new(
        "maven_pom_project",
        "One seeded project-shaped POM, parsed for its coordinates.",
    )
    .chunked(25);
    let mut rng = Rng(0xE703_7ED1_A0B4_28DB);
    let mut resolved = 0;
    for _ in 0..5_000 {
        let mut lines = vec![
            "<?xml version=\"1.0\"?>".to_string(),
            "<project>".to_string(),
        ];
        let mut body: Vec<String> = [
            "<groupId>org.example</groupId>",
            "<artifactId>demo</artifactId>",
            "<version>1.0.0</version>",
        ]
        .iter()
        .map(|s| format!("  {s}"))
        .collect();
        for _ in 0..rng.below(8) {
            let at = rng.below(body.len() + 1);
            body.insert(at, format!("  {}", rng.pick(FRAGMENTS)));
        }
        lines.extend(body);
        lines.push("</project>".to_string());
        let pom = lines.join(rng.pick(&["\n", "\r\n"]));
        let got = parse_pom_group_artifact_version(&pom);
        resolved += usize::from(got.is_some());
        g.next(&pom, &got);
    }
    assert!(resolved > 1_000, "the corpus exercises the resolving path");
    g.finish();
}
