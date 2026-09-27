//! Equivalence oracle for the POM coordinate parser, which now uses static
//! tag needles, borrows comment-free lines, skips tag-free lines and stops
//! once the project's own coordinates are complete. The previous
//! implementation is kept here verbatim; the production parser must return
//! the identical result on every document.

use super::maven_crawler::parse_pom_group_artifact_version;

/// Extract the text value between `<element>` and `</element>` on a single line.
fn extract_xml_value(line: &str, element: &str) -> Option<String> {
    let open = format!("<{element}>");
    let close = format!("</{element}>");
    let start = line.find(&open)?;
    let value_start = start + open.len();
    let end = line[value_start..].find(&close)?;
    let value = line[value_start..value_start + end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Strip the commented-out portions of a single line, threading the
/// `in_comment` state across lines so multi-line `<!-- ... -->` blocks are
/// handled. XML comments do not nest, so we always close on the first `-->`.
///
/// This runs before any tag matching: POM files routinely carry license
/// headers and commented-out `<dependency>`/`<build>` snippets, and naive
/// substring matching would otherwise miscount skip-section depth (e.g. a
/// comment containing `</build>` could "close" a block that is still open
/// and leak a plugin's coordinates as the project's).
fn strip_comment_spans(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        if *in_comment {
            match rest.find("-->") {
                Some(end) => {
                    rest = &rest[end + 3..];
                    *in_comment = false;
                }
                None => return out, // remainder of the line is inside a comment
            }
        } else {
            match rest.find("<!--") {
                Some(start) => {
                    out.push_str(&rest[..start]);
                    rest = &rest[start + 4..];
                    *in_comment = true;
                }
                None => {
                    out.push_str(rest);
                    return out;
                }
            }
        }
    }
}

/// Find the first *real* opening tag for `element` on this line and report
/// whether it self-closes (`Some(true)` for `<dependencies/>`, `Some(false)`
/// for a plain `<dependencies>` or `<dependencies foo="x">`); `None` if there
/// is no opening tag at all.
///
/// "Real" means there is a tag boundary immediately after the element name —
/// `>`, `/`, whitespace, or end-of-line. This is critical: a bare substring
/// match would prefix-match a *different* element such as `<buildtools>` as if
/// it opened `<build>`. Because the corresponding close `</buildtools>` never
/// equals `</build>`, that phantom open would never be matched by a close and
/// would leak the entire remainder of the document into the skip section,
/// dropping the project's real coordinates.
fn opening_tag(line: &str, element: &str) -> Option<bool> {
    let needle = format!("<{element}");
    let mut from = 0;
    while let Some(rel) = line[from..].find(&needle) {
        let pos = from + rel;
        let after = &line[pos + needle.len()..];
        match after.chars().next() {
            // Tag name runs to the end of the line (attributes continue on the
            // next line): a real, non-self-closing open.
            None => return Some(false),
            Some(c) if c == '>' || c == '/' || c.is_whitespace() => {
                let self_closes = match after.find('>') {
                    Some(gt) => after[..gt].trim_end().ends_with('/'),
                    None => false,
                };
                return Some(self_closes);
            }
            // Prefix match of a longer name (`<buildtools>`): keep scanning for
            // a genuine `<build>`/`<build ...>`/`<build/>` later on the line.
            _ => from = pos + needle.len(),
        }
    }
    None
}

/// Does this line contain a *real* closing tag `</element>` (tolerating
/// whitespace before `>`, e.g. `</build >`)? The boundary `>` is required, so
/// `</buildtools>` is not treated as a close of `</build>` — mirroring the
/// boundary discipline of [`opening_tag`].
fn contains_closing_tag(line: &str, element: &str) -> bool {
    let needle = format!("</{element}");
    let mut from = 0;
    while let Some(rel) = line[from..].find(&needle) {
        let pos = from + rel;
        let after = &line[pos + needle.len()..];
        if after.trim_start().starts_with('>') {
            return true;
        }
        from = pos + needle.len();
    }
    false
}

/// Parse `groupId`, `artifactId`, and `version` from a POM XML file.
///
/// Uses a simple line-based parser — no XML crate dependency.
/// Tracks nesting depth to skip `<dependencies>`, `<build>`, `<profiles>`, etc.
/// Extracts top-level `<groupId>`, `<artifactId>`, `<version>` from `<project>`.
/// Falls back to `<parent>` block for groupId if missing at top level.
/// Returns `None` for property references (`${...}`).
fn reference_parse_pom(content: &str) -> Option<(String, String, String)> {
    let mut group_id: Option<String> = None;
    let mut artifact_id: Option<String> = None;
    let mut version: Option<String> = None;
    let mut parent_group_id: Option<String> = None;

    let mut in_parent = false;
    let mut in_comment = false;
    let mut skip_depth: u32 = 0;

    let skip_sections = [
        "dependencies",
        "build",
        "profiles",
        "reporting",
        "dependencyManagement",
        "pluginManagement",
        "modules",
        "distributionManagement",
        "repositories",
        "pluginRepositories",
        // Free-form (xs:any): a property may be named exactly `version`/
        // `groupId`/`artifactId` (Maven warns but permits it) and would
        // otherwise win first-match extraction over the project's own
        // coordinates. Project coordinates never live in <properties>,
        // so skipping it can only prevent leaks.
        "properties",
    ];

    for line in content.lines() {
        let cleaned = strip_comment_spans(line, &mut in_comment);
        let trimmed = cleaned.trim();

        // Check for skip section open/close. A tag that opens and closes on
        // the same line (`<modules></modules>`) or self-closes
        // (`<dependencies/>`) leaves the depth unchanged; only a lone open
        // increments and a lone close decrements.
        //
        // Any line carrying a close tag still holds that section's content up
        // to the close (`<version>9.9</version></dependencies>`, or a whole
        // compact `<dependencies>...</dependencies>` block), so it must not
        // reach extraction even once the depth is back to 0 — otherwise a
        // dependency's coordinates leak as the project's. A coordinate that
        // legitimately follows a close on the same line is sacrificed to
        // `None`, which scan rescues via the directory-path fallback.
        let mut saw_section_close = false;
        for section in &skip_sections {
            let open = opening_tag(trimmed, section);
            let has_open = open.is_some();
            let has_close = contains_closing_tag(trimmed, section);
            saw_section_close |= has_close;
            if has_open && !has_close && open != Some(true) {
                skip_depth += 1;
            } else if has_close && !has_open {
                skip_depth = skip_depth.saturating_sub(1);
            }
        }

        if skip_depth > 0 || saw_section_close {
            continue;
        }

        // Track parent section (a self-closing `<parent/>` carries no
        // coordinates, so it never opens a parent block).
        let parent_open = opening_tag(trimmed, "parent");
        if parent_open.is_some()
            && !contains_closing_tag(trimmed, "parent")
            && parent_open != Some(true)
        {
            in_parent = true;
            continue;
        }
        if contains_closing_tag(trimmed, "parent") {
            in_parent = false;
            continue;
        }

        if in_parent {
            if parent_group_id.is_none() {
                if let Some(val) = extract_xml_value(trimmed, "groupId") {
                    if val.contains("${") {
                        // Property reference in parent — skip
                    } else {
                        parent_group_id = Some(val);
                    }
                }
            }
            continue;
        }

        // Extract top-level coordinates
        if group_id.is_none() {
            if let Some(val) = extract_xml_value(trimmed, "groupId") {
                if val.contains("${") {
                    return None;
                }
                group_id = Some(val);
            }
        }
        if artifact_id.is_none() {
            if let Some(val) = extract_xml_value(trimmed, "artifactId") {
                if val.contains("${") {
                    return None;
                }
                artifact_id = Some(val);
            }
        }
        if version.is_none() {
            if let Some(val) = extract_xml_value(trimmed, "version") {
                if val.contains("${") {
                    return None;
                }
                version = Some(val);
            }
        }
    }

    // Fall back to parent groupId
    let final_group_id = group_id.or(parent_group_id)?;
    let final_artifact_id = artifact_id?;
    let final_version = version?;

    if final_group_id.is_empty() || final_artifact_id.is_empty() || final_version.is_empty() {
        return None;
    }

    Some((final_group_id, final_artifact_id, final_version))
}

/// Deterministic xorshift64* — no `rand` dev-dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

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
fn parser_matches_reference_on_random_poms() {
    let mut rng = Rng(0xA076_1D64_78BD_642F);
    for case in 0..20_000 {
        let pom = synth_pom(&mut rng);
        assert_eq!(
            parse_pom_group_artifact_version(&pom),
            reference_parse_pom(&pom),
            "case {case}: {pom:?}"
        );
    }
}

/// Well-formed project poms with the coordinates placed before, between and
/// after the noisy sections — the shapes the early exit stops on.
#[test]
fn parser_matches_reference_on_project_shaped_poms() {
    let mut rng = Rng(0xE703_7ED1_A0B4_28DB);
    let mut resolved = 0;
    for case in 0..5_000 {
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
        let want = reference_parse_pom(&pom);
        resolved += usize::from(want.is_some());
        assert_eq!(
            parse_pom_group_artifact_version(&pom),
            want,
            "case {case}: {pom:?}"
        );
    }
    assert!(resolved > 1_000, "the corpus exercises the resolving path");
}
