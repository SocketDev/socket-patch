//! Maven's `settings.xml` mirrors, and whether one would take over a
//! repository hosted mode adds to a pom. Pure: the settings are read by
//! the caller ([`crate::crawlers::maven_crawler::settings_mirrors`]).
//!
//! A `<mirror>` replaces every repository its `<mirrorOf>` matches: Maven
//! then asks the mirror's URL, never the repository's own. A company's
//! `<mirrorOf>*</mirrorOf>` therefore sends the `socket-patch-<uuid>`
//! repository to its repository manager, which does not hold the patched
//! version, and the build fails to resolve it.
//!
//! The matching is Maven's own (`DefaultMirrorSelector`, the same in
//! maven-core and maven-resolver):
//!
//! * a mirror whose whole `<mirrorOf>` is the repository's id wins over
//!   every pattern, whatever the order of the mirrors;
//! * otherwise the first mirror, in settings order, whose pattern matches:
//!   `*`; `external:*` (any repository not on `localhost` / `127.0.0.1`
//!   and not a `file:` URL); `external:http:*` (the same, over plain
//!   HTTP); a comma-separated list of ids and those wildcards, in which
//!   `!id` excludes that repository;
//! * and whose `<mirrorOfLayouts>` (empty by default: any) accepts the
//!   repository's layout.
//!
//! An id in a pattern is always a whole id: `!socket-patch-*` excludes
//! nothing. The settings reader trims the whole `<mirrorOf>`, but a segment
//! of a list is compared as written: in `*, !id` the exclusion starts with
//! a space, is no exclusion, and the mirror takes the repository.
//!
//! Checked against Maven itself: every case of the tests below was run
//! through `DefaultMirrorSelector` of Maven 3.6.3, 3.9.4, 3.9.16 and
//! 4.0.0-rc-7 (the same answers, but for `external:http:*`, which Maven
//! knows from 3.8.1), and the spaced, the glob and the padded patterns
//! through real builds of 3.6.3, 3.9.16 and 4.0.0-rc-7.

use serde::{Deserialize, Serialize};

/// One `<mirror>` of a settings file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Mirror {
    pub(crate) id: String,
    pub(crate) mirror_of: String,
    /// `<mirrorOfLayouts>`, when the mirror names any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) layouts: Option<String>,
    /// The settings file that declares the mirror.
    pub(crate) source: String,
}

/// The layout of every repository hosted mode writes.
const LAYOUT: &str = "default";

/// `scheme` and `host` of a repository URL, as the resolver reads them
/// (`RemoteRepository.getProtocol` / `getHost`): the scheme is what comes
/// before `://` (so `dav:http`), the host what follows it up to a `/` or
/// a port, without any `user@`.
fn scheme_and_host(url: &str) -> (&str, &str) {
    let Some((scheme, rest)) = url.split_once("://") else {
        return (url.split(':').next().unwrap_or_default(), "");
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority.rsplit('@').next().unwrap_or_default();
    (scheme, host.split(':').next().unwrap_or_default())
}

fn is_local(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1"
}

fn is_external(url: &str) -> bool {
    let (scheme, host) = scheme_and_host(url);
    !(is_local(host) || scheme.eq_ignore_ascii_case("file"))
}

fn is_external_http(url: &str) -> bool {
    let (scheme, host) = scheme_and_host(url);
    ["http", "dav", "dav:http", "dav+http"]
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s))
        && !is_local(host)
}

/// Whether the `<mirrorOf>` `pattern` matches the repository `id` at `url`
/// (Maven's `matchPattern`). Segments are read left to right, each as
/// written: an exclusion of the id ends the reading with no match, the id
/// itself ends it with a match, and a wildcard matches unless a later
/// segment excludes the id.
pub(crate) fn matches_pattern(pattern: &str, id: &str, url: &str) -> bool {
    if pattern == "*" || pattern == id {
        return true;
    }
    let mut matched = false;
    for segment in pattern.split(',') {
        if segment.len() > 1 && segment.starts_with('!') {
            if &segment[1..] == id {
                return false;
            }
        } else if segment == id {
            return true;
        } else if (segment == "external:*" && is_external(url))
            || (segment == "external:http:*" && is_external_http(url))
            || segment == "*"
        {
            matched = true;
        }
    }
    matched
}

/// Whether a mirror's `<mirrorOfLayouts>` accepts `layout` (Maven's
/// `matchesLayout`): none, or `*`, accepts any; else a list read like
/// [`matches_pattern`].
fn matches_layout(layouts: Option<&str>, layout: &str) -> bool {
    let Some(layouts) = layouts.filter(|l| !l.is_empty() && *l != "*") else {
        return true;
    };
    if layouts == layout {
        return true;
    }
    let mut matched = false;
    for segment in layouts.split(',') {
        if segment.len() > 1 && segment.starts_with('!') {
            if &segment[1..] == layout {
                return false;
            }
        } else if segment == layout {
            return true;
        } else if segment == "*" {
            matched = true;
        }
    }
    matched
}

/// Whether `mirror` names the repository `id`: its `<mirrorOf>` is the
/// id, or lists it as an id of its own (`central,socket-patch-<uuid>`),
/// each segment compared as written, as Maven compares it.
fn names(mirror: &Mirror, id: &str) -> bool {
    mirror.mirror_of.split(',').any(|segment| segment == id)
}

/// The mirror Maven uses for the repository `id` at `url`, and whether it
/// names that repository ([`names`]).
pub(crate) fn select<'m>(mirrors: &'m [Mirror], id: &str, url: &str) -> Option<(&'m Mirror, bool)> {
    let layout_ok = |m: &&Mirror| matches_layout(m.layouts.as_deref(), LAYOUT);
    let exact = mirrors.iter().filter(layout_ok).find(|m| m.mirror_of == id);
    exact.map(|m| (m, true)).or_else(|| {
        mirrors
            .iter()
            .filter(layout_ok)
            .find(|m| matches_pattern(&m.mirror_of, id, url))
            .map(|m| (m, names(m, id)))
    })
}

/// `dominant` followed by the mirrors of `recessive` whose id it does not
/// declare, as Maven merges the user settings over the global ones.
pub(crate) fn merge(dominant: Vec<Mirror>, recessive: Vec<Mirror>) -> Vec<Mirror> {
    let mut merged = dominant;
    for mirror in recessive {
        if !merged.iter().any(|m| m.id == mirror.id) {
            merged.push(mirror);
        }
    }
    merged
}

/// The mirror that would take over the repository `id` at `url` without
/// naming it, in any of `sets` (each the merged mirrors of one way Maven
/// may be started). A mirror whose `<mirrorOf>` names the id, alone or as
/// one id of a list, was written for that repository: whoever runs it
/// chose to serve the Socket repository there, and it is not one. (Nor
/// would the exclusion the warning suggests change anything for it.)
pub(crate) fn capturing<'m>(sets: &'m [Vec<Mirror>], id: &str, url: &str) -> Option<&'m Mirror> {
    sets.iter()
        .find_map(|mirrors| match select(mirrors, id, url) {
            Some((mirror, false)) => Some(mirror),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "socket-patch-77777777-7777-7777-7777-777777777777";
    const URL: &str = "https://patch.socket.dev/patch-registry/maven/t/u/maven2";

    fn mirror(id: &str, of: &str) -> Mirror {
        Mirror {
            id: id.into(),
            mirror_of: of.into(),
            layouts: None,
            source: "settings.xml".into(),
        }
    }

    /// The cases of Maven's "Using Mirrors for Repositories" guide.
    #[test]
    fn the_documented_patterns_match_as_maven_matches_them() {
        // `*`: everything.
        assert!(matches_pattern("*", ID, URL));
        // `external:*`: everything not on the localhost and not file based.
        assert!(matches_pattern("external:*", ID, URL));
        assert!(!matches_pattern(
            "external:*",
            ID,
            "http://localhost:8081/repo"
        ));
        assert!(!matches_pattern("external:*", ID, "http://127.0.0.1/repo"));
        assert!(!matches_pattern("external:*", ID, "file:///srv/repo"));
        assert!(!matches_pattern("external:*", ID, "file:/srv/repo"));
        // `external:http:*`: any repository not on the localhost using HTTP.
        assert!(!matches_pattern("external:http:*", ID, URL));
        assert!(matches_pattern(
            "external:http:*",
            ID,
            "http://patch.example/m2"
        ));
        assert!(matches_pattern(
            "external:http:*",
            ID,
            "dav:http://patch.example/m2"
        ));
        assert!(!matches_pattern(
            "external:http:*",
            ID,
            "http://localhost/m2"
        ));
        // `repo,repo1`: repo or repo1.
        assert!(matches_pattern(&format!("central,{ID}"), ID, URL));
        assert!(!matches_pattern("central,jboss", ID, URL));
        // `*,!repo1`: everything except repo1.
        assert!(!matches_pattern(&format!("*,!{ID}"), ID, URL));
        assert!(matches_pattern("*,!central", ID, URL));
        assert!(matches_pattern(ID, ID, URL));
        assert!(!matches_pattern("central", ID, URL));
    }

    /// The reading is ordered, as in `DefaultMirrorSelector.matchPattern`.
    #[test]
    fn a_list_is_read_left_to_right() {
        // An exclusion ends it, wherever the wildcard stands.
        assert!(!matches_pattern(&format!("!{ID},*"), ID, URL));
        assert!(!matches_pattern(&format!("external:*,!{ID}"), ID, URL));
        // The id itself ends it before a later exclusion is read.
        assert!(matches_pattern(&format!("{ID},!{ID}"), ID, URL));
        // A segment is compared as written: a space before `!` makes it
        // no exclusion (the mirror takes the repository), and one around
        // an id makes it another id.
        assert!(matches_pattern(&format!("*, !{ID}"), ID, URL));
        assert!(!matches_pattern(&format!("central , {ID}"), ID, URL));
        // An id is a whole id: no pattern excludes a family of them.
        assert!(matches_pattern("*,!socket-patch-*", ID, URL));
        assert!(matches_pattern("*,!socket-patch", ID, URL));
        // A lone `!` is not an exclusion, and matches nothing.
        assert!(!matches_pattern("!", ID, URL));
        assert!(!matches_pattern("", ID, URL));
    }

    /// A mirror that lists the repository's id among others was written
    /// for it: whoever runs that mirror chose to serve the Socket
    /// repository there, so it is no capture (and excluding the id from a
    /// list that names it would change nothing).
    #[test]
    fn a_mirror_that_lists_the_repository_is_no_capture() {
        for of in [
            format!("central,{ID}"),
            format!("{ID},central"),
            format!("*,{ID}"),
            format!("external:*,{ID},!other"),
        ] {
            let mirrors = vec![mirror("internal", &of)];
            assert_eq!(
                select(&mirrors, ID, URL).map(|(m, named)| (m.id.as_str(), named)),
                Some(("internal", true)),
                "{of}"
            );
            assert_eq!(capturing(&[mirrors], ID, URL), None, "{of}");
        }
        // Naming another id, or the id with a space before it (a segment
        // is compared as written), is not naming this repository.
        for of in ["*,central".to_string(), format!("*, {ID}")] {
            let mirrors = vec![mirror("corp", &of)];
            assert_eq!(
                capturing(&[mirrors], ID, URL).map(|m| m.id.as_str()),
                Some("corp"),
                "{of}"
            );
        }
    }

    #[test]
    fn a_mirror_of_the_repository_alone_wins_over_any_pattern() {
        let mirrors = [mirror("corp", "*"), mirror("socket", ID)];
        let (chosen, exact) = select(&mirrors, ID, URL).unwrap();
        assert_eq!((chosen.id.as_str(), exact), ("socket", true));
        assert_eq!(capturing(&[mirrors.to_vec()], ID, URL), None);
        // Without it, the first matching pattern in settings order.
        let mirrors = [
            mirror("only-central", "central"),
            mirror("corp", "external:*"),
            mirror("all", "*"),
        ];
        let (chosen, exact) = select(&mirrors, ID, URL).unwrap();
        assert_eq!((chosen.id.as_str(), exact), ("corp", false));
        assert_eq!(
            capturing(&[vec![], mirrors.to_vec()], ID, URL).map(|m| m.id.as_str()),
            Some("corp")
        );
        // The blocker Maven 3.8.1+ ships matches plain HTTP only.
        let blocker = [mirror("maven-default-http-blocker", "external:http:*")];
        assert_eq!(select(&blocker, ID, URL), None);
        assert_eq!(select(&[], ID, URL), None);
    }

    #[test]
    fn a_mirror_for_another_layout_is_not_chosen() {
        let layouts = |l: &str| Mirror {
            layouts: Some(l.into()),
            ..mirror("corp", "*")
        };
        for accepted in ["", "*", "default", "legacy,default", "*,!legacy"] {
            assert!(
                select(&[layouts(accepted)], ID, URL).is_some(),
                "{accepted}"
            );
        }
        for refused in ["legacy", "*,!default", "!default,*", "p2"] {
            assert_eq!(select(&[layouts(refused)], ID, URL), None, "{refused}");
        }
    }

    #[test]
    fn the_user_settings_shadow_a_global_mirror_of_the_same_id() {
        let merged = merge(
            vec![mirror("corp", "central")],
            vec![mirror("corp", "*"), mirror("blocker", "external:http:*")],
        );
        let ids: Vec<(&str, &str)> = merged
            .iter()
            .map(|m| (m.id.as_str(), m.mirror_of.as_str()))
            .collect();
        assert_eq!(ids, [("corp", "central"), ("blocker", "external:http:*")]);
        assert_eq!(capturing(&[merged], ID, URL), None);
    }
}
