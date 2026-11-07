//! Maven property interpolation, shared by VEX discovery ([`super::PomScope`])
//! and the vendored reactor planner, so both read a `${…}` the same way:
//! Maven's lookup order ([`lookup_property`]), one bounded interpolator
//! ([`interpolate_strict`] / [`interpolate_lenient`]), and the profile
//! combinations that may change a value ([`profile_combinations`]). Pure.

use std::collections::{BTreeMap, BTreeSet};

/// Nesting depth past which interpolation gives up: a property named
/// through more than this many others (Maven itself fails on a cycle,
/// which this bounds too).
pub(crate) const MAX_INTERPOLATION_DEPTH: usize = 16;

/// Most lookups one interpolation makes before giving up: a value naming
/// the next property many times over would otherwise cost exponentially
/// many with every level ("billion laughs").
const MAX_LOOKUPS: usize = 1024;

/// Longest text one interpolation builds before giving up.
pub(crate) const MAX_RESOLVED_LEN: usize = 4096;

/// Most profiles whose every combination [`profile_combinations`] lists
/// (2^8 - 1 combinations); a value more profiles may change is not
/// enumerated (the caller fails closed).
pub(crate) const MAX_COMBINED_PROFILES: usize = 8;

/// A `project.*` / `pom.*` reference: Maven reads it from the model, ahead
/// of any user or pom property of the same name.
pub(crate) fn is_model_reference(name: &str) -> bool {
    name.starts_with("project.") || name.starts_with("pom.")
}

/// One pom's `<properties>` as Maven reads them with `profiles` active:
/// each active profile's merged over the pom's own, a later one (in pom
/// order) winning.
pub(crate) struct PomLayer<'a> {
    pub(crate) own: &'a BTreeMap<String, String>,
    pub(crate) profiles: Vec<&'a BTreeMap<String, String>>,
}

impl PomLayer<'_> {
    fn get(&self, name: &str) -> Option<&String> {
        self.profiles
            .iter()
            .rev()
            .find_map(|p| p.get(name))
            .or_else(|| self.own.get(name))
    }
}

/// What `${name}` reads, in Maven's model interpolator's order: a
/// `project.*` / `pom.*` reference the model (`model`) answers, then the
/// build's user properties (`.mvn/maven.config`'s `-D`), then each pom's
/// properties with its active profiles merged in (`layers`, nearest pom
/// first — a child's beat its parent's), then a deprecated bare model
/// reference (`${version}`) `model` answers. The value is returned raw:
/// [`interpolate_strict`] resolves what it names in turn.
pub(crate) fn lookup_property<'a>(
    name: &str,
    model: &dyn Fn(&str) -> Option<String>,
    user: &BTreeMap<String, String>,
    layers: impl IntoIterator<Item = PomLayer<'a>>,
) -> Option<String> {
    if is_model_reference(name) {
        if let Some(v) = model(name) {
            return Some(v);
        }
    }
    if let Some(v) = user.get(name) {
        return Some(v.clone());
    }
    for layer in layers {
        if let Some(v) = layer.get(name) {
            return Some(v.clone());
        }
    }
    if is_model_reference(name) {
        None
    } else {
        model(name)
    }
}

/// An interpolation of a text through a lookup: [`interpolate_strict`],
/// or a keep-unresolved one built on [`interpolate_lenient`].
pub(crate) type Interpolate = fn(&str, &dyn Fn(&str) -> Option<String>) -> Option<String>;

/// `value` with every `${name}` replaced by `lookup(name)`, itself
/// interpolated the same way, as Maven's model interpolator resolves a
/// property defined through another. `None` when a name is undefined, a
/// `${` is unterminated, a name is reached through itself (a cycle) or
/// through more than [`MAX_INTERPOLATION_DEPTH`] others, or the work
/// bounds are hit: an unresolved value never stands for a version.
pub(crate) fn interpolate_strict(
    value: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    let lookups = std::cell::Cell::new(MAX_LOOKUPS);
    expand(value, lookup, &mut Vec::new(), &lookups, false)
}

/// [`interpolate_strict`] for a coordinate, where an unresolved reference
/// must stay visible: an undefined, cyclic or too deeply nested `${name}`
/// (or an unterminated `${`) is kept as written, so
/// [`may_name`](super::may_name) can treat it as unknown text; past the
/// work bounds the whole value is returned as written.
pub(crate) fn interpolate_lenient(value: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    let lookups = std::cell::Cell::new(MAX_LOOKUPS);
    expand(value, lookup, &mut Vec::new(), &lookups, true).unwrap_or_else(|| value.to_string())
}

/// [`interpolate_lenient`] as an [`Interpolate`] (it always gives a text).
pub(crate) fn interpolate_keeping(
    value: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
    Some(interpolate_lenient(value, lookup))
}

fn expand(
    value: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    stack: &mut Vec<String>,
    lookups: &std::cell::Cell<usize>,
    keep: bool,
) -> Option<String> {
    let mut out = String::new();
    let mut rest = value;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        let Some(close) = after.find('}') else {
            if !keep {
                return None;
            }
            out.push_str(&rest[at..]);
            rest = "";
            break;
        };
        let name = &after[..close];
        let reference = &rest[at..at + close + 3];
        rest = &after[close + 1..];
        let resolved = if stack.len() >= MAX_INTERPOLATION_DEPTH || stack.iter().any(|n| n == name)
        {
            None
        } else {
            lookups.set(lookups.get().checked_sub(1)?);
            match lookup(name) {
                Some(raw) => {
                    stack.push(name.to_string());
                    let v = expand(&raw, lookup, stack, lookups, keep);
                    stack.pop();
                    Some(v?)
                }
                None => None,
            }
        };
        match resolved {
            Some(v) => out.push_str(&v),
            None if keep => out.push_str(reference),
            None => return None,
        }
        if out.len() > MAX_RESOLVED_LEN {
            return None;
        }
    }
    out.push_str(rest);
    (out.len() <= MAX_RESOLVED_LEN).then_some(out)
}

/// The names `text` references (`${name}`), in order.
fn references(text: &str) -> impl Iterator<Item = &str> {
    let mut rest = text;
    std::iter::from_fn(move || {
        let at = rest.find("${")?;
        let after = &rest[at + 2..];
        let close = after.find('}')?;
        rest = &after[close + 1..];
        Some(&after[..close])
    })
}

/// Where `${name}` may be defined, for [`profile_combinations`]: every raw
/// text it may read under some set of active profiles (the model's, a
/// user property, a pom's, a profile's), and the profiles whose own
/// definition may be the one read (none when something Maven reads first,
/// a model reference or a user property, fixes it).
#[derive(Default)]
pub(crate) struct Definitions {
    pub(crate) texts: Vec<String>,
    pub(crate) profiles: Vec<usize>,
}

/// Every nonempty combination of the profiles that may change what any of
/// `values` interpolates to — those defining a name reachable from one
/// through any definition ([`Definitions`]) — smallest first, each sorted:
/// Maven activates any number of profiles together, so a value two
/// profiles move only jointly is caught, and the texts of one declaration
/// (its groupId, artifactId and version) are read under the same
/// combinations. Empty when no profile can change them. `None` when more
/// than [`MAX_COMBINED_PROFILES`] may, or the walk exceeds its bound: the
/// caller fails closed.
pub(crate) fn profile_combinations(
    values: &[&str],
    defs: &dyn Fn(&str) -> Definitions,
) -> Option<Vec<Vec<usize>>> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = values
        .iter()
        .flat_map(|v| references(v))
        .map(str::to_string)
        .collect();
    let mut relevant: BTreeSet<usize> = BTreeSet::new();
    while let Some(name) = queue.pop() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if seen.len() > MAX_LOOKUPS {
            return None;
        }
        let d = defs(&name);
        relevant.extend(d.profiles);
        for text in &d.texts {
            queue.extend(references(text).map(str::to_string));
        }
    }
    if relevant.len() > MAX_COMBINED_PROFILES {
        return None;
    }
    let relevant: Vec<usize> = relevant.into_iter().collect();
    let mut masks: Vec<u32> = (1..(1u32 << relevant.len())).collect();
    masks.sort_by_key(|m| (m.count_ones(), *m));
    Some(
        masks
            .into_iter()
            .map(|m| {
                (0..relevant.len())
                    .filter(|i| m & (1 << i) != 0)
                    .map(|i| relevant[i])
                    .collect()
            })
            .collect(),
    )
}

/// The `name -> trimmed value` pairs of a `<properties>` body, into `map`
/// (a name's first definition wins). An element's name is its tag up to
/// whitespace or `/`, so `<v combine.self="override">` and `<v >` define
/// `v`, and `<v/>` defines it empty; a comment-blanked or malformed child
/// is an error (fail closed).
pub(crate) fn read_properties(
    body: &str,
    map: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let mut from = 0;
    while let Some(rel) = body[from..].find('<') {
        let lt = from + rel;
        let Some(gt) = body[lt..].find('>').map(|r| lt + r) else {
            return Err("unterminated tag in <properties>".to_string());
        };
        let tag = &body[lt + 1..gt];
        let name_end = tag
            .find(|c: char| c.is_ascii_whitespace() || c == '/')
            .unwrap_or(tag.len());
        let name = &tag[..name_end];
        if !super::is_property_name(name) {
            from = gt + 1;
            continue;
        }
        // A later definition replaces an earlier one, as Maven's model
        // reader's `Properties.put` does.
        if tag.ends_with('/') {
            map.insert(name.to_string(), String::new());
            from = gt + 1;
            continue;
        }
        // `</name>`, with optional whitespace before the `>`.
        let close = format!("</{name}");
        let mut search = gt + 1;
        let (end, after) = loop {
            let Some(at) = body[search..].find(&close).map(|r| search + r) else {
                return Err(format!("unterminated <{name}> in <properties>"));
            };
            let tail = &body[at + close.len()..];
            let ws = tail.len() - tail.trim_start().len();
            if tail[ws..].starts_with('>') {
                break (at, at + close.len() + ws + 1);
            }
            search = at + close.len();
        };
        map.insert(name.to_string(), body[gt + 1..end].trim().to_string());
        from = after;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn strict_and_lenient_share_one_expansion() {
        let props = map(&[("a", "${b}"), ("b", "1"), ("c", "${c}"), ("d", "x${e}")]);
        let lookup = |n: &str| props.get(n).cloned();
        assert_eq!(interpolate_strict("v${a}", &lookup).as_deref(), Some("v1"));
        assert_eq!(interpolate_strict("${c}", &lookup), None, "cycle");
        assert_eq!(interpolate_strict("${d}", &lookup), None, "undefined");
        assert_eq!(interpolate_strict("${a", &lookup), None, "unterminated");
        assert_eq!(interpolate_lenient("v${a}", &lookup), "v1");
        assert_eq!(interpolate_lenient("${c}-${a}", &lookup), "${c}-1");
        assert_eq!(interpolate_lenient("${d}", &lookup), "x${e}");
        assert_eq!(interpolate_lenient("${a", &lookup), "${a");
    }

    #[test]
    fn lookup_follows_mavens_order() {
        let model = |n: &str| match n {
            "project.version" => Some("9".to_string()),
            "version" => Some("bare".to_string()),
            _ => None,
        };
        let user = map(&[("u", "user"), ("project.version", "no"), ("p", "user")]);
        let own = map(&[("p", "pom"), ("q", "pom"), ("version", "prop")]);
        let first = map(&[("q", "first"), ("r", "first")]);
        let second = map(&[("r", "second")]);
        let layer = || PomLayer {
            own: &own,
            profiles: vec![&first, &second],
        };
        let get = |n: &str| lookup_property(n, &model, &user, [layer()]);
        assert_eq!(get("project.version").as_deref(), Some("9"));
        assert_eq!(get("p").as_deref(), Some("user"));
        assert_eq!(get("q").as_deref(), Some("first"));
        assert_eq!(get("r").as_deref(), Some("second"), "a later profile wins");
        assert_eq!(get("version").as_deref(), Some("prop"));
        let empty = BTreeMap::new();
        let bare = lookup_property("version", &model, &empty, []);
        assert_eq!(bare.as_deref(), Some("bare"));
        assert_eq!(get("project.other"), None);
    }

    #[test]
    fn combinations_cover_the_relevant_profiles_only() {
        // v -> w; profile 0 defines v, profile 1 w, profile 2 only x.
        let defs = |n: &str| match n {
            "v" => Definitions {
                texts: vec!["${w}".into(), "1".into()],
                profiles: vec![0],
            },
            "w" => Definitions {
                texts: vec!["1".into()],
                profiles: vec![1],
            },
            _ => Definitions {
                texts: vec![],
                profiles: vec![2],
            },
        };
        assert_eq!(
            profile_combinations(&["${v}"], &defs),
            Some(vec![vec![0], vec![1], vec![0, 1]])
        );
        assert_eq!(profile_combinations(&["1.0"], &defs), Some(vec![]));
        let many = |_: &str| Definitions {
            texts: vec![],
            profiles: (0..=MAX_COMBINED_PROFILES).collect(),
        };
        assert_eq!(profile_combinations(&["${v}"], &many), None);
    }

    #[test]
    fn properties_read_attributed_and_spaced_tags() {
        let mut m = BTreeMap::new();
        read_properties(
            "<a x=\"y\">1</a><b >2</b ><c\n>3</c><d/><e />\
             <f>4</f><f>5</f>",
            &mut m,
        )
        .unwrap();
        assert_eq!(
            m,
            map(&[
                ("a", "1"),
                ("b", "2"),
                ("c", "3"),
                ("d", ""),
                ("e", ""),
                ("f", "5")
            ])
        );
        assert!(read_properties("<a>1", &mut BTreeMap::new()).is_err());
    }
}
