//! Maven's version order and version ranges, as its resolver reads them
//! (`GenericVersion` / `GenericVersionRange` of maven-resolver-util): what
//! decides which version a range selects and which of two siblings wins.

use std::cmp::Ordering;

/// One token of a version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Item {
    /// The `min` a `[1.*]` range ends its lower bound with.
    Min,
    /// `alpha` (-5) … `sp` (1); `ga` / `final` / `release` are 0.
    Qualifier(i32),
    /// Any other word, lowercased.
    Word(String),
    /// A number of fewer than ten digits.
    Int(u32),
    /// A longer number: its digits, without leading zeros.
    Big(String),
    /// The `max` a `[1.*]` range ends its upper bound with.
    Max,
}

impl Item {
    fn kind(&self) -> u8 {
        match self {
            Item::Min => 0,
            Item::Qualifier(_) => 2,
            Item::Word(_) => 3,
            Item::Int(_) => 4,
            Item::Big(_) => 5,
            Item::Max => 8,
        }
    }

    fn is_number(&self) -> bool {
        !matches!(self, Item::Qualifier(_) | Item::Word(_))
    }

    /// Against the padding item (`0`, or the empty qualifier).
    fn cmp_padding(&self) -> Ordering {
        match self {
            Item::Min => Ordering::Less,
            Item::Max | Item::Big(_) | Item::Word(_) => Ordering::Greater,
            Item::Int(n) => n.cmp(&0),
            Item::Qualifier(q) => q.cmp(&0),
        }
    }

    fn cmp_item(&self, other: &Item) -> Ordering {
        match (self, other) {
            (Item::Qualifier(a), Item::Qualifier(b)) => a.cmp(b),
            (Item::Int(a), Item::Int(b)) => a.cmp(b),
            (Item::Word(a), Item::Word(b)) => a.cmp(b),
            (Item::Big(a), Item::Big(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
            _ => self.kind().cmp(&other.kind()),
        }
    }
}

/// A version in Maven's order.
#[derive(Debug, Clone)]
pub(crate) struct MavenVersion {
    items: Vec<Item>,
}

impl MavenVersion {
    pub(crate) fn parse(version: &str) -> MavenVersion {
        let text: Vec<char> = if version.is_empty() {
            vec!['0']
        } else {
            version.chars().collect()
        };
        let mut items = Vec::new();
        let mut index = 0;
        while index < text.len() {
            // -2: nothing read, -1: a word, 0: leading zeros, 1: a number.
            let mut state = -2;
            let mut start = index;
            let mut end = text.len();
            let mut terminated_by_number = false;
            while index < text.len() {
                let c = text[index];
                if matches!(c, '.' | '-' | '_') {
                    end = index;
                    index += 1;
                    break;
                }
                if let Some(digit) = c.to_digit(10) {
                    if state == -1 {
                        end = index;
                        terminated_by_number = true;
                        break;
                    }
                    if state == 0 {
                        start += 1;
                    }
                    state = i32::from(state > 0 || digit > 0);
                } else {
                    if state >= 0 {
                        end = index;
                        break;
                    }
                    state = -1;
                }
                index += 1;
            }
            let (token, number): (String, bool) = if end > start {
                (text[start..end].iter().collect(), state >= 0)
            } else {
                ("0".to_string(), true)
            };
            items.push(if number {
                // Unicode digits other than 0-9 do not parse: such a
                // version only ever compares with itself here.
                match (token.len() < 10)
                    .then(|| token.parse::<u32>().ok())
                    .flatten()
                {
                    Some(n) => Item::Int(n),
                    None => Item::Big(token),
                }
            } else {
                let lower = token.to_lowercase();
                let last = index >= text.len();
                match lower.as_str() {
                    "min" if last => Item::Min,
                    "max" if last => Item::Max,
                    "a" if terminated_by_number => Item::Qualifier(-5),
                    "b" if terminated_by_number => Item::Qualifier(-4),
                    "m" if terminated_by_number => Item::Qualifier(-3),
                    "alpha" => Item::Qualifier(-5),
                    "beta" => Item::Qualifier(-4),
                    "milestone" => Item::Qualifier(-3),
                    "cr" | "rc" => Item::Qualifier(-2),
                    "snapshot" => Item::Qualifier(-1),
                    "ga" | "final" | "release" => Item::Qualifier(0),
                    "sp" => Item::Qualifier(1),
                    _ => Item::Word(lower),
                }
            });
        }
        trim_padding(&mut items);
        MavenVersion { items }
    }
}

/// Drop the trailing run of padding items of each kind (`1.0.0` is `1`,
/// `1-ga` is `1`).
fn trim_padding(items: &mut Vec<Item>) {
    let mut number: Option<bool> = None;
    let mut end = items.len().saturating_sub(1);
    let mut i = end;
    while i > 0 {
        let is_number = items[i].is_number();
        if number != Some(is_number) {
            end = i;
            number = Some(is_number);
        }
        if end == i
            && (i == items.len() - 1 || items[i - 1].is_number() == is_number)
            && items[i].cmp_padding() == Ordering::Equal
        {
            items.remove(i);
            end = end.saturating_sub(1);
        }
        i -= 1;
    }
}

/// How the items of `items` from `index` on compare with padding; with
/// `number`, only the items of that kind are read.
fn compare_padding(items: &[Item], index: usize, number: Option<bool>) -> Ordering {
    for item in &items[index..] {
        if number.is_some_and(|n| n != item.is_number()) {
            continue;
        }
        let rel = item.cmp_padding();
        if rel != Ordering::Equal {
            return rel;
        }
    }
    Ordering::Equal
}

impl Ord for MavenVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let (these, those) = (&self.items, &other.items);
        let mut number = true;
        let mut index = 0;
        loop {
            match (these.get(index), those.get(index)) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return compare_padding(those, index, None).reverse(),
                (Some(_), None) => return compare_padding(these, index, None),
                (Some(this), Some(that)) => {
                    if this.is_number() != that.is_number() {
                        return if number == this.is_number() {
                            compare_padding(these, index, Some(number))
                        } else {
                            compare_padding(those, index, Some(number)).reverse()
                        };
                    }
                    let rel = this.cmp_item(that);
                    if rel != Ordering::Equal {
                        return rel;
                    }
                    number = this.is_number();
                }
            }
            index += 1;
        }
    }
}

impl PartialOrd for MavenVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for MavenVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for MavenVersion {}

/// One `[a,b)` of a version requirement.
#[derive(Debug, Clone)]
struct Bounds {
    lower: Option<(MavenVersion, bool)>,
    upper: Option<(MavenVersion, bool)>,
}

impl Bounds {
    fn contains(&self, version: &MavenVersion) -> bool {
        if let Some((bound, inclusive)) = &self.lower {
            match bound.cmp(version) {
                Ordering::Greater => return false,
                Ordering::Equal if !inclusive => return false,
                _ => {}
            }
        }
        if let Some((bound, inclusive)) = &self.upper {
            match bound.cmp(version) {
                Ordering::Less => return false,
                Ordering::Equal if !inclusive => return false,
                _ => {}
            }
        }
        true
    }
}

/// A hard version requirement: the union of one or more ranges
/// (`[1.0,2.0)`, `(,1.0],[1.2,)`, `[1.5]`, `[1.*]`).
#[derive(Debug, Clone)]
pub(crate) struct VersionRange {
    ranges: Vec<Bounds>,
    /// The one version of `[1.5]`, which Maven resolves without listing
    /// the artifact's versions.
    exact: Option<String>,
}

impl VersionRange {
    /// `spec` as a range; `None` when it is a plain (soft) version or not
    /// a requirement Maven accepts.
    pub(crate) fn parse(spec: &str) -> Option<VersionRange> {
        let mut rest = spec.trim();
        if !rest.starts_with(['[', '(']) {
            return None;
        }
        let mut ranges = Vec::new();
        let mut exact = None;
        while rest.starts_with(['[', '(']) {
            let close = rest.find([')', ']'])?;
            let (bounds, single) = parse_bounds(&rest[..=close])?;
            exact = single;
            ranges.push(bounds);
            rest = rest[close + 1..].trim();
            if let Some(more) = rest.strip_prefix(',') {
                rest = more.trim();
            }
        }
        if !rest.is_empty() {
            return None;
        }
        let exact = exact.filter(|_| ranges.len() == 1);
        Some(VersionRange { ranges, exact })
    }

    pub(crate) fn contains(&self, version: &str) -> bool {
        let version = MavenVersion::parse(version);
        self.ranges.iter().any(|r| r.contains(&version))
    }

    /// The single version of an exact requirement (`[1.5]`).
    pub(crate) fn exact(&self) -> Option<&str> {
        self.exact.as_deref()
    }
}

/// One bracketed range and, for `[v]`, that version.
fn parse_bounds(range: &str) -> Option<(Bounds, Option<String>)> {
    let lower_inclusive = range.starts_with('[');
    let upper_inclusive = range.ends_with(']');
    let inner = range.get(1..range.len() - 1)?;
    let Some((low, high)) = inner.split_once(',') else {
        if !lower_inclusive || !upper_inclusive {
            return None;
        }
        let version = inner.trim();
        if let Some(prefix) = version.strip_suffix('*').filter(|p| p.ends_with('.')) {
            return Some((
                Bounds {
                    lower: Some((MavenVersion::parse(&format!("{prefix}min")), true)),
                    upper: Some((MavenVersion::parse(&format!("{prefix}max")), true)),
                },
                None,
            ));
        }
        let bound = MavenVersion::parse(version);
        return Some((
            Bounds {
                lower: Some((bound.clone(), true)),
                upper: Some((bound, true)),
            },
            Some(version.to_string()),
        ));
    };
    let (low, high) = (low.trim(), high.trim());
    if high.contains(',') {
        return None;
    }
    let lower = (!low.is_empty()).then(|| MavenVersion::parse(low));
    let upper = (!high.is_empty()).then(|| MavenVersion::parse(high));
    if let (Some(l), Some(u)) = (&lower, &upper) {
        if u < l {
            return None;
        }
    }
    Some((
        Bounds {
            lower: lower.map(|v| (v, lower_inclusive)),
            upper: upper.map(|v| (v, upper_inclusive)),
        },
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> Ordering {
        MavenVersion::parse(a).cmp(&MavenVersion::parse(b))
    }

    #[test]
    fn versions_order_as_maven_orders_them() {
        // Ascending, each strictly below the next.
        let ascending = [
            "1.0-alpha-1",
            "1.0-alpha-2",
            "1.0-beta-1",
            "1.0-milestone-1",
            "1.0-rc-1",
            "1.0-SNAPSHOT",
            "1.0",
            "1.0-sp",
            "1.0-abc",
            "1.0.1",
            "1.1",
            "1.2",
            "1.10",
            "2.0",
            "2.7.9.2",
            "2.9.0",
            "2.9.10",
            "2.9.10.8",
            "2.10.0",
            "10.0",
        ];
        for pair in ascending.windows(2) {
            assert_eq!(cmp(pair[0], pair[1]), Ordering::Less, "{pair:?}");
            assert_eq!(cmp(pair[1], pair[0]), Ordering::Greater, "{pair:?}");
        }
    }

    #[test]
    fn equal_spellings_compare_equal() {
        for (a, b) in [
            ("1", "1.0"),
            ("1.0", "1.0.0"),
            ("1.0", "1-ga"),
            ("1.0", "1.0-final"),
            ("1.0-rc1", "1.0-cr1"),
            ("1.0a1", "1.0-alpha-1"),
            ("1.0b2", "1.0-beta-2"),
            ("1.0m3", "1.0-milestone-3"),
            ("1.0-RC1", "1.0-rc1"),
            ("1.0.0-RELEASE", "1"),
            ("01.2", "1.2"),
        ] {
            assert_eq!(cmp(a, b), Ordering::Equal, "{a} vs {b}");
        }
    }

    #[test]
    fn suffixed_versions_sort_above_their_base() {
        assert_eq!(cmp("2.7.9.2-socket.8e82692a", "2.7.9.2"), Ordering::Greater);
        assert_eq!(cmp("2.7.9.2-socket.8e82692a", "2.7.9.3"), Ordering::Less);
    }

    #[test]
    fn long_numbers_compare_by_value() {
        assert_eq!(
            cmp("1.20260101000000", "1.20250101000000"),
            Ordering::Greater
        );
        assert_eq!(cmp("1.20260101000000", "1.999999999"), Ordering::Greater);
    }

    #[test]
    fn ranges_admit_what_maven_admits() {
        let range = VersionRange::parse("[2.9.0,2.9.10]").unwrap();
        for v in ["2.9.0", "2.9.5", "2.9.10"] {
            assert!(range.contains(v), "{v}");
        }
        for v in ["2.7.9.2", "2.8.11", "2.9.10.1", "2.10.0", "2.9.0-rc1"] {
            assert!(!range.contains(v), "{v}");
        }
        let half_open = VersionRange::parse("[1.9,1.11)").unwrap();
        assert!(half_open.contains("1.9") && half_open.contains("1.10.0"));
        assert!(!half_open.contains("1.11") && !half_open.contains("1.8"));
        let unbounded = VersionRange::parse("(,1.0],[1.2,)").unwrap();
        assert!(unbounded.contains("0.5") && unbounded.contains("1.0") && unbounded.contains("3"));
        assert!(!unbounded.contains("1.1"));
        let prefix = VersionRange::parse("[1.2.*]").unwrap();
        assert!(prefix.contains("1.2.0") && prefix.contains("1.2.99"));
        assert!(!prefix.contains("1.3") && !prefix.contains("1.1.9"));
    }

    #[test]
    fn an_exact_requirement_names_its_version() {
        let exact = VersionRange::parse("[1.5]").unwrap();
        assert_eq!(exact.exact(), Some("1.5"));
        assert!(exact.contains("1.5") && !exact.contains("1.5.1"));
        assert_eq!(VersionRange::parse("[1.0,2.0)").unwrap().exact(), None);
    }

    #[test]
    fn plain_versions_and_malformed_ranges_are_not_ranges() {
        for spec in [
            "1.0",
            "",
            "LATEST",
            "[1.0",
            "(1.0)",
            "[2.0,1.0]",
            "[1,2,3]",
            "[1,2) x",
        ] {
            assert!(VersionRange::parse(spec).is_none(), "{spec}");
        }
    }
}
