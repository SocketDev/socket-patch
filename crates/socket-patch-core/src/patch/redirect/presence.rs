//! One-pass substring presence for many needle groups over a few texts.
//!
//! The hosted confirmation probe asks, for every candidate, whether any of its
//! needles (artifact url in each spelling, index url, maven suffixed version…)
//! occurs in any of the run's final lock texts. Asking that one candidate at a
//! time with `str::contains` costs O(candidates × total text bytes), which on a
//! monorepo with hundreds of patched packages and multi-MB locks is the largest
//! single-threaded term of a hosted run. [`groups_present`] answers the same
//! question for every group with one Aho-Corasick pass over each text.
//!
//! Substring presence does not depend on the order in which texts or needles
//! are searched, so the answer is the per-group `any()` exactly; the result
//! vector is in group order.

use std::collections::HashMap;

use aho_corasick::AhoCorasick;

/// For each group, whether ANY of its needles is a substring of ANY text.
///
/// Exactly `groups.map(|g| g.iter().any(|n| texts.iter().any(|t| t.contains(n))))`,
/// including its edge cases: an empty needle is contained in every text (so
/// it is present iff there is at least one text), and an empty group is never
/// present.
pub fn groups_present<T, G, N>(texts: &[T], groups: &[G]) -> Vec<bool>
where
    T: AsRef<str>,
    G: AsRef<[N]>,
    N: AsRef<str>,
{
    // Dedup needles: candidates often share an index url (a bare patch-server
    // origin), and one automaton pattern per distinct needle keeps it small.
    let mut ids: HashMap<&str, usize> = HashMap::new();
    let mut patterns: Vec<&str> = Vec::new();
    let group_ids: Vec<Vec<usize>> = groups
        .iter()
        .map(|group| {
            group
                .as_ref()
                .iter()
                .filter_map(|needle| {
                    let needle = needle.as_ref();
                    // Answered below without the automaton.
                    if needle.is_empty() {
                        return None;
                    }
                    Some(*ids.entry(needle).or_insert_with(|| {
                        patterns.push(needle);
                        patterns.len() - 1
                    }))
                })
                .collect()
        })
        .collect();

    let mut hit = vec![false; patterns.len()];
    if !patterns.is_empty() && !texts.is_empty() {
        // Standard match semantics + overlapping search reports EVERY
        // occurrence of every pattern, so no needle can be shadowed by a
        // longer or earlier one that overlaps it.
        let ac = AhoCorasick::new(&patterns)
            .expect("aho-corasick automaton over non-empty literal needles");
        let mut remaining = patterns.len();
        'texts: for text in texts {
            for m in ac.find_overlapping_iter(text.as_ref()) {
                let id = m.pattern().as_usize();
                if !hit[id] {
                    hit[id] = true;
                    remaining -= 1;
                    if remaining == 0 {
                        break 'texts;
                    }
                }
            }
        }
    }

    let any_text = !texts.is_empty();
    groups
        .iter()
        .zip(&group_ids)
        .map(|(group, ids)| {
            ids.iter().any(|&id| hit[id])
                || (any_text && group.as_ref().iter().any(|n| n.as_ref().is_empty()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-group `any()` this module replaces — the oracle.
    fn naive<T: AsRef<str>, N: AsRef<str>>(texts: &[T], groups: &[Vec<N>]) -> Vec<bool> {
        groups
            .iter()
            .map(|g| {
                g.iter()
                    .any(|n| texts.iter().any(|t| t.as_ref().contains(n.as_ref())))
            })
            .collect()
    }

    fn check(texts: &[&str], groups: &[Vec<&str>]) {
        assert_eq!(
            groups_present(texts, groups),
            naive(texts, groups),
            "texts={texts:?} groups={groups:?}"
        );
    }

    #[test]
    fn edge_cases_match_contains() {
        check(&[], &[vec!["a"], vec![""], vec![]]);
        check(&[""], &[vec!["a"], vec![""], vec![]]);
        check(&["abc"], &[vec![], vec![""], vec!["", "zzz"], vec!["zzz"]]);
        // Overlapping and nested needles are each reported.
        check(
            &["abcd"],
            &[vec!["abc"], vec!["bc"], vec!["bcd"], vec!["abcde"]],
        );
        check(&["aaaa"], &[vec!["aa"], vec!["aaa"], vec!["aaaaa"]]);
        // A needle split across two texts is not present.
        check(&["ab", "cd"], &[vec!["bc"], vec!["cd"], vec!["ab", "x"]]);
        // Shared needles across groups, and duplicates within one.
        check(
            &["http://h/x.tgz"],
            &[vec!["http://h", "http://h"], vec!["http://h"], vec!["y"]],
        );
        // Multi-byte UTF-8.
        check(
            &["héllo wörld"],
            &[vec!["ö"], vec!["é"], vec!["o w"], vec!["ü"]],
        );
        // Escaped spellings.
        check(
            &[r#"{"url":"https:\/\/p\/a.zip"}"#],
            &[
                vec!["https://p/a.zip", r"https:\/\/p\/a.zip"],
                vec!["https://p/a.zip"],
            ],
        );
    }

    #[test]
    fn pseudo_random_corpus_matches_contains() {
        // Small alphabet so needles hit, miss, overlap and nest often.
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let alphabet = ['a', 'b', '/', '\\', '%'];
        let mut word = |max: u64, next: &mut dyn FnMut() -> u64| -> String {
            let len = next() % (max + 1);
            (0..len)
                .map(|_| alphabet[(next() % alphabet.len() as u64) as usize])
                .collect()
        };
        for _ in 0..400 {
            let texts: Vec<String> = (0..next() % 4).map(|_| word(40, &mut next)).collect();
            let groups: Vec<Vec<String>> = (0..next() % 8)
                .map(|_| (0..next() % 4).map(|_| word(5, &mut next)).collect())
                .collect();
            assert_eq!(
                groups_present(&texts, &groups),
                naive(&texts, &groups),
                "texts={texts:?} groups={groups:?}"
            );
        }
    }
}
