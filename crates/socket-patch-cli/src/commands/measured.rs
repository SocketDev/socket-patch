//! What Socket measured about a patch, for human output: whether it
//! blocks the exploits of the advisories it fixes, whether the package's
//! own tests still pass, how large it is and what it costs at run time
//! (the patch view's `statistics`, see [`PatchStatistics`]).
//!
//! The wording is pure and unit-tested; [`fetch`] is the one request.
//! Measurements are a courtesy to someone reading the output: they are
//! asked for only when stdout is a terminal ([`wanted`]), and a patch that
//! was never measured, or whose answer fails, simply shows none.

use std::collections::HashMap;

use socket_patch_core::api::client::{hold_back_debug, ApiClient, ApiError, HeldBack};
use socket_patch_core::api::types::{PatchRatio, PatchStatistics};

use crate::args::GlobalArgs;
use crate::ui::plural;

/// What the patch service measured, by patch uuid.
pub(crate) type Measured = HashMap<String, PatchStatistics>;

/// One patch's measurement request: its uuid, and the answer with its
/// `--debug` lines held back until the caller's turn to print.
pub(crate) type Measurement = (String, HeldBack<Result<Option<PatchStatistics>, ApiError>>);

/// How long a listing waits for its measurements ([`fetch`]). The ones
/// still out by then are left off: a listing is not held up for a
/// courtesy.
const LISTING_WAIT: std::time::Duration = std::time::Duration::from_millis(1500);

/// Whether this run shows measurements: a human run (neither `--json` nor
/// `--silent`) whose stdout is a terminal. A pipe, a log and a script make
/// no extra request and read the same every time.
pub(crate) fn wanted(common: &GlobalArgs) -> bool {
    !common.json && !common.silent && crate::ui::attended(crate::ui::Stream::Stdout)
}

/// Ask the patch service what it measured about each of `uuids`.
/// Answers come back as they arrive.
///
/// The requests are a courtesy beside the run's real ones, so they stay
/// out of their way: they keep to the patch API's own window (the public
/// proxy's is small, and one request at a time where file descriptors
/// are scarce), and one that is throttled is given up, not retried. A
/// retry would open the run's one retry window, which the downloads that
/// follow may need.
///
/// Every request takes a slot of `window` first ([`window`]): a run that
/// asks in several rounds (a scan of many project directories asks once
/// for each) keeps to one window for all of them, not one each.
pub(crate) async fn request(
    client: &ApiClient,
    uuids: Vec<String>,
    window: &Window,
) -> Vec<Measurement> {
    use futures_util::StreamExt;
    use socket_patch_core::api::retry::{ApiRetryPolicy, RetryHooks};
    use socket_patch_core::utils::concurrent::api_concurrency_for;
    let at_once = api_concurrency_for(client.uses_public_proxy(), uuids.len().max(1));
    let client = client
        .clone()
        .with_api_retry(ApiRetryPolicy::none(), RetryHooks::default());
    let client = &client;
    futures_util::stream::iter(uuids)
        .map(|uuid| async move {
            // Never closed, so the slot is always given.
            let _slot = window.acquire().await;
            let answer = hold_back_debug(client.fetch_patch_statistics(&uuid)).await;
            (uuid, answer)
        })
        .buffer_unordered(at_once)
        .collect()
        .await
}

/// The measurement requests a run may have out at once, whoever asks:
/// the patch API's own window for `client`'s route.
pub(crate) type Window = std::sync::Arc<tokio::sync::Semaphore>;

/// A [`Window`] for `client`'s route.
pub(crate) fn window(client: &ApiClient) -> Window {
    use socket_patch_core::utils::concurrent::api_concurrency_for;
    std::sync::Arc::new(tokio::sync::Semaphore::new(api_concurrency_for(
        client.uses_public_proxy(),
        usize::MAX,
    )))
}

/// Fold `answers` into `measured`, printing each request's `--debug`
/// lines. A failed request, or a patch that was not measured, adds
/// nothing.
pub(crate) fn collect(measured: &mut Measured, answers: Vec<Measurement>) {
    for (uuid, answer) in answers {
        if let Ok(Some(stats)) = answer.release() {
            measured.insert(uuid, stats);
        }
    }
}

/// [`request`] and [`collect`] in one step, for a caller that shows the
/// measurements right away. Empty when the run does not show them, and
/// when they are not all in within [`LISTING_WAIT`].
pub(crate) async fn fetch(common: &GlobalArgs, client: &ApiClient, uuids: Vec<String>) -> Measured {
    let mut measured = Measured::new();
    if wanted(common) && !uuids.is_empty() {
        let window = window(client);
        if let Ok(answers) =
            tokio::time::timeout(LISTING_WAIT, request(client, uuids, &window)).await
        {
            collect(&mut measured, answers);
        }
    }
    measured
}

/// A relative change as a signed percentage with one decimal: `0.0356` is
/// `+3.6%`, `-0.0446` is `-4.5%`. A change that rounds to nothing is `0%`.
pub(crate) fn percent(change: f64) -> String {
    let tenths = (change * 1000.0).round();
    if !tenths.is_finite() || tenths == 0.0 {
        return "0%".to_string();
    }
    format!("{:+.1}%", tenths / 10.0)
}

/// `2 of 2 exploits blocked`.
fn exploits_blocked(blocked: PatchRatio) -> String {
    format!(
        "{} of {} blocked",
        blocked.count,
        plural(blocked.total as usize, "exploit", "exploits")
    )
}

/// `35 of 35 tests passing`.
fn tests_passing(passing: PatchRatio) -> String {
    format!(
        "{} of {} passing",
        passing.count,
        plural(passing.total as usize, "test", "tests")
    )
}

/// What was measured about a patch, in a few words for a table row:
/// `exploit blocked, 25/25 tests`. The exploits are the proofs of concept
/// of the advisories the patch fixes, run against the patched package; the
/// tests are the package's own, run on it. A part that was not measured is
/// left out, and an exploit count is spelled out only past one or when the
/// patch does not block them all.
pub(crate) fn evidence(stats: &PatchStatistics) -> String {
    let mut parts = Vec::new();
    if let Some(pocs) = stats.pocs {
        let blocked = pocs.blocked_after;
        parts.push(if !blocked.is_all() {
            format!("{}/{} exploits blocked", blocked.count, blocked.total)
        } else if blocked.total == 1 {
            "exploit blocked".to_string()
        } else {
            format!("{} exploits blocked", blocked.total)
        });
    }
    if let Some(tests) = stats.tests {
        parts.push(format!("{}/{} tests", tests.after.count, tests.after.total));
    }
    parts.join(", ")
}

/// What was measured about a patch, as labelled lines for a listing (no
/// indent): what it was verified against, how large it is, and what it
/// costs at run time. A line whose part was not measured is left out.
///
/// ```text
/// Verified: 2 of 2 exploits blocked, 35 of 35 tests passing
/// Change: +9 -2 lines in 2 files, 3 functions
/// Performance: patched code +3.6%, memory +0.1%
/// ```
///
/// "Patched code" is the wall time of a workload through the code the
/// patch touches; "runtime" is that of the package's general workload.
pub(crate) fn lines(stats: &PatchStatistics) -> Vec<String> {
    lines_with(stats, false)
}

/// [`lines`], and with `before` what the same exploits and tests did on
/// the unpatched package, where that was measured:
/// `Verified: 2 of 2 exploits blocked (2 of 2 worked before the patch),
/// 35 of 35 tests passing (35 of 35 before the patch)`.
pub(crate) fn lines_with(stats: &PatchStatistics, before: bool) -> Vec<String> {
    let mut lines = Vec::new();
    let mut verified = Vec::new();
    if let Some(pocs) = stats.pocs {
        let mut part = exploits_blocked(pocs.blocked_after);
        if let Some(worked) = pocs.reproduced_before.filter(|_| before) {
            part.push_str(&format!(
                " ({} of {} worked before the patch)",
                worked.count, worked.total
            ));
        }
        verified.push(part);
    }
    if let Some(tests) = stats.tests {
        let mut part = tests_passing(tests.after);
        if let Some(passed) = tests.before.filter(|_| before) {
            part.push_str(&format!(
                " ({} of {} before the patch)",
                passed.count, passed.total
            ));
        }
        verified.push(part);
    }
    if !verified.is_empty() {
        lines.push(format!("Verified: {}", verified.join(", ")));
    }
    let mut change = Vec::new();
    if let Some(diff) = stats.diff {
        change.push(format!(
            "+{} -{} lines in {}",
            diff.lines_added,
            diff.lines_removed,
            plural(diff.files_changed as usize, "file", "files")
        ));
    }
    if let Some(functions) = stats.functions_changed {
        change.push(plural(functions as usize, "function", "functions"));
    }
    if !change.is_empty() {
        lines.push(format!("Change: {}", change.join(", ")));
    }
    if let Some(perf) = stats.performance {
        let cost: Vec<String> = [
            ("runtime", perf.general_wall_change),
            ("patched code", perf.hot_wall_change),
            ("memory", perf.peak_mem_change),
        ]
        .into_iter()
        .filter_map(|(what, change)| Some(format!("{what} {}", percent(change?))))
        .collect();
        if !cost.is_empty() {
            lines.push(format!("Performance: {}", cost.join(", ")));
        }
    }
    lines
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use socket_patch_core::api::types::{
        PatchDiffSize, PatchExploitRuns, PatchPerformance, PatchTestRuns,
    };

    /// Measurements: `exploits` blocked of as many run, `tests` passing of
    /// `tests_total`.
    pub(crate) fn stats(exploits: u64, tests: u64, tests_total: u64) -> PatchStatistics {
        PatchStatistics {
            pocs: Some(PatchExploitRuns {
                reproduced_before: None,
                blocked_after: PatchRatio {
                    count: exploits,
                    total: exploits,
                },
            }),
            tests: Some(PatchTestRuns {
                before: None,
                after: PatchRatio {
                    count: tests,
                    total: tests_total,
                },
            }),
            ..PatchStatistics::default()
        }
    }

    #[test]
    fn evidence_says_what_was_measured_in_a_few_words() {
        assert_eq!(evidence(&stats(1, 25, 25)), "exploit blocked, 25/25 tests");
        assert_eq!(
            evidence(&stats(2, 34, 35)),
            "2 exploits blocked, 34/35 tests"
        );
        let partly = PatchStatistics {
            pocs: Some(PatchExploitRuns {
                reproduced_before: None,
                blocked_after: PatchRatio { count: 1, total: 2 },
            }),
            ..PatchStatistics::default()
        };
        assert_eq!(evidence(&partly), "1/2 exploits blocked");
        // Measured, but neither exploits nor tests: nothing to say here.
        assert_eq!(evidence(&PatchStatistics::default()), "");
    }

    #[test]
    fn lines_label_each_measured_part_and_skip_the_rest() {
        let full = PatchStatistics {
            diff: Some(PatchDiffSize {
                lines_added: 9,
                lines_removed: 2,
                files_changed: 2,
            }),
            functions_changed: Some(3),
            performance: Some(PatchPerformance {
                general_wall_change: None,
                hot_wall_change: Some(0.03564810053424257),
                peak_mem_change: Some(0.00035335689045936394),
            }),
            ..stats(2, 35, 35)
        };
        assert_eq!(
            lines(&full),
            [
                "Verified: 2 of 2 exploits blocked, 35 of 35 tests passing",
                "Change: +9 -2 lines in 2 files, 3 functions",
                "Performance: patched code +3.6%, memory 0%",
            ]
        );
        let small = PatchStatistics {
            diff: Some(PatchDiffSize {
                lines_added: 5,
                lines_removed: 0,
                files_changed: 1,
            }),
            tests: Some(PatchTestRuns {
                before: None,
                after: PatchRatio { count: 1, total: 1 },
            }),
            // Measured with nothing to report: no line.
            performance: Some(PatchPerformance::default()),
            ..PatchStatistics::default()
        };
        assert_eq!(
            lines(&small),
            [
                "Verified: 1 of 1 test passing",
                "Change: +5 -0 lines in 1 file"
            ]
        );
        assert!(lines(&PatchStatistics::default()).is_empty());
        // With the unpatched package's runs, where they were measured.
        let mut both = stats(2, 35, 35);
        both.pocs.as_mut().unwrap().reproduced_before = Some(PatchRatio { count: 2, total: 2 });
        both.tests.as_mut().unwrap().before = Some(PatchRatio {
            count: 34,
            total: 35,
        });
        assert_eq!(
            lines_with(&both, true),
            [
                "Verified: 2 of 2 exploits blocked (2 of 2 worked before the patch), 35 of 35 \
              tests passing (34 of 35 before the patch)"
            ]
        );
        assert_eq!(lines_with(&both, false), lines(&stats(2, 35, 35)));
        assert_eq!(
            lines_with(&stats(2, 35, 35), true),
            lines(&stats(2, 35, 35))
        );
    }

    #[test]
    fn percent_is_signed_with_one_decimal() {
        assert_eq!(percent(0.03564810053424257), "+3.6%");
        assert_eq!(percent(-0.044605818765549615), "-4.5%");
        assert_eq!(percent(0.001246555570135153), "+0.1%");
        assert_eq!(percent(0.0002), "0%");
        assert_eq!(percent(-0.0002), "0%");
        assert_eq!(percent(1.5), "+150.0%");
        assert_eq!(percent(f64::NAN), "0%");
    }

    /// The wire shape of the view endpoint's `statistics`, as the service
    /// sends it: every part optional, unknown keys ignored.
    #[test]
    fn statistics_parse_from_the_view_endpoints_shape() {
        let stats: PatchStatistics = serde_json::from_str(
            r#"{
                "diff": {"linesAdded": 64, "linesRemoved": 34, "filesChanged": 2},
                "functionsChanged": 4,
                "tests": {"before": {"count": 106, "total": 106},
                          "after": {"count": 106, "total": 106}},
                "pocs": {"reproducedBefore": {"count": 1, "total": 1},
                         "blockedAfter": {"count": 1, "total": 1}},
                "performance": {"generalWallChange": null,
                                "hotWallChange": -0.044605818765549615,
                                "peakMemChange": 0.001246555570135153},
                "somethingNew": {"a": 1}
            }"#,
        )
        .expect("the service's statistics parse");
        assert_eq!(
            lines(&stats),
            [
                "Verified: 1 of 1 exploit blocked, 106 of 106 tests passing",
                "Change: +64 -34 lines in 2 files, 4 functions",
                "Performance: patched code -4.5%, memory +0.1%",
            ]
        );
        let sparse: PatchStatistics = serde_json::from_str(
            r#"{"diff": null, "functionsChanged": null, "tests": null, "pocs": null,
                "performance": null}"#,
        )
        .expect("an unmeasured patch parses");
        assert_eq!(sparse, PatchStatistics::default());
    }
}
