//! Distribution-free statistics for interleaved A/B samples.
//!
//! A CI runner's speed drifts over a job, and two runners differ by more
//! than most regressions, so the comparison only ever pairs a base run with
//! the head run taken right after it on the same machine. Each pair yields
//! one `head / base` ratio; the verdict reads the median ratio and a
//! sign-test confidence interval for it, which assumes nothing about the
//! timing distribution (CI timings are skewed and heavy-tailed, so a
//! t-interval would be wrong).

/// Median of `xs` (the mean of the middle pair for an even count).
/// `NaN` for an empty slice.
pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NAN;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        v[mid]
    } else {
        (v[mid - 1] + v[mid]) / 2.0
    }
}

/// `P(X <= k)` for `X ~ Binomial(n, 1/2)`, summed in log space so large
/// sample counts neither overflow nor underflow.
fn binomial_half_cdf(n: usize, k: usize) -> f64 {
    let mut ln_p = -(n as f64) * std::f64::consts::LN_2;
    let mut total = ln_p.exp();
    for i in 1..=k.min(n) {
        ln_p += ((n - i + 1) as f64).ln() - (i as f64).ln();
        total += ln_p.exp();
    }
    total.min(1.0)
}

/// The sign-test confidence interval for the median of `xs`: the order
/// statistics `[x(k), x(n+1-k)]` for the largest `k` whose coverage
/// `1 - 2 P(X < k)` is at least `confidence`. `None` when there are too
/// few samples to reach it (fewer than 6 for 95%).
pub fn median_ci(xs: &[f64], confidence: f64) -> Option<(f64, f64)> {
    let n = xs.len();
    if n == 0 {
        return None;
    }
    let mut k = 0usize;
    while k < n / 2 && 1.0 - 2.0 * binomial_half_cdf(n, k) >= confidence {
        k += 1;
    }
    if k == 0 {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    Some((v[k - 1], v[n - k]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Slower by more than the threshold, and the whole interval is above 1.
    Regression,
    /// Faster by more than the threshold, and the whole interval is below 1.
    Improvement,
    /// Within the threshold, or not significant.
    Unchanged,
    /// Too few pairs for an interval.
    Inconclusive,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Comparison {
    /// Median of the per-pair `head / base` ratios.
    pub ratio: f64,
    /// Sign-test interval for that median.
    pub ci: Option<(f64, f64)>,
    pub base_median: f64,
    pub head_median: f64,
    pub verdict: Verdict,
}

/// What counts as a change worth failing on.
#[derive(Debug, Clone, Copy)]
pub struct Gate {
    /// Relative threshold: 0.10 flags a median ratio above 1.10 (or below
    /// 1 / 1.10 as an improvement).
    pub threshold: f64,
    /// The medians must also differ by at least this much in absolute
    /// terms, so a 2 ms scheduler hiccup on a 15 ms run is not a "13%
    /// regression".
    pub min_abs_delta: f64,
    pub confidence: f64,
}

/// Compare paired samples (`base[i]` was measured right before `head[i]`).
pub fn compare_paired(base: &[f64], head: &[f64], gate: Gate) -> Comparison {
    assert_eq!(base.len(), head.len(), "paired samples");
    let ratios: Vec<f64> = base
        .iter()
        .zip(head)
        .map(|(b, h)| if *b > 0.0 { h / b } else { 1.0 })
        .collect();
    let ratio = median(&ratios);
    let ci = median_ci(&ratios, gate.confidence);
    let base_median = median(base);
    let head_median = median(head);
    let abs_delta = (head_median - base_median).abs();
    let verdict = match ci {
        None => Verdict::Inconclusive,
        Some((lo, _))
            if ratio > 1.0 + gate.threshold && lo > 1.0 && abs_delta >= gate.min_abs_delta =>
        {
            Verdict::Regression
        }
        Some((_, hi))
            if ratio < 1.0 / (1.0 + gate.threshold)
                && hi < 1.0
                && abs_delta >= gate.min_abs_delta =>
        {
            Verdict::Improvement
        }
        Some(_) => Verdict::Unchanged,
    };
    Comparison {
        ratio,
        ci,
        base_median,
        head_median,
        verdict,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATE: Gate = Gate {
        threshold: 0.10,
        min_abs_delta: 1.0,
        confidence: 0.95,
    };

    #[test]
    fn median_handles_odd_even_and_unsorted_input() {
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 3.0, 2.0]), 2.5);
        assert!(median(&[]).is_nan());
    }

    #[test]
    fn binomial_cdf_matches_exact_values() {
        // Bin(15, 1/2): P(X <= 3) = (1 + 15 + 105 + 455) / 2^15.
        assert!((binomial_half_cdf(15, 3) - 576.0 / 32768.0).abs() < 1e-12);
        assert!((binomial_half_cdf(4, 4) - 1.0).abs() < 1e-12);
        // Large n stays finite.
        let p = binomial_half_cdf(2000, 1000);
        assert!(p > 0.5 && p < 0.52, "{p}");
    }

    #[test]
    fn median_ci_uses_the_sign_test_order_statistics() {
        let xs: Vec<f64> = (1..=15).map(f64::from).collect();
        // n = 15 at 95%: k = 4 (coverage 0.965), so [x(4), x(12)].
        assert_eq!(median_ci(&xs, 0.95), Some((4.0, 12.0)));
        // Five samples cannot reach 95% (the widest interval covers 93.75%).
        assert_eq!(median_ci(&xs[..5], 0.95), None);
        assert_eq!(median_ci(&xs[..6], 0.95), Some((1.0, 6.0)));
    }

    #[test]
    fn a_consistent_slowdown_is_a_regression() {
        let base: Vec<f64> = (0..15).map(|i| 100.0 + f64::from(i % 3)).collect();
        let head: Vec<f64> = base.iter().map(|b| b * 1.25).collect();
        let c = compare_paired(&base, &head, GATE);
        assert_eq!(c.verdict, Verdict::Regression);
        assert!((c.ratio - 1.25).abs() < 1e-9);
    }

    #[test]
    fn a_consistent_speedup_is_an_improvement() {
        let base = vec![100.0; 12];
        let head = vec![70.0; 12];
        assert_eq!(
            compare_paired(&base, &head, GATE).verdict,
            Verdict::Improvement
        );
    }

    #[test]
    fn noise_around_one_is_unchanged() {
        let base = vec![100.0; 15];
        let head: Vec<f64> = (0..15)
            .map(|i| if i % 2 == 0 { 92.0 } else { 109.0 })
            .collect();
        assert_eq!(
            compare_paired(&base, &head, GATE).verdict,
            Verdict::Unchanged
        );
    }

    #[test]
    fn a_large_median_with_a_wide_interval_is_not_a_regression() {
        // Most pairs are 1.2x but a third are 0.8x: the median is past the
        // threshold, the interval is not wholly above 1.
        let base = vec![100.0; 15];
        let head: Vec<f64> = (0..15)
            .map(|i| if i % 3 == 0 { 80.0 } else { 120.0 })
            .collect();
        let c = compare_paired(&base, &head, GATE);
        assert!(c.ratio > 1.1);
        assert_eq!(c.verdict, Verdict::Unchanged);
    }

    #[test]
    fn a_tiny_absolute_delta_is_not_a_regression() {
        let base = vec![2.0; 15];
        let head = vec![2.6; 15];
        let c = compare_paired(&base, &head, GATE);
        assert!(c.ratio > 1.25);
        assert_eq!(c.verdict, Verdict::Unchanged);
    }

    #[test]
    fn too_few_pairs_is_inconclusive() {
        let c = compare_paired(&[1.0, 1.0], &[5.0, 5.0], GATE);
        assert_eq!(c.verdict, Verdict::Inconclusive);
    }
}
