/**
 * optimize-test-perf.config.ts — test-suite performance sweep for study-crates.ts.
 *
 * Runs one session per test file and asks it to make the file's tests FASTER
 * without reducing what they cover or how hard they fail:
 *
 *   npx tsx scripts/study-crates.ts --tests \
 *     --prompt-file scripts/optimize-test-perf.config.ts
 *
 * (Use `--target all` to also visit src files and their inline #[cfg(test)]
 *  modules, `--crate`/`--filter` to narrow scope, and `--dry-run` to preview.)
 *
 * IMPORTANT: keep the default --concurrency 1. Sessions may touch shared
 * harness modules (tests/common/mod.rs and friends) and they benchmark
 * wall-clock time — parallel sessions would both race on shared files and
 * corrupt each other's timing measurements.
 *
 * Framing
 * -------
 * Speed is the only allowed win, and coverage/quality regressions are the only
 * forbidden cost. The prompt therefore forces three proof obligations on every
 * session that changes anything:
 *   1. Inventory proof: `cargo test ... -- --list` output identical before and
 *      after (no test deleted, merged, ignored, or renamed away).
 *   2. Strength proof: for every test whose setup or exercised path changed, a
 *      sabotage (RED) check — temporarily break the guarded behavior, confirm
 *      the optimized test still fails, restore.
 *   3. Timing proof: warm before/after wall-clock numbers, measured after a
 *      throwaway first run (fresh macOS binaries can stall ~90s in dyld — that
 *      stall is not test time).
 * Sessions that can't find a meaningful win are told to say "already fast" and
 * stop — a no-op is a valid, desirable outcome.
 *
 * FileCtx fields available (see study-crates.ts):
 *   file        repo-relative POSIX path, e.g. "crates/socket-patch-core/tests/diff_e2e.rs"
 *   abspath     absolute path on disk
 *   crate       crate dir name, e.g. "socket-patch-core"
 *   name        basename, e.g. "diff_e2e.rs"
 *   stem        basename without extension, e.g. "diff_e2e"
 *   relInCrate  path within the crate's tests/ (or src/) dir
 *   isTest      true when discovered under tests/
 */

import type { FileCtx } from "./study-crates.ts";

export const model = "claude-opus-5";

// Every ecosystem is compiled in unconditionally — the old per-ecosystem
// feature gates (`cargo`, `golang`, `maven`, …) no longer exist, and naming
// them makes cargo abort with "none of the selected packages contains these
// features". The default feature set is already exactly what we want here:
// all nine ecosystems, minus the cfg-gated `docker-e2e`/`setup-e2e` suites
// that `--all-features` would drag in.
const FEATURES = "";

export default function render(ctx: FileCtx): string {
  const featureFlag = FEATURES ? ` --features ${FEATURES}` : "";
  const isHarness =
    /(^|\/)(common|setup_matrix_common|helpers?|support|fixtures?)(\/|$)/.test(
      ctx.relInCrate,
    ) || ctx.name === "mod.rs";

  const runCmd = ctx.isTest
    ? `cargo test -p ${ctx.crate} --test ${ctx.stem}${featureFlag}`
    : `cargo test -p ${ctx.crate} --lib${featureFlag} <module path filter>`;

  const lines: string[] = [
    `You are optimizing the RUNTIME PERFORMANCE of the tests in a single file.`,
    `Treat this as your only task and stay within this one file (plus, only when`,
    `unavoidable, the shared harness modules it pulls in).`,
    ``,
    `Target file: ${ctx.file}`,
    `Crate: ${ctx.crate}`,
    ``,
    ctx.isTest
      ? `This is an integration-test file.`
      : `This is a source file — your scope is ONLY its inline #[cfg(test)]` +
        ` module(s). Do not change any production code in the file.`,
    ``,
    `## Goal`,
    `Make these tests finish faster while covering exactly as much and failing`,
    `exactly as hard as they do today. Speed is the only allowed win; any loss`,
    `of coverage, assertion strength, isolation, or determinism is a regression`,
    `and disqualifies the change. If the file is already fast or has no safe`,
    `win, say so plainly and change nothing — a no-op is a good outcome.`,
    ``,
    `## Method`,
    `1. Baseline. Build and run the tests, then run them AGAIN and record the`,
    `   second run's wall-clock time (freshly built binaries on macOS can stall`,
    `   ~90s in dyld on first launch — that stall is launch overhead, not test`,
    `   time; never count it or "fix" it):`,
    `     ${runCmd}`,
    `   (If a feature in the list doesn't exist for this crate, drop it and`,
    `    note that. Report exactly what you ran.)`,
    `   Also snapshot the test inventory:`,
    `     ${runCmd} -- --list`,
    `2. Profile before touching anything. Find where the time actually goes —`,
    `   time individual tests with name filters if needed. Do not optimize on`,
    `   suspicion; every change must chase a measured cost.`,
    `3. Optimize. Legitimate wins, roughly in order of typical payoff here:`,
    `   * Fixed sleeps and generous timeouts on paths that could poll: replace`,
    `     sleep-then-assert with poll-until-condition under a deadline. Keep the`,
    `     deadline as generous as the old timeout — the win is the common case`,
    `     finishing early, not a tighter limit that flakes on slow CI.`,
    `   * Expensive setup repeated per test (building fixture trees, spawning`,
    `     helper processes, compiling anything): compute once and share via`,
    `     OnceLock/lazy ONLY if the shared value is genuinely immutable and`,
    `     read-only afterwards. Anything a test mutates — temp dirs, env vars,`,
    `     lockfiles, cwd — must stay per-test.`,
    `   * Redundant work inside one test: re-running a process to check a second`,
    `     property observable from the first run's output; re-copying a fixture`,
    `     tree the test never mutates; needlessly large fixture payloads whose`,
    `     size provably doesn't matter to any assertion (be conservative — size`,
    `     is sometimes the point, e.g. chunking/streaming boundaries).`,
    `   * Waiting out a full timeout on expected-failure paths where the failure`,
    `     is detectable immediately.`,
    `4. Prove coverage is intact:`,
    `   * Inventory proof: rerun \`-- --list\` and diff against the snapshot —`,
    `     it must be IDENTICAL. No test deleted, merged, renamed, or #[ignore]d.`,
    `   * Strength proof (sabotage / RED check): for EVERY test whose setup or`,
    `     exercised code path you changed, temporarily sabotage the behavior it`,
    `     guards (break the prod code path or the fixture it validates), confirm`,
    `     the optimized test FAILS, then restore cleanly. A pure timing change`,
    `     (sleep -> poll with same deadline) needs this too — polling loops are`,
    `     a classic place to accidentally accept the pre-condition state.`,
    `   * Stability proof: run the optimized tests 3 times back to back — all`,
    `     green. Shared-fixture and parallelism changes are the classic source`,
    `     of new flakes; one green run proves nothing. (Network blips can make`,
    `     pip-fixture tests fail spuriously — rerun before diagnosing.)`,
    `5. Measure the win: report warm before/after wall-clock. If the total`,
    `   saving is under ~20% of the file's runtime AND under ~2 seconds, revert`,
    `   everything and report "already fast" — churn is not worth micro-wins.`,
    ``,
    `## Hard constraints`,
    `* Never delete, merge, #[ignore], or skip a test, and never weaken, remove,`,
    `  or loosen an assertion. Every assertion that exists today must still run`,
    `  and still be at least as strict.`,
    `* Never reduce case counts, matrix dimensions, or iteration counts that`,
    `  contribute coverage. If a loop looks arbitrarily large, that is a finding`,
    `  to REPORT, not a change to make — you cannot prove locally which`,
    `  iteration would have caught tomorrow's bug.`,
    `* Never swap a real code path for a mock/stub/fake to save time. Faking`,
    `  out the thing under test is a coverage loss even when every assertion`,
    `  still passes.`,
    `* Never remove serialization, locks, or env scrubbing that guard shared`,
    `  state. Tests here mutate process env and global fixtures; env races have`,
    `  caused real flakes in this repo. If a serial guard looks unnecessary,`,
    `  report it — do not remove it.`,
    `* Never relax hermeticity: per-test temp dirs stay per-test, env setup and`,
    `  scrub lists stay intact, and no test may start depending on another`,
    `  test's leftovers or on execution order.`,
    `* Do not modify production/source code${ctx.isTest ? `` : ` outside the #[cfg(test)] module`},`,
    `  CI configuration, cargo profiles, or global test-runner settings. If a`,
    `  prod-side change (e.g. an injectable clock) would unlock a big win,`,
    `  describe it in your summary instead of making it.`,
    `* Timing changes must not tighten any deadline below its current value on`,
    `  the failure path — faster when green, never flakier when slow.`,
    `* If any proof step fails or is impractical for a change, revert that`,
    `  change. Fail closed: no proof, no optimization.`,
  ];

  if (isHarness) {
    lines.push(
      ``,
      `## Note: this is a shared test harness / setup module`,
      `${ctx.relInCrate} is scaffolding other test files depend on, so a win`,
      `here multiplies across the suite — and so does a regression. Any change`,
      `to shared setup must keep its per-caller semantics identical (same env`,
      `scrubbing, same fresh-state guarantees per invocation). After editing,`,
      `run EVERY test target in this crate that imports this module, not just`,
      `one, and apply the sabotage check through at least one representative`,
      `consumer. Prefer additive opt-in fast paths (a cached read-only variant`,
      `alongside the existing builder) over changing what existing callers get.`,
    );
  }

  lines.push(
    ``,
    `## Report`,
    `End with a concise summary (3-6 bullets): where the time was going, each`,
    `optimization applied, warm before/after wall-clock, the three proofs`,
    `(inventory diff clean, which tests you sabotage-checked, 3x-green), and`,
    `any speed-up opportunities you deliberately left on the table because they`,
    `would need prod changes or risk coverage. If you changed nothing, one`,
    `bullet saying the file is already fast — with the measured runtime — is a`,
    `complete, successful report.`,
  );

  return lines.join("\n");
}
