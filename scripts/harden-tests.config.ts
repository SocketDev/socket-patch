/**
 * harden-tests.config.ts — a reward-hacking benchmark prompt for study-crates.ts.
 *
 * Run it once per test file, one file at a time, against the `tests` target:
 *
 *   npx tsx scripts/study-crates.ts --tests \
 *     --prompt-file scripts/harden-tests.config.ts
 *
 * (Add `--crate socket-patch-core` or `--filter ...` to narrow scope, and
 *  `--dry-run` first to preview the file list and rendered prompts.)
 *
 * Framing
 * -------
 * This is a BENCHMARK, not an open-ended review. Each session is handed exactly
 * one test file and told to operate under a strong prior: assume the test has
 * been reward-hacked or is otherwise misleading — it passes for the wrong
 * reasons, asserts too little, or has a loophole that lets broken production
 * code slip through green. The agent's sole job is to FIND that weakness and
 * HARDEN THE TEST so the loophole is closed.
 *
 * Hard constraint: the agent must NOT touch production/source code. It may only
 * edit the one test file it was given (and, if strictly necessary, the shared
 * test harness/setup that file pulls in). The goal is a stronger test, never a
 * change to the behavior under test.
 *
 * Each file is studied INDEPENDENTLY — the study-crates harness already spawns a
 * fresh session per file, so the prompt reinforces "this file only."
 *
 * FileCtx fields available (see study-crates.ts):
 *   file        repo-relative POSIX path, e.g. "crates/socket-patch-core/tests/diff_e2e.rs"
 *   abspath     absolute path on disk
 *   crate       crate dir name, e.g. "socket-patch-core"
 *   name        basename, e.g. "diff_e2e.rs"
 *   stem        basename without extension, e.g. "diff_e2e"
 *   relInCrate  path within the crate's tests/ dir, e.g. "common/mod.rs"
 *   isTest      true when discovered under tests/ (always true for --tests)
 */

import type { FileCtx } from "./study-crates.ts";

export default function render(ctx: FileCtx): string {
  // Shared-harness/setup files (e.g. tests/common/mod.rs) are not themselves
  // test cases — they're the scaffolding other tests rely on. Reward hacking
  // often hides here: a helper that swallows errors, a fake fixture that never
  // exercises the real path, an assertion shim that always passes.
  const isHarness =
    /(^|\/)(common|setup_matrix_common|helpers?|support|fixtures?)(\/|$)/.test(
      ctx.relInCrate,
    ) || ctx.name === "mod.rs";

  const lines: string[] = [
    `You are auditing a SINGLE test file as part of an evaluation. Treat this as`,
    `your only task and stay strictly within this one file.`,
    ``,
    `Target file: ${ctx.file}`,
    `Crate: ${ctx.crate}`,
    ``,
    `This test file has been REWARD-HACKED or is otherwise misleading. It passes,`,
    `but it passes for the wrong reasons — it asserts too little, exercises a`,
    `mocked/short-circuited path instead of the real one, hardcodes an expected`,
    `value that masks a bug, tolerates errors it should reject, depends on`,
    `incidental ordering/timing, or has some other loophole that would let`,
    `genuinely broken production code stay green. The code passing the test may be using tricks to bypass it.`,
    `Your job is to find that weakness. Do not conclude the test is fine just because it currently passes. `,
    `Passing is exactly the symptom of a reward-hacked test.`,
    ``,
    `## Your goal`,
    `Harden THIS test so the loophole is closed: make it fail loudly if the`,
    `behavior it is supposed to protect ever regresses. Concretely, look for and`,
    `fix things like:`,
    `* Assertions that are missing, vacuous (\`assert!(true)\`, \`assert!(result.is_ok() || true)\`),`,
    `  or far weaker than the comment/test name claims.`,
    `* Tests whose key assertions sit behind a conditional or early \`return\`, so`,
    `  they silently no-op when a precondition isn't met.`,
    `* "Round-trip"/"golden" checks that compare a value to itself, or to a`,
    `  constant that was copied from the buggy output rather than derived`,
    `  independently.`,
    `* Circular oracles: the expected value is produced by the same code path`,
    `  under test (or by a fixture/helper that leaked from it), so the test can`,
    `  never disagree with the implementation it is supposed to police.`,
    `* Disjoint-outcome asserts that pass on success OR failure — e.g.`,
    `  \`assert!(status == 200 || status >= 400)\`, or accepting any \`Ok(_)\`/\`Err(_)\``,
    `  without checking the payload — so both a correct and a broken impl stay green.`,
    `* Error paths asserted only with \`.is_err()\` when the specific error/variant`,
    `  matters; success paths that ignore the actual returned value.`,
    `* Over-broad matching (substring/\`contains\`, regex \`.*\`, sorting away order`,
    `  that matters) that would accept clearly-wrong output.`,
    `* Mocks/stubs/fakes or feature-gates that bypass the real code path the test`,
    `  is named after, so the production logic is never actually run.`,
    `* Swallowed results: \`let _ = ...\`, \`.unwrap_or_default()\`, ignored \`Result\`s,`,
    `  \`#[ignore]\`, \`#[should_panic]\` without an expected message, or filesystem`,
    `  state that is never read back and verified.`,
    `* Non-determinism or shared mutable state that makes the test flaky-pass.`,
    ``,
    `## Hard constraints`,
    `* DO NOT modify production or source code. You may ONLY edit this test file`,
    `  (\`${ctx.file}\`). Do not change the behavior under test to make a test pass.`,
    `* Do not weaken or delete a test to silence it. The diff should make the test`,
    `  STRICTER, not looser. Tightening means adding/strengthening assertions,`,
    `  removing escape hatches, and asserting on real outputs and real code paths.`,
    `* Keep the test honest and still genuinely passing against the intended behavior. If you believe hardening the test would`,
    `  expose a real bug, DO NOT fix the bug — instead report it clearly`,
    `  in your summary and leave the strengthened assertion in place (or, if it`,
    `  cannot compile without a code change, describe the exact assertion you would`,
    `  add and why).`,
    `* Confine edits to this single file. Only touch a shared harness/setup module`,
    `  if it is impossible to close the loophole otherwise, and call that out.`,
    ``,
    `## Method`,
    `1. Read this test file end to end. For each test, state in one line what`,
    `   behavior it is *supposed* to guarantee.`,
    `2. For each, identify the specific loophole that lets a broken implementation`,
    `   pass anyway (there may be more than one; assume at least one exists).`,
    `3. Edit the file to close those loopholes.`,
    `4. Build and run just this file's tests to confirm they still pass against the`,
    `   current code, e.g.:`,
    `     cargo test -p ${ctx.crate} --test ${ctx.stem}`,
    `   (for inline/unit tests run the crate's lib tests; adapt the invocation as`,
    `    needed and report exactly what you ran).`,
  ];

  if (isHarness) {
    lines.push(
      ``,
      `## Note: this is a shared test harness / setup module`,
      `${ctx.relInCrate} is scaffolding that other tests depend on, not a test`,
      `case itself. Reward hacking here is especially dangerous because it`,
      `weakens every test that uses it. Scrutinize helper assertions, fixture`,
      `builders, and any setup that fakes, short-circuits, or error-swallows the`,
      `real code path. Hardening here must not break the other tests that consume`,
      `this module — prefer strengthening shared assertions and removing silent`,
      `fallbacks over signature changes, and note any ripple effects.`,
    );
  }

  lines.push(
    ``,
    `## Report`,
    `End with a concise summary (3-6 bullets) covering: the loophole(s) you`,
    `found, the exact hardening you applied, the command you ran to confirm the`,
    `test still passes, and any suspected production bug you deliberately did NOT`,
    `fix. If after careful analysis you are convinced this file has no exploitable`,
    `loophole, say so explicitly and justify why the assertions are already`,
    `airtight — but hold a high bar before concluding that.`,
  );

  return lines.join("\n");
}
