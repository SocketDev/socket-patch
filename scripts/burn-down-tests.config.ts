/**
 * burn-down-tests.config.ts — the per-test FIX prompt for burn-down-tests.ts.
 *
 * The burn-down harness hands a single fresh Claude session exactly one
 * currently-failing test and asks it to fix that test CORRECTLY — by repairing
 * the real root cause (usually production code), never by weakening, deleting,
 * or gaming the test. This is the inverse of harden-tests.config.ts: there the
 * agent may only touch tests; here the agent's job is to make a red test go
 * green for the right reasons.
 *
 *   npx tsx scripts/burn-down-tests.ts \
 *     --prompt-file scripts/burn-down-tests.config.ts
 *
 * (This is the default fix prompt; --prompt-file only needs to be passed to
 *  override it.)
 *
 * The harness independently re-runs cargo to confirm the test passes and that
 * no other test regressed, then a separate adversarial review agent
 * (burn-down-review.config.ts) checks the diff for reward hacking BEFORE the
 * harness commits. So a fix that merely games the assertion will be caught and
 * reverted — fix the actual defect.
 *
 * TestCtx fields available (see burn-down-tests.ts):
 *   test           the failing test's name, runnable as `cargo test <test> -- --exact`
 *   failureDetail  the captured panic/assertion output for this test (may be empty)
 *   features       the cargo --features string the harness runs the suite with
 *   attempt        1-based attempt number for this test (incremented on retry)
 *   iteration      1-based loop iteration across the whole burn-down run
 */

export interface TestCtx {
  test: string;
  failureDetail: string;
  features: string;
  attempt: number;
  iteration: number;
}

export default function render(ctx: TestCtx): string {
  const featureFlag = ctx.features ? ` --features ${ctx.features}` : "";
  const lines: string[] = [
    `# Fix exactly one failing test`,
    ``,
    `You are part of a test burn-down. Exactly one failing test has been handed`,
    `to you. Fix it correctly and stay focused on this one test.`,
    ``,
    `Failing test: ${ctx.test}`,
    `Attempt: ${ctx.attempt}${ctx.attempt > 1 ? " (a previous attempt did not satisfy the harness — try a genuinely different, correct approach)" : ""}`,
    ``,
    `## Observed failure`,
    ctx.failureDetail.trim()
      ? "```\n" + ctx.failureDetail.trim() + "\n```"
      : `(No failure output was captured. Reproduce it yourself to see the failure.)`,
    ``,
    `## Your goal`,
    `Make this test pass by fixing the ROOT CAUSE of the failure. In the large`,
    `majority of cases the bug is in PRODUCTION code, not the test — the test is`,
    `correctly catching a real defect. Diagnose what behavior the test demands,`,
    `find why the implementation does not provide it, and fix the implementation.`,
    ``,
    `## Method`,
    `1. Reproduce the failure and read the actual output:`,
    `     cargo test ${ctx.test}${featureFlag} -- --exact --nocapture`,
    `2. Read the test to understand the exact behavior it is asserting and why.`,
    `3. Trace into the production code that the test exercises and locate the`,
    `   real defect. Fix it at its source.`,
    `4. Confirm THIS test now passes:`,
    `     cargo test ${ctx.test}${featureFlag} -- --exact`,
    `5. Confirm you did not break anything else. Run the broader suite (or at`,
    `   least the affected crate's tests) and make sure no previously-passing`,
    `   test now fails:`,
    `     cargo test --workspace${featureFlag} --no-fail-fast`,
    ``,
    `## Hard constraints`,
    `- Fix the real cause. Do NOT make the test pass by gaming it. Specifically,`,
    `  do NOT: weaken/loosen/remove its assertions; change the expected value to`,
    `  match the buggy output; add #[ignore] or #[should_panic]; special-case the`,
    `  test's exact input in production code; stub, short-circuit, or feature-gate`,
    `  out the code path the test exercises; or otherwise satisfy the letter of`,
    `  the test while violating its spirit. A separate reviewer WILL inspect your`,
    `  diff for exactly these moves and reject the fix if it finds them.`,
    `- Do NOT modify, delete, or disable any OTHER test, and do not break any`,
    `  currently-passing test.`,
    `- If — and only if — the test itself genuinely asserts incorrect behavior`,
    `  (the implementation is right and the test is wrong), you may correct the`,
    `  test, but you MUST justify in your summary precisely why the asserted`,
    `  behavior is wrong and what the correct behavior is.`,
    `- Do NOT run git or commit anything. The harness verifies and commits.`,
    ``,
    `## Bailout`,
    `If, after diagnosing, you conclude this test cannot be fixed correctly within`,
    `a focused single-test change — e.g. it needs a broad/risky refactor, depends`,
    `on missing infrastructure, or you cannot fix it without changing behavior you`,
    `cannot confidently verify — do NOT force a fix or game the test. Instead,`,
    `leave the working tree unchanged and end your summary with a single line:`,
    `     BAILOUT: <one-line reason>`,
    `The harness will park this test for human review and move on. Bailing out is`,
    `the correct, honest choice when a clean fix is out of reach — far better than`,
    `a hack the reviewer will reject.`,
    ``,
    `## Report`,
    `End with a concise summary (3-6 bullets): the root cause you found, the`,
    `production change you made (files + what), the exact commands you ran to`,
    `confirm this test passes and that nothing else regressed, and — if you`,
    `changed the test instead of prod — your justification. If you bailed out,`,
    `the final line must be the \`BAILOUT: <reason>\` marker.`,
  ];

  return lines.join("\n");
}
