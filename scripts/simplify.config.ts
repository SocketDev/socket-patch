/**
 * simplify.config.ts — duplication + dead-code cleanup sweep for study-crates.ts.
 *
 * Runs one session per source file:
 *
 *   npx tsx scripts/study-crates.ts --prompt-file scripts/simplify.config.ts
 *
 * IMPORTANT: keep the default --concurrency 1. Unlike the bug sweep, sessions
 * routinely edit files OTHER than the one under review (rewriting a duplicating
 * file to import from this one, extracting shared helpers), so parallel
 * sessions would race on the same files. Sequential sessions compose: each one
 * sees the previous sessions' consolidations, so a duplicate pair is resolved
 * once and the later file's session finds it already clean.
 *
 * Start from a clean git tree and review/commit incrementally — the per-file
 * raw logs under --out make it easy to attribute each change to its session.
 *
 * What each session does, given one file:
 *   1. Duplication: find functionality this file shares with the rest of the
 *      workspace and consolidate it — move it to an existing common module,
 *      import the better implementation from elsewhere, or rewrite the other
 *      file(s) to use this one.
 *   2. Simplification: remove unnecessary abstractions, dead code, and unused
 *      methods; narrow over-wide interfaces.
 * All changes must be strictly behavior-preserving and test-verified.
 *
 * FileCtx fields available (see study-crates.ts):
 *   file        repo-relative POSIX path, e.g. "crates/socket-patch-core/src/lib.rs"
 *   abspath     absolute path on disk
 *   crate       crate dir name, e.g. "socket-patch-core"
 *   name        basename, e.g. "lib.rs"
 *   stem        basename without extension, e.g. "lib"
 *   relInCrate  path within the crate's src dir, e.g. "api/client.rs"
 */

import type { FileCtx } from "./study-crates.ts";

export const model = "claude-fable-5";

export default function render(ctx: FileCtx): string {
  const sections: string[] = [];

  sections.push(
    `You are simplifying ${ctx.file} in the ${ctx.crate} crate.`,
    `The goal is strictly behavior-preserving cleanup: less code, fewer`,
    `abstractions, smaller interfaces, no functional change.`,
    ``,
    `Work through, in order:`,
    ``,
    `1. Duplication. Read the file, then search the rest of the workspace for`,
    `code that overlaps with it — similar helpers, parallel parsing or`,
    `validation logic, copy-pasted blocks that have started to diverge. For`,
    `each real overlap, first confirm the two sites genuinely share semantics`,
    `(near-duplicates in this codebase sometimes differ deliberately), then`,
    `pick ONE resolution:`,
    `  - if a shared home already exists (e.g. a utils module), keep the single`,
    `    best implementation there and update all callers;`,
    `  - if another file already has the better implementation, rewrite this`,
    `    file to use it;`,
    `  - if this file has the better implementation, rewrite the other file(s)`,
    `    to import from here, promoting the code to a common module only if`,
    `    crate or module boundaries require it.`,
    `Prefer the smallest move that removes the duplicate; do not invent a new`,
    `common module for a single trivial helper.`,
    ``,
    `2. Local simplification. Within this file: delete dead code and unused`,
    `methods, fields, and parameters; collapse single-use indirections (a trait`,
    `with one impl, a wrapper that only forwards, a helper called once whose`,
    `body is clearer inline); narrow interfaces to what callers actually use;`,
    `and reduce visibility (pub -> pub(crate) or private) when nothing outside`,
    `the module uses an item.`,
    ``,
    `Hard rules:`,
    `- Behavior-preserving only: no new features, no semantic changes, and no`,
    `  new abstractions — the diff should shrink total code and interface`,
    `  surface, not trade one structure for another.`,
    `- Before deleting anything as "unused", search the whole workspace,`,
    `  including tests, the CLI crate, and feature-gated code (#[cfg(...)]).`,
    `  An item unreferenced under default features may be used under another`,
    `  feature combination or by an integration test.`,
    `- Defensive code is not mess. Fail-closed guards, path-traversal and`,
    `  symlink checks, atomic write/rename patterns, and permission handling in`,
    `  this codebase are deliberate — do not simplify them away even where they`,
    `  look redundant.`,
    `- Never delete or weaken a test to make a cleanup possible. Update tests`,
    `  only mechanically, when an interface they exercise moved or was renamed.`,
    `- If the file is already clean and has no real duplication, say so plainly`,
    `  and stop — do not restructure for its own sake.`,
  );

  // Path-specific emphasis: the patch engine and crawlers carry the most
  // invariants.
  if (ctx.relInCrate.startsWith("patch/")) {
    sections.push(
      ``,
      `This file is part of the patch engine. Apply, rollback, and sidecar`,
      `paths intentionally share some shapes while differing in semantics —`,
      `consolidate only after verifying both call sites need identical`,
      `behavior, and never relax filesystem safety, atomicity, or rollback`,
      `correctness while doing so.`,
    );
  } else if (ctx.relInCrate.startsWith("crawlers/")) {
    sections.push(
      ``,
      `This is a package-manager crawler. Crawlers for different ecosystems`,
      `look similar but encode different on-disk layout rules — only extract`,
      `shared helpers where the semantics are truly ecosystem-independent.`,
    );
  }

  sections.push(
    ``,
    `Before finishing, verify: the workspace builds warning-free and the test`,
    `suites of every crate you touched pass. If you removed feature-gated or`,
    `pub code, check the other feature combinations build too.`,
    ``,
    `End with a concise 3-6 bullet summary: duplicates consolidated (and in`,
    `which direction), abstractions and dead code removed, net line delta, and`,
    `test results.`,
  );

  return sections.join("\n");
}
