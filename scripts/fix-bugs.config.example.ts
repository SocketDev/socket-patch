/**
 * Bug-fixing sweep prompt module for scripts/study-crates.ts.
 *
 * Pass it with:
 *   npx tsx scripts/study-crates.ts --prompt-file scripts/fix-bugs.config.example.ts
 *
 * The module's default export is a function `(ctx: FileCtx) => string` that
 * returns the prompt for one file. This gives you full programmatic control:
 * branch on the crate, the path, the file name, inject extra instructions for
 * specific subsystems, etc. The `model` export pins the model for the sweep;
 * an explicit --model flag overrides it.
 *
 * FileCtx fields available:
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
  const base = [
    `Review ${ctx.file} in the ${ctx.crate} crate for real production bugs.`,
    `Read it line by line. Treat every suspected bug as unconfirmed until you`,
    `write a regression test that fails on the current code; then apply the`,
    `minimal fix and make the test pass.`,
    `Do not refactor, clean up, or restructure beyond what each fix requires,`,
    `and never weaken an existing test to get green.`,
    `If the file turns out to be clean, say so plainly and stop — do not invent findings.`,
  ];

  // Path-specific emphasis: the patch engine and crawlers carry the most
  // invariants.
  if (ctx.relInCrate.startsWith("patch/")) {
    base.push(
      `This file is part of the patch engine — pay special attention to`,
      `filesystem safety, atomicity, and rollback correctness.`,
    );
  } else if (ctx.relInCrate.startsWith("crawlers/")) {
    base.push(
      `This is a package-manager crawler — note the on-disk layout assumptions`,
      `it makes and how it handles missing or malformed package metadata.`,
    );
  }

  base.push(
    `Finish by running the affected tests, then end with a concise 3-6 bullet`,
    `summary: bugs found (or "clean"), fixes applied, and test results.`,
  );
  return base.join(" ");
}
