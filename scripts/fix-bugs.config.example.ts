/**
 * Example prompt module for scripts/study-crates.ts.
 *
 * Pass it with:
 *   npx tsx scripts/study-crates.ts --prompt-file scripts/study-crates.config.example.ts
 *
 * The module's default export is a function `(ctx: FileCtx) => string` that
 * returns the prompt for one file. This gives you full programmatic control:
 * branch on the crate, the path, the file name, inject extra instructions for
 * specific subsystems, etc.
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

export default function render(ctx: FileCtx): string {
  const base = [
    `There are bugs in ${ctx.file} in the ${ctx.crate} crate.`,
    `Carefully read the code line by line and fix all of the bugs.  Add additional tests to prevent regressions.`,
    `If you can't find any problems, it's ok to quit.`
  ];

  // Example of path-specific emphasis: be extra careful around the patch engine
  // and crawlers, which carry the most invariants.
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

  base.push(`End with a concise 3-6 bullet summary of the most important takeaways.`);
  return base.join(" ");
}
