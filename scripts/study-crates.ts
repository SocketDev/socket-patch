#!/usr/bin/env -S npx tsx
/**
 * study-crates.ts — drive `claude` once per file in each crate.
 *
 * By default it walks every `crates/*\/src/**\/*.rs` source file. With
 * `--target tests` (or `--tests`) it instead walks every `crates/*\/tests/**\/*.rs`
 * file — integration tests, test harnesses, and shared setup modules
 * (e.g. `tests/common/mod.rs`). `--target all` does both. For each discovered
 * file it spawns a non-interactive Claude Code session with a configurable
 * prompt, streams its output live to stdout, logs incremental progress, and
 * aggregates every session's final result into a single `SUMMARY.md` (plus raw
 * stream logs per file).
 *
 * Each session runs with `--dangerously-skip-permissions` and full autonomy
 * (Claude may read/edit code, run commands, etc.). Sessions run sequentially by
 * default.
 *
 * Usage:
 *   npx tsx scripts/study-crates.ts [options]
 *
 * Common examples:
 *   # Dry run — list discovered files and the rendered prompt, run nothing:
 *   npx tsx scripts/study-crates.ts --dry-run
 *
 *   # Study only the CLI crate with the default prompt:
 *   npx tsx scripts/study-crates.ts --crate socket-patch-cli
 *
 *   # Custom inline prompt with placeholders:
 *   npx tsx scripts/study-crates.ts --filter 'utils/purl' \
 *     -p 'Inspect {file} for panics and unwraps. Summarize risks.'
 *
 *   # Fully programmatic prompt via a TS module:
 *   npx tsx scripts/study-crates.ts --prompt-file scripts/study-crates.config.example.ts
 *
 *   # Audit every test file/harness one at a time for reward-hacked tests:
 *   npx tsx scripts/study-crates.ts --tests \
 *     --prompt-file scripts/harden-tests.config.ts
 *
 * Options:
 *   -p, --prompt <template>   Prompt template string. Placeholders: {file},
 *                             {abspath}, {crate}, {name}, {stem}, {relInCrate}.
 *   --prompt-file <path>      TS/JS module whose default export is
 *                             (ctx: FileCtx) => string (or { render(ctx) }).
 *                             Takes precedence over --prompt. May also
 *                             `export const model = "..."` to pin a model.
 *   --out <dir>               Output dir (default: study-output).
 *   --model <model>           Model passed to claude --model. Overrides a
 *                             prompt-file's `model` export.
 *   --filter <regex>          Only files whose repo-relative path matches.
 *   --crate <name>            Limit to a single crate dir name.
 *   --target <src|tests|all>  Which files to study (default: src). `tests`
 *                             walks each crate's tests/ dir (integration tests,
 *                             harnesses, shared setup modules); `all` does both.
 *   --tests                   Shorthand for --target tests.
 *   --concurrency <n>         Parallel sessions (default: 1 = sequential).
 *   --timeout <sec>           Per-file timeout in seconds (default: none —
 *                             sessions run until completion).
 *   --dry-run                 List files + rendered prompts; run nothing.
 *   -h, --help                Show this help.
 *
 * Env:
 *   CLAUDE_BIN                Path to the claude binary (default: "claude" on PATH).
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import {
  mkdirSync,
  writeFileSync,
  appendFileSync,
  readFileSync,
  existsSync,
  rmSync,
  createWriteStream,
  readdirSync,
  statSync,
} from "node:fs";
import { join, dirname, relative, basename, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FileCtx {
  /** Repo-relative POSIX path, e.g. "crates/socket-patch-core/src/lib.rs" */
  file: string;
  /** Absolute path on disk. */
  abspath: string;
  /** Crate directory name, e.g. "socket-patch-core". */
  crate: string;
  /** Basename, e.g. "lib.rs". */
  name: string;
  /** Basename without extension, e.g. "lib". */
  stem: string;
  /**
   * Path relative to the crate root dir the file was discovered under
   * (its `src/` dir for source files, its `tests/` dir for test files),
   * e.g. "api/client.rs" or "common/mod.rs".
   */
  relInCrate: string;
  /**
   * True when this file came from the crate's `tests/` directory
   * (an integration test, test harness, or shared setup module) rather
   * than from `src/`. Prompt renderers can branch on this.
   */
  isTest: boolean;
}

/** Which files study-crates discovers and feeds to claude. */
export type StudyTarget = "src" | "tests" | "all";

type PromptRenderer = (ctx: FileCtx) => string;

interface FileResult {
  ctx: FileCtx;
  ok: boolean;
  reason?: string;
  summary: string;
  costUsd: number;
  durationMs: number;
  numTurns: number;
  sessionId?: string;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_PROMPT_TEMPLATE = [
  "Inspect the file {file} in the {crate} crate and produce a detailed study.",
  "Cover: its responsibilities and role in the crate; the public API it exposes;",
  "key data structures and types; control flow of the main functions; error",
  "handling strategy; invariants and assumptions it relies on; notable edge cases;",
  "and any bugs, smells, or refactoring opportunities you notice.",
  "End with a concise 3-6 bullet summary of the most important takeaways.",
].join(" ");

// ---------------------------------------------------------------------------
// Repo layout
// ---------------------------------------------------------------------------

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const CRATES_DIR = join(REPO_ROOT, "crates");
const CLAUDE_BIN = process.env.CLAUDE_BIN || "claude";

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

interface Args {
  prompt?: string;
  promptFile?: string;
  out: string;
  model?: string;
  filter?: string;
  crate?: string;
  target: StudyTarget;
  concurrency: number;
  timeoutSec: number;
  offset: number;
  dryRun: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = {
    out: "study-output",
    target: "src",
    concurrency: 1,
    timeoutSec: Infinity,
    offset: 0,
    dryRun: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => {
      const v = argv[++i];
      if (v === undefined) fail(`Missing value for ${arg}`);
      return v;
    };
    switch (arg) {
      case "-p":
      case "--prompt":
        a.prompt = next();
        break;
      case "--prompt-file":
        a.promptFile = next();
        break;
      case "--out":
        a.out = next();
        break;
      case "--model":
        a.model = next();
        break;
      case "--filter":
        a.filter = next();
        break;
      case "--crate":
        a.crate = next();
        break;
      case "--target": {
        const v = next();
        if (v !== "src" && v !== "tests" && v !== "all") {
          fail(`--target must be one of: src, tests, all (got "${v}")`);
        }
        a.target = v;
        break;
      }
      case "--tests":
        // Convenience shorthand for `--target tests`.
        a.target = "tests";
        break;
      case "--concurrency":
        a.concurrency = Math.max(1, parseInt(next(), 10) || 1);
        break;
      case "--timeout": {
        const v = parseInt(next(), 10);
        if (!Number.isFinite(v) || v < 1) {
          fail(`--timeout must be a positive number of seconds`);
        }
        a.timeoutSec = v;
        break;
      }
      case "--offset":
        a.offset = Math.max(0, parseInt(next(), 10) || 0);
        break;
      case "--dry-run":
        a.dryRun = true;
        break;
      case "-h":
      case "--help":
        a.help = true;
        break;
      default:
        fail(`Unknown argument: ${arg}`);
    }
  }
  return a;
}

function fail(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(2);
}

const HELP = `study-crates.ts — run claude once per non-test crate source file.

Usage: npx tsx scripts/study-crates.ts [options]

  -p, --prompt <template>   Prompt template. Placeholders: {file} {abspath}
                            {crate} {name} {stem} {relInCrate}.
  --prompt-file <path>      TS/JS module exporting default (ctx) => string.
                            May also export const model = "..." to pin a model.
  --out <dir>               Output dir (default: study-output).
  --model <model>           Model passed to claude --model (overrides a
                            prompt-file's model export).
  --filter <regex>          Only files whose repo-relative path matches.
  --crate <name>            Limit to a single crate dir name.
  --target <src|tests|all>  Which files to study (default: src).
                            src   = non-test source under each crate's src/.
                            tests = integration tests, test harnesses, and
                                    shared setup modules under each crate's
                                    tests/ dir.
                            all   = both src and tests.
  --tests                   Shorthand for --target tests.
  --concurrency <n>         Parallel sessions (default: 1).
  --timeout <sec>           Per-file timeout in seconds (default: none —
                            sessions run until completion).
  --offset <n>              Skip the first <n> files in the deterministic order
                            (default: 0). Use to resume after a crash.
  --dry-run                 List files + rendered prompts; run nothing.
  -h, --help                Show this help.

Env: CLAUDE_BIN  Path to the claude binary (default: "claude").`;

// ---------------------------------------------------------------------------
// File discovery
// ---------------------------------------------------------------------------

function walkRs(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walkRs(full, out);
    } else if (entry.isFile() && entry.name.endsWith(".rs")) {
      out.push(full);
    }
  }
}

function discoverFiles(args: Args): FileCtx[] {
  const crates = readdirSync(CRATES_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((name) => !args.crate || name === args.crate)
    .sort();

  const filterRe = args.filter ? new RegExp(args.filter) : undefined;
  const files: FileCtx[] = [];

  // Each crate root we scan, tagged with whether its files are tests. `relInCrate`
  // is taken relative to the root dir, so it stays meaningful in both modes.
  const roots: Array<{ subdir: string; isTest: boolean }> = [];
  if (args.target === "src" || args.target === "all") {
    roots.push({ subdir: "src", isTest: false });
  }
  if (args.target === "tests" || args.target === "all") {
    roots.push({ subdir: "tests", isTest: true });
  }

  for (const crate of crates) {
    for (const root of roots) {
      const rootDir = join(CRATES_DIR, crate, root.subdir);
      let exists = false;
      try {
        exists = statSync(rootDir).isDirectory();
      } catch {
        exists = false;
      }
      if (!exists) continue;

      const abs: string[] = [];
      walkRs(rootDir, abs);
      abs.sort();

      for (const abspath of abs) {
        const file = relative(REPO_ROOT, abspath).split("\\").join("/");
        if (filterRe && !filterRe.test(file)) continue;
        const name = basename(abspath);
        files.push({
          file,
          abspath,
          crate,
          name,
          stem: name.replace(/\.rs$/, ""),
          relInCrate: relative(rootDir, abspath).split("\\").join("/"),
          isTest: root.isTest,
        });
      }
    }
  }
  // Impose a single, stable total order over the full set so the global index
  // (and therefore --offset) is deterministic across runs and independent of
  // crate/root traversal nesting. Sort by repo-relative POSIX path.
  files.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0));
  return files;
}

// ---------------------------------------------------------------------------
// Prompt rendering
// ---------------------------------------------------------------------------

function templateRenderer(template: string): PromptRenderer {
  return (ctx: FileCtx) =>
    template.replace(/\{(\w+)\}/g, (m, key: string) => {
      const v = (ctx as unknown as Record<string, unknown>)[key];
      return v === undefined ? m : String(v);
    });
}

async function loadRenderer(args: Args): Promise<PromptRenderer> {
  if (args.promptFile) {
    const modPath = resolve(process.cwd(), args.promptFile);
    const mod = await import(pathToFileURL(modPath).href);
    // Prompt modules may pin a model via `export const model = "..."`.
    if (!args.model && typeof mod.model === "string") args.model = mod.model;
    const candidate = mod.default ?? mod.render ?? mod;
    if (typeof candidate === "function") return candidate as PromptRenderer;
    if (candidate && typeof candidate.render === "function") {
      return candidate.render.bind(candidate) as PromptRenderer;
    }
    fail(
      `--prompt-file ${args.promptFile} must export a default function (ctx) => string`,
    );
  }
  if (args.prompt) return templateRenderer(args.prompt);
  return templateRenderer(DEFAULT_PROMPT_TEMPLATE);
}

// ---------------------------------------------------------------------------
// Running a single claude session
// ---------------------------------------------------------------------------

function sanitize(file: string): string {
  return file.replace(/[^A-Za-z0-9._-]+/g, "_");
}

function runOne(
  ctx: FileCtx,
  prompt: string,
  args: Args,
  index: number,
  total: number,
  rawDir: string,
): Promise<FileResult> {
  return new Promise((resolvePromise) => {
    const tag = `[${index + 1}/${total}] ${ctx.file}`;
    console.log(`\n${tag}`);

    const cliArgs = [
      "-p",
      prompt,
      "--dangerously-skip-permissions",
      "--output-format",
      "stream-json",
      "--verbose",
    ];
    if (args.model) cliArgs.push("--model", args.model);

    const child = spawn(CLAUDE_BIN, cliArgs, {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const rawPath = join(rawDir, `${sanitize(ctx.file)}.jsonl`);
    const rawStream = createWriteStream(rawPath);

    const result: FileResult = {
      ctx,
      ok: false,
      summary: "",
      costUsd: 0,
      durationMs: 0,
      numTurns: 0,
    };

    let stderrBuf = "";
    let timedOut = false;
    const start = Date.now();

    const timer = Number.isFinite(args.timeoutSec)
      ? setTimeout(() => {
          timedOut = true;
          child.kill("SIGKILL");
        }, args.timeoutSec * 1000)
      : undefined;

    const rl = createInterface({ input: child.stdout });
    rl.on("line", (line) => {
      rawStream.write(line + "\n");
      const trimmed = line.trim();
      if (!trimmed) return;
      let evt: any;
      try {
        evt = JSON.parse(trimmed);
      } catch {
        // Non-JSON line — surface it as-is.
        console.log(`  ${trimmed}`);
        return;
      }
      handleEvent(evt, ctx, result);
    });

    child.stderr.on("data", (d) => {
      stderrBuf += d.toString();
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      rawStream.end();
      result.ok = false;
      result.reason = `spawn failed: ${err.message}`;
      result.durationMs = Date.now() - start;
      console.log(`  ✗ ${result.reason}`);
      resolvePromise(result);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      rawStream.end();
      if (result.durationMs === 0) result.durationMs = Date.now() - start;
      if (timedOut) {
        result.ok = false;
        result.reason = `timed out after ${args.timeoutSec}s`;
      } else if (code !== 0 && !result.ok) {
        result.ok = false;
        result.reason =
          `exited with code ${code}` +
          (stderrBuf.trim() ? `: ${stderrBuf.trim().split("\n").slice(-3).join(" | ")}` : "");
      }
      const secs = (result.durationMs / 1000).toFixed(1);
      if (result.ok) {
        console.log(
          `  ✓ done in ${secs}s · $${result.costUsd.toFixed(4)} · ${result.numTurns} turns`,
        );
      } else {
        console.log(`  ✗ failed (${secs}s): ${result.reason ?? "unknown error"}`);
      }
      resolvePromise(result);
    });
  });
}

function handleEvent(evt: any, ctx: FileCtx, result: FileResult): void {
  switch (evt.type) {
    case "system":
      if (evt.subtype === "init" && evt.session_id) {
        result.sessionId = evt.session_id;
      }
      break;
    case "assistant": {
      const blocks = evt.message?.content ?? [];
      for (const b of blocks) {
        if (b.type === "text" && b.text?.trim()) {
          for (const ln of b.text.replace(/\n+$/, "").split("\n")) {
            console.log(`  │ ${ln}`);
          }
        } else if (b.type === "tool_use") {
          const detail = toolDetail(b);
          console.log(`  ⚙ ${b.name}${detail ? " " + detail : ""}`);
        }
      }
      break;
    }
    case "result": {
      result.ok = evt.subtype === "success" && !evt.is_error;
      result.summary =
        typeof evt.result === "string" ? evt.result : result.summary;
      result.costUsd = Number(evt.total_cost_usd) || 0;
      result.durationMs = Number(evt.duration_ms) || result.durationMs;
      result.numTurns = Number(evt.num_turns) || result.numTurns;
      if (!result.ok && !result.reason) {
        result.reason = evt.subtype || "claude reported an error";
      }
      break;
    }
    default:
      break;
  }
}

function toolDetail(block: any): string {
  const inp = block.input ?? {};
  const path = inp.file_path ?? inp.path ?? inp.notebook_path;
  if (path) return String(path).replace(REPO_ROOT + "/", "");
  if (typeof inp.command === "string") {
    return inp.command.length > 80 ? inp.command.slice(0, 77) + "..." : inp.command;
  }
  if (typeof inp.pattern === "string") return `/${inp.pattern}/`;
  return "";
}

// ---------------------------------------------------------------------------
// Concurrency helper
// ---------------------------------------------------------------------------

async function runPool<T, R>(
  items: T[],
  limit: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  async function lane(): Promise<void> {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }
  const lanes = Array.from({ length: Math.min(limit, items.length) }, lane);
  await Promise.all(lanes);
  return results;
}

// ---------------------------------------------------------------------------
// Result persistence (for crash-resume via --offset)
// ---------------------------------------------------------------------------

/**
 * Path of the machine-readable result log. One JSON object per line, appended
 * as each file completes, so a crashed sweep can be resumed with --offset
 * without losing the work already done. `writeSummary` reads this back to
 * build a SUMMARY.md spanning every pass, not just the current one.
 */
function resultsLogPath(outDir: string): string {
  return join(outDir, "results.jsonl");
}

/** Append one completed file's result to the resume log (atomic per call). */
function appendResult(outDir: string, r: FileResult): void {
  try {
    appendFileSync(resultsLogPath(outDir), JSON.stringify(r) + "\n");
  } catch (err) {
    // Persistence is best-effort: a failed append must not abort the sweep.
    const message = err instanceof Error ? err.message : String(err);
    console.log(`  ! could not persist result for ${r.ctx.file}: ${message}`);
  }
}

/**
 * Load all previously-logged results, de-duplicated by file (last write wins,
 * so a re-run of the same file in a later pass supersedes the earlier one).
 * Returns an empty array if the log is absent or unreadable.
 */
function loadPriorResults(outDir: string): FileResult[] {
  const path = resultsLogPath(outDir);
  if (!existsSync(path)) return [];
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const byFile = new Map<string, FileResult>();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const r = JSON.parse(trimmed) as FileResult;
      if (r?.ctx?.file) byFile.set(r.ctx.file, r);
    } catch {
      // Skip a corrupt/truncated line (e.g. a crash mid-write) rather than fail.
    }
  }
  return [...byFile.values()];
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

function writeSummary(
  outDir: string,
  unordered: FileResult[],
  args: Args,
): string {
  // Results may arrive out of discovery order (concurrency) or merged from a
  // resume log (Map iteration); impose the same stable path order used for
  // discovery so the report is deterministic across runs.
  const results = [...unordered].sort((a, b) =>
    a.ctx.file < b.ctx.file ? -1 : a.ctx.file > b.ctx.file ? 1 : 0,
  );
  const ok = results.filter((r) => r.ok);
  const failed = results.filter((r) => !r.ok);
  const totalCost = results.reduce((s, r) => s + r.costUsd, 0);
  const totalMs = results.reduce((s, r) => s + r.durationMs, 0);

  const lines: string[] = [];
  const title =
    args.target === "tests"
      ? "Crate Test Study"
      : args.target === "all"
        ? "Crate Source + Test Study"
        : "Crate Source Study";
  lines.push(`# ${title}`);
  lines.push("");
  lines.push(`Generated by \`scripts/study-crates.ts\` (target: ${args.target}).`);
  lines.push("");
  lines.push("## Totals");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | --- |");
  lines.push(`| Files studied | ${results.length} |`);
  lines.push(`| Succeeded | ${ok.length} |`);
  lines.push(`| Failed | ${failed.length} |`);
  lines.push(`| Total cost (USD) | $${totalCost.toFixed(4)} |`);
  lines.push(`| Total session time | ${(totalMs / 1000).toFixed(1)}s |`);
  if (args.model) lines.push(`| Model | ${args.model} |`);
  lines.push("");

  if (failed.length) {
    lines.push("## Failures");
    lines.push("");
    for (const r of failed) {
      lines.push(`- \`${r.ctx.file}\` — ${r.reason ?? "unknown error"}`);
    }
    lines.push("");
  }

  lines.push("## Per-file studies");
  lines.push("");
  for (const r of results) {
    lines.push(`### ${r.ctx.file}`);
    lines.push("");
    const status = r.ok ? "✓" : "✗";
    lines.push(
      `${status} crate \`${r.ctx.crate}\` · $${r.costUsd.toFixed(4)} · ` +
        `${(r.durationMs / 1000).toFixed(1)}s · ${r.numTurns} turns` +
        (r.sessionId ? ` · session \`${r.sessionId}\`` : ""),
    );
    lines.push("");
    if (r.ok) {
      lines.push(r.summary.trim() || "_(no summary text returned)_");
    } else {
      lines.push(`**Failed:** ${r.reason ?? "unknown error"}`);
      if (r.summary.trim()) {
        lines.push("");
        lines.push(r.summary.trim());
      }
    }
    lines.push("");
  }

  const summaryPath = join(outDir, "SUMMARY.md");
  writeFileSync(summaryPath, lines.join("\n"));
  return summaryPath;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(HELP);
    return;
  }

  const allFiles = discoverFiles(args);
  if (allFiles.length === 0) {
    fail("No matching source files found.");
  }
  if (args.offset >= allFiles.length) {
    fail(
      `--offset ${args.offset} skips all ${allFiles.length} discovered file(s); nothing to do.`,
    );
  }
  // Resume support: skip the first `offset` files in the deterministic order.
  const files =
    args.offset > 0 ? allFiles.slice(args.offset) : allFiles;
  if (args.offset > 0) {
    console.log(
      `Skipping first ${args.offset} of ${allFiles.length} file(s) (--offset); ` +
        `${files.length} remaining.`,
    );
  }

  const renderer = await loadRenderer(args);

  if (args.dryRun) {
    const label =
      args.target === "tests"
        ? "test"
        : args.target === "all"
          ? "source + test"
          : "non-test source";
    if (args.model) console.log(`Model: ${args.model}\n`);
    console.log(`Discovered ${files.length} ${label} file(s):\n`);
    files.forEach((ctx, i) => {
      // Global index (incl. --offset) so the printed number is the value to
      // pass as --offset to resume from this file.
      console.log(`• [${args.offset + i}] ${ctx.file}`);
      const prompt = renderer(ctx);
      const preview = prompt.length > 240 ? prompt.slice(0, 237) + "..." : prompt;
      console.log(`    prompt: ${preview.replace(/\n/g, " ")}`);
    });
    console.log(
      `\n(dry run — nothing executed; ${files.length} session(s) would run, ` +
        `concurrency ${args.concurrency})`,
    );
    return;
  }

  const outDir = resolve(process.cwd(), args.out);
  const rawDir = join(outDir, "raw");
  mkdirSync(rawDir, { recursive: true });

  // Resume support: a fresh run (offset 0) starts the result log clean so a
  // prior sweep's entries don't leak into this report. A resume (offset > 0)
  // keeps the log and appends to it, so SUMMARY.md spans every pass.
  if (args.offset === 0) {
    rmSync(resultsLogPath(outDir), { force: true });
  } else {
    const priorCount = loadPriorResults(outDir).length;
    console.log(
      `Resuming: ${priorCount} prior result(s) loaded from ` +
        `${resultsLogPath(outDir)} will be merged into the report.`,
    );
  }

  console.log(
    `Studying ${files.length} file(s) with ${CLAUDE_BIN} ` +
      `(concurrency ${args.concurrency}, timeout ${
        Number.isFinite(args.timeoutSec) ? `${args.timeoutSec}s` : "none"
      }).`,
  );
  console.log(`Output → ${outDir}`);

  let done = 0;
  let runningCost = 0;
  const total = files.length;

  const results = await runPool(files, args.concurrency, async (ctx, i) => {
    // Never let one file's failure abort the whole sweep: any unexpected throw
    // (e.g. a renderer that blows up on this ctx) is recorded as a failed
    // result and the pool moves on. runOne itself already resolves on
    // spawn/timeout/non-zero errors rather than rejecting.
    let r: FileResult;
    try {
      const prompt = renderer(ctx);
      r = await runOne(ctx, prompt, args, i, total, rawDir);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.log(`  ✗ skipped ${ctx.file}: ${message}`);
      r = {
        ctx,
        ok: false,
        reason: `unhandled error: ${message}`,
        summary: "",
        costUsd: 0,
        durationMs: 0,
        numTurns: 0,
      };
    }
    // Persist immediately so a later crash can resume via --offset without
    // losing this file's work.
    appendResult(outDir, r);
    done++;
    runningCost += r.costUsd;
    console.log(
      `  …progress: ${done}/${total} complete · running cost $${runningCost.toFixed(4)}`,
    );
    return r;
  });

  // Merge this pass with any prior passes recorded in the resume log (last
  // write per file wins, handled by loadPriorResults) so SUMMARY.md reflects
  // every file studied across resumes, not just this invocation. writeSummary
  // re-imposes the deterministic file order.
  const merged = loadPriorResults(outDir);
  const summaryPath = writeSummary(outDir, merged, args);

  const thisOk = results.filter((r) => r.ok).length;
  const thisFailed = results.length - thisOk;
  const mergedOk = merged.filter((r) => r.ok).length;
  const mergedFailed = merged.length - mergedOk;
  console.log("\n──────────────────────────────────────────");
  console.log(
    `This pass: ${thisOk} succeeded, ${thisFailed} failed of ${total}.`,
  );
  if (args.offset > 0 || merged.length !== results.length) {
    console.log(
      `Overall (incl. prior passes): ${mergedOk} succeeded, ` +
        `${mergedFailed} failed of ${merged.length}.`,
    );
  }
  console.log(`Total cost (this pass): $${runningCost.toFixed(4)}`);
  console.log(`Summary written to ${summaryPath}`);
  console.log(`Raw streams in ${rawDir}`);
  if (mergedFailed > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
