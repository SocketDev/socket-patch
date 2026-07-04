#!/usr/bin/env -S npx tsx
/**
 * burn-down-tests.ts — drive `claude` to burn down failing tests, one at a time.
 *
 * A serial loop (NOT the parallel per-file sweep that study-crates.ts runs):
 *
 *   1. Run the test suite and enumerate every currently-FAILING test.
 *   2. Sort them deterministically and select EXACTLY ONE.
 *   3. Spawn a fresh, autonomous Claude session to fix that one test by
 *      repairing its root cause (see scripts/burn-down-tests.config.ts).
 *   4. INDEPENDENTLY verify with cargo: the target test now passes and no other
 *      test regressed.
 *   5. A second, adversarial REVIEW session inspects the diff for reward
 *      hacking (see scripts/burn-down-review.config.ts). Fail closed.
 *   6. Only if cargo is green AND the review says GENUINE: commit that single
 *      fix (`git commit`). Then loop.
 *
 * A test that cannot be fixed safely — the fix agent bails out, it exhausts
 * --max-attempts, or its fix keeps getting rejected as a reward hack — is
 * marked STUCK, left untouched, and the loop moves on to a different test.
 * Stuck tests are collected into BURNDOWN.md's "Needs human review" section.
 *
 * Usage:
 *   npx tsx scripts/burn-down-tests.ts [options]
 *
 *   # See what it would do (enumerate + pick + show prompt; run nothing):
 *   npx tsx scripts/burn-down-tests.ts --dry-run
 *
 *   # Burn down with a specific model and a higher per-test retry budget:
 *   npx tsx scripts/burn-down-tests.ts --model claude-opus-4-8 --max-attempts 3
 *
 * Options:
 *   --features <csv>          cargo features for the suite + single-test runs
 *                             (default: none — every ecosystem is unconditional;
 *                             intentionally NOT --all-features, which would pull
 *                             in the infra-gated docker-e2e / setup-e2e suites).
 *   --test-cmd <cmd>          Override the full-suite enumeration command
 *                             (default: cargo test --workspace --features <csv>
 *                             --no-fail-fast).
 *   --max-attempts <n>        Attempts per test before it is parked (default: 2).
 *   --max-iterations <n>      Hard cap on total loop iterations (default: 200).
 *   --timeout <sec>           Per-agent-session timeout (default: 1800).
 *   --model <model>           Model for the fix agent (claude --model).
 *   --review-model <model>    Model for the review agent (defaults to --model).
 *   --no-review               Disable the reward-hack review gate (NOT advised).
 *   --commit-prefix <s>       Commit message prefix (default: "fix(test): ").
 *   --prompt-file <path>      Fix-prompt module (default: burn-down-tests.config.ts).
 *   --review-prompt-file <p>  Review-prompt module (default: burn-down-review.config.ts).
 *   --out <dir>               Output dir (default: burndown-output).
 *   --allow-dirty             Skip the clean-working-tree precondition.
 *   --dry-run                 Enumerate + pick + show prompt; run nothing.
 *   -h, --help                Show this help.
 *
 * SAFETY: on a failed/rejected attempt the harness runs `git reset --hard` +
 * `git clean -fd` (excluding --out) to discard the agent's uncommitted changes.
 * This only ever discards UNCOMMITTED work; committed fixes are safe. Run on a
 * clean tree (or pass --allow-dirty knowing the first commit bundles your
 * pending changes). Commits use --no-verify to avoid hook interference.
 *
 * Env:
 *   CLAUDE_BIN                Path to the claude binary (default: "claude").
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import {
  mkdirSync,
  writeFileSync,
  appendFileSync,
  readFileSync,
  existsSync,
  createWriteStream,
} from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// ---------------------------------------------------------------------------
// Repo layout
// ---------------------------------------------------------------------------

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const CLAUDE_BIN = process.env.CLAUDE_BIN || "claude";

const DEFAULT_FEATURES = "";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Args {
  features: string;
  testCmd?: string;
  maxAttempts: number;
  maxIterations: number;
  timeoutSec: number;
  model?: string;
  reviewModel?: string;
  review: boolean;
  commitPrefix: string;
  promptFile?: string;
  reviewPromptFile?: string;
  out: string;
  allowDirty: boolean;
  dryRun: boolean;
  help: boolean;
}

/** Result of one autonomous claude session (fix or review). */
interface AgentResult {
  ok: boolean;
  reason?: string;
  summary: string;
  costUsd: number;
  durationMs: number;
  numTurns: number;
  sessionId?: string;
}

/** Outcome of running cargo (full suite or a single test). */
interface CargoResult {
  failing: string[];
  detail: Map<string, string>;
  compiled: boolean;
  raw: string;
  exitCode: number | null;
}

interface TestCtx {
  test: string;
  failureDetail: string;
  features: string;
  attempt: number;
  iteration: number;
}

interface ReviewCtx {
  test: string;
  failureDetail: string;
  diff: string;
  features: string;
}

type FixRenderer = (ctx: TestCtx) => string;
type ReviewRenderer = (ctx: ReviewCtx) => string;

// ---------------------------------------------------------------------------
// Arg parsing
// ---------------------------------------------------------------------------

function fail(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(2);
}

function parseArgs(argv: string[]): Args {
  const a: Args = {
    features: DEFAULT_FEATURES,
    maxAttempts: 2,
    maxIterations: 200,
    timeoutSec: 1800,
    review: true,
    commitPrefix: "fix(test): ",
    out: "burndown-output",
    allowDirty: false,
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
      case "--features":
        a.features = next();
        break;
      case "--test-cmd":
        a.testCmd = next();
        break;
      case "--max-attempts":
        a.maxAttempts = Math.max(1, parseInt(next(), 10) || 2);
        break;
      case "--max-iterations":
        a.maxIterations = Math.max(1, parseInt(next(), 10) || 200);
        break;
      case "--timeout":
        a.timeoutSec = Math.max(1, parseInt(next(), 10) || 1800);
        break;
      case "--model":
        a.model = next();
        break;
      case "--review-model":
        a.reviewModel = next();
        break;
      case "--no-review":
        a.review = false;
        break;
      case "--commit-prefix":
        a.commitPrefix = next();
        break;
      case "--prompt-file":
        a.promptFile = next();
        break;
      case "--review-prompt-file":
        a.reviewPromptFile = next();
        break;
      case "--out":
        a.out = next();
        break;
      case "--allow-dirty":
        a.allowDirty = true;
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

const HELP = `burn-down-tests.ts — fix failing tests one at a time, in a loop.

Usage: npx tsx scripts/burn-down-tests.ts [options]

  --features <csv>          cargo features (default: ${DEFAULT_FEATURES}).
  --test-cmd <cmd>          Override the full-suite enumeration command.
  --max-attempts <n>        Attempts per test before parking it (default: 2).
  --max-iterations <n>      Hard cap on loop iterations (default: 200).
  --timeout <sec>           Per-agent-session timeout (default: 1800).
  --model <model>           Model for the fix agent.
  --review-model <model>    Model for the review agent (defaults to --model).
  --no-review               Disable the reward-hack review gate.
  --commit-prefix <s>       Commit message prefix (default: "fix(test): ").
  --prompt-file <path>      Fix-prompt module (default: burn-down-tests.config.ts).
  --review-prompt-file <p>  Review-prompt module (default: burn-down-review.config.ts).
  --out <dir>               Output dir (default: burndown-output).
  --allow-dirty             Skip the clean-working-tree precondition.
  --dry-run                 Enumerate + pick + show prompt; run nothing.
  -h, --help                Show this help.

Env: CLAUDE_BIN  Path to the claude binary (default: "claude").`;

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/** Run a shell command, capturing combined stdout+stderr. Never rejects. */
function sh(
  cmd: string,
  opts: { timeoutSec?: number } = {},
): Promise<{ code: number | null; out: string }> {
  return new Promise((resolvePromise) => {
    const child = spawn("bash", ["-c", cmd], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let timer: NodeJS.Timeout | undefined;
    if (opts.timeoutSec) {
      timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutSec * 1000);
    }
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (out += d.toString()));
    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      resolvePromise({ code: null, out: out + `\n[spawn error] ${err.message}` });
    });
    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolvePromise({ code, out });
    });
  });
}

/** Quote a string for safe use as a single shell argument. */
function shq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

// ---------------------------------------------------------------------------
// git helpers
// ---------------------------------------------------------------------------

async function gitDirtyFiles(): Promise<string[]> {
  const { out } = await sh("git status --porcelain");
  return out
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.length > 0)
    .sort();
}

async function gitDiffHead(): Promise<string> {
  const { out } = await sh("git diff HEAD");
  return out;
}

/** Discard ALL uncommitted changes, but never touch the output dir. */
async function gitResetHard(outDirRel: string): Promise<void> {
  await sh("git reset --hard HEAD");
  // -e excludes the harness output dir so its logs/report survive the clean.
  await sh(`git clean -fd -e ${shq(outDirRel)}`);
}

/**
 * Make the harness output dir invisible to git via .git/info/exclude, so its
 * logs are never swept into a fix commit by `git add -A`, never pollute the
 * clean-tree precondition or the read-only review guard, and are preserved by
 * `git clean`. No-op when the output dir lives outside the repo or .git is not
 * a standard directory.
 */
function ensureGitIgnoredOutput(outDirRel: string): void {
  if (outDirRel.startsWith("..")) return; // outside the repo — git won't see it
  const infoDir = join(REPO_ROOT, ".git", "info");
  if (!existsSync(infoDir)) return; // non-standard .git (worktree/submodule)
  const excludePath = join(infoDir, "exclude");
  const pattern = `/${outDirRel.replace(/\/+$/, "")}/`;
  try {
    const cur = existsSync(excludePath) ? readFileSync(excludePath, "utf8") : "";
    if (cur.split("\n").some((l) => l.trim() === pattern)) return;
    const sep = cur === "" || cur.endsWith("\n") ? "" : "\n";
    appendFileSync(excludePath, `${sep}${pattern}\n`);
  } catch {
    // best-effort
  }
}

async function gitCommit(message: string): Promise<string> {
  await sh("git add -A");
  await sh(`git commit --no-verify -m ${shq(message)}`);
  const { out } = await sh("git rev-parse HEAD");
  return out.trim();
}

// ---------------------------------------------------------------------------
// cargo: run + parse failing tests
// ---------------------------------------------------------------------------

/**
 * Parse libtest console output. Failing tests appear as
 *   `test <name> ... FAILED`
 * and their captured output as a `---- <name> stdout ----` block. We also
 * decide whether the suite actually compiled and ran (vs. a build error).
 */
function parseTestOutput(raw: string): {
  failing: string[];
  detail: Map<string, string>;
  compiled: boolean;
} {
  const lines = raw.split("\n");
  const failingSet = new Set<string>();
  const detail = new Map<string, string>();

  let ran = false;
  for (const line of lines) {
    const t = line.trim();
    if (/^running \d+ tests?$/.test(t) || /^test result:/.test(t)) ran = true;
    const m = /^test (.+?) \.\.\. FAILED$/.exec(t);
    if (m) failingSet.add(m[1]);
  }

  // Extract per-test failure detail blocks.
  for (let i = 0; i < lines.length; i++) {
    const m = /^---- (.+?) stdout ----$/.exec(lines[i].trim());
    if (!m) continue;
    const name = m[1];
    const block: string[] = [];
    for (let j = i + 1; j < lines.length; j++) {
      const lt = lines[j].trim();
      if (
        /^---- .+ ----$/.test(lt) ||
        /^failures:$/.test(lt) ||
        /^test result:/.test(lt)
      ) {
        break;
      }
      block.push(lines[j]);
    }
    detail.set(name, block.join("\n").trim());
  }

  return { failing: [...failingSet], detail, compiled: ran };
}

async function runCargo(cmd: string, timeoutSec?: number): Promise<CargoResult> {
  const { code, out } = await sh(cmd, { timeoutSec });
  const { failing, detail, compiled } = parseTestOutput(out);
  return { failing, detail, compiled, raw: out, exitCode: code };
}

function suiteCommand(args: Args): string {
  if (args.testCmd) return args.testCmd;
  const feat = args.features ? ` --features ${args.features}` : "";
  return `cargo test --workspace${feat} --no-fail-fast`;
}

function singleTestCommand(args: Args, test: string): string {
  const feat = args.features ? ` --features ${args.features}` : "";
  return `cargo test ${shq(test)}${feat} -- --exact`;
}

// ---------------------------------------------------------------------------
// claude session runner (mirrors study-crates.ts machinery)
// ---------------------------------------------------------------------------

function sanitize(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, "_");
}

function toolDetail(block: any): string {
  const inp = block.input ?? {};
  const path = inp.file_path ?? inp.path ?? inp.notebook_path;
  if (path) return String(path).replace(REPO_ROOT + "/", "");
  if (typeof inp.command === "string") {
    return inp.command.length > 80
      ? inp.command.slice(0, 77) + "..."
      : inp.command;
  }
  if (typeof inp.pattern === "string") return `/${inp.pattern}/`;
  return "";
}

function handleEvent(evt: any, result: AgentResult): void {
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
          const d = toolDetail(b);
          console.log(`  ⚙ ${b.name}${d ? " " + d : ""}`);
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

function runAgent(
  prompt: string,
  model: string | undefined,
  timeoutSec: number,
  rawPath: string,
): Promise<AgentResult> {
  return new Promise((resolvePromise) => {
    const cliArgs = [
      "-p",
      prompt,
      "--dangerously-skip-permissions",
      "--output-format",
      "stream-json",
      "--verbose",
    ];
    if (model) cliArgs.push("--model", model);

    const child = spawn(CLAUDE_BIN, cliArgs, {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const rawStream = createWriteStream(rawPath);
    const result: AgentResult = {
      ok: false,
      summary: "",
      costUsd: 0,
      durationMs: 0,
      numTurns: 0,
    };

    let stderrBuf = "";
    let timedOut = false;
    const start = Date.now();
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutSec * 1000);

    const rl = createInterface({ input: child.stdout });
    rl.on("line", (line) => {
      rawStream.write(line + "\n");
      const trimmed = line.trim();
      if (!trimmed) return;
      let evt: any;
      try {
        evt = JSON.parse(trimmed);
      } catch {
        console.log(`  ${trimmed}`);
        return;
      }
      handleEvent(evt, result);
    });

    child.stderr.on("data", (d) => (stderrBuf += d.toString()));

    child.on("error", (err) => {
      clearTimeout(timer);
      rawStream.end();
      result.ok = false;
      result.reason = `spawn failed: ${err.message}`;
      result.durationMs = Date.now() - start;
      resolvePromise(result);
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      rawStream.end();
      if (result.durationMs === 0) result.durationMs = Date.now() - start;
      if (timedOut) {
        result.ok = false;
        result.reason = `timed out after ${timeoutSec}s`;
      } else if (code !== 0 && !result.ok) {
        result.ok = false;
        result.reason =
          `exited with code ${code}` +
          (stderrBuf.trim()
            ? `: ${stderrBuf.trim().split("\n").slice(-3).join(" | ")}`
            : "");
      }
      resolvePromise(result);
    });
  });
}

// ---------------------------------------------------------------------------
// Prompt renderers
// ---------------------------------------------------------------------------

async function loadModule<T>(path: string, what: string): Promise<T> {
  const modPath = resolve(process.cwd(), path);
  const mod = await import(pathToFileURL(modPath).href);
  const candidate = mod.default ?? mod.render ?? mod;
  if (typeof candidate === "function") return candidate as T;
  if (candidate && typeof candidate.render === "function") {
    return candidate.render.bind(candidate) as T;
  }
  fail(`${what} ${path} must export a default function`);
}

// ---------------------------------------------------------------------------
// Verdict / bailout parsing
// ---------------------------------------------------------------------------

function parseVerdict(summary: string): { genuine: boolean; reason: string } {
  // Scan from the end for the last explicit VERDICT line. Fail closed.
  const lines = summary.split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = /^\s*VERDICT:\s*(GENUINE|REWARD_HACK)\b(.*)$/i.exec(lines[i]);
    if (m) {
      const genuine = m[1].toUpperCase() === "GENUINE";
      return { genuine, reason: m[2].replace(/^[\s—:-]+/, "").trim() };
    }
  }
  return { genuine: false, reason: "no explicit VERDICT line found (fail closed)" };
}

function parseBailout(summary: string): string | null {
  const lines = summary.split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = /^\s*BAILOUT:\s*(.*)$/i.exec(lines[i]);
    if (m) return m[1].trim() || "(no reason given)";
  }
  return null;
}

// ---------------------------------------------------------------------------
// Report + resume log
// ---------------------------------------------------------------------------

interface FixedRecord {
  test: string;
  sha: string;
  attempts: number;
  verdict: string;
}
interface StuckRecord {
  test: string;
  reason: string;
  attempts: number;
}

function logAttempt(outDir: string, record: Record<string, unknown>): void {
  try {
    appendFileSync(
      join(outDir, "burndown-log.jsonl"),
      JSON.stringify(record) + "\n",
    );
  } catch {
    // best-effort
  }
}

function writeBurndown(
  outDir: string,
  fixed: FixedRecord[],
  stuck: StuckRecord[],
  remaining: string[],
  totals: { iterations: number; costUsd: number; wallMs: number },
): string {
  const lines: string[] = [];
  lines.push("# Test Burn-Down");
  lines.push("");
  lines.push("Generated by `scripts/burn-down-tests.ts`.");
  lines.push("");
  lines.push("## Totals");
  lines.push("");
  lines.push("| Metric | Value |");
  lines.push("| --- | --- |");
  lines.push(`| Tests fixed (committed) | ${fixed.length} |`);
  lines.push(`| Tests parked for review | ${stuck.length} |`);
  lines.push(`| Still failing (uncategorized) | ${remaining.length} |`);
  lines.push(`| Loop iterations | ${totals.iterations} |`);
  lines.push(`| Total agent cost (USD) | $${totals.costUsd.toFixed(4)} |`);
  lines.push(`| Wall-clock | ${(totals.wallMs / 1000).toFixed(1)}s |`);
  lines.push("");

  lines.push("## Fixed");
  lines.push("");
  if (fixed.length === 0) {
    lines.push("_(none)_");
  } else {
    lines.push("| Test | Commit | Attempts | Review |");
    lines.push("| --- | --- | --- | --- |");
    for (const f of fixed) {
      lines.push(
        `| \`${f.test}\` | \`${f.sha.slice(0, 12)}\` | ${f.attempts} | ${f.verdict} |`,
      );
    }
  }
  lines.push("");

  lines.push("## Needs human review (stuck — left untouched)");
  lines.push("");
  if (stuck.length === 0) {
    lines.push("_(none)_");
  } else {
    for (const s of stuck) {
      lines.push(`- \`${s.test}\` — ${s.reason} (after ${s.attempts} attempt(s))`);
    }
  }
  lines.push("");

  if (remaining.length) {
    lines.push("## Still failing at exit (cap/iteration reached)");
    lines.push("");
    for (const t of remaining) lines.push(`- \`${t}\``);
    lines.push("");
  }

  const p = join(outDir, "BURNDOWN.md");
  writeFileSync(p, lines.join("\n"));
  return p;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sortedUnique(xs: string[]): string[] {
  return [...new Set(xs)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function isSubset(sub: string[], superSet: Set<string>): boolean {
  return sub.every((x) => superSet.has(x));
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

  const fixRenderer: FixRenderer = args.promptFile
    ? await loadModule<FixRenderer>(args.promptFile, "--prompt-file")
    : await loadModule<FixRenderer>(
        join(SCRIPT_DIR, "burn-down-tests.config.ts"),
        "fix prompt",
      );
  const reviewRenderer: ReviewRenderer = args.review
    ? args.reviewPromptFile
      ? await loadModule<ReviewRenderer>(
          args.reviewPromptFile,
          "--review-prompt-file",
        )
      : await loadModule<ReviewRenderer>(
          join(SCRIPT_DIR, "burn-down-review.config.ts"),
          "review prompt",
        )
    : (() => "");

  const outDir = resolve(process.cwd(), args.out);
  const outDirRel = relative(REPO_ROOT, outDir) || args.out;
  const rawDir = join(outDir, "raw");
  mkdirSync(rawDir, { recursive: true });
  // Keep the harness's own output out of git: never committed, never flagged
  // as a dirty/regressing change, preserved across `git clean`.
  ensureGitIgnoredOutput(outDirRel);

  const suiteCmd = suiteCommand(args);
  console.log(`Test command: ${suiteCmd}`);
  console.log("Enumerating failing tests (initial full run)…");
  const initial = await runCargo(suiteCmd, args.timeoutSec);

  if (!initial.compiled) {
    console.error(
      "\n✗ The test suite did not compile/run — cannot enumerate failing " +
        "tests. Fix the build first. Tail of cargo output:\n",
    );
    console.error(initial.raw.trim().split("\n").slice(-40).join("\n"));
    process.exit(1);
  }

  let failing = sortedUnique(initial.failing);
  let detail = initial.detail;
  console.log(`\nFailing tests: ${failing.length}`);
  for (const t of failing) console.log(`  • ${t}`);

  if (failing.length === 0) {
    console.log("\n✓ No failing tests. Nothing to burn down.");
    return;
  }

  // ----- dry run -----
  if (args.dryRun) {
    const pick = failing[0];
    const prompt = fixRenderer({
      test: pick,
      failureDetail: detail.get(pick) ?? "",
      features: args.features,
      attempt: 1,
      iteration: 1,
    });
    console.log(`\nWould select: ${pick}\n`);
    console.log("--- rendered fix prompt ---");
    console.log(prompt);
    console.log(
      `\n(dry run — nothing executed; ${failing.length} failing test(s) ` +
        `would be burned down one at a time)`,
    );
    return;
  }

  // ----- clean tree precondition -----
  if (!args.allowDirty) {
    const dirty = await gitDirtyFiles();
    if (dirty.length) {
      console.error(
        "\n✗ Working tree is not clean. The harness commits after each fix, " +
          "so pending changes would be bundled into the first commit.\n" +
          "  Commit or stash your changes, or pass --allow-dirty to proceed.\n" +
          "  Dirty entries:",
      );
      for (const d of dirty.slice(0, 20)) console.error(`    ${d}`);
      process.exit(1);
    }
  }

  console.log(`\nOutput → ${outDir}`);
  console.log(
    `Burning down ${failing.length} failing test(s) ` +
      `(max-attempts ${args.maxAttempts}, review ${args.review ? "ON" : "OFF"}).`,
  );

  const fixed: FixedRecord[] = [];
  const stuck: StuckRecord[] = [];
  const attempts = new Map<string, number>();
  const stuckSet = new Set<string>();
  let totalCost = 0;
  let iteration = 0;
  const startWall = Date.now();

  while (iteration < args.maxIterations) {
    // Pick the lexicographically-first failing test that isn't parked.
    const candidates = failing.filter((t) => !stuckSet.has(t));
    if (candidates.length === 0) break;
    const test = candidates[0];
    iteration++;
    const attempt = (attempts.get(test) ?? 0) + 1;
    const prevFailing = new Set(failing);

    console.log(
      `\n[iteration ${iteration}] fixing: ${test} ` +
        `(attempt ${attempt}/${args.maxAttempts}, ${candidates.length} failing left)`,
    );

    // ----- fix agent -----
    const fixPrompt = fixRenderer({
      test,
      failureDetail: detail.get(test) ?? "",
      features: args.features,
      attempt,
      iteration,
    });
    const fixRaw = join(rawDir, `${sanitize(test)}.attempt${attempt}.fix.jsonl`);
    const fixRes = await runAgent(fixPrompt, args.model, args.timeoutSec, fixRaw);
    totalCost += fixRes.costUsd;
    const bailout = parseBailout(fixRes.summary);
    logAttempt(outDir, {
      iteration,
      test,
      attempt,
      phase: "fix",
      sessionId: fixRes.sessionId,
      ok: fixRes.ok,
      reason: fixRes.reason,
      bailout,
      costUsd: fixRes.costUsd,
      durationMs: fixRes.durationMs,
    });

    // ----- bailout: park immediately, no cargo, no commit -----
    if (bailout) {
      console.log(`  ⏭ bailout: ${bailout} — parking for review`);
      await gitResetHard(outDirRel);
      stuckSet.add(test);
      stuck.push({ test, reason: `bailout: ${bailout}`, attempts: attempt });
      continue;
    }

    const recordFailedAttempt = async (reason: string) => {
      console.log(`  ✗ attempt failed: ${reason}`);
      await gitResetHard(outDirRel);
      attempts.set(test, attempt);
      if (attempt >= args.maxAttempts) {
        stuckSet.add(test);
        stuck.push({
          test,
          reason: `unfixed after ${attempt} attempt(s): ${reason}`,
          attempts: attempt,
        });
        console.log(`  ⏭ parking ${test} for review (max attempts reached)`);
      }
      // Tree is restored to pre-attempt state, so `failing`/`detail` still hold.
    };

    if (!fixRes.ok) {
      await recordFailedAttempt(fixRes.reason ?? "fix session did not succeed");
      continue;
    }

    // ----- cargo verification: target passes -----
    console.log(`  → verifying ${test} passes…`);
    const single = await runCargo(singleTestCommand(args, test), args.timeoutSec);
    if (!single.compiled || single.failing.includes(test) || single.failing.length) {
      await recordFailedAttempt(
        !single.compiled ? "fix broke the build" : "target test still fails",
      );
      continue;
    }

    // ----- cargo verification: no regressions (full suite) -----
    console.log("  → re-running full suite to check for regressions…");
    const after = await runCargo(suiteCmd, args.timeoutSec);
    if (!after.compiled) {
      await recordFailedAttempt("fix broke the build (full suite)");
      continue;
    }
    const afterFailing = sortedUnique(after.failing);
    if (afterFailing.includes(test)) {
      await recordFailedAttempt("target test still fails in full suite");
      continue;
    }
    if (!isSubset(afterFailing, prevFailing)) {
      const regressions = afterFailing.filter((t) => !prevFailing.has(t));
      await recordFailedAttempt(`introduced regressions: ${regressions.join(", ")}`);
      continue;
    }

    // ----- no-op guard: passing without any change -----
    const diff = await gitDiffHead();
    if (!diff.trim()) {
      console.log(
        `  ℹ ${test} now passes with no code change (already fixed / flaky) — ` +
          "dropping without a commit",
      );
      attempts.delete(test);
      failing = afterFailing;
      detail = after.detail;
      continue;
    }

    // ----- reward-hack review gate -----
    let verdictLabel = "skipped";
    if (args.review) {
      console.log("  → reviewing fix for reward hacking…");
      const dirtyBefore = await gitDirtyFiles();
      const reviewPrompt = reviewRenderer({
        test,
        failureDetail: detail.get(test) ?? "",
        diff,
        features: args.features,
      });
      const revRaw = join(
        rawDir,
        `${sanitize(test)}.attempt${attempt}.review.jsonl`,
      );
      const revRes = await runAgent(
        reviewPrompt,
        args.reviewModel ?? args.model,
        args.timeoutSec,
        revRaw,
      );
      totalCost += revRes.costUsd;
      const verdict = parseVerdict(revRes.summary);
      logAttempt(outDir, {
        iteration,
        test,
        attempt,
        phase: "review",
        sessionId: revRes.sessionId,
        ok: revRes.ok,
        genuine: verdict.genuine,
        verdictReason: verdict.reason,
        costUsd: revRes.costUsd,
        durationMs: revRes.durationMs,
      });

      // Guard: the read-only reviewer must not have mutated the tree.
      const dirtyAfter = await gitDirtyFiles();
      if (JSON.stringify(dirtyAfter) !== JSON.stringify(dirtyBefore)) {
        await recordFailedAttempt(
          "review agent modified the working tree (must be read-only)",
        );
        continue;
      }
      if (!revRes.ok) {
        await recordFailedAttempt(
          `review session did not succeed: ${revRes.reason ?? "unknown"}`,
        );
        continue;
      }
      if (!verdict.genuine) {
        await recordFailedAttempt(`reward-hack rejected: ${verdict.reason}`);
        continue;
      }
      verdictLabel = "GENUINE";
      console.log("  ✓ review: GENUINE");
    }

    // ----- commit -----
    const sha = await gitCommit(`${args.commitPrefix}${test}`);
    fixed.push({ test, sha, attempts: attempt, verdict: verdictLabel });
    attempts.delete(test);
    console.log(`  ✓ committed ${sha.slice(0, 12)} — ${test}`);

    // Adopt the post-fix suite result as the next iteration's enumeration.
    failing = afterFailing;
    detail = after.detail;
  }

  const remaining = failing.filter((t) => !stuckSet.has(t));
  const summaryPath = writeBurndown(outDir, fixed, stuck, remaining, {
    iterations: iteration,
    costUsd: totalCost,
    wallMs: Date.now() - startWall,
  });

  console.log("\n──────────────────────────────────────────");
  console.log(`Fixed (committed): ${fixed.length}`);
  console.log(`Parked for review: ${stuck.length}`);
  if (remaining.length) {
    console.log(
      `Still failing (cap reached): ${remaining.length} — ${remaining.join(", ")}`,
    );
  }
  console.log(`Total agent cost: $${totalCost.toFixed(4)}`);
  console.log(`Report: ${summaryPath}`);
  console.log(`Raw streams + log in: ${outDir}`);

  if (stuck.length > 0 || remaining.length > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
