import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { withAdapter } from "./adapter.mts";
import { cases, challengeCases, type Repository } from "./cases.mts";
import { answerSchema, gradeAnswer } from "./grade.mts";
import { prepareSnapshot, snapshotDigest } from "./prepare.mts";

const args = process.argv.slice(2);
const usage =
  "Usage: run-skill-baseline.mts --repos DIR [--suite SUITE] [--case ID] [--model MODEL | -- COMMAND ...]";
const separator = args.indexOf("--");
const adapter = separator < 0 ? undefined : args.slice(separator + 1);
const { values } = parseArgs({
  args: separator < 0 ? args : args.slice(0, separator),
  options: {
    repos: { type: "string" },
    suite: { type: "string" },
    case: { type: "string" },
    model: { type: "string" },
    help: { type: "boolean", short: "h" },
  },
});
if (values.help) {
  console.log(usage);
  for (const suite of new Set(cases.map((c) => c.suite))) {
    console.log(
      `${suite}: ${cases
        .filter((c) => c.suite === suite)
        .map((c) => c.id)
        .join(", ")}`,
    );
  }
  console.log(
    "challenge: the downstream patch, sanitizer, queue, and archive cases",
  );
  process.exit(0);
}
if (!values.repos || (adapter && (!adapter.length || values.model))) {
  throw new Error(usage);
}
if (adapter && /[/\\]/u.test(adapter[0])) adapter[0] = resolve(adapter[0]);
const suiteCases =
  values.suite === "challenge"
    ? challengeCases
    : cases.filter((c) => !values.suite || c.suite === values.suite);
const selected = suiteCases.filter((c) => !values.case || c.id === values.case);
if (!selected.length)
  throw new Error("No matching dependency reachability cases");
const clones: Partial<Record<Repository, string>> = {};
for (const c of selected) {
  for (const slug of [
    c.repository,
    ...c.stage.flatMap((file) =>
      file.kind === "git" ? [file.repository] : [],
    ),
  ]) {
    clones[slug] = resolve(values.repos, slug);
  }
}

const promptFor = (question: string) =>
  [
    question,
    "Inspect the supplied source snapshot offline and read-only. Return a JSON object with " +
      "verdict (exploitable, ruled_out, or unknown), dependency_version, reason, and evidence. " +
      "For dependency_version, give only the bare version of the component named in the advisory as a string. Put package names and build details in reason. " +
      "Support the version and each decisive step with a short citation: {path, startLine, endLine, code}. " +
      "Use a repository-relative path and 1-based inclusive line numbers. Copy the complete cited lines " +
      "exactly, including indentation, without line numbers or ellipses.",
  ].join("\n\n");

const reports = join(import.meta.dirname, "reports");
await mkdir(reports, { recursive: true });
const directory = await mkdtemp(join(reports, "run-"));
const sourceRoot = join(import.meta.dirname, "../..");
const git = (...args: string[]) =>
  execFileSync("git", args, { cwd: sourceRoot, encoding: "utf8" }).trim();
const codexVersion = async (name: string) =>
  JSON.parse(
    await readFile(
      join(
        sourceRoot,
        "sdk/typescript/node_modules/@openai",
        name,
        "package.json",
      ),
      "utf8",
    ),
  ).version as string;
const results: {
  id: string;
  suite: string;
  revision: string;
  snapshotSha256: string;
  promptSha256: string;
  stagingMs: number;
  analysisMs: number;
  usage: unknown;
  answer: unknown;
  grade: Awaited<ReturnType<typeof gradeAnswer>>;
}[] = [];
const identity = {
  sourceRevision: git("rev-parse", "HEAD"),
  sourceDirty: git("status", "--porcelain") !== "",
  evaluator: adapter ? "external-adapter" : "attack-path-analysis",
  adapterCommand: adapter?.[0] ?? null,
  codexSdkVersion: adapter ? null : await codexVersion("codex-sdk"),
  codexCliVersion: adapter ? null : await codexVersion("codex"),
  requestedModel: values.model ?? null,
  reasoningEffort: adapter ? null : "xhigh",
  skillSha256: adapter
    ? null
    : createHash("sha256")
        .update(
          await readFile(
            join(
              sourceRoot,
              "plugins/codex-security/skills/attack-path-analysis/SKILL.md",
            ),
          ),
        )
        .digest("hex"),
  selected: selected.map((c) => c.id),
};
let error: string | undefined;
let interrupted = false;
const save = () =>
  writeFile(
    join(directory, "report.json"),
    JSON.stringify(
      {
        ...identity,
        complete: !error && !interrupted && results.length === selected.length,
        interrupted,
        error,
        passed: results.filter((r) => r.grade.pass).length,
        results,
      },
      null,
      2,
    ) + "\n",
  );
console.log(`Eval artifacts: ${directory}`);
await save();
async function execute(state: {
  root: string;
  signal: AbortSignal;
  run(
    repo: string,
    prompt: string,
    schema: unknown,
  ): Promise<{ answer: unknown; usage: unknown }>;
}) {
  try {
    for (const c of selected) {
      state.signal.throwIfAborted();
      const started = performance.now();
      const repo = await prepareSnapshot(state.root, c, clones, state.signal);
      try {
        const snapshotSha256 = await snapshotDigest(repo, c);
        // Keep the exact input for grading even if an adapter edits its files
        // or the developer changes a fixture during a long run.
        const working = adapter ? join(dirname(repo), "candidate") : repo;
        if (adapter)
          await cp(repo, working, { recursive: true, verbatimSymlinks: true });
        const ready = performance.now();
        const prompt = promptFor(c.question);
        const { answer, usage } = await state.run(
          working,
          prompt,
          answerSchema,
        );
        const analysisMs = Math.round(performance.now() - ready);
        // These historical prompts supply the caller and deployment assumptions.
        const verdict =
          c.verdict === "potentially_exploitable" ? "exploitable" : c.verdict;
        const grade = await gradeAnswer(answer, { ...c, verdict }, repo);
        results.push({
          id: c.id,
          suite: c.suite,
          revision: c.revision,
          snapshotSha256,
          promptSha256: createHash("sha256").update(prompt).digest("hex"),
          stagingMs: Math.round(ready - started),
          analysisMs,
          usage,
          answer,
          grade,
        });
        await save();
        console.log(
          `${c.id}: ${grade.pass ? "PASS" : "FAIL"} (${(analysisMs / 1000).toFixed(1)}s)`,
        );
        for (const issue of grade.errors) console.log(`  ${issue}`);
      } finally {
        await rm(dirname(repo), { recursive: true, force: true });
      }
    }
  } finally {
    interrupted = state.signal.aborted;
  }
}
try {
  if (adapter) {
    await withAdapter(adapter, execute);
  } else {
    const { withModel } = await import("./model.mts");
    await withModel(values.model, execute);
  }
  const passed = results.filter((r) => r.grade.pass).length;
  console.log(`Passed ${passed}/${selected.length}`);
  if (passed !== selected.length && !process.exitCode) process.exitCode = 1;
} catch (failure) {
  error = failure instanceof Error ? failure.message : String(failure);
  throw failure;
} finally {
  interrupted ||= process.exitCode === 130 || process.exitCode === 143;
  await save();
}
