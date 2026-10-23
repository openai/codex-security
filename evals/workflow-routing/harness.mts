import { createHash } from "node:crypto";
import { cp, mkdir, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import type {
  ThreadEvent,
  ThreadOptions,
} from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import { codexSettings, threadSettings } from "../secret-discovery/harness.mts";
import { cases, routingPrompt, type RoutingCase } from "./cases.mts";

const pluginRoot = join(import.meta.dirname, "../../plugins/codex-security");
export const sha256 = (text: string) =>
  createHash("sha256").update(text).digest("hex");

export interface Skill {
  name: string;
  sha256: string;
  heading: string;
  introduction: string;
}

/** Install unchanged repository skills; labels and grader stay outside this tree. */
export async function prepareRoutingEval(root: string) {
  const repo = join(root, "repository");
  const runtime = join(repo, ".agents");
  await mkdir(runtime, { recursive: true });
  for (const directory of ["skills", "references"]) {
    await cp(join(pluginRoot, directory), join(runtime, directory), {
      recursive: true,
    });
  }
  const skills: Skill[] = [];
  for (const name of (await readdir(join(runtime, "skills"))).sort()) {
    const source = await readFile(
      join(runtime, "skills", name, "SKILL.md"),
      "utf8",
    );
    const body = source.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/u, "");
    const paragraphs = body.trim().split(/\r?\n\s*\r?\n/u);
    const heading = paragraphs[0];
    const introduction = paragraphs.find(
      (paragraph) => !paragraph.startsWith("#"),
    );
    if (!heading?.startsWith("# ") || !introduction)
      throw new Error(`Cannot identify production skill content: ${name}`);
    skills.push({ name, sha256: sha256(source), heading, introduction });
  }
  return { repo, runtime, skills };
}

export function routingSettings(
  home: string,
  codexPath: string,
  environment = process.env,
) {
  // Repository skills are the only skill installation in this eval. Keep the
  // caller's ~/.agents/skills out of discovery as well as their Codex config.
  return codexSettings(home, codexPath, {
    ...environment,
    HOME: home,
    ...(process.platform === "win32" ? { USERPROFILE: home } : {}),
  });
}

function unnumbered(text: string) {
  return text.replace(/\r\n/gu, "\n").replace(/^\s*\d+\t/gmu, "");
}

/** Recognize returned production content, not a filename or a claimed choice. */
export function gradeRoutingTrace(
  expected: string | null,
  skills: readonly Skill[],
  events: readonly ThreadEvent[],
) {
  const reads: string[] = [];
  const commands: string[] = [];
  let failedCommands = 0;
  let unexpectedActions = 0;
  let failed = false;
  let completed = false;
  let finalResponse = "";
  for (const event of events) {
    if (event.type === "turn.completed") completed = true;
    if (event.type === "turn.failed" || event.type === "error") failed = true;
    if (event.type !== "item.completed") continue;
    const { item } = event;
    if (item.type === "agent_message") finalResponse = item.text;
    if (["file_change", "mcp_tool_call", "web_search"].includes(item.type))
      unexpectedActions++;
    if (item.type !== "command_execution") continue;
    commands.push(item.command);
    if (item.exit_code !== 0 || item.status !== "completed") {
      failedCommands++;
      continue;
    }
    const output = unnumbered(item.aggregated_output);
    for (const skill of skills) {
      if (output.includes(skill.heading) && output.includes(skill.introduction))
        reads.push(skill.name);
    }
  }
  const loadedSkills = [...new Set(reads)];
  const expectedSkills = expected === null ? [] : [expected];
  return {
    passed:
      completed &&
      !failed &&
      finalResponse.trim().length > 0 &&
      unexpectedActions === 0 &&
      JSON.stringify(loadedSkills) === JSON.stringify(expectedSkills),
    turnCompleted: completed,
    turnFailed: failed,
    expectedSkill: expected,
    loadedSkills,
    commandCount: commands.length,
    failedCommands,
    repeatedCommands: commands.length - new Set(commands).size,
    repeatedSkillReads: reads.length - loadedSkills.length,
    unexpectedActions,
    finalResponse,
  };
}

export interface RoutingCodex {
  startThread(options: ThreadOptions): {
    runStreamed(
      prompt: string,
      options: { signal: AbortSignal },
    ): Promise<{ events: AsyncIterable<ThreadEvent> }>;
  };
}

export async function runRoutingCase(
  prepared: Awaited<ReturnType<typeof prepareRoutingEval>>,
  scenario: RoutingCase,
  codex: RoutingCodex,
  { model, signal }: { model?: string; signal?: AbortSignal } = {},
) {
  const prompt = routingPrompt(scenario);
  const events: ThreadEvent[] = [];
  const combined = signal ?? new AbortController().signal;
  const started = performance.now();
  let error: string | undefined;
  try {
    const thread = codex.startThread(threadSettings(prepared, model));
    const stream = await thread.runStreamed(prompt, { signal: combined });
    for await (const event of stream.events) {
      events.push(event);
      // Drain after cancellation before the shared harness removes temp state.
    }
    combined.throwIfAborted();
  } catch (failure) {
    error ??= failure instanceof Error ? failure.message : String(failure);
  }
  const usage = events.findLast(
    (event) => event.type === "turn.completed",
  )?.usage;
  const grade = gradeRoutingTrace(scenario.skill, prepared.skills, events);
  return {
    events,
    report: {
      caseId: scenario.id,
      ...grade,
      passed: grade.passed && error === undefined,
      ...(error ? { error } : {}),
      elapsedMilliseconds: Math.round(performance.now() - started),
      usage: usage ?? null,
      promptSha256: sha256(prompt),
    },
  };
}

/** Partial or interrupted cohorts cannot be mistaken for all-case success. */
export function summarizeRoutingCases(
  results: readonly { caseId: string; passed: boolean }[],
  {
    interrupted = false,
    error,
  }: { interrupted?: boolean; error?: string } = {},
) {
  const missingCases = cases
    .filter(
      (scenario) => !results.some((result) => result.caseId === scenario.id),
    )
    .map((scenario) => scenario.id);
  const complete = missingCases.length === 0 && results.length === cases.length;
  const passed =
    complete &&
    !interrupted &&
    error === undefined &&
    results.every((result) => result.passed);
  return {
    status: interrupted
      ? "interrupted"
      : error
        ? "failed"
        : !complete
          ? "incomplete"
          : passed
            ? "passed"
            : "failed",
    passed,
    expectedCases: cases.map((scenario) => scenario.id),
    missingCases,
    ...(error ? { error } : {}),
  };
}
