import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import type { ThreadEvent } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import { cases, routingPrompt } from "./cases.mts";
import {
  gradeRoutingTrace,
  prepareRoutingEval,
  routingSettings,
  runRoutingCase,
  sha256,
  summarizeRoutingCases,
  type Skill,
} from "./harness.mts";

const root = await mkdtemp(join(tmpdir(), "routing-contract-"));
after(() => rm(root, { recursive: true, force: true }));
const prepared = await prepareRoutingEval(root);
const skill = (name: string) =>
  prepared.skills.find((entry) => entry.name === name)!;
const message: ThreadEvent = {
  type: "item.completed",
  item: {
    id: "message",
    type: "agent_message",
    text: "Ready for the next step.",
  },
};
const completed: ThreadEvent = {
  type: "turn.completed",
  usage: {
    input_tokens: 10,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 5,
    reasoning_output_tokens: 0,
  },
};
function read(
  entry: Skill,
  output = `${entry.heading}\n\n${entry.introduction}`,
): ThreadEvent {
  return {
    type: "item.completed",
    item: {
      id: "read",
      type: "command_execution",
      command: `cat .agents/skills/${entry.name}/SKILL.md`,
      aggregated_output: output,
      status: "completed",
      exit_code: 0,
    },
  };
}
const grade = (expected: string | null, events: ThreadEvent[]) =>
  gradeRoutingTrace(expected, prepared.skills, events);

test("stages every production skill unchanged without the labels or harness", async () => {
  assert.deepEqual(await readdir(prepared.repo), [".agents"]);
  assert.deepEqual((await readdir(prepared.runtime)).sort(), [
    "references",
    "skills",
  ]);
  for (const entry of prepared.skills) {
    const source = await readFile(
      join(
        import.meta.dirname,
        "../../plugins/codex-security/skills",
        entry.name,
        "SKILL.md",
      ),
      "utf8",
    );
    const staged = await readFile(
      join(prepared.runtime, "skills", entry.name, "SKILL.md"),
      "utf8",
    );
    assert.equal(staged, source);
    assert.equal(entry.sha256, sha256(source));
  }
  for (const scenario of cases) {
    if (scenario.skill) assert.ok(skill(scenario.skill));
    assert.ok(!routingPrompt(scenario).includes(scenario.id));
    assert.ok(!routingPrompt(scenario).includes("$"));
  }
});

for (const scenario of cases) {
  test(`accepts the expected observed route: ${scenario.id}`, () => {
    const reads = scenario.skill ? [read(skill(scenario.skill))] : [];
    assert.equal(
      grade(scenario.skill, [...reads, message, completed]).passed,
      true,
    );
  });
}

test("a claimed choice or filename listing cannot satisfy a skill read", () => {
  const expected = skill("security-scan");
  for (const events of [
    [message, completed],
    [
      read(expected, ".agents/skills/security-scan/SKILL.md"),
      message,
      completed,
    ],
    [
      read(expected, `${expected.heading}\nname: security-scan`),
      message,
      completed,
    ],
  ]) {
    assert.equal(grade(expected.name, events).passed, false);
  }
});

test("accepts numbered source output but rejects failed or unfinished reads", () => {
  const expected = skill("verify-fix");
  const output = `${expected.heading}\n\n${expected.introduction}`
    .split("\n")
    .map((line, index) => `${index + 1}\t${line}`)
    .join("\n");
  assert.equal(
    grade(expected.name, [read(expected, output), message, completed]).passed,
    true,
  );
  for (const patch of [
    { exit_code: 1 },
    { exit_code: undefined },
    { status: "failed" },
    { status: "in_progress" },
  ]) {
    const event = read(expected);
    if (event.type === "item.completed") Object.assign(event.item, patch);
    assert.equal(
      grade(expected.name, [event, message, completed]).passed,
      false,
    );
  }
});

test("rejects deep-by-default, implicit verification, and loading every skill", () => {
  for (const [expected, loaded] of [
    ["security-scan", ["deep-security-scan"]],
    ["fix-finding", ["fix-finding", "verify-fix"]],
    ["security-diff-scan", prepared.skills.map((entry) => entry.name)],
    [null, ["fix-finding"]],
    [null, ["verify-fix"]],
  ] as const) {
    assert.equal(
      grade(expected, [
        ...loaded.map((name) => read(skill(name))),
        message,
        completed,
      ]).passed,
      false,
    );
  }
});

test("recognizes content returned by glob reads in positive and negative cases", () => {
  const event = read(skill("security-scan"));
  if (
    event.type === "item.completed" &&
    event.item.type === "command_execution"
  )
    event.item.command = "cat .agents/skills/security-scan/*";
  assert.equal(
    grade("security-scan", [event, message, completed]).passed,
    true,
  );
  assert.equal(grade(null, [event, message, completed]).passed, false);
});

test("failed or incomplete turns cannot pass even with the correct skill", () => {
  const observed = [read(skill("security-scan")), message];
  assert.equal(grade("security-scan", observed).passed, false);
  assert.equal(
    grade("security-scan", [
      ...observed,
      { type: "turn.failed", error: { message: "fixture failure" } },
      completed,
    ]).passed,
    false,
  );
  assert.equal(
    grade("security-scan", [read(skill("security-scan")), completed]).passed,
    false,
  );
});

test("records repeated reads and failed commands without pretending to measure completion", () => {
  const observed = read(skill("security-scan"));
  const failure = read(skill("security-scan"));
  if (failure.type === "item.completed")
    Object.assign(failure.item, { exit_code: 1, status: "failed" });
  const result = grade("security-scan", [
    failure,
    observed,
    observed,
    message,
    completed,
  ]);
  assert.equal(result.passed, true);
  assert.equal(result.failedCommands, 1);
  assert.equal(result.repeatedCommands, 2);
  assert.equal(result.repeatedSkillReads, 1);
});

test("rejects workflow execution visible in non-shell tool traces", () => {
  const event: ThreadEvent = {
    type: "item.completed",
    item: {
      id: "write",
      type: "file_change",
      status: "completed",
      changes: [{ path: "app.js", kind: "update" }],
    },
  };
  assert.equal(
    grade("fix-finding", [
      read(skill("fix-finding")),
      event,
      message,
      completed,
    ]).passed,
    false,
  );
});

test("uses an isolated home for Codex config and ambient skill discovery", () => {
  const settings = routingSettings(
    join(root, "home"),
    join(root, "bin", "codex"),
    { HOME: "/ambient", PATH: "/usr/bin" },
  );
  assert.equal(settings.env.HOME, join(root, "home"));
  assert.equal(settings.env.CODEX_HOME, join(root, "home"));
  assert.ok(settings.configOverrides.includes("features.plugins=false"));
});

test("starts a fresh thread in the fixture and grades its actual events", async () => {
  const events = [read(skill("security-scan")), message, completed];
  const result = await runRoutingCase(
    prepared,
    cases[0],
    {
      startThread(options) {
        assert.equal(options.workingDirectory, prepared.repo);
        assert.equal(options.model, "fixture-model");
        return {
          async runStreamed(prompt) {
            assert.equal(prompt, routingPrompt(cases[0]));
            return {
              events: (async function* () {
                yield* events;
              })(),
            };
          },
        };
      },
    },
    { model: "fixture-model" },
  );
  assert.equal(result.report.passed, true);
  assert.equal(result.report.usage?.input_tokens, 10);
  assert.deepEqual(result.events, events);
});

test("keeps an interrupted result failed while draining its stream", async () => {
  const controller = new AbortController();
  let drained = false;
  const result = await runRoutingCase(
    prepared,
    cases[0],
    {
      startThread() {
        return {
          async runStreamed() {
            return {
              events: (async function* () {
                yield read(skill("security-scan"));
                controller.abort(new Error("fixture cancellation"));
                yield message;
                yield completed;
                drained = true;
              })(),
            };
          },
        };
      },
    },
    { signal: controller.signal },
  );
  assert.equal(drained, true);
  assert.equal(result.report.passed, false);
  assert.equal(result.report.error, "fixture cancellation");
});

test("cohort reports distinguish partial, interrupted, failed, and complete results", () => {
  const results = cases.map((scenario) => ({
    caseId: scenario.id,
    passed: true,
  }));
  const partial = summarizeRoutingCases(results.slice(0, 1));
  assert.equal(partial.passed, false);
  assert.equal(partial.status, "incomplete");
  assert.deepEqual(
    partial.missingCases,
    cases.slice(1).map((scenario) => scenario.id),
  );
  const interrupted = summarizeRoutingCases(results.slice(0, 1), {
    interrupted: true,
  });
  assert.equal(interrupted.status, "interrupted");
  assert.equal(interrupted.passed, false);
  assert.equal(
    summarizeRoutingCases([], { error: "preflight failed" }).status,
    "failed",
  );
  assert.equal(summarizeRoutingCases(results).passed, true);
  assert.equal(
    summarizeRoutingCases(results, { interrupted: true }).passed,
    false,
  );
});
