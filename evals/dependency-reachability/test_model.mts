import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  runStructuredTurn,
  type EvalCodex,
} from "../secret-discovery/harness.mts";
import { modelSettings, stageSkill } from "./model.mts";

test("forwards only the native workload identity context alongside normal eval settings", () => {
  const settings = modelSettings("/home/fixture", "/opt/codex/bin/codex", {
    OPENAI_FEDERATION_RULE_ID: "synthetic-rule",
    OPENAI_IDENTITY_TOKEN_FILE: "/synthetic/identity",
    OPENAI_WORKLOAD_IDENTITY_CONTEXT: "synthetic-context",
    GITHUB_TOKEN: "unrelated",
  });
  assert.equal(settings.env.OPENAI_FEDERATION_RULE_ID, "synthetic-rule");
  assert.equal(settings.env.OPENAI_IDENTITY_TOKEN_FILE, "/synthetic/identity");
  assert.equal(
    settings.env.OPENAI_WORKLOAD_IDENTITY_CONTEXT,
    "synthetic-context",
  );
  assert.equal(settings.env.GITHUB_TOKEN, undefined);
  assert.ok(
    settings.configOverrides.includes(
      'shell_environment_policy.inherit="core"',
    ),
  );
});

test("stages the production skill with its references outside the source checkout", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "reachability-skill-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const { runtime, path, instructions } = await stageSkill(root);
  const production = join(import.meta.dirname, "../../plugins/codex-security");
  assert.deepEqual((await readdir(runtime)).sort(), ["references", "skills"]);
  assert.deepEqual(await readdir(join(runtime, "skills")), [
    "attack-path-analysis",
  ]);
  assert.equal(
    instructions,
    await readFile(
      join(production, "skills/attack-path-analysis/SKILL.md"),
      "utf8",
    ),
  );
  assert.equal(await readFile(path, "utf8"), instructions);
  assert.deepEqual(
    await readFile(join(runtime, "references/artifact-storage.md")),
    await readFile(join(production, "references/artifact-storage.md")),
  );
});

const answer = {
  type: "item.completed",
  item: { type: "agent_message", text: "{}" },
};
const retry = { type: "error", message: "fixture connection retry" };
const completed = { type: "turn.completed" };
const failed = { type: "turn.failed", error: { message: "fixture failure" } };

for (const { name, events, error } of [
  {
    name: "accepts a completed answer after a retry",
    events: [retry, answer, completed],
  },
  {
    name: "a failed turn cannot pass after an answer",
    events: [retry, answer, failed],
    error: /fixture failure/,
  },
  {
    name: "preserves the error if a retry never completes",
    events: [answer, retry],
    error: /fixture connection retry/,
  },
  {
    name: "requires an answer from a completed turn",
    events: [completed],
    error: /without an answer/,
  },
]) {
  test(name, async () => {
    const codex: EvalCodex = {
      startThread: () => ({
        runStreamed: async () => ({
          events: (async function* () {
            yield* events;
          })(),
        }),
      }),
    };
    const result = runStructuredTurn(
      { repo: "/repo", runtime: "/runtime" },
      codex,
      "case",
      {},
    );
    if (error) await assert.rejects(result, error);
    else assert.equal((await result).finalResponse, "{}");
  });
}
