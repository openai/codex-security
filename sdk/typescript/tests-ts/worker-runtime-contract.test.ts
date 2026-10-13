import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, spyOn, test } from "bun:test";
import { resolveCodexProfile, type JsonObject } from "../src/config.js";
import { scanPreflightCodexConfig } from "../src/preflight-config.js";
import { readScanLogs } from "../src/scan-logs.js";
import { readCodexSessionTurn } from "../src/codex-session.js";
import { readCodexSessionTurn as readWorkerTurn } from "../../../plugins/codex-security/mcp-app/src/codex-session.js";
import { readOriginalParentEvents } from "../../../plugins/codex-security/mcp-app/src/deep-scan/parent-history.js";
import {
  projectWorkerSettings,
  resolveWorkerProfile,
} from "../../../plugins/codex-security/mcp-app/src/deep-scan/worker-settings.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

for (const provider of [
  "openai",
  "openrouter",
  "fireworks",
  "amazon-bedrock",
]) {
  test(`standalone worker selection agrees with SDK preflight: ${provider}`, () => {
    const config: JsonObject = {
      model: "initial-model",
      profile: "review.production",
      profiles: {
        "review.production": {
          model: "selected-model",
          model_provider: provider,
          model_reasoning_effort: "high",
          model_reasoning_summary: "concise",
          service_tier: "flex",
          features: {
            api_key_cyber_access_programs: true,
            api_key_model_discovery: false,
          },
          model_providers: {
            "amazon-bedrock": {
              aws: { region: "us-east-1", profile: "synthetic-review" },
            },
          },
        },
      },
    };
    const resolved = resolveWorkerProfile(config);
    expect(resolved).toEqual(resolveCodexProfile(config));
    expect(projectWorkerSettings(resolved)).toEqual(
      scanPreflightCodexConfig(resolved as JsonObject),
    );
    expect(config["model"]).toBe("initial-model");
  });
}

for (const completion of [
  "usage",
  "missing-usage",
  "upstream-null-usage-error",
] as const) {
  test(`standalone worker and SDK retain the same stream lifecycle: ${completion}`, async () => {
    const results = [];
    for (const reader of [readCodexSessionTurn, readWorkerTurn]) {
      const observed: string[] = [];
      let closed = false;
      const events = (async function* () {
        try {
          yield { type: "thread.started", thread_id: "synthetic-thread" };
          yield {
            type: "item.completed",
            item: { type: "agent_message", text: "accepted output" },
          };
          if (completion === "upstream-null-usage-error") {
            throw new TypeError(
              "Cannot read properties of null (reading 'cache_write_input_tokens')",
            );
          }
          yield {
            type: "turn.completed",
            ...(completion === "usage" ? { usage: { input_tokens: 3 } } : {}),
          };
          yield { type: "error", message: "after completion" };
        } finally {
          closed = true;
        }
      })();
      results.push(
        await reader({
          thread: { id: null },
          events,
          onEvent: (event) => {
            observed.push(event.type);
          },
          stopOnCompletion: true,
        }),
      );
      expect(observed).toEqual([
        "thread.started",
        "item.completed",
        "turn.completed",
      ]);
      expect(closed).toBe(true);
    }
    expect(results[0]).toEqual(results[1]);
    expect(results[0]?.status).toBe("completed");
    expect(results[0]?.finalResponse).toBe("accepted output");
    expect(results[0]?.usage).toEqual(
      completion === "usage" ? { input_tokens: 3 } : null,
    );
  });
}

for (const copy of ["identical", "longer", "divergent"] as const) {
  test(`standalone original-parent history agrees with SDK canonical copies: ${copy}`, async () => {
    const home = await temporaryDirectory();
    const original = [
      {
        type: "session_meta",
        payload: { id: "synthetic-owner", timestamp: "2026-01-01T00:01:00Z" },
      },
      {
        type: "session_meta",
        payload: { id: "synthetic-other", timestamp: "2026-01-01T00:00:00Z" },
      },
      { type: "turn_context", payload: { model: "foreign-model" } },
      {
        type: "event_msg",
        payload: { type: "task_started", started_at: 1767225660 },
      },
      { type: "turn_context", payload: { model: "owner-model" } },
    ];
    const archived =
      copy === "longer"
        ? [
            ...original,
            { type: "turn_context", payload: { model: "later-owner-model" } },
          ]
        : copy === "divergent"
          ? [
              ...original.slice(0, -1),
              { type: "turn_context", payload: { model: "divergent-model" } },
              { type: "event_msg", payload: { type: "task_complete" } },
            ]
          : original;
    for (const [directory, events] of [
      ["sessions", original],
      ["archived_sessions", archived],
    ] as const) {
      await mkdir(join(home, directory));
      await writeFile(
        join(home, directory, "owner.jsonl"),
        events.map((event) => JSON.stringify(event)).join("\n") + "\n",
      );
    }
    const worker = await readOriginalParentEvents(home, "synthetic-owner");
    const sdk = await readScanLogs({
      scanId: "synthetic-scan",
      threadId: "synthetic-owner",
      codexHome: home,
    });
    expect(worker).toEqual(
      sdk.events.map(({ event }) => event as Record<string, unknown>),
    );
    expect(
      worker.some((event) => JSON.stringify(event).includes("foreign-model")),
    ).toBe(false);
    expect(
      worker.some((event) => JSON.stringify(event).includes("divergent-model")),
    ).toBe(false);
    expect(worker.at(-1)?.["payload"]).toEqual({
      model: copy === "longer" ? "later-owner-model" : "owner-model",
    });
  });
}

test("original-parent settings skip unrelated rollout bodies", async () => {
  const home = await temporaryDirectory();
  await mkdir(join(home, "sessions"));
  const owner = {
    type: "session_meta",
    payload: { id: "synthetic-owner" },
  };
  const foreignBody = JSON.stringify({
    type: "turn_context",
    payload: { model: "synthetic-foreign-rollout-body" },
  });
  await writeFile(
    join(home, "sessions", "foreign.jsonl"),
    JSON.stringify({
      type: "session_meta",
      payload: { id: "synthetic-other" },
    }) +
      "\n" +
      Array.from({ length: 200 }, () => foreignBody).join("\n") +
      "\n",
  );
  await writeFile(
    join(home, "sessions", "owner.jsonl"),
    JSON.stringify(owner) + "\n",
  );
  const parseJson = JSON.parse;
  const foreignBodies: string[] = [];
  const parser = spyOn(JSON, "parse").mockImplementation((text, reviver) => {
    if (text.includes("synthetic-foreign-rollout-body"))
      foreignBodies.push(text);
    return parseJson(text, reviver);
  });
  try {
    expect(await readOriginalParentEvents(home, "synthetic-owner")).toEqual([
      owner,
    ]);
    expect(foreignBodies).toEqual([]);
  } finally {
    parser.mockRestore();
  }
});
