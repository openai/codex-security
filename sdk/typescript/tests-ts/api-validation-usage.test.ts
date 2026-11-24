import { afterEach, describe, expect, test } from "bun:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import { estimateScanCost } from "../src/cost.js";
import type { ThreadEvent } from "@openai/codex-sdk";
import { ScanInterruptedError } from "../src/errors.js";
import {
  OperationTelemetry,
  type OperationTelemetryEvent,
} from "../src/operation-telemetry.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { completedUsageFixture } from "./support/completed-usage.js";
import { writeSession } from "./support/usage-rollout.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-validation-usage-",
);
afterEach(cleanup);

const parentUsage = {
  input_tokens: 10,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 3,
  reasoning_output_tokens: 0,
};
const childUsage = { ...parentUsage, input_tokens: 90, output_tokens: 7 };
const assessment = {
  disposition: "reportable",
  report: "Synthetic validation assessment.",
};
type ValidationEnding = "completed" | "failed" | "canceled" | "invalid";

async function validationFixture({
  ending = "completed",
  child = childUsage,
}: {
  ending?: ValidationEnding;
  child?: Record<string, number>;
} = {}) {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  await mkdir(repository);
  await mkdir(codexHome);
  const controller = new AbortController();
  const telemetry: Readonly<OperationTelemetryEvent>[] = [];
  const environment = {
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
    OPENAI_API_KEY: "synthetic-validation-key",
  };
  async function* events(): AsyncGenerator<ThreadEvent> {
    await writeSession(codexHome, "validation-parent", parentUsage);
    await writeSession(codexHome, "validation-child", child, {
      parent: "validation-parent",
    });
    yield { type: "thread.started", thread_id: "validation-parent" };
    if (ending === "canceled") {
      controller.abort();
      throw controller.signal.reason;
    }
    if (ending === "failed") {
      yield {
        type: "turn.failed",
        error: { message: "Synthetic validation failure." },
      };
      return;
    }
    yield {
      type: "item.completed",
      item: {
        id: "assessment",
        type: "agent_message",
        text: ending === "invalid" ? "not JSON" : JSON.stringify(assessment),
      },
    };
    yield { type: "turn.completed", usage: parentUsage };
  }
  const client = new TestClient(
    {
      codexOverrides: {
        model: "test-model",
        model_reasoning_effort: "high",
        approval_policy: "never",
        analytics: { enabled: false },
      },
    },
    {
      environment,
      prepareRuntime: async () => ({
        ...preparedRuntime(codexHome),
        environment,
      }),
      resolvePluginPython: async () => "/managed/python",
      createOperationTelemetry: (options) => new OperationTelemetry(options),
      createCodex: () => ({
        startThread: () => ({
          id: null,
          runStreamed: async () => ({ events: events() }),
        }),
      }),
    },
  );
  return {
    client,
    options: {
      repositoryPath: repository,
      finding: "Synthetic candidate finding",
      outputDir: join(root, "validation"),
      signal: controller.signal,
      auth: "api-key" as const,
      onTelemetry: (event: Readonly<OperationTelemetryEvent>) =>
        telemetry.push(event),
    },
    terminal() {
      expect(telemetry.map((event) => event.type)).toEqual([
        "attempt_started",
        "attempt_finished",
      ]);
      return telemetry.at(-1)!;
    },
  };
}

describe("standalone validation usage", () => {
  test("includes native child threads in the terminal measurement", async () => {
    const fixture = await validationFixture();
    await using client = fixture.client;
    expect(await client.validate(fixture.options)).toMatchObject(assessment);
    expect(fixture.terminal()).toMatchObject({
      outcome: "completed",
      measurement: {
        coverage: "complete",
        threadCount: 2,
        missingThreadCount: 0,
        usage: { input_tokens: 100, output_tokens: 10, total_tokens: 110 },
      },
    });
  });

  test("keeps parent usage partial when a known child has no usage", async () => {
    const fixture = await validationFixture({ child: {} });
    await using client = fixture.client;
    expect(await client.validate(fixture.options)).toMatchObject(assessment);
    expect(fixture.terminal()).toMatchObject({
      outcome: "completed",
      measurement: {
        coverage: "partial",
        threadCount: 1,
        missingThreadCount: 1,
        usage: { input_tokens: 10, output_tokens: 3, total_tokens: 13 },
      },
    });
  });

  test.each(["failed", "canceled", "invalid"] as const)(
    "retains native parent and child usage after a %s validation",
    async (ending) => {
      const fixture = await validationFixture({ ending });
      await using client = fixture.client;
      await expect(client.validate(fixture.options)).rejects.toThrow(
        ending === "canceled"
          ? ScanInterruptedError
          : ending === "failed"
            ? "Synthetic validation failure."
            : "Finding validation returned an invalid result.",
      );
      expect(fixture.terminal()).toMatchObject({
        outcome: ending === "canceled" ? "canceled" : "failed",
        measurement: {
          coverage: "complete",
          threadCount: 2,
          missingThreadCount: 0,
          usage: { input_tokens: 100, output_tokens: 10, total_tokens: 110 },
        },
      });
    },
  );
});

const completionUsage = {
  input_tokens: 100,
  cached_input_tokens: 20,
  cache_write_input_tokens: 7,
  output_tokens: 10,
  reasoning_output_tokens: 3,
};

test.each([
  "invalid JSON",
  "invalid schema",
  "valid assessment",
  "canceled after completion",
  "canceled on completion",
  "nonzero exit after completion",
  "nonzero exit before completion",
  "null usage",
  "absent usage",
] as const)(
  "preserves completed SDK validation usage with %s",
  async (ending) => {
    const response =
      ending === "invalid JSON"
        ? "not JSON"
        : JSON.stringify(
            ending === "invalid schema"
              ? { ...assessment, disposition: "invalid" }
              : assessment,
          );
    const fixture = await completedUsageFixture(
      await temporaryDirectory(),
      "validation",
      ending,
      response,
      completionUsage,
    );
    await using client = fixture.client;
    const { model, usage, canceled, failedExit } = fixture;
    const pending = client.validate(fixture.request);
    const invalid = ending === "invalid JSON" || ending === "invalid schema";
    if (canceled) {
      await expect(pending).rejects.toBeInstanceOf(ScanInterruptedError);
    } else if (failedExit) {
      await expect(pending).rejects.toThrow(
        "Codex Exec exited with code 17: Synthetic validation child exit diagnostic.",
      );
    } else if (invalid) {
      await expect(pending).rejects.toThrow(
        "Finding validation returned an invalid result.",
      );
    } else {
      expect(await pending).toMatchObject({
        ...assessment,
        threadId: "validation-usage-thread",
      });
    }
    const terminal = await fixture.readTerminalEvent();
    expect(terminal.outcome).toBe(
      canceled ? "canceled" : invalid || failedExit ? "failed" : "completed",
    );
    expect(terminal.measurement).toMatchObject({
      usage: usage == null ? null : { ...completionUsage, total_tokens: 110 },
      coverage: usage == null ? "unavailable" : "complete",
      cost: estimateScanCost(model, usage),
    });
  },
);
