import { Codex } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { access, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { estimateScanCost, type ScanUsageMeasurement } from "../src/cost.js";
import { ScanInterruptedError } from "../src/errors.js";
import {
  OperationTelemetry,
  readOperationTelemetry,
  type OperationTelemetryEvent,
} from "../src/operation-telemetry.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { nodeCommand } from "./support/shell.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures(
  "codex-security-patch-usage-",
);
afterEach(cleanup);

const receipt = {
  input_tokens: 100,
  cached_input_tokens: 0,
  cache_write_input_tokens: 0,
  output_tokens: 10,
  reasoning_output_tokens: 0,
};
const noChange = {
  status: "no_change",
  changedFiles: [],
  verificationReport: "The synthetic finding is already safe.",
  reason: null,
};

test.each([
  "invalid JSON",
  "invalid schema",
  "valid no_change",
  "canceled after completion",
  "canceled on completion",
  "nonzero exit after completion",
  "nonzero exit before completion",
  "null usage",
  "absent usage",
] as const)("preserves completed SDK patch usage with %s", async (ending) => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const state = join(root, "state");
  await mkdir(repository);
  await mkdir(codexHome);
  const controller = new AbortController();
  const observed: Readonly<OperationTelemetryEvent>[] = [];
  const measurements: Readonly<ScanUsageMeasurement>[] = [];
  const model = "gpt-5.6-terra";
  const environment = {
    CODEX_SECURITY_STATE_DIR: state,
    OPENAI_API_KEY: "synthetic-patch-usage-key",
  };
  const usage =
    ending === "null usage"
      ? null
      : ending === "absent usage" || ending === "nonzero exit before completion"
        ? undefined
        : receipt;
  const response =
    ending === "invalid JSON"
      ? "not JSON"
      : JSON.stringify(
          ending === "invalid schema"
            ? { ...noChange, verificationReport: " " }
            : noChange,
        );
  const canceled =
    ending === "canceled after completion" ||
    ending === "canceled on completion";
  const failedExit = ending.startsWith("nonzero exit");
  const childScript = join(root, "patch-child.mjs");
  await writeFile(
    childScript,
    [
      "for await (const _chunk of process.stdin) {}",
      "const send = (event) => console.log(JSON.stringify(event));",
      'send({ type: "thread.started", thread_id: "patch-usage-thread" });',
      `send(${JSON.stringify({ type: "item.completed", item: { id: "result", type: "agent_message", text: response } })});`,
      ...(ending === "nonzero exit before completion"
        ? []
        : [`send(${JSON.stringify({ type: "turn.completed", usage })});`]),
      ...(canceled
        ? ["setInterval(() => {}, 1_000);", "await new Promise(() => {});"]
        : failedExit
          ? [
              'process.stderr.write("Synthetic patch child exit diagnostic.\\n");',
              "process.exit(17);",
            ]
          : ["process.exit(0);"]),
    ].join("\n"),
  );
  let executions = 0;
  await using client = new TestClient(
    { codexOverrides: { model, analytics: { enabled: false } } },
    {
      environment,
      prepareRuntime: async () => ({
        ...preparedRuntime(codexHome),
        environment,
      }),
      resolvePluginPython: async () => "/managed/python",
      createOperationTelemetry: (options) => new OperationTelemetry(options),
      createCodex: (options) => {
        const codex = new Codex({
          ...options,
          codexPathOverride: nodeCommand().command,
          env: {
            ...options.env,
            NODE_OPTIONS: `--import=${pathToFileURL(childScript).href}`,
          },
        });
        return {
          startThread: (options) => {
            const thread = codex.startThread(options);
            const runStreamed = thread.runStreamed.bind(thread);
            thread.runStreamed = async (...args) => {
              executions++;
              const { events } = await runStreamed(...args);
              return {
                events: (async function* () {
                  for await (const event of events) {
                    if (
                      event.type === "turn.completed" &&
                      ending === "canceled on completion"
                    ) {
                      controller.abort(new Error("Synthetic cancellation."));
                    }
                    yield event;
                    if (
                      event.type === "turn.completed" &&
                      ending === "canceled after completion"
                    ) {
                      controller.abort(new Error("Synthetic cancellation."));
                    }
                  }
                })(),
              };
            };
            return thread;
          },
        };
      },
    },
  );
  const pending = client.patch({
    repositoryPath: repository,
    finding: "Synthetic candidate finding.",
    auth: "api-key",
    signal: controller.signal,
    onTelemetry: (event) => observed.push(event),
    onMeasurement: (measurement) => measurements.push(measurement),
  });
  const invalid = ending === "invalid JSON" || ending === "invalid schema";
  if (canceled) {
    await expect(pending).rejects.toBeInstanceOf(ScanInterruptedError);
  } else if (failedExit) {
    await expect(pending).rejects.toThrow(
      "Codex Exec exited with code 17: Synthetic patch child exit diagnostic.",
    );
  } else if (invalid) {
    await expect(pending).rejects.toThrow(
      "Finding patch returned an invalid result.",
    );
  } else {
    expect(await pending).toMatchObject({
      status: "no_change",
      threadId: "patch-usage-thread",
      cost: estimateScanCost(model, usage),
    });
  }
  expect(executions).toBe(1);
  await expect(access(join(codexHome, "sessions"))).rejects.toHaveProperty(
    "code",
    "ENOENT",
  );
  const saved = await readOperationTelemetry(state);
  expect(saved.parseFailures).toBe(0);
  expect(saved.events.map((event) => event.type)).toEqual([
    "attempt_started",
    "attempt_finished",
  ]);
  expect(observed.map((event) => event.eventId)).toEqual(
    saved.events.map((event) => event.eventId),
  );
  const terminal = saved.events.at(-1)!;
  expect(terminal.outcome).toBe(
    canceled ? "canceled" : invalid || failedExit ? "failed" : "completed",
  );
  expect(terminal.measurement).toEqual(measurements.at(-1));
  expect(terminal.measurement).toMatchObject({
    usage:
      usage == null
        ? null
        : { input_tokens: 100, output_tokens: 10, total_tokens: 110 },
    coverage: usage == null ? "unavailable" : "complete",
    cost: estimateScanCost(model, usage),
  });
});
