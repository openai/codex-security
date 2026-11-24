import { Codex } from "@openai/codex-sdk";
import { expect } from "bun:test";
import { access, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  OperationTelemetry,
  readOperationTelemetry,
  type OperationTelemetryEvent,
} from "../../src/operation-telemetry.js";
import { TestClient } from "./api-client.js";
import { preparedRuntime } from "./api-events.js";
import { nodeCommand } from "./shell.js";

export async function completedUsageFixture(
  root: string,
  operation: "patch" | "validation",
  ending: string,
  response: string,
  receipt: Record<string, number>,
) {
  const repository = join(root, "repository");
  const codexHome = join(root, "codex-home");
  const state = join(root, "state");
  await mkdir(repository);
  await mkdir(codexHome);
  const controller = new AbortController();
  const observed: Readonly<OperationTelemetryEvent>[] = [];
  const model = "gpt-5.6-terra";
  const environment = {
    CODEX_SECURITY_STATE_DIR: state,
    OPENAI_API_KEY: `synthetic-${operation}-usage-key`,
  };
  const usage =
    ending === "null usage"
      ? null
      : ending === "absent usage" || ending === "nonzero exit before completion"
        ? undefined
        : receipt;
  const canceled =
    ending === "canceled after completion" ||
    ending === "canceled on completion";
  const failedExit = ending.startsWith("nonzero exit");
  const childScript = join(root, `${operation}-child.mjs`);
  await writeFile(
    childScript,
    [
      "for await (const _chunk of process.stdin) {}",
      "const send = (event) => console.log(JSON.stringify(event));",
      `send({ type: "thread.started", thread_id: "${operation}-usage-thread" });`,
      `send(${JSON.stringify({ type: "item.completed", item: { id: "result", type: "agent_message", text: response } })});`,
      ...(ending === "nonzero exit before completion"
        ? []
        : [`send(${JSON.stringify({ type: "turn.completed", usage })});`]),
      ...(canceled
        ? ["setInterval(() => {}, 1_000);", "await new Promise(() => {});"]
        : failedExit
          ? [
              `process.stderr.write("Synthetic ${operation} child exit diagnostic.\\n");`,
              "process.exit(17);",
            ]
          : ["process.exit(0);"]),
    ].join("\n"),
  );
  let executions = 0;
  const client = new TestClient(
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

  return {
    client,
    model,
    usage,
    canceled,
    failedExit,
    request: {
      repositoryPath: repository,
      finding: "Synthetic candidate finding.",
      auth: "api-key" as const,
      signal: controller.signal,
      onTelemetry: (event: Readonly<OperationTelemetryEvent>) =>
        observed.push(event),
    },
    async readTerminalEvent() {
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

      return saved.events.at(-1)!;
    },
  };
}
