import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";

const record = (value) =>
  appendFileSync(
    process.env.SYNTHETIC_PROVIDER_LOG,
    `${JSON.stringify(value)}\n`,
  );
const send = (value) => process.stdout.write(`${JSON.stringify(value)}\n`);
const configPath = join(process.env.CODEX_HOME, "config.toml");
record({
  args: process.argv.slice(2),
  config: existsSync(configPath) ? readFileSync(configPath, "utf8") : "",
  environment: {
    GATEWAY_API_KEY: process.env.GATEWAY_API_KEY,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    CODEX_API_KEY: process.env.CODEX_API_KEY,
  },
});

if (process.env.SYNTHETIC_SKILL_COMMAND === "validate") {
  send({
    type: "item.completed",
    item: { type: "agent_message", text: "Synthetic validation complete" },
  });
} else {
  for await (const line of createInterface({ input: process.stdin })) {
    const request = JSON.parse(line);
    record(request);
    if (request.method === "initialize") {
      send({ id: request.id, result: {} });
    } else if (request.method === "account/login/start") {
      send({ id: request.id, result: { type: "apiKey" } });
    } else if (request.method === "config/read") {
      send({ id: request.id, result: { layers: [] } });
    } else if (request.method === "thread/start") {
      send({
        id: request.id,
        result: {
          thread: { id: "synthetic-thread" },
          sandbox: {
            type:
              request.params.sandbox === "read-only"
                ? "readOnly"
                : "workspaceWrite",
          },
        },
      });
    } else if (request.method === "command/exec") {
      send({ id: request.id, result: { exitCode: 0 } });
    } else if (request.method === "turn/start") {
      send({ id: request.id, result: { turn: { id: "synthetic-turn" } } });
      send({
        method: "item/completed",
        params: {
          threadId: "synthetic-thread",
          turnId: "synthetic-turn",
          item: {
            type: "agentMessage",
            text:
              process.env.SYNTHETIC_SKILL_COMMAND === "verify-fix"
                ? JSON.stringify({
                    results: [
                      {
                        id: "finding-1",
                        status: "fixed",
                        evidence: "Synthetic verification",
                      },
                    ],
                  })
                : "Synthetic patch complete",
          },
        },
      });
      send({
        method: "turn/completed",
        params: {
          threadId: "synthetic-thread",
          turn: { id: "synthetic-turn", status: "completed" },
        },
      });
    }
  }
}
