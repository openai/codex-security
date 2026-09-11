import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn(process.env.SYNTHETIC_NATIVE_CODEX, process.argv.slice(2), {
  env: process.env,
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true,
});
child.stderr.pipe(process.stderr);
const send = (value) => process.stdout.write(JSON.stringify(value) + "\n");
let turnRequest;
let modelProvider;
await Promise.all([
  (async () => {
    for await (const line of createInterface({ input: process.stdin })) {
      const request = JSON.parse(line);
      if (request.method === "turn/start") {
        turnRequest = request;
        child.stdin.write(
          JSON.stringify({
            id: "inspect-config",
            method: "config/read",
            params: { cwd: process.cwd(), includeLayers: true },
          }) + "\n",
        );
      } else child.stdin.write(line + "\n");
    }
    child.stdin.end();
  })(),
  (async () => {
    for await (const line of createInterface({ input: child.stdout })) {
      const response = JSON.parse(line);
      if (response.id === 2) modelProvider = response.result?.modelProvider;
      if (response.id !== "inspect-config") {
        process.stdout.write(line + "\n");
        continue;
      }
      const threadId = turnRequest.params.threadId;
      const turnId = "synthetic-turn";
      const config = response.result.config;
      send({ id: turnRequest.id, result: { turn: { id: turnId } } });
      send({
        method: "item/completed",
        params: {
          threadId,
          turnId,
          item: {
            type: "agentMessage",
            text: JSON.stringify({
              modelProvider,
              projectServerConfigured:
                config.mcp_servers?.synthetic !== undefined,
            }),
          },
        },
      });
      send({
        method: "turn/completed",
        params: { threadId, turn: { id: turnId, status: "completed" } },
      });
    }
  })(),
]);
