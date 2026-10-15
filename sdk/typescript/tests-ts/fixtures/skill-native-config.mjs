import { send, completeTurn } from "./app-server-messages.mjs";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const child = spawn(process.env.SYNTHETIC_NATIVE_CODEX, process.argv.slice(2), {
  env: process.env,
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true,
});
child.stderr.pipe(process.stderr);
let turnRequest;
let modelProvider;
await Promise.all([
  (async () => {
    for await (const line of createInterface({ input: process.stdin })) {
      const request = JSON.parse(line);
      if (request.method === "command/exec") {
        send({ id: request.id, result: { exitCode: 0 } });
      } else if (request.method === "turn/start") {
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
      const config = response.result.config;
      completeTurn(
        turnRequest,
        () =>
          JSON.stringify({
            modelProvider,
            projectServerConfigured:
              config.mcp_servers?.synthetic !== undefined,
          }),
        threadId,
      );
    }
  })(),
]);
