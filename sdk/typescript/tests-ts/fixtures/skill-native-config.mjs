import { send, completeTurn } from "./app-server-messages.mjs";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";

const methods = new Map();
const child = spawn(process.env.SYNTHETIC_NATIVE_CODEX, process.argv.slice(2), {
  env: process.env,
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true,
});
child.stderr.pipe(process.stderr);
const input = createInterface({ input: process.stdin });
const childClosed = new Promise((resolve) => {
  child.once("close", (code) => {
    process.exitCode = code ?? 1;
    input.close();
    process.stdin.destroy();
    resolve();
  });
});
let preflightClient = false;
let preflightConfigId;
let turnRequest;
let modelProvider;
let initialConfig;
let daybreakEnabled;
await Promise.all([
  (async () => {
    for await (const line of input) {
      const request = JSON.parse(line);
      if (request.id !== undefined) methods.set(request.id, request.method);
      if (request.method === "initialize")
        preflightClient =
          request.params.clientInfo.name === "codex_security_deep_scan";
      if (
        preflightClient &&
        request.method === "config/read" &&
        request.params.includeLayers === true
      )
        preflightConfigId = request.id;
      if (request.method === "thread/start") {
        daybreakEnabled = request.params.daybreakEnabled ?? null;
      }
      if (request.method === "command/exec") {
        send({ id: request.id, result: { exitCode: 0 } });
      } else if (request.method === "model/list") {
        send({ id: request.id, result: { data: [], nextCursor: null } });
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
    let preflightResponse;
    for await (const line of createInterface({ input: child.stdout })) {
      const response = JSON.parse(line);
      if (
        preflightConfigId !== undefined &&
        response.id === preflightConfigId
      ) {
        // The one-shot origins reader terminates this proxy after the response.
        // Close its native child first, including on Windows where SIGTERM is forced.
        preflightResponse = line;
        child.stdin.end();
        continue;
      }
      if (methods.get(response.id) === "thread/start")
        modelProvider = response.result?.modelProvider;
      if (methods.get(response.id) === "config/read")
        initialConfig = response.result?.config;
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
            daybreak: initialConfig?.daybreak ?? null,
            daybreakEnabled,
            daybreakFeatures: Object.fromEntries(
              [
                "cli_daybreak",
                "api_key_cyber_access_programs",
                "api_key_model_discovery",
              ].map((key) => [key, initialConfig?.features?.[key] ?? null]),
            ),
          }),
        threadId,
      );
    }
    if (preflightResponse !== undefined) {
      await childClosed;
      process.stdout.write(preflightResponse + "\n");
    }
  })(),
  childClosed,
]);
