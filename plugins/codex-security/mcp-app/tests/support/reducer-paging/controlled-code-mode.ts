import { temporaryDirectory } from "../temporary-directories.ts";
import type { ChildProcessByStdio } from "node:child_process";
import type { Readable } from "node:stream";
import type { AddressInfo } from "node:net";
interface ToolOutput {
  call_id: string;
  type: string;
  output: string | { text: string }[];
}
import { spawn } from "node:child_process";
import { once } from "node:events";
import { rm } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import path from "node:path";

function responseEvents(id: string, item: unknown) {
  return [
    { type: "response.created", response: { id } },
    { type: "response.output_item.done", item },
    {
      type: "response.completed",
      response: {
        id,
        usage: {
          input_tokens: 0,
          input_tokens_details: null,
          output_tokens: 0,
          output_tokens_details: null,
          total_tokens: 0,
        },
      },
    },
  ]
    .map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`)
    .join("");
}

/** Execute one scripted cell through the real CLI, external code host, and MCP. */
export async function runControlledCodeMode({
  code,
  mcpServer,
  workingDirectory,
  prompt,
}: {
  code: string;
  mcpServer: { command: string; args: string[] };
  workingDirectory: string;
  prompt: string;
}) {
  // Resolve through the SDK so the launcher and native host use its pinned version.
  const sdkRequire = createRequire(import.meta.resolve("@openai/codex-sdk"));
  const launcher = path.join(
    path.dirname(sdkRequire.resolve("@openai/codex/package.json")),
    "bin",
    "codex.js",
  );
  const codexHome = await temporaryDirectory("codex-controlled-ipc-");
  const toolOutputs = new Map<string, ToolOutput>();
  const serverErrors: string[] = [];
  let responseCount = 0;
  let pendingCallId = "controlled-exec";
  let child: ChildProcessByStdio<null, null, Readable> | undefined;
  let closed: Promise<number | null> | undefined;
  let stderr = "";
  const server = createServer(async (request, response) => {
    try {
      // The CLI also sends analytics here; those must not advance the model script.
      if (request.url !== "/v1/responses") {
        request.resume();
        response.writeHead(200, { "content-type": "application/json" });
        response.end("{}");
        return;
      }
      const chunks = await request.toArray();
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      for (const item of body.input ?? []) {
        if (
          item.type === "custom_tool_call_output" ||
          item.type === "function_call_output"
        ) {
          toolOutputs.set(item.call_id, item);
        }
      }
      responseCount += 1;
      const id = `controlled-response-${responseCount}`;
      const output = toolOutputs.get(pendingCallId)?.output;
      const status = typeof output === "string" ? output : output?.[0]?.text;
      const runningCell = status?.match(/^Script running with cell ID (\d+)\n/);
      if (runningCell) pendingCallId = `controlled-wait-${responseCount}`;
      const item =
        responseCount === 1
          ? {
              type: "custom_tool_call",
              call_id: pendingCallId,
              name: "exec",
              input: code,
            }
          : runningCell
            ? {
                type: "function_call",
                call_id: pendingCallId,
                name: "wait",
                arguments: JSON.stringify({ cell_id: runningCell[1] }),
              }
            : {
                type: "message",
                id: `controlled-message-${responseCount}`,
                role: "assistant",
                content: [{ type: "output_text", text: "Eval complete." }],
              };
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end(responseEvents(id, item));
    } catch (error) {
      serverErrors.push(String(error));
      response.writeHead(500);
      response.end("Controlled provider failed.");
    }
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const port = (server.address() as AddressInfo).port;
    const config = [
      'model_provider="controlled"',
      `model_providers.controlled={name="controlled",base_url="http://127.0.0.1:${port}/v1",wire_api="responses",requires_openai_auth=false,supports_websockets=false}`,
      "features.code_mode.enabled=true",
      "features.code_mode_host.enabled=true",
      "features.code_mode_host.disable_in_process_fallback=true",
      `mcp_servers.cs_artifacts.command=${JSON.stringify(mcpServer.command)}`,
      `mcp_servers.cs_artifacts.args=${JSON.stringify(mcpServer.args)}`,
    ];
    // Pass only process-launch essentials; never inherit the caller's model auth.
    const env: NodeJS.ProcessEnv = {
      CODEX_HOME: codexHome,
      CODEX_SQLITE_HOME: codexHome,
    };
    for (const key of [
      "PATH",
      "SystemRoot",
      "SystemDrive",
      "ComSpec",
      "PATHEXT",
      "TEMP",
      "TMP",
      "TMPDIR",
    ]) {
      if (process.env[key] !== undefined) env[key] = process.env[key];
    }
    const args = [
      launcher,
      "exec",
      "--skip-git-repo-check",
      "--experimental-json",
      "--sandbox",
      "read-only",
      "-m",
      "gpt-5.1-codex",
      ...config.flatMap((entry) => ["-c", entry]),
      prompt,
    ];
    child = spawn(process.execPath, args, {
      cwd: workingDirectory,
      env,
      // JSONL stdout can duplicate the deliberately oversized MCP response.
      stdio: ["ignore", "ignore", "pipe"],
    });
    closed = new Promise((resolve) => child!.once("close", resolve));
    child.stderr.setEncoding("utf8").on("data", (chunk) => {
      stderr += chunk;
    });
    const exitCode: number | null = (await once(child, "close"))[0];
    return {
      exitCode,
      toolOutputs: [...toolOutputs.values()],
      stderr,
      serverErrors,
    };
  } finally {
    child?.kill();
    if (closed) await closed;
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    await rm(codexHome, { recursive: true, force: true });
  }
}
