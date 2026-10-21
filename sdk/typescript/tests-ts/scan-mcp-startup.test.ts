import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Codex } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import { DiffTarget } from "../src/index.js";
import { resolveCodexCommand } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { scanRuntimeDependencies } from "./support/api-events.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const { temporaryDirectory, cleanup } =
  createApiTestFixtures("scan-mcp-startup-");
afterEach(cleanup);

test.each(["standard", "diff", "deep", "custom"] as const)(
  "the %s scan prompt waits for its MCP tools before the first model request",
  async (mode) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const codexHome = join(root, "codex-home");
    const scanDir = join(root, "scan");
    for (const directory of [repository, codexHome, scanDir])
      await mkdir(directory, { mode: 0o700 });
    if (mode === "diff") {
      await writeFile(join(repository, "fixture.ts"), "export {};\n");
      for (const args of [
        ["init", "-q"],
        ["add", "fixture.ts"],
        [
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.com",
          "commit",
          "-qm",
          "fixture",
        ],
      ])
        execFileSync("git", args, { cwd: repository, stdio: "pipe" });
    }
    let prompt = "";
    const client = TestClient.withDependencies({
      ...scanRuntimeDependencies(codexHome, scanDir),
      createCodex: () => ({
        startThread: () => ({
          id: null,
          async runStreamed(input: string) {
            prompt = input;
            throw new Error("scan prompt captured");
          },
        }),
      }),
    });
    try {
      await expect(
        client.run(repository, {
          ...(mode === "deep" ? { mode: "deep" } : {}),
          ...(mode === "diff"
            ? { target: DiffTarget.refs({ base: "HEAD", head: "HEAD" }) }
            : {}),
          ...(mode === "custom"
            ? { validationPrompt: "Validate the synthetic candidates." }
            : {}),
        }),
      ).rejects.toThrow("scan prompt captured");
    } finally {
      await client.close();
    }

    const captured = Promise.withResolvers<Record<string, unknown>>();
    let initialized = false;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch(request) {
        if (new URL(request.url).pathname === "/mcp") {
          if (request.method !== "POST")
            return new Response(null, { status: 405 });
          const message = (await request.json()) as {
            id?: number;
            method: string;
            params?: { protocolVersion?: string };
          };
          if (message.method === "initialize") {
            // Keep a healthy server pending beyond the fixture's optional grace.
            // Assert catalog contents, not wall-clock timing.
            await Bun.sleep(250);
            initialized = true;
            return Response.json({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                protocolVersion:
                  message.params?.protocolVersion ?? "2025-03-26",
                capabilities: { tools: {} },
                serverInfo: { name: "synthetic-startup", version: "1" },
              },
            });
          }
          if (message.method === "tools/list")
            return Response.json({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                tools: [
                  {
                    name: "synthetic_ready",
                    description: "Synthetic startup readiness tool.",
                    inputSchema: { type: "object", properties: {} },
                  },
                ],
              },
            });
          return new Response(null, { status: 202 });
        }
        if (new URL(request.url).pathname !== "/v1/responses")
          return Response.json({});
        const body = (await request.json()) as Record<string, unknown>;
        captured.resolve({ body, initialized });
        return new Response(
          'event: response.completed\ndata: {"type":"response.completed","response":{"id":"synthetic-response","output":[],"usage":{"input_tokens":0,"output_tokens":0}}}\n\n',
          { headers: { "content-type": "text/event-stream" } },
        );
      },
    });
    const nativeHome = join(root, "native-home");
    await mkdir(nativeHome, { mode: 0o700 });
    const environment: Record<string, string> = { CODEX_HOME: nativeHome };
    for (const key of ["PATH", "SystemRoot", "TEMP", "TMP"])
      if (process.env[key]) environment[key] = process.env[key]!;
    const codex = new Codex({
      codexPathOverride: resolveCodexCommand({}).command,
      env: environment,
      config: {
        model_provider: "synthetic",
        model_providers: {
          synthetic: {
            name: "Synthetic",
            base_url: `${server.url}v1`,
            wire_api: "responses",
            requires_openai_auth: false,
          },
        },
        mcp_optional_startup_grace_ms: 1,
        mcp_servers: {
          "codex-security": { url: `${server.url}mcp`, startup_timeout_sec: 5 },
        },
      },
    });
    const abort = new AbortController();
    const execution = codex
      .startThread({
        workingDirectory: repository,
        skipGitRepoCheck: true,
        model: "gpt-5.4",
        approvalPolicy: "never",
        sandboxMode: "read-only",
      })
      .run(prompt, { signal: abort.signal })
      .catch((error: unknown) => error);
    try {
      const request = await Promise.race([
        captured.promise,
        execution.then((result) => {
          throw new Error(
            `Native turn ended before the synthetic request: ${String(result)}`,
          );
        }),
      ]);
      expect(request["initialized"]).toBe(true);
      expect(JSON.stringify(request["body"])).toContain("synthetic_ready");
    } finally {
      abort.abort();
      await execution;
      await server.stop(true);
    }
  },
);
