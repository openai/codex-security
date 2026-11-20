import { expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { readSkillCommandOutput } from "../src/cli.js";
import { resolveCodexCommand } from "../src/runtime.js";
import {
  createDependencyEvidenceCapture,
  type DependencyEvidenceRecord,
} from "../src/dependency-evidence-sources.js";
import { createDependencyLinkedResourceCapture } from "../src/dependency-linked-resources.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

// Serve both APIs on loopback. The scripted model calls a real native MCP tool;
// only the host should receive the resource requested on the original call.
test("the bundled native investigator keeps linked MCP resource bytes out of model requests", async () => {
  await using home = await scopedTemporaryDirectory("native-evidence-");
  const bytes = "private fixture frame\n".repeat(10_000);
  const uri = "fixture://frames";
  const requests: string[] = [];
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      if (request.method !== "POST") return new Response(null, { status: 405 });
      const body = await request.text();
      const path = new URL(request.url).pathname;
      if (path === "/mcp") {
        const rpc = JSON.parse(body) as {
          method: string;
          id?: number;
          params?: { protocolVersion?: string; uri?: string };
        };
        if (rpc.id === undefined) return new Response(null, { status: 202 });
        let result: unknown;
        switch (rpc.method) {
          case "initialize":
            result = {
              protocolVersion: rpc.params?.protocolVersion,
              serverInfo: { name: "fixture", version: "1" },
              capabilities: { tools: {}, resources: {} },
            };
            break;
          case "tools/list":
            result = {
              tools: [
                {
                  name: "linked",
                  description: "Look up sampled frames",
                  annotations: {
                    readOnlyHint: true,
                    destructiveHint: false,
                    openWorldHint: false,
                  },
                  inputSchema: { type: "object", properties: {} },
                },
              ],
            };
            break;
          case "tools/call":
            result = {
              content: [{ type: "resource_link", name: "frames", uri }],
            };
            break;
          case "resources/read":
            result = { contents: [{ uri: rpc.params?.uri, text: bytes }] };
            break;
          case "resources/templates/list":
            result = { resourceTemplates: [] };
            break;
          default:
            result = { resources: [] };
        }
        return Response.json({ jsonrpc: "2.0", id: rpc.id, result });
      }
      if (path !== "/v1/responses") return new Response(null, { status: 404 });
      requests.push(body);
      const item =
        requests.length === 1
          ? {
              type: "function_call",
              namespace: "mcp__fixture",
              name: "linked",
              call_id: "lookup",
              arguments: "{}",
            }
          : {
              type: "message",
              role: "assistant",
              id: "answer",
              content: [
                { type: "output_text", text: "Investigation complete." },
              ],
            };
      const response = {
        id: "response-" + requests.length,
        usage: { input_tokens: 2, output_tokens: 1, total_tokens: 3 },
      };
      const events = [
        { type: "response.created", response },
        { type: "response.output_item.done", item },
        { type: "response.completed", response },
      ];
      return new Response(
        events.map((e) => "data: " + JSON.stringify(e) + "\n\n").join(""),
        { headers: { "Content-Type": "text/event-stream" } },
      );
    },
  });
  const settings = [
    'model="gpt-5.4"',
    'model_provider="fixture"',
    'model_providers.fixture={name="Loopback",wire_api="responses",requires_openai_auth=false,base_url=' +
      JSON.stringify(new URL("/v1", server.url).href) +
      "}",
    'mcp_servers.fixture={required=true,enabled_tools=["linked"],url=' +
      JSON.stringify(new URL("/mcp", server.url).href) +
      "}",
    "features.apps=false",
    "features.plugins=false",
    "features.multi_agent=false",
    "features.multi_agent_v2=true",
    'permissions.dependency_investigation={filesystem={":root"="read"},network={enabled=false}}',
    'default_permissions="dependency_investigation"',
    'approval_policy="never"',
  ];
  const child = spawn(
    resolveCodexCommand({}).command,
    ["app-server", "--stdio", ...settings.flatMap((v) => ["--config", v])],
    {
      cwd: home.path,
      env: {
        PATH: process.env["PATH"],
        SystemRoot: process.env["SystemRoot"],
        CODEX_HOME: home.path,
        NO_PROXY: "127.0.0.1",
      },
      stdio: ["pipe", "pipe", "ignore"],
    },
  );
  const selected = { fixture: { enabled_tools: ["linked"] } };
  const records: DependencyEvidenceRecord[] = [];
  const errors: string[] = [];
  const capture = createDependencyEvidenceCapture(selected);
  const linked = createDependencyLinkedResourceCapture({
    servers: selected,
    onEvidence: (r) => records.push(r),
    onDiagnostic: (s) => errors.push(s),
  });
  // An initialization or handshake failure must release the child even before the test times out.
  const timer = setTimeout(() => child.kill(), 24_000);
  try {
    const turn = await readSkillCommandOutput(child.stdout, {
      directory: home.path,
      input: child.stdin,
      prompt: "Look up the linked frames.",
      threadSource: "security_validation",
      cyberAccessProgram: "standard",
      linkedEvidence: {
        async item(event, read, invocation) {
          const origin = capture(event);
          if (!origin) return;
          records.push(origin);
          await linked(origin, read, invocation);
        },
      },
    });
    expect(turn).toMatchObject({
      completed: true,
      message: "Investigation complete.",
    });
    expect(records).toHaveLength(2);
    expect(records[1]).toMatchObject({
      originCallId: "lookup",
      linkedFrom: records[0]!.sha256,
      result: { contents: [{ uri, text: bytes }] },
    });
    expect(errors).toEqual([]);
    expect(requests).toHaveLength(2);
    expect(requests[1]).toContain(uri);
    expect(requests.join("")).not.toContain("private fixture frame");
  } finally {
    clearTimeout(timer);
    child.kill();
    server.stop(true);
  }
}, 30_000);
