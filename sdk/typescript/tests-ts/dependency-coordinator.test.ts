import { expect, test } from "bun:test";
import { PassThrough, Writable } from "node:stream";
import { dependencyCoordinatorPermissionsMatch } from "../src/exploitability/analyzers/repository/coordinator.js";
import { readSkillCommandOutput } from "../src/cli.js";
import {
  createDependencyEvidenceCapture,
  type DependencyEvidenceRecord,
} from "../src/exploitability/evidence-sources.js";
import { createDependencyLinkedResourceCapture } from "../src/exploitability/linked-resources.js";
import {
  evidencePreviews,
  evidencePage,
} from "../src/exploitability/investigation-session.js";

test("the selected coordinator's child retrieves linked evidence on its own native thread before exit", async () => {
  const profile = {
    filesystem: { ":root": "read" },
    network: { enabled: false },
  };
  const flags = {
    default_permissions: "dependency_investigation",
    permissions: { dependency_investigation: profile },
  };
  const stream = new PassThrough();
  const requests: Record<string, unknown>[] = [];
  const records: DependencyEvidenceRecord[] = [];
  const errors: string[] = [];
  const usage: unknown[] = [];
  const original = "frame\n".repeat(12_000) + "last witness";
  const link = {
    type: "resource_link",
    name: "samples",
    uri: "fixture://samples",
  };
  const servers = { sampled: { enabled_tools: ["find_samples"] } };
  const capture = createDependencyEvidenceCapture(servers);
  const linked = createDependencyLinkedResourceCapture({
    servers,
    onEvidence: (r) => records.push(r),
    onDiagnostic: (s) => errors.push(s),
  });
  const write = (v: unknown) => stream.write(JSON.stringify(v) + "\n");
  const notify = (method: string, params: unknown) => write({ method, params });
  const event = (threadId: string, server: string) =>
    notify("item/completed", {
      threadId,
      turnId: "turn",
      item: {
        id: "call-27",
        type: "mcpToolCall",
        status: "completed",
        server,
        tool: "find_samples",
        arguments: {},
        result: { content: [link] },
      },
    });
  const input = new Writable({
    write(chunk, _enc, cb) {
      const req = JSON.parse(chunk.toString());
      requests.push(req);
      if (req.method === "initialize") write({ id: req.id, result: {} });
      else if (req.method === "config/read")
        write({
          id: req.id,
          result: {
            config: flags,
            layers: [{ name: { type: "sessionFlags" }, config: flags }],
          },
        });
      else if (req.method === "thread/start") {
        expect(req.params).toMatchObject({
          permissions: "dependency_investigation",
          approvalPolicy: "never",
          ephemeral: true,
        });
        expect(req.params.sandbox).toBeUndefined();
        write({
          id: req.id,
          result: {
            thread: { id: "root", ephemeral: true },
            activePermissionProfile: { id: "dependency_investigation" },
            model: "fixture",
            modelProvider: "fixture",
          },
        });
      } else if (req.method === "turn/start") {
        write({ id: req.id, result: { turn: { id: "turn" } } });
        notify("thread/started", {
          thread: { id: "child", parentThreadId: "root" },
        });
        event("other", "sampled");
        event("child", "unselected");
        event("child", "sampled");
        notify("thread/tokenUsage/updated", {
          threadId: "child",
          tokenUsage: { total: { inputTokens: 7, outputTokens: 4 } },
        });
        notify("item/completed", {
          threadId: "root",
          turnId: "turn",
          item: { type: "agentMessage", text: "Report ready." },
        });
        notify("turn/completed", {
          threadId: "root",
          turn: { id: "turn", status: "completed" },
        });
      } else if (req.method === "mcpServer/resource/read") {
        setImmediate(() =>
          write({
            id: req.id,
            result: { contents: [{ uri: link.uri, text: original }] },
          }),
        );
      }
      cb();
    },
    final(cb) {
      stream.end();
      cb();
    },
  });
  const result = await readSkillCommandOutput(stream, {
    input,
    directory: "/fixture",
    prompt: "Investigate",
    threadSource: "security_validation",
    cyberAccessProgram: "standard",
    linkedEvidence: {
      async item(event, read, invocation) {
        const origin = capture(event);
        if (!origin) return;
        records.push(origin);
        await linked(origin, read, invocation);
      },
      usage(v) {
        usage.push(v);
      },
    },
  });
  expect(result).toMatchObject({ completed: true, message: "Report ready." });
  expect(
    requests.filter((r) => r["method"] === "mcpServer/resource/read"),
  ).toMatchObject([
    {
      params: {
        threadId: "child",
        originCallId: "call-27",
        server: "sampled",
        uri: link.uri,
      },
    },
  ]);
  expect(records).toHaveLength(2);
  expect(records[1]).toMatchObject({
    linkedFrom: records[0]!.sha256,
    result: { contents: [{ text: original }] },
  });
  expect(JSON.stringify(requests)).not.toContain("last witness");
  expect(JSON.stringify(evidencePreviews([records[1]!])).length).toBeLessThan(
    9000,
  );
  expect(
    evidencePage(records[1]!, {
      id: records[1]!.sha256,
      path: ["contents", 0, "text"],
      offset: JSON.stringify(original).length - 20,
    }).text,
  ).toContain("last witness");
  expect(errors).toEqual([]);
  expect(usage).toMatchObject([{ input_tokens: 7, output_tokens: 4 }]);
});

test("evidence previews and citations select the same original JSON", () => {
  const page = (
    result: Record<string, unknown>,
    textBlock: number | null,
    record: (string | number)[],
    path?: (string | number)[],
  ) =>
    evidencePage(
      {
        sha256: "receipt",
        server: "sampler",
        tool: "lookup",
        arguments: {},
        result,
      },
      {
        id: "receipt",
        selection: { textBlock, record },
        ...(path && { path }),
      },
    ).text;
  const text = '{"rows":[{"__proto__":false}]}';
  const tool = { content: [{ type: "text", text }] };
  const resource = { contents: [{ text }] };
  expect(page(tool, 0, ["rows", 0], ["__proto__"])).toBe("false");
  expect(page(resource, 0, ["rows", 0, "__proto__"])).toBe("false");
  expect(
    page({ structuredContent: null, structured_content: "other" }, null, []),
  ).toBe("null");
  expect(() => page(tool, 0, ["rows"], ["0"])).toThrow(/Selector/);
  expect(() => page(tool, 0, ["rows", "0"])).toThrow(/Selector/);
  expect(() => page(tool, 0, ["rows", 0, "constructor"])).toThrow(/Selector/);
  expect(() => page({ content: [{ type: "image", text }] }, 0, [])).toThrow(
    /JSON text block/,
  );
});

test("native permission table merging cannot silently widen linked evidence sessions", () => {
  const profile = {
    filesystem: { ":root": "read" },
    network: { enabled: false },
  };
  const config = {
    default_permissions: "dependency_investigation",
    permissions: { dependency_investigation: profile },
  };
  const layers = [{ name: { type: "sessionFlags" }, config }];
  expect(dependencyCoordinatorPermissionsMatch(config, layers)).toBe(true);
  expect(
    dependencyCoordinatorPermissionsMatch(
      {
        ...config,
        permissions: {
          dependency_investigation: { ...profile, extends: null },
        },
      },
      layers,
    ),
  ).toBe(true);
  expect(
    dependencyCoordinatorPermissionsMatch(
      {
        ...config,
        permissions: {
          dependency_investigation: {
            ...profile,
            filesystem: { ...profile.filesystem, "/tmp": "write" },
          },
        },
      },
      layers,
    ),
  ).toBe(false);
  expect(dependencyCoordinatorPermissionsMatch(config, [])).toBe(false);
});
