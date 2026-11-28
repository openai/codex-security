import { expect, test } from "bun:test";
import { PassThrough, Writable } from "node:stream";
import {
  createDependencyCoordinatorSession,
  dependencyCoordinatorPermissionsMatch,
} from "../src/exploitability/analyzers/repository/coordinator.js";
import { readSkillCommandOutput } from "../src/cli.js";
import type { JsonObject } from "../src/config.js";
import {
  createDependencyEvidenceCapture,
  type DependencyEvidenceRecord,
  type Sample,
} from "../src/exploitability/evidence-sources.js";
import { createDependencyLinkedResourceCapture } from "../src/exploitability/linked-resources.js";
import {
  evidencePreviews,
  evidencePage,
} from "../src/exploitability/investigation-session.js";

const profile = {
  filesystem: { ":root": "read" },
  network: { enabled: false },
};
const config = {
  default_permissions: "dependency_investigation",
  permissions: { dependency_investigation: profile },
};

test("the selected coordinator's child retrieves linked evidence on its own native thread before exit", async () => {
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
            config,
            layers: [{ name: { type: "sessionFlags" }, config }],
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

test("evidence pages require exact, own JSON paths", () => {
  const receipt = { server: "mcp", tool: "list", sha256: "id", arguments: {} };
  type Path = (string | number)[];
  const page = (
    result: Record<string, unknown>,
    record: Path,
    path: Path = [],
    textBlock: number | null = 0,
  ) =>
    evidencePage(
      { ...receipt, result },
      { id: "id", selection: { textBlock, record }, path },
    ).text;
  const text = '{"rows":[{"__proto__":false}]}';
  const tool = { content: [{ type: "text", text }] };
  expect(page(tool, ["rows", 0], ["__proto__"])).toBe("false");
  const resource = { contents: [{ text }] };
  expect(page(resource, ["rows", 0, "__proto__"])).toBe("false");
  const dual = { structuredContent: null, structured_content: "other" };
  expect(page(dual, [], [], null)).toBe("null");
  expect(() => page(tool, ["rows"], ["0"])).toThrow(/Selector/);
  expect(() => page(tool, ["rows", "0"])).toThrow(/Selector/);
  expect(() => page(tool, ["rows", 0, "constructor"])).toThrow(/Selector/);
  const image = { content: [{ type: "image", text }] };
  expect(() => page(image, [])).toThrow(/JSON text block/);
});

test("native permission table merging cannot silently widen linked evidence sessions", () => {
  const layers = [{ name: { type: "sessionFlags" }, config }];
  const matches = (actual: JsonObject) =>
    dependencyCoordinatorPermissionsMatch(
      { ...config, permissions: { dependency_investigation: actual } },
      layers,
    );
  expect(matches({ ...profile, extends: null })).toBe(true);
  const filesystem = { ...profile.filesystem, "/tmp": "write" };
  expect(matches({ ...profile, filesystem })).toBe(false);
  expect(dependencyCoordinatorPermissionsMatch(config, [])).toBe(false);
});

test("native sampling rejects tool calls and stale turns, and cancels pending requests", async () => {
  const sent: Record<string, unknown>[] = [];
  const abort = new AbortController();
  let turn = "turn-1";
  let sample: Sample | undefined;
  const totals: number[] = [];
  const session = createDependencyCoordinatorSession(
    {
      async item() {},
      sampler: (fn) => {
        sample = fn;
      },
      signal: abort.signal,
      usage: (value) => totals.push(value.total_tokens),
    },
    (request) => sent.push(request),
    undefined,
    () => turn,
  );
  session.register("root");
  const ask = () => sample!("lookup");
  function reply(text: string | null, sourceTurnId = turn) {
    session.receive({
      id: sent.at(-1)!["id"],
      result: { sourceTurnId, text, inputTokens: 5, outputTokens: 1 },
    });
  }

  const toolAttempt = ask();
  expect(sent[0]).toMatchObject({
    method: "thread/sample",
    params: {
      threadId: "root",
      expectedTurnId: turn,
      allowInProgressTurn: true,
      disableMcp: true,
      prompt: "lookup",
    },
  });
  reply(null);
  expect(await toolAttempt).toBeUndefined();
  expect(sent).toHaveLength(1);

  session.receive({
    method: "turn/completed",
    params: { threadId: "root", turn: { id: turn } },
  });
  const completed = ask();
  reply("complete");
  expect(await completed).toBe("complete");
  expect(totals).toEqual([6, 6]);
  const wrong = ask();
  reply("complete", "wrong");
  expect(await wrong).toBeUndefined();
  const stale = ask();
  turn = "turn-2";
  reply("complete", "turn-1");
  expect(await stale).toBeUndefined();

  const pending = ask();
  const requestId = sent.at(-1)!["id"];
  abort.abort();
  expect(await pending).toBeUndefined();
  expect(sent.at(-1)).toMatchObject({
    method: "thread/sample/cancel",
    params: { requestId },
  });
  session.close();
  expect(sample).toBeUndefined();
});
