import { expect, test } from "bun:test";
import {
  createDependencyBlockEvidence,
  dependencyAbortTool,
} from "../src/exploitability/analyzers/repository/blocked-evidence.js";
import {
  createDependencyEvidenceCapture,
  type DependencyEvidenceRecord,
} from "../src/exploitability/evidence-sources.js";
import { createDependencyCoordinatorSession } from "../src/exploitability/analyzers/repository/coordinator.js";
import {
  DependencyInvestigationBlockedError,
  runReviewedDependencyCheck,
} from "../src/exploitability/analyzers/repository/check.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { execFileSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { readSkillCommandOutput } from "../src/cli.js";

const target = { server: "builds", name: "lookup" };
const details = {
  category: "widespread_required_data_unavailable",
  affectedScope: "Two selected releases",
  reason: "Both required release records are unavailable",
  scopeImpact: "The selected deployments cannot be identified.",
  unblockCondition: "Restore build inventory.",
};
const startupRequest = (receiptId: string) => ({
  ...details,
  coverage: {
    basis: "server_startup",
    server: "builds",
    receiptId,
    requiredCheck: "Resolve the selected releases",
  },
});
function fixture() {
  const records = new Map<string, DependencyEvidenceRecord>();
  const block = createDependencyBlockEvidence(new Set(["builds"]), records);
  const capture = createDependencyEvidenceCapture(
    { builds: { enabled_tools: ["lookup"] } },
    (r, body) => block.failed(r, body),
  );
  const result = (
    args: unknown,
    payload: Record<string, unknown>,
    status = "completed",
  ) => {
    const r = capture({
      type: "item.completed",
      item: {
        type: "mcp_tool_call",
        id: "call",
        server: "builds",
        tool: "lookup",
        arguments: args,
        result: payload,
        status,
      },
    });
    if (r) {
      records.set(r.sha256, r);
      block.observe(r);
      return r.sha256;
    }
    return [...block.failures.keys()].at(-1)!;
  };
  return { block, result, records };
}
const select = (receiptId: string, key: string) => ({
  receiptId,
  textBlock: null,
  record: [key],
});
test("observed coverage must enumerate distinct selected requests and the current returned values", () => {
  const { block, result } = fixture();
  const row = (id: string) => ({
    requiredRecord: id,
    selection: select(
      result({ release: id }, { structuredContent: { artifact: null } }),
      "artifact",
    ),
    missing: true,
  });
  const first = row("one"),
    second = row("two");
  const proposal = {
    ...details,
    tool: target,
    coverage: {
      basis: "observed_scope",
      scope: "releases",
      checked: 2,
      missing: 2,
      checks: [first, second],
      representativeness: "Both commissioned releases were checked.",
    },
  };
  expect(block.verify(proposal, "root", [])).toMatchObject({
    nativeThreadId: "root",
    retainedEvidence: {
      inventoryReceiptIds: [
        first.selection.receiptId,
        second.selection.receiptId,
      ],
    },
  });
  const verify = (edit: Record<string, unknown>) => () =>
    block.verify(
      { ...proposal, coverage: { ...proposal.coverage, ...edit } },
      "root",
      [],
    );
  expect(verify({ checks: [first, first] })).toThrow();
  expect(
    verify({ checks: [{ ...first, requiredRecord: "forged" }, second] }),
  ).toThrow();
  expect(verify({ checked: 7 })).toThrow();
  expect(() =>
    block.verify({ ...proposal, status: "blocked" }, "root", []),
  ).toThrow();
  expect(() =>
    block.verify(
      { ...proposal, evidenceReferences: ["unobserved"] },
      "root",
      [],
    ),
  ).toThrow();
  expect(() =>
    block.verify(
      { ...proposal, tool: { ...target, name: "unrelated" } },
      "root",
      [],
    ),
  ).toThrow();
  result({ release: "one" }, { structuredContent: { artifact: "fixed" } });
  expect(() => block.verify(proposal, "root", [])).toThrow(/current/);
  const healthy = select(
    result({ release: "two" }, { structuredContent: { artifact: ["found"] } }),
    "artifact",
  );
  expect(
    verify({
      checks: [
        {
          ...first,
          selection: select(
            result(
              { release: "one" },
              { structuredContent: { artifact: null } },
            ),
            "artifact",
          ),
        },
        { ...second, selection: healthy },
      ],
    }),
  ).toThrow(/missing status/);
  const absent = (release: string, partial: boolean) => ({
    requiredRecord: release,
    selection: select(
      result(
        { release },
        { structuredContent: { artifact: null, metadata: { partial } } },
      ),
      "artifact",
    ),
    missing: true,
  });
  expect(
    verify({ checks: [absent("one", true), absent("two", false)] }),
  ).toThrow(/incomplete lookup coverage/i);
});
test("one provider response can block only the requested scope it marks unavailable", () => {
  const { block, result } = fixture();
  const scope = "production";
  const unavailable = {
    scope,
    available: false,
    reason: "Nenhum registro confirmado.",
  };
  const lookup = (payload: object, requestScope = scope) =>
    result({ scope: requestScope }, { structuredContent: payload });
  const verify = (receiptId: string, affectedScope = scope) =>
    block.verify(
      {
        ...details,
        affectedScope,
        tool: target,
        coverage: {
          basis: "provider_declared",
          receiptId,
          representativeness:
            "The deployment inventory covers the requested environment.",
        },
      },
      "root",
      [],
    );
  const receipt = lookup({ coverage: unavailable });
  expect(verify(receipt).coverage).toMatchObject({
    basis: "provider_declared",
    receiptId: receipt,
  });
  expect(() => verify(receipt, "staging")).toThrow(/same scope/);
  expect(() => verify(lookup({ coverage: unavailable }, "staging"))).toThrow(
    /same scope/,
  );
  for (const response of [
    { message: "All inventory checks passed except one missing record." },
    { coverage: { scope, complete: false } },
    { coverage: { scope: "staging", available: false } },
    { complete: true, coverage: unavailable },
    { coverage: { ...unavailable, result_complete: true } },
    { coverage: unavailable, metadata: { available: true } },
    { coverage: unavailable, complete: "false" },
    { coverage: unavailable, next_page_token: "", nextCursor: "more" },
    { coverage: unavailable, backend_partial: true },
    { metadata: { coverage: unavailable } },
  ])
    expect(() => verify(lookup(response))).toThrow(/structured coverage/);
  expect(
    verify(lookup({ coverage: { ...unavailable, complete: false } })),
  ).toMatchObject({ affectedScope: scope });
  expect(() => verify(receipt)).toThrow(/current/);
  expect(() =>
    verify(lookup({ status: "not_recorded", coverage: unavailable })),
  ).toThrow(/archived/);
});

test("the native coordinator owns the current failed required startup and only the active root turn can block", async () => {
  const { block, result } = fixture();
  const optional = block.startup("builds", "failed", false, "Optional source")!;
  expect(optional).toBeTruthy();
  expect(() => block.verify(startupRequest(optional), "root", [])).toThrow(
    "current failed startup",
  );
  const sent: Record<string, unknown>[] = [];
  let selected: string | undefined;
  const session = createDependencyCoordinatorSession(
    {
      async item() {},
      startup(name, status, error) {
        selected = block.startup(name, status, name === "builds", error);
      },
      abort: {
        ...dependencyAbortTool,
        call: (input, id) => block.verify(input, id, []),
      },
    },
    (r) => sent.push(r),
  );
  session.register("root");
  expect(session.abortTool).toMatchObject({
    type: "namespace",
    name: "codex_security_reports",
    tools: [{ name: "abort_codex_security_investigation" }],
  });
  const status = (name: string, s: string, threadId: string | null) =>
    session.receive({
      method: "mcpServer/startupStatus/updated",
      params: {
        name,
        status: s,
        threadId,
        error: "fixture service is offline",
      },
    });
  status("builds", "failed", "child");
  expect(selected).toBeUndefined();
  status("optional", "failed", "root");
  expect(selected).toBeUndefined();
  status("builds", "failed", "root");
  const original = selected!;
  expect(original).toBeTruthy();
  const call = (threadId: string, turnId: string, receiptId: string) => {
    session.abortCall(
      {
        id: "rpc",
        method: "item/tool/call",
        params: {
          threadId,
          turnId,
          namespace: "codex_security_reports",
          tool: dependencyAbortTool.name,
          arguments: startupRequest(receiptId),
        },
      },
      "now",
    );
    return sent.at(-1)!["result"];
  };
  expect(call("child", "now", original)).toMatchObject({ success: false });
  expect(call("root", "old", original)).toMatchObject({ success: false });
  expect(call("root", "now", "made-up")).toMatchObject({ success: false });
  expect(call("root", "now", original)).toMatchObject({ success: true });
  status("builds", "ready", "root");
  expect(call("root", "now", original)).toMatchObject({ success: false });
  status("builds", "failed", null);
  const repeated = selected!;
  expect(repeated).not.toBe(original);
  result({ release: "one" }, { structuredContent: { name: "resolved" } });
  expect(call("root", "now", repeated)).toMatchObject({ success: false });
  status("builds", "failed", "root");
  session.receive({
    method: "turn/completed",
    params: { threadId: "root", turn: { id: "now", status: "failed" } },
  });
  expect(call("root", "now", selected!)).toMatchObject({ success: false });
  session.close();
});
test("the coordinator registers and answers its abort tool on the native wire", async () => {
  const stream = new PassThrough();
  const write = (event: unknown) => stream.write(JSON.stringify(event) + "\n");
  const config = {
    default_permissions: "dependency_investigation",
    permissions: {
      dependency_investigation: {
        filesystem: { ":root": "read" },
        network: { enabled: false },
      },
    },
  };
  const { block } = fixture();
  const results: unknown[] = [];
  const input = new Writable({
    write(data, _encoding, done) {
      const request = JSON.parse(data.toString());
      if (request.method === "initialize")
        write({ id: request.id, result: {} });
      if (request.method === "config/read")
        write({
          id: request.id,
          result: {
            config,
            layers: [{ name: { type: "sessionFlags" }, config }],
          },
        });
      if (request.method === "thread/start") {
        expect(request.params.dynamicTools).toMatchObject([
          {
            name: "codex_security_reports",
            tools: [{ name: dependencyAbortTool.name }],
          },
        ]);
        write({
          id: request.id,
          result: {
            thread: { id: "leader", ephemeral: true },
            activePermissionProfile: { id: "dependency_investigation" },
            model: "fixture",
            modelProvider: "fixture",
          },
        });
      }
      if (request.method === "turn/start") {
        write({ id: request.id, result: { turn: { id: "active" } } });
        write({
          method: "mcpServer/startupStatus/updated",
          params: {
            threadId: "leader",
            name: "builds",
            status: "failed",
            error: "Offline",
          },
        });
      }
      if (request.id === "abort") {
        results.push(request.result);
        write({
          method: "turn/completed",
          params: {
            threadId: "leader",
            turn: { id: "active", status: "completed" },
          },
        });
      }
      done();
    },
    final(done) {
      stream.end();
      done();
    },
  });
  await readSkillCommandOutput(stream, {
    input,
    directory: "/fixture",
    prompt: "Investigate",
    threadSource: "security_validation",
    cyberAccessProgram: "standard",
    linkedEvidence: {
      async item() {},
      startup(server, status, error) {
        const receiptId = block.startup(server, status, true, error)!;
        write({
          id: "abort",
          method: "item/tool/call",
          params: {
            threadId: "leader",
            turnId: "active",
            namespace: "codex_security_reports",
            tool: dependencyAbortTool.name,
            arguments: startupRequest(receiptId),
          },
        });
      },
      abort: {
        ...dependencyAbortTool,
        call: (args, id) => block.verify(args, id, []),
      },
    },
  });
  expect(results).toEqual([
    {
      success: true,
      contentItems: [
        {
          type: "inputText",
          text: expect.stringContaining('"nativeThreadId":"leader"'),
        },
      ],
    },
  ]);
});

test("a validated block stops the advisory even when the investigator returns a final answer", async () => {
  await using dir = await scopedTemporaryDirectory("dependency-blocked-");
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: dir.path });
  git("init", "-q");
  await writeFile(
    join(dir.path, "package.json"),
    '{"name":"app","dependencies":{"codec":"1.0.0"}}',
  );
  git("add", ".");
  git(
    "-c",
    "user.name=Test",
    "-c",
    "user.email=t@example.invalid",
    "commit",
    "-qm",
    "fixture",
  );
  let calls = 0;
  const execution = runReviewedDependencyCheck(
    {
      directory: dir.path,
      subject: "CVE-2099-1000",
      signal: new AbortController().signal,
      evidenceSources: [
        { server: "builds", instructions: "Identify both releases." },
      ],
    },
    {
      lookupCve: async () => ({ cve: "CVE-2099-1000", advisories: [] }),
      runAgent: async (req) => {
        calls++;
        req.onEvidenceStartup!("builds", "failed", true, "Unreachable");
        const tools = await req.investigationTools!();
        const page = (await tools.call("read_dependency_evidence", {
          server: "builds",
        })) as { receipts: { id: string }[] };
        const id = page.receipts[0]!.id;
        const archive = (await tools.call("read_dependency_evidence", {
          id,
        })) as { text: string };
        expect(archive.text).toContain("Unreachable");
        expect(() =>
          req.abortInvestigation!(startupRequest("forged"), "root"),
        ).toThrow();
        expect(req.signal.aborted).toBe(false);
        req.abortInvestigation!(startupRequest(id), "root");
        expect(req.signal.aborted).toBe(true);
        return JSON.stringify({ uses: [], limitations: [] });
      },
    },
  );
  let failure: unknown;
  try {
    await execution;
  } catch (e) {
    failure = e;
  }
  expect(failure).toBeInstanceOf(DependencyInvestigationBlockedError);
  expect(
    (failure as DependencyInvestigationBlockedError).outcome,
  ).toMatchObject({
    status: "blocked",
    cve: "CVE-2099-1000",
    nativeThreadId: "root",
    retainedEvidence: { inventoryReceiptIds: [expect.any(String)] },
  });
  expect(calls).toBe(1);
});
