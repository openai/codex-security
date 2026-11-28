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
  const row = (id: string, fields: object = {}) => {
    const structuredContent = {
      artifact: null,
      coverage: { complete: true },
      ...fields,
    };
    const receipt = result({ release: id }, { structuredContent });
    return {
      requiredRecord: id,
      selection: select(receipt, "artifact"),
      missing: true,
    };
  };
  const first = row("one"),
    second = row("two", { artifact: [] });
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
  ).toThrow(/current original/);
  result({ release: "one" }, { structuredContent: { artifact: "fixed" } });
  expect(() => block.verify(proposal, "root", [])).toThrow(/current/);
  expect(
    verify({ checks: [row("one"), row("two", { artifact: ["found"] })] }),
  ).toThrow(/missing status/);
  for (const fields of [
    { coverage: undefined },
    { coverage: { complete: true, available: false } },
    { nextCursor: "more" },
  ]) {
    expect(verify({ checks: [row("one", fields), row("two")] })).toThrow(
      /incomplete lookup coverage/i,
    );
  }
  const nested = result(
    { query: { notes: "one" } },
    { structuredContent: { artifact: null, coverage: { complete: true } } },
  );
  expect(
    verify({
      checks: [{ ...first, selection: select(nested, "artifact") }, row("two")],
    }),
  ).toThrow(/record identity/);
  const failed = result(
    { release: "one" },
    { structuredContent: { status: "failed" } },
    "failed",
  );
  expect(
    verify({
      checks: [{ ...first, selection: select(failed, "status") }, row("two")],
    }),
  ).not.toThrow();
});
test("one provider response can block only the requested scope it marks unavailable", () => {
  const { block, result } = fixture();
  const scope = "production";
  const unavailable = {
    scope,
    available: false,
    complete: false,
    reason: "Nenhum registro confirmado.",
  };
  const lookup = (payload: object, requestScope = scope) =>
    result(
      { scope: requestScope },
      { structuredContent: payload, content: [], _meta: null },
    );
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
    { coverage: { ...unavailable, complete: true } },
    { coverage: unavailable, metadata: { available: true } },
  ])
    expect(() => verify(lookup(response))).toThrow(/structured coverage/);
  const payload = { coverage: unavailable };
  const withText = (body: object, meta: unknown = null) =>
    result(
      { scope },
      {
        structuredContent: payload,
        content: [{ type: "text", text: JSON.stringify(body) }],
        _meta: meta,
      },
    );
  expect(verify(withText(payload)).affectedScope).toBe(scope);
  expect(() => verify(withText(payload, { nextCursor: "more" }))).toThrow(
    /structured coverage/,
  );
  expect(() =>
    verify(withText({ coverage: { scope, available: true } })),
  ).toThrow(/structured coverage/);
  expect(() => verify(receipt)).toThrow(/current/);
  expect(() =>
    verify(lookup({ status: "not_recorded", coverage: unavailable })),
  ).toThrow(/archived/);
});

test("only the active root turn can block on a current required startup failure", () => {
  const { block, result } = fixture();
  const optional = block.startup("builds", "failed", false, "Optional source")!;
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
  expect(call("root", "now", original)).toMatchObject({
    success: true,
    contentItems: [
      {
        type: "inputText",
        text: expect.stringContaining('"nativeThreadId":"root"'),
      },
    ],
  });
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
