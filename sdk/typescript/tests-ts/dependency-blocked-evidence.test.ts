import { expect, test } from "bun:test";
import {
  createDependencyBlockEvidence,
  dependencyAbortTool,
} from "../src/dependency-blocked-evidence.js";
import {
  createDependencyEvidenceCapture,
  type DependencyEvidenceRecord,
} from "../src/dependency-evidence-sources.js";
import { createDependencyResourceSession } from "../src/dependency-resource-session.js";
import {
  DependencyInvestigationBlockedError,
  runReviewedDependencyCheck,
} from "../src/dependency-reviewed-check.js";
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
});
test("a provider declaration is bound to the genuine scoped and current response", () => {
  const { block, result } = fixture();
  const declaration = "Required release data is unavailable.";
  const proposal = (receiptId: string) => ({
    ...details,
    tool: target,
    coverage: {
      basis: "provider_declared",
      scope: "two releases",
      representativeness: "All selected releases are covered",
      declaration,
      selection: select(receiptId, "message"),
    },
  });
  const receipt = result(
    { releases: ["one", "two"] },
    { structuredContent: { message: declaration } },
  );
  expect(block.verify(proposal(receipt), "root", []).coverage.basis).toBe(
    "provider_declared",
  );
  expect(() =>
    block.verify(
      {
        ...proposal(receipt),
        coverage: { ...proposal(receipt).coverage, declaration: "invented" },
      },
      "root",
      [],
    ),
  ).toThrow();
  expect(() =>
    block.verify(
      proposal(result({}, { structuredContent: { message: declaration } })),
      "root",
      [],
    ),
  ).toThrow(/unscoped/);
  const healthy = "No records are missing.";
  const positive = proposal(
    result(
      { releases: ["one", "two"] },
      { structuredContent: { message: healthy } },
    ),
  );
  expect(() =>
    block.verify(
      { ...positive, coverage: { ...positive.coverage, declaration: healthy } },
      "root",
      [],
    ),
  ).toThrow(/unavailable/);
  for (const payload of [
    { message: "Release one is missing." },
    { message: "missing", complete: true },
    { message: declaration, complete: true },
  ]) {
    const isolated = proposal(
      result({ release: "one" }, { structuredContent: payload }),
    );
    expect(() =>
      block.verify(
        {
          ...isolated,
          coverage: { ...isolated.coverage, declaration: payload.message },
        },
        "root",
        [],
      ),
    ).toThrow(/unavailable/);
  }
  const proof = result(
    { releases: ["one", "two"] },
    {
      structuredContent: {
        coverage: {
          scope: "selected releases",
          complete: false,
          reason: "Nenhum registro confirmado.",
        },
      },
    },
  );
  const declared = proposal(proof);
  expect(
    block.verify(
      {
        ...declared,
        coverage: {
          ...declared.coverage,
          declaration: "Nenhum registro confirmado.",
          selection: {
            receiptId: proof,
            textBlock: null,
            record: ["coverage", "reason"],
          },
        },
      },
      "root",
      [],
    ).coverage.basis,
  ).toBe("provider_declared");
  const contradictory = result(
    { release: "one" },
    {
      structuredContent: { coverage: { complete: true } },
      content: [
        { type: "text", text: JSON.stringify({ message: declaration }) },
      ],
    },
  );
  const alternate = proposal(contradictory);
  expect(() =>
    block.verify(
      {
        ...alternate,
        coverage: {
          ...alternate.coverage,
          selection: { ...alternate.coverage.selection, textBlock: 0 },
        },
      },
      "root",
      [],
    ),
  ).toThrow(/unavailable/);
  const archived = result(
    { releases: ["one", "two"] },
    {
      isError: true,
      structuredContent: { status: "not_recorded", message: declaration },
      content: [
        { type: "text", text: JSON.stringify({ message: declaration }) },
      ],
    },
    "failed",
  );
  expect(() =>
    block.verify(
      {
        ...proposal(archived),
        coverage: {
          ...proposal(archived).coverage,
          selection: { ...select(archived, "message"), textBlock: 0 },
        },
      },
      "root",
      [],
    ),
  ).toThrow(/archived/);
  expect(() => block.verify(proposal(receipt), "root", [])).toThrow(/current/);
});
test("the native coordinator owns the current failed required startup and only the active root turn can block", async () => {
  const { block, result } = fixture();
  expect(
    block.startup("builds", "failed", false, "Optional source"),
  ).toBeUndefined();
  const sent: Record<string, unknown>[] = [];
  let selected: string | undefined;
  const session = createDependencyResourceSession(
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
        const page = (await tools.call("list_dependency_evidence", {
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
