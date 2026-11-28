import { expect, test } from "bun:test";
import {
  createDependencyEvidenceCapture,
  dependencyLookupSearch,
  lookupCoverage,
  selectDependencyEvidenceServers,
} from "../src/exploitability/evidence-sources.js";

test("an investigator can cite only completed calls to its selected evidence tools", () => {
  const deployments = {
    command: "example-deployments",
    enabled_tools: ["lookup", "retired"],
    disabled_tools: ["retired"],
  };
  const servers = selectDependencyEvidenceServers(
    [{ server: "deployments", instructions: "Look up the running revision." }],
    { deployments, other: { command: "another-tool" } },
  );
  expect(servers).toEqual({ deployments });
  const call = {
    type: "mcp_tool_call",
    status: "completed",
    server: "deployments",
    tool: "lookup",
    arguments: { service: "example" },
    result: { content: [{ type: "text", text: "Running revision 123" }] },
  };
  const failures: unknown[] = [];
  const capture = createDependencyEvidenceCapture(servers, (failed) =>
    failures.push(failed),
  );
  const record = (item: unknown) => capture({ type: "item.completed", item });
  const captured = record(call);
  expect(captured).toEqual({
    server: call.server,
    tool: call.tool,
    arguments: call.arguments,
    result: call.result,
    sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
  });
  expect(record({ ...call, arguments: { service: "other" } })?.sha256).not.toBe(
    captured!.sha256,
  );
  for (const item of [
    { ...call, server: "other" },
    { ...call, tool: "unlisted" },
    { ...call, tool: "retired" },
    { ...call, status: "failed" },
    { ...call, status: "failed", server: "other" },
    { ...call, status: "failed", tool: "retired" },
    { ...call, result: { ...call.result, isError: true } },
    { type: "command_execution", aggregated_output: JSON.stringify(call) },
  ])
    expect(record(item)).toBeUndefined();
  const failed = {
    server: call.server,
    tool: call.tool,
    arguments: call.arguments,
  };
  expect(failures).toEqual([failed, failed]);
});

test("selecting an unknown or disabled server gives a configuration error", () => {
  for (const server of ["missing", "disabled"])
    expect(() =>
      selectDependencyEvidenceServers(
        [{ server, instructions: "Find the running revision." }],
        { disabled: { enabled: false } },
      ),
    ).toThrow("codex.mcp_servers");
});

test("captures resource reads linked by a successful lookup on the same server and run", () => {
  const server = { enabled_tools: ["profiles.lookup"] };
  const servers = { primary: server, secondary: server };
  const capture = createDependencyEvidenceCapture(servers);
  const uri = "profile://workloads/example";
  const lookup = {
    type: "mcp_tool_call",
    server: "primary",
    tool: "profiles.lookup",
    arguments: { workload: "example" },
    status: "completed",
    result: { content: [{ type: "resource_link", uri, name: "samples" }] },
  };
  const resource = (server: string) => ({
    type: "item.completed",
    item: {
      type: "mcp_tool_call",
      server,
      tool: "read_mcp_resource",
      arguments: { server, uri },
      status: "completed",
      result: {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              server,
              uri,
              contents: [
                { uri, text: "Observed sample from the example workload." },
              ],
            }),
          },
        ],
      },
    },
  });
  capture({ type: "item.completed", item: { ...lookup, status: "failed" } });
  expect(capture(resource("primary"))).toBeUndefined();
  expect(capture({ type: "item.completed", item: lookup })?.tool).toBe(
    "profiles.lookup",
  );
  expect(capture(resource("primary"))?.result).toEqual(
    resource("primary").item.result,
  );
  expect(capture(resource("secondary"))).toBeUndefined();
  expect(
    createDependencyEvidenceCapture(servers)(resource("primary")),
  ).toBeUndefined();
});

test("report coverage follows declared response envelopes and never service rows", () => {
  const summarize = (payload: Record<string, unknown>) =>
    dependencyLookupSearch({
      server: "registry",
      tool: "list",
      sha256: "receipt",
      arguments: {},
      result: { structuredContent: payload },
    });
  expect(summarize({ outcome: "found", status: "no_match" })).toMatchObject({
    result: "returned",
  });
  expect(
    summarize({
      coverage: { complete: true },
      rows: [{ partial: true, status: "no_match" }],
      data: { service: { status: "matched", complete: false } },
    }),
  ).toMatchObject({ result: "returned", completeness: "complete" });
  expect(
    summarize({
      coverage: { complete: true },
      next_page_token: "",
      nextCursor: "page2",
    }),
  ).toMatchObject({ completeness: "partial" });
  expect(
    summarize({
      coverage: { complete: true },
      metadata: { coverage: { result_complete: false } },
    }),
  ).toMatchObject({ completeness: "partial" });
  expect(summarize({ complete: true, hasMore: "false" })).toMatchObject({
    completeness: "unknown",
  });
  expect(summarize({ complete: true, coverage: "unknown" })).toMatchObject({
    completeness: "unknown",
  });
  expect(
    summarize({ complete: true, nextCursor: null, nextPageToken: "" }),
  ).toMatchObject({ completeness: "complete" });
  expect(
    summarize({
      complete: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({ rows: [{ name: "…25 chars truncated…" }] }),
        },
      ],
    }),
  ).toMatchObject({ completeness: "complete" });
});

test("coverage inspects the selected resource root without treating payload JSON as an MCP envelope", () => {
  const resource = {
    contents: [
      { text: JSON.stringify({ coverage: { complete: false } }) },
      { text: JSON.stringify({ complete: true }) },
    ],
  };
  expect(
    lookupCoverage(resource, { textBlock: 0, record: [] }).incomplete,
  ).toBe(true);
  expect(
    lookupCoverage(resource, { textBlock: 1, record: [] }).incomplete,
  ).toBe(false);
  const ordinary = {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          complete: true,
          content: [{ type: "text", text: '{"partial":true}' }],
        }),
      },
    ],
  };
  expect(lookupCoverage(ordinary).completeness).toBe("complete");
});
