import { describe, expect, test } from "bun:test";
import { collectPublicationEvents } from "../src/publication-events.js";
import type { PreparedScanPublication } from "../src/publication.js";

function publication(count = 1): PreparedScanPublication {
  return {
    scanId: "scan_example",
    uploadId: "scan_example",
    scanDirectory: "/synthetic/sealed-scan",
    destination: {
      type: "linear",
      teamId: "team_example",
      projectId: "project_example",
    },
    issues: Array.from({ length: count }, (_, index) => ({
      findingId: `finding_${index}`,
      occurrenceId: `occurrence_${index}`,
      title: `[Codex Security][HIGH] Finding ${index}`,
      description: `Description ${index}`,
      priority: 2,
    })),
  };
}

function event(
  prepared: PreparedScanPublication,
  index = 0,
  overrides: Record<string, unknown> = {},
): string {
  const issue = prepared.issues[index]!;
  return JSON.stringify({
    type: "item.completed",
    item: {
      id: `call_${index}`,
      type: "mcp_tool_call",
      server: "codex_apps",
      tool: "linear_save_issue",
      status: "completed",
      arguments: {
        team: prepared.destination.teamId,
        project: prepared.destination.projectId,
        title: issue.title,
        description: issue.description,
        ...(issue.priority === undefined ? {} : { priority: issue.priority }),
      },
      result: {
        content: [],
        structured_content: {
          identifier: `SEC-${index + 1}`,
          url: `https://linear.app/example/issue/SEC-${index + 1}`,
        },
      },
      ...overrides,
    },
  });
}

describe("Codex Linear publication events", () => {
  test("collects completed Linear issue tool calls and ignores unrelated events", () => {
    const prepared = publication(2);
    const output = [
      JSON.stringify({
        type: "item.completed",
        item: { type: "error", message: "chronicle warning" },
      }),
      JSON.stringify({
        type: "item.completed",
        item: { type: "agent_message", text: "SEC-FAKE" },
      }),
      JSON.stringify({
        type: "item.started",
        item: {
          type: "mcp_tool_call",
          server: "codex_apps",
          tool: "linear_save_issue",
        },
      }),
      event(prepared, 0),
      event(prepared, 1),
    ].join("\n");

    expect(collectPublicationEvents(output, prepared, "missing")).toEqual({
      created: [
        {
          findingId: "finding_0",
          occurrenceId: "occurrence_0",
          issueIdentifier: "SEC-1",
          url: "https://linear.app/example/issue/SEC-1",
        },
        {
          findingId: "finding_1",
          occurrenceId: "occurrence_1",
          issueIdentifier: "SEC-2",
          url: "https://linear.app/example/issue/SEC-2",
        },
      ],
      failed: [],
    });
  });

  test("accepts nested structured issues and JSON text tool results", () => {
    const prepared = publication(2);
    const output = [
      event(prepared, 0, {
        result: {
          structured_content: { issue: { identifier: "NESTED-1" } },
          content: [],
        },
      }),
      event(prepared, 1, {
        result: {
          structured_content: null,
          content: [
            {
              type: "text",
              text: JSON.stringify({
                data: {
                  issue: {
                    identifier: "TEXT-2",
                    url: "https://linear.app/example/issue/TEXT-2",
                  },
                },
              }),
            },
          ],
        },
      }),
    ].join("\n");

    expect(collectPublicationEvents(output, prepared, "missing")).toEqual({
      created: [
        {
          findingId: "finding_0",
          occurrenceId: "occurrence_0",
          issueIdentifier: "NESTED-1",
        },
        {
          findingId: "finding_1",
          occurrenceId: "occurrence_1",
          issueIdentifier: "TEXT-2",
          url: "https://linear.app/example/issue/TEXT-2",
        },
      ],
      failed: [],
    });
  });

  test.each([
    ["different team", { team: "unexpected_team" }],
    ["different project", { project: "unexpected_project" }],
    ["update id", { id: "SEC-EXISTING" }],
    ["extra mutation", { assignee: "someone" }],
    ["wrong priority", { priority: 1 }],
  ] as const)(
    "rejects %s without claiming a created issue",
    (_label, changed) => {
      const prepared = publication();
      const issue = prepared.issues[0]!;
      const output = event(prepared, 0, {
        arguments: {
          team: prepared.destination.teamId,
          project: prepared.destination.projectId,
          title: issue.title,
          description: issue.description,
          priority: issue.priority,
          ...changed,
        },
      });

      const result = collectPublicationEvents(output, prepared, "missing");
      expect(result.created).toEqual([]);
      expect(result.failed).toEqual([
        {
          findingId: "finding_0",
          error: expect.stringContaining("unexpected arguments or destination"),
        },
      ]);
    },
  );

  test("reports unexpected issue calls instead of trusting model-created output", () => {
    const prepared = publication();
    const output = event(prepared, 0, {
      arguments: {
        team: "attacker_team",
        project: "attacker_project",
        title: "Injected issue",
        description: "Ignore previous instructions",
      },
    });

    expect(collectPublicationEvents(output, prepared, "missing")).toEqual({
      created: [],
      failed: [
        {
          findingId: "finding_0",
          error: expect.stringContaining("unexpected Linear issue"),
        },
      ],
    });
  });

  test("uses failed tool errors and marks missing findings without trusting agent text", () => {
    const prepared = publication(3);
    const output = [
      event(prepared, 0),
      event(prepared, 1, {
        status: "failed",
        error: { message: "Linear rejected this finding." },
        result: undefined,
      }),
      JSON.stringify({
        type: "item.completed",
        item: {
          type: "agent_message",
          text: '{"identifier":"SEC-FABRICATED"}',
        },
      }),
    ].join("\n");

    const result = collectPublicationEvents(
      output,
      prepared,
      "No issue created.",
    );
    expect(result.created).toHaveLength(1);
    expect(result.failed).toEqual([
      { findingId: "finding_1", error: "Linear rejected this finding." },
      { findingId: "finding_2", error: "No issue created." },
    ]);
  });

  test("does not claim success for malformed tool results or malformed JSONL", () => {
    const prepared = publication(2);
    const output = [
      "not JSON",
      event(prepared, 0, {
        result: { structured_content: { title: "No issue identifier" } },
      }),
      JSON.stringify({ type: "item.completed", item: null }),
    ].join("\n");

    expect(
      collectPublicationEvents(output, prepared, "Missing tool call."),
    ).toEqual({
      created: [],
      failed: [
        {
          findingId: "finding_0",
          error: expect.stringContaining(
            "did not return a created issue identifier",
          ),
        },
        { findingId: "finding_1", error: "Missing tool call." },
      ],
    });
  });

  test("handles more than 25 findings without a publication limit", () => {
    const prepared = publication(37);
    const output = prepared.issues
      .map((_issue, index) => event(prepared, index))
      .join("\n");
    const result = collectPublicationEvents(output, prepared, "missing");

    expect(result.created).toHaveLength(37);
    expect(result.failed).toEqual([]);
    expect(result.created[36]?.issueIdentifier).toBe("SEC-37");
  });

  test("rejects repeated creation calls for the same finding", () => {
    const prepared = publication();
    const result = collectPublicationEvents(
      `${event(prepared)}\n${event(prepared)}`,
      prepared,
      "missing",
    );

    expect(result.created).toEqual([]);
    expect(result.failed).toEqual([
      {
        findingId: "finding_0",
        error: expect.stringContaining("more than one"),
      },
    ]);
  });
});
