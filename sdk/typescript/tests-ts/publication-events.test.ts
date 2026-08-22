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
      description: [
        `**Finding ID:** finding_${index}`,
        `**Occurrence ID:** occurrence_${index}`,
        `Description ${index}`,
      ].join("\n"),
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
      tool: "linear.save_issue",
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
  test("collects dotted and legacy Linear issue calls while ignoring unrelated events", () => {
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
          tool: "linear.save_issue",
        },
      }),
      event(prepared, 0),
      event(prepared, 1, { tool: "linear_save_issue" }),
    ].join("\n");

    expect(collectPublicationEvents(output, prepared, "missing")).toEqual({
      completedEvents: [
        event(prepared, 0),
        event(prepared, 1, { tool: "linear_save_issue" }),
      ],
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
      completedEvents: output.split("\n"),
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

  test("does not verify rewritten issue content even when finding identities match", () => {
    const prepared = publication(8);
    const output = prepared.issues
      .map((issue, index) =>
        event(prepared, index, {
          arguments: {
            team: prepared.destination.teamId,
            project: prepared.destination.projectId,
            title: index < 6 ? issue.title : "A rewritten issue title",
            description:
              index < 6
                ? issue.description
                : `Finding ${issue.findingId}; occurrence ${issue.occurrenceId}`,
            priority: index < 6 ? issue.priority : 4,
          },
        }),
      )
      .join("\n");

    const result = collectPublicationEvents(output, prepared, "missing");
    expect(result.created).toHaveLength(6);
    expect(result.created.map((issue) => issue.issueIdentifier)).toEqual([
      "SEC-1",
      "SEC-2",
      "SEC-3",
      "SEC-4",
      "SEC-5",
      "SEC-6",
    ]);
    expect(result.failed.map((issue) => issue.findingId)).toEqual([
      "finding_6",
      "finding_7",
    ]);
    expect(result.indeterminate).toBe(true);
    expect(result.completedEvents).toEqual(output.split("\n"));
  });

  test("retains every completed mutation for an indeterminate finding", () => {
    const prepared = publication();
    const first = event(prepared);
    const second = JSON.parse(first);
    second.item.arguments.title = "Changed title";
    second.item.result.structured_content.identifier = "SEC-OTHER";
    const changed = JSON.stringify(second);

    const result = collectPublicationEvents(
      `${first}\n${changed}`,
      prepared,
      "missing",
    );
    expect(result.created).toEqual([]);
    expect(result.failed).toHaveLength(1);
    expect(result.completedEvents).toEqual([first, changed]);
  });

  test("keeps verified findings when an additional completed mutation is unknown", () => {
    const prepared = publication();
    const first = event(prepared);
    const extra = JSON.parse(first);
    extra.item.arguments.description = "An unrelated issue";
    extra.item.result.structured_content.identifier = "SEC-OTHER";
    const unknown = JSON.stringify(extra);

    const result = collectPublicationEvents(
      `${first}\n${unknown}`,
      prepared,
      "missing",
    );
    expect(result.created[0]?.issueIdentifier).toBe("SEC-1");
    expect(result.failed).toEqual([]);
    expect(result.completedEvents).toEqual([first, unknown]);
  });

  test("rejects missing, mismatched, or ambiguous finding occurrence IDs", () => {
    const prepared = publication(2);
    const first = prepared.issues[0]!;
    const second = prepared.issues[1]!;
    for (const description of [
      first.findingId,
      first.occurrenceId,
      `${first.findingId} ${second.occurrenceId}`,
      `${first.findingId} ${first.occurrenceId} ${second.findingId} ${second.occurrenceId}`,
    ]) {
      const result = collectPublicationEvents(
        event(prepared, 0, { arguments: { description } }),
        prepared,
        "missing",
      );
      expect(result.created).toEqual([]);
      expect(result.failed).toHaveLength(2);
    }
  });

  test("accepts Linear issues that expose their human-readable issue key as id", () => {
    const prepared = publication(3);
    const output = [
      event(prepared, 0, {
        result: {
          content: [],
          structured_content: {
            id: "EXAMPLE-123",
            url: "https://linear.app/example/issue/EXAMPLE-123",
          },
        },
      }),
      event(prepared, 1, {
        result: {
          content: [],
          structured_content: { issue: { id: "EXAMPLE-124" } },
        },
      }),
      event(prepared, 2, {
        result: {
          structured_content: null,
          content: [
            {
              type: "text",
              text: JSON.stringify({ data: { issue: { id: "EXAMPLE-125" } } }),
            },
          ],
        },
      }),
    ].join("\n");

    expect(collectPublicationEvents(output, prepared, "missing")).toEqual({
      completedEvents: output.split("\n"),
      created: [
        {
          findingId: "finding_0",
          occurrenceId: "occurrence_0",
          issueIdentifier: "EXAMPLE-123",
          url: "https://linear.app/example/issue/EXAMPLE-123",
        },
        {
          findingId: "finding_1",
          occurrenceId: "occurrence_1",
          issueIdentifier: "EXAMPLE-124",
        },
        {
          findingId: "finding_2",
          occurrenceId: "occurrence_2",
          issueIdentifier: "EXAMPLE-125",
        },
      ],
      failed: [],
    });
  });

  test("recognizes the actual dotted connected-app tool event and Linear id-only response", () => {
    const prepared = publication(2);
    const output = [
      JSON.stringify({
        type: "item.completed",
        item: {
          id: "preflight-user",
          type: "mcp_tool_call",
          server: "codex_apps",
          tool: "linear.get_user",
          arguments: { query: "me" },
          result: {
            content: [{ type: "text", text: "Connected Linear user." }],
            structured_content: { id: "user_synthetic" },
          },
          status: "completed",
        },
      }),
      event(prepared, 0, {
        id: "actual-hosted-creation-0",
        tool: "linear.save_issue",
        result: {
          content: [
            { type: "text", text: JSON.stringify({ id: "EXAMPLE-123" }) },
          ],
          structured_content: {
            id: "EXAMPLE-123",
            url: "https://linear.app/example/issue/EXAMPLE-123",
          },
        },
      }),
      event(prepared, 1, {
        id: "actual-hosted-creation-1",
        tool: "linear.save_issue",
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                id: "EXAMPLE-124",
                url: "https://linear.app/example/issue/EXAMPLE-124",
              }),
            },
          ],
          structured_content: null,
        },
      }),
    ].join("\n");

    expect(collectPublicationEvents(output, prepared, "missing")).toEqual({
      completedEvents: output.split("\n").slice(1),
      created: [
        {
          findingId: "finding_0",
          occurrenceId: "occurrence_0",
          issueIdentifier: "EXAMPLE-123",
          url: "https://linear.app/example/issue/EXAMPLE-123",
        },
        {
          findingId: "finding_1",
          occurrenceId: "occurrence_1",
          issueIdentifier: "EXAMPLE-124",
          url: "https://linear.app/example/issue/EXAMPLE-124",
        },
      ],
      failed: [],
    });
  });

  test.each([
    ["unrelated dotted mutation", "linear.update_issue"],
    ["suffix spoof", "linear.save_issue.unverified"],
    ["prefix spoof", "other.linear.save_issue"],
    ["nested function name", "mcp__codex_apps__linear_save_issue"],
  ] as const)("does not trust %s", (_label, tool) => {
    const prepared = publication();
    expect(
      collectPublicationEvents(
        event(prepared, 0, { tool }),
        prepared,
        "not verified",
      ),
    ).toEqual({
      created: [],
      failed: [{ findingId: "finding_0", error: "not verified" }],
    });
  });

  test("does not trust the dotted Linear mutation from another MCP server", () => {
    const prepared = publication();
    expect(
      collectPublicationEvents(
        event(prepared, 0, {
          tool: "linear.save_issue",
          server: "untrusted_apps",
        }),
        prepared,
        "not verified",
      ),
    ).toEqual({
      created: [],
      failed: [{ findingId: "finding_0", error: "not verified" }],
    });
  });

  test.each([
    ["different team", { team: "team_unexpected" }],
    ["different project", { project: "project_unexpected" }],
    ["different title", { title: "Unexpected finding title" }],
    ["different priority", { priority: 1 }],
    ["missing priority", { priority: undefined }],
    ["existing issue id", { id: "EXAMPLE-999" }],
    ["additional argument", { assignee: "synthetic_user" }],
  ] as const)(
    "retains an indeterminate result for a completed Linear mutation with %s",
    (_label, changed) => {
      const prepared = publication();
      const issue = prepared.issues[0]!;
      const output = event(prepared, 0, {
        tool: "linear.save_issue",
        arguments: {
          team: prepared.destination.teamId,
          project: prepared.destination.projectId,
          title: issue.title,
          description: issue.description,
          priority: issue.priority,
          ...changed,
        },
        result: {
          content: [],
          structured_content: { id: "EXAMPLE-123" },
        },
      });

      const result = collectPublicationEvents(output, prepared, "not verified");
      expect(result.created).toEqual([]);
      expect(result.failed).toEqual([
        {
          findingId: "finding_0",
          error:
            "Codex attempted to create a Linear issue with unexpected arguments or destination.",
        },
      ]);
      expect(result.indeterminate).toBe(true);
    },
  );

  test("does not require recovery for a rejected mutation", () => {
    const prepared = publication();
    const result = collectPublicationEvents(
      event(prepared, 0, {
        status: "failed",
        arguments: {
          team: "another-team",
          description: prepared.issues[0]!.description,
        },
      }),
      prepared,
      "not verified",
    );

    expect(result.created).toEqual([]);
    expect(result.failed).toHaveLength(1);
    expect(result.indeterminate).toBeUndefined();
  });

  test("keeps one verified mutation when another attempt is rejected", () => {
    const prepared = publication();
    const completed = event(prepared);
    const rejected = event(prepared, 0, {
      id: "call_retry",
      status: "failed",
      error: { message: "Linear rejected the retry." },
      result: undefined,
    });

    for (const output of [
      `${completed}\n${rejected}`,
      `${rejected}\n${completed}`,
    ]) {
      const result = collectPublicationEvents(output, prepared, "missing");
      expect(result.created[0]?.issueIdentifier).toBe("SEC-1");
      expect(result.failed).toEqual([]);
      expect(result.indeterminate).toBeUndefined();
      expect(result.completedEvents).toEqual([completed]);
    }
  });

  test("accepts team-only informational issues without optional arguments", () => {
    const prepared = publication();
    delete prepared.destination.projectId;
    delete prepared.issues[0]!.priority;

    const result = collectPublicationEvents(
      event(prepared),
      prepared,
      "missing",
    );
    expect(result.created[0]?.issueIdentifier).toBe("SEC-1");
    expect(result.failed).toEqual([]);
    expect(result.indeterminate).toBeUndefined();
  });

  test("does not trust issue ids reported by an agent message or a code-mode wrapper", () => {
    const prepared = publication();
    const issue = prepared.issues[0]!;
    const output = [
      JSON.stringify({
        type: "item.completed",
        item: {
          id: "message",
          type: "agent_message",
          text: JSON.stringify({
            id: "EXAMPLE-FABRICATED",
            title: issue.title,
          }),
        },
      }),
      JSON.stringify({
        type: "response_item",
        payload: {
          type: "custom_tool_call",
          name: "exec",
          call_id: "unverified-wrapper",
          input:
            "await tools.mcp__codex_apps__linear_save_issue(unverifiedArguments)",
        },
      }),
      JSON.stringify({
        type: "response_item",
        payload: {
          type: "custom_tool_call_output",
          call_id: "unverified-wrapper",
          output: [
            {
              type: "input_text",
              text: JSON.stringify({ id: "EXAMPLE-FABRICATED" }),
            },
          ],
        },
      }),
    ].join("\n");

    expect(collectPublicationEvents(output, prepared, "not verified")).toEqual({
      created: [],
      failed: [{ findingId: "finding_0", error: "not verified" }],
    });
  });

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
      indeterminate: true,
      completedEvents: [output],
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
      completedEvents: [output.split("\n")[1]!],
      unresolvedCompletions: ["finding_0"],
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
