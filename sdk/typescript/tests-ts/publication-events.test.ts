import { describe, expect, test } from "bun:test";
import {
  collectPublicationEvents,
  matchPublicationIssue,
  resolvePublicationClaims,
} from "../src/publication-events.js";
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
  overrides: {
    arguments?: Record<string, unknown>;
    error?: string;
    result?: unknown;
    server?: string;
    status?: "completed" | "failed";
    tool?: string;
  } = {},
): string {
  const issue = prepared.issues[index]!;
  return JSON.stringify({
    type: "item.completed",
    item: {
      id: `call_${index}`,
      type: "mcp_tool_call",
      server: overrides.server ?? "codex_apps",
      tool: overrides.tool ?? "linear.save_issue",
      status: overrides.status ?? "completed",
      arguments: overrides.arguments ?? {
        team: prepared.destination.teamId,
        project: prepared.destination.projectId,
        title: issue.title,
        description: issue.description,
        priority: issue.priority,
      },
      ...(overrides.status === "failed"
        ? { error: { message: overrides.error ?? "Linear rejected it." } }
        : {
            result:
              overrides.result ??
              ({
                structured_content: {
                  identifier: `SEC-${index + 1}`,
                  url: `https://linear.app/example/issue/SEC-${index + 1}`,
                },
                content: [],
              } satisfies Record<string, unknown>),
          }),
    },
  });
}

describe("Linear publication claim resolution", () => {
  const entityId = "11111111-2222-4333-8444-555555555555";
  const alternateEntityId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
  const identifier = "SYNTH-501";
  const url = `https://linear.app/example/issue/${identifier}`;
  const resolved = (
    claims: ReturnType<typeof resolvePublicationClaims>["claims"],
    issueIdentifier = identifier,
    resolvedUrl?: string,
  ): ReturnType<typeof resolvePublicationClaims> => ({
    state: "resolved",
    claims,
    issueIdentifier,
    ...(resolvedUrl === undefined ? {} : { url: resolvedUrl }),
  });

  const cases: Array<
    [string, unknown, ReturnType<typeof resolvePublicationClaims>]
  > = [
    [
      "older id/key result",
      { id: entityId, key: identifier, url },
      resolved(
        [
          { kind: "identifier", value: identifier },
          { kind: "entityId", value: entityId },
          { kind: "url", value: url },
        ],
        identifier,
        url,
      ),
    ],
    [
      "current id-only human key",
      { id: identifier },
      resolved([{ kind: "identifier", value: identifier }]),
    ],
    [
      "rich nested result",
      {
        id: entityId,
        structured_content: { data: { issue: { identifier, url } } },
      },
      resolved(
        [
          { kind: "identifier", value: identifier },
          { kind: "entityId", value: entityId },
          { kind: "url", value: url },
        ],
        identifier,
        url,
      ),
    ],
    [
      "UUID aliases and surrounding whitespace",
      {
        id: ` ${entityId.toUpperCase()} `,
        issueIdentifier: `\n${entityId}\t`,
      },
      {
        state: "absent",
        claims: [{ kind: "entityId", value: entityId }],
      },
    ],
    [
      "human issue-key case remains semantic",
      {
        identifier,
        structured_content: { identifier: identifier.toLowerCase() },
      },
      {
        state: "conflicting",
        claims: [
          { kind: "identifier", value: identifier },
          { kind: "identifier", value: identifier.toLowerCase() },
        ],
      },
    ],
    [
      "whitespace-normalized rich result",
      {
        id: ` ${entityId}\n`,
        key: `\t${identifier} `,
        url: ` ${url}\n`,
      },
      resolved(
        [
          { kind: "identifier", value: identifier },
          { kind: "entityId", value: entityId },
          { kind: "url", value: url },
        ],
        identifier,
        url,
      ),
    ],
    [
      "equivalent Linear URL spellings",
      {
        identifier,
        url,
        structured_content: { url: `${url}/` },
        issue: { url: `${url}/synthetic-title/` },
      },
      resolved(
        [
          { kind: "identifier", value: identifier },
          { kind: "url", value: url },
          { kind: "url", value: `${url}/` },
          { kind: "url", value: `${url}/synthetic-title/` },
        ],
        identifier,
        url,
      ),
    ],
    [
      "different Linear workspaces",
      {
        identifier,
        url,
        issue: { url: `https://linear.app/another/issue/${identifier}` },
      },
      {
        state: "conflicting",
        claims: [
          { kind: "identifier", value: identifier },
          {
            kind: "url",
            value: `https://linear.app/another/issue/${identifier}`,
          },
          { kind: "url", value: url },
        ],
      },
    ],
    [
      "URL and human key contradiction",
      {
        issueIdentifier: "SYNTH-502",
        url,
      },
      {
        state: "conflicting",
        claims: [
          { kind: "identifier", value: "SYNTH-502" },
          { kind: "url", value: url },
        ],
      },
    ],
    [
      "opaque entity relabeled as a human key",
      {
        id: "synthetic-opaque-entity",
        issueIdentifier: "synthetic-opaque-entity",
      },
      {
        state: "conflicting",
        claims: [
          { kind: "identifier", value: "synthetic-opaque-entity" },
          { kind: "entityId", value: "synthetic-opaque-entity" },
        ],
      },
    ],
    [
      "conflicting entity IDs",
      {
        identifier,
        id: entityId,
        structuredContent: { issue: { id: alternateEntityId } },
      },
      {
        state: "conflicting",
        claims: [
          { kind: "identifier", value: identifier },
          { kind: "entityId", value: entityId },
          { kind: "entityId", value: alternateEntityId },
        ],
      },
    ],
    [
      "equal claims across every carrier",
      {
        id: entityId,
        identifier,
        url,
        structured_content: {
          issue: { id: entityId, issueIdentifier: identifier, url },
        },
        content: [
          {
            type: "text",
            text: JSON.stringify({ data: { issue: { id: identifier, url } } }),
          },
        ],
      },
      resolved(
        [
          { kind: "identifier", value: identifier },
          { kind: "entityId", value: entityId },
          { kind: "url", value: url },
        ],
        identifier,
        url,
      ),
    ],
    [
      "non-issue key",
      { key: "SYNTH-NOT-A-NUMBER" },
      { state: "absent", claims: [] },
    ],
    [
      "URL-only evidence",
      { content: [{ type: "text", text: JSON.stringify({ issue: { url } }) }] },
      { state: "absent", claims: [{ kind: "url", value: url }] },
    ],
  ];

  test.each(cases)("%s", (_name, value, expected) => {
    expect(resolvePublicationClaims(value)).toEqual(expected);
  });

  test.each([
    ["root", { identifier }],
    ["structured", { structured_content: { issueIdentifier: identifier } }],
    [
      "structured alias",
      { structuredContent: { data: { issue: { id: identifier } } } },
    ],
    [
      "JSON text",
      {
        content: [
          {
            type: "text",
            text: JSON.stringify({ issue: { identifier } }),
          },
        ],
      },
    ],
  ] as const)(
    "resolves the same human key from the %s carrier",
    (_name, value) => {
      expect(resolvePublicationClaims(value)).toEqual(
        resolved([{ kind: "identifier", value: identifier }]),
      );
    },
  );
});

describe("Linear publication event evidence", () => {
  test("normalizes completed, unknown-owner, wrong-argument, and failed calls in order", () => {
    const prepared = publication(2);
    const exact = event(prepared, 0);
    const unknown = event(prepared, 0, {
      arguments: { description: "No publication identity" },
      result: { identifier: "SYNTH-UNKNOWN" },
    });
    const issue = prepared.issues[1]!;
    const wrongArguments = event(prepared, 1, {
      arguments: {
        team: "team_unexpected",
        project: prepared.destination.projectId,
        title: issue.title,
        description: issue.description,
        priority: issue.priority,
      },
      result: {
        structured_content: {
          url: "https://linear.app/example/issue/SYNTH-RESERVED",
        },
      },
    });
    const rejected = event(prepared, 1, {
      status: "failed",
      error: "Linear rejected the retry.",
    });

    expect(
      collectPublicationEvents(
        [exact, unknown, wrongArguments, rejected].join("\n"),
        prepared,
        "missing",
      ),
    ).toEqual([
      {
        source: "event",
        status: "completed",
        rawLine: exact,
        ownerFindingId: "finding_0",
        argumentsValid: true,
        resolution: {
          state: "resolved",
          issueIdentifier: "SEC-1",
          url: "https://linear.app/example/issue/SEC-1",
          claims: [
            { kind: "identifier", value: "SEC-1" },
            {
              kind: "url",
              value: "https://linear.app/example/issue/SEC-1",
            },
          ],
        },
      },
      {
        source: "event",
        status: "completed",
        rawLine: unknown,
        argumentsValid: false,
        resolution: {
          state: "resolved",
          issueIdentifier: "SYNTH-UNKNOWN",
          claims: [{ kind: "identifier", value: "SYNTH-UNKNOWN" }],
        },
      },
      {
        source: "event",
        status: "completed",
        rawLine: wrongArguments,
        ownerFindingId: "finding_1",
        argumentsValid: false,
        resolution: {
          state: "absent",
          claims: [
            {
              kind: "url",
              value: "https://linear.app/example/issue/SYNTH-RESERVED",
            },
          ],
        },
      },
      {
        source: "event",
        status: "failed",
        rawLine: rejected,
        ownerFindingId: "finding_1",
        argumentsValid: true,
        resolution: { state: "absent", claims: [] },
        error: "Linear rejected the retry.",
      },
    ]);
  });

  test.each([
    [
      "identifier",
      { structured_content: { identifier: "SYNTH-FAILED" } },
      {
        state: "resolved",
        issueIdentifier: "SYNTH-FAILED",
        claims: [{ kind: "identifier", value: "SYNTH-FAILED" }],
      },
    ],
    [
      "URL",
      {
        structured_content: {
          url: "https://linear.app/example/issue/SYNTH-FAILED",
        },
      },
      {
        state: "absent",
        claims: [
          {
            kind: "url",
            value: "https://linear.app/example/issue/SYNTH-FAILED",
          },
        ],
      },
    ],
  ] as const)(
    "retains %s claims from a failed result without an error",
    (_name, result, resolution) => {
      const prepared = publication();
      const terminal = JSON.parse(event(prepared, 0, { status: "failed" })) as {
        item: Record<string, unknown>;
      };
      delete terminal.item["error"];
      terminal.item["result"] = result;
      const rawLine = JSON.stringify(terminal);

      expect(
        collectPublicationEvents(rawLine, prepared, "Synthetic failure."),
      ).toEqual([
        {
          source: "event",
          status: "failed",
          rawLine,
          ownerFindingId: "finding_0",
          argumentsValid: true,
          resolution: {
            ...resolution,
            claims: resolution.claims.map((claim) => ({ ...claim })),
          },
          error: "Synthetic failure.",
        },
      ]);
    },
  );

  test.each([
    ["dotted", "linear.save_issue"],
    ["legacy", "linear_save_issue"],
  ] as const)("recognizes the %s tool name", (_name, tool) => {
    const prepared = publication();
    expect(
      collectPublicationEvents(
        event(prepared, 0, { tool }),
        prepared,
        "missing",
      ),
    ).toHaveLength(1);
  });

  test.each([
    ["unrelated tool", { tool: "linear.update_issue" }],
    ["spoofed suffix", { tool: "linear.save_issue.unverified" }],
    ["wrong server", { server: "untrusted_apps" }],
  ] as const)("ignores %s", (_name, overrides) => {
    const prepared = publication();
    expect(
      collectPublicationEvents(
        event(prepared, 0, overrides),
        prepared,
        "missing",
      ),
    ).toEqual([]);
  });

  test("retains both completed calls and their raw order", () => {
    const prepared = publication();
    const absent = event(prepared, 0, {
      result: { structured_content: { title: "No identifier" } },
    });
    const resolved = event(prepared, 0, {
      result: { structured_content: { identifier: "SYNTH-DUPLICATE" } },
    });
    const evidence = collectPublicationEvents(
      `${absent}\n${resolved}`,
      prepared,
      "missing",
    );
    expect(evidence.map((item) => item.rawLine)).toEqual([absent, resolved]);
    expect(evidence.map((item) => item.status)).toEqual([
      "completed",
      "completed",
    ]);
  });

  test("matches unique exact arguments before incidental sibling identifiers", () => {
    const prepared = publication(2);
    const [first, sibling] = prepared.issues;
    first!.description += `\nRepository text: ${sibling!.findingId} ${sibling!.occurrenceId}`;
    const rawLine = event(prepared, 0);
    const completed = JSON.parse(rawLine) as {
      item: { arguments: Record<string, unknown> };
    };

    expect(matchPublicationIssue(prepared, completed.item.arguments)).toBe(
      first,
    );
    expect(
      collectPublicationEvents(rawLine, prepared, "missing"),
    ).toMatchObject([
      {
        ownerFindingId: first!.findingId,
        argumentsValid: true,
      },
    ]);
  });

  test("matches finding and occurrence identifiers only at token boundaries", () => {
    const prepared = publication(2);
    const first = prepared.issues[0]!;
    expect(
      matchPublicationIssue(prepared, { description: first.description }),
    ).toBe(first);
    for (const description of [
      first.findingId,
      first.occurrenceId,
      `${first.findingId}-suffix ${first.occurrenceId}`,
      `${first.findingId} ${first.occurrenceId} finding_1 occurrence_1`,
    ]) {
      expect(matchPublicationIssue(prepared, { description })).toBeUndefined();
    }
  });
});
