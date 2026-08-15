import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  publishScanInternal,
  type PublicationCodexResult,
  type PublishScanDependencies,
  type PublishScanOptions,
  type PublishScanProgress,
} from "../src/publish.js";
import type {
  PreparedPublicationIssue,
  PreparedScanPublication,
} from "../src/publication.js";

const OPTIONS: PublishScanOptions = {
  destination: "linear",
  teamId: "team-example",
  projectId: "project-example",
};
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

function preparedPublication(
  count = 1,
  scanId = "scan-example",
): PreparedScanPublication {
  return {
    scanId,
    uploadId: scanId,
    scanDirectory: join(tmpdir(), "completed-scan"),
    destination: {
      type: "linear",
      teamId: OPTIONS.teamId,
      projectId: OPTIONS.projectId,
    },
    issues: Array.from({ length: count }, (_, index) => ({
      findingId: `finding-${index + 1}`,
      occurrenceId: `occurrence-${index + 1}`,
      title: `[Codex Security][HIGH] Synthetic finding ${index + 1}`,
      description: `Finding ${index + 1}\n\n\`\`\`ts\nunsafe(input)\n\`\`\``,
      priority: 2,
    })),
  };
}

function issueEvent(
  issue: PreparedPublicationIssue,
  options: {
    status?: "completed" | "failed";
    error?: string;
    identifier?: string;
    url?: string;
  } = {},
): string {
  const identifier = options.identifier ?? `SEC-${issue.findingId.slice(8)}`;
  const url = options.url ?? `https://linear.app/example/issue/${identifier}`;
  return JSON.stringify({
    type: "item.completed",
    item: {
      id: `tool-${issue.findingId}`,
      type: "mcp_tool_call",
      server: "codex_apps",
      tool: "linear_save_issue",
      arguments: {
        team: OPTIONS.teamId,
        project: OPTIONS.projectId,
        title: issue.title,
        description: issue.description,
        ...(issue.priority === undefined ? {} : { priority: issue.priority }),
      },
      ...(options.status === "failed"
        ? {
            status: "failed",
            error: { message: options.error ?? "Issue creation failed." },
          }
        : {
            status: "completed",
            result: {
              content: [],
              structured_content: { identifier, url },
            },
          }),
    },
  });
}

function dependencies(
  publication: PreparedScanPublication,
  invocation: Partial<PublicationCodexResult> = {},
  overrides: Partial<PublishScanDependencies> = {},
): PublishScanDependencies {
  const stateDirectory = join(
    tmpdir(),
    `codex-security-publication-test-${randomUUID()}`,
  );
  temporaryDirectories.push(stateDirectory);
  return {
    environment: {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    },
    prepare: async () => publication,
    resolveCodex: () => ({ command: "synthetic-codex" }),
    runCodex: async () => ({
      exitCode: 0,
      stdout: publication.issues.map((issue) => issueEvent(issue)).join("\n"),
      stderr: "",
      ...invocation,
    }),
    preparePublicationStore: async () => undefined,
    recordPublishedIssues: async (_publication, issues) => [...issues],
    writeReceipt: async () => undefined,
    ...overrides,
  };
}

interface PublicationPromptData {
  scanId: string;
  handoffFile: string;
  batches: Array<
    Array<{
      findingId: string;
      occurrenceId: string;
      arguments: Record<string, unknown>;
    }>
  >;
}

function publicationData(input: string): PublicationPromptData {
  const encoded = input
    .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
    .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
  return JSON.parse(encoded) as PublicationPromptData;
}

function handoffRecord(
  publication: PreparedScanPublication,
  issue: PreparedPublicationIssue,
  options: {
    identifier?: string;
    identifierKey?: "issueIdentifier" | "identifier" | "id";
    url?: string;
    error?: string;
  } = {},
): Record<string, unknown> {
  return {
    scanId: publication.scanId,
    findingId: issue.findingId,
    occurrenceId: issue.occurrenceId,
    ...(options.error === undefined
      ? {
          [options.identifierKey ?? "issueIdentifier"]:
            options.identifier ?? `SEC-${issue.findingId.slice(8)}`,
          ...(options.url === undefined ? {} : { url: options.url }),
        }
      : { error: options.error }),
    arguments: {
      team: publication.destination.teamId,
      project: publication.destination.projectId,
      title: issue.title,
      description: issue.description,
      ...(issue.priority === undefined ? {} : { priority: issue.priority }),
    },
  };
}

async function writeHandoff(
  input: string,
  records: readonly (Record<string, unknown> | string)[],
): Promise<void> {
  const { handoffFile } = publicationData(input);
  await appendFile(
    handoffFile,
    `${records
      .map((record) =>
        typeof record === "string" ? record : JSON.stringify(record),
      )
      .join("\n")}\n`,
    "utf8",
  );
}

describe("connected Linear publication", () => {
  test("reuses ambient Codex configuration and streams exact issue data on stdin", async () => {
    const publication = preparedPublication();
    const stateDirectory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-environment-"),
    );
    temporaryDirectories.push(stateDirectory);
    const environment = {
      CODEX_HOME: "/existing/connected-codex-home",
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    };
    let command: string | undefined;
    let args: readonly string[] | undefined;
    let input: string | undefined;
    let inheritedEnvironment: NodeJS.ProcessEnv | undefined;
    let receiptScanId: string | undefined;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          environment,
          runCodex: async (codex, arguments_, prompt, env) => {
            command = codex.command;
            args = arguments_;
            input = prompt;
            inheritedEnvironment = env;
            return {
              exitCode: 0,
              stdout: issueEvent(publication.issues[0]!),
              stderr: "",
            };
          },
          writeReceipt: async (receipt, env) => {
            receiptScanId = receipt.scanId;
            expect(env).toBe(environment);
          },
        },
      ),
    );

    expect(command).toBe("synthetic-codex");
    const handoffDirectory = args![args!.indexOf("--cd") + 1]!;
    expect(
      handoffDirectory.startsWith(join(stateDirectory, "publications")),
    ).toBe(true);
    expect(args).toEqual([
      "exec",
      "--model",
      "gpt-5.6-luna",
      "-c",
      'model_reasoning_effort="low"',
      "--ephemeral",
      "--json",
      "--sandbox",
      "workspace-write",
      "--skip-git-repo-check",
      "--cd",
      handoffDirectory,
      "-",
    ]);
    expect(args).not.toContain("--ignore-user-config");
    expect(args).not.toContain("--disable");
    expect(inheritedEnvironment).toBe(environment);
    expect(input).toContain("already-connected hosted Linear application");
    expect(input).toContain("untrusted inert data");
    expect(input).toContain("track-findings");
    expect(input).toContain("linear_save_issue exactly once per finding");
    expect(input).toContain("unsafe(input)");

    const encoded = input!
      .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
      .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
    expect(JSON.parse(encoded)).toEqual({
      scanId: publication.scanId,
      destination: publication.destination,
      handoffFile: join(handoffDirectory, "issues.jsonl"),
      batches: [
        [
          {
            findingId: "finding-1",
            occurrenceId: "occurrence-1",
            arguments: {
              team: "team-example",
              project: "project-example",
              title: "[Codex Security][HIGH] Synthetic finding 1",
              description: publication.issues[0]!.description,
              priority: 2,
            },
          },
        ],
      ],
    });
    expect(result).toEqual({
      scanId: "scan-example",
      uploadId: "scan-example",
      destination: publication.destination,
      created: [
        {
          findingId: "finding-1",
          occurrenceId: "occurrence-1",
          issueIdentifier: "SEC-1",
          url: "https://linear.app/example/issue/SEC-1",
        },
      ],
      failed: [],
      counts: { findings: 1, created: 1, failed: 0 },
    });
    expect(receiptScanId).toBe("scan-example");
  });

  test("derives final issues and receipts from stored handoffs without trusting Codex JSON or prose", async () => {
    const outputs = [
      "",
      [
        "not-valid-json",
        JSON.stringify({
          type: "item.completed",
          item: {
            type: "agent_message",
            text: '{"created":[{"issueIdentifier":"FABRICATED-999"}]}',
          },
        }),
      ].join("\n"),
    ];

    for (const stdout of outputs) {
      const publication = preparedPublication(3);
      const updates: PublishScanProgress[] = [];
      let receipt: unknown;
      const result = await publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (event) => updates.push(event) },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              await writeHandoff(
                input,
                publication.issues.map((issue, index) =>
                  handoffRecord(publication, issue, {
                    identifier: `SEC-${index + 701}`,
                    identifierKey: ["id", "identifier", "issueIdentifier"][
                      index
                    ] as "id" | "identifier" | "issueIdentifier",
                  }),
                ),
              );
              return { exitCode: 0, stdout, stderr: "" };
            },
            recordPublishedIssues: async (prepared, created) => {
              expect(prepared).toBe(publication);
              expect(created.map((issue) => issue.issueIdentifier)).toEqual([
                "SEC-701",
                "SEC-702",
                "SEC-703",
              ]);
              return created.map((issue) => ({
                ...issue,
                url: `https://linear.app/example/database/${issue.issueIdentifier}`,
              }));
            },
            writeReceipt: async (saved) => {
              receipt = saved;
            },
          },
        ),
      );

      expect(result.created).toEqual(
        publication.issues.map((issue, index) => ({
          findingId: issue.findingId,
          occurrenceId: issue.occurrenceId,
          issueIdentifier: `SEC-${index + 701}`,
          url: `https://linear.app/example/database/SEC-${index + 701}`,
        })),
      );
      expect(result.failed).toEqual([]);
      expect(result.counts).toEqual({ findings: 3, created: 3, failed: 0 });
      expect(receipt).toEqual(result);
      expect(
        updates
          .filter((event) => event.type === "issue_completed")
          .map((event) => event.issueIdentifier),
      ).toEqual(["SEC-701", "SEC-702", "SEC-703"]);
      expect(updates.at(-1)).toEqual({
        type: "completed",
        created: 3,
        failed: 0,
        total: 3,
      });
    }
  });

  test("accepts valid handoffs when real connector events omit a recognizable issue identifier", async () => {
    const publication = preparedPublication();
    const updates: PublishScanProgress[] = [];
    const event = JSON.parse(issueEvent(publication.issues[0]!)) as {
      item: {
        tool: string;
        result: { content: unknown[]; structured_content: unknown };
      };
    };
    event.item.tool = "linear.save_issue";
    event.item.result = {
      content: [],
      structured_content: { nested_connector_response: "unrecognized" },
    };

    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, onProgress: (update) => updates.push(update) },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input, _environment, onEvent) => {
            onEvent?.(event);
            await writeHandoff(input, [
              handoffRecord(publication, publication.issues[0]!, {
                identifier: "SEC-808",
              }),
            ]);
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(result.created[0]!.issueIdentifier).toBe("SEC-808");
    expect(result.failed).toEqual([]);
    expect(
      updates.filter((update) => update.type === "issue_completed"),
    ).toEqual([
      {
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-808",
        completed: 1,
        total: 1,
      },
    ]);
  });

  test("creates deterministic concurrent batches of at most 20 and persists every settled batch", async () => {
    const publication = preparedPublication(41);
    let batchSizes: number[] = [];
    let handoffFile: string | undefined;
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            expect(input).toContain("concurrently with Promise.allSettled");
            expect(input).toContain("Do not search, deduplicate");
            expect(input).toContain("invoke the track-findings skill");
            expect(input.toLowerCase()).not.toContain("sequential");
            const data = publicationData(input);
            batchSizes = data.batches.map((batch) => batch.length);
            handoffFile = data.handoffFile;
            const issues = new Map(
              publication.issues.map((issue) => [issue.findingId, issue]),
            );
            for (const batch of data.batches) {
              await writeHandoff(
                input,
                [...batch]
                  .reverse()
                  .map((entry) =>
                    handoffRecord(publication, issues.get(entry.findingId)!),
                  ),
              );
            }
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(batchSizes).toEqual([20, 20, 1]);
    expect(result.created.map((issue) => issue.findingId)).toEqual(
      publication.issues.map((issue) => issue.findingId),
    );
    expect(result.counts).toEqual({ findings: 41, created: 41, failed: 0 });
    expect(await readFile(handoffFile!, "utf8").catch(() => null)).toBeNull();
  });

  test("preserves valid handoffs while reporting failed, missing, and malformed finding records", async () => {
    const publication = preparedPublication(4);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            await writeHandoff(input, [
              handoffRecord(publication, publication.issues[0]!),
              handoffRecord(publication, publication.issues[1]!, {
                error: "The connected project rejected this finding.",
              }),
              "{malformed-json",
              handoffRecord(publication, publication.issues[3]!),
            ]);
            return { exitCode: 0, stdout: "invalid", stderr: "" };
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.findingId)).toEqual([
      "finding-1",
      "finding-4",
    ]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-2",
        error: "The connected project rejected this finding.",
      },
      {
        findingId: "finding-3",
        error: "Codex wrote an invalid Linear publication handoff.",
      },
    ]);
    expect(result.counts).toEqual({ findings: 4, created: 2, failed: 2 });
  });

  test("never discards valid created issues because of unrelated trailing handoff noise", async () => {
    const publication = preparedPublication(2);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            await writeHandoff(input, [
              ...publication.issues.map((issue) =>
                handoffRecord(publication, issue),
              ),
              "{truncated-trailing-line",
              { findingId: "unrelated-finding" },
            ]);
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.issueIdentifier)).toEqual([
      "SEC-1",
      "SEC-2",
    ]);
    expect(result.failed).toEqual([]);
  });

  test("salvages verified issue events missing from a partial handoff without overriding explicit failures", async () => {
    const publication = preparedPublication(3);
    let recovered: string | undefined;
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            const first = publication.issues[0]!;
            const second = publication.issues[1]!;
            const third = publication.issues[2]!;
            await writeHandoff(input, [
              handoffRecord(publication, first),
              handoffRecord(publication, third, {
                error: "The handoff explicitly rejected this finding.",
              }),
            ]);
            recovered = publicationData(input).handoffFile;
            return {
              exitCode: 0,
              stdout: [issueEvent(second), issueEvent(third)].join("\n"),
              stderr: "",
            };
          },
          recordPublishedIssues: async (_prepared, created) => {
            const records = (await readFile(recovered!, "utf8"))
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(records.map((record) => record["findingId"])).toEqual([
              "finding-1",
              "finding-3",
              "finding-2",
            ]);
            expect(records[2]!["issueIdentifier"]).toBe("SEC-2");
            return [...created];
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.findingId)).toEqual([
      "finding-1",
      "finding-2",
    ]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-3",
        error: "The handoff explicitly rejected this finding.",
      },
    ]);
  });

  test("retains both written and salvaged issue mappings if the publication database fails", async () => {
    const publication = preparedPublication(2);
    let handoffFile: string | undefined;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-RECOVERABLE",
                }),
              ]);
              return {
                exitCode: 0,
                stdout: issueEvent(publication.issues[1]!),
                stderr: "",
              };
            },
            recordPublishedIssues: async () => {
              throw new Error(
                "The local publication database is temporarily unavailable.",
              );
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /temporarily unavailable.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    const records = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      records.map((record) => [record["findingId"], record["issueIdentifier"]]),
    ).toEqual([
      ["finding-1", "SEC-RECOVERABLE"],
      ["finding-2", "SEC-2"],
    ]);
  });

  test("rejects mismatched destinations, payloads, duplicate findings, and cross-scan handoffs", async () => {
    const scenarios: Array<{
      name: string;
      mutate: (record: Record<string, unknown>) => Record<string, unknown>[];
    }> = [
      {
        name: "another scan",
        mutate: (record) => [{ ...record, scanId: "another-scan" }],
      },
      {
        name: "another occurrence",
        mutate: (record) => [{ ...record, occurrenceId: "another-occurrence" }],
      },
      ...["team", "project", "title", "description", "priority"].map((key) => ({
        name: `unexpected ${key}`,
        mutate: (record: Record<string, unknown>) => [
          {
            ...record,
            arguments: {
              ...(record["arguments"] as Record<string, unknown>),
              [key]: key === "priority" ? 4 : `unexpected-${key}`,
            },
          },
        ],
      })),
      {
        name: "an additional Linear argument",
        mutate: (record) => [
          {
            ...record,
            arguments: {
              ...(record["arguments"] as Record<string, unknown>),
              id: "existing-issue",
            },
          },
        ],
      },
      {
        name: "an additional handoff field",
        mutate: (record) => [{ ...record, untrusted: true }],
      },
      {
        name: "duplicate finding records",
        mutate: (record) => [record, record],
      },
      {
        name: "an unexpected finding",
        mutate: (record) => [{ ...record, findingId: "another-finding" }],
      },
    ];

    for (const scenario of scenarios) {
      const publication = preparedPublication();
      let persisted = false;
      const result = await publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              await writeHandoff(
                input,
                scenario.mutate(
                  handoffRecord(publication, publication.issues[0]!),
                ),
              );
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, created) => {
              persisted = true;
              return [...created];
            },
          },
        ),
      );

      expect(result.created, scenario.name).toEqual([]);
      expect(result.failed, scenario.name).toHaveLength(1);
      expect(result.failed[0]!.findingId, scenario.name).toBe("finding-1");
      expect(persisted, scenario.name).toBe(false);
    }
  });

  test("rejects handoffs contradicted by observed trusted Linear mutations", async () => {
    const scenarios: Array<{
      name: string;
      events: (publication: PreparedScanPublication) => string[];
    }> = [
      {
        name: "unexpected destination",
        events: (publication) => {
          const event = JSON.parse(issueEvent(publication.issues[0]!)) as {
            item: { arguments: Record<string, unknown> };
          };
          event.item.arguments["team"] = "unexpected-team";
          return [JSON.stringify(event)];
        },
      },
      {
        name: "different created issue",
        events: (publication) => [
          issueEvent(publication.issues[0]!, { identifier: "SEC-OTHER" }),
        ],
      },
      {
        name: "failed connector call",
        events: (publication) => [
          issueEvent(publication.issues[0]!, {
            status: "failed",
            error: "The connected Linear project denied this request.",
          }),
        ],
      },
      {
        name: "duplicate connector calls",
        events: (publication) => [
          issueEvent(publication.issues[0]!),
          issueEvent(publication.issues[0]!),
        ],
      },
    ];

    for (const scenario of scenarios) {
      const publication = preparedPublication();
      const result = await publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!),
              ]);
              return {
                exitCode: 0,
                stdout: scenario.events(publication).join("\n"),
                stderr: "",
              };
            },
          },
        ),
      );

      expect(result.created, scenario.name).toEqual([]);
      expect(result.failed, scenario.name).toHaveLength(1);
    }
  });

  test("verifies the existing publication database before starting Codex or creating issues", async () => {
    const publication = preparedPublication();
    let resolved = false;
    let started = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          {},
          {
            preparePublicationStore: async () => {
              throw new Error(
                "The local scan history does not contain this finding.",
              );
            },
            resolveCodex: () => {
              resolved = true;
              return { command: "must-not-run" };
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
          },
        ),
      ),
    ).rejects.toThrow("local scan history does not contain this finding");

    expect(resolved).toBe(false);
    expect(started).toBe(false);
  });

  test("previews every finding without starting Codex or writing a receipt", async () => {
    const publication = preparedPublication(2);
    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, dryRun: true },
      dependencies(
        publication,
        {},
        {
          resolveCodex: () => {
            throw new Error("dry runs must not resolve Codex");
          },
          runCodex: async () => {
            throw new Error("dry runs must not start Codex");
          },
          writeReceipt: async () => {
            throw new Error("dry runs must not write receipts");
          },
        },
      ),
    );

    expect(result).toEqual({
      scanId: "scan-example",
      uploadId: "scan-example",
      destination: publication.destination,
      created: [],
      failed: [],
      counts: { findings: 2, created: 0, failed: 0 },
      dryRun: true,
      issues: publication.issues,
    });
  });

  test("streams dotted Linear events, ordered progress, and a partial-publication receipt", async () => {
    const directory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-stream-"),
    );
    temporaryDirectories.push(directory);
    const publication = preparedPublication(3);
    const preload = join(directory, "codex-preload.cjs");
    await writeFile(
      preload,
      [
        'const fs = require("node:fs");',
        'const prompt = fs.readFileSync(0, "utf8");',
        'if (!prompt.includes("BEGIN UNTRUSTED PUBLICATION DATA")) process.exit(2);',
        "const lines = JSON.parse(process.env.CODEX_PUBLICATION_TEST_EVENTS);",
        'fs.writeSync(1, "not-json\\n");',
        "const first = JSON.stringify(lines[0]);",
        "const boundary = Math.floor(first.length / 2);",
        "fs.writeSync(1, first.slice(0, boundary));",
        "fs.writeSync(1, `${first.slice(boundary)}\\r\\n`);",
        "fs.writeSync(1, `${JSON.stringify(lines[1])}\\n`);",
        "fs.writeSync(1, `${JSON.stringify(lines[2])}\\n`);",
        "fs.writeSync(1, JSON.stringify(lines[3]));",
        "process.exit(0);",
      ].join("\n"),
      "utf8",
    );
    const reasoning = {
      type: "item.completed",
      item: { type: "reasoning", text: "Creating the requested issue." },
    };
    const issues = publication.issues.slice(0, 2).map((finding, index) => {
      const issue = JSON.parse(issueEvent(finding)) as {
        item: {
          tool: string;
          result: {
            content: unknown[];
            structured_content: { id: string; url: string };
          };
        };
      };
      const identifier = `SEC-${index + 901}`;
      issue.item.tool = "linear.save_issue";
      issue.item.result = {
        content: [],
        structured_content: {
          id: identifier,
          url: `https://linear.app/example/issue/${identifier}`,
        },
      };
      return issue;
    });
    const failure = JSON.parse(
      issueEvent(publication.issues[2]!, {
        status: "failed",
        error: "The connected Linear project rejected this finding.",
      }),
    ) as { item: { tool: string } };
    failure.item.tool = "linear.save_issue";
    const updates: PublishScanProgress[] = [];
    const injected = dependencies(
      publication,
      {},
      {
        environment: {
          ...process.env,
          CODEX_SECURITY_STATE_DIR: join(directory, "state"),
          NODE_OPTIONS: `--require=${JSON.stringify(preload)}`,
          CODEX_PUBLICATION_TEST_EVENTS: JSON.stringify([
            reasoning,
            ...issues,
            failure,
          ]),
        },
        resolveCodex: () => ({
          command: execFileSync("node", ["-p", "process.execPath"], {
            encoding: "utf8",
          }).trim(),
        }),
      },
    );
    delete injected.runCodex;
    delete injected.writeReceipt;

    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, onProgress: (event) => updates.push(event) },
      injected,
    );

    expect(result.created).toEqual([
      {
        findingId: "finding-1",
        occurrenceId: "occurrence-1",
        issueIdentifier: "SEC-901",
        url: "https://linear.app/example/issue/SEC-901",
      },
      {
        findingId: "finding-2",
        occurrenceId: "occurrence-2",
        issueIdentifier: "SEC-902",
        url: "https://linear.app/example/issue/SEC-902",
      },
    ]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-3",
        error: "The connected Linear project rejected this finding.",
      },
    ]);
    expect(result.counts).toEqual({ findings: 3, created: 2, failed: 1 });
    expect(updates).toEqual([
      { type: "started", scanId: "scan-example", total: 3 },
      { type: "codex_event", event: reasoning },
      { type: "codex_event", event: issues[0] },
      {
        type: "issue_completed",
        findingId: "finding-1",
        issueIdentifier: "SEC-901",
        completed: 1,
        total: 3,
      },
      { type: "codex_event", event: issues[1] },
      {
        type: "issue_completed",
        findingId: "finding-2",
        issueIdentifier: "SEC-902",
        completed: 2,
        total: 3,
      },
      { type: "codex_event", event: failure },
      {
        type: "issue_completed",
        findingId: "finding-3",
        error: "The connected Linear project rejected this finding.",
        completed: 3,
        total: 3,
      },
      { type: "completed", created: 2, failed: 1, total: 3 },
    ]);
    const receipt = join(
      directory,
      "state",
      "publications",
      "linear",
      `${createHash("sha256").update(publication.scanId).digest("hex")}.json`,
    );
    expect(JSON.parse(await readFile(receipt, "utf8"))).toEqual(result);
  });

  test("never reports an issue for unverified destinations or repeated tool events", async () => {
    const publication = preparedPublication();
    const updates: PublishScanProgress[] = [];
    const unexpected = JSON.parse(issueEvent(publication.issues[0]!)) as Record<
      string,
      unknown
    >;
    const item = unexpected["item"] as Record<string, unknown>;
    const args = item["arguments"] as Record<string, unknown>;
    args["team"] = "another-team";
    const valid = JSON.parse(issueEvent(publication.issues[0]!)) as unknown;

    await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, onProgress: (event) => updates.push(event) },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_codex, _args, _input, _environment, onEvent) => {
            onEvent!(unexpected);
            expect(updates.at(-1)).toEqual({
              type: "codex_event",
              event: unexpected,
            });
            onEvent!(valid);
            onEvent!(valid);
            return {
              exitCode: 0,
              stdout: JSON.stringify(valid),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(updates.filter((event) => event.type === "issue_completed")).toEqual(
      [
        {
          type: "issue_completed",
          findingId: "finding-1",
          issueIdentifier: "SEC-1",
          completed: 1,
          total: 1,
        },
      ],
    );
  });

  test("does not allow a failing progress observer to stop issue publication", async () => {
    const publication = preparedPublication();
    let observations = 0;
    const result = await publishScanInternal(
      publication.scanDirectory,
      {
        ...OPTIONS,
        onProgress: () => {
          observations += 1;
          throw new Error("The optional progress display failed.");
        },
      },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_codex, _args, _input, _environment, onEvent) => {
            const event = JSON.parse(
              issueEvent(publication.issues[0]!),
            ) as unknown;
            onEvent!(event);
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 1, created: 1, failed: 0 });
    expect(observations).toBe(4);
  });

  test("does not start Codex or write a receipt when the scan has no findings", async () => {
    const publication = preparedPublication(0);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          resolveCodex: () => {
            throw new Error("empty scans must not resolve Codex");
          },
          writeReceipt: async () => {
            throw new Error("empty scans must not write receipts");
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 0, created: 0, failed: 0 });
  });

  test("preserves successful issues when another creation fails", async () => {
    const publication = preparedPublication(3);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(publication, {
        stdout: [
          issueEvent(publication.issues[0]!),
          issueEvent(publication.issues[1]!, {
            status: "failed",
            error: "The destination rejected this issue.",
          }),
        ].join("\n"),
      }),
    );

    expect(result.created).toHaveLength(1);
    expect(result.failed).toEqual([
      {
        findingId: "finding-2",
        error: "The destination rejected this issue.",
      },
      {
        findingId: "finding-3",
        error: "Codex did not create a Linear issue for this finding.",
      },
    ]);
    expect(result.counts).toEqual({ findings: 3, created: 1, failed: 2 });
  });

  test("reports Codex and connected-app failures without invented issue creation", async () => {
    const publication = preparedPublication();
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(publication, {
        exitCode: 1,
        stdout: "",
        stderr: "Linear is not connected.",
      }),
    );

    expect(result.created).toEqual([]);
    expect(result.failed).toEqual([
      {
        findingId: "finding-1",
        error:
          "Codex could not publish through the connected Linear app: Linear is not connected.",
      },
    ]);
  });

  test("creates a fresh issue on every publication without deduplicating", async () => {
    const publication = preparedPublication();
    let calls = 0;
    const injected = dependencies(
      publication,
      {},
      {
        runCodex: async () => {
          calls += 1;
          return {
            exitCode: 0,
            stdout: issueEvent(publication.issues[0]!, {
              identifier: `SEC-${calls}`,
            }),
            stderr: "",
          };
        },
      },
    );

    const first = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      injected,
    );
    const second = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      injected,
    );

    expect(calls).toBe(2);
    expect(first.uploadId).toBe(second.uploadId);
    expect(first.created[0]!.issueIdentifier).toBe("SEC-1");
    expect(second.created[0]!.issueIdentifier).toBe("SEC-2");
  });

  test("keeps publication receipts outside sealed scans and hashes unsafe scan IDs", async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), "codex-security-publication-receipt-"),
    );
    temporaryDirectories.push(stateDirectory);
    const publication = preparedPublication(1, "../../outside/scan");
    const injected = dependencies(
      publication,
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
      },
    );
    delete injected.writeReceipt;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      injected,
    );
    const digest = createHash("sha256")
      .update("../../outside/scan")
      .digest("hex");
    const receipt = join(
      stateDirectory,
      "publications",
      "linear",
      `${digest}.json`,
    );

    expect(JSON.parse(await readFile(receipt, "utf8"))).toEqual(result);
  });

  test("requires an exact destination, team, and project before reading a scan", async () => {
    const publication = preparedPublication();
    for (const options of [
      { ...OPTIONS, destination: "azure" } as unknown as PublishScanOptions,
      { ...OPTIONS, teamId: "  " },
      { ...OPTIONS, projectId: "  " },
    ]) {
      await expect(
        publishScanInternal(
          publication.scanDirectory,
          options,
          dependencies(
            publication,
            {},
            {
              prepare: async () => {
                throw new Error("invalid destinations must not load scans");
              },
            },
          ),
        ),
      ).rejects.toThrow();
    }
  });
});
