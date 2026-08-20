import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  appendFile,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
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
      description: [
        `**Finding ID:** finding-${index + 1}`,
        `**Occurrence ID:** occurrence-${index + 1}`,
        "",
        `Finding ${index + 1}`,
        "",
        "```ts",
        "unsafe(input)",
        "```",
      ].join("\n"),
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

type LinearClient = ReturnType<
  NonNullable<PublishScanDependencies["linearClient"]>
>;
type LinearIssueInput = Parameters<LinearClient["createIssue"]>[0];

function linearApiClient(
  publication: PreparedScanPublication,
  options: {
    configured?: (apiKey: string) => void;
    create?: (
      input: LinearIssueInput,
      signal: AbortSignal | null | undefined,
    ) => Promise<void> | void;
  } = {},
): NonNullable<PublishScanDependencies["linearClient"]> {
  return ({ apiKey, signal, redirect }) => {
    expect(redirect).toBe("error");
    options.configured?.(apiKey ?? "");
    return {
      users: async () => ({ nodes: [{ id: "assignee-from-email" }] }),
      createIssue: async (input: LinearIssueInput) => {
        await options.create?.(input, signal);
        const index = publication.issues.findIndex(
          ({ title }) => title === input.title,
        );
        const identifier = `SEC-${index + 1}`;
        return {
          success: true,
          issue: Promise.resolve({
            identifier,
            url: `https://linear.app/example/issue/${identifier}`,
          }),
        };
      },
    } as unknown as LinearClient;
  };
}

interface PublicationPromptData {
  scanId: string;
  handoffFile: string;
  publicationFile: string;
  batches: Array<
    Array<{
      findingId: string;
      occurrenceId: string;
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
      ...(publication.destination.projectId === undefined
        ? {}
        : { project: publication.destination.projectId }),
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

async function processHasExited(pid: number): Promise<boolean> {
  if (!Number.isSafeInteger(pid) || pid < 1) return false;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ESRCH") return true;
      throw error;
    }
    if (process.platform === "linux") {
      const state = await readFile(`/proc/${pid}/stat`, "utf8").catch(
        () => undefined,
      );
      if (state === undefined || /\) Z /u.test(state)) return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return false;
}

describe("direct Linear API publication", () => {
  test("leaves issues unassigned unless an email or user ID is selected", async () => {
    for (const scenario of [
      { requested: undefined, assigned: undefined, teamOnly: false },
      {
        requested: "teammate@example.test",
        assigned: "assignee-from-email",
        teamOnly: true,
      },
      { requested: "user-123", assigned: "user-123", teamOnly: false },
    ]) {
      const publication = preparedPublication();
      if (scenario.teamOnly) delete publication.destination.projectId;
      const inputs: LinearIssueInput[] = [];
      let configuredKey = "";
      const injected = dependencies(
        publication,
        {},
        {
          linearClient: linearApiClient(publication, {
            configured: (key) => {
              configuredKey = key;
            },
            create: (input) => {
              inputs.push(input);
            },
          }),
          resolveCodex: () => {
            throw new Error("Direct publication must not start Codex.");
          },
        },
      );
      injected.environment!["CODEX_SECURITY_LINEAR_API_KEY"] =
        "environment-key";
      const result = await publishScanInternal(
        publication.scanDirectory,
        {
          destination: "linear",
          teamId: OPTIONS.teamId,
          ...(scenario.teamOnly ? {} : { projectId: OPTIONS.projectId }),
          ...(scenario.requested === undefined
            ? {}
            : { linearApiKey: "explicit-key", assigneeId: scenario.requested }),
        },
        injected,
      );

      expect(configuredKey).toBe(
        scenario.requested === undefined ? "environment-key" : "explicit-key",
      );
      expect(inputs).toEqual([
        {
          teamId: OPTIONS.teamId,
          ...(scenario.teamOnly ? {} : { projectId: OPTIONS.projectId }),
          title: publication.issues[0]!.title,
          description: publication.issues[0]!.description,
          priority: 2,
          ...(scenario.assigned === undefined
            ? {}
            : { assigneeId: scenario.assigned }),
        },
      ]);
      if (scenario.assigned === undefined) {
        expect(inputs[0]).not.toHaveProperty("assigneeId");
      }
      expect(result.counts).toEqual({ findings: 1, created: 1, failed: 0 });
    }
  });

  test("completes direct batches before continuing and preserves individual failures", async () => {
    const publication = preparedPublication(23);
    let started = 0;
    let completed = 0;
    let releaseFirstBatch: (() => void) | undefined;
    const firstBatchStarted = new Promise<void>((resolve) => {
      releaseFirstBatch = resolve;
    });
    const result = await publishScanInternal(
      publication.scanDirectory,
      { ...OPTIONS, linearApiKey: "synthetic-key" },
      dependencies(
        publication,
        {},
        {
          linearClient: linearApiClient(publication, {
            create: async (input) => {
              const index = publication.issues.findIndex(
                ({ title }) => title === input.title,
              );
              started += 1;
              if (started === 20) releaseFirstBatch?.();
              if (index < 20) await firstBatchStarted;
              else expect(completed).toBeGreaterThanOrEqual(20);
              completed += 1;
              if (index === 21)
                throw new Error("Linear rejected this finding.");
            },
          }),
        },
      ),
    );

    expect(started).toBe(23);
    expect(result.counts).toEqual({ findings: 23, created: 22, failed: 1 });
    expect(result.failed).toEqual([
      { findingId: "finding-22", error: "Linear rejected this finding." },
    ]);
  });

  test("recovers completed direct issues before honoring cancellation", async () => {
    const publication = preparedPublication(23);
    const controller = new AbortController();
    let started = 0;
    let stopped = 0;
    let persisted: string[] = [];
    let receipt: unknown;
    const injected = dependencies(
      publication,
      {},
      {
        linearClient: linearApiClient(publication, {
          create: async (input, signal) => {
            started += 1;
            if (input.title === publication.issues[0]!.title) return;
            await new Promise<void>((_resolve, reject) => {
              signal?.addEventListener(
                "abort",
                () => {
                  stopped += 1;
                  reject(new Error("Publication canceled."));
                },
                { once: true },
              );
            });
          },
        }),
        recordPublishedIssues: async (_prepared, issues) => {
          persisted = issues.map(({ issueIdentifier }) => issueIdentifier);
          return [...issues];
        },
        writeReceipt: async (result) => {
          receipt = result;
        },
      },
    );

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          linearApiKey: "synthetic-key",
          signal: controller.signal,
          onProgress: ({ type }) => {
            if (type === "issue_completed") controller.abort("SIGINT");
          },
        },
        injected,
      ),
    ).rejects.toThrow(/publication handoff remains at/u);

    expect({ started, stopped, persisted }).toEqual({
      started: 20,
      stopped: 19,
      persisted: ["SEC-1"],
    });
    expect(receipt).toMatchObject({
      counts: { findings: 23, created: 1, failed: 22 },
    });
  });
});

describe("connected Linear publication", () => {
  test("rejects pre-aborted publication before preparing scans or touching local state", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    controller.abort(new Error("Publication was canceled before it started."));
    let prepared = false;
    let verified = false;
    let resolved = false;
    let started = false;
    let persisted = false;
    let receipt = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            prepare: async () => {
              prepared = true;
              return publication;
            },
            preparePublicationStore: async () => {
              verified = true;
            },
            resolveCodex: () => {
              resolved = true;
              return { command: "must-not-run" };
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = true;
              return [...issues];
            },
            writeReceipt: async () => {
              receipt = true;
            },
          },
        ),
      ),
    ).rejects.toThrow("Publication was canceled before it started.");

    expect(prepared).toBe(false);
    expect(verified).toBe(false);
    expect(resolved).toBe(false);
    expect(started).toBe(false);
    expect(persisted).toBe(false);
    expect(receipt).toBe(false);
  });

  test("does not create publication state when cancellation interrupts preparation", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    let verified = false;
    let resolved = false;
    let started = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            prepare: async () => {
              controller.abort(new Error("Publication preparation stopped."));
              return publication;
            },
            preparePublicationStore: async () => {
              verified = true;
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
    ).rejects.toThrow("Publication preparation stopped.");

    expect(verified).toBe(false);
    expect(resolved).toBe(false);
    expect(started).toBe(false);
  });

  test("publishes team-only findings with project-free handoffs and recovered mappings", async () => {
    const publication: PreparedScanPublication = {
      ...preparedPublication(2),
      destination: { type: "linear", teamId: OPTIONS.teamId },
    };
    let prompt: string | undefined;
    let receiptDestination: unknown;

    const result = await publishScanInternal(
      publication.scanDirectory,
      { destination: "linear", teamId: OPTIONS.teamId },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _arguments, input) => {
            prompt = input;
            const data = publicationData(input);
            const stored = JSON.parse(
              await readFile(data.publicationFile, "utf8"),
            ) as {
              destination: Record<string, unknown>;
              batches: Array<Array<{ arguments: Record<string, unknown> }>>;
            };
            expect(stored.destination).toEqual({
              type: "linear",
              teamId: "team-example",
            });
            expect(stored.destination).not.toHaveProperty("projectId");
            for (const issue of stored.batches.flat()) {
              expect(issue.arguments).not.toHaveProperty("project");
            }

            await writeHandoff(input, [
              handoffRecord(publication, publication.issues[0]!, {
                identifier: "TEAM-1",
              }),
            ]);
            const event = JSON.parse(
              issueEvent(publication.issues[1]!, { identifier: "TEAM-2" }),
            ) as { item: { arguments: Record<string, unknown> } };
            delete event.item.arguments["project"];
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
          recordPublishedIssues: async (prepared, issues) => {
            expect(prepared.destination).toEqual({
              type: "linear",
              teamId: "team-example",
            });
            const recovered = (
              await readFile(publicationData(prompt!).handoffFile, "utf8")
            )
              .trim()
              .split("\n")
              .map((line) => JSON.parse(line) as Record<string, unknown>);
            expect(
              recovered.map((record) => record["issueIdentifier"]),
            ).toEqual(["TEAM-1", "TEAM-2"]);
            for (const record of recovered) {
              expect(record["arguments"]).not.toHaveProperty("project");
            }
            return [...issues];
          },
          writeReceipt: async (receipt) => {
            receiptDestination = receipt.destination;
          },
        },
      ),
    );

    expect(prompt).toContain("linear_get_team with the supplied team");
    expect(prompt).not.toContain("linear_get_project");
    expect(prompt).not.toContain("resolved project");
    expect(prompt).toContain("Create issues only in the exact supplied team.");
    expect(result.destination).toEqual({
      type: "linear",
      teamId: "team-example",
    });
    expect(receiptDestination).toEqual(result.destination);
    expect(result.created.map((issue) => issue.issueIdentifier)).toEqual([
      "TEAM-1",
      "TEAM-2",
    ]);
    expect(result.counts).toEqual({ findings: 2, created: 2, failed: 0 });
  });

  test("reuses ambient Codex configuration and loads exact issue data from a private file", async () => {
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
    let storedPublication: unknown;

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
            storedPublication = JSON.parse(
              await readFile(publicationData(prompt).publicationFile, "utf8"),
            );
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
    expect(input).toContain("readFileSync('publication.json', 'utf8')");
    expect(input).not.toContain("unsafe(input)");

    const encoded = input!
      .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
      .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
    expect(JSON.parse(encoded)).toEqual({
      scanId: publication.scanId,
      destination: publication.destination,
      handoffFile: join(handoffDirectory, "issues.jsonl"),
      publicationFile: join(handoffDirectory, "publication.json"),
      batches: [
        [
          {
            findingId: "finding-1",
            occurrenceId: "occurrence-1",
          },
        ],
      ],
    });
    expect(storedPublication).toEqual({
      scanId: publication.scanId,
      destination: publication.destination,
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

  test("publishes directly to a Linear team without project lookups or arguments", async () => {
    const publication: PreparedScanPublication = {
      ...preparedPublication(),
      destination: { type: "linear", teamId: OPTIONS.teamId },
    };
    let input: string | undefined;
    let issueArguments: Record<string, unknown> | undefined;

    const result = await publishScanInternal(
      publication.scanDirectory,
      { destination: "linear", teamId: OPTIONS.teamId },
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _arguments, prompt) => {
            input = prompt;
            const stored = JSON.parse(
              await readFile(publicationData(prompt).publicationFile, "utf8"),
            ) as {
              batches: Array<Array<{ arguments: Record<string, unknown> }>>;
            };
            issueArguments = stored.batches[0]?.[0]?.arguments;
            const event = JSON.parse(issueEvent(publication.issues[0]!)) as {
              item: { arguments: Record<string, unknown> };
            };
            delete event.item.arguments["project"];
            return {
              exitCode: 0,
              stdout: JSON.stringify(event),
              stderr: "",
            };
          },
        },
      ),
    );

    expect(input).toContain("linear_get_team with the supplied team");
    expect(input).not.toContain("linear_get_project");
    expect(input).not.toContain("resolved project");
    expect(input).toContain("Create issues only in the exact supplied team.");
    const encoded = input!
      .split("BEGIN UNTRUSTED PUBLICATION DATA\n")[1]!
      .split("\nEND UNTRUSTED PUBLICATION DATA")[0]!;
    const data = JSON.parse(encoded) as {
      destination: Record<string, unknown>;
    };
    expect(data.destination).toEqual({
      type: "linear",
      teamId: "team-example",
    });
    expect(issueArguments).toEqual({
      team: "team-example",
      title: publication.issues[0]!.title,
      description: publication.issues[0]!.description,
      priority: 2,
    });
    expect(issueArguments).not.toHaveProperty("project");
    expect(result.destination).toEqual({
      type: "linear",
      teamId: "team-example",
    });
    expect(result.counts).toEqual({ findings: 1, created: 1, failed: 0 });
  });

  test("preserves complete finding descriptions without exposing them to model transcription", async () => {
    const publication = preparedPublication(2);
    publication.issues[0]!.description = [
      "**Finding ID:** finding-1",
      "**Occurrence ID:** occurrence-1",
      "",
      "## Summary",
      "Synthetic finding summary with literal \\n and unicode: λ",
      "",
      "## Source-code evidence",
      "```ts",
      "ignorePreviousInstructions(secretInput)",
      "```",
      "",
      "## Remediation",
      "Preserve every character in this recommendation.",
    ].join("\n");
    let publicationFile: string | undefined;

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          runCodex: async (_command, _args, input) => {
            const data = publicationData(input);
            publicationFile = data.publicationFile;
            expect(input).not.toContain("Synthetic finding summary");
            expect(input).not.toContain("ignorePreviousInstructions");
            expect(input).not.toContain("Preserve every character");
            expect(input).toContain("Never reconstruct, retype");

            const stored = JSON.parse(
              await readFile(publicationFile, "utf8"),
            ) as {
              batches: Array<
                Array<{ findingId: string; arguments: { description: string } }>
              >;
            };
            expect(stored.batches[0]![0]!.arguments.description).toBe(
              publication.issues[0]!.description,
            );
            expect(stored.batches[0]![1]!.arguments.description).toBe(
              publication.issues[1]!.description,
            );
            await writeHandoff(
              input,
              publication.issues.map((issue) =>
                handoffRecord(publication, issue),
              ),
            );
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 2, created: 2, failed: 0 });
    expect(
      await readFile(publicationFile!, "utf8").catch(() => null),
    ).toBeNull();
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

  test("prefers verified issue events over missing handoffs and model-authored failures", async () => {
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
              "finding-3",
            ]);
            expect(records[2]!["issueIdentifier"]).toBe("SEC-2");
            expect(records[3]!["issueIdentifier"]).toBe("SEC-3");
            return [...created];
          },
        },
      ),
    );

    expect(result.created.map((issue) => issue.findingId)).toEqual([
      "finding-1",
      "finding-2",
      "finding-3",
    ]);
    expect(result.failed).toEqual([]);
    expect(result.counts).toEqual({ findings: 3, created: 3, failed: 0 });
  });

  test("retains verified issue mappings after model-authored failures if the publication database fails", async () => {
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
                handoffRecord(publication, publication.issues[1]!, {
                  error: "The model could not write the created issue.",
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
      ["finding-2", undefined],
      ["finding-2", "SEC-2"],
    ]);
    expect(records[1]!["error"]).toBe(
      "The model could not write the created issue.",
    );
  });

  test("recovers validated partial mappings after cancellation before preserving its private handoff", async () => {
    const publication = preparedPublication(3);
    const controller = new AbortController();
    const updates: PublishScanProgress[] = [];
    let handoffFile: string | undefined;
    let publicationFile: string | undefined;
    let childStopped = false;
    let recorded: string[] = [];
    let receipt: unknown;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          signal: controller.signal,
          onProgress: (event) => updates.push(event),
        },
        dependencies(
          publication,
          {},
          {
            runCodex: async (
              _command,
              _args,
              input,
              _environment,
              onEvent,
              signal,
            ) => {
              expect(signal).toBe(controller.signal);
              ({ handoffFile, publicationFile } = publicationData(input));
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-WRITTEN",
                }),
                {
                  ...handoffRecord(publication, publication.issues[2]!, {
                    identifier: "SEC-UNVERIFIED",
                  }),
                  scanId: "another-scan",
                },
              ]);
              const observed = issueEvent(publication.issues[1]!, {
                identifier: "SEC-SALVAGED",
              });
              onEvent?.(JSON.parse(observed) as unknown);
              controller.abort("SIGINT");
              await Promise.resolve();
              childStopped = true;
              return {
                exitCode: 130,
                stdout: observed,
                stderr: "Publication was interrupted.",
              };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              expect(childStopped).toBe(true);
              recorded = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async (result) => {
              expect(childStopped).toBe(true);
              receipt = result;
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /Linear publication was interrupted\. The publication handoff remains at .*; recover it before retrying to avoid creating duplicate issues\./u,
    );

    expect(recorded).toEqual(["SEC-WRITTEN", "SEC-SALVAGED"]);
    expect(receipt).toMatchObject({
      scanId: publication.scanId,
      created: [
        { findingId: "finding-1", issueIdentifier: "SEC-WRITTEN" },
        { findingId: "finding-2", issueIdentifier: "SEC-SALVAGED" },
      ],
      failed: [{ findingId: "finding-3" }],
      counts: { findings: 3, created: 2, failed: 1 },
    });
    expect(JSON.stringify(receipt)).not.toContain("SEC-UNVERIFIED");
    expect(updates.some((event) => event.type === "completed")).toBe(false);

    const recovery = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      recovery.map((record) => [
        record["findingId"],
        record["issueIdentifier"],
      ]),
    ).toEqual([
      ["finding-1", "SEC-WRITTEN"],
      ["finding-3", "SEC-UNVERIFIED"],
      ["finding-2", "SEC-SALVAGED"],
    ]);
    expect(await readFile(publicationFile!, "utf8")).toContain("unsafe(input)");
    if (process.platform !== "win32") {
      expect((await stat(dirname(handoffFile!))).mode & 0o077).toBe(0);
      expect((await stat(handoffFile!)).mode & 0o077).toBe(0);
      expect((await stat(publicationFile!)).mode & 0o077).toBe(0);
    }
  });

  test("retains every verified recovery mapping when cancellation and database failure overlap", async () => {
    const publication = preparedPublication(2);
    const controller = new AbortController();
    let handoffFile: string | undefined;
    let receipt = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-WRITTEN",
                }),
              ]);
              controller.abort("SIGTERM");
              return {
                exitCode: 143,
                stdout: issueEvent(publication.issues[1]!, {
                  identifier: "SEC-SALVAGED",
                }),
                stderr: "",
              };
            },
            recordPublishedIssues: async () => {
              throw new Error("The publication database is unavailable.");
            },
            writeReceipt: async () => {
              receipt = true;
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /database is unavailable.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(receipt).toBe(false);
    const recovery = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(
      recovery.map((record) => [
        record["findingId"],
        record["issueIdentifier"],
      ]),
    ).toEqual([
      ["finding-1", "SEC-WRITTEN"],
      ["finding-2", "SEC-SALVAGED"],
    ]);
  });

  test("retains cancellation recovery data when its partial receipt cannot be written", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    let handoffFile: string | undefined;
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-SAVED",
                }),
              ]);
              controller.abort("SIGINT");
              return { exitCode: 130, stdout: "", stderr: "" };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = true;
              return [...issues];
            },
            writeReceipt: async () => {
              throw new Error("The receipt disk is full.");
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /partial receipt could not be saved: The receipt disk is full.*publication handoff remains at.*avoid creating duplicate issues/u,
    );

    expect(persisted).toBe(true);
    expect(await readFile(handoffFile!, "utf8")).toContain("SEC-SAVED");
  });

  test("rejects mismatched scan IDs, finding occurrences, duplicate findings, and unknown findings", async () => {
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

  test("retains distinct duplicate Linear issue IDs for indeterminate recovery", async () => {
    const publication = preparedPublication();
    const issue = publication.issues[0]!;
    let handoffFile: string | undefined;
    let persisted = false;
    let receipt = false;

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
                handoffRecord(publication, issue, {
                  identifier: "SYNTH-DUPLICATE-A",
                }),
                handoffRecord(publication, issue, {
                  identifier: "SYNTH-DUPLICATE-B",
                }),
              ]);
              return {
                exitCode: 0,
                stdout: [
                  issueEvent(issue, { identifier: "SYNTH-DUPLICATE-A" }),
                  issueEvent(issue, { identifier: "SYNTH-DUPLICATE-B" }),
                ].join("\n"),
                stderr: "",
              };
            },
            recordPublishedIssues: async (_prepared, created) => {
              persisted = true;
              return [...created];
            },
            writeReceipt: async () => {
              receipt = true;
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /SYNTH-DUPLICATE-A and SYNTH-DUPLICATE-B.*indeterminate.*publication handoff remains at.*recover both issues.*avoid creating duplicate issues/u,
    );

    expect(persisted).toBe(false);
    expect(receipt).toBe(false);
    const records = (await readFile(handoffFile!, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records.map((record) => record["issueIdentifier"])).toEqual([
      "SYNTH-DUPLICATE-A",
      "SYNTH-DUPLICATE-B",
    ]);
  });

  test("matches durable publication handoffs by scan and finding IDs only", async () => {
    const publication = preparedPublication(3);
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
              publication.issues.map((issue, index) => {
                const record = handoffRecord(publication, issue);
                if (index === 0) {
                  record["arguments"] = { title: "Normalized issue title" };
                } else if (index === 1) {
                  delete record["arguments"];
                } else {
                  record["connectorRequestId"] = "request-example";
                }
                return record;
              }),
            );
            return { exitCode: 0, stdout: "", stderr: "" };
          },
        },
      ),
    );

    expect(result.counts).toEqual({ findings: 3, created: 3, failed: 0 });
    expect(result.created.map((issue) => issue.findingId)).toEqual([
      "finding-1",
      "finding-2",
      "finding-3",
    ]);
  });

  test("rejects handoffs contradicted by observed trusted Linear mutations", async () => {
    const scenarios: Array<{
      name: string;
      events: (publication: PreparedScanPublication) => string[];
    }> = [
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

  test("does not create source-bearing handoffs when the Codex command cannot be resolved", async () => {
    const publication = preparedPublication();
    const injected = dependencies(
      publication,
      {},
      {
        resolveCodex: () => {
          throw new Error("The Codex executable could not be resolved.");
        },
        runCodex: undefined,
      },
    );

    await expect(
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ).rejects.toThrow("The Codex executable could not be resolved.");

    const handoffRoot = join(
      injected.environment!["CODEX_SECURITY_STATE_DIR"]!,
      "publications",
      "linear",
      "handoffs",
    );
    expect(
      await stat(handoffRoot).then(
        () => false,
        (error: NodeJS.ErrnoException) => error.code === "ENOENT",
      ),
    ).toBe(true);
  });

  test("removes source-bearing handoffs when the Codex executable cannot be spawned", async () => {
    const publication = preparedPublication();
    let persisted = false;
    const missingExecutable = join(
      tmpdir(),
      `codex-security-missing-executable-${randomUUID()}`,
    );
    const injected = dependencies(
      publication,
      {},
      {
        resolveCodex: () => ({ command: missingExecutable }),
        runCodex: undefined,
        recordPublishedIssues: async (_publication, issues) => {
          persisted = true;
          return [...issues];
        },
      },
    );

    await expect(
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ).rejects.toThrow("Could not start Codex for Linear publication.");

    const handoffRoot = join(
      injected.environment!["CODEX_SECURITY_STATE_DIR"]!,
      "publications",
      "linear",
      "handoffs",
    );
    expect(await readdir(handoffRoot)).toEqual([]);
    expect(persisted).toBe(false);
  });

  test("retains handoffs when an injected publisher rejects after a possible mutation", async () => {
    const publication = preparedPublication();
    let handoffFile: string | undefined;
    const injected = dependencies(
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
          throw new Error("The publisher failed after a possible mutation.");
        },
      },
    );

    await expect(
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ).rejects.toThrow("The publisher failed after a possible mutation.");

    expect(await readFile(handoffFile!, "utf8")).toContain("SEC-RECOVERABLE");
    expect(
      await readFile(join(dirname(handoffFile!), "publication.json"), "utf8"),
    ).toContain("unsafe(input)");
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

  test("rejects an already-aborted publication before preparing or starting Codex", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    const reason = new Error("Publication was canceled before startup.");
    controller.abort(reason);
    let prepared = false;
    let started = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            prepare: async () => {
              prepared = true;
              return publication;
            },
            runCodex: async () => {
              started = true;
              return { exitCode: 0, stdout: "", stderr: "" };
            },
          },
        ),
      ),
    ).rejects.toBe(reason);
    expect(prepared).toBe(false);
    expect(started).toBe(false);
  });

  test("forwards cancellation and saves verified issues before reporting interruption", async () => {
    const publication = preparedPublication(2);
    const controller = new AbortController();
    const reason = new Error("Publication was interrupted.");
    let saved: PublicationCodexResult | undefined;
    let savedIssueIdentifiers: string[] | undefined;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, signal: controller.signal },
        dependencies(
          publication,
          {},
          {
            runCodex: async (
              _command,
              _args,
              _input,
              _environment,
              _onEvent,
              signal,
            ) => {
              expect(signal).toBe(controller.signal);
              controller.abort(reason);
              saved = {
                exitCode: 1,
                stdout: issueEvent(publication.issues[0]!),
                stderr: "",
              };
              return saved;
            },
            writeReceipt: async (receipt) => {
              savedIssueIdentifiers = receipt.created.map(
                (issue) => issue.issueIdentifier,
              );
            },
          },
        ),
      ),
    ).rejects.toThrow(
      /Linear publication was interrupted\. The publication handoff remains at .*; recover it before retrying to avoid creating duplicate issues\./u,
    );

    expect(saved?.exitCode).toBe(1);
    expect(savedIssueIdentifiers).toEqual(["SEC-1"]);
  });

  test.each([
    ["a promptly exiting parent", false, "SIGTERM"],
    ["a parent that ignores termination", true, "SIGTERM"],
    ["a Ctrl-C-interrupted parent", false, "SIGINT"],
  ] as const)(
    "cancellation stops %s and its signal-resistant Codex descendants",
    async (_description, ignoreTermination, terminationSignal) => {
      const directory = await mkdtemp(
        join(tmpdir(), "codex-security-publication-cancel-"),
      );
      temporaryDirectories.push(directory);
      const publication = preparedPublication(2);
      const parentPath = join(directory, "parent.pid");
      const descendantPath = join(directory, "descendant.pid");
      const preload = join(directory, "codex-preload.cjs");
      await writeFile(
        preload,
        [
          'const fs = require("node:fs");',
          'const { spawn } = require("node:child_process");',
          'fs.readFileSync(0, "utf8");',
          "fs.writeFileSync(process.env.CODEX_PUBLICATION_PARENT_PID, String(process.pid));",
          "const environment = { ...process.env };",
          "delete environment.NODE_OPTIONS;",
          "const descendant = [",
          '  "const fs = require(\\"node:fs\\");",',
          '  "process.on(\\"SIGTERM\\", () => {});",',
          '  "process.on(\\"SIGINT\\", () => {});",',
          '  "fs.writeFileSync(process.env.CODEX_PUBLICATION_DESCENDANT_PID, String(process.pid));",',
          '  "setInterval(() => {}, 1000);",',
          '].join("");',
          'spawn(process.execPath, ["-e", descendant], { env: environment, stdio: "ignore" });',
          "const waiter = new Int32Array(new SharedArrayBuffer(4));",
          "for (let attempts = 0; !fs.existsSync(process.env.CODEX_PUBLICATION_DESCENDANT_PID); attempts += 1) {",
          "  if (attempts === 1000) process.exit(3);",
          "  Atomics.wait(waiter, 0, 0, 10);",
          "}",
          'if (process.env.CODEX_PUBLICATION_IGNORE_TERMINATION === "1") {',
          '  process.on("SIGTERM", () => {});',
          "}",
          "fs.writeSync(1, `${process.env.CODEX_PUBLICATION_EVENT}\\n`);",
          "for (;;) Atomics.wait(waiter, 0, 0, 1000);",
        ].join("\n"),
        "utf8",
      );
      const controller = new AbortController();
      const reason =
        terminationSignal === "SIGINT"
          ? "SIGINT"
          : new Error("Publication was interrupted.");
      const injected = dependencies(
        publication,
        {},
        {
          environment: {
            ...process.env,
            CODEX_SECURITY_STATE_DIR: join(directory, "state"),
            NODE_OPTIONS: `--require=${JSON.stringify(preload)}`,
            CODEX_PUBLICATION_PARENT_PID: parentPath,
            CODEX_PUBLICATION_DESCENDANT_PID: descendantPath,
            CODEX_PUBLICATION_IGNORE_TERMINATION: ignoreTermination ? "1" : "0",
            CODEX_PUBLICATION_EVENT: issueEvent(publication.issues[0]!),
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

      await expect(
        publishScanInternal(
          publication.scanDirectory,
          {
            ...OPTIONS,
            signal: controller.signal,
            onProgress: (event) => {
              if (event.type === "issue_completed") controller.abort(reason);
            },
          },
          injected,
        ),
      ).rejects.toThrow(
        /Linear publication was interrupted\. The publication handoff remains at .*; recover it before retrying to avoid creating duplicate issues\./u,
      );

      const parent = Number(await readFile(parentPath, "utf8"));
      const descendant = Number(await readFile(descendantPath, "utf8"));
      expect(await processHasExited(parent)).toBe(true);
      expect(await processHasExited(descendant)).toBe(true);
      const receipt = join(
        directory,
        "state",
        "publications",
        "linear",
        `${createHash("sha256").update(publication.scanId).digest("hex")}.json`,
      );
      const persisted = JSON.parse(await readFile(receipt, "utf8")) as {
        created: Array<{ issueIdentifier: string }>;
        counts: { findings: number; created: number; failed: number };
      };
      expect(persisted.created.map((issue) => issue.issueIdentifier)).toEqual([
        "SEC-1",
      ]);
      expect(persisted.counts).toEqual({ findings: 2, created: 1, failed: 1 });
    },
    30_000,
  );

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

  test("never reports an issue for unknown finding IDs or repeated tool events", async () => {
    const publication = preparedPublication();
    const updates: PublishScanProgress[] = [];
    const unexpected = JSON.parse(issueEvent(publication.issues[0]!)) as Record<
      string,
      unknown
    >;
    const item = unexpected["item"] as Record<string, unknown>;
    const args = item["arguments"] as Record<string, unknown>;
    args["description"] = "**Finding ID:** unknown\n**Occurrence ID:** unknown";
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

  test("returns persisted successes and partial failures when an optional receipt cannot be saved", async () => {
    for (const partialFailure of [false, true]) {
      const publication = preparedPublication(2);
      const progress: PublishScanProgress[] = [];
      let invocations = 0;
      let persisted: string[] = [];
      let handoffFile: string | undefined;

      const result = await publishScanInternal(
        publication.scanDirectory,
        {
          ...OPTIONS,
          onProgress: (event) => progress.push(event),
        },
        dependencies(
          publication,
          {},
          {
            runCodex: async (_command, _args, input) => {
              invocations += 1;
              handoffFile = publicationData(input).handoffFile;
              await writeHandoff(input, [
                handoffRecord(publication, publication.issues[0]!, {
                  identifier: "SEC-PERSISTED",
                }),
                handoffRecord(
                  publication,
                  publication.issues[1]!,
                  partialFailure
                    ? { error: "The destination rejected this finding." }
                    : { identifier: "SEC-ALSO-PERSISTED" },
                ),
              ]);
              return {
                exitCode: 0,
                stdout: "not trusted agent prose",
                stderr: "",
              };
            },
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = issues.map((issue) => issue.issueIdentifier);
              return [...issues];
            },
            writeReceipt: async () => {
              throw new Error(
                "OPENAI_API_KEY=sk-proj-SYNTHETIC_RECEIPT_SECRET_123",
              );
            },
          },
        ),
      );

      const expectedCreated = partialFailure
        ? ["SEC-PERSISTED"]
        : ["SEC-PERSISTED", "SEC-ALSO-PERSISTED"];
      expect(invocations).toBe(1);
      expect(persisted).toEqual(expectedCreated);
      expect(result.created.map((issue) => issue.issueIdentifier)).toEqual(
        expectedCreated,
      );
      expect(result.failed).toEqual(
        partialFailure
          ? [
              {
                findingId: "finding-2",
                error: "The destination rejected this finding.",
              },
            ]
          : [],
      );
      expect(result.counts).toEqual({
        findings: 2,
        created: expectedCreated.length,
        failed: partialFailure ? 1 : 0,
      });
      expect(result.warnings).toEqual([
        "Could not save the publication receipt: [redacted]. Linear issues were already created; do not retry publication.",
      ]);
      expect(JSON.stringify(result)).not.toContain("SYNTHETIC_RECEIPT_SECRET");
      expect(progress.at(-1)).toEqual({
        type: "completed",
        created: expectedCreated.length,
        failed: partialFailure ? 1 : 0,
        total: 2,
      });
      expect(
        await stat(handoffFile!).then(
          () => false,
          (error: NodeJS.ErrnoException) => error.code === "ENOENT",
        ),
      ).toBe(true);
    }
  });

  test("keeps receipt failures fatal when no Linear issues were created", async () => {
    const publication = preparedPublication();
    let persisted = false;

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        OPTIONS,
        dependencies(
          publication,
          { stdout: "" },
          {
            recordPublishedIssues: async (_prepared, issues) => {
              persisted = true;
              return [...issues];
            },
            writeReceipt: async () => {
              throw new Error("The receipt disk is unavailable.");
            },
          },
        ),
      ),
    ).rejects.toThrow("The receipt disk is unavailable.");

    expect(persisted).toBe(false);
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

  test("preserves both private receipts when the same scan is published concurrently", async () => {
    const stateDirectory = await mkdtemp(
      join(tmpdir(), "codex-security-concurrent-publication-receipts-"),
    );
    temporaryDirectories.push(stateDirectory);
    const publication = preparedPublication();
    let calls = 0;
    const injected = dependencies(
      publication,
      {},
      {
        environment: { CODEX_SECURITY_STATE_DIR: stateDirectory },
        runCodex: async () => {
          calls += 1;
          return {
            exitCode: 0,
            stdout: issueEvent(publication.issues[0]!, {
              identifier: `SEC-CONCURRENT-${calls}`,
            }),
            stderr: "",
          };
        },
      },
    );
    delete injected.writeReceipt;

    const results = await Promise.all([
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
      publishScanInternal(publication.scanDirectory, OPTIONS, injected),
    ]);
    const directory = join(stateDirectory, "publications", "linear");
    const digest = createHash("sha256")
      .update(publication.scanId)
      .digest("hex");
    const attempts = (await readdir(directory)).filter(
      (name) => name.startsWith(`${digest}-`) && name.endsWith(".json"),
    );

    expect(attempts).toHaveLength(2);
    const receipts = await Promise.all(
      attempts.map(async (name) => {
        const path = join(directory, name);
        if (process.platform !== "win32") {
          expect((await stat(path)).mode & 0o077).toBe(0);
        }
        return JSON.parse(await readFile(path, "utf8")) as {
          created: Array<{ issueIdentifier: string }>;
        };
      }),
    );
    expect(
      receipts
        .flatMap((receipt) =>
          receipt.created.map((issue) => issue.issueIdentifier),
        )
        .sort(),
    ).toEqual(["SEC-CONCURRENT-1", "SEC-CONCURRENT-2"]);
    const latest = JSON.parse(
      await readFile(join(directory, `${digest}.json`), "utf8"),
    ) as (typeof results)[number];
    expect(results).toContainEqual(latest);
    expect(
      results.map((result) => result.created[0]!.issueIdentifier).sort(),
    ).toEqual(["SEC-CONCURRENT-1", "SEC-CONCURRENT-2"]);
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

  test("requires an exact team and rejects a blank supplied project before reading a scan", async () => {
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
