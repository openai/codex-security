import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
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
  return {
    prepare: async () => publication,
    resolveCodex: () => ({ command: "synthetic-codex" }),
    runCodex: async () => ({
      exitCode: 0,
      stdout: publication.issues.map((issue) => issueEvent(issue)).join("\n"),
      stderr: "",
      ...invocation,
    }),
    writeReceipt: async () => undefined,
    ...overrides,
  };
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

describe("connected Linear publication", () => {
  test("reuses ambient Codex configuration and streams exact issue data on stdin", async () => {
    const publication = preparedPublication();
    const environment = {
      CODEX_HOME: "/existing/connected-codex-home",
      CODEX_SECURITY_STATE_DIR: "/existing/security-state",
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
    expect(args).toEqual([
      "exec",
      "--model",
      "gpt-5.6-luna",
      "-c",
      'model_reasoning_effort="low"',
      "--ephemeral",
      "--json",
      "--sandbox",
      "read-only",
      "--skip-git-repo-check",
      "--cd",
      publication.scanDirectory,
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
      issues: [
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

  test.each([
    ["complete", false],
    ["partial", true],
  ] as const)(
    "returns %s verified publication instead of retrying after a receipt failure",
    async (_outcome, partial) => {
      const publication = preparedPublication(2);
      const updates: PublishScanProgress[] = [];
      const output = [
        issueEvent(publication.issues[0]!),
        issueEvent(
          publication.issues[1]!,
          partial
            ? { status: "failed", error: "The project rejected this finding." }
            : {},
        ),
      ].join("\n");
      let invocations = 0;
      let receiptAttempts = 0;

      const result = await publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (event) => updates.push(event) },
        dependencies(
          publication,
          {},
          {
            runCodex: async () => {
              invocations += 1;
              return { exitCode: 0, stdout: output, stderr: "" };
            },
            writeReceipt: async () => {
              receiptAttempts += 1;
              throw new Error("The receipt disk is full");
            },
          },
        ),
      );

      expect(result.created.map((issue) => issue.issueIdentifier)).toEqual(
        partial ? ["SEC-1"] : ["SEC-1", "SEC-2"],
      );
      expect(result.failed).toEqual(
        partial
          ? [
              {
                findingId: "finding-2",
                error: "The project rejected this finding.",
              },
            ]
          : [],
      );
      expect(result.counts).toEqual({
        findings: 2,
        created: partial ? 1 : 2,
        failed: partial ? 1 : 0,
      });
      expect(result.warnings).toEqual([
        "Could not save the publication receipt: The receipt disk is full. Linear issues were already created; do not retry publication.",
      ]);
      expect(updates.at(-1)).toEqual({
        type: "completed",
        created: partial ? 1 : 2,
        failed: partial ? 1 : 0,
        total: 2,
      });
      expect(invocations).toBe(1);
      expect(receiptAttempts).toBe(1);
    },
  );

  test("redacts sensitive receipt diagnostics while returning verified issues", async () => {
    const publication = preparedPublication();
    const syntheticSecret = "sk-proj-SYNTHETIC_PUBLIC_TEST_TOKEN";

    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(
        publication,
        {},
        {
          writeReceipt: async () => {
            throw new Error(`Authorization: Bearer ${syntheticSecret}`);
          },
        },
      ),
    );

    expect(result.created[0]?.issueIdentifier).toBe("SEC-1");
    expect(result.warnings).toEqual([
      "Could not save the publication receipt: [redacted]. Linear issues were already created; do not retry publication.",
    ]);
    expect(JSON.stringify(result)).not.toContain(syntheticSecret);
  });

  test("keeps receipt failures fatal when no created Linear issue was verified", async () => {
    const publication = preparedPublication();
    const receiptFailure = new Error(
      "The publication receipt cannot be saved.",
    );
    const updates: PublishScanProgress[] = [];

    await expect(
      publishScanInternal(
        publication.scanDirectory,
        { ...OPTIONS, onProgress: (event) => updates.push(event) },
        dependencies(
          publication,
          {
            stdout: JSON.stringify({
              type: "item.completed",
              item: {
                type: "agent_message",
                text: "Created fabricated issue SEC-UNVERIFIED.",
              },
            }),
          },
          {
            writeReceipt: async () => {
              throw receiptFailure;
            },
          },
        ),
      ),
    ).rejects.toBe(receiptFailure);

    expect(updates.some((event) => event.type === "completed")).toBe(false);
  });

  test("keeps receipt failures fatal when cancellation has already interrupted publication", async () => {
    const publication = preparedPublication();
    const controller = new AbortController();
    const cancellation = new Error("Publication was interrupted.");
    const receiptFailure = new Error("The partial receipt cannot be saved.");
    const updates: PublishScanProgress[] = [];

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
            runCodex: async () => {
              controller.abort(cancellation);
              return {
                exitCode: 1,
                stdout: issueEvent(publication.issues[0]!),
                stderr: "",
              };
            },
            writeReceipt: async () => {
              throw receiptFailure;
            },
          },
        ),
      ),
    ).rejects.toBe(receiptFailure);

    expect(controller.signal.reason).toBe(cancellation);
    expect(updates.some((event) => event.type === "completed")).toBe(false);
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
    ).rejects.toBe(reason);

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
      ).rejects.toBe(reason);

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

  test("publishes more than 25 findings without using the tracking skill", async () => {
    const publication = preparedPublication(30);
    const result = await publishScanInternal(
      publication.scanDirectory,
      OPTIONS,
      dependencies(publication),
    );

    expect(result.created).toHaveLength(30);
    expect(result.failed).toEqual([]);
    expect(result.counts).toEqual({ findings: 30, created: 30, failed: 0 });
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
