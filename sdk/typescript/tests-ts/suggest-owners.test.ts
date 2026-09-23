import { execFile as execFileCallback } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import type { ThreadOptions, TurnOptions } from "@openai/codex-sdk";
import { afterEach, expect, test } from "bun:test";
import type { OwnerContext } from "../src/owner-evidence.js";
import {
  suggestOwners,
  type OwnerFinding,
  type SuggestOwnersOptions,
} from "../src/suggest-owners.js";

const execFile = promisify(execFileCallback);
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

const finding: OwnerFinding = {
  findingId: "finding-one",
  title: "Missing authorization",
  summary: "Check access before reading a record.",
  locations: [{ path: "handler.ts", startLine: 2, endLine: 3 }],
};

async function repository() {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "owner-repository-")),
  );
  directories.push(path);
  const git = async (...args: string[]) =>
    (await execFile("git", ["-C", path, ...args])).stdout.trim();
  await git("init", "-q");
  await git("config", "user.name", "Alex Example");
  await git("config", "user.email", "alex@example.test");
  await git("config", "commit.gpgsign", "false");
  await writeFile(
    join(path, "handler.ts"),
    "// Records\nexport function readRecord(id) {\n  return records[id];\n}\n",
  );
  await git("add", ".");
  await git("commit", "-qm", "Add record handler");
  const original = await git("rev-parse", "HEAD");
  await writeFile(
    join(path, "handler.ts"),
    "// Record access\nexport function readRecord(id) {\n  return records[id];\n}\n",
  );
  await git(
    "-c",
    "user.name=Blair Example",
    "-c",
    "user.email=blair@example.test",
    "commit",
    "-qam",
    "Clarify comment",
  );
  return { path, git, original, revision: await git("rev-parse", "HEAD") };
}

function fakeCodex(decide: (context: OwnerContext) => unknown = chooseAlex) {
  const calls: {
    context: OwnerContext;
    thread: ThreadOptions;
    turn: TurnOptions;
  }[] = [];
  const codex: NonNullable<SuggestOwnersOptions["codex"]> = {
    startThread(thread) {
      return {
        async run(prompt, turn) {
          const context = JSON.parse(
            prompt.split("\n\n").at(-1)!,
          ) as OwnerContext;
          calls.push({ context, thread, turn });
          const result = decide(context);
          return {
            finalResponse:
              typeof result === "string" ? result : JSON.stringify(result),
          };
        },
      };
    },
  };
  return { codex, calls };
}

function chooseAlex(context: OwnerContext) {
  const index = context.identities.findIndex(
    ({ email }) => email === "alex@example.test",
  );
  return {
    identityIndex: index,
    reason:
      "Alex maintains the record handler; Blair only changed its comment.",
    evidenceIds: context.evidence
      .filter((item) => item.identityIndex === index)
      .map(({ id }) => id),
  };
}

test("combines source, affected-line authorship, and history through the restricted model runner", async () => {
  const repo = await repository();
  const dirty = "uncommitted source must remain untouched\n";
  await writeFile(join(repo.path, "handler.ts"), dirty);
  await writeFile(
    join(repo.path, ".mailmap"),
    "Imposter <imposter@example.test> Alex Example <alex@example.test>\n",
  );
  const input = structuredClone(finding);
  const { codex, calls } = fakeCodex();
  const signal = new AbortController().signal;
  const report = await suggestOwners(repo.path, [input], {
    codex,
    signal,
    model: "synthetic-model",
    reasoningEffort: "high",
  });
  expect(report).toMatchObject({
    revision: repo.revision,
    model: "synthetic-model",
    reasoningEffort: "high",
    results: [
      {
        findingId: finding.findingId,
        status: "identified",
        owner: { name: "Alex Example", email: "alex@example.test" },
      },
    ],
  });
  expect(
    report.results[0]!.evidence.find(({ kind }) => kind === "blame"),
  ).toMatchObject({
    path: "handler.ts",
    commit: repo.revision,
    startLine: 2,
    endLine: 3,
  });
  expect(
    calls[0]!.context.evidence.find(({ kind }) => kind === "source")!.content,
  ).toContain("return records[id]");
  expect(calls[0]!.context.identities).toHaveLength(2);
  expect(calls[0]!.thread).toMatchObject({
    threadSource: "security_assignee_recommendation",
    model: "synthetic-model",
    modelReasoningEffort: "high",
    sandboxMode: "read-only",
    approvalPolicy: "never",
    networkAccessEnabled: false,
    webSearchMode: "disabled",
  });
  expect(calls[0]!.turn.signal).toBe(signal);
  expect(await readFile(join(repo.path, "handler.ts"), "utf8")).toBe(dirty);
  expect(input).toEqual(finding);
});

test("abstains without a model call when locations do not identify committed regular source", async () => {
  const repo = await repository();
  await repo.git(
    "update-index",
    "--add",
    "--cacheinfo",
    `120000,${await repo.git("rev-parse", "HEAD:handler.ts")},alias.ts`,
  );
  await writeFile(join(repo.path, "binary.dat"), Buffer.from([0, 1, 2]));
  await repo.git("add", "binary.dat");
  await repo.git("commit", "-qm", "Add non-source entries");
  await writeFile(join(repo.path, "untracked.ts"), "local source");
  const { codex, calls } = fakeCodex();
  const locations = [
    [],
    [{ path: "missing.ts" }],
    [{ path: "../outside.ts" }],
    [{ path: ":(glob)*" }],
    [{ path: "handler.ts", startLine: 100 }],
    [{ path: "alias.ts" }],
    [{ path: "binary.dat" }],
    [{ path: "untracked.ts" }],
  ];
  const report = await suggestOwners(
    repo.path,
    locations.map((locations, index) => ({
      ...finding,
      findingId: `finding-${index}`,
      locations,
    })),
    { codex },
  );
  expect(calls).toHaveLength(0);
  expect(
    report.results.every(
      ({ status, owner, limitations }) =>
        status === "abstained" && owner === null && limitations.length > 0,
    ),
  ).toBe(true);
});

test("keeps renamed-file blame citations at HEAD and inherits SDK model settings", async () => {
  const repo = await repository();
  const path = "record [1].ts";
  await repo.git("mv", "handler.ts", path);
  await repo.git("commit", "-qm", "Rename record handler");
  const { codex, calls } = fakeCodex();
  const report = await suggestOwners(
    repo.path,
    [{ ...finding, locations: [{ path, startLine: 2, endLine: 3 }] }],
    {
      codex,
      config: {
        codexOverrides: {
          model: "configured-model",
          model_reasoning_effort: "low",
        },
      },
    },
  );
  expect(report.results[0]!.status).toBe("identified");
  expect(
    report.results[0]!.evidence.find(({ kind }) => kind === "blame"),
  ).toMatchObject({
    path,
    commit: await repo.git("rev-parse", "HEAD"),
    startLine: 2,
    endLine: 3,
  });
  expect(calls[0]!.thread).toMatchObject({
    model: "configured-model",
    modelReasoningEffort: "low",
  });
  expect(report).toMatchObject({
    model: "configured-model",
    reasoningEffort: "low",
  });
});

test("rejects invented identities and citations and preserves later results", async () => {
  const repo = await repository();
  const invalid: ((context: OwnerContext) => unknown)[] = [
    () => "not JSON",
    (context) => ({
      ...chooseAlex(context),
      identityIndex: context.identities.length,
    }),
    (context) => ({ ...chooseAlex(context), evidenceIds: ["invented"] }),
    (context) => ({ ...chooseAlex(context), evidenceIds: [] }),
    (context) => ({
      ...chooseAlex(context),
      evidenceIds: [
        context.evidence.find(({ identityIndex }) => identityIndex === 1)!.id,
      ],
    }),
    (context) => ({ ...chooseAlex(context), reason: " " }),
    (context) => ({
      ...chooseAlex(context),
      owner: { email: "invented@example.test" },
    }),
  ];
  let index = 0;
  const { codex } = fakeCodex((context) =>
    (invalid[index++] ?? chooseAlex)(context),
  );
  const report = await suggestOwners(
    repo.path,
    Array.from({ length: invalid.length + 1 }, (_, index) => ({
      ...finding,
      findingId: `finding-${index}`,
    })),
    { codex },
  );
  expect(
    report.results
      .slice(0, -1)
      .every(
        ({ status, owner, evidence }) =>
          status === "error" && owner === null && evidence.length === 0,
      ),
  ).toBe(true);
  expect(report.results.at(-1)!.status).toBe("identified");
});

test("ignores stale line ranges, reports shallow history, and preserves model abstentions", async () => {
  const repo = await repository();
  await writeFile(join(repo.path, ".git", "shallow"), `${repo.revision}\n`);
  const { codex, calls } = fakeCodex(() => ({
    identityIndex: -1,
    reason: "History is incomplete.",
    evidenceIds: [],
  }));
  const report = await suggestOwners(
    repo.path,
    [
      {
        ...finding,
        sourceRevision: repo.original,
        locations: [{ path: "handler.ts", startLine: 200 }],
      },
    ],
    { codex },
  );
  expect(calls).toHaveLength(1);
  expect(report.results[0]).toMatchObject({
    status: "abstained",
    owner: null,
    reason: "History is incomplete.",
  });
  expect(report.results[0]!.limitations.join(" ")).toMatch(/shallow/u);
  expect(report.results[0]!.limitations.join(" ")).toMatch(
    /line ranges were not used/u,
  );
  expect(
    calls[0]!.context.evidence.find(({ kind }) => kind === "source"),
  ).toMatchObject({ startLine: 1, endLine: 4 });
});

test("propagates cancellation", async () => {
  const repo = await repository();
  const controller = new AbortController();
  const canceled = fakeCodex(() => {
    controller.abort(new Error("Canceled by caller"));
    throw controller.signal.reason;
  });
  await expect(
    suggestOwners(repo.path, [finding], {
      codex: canceled.codex,
      signal: controller.signal,
    }),
  ).rejects.toThrow("Canceled by caller");
});
