import { afterEach, beforeEach, expect, test } from "bun:test";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { ValidationItemRecord } from "../src/validation-provider.js";
import { remediationPrompt } from "../src/remediation.js";
import {
  assessmentStateDirectories,
  saveCliContinuumAssessments,
  savedContinuumAssessments,
} from "../src/saved-continuum-assessment.js";

test("uses both native storage locations under default settings", () => {
  expect(assessmentStateDirectories({})).toEqual({
    plugin: join(homedir(), ".codex-security"),
    cli: join(homedir(), ".codex", "state", "plugins", "codex-security"),
  });
});

const config = { provider: "continuum", continuum: { environment_id: "env" } };
const prefix = "arn:aws:continuum:us-east-1:123456789012:environments/env";
const conclusion = {
  itemId: "occ_a",
  provider: "continuum" as const,
  findingId: "finding-a",
  findingArn: prefix + "/code-findings/finding-a",
  issueId: "issue-a",
  issueArn: prefix + "/code-issues/issue-a",
  validationArtifactId: "artifact-1",
  scoringArtifactId: "artifact-2",
  submittedAt: "2026-11-21T01:00:00Z",
  verdict: "UNCERTAIN",
  terminalStatus: "FAILED",
  resultScope: "issue" as const,
  issueFindingCount: 2,
  joinedValidatedIssue: true,
  claimMatch: "unknown" as const,
  freshness: { stale: true, reasons: ["pre-existing proof"] },
  reasons: [{ basis: "CODE", reason: "no deployment edge" }],
};
let root: string;
let repo: string;
let path: string;
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), "saved-conclusion-"));
  repo = join(root, "repository");
  await mkdir(repo);
  await mkdir(join(root, "validation-providers"));
  path = join(root, "validation-providers", "scan.json");
  await writeFile(path, JSON.stringify(config));
});
afterEach(() => rm(root, { recursive: true, force: true }));
const read = (scan = "scan") =>
  savedContinuumAssessments({ CODEX_SECURITY_STATE_DIR: root }, scan, repo, [
    "occ_a",
  ]);
function save(items: unknown[], overrides: object = {}) {
  return writeFile(
    path + ".result",
    JSON.stringify({
      configuration: config,
      repositoryPath: repo,
      result: { provider: "continuum" },
      records: { schemaVersion: 1, items },
      retry: null,
      ...overrides,
    }),
  );
}
test("projects only conclusions with the attribution limits and external identifiers", async () => {
  await save([{ ...conclusion, proofBody: "untrusted", secret: "private" }]);
  expect((await read()).get("occ_a")).toEqual(conclusion);
  expect((await read()).has("occ_b")).toBe(false);
  expect((await read("other-scan")).size).toBe(0);
});
test("ignores missing cache even when the repository supplies a lookalike", async () => {
  await writeFile(join(repo, "validation.json"), JSON.stringify(conclusion));
  expect((await read()).size).toBe(0);
});
test("rejects ambiguous occurrence IDs", async () => {
  await save([conclusion, conclusion, conclusion]);
  expect((await read()).size).toBe(0);
});
test.each([
  { configuration: { ...config, extra: true } },
  { repositoryPath: "elsewhere" },
  { retry: undefined },
])("rejects a mismatched or legacy result %j", async (extra) => {
  await save([conclusion], extra);
  expect((await read()).size).toBe(0);
});
test.each([
  { issueId: "other" },
  { findingId: "other" },
  { provider: "other" },
  {
    findingArn: conclusion.findingArn.replace("/env/", "/other/"),
    issueArn: conclusion.issueArn.replace("/env/", "/other/"),
  },
])("rejects inconsistent external identity %j", async (extra) => {
  await save([{ ...conclusion, ...extra }]);
  expect((await read()).size).toBe(0);
});
test("rejects paths redirected into repository content", async () => {
  const file = join(repo, "cache");
  await writeFile(file, "{}");
  await symlink(file, path + ".result");
  expect((await read()).size).toBe(0);
});
test.each(["patch", "verify"] as const)(
  "%s asks for separate AWS and local evidence with original criteria",
  async (operation) => {
    const finding = {
      occurrenceId: "occ_a",
      remediationTests: ["criterion A"],
    };
    const context = {
      operation,
      pluginRoot: resolve("_bundled_plugin"),
      verificationIds: ["occ_a"],
    };
    const baseline = await remediationPrompt({
      ...context,
      contents: [finding],
    });
    expect(baseline).not.toContain("continuumAssessment");
    const contents = [{ ...finding, continuumAssessment: conclusion }];
    const enriched = await remediationPrompt({ ...context, contents });
    expect(enriched).toContain(JSON.stringify(contents));
    expect(enriched).toContain(
      "all its remediationTests as the acceptance criteria",
    );
    expect(enriched).toContain("separately give your local evidence");
  },
);

function saveCli(
  items: Omit<ValidationItemRecord, "severityBefore" | "severityAfter">[],
  environment = "env",
  state = root,
) {
  return saveCliContinuumAssessments(
    { CODEX_SECURITY_STATE_DIR: state },
    repo,
    "scan",
    { provider: "continuum", continuum: { environment_id: environment } },
    items.map((item) => ({
      severityBefore: "high",
      severityAfter: "high",
      ...item,
    })),
  );
}

test("loads only the requested occurrences from concurrent partial CLI batches", async () => {
  await rm(path);
  const other = { ...conclusion, itemId: "occ_b" };
  await Promise.all([
    saveCli([conclusion, { ...other, verdict: "UNAVAILABLE" }]),
    saveCli([{ ...conclusion, issueUrl: "https://console.example/issue" }]),
    saveCli([other]),
  ]);
  expect([...(await read()).entries()]).toEqual([["occ_a", conclusion]]);
  const env = { CODEX_SECURITY_STATE_DIR: root };
  expect(
    (
      await savedContinuumAssessments(env, "scan", repo, ["occ_a", "occ_b"])
    ).get("occ_b"),
  ).toEqual(other);
  expect((await read("other")).size).toBe(0);
  expect(
    (await savedContinuumAssessments(env, "scan", root, ["occ_a"])).size,
  ).toBe(0);
});

test("plugin binding restricts an ambiguous CLI selection to its destination", async () => {
  const other = {
    ...conclusion,
    findingArn: conclusion.findingArn.replace("/env/", "/other/"),
    issueArn: conclusion.issueArn.replace("/env/", "/other/"),
  };
  await saveCli([other], "other");
  expect((await read()).size).toBe(0);
  await saveCli([conclusion]);
  expect((await read()).get("occ_a")).toEqual(conclusion);
  await writeFile(path, "{");
  expect((await read()).size).toBe(0);
  await writeFile(
    path,
    JSON.stringify({
      provider: "continuum",
      continuum: { environment_id: "env", aws_region: "other" },
    }),
  );
  expect((await read()).size).toBe(0);
  await rm(path);
  expect((await read()).size).toBe(0);
});

test("keeps CLI storage outside repository control for writes and reloads", async () => {
  await expect(saveCli([conclusion], "env", repo)).rejects.toThrow();
  await saveCli([conclusion]);
  const store = (await readdir(root)).find((name) =>
    name.startsWith("cli-continuum-"),
  );
  expect(store).toBeDefined();
  const dir = join(root, store!);
  const moved = join(repo, "state");
  await rename(dir, moved);
  await symlink(moved, dir, process.platform === "win32" ? "junction" : "dir");
  expect((await read()).size).toBe(0);
  await expect(saveCli([conclusion])).rejects.toThrow();
});
test("a changed snapshot invalidates only its own occurrence across caches", async () => {
  await save([conclusion]);
  const other = { ...conclusion, itemId: "occ_b" };
  await saveCli([conclusion, other]);
  const [storage] = (await readdir(root)).filter((name) =>
    name.startsWith("cli-continuum-"),
  );
  const directory = join(root, storage!);
  for (const name of await readdir(directory)) {
    const filename = join(directory, name);
    const saved = JSON.parse(await readFile(filename, "utf8"));
    if (saved.record.itemId === "occ_a") {
      saved.record.verdict = "EXPLOITABLE";
      await writeFile(filename, JSON.stringify(saved));
    }
  }
  const results = await savedContinuumAssessments(
    { CODEX_SECURITY_STATE_DIR: root },
    "scan",
    repo,
    ["occ_a", "occ_b"],
  );
  expect([...results.values()]).toEqual([other]);
});

const observation = {
  kind: "source_analysis" as const,
  effect: "DATA_LEAKED",
  summary: "Source shows file persists.",
};
const completed = {
  ...conclusion,
  resultScope: "finding" as const,
  claimMatch: "on_target" as const,
  verdict: "EXPLOITABLE",
  issueFindingCount: 1,
  joinedValidatedIssue: false,
  freshness: { stale: false, reasons: [], validatedAt: "2026-11-21T02:00:00Z" },
  terminalStatus: "COMPLETED",
  proofObservation: observation,
};
test.each(["execution", "source_analysis"] as const)(
  "preserves %s observations for the selected run",
  async (kind) => {
    const actual = { ...observation, kind };
    await save([
      { ...completed, proofObservation: { ...actual, rawScript: "excluded" } },
    ]);
    expect((await read()).get("occ_a")?.proofObservation).toEqual(actual);
  },
);
test.each([
  {
    freshness: {
      ...completed.freshness,
      evidenceCreatedAt: "2020-01-01T00:00:00Z",
    },
  },
  { issueFindingCount: 2 },
  { joinedValidatedIssue: true },
  { terminalStatus: "FAILED" },
  { freshness: { stale: true, reasons: [] } },
  { validationArtifactId: undefined },
  { scoringArtifactId: undefined },
  { claimMatch: "unknown" },
  { claimMatch: "different_flaw" },
  { resultScope: "issue" },
  { verdict: "UNCERTAIN" },
  { freshness: { stale: false, reasons: [] } },
  {
    freshness: {
      stale: false,
      reasons: [],
      validatedAt: "2020-01-01T00:00:00Z",
    },
  },
])(
  "drops unbound proof attribution while preserving status %j",
  async (limits) => {
    await save([{ ...completed, ...limits }]);
    const result = (await read()).get("occ_a");
    expect(result?.proofObservation).toBeUndefined();
    expect(result?.verdict).toBe(limits.verdict ?? "EXPLOITABLE");
  },
);

test("an explicit CLI retry supersedes a cached plugin timeout only for the same admission", async () => {
  const timeout = {
    ...conclusion,
    verdict: "UNAVAILABLE",
    terminalStatus: undefined,
  };
  await save([timeout]);
  await saveCli([
    { ...completed, submittedAt: "2026-11-21T01:20:00Z" },
    {
      ...completed,
      findingId: "other",
      findingArn: prefix + "/code-findings/other",
    },
  ]);
  expect((await read()).get("occ_a")?.verdict).toBe("UNAVAILABLE");
  await saveCli([completed]);
  expect((await read()).get("occ_a")).toEqual(completed);
});

test("chooses the newest artifact from the same admission and issue across CLI and plugin", async () => {
  const failed = {
    ...conclusion,
    freshness: {
      ...conclusion.freshness,
      evidenceCreatedAt: "2026-11-21T01:11:00Z",
    },
  };
  await save([failed]);
  await saveCli([failed, completed]);
  expect((await read()).get("occ_a")).toEqual(completed);
  const newer = {
    ...failed,
    validationArtifactId: "newer",
    freshness: {
      ...failed.freshness,
      evidenceCreatedAt: "2026-11-21T02:30:00Z",
    },
  };
  await save([newer]);
  expect((await read()).get("occ_a")).toEqual(newer);
  await saveCli([newer]);
  await save([completed]);
  expect((await read()).get("occ_a")).toEqual(newer);
  await save([{ ...newer, validationArtifactId: "conflict" }]);
  expect((await read()).size).toBe(0);
});

test("withholds distinct terminal records without comparable lineage and times", async () => {
  await saveCli([completed]);
  await save([conclusion]);
  expect((await read()).size).toBe(0);
  await save([
    { ...completed, issueId: "other", issueArn: prefix + "/code-issues/other" },
  ]);
  expect((await read()).size).toBe(0);
});

test("retains a terminal decline that has no issue across transport failures", async () => {
  const declined = {
    ...conclusion,
    issueId: undefined,
    issueArn: undefined,
    terminalStatus: undefined,
    verdict: "DISCARDED",
  };
  await saveCli([declined]);
  await saveCli([{ ...declined, verdict: "UNAVAILABLE" }]);
  expect((await read()).get("occ_a")?.verdict).toBe("DISCARDED");
});
