import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { execFileSync } from "node:child_process";
import * as filesystem from "node:fs/promises";
import {
  chmod,
  link,
  lstat,
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
import { basename, dirname, join } from "node:path";
import * as gitMetadata from "../src/local-git-metadata.js";
import type { ValidationItemRecord } from "../src/validation-provider.js";
import { assessmentStateDirectories } from "../src/continuum-assessment-store.js";
import {
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
  await saveCli([conclusion]);
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
test("protects Git metadata resolved with the caller's environment in both stores", async () => {
  await saveCli([conclusion]);
  await save([conclusion]);
  // Windows drive-relative Git metadata can resolve inside the selected state
  // path under the caller's environment even if the ambient drive differs.
  const environment = { CODEX_SECURITY_STATE_DIR: root, "=D:": root };
  using roots = spyOn(gitMetadata, "commandGitProtectionRoots");
  roots.mockImplementation(async (_repository, env) =>
    env["=D:"] === root ? [await filesystem.realpath(root)] : [],
  );
  const load = () =>
    savedContinuumAssessments(environment, "scan", repo, ["occ_a"]);
  expect((await load()).size).toBe(0);
  await rm(path);
  expect((await load()).size).toBe(0);
  await expect(
    saveCliContinuumAssessments(environment, repo, "scan", config, [
      { ...conclusion, severityBefore: "high", severityAfter: "high" },
    ]),
  ).rejects.toThrow();
});

test("rejects a plugin assessment editable through a checkout hard link", async () => {
  await save([conclusion]);
  const alias = join(repo, "alias.json");
  await link(path + ".result", alias);
  const forged = JSON.parse(await readFile(alias, "utf8"));
  forged.records.items[0].verdict = "EXPLOITABLE";
  await writeFile(alias, JSON.stringify(forged));
  expect((await read()).size).toBe(0);
});

test("rejects plugin state in a directory another user can write", async () => {
  await save([conclusion]);
  expect((await read()).get("occ_a")).toEqual(conclusion);
  const directory = dirname(path);
  if (process.platform === "win32") {
    execFileSync("icacls.exe", [directory, "/grant", "*S-1-1-0:W"]);
  } else {
    await chmod(directory, 0o775);
  }
  expect((await read()).size).toBe(0);
});

test.skipIf(process.platform === "win32")(
  "accepts read-only sharing but rejects writable plugin files and ancestors",
  async () => {
    await save([conclusion]);
    await chmod(dirname(path), 0o755);
    for (const file of [path, path + ".result"]) {
      await chmod(file, 0o664);
      expect((await read()).size).toBe(0);
      expect((await lstat(file)).mode & 0o777).toBe(0o664);
      await chmod(file, 0o644);
    }
    expect((await read()).get("occ_a")).toEqual(conclusion);
    await chmod(root, 0o777);
    expect((await read()).size).toBe(0);
  },
);

test("rejects paths redirected into repository content", async () => {
  const file = join(repo, "cache");
  await save([conclusion]);
  await rename(path + ".result", file);
  await symlink(file, path + ".result");
  expect((await read()).size).toBe(0);
});
async function cliDirectory() {
  const name = (await readdir(root)).find((name) =>
    name.startsWith("cli-continuum-"),
  );
  if (!name) throw new Error("Missing CLI assessment directory");
  return join(root, name);
}

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

test("a writer can populate the assessment directory after another observes it empty", async () => {
  const list = filesystem.readdir;
  using listing = spyOn(filesystem, "readdir");
  listing.mockImplementation(async (...args) => {
    const entries = await Reflect.apply(list, filesystem, args);
    const directory = String(args[0]);
    if (
      entries.length === 0 &&
      basename(directory).startsWith("cli-continuum-")
    ) {
      // Interleave another writer's temporary file with any emptiness check.
      await writeFile(join(directory, "concurrent.tmp"), "");
    }
    return entries;
  });
  await saveCli([conclusion]);
  expect((await read()).get("occ_a")).toEqual(conclusion);
});

test.skipIf(process.platform === "win32")(
  "keeps a new assessment directory traversable under a restrictive owner umask",
  async () => {
    const previous = process.umask(0o100);
    try {
      await saveCli([conclusion]);
    } finally {
      process.umask(previous);
    }
    expect((await read()).get("occ_a")).toEqual(conclusion);
  },
);

test.skipIf(process.platform === "win32")(
  "rejects a shared assessment directory on reads and writes without changing its permissions",
  async () => {
    await saveCli([conclusion]);
    const directory = await cliDirectory();
    await chmod(directory, 0o770);
    expect((await read()).size).toBe(0);
    await expect(saveCli([conclusion])).rejects.toThrow();
    expect((await lstat(directory)).mode & 0o777).toBe(0o770);
  },
);

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
  const dir = await cliDirectory();
  const moved = join(repo, "state");
  await rename(dir, moved);
  await symlink(moved, dir, process.platform === "win32" ? "junction" : "dir");
  expect((await read()).size).toBe(0);
  await expect(saveCli([conclusion])).rejects.toThrow();
});

test("rejects an external state path routed through a repository link before creating it", async () => {
  const destination = join(root, "destination");
  await mkdir(destination);
  const relay = join(repo, "relay");
  const alias = join(root, "alias");
  const type = process.platform === "win32" ? "junction" : "dir";
  await symlink(destination, relay, type);
  await symlink(relay, alias, type);
  await expect(
    saveCli([conclusion], "env", join(alias, "new-state")),
  ).rejects.toThrow();
  expect(await readdir(destination)).not.toContain("new-state");
});

test("a changed snapshot invalidates only its own occurrence across caches", async () => {
  await save([conclusion]);
  const other = { ...conclusion, itemId: "occ_b" };
  await saveCli([conclusion, other]);
  const directory = await cliDirectory();
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
  {
    freshness: {
      ...completed.freshness,
      validatedAt: "2026-11-21T02:00:00.000001Z",
      evidenceCreatedAt: "2026-11-21T02:00:00.000002Z",
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
  await save([timeout], { retry: [timeout] });
  const pluginCache = await readFile(path + ".result", "utf8");
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
  expect(await readFile(path + ".result", "utf8")).toBe(pluginCache);
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
      evidenceCreatedAt: "2026-11-21T02:00:00.000001Z",
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
