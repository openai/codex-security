import { afterEach, beforeEach, expect, spyOn, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import * as filesystem from "node:fs/promises";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import * as gitMetadata from "../src/local-git-metadata.js";
import type { ValidationItemRecord } from "../src/validation-provider.js";
import { continuumAssessmentVersion } from "../src/continuum-assessment-store.js";
import {
  saveCliContinuumAssessments,
  savedContinuumAssessments,
} from "../src/saved-continuum-assessment.js";

import { assessPluginFindings } from "../src/plugin-validation.js";
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
const expected = {
  itemId: "occ_a",
  provider: "continuum",
  verdict: "UNCERTAIN",
  terminalStatus: "FAILED",
  resultScope: "issue",
  joinedValidatedIssue: true,
  claimMatch: "unknown",
  freshness: { stale: true },
} as const;
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
      schemaVersion: continuumAssessmentVersion,
      configuration: config,
      repositoryPath: repo,
      result: { provider: "continuum" },
      records: { schemaVersion: 1, items },
      retry: null,
      ...overrides,
    }),
  );
}
test("keeps provider identifiers, reasons and other free text out of model input", async () => {
  await save([
    {
      ...conclusion,
      statusMessage: "private",
      proofBody: "untrusted",
      secret: "private",
    },
  ]);
  expect((await read()).get("occ_a")).toEqual(expected);
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
test("a failed submission allows a single CLI admission without releasing partial or duplicate bindings", async () => {
  const failure = {
    provider: "continuum",
    itemId: "occ_a",
    verdict: "UNAVAILABLE",
    unavailable: "No credentials",
  };
  await save([failure]);
  expect(await saveCli([conclusion])).toBeUndefined();
  expect((await read()).get("occ_a")).toEqual(expected);
  for (const items of [
    [failure, conclusion],
    [failure, failure],
    [{ ...failure, findingId: conclusion.findingId }],
  ]) {
    await save(items);
    expect((await read()).size).toBe(0);
  }
  await save([failure]);
  await saveCli([{ ...conclusion, submittedAt: "2026-11-21T01:20:00Z" }]);
  expect((await read()).size).toBe(0);
});
test.each([
  { configuration: { ...config, extra: true } },
  { repositoryPath: "elsewhere" },
  { retry: undefined },
  { records: { schemaVersion: 1, items: [null] } },
])(
  "an invalid bound result cannot release the submission pin %j",
  async (extra) => {
    const other = {
      ...conclusion,
      findingId: "other",
      findingArn: prefix + "/code-findings/other",
    };
    await saveCli([other]);
    expect((await read()).get("occ_a")).toEqual({
      ...expected,
      itemId: other.itemId,
    });
    await save([conclusion], extra);
    expect((await read()).size).toBe(0);
  },
);
test.each([
  { issueId: "other" },
  { findingId: "other" },
  { provider: "other" },
  {
    findingArn: conclusion.findingArn.replace("/env/", "/other/"),
    issueArn: conclusion.issueArn.replace("/env/", "/other/"),
  },
])("rejects inconsistent external identity %j", async (extra) => {
  await saveCli([conclusion]);
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
  expect((await read()).get("occ_a")).toEqual(expected);
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
    expect((await read()).get("occ_a")).toEqual(expected);
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
  requestedAt?: number,
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
    requestedAt,
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
  expect([...(await read()).entries()]).toEqual([["occ_a", expected]]);
  const env = { CODEX_SECURITY_STATE_DIR: root };
  expect(
    (
      await savedContinuumAssessments(env, "scan", repo, ["occ_a", "occ_b"])
    ).get("occ_b"),
  ).toEqual({ ...expected, itemId: other.itemId });
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
  expect((await read()).get("occ_a")).toEqual(expected);
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
    expect((await read()).get("occ_a")).toEqual(expected);
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
  expect((await read()).get("occ_a")).toEqual(expected);
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
    if (!name.endsWith(".json")) continue;
    const filename = join(directory, name);
    const saved = JSON.parse(await readFile(filename, "utf8"));
    if (saved.entries[0].record.itemId === "occ_a") {
      saved.entries[0].record.verdict = "EXPLOITABLE";
      await writeFile(filename, JSON.stringify(saved));
    }
  }
  const results = await savedContinuumAssessments(
    { CODEX_SECURITY_STATE_DIR: root },
    "scan",
    repo,
    ["occ_a", "occ_b"],
  );
  expect([...results.values()]).toEqual([
    { ...expected, itemId: other.itemId },
  ]);
});

const completed = {
  ...conclusion,
  resultScope: "finding" as const,
  claimMatch: "unknown" as const,
  verdict: "EXPLOITABLE",
  issueFindingCount: 1,
  joinedValidatedIssue: false,
  freshness: { stale: false, reasons: [], validatedAt: "2026-11-21T02:00:00Z" },
  terminalStatus: "COMPLETED",
};
const expectedCompleted = {
  ...expected,
  resultScope: "finding",
  verdict: "EXPLOITABLE",
  joinedValidatedIssue: false,
  freshness: { stale: false, validatedAt: completed.freshness.validatedAt },
  terminalStatus: "COMPLETED",
} as const;
test.each([undefined, 2, 3])(
  "withholds older workbench conclusions until refreshed (version %s)",
  async (schemaVersion) => {
    await save([completed], { schemaVersion });
    await saveCli([completed]);
    expect((await read()).size).toBe(0);
  },
);

test.each([1, 2, 3])(
  "v%i CLI snapshots cannot supply or mask a refreshed assessment",
  async (schemaVersion) => {
    const repositoryPath = await realpath(repo);
    const digest = (value: string) => hash("sha256", value);
    const directory = join(
      root,
      (schemaVersion === 1
        ? "cli-continuum-"
        : `cli-continuum-v${schemaVersion}-`) +
        digest(JSON.stringify([repositoryPath, "scan"])),
    );
    await mkdir(directory, { mode: 0o700 });
    const raw = JSON.stringify({
      schemaVersion,
      repositoryPath,
      scanId: "scan",
      environmentId: "env",
      record: completed,
    });
    const filename = join(
      directory,
      ["occ_a", "env", raw].map(digest).join(".") + ".json",
    );
    await writeFile(filename, raw);
    expect((await read()).size).toBe(0);
    await saveCli([conclusion]);
    expect((await read()).get("occ_a")).toEqual(expected);
    expect(await readFile(filename, "utf8")).toEqual(raw);
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
  const warning = await saveCli([
    { ...completed, submittedAt: "2026-11-21T01:20:00Z" },
    {
      ...completed,
      findingId: "other",
      findingArn: prefix + "/code-findings/other",
    },
  ]);
  expect(warning).toContain("occ_a");
  expect((await read()).get("occ_a")?.verdict).toBe("UNAVAILABLE");
  await saveCli([completed]);
  expect((await read()).get("occ_a")).toEqual(expectedCompleted);
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
  expect((await read()).get("occ_a")).toEqual(expectedCompleted);
  const newer = {
    ...failed,
    validationArtifactId: "newer",
    freshness: {
      ...failed.freshness,
      evidenceCreatedAt: "2026-11-21T02:00:00.000001Z",
    },
  };
  await save([newer]);
  expect((await read()).get("occ_a")).toEqual({
    ...expected,
    freshness: {
      ...expected.freshness,
      evidenceCreatedAt: newer.freshness.evidenceCreatedAt,
    },
  });
  await saveCli([newer]);
  await save([completed]);
  expect((await read()).get("occ_a")).toEqual({
    ...expected,
    freshness: {
      ...expected.freshness,
      evidenceCreatedAt: newer.freshness.evidenceCreatedAt,
    },
  });
  await save([{ ...newer, validationArtifactId: "conflict" }]);
  expect((await read()).size).toBe(0);
});

test("withholds conclusions when validation times or issue identities conflict", async () => {
  await saveCli([completed]);
  await save([conclusion]);
  expect((await read()).size).toBe(0);
  for (const verdict of [completed.verdict, "UNAVAILABLE"]) {
    await save([
      {
        ...completed,
        verdict,
        issueId: "other",
        issueArn: prefix + "/code-issues/other",
      },
    ]);
    expect((await read()).size).toBe(0);
  }
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

test("concurrent CLI validations select by request order across receipt switches", async () => {
  await rm(path);
  const other = {
    ...completed,
    findingId: "other",
    findingArn: prefix + "/code-findings/other",
    submittedAt: "2026-11-21T01:20:00Z",
    verdict: "NOT_EXPLOITABLE",
  };
  // The later request finishes first.
  await saveCli([other], "env", root, 2);
  expect(await saveCli([completed], "env", root, 1)).toContain("occ_a");
  expect((await read()).get("occ_a")?.verdict).toBe("NOT_EXPLOITABLE");
  // A fresh request can switch back. Late duplicates cannot undo that choice.
  await saveCli([completed], "env", root, 4);
  await saveCli([other], "env", root, 3);
  await saveCli([completed], "env", root, 1);
  expect((await read()).get("occ_a")?.verdict).toBe("EXPLOITABLE");
});

test("a tied provider score withholds older cached scoring until a newer linked score", async () => {
  const scored = {
    ...completed,
    providerSeverity: "critical",
    reachableFromAttacker: true,
    freshness: { ...completed.freshness, scoredAt: "2026-11-21T03:00:00Z" },
  };
  await save([scored]);
  const tie = {
    ...completed,
    scoringArtifactId: undefined,
    scoringPending: true,
    freshness: { ...completed.freshness, scoredAt: "2026-11-21T03:01:00Z" },
  };
  await saveCli([tie]);
  await saveCli([{ ...tie, freshness: completed.freshness }]);
  const pending = (await read()).get("occ_a");
  expect(pending?.verdict).toBe("EXPLOITABLE");
  expect(pending?.scoringPending).toBe(true);
  expect(pending?.issueSeverity).toBeUndefined();
  expect(pending?.issueReachableFromAttacker).toBeUndefined();
  await saveCli([
    {
      ...scored,
      scoringArtifactId: "score-new",
      providerSeverity: "low",
      freshness: { ...scored.freshness, scoredAt: "2026-11-21T03:02:00Z" },
    },
  ]);
  expect((await read()).get("occ_a")).toMatchObject({
    verdict: completed.verdict,
    issueSeverity: "low",
    issueReachableFromAttacker: true,
  });
});

test("a later unresolved validation tie suppresses the prior verdict until resolved", async () => {
  await save([completed]);
  await saveCli([
    {
      ...completed,
      verdict: "UNKNOWN",
      validationArtifactId: undefined,
      scoringArtifactId: undefined,
      terminalStatus: undefined,
      freshness: {
        stale: false,
        reasons: [],
        evidenceCreatedAt: "2026-11-21T03:00:00Z",
      },
    },
  ]);
  expect((await read()).get("occ_a")?.verdict).toBe("UNKNOWN");
  await saveCli([
    {
      ...completed,
      validationArtifactId: "later",
      freshness: {
        ...completed.freshness,
        validatedAt: "2026-11-21T04:00:00Z",
      },
    },
  ]);
  expect((await read()).get("occ_a")?.verdict).toBe("EXPLOITABLE");
});

test("workbench bindings follow CODEX_HOME and explicit state overrides", async () => {
  const home = join(root, "home");
  const otherHome = join(root, "other");
  const state = join(home, "state/plugins/codex-security");
  await mkdir(state, { recursive: true });
  await save([completed]);
  await rename(dirname(path), join(state, "validation-providers"));
  const readHome = (CODEX_HOME: string, CODEX_SECURITY_STATE_DIR?: string) =>
    savedContinuumAssessments(
      { CODEX_HOME, CODEX_SECURITY_STATE_DIR },
      "scan",
      repo,
      ["occ_a"],
    );
  expect((await readHome(home)).get("occ_a")).toEqual(expectedCompleted);
  expect((await readHome(otherHome)).size).toBe(0);
  expect((await readHome(otherHome, state)).get("occ_a")).toEqual(
    expectedCompleted,
  );
});

test("revised submission and a return to the original receipt select the requested admission", async () => {
  await rm(path);
  const other = {
    ...conclusion,
    submittedAt: "2026-11-21T01:20:00Z",
    severityBefore: "high",
    severityAfter: "high",
  };
  await saveCli([completed]);
  for (let i = 0; i < 2; i++) {
    await saveCliContinuumAssessments(
      { CODEX_SECURITY_STATE_DIR: root },
      repo,
      "scan",
      config,
      [other],
    );
    expect((await read()).get("occ_a")).toEqual(expected);
  }
  await saveCli([completed]);
  expect((await read()).get("occ_a")).toEqual(expectedCompleted);
  await saveCli([
    {
      ...completed,
      findingArn: completed.findingArn.replace("123456789012", "000000000000"),
      issueArn: completed.issueArn.replace("123456789012", "000000000000"),
    },
  ]);
  expect((await read()).size).toBe(0);
});

test("a pending linked score survives transport failure unless the issue changed", async () => {
  const prior = {
    disposition: "deferred" as const,
    report: "Waiting for score",
    provenance: { provider: "continuum", providerVersion: "1" },
    record: {
      ...completed,
      severityBefore: "high",
      severityAfter: "high",
      scoringPending: true,
    },
  };
  for (const issueId of [undefined, "issue-a", "issue-b"]) {
    const provider = () => ({
      name: "continuum",
      version: "1",
      async validate() {
        if (!issueId) throw Error("signed out");
        return {
          ...prior,
          unavailable: "signed out",
          record: {
            ...prior.record,
            issueId,
            issueArn: prefix + "/code-issues/" + issueId,
            verdict: "UNAVAILABLE",
            scoringPending: undefined,
            terminalStatus: undefined,
            validationArtifactId: undefined,
          },
        };
      },
    });
    const result = await assessPluginFindings(
      config,
      [{ occurrenceId: "occ_a" }],
      { repositoryPath: repo },
      provider,
      [prior],
    );
    expect(result.retry?.[0]?.record).toMatchObject(
      issueId === "issue-b"
        ? { issueId, verdict: "UNAVAILABLE", validationArtifactId: undefined }
        : { ...prior.record, unavailable: "signed out" },
    );
  }
});

test("a change in live issue membership leaves the saved finding verdict intact", async () => {
  await save([completed]);
  await saveCli([{ ...completed, issueFindingCount: 3 }]);
  expect((await read()).get("occ_a")).toEqual(expectedCompleted);
});

test.each([true, false])(
  "rescoring one validation preserves the verdict and chooses the latest linked issue score (%s)",
  async (reverse) => {
    const first = {
      ...completed,
      providerSeverity: "high",
      freshness: {
        ...completed.freshness,
        scoredAt: "2026-11-21T03:00:00.000001Z",
      },
    };
    const second = {
      ...first,
      issueFindingCount: 2,
      scoringArtifactId: "other-score",
      providerSeverity: "critical",
      freshness: {
        ...first.freshness,
        scoredAt: "2026-11-21T03:00:00.000002Z",
      },
    };
    await save([reverse ? first : second]);
    await saveCli([
      reverse ? second : first,
      { ...completed, scoringPending: true },
    ]);
    expect((await read()).get("occ_a")).toMatchObject({
      verdict: completed.verdict,
      issueSeverity: "critical",
    });
    await saveCli([
      { ...second, scoringArtifactId: "conflict", providerSeverity: "low" },
    ]);
    expect((await read()).get("occ_a")).toEqual({
      ...expectedCompleted,
      scoringPending: true,
    });
  },
);
