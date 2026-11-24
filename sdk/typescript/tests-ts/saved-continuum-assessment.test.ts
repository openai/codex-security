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
  continuumObservations,
  type ContinuumObservation,
} from "../src/continuum-validation-evidence.js";
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

type Item = Omit<ValidationItemRecord, "severityBefore" | "severityAfter"> &
  ContinuumObservation;
function observation({
  siblingOnly,
  siblingArtifacts,
  issueChanged,
  ...item
}: Item) {
  const record = {
    severityBefore: "high",
    severityAfter: "high",
    ...structuredClone(item),
  };
  continuumObservations.set(record, {
    siblingOnly,
    siblingArtifacts,
    issueChanged,
  });
  return record;
}

function saveCli(
  items: Item[],
  environment = "env",
  state = root,
  requestedAt?: number,
) {
  return saveCliContinuumAssessments(
    { CODEX_SECURITY_STATE_DIR: state },
    repo,
    "scan",
    { provider: "continuum", continuum: { environment_id: environment } },
    items.map(observation),
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
test.each([undefined, 2, 3, 4, 5, 6])(
  "a legacy plugin verdict only binds the original admission for a fresh CLI assessment (version %s)",
  async (schemaVersion) => {
    await save(
      [
        {
          ...completed,
          ...(schemaVersion === undefined || schemaVersion < 4
            ? {
                claimMatch: "on_target",
                proofObservation: { kind: "execution" },
              }
            : {}),
        },
      ],
      { schemaVersion },
    );
    expect((await read()).size).toBe(0);
    await saveCli([{ ...completed, submittedAt: "2026-11-21T01:20:00Z" }]);
    expect((await read()).size).toBe(0);
    await saveCli([conclusion]);
    expect((await read()).get("occ_a")).toEqual(expected);
  },
);

test.each([1, 2, 3, 4, 5, 6])(
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
    const entry = { environmentId: "env", record: completed };
    const entries = [entry];
    const raw = JSON.stringify({
      schemaVersion,
      repositoryPath,
      scanId: "scan",
      ...(schemaVersion >= 4
        ? { entries, checksum: digest(JSON.stringify(entries)) }
        : entry),
    });
    const parts = ["occ_a", "env"];
    if (schemaVersion < 4) parts.push(raw);
    const filename = join(directory, parts.map(digest).join(".") + ".json");
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

const scored = {
  ...completed,
  providerSeverity: "critical",
  reachableFromAttacker: true,
  freshness: { ...completed.freshness, scoredAt: "2026-11-21T03:00:00Z" },
};

test("a tied provider score withholds older cached scoring until a newer linked score", async () => {
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

test("changed CLI opt-in and a return to the original receipt select the requested admission", async () => {
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
      {
        ...config,
        continuum: { ...config.continuum, include_local_validation: true },
      },
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

test("a failed legacy refresh retains only the admission for a valid same-submission CLI result", async () => {
  const legacy = {
    ...completed,
    claimMatch: "on_target",
    proofObservation: { kind: "execution" },
  };
  await save([legacy], { schemaVersion: 3 });
  const result = await pollPlugin(Error("signed out"));
  expect(result.records.items[0]).toMatchObject({
    findingArn: completed.findingArn,
    submittedAt: completed.submittedAt,
    claimMatch: "unknown",
    verdict: "UNAVAILABLE",
  });
  expect(result.records.items[0]).not.toHaveProperty("proofObservation");
  await saveCli([conclusion]);
  expect((await read()).get("occ_a")).toEqual(expected);
});

test.each(["duplicate", "invalid"])(
  "failed refreshes of a %s legacy admission keep unrelated CLI evidence out until recovery",
  async (kind) => {
    const third = {
      ...completed,
      findingId: "third",
      findingArn: prefix + "/code-findings/third",
      verdict: "NOT_EXPLOITABLE",
    };
    const legacy =
      kind === "duplicate"
        ? [
            completed,
            {
              ...completed,
              findingId: "other",
              findingArn: prefix + "/code-findings/other",
            },
          ]
        : [{ ...completed, findingId: "wrong" }];
    await save(legacy, { schemaVersion: kind === "duplicate" ? 4 : 3 });
    await saveCli([third]);
    expect((await read()).size).toBe(0);
    for (let attempt = 0; attempt < 2; attempt++) {
      const result = await pollPlugin(Error("signed out"));
      expect(result.summary).toContain("ambiguous");
      expect((await read()).size).toBe(0);
    }
    await pollPlugin(completed);
    expect((await read()).get("occ_a")).toEqual(expectedCompleted);
  },
);

const pendingScore = {
  ...completed,
  scoringArtifactId: undefined,
  scoringPending: true,
};
const moved = {
  ...pendingScore,
  issueId: "next",
  issueArn: prefix + "/code-issues/next",
  verdict: "NOT_EXPLOITABLE",
  freshness: { ...completed.freshness, validatedAt: "2026-11-21T01:30:00Z" },
};
const validationTie = {
  ...completed,
  unavailable: "Conflicting validation artifacts (first, second)",
  verdict: "UNKNOWN",
  terminalStatus: undefined,
  resultScope: "issue" as const,
  validationArtifactId: undefined,
  scoringArtifactId: undefined,
  freshness: {
    stale: false,
    reasons: [],
    evidenceCreatedAt: completed.freshness.validatedAt,
  },
};

const unlinked = {
  ...validationTie,
  verdict: "UNAVAILABLE",
  unavailable: "Association pending",
  issueUnlinked: true as const,
  freshness: { stale: false, reasons: [] },
};
const newerValidation = {
  ...completed,
  validationArtifactId: "resolved",
  freshness: {
    ...completed.freshness,
    validatedAt: "2026-11-21T02:00:00.000001Z",
  },
};

test("a confirmed issue move supersedes the old verdict and score in CLI request order", async () => {
  await rm(path);
  // The old poll finishes late and has newer evidence for a different issue.
  await saveCli([moved], "env", root, 2);
  expect(await saveCli([scored], "env", root, 1)).toContain("occ_a");
  const selected = (await read()).get("occ_a");
  expect(selected?.verdict).toBe("NOT_EXPLOITABLE");
  expect(selected?.issueSeverity).toBeUndefined();
  expect(selected?.issueReachableFromAttacker).toBeUndefined();

  // A failed lookup on the way back cannot revive either verdict.
  await saveCli([{ ...completed, verdict: "UNAVAILABLE" }], "env", root, 3);
  expect((await read()).size).toBe(0);
  expect(await saveCli([pendingScore], "env", root, 4)).toBeUndefined();
  expect((await read()).get("occ_a")).toEqual({
    ...expectedCompleted,
    scoringPending: true,
  });
  await writeFile(path, JSON.stringify(config));
  await save([scored]);
  expect((await read()).get("occ_a")?.issueSeverity).toBeUndefined();
});

test("returning to an issue does not settle a disputed verdict", async () => {
  await saveCli([validationTie]);
  await saveCli([moved]);
  await saveCli([completed]);
  expect((await read()).size).toBe(0);
  await saveCli([newerValidation]);
  expect((await read()).get("occ_a")?.verdict).toBe("EXPLOITABLE");
});

test("undated evidence from a detached issue cannot mask a dated confirmation", async () => {
  await saveCli([{ ...completed, freshness: { stale: false, reasons: [] } }]);
  await saveCli([unlinked]);
  await saveCli([completed]);
  expect((await read()).get("occ_a")).toEqual(expectedCompleted);
});

test("a fallback for other members cannot mask a confirmed validation after relinking", async () => {
  const fallback = { ...newerValidation, resultScope: "issue" as const };
  await saveCli([fallback]); // Older releases did not mark other members' runs.
  await saveCli([unlinked]);
  await saveCli([
    { ...completed, siblingArtifacts: [fallback.validationArtifactId] },
  ]);
  expect((await read()).get("occ_a")).toEqual(expectedCompleted);
});

test("a return during one CLI poll cannot restore the score from an earlier visit", async () => {
  await saveCli([scored]);
  await saveCli([{ ...pendingScore, issueChanged: true }]);
  expect((await read()).get("occ_a")).toEqual({
    ...expectedCompleted,
    scoringPending: true,
  });
});

test("issue moves require ordered CLI evidence and agreement with the workbench", async () => {
  await saveCli([completed, moved], "env", root, 1);
  expect((await read()).size).toBe(0);
  await save([completed]);
  expect(await saveCli([moved], "env", root, 2)).toContain("occ_a");
  expect((await read()).size).toBe(0);
  await save([moved]);
  expect((await read()).get("occ_a")?.verdict).toBe("NOT_EXPLOITABLE");
});

test("a confirmed unlink suppresses previous verdicts until the issue is established again", async () => {
  await saveCli([completed]);
  await save([unlinked]);
  expect((await read()).size).toBe(0);
  await rm(path + ".result");
  await saveCli([unlinked]);
  expect((await read()).get("occ_a")?.verdict).toBe("UNAVAILABLE");
  await saveCli([moved]);
  expect((await read()).get("occ_a")?.verdict).toBe("NOT_EXPLOITABLE");
});

async function pollPlugin(item: Item | Error, occurrences = ["occ_a"]) {
  const file = Bun.file(path + ".result");
  const previous = (await file.exists()) ? await file.json() : undefined;
  const result = await assessPluginFindings(
    config,
    occurrences.map((occurrenceId) => ({ occurrenceId })),
    { repositoryPath: repo },
    () => ({
      name: "continuum",
      version: "1",
      async validate({ occurrenceId }: Record<string, unknown>) {
        if (item instanceof Error) throw item;
        if (occurrenceId !== item.itemId) throw Error("Submission failed");
        return {
          disposition:
            item.unavailable || item.scoringPending ? "deferred" : "reportable",
          report: item.unavailable ?? item.verdict,
          unavailable: item.unavailable,
          provenance: { provider: "continuum", providerVersion: "1" },
          record: observation(item),
        };
      },
    }),
    previous?.retry ?? [],
    previous?.schemaVersion === continuumAssessmentVersion
      ? []
      : previous?.records.items,
    previous?.polls,
  );
  await save(result.records.items, {
    retry: result.retry,
    polls: result.polls,
  });
  return result;
}

test("a validation dispute survives unlinking until a newer validation arrives", async () => {
  await pollPlugin(validationTie);
  await pollPlugin(unlinked);
  for (const validatedAt of [
    completed.freshness.validatedAt,
    "2026-11-21T01:59:00Z",
  ]) {
    const result = await pollPlugin({
      ...completed,
      issueFindingCount: 3,
      providerSeverity: "high",
      freshness: { ...completed.freshness, validatedAt },
    });
    expect(result.status).toBe("incomplete");
    expect(result.records.items[0]).toMatchObject({
      verdict: "UNKNOWN",
      issueFindingCount: 3,
      providerSeverity: "high",
    });
    expect(result.report).toContain(validationTie.unavailable);
    expect(result.report).not.toContain(completed.verdict);
  }
  expect((await pollPlugin(newerValidation)).status).toBe("complete");
});

test("a validation dispute does not block a different issue", async () => {
  await pollPlugin(validationTie);
  const result = await pollPlugin({
    ...completed,
    issueId: moved.issueId,
    issueArn: moved.issueArn,
  });
  expect(result.status).toBe("complete");
});

const scoreTie = { ...pendingScore, freshness: scored.freshness };
const newerScore = {
  ...scored,
  freshness: { ...scored.freshness, scoredAt: "2026-11-21T03:00:00.000001Z" },
};
const olderValidation = {
  ...pendingScore,
  validationArtifactId: "earlier",
  freshness: { ...completed.freshness, validatedAt: "2026-11-21T01:30:00Z" },
};

test("a first association without evidence can be completed by the CLI", async () => {
  await pollPlugin({
    ...unlinked,
    issueUnlinked: undefined,
    issueChanged: true,
  });
  await saveCli([scored]);
  expect((await read()).get("occ_a")?.issueSeverity).toBe("critical");
});

test("a sibling-only bundle cannot resolve a disputed issue score after a move", async () => {
  const sibling = {
    ...newerValidation,
    resultScope: "issue" as const,
    siblingOnly: true,
  };
  await pollPlugin({ ...scoreTie, resultScope: "issue", siblingOnly: false });
  await pollPlugin(unlinked);
  await pollPlugin(sibling);
  await saveCli([sibling]);
  expect((await read()).size).toBe(0);
});

test("a fresh score dispute also applies to an unmarked copy of the same issue fallback", async () => {
  await saveCli([{ ...scored, resultScope: "issue" }]);
  await saveCli([{ ...scoreTie, resultScope: "issue", siblingOnly: true }]);
  expect((await read()).get("occ_a")?.scoringPending).toBe(true);
});

test("a failed score lookup preserves the dispute but its error clears on retry", async () => {
  await pollPlugin(scoreTie);
  const unavailable = "Score lookup failed";
  const failed = await pollPlugin({
    ...pendingScore,
    unavailable,
    reasons: [{ basis: "INFERRED", reason: unavailable }],
  });
  expect(failed.report).toContain(unavailable);
  expect(failed.records.items[0]?.freshness.scoredAt).toBe(
    scored.freshness.scoredAt,
  );
  const retry = await pollPlugin({
    ...scored,
    freshness: { ...scored.freshness, scoredAt: "2026-11-21T02:59:00Z" },
  });
  expect(retry.report).toContain("newer score");
  expect(JSON.stringify(retry.records)).not.toContain(unavailable);
});

test("returning to an issue requires confirming its validation and resolving its score dispute", async () => {
  await pollPlugin(scoreTie);
  expect((await pollPlugin(olderValidation)).records.items[0]?.verdict).toBe(
    completed.verdict,
  );
  await pollPlugin(moved);
  expect((await pollPlugin(olderValidation)).records.items[0]?.verdict).toBe(
    "UNKNOWN",
  );

  expect((await pollPlugin(scored)).retry).not.toBeNull();
  expect((await read()).get("occ_a")).toEqual({
    ...expectedCompleted,
    scoringPending: true,
    freshness: {
      ...expectedCompleted.freshness,
      scoredAt: scored.freshness.scoredAt,
    },
  });
  expect((await pollPlugin(newerScore)).retry).toBeNull();
  expect((await read()).get("occ_a")).toMatchObject({
    verdict: "EXPLOITABLE",
    issueSeverity: "critical",
    issueReachableFromAttacker: true,
  });
});

test("only a CLI request started after the plugin saw the issue return can confirm its score", async () => {
  // A failed first submission leaves a retry without a corresponding record.
  const retry = (item: Item) => pollPlugin(item, ["occ_b", "occ_a"]);
  await retry(scoreTie);
  await retry(moved);
  await retry(olderValidation);
  await saveCli([newerScore], "env", root, 1);
  expect((await read()).get("occ_a")?.issueSeverity).toBeUndefined();
  await saveCli([scored]);
  expect((await read()).get("occ_a")).toEqual({
    ...expectedCompleted,
    scoringPending: true,
  });
  await retry(pendingScore);
  expect((await read()).get("occ_a")?.issueSeverity).toBeUndefined();
  await saveCli([newerScore]);
  expect((await read()).get("occ_a")?.issueSeverity).toBe("critical");
  await retry(olderValidation);
  expect((await read()).get("occ_a")?.issueSeverity).toBe("critical");
});

test("a fresh workbench poll can confirm a verdict before its score after a CLI-only unlink", async () => {
  await pollPlugin(scoreTie);
  await saveCli([unlinked]);
  await saveCli([olderValidation]);
  expect((await read()).size).toBe(0);
  await pollPlugin(scored);
  const pending = (await read()).get("occ_a");
  expect(pending?.verdict).toBe("EXPLOITABLE");
  expect(pending?.issueSeverity).toBeUndefined();
  await pollPlugin(newerScore);
  expect((await read()).get("occ_a")?.issueSeverity).toBe("critical");
});

test("a workbench batch spanning a CLI unlink cannot confirm the return", async () => {
  await save([scored], {
    polls: { occ_a: { requestedAt: 1, changedAt: 4 } },
  });
  await saveCli([unlinked], "env", root, 2);
  await saveCli([{ ...completed, verdict: "UNAVAILABLE" }], "env", root, 3);
  expect((await read()).size).toBe(0);
});

test.each(["move", "unlink"])(
  "a workbench score read after a CLI %s but during an unlink cannot confirm the return",
  async (firstResult) => {
    // The first CLI request finishes after the second and the workbench poll.
    await saveCli([firstResult === "move" ? moved : unlinked], "env", root, 2);
    await pollPlugin(scored);
    await saveCli([unlinked], "env", root, 1);
    await saveCli([pendingScore]);
    expect((await read()).get("occ_a")?.scoringPending).toBe(true);
  },
);

test("a CLI verdict from before unlinking cannot return when plugin retries finish", async () => {
  const opposite = { ...newerValidation, verdict: "NOT_EXPLOITABLE" } as const;
  await saveCli([opposite], "env", root, 1);
  await pollPlugin(unlinked);
  expect((await pollPlugin(pendingScore)).retry).not.toBeNull();
  expect((await read()).size).toBe(0);
  expect((await pollPlugin(completed)).retry).toBeNull();
  expect((await read()).size).toBe(0);
  await saveCli([opposite]);
  expect((await read()).get("occ_a")?.verdict).toBe(opposite.verdict);
});

test("a newer score cannot resolve conflicting validations at the same time", async () => {
  await pollPlugin(scoreTie);
  const conflict = await pollPlugin({
    ...scored,
    validationArtifactId: "other",
    verdict: "NOT_EXPLOITABLE",
  });
  expect(conflict.records.items[0]?.verdict).toBe("UNKNOWN");
  expect(conflict.records.items[0]?.validationArtifactId).toBeUndefined();
  expect((await pollPlugin(newerScore)).status).toBe("incomplete");
});

test.each([undefined, "issue-a", "issue-b"])(
  "a pending linked score survives transport failure unless the issue changed (%s)",
  async (issueId) => {
    const prior = { ...completed, scoringPending: true };
    await pollPlugin(prior);
    const result = await pollPlugin(
      issueId
        ? {
            ...completed,
            issueId,
            issueArn: prefix + "/code-issues/" + issueId,
            verdict: "UNAVAILABLE",
            unavailable: "signed out",
            terminalStatus: undefined,
            validationArtifactId: undefined,
          }
        : Error("signed out"),
    );
    expect(result.retry?.[0]?.record).toMatchObject(
      issueId === "issue-b"
        ? { issueId, verdict: "UNAVAILABLE", validationArtifactId: undefined }
        : {
            ...prior,
            severityBefore: "high",
            severityAfter: "high",
            unavailable: "signed out",
          },
    );
  },
);

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
