import { setFindingIdentity, sha256 } from "./support/finding-identity.js";
import { existsSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { readFile, writeFile, mkdir, chmod } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
import {
  LocalDeduplication,
  type FindingEmbeddingBinding,
} from "../src/deduplication/local.js";
import {
  deduplicateScanDirectoryInternal,
  deduplicateScanInternal,
} from "../src/deduplication/scan.js";
import { FindingWorkflow } from "../src/finding-workflow.js";
import {
  EMBEDDING_DIMENSIONS,
  EMBEDDING_MODEL,
  type FindingEmbedder,
} from "../src/server/embeddings.js";
import { SqliteFindingsStore } from "../src/server/sqlite-store.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { workflowFixture } from "./support/workflow-fixture.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { emptyNeighborhoodReviewer } from "./support/deduplication.js";
import { screeningPairSlot } from "../src/deduplication/deduplication-reviewer.js";
import { rejecting } from "./support/errors.js";
import { PLUGIN_ROOT } from "./plugin-root.js";
import type { Finding } from "../src/models.js";
import type { CodexReview } from "../src/deduplication/codex-review.js";
import { comparisonEnvironment } from "../src/scan-comparison.js";
import { reviewSettingsDigest } from "../src/deduplication/checkpointed-review.js";

const temporaryDirectories = createTemporaryDirectories();
afterEach(temporaryDirectories.cleanup);
const vector = [1, ...Array<number>(EMBEDDING_DIMENSIONS - 1).fill(0)];

for (const mode of ["direct", "fresh workflow", "resumed workflow"]) {
  test.skipIf(process.platform === "win32")(
    `directory dedupe rejects repository Python before probing it from another directory (${mode})`,
    async () => {
      const f = await fixture();
      const options = {
        repository: f.repository,
        embedding: f.embedding,
        ...(mode === "direct" ? {} : { workflowId: "protected-python" }),
      };
      if (mode === "resumed workflow") {
        await deduplicateScanDirectoryInternal(f.scanDir, options, {
          environment: f.environment,
          reviewer: emptyNeighborhoodReviewer(),
        });
        f.embed.mockClear();
      }
      const python = join(f.repository, "python3");
      const marker = join(f.root, "python-probed");
      await writeFile(
        python,
        '#!/bin/sh\nprintf "probed" > "$TEST_PYTHON_PROBE"\nprintf "codex-security-python-ok\\n"\n',
      );
      await chmod(python, 0o700);
      expect(process.cwd()).not.toBe(f.repository);
      await expect(
        deduplicateScanDirectoryInternal(f.scanDir, options, {
          environment: {
            ...f.environment,
            PYTHON: python,
            TEST_PYTHON_PROBE: marker,
          },
          runWorkbench: rejecting("Repository Python reached the workbench"),
          reviewer: emptyNeighborhoodReviewer(),
        }),
      ).rejects.toThrow("PYTHON interpreter is unavailable or unusable");
      expect(existsSync(marker)).toBe(false);
      expect(f.embed).not.toHaveBeenCalled();
    },
  );
}

function duplicateReviewer() {
  return {
    screen: mock(async (findings: readonly Finding[]) => ({
      decisions: Object.fromEntries(
        findings
          .slice(1)
          .map((_, index) => [
            screeningPairSlot(index),
            { decision: "SAME" as const, rationale: "Same control" },
          ]),
      ),
    })),
    reviewPair: mock(async (findings: readonly Finding[]) => ({
      decision: "SAME" as const,
      rationale: "Same control",
      canonicalFindingId: findings[0]!.findingId,
      mergedFinding: findings[0]!,
    })),
  };
}

test.each([undefined, "", " \t", "synthetic-primary"])(
  "local embeddings select the first nonblank API key (primary: %j)",
  async (primary) => {
    const f = await fixture();
    const finding = f.document.findings[0]!;
    const request = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({
        model: EMBEDDING_MODEL,
        data: [{ index: 0, embedding: vector }],
      }),
    );
    try {
      const local = new LocalDeduplication(
        {
          ...f.environment,
          OPENAI_API_KEY: primary,
          CODEX_API_KEY: "synthetic-secondary",
        },
        { repositoryId: f.targetId },
        f.repository,
        undefined,
        async (_options, _args, input) =>
          JSON.parse(input!).action === "prepare"
            ? JSON.parse(
                JSON.stringify({
                  cacheKeys: { [finding.findingId]: "synthetic-cache-key" },
                  findingsToEmbed: [finding],
                }),
              )
            : {},
      );
      await local.prepare([finding], f.targetId);
      expect(request).toHaveBeenCalledTimes(1);
      expect(request.mock.calls[0]![1]?.headers).toMatchObject({
        Authorization: `Bearer ${primary?.trim() ? primary : "synthetic-secondary"}`,
      });
    } finally {
      request.mockRestore();
    }
  },
);

async function fixture() {
  const value = await workflowFixture();
  temporaryDirectories.track(value.root);
  const manifestPath = join(value.scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const targetId = `target_sha256_${sha256(`local-workspace\0${value.repository}`)}`;
  manifest.scan.target.targetId = targetId;
  for (const finding of value.document.findings)
    setFindingIdentity(manifest.scan, finding);
  const findingsText = JSON.stringify(value.document);
  await writeFile(join(value.scanDir, "findings.json"), findingsText);
  manifest.scan.artifacts.find(
    (artifact: { path: string }) => artifact.path === "findings.json",
  ).sha256 = sha256(findingsText);
  await writeFile(manifestPath, JSON.stringify(manifest));
  const options = {
    environment: value.environment,
    pluginRoot: PLUGIN_ROOT,
    python: await resolvePluginPython({ environment: value.environment }),
  };
  const embed = mock(async (findings: readonly Finding[]) =>
    findings.map(() => ({ model: EMBEDDING_MODEL, vector })),
  );
  const embedding: FindingEmbeddingBinding = {
    embedder: { embed },
    model: EMBEDDING_MODEL,
    dimensions: EMBEDDING_DIMENSIONS,
    cacheNamespace: "synthetic-default-v1",
  };
  const local = (
    embedder: FindingEmbedder = { embed },
    allRepositories = false,
    signal?: AbortSignal,
  ) =>
    new LocalDeduplication(
      value.environment,
      allRepositories ? { allRepositories: true } : { repositoryId: targetId },
      value.repository,
      signal,
      undefined,
      { ...embedding, embedder },
    );
  return {
    ...value,
    targetId,
    options,
    embed,
    embedding,
    local,
    store: new SqliteFindingsStore(value.environment),
  };
}

test("local dedupe indexes a sealed directory, reuses vectors and never calls the findings API", async () => {
  const f = await fixture();
  const original = await readFile(join(f.scanDir, "findings.json"), "utf8");
  const dependencies = {
    environment: f.environment,
    reviewer: emptyNeighborhoodReviewer(),
    fetch: rejecting("Unexpected findings HTTP call"),
  };
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    { repository: f.repository, embedding: f.embedding },
    dependencies,
  );
  expect(result.deduplicationStatus).toBe("completed");
  expect(f.embed).toHaveBeenCalledTimes(1);
  const history = async (args: readonly string[], input?: string) =>
    args[0] === "get-scan"
      ? {
          scan: {
            scanId: f.document.scanId,
            scanDir: f.scanDir,
            targetPath: f.repository,
            progress: { status: "complete" },
          },
        }
      : await runWorkbench(f.options, args, input);
  expect(
    await deduplicateScanInternal(
      f.document.scanId,
      { embedding: f.embedding },
      { ...dependencies, runWorkbench: history },
    ),
  ).toEqual(result);
  expect(f.embed).toHaveBeenCalledTimes(1);
  expect(await readFile(join(f.scanDir, "findings.json"), "utf8")).toBe(
    original,
  );
});

test("saved-scan local review persists a group with an existing repository finding", async () => {
  const f = await fixture();
  const anchor = f.document.findings[0]!;
  const neighbor = {
    ...anchor,
    findingId: "csf_neighbor",
    fingerprints: { ...anchor.fingerprints, primary: "neighbor" },
  };
  await f.store.insert(
    [{ finding: neighbor, embedding: { model: EMBEDDING_MODEL, vector } }],
    f.targetId,
  );
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    { repository: f.repository, embedding: f.embedding },
    {
      environment: f.environment,
      fetch: rejecting("Unexpected HTTP call"),
      reviewer: duplicateReviewer(),
    },
  );
  expect(result.duplicateGroups).toHaveLength(1);
  expect(new Set(result.duplicateGroups[0])).toEqual(
    new Set([anchor.findingId, neighbor.findingId]),
  );
  expect(await f.store.listDedupeGroups(anchor.findingId)).toHaveLength(1);
  expect(f.embed).toHaveBeenCalledTimes(1);
  expect(f.embed.mock.calls[0]![0]).toHaveLength(2);
});

test("saved-scan dedupe uses configured Codex models and efforts for both review stages", async () => {
  const f = await fixture();
  await mkdir(f.environment.CODEX_HOME);
  await writeFile(
    join(f.environment.CODEX_HOME, "config.toml"),
    'model = "synthetic-configured"\nmodel_reasoning_effort = "medium"\n',
  );
  const anchor = f.document.findings[0]!;
  await f.store.insert(
    [
      {
        finding: {
          ...anchor,
          findingId: "csf_neighbor",
          fingerprints: { ...anchor.fingerprints, primary: "neighbor" },
        },
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    f.targetId,
  );
  const calls: string[][] = [];
  await deduplicateScanDirectoryInternal(
    f.scanDir,
    { repository: f.repository, embedding: f.embedding },
    {
      environment: f.environment,
      reviewRunner: {
        async run<T>(review: CodexReview<T>): Promise<T> {
          calls.push([review.stage, review.model, review.effort]);
          return review.validate(
            review.stage === "screening"
              ? {
                  decisions: {
                    "pair-1": {
                      decision: "SAME",
                      rationale: "Review together",
                    },
                  },
                }
              : { decision: "DISTINCT", rationale: "Independent fixes" },
          );
        },
      },
    },
  );
  expect(calls).toEqual([
    ["screening", "synthetic-configured", "medium"],
    ["pair-review", "synthetic-configured", "medium"],
  ]);
});

test.each(["environment", "configuration"])(
  "workflow ignores native SQLite writes but detects source changes (%s)",
  async (selection) => {
    const f = await fixture();
    const sqliteHome = join(f.repository, "runtime", "native");
    await mkdir(f.environment.CODEX_HOME, { recursive: true });
    if (selection === "configuration")
      await writeFile(
        join(f.environment.CODEX_HOME, "config.toml"),
        `sqlite_home = ${JSON.stringify(sqliteHome)}\n`,
      );
    await writeFile(join(f.repository, "source.py"), "original source\n");
    await writeFile(join(f.repository, ".gitignore"), "runtime/\nsource.py\n");
    const anchor = f.document.findings[0]!;
    await f.store.insert(
      [
        {
          finding: {
            ...anchor,
            findingId: "csf_neighbor",
            fingerprints: { ...anchor.fingerprints, primary: "neighbor" },
          },
          embedding: { model: EMBEDDING_MODEL, vector },
        },
      ],
      f.targetId,
    );
    const environment = {
      ...f.environment,
      OPENAI_API_KEY: "synthetic-review-key",
      ...(selection === "environment" ? { CODEX_SQLITE_HOME: sqliteHome } : {}),
    };
    let calls = 0;
    let mutateSource = false;
    let loseAcknowledgement = true;
    const options = {
      repository: f.repository,
      workflowId: `native-state-${selection}`,
      embedding: f.embedding,
    };
    const dependencies = {
      environment,
      runWorkbench: async (args: readonly string[], input?: string) => {
        const result = await runWorkbench(f.options, args, input);
        if (args[0] === "store-dedupe-groups" && loseAcknowledgement) {
          loseAcknowledgement = false;
          throw new Error("Lost native-state group acknowledgement");
        }
        return result;
      },
      reviewRunner: {
        async run<T>(review: CodexReview<T>): Promise<T> {
          calls++;
          await mkdir(sqliteHome, { recursive: true });
          await writeFile(
            join(sqliteHome, "state_5.sqlite"),
            `synthetic native state ${calls}`,
          );
          if (mutateSource)
            await writeFile(
              join(f.repository, "source.py"),
              "changed source\n",
            );
          const decision = { decision: "SAME", rationale: "Same control" };
          return review.validate(
            review.stage === "screening"
              ? { decisions: { "pair-1": decision } }
              : decision,
          );
        },
      },
    };
    await expect(
      deduplicateScanDirectoryInternal(f.scanDir, options, dependencies),
    ).rejects.toThrow("Lost native-state group acknowledgement");
    expect(calls).toBe(2);
    await writeFile(
      join(sqliteHome, "state_5.sqlite-wal"),
      "later native activity",
    );
    expect(
      (await deduplicateScanDirectoryInternal(f.scanDir, options, dependencies))
        .deduplicationStatus,
    ).toBe("completed");
    expect(calls).toBe(2);
    mutateSource = true;
    await expect(
      deduplicateScanDirectoryInternal(
        f.scanDir,
        { ...options, workflowId: `${options.workflowId}-source-change` },
        dependencies,
      ),
    ).rejects.toThrow("Source changed during deduplication");
  },
);

test.each([
  "stored-login",
  "managed-defaults",
  "environment-key",
  "command-auth",
])(
  "saved-scan reviews select models from the effective %s provider environment",
  async (selection) => {
    const f = await fixture();
    await mkdir(f.environment.CODEX_HOME);
    const credentialHome = join(
      f.environment.CODEX_SECURITY_STATE_DIR,
      "codex-home",
    );
    await mkdir(credentialHome, { recursive: true });
    await writeFile(
      join(f.environment.CODEX_HOME, "config.toml"),
      [
        'model = "ambient-model"',
        'model_reasoning_effort = "medium"',
        ...(selection === "managed-defaults"
          ? []
          : [
              'model_provider = "ambient-provider"',
              "[model_providers.ambient-provider]",
              'name = "Synthetic ambient provider"',
              'wire_api = "responses"',
              'base_url = "https://ambient.example.test/v1"',
              'env_key = "SYNTHETIC_PROVIDER_KEY"',
            ]),
        ...(selection === "command-auth"
          ? ['auth = { command = "synthetic-auth" }']
          : []),
      ].join("\n"),
    );
    await writeFile(
      join(credentialHome, "config.toml"),
      selection === "managed-defaults"
        ? '[permissions.synthetic]\nextends = ":read-only"\n'
        : 'model = "stored-model"\nmodel_reasoning_effort = "high"\n',
    );
    const anchor = f.document.findings[0]!;
    await f.store.insert(
      [
        {
          finding: {
            ...anchor,
            findingId: "csf_neighbor",
            fingerprints: { ...anchor.fingerprints, primary: "neighbor" },
          },
          embedding: { model: EMBEDDING_MODEL, vector },
        },
      ],
      f.targetId,
    );
    const environment = {
      ...f.environment,
      ...(selection === "environment-key"
        ? { OPENAI_API_KEY: "synthetic-embedding-and-review-key" }
        : {}),
    };
    const originalEnvironment = { ...environment };
    const accountStatus = mock(async () => ({
      authenticated: true,
      details: "Synthetic signed-in account",
    }));
    const calls: string[][] = [];
    let selectedEnvironment: NodeJS.ProcessEnv = environment;
    const bindings: {
      model: string;
      effort: string;
      settingsDigest: string;
    }[] = [];
    await deduplicateScanDirectoryInternal(
      f.scanDir,
      {
        repository: f.repository,
        embedding: f.embedding,
        workflowId: `effective-${selection}`,
      },
      {
        environment,
        resolveReviewEnvironment: async (source, _accountStatus, signal) => {
          selectedEnvironment = await comparisonEnvironment(
            source,
            accountStatus,
            signal,
            async () => credentialHome,
          );
          return selectedEnvironment as Record<string, string>;
        },
        runWorkbench: async (args, input) => {
          const payload = input ? JSON.parse(input) : {};
          if (payload.action === "save-review") bindings.push(payload.binding);
          return runWorkbench(f.options, args, input);
        },
        reviewRunner: {
          async run<T>(review: CodexReview<T>): Promise<T> {
            calls.push([review.stage, review.model, review.effort]);
            return review.validate(
              review.stage === "screening"
                ? {
                    decisions: {
                      "pair-1": {
                        decision: "SAME",
                        rationale: "Compare the complete originals",
                      },
                    },
                  }
                : { decision: "DISTINCT", rationale: "Independent controls" },
            );
          },
        },
      },
    );
    const settings =
      selection === "stored-login"
        ? ["stored-model", "high"]
        : ["ambient-model", "medium"];
    expect(calls).toEqual([
      ["screening", ...settings],
      ["pair-review", ...settings],
    ]);
    expect(bindings.map(({ model, effort }) => [model, effort])).toEqual([
      settings,
      settings,
    ]);
    const digest = await reviewSettingsDigest(selectedEnvironment, {
      model: settings[0]!,
      model_reasoning_effort: settings[1]!,
    });
    expect(bindings.every((binding) => binding.settingsDigest === digest)).toBe(
      true,
    );
    expect(accountStatus).toHaveBeenCalledTimes(
      ["stored-login", "managed-defaults"].includes(selection) ? 1 : 0,
    );
    expect(environment).toEqual(originalEnvironment);
  },
);

test("all-repository reviews receive stored source associations without rewriting findings", async () => {
  const f = await fixture();
  const anchor = f.document.findings[0]!;
  const neighbor = {
    ...anchor,
    findingId: "__proto__",
    fingerprints: { ...anchor.fingerprints, primary: "other-repository" },
  };
  await f.store.insert(
    [{ finding: neighbor, embedding: { model: EMBEDDING_MODEL, vector } }],
    "repository-b",
  );
  const contexts: unknown[] = [];
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    { repository: f.repository, embedding: f.embedding, allRepositories: true },
    {
      environment: f.environment,
      reviewRunner: {
        async run<T>(review: CodexReview<T>): Promise<T> {
          const context = review.prompt
            .split("\n")
            .find((line) => line.startsWith('{"approvedRepositoryId":'))!;
          contexts.push(JSON.parse(context));
          return review.validate(
            review.stage === "screening"
              ? {
                  decisions: {
                    "pair-1": {
                      decision: "SAME",
                      rationale: "Review the supplied evidence independently",
                    },
                  },
                }
              : { decision: "DISTINCT", rationale: "Separate source controls" },
          );
        },
      },
    },
  );
  expect(contexts).toHaveLength(2);
  for (const context of contexts)
    expect(context).toEqual({
      approvedRepositoryId: f.targetId,
      findings: [
        { findingId: anchor.findingId, repositoryIds: [f.targetId] },
        { findingId: neighbor.findingId, repositoryIds: ["repository-b"] },
      ],
    });
  expect(result.duplicateGroups).toEqual([]);
  expect(
    JSON.parse(await readFile(join(f.scanDir, "findings.json"), "utf8")),
  ).toEqual(f.document);
});

test.each(["model", "dimensions", "cacheNamespace"] as const)(
  "custom embedding bindings reuse their vectors and invalidate changed %s",
  async (changed) => {
    const f = await fixture();
    const embed = mock(async (findings: readonly Finding[]) =>
      findings.map(() => ({ model: "synthetic-model", vector: [1, 0, 0] })),
    );
    const embedding: FindingEmbeddingBinding = {
      embedder: { embed },
      model: "synthetic-model",
      dimensions: 3,
      cacheNamespace: "synthetic-provider:preprocessing-v1",
    };
    const dependencies = {
      environment: f.environment,
      reviewer: emptyNeighborhoodReviewer(),
    };
    await deduplicateScanDirectoryInternal(
      f.scanDir,
      { repository: f.repository, embedding },
      dependencies,
    );
    await deduplicateScanDirectoryInternal(
      f.scanDir,
      { repository: f.repository, embedding },
      dependencies,
    );
    expect(embed).toHaveBeenCalledTimes(1);
    const before = new LocalDeduplication(
      f.environment,
      { repositoryId: f.targetId },
      f.repository,
      undefined,
      undefined,
      embedding,
    );
    await before.prepare(f.document.findings, f.targetId);
    const next = {
      ...embedding,
      ...(changed === "model" ? { model: "synthetic-next-model" } : {}),
      ...(changed === "dimensions" ? { dimensions: 2 } : {}),
      ...(changed === "cacheNamespace"
        ? { cacheNamespace: "synthetic-other-provider:preprocessing-v1" }
        : {}),
    };
    const nextEmbed = mock(async (findings: readonly Finding[]) =>
      findings.map(() => ({
        model: next.model,
        vector: Array.from({ length: next.dimensions }, (_, i) =>
          i === 0 ? 1 : 0,
        ),
      })),
    );
    await deduplicateScanDirectoryInternal(
      f.scanDir,
      {
        repository: f.repository,
        embedding: { ...next, embedder: { embed: nextEmbed } },
      },
      dependencies,
    );
    expect(nextEmbed).toHaveBeenCalledTimes(1);
    await expect(
      before.potentialDuplicates(f.document.findings[0]!.findingId),
    ).rejects.toThrow("Findings changed");
    await expect(before.storeDedupeGroups([])).rejects.toThrow(
      "Findings changed",
    );
  },
);

test("remote dedupe rejects a local embedding binding", async () => {
  const f = await fixture();
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      {
        repository: f.repository,
        findingsUrl: "https://synthetic.invalid",
        embedding: f.embedding,
      },
      {
        environment: f.environment,
        fetch: rejecting("Unexpected findings request"),
      },
    ),
  ).rejects.toThrow(
    "Custom embeddings are only supported for local deduplication",
  );
  expect(f.embed).not.toHaveBeenCalled();
});

test("scope preparation refreshes legacy embeddings, preserves current bodies, and protects concurrent writes", async () => {
  const f = await fixture();
  const original = f.document.findings[0]!;
  const newer = { ...original, title: "Current stored evidence" };
  const other = {
    ...original,
    findingId: "csf_other",
    fingerprints: { ...original.fingerprints, primary: "other" },
  };
  await f.store.insert(
    [{ finding: newer, embedding: { model: EMBEDDING_MODEL, vector } }],
    f.targetId,
  );
  await f.store.insert(
    [{ finding: other, embedding: { model: EMBEDDING_MODEL, vector } }],
    "other-repository",
  );
  const local = f.local();
  await local.prepare([original], f.targetId);
  expect(f.embed.mock.calls.map(([findings]) => findings[0]!.title)).toEqual([
    newer.title,
  ]);
  expect(
    (await local.potentialDuplicates(original.findingId)).potentialDuplicates,
  ).toEqual([]);
  const all = f.local(undefined, true);
  await all.prepare([original], f.targetId);
  expect(
    (await all.potentialDuplicates(original.findingId)).potentialDuplicates.map(
      (v) => v.findingId,
    ),
  ).toEqual([other.findingId]);
  await all.storeDedupeGroups([[original.findingId, other.findingId]]);
  expect(await f.store.listDedupeGroups(original.findingId)).toHaveLength(1);
  await f.store.insert(
    [
      {
        finding: { ...newer, title: "Concurrent update" },
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    f.targetId,
  );
  await expect(local.potentialDuplicates(original.findingId)).rejects.toThrow(
    "Findings changed",
  );
  await expect(local.storeDedupeGroups([])).rejects.toThrow("Findings changed");
});

test("embedding writes reject stale content and reuse certified vectors", async () => {
  const f = await fixture();
  const finding = f.document.findings[0]!;
  const racing = f.local({
    async embed(findings) {
      await f.store.insert([
        {
          finding: { ...finding, title: "Concurrent body" },
          embedding: { model: EMBEDDING_MODEL, vector },
        },
      ]);
      return await f.embed(findings);
    },
  });
  await expect(racing.prepare([finding], f.targetId)).rejects.toThrow(
    "Findings changed",
  );
  const local = f.local();
  await local.prepare([finding], f.targetId);
  expect(
    (await local.potentialDuplicates(finding.findingId)).finding.title,
  ).toBe("Concurrent body");
  const unavailable = f.local({
    embed: rejecting("Missing embedding credentials"),
  });
  await unavailable.prepare([finding], f.targetId);
  const differentProvider = new LocalDeduplication(
    {
      ...f.environment,
      CODEX_SECURITY_EMBEDDINGS_URL: "https://synthetic.invalid/embeddings",
    },
    { repositoryId: f.targetId },
    f.repository,
    undefined,
    undefined,
    {
      ...f.embedding,
      cacheNamespace: "synthetic-other-provider-v1",
      embedder: { embed: rejecting("Missing embedding credentials") },
    },
  );
  await expect(
    differentProvider.prepare([finding], f.targetId),
  ).rejects.toThrow("Missing embedding credentials");
});

test.each(["failure", "cancellation"] as const)(
  "preparation checkpoints batches and reuses them after a later %s",
  async (failure) => {
    const f = await fixture();
    const findings = Array.from({ length: 65 }, (_, index) => ({
      ...f.document.findings[0]!,
      findingId: `csf_batch_${index}`,
      fingerprints: {
        ...f.document.findings[0]!.fingerprints,
        primary: `batch-${index}`,
      },
      identity: { anchor: `batch-${index}` },
    }));
    const controller = new AbortController();
    const reason = new Error(`Later batch ${failure}`);
    const batches: Finding[][] = [];
    const interrupted = f.local(
      {
        async embed(batch) {
          batches.push([...batch]);
          if (batches.length === 2) {
            if (failure === "failure") throw reason;
            controller.abort(reason);
          }
          return await f.embed(batch);
        },
      },
      false,
      controller.signal,
    );
    await expect(interrupted.prepare(findings, f.targetId)).rejects.toBe(
      reason,
    );
    expect(batches).toHaveLength(2);
    expect(batches[0]!.length).toBeGreaterThan(1);
    const completed = new Set(batches[0]!.map((finding) => finding.findingId));
    const resumedEmbed = mock(async (batch: readonly Finding[]) =>
      f.embed(batch),
    );
    await f.local({ embed: resumedEmbed }).prepare(findings, f.targetId);
    expect(
      new Set(
        resumedEmbed.mock.calls.flatMap(([batch]) =>
          batch.map((finding) => finding.findingId),
        ),
      ),
    ).toEqual(
      new Set(
        findings
          .filter((finding) => !completed.has(finding.findingId))
          .map((finding) => finding.findingId),
      ),
    );
    await f
      .local({ embed: rejecting("Completed preparation must be cached") })
      .prepare(findings, f.targetId);
  },
);

test("local workflow replays a lost group acknowledgement without publication or more embeddings", async () => {
  const f = await fixture();
  const anchor = f.document.findings[0]!;
  const neighbor = {
    ...anchor,
    findingId: "csf_neighbor",
    fingerprints: { ...anchor.fingerprints, primary: "neighbor" },
  };
  await f.store.insert(
    [{ finding: neighbor, embedding: { model: EMBEDDING_MODEL, vector } }],
    f.targetId,
  );
  const reviewer = duplicateReviewer();
  let loseAcknowledgement = true;
  const workbench = async (args: readonly string[], input?: string) => {
    const result = await runWorkbench(f.options, args, input);
    if (
      args[0] === "store-dedupe-groups" &&
      JSON.parse(input!).action === "commit" &&
      loseAcknowledgement
    ) {
      loseAcknowledgement = false;
      throw new Error("Lost group acknowledgement");
    }
    return result;
  };
  const options = {
    repository: f.repository,
    workflowId: "local-workflow",
    embedding: f.embedding,
  };
  const dependencies = {
    environment: f.environment,
    runWorkbench: workbench,
    reviewer,
    fetch: rejecting("Unexpected publication"),
  };
  await expect(
    deduplicateScanDirectoryInternal(f.scanDir, options, dependencies),
  ).rejects.toThrow("Lost group acknowledgement");
  const stored = await f.store.listDedupeGroups(anchor.findingId);
  expect(stored).toHaveLength(1);
  expect(new Set(stored[0]!.findingIds)).toEqual(
    new Set([anchor.findingId, neighbor.findingId]),
  );
  expect(reviewer.screen).toHaveBeenCalledTimes(1);
  expect(reviewer.reviewPair).toHaveBeenCalledTimes(1);
  const result = await deduplicateScanDirectoryInternal(
    f.scanDir,
    options,
    dependencies,
  );
  expect(result.deduplicationStatus).toBe("completed");
  expect(result.duplicateGroups).toHaveLength(1);
  expect(new Set(result.duplicateGroups[0])).toEqual(
    new Set([anchor.findingId, neighbor.findingId]),
  );
  expect(await f.store.listDedupeGroups(anchor.findingId)).toEqual(stored);
  expect(await f.store.listDedupeGroups(neighbor.findingId)).toEqual(stored);
  expect(reviewer.screen).toHaveBeenCalledTimes(1);
  expect(reviewer.reviewPair).toHaveBeenCalledTimes(1);
  expect(f.embed).toHaveBeenCalledTimes(1);
  const workflow = await new FindingWorkflow(
    options.workflowId,
    f.environment,
  ).get();
  expect(workflow?.destination).toStartWith("sqlite:");
  expect(workflow?.stages.publish.status).toBe("pending");
  expect(workflow?.stages.dedupe.status).toBe("completed");
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      {
        ...options,
        embedding: undefined,
        findingsUrl: "http://synthetic.invalid",
      },
      dependencies,
    ),
  ).rejects.toThrow("different destination");
});

test("empty input does not embed unrelated history and cancellation stops preparation", async () => {
  const f = await fixture();
  await f.store.insert(
    [
      {
        finding: f.document.findings[0]!,
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    f.targetId,
  );
  await f
    .local({ embed: rejecting("Empty scan must not embed") })
    .prepare([], f.targetId);
  const controller = new AbortController();
  controller.abort(new Error("Canceled"));
  const local = new LocalDeduplication(
    f.environment,
    { allRepositories: true },
    f.repository,
    controller.signal,
    undefined,
    f.embedding,
  );
  await expect(local.prepare(f.document.findings, f.targetId)).rejects.toThrow(
    "Canceled",
  );
  expect(f.embed).not.toHaveBeenCalled();
});

test("sealed artifacts cannot select a different local repository corpus", async () => {
  const f = await fixture();
  await f.store.insert(
    [
      {
        finding: f.document.findings[0]!,
        embedding: { model: EMBEDDING_MODEL, vector },
      },
    ],
    f.targetId,
  );
  const differentRepository = join(f.root, "other-checkout");
  await mkdir(differentRepository);
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      { repository: differentRepository, embedding: f.embedding },
      {
        environment: f.environment,
        reviewer: emptyNeighborhoodReviewer(),
      },
    ),
  ).rejects.toThrow("scan target does not match");
  expect(f.embed).not.toHaveBeenCalled();
});

test("local workbench calls receive cancellation and cannot report success after a canceled commit", async () => {
  const f = await fixture();
  const controller = new AbortController();
  const reason = new Error("Canceled during group commit");
  const actions: string[] = [];
  await expect(
    deduplicateScanDirectoryInternal(
      f.scanDir,
      {
        repository: f.repository,
        signal: controller.signal,
        embedding: f.embedding,
      },
      {
        environment: f.environment,
        reviewer: emptyNeighborhoodReviewer(),
        runWorkbench: async (args, input, signal) => {
          expect(signal).toBe(controller.signal);
          const result = await runWorkbench(
            { ...f.options, signal },
            args,
            input,
          );
          if (
            [
              "local-dedupe",
              "find-potential-duplicates",
              "store-dedupe-groups",
            ].includes(args[0]!)
          ) {
            const { action } = JSON.parse(input!);
            actions.push(action);
            if (action === "commit") controller.abort(reason);
          }
          return result;
        },
      },
    ),
  ).rejects.toBe(reason);
  expect(actions).toEqual(["prepare", "embed", "neighbors", "commit"]);
});

test.skipIf(process.platform === "win32")(
  "local preparation cancels an active Python probe",
  async () => {
    const f = await fixture();
    const python = join(f.root, "slow-python");
    const marker = join(f.root, "probe-started");
    await writeFile(
      python,
      '#!/bin/sh\nprintf started > "$TEST_PYTHON_PROBE"\nexec sleep 10\n',
    );
    await chmod(python, 0o700);
    const controller = new AbortController();
    try {
      const local = new LocalDeduplication(
        { ...f.environment, PYTHON: python, TEST_PYTHON_PROBE: marker },
        { repositoryId: f.targetId },
        f.repository,
        controller.signal,
        undefined,
        f.embedding,
      );
      const outcome = local
        .prepare(f.document.findings, f.targetId)
        .catch((error: unknown) => error);
      const completion = outcome.then((error) => ({ error }));
      while (!existsSync(marker)) {
        const exited = await Promise.race([delay(10), completion]);
        if (exited) throw exited.error;
      }
      controller.abort();
      expect(await outcome).toMatchObject({ name: "AbortError" });
    } finally {
      controller.abort();
    }
  },
);

test("local embeddings preserve an endpoint from a copied Windows environment", async () => {
  const f = await fixture();
  const finding = f.document.findings[0]!;
  const endpoint = "https://synthetic.invalid/embeddings";
  const request = spyOn(globalThis, "fetch").mockResolvedValue(
    Response.json({
      model: EMBEDDING_MODEL,
      data: [{ index: 0, embedding: vector }],
    }),
  );
  try {
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    let local: LocalDeduplication;
    try {
      // Only construction reads the copied environment; restore before async work.
      Object.defineProperty(process, "platform", { value: "win32" });
      local = new LocalDeduplication(
        {
          ...f.environment,
          codex_security_embeddings_url: endpoint,
          openai_api_key: "synthetic-key",
        },
        { repositoryId: f.targetId },
        f.repository,
        undefined,
        async (_options, _args, input) =>
          JSON.parse(input!).action === "prepare"
            ? JSON.parse(
                JSON.stringify({
                  cacheKeys: { [finding.findingId]: "synthetic-key" },
                  findingsToEmbed: [finding],
                }),
              )
            : {},
      );
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
    await local.prepare([finding], f.targetId);
    expect(request).toHaveBeenCalledTimes(1);
    expect(request.mock.calls[0]![0]).toBe(endpoint);
    expect(request.mock.calls[0]![1]?.headers).toMatchObject({
      Authorization: "Bearer synthetic-key",
    });
  } finally {
    request.mockRestore();
  }
});
