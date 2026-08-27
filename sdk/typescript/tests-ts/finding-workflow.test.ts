import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import type { JsonObject } from "../src/config.js";
import {
  FindingWorkflow,
  workflowDestination,
  type WorkflowState,
} from "../src/finding-workflow.js";
import { publishScanToCustomInternal } from "../src/custom-publish.js";
import { deduplicateScanInternal } from "../src/deduplication/scan.js";
import {
  resolvePluginPython,
  runCodexCommand,
  runWorkbench,
} from "../src/runtime.js";
import type { Finding, FindingsDocument, ScanManifest } from "../src/models.js";
import type { CodexReview } from "../src/deduplication/codex-review.js";
import {
  CheckpointedReviewRunner,
  reviewSettingsDigest,
} from "../src/deduplication/checkpointed-review.js";
import {
  CodexDeduplicationReviewer,
  type DuplicateDecision,
} from "../src/deduplication/deduplication-reviewer.js";
import { PLUGIN_ROOT } from "./plugin-root.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "findings-workflow-"));
  directories.push(root);
  const scanDir = join(root, "scan");
  const repository = join(root, "repository");
  await mkdir(repository);
  await cp(join(PLUGIN_ROOT, "examples/completed-scan"), scanDir, {
    recursive: true,
  });
  if (process.platform !== "win32") await chmod(scanDir, 0o700);
  const environment = {
    PATH: process.env["PATH"],
    SystemRoot: process.env["SystemRoot"],
    TEMP: process.env["TEMP"],
    TMP: process.env["TMP"],
    CODEX_HOME: join(root, "codex"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const document = JSON.parse(
    await readFile(join(scanDir, "findings.json"), "utf8"),
  ) as FindingsDocument;
  const workbenchOptions = {
    environment,
    pluginRoot: PLUGIN_ROOT,
    python: await resolvePluginPython({ environment }),
  };
  const history = async (args: readonly string[], input?: string) =>
    args[0] === "get-scan"
      ? {
          scan: {
            scanId: document.scanId,
            scanDir,
            targetPath: repository,
            progress: { status: "complete" },
          },
        }
      : await runWorkbench(workbenchOptions, args, input);
  return {
    root,
    repository,
    scanDir,
    environment,
    document,
    history,
    workbenchOptions,
  };
}

async function restoreLegacyWorkflow(
  environment: NodeJS.ProcessEnv,
  state: object,
  reviews: object[],
) {
  const probe = await runCodexCommand(
    { command: await resolvePluginPython({ environment }) },
    [
      "-I",
      "-B",
      "-c",
      `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_schema import MIGRATIONS, apply_migrations, sql_statements
db = sqlite3.connect(sys.argv[2])
db.row_factory = sqlite3.Row
db.execute("PRAGMA foreign_keys = ON")
payload = json.load(sys.stdin)
state = payload["state"]
timestamp = "2026-08-01T00:00:00Z"
with db:
    db.execute("DROP TABLE finding_workflow_reviews")
    db.execute("DROP TABLE finding_workflows")
    db.execute("DELETE FROM schema_migrations WHERE version >= 38")
    for version, _, sql in MIGRATIONS:
        if version in (36, 37):
            for statement in sql_statements(sql):
                db.execute(statement)
    db.execute("INSERT INTO finding_workflows VALUES (?, ?, ?, ?)",
               (state["id"], json.dumps(state), timestamp, timestamp))
    for review in payload["reviews"]:
        db.execute("INSERT INTO finding_workflow_reviews VALUES (?, ?, ?, ?, ?)",
                   (state["id"], review["key"], json.dumps(review["binding"]), json.dumps(review["result"]), timestamp))
before = list(db.iterdump())
try:
    apply_migrations(db, (*MIGRATIONS, (999, "synthetic failure", "INSERT INTO synthetic_missing_table VALUES (1);")), lambda: timestamp, lambda _: None)
except sqlite3.OperationalError:
    pass
else:
    raise AssertionError("Migration should fail")
assert not db.in_transaction
assert list(db.iterdump()) == before, "Failed migration must preserve workflow and review rows together"
db.close()`,
      join(PLUGIN_ROOT, "scripts"),
      join(environment["CODEX_SECURITY_STATE_DIR"]!, "workbench.sqlite3"),
    ],
    environment,
    JSON.stringify({ state, reviews }),
  );
  expect(probe.exitCode, probe.stderr).toBe(0);
}

test("migrates workflow columns atomically without losing receipts, pending writes, or resume state", async () => {
  const { environment, repository, scanDir, workbenchOptions } =
    await fixture();
  const completed = {
    id: "migrated-completed",
    repositoryPath: repository,
    scanRequestDigest: "scan-request-hash",
    scanId: "synthetic-scan",
    scanDir,
    artifactDigest: "artifact-hash",
    destination: "http://synthetic.test/",
    scope: { repositoryId: "synthetic-repository" },
    stages: {
      scan: { status: "completed", result: null },
      publish: { status: "completed", result: { findingIds: [] } },
      dedupe: { status: "completed", result: { duplicateGroups: [] } },
    },
  } as const;
  const unfinished = {
    id: "migrated-unfinished",
    scope: { allRepositories: true },
    stages: {
      scan: { status: "failed", error: "Synthetic scan interruption" },
      publish: { status: "running", error: "Synthetic earlier failure" },
      dedupe: {
        status: "failed",
        error: "Synthetic lost acknowledgement",
        result: { duplicateGroups: [["a", "b"]] },
        pendingWrite: { groups: [["a", "b"]] },
      },
    },
  } satisfies WorkflowState;
  const pending = {
    id: "migrated-pending",
    stages: {
      scan: { status: "pending" },
      publish: { status: "pending" },
      dedupe: { status: "pending" },
    },
  } as const;
  await mkdir(environment.CODEX_SECURITY_STATE_DIR);
  const probe = await runCodexCommand(
    { command: workbenchOptions.python },
    [
      "-I",
      "-B",
      "-c",
      `import json, sqlite3, sys
sys.path.insert(0, sys.argv[1])
from workbench_schema import MIGRATIONS, apply_migrations
db = sqlite3.connect(sys.argv[2])
db.row_factory = sqlite3.Row
db.execute("PRAGMA foreign_keys = ON")
timestamp = "2026-08-01T00:00:00Z"
apply = lambda migrations: apply_migrations(db, migrations, lambda: timestamp, lambda _: None)
apply(tuple(m for m in MIGRATIONS if m[0] <= 36))
states = json.load(sys.stdin)
with db:
    for state in states:
        db.execute("INSERT INTO finding_workflows VALUES (?, ?, ?, ?)",
                   (state["id"], json.dumps(state), timestamp, "2026-08-02T00:00:00Z"))
    db.execute("CREATE TABLE synthetic_workflow_references (workflow_id TEXT REFERENCES finding_workflows(id) ON DELETE CASCADE)")
    db.execute("INSERT INTO synthetic_workflow_references VALUES (?)", (states[0]["id"],))
before = list(db.iterdump())
try:
    apply((*MIGRATIONS, (999, "synthetic failure", "INSERT INTO synthetic_missing_table VALUES (1);")))
except sqlite3.OperationalError:
    pass
else:
    raise AssertionError("Migration should fail")
assert not db.in_transaction
assert list(db.iterdump()) == before, "Migration must roll back schema and data together"
apply(MIGRATIONS)
after = list(db.iterdump())
apply(MIGRATIONS)
assert list(db.iterdump()) == after
assert "state_json" not in {row["name"] for row in db.execute("PRAGMA table_info(finding_workflows)")}
assert db.execute("SELECT COUNT(*) FROM synthetic_workflow_references").fetchone()[0] == 1
assert list(db.execute("PRAGMA foreign_key_check")) == []
assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
print(json.dumps([dict(row) for row in db.execute("SELECT * FROM finding_workflows ORDER BY id")]))`,
      join(PLUGIN_ROOT, "scripts"),
      join(environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
    ],
    environment,
    JSON.stringify([completed, unfinished, pending]),
  );
  expect(probe.exitCode, probe.stderr).toBe(0);
  const rows = JSON.parse(probe.stdout);
  expect(rows[0]).toMatchObject({
    id: completed.id,
    repository_path: repository,
    scan_request_digest: completed.scanRequestDigest,
    scan_id: completed.scanId,
    scan_dir: scanDir,
    artifact_digest: completed.artifactDigest,
    destination: completed.destination,
    scope_repository_id: completed.scope.repositoryId,
    scope_all_repositories: null,
    scan_status: "completed",
    scan_error: null,
    publish_status: "completed",
    publish_error: null,
    dedupe_status: "completed",
    dedupe_error: null,
    created_at: "2026-08-01T00:00:00Z",
    updated_at: "2026-08-02T00:00:00Z",
  });
  expect(JSON.parse(rows[0].results_json)).toEqual({
    scan: null,
    publish: completed.stages.publish.result,
    dedupe: completed.stages.dedupe.result,
  });
  for (const state of [completed, unfinished, pending]) {
    expect(await new FindingWorkflow(state.id, environment).get()).toEqual(
      state,
    );
  }
  const workflow = new FindingWorkflow(completed.id, environment);
  for (const stage of ["scan", "publish", "dedupe"] as const) {
    expect(
      await workflow.run<unknown>(stage, async () => {
        throw new Error("Completed work must not run again after migration");
      }),
    ).toEqual(completed.stages[stage].result);
  }
  const resumed = new FindingWorkflow(unfinished.id, environment);
  await resumed.run("scan", async () => ({ scanId: "resumed-scan" }));
  expect((await resumed.get())?.stages.scan).toEqual({
    status: "completed",
    result: { scanId: "resumed-scan" },
  });
  expect((await resumed.get())?.stages.dedupe).toEqual(
    unfinished.stages.dedupe,
  );
});

test("scan registration commits its workflow identity atomically and rolls back failed registration", async () => {
  const { root, repository, environment, workbenchOptions } = await fixture();
  const workflow = new FindingWorkflow("registered-workflow", environment);
  await workflow.bind({ repositoryPath: repository });
  await workflow.begin("scan");
  const register = async (workflowId: string, suffix: string) => {
    const directory = join(root, suffix);
    await mkdir(directory, { mode: 0o700 });
    return await runWorkbench(
      workbenchOptions,
      [
        "register-cli-scan",
        "--repository",
        repository,
        "--scan-dir",
        directory,
        "--registration-json-stdin",
      ],
      JSON.stringify({
        workflowId,
        recipe: {
          repository,
          mode: "standard",
          target: { kind: "repository", paths: [] },
          config: {},
        },
      }),
    );
  };
  const registered = await register("registered-workflow", "registered-scan");
  expect(
    await new FindingWorkflow("registered-workflow", environment).get(),
  ).toMatchObject({
    scanId: registered["scanId"],
    scanDir: registered["scanDir"],
    stages: { scan: { status: "running" } },
  });
  await expect(
    register("unknown-workflow", "rolled-back-scan"),
  ).rejects.toThrow("must be started");
  const history = await runWorkbench(workbenchOptions, [
    "list-scans",
    "--repository",
    repository,
  ]);
  expect(history["scans"]).toHaveLength(1);
  const retried = await register("registered-workflow", "retried-scan");
  expect(retried["scanId"]).not.toBe(registered["scanId"]);
  expect((await workflow.get())?.scanId).toBe(retried["scanId"] as string);
});

test.each(["running", "completed"])(
  "survives termination with a %s stage and resumes in a fresh process",
  async (status) => {
    const { environment } = await fixture();
    const source = `import { FindingWorkflow } from ${JSON.stringify(new URL("../src/finding-workflow.ts", import.meta.url).href)};
const workflow = new FindingWorkflow("interrupted", process.env);
const timer = setInterval(() => {}, 1000);
await workflow.run("publish", async () => {
  if (${JSON.stringify(status)} === "running") {
    process.stdout.write("ready\\n");
    await new Promise(() => {});
  }
  return { findingIds: [] };
});
process.stdout.write("ready\\n");`;
    const child = spawn(process.execPath, ["--eval", source], {
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    const closed = once(child, "close");
    let errors = "";
    child.stderr.on("data", (chunk) => {
      errors += String(chunk);
    });
    try {
      const ready = await Promise.race([
        once(child.stdout, "data").then(([data]) => String(data)),
        closed.then(() => {
          throw new Error(
            errors || "Workflow child exited before the checkpoint",
          );
        }),
      ]);
      expect(ready).toContain("ready");
      child.kill();
      await closed;
      const workflow = new FindingWorkflow("interrupted", environment);
      expect((await workflow.get())?.stages.publish.status).toBe(status);
      let attempts = 0;
      expect(
        await workflow.run("publish", async () => {
          attempts++;
          return { findingIds: [] };
        }),
      ).toEqual({ findingIds: [] });
      expect(attempts).toBe(status === "running" ? 1 : 0);
      expect(
        (await new FindingWorkflow("interrupted", environment).get())?.stages
          .publish,
      ).toEqual({ status: "completed", result: { findingIds: [] } });
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill();
      await closed;
    }
  },
);

test("reuses publication after dedupe failure and persists a successful empty duplicate result", async () => {
  const { scanDir, environment, document, history } = await fixture();
  const original = await readFile(join(scanDir, "findings.json"), "utf8");
  const workflowId = "resume-example";
  const options = { workflowId, findingsUrl: "http://synthetic.test/service" };
  let publications = 0;
  let lookups = 0;
  let unavailable = true;
  const request = async (url: URL) => {
    if (url.pathname.endsWith("/bulk/findings")) {
      publications++;
      return Response.json(
        document.findings.map((finding) => finding.findingId),
      );
    }
    lookups++;
    if (unavailable) throw new Error("Synthetic lookup failure");
    return Response.json({
      finding: document.findings[0],
      potentialDuplicates: [],
    });
  };
  const receipt = await publishScanToCustomInternal(scanDir, options, {
    environment,
    fetch: request,
  });
  await expect(
    deduplicateScanInternal(document.scanId, options, {
      environment,
      fetch: request,
      runWorkbench: history,
    }),
  ).rejects.toThrow("Synthetic lookup failure");
  const workflow = new FindingWorkflow(workflowId, environment);
  expect((await workflow.get())?.stages).toMatchObject({
    scan: { status: "completed" },
    publish: { status: "completed", result: receipt },
    dedupe: { status: "failed", error: "Synthetic lookup failure" },
  });
  expect(publications).toBe(1);
  unavailable = false;
  const result = await deduplicateScanInternal(document.scanId, options, {
    environment,
    fetch: request,
    runWorkbench: history,
  });
  expect(result).toEqual({
    scanId: document.scanId,
    uniqueFindingIds: document.findings.map((finding) => finding.findingId),
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
  expect((await workflow.get())?.stages.dedupe).toEqual({
    status: "completed",
    result,
  });
  expect(
    await deduplicateScanInternal(document.scanId, options, {
      environment,
      runWorkbench: history,
      fetch: async () => {
        throw new Error("Completed stages must not make HTTP requests");
      },
    }),
  ).toEqual(result);
  expect(publications).toBe(1);
  expect(lookups).toBe(2);
  expect(await readFile(join(scanDir, "findings.json"), "utf8")).toBe(original);
});

test("an empty scan completes publication and dedupe and remains retrievable", async () => {
  const { scanDir, environment, document, history } = await fixture();
  document.findings = [];
  const content = JSON.stringify(document);
  await writeFile(join(scanDir, "findings.json"), content);
  const manifestPath = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(
    await readFile(manifestPath, "utf8"),
  ) as ScanManifest;
  manifest.scan.artifacts!.find(
    (artifact) => artifact.path === "findings.json",
  )!.sha256 = createHash("sha256").update(content).digest("hex");
  await writeFile(manifestPath, JSON.stringify(manifest));
  const options = {
    workflowId: "empty-scan",
    findingsUrl: "http://synthetic.test",
  };
  let requests = 0;
  const fetch = async (_url: URL, init: RequestInit) => {
    requests++;
    expect(JSON.parse(init.body as string).findings).toEqual([]);
    return Response.json([]);
  };
  const result = await deduplicateScanInternal(document.scanId, options, {
    environment,
    runWorkbench: history,
    fetch,
  });
  expect(result).toEqual({
    scanId: document.scanId,
    uniqueFindingIds: [],
    duplicateGroups: [],
    deduplicationStatus: "completed",
  });
  expect(
    await deduplicateScanInternal(document.scanId, options, {
      environment,
      runWorkbench: history,
      fetch,
    }),
  ).toEqual(result);
  expect(requests).toBe(1);
  expect(
    (await new FindingWorkflow(options.workflowId, environment).get())?.stages
      .publish,
  ).toMatchObject({
    status: "completed",
    result: { findingIds: [], findingCount: 0 },
  });
});

test("failed publication stays unfinished, dry-run does not advance it, and retry records the receipt", async () => {
  const { scanDir, environment, document } = await fixture();
  const options = {
    workflowId: "publication-retry",
    findingsUrl: "http://synthetic.test",
  };
  await expect(
    publishScanToCustomInternal(scanDir, options, {
      environment,
      fetch: async () => new Response("", { status: 503 }),
    }),
  ).rejects.toThrow("HTTP 503");
  const workflow = new FindingWorkflow(options.workflowId, environment);
  const failed = await workflow.get();
  expect(failed?.stages.publish.status).toBe("failed");
  expect(failed?.stages.publish.result).toBeUndefined();
  await publishScanToCustomInternal(
    scanDir,
    { ...options, dryRun: true },
    { environment },
  );
  expect(await workflow.get()).toEqual(failed);
  const result = await publishScanToCustomInternal(scanDir, options, {
    environment,
    fetch: async () =>
      Response.json(document.findings.map((finding) => finding.findingId)),
  });
  expect((await workflow.get())?.stages.publish).toEqual({
    status: "completed",
    result,
  });
});

test("separates workflow identities and rejects different scans, destinations, and scopes", async () => {
  const { environment } = await fixture();
  const binding = {
    scanId: "scan-a",
    scanDir: "synthetic-artifacts",
    destination: workflowDestination(
      "http://synthetic:password@synthetic.test",
    ),
    scope: { repositoryId: "repository-a" },
  };
  const first = new FindingWorkflow("first", environment);
  await first.bind(binding);
  expect((await first.get())?.destination).toBe("http://synthetic.test/");
  await first.run("dedupe", async () => ({ duplicateGroups: [] }));
  for (const changed of [
    { scanId: "scan-b" },
    { destination: "http://other.test/" },
    { scope: { allRepositories: true as const } },
  ]) {
    await expect(first.bind({ ...binding, ...changed })).rejects.toThrow(
      "already bound to a different",
    );
    const separate = new FindingWorkflow(
      `separate-${Object.keys(changed)[0]}`,
      environment,
    );
    expect(
      (await separate.bind({ ...binding, ...changed })).stages.dedupe.status,
    ).toBe("pending");
  }
  expect((await first.get())?.stages.dedupe).toEqual({
    status: "completed",
    result: { duplicateGroups: [] },
  });
});

test("does not write workflow metadata into sealed artifacts", async () => {
  const { scanDir, environment } = await fixture();
  await expect(
    publishScanToCustomInternal(
      scanDir,
      { workflowId: "unsafe-location", findingsUrl: "http://synthetic.test" },
      {
        environment: {
          ...environment,
          CODEX_SECURITY_STATE_DIR: join(scanDir, "state"),
        },
        fetch: async () => {
          throw new Error("Must not publish");
        },
      },
    ),
  ).rejects.toThrow("outside the sealed scan artifacts");
});

function merged(findings: readonly Finding[]) {
  return {
    decision: "SAME" as const,
    rationale: "REVIEW_OUTPUT_ONLY: one correction covers the supplied paths.",
    canonicalFindingId: findings[0]!.findingId,
    mergedFinding: {
      ...findings[0]!,
      title: "MERGED_OUTPUT_ONLY",
      extensions: { originals: findings },
    },
  };
}
const distinct: DuplicateDecision = {
  decision: "DISTINCT",
  rationale: "REVIEW_OUTPUT_ONLY: independent corrections are required.",
};

test.each(["screen", "pair"])(
  "resumes unfinished %s reviews using validated checkpoints and original inputs",
  async (interruptAt) => {
    const { scanDir, environment, document, history } = await fixture();
    const findings = [
      document.findings[0]!,
      ...[1, 2, 3].map((index) => ({
        ...structuredClone(document.findings[0]!),
        findingId: `csf_${"f".repeat(23)}${index}`,
        title: `Synthetic original ${index}`,
      })),
    ];
    const options = {
      workflowId: `reviews-${interruptAt}`,
      findingsUrl: "http://synthetic.test",
    };
    const calls: string[] = [];
    let interrupted = false;
    const reviewRunner = {
      async run<T>(review: CodexReview<T>): Promise<T> {
        expect(review.prompt).not.toContain("REVIEW_OUTPUT_ONLY");
        expect(review.prompt).not.toContain("MERGED_OUTPUT_ONLY");
        const originals = JSON.parse(
          review.prompt.slice(review.prompt.lastIndexOf("\n\n") + 2),
        ).findings as Finding[];
        for (const finding of originals)
          expect(finding).toEqual(
            findings.find(
              (original) => original.findingId === finding.findingId,
            )!,
          );
        const stage = review.model === "gpt-5.6-luna" ? "screen" : "pair";
        calls.push(stage);
        if (
          !interrupted &&
          stage === interruptAt &&
          (stage !== "pair" ||
            calls.filter((call) => call === "pair").length === 2)
        ) {
          interrupted = true;
          throw new Error("Synthetic interrupted review");
        }
        return review.validate(
          stage === "screen"
            ? {
                decisions: originals.slice(1).map((finding) => ({
                  findingIds: [originals[0]!.findingId, finding.findingId],
                  ...merged([originals[0]!, finding]),
                })),
              }
            : originals.some(
                  (finding) => finding.findingId === findings[3]!.findingId,
                )
              ? distinct
              : merged(originals),
        );
      },
    };
    const fetch = async (url: URL) =>
      url.pathname.endsWith("/bulk/findings")
        ? Response.json([findings[0]!.findingId])
        : url.pathname.endsWith("/dedupe-groups")
          ? Response.json([])
          : Response.json({
              finding: findings[0],
              potentialDuplicates: findings.slice(1),
            });
    await publishScanToCustomInternal(scanDir, options, { environment, fetch });
    await expect(
      deduplicateScanInternal(document.scanId, options, {
        environment,
        runWorkbench: history,
        reviewRunner,
        fetch,
      }),
    ).rejects.toThrow("Synthetic interrupted review");
    const result = await deduplicateScanInternal(document.scanId, options, {
      environment,
      runWorkbench: history,
      reviewRunner,
      fetch,
    });
    expect(result.duplicateGroups).toEqual([
      findings.slice(0, 3).map((finding) => finding.findingId),
    ]);
    expect(calls.filter((stage) => stage === "screen")).toHaveLength(
      interruptAt === "screen" ? 2 : 1,
    );
    expect(calls.filter((stage) => stage === "pair")).toHaveLength(
      interruptAt === "pair" ? 4 : 3,
    );
    const count = calls.length;
    expect(
      await deduplicateScanInternal(document.scanId, options, {
        environment,
        runWorkbench: history,
        reviewRunner,
        fetch: async () => {
          throw new Error("Completed workflow must use its saved result");
        },
      }),
    ).toEqual(result);
    expect(calls).toHaveLength(count);
  },
);

test.each([
  "before-post",
  "before-write",
  "lost-ack",
  "lost-completion",
  "migrated-lost-ack",
])(
  "replays the exact saved group payload after %s without models",
  async (failure) => {
    const { environment, document, history } = await fixture();
    const originals = [
      document.findings[0]!,
      { ...document.findings[0]!, findingId: `csf_${"f".repeat(24)}` },
    ];
    const options = {
      workflowId: `write-${failure}`,
      findingsUrl: "http://synthetic.test",
    };
    const bodies: string[] = [];
    const checkpoints: object[] = [];
    let modelCalls = 0;
    let failed = false;
    const reviewRunner = {
      async run<T>(review: CodexReview<T>): Promise<T> {
        modelCalls++;
        return review.validate(
          review.model === "gpt-5.6-luna"
            ? {
                decisions: [
                  {
                    findingIds: originals.map((finding) => finding.findingId),
                    ...merged(originals),
                  },
                ],
              }
            : merged(originals),
        );
      },
    };
    const fetch = async (url: URL, init: RequestInit) => {
      if (url.pathname.endsWith("/bulk/findings"))
        return Response.json([originals[0]!.findingId]);
      if (!url.pathname.endsWith("/dedupe-groups"))
        return Response.json({
          finding: originals[0],
          potentialDuplicates: [originals[1]],
        });
      const saved = (await new FindingWorkflow(
        options.workflowId,
        environment,
      ).get())!.stages.dedupe;
      expect(saved.status).toBe("running");
      expect(saved.result).toMatchObject({
        duplicateGroups: [originals.map((finding) => finding.findingId)],
      });
      expect(saved.pendingWrite).toEqual(JSON.parse(init.body as string));
      bodies.push(init.body as string);
      if (!failed && failure !== "lost-completion") {
        failed = true;
        if (failure === "before-write")
          return new Response("", { status: 503 });
        return new Response("incomplete acknowledgement", { status: 201 });
      }
      return Response.json([]);
    };
    const runWorkbench = async (args: readonly string[], input?: string) => {
      const payload = input ? JSON.parse(input) : {};
      if (
        !failed &&
        failure === "before-post" &&
        payload.action === "prepare-dedupe"
      ) {
        await history(args, input);
        failed = true;
        throw new Error("Synthetic stop before posting");
      }
      if (
        !failed &&
        failure === "lost-completion" &&
        payload.action === "complete" &&
        payload.stage === "dedupe"
      ) {
        failed = true;
        throw new Error("Synthetic completion receipt failure");
      }
      const result = await history(args, input);
      if (payload.action === "save-review") checkpoints.push(payload);
      return result;
    };
    await expect(
      deduplicateScanInternal(document.scanId, options, {
        environment,
        runWorkbench,
        reviewRunner,
        fetch,
      }),
    ).rejects.toThrow();
    if (failure === "migrated-lost-ack") {
      await restoreLegacyWorkflow(
        environment,
        (await new FindingWorkflow(options.workflowId, environment).get())!,
        checkpoints,
      );
    }
    expect(
      (await new FindingWorkflow(options.workflowId, environment).get())?.stages
        .dedupe.status,
    ).toBe("failed");
    const result = await deduplicateScanInternal(document.scanId, options, {
      environment,
      runWorkbench: history,
      reviewRunner,
      fetch,
    });
    expect(bodies).toHaveLength(failure === "before-post" ? 1 : 2);
    expect(new Set(bodies).size).toBe(1);
    expect(modelCalls).toBe(2);
    expect(
      (await new FindingWorkflow(options.workflowId, environment).get())?.stages
        .dedupe,
    ).toEqual({ status: "completed", result });
  },
);

test.each(["current", "legacy", "workflow-columns"])(
  "persists DISTINCT and complete SAME checkpoints across %s databases",
  async (version) => {
    const { environment, repository, document, workbenchOptions } =
      await fixture();
    const workflow = new FindingWorkflow("all-decisions", environment);
    await workflow.bind({});
    if (version === "workflow-columns") {
      const probe = await runCodexCommand(
        { command: workbenchOptions.python },
        [
          "-I",
          "-B",
          "-c",
          `import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute("DROP TABLE finding_workflow_reviews")
    db.execute("DELETE FROM schema_migrations WHERE version IN (37, 39)")`,
          join(environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
        ],
        environment,
      );
      expect(probe.exitCode, probe.stderr).toBe(0);
    }
    const originals = [
      document.findings[0]!,
      { ...document.findings[0]!, findingId: `csf_${"f".repeat(24)}` },
    ];
    let calls = 0;
    const checkpoints: Array<{
      key: string;
      binding: JsonObject;
      result: unknown;
    }> = [];
    const recordCheckpoint: typeof runWorkbench = async (
      options,
      args,
      input,
    ) => {
      const result = await runWorkbench(options, args, input);
      const payload = input ? JSON.parse(input) : {};
      if (payload.action === "save-review") checkpoints.push(payload);
      return result;
    };
    const runner = {
      async run<T>(review: CodexReview<T>): Promise<T> {
        calls++;
        return review.validate(
          review.model === "gpt-5.6-luna"
            ? {
                decisions: [
                  {
                    findingIds: originals.map((finding) => finding.findingId),
                    ...distinct,
                  },
                ],
              }
            : merged(originals),
        );
      },
    };
    const makeReviewer = async () =>
      new CodexDeduplicationReviewer(
        new CheckpointedReviewRunner(
          new FindingWorkflow(workflow.id, environment, recordCheckpoint),
          runner,
          await workflow.sourceSnapshot(repository),
          { allRepositories: true },
          "synthetic-settings-hash",
        ),
      );
    const first = await makeReviewer();
    const screening = await first.screen(originals);
    const pair = await first.reviewPair(originals);
    if (version === "legacy")
      await restoreLegacyWorkflow(
        environment,
        (await workflow.get())!,
        checkpoints,
      );
    const resumed = await makeReviewer();
    expect(await resumed.screen(originals)).toEqual(screening);
    expect(await resumed.reviewPair(originals)).toEqual(pair);
    expect(pair).toEqual(merged(originals));
    expect(calls).toBe(2);
    expect(checkpoints).toHaveLength(2);
    const probe = await runCodexCommand(
      { command: workbenchOptions.python },
      [
        "-I",
        "-B",
        "-c",
        `import json, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
db.row_factory = sqlite3.Row
assert "binding_json" not in {row["name"] for row in db.execute("PRAGMA table_info(finding_workflow_reviews)")}
assert list(db.execute("PRAGMA foreign_key_check")) == []
assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
print(json.dumps([dict(row) for row in db.execute("SELECT * FROM finding_workflow_reviews ORDER BY review_key")]))`,
        join(environment.CODEX_SECURITY_STATE_DIR, "workbench.sqlite3"),
      ],
      environment,
    );
    expect(probe.exitCode, probe.stderr).toBe(0);
    const rows = JSON.parse(probe.stdout);
    for (const { key, binding, result } of checkpoints) {
      const source = binding["source"] as JsonObject;
      const row = rows.find(
        (row: { review_key: string }) => row.review_key === key,
      );
      expect(row).toMatchObject({
        workflow_id: workflow.id,
        review_contract_version: binding["version"],
        codex_version: binding["codexVersion"],
        source_repository_path: source["repository"],
        source_revision: source["revision"],
        source_refs_digest: source["refsDigest"],
        source_content_digest: source["content"],
        scope_repository_id: null,
        scope_all_repositories: 1,
        model: binding["model"],
        effort: binding["effort"],
        settings_digest: binding["settingsDigest"],
        prompt_digest: binding["promptDigest"],
        contract_digest: binding["contractDigest"],
      });
      if (version === "legacy")
        expect(row.created_at).toBe("2026-08-01T00:00:00Z");
      expect(JSON.parse(row.result_json)).toEqual(result);
    }
  },
);

test.each([
  "finding",
  "source",
  "scope",
  "model",
  "effort",
  "prompt",
  "contract",
  "configuration",
])("does not reuse a checkpoint for changed %s inputs", async (changed) => {
  const { environment, repository, document } = await fixture();
  const workflow = new FindingWorkflow(`changed-${changed}`, environment);
  await workflow.bind({});
  let calls = 0;
  const runner = {
    async run<T>(review: CodexReview<T>): Promise<T> {
      calls++;
      return review.validate(distinct);
    },
  };
  const review: CodexReview<DuplicateDecision> = {
    model: "gpt-5.6-sol",
    effort: "ultra",
    prompt: JSON.stringify(document.findings),
    schema: { type: "object" },
    validate: () => distinct,
  };
  const source = await workflow.sourceSnapshot(repository);
  const scope = { repositoryId: "synthetic-repository" };
  const initial = new CheckpointedReviewRunner(
    workflow,
    runner,
    source,
    scope,
    await reviewSettingsDigest(environment),
  );
  await initial.run(review);
  await initial.run(review);
  expect(calls).toBe(1);
  if (changed === "source")
    await writeFile(join(repository, "source.txt"), "changed source");
  if (changed === "configuration") {
    await mkdir(environment.CODEX_HOME);
    await writeFile(
      join(environment.CODEX_HOME, "config.toml"),
      'model_reasoning_summary = "none"\n',
    );
  }
  const next = { ...review };
  if (changed === "finding")
    next.prompt = JSON.stringify([
      { ...document.findings[0], title: "Changed original" },
    ]);
  if (changed === "model") next.model = "gpt-5.6-luna";
  if (changed === "effort") next.effort = "high";
  if (changed === "prompt") next.prompt += "Changed review contract";
  if (changed === "contract")
    next.schema = { type: "object", required: ["decision"] };
  const resumed = new CheckpointedReviewRunner(
    new FindingWorkflow(workflow.id, environment),
    runner,
    await workflow.sourceSnapshot(repository),
    changed === "scope" ? { allRepositories: true } : scope,
    await reviewSettingsDigest(environment),
  );
  await resumed.run(next);
  expect(calls).toBe(2);
});

test("source snapshots include revisions and ignored content without following directory links", async () => {
  const { environment, repository, root } = await fixture();
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repository, stdio: "pipe" });
  git("init", "--quiet");
  await writeFile(join(repository, ".gitignore"), "ignored.txt\n");
  await writeFile(join(repository, "tracked.txt"), "original");
  await mkdir(join(repository, "tracked-directory"));
  await writeFile(
    join(repository, "tracked-directory", "source.txt"),
    "tracked source",
  );
  git("add", ".");
  git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.test",
    "commit",
    "--quiet",
    "-m",
    "Synthetic source",
  );
  const workflow = new FindingWorkflow("source-snapshots", environment);
  const first = await workflow.sourceSnapshot(repository);
  await writeFile(join(repository, "ignored.txt"), "ignored source");
  const second = await workflow.sourceSnapshot(repository);
  expect(second["revision"]).toBe(first["revision"]);
  expect(second["content"]).not.toBe(first["content"]);
  git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.test",
    "commit",
    "--quiet",
    "--allow-empty",
    "-m",
    "Next synthetic revision",
  );
  expect((await workflow.sourceSnapshot(repository))["revision"]).not.toBe(
    first["revision"],
  );
  const beforeRef = await workflow.sourceSnapshot(repository);
  git("branch", "synthetic-source-reference");
  const afterRef = await workflow.sourceSnapshot(repository);
  expect(afterRef["revision"]).toBe(beforeRef["revision"]);
  expect(afterRef["refsDigest"]).not.toBe(beforeRef["refsDigest"]);
  const outside = join(root, "outside");
  await mkdir(outside);
  await writeFile(join(outside, "private.txt"), "synthetic outside content");
  const { symlink } = await import("node:fs/promises");
  await symlink(
    outside,
    join(repository, "linked"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const linked = await workflow.sourceSnapshot(repository);
  await writeFile(join(outside, "private.txt"), "changed outside content");
  expect(await workflow.sourceSnapshot(repository)).toEqual(linked);
  await rm(join(repository, "tracked-directory"), { recursive: true });
  await writeFile(join(outside, "source.txt"), "synthetic outside source");
  await symlink(
    outside,
    join(repository, "tracked-directory"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const replaced = await workflow.sourceSnapshot(repository);
  await writeFile(join(outside, "source.txt"), "changed outside source");
  expect(await workflow.sourceSnapshot(repository)).toEqual(replaced);
});

test("does not checkpoint a review when source changes during its execution", async () => {
  const { environment, repository, document } = await fixture();
  const workflow = new FindingWorkflow("source-drift", environment);
  await workflow.bind({});
  const source = await workflow.sourceSnapshot(repository);
  const runner = new CheckpointedReviewRunner(
    workflow,
    {
      async run<T>(review: CodexReview<T>): Promise<T> {
        await writeFile(
          join(repository, "changed.txt"),
          "changed during review",
        );
        return review.validate(distinct);
      },
    },
    source,
    { allRepositories: true },
  );
  const review: CodexReview<DuplicateDecision> = {
    model: "gpt-5.6-sol",
    effort: "ultra",
    prompt: JSON.stringify(document.findings),
    schema: {},
    validate: () => distinct,
  };
  await expect(runner.run(review)).rejects.toThrow(
    "Source changed during deduplication",
  );
  await rm(join(repository, "changed.txt"));
  let calls = 0;
  await new CheckpointedReviewRunner(
    workflow,
    {
      async run<T>(review: CodexReview<T>): Promise<T> {
        calls++;
        return review.validate(distinct);
      },
    },
    source,
    { allRepositories: true },
  ).run(review);
  expect(calls).toBe(1);
});
