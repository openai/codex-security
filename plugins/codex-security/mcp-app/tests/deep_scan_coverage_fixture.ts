import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { build } from "esbuild";

import type { JsonObject } from "../src/types.js";
import type { CodexWorkerRequest } from "../src/deep-scan/types.js";
import { readJson } from "./support/json.ts";

type FixtureRuntime = typeof import("../src/deep-scan/artifacts.js") &
  typeof import("../src/deep-scan/coordinator.js") &
  typeof import("../src/deep-scan/store.js") &
  typeof import("../src/artifact-context.js") &
  typeof import("../src/artifact-scan-draft.js") &
  typeof import("../src/artifact-deep-reducer.js");

interface CoverageFixtureOptions {
  resume?: boolean;
  continueAfterResume?: boolean;
  stopAfterDraft?: boolean;
  stopBeforeDraft?: boolean;
  receiptRetry?: boolean;
  firstCheckpointReceipt?: "shared" | "worker";
  sameAttemptCloseout?: boolean;
  extraReceiptRetry?: boolean;
  rewriteReturnedCoverage?: boolean;
  sameNamedNewSurface?: boolean;
  closeRetriedSurface?: boolean;
  receiptOwnershipRetry?: "ordinary" | "candidate" | "unrelated";
  receiptSpelling?:
    | "worker"
    | "scan"
    | "equivalent scan"
    | "active scan"
    | "equivalent active scan"
    | "shared scan"
    | "equivalent shared scan";
  activeReceiptSpelling?: "worker" | "scan" | "equivalent scan";
  sharedReceipt?: boolean;
  receiptCollision?: boolean;
  emptyReceipt?: boolean;
  retryPending?: boolean;
  retryCoverage?: JsonObject[];
  retryFindings?: JsonObject[][];
  questionRows?: (string | JsonObject)[];
  interruptPublication?: boolean;
}
interface ProjectedRecord {
  id?: string;
  provenance: { workerId: string; attempt: number; candidateId?: string };
}
interface PublishedCoverage {
  completeness: string;
  surfaces: (ProjectedRecord & {
    id: string;
    label: string;
    candidateId?: string;
    disposition: string;
    receiptRefs: string[];
  })[];
  deferred: (ProjectedRecord & {
    id: string;
    candidateId?: string;
    reason: string;
    surfaceIds: string[];
  })[];
  explicitExclusions: ProjectedRecord[];
  openQuestions: (ProjectedRecord & {
    question: string;
    followUpPrompt?: string;
  })[];
  reviews: { workerId: string; attempt: number; completeness: string }[];
}
export async function readFixtureCoverage(
  scanDir: string,
): Promise<PublishedCoverage> {
  return readJson(path.join(scanDir, "coverage.json"));
}

const pluginRoot = fileURLToPath(new URL("../../", import.meta.url));
const exec = promisify(execFile);
const bundled = await build({
  bundle: true,
  stdin: {
    contents: [
      'export { archiveDirectory } from "./src/deep-scan/artifacts.ts";',
      'export { DeepScanCoordinator } from "./src/deep-scan/coordinator.ts";',
      'export { WorkbenchDeepScanStore } from "./src/deep-scan/store.ts";',
      'export { createScanArtifactContext } from "./src/artifact-context.ts";',
      'export { getCodexSecurityCompletedScan, recordCodexSecurityWorkerScanDraft, recordCodexSecurityScanDraftViaWorkbench } from "./src/artifact-scan-draft.ts";',
      'export { recordCodexSecurityDeepReduction } from "./src/artifact-deep-reducer.ts";',
    ].join("\n"),
    resolveDir: path.join(pluginRoot, "mcp-app"),
  },
  format: "esm",
  platform: "node",
  loader: { ".md": "text" },
  write: false,
});
export async function publishCoverageFixture(
  root: string,
  completeness: string,
  {
    resume = false,
    continueAfterResume = false,
    stopAfterDraft = false,
    stopBeforeDraft = false,
    receiptRetry = false,
    firstCheckpointReceipt,
    sameAttemptCloseout = false,
    extraReceiptRetry = false,
    rewriteReturnedCoverage = false,
    sameNamedNewSurface = false,
    closeRetriedSurface = false,
    receiptOwnershipRetry,
    receiptSpelling = "worker",
    activeReceiptSpelling = "worker",
    sharedReceipt = false,
    receiptCollision = false,
    emptyReceipt = false,
    retryPending = false,
    retryCoverage,
    retryFindings,
    questionRows,
    interruptPublication = false,
  }: CoverageFixtureOptions = {},
) {
  const runtimePath = path.join(root, "fixture-runtime.mjs");
  await writeFile(runtimePath, bundled.outputFiles![0]!.contents);
  const {
    archiveDirectory,
    getCodexSecurityCompletedScan,
    DeepScanCoordinator,
    WorkbenchDeepScanStore,
    createScanArtifactContext,
    recordCodexSecurityScanDraftViaWorkbench,
    recordCodexSecurityWorkerScanDraft,
    recordCodexSecurityDeepReduction,
  } = (await import(pathToFileURL(runtimePath).href)) as FixtureRuntime;
  const targetPath = path.join(root, "target");
  const codexHome = path.join(root, "codex-home");
  const scanRoot = path.join(root, "scans");
  const threadId = "coverage-fixture-owner";
  const statuses =
    completeness === "partial"
      ? ["partial", "complete", "unknown"]
      : completeness === "unknown"
        ? ["unknown", "complete", "complete"]
        : ["complete"];
  await mkdir(scanRoot, { mode: 0o700 });
  await mkdir(targetPath, { recursive: true });
  await mkdir(path.join(codexHome, "codex-security"), { recursive: true });
  await writeFile(path.join(targetPath, "source.py"), "# Synthetic source\n");
  await writeFile(
    path.join(codexHome, "codex-security", "config.toml"),
    `[deep_scan]\nworkers = 1\nsubagents = 0\nstop_after_no_new = ${statuses.length}\nmax_discovery_runs = ${statuses.length}\n`,
  );
  const runWorkbench = async (args: string[]) => {
    const workbenchPath = path.join(pluginRoot, "scripts", "workbench_db.py");
    const command = [workbenchPath, ...args];
    if (interruptPublication && args[0] === "fail-scan") {
      command.unshift(
        "-c",
        `
import os, runpy, sys
sys.path.insert(0, os.path.dirname(sys.argv[1]))
import workbench_saved_results

def interrupt_publication(*args, **kwargs):
    raise OSError("Synthetic publication interruption.")

workbench_saved_results._write_prepared_scan_finalization = interrupt_publication
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
`,
      );
    }
    const { stdout } = await exec(process.env.PYTHON || "python3", command, {
      env: {
        ...process.env,
        CODEX_HOME: codexHome,
        CODEX_SECURITY_STATE_DIR: path.join(root, "state"),
      },
    });
    return JSON.parse(stdout);
  };
  const store = new WorkbenchDeepScanStore(runWorkbench);
  let run = await store.begin({
    targetPath,
    scope: ".",
    threadId,
    scanRoot,
  });
  const context = await createScanArtifactContext(run.scanId, runWorkbench, {
    requireRunning: true,
  });
  const rawSources = new Map<string, string>();
  const writeReceiptAttempt = async (artifactDir: string) => {
    if (retryCoverage) {
      await mkdir(artifactDir, { recursive: true });
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          layout: "worker",
          repoRoot: targetPath,
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete: false,
          findings: retryFindings?.[0] ?? [],
          coverage: retryCoverage[0],
        },
      );
      return;
    }
    await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
    await writeFile(
      path.join(artifactDir, "artifacts", "prior.txt"),
      emptyReceipt ? "" : "Archived receipt.\n",
    );
    if (receiptCollision) {
      await mkdir(path.join(run.scanDir, "artifacts"), { recursive: true });
      await writeFile(
        path.join(run.scanDir, "artifacts", "prior.txt"),
        "Synthetic unrelated parent review.\n",
      );
    }
    const archivedRef = `${path.relative(run.scanDir, path.dirname(artifactDir)).split(path.sep).join("/")}/attempts/attempt-01/artifacts/prior.txt`;
    const sharedPrior = "artifacts/01_context/false_positive_feedback.json";
    const sharedPriorReceipt =
      receiptSpelling === "shared scan" ||
      receiptSpelling === "equivalent shared scan";
    if (sharedPriorReceipt) {
      await mkdir(path.dirname(path.join(run.scanDir, sharedPrior)), {
        recursive: true,
      });
      await writeFile(
        path.join(run.scanDir, sharedPrior),
        emptyReceipt ? "" : "Archived receipt.\n",
      );
    }
    const receiptRef = sharedPriorReceipt
      ? sharedPrior.replace(
          "artifacts/",
          receiptSpelling === "equivalent shared scan"
            ? "artifacts/./"
            : "artifacts/",
        )
      : receiptSpelling === "worker"
        ? "artifacts/prior.txt"
        : receiptSpelling === "scan"
          ? archivedRef
          : receiptSpelling === "equivalent scan"
            ? archivedRef.replace("artifacts/", "artifacts/./")
            : `${path.relative(run.scanDir, artifactDir).split(path.sep).join("/")}/artifacts/prior.txt`.replace(
                "artifacts/",
                receiptSpelling === "equivalent active scan"
                  ? "artifacts/./"
                  : "artifacts/",
              );
    if (receiptOwnershipRetry) {
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          layout: "worker",
          repoRoot: targetPath,
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete: false,
          findings: [],
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                id: "current",
                label: "Current review",
                disposition:
                  receiptOwnershipRetry === "unrelated"
                    ? "no_issue_found"
                    : "needs_follow_up",
                ...(receiptOwnershipRetry === "candidate"
                  ? { candidateId: "prior-candidate" }
                  : {}),
                receiptRefs: [receiptRef],
              },
              ...(receiptOwnershipRetry === "unrelated"
                ? [
                    {
                      id: "closed",
                      label: "Separate review",
                      disposition: "needs_follow_up",
                      receiptRefs: [receiptRef],
                    },
                  ]
                : []),
            ],
            explicitExclusions: [],
            deferred:
              receiptOwnershipRetry === "ordinary"
                ? []
                : [
                    {
                      id: "prior-gap",
                      ...(receiptOwnershipRetry === "candidate"
                        ? { candidateId: "prior-candidate" }
                        : {}),
                      reason: "Verify the earlier boundary.",
                      surfaceIds: [
                        receiptOwnershipRetry === "unrelated"
                          ? "closed"
                          : "current",
                      ],
                    },
                  ],
          },
        },
      );
      return;
    }
    if (closeRetriedSurface) {
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          layout: "worker",
          repoRoot: targetPath,
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete: false,
          findings: [],
          coverage: {
            completeness: "partial",
            surfaces: [
              {
                id: "current",
                label: "Current review",
                disposition: "needs_follow_up",
                receiptRefs: [receiptRef],
              },
            ],
            explicitExclusions: [],
            deferred: [
              {
                id: "prior-gap",
                reason: "Verify the earlier boundary.",
                surfaceIds: ["current"],
              },
            ],
          },
        },
      );
      return;
    }
    await recordCodexSecurityWorkerScanDraft(
      {
        root: artifactDir,
        layout: "worker",
        repoRoot: targetPath,
        scanId: run.scanId,
      },
      {
        scanId: run.scanId,
        complete: false,
        findings: [],
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "prior",
              label: "Prior review",
              disposition: "needs_follow_up",
              candidateId: "shared-prior-candidate",
              receiptRefs: [receiptRef],
            },
            {
              id: "prior-second",
              label: "Prior second surface",
              disposition: "needs_follow_up",
              candidateId: "shared-prior-candidate",
              receiptRefs: [receiptRef],
            },
          ],
          explicitExclusions: [],
          deferred: [
            {
              id: "prior-gap",
              candidateId: "shared-prior-candidate",
              reason: "Verify the earlier attempt's unresolved boundary.",
              surfaceIds: ["prior", "prior-second"],
            },
            {
              id: "prior-gap-2",
              candidateId: "shared-prior-candidate",
              reason: "Verify the same candidate's second boundary.",
              surfaceIds: ["prior", "prior-second"],
            },
          ],
        },
      },
    );
  };
  const writeDiscovery = async (
    artifactDir: string,
    index: number,
    complete = true,
  ) => {
    const status = statuses[index];
    if (firstCheckpointReceipt) {
      await mkdir(artifactDir, { recursive: true });
      const firstRef =
        firstCheckpointReceipt === "shared"
          ? "artifacts/01_context/false_positive_feedback.json"
          : "artifacts/first.txt";
      const firstRoot =
        firstCheckpointReceipt === "shared" ? run.scanDir : artifactDir;
      await mkdir(path.dirname(path.join(firstRoot, firstRef)), {
        recursive: true,
      });
      await writeFile(
        path.join(firstRoot, firstRef),
        "Synthetic first checkpoint.\n",
      );
      if (firstCheckpointReceipt === "worker") {
        await mkdir(path.dirname(path.join(run.scanDir, firstRef)), {
          recursive: true,
        });
        await writeFile(
          path.join(run.scanDir, firstRef),
          "Synthetic unrelated parent checkpoint.\n",
        );
      }
      const workerContext = {
        root: artifactDir,
        layout: "worker" as const,
        repoRoot: targetPath,
        scanId: run.scanId,
      };
      await recordCodexSecurityWorkerScanDraft(workerContext, {
        scanId: run.scanId,
        complete: false,
        findings: [],
        coverage: {
          completeness: "partial",
          surfaces: [
            {
              id: "first",
              label: "First checkpoint",
              disposition: sameAttemptCloseout
                ? "needs_follow_up"
                : "no_issue_found",
              receiptRefs: [firstRef],
              provenance: { scanReceiptRefs: [firstRef] },
            },
          ],
          explicitExclusions: [],
          deferred: sameAttemptCloseout
            ? [
                {
                  id: "first-gap",
                  reason: "Verify the same boundary.",
                  surfaceIds: ["first"],
                },
              ]
            : [],
        },
      });
      for (const name of await readdir(path.join(artifactDir, "checkpoints"))) {
        const checkpoint = path.join(artifactDir, "checkpoints", name);
        rawSources.set(checkpoint, await readFile(checkpoint, "utf8"));
      }
      const nextRef = receiptCollision ? firstRef : "artifacts/later.txt";
      await mkdir(path.dirname(path.join(artifactDir, nextRef)), {
        recursive: true,
      });
      await writeFile(
        path.join(artifactDir, nextRef),
        "Synthetic later checkpoint.\n",
      );
      await recordCodexSecurityWorkerScanDraft(workerContext, {
        scanId: run.scanId,
        complete,
        findings: [],
        coverage: {
          completeness: status,
          surfaces: [
            {
              id: sameAttemptCloseout ? "first" : "later",
              label: sameAttemptCloseout
                ? "First checkpoint"
                : "Later checkpoint",
              disposition: "no_issue_found",
              receiptRefs: [nextRef],
            },
          ],
          explicitExclusions: [],
          deferred: [],
          ...(sameAttemptCloseout
            ? {
                resolvedDeferred: [
                  { id: "first-gap", reason: "The same boundary is verified." },
                ],
              }
            : {}),
        },
      });
      const resultPath = path.join(artifactDir, "result.json");
      rawSources.set(resultPath, await readFile(resultPath, "utf8"));
      return;
    }
    const pending = completeness === "partial" && status !== "complete";
    const coverage: JsonObject = {
      completeness: status,
      reviews: [
        { workerId: "untrusted-worker", attempt: 99, completeness: "complete" },
      ],
      surfaces: [
        {
          id: "shared-surface",
          label: "Archive route",
          disposition: pending ? "needs_follow_up" : "no_issue_found",
          receiptRefs: ["artifacts/review.md"],
        },
        {
          id: "shared-surface",
          label: "Archive settings",
          disposition: "no_issue_found",
          receiptRefs: ["artifacts/review.md"],
        },
      ],
      explicitExclusions: [
        { pattern: "vendor/", reason: "External dependency." },
      ],
      deferred: pending
        ? [
            {
              id: "same-id",
              candidateId: "candidate-1",
              reason:
                index === 0
                  ? "Verify entry boundaries."
                  : "Verify symbolic links.",
              paths: ["source.py"],
              surfaceIds: ["shared-surface"],
            },
          ]
        : [],
      openQuestions:
        questionRows ??
        (pending ? [{ question: `Deployment question ${index + 1}.` }] : []),
      ...(retryCoverage && index === 0
        ? structuredClone(retryCoverage[1])
        : {}),
    };
    for (const field of [
      "surfaces",
      "explicitExclusions",
      "deferred",
      "openQuestions",
    ]) {
      for (const item of coverage[field] as (string | JsonObject)[]) {
        if (typeof item === "string") continue;
        item.provenance = {
          description: `Original ${field} context.`,
          details: { evidence: ["source review"] },
          workerId: "untrusted-worker",
          attempt: 99,
          sourceId: "untrusted-source",
          candidateId: "untrusted-candidate",
        };
      }
    }
    await mkdir(path.join(artifactDir, "artifacts"), { recursive: true });
    await writeFile(
      path.join(artifactDir, "artifacts", "review.md"),
      emptyReceipt ? "" : "Synthetic review evidence.\n",
    );
    if (receiptCollision) {
      await mkdir(path.join(run.scanDir, "artifacts"), { recursive: true });
      await writeFile(
        path.join(run.scanDir, "artifacts", "review.md"),
        "Synthetic unrelated parent review.\n",
      );
    }
    if (
      receiptRetry &&
      receiptCollision &&
      (receiptSpelling === "shared scan" ||
        receiptSpelling === "equivalent shared scan")
    ) {
      const collision = path.join(
        artifactDir,
        "artifacts",
        "01_context",
        "false_positive_feedback.json",
      );
      await mkdir(path.dirname(collision), { recursive: true });
      await writeFile(collision, "Synthetic unrelated retry receipt.\n");
    }
    const activeQualifiedRef = `${path.relative(run.scanDir, artifactDir).split(path.sep).join("/")}/artifacts/review.md`;
    const sharedRef = "artifacts/01_context/false_positive_feedback.json";
    if (sharedReceipt) {
      await mkdir(path.dirname(path.join(run.scanDir, sharedRef)), {
        recursive: true,
      });
      await writeFile(
        path.join(run.scanDir, sharedRef),
        emptyReceipt ? "" : "Synthetic review evidence.\n",
      );
    }
    if (sameNamedNewSurface) {
      const local = path.join(artifactDir, sharedRef);
      await mkdir(path.dirname(local), { recursive: true });
      await writeFile(local, "Synthetic review evidence.\n");
    }
    const closureReceiptRef = receiptCollision
      ? receiptSpelling === "shared scan"
        ? sharedRef
        : "artifacts/prior.txt"
      : "artifacts/review.md";
    if (closeRetriedSurface) {
      const local = path.join(artifactDir, closureReceiptRef);
      await mkdir(path.dirname(local), { recursive: true });
      await writeFile(local, "Synthetic review evidence.\n");
    }
    const activeReceiptRef = closeRetriedSurface
      ? closureReceiptRef
      : sameNamedNewSurface
        ? sharedRef
        : sharedReceipt
          ? sharedRef
          : activeReceiptSpelling === "worker"
            ? "artifacts/review.md"
            : activeReceiptSpelling === "scan"
              ? activeQualifiedRef
              : activeQualifiedRef.replace("artifacts/", "artifacts/./");
    const resultPath = path.join(artifactDir, "result.json");
    if (receiptOwnershipRetry) {
      const newRef = receiptCollision
        ? receiptSpelling === "shared scan"
          ? sharedRef
          : "artifacts/prior.txt"
        : "artifacts/review.md";
      const local = path.join(artifactDir, newRef);
      await mkdir(path.dirname(local), { recursive: true });
      await writeFile(local, "Synthetic review evidence.\n");
      const current = {
        id: "current",
        label: "Current review",
        disposition:
          receiptOwnershipRetry === "candidate" ? "rejected" : "no_issue_found",
        ...(receiptOwnershipRetry === "candidate"
          ? { candidateId: "prior-candidate" }
          : {}),
        receiptRefs: [newRef],
      };
      if (receiptOwnershipRetry === "unrelated") {
        current.receiptRefs = [
          receiptSpelling === "shared scan"
            ? sharedRef
            : `${path.relative(run.scanDir, path.dirname(artifactDir)).split(path.sep).join("/")}/attempts/attempt-01/artifacts/prior.txt`,
        ];
      }
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          layout: "worker",
          repoRoot: targetPath,
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete,
          findings: [],
          coverage: {
            completeness: status,
            surfaces: [
              current,
              ...(receiptOwnershipRetry === "unrelated"
                ? [
                    {
                      id: "closed",
                      label: "Separate review",
                      disposition: "no_issue_found",
                      receiptRefs: [newRef],
                    },
                  ]
                : []),
            ],
            explicitExclusions: [],
            deferred: [],
            ...(receiptOwnershipRetry === "unrelated"
              ? {
                  resolvedDeferred: [
                    {
                      id: "prior-gap",
                      reason: "The separate boundary is verified.",
                    },
                  ],
                }
              : {}),
          },
        },
      );
      rawSources.set(resultPath, await readFile(resultPath, "utf8"));
      return;
    }
    if (receiptRetry) {
      const saved = await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          repoRoot: targetPath,
          layout: "worker",
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete,
          findings: [],
          coverage: {
            completeness: retryPending ? "partial" : status,
            surfaces: [
              {
                id: "current",
                label: "Current review",
                disposition: "no_issue_found",
                receiptRefs: [activeReceiptRef],
                ...(receiptCollision
                  ? { provenance: { scanReceiptRefs: [activeReceiptRef] } }
                  : {}),
              },
            ],
            explicitExclusions: [],
            ...(closeRetriedSurface
              ? {
                  resolvedDeferred: [
                    { id: "prior-gap", reason: "The boundary is verified." },
                  ],
                }
              : {}),
            deferred: retryPending
              ? [
                  {
                    id: "prior-gap",
                    candidateId: "shared-prior-candidate",
                    reason: "The earlier boundary still needs verification.",
                    surfaceIds: ["prior", "prior-second"],
                  },
                ]
              : [],
          },
        },
      );

      if (rewriteReturnedCoverage && index === 0) {
        await recordCodexSecurityWorkerScanDraft(
          {
            root: artifactDir,
            repoRoot: targetPath,
            layout: "worker",
            scanId: run.scanId,
          },
          {
            scanId: run.scanId,
            complete,
            findings: [],
            coverage: structuredClone(saved.coverage),
          },
        );
      }
    } else {
      await recordCodexSecurityWorkerScanDraft(
        {
          root: artifactDir,
          repoRoot: targetPath,
          layout: "worker",
          scanId: run.scanId,
        },
        {
          scanId: run.scanId,
          complete: true,
          findings: index === 0 ? (retryFindings?.[1] ?? []) : [],
          coverage,
        },
      );
      for (const name of await readdir(path.join(artifactDir, "checkpoints"))) {
        const checkpointPath = path.join(artifactDir, "checkpoints", name);
        rawSources.set(checkpointPath, await readFile(checkpointPath, "utf8"));
      }
    }
    if (complete)
      rawSources.set(resultPath, await readFile(resultPath, "utf8"));
  };
  if (resume) {
    const workers = [];
    const seeded = continueAfterResume ? statuses.slice(0, -1) : statuses;
    for (const index of seeded.keys()) {
      const workerRoot = path.join(
        run.scanDir,
        "artifacts",
        "deep_discovery",
        "workers",
        `discovery-${String(index + 1).padStart(4, "0")}`,
      );
      const artifactDir = path.join(workerRoot, "output");
      const worker = {
        id: randomUUID(),
        scanId: run.scanId,
        kind: "discovery" as const,
        promptPath: path.join(workerRoot, "prompt.md"),
        artifactDir,
        attempt: index === 0 ? (extraReceiptRetry ? 3 : 2) : 1,
      };
      if (receiptRetry || (retryCoverage && index === 0)) {
        await writeReceiptAttempt(artifactDir);
        await archiveDirectory(
          artifactDir,
          path.join(workerRoot, "attempts", "attempt-01"),
        );
      }
      if (extraReceiptRetry && index === 0) {
        await writeDiscovery(artifactDir, index, false);
        await archiveDirectory(
          artifactDir,
          path.join(workerRoot, "attempts", "attempt-02"),
        );
      }
      await writeDiscovery(artifactDir, index);
      await writeFile(worker.promptPath, "Synthetic discovery prompt.\n");
      for (const status of ["queued", "running", "succeeded"] as const) {
        await store.updateWorker({
          ...worker,
          status,
          ...(status === "succeeded"
            ? { resultManifestPath: path.join(artifactDir, "result.json") }
            : {}),
        });
      }
      workers.push(worker);
    }
    const artifactDir = path.join(
      run.scanDir,
      "artifacts",
      "deep_discovery",
      "dedup",
      "dedup-0001",
      "output",
    );
    const promptPath = path.join(path.dirname(artifactDir), "prompt.md");
    await mkdir(artifactDir, { recursive: true });
    await writeFile(promptPath, "Synthetic reducer prompt.\n");
    const id = randomUUID();
    await store.claimDedup({
      id,
      scanId: run.scanId,
      workerIds: workers.map((worker) => worker.id),
      artifactDir,
      promptPath,
    });
    const resultManifestPath = path.join(artifactDir, "result.json");
    // Legacy accepted reducers omitted coverage entirely.
    await writeFile(
      resultManifestPath,
      JSON.stringify({
        scanId: run.scanId,
        findings: retryFindings?.flat() ?? [],
      }),
    );
    rawSources.set(
      resultManifestPath,
      await readFile(resultManifestPath, "utf8"),
    );
    await store.commitDedup({
      id,
      scanId: run.scanId,
      newFindings: retryFindings ? 1 : 0,
      resultManifestPath,
    });
    run = await store.get(run.scanId, threadId);
  }
  let discoveryCalls = 0;
  const executor = {
    async run(request: CodexWorkerRequest) {
      assert.equal(
        resume && !continueAfterResume,
        false,
        "accepted legacy sources should resume without new model work",
      );
      assert.ok(request.artifactContext);
      const thread = request.resumeThreadId ?? randomUUID();
      await request.onThreadStarted?.(thread);
      if (request.kind === "discovery") {
        discoveryCalls++;
        const index =
          Number(
            path
              .basename(path.dirname(request.artifactContext.root))
              .split("-")
              .at(-1),
          ) - 1;
        if (index === 0 && discoveryCalls === 1) {
          if (receiptRetry || (retryCoverage && index === 0)) {
            await writeReceiptAttempt(request.artifactContext.root);
          }
          return {
            threadId: thread,
            finalResponse: "Continue the unfinished audit.",
          };
        }
        await writeDiscovery(
          request.artifactContext.root,
          index,
          !(extraReceiptRetry && index === 0 && discoveryCalls === 2),
        );
      } else {
        await recordCodexSecurityDeepReduction(
          {
            ...request.artifactContext,
            repoRoot: targetPath,
            scanId: run.scanId,
          },
          { scanId: run.scanId, findings: retryFindings?.flat() ?? [] },
        );
      }
      return { threadId: thread, finalResponse: "Audit finished." };
    },
  };
  const coordinator = new DeepScanCoordinator({
    run,
    store,
    executor,
    pluginRoot,
    retryDelaysMs: extraReceiptRetry ? [1, 1] : [1],
    onComplete: async (draft, signal) => {
      if (stopBeforeDraft)
        throw new Error("Synthetic stop before parent draft.");
      await recordCodexSecurityScanDraftViaWorkbench(
        context,
        draft,
        runWorkbench,
        signal,
      );
    },
  });
  coordinator.start();
  const terminal = await coordinator.wait(undefined, 30_000);
  assert.equal(
    terminal?.status,
    stopBeforeDraft ? "failed" : "succeeded",
    terminal?.error ?? "Deep Scan did not reach the expected terminal state.",
  );
  assert.ok(terminal);
  if (!retryFindings) {
    assert.equal(
      terminal.noNewStreak,
      statuses.length,
      "source coverage must not change stopping policy",
    );
  }
  assert.equal(
    discoveryCalls,
    resume
      ? continueAfterResume
        ? 1
        : 0
      : statuses.length + (extraReceiptRetry ? 2 : 1),
  );
  const accepted = await store.get(run.scanId, threadId);
  for (const worker of (accepted.persistedWorkers ?? []).filter(
    (worker) => worker.kind === "dedup",
  )) {
    assert.ok(worker.resultManifestPath);
    const result = JSON.parse(
      await readFile(worker.resultManifestPath, "utf8"),
    );
    assert.equal(
      Object.hasOwn(result, "sourceCoverage"),
      false,
      "v1 reducers remain readable by earlier binaries",
    );
    if (!rawSources.has(worker.resultManifestPath)) {
      for (const name of await readdir(
        path.join(worker.artifactDir, "checkpoints"),
      )) {
        const checkpoint = JSON.parse(
          await readFile(
            path.join(worker.artifactDir, "checkpoints", name),
            "utf8",
          ),
        );
        assert.equal(
          Object.hasOwn(checkpoint, "sourceCoverage"),
          false,
          "v1 checkpoints remain readable by earlier binaries",
        );
      }
    }
  }
  if (stopBeforeDraft) {
    const recovered = await runWorkbench([
      "recover-scan-results",
      "--scan-id",
      run.scanId,
    ]);
    assert.equal(recovered.scan.resultsRecoveryNeeded, false);
    const coveragePath = path.join(run.scanDir, "coverage.json");
    const published = await readFile(coveragePath, "utf8");
    await runWorkbench(["recover-scan-results", "--scan-id", run.scanId]);
    assert.equal(await readFile(coveragePath, "utf8"), published);
  } else if (stopAfterDraft) {
    const stopped = await runWorkbench([
      "fail-scan",
      "--scan-id",
      run.scanId,
      "--message",
      "Synthetic stop after parent draft.",
    ]);
    assert.equal(stopped.scan.resultsRecoveryNeeded, interruptPublication);
    const recovered = await runWorkbench([
      "recover-scan-results",
      "--scan-id",
      run.scanId,
    ]);
    assert.equal(recovered.scan.resultsRecoveryNeeded, false);
  } else {
    await runWorkbench(["complete-scan", "--scan-id", run.scanId]);
    const completed = await getCodexSecurityCompletedScan(
      await createScanArtifactContext(run.scanId, runWorkbench),
      { scanId: run.scanId },
    );
    assert.deepEqual(
      completed.coverage,
      JSON.parse(
        await readFile(path.join(run.scanDir, "coverage.json"), "utf8"),
      ),
    );
  }
  for (const [file, bytes] of rawSources)
    assert.equal(await readFile(file, "utf8"), bytes);
  if (firstCheckpointReceipt) {
    const coverage = await readFixtureCoverage(run.scanDir);
    assert.equal(
      coverage.completeness,
      stopAfterDraft || stopBeforeDraft ? "partial" : "complete",
    );
    assert.deepEqual(
      coverage.deferred.map((row) => row.id),
      stopAfterDraft || stopBeforeDraft ? ["scan-stopped"] : [],
    );
    if (sameAttemptCloseout) {
      const surface = coverage.surfaces.find(
        (row) => row.label === "First checkpoint",
      );
      assert.ok(surface);
      assert.equal(surface.disposition, "no_issue_found");
      assert.equal(surface.receiptRefs.length, 2);
      const receipts = await Promise.all(
        surface.receiptRefs.map((ref) =>
          readFile(path.join(run.scanDir, ref), "utf8"),
        ),
      );
      assert.deepEqual(
        receipts.sort(),
        [
          "Synthetic first checkpoint.\n",
          "Synthetic later checkpoint.\n",
        ].sort(),
      );
      assert.equal(
        Object.hasOwn(surface.provenance ?? {}, "scanReceiptRefs"),
        false,
      );
      return { scanDir: run.scanDir, threadId, terminal };
    }
    for (const [label, expected] of [
      ["First checkpoint", "Synthetic first checkpoint.\n"],
      ["Later checkpoint", "Synthetic later checkpoint.\n"],
    ]) {
      const surface = coverage.surfaces.find((row) => row.label === label);
      assert.ok(surface);
      assert.equal(surface.receiptRefs.length, 1);
      assert.equal(
        await readFile(path.join(run.scanDir, surface.receiptRefs[0]), "utf8"),
        expected,
        "Each checkpoint keeps its observed receipt owner before any attempt archive exists.",
      );
      assert.equal(
        Object.hasOwn(surface.provenance ?? {}, "scanReceiptRefs"),
        false,
      );
    }
    return { scanDir: run.scanDir, threadId, terminal };
  }
  if (receiptOwnershipRetry) {
    const coverage = await readFixtureCoverage(run.scanDir);
    const current = coverage.surfaces.find(
      (surface) => surface.label === "Current review",
    );
    assert.ok(current);
    assert.equal(
      current.disposition,
      receiptOwnershipRetry === "candidate" ? "rejected" : "no_issue_found",
    );
    assert.equal(current.receiptRefs.length, 1);
    assert.equal(
      await readFile(path.join(run.scanDir, current.receiptRefs[0]), "utf8"),
      receiptOwnershipRetry === "unrelated"
        ? "Archived receipt.\n"
        : "Synthetic review evidence.\n",
      "Published receipt retains the source context of its actual observation.",
    );
    if (receiptOwnershipRetry === "unrelated") {
      const closed = coverage.surfaces.find(
        (surface) => surface.label === "Separate review",
      );
      assert.ok(closed);
      const bytes = await Promise.all(
        closed.receiptRefs.map((ref) =>
          readFile(path.join(run.scanDir, ref), "utf8"),
        ),
      );
      assert.deepEqual(
        bytes.sort(),
        ["Archived receipt.\n", "Synthetic review evidence.\n"].sort(),
      );
    }
    assert.equal(coverage.completeness, "complete");
    assert.deepEqual(coverage.deferred, []);
    return { scanDir: run.scanDir, threadId, terminal };
  }
  if (closeRetriedSurface) {
    const coverage = await readFixtureCoverage(run.scanDir);
    assert.equal(coverage.completeness, "complete");
    assert.deepEqual(coverage.deferred, []);
    assert.equal(coverage.surfaces.length, 1);
    const surface = coverage.surfaces[0];
    assert.equal(surface.label, "Current review");
    assert.equal(surface.disposition, "no_issue_found");
    assert.equal(
      surface.receiptRefs.length,
      2,
      "Closing a saved surface keeps both source-context receipts.",
    );
    const receipts = await Promise.all(
      surface.receiptRefs.map((ref) =>
        readFile(path.join(run.scanDir, ref), "utf8"),
      ),
    );
    assert.deepEqual(
      receipts.sort(),
      ["Archived receipt.\n", "Synthetic review evidence.\n"].sort(),
    );
    assert.equal(new Set(surface.receiptRefs).size, 2);
    return { scanDir: run.scanDir, threadId, terminal };
  }
  if (receiptRetry) {
    const coverage = await readFixtureCoverage(run.scanDir);
    for (const surface of coverage.surfaces) {
      assert.equal(
        Object.hasOwn(surface.provenance ?? {}, "scanReceiptRefs"),
        false,
        "host receipt ownership is not exposed as model-authored provenance",
      );
    }
    const current = coverage.surfaces.filter(
      (surface) => surface.label === "Current review",
    );
    assert.equal(current.length, 1);
    if (sharedReceipt)
      assert.equal(
        current[0].receiptRefs[0],
        "artifacts/01_context/false_positive_feedback.json",
      );
    else
      assert.match(
        current[0].receiptRefs[0],
        sameNamedNewSurface
          ? /\/output\/artifacts\/01_context\/false_positive_feedback\.json$/
          : /\/output\/artifacts\/review\.md$/,
      );
    assert.equal(
      await readFile(path.join(run.scanDir, current[0].receiptRefs[0]), "utf8"),
      emptyReceipt ? "" : "Synthetic review evidence.\n",
    );
    const prior = coverage.surfaces.filter((surface) =>
      surface.label.startsWith("Prior "),
    );
    assert.equal(prior.length, 2);
    assert.equal(prior[0].disposition, "needs_follow_up");
    const pending = coverage.deferred.filter(
      (item) => item.provenance?.candidateId === "shared-prior-candidate",
    );
    assert.equal(pending.length, 2);
    for (const item of pending) {
      assert.equal(item.candidateId, prior[0].candidateId);
      assert.deepEqual(
        item.surfaceIds,
        prior.map((surface) => surface.id),
      );
      assert.ok(
        prior.every((surface) => surface.candidateId === item.candidateId),
      );
    }
    assert.equal(coverage.completeness, "partial");
    assert.deepEqual(
      pending.map((item) => item.reason).sort(),
      [
        retryPending
          ? "The earlier boundary still needs verification."
          : "Verify the earlier attempt's unresolved boundary.",
        "Verify the same candidate's second boundary.",
      ].sort(),
    );
    if (
      receiptSpelling === "shared scan" ||
      receiptSpelling === "equivalent shared scan"
    )
      assert.equal(
        prior[0].receiptRefs[0],
        "artifacts/01_context/false_positive_feedback.json",
      );
    else
      assert.match(
        prior[0].receiptRefs[0],
        /\/attempts\/attempt-01\/artifacts\/prior\.txt$/,
      );
    assert.equal(
      await readFile(path.join(run.scanDir, prior[0].receiptRefs[0]), "utf8"),
      emptyReceipt ? "" : "Archived receipt.\n",
    );
  }
  return { scanDir: run.scanDir, threadId, terminal };
}
