import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import type { TestContext } from "node:test";
import { temporaryDirectory } from "./support/temporary-directories.ts";

export const scanId = "7fc17317-9594-49e0-b06a-d72fd7e14bba";

export function workerDraft<Finding extends Record<string, unknown>>(
  findings: Finding[],
  extra = {},
) {
  return {
    scanId,
    findings,
    reviewState: {
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
    ...extra,
  };
}

export function finding(id: string, repositoryPath: string) {
  return {
    ruleId: "cross-site-scripting." + id,
    identity: { anchor: id },
    title: "Unsafe request output " + id,
    summary: "A request-controlled value reaches an HTML response.",
    severity: { level: "high" as const },
    confidence: {
      level: "high" as const,
      rationale: "The source establishes reachability.",
    },
    taxonomy: { category: "cross-site-scripting", cwe: ["CWE-79"] },
    locations: [{ path: repositoryPath, startLine: 1, endLine: 2 }],
    remediation: "Encode request-controlled values before emitting HTML.",
    provenance: { source: "local_plugin" },
  };
}

export async function workerHistoryFixture(t: TestContext, attempt: number) {
  const root = await temporaryDirectory("worker-history-", true);
  t.after(() => rm(root, { recursive: true, force: true }));
  const scanRoot = path.join(root, "scan");
  const workerRoot = path.join(
    scanRoot,
    "artifacts/deep_discovery/workers/discovery-0001",
  );
  const output = path.join(workerRoot, "output");
  await mkdir(output, { recursive: true });
  const resultPath = path.join(output, "result.json");
  const reducerRoot = path.join(
    scanRoot,
    "artifacts/deep_discovery/dedup/dedup-0001/output",
  );
  await mkdir(reducerRoot, { recursive: true });
  const workerContext = {
    root: output,
    repoRoot: root,
    scanId,
    layout: "worker",
  };
  const context = {
    root: reducerRoot,
    repoRoot: root,
    scanId,
    layout: "reducer",
    deepReducer: {
      scanRoot,
      claimedWorkers: [{ id: "synthetic-worker", attempt, resultPath }],
    },
  };
  return {
    root,
    scanRoot,
    workerRoot,
    output,
    resultPath,
    reducerRoot,
    workerContext,
    context,
  };
}
