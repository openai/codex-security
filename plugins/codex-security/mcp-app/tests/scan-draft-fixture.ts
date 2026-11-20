import { importModule } from "./import-module.ts";
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

export function reviewDraft<Finding extends Record<string, unknown>>(
  complete: boolean,
  reviewState: Record<string, unknown> = {},
  findings: Finding[] = [],
) {
  const draft = workerDraft(findings);
  return {
    ...draft,
    complete,
    reviewState: { ...draft.reviewState, ...reviewState },
  };
}

function loadHistoryRuntime() {
  return importModule({
    stdin: {
      contents: `export { recordCodexSecurityWorkerScanDraft } from "./artifact-scan-draft.ts";
        export { archiveDirectory, createDeepScanArtifacts } from "./deep-scan/artifacts.ts";
        export { readAcceptedDiscovery, validateDiscoveryArtifacts } from "./deep-scan/artifact-validation.ts";`,
      resolveDir: path.join(import.meta.dirname, "../src"),
    },
  });
}
let historyRuntime: ReturnType<typeof loadHistoryRuntime> | undefined;

export async function workerHistoryFixture(t: TestContext, attempt: number) {
  const runtime = await (historyRuntime ??= loadHistoryRuntime());
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
  const workerContext = {
    root: output,
    repoRoot: root,
    scanId,
    layout: "worker",
  };
  const worker = { id: "synthetic-worker", attempt, resultPath };
  const artifacts = runtime.createDeepScanArtifacts(scanRoot);
  return {
    root,
    scanRoot,
    workerRoot,
    output,
    resultPath,
    workerContext,
    worker,
    artifacts,
    record: (draft: unknown) =>
      runtime.recordCodexSecurityWorkerScanDraft(workerContext, draft),
    readAccepted: () =>
      runtime.readAcceptedDiscovery(artifacts, worker, scanId),
    validate: () =>
      runtime.validateDiscoveryArtifacts(artifacts, resultPath, scanId),
    archive: (destination = path.join(workerRoot, "attempts/attempt-01")) =>
      runtime.archiveDirectory(output, destination),
  };
}
