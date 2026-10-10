import { createApiTestFixtures } from "./support/temporary-directories.js";
import { copyCompletedScan } from "./plugin-root.js";
import { mkdir, readFile, writeFile, utimes } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test, spyOn } from "bun:test";
import { build } from "esbuild";
import { runScanEvents } from "../src/api.js";
import type { ScanDraftInput } from "../src/accepted-audit.js";
import * as auditModule from "../src/accepted-audit.js";
import { resolvePluginPath } from "../src/runtime.js";
import { strToU8, zipSync } from "fflate";
import { createHash } from "node:crypto";
import { PLUGIN_ROOT } from "./plugin-root.js";
import { completedEvents } from "./support/api-events.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

const bundle = await build({
  stdin: {
    resolveDir: fileURLToPath(
      new URL("../../../plugins/codex-security/mcp-app/", import.meta.url),
    ),
    contents: `export * from "./src/artifact-scan-draft.ts";
      export { recordCodexSecurityScanDraft } from "./tests/scan-draft-writer-fixture.ts";
      export * from "./src/deep-scan/artifacts.ts";
      export * from "./src/deep-scan/artifact-validation.ts";
      export * from "./src/deep-scan/worker-runner.ts";`,
  },
  bundle: true,
  format: "esm",
  platform: "node",
  loader: { ".md": "text" },
  write: false,
});
const bundlePath = join(await temporaryDirectory(), "deep-admission.mjs");
await writeFile(bundlePath, bundle.outputFiles[0]!.contents);
const {
  createDeepScanArtifacts,
  recordCodexSecurityScanDraft,
  readDiscoveryAuditDraft,
  DeepScanWorkerRunner,
} = await import(pathToFileURL(bundlePath).href);

const scanId = "811aef98-3709-4c2d-8b7a-742977521865";
type Mutation =
  | "missing-findings"
  | "contradictory-coverage"
  | "inverted-lines"
  | "wrong-scan"
  | "legacy-details";
const cases: {
  name: string;
  coverage: "complete" | "partial" | "unknown";
  complete?: boolean;
  mutation?: Mutation;
  accepted: boolean;
}[] = [
  {
    name: "complete coverage",
    coverage: "complete",
    complete: true,
    accepted: true,
  },
  {
    name: "partial coverage",
    coverage: "partial",
    complete: true,
    accepted: true,
  },
  {
    name: "unknown coverage",
    coverage: "unknown",
    complete: true,
    accepted: true,
  },
  { name: "omitted completion marker", coverage: "partial", accepted: true },
  {
    name: "persisted legacy details",
    coverage: "partial",
    mutation: "legacy-details",
    accepted: true,
  },
  {
    name: "unfinished checkpoint",
    coverage: "partial",
    complete: false,
    accepted: false,
  },
  {
    name: "missing findings",
    coverage: "partial",
    mutation: "missing-findings",
    accepted: false,
  },
  {
    name: "complete coverage with deferred work",
    coverage: "partial",
    mutation: "contradictory-coverage",
    accepted: false,
  },
  {
    name: "inverted finding lines",
    coverage: "partial",
    mutation: "inverted-lines",
    accepted: false,
  },
  {
    name: "mismatched canonical scan ID",
    coverage: "partial",
    mutation: "wrong-scan",
    accepted: false,
  },
];

for (const scenario of cases) {
  test(`Standard and Deep production admission: ${scenario.name}`, async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const standardRoot = join(root, "standard");
    const deepRoot = join(root, "deep");
    await Promise.all([
      mkdir(repository),
      mkdir(standardRoot, { mode: 0o700 }),
      mkdir(deepRoot, { mode: 0o700 }),
    ]);
    const semantic: ScanDraftInput = {
      scanId,
      ...(scenario.complete === undefined
        ? {}
        : { complete: scenario.complete }),
      scope: { summary: "Archive extraction." },
      threatModel: { summary: "An untrusted caller supplies archive entries." },
      findings: [
        {
          ruleId: "path-traversal.archive",
          title: "Unsafe archive extraction",
          summary: "An archive entry reaches a filesystem write.",
          severity: { level: "high" },
          confidence: { level: "high", rationale: "Source review." },
          taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
          locations: [{ path: "extract.py", startLine: 4, endLine: 7 }],
          remediation: "Validate the resolved output path before writing.",
          provenance: { source: "local_plugin", candidateId: "archive-entry" },
        },
      ],
      coverage: {
        completeness: scenario.coverage,
        surfaces: [{ label: "Archive extraction", disposition: "reported" }],
        explicitExclusions: [],
        deferred:
          scenario.coverage === "complete"
            ? []
            : [
                {
                  id: "deployment",
                  reason: "Deployment controls remain unverified.",
                },
              ],
      },
    };
    await recordCodexSecurityScanDraft(
      {
        root: standardRoot,
        repoRoot: repository,
        layout: "scan",
        scanId,
        mode: "standard",
        status: "running",
        scope: ".",
        targetContract: {
          target: {
            allowedKinds: ["directory_snapshot"],
            targetId: "target_example",
            displayName: "example",
            requiredSnapshotDigest: `codex-security-snapshot/v1:sha256:${"a".repeat(64)}`,
          },
          scope: { requiredIncludePaths: ["."], requiredExcludePaths: [] },
          diffTarget: null,
        },
      },
      semantic,
    );
    const submitted = mutateDraft(semantic, scenario.mutation);
    const findings = {
      scanId: submitted.scanId,
      findings: submitted.findings?.map((finding) => ({
        ...finding,
        findingId: "finding_example",
        occurrenceId: "occurrence_example",
        fingerprints: { identity: "synthetic" },
      })),
    };
    const coverage = JSON.parse(
      await readFile(join(standardRoot, "coverage.json"), "utf8"),
    );
    Object.assign(coverage, submitted.coverage);
    await Promise.all([
      writeFile(join(standardRoot, "findings.json"), JSON.stringify(findings)),
      writeFile(join(standardRoot, "coverage.json"), JSON.stringify(coverage)),
    ]);
    const standard = await observeStandardAdmission(
      repository,
      standardRoot,
      scanId,
    );

    const artifacts = createDeepScanArtifacts(deepRoot);
    const acceptedPaths: string[] = [];
    let executions = 0;
    const runner = new DeepScanWorkerRunner({
      run: {
        scanId,
        scanDir: deepRoot,
        targetPath: repository,
        scope: ".",
        config: { subagents: 0 },
      },
      artifacts,
      pluginRoot: PLUGIN_ROOT,
      signal: new AbortController().signal,
      retryDelaysMs: [],
      random: () => 0,
      log: () => {},
      clock: { now: () => Date.now(), sleep: async () => {} },
      executor: {
        async run(request: {
          artifactContext: { root: string };
          onThreadStarted?: (id: string) => Promise<void>;
        }) {
          executions++;
          await request.onThreadStarted?.("deep-thread");
          await writeFile(
            join(request.artifactContext.root, "result.json"),
            JSON.stringify(submitted),
          );
          return { threadId: "deep-thread" };
        },
      },
      store: {
        async updateWorker(update: {
          status: string;
          resultManifestPath?: string;
        }) {
          if (update.status === "succeeded") {
            acceptedPaths.push(update.resultManifestPath!);
            return { ...update, completionSequence: 1 };
          }
          return update;
        },
      },
    });
    const deepResult = await runner.runDiscoveryWorker(
      "worker-1",
      "discovery-1",
    );
    expect(executions).toBe(1);
    if (scenario.accepted) {
      expect(standard.error).toBe(standard.finalization);
      expect(standard.finalizations).toBe(1);
      expect(standard.drafts).toHaveLength(1);
      expect(deepResult.status).toBe("succeeded");
      expect(acceptedPaths).toEqual([deepResult.worker.resultPath]);
      const deepDraft: ScanDraftInput = await readDiscoveryAuditDraft(
        artifacts,
        deepResult.worker.resultPath,
        scanId,
      );
      expect(standard.drafts[0]!.findings).toEqual(deepDraft.findings);
      expect(standard.drafts[0]!.coverage).toEqual(deepDraft.coverage);
      expect(standard.drafts[0]!.scope).toEqual(deepDraft.scope);
      expect(standard.drafts[0]!.threatModel).toEqual(deepDraft.threatModel);
      if (scenario.mutation === "legacy-details") {
        expect(deepDraft.findings[0]!["validation"]).toEqual({
          limitations: ["Legacy persisted limitation."],
        });
      }
    } else {
      expect(standard.error).toBeInstanceOf(Error);
      expect(standard.error).not.toBe(standard.finalization);
      expect(standard.finalizations).toBe(0);
      expect(deepResult.status).toBe("failed");
      expect(acceptedPaths).toHaveLength(0);
    }
    expect(standard.calls).toBe(
      scenario.accepted || scenario.complete === false ? 1 : 0,
    );
    const manifest = JSON.parse(
      await readFile(join(standardRoot, "scan-manifest.json"), "utf8"),
    );
    expect(manifest.scan.sealedAt).toBeUndefined();
    await expect(readFile(join(standardRoot, "report.md"))).rejects.toThrow();
  });
}

test("Standard admission preserves existing canonical scan IDs", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  const scanDir = await copyCompletedScan(root);
  const manifest = JSON.parse(
    await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
  );
  const standard = await observeStandardAdmission(repository, scanDir);
  expect(manifest.scan.id).toBe("scan_example_001");
  expect(standard.error).toBe(standard.finalization);
  expect(standard.finalizations).toBe(1);
  expect(standard.drafts).toHaveLength(1);
  expect(standard.calls).toBe(1);
  expect(standard.drafts[0]!.scanId).toBe(manifest.scan.id);
});

test.each(["directory", "zip"])(
  "accepted older %s plugin does not supply the SDK admission reader",
  async (kind) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const manifest = JSON.stringify({
      name: "codex-security",
      version: "0.1.0",
    });
    const oldHelper =
      "throw new Error('The older CLI-only helper must not be imported.');";
    let selected: string;
    if (kind === "directory") {
      const plugin = join(root, "older-plugin");
      await mkdir(join(plugin, ".codex-plugin"), { recursive: true });
      await mkdir(join(plugin, "mcp"));
      await writeFile(join(plugin, ".codex-plugin/plugin.json"), manifest);
      await writeFile(join(plugin, "mcp/helpers.mjs"), oldHelper);
      selected = await resolvePluginPath(plugin, join(root, "bootstrap"));
    } else {
      const archive = join(root, "older-plugin.zip");
      await writeFile(
        archive,
        zipSync({
          "release/.codex-plugin/plugin.json": strToU8(manifest),
          "release/mcp/helpers.mjs": strToU8(oldHelper),
        }),
      );
      selected = await resolvePluginPath(archive, join(root, "bootstrap"));
    }
    const scanDir = await copyCompletedScan(root);
    const marker = new Error("The enclosing finalizer was reached.");
    let finalizations = 0;
    const error = await runScanEvents({
      thread: {
        id: "standard-thread",
        async runStreamed() {
          return { events: completedEvents("standard-thread") };
        },
      },
      events: completedEvents("standard-thread"),
      signal: new AbortController().signal,
      scanDir,
      pluginRoot: selected,
      expectation: {
        repository,
        repositoryRevision: null,
        target: { kind: "repository", paths: [] },
        mode: "standard",
        pluginVersion: "0.1.0",
      },
      onFinalize: async () => {
        finalizations++;
        throw marker;
      },
    }).catch((error: unknown) => error);
    expect(error).toBe(marker);
    expect(finalizations).toBe(1);
  },
);

test.each([
  "complete head",
  "unfinished head",
  "newer canonical",
  "wrong scan",
  "missing head",
])("Standard admission honors committed publication: %s", async (scenario) => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  const scanDir = await copyCompletedScan(root);
  const names = ["scan-manifest.json", "findings.json", "coverage.json"];
  const [manifest, findings, coverage] = await Promise.all(
    names.map(async (name) =>
      JSON.parse(await readFile(join(scanDir, name), "utf8")),
    ),
  );
  manifest.scan.id = findings.scanId = coverage.scanId = scanId;
  delete manifest.scan.sealedAt;
  delete manifest.scan.completedAt;
  manifest.scan.complete = false;
  const helper = (
    await import(pathToFileURL(join(PLUGIN_ROOT, "mcp/helpers.mjs")).href)
  ).default;
  const checkpoint: ScanDraftInput = helper.parseCanonicalScanDraft({
    scanId,
    manifest,
    findings,
    coverage,
  });
  checkpoint.complete =
    scenario === "complete head" ||
    scenario === "wrong scan" ||
    scenario === "missing head";
  if (scenario === "wrong scan")
    checkpoint.scanId = "553a0c18-dcdf-4a3b-8e39-2751a8187bce";
  const encoded = JSON.stringify(checkpoint);
  const filename = createHash("sha256").update(encoded).digest("hex") + ".json";
  await mkdir(join(scanDir, "checkpoints"));
  if (scenario !== "missing head")
    await writeFile(join(scanDir, "checkpoints", filename), encoded);
  await writeFile(
    join(scanDir, "checkpoint-head.json"),
    JSON.stringify({ checkpoint: filename }),
  );
  await utimes(join(scanDir, "checkpoint-head.json"), 2000, 2000);
  if (scenario === "newer canonical") manifest.scan.complete = true;
  for (const [index, document] of [manifest, findings, coverage].entries()) {
    const name = names[index]!;
    await writeFile(join(scanDir, name), JSON.stringify(document));
    const time = scenario === "newer canonical" ? 3000 : 1000;
    await utimes(join(scanDir, name), time, time);
  }
  const result = await observeStandardAdmission(repository, scanDir, scanId);
  const accepted =
    scenario === "complete head" || scenario === "newer canonical";
  expect(result.finalizations).toBe(accepted ? 1 : 0);
  if (accepted) expect(result.error).toBe(result.finalization);
  else expect(result.error).toBeInstanceOf(Error);
  expect(manifest.scan.sealedAt).toBeUndefined();
});

async function observeStandardAdmission(
  repository: string,
  scanDir: string,
  scanId?: string,
) {
  const drafts: ScanDraftInput[] = [];
  const original = auditModule.auditEvidence;
  const observer = spyOn(auditModule, "auditEvidence").mockImplementation(
    (draft) => {
      drafts.push(draft);
      return original(draft);
    },
  );
  const finalization = new Error("The enclosing finalizer owns the next step.");
  let finalizations = 0;
  const error = await runScanEvents({
    scanId,
    thread: {
      id: "standard-thread",
      async runStreamed() {
        return { events: completedEvents("standard-thread") };
      },
    },
    events: completedEvents("standard-thread"),
    signal: new AbortController().signal,
    scanDir,
    pluginRoot: PLUGIN_ROOT,
    expectation: {
      repository,
      repositoryRevision: null,
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.0",
    },
    onFinalize: async () => {
      finalizations++;
      throw finalization;
    },
  })
    .catch((error: unknown) => error)
    .finally(() => observer.mockRestore());
  return {
    error,
    finalization,
    finalizations,
    drafts,
    calls: drafts.length,
  };
}

function mutateDraft(
  input: ScanDraftInput,
  mutation?: Mutation,
): ScanDraftInput {
  const draft = structuredClone(input);
  if (mutation === "missing-findings")
    return { ...draft, findings: undefined } as unknown as ScanDraftInput;
  if (mutation === "wrong-scan")
    draft.scanId = "553a0c18-dcdf-4a3b-8e39-2751a8187bce";
  if (mutation === "contradictory-coverage")
    draft.coverage["completeness"] = "complete";
  if (mutation === "inverted-lines") {
    const locations = draft.findings[0]!["locations"] as Record<
      string,
      unknown
    >[];
    locations[0]!["endLine"] = 1;
  }
  if (mutation === "legacy-details")
    draft.findings[0]!["validation"] = {
      method: null,
      limitations: "Legacy persisted limitation.",
    };
  return draft;
}

// File-authored canonical artifacts use the public coverage ID contract.
test.each(["API v1", "api-v1"])(
  "canonical surface admission: %s",
  async (id) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const scanDir = await copyCompletedScan(root);
    const coveragePath = join(scanDir, "coverage.json");
    const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
    coverage.surfaces[0].id = id;
    await writeFile(coveragePath, JSON.stringify(coverage));
    const result = await observeStandardAdmission(repository, scanDir);
    console.log(
      JSON.stringify({
        id,
        finalizations: result.finalizations,
        error: String(result.error),
      }),
    );
    expect(result.error).toBe(result.finalization);
    expect(result.finalizations).toBe(1);
  },
);
