import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { runScanEvents } from "../src/api.js";
import { loadContract } from "../src/contract.js";
import { PLUGIN_ROOT, copyCompletedScan } from "./plugin-root.js";
import { completedEvents } from "./support/api-events.js";
import { sha256 } from "./support/finding-identity.js";

const { temporaryDirectory, cleanup } = createApiTestFixtures();
afterEach(cleanup);

const bundlePath = join(await temporaryDirectory(), "deep-admission.mjs");
try {
  await build({
    stdin: {
      resolveDir: fileURLToPath(
        new URL("../../../plugins/codex-security/mcp-app/", import.meta.url),
      ),
      contents: `export * from "./src/artifact-scan-draft.ts";
      export * from "./src/deep-scan/artifacts.ts";
      export * from "./src/deep-scan/artifact-validation.ts";
      export * from "./src/deep-scan/worker-runner.ts";`,
    },
    bundle: true,
    format: "esm",
    platform: "node",
    loader: { ".md": "text" },
    outfile: bundlePath,
  });
} catch (error) {
  await cleanup().catch(() => undefined);
  throw error;
}
const {
  createDeepScanArtifacts,
  recordCodexSecurityScanDraftViaWorkbench,
  parseCanonicalScanDraft,
  parseScanDraft,
  validateDiscoveryArtifacts,
  DeepScanWorkerRunner,
} = await import(pathToFileURL(bundlePath).href);

interface DraftFixture {
  scanId: string;
  complete?: boolean;
  scope?: Record<string, unknown>;
  threatModel?: Record<string, unknown>;
  findings: Record<string, unknown>[];
  coverage: Record<string, unknown>;
}

const scanId = "811aef98-3709-4c2d-8b7a-742977521865";
type Mutation =
  | "missing-findings"
  | "inverted-lines"
  | "wrong-scan"
  | "legacy-details"
  | "legacy-evidence"
  | "legacy-surface";
const cases: {
  name: string;
  legacyCompleteness?: string;
  complete?: boolean;
  mutation?: Mutation;
  accepted: boolean;
  canonicalAccepted?: boolean;
}[] = [
  { name: "scope notes", complete: true, accepted: true },
  {
    name: "legacy completeness metadata",
    legacyCompleteness: "partial",
    complete: true,
    accepted: true,
  },
  { name: "omitted completion marker", accepted: true },
  {
    name: "legacy finding details",
    mutation: "legacy-details",
    accepted: false,
  },
  {
    name: "legacy evidence coordinates",
    mutation: "legacy-evidence",
    accepted: false,
    canonicalAccepted: true,
  },
  {
    name: "legacy surface ID",
    mutation: "legacy-surface",
    accepted: false,
    canonicalAccepted: true,
  },
  { name: "unfinished checkpoint", complete: false, accepted: false },
  { name: "missing findings", mutation: "missing-findings", accepted: false },
  {
    name: "inverted finding lines",
    mutation: "inverted-lines",
    accepted: false,
  },
  {
    name: "mismatched canonical scan ID",
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
    const semantic: DraftFixture = {
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
        ...(scenario.legacyCompleteness === undefined
          ? {}
          : { completeness: scenario.legacyCompleteness }),
        surfaces: [
          {
            label: "Archive extraction",
            disposition: "reported",
          },
        ],
        explicitExclusions: [],
        deferred: [{ reason: "Deployment controls remain unverified." }],
      },
    };
    await recordCodexSecurityScanDraftViaWorkbench(
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
      async (args: string[]) => {
        const draft = JSON.parse(
          await readFile(args[args.indexOf("--draft-path") + 1]!, "utf8"),
        );
        await Promise.all(
          [
            ["manifest", "scan-manifest.json"],
            ["findings", "findings.json"],
            ["coverage", "coverage.json"],
          ].map(([key, name]) =>
            writeFile(join(standardRoot, name!), JSON.stringify(draft[key!])),
          ),
        );
      },
    );
    const submitted = mutateDraft(semantic, scenario.mutation);
    if (scenario.mutation === "legacy-evidence") {
      expect(() => parseScanDraft(semantic)).not.toThrow();
      expect(() => parseScanDraft(submitted)).toThrow(/code_evidence/);
    }
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
    if (scenario.canonicalAccepted ?? scenario.accepted) {
      expect(standard.error).toBe(standard.finalization);
      expect(standard.finalizations).toBe(1);
    } else {
      expect(standard.error).toBeInstanceOf(Error);
      expect(standard.error).not.toBe(standard.finalization);
      expect(standard.finalizations).toBe(0);
    }
    if (scenario.accepted) {
      expect(deepResult.status).toBe("succeeded");
      expect(acceptedPaths).toEqual([deepResult.worker.resultPath]);
      const deepDraft: DraftFixture = await validateDiscoveryArtifacts(
        artifacts,
        deepResult.worker.resultPath,
        scanId,
      );
      const canonicalDraft = parseCanonicalScanDraft({
        scanId,
        manifest: JSON.parse(
          await readFile(join(standardRoot, "scan-manifest.json"), "utf8"),
        ),
        findings,
        coverage,
      });
      expect(deepDraft.findings).toEqual(canonicalDraft.findings);
      expect(deepDraft.coverage).toEqual(canonicalDraft.coverage);
      expect(deepDraft.scope).toEqual(canonicalDraft.scope);
      expect(deepDraft.threatModel).toEqual(canonicalDraft.threatModel);
    } else {
      expect(deepResult.status).toBe("failed");
      expect(acceptedPaths).toHaveLength(0);
    }
    const manifest = JSON.parse(
      await readFile(join(standardRoot, "scan-manifest.json"), "utf8"),
    );
    expect(manifest.scan.sealedAt).toBeUndefined();
    await expect(readFile(join(standardRoot, "report.md"))).rejects.toThrow();
  });
}

test("Standard admission accepts the existing scan ID and preserves BOM-prefixed canonical files", async () => {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  await mkdir(repository);
  const scanDir = await copyCompletedScan(root);
  const files = [];
  for (const name of ["scan-manifest.json", "findings.json", "coverage.json"]) {
    const file = join(scanDir, name);
    const original = await readFile(file);
    if (name === "scan-manifest.json")
      expect(JSON.parse(original.toString()).scan.id).toBe("scan_example_001");
    const bytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), original]);
    await writeFile(file, bytes);
    files.push({ file, bytes });
  }
  const standard = await observeStandardAdmission(repository, scanDir);
  expect(standard.error).toBe(standard.finalization);
  expect(standard.finalizations).toBe(1);
  for (const { file, bytes } of files)
    expect(await readFile(file)).toEqual(bytes);
});

test("sealed legacy evidence stays readable during canonical admission", async () => {
  const scanDir = await copyCompletedScan(await temporaryDirectory());
  const file = join(scanDir, "findings.json");
  const findings = JSON.parse(await readFile(file, "utf8"));
  const evidence = {
    id: "legacy-reversed-end",
    code: "read(input)",
    path: "src/legacy.py",
    startLine: 48,
    endLine: 47,
  };
  findings.findings[0].code_evidence = [evidence];
  const saved = JSON.stringify(findings);
  await writeFile(file, saved);
  const manifestFile = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
  manifest.scan.artifacts.find(
    (artifact: { path: string }) => artifact.path === "findings.json",
  ).sha256 = sha256(saved);
  await writeFile(manifestFile, JSON.stringify(manifest));
  const expectation = {
    repository: "/repository",
    repositoryRevision: "deadbeef",
    target: { kind: "repository" as const, paths: [] },
    mode: "standard" as const,
    pluginVersion: "0.1.0",
  };
  const contract = await loadContract(scanDir, {
    pluginRoot: PLUGIN_ROOT,
    expectation,
    workbenchValidated: true,
  });
  expect(contract.findings.findings[0]?.["code_evidence"]).toEqual([evidence]);
  expect(await readFile(file, "utf8")).toBe(saved);

  const coverage = JSON.parse(
    await readFile(join(scanDir, "coverage.json"), "utf8"),
  );
  const canonical = parseCanonicalScanDraft({
    scanId: manifest.scan.id,
    manifest,
    findings,
    coverage,
  });
  expect(canonical.findings[0]?.code_evidence).toEqual([evidence]);
});

test("canonical admission still rejects reversed typed evidence bounds", async () => {
  const scanDir = await copyCompletedScan(await temporaryDirectory());
  const file = join(scanDir, "findings.json");
  const findings = JSON.parse(await readFile(file, "utf8"));
  findings.findings[0].codeEvidence = [
    {
      id: "typed-reversed-end",
      label: "Source read",
      code: "read(input)",
      explanation: "The input reaches a read.",
      path: "src/typed.py",
      startLine: 48,
      endLine: 47,
    },
  ];
  await writeFile(file, JSON.stringify(findings));
  const outcome = await observeStandardAdmission("/repository", scanDir);
  expect(outcome.error).toMatchObject({
    message: expect.stringContaining(
      "codeEvidence[0].endLine must not precede startLine",
    ),
  });
  expect(outcome.finalizations).toBe(0);
});

async function observeStandardAdmission(
  repository: string,
  scanDir: string,
  scanId?: string,
) {
  const finalization = new Error("The enclosing finalizer owns the next step.");
  let finalizations = 0;
  const thread = {
    id: "standard-thread",
    async runStreamed() {
      return { events: completedEvents("standard-thread") };
    },
  };
  const error = await runScanEvents({
    scanId,
    thread,
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
  }).catch((error: unknown) => error);
  return {
    error,
    finalization,
    finalizations,
  };
}

function mutateDraft(input: DraftFixture, mutation?: Mutation): DraftFixture {
  const draft = structuredClone(input);
  if (mutation === "missing-findings")
    return { ...draft, findings: undefined } as unknown as DraftFixture;
  if (mutation === "wrong-scan")
    draft.scanId = "553a0c18-dcdf-4a3b-8e39-2751a8187bce";
  if (mutation === "inverted-lines") {
    const locations = draft.findings[0]!["locations"] as Record<
      string,
      unknown
    >[];
    locations[0]!["endLine"] = 1;
  }
  if (mutation === "legacy-surface")
    (draft.coverage["surfaces"] as Record<string, unknown>[])[0]!["id"] =
      "HTTP API";
  if (mutation === "legacy-evidence")
    draft.findings[0]!["code_evidence"] = [
      {
        id: "legacy-reversed-end",
        code: "read(input)",
        path: "src/legacy.py",
        startLine: 48,
        endLine: 47,
      },
    ];
  if (mutation === "legacy-details")
    draft.findings[0]!["validation"] = {
      method: null,
      limitations: "Legacy persisted limitation.",
    };
  return draft;
}
