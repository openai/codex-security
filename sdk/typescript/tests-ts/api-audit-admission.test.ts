import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, expect, test } from "bun:test";
import { build } from "esbuild";
import { runScanEvents } from "../src/api.js";
import { loadContract } from "../src/contract.js";
import { sha256 } from "./support/finding-identity.js";
import { runWorkbench } from "../src/runtime.js";
import { TestClient } from "./support/api-client.js";
import { preparedRuntime } from "./support/api-events.js";
import { runNodePython } from "./support/python-probe.js";
import type { ScanDraftInput } from "../src/accepted-audit.js";
import { PLUGIN_ROOT, copyCompletedScan } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import { completedEvents } from "./support/api-events.js";

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
      export { recordCodexSecurityScanDraft } from "./tests/scan-draft-writer-fixture.ts";
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
  parseCanonicalScanDraft,
  parseScanDraft,
  recordCodexSecurityScanDraft,
  recordCodexSecurityScanDraftViaWorkbench,
  readDiscoveryAuditDraft,
  DeepScanWorkerRunner,
} = await import(pathToFileURL(bundlePath).href);

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
      expect(standard.drafts).toHaveLength(1);
    } else {
      expect(standard.error).toBeInstanceOf(Error);
      expect(standard.error).not.toBe(standard.finalization);
      expect(standard.finalizations).toBe(0);
    }
    if (scenario.accepted) {
      expect(deepResult.status).toBe("succeeded");
      expect(acceptedPaths).toEqual([deepResult.worker.resultPath]);
      const deepDraft: ScanDraftInput = await readDiscoveryAuditDraft(
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
  expect(standard.drafts[0]!.scanId).toBe(manifest.scan.id);
});

test.each(["http", "HTTP", "HTTP API"])(
  "Standard admission preserves file-authored canonical surface ID %s",
  async (surfaceId) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const scanDir = await copyCompletedScan(root);
    const coveragePath = join(scanDir, "coverage.json");
    const coverage = JSON.parse(await readFile(coveragePath, "utf8"));
    coverage.surfaces[0].id = surfaceId;
    await writeFile(coveragePath, JSON.stringify(coverage));
    const standard = await observeStandardAdmission(repository, scanDir);
    expect(standard.error).toBe(standard.finalization);
    expect(standard.finalizations).toBe(1);
    expect(
      (standard.drafts[0]!.coverage["surfaces"] as { id: string }[])[0]!.id,
    ).toBe(surfaceId);
    expect(JSON.parse(await readFile(coveragePath, "utf8"))).toEqual(coverage);
  },
);

test.each(["current", "legacy"])(
  "Standard admission retains selected %s plugin helper compatibility",
  async (kind) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const scanDir = await copyCompletedScan(root);
    const pluginRoot = join(root, "selected-plugin");
    await mkdir(join(pluginRoot, "mcp"), { recursive: true });
    await writeFile(
      join(pluginRoot, "mcp", "helpers.mjs"),
      kind === "legacy"
        ? "process.exitCode = 2;\n"
        : `export { default } from ${JSON.stringify(pathToFileURL(join(PLUGIN_ROOT, "mcp", "helpers.mjs")).href)};\n`,
    );
    const finalization = new Error("Finalization receives the admitted scan.");
    let finalizations = 0;
    const previousExitCode = process.exitCode;
    try {
      const error = await runScanEvents({
        thread: { id: "standard-thread" },
        events: completedEvents("standard-thread"),
        signal: new AbortController().signal,
        scanDir,
        pluginRoot,
        expectation: {
          repository,
          repositoryRevision: null,
          target: { kind: "repository", paths: [] },
          mode: "standard",
          pluginVersion: "0.1.95",
        },
        onFinalize: async () => {
          finalizations++;
          throw finalization;
        },
      }).catch((error: unknown) => error);
      expect(error).toBe(finalization);
      expect(finalizations).toBe(1);
      expect(process.exitCode).toBe(previousExitCode);
    } finally {
      process.exitCode = previousExitCode;
    }
  },
);

test.each(["scan-manifest.json", "findings.json", "coverage.json"])(
  "Standard admission preserves BOM-prefixed %s bytes",
  async (name) => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(repository);
    const scanDir = await copyCompletedScan(root);
    const file = join(scanDir, name);
    const bytes = Buffer.concat([
      Buffer.from([0xef, 0xbb, 0xbf]),
      await readFile(file),
    ]);
    await writeFile(file, bytes);
    const standard = await observeStandardAdmission(repository, scanDir);
    expect(standard.error).toBe(standard.finalization);
    expect(standard.finalizations).toBe(1);
    expect(await readFile(file)).toEqual(bytes);
  },
);

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
  const manifest = await replaceSealedFindings(scanDir, saved);
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

test.each(["standard", "deep"] as const)(
  "managed %s preparation without accepted authority rejects historical findings",
  async (mode) => {
    const scanDir = await copyCompletedScan(await temporaryDirectory());
    const file = join(scanDir, "findings.json");
    const findings = JSON.parse(await readFile(file, "utf8"));
    findings.findings[0].root_cause = { summary: "Unaccepted legacy detail." };
    const original = JSON.stringify(findings);
    await replaceSealedFindings(scanDir, original);
    let preparations = 0;
    await expect(
      runScanEvents({
        thread: { id: "synthetic-thread" },
        events: completedEvents("synthetic-thread"),
        signal: new AbortController().signal,
        scanDir,
        pluginRoot: PLUGIN_ROOT,
        expectation: {
          repository: "/repository",
          repositoryRevision: "deadbeef",
          target: { kind: "repository", paths: [] },
          mode,
          pluginVersion: "0.1.0",
        },
        workbenchValidated: true,
        acceptedFindings: () => false,
        onFinalize: async () => {
          preparations++;
          return null;
        },
      }),
    ).rejects.toThrow("root_cause");
    expect(preparations).toBe(1);
    expect(await readFile(file, "utf8")).toBe(original);
  },
);

test("recovered admission does not repeat successful managed finalization", async () => {
  const scanDir = await copyCompletedScan(await temporaryDirectory());
  const file = join(scanDir, "findings.json");
  const saved = await readFile(file);
  await writeFile(file, "interrupted synthetic artifact");
  const finalizedUsage = { input_tokens: 13, output_tokens: 5 };
  let finalizations = 0;
  let recoveries = 0;
  const result = await runScanEvents({
    thread: { id: "standard-thread" },
    events: completedEvents("standard-thread"),
    signal: new AbortController().signal,
    scanDir,
    pluginRoot: PLUGIN_ROOT,
    expectation: {
      repository: "/repository",
      repositoryRevision: "deadbeef",
      target: { kind: "repository", paths: [] },
      mode: "standard",
      pluginVersion: "0.1.0",
    },
    workbenchValidated: true,
    onFinalize: async () => {
      finalizations++;
      return finalizedUsage;
    },
    recoverCompletion: async () => {
      recoveries++;
      await writeFile(file, saved);
      return {
        threadId: "standard-thread",
        status: "completed",
        finalResponse: "Recovered synthetic scan.",
        usage: null,
        lastStreamError: null,
      };
    },
  });
  expect(recoveries).toBe(1);
  expect(finalizations).toBe(1);
  expect(result.turnResult.usage).toEqual(finalizedUsage);
});

async function replaceSealedFindings(scanDir: string, contents: string) {
  await writeFile(join(scanDir, "findings.json"), contents);
  const manifestFile = join(scanDir, "scan-manifest.json");
  const manifest = JSON.parse(await readFile(manifestFile, "utf8"));
  manifest.scan.artifacts.find(
    (artifact: { path: string }) => artifact.path === "findings.json",
  ).sha256 = sha256(contents);
  await writeFile(manifestFile, JSON.stringify(manifest));
  return manifest;
}

async function observeStandardAdmission(
  repository: string,
  scanDir: string,
  scanId?: string,
) {
  const drafts: ScanDraftInput[] = [];
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
      const [manifest, findings, coverage] = await Promise.all(
        ["scan-manifest.json", "findings.json", "coverage.json"].map(
          async (name) =>
            JSON.parse(
              new TextDecoder("utf-8", { fatal: true }).decode(
                await readFile(join(scanDir, name)),
              ),
            ),
        ),
      );
      drafts.push(
        parseCanonicalScanDraft({
          scanId: scanId ?? manifest.scan.id,
          manifest,
          findings,
          coverage,
        }),
      );
      throw finalization;
    },
  }).catch((error: unknown) => error);
  return {
    error,
    finalization,
    finalizations,
    drafts,
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

for (const scenario of ["published", "interrupted", "unfinished"] as const) {
  test(`Standard admission reconciles its committed terminal checkpoint: ${scenario}`, async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const home = join(root, "codex-home");
    const scanDir = join(root, "scan");
    await mkdir(repository);
    await writeFile(join(repository, "extract.py"), "# Synthetic source\n");
    await mkdir(home);
    await mkdir(scanDir, { mode: 0o700 });
    const environment = {
      ...process.env,
      CODEX_HOME: home,
      CODEX_SECURITY_STATE_DIR: join(root, "state"),
    };
    const python = process.env["PYTHON"] ?? Bun.which("python3")!;
    let registration: Record<string, unknown>;
    let savedOptions: Parameters<typeof runWorkbench>[0];
    const commands: string[] = [];
    const runtime = preparedRuntime(home);
    runtime.plugin.version = JSON.parse(
      await readFile(join(PLUGIN_ROOT, ".codex-plugin", "plugin.json"), "utf8"),
    ).version;
    const client = new TestClient(
      {},
      {
        environment,
        prepareRuntime: async () => ({ ...runtime, environment }),
        resolvePluginPython: async () => python,
        prepareOutputDir: async () => scanDir,
        runWorkbench: async (options, args, input) => {
          savedOptions = options;
          commands.push(args[0]!);
          const value = await runWorkbench(options, args, input);
          if (args[0] === "register-cli-scan") registration = value;
          return value;
        },
        createCodex: () => ({
          startThread: () => ({
            id: null,
            async runStreamed() {
              const id = String(registration!["scanId"]);
              const context = {
                root: scanDir,
                repoRoot: repository,
                layout: "scan",
                scanId: id,
                mode: "standard",
                status: "running",
                scope: ".",
                targetContract: registration!["contract"],
              };
              const draft: ScanDraftInput = {
                scanId: id,
                complete: false,
                scope: { summary: "Archive extraction." },
                threatModel: {
                  summary: "An untrusted caller supplies archive entries.",
                },
                findings: [
                  {
                    ruleId: "path-traversal.archive",
                    title: "Unsafe archive extraction",
                    summary: "An archive entry reaches a filesystem write.",
                    severity: { level: "high" },
                    confidence: { level: "high", rationale: "Source review." },
                    taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
                    locations: [
                      { path: "extract.py", startLine: 1, endLine: 1 },
                    ],
                    remediation:
                      "Validate the resolved output path before writing.",
                    provenance: {
                      source: "local_plugin",
                      candidateId: "archive-entry",
                    },
                  },
                ],
                coverage: {
                  completeness: "partial",
                  surfaces: [
                    {
                      id: "archive",
                      label: "Archive extraction",
                      disposition: "reported",
                    },
                  ],
                  explicitExclusions: [],
                  deferred: [
                    {
                      id: "deployment",
                      reason: "Deployment controls remain unverified.",
                    },
                  ],
                },
              };
              const publish = (args: readonly string[]) =>
                runWorkbench(savedOptions!, args);
              await recordCodexSecurityScanDraftViaWorkbench(
                context,
                draft,
                publish,
              );
              if (scenario !== "unfinished") {
                const terminal = { ...draft, complete: true };
                if (scenario === "interrupted") {
                  await expect(
                    recordCodexSecurityScanDraftViaWorkbench(
                      context,
                      terminal,
                      async (args: readonly string[]) => {
                        const result = runNodePython(
                          python,
                          [
                            "-c",
                            [
                              "import sys",
                              "sys.path.insert(0, sys.argv[1])",
                              "import workbench_db as db",
                              "original = db.saved_results.write_scan_local_bytes",
                              "def fail_manifest(root, relative, contents):",
                              "    if relative == 'scan-manifest.json': raise OSError('Synthetic interrupted canonical manifest publication')",
                              "    return original(root, relative, contents)",
                              "db.saved_results.write_scan_local_bytes = fail_manifest",
                              "sys.argv = ['workbench_db.py', *sys.argv[2:]]",
                              "db.main()",
                            ].join("\n"),
                            join(PLUGIN_ROOT, "scripts"),
                            ...args,
                          ],
                          {
                            env: {
                              ...process.env,
                              ...savedOptions!.environment,
                            },
                          },
                        );
                        expect(result.status).toBe(1);
                        expect(result.stderr).toContain(
                          "Synthetic interrupted canonical manifest publication",
                        );
                        throw new Error(
                          "Synthetic interrupted canonical manifest publication",
                        );
                      },
                    ),
                  ).rejects.toThrow(
                    "Synthetic interrupted canonical manifest publication",
                  );
                  const head = JSON.parse(
                    await readFile(
                      join(scanDir, "checkpoint-head.json"),
                      "utf8",
                    ),
                  );
                  const checkpoint = JSON.parse(
                    await readFile(
                      join(scanDir, "checkpoints", head.checkpoint),
                      "utf8",
                    ),
                  );
                  expect(checkpoint.complete).not.toBe(false);
                  expect(
                    JSON.parse(
                      await readFile(
                        join(scanDir, "scan-manifest.json"),
                        "utf8",
                      ),
                    ).scan.complete,
                  ).toBe(false);
                } else
                  await recordCodexSecurityScanDraftViaWorkbench(
                    context,
                    terminal,
                    publish,
                  );
              }
              return { events: completedEvents("standard-checkpoint-thread") };
            },
          }),
        }),
      },
    );
    try {
      const pending = client.run(repository);
      if (scenario === "unfinished") {
        await expect(pending).rejects.toThrow();
        expect(commands).not.toContain("complete-scan");
      } else {
        const result = await pending;
        expect(result.findings.findings).toHaveLength(1);
        expect(result.findings.findings[0]!.title).toBe(
          "Unsafe archive extraction",
        );
        expect(commands).toContain("prepare-scan-completion");
        expect(commands).toContain("complete-scan");
        expect(commands).not.toContain("fail-scan");
      }
    } finally {
      await client.close();
    }
  });
}
