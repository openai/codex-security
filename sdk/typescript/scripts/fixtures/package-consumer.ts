import {
  CodexSecurity,
  DiffTarget,
  deduplicateScan,
  estimateScanCost,
  planComponents,
  publishScanToCustom,
  runComponentScans,
  type ComponentScanOptions,
  type DeduplicateScanResult,
  type CustomPublicationResult,
  type Finding,
  type PatchOptions,
  type PatchResult,
  type ScanCost,
  type ScanOptions,
  type ScanProgress,
  type ScanResult,
  type ValidationOptions,
  type ValidationResult,
} from "@openai/codex-security";
import {
  OpenAiFindingEmbedder,
  SqliteFindingsStore,
  startFindingsServer,
} from "@openai/codex-security/server";

export async function findingsServer(getApiKey: () => Promise<string>) {
  return await startFindingsServer({
    store: new SqliteFindingsStore(),
    embeddings: new OpenAiFindingEmbedder(
      getApiKey,
      fetch,
      process.env["CODEX_SECURITY_EMBEDDINGS_URL"] || undefined,
    ),
    host: "127.0.0.1",
    port: 0,
  });
}

export async function publishCustom(
  scanDir: string,
  signal: AbortSignal,
): Promise<CustomPublicationResult> {
  return await publishScanToCustom(scanDir, {
    workflowId: "example-workflow",
    findingsUrl: "http://127.0.0.1:3000",
    signal,
  });
}

export async function dedupe(
  scanId: string,
  signal: AbortSignal,
): Promise<DeduplicateScanResult> {
  return await deduplicateScan(scanId, {
    workflowId: "example-workflow",
    findingsUrl: "http://127.0.0.1:3000",
    allRepositories: true,
    signal,
  });
}

const options: ScanOptions = {
  workflowId: "example-workflow",
  target: DiffTarget.refs({ base: "HEAD~1" }),
  onProgress(progress: ScanProgress) {
    progress.filesCompleted satisfies number;
  },
};

export async function scan(repository: string): Promise<ScanResult> {
  const client = new CodexSecurity();
  try {
    return await client.run(repository, options);
  } finally {
    await client.close();
  }
}

export const cost: ScanCost | null = estimateScanCost("gpt-5.6-sol", {
  input_tokens: 10,
  output_tokens: 2,
});

interface ImportedFinding {
  id: string;
  title: string;
  location: { file: string; line: number };
}

export async function validate(
  repositoryPath: string,
  finding: Finding | ImportedFinding,
): Promise<ValidationResult> {
  await using client = new CodexSecurity();
  const options: ValidationOptions = {
    repositoryPath,
    finding,
  };
  return await client.validate(options);
}

export async function patch(
  repositoryPath: string,
  finding: Finding | ImportedFinding,
): Promise<PatchResult> {
  await using client = new CodexSecurity();
  const options: PatchOptions = {
    repositoryPath,
    finding,
    model: "gpt-5.6-sol",
    reasoningEffort: "high",
  };
  const result = await client.patch(options);
  result.changedFiles satisfies readonly string[];
  // @ts-expect-error Patch results expose changed files as immutable metadata.
  result.changedFiles.push("unexpected.ts");
  switch (result.status) {
    case "verified":
    case "no_change":
      result.verificationReport satisfies string;
      break;
    case "blocked":
    case "failed":
      result.reason satisfies string;
      break;
    default:
      result satisfies never;
  }
  return result;
}

const invalidPatchOptions: PatchOptions = {
  repositoryPath: "/synthetic/repository",
  finding: "Synthetic finding",
  // @ts-expect-error Patch reasoning effort is restricted to Codex SDK values.
  reasoningEffort: "extreme",
};
void invalidPatchOptions;

// @ts-expect-error The dependency-injection constructor is internal.
new CodexSecurity({}, undefined as never, undefined as never);

export async function scanComponents(repository: string, outputDir: string) {
  const plan = await planComponents(repository);
  const options: ComponentScanOptions = {
    repository,
    outputDir,
    components: plan.components,
  };
  return await runComponentScans(options);
}

// @ts-expect-error The model client is an internal test dependency.
planComponents("synthetic-repository", { codex: {} });
