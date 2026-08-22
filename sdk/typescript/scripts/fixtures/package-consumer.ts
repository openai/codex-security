import {
  CodexSecurity,
  DiffTarget,
  estimateScanCost,
  matchScanFindings,
  type Finding,
  type ScanCost,
  type ScanComparisonInput,
  type ScanComparisonOptions,
  type ScanComparisonResult,
  type ScanOptions,
  type ScanProgress,
  type ScanResult,
  type ValidationOptions,
  type ValidationResult,
} from "@openai/codex-security";

const options: ScanOptions = {
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

// @ts-expect-error The dependency-injection constructor is internal.
new CodexSecurity({}, undefined as never, undefined as never);

const comparisonInput: ScanComparisonInput = {
  before: [],
  after: [],
  knownFindingGroups: [["finding-a", "finding-b"]],
};
const comparisonOptions: ScanComparisonOptions = {
  environment: { CODEX_SECURITY_STATE_DIR: "." },
  model: "synthetic-model",
  reasoningEffort: "medium",
  signal: new AbortController().signal,
  workingDirectory: ".",
  onProgress: ({ phase }) => {
    void phase;
  },
};
const comparisonResult: Promise<ScanComparisonResult> = matchScanFindings(
  comparisonInput,
  comparisonOptions,
);
void comparisonResult;

// @ts-expect-error Historical matching policy is internal.
matchScanFindings(comparisonInput, { allowHistoricalUncertainty: true });
const codex = {
  startThread: () => ({ run: async () => ({ finalResponse: "{}" }) }),
};
// @ts-expect-error Codex injection is internal.
matchScanFindings(comparisonInput, { codex });
