import {
  CodexSecurity,
  DiffTarget,
  estimateScanCost,
  type ScanCost,
  type ScanOptions,
  type ScanProgress,
  type ScanResult,
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

// @ts-expect-error The dependency-injection constructor is internal.
new CodexSecurity({}, undefined as never, undefined as never);
