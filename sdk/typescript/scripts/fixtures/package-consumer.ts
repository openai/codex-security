import {
  CodexSecurity,
  DiffTarget,
  estimateScanCost,
  publishScan,
  type PublishScanOptions,
  type PublishScanResult,
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

const publicationOptions: PublishScanOptions = {
  destination: "linear",
  teamId: "team-example",
  findingIds: ["finding-example"],
  expectedDigest: "0".repeat(64),
  dryRun: true,
};

export async function previewPublication(
  scanDirectory: string,
): Promise<PublishScanResult> {
  const result = await publishScan(scanDirectory, publicationOptions);
  result.payloadDigest satisfies string;
  return result;
}

// @ts-expect-error The dependency-injection constructor is internal.
new CodexSecurity({}, undefined as never, undefined as never);
