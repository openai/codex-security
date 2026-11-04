import { fileURLToPath } from "node:url";
import { importSource } from "./import-module.ts";
import { scanId as fixtureScanId } from "./scan-draft-fixture.ts";

const load = (file: string) =>
  importSource(
    fileURLToPath(new URL(`../src/deep-scan/${file}.ts`, import.meta.url)),
  );

const { createDeepScanArtifacts } = await load("artifacts");
const validation = await load("artifact-validation");
const { mergeBatch } = await load("iteration");
export const { scanUnionToDraft, persistedScanUnion, parseScanUnion } =
  validation;

// Admit worker output and merge it through the coordinator's normal entry points.
export async function mergeWorkerFiles(
  scanDir: string,
  workers: { id: string; resultPath: string }[],
  previous: Record<string, unknown> = { scanId: fixtureScanId, findings: [] },
) {
  const aggregate = parseScanUnion(previous);
  const accepted = await Promise.all(
    workers.map(async (worker) => ({
      ...worker,
      result: await validation.validateDiscoveryArtifacts(
        createDeepScanArtifacts(scanDir),
        worker.resultPath,
        aggregate.scanId,
        { workerId: worker.id },
      ),
    })),
  );
  await mergeBatch(
    aggregate,
    accepted,
    scanDir,
    async (prompt: string) => {
      const reports = JSON.parse(prompt.split("\n").at(-1)!);
      return JSON.stringify({
        defects: [],
        uncertain: reports.map(({ id }: { id: number }) => id),
      });
    },
    (error: unknown) => {
      throw error;
    },
  );
  return aggregate;
}
