import { join } from "node:path";
import type { DeepReducerWorkerContext } from "../../src/artifact-io.ts";
import { scanId } from "../scan-draft-fixture.ts";

/** Bind reducer reads to the named workers and previous result under one scan. */
export function reducerAssignment(
  repoRoot: string,
  scanRoot = join(repoRoot, "scan"),
) {
  const deepRoot = join(scanRoot, "artifacts", "deep_discovery");
  return {
    workerOutput: (label: string) => join(deepRoot, "workers", label, "output"),
    reducerOutput: (label: string) => join(deepRoot, "dedup", label, "output"),
    context(
      root: string,
      claimedWorkers: DeepReducerWorkerContext[],
      previousReducerResultPath?: string,
    ) {
      return {
        root,
        repoRoot,
        scanId,
        layout: "reducer" as const,
        deepReducer: {
          scanRoot,
          claimedWorkers,
          ...(previousReducerResultPath === undefined
            ? {}
            : { previousReducerResultPath }),
        },
      };
    },
  };
}
