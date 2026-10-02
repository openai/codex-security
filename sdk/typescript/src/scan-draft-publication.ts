import { randomUUID } from "node:crypto";
import { join } from "node:path";
import {
  prepareSemanticScanDraft,
  type SemanticScan,
  type PreparedScanDraft,
} from "./scan-semantics.js";

export interface ScanDraftPublicationOptions {
  scanDir: string;
  writer: {
    restore(path: string, contents: Uint8Array): Promise<void>;
  };
  workbench: (args: readonly string[]) => Promise<unknown>;
  expectedDigest?: string;
  reconciledCheckpointIds?: readonly string[];
  claimToken?: string;
}

/** Prepare and publish semantic input through the workbench's locked writer. */
export async function writeSemanticScanDraft(
  options: ScanDraftPublicationOptions & {
    contract: Parameters<typeof prepareSemanticScanDraft>[0];
  },
  draft: SemanticScan,
): Promise<void> {
  await writePreparedScanDraft(
    options,
    draft,
    prepareSemanticScanDraft(options.contract, draft),
  );
}

/** Stage the semantic checkpoint and already-reconciled canonical documents once. */
export async function writePreparedScanDraft(
  options: ScanDraftPublicationOptions,
  draft: SemanticScan,
  documents: PreparedScanDraft,
): Promise<unknown> {
  const draftPath = `drafts/${randomUUID()}.json`;
  const checkpointPath = `drafts/${randomUUID()}.checkpoint.json`;
  // The locked workbench writer owns acknowledgement and successful-stage cleanup.
  await options.writer.restore(
    draftPath,
    Buffer.from(
      JSON.stringify({
        ...documents,
        reconciledCheckpointIds: options.reconciledCheckpointIds ?? [],
      }),
    ),
  );
  const { handoffClaimToken: _claim, ...checkpoint } = draft;
  await options.writer.restore(
    checkpointPath,
    Buffer.from(JSON.stringify(checkpoint)),
  );
  return options.workbench([
    "write-scan-draft",
    "--scan-id",
    draft.scanId,
    "--draft-path",
    join(options.scanDir, draftPath),
    "--checkpoint-path",
    join(options.scanDir, checkpointPath),
    ...(options.expectedDigest === undefined
      ? []
      : ["--expected-draft-digest", options.expectedDigest]),
    ...(options.claimToken === undefined
      ? []
      : ["--claim-token", options.claimToken]),
  ]);
}
