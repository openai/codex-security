import { randomUUID } from "node:crypto";
import { join } from "node:path";
import {
  prepareSemanticScanDraft,
  type SemanticScan,
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
    draft.scanId,
    prepareSemanticScanDraft(options.contract, draft),
    draft,
  );
}

/** Stage the semantic checkpoint and already-reconciled canonical documents once. */
export async function writePreparedScanDraft(
  options: ScanDraftPublicationOptions,
  scanId: string,
  documents: { manifest: unknown; findings: unknown; coverage: unknown },
  draft?: SemanticScan,
): Promise<unknown> {
  const draftPath = `drafts/${randomUUID()}.json`;
  const checkpointPath =
    draft === undefined ? undefined : `drafts/${randomUUID()}.checkpoint.json`;
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
  if (draft !== undefined && checkpointPath !== undefined) {
    const { handoffClaimToken: _claim, ...checkpoint } = draft;
    await options.writer.restore(
      checkpointPath,
      Buffer.from(JSON.stringify(checkpoint)),
    );
  }
  return options.workbench([
    "write-scan-draft",
    "--scan-id",
    scanId,
    "--draft-path",
    join(options.scanDir, draftPath),
    ...(checkpointPath === undefined
      ? []
      : ["--checkpoint-path", join(options.scanDir, checkpointPath)]),
    ...(options.expectedDigest === undefined
      ? []
      : ["--expected-draft-digest", options.expectedDigest]),
    ...(options.claimToken === undefined
      ? []
      : ["--claim-token", options.claimToken]),
  ]);
}
