import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  readArtifactJsonObject,
  replaceArtifactText,
} from "./artifact-io.js";
import { asRecord } from "./record.js";
import { renderThreatModel } from "./threat-model-render.js";

const pendingDocuments = new Map<string, Promise<void>>();

/** Materialize a saved model without making its convenience file a checkpoint gate. */
export async function saveThreatModelDocument(
  context: ArtifactContext,
  threatModel: Record<string, unknown> | undefined,
): Promise<string | undefined> {
  if (threatModel === undefined || context.pluginRoot === undefined) return;
  const previous = pendingDocuments.get(context.root) ?? Promise.resolve();
  const operation = previous.then(() =>
    writeCurrentThreatModelDocument(context),
  );
  const pending = operation.then(() => undefined);
  pendingDocuments.set(context.root, pending);
  try {
    return await operation;
  } finally {
    if (pendingDocuments.get(context.root) === pending) {
      pendingDocuments.delete(context.root);
    }
  }
}

async function writeCurrentThreatModelDocument(
  context: ArtifactContext,
): Promise<string | undefined> {
  try {
    const source = await readArtifactJsonObject(
      context,
      [context.layout === "scan" ? "scan-manifest.json" : "result.json"],
      "saved threat model",
    );
    const document = asRecord(context.layout === "scan" ? source.scan : source);
    const threatModel = document?.threatModel;
    if (threatModel === undefined) return;
    const destination = await artifactDestination(
      context,
      ["threatmodel.md"],
      "threat model document",
    );
    const target = asRecord(document?.target);
    const snapshotDigest =
      target?.snapshotDigest ??
      asRecord(context.targetContract?.target)?.requiredSnapshotDigest;
    const markdown = renderThreatModel({
      threatModel,
      provenance: {
        source: context.layout,
        scanId: context.scanId,
        target: context.repoRoot,
        revision: context.targetRevision,
        snapshotDigest:
          typeof snapshotDigest === "string" ? snapshotDigest : undefined,
        status: context.status ?? "running",
        provisional: context.status !== "complete",
        ...(context.scope === undefined
          ? {}
          : { scanScope: { includePaths: [context.scope] } }),
      },
    });
    await replaceArtifactText(destination, markdown);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return `The threat model was saved, but threatmodel.md could not be written: ${reason}`;
  }
}
