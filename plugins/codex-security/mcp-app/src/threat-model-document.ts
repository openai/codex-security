import { join } from "node:path";
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  readArtifactJsonObject,
  replaceArtifactText,
} from "./artifact-io.js";
import { resolvePythonCommand, runPythonWithInput } from "./python_command.js";
import { asRecord } from "./record.js";

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
    const python = context.pythonCommand ?? (await resolvePythonCommand());
    const target = asRecord(document?.target);
    const markdown = await renderThreatModel(python, context.pluginRoot!, {
      threatModel,
      provenance: {
        source: context.layout,
        scanId: context.scanId,
        target: context.repoRoot,
        revision: context.targetRevision,
        snapshotDigest:
          target?.snapshotDigest ??
          asRecord(context.targetContract?.target)?.requiredSnapshotDigest,
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

function renderThreatModel(
  python: string,
  pluginRoot: string,
  input: Record<string, unknown>,
): Promise<string> {
  return runPythonWithInput(
    python,
    [
      "-I",
      "-X",
      "utf8",
      join(pluginRoot, "scripts", "threat_model_projection.py"),
      "--input-json-stdin",
    ],
    JSON.stringify(input),
    "Threat-model renderer",
  );
}
