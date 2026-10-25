import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { basename, dirname, join, relative, sep } from "node:path";
import { coverageReceiptComponents } from "./coverage-publication.js";
import { isRecord as isObject } from "./record.js";
import { isDeepStrictEqual } from "node:util";
import type { ArtifactContext } from "./artifact-context.js";
import { isTerminalCandidateDecision } from "./artifact-candidates.js";
import {
  artifactDestination,
  readArtifactBytes,
  replaceArtifactBytes,
} from "./artifact-io.js";
import type { JsonObject } from "./types.js";

export function workerCoverageReceiptLocation(
  context: ArtifactContext,
  surface: JsonObject,
  ref: string,
): { context: ArtifactContext; components: string[]; shared?: boolean } {
  const components = coverageReceiptComponents(ref);
  if (context.layout !== "worker") return { context, components };
  const parent = dirname(context.root);
  const archived = basename(parent) === "attempts";
  const worker = archived ? dirname(parent) : parent;
  const workerPrefix = `artifacts/deep_discovery/workers/${basename(worker)}/`;
  const outputPrefix = `${workerPrefix}output/`;
  const shared =
    isObject(surface.provenance) &&
    (surface.provenance.scanReceiptRefs as string[] | undefined)?.includes(ref);
  if (archived && !shared && ref.startsWith(outputPrefix)) {
    return {
      context,
      components: coverageReceiptComponents(ref.slice(outputPrefix.length)),
    };
  }
  if (
    shared ||
    ref.startsWith(outputPrefix) ||
    ref.startsWith(`${workerPrefix}attempts/`)
  ) {
    return {
      context: {
        ...context,
        root: dirname(dirname(dirname(dirname(worker)))),
      },
      components,
      shared,
    };
  }
  return { context, components };
}

function isRetainedWorkerReceipt(
  location: ReturnType<typeof workerCoverageReceiptLocation>,
  workerOutput: string,
): boolean {
  if (location.shared) return false;
  const file = join(location.context.root, ...location.components);
  const ref = relative(dirname(workerOutput), file).split(sep).join("/");
  return /^(?:output|attempts\/[^/]+)\/artifacts\/retained-receipts\/[0-9a-f]{64}$/.test(
    ref,
  );
}

/** Keep receipts and candidate evidence bound to the worker attempt that saved them. */
export async function recoverWorkerCandidateReceipts(
  coverage: JsonObject,
  source: ArtifactContext,
  retainIn?: ArtifactContext,
): Promise<Set<string>> {
  const reopened = new Set<string>();
  const deferred = coverage.deferred as JsonObject[];
  const surfaces = coverage.surfaces as JsonObject[];
  const rows = [...surfaces, ...(coverage.explicitExclusions as JsonObject[])];
  for (const [index, surface] of rows.entries()) {
    const isSurface = index < surfaces.length;
    const candidateId =
      typeof surface.candidateId === "string" && surface.candidateId.trim()
        ? surface.candidateId
        : undefined;
    if (!isSurface && candidateId === undefined) continue;
    if (
      !isTerminalCandidateDecision(surface) &&
      !(
        !isSurface &&
        typeof surface.candidateId === "string" &&
        surface.receiptRefs !== undefined
      ) &&
      !(
        retainIn !== undefined &&
        surface.disposition === "needs_follow_up" &&
        typeof surface.candidateId === "string"
      )
    )
      continue;
    const pendingSurface =
      isSurface && surface.disposition === "needs_follow_up";
    const retainedRefs: string[] = [];
    const refs = surface.receiptRefs === undefined ? [] : surface.receiptRefs;
    for (const ref of Array.isArray(refs) ? refs : [refs]) {
      let contents: Buffer;
      try {
        if (!Array.isArray(refs))
          throw new Error(
            "Worker candidate receipt references must be an array.",
          );
        if (typeof ref !== "string")
          throw new Error("Worker candidate receipt must be a string.");
        if (!ref.startsWith("artifacts/"))
          throw new Error("Worker candidate receipt must be under artifacts/.");
        const location = workerCoverageReceiptLocation(
          source,
          isSurface ? surface : {},
          ref,
        );
        contents = await readArtifactBytes(
          location.context,
          location.components,
          "Worker candidate receipt",
        );
        // Open observations keep their owner; only this worker's existing
        // sealed copy needs a new digest when recovered bytes have changed.
        if (
          !retainIn ||
          (pendingSurface && !isRetainedWorkerReceipt(location, retainIn.root))
        ) {
          retainedRefs.push(ref);
          continue;
        }
      } catch (error) {
        if (candidateId !== undefined) reopened.add(candidateId);
        surface.disposition = "needs_follow_up";
        let pending =
          candidateId === undefined
            ? undefined
            : deferred.find((item) => item.candidateId === candidateId);
        if (pending === undefined) {
          pending = {
            ...(candidateId === undefined ? {} : { candidateId }),
            reason: error instanceof Error ? error.message : String(error),
            ...(typeof surface.id === "string" && surface.id.trim() && isSurface
              ? { surfaceIds: [surface.id] }
              : {}),
          };
          deferred.push(pending);
        }
        // Generic surface metadata does not introduce a candidate identity.
        if (candidateId === undefined) continue;
        for (const [field, archive] of [
          ["candidate", "originalCandidates"],
          ["finding", "previousFindings"],
        ] as const) {
          const values = Array.isArray(surface[archive])
            ? [...surface[archive]]
            : [];
          if (field in surface) {
            if (!(field in pending))
              pending[field] = structuredClone(surface[field]);
            else if (!isDeepStrictEqual(pending[field], surface[field]))
              values.push(surface[field]);
          }
          if (values.length > 0) {
            const saved = Array.isArray(pending[archive])
              ? pending[archive]
              : [];
            for (const value of values) {
              if (!saved.some((previous) => isDeepStrictEqual(previous, value)))
                saved.push(structuredClone(value));
            }
            pending[archive] = saved;
          }
        }
        continue;
      }
      const digest = createHash("sha256").update(contents).digest("hex");
      const components = ["artifacts", "retained-receipts", digest];
      const destination = await artifactDestination(
        retainIn,
        components,
        "Retained worker candidate receipt",
      );
      const exists = await fs.lstat(destination).then(
        () => true,
        (error: NodeJS.ErrnoException) => {
          if (error.code !== "ENOENT") throw error;
          return false;
        },
      );
      if (exists) {
        const previous = await readArtifactBytes(
          retainIn,
          components,
          "Retained worker candidate receipt",
        );
        if (!previous.equals(contents))
          throw new Error(
            "Retained worker candidate receipt does not match its digest.",
          );
      } else {
        await replaceArtifactBytes(destination, contents);
      }
      retainedRefs.push(components.join("/"));
    }
    surface.receiptRefs = retainedRefs;
  }
  return reopened;
}
