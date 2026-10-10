import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import type { ArtifactContext } from "./artifact-context.js";
import { isTerminalCandidateDecision } from "./artifact-candidates.js";
import {
  artifactDestination,
  readArtifactBytes,
  replaceArtifactBytes,
} from "./artifact-io.js";
import type { JsonObject } from "./types.js";

/** Keep receipts and candidate evidence bound to the worker attempt that saved them. */
export async function recoverWorkerCandidateReceipts(
  coverage: JsonObject,
  source: ArtifactContext,
  retainIn?: ArtifactContext,
): Promise<Set<string>> {
  const reopened = new Set<string>();
  const deferred = coverage.deferred as JsonObject[];
  for (const surface of coverage.surfaces as JsonObject[]) {
    if (
      !isTerminalCandidateDecision(surface) &&
      !(
        retainIn !== undefined &&
        surface.disposition === "needs_follow_up" &&
        typeof surface.candidateId === "string"
      )
    )
      continue;
    const candidateId =
      typeof surface.candidateId === "string" && surface.candidateId.trim()
        ? surface.candidateId
        : undefined;
    const retainedRefs: string[] = [];
    for (const ref of (surface.receiptRefs as string[] | undefined) ?? []) {
      let contents: Buffer;
      try {
        if (!ref.startsWith("artifacts/"))
          throw new Error("Worker candidate receipt must be under artifacts/.");
        contents = await readArtifactBytes(
          source,
          ref.split("/").filter((part) => part !== "" && part !== "."),
          "Worker candidate receipt",
        );
      } catch (error) {
        if (candidateId !== undefined) reopened.add(candidateId);
        surface.disposition = "needs_follow_up";
        coverage.completeness = "partial";
        let pending =
          candidateId === undefined
            ? undefined
            : deferred.find((item) => item.candidateId === candidateId);
        if (pending === undefined) {
          pending = {
            ...(candidateId === undefined ? {} : { candidateId }),
            reason: error instanceof Error ? error.message : String(error),
            ...(typeof surface.id === "string"
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
      if (retainIn === undefined) {
        retainedRefs.push(ref);
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
