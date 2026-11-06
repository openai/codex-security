import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { readRegularInputFile } from "./prompt-files.js";
import { isRecord } from "./record.js";
import { relativePathIsOutside } from "./targets.js";

export interface DependencyCandidateObservation {
  kind: "graph";
  tool: string;
}

/** A discovered source location, not a finding or an applicability decision. */
export interface DependencyCandidate {
  id: string;
  path: string;
  line?: number;
  /** The target of a structural package dependency at this location. */
  package?: { name: string; scope?: string };
  /** Fingerprint of the verified source line; semantic proof uses cited excerpts. */
  sourceSha256?: string;
  /** UTF-8 byte length of that source line, excluding its newline terminator. */
  sourceBytes?: number;
  observations: DependencyCandidateObservation[];
}

export interface DependencyCandidateSnapshot {
  generation: number;
  candidates: DependencyCandidate[];
  /** Accounting boundaries, not a report limitation or verdict. */
  scope: string;
  limitations: string[];
}

export interface DependencyCandidates {
  /** Return the candidates observed in this result, including rediscoveries. */
  observeGraph(tool: string, result: unknown): Promise<DependencyCandidate[]>;
  snapshot(): DependencyCandidateSnapshot;
}

type Location = Pick<DependencyCandidate, "path" | "line" | "package">;

const discoveryScope =
  "Candidates are verified repository locations for graph relations candidate_call, candidate_flow, and depends_on. Search matches are leads for investigation and may be cited in assessments. Candidate accounting covers the observed structural evidence. Discovery completeness and applicability require separate assessment.";

function sourceLines(source: string): string[] {
  // A trailing newline terminates the last line; it does not add a line.
  return source ? source.replace(/\n$/u, "").split("\n") : [];
}

function positiveLine(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isCandidateRelation(relation: unknown): boolean {
  return (
    relation === "candidate_call" ||
    relation === "candidate_flow" ||
    relation === "depends_on"
  );
}

function dependencyPackage(
  fact: Record<string, unknown>,
): DependencyCandidate["package"] {
  const target = fact["to"];
  if (
    fact["relation"] === "depends_on" &&
    isRecord(target) &&
    target["kind"] === "package" &&
    typeof target["name"] === "string"
  )
    return {
      name: target["name"],
      ...(typeof target["scope"] === "string" && { scope: target["scope"] }),
    };
}

function graphLocations(result: Record<string, unknown>): Location[] {
  const locations: Location[] = [];
  if (Array.isArray(result["trace"])) {
    for (const step of result["trace"]) {
      if (
        !isRecord(step) ||
        !isCandidateRelation(step["relation"]) ||
        !Array.isArray(step["evidence"])
      )
        continue;
      const target = dependencyPackage(step);
      for (const evidence of step["evidence"]) {
        if (!isRecord(evidence) || typeof evidence["source"] !== "string")
          continue;
        const lines = evidence["lines"];
        if (lines === undefined || (Array.isArray(lines) && !lines.length)) {
          locations.push({ path: evidence["source"], package: target });
        } else if (Array.isArray(lines)) {
          for (const line of lines)
            if (positiveLine(line))
              locations.push({
                path: evidence["source"],
                line,
                package: target,
              });
        }
      }
    }
  }
  for (const key of ["paths", "evidence"]) {
    const entries = result[key];
    if (!Array.isArray(entries)) continue;
    for (const fact of entries) {
      if (!isRecord(fact) || !isCandidateRelation(fact["relation"])) continue;
      const path = fact["source"];
      const line = fact["line"];
      if (
        typeof path === "string" &&
        (line === undefined || positiveLine(line))
      )
        locations.push({ path, line, package: dependencyPackage(fact) });
    }
  }
  return locations;
}

function copyCandidate(candidate: DependencyCandidate): DependencyCandidate {
  return {
    ...candidate,
    ...(candidate.package && { package: { ...candidate.package } }),
    observations: candidate.observations.map((observation) => ({
      ...observation,
    })),
  };
}

/** One registry per read-only scan; report dispositions are owned by its queue. */
export async function createDependencyCandidates(
  repository: string,
): Promise<DependencyCandidates> {
  const root = await realpath(repository);
  const candidates = new Map<string, DependencyCandidate>();
  let generation = 0;

  async function source(path: string) {
    try {
      const file = await realpath(path);
      const local = relative(root, file);
      if (relativePathIsOutside(local)) return;
      return {
        path: local.split(sep).join("/"),
        lines: sourceLines(await readRegularInputFile(file, root)),
      };
    } catch {
      // Only verified repository files become candidates. Discovery coverage
      // is established separately from this registry's observed locations.
      return;
    }
  }

  async function observeGraph(
    tool: string,
    result: unknown,
  ): Promise<DependencyCandidate[]> {
    if (!isRecord(result)) return [];
    const observed = new Map<string, DependencyCandidate>();
    const byPath = Map.groupBy(graphLocations(result), ({ path }) =>
      resolve(root, path),
    );
    // Group reads within this observation. Only source fingerprints and receipt
    // metadata survive; full file contents are not cached across the scan.
    for (const [path, matches] of byPath) {
      const file = await source(path);
      if (!file) continue;
      for (const location of matches) {
        if (location.line !== undefined && location.line > file.lines.length)
          continue;
        const key = JSON.stringify([
          file.path,
          location.line,
          location.package?.name,
          location.package?.scope,
        ]);
        const text =
          location.line === undefined
            ? undefined
            : file.lines[location.line - 1];
        const sourceSha256 =
          text === undefined
            ? undefined
            : createHash("sha256").update(text, "utf8").digest("hex");
        const sourceBytes =
          text === undefined ? undefined : Buffer.byteLength(text, "utf8");
        let candidate = candidates.get(key);
        if (!candidate) {
          candidate = {
            id: `candidate-${candidates.size + 1}`,
            path: file.path,
            ...(location.package && { package: location.package }),
            ...(location.line === undefined ? {} : { line: location.line }),
            ...(sourceSha256 === undefined
              ? {}
              : { sourceSha256, sourceBytes }),
            observations: [],
          };
          candidates.set(key, candidate);
          generation++;
        } else if (candidate.sourceSha256 !== sourceSha256) {
          candidate.sourceSha256 = sourceSha256;
          candidate.sourceBytes = sourceBytes;
          generation++;
        }
        if (!candidate.observations.some((previous) => previous.tool === tool))
          candidate.observations.push({ kind: "graph", tool });
        observed.set(candidate.id, candidate);
      }
    }
    return [...observed.values()].map(copyCandidate);
  }

  return {
    observeGraph,
    snapshot() {
      return {
        generation,
        candidates: [...candidates.values()]
          .sort(
            (left, right) =>
              left.path.localeCompare(right.path) ||
              (left.line ?? 0) - (right.line ?? 0),
          )
          .map(copyCandidate),
        scope: discoveryScope,
        limitations: [],
      };
    },
  };
}
