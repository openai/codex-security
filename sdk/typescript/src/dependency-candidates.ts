import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { readRegularInputFile } from "./prompt-files.js";
import { isRecord } from "./record.js";
import { relativePathIsOutside } from "./targets.js";

export interface DependencyCandidateObservation {
  kind: "graph" | "command";
  tool?: string;
  itemId?: string;
}

/** A discovered source location, not a finding or an applicability decision. */
export interface DependencyCandidate {
  id: string;
  path: string;
  line?: number;
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
  observeCommand(item: Record<string, unknown>): Promise<DependencyCandidate[]>;
  snapshot(): DependencyCandidateSnapshot;
}

interface Location {
  path: string;
  line?: number;
}

const discoveryScope =
  "These candidates are verified repository locations observed in graph results and line-numbered discovery output; recognized file-display commands do not add candidates. Unstructured or truncated output is not guaranteed to be represented. Accounting for observed candidates does not establish exhaustive discovery or determine applicability; these boundaries alone do not invalidate a supported scoped conclusion.";

function sourceLines(source: string): string[] {
  // A trailing newline terminates the last line; it does not add a line.
  return source ? source.replace(/\n$/u, "").split("\n") : [];
}

function positiveLine(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function graphLocations(result: Record<string, unknown>): Location[] {
  const locations: Location[] = [];
  if (Array.isArray(result["trace"])) {
    for (const step of result["trace"]) {
      if (!isRecord(step) || !Array.isArray(step["evidence"])) continue;
      for (const evidence of step["evidence"]) {
        if (!isRecord(evidence) || typeof evidence["source"] !== "string")
          continue;
        const lines = evidence["lines"];
        if (Array.isArray(lines) && lines.length) {
          for (const line of lines)
            if (positiveLine(line))
              locations.push({ path: evidence["source"], line });
        } else {
          locations.push({ path: evidence["source"] });
        }
      }
    }
  }
  for (const key of ["references", "paths", "evidence"]) {
    const entries = result[key];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (!isRecord(entry)) continue;
      const path = entry[key === "references" ? "path" : "source"];
      if (typeof path !== "string") continue;
      const line = entry["line"];
      if (line === undefined || positiveLine(line))
        locations.push({ path, ...(line === undefined ? {} : { line }) });
    }
  }
  return locations;
}

// These expressions display every line (or every nonempty line), rather than
// discover a particular source use. Keep the list explicit: sampling a regex on
// a few strings cannot prove that an arbitrary expression is a whole-file read.
const lineDisplayPatterns = new Set([
  "",
  "^",
  "$",
  ".",
  ".*",
  ".+",
  "^.*",
  "^.*$",
  "^.+",
  "^.+$",
]);

function wholeFileInspection(item: Record<string, unknown>): boolean {
  const actions = item["commandActions"] ?? item["parsed_cmd"];
  if (!Array.isArray(actions) || !actions.length) return false;
  return actions.every((action) => {
    if (!isRecord(action)) return false;
    // Prefer the runtime's explicit operation classification. A displayed file
    // is evidence to inspect, not a new candidate for each displayed line.
    if (["read", "listFiles", "list_files"].includes(String(action["type"])))
      return true;
    if (action["type"] !== "search" || typeof action["query"] !== "string")
      return false;
    const command = action["command"] ?? action["cmd"];
    if (typeof command !== "string") return false;
    // Limit regex interpretation to ripgrep. Other commands and unknown/chained
    // actions retain ordinary capture, including actual FFmpeg search results.
    if (!/^(?:[^\s'"`]*\/)?rg(?:\s|$)/u.test(command.trim())) return false;
    // These modes change the meaning/output of an apparent all-lines pattern.
    // Conservative detection may retain an inspection, never discard a real hit.
    if (
      /(?:^|[\s'"])(?:--(?:word-regexp|line-regexp|only-matching|invert-match|multiline)(?:[\s'"=]|$)|-[a-zA-Z]*[wxovU][a-zA-Z]*(?=[\s'"]|$))/u.test(
        command,
      )
    )
      return false;
    const fixed =
      /(?:^|[\s'"])(?:--fixed-strings(?:[\s'"=]|$)|-[a-zA-Z]*F[a-zA-Z]*(?=[\s'"]|$))/u.test(
        command,
      );
    const query = action["query"];
    if (fixed) return query === "";
    if (lineDisplayPatterns.has(query)) return true;
    // A top-level universal branch makes the entire alternation a display.
    // With escapes, groups or classes, leave interpretation to the search tool;
    // do not guess at regex grammar or conflate a literal pipe with alternation.
    if (/[\\[\]()]/u.test(query)) return false;
    return query.split("|").some((branch) => lineDisplayPatterns.has(branch));
  });
}

function commandLocations(output: string): Location[] {
  const locations: Location[] = [];
  for (const text of output.split(/\r?\n/u)) {
    if (text.startsWith("{")) {
      try {
        const match: unknown = JSON.parse(text);
        if (isRecord(match) && match["type"] === "match") {
          const data = match["data"];
          if (isRecord(data)) {
            const path = data["path"];
            if (
              isRecord(path) &&
              typeof path["text"] === "string" &&
              positiveLine(data["line_number"])
            ) {
              locations.push({
                path: path["text"],
                line: data["line_number"],
              });
              continue;
            }
          }
        }
      } catch {
        // Ordinary source output need not be JSON.
      }
    }
    // Includes rg -n / grep -n, with an optional column from rg --column.
    // This does not attempt to interpret the shell command or its pipelines.
    const match = /^(.+?):([1-9][0-9]*):(?:[1-9][0-9]*:)?(.*)$/u.exec(text);
    if (match) {
      const line = Number(match[2]);
      if (positiveLine(line)) locations.push({ path: match[1]!, line });
    }
  }
  return locations;
}

function copyCandidate(candidate: DependencyCandidate): DependencyCandidate {
  return {
    ...candidate,
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

  async function observe(
    locations: Location[],
    cwd: string,
    origin: DependencyCandidateObservation,
  ): Promise<DependencyCandidate[]> {
    const observed = new Map<string, DependencyCandidate>();
    const byPath = Map.groupBy(locations, ({ path }) => resolve(cwd, path));
    // Group reads within this observation. Only source fingerprints and receipt
    // metadata survive; full file contents are not cached across the scan.
    for (const [path, matches] of byPath) {
      const file = await source(path);
      if (!file) continue;
      for (const location of matches) {
        if (location.line !== undefined && location.line > file.lines.length)
          continue;
        const key = JSON.stringify([file.path, location.line ?? null]);
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
        const observation: DependencyCandidateObservation = { ...origin };
        if (
          !candidate.observations.some(
            (previous) =>
              JSON.stringify(previous) === JSON.stringify(observation),
          )
        )
          candidate.observations.push(observation);
        observed.set(candidate.id, candidate);
      }
    }
    return [...observed.values()].map(copyCandidate);
  }

  return {
    async observeGraph(tool, result) {
      if (!isRecord(result)) return [];
      return observe(graphLocations(result), root, { kind: "graph", tool });
    },
    async observeCommand(item) {
      if (wholeFileInspection(item)) return [];
      const output = item["aggregatedOutput"] ?? item["aggregated_output"];
      if (typeof output !== "string") return [];
      let cwd = typeof item["cwd"] === "string" ? item["cwd"] : root;
      if (cwd.startsWith("file:")) cwd = fileURLToPath(cwd);
      return observe(commandLocations(output), cwd, {
        kind: "command",
        ...(typeof item["id"] === "string" ? { itemId: item["id"] } : {}),
      });
    },
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
