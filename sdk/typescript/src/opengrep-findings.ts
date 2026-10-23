import { posix } from "node:path";
import { errorMessage } from "./errors.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  parseNativeJsonResult,
  projectNativeJsonResult,
  sourceRepositoryUrl,
} from "./native-json-findings.js";
import {
  array,
  readScannerJson,
  record,
  requiredText,
  stableId,
} from "./scanner-import.js";

export interface OpenGrepImportOptions {
  /** Source repository declared by the caller, independent of the destination. */
  sourceRepositoryUrl: string;
}

// Sort observations independently of report order and object-key insertion order.
function observationKey(value: unknown): string {
  return JSON.stringify(value, (_key, child: unknown) =>
    child !== null && typeof child === "object" && !Array.isArray(child)
      ? Object.fromEntries(
          Object.entries(child).sort(([left], [right]) =>
            left < right ? -1 : left > right ? 1 : 0,
          ),
        )
      : child,
  );
}

/** Import native scanner evidence without assigning a Codex assessment. */
export function normalizeOpenGrepFindings(
  input: unknown,
  options: OpenGrepImportOptions,
): ExternalFindings {
  const document = record(input, "OpenGrep report");
  const repositoryUrl = sourceRepositoryUrl(
    options?.sourceRepositoryUrl,
    "OpenGrep",
  );
  const version = requiredText(document["version"], "OpenGrep version");
  const errors = array(document["errors"] ?? [], "OpenGrep errors");
  const { results, ...report } = document;
  const values = array(results, "OpenGrep results");
  const projection = {
    origin: "OpenGrep",
    repositoryUrl,
    severity: () => "unknown",
    reportContext: { version },
    scanErrorCount: errors.length,
  };
  const output: ExternalFindings = {
    read: values.length,
    findings: [],
    excluded: [],
    report: structuredClone(report),
  };
  type Observation = {
    position: number;
    parsed: ReturnType<typeof parseNativeJsonResult>;
    key: string;
  };
  const groups = new Map<string, Observation[]>();
  for (const [index, value] of values.entries()) {
    let id: string | null = null;
    try {
      const parsed = parseNativeJsonResult(value, "OpenGrep");
      if (parsed.path !== null) parsed.path = posix.normalize(parsed.path);
      // Native fingerprint counters change when another analysis pass adds matches.
      // A source move creates a new occurrence; this is not cross-revision matching.
      id = stableId("opengrep-location", [
        parsed.rule,
        parsed.path ?? parsed.rawPath,
        parsed.line,
        parsed.column,
        parsed.endLine,
        parsed.endColumn,
      ]);
      projectNativeJsonResult(parsed, {
        ...projection,
        observations: [parsed.result],
      });
      const group = groups.get(id) ?? [];
      group.push({
        position: index + 1,
        parsed,
        key: observationKey(parsed.result),
      });
      groups.set(id, group);
    } catch (error) {
      output.excluded.push({
        position: index + 1,
        source_finding_id: id,
        reason: errorMessage(error),
      });
    }
  }
  for (const [id, observations] of [...groups].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  )) {
    observations.sort((left, right) =>
      left.key < right.key ? -1 : left.key > right.key ? 1 : 0,
    );
    try {
      output.findings.push({
        source_finding_id: id,
        evidence: projectNativeJsonResult(observations[0]!.parsed, {
          ...projection,
          observations: observations.map(({ parsed }) => parsed.result),
        }),
      });
    } catch (error) {
      for (const observation of observations)
        output.excluded.push({
          position: observation.position,
          source_finding_id: id,
          reason: errorMessage(error),
        });
    }
  }
  output.excluded.sort((left, right) => left.position - right.position);
  return output;
}

export async function readOpenGrepFindings(
  path: string,
  options: OpenGrepImportOptions,
): Promise<ExternalFindings> {
  return normalizeOpenGrepFindings(await readScannerJson(path), options);
}
