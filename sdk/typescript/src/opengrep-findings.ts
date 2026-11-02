import { posix } from "node:path";
import {
  legacySizeOutcome,
  validateExternalEvidenceJson,
  validateExternalReport,
  type ExternalImportTarget,
} from "./external-import-contract.js";
import { canonicalJson } from "./record.js";
import { errorMessage } from "./errors.js";
import type { ExternalFindings } from "./external-findings.js";
import {
  messageText,
  parseNativeJsonResult,
  projectNativeJsonResult,
  sourceRepositoryUrl,
} from "./native-json-findings.js";
import {
  array,
  readScannerJson,
  record,
  relativePath,
  rememberReaderSizeUncertainty,
  finishReaderSizeSelection,
  requiredText,
  stableId,
} from "./scanner-import.js";

export interface OpenGrepImportOptions {
  /** Source repository declared by the caller, independent of the destination. */
  sourceRepositoryUrl: string;
}

/** Import native scanner evidence without assigning a Codex assessment. */
export function normalizeOpenGrepFindings(
  input: unknown,
  options: OpenGrepImportOptions,
  target: ExternalImportTarget = "cloud",
): ExternalFindings {
  const document = record(input, "OpenGrep report");
  const repositoryUrl = sourceRepositoryUrl(
    options?.sourceRepositoryUrl,
    "OpenGrep",
  );
  const version = requiredText(document["version"], "OpenGrep version");
  const { results, ...report } = document;
  const values = array(results, "OpenGrep results");
  const errors = array(report["errors"], "OpenGrep errors");
  validateExternalReport(report);
  const projection = {
    origin: "OpenGrep",
    repositoryUrl,
    severity: () => "unknown",
    reportContext: { version },
    target,
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
  };
  function exclude(position: number, id: string | null, error: unknown) {
    output.excluded.push({
      position,
      source_finding_id: id,
      reason: errorMessage(error),
    });
  }
  function projectGroup(observations: Observation[]) {
    const results = observations.map(({ parsed }) => parsed.result);
    if (results.length === 1)
      return projectNativeJsonResult(observations[0]!.parsed, {
        ...projection,
        observations: results,
      });
    const sourceData = {
      report: { version },
      scan_error_count: errors.length,
      results,
    };
    // Replacing [] with the same raw results adds the same wire bytes to every candidate.
    const rawBytes =
      validateExternalEvidenceJson({ source_data: sourceData }, target) -
      validateExternalEvidenceJson(
        { source_data: { ...sourceData, results: [] } },
        target,
      );
    let projectionError: unknown;
    for (const { parsed } of observations) {
      try {
        const evidence = projectNativeJsonResult(parsed, {
          ...projection,
          observations: [],
        });
        validateExternalEvidenceJson(evidence, target, rawBytes);
        evidence.source_data!["results"] = results;
        return evidence;
      } catch (error) {
        projectionError ??= error;
      }
    }
    throw projectionError;
  }
  function retainPublishableTraces(observations: Observation[], id: string) {
    const emptyWrapperBytes = validateExternalEvidenceJson(
      { source_data: { results: [] } },
      target,
    );
    function sizeWithTrace(observation: Observation, evidenceBytes: number) {
      return validateExternalEvidenceJson(
        { source_data: { results: [observation.parsed.result] } },
        target,
        evidenceBytes - emptyWrapperBytes,
      );
    }
    const singletonErrors = new Map<Observation, string>();
    let smallestProjectionBytes = Infinity;
    let coreRawBytes = 0;
    for (const observation of observations) {
      try {
        const evidence = projectNativeJsonResult(observation.parsed, {
          ...projection,
          observations: [],
        });
        const projectedBytes = validateExternalEvidenceJson(evidence, target);
        const singletonBytes = sizeWithTrace(observation, projectedBytes);
        coreRawBytes += singletonBytes - projectedBytes;
        smallestProjectionBytes = Math.min(
          smallestProjectionBytes,
          projectedBytes,
        );
      } catch (error) {
        singletonErrors.set(observation, errorMessage(error));
      }
    }
    if (!singletonErrors.size) return observations;
    // Reserve every independently publishable trace, including the commas in
    // their results array, before trying raw-only traces in canonical order.
    const coreCount = observations.length - singletonErrors.size;
    let groupBytes = smallestProjectionBytes + coreRawBytes + coreCount - 1;
    return observations.filter((observation) => {
      let reason = singletonErrors.get(observation);
      if (reason === undefined) return true;
      if (coreCount) {
        try {
          groupBytes = sizeWithTrace(observation, groupBytes + 1);
          return true;
        } catch (error) {
          const groupReason = errorMessage(error);
          if (groupReason !== reason)
            reason = `${groupReason} This trace also fails standalone validation. ${reason}`;
        }
      }
      exclude(observation.position, id, reason);
      return false;
    });
  }
  const groups = new Map<string, Observation[]>();
  for (const [index, value] of values.entries()) {
    let id: string | null = null;
    try {
      const parsed = parseNativeJsonResult(value, "OpenGrep");
      if (parsed.path !== null) {
        // Validate the emitted spelling across platforms, keeping literal POSIX backslashes.
        const path = posix.normalize(parsed.rawPath);
        parsed.path =
          relativePath(posix.normalize(path.replaceAll("\\", "/"))) === null
            ? null
            : path;
      }
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
      messageText(parsed.extra["message"], "OpenGrep");
      const group = groups.get(id) ?? [];
      group.push({ position: index + 1, parsed });
      groups.set(id, group);
    } catch (error) {
      exclude(index + 1, id, error);
    }
  }
  for (const [id, observations] of [...groups].sort(([left], [right]) =>
    left < right ? -1 : left > right ? 1 : 0,
  )) {
    const ordered =
      observations.length === 1
        ? observations
        : observations
            .flatMap((observation) => {
              try {
                const result = structuredClone(observation.parsed.result);
                // The group adds these same raw bytes when choosing a representative
                // and deciding which traces fit alongside it.
                validateExternalEvidenceJson(
                  { source_data: { results: [result] } },
                  target,
                  0,
                  (previousBytes, currentBytes) => {
                    if (previousBytes !== currentBytes)
                      rememberReaderSizeUncertainty(output, id);
                  },
                );
                observation.parsed.result = result;
                return [{ observation, key: canonicalJson(result) }];
              } catch (error) {
                exclude(observation.position, id, error);
                return [];
              }
            })
            .sort((left, right) =>
              left.key < right.key ? -1 : left.key > right.key ? 1 : 0,
            )
            .map(({ observation }) => observation);
    if (!ordered.length) continue;
    let retained = ordered;
    try {
      let evidence;
      try {
        evidence = projectGroup(retained);
      } catch (error) {
        if (retained.length === 1) throw error;
        retained = retainPublishableTraces(retained, id);
        if (!retained.length) continue;
        if (retained.length === ordered.length) throw error;
        evidence = projectGroup(retained);
      }
      if (legacySizeOutcome(evidence) === null)
        rememberReaderSizeUncertainty(output, id);
      output.findings.push({ source_finding_id: id, evidence });
    } catch (error) {
      if (error instanceof Error && legacySizeOutcome(error) !== undefined)
        rememberReaderSizeUncertainty(output, id);
      for (const observation of retained)
        exclude(observation.position, id, error);
    }
  }
  output.excluded.sort((left, right) => left.position - right.position);
  return finishReaderSizeSelection(output);
}

export async function readOpenGrepFindings(
  path: string,
  options: OpenGrepImportOptions,
  target: ExternalImportTarget = "cloud",
): Promise<ExternalFindings> {
  return normalizeOpenGrepFindings(
    await readScannerJson(path),
    options,
    target,
  );
}
