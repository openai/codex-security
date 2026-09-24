import type { ArtifactContext } from "./artifact-context.js";
import {
  deepReducerInputsInputSchema,
  getCodexSecurityDeepReducerInputs,
} from "./artifact-deep-reducer.js";
import type {
  DeepReductionInput,
  DeepReductionSources,
} from "./deep-scan/artifact-validation.js";

export interface DeepReducerPageInput {
  cursor?: string;
  maxBytes: number;
  findingRef?: string;
}

/** Concatenate every json fragment for one document before parsing it. */
export interface DeepReducerPage {
  json: string;
  nextCursor?: string;
}

type Finding = DeepReductionInput["findings"][number];

interface ReducerDocuments {
  inputs: string;
  findings: Map<string, Finding>;
  serializedFindings: Map<string, string>;
}

// Each artifact server binds one immutable reducer assignment. Cache that
// snapshot so small pages do not repeatedly read and serialize all inputs.
const documents = new WeakMap<ArtifactContext, Promise<ReducerDocuments>>();

/** The single payload representation used by both the tool and byte accounting. */
export function deepReducerPageResponse(page: DeepReducerPage): {
  content: [{ type: "text"; text: string }];
} {
  return { content: [{ type: "text", text: JSON.stringify(page) }] };
}

export async function getCodexSecurityDeepReducerInputsPage(
  context: ArtifactContext,
  value: DeepReducerPageInput,
): Promise<DeepReducerPage> {
  const input = deepReducerInputsInputSchema.parse(value);
  let pending = documents.get(context);
  if (!pending) {
    pending = getCodexSecurityDeepReducerInputs(context)
      .then(createDocuments)
      .catch((error: unknown) => {
        documents.delete(context);
        throw error;
      });
    documents.set(context, pending);
  }
  const snapshot = await pending;
  let json = snapshot.inputs;
  if (input.findingRef !== undefined) {
    const finding = snapshot.findings.get(input.findingRef);
    if (!finding)
      throw new Error(
        "The requested findingRef is not assigned to this reducer.",
      );
    const cached = snapshot.serializedFindings.get(input.findingRef);
    json = cached ?? JSON.stringify(finding);
    if (cached === undefined)
      snapshot.serializedFindings.set(input.findingRef, json);
  }
  return pageDocument(json, input);
}

function createDocuments(sources: DeepReductionSources): ReducerDocuments {
  const findings = new Map<string, Finding>();
  const discoveries = sources.discoveries.map((discovery) => ({
    workerId: discovery.workerId,
    result: {
      ...discovery.result,
      findings: discovery.result.findings.map((finding, index) => {
        findings.set(`source:${discovery.workerId}:${index}`, finding);
        return projectFinding(finding);
      }),
    },
  }));
  const previous = sources.previous
    ? {
        ...sources.previous,
        findings: sources.previous.findings.map((finding, index) => {
          findings.set(`previous:${index}`, finding);
          const originals = (finding.provenance as Record<string, unknown>)
            .sourceFindings as
            Array<{ id: string; finding: Finding }> | undefined;
          // Match retainSourceFindings: old aggregates without retained
          // originals contribute one source named previous:<index>.
          const refs = originals?.length
            ? originals.map((original) => {
                findings.set(`source:${original.id}`, original.finding);
                return original.id;
              })
            : [`previous:${index}`];
          if (!originals?.length)
            findings.set(`source:previous:${index}`, finding);
          return projectFinding(finding, refs);
        }),
      }
    : null;
  return {
    inputs: JSON.stringify({ discoveries, previous }),
    findings,
    serializedFindings: new Map(),
  };
}

function projectFinding(finding: Finding, refs?: string[]): Finding {
  const {
    sourceFindings: _sources,
    previousFindings: _previous,
    originalCandidates: _candidates,
    ...provenance
  } = finding.provenance as Record<string, unknown>;
  return {
    ...finding,
    provenance: {
      ...provenance,
      ...(refs === undefined ? {} : { sourceFindingIds: refs }),
    },
  };
}

function pageDocument(
  document: string,
  input: DeepReducerPageInput,
): DeepReducerPage {
  const start = Number(input.cursor ?? "0");
  if (!Number.isSafeInteger(start) || start > document.length)
    throw new Error(
      "The reducer input cursor is outside the selected document.",
    );
  if (unicodeBoundary(document, start) !== start)
    throw new Error("The reducer input cursor splits a Unicode character.");

  const pageAt = (end: number): DeepReducerPage => ({
    json: document.slice(start, end),
    ...(end < document.length ? { nextCursor: String(end) } : {}),
  });
  const fits = (page: DeepReducerPage): boolean =>
    Buffer.byteLength(JSON.stringify(deepReducerPageResponse(page)), "utf8") <=
    input.maxBytes;

  // A UTF-16 code unit cannot occupy less than one byte in this JSON response.
  // Bound the search by the requested budget, not the entire remaining document.
  const maximumEnd = unicodeBoundary(
    document,
    start + Math.min(document.length - start, input.maxBytes),
  );
  const complete = pageAt(maximumEnd);
  if (fits(complete)) return complete;

  let low = start;
  let high = maximumEnd;
  let acceptedEnd = start;
  while (low <= high) {
    const middle = low + Math.floor((high - low) / 2);
    const end = unicodeBoundary(document, middle);
    if (fits(pageAt(end))) {
      acceptedEnd = end;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  if (acceptedEnd === start)
    throw new Error(
      "The reducer input maxBytes budget cannot fit a response with the next character. Increase maxBytes and retry the same cursor.",
    );
  return pageAt(acceptedEnd);
}

function unicodeBoundary(value: string, offset: number): number {
  const before = value.charCodeAt(offset - 1);
  const after = value.charCodeAt(offset);
  return before >= 0xd800 &&
    before <= 0xdbff &&
    after >= 0xdc00 &&
    after <= 0xdfff
    ? offset - 1
    : offset;
}
