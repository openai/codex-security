import { realpath } from "node:fs/promises";
import { z } from "zod";
import type { JsonObject } from "./config.js";
import { effectiveStackSinks } from "./dependency-stack-advisory.js";
import { DependencyAttemptStore } from "./dependency-attempt-store.js";
import {
  createDependencyClaims,
  dependencyClaimHash,
  dependencyClaimQuerySchema,
  dependencyClaimQueueSchema,
  type PreparedDependencyClaim,
} from "./dependency-stack-claims.js";
import {
  inventoryJsonField,
  type BoundDependencyInventoryReceipt,
  type DependencyInventoryReceiptSelection,
} from "./dependency-stack-evidence.js";
import { readDependencyClaimExcerpts } from "./dependency-stack-evidence.js";
import {
  dependencySourceNoteSchema,
  prepareDependencySourceNote,
  saveDependencySourceNote,
} from "./dependency-stack-evidence.js";
import {
  assertStackAssessmentClaims,
  finalizeStackReport,
  prepareStackAssessment,
  stackAssessmentInputSchema,
  stackInvestigationReportSchema,
  summarizeStackCoverage,
  type StackAssessment,
  type StackInvestigationReport,
} from "./dependency-stack-assessment.js";
import {
  readStackPacket,
  stackFramesRootFirst,
  stackPacketWorkItems,
  type StackPacket,
} from "./dependency-stack-packet.js";
import { CodexSecurityError } from "./errors.js";
import { isRecord } from "./record.js";

const id = z.string().min(1);
const stackReadSchema = z.strictObject({ workItemId: id });
const descriptors = [
  {
    name: "init",
    description:
      "Verify the packet and target checkout, then create or reopen this attempt.",
  },
  {
    name: "next",
    description:
      "Read the next observation or coverage gap and the frozen advisory.",
  },
  {
    name: "tools",
    description: "List available commands and their JSON input schemas.",
  },
  {
    name: "read-stacks",
    description:
      "Read an item's captured frames with their original indices and its receipt ID.",
    schema: stackReadSchema,
  },
  {
    name: "record-evidence",
    description:
      "Save a source note from the pinned repository and return its reference.",
    schema: dependencySourceNoteSchema,
    mutation: true,
  },
  {
    name: "record-claims",
    description:
      "Save a batch of scoped claims with exact source ranges, receipt selections or dependencies.",
    schema: dependencyClaimQueueSchema,
    mutation: true,
  },
  {
    name: "query-claims",
    description:
      "Look up current claim revisions by ID or search their scopes and payloads.",
    schema: dependencyClaimQuerySchema,
  },
  {
    name: "record-assessments",
    description:
      "Save a disposition for the current work item and its supporting claim revisions.",
    schema: stackAssessmentInputSchema,
    mutation: true,
  },
  {
    name: "summarize-coverage",
    description: "List completed and outstanding items and coverage gaps.",
  },
  {
    name: "finalize",
    description:
      "Verify the assessments and their evidence and return the immutable report.",
  },
] satisfies {
  name: string;
  description: string;
  schema?: z.ZodType;
  mutation?: boolean;
}[];

export const stackRunTools = descriptors.map(
  ({ name, description, ...entry }) => {
    if (!("schema" in entry) || !entry.schema) return { name, description };
    const inputSchema = z.toJSONSchema(entry.schema) as JsonObject;
    if ("mutation" in entry && entry.mutation) {
      inputSchema["properties"] = {
        ...(inputSchema["properties"] as JsonObject),
        operationId: {
          type: "string",
          minLength: 1,
          description: "Optional retry key, unique within this attempt.",
        },
      };
    }
    return { name, description, inputSchema };
  },
);

interface RunLocation {
  inputs: string;
  repo: string;
  fingerprint: string;
  manifest: StackPacket["manifest"];
  hostReview?: true;
}

type WorkItem = ReturnType<typeof stackPacketWorkItems>[number];
type Ledger = ReturnType<typeof createDependencyClaims>;
type ClaimInput = z.infer<typeof dependencyClaimQueueSchema>["claims"][number];

function runLocation(store: DependencyAttemptStore): RunLocation {
  const location = store.get<RunLocation>("manifest", "active");
  if (!location)
    throw new CodexSecurityError("Initialize the investigation with run init.");
  return location;
}

async function initialize(
  state: string,
  inputs?: string,
  repo?: string,
  signal?: AbortSignal,
  hostReview?: boolean,
) {
  if (!inputs || !repo)
    throw new CodexSecurityError("run init requires --inputs and --repo.");
  const inputPath = await realpath(inputs);
  const repoPath = await realpath(repo);
  const { manifest } = await readStackPacket(inputPath, repoPath, signal);
  const fingerprint = dependencyClaimHash(manifest);
  const store = new DependencyAttemptStore(state);
  try {
    return store.transaction(() => {
      store.bindIdentity(manifest);
      const existing = store.get<RunLocation>("manifest", "active");
      store.set("manifest", "active", {
        inputs: inputPath,
        repo: repoPath,
        fingerprint,
        manifest,
        ...((hostReview || existing?.hostReview) && { hostReview: true }),
      });
      return manifest;
    });
  } finally {
    store.close();
  }
}

function mutation(store: DependencyAttemptStore, name: string, input: unknown) {
  if (!isRecord(input))
    throw new CodexSecurityError("Pass a JSON object on stdin.");
  const { operationId, ...body } = input;
  const round = store.get<number>("review", "round") ?? 0;
  const operation =
    operationId === undefined
      ? "input:" + dependencyClaimHash({ name, body })
      : "id:" + id.parse(operationId);
  const key = round ? `review:${round}:${operation}` : operation;
  return {
    body,
    receipt: () => store.operation<unknown>(key, name, body),
    commit: (write: () => unknown) =>
      store.mutate(key, name, body, () => {
        if ((store.get<number>("review", "round") ?? 0) !== round)
          throw new CodexSecurityError(
            "Independent review reopened the investigation. Run next again.",
          );
        if (store.get("report", "final"))
          throw new CodexSecurityError(
            "This investigation has been finalized.",
          );
        return write();
      }),
  };
}

/** Reopen a private draft while keeping the other assessments and the evidence ledger. */
export function reviseLocalStackReport(
  state: string,
  draft: StackInvestigationReport,
  workItemIds: readonly string[],
): void {
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    store.transaction(() => {
      const saved = store.get("report", "final");
      if (
        !runLocation(store).hostReview ||
        !saved ||
        dependencyClaimHash(saved) !== dependencyClaimHash(draft)
      )
        throw new CodexSecurityError(
          "The report is not the current local review draft.",
        );
      const round = store.get<number>("review", "round") ?? 0;
      store.set("review-draft", String(round), saved);
      for (const workItemId of workItemIds)
        store.delete("stack-assessment", workItemId);
      store.delete("report", "final");
      store.set("review", "round", round + 1);
    });
  } finally {
    store.close();
  }
}

function captureId(packet: StackPacket, item: WorkItem) {
  return (
    "capture-" + dependencyClaimHash([packet.manifest.inputDigest, item.id])
  );
}

function selectReceipt(
  packet: StackPacket,
  items: Map<string, WorkItem>,
  receiptId: string,
  selection?: DependencyInventoryReceiptSelection,
): BoundDependencyInventoryReceipt {
  const item = items.get(receiptId);
  if (!item)
    throw new CodexSecurityError("Unknown capture receipt: " + receiptId);
  if (selection && selection.textBlock !== null) {
    throw new CodexSecurityError(
      "A captured stack is structured data. Use textBlock: null.",
    );
  }
  const result = selection ? inventoryJsonField(item, selection.record) : item;
  if (result === undefined)
    throw new CodexSecurityError("The selected capture record does not exist.");
  return {
    receiptId,
    key: dependencyClaimHash([receiptId, selection?.record ?? null]),
    server: "stack-packet",
    originalPayloadSha256: packet.manifest.files.stacks.sha256,
    origin: {
      tool: "read-stacks",
      arguments: {
        inputDigest: packet.manifest.inputDigest,
        workItemId: item.id,
        queryId: item.queryId,
        groupId: item.groupId,
      },
    },
    ...(selection && {
      selection: { textBlock: null, record: selection.record },
    }),
    result,
  };
}

async function prepareClaims(
  rows: ClaimInput[],
  packet: StackPacket,
  workItems: WorkItem[],
  repository: string,
  signal?: AbortSignal,
) {
  const claims: {
    prepared: PreparedDependencyClaim;
    expectedRevision?: number;
  }[] = [];
  const seen = new Set<string>();
  const receiptsById = new Map(
    workItems.map((item) => [captureId(packet, item), item]),
  );
  for (const row of rows) {
    if (seen.has(row.id))
      throw new CodexSecurityError("Duplicate claim ID in batch: " + row.id);
    seen.add(row.id);
    const target = packet.manifest.target.sha;
    const ranges = row.evidence.map((range) => {
      if (range.commit && range.commit !== target)
        throw new CodexSecurityError(
          "A claim must cite the investigation target SHA.",
        );
      return { ...range, commit: target };
    });
    const excerpts = await readDependencyClaimExcerpts(
      ranges,
      repository,
      signal,
    );
    const receipts = [
      ...(row.receiptIds ?? []).map((ref) =>
        selectReceipt(packet, receiptsById, ref),
      ),
      ...(row.receiptSelections ?? []).map((selection) =>
        selectReceipt(packet, receiptsById, selection.receiptId, selection),
      ),
    ];
    if (!excerpts.length && !receipts.length && !row.dependencies.length) {
      throw new CodexSecurityError(
        "A claim needs a cited source range, capture receipt or exact supporting claim.",
      );
    }
    claims.push({
      prepared: {
        id: row.id,
        scope: row.scope,
        payload: row.payload,
        dependencies: row.dependencies,
        excerpts,
        receipts,
      },
      ...(row.expectedRevision !== undefined && {
        expectedRevision: row.expectedRevision,
      }),
    });
  }
  return claims;
}

function currentAssessments(store: DependencyAttemptStore, claims: Ledger) {
  return store
    .values<StackAssessment>("stack-assessment")
    .filter((assessment) =>
      assessment.supportingClaims.every((ref) => claims.isUsable(ref)),
    );
}

function nextItem(items: WorkItem[], assessments: StackAssessment[]) {
  const complete = new Set(assessments.map((item) => item.workItemId));
  return items.find((item) => !complete.has(item.id));
}

function openClaims(store: DependencyAttemptStore, { manifest }: StackPacket) {
  return createDependencyClaims(
    {
      inputDigest: manifest.inputDigest,
      cve: manifest.cve,
      target: manifest.target,
    },
    store,
  );
}

async function verifyFinal(
  store: DependencyAttemptStore,
  packet: StackPacket,
  repository: string,
  claims: Ledger,
  requireSaved: boolean,
  signal?: AbortSignal,
): Promise<StackInvestigationReport> {
  const saved = store.get("report", "final");
  if (requireSaved && !saved)
    throw new CodexSecurityError(
      "The investigator did not finalize the report.",
    );
  const decisions = store.values<StackAssessment>("stack-assessment");
  const snapshot = finalizeStackReport(packet, decisions, claims);
  const digest = dependencyClaimHash(snapshot);
  const items = stackPacketWorkItems(packet);
  const byId = new Map(items.map((item) => [item.id, item]));
  for (const assessment of decisions) {
    await prepareStackAssessment(
      assessment,
      byId.get(assessment.workItemId)!,
      packet,
      claims,
      signal,
    );
  }
  for (const ref of snapshot.claims) {
    const original = claims.get(ref);
    if (!original)
      throw new CodexSecurityError(
        "A supporting claim changed during finalization.",
      );
    const [current] = await prepareClaims(
      [
        {
          id: original.id,
          scope: original.scope,
          payload: original.payload,
          dependencies: original.dependencies,
          evidence: original.excerpts.map(
            ({ path, commit, startLine, endLine }) => ({
              path,
              startLine,
              endLine,
              ...(commit && { commit }),
            }),
          ),
          receiptIds: original.receipts
            .filter((r) => !r.selection)
            .map((r) => r.receiptId),
          receiptSelections: original.receipts.flatMap((r) =>
            r.selection ? [{ ...r.selection, receiptId: r.receiptId }] : [],
          ),
        },
      ],
      packet,
      items,
      repository,
      signal,
    );
    const verified = current!.prepared;
    if (
      claims.preview(verified, original.revision).hash !== ref.hash ||
      dependencyClaimHash(verified.excerpts) !==
        dependencyClaimHash(original.excerpts) ||
      dependencyClaimHash(verified.receipts) !==
        dependencyClaimHash(original.receipts)
    ) {
      throw new CodexSecurityError(
        "Supporting evidence changed for claim " + ref.id + ".",
      );
    }
  }
  return store.transaction(() => {
    const report = finalizeStackReport(
      packet,
      store.values<StackAssessment>("stack-assessment"),
      claims,
    );
    if (dependencyClaimHash(report) !== digest)
      throw new CodexSecurityError(
        "The investigation changed during finalization. Retry finalize.",
      );
    const existing = store.get("report", "final");
    if (existing !== undefined) {
      if (
        dependencyClaimHash(stackInvestigationReportSchema.parse(existing)) !==
        digest
      )
        throw new CodexSecurityError(
          "The saved report differs from the verified assessments and evidence.",
        );
    } else {
      if (requireSaved)
        throw new CodexSecurityError("The finalized report was removed.");
      store.set("report", "final", report);
    }
    return report;
  });
}

export async function readFinalStackReport(
  state: string,
  expected?: {
    packet: StackPacket;
    repository: string;
    signal?: AbortSignal;
  },
): Promise<StackInvestigationReport> {
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    const location = runLocation(store);
    const packet =
      expected?.packet ??
      (await readStackPacket(location.inputs, location.repo));
    if (dependencyClaimHash(packet.manifest) !== location.fingerprint)
      throw new CodexSecurityError(
        "Finalized state does not belong to this input packet.",
      );
    return await verifyFinal(
      store,
      packet,
      expected?.repository ?? location.repo,
      openClaims(store, packet),
      true,
      expected?.signal,
    );
  } finally {
    store.close();
  }
}

export async function executeStackRun(
  command: string,
  options: {
    state: string;
    inputs?: string;
    repo?: string;
    input?: unknown;
    signal?: AbortSignal;
    hostReview?: boolean;
  },
): Promise<unknown> {
  const { state, signal } = options;
  if (command === "init")
    return initialize(
      state,
      options.inputs,
      options.repo,
      signal,
      options.hostReview,
    );
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    const location = runLocation(store);
    if (command === "tools") return { commands: stackRunTools };
    const packet = await readStackPacket(
      location.inputs,
      location.repo,
      signal,
    );
    if (dependencyClaimHash(packet.manifest) !== location.fingerprint) {
      throw new CodexSecurityError("The frozen investigation packet changed.");
    }
    const { manifest } = packet;
    const claims = openClaims(store, packet);
    const items = stackPacketWorkItems(packet);
    const assessments = () => currentAssessments(store, claims);
    const current = () => nextItem(items, assessments());
    switch (command) {
      case "next": {
        const item = current();
        if (!item)
          return {
            workItem: null,
            coverage: summarizeStackCoverage(packet, assessments()),
          };
        const observation = item.observation;
        const sinks = effectiveStackSinks(packet);
        return {
          workItem: {
            ...item,
            observation: observation && {
              id: observation.id,
              stackHash: observation.stackHash,
              sourceIndex: observation.sourceIndex,
              sinkIndex: observation.sinkIndex,
              frameCount: observation.frames.length,
              framesTruncated: observation.framesTruncated,
              sinkIds: observation.sinkIds,
              sinkMatches: observation.sinkMatches,
            },
          },
          receiptId: captureId(packet, item),
          target: manifest.target,
          cve: manifest.cve,
          advisory: manifest.advisory,
          ...(manifest.triggerAnalysis && {
            triggerAnalysis: manifest.triggerAnalysis,
          }),
          ...(manifest.advisoryDetails && {
            advisoryDetails: manifest.advisoryDetails,
          }),
          ...(manifest.advisoryLookupError && {
            advisoryLookupError: manifest.advisoryLookupError,
          }),
          sources: packet.sources.sources,
          sinks,
          openQuestions: sinks.flatMap((sink) => sink.preconditions),
        };
      }
      case "read-stacks": {
        const { workItemId } = stackReadSchema.parse(options.input);
        const item = items.find((entry) => entry.id === workItemId);
        if (!item)
          throw new CodexSecurityError("Unknown work item: " + workItemId);
        return {
          ...item,
          receiptId: captureId(packet, item),
          rootFirstRawIndices: item.observation
            ? stackFramesRootFirst(item.observation).map(
                ({ rawIndex }) => rawIndex,
              )
            : [],
        };
      }
      case "query-claims":
        return claims.query(options.input);
      case "summarize-coverage":
        return summarizeStackCoverage(packet, assessments());
      case "finalize":
        return await verifyFinal(
          store,
          packet,
          location.repo,
          claims,
          false,
          signal,
        );
      case "record-evidence": {
        const op = mutation(store, command, options.input);
        const previous = op.receipt();
        if (previous) return previous.result;
        const captured = await prepareDependencySourceNote(
          location.repo,
          op.body,
          {
            targetSha: manifest.target.sha,
            logicalRepository: manifest.target.repository,
            ...(signal && { signal }),
          },
        );
        return op.commit(() => saveDependencySourceNote(store, captured));
      }
      case "record-claims": {
        const op = mutation(store, command, options.input);
        const previous = op.receipt();
        if (previous) return previous.result;
        const input = dependencyClaimQueueSchema.parse(op.body);
        const rows = await prepareClaims(
          input.claims,
          packet,
          items,
          location.repo,
          signal,
        );
        return op.commit(() => {
          const refs = rows.map(({ prepared, expectedRevision }) => {
            const { record } = claims.propose(prepared, expectedRevision);
            return claims.reference(record);
          });
          if (!refs.every((ref) => claims.isUsable(ref)))
            throw new CodexSecurityError(
              "A claim in this batch invalidates a sibling's supporting revision.",
            );
          return { claims: refs };
        });
      }
      case "record-assessments": {
        const op = mutation(store, command, options.input);
        const previous = op.receipt();
        if (previous) return previous.result;
        const input = stackAssessmentInputSchema.parse(op.body);
        const item = current();
        if (
          !item ||
          input.items.length !== 1 ||
          input.items[0]!.workItemId !== item.id
        ) {
          throw new CodexSecurityError(
            "Select the single outstanding work item returned by run next.",
          );
        }
        const assessment = await prepareStackAssessment(
          input.items[0]!,
          item,
          packet,
          claims,
          signal,
        );
        return op.commit(() => {
          if (current()?.id !== item.id)
            throw new CodexSecurityError(
              "The active work item changed. Run next again.",
            );
          assertStackAssessmentClaims(assessment, claims);
          store.set("stack-assessment", item.id, assessment);
          return { workItemId: item.id, verdict: assessment.verdict };
        });
      }
      default:
        throw new CodexSecurityError(
          "Unknown investigation command: " + command,
        );
    }
  } finally {
    store.close();
  }
}
