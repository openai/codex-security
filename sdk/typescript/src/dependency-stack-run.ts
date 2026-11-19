import { realpath } from "node:fs/promises";
import { z } from "zod";
import type { JsonObject } from "./config.js";
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
import {
  prepareRuntimeEvidence,
  runtimeEvidenceInputSchema,
  saveRuntimeEvidence,
  selectRuntimeReceipt,
} from "./dependency-stack-runtime-receipts.js";
import {
  getLiveRun,
  initializeLive,
  liveInitInputSchema,
  liveMetadataGaps,
  overlayPacket,
  recordObservations,
  recordObservationsInputSchema,
  supplementalReceipt,
} from "./dependency-stack-live.js";

const id = z.string().min(1);
const recordEvidenceSchema = z.union([
  dependencySourceNoteSchema,
  runtimeEvidenceInputSchema,
]);
const descriptors = [
  {
    name: "init",
    description:
      "Create or reopen an investigation from a checkout, optionally importing a prepared packet or updating interactive metadata.",
    schema: liveInitInputSchema,
  },
  {
    name: "next",
    description:
      "Read the next observation or coverage gap, its original frames and capture receipt.",
  },
  {
    name: "tools",
    description: "List available commands and their JSON input schemas.",
  },
  {
    name: "record-evidence",
    description:
      "Save pinned source evidence or import an original runtime result and return its reference.",
    schema: recordEvidenceSchema,
    mutation: true,
  },
  {
    name: "record-observations",
    description:
      "Append scoped query observations or coverage gaps to the investigation worklist.",
    schema: recordObservationsInputSchema,
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
      const addRetryKey = (schema: JsonObject) => {
        if (Array.isArray(schema["anyOf"])) {
          for (const branch of schema["anyOf"])
            if (isRecord(branch)) addRetryKey(branch as JsonObject);
        } else {
          schema["properties"] = {
            ...(schema["properties"] as JsonObject),
            operationId: {
              type: "string",
              minLength: 1,
              description: "Optional retry key, unique within this attempt.",
            },
          };
        }
      };
      addRetryKey(inputSchema);
    }
    return { name, description, inputSchema };
  },
);

interface RunLocation {
  inputs: string;
  repo: string;
  fingerprint: string;
  manifest: StackPacket["manifest"];
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
  input?: unknown,
  signal?: AbortSignal,
) {
  if (!repo) throw new CodexSecurityError("run init requires --repo.");
  if (!inputs) {
    const store = new DependencyAttemptStore(state);
    try {
      return await initializeLive(store, repo, input, signal);
    } finally {
      store.close();
    }
  }
  if (input !== undefined)
    throw new CodexSecurityError(
      "Packet initialization cannot also supply interactive metadata.",
    );
  const inputPath = await realpath(inputs);
  const repoPath = await realpath(repo);
  const { manifest } = await readStackPacket(inputPath, repoPath, signal);
  const fingerprint = dependencyClaimHash(manifest);
  const store = new DependencyAttemptStore(state);
  try {
    return store.transaction(() => {
      if (!store.get("manifest", "active"))
        store.set("stack-protocol", "capture-origin", "next");
      store.bindIdentity(manifest);
      store.set("manifest", "active", {
        inputs: inputPath,
        repo: repoPath,
        fingerprint,
        manifest,
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
  const key =
    operationId === undefined
      ? "input:" + dependencyClaimHash({ name, body })
      : "id:" + id.parse(operationId);
  return {
    body,
    receipt: () => store.operation<unknown>(key, name, body),
    commit: (write: () => unknown) =>
      store.mutate(key, name, body, () => {
        if (store.get("report", "final"))
          throw new CodexSecurityError(
            "This investigation has been finalized.",
          );
        return write();
      }),
  };
}

function captureId(packet: StackPacket, item: WorkItem) {
  return (
    "capture-" + dependencyClaimHash([packet.manifest.inputDigest, item.id])
  );
}

function selectReceipt(
  packet: StackPacket,
  items: Map<string, WorkItem>,
  store: DependencyAttemptStore,
  receiptId: string,
  selection?: DependencyInventoryReceiptSelection,
): BoundDependencyInventoryReceipt {
  const item = items.get(receiptId);
  if (!item) return selectRuntimeReceipt(store, receiptId, selection);
  if (selection && selection.textBlock !== null) {
    throw new CodexSecurityError(
      "A captured stack is structured data. Use textBlock: null.",
    );
  }
  const result = selection ? inventoryJsonField(item, selection.record) : item;
  if (result === undefined)
    throw new CodexSecurityError("The selected capture record does not exist.");
  const supplemental = supplementalReceipt(store, item);
  return {
    receiptId,
    key: dependencyClaimHash([receiptId, selection?.record ?? null]),
    server: supplemental ? "stack-observation" : "stack-packet",
    originalPayloadSha256:
      supplemental?.sha256 ?? packet.manifest.files.stacks.sha256,
    origin: {
      tool: supplemental
        ? "next"
        : (store.get<string>("stack-protocol", "capture-origin") ??
          "read-stacks"),
      arguments: {
        inputDigest: packet.manifest.inputDigest,
        workItemId: item.id,
        queryId: item.queryId,
        groupId: item.groupId,
        ...(supplemental?.receiptId && {
          sourceReceiptId: supplemental.receiptId,
        }),
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
  store: DependencyAttemptStore,
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
        selectReceipt(packet, receiptsById, store, ref),
      ),
      ...(row.receiptSelections ?? []).map((selection) =>
        selectReceipt(
          packet,
          receiptsById,
          store,
          selection.receiptId,
          selection,
        ),
      ),
    ];
    // Keep the original imported artifact alongside every supplemental capture
    // so an exported report can be reviewed without the investigation database.
    for (const receipt of [...receipts]) {
      if (receipt.server !== "stack-observation") continue;
      const sourceId = receipt.origin.arguments["sourceReceiptId"];
      if (typeof sourceId !== "string") continue;
      if (
        receipts.some((item) => item.receiptId === sourceId && !item.selection)
      )
        continue;
      receipts.push(selectRuntimeReceipt(store, sourceId));
    }
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

function investigationVersion(store: DependencyAttemptStore) {
  return dependencyClaimHash({
    live: getLiveRun(store) ?? null,
    queries: store.keys("supplemental-query"),
    runtime: store.keys("runtime-receipt"),
    sources: store.keys("source-note"),
  });
}

function packetSnapshot(store: DependencyAttemptStore, base?: StackPacket) {
  return store.read(() => ({
    packet: overlayPacket(store, base),
    version: investigationVersion(store),
  }));
}

function reportWithEffectiveInputs(
  store: DependencyAttemptStore,
  packet: StackPacket,
  report: StackInvestigationReport,
): StackInvestigationReport {
  if (
    !getLiveRun(store) &&
    !store.size("supplemental-query") &&
    !store.size("runtime-receipt")
  )
    return report;
  return {
    ...report,
    effectiveInputDigest: dependencyClaimHash({
      format: "codex-security.stack-effective-input/v1",
      inputDigest: packet.manifest.inputDigest,
      target: packet.manifest.target,
      sources: packet.sources,
      sinks: packet.sinks,
      stacks: packet.stacks,
      runtimeReceiptIds: store.keys("runtime-receipt").sort(),
    }),
  };
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
  version?: string,
): Promise<StackInvestigationReport> {
  const saved = store.get("report", "final");
  if (requireSaved && !saved)
    throw new CodexSecurityError(
      "The investigator did not finalize the report.",
    );
  const decisions = store.values<StackAssessment>("stack-assessment");
  const snapshot = reportWithEffectiveInputs(
    store,
    packet,
    finalizeStackReport(packet, decisions, claims),
  );
  const digest = dependencyClaimHash(snapshot);
  const items = stackPacketWorkItems(packet);
  const byId = new Map(items.map((item) => [item.id, item]));
  for (const assessment of decisions) {
    prepareStackAssessment(
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
      store,
      signal,
    );
    const verified = current!.prepared;
    if (
      claims.preview(verified, original.revision).hash !== ref.hash ||
      dependencyClaimHash(verified.excerpts) !==
        dependencyClaimHash(original.excerpts) ||
      dependencyClaimHash(verified.receipts.map(dependencyClaimHash).sort()) !==
        dependencyClaimHash(original.receipts.map(dependencyClaimHash).sort())
    ) {
      throw new CodexSecurityError(
        "Supporting evidence changed for claim " + ref.id + ".",
      );
    }
  }
  return store.transaction(() => {
    if (version !== undefined && investigationVersion(store) !== version)
      throw new CodexSecurityError(
        "New observations or investigation metadata arrived during finalization. Retry finalize.",
      );
    const report = reportWithEffectiveInputs(
      store,
      packet,
      finalizeStackReport(
        packet,
        store.values<StackAssessment>("stack-assessment"),
        claims,
      ),
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
  expected?: { packet: StackPacket; repository: string; signal?: AbortSignal },
): Promise<StackInvestigationReport> {
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    const live = getLiveRun(store);
    if (live && expected)
      throw new CodexSecurityError(
        "Finalized state does not belong to the expected input packet.",
      );
    const location = live ? undefined : runLocation(store);
    const base = location
      ? (expected?.packet ??
        (await readStackPacket(
          location.inputs,
          location.repo,
          expected?.signal,
        )))
      : undefined;
    if (
      location &&
      dependencyClaimHash(base!.manifest) !== location.fingerprint
    )
      throw new CodexSecurityError(
        "Finalized state does not belong to this input packet.",
      );
    const { packet, version } = packetSnapshot(store, base);
    if (
      expected &&
      dependencyClaimHash(packet.stacks.queries) !==
        dependencyClaimHash(expected.packet.stacks.queries)
    )
      throw new CodexSecurityError(
        "Finalized state contains observations outside the expected input packet.",
      );
    return await verifyFinal(
      store,
      packet,
      expected?.repository ?? live?.repo ?? location!.repo,
      openClaims(store, packet),
      true,
      expected?.signal,
      version,
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
  },
): Promise<unknown> {
  const { state, signal } = options;
  if (command === "init")
    return initialize(
      state,
      options.inputs,
      options.repo,
      options.input,
      signal,
    );
  const store = new DependencyAttemptStore(state, { create: false });
  try {
    const live = getLiveRun(store);
    const location = live ? undefined : runLocation(store);
    const repository = live?.repo ?? location!.repo;
    if (command === "tools") return { commands: stackRunTools };
    const base = location
      ? await readStackPacket(location.inputs, repository, signal)
      : undefined;
    if (
      location &&
      dependencyClaimHash(base!.manifest) !== location.fingerprint
    ) {
      throw new CodexSecurityError("The frozen investigation packet changed.");
    }
    if (command === "record-evidence") {
      const op = mutation(store, command, options.input);
      const previous = op.receipt();
      if (previous) return previous.result;
      if (op.body["kind"] === "runtime") {
        const captured = await prepareRuntimeEvidence(
          op.body,
          repository,
          signal,
        );
        return op.commit(() => saveRuntimeEvidence(store, captured));
      }
      const target = live?.target ?? base!.manifest.target;
      const captured = await prepareDependencySourceNote(repository, op.body, {
        targetSha: target.sha,
        logicalRepository: target.repository,
        ...(signal && { signal }),
      });
      return op.commit(() => {
        if (
          live &&
          dependencyClaimHash(getLiveRun(store)?.target) !==
            dependencyClaimHash(target)
        )
          throw new CodexSecurityError(
            "The investigation target changed while reading source evidence. Retry record-evidence.",
          );
        return saveDependencySourceNote(store, captured);
      });
    }
    if (command === "record-observations") {
      const op = mutation(store, command, options.input);
      const previous = op.receipt();
      if (previous) return previous.result;
      const input = recordObservationsInputSchema.parse(op.body);
      if (input.receiptId) selectRuntimeReceipt(store, input.receiptId);
      return op.commit(() => recordObservations(store, input, base));
    }
    if (live) {
      const gaps = liveMetadataGaps(store);
      if (command === "next" && gaps.length)
        return { workItem: null, target: live.target, openQuestions: gaps };
    }
    const { packet, version } = packetSnapshot(store, base);
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
        return {
          workItem: item,
          receiptId: captureId(packet, item),
          rootFirstRawIndices: item.observation
            ? stackFramesRootFirst(item.observation).map(
                ({ rawIndex }) => rawIndex,
              )
            : [],
          target: manifest.target,
          cve: manifest.cve,
          advisory: manifest.advisory,
          sources: packet.sources.sources,
          sinks: packet.sinks.sinks,
          openQuestions: packet.sinks.sinks.flatMap(
            (sink) => sink.preconditions,
          ),
        };
      }
      case "query-claims":
        return claims.query(options.input);
      case "summarize-coverage":
        return summarizeStackCoverage(packet, assessments());
      case "finalize":
        if (live && (!packet.sinks.sinks.length || !items.length))
          throw new CodexSecurityError(
            "Finalize requires at least one identified sink and an assessed observation or coverage gap.",
          );
        return await verifyFinal(
          store,
          packet,
          repository,
          claims,
          false,
          signal,
          version,
        );
      case "record-claims": {
        const op = mutation(store, command, options.input);
        const previous = op.receipt();
        if (previous) return previous.result;
        const input = dependencyClaimQueueSchema.parse(op.body);
        const rows = await prepareClaims(
          input.claims,
          packet,
          items,
          repository,
          store,
          signal,
        );
        return op.commit(() => {
          if (investigationVersion(store) !== version)
            throw new CodexSecurityError(
              "The investigation changed while preparing claims. Retry record-claims.",
            );
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
        const assessment = prepareStackAssessment(
          input.items[0]!,
          item,
          packet,
          claims,
          signal,
        );
        return op.commit(() => {
          if (investigationVersion(store) !== version)
            throw new CodexSecurityError(
              "The investigation changed while assessing this path. Run next again.",
            );
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
