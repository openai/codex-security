import {
  exactUnion,
  isObject,
  preserveFindingDetails,
  prepareSemanticScanDraft,
  type PreparedScanDraft,
  requireObject,
  scanFindingIdentity,
  semanticScanDraft,
  validateCoverageSemantics,
  validateFindingSemantics,
  type SemanticScan,
  type SemanticFinding,
} from "../../../../sdk/typescript/src/scan-semantics.js";
import { isNonEmptyString } from "./record.js";
import { createHash, randomUUID } from "node:crypto";
import { writePreparedScanDraft } from "../../../../sdk/typescript/src/scan-draft-publication.js";
import { promises as fs } from "node:fs";
import { join } from "node:path";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import scanDraftDocument from "../../schemas/tools/scan-draft.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import type { RunArtifactWorkbench } from "./artifact-context.js";
import {
  artifactDestination,
  replaceArtifactText,
  readArtifactJsonObject,
  readArtifactText,
  readArtifactTextWithMetadata,
  requireArtifactRoot,
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";

type JsonObject = Record<string, unknown>;

export type ScanDraftInput = SemanticScan;

export interface CompletedScanInput {
  scanId: string;
  handoffClaimToken?: string;
}

export interface ScanDraftResult {
  scanId: string;
  findingCount: number;
  surfaceCount: number;
  coverage: PreparedScanDraft["coverage"];
  warnings?: string[];
  operation: "replace";
  status: "draft_written";
}

export interface CompletedScanResult {
  scanId: string;
  manifest: JsonObject;
  findings: JsonObject;
  coverage: JsonObject;
}

type SavedDraftRecord = {
  name: string;
  input: ScanDraftInput;
  modifiedMs: number;
};

type PublishScanDraft = (
  draft: PreparedScanDraft,
  expectedDigest: string | undefined,
  checkpoint: ScanDraftInput,
  reconciledCheckpointIds: readonly string[],
) => Promise<string[] | void>;

const schemaDocuments = [commonSchema, scanDraftDocument] as SchemaDocument[];

export const scanDraftInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  scanDraftDocument.$id,
  "scanDraftInput",
) as z.ZodType<ScanDraftInput>;

export const completedScanInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  scanDraftDocument.$id,
  "completedScanInput",
) as z.ZodType<CompletedScanInput>;

/** Replace the three existing final-input documents without completing or sealing a scan. */
export async function recordCodexSecurityScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
  publishDraft: PublishScanDraft,
  signal?: AbortSignal,
): Promise<ScanDraftResult> {
  const parsed = parseScanDraft(input);
  requireBoundScan(context, parsed, true);
  if (
    context.mode === "deep" &&
    parsed.complete !== false &&
    parsed.coverage.resolvedDeferred?.length
  )
    throw new Error(
      "scan draft: terminal Deep drafts cannot resolve child deferred work.",
    );

  for (;;) {
    signal?.throwIfAborted();
    const preserved = await preserveScanDraft(context, parsed);
    const reconciled = preserved.input;
    const hardening = await readExistingHardeningPortfolio(context);
    const draft = prepareSemanticScanDraft(context, reconciled, hardening);
    try {
      const warnings = await publishDraft(
        draft,
        preserved.previousDigest,
        context.mode === "deep" && parsed.complete !== false
          ? reconciled
          : parsed,
        preserved.checkpointIds,
      );
      return {
        scanId: reconciled.scanId,
        findingCount: draft.findings.findings.length,
        surfaceCount: draft.coverage.surfaces.length,
        coverage: draft.coverage,
        ...(warnings?.length ? { warnings } : {}),
        operation: "replace",
        status: "draft_written",
      };
    } catch (error) {
      if (!isScanDraftConflict(error)) throw error;
      signal?.throwIfAborted();
    }
  }
}

/** Publish through the workbench's claim and completion lock. */
export async function recordCodexSecurityScanDraftViaWorkbench(
  context: ArtifactContext,
  input: ScanDraftInput,
  runWorkbench: RunArtifactWorkbench,
  signal?: AbortSignal,
): Promise<ScanDraftResult> {
  return recordCodexSecurityScanDraft(
    context,
    input,
    async (documents, expectedDigest, checkpoint, reconciledCheckpointIds) => {
      try {
        const result = await writePreparedScanDraft(
          {
            scanDir: context.root,
            expectedDigest,
            reconciledCheckpointIds,
            claimToken: context.handoffClaimToken,
            writer: {
              restore: async (relative, contents) => {
                const path = await artifactDestination(
                  context,
                  relative.split("/"),
                  "staged scan draft",
                );
                await replaceArtifactText(
                  path,
                  Buffer.from(contents).toString("utf8"),
                );
              },
            },
            workbench: (args) => runWorkbench([...args]),
          },
          checkpoint.scanId,
          documents,
          checkpoint,
        );
        return isObject(result) && Array.isArray(result.warnings)
          ? result.warnings.filter(
              (warning): warning is string => typeof warning === "string",
            )
          : undefined;
      } catch (error) {
        if (!workbenchScanDraftConflict(error)) throw error;
        throw Object.assign(
          new Error("The committed scan draft changed during reconciliation."),
          {
            code: "scan_draft_conflict",
          },
        );
      }
    },
    signal,
  );
}

/** Reconcile the committed snapshot and pending evidence; omission is not resolution. */
async function preserveScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<{
  input: ScanDraftInput;
  previousDigest: string;
  checkpointIds: string[];
}> {
  const state = await readPreviousScanDraft(context);
  const pending = await readPendingCheckpoints(
    context,
    state.acknowledged ?? [],
  );
  // A partial retry adopts the first terminal decision, including one whose
  // pending checkpoint was saved after the committed snapshot.
  const previous = [...state.drafts, ...pending]
    .sort(
      (left, right) =>
        right.modifiedMs - left.modifiedMs ||
        right.name.localeCompare(left.name),
    )
    .map((entry) => entry.input);
  validateDeferredClosures(input, previous);
  // Parsed input belongs to this operation. Assign once so retries keep the same IDs.
  assignDraftIds(
    input,
    previous.flatMap((draft) => draft.coverage.deferred),
    previous.flatMap((draft) => draft.findings),
  );
  let result = semanticDraft(context, prepareSemanticScanDraft(context, input));
  requireDraftIdentities(result);
  for (const draft of previous) {
    // Final Deep aggregates supersede accepted history, but not uncommitted evidence.
    if (
      draft === state.input &&
      context.mode === "deep" &&
      input.complete !== false
    )
      continue;
    result = preserveDraft(result, draft);
  }
  result.threatModel ??= state.input?.threatModel;
  return {
    input: result,
    previousDigest: state.digest,
    checkpointIds: pending.map((entry) => entry.name),
  };
}

function validateDeferredClosures(
  input: ScanDraftInput,
  previous: ScanDraftInput[],
): void {
  const requested = new Set<string>();
  const saved = previous.flatMap((draft) => draft.coverage.deferred);
  const resolvedCandidates = new Set(
    [
      ...input.findings.map(findingCandidateId),
      ...input.coverage.surfaces
        .filter(
          (surface) =>
            surface.disposition === "rejected" ||
            surface.disposition === "not_applicable",
        )
        .map((surface) => surface.candidateId),
    ].filter((id) => id !== undefined),
  );
  const alreadyClosed = new Set(
    previous.flatMap((draft) =>
      (draft.coverage.resolvedDeferred ?? []).map((row) => row.id),
    ),
  );
  for (const closure of input.coverage.resolvedDeferred ?? []) {
    const id = closure.id;
    if (requested.has(id))
      throw new Error(`scan draft: coverage.resolvedDeferred repeats ${id}.`);
    requested.add(id);
    const rows = saved.filter((row) => row.id === id || row.candidateId === id);
    if (
      rows.some(
        (row) =>
          (row.candidateId !== undefined ||
            row.candidate !== undefined ||
            row.finding !== undefined) &&
          (row.candidateId === undefined ||
            !resolvedCandidates.has(row.candidateId)),
      )
    )
      throw new Error(
        `scan draft: coverage.resolvedDeferred cannot close candidate ${id}; record its finding or disposition.`,
      );
    if (!rows.length && !alreadyClosed.has(id))
      throw new Error(
        `scan draft: coverage.resolvedDeferred names no saved generic deferral: ${id}.`,
      );
    if (
      input.coverage.deferred.some(
        (row) => row.id === id || row.candidateId === id,
      )
    )
      throw new Error(
        `scan draft: resolved deferred work is still active: ${id}.`,
      );
  }
}

function preserveDraft(
  input: ScanDraftInput,
  previous: ScanDraftInput,
): ScanDraftInput {
  // Keep the final presentation authoritative while retaining late evidence.
  const reopenedWork = input.coverage.deferred.filter((row) =>
    previous.coverage.resolvedDeferred?.some(
      (closure) => closure.id === row.id,
    ),
  );
  const reopensClosedWork = reopenedWork.length > 0;
  const reopenedSurfaces = new Set(
    reopenedWork.flatMap((row) => row.surfaceIds ?? []),
  );
  if (
    input.complete === false &&
    previous.complete !== false &&
    !reopensClosedWork
  )
    [input, previous] = [previous, input];

  const result = structuredClone(input);
  const activeIds = new Set(result.coverage.deferred.map((row) => row.id));
  const closures = new Map(
    (previous.coverage.resolvedDeferred ?? [])
      .filter((closure) => !activeIds.has(closure.id))
      .map((closure) => [closure.id, closure]),
  );
  for (const closure of result.coverage.resolvedDeferred ?? [])
    closures.set(closure.id, closure);
  if (closures.size) result.coverage.resolvedDeferred = [...closures.values()];
  else delete result.coverage.resolvedDeferred;
  result.scope ??= previous.scope;
  result.threatModel ??= previous.threatModel;
  const findings = new Map(
    result.findings.map((finding) => [scanFindingIdentity(finding), finding]),
  );
  const rejected = new Map(
    result.coverage.surfaces
      .filter(
        (surface) =>
          surface.disposition === "rejected" ||
          surface.disposition === "not_applicable",
      )
      .filter((surface) => typeof surface.candidateId === "string")
      .map((surface) => [surface.candidateId, surface]),
  );
  for (const finding of previous.findings) {
    const disposition = rejected.get(findingCandidateId(finding));
    if (disposition) {
      disposition.finding ??= finding;
      disposition.previousFindings = exactUnion(
        Array.isArray(disposition.previousFindings)
          ? disposition.previousFindings
          : [],
        [finding],
      );
      continue;
    }
    const id = scanFindingIdentity(finding);
    const current = findings.get(id);
    if (current) preserveFindingDetails(current, finding);
    else {
      result.findings.push(finding);
      findings.set(id, finding);
    }
  }

  const resolvedCandidates = new Map<unknown, JsonObject>([
    ...result.findings
      .map((finding) => [findingCandidateId(finding), finding] as const)
      .filter(([id]) => id !== undefined),
    ...rejected,
  ]);
  const surfaces = new Map(
    result.coverage.surfaces.map((surface) => [surface.id, surface]),
  );
  const previousSurfaces = new Map(
    previous.coverage.surfaces.map((surface) => [surface.id, surface]),
  );
  const pendingSurfaces = new Set(
    result.coverage.deferred.flatMap((row) => row.surfaceIds ?? []),
  );
  const deferred = new Map(
    result.coverage.deferred.map((row) => [row.id, row]),
  );
  const pendingCandidates = new Map<unknown, JsonObject>(
    result.coverage.deferred
      .filter((row) => typeof row.candidateId === "string")
      .map((row) => [row.candidateId, row]),
  );
  for (const row of previous.coverage.deferred) {
    const current =
      resolvedCandidates.get(row.candidateId) ?? deferred.get(row.id);
    if (current) {
      preserveCandidateEvidence(current, row);
      continue;
    }
    if (closures.has(row.id!)) continue;
    if (
      row.candidateId === undefined &&
      row.candidate === undefined &&
      row.finding === undefined &&
      row.surfaceIds?.length &&
      row.surfaceIds.every((id) => {
        const surface = surfaces.get(id);
        return (
          surface &&
          previousSurfaces.get(id)?.disposition === "needs_follow_up" &&
          surface.disposition !== "needs_follow_up" &&
          !pendingSurfaces.has(id)
        );
      })
    )
      continue;
    result.coverage.deferred.push(row);
  }
  for (const surface of previous.coverage.surfaces) {
    const retainedSurface = surfaces.get(surface.id);
    if (retainedSurface)
      retainedSurface.receiptRefs = exactUnion(
        retainedSurface.receiptRefs ?? [],
        surface.receiptRefs ?? [],
      );
    const current =
      resolvedCandidates.get(surface.candidateId) ??
      pendingCandidates.get(surface.candidateId) ??
      surfaces.get(surface.id);
    if (current) {
      preserveCandidateEvidence(current, surface);
      continue;
    }
    result.coverage.surfaces.push(
      surface.candidateId === undefined && reopenedSurfaces.has(surface.id!)
        ? { ...surface, disposition: "needs_follow_up" }
        : surface,
    );
  }
  result.coverage.explicitExclusions = exactUnion(
    result.coverage.explicitExclusions,
    previous.coverage.explicitExclusions,
  );
  if (result.complete === false)
    result.coverage.openQuestions = exactUnion(
      result.coverage.openQuestions ?? [],
      previous.coverage.openQuestions ?? [],
    );
  if (
    result.coverage.deferred.length ||
    result.coverage.surfaces.some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  )
    result.coverage.completeness = "partial";
  return result;
}

function preserveCandidateEvidence(
  current: JsonObject,
  previous: JsonObject,
): void {
  if (isObject(current.provenance)) {
    if (previous.candidate !== undefined)
      current.provenance.originalCandidates = exactUnion(
        Array.isArray(current.provenance.originalCandidates)
          ? current.provenance.originalCandidates
          : [],
        [previous.candidate],
      );
    for (const finding of [
      previous.finding,
      ...(Array.isArray(previous.previousFindings)
        ? previous.previousFindings
        : []),
    ])
      if (isObject(finding)) preserveFindingDetails(current, finding);
  } else {
    if (previous.candidate !== undefined)
      current.candidate ??= previous.candidate;
    if (previous.finding !== undefined) current.finding ??= previous.finding;
    if (Array.isArray(previous.previousFindings))
      current.previousFindings = exactUnion(
        Array.isArray(current.previousFindings) ? current.previousFindings : [],
        previous.previousFindings,
      );
  }
}

function findingCandidateId(finding: SemanticFinding): string | undefined {
  return [
    finding.provenance.candidateId,
    finding.extensions?.["candidateId"],
    finding.extensions?.["reportId"],
    finding.extensions?.["ledgerRowId"],
  ].find(
    (value): value is string =>
      typeof value === "string" && Boolean(value.trim()),
  );
}

function semanticDraft(
  context: ArtifactContext,
  draft: PreparedScanDraft,
): ScanDraftInput {
  return semanticScanDraft(
    context.scanId!,
    draft.manifest.scan,
    draft.findings.findings,
    draft.coverage,
  );
}

function assignDraftIds(
  input: ScanDraftInput,
  previousDeferred: ScanDraftInput["coverage"]["deferred"],
  previousFindings: SemanticFinding[],
): void {
  for (const finding of input.findings) {
    if (finding.identity !== undefined) continue;
    const candidateId = findingCandidateId(finding);
    const sameCandidate = (other: SemanticFinding) =>
      candidateId !== undefined &&
      findingCandidateId(other) === candidateId &&
      other.ruleId === finding.ruleId &&
      ["source", "sourceScanId", "sourceWorkerId"].every(
        (key) => other.provenance[key] === finding.provenance[key],
      );
    const identities = new Map(
      previousFindings
        .filter((other) => other.identity !== undefined && sameCandidate(other))
        .map((other) => [
          JSON.stringify([
            other.identity!.anchor,
            other.identity!.instance ?? null,
          ]),
          other.identity!,
        ]),
    );
    const [saved] = identities.values();
    finding.identity =
      identities.size === 1 &&
      !input.findings.some((other) => other !== finding && sameCandidate(other))
        ? saved!
        : { anchor: randomUUID() };
  }
  for (const surface of input.coverage.surfaces) surface.id ??= randomUUID();
  for (const row of input.coverage.deferred) {
    if (row.id !== undefined) continue;
    const matches = new Set(
      previousDeferred
        .filter(
          (saved) =>
            row.candidateId !== undefined &&
            saved.candidateId === row.candidateId,
        )
        .map((saved) => saved.id),
    );
    const [savedId] = matches;
    row.id =
      matches.size === 1 &&
      savedId !== undefined &&
      !input.coverage.deferred.some(
        (other) =>
          other !== row &&
          (other.id === savedId || other.candidateId === row.candidateId),
      )
        ? savedId
        : randomUUID();
  }
}

async function readPreviousScanDraft(context: ArtifactContext): Promise<{
  input?: ScanDraftInput;
  drafts: SavedDraftRecord[];
  digest: string;
  acknowledged?: unknown[];
}> {
  const snapshot = await readOptionalArtifact(context, [
    "artifacts",
    "scan-draft.json",
  ]);
  const draft =
    snapshot === undefined
      ? undefined
      : (parseJsonObject(
          snapshot.contents,
          "committed scan draft",
        ) as unknown as PreparedScanDraft & {
          reconciledCheckpointIds?: unknown;
          canonicalExport?: {
            previous?: Record<string, string | null>;
            current?: Record<string, string>;
          };
        });
  const input = draft === undefined ? undefined : savedDraft(context, draft);
  const drafts: SavedDraftRecord[] =
    input === undefined
      ? []
      : [
          {
            input,
            name: "artifacts/scan-draft.json",
            modifiedMs: snapshot!.modifiedMs,
          },
        ];
  const names = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
  ] as const;
  const files = await Promise.all(
    names.map((name) => readOptionalArtifact(context, [name])),
  );
  const contents = files.map((file) => file?.contents);
  const state = {
    input,
    drafts,
    acknowledged: Array.isArray(draft?.reconciledCheckpointIds)
      ? draft.reconciledCheckpointIds
      : [],
    // Canonical files can be authored independently after the last snapshot.
    // The writer must reject a token if either source changes during reconciliation.
    digest: draftDigest([
      ...(snapshot === undefined
        ? []
        : [["artifacts/scan-draft.json", snapshot.contents] as const]),
      ...names.map((name, index) => [name, contents[index]] as const),
    ]),
  };
  if (contents.every((value) => value === undefined)) return state;
  if (contents.some((value) => value === undefined)) {
    if (snapshot !== undefined) return state;
    throw new Error("previous scan draft: canonical documents are incomplete.");
  }
  if (
    draft?.canonicalExport &&
    names.every((name, index) => {
      const digest = createHash("sha256")
        .update(contents[index]!)
        .digest("hex");
      return (
        digest === draft.canonicalExport!.current?.[name] ||
        digest === draft.canonicalExport!.previous?.[name]
      );
    })
  )
    return state;
  const manifest = parseJsonObject(
    contents[0]!,
    "previous scan draft manifest",
  );
  // Older snapshots lack export digests. Preserve their matching-envelope
  // fallback; current snapshots admit authored changes without timestamp rules.
  if (
    draft !== undefined &&
    !draft.canonicalExport &&
    (!isObject(manifest.scan) ||
      manifest.scan.completedAt == null ||
      manifest.scan.completedAt !==
        (draft.manifest.scan as JsonObject)["completedAt"])
  )
    return state;
  const canonical = savedDraft(context, {
    manifest,
    findings: parseJsonObject(contents[1]!, "previous scan draft findings"),
    coverage: parseJsonObject(contents[2]!, "previous scan draft coverage"),
  } as unknown as PreparedScanDraft);
  drafts.push({
    input: canonical,
    name: "scan-manifest.json",
    modifiedMs: Math.max(...files.map((file) => file!.modifiedMs)),
  });
  state.input ??= canonical;
  return state;
}

async function readPendingCheckpoints(
  context: ArtifactContext,
  acknowledged: readonly unknown[],
): Promise<SavedDraftRecord[]> {
  let directory = await requireArtifactRoot(
    context.root,
    "pending scan checkpoints",
  );
  for (const part of ["checkpoints", "pending"]) {
    const parent = directory;
    directory = join(directory, part);
    let metadata;
    try {
      metadata = await fs.lstat(directory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        if (part === "checkpoints") return [];
        // Older writers saved stable checkpoints before the pending index existed.
        directory = parent;
        break;
      }
      throw error;
    }
    if (metadata.isSymbolicLink() || !metadata.isDirectory())
      throw new Error("Pending scan checkpoints require a safe directory.");
  }
  const checkpoints = [];
  for (const name of await fs.readdir(directory)) {
    if (!/^[0-9a-f]{64}\.json$/u.test(name) || acknowledged.includes(name))
      continue;
    // Pending payloads retain staged evidence if the immutable copy was interrupted.
    let components = ["checkpoints", name];
    let contents = await readOptionalArtifactText(context, components);
    if (contents === undefined) {
      components = ["checkpoints", "pending", name];
      contents = await readOptionalArtifactText(context, components);
    }
    if (contents?.startsWith("drafts/")) {
      if (!/^drafts\/[0-9a-fA-F-]+\.checkpoint\.json$/u.test(contents))
        throw new Error("scan checkpoint: invalid staged checkpoint path.");
      components = contents.split("/");
      contents = await readOptionalArtifactText(context, components);
      if (
        contents !== undefined &&
        createHash("sha256").update(contents).digest("hex") + ".json" !== name
      )
        throw new Error("scan checkpoint: staged checkpoint digest changed.");
    }
    if (contents === undefined) continue;
    const metadata = await fs
      .lstat(join(context.root, ...components))
      .catch((error) => {
        if ((error as NodeJS.ErrnoException).code === "ENOENT")
          return undefined;
        throw error;
      });
    if (metadata === undefined) continue;
    const saved = parseJsonObject(contents, "pending scan checkpoint");
    if (saved.scanId !== context.scanId)
      throw new Error("Pending scan checkpoint belongs to a different scan.");
    const input = parseScanDraft(
      semanticScanDraft(
        context.scanId!,
        saved,
        saved.findings as JsonObject[],
        requireObject(saved.coverage, "pending scan checkpoint coverage"),
      ),
    );
    requireDraftIdentities(input);
    checkpoints.push({ name, input, modifiedMs: metadata.mtimeMs });
  }
  // An incomplete retry adopts the first final draft, so newer decisions win.
  checkpoints.sort(
    (left, right) =>
      right.modifiedMs - left.modifiedMs || right.name.localeCompare(left.name),
  );
  return checkpoints;
}

function savedDraft(
  context: ArtifactContext,
  draft: PreparedScanDraft,
): ScanDraftInput {
  const scan = requireObject(draft.manifest.scan, "committed scan draft.scan");
  if (scan.id !== context.scanId)
    throw new Error(
      "scan checkpoint: saved result belongs to a different scan.",
    );
  const input = parsePersistedScanDraft(semanticDraft(context, draft));
  requireDraftIdentities(input);
  return input;
}

function requireDraftIdentities(input: ScanDraftInput): void {
  if (
    input.findings.some((finding) => finding.identity === undefined) ||
    input.coverage.surfaces.some((surface) => surface.id === undefined) ||
    input.coverage.deferred.some((row) => row.id === undefined)
  )
    throw new Error(
      "The saved draft has no stable IDs; finish it with its original plugin version or start a new scan.",
    );
  for (const ids of [
    input.findings.map(scanFindingIdentity),
    input.coverage.surfaces.map((surface) => surface.id),
    input.coverage.deferred.map((row) => row.id),
  ]) {
    if (new Set(ids).size !== ids.length)
      throw new Error(
        "The scan draft repeats an identity; use distinct finding instances and coverage IDs.",
      );
  }
}

async function readOptionalArtifactText(
  context: ArtifactContext,
  components: readonly string[],
): Promise<string | undefined> {
  return (await readOptionalArtifact(context, components))?.contents;
}

async function readOptionalArtifact(
  context: ArtifactContext,
  components: readonly string[],
): Promise<{ contents: string; modifiedMs: number } | undefined> {
  try {
    return await readArtifactTextWithMetadata(
      context,
      components,
      "previous scan draft",
    );
  } catch (error) {
    if (
      error instanceof Error &&
      error.message ===
        "previous scan draft: the requested artifact is unavailable."
    ) {
      return undefined;
    }
    throw error;
  }
}

function parseJsonObject(contents: string, label: string): JsonObject {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch {
    throw new Error(`${label}: stored JSON is malformed.`);
  }
  return requireObject(parsed, `${label}: stored JSON`);
}

function draftDigest(
  documents: ReadonlyArray<readonly [string, string | undefined]>,
): string {
  const digest = createHash("sha256");
  for (const [name, contents] of documents) {
    digest.update(name).update("\0");
    if (contents === undefined) digest.update("missing\0");
    else digest.update("present\0").update(contents).update("\0");
  }
  return digest.digest("hex");
}

function isScanDraftConflict(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    error.code === "scan_draft_conflict"
  );
}

function workbenchScanDraftConflict(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const stderr =
    "stderr" in error && typeof error.stderr === "string" ? error.stderr : "";
  return `${error.message}\n${stderr}`.includes("scan_draft_conflict");
}

/** Return the existing sealed documents only after workbench completion succeeds. */
export async function getCodexSecurityCompletedScan(
  context: ArtifactContext,
  input: CompletedScanInput,
): Promise<CompletedScanResult> {
  const parsed = completedScanInputSchema.parse(input);
  requireBoundScan(context, parsed, false);
  if (context.status !== "complete") {
    throw new Error(
      "completed scan: the selected scan has not completed successfully.",
    );
  }

  const [manifest, findings, coverage] = await Promise.all([
    readArtifactJsonObject(
      context,
      ["scan-manifest.json"],
      "completed scan manifest",
    ),
    readArtifactJsonObject(
      context,
      ["findings.json"],
      "completed scan findings",
    ),
    readArtifactJsonObject(
      context,
      ["coverage.json"],
      "completed scan coverage",
    ),
  ]);

  const scan = requireObject(manifest.scan, "completed scan manifest.scan");
  if (
    scan.id !== parsed.scanId ||
    scan.status !== "completed" ||
    typeof scan.sealedAt !== "string" ||
    !scan.sealedAt ||
    !Array.isArray(scan.artifacts) ||
    findings.scanId !== parsed.scanId ||
    coverage.scanId !== parsed.scanId
  ) {
    throw new Error(
      "completed scan: canonical documents do not match the sealed workbench scan.",
    );
  }

  return { scanId: parsed.scanId, manifest, findings, coverage };
}

function parseSavedScanDraft(input: unknown): ScanDraftInput {
  const parsed = scanDraftInputSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  validateCoverageSemantics(parsed.coverage);
  return parsed;
}

export function parseScanDraft(input: unknown): ScanDraftInput {
  const parsed = parseSavedScanDraft(input);
  if (parsed.complete === false && parsed.coverage.resolvedDeferred?.length)
    throw new Error(
      "scan draft: coverage.resolvedDeferred is allowed only on a terminal draft.",
    );
  return parsed;
}

/** Validate saved drafts before reconciling interrupted writes and older findings. */
export function parsePersistedScanDraft(
  input: Record<string, unknown> | ScanDraftInput,
): ScanDraftInput {
  const compatible = structuredClone(input);
  if (!Array.isArray(compatible.findings)) {
    return parseSavedScanDraft(compatible);
  }
  for (const finding of compatible.findings) {
    if (!isObject(finding)) continue;
    normalizePersistedFindingDetails(finding);
  }
  return parseSavedScanDraft(compatible);
}

function parsePersistedCheckpoint(
  input: Record<string, unknown>,
): ScanDraftInput {
  const compatible = structuredClone(input);
  if (isObject(compatible.scope)) {
    delete compatible.scope.includePaths;
    delete compatible.scope.excludePaths;
    if (Object.keys(compatible.scope).length === 0) delete compatible.scope;
  }
  if (isObject(compatible.coverage)) {
    for (const field of [
      "documentType",
      "schemaVersion",
      "scanId",
      "mode",
      "includePaths",
      "excludePaths",
      "receiptRefs",
      "inventoryStrategy",
    ])
      delete compatible.coverage[field];
  }
  if (Array.isArray(compatible.findings)) {
    for (const finding of compatible.findings) {
      if (!isObject(finding)) continue;
      delete finding.findingId;
      delete finding.occurrenceId;
      delete finding.fingerprints;
    }
  }
  return parsePersistedScanDraft(compatible);
}

function normalizePersistedFindingDetails(finding: JsonObject): void {
  const canonicalEvidence = Array.isArray(finding.codeEvidence)
    ? finding.codeEvidence
    : [];
  const evidenceIds = new Set(
    canonicalEvidence.flatMap((evidence) => {
      if (!isObject(evidence)) return [];
      const id = evidence.id;
      return isNonEmptyString(id) ? [id] : [];
    }),
  );
  if (Array.isArray(finding.code_evidence)) {
    const compatibleEvidence: JsonObject[] = [];
    for (const evidence of finding.code_evidence) {
      if (!isObject(evidence)) continue;
      const id = evidence.id;
      const code = evidence.code;
      if (
        !isNonEmptyString(id) ||
        !isNonEmptyString(code) ||
        evidenceIds.has(id)
      ) {
        continue;
      }
      evidenceIds.add(id);
      compatibleEvidence.push(evidence);
    }
    finding.code_evidence = compatibleEvidence;
  } else if ("code_evidence" in finding) {
    delete finding.code_evidence;
  }

  for (const [sectionName, listFields] of [
    ["rootCause", ["evidenceRefs", "evidence_refs"]],
    ["root_cause", ["evidenceRefs", "evidence_refs"]],
    [
      "validation",
      [
        "assertions",
        "counterEvidence",
        "evidence",
        "evidenceRefs",
        "evidence_refs",
        "limitations",
      ],
    ],
    [
      "attackPath",
      [
        "assumptions",
        "blindspots",
        "controls",
        "evidenceRefs",
        "evidence_refs",
        "limitations",
        "preconditions",
        "steps",
      ],
    ],
  ] satisfies Array<[string, string[]]>) {
    const section = finding[sectionName];
    if (!isObject(section)) continue;
    normalizePersistedStringLists(section, listFields);
  }

  const rootCause = finding.rootCause;
  if (isObject(rootCause)) {
    if (!isNonEmptyString(rootCause.summary)) {
      delete finding.rootCause;
    } else {
      removeUnsupportedPersistedStrings(rootCause, ["code", "language"]);
    }
  }
  const legacyRootCause = finding.root_cause;
  if (isObject(legacyRootCause)) {
    removeUnsupportedPersistedStrings(legacyRootCause, [
      "summary",
      "code",
      "language",
    ]);
  } else if ("root_cause" in finding && !isNonEmptyString(legacyRootCause)) {
    delete finding.root_cause;
  }

  const validation = finding.validation;
  if (isObject(validation)) {
    removeUnsupportedPersistedStrings(validation, [
      "method",
      "status",
      "summary",
      "disposition",
      "result",
    ]);
  }

  const attackPath = finding.attackPath;
  if (!isObject(attackPath)) return;
  removeUnsupportedPersistedStrings(attackPath, ["summary"]);
  for (const field of ["dataFlow", "data_flow", "dataflow", "reachability"]) {
    const detail = attackPath[field];
    if (!isObject(detail)) {
      if (!isNonEmptyString(detail)) delete attackPath[field];
      continue;
    }
    removeUnsupportedPersistedStrings(detail, [
      "summary",
      "source",
      "sink",
      "outcome",
      ...(field === "reachability" ? ["attacker", "entrypoint"] : []),
    ]);
    normalizePersistedStringLists(detail, [
      "evidenceRefs",
      "evidence_refs",
      "transformations",
      ...(field === "reachability" ? ["preconditions"] : []),
    ]);
  }
  for (const field of ["impact", "likelihood"]) {
    const detail = attackPath[field];
    if (isObject(detail)) {
      removeUnsupportedPersistedStrings(detail, ["level", "rationale", "why"]);
    } else if (
      detail !== undefined &&
      detail !== null &&
      !isNonEmptyString(detail)
    ) {
      delete attackPath[field];
    }
  }

  function normalizePersistedStringLists(
    section: JsonObject,
    fields: string[],
  ): void {
    for (const field of fields) {
      if (!(field in section)) continue;
      const value = section[field];
      const normalized = isNonEmptyString(value)
        ? [value]
        : Array.isArray(value)
          ? value.filter(isNonEmptyString)
          : [];
      if (normalized.length > 0) section[field] = normalized;
      else delete section[field];
    }
    for (const field of ["evidenceRefs", "evidence_refs"]) {
      const refs = section[field];
      if (!Array.isArray(refs)) continue;
      section[field] = refs.filter((ref) => evidenceIds.has(ref));
    }
  }
}

function removeUnsupportedPersistedStrings(
  section: JsonObject,
  fields: string[],
): void {
  for (const field of fields) {
    if (field in section && !isNonEmptyString(section[field])) {
      delete section[field];
    }
  }
}

function requireBoundScan(
  context: ArtifactContext,
  input: CompletedScanInput,
  requireRunning: boolean,
): void {
  requireMatchingScan(context, input);
  if (requireRunning && context.status !== "running") {
    throw new Error(
      "scan draft: only a running workbench scan can accept draft artifacts.",
    );
  }
}

function requireMatchingScan(
  context: ArtifactContext,
  input: CompletedScanInput,
): void {
  if (context.scanId !== input.scanId) {
    throw new Error(
      "scan draft: scanId does not match the authoritative workbench scan.",
    );
  }
  if (
    context.handoffClaimToken !== undefined &&
    context.handoffClaimToken !== input.handoffClaimToken
  ) {
    throw new Error(
      "scan draft: pass the current authoritative handoffClaimToken.",
    );
  }
}

async function readExistingHardeningPortfolio(
  context: ArtifactContext,
): Promise<{ portfolioPath: "hardening/hardening.md" } | undefined> {
  const label = "scan draft hardening portfolio";
  try {
    await readArtifactText(context, ["hardening", "hardening.md"], label);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === `${label}: the requested artifact is unavailable.`
    ) {
      return undefined;
    }
    throw error;
  }
  return { portfolioPath: "hardening/hardening.md" };
}
