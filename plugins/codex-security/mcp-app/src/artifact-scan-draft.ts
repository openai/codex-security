import { isDeepStrictEqual } from "node:util";
import {
  normalizeDeferred,
  normalizeSurfaces,
  containsSavedFinding,
  containsSavedValue,
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
  type SemanticCoverage,
} from "../../../../sdk/typescript/src/scan-semantics.js";
import { createHash } from "node:crypto";
import { writePreparedScanDraft } from "../../../../sdk/typescript/src/scan-draft-publication.js";
import { promises as fs } from "node:fs";
import { join, sep } from "node:path";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import scanDraftDocument from "../../schemas/tools/scan-draft.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import type { RunArtifactWorkbench } from "./artifact-context.js";
import {
  artifactDestination,
  readArtifactJsonObject,
  readArtifactText,
  readArtifactTextWithMetadata,
  replaceArtifactText,
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";

type JsonObject = Record<string, unknown>;

export type ScanDraftInput = SemanticScan;
interface SavedScanDraft {
  input: ScanDraftInput;
  modifiedMs: number;
  head?: boolean;
  attempt?: string;
}

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
    resolvedDeferred(parsed.coverage).length > 0
  )
    throw new Error(
      "scan draft: terminal Deep drafts cannot resolve child deferred work.",
    );

  for (;;) {
    signal?.throwIfAborted();
    // Deep results replace findings and coverage while retaining an omitted model.
    // Do not merge older review work into them.
    const preserved =
      context.mode === "deep" && parsed.complete !== false
        ? {
            ...(await preserveDeepThreatModel(context, parsed)),
            checkpointIds: [],
          }
        : await preserveScanDraft(context, parsed);
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

/** Stage a parent draft, then publish it under the workbench completion lock. */
export async function recordCodexSecurityScanDraftViaWorkbench(
  context: ArtifactContext,
  input: ScanDraftInput,
  runWorkbench: RunArtifactWorkbench,
  signal?: AbortSignal,
): Promise<ScanDraftResult> {
  return recordCodexSecurityScanDraft(
    context,
    input,
    async (draft, expectedDigest, checkpoint, reconciledCheckpointIds) => {
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
          checkpoint,
          draft,
        );
        const warnings = isObject(result) ? result.warnings : undefined;
        return Array.isArray(warnings)
          ? warnings.filter(
              (warning): warning is string => typeof warning === "string",
            )
          : undefined;
      } catch (error) {
        if (!workbenchScanDraftConflict(error)) throw error;
        throw Object.assign(
          new Error(
            "The canonical scan draft changed while this checkpoint was being reconciled.",
          ),
          { code: "scan_draft_conflict" },
        );
      }
    },
    signal,
  );
}

async function preserveScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<{
  input: ScanDraftInput;
  previousDigest: string;
  checkpointIds: string[];
}> {
  const currentCheckpointName = scanDraftCheckpointName(input);
  input = structuredClone(input);
  input.coverage.deferred = normalizeDeferred(input.coverage.deferred);
  let result = structuredClone(input);
  const previousState = await readPreviousScanDraft(context);
  const previous = previousState.input;
  if (previous && previous.scanId !== input.scanId)
    throw new Error(
      "scan checkpoint: saved result belongs to a different scan.",
    );
  const current = await readCurrentCheckpoints(context, currentCheckpointName);
  const head = await readCheckpointHead(context, "current");
  const accepted =
    head === undefined
      ? undefined
      : parsePersistedScanDraft(
          await readArtifactJsonObject(
            context,
            ["checkpoints", head.checkpoint],
            "accepted scan checkpoint",
          ),
        );
  if (accepted !== undefined && accepted.scanId !== context.scanId)
    throw new Error(
      "scan checkpoint: accepted checkpoint belongs to a different scan.",
    );
  const savedSources: SavedScanDraft[] = [
    ...(accepted === undefined
      ? []
      : [{ input: accepted, modifiedMs: head!.modifiedMs, head: true }]),
    ...(previous
      ? [{ input: previous, modifiedMs: previousState.modifiedMs ?? 0 }]
      : []),
    ...current,
  ].sort(
    (left: SavedScanDraft, right: SavedScanDraft) =>
      right.modifiedMs - left.modifiedMs ||
      Number(right.head ?? false) - Number(left.head ?? false),
  );
  const sources = savedSources.map(({ input }) => input);
  // Older checkpoints can omit IDs already assigned in their published output.
  const savedDeferred = sources.flatMap(
    (source) => source.coverage.deferred as JsonObject[],
  );
  const savedSurfaces = sources.flatMap(
    (source) => source.coverage.surfaces as JsonObject[],
  );
  for (const source of sources) {
    const reservedSurfaceIds = new Set(
      (source.coverage.surfaces as JsonObject[]).flatMap((row) =>
        typeof row.id === "string" ? [row.id] : [],
      ),
    );
    const surfaces = (source.coverage.surfaces as JsonObject[]).map((row) => {
      if (typeof row.id === "string") return row;
      const matching = savedSurfaces.find(
        ({ id, ...content }) =>
          typeof id === "string" &&
          !reservedSurfaceIds.has(id) &&
          isDeepStrictEqual(
            { ...content, receiptRefs: content.receiptRefs ?? [] },
            { ...row, receiptRefs: row.receiptRefs ?? [] },
          ),
      );
      if (matching === undefined) return row;
      const id = matching.id as string;
      reservedSurfaceIds.add(id);
      return { ...row, id };
    });
    const normalizedSurfaces = normalizeSurfaces(
      surfaces as SemanticCoverage["surfaces"],
    );
    // Retain explicit duplicate IDs so closure checks can still detect ambiguity.
    source.coverage.surfaces = surfaces.map((row, index) =>
      typeof row.id === "string" ? row : normalizedSurfaces[index]!,
    ) as SemanticCoverage["surfaces"];
    const reservedIds = new Set(
      (source.coverage.deferred as JsonObject[]).flatMap((row) =>
        typeof row.id === "string" ? [row.id] : [],
      ),
    );
    source.coverage.deferred = normalizeDeferred(
      (source.coverage.deferred as SemanticCoverage["deferred"]).map((row) => {
        if (
          typeof row.id === "string" ||
          "candidateId" in row ||
          "candidate" in row ||
          "finding" in row
        )
          return row;
        const matching = savedDeferred.find(
          ({ id, ...content }) =>
            typeof id === "string" &&
            !reservedIds.has(id) &&
            isDeepStrictEqual(content, row),
        );
        if (matching === undefined) return row;
        const id = matching.id as string;
        reservedIds.add(id);
        return { ...row, id };
      }),
    );
  }
  const ambiguousDeferredIds = ambiguousGenericDeferredIds(sources);
  const keepsGenericWork = (row: JsonObject) =>
    ambiguousGenericEntry(row, ambiguousDeferredIds);
  const retainedFinal =
    input.complete === false
      ? savedSources.find(({ input }) => input.complete !== false)
      : undefined;
  if (retainedFinal) result = structuredClone(retainedFinal.input);
  const retainedScope = sources.find(
    (source) => source.scope !== undefined,
  )?.scope;
  if (result.scope === undefined && retainedScope !== undefined) {
    result.scope = retainedScope;
  }
  const retainedThreatModel = sources.find(
    (source) => source.threatModel !== undefined,
  )?.threatModel;
  if (result.threatModel === undefined && retainedThreatModel !== undefined) {
    result.threatModel = structuredClone(retainedThreatModel);
  }

  const reopenedSurfaces = new Set<JsonObject>();
  if (retainedFinal) {
    const terminalOutcomeIds = completedCandidateIds(retainedFinal.input);
    for (const surface of result.coverage.surfaces as JsonObject[]) {
      if (
        terminalOutcomeIds.has((surface.candidateId ?? surface.id) as string) &&
        typeof surface.id === "string"
      )
        terminalOutcomeIds.add(surface.id);
    }
    const closedIds = new Set(
      resolvedDeferred(result.coverage).map((row) => row.id as string),
    );
    const retainedIndex = savedSources.indexOf(retainedFinal);
    const progressSources = savedSources
      .filter(
        (source, index) =>
          source.input.complete === false &&
          (index < retainedIndex ||
            (source.attempt === retainedFinal.attempt &&
              source.modifiedMs === retainedFinal.modifiedMs)),
      )
      .map(({ input }) => input)
      .reverse();
    progressSources.push(input);
    let acceptProgress = coverageHasOutstandingWork(result.coverage);
    for (const observation of progressSources) {
      const progress = structuredClone(observation);
      const reopenedIds = new Set(
        (progress.coverage.deferred as JsonObject[]).flatMap((row) =>
          [row.id, row.candidateId].filter(
            (id): id is string => typeof id === "string" && closedIds.has(id),
          ),
        ),
      );
      if (reopenedIds.size > 0) acceptProgress = true;
      if (!acceptProgress) continue;
      result.complete = false;
      const resolved = reconcileDeferredSurfaces(
        progress.coverage,
        sources,
        reopenedIds,
        new Set(),
        ambiguousGenericDeferredIds(sources),
        [],
      );
      for (const surface of resolved) reopenedSurfaces.add(surface);
      result.coverage = preserveScanCoverage(
        {
          ...result.coverage,
          deferred: progress.coverage.deferred.filter(
            (row) =>
              ambiguousGenericEntry(
                row,
                ambiguousGenericDeferredIds(sources),
              ) ||
              !terminalOutcomeIds.has((row.candidateId ?? row.id) as string),
          ),
          surfaces: progress.coverage.surfaces.filter(
            (surface) =>
              ambiguousGenericEntry(
                surface,
                ambiguousGenericDeferredIds(sources),
              ) ||
              (!terminalOutcomeIds.has(surface.id as string) &&
                !terminalOutcomeIds.has(surface.candidateId as string)),
          ),
        },
        result.coverage,
        ambiguousGenericDeferredIds(sources),
      );
      sources.unshift(progress);
    }
  }
  const currentCandidateIds = completedCandidateIds(result);
  const resolvedCandidateIds = completedCandidateIds(result, sources);
  const { closedDeferredIds, resolvedSurfaces: resolvedGenericSurfaces } =
    reconcileResolvedDeferred(
      result,
      resolvedDeferred(input.coverage),
      sources,
      savedSources,
      resolvedCandidateIds,
      ambiguousDeferredIds,
      retainedFinal?.input,
    );
  for (const surface of reopenedSurfaces) resolvedGenericSurfaces.add(surface);
  const resolvedFollowUpSurfaces = sources.flatMap((source) => {
    const pending = source.coverage.deferred;
    if (
      pending.length === 0 ||
      pending.some((item) => {
        const candidateId = item.candidateId ?? item.id;
        return (
          keepsGenericWork(item) ||
          typeof candidateId !== "string" ||
          !currentCandidateIds.has(candidateId)
        );
      })
    )
      return [];
    return source.coverage.surfaces.filter(
      (surface) => surface.disposition === "needs_follow_up",
    );
  });

  for (const source of sources) {
    const deferred = result.coverage.deferred;
    const dispositions = result.coverage.surfaces.filter(
      (surface) =>
        (surface.disposition === "rejected" ||
          surface.disposition === "not_applicable") &&
        typeof surface.candidateId === "string",
    );
    const candidateRows = [...deferred, ...dispositions];
    for (const pending of source.coverage.deferred) {
      const candidateId = pending.candidateId ?? pending.id;
      if (typeof candidateId !== "string") continue;
      const finding = result.findings.find(
        (item) => findingCandidateId(item) === candidateId,
      );
      if (finding) {
        const provenance = finding.provenance;
        if (pending.candidate !== undefined)
          provenance.originalCandidates = exactUnion(
            Array.isArray(provenance.originalCandidates)
              ? provenance.originalCandidates
              : [],
            [pending.candidate],
          );
        if (isObject(pending.finding))
          preserveFindingDetails(finding, pending.finding);
      } else {
        const candidateRow = candidateRows.find(
          (item) =>
            !keepsGenericWork(item) &&
            (item.candidateId === candidateId || item.id === candidateId),
        );
        if (candidateRow) {
          for (const field of ["candidate", "finding"] as const) {
            if (pending[field] !== undefined)
              candidateRow[field] ??= structuredClone(pending[field]);
          }
        }
      }
    }
    for (const finding of source.findings) {
      const candidateId = findingCandidateId(finding);
      const disposition =
        candidateId === undefined
          ? undefined
          : dispositions.find(
              (item) =>
                item.candidateId === candidateId || item.id === candidateId,
            );
      if (disposition) {
        disposition.finding ??= structuredClone(finding);
        continue;
      }
      const matches = result.findings.filter((current) =>
        sameSavedFinding(current, finding),
      );
      if (
        matches.length === 1 &&
        source.findings.filter((current) => sameSavedFinding(current, finding))
          .length === 1
      ) {
        preserveFindingDetails(matches[0]!, finding);
      } else {
        if (!matches.some((current) => containsSavedFinding(current, finding)))
          result.findings.push(structuredClone(finding));
      }
    }
    const resolvedIds = new Set(
      [
        ...result.findings.map(findingCandidateId),
        ...candidateRows
          .filter((item) => !keepsGenericWork(item))
          .map((item) => item.candidateId ?? item.id),
      ].filter((value): value is string => typeof value === "string"),
    );
    const previousCoverage = {
      ...source.coverage,
      deferred: source.coverage.deferred.filter((item) => {
        const candidateId = item.candidateId ?? item.id;
        return (
          (keepsGenericWork(item) ||
            typeof candidateId !== "string" ||
            !resolvedIds.has(candidateId)) &&
          !closedDeferredIds.has(item.id as string)
        );
      }),
      surfaces: source.coverage.surfaces.filter((surface) => {
        if (resolvedGenericSurfaces.has(surface)) return false;
        const candidateId = surface.candidateId ?? surface.id;
        return (
          (keepsGenericWork(surface) ||
            typeof candidateId !== "string" ||
            !resolvedIds.has(candidateId)) &&
          !coverageEntryPresent(
            result.coverage.surfaces,
            surface,
            ambiguousDeferredIds,
          ) &&
          !(
            surface.disposition === "needs_follow_up" &&
            coverageEntryPresent(resolvedFollowUpSurfaces, surface)
          )
        );
      }),
      openQuestions:
        result.complete === false
          ? (source.coverage.openQuestions ?? []).filter(
              (question) =>
                !coverageEntryPresent(
                  result.coverage.openQuestions ?? [],
                  question,
                ),
            )
          : [],
    };
    result.coverage.surfaces = exactUnion(
      result.coverage.surfaces,
      previousCoverage.surfaces,
    );
    result.coverage = preserveScanCoverage(
      result.coverage,
      previousCoverage,
      ambiguousDeferredIds,
    );
  }
  result.coverage.deferred = normalizeDeferred(result.coverage.deferred);
  result.coverage.surfaces = normalizeSurfaces(result.coverage.surfaces);
  return {
    input: result,
    previousDigest: previousState.digest,
    // Keep ambiguous source evidence pending while its independent generic task remains.
    checkpointIds: current
      .filter(
        ({ input }) =>
          !input.coverage.deferred.some(
            (row) =>
              ambiguousGenericEntry(row, ambiguousDeferredIds) &&
              result.coverage.deferred.some((saved) =>
                isDeepStrictEqual(saved, row),
              ),
          ),
      )
      .map(({ name }) => name),
  };
}

async function readCurrentCheckpoints(
  context: ArtifactContext,
  excludedCheckpoint: string,
): Promise<Array<{ name: string; input: ScanDraftInput; modifiedMs: number }>> {
  const root = join(context.root, "checkpoints", "pending");
  const metadata = await lstatIfExists(root);
  if (metadata === undefined) return [];
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    throw new Error(
      "scan checkpoint: current checkpoint set is not a safe directory.",
    );
  }
  const [canonicalRoot, canonicalCheckpointRoot] = await Promise.all([
    fs.realpath(context.root),
    fs.realpath(root),
  ]);
  if (!canonicalCheckpointRoot.startsWith(canonicalRoot + sep)) {
    throw new Error(
      "scan checkpoint: current checkpoint set escaped its artifact directory.",
    );
  }
  const checkpoints: Array<{
    name: string;
    input: ScanDraftInput;
    modifiedMs: number;
  }> = [];
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    if (!entry.name.endsWith(".json") || entry.name === excludedCheckpoint)
      continue;
    // Markers precede history writes and can be acknowledged while we read.
    let observation = await readOptionalArtifactTextWithMetadata(
      context,
      ["checkpoints", entry.name],
      "current scan checkpoint",
    );
    if (observation === undefined) {
      const stagedPath = await readOptionalArtifactText(
        context,
        ["checkpoints", "pending", entry.name],
        "current scan checkpoint marker",
      );
      if (stagedPath) {
        if (!/^drafts\/[0-9a-fA-F-]+\.checkpoint\.json$/u.test(stagedPath))
          throw new Error("scan checkpoint: invalid staged checkpoint path.");
        observation = await readOptionalArtifactTextWithMetadata(
          context,
          stagedPath.split("/"),
          "staged scan checkpoint",
        );
        if (
          observation !== undefined &&
          createHash("sha256").update(observation.contents).digest("hex") +
            ".json" !==
            entry.name
        )
          throw new Error("scan checkpoint: staged checkpoint digest changed.");
      }
    }
    if (observation === undefined) continue;
    const input = parsePersistedScanDraft(
      parseJsonObject(observation.contents, "current scan checkpoint"),
    );
    if (input.scanId !== context.scanId)
      throw new Error(
        "scan checkpoint: current checkpoint belongs to a different scan.",
      );
    const modifiedMs = observation.modifiedMs;
    checkpoints.push({ name: entry.name, input, modifiedMs });
  }
  return checkpoints;
}

function scanDraftCheckpointName(input: ScanDraftInput): string {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  return (
    createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") +
    ".json"
  );
}

async function readPreviousScanDraft(
  context: ArtifactContext,
): Promise<{ input?: ScanDraftInput; digest: string; modifiedMs?: number }> {
  const names = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
  ] as const;
  const contents = await Promise.all(
    names.map((name) => readOptionalArtifactText(context, [name])),
  );
  const digest = draftDigest(
    names.map((name, index) => [name, contents[index]]),
  );
  if (contents.every((value) => value === undefined)) return { digest };
  if (contents.some((value) => value === undefined)) {
    throw new Error("previous scan draft: canonical documents are incomplete.");
  }
  const manifest = parseJsonObject(
    contents[0]!,
    "previous scan draft manifest",
  );
  const findings = parseJsonObject(
    contents[1]!,
    "previous scan draft findings",
  );
  const coverage = parseJsonObject(
    contents[2]!,
    "previous scan draft coverage",
  );
  const scan = requireObject(manifest.scan, "previous scan draft.scan");
  return {
    digest,
    modifiedMs: (
      await readArtifactTextWithMetadata(
        context,
        ["coverage.json"],
        "previous scan draft",
      )
    ).modifiedMs,
    input: parsePersistedScanDraft(
      semanticScanDraft(
        context.scanId!,
        scan,
        findings.findings as JsonObject[],
        coverage,
      ) as unknown as JsonObject,
    ),
  };
}

async function lstatIfExists(
  path: string,
): Promise<Awaited<ReturnType<typeof fs.lstat>> | undefined> {
  try {
    return await fs.lstat(path);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function readOptionalArtifactText(
  context: ArtifactContext,
  components: readonly string[],
  label = "previous scan draft",
): Promise<string | undefined> {
  try {
    return await readArtifactText(context, components, label);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === `${label}: the requested artifact is unavailable.`
    ) {
      return undefined;
    }
    throw error;
  }
}

async function readOptionalArtifactTextWithMetadata(
  context: ArtifactContext,
  components: readonly string[],
  label = "previous scan draft",
): Promise<{ contents: string; modifiedMs: number } | undefined> {
  try {
    return await readArtifactTextWithMetadata(context, components, label);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === `${label}: the requested artifact is unavailable.`
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

function sameSavedFinding(left: JsonObject, right: JsonObject): boolean {
  if (left.ruleId !== right.ruleId) return false;
  if (left.identity && right.identity)
    return scanFindingIdentity(left) === scanFindingIdentity(right);
  const leftCandidate = findingCandidateId(left);
  if (leftCandidate && leftCandidate === findingCandidateId(right)) return true;
  return (
    scanFindingIdentity({ ...left, identity: undefined }) ===
    scanFindingIdentity({ ...right, identity: undefined })
  );
}

function coverageEntryPresent(
  entries: unknown[],
  previous: unknown,
  ambiguousIds = new Set<string>(),
): boolean {
  return entries.some((entry) => {
    const current =
      typeof entry === "string" ? { question: entry.trim() } : entry;
    const original =
      typeof previous === "string"
        ? { question: previous.trim() }
        : structuredClone(previous);
    if (isObject(current) && isObject(original)) {
      if (
        ambiguousGenericEntry(current, ambiguousIds) ||
        ambiguousGenericEntry(original, ambiguousIds)
      )
        return isDeepStrictEqual(current, original);
      const currentIdentities = coverageEntryIdentities(current);
      if (
        coverageEntryIdentities(original).some((identity) =>
          currentIdentities.includes(identity),
        )
      ) {
        return true;
      }
      if (
        current.receiptRefs === undefined &&
        Array.isArray(original.receiptRefs) &&
        original.receiptRefs.length === 0
      )
        delete original.receiptRefs;
    }
    return containsSavedValue(current, original);
  });
}

function coverageEntryIdentities(entry: JsonObject): string[] {
  const stable: string[] = [];
  for (const field of ["id", "candidateId"] as const) {
    const value = entry[field];
    if (typeof value === "string" && value.trim())
      stable.push(`stable:${value}`);
  }
  return stable;
}

/** Explicit, unambiguous resolution closes historical work; omission does not. */

function preserveScanCoverage(
  coverage: SemanticCoverage,
  source: SemanticCoverage,
  ambiguousDeferredIds = new Set<string>(),
): SemanticCoverage {
  const result = structuredClone(coverage);
  const retain = <Entry>(
    values: Entry[],
    previous: Entry[],
    deferred = false,
  ): Entry[] => {
    const present = deferred ? deferredEntryPresent : coverageEntryPresent;
    for (const value of previous)
      if (!present(values, value, ambiguousDeferredIds))
        values.push(structuredClone(value));
    return values;
  };
  result.surfaces = retain(result.surfaces, source.surfaces);
  result.explicitExclusions = retain(
    result.explicitExclusions,
    source.explicitExclusions,
  );
  result.deferred = retain(result.deferred, source.deferred, true);
  const questions = retain(
    result.openQuestions ?? [],
    source.openQuestions ?? [],
  );
  if (questions.length > 0 || result.openQuestions !== undefined)
    result.openQuestions = questions;
  if (coverageHasOutstandingWork(result)) result.completeness = "partial";
  return result;
}

function coverageHasOutstandingWork(coverage: SemanticCoverage): boolean {
  return (
    coverage.deferred.length > 0 ||
    coverage.surfaces.some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  );
}

function findingCandidateId(finding: JsonObject): string | undefined {
  const provenance = finding.provenance;
  if (
    isObject(provenance) &&
    typeof provenance.candidateId === "string" &&
    provenance.candidateId.trim()
  ) {
    return provenance.candidateId;
  }
  const extensions = finding.extensions;
  if (isObject(extensions)) {
    for (const field of ["candidateId", "reportId", "ledgerRowId"] as const) {
      const value = extensions[field];
      if (typeof value === "string" && value.trim()) return value;
    }
  }
  return undefined;
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

export function parseScanDraft(input: unknown): ScanDraftInput {
  const parsed = parseScanDraftDocument(input);
  const deferredIds = new Set<string>();
  const ambiguousIds = ambiguousGenericDeferredIds([parsed]);
  for (const row of parsed.coverage.deferred) {
    if (typeof row.id !== "string") continue;
    if (deferredIds.has(row.id) || ambiguousIds.has(row.id))
      throw new Error(`scan draft: coverage.deferred repeats ${row.id}.`);
    deferredIds.add(row.id);
  }
  if (parsed.complete === false && resolvedDeferred(parsed.coverage).length > 0)
    throw new Error(
      "scan draft: coverage.resolvedDeferred is allowed only on a terminal draft.",
    );
  parsed.coverage.deferred = normalizeDeferred(parsed.coverage.deferred);
  parsed.coverage.surfaces = normalizeSurfaces(parsed.coverage.surfaces);
  return parsed;
}

function parseScanDraftDocument(input: unknown): ScanDraftInput {
  const parsed = scanDraftInputSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  validateCoverageSemantics(parsed.coverage);
  return parsed;
}

/** Project current canonical metadata without coercing persisted finding details. */
function parsePersistedScanDraft(
  input: Record<string, unknown>,
): ScanDraftInput {
  try {
    const projected = semanticScanDraft(
      input.scanId as string,
      input,
      input.findings as JsonObject[],
      requireObject(input.coverage, "saved scan draft coverage"),
    );
    return parseScanDraftDocument({
      ...input,
      ...(isObject(input.scope) ? { scope: projected.scope } : {}),
      findings: projected.findings,
      coverage: projected.coverage,
    });
  } catch (cause) {
    throw new Error(
      "Saved scan draft does not match the current schema. Start a new scan; the saved artifacts remain available.",
      { cause },
    );
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

function resolvedDeferred(coverage: JsonObject): JsonObject[] {
  return (coverage.resolvedDeferred as JsonObject[] | undefined) ?? [];
}

function genericDeferred(row: JsonObject): boolean {
  return (
    typeof row.candidateId !== "string" &&
    !("candidate" in row) &&
    !("finding" in row)
  );
}

function ambiguousGenericEntry(
  row: JsonObject,
  identities: Set<string>,
): boolean {
  return (
    typeof row.id === "string" && identities.has(row.id) && genericDeferred(row)
  );
}

function ambiguousGenericDeferredIds(sources: ScanDraftInput[]): Set<string> {
  const ambiguous = new Set<string>();
  for (const source of sources) {
    const rows = source.coverage.deferred as JsonObject[];
    const candidateIds = new Set(
      rows
        .filter((row) => !genericDeferred(row))
        .flatMap((row) =>
          [row.id, row.candidateId].filter(
            (id): id is string => typeof id === "string",
          ),
        ),
    );
    const byId = new Map<string, JsonObject>();
    for (const row of rows) {
      if (typeof row.id !== "string" || !genericDeferred(row)) continue;
      const previous = byId.get(row.id);
      if (
        candidateIds.has(row.id) ||
        (previous !== undefined && !isDeepStrictEqual(previous, row))
      )
        ambiguous.add(row.id);
      byId.set(row.id, row);
    }
  }
  return ambiguous;
}

function reconcileResolvedDeferred(
  result: ScanDraftInput,
  requestedClosures: JsonObject[],
  sources: ScanDraftInput[],
  savedSources: SavedScanDraft[],
  resolvedCandidateIds: Set<string>,
  ambiguousIds: Set<string>,
  retainedFinal?: ScanDraftInput,
): { closedDeferredIds: Set<string>; resolvedSurfaces: Set<JsonObject> } {
  const activeDeferred = result.coverage.deferred as JsonObject[];
  // Legacy aliases cannot identify which independent task was completed.
  // Keep generic work separate from candidate outcomes and ambiguous closures.
  for (const source of sources) {
    for (const row of source.coverage.deferred as JsonObject[]) {
      if (
        ambiguousGenericEntry(row, ambiguousIds) &&
        !activeDeferred.some((current) => isDeepStrictEqual(current, row))
      )
        activeDeferred.push(structuredClone(row));
    }
  }
  const observedIds = new Set(
    activeDeferred.flatMap((row) =>
      [row.id, row.candidateId].filter(
        (id): id is string => typeof id === "string",
      ),
    ),
  );
  // Equal timestamps cannot prove that a closure followed pending work.
  const pendingByTime = new Map<string, Set<string>>();
  const tiedPending = new Map<ScanDraftInput, Set<string>>();
  for (const source of savedSources) {
    const key = JSON.stringify([source.attempt, source.modifiedMs]);
    const pending = pendingByTime.get(key) ?? new Set<string>();
    for (const row of source.input.coverage.deferred as JsonObject[]) {
      pending.add(row.id as string);
      if (typeof row.candidateId === "string") pending.add(row.candidateId);
    }
    pendingByTime.set(key, pending);
    tiedPending.set(source.input, pending);
  }
  const historical = sources.flatMap(
    (source) => source.coverage.deferred as JsonObject[],
  );
  const candidateRows = historical.filter((row) => !genericDeferred(row));
  const candidateIds = new Set(
    candidateRows.flatMap((row) =>
      [row.id, row.candidateId].filter(
        (id): id is string => typeof id === "string",
      ),
    ),
  );
  const closures = new Map<string, JsonObject>();
  const previouslyClosed = new Set<string>();
  const closureSources = new Map<string, ScanDraftInput>();
  for (const source of sources) {
    // Keep the first saved state for each ID so reopened work stays pending.
    for (const row of source.coverage.deferred as JsonObject[]) {
      observedIds.add(row.id as string);
      if (typeof row.candidateId === "string") observedIds.add(row.candidateId);
    }
    if (
      source.complete === false &&
      !savedSources.some((saved) => saved.input === source && saved.head)
    )
      continue;
    for (const closure of resolvedDeferred(source.coverage)) {
      const id = closure.id as string;
      previouslyClosed.add(id);
      if (
        !candidateIds.has(id) &&
        !observedIds.has(id) &&
        !tiedPending.get(source)?.has(id)
      ) {
        closures.set(id, closure);
        closureSources.set(id, source);
      }
      observedIds.add(id);
    }
  }
  const requested = new Set<string>();
  for (const closure of requestedClosures) {
    const id = closure.id as string;
    if (requested.has(id))
      throw new Error(`scan draft: coverage.resolvedDeferred repeats ${id}.`);
    requested.add(id);
    closures.set(id, closure);
  }
  for (const id of closures.keys()) {
    if (ambiguousIds.has(id))
      throw new Error(
        `scan draft: coverage.resolvedDeferred cannot close ambiguous saved deferred work: ${id}.`,
      );
    if (candidateIds.has(id)) {
      if (
        candidateRows
          .filter((row) => row.id === id || row.candidateId === id)
          .every((row) =>
            resolvedCandidateIds.has((row.candidateId ?? row.id) as string),
          )
      ) {
        // The ordinary candidate outcome resolves this work; keep closures generic-only.
        closures.delete(id);
        continue;
      }
      throw new Error(
        `scan draft: coverage.resolvedDeferred cannot close candidate ${id}; record its finding or disposition.`,
      );
    }
    if (
      !closureSources.has(id) &&
      !historical.some((row) => row.id === id || row.candidateId === id)
    )
      throw new Error(
        `scan draft: coverage.resolvedDeferred names no saved generic deferral: ${id}.`,
      );
    if (activeDeferred.some((row) => row.id === id || row.candidateId === id))
      throw new Error(
        `scan draft: resolved deferred work is still active: ${id}.`,
      );
  }
  if (closures.size > 0) {
    result.coverage.resolvedDeferred = [...closures.values()].map(
      (closure) => structuredClone(closure) as { id: string; reason: string },
    );
  } else {
    delete result.coverage.resolvedDeferred;
  }
  const closedDeferredIds = new Set(closures.keys());
  const reopenedIds = new Set(
    [...activeDeferred, ...historical]
      .map((row) => row.id as string)
      .filter(
        (id) =>
          previouslyClosed.has(id) &&
          !closedDeferredIds.has(id) &&
          !candidateIds.has(id),
      ),
  );
  const inherited = [
    ...new Set([
      ...closureSources.values(),
      ...sources.filter((source) =>
        (source.coverage.deferred as JsonObject[]).some((row) =>
          reopenedIds.has(row.id as string),
        ),
      ),
    ]),
  ];
  const resolvedSurfaces = reconcileDeferredSurfaces(
    result.coverage,
    sources,
    closedDeferredIds,
    resolvedCandidateIds,
    ambiguousIds,
    inherited,
    savedSources,
    retainedFinal,
    reopenedIds,
  );
  return { closedDeferredIds, resolvedSurfaces };
}

function reconcileDeferredSurfaces(
  coverage: JsonObject,
  sources: ScanDraftInput[],
  closedDeferredIds: Set<string>,
  resolvedCandidateIds: Set<string>,
  ambiguousDeferredIds: Set<string>,
  inherited: ScanDraftInput[],
  savedSources: SavedScanDraft[] = [],
  retainedFinal?: ScanDraftInput,
  reopenedIds: Set<string> = new Set(),
): Set<JsonObject> {
  const resolved = new Set<JsonObject>();
  const workIds = new Set([...closedDeferredIds, ...reopenedIds]);
  if (workIds.size === 0) return resolved;
  const current = coverage.surfaces as JsonObject[];
  const inheritedSurfaces = inherited.flatMap((source) =>
    (source.coverage.surfaces as JsonObject[]).map((surface) => ({
      surface,
      source,
    })),
  );
  const observations = new Map(
    savedSources.map((source) => [source.input, source]),
  );
  const carriesCandidate = (surface: JsonObject) =>
    "candidateId" in surface || "candidate" in surface || "finding" in surface;
  const latestDeferred = [...(coverage.deferred as JsonObject[])];
  for (const source of sources) {
    for (const row of source.coverage.deferred as JsonObject[]) {
      if (!deferredEntryPresent(latestDeferred, row, ambiguousDeferredIds))
        latestDeferred.push(row);
    }
  }
  const pending = latestDeferred.filter(
    (row) =>
      !closedDeferredIds.has(row.id as string) &&
      (ambiguousGenericEntry(row, ambiguousDeferredIds) ||
        !resolvedCandidateIds.has((row.candidateId ?? row.id) as string)),
  );
  for (const { surface: original, source: inheritedSource } of [
    ...current.map((surface) => ({
      surface,
      source: retainedFinal,
    })),
    ...inheritedSurfaces,
  ]) {
    const saved = !current.includes(original);
    let surface = saved ? structuredClone(original) : original;
    if (typeof surface.id !== "string" || carriesCandidate(surface)) continue;
    const id = surface.id;
    const sameSurface = (other: JsonObject) => other.id === id;
    const currentMatches = current.filter(sameSurface);
    if (saved ? currentMatches.length > 0 : currentMatches.length !== 1)
      continue;
    const matches = sources.map((source) => ({
      source,
      surfaces: (source.coverage.surfaces as JsonObject[]).filter(sameSurface),
      deferred: source.coverage.deferred as JsonObject[],
    }));
    if (
      matches.some(
        ({ surfaces }) =>
          surfaces.length > 1 || surfaces.some(carriesCandidate),
      )
    )
      continue;
    if (inheritedSource) {
      const latest = matches.find(({ surfaces }) => surfaces.length > 0)!;
      const latestObservation = observations.get(latest.source);
      const pendingAtSameTime =
        latestObservation &&
        matches.find(({ source, surfaces }) => {
          const observation = observations.get(source);
          return (
            observation?.attempt === latestObservation.attempt &&
            observation?.modifiedMs === latestObservation.modifiedMs &&
            surfaces[0]?.disposition === "needs_follow_up"
          );
        });
      surface = structuredClone((pendingAtSameTime ?? latest).surfaces[0]!);
    }
    const previousSurfaces = matches.flatMap(({ surfaces }) => surfaces);
    if (
      surface.disposition !== "needs_follow_up" &&
      pending.some(
        (row) =>
          row.id === id ||
          ((row.surfaceIds as string[] | undefined) ?? []).includes(id),
      )
    ) {
      const followUp = previousSurfaces.find(
        (row) => row.disposition === "needs_follow_up",
      );
      if (!followUp) continue;
      surface = {
        ...structuredClone(followUp),
        receiptRefs: surface.receiptRefs,
      };
    }
    const linked =
      pending.some(
        (row) =>
          row.id === id ||
          ((row.surfaceIds as string[] | undefined) ?? []).includes(id),
      ) ||
      matches.some(
        ({ surfaces, deferred }) =>
          surfaces.length > 0 &&
          deferred.some(
            (row) =>
              workIds.has(row.id as string) &&
              (row.id === id ||
                ((row.surfaceIds as string[] | undefined) ?? []).includes(id)),
          ),
      );
    if (!linked) continue;
    surface.receiptRefs = exactUnion(
      (surface.receiptRefs as unknown[] | undefined) ?? [],
      previousSurfaces.flatMap(
        (row) => (row.receiptRefs as unknown[] | undefined) ?? [],
      ),
    );
    if (saved) current.push(surface);
    else current[current.indexOf(original)] = surface;
    for (const previous of previousSurfaces) {
      if (
        surface.disposition === "needs_follow_up" ||
        previous.disposition === "needs_follow_up"
      )
        resolved.add(previous);
    }
  }
  return resolved;
}

function deferredEntryPresent(
  entries: unknown[],
  previous: unknown,
  ambiguousIds = new Set<string>(),
): boolean {
  return entries.some(
    (current) =>
      isDeepStrictEqual(current, previous) ||
      (isObject(current) &&
        isObject(previous) &&
        !ambiguousGenericEntry(current, ambiguousIds) &&
        !ambiguousGenericEntry(previous, ambiguousIds) &&
        [previous.id, previous.candidateId].some(
          (id) =>
            typeof id === "string" &&
            (current.id === id || current.candidateId === id),
        )),
  );
}

function completedCandidateIds(
  result: ScanDraftInput,
  sources: ScanDraftInput[] = [],
): Set<string> {
  const completed = new Set<string>();
  const observed = new Set<string>();
  for (const source of [result, ...sources]) {
    for (const finding of source.findings) {
      const id = findingCandidateId(finding);
      if (id !== undefined) completed.add(id);
    }
    const dispositions = (source.coverage.surfaces as JsonObject[]).filter(
      (surface) =>
        surface.disposition === "rejected" ||
        surface.disposition === "not_applicable",
    );
    for (const surface of dispositions) {
      const id = surface.candidateId;
      if (typeof id === "string" && !observed.has(id)) completed.add(id);
    }
    for (const row of [
      ...(source.coverage.deferred as JsonObject[]),
      ...dispositions,
    ]) {
      const id = row.candidateId ?? row.id;
      if (typeof id === "string") observed.add(id);
    }
  }
  return completed;
}

async function preserveDeepThreatModel(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<{ input: ScanDraftInput; previousDigest?: string }> {
  if (input.threatModel !== undefined) return { input };
  const { contents, digest } = await readPreviousScanDocuments(context);
  const previous =
    contents[0] === undefined
      ? undefined
      : requireObject(
          parseJsonObject(contents[0], "previous scan draft manifest").scan,
          "previous scan draft.scan",
        );
  return {
    input:
      previous?.threatModel === undefined
        ? input
        : scanDraftInputSchema.parse({
            ...input,
            threatModel: previous.threatModel,
          }),
    previousDigest: digest,
  };
}
async function readPreviousScanDocuments(context: ArtifactContext) {
  const names = [
    "scan-manifest.json",
    "findings.json",
    "coverage.json",
  ] as const;
  const saved = await Promise.all(
    names.map((name) => readOptionalArtifactTextWithMetadata(context, [name])),
  );
  const contents = saved.map((record) => record?.contents);
  return {
    saved,
    contents,
    digest: draftDigest(names.map((name, index) => [name, contents[index]])),
  };
}

async function readCheckpointHead(
  context: ArtifactContext,
  kind: "current" | "archived",
): Promise<{ checkpoint: string; modifiedMs: number } | undefined> {
  const metadata = await lstatIfExists(
    join(context.root, "checkpoint-head.json"),
  );
  if (metadata === undefined) return;
  if (metadata.isSymbolicLink() || !metadata.isFile())
    throw new Error(
      `scan checkpoint: ${kind} checkpoint head is not a safe file.`,
    );
  const label = `${kind} scan checkpoint head`;
  const saved = await readArtifactTextWithMetadata(
    context,
    ["checkpoint-head.json"],
    label,
  );
  const head = parseJsonObject(saved.contents, label);
  if (
    typeof head.checkpoint !== "string" ||
    !/^[a-f0-9]{64}\.json$/u.test(head.checkpoint)
  )
    throw new Error(`scan checkpoint: ${kind} checkpoint head is invalid.`);
  // Reselecting an immutable checkpoint updates only the head file.
  return { checkpoint: head.checkpoint, modifiedMs: saved.modifiedMs };
}
