import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import scanDraftDocument from "../../schemas/tools/scan-draft.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import type { RunArtifactWorkbench } from "./artifact-context.js";
import {
  artifactDestination,
  readArtifactJsonObject,
  readArtifactText,
  replaceArtifactJson,
} from "./artifact-io.js";
import {
  loadArtifactZodSchema,
  type SchemaDocument,
} from "./artifact-schema-loader.js";

type JsonObject = Record<string, unknown>;

export interface ScanDraftInput {
  scanId: string;
  complete?: boolean;
  handoffClaimToken?: string;
  scope?: JsonObject;
  threatModel?: JsonObject;
  findings: JsonObject[];
  coverage: JsonObject;
}

export interface CompletedScanInput {
  scanId: string;
  handoffClaimToken?: string;
}

export interface ScanDraftResult {
  scanId: string;
  findingCount: number;
  surfaceCount: number;
  coverage: JsonObject;
  operation: "replace";
  status: "draft_written";
}

export interface CompletedScanResult {
  scanId: string;
  manifest: JsonObject;
  findings: JsonObject;
  coverage: JsonObject;
}

interface PreparedScanDraft {
  manifest: JsonObject;
  findings: JsonObject;
  coverage: JsonObject;
}

interface SavedScanDraft {
  input: ScanDraftInput;
  modifiedMs: number;
  head?: boolean;
  attempt?: string;
}

type PublishScanDraft = (
  draft: PreparedScanDraft,
  expectedDigest: string | undefined,
  checkpoint: ScanDraftInput,
) => Promise<void>;

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
  publishDraft?: PublishScanDraft,
  signal?: AbortSignal,
): Promise<ScanDraftResult> {
  const parsed = parseScanDraft(input);
  requireBoundScan(context, parsed, true);
  const finalDeepDraft = context.mode === "deep" && parsed.complete !== false;
  if (finalDeepDraft && resolvedDeferred(parsed.coverage).length > 0) {
    throw new Error(
      "scan draft: terminal Deep drafts cannot resolve child deferred work.",
    );
  }
  if (finalDeepDraft && !publishDraft)
    await saveScanDraftCheckpoint(context, parsed);

  for (;;) {
    signal?.throwIfAborted();
    // Deep results are ready to save. Do not merge older drafts or
    // checkpoints into them.
    const preserved = finalDeepDraft
      ? { input: parsed, previousDigest: undefined }
      : await preserveScanDraft(context, parsed, !publishDraft);
    const reconciled = preserved.input;
    const contract = requireObject(
      context.targetContract,
      "scan draft: authoritative target contract",
    );
    const trustedTarget = requireObject(
      contract.target,
      "scan draft: authoritative target",
    );
    const trustedScope = requireObject(
      contract.scope,
      "scan draft: authoritative scope",
    );
    const target = buildTarget(context, contract, trustedTarget);
    const scope = buildScope(context, trustedScope, reconciled.scope);
    const findings = buildFindings(reconciled.findings, context.mode);
    const coverage = buildCoverage(
      context,
      contract,
      reconciled.coverage,
      scope,
      target,
    );
    const hardening = await readExistingHardeningPortfolio(context);
    const manifestScan: JsonObject = {
      ...(reconciled.complete === false ? { complete: false } : {}),
      target,
      scope,
      ...(reconciled.threatModel === undefined
        ? {}
        : { threatModel: reconciled.threatModel }),
      ...(hardening === undefined ? {} : { hardening }),
    };

    try {
      const draft = {
        findings: { findings },
        coverage,
        manifest: { scan: manifestScan },
      };
      if (publishDraft) {
        await publishDraft(draft, preserved.previousDigest, parsed);
      } else {
        const destinations = await Promise.all([
          artifactDestination(
            context,
            ["findings.json"],
            "scan draft findings",
          ),
          artifactDestination(
            context,
            ["coverage.json"],
            "scan draft coverage",
          ),
          artifactDestination(
            context,
            ["scan-manifest.json"],
            "scan draft manifest",
          ),
        ]);
        await replaceArtifactJson(destinations[0], { findings });
        await replaceArtifactJson(destinations[1], coverage);
        await replaceArtifactJson(destinations[2], { scan: manifestScan });
      }
      return {
        scanId: reconciled.scanId,
        findingCount: findings.length,
        surfaceCount: (coverage.surfaces as unknown[]).length,
        coverage,
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
    async (draft, expectedDigest, checkpoint) => {
      const checkpointPath = await artifactDestination(
        context,
        ["drafts", `${randomUUID()}.checkpoint.json`],
        "staged scan checkpoint",
      );
      const draftPath = await artifactDestination(
        context,
        ["drafts", `${randomUUID()}.json`],
        "staged scan draft",
      );
      try {
        const { handoffClaimToken: _claim, ...snapshot } = checkpoint;
        await Promise.all([
          replaceArtifactJson(checkpointPath, snapshot),
          replaceArtifactJson(draftPath, draft),
        ]);
        const arguments_ = [
          "write-scan-draft",
          "--scan-id",
          input.scanId,
          "--draft-path",
          draftPath,
          "--checkpoint-path",
          checkpointPath,
        ];
        if (expectedDigest !== undefined) {
          arguments_.push("--expected-draft-digest", expectedDigest);
        }
        if (context.handoffClaimToken) {
          arguments_.push("--claim-token", context.handoffClaimToken);
        }
        try {
          await runWorkbench(arguments_);
        } catch (error) {
          if (!workbenchScanDraftConflict(error)) throw error;
          throw Object.assign(
            new Error(
              "The canonical scan draft changed while this checkpoint was being reconciled.",
            ),
            { code: "scan_draft_conflict" },
          );
        }
      } finally {
        await Promise.all([
          fs.rm(checkpointPath, { force: true }),
          fs.rm(draftPath, { force: true }),
        ]);
      }
    },
    signal,
  );
}

/** Save a Standard worker draft in its assigned output directory. */
export async function recordCodexSecurityWorkerScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<ScanDraftResult> {
  const parsed = parseScanDraft(input);
  if (context.layout !== "worker") {
    throw new Error(
      "scan draft: this operation requires a bound worker context.",
    );
  }
  if (context.scanId !== parsed.scanId) {
    throw new Error(
      "scan draft: scanId does not match the coordinator-bound worker scan.",
    );
  }

  const scope = context.scope;
  let scoped =
    scope && scope !== "."
      ? {
          ...parsed,
          findings: parsed.findings.filter((finding) =>
            (finding.locations as JsonObject[]).some((location) => {
              const path = (location.path as string).replace(/^\.\//u, "");
              return path === scope || path.startsWith(`${scope}/`);
            }),
          ),
        }
      : parsed;
  scoped = (await preserveScanDraft(context, scoped)).input;
  const destination = await artifactDestination(
    context,
    ["result.json"],
    "worker scan draft",
  );
  await replaceArtifactJson(destination, scoped);

  return {
    scanId: parsed.scanId,
    findingCount: scoped.findings.length,
    surfaceCount: (scoped.coverage.surfaces as unknown[]).length,
    coverage: scoped.coverage,
    operation: "replace",
    status: "draft_written",
  };
}

/** Keep the semantic input before any replaceable worker or canonical artifact. */
export async function saveScanDraftCheckpoint(
  context: ArtifactContext,
  input: Omit<ScanDraftInput, "coverage">,
  updateHead = true,
): Promise<void> {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  const contents = JSON.stringify(snapshot, null, 2) + "\n";
  const name = scanDraftCheckpointName(input);
  const destination = await artifactDestination(
    context,
    ["checkpoints", name],
    "scan checkpoint",
  );
  try {
    const existing = await fs.readFile(destination, "utf8");
    if (existing !== contents)
      throw new Error(
        "scan checkpoint: existing content does not match its digest.",
      );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await replaceArtifactJson(destination, snapshot);
  }
  if (context.layout === "worker" && updateHead) {
    const head = await artifactDestination(
      context,
      ["checkpoint-head.json"],
      "scan checkpoint head",
    );
    await replaceArtifactJson(head, { checkpoint: name });
  }
}

async function preserveScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
  saveCheckpoint = true,
): Promise<{ input: ScanDraftInput; previousDigest: string }> {
  const currentCheckpointName = scanDraftCheckpointName(input);
  const requiresClosureValidation = resolvedDeferred(input.coverage).length > 0;
  if (saveCheckpoint && !requiresClosureValidation)
    await saveScanDraftCheckpoint(context, input, false);
  let result = structuredClone(input);
  const previousState = await readPreviousScanDraft(context);
  const previous = previousState.input;
  if (previous && previous.scanId !== input.scanId)
    throw new Error(
      "scan checkpoint: saved result belongs to a different scan.",
    );
  const current = await readCurrentCheckpoints(context, currentCheckpointName);
  const archived =
    context.layout === "worker"
      ? await readArchivedWorkerCheckpoints(context)
      : [];
  if (previous) {
    current.unshift({ input: previous, modifiedMs: previousState.modifiedMs });
  }
  current.sort(
    (left, right) =>
      right.modifiedMs - left.modifiedMs ||
      Number(right.head ?? false) - Number(left.head ?? false),
  );
  const savedSources = [...current, ...archived];
  const sources = savedSources.map(({ input }) => input);
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
    for (const observation of progressSources) {
      const reopened = (observation.coverage.deferred as JsonObject[]).filter(
        (row) =>
          closedIds.has(row.id as string) ||
          closedIds.has(row.candidateId as string),
      );
      if (reopened.length > 0) {
        const reopenedIds = new Set(
          reopened.flatMap((row) =>
            [row.id, row.candidateId].filter(
              (id): id is string => typeof id === "string" && closedIds.has(id),
            ),
          ),
        );
        const progress = structuredClone(observation);
        const { resolved, updated } = reconcileDeferredSurfaces(
          progress.coverage,
          sources,
          reopenedIds,
          new Set(),
          [],
        );
        for (const surface of resolved) reopenedSurfaces.add(surface);
        result.coverage = preserveScanCoverage(
          { ...result.coverage, surfaces: [...updated] },
          [result.coverage],
          false,
        );
        result.coverage.surfaces = exactUnion(
          result.coverage.surfaces as JsonObject[],
          (progress.coverage.surfaces as JsonObject[]).filter(
            (surface) => !updated.has(surface),
          ),
        );
        sources.unshift(progress);
      }
    }
  }
  const resolvedCandidateIds = completedCandidateIds(result, sources);
  const { closedDeferredIds, resolvedSurfaces } = reconcileResolvedDeferred(
    result,
    resolvedDeferred(input.coverage),
    sources,
    savedSources,
    resolvedCandidateIds,
    retainedFinal?.input,
  );
  for (const surface of reopenedSurfaces) resolvedSurfaces.add(surface);
  if (saveCheckpoint && requiresClosureValidation)
    await saveScanDraftCheckpoint(context, input, false);

  const resolvedFollowUpSurfaces = sources.flatMap((source) => {
    const pending = source.coverage.deferred as JsonObject[];
    if (
      pending.length === 0 ||
      pending.some((item) => {
        const candidateId = item.candidateId ?? item.id;
        return (
          typeof candidateId !== "string" ||
          !resolvedCandidateIds.has(candidateId)
        );
      })
    )
      return [];
    return (source.coverage.surfaces as JsonObject[]).filter(
      (surface) => surface.disposition === "needs_follow_up",
    );
  });

  for (const source of sources) {
    const deferred = result.coverage.deferred as JsonObject[];
    const dispositions = (result.coverage.surfaces as JsonObject[]).filter(
      (surface) =>
        (surface.disposition === "rejected" ||
          surface.disposition === "not_applicable") &&
        typeof surface.candidateId === "string",
    );
    const candidateRows = [...deferred, ...dispositions];
    for (const pending of source.coverage.deferred as JsonObject[]) {
      const candidateId = pending.candidateId ?? pending.id;
      if (typeof candidateId !== "string") continue;
      const finding = result.findings.find(
        (item) => findingCandidateId(item) === candidateId,
      );
      if (finding) {
        const provenance = finding.provenance as JsonObject;
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
          (item) => item.candidateId === candidateId || item.id === candidateId,
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
        ...candidateRows.map((item) => item.candidateId ?? item.id),
      ].filter((value): value is string => typeof value === "string"),
    );
    const previousCoverage = {
      ...source.coverage,
      deferred: (source.coverage.deferred as JsonObject[]).filter((item) => {
        const candidateId = item.candidateId ?? item.id;
        return (
          (typeof candidateId !== "string" || !resolvedIds.has(candidateId)) &&
          !closedDeferredIds.has(item.id as string)
        );
      }),
      surfaces: (source.coverage.surfaces as JsonObject[]).filter((surface) => {
        if (resolvedSurfaces.has(surface)) return false;
        const candidateId = surface.candidateId ?? surface.id;
        return (
          (typeof candidateId !== "string" || !resolvedIds.has(candidateId)) &&
          !coverageEntryPresent(
            result.coverage.surfaces as unknown[],
            surface,
          ) &&
          !(
            surface.disposition === "needs_follow_up" &&
            coverageEntryPresent(resolvedFollowUpSurfaces, surface)
          )
        );
      }),
      openQuestions:
        result.complete === false
          ? (
              (source.coverage.openQuestions as unknown[] | undefined) ?? []
            ).filter(
              (question) =>
                !coverageEntryPresent(
                  (result.coverage.openQuestions as unknown[] | undefined) ??
                    [],
                  question,
                ),
            )
          : [],
    };
    result.coverage.surfaces = exactUnion(
      result.coverage.surfaces as JsonObject[],
      previousCoverage.surfaces,
    );
    result.coverage = preserveScanCoverage(
      result.coverage,
      [previousCoverage],
      false,
    );
  }
  result.coverage.deferred = normalizeDeferred(
    result.coverage.deferred as JsonObject[],
  );
  result.coverage.surfaces = normalizeSurfaces(
    result.coverage.surfaces as JsonObject[],
  );
  if (saveCheckpoint) await saveScanDraftCheckpoint(context, result);
  return { input: result, previousDigest: previousState.digest };
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

function resolvedDeferred(coverage: JsonObject): JsonObject[] {
  return (coverage.resolvedDeferred as JsonObject[] | undefined) ?? [];
}

function reconcileResolvedDeferred(
  result: ScanDraftInput,
  requestedClosures: JsonObject[],
  sources: ScanDraftInput[],
  savedSources: SavedScanDraft[],
  resolvedCandidateIds: Set<string>,
  retainedFinal?: ScanDraftInput,
): { closedDeferredIds: Set<string>; resolvedSurfaces: Set<JsonObject> } {
  const activeDeferred = result.coverage.deferred as JsonObject[];
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
  const candidateIds = new Set(
    historical
      .filter(
        (row) =>
          typeof row.candidateId === "string" ||
          "candidate" in row ||
          "finding" in row,
      )
      .flatMap((row) =>
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
    if (source.complete === false) continue;
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
    if (candidateIds.has(id))
      throw new Error(
        `scan draft: coverage.resolvedDeferred cannot close candidate ${id}; record its finding or disposition.`,
      );
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
    result.coverage.resolvedDeferred = [...closures.values()].map((closure) =>
      structuredClone(closure),
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
  const { resolved: resolvedSurfaces } = reconcileDeferredSurfaces(
    result.coverage,
    sources,
    closedDeferredIds,
    resolvedCandidateIds,
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
  inherited: ScanDraftInput[],
  savedSources: SavedScanDraft[] = [],
  retainedFinal?: ScanDraftInput,
  reopenedIds: Set<string> = new Set(),
): { resolved: Set<JsonObject>; updated: Set<JsonObject> } {
  const resolved = new Set<JsonObject>();
  const updated = new Set<JsonObject>();
  const workIds = new Set([...closedDeferredIds, ...reopenedIds]);
  if (workIds.size === 0) return { resolved, updated };
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
  const pending = [
    ...(coverage.deferred as JsonObject[]),
    ...sources.flatMap((source) => source.coverage.deferred as JsonObject[]),
  ].filter(
    (row) =>
      !closedDeferredIds.has(row.id as string) &&
      !resolvedCandidateIds.has((row.candidateId ?? row.id) as string),
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
    )
      continue;
    const linked = matches.some(
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
    updated.add(surface);
    for (const previous of previousSurfaces) {
      if (
        surface.disposition === "needs_follow_up" ||
        previous.disposition === "needs_follow_up"
      )
        resolved.add(previous);
    }
  }
  return { resolved, updated };
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
  const head = parseJsonObject(
    await readArtifactText(context, ["checkpoint-head.json"], label),
    label,
  );
  if (
    typeof head.checkpoint !== "string" ||
    !/^[a-f0-9]{64}\.json$/u.test(head.checkpoint)
  )
    throw new Error(`scan checkpoint: ${kind} checkpoint head is invalid.`);
  // Reselecting an immutable checkpoint updates only the head file.
  return { checkpoint: head.checkpoint, modifiedMs: Number(metadata.mtimeMs) };
}

async function readCurrentCheckpoints(
  context: ArtifactContext,
  excludedCheckpoint: string,
): Promise<SavedScanDraft[]> {
  const checkpointRoot = join(context.root, "checkpoints");
  const checkpointRootMetadata = await lstatIfExists(checkpointRoot);
  if (checkpointRootMetadata === undefined) return [];
  if (
    checkpointRootMetadata.isSymbolicLink() ||
    !checkpointRootMetadata.isDirectory()
  ) {
    throw new Error(
      "scan checkpoint: current checkpoint set is not a safe directory.",
    );
  }
  const [canonicalRoot, canonicalCheckpointRoot] = await Promise.all([
    fs.realpath(context.root),
    fs.realpath(checkpointRoot),
  ]);
  if (!canonicalCheckpointRoot.startsWith(canonicalRoot + sep)) {
    throw new Error(
      "scan checkpoint: current checkpoint set escaped its artifact directory.",
    );
  }

  const head = await readCheckpointHead(context, "current");
  const checkpointHead = head?.checkpoint;

  const checkpoints: Array<{
    input: ScanDraftInput;
    modifiedMs: number;
    head: boolean;
    name: string;
  }> = [];
  for (const entry of await fs.readdir(canonicalCheckpointRoot, {
    withFileTypes: true,
  })) {
    if (
      !entry.isFile() ||
      !entry.name.endsWith(".json") ||
      entry.name === excludedCheckpoint
    )
      continue;
    const checkpointPath = join(canonicalCheckpointRoot, entry.name);
    const checkpointMetadata = await fs.lstat(checkpointPath);
    if (checkpointMetadata.isSymbolicLink() || !checkpointMetadata.isFile()) {
      throw new Error(
        "scan checkpoint: current checkpoint is not a safe file.",
      );
    }
    const input = parsePersistedCheckpoint(
      parseJsonObject(
        await readArtifactText(
          context,
          ["checkpoints", entry.name],
          "current scan checkpoint",
        ),
        "current scan checkpoint",
      ),
    );
    if (input.scanId !== context.scanId) {
      throw new Error(
        "scan checkpoint: current checkpoint belongs to a different scan.",
      );
    }
    checkpoints.push({
      input,
      modifiedMs:
        entry.name === checkpointHead
          ? head!.modifiedMs
          : Number(checkpointMetadata.mtimeMs),
      head: entry.name === checkpointHead,
      name: entry.name,
    });
  }
  if (
    checkpointHead !== undefined &&
    checkpointHead !== excludedCheckpoint &&
    !checkpoints.some(({ head }) => head)
  ) {
    throw new Error("scan checkpoint: current checkpoint head is missing.");
  }
  checkpoints.sort(
    (left, right) =>
      right.modifiedMs - left.modifiedMs ||
      Number(right.head) - Number(left.head) ||
      right.name.localeCompare(left.name),
  );
  return checkpoints;
}

function scanDraftCheckpointName(
  input: Omit<ScanDraftInput, "coverage">,
): string {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  return (
    createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") +
    ".json"
  );
}

async function readPreviousScanDraft(
  context: ArtifactContext,
): Promise<{ input?: ScanDraftInput; digest: string; modifiedMs: number }> {
  if (context.layout === "worker") {
    const contents = await readOptionalArtifactText(context, ["result.json"]);
    return {
      ...(contents === undefined
        ? {}
        : {
            input: parsePersistedScanDraft(
              parseJsonObject(contents, "previous scan draft"),
            ),
          }),
      digest: draftDigest([["result.json", contents]]),
      modifiedMs: Number(
        (await lstatIfExists(join(context.root, "result.json")))?.mtimeMs ?? 0,
      ),
    };
  }
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
  if (contents.every((value) => value === undefined))
    return { digest, modifiedMs: 0 };
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
    modifiedMs: Number(
      (await fs.lstat(join(context.root, "coverage.json"))).mtimeMs,
    ),
    input: parsePersistedCheckpoint({
      scanId: context.scanId,
      ...(scan.complete === false ? { complete: false } : {}),
      ...(isObject(scan.scope) ? { scope: scan.scope } : {}),
      ...(isObject(scan.threatModel) ? { threatModel: scan.threatModel } : {}),
      findings: findings.findings,
      coverage,
    }),
  };
}

async function readArchivedWorkerCheckpoints(
  context: ArtifactContext,
): Promise<SavedScanDraft[]> {
  const workerRoot = dirname(context.root);
  const attemptsRoot = join(workerRoot, "attempts");
  const attemptsMetadata = await lstatIfExists(attemptsRoot);
  if (attemptsMetadata === undefined) return [];
  if (attemptsMetadata.isSymbolicLink() || !attemptsMetadata.isDirectory()) {
    throw new Error(
      "scan checkpoint: archived attempts are not a safe directory.",
    );
  }
  const [canonicalWorkerRoot, canonicalAttemptsRoot] = await Promise.all([
    fs.realpath(workerRoot),
    fs.realpath(attemptsRoot),
  ]);
  if (!canonicalAttemptsRoot.startsWith(canonicalWorkerRoot + sep)) {
    throw new Error(
      "scan checkpoint: archived attempts escaped their worker directory.",
    );
  }

  const archived: SavedScanDraft[] = [];
  const attempts = (
    await fs.readdir(canonicalAttemptsRoot, { withFileTypes: true })
  )
    .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink())
    .sort(
      (left, right) =>
        archivedAttemptNumber(right.name) - archivedAttemptNumber(left.name) ||
        right.name.localeCompare(left.name),
    );
  for (const attempt of attempts) {
    const attemptRoot = await fs.realpath(
      join(canonicalAttemptsRoot, attempt.name),
    );
    if (!attemptRoot.startsWith(canonicalAttemptsRoot + sep)) {
      throw new Error(
        "scan checkpoint: archived attempt escaped its worker directory.",
      );
    }
    const drafts: Array<{
      input: ScanDraftInput;
      modifiedMs: number;
      result: boolean;
      head?: boolean;
      name: string;
    }> = [];
    const attemptContext = { ...context, root: attemptRoot };
    const head = await readCheckpointHead(attemptContext, "archived");
    let checkpointHead: ScanDraftInput | undefined;
    if (head) {
      checkpointHead = parsePersistedScanDraft(
        parseJsonObject(
          await readArtifactText(
            attemptContext,
            ["checkpoints", head.checkpoint],
            "archived scan checkpoint head",
          ),
          "archived scan checkpoint head",
        ),
      );
      requireMatchingScan(context, checkpointHead);
    }
    const resultMetadata = await lstatIfExists(
      join(attemptRoot, "result.json"),
    );
    if (resultMetadata !== undefined) {
      if (resultMetadata.isSymbolicLink() || !resultMetadata.isFile()) {
        throw new Error("scan checkpoint: archived result is not a safe file.");
      }
      const contents = await readArtifactText(
        attemptContext,
        ["result.json"],
        "archived scan result",
      );
      let result: ScanDraftInput | undefined;
      try {
        result = parsePersistedScanDraft(
          parseJsonObject(contents, "archived scan result"),
        );
      } catch {
        // A failed attempt may leave an invalid replaceable result after valid checkpoints.
      }
      if (result !== undefined) {
        requireMatchingScan(context, result);
        drafts.push({
          input: result,
          modifiedMs: Number(resultMetadata.mtimeMs),
          result: true,
          name: "result.json",
        });
      }
    }
    const checkpointRoot = join(attemptRoot, "checkpoints");
    const checkpointMetadata = await lstatIfExists(checkpointRoot);
    if (checkpointMetadata !== undefined) {
      if (
        checkpointMetadata.isSymbolicLink() ||
        !checkpointMetadata.isDirectory()
      ) {
        throw new Error(
          "scan checkpoint: archived checkpoint set is not a safe directory.",
        );
      }
      const checkpoints = (
        await fs.readdir(checkpointRoot, { withFileTypes: true })
      )
        .filter(
          (entry) =>
            entry.isFile() &&
            entry.name.endsWith(".json") &&
            entry.name !== head?.checkpoint,
        )
        .sort((left, right) => left.name.localeCompare(right.name));
      for (const checkpoint of checkpoints) {
        const checkpointPath = join(checkpointRoot, checkpoint.name);
        const checkpointMetadata = await fs.lstat(checkpointPath);
        if (
          checkpointMetadata.isSymbolicLink() ||
          !checkpointMetadata.isFile()
        ) {
          throw new Error(
            "scan checkpoint: archived checkpoint is not a safe file.",
          );
        }
        const contents = await readArtifactText(
          attemptContext,
          ["checkpoints", checkpoint.name],
          "archived scan checkpoint",
        );
        const draft = parsePersistedScanDraft(
          parseJsonObject(contents, "archived scan checkpoint"),
        );
        requireMatchingScan(context, draft);
        drafts.push({
          input: draft,
          modifiedMs: Number(checkpointMetadata.mtimeMs),
          result: false,
          name: checkpoint.name,
        });
      }
    }
    if (checkpointHead !== undefined) {
      drafts.push({
        input: checkpointHead,
        modifiedMs: head!.modifiedMs,
        head: true,
        result: false,
        name: head!.checkpoint,
      });
    }
    drafts.sort(
      (left, right) =>
        right.modifiedMs - left.modifiedMs ||
        Number(right.head ?? false) - Number(left.head ?? false) ||
        Number(right.result) - Number(left.result) ||
        right.name.localeCompare(left.name),
    );
    archived.push(
      ...drafts.map((draft) => ({ ...draft, attempt: attempt.name })),
    );
  }
  return archived;
}

function archivedAttemptNumber(name: string): number {
  const match = /^attempt-(\d+)$/.exec(name);
  return match ? Number(match[1]) : -1;
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
): Promise<string | undefined> {
  try {
    return await readArtifactText(context, components, "previous scan draft");
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

function withoutPreviousFindings(finding: JsonObject): JsonObject {
  const result = structuredClone(finding);
  if (isObject(result.provenance)) delete result.provenance.previousFindings;
  return result;
}

/** Preserve both original sources and details synthesized after those sources. */
export function preserveFindingDetails(
  current: JsonObject,
  previous: JsonObject,
): void {
  if (current.identity === undefined && previous.identity !== undefined) {
    current.identity = structuredClone(previous.identity);
  }
  const provenance = requireObject(
    current.provenance,
    "saved finding provenance",
  );
  const oldProvenance = isObject(previous.provenance)
    ? previous.provenance
    : {};
  for (const field of [
    "sourceFindingIds",
    "sourceFindings",
    "previousFindings",
    "originalCandidates",
  ] as const) {
    const values = exactUnion(
      Array.isArray(provenance[field]) ? provenance[field] : [],
      Array.isArray(oldProvenance[field]) ? oldProvenance[field] : [],
    );
    if (values.length) provenance[field] = values;
  }
  if (!containsSavedFinding(current, previous)) {
    const original = withoutPreviousFindings(previous);
    if (isObject(original.provenance))
      delete original.provenance.sourceFindings;
    provenance.previousFindings = exactUnion(
      Array.isArray(provenance.previousFindings)
        ? provenance.previousFindings
        : [],
      [original],
    );
  }
}

function containsSavedFinding(
  current: JsonObject,
  previous: JsonObject,
): boolean {
  const original = withoutPreviousFindings(previous);
  if (current.identity === undefined) delete original.identity;
  return containsSavedValue(current, original);
}

function containsSavedValue(current: unknown, previous: unknown): boolean {
  if (Array.isArray(previous)) {
    return (
      Array.isArray(current) &&
      previous.every((value) =>
        current.some((entry) => containsSavedValue(entry, value)),
      )
    );
  }
  if (isObject(previous)) {
    return (
      isObject(current) &&
      Object.entries(previous).every(([key, value]) =>
        containsSavedValue(current[key], value),
      )
    );
  }
  return current === previous;
}

function deferredEntryPresent(entries: unknown[], previous: unknown): boolean {
  return entries.some(
    (current) =>
      isDeepStrictEqual(current, previous) ||
      (isObject(current) &&
        isObject(previous) &&
        [previous.id, previous.candidateId].some(
          (id) =>
            typeof id === "string" &&
            (current.id === id || current.candidateId === id),
        )),
  );
}

function coverageEntryPresent(entries: unknown[], previous: unknown): boolean {
  return entries.some((entry) => {
    const current =
      typeof entry === "string" ? { question: entry.trim() } : entry;
    const original =
      typeof previous === "string"
        ? { question: previous.trim() }
        : structuredClone(previous);
    if (isObject(current) && isObject(original)) {
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

/** Reducers cannot resolve source review by omitting its coverage records. */
export function preserveScanCoverage(
  coverage: JsonObject,
  sources: JsonObject[],
  preserveCompleteness = true,
): JsonObject {
  const result = structuredClone(coverage);
  for (const field of [
    "surfaces",
    "explicitExclusions",
    "deferred",
    "openQuestions",
  ] as const) {
    const current = (result[field] as unknown[] | undefined) ?? [];
    const values = [...current];
    for (const source of sources) {
      for (const value of (source[field] as unknown[] | undefined) ?? []) {
        const present =
          field === "deferred" ? deferredEntryPresent : coverageEntryPresent;
        if (!present(values, value)) values.push(structuredClone(value));
      }
    }
    if (
      field !== "openQuestions" ||
      values.length > 0 ||
      result[field] !== undefined
    )
      result[field] = values;
  }
  if (
    coverageHasOutstandingWork(result) ||
    (preserveCompleteness &&
      sources.some(
        (source) =>
          source.completeness === "partial" &&
          !coverageHasOutstandingWork(source),
      ))
  )
    result.completeness = "partial";
  else if (
    preserveCompleteness &&
    sources.some((source) => source.completeness === "unknown")
  ) {
    result.completeness = "unknown";
  }
  return result;
}

function coverageHasOutstandingWork(coverage: JsonObject): boolean {
  return (
    ((coverage.deferred as unknown[] | undefined) ?? []).length > 0 ||
    ((coverage.surfaces as JsonObject[] | undefined) ?? []).some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  );
}

function exactUnion<Value>(...groups: Value[][]): Value[] {
  const seen = new Set<string>();
  return groups.flat().filter((value) => {
    const key = JSON.stringify(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function scanFindingIdentity(finding: JsonObject): string {
  const identity = finding.identity as JsonObject | undefined;
  if (identity)
    return JSON.stringify([
      finding.ruleId,
      identity.anchor,
      identity.instance ?? null,
    ]);
  const location = (finding.locations as JsonObject[])[0]!;
  return JSON.stringify([
    finding.ruleId,
    location.path,
    location.startLine,
    location.endLine ?? null,
  ]);
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

export function parseScanDraft(input: ScanDraftInput): ScanDraftInput {
  const parsed = parseScanDraftDocument(input);
  if (parsed.complete === false && resolvedDeferred(parsed.coverage).length > 0)
    throw new Error(
      "scan draft: coverage.resolvedDeferred is allowed only on a terminal draft.",
    );
  parsed.coverage.deferred = normalizeDeferred(
    parsed.coverage.deferred as JsonObject[],
  );
  parsed.coverage.surfaces = normalizeSurfaces(
    parsed.coverage.surfaces as JsonObject[],
  );
  return parsed;
}

function parseScanDraftDocument(input: unknown): ScanDraftInput {
  const parsed = scanDraftInputSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  validateCoverageSemantics(parsed.coverage);
  return parsed;
}

/** Validate saved drafts before reconciling interrupted writes and older findings. */
export function parsePersistedScanDraft(
  input: Record<string, unknown>,
): ScanDraftInput {
  const compatible = structuredClone(input);
  if (!Array.isArray(compatible.findings)) {
    return parseScanDraftDocument(compatible);
  }
  for (const finding of compatible.findings) {
    if (!isObject(finding)) continue;
    normalizePersistedFindingDetails(finding);
  }
  return parseScanDraftDocument(compatible);
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
      return typeof id === "string" && id.trim().length > 0 ? [id] : [];
    }),
  );
  if (Array.isArray(finding.code_evidence)) {
    const compatibleEvidence: JsonObject[] = [];
    for (const evidence of finding.code_evidence) {
      if (!isObject(evidence)) continue;
      const id = evidence.id;
      const code = evidence.code;
      if (
        typeof id !== "string" ||
        id.trim().length === 0 ||
        typeof code !== "string" ||
        code.trim().length === 0 ||
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
    filterPersistedEvidenceRefs(section, evidenceIds);
  }

  const rootCause = finding.rootCause;
  if (isObject(rootCause)) {
    if (
      typeof rootCause.summary !== "string" ||
      rootCause.summary.trim().length === 0
    ) {
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
  } else if (
    "root_cause" in finding &&
    (typeof legacyRootCause !== "string" || legacyRootCause.trim().length === 0)
  ) {
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
    if (detail === null) {
      delete attackPath[field];
      continue;
    }
    if (typeof detail === "string") {
      if (detail.trim().length === 0) delete attackPath[field];
      continue;
    }
    if (!isObject(detail)) {
      if (field in attackPath) delete attackPath[field];
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
    filterPersistedEvidenceRefs(detail, evidenceIds);
  }
  for (const field of ["impact", "likelihood"]) {
    const detail = attackPath[field];
    if (isObject(detail)) {
      removeUnsupportedPersistedStrings(detail, ["level", "rationale", "why"]);
    } else if (
      detail !== undefined &&
      detail !== null &&
      (typeof detail !== "string" || detail.trim().length === 0)
    ) {
      delete attackPath[field];
    }
  }
}

function normalizePersistedStringLists(
  section: JsonObject,
  fields: string[],
): void {
  for (const field of fields) {
    if (!(field in section)) continue;
    const value = section[field];
    const normalized =
      typeof value === "string"
        ? value.trim().length > 0
          ? [value]
          : []
        : Array.isArray(value)
          ? value.filter(
              (item): item is string =>
                typeof item === "string" && item.trim().length > 0,
            )
          : [];
    if (normalized.length > 0) section[field] = normalized;
    else delete section[field];
  }
}

function filterPersistedEvidenceRefs(
  section: JsonObject,
  evidenceIds: Set<string>,
): void {
  for (const field of ["evidenceRefs", "evidence_refs"]) {
    const refs = section[field];
    if (!Array.isArray(refs)) continue;
    section[field] = refs.filter(
      (ref): ref is string =>
        typeof ref === "string" &&
        ref.trim().length > 0 &&
        evidenceIds.has(ref),
    );
  }
}

function removeUnsupportedPersistedStrings(
  section: JsonObject,
  fields: string[],
): void {
  for (const field of fields) {
    if (
      field in section &&
      (typeof section[field] !== "string" || section[field].trim().length === 0)
    ) {
      delete section[field];
    }
  }
}

function requireBoundScan(
  context: ArtifactContext,
  input: CompletedScanInput,
  requireRunning: boolean,
): void {
  if (context.layout !== "scan") {
    throw new Error(
      "scan draft: this operation requires an authoritative parent scan context.",
    );
  }
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

function buildTarget(
  context: ArtifactContext,
  contract: JsonObject,
  trustedTarget: JsonObject,
): JsonObject {
  const allowedKinds = trustedTarget.allowedKinds;
  if (
    !Array.isArray(allowedKinds) ||
    !allowedKinds.length ||
    !allowedKinds.every((kind) => typeof kind === "string")
  ) {
    throw new Error(
      "scan draft: the authoritative target has no allowed target kind.",
    );
  }
  if (
    typeof trustedTarget.targetId !== "string" ||
    !trustedTarget.targetId ||
    typeof trustedTarget.displayName !== "string" ||
    !trustedTarget.displayName
  ) {
    throw new Error(
      "scan draft: the authoritative target identity is incomplete.",
    );
  }

  const target: JsonObject = {
    kind: allowedKinds[0],
    targetId: trustedTarget.targetId,
    displayName: trustedTarget.displayName,
  };
  if (context.mode === "diff") {
    const diffTarget = requireObject(
      contract.diffTarget,
      "scan draft: authoritative diff target",
    );
    for (const field of ["baseRevision", "headRevision"] as const) {
      const value = diffTarget[field];
      if (typeof value !== "string" || !value) {
        throw new Error(
          `scan draft: authoritative diff target is missing ${field}.`,
        );
      }
      target[field] = value;
    }
    if (diffTarget.kind === "working_tree") {
      if (
        typeof diffTarget.contentDigest !== "string" ||
        !diffTarget.contentDigest
      ) {
        throw new Error(
          "scan draft: authoritative working-tree target has no snapshot digest.",
        );
      }
      target.snapshotDigest = diffTarget.contentDigest;
    } else if (diffTarget.kind === "commit" || diffTarget.kind === "range") {
      const digest = createHash("sha256")
        .update("codex-security-diff/v1\0")
        .update(diffTarget.kind)
        .update("\0")
        .update(target.baseRevision as string)
        .update("\0")
        .update(target.headRevision as string)
        .digest("hex");
      target.snapshotDigest = `codex-security-snapshot/v1:sha256:${digest}`;
    } else {
      throw new Error(
        "scan draft: the authoritative diff target kind is invalid.",
      );
    }
  } else {
    if (context.targetRevision && context.targetRevision !== "unversioned") {
      target.revision = context.targetRevision;
    }
    if (trustedTarget.requiredSnapshotDigest !== undefined) {
      if (
        typeof trustedTarget.requiredSnapshotDigest !== "string" ||
        !trustedTarget.requiredSnapshotDigest
      ) {
        throw new Error(
          "scan draft: the authoritative target snapshot digest is invalid.",
        );
      }
      target.snapshotDigest = trustedTarget.requiredSnapshotDigest;
    }
  }
  return target;
}

function buildScope(
  context: ArtifactContext,
  trustedScope: JsonObject,
  semanticScope?: JsonObject,
): JsonObject {
  const includePaths = trustedScope.requiredIncludePaths;
  const excludePaths = trustedScope.requiredExcludePaths;
  const resolvedIncludePaths =
    includePaths === undefined
      ? [
          typeof trustedScope.requestedPath === "string"
            ? trustedScope.requestedPath
            : (context.scope ?? "."),
        ]
      : requireTextArray(
          includePaths,
          "scan draft: authoritative included scope",
        );
  const resolvedExcludePaths =
    excludePaths === undefined
      ? []
      : requireTextArray(
          excludePaths,
          "scan draft: authoritative excluded scope",
        );

  return {
    ...semanticScope,
    includePaths: resolvedIncludePaths,
    excludePaths: resolvedExcludePaths,
  };
}

function buildFindings(findings: JsonObject[], mode?: string): JsonObject[] {
  const generatedIdentities = findings.map((finding, index) => {
    if (finding.identity !== undefined) return undefined;
    const candidateId = (finding.extensions as JsonObject | undefined)
      ?.candidateId;
    const identitySource =
      typeof candidateId === "string" && candidateId.trim()
        ? candidateId
        : (finding.title as string);
    const extensions = finding.extensions as JsonObject | undefined;
    const siblingSource = [extensions?.reportId, extensions?.ledgerRowId].find(
      (value): value is string =>
        typeof value === "string" && Boolean(value.trim()),
    );
    return {
      anchor: semanticIdentifier(identitySource, `finding-${index + 1}`),
      stableInstanceSource: siblingSource,
      siblingSource: siblingSource ?? (finding.title as string),
    };
  });
  const anchorCounts = new Map<string, number>();
  for (const [index, finding] of findings.entries()) {
    const generatedIdentity = generatedIdentities[index];
    const authoredIdentity = finding.identity as JsonObject | undefined;
    const anchor =
      generatedIdentity?.anchor ?? (authoredIdentity?.anchor as string);
    const ruleScopedAnchor = `${finding.ruleId}\0${anchor}`;
    anchorCounts.set(
      ruleScopedAnchor,
      (anchorCounts.get(ruleScopedAnchor) ?? 0) + 1,
    );
  }

  const identified: JsonObject[] = findings.map((finding, index) => {
    const generatedIdentity = generatedIdentities[index];
    if (generatedIdentity === undefined) return { ...finding };
    const identity: JsonObject = { anchor: generatedIdentity.anchor };
    const ruleScopedAnchor = `${finding.ruleId}\0${generatedIdentity.anchor}`;
    if (
      generatedIdentity.stableInstanceSource !== undefined ||
      (anchorCounts.get(ruleScopedAnchor) ?? 0) > 1
    ) {
      const baseInstance = semanticIdentifier(
        generatedIdentity.siblingSource,
        `finding-${index + 1}`,
      );
      identity.instance = baseInstance;
    }
    return {
      ...finding,
      identity,
    };
  });
  if (mode !== "deep") return identified;

  // Keep both findings when workers reuse an ID.
  // Add a numeric suffix to make each ID unique.
  const reserved = new Set(identified.map(scanFindingIdentity));
  const used = new Set<string>();
  return identified.map((finding) => {
    const key = scanFindingIdentity(finding);
    if (!used.has(key)) {
      used.add(key);
      return finding;
    }
    const identity = finding.identity as JsonObject;
    const baseInstance = identity.instance ?? "saved";
    let suffix = 2;
    const distinct: JsonObject & { identity: JsonObject } = {
      ...finding,
      identity: { ...identity },
    };
    do {
      distinct.identity.instance = `${baseInstance}-${suffix}`;
      suffix += 1;
    } while (
      reserved.has(scanFindingIdentity(distinct)) ||
      used.has(scanFindingIdentity(distinct))
    );
    const provenance = finding.provenance as JsonObject;
    distinct.provenance = {
      ...provenance,
      preservedIdentity:
        provenance.preservedIdentity ?? structuredClone(identity),
    };
    used.add(scanFindingIdentity(distinct));
    return distinct;
  });
}

function buildCoverage(
  context: ArtifactContext,
  contract: JsonObject,
  semanticCoverage: JsonObject,
  scope: JsonObject,
  target: JsonObject,
): JsonObject {
  const openQuestions = semanticCoverage.openQuestions as
    Array<string | JsonObject> | undefined;

  return {
    ...semanticCoverage,
    mode: coverageMode(context, contract),
    inventoryStrategy: inventoryStrategy(context, scope, target),
    includePaths: scope.includePaths,
    excludePaths: scope.excludePaths,
    surfaces: (semanticCoverage.surfaces as JsonObject[]).map((surface) => ({
      ...surface,
      receiptRefs: surface.receiptRefs ?? [],
    })),
    ...(openQuestions === undefined
      ? {}
      : {
          openQuestions: openQuestions.map((question) =>
            typeof question === "string"
              ? { question: question.trim() }
              : question,
          ),
        }),
  };
}

function normalizeSurfaces(surfaces: JsonObject[]): JsonObject[] {
  const reservedSurfaceIds = new Set(
    surfaces.flatMap((surface) =>
      typeof surface.id === "string" ? [surface.id] : [],
    ),
  );
  const surfaceIds = new Set<string>();
  return surfaces.map((surface) => {
    const explicitId = typeof surface.id === "string";
    const baseId = explicitId
      ? (surface.id as string)
      : `surface-${createHash("sha256")
          .update(JSON.stringify(surface))
          .digest("hex")
          .slice(0, 16)}`;
    let id = baseId;
    if (surfaceIds.has(id) || (!explicitId && reservedSurfaceIds.has(id))) {
      let suffix = 2;
      do {
        id = `${baseId}-${suffix}`;
        suffix += 1;
      } while (surfaceIds.has(id) || reservedSurfaceIds.has(id));
    }
    surfaceIds.add(id);
    return { ...surface, id };
  });
}

function normalizeDeferred(rows: JsonObject[]): JsonObject[] {
  // Reserve later owned identities before deriving any earlier missing ones.
  const ids = new Set(
    rows.flatMap((item) => (typeof item.id === "string" ? [item.id] : [])),
  );
  const reservedCandidateIds = new Set(
    rows.flatMap((item) =>
      typeof item.candidateId === "string" ? [item.candidateId] : [],
    ),
  );
  return rows.map((item) => {
    if (typeof item.id === "string") return item;

    const candidateId = item.candidateId;
    const baseId =
      typeof candidateId === "string"
        ? candidateId
        : `deferred-${createHash("sha256")
            .update(JSON.stringify(item))
            .digest("hex")
            .slice(0, 16)}`;
    let id = baseId;
    let suffix = 2;
    while (
      ids.has(id) ||
      (typeof candidateId !== "string" && reservedCandidateIds.has(id))
    ) {
      id = `${baseId}-${suffix}`;
      suffix += 1;
    }
    ids.add(id);
    return { ...item, id };
  });
}

function coverageMode(context: ArtifactContext, contract: JsonObject): string {
  if (context.mode === "diff") {
    const diff = requireObject(
      contract.diffTarget,
      "scan draft: authoritative diff target",
    );
    const modes: Record<string, string> = {
      commit: "commit",
      range: "branch_diff",
      working_tree: "working_tree",
    };
    const mode = modes[String(diff.kind)];
    if (!mode)
      throw new Error(
        "scan draft: the authoritative diff coverage mode is invalid.",
      );
    return mode;
  }

  const trustedScope = requireObject(
    contract.scope,
    "scan draft: authoritative scope",
  );
  const includes = trustedScope.requiredIncludePaths;
  const scoped = Array.isArray(includes)
    ? includes.length !== 1 || includes[0] !== "."
    : typeof trustedScope.requestedPath === "string" &&
      trustedScope.requestedPath !== ".";
  if (scoped) return "scoped_path";
  return context.mode === "deep" ? "deep_repository" : "repository";
}

function inventoryStrategy(
  context: ArtifactContext,
  scope: JsonObject,
  target: JsonObject,
): string {
  if (context.mode === "diff") return "diff";
  const includePaths = scope.includePaths as string[];
  if (includePaths.length !== 1 || includePaths[0] !== ".")
    return "scoped_path";
  if (context.mode === "deep") return "repository";
  if (target.kind === "directory_snapshot") return "directory";
  return "repository";
}

function validateFindingSemantics(findings: JsonObject[]): void {
  for (const [findingIndex, finding] of findings.entries()) {
    const severity = finding.severity as JsonObject;
    if (
      severity.score !== undefined &&
      typeof severity.scoringSystem !== "string"
    ) {
      throw new Error(
        `scan draft: findings[${findingIndex}].severity.scoringSystem is required with severity.score.`,
      );
    }

    const locations = finding.locations as JsonObject[];
    for (const [locationIndex, location] of locations.entries()) {
      if (
        typeof location.endLine === "number" &&
        location.endLine < (location.startLine as number)
      ) {
        throw new Error(
          `scan draft: findings[${findingIndex}].locations[${locationIndex}].endLine ` +
            "must not precede startLine.",
        );
      }
    }

    const evidenceIds = new Set<string>();
    for (const [evidenceName, evidenceCatalog] of [
      ["codeEvidence", finding.codeEvidence],
      ["code_evidence", finding.code_evidence],
    ] as const) {
      for (const [evidenceIndex, evidence] of (
        (evidenceCatalog as JsonObject[] | undefined) ?? []
      ).entries()) {
        const id = evidence.id as string;
        if (evidenceIds.has(id)) {
          throw new Error(
            `scan draft: findings[${findingIndex}].${evidenceName}[${evidenceIndex}].id ` +
              `duplicates ${id}.`,
          );
        }
        evidenceIds.add(id);
        if (
          typeof evidence.endLine === "number" &&
          evidence.endLine < (evidence.startLine as number)
        ) {
          throw new Error(
            `scan draft: findings[${findingIndex}].${evidenceName}[${evidenceIndex}].endLine ` +
              "must not precede startLine.",
          );
        }
      }
    }

    const referencedSections: Array<[string, unknown]> = [
      ["rootCause", finding.rootCause],
      ["root_cause", finding.root_cause],
      ["validation", finding.validation],
      ["attackPath", finding.attackPath],
    ];
    if (isObject(finding.attackPath)) {
      for (const sectionName of [
        "dataFlow",
        "dataflow",
        "data_flow",
        "reachability",
      ]) {
        referencedSections.push([
          `attackPath.${sectionName}`,
          finding.attackPath[sectionName],
        ]);
      }
    }
    for (const [sectionName, section] of referencedSections) {
      if (!isObject(section)) continue;
      for (const referencesName of ["evidenceRefs", "evidence_refs"]) {
        const references = section[referencesName];
        if (references === undefined) continue;
        if (
          !Array.isArray(references) ||
          references.some(
            (reference) =>
              typeof reference !== "string" || !evidenceIds.has(reference),
          )
        ) {
          throw new Error(
            `scan draft: findings[${findingIndex}].${sectionName}.${referencesName} ` +
              "must refer to that finding's existing code-evidence IDs.",
          );
        }
      }
    }
  }
}

function validateCoverageSemantics(coverage: JsonObject): void {
  if (coverage.completeness !== "complete") return;
  if ((coverage.deferred as unknown[]).length > 0) {
    throw new Error(
      "scan draft: complete coverage cannot contain deferred work.",
    );
  }
  if (
    (coverage.surfaces as JsonObject[]).some(
      (surface) => surface.disposition === "needs_follow_up",
    )
  ) {
    throw new Error(
      "scan draft: complete coverage cannot contain needs_follow_up surfaces.",
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

function requireObject(value: unknown, context: string): JsonObject {
  if (!isObject(value)) throw new Error(`${context} must be an object.`);
  return value;
}

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireTextArray(value: unknown, context: string): string[] {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string" || !entry)
  ) {
    throw new Error(`${context} must contain an array of nonempty paths.`);
  }
  return [...value];
}

function semanticIdentifier(value: string, fallback: string): string {
  const identifier = value
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/gu, "")
    .toLowerCase()
    .replace(/[^a-z0-9._/-]+/gu, "-")
    .replace(/^-+|-+$/gu, "");
  return identifier || fallback;
}
