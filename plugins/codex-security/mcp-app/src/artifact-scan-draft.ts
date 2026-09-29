import {
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
import { createHash, randomUUID } from "node:crypto";
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
  replaceArtifactJson,
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
  publishDraft: PublishScanDraft,
  signal?: AbortSignal,
): Promise<ScanDraftResult> {
  const parsed = parseScanDraft(input);
  requireBoundScan(context, parsed, true);

  for (;;) {
    signal?.throwIfAborted();
    // Deep results are ready to save. Do not merge older drafts or
    // checkpoints into them.
    const preserved =
      context.mode === "deep" && parsed.complete !== false
        ? { input: parsed, previousDigest: undefined }
        : await preserveScanDraft(context, parsed);
    const reconciled = preserved.input;
    const hardening = await readExistingHardeningPortfolio(context);
    const draft = prepareSemanticScanDraft(context, reconciled, hardening);
    try {
      await publishDraft(draft, preserved.previousDigest, parsed);
      return {
        scanId: reconciled.scanId,
        findingCount: draft.findings.findings.length,
        surfaceCount: draft.coverage.surfaces.length,
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

async function preserveScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<{ input: ScanDraftInput; previousDigest: string }> {
  const currentCheckpointName = scanDraftCheckpointName(input);
  let result = structuredClone(input);
  const previousState = await readPreviousScanDraft(context);
  const previous = previousState.input;
  if (previous && previous.scanId !== input.scanId)
    throw new Error(
      "scan checkpoint: saved result belongs to a different scan.",
    );
  const current = await readCurrentCheckpoints(context, currentCheckpointName);
  const sources: ScanDraftInput[] = previous ? [previous, ...current] : current;
  if (input.complete === false) {
    const final = sources.find((source) => source.complete !== false);
    if (final) result = structuredClone(final);
  }
  // Older drafts used the deferred row's id as a candidate alias. Keep its
  // scope without promoting legacy IDs into the stricter candidateId field.
  const historicalCandidateIds = new Set(
    sources.flatMap((source) =>
      source.coverage.surfaces.flatMap((surface) =>
        typeof surface.candidateId === "string" ? [surface.candidateId] : [],
      ),
    ),
  );
  for (const scan of [result, ...sources])
    for (const row of scan.coverage.deferred)
      if (
        row.candidateId === undefined &&
        typeof row.id === "string" &&
        historicalCandidateIds.has(row.id)
      )
        row.candidateScoped = true;
  const resolvedSurfaces = resolvedCoverageSurfaceIds(result.coverage, sources);
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

  const resolvedCandidateIds = new Set(
    [
      ...result.findings.map(findingCandidateId),
      ...result.coverage.surfaces
        .filter(
          (surface) =>
            surface.disposition === "rejected" ||
            surface.disposition === "not_applicable",
        )
        .map((surface) => surface.candidateId),
    ].filter((value): value is string => typeof value === "string"),
  );
  const resolvedFollowUpSurfaces = sources.flatMap((source) => {
    const pending = source.coverage.deferred;
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
          (item) => item.candidateId === candidateId || item.id === candidateId,
        );
        if (candidateRow) {
          if (
            candidateRow.candidateId === undefined &&
            (pending.candidateScoped === true ||
              typeof pending.candidateId === "string")
          )
            candidateRow.candidateScoped = true;
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
        ...dispositions.map((item) => item.candidateId ?? item.id),
      ].filter((value): value is string => typeof value === "string"),
    );
    const previousCoverage = {
      ...source.coverage,
      deferred: source.coverage.deferred.filter((item) => {
        const candidateId = item.candidateId ?? item.id;
        return (
          (typeof candidateId !== "string" || !resolvedIds.has(candidateId)) &&
          !(
            typeof item.candidateId !== "string" &&
            item.candidateScoped !== true &&
            item.candidate === undefined &&
            item.finding === undefined &&
            Array.isArray(item.surfaceIds) &&
            item.surfaceIds.length > 0 &&
            item.surfaceIds.every(
              (id) => typeof id === "string" && resolvedSurfaces.has(id),
            )
          ) &&
          !coverageEntryPresent(result.coverage.deferred, item)
        );
      }),
      surfaces: source.coverage.surfaces.filter((surface) => {
        const candidateId = surface.candidateId ?? surface.id;
        return (
          (typeof candidateId !== "string" || !resolvedIds.has(candidateId)) &&
          !coverageEntryPresent(result.coverage.surfaces, surface) &&
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
    result.coverage = preserveScanCoverage(result.coverage, previousCoverage);
  }
  return { input: result, previousDigest: previousState.digest };
}

async function readCurrentCheckpoints(
  context: ArtifactContext,
  excludedCheckpoint: string,
): Promise<ScanDraftInput[]> {
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

  const checkpoints: Array<{
    input: ScanDraftInput;
    modifiedMs: number;
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
    const input = parsePersistedScanDraft(
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
      modifiedMs: Number(checkpointMetadata.mtimeMs),
      name: entry.name,
    });
  }
  checkpoints.sort(
    (left, right) =>
      right.modifiedMs - left.modifiedMs || right.name.localeCompare(left.name),
  );
  return checkpoints.map(({ input }) => input);
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
): Promise<{ input?: ScanDraftInput; digest: string }> {
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
      if (current.id === undefined) delete original.id;
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
  if (stable.length > 0) return stable;
  if (typeof entry.label === "string" && entry.label.trim()) {
    return [
      `surface:${typeof entry.riskArea === "string" ? entry.riskArea : ""}:${entry.label}`,
    ];
  }
  return [];
}

/** Explicit, unambiguous resolution closes historical work; omission does not. */
function resolvedCoverageSurfaceIds(
  coverage: SemanticCoverage,
  sources: ScanDraftInput[],
): Set<string> {
  const key = (surface: SemanticCoverage["surfaces"][number]) =>
    JSON.stringify([surface.label, surface.riskArea ?? null]);
  const historical = new Map<string, string | null>();
  for (const source of sources)
    for (const surface of source.coverage.surfaces) {
      if (typeof surface.id !== "string") continue;
      const identity = key(surface);
      historical.set(
        surface.id,
        historical.has(surface.id) && historical.get(surface.id) !== identity
          ? null
          : identity,
      );
    }
  const surfaces = coverage.surfaces;
  const counts = new Map<string, number>();
  for (const surface of surfaces)
    if (typeof surface.id === "string")
      counts.set(surface.id, (counts.get(surface.id) ?? 0) + 1);
  const pending = new Set(
    coverage.deferred.flatMap((row) =>
      Array.isArray(row.surfaceIds) ? row.surfaceIds : [],
    ),
  );
  return new Set(
    surfaces.flatMap((surface) =>
      typeof surface.id === "string" &&
      typeof surface.candidateId !== "string" &&
      counts.get(surface.id) === 1 &&
      surface.disposition !== "needs_follow_up" &&
      !pending.has(surface.id) &&
      historical.get(surface.id) === key(surface)
        ? [surface.id]
        : [],
    ),
  );
}

/** Keep saved coverage that the current draft has not resolved. */
function preserveScanCoverage(
  coverage: SemanticCoverage,
  source: SemanticCoverage,
): SemanticCoverage {
  const result = structuredClone(coverage);
  const retain = <Entry>(values: Entry[], previous: Entry[]): Entry[] => {
    for (const value of previous)
      if (!coverageEntryPresent(values, value))
        values.push(structuredClone(value));
    return values;
  };
  result.surfaces = retain(result.surfaces, source.surfaces);
  result.explicitExclusions = retain(
    result.explicitExclusions,
    source.explicitExclusions,
  );
  result.deferred = retain(result.deferred, source.deferred);
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
    return parseScanDraft({
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
