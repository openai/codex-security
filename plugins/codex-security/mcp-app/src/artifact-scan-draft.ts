import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, sep } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import scanDraftDocument from "../../schemas/tools/scan-draft.schema.json";
import {
  candidateKey,
  coverageCandidateKey,
  findingCandidateKey,
  findingCandidateOwner,
  isTerminalCandidateDecision,
  resolvedCandidateKeys as collectResolvedCandidateKeys,
  surfaceReferenceKey,
} from "./artifact-candidates.js";
import type { ArtifactContext } from "./artifact-context.js";
import type { RunArtifactWorkbench } from "./artifact-context.js";
import {
  preserveDiffCandidateDecisions,
  preserveUnresolvedDiffCandidates,
  readDiffCandidates,
  refreshDiffCandidateHistory,
  type DiffCandidates,
} from "./artifact-diff-candidates.js";
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
  if (context.mode === "diff")
    parsed.coverage = normalizeCheckpointCoverage(parsed.coverage);
  requireBoundScan(context, parsed, true);
  for (;;) {
    const candidates = await readDiffCandidates(context);
    const checkpoint = preserveUnresolvedDiffCandidates(
      preserveDiffCandidateDecisions(parsed, candidates),
      candidates,
    );
    if (!publishDraft) await saveScanDraftCheckpoint(context, checkpoint);
    signal?.throwIfAborted();
    // Deep results are ready to save. Do not merge older drafts or
    // checkpoints into them.
    const preserved =
      context.mode === "deep" && parsed.complete !== false
        ? { input: parsed, previousDigest: undefined }
        : await preserveScanDraft(
            context,
            { ...parsed, findings: checkpoint.findings },
            false,
            scanDraftCheckpointName(checkpoint),
            candidates,
          );
    const reconciled = preserveUnresolvedDiffCandidates(
      preserved.input,
      candidates,
    );
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
        await publishDraft(draft, preserved.previousDigest, checkpoint);
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

/** Preserve one complete Standard scan draft inside its assigned worker output. */
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
  currentCheckpointName = scanDraftCheckpointName(input),
  diffCandidates?: DiffCandidates,
): Promise<{ input: ScanDraftInput; previousDigest: string }> {
  if (saveCheckpoint) await saveScanDraftCheckpoint(context, input, false);
  let result = structuredClone(input);
  // All records inside one worker output belong to that worker, including imports.
  const owner = context.layout === "worker" ? context.root : undefined;
  const findingKey = (finding: JsonObject) =>
    findingCandidateKey(finding, owner);
  const coverageKey = (item: JsonObject) => coverageCandidateKey(item, owner);
  const surfaceKey = (id: unknown, item: JsonObject) =>
    candidateKey(id, owner ?? item.sourceWorkerId);
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
  const sources = refreshDiffCandidateHistory(
    previous ? [previous, ...current, ...archived] : [...current, ...archived],
    diffCandidates,
  );
  if (input.complete === false) {
    const final = sources.find((source) => source.complete !== false);
    if (final) {
      result = structuredClone(final);
      if (diffCandidates !== undefined) {
        sources.unshift(input);
        const currentDecisionKeys = collectResolvedCandidateKeys(
          { ...input, findings: [] },
          owner,
        );
        for (const section of ["surfaces", "explicitExclusions"]) {
          result.coverage[section] = [
            ...(input.coverage[section] as JsonObject[]).filter(
              isTerminalCandidateDecision,
            ),
            ...(result.coverage[section] as JsonObject[]).filter(
              (item) =>
                !isTerminalCandidateDecision(item) ||
                !currentDecisionKeys.has(coverageKey(item)!),
            ),
          ];
        }
        if (
          input.coverage.completeness === "partial" &&
          input.coverage.completenessBeforeCandidates === undefined
        ) {
          result.coverage.completeness = "partial";
          delete result.coverage.completenessBeforeCandidates;
        }
      }
    }
  }
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

  // Ledger decisions clear candidate-linked work, not unlinked legacy follow-ups.
  const legacyResolvedFollowUpCandidateKeys = new Set(
    [
      ...result.findings.map((finding) => findingKey(finding)),
      ...(result.coverage.surfaces as JsonObject[])
        .filter(isTerminalCandidateDecision)
        .map((surface) => coverageKey(surface)),
    ].filter((value): value is string => typeof value === "string"),
  );
  result = preserveDiffCandidateDecisions(
    result,
    diffCandidates,
    sources,
    input.findings,
  );
  const resolvedCandidateKeys = collectResolvedCandidateKeys(result, owner);
  const resolvedSurfaceIds = new Set<string>();
  const pendingSurfaceCandidates = new Map<string, Set<string | undefined>>();
  const pendingCandidateKeys = new Set<string>();
  for (const source of [result, ...sources]) {
    for (const item of source.coverage.deferred as JsonObject[]) {
      const candidateId = coverageKey(item);
      const resolved =
        typeof candidateId === "string" &&
        resolvedCandidateKeys.has(candidateId);
      if (!resolved && typeof candidateId === "string")
        pendingCandidateKeys.add(candidateId);
      for (const id of Array.isArray(item.surfaceIds) ? item.surfaceIds : []) {
        if (typeof id !== "string") continue;
        const reference = surfaceReferenceKey(
          id,
          item,
          source.coverage.surfaces as JsonObject[],
          owner,
        )!;
        if (resolved) {
          resolvedSurfaceIds.add(reference);
        } else {
          const candidates =
            pendingSurfaceCandidates.get(reference) ?? new Set();
          candidates.add(
            typeof candidateId === "string" ? candidateId : undefined,
          );
          pendingSurfaceCandidates.set(reference, candidates);
        }
      }
    }
  }
  const resolvedFollowUpSurfaces = sources.flatMap((source) => {
    const pending = source.coverage.deferred as JsonObject[];
    if (
      pending.length === 0 ||
      pending.some((item) => {
        const candidateId = coverageKey(item);
        return (
          typeof candidateId !== "string" ||
          !legacyResolvedFollowUpCandidateKeys.has(candidateId)
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
    const dispositions = [
      ...(result.coverage.surfaces as JsonObject[]),
      ...(result.coverage.explicitExclusions as JsonObject[]),
    ].filter(isTerminalCandidateDecision);
    const candidateRows = [...dispositions, ...deferred];
    for (const pending of source.coverage.deferred as JsonObject[]) {
      const candidateId = coverageKey(pending);
      if (typeof candidateId !== "string") continue;
      const finding = result.findings.find(
        (item) => findingKey(item) === candidateId,
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
          (item) => coverageKey(item) === candidateId,
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
      const candidateId = findingKey(finding);
      const disposition =
        candidateId === undefined
          ? undefined
          : dispositions.find((item) => coverageKey(item) === candidateId);
      if (disposition) {
        disposition.finding ??= structuredClone(finding);
        continue;
      }
      const matches = result.findings.filter((current) =>
        sameSavedFinding(current, finding, owner),
      );
      if (
        matches.length === 1 &&
        source.findings.filter((current) =>
          sameSavedFinding(current, finding, owner),
        ).length === 1
      ) {
        preserveFindingDetails(matches[0]!, finding);
      } else {
        if (!matches.some((current) => containsSavedFinding(current, finding)))
          result.findings.push(structuredClone(finding));
      }
    }
    for (const candidateId of [
      ...result.findings.map((finding) => findingKey(finding)),
      ...dispositions.map((item) => coverageKey(item)),
    ]) {
      if (typeof candidateId === "string")
        resolvedCandidateKeys.add(candidateId);
    }
    const representedCandidateKeys = new Set(
      [
        ...result.findings.map((finding) => findingKey(finding)),
        ...candidateRows.map((item) => coverageKey(item)),
      ].filter((value): value is string => typeof value === "string"),
    );
    const currentSurfaces = result.coverage.surfaces as JsonObject[];
    // A shared surface keeps its own identity beside the candidate's terminal decision.
    for (const surface of source.coverage.surfaces as JsonObject[]) {
      if (
        surface.disposition === "needs_follow_up" &&
        typeof surface.id === "string" &&
        [
          ...(pendingSurfaceCandidates.get(surfaceKey(surface.id, surface)!) ??
            []),
        ].some((id) => id === undefined || !resolvedCandidateKeys.has(id)) &&
        !currentSurfaces.some(
          (current) =>
            surfaceKey(current.id, current) === surfaceKey(surface.id, surface),
        )
      )
        currentSurfaces.push(structuredClone(surface));
    }
    const previousCoverage = {
      ...source.coverage,
      deferred: (source.coverage.deferred as JsonObject[]).filter((item) => {
        const candidateId = coverageKey(item);
        return (
          (typeof candidateId !== "string" ||
            !representedCandidateKeys.has(candidateId)) &&
          !coverageEntryPresent(result.coverage.deferred as unknown[], item)
        );
      }),
      surfaces: (source.coverage.surfaces as JsonObject[]).filter((surface) => {
        const candidateId = coverageKey(surface);
        if (
          coverageEntryPresent(result.coverage.surfaces as unknown[], surface)
        )
          return false;
        return (
          (typeof candidateId !== "string" ||
            !representedCandidateKeys.has(candidateId)) &&
          !(
            surface.disposition === "needs_follow_up" &&
            ((typeof candidateId === "string" &&
              resolvedCandidateKeys.has(candidateId)) ||
              (typeof surface.id === "string" &&
                resolvedSurfaceIds.has(surfaceKey(surface.id, surface)!))) &&
            !(
              typeof candidateId === "string" &&
              pendingCandidateKeys.has(candidateId)
            )
          ) &&
          !(
            surface.disposition === "needs_follow_up" &&
            coverageEntryPresent(resolvedFollowUpSurfaces, surface)
          )
        );
      }),
      explicitExclusions: (
        source.coverage.explicitExclusions as JsonObject[]
      ).filter((exclusion) => {
        const candidateId = coverageKey(exclusion);
        return (
          (typeof candidateId !== "string" ||
            !representedCandidateKeys.has(candidateId)) &&
          !coverageEntryPresent(
            result.coverage.explicitExclusions as unknown[],
            exclusion,
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
    result.coverage = preserveScanCoverage(
      result.coverage,
      [previousCoverage],
      false,
    );
  }
  if (saveCheckpoint) await saveScanDraftCheckpoint(context, result);
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

  let checkpointHead: string | undefined;
  if (context.layout === "worker") {
    const headMetadata = await lstatIfExists(
      join(context.root, "checkpoint-head.json"),
    );
    if (headMetadata !== undefined) {
      if (headMetadata.isSymbolicLink() || !headMetadata.isFile()) {
        throw new Error(
          "scan checkpoint: current checkpoint head is not a safe file.",
        );
      }
      const head = parseJsonObject(
        await readArtifactText(
          context,
          ["checkpoint-head.json"],
          "current scan checkpoint head",
        ),
        "current scan checkpoint head",
      );
      if (
        typeof head.checkpoint !== "string" ||
        !/^[a-f0-9]{64}\.json$/u.test(head.checkpoint)
      ) {
        throw new Error("scan checkpoint: current checkpoint head is invalid.");
      }
      checkpointHead = head.checkpoint;
    }
  }

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
      modifiedMs: Number(checkpointMetadata.mtimeMs),
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
      Number(right.head) - Number(left.head) ||
      right.modifiedMs - left.modifiedMs ||
      right.name.localeCompare(left.name),
  );
  return checkpoints.map(({ input }) => input);
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
): Promise<{ input?: ScanDraftInput; digest: string }> {
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
  const semanticScope = isObject(scan.scope) ? { ...scan.scope } : undefined;
  if (semanticScope) {
    delete semanticScope.includePaths;
    delete semanticScope.excludePaths;
  }
  const semanticCoverage = { ...coverage };
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
    delete semanticCoverage[field];
  return {
    digest,
    input: parsePersistedScanDraft({
      scanId: context.scanId,
      ...(scan.complete === false ? { complete: false } : {}),
      ...(semanticScope && Object.keys(semanticScope).length > 0
        ? { scope: semanticScope }
        : {}),
      ...(isObject(scan.threatModel)
        ? { threatModel: structuredClone(scan.threatModel) }
        : {}),
      findings: (findings.findings as JsonObject[]).map((finding) => {
        const semantic = { ...finding };
        for (const field of ["findingId", "occurrenceId", "fingerprints"])
          delete semantic[field];
        return semantic;
      }),
      coverage: semanticCoverage,
    }),
  };
}

async function readArchivedWorkerCheckpoints(
  context: ArtifactContext,
): Promise<ScanDraftInput[]> {
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

  const archived: ScanDraftInput[] = [];
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
      name: string;
    }> = [];
    let checkpointHead: ScanDraftInput | undefined;
    let checkpointHeadName: string | undefined;
    const headMetadata = await lstatIfExists(
      join(attemptRoot, "checkpoint-head.json"),
    );
    if (headMetadata !== undefined) {
      if (headMetadata.isSymbolicLink() || !headMetadata.isFile()) {
        throw new Error(
          "scan checkpoint: archived checkpoint head is not a safe file.",
        );
      }
      const head = parseJsonObject(
        await readArtifactText(
          { ...context, root: attemptRoot },
          ["checkpoint-head.json"],
          "archived scan checkpoint head",
        ),
        "archived scan checkpoint head",
      );
      if (
        typeof head.checkpoint !== "string" ||
        !/^[a-f0-9]{64}\.json$/u.test(head.checkpoint)
      ) {
        throw new Error(
          "scan checkpoint: archived checkpoint head is invalid.",
        );
      }
      checkpointHeadName = head.checkpoint;
      checkpointHead = parsePersistedScanDraft(
        parseJsonObject(
          await readArtifactText(
            { ...context, root: attemptRoot },
            ["checkpoints", checkpointHeadName],
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
        { ...context, root: attemptRoot },
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
            entry.name !== checkpointHeadName,
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
          { ...context, root: attemptRoot },
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
    drafts.sort(
      (left, right) =>
        right.modifiedMs - left.modifiedMs ||
        Number(right.result) - Number(left.result) ||
        right.name.localeCompare(left.name),
    );
    if (checkpointHead !== undefined) archived.push(checkpointHead);
    archived.push(...drafts.map((draft) => draft.input));
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

function sameSavedFinding(
  left: JsonObject,
  right: JsonObject,
  owner?: string,
): boolean {
  if (left.ruleId !== right.ruleId) return false;
  if (
    owner === undefined &&
    !isDeepStrictEqual(
      findingCandidateOwner(left) ?? null,
      findingCandidateOwner(right) ?? null,
    )
  )
    return false;
  if (left.identity && right.identity)
    return scanFindingIdentity(left) === scanFindingIdentity(right);
  const leftCandidate = findingCandidateKey(left, owner);
  if (leftCandidate && leftCandidate === findingCandidateKey(right, owner))
    return true;
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
      stable.push(`stable:${candidateKey(value, entry.sourceWorkerId)}`);
  }
  if (stable.length > 0) return stable;
  if (typeof entry.label === "string" && entry.label.trim()) {
    return [
      `surface:${typeof entry.riskArea === "string" ? entry.riskArea : ""}:${entry.label}`,
    ];
  }
  return [];
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
        if (!coverageEntryPresent(values, value))
          values.push(structuredClone(value));
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
  if (
    coverage.completeness !== "partial" &&
    result.completeness === "partial" &&
    sources.some((source) => source.completenessBeforeCandidates !== undefined)
  ) {
    result.completenessBeforeCandidates = coverage.completeness;
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
  const parsed = scanDraftInputSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  validateCoverageSemantics(parsed.coverage);
  return parsed;
}

/** Re-admit results persisted by older plugin versions without loosening live tool input. */
export function parsePersistedScanDraft(
  input: Record<string, unknown>,
): ScanDraftInput {
  const compatible = structuredClone(input);
  if (!Array.isArray(compatible.findings)) {
    return parseScanDraft(compatible as unknown as ScanDraftInput);
  }
  for (const finding of compatible.findings) {
    if (!isObject(finding)) continue;
    normalizePersistedFindingDetails(finding);
  }
  return parseScanDraft(compatible as unknown as ScanDraftInput);
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
  const normalized = normalizeCoverageEntries(semanticCoverage);
  const openQuestions = semanticCoverage.openQuestions as
    Array<string | JsonObject> | undefined;

  return {
    ...semanticCoverage,
    mode: coverageMode(context, contract),
    inventoryStrategy: inventoryStrategy(context, scope, target),
    includePaths: scope.includePaths,
    excludePaths: scope.excludePaths,
    surfaces: normalized.surfaces,
    deferred: normalized.deferred,
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

function normalizeCheckpointCoverage(coverage: JsonObject): JsonObject {
  const normalized = normalizeCoverageEntries(coverage);
  // Explicit IDs and references are normalized together. Missing IDs still use
  // semantic identity until historical coverage has been reconciled.
  for (const section of ["surfaces", "deferred"]) {
    const original = coverage[section] as JsonObject[];
    normalized[section] = (normalized[section] as JsonObject[]).map(
      (item, index) => {
        if (typeof original[index]!.id === "string") return item;
        const { id: _id, ...semantic } = item;
        return semantic;
      },
    );
  }
  return normalized;
}

function normalizeCoverageEntries(coverage: JsonObject): JsonObject {
  const surfaces = coverage.surfaces as JsonObject[];
  const reservedSurfaceIds = new Set(
    surfaces.flatMap((surface) =>
      typeof surface.id === "string" ? [surface.id] : [],
    ),
  );
  const surfaceIds = new Set<string>();
  const renamedSurfaces = new Map<string, string>();
  const normalizedSurfaces = surfaces.map((surface, index) => {
    const explicitId = typeof surface.id === "string";
    const baseId = explicitId
      ? (surface.id as string)
      : `surface_${semanticIdentifier(surface.label as string, String(index + 1))}`;
    let id = baseId;
    if (surfaceIds.has(id) || (!explicitId && reservedSurfaceIds.has(id))) {
      let suffix = 2;
      do {
        id = `${baseId}-${suffix}`;
        suffix += 1;
      } while (surfaceIds.has(id) || reservedSurfaceIds.has(id));
    }
    surfaceIds.add(id);
    const originalKey = candidateKey(surface.id, surface.sourceWorkerId);
    if (explicitId && !renamedSurfaces.has(originalKey!))
      renamedSurfaces.set(originalKey!, id);
    return {
      ...surface,
      id,
      receiptRefs: surface.receiptRefs ?? [],
    };
  });
  const deferred = coverage.deferred as JsonObject[];
  // Reserve later owned identities before deriving any earlier missing ones.
  const deferredIds = new Set(
    deferred.flatMap((item) => (typeof item.id === "string" ? [item.id] : [])),
  );
  const reservedCandidateIds = new Set(
    deferred.flatMap((item) =>
      typeof item.candidateId === "string" ? [item.candidateId] : [],
    ),
  );
  const normalizedDeferred = deferred.map((item) => {
    const linked = Array.isArray(item.surfaceIds)
      ? {
          ...item,
          surfaceIds: item.surfaceIds.map(
            (id) =>
              renamedSurfaces.get(surfaceReferenceKey(id, item, surfaces)!) ??
              id,
          ),
        }
      : item;
    if (typeof item.id === "string") return linked;

    const candidateId = item.candidateId;
    const baseId =
      typeof candidateId === "string"
        ? candidateId
        : `deferred-${createHash("sha256")
            .update(
              JSON.stringify([
                item.reason,
                item.paths ?? [],
                item.surfaceIds ?? [],
              ]),
            )
            .digest("hex")
            .slice(0, 16)}`;
    let id = baseId;
    let suffix = 2;
    while (
      deferredIds.has(id) ||
      (typeof candidateId !== "string" && reservedCandidateIds.has(id))
    ) {
      id = `${baseId}-${suffix}`;
      suffix += 1;
    }
    deferredIds.add(id);
    return { ...linked, id };
  });
  return {
    ...coverage,
    surfaces: normalizedSurfaces,
    deferred: normalizedDeferred,
  };
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
