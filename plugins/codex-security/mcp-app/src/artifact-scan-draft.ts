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
} from "../../../../sdk/typescript/src/scan-semantics.js";
export { preserveFindingDetails, scanFindingIdentity } from "../../../../sdk/typescript/src/scan-semantics.js";
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
  publishDraft?: PublishScanDraft,
  signal?: AbortSignal,
): Promise<ScanDraftResult> {
  const parsed = parseScanDraft(input);
  requireBoundScan(context, parsed, true);
  if (!publishDraft) await saveScanDraftCheckpoint(context, parsed);

  for (;;) {
    signal?.throwIfAborted();
    // Deep results are ready to save. Do not merge older drafts or
    // checkpoints into them.
    const preserved = context.mode === "deep" && parsed.complete !== false
      ? { input: parsed, previousDigest: undefined }
      : await preserveScanDraft(context, parsed);
    const reconciled = preserved.input;
    const hardening = await readExistingHardeningPortfolio(context);
    const draft = prepareSemanticScanDraft(context, reconciled, hardening);
    try {
      if (publishDraft) {
        await publishDraft(draft, preserved.previousDigest, parsed);
      } else {
        const destinations = await Promise.all([
          artifactDestination(context, ["findings.json"], "scan draft findings"),
          artifactDestination(context, ["coverage.json"], "scan draft coverage"),
          artifactDestination(context, ["scan-manifest.json"], "scan draft manifest"),
        ]);
        await replaceArtifactJson(destinations[0], draft.findings);
        await replaceArtifactJson(destinations[1], draft.coverage);
        await replaceArtifactJson(destinations[2], draft.manifest);
      }
      return {
        scanId: reconciled.scanId,
        findingCount: (draft.findings.findings as unknown[]).length,
        surfaceCount: (draft.coverage.surfaces as unknown[]).length,
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

/** Keep the semantic input before replacing canonical artifacts. */
export async function saveScanDraftCheckpoint(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<void> {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  const contents = JSON.stringify(snapshot, null, 2) + "\n";
  const name = scanDraftCheckpointName(input);
  const destination = await artifactDestination(context, ["checkpoints", name], "scan checkpoint");
  try {
    const existing = await fs.readFile(destination, "utf8");
    if (existing !== contents) throw new Error("scan checkpoint: existing content does not match its digest.");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await replaceArtifactJson(destination, snapshot);
  }
}

async function preserveScanDraft(
  context: ArtifactContext,
  input: ScanDraftInput,
): Promise<{ input: ScanDraftInput; previousDigest: string }> {
  const currentCheckpointName = scanDraftCheckpointName(input);
  let result = structuredClone(input);
  const previousState = await readPreviousScanDraft(context);
  const previous = previousState.input;
  if (previous && previous.scanId !== input.scanId) throw new Error("scan checkpoint: saved result belongs to a different scan.");
  const current = await readCurrentCheckpoints(context, currentCheckpointName);
  const sources: ScanDraftInput[] = previous ? [previous, ...current] : current;
  if (input.complete === false) {
    const final = sources.find((source) => source.complete !== false);
    if (final) result = structuredClone(final);
  }
  const retainedScope = sources.find((source) => source.scope !== undefined)?.scope;
  if (result.scope === undefined && retainedScope !== undefined) {
    result.scope = retainedScope;
  }
  const retainedThreatModel = sources.find((source) => (
    source.threatModel !== undefined
  ))?.threatModel;
  if (result.threatModel === undefined && retainedThreatModel !== undefined) {
    result.threatModel = structuredClone(retainedThreatModel);
  }

  const resolvedCandidateIds = new Set([
    ...result.findings.map(findingCandidateId),
    ...(result.coverage.surfaces as JsonObject[])
      .filter((surface) => (
        surface.disposition === "rejected" || surface.disposition === "not_applicable"
      ))
      .map((surface) => surface.candidateId),
  ].filter((value): value is string => typeof value === "string"));
  const resolvedFollowUpSurfaces = sources.flatMap((source) => {
    const pending = source.coverage.deferred as JsonObject[];
    if (pending.length === 0 || pending.some((item) => {
      const candidateId = item.candidateId ?? item.id;
      return typeof candidateId !== "string" || !resolvedCandidateIds.has(candidateId);
    })) return [];
    return (source.coverage.surfaces as JsonObject[]).filter(
      (surface) => surface.disposition === "needs_follow_up",
    );
  });

  for (const source of sources) {
    const deferred = result.coverage.deferred as JsonObject[];
    const dispositions = (result.coverage.surfaces as JsonObject[]).filter((surface) => (
        (surface.disposition === "rejected" || surface.disposition === "not_applicable")
        && typeof surface.candidateId === "string"
    ));
    const candidateRows = [...deferred, ...dispositions];
    for (const pending of source.coverage.deferred as JsonObject[]) {
      const candidateId = pending.candidateId ?? pending.id;
      if (typeof candidateId !== "string") continue;
      const finding = result.findings.find((item) => findingCandidateId(item) === candidateId);
      if (finding) {
        const provenance = finding.provenance as JsonObject;
        if (pending.candidate !== undefined) provenance.originalCandidates = exactUnion(
          Array.isArray(provenance.originalCandidates) ? provenance.originalCandidates : [], [pending.candidate],
        );
        if (isObject(pending.finding)) preserveFindingDetails(finding, pending.finding);
      } else {
        const candidateRow = candidateRows.find((item) => (
          item.candidateId === candidateId || item.id === candidateId
        ));
        if (candidateRow) {
          for (const field of ["candidate", "finding"] as const) {
            if (pending[field] !== undefined) candidateRow[field] ??= structuredClone(pending[field]);
          }
        }
      }
    }
    for (const finding of source.findings) {
      const candidateId = findingCandidateId(finding);
      const disposition = candidateId === undefined ? undefined : dispositions.find((item) => (
        item.candidateId === candidateId || item.id === candidateId
      ));
      if (disposition) {
        disposition.finding ??= structuredClone(finding);
        continue;
      }
      const matches = result.findings.filter((current) => sameSavedFinding(current, finding));
      if (matches.length === 1 && source.findings.filter((current) => (
        sameSavedFinding(current, finding)
      )).length === 1) {
        preserveFindingDetails(matches[0]!, finding);
      } else {
        if (!matches.some((current) => containsSavedFinding(current, finding))) result.findings.push(structuredClone(finding));
      }
    }
    const resolvedIds = new Set([
      ...result.findings.map(findingCandidateId),
      ...candidateRows.map((item) => item.candidateId ?? item.id),
    ].filter((value): value is string => typeof value === "string"));
    const previousCoverage = {
      ...source.coverage,
      deferred: (source.coverage.deferred as JsonObject[]).filter((item) => {
        const candidateId = item.candidateId ?? item.id;
        return (
          (typeof candidateId !== "string" || !resolvedIds.has(candidateId))
          && !coverageEntryPresent(result.coverage.deferred as unknown[], item)
        );
      }),
      surfaces: (source.coverage.surfaces as JsonObject[]).filter((surface) => {
        const candidateId = surface.candidateId ?? surface.id;
        return (
          (typeof candidateId !== "string" || !resolvedIds.has(candidateId))
          && !coverageEntryPresent(result.coverage.surfaces as unknown[], surface)
          && !(
            surface.disposition === "needs_follow_up"
            && coverageEntryPresent(resolvedFollowUpSurfaces, surface)
          )
        );
      }),
      openQuestions: result.complete === false
        ? ((source.coverage.openQuestions as unknown[] | undefined) ?? []).filter((question) => (
            !coverageEntryPresent((result.coverage.openQuestions as unknown[] | undefined) ?? [], question)
          ))
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
    checkpointRootMetadata.isSymbolicLink()
    || !checkpointRootMetadata.isDirectory()
  ) {
    throw new Error("scan checkpoint: current checkpoint set is not a safe directory.");
  }
  const [canonicalRoot, canonicalCheckpointRoot] = await Promise.all([
    fs.realpath(context.root),
    fs.realpath(checkpointRoot),
  ]);
  if (!canonicalCheckpointRoot.startsWith(canonicalRoot + sep)) {
    throw new Error("scan checkpoint: current checkpoint set escaped its artifact directory.");
  }

  const checkpoints: Array<{
    input: ScanDraftInput;
    modifiedMs: number;
    name: string;
  }> = [];
  for (const entry of await fs.readdir(canonicalCheckpointRoot, { withFileTypes: true })) {
    if (
      !entry.isFile()
      || !entry.name.endsWith(".json")
      || entry.name === excludedCheckpoint
    ) continue;
    const checkpointPath = join(canonicalCheckpointRoot, entry.name);
    const checkpointMetadata = await fs.lstat(checkpointPath);
    if (checkpointMetadata.isSymbolicLink() || !checkpointMetadata.isFile()) {
      throw new Error("scan checkpoint: current checkpoint is not a safe file.");
    }
    const input = parsePersistedCheckpoint(parseJsonObject(await readArtifactText(
      context,
      ["checkpoints", entry.name],
      "current scan checkpoint",
    ), "current scan checkpoint"));
    if (input.scanId !== context.scanId) {
      throw new Error("scan checkpoint: current checkpoint belongs to a different scan.");
    }
    checkpoints.push({
      input,
      modifiedMs: Number(checkpointMetadata.mtimeMs),
      name: entry.name,
    });
  }
  checkpoints.sort((left, right) => right.modifiedMs - left.modifiedMs
    || right.name.localeCompare(left.name));
  return checkpoints.map(({ input }) => input);
}

function scanDraftCheckpointName(input: ScanDraftInput): string {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  return createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") + ".json";
}

async function readPreviousScanDraft(
  context: ArtifactContext,
): Promise<{ input?: ScanDraftInput; digest: string }> {
  const names = ["scan-manifest.json", "findings.json", "coverage.json"] as const;
  const contents = await Promise.all(names.map((name) => (
    readOptionalArtifactText(context, [name])
  )));
  const digest = draftDigest(names.map((name, index) => [name, contents[index]]));
  if (contents.every((value) => value === undefined)) return { digest };
  if (contents.some((value) => value === undefined)) {
    throw new Error("previous scan draft: canonical documents are incomplete.");
  }
  const manifest = parseJsonObject(contents[0]!, "previous scan draft manifest");
  const findings = parseJsonObject(contents[1]!, "previous scan draft findings");
  const coverage = parseJsonObject(contents[2]!, "previous scan draft coverage");
  const scan = requireObject(manifest.scan, "previous scan draft.scan");
  return {
    digest,
    input: parsePersistedScanDraft(semanticScanDraft(
      context.scanId!, scan, findings.findings as JsonObject[], coverage,
    ) as unknown as JsonObject),
  };
}

async function lstatIfExists(path: string): Promise<Awaited<ReturnType<typeof fs.lstat>> | undefined> {
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
    if (error instanceof Error && error.message === "previous scan draft: the requested artifact is unavailable.") {
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

function draftDigest(documents: ReadonlyArray<readonly [string, string | undefined]>): string {
  const digest = createHash("sha256");
  for (const [name, contents] of documents) {
    digest.update(name).update("\0");
    if (contents === undefined) digest.update("missing\0");
    else digest.update("present\0").update(contents).update("\0");
  }
  return digest.digest("hex");
}

function isScanDraftConflict(error: unknown): boolean {
  return error instanceof Error
    && "code" in error
    && error.code === "scan_draft_conflict";
}

function workbenchScanDraftConflict(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const stderr = "stderr" in error && typeof error.stderr === "string"
    ? error.stderr
    : "";
  return `${error.message}\n${stderr}`.includes("scan_draft_conflict");
}

function sameSavedFinding(left: JsonObject, right: JsonObject): boolean {
  if (left.ruleId !== right.ruleId) return false;
  if (left.identity && right.identity) return scanFindingIdentity(left) === scanFindingIdentity(right);
  const leftCandidate = findingCandidateId(left);
  if (leftCandidate && leftCandidate === findingCandidateId(right)) return true;
  return scanFindingIdentity({ ...left, identity: undefined }) === scanFindingIdentity({ ...right, identity: undefined });
}

function coverageEntryPresent(entries: unknown[], previous: unknown): boolean {
  return entries.some((entry) => {
    const current = typeof entry === "string" ? { question: entry.trim() } : entry;
    const original = typeof previous === "string" ? { question: previous.trim() } : structuredClone(previous);
    if (isObject(current) && isObject(original)) {
      const currentIdentities = coverageEntryIdentities(current);
      if (coverageEntryIdentities(original).some((identity) => currentIdentities.includes(identity))) {
        return true;
      }
      if (current.id === undefined) delete original.id;
      if (current.receiptRefs === undefined && Array.isArray(original.receiptRefs) && original.receiptRefs.length === 0) delete original.receiptRefs;
    }
    return containsSavedValue(current, original);
  });
}

function coverageEntryIdentities(entry: JsonObject): string[] {
  const stable: string[] = [];
  for (const field of ["id", "candidateId"] as const) {
    const value = entry[field];
    if (typeof value === "string" && value.trim()) stable.push(`stable:${value}`);
  }
  if (stable.length > 0) return stable;
  if (typeof entry.label === "string" && entry.label.trim()) {
    return [
      `surface:${typeof entry.riskArea === "string" ? entry.riskArea : ""}:${entry.label}`,
    ];
  }
  return [];
}

/** Keep saved coverage that the current draft has not resolved. */
function preserveScanCoverage(coverage: JsonObject, source: JsonObject): JsonObject {
  const result = structuredClone(coverage);
  for (const field of ["surfaces", "explicitExclusions", "deferred", "openQuestions"] as const) {
    const values = (result[field] as unknown[] | undefined) ?? [];
    for (const value of (source[field] as unknown[] | undefined) ?? []) {
      if (!coverageEntryPresent(values, value)) values.push(structuredClone(value));
    }
    if (field !== "openQuestions" || values.length > 0 || result[field] !== undefined) result[field] = values;
  }
  if (coverageHasOutstandingWork(result)) result.completeness = "partial";
  return result;
}

function coverageHasOutstandingWork(coverage: JsonObject): boolean {
  return ((coverage.deferred as unknown[] | undefined) ?? []).length > 0
    || ((coverage.surfaces as JsonObject[] | undefined) ?? []).some((surface) => (
      surface.disposition === "needs_follow_up"
    ));
}

function findingCandidateId(finding: JsonObject): string | undefined {
  const provenance = finding.provenance;
  if (isObject(provenance) && typeof provenance.candidateId === "string" && provenance.candidateId.trim()) {
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
  const parsed = scanDraftInputSchema.parse(input);
  validateFindingSemantics(parsed.findings);
  validateCoverageSemantics(parsed.coverage);
  return parsed;
}

/** Re-admit results persisted by older plugin versions without loosening live tool input. */
export function parsePersistedScanDraft(
  input: Record<string, unknown>
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

function parsePersistedCheckpoint(input: Record<string, unknown>): ScanDraftInput {
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
    ]) delete compatible.coverage[field];
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
    })
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
        "limitations"
      ]
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
        "steps"
      ]
    ]
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
      "language"
    ]);
  } else if (
    "root_cause" in finding &&
    (typeof legacyRootCause !== "string" ||
      legacyRootCause.trim().length === 0)
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
      "result"
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
      ...(field === "reachability" ? ["attacker", "entrypoint"] : [])
    ]);
    normalizePersistedStringLists(detail, [
      "evidenceRefs",
      "evidence_refs",
      "transformations",
      ...(field === "reachability" ? ["preconditions"] : [])
    ]);
    filterPersistedEvidenceRefs(detail, evidenceIds);
  }
  for (const field of ["impact", "likelihood"]) {
    const detail = attackPath[field];
    if (isObject(detail)) {
      removeUnsupportedPersistedStrings(detail, [
        "level",
        "rationale",
        "why"
      ]);
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
  fields: string[]
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
                typeof item === "string" && item.trim().length > 0
            )
          : [];
    if (normalized.length > 0) section[field] = normalized;
    else delete section[field];
  }
}

function filterPersistedEvidenceRefs(
  section: JsonObject,
  evidenceIds: Set<string>
): void {
  for (const field of ["evidenceRefs", "evidence_refs"]) {
    const refs = section[field];
    if (!Array.isArray(refs)) continue;
    section[field] = refs.filter(
      (ref): ref is string =>
        typeof ref === "string" &&
        ref.trim().length > 0 &&
        evidenceIds.has(ref)
    );
  }
}

function removeUnsupportedPersistedStrings(
  section: JsonObject,
  fields: string[]
): void {
  for (const field of fields) {
    if (
      field in section &&
      (typeof section[field] !== "string" ||
        section[field].trim().length === 0)
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
