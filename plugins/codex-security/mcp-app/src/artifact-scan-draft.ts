import { createHash, randomUUID } from "node:crypto";
import { promises as fs } from "node:fs";
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

  signal?.throwIfAborted();
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
  const scope = buildScope(context, trustedScope, parsed.scope);
  const findings = buildFindings(parsed.findings, context.mode);
  const coverage = buildCoverage(
    context,
    contract,
    parsed.coverage,
    scope,
    target,
  );
  const hardening = await readExistingHardeningPortfolio(context);
  const manifestScan: JsonObject = {
    ...(parsed.complete === false ? { complete: false } : {}),
    target,
    scope,
    ...(parsed.threatModel === undefined
      ? {}
      : { threatModel: parsed.threatModel }),
    ...(hardening === undefined ? {} : { hardening }),
  };

  const draft = {
    findings: { findings },
    coverage,
    manifest: { scan: manifestScan },
  };
  if (publishDraft) {
    await publishDraft(draft, parsed);
  } else {
    const destinations = await Promise.all([
      artifactDestination(context, ["findings.json"], "scan draft findings"),
      artifactDestination(context, ["coverage.json"], "scan draft coverage"),
      artifactDestination(context, ["scan-manifest.json"], "scan draft manifest"),
    ]);
    await replaceArtifactJson(destinations[0], { findings });
    await replaceArtifactJson(destinations[1], coverage);
    await replaceArtifactJson(destinations[2], { scan: manifestScan });
  }
  return {
    scanId: parsed.scanId,
    findingCount: findings.length,
    surfaceCount: (coverage.surfaces as unknown[]).length,
    operation: "replace",
    status: "draft_written",
  };
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
    async (draft, checkpoint) => {
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
        if (context.handoffClaimToken) {
          arguments_.push("--claim-token", context.handoffClaimToken);
        }
        await runWorkbench(arguments_);
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
  const scoped =
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
  await saveScanDraftCheckpoint(context, scoped);
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
  if (context.layout === "worker") {
    const head = await artifactDestination(
      context,
      ["checkpoint-head.json"],
      "scan checkpoint head",
    );
    await replaceArtifactJson(head, { checkpoint: name });
  }
}

function scanDraftCheckpointName(input: Omit<ScanDraftInput, "coverage">): string {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  return createHash("sha256").update(JSON.stringify(snapshot)).digest("hex") + ".json";
}

function withoutPreviousFindings(finding: JsonObject): JsonObject {
  const result = structuredClone(finding);
  if (isObject(result.provenance)) delete result.provenance.previousFindings;
  return result;
}

/** Preserve both original sources and details synthesized after those sources. */
export function preserveFindingDetails(current: JsonObject, previous: JsonObject): void {
  if (current.identity === undefined && previous.identity !== undefined) {
    current.identity = structuredClone(previous.identity);
  }
  const provenance = requireObject(current.provenance, "saved finding provenance");
  const oldProvenance = isObject(previous.provenance) ? previous.provenance : {};
  for (const field of ["sourceFindingIds", "sourceFindings", "previousFindings", "originalCandidates"] as const) {
    const values = exactUnion(
      Array.isArray(provenance[field]) ? provenance[field] : [],
      Array.isArray(oldProvenance[field]) ? oldProvenance[field] : [],
    );
    if (values.length) provenance[field] = values;
  }
  if (!containsSavedFinding(current, previous)) {
    const original = withoutPreviousFindings(previous);
    if (isObject(original.provenance)) delete original.provenance.sourceFindings;
    provenance.previousFindings = exactUnion(
      Array.isArray(provenance.previousFindings) ? provenance.previousFindings : [], [original],
    );
  }
}

function containsSavedFinding(current: JsonObject, previous: JsonObject): boolean {
  const original = withoutPreviousFindings(previous);
  if (current.identity === undefined) delete original.identity;
  return containsSavedValue(current, original);
}

function containsSavedValue(current: unknown, previous: unknown): boolean {
  if (Array.isArray(previous)) {
    return Array.isArray(current) && previous.every((value) => current.some((entry) => containsSavedValue(entry, value)));
  }
  if (isObject(previous)) {
    return isObject(current) && Object.entries(previous).every(([key, value]) => containsSavedValue(current[key], value));
  }
  return current === previous;
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
  if (identity) return JSON.stringify([finding.ruleId, identity.anchor, identity.instance ?? null]);
  const location = (finding.locations as JsonObject[])[0]!;
  return JSON.stringify([finding.ruleId, location.path, location.startLine, location.endLine ?? null]);
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
            : context.scope ?? ".",
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
      ...finding, identity: { ...identity },
    };
    do {
      distinct.identity.instance = `${baseInstance}-${suffix}`;
      suffix += 1;
    } while (reserved.has(scanFindingIdentity(distinct)) || used.has(scanFindingIdentity(distinct)));
    const provenance = finding.provenance as JsonObject;
    distinct.provenance = {
      ...provenance,
      preservedIdentity: provenance.preservedIdentity ?? structuredClone(identity),
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
  const surfaces = semanticCoverage.surfaces as JsonObject[];
  const reservedSurfaceIds = new Set(
    surfaces.flatMap((surface) =>
      typeof surface.id === "string" ? [surface.id] : [],
    ),
  );
  const surfaceIds = new Set<string>();
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
    return {
      ...surface,
      id,
      receiptRefs: surface.receiptRefs ?? [],
    };
  });
  const deferred = semanticCoverage.deferred as JsonObject[];
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
    if (typeof item.id === "string") return item;

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
    return { ...item, id };
  });
  const openQuestions = semanticCoverage.openQuestions as
    | Array<string | JsonObject>
    | undefined;

  return {
    ...semanticCoverage,
    mode: coverageMode(context, contract),
    inventoryStrategy: inventoryStrategy(context, scope, target),
    includePaths: scope.includePaths,
    excludePaths: scope.excludePaths,
    surfaces: normalizedSurfaces,
    deferred: normalizedDeferred,
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
