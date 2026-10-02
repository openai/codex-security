import {
  containsSavedFinding,
  containsSavedValue,
  exactUnion,
  isObject,
  preserveFindingDetails,
  requireObject,
  scanFindingIdentity,
  validateCoverageSemantics,
  validateFindingSemantics,
  semanticScanDraft,
  type SemanticCoverage,
  type SemanticScan,
} from "../../../../sdk/typescript/src/scan-semantics.js";
export {
  preserveFindingDetails,
  scanFindingIdentity,
} from "../../../../sdk/typescript/src/scan-semantics.js";
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { dirname, join, sep } from "node:path";
import type * as z from "zod/v4";
import commonSchema from "../../schemas/definitions/artifact-common.schema.json";
import scanDraftDocument from "../../schemas/tools/scan-draft.schema.json";
import type { ArtifactContext } from "./artifact-context.js";
import {
  artifactDestination,
  readArtifactText,
  replaceArtifactJson,
  replaceArtifactText,
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

const schemaDocuments = [commonSchema, scanDraftDocument] as SchemaDocument[];

export const scanDraftInputSchema = loadArtifactZodSchema(
  schemaDocuments,
  scanDraftDocument.$id,
  "scanDraftInput",
) as z.ZodType<ScanDraftInput>;

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

export async function saveScanDraftCheckpoint(
  context: ArtifactContext,
  input: Omit<ScanDraftInput, "coverage">,
  updateHead = true,
): Promise<void> {
  const { handoffClaimToken: _claim, ...snapshot } = input;
  const contents =
    context.layout === "worker"
      ? JSON.stringify(snapshot, null, 2) + "\n"
      : JSON.stringify(snapshot);
  const name = scanDraftCheckpointName(input);
  const destination = await artifactDestination(
    context,
    ["checkpoints", name],
    "scan checkpoint",
  );
  if (context.layout !== "worker") {
    const historyRoot = dirname(destination);
    const pending = await lstatIfExists(join(historyRoot, "pending"));
    // Pre-index scans still need their unpublished history on retries.
    const legacyHistory =
      pending === undefined &&
      (await fs.readdir(historyRoot)).some((entry) => entry.endsWith(".json"));
    if (!legacyHistory) {
      const marker = await artifactDestination(
        context,
        ["checkpoints", "pending", name],
        "scan checkpoint marker",
      );
      await replaceArtifactText(marker, "");
    }
  }
  try {
    const existing = await fs.readFile(destination, "utf8");
    if (
      existing !== contents &&
      existing !== JSON.stringify(snapshot, null, 2) + "\n"
    )
      throw new Error(
        "scan checkpoint: existing content does not match its digest.",
      );
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    await replaceArtifactText(destination, contents);
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
): Promise<{
  input: ScanDraftInput;
  previousDigest: string;
  checkpointIds: string[];
}> {
  const currentCheckpointName = scanDraftCheckpointName(input);
  if (saveCheckpoint) await saveScanDraftCheckpoint(context, input, false);
  let result = structuredClone(input as SemanticScan);
  const previousState = await readPreviousScanDraft(context);
  const previous = previousState.input;
  if (previous && previous.scanId !== input.scanId)
    throw new Error(
      "scan checkpoint: saved result belongs to a different scan.",
    );
  const current = await readCurrentCheckpoints(context, currentCheckpointName);
  const inputs = current.map(({ input }) => input);
  const archived =
    context.layout === "worker"
      ? await readArchivedWorkerCheckpoints(context)
      : [];
  const sources = (
    previous ? [previous, ...inputs, ...archived] : [...inputs, ...archived]
  ) as SemanticScan[];
  if (input.complete === false) {
    const final = sources.find((source) => source.complete !== false);
    if (final) {
      result = structuredClone(final);
    }
  }
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
  if (saveCheckpoint) await saveScanDraftCheckpoint(context, result);
  return {
    input: result,
    previousDigest: previousState.digest,
    checkpointIds: current.map(({ name }) => name),
  };
}

async function readCurrentCheckpoints(
  context: ArtifactContext,
  excludedCheckpoint: string,
): Promise<Array<{ name: string; input: ScanDraftInput }>> {
  const root = join(context.root, "checkpoints", "pending");
  const metadata = await lstatIfExists(root);
  if (context.layout === "worker") {
    const inputs = await readLegacyCheckpoints(context, excludedCheckpoint);
    return inputs.map((input) => ({
      name: scanDraftCheckpointName(input),
      input,
    }));
  }
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
  const checkpoints: Array<{ name: string; input: ScanDraftInput }> = [];
  for (const entry of await fs.readdir(root, { withFileTypes: true })) {
    if (!entry.name.endsWith(".json") || entry.name === excludedCheckpoint)
      continue;
    // Markers precede history writes and can be acknowledged while we read.
    let contents = await readOptionalArtifactText(
      context,
      ["checkpoints", entry.name],
      "current scan checkpoint",
    );
    if (contents === undefined) {
      const stagedPath = await readOptionalArtifactText(
        context,
        ["checkpoints", "pending", entry.name],
        "current scan checkpoint marker",
      );
      if (stagedPath) {
        if (!/^drafts\/[0-9a-fA-F-]+\.checkpoint\.json$/u.test(stagedPath))
          throw new Error("scan checkpoint: invalid staged checkpoint path.");
        contents = await readOptionalArtifactText(
          context,
          stagedPath.split("/"),
          "staged scan checkpoint",
        );
        if (
          contents !== undefined &&
          createHash("sha256").update(contents).digest("hex") + ".json" !==
            entry.name
        )
          throw new Error("scan checkpoint: staged checkpoint digest changed.");
      }
    }
    if (contents === undefined) continue;
    const input = parseCanonicalPersistedScanDraft(
      parseJsonObject(contents, "current scan checkpoint"),
    );
    if (input.scanId !== context.scanId)
      throw new Error(
        "scan checkpoint: current checkpoint belongs to a different scan.",
      );
    checkpoints.push({ name: entry.name, input });
  }
  return checkpoints;
}

async function readLegacyCheckpoints(
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
  return {
    digest,
    input: parseCanonicalPersistedScanDraft(
      semanticScanDraft(
        context.scanId!,
        scan,
        findings.findings as JsonObject[],
        coverage,
      ) as unknown as JsonObject,
    ),
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

function resolvedCoverageSurfaceIds(
  coverage: SemanticCoverage,
  sources: SemanticScan[],
): Set<string> {
  const key = (surface: SemanticCoverage["surfaces"][number]) =>
    JSON.stringify([surface.label, surface.riskArea ?? null]);
  const historical = new Map<string, string | null>();
  const previouslyPending = new Set(
    sources.flatMap((source) =>
      source.coverage.surfaces
        .filter((surface) => surface.disposition === "needs_follow_up")
        .map((surface) => surface.id),
    ),
  );
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
      previouslyPending.has(surface.id) &&
      historical.get(surface.id) === key(surface)
        ? [surface.id]
        : [],
    ),
  );
}

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
  return [
    isObject(finding.provenance) ? finding.provenance.candidateId : undefined,
    isObject(finding.extensions) ? finding.extensions.candidateId : undefined,
    isObject(finding.extensions) ? finding.extensions.reportId : undefined,
    isObject(finding.extensions) ? finding.extensions.ledgerRowId : undefined,
  ].find((id): id is string => typeof id === "string" && id.trim().length > 0);
}

export function parseScanDraft(input: unknown): ScanDraftInput {
  const parsed = scanDraftInputSchema.parse(input);
  validateFindingSemantics(parsed.findings as SemanticScan["findings"]);
  validateCoverageSemantics(parsed.coverage as SemanticScan["coverage"]);
  return parsed;
}

function parseCanonicalPersistedScanDraft(
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
