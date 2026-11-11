import { isDeepStrictEqual } from "node:util";
import cloudSchema from "../schemas/external-findings.schema.json" with { type: "json" };
import { CodexSecurityError, errorMessage } from "./errors.js";
import type { Provider } from "./external-import-models.js";
import {
  distinctSourceRepositories,
  recordExternalFindingPublications,
  selectLocalExternalFindings,
  type LocalExternalFindingSelection,
  type LocalFindingReceipt,
  type LocalExternalImportDependencies,
  type StoredExternalFinding,
} from "./external-findings-local.js";
import {
  cloudReviewDigest,
  ExternalPublicationError,
  prepareNormalizedExternalPublication,
  type ExternalPublicationDependencies,
  type ExternalPublicationPreview,
  type ExternalPublicationResult,
  type PreparedExternalPublication,
} from "./external-findings-publish.js";
import {
  NoPublishableFindingsError,
  externalImportDisposition,
  type ExternalFindings,
  type ExternalSourceRepository,
} from "./external-findings.js";
import { projectStoredFinding } from "./stored-finding-projection.js";

type Dependencies = ExternalPublicationDependencies &
  LocalExternalImportDependencies;
type Reference = Pick<
  StoredExternalFinding,
  "id" | "version" | "provider" | "sourceKey" | "sourceFindingId"
>;
type Metadata = Pick<ExternalFindings, "read" | "excluded" | "report">;

export interface StoredFindingsPublicationGroup {
  /** Prepare this selection again to resume the same reviewed source in another process. */
  selection: LocalExternalFindingSelection;
  preview: ExternalPublicationPreview;
  reviewId: string;
  publish(reviewId: string): Promise<ExternalPublicationResult>;
}

export interface StoredFindingsPublication {
  groups: StoredFindingsPublicationGroup[];
  excluded: (Reference & { reason: string })[];
}

function reference({
  id,
  version,
  provider,
  sourceKey,
  sourceFindingId,
}: StoredExternalFinding): Reference {
  return { id, version, provider, sourceKey, sourceFindingId };
}

function cloudProvider(provider: string): provider is Provider {
  return cloudSchema.$defs.ImportSource.properties.provider.enum.includes(
    provider,
  );
}

function cloudSelection(
  rows: StoredExternalFinding[],
  sourceRepositories: readonly ExternalSourceRepository[],
  inspectorMap: ReadonlyMap<string, string> | undefined,
  metadata?: Metadata,
): ExternalFindings {
  const selected: ExternalFindings = {
    read: metadata?.excluded.length ?? 0,
    findings: [],
    excluded: [...(metadata?.excluded ?? [])],
    report: metadata?.report,
  };
  const skipped = new Set(selected.excluded.map((item) => item.position));
  let position = 0;
  for (const row of rows) {
    const projection = projectStoredFinding(
      row,
      sourceRepositories,
      inspectorMap,
    );
    selected.findings.push(...projection.findings);
    selected.read += projection.read;
    const positions = Array.from({ length: projection.read }, () => {
      do {
        position++;
      } while (skipped.has(position));
      return position;
    });
    for (const item of projection.excluded)
      selected.excluded.push({
        ...item,
        position: positions[item.position - 1]!,
        source_finding_id: row.sourceFindingId,
        ...(projection.read > 1 && {
          reason: `Retained trace ${item.position} in ${JSON.stringify(row.sourceFindingId)} (position in stored selection order): ${item.reason}`,
        }),
      });
  }
  // A native source may account for additional input observations, and an agent
  // report may count a grouped occurrence once before its traces are expanded.
  selected.read = Math.max(selected.read, metadata?.read ?? 0);
  selected.excluded.sort((a, b) => a.position - b.position);
  return selected;
}

function receiptRecorder(
  preview: ExternalPublicationPreview,
  rows: StoredExternalFinding[],
  dependencies: Dependencies,
) {
  // Keep only the identifiers needed for receipts. The caller can edit its public preview.
  const pins = new Map(
    rows.map(({ id, version, sourceFindingId }) => [
      sourceFindingId,
      { id, version },
    ]),
  );
  const ready = preview.findings.map((f) => pins.get(f.source_finding_id)!);
  const batches = preview.requests.map(
    ({ items }) =>
      new Map(
        items.map((item) => [
          item.client_id,
          pins.get(item.source_finding_id)!,
        ]),
      ),
  );
  const destination = {
    repository: rows[0]!.repository,
    cloudApiUrl: preview.cloudApiUrl,
    accountId: preview.accountId,
    destinationId: preview.destination.id,
  };
  return async (result: ExternalPublicationResult) => {
    const entries: LocalFindingReceipt[] = [];
    const job = result.privateJob;
    // The private inbox provides job totals, with no per-item outcomes.
    if (
      job?.status === "completed" &&
      !result.counts.error &&
      !result.unacknowledged
    ) {
      for (const pin of ready)
        entries.push({ ...pin, receiptId: job.id, outcome: "private_job" });
    }
    for (const [index, receipt] of result.receipts.entries()) {
      for (const item of receipt.results) {
        if (item.outcome !== "error")
          entries.push({
            ...batches[index]!.get(item.client_id)!,
            receiptId: receipt.id,
            outcome: item.outcome,
            cloudFindingId: item.canonical_finding_id ?? undefined,
          });
      }
    }
    if (!entries.length) return;
    try {
      await recordExternalFindingPublications(
        { ...destination, entries },
        dependencies,
      );
    } catch (error) {
      throw new ExternalPublicationError(
        `Cloud returned receipts, but the workbench could not record them: ${errorMessage(error)}`,
        result,
        error,
      );
    }
  };
}

function prepareSource(
  rows: StoredExternalFinding[],
  options: { repository: string; provider: Provider; sourceKey: string },
  dependencies: Dependencies,
  metadata?: Metadata,
) {
  const references = [...(dependencies.sourceRepositories ?? [])];
  const inspectorProjectMap = new Map<string, string>();
  for (const row of rows) {
    references.push(...(row.provenance?.sourceRepositories ?? []));
    for (const [arn, url] of row.provenance?.inspectorProjectMap ?? []) {
      if (inspectorProjectMap.has(arn) && inspectorProjectMap.get(arn) !== url)
        throw new CodexSecurityError(
          "The selected findings disagree on the Inspector project repository.",
        );
      inspectorProjectMap.set(arn, url);
    }
  }
  const sourceRepositories = distinctSourceRepositories(references);
  return prepareNormalizedExternalPublication(
    cloudSelection(
      rows,
      sourceRepositories,
      inspectorProjectMap.size ? inspectorProjectMap : undefined,
      metadata,
    ),
    { ...options, ...(inspectorProjectMap.size && { inspectorProjectMap }) },
    { ...dependencies, sourceRepositories },
  );
}

/** Preview each source once. Each group's approval can be resumed independently. */
export async function prepareStoredFindingsPublication(
  selection: LocalExternalFindingSelection,
  options: { repository: string },
  dependencies: Dependencies = {},
): Promise<StoredFindingsPublication> {
  const { importId } = selection;
  const stored = await selectLocalExternalFindings(selection, dependencies);
  const groups: StoredFindingsPublicationGroup[] = [];
  const excluded: StoredFindingsPublication["excluded"] = [];
  const bySource = Map.groupBy(stored.findings, ({ provider, sourceKey }) =>
    JSON.stringify([provider, sourceKey]),
  );
  for (const rows of bySource.values()) {
    const { provider, sourceKey, repository } = rows[0]!;
    if (!cloudProvider(provider)) {
      const reason = `The Cloud import contract does not support provider ${JSON.stringify(provider)}.`;
      for (const row of rows) excluded.push({ ...reference(row), reason });
      continue;
    }
    let prepared: PreparedExternalPublication;
    try {
      prepared = await prepareSource(
        rows,
        { ...options, provider, sourceKey },
        dependencies,
        importId === undefined ? undefined : stored,
      );
    } catch (error) {
      if (
        !(error instanceof NoPublishableFindingsError) ||
        externalImportDisposition(error.selection) === "failed"
      )
        throw error;
      appendExclusions(rows, error.selection);
      continue;
    }
    const { preview } = prepared;
    appendExclusions(rows, preview);
    const first = groups[0]?.preview;
    if (
      first &&
      (first.accountId !== preview.accountId ||
        !isDeepStrictEqual(first.destination, preview.destination))
    )
      throw new CodexSecurityError(
        "The Cloud account or repository changed during publication preparation.",
      );
    const findings = rows.map(({ id, version }) => ({ id, version }));
    const reviewId = cloudReviewDigest(preview, repository, findings);
    const record = receiptRecorder(preview, rows, dependencies);
    groups.push({
      selection:
        importId === undefined
          ? { repository, findings }
          : { repository, importId },
      preview,
      reviewId,
      async publish(approvedReviewId) {
        if (approvedReviewId !== reviewId)
          throw new CodexSecurityError(
            "The stored findings publication has changed. Review the new preview before publishing.",
          );
        let recordingStarted = false;
        async function recordOnce(result: ExternalPublicationResult) {
          if (recordingStarted) return;
          recordingStarted = true;
          await record(result);
        }
        let result: ExternalPublicationResult;
        try {
          result = await prepared.publish(recordOnce);
        } catch (error) {
          if (error instanceof ExternalPublicationError)
            await recordOnce(error.result);
          throw error;
        }
        await recordOnce(result);
        return result;
      },
    });
  }
  return { groups, excluded };

  function appendExclusions(
    rows: StoredExternalFinding[],
    projected: ExternalFindings,
  ) {
    const accepted = new Set(
      projected.findings.map((f) => f.source_finding_id),
    );
    const reasons = new Map(
      projected.excluded.map((f) => [f.source_finding_id, f.reason]),
    );
    for (const row of rows) {
      if (!accepted.has(row.sourceFindingId))
        excluded.push({
          ...reference(row),
          reason:
            reasons.get(row.sourceFindingId) ??
            "Excluded by the Cloud publisher.",
        });
    }
  }
}
