import { hash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import {
  normalizeEndorFindings,
  requiresStructuredEndorReport,
} from "./endor-findings.js";
import type { ExternalFinding } from "./external-findings.js";
import {
  SCANNER_IMPORT_MEDIA_TYPE,
  importResponseMediaType,
} from "./external-import-contract.js";
import type { ImportSource } from "./external-import-models.js";
import { canonicalJson, isRecord } from "./record.js";
import { normalizeWizJson } from "./wiz-findings.js";

const structuredFormat = "security.findings.v1";
const privateFormat = z.enum([
  structuredFormat,
  "endor.findings_json.v1",
  "wiz.vulnerability_json.v1",
]);
export type PrivateImportFormat = z.infer<typeof privateFormat>;

const jobVersion = z.union([z.literal(2), z.literal(3)]);
export type PrivateJobVersion = z.infer<typeof jobVersion>;
export const privateJobVersions: Partial<
  Record<ImportSource["provider"], PrivateJobVersion>
> = {
  inspector: 2,
  continuum: 2,
  blackduck: 3,
  checkmarx: 3,
  sonar: 3,
  tenable: 3,
  trivy: 3,
  veracode: 3,
};
const fileId = z.string().regex(/^aifile_[0-9a-f]{32}$/u);
const contextSchema = z.object({
  object: z.literal("security.finding_import_context"),
  context_version: z.string().min(1),
  can_upload: z.boolean(),
  can_create_import_jobs: z.boolean(),
  can_read: z.boolean(),
  formats: z.array(z.string()),
  limits: z.object({
    max_direct_file_bytes: z.int().positive(),
    max_record_bytes: z.int().positive(),
  }),
});
const fileSchema = z.object({
  id: fileId,
  object: z.literal("security.finding_import_file"),
  purpose: z.literal("report"),
  sha256: z.string(),
  bytes: z.int().positive(),
});
const jobSchema = z.object({
  object: z.literal("security.finding_import_job"),
  id: z.string().regex(/^import_[0-9a-f]{32}$/u),
  request_id: z.uuid(),
  source: z.object({ provider: z.string(), source_key: z.string() }),
  input: z.object({
    type: z.literal("file"),
    file_id: fileId,
    format: privateFormat,
  }),
  default_targets: z.array(
    z.object({
      type: z.literal("repository"),
      repo_id: z.string(),
      repo_connector_id: z.string(),
    }),
  ),
  status: z.enum([
    "queued",
    "in_progress",
    "cancelling",
    "completed",
    "failed",
    "cancelled",
  ]),
  counts: z.object({
    total: z.int().nonnegative().nullable(),
    discovered: z.int().nonnegative(),
    created: z.int().nonnegative(),
    updated: z.int().nonnegative(),
    unchanged: z.int().nonnegative(),
    error: z.int().nonnegative(),
    unprocessed: z.int().nonnegative(),
  }),
  poll_after_seconds: z.int().positive().nullable(),
  error: z.object({ message: z.string() }).nullable(),
});

export type PrivateImportContext = z.infer<typeof contextSchema>;
export type PrivateImportJob = z.infer<typeof jobSchema>;

class PrivateReportSizeError extends CodexSecurityError {}

export function privateReport(
  findings: ExternalFinding[],
  limits: PrivateImportContext["limits"],
) {
  if (findings.length > 10_000)
    throw new CodexSecurityError(
      "A structured report accepts up to 10,000 findings. Split this selection.",
    );
  const records = findings.map(({ source_finding_id, evidence }) => {
    if (source_finding_id !== source_finding_id.trim())
      throw new CodexSecurityError(
        "A private source finding ID cannot have leading or trailing whitespace.",
      );
    const record = {
      source_finding_id,
      evidence: {
        ...evidence,
        severity: evidence.severity === "unknown" ? null : evidence.severity,
        locations: evidence.locations?.map(({ path, line }, index) => ({
          path,
          start_line: line,
          ...(index === 0 && evidence.details?.code?.end_line != null
            ? { end_line: evidence.details.code.end_line }
            : {}),
        })),
      },
    };
    if (Buffer.byteLength(canonicalJson(record)) > limits.max_record_bytes)
      throw new PrivateReportSizeError(
        `Finding ${JSON.stringify(source_finding_id)} exceeds the private import record limit.`,
      );
    return record;
  });
  const bytes = canonicalJson({ format: structuredFormat, findings: records });
  if (Buffer.byteLength(bytes) > limits.max_direct_file_bytes)
    throw new PrivateReportSizeError(
      "The selected report exceeds the Cloud direct-upload limit. Split this selection.",
    );
  return {
    format: structuredFormat as PrivateImportFormat,
    bytes,
    digest: hash("sha256", bytes),
  };
}

/** Encode only the reviewed occurrences, whether they came from a file or the workbench. */
export function selectPrivateReport(
  findings: ExternalFinding[],
  provider: string,
  context: PrivateImportContext,
  approvedFormat?: PrivateImportFormat,
): ReturnType<typeof privateReport> {
  const nativeFormat =
    provider === "endor"
      ? "endor.findings_json.v1"
      : provider === "wiz"
        ? "wiz.vulnerability_json.v1"
        : undefined;
  let format =
    approvedFormat ??
    (context.formats.includes(structuredFormat)
      ? structuredFormat
      : nativeFormat);
  let sizeError: PrivateReportSizeError | undefined;
  if (!nativeFormat || !format || format === structuredFormat) {
    try {
      return privateReport(findings, context.limits);
    } catch (error) {
      if (
        !(error instanceof PrivateReportSizeError) ||
        approvedFormat ||
        !nativeFormat ||
        !context.formats.includes(nativeFormat)
      )
        throw error;
      sizeError = error;
      format = nativeFormat;
    }
  }
  if (!approvedFormat && !context.formats.includes(format))
    throw new CodexSecurityError(
      "Private findings import is unavailable for this report format.",
    );

  // The native endpoint derives its own evidence. Verify that it will receive
  // the selected occurrences with exactly the fields the user reviewed.
  const rows = findings.map(({ evidence }) => evidence.source_data);
  const endor = provider === "endor";
  const payload = endor ? { list: { objects: rows } } : rows;
  let totalRowBytes = 0;
  if (
    format === nativeFormat &&
    findings.length > 0 &&
    findings.length <= 10_000 &&
    rows.every((row, i) => {
      if (!isRecord(row)) return false;
      const id = findings[i]!.source_finding_id;
      const bytes = Buffer.byteLength(canonicalJson(row));
      totalRowBytes += bytes;
      return (
        row[endor ? "uuid" : "id"] === id &&
        id === id.trim() &&
        (endor || !("source_finding_id" in row)) &&
        bytes <= context.limits.max_record_bytes &&
        totalRowBytes <= context.limits.max_direct_file_bytes
      );
    })
  ) {
    const projected = endor
      ? normalizeEndorFindings(payload)
      : normalizeWizJson(payload, "cloud");
    if (
      !projected.excluded.length &&
      !requiresStructuredEndorReport(projected) &&
      projected.findings.length === findings.length &&
      projected.findings.every(
        (row, i) =>
          row.source_finding_id === findings[i]!.source_finding_id &&
          canonicalJson(row.evidence) === canonicalJson(findings[i]!.evidence),
      )
    ) {
      const bytes = canonicalJson(payload);
      if (Buffer.byteLength(bytes) <= context.limits.max_direct_file_bytes)
        return { format, bytes, digest: hash("sha256", bytes) };
    }
  }
  if (sizeError) throw sizeError;
  throw new CodexSecurityError(
    `The selection cannot be represented exactly within the limits of ${nativeFormat}. This Cloud service must support ${structuredFormat} to publish it.`,
  );
}

const checkpointSchema = z.object({
  format: privateFormat,
  apiBaseUrl: z.string(),
  accountId: z.string(),
  contextVersion: z.string(),
  sha256: z.string(),
  source: jobSchema.shape.source,
  repository: z.object({ id: z.string(), repo_connector_id: z.string() }),
  uploadRequestId: z.uuid(),
  jobRequestId: z.uuid(),
  jobApiVersion: jobVersion.optional(),
  approvedRepositoryUrl: z.string(),
  approvedRepositoryPlatform: z.literal("other").optional(),
  fileId: fileId.optional(),
  jobId: jobSchema.shape.id.optional(),
  receipt: jobSchema
    .refine((job) => job.status === "completed" || unsuccessfulJob(job))
    .optional(),
  previousReceipt: jobSchema.refine(unsuccessfulJob).optional(),
});

function matchesJobScope(
  job: PrivateImportJob,
  scope: Pick<
    z.infer<typeof checkpointSchema>,
    "format" | "source" | "repository"
  >,
) {
  const [target] = job.default_targets;
  return (
    job.input.format === scope.format &&
    job.source.provider === scope.source.provider &&
    job.source.source_key === scope.source.source_key &&
    job.default_targets.length === 1 &&
    target?.repo_id === scope.repository.id &&
    target.repo_connector_id === scope.repository.repo_connector_id
  );
}

export function unsuccessfulJob(job: PrivateImportJob | undefined) {
  return job?.status === "failed" || job?.status === "cancelled";
}

export function parsePrivateCheckpoint(serialized: string | undefined) {
  return serialized === undefined
    ? undefined
    : checkpointSchema.parse(JSON.parse(serialized));
}

export function readPrivateCheckpoint(
  checkpoint: ReturnType<typeof parsePrivateCheckpoint>,
  expected: {
    format: PrivateImportFormat;
    apiBaseUrl: string;
    accountId: string;
    contextVersion: string;
    sha256: string;
    source: ImportSource;
    repository: { id: string; repo_connector_id: string };
  },
) {
  if (!checkpoint) return;
  const { fileId, jobId, receipt, previousReceipt } = checkpoint;
  const { apiBaseUrl, accountId, source, repository } = checkpoint;
  const { contextVersion, format, sha256, ...scope } = expected;
  const sameContext = checkpoint.contextVersion === contextVersion;
  if (
    canonicalJson({ apiBaseUrl, accountId, source, repository }) !==
      canonicalJson(scope) ||
    (sameContext &&
      (checkpoint.format !== format || checkpoint.sha256 !== sha256)) ||
    (jobId && !fileId) ||
    [receipt, previousReceipt].some(
      (job) => job && !matchesJobScope(job, checkpoint),
    ) ||
    (receipt &&
      (receipt.id !== jobId ||
        receipt.request_id !== checkpoint.jobRequestId ||
        receipt.input.file_id !== fileId)) ||
    checkpoint.uploadRequestId === checkpoint.jobRequestId
  )
    throw new CodexSecurityError(
      "Saved private import does not match this account, repository or report.",
    );
  return sameContext ? checkpoint : undefined;
}

class PrivateImportRequestError extends CodexSecurityError {
  constructor(
    readonly status: number,
    readonly code: string | undefined,
    message: string,
  ) {
    super(message);
  }
}

export function privateImportClient(
  base: string,
  credentials: { access_token: string; account_id: string },
  fetch: (url: string, options: RequestInit) => Promise<Response>,
  signal?: AbortSignal,
) {
  async function request(
    path: string,
    body?: FormData | string,
    mediaType = "application/json",
  ) {
    const timeout = AbortSignal.timeout(body === undefined ? 30_000 : 60_000);
    const response = await fetch(`${base}${path}`, {
      method: body === undefined ? "GET" : "POST",
      body,
      redirect: "error",
      headers: {
        Authorization: `Bearer ${credentials.access_token}`,
        "ChatGPT-Account-ID": credentials.account_id,
        Accept: mediaType,
        ...(typeof body === "string" ? { "Content-Type": mediaType } : {}),
      },
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => undefined);
      const error = z
        .object({
          error: z.object({ code: z.string(), message: z.string().optional() }),
        })
        .safeParse(payload);
      const detail = error.data?.error;
      const retryAfter = response.headers.get("Retry-After");
      let message = `Private import failed (HTTP ${response.status}): ${detail?.message ?? detail?.code ?? response.statusText}`;
      if (retryAfter) message += ` Retry-After: ${retryAfter}.`;
      throw new PrivateImportRequestError(
        response.status,
        detail?.code,
        message,
      );
    }
    if (
      mediaType === SCANNER_IMPORT_MEDIA_TYPE &&
      importResponseMediaType(response) !== SCANNER_IMPORT_MEDIA_TYPE
    )
      throw new CodexSecurityError(
        "Cloud returned an unexpected media type for the private import job.",
      );
    return response;
  }
  return {
    async context() {
      return contextSchema.parse(
        await (await request("/finding-imports/context")).json(),
      );
    },
    async upload(input: {
      requestId: string;
      contextVersion: string;
      bytes: string;
      digest: string;
      recovering: boolean;
    }) {
      let response: Response | undefined;
      if (input.recovering) {
        try {
          response = await request(
            `/finding-imports/file-requests/${input.requestId}`,
          );
        } catch (error) {
          if (
            !(error instanceof PrivateImportRequestError) ||
            (error.status !== 404 &&
              !(error.status === 409 && error.code === "upload_retryable"))
          )
            throw error;
        }
      }
      if (!response) {
        const form = new FormData();
        form.set("request_id", input.requestId);
        form.set("context_version", input.contextVersion);
        form.set("purpose", "report");
        form.set(
          "file",
          new Blob([input.bytes], { type: "application/json" }),
          "findings.json",
        );
        response = await request("/finding-imports/files", form);
      }
      const file = fileSchema.parse(await response.json());
      if (
        file.sha256 !== input.digest ||
        file.bytes !== Buffer.byteLength(input.bytes)
      )
        throw new CodexSecurityError(
          "The uploaded file does not match the reviewed report.",
        );
      return file.id;
    },
    async job(
      input: {
        requestId: string;
        contextVersion: string;
        fileId: string;
        format: PrivateImportFormat;
        source: ImportSource;
        repository: { id: string; repo_connector_id: string };
        jobId?: string;
        apiVersion: "current" | 1 | PrivateJobVersion;
      },
      accepted: (id: string) => Promise<void>,
    ) {
      const { apiVersion } = input;
      const prefix =
        apiVersion === 2 || apiVersion === 3 ? `/v${apiVersion}` : "";
      const jobs = prefix + "/finding-imports/jobs";
      const mediaType =
        apiVersion === "current"
          ? SCANNER_IMPORT_MEDIA_TYPE
          : "application/json";
      const readJob = (id: string) =>
        request(`${jobs}/${id}`, undefined, mediaType);
      let id = input.jobId;
      let response = id
        ? await readJob(id)
        : await request(
            jobs,
            JSON.stringify({
              request_id: input.requestId,
              context_version: input.contextVersion,
              source: input.source,
              input: {
                type: "file",
                file_id: input.fileId,
                format: input.format,
              },
              default_targets: [
                {
                  type: "repository",
                  repo_id: input.repository.id,
                  repo_connector_id: input.repository.repo_connector_id,
                },
              ],
            }),
            mediaType,
          );
      for (;;) {
        const job = jobSchema.parse(await response.json());
        if (
          (id !== undefined && job.id !== id) ||
          job.request_id !== input.requestId ||
          job.input.file_id !== input.fileId ||
          !matchesJobScope(job, input)
        )
          throw new CodexSecurityError(
            "Cloud returned a job for a different private import.",
          );
        if (job.status === "completed" || unsuccessfulJob(job)) return job;
        if (!id) {
          id = job.id;
          await accepted(id);
        }
        const retry = response.headers.get("Retry-After");
        const seconds = retry === null ? 0 : Number(retry);
        await delay(
          Math.max(
            Number.isFinite(seconds) ? seconds : 0,
            job.poll_after_seconds ?? 1,
          ) * 1000,
          undefined,
          { signal },
        );
        response = await readJob(id);
      }
    },
  };
}
