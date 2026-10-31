import { hash } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { CodexSecurityError } from "./errors.js";
import type { ExternalFinding } from "./external-findings.js";
import type { ImportSource } from "./external-import-models.js";
import { canonicalJson } from "./record.js";

const format = "security.findings.v1";
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
    format: z.literal(format),
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
      throw new CodexSecurityError(
        `Finding ${JSON.stringify(source_finding_id)} exceeds the private import record limit.`,
      );
    return record;
  });
  const bytes = canonicalJson({ format, findings: records });
  if (Buffer.byteLength(bytes) > limits.max_direct_file_bytes)
    throw new CodexSecurityError(
      "The selected report exceeds the Cloud direct-upload limit. Split this selection.",
    );
  return { bytes, digest: hash("sha256", bytes) };
}

const checkpointSchema = z.object({
  apiBaseUrl: z.string(),
  accountId: z.string(),
  contextVersion: z.string(),
  sha256: z.string(),
  source: z.object({ provider: z.string(), source_key: z.string() }),
  repository: z.object({ id: z.string(), repo_connector_id: z.string() }),
  uploadRequestId: z.uuid(),
  jobRequestId: z.uuid(),
  fileId: fileId.optional(),
  jobId: jobSchema.shape.id.optional(),
  receipt: jobSchema.optional(),
});

export function readPrivateCheckpoint(
  serialized: string,
  expected: {
    apiBaseUrl: string;
    accountId: string;
    contextVersion: string;
    sha256: string;
    source: ImportSource;
    repository: { id: string; repo_connector_id: string };
  },
) {
  const checkpoint = checkpointSchema.parse(JSON.parse(serialized));
  const { uploadRequestId, jobRequestId, fileId, jobId, receipt, ...binding } =
    checkpoint;
  if (
    canonicalJson({ ...binding, contextVersion: expected.contextVersion }) !==
      canonicalJson(expected) ||
    (jobId && !fileId) ||
    (receipt &&
      (receipt.id !== jobId ||
        receipt.request_id !== jobRequestId ||
        receipt.input.file_id !== fileId)) ||
    uploadRequestId === jobRequestId
  )
    throw new CodexSecurityError(
      "Saved private import does not match this account, repository or report.",
    );
  return checkpoint;
}

export class PrivateImportRequestError extends CodexSecurityError {
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
  async function request(path: string, body?: FormData | string) {
    const timeout = AbortSignal.timeout(body === undefined ? 30_000 : 60_000);
    const response = await fetch(`${base}/finding-imports/${path}`, {
      method: body === undefined ? "GET" : "POST",
      body,
      redirect: "error",
      headers: {
        Authorization: `Bearer ${credentials.access_token}`,
        "ChatGPT-Account-ID": credentials.account_id,
        Accept: "application/json",
        ...(typeof body === "string"
          ? { "Content-Type": "application/json" }
          : {}),
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
      throw new PrivateImportRequestError(
        response.status,
        detail?.code,
        `Private import failed (HTTP ${response.status}): ${detail?.message ?? detail?.code ?? response.statusText}`,
      );
    }
    return response;
  }
  return {
    async context() {
      return contextSchema.parse(await (await request("context")).json());
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
          response = await request(`file-requests/${input.requestId}`);
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
        response = await request("files", form);
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
        source: ImportSource;
        repository: { id: string; repo_connector_id: string };
        jobId?: string;
      },
      accepted: (id: string) => Promise<void>,
    ) {
      let id = input.jobId;
      let response = id
        ? await request(`jobs/${id}`)
        : await request(
            "jobs",
            JSON.stringify({
              request_id: input.requestId,
              context_version: input.contextVersion,
              source: input.source,
              input: { type: "file", file_id: input.fileId, format },
              default_targets: [
                {
                  type: "repository",
                  repo_id: input.repository.id,
                  repo_connector_id: input.repository.repo_connector_id,
                },
              ],
            }),
          );
      for (;;) {
        const job = jobSchema.parse(await response.json());
        if (
          (id !== undefined && job.id !== id) ||
          job.request_id !== input.requestId ||
          job.input.file_id !== input.fileId ||
          job.source.provider !== input.source.provider ||
          job.source.source_key !== input.source.source_key ||
          job.default_targets.length !== 1 ||
          job.default_targets[0]?.repo_id !== input.repository.id ||
          job.default_targets[0]?.repo_connector_id !==
            input.repository.repo_connector_id
        )
          throw new CodexSecurityError(
            "Cloud returned a job for a different private import.",
          );
        if (!id) {
          id = job.id;
          await accepted(id);
        }
        if (
          job.status === "completed" ||
          job.status === "failed" ||
          job.status === "cancelled"
        )
          return job;
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
        response = await request(`jobs/${id}`);
      }
    },
  };
}
