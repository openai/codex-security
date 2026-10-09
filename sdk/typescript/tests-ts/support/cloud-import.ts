import { createHash } from "node:crypto";
import { expect } from "bun:test";
import type {
  CreateImportedScan,
  ImportedScanReceipt,
  ImportDestination,
} from "../../src/cloud-import-models.js";

export const nativeCloudDestination: ImportDestination = {
  environment_id: "env-1",
  environment_name: "Example",
  repository_id: "repo-1",
  repository_full_name: "example/repo",
  repository_remote: "https://github.com/example/repo.git",
  connector_id: "connector-1",
};

export function nativeCloudServer(
  options: {
    destinations?: ImportDestination[];
    accepted?: boolean;
    finalizing?: boolean;
    retentionFailed?: boolean;
    finalizeStatus?: "accepted" | "finalizing";
    failed?: boolean;
    rejectPutOnce?: boolean;
  } = {},
) {
  const calls: { url: string; method: string; body?: BodyInit | null }[] = [];
  let publication: ImportedScanReceipt | undefined;
  let create: CreateImportedScan | undefined;
  let rejected = false;
  const fetch = async (url: string, request: RequestInit) => {
    calls.push({ url, method: request.method!, body: request.body });
    expect((request.headers as Record<string, string>)["Authorization"]).toBe(
      "Bearer synthetic-access-token",
    );
    expect(request.redirect).toBe("error");
    if (url.includes("/destinations"))
      return Response.json({
        protocol_version: 1,
        destinations: options.destinations ?? [nativeCloudDestination],
      });
    if (url.endsWith("/v1")) {
      create = JSON.parse(String(request.body));
      publication ??= {
        protocol_version: 1,
        imported_scan_id: "import-1",
        source: "cli",
        source_scan_id: create!.source_scan_id,
        environment_id: nativeCloudDestination.environment_id,
        repository_id: nativeCloudDestination.repository_id,
        repository_full_name: nativeCloudDestination.repository_full_name,
        repository_remote: create!.repository_remote,
        connector_id: create!.connector_id,
        target_kind: create!.target_kind,
        base_commit: create!.base_commit,
        snapshot_digest: create!.snapshot_digest ?? null,
        upload_status:
          options.finalizing || options.retentionFailed
            ? "finalizing"
            : options.accepted
              ? "accepted"
              : "uploading",
        materialization_status:
          options.failed || options.retentionFailed ? "failed" : "pending",
        dedupe_status: "pending",
        artifacts: create!.artifacts.map((item) => ({
          ...item,
          uploaded: Boolean(
            options.accepted || options.finalizing || options.retentionFailed,
          ),
          download_url: null,
        })),
        created_at: "2026-06-01T00:00:00Z",
        scan_started_at: create!.scan_started_at,
        scan_completed_at: create!.scan_completed_at,
        finalized_at: null,
        finalization_started_at: null,
        materialization_completed_at: null,
        finding_count: null,
        failure_code: options.retentionFailed
          ? "artifact_retention_failed"
          : null,
        status_url: "/api/aardvark/imported-scans/v1/import-1",
      };
    } else if (request.method === "PUT") {
      if (options.rejectPutOnce && !rejected && url.endsWith("findings.json")) {
        rejected = true;
        throw new Error("connection lost");
      }
      const name = url.split("/").at(-1);
      const artifact = publication!.artifacts.find(
        (item) => item.name === name,
      )!;
      const contents = request.body as Uint8Array;
      expect(createHash("sha256").update(contents).digest("hex")).toBe(
        artifact.sha256,
      );
      expect(contents.byteLength).toBe(artifact.size_bytes);
      artifact.uploaded = true;
    } else if (url.endsWith("/finalize"))
      publication!.upload_status = options.finalizeStatus ?? "accepted";
    else if (url.endsWith("/retry"))
      publication!.materialization_status = "pending";
    return Response.json(publication);
  };
  return {
    fetch,
    calls,
    get create() {
      return create;
    },
  };
}
