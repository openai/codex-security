import { hash } from "node:crypto";
import type { ExternalPublicationPreview } from "./external-findings-publish.js";
import { canonicalJson } from "./record.js";

/** Bind reviewed evidence to its account, repository, connector and destination version. */
export function cloudReviewDigest(
  preview: ExternalPublicationPreview,
  checkout: string,
  findings?: readonly { id: string; version: number }[],
) {
  return hash(
    "sha256",
    canonicalJson({
      checkout,
      api: preview.cloudApiUrl,
      account: preview.accountId,
      repository: preview.destination.id,
      connector: preview.destination.repo_connector_id,
      url: preview.destination.url,
      reset: preview.destination.reset_marker,
      source: preview.source,
      privateImport: preview.privateImport,
      ...(findings && { findings, excluded: preview.excluded }),
      items: preview.requests.flatMap((request) =>
        request.items.map((item) => [
          item.source_finding_id,
          item.expected_version,
          request.repository.environment_id,
          item.evidence,
        ]),
      ),
    }),
  );
}
