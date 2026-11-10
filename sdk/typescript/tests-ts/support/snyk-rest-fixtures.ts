import { isolatedGitReportFixture } from "../external-findings-local-helpers.js";
import { canonicalJson } from "../../src/record.js";
import {
  SNYK_REST_ISSUES_FORMAT,
  type CollectSnykIssuesOptions,
  type SnykIssuesExport,
  type SnykIssuesProduct,
} from "../../src/snyk-rest-findings.js";

export const snykOptions = {
  apiOrigin: "https://api.eu.snyk.io",
  organizationId: "11111111-1111-4111-8111-111111111111",
  projectId: "22222222-2222-4222-8222-222222222222",
  sourceRepositoryUrl: "https://github.com/example/repository",
  product: "open-source",
} satisfies CollectSnykIssuesOptions;

export function snykLocalFixture(checkout?: { remote?: string }) {
  return isolatedGitReportFixture(
    "snyk.json",
    { provider: "snyk", sourceKey: snykOptions.projectId },
    checkout,
  );
}

export function snykProject(
  manager = "npm",
  url = snykOptions.sourceRepositoryUrl,
) {
  return {
    data: {
      type: "project",
      id: snykOptions.projectId,
      attributes: {
        type: manager,
        origin: "github",
        target_file: "app/package.json",
      },
      relationships: {
        organization: { data: { type: "org", id: snykOptions.organizationId } },
        target: {
          data: {
            type: "target",
            id: "33333333-3333-4333-8333-333333333333",
            attributes: { url },
          },
        },
      },
    },
  };
}

export function snykIssue(code: boolean, projectId = snykOptions.projectId) {
  const representation = code
    ? {
        sourceLocation: {
          file: "src/app.ts",
          region: { start: { line: 3 } },
          commit_id: "abc123",
        },
      }
    : { dependency: { package_name: "example-lib", package_version: "1.0.0" } };
  return {
    type: "issue",
    id: "44444444-4444-4444-8444-444444444444",
    attributes: {
      key: "opaque-issue-key",
      type: code ? "code" : "package_vulnerability",
      title: "Synthetic finding",
      status: "open",
      ignored: true,
      effective_severity_level: "high",
      updated_at: "2026-01-01T00:00:00Z",
      problems: [{ type: "rule", id: "sample-rule" }],
      coordinates: [{ state: "open", representations: [representation] }],
    },
    relationships: {
      organization: {
        data: { type: "organization", id: snykOptions.organizationId },
      },
      scan_item: { data: { type: "project", id: projectId } },
    },
  };
}

/** A complete project response and issue page saved by the Snyk collector. */
export function snykRestFixture(
  product: SnykIssuesProduct,
  { sourceRepositoryUrl = snykOptions.sourceRepositoryUrl } = {},
): SnykIssuesExport {
  const code = product === "code";
  return {
    ...snykOptions,
    product,
    sourceRepositoryUrl,
    format: SNYK_REST_ISSUES_FORMAT,
    apiVersion: "2026-03-25",
    complete: true,
    projectJson: canonicalJson(
      snykProject(code ? "sast" : "npm", sourceRepositoryUrl).data,
    ),
    targetJson: "null",
    pages: [
      {
        startingAfter: null,
        responseJson: canonicalJson({ data: [snykIssue(code)] }),
      },
    ],
  };
}
