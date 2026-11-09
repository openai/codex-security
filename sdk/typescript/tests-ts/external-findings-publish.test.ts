import boxedNumberCheckpoints from "./fixtures/boxed-number-checkpoints.json" with { type: "json" };
import boxedSonarCheckpoint from "./fixtures/boxed-sonar-checkpoint.json" with { type: "json" };
import {
  snykJson,
  snykPluginExport,
  snykSarif,
} from "./support/snyk-import-fixtures.js";
import {
  opengrepJson,
  opengrepTraceJson,
} from "./support/opengrep-import-fixtures.js";
import {
  normalizeSnykFindingsExport,
  normalizeSnykJson,
  normalizeSnykSarif,
  snykRepositoryUrls,
} from "../src/snyk-findings.js";
import {
  semgrepJson,
  semgrepPercentPathReports,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";
import { sonarGitTestEnvironment } from "./support/sonar-import-fixtures.js";
import {
  normalizeEndorFindings,
  normalizePreviousEndorFindings,
} from "../src/endor-findings.js";
import { createServer, type ServerResponse } from "node:http";
import { execFile } from "node:child_process";
import { hash } from "node:crypto";
import { runInNewContext } from "node:vm";
import * as fs from "node:fs/promises";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { Database } from "bun:sqlite";
import { NoPublishableFindingsError } from "../src/index.js";
import { afterEach, expect, spyOn, test, mock } from "bun:test";
import {
  ExternalPublicationError,
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
  type ExternalPublicationOptions,
  type ExternalPublicationProgress,
  type ExternalPublicationResult,
  type NormalizedExternalPublicationOptions,
  type PreparedExternalPublication,
} from "../src/external-findings-publish.js";
import { canonicalJson } from "../src/record.js";
import {
  normalizeSemgrepPlatformFindings,
  selectSemgrepPlatformFindings,
  semgrepPlatformFormat,
} from "../src/semgrep-platform-findings.js";
import {
  normalizePreviousSemgrepFindings,
  normalizeSemgrepFindings,
} from "../src/semgrep-findings.js";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-collector.js";
import { normalizeSnykIssues } from "../src/snyk-rest-findings.js";
import releasedSnykCheckpoints from "./fixtures/snyk-released-checkpoints.json" with { type: "json" };
import { snykRestFixture } from "./support/snyk-rest-fixtures.js";

import {
  snapshotNormalizedFindings,
  type ExternalFindings,
  type ExternalSourceRepository,
} from "../src/external-findings.js";
import {
  normalizeGitHubAdvisories,
  normalizeGitHubCodeScanningAlerts,
  readGitHubFindings,
} from "../src/github-findings.js";
import {
  privateReport,
  selectPrivateReport,
} from "../src/private-finding-import.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import { normalizeOpenGrepFindings } from "../src/opengrep-findings.js";
import {
  cloudRepositoryUrlKey,
  validateExternalEvidence,
  validateImportRequest,
  validateRepositories,
} from "../src/external-import-contract.js";
import type {
  FindingImportReceipt,
  FindingImportRequest,
  SourceReport,
} from "../src/external-import-models.js";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { normalizeGitHubDependabotAlerts } from "../src/github-dependabot-findings.js";
import { githubDependabotAlert } from "./support/github-dependabot-fixtures.js";
import {
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import {
  normalizePreviousTrivyFindings,
  normalizeTrivyFindings,
} from "../src/trivy-findings.js";
import {
  normalizeInspectorFindings,
  normalizePreviousInspectorFindings,
} from "../src/inspector-findings.js";
import { normalizePreviousContinuumFindings } from "../src/continuum-findings.js";
import {
  trivyReport,
  trivyReportWithManyLocations,
  trivyRepositoryHeader,
} from "./support/trivy-import-fixtures.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  inspectorCodeFinding,
  inspectorReport,
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";
import {
  continuumDetail,
  continuumRepository,
} from "./support/continuum-import-fixtures.js";
import {
  normalizeBlackDuckFindings,
  normalizePreviousBlackDuckFindings,
} from "../src/blackduck-findings.js";
import {
  normalizePreviousVeracodeFindings,
  normalizeVeracodeFindings,
} from "../src/veracode-findings.js";
import {
  veracodeMixedPolicyPage,
  veracodePolicyPage,
  veracodePolicyRow,
} from "./support/veracode-import-fixtures.js";
import {
  blackDuckBomReport,
  blackDuckBomRow,
} from "./support/blackduck-import-fixtures.js";

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});
const options = {
  repository: "repo-example",
  provider: "wiz" as const,
  sourceKey: "tenant-example/vulnerability-finding",
};
const normalized = (id = "vendor-1", severity = "high") => ({
  source_finding_id: id,
  evidence: {
    title: "Example vulnerable package",
    severity,
    source_data: { id },
  },
});

test.each(["local", "cloud"] as const)(
  "checks raw numbers before capturing normalized evidence and reports on %s",
  (target) => {
    const raw = (JSON as JSON & { rawJSON(token: string): unknown }).rawJSON;
    const capture = (metric: unknown, inReport = false) => {
      const data: ExternalFindings = {
        read: 1,
        findings: [
          { ...normalized(), evidence: { title: "Example", severity: "high" } },
        ],
        excluded: [],
      };
      if (inReport) data.report = { metric };
      else data.findings[0]!.evidence.source_data = { metric };
      return snapshotNormalizedFindings(data, undefined, target);
    };
    for (const inReport of [true, false]) {
      for (const token of ["1.0000000000000001", "-1e-400"])
        expect(() => capture(raw(token), inReport)).toThrow("loses precision");
      expect(() => capture(raw("1e400"), inReport)).toThrow("finite JSON");
      expect(() => capture(raw("9007199254740993"), inReport)).toThrow(
        "safe integer",
      );
    }
    expect(capture(raw("12.50E-1")).findings[0]?.evidence.source_data).toEqual({
      metric: 1.25,
    });
    expect(capture(1e-7, true).report).toEqual({ metric: 1e-7 });
    expect(capture(raw('"1.0000000000000001"'), true).report).toEqual({
      metric: "1.0000000000000001",
    });
  },
);

test("Cloud stops before expanding a shared subtree beyond its JSON depth limit", async () => {
  const f = await fixture();
  let reads = 0;
  let subtree: Record<string, unknown> = {
    get score() {
      reads++;
      return 7;
    },
  };
  for (let i = 0; i < 7; i++) subtree = { left: subtree, right: subtree };
  for (let i = 0; i < 20; i++) subtree = { child: subtree };
  const input: ExternalFindings = {
    read: 1,
    findings: [
      {
        source_finding_id: "shared-tree",
        evidence: {
          title: "Shared tree",
          severity: "high",
          source_data: subtree,
        },
      },
    ],
    excluded: [],
  };

  await expect(
    prepareNormalizedExternalPublication(input, options, f.deps),
  ).rejects.toThrow("Cloud JSON depth limit of 20");
  expect(reads).toBe(0);
  expect(f.posts).toHaveLength(0);
  expect(snapshotNormalizedFindings(input).findings).toHaveLength(1);
  expect(reads).toBe(128);
});

test("checks incompatible provider options before Cloud access", async () => {
  const f = await fixture();
  const parsed = await readVendorFindings(f.file);
  const credentials = mock(async () => {
    throw new Error("Unexpected credential read");
  });
  const deps = { ...f.deps, credentials };
  const incompatible = { ...options, inspectorProjectMap: new Map() };
  const message = "map requires the inspector provider";
  await expect(
    prepareNormalizedExternalPublication(parsed, incompatible, deps),
  ).rejects.toThrow(message);
  await expect(
    prepareExternalPublication(
      join(f.root, "missing.json"),
      incompatible,
      deps,
    ),
  ).rejects.toThrow(message);
  expect(credentials).not.toHaveBeenCalled();
  expect(f.posts).toHaveLength(0);
});

test("Wiz's gzip JSON report retains finding identity, evidence and repository locations", async () => {
  const report = {
    id: "vendor-report-1",
    row: veracodePolicyRow(),
    name: "CVE-2026-0001",
    detailedName: "example-package",
    version: "1.2.3",
    fixedVersion: "1.2.4",
    vendorSeverity: "HIGH",
    detectionMethod: "LIBRARY",
    description: "Reported vulnerable package in the repository lockfile.",
    locationPath: "/pnpm-lock.yaml",
    lastDetectedAt: "2026-01-01T00:00:00Z",
    vulnerableAsset: {
      id: "vendor-repository-branch-1",
      nativeType: "github#repositoryBranch",
      name: "example/project/main",
      cloudProviderURL: "https://github.com/example/project/tree/main",
    },
  };
  const f = await fixture();
  // Wiz can keep the .json filename while compression is enabled.
  await writeFile(
    f.file,
    gzipSync(
      [report, { ...report, id: `veracode-static-policy:${"a".repeat(64)}` }]
        .map((record) => JSON.stringify(record))
        .join("\n"),
    ),
  );
  const parsed = await readVendorFindings(f.file);
  expect(parsed.read).toBe(2);
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]).toMatchObject({
    source_finding_id: report.id,
    evidence: {
      severity: "high",
      packages: [{ name: "example-package", manifest_path: "pnpm-lock.yaml" }],
      locations: [{ path: "pnpm-lock.yaml" }],
      source_updated_at: null,
      code_revision: null,
      source_data: report,
    },
  });
  f.state.repositoryUrl = otherRepository;
  await expect(
    prepareExternalPublication(f.file, options, f.deps),
  ).rejects.toThrow("does not match the selected Cloud repository");
  await expect(
    prepareNormalizedExternalPublication(parsed, options, f.deps),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(0);
  f.state.repositoryUrl = exampleRepository;
  const result = await (
    await prepareExternalPublication(f.file, options, f.deps)
  ).publish();
  expect(result.counts.created).toBe(2);
  expect(result.verified).toBe(2);

  await writeFile(
    f.file,
    JSON.stringify([
      {
        ...report,
        vulnerableAsset: { id: "workload-1", type: "CONTAINER_IMAGE" },
      },
    ]),
  );
  const workload = await readVendorFindings(f.file);
  expect(workload.findings[0]!.evidence.locations).toEqual([]);
  expect(
    workload.findings[0]!.evidence.packages?.[0]?.manifest_path,
  ).toBeNull();
});

test("a Wiz Raw Event export explains the finding-report path before contacting Cloud", async () => {
  const f = await fixture({
    id: "scan-event-1",
    codeAnalyzerDetails: { commit: { ref: "main" } },
    scannersRunStatuses: {
      vulnerabilities: { enabled: true, status: "SUCCESS" },
    },
    analytics: { numVulnerabilityFindings: 3 },
  });
  let contactedCloud = false;
  await expect(
    prepareExternalPublication(f.file, options, {
      ...f.deps,
      fetch: async () => {
        contactedCloud = true;
        throw new Error("Unexpected Cloud request");
      },
    }),
  ).rejects.toThrow("scan metadata rather than vulnerability records");
  expect(contactedCloud).toBe(false);
});

test("Dependabot keeps an older approval when an emitted boxed number excludes a row", async () => {
  const f = await fixture();
  const selection = {
    ...options,
    provider: "github" as const,
    sourceKey: "github.com/example/project/dependabot",
  };
  const a = githubDependabotAlert(1);
  const b = { ...githubDependabotAlert(2), score: new Number(NaN) };
  const prepare = (rows: unknown[], target: "local" | "cloud" = "cloud") =>
    prepareReleased(
      f,
      normalizeGitHubDependabotAlerts(rows, target),
      selection,
    );
  expect((await prepare([a, b])).preview.requests[0]!.items).toHaveLength(1);

  // The released reader admitted both rows and serialized the non-finite wrapper to null.
  const request = {
    ...(await prepare([a, { ...b, score: null }])).preview.requests[0]!,
    request_id: "e1a703b7-7e69-4a6b-a6c5-02ff7a47fd45",
  };
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "c26b480acaefaa832105d472abf05a372c9eb3d7c0749c15700e802466cb4b3a",
  );
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "a79e3af4845c4c7b5e0abffb5ed37054bb2debdf57b8a8b10acf3d7bd36a5e9f.pending.json",
    requests: [request],
    inputDigest:
      "7b23cc522ea792cfa321415c62c5732421fb63f5c1efbba9fa6f81fb086c9e7f",
  });

  for (const target of ["local", "cloud"] as const) {
    await expect(prepare([a, b], target)).rejects.toThrow(
      "checkpoint was preserved",
    );
  }
  expect(f.posts).toHaveLength(0);
  expect(await readFile(path, "utf8")).toBe(saved);
  const changed = {
    ...a,
    security_advisory: { ...a.security_advisory, summary: "Changed advisory" },
  };
  expect((await prepare([changed, b])).preview.resumed).toBe(false);
});

test("Dependabot retries the approved subset when a numeric size correction admits another alert", async () => {
  const f = await fixture();
  const selection = {
    ...options,
    provider: "github" as const,
    sourceKey: "github.com/example/project/dependabot",
  };
  const a = githubDependabotAlert(1);
  const b = {
    ...githubDependabotAlert(2),
    score: new Number(0.00001),
    pad: "",
  };
  const bare = normalizeGitHubDependabotAlerts([b], "cloud").findings[0]!
    .evidence;
  b.pad = "x".repeat(256 * 1024 + 1 - Buffer.byteLength(JSON.stringify(bare)));
  const normalized = normalizeGitHubDependabotAlerts([a, b], "cloud");
  const prepare = () => prepareReleased(f, normalized, selection);
  const fresh = (await prepare()).preview.requests[0]!;
  expect(fresh.items).toHaveLength(2);

  // Recorded from the released reader when only alert 1 fit its size calculation.
  const request = {
    ...fresh,
    request_id: "95af968c-8f7c-4cb5-a79a-561eb06e39e8",
    items: fresh.items.slice(0, 1),
  };
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "bdec6e68ba764e63a60c83e14d7b691b03332c7af1c4ac031c2b5ca1cb92c69f",
  );
  await stageReleasedCheckpoint(f, {
    filename:
      "c99d3e8e89437eeb0462959cc3504183d1c67b8bc5a07bfe0af58da058bca72d.pending.json",
    requests: [request],
    inputDigest:
      "50c57ce23ee63e16bd06580d955f37110cdc827b26b4737c58ae13bfb88c2bca",
  });

  const resumed = await prepare();
  expect(resumed.preview.resumed).toBe(true);
  expect((await resumed.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test("Dependabot publishes on the existing GitHub provider and rejects foreign repositories before POST", async () => {
  const input = { ...githubDependabotAlert(), source: "extra" };
  const correct = await fixture([input]);
  const selection = {
    ...options,
    provider: "github" as const,
    sourceKey: "github.com/example/project/dependabot",
  };
  const first = await prepareExternalPublication(
    correct.file,
    selection,
    correct.deps,
  );
  expect(first.preview.requests[0]!.source.provider).toBe("github");
  expect(correct.posts).toHaveLength(0);
  first.preview.requests[0]!.items[0]!.evidence.url =
    "https://github.com/example/other/security/dependabot/1";
  correct.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow();
  expect(JSON.parse(correct.posts[0]!).items[0].evidence.url).toBe(
    input.html_url,
  );
  const retry = await prepareExternalPublication(
    correct.file,
    selection,
    correct.deps,
  );
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).counts.created).toBe(1);
  expect(correct.posts[1]).toBe(correct.posts[0]);
  const replay = await prepareExternalPublication(
    correct.file,
    selection,
    correct.deps,
  );
  expect((await replay.publish()).counts.unchanged).toBe(1);
  const foreign = await fixture([input], "https://github.com/example/other");
  await expect(
    prepareExternalPublication(foreign.file, selection, foreign.deps),
  ).rejects.toThrow(/does not match/i);
  const native = await readGitHubFindings(correct.file);
  await expect(
    prepareNormalizedExternalPublication(native, selection, foreign.deps),
  ).rejects.toThrow(/does not match/i);
  const projected = structuredClone(native);
  delete projected.findings[0]!.evidence.source_data;
  await expect(
    prepareNormalizedExternalPublication(projected, selection, foreign.deps),
  ).rejects.toThrow(/does not match/i);
  expect(
    (
      await prepareNormalizedExternalPublication(
        projected,
        selection,
        correct.deps,
      )
    ).preview.requests,
  ).toHaveLength(1);
  projected.findings[0]!.evidence.url = input.url;
  projected.findings[0]!.evidence.source_data = {
    security_vulnerability: input.security_vulnerability,
  };
  projected.findings[0]!.source_finding_id = "alert-1";
  const compatible = await prepareNormalizedExternalPublication(
    projected,
    selection,
    correct.deps,
  );
  expect((await compatible.publish()).counts.created).toBe(1);
  expect(
    (
      await (
        await prepareNormalizedExternalPublication(
          projected,
          selection,
          correct.deps,
        )
      ).publish()
    ).counts.unchanged,
  ).toBe(1);
  await expect(
    prepareNormalizedExternalPublication(projected, selection, foreign.deps),
  ).rejects.toThrow(/does not match/i);
  const conflicting = structuredClone(native);
  conflicting.findings[0]!.evidence.url = githubDependabotAlert(2).html_url;
  await expect(
    prepareNormalizedExternalPublication(conflicting, selection, correct.deps),
  ).rejects.toThrow(/alert URL/i);
  const relabeled = structuredClone(native);
  relabeled.findings[0]!.source_finding_id =
    "github.com/example/other/dependabot/2";
  await expect(
    prepareNormalizedExternalPublication(relabeled, selection, foreign.deps),
  ).rejects.toThrow(/source finding ID/i);
  expect(foreign.posts).toHaveLength(0);
});

async function fixture(
  records: unknown = [normalized()],
  repositoryUrl = "https://github.com/example/project",
  repoConnectorId = "github",
) {
  const root = await mkdtemp(join(tmpdir(), "external-findings-"));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  const file = join(root, "selected findings.json");
  await writeFile(file, JSON.stringify(records));
  const environment = {
    ...process.env,

    CODEX_HOME: join(root, "credentials"),
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  await mkdir(environment.CODEX_HOME, { mode: 0o700 });
  await writeFile(
    join(environment.CODEX_HOME, "config.toml"),
    'cli_auth_credentials_store = "file"\n',
  );
  await writeFile(
    join(environment.CODEX_HOME, "auth.json"),
    JSON.stringify({
      tokens: {
        access_token: "synthetic-token",
        account_id: "synthetic-account",
      },
    }),
  );
  const reports = new Map<string, SourceReport>();
  const receipts = new Map<string, FindingImportReceipt>();
  const posts: string[] = [];
  const state = {
    repositoryUrl,
    marker: "generation-1",
    environmentId: "environment-example" as string | null,
    materializeDefaults: false,
    holdReadback: null as (() => void) | null,
    loseResponse: false,
    brokenReadback: false,
    throttle: false,
    catalogReads: 0,
    catalogHeaders: {} as Record<string, string>,
    sourceLookups: [] as string[],
    postBudget: Infinity,
    finalError: false,
  };
  const destination = () => ({
    id: options.repository,
    object: "security.repository",
    repo_connector_id: repoConnectorId,
    url: state.repositoryUrl,
    default_branch: "main",
    reset_marker: state.marker,
    import_environment_id: state.environmentId,
  });
  function json(response: ServerResponse, value: unknown, status = 200) {
    response.writeHead(status, { "Content-Type": "application/json" });
    response.end(JSON.stringify(value));
  }
  const server = createServer(async (incoming, response) => {
    try {
      expect(incoming.headers.authorization).toBe("Bearer synthetic-token");
      expect(incoming.headers["chatgpt-account-id"]).toBe("synthetic-account");
      const url = new URL(incoming.url!, "http://localhost");
      if (url.pathname.endsWith("/repositories")) {
        state.catalogReads++;
        for (const [name, value] of Object.entries(state.catalogHeaders))
          response.setHeader(name, value);
        return json(response, {
          object: "page",
          data: [destination()],
          has_more: false,
          next: null,
        });
      }
      if (url.pathname.endsWith("/source_reports")) {
        const id = url.searchParams.get("source_finding_id")!;
        state.sourceLookups.push(id);
        const report = reports.get(id);
        let summary;
        if (report) {
          const { evidence, last_import: _lastImport, ...rest } = report;
          summary = {
            ...rest,
            object: "security.source_report_summary",
            title: evidence.title,
            severity: evidence.severity,
            source_updated_at: evidence.source_updated_at ?? null,
          };
        }
        return json(response, {
          object: "page",
          data: summary ? [summary] : [],
          has_more: false,
          next: null,
        });
      }
      if (url.pathname.includes("/source_reports/")) {
        if (state.holdReadback) return state.holdReadback();
        if (state.brokenReadback)
          return json(
            response,
            { error: { message: "Readback unavailable" } },
            503,
          );
        const report = [...reports.values()].find(
          (item) =>
            item.id === decodeURIComponent(url.pathname.split("/").at(-1)!),
        );
        if (report && state.materializeDefaults)
          return json(response, {
            ...report,
            evidence: {
              advisory_ids: [],
              locations: [],
              image_digests: [],
              source_data: {},
              ...report.evidence,
              packages: (report.evidence.packages ?? []).map((entry) => ({
                fixed_versions: [],
                ...entry,
              })),
            },
          });
        return json(response, report, report ? 200 : 404);
      }
      if (url.pathname.endsWith("/finding_imports")) {
        let body = "";
        for await (const chunk of incoming) body += chunk;
        posts.push(body);
        const request = validateImportRequest(JSON.parse(body));
        if (state.throttle || state.postBudget === 0) {
          response.setHeader("Retry-After", "1");
          return json(response, { error: { message: "Slow down" } }, 429);
        }
        state.postBudget--;
        if (request.repository.reset_marker !== state.marker)
          return json(
            response,
            { error: { message: "stale_reset_marker" } },
            409,
          );
        let receipt = receipts.get(request.request_id);
        if (!receipt) {
          receipt = {
            id: request.request_id,
            object: "security.finding_import",
            repository: request.repository,
            source: request.source,
            actor: "synthetic-user",
            created_at: 1,
            item_count: request.items.length,
            counts: { created: 0, updated: 0, unchanged: 0, error: 0 },
            results: [],
          };
          for (const item of request.items) {
            const previous = reports.get(item.source_finding_id);
            const scopeConflict =
              previous !== undefined &&
              previous.environment_id !== request.repository.environment_id;
            if (state.finalError || scopeConflict) {
              receipt.counts.error = (receipt.counts.error ?? 0) + 1;
              receipt.results.push({
                client_id: item.client_id,
                outcome: "error",
                source_report_id: null,
                observation_id: null,
                canonical_finding_id: null,
                version: null,
                error: {
                  code: scopeConflict ? "scope_conflict" : "version_conflict",
                  message: scopeConflict
                    ? "Source report belongs to a different Cloud environment"
                    : "Reload current evidence",
                },
              });
              continue;
            }
            const outcome = previous
              ? JSON.stringify(previous.evidence) ===
                JSON.stringify(item.evidence)
                ? "unchanged"
                : "updated"
              : "created";
            if (outcome === "updated")
              expect(item.expected_version).toBe(previous!.version);
            const version = previous
              ? previous.version + (outcome === "updated" ? 1 : 0)
              : 1;
            const identity = hash("sha256", item.source_finding_id);
            const report: SourceReport = {
              id: `aif_${identity}`,
              object: "security.source_report",
              origin: "imported",
              repo_id: request.repository.id,
              repo_connector_id: request.repository.repo_connector_id,
              environment_id: request.repository.environment_id,
              canonical_finding_id: `acf_${identity.slice(0, 32)}`,
              source: request.source,
              source_finding_id: item.source_finding_id,
              observation_id: `aio_${hash("sha256", `${identity}:${version}`)}`,
              version,
              evidence: item.evidence,
              assessment: { state: "not_assessed" },
              last_import: null,
              created_at: 1,
              updated_at: version,
            };
            reports.set(item.source_finding_id, report);
            receipt.counts[outcome] = (receipt.counts[outcome] ?? 0) + 1;
            receipt.results.push({
              client_id: item.client_id,
              outcome,
              source_report_id: report.id,
              observation_id: report.observation_id,
              canonical_finding_id: report.canonical_finding_id,
              version,
              error: null,
            });
          }
          receipts.set(request.request_id, receipt);
        }
        if (state.loseResponse) {
          state.loseResponse = false;
          response.destroy();
          return;
        }
        return json(response, receipt);
      }
      json(response, { error: { message: "Unexpected fixture route" } }, 404);
    } catch (error) {
      json(response, { error: { message: String(error) } }, 500);
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(
    () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections();
      }),
  );
  const port = (server.address() as { port: number }).port;
  const transport = (url: string, init: RequestInit) =>
    fetch(
      `http://127.0.0.1:${port}${new URL(url).pathname}${new URL(url).search}`,
      init,
    );
  const deps = { environment, fetch: transport };
  const cliDeps = { ...dependencies(), environment, cloudFetch: transport };
  const command = [
    "publish",
    "findings",
    file,
    "--to",
    "cloud",
    "--repository",
    options.repository,
    "--provider",
    options.provider,
    "--source-key",
    options.sourceKey,
    "--format",
    "json",
  ];
  return {
    root,
    file,
    reports,
    receipts,
    posts,
    state,
    destination,
    environment,
    port,
    deps,
    cliDeps,
    command,
    async writeCheckpoint(filename: string, checkpoint: unknown) {
      const directory = join(
        environment.CODEX_SECURITY_STATE_DIR,
        "external-finding-publications",
      );
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const path = join(directory, filename);
      await writeFile(path, JSON.stringify(checkpoint), { mode: 0o600 });
      return path;
    },
    async loseResponse(prepared: PreparedExternalPublication) {
      state.loseResponse = true;
      const failure: unknown = await prepared
        .publish()
        .catch((error: unknown) => error);
      if (!(failure instanceof ExternalPublicationError))
        throw new Error("Expected an interrupted publication", {
          cause: failure,
        });
      expect(failure.message).toContain("resume the saved request");
      return failure.result.savedSubmission!;
    },
  };
}

test.each([true, false])(
  "repository severity exclusions keep the approved requests on retry (initial advertisement %s)",
  async (advertised) => {
    const f = await fixture([
      normalized("unreported", "unknown"),
      normalized("invalid", "unsupported"),
      normalized("reported", "high"),
    ]);
    const header = "Codex-Security-Repository-Import-Severities";
    const severities = "critical,high,medium,low,informational";
    if (advertised) f.state.catalogHeaders[header] = severities;
    const prepare = () => prepareExternalPublication(f.file, options, f.deps);
    const first = await prepare();
    const selected = advertised ? ["reported"] : ["unreported", "reported"];
    expect(first.preview.findings.map((f) => f.source_finding_id)).toEqual(
      selected,
    );
    expect(f.state.sourceLookups.sort()).toEqual([...selected].sort());
    expect(first.preview.excluded.map(({ position }) => position)).toEqual(
      advertised ? [1, 2] : [2],
    );
    if (advertised)
      expect(first.preview.excluded[0]?.reason).toContain('severity "unknown"');
    await f.loseResponse(first);
    f.state.catalogHeaders = advertised ? {} : { [header]: severities };
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests).toEqual(first.preview.requests);
    expect(retry.preview.excluded).toEqual(first.preview.excluded);
    const result = await retry.publish();
    expect(result).toMatchObject({
      status: "partial",
      read: 3,
      ready: selected.length,
      verified: selected.length,
      unacknowledged: 0,
    });
    expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
  },
);

test.each([
  "equivalent",
  "other path",
  "raw change",
  "manifest change",
  "URL",
] as const)(
  "direct readback compares qualified literal scanner paths without changing the approved request (%s)",
  async (mode) => {
    const path =
      mode === "URL" ? "https://example.test/file.json" : "schema:prod.json";
    const input = normalized();
    const f = await fixture([
      {
        ...input,
        evidence: {
          ...input.evidence,
          locations: [{ path, line: 5 }],
          packages: [{ name: "example", manifest_path: path }],
          source_data: { original_path: path },
        },
      },
    ]);
    const prepare = () =>
      prepareExternalPublication(f.file, options, {
        ...f.deps,
        fetch: async (url, init) => {
          const response = await f.deps.fetch(url, init);
          if (!new URL(url).pathname.includes("/source_reports/"))
            return response;
          const report = await response.json();
          report.evidence.locations[0].path =
            mode === "other path" ? "./different:file.json" : `./${path}`;
          report.evidence.packages[0].manifest_path =
            mode === "manifest change" ? "different.json" : `./${path}`;
          if (mode === "raw change")
            report.evidence.source_data.original_path = `./${path}`;
          return Response.json(report);
        },
      });
    const first = await prepare();
    await f.loseResponse(first);
    const resumed = await prepare();
    expect(resumed.preview.requests).toEqual(first.preview.requests);
    const result = resumed.publish();
    if (mode === "equivalent") expect((await result).verified).toBe(1);
    else await expect(result).rejects.toThrow("Cloud readback did not match");
    expect(f.posts[1]).toBe(f.posts[0]);
    expect(JSON.parse(f.posts[0]!).items[0].evidence).toMatchObject({
      locations: [{ path }],
      packages: [{ manifest_path: path }],
      source_data: { original_path: path },
    });
  },
);

test("repository severity restrictions exclude unsupported rows before lookups; private imports retain them", async () => {
  const { f, prepareFile } = await privateUploadFixture(
    [normalized("unreported", "unknown")],
    "wiz",
  );
  f.state.catalogHeaders = {
    "Codex-Security-Repository-Import-Severities": "high",
  };
  await expect(prepareFile()).rejects.toMatchObject({
    selection: {
      read: 1,
      findings: [],
      excluded: [{ position: 1, source_finding_id: "unreported" }],
    },
  });
  expect(f.state.catalogReads).toBe(1);
  expect(f.state.sourceLookups).toEqual([]);
  f.state.catalogHeaders["Codex-Security-Private-Import-Providers"] = "wiz";
  const { preview } = await prepareFile();
  expect(preview.privateImport).toBeDefined();
  expect(preview.findings.map(({ evidence }) => evidence.severity)).toEqual([
    "unknown",
  ]);
  expect(preview.excluded).toEqual([]);
  expect(f.posts).toHaveLength(0);
});

test("a zero-record report needs no Cloud account, destination lookup, confirmation, or submission", async () => {
  const f = await fixture([]);
  await rm(f.environment.CODEX_HOME, { recursive: true });
  const fetch = spyOn(f.cliDeps, "cloudFetch");
  const cli = createCliTest(main);
  const code = await cli.runCli(
    [...f.command, "--full-output", "--dry-run"],
    f.cliDeps,
  );
  expect(code, cli.stderr.text()).toBe(0);
  expect(fetch).not.toHaveBeenCalled();
  const { ok, data } = JSON.parse(cli.stdout.text());
  expect(ok).toBe(true);
  expect(data).toMatchObject({
    status: "empty",
    published: false,
    dryRun: true,
    read: 0,
    ready: 0,
    findings: [],
    excluded: [],
  });
  expect(data).not.toHaveProperty("destination");
  expect(data).not.toHaveProperty("accountId");
  await expect(readdir(f.environment.CODEX_SECURITY_STATE_DIR)).rejects.toThrow(
    "ENOENT",
  );
});

test("an empty monitored Snyk capture finishes without an upload after catalog lookup", async () => {
  const report = snykRestFixture("open-source");
  report.pages = [{ startingAfter: null, responseJson: '{"data":[]}' }];
  const f = await fixture(report, report.sourceRepositoryUrl);
  const cli = createCliTest(main);
  const args = f.command.map((arg) => (arg === "wiz" ? "snyk" : arg));
  expect(await cli.runCli(args, f.cliDeps)).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    status: "empty",
    published: false,
  });
  expect(f.posts).toHaveLength(0);
});

test("an entirely excluded report fails with all positions intact and a short diagnostic", async () => {
  const f = await fixture(
    Array.from({ length: 500 }, (_, index) =>
      normalized(`id-\x1b[2J${index}`, "unsupported"),
    ),
  );
  await rm(f.environment.CODEX_HOME, { recursive: true });
  const cli = createCliTest(main);
  expect(
    await cli.runCli([...f.command, "--dry-run", "--full-output"], f.cliDeps),
  ).toBe(2);
  const output = JSON.parse(cli.stdout.text());
  expect(output).toMatchObject({
    ok: false,
    error: { code: "IMPORT_FAILED" },
    data: { status: "failed", read: 500, ready: 0 },
  });
  expect(
    output.data.excluded.map((row: { position: number }) => row.position),
  ).toEqual(Array.from({ length: 500 }, (_, index) => index + 1));
  expect(output.data.excluded.at(-1)).toMatchObject({
    source_finding_id: "id-\x1b[2J499",
    reason: expect.any(String),
  });
  expect(cli.stderr.text()).not.toContain("Item 500");
  expect(output.error.message).not.toContain("Item 500");
  const terminal = createCliTest(main);
  expect(
    await terminal.runCli([...f.command.slice(0, -2), "--yes"], f.cliDeps),
  ).toBe(2);
  expect(terminal.stderr.text()).toContain("Excluded item 1:");
  expect(terminal.stderr.text()).toContain("Showing 5 of 500 exclusions");
  expect(terminal.stderr.text()).not.toContain("Excluded item 6:");
  expect(terminal.stderr.text()).not.toContain("\x1b");
  const flags = [
    ...f.command.slice(0, -1),
    "jsonl",
    "--full-output",
    "--filter-output=findings",
  ];
  const filtered = createCliTest(main);
  expect(await filtered.runCli(flags, f.cliDeps)).toBe(2);
  const failure = JSON.parse(filtered.stdout.text());
  expect(failure.data.excluded).toEqual(output.data.excluded);
  expect(failure.meta.command).toBe("publish findings");
  const limited = createCliTest(main);
  expect(await limited.runCli([...flags, "--token-limit=5"], f.cliDeps)).toBe(
    2,
  );
  expect(JSON.parse(limited.stdout.text())).toMatchObject({
    ok: false,
    data: expect.any(String),
    meta: { nextOffset: 5 },
  });
  expect(f.posts).toHaveLength(0);
});

test("normalized SDK callers can distinguish an empty report from exclusions without authenticating", async () => {
  for (const selection of [
    { read: 0, findings: [], excluded: [] },
    {
      read: 1,
      findings: [],
      excluded: [
        { position: 1, source_finding_id: null, reason: "Not an occurrence" },
      ],
    },
  ]) {
    const prepared = prepareNormalizedExternalPublication(selection, options, {
      environment: {},
      credentials: async () => {
        throw new Error("Unexpected credential read");
      },
    });
    await expect(prepared).rejects.toBeInstanceOf(NoPublishableFindingsError);
    await expect(prepared).rejects.toMatchObject({ selection });
  }
});

test("a failed scanner run is not an empty successful import", async () => {
  const f = await fixture({
    version: "1.100.0",
    results: [],
    errors: [{ message: "example scan error" }],
  });
  const command = f.command.map((argument) =>
    argument === "wiz" ? "semgrep" : argument,
  );
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      [
        ...command,
        "--source-repository-url",
        "https://github.com/example/project",
        "--yes",
      ],
      f.cliDeps,
    ),
  ).toBe(2);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    status: "failed",
    error: expect.stringContaining("scan errors"),
  });
  expect(f.posts).toHaveLength(0);
});

async function hostedFixture(
  provider: "semgrep" | "snyk",
  records: unknown,
  url: string,
  sourceKey = options.sourceKey,
) {
  const cloud = await fixture(records, url);
  const settings = { ...options, provider, sourceKey };
  return {
    ...cloud,
    prepareFile: () =>
      prepareExternalPublication(cloud.file, settings, cloud.deps),
    prepareNormalized: <Input extends ExternalFindings>(
      input: Input,
      selectedProvider: FindingImportRequest["source"]["provider"] = provider,
    ) =>
      prepareNormalizedExternalPublication(
        input,
        { ...settings, provider: selectedProvider },
        cloud.deps,
      ),
  };
}

test.each(["open-source", "code"] as const)(
  "private GitLab SSH %s findings match the catalog through file and SDK imports",
  async (product) => {
    const url = "https://scm.example.test/Team/Project";
    const report = snykRestFixture(product, { sourceRepositoryUrl: url });
    const project = JSON.parse(report.projectJson);
    project.attributes.origin = "gitlab";
    project.relationships.target.data.attributes.url =
      "git@scm.example.test:Team/Project.git";
    report.projectJson = JSON.stringify(project);
    const references: ExternalSourceRepository[] = [
      { url, platform: "gitlab" },
    ];
    const input = normalizeSnykIssues(report, "cloud", references);
    const f = await fixture(report, url);
    const settings = { ...options, provider: "snyk" as const };
    const deps = { ...f.deps, sourceRepositories: references };
    const file = () => prepareExternalPublication(f.file, settings, deps);
    const sdk = () =>
      prepareNormalizedExternalPublication(input, settings, deps);

    for (const wrong of [url.toLowerCase(), url + "-different"]) {
      f.state.repositoryUrl = wrong;
      await expect(file()).rejects.toThrow(/repository|project/iu);
      await expect(sdk()).rejects.toThrow(/repository|project/iu);
    }
    f.state.repositoryUrl = url;
    const differentReader = {
      ...deps,
      sourceRepositories: [
        ...references,
        { url: url.toLowerCase(), platform: "gitlab" as const },
      ],
    };
    await expect(
      prepareExternalPublication(f.file, settings, differentReader),
    ).rejects.toThrow(/repository|project/iu);
    await expect(
      prepareNormalizedExternalPublication(input, settings, differentReader),
    ).rejects.toThrow(/repository|project/iu);
    if (product === "code") {
      const mislabeled = structuredClone(input);
      mislabeled.findings[0]!.evidence.details!.repository!.url =
        url.toLowerCase();
      await expect(
        prepareNormalizedExternalPublication(mislabeled, settings, deps),
      ).rejects.toThrow(/repository|project/iu);
    }
    expect(f.posts).toHaveLength(0);
    expect((await (await file()).publish()).counts.created).toBe(1);
    expect((await (await sdk()).publish()).counts.unchanged).toBe(1);
  },
);

function selectedSemgrepReport(
  project: { name: string; url: string },
  fields: Record<string, unknown>,
  sourceRepositories: readonly ExternalSourceRepository[] = [],
) {
  const ref = "refs/heads/release";
  const finding = {
    id: 23,
    ref,
    repository: { url: project.url },
    severity: "high",
    status: "open",
    ...fields,
  };
  return selectSemgrepPlatformFindings({
    deployment: "example",
    ref,
    projectResponse: JSON.stringify({ project: { id: 14, ...project } }),
    findingsResponses: [JSON.stringify({ findings: [finding] })],
    findingIds: ["23"],
    sourceRepositories,
  });
}

function privateSnykProject() {
  const url = "https://git.example.test/Team/OldProject";
  const capture = snykRestFixture("open-source", { sourceRepositoryUrl: url });
  const project = JSON.parse(capture.projectJson);
  project.attributes.origin = "cli";
  project.relationships.target.data.attributes.url =
    "git@git.example.test:team/oldproject.git";
  capture.projectJson = JSON.stringify(project);
  const report = normalizeSnykIssues(capture, "cloud", [
    { url, platform: "github" },
  ]);
  return { url, capture, report };
}

test("a projected Snyk issue resumes its approved private repository after a rename", async () => {
  const { url, capture, report } = privateSnykProject();
  const renamed = "https://git.example.test/Team/NewProject";
  const row = report.findings[0]!;
  row.evidence.source_data = {
    issueJson: row.evidence.source_data!["issueJson"],
  };
  const f = await hostedFixture("snyk", capture, url);
  await f.loseResponse(await f.prepareNormalized(report));
  f.state.repositoryUrl = renamed;
  const resumed = await f.prepareNormalized(report);
  expect(resumed.preview.resumed).toBe(true);
  await resumed.publish();
  expect(f.posts[1]).toBe(f.posts[0]);
  const fresh = await hostedFixture("snyk", capture, renamed);
  await expect(fresh.prepareNormalized(report)).rejects.toThrow(
    "Snyk target URL",
  );
  expect(fresh.posts).toHaveLength(0);
});

async function privateUploadFixture(
  raw: unknown,
  provider: "endor" | "semgrep" | "snyk" | "wiz",
  repositoryUrl?: string,
) {
  const f = await fixture(raw, repositoryUrl);
  const settings = { ...options, provider };
  f.state.catalogHeaders["Codex-Security-Private-Import-Providers"] = provider;
  const inbox = {
    version: "original-inbox",
    formats: ["security.findings.v1"],
    recoverUpload: false,
  };
  const uploads: { id: string; bytes: string }[] = [];
  const jobs: unknown[] = [];
  const fileId = "aifile_" + "a".repeat(32);
  const deps = {
    ...f.deps,
    fetch: async (url: string, init: RequestInit) => {
      const { pathname } = new URL(url);
      if (pathname.endsWith("/finding-imports/context"))
        return privateInboxContext(inbox.version, inbox.formats);
      if (pathname.includes("/finding-imports/file-requests/")) {
        const prior = uploads.find((upload) =>
          pathname.endsWith("/" + upload.id),
        );
        return inbox.recoverUpload && prior
          ? Response.json(privateFileMetadata(fileId, prior.bytes))
          : new Response(null, { status: 404 });
      }
      if (pathname.endsWith("/finding-imports/jobs")) {
        expect(init.method).toBe("POST");
        const job = JSON.parse(String(init.body));
        jobs.push(job);
        return Response.json(
          privateJobReceipt(job, "import_" + "b".repeat(32)),
        );
      }
      if (pathname.endsWith("/finding-imports/files")) {
        const form = init.body as FormData;
        uploads.push({
          id: String(form.get("request_id")),
          bytes: await (form.get("file") as Blob).text(),
        });
        throw new Error("Interrupted private upload");
      }
      return f.deps.fetch(url, init);
    },
  };
  const prepareFile = () => prepareExternalPublication(f.file, settings, deps);
  return { f, settings, deps, inbox, uploads, jobs, fileId, prepareFile };
}

test("a Snyk private upload resumes after a rename and still checks supplemental SDK repository claims", async () => {
  const { url, capture, report } = privateSnykProject();
  const { f, settings, deps, inbox, uploads, prepareFile } =
    await privateUploadFixture(capture, "snyk", url);
  const original = await prepareFile();
  await expect(original.publish()).rejects.toThrow(
    "Interrupted private upload",
  );
  f.state.repositoryUrl = "https://git.example.test/Team/NewProject";
  const conflicting = { ...report, sourceRepositoryUrl: f.state.repositoryUrl };
  await expect(
    prepareNormalizedExternalPublication(conflicting, settings, deps),
  ).rejects.toThrow(/repository|project/iu);
  expect((await prepareFile()).preview.resumed).toBe(true);
  const retry = await prepareNormalizedExternalPublication(
    report,
    settings,
    deps,
  );
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.privateImport).toEqual(original.preview.privateImport);
  await expect(retry.publish()).rejects.toThrow("Interrupted private upload");
  expect(uploads).toHaveLength(2);
  expect(uploads[1]).toEqual(uploads[0]);

  inbox.version = "new-inbox";
  await expect(prepareFile()).rejects.toThrow(/repository|project/iu);
});

test("a self-contained Snyk issue keeps its Cloud identity with or without a report header", async () => {
  const capture = snykRestFixture("open-source");
  const report = normalizeSnykIssues(capture);
  const { read, findings, excluded } = report;
  const data = findings[0]!.evidence.source_data!;
  data["issueJson"] = JSON.stringify(
    JSON.parse(String(data["issueJson"])),
    null,
    2,
  );
  const f = await hostedFixture("snyk", capture, capture.sourceRepositoryUrl);
  await f.loseResponse(await f.prepareNormalized(report));
  const resumed = await f.prepareNormalized({ read, findings, excluded });
  expect(resumed.preview.resumed).toBe(true);
  await resumed.publish();
  expect(f.posts[1]).toBe(f.posts[0]);
  expect(
    (await (await f.prepareNormalized(report)).publish()).counts.unchanged,
  ).toBe(1);
});

test("a pending projected Snyk issue keeps its generated ID bound to the original API region", async () => {
  const capture = snykRestFixture("open-source");
  const report = normalizeSnykIssues(capture);
  const row = report.findings[0]!;
  row.evidence.source_data = {
    issueJson: row.evidence.source_data!["issueJson"],
  };
  const f = await hostedFixture("snyk", capture, capture.sourceRepositoryUrl);
  const prepare = (apiOrigin: string) => {
    const projected = {
      ...report,
      snykRestContext: { ...report.snykRestContext, apiOrigin },
    };
    return prepareNormalizedExternalPublication(
      projected,
      { ...options, provider: "snyk" },
      f.deps,
    );
  };
  const selected = await prepare(capture.apiOrigin);
  expect(selected.preview.findings).toEqual(
    (await f.prepareFile()).preview.findings,
  );
  const pending = await f.loseResponse(selected);
  const before = await readFile(pending);
  await expect(prepare("https://api.snyk.io")).rejects.toThrow(
    "normalized finding ID",
  );
  expect(await readFile(pending)).toEqual(before);
  expect((await prepare(capture.apiOrigin)).preview.resumed).toBe(true);
  await (await f.prepareFile()).publish();
  expect(f.posts[1]).toBe(f.posts[0]);
});

test("a resumed Snyk issue checks its retained target against a new SCM mapping", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = snykRestFixture("open-source", { sourceRepositoryUrl: url });
  const project = JSON.parse(report.projectJson);
  project.attributes.origin = "cli";
  project.relationships.target.data.attributes.url =
    "git@scm.example.test:team/project.git";
  report.projectJson = JSON.stringify(project);
  const references = [{ url, platform: "github" as const }];
  const { read, findings, excluded } = normalizeSnykIssues(
    report,
    "cloud",
    references,
  );
  const f = await fixture(report, url);
  const prepare = (platform: "github" | "gitlab") =>
    prepareNormalizedExternalPublication(
      { read, findings, excluded },
      { ...options, provider: "snyk" },
      { ...f.deps, sourceRepositories: [{ url, platform }] },
    );

  await expect(prepare("gitlab")).rejects.toThrow("Snyk target URL");
  const pending = await f.loseResponse(await prepare("github"));
  const before = await readFile(pending);
  await expect(prepare("gitlab")).rejects.toThrow("Snyk target URL");
  expect(await readFile(pending)).toEqual(before);
  await (await prepare("github")).publish();
  expect(f.posts[1]).toBe(f.posts[0]);
});

test("Cloud Semgrep reader references retain the Git HTTP host", async () => {
  const f = await fixture();
  const prepare = (host: string, reader: string) => {
    const url = `https://${host}/org/project`;
    f.state.repositoryUrl = url;
    return prepareNormalizedExternalPublication(
      {
        read: 1,
        excluded: [],
        findings: [
          {
            source_finding_id: "generic-1",
            evidence: {
              title: "Example issue",
              severity: "high",
              details: { kind: "sast", repository: { url } },
            },
          },
        ],
      },
      { ...options, provider: "semgrep" },
      {
        ...f.deps,
        sourceRepositories: [
          { url: `https://${reader}/org/project`, platform: "github" },
        ],
      },
    );
  };
  await expect(prepare("127.0.0.1", "0177.1.")).rejects.toThrow(
    /does not match/,
  );
  for (const host of ["127.0.0.1", "[::1]", "0177.1."]) {
    expect((await prepare(host, host)).preview.findings).toHaveLength(1);
  }
});

test("a Semgrep file retry preserves the approved private repository's case", async () => {
  const url = "https://scm.example.test/Team/Project";
  const ref = "refs/heads/topic";
  const report = {
    format: "semgrep-platform-findings/v1",
    deployment: "example",
    project: { id: 10, name: "Team/Project", url },
    ref,
    product: "sast",
    findingCount: 1,
    findings: [{ id: 12, ref, repository: { url }, rule_name: "example.rule" }],
  };
  const f = await hostedFixture("semgrep", report, url);
  const settings = { ...options, provider: "semgrep" as const };
  const strict = {
    ...f.deps,
    sourceRepositories: [{ url, platform: "gitlab" as const }],
  };
  await f.loseResponse(
    await prepareExternalPublication(f.file, settings, strict),
  );
  await writeFile(
    f.file,
    JSON.stringify({ ...report, sourceRepositoryUrl: url.toLowerCase() }),
  );
  await expect(
    prepareExternalPublication(f.file, settings, strict),
  ).rejects.toThrow(/repository/iu);
  await expect(
    prepareExternalPublication(f.file, settings, f.deps),
  ).rejects.toThrow(/repository/iu);
  expect(f.posts).toHaveLength(1);
  await writeFile(f.file, JSON.stringify(report));
  const retry = await prepareExternalPublication(f.file, settings, f.deps);
  expect(retry.preview.resumed).toBe(true);
  await retry.publish();
  expect(f.posts[1]).toBe(f.posts[0]);
  expect(f.receipts.size).toBe(1);
});

test.each(["file", "SDK"] as const)(
  "a private GitHub repository recognizes an offline Semgrep capture on a %s retry",
  async (first) => {
    const url = "https://scm.example.test/Org/Repo";
    const project = { name: "Org/Repo", id: 77, url };
    const ref = "refs/heads/topic";
    const native = {
      id: 23,
      ref,
      repository: { id: project.id, name: "org/repo" },
      rule: { name: "example.rule", message: "Example issue" },
      location: { file_path: "src/example.ts", line: 2 },
      severity: "informational",
    };
    const report = await collectSemgrepPlatformFindings(
      {
        project: project.name,
        deployment: "example",
        ref,
        token: "synthetic-token",
      },
      {
        environment: {},
        fetch: async (url) =>
          Response.json(
            url.pathname.endsWith("/findings")
              ? { findings: [native] }
              : { project },
          ),
      },
    );
    const offline = normalizeSemgrepPlatformFindings(report);
    const row = offline.findings[0]!;
    expect(row.evidence.source_data?.["format"]).toBe(semgrepPlatformFormat);
    const f = await hostedFixture("semgrep", report, url);
    const sdk = () => f.prepareNormalized(offline);
    const file = await f.prepareFile();
    expect(file.preview.findings[0]?.evidence.source_data?.["format"]).toBe(
      "semgrep-platform-selection/v1",
    );
    expect((await sdk()).preview.findings).toEqual(file.preview.findings);
    await f.loseResponse(first === "file" ? file : await sdk());
    const retry = await (first === "file" ? sdk() : f.prepareFile());
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts[1]).toBe(f.posts[0]);
    expect(f.receipts.size).toBe(1);
    expect((await (await sdk()).publish()).counts.unchanged).toBe(1);
    expect(f.reports.size).toBe(1);

    row.source_finding_id = "custom-occurrence";
    row.evidence.severity = "high";
    row.evidence.source_data!["reviewNote"] = "Keep This Case";
    expect((await sdk()).preview.findings[0]).toMatchObject({
      source_finding_id: "custom-occurrence",
      evidence: {
        severity: "high",
        source_data: {
          reviewNote: "Keep This Case",
          semgrepPlatformFindingJson:
            row.evidence.source_data!["semgrepPlatformFindingJson"],
        },
      },
    });
  },
);

test("an independent GitLab mapping preserves Semgrep repository case on a private host", async () => {
  const url = "https://scm.example.test/Team/Project";
  const sourceRepositories = [{ url, platform: "gitlab" as const }];
  const report = selectedSemgrepReport(
    { name: "Team/Project", url },
    { rule_name: "sample.rule" },
    sourceRepositories,
  );
  const f = await fixture(report, url);
  const settings = { ...options, provider: "semgrep" as const };
  const deps = { ...f.deps, sourceRepositories };
  const file = () => prepareExternalPublication(f.file, settings, deps);
  const { findings } = (await file()).preview;
  const input = { read: findings.length, excluded: [], findings };
  f.state.repositoryUrl = url.toLowerCase();
  await expect(file()).rejects.toThrow(/repository|project/iu);
  await expect(
    prepareNormalizedExternalPublication(input, settings, deps),
  ).rejects.toThrow(/repository|project/iu);
  expect(f.posts).toHaveLength(0);
});

test.each(["semgrep", "snyk"] as const)(
  "%s checks typed-only repository evidence and reader ports against Cloud",
  async (provider) => {
    const url = "https://scm.example.test/Group/Project";
    const f = await fixture([], url);
    const prepare = (
      typed: string,
      reference: string,
      platform: "github" | "gitlab",
    ) =>
      prepareNormalizedExternalPublication(
        {
          read: 1,
          excluded: [],
          findings: [
            {
              source_finding_id: "reader-1",
              evidence: {
                title: "Example issue",
                severity: "high",
                details: { kind: "sast", repository: { url: typed } },
              },
            },
          ],
        },
        { ...options, provider },
        { ...f.deps, sourceRepositories: [{ url: reference, platform }] },
      );
    await expect(prepare(url.toLowerCase(), url, "gitlab")).rejects.toThrow(
      /repository|project/iu,
    );
    const withPort = url.replace(".test/", ".test:443/");
    for (const scm of ["github", "gitlab"] as const) {
      await expect(prepare(url, withPort, scm)).rejects.toThrow(
        /repository|project/iu,
      );
    }
    expect((await prepare(url, url, "gitlab")).preview.findings).toHaveLength(
      1,
    );
    expect(
      (await prepare(url.toLowerCase(), url, "github")).preview.findings,
    ).toHaveLength(1);
    f.state.repositoryUrl = withPort;
    await expect(prepare(withPort, url, "gitlab")).rejects.toThrow(
      /repository|project/iu,
    );
    expect(
      (await prepare(withPort, withPort, "gitlab")).preview.findings,
    ).toHaveLength(1);
  },
);

test("Semgrep publication compares the operator's source URL with Cloud repository port semantics", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = selectedSemgrepReport(
    { name: "Team/Project", url },
    { rule_name: "sample.rule" },
  );
  const f = await hostedFixture("semgrep", report, url);
  const prepare = (sourceRepositoryUrl: string) =>
    prepareExternalPublication(
      f.file,
      { ...options, provider: "semgrep", sourceRepositoryUrl },
      f.deps,
    );
  const different = "https://scm.example.test:443/Team/Project";
  await expect(prepare(different)).rejects.toThrow(/does not match/i);
  expect(f.posts).toHaveLength(0);
  await f.loseResponse(await prepare(url));
  await expect(prepare(different)).rejects.toThrow(/does not match/i);
  expect(f.posts).toHaveLength(1);
  expect((await prepare(url)).preview.resumed).toBe(true);
});

test("Semgrep Cloud checks the original port on a selected finding's repository URL", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = selectedSemgrepReport(
    { name: "Team/Project", url },
    {
      repository: { url: "https://scm.example.test:443/Team/Project" },
      rule_name: "sample.rule",
    },
  );
  const f = await hostedFixture("semgrep", report, url);
  await expect(f.prepareFile()).rejects.toThrow(/repository/iu);
  const sdk = normalizeSemgrepFindings(report, {}, "local");
  await expect(f.prepareNormalized(sdk)).rejects.toThrow(/repository/iu);
  expect(f.posts).toHaveLength(0);
});

test("Semgrep reader aliases also match the normalized source's SCM policy", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = selectedSemgrepReport(
    { name: "Team/Project", url },
    { rule_name: "sample.rule" },
  );
  const f = await hostedFixture("semgrep", report, url);
  const native = normalizeSemgrepFindings(report, {}, "cloud");
  const strict = { ...native, sourceRepositoryPlatform: "other" as const };
  const prepare = (source: typeof native, readerUrl: string) =>
    prepareNormalizedExternalPublication(
      source,
      { ...options, provider: "semgrep" },
      {
        ...f.deps,
        sourceRepositories: [{ platform: "github", url: readerUrl }],
      },
    );
  expect(
    (await prepare(native, url.toLowerCase())).preview.findings,
  ).toHaveLength(1);
  expect(
    (await prepare(native, "git@scm.example.test:Team/Project.git")).preview
      .findings,
  ).toHaveLength(1);
  expect(
    (await prepare(strict, "git@scm.example.test:Team/Project")).preview
      .findings,
  ).toHaveLength(1);
  await expect(prepare(strict, url.toLowerCase())).rejects.toThrow(
    /repository/iu,
  );
  expect(f.posts).toHaveLength(0);
});

test("an undefined optional Snyk context permits generic SDK evidence", async () => {
  class Report {
    snykRestContext?: Record<string, unknown>;
    read = 1;
    excluded = [];
    findings = [
      {
        source_finding_id: "generic-1",
        evidence: { title: "Example issue", severity: "high" as const },
      },
    ];
  }
  const f = await fixture();
  const report = new Report();
  const prepared = await prepareNormalizedExternalPublication(
    report,
    options,
    f.deps,
  );
  expect((await prepared.publish()).counts.created).toBe(1);
  report.snykRestContext = {};
  await expect(
    prepareNormalizedExternalPublication(
      report,
      { ...options, provider: "snyk" },
      f.deps,
    ),
  ).rejects.toThrow("Expected a versioned Snyk REST report context");
});

test.each(["sast", "sca"])(
  "Guardian %s files publish and replay only at their selected repository",
  async (product) => {
    const url = "https://github.com/example/project";
    const repository = "example/project";
    const ref = "refs/heads/topic";
    const id = "09007199254740993";
    const report = {
      format: "semgrep-guardian-selection/v1",
      sourceRepositoryUrl: url,
      request: {
        name:
          product === "sast"
            ? "get_semgrep_sast_findings"
            : "get_semgrep_supply_chain_findings",
        arguments: {
          deployment_name: "example",
          repository_name: repository,
          ref,
        },
      },
      findingIds: [id],
      structuredContent: {
        findings: [
          {
            id,
            ref,
            repository: { name: repository },
            issueType: product,
            severity: "HIGH",
            rulePath: "example.rule",
            message: "Example finding",
            filePath: "src/app.ts",
            line: 3,
          },
        ],
      },
    };
    const f = await fixture(report, url);
    const binding = { ...options, provider: "semgrep" as const };
    const local = normalizeSemgrepFindings(report, {}, "local");
    const prepare = () => prepareExternalPublication(f.file, binding, f.deps);
    const prepared = await prepare();
    expect(prepared.preview.findings).toEqual(local.findings);
    await f.loseResponse(prepared);
    expect((await (await prepare()).publish()).verified).toBe(1);
    const unscored = structuredClone(report);
    unscored.structuredContent.findings[0]!.severity = "UNSPECIFIED";
    const inbox = await privateUploadFixture(unscored, "semgrep", url);
    const headers = inbox.f.state.catalogHeaders;
    headers["Codex-Security-Repository-Import-Severities"] = "high";
    delete headers["Codex-Security-Private-Import-Providers"];
    await expect(inbox.prepareFile()).rejects.toMatchObject({
      selection: { findings: [], excluded: [{ position: 1 }] },
    });
    headers["Codex-Security-Private-Import-Providers"] = "semgrep";
    const privatePreview = (await inbox.prepareFile()).preview;
    expect(privatePreview.privateImport?.format).toBe("security.findings.v1");
    expect(privatePreview.findings[0]!.evidence.severity).toBe("unknown");
    const elsewhere = await fixture(report, "https://github.com/other/project");
    await expect(
      prepareExternalPublication(elsewhere.file, binding, elsewhere.deps),
    ).rejects.toThrow(/repository/iu);
    await expect(
      prepareNormalizedExternalPublication(
        { ...local, report: undefined },
        binding,
        elsewhere.deps,
      ),
    ).rejects.toThrow(/repository/iu);
    expect(elsewhere.posts).toHaveLength(0);
    const missingSource = structuredClone(local);
    delete missingSource.findings[0]!.evidence.source_data![
      "sourceRepositoryUrl"
    ];
    await expect(
      prepareNormalizedExternalPublication(missingSource, binding, f.deps),
    ).rejects.toThrow(/Guardian --source-repository-url/u);
    const wrongRef = structuredClone(local);
    wrongRef.findings[0]!.evidence.branch = "refs/heads/other";
    await expect(
      prepareNormalizedExternalPublication(wrongRef, binding, f.deps),
    ).rejects.toThrow(/selected ref/u);
    const changed = {
      ...local,
      findings: [{ ...local.findings[0]!, source_finding_id: "another-id" }],
    };
    await expect(
      prepareNormalizedExternalPublication(changed, binding, f.deps),
    ).rejects.toThrow(/original Guardian finding/);
  },
);

test("a saved selection with Guardian evidence cannot resume under another provider", async () => {
  const f = await fixture([normalized()]);
  const prepare = () => prepareExternalPublication(f.file, options, f.deps);
  const path = await f.loseResponse(await prepare());
  const saved = JSON.parse(await readFile(path, "utf8"));
  const { source_finding_id, evidence } = saved.requests[0].items[0];
  evidence.source_data = { format: "semgrep-guardian-selection/v1" };
  // An older reader can store a different projection of the same finding.
  saved.inputProjection.savedEvidenceDigest = hash(
    "sha256",
    canonicalJson([{ source_finding_id, evidence }]),
  );
  const bytes = JSON.stringify(saved);
  await writeFile(path, bytes);
  await expect(prepare()).rejects.toThrow(/semgrep provider/);
  expect(f.posts).toHaveLength(1);
  expect(await readFile(path, "utf8")).toBe(bytes);
});

test("Trivy Cloud preparation reads the serialized batch and rows", async () => {
  const report = normalizeTrivyFindings(trivyReport(), "cloud", ".");
  const row = report.findings[0]!;
  for (const input of [
    {
      ...report,
      get findings(): never {
        throw new Error("Unused batch getter");
      },
      toJSON: () => report,
    },
    {
      ...report,
      findings: [
        {
          ...row,
          get evidence(): never {
            throw new Error("Unused row getter");
          },
          toJSON: () => row,
        },
      ],
    },
  ]) {
    await expect(
      prepareNormalizedExternalPublication(input, trivyOptions, {
        environment: {},
        credentials: async () => {
          throw new Error("Reached credential lookup");
        },
      }),
    ).rejects.toThrow("Reached credential lookup");
  }
});

test("a normalized Semgrep report checks the provider before Cloud credentials", async () => {
  const url = "https://github.com/example/project";
  const report = normalizeSemgrepFindings(
    selectedSemgrepReport({ name: "example/project", url }, {}),
    {},
    "cloud",
  );
  await expect(
    prepareNormalizedExternalPublication(
      report,
      { ...options, provider: "wiz" },
      {
        environment: {},
        credentials: async () => {
          throw new Error("Unexpected credential lookup");
        },
      },
    ),
  ).rejects.toThrow("requires the semgrep provider");
});

test.each(["ticket", "HEAD", "release"] as const)(
  "Cloud replays a previously approved Semgrep request with its original scope checks (%s)",
  async (kind) => {
    const url = "https://github.com/example/project";
    const other = "https://github.com/example/other";
    const ref = kind === "ticket" ? "refs/heads/release" : kind;
    const scope = {
      deployment: "example",
      projectId: "14",
      ref,
      product: "sast",
    };
    const capture = {
      format: "semgrep-platform-findings/v1",
      deployment: scope.deployment,
      ref,
      product: scope.product,
      project: { id: 14, name: "example/project", url },
      findingCount: 1,
      findings: [{ id: 23, rule_name: "example.rule", ref }],
    };
    const f = await hostedFixture("semgrep", capture, url);
    const report = normalizeSemgrepFindings(capture, {}, "cloud");
    const row = report.findings[0]!;
    const bare = {
      read: 1,
      excluded: [],
      findings: [row],
      sourceRepositoryUrl: url,
    };
    const marked = {
      ...bare,
      sourceFormat: "semgrep-platform-findings/v1" as const,
      semgrepPlatformScope: scope,
    };
    if (kind === "ticket") {
      row.source_finding_id = "operator-assigned";
      row.evidence.source_data = {
        format: "ticket/v1",
        finding: { id: "TRACK-23", repository: { url: other } },
      };
      await expect(f.prepareNormalized(marked)).rejects.toThrow(
        /original collection scope/iu,
      );
    }
    const path = await f.loseResponse(
      await f.prepareNormalized(kind === "ticket" ? bare : marked),
    );
    const saved = JSON.parse(await readFile(path, "utf8"));
    // The released publisher stored whether a report was marked and the original evidence digests.
    const { inputDigest, savedEvidenceDigest } = saved.inputProjection;
    saved.inputProjection = {
      retainedHostedSelection: true,
      inputDigest,
      savedEvidenceDigest,
    };
    const bytes = JSON.stringify(saved);
    await writeFile(
      path,
      JSON.stringify({ ...saved, accountId: "other-account" }),
    );
    await expect(f.prepareNormalized(marked)).rejects.toThrow(/account/iu);
    await writeFile(path, bytes);
    await expect(
      f.prepareNormalized({ ...marked, sourceRepositoryUrl: other }),
    ).rejects.toThrow(/scope|repository/iu);
    if (kind !== "ticket") {
      await expect(
        f.prepareNormalized({
          ...marked,
          semgrepPlatformScope: { ...scope, ref: "refs/heads/" + ref },
        }),
      ).rejects.toThrow(/scope|ref/iu);
    }
    expect(await readFile(path, "utf8")).toBe(bytes);
    expect(f.posts).toHaveLength(1);
    const retry = await f.prepareNormalized(marked);
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toEqual([
      JSON.stringify(saved.requests[0]),
      JSON.stringify(saved.requests[0]),
    ]);
  },
);

test.each(["ticket metadata", "retained ref"] as const)(
  "a mixed Semgrep request retries with an unmarked row containing %s",
  async (kind) => {
    const url = "https://github.com/example/project";
    const capture = selectedSemgrepReport({ name: "example/project", url }, {});
    const report = normalizeSemgrepFindings(capture, {}, "cloud");
    const finding =
      kind === "ticket metadata"
        ? { id: "T-1", title: "Ticket" }
        : { id: 23, ref: "refs/heads/other" };
    const unmarked = {
      read: 2,
      excluded: [],
      findings: [
        ...report.findings,
        {
          source_finding_id: "ticket-1",
          evidence: {
            title: "Ticket",
            severity: "low" as const,
            source_data: { finding },
          },
        },
      ],
    };
    const f = await hostedFixture("semgrep", capture, url);
    const first = await f.prepareNormalized(unmarked);
    const pending = await f.loseResponse(first);
    const marked = { ...report, ...unmarked };
    if (kind === "retained ref") {
      const bytes = await readFile(pending);
      await expect(f.prepareNormalized(marked)).rejects.toThrow(/scope/iu);
      expect(await readFile(pending)).toEqual(bytes);
      expect(f.posts).toHaveLength(1);
    }
    const retry = await f.prepareNormalized(
      kind === "ticket metadata" ? marked : unmarked,
    );
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests).toEqual(first.preview.requests);
    await retry.publish();
    expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
  },
);

test("Cloud binds newly approved marked ticket context to its deployment", async () => {
  const url = "https://github.com/example/project";
  const f = await hostedFixture("semgrep", semgrepJson(), url);
  const report = normalizeSemgrepFindings(
    semgrepJson(),
    { sourceRepositoryUrl: url },
    "cloud",
  );
  report.findings[0]!.evidence.source_data = {
    ticket: { id: "TRACK-23", ref: "HEAD" },
  };
  const scope = {
    deployment: "example",
    projectId: "14",
    ref: "refs/heads/release",
    product: "sast",
  };
  const input = {
    ...report,
    sourceRepositoryUrl: url,
    sourceFormat: "semgrep-platform-findings/v1" as const,
    semgrepPlatformScope: scope,
  };
  const path = await f.loseResponse(await f.prepareNormalized(input));
  const bytes = await readFile(path, "utf8");
  await expect(
    f.prepareNormalized({
      ...input,
      semgrepPlatformScope: { ...scope, deployment: "another" },
    }),
  ).rejects.toThrow(/scope|deployment/iu);
  expect(await readFile(path, "utf8")).toBe(bytes);
  expect(f.posts).toHaveLength(1);
  const retry = await f.prepareNormalized(input);
  expect(retry.preview.resumed).toBe(true);
  await retry.publish();
  expect(f.posts[1]).toBe(f.posts[0]);
});

test.each(["marked", "unmarked"] as const)(
  "Cloud preserves a Semgrep approval's scope when recovering the raw checkpoint key during %s retries",
  async (retryKind) => {
    const changedScope = retryKind === "marked";
    const url = "https://scm.example.test/Org/Repo";
    const capture = {
      format: semgrepPlatformFormat,
      repositoryAliases: ["org/repo"],
      deployment: "example",
      ref: "refs/heads/release",
      product: "sast",
      project: { id: "14", name: "Org/Repo", url },
      findingCount: 1,
      findings: [
        JSON.stringify({
          id: 23,
          rule_name: "sample.rule",
          repository: { id: 14, name: "org/repo" },
          ref: "refs/heads/release",
        }),
      ],
    };
    const f = await hostedFixture("semgrep", capture, url);
    const native = normalizeSemgrepPlatformFindings(capture);
    const ticket = {
      source_finding_id: "custom",
      evidence: {
        title: "Ticket",
        severity: "high" as const,
        source_data: { finding: { ref: "refs/heads/other" } },
      },
    };
    const findings = [...native.findings, ticket];
    const bare = {
      read: 2,
      excluded: [],
      findings,
      sourceRepositoryPlatform: "other" as const,
      sourceRepositoryUrl: url,
    };
    const marked = { ...native, read: 2, findings };
    const mapped = { ...bare, sourceRepositoryPlatform: "github" as const };
    const path = await f.loseResponse(await f.prepareNormalized(bare));
    const bytes = await readFile(path, "utf8");

    // The raw publisher installs its checkpoint after the mapped reader misses the raw key.
    const staged = path + ".staged";
    await fs.rename(path, staged);
    const originalRead = fs.readFile;
    let installed = false;
    const lookup = spyOn(fs, "readFile").mockImplementation(((
      ...args: Parameters<typeof fs.readFile>
    ) => {
      const result = originalRead(...args);
      if (args[0] !== path || installed) return result;
      installed = true;
      return result.finally(() => fs.rename(staged, path));
    }) as typeof fs.readFile);
    try {
      if (changedScope)
        await expect(f.prepareNormalized(marked)).rejects.toThrow(
          /approved request/iu,
        );
      else
        expect((await f.prepareNormalized(mapped)).preview.resumed).toBe(true);
    } finally {
      lookup.mockRestore();
    }
    expect(installed).toBe(true);
    if (changedScope) expect(await readFile(path, "utf8")).toBe(bytes);
    else {
      await expect(fs.stat(path)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(f.prepareNormalized(marked)).rejects.toThrow(
        /approved request/iu,
      );
    }
    expect(f.posts).toHaveLength(1);
    const resumed = await f.prepareNormalized(changedScope ? bare : mapped);
    expect(resumed.preview.requests).toEqual(JSON.parse(bytes).requests);
    expect(resumed.preview.resumed).toBe(true);
    await resumed.publish();
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test("Cloud checks both native Semgrep rows when a projection retains both formats", async () => {
  const url = "https://github.com/example/project";
  const f = await hostedFixture(
    "semgrep",
    selectedSemgrepReport(
      { name: "example/project", url },
      { rule_name: "sample.rule" },
    ),
    url,
  );
  const { findings } = (await f.prepareFile()).preview;
  const input = { read: 1, excluded: [], findings };
  const raw = findings[0]!.evidence.source_data!;
  const json = String(raw["semgrepPlatformFindingJson"]);
  const row = { ...JSON.parse(json), attempts: 1, scoreRatio: 1.25 };
  raw["finding"] = { annotation: "operator note" };
  expect((await f.prepareNormalized(input)).preview.findings).toHaveLength(1);
  const score = "9007199254740993";
  raw["semgrepPlatformFindingJson"] =
    `{"attempts":1.0,"scoreRatio":1.250,"score":${score},${json.slice(1)}`;
  raw["finding"] = { ...row, score };
  raw["numericFields"] = { finding: { score } };
  raw["format"] = "semgrep-platform-findings/v1";
  raw["repositoryAliases"] = [];
  expect((await f.prepareNormalized(input)).preview.findings).toHaveLength(1);
  raw["finding"] = {
    ...row,
    score,
    repository: { url: "https://github.com/foreign/project" },
  };
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  raw["format"] = "semgrep-platform-selection/v1";
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  raw["finding"] = { ...row, score, id: 31 };
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  expect(f.posts).toHaveLength(0);
});

test("textual and witnessed Semgrep finding IDs are checked even above the signed range", async () => {
  const url = "https://github.com/example/project";
  const report = selectedSemgrepReport(
    { name: "example/project", url },
    { rule_name: "sample.rule" },
  );
  const id = "1000000000000000000002";
  report.findings[0] = report.findings[0]!.replace('"id":23', '"id":' + id);
  const f = await hostedFixture("semgrep", report, url);
  const { findings } = (await f.prepareFile()).preview;
  const input = { read: 1, excluded: [], findings };
  const raw = findings[0]!.evidence.source_data!;
  const original = {
    ...JSON.parse(String(raw["semgrepPlatformFindingJson"])),
    id,
  };
  raw["numericFields"] = { finding: { id } };
  raw["finding"] = {
    ...original,
    repository: { url: "https://github.com/foreign/project" },
  };
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  raw["finding"] = original;
  expect((await f.prepareNormalized(input)).preview.findings).toHaveLength(1);
  const otherId = "1000000000000000000003";
  raw["finding"] = { ...original, id: otherId };
  raw["numericFields"] = { finding: { id: otherId } };
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  const numericJson = raw["semgrepPlatformFindingJson"];
  delete raw["numericFields"];
  raw["semgrepPlatformFindingJson"] = JSON.stringify(original);
  raw["finding"] = {
    ...original,
    repository: { url: "https://github.com/foreign/project" },
  };
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  raw["finding"] = original;
  expect((await f.prepareNormalized(input)).preview.findings).toHaveLength(1);
  raw["semgrepPlatformFindingJson"] = numericJson;
  await expect(f.prepareNormalized(input)).rejects.toThrow(
    /Semgrep.*disagree/i,
  );
  expect(f.posts).toHaveLength(0);
});

test.each([true, false])(
  "a new Semgrep reader mapping rechecks the original saved SCA row (exact case %s)",
  async (exact) => {
    const url = "https://scm.example.test/Team/Project";
    const report = {
      format: semgrepPlatformFormat,
      deployment: "example",
      project: { id: "14", name: "Team/Project", url },
      product: "sca",
      ref: "refs/heads/topic",
      repositoryAliases: [],
      findingCount: 1,
      findings: [
        JSON.stringify({
          id: 23,
          rule_name: "sample.rule",
          repository: { url: exact ? url : url.toLowerCase() },
        }),
      ],
    };
    const input = normalizeSemgrepFindings(
      report,
      { sourceRepositories: [{ url, platform: "github" }] },
      "cloud",
    );
    const f = await hostedFixture("semgrep", report, url);
    const strict = () =>
      prepareNormalizedExternalPublication(
        input,
        { ...options, provider: "semgrep" },
        {
          ...f.deps,
          sourceRepositories: [{ url, platform: "gitlab" }],
        },
      );
    if (!exact) await expect(strict()).rejects.toThrow(/repository/iu);
    const pending = await f.loseResponse(await f.prepareNormalized(input));
    const approved = await readFile(pending, "utf8");
    if (exact) expect((await strict()).preview.resumed).toBe(true);
    else await expect(strict()).rejects.toThrow(/repository/iu);
    expect(await readFile(pending, "utf8")).toBe(approved);
    await (await f.prepareNormalized(input)).publish();
    expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
  },
);

test("marked Semgrep rows require their provider while unmarked Wiz records can publish", async () => {
  const url = "https://github.com/example/project";
  const f = await fixture([], url);
  const prepare = (
    id: string | number | null,
    projectUrl: string | null,
    provider: "wiz" | "semgrep" = "wiz",
    format?: string,
  ) =>
    prepareNormalizedExternalPublication(
      {
        read: 1,
        excluded: [],
        findings: [
          {
            source_finding_id: "opaque",
            evidence: {
              title: "Example",
              severity: "low",
              source_data: {
                ...(format && { format }),
                deployment: "demo",
                project: { id: "10", name: "example/project", url: projectUrl },
                ref: "refs/heads/topic",
                product: "sast",
                finding: { id },
              },
            },
          },
        ],
      },
      { ...options, provider },
      f.deps,
    );
  await expect(
    prepare("1.2e1", null, "wiz", "semgrep-platform-findings/v1"),
  ).rejects.toThrow(/semgrep provider/i);
  expect((await prepare("1.2e1", null)).preview.findings).toHaveLength(1);
  await expect(prepare(null, null, "semgrep")).rejects.toThrow(/Semgrep/i);
  expect(
    (await prepare(12, url, "wiz", "wiz-findings/v1")).preview.findings,
  ).toHaveLength(1);
  expect(f.posts).toHaveLength(0);
  expect((await (await prepare("WIZ-1", url)).publish()).counts.created).toBe(
    1,
  );
});

async function useReleasedCheckpoint(path: string) {
  const captured = await readFile(path, "utf8");
  const pending = JSON.parse(captured);
  delete pending.approvedRepositoryUrl;
  delete pending.approvedRepositoryPlatform;
  await writeFile(path, JSON.stringify(pending));

  return () => writeFile(path, captured);
}

test.each(["semgrep", "snyk"] as const)(
  "%s hosted findings bind the original repository and replay the approved request",
  async (provider) => {
    const url =
      provider === "semgrep"
        ? "https://scm.example.test/Example/Project"
        : "https://github.com/example/project";
    const report =
      provider === "semgrep"
        ? selectedSemgrepReport(
            { name: "example/project", url },
            { rule_message: "é".repeat(257) },
          )
        : snykRestFixture("open-source", { sourceRepositoryUrl: url });
    const f = await hostedFixture(
      provider,
      report,
      url,
      "example/project/hosted",
    );
    const first = await f.prepareFile();
    expect(first.preview.findings).toHaveLength(1);
    if (provider === "semgrep") {
      expect(first.preview.findings[0]!.evidence).toMatchObject({
        title: "Semgrep finding 23",
        description: "é".repeat(257),
      });
    }
    const { findings } = first.preview;
    const normalized = { read: 1, excluded: [], findings };
    await expect(f.prepareNormalized(normalized, "wiz")).rejects.toThrow(
      /provider/i,
    );
    if (provider === "semgrep") {
      f.state.repositoryUrl = url.replace("Project", "%50roject");
      expect((await f.prepareFile()).preview.findings).toHaveLength(1);
      expect(
        (await f.prepareNormalized(normalized)).preview.findings,
      ).toHaveLength(1);
      f.state.repositoryUrl = url.replace(
        "scm.example.test/",
        "scm.example.test:443/",
      );
      await expect(f.prepareFile()).rejects.toThrow(/does not match/);
      f.state.repositoryUrl = url;
      const alias = structuredClone(normalized);
      alias.findings[0]!.evidence.details!.repository!.url =
        url.toLowerCase() + ".git";
      expect((await f.prepareNormalized(alias)).preview.findings).toHaveLength(
        1,
      );
      const strictAlias = {
        ...alias,
        sourceRepositoryPlatform: "other" as const,
      };
      await expect(f.prepareNormalized(strictAlias)).rejects.toThrow(
        /repository/i,
      );

      const strict = {
        ...structuredClone(normalized),
        sourceRepositoryUrl: url,
        sourceRepositoryPlatform: "other" as const,
      };
      const raw = strict.findings[0]!.evidence.source_data!;
      const row = JSON.parse(String(raw["semgrepPlatformFindingJson"]));
      row.repository.url = url.toLowerCase();
      raw["semgrepPlatformFindingJson"] = JSON.stringify(row);
      await expect(f.prepareNormalized(strict)).rejects.toThrow(/repository/i);
    }
    const untagged = structuredClone(normalized);
    delete untagged.findings[0]!.evidence.source_data!["format"];
    await expect(f.prepareNormalized(untagged, "wiz")).rejects.toThrow(
      /provider/i,
    );
    const incomplete = structuredClone(normalized);
    const payload =
      provider === "semgrep" ? "semgrepPlatformFindingJson" : "issueJson";
    delete incomplete.findings[0]!.evidence.source_data![payload];
    await expect(f.prepareNormalized(incomplete)).rejects.toThrow();
    expect(f.posts).toHaveLength(0);
    f.state.repositoryUrl = "https://github.com/example/different";
    await expect(f.prepareNormalized(normalized)).rejects.toThrow(
      /repository/i,
    );
    expect(f.posts).toHaveLength(0);
    f.state.repositoryUrl = url;

    const pendingPath = await f.loseResponse(first);
    if (provider === "semgrep") {
      const { snykRestContext } = normalizeSnykIssues({
        ...snykRestFixture("code", {
          sourceRepositoryUrl: "https://github.com/example/other",
        }),
        pages: [{ startingAfter: null, responseJson: '{"data":[]}' }],
      });
      const mixed = { ...normalized, snykRestContext };
      await expect(f.prepareNormalized(mixed)).rejects.toThrow(
        /requires the snyk provider/i,
      );
      const opaque = {
        ...normalized,
        snykRestContext: { note: "projection metadata" },
      };
      await expect(f.prepareNormalized(opaque)).rejects.toThrow(
        /snyk provider/i,
      );
      expect((await f.prepareNormalized(normalized)).preview.resumed).toBe(
        true,
      );
      expect(f.posts).toHaveLength(1);
    }
    f.state.repositoryUrl = "https://github.com/example/renamed";
    if (provider === "snyk") {
      const restore = await useReleasedCheckpoint(pendingPath);
      // The released publisher checked typed repository URLs only. The saved SCA project's
      // original JSON does not establish which URL the catalog had at approval.
      await expect(f.prepareFile()).rejects.toThrow(/does not match/);
      await restore();
    }
    // A normalized caller can omit the redundant project/platform hints on the next try.
    const projected = await f.prepareNormalized(normalized);
    expect(projected.preview.resumed).toBe(true);
    expect(projected.preview.requests).toEqual(first.preview.requests);
    const retry = await f.prepareFile();
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts[1]).toBe(f.posts[0]);
    f.state.repositoryUrl = url;
    const replay = await f.prepareFile();
    expect((await replay.publish()).counts.unchanged).toBe(1);
    expect(f.reports.size).toBe(1);
  },
);

test("Semgrep Cloud validates a normalized report's monitored scope on import and retry", async () => {
  const url = "https://github.com/example/project";
  const report = selectedSemgrepReport(
    { name: "example/project", url },
    { rule_name: "example.rule" },
  );
  const f = await hostedFixture("semgrep", report, url);
  const file = await f.prepareFile();
  const { semgrepPlatformScope, ...normalized } =
    normalizeSemgrepPlatformFindings(report, {}, "cloud");
  const sarif = semgrepSarif();
  Object.assign(sarif.runs[0]!, {
    versionControlProvenance: [{ repositoryUri: url, branch: "other" }],
  });
  const findings = normalized.findings.concat(
    normalizeSemgrepFindings(sarif, { sourceRepositoryUrl: url }).findings,
  );
  const mixed = {
    ...normalized,
    semgrepPlatformScope,
    read: findings.length,
    findings,
  };
  expect((await f.prepareNormalized(mixed)).preview.findings).toHaveLength(2);
  await expect(
    f.prepareNormalized({ ...mixed, sourceFormat: semgrepPlatformFormat }),
  ).rejects.toThrow(/branch.*ref/i);
  const other = (change: Partial<typeof semgrepPlatformScope>) =>
    f.prepareNormalized({
      ...normalized,
      semgrepPlatformScope: { ...semgrepPlatformScope, ...change },
    });
  const { sourceFormat: _format, ...withoutFormat } = normalized;
  Object.defineProperty(withoutFormat, "semgrepPlatformScope", {
    get: () => semgrepPlatformScope,
  });
  for (const provider of ["semgrep", "wiz"] as const)
    await expect(f.prepareNormalized(withoutFormat, provider)).rejects.toThrow(
      /requires its source format/,
    );
  await expect(other({ projectId: "15" })).rejects.toThrow(
    /scope does not match/,
  );
  expect(f.posts).toHaveLength(0);

  await f.loseResponse(file);
  await expect(
    f.prepareNormalized({ ...withoutFormat, semgrepPlatformScope }),
  ).rejects.toThrow(/requires its source format/);
  await expect(other({ ref: "refs/heads/other" })).rejects.toThrow(
    /scope does not match/,
  );
  Object.defineProperty(normalized, "semgrepPlatformScope", {
    get: () => semgrepPlatformScope,
  });
  const retry = await f.prepareNormalized(normalized);
  expect(retry.preview.requests).toEqual(file.preview.requests);
  expect((await retry.publish()).verified).toBe(1);
  expect(f.posts[1]).toBe(f.posts[0]);

  const projected = (title: string, scoped = true) =>
    f.prepareNormalized({
      ...(scoped
        ? { ...normalized, semgrepPlatformScope }
        : { read: 1, excluded: [] }),
      findings: [
        { source_finding_id: "ticket", evidence: { title, severity: "high" } },
      ],
    });
  await f.loseResponse(await projected("Initial title"));
  await expect(projected("New title")).rejects.toThrow(
    "pending hosted Cloud request",
  );
  await expect(projected("New title", false)).rejects.toThrow(
    "pending hosted Cloud request",
  );
});

test("Semgrep checks an alias witness before excluding it from the Cloud preview", async () => {
  const url = "https://scm.example.test/Org/Project";
  const report = (witnessUrl: string) => ({
    format: semgrepPlatformFormat,
    deployment: "example",
    project: { id: "14", name: "Org/Project", url },
    product: "sast",
    ref: "refs/heads/topic",
    findingCount: 2,
    repositoryAliases: ["display"],
    findings: [
      JSON.stringify({
        id: 11,
        rule_name: "sample.rule",
        repository: { name: "display" },
      }),
      JSON.stringify({
        id: 12,
        rule_name: "x".repeat(513),
        repository: { name: "display", url: witnessUrl },
      }),
    ],
  });
  const f = await hostedFixture("semgrep", report(url), url);
  const matching = await f.prepareFile();
  expect(matching.preview.findings).toHaveLength(1);
  expect(matching.preview.excluded).toHaveLength(1);
  const wrong = report("https://scm.example.test:443/Org/Project");
  expect(normalizeSemgrepFindings(wrong, {}, "local").findings).toHaveLength(2);
  await writeFile(f.file, JSON.stringify(wrong));
  await expect(f.prepareFile()).rejects.toThrow(/repository/i);
  expect(f.posts).toHaveLength(0);
});

test("an original Semgrep v1 name-only finding needs a repository witness in the same batch and scope", async () => {
  const f = await fixture();
  const url = f.state.repositoryUrl;
  const project = { id: 10, name: "example/project", url };
  const ref = "refs/heads/topic";
  const label = "display";
  function rows(repository = project, branch = ref) {
    const scope = {
      format: "semgrep-platform-findings/v1",
      deployment: "demo",
      project: repository,
      ref: branch,
      product: "sast",
      repositoryAliases: [label],
    };
    const row = { ref: branch, rule: { name: "fixture.rule" } };
    const native = [
      { ...row, id: 12, repository: { name: label } },
      {
        ...row,
        id: 13,
        repository: {
          name: label,
          id: String(repository.id),
          url: repository.url,
        },
      },
    ];
    const { findings } = normalizeSemgrepFindings(
      {
        ...scope,
        findingCount: native.length,
        findings: native,
      },
      {},
      "cloud",
    );
    for (const [i, finding] of findings.entries())
      finding.evidence.source_data = { ...scope, finding: native[i] };
    return findings;
  }
  const batch = rows();
  const prepare = (findings: typeof batch) => {
    const input = {
      findings,
      read: findings.length,
      excluded: [],
      sourceRepositoryUrl: url,
    };
    return prepareNormalizedExternalPublication(
      input,
      { ...options, provider: "semgrep" },
      f.deps,
    );
  };
  for (const unrelated of [
    rows({ ...project, id: 11 }),
    rows(project, "refs/heads/other"),
    rows({
      ...project,
      name: "other/project",
      url: "https://github.com/other/project",
    }),
  ]) {
    await expect(prepare([batch[0]!, unrelated[1]!])).rejects.toThrow(
      /witness|alias/,
    );
  }
  expect(f.posts).toHaveLength(0);
  const first = await prepare(batch);
  const witness =
    first.preview.findings[0]!.evidence.source_data?.["repositoryWitnessJson"];
  expect(JSON.parse(String(witness))).toEqual({
    name: label,
    id: String(project.id),
  });
  expect((await first.publish()).counts.created).toBe(2);
  expect((await (await prepare(batch)).publish()).counts.unchanged).toBe(2);
});

test("Semgrep Supply Chain binds package evidence to its case-sensitive source project", async () => {
  const url = "https://scm.example.test/Team/Project";
  const f = await hostedFixture(
    "semgrep",
    {
      format: semgrepPlatformFormat,
      deployment: "example",
      project: { id: "14", name: "Team/Project", url },
      product: "sca",
      ref: "refs/heads/topic",
      repositoryAliases: ["Team/Project"],
      findingCount: 1,
      findings: [
        JSON.stringify({
          id: 11,
          vulnerability_identifier: "CVE-2025-0001",
          found_dependency: {
            package: "example-package",
            ecosystem: "npm",
            version: "1.0.0",
          },
        }),
      ],
    },
    url,
  );
  const first = await f.prepareFile();
  expect(
    first.preview.findings[0]?.evidence.details?.repository,
  ).toBeUndefined();
  const other = "https://scm.example.test/Other/Project";
  const sarif = semgrepSarif();
  const run = sarif.runs[0]!;
  Object.assign(run, { versionControlProvenance: [{ repositoryUri: other }] });
  const mixed = normalizeSemgrepFindings(sarif, { sourceRepositoryUrl: other });
  delete mixed.findings[0]!.evidence.details;
  mixed.findings.push(...first.preview.findings);
  await expect(f.prepareNormalized(mixed)).rejects.toThrow(/does not match/);
  const prepareSarif = (repositoryUri: string) => {
    mixed.findings[0]!.evidence.source_data!["runContext"] = {
      versionControlProvenance: [{ repositoryUri }],
    };
    const input = { ...mixed, sourceRepositoryUrl: url };
    return f.prepareNormalized(input);
  };
  delete mixed.findings[0]!.evidence.source_data!["documentContext"];
  await expect(prepareSarif(other)).rejects.toThrow(/does not match/);
  expect((await prepareSarif(url)).preview.findings).toHaveLength(2);
  for (const unsafe of [
    "https://synthetic@scm.example.test/Team/Project",
    String.raw`https://scm.example.test\Other\Project?dest=/Team/Project`,
  ])
    await expect(prepareSarif(unsafe)).rejects.toThrow(/without credentials/);
  const projected = {
    read: 1,
    excluded: [],
    findings: first.preview.findings,
    sourceRepositoryUrl: "",
  };
  f.state.repositoryUrl = other;
  await expect(f.prepareNormalized(projected)).rejects.toThrow(/repository/i);
  // A normalized SDK caller can keep the project binding while projecting only titles.
  const opaque = {
    ...first.preview,
    findings: [
      {
        source_finding_id: "projected",
        evidence: { title: "Dependency", severity: "low" as const },
      },
    ],
  };
  await expect(f.prepareNormalized(opaque)).rejects.toThrow(/does not match/);
  await expect(f.prepareNormalized(opaque, "wiz")).rejects.toThrow(
    /semgrep provider/,
  );
  const missingSource = { ...opaque, sourceRepositoryUrl: undefined };
  await expect(f.prepareNormalized(missingSource)).rejects.toThrow(
    /source-repository-url/,
  );
  f.state.repositoryUrl = url.toLowerCase();
  const alias = await f.prepareFile();
  expect(alias.preview.findings).toHaveLength(1);
  const strict = {
    ...projected,
    sourceRepositoryUrl: url,
    sourceRepositoryPlatform: "other" as const,
  };
  await expect(f.prepareNormalized(strict)).rejects.toThrow(/does not match/);
  f.state.repositoryUrl = url;
  strict.findings.push({
    source_finding_id: "blackduck-bom:" + "a".repeat(64),
    evidence: {
      title: "Projected package",
      severity: "high",
      source_data: { sourceRepositoryUrl: url.toLowerCase() },
    },
  });
  await expect(f.prepareNormalized(strict)).rejects.toThrow(/does not match/);
  f.state.repositoryUrl = url.replace(
    "scm.example.test/",
    "scm.example.test:443/",
  );
  await expect(f.prepareFile()).rejects.toThrow(/does not match/);
  expect(f.posts).toHaveLength(0);
});

test.each(["open-source", "code"] as const)(
  "a released Snyk %s checkpoint retains one request across projections and renames",
  async (product) => {
    const url = "https://github.com/example/project";
    const capture = snykRestFixture(product, { sourceRepositoryUrl: url });
    const input = normalizeSnykIssues(capture);
    delete input.findings[0]!.evidence.source_data;
    const f = await hostedFixture("snyk", capture, url);
    Reflect.deleteProperty(f.environment, "CODEX_SECURITY_CLOUD_BASE_URL");
    let repository = url;
    const bare = {
      read: input.read,
      findings: input.findings,
      excluded: input.excluded,
    };
    const projected = Object.assign(
      Object.create({
        get sourceRepositoryUrl() {
          return repository;
        },
      }) as typeof input,
      bare,
    );
    const prepare = () => f.prepareNormalized(projected);

    await expect(prepare()).rejects.toThrow(/Snyk original issue/);
    expect(f.posts).toHaveLength(0);

    // The released SDK approved these findings without retaining a native issue.
    const { file, checkpoint } = releasedSnykCheckpoints[product];
    await f.writeCheckpoint(file, checkpoint);
    const first = await f.prepareNormalized(bare);
    expect(first.preview.resumed).toBe(true);
    await f.loseResponse(first);
    await expect(f.prepareFile()).rejects.toThrow(
      "pending hosted Cloud request",
    );
    expect(f.posts).toEqual([JSON.stringify(checkpoint.requests[0])]);

    f.state.repositoryUrl = "https://github.com/example/renamed";
    await expect(prepare()).rejects.toThrow(/does not match/);
    expect((await f.prepareNormalized(bare)).preview.resumed).toBe(true);
    f.state.repositoryUrl = url;
    expect((await prepare()).preview.resumed).toBe(true);
    const bareRetry = await f.prepareNormalized(bare);
    expect(bareRetry.preview.requests).toEqual(first.preview.requests);
    repository = "https://github.com/example/different";
    await expect(prepare()).rejects.toThrow(/does not match/);
    repository = url;
    // Binding while the catalog still matches establishes the URL for a future rename.
    await f.loseResponse(await prepare());
    f.state.repositoryUrl = "https://github.com/example/renamed";
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toHaveLength(3);
    expect(new Set(f.posts).size).toBe(1);
  },
);

test("a released Snyk checkpoint cannot authenticate the case of a typed URL", async () => {
  const url = "https://scm.example.test/Team/Repo";
  const f = await hostedFixture("snyk", [], url.toLowerCase());
  const report = snykRestFixture("code", { sourceRepositoryUrl: url });
  const project = JSON.parse(report.projectJson);
  project.attributes.origin = "gitlab";
  report.projectJson = JSON.stringify(project);
  const { snykRestContext, findings } = normalizeSnykIssues(report);
  findings[0]!.source_finding_id = "projected";
  delete findings[0]!.evidence.source_data;
  const bare = { read: 1, excluded: [], findings };
  const pending = await f.loseResponse(await f.prepareNormalized(bare));
  await useReleasedCheckpoint(pending);

  await expect(
    f.prepareNormalized({ ...bare, snykRestContext }),
  ).rejects.toThrow(/does not match/);
  expect((await f.prepareNormalized(bare)).preview.resumed).toBe(true);
});

test.each([
  ["Kit", "Kit"],
  ["Kit", "Kit"],
  ["åpp", "Åpp"],
])(
  "released catalog spelling %s cannot authorize %s after a rename",
  async (catalog, typed) => {
    const root = "https://github.com/example/";
    const url = root + typed;
    const f = await hostedFixture("snyk", [], root + catalog);
    const { findings } = normalizeSnykIssues(
      snykRestFixture("code", { sourceRepositoryUrl: url }),
    );
    findings[0]!.source_finding_id = "reader-issue";
    delete findings[0]!.evidence.source_data;
    const bare = { read: 1, excluded: [], findings };
    const pending = await f.loseResponse(await f.prepareNormalized(bare));
    await useReleasedCheckpoint(pending);
    const original = await readFile(pending);

    f.state.repositoryUrl = root + "renamed";
    await expect(
      f.prepareNormalized({ ...bare, sourceRepositoryUrl: url }),
    ).rejects.toThrow(/does not match/);
    expect(await readFile(pending)).toEqual(original);
    const retry = await f.prepareNormalized(bare);
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test("a rejected projected Black Duck row leaves a released Snyk checkpoint recoverable", async () => {
  const url = "https://github.com/example/project";
  const f = await hostedFixture("snyk", [], url);
  const input = normalizeBlackDuckFindings([blackDuckBomRow()], url);
  input.findings[0]!.evidence.source_data = { sourceRepositoryUrl: url };
  const prepare = (sourceRepositoryUrl: string) =>
    f.prepareNormalized({ ...input, sourceRepositoryUrl });
  const pending = await f.loseResponse(await prepare(url));
  await useReleasedCheckpoint(pending);
  const original = await readFile(pending);

  f.state.repositoryUrl = "https://github.com/example/renamed";
  await expect(prepare(f.state.repositoryUrl)).rejects.toThrow(
    /does not match/,
  );
  expect(await readFile(pending)).toEqual(original);
  f.state.repositoryUrl = url;
  const retry = await prepare(url);
  expect(retry.preview.resumed).toBe(true);
  await retry.publish();
  expect(f.posts[1]).toBe(f.posts[0]);
});

test("a Snyk retry adopts case sensitivity when the operator publishes", async () => {
  const url = "https://scm.example.test/Team/Repo";
  const f = await hostedFixture("snyk", [], url);
  const bare = {
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: "projected",
        evidence: { title: "Dependency", severity: "low" as const },
      },
    ],
  };
  const strict = () =>
    f.prepareNormalized({
      ...bare,
      sourceRepositoryUrl: url,
      sourceRepositoryPlatform: "other",
    });
  const alias = () =>
    f.prepareNormalized({ ...bare, sourceRepositoryUrl: url.toLowerCase() });
  const initial = await strict();
  const pending = await f.loseResponse(initial);
  await expect(alias()).rejects.toThrow(/does not match/);

  // The released SDK did not record a repository URL or SCM policy.
  await useReleasedCheckpoint(pending);
  const strictRetry = await strict();
  const aliasRetry = await alias();
  expect(f.posts).toHaveLength(1);
  await f.loseResponse(aliasRetry);
  await f.loseResponse(strictRetry);
  await expect(alias()).rejects.toThrow(/does not match/);

  f.state.repositoryUrl = "https://scm.example.test/Team/Renamed";
  await expect(
    f.prepareNormalized({
      ...bare,
      sourceRepositoryUrl: f.state.repositoryUrl,
    }),
  ).rejects.toThrow(/does not match/);
  const retry = await strict();
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.requests).toEqual(initial.preview.requests);
  expect((await f.prepareNormalized(bare)).preview.requests).toEqual(
    initial.preview.requests,
  );
  await retry.publish();
  expect(f.posts).toEqual(Array(4).fill(f.posts[0]));
});

test("Snyk Code accepts equivalent URL escapes and still rejects a foreign typed row", async () => {
  const url = "https://github.com/example/project";
  const report = snykRestFixture("code", {
    sourceRepositoryUrl: url.replace("/project", "/%70roject"),
  });
  const f = await hostedFixture("snyk", report, url);
  const preview = await f.prepareFile();
  expect(preview.preview.findings).toHaveLength(1);

  const input = normalizeSnykIssues(report);
  expect((await f.prepareNormalized(input)).preview.findings).toHaveLength(1);
  for (const foreign of [
    "https://github.com/other/project",
    "https://github.com:8443/example/project",
  ]) {
    input.findings[0]!.evidence.details!.repository!.url = foreign;
    await expect(f.prepareNormalized(input)).rejects.toThrow(/repository/i);
  }
  expect(f.posts).toHaveLength(0);
});

test.each(["semgrep", "snyk"] as const)(
  "%s file publication uses the authenticated GitHub repository for private-host aliases",
  async (provider) => {
    const url = "https://scm.example.test/Org/Repo";
    const selected = selectedSemgrepReport(
      { name: "Org/Repo", url },
      { repository: { url: url.toLowerCase() }, rule_name: "sample.rule" },
      [{ url, platform: "github" }],
    );
    const snyk = snykRestFixture("code", { sourceRepositoryUrl: url });
    const project = JSON.parse(snyk.projectJson);
    project.attributes.origin = "cli";
    project.relationships.target.data.attributes.url =
      "git@scm.example.test:org/repo.git";
    snyk.projectJson = JSON.stringify(project);
    const report = provider === "semgrep" ? selected : snyk;
    const f = await hostedFixture(provider, report, url);
    const first = await f.prepareFile();
    expect(first.preview.findings).toHaveLength(1);
    expect(f.state.catalogReads).toBe(1);
    const renamed = "https://scm.example.test/Another/Repo";
    f.state.repositoryUrl = renamed;
    await expect(f.prepareFile()).rejects.toThrow(/repository|project/iu);
    expect(f.posts).toHaveLength(0);
    f.state.repositoryUrl = url;
    await f.loseResponse(first);
    f.state.repositoryUrl = renamed;
    const retry = await f.prepareFile();
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toHaveLength(2);
    expect(f.posts[1]).toBe(f.posts[0]);
    await expect(f.prepareFile()).rejects.toThrow(/repository|project/iu);
  },
);

test.each(["file", "operator"])(
  "Semgrep v1 keeps the native project's explicit port when checking %s mappings",
  async (mapping) => {
    const url = "https://scm.example.test:443/team/project";
    const ref = "refs/heads/release";
    const report = {
      format: "semgrep-platform-findings/v1",
      deployment: "example",
      project: { id: 14, name: "team/project", url },
      ref,
      product: "sast",
      findingCount: 1,
      findings: [{ id: 23, ref, rule: { name: "sample.check" } }],
    };
    const f = await fixture(report, url);
    const prepare = async (sourceRepositoryUrl: string) => {
      if (mapping === "file")
        await writeFile(
          f.file,
          JSON.stringify({ ...report, sourceRepositoryUrl }),
        );
      return prepareExternalPublication(
        f.file,
        {
          ...options,
          provider: "semgrep",
          ...(mapping === "operator" && { sourceRepositoryUrl }),
        },
        f.deps,
      );
    };
    const withoutPort = url.replace(":443", "");
    for (const catalog of [withoutPort, url]) {
      f.state.repositoryUrl = catalog;
      await expect(prepare(withoutPort)).rejects.toThrow(/does not match/);
    }
    expect((await prepare(url)).preview.findings).toHaveLength(1);
    expect(f.posts).toHaveLength(0);
  },
);

test.each([true, false])(
  "a Semgrep v1 private SSH file retries after a rename (operator mapping %s)",
  async (mapped) => {
    const url = "https://scm.example.test/Org/Repo";
    const ref = "refs/heads/release";
    const f = await fixture(
      {
        format: "semgrep-platform-findings/v1",
        deployment: "example",
        project: {
          id: 14,
          name: "Org/Repo",
          url: "git@scm.example.test:org/repo.git",
        },
        product: "sast",
        ref,
        findingCount: 1,
        findings: [
          { id: 23, ref, rule: { name: "sample.rule" }, repository: { url } },
        ],
      },
      url,
    );
    const prepare = (sourceRepositoryUrl = mapped ? url : undefined) =>
      prepareExternalPublication(
        f.file,
        { ...options, provider: "semgrep", sourceRepositoryUrl },
        f.deps,
      );
    await f.loseResponse(await prepare());
    f.state.repositoryUrl = "https://scm.example.test/Org/Renamed";
    await expect(
      prepare(url.replace(".test/", ".test:443/")),
    ).rejects.toThrow();
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toHaveLength(2);
    expect(f.posts[1]).toBe(f.posts[0]);
    await expect(prepare()).rejects.toThrow(/repository|project/iu);
  },
);

test.each([true, false])(
  "an escaped projected repository in a Snyk checkpoint matches the current destination (declared %s)",
  async (declared) => {
    const f = await fixture();
    const url = f.state.repositoryUrl;
    const escaped = url.replace("/project", "/%70roject");
    const result = normalizeSnykIssues(
      snykRestFixture("code", { sourceRepositoryUrl: url }),
    );
    const input = declared
      ? result
      : {
          read: result.read,
          excluded: result.excluded,
          findings: result.findings,
        };
    result.findings[0]!.evidence.details!.repository!.url = escaped;
    const prepare = () =>
      prepareNormalizedExternalPublication(
        input,
        { ...options, provider: "snyk" },
        f.deps,
      );
    f.state.repositoryUrl = "https://github.com/example/different";
    await expect(prepare()).rejects.toThrow(
      /does not match the selected Cloud repository/,
    );
    expect(f.posts).toHaveLength(0);
    f.state.repositoryUrl = url;
    await f.loseResponse(await prepare());
    f.state.repositoryUrl = url.replace("/project", "/Project");
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toHaveLength(2);
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test.each(["semgrep", "snyk"] as const)(
  "a strict %s source and opaque Black Duck projection survive a catalog casing change",
  async (provider) => {
    const url = "https://scm.example.test/Team/Project";
    const f = await hostedFixture(provider, [], url);
    const projected = normalizeBlackDuckFindings([blackDuckBomRow()], url)
      .findings[0]!;
    projected.evidence.source_data = { sourceRepositoryUrl: url };
    const report = {
      read: 1,
      excluded: [],
      findings: [projected],
      sourceRepositoryUrl: url,
      sourceRepositoryPlatform: "other" as const,
    };
    await f.loseResponse(await f.prepareNormalized(report));
    f.state.repositoryUrl = "https://scm.example.test/Other/Project";
    await expect(f.prepareNormalized(report)).rejects.toThrow(/does not match/);
    f.state.repositoryUrl = url.toLowerCase();
    const retry = await f.prepareNormalized(report);
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toHaveLength(2);
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test.each(["semgrep", "snyk"] as const)(
  "a projected Black Duck finding cannot resume under a different %s catalog authority",
  async (provider) => {
    const url = "https://127.0.0.1:443/Org/Project";
    const f = await hostedFixture(provider, [], url);
    const bare = normalizeBlackDuckFindings([blackDuckBomRow()], url);
    bare.findings[0]!.evidence.source_data = { sourceRepositoryUrl: url };
    const declared = { ...bare, sourceRepositoryUrl: url };
    const pending = await f.loseResponse(await f.prepareNormalized(bare));
    await useReleasedCheckpoint(pending);
    expect((await f.prepareNormalized(declared)).preview.resumed).toBe(true);
    const saved = await readFile(pending);

    f.state.repositoryUrl = "https://0177.1.:443/Org/Project";
    await expect(f.prepareNormalized(bare)).rejects.toThrow(/does not match/);
    await expect(f.prepareNormalized(declared)).rejects.toThrow(
      /does not match/,
    );
    expect(await readFile(pending)).toEqual(saved);
    expect(f.posts).toHaveLength(1);

    f.state.repositoryUrl = url;
    await (await f.prepareNormalized(declared)).publish();
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test("a private Snyk GitHub project uses its authenticated catalog alias", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = snykRestFixture("code", { sourceRepositoryUrl: url });
  const project = JSON.parse(report.projectJson);
  project.attributes.origin = "github-enterprise";
  report.projectJson = JSON.stringify(project);
  const f = await hostedFixture("snyk", report, url.toLowerCase());
  const first = await f.prepareFile();
  expect(first.preview.findings).toHaveLength(1);

  project.attributes.origin = "gitlab";
  report.projectJson = JSON.stringify(project);
  await writeFile(f.file, JSON.stringify(report));
  await expect(f.prepareFile()).rejects.toThrow(/repository/i);
  expect(f.posts).toHaveLength(0);
});

test("an original Semgrep SDK row keeps the approved repository casing on retry", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = selectedSemgrepReport(
    { name: "Team/Project", url },
    { rule_name: "sample.rule" },
  );
  const f = await hostedFixture("semgrep", report, url);
  const { findings } = (await f.prepareFile()).preview;
  const raw = findings[0]!.evidence.source_data!;
  raw["format"] = "semgrep-platform-findings/v1";
  raw["finding"] = JSON.parse(report.findings[0]!);
  delete raw["semgrepPlatformFindingJson"];
  raw["sourceRepositoryUrl"] = url;
  const bare = { read: 1, findings, excluded: [] };
  const first = await f.prepareNormalized({
    ...bare,
    sourceRepositoryPlatform: "other",
  });
  await f.loseResponse(first);
  raw["sourceRepositoryUrl"] = url.toLowerCase();
  await expect(f.prepareNormalized(bare)).rejects.toThrow(
    /original Semgrep input and SCM repository mapping/u,
  );
  raw["sourceRepositoryUrl"] = url;
  expect((await f.prepareNormalized(bare)).preview.requests).toEqual(
    first.preview.requests,
  );
});

test("an original Semgrep SDK row keeps its approved GitHub alias after a rename", async () => {
  const url = "https://scm.example.test/Org/Repo";
  const ref = "refs/heads/release";
  const scope = {
    format: "semgrep-platform-findings/v1",
    deployment: "example",
    project: { id: 14, name: "Org/Repo", url },
    ref,
    product: "sast",
  };
  const finding = {
    id: 23,
    ref,
    rule: { name: "sample.rule" },
    repository: { name: "org/repo", url },
  };
  const f = await hostedFixture(
    "semgrep",
    { ...scope, findingCount: 1, findings: [finding] },
    url,
  );
  const first = await f.prepareFile();
  const findings = structuredClone(first.preview.findings);
  findings[0]!.evidence.source_data = { ...scope, finding };
  const sdk = { read: 1, excluded: [], findings, sourceRepositoryUrl: url };
  await f.loseResponse(first);
  f.state.repositoryUrl = "https://scm.example.test/Org/Renamed";
  const retry = await f.prepareNormalized(sdk);
  expect(retry.preview.resumed).toBe(true);
  await retry.publish();
  expect(f.posts[1]).toBe(f.posts[0]);
  await expect(f.prepareNormalized(sdk)).rejects.toThrow(
    /repository|project/iu,
  );
});

test.each(["interrupted file", "completed SDK"])(
  "Semgrep v1 file and original SDK rows reuse the same evidence (%s)",
  async (first) => {
    const url = "https://scm.example.test/Team/Project";
    const id = "9007199254740993";
    const scope = {
      format: "semgrep-platform-findings/v1",
      deployment: "example",
      project: { id: 77, name: "Team/Project", url: null },
      sourceRepositoryUrl: url,
      ref: "refs/heads/release",
      product: "sast",
      repositoryAliases: ["project"],
    };
    const finding = {
      id,
      ref: scope.ref,
      repository: { name: "project", url: url.toLowerCase() },
      rule: { name: "sample.check" },
      severity: "HIGH",
      location: { file_path: "src\\service.ts", line: 3, end_line: 5 },
    };
    const report = {
      ...scope,
      findingCount: 1,
      findings: [finding],
      numericFields: { findings: { 0: { id } } },
    };
    const f = await hostedFixture("semgrep", report, url);
    const { read, findings, excluded } = normalizeSemgrepFindings(
      report,
      { sourceRepositories: [{ url, platform: "github" }] },
      "cloud",
    );
    const sdk = { read, findings, excluded };
    const evidence = findings[0]!.evidence;
    evidence.severity = "unknown";
    evidence.locations = [];
    evidence.details!.code!.end_line = null;
    findings[0]!.evidence.source_data = {
      ...scope,
      finding,
      numericFields: { finding: { id } },
    };
    const otherPort = structuredClone(sdk);
    otherPort.findings[0]!.evidence.source_data!["sourceRepositoryUrl"] =
      url.replace(".test/", ".test:443/");
    await expect(f.prepareNormalized(otherPort)).rejects.toThrow(
      /repository/iu,
    );
    if (first === "interrupted file") {
      await f.loseResponse(await f.prepareFile());
      f.state.repositoryUrl = "https://scm.example.test/Team/Renamed";
      const retry = await f.prepareNormalized(sdk);
      expect(retry.preview.resumed).toBe(true);
      await retry.publish();
      expect(f.posts[1]).toBe(f.posts[0]);
      await expect(f.prepareNormalized(sdk)).rejects.toThrow(
        /repository|project/i,
      );
    } else {
      expect(
        (await (await f.prepareNormalized(sdk)).publish()).counts.created,
      ).toBe(1);
      expect((await (await f.prepareFile()).publish()).counts.unchanged).toBe(
        1,
      );
    }
  },
);

test("a Semgrep selection with distinct submitted and native IDs remains independent", async () => {
  const url = "https://github.com/example/project";
  const capture = selectedSemgrepReport(
    { name: "example/project", url },
    { rule_name: "example.rule" },
  );
  const f = await hostedFixture("semgrep", capture, url);
  const prepare = (nativeId: number, submittedId: string) => {
    const findings = capture.findings.map((row) =>
      JSON.stringify({ ...JSON.parse(row), id: nativeId }),
    );
    const input = normalizeSemgrepFindings(
      { ...capture, findings },
      {},
      "cloud",
    );
    input.findings[0]!.source_finding_id = submittedId;
    return f.prepareNormalized(input);
  };
  await f.loseResponse(await prepare(23, "first-ticket"));
  await expect(prepare(23, "another-ticket")).rejects.toThrow(
    "pending hosted Cloud request",
  );
  await expect(prepare(24, "first-ticket")).rejects.toThrow(
    "pending hosted Cloud request",
  );
  expect((await prepare(24, "another-ticket")).preview.resumed).toBe(false);
  expect(f.posts).toHaveLength(1);
});

test.each(["semgrep", "snyk"] as const)(
  "%s holds an overlapping native update until the initial request is recovered",
  async (provider) => {
    const url = "https://github.com/example/project";
    const report =
      provider === "semgrep"
        ? selectedSemgrepReport(
            { name: "example/project", url },
            { rule_name: "example.rule" },
          )
        : snykRestFixture("open-source", { sourceRepositoryUrl: url });
    const f = await hostedFixture(provider, report, url);
    const first = await f.prepareFile();
    const original = {
      findings: first.preview.findings,
      read: first.preview.findings.length,
      excluded: [],
      sourceRepositoryUrl: url,
      report: { capture: "example" },
    };
    if (provider === "semgrep")
      original.findings[0]!.source_finding_id = "caller-selected";
    const changed = structuredClone(original);
    changed.findings[0]!.evidence.title += " updated";
    const stale = await f.prepareNormalized(changed);
    f.state.marker = "next-generation";
    const challenger = await f.prepareNormalized(changed);
    const winner = await f.prepareNormalized(original);
    const observer = observeLockContention();
    const rename = fs.rename;
    let competing: Promise<unknown> | undefined;
    const install = spyOn(fs, "rename").mockImplementationOnce(
      async (...args) => {
        // Start the other publisher after the winner's pending scan and before its atomic rename.
        competing = challenger.publish().catch((error: unknown) => error);
        const first = await Promise.race([
          observer.contended.then(() => "locked"),
          competing.then(() => "completed"),
        ]);
        expect(first).toBe("locked");
        return rename(...args);
      },
    );
    let pending: string;
    try {
      pending = await f.loseResponse(winner);
      expect(String(await competing)).toContain("pending hosted Cloud request");
    } finally {
      install.mockRestore();
      observer.restore();
    }
    const bytes = await readFile(pending, "utf8");
    if (provider === "semgrep") {
      const projected = structuredClone(changed);
      delete projected.findings[0]!.evidence.source_data;
      await expect(f.prepareNormalized(projected)).rejects.toThrow(
        "pending hosted Cloud request",
      );
    }
    await expect(stale.publish()).rejects.toThrow("reset markers");

    await expect(f.prepareFile()).rejects.toThrow(
      "deployment could not be established",
    );
    await expect(f.prepareNormalized(changed)).rejects.toThrow(
      "pending hosted Cloud request",
    );
    expect(await readFile(pending, "utf8")).toBe(bytes);
    expect(f.posts).toHaveLength(1);
    const captured = await f.prepareNormalized(original);
    await (await f.prepareNormalized(original)).publish();
    expect(f.posts[1]).toBe(f.posts[0]);
    const newer = await f.loseResponse(await f.prepareNormalized(changed));
    const approved = await readFile(newer, "utf8");
    await expect(captured.publish()).rejects.toThrow(
      "pending hosted Cloud request",
    );
    expect(f.posts).toHaveLength(3);
    expect(await readFile(newer, "utf8")).toBe(approved);
    expect(
      (await (await f.prepareNormalized(changed)).publish()).counts.updated,
    ).toBe(1);
  },
);

test.each([
  ["semgrep", "native"],
  ["semgrep", "SDK metadata and assigned IDs"],
  ["semgrep", "released assigned IDs"],
  ["semgrep", "released ID only"],
  ["semgrep", "released assigned JSON row"],
  ["snyk", "released assigned JSON row"],
  ["snyk", "released assigned IDs"],
  ["semgrep", "per-finding metadata"],
  ["semgrep", "projected metadata"],
  ["snyk", "released unmarked with metadata"],
  ["snyk", "released compact issue JSON"],
  ["semgrep", "released relabeled with metadata"],
  ["semgrep", "released normalized SDK"],
  ["semgrep", "released partial object row"],
  ["semgrep", "released partial JSON row"],
  ["semgrep", "released partial native project URL"],
  ["semgrep", "released without format"],
  ["snyk", "released without format"],
  ["semgrep", "released unrelated evidence"],
  ["snyk", "released unrelated evidence"],
  ["snyk", "native"],
  ["snyk", "projected evidence"],
] as const)(
  "%s preserves the pending v1 request across a reader upgrade (%s)",
  async (provider, mode) => {
    const url = "https://github.com/example/project";
    const project = { id: 14, name: "example/project", url };
    const ref = "refs/heads/release";
    const finding = {
      id: 23,
      ref,
      repository: { url },
      severity: "high",
      rule_name: "example.rule",
    };
    const nativeFindings = [finding, { ...finding, id: 24 }];
    const { projectJson, targetJson, pages, ...scope } = snykRestFixture(
      "code",
      { sourceRepositoryUrl: url },
    );
    const semgrep = {
      format: "semgrep-platform-findings/v1",
      deployment: "example",
      project: mode === "native" ? { ...project, url: null } : project,
      ...(mode === "native" && { sourceRepositoryUrl: url }),
      product: "sast",
      ref,
      repositoryAliases: [],
    };
    const report =
      provider === "semgrep"
        ? {
            ...semgrep,
            findingCount: nativeFindings.length,
            findings: nativeFindings,
          }
        : {
            ...scope,
            format: "snyk-rest-issues/v1",
            project: JSON.parse(projectJson),
            target: JSON.parse(targetJson),
            pages: pages.map(({ startingAfter, responseJson }) => ({
              startingAfter,
              response: JSON.parse(responseJson),
            })),
          };
    const f = await hostedFixture(
      provider,
      provider === "snyk" && mode === "released assigned JSON row"
        ? snykRestFixture("code", { sourceRepositoryUrl: url })
        : report,
      url,
    );
    // The legacy filename below belongs to the default Cloud deployment.
    Reflect.deleteProperty(f.environment, "CODEX_SECURITY_CLOUD_BASE_URL");
    const prior = await f.prepareFile();
    const current = await f.loseResponse(prior);
    const dir = dirname(current);
    const pending = JSON.parse(await readFile(current, "utf8"));
    delete pending.approvedRepositoryUrl;
    delete pending.approvedRepositoryPlatform;
    const request = pending.requests[0] as FindingImportRequest;
    const rows = request.items.map(({ source_finding_id, evidence }, index) => {
      if (provider === "semgrep" && mode !== "released assigned JSON row")
        evidence.source_data = { ...semgrep, finding: nativeFindings[index] };
      return { source_finding_id, evidence };
    });
    const omittedMetadata =
      mode === "released compact issue JSON" ||
      (provider === "semgrep" && mode === "released without format");
    const metadata =
      mode === "SDK metadata and assigned IDs" || omittedMetadata
        ? { batch: "example" }
        : undefined;
    const assigned =
      metadata ||
      mode === "projected metadata" ||
      mode === "released assigned IDs" ||
      mode === "released assigned JSON row" ||
      mode === "released unrelated evidence";
    if (assigned)
      rows.forEach((row, index) => {
        request.items[index]!.source_finding_id = row.source_finding_id =
          "custom-" + index;
      });
    const released = mode.startsWith("released ");
    const enrichedNative =
      mode === "released unmarked with metadata" ||
      mode === "released relabeled with metadata";
    if (mode === "released compact issue JSON")
      for (const { evidence } of rows)
        evidence.source_data = {
          issueJson: JSON.stringify(evidence.source_data!["issue"]),
        };
    if (mode === "released without format")
      for (const { evidence } of rows) delete evidence.source_data!["format"];
    if (enrichedNative)
      for (const { evidence } of rows)
        evidence.source_data =
          provider === "snyk"
            ? { issue: evidence.source_data!["issue"] }
            : { ...evidence.source_data, format: "normalized/v1" };
    if (mode === "released unrelated evidence")
      for (const { evidence } of rows)
        evidence.source_data = {
          project: { label: "example" },
          [provider === "semgrep" ? "finding" : "issue"]: { note: "custom" },
        };
    if (
      mode === "projected evidence" ||
      mode === "projected metadata" ||
      mode === "released ID only"
    )
      for (const { evidence } of rows) delete evidence.source_data;
    const partial =
      mode === "released partial object row" ||
      mode === "released partial JSON row" ||
      mode === "released partial native project URL";
    if (partial) {
      for (const { evidence } of rows) {
        delete evidence.details;
        const nativeProjectUrl = "git@github.com:example/project.git";
        if (mode === "released partial native project URL") {
          evidence.source_data = {
            format: "semgrep-platform-findings/v2",
            nativeProjectUrl,
            semgrepPlatformFindingJson: JSON.stringify({
              ref,
              rule_name: "example.rule",
            }),
          };
          continue;
        }
        const finding = { ref, repository: { url: nativeProjectUrl } };
        evidence.source_data = {
          format: semgrep.format,
          ...(mode === "released partial object row"
            ? { finding }
            : { semgrepPlatformFindingJson: JSON.stringify(finding) }),
        };
      }
    }
    const originalRows =
      mode === "per-finding metadata" ||
      mode === "projected metadata" ||
      enrichedNative
        ? rows.map((row, index) => ({ ...row, ticket: "example-" + index }))
        : rows;
    const identity = metadata
      ? { findings: originalRows, report: metadata }
      : originalRows;
    const digest = (value: unknown) => hash("sha256", canonicalJson(value));
    pending.inputProjection = {
      savedEvidenceDigest: digest(rows),
      inputDigest: released
        ? digest(identity)
        : digest([
            identity,
            [url, provider === "semgrep" ? null : false, false],
          ]),
    };
    const oldKey = digest([
      pending.accountId,
      request.repository.id,
      request.repository.repo_connector_id,
      request.source,
      identity,
    ]);
    const oldPath = join(dir, oldKey + ".pending.json");
    await rm(current);
    let bytes = JSON.stringify(pending);
    await writeFile(oldPath, bytes, { mode: 0o600 });

    const input = {
      read: rows.length,
      excluded: [],
      findings: structuredClone(prior.preview.findings),
      sourceRepositoryUrl: url,
      ...(metadata && { report: metadata }),
    };
    if (assigned)
      input.findings.forEach((row, index) => {
        row.source_finding_id = rows[index]!.source_finding_id;
      });
    const prepareRows = (findings: ExternalFindings["findings"]) =>
      f.prepareNormalized({ ...input, read: findings.length, findings });
    const retry = metadata ? () => f.prepareNormalized(input) : f.prepareFile;
    if (mode === "released ID only") {
      const assigned = input.findings.map((row, i) => ({
        ...row,
        source_finding_id: "ticket-" + i,
      }));
      await expect(prepareRows(assigned)).rejects.toThrow("pending hosted");
      expect(await readFile(oldPath, "utf8")).toBe(bytes);
      expect(f.posts).toHaveLength(1);
      return;
    }
    if (mode === "released assigned IDs" || omittedMetadata) {
      // The scanner now generates different IDs for the original native rows.
      await expect(f.prepareFile()).rejects.toThrow("pending hosted");
      expect(await readFile(oldPath, "utf8")).toBe(bytes);
      expect(f.posts).toHaveLength(1);
      return;
    }
    if (mode === "released unrelated evidence") {
      expect((await retry()).preview.resumed).toBe(false);
      expect(await readFile(oldPath, "utf8")).toBe(bytes);
      return;
    }
    if (partial) {
      const bare = { read: rows.length, excluded: [], findings: rows };
      await expect(
        f.prepareNormalized({
          ...bare,
          sourceFormat: semgrep.format,
          sourceRepositoryUrl: url,
          semgrepPlatformScope: {
            deployment: semgrep.deployment,
            projectId: String(project.id),
            product: semgrep.product,
            ref: "refs/heads/other",
          },
        }),
      ).rejects.toThrow(/scope/iu);
      f.state.repositoryUrl = "https://github.com/example/renamed";
      await expect(
        f.prepareNormalized({
          ...bare,
          sourceRepositoryUrl: f.state.repositoryUrl,
        }),
      ).rejects.toThrow(/repository|project/i);
      expect((await f.prepareNormalized(bare)).preview.requests).toEqual(
        pending.requests,
      );
      f.state.repositoryUrl = url;
      expect((await prepareRows(rows)).preview.requests).toEqual(
        pending.requests,
      );
      return;
    }
    if (mode === "released normalized SDK") {
      expect((await prepareRows(rows)).preview.resumed).toBe(true);
      bytes = await readFile(oldPath, "utf8");
      expect(JSON.parse(bytes)).toMatchObject({
        approvedRepositoryUrl: url,
        requests: pending.requests,
        inputProjection: {
          ...pending.inputProjection,
          retainedHostedSelection: true,
        },
      });
    }
    const older = "Resume it with the SDK build that created it";
    if (mode === "projected metadata") {
      const edited = structuredClone(originalRows).reverse();
      edited[0]!.evidence.title += " updated";
      await expect(prepareRows(edited)).rejects.toThrow(older);
      expect((await prepareRows(rows)).preview.resumed).toBe(false);
      expect(await readFile(oldPath, "utf8")).toBe(bytes);
      return;
    }
    await expect(retry()).rejects.toThrow(older);
    // The exact projected path has a bare filename but a repository-bound payload digest.
    if (mode === "projected evidence")
      await expect(prepareRows(rows)).rejects.toThrow(older);
    const changed = structuredClone(input.findings).reverse();
    changed[0]!.evidence.title += " changed";
    await expect(prepareRows(changed)).rejects.toThrow(older);
    const unrelated = {
      source_finding_id: "unrelated",
      evidence: { title: "Another finding", severity: "high" as const },
    };
    if (mode === "native") {
      const other = "https://github.com/example/another";
      f.state.repositoryUrl = other;
      const otherInput = {
        ...input,
        read: 1,
        findings: [unrelated],
        sourceRepositoryUrl: other,
      };
      const fresh = await prepareNormalizedExternalPublication(
        otherInput,
        { ...options, provider },
        {
          ...f.deps,
          environment: {
            ...f.environment,
            CODEX_SECURITY_CLOUD_BASE_URL:
              "http://127.0.0.1:4200/backend-api/aardvark",
          },
        },
      );
      expect(fresh.preview.resumed).toBe(false);
      f.state.repositoryUrl = url;
    }
    if (enrichedNative) {
      await expect(
        prepareRows([input.findings[0]!, unrelated]),
      ).rejects.toThrow(older);
    }
    const disjoint = prepareRows([unrelated]);
    if (released || mode === "per-finding metadata")
      expect((await disjoint).preview.resumed).toBe(false);
    else await expect(disjoint).rejects.toThrow(older);
    expect(f.posts).toHaveLength(1);
    expect(await readFile(oldPath, "utf8")).toBe(bytes);
    f.state.marker = "generation-2";
    if (mode === "per-finding metadata" || enrichedNative) {
      await expect(retry()).rejects.toThrow(
        "deployment could not be established",
      );
      expect(await readFile(oldPath, "utf8")).toBe(bytes);
    }
    const afterReset =
      mode === "projected evidence" ||
      mode === "per-finding metadata" ||
      enrichedNative
        ? () => prepareRows(originalRows)
        : retry;
    await expect(afterReset()).rejects.toThrow("retired without uploading");
    expect(
      (await readdir(dir)).filter((name) => name.endsWith(".pending.json")),
    ).toEqual([]);
    expect((await retry()).preview.resumed).toBe(false);
    expect(f.posts).toHaveLength(1);
  },
);

function sonarCapture(repositoryUrl: string) {
  return {
    format: "sonar-issues/v1" as const,
    server: "https://sonarcloud.io",
    organization: "example",
    project: "example_project",
    branch: "main",
    projectBase: "",
    repositoryUrl,
    pages: [
      {
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [
          {
            key: "issue-1",
            project: "example_project",
            component: "file",
            rule: "example:R1",
            message: "Review input handling",
            type: "VULNERABILITY",
            severity: "CRITICAL",
            flows: [
              {
                locations: [
                  {
                    component: "file",
                    textRange: { startLine: 2, endLine: 3 },
                  },
                ],
              },
            ],
          },
        ],
        components: [{ key: "file", path: "src/example.ts" }],
      },
    ],
  };
}

test("Sonar replays the selected evidence locally and to Cloud without signing in to Sonar again", async () => {
  const repo = "https://github.com/example/project";
  const source = sonarCapture(repo);
  const f = await fixture(source, repo);
  const checkout = join(f.root, "checkout");
  const git = promisify(execFile);
  const environment = sonarGitTestEnvironment({
    ...f.cliDeps.environment,
    CODEX_SECURITY_CLOUD_BASE_URL: "https://cloud.example.test",
  });
  await git("git", ["init", "--quiet", checkout], { env: environment });
  await git("git", ["-C", checkout, "remote", "add", "origin", repo], {
    env: environment,
  });
  const paths = new Set<string>();
  const deps = {
    ...f.cliDeps,
    environment,
    currentDirectory: () => checkout,
    cloudFetch: (url: string, init: RequestInit) => {
      paths.add(new URL(url).pathname);
      return f.cliDeps.cloudFetch(url, init);
    },
  };
  const first = createCliTest(main);
  const previewExit = await first.runCli(
    [
      "import",
      "sonar",
      "--sonar-project",
      source.project,
      "--sonar-branch",
      source.branch,
      "--sonar-issue",
      "issue-1",
      "--dry-run",
      "--format",
      "json",
    ],
    {
      ...deps,
      collectSonarIssues: async (selection) => {
        expect(selection.issueKeys).toEqual(["issue-1"]);
        return source;
      },
    },
  );
  expect(previewExit, first.stderr.text()).toBe(0);
  expect(f.posts).toHaveLength(0);
  const capture: string = JSON.parse(first.stdout.text()).capture;
  expect(JSON.parse(await readFile(capture, "utf8"))).toEqual(source);
  const previewArgs = [
    "import",
    "sonar",
    capture,
    "--to",
    "cloud",
    "--format",
    "json",
  ];

  const outside = join(f.root, "without-remotes");
  await mkdir(outside);
  const noRemotes = createCliTest(main);
  expect(
    await noRemotes.runCli([...previewArgs, "--dry-run"], {
      ...deps,
      currentDirectory: () => outside,
    }),
  ).toBe(2);
  expect(noRemotes.stderr.text()).toContain("--source-repository-url");
  expect(f.posts).toHaveLength(0);

  const cloudPreview = createCliTest(main);
  expect(await cloudPreview.runCli([...previewArgs, "--dry-run"], deps)).toBe(
    0,
  );
  const reviewed = JSON.parse(cloudPreview.stdout.text());
  expect(reviewed.cloud.destination.url).toBe(repo);
  expect(reviewed.capture).not.toBe(capture);
  expect(f.posts).toHaveLength(0);
  const args = [
    "import",
    "sonar",
    reviewed.capture,
    "--to",
    "cloud",
    "--format",
    "json",
  ];

  const unavailable = createCliTest(main);
  expect(
    await unavailable.runCli([...args, "--yes"], {
      ...deps,
      cloudFetch: async () => new Response("Unknown account", { status: 403 }),
    }),
  ).toBe(2);
  expect(JSON.parse(unavailable.stdout.text()).local.counts.created).toBe(1);

  const replay = createCliTest(main);
  expect(await replay.runCli([...args, "--yes"], deps)).toBe(0);
  const result = JSON.parse(replay.stdout.text());
  expect(result.local.counts.unchanged).toBe(1);
  expect(result.cloud.verified).toBe(1);
  const posted = JSON.parse(f.posts[0]!);
  expect(posted.source).toEqual({
    provider: "sonar",
    source_key: result.sourceKey,
  });
  expect(posted.items[0].source_finding_id).toBe("issue-1");
  const repository = f.destination();
  const reportsPath = `/external/v2/repository_connectors/${repository.repo_connector_id}/repositories/${repository.id}/source_reports`;
  expect(paths).toEqual(
    new Set([
      "/external/repositories",
      reportsPath,
      "/external/v2/finding_imports",
      `${reportsPath}/${f.reports.get("issue-1")!.id}`,
    ]),
  );
  expect(posted.items[0].evidence.source_data.issue.flows).toEqual(
    source.pages[0]!.issues[0]!.flows,
  );
});

test("normalized Sonar publication checks retained bindings on preview and retry", async () => {
  const f = await fixture();
  const repository = f.state.repositoryUrl;
  const foreign = repository + "-other";
  const selected = { ...options, provider: "sonar" as const };
  const context = { format: "sonar-issues/v1", repositoryUrl: repository };
  const finding = {
    source_finding_id: "issue-1",
    evidence: {
      title: "Review input handling",
      severity: "high" as const,
      source_data: { ...context, issue: { key: "issue-1" } },
    },
  };
  const rows = { read: 1, findings: [finding], excluded: [] };
  const named = {
    source_finding_id: "issue-2",
    evidence: {
      ...finding.evidence,
      branch: "main",
      source_data: { ...context, branch: "main", issue: { key: "issue-2" } },
    },
  };
  const selection = { read: 2, findings: [finding, named], excluded: [] };
  const prepare = (findings = selection.findings) =>
    prepareReleased(
      f,
      { ...selection, findings, report: { ...context, branch: "main" } },
      selected,
    );
  await expect(prepareReleased(f, selection, selected)).rejects.toThrow(
    "without a ref",
  );
  await expect(
    prepareReleased(
      f,
      {
        ...rows,
        report: { ...context, branch: "main" },
        findings: [
          {
            ...finding,
            evidence: { ...finding.evidence, branch: "unrelated" },
          },
        ],
      },
      selected,
    ),
  ).rejects.toThrow("retained Sonar branch");
  await expect(
    prepareReleased(
      f,
      { ...rows, report: { ...context, repositoryUrl: foreign } },
      selected,
    ),
  ).rejects.toThrow("does not match the selected Cloud repository");
  f.state.loseResponse = true;
  await expect((await prepare()).publish()).rejects.toThrow(
    "resume the saved request",
  );
  await expect(
    prepareReleased(
      f,
      { ...selection, report: { ...context, branch: "other" } },
      selected,
    ),
  ).rejects.toThrow("conflicting branch");
  f.state.repositoryUrl = foreign;
  await expect(prepare()).rejects.toThrow(
    "does not match the selected Cloud repository",
  );
  expect(f.posts).toHaveLength(1);
  f.state.repositoryUrl = repository;
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  await retry.publish();
  expect(f.posts).toHaveLength(2);
  expect(f.posts[1]).toBe(f.posts[0]);

  // This old boxed update relies on the report for issue-1's branch on every retry.
  const { filename, checkpoint } = boxedSonarCheckpoint;
  const savedPath = join(
    f.root,
    "state",
    "external-finding-publications",
    filename,
  );
  await writeFile(savedPath, JSON.stringify(checkpoint), { mode: 0o600 });
  const withEffort = (effort: unknown) => {
    const updated = {
      ...finding,
      evidence: {
        ...finding.evidence,
        source_data: { ...finding.evidence.source_data, effort },
      },
    };
    return prepare([updated, named]);
  };
  f.state.throttle = true;
  const boxed = await withEffort(new Number(2.5));
  expect(boxed.preview.resumed).toBe(true);
  await expect(boxed.publish()).rejects.toThrow("Slow down");
  f.state.throttle = false;
  const primitive = await withEffort(2.5);
  expect(primitive.preview.resumed).toBe(true);
  expect((await primitive.publish()).verified).toBe(2);
  const approved = JSON.stringify(checkpoint.requests[0]);
  expect(f.posts.slice(2)).toEqual([approved, approved]);
});

test("Wiz occurrence mapping preserves original evidence without inventing repository provenance", async () => {
  const record = {
    id: "wiz-occurrence",
    name: "CVE-2099-0001",
    detailedName: "example-lib",
    version: "1.2.0",
    fixedVersion: "1.2.1",
    vendorSeverity: "HIGH",
    portalUrl: "https://example.test/finding",
    locationPath: "/usr/lib/example",
    lastDetectedAt: "2026-10-01T00:00:00Z",
    projects: [{ id: "project-a" }, { id: "project-b" }],
    packageManager: "legacy-manager",
    vulnerableAsset: { id: "image-resource", imageDigest: "sha256:example" },
  };
  const f = await fixture([record]);
  const parsed = await readVendorFindings(f.file);
  expect(parsed.findings[0]).toMatchObject({
    source_finding_id: record.id,
    evidence: {
      severity: "high",
      locations: [],
      code_revision: null,
      branch: null,
      source_updated_at: null,
      source_data: record,
      image_digests: ["sha256:example"],
      advisory_ids: [record.name],
      packages: [{ name: "example-lib", ecosystem: "legacy-manager" }],
    },
  });
});

test("Wiz API nodes preserve artifact ecosystems and distinguish container digests from VM image IDs", async () => {
  const finding = {
    name: "Vendor display advisory",
    vulnerabilityExternalId: "CVE-2099-0001",
    detailedName: "example-package",
    version: "1.2.0",
    vendorSeverity: "HIGH",
  };
  const records = [
    {
      ...finding,
      id: "container-package",
      artifactType: { osPackageManager: "DPKG", codeLibraryLanguage: null },
      codeLibraryLanguage: "JAVA",
      vulnerableAsset: {
        id: "container-image",
        type: "CONTAINER_IMAGE",
        imageId: `sha256:${"a".repeat(64)}`,
      },
    },
    {
      ...finding,
      id: "vm-library",
      artifactType: { osPackageManager: null, codeLibraryLanguage: "PYTHON" },
      codeLibraryLanguage: "JAVA",
      vulnerableAsset: {
        id: "virtual-machine",
        type: "VIRTUAL_MACHINE",
        imageId: "ami-synthetic",
        containerImageId: "ami-synthetic-alias",
      },
    },
    {
      ...finding,
      id: "container-alias",
      vulnerableAsset: {
        id: "aliased-image",
        type: "CONTAINER_IMAGE",
        containerImageId: `sha256:${"d".repeat(64)}`,
      },
    },
    {
      ...finding,
      id: "running-container",
      vulnerableAsset: {
        id: "running-image",
        type: "CONTAINER",
        ImageExternalId: `sha256:${"e".repeat(64)}`,
      },
    },
    {
      ...finding,
      id: "explicit-metadata",
      packageManager: "reported-manager",
      imageDigest: `sha256:${"b".repeat(64)}`,
      artifactType: { osPackageManager: "DPKG" },
      codeLibraryLanguage: "JAVA",
      vulnerableAsset: {
        id: "explicit-container",
        type: "CONTAINER_IMAGE",
        imageId: `sha256:${"c".repeat(64)}`,
      },
    },
    {
      ...finding,
      id: "legacy-library",
      codeLibraryLanguage: "JAVASCRIPT",
      vulnerableAsset: { id: "legacy-image" },
    },
  ];
  const f = await fixture({
    data: {
      vulnerabilityFindings: {
        nodes: records,
        pageInfo: { hasNextPage: false },
      },
    },
  });
  const parsed = await readVendorFindings(f.file);
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.evidence.title).toContain(finding.name);
  expect(parsed.findings.map(({ evidence }) => evidence.advisory_ids)).toEqual(
    records.map(() => [finding.vulnerabilityExternalId]),
  );
  expect(
    parsed.findings.map(({ evidence }) => ({
      ecosystem: evidence.packages?.[0]?.ecosystem,
      digests: evidence.image_digests,
    })),
  ).toEqual([
    { ecosystem: "DPKG", digests: [`sha256:${"a".repeat(64)}`] },
    { ecosystem: "PYTHON", digests: [] },
    { ecosystem: null, digests: [`sha256:${"d".repeat(64)}`] },
    { ecosystem: null, digests: [`sha256:${"e".repeat(64)}`] },
    { ecosystem: "reported-manager", digests: [`sha256:${"b".repeat(64)}`] },
    { ecosystem: "JAVASCRIPT", digests: [] },
  ]);
  expect(parsed.findings.map(({ evidence }) => evidence.source_data)).toEqual(
    records,
  );
});

test("Wiz network-scan findings are excluded without requiring a detection method on package exports", async () => {
  const supported = {
    id: "package-occurrence",
    name: "CVE-2099-0001",
    detailedName: "example-package",
    vendorSeverity: "HIGH",
    vulnerableAsset: { id: "synthetic-asset" },
  };
  const network = {
    ...supported,
    id: "network-occurrence",
    name: "CWE-89",
    detailedName: "GET /synthetic-endpoint",
    detectionMethod: "EXTERNAL_NETWORK_SCAN",
  };
  const f = await fixture([supported, network]);
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect(
    prepared.preview.findings.map((finding) => finding.source_finding_id),
  ).toEqual([supported.id]);
  expect(prepared.preview.excluded).toEqual([
    expect.objectContaining({
      source_finding_id: network.id,
      reason: expect.stringContaining("external network"),
    }),
  ]);
  expect((await prepared.publish()).counts.created).toBe(1);
  expect(f.reports.has(network.id)).toBe(false);
});

test("unsupported records are visible exclusions; duplicate identities and unfinished pages stop publication", async () => {
  const f = await fixture([normalized(), normalized("unknown", "unsupported")]);
  const parsed = await readVendorFindings(f.file);
  expect(parsed.findings).toHaveLength(1);
  expect(parsed.excluded).toHaveLength(1);
  await writeFile(f.file, JSON.stringify([normalized(), normalized()]));
  await expect(readVendorFindings(f.file)).rejects.toThrow("Duplicate source");
  await writeFile(
    f.file,
    JSON.stringify({
      data: {
        vulnerabilityFindings: {
          nodes: [normalized()],
          pageInfo: { hasNextPage: true },
        },
      },
    }),
  );
  await expect(readVendorFindings(f.file)).rejects.toThrow("another page");
});

test("Cloud evidence constraints exclude invalid normalized records before approval", async () => {
  let nested: unknown = "leaf";
  for (let index = 0; index < 20; index++) nested = { child: nested };
  const invalid = [
    { title: "é".repeat(300) },
    { description: "" },
    { packages: [{ name: "example", installed_version: "1.0\0" }] },
    { advisory_ids: ["é".repeat(300)] },
    { locations: [{ path: "../outside.ts" }] },
    { url: "https://user@example.test/finding" },
    { source_data: { content: "x".repeat(6 * 1024 * 1024) } },
    { source_data: { nested } },
    { url: "https://[example.test" },
  ].map((evidence, index) => ({
    source_finding_id: `invalid-${index}`,
    evidence: { ...normalized().evidence, ...evidence },
  }));
  const f = await fixture([normalized(), ...invalid]);
  const cli = createCliTest(main);
  expect(await cli.runCli([...f.command, "--dry-run"], f.cliDeps)).toBe(0);
  const preview = JSON.parse(cli.stdout.text());
  expect(preview.findings).toHaveLength(1);
  expect(preview.excluded).toHaveLength(invalid.length);
  expect(preview.excluded[6].reason).toContain("256 KiB");
  expect(f.posts).toHaveLength(0);
  await writeFile(f.file, JSON.stringify(invalid));
  const rejected = createCliTest(main);
  expect(await rejected.runCli([...f.command, "--yes"], f.cliDeps)).toBe(2);
  expect(rejected.stderr.text()).toContain("No supported findings");
  expect(f.posts).toHaveLength(0);
  expect(await readdir(join(f.root, "state")).catch(() => [])).toEqual([]);
});

test("raw Wiz records apply Cloud string and URL constraints before approval", async () => {
  const wiz = {
    id: "wiz-valid",
    name: "CVE-2099-0001",
    detailedName: "example-package",
    vendorSeverity: "HIGH",
    vulnerableAsset: { id: "example-image" },
  };
  const f = await fixture([
    wiz,
    { ...wiz, id: "wiz-title", title: "é".repeat(300) },
    { ...wiz, id: "é".repeat(300) },
    { ...wiz, id: "wiz\0id" },
    { ...wiz, id: "wiz-url", portalUrl: "https://@example.test" },
  ]);
  const cli = createCliTest(main);
  expect(await cli.runCli([...f.command, "--dry-run"], f.cliDeps)).toBe(0);
  const preview = JSON.parse(cli.stdout.text());
  expect(preview.findings).toHaveLength(1);
  expect(preview.excluded).toHaveLength(4);
  expect(f.posts).toHaveLength(0);
});

test("Cloud validation preserves allowed evidence boundaries and raw vendor strings", () => {
  let nested: unknown = "leaf";
  for (let index = 0; index < 18; index++) nested = { child: nested };
  const evidence = {
    title: "é".repeat(256),
    severity: "high" as const,
    description: "é".repeat(32768),
    url: "https://example.test:non-numeric/finding",
    advisory_ids: [" ", "\0", "é".repeat(256)],
    packages: [{ name: "example", manifest_path: "../vendor-manifest" }],
    locations: [{ path: "src\\example.ts" }],
    source_data: { nested, title: "", path: "\0", content: "x".repeat(4096) },
  };
  expect(validateExternalEvidence(evidence)).toEqual(evidence);
  for (const url of [
    "ftp://example.test",
    "https:///finding",
    "https:\\example.test",
    "http://@example.test",
    "https://[127.0.0.1]/finding",
    "https://[example.test]/finding",
    "https://prefix[::1]/finding",
    "https://[::1]suffix/finding",
    "https://[::1%]/finding",
    "https://[::1%a%b]/finding",
    "https://example.com／path",
    "https://example.test\uFF1A443/finding",
    "https://exam\u2100ple.test/finding",
  ]) {
    expect(() => validateExternalEvidence({ ...evidence, url })).toThrow(
      "HTTP(S)",
    );
  }
  for (const url of [
    "https://[::1]/finding",
    "https://[fe80::1%25eth0]/finding",
    "https://[fe80::1%zone!]/finding",
    "https://[v1.example]/finding",
    "https://[vF.example]:service",
    "https://[fe80::1%eth0]/finding",
    "https://[::1]:non-numeric/finding",
    "https://bücher.example/finding",
  ]) {
    expect(validateExternalEvidence({ ...evidence, url }).url).toBe(url);
  }
  for (const path of ["/absolute.ts", "C:\\source.ts", "src\\..\\outside.ts"]) {
    expect(() =>
      validateExternalEvidence({ ...evidence, locations: [{ path }] }),
    ).toThrow("repository-relative");
  }
  expect(() =>
    validateExternalEvidence({ ...evidence, source_data: { value: Infinity } }),
  ).toThrow("finite JSON");
});

test("request and pagination metadata retain Cloud byte limits and distinct identities", async () => {
  const f = await fixture();
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  const request = prepared.preview.requests[0]!;
  expect(() =>
    validateImportRequest({
      ...request,
      source: { ...request.source, source_key: "tenant\0" },
    }),
  ).toThrow("NUL");
  expect(() =>
    validateImportRequest({
      ...request,
      repository: { ...request.repository, id: "é".repeat(300) },
    }),
  ).toThrow("UTF-8");
  const item = request.items[0]!;
  expect(() =>
    validateImportRequest({
      ...request,
      items: [{ ...item, client_id: "é".repeat(100) }],
    }),
  ).toThrow("128 UTF-8");
  expect(() =>
    validateImportRequest({
      ...request,
      items: [item, { ...item, source_finding_id: "another" }],
    }),
  ).toThrow("duplicate client");
  expect(() =>
    validateImportRequest({
      ...request,
      items: [item, { ...item, client_id: "another" }],
    }),
  ).toThrow("duplicate source");
  const page = {
    data: [f.destination()],
    has_more: true,
    next: "é".repeat(2048),
  };
  expect(validateRepositories(page).next).toBe(page.next);
  expect(() =>
    validateRepositories({ ...page, next: `${page.next}é` }),
  ).toThrow("4096 UTF-8");
});

const inspectorOptions = {
  ...options,
  provider: "inspector" as const,
  sourceRepositoryUrl: inspectorRepositoryUrl,
};

async function inspectorPublicationFixture(name = inspectorRepositoryUrl) {
  const input = inspectorPackageFinding();
  const project = input.resources[0]!;
  project.details.codeRepository.projectName = name;
  const f = await fixture({ findings: [input] });
  const map = new Map([[project.id, inspectorRepositoryUrl]]);
  const prepare = (settings: ExternalPublicationOptions = inspectorOptions) =>
    prepareExternalPublication(f.file, settings, f.deps);
  async function loseResponse(prepared: PreparedExternalPublication) {
    await f.loseResponse(prepared);
    return f.posts.at(-1)!;
  }
  return { f, input, project, map, prepare, loseResponse };
}

function checkmarxSastRow() {
  return {
    type: "sast",
    similarityId: "17",
    severity: "MEDIUM",
    data: { resultHash: "c97c", queryName: "Example_Query" },
  };
}

test("Checkmarx publishes a native SAST finding only to its declared Cloud repository", async () => {
  const row = checkmarxSastRow();
  const f = await fixture({ scanID: "scan-a", totalCount: 1, results: [row] });
  const selected = {
    ...options,
    provider: "checkmarx" as const,
    sourceRepositoryUrl: f.state.repositoryUrl,
  };
  const prepare = () => prepareExternalPublication(f.file, selected, f.deps);
  const first = await prepare();
  expect(first.preview.requests[0]).toMatchObject({
    source: { provider: "checkmarx", source_key: selected.sourceKey },
    items: [{ evidence: { source_scan_id: "scan-a", source_data: { row } } }],
  });
  const sibling = sdkRow("sdk-id");
  sibling.evidence.source_scan_id = "scan-b";
  await expect(
    prepareNormalizedExternalPublication(
      sdkSelection([...first.preview.findings, sibling]),
      selected,
      f.deps,
    ),
  ).rejects.toThrow(/same product, project and scan/i);
  const replayWithReport = (change: Record<string, unknown>) =>
    prepareNormalizedExternalPublication(
      { ...first.preview, report: { ...first.preview.report, ...change } },
      selected,
      f.deps,
    );
  await expect(
    replayWithReport({
      sourceRepositoryUrl: "https://github.com/example/other",
    }),
  ).rejects.toThrow(/does not match the selected Cloud repository/i);
  f.state.repositoryUrl = "https://github.com/example/other";
  await expect(prepare()).rejects.toThrow(/does not match/i);
  expect(f.posts).toHaveLength(0);
  f.state.repositoryUrl = selected.sourceRepositoryUrl;
  await f.loseResponse(first);
  await expect(replayWithReport({ scanId: "different-scan" })).rejects.toThrow(
    /does not match the retained report/i,
  );
  f.state.repositoryUrl = "https://github.com/example/other";
  await expect(prepare()).rejects.toThrow(/does not match/i);
  expect(f.posts).toHaveLength(1);
  f.state.repositoryUrl = selected.sourceRepositoryUrl;
  const replay = await prepare();
  expect(replay.preview.resumed).toBe(true);
  expect((await replay.publish()).verified).toBe(1);
  expect(f.posts[1]).toBe(f.posts[0]!);
});

test("Continuum Cloud publication checks repository and provider and replays an interrupted request", async () => {
  const detail = continuumDetail();
  const f = await fixture(detail, continuumRepository);
  const selected = {
    ...options,
    provider: "continuum" as const,
    sourceKey: "continuum/example/project",
    sourceRepositoryUrl: continuumRepository,
  };
  const prepare = () => prepareExternalPublication(f.file, selected, f.deps);
  const first = await prepare();
  expect(first.preview.requests[0]).toMatchObject({
    source: { provider: "continuum", source_key: selected.sourceKey },
    items: [
      {
        source_finding_id: detail.findingArn,
        evidence: { source_data: { finding: detail } },
      },
    ],
  });
  await expect(
    prepareNormalizedExternalPublication(
      first.preview,
      { ...selected, provider: "wiz" },
      f.deps,
    ),
  ).rejects.toThrow(/continuum provider/i);
  const relabeled = structuredClone(first.preview);
  relabeled.findings[0]!.source_finding_id = "another-id";
  await expect(
    prepareNormalizedExternalPublication(relabeled, selected, f.deps),
  ).rejects.toThrow(/source finding ID|occurrence|ARN/i);

  f.state.repositoryUrl = "https://github.com/example/other";
  await expect(prepare()).rejects.toThrow(/does not match/i);
  expect(f.posts).toHaveLength(0);
  f.state.repositoryUrl = continuumRepository;

  f.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).verified).toBe(1);
  expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
});

test("Inspector publication checks its source and reuses the finding ARN", async () => {
  const { f, input, prepare } = await inspectorPublicationFixture();
  const prepared = await prepare();
  expect(prepared.preview.source.provider).toBe("inspector");
  expect((await prepared.publish()).counts.created).toBe(1);
  expect((await (await prepare()).publish()).counts.unchanged).toBe(1);
  expect(f.reports.has(input.findingArn)).toBe(true);

  const row = prepared.preview.findings[0]!;
  const opaque = structuredClone(row);
  opaque.source_finding_id = "typed-only";
  delete opaque.evidence.source_data;
  const other = "https://github.com/example/other";
  opaque.evidence.details = { kind: "sast", repository: { url: other } };
  await expect(
    prepareNormalizedExternalPublication(
      { ...prepared.preview, findings: [row, opaque] },
      inspectorOptions,
      f.deps,
    ),
  ).rejects.toThrow(/typed-only.*does not match/i);

  f.state.repositoryUrl = other;
  await expect(prepare()).rejects.toThrow(/does not match/i);
  for (const source_data of [row.evidence.source_data, { finding: input }]) {
    row.evidence.source_data = source_data;
    await expect(
      prepareNormalizedExternalPublication(prepared.preview, options, f.deps),
    ).rejects.toThrow("requires the inspector provider");
  }
  expect(f.posts).toHaveLength(2);
});

test.each(["Inspector", "Trivy"] as const)(
  "Wiz can import, resume and update its own occurrence with upstream %s evidence",
  async (upstream) => {
    const trivy = selectedTrivyRows().findings[0]!;
    const record = {
      id:
        upstream === "Trivy" ? trivy.source_finding_id : "wiz-vulnerability-1",
      name: "CVE-2099-1234",
      detailedName: "example-package",
      vendorSeverity: "HIGH",
      vulnerableAsset: { id: "example-asset" },
      ...(upstream === "Trivy"
        ? trivy.evidence.source_data
        : { finding: inspectorPackageFinding() }),
    };
    const f = await fixture([record]);
    await using local = await localFindingsFixture({
      remote: foreignArtifactUrl,
    });
    const prepared = await prepareNormalizedLocalImport(
      await readVendorFindings(f.file),
      { ...options, repository: local.repository },
      { environment: local.environment },
    );
    expect((await prepared.import()).counts.created).toBe(1);

    const prepare = () => prepareExternalPublication(f.file, options, f.deps);
    const first = await prepare();
    f.state.loseResponse = true;
    const error = await first.publish().catch((error: unknown) => error);
    if (!(error instanceof ExternalPublicationError)) throw error;
    expect(f.reports.get(record.id)?.evidence.source_data).toEqual(record);

    // Older checkpoints can contain the original requests without their input projection.
    const path = error.result.savedSubmission!;
    const saved = JSON.parse(await readFile(path, "utf8"));
    delete saved.inputProjection;
    await writeFile(path, JSON.stringify(saved));
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).verified).toBe(1);
    expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);

    record.vendorSeverity = "MEDIUM";
    await writeFile(f.file, JSON.stringify([record]));
    const updated = await prepareNormalizedExternalPublication(
      await readVendorFindings(f.file),
      options,
      f.deps,
    );
    expect((await updated.publish()).counts.updated).toBe(1);
    expect(f.reports.get(record.id)?.evidence.source_data).toEqual(record);
  },
);

test.each(["example/project", inspectorRepositoryUrl])(
  "pending Inspector requests for %s recheck their project mapping and destination host",
  async (name) => {
    const { f, project, map, prepare, loseResponse } =
      await inspectorPublicationFixture(name);
    const otherUrl = "https://git.example.test/example/project";
    const supplied = new Map(map);
    const settings: ExternalPublicationOptions = {
      ...inspectorOptions,
      inspectorProjectMap: supplied,
    };
    const preparing = prepare(settings);
    if (name === inspectorRepositoryUrl) delete settings.inspectorProjectMap;
    else supplied.clear();
    const prepared = await preparing;
    const firstBody = await loseResponse(prepared);
    const resume = (inspectorProjectMap?: ReadonlyMap<string, string>) =>
      prepareNormalizedExternalPublication(
        prepared.preview,
        { ...inspectorOptions, inspectorProjectMap },
        f.deps,
      );

    await expect(resume()).rejects.toThrow(/project|repository/i);
    await expect(resume(new Map([[project.id, otherUrl]]))).rejects.toThrow(
      /project|repository/i,
    );
    // Connector and repository IDs stay stable while the host changes.
    f.state.repositoryUrl = otherUrl;
    await expect(resume(map)).rejects.toThrow(/repository/i);
    expect(f.posts).toHaveLength(1);

    f.state.repositoryUrl = inspectorRepositoryUrl;
    const retry = await resume(map);
    expect(retry.preview.resumed).toBe(true);
    retry.preview.requests[0]!.items[0]!.evidence.source_data![
      "sourceRepositoryUrl"
    ] = otherUrl;
    expect((await retry.publish()).verified).toBe(1);
    expect(f.posts).toEqual([firstBody, firstBody]);
  },
);

test("a repository reset retires an Inspector request even when the destination URL changed", async () => {
  const { f, map, prepare, loseResponse } = await inspectorPublicationFixture();
  const first = await prepare({
    ...inspectorOptions,
    inspectorProjectMap: map,
  });
  await loseResponse(first);
  f.state.marker = "generation-2";
  f.state.repositoryUrl = "https://github.com/example/new-destination";
  await expect(prepare()).rejects.toThrow("retired without uploading");
  await expect(prepare()).rejects.toThrow("does not match");
  expect(f.posts).toHaveLength(1);

  f.state.repositoryUrl = inspectorRepositoryUrl;
  const fresh = await prepare();
  expect(fresh.preview.resumed).toBe(false);
  const request = fresh.preview.requests[0]!;
  expect(request.repository.reset_marker).toBe("generation-2");
  expect(request.request_id).not.toBe(first.preview.requests[0]!.request_id);
});

test("publishing an Inspector retry adopts its project map without changing the pending request", async () => {
  const { f, map, prepare, loseResponse } = await inspectorPublicationFixture();
  const mappedOptions = { ...inspectorOptions, inspectorProjectMap: map };
  const body = await loseResponse(await prepare());
  const mapped = await prepare(mappedOptions);
  const withoutMap = await prepare(); // Previewing the map does not change the checkpoint.
  await loseResponse(mapped);
  await expect(prepare()).rejects.toThrow(
    "Supply the verified Inspector project binding",
  );
  await expect(withoutMap.publish()).rejects.toThrow(
    "Another publication prepared this input",
  );
  expect((await (await prepare(mappedOptions)).publish()).verified).toBe(1);
  expect(f.posts).toEqual([body, body, body]);
});

test.each(["inspector", "sonar"] as const)(
  "a normalized %s retry checks its typed repository without native evidence",
  async (provider) => {
    const f = await fixture();
    const finding = {
      source_finding_id: "vendor-1",
      evidence: {
        title: "Synthetic code finding",
        severity: "high" as const,
        details: {
          kind: "sast" as const,
          repository: { url: inspectorRepositoryUrl },
        },
      },
    };
    const prepare = () =>
      prepareNormalizedExternalPublication(
        { read: 1, findings: [finding], excluded: [] },
        { ...options, provider },
        f.deps,
      );
    f.state.loseResponse = true;
    await expect((await prepare()).publish()).rejects.toThrow(
      "resume the saved request",
    );
    f.state.repositoryUrl = "https://github.com/different/project";
    await expect(prepare()).rejects.toThrow(
      "does not match the selected Cloud repository",
    );
    expect(f.posts).toHaveLength(1);
  },
);

function inspectorReportWithRelatedCves() {
  const pkg = inspectorPackageFinding();
  // The previous reader excluded this row because it projected 101 advisory IDs.
  pkg.packageVulnerabilityDetails.relatedVulnerabilities = Array.from(
    { length: 100 },
    (_, i) => `CVE-2099-${3000 + i}`,
  );
  return { findings: [inspectorCodeFinding(), pkg] };
}

const exampleRepository = "https://github.com/example/project";
const githubOrigin = {
  ...blackDuckBomRow(),
  componentVersionOriginName: "github",
  componentVersionOriginId: "example/library/v1",
  packageUrl: "pkg:github/Example/Library@v1",
};
const nativeSemgrep = semgrepJson();

const awsReaderUpgrades = [
  {
    provider: "inspector",
    raw: inspectorReportWithRelatedCves(),
    normalizePrevious: normalizePreviousInspectorFindings,
    sourceRepositoryUrl: inspectorRepositoryUrl,
    previousDigest:
      "4e90748318e5952a1fa90ff9c25153396340a097db6112f27bdf89a3a092dade",
    expectedCount: 2,
    previousSha256:
      "91b5a4d309daee520029a3d54e809ad84d8b47ee97df5fd54d56323fc246f640",
  },
  {
    provider: "continuum",
    raw: continuumDetail(),
    normalizePrevious: normalizePreviousContinuumFindings,
    sourceRepositoryUrl: continuumRepository,
    previousDigest:
      "22307dedb51cefecf56d11fd68f45324dceb5226bfddfbd48c635a462bb68fb5",
    expectedCount: 1,
    previousSha256:
      "98f888f8b748bb54a209b19de53af40867f5f129049a99da0387e697895aa320",
  },
] as const;

test.each([
  ...awsReaderUpgrades,
  {
    provider: "blackduck",
    raw: blackDuckBomReport([githubOrigin]),
    normalizePrevious: normalizePreviousBlackDuckFindings,
    sourceRepositoryUrl: exampleRepository,
    previousDigest:
      "ade8411242d3cac1fb490a86159d1b4a3b57a7d7f18bee64cadc971e3433185e",
    expectedCount: 1,
  },
  {
    provider: "veracode",
    raw: veracodeMixedPolicyPage(),
    normalizePrevious: normalizePreviousVeracodeFindings,
    sourceRepositoryUrl: exampleRepository,
    previousDigest:
      "0ca5d464a797a1a17e18a69f9b4cad172a458be2955c8a24048df78e2798b8b6",
    expectedCount: 2,
  },
  {
    provider: "semgrep",
    raw: {
      ...nativeSemgrep,
      explanations: [
        {
          op: "And",
          matches: [{ ...nativeSemgrep.results[0]!, path: "src/other.ts" }],
          children: [],
        },
      ],
    },
    normalizePrevious: (raw: unknown, sourceRepositoryUrl: string) =>
      normalizePreviousSemgrepFindings(raw, { sourceRepositoryUrl }),
    sourceRepositoryUrl: exampleRepository,
    previousDigest:
      "2265f4b64025fe061d950e8b20eba222563001a781b645846646000fbbcdc4a0",
    expectedCount: 1,
  },
  {
    provider: "trivy",
    raw: trivyReportWithManyLocations(),
    normalizePrevious: (raw: unknown) =>
      normalizePreviousTrivyFindings(raw, "cloud", "."),
    sourceRepositoryUrl: exampleRepository,
    previousDigest:
      "b4158738af7b92798b6f2b77d8f07343a9422cfb0ffafe4db6410a2bfe7d3b1e",
    expectedCount: 2,
  },
] as const)(
  "a raw $provider retry preserves the repository request from the previous reader",
  async ({
    provider,
    raw,
    normalizePrevious,
    sourceRepositoryUrl,
    previousDigest,
    expectedCount,
  }) => {
    const f = await fixture(raw, sourceRepositoryUrl);
    const settings = {
      ...options,
      provider,
      ...(provider === "trivy"
        ? { trivyScanRoot: "." }
        : { sourceRepositoryUrl }),
    };
    const prepare = () => prepareExternalPublication(f.file, settings, f.deps);

    // Round-trip the previous SDK's output through JSON as a saved caller artifact.
    const previous = JSON.parse(
      JSON.stringify(normalizePrevious(raw, sourceRepositoryUrl)),
    );
    expect(hash("sha256", canonicalJson(previous.findings))).toBe(
      previousDigest,
    );
    const original = await prepareNormalizedExternalPublication(
      previous,
      settings,
      f.deps,
    );
    const pending = await f.loseResponse(original);
    const request = f.posts[0]!;

    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests).toEqual(original.preview.requests);
    expect(await f.loseResponse(retry)).toBe(pending);
    expect((await (await prepare()).publish()).verified).toBe(1);
    expect(f.posts).toEqual([request, request, request]);

    const fresh = await prepare();
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.findings).toHaveLength(expectedCount);
    expect(fresh.preview.findings).not.toEqual(original.preview.findings);
    expect((await fresh.publish()).verified).toBe(expectedCount);
  },
);

test("publishes a filtered numeric Veracode CWE that the previous reader rejected", async () => {
  const raw = veracodeMixedPolicyPage();
  raw._links.self.href += "&cwe=79";
  const f = await fixture(raw, exampleRepository);
  const settings = {
    ...options,
    provider: "veracode" as const,
    sourceRepositoryUrl: exampleRepository,
  };
  expect(() =>
    normalizePreviousVeracodeFindings(raw, exampleRepository),
  ).toThrow("Veracode cwe must be an object");
  const prepared = await prepareExternalPublication(f.file, settings, f.deps);
  expect((await prepared.publish()).verified).toBe(2);
});

test("a fresh AWS publication waits for the previous reader to save its request", async () => {
  const raw = continuumDetail();
  const f = await fixture(raw, continuumRepository);
  const settings = {
    ...options,
    provider: "continuum" as const,
    sourceRepositoryUrl: continuumRepository,
  };
  const previous = await prepareNormalizedExternalPublication(
    normalizePreviousContinuumFindings(raw, continuumRepository),
    settings,
    f.deps,
  );
  const fresh = await prepareExternalPublication(f.file, settings, f.deps);
  const observer = observeLockContention();
  const rename = fs.rename;
  let competitor: Promise<unknown> | undefined;
  let outcome: string | undefined;
  const install = spyOn(fs, "rename").mockImplementationOnce(
    async (...args) => {
      // The earlier publisher holds its lock but has not installed its checkpoint yet.
      competitor = fresh.publish().catch((error: unknown) => error);
      outcome = await Promise.race([
        observer.contended.then(() => "locked"),
        competitor.then(() => "finished"),
      ]);
      return rename(...args);
    },
  );
  try {
    f.state.throttle = true;
    await expect(previous.publish()).rejects.toThrow("Slow down");
    expect(outcome).toBe("locked");
    expect(String(await competitor)).toContain(
      "Another publication prepared this input",
    );
    expect(f.posts).toHaveLength(1);
  } finally {
    install.mockRestore();
    observer.restore();
  }
});

const savedBlackDuckEvidence = {
  data: { format: "blackduck-bom-6" },
  requiredProvider: "blackduck",
  digest: "d3001de83673b0f42b1d1d42cb19ea546869d41ed99504ca213b303267bb1346",
};

const savedDependabotData = {
  ...githubDependabotAlert(),
  sourceRepositoryUrl: "https://github.com/example/different",
};

const checkmarxFormat = { format: "cxsast-xml" };
const otherRepository = "https://github.com/example/other";
const savedEndorData = (repositoryUri: string) => ({
  ...checkmarxFormat,
  runContext: { versionControlProvenance: ["opaque", { repositoryUri }] },
});
const endorCheckpoint = {
  requiredProvider: "checkmarx",
  selected: { ...options, provider: "endor" as const },
};

const wizBranchAsset = {
  nativeType: "github#repositoryBranch",
  cloudProviderURL: exampleRepository + "/tree/main",
};

test.each([
  {
    data: { ...checkmarxFormat, vulnerableAsset: wizBranchAsset },
    selected: options,
    requiredProvider: "checkmarx",
    filename:
      "44c97129ef37ba88ccf7d6a1c43c3ef4c051080c0e746145b1f37dc6216f0181.pending.json",
    digest: "7c90e7bf4a7d9c64c7cbbc15fdcdf6a3ff0e14f50cda77c9b523d834cf337dd7",
  },
  {
    ...endorCheckpoint,
    data: savedEndorData(exampleRepository),
    filename:
      "4d59df5533b5d0acbbcc2e28884e597a52d8b55e354eb15539d6cfba37c79011.pending.json",
    digest: "d19b090ff4cd18329b37e74e674394deb2670c1d0dfc7bc088c02edcbb088cad",
  },
  {
    ...endorCheckpoint,
    data: {
      ...savedEndorData(exampleRepository),
      sourceRepositoryUrl: exampleRepository,
    },
    filename:
      "624c404a8fcf0e8241c30d9b1a434d78aaa2c1e87d211465e0698821ab1c509f.pending.json",
    digest: "f77bce9f03733812b5fda88ae988193b54462baf78be95ba6b4de49658b103d9",
  },
  {
    ...endorCheckpoint,
    data: {
      ...savedEndorData(otherRepository),
      sourceRepositoryUrl: exampleRepository,
    },
    conflictingUrl: otherRepository,
    filename:
      "70e7f4be8d0d9eb0306f18ea1a2b256641bee797b3626a8dfc2920d0a15abcd2.pending.json",
    digest: "8fedf62999d4c5f510706db4647ad3d847e8e5f6f5f3d75eb365da193c16ea1a",
  },
  {
    data: { format: "snyk-rest-issues/v2", issueJson: "{}" },
    requiredProvider: "snyk",
    digest: "e5b609dd6f1d5846f1b84457c319fb02505e55385ed2a4823f2a359fef7e3f33",
    selected: { ...options, provider: "snyk" as const },
    filename:
      "d7c57e64c210ec93849be17563ba9ae4e9abbd5bd614fbc99a27346e72ce80ed.pending.json",
  },
  {
    data: { format: "semgrep-platform-findings/v1" },
    requiredProvider: "semgrep",
    digest: "03781aba18f0321eef4e0aeccb512116387931f166fa42c148587085933cd48b",
    selected: { ...options, provider: "veracode" as const },
    filename:
      "b1fda8b80a88dc44670dcd566e5b4e13f8a3cc1ddd776973a047ffe45e998987.pending.json",
  },
  {
    ...savedBlackDuckEvidence,
    selected: options,
    filename:
      "2dfdb44c2c7494f4eed20e59244df967598fc3a284589ec2f6c3a24bfff7b2d0.pending.json",
  },
  {
    ...savedBlackDuckEvidence,
    selected: { ...options, provider: "inspector" as const },
    filename:
      "d0ba21fbe6c5927206db937694c98f69ad59e33fc390cae6eb6bd01249b5ca10.pending.json",
  },
  {
    selected: { ...options, provider: "github" as const },
    data: savedDependabotData,
    requiredProvider: "blackduck",
    filename:
      "2dc327e13b7b9548e828b0fe3193988a26c53c9c956b364c69990abdb418c298.pending.json",
    digest: "abe417c10599f27dc9adc599465af29f693069deaca7942f79c952871216070e",
  },
  {
    selected: { ...options, provider: "inspector" as const },
    data: {
      sourceRepositoryUrl: inspectorRepositoryUrl,
      applicationUrl: veracodePolicyPage()._links.application.href,
      row: veracodePolicyRow(),
    },
    requiredProvider: "veracode",
    filename:
      "7d21ed6ce9acbc4bf00c5c7d7ed02b8e7937e92efa796e6218d57273eb9ce2f4.pending.json",
    digest: "13b472f7b050ef94705eed1fb4487b206386130f988d3ee6f87824f02f4d79f0",
  },
])(
  "checks a saved $selected.provider request from before $requiredProvider checks",
  async (saved) => {
    const { selected, data, requiredProvider, filename, digest } = saved;
    const f = await fixture();
    const environment: NodeJS.ProcessEnv = { ...f.environment };
    // These persisted keys came from the default deployment.
    delete environment["CODEX_SECURITY_CLOUD_BASE_URL"];
    delete environment["CODEX_SECURITY_CLOUD_WEB_URL"];
    const alert =
      selected.provider === "github" ? savedDependabotData : undefined;
    const row = normalized();
    const finding = {
      source_finding_id: alert
        ? "blackduck-bom:" + "a".repeat(64)
        : row.source_finding_id,
      evidence: validateExternalEvidence(
        alert
          ? {
              title: "Dependabot alert",
              severity: "high",
              url: alert.html_url,
              source_data: data,
            }
          : { ...row.evidence, source_data: data },
      ),
    };
    const input = { read: 1, excluded: [], findings: [finding] };
    const prepare = (sourceRepositoryUrl?: string) =>
      prepareNormalizedExternalPublication(
        { ...input, ...(sourceRepositoryUrl && { sourceRepositoryUrl }) },
        selected,
        {
          ...f.deps,
          environment,
        },
      );

    // The previous publisher accepted this opaque evidence. Keep its checkpoint
    // filename and digests so this exercises recovery across the provider change.
    const directory = join(
      f.environment.CODEX_SECURITY_STATE_DIR,
      "external-finding-publications",
    );
    const request = {
      request_id: "efbc3c2e-0462-4411-89aa-9ced1d34223c",
      repository: {
        id: selected.repository,
        repo_connector_id: "github",
        environment_id: f.state.environmentId,
        reset_marker: f.state.marker,
      },
      source: { provider: selected.provider, source_key: selected.sourceKey },
      items: [{ client_id: "item-1", ...finding, expected_version: 0 }],
    };
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(
      join(directory, filename),
      JSON.stringify({
        accountId: "synthetic-account",
        requests: [request],
        inputProjection: { inputDigest: digest, savedEvidenceDigest: digest },
      }),
      { mode: 0o600 },
    );

    if ("conflictingUrl" in saved && saved.conflictingUrl) {
      await expect(prepare()).rejects.toThrow(
        `belongs to "${saved.conflictingUrl}"`,
      );
      expect(f.posts).toHaveLength(0);
      return;
    }
    if (alert) {
      // The original publisher selected the alert's repository. Changing the
      // catalog to match the projection must not permit replay to another repo.
      const originalRepository = f.state.repositoryUrl;
      f.state.repositoryUrl = alert.sourceRepositoryUrl;
      await expect(prepare()).rejects.toThrow(
        `belongs to "${originalRepository}"`,
      );
      expect(f.posts).toHaveLength(0);
      return;
    }
    if (requiredProvider === "checkmarx") {
      const original = f.state.repositoryUrl;
      f.state.repositoryUrl += "-other";
      await expect(prepare()).rejects.toThrow(`belongs to "${original}"`);
      expect(f.posts).toHaveLength(0);
      f.state.repositoryUrl = original;
    }
    if (selected.provider === "snyk") {
      const other = "https://github.com/example/other";
      await expect(prepare(other)).rejects.toThrow(/does not match/);
      expect((await prepare(f.state.repositoryUrl)).preview.resumed).toBe(true);
      expect((await prepare(f.state.repositoryUrl)).preview.resumed).toBe(true);
      await expect(prepare(other)).rejects.toThrow(/does not match/);
    }
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).counts.created).toBe(1);
    expect(f.posts.map((body) => JSON.parse(body))).toEqual([request]);
    if (selected.provider === requiredProvider)
      await expect(prepare()).rejects.toThrow(/Snyk/i);
    else
      await expect(prepare()).rejects.toThrow(
        `requires the ${requiredProvider} provider`,
      );
  },
);

test.each(["wiz", "inspector"] as const)(
  "rechecks a projected Black Duck repository on a saved %s publication",
  async (provider) => {
    const f = await fixture();
    const source = f.state.repositoryUrl;
    const input = normalizeBlackDuckFindings([blackDuckBomRow()], source);
    input.findings[0]!.evidence.source_data = { sourceRepositoryUrl: source };
    const prepare = () =>
      prepareNormalizedExternalPublication(
        input,
        { ...options, provider },
        f.deps,
      );

    f.state.loseResponse = true;
    await expect((await prepare()).publish()).rejects.toThrow(
      "resume the saved request",
    );
    f.state.repositoryUrl = "https://github.com/example/different";
    await expect(prepare()).rejects.toThrow(
      "does not match the selected Cloud repository",
    );
    expect(f.posts).toHaveLength(1);
    f.state.repositoryUrl = source;
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    await retry.publish();
    expect(f.posts).toHaveLength(2);
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

const projectedId = "checkmarx-one:" + "a".repeat(64);

function sdkRow(id: string, source_data?: Record<string, unknown>) {
  const row = normalized(id);
  return {
    ...row,
    evidence: validateExternalEvidence({ ...row.evidence, source_data }),
  };
}

function sdkSelection(
  findings: ExternalFindings["findings"],
  report?: ExternalFindings["report"],
): ExternalFindings {
  return { read: findings.length, excluded: [], findings, report };
}

test.each(["row", "report", "Snyk SARIF"] as const)(
  "keeps the projected Checkmarx repository from the %s across retries",
  async (scope) => {
    const f = await fixture();
    const sourceRepositoryUrl = f.state.repositoryUrl;
    const snyk = scope === "Snyk SARIF";
    const selected = snyk ? { ...options, provider: "snyk" as const } : options;
    const report = scope === "report" ? { sourceRepositoryUrl } : undefined;
    const input = snyk
      ? (await snykRepositoryEvidence("SARIF", sourceRepositoryUrl)).normalized
      : sdkSelection(
          [
            sdkRow(
              projectedId,
              scope === "row" ? { sourceRepositoryUrl } : undefined,
            ),
          ],
          report,
        );
    input.findings[0]!.source_finding_id = projectedId;
    const prepare = (selection: ExternalFindings = input) =>
      prepareNormalizedExternalPublication(selection, selected, f.deps);
    f.state.repositoryUrl = otherRepository;
    if (report)
      expect(
        (await prepare(sdkSelection([sdkRow("opaque-sdk-id")], report))).preview
          .requests,
      ).toHaveLength(1);
    await expect(prepare()).rejects.toThrow(/belongs to|does not match/);
    f.state.repositoryUrl = sourceRepositoryUrl;
    await f.loseResponse(await prepare());
    f.state.repositoryUrl = otherRepository;
    await expect(prepare()).rejects.toThrow(/belongs to|does not match/);
    expect(f.posts).toHaveLength(1);
    f.state.repositoryUrl = sourceRepositoryUrl;
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).verified).toBe(1);
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test("Checkmarx projections under Wiz bind retained row URLs and native repository branch assets", async () => {
  const f = await fixture();
  const sourceRepositoryUrl = f.state.repositoryUrl;
  f.state.repositoryUrl = otherRepository;
  const report = { sourceRepositoryUrl: otherRepository };
  const prepare = (
    findings: ExternalFindings["findings"],
    metadata?: typeof report,
  ) =>
    prepareNormalizedExternalPublication(
      sdkSelection(findings, metadata),
      options,
      f.deps,
    );
  const branch = { vulnerableAsset: wizBranchAsset };
  const mismatch = `belongs to "${sourceRepositoryUrl}"`;
  const projected = sdkRow(projectedId, branch);
  await expect(prepare([projected], report)).rejects.toThrow(mismatch);
  await expect(prepare([projected])).rejects.toThrow(mismatch);
  for (const data of [branch, { sourceRepositoryUrl }]) {
    const sibling = sdkRow("wiz-finding", data);
    expect((await prepare([sibling], report)).preview.requests).toHaveLength(1);
    await expect(
      prepare([sdkRow(projectedId), sibling], report),
    ).rejects.toThrow(mismatch);
  }
  expect(f.posts).toHaveLength(0);
});

test("Black Duck Cloud replay preserves package occurrence and rejects a different destination", async () => {
  const row = {
    ...blackDuckBomRow(),
    packageUrl: "pkg:composer/example/library@2.0",
  };
  const report = blackDuckBomReport([row]);
  const correct = await fixture(report);
  const selected = {
    ...options,
    provider: "blackduck" as const,
    sourceKey: "scanner/project-a/release-a",
    sourceRepositoryUrl: "https://github.com/example/project",
  };
  const prepare = () =>
    prepareExternalPublication(correct.file, selected, correct.deps);
  const first = await prepare();
  expect(correct.posts).toHaveLength(0);
  expect(first.preview.requests[0]!.source.provider).toBe("blackduck");
  first.preview.requests[0]!.items[0]!.evidence.source_data![
    "sourceRepositoryUrl"
  ] = "https://git.example.test/example/project";
  correct.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  expect([...correct.reports.values()][0]!.evidence.source_data).toMatchObject({
    sourceRepositoryUrl: selected.sourceRepositoryUrl,
  });
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).counts.created).toBe(1);
  expect(correct.posts).toHaveLength(2);
  expect(correct.posts[1]).toBe(correct.posts[0]);
  expect([...correct.reports.values()][0]!.evidence.packages).toMatchObject([
    {
      name: "example/library",
      ecosystem: "composer",
      installed_version: "2.0",
    },
  ]);
  expect((await (await prepare()).publish()).counts.unchanged).toBe(1);
  const foreign = await fixture(report, "https://github.com/example/other");
  await expect(
    prepareExternalPublication(foreign.file, selected, foreign.deps),
  ).rejects.toThrow(/does not match/i);
  expect(foreign.posts).toHaveLength(0);
  const native = normalizeBlackDuckFindings(
    report,
    selected.sourceRepositoryUrl,
  );
  const mixed = structuredClone(native);
  mixed.findings.push(
    ...normalizeBlackDuckFindings(
      [blackDuckBomRow(undefined, "release-b")],
      selected.sourceRepositoryUrl,
    ).findings,
  );
  mixed.read = mixed.findings.length;
  await expect(
    prepareNormalizedExternalPublication(mixed, selected, correct.deps),
  ).rejects.toThrow(/same project version/);
  await expect(
    prepareNormalizedExternalPublication(
      native,
      { ...selected, provider: "wiz" },
      foreign.deps,
    ),
  ).rejects.toThrow(/requires the blackduck provider/);
  const stripped = structuredClone(native);
  const data = stripped.findings[0]!.evidence.source_data!;
  delete data["row"];
  delete data["format"];
  const wiz = { ...selected, provider: "wiz" as const };
  const matching = await fixture();
  for (const sourceData of [
    data,
    { sourceRepositoryUrl: selected.sourceRepositoryUrl },
  ]) {
    stripped.findings[0]!.evidence.source_data = sourceData;
    await expect(
      prepareNormalizedExternalPublication(stripped, wiz, foreign.deps),
    ).rejects.toThrow(/does not match the selected Cloud repository/);
    await prepareNormalizedExternalPublication(stripped, wiz, matching.deps);
  }
  for (const url of [
    "ssh://git@git.example.test/team/project.git",
    ` ${selected.sourceRepositoryUrl}`,
  ]) {
    stripped.findings[0]!.evidence.source_data = { sourceRepositoryUrl: url };
    await expect(
      prepareNormalizedExternalPublication(stripped, wiz, foreign.deps),
    ).rejects.toThrow();
  }
  expect(foreign.posts).toHaveLength(0);
  stripped.findings[0]!.evidence.source_data = { upstream: data };
  await prepareNormalizedExternalPublication(stripped, wiz, foreign.deps);
  delete stripped.findings[0]!.evidence.source_data;
  await expect(
    prepareNormalizedExternalPublication(stripped, selected, foreign.deps),
  ).rejects.toThrow(/retained Black Duck/);
  const normalized = structuredClone(native);
  normalized.findings[0]!.source_finding_id = "sdk-id";
  normalized.findings[0]!.evidence.source_data = {
    sourceRepositoryUrl: selected.sourceRepositoryUrl,
    projectVersionUrl: "https://scanner.example.test/dashboard/version",
  };
  await prepareNormalizedExternalPublication(
    normalized,
    selected,
    correct.deps,
  );

  const summary = normalized.findings[0]!;
  delete summary.evidence.source_data;
  summary.evidence.details = {
    kind: "sast",
    repository: { url: selected.sourceRepositoryUrl },
  };
  const prepareSummary = () =>
    prepareNormalizedExternalPublication(normalized, selected, correct.deps);
  const prepared = await prepareSummary();
  const expected = JSON.stringify(prepared.preview.requests[0]);
  correct.state.loseResponse = true;
  await expect(prepared.publish()).rejects.toThrow("resume the saved request");
  const posted = correct.posts.length;
  correct.state.repositoryUrl = foreign.state.repositoryUrl;
  await expect(prepareSummary()).rejects.toThrow(/does not match/);
  expect(correct.posts).toHaveLength(posted);
  correct.state.repositoryUrl = selected.sourceRepositoryUrl;
  const resumed = await prepareSummary();
  expect(resumed.preview.resumed).toBe(true);
  await resumed.publish();
  expect(correct.posts.slice(-2)).toEqual([expected, expected]);
});

test("Veracode Cloud replays an application policy issue and rejects a foreign destination before POST", async () => {
  const page = veracodePolicyPage([veracodePolicyRow(1)]);
  const correct = await fixture([page]);
  const selected = {
    ...options,
    provider: "veracode" as const,
    sourceRepositoryUrl: "https://github.com/example/project",
    sourceKey: "veracode/example/static",
  };
  const prepare = () =>
    prepareExternalPublication(correct.file, selected, correct.deps);
  const first = await prepare();
  expect(first.preview.requests[0]!.source.provider).toBe("veracode");
  await expect(
    prepareNormalizedExternalPublication(
      normalizeVeracodeFindings(page, selected.sourceRepositoryUrl),
      { ...selected, provider: "wiz" },
      correct.deps,
    ),
  ).rejects.toThrow(/requires the veracode provider/i);
  for (const row of [
    { ...veracodePolicyRow(), context_type: "SANDBOX" },
    { ...veracodePolicyRow(), scan_type: "DYNAMIC" },
  ]) {
    const input = normalizeVeracodeFindings(page, selected.sourceRepositoryUrl);
    input.findings[0]!.source_finding_id = "sdk-id";
    input.findings[0]!.evidence.source_data!["row"] = row;
    await expect(
      prepareNormalizedExternalPublication(input, selected, correct.deps),
    ).rejects.toThrow(/context|STATIC/);
  }
  const partial = normalizeVeracodeFindings(page, selected.sourceRepositoryUrl);
  const finding = partial.findings[0]!;
  delete finding.evidence.source_data!["applicationUrl"];
  const foreignUrl = "https://github.com/example/other";
  const foreign = await fixture(undefined, foreignUrl);
  finding.evidence.details!.repository!.url = foreignUrl;
  for (const id of [finding.source_finding_id, "sdk-id"]) {
    finding.source_finding_id = id;
    await expect(
      prepareNormalizedExternalPublication(
        partial,
        { ...selected, provider: "wiz" },
        foreign.deps,
      ),
    ).rejects.toThrow(/requires the veracode provider/i);
  }
  finding.evidence.details!.repository!.url = selected.sourceRepositoryUrl;
  await expect(
    prepareNormalizedExternalPublication(partial, selected, correct.deps),
  ).rejects.toThrow(/retained application/i);
  finding.evidence.source_data = {
    sourceRepositoryUrl: selected.sourceRepositoryUrl,
    applicationUrl:
      "https://scanner.example.test/appsec/v1/applications/dashboard",
    row: { status: "ready" },
  };
  expect(
    (
      await prepareNormalizedExternalPublication(
        partial,
        { ...selected, provider: "wiz" },
        correct.deps,
      )
    ).preview.findings,
  ).toHaveLength(1);
  const mixed = normalizeVeracodeFindings(page, selected.sourceRepositoryUrl);
  const sdkFinding = structuredClone(mixed.findings[0]!);
  sdkFinding.source_finding_id = "sdk-id";
  delete sdkFinding.evidence.source_data;
  sdkFinding.evidence.details!.repository!.url =
    "https://github.com/example/other";
  mixed.findings.push(sdkFinding);
  mixed.read++;
  await expect(
    prepareNormalizedExternalPublication(mixed, selected, correct.deps),
  ).rejects.toThrow(/does not match/);
  expect(correct.posts).toHaveLength(0);
  first.preview.requests[0]!.items[0]!.evidence.source_data![
    "sourceRepositoryUrl"
  ] = "https://github.com/example/other";
  correct.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).counts.created).toBe(1);
  expect(correct.posts[1]).toBe(correct.posts[0]);
  expect((await (await prepare()).publish()).counts.unchanged).toBe(1);
  const other = await fixture([page], "https://github.com/example/other");
  await expect(
    prepareExternalPublication(other.file, selected, other.deps),
  ).rejects.toThrow(/does not match/i);
  expect(other.posts).toHaveLength(0);
});

test("CLI preview and rejected confirmation never POST or persist an upload", async () => {
  const f = await fixture();
  const cli = createCliTest(main);
  const code = await cli.runCli([...f.command, "--dry-run"], f.cliDeps);
  expect({ code, error: cli.stderr.text() }).toEqual({ code: 0, error: "" });
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    dryRun: true,
    accountId: "synthetic-account",
    destination: {
      id: options.repository,
      import_environment_id: "environment-example",
    },
    read: 1,
  });
  expect(f.posts).toHaveLength(0);
  expect(await readdir(join(f.root, "state")).catch(() => [])).toEqual([]);
  const rejected = createCliTest(main);
  expect(
    await rejected.runCli(f.command, {
      ...f.cliDeps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async () => false,
      },
    }),
  ).toBe(0);
  expect(f.posts).toHaveLength(0);
  const headless = createCliTest(main);
  expect(await headless.runCli(f.command, f.cliDeps)).toBe(2);
  expect(headless.stderr.text()).toContain("needs confirmation");
});

test("CLI creates, reimports unchanged, and updates the same canonical finding", async () => {
  const f = await fixture();
  const first = createCliTest(main);
  expect(await first.runCli([...f.command, "--yes"], f.cliDeps)).toBe(0);
  const canonical = f.reports.get("vendor-1")!.canonical_finding_id;
  expect(JSON.parse(first.stdout.text()).counts.created).toBe(1);
  expect(first.stderr.text()).not.toContain("Selected findings and evidence:");
  const again = await prepareExternalPublication(f.file, options, f.deps);
  expect((await again.publish()).counts.unchanged).toBe(1);
  await writeFile(f.file, JSON.stringify([normalized("vendor-1", "critical")]));
  const updated = await prepareExternalPublication(f.file, options, f.deps);
  expect(updated.preview.requests[0]!.items[0]!.expected_version).toBe(1);
  expect((await updated.publish()).counts.updated).toBe(1);
  expect(f.reports.get("vendor-1")).toMatchObject({
    canonical_finding_id: canonical,
    version: 2,
  });
});

test("normalized input accepts server-materialized optional evidence defaults", async () => {
  const f = await fixture([
    {
      source_finding_id: "vendor-1",
      evidence: {
        title: "Example vulnerable package",
        severity: "high",
        packages: [{ name: "example-package" }],
      },
    },
  ]);
  f.state.materializeDefaults = true;
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect((await prepared.publish()).counts.created).toBe(1);
  expect(f.reports.get("vendor-1")?.evidence).toMatchObject({
    advisory_ids: [],
    packages: [{ name: "example-package", fixed_versions: [] }],
    locations: [],
    image_digests: [],
    source_data: {},
  });
  const stateFiles = await readdir(
    join(f.root, "state", "external-finding-publications"),
  );
  expect(stateFiles.some((name) => name.endsWith(".pending.json"))).toBe(false);
});

test.each(["human", "json"])(
  "interactive %s publication summarizes the input and confirms exclusions",
  async (format) => {
    const selected = {
      ...normalized("vendor-selected"),
      evidence: {
        ...normalized("vendor-selected").evidence,
        title: "Selected \u001b[31m evidence",
        description: "Description to approve",
        source_data: { id: "vendor-selected", note: "Original vendor detail" },
      },
    };
    const f = await fixture([
      selected,
      normalized("unsupported", "unsupported"),
    ]);
    const cli = createCliTest(main);
    let prompted = false;
    expect(
      await cli.runCli(format === "json" ? f.command : f.command.slice(0, -2), {
        ...f.cliDeps,
        externalPublicationPrompt: {
          isInteractive: () => true,
          confirm: async (question, defaultValue) => {
            prompted = true;
            expect(defaultValue).toBe(false);
            expect(cli.stderr.text()).toContain(
              "https://github.com/example/project",
            );
            expect(cli.stderr.text()).toContain(options.sourceKey);
            expect(cli.stderr.text()).toContain("synthetic-account");
            expect(cli.stderr.text()).toContain("environment-example");
            expect(cli.stderr.text()).toContain("Excluded: 1");
            expect(question).toBe(
              "Publish this finding and skip 1 excluded record?",
            );
            expect(cli.stderr.text()).toContain("vendor-selected [high]");
            expect(cli.stderr.text()).toContain(f.file);
            expect(cli.stderr.text()).toContain("--dry-run --format json");
            expect(cli.stderr.text()).not.toContain("Original vendor detail");
            expect(cli.stderr.text()).not.toContain("\u001b");
            expect(cli.stderr.text()).not.toContain("synthetic-token");
            expect(cli.stdout.text()).toBe("");
            expect(f.posts).toHaveLength(0);
            return true;
          },
        },
      }),
    ).toBe(1);
    expect(prompted).toBe(true);
    expect(f.reports.has("vendor-selected")).toBe(true);
    if (format === "json") {
      const result = JSON.parse(cli.stdout.text());
      expect(result.status).toBe("partial");
      expect(result.counts.created).toBe(1);
      expect(result.cloudUrl).toBe(
        `https://chatgpt.com/mcp-app/connector_openai_defense_factory/open_defense_factory#/repositories/${options.repository}/findings`,
      );
    } else {
      expect(cli.stdout.text()).toContain(
        "View Cloud repository: https://chatgpt.com/mcp-app/",
      );
      expect(cli.stdout.text()).not.toContain("/codex/cloud/security/findings");
    }
  },
);

test.each([false, true])(
  "saved request survives a publisher process restart (abrupt: %p)",
  async (abrupt) => {
    const f = await fixture();
    const runner = join(f.root, "run-cli.ts");
    const cliUrl = pathToFileURL(join(import.meta.dir, "../src/cli.ts")).href;
    const fixturesUrl = pathToFileURL(
      join(import.meta.dir, "cli-fixtures.ts"),
    ).href;
    await writeFile(
      runner,
      `import { main } from ${JSON.stringify(cliUrl)};\nimport { dependencies } from ${JSON.stringify(fixturesUrl)};\nprocess.exitCode = await main(process.argv.slice(2), process.stdout, process.stderr, { ...dependencies({ environment: process.env }), cloudFetch: (url, init) => fetch('http://127.0.0.1:${f.port}' + new URL(url).pathname + new URL(url).search, init) });\n`,
    );
    function run() {
      const process = Bun.spawn(
        [Bun.which("bun")!, runner, ...f.command, "--yes"],
        { env: f.environment, stdout: "pipe", stderr: "pipe" },
      );
      const result = Promise.all([
        process.exited,
        new Response(process.stdout).text(),
        new Response(process.stderr).text(),
      ]).then(([code, stdout, stderr]) => ({ code, stdout, stderr }));
      return { process, result };
    }
    const readback = Promise.withResolvers<void>();
    if (abrupt) f.state.holdReadback = () => readback.resolve();
    else f.state.loseResponse = true;
    const first = run();
    if (abrupt) {
      await readback.promise;
      first.process.kill("SIGKILL");
    }
    const lost = await first.result;
    expect(lost.code).not.toBe(0);
    if (!abrupt) {
      expect(lost.code).toBe(2);
      expect(lost.stderr).toContain("resume the saved request");
    }
    expect(f.reports.size).toBe(1);
    const firstBody = f.posts[0];
    f.state.holdReadback = null;
    const second = await run().result;
    expect(second.code, second.stderr).toBe(0);
    if (abrupt) expect(f.posts).toHaveLength(1);
    else expect(f.posts[1]).toBe(firstBody);
    expect(f.receipts.size).toBe(1);
    expect(JSON.parse(second.stdout).counts.created).toBe(1);
  },
);

function observeLockContention() {
  const contended = Promise.withResolvers<void>();
  const original = Database.prototype.exec;
  const spy = spyOn(Database.prototype, "exec").mockImplementation(function (
    this: Database,
    ...args: Parameters<typeof original>
  ) {
    try {
      return original.apply(this, args);
    } catch (error) {
      if (
        args[0] === "BEGIN EXCLUSIVE" &&
        (error as { code?: string }).code === "SQLITE_BUSY"
      )
        contended.resolve();
      throw error;
    }
  });
  return { contended: contended.promise, restore: () => spy.mockRestore() };
}

async function pauseAtPublication(
  f: Awaited<ReturnType<typeof fixture>>,
  stage: "receipt" | "readback" = "readback",
) {
  const arrived = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const completion = (
    await prepareExternalPublication(f.file, options, {
      ...f.deps,
      fetch: async (url, init) => {
        const response =
          stage === "receipt" ? await f.deps.fetch(url, init) : undefined;
        if (
          (stage === "receipt" && init.method === "POST") ||
          (stage === "readback" &&
            new URL(url).pathname.includes("/source_reports/"))
        ) {
          arrived.resolve();
          await release.promise;
        }
        return response ?? f.deps.fetch(url, init);
      },
    })
  ).publish();
  await Promise.race([
    arrived.promise,
    completion.then(() => {
      throw new Error("Publication completed without reaching the pause.");
    }),
  ]);
  return { completion, release };
}

test("overlapping retries cannot delete a newer pending submission or roll back newer evidence", async () => {
  const f = await fixture();
  f.state.brokenReadback = true;
  await expect(
    (await prepareExternalPublication(f.file, options, f.deps)).publish(),
  ).rejects.toThrow("resume the saved request");
  f.state.brokenReadback = false;
  const { completion: first, release } = await pauseAtPublication(f);
  const observer = observeLockContention();
  const second = (
    await prepareExternalPublication(f.file, options, f.deps)
  ).publish();
  try {
    await Promise.race([
      observer.contended,
      second.then(() => {
        throw new Error("Concurrent publication skipped the active lock.");
      }),
    ]);
    expect(f.posts).toHaveLength(1);
    release.resolve();
    await Promise.all([first, second]);
    expect(f.posts).toHaveLength(1);
  } finally {
    release.resolve();
    observer.restore();
    await Promise.allSettled([first, second]);
  }
  const newer = await prepareExternalPublication(f.file, options, f.deps);
  f.state.loseResponse = true;
  await expect(newer.publish()).rejects.toThrow("resume the saved request");
  const acceptedBody = f.posts.at(-1);
  await writeFile(f.file, JSON.stringify([normalized("vendor-1", "critical")]));
  await (await prepareExternalPublication(f.file, options, f.deps)).publish();
  await writeFile(f.file, JSON.stringify([normalized()]));
  const retry = await prepareExternalPublication(f.file, options, f.deps);
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.requests[0]!.request_id).toBe(
    newer.preview.requests[0]!.request_id,
  );
  await retry.publish();
  expect(f.posts.at(-1)).toBe(acceptedBody);
  expect(f.reports.get("vendor-1")?.evidence.severity).toBe("critical");
});

test("reset retirement tolerates a checkpoint written while waiting for the active publisher", async () => {
  const f = await fixture();
  const { completion: active, release } = await pauseAtPublication(
    f,
    "receipt",
  );
  f.state.marker = "generation-2";
  f.state.environmentId = "replacement-environment";
  f.state.brokenReadback = true;
  const observer = observeLockContention();
  const reset = prepareExternalPublication(f.file, options, f.deps);
  const resetResult = reset.then(
    () => "unexpected-success",
    (error: Error) => error.message,
  );
  try {
    await Promise.race([
      observer.contended,
      resetResult.then(() => {
        throw new Error("Reset skipped the active publication lock.");
      }),
    ]);
    expect(f.posts).toHaveLength(1);
    release.resolve();
    await expect(active).rejects.toThrow("resume the saved request");
    expect(await resetResult).toContain("retired without uploading");
  } finally {
    release.resolve();
    observer.restore();
    await Promise.allSettled([active, resetResult]);
  }
  f.state.brokenReadback = false;
  f.reports.clear();
  const fresh = await prepareExternalPublication(f.file, options, f.deps);
  expect(fresh.preview.resumed).toBe(false);
  expect((await fresh.publish()).counts.created).toBe(1);
});

test.each(["receipt", "readback"] as const)(
  "canceling a waiting CLI preserves acknowledgements and the active request during %s",
  async (stage) => {
    const f = await fixture();
    const { completion: active, release } = await pauseAtPublication(f, stage);
    const directory = join(f.root, "state", "external-finding-publications");
    const name = (await readdir(directory)).find((name) =>
      name.endsWith(".pending.json"),
    )!;
    const before = await readFile(join(directory, name), "utf8");
    const listeners = new Map<string, () => void>();
    const cli = createCliTest(main);
    const observer = observeLockContention();
    const waiting = cli.runCli([...f.command, "--yes"], {
      ...f.cliDeps,
      addSignalListener: (signal, listener) => {
        listeners.set(signal, listener);
      },
      removeSignalListener: (signal) => {
        listeners.delete(signal);
      },
    });
    try {
      await Promise.race([
        observer.contended,
        waiting.then(() => {
          throw new Error("Concurrent publication skipped the active lock.");
        }),
      ]);
      listeners.get("SIGINT")!();
      expect(await waiting).toBe(130);
      const interrupted = JSON.parse(cli.stdout.text());
      expect(interrupted).toMatchObject({
        status: "interrupted",
        counts: { created: stage === "readback" ? 1 : 0 },
        unacknowledged: stage === "readback" ? 0 : 1,
        verified: 0,
        savedSubmission: join(directory, name),
      });
      expect(interrupted.receipts).toEqual(JSON.parse(before).receipts ?? []);
      expect(await readFile(join(directory, name), "utf8")).toBe(before);
      expect(listeners.size).toBe(0);
      expect(f.posts).toHaveLength(1);
      const retry = await prepareExternalPublication(f.file, options, f.deps);
      expect(retry.preview.resumed).toBe(true);
      expect(retry.preview.requests[0]!.request_id).toBe(
        JSON.parse(f.posts[0]!).request_id,
      );
      release.resolve();
      expect((await active).counts.created).toBe(1);
    } finally {
      release.resolve();
      observer.restore();
      await Promise.allSettled([active, waiting]);
    }
  },
);

test("canceling before acquiring a new publication lock reports no saved work", async () => {
  const f = await fixture();
  const controller = new AbortController();
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    signal: controller.signal,
  });
  controller.abort();
  try {
    await prepared.publish();
    throw new Error("Expected cancellation");
  } catch (error) {
    expect(error).toBeInstanceOf(ExternalPublicationError);
    const result = (error as ExternalPublicationError).result;
    expect(result).toMatchObject({
      status: "interrupted",
      receipts: [],
      counts: { created: 0, updated: 0, unchanged: 0, error: 0 },
      unacknowledged: 1,
      verified: 0,
    });
    expect(result.savedSubmission).toBeUndefined();
  }
  expect(f.posts).toEqual([]);
  expect(
    (
      await readdir(join(f.root, "state", "external-finding-publications"))
    ).filter((name) => name.endsWith(".pending.json")),
  ).toEqual([]);
});

test("lock cancellation does not report a saved receipt for another request", async () => {
  const f = await fixture();
  f.state.brokenReadback = true;
  await expect(
    (await prepareExternalPublication(f.file, options, f.deps)).publish(),
  ).rejects.toThrow("resume the saved request");
  const directory = join(f.root, "state", "external-finding-publications");
  const name = (await readdir(directory)).find((name) =>
    name.endsWith(".pending.json"),
  )!;
  const saved = JSON.parse(await readFile(join(directory, name), "utf8"));
  saved.receipts[0].id = "another-request";
  const bytes = JSON.stringify(saved);
  await writeFile(join(directory, name), bytes);
  const controller = new AbortController();
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    signal: controller.signal,
  });
  controller.abort();
  await expect(prepared.publish()).rejects.toThrow(
    "receipt for a different publication",
  );
  expect(await readFile(join(directory, name), "utf8")).toBe(bytes);
  expect(f.posts).toHaveLength(1);
});

test.skipIf(process.platform !== "win32")(
  "Windows publication checkpoints start private beneath a shared parent",
  async () => {
    const f = await fixture();
    const shared = join(f.root, "shared");
    await mkdir(shared);
    f.environment.CODEX_SECURITY_STATE_DIR = join(shared, "state");
    const exec = promisify(execFile);
    const system = join(process.env["SystemRoot"] ?? "C:\\Windows", "System32");
    await exec(join(system, "icacls.exe"), [
      shared,
      "/grant",
      "*S-1-1-0:(OI)(CI)R",
    ]);
    const descriptor = async (path: string): Promise<string> => {
      const result = await exec(
        join(system, "WindowsPowerShell", "v1.0", "powershell.exe"),
        [
          "-NoLogo",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "$ErrorActionPreference = 'Stop'; (Microsoft.PowerShell.Security\\Get-Acl -LiteralPath $env:CODEX_SECURITY_TEST_ACL_PATH).Sddl",
        ],
        {
          env: {
            ...Object.fromEntries(
              Object.entries(process.env).filter(
                ([name]) => name.toUpperCase() !== "PSMODULEPATH",
              ),
            ),
            CODEX_SECURITY_TEST_ACL_PATH: path,
            PSModulePath: join(system, "WindowsPowerShell", "v1.0", "Modules"),
          },
        },
      );
      return result.stdout.trim();
    };
    const before = await descriptor(shared);
    expect(before).toContain(";;;WD)");
    f.state.brokenReadback = true;
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow("resume the saved request");
    const directory = join(
      f.environment.CODEX_SECURITY_STATE_DIR,
      "external-finding-publications",
    );
    const name = (await readdir(directory)).find((name) =>
      name.endsWith(".pending.json"),
    )!;
    for (const path of [f.environment.CODEX_SECURITY_STATE_DIR, directory]) {
      const acl = await descriptor(path);
      expect(acl).toContain("D:P");
      expect(acl).not.toContain(";;;WD)");
    }
    expect(await descriptor(join(directory, name))).not.toContain(";;;WD)");
    expect(await descriptor(shared)).toBe(before);
    f.state.brokenReadback = false;
    expect(
      (
        await (
          await prepareExternalPublication(f.file, options, f.deps)
        ).publish()
      ).counts.created,
    ).toBe(1);
    expect(f.posts).toHaveLength(1);
  },
  60_000,
);

test("readback failure retries acknowledged receipts without another POST", async () => {
  const f = await fixture();
  f.state.brokenReadback = true;
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  await expect(prepared.publish()).rejects.toThrow("resume the saved request");
  f.state.brokenReadback = false;
  const retry = await prepareExternalPublication(f.file, options, f.deps);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).counts.created).toBe(1);
  expect(f.posts).toHaveLength(1);
});

test("an older pending receipt can resume after newer evidence without rolling it back", async () => {
  const f = await fixture();
  f.state.loseResponse = true;
  await expect(
    (await prepareExternalPublication(f.file, options, f.deps)).publish(),
  ).rejects.toThrow("resume the saved request");
  const original = f.posts[0];
  await writeFile(f.file, JSON.stringify([normalized("vendor-1", "critical")]));
  expect(
    (
      await (
        await prepareExternalPublication(f.file, options, f.deps)
      ).publish()
    ).counts.updated,
  ).toBe(1);
  await writeFile(f.file, JSON.stringify([normalized()]));
  const replay = await (
    await prepareExternalPublication(f.file, options, f.deps)
  ).publish();
  expect(f.posts.at(-1)).toBe(original);
  expect(replay.receipts[0]!.results[0]!.version).toBe(1);
  expect(f.reports.get("vendor-1")).toMatchObject({
    version: 2,
    evidence: { severity: "critical" },
  });
});

test.each(["environment-example", "replacement-environment", null])(
  "repository reset retires a pending request with environment %p",
  async (environmentId) => {
    const f = await fixture();
    f.state.throttle = true;
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow("Retry-After: 1");
    f.state.marker = "generation-2";
    f.state.environmentId = environmentId;
    await expect(
      prepareExternalPublication(f.file, options, f.deps),
    ).rejects.toThrow("retired without uploading");
    expect(f.posts).toHaveLength(1);
    if (environmentId === null) {
      await expect(
        prepareExternalPublication(f.file, options, f.deps),
      ).rejects.toThrow("Configure an authorized Cloud environment");
      f.state.environmentId = "replacement-environment";
    }
    f.state.throttle = false;
    const fresh = await prepareExternalPublication(f.file, options, f.deps);
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.requests[0]!.repository).toMatchObject({
      reset_marker: "generation-2",
      environment_id: f.state.environmentId,
    });
    expect((await fresh.publish()).counts.created).toBe(1);
    expect(f.posts).toHaveLength(2);
    expect(JSON.parse(f.posts[1]!).request_id).not.toBe(
      JSON.parse(f.posts[0]!).request_id,
    );
  },
);

test("empty or oversized normalized input stops before Cloud discovery", async () => {
  const oversized = {
    source_finding_id: "oversized",
    evidence: {
      title: "Oversized evidence",
      severity: "high" as const,
      source_data: { raw: "x".repeat(5 * 1024 * 1024) },
    },
  };
  const prepare = (findings: (typeof oversized)[]) =>
    prepareNormalizedExternalPublication(
      { read: findings.length, findings, excluded: [] },
      options,
      {
        environment: {},
        credentials: async () => {
          throw new Error("Unexpected authentication");
        },
      },
    );
  await expect(prepare([])).rejects.toThrow("No supported findings");
  await expect(prepare([oversized])).rejects.toThrow("256 KiB");
});

test.each([0, 1])(
  "batching accounts for exactly 5 MiB plus %i UTF-8 bytes",
  async (extraByte) => {
    const f = await fixture();
    const findings = Array.from({ length: 21 }, (_, index) => ({
      source_finding_id: `vendor-${index}`,
      evidence: {
        title: 'Quoted "雪"\\\n🌱',
        severity: "high" as const,
        source_data: { padding: "" },
      },
    }));
    const prepare = () =>
      prepareNormalizedExternalPublication(
        { read: findings.length, findings, excluded: [] },
        { ...options, sourceKey: 'tenant/"境界"' },
        f.deps,
      );
    const template = (await prepare()).preview.requests[0]!;
    const targetBytes = 5 * 1024 * 1024 + extraByte;
    const padding = targetBytes - Buffer.byteLength(JSON.stringify(template));
    for (const [index, finding] of findings.entries())
      finding.evidence.source_data.padding = "x".repeat(
        Math.floor(padding / findings.length) +
          Number(index < padding % findings.length),
      );
    findings.push({ ...findings[0]!, source_finding_id: "trailing" });
    const { requests } = (await prepare()).preview;
    expect(requests.map((request) => request.items.length)).toEqual(
      extraByte === 0 ? [21, 1] : [20, 2],
    );
    const items = requests.flatMap((request) => request.items).slice(0, -1);
    expect(Buffer.byteLength(JSON.stringify({ ...requests[0], items }))).toBe(
      targetBytes,
    );
  },
);

test.each([100, 101])(
  "batching preserves order for %i items",
  async (count) => {
    const records = Array.from({ length: count }, (_, index) =>
      normalized(`vendor-${index}`),
    );
    const f = await fixture(records);
    const prepared = await prepareExternalPublication(f.file, options, f.deps);
    const { requests } = prepared.preview;
    expect(requests.map((request) => request.items.length)).toEqual(
      count === 100 ? [100] : [100, 1],
    );
    expect(
      requests.flatMap((request) =>
        request.items.map((item) => [item.client_id, item.source_finding_id]),
      ),
    ).toEqual(
      records.map((record, index) => [
        `item-${index + 1}`,
        record.source_finding_id,
      ]),
    );
    expect((await prepared.publish()).counts.created).toBe(count);
  },
);

test("publication keeps final item errors visible", async () => {
  const errorFixture = await fixture();
  errorFixture.state.finalError = true;
  const cli = createCliTest(main);
  expect(
    await cli.runCli([...errorFixture.command, "--yes"], errorFixture.cliDeps),
  ).toBe(1);
  expect(JSON.parse(cli.stdout.text()).receipts[0].results[0]).toMatchObject({
    outcome: "error",
    error: { code: "version_conflict" },
  });
});

test("local receipts contain no credential and pending bodies match transmitted bytes", async () => {
  const f = await fixture();
  f.state.throttle = true;
  await expect(
    (await prepareExternalPublication(f.file, options, f.deps)).publish(),
  ).rejects.toThrow("Slow down");
  const directory = join(f.root, "state", "external-finding-publications");
  const name = (await readdir(directory)).find((name) =>
    name.endsWith(".pending.json"),
  )!;
  const saved = await readFile(join(directory, name), "utf8");
  expect(saved).not.toContain("synthetic-token");
  expect(
    JSON.stringify(
      (JSON.parse(saved) as { requests: FindingImportRequest[] }).requests[0],
    ),
  ).toBe(f.posts[0]!);
});

test("a restarted large publication resumes after the ten-request rate window", async () => {
  const f = await fixture(
    Array.from({ length: 1001 }, (_, i) => normalized(`bulk-${i}`)),
  );
  const runner = join(f.root, "run-batched-cli.ts");
  const cliUrl = pathToFileURL(join(import.meta.dir, "../src/cli.ts")).href;
  const fixturesUrl = pathToFileURL(
    join(import.meta.dir, "cli-fixtures.ts"),
  ).href;
  await writeFile(
    runner,
    `import { main } from ${JSON.stringify(cliUrl)};\nimport { dependencies } from ${JSON.stringify(fixturesUrl)};\nprocess.exitCode = await main(process.argv.slice(2), process.stdout, process.stderr, { ...dependencies({ environment: process.env }), cloudFetch: (url, init) => fetch('http://127.0.0.1:${f.port}' + new URL(url).pathname + new URL(url).search, init) });\n`,
  );
  async function run() {
    const child = Bun.spawn(
      [Bun.which("bun")!, runner, ...f.command, "--yes"],
      {
        env: f.environment,
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [code, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { code, stdout, stderr };
  }
  f.state.postBudget = 10;
  const first = await run();
  expect(first.code).toBe(2);
  expect(first.stderr).toContain("HTTP 429");
  expect(f.reports.size).toBe(1000);
  expect(f.posts).toHaveLength(11);
  const rejectedBody = f.posts[10];
  f.state.postBudget = 10;
  const second = await run();
  expect(second.code).toBe(0);
  expect(JSON.parse(second.stdout).counts.created).toBe(1001);
  expect(f.posts).toHaveLength(12);
  expect(f.posts[11]).toBe(rejectedBody);
  expect(f.reports.size).toBe(1001);
  expect(f.receipts.size).toBe(11);
});

test("a failed checkpoint leaves the original pending request recoverable", async () => {
  const f = await fixture();
  const rename = fs.rename;
  const checkpoint = spyOn(fs, "rename").mockImplementation(
    async (source, destination) => {
      if (String(destination).endsWith(".pending.json") && f.posts.length > 0)
        throw new Error("Checkpoint interrupted");
      return rename(source, destination);
    },
  );
  try {
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow("Checkpoint interrupted");
  } finally {
    checkpoint.mockRestore();
  }
  const directory = join(f.root, "state", "external-finding-publications");
  const name = (await readdir(directory)).find((name) =>
    name.endsWith(".pending.json"),
  )!;
  const saved = JSON.parse(await readFile(join(directory, name), "utf8"));
  expect(saved.receipts).toBeUndefined();
  expect(JSON.stringify(saved.requests[0])).toBe(f.posts[0]!);
  await writeFile(join(directory, `${name}.orphan.tmp`), "{");
  expect(
    (
      await (
        await prepareExternalPublication(f.file, options, f.deps)
      ).publish()
    ).counts.created,
  ).toBe(1);
  expect(f.posts).toHaveLength(2);
  expect(f.posts[1]).toBe(f.posts[0]);
  expect(f.receipts.size).toBe(1);
});

test.each(["pending", "result"])(
  "a failed %s file installation cleans up temporary files and can be retried",
  async (stage) => {
    const f = await fixture();
    const rename = fs.rename;
    const installation = spyOn(fs, "rename").mockImplementation(
      async (source, destination) => {
        if (String(destination).endsWith(`.${stage}.json`))
          throw new Error("File installation interrupted");
        return rename(source, destination);
      },
    );
    try {
      await expect(
        (await prepareExternalPublication(f.file, options, f.deps)).publish(),
      ).rejects.toThrow("File installation interrupted");
    } finally {
      installation.mockRestore();
    }
    const directory = join(f.root, "state", "external-finding-publications");
    const files = await readdir(directory);
    expect(files.filter((name) => name.endsWith(".tmp"))).toEqual([]);
    expect(files.some((name) => name.endsWith(".pending.json"))).toBe(
      stage === "result",
    );
    expect(f.posts).toHaveLength(stage === "result" ? 1 : 0);
    expect(
      (
        await (
          await prepareExternalPublication(f.file, options, f.deps)
        ).publish()
      ).counts.created,
    ).toBe(1);
    expect(f.posts).toHaveLength(1);
  },
);

test.each(["request", "counts", "length", "schema"])(
  "cached receipts retain publication validation (%s)",
  async (invalid) => {
    const f = await fixture();
    f.state.brokenReadback = true;
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow("resume the saved request");
    const directory = join(f.root, "state", "external-finding-publications");
    const name = (await readdir(directory)).find((name) =>
      name.endsWith(".pending.json"),
    )!;
    const pending = join(directory, name);
    const saved = JSON.parse(await readFile(pending, "utf8"));
    if (invalid === "request")
      saved.receipts[0].id = "00000000-0000-4000-8000-000000000000";
    if (invalid === "counts") saved.receipts[0].counts.error = 1;
    if (invalid === "length") saved.receipts.push(saved.receipts[0]);
    if (invalid === "schema") saved.receipts[0].source.provider = "unsupported";
    await writeFile(pending, JSON.stringify(saved));
    f.state.brokenReadback = false;
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow();
    expect(f.posts).toHaveLength(1);
    expect(
      (await readdir(directory)).filter((name) => name.endsWith(".tmp")),
    ).toEqual([]);
  },
);

test("an opaque retry preserves a released partial submission whose final row exceeds the corrected limit", async () => {
  const f = await fixture();
  const rows = Array.from({ length: 101 }, (_, i) => {
    const row = normalized(`item-${i}`);
    return { ...row, evidence: { ...row.evidence, severity: "high" as const } };
  });
  const pad = "x".repeat(261872);
  Object.assign(rows[100]!.evidence, {
    source_data: {
      get score() {
        return Object.assign(new Number(1e-7), { toJSON: () => 0 });
      },
      pad,
    },
  });
  const prepare = (selected = rows, sourceKey = options.sourceKey) =>
    prepareReleased(
      f,
      { read: selected.length, findings: selected, excluded: [] },
      { ...options, sourceKey },
    );
  const ready = await prepare();
  const [first, last] = ready.preview.requests;
  const [acknowledged] = (await (await prepare(rows.slice(0, 100))).publish())
    .receipts;

  // Rebuild the released SDK's checkpoint, including its first 100 acknowledged items.
  first!.request_id = "353fb2dc-0e4a-4be5-b825-5755e4678aa5";
  last!.request_id = "66da2566-e3c5-4557-aef2-10ffd179982d";
  last!.items[0]!.evidence.source_data = {
    score: 1e-7,
    pad,
  };
  const digest =
    "ae9fd2d8c0f71c489d99604663201894d8d2fe91550bb949035177c8bd0595ef";
  const saved = JSON.stringify({
    accountId: "synthetic-account",
    requests: [first, last],
    receipts: [{ ...acknowledged, id: first!.request_id }],
    inputProjection: { inputDigest: digest, savedEvidenceDigest: digest },
  });
  expect(hash("sha256", saved)).toBe(
    "4ca49c21887a29fdb56ea1bcb8197ef5fed02c68f7aacfaa0cc06d9c9b5a128a",
  );
  const path = join(
    f.root,
    "state",
    "external-finding-publications",
    "b8d2c1dda3201683c738fb810639279ba8e30a5dfd1402288a5d7017f7b572e8.pending.json",
  );
  await writeFile(path, saved, { mode: 0o600 });

  await expect(prepare()).rejects.toThrow("checkpoint was preserved");
  await expect(ready.publish()).rejects.toThrow("checkpoint was preserved");
  f.reports.clear(); // The separate source has no prior findings.
  expect((await prepare(rows, "tenant-example/other")).preview.resumed).toBe(
    false,
  );
  expect(f.posts).toHaveLength(1);
  expect(await readFile(path, "utf8")).toBe(saved);
});

test("a held retry reports the acknowledged batch after another resumer retires the checkpoint", async () => {
  const f = await fixture(
    Array.from({ length: 101 }, (_, index) => normalized(`item-${index}`)),
  );
  const prepare = () => prepareExternalPublication(f.file, options, f.deps);
  f.state.postBudget = 1;
  const original = await prepare();
  await expect(original.publish()).rejects.toThrow("Slow down");
  const receipt = f.receipts.get(original.preview.requests[0]!.request_id)!;
  expect(receipt.item_count).toBe(100);
  const first = await prepare();
  const held = await prepare();
  f.state.postBudget = Infinity;
  f.state.marker = "generation-2";
  await expect(first.publish()).rejects.toThrow("HTTP 409");

  const error = await held.publish().catch((error: unknown) => error);
  if (!(error instanceof ExternalPublicationError)) throw error;
  expect(error.result).toMatchObject({
    status: "interrupted",
    counts: { created: 100, updated: 0, unchanged: 0, error: 0 },
    unacknowledged: 1,
  });
  expect(error.result.receipts).toEqual([receipt]);
  expect(error.result).not.toHaveProperty("savedSubmission");
  const bodies = original.preview.requests.map((request) =>
    JSON.stringify(request),
  );
  expect(f.posts).toEqual([bodies[0]!, bodies[1]!, bodies[1]!]);
  const directory = join(f.root, "state", "external-finding-publications");
  expect(
    (await readdir(directory)).filter((name) => name.endsWith(".pending.json")),
  ).toEqual([]);
});

test.each(["matching", "replaced", "missing"])(
  "a held ordinary retry preserves the newer pending request when its original result is %s",
  async (terminal) => {
    const f = await fixture(
      Array.from({ length: 101 }, (_, index) => normalized(`item-${index}`)),
    );
    const prepare = () => prepareExternalPublication(f.file, options, f.deps);
    f.state.postBudget = 1;
    await expect((await prepare()).publish()).rejects.toThrow("Slow down");
    const held = await prepare();
    f.state.postBudget = Infinity;
    const completed = await (await prepare()).publish();
    if (terminal === "replaced") await (await prepare()).publish();

    const fresh = await prepare();
    expect(fresh.preview.requests[0]!.request_id).not.toBe(
      held.preview.requests[0]!.request_id,
    );
    f.state.postBudget = 0;
    const staged = await fresh.publish().catch((error: unknown) => error);
    if (!(staged instanceof ExternalPublicationError)) throw staged;
    expect(staged.message).toContain("HTTP 429");
    const path = staged.result.savedSubmission!;
    const saved = await readFile(path, "utf8");
    if (terminal === "missing")
      await rm(path.replace(/\.pending\.json$/, ".result.json"));

    const posts = [...f.posts];
    if (terminal === "matching") {
      expect(await held.publish()).toEqual(completed);
    } else {
      const error = await held.publish().catch((error: unknown) => error);
      if (!(error instanceof ExternalPublicationError)) throw error;
      expect(error.result).toMatchObject({
        status: "interrupted",
        counts: { created: 100, updated: 0, unchanged: 0, error: 0 },
        unacknowledged: 1,
      });
      expect(error.result.receipts).toEqual([completed.receipts[0]!]);
      expect(error.result).not.toHaveProperty("savedSubmission");
    }
    expect(f.posts).toEqual(posts);
    expect(await readFile(path, "utf8")).toBe(saved);
  },
);

test.each([1, 101])(
  "a prepared retry keeps its receipts after another resumer completes (%i items)",
  async (count) => {
    const f = await fixture(
      Array.from({ length: count }, (_, index) => normalized(`item-${index}`)),
    );
    f.state.postBudget = 1;
    f.state.brokenReadback = true;
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow("resume the saved request");
    f.state.brokenReadback = false;
    const first = await prepareExternalPublication(f.file, options, f.deps);
    const second = await prepareExternalPublication(f.file, options, f.deps);
    f.state.postBudget = Infinity;
    const completed = await first.publish();
    expect(completed.counts.created).toBe(count);
    const completedPosts = f.posts.length;
    f.state.postBudget = 0;
    expect(await second.publish()).toEqual(completed);
    expect(f.posts).toHaveLength(completedPosts);
    const fresh = await prepareExternalPublication(f.file, options, f.deps);
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.requests[0]!.request_id).not.toBe(
      first.preview.requests[0]!.request_id,
    );
    f.state.postBudget = Infinity;
    expect((await fresh.publish()).counts.unchanged).toBe(count);
  },
);

test.each([
  ["initial", "write"],
  ["initial", "sync"],
  ["result", "write"],
  ["result", "sync"],
  ["result", "rename"],
])(
  "failed %s staging cleans temporary data and remains retryable (%s)",
  async (stage, fault) => {
    const f = await fixture();
    const prepared = await prepareExternalPublication(f.file, options, f.deps);
    const originalOpen = fs.open;
    const originalRename = fs.rename;
    let temporaryOpens = 0;
    let injected = false;
    const openSpy = spyOn(fs, "open").mockImplementation(async (...args) => {
      const handle = await originalOpen(...args);
      // A fresh publication stages the pending body, its checkpoint, then its result.
      if (
        String(args[0]).endsWith(".tmp") &&
        ++temporaryOpens === (stage === "initial" ? 1 : 3)
      ) {
        if (fault === "write") {
          const originalWrite = handle.writeFile.bind(handle);
          handle.writeFile = async (data) => {
            const serialized = String(data);
            await originalWrite(
              serialized.slice(0, Math.ceil(serialized.length / 2)),
            );
            injected = true;
            throw new Error("Synthetic disk write failed");
          };
        } else if (fault === "sync") {
          handle.sync = async () => {
            injected = true;
            throw new Error("Synthetic file sync failed");
          };
        }
      }
      return handle;
    });
    const renameSpy = spyOn(fs, "rename").mockImplementation(
      async (from, to) => {
        if (fault === "rename" && String(to).endsWith(".result.json")) {
          injected = true;
          throw new Error("Synthetic result rename failed");
        }
        return originalRename(from, to);
      },
    );
    try {
      await expect(prepared.publish()).rejects.toThrow("Synthetic");
    } finally {
      openSpy.mockRestore();
      renameSpy.mockRestore();
    }
    expect(injected).toBe(true);
    const directory = join(f.root, "state", "external-finding-publications");
    const files = await readdir(directory);
    expect(files.filter((name) => name.endsWith(".tmp"))).toEqual([]);
    expect(files.some((name) => name.endsWith(".pending.json"))).toBe(
      stage === "result",
    );
    expect(f.posts).toHaveLength(stage === "initial" ? 0 : 1);
    const retry = await prepareExternalPublication(f.file, options, f.deps);
    expect(retry.preview.resumed).toBe(stage === "result");
    expect((await retry.publish()).counts.created).toBe(1);
    expect(f.posts).toHaveLength(1);
    expect(f.receipts.size).toBe(1);
    expect(
      (await readdir(directory)).some((name) => name.endsWith(".tmp")),
    ).toBe(false);
  },
);

test.each(["JSON", "JSONL"])(
  "malformed %s input keeps Node parser diagnostics terminal-safe",
  async (format) => {
    const f = await fixture();
    await writeFile(
      f.file,
      `${format === "JSONL" ? "{}\n" : ""}\u001b[2Jmalformed`,
    );
    // Bundle beneath the SDK so the real Node process resolves installed packages.
    const bundle = await mkdtemp(
      join(import.meta.dir, "..", ".import-parser-"),
    );
    cleanups.push(() => rm(bundle, { recursive: true, force: true }));
    const runner = join(bundle, "parse-input.mts");
    await writeFile(
      runner,
      `
      export { main } from "../src/cli.js";
      export { dependencies } from "../tests-ts/cli-fixtures.js";
    `,
    );
    const built = await Bun.build({
      entrypoints: [runner],
      outdir: bundle,
      target: "node",
      format: "esm",
      packages: "external",
    });
    expect(built.success).toBe(true);
    const invocation = join(bundle, "invoke.mjs");
    await writeFile(
      invocation,
      `
      import { main, dependencies } from ${JSON.stringify(pathToFileURL(built.outputs[0]!.path).href)};
      process.exitCode = await main(process.argv.slice(2), process.stdout, process.stderr, {
        ...dependencies({ environment: process.env }),
        cloudFetch: async () => { throw new Error("Unexpected Cloud request"); },
      });
    `,
    );
    const child = Bun.spawn(
      [Bun.which("node")!, invocation, ...f.command, "--dry-run"],
      {
        env: f.environment,
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [code, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(code).toBe(2);
    expect(JSON.parse(stdout)).toMatchObject({
      status: "failed",
      error: expect.stringContaining("malformed"),
    });
    expect(stdout).not.toContain("\u001b");
    expect(stderr).toContain(
      "Could not read vendor findings as UTF-8 JSON, JSONL, or Wiz CSV:",
    );
    expect(stderr).toContain("malformed");
    expect(stderr).not.toContain("\u001b");
    expect(f.posts).toHaveLength(0);
    expect(await readdir(join(f.root, "state")).catch(() => [])).toEqual([]);
  },
);

test.each([
  {
    kind: "OS package container image",
    artifactType: { group: "OS_PACKAGE", osPackageManager: "RPM" },
    vulnerableAsset: { id: "image-os", imageId: "sha256:os-image" },
    ecosystem: "RPM",
    digest: "sha256:os-image",
  },
  {
    kind: "code library container image",
    artifactType: { group: "CODE_LIBRARY", codeLibraryLanguage: "PYTHON" },
    vulnerableAsset: { id: "image-library", imageId: "sha256:library-image" },
    ecosystem: "PYTHON",
    digest: "sha256:library-image",
  },
  {
    kind: "running container",
    artifactType: { group: "CODE_LIBRARY", codeLibraryLanguage: "JAVA" },
    vulnerableAsset: {
      id: "container-library",
      ImageExternalId: "sha256:running-image",
    },
    ecosystem: "JAVA",
    digest: "sha256:running-image",
  },
])(
  "Wiz GraphQL nodes retain $kind metadata",
  async ({ artifactType, vulnerableAsset, ecosystem, digest }) => {
    const record = {
      id: "synthetic-occurrence",
      name: "CVE-2099-0002",
      detailedName: "example-lib",
      version: "1.0.0",
      vendorSeverity: "HIGH",
      artifactType,
      vulnerableAsset,
    };
    const f = await fixture({
      data: {
        vulnerabilityFindings: {
          nodes: [record],
          pageInfo: { hasNextPage: false },
        },
      },
    });
    const parsed = await readVendorFindings(f.file);
    expect(parsed.excluded).toEqual([]);
    expect(parsed.findings[0]).toMatchObject({
      source_finding_id: record.id,
      evidence: {
        packages: [
          { name: "example-lib", ecosystem, installed_version: "1.0.0" },
        ],
        image_digests: [digest],
        source_data: record,
      },
    });
  },
);

test.each([false, true])(
  "receipt client IDs correlate reordered results (cached: %p)",
  async (cached) => {
    const f = await fixture([
      normalized("vendor-first", "high"),
      normalized("vendor-second", "low"),
    ]);
    const deps = {
      ...f.deps,
      fetch: async (url: string, init: RequestInit) => {
        const response = await f.deps.fetch(url, init);
        if (init.method !== "POST" || !response.ok) return response;
        const receipt = (await response.json()) as FindingImportReceipt;
        receipt.results.reverse();
        return new Response(JSON.stringify(receipt), {
          headers: { "Content-Type": "application/json" },
        });
      },
    };
    let prepared = await prepareExternalPublication(f.file, options, deps);
    if (cached) {
      f.state.brokenReadback = true;
      await expect(prepared.publish()).rejects.toThrow("Readback unavailable");
      f.state.brokenReadback = false;
      f.state.postBudget = 0;
      prepared = await prepareExternalPublication(f.file, options, deps);
      expect(prepared.preview.resumed).toBe(true);
    }
    const result = await prepared.publish();
    expect(result.counts.created).toBe(2);
    expect(result.receipts[0]!.results.map((item) => item.client_id)).toEqual([
      "item-2",
      "item-1",
    ]);
    expect(f.posts).toHaveLength(1);
    expect(f.receipts.size).toBe(1);
  },
);

test.each(["duplicate", "missing", "unexpected"])(
  "receipt client IDs reject %s results before checkpointing",
  async (invalid) => {
    const f = await fixture([
      normalized("vendor-first"),
      normalized("vendor-second"),
    ]);
    const deps = {
      ...f.deps,
      fetch: async (url: string, init: RequestInit) => {
        const response = await f.deps.fetch(url, init);
        if (init.method !== "POST" || !response.ok) return response;
        const receipt = (await response.json()) as FindingImportReceipt;
        if (invalid === "duplicate")
          receipt.results[1]!.client_id = receipt.results[0]!.client_id;
        if (invalid === "missing") receipt.results.pop();
        if (invalid === "unexpected")
          receipt.results[0]!.client_id = "unexpected-client";
        return new Response(JSON.stringify(receipt), {
          headers: { "Content-Type": "application/json" },
        });
      },
    };
    await expect(
      (await prepareExternalPublication(f.file, options, deps)).publish(),
    ).rejects.toThrow("Cloud returned a receipt for a different publication");
    const directory = join(f.root, "state", "external-finding-publications");
    const pending = (await readdir(directory)).find((name) =>
      name.endsWith(".pending.json"),
    )!;
    expect(
      JSON.parse(await readFile(join(directory, pending), "utf8")).receipts ??
        [],
    ).toEqual([]);
    expect(f.posts).toHaveLength(1);
  },
);

test.each(["replacement-environment", null])(
  "saved publication preserves its environment when discovery changes to %p",
  async (environmentId) => {
    const f = await fixture();
    f.state.loseResponse = true;
    await expect(
      (await prepareExternalPublication(f.file, options, f.deps)).publish(),
    ).rejects.toThrow("resume the saved request");
    const original = f.posts[0]!;
    f.state.environmentId = environmentId;
    const retry = await prepareExternalPublication(f.file, options, f.deps);
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests[0]!.repository.environment_id).toBe(
      "environment-example",
    );
    expect((await retry.publish()).counts.created).toBe(1);
    expect(f.posts.at(-1)).toBe(original);
  },
);

test("mixed environments preserve input order and are shown before confirmation", async () => {
  const f = await fixture([normalized("existing-a"), normalized("existing-c")]);
  await (await prepareExternalPublication(f.file, options, f.deps)).publish();
  const originalIds = ["existing-a", "existing-c"].map(
    (id) => f.reports.get(id)!.canonical_finding_id,
  );
  f.state.environmentId = "replacement-environment";
  await writeFile(
    f.file,
    JSON.stringify([
      normalized("existing-a", "critical"),
      normalized("new-b"),
      normalized("existing-c", "critical"),
    ]),
  );
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect(
    prepared.preview.requests.map(
      (request) => request.repository.environment_id,
    ),
  ).toEqual([
    "environment-example",
    "replacement-environment",
    "environment-example",
  ]);
  expect(
    prepared.preview.requests.flatMap((request) =>
      request.items.map((item) => [
        item.source_finding_id,
        item.expected_version,
      ]),
    ),
  ).toEqual([
    ["existing-a", 1],
    ["new-b", 0],
    ["existing-c", 1],
  ]);
  f.state.throttle = true;
  await expect(prepared.publish()).rejects.toThrow("Retry-After");
  f.state.throttle = false;
  f.state.environmentId = "changed-default";
  const cli = createCliTest(main);
  expect(
    await cli.runCli(f.command, {
      ...f.cliDeps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async () => {
          expect(cli.stderr.text()).toContain(
            "Environment: environment-example, replacement-environment",
          );
          expect(cli.stderr.text()).not.toContain("changed-default");
          expect(f.posts).toHaveLength(2);
          return true;
        },
      },
    }),
  ).toBe(0);
  expect(
    JSON.parse(cli.stdout.text()).receipts.map(
      (receipt: FindingImportReceipt) => receipt.id,
    ),
  ).toEqual(prepared.preview.requests.map((request) => request.request_id));
  expect(f.posts[2]).toBe(f.posts[1]);
  expect(JSON.parse(cli.stdout.text()).counts).toEqual({
    created: 1,
    updated: 2,
    unchanged: 0,
    error: 0,
  });
  expect(
    ["existing-a", "new-b", "existing-c"].map(
      (id) => f.reports.get(id)!.environment_id,
    ),
  ).toEqual([
    "environment-example",
    "replacement-environment",
    "environment-example",
  ]);
  expect(
    ["existing-a", "existing-c"].map(
      (id) => f.reports.get(id)!.canonical_finding_id,
    ),
  ).toEqual(originalIds);
});

test("existing source updates do not need a newly discovered default environment", async () => {
  const f = await fixture();
  await (await prepareExternalPublication(f.file, options, f.deps)).publish();
  f.state.environmentId = null;
  await writeFile(f.file, JSON.stringify([normalized("vendor-1", "critical")]));
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect(prepared.preview.requests[0]!.repository.environment_id).toBe(
    "environment-example",
  );
  expect((await prepared.publish()).counts.updated).toBe(1);
  const posts = f.posts.length;
  await writeFile(f.file, JSON.stringify([normalized("new-vendor")]));
  await expect(
    prepareExternalPublication(f.file, options, f.deps),
  ).rejects.toThrow("Configure an authorized Cloud environment");
  expect(f.posts).toHaveLength(posts);
});

test.each([
  ["id", `aif_${"0".repeat(64)}`],
  ["environment_id", "unexpected-environment"],
])("source readback must preserve acknowledged %s", async (field, value) => {
  const f = await fixture();
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    fetch: async (url, init) => {
      const response = await f.deps.fetch(url, init);
      if (new URL(url).pathname.includes("/source_reports/")) {
        return Response.json({
          ...(await response.json()),
          [field]: value,
        });
      }
      return response;
    },
  });
  await expect(prepared.publish()).rejects.toThrow(
    "Cloud readback did not match the saved finding identity",
  );
  expect(f.posts).toHaveLength(1);
  const retry = await prepareExternalPublication(f.file, options, f.deps);
  expect((await retry.publish()).counts.created).toBe(1);
  expect(f.posts).toHaveLength(1);
});

test("malformed bracketed URLs exclude only their own finding before upload", async () => {
  const invalid = normalized("invalid-url");
  const f = await fixture([
    normalized("valid-url"),
    {
      ...invalid,
      evidence: { ...invalid.evidence, url: "https://[127.0.0.1]/finding" },
    },
  ]);
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect(
    prepared.preview.findings.map((finding) => finding.source_finding_id),
  ).toEqual(["valid-url"]);
  expect(prepared.preview.excluded).toHaveLength(1);
  expect(prepared.preview.excluded[0]!.reason).toContain("HTTP(S)");
  expect((await prepared.publish()).counts.created).toBe(1);
  expect(f.reports.has("invalid-url")).toBe(false);
});

test.each([false, true])(
  "publication waits through the server budget while retaining cancellation: %p",
  async (cancel) => {
    const f = await fixture();
    const arrived = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const controller = new AbortController();
    const prepared = await prepareExternalPublication(f.file, options, {
      ...f.deps,
      signal: controller.signal,
      fetch: async (url, init) => {
        if (init.method === "POST") {
          arrived.resolve();
          await release.promise;
        }
        return f.deps.fetch(url, init);
      },
    });
    const deadlines: { milliseconds: number; controller: AbortController }[] =
      [];
    const timeout = spyOn(AbortSignal, "timeout").mockImplementation(
      (milliseconds) => {
        const controller = new AbortController();
        deadlines.push({ milliseconds, controller });
        return controller.signal;
      },
    );
    const completion = prepared.publish();
    try {
      await Promise.race([
        arrived.promise,
        completion.then(() => {
          throw new Error(
            "Publication completed before the POST was released.",
          );
        }),
      ]);
      // Advance a controlled clock through the server's publication budget.
      for (const deadline of deadlines) {
        if (deadline.milliseconds <= 45_000)
          deadline.controller.abort(
            new DOMException("Publication deadline elapsed", "TimeoutError"),
          );
      }
      if (cancel) controller.abort(new Error("Synthetic cancellation"));
      release.resolve();
      if (cancel) {
        await expect(completion).rejects.toThrow("Synthetic cancellation");
        expect(f.posts).toHaveLength(0);
        const retry = await prepareExternalPublication(f.file, options, f.deps);
        expect(retry.preview.resumed).toBe(true);
        expect(retry.preview.requests[0]!.request_id).toBe(
          prepared.preview.requests[0]!.request_id,
        );
        expect((await retry.publish()).counts.created).toBe(1);
        expect(f.posts[0]).toBe(JSON.stringify(prepared.preview.requests[0]));
      } else {
        expect((await completion).counts.created).toBe(1);
        expect(f.posts).toHaveLength(1);
      }
    } finally {
      release.resolve();
      await completion.catch(() => undefined);
      timeout.mockRestore();
    }
  },
);

test("numeric evidence size excludes an oversized item and preserves a valid mixed-format sibling", async () => {
  const oversized = {
    ...normalized("oversized-numbers"),
    evidence: {
      ...normalized().evidence,
      source_data: { metrics: Array(48_000).fill(1e-7) },
    },
  };
  const accepted = {
    ...normalized("accepted-numbers"),
    evidence: {
      ...normalized().evidence,
      source_data: {
        metrics: [...Array(10_000).fill(1e-7), ...Array(30_000).fill(1e-6)],
      },
    },
  };
  expect(Buffer.byteLength(JSON.stringify(accepted.evidence))).toBeGreaterThan(
    256 * 1024,
  );
  const f = await fixture([oversized, accepted]);
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect(
    prepared.preview.findings.map((finding) => finding.source_finding_id),
  ).toEqual(["accepted-numbers"]);
  expect(prepared.preview.excluded).toHaveLength(1);
  expect(prepared.preview.excluded[0]!.reason).toContain("256 KiB");
  expect((await prepared.publish()).counts.created).toBe(1);
  expect(f.posts).toHaveLength(1);
  expect(JSON.parse(f.posts[0]!).items[0].evidence.source_data).toEqual(
    accepted.evidence.source_data,
  );
  expect(f.reports.has("oversized-numbers")).toBe(false);
});

test.each([0xff, 0xfe])(
  "invalid UTF-8 byte %p cannot change a source identity",
  async (byte) => {
    const f = await fixture();
    await writeFile(
      f.file,
      Buffer.concat([
        Buffer.from('{"source_finding_id":"vendor-'),
        Buffer.from([byte]),
        Buffer.from('","evidence":{"title":"Example","severity":"high"}}'),
      ]),
    );
    await expect(
      prepareExternalPublication(f.file, options, f.deps),
    ).rejects.toThrow("UTF-8");
    expect(f.posts).toHaveLength(0);
    await writeFile(
      f.file,
      `\uFEFF${JSON.stringify(normalized("vendor-\uFFFD"))}`,
    );
    expect(
      (await readVendorFindings(f.file)).findings[0]!.source_finding_id,
    ).toBe("vendor-\uFFFD");
  },
);

test("unsafe evidence integers are rejected while exact strings and safe integers survive", async () => {
  const f = await fixture();
  await writeFile(
    f.file,
    `[
    {"source_finding_id":"unsafe-a","evidence":{"title":"Example","severity":"high","source_data":{"counter":9007199254740992}}},
    {"source_finding_id":"unsafe-b","evidence":{"title":"Example","severity":"high","source_data":{"counter":9007199254740993}}},
    {"source_finding_id":"unsafe-negative","evidence":{"title":"Example","severity":"high","source_data":{"counter":-9007199254740993}}},
    {"source_finding_id":"exact","evidence":{"title":"Example","severity":"high","source_data":{"counter":"9007199254740993","safe":9007199254740991,"fraction":0.125}}}
  ]`,
  );
  const parsed = await readVendorFindings(f.file);
  expect(parsed.excluded.map((item) => item.source_finding_id)).toEqual([
    "unsafe-a",
    "unsafe-b",
    "unsafe-negative",
  ]);
  expect(
    parsed.excluded.every((item) => item.reason.includes("safe integer")),
  ).toBe(true);
  expect(parsed.findings[0]!.evidence.source_data).toEqual({
    counter: "9007199254740993",
    safe: Number.MAX_SAFE_INTEGER,
    fraction: 0.125,
  });
});

test("mixed valid and rejected input reports partial completion with exit code 1", async () => {
  const f = await fixture([
    normalized("invalid", "unsupported"),
    normalized("valid"),
  ]);
  const cli = createCliTest(main);
  expect(await cli.runCli([...f.command, "--yes"], f.cliDeps)).toBe(1);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    status: "partial",
    read: 2,
    ready: 1,
    counts: { created: 1, error: 0 },
    unacknowledged: 0,
    verified: 1,
    excluded: [{ source_finding_id: "invalid", position: 1 }],
  });
});

test("server item failures identify the vendor record after local exclusions", async () => {
  const f = await fixture([
    normalized("invalid", "unsupported"),
    normalized("rejected-vendor"),
  ]);
  f.state.finalError = true;
  const cli = createCliTest(main);
  expect(await cli.runCli([...f.command, "--yes"], f.cliDeps)).toBe(1);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    status: "partial",
    verified: 0,
    unacknowledged: 0,
    failures: [
      {
        source_finding_id: "rejected-vendor",
        code: "version_conflict",
        message: "Reload current evidence",
      },
    ],
  });
});

test("interrupted CLI output preserves acknowledged batches and resumes only unfinished uploads", async () => {
  const f = await fixture(
    Array.from({ length: 101 }, (_, i) => normalized(`vendor-${i}`)),
  );
  f.state.postBudget = 1;
  const first = createCliTest(main);
  expect(await first.runCli([...f.command, "--yes"], f.cliDeps)).toBe(2);
  const partial = JSON.parse(first.stdout.text());
  expect(partial).toMatchObject({
    status: "interrupted",
    ready: 101,
    counts: { created: 100 },
    unacknowledged: 1,
    verified: 0,
  });
  expect(partial.receipts).toHaveLength(1);
  expect(partial.savedSubmission).toEndWith(".pending.json");
  expect(partial.error).toContain("Repeat the same command");
  expect(f.reports.size).toBe(100);
  f.state.postBudget = Infinity;
  const retry = createCliTest(main);
  expect(await retry.runCli([...f.command, "--yes"], f.cliDeps)).toBe(0);
  expect(JSON.parse(retry.stdout.text())).toMatchObject({
    status: "complete",
    counts: { created: 101 },
    unacknowledged: 0,
    verified: 101,
  });
  expect(f.posts).toHaveLength(3);
  expect(f.posts[2]).toBe(f.posts[1]);
});

test("readback retry preserves acknowledged findings and scanner diagnostics", async () => {
  const input = opengrepJson();
  const f = await fixture(input);
  f.state.brokenReadback = true;
  const settings = {
    ...options,
    provider: "opengrep" as const,
    sourceRepositoryUrl: f.destination().url,
  };
  const prepared = await prepareExternalPublication(f.file, settings, f.deps);
  try {
    await prepared.publish();
    throw new Error("Expected readback interruption");
  } catch (error) {
    if (!(error instanceof ExternalPublicationError)) throw error;
    expect(error.result).toMatchObject({
      status: "interrupted",
      counts: { created: 1 },
      unacknowledged: 0,
      verified: 0,
    });
    (error.result.report!["errors"] as unknown[]).pop();
  }
  const changed = structuredClone(input);
  changed.errors[0]!.message = "A different scanner diagnostic";
  await writeFile(f.file, JSON.stringify(changed));
  const different = await prepareExternalPublication(f.file, settings, f.deps);
  expect(different.preview.resumed).toBe(false);
  expect(different.preview.report?.["errors"]).toEqual(changed.errors);
  await writeFile(f.file, JSON.stringify(input));
  const original = await prepareExternalPublication(f.file, settings, f.deps);
  expect(original.preview.resumed).toBe(true);
  f.state.brokenReadback = false;
  const retried = await original.publish();
  expect(retried.report?.["errors"]).toEqual(input.errors);
  expect(retried.verified).toBe(1);
  expect(f.posts).toHaveLength(1);
});

test("each discovery page requests the repository and refreshes its private import capabilities", async () => {
  const f = await fixture(blackDuckBomReport());
  const repository = `${f.destination().url}.git`;
  const queries: URLSearchParams[] = [];
  const prepared = await prepareExternalPublication(
    f.file,
    {
      ...options,
      repository,
      provider: "blackduck",
      sourceRepositoryUrl: f.destination().url,
    },
    {
      ...f.deps,
      fetch: async (input, init) => {
        const url = new URL(input);
        if (!url.pathname.endsWith("/repositories"))
          return f.deps.fetch(input, init);
        queries.push(url.searchParams);
        const first = queries.length === 1;
        return Response.json(
          {
            object: "page",
            data: first ? [] : [f.destination()],
            has_more: first,
            next: first ? "next-page" : null,
          },
          {
            headers: first
              ? {
                  "Codex-Security-Private-Import-Job-Version": "3",
                  "Codex-Security-Private-Import-Providers": "blackduck",
                }
              : {},
          },
        );
      },
    },
  );
  expect(prepared.preview.privateImport).toBeUndefined();
  expect(prepared.preview.destination.id).toBe(options.repository);
  expect(queries.map((query) => query.get("repository"))).toEqual([
    repository,
    repository,
  ]);
  expect(queries.map((query) => query.get("page"))).toEqual([
    null,
    "next-page",
  ]);
  expect(f.posts).toHaveLength(0);
});

test("repository URLs and IDs share the same resumable destination", async () => {
  const f = await fixture();
  f.state.loseResponse = true;
  const first = await prepareExternalPublication(
    f.file,
    { ...options, repository: `${f.destination().url}.git` },
    f.deps,
  );
  expect(first.preview.destination.id).toBe(options.repository);
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  const retry = await prepareExternalPublication(f.file, options, f.deps);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).status).toBe("complete");
  expect(f.posts[1]).toBe(f.posts[0]);
});

test("Cloud deployment routing covers every request and isolates saved retries", async () => {
  const f = await fixture();
  const cloudBase = "https://cloud.example.test/pilot/backend-api/aardvark";
  const requested: string[] = [];
  const deps = {
    ...f.deps,
    environment: {
      ...f.deps.environment,
      CODEX_SECURITY_CLOUD_BASE_URL: `${cloudBase}///`,
    },
    fetch: async (url: string, init: RequestInit) => {
      requested.push(url);
      expect(url.startsWith(`${cloudBase}/external/`)).toBe(true);
      return f.deps.fetch(url, init);
    },
  };
  f.state.brokenReadback = true;
  const prepared = await prepareExternalPublication(f.file, options, deps);
  expect(prepared.preview.cloudApiUrl).toBe(`${cloudBase}/external`);
  await expect(prepared.publish()).rejects.toThrow("resume the saved request");
  const otherDeployment = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    environment: {
      ...f.deps.environment,
      CODEX_SECURITY_CLOUD_BASE_URL:
        "https://other-cloud.example.test/backend-api/aardvark",
    },
  });
  expect(otherDeployment.preview.resumed).toBe(false);
  const retry = await prepareExternalPublication(f.file, options, deps);
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.requests).toEqual(prepared.preview.requests);
  f.state.brokenReadback = false;
  const result = await retry.publish();
  expect(result.cloudApiUrl).toBe(`${cloudBase}/external`);
  expect(result.cloudUrl).toBeUndefined();
  expect(result.verified).toBe(1);
  expect(f.posts).toHaveLength(1);
  expect(requested.some((url) => url.includes("/repositories?"))).toBe(true);
  expect(requested.some((url) => url.includes("/source_reports?"))).toBe(true);
  expect(requested.some((url) => url.endsWith("/finding_imports"))).toBe(true);
  expect(requested.some((url) => url.includes("/source_reports/"))).toBe(true);
  expect(requested.some((url) => url.includes("/external/v2/"))).toBe(false);
});

test.each(["localhost", "127.0.0.1", "127.0.0.2", "[::1]"])(
  "loopback Cloud APIs support local HTTP publication: %s",
  async (host) => {
    const f = await fixture();
    const cloudBase = `http://${host}:4200/backend-api/aardvark`;
    const prepared = await prepareExternalPublication(f.file, options, {
      ...f.deps,
      environment: {
        ...f.environment,
        CODEX_SECURITY_CLOUD_BASE_URL: cloudBase,
      },
      fetch: (url, init) => {
        expect(url.startsWith(`${cloudBase}/external/`)).toBe(true);
        return f.deps.fetch(url, init);
      },
    });
    expect((await prepared.publish()).status).toBe("complete");
    expect(f.posts).toHaveLength(1);
  },
);

test("a separate Cloud app URL follows the resolved repository without changing API routing", async () => {
  const f = await fixture();
  const requested: string[] = [];
  const environment = {
    ...f.environment,
    CODEX_SECURITY_CLOUD_BASE_URL:
      "https://api.example.test/backend-api/aardvark",
    CODEX_SECURITY_CLOUD_WEB_URL:
      "http://localhost:4200/security?preview=true#/old",
  };
  const prepared = await prepareExternalPublication(
    f.file,
    { ...options, repository: f.destination().url },
    {
      ...f.deps,
      environment,
      fetch: (url, init) => {
        requested.push(url);
        return f.deps.fetch(url, init);
      },
    },
  );
  const link = `http://localhost:4200/security?preview=true#/repositories/${options.repository}/findings`;
  expect(prepared.preview.cloudUrl).toBe(link);
  expect((await prepared.publish()).cloudUrl).toBe(link);
  expect(
    requested.every((url) =>
      url.startsWith(environment.CODEX_SECURITY_CLOUD_BASE_URL),
    ),
  ).toBe(true);

  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      f.command
        .filter((value) => !["--format", "json"].includes(value))
        .concat("--yes"),
      { ...f.cliDeps, environment },
    ),
  ).toBe(0);
  expect(cli.stdout.text()).toContain(`View Cloud repository: ${link}`);
});

test.each([
  "",
  "/relative",
  "file:///tmp/cloud",
  "https://user:password@example.test",
])(
  "invalid Cloud app URL fails before authentication or network: %s",
  async (url) => {
    const f = await fixture();
    let calls = 0;
    await expect(
      prepareExternalPublication(f.file, options, {
        ...f.deps,
        environment: { ...f.environment, CODEX_SECURITY_CLOUD_WEB_URL: url },
        credentials: async () => {
          calls++;
          throw new Error("Unexpected auth");
        },
        fetch: async () => {
          calls++;
          throw new Error("Unexpected network");
        },
      }),
    ).rejects.toThrow("CODEX_SECURITY_CLOUD_WEB_URL");
    expect(calls).toBe(0);
  },
);

test.each([
  "",
  "  ",
  "/relative",
  "file:///tmp/cloud",
  "https://user:password@cloud.example.test",
  "https://cloud.example.test?deployment=pilot",
  "https://cloud.example.test#pilot",
  "http://cloud.example.test/backend-api/aardvark",
  "http://127.example.test/backend-api/aardvark",
  "http://192.0.2.1/backend-api/aardvark",
])(
  "invalid Cloud base URL fails before authentication or network: %s",
  async (baseUrl) => {
    const f = await fixture();
    let calls = 0;
    await expect(
      prepareExternalPublication(f.file, options, {
        ...f.deps,
        environment: {
          ...f.deps.environment,
          CODEX_SECURITY_CLOUD_BASE_URL: baseUrl,
        },
        credentials: async () => {
          calls++;
          throw new Error("Unexpected credential read");
        },
        fetch: async () => {
          calls++;
          throw new Error("Unexpected network request");
        },
      }),
    ).rejects.toThrow("CODEX_SECURITY_CLOUD_BASE_URL");
    expect(calls).toBe(0);
  },
);

test("read lookups and verification run concurrently with bounded requests and ordered input", async () => {
  const f = await fixture(
    Array.from({ length: 9 }, (_, i) => normalized(`vendor-${i}`)),
  );
  const phases: ExternalPublicationProgress[] = [];
  let active = 0;
  let maximum = 0;
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    onProgress: (event) => phases.push(event),
    fetch: async (url, init) => {
      if (!url.includes("/source_reports")) return f.deps.fetch(url, init);
      active++;
      maximum = Math.max(maximum, active);
      try {
        await Promise.resolve();
        return await f.deps.fetch(url, init);
      } finally {
        active--;
      }
    },
  });
  expect(
    prepared.preview.requests.flatMap((batch) =>
      batch.items.map((item) => item.source_finding_id),
    ),
  ).toEqual(Array.from({ length: 9 }, (_, i) => `vendor-${i}`));
  expect((await prepared.publish()).status).toBe("complete");
  expect(maximum).toBeGreaterThan(1);
  expect(maximum).toBeLessThanOrEqual(4);
  expect(active).toBe(0);
  for (const phase of ["preparing", "uploading", "verifying"])
    expect(
      phases.filter((event) => event.phase === phase).at(-1),
    ).toMatchObject({ completed: 9, total: 9 });
});

test("progress is optional and stderr progress never corrupts JSON results", async () => {
  const f = await fixture();
  const phases = new Set<ExternalPublicationProgress["phase"]>();
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    onProgress: ({ phase }) => {
      phases.add(phase);
      if (phase === "reading")
        return Promise.reject(new Error("Optional async observer failed"));
      throw new Error("Optional observer failed");
    },
  });
  expect((await prepared.publish()).status).toBe("complete");
  expect([...phases]).toEqual([
    "reading",
    "discovering",
    "preparing",
    "waiting",
    "uploading",
    "verifying",
  ]);
  const cli = createCliTest(main, { stderr: true });
  expect(await cli.runCli([...f.command, "--yes"], f.cliDeps)).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    status: "complete",
    counts: { unchanged: 1 },
  });
  expect(cli.stderr.text()).toContain("Preparing findings");
  expect(cli.stderr.text()).toContain("Verifying source records: 1/1");
});

test("human previews stay compact while JSON previews retain complete evidence", async () => {
  const records = Array.from({ length: 6 }, (_, i) => ({
    ...normalized(`vendor-${i}`),
    evidence: {
      ...normalized().evidence,
      source_data: { detail: `complete-vendor-evidence-${i}` },
    },
  }));
  const f = await fixture(records);
  const human = createCliTest(main);
  expect(
    await human.runCli([...f.command.slice(0, -2), "--dry-run"], f.cliDeps),
  ).toBe(0);
  expect(human.stderr.text()).toContain("Showing 5 of 6 findings");
  expect(human.stderr.text()).not.toContain("complete-vendor-evidence-");
  expect(human.stdout.text()).not.toContain("request_id");
  const json = createCliTest(main);
  expect(await json.runCli([...f.command, "--dry-run"], f.cliDeps)).toBe(0);
  expect(JSON.parse(json.stdout.text()).findings).toHaveLength(6);
  expect(
    JSON.parse(json.stdout.text()).findings[5].evidence.source_data.detail,
  ).toBe("complete-vendor-evidence-5");
  expect(f.posts).toHaveLength(0);
});

test("normalized SDK publication preserves caller evidence and exclusion accounting", async () => {
  const f = await fixture();
  const input = {
    read: 2,
    findings: [normalized()],
    excluded: [
      {
        position: 2,
        source_finding_id: null,
        reason: "Unsupported source record.",
      },
    ],
  };
  const original = structuredClone(input);
  const prepared = await prepareNormalizedExternalPublication(
    input as Parameters<typeof prepareNormalizedExternalPublication>[0],
    Object.create(options) as typeof options,
    f.deps,
  );
  expect(input).toEqual(original);
  expect(prepared.preview.read).toBe(2);
  const result = await prepared.publish();
  expect(result.status).toBe("partial");
  expect(result.counts.created).toBe(1);
  expect(result.excluded).toEqual(input.excluded);
  expect(result.verified).toBe(1);
});

test("GitHub publication previews, imports, re-imports, updates and resumes selected-ref evidence", async () => {
  const imported = importedAlert();
  const f = await fixture([imported]);
  const githubOptions = {
    ...options,
    provider: "github" as const,
    sourceKey: "github.com/example/project/code-scanning",
  };
  const command = f.command.map((arg) =>
    arg === "wiz"
      ? "github"
      : arg === options.sourceKey
        ? githubOptions.sourceKey
        : arg,
  );
  const cli = createCliTest(main);
  expect(
    await cli.runCli([...command, "--dry-run", "--format", "json"], f.cliDeps),
  ).toBe(0);
  expect(f.posts).toHaveLength(0);
  expect(JSON.parse(cli.stdout.text()).source.provider).toBe("github");
  const first = await (
    await prepareExternalPublication(f.file, githubOptions, f.deps)
  ).publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  const repeated = await (
    await prepareExternalPublication(f.file, githubOptions, f.deps)
  ).publish();
  expect(repeated.counts.unchanged).toBe(1);
  imported.alert.most_recent_instance.state = "fixed";
  await writeFile(f.file, JSON.stringify([imported]));
  f.state.loseResponse = true;
  await expect(
    (await prepareExternalPublication(f.file, githubOptions, f.deps)).publish(),
  ).rejects.toBeInstanceOf(ExternalPublicationError);
  const prepared = await prepareExternalPublication(
    f.file,
    githubOptions,
    f.deps,
  );
  expect(prepared.preview.resumed).toBe(true);
  const resumed = await prepared.publish();
  expect(resumed.counts.updated).toBe(1);
  expect(resumed.verified).toBe(1);
  expect([...f.reports.values()][0]).toMatchObject({
    source: { provider: "github" },
    evidence: { details: { source_status: "fixed" }, source_data: imported },
    assessment: { state: "not_assessed" },
  });
  await writeFile(f.file, JSON.stringify([importedAlert("refs/heads/review")]));
  const differentRef = await (
    await prepareExternalPublication(f.file, githubOptions, f.deps)
  ).publish();
  expect(differentRef.counts.created).toBe(1);
  expect(f.reports.size).toBe(2);
});

test.each([
  ["code scanning", () => normalizeGitHubCodeScanningAlerts([importedAlert()])],
  [
    "repository advisory",
    () => normalizeGitHubAdvisories([importedAdvisory()]),
  ],
] as const)(
  "the retained GitHub %s export binds its SDK projection to the original repository",
  async (_, make) => {
    const input = make();
    const evidence = input.findings[0]!.evidence;
    const f = await fixture(undefined, otherRepository);
    const prepare = () =>
      prepareNormalizedExternalPublication(
        input,
        { ...options, provider: "github" },
        f.deps,
      );
    evidence.details!.repository!.url = otherRepository;
    await expect(prepare()).rejects.toThrow(
      "does not match the original GitHub finding",
    );
    delete evidence.details;
    await expect(prepare()).rejects.toThrow(
      "does not match the selected Cloud repository",
    );
    expect(f.posts).toHaveLength(0);

    f.state.repositoryUrl = exampleRepository;
    await f.loseResponse(await prepare());
    f.state.repositoryUrl = otherRepository;
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).verified).toBe(1);
    expect(f.posts[1]).toBe(f.posts[0]);
  },
);

test("GitHub imports reject a different Cloud destination before uploading", async () => {
  const imported = importedAlert("refs/heads/main", "git.example.test");
  const f = await fixture([imported]);
  await expect(
    prepareExternalPublication(
      f.file,
      { ...options, provider: "github" },
      f.deps,
    ),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(0);
});

test("global GHSA publication retains unassessed applicability through repeat import and withdrawal", async () => {
  const imported = importedAdvisory("global");
  const f = await fixture([imported]);
  const selected = {
    ...options,
    provider: "github" as const,
    sourceKey: "github.com/example/project/security-advisories",
  };
  expect(
    (
      await (
        await prepareExternalPublication(f.file, selected, f.deps)
      ).publish()
    ).counts.created,
  ).toBe(1);
  expect(
    (
      await (
        await prepareExternalPublication(f.file, selected, f.deps)
      ).publish()
    ).counts.unchanged,
  ).toBe(1);
  const withdrawn = {
    ...imported,
    advisory: { ...imported.advisory, withdrawn_at: "2026-01-03T00:00:00Z" },
  };
  await writeFile(f.file, JSON.stringify([withdrawn]));
  const result = await (
    await prepareExternalPublication(f.file, selected, f.deps)
  ).publish();
  expect(result.counts.updated).toBe(1);
  expect(result.verified).toBe(1);
  const report = [...f.reports.values()][0]!;
  expect(report.evidence.details).toMatchObject({
    kind: "advisory",
    advisory: { source: "global" },
    source_status: "withdrawn",
  });
  expect(report.evidence.details).not.toHaveProperty("repository");
  expect(report.assessment?.state).toBe("not_assessed");
  expect(report.evidence.packages![0]!.installed_version).toBeNull();
});

test("saved GitHub JSONL and gzip preserve evidence while malformed UTF-8 cannot change identities", async () => {
  const imported = [importedAlert(), importedAdvisory("global")];
  const f = await fixture(imported);
  const jsonl = imported.map((record) => JSON.stringify(record)).join("\n");
  for (const bytes of [Buffer.from(jsonl), gzipSync(jsonl)]) {
    await writeFile(f.file, bytes);
    const parsed = await readGitHubFindings(f.file);
    expect(parsed.read).toBe(2);
    expect(parsed.excluded).toEqual([]);
    expect(
      parsed.findings.map((finding) => finding.evidence.source_data) as unknown,
    ).toEqual(imported);
  }
  await writeFile(f.file, Buffer.from([0xff]));
  await expect(readGitHubFindings(f.file)).rejects.toThrow("UTF-8");
});

test("normalized publication omits only new null fields to match canonical Cloud readback", async () => {
  const f = await fixture();
  const evidence = {
    title: "Synthetic advisory without known package range",
    severity: "unknown" as const,
    packages: [
      {
        name: "example-package",
        vulnerable_version_range: null,
        installed_version: null,
      },
    ],
    details: {
      kind: "advisory" as const,
      repository: null,
      advisory: { source: "global" as const },
    },
  };
  const prepared = await prepareNormalizedExternalPublication(
    {
      read: 1,
      findings: [{ source_finding_id: "synthetic-global-advisory", evidence }],
      excluded: [],
    },
    options,
    f.deps,
  );
  const sent = prepared.preview.findings[0]!.evidence;
  expect(sent.packages![0]).not.toHaveProperty("vulnerable_version_range");
  expect(sent.packages![0]!.installed_version).toBeNull();
  expect(sent.details).not.toHaveProperty("repository");
  expect(evidence.details.repository).toBeNull();
  expect((await prepared.publish()).verified).toBe(1);

  await writeFile(
    f.file,
    JSON.stringify([
      {
        source_finding_id: "synthetic-sast",
        evidence: {
          title: "Synthetic SAST evidence",
          severity: "high",
          packages: [
            { name: "example-package", vulnerable_version_range: null },
          ],
          details: {
            kind: "sast",
            repository: { url: "https://github.com/example/project" },
            advisory: null,
          },
        },
      },
    ]),
  );
  const wiz = await prepareExternalPublication(f.file, options, f.deps);
  expect(wiz.preview.findings[0]!.evidence.details).not.toHaveProperty(
    "advisory",
  );
  expect(wiz.preview.findings[0]!.evidence.details!.scanner_origin).toBeNull();
  expect((await wiz.publish()).verified).toBe(1);
});

test("normalized SDK publication detaches raw evidence aliases before validating every finding", async () => {
  const f = await fixture();
  const sharedPackage = { name: "example-package" };
  const input = {
    read: 2,
    report: { package: sharedPackage },
    findings: [
      {
        source_finding_id: "shared-first",
        evidence: {
          title: "First report",
          severity: "high" as const,
          packages: [sharedPackage],
          source_data: { package: sharedPackage },
        },
      },
      {
        source_finding_id: "shared-second",
        evidence: {
          title: "Second report",
          severity: "high" as const,
          source_data: { earlier_package: sharedPackage },
        },
      },
    ],
    excluded: [],
  };
  const original = JSON.stringify(input);
  const prepared = await prepareNormalizedExternalPublication(
    input,
    options,
    f.deps,
  );
  expect(JSON.stringify(input)).toBe(original);
  expect(prepared.preview.report).toEqual({
    package: { name: "example-package" },
  });
  expect(prepared.preview.findings[0]!.evidence.source_data).toEqual({
    package: { name: "example-package" },
  });
  expect(prepared.preview.findings[1]!.evidence.source_data).toEqual({
    earlier_package: { name: "example-package" },
  });
  await writeFile(f.file, JSON.stringify(input.findings));
  const fromFile = await prepareExternalPublication(f.file, options, f.deps);
  expect(prepared.preview.findings).toEqual(fromFile.preview.findings);
});

test.each(["code-scanning", "advisory"])(
  "%s imports bind an explicit default port to the matching Cloud repository",
  async (family) => {
    const alert = importedAlert("refs/heads/main", "github.com:443");
    const advisory = importedAdvisory();
    advisory.githubHost = "github.com:443";
    advisory.url = advisory.advisory.html_url = advisory.url.replace(
      "github.com",
      advisory.githubHost,
    );
    const f = await fixture([family === "code-scanning" ? alert : advisory]);
    const selected = { ...options, provider: "github" as const };
    await expect(
      prepareExternalPublication(f.file, selected, f.deps),
    ).rejects.toThrow("does not match the selected Cloud repository");
    expect(f.posts).toHaveLength(0);
    const matching = {
      ...f.deps,
      fetch: async (url: string, init: RequestInit) => {
        const response = await f.deps.fetch(url, init);
        if (new URL(url).pathname.endsWith("/repositories")) {
          const body = await response.json();
          body.data[0].url = "https://github.com:443/example/project";
          return Response.json(body);
        }
        return response;
      },
    };
    const result = await (
      await prepareExternalPublication(f.file, selected, matching)
    ).publish();
    expect(result.counts.created).toBe(1);
    expect(result.verified).toBe(1);
  },
);

function scoredFindings(
  score: unknown,
  report?: Record<string, unknown>,
  aliasSelection = false,
) {
  const evidence = {
    title: "Scanner score",
    severity: "high" as const,
    source_data: { score },
  };
  return {
    read: 1,
    excluded: [],
    findings: [
      {
        source_finding_id: "boxed-score",
        selection: aliasSelection ? evidence : "security", // Hashed by older publishers but absent from requests.
        evidence,
      },
    ],
    report,
  };
}

type PublicationFixture = Awaited<ReturnType<typeof fixture>>;

// Historical filenames include the deployment. Use the one recorded in these fixtures.
function prepareReleased(
  f: PublicationFixture,
  input: ExternalFindings,
  selected: NormalizedExternalPublicationOptions = options,
) {
  return prepareNormalizedExternalPublication(input, selected, {
    ...f.deps,
    environment: {
      ...f.environment,
      CODEX_SECURITY_CLOUD_BASE_URL: undefined,
      CODEX_SECURITY_CLOUD_WEB_URL: undefined,
    },
  });
}

async function stageReleasedCheckpoint(
  f: PublicationFixture,
  {
    filename,
    requests,
    inputDigest,
    savedEvidenceDigest = inputDigest,
    accountId = boxedNumberCheckpoints.accountId,
  }: {
    filename: string;
    requests: readonly unknown[];
    inputDigest: string;
    savedEvidenceDigest?: string;
    accountId?: string;
  },
) {
  const directory = join(f.root, "state", "external-finding-publications");
  const path = join(directory, filename);
  const checkpoint = {
    accountId,
    requests,
    inputProjection: { inputDigest, savedEvidenceDigest },
  };
  const saved = JSON.stringify(checkpoint);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(path, saved, { mode: 0o600 });
  return { checkpoint, directory, path, saved };
}

// These filenames, request IDs and projections were recorded by the old SDK.
async function oldScoreApproval(field: string, stageApproval = true) {
  const f = await fixture();
  const { filename, requestId, inputProjection } =
    boxedNumberCheckpoints.cases.find((item) => item.field === field)!;
  const prepare = (
    score: unknown,
    report?: Record<string, unknown>,
    flag?: unknown,
  ) => {
    const input = scoredFindings(score, report, field === "aliased");
    if (flag !== undefined)
      Object.assign(input.findings[0]!.evidence.source_data, { flag });
    return prepareReleased(f, input);
  };
  const request = {
    request_id: requestId,
    ...structuredClone(boxedNumberCheckpoints.request),
  };
  if (field === "flag") {
    request.items[0]!.expected_version = 0;
    Object.assign(request.items[0]!.evidence.source_data, {
      score: 12,
      flag: {},
    });
  } else {
    if (field === "empty-report")
      request.items[0]!.evidence.source_data.score = 12;
    await (await prepare(0)).publish(); // The old checkpoint approved an update.
    f.posts.length = 0;
  }
  const directory = join(f.root, "state", "external-finding-publications");
  const path = join(directory, filename);
  const saved = JSON.stringify({
    accountId: boxedNumberCheckpoints.accountId,
    requests: [request],
    inputProjection,
  });
  if (stageApproval) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(path, saved, { mode: 0o600 });
  }
  return { f, prepare, directory, path, filename, request, saved };
}

test.each(["invalid title", "unsafe number", "cross-realm serializer error"])(
  "a fresh %s can only publish its verified older request",
  async (kind) => {
    const { f, path, saved, request } = await oldScoreApproval(
      "evidence",
      false,
    );
    const score = new Number(2.5);
    const selected = scoredFindings(score);
    if (kind === "cross-realm serializer error") {
      Object.defineProperty(score, "toJSON", {
        value: runInNewContext(
          '() => { throw new TypeError("invalid metric") }',
        ),
      });
    } else if (kind === "unsafe number") {
      Object.defineProperty(score, "toJSON", { value: () => 2 ** 53 });
    } else {
      Object.setPrototypeOf(selected.findings[0]!.evidence, {
        toJSON(this: Record<string, unknown>) {
          return { ...this, title: "" };
        },
      });
    }
    const prepare = () => prepareReleased(f, selected);
    await expect(prepare()).rejects.toThrow();
    expect(f.posts).toHaveLength(0);
    await writeFile(path, saved, { mode: 0o600 });
    const recovered = await prepare();
    expect(recovered.preview.resumed).toBe(true);
    await recovered.publish();
    expect(f.posts).toEqual([JSON.stringify(request)]);
  },
);

test.each(["deep shared data", "cycle", "row BigInt"])(
  "a compact export remains publishable with an unusable native %s",
  async (kind) => {
    const f = await fixture();
    const input = scoredFindings(4);
    if (kind === "row BigInt") {
      Object.assign(input.findings[0]!, {
        cursor: Object.assign(Object(17n), { toJSON: () => "17" }),
      });
    } else {
      class Compact {
        constructor(readonly content: unknown) {}
        toJSON() {
          return 4;
        }
      }
      let content: unknown = {};
      if (kind === "cycle") Object.assign(content as object, { self: content });
      else for (let n = 0; n < 24; n++) content = [content, content];
      input.findings[0]!.evidence.source_data.score = new Compact(content);
    }
    const preview = await prepareReleased(f, input);
    expect(preview.preview.resumed).toBe(false);
    await preview.publish();
    expect(JSON.parse(f.posts[0]!).items[0].evidence.source_data.score).toBe(4);
  },
);

test.each(["getter", "data property"])(
  "a JSON hook cannot replace a %s score to match a released approval",
  async (kind) => {
    const { f, path, saved } = await oldScoreApproval("evidence");
    const input = scoredFindings(undefined);
    const data = input.findings[0]!.evidence.source_data;
    const score = Object.assign(new Number(8), {
      toJSON() {
        Object.defineProperty(data, "score", { value: new Number(2.5) });
        return 9;
      },
    });
    if (kind === "getter")
      Object.defineProperty(data, "score", {
        configurable: true,
        enumerable: true,
        get: () => score,
      });
    else data.score = score;

    await expect(prepareReleased(f, input)).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe(saved);
    expect(f.posts).toHaveLength(0);
  },
);

test("a shared mutation across two GitHub alerts preserves their released approval", async () => {
  const f = await fixture();
  const prepare = () => {
    const counter = { n: new Number(0) };
    const first = {
      get sample() {
        counter.n = new Number(Number(counter.n) + 1);
        return counter.n;
      },
      counter,
    };
    class Metrics {
      score = Object.assign(new Number(7), { toJSON: () => 9 });
      counter = counter;
    }
    const rows = [first, new Metrics()].map((extension, i) => {
      const row = importedAlert();
      row.number = row.alert.number = 12 + i;
      row.url = row.alert.html_url = row.url.replace(/12$/, String(row.number));
      Object.assign(row.alert, { extension });
      return row;
    });
    return prepareReleased(f, normalizeGitHubCodeScanningAlerts(rows), {
      ...options,
      provider: "github",
    });
  };

  const request = JSON.parse(
    JSON.stringify((await prepare()).preview.requests[0]),
  );
  const first = request.items[0].evidence.source_data.alert.extension;
  const second = request.items[1].evidence.source_data.alert.extension;
  expect([first.counter.n, second.counter.n, second.score]).toEqual([1, 1, 9]);
  // The released publisher captured both alerts after three getter reads.
  first.sample = first.counter.n = second.counter.n = 3;
  second.score = 7;
  request.request_id = "035de7b2-7e71-4166-be9a-99ae1251217b";
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "8ce6e5a6d4be2062a39ba7325554f7849096b472a67ae1672fd614c681db9a37",
  );
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "a7b6eecd18536c47e5bcd5e1db25a45b3faca1715eab39e2884b06bf67b1e62f.pending.json",
    requests: [request],
    inputDigest:
      "1fa6cbfd77fccdeec029930585f46595118e9f95b8083480239ac50176fb9a52",
  });

  await expect(prepare()).rejects.toThrow("cannot be matched");
  expect(f.posts).toHaveLength(0);
  expect(await readFile(path, "utf8")).toBe(saved);
});

test("a Sonar report resumes its released request after a size change", async () => {
  const { normalizeSonarFindings: normalize } =
    await import("../src/sonar-findings.js");
  const repository = "https://github.com/example/project";
  const issue = {
    key: "issue-one",
    project: "example",
    component: "example:one",
    rule: "example:S1",
    message: "Synthetic finding",
    type: "VULNERABILITY",
  };
  const boundary = {
    ...issue,
    key: "issue-two",
    score: new Number(0.00001),
    pad: "",
  };
  const raw = {
    paging: { pageIndex: 1, pageSize: 10, total: 2 },
    issues: [issue, boundary],
  };
  const base = normalize(raw, repository);
  boundary.pad = "p".repeat(
    262_145 - Buffer.byteLength(JSON.stringify(base.findings[1]!.evidence)),
  );
  const selection = normalize(raw, repository);
  const f = await fixture();
  const selected = { ...options, provider: "sonar" as const };
  const prepare = () => prepareReleased(f, selection, selected);
  const fresh = await prepare();
  expect(fresh.preview.findings.map((row) => row.source_finding_id)).toEqual([
    "issue-one",
    "issue-two",
  ]);
  // The earlier SDK approved only the first issue and retained the Sonar report.
  const batch = fresh.preview.requests[0]!;
  const request = {
    ...batch,
    request_id: "bd9002e4-5abe-469b-ad2d-a64514f82e1b",
    items: [batch.items[0]!],
  };
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "e6bc41119d363155e2d2388985ce3b476dfd3c6898297b5154a9b09ab192ac95",
  );
  await stageReleasedCheckpoint(f, {
    filename:
      "bb2529dff62d8c9bb1c064d18f2b649c412b3d310914a8d4221c115a00f71e4c.pending.json",
    requests: [request],
    inputDigest:
      "62f0d447578728d3c8afa0ebfa0d1a2d8d7ab5c9d1a96af2855508bc5e6da986",
    savedEvidenceDigest:
      "25716f8958e0b38376fe5fdaad85b648ca3b0ed23a86c37a246a1537a75c848d",
  });
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.report).toEqual(selection.report);
  expect(retry.preview.findings.map((row) => row.source_finding_id)).toEqual([
    "issue-one",
  ]);
  expect((await retry.publish()).verified).toBe(1);
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test("an uncertain newly eligible advisory cannot replace a released subset", async () => {
  const f = await fixture();
  const selected = { ...options, provider: "github" as const };
  const prepare = (rows: ReturnType<typeof importedAdvisory>[]) =>
    prepareReleased(f, normalizeGitHubAdvisories(rows), selected);
  const first = importedAdvisory();
  const id = "GHSA-abcd-efgh-5678";
  const url = first.url.replace(first.ghsaId, id);
  const second = {
    ...first,
    ghsaId: id,
    url,
    advisory: { ...first.advisory, ghsa_id: id, html_url: url },
  };
  const value = Object.assign(new Number(7), { bad: Infinity });
  Object.defineProperty(second.advisory, "score", {
    enumerable: true,
    get: () => value,
  });
  expect(normalizeGitHubAdvisories([first, second]).findings).toHaveLength(2);

  const request = {
    ...(await prepare([first])).preview.requests[0]!,
    request_id: "58b468b5-45c6-4804-8f5a-5e2919c967c5",
  };
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "19039224ccc25a9375739c7f16227a26e9fd92cf900de1a32425c20c94697488",
  );
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "6137d904632ecb17ecdf0276e37794699ff19f6e37f6a89b833b56ec0a7c953b.pending.json",
    requests: [request],
    inputDigest:
      "fbba527f5ff2cf86972d97f543de935515cbaa618ab2f1168ddbb3d1ab3ea338",
  });

  await expect(prepare([first, second])).rejects.toThrow("cannot be matched");
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toEqual([]);
  expect((await (await prepare([first])).publish()).receipts[0]!.id).toBe(
    request.request_id,
  );
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test("an ambiguous getter cannot start another import after a released approval was matched", async () => {
  const { f, prepare, path, request } = await oldScoreApproval("evidence");
  const score = Object.assign(new Number(2.5), { toJSON: () => 9 });
  f.state.throttle = true;
  await expect((await prepare(score)).publish()).rejects.toThrow("Slow down");
  const pending = await readFile(path, "utf8");
  f.state.throttle = false;

  const input = scoredFindings(undefined);
  Object.defineProperty(input.findings[0]!.evidence.source_data, "score", {
    enumerable: true,
    get: () => score,
  });
  const publish = async () => (await prepareReleased(f, input)).publish();
  await expect(publish()).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(pending);
  expect(f.posts).toEqual([JSON.stringify(request)]);

  const retry = await prepare(score);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request), JSON.stringify(request)]);
});

test("a fresh boxed approval cannot claim a different getter-backed JSON import", async () => {
  const { f, prepare } = await oldScoreApproval("evidence", false);
  f.state.throttle = true;
  const first = await prepare(new Number(1));
  await expect(first.publish()).rejects.toThrow("Slow down");
  const input = scoredFindings(undefined);
  Object.defineProperty(input.findings[0]!.evidence.source_data, "score", {
    enumerable: true,
    get: () => 2,
  });
  const second = await prepareReleased(f, input);
  expect(second.preview.resumed).toBe(false);
  expect(second.preview.requests[0]!.request_id).not.toBe(
    first.preview.requests[0]!.request_id,
  );
  expect(second.preview.requests[0]!.items[0]!.evidence.source_data).toEqual({
    score: 2,
  });
  expect(f.posts).toEqual([JSON.stringify(first.preview.requests[0])]);
});

test("a root serializer cannot add a report to distinguish a released approval", async () => {
  const { f, request } = await oldScoreApproval("unreported", false);
  const { source_finding_id, evidence } = scoredFindings(2.5).findings[0]!;
  class ScannerBatch {
    read = 1;
    excluded = [];
    findings = [{ source_finding_id, evidence }];
    reportForJson() {
      return { version: "1" };
    }
    toJSON() {
      return { ...this, report: this.reportForJson() };
    }
  }
  const input = new ScannerBatch();
  const prepare = () => prepareReleased(f, input);
  const held = await prepare();
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "29fc89c807be65a8b3a173feeb64e86595e3debbdb91dc00b1a9cfb6eea869cc.pending.json",
    requests: [
      { ...request, request_id: "7e77248b-2906-44a7-b467-5225966ac7a2" },
    ],
    inputDigest:
      "875a8aec2f1b7c573a6d05d983f6afa0f964a6e1c96d22c8c8691cc2de824ccc",
  });
  await expect(prepare()).rejects.toThrow("cannot be matched");
  await expect(held.publish()).rejects.toThrow("cannot be matched");
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toEqual([]);
  const independent = await prepareReleased(f, {
    ...input,
    report: input.reportForJson(),
  });
  expect(independent.preview.resumed).toBe(false);
});

test("a finding serializer cannot replace the ID of an older approval", async () => {
  const { f, path, saved } = await oldScoreApproval("unreported");
  const input = scoredFindings(2.5);
  const stored = input.findings[0]!;
  const prepare = () => prepareReleased(f, input);
  class ScannerFinding {
    exportedId() {
      return "exported-id";
    }
    toJSON() {
      return { ...stored, source_finding_id: this.exportedId() };
    }
  }
  const finding = Object.assign(new ScannerFinding(), stored);
  input.findings[0] = finding;
  await expect(prepare()).rejects.toThrow("cannot be matched");
  let idReads = 0;
  Object.defineProperty(finding, "source_finding_id", {
    enumerable: true,
    get() {
      idReads++;
      return stored.source_finding_id;
    },
  });
  await expect(prepare()).rejects.toThrow("cannot be matched");
  expect(idReads).toBe(0);
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toEqual([]);

  input.findings[0] = { ...stored, source_finding_id: "independent-id" };
  Object.defineProperty(input.findings[0].evidence.source_data, "score", {
    enumerable: true,
    get: () => 2.5,
  });
  expect((await prepare()).preview.resumed).toBe(false);
});

test("a vendor evidence class resumes its released title and exports its JSON title for a fresh import", async () => {
  class ScannerEvidence {
    title = "Scanner score";
    severity = "high" as const;
    source_data = { score: 2.5 };
    toJSON() {
      return { ...this, title: "New scanner score" };
    }
  }
  const { f, path, request, saved } = await oldScoreApproval("unreported");
  const input = scoredFindings(2.5);
  input.findings[0]!.evidence = new ScannerEvidence();
  const prepare = () => prepareReleased(f, input);
  // Without an independent native capture, the exported title cannot rule out this approval.
  class UncertainEvidence extends ScannerEvidence {
    exportedTitle() {
      return "Separate scanner title";
    }
    override toJSON() {
      return { ...this, title: this.exportedTitle() };
    }
  }
  input.findings[0]!.evidence = new UncertainEvidence();
  await expect(prepare()).rejects.toThrow("cannot be matched");
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toEqual([]);

  input.findings[0]!.evidence = {
    ...new ScannerEvidence(),
    title: "Separate scanner title",
  };
  expect((await prepare()).preview.resumed).toBe(false);
  input.findings[0]!.evidence = new ScannerEvidence();
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request)]);

  const fresh = await prepare();
  expect(fresh.preview.resumed).toBe(false);
  expect((await fresh.publish()).verified).toBe(1);
  expect(JSON.parse(f.posts[1]!).items[0].evidence.title).toBe(
    "New scanner score",
  );
});

test("a shared rule in report metadata resumes the released request", async () => {
  const f = await fixture();
  const rule = { name: "example-rule" };
  const input = scoredFindings(new Number(2.5), { rule });
  Object.assign(input.findings[0]!.evidence, {
    details: { kind: "sast", repository: { url: f.destination().url }, rule },
  });
  const prepare = () => prepareReleased(f, input);
  const request = {
    ...(await prepare()).preview.requests[0]!,
    request_id: "0697e266-e0a5-4aa5-b30b-3b89cbd48ac1",
  };
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "8c76780e8aca7582a293dee9483002401d6907e51833fc806cd1a058fe54b855",
  );
  await stageReleasedCheckpoint(f, {
    filename:
      "749e46bc07036abe74f047011264147993bd96f384099bcf1b729c8c2634a1b0.pending.json",
    requests: [request],
    inputDigest:
      "49cf7aa8362d8967c5638238b719d925e7e1814d48a4a7a0844e69ef9260b869",
    savedEvidenceDigest:
      "a2d3adb20cf97c597828fd54ec361490a8a34e479a42d01d3b85ff245b0b384b",
  });

  const resumed = await prepare();
  expect(resumed.preview.resumed).toBe(true);
  expect((await resumed.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test("a boxed JSON hook keeps the released request and applies to fresh normalized publication", async () => {
  const { f, prepare, path, request, saved } =
    await oldScoreApproval("evidence");
  const score = (native: number) =>
    Object.assign(new Number(native), { toJSON: () => 9 });

  await expect(prepare(score(8))).rejects.toThrow();
  for (const plain of [2.5, JSON.parse(JSON.stringify(score(2.5))), "7.00"])
    await expect(prepare(plain)).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toHaveLength(0);

  f.state.brokenReadback = true;
  const migrated = await prepare(new Number(2.5));
  await expect(migrated.publish()).rejects.toThrow("Readback unavailable");
  f.state.brokenReadback = false;
  const resumed = await prepare(score(2.5));
  expect(resumed.preview.resumed).toBe(true);
  expect((await resumed.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request)]);

  const ordinary = await prepare(new Number(2.5));
  f.state.brokenReadback = true;
  await expect(ordinary.publish()).rejects.toThrow("Readback unavailable");
  const pending = await readFile(path, "utf8");
  await expect(prepare(score(2.5))).rejects.toThrow("Finish the other pending");
  expect(await readFile(path, "utf8")).toBe(pending);
  f.state.brokenReadback = false;
  expect((await (await prepare(2.5)).publish()).receipts[0]!.id).toBe(
    ordinary.preview.requests[0]!.request_id,
  );
  expect(f.posts).toEqual([
    JSON.stringify(request),
    JSON.stringify(ordinary.preview.requests[0]),
  ]);
  const fresh = await prepare(score(2.5));
  expect(fresh.preview.resumed).toBe(false);
  expect((await fresh.publish()).verified).toBe(1);
  expect(JSON.parse(f.posts[2]!).items[0].evidence.source_data).toEqual({
    score: 9,
  });
});

test.each([
  { field: "evidence", native: 2.5, report: undefined },
  { field: "empty-report", native: 12, report: {} },
])(
  "a released $field approval stays on its original deployment",
  async ({ field, native, report }) => {
    const { f, path, saved, request } = await oldScoreApproval(field);
    const input = scoredFindings(
      Object.assign(new Number(native), { toJSON: () => 9 }),
      report,
    );
    if (report) {
      class SourceData {
        score = new Number(native);
        toJSON() {
          return { score: 9 };
        }
      }
      input.findings[0]!.evidence.source_data = new SourceData();
    }
    const other = await prepareNormalizedExternalPublication(input, options, {
      ...f.deps,
      environment: {
        ...f.environment,
        CODEX_SECURITY_CLOUD_BASE_URL: "https://other.example.test/backend-api",
        CODEX_SECURITY_CLOUD_WEB_URL: "https://other.example.test",
      },
    });
    expect(other.preview.resumed).toBe(false);
    expect(other.preview.requests[0]!.request_id).not.toBe(request.request_id);
    expect(other.preview.requests[0]!.items[0]!.evidence.source_data).toEqual({
      score: 9,
    });
    expect(f.posts).toHaveLength(0);
    expect(await readFile(path, "utf8")).toBe(saved);
  },
);

test("an opaque retry cannot choose between independent old and new approvals", async () => {
  const {
    f,
    path: oldPath,
    saved,
    directory,
  } = await oldScoreApproval("unreported", false);
  const exported = scoredFindings(9);
  exported.findings[0]!.source_finding_id = "exported-row";
  const opaque = scoredFindings(2.5);
  const nativeRows = opaque.findings;
  Object.defineProperty(opaque, "findings", { get: () => nativeRows });
  Object.defineProperty(opaque, "toJSON", { value: () => exported });
  const prepare = (input: typeof opaque) => prepareReleased(f, input);

  const newer = await prepare(exported);
  const request = newer.preview.requests[0]!;
  const body = JSON.stringify(request);
  f.state.throttle = true;
  await expect(newer.publish()).rejects.toThrow("Slow down");
  const filename = (await readdir(directory)).find((name) =>
    name.endsWith(".pending.json"),
  )!;
  const newPath = join(directory, filename);
  const newerBytes = await readFile(newPath, "utf8");
  const held = await prepare(opaque);
  expect(held.preview.requests[0]!.request_id).toBe(request.request_id);
  f.state.throttle = false;
  await writeFile(oldPath, saved, { mode: 0o600 });

  await expect(prepare(opaque)).rejects.toThrow();
  await expect(held.publish()).rejects.toThrow();
  expect(f.posts).toEqual([body]);
  expect(await readFile(oldPath, "utf8")).toBe(saved);
  expect(await readFile(newPath, "utf8")).toBe(newerBytes);
  const approved = await prepare(exported);
  expect((await approved.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([body, body]);
  expect(await readFile(oldPath, "utf8")).toBe(saved);
});

test.each([false, true])(
  "a getter-backed approval stays scoped to its deployment (with report: %s)",
  async (reported) => {
    const f = await fixture();
    const finding = {
      source_finding_id: "synthetic-score",
      evidence: {
        title: "Score",
        severity: "high" as const,
        source_data: {
          get score() {
            return 2.5;
          },
        },
      },
    };
    const prepare = (host: string) =>
      prepareNormalizedExternalPublication(
        {
          read: 1,
          excluded: [],
          findings: [finding],
          report: reported ? { version: "1" } : undefined,
        },
        options,
        {
          ...f.deps,
          environment: {
            ...f.environment,
            CODEX_SECURITY_CLOUD_BASE_URL: `https://${host}.example.test/backend-api/aardvark`,
            CODEX_SECURITY_CLOUD_WEB_URL: `https://${host}.example.test`,
          },
        },
      );
    // Recorded with the released SDK on deployment one.
    const request = {
      ...(await prepare("one")).preview.requests[0]!,
      request_id: reported
        ? "afcc3987-d289-4b85-9e7c-8ff755ebb64b"
        : "bf6f1063-9647-43d8-82b9-982961522482",
    };
    const digest =
      "01ad76cac2893a22136a81e7e61aeef35edb7a51e97f2944713e744756362721";
    const { path, saved } = await stageReleasedCheckpoint(f, {
      filename: reported
        ? "66fdd41e29ebfe07ca8fe9e54689df0027301c08a19b8b17b82254aadb536b44.pending.json"
        : "b4eed57e616f2289bf467f18fba85e2e9ba305a360a798d9e9d8125b06e148fe.pending.json",
      requests: [request],
      inputDigest: reported
        ? "af3bca9d5d1b53284f6da3d32b4de04d196cf14f96a0b7a00711dcd6e90e896d"
        : digest,
      savedEvidenceDigest: digest,
    });
    expect((await prepare("one")).preview.requests).toEqual([request]);
    const independent = await prepare("two");
    expect(independent.preview.resumed).toBe(false);
    expect(independent.preview.requests[0]!.request_id).not.toBe(
      request.request_id,
    );
    expect((await independent.publish()).verified).toBe(1);
    expect(f.posts).toEqual([JSON.stringify(independent.preview.requests[0])]);
    expect(await readFile(path, "utf8")).toBe(saved);
  },
);

test.each([
  { first: "reported", reportedScore: 2.5 },
  { first: "report-free", reportedScore: 2.5 },
  { first: "reported", reportedScore: 7 },
])(
  "distinct released boxed approvals preserve both selections when $first resumes first (reported score $reportedScore)",
  async ({ first, reportedScore }) => {
    const { f, prepare, directory, path, request, saved } =
      await oldScoreApproval("evidence");
    // The released SDK used this report-bound digest for either boxed score.
    const reportedPath = join(
      directory,
      "ad28704f08feeeaf1adb30d1010204b8ac942fa0c215c5b4eabb4990d338f23a.pending.json",
    );
    const recorded = JSON.parse(saved);
    const reportedRequest = structuredClone(request);
    reportedRequest.request_id =
      reportedScore === 7
        ? "fdfa27bc-13f6-4c83-8abc-fc3619e3b512"
        : "ec3a5d47-b29e-493a-90ea-effa70148ef4";
    reportedRequest.items[0]!.evidence.source_data.score = reportedScore;
    recorded.requests = [reportedRequest];
    recorded.inputProjection.inputDigest =
      "53cc56f227da631bd73c1301c623b9d8c55aca65e03feb324808ae9c886ed1da";
    await writeFile(reportedPath, JSON.stringify(recorded), { mode: 0o600 });

    const reported = {
      report: { version: "1" },
      score: reportedScore,
      path: reportedPath,
      request: reportedRequest,
    };
    const plain = { report: undefined, score: 2.5, path, request };
    const order = first === "reported" ? [reported, plain] : [plain, reported];
    f.state.throttle = true;
    for (const selection of order) {
      const sibling = selection === reported ? plain : reported;
      const siblingBytes = await readFile(sibling.path, "utf8");
      const prepared = await prepare(
        new Number(selection.score),
        selection.report,
      );
      expect(prepared.preview.resumed).toBe(true);
      expect(prepared.preview.requests[0]!.request_id).toBe(
        selection.request.request_id,
      );
      await expect(prepared.publish()).rejects.toThrow("Slow down");
      expect(await readFile(sibling.path, "utf8")).toBe(siblingBytes);
    }
    expect(f.posts).toEqual(
      order.map((selection) => JSON.stringify(selection.request)),
    );
  },
);

function failCheckpointReads(unreadable: (path: string) => boolean) {
  const read = fs.readFile;
  return spyOn(fs, "readFile").mockImplementation((async (
    ...args: Parameters<typeof read>
  ) => {
    if (unreadable(String(args[0])))
      throw Object.assign(new Error("Unreadable checkpoint"), {
        code: "EACCES",
      });
    return read(...args);
  }) as typeof read);
}

test.each(["released", "fresh"])(
  "a primitive retry uses the lookup for a %s boxed approval without reading unrelated checkpoints",
  async (kind) => {
    const { f, prepare, directory, filename, path, request, saved } =
      await oldScoreApproval("evidence", kind === "released");
    const boxed = await prepare(new Number(2.5));
    const approved = boxed.preview.requests[0]!;
    if (kind === "released")
      expect(approved.request_id).toBe(request.request_id);
    f.state.brokenReadback = true;
    await expect(boxed.publish()).rejects.toThrow("Readback unavailable");
    const files = await readdir(directory);
    expect(files.filter((file) => file.endsWith(".pending.json"))).toEqual([
      filename,
    ]);
    const checkpoint = JSON.parse(await readFile(path, "utf8"));

    const unrelated = join(
      directory,
      `${hash("sha256", "another-account")}.pending.json`,
    );
    await writeFile(
      unrelated,
      JSON.stringify({ ...JSON.parse(saved), accountId: "another-account" }),
      { mode: 0o600 },
    );
    using reads = failCheckpointReads((path) => path === unrelated);
    f.state.brokenReadback = false;
    const retry = await prepare(2.5);
    expect(retry.preview.resumed).toBe(true);
    expect(JSON.stringify(retry.preview.requests)).toBe(
      JSON.stringify(boxed.preview.requests),
    );
    expect((await retry.publish()).receipts[0]!.id).toBe(approved.request_id);
    expect(f.posts).toEqual([JSON.stringify(approved)]);
    expect(files).toContain(`${checkpoint.wireKey}.lookup.json`);
    expect(reads.mock.calls.some(([file]) => String(file) === unrelated)).toBe(
      false,
    );
  },
);

test("the original boxed approval keeps its filename, request and receipts on a primitive retry", async () => {
  const { f, prepare, directory, path, filename, request, saved } =
    await oldScoreApproval("evidence");
  for (const score of [new Number(9.5), {}]) {
    await expect(prepare(score)).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe(saved);
  }
  expect(f.posts).toEqual([]);
  const recovered = await prepare(new Number(2.5));
  expect(recovered.preview.resumed).toBe(true);
  expect(JSON.stringify(recovered.preview.requests)).toBe(
    JSON.stringify([request]),
  );
  f.state.brokenReadback = true;
  const interrupted = await recovered
    .publish()
    .catch((error: unknown) => error);
  if (!(interrupted instanceof ExternalPublicationError)) throw interrupted;
  expect(interrupted.result.savedSubmission).toBe(path);
  const pending = (await readdir(directory)).filter((name) =>
    name.endsWith(".pending.json"),
  );
  expect(pending).toEqual([filename]);
  expect(JSON.parse(await readFile(path, "utf8")).receipts[0].id).toBe(
    request.request_id,
  );
  f.state.brokenReadback = false;
  const retry = await prepare(2.5);
  const sibling = await prepare(2.5);
  const stale = await prepare(2.5);
  expect(retry.preview.resumed).toBe(true);
  expect(JSON.stringify(retry.preview.requests)).toBe(
    JSON.stringify([request]),
  );
  // An older checkpoint at an unknown filename can appear after both retries were prepared.
  const unknown = join(
    directory,
    `${hash("sha256", "other-deployment")}.pending.json`,
  );
  const projectionless = JSON.stringify({
    accountId: boxedNumberCheckpoints.accountId,
    requests: [request],
  });
  await writeFile(unknown, projectionless, { mode: 0o600 });
  const result = await retry.publish();
  expect(result.verified).toBe(1);
  expect(result.receipts.map(({ id }) => id)).toEqual([request.request_id]);
  {
    using reads = spyOn(fs, "readFile");
    expect(await sibling.publish()).toEqual(result);
    expect(reads.mock.calls.map(([path]) => String(path))).not.toContain(
      unknown,
    );
  }
  expect(f.posts).toEqual([JSON.stringify(request)]);
  expect(await Bun.file(path).exists()).toBe(false);
  expect(await readFile(unknown, "utf8")).toBe(projectionless);
  await rm(unknown);

  // A later approval of the same input replaced the completed result.
  const fresh = await prepare(2.5);
  const replacement = await fresh.publish();
  expect(replacement.receipts[0]!.id).not.toBe(request.request_id);
  await expect(stale.publish()).rejects.toThrow(/another publication|review/i);
  expect(f.posts).toEqual([
    JSON.stringify(request),
    JSON.stringify(fresh.preview.requests[0]),
  ]);
  expect(await Bun.file(path).exists()).toBe(false);
});

test.each(["released", "current"])(
  "a known %s retry preserves its approval when unrelated checkpoints are unreadable",
  async (format) => {
    const released = format === "released";
    const { f, prepare, directory, request, path, saved } =
      await oldScoreApproval("unreported", released);
    f.state.throttle = true;
    for (const score of [1, 2, 3]) {
      await expect((await prepare(score)).publish()).rejects.toThrow(
        "Slow down",
      );
    }
    const unrelated = new Set(
      (await readdir(directory))
        .filter((name) => name.endsWith(".pending.json"))
        .map((name) => join(directory, name))
        .filter((candidate) => candidate !== path),
    );
    expect(unrelated.size).toBe(3);
    let requestId = request.request_id;
    if (released) {
      expect(await readFile(path, "utf8")).toBe(saved);
    } else {
      const selected = await prepare(2.5);
      requestId = selected.preview.requests[0]!.request_id;
      await expect(selected.publish()).rejects.toThrow("Slow down");
    }

    let unreadable = false;
    const statePaths = new Set([directory, await fs.realpath(directory)]);
    using listings = spyOn(fs, "readdir");
    using reads = failCheckpointReads(
      (path) => unreadable && unrelated.has(path),
    );
    const operations = () => ({
      listed: listings.mock.calls.some(([path]) =>
        statePaths.has(String(path)),
      ),
      readUnrelated: reads.mock.calls.some(([path]) =>
        unrelated.has(String(path)),
      ),
    });
    if (released) {
      const original = await prepare(2.5);
      reads.mockClear();
      listings.mockClear();
      await expect(original.publish()).rejects.toThrow("Slow down");
      expect(operations()).toEqual({ listed: true, readUnrelated: true });
      expect(f.posts.at(-1)).toBe(JSON.stringify(request));
    }
    unreadable = true;
    f.state.throttle = false;
    reads.mockClear();
    listings.mockClear();
    const retry = await prepare(2.5);
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests[0]!.request_id).toBe(requestId);
    expect(operations()).toEqual({ listed: false, readUnrelated: false });
    f.state.brokenReadback = true;
    await expect(retry.publish()).rejects.toThrow("Readback unavailable");
    const stored = JSON.parse(await readFile(path, "utf8"));
    expect(stored.receipts[0].id).toBe(requestId);
    if (released)
      expect(f.posts.slice(-2)).toEqual([
        JSON.stringify(request),
        JSON.stringify(request),
      ]);
    const posted = [...f.posts];
    f.state.brokenReadback = false;
    expect((await (await prepare(2.5)).publish()).receipts).toEqual(
      stored.receipts,
    );
    expect(f.posts).toEqual(posted);
    expect(operations()).toEqual({ listed: false, readUnrelated: false });
    listings.mockClear();
    reads.mockClear();
    // A fresh selection must discover possible historical approvals.
    await expect(prepare(4)).rejects.toThrow("Unreadable checkpoint");
    expect(operations()).toEqual({ listed: true, readUnrelated: true });
  },
);

test("a released receipt can finish readback when caching the checkpoint scan fails", async () => {
  const { f, prepare, path, saved, request } =
    await oldScoreApproval("unreported");
  f.state.brokenReadback = true;
  await expect((await prepare(2.5)).publish()).rejects.toThrow(
    "Readback unavailable",
  );
  const receipts = [f.receipts.get(request.request_id)!];
  const released = { ...JSON.parse(saved), receipts };
  await writeFile(path, JSON.stringify(released));

  const rename = fs.rename;
  using _writes = spyOn(fs, "rename").mockImplementation(async (from, to) => {
    if (String(to) === path) {
      const { canonicalChecked, ...pending } = JSON.parse(
        await readFile(from, "utf8"),
      );
      if (canonicalChecked && Bun.deepEquals(pending, released))
        throw Object.assign(new Error("No space for checkpoint metadata"), {
          code: "ENOSPC",
        });
    }
    return rename(from, to);
  });
  const retry = await prepare(2.5);
  expect(retry.preview.resumed).toBe(true);
  const interrupted = await retry.publish().catch((error: unknown) => error);
  if (!(interrupted instanceof ExternalPublicationError)) throw interrupted;
  expect(interrupted.result).toMatchObject({
    status: "interrupted",
    counts: { updated: 1 },
    receipts,
    unacknowledged: 0,
    savedSubmission: path,
  });
  expect(await readFile(path, "utf8")).toBe(JSON.stringify(released));
  f.state.brokenReadback = false;
  const completed = await (await prepare(2.5)).publish();
  expect(completed).toMatchObject({
    status: "complete",
    verified: 1,
    receipts,
  });
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test("checking a released canonical approval preserves ambiguous boxed report metadata", async () => {
  const { f, prepare } = await oldScoreApproval("report");
  f.state.throttle = true;
  const older = await prepare(2.5, { elapsed: {} });
  expect(older.preview.resumed).toBe(true);
  await expect(older.publish()).rejects.toThrow("Slow down");
  const numeric = await prepare(2.5, { elapsed: 4.5 });
  expect(numeric.preview.resumed).toBe(false);
  await expect(numeric.publish()).rejects.toThrow("Slow down");
  await expect(prepare(2.5, { elapsed: new Number(4.5) })).rejects.toThrow(
    "older saved import cannot be matched",
  );
  expect(f.posts).toEqual([
    JSON.stringify(older.preview.requests[0]),
    JSON.stringify(numeric.preview.requests[0]),
  ]);
});

test("a second matching checkpoint preserves the receipts shown at preview", async () => {
  const prior = await oldScoreApproval("unreported");
  prior.f.state.brokenReadback = true;
  await expect((await prior.prepare(2.5)).publish()).rejects.toThrow(
    "Readback unavailable",
  );
  const receipts = [prior.f.receipts.get(prior.request.request_id)!];
  const saved = JSON.stringify({ ...JSON.parse(prior.saved), receipts });
  await writeFile(prior.path, saved);
  const held = await prior.prepare(2.5);
  const competing = await oldScoreApproval("evidence");
  await competing.prepare(new Number(2.5));
  const tagged = await readFile(competing.path, "utf8");
  const otherPath = join(prior.directory, competing.filename);
  await writeFile(otherPath, tagged);

  const error = await held.publish().catch((cause: unknown) => cause);
  expect(error).toBeInstanceOf(ExternalPublicationError);
  if (!(error instanceof ExternalPublicationError)) throw error;
  expect(error.message).toContain("Two saved imports match");
  expect(error.result).toMatchObject({
    status: "interrupted",
    receipts,
    counts: { updated: 1 },
    unacknowledged: 0,
  });
  expect(prior.f.posts).toEqual([JSON.stringify(prior.request)]);
  expect(await readFile(prior.path, "utf8")).toBe(saved);
  expect(await readFile(otherPath, "utf8")).toBe(tagged);
});

test("matching released primitive and boxed approvals preserve both requests", async () => {
  const primitive = await oldScoreApproval("unreported");
  const boxed = await oldScoreApproval("evidence", false);
  const held = await primitive.prepare(2.5);
  const boxedPath = join(primitive.directory, boxed.filename);
  await writeFile(boxedPath, boxed.saved, { mode: 0o600 });
  await expect(primitive.prepare(new Number(2.5))).rejects.toThrow(
    "Two saved imports match",
  );
  expect(primitive.f.posts).toEqual([]);
  expect(await readFile(primitive.path, "utf8")).toBe(primitive.saved);
  expect(await readFile(boxedPath, "utf8")).toBe(boxed.saved);

  // A later independent canonical approval must still be checked alongside a valid lookup.
  await rm(primitive.path);
  await primitive.prepare(new Number(2.5));
  const tagged = await readFile(boxedPath, "utf8");
  const lookup = `${JSON.parse(tagged).wireKey}.lookup.json`;
  expect(await readdir(primitive.directory)).toContain(lookup);
  await writeFile(primitive.path, primitive.saved, { mode: 0o600 });
  for (const hintAvailable of [true, false]) {
    // A process can exit after writing the tagged approval and before saving its lookup.
    if (!hintAvailable) await rm(join(primitive.directory, lookup));
    for (const score of [2.5, new Number(2.5)])
      await expect(primitive.prepare(score)).rejects.toThrow(
        "Two saved imports match",
      );
    await expect(held.publish()).rejects.toThrow("Two saved imports match");
    expect(await readFile(primitive.path, "utf8")).toBe(primitive.saved);
    expect(await readFile(boxedPath, "utf8")).toBe(tagged);
    expect(primitive.f.posts).toEqual([]);
  }

  // A partial check must see the second approval once it becomes readable.
  {
    using _reads = failCheckpointReads((path) => path === boxedPath);
    primitive.f.state.throttle = true;
    await expect(held.publish()).rejects.toThrow("Slow down");
  }
  await expect(primitive.prepare(2.5)).rejects.toThrow(
    "Two saved imports match",
  );
  expect(await readFile(primitive.path, "utf8")).toBe(primitive.saved);
  expect(await readFile(boxedPath, "utf8")).toBe(tagged);
  expect(primitive.f.posts).toEqual([JSON.stringify(primitive.request)]);
});

test.each(["report", "mixed", "aliased"])(
  "ambiguous historical %s data preserves the pending approval",
  async (field) => {
    const { f, prepare, path, saved } = await oldScoreApproval(field);
    const retry =
      field === "mixed"
        ? prepare(new Number(2.5), { elapsed: {} })
        : prepare(2.5, { elapsed: new Number(4.5) });
    await expect(retry).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe(saved);
    expect(f.posts).toEqual([]);
  },
);

test("a new boxed report does not claim an unrelated older approval", async () => {
  const { f, prepare, path, saved, request } =
    await oldScoreApproval("unreported");
  const fresh = await prepare(2.5, { elapsed: new Number(4.5) });
  expect(fresh.preview.resumed).toBe(false);
  expect(fresh.preview.requests[0]!.request_id).not.toBe(request.request_id);
  expect(JSON.stringify((await prepare(2.5)).preview.requests)).toBe(
    JSON.stringify([request]),
  );
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toEqual([]);
});

test("an older boxed score with an empty report resumes its original request", async () => {
  const { f, prepare, request } = await oldScoreApproval("empty-report");
  const boxed = await prepare(new Number(12), {});
  expect(boxed.preview.resumed).toBe(true);
  f.state.throttle = true;
  await expect(boxed.publish()).rejects.toThrow("Slow down");
  f.state.throttle = false;
  const primitive = await prepare(12, {});
  expect(primitive.preview.resumed).toBe(true);
  expect((await primitive.publish()).verified).toBe(1);
  const approved = JSON.stringify(request);
  expect(f.posts).toEqual([approved, approved]);
});

test("a boxed false flag remains independent of an approved empty object", async () => {
  const f = await fixture();
  const prepare = (score: unknown, flag: unknown) => {
    const input = scoredFindings(score);
    Object.assign(input.findings[0]!.evidence.source_data, { flag });
    return prepareNormalizedExternalPublication(input, options, f.deps);
  };
  f.state.throttle = true;
  const original = await prepare(1, {});
  await expect(original.publish()).rejects.toThrow("Slow down");
  const boxed = await prepare(new Number(1), new Boolean(false));
  expect(boxed.preview.resumed).toBe(false);
  expect(boxed.preview.requests[0]!.request_id).not.toBe(
    original.preview.requests[0]!.request_id,
  );
  await expect(boxed.publish()).rejects.toThrow("Slow down");
  expect(JSON.parse(f.posts[1]!).items[0].evidence.source_data).toEqual({
    score: 1,
    flag: false,
  });
  const primitive = await prepare(1, false);
  expect(primitive.preview.resumed).toBe(true);
  f.state.throttle = false;
  expect((await primitive.publish()).receipts[0]!.id).toBe(
    boxed.preview.requests[0]!.request_id,
  );
  expect(f.posts[2]).toBe(f.posts[1]);
  const empty = await prepare(1, {});
  expect(empty.preview.resumed).toBe(true);
  expect(JSON.stringify(empty.preview.requests[0])).toBe(f.posts[0]!);
});

test("an older empty flag cannot authorize a boxed Boolean", async () => {
  const { f, prepare, path, saved, request } = await oldScoreApproval("flag");
  await expect(
    prepare(new Number(12), undefined, new Boolean(true)),
  ).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toEqual([]);
  const original = await prepare(new Number(12), undefined, {});
  expect(original.preview.resumed).toBe(true);
  expect((await original.publish()).verified).toBe(1);
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test.each(["evidence", "report"])(
  "a fresh boxed %s reuses its historical filename until the numeric retry completes",
  async (field) => {
    const { f, prepare, path } = await oldScoreApproval(field, false);
    const select = (value: unknown) =>
      field === "report" ? prepare(2.5, { elapsed: value }) : prepare(value);
    const value = field === "report" ? 4.5 : 2.5;
    const ordinary = await select({});
    const competing = await select(new Number(value + 1));
    const boxed = await select(new Number(value));
    f.state.throttle = true;
    await expect(boxed.publish()).rejects.toThrow("Slow down");
    const saved = await readFile(path, "utf8");
    const body = f.posts[0]!;
    expect(JSON.parse(saved).requests).toEqual([JSON.parse(body)]);
    for (const stale of [ordinary, competing]) {
      await expect(stale.publish()).rejects.toThrow(/pending|review/i);
    }
    await expect(select({})).rejects.toThrow(/finish the other pending/i);
    expect(f.posts).toEqual([body]);
    expect(await readFile(path, "utf8")).toBe(saved);

    const numeric = await select(value);
    expect(numeric.preview.resumed).toBe(true);
    expect(numeric.preview.requests).toEqual([JSON.parse(body)]);
    f.state.throttle = false;
    expect((await numeric.publish()).verified).toBe(1);
    expect(await Bun.file(path).exists()).toBe(false);
    const fresh = await select({});
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.requests[0]!.request_id).not.toBe(
      numeric.preview.requests[0]!.request_id,
    );
    expect((await fresh.publish()).verified).toBe(1);
    expect(f.posts).toEqual([
      body,
      body,
      JSON.stringify(fresh.preview.requests[0]),
    ]);
  },
);

test("normalized SDK publication rejects nonfinite raw evidence without JSON coercion", async () => {
  const f = await fixture();
  const input = {
    read: 1,
    findings: [
      {
        source_finding_id: "nonfinite-raw-evidence",
        evidence: {
          title: "Synthetic evidence",
          severity: "high" as const,
          source_data: { score: Infinity },
        },
      },
    ],
    excluded: [],
  };
  await expect(
    prepareNormalizedExternalPublication(input, options, f.deps),
  ).rejects.toThrow("finite JSON numbers");
  expect(input.findings[0]!.evidence.source_data.score).toBe(Infinity);
  expect(f.posts).toHaveLength(0);
});

test("normalized SDK publication rejects unserializable report metadata before upload", async () => {
  const f = await fixture();
  const input = {
    read: 1,
    report: { elapsedNs: 1n },
    findings: [
      {
        source_finding_id: "synthetic-report",
        evidence: { title: "Example", severity: "unknown" as const },
      },
    ],
    excluded: [],
  };
  await expect(
    prepareNormalizedExternalPublication(input, options, f.deps),
  ).rejects.toThrow(/bigint/i);
  await expect(
    prepareNormalizedExternalPublication(
      { ...input, report: { elapsed: new Number(Infinity) } },
      options,
      f.deps,
    ),
  ).rejects.toThrow("finite JSON numbers");
  await expect(
    prepareNormalizedExternalPublication(
      { ...input, report: { toJSON: () => Infinity } },
      options,
      f.deps,
    ),
  ).rejects.toThrow("finite JSON numbers");
  expect(f.posts).toHaveLength(0);
});

test.each([Error, TypeError])(
  "a native %p resumes its released message-only approval",
  async (Diagnostic) => {
    const { f, directory, prepare, request } = await oldScoreApproval(
      "evidence",
      false,
    );
    request.request_id = "15ab6427-635d-4537-9975-f7f536155b49";
    const { path, saved } = await stageReleasedCheckpoint(f, {
      filename:
        "19d4eb5e5738ac54ae3d847f50534f09ac60882b0145fa5abc4260299e7f02b6.pending.json",
      requests: [request],
      inputDigest:
        "603ea14278affa7a9a27fc2a624f5a2ce8fd85460f99175bef69a0572430b59b",
      savedEvidenceDigest:
        "875a8aec2f1b7c573a6d05d983f6afa0f964a6e1c96d22c8c8691cc2de824ccc",
    });
    const diagnostic = () =>
      Object.assign(
        new Diagnostic("scanner message", { cause: "scanner failure" }),
        { code: "E_TEST" },
      );
    const exportedDiagnostic = Object.assign(diagnostic(), {
      toJSON: () => ({ code: "TIMEOUT" }),
    });
    const prepareExported = () =>
      prepare(2.5, { errors: [exportedDiagnostic] });
    await expect(prepareExported()).rejects.toThrow("cannot be matched");
    expect(await readFile(path, "utf8")).toBe(saved);
    expect(f.posts).toEqual([]);

    const uncertain = diagnostic();
    let stackReads = 0;
    Object.defineProperty(uncertain, "stack", {
      get() {
        stackReads++;
        return "custom stack";
      },
    });
    await expect(prepare(2.5, { errors: [uncertain] })).rejects.toThrow(
      "cannot be matched",
    );
    expect(stackReads).toBe(0);
    expect(f.posts).toEqual([]);
    expect(await readFile(path, "utf8")).toBe(saved);

    const prepareUnsafeExport = (error: Error, beforeExport?: () => void) => {
      const input = scoredFindings(2.5, { errors: [error] });
      Object.setPrototypeOf(input.findings[0]!.evidence.source_data, {
        toJSON() {
          beforeExport?.();
          return { score: 2 ** 53 };
        },
      });
      return prepareReleased(f, input);
    };
    const changed = diagnostic();
    await expect(
      prepareUnsafeExport(changed, () =>
        Object.defineProperty(changed, "stack", {
          get() {
            stackReads++;
            return "custom stack";
          },
        }),
      ),
    ).rejects.toThrow("safe integer");
    expect(stackReads).toBe(0);
    expect(f.posts).toEqual([]);
    expect(await readFile(path, "utf8")).toBe(saved);

    const report = { errors: [diagnostic()] };
    expect((await prepare(2.5, report)).preview.resumed).toBe(true);
    const retry = await prepareUnsafeExport(report.errors[0]!);
    expect(retry.preview.resumed).toBe(true);
    const completed = await retry.publish();
    expect(completed.receipts[0]!.id).toBe(request.request_id);
    const expected = structuredClone(report.errors[0]!);
    for (const value of [retry.preview.report, completed.report]) {
      const error = (value?.["errors"] as Error[])[0]!;
      expect(error).toBeInstanceOf(Diagnostic);
      expect(error.message).toBe(expected.message);
      expect(error.stack).toBe(expected.stack);
      expect(error.cause).toBe(expected.cause);
      expect(error).not.toHaveProperty("code");
    }
    const results = await Promise.all(
      (await readdir(directory))
        .filter((name) => name.endsWith(".result.json"))
        .map(
          async (name) =>
            JSON.parse(
              await readFile(join(directory, name), "utf8"),
            ) as ExternalPublicationResult,
        ),
    );
    const receipt = results.find(
      (result) => result.receipts[0]?.id === request.request_id,
    );
    expect(receipt?.report).toEqual({
      errors: [{ message: "scanner message" }],
    });
    expect(f.posts).toEqual([JSON.stringify(request)]);
    expect((await prepareExported()).preview.report?.["errors"]).toEqual([
      { code: "TIMEOUT" },
    ]);
    const fresh = await prepare(2.5, report);
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.report?.["errors"]).toEqual([
      expect.objectContaining({ message: "scanner message", code: "E_TEST" }),
    ]);
  },
);

test("publication JSON retains native Error messages and scanner diagnostics", async () => {
  const scannerErrors = opengrepJson().errors;
  const error = Object.assign(
    runInNewContext(
      'new TypeError(undefined, { cause: "scanner failure" })',
    ) as TypeError,
    { code: "RULE_TIMEOUT", message: "Scanner rule timed out." },
  );
  const nested = {
    path: "src/example.ts",
    cause: new Error("Parser stopped."),
  };
  const report = { errors: [error, nested, ...scannerErrors] };
  const jsonErrors = [
    { message: error.message, code: error.code },
    { path: nested.path, cause: { message: nested.cause.message } },
    ...scannerErrors,
  ];
  const f = await fixture();
  await expect(
    prepareNormalizedExternalPublication(
      { read: 0, findings: [], excluded: [], report },
      options,
      f.deps,
    ),
  ).rejects.toThrow(`Scanner diagnostics: ${JSON.stringify(jsonErrors)}`);
  expect(f.posts).toHaveLength(0);

  const prepared = await prepareNormalizedExternalPublication(
    {
      read: 1,
      findings: [
        {
          source_finding_id: "synthetic-report",
          evidence: { title: "Example finding", severity: "high" },
        },
      ],
      excluded: [],
      report,
    },
    options,
    f.deps,
  );
  nested.cause.message = "Caller changed the diagnostic.";
  const completed = await prepared.publish();
  expect(completed.verified).toBe(1);
  for (const value of [prepared.preview.report, completed.report]) {
    const errors = value?.["errors"] as Error[];
    expect(errors[0]).toBeInstanceOf(TypeError);
    expect(errors[0]).toHaveProperty("code", error.code);
    expect(errors[0]!.message).toBe(error.message);
    expect(errors[0]!.cause).toBe(structuredClone(error).cause);
    expect(errors[1]?.cause).toHaveProperty("message", "Parser stopped.");
    expect(value?.["errors"]).toEqual([
      expect.any(Error),
      { path: nested.path, cause: expect.any(Error) },
      ...scannerErrors,
    ]);
  }
  const dir = join(f.root, "state", "external-finding-publications");
  const receipt = (await readdir(dir)).find((name) =>
    name.endsWith(".result.json"),
  )!;
  expect(JSON.parse(await readFile(join(dir, receipt), "utf8")).report).toEqual(
    {
      errors: jsonErrors,
    },
  );
});

test("invalid source namespaces fail before authentication or Cloud requests", async () => {
  const f = await fixture();
  const contacted: string[] = [];
  for (const sourceKey of [" ", "x".repeat(513), "tenant\0namespace"])
    await expect(
      prepareExternalPublication(
        f.file,
        { ...options, sourceKey },
        {
          ...f.deps,
          credentials: async () => {
            contacted.push("credentials");
            throw new Error("Unexpected authentication");
          },
          fetch: async () => {
            contacted.push("fetch");
            throw new Error("Unexpected Cloud request");
          },
        },
      ),
    ).rejects.toThrow("source key must contain");
  expect(contacted).toEqual([]);
});

test("normalized SDK publication accepts Cloud providers without their file reader", async () => {
  const f = await fixture();
  const prepared = await prepareNormalizedExternalPublication(
    {
      read: 1,
      findings: [
        {
          source_finding_id: "synthetic-endor-finding",
          evidence: { title: "Synthetic finding", severity: "unknown" },
        },
      ],
      excluded: [],
    },
    { ...options, provider: "endor" },
    f.deps,
  );
  expect(prepared.preview.source.provider).toBe("endor");
  expect((await prepared.publish()).verified).toBe(1);
  expect(JSON.parse(f.posts[0]!).source.provider).toBe("endor");
});

test.each([
  { run: "scan-123" },
  { run: { versionControlProvenance: "opaque scanner metadata" } },
])(
  "normalized Snyk publication preserves opaque source metadata: %j",
  async (sourceData) => {
    const original = normalized();
    const finding = {
      ...original,
      evidence: validateExternalEvidence({
        ...original.evidence,
        source_data: sourceData,
      }),
    };
    const f = await fixture();
    const prepared = await prepareNormalizedExternalPublication(
      { read: 1, findings: [finding], excluded: [] },
      { ...options, provider: "snyk" },
      f.deps,
    );
    expect((await prepared.publish()).verified).toBe(1);
    expect([...f.reports.values()][0]!.evidence.source_data).toEqual(
      sourceData,
    );
  },
);

test("Snyk SARIF publish, replay and changed evidence preserve Cloud identity", async () => {
  const input = snykSarif();
  const f = await fixture(input);
  const settings = {
    ...options,
    provider: "snyk" as const,
    sourceKey: "organization/project/main",
  };
  const first = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  const original = structuredClone([...f.reports.values()][0]!);
  const second = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(second.counts.unchanged).toBe(1);
  input.runs[0]!.results[0]!.message.text = "Updated source evidence";
  await writeFile(f.file, JSON.stringify(input));
  const third = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(third.counts.updated).toBe(1);
  const updated = [...f.reports.values()][0]!;
  expect(updated.id).toBe(original.id);
  expect(updated.canonical_finding_id).toBe(original.canonical_finding_id);
  expect(updated.version).toBe(2);
});

for (const [provider, report, normalize, dryRunTitle] of [
  [
    "snyk",
    snykSarif,
    normalizeSnykSarif,
    "Snyk CLI dry run selects its adapter without writing an import",
  ],
  [
    "endor",
    endorSarif,
    normalizeEndorFindings,
    "Endor CLI dry-run recognizes SARIF without writing imports",
  ],
] as const) {
  test(dryRunTitle, async () => {
    const f = await fixture(report());
    const command = [...f.command, "--dry-run"];
    command[command.indexOf("--provider") + 1] = provider;
    const cli = createCliTest(main);
    expect(await cli.runCli(command, f.cliDeps)).toBe(0);
    expect(f.posts).toHaveLength(0);
  });

  test(`${provider} checks empty SARIF runs before a fresh submission`, async () => {
    const source = report();
    const run = {
      ...source.runs[0]!,
      results: [],
      versionControlProvenance: [
        {
          repositoryUri:
            provider === "snyk"
              ? "git+ssh://git@github.com/example/project.git"
              : exampleRepository,
        },
      ],
    };
    const input = { ...source, runs: [...source.runs, run] };
    const f = await fixture(input);
    const selected = { ...options, provider };
    const prepare = () => prepareExternalPublication(f.file, selected, f.deps);
    expect((await prepare()).preview.findings).toHaveLength(1);

    run.versionControlProvenance[0]!.repositoryUri = otherRepository;
    await writeFile(f.file, JSON.stringify(input));
    await expect(prepare()).rejects.toThrow(
      "does not match the selected Cloud repository",
    );
    expect(f.posts).toHaveLength(0);

    // An SDK selection carries only its result-bearing run. Existing approved
    // requests must send those exact bytes, even if the native file has other runs.
    const sdk = await prepareNormalizedExternalPublication(
      normalize(input),
      selected,
      f.deps,
    );
    await f.loseResponse(sdk);
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).verified).toBe(1);
    expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
    await expect(prepare()).rejects.toThrow(
      "does not match the selected Cloud repository",
    );
  });

  test.each([
    { uris: ["https://github.com/other/project"] },
    {
      uris: [
        "https://github.com/example/project",
        "https://github.com/other/project",
      ],
    },
    { uris: ["https://github.com:443/example/project"] },
  ])(
    `${provider === "snyk" ? "Snyk" : "Endor"} source repository provenance binds both publication entrypoints: %p`,
    async ({ uris }) => {
      const original = report();
      const input = {
        ...original,
        runs: original.runs.map((run) => ({
          ...run,
          versionControlProvenance: uris.map((repositoryUri) => ({
            repositoryUri,
          })),
        })),
      };
      const f = await fixture(input);
      const selected = { ...options, provider };
      await expect(
        prepareExternalPublication(f.file, selected, f.deps),
      ).rejects.toThrow("does not match the selected Cloud repository");
      await expect(
        prepareNormalizedExternalPublication(
          normalize(input),
          selected,
          f.deps,
        ),
      ).rejects.toThrow("does not match the selected Cloud repository");
      expect(f.posts).toHaveLength(0);
      expect(f.reports.size).toBe(0);
    },
  );
}

test("Snyk checks empty projects alongside findings in a CLI JSON export", async () => {
  const project = { ...snykJson(), path: exampleRepository };
  const other = {
    ...project,
    ok: true,
    vulnerabilities: [],
    path: otherRepository,
  };
  const f = await fixture([project, other]);
  await expect(
    prepareExternalPublication(
      f.file,
      { ...options, provider: "snyk" },
      f.deps,
    ),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(0);
});

test("native Snyk remote tests bind file and normalized imports to the reported GitHub repository", async () => {
  const input = snykJson();
  input.path = "https://github.com/other/project#release/v1";
  const f = await fixture(input);
  const selected = { ...options, provider: "snyk" as const };
  await expect(
    prepareExternalPublication(f.file, selected, f.deps),
  ).rejects.toThrow("does not match the selected Cloud repository");
  await expect(
    prepareNormalizedExternalPublication(
      normalizeSnykJson(input),
      selected,
      f.deps,
    ),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(0);

  input.path = "https://github.com/example/project.git#release/v1";
  await writeFile(f.file, JSON.stringify(input));
  const prepared = await prepareExternalPublication(f.file, selected, f.deps);
  expect((await prepared.publish()).verified).toBe(1);
  expect([...f.reports.values()][0]!.evidence.source_data).toMatchObject({
    project: { path: input.path },
  });
});

test("Snyk source repository binding is rechecked for a fresh import after completion", async () => {
  const input: any = snykSarif();
  input.runs[0].versionControlProvenance = [
    {
      repositoryUri: "https://GITHUB.COM/EXAMPLE/PROJECT.git",
      revisionId: "synthetic-revision",
    },
  ];
  const original = structuredClone(input);
  const f = await fixture(input);
  const selected = { ...options, provider: "snyk" as const };
  const first = await (
    await prepareExternalPublication(f.file, selected, f.deps)
  ).publish();
  expect(first.verified).toBe(1);
  expect([...f.reports.values()][0]!.evidence.source_data).toMatchObject({
    run: {
      versionControlProvenance: original.runs[0].versionControlProvenance,
    },
  });
  const changedDestination = {
    ...f.deps,
    fetch: async (url: string, init: RequestInit) => {
      const response = await f.deps.fetch(url, init);
      if (new URL(url).pathname.endsWith("/repositories")) {
        const body = await response.json();
        body.data[0].url = "https://github.com/other/project";
        return Response.json(body);
      }
      return response;
    },
  };
  const posted = f.posts.length;
  await expect(
    prepareExternalPublication(f.file, selected, changedDestination),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(posted);
  expect(input).toEqual(original);
});

async function snykRepositoryEvidence(
  format: "plugin" | "SARIF",
  repository: string,
) {
  if (format === "plugin") {
    const input = snykPluginExport();
    input.collection.target.repository = repository;
    return {
      input,
      normalized: normalizeSnykFindingsExport(input),
      original: { collection: input.collection, finding: input.findings[0] },
    };
  }
  const sarif = snykSarif();
  const provenance = [{ repositoryUri: repository }];
  const input = {
    ...sarif,
    runs: sarif.runs.map((run) => ({
      ...run,
      versionControlProvenance: provenance,
    })),
  };
  return {
    input,
    normalized: normalizeSnykSarif(input),
    original: { run: { versionControlProvenance: provenance } },
  };
}

const gitHubProject = "https://github.com/example/project";
const connectedProject = "https://git.example.test/example/project";
const foreignArtifactUrl = "https://github.com/example/other";

const trivyOptions = {
  ...options,
  provider: "trivy" as const,
  trivyScanRoot: ".",
};

async function trivyCloud(
  report: unknown = trivyReport(),
  destination = gitHubProject,
) {
  const f = await fixture(report, destination);
  return {
    ...f,
    fileImport: () => prepareExternalPublication(f.file, trivyOptions, f.deps),
    selected: (rows: ExternalFindings, settings = trivyOptions) =>
      prepareNormalizedExternalPublication(rows, settings, f.deps),
  };
}

test.each([
  [
    "http://git.example.test/Example/Project",
    "http://git.example.test/example/project.git",
    true,
  ],
  [connectedProject, "git@git.example.test:example/project.git", true],
  [
    "ssh://tenant-a@git.example.test/example/project",
    "ssh://git.example.test/example/project",
    false,
  ],
] as const)(
  "Trivy CLI binds artifact %s and origin %s before publication",
  async (ArtifactName, RepoURL, matches) => {
    const cloud = await trivyCloud(
      { ...trivyReport(), ArtifactName, Metadata: { RepoURL } },
      RepoURL.startsWith("http:")
        ? connectedProject.replace("https:", "http:")
        : connectedProject,
    );
    const args = [...cloud.command, "--trivy-scan-root", "."];
    args[args.indexOf("--provider") + 1] = "trivy";
    const cli = createCliTest(main);
    for (const mode of ["--dry-run", "--yes"]) {
      expect(await cli.runCli([...args, mode], cloud.cliDeps)).toBe(
        matches ? 0 : 2,
      );
      if (!matches)
        expect(cli.stderr.text()).toContain("Trivy omitted the SSH user");
      expect(cloud.posts).toHaveLength(matches && mode === "--yes" ? 1 : 0);
    }
    if (matches)
      expect([...cloud.reports.values()]).toMatchObject([
        {
          source: { provider: "trivy" },
          assessment: { state: "not_assessed" },
          evidence: { source_data: { report: { Metadata: { RepoURL } } } },
        },
      ]);
  },
);

test.each([
  ["HTTPS://github.com/example/project", gitHubProject],
  ["Git+SSH://git@github.com/example/project", gitHubProject],
  ["http://git.example.test/example/project.git", connectedProject],
  [gitHubProject, foreignArtifactUrl],
  ["git@github.com:example/project.git.git", gitHubProject],
  ["ssh://git@git.example.test/other/../example/project.git", connectedProject],
  ["https://0177.1./org/project", "https://127.0.0.1/org/project"],
])(
  "Trivy file and selected row preserve origin %s at destination %s",
  async (RepoURL, destination) => {
    const report = { ...trivyReport(), Metadata: { RepoURL } };
    const cloud = await trivyCloud(report, destination);
    await expect(cloud.fileImport()).rejects.toThrow("does not match");
    await expect(cloud.selected(selectedTrivyRows(report))).rejects.toThrow(
      "does not match",
    );
    expect(cloud.posts).toHaveLength(0);
  },
);

// A selected row can be imported without the original batch header.
function selectedTrivyRows(report: unknown = trivyReport()) {
  const { findings, read, excluded } = normalizeTrivyFindings(
    report,
    "cloud",
    ".",
  );
  return { findings, read, excluded };
}

test.each(["complete", "projected", "header only", "URL only"] as const)(
  "selected Trivy %s evidence keeps its provider and repository",
  async (shape) => {
    const rows = selectedTrivyRows();
    const row = rows.findings[0]!;
    const header = row.evidence.source_data!["report"] as Record<
      string,
      unknown
    >;
    if (shape === "projected") delete header["ArtifactType"];
    if (shape === "header only") row.evidence.source_data = { report: header };
    if (shape === "URL only")
      row.evidence.source_data = {
        report: { Metadata: { RepoURL: gitHubProject } },
      };
    else row.source_finding_id = "selected-occurrence";
    await expectTrivyReplay(rows);
    await expectTrivyReplay(rows, /does not match/, foreignArtifactUrl);
    await expectTrivyReplay(
      rows,
      /requires the trivy provider/,
      foreignArtifactUrl,
      "wiz",
    );
  },
);

test.each(["batch header", "SAST fields", "package fields"])(
  "Trivy ownership survives projection as Wiz %s",
  async (shape) => {
    const rows: ExternalFindings = selectedTrivyRows();
    const row = rows.findings[0]!;
    const data = row.evidence.source_data!;
    const id = "selected-occurrence";
    row.source_finding_id = id;
    if (shape === "batch header") {
      rows.report = data["report"] as Record<string, unknown>;
      delete row.evidence.source_data;
    } else if (shape === "SAST fields") {
      data["id"] = id;
      row.source_finding_id = `sast:${id}`;
      row.evidence.details = {
        kind: "sast",
        repository: { id: "wiz-repository", url: foreignArtifactUrl },
      };
    } else
      Object.assign(data, {
        id,
        name: "CVE-2099-0001",
        detailedName: "example-package",
        vendorSeverity: "HIGH",
        vulnerableAsset: { id: "example-asset" },
      });
    await expectTrivyReplay(
      rows,
      /requires the trivy provider/,
      foreignArtifactUrl,
      "wiz",
    );
  },
);

test("Wiz SAST can carry upstream Trivy evidence while binding its own repository through inventory", async () => {
  const record = {
    ...selectedTrivyRows().findings[0]!.evidence.source_data,
    id: "example-occurrence",
    name: "Synthetic finding",
    severity: "HIGH",
    repository: { id: "wiz-repository" },
  };
  const cloud = await fixture(
    {
      data: {
        sastFindings: { nodes: [record] },
        versionControlResources: {
          nodes: [
            {
              platform: "GITHUB",
              repository: { ...record.repository, url: foreignArtifactUrl },
            },
          ],
        },
      },
    },
    foreignArtifactUrl,
  );
  const rows = await readVendorFindings(cloud.file);
  expect(rows.findings[0]).toMatchObject({
    source_finding_id: `sast:${record.id}`,
    evidence: {
      details: { repository: { url: foreignArtifactUrl } },
      source_data: record,
    },
  });
  await using local = await localFindingsFixture({
    remote: foreignArtifactUrl,
  });
  const prepared = await prepareNormalizedLocalImport(
    rows,
    { ...options, repository: local.repository },
    { environment: local.environment },
  );
  expect((await prepared.import()).counts.created).toBe(1);
  const publication = await prepareExternalPublication(
    cloud.file,
    options,
    cloud.deps,
  );
  expect((await publication.publish()).counts.created).toBe(1);
});

async function expectTrivyReplay(
  rows: ExternalFindings,
  error?: string | RegExp,
  remote = gitHubProject,
  provider: "trivy" | "wiz" = "trivy",
) {
  await using local = await localFindingsFixture({ remote });
  const cloud = await fixture(undefined, remote);
  const settings = { ...options, provider };
  for (const prepare of [
    () =>
      prepareNormalizedLocalImport(
        rows,
        { ...settings, repository: local.repository },
        { environment: local.environment },
      ),
    () => prepareNormalizedExternalPublication(rows, settings, cloud.deps),
  ]) {
    if (error) await expect(prepare()).rejects.toThrow(error);
    else expect((await prepare()).preview.findings).toHaveLength(1);
  }
}

const uppercaseWebUrl = "HTTPS://github.com/Example/Project";
const userlessSsh = "ssh://github.com/example/project";
const explicitSsh = "ssh://git@github.com/example/project";
test.each([
  [gitHubProject, uppercaseWebUrl, undefined],
  [gitHubProject, foreignArtifactUrl, /does not match|different repositories/],
  [uppercaseWebUrl, gitHubProject, /does not match|different repositories/],
  [userlessSsh, gitHubProject, /omitted the SSH user/],
  [explicitSsh, gitHubProject, undefined],
] as const)(
  "Trivy compares the raw origin %s independently of the typed repository %s",
  async (raw, typed, error) => {
    const rows = selectedTrivyRows();
    const evidence = rows.findings[0]!.evidence;
    evidence.source_data!["report"] = trivyRepositoryHeader(raw);
    evidence.details = { kind: "sast", repository: { url: typed } };
    await expectTrivyReplay(
      { ...rows, report: trivyRepositoryHeader(gitHubProject) },
      error,
    );
  },
);

test("each normalized Trivy finding must retain its report's repository", async () => {
  const report = trivyReport();
  report.Results.push({
    ...report.Results[0]!,
    Target: "nested/package-lock.json",
  });
  const input = normalizeTrivyFindings(report, "cloud", ".");
  delete input.findings[1]!.evidence.source_data;
  input.report = trivyRepositoryHeader(report.Metadata.RepoURL);
  await expectTrivyReplay(input, /retain/i);
});

test.each([
  [`${gitHubProject}/Kit`, `${gitHubProject}/Kit`, false],
  [`${gitHubProject}/Kit`, `${gitHubProject}/%E2%84%AAit`, true],
  ["https://0177.1./org/project", "https://127.0.0.1/org/project", false],
] as const)(
  "Trivy compares typed and catalog URLs %s and %s",
  async (source, target, matches) => {
    const cloud = await trivyCloud(undefined, target);
    const rows = selectedTrivyRows({ ...trivyReport(), Metadata: {} });
    const catalog = cloud.selected(rows, {
      ...trivyOptions,
      repository: source,
    });
    if (matches) expect((await catalog).preview.destination.url).toBe(target);
    else
      await expect(catalog).rejects.toThrow(
        "destination repository is not available",
      );

    for (const kind of ["typed", "native"]) {
      const report = {
        ...trivyReport(),
        Metadata: { RepoURL: kind === "native" ? source : target },
      };
      const rows = selectedTrivyRows(report);
      if (kind === "typed")
        rows.findings[0]!.evidence.details = {
          kind: "sast",
          repository: { url: source },
        };
      const prepared = cloud.selected(rows);
      if (matches) expect((await prepared).preview.findings).toHaveLength(1);
      else await expect(prepared).rejects.toThrow("does not match");
    }
  },
);

test("Trivy preparation rejects retained Inspector findings", async () => {
  const input = normalizeInspectorFindings(inspectorReport(), gitHubProject);
  const cloud = await fixture();
  await expect(
    prepareNormalizedExternalPublication(input, trivyOptions, cloud.deps),
  ).rejects.toThrow(
    "Retained Inspector evidence requires the inspector provider.",
  );
});

test("Trivy typed repository links and catalog URLs must identify the same HTTP and Git path", async () => {
  const ambiguous = "https://github.com/example/%2e%2e/../project";
  const error = /HTTP path that does not match its Git path/u;
  const input = selectedTrivyRows({ ...trivyReport(), Metadata: {} });
  input.findings[0]!.evidence.details = {
    kind: "sast",
    repository: { url: ambiguous },
  };
  await expectTrivyReplay(input, error);

  const rows = selectedTrivyRows();
  const cloud = await trivyCloud();
  await expect(
    cloud.selected(rows, { ...trivyOptions, repository: ambiguous }),
  ).rejects.toThrow(error);
  cloud.state.repositoryUrl = ambiguous;
  await expect(cloud.selected(rows)).rejects.toThrow(error);
});

const credentialUrl = "https://scanner:fixture@github.com/example/project";

test.each([
  ["filesystem", credentialUrl, "without credentials"],
  [undefined, credentialUrl, "without credentials"],
  ["unknown", credentialUrl, "without credentials"],
  [undefined, foreignArtifactUrl, "does not match"],
  ["filesystem", foreignArtifactUrl, undefined],
] as const)(
  "checks retained Trivy artifact type %s with URL %s",
  async (ArtifactType, ArtifactName, error) => {
    const input = normalizeTrivyFindings(
      { ...trivyReport(), Metadata: {} },
      "cloud",
      ".",
    );
    input.findings[0]!.evidence.source_data!["report"] = {
      SchemaVersion: 2,
      ...(ArtifactType && { ArtifactType }),
      ArtifactName,
    };
    await expectTrivyReplay(input, error);
  },
);

test.each([
  ["repository", "other", false],
  ["repository", "project", true],
  ["filesystem", "other", true],
])(
  "Trivy %s artifact URL ending in %s binds individual findings when it identifies a repository",
  async (ArtifactType, project, accepts) => {
    const ArtifactName = `ssh://git@github.com/example/${project}.git`;
    const report = {
      ...trivyReport(),
      ArtifactType,
      ArtifactName,
      Metadata: {},
    };
    const cloud = await trivyCloud(report);
    for (const prepare of [
      cloud.fileImport,
      () => cloud.selected(selectedTrivyRows(report)),
    ]) {
      if (!accepts) {
        await expect(prepare()).rejects.toThrow("does not match");
        continue;
      }
      const prepared = await prepare();
      if (ArtifactType === "repository") {
        const other = await trivyCloud(report, foreignArtifactUrl);
        await expect(
          other.selected(JSON.parse(JSON.stringify(prepared.preview))),
        ).rejects.toThrow("does not match");
      }
      await prepared.publish();
      expect(
        JSON.parse(cloud.posts.at(-1)!).items[0].evidence.source_data.report
          .ArtifactName,
      ).toBe(ArtifactName);
    }
  },
);

test.each([
  ["empty", [], "No supported findings are ready to publish"],
  [
    "excluded-only",
    [{ Class: "os-pkgs" }],
    "Unsupported Trivy result class: os-pkgs",
  ],
] as const)(
  "an %s Trivy report stops before Cloud authentication or repository discovery",
  async (_name, Results, error) => {
    const report = {
      ...trivyReport(),
      Metadata: { RepoURL: "ssh://git.example.test/example/project" },
      Results,
    };
    const cloud = await fixture(report);
    const unexpected = async () => {
      throw new Error("Unexpected Cloud access");
    };
    const deps = {
      environment: cloud.environment,
      credentials: unexpected,
      fetch: unexpected,
    };
    await expect(
      prepareExternalPublication(cloud.file, trivyOptions, deps),
    ).rejects.toThrow(error);
    const input = normalizeTrivyFindings(report, "cloud", ".");
    await expect(
      prepareNormalizedExternalPublication(input, trivyOptions, deps),
    ).rejects.toThrow(error);
    input.report = trivyRepositoryHeader(credentialUrl);
    await expect(
      prepareNormalizedExternalPublication(input, trivyOptions, deps),
    ).rejects.toThrow("without credentials");
  },
);

test.each([
  [
    {
      provider: "trivy",
      trivyScanRoot: ".",
      sourceRepositoryUrl: "https://github.com/example/other",
    },
    "--source-repository-url",
  ],
  [{ provider: "trivy" }, "--trivy-scan-root"],
  [{ provider: "wiz", trivyScanRoot: "." }, "only to --provider trivy"],
  [{ provider: "snyk", trivyScanRoot: "." }, "only to --provider trivy"],
  [{ provider: "semgrep", trivyScanRoot: "." }, "only to --provider trivy"],
] as const)(
  "rejects invalid file import options %p",
  async (settings, message) => {
    const f = await fixture(trivyReport());
    await expect(
      prepareExternalPublication(f.file, { ...options, ...settings }, f.deps),
    ).rejects.toThrow(message);
    expect(f.posts).toHaveLength(0);
  },
);

const tenantProject = "https://tenant.ghe.com/example/project";

const snykRepositoryAliases: [string, string][] = [
  ["https://github.com/example/project.git", gitHubProject],
  ["git@github.com:example/project.git", gitHubProject],
  ["ssh://git@github.com/example/project.git", gitHubProject],
  ["ssh://git@github.com:22/example/project.git", gitHubProject],
  ["ssh://git@ssh.github.com:443/example/project.git", gitHubProject],
  ["git@git.example.test:example/project.git", connectedProject],
  ["ssh://git@git.example.test/example/project.git", connectedProject],
  ["ssh://git@git.example.test:22/example/project.git", connectedProject],
  ["tenant@tenant.ghe.com:example/project.git", tenantProject],
  ["ssh://tenant@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://tenant@tenant.ghe.com:22/example/project.git", tenantProject],
  // Preserve the existing generic git-user aliases for connected catalog hosts.
  ["git@tenant.ghe.com:example/project.git", tenantProject],
  ["ssh://git@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://git@tenant.ghe.com:22/example/project.git", tenantProject],
  ["git@GIT.EXAMPLE.TEST:example/project.git", connectedProject],
  ["https://git.example.test/example/project.git", connectedProject],
];

test.each([
  [
    "plugin",
    "ssh://tenant@tenant.ghe.com:22/example/project.git",
    tenantProject,
  ] as const,
  [
    "SARIF",
    "ssh://git@ssh.github.com:443/example/project.git",
    gitHubProject,
  ] as const,
  ["plugin", "unknown", gitHubProject] as const,
  [
    "plugin",
    "git+ssh://git@github.com/example/project.git",
    gitHubProject,
  ] as const,
])(
  "Snyk %s export imports and replays with repository remote %s",
  async (format, repository, destination) => {
    const { input, normalized, original } = await snykRepositoryEvidence(
      format,
      repository,
    );
    const f = await fixture(input, destination, "connector-selected");
    const selected = {
      ...options,
      provider: "snyk" as const,
      sourceKey: "example/project/main/plugin-sca",
    };
    const first = await (
      await prepareExternalPublication(f.file, selected, f.deps)
    ).publish();
    expect(first.counts.created).toBe(1);
    expect(first.verified).toBe(1);
    expect(JSON.parse(f.posts[0]!).repository.repo_connector_id).toBe(
      "connector-selected",
    );
    expect([...f.reports.values()][0]!.evidence.source_data).toMatchObject(
      original,
    );
    const second = await (
      await prepareNormalizedExternalPublication(normalized, selected, f.deps)
    ).publish();
    expect(second.counts.unchanged).toBe(1);
  },
);

const snykRepositoryMismatches: [string, string][] = [
  ...["\t", "\r", "\n"].flatMap((control): [string, string][] => [
    [`ssh://git@github.${control}com/example/project.git`, gitHubProject],
    [`ssh://git@github.com/example/pro${control}ject.git`, gitHubProject],
    [
      `ssh://tenant@tenant.${control}ghe.com/example/project.git`,
      tenantProject,
    ],
    [
      `ssh://tenant@tenant.ghe.com/example/pro${control}ject.git`,
      tenantProject,
    ],
    [
      `ssh://git@ssh.github.${control}com:443/example/project.git`,
      gitHubProject,
    ],
    [
      `ssh://git@ssh.github.com:443/example/pro${control}ject.git`,
      gitHubProject,
    ],
  ]),
  [
    "ssh://tenant@other:synthetic@tenant.ghe.com/example/project.git",
    tenantProject,
  ],
  ["ssh://tenant@other:@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://git@other:synthetic@github.com/example/project.git", gitHubProject],
  ["ssh://git@other:@github.com/example/project.git", gitHubProject],
  ["ssh://te\nnant@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://te\tnant@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://te\rnant@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://gi\nt@github.com/example/project.git", gitHubProject],
  ["ssh://tenant@other@tenant.ghe.com/example/project.git", tenantProject],
  ["other@tenant.ghe.com:example/project.git", tenantProject],
  ["ssh://other@tenant.ghe.com:22/example/project.git", tenantProject],
  [
    "tenant@tenant.ghe.com:example/project.git",
    "https://other.ghe.com/example/project",
  ],
  ["ssh://tenant@git.example.test/example/project.git", connectedProject],
  [
    "ssh://tenant@api.tenant.ghe.com/example/project.git",
    "https://api.tenant.ghe.com/example/project",
  ],
  ["ssh://tenant:synthetic@tenant.ghe.com/example/project.git", tenantProject],
  ["ssh://tenant:@tenant.ghe.com/example/project.git", tenantProject],
  [
    "ssh://tenant@tenant.ghe.com:443/example/project.git",
    "https://tenant.ghe.com:443/example/project",
  ],
  [
    "ssh://tenant@tenant.ghe.com:22/example/project.git",
    "https://tenant.ghe.com:443/example/project",
  ],
  ["tenant@tenant.ghe.com:other/project.git", tenantProject],
  ["ssh://tenant@ssh.github.com:443/example/project.git", gitHubProject],
  [
    "tenant@tenant.ghe.com:example/project.git",
    "http://tenant.ghe.com/example/project",
  ],
  ["git@github.com:other/project.git", gitHubProject],
  ["ssh://git@github.com:2222/example/project.git", gitHubProject],
  ["ssh://git@ssh.github.com:2222/example/project.git", gitHubProject],
  ["ssh://git@git.example.test:443/example/project.git", gitHubProject],
  [
    "ssh://git@git.example.test:2222/example/project.git",
    "https://git.example.test:2222/example/project",
  ],
  [
    "ssh://git@git.example.test:443/example/project.git",
    "https://git.example.test:443/example/project",
  ],
  [
    "ssh://git@github.com:2222/example/project.git",
    "https://github.com:2222/example/project",
  ],
  [
    "ssh://git@github.com:443/example/project.git",
    "https://github.com:443/example/project",
  ],
  [
    "ssh://tenant@tenant.ghe.com:2222/example/project.git",
    "https://tenant.ghe.com:2222/example/project",
  ],
  [
    "ssh://git@ssh.github.com:2222/example/project.git",
    "https://ssh.github.com:2222/example/project",
  ],
  ["git@other.example.test:example/project.git", connectedProject],
  ["git@git.example.test:other/project.git", connectedProject],
  [
    "git@git.example.test:example/project.git",
    "https://git.example.test:443/example/project",
  ],
  [
    "ssh://git@git.example.test:22/example/project.git",
    "https://git.example.test:22/example/project",
  ],
  [
    "ssh://git@git.example.test/example/project.git",
    "http://git.example.test/example/project",
  ],
];

// Check the URL matrix before involving the filesystem, catalog, or publication state.
for (const [cases, matches] of [
  [snykRepositoryAliases, true],
  [snykRepositoryMismatches, false],
] as const) {
  test.each(cases)(
    `Snyk repository %j against %j (matches=${matches})`,
    async (repository, destination) => {
      for (const format of ["plugin", "SARIF"] as const) {
        const { normalized, original } = await snykRepositoryEvidence(
          format,
          repository,
        );
        const source = normalized.findings[0]!.evidence.source_data;
        const urls = snykRepositoryUrls(source, {
          cloudRepositoryUrl: destination,
        });
        expect(urls, format).toHaveLength(1);
        expect(
          cloudRepositoryUrlKey(urls[0]!) ===
            cloudRepositoryUrlKey(destination),
          format,
        ).toBe(matches);
        expect(source, format).toMatchObject(original);
      }
    },
  );
}

test.each([
  [
    "plugin",
    "ssh://git@github.\tcom/example/project.git",
    gitHubProject,
  ] as const,
  [
    "SARIF",
    "ssh://git@github.com:2222/example/project.git",
    gitHubProject,
  ] as const,
  ["SARIF", "unknown", gitHubProject] as const,
  [
    "plugin",
    "ssh://git@github.com/example/project.git?other",
    gitHubProject,
  ] as const,
])(
  "Snyk %s repository claim %s cannot target %s",
  async (format, repository, destination) => {
    const { input, normalized, original } = await snykRepositoryEvidence(
      format,
      repository,
    );
    const f = await fixture(input, destination);
    const selected = { ...options, provider: "snyk" as const };
    await expect(
      prepareExternalPublication(f.file, selected, f.deps),
    ).rejects.toThrow("does not match the selected Cloud repository");
    await expect(
      prepareNormalizedExternalPublication(normalized, selected, f.deps),
    ).rejects.toThrow("does not match the selected Cloud repository");
    expect(f.posts).toHaveLength(0);
    expect(normalized.findings[0]!.evidence.source_data).toMatchObject(
      original,
    );
  },
);

test("native Snyk JSON publishes selected dependency occurrences and replays their evidence", async () => {
  const input = snykJson();
  const f = await fixture(input);
  const selected = {
    ...options,
    provider: "snyk" as const,
    sourceKey: "example/project/main/root/native-sca",
  };
  const prepared = await prepareExternalPublication(f.file, selected, f.deps);
  expect(prepared.preview.excluded).toEqual([]);
  const first = await prepared.publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  expect([...f.reports.values()][0]!.evidence).toMatchObject({
    locations: [],
    packages: [{ name: "@example/package", manifest_path: null }],
    source_data: { vulnerability: input.vulnerabilities[0] },
  });
  const second = await (
    await prepareExternalPublication(f.file, selected, f.deps)
  ).publish();
  expect(second.counts.unchanged).toBe(1);
});

test("Semgrep publication preserves identity across JSON and SARIF with explicit repository provenance", async () => {
  const f = await fixture(semgrepJson());
  const settings = {
    ...options,
    provider: "semgrep" as const,
    sourceKey: "organization/project/main",
    sourceRepositoryUrl: "https://github.com/example/project",
  };
  const prepared = await prepareExternalPublication(f.file, settings, f.deps);
  expect(prepared.preview.source).toEqual({
    provider: "semgrep",
    source_key: settings.sourceKey,
  });
  const first = await prepared.publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  const original = structuredClone([...f.reports.values()][0]!);
  expect(original.source.provider).toBe("semgrep");
  expect(original.evidence.details?.kind).toBe("sast");
  expect(
    (
      await (
        await prepareExternalPublication(f.file, settings, f.deps)
      ).publish()
    ).counts.unchanged,
  ).toBe(1);
  await writeFile(f.file, JSON.stringify(semgrepSarif()));
  const changed = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(changed.counts.updated).toBe(1);
  const updated = [...f.reports.values()][0]!;
  expect(updated.id).toBe(original.id);
  expect(updated.canonical_finding_id).toBe(original.canonical_finding_id);
  expect(updated.evidence.source_data).toMatchObject({
    result: semgrepSarif().runs[0]!.results[0],
  });
});

test.each([
  ["semgrep", semgrepJson],
  ["opengrep", opengrepJson],
] as const)(
  "%s file retries a released request with its original source URL after a rename",
  async (provider, scannerOutput) => {
    const f = await fixture(scannerOutput());
    const originalUrl = f.destination().url;
    const prepare = (sourceRepositoryUrl: string) =>
      prepareExternalPublication(
        f.file,
        { ...options, provider, sourceRepositoryUrl },
        f.deps,
      );
    const original = await prepare(originalUrl);
    const pending = await f.loseResponse(original);
    await useReleasedCheckpoint(pending);
    f.state.repositoryUrl = "https://github.com/example/renamed";

    await expect(prepare("https://github.com/other/project")).rejects.toThrow(
      /does not match/,
    );
    const retry = await prepare(originalUrl);
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests).toEqual(original.preview.requests);
    await retry.publish();
    expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
    expect(f.receipts.size).toBe(1);
  },
);

test("OpenGrep publication retains grouped evidence through Cloud readback and replay", async () => {
  const input = opengrepTraceJson();
  const { results, ...report } = input;
  const f = await fixture(input);
  const settings = {
    ...options,
    provider: "opengrep" as const,
    sourceKey: "organization/project/main/opengrep",
    sourceRepositoryUrl: "https://github.com/example/project",
  };
  const prepared = await prepareExternalPublication(f.file, settings, f.deps);
  expect(prepared.preview.source).toEqual({
    provider: "semgrep",
    source_key: settings.sourceKey,
  });
  expect(prepared.preview.report).toEqual(report);
  expect(prepared.preview.findings).toHaveLength(1);
  expect(prepared.preview.excluded).toEqual([]);
  prepared.preview.report!["errors"] = [];
  const first = await prepared.publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  expect(first.report).toEqual(report);
  const original = structuredClone([...f.reports.values()][0]!);
  expect(original).toMatchObject({
    origin: "imported",
    source: { provider: "semgrep" },
    assessment: { state: "not_assessed" },
    evidence: {
      details: { kind: "sast", scanner_origin: "OpenGrep" },
      source_data: { scan_error_count: input.errors.length },
    },
  });
  expect(original.evidence.source_data!["results"]).toHaveLength(2);
  expect(original.evidence.source_data!["results"]).toEqual(
    expect.arrayContaining(results),
  );
  expect(original.evidence).not.toHaveProperty("confidence");
  expect(JSON.parse(f.posts[0]!).source.provider).toBe("semgrep");
  const repeated = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(repeated.counts.unchanged).toBe(1);
  expect(repeated.report).toEqual(report);

  input.results[0]!.extra.message = "Updated OpenGrep evidence";
  input.results[0]!.extra.fingerprint = "new-scanner-fingerprint_9";
  await writeFile(f.file, JSON.stringify(input));
  const changed = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(changed.counts.updated).toBe(1);
  expect(changed.verified).toBe(1);
  expect(changed.report).toEqual(report);
  expect([...f.reports.values()]).toHaveLength(1);
  const updated = [...f.reports.values()][0]!;
  expect(updated).toMatchObject({
    id: original.id,
    canonical_finding_id: original.canonical_finding_id,
    source_finding_id: original.source_finding_id,
    version: 2,
    origin: "imported",
    assessment: { state: "not_assessed" },
  });
  expect(updated.evidence.source_data!["results"]).toHaveLength(2);
  expect(updated.evidence.source_data!["results"]).toEqual(
    expect.arrayContaining(input.results),
  );
});

test("repository severity exclusions identify every original OpenGrep trace", async () => {
  const report = opengrepTraceJson();
  const [first, second] = report.results;
  const other = { ...first!, path: "src/other.ts" };
  const input = {
    ...report,
    errors: [],
    results: [first, other, null, second],
  };
  const f = await fixture(input);
  const settings = {
    ...options,
    provider: "opengrep" as const,
    sourceRepositoryUrl: "https://github.com/example/project",
  };
  const parsed = normalizeOpenGrepFindings(input, settings);
  const ids = new Map(
    parsed.findings.map(({ source_finding_id, evidence }) => [
      evidence.locations![0]!.path,
      source_finding_id,
    ]),
  );
  f.state.catalogHeaders["Codex-Security-Repository-Import-Severities"] =
    "high";
  const prepare = (input: ExternalFindings) =>
    prepareNormalizedExternalPublication(
      input,
      { ...settings, provider: "semgrep" },
      f.deps,
    );
  const originalIds = [
    ids.get(first!.path)!,
    ids.get(other.path)!,
    null,
    ids.get(first!.path)!,
  ];
  for (const [load, expectedIds] of [
    [() => prepareExternalPublication(f.file, settings, f.deps), originalIds],
    [() => prepare({ ...parsed }), originalIds],
    [() => prepare(structuredClone(parsed)), [null, null, null, null]],
    [
      () => prepare(JSON.parse(JSON.stringify(parsed))),
      [null, null, null, null],
    ],
  ] as const) {
    const failure = await load().catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(NoPublishableFindingsError);
    const { selection, summary } = failure as NoPublishableFindingsError;
    expect(summary).toContain("4 read, 4 excluded");
    expect(selection.excluded.map(({ position }) => position)).toEqual([
      1, 2, 3, 4,
    ]);
    expect(
      selection.excluded.map(({ source_finding_id }) => source_finding_id),
    ).toEqual([...expectedIds]);
    expect(selection.excluded[2]).toEqual(parsed.excluded[0]);
  }
  expect(f.posts).toHaveLength(0);
});

test("empty OpenGrep Cloud imports retain scanner diagnostics without uploading", async () => {
  const input = opengrepJson();
  input.results = [];
  const f = await fixture(input);
  await expect(
    prepareExternalPublication(
      f.file,
      {
        ...options,
        provider: "opengrep",
        sourceRepositoryUrl: "https://github.com/example/project",
      },
      f.deps,
    ),
  ).rejects.toThrow(input.errors[0]!.message);
  expect(f.posts).toHaveLength(0);
});

test("OpenGrep CLI Cloud preview forwards source provenance without uploading", async () => {
  const input = opengrepJson();
  const f = await fixture(input);
  const command = [
    ...f.command,
    "--dry-run",
    "--source-repository-url",
    "https://github.com/example/project",
  ];
  command[command.indexOf("--provider") + 1] = "opengrep";
  const cli = createCliTest(main);
  expect(await cli.runCli(command, f.cliDeps)).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    source: { provider: "semgrep", source_key: options.sourceKey },
    report: { errors: input.errors },
    findings: [
      {
        evidence: {
          details: { scanner_origin: "OpenGrep" },
          source_data: { results: input.results },
        },
      },
    ],
  });
  const humanCommand = [...command];
  humanCommand.splice(humanCommand.indexOf("--format"), 2);
  const human = createCliTest(main);
  expect(await human.runCli(humanCommand, f.cliDeps)).toBe(0);
  expect(human.stderr.text()).toContain(input.errors[0]!.message);
  expect(f.posts).toHaveLength(0);
});

test("Semgrep native percent paths retain CE records through JSON-to-SARIF publication", async () => {
  const { paths, json, sarif } = semgrepPercentPathReports();
  const f = await fixture(json);
  const settings = {
    ...options,
    provider: "semgrep" as const,
    sourceKey: "organization/project/main",
    sourceRepositoryUrl: "https://github.com/example/project",
  };
  const first = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(first.counts.created).toBe(paths.length);
  expect(first.verified).toBe(paths.length);
  const originalIds = [...f.reports.values()]
    .map((report) => [report.id, report.canonical_finding_id])
    .sort();
  await writeFile(f.file, JSON.stringify(sarif));
  const changed = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(changed.counts.created).toBe(0);
  expect(changed.counts.updated).toBe(paths.length);
  expect(changed.verified).toBe(paths.length);
  expect(
    [...f.reports.values()]
      .map((report) => [report.id, report.canonical_finding_id])
      .sort(),
  ).toEqual(originalIds);
  expect(
    [...f.reports.values()]
      .map((report) => report.evidence.locations?.[0]?.path)
      .sort(),
  ).toEqual(paths.toSorted());
  expect(
    (
      await (
        await prepareExternalPublication(f.file, settings, f.deps)
      ).publish()
    ).counts.unchanged,
  ).toBe(paths.length);
});

test("Semgrep publication retains unsupported SARIF bases without repository locations", async () => {
  const input: any = semgrepSarif();
  const run = input.runs[0];
  run.results[0].locations[0].physicalLocation.artifactLocation.uriBaseId =
    "ROOT";
  run.originalUriBaseIds = { ROOT: { uri: "file:///outside/" } };
  const f = await fixture(input);
  const settings = {
    ...options,
    provider: "semgrep" as const,
    sourceKey: "organization/project/main",
    sourceRepositoryUrl: "https://github.com/example/project",
  };
  const first = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  const original = structuredClone([...f.reports.values()][0]!);
  expect(original.evidence.locations).toEqual([]);
  expect(original.evidence.source_data).toMatchObject({
    result: run.results[0],
    runContext: { originalUriBaseIds: run.originalUriBaseIds },
  });
  expect(JSON.parse(f.posts[0]!).items[0].evidence.locations).toEqual([]);

  run.originalUriBaseIds.ROOT.uri = "subproject/";
  await writeFile(f.file, JSON.stringify(input));
  const changed = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(changed.counts.updated).toBe(1);
  const updated = [...f.reports.values()][0]!;
  expect(updated.id).toBe(original.id);
  expect(updated.canonical_finding_id).toBe(original.canonical_finding_id);
  expect(updated.evidence.locations).toEqual([]);
  expect(updated.evidence.source_data).toMatchObject({
    runContext: { originalUriBaseIds: run.originalUriBaseIds },
  });
  expect(
    (
      await (
        await prepareExternalPublication(f.file, settings, f.deps)
      ).publish()
    ).counts.unchanged,
  ).toBe(1);
});

test("Semgrep refuses missing source identity and a conflicting Cloud destination without uploads", async () => {
  const f = await fixture(semgrepJson());
  await expect(
    prepareExternalPublication(
      f.file,
      { ...options, provider: "semgrep" },
      f.deps,
    ),
  ).rejects.toThrow("sourceRepositoryUrl");
  await expect(
    prepareExternalPublication(
      f.file,
      {
        ...options,
        provider: "semgrep",
        sourceRepositoryUrl: "https://github.com/other/project",
      },
      f.deps,
    ),
  ).rejects.toThrow(/repository/i);
  expect(f.posts).toHaveLength(0);
});

test("Semgrep CLI dry-run preserves explicit source repository and does not upload", async () => {
  const f = await fixture(semgrepJson());
  const command = [
    ...f.command,
    "--dry-run",
    "--source-repository-url",
    "https://github.com/example/project",
  ];
  command[command.indexOf("--provider") + 1] = "semgrep";
  const cli = createCliTest(main);
  expect(await cli.runCli(command, f.cliDeps)).toBe(0);
  expect(f.posts).toHaveLength(0);
});

test("Endor JSON and SARIF reuse UUID identity through Cloud publication", async () => {
  const input = endorFinding();
  const f = await fixture(input);
  const settings = {
    ...options,
    provider: "endor" as const,
    sourceKey: "namespace/project/main",
  };
  const first = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(first.counts.created).toBe(1);
  const original = structuredClone([...f.reports.values()][0]!);
  expect(
    (
      await (
        await prepareExternalPublication(f.file, settings, f.deps)
      ).publish()
    ).counts.unchanged,
  ).toBe(1);
  const sarif = endorSarif();
  await writeFile(f.file, JSON.stringify(sarif));
  const changed = await (
    await prepareExternalPublication(f.file, settings, f.deps)
  ).publish();
  expect(changed.counts.updated).toBe(1);
  expect(changed.verified).toBe(1);
  const updated = [...f.reports.values()][0]!;
  expect(updated.id).toBe(original.id);
  expect(updated.canonical_finding_id).toBe(original.canonical_finding_id);
  expect(updated.evidence.source_data).toMatchObject({
    result: sarif.runs[0]!.results[0],
  });
});
test.each(["file", "selected rows"] as const)(
  "a Trivy %s publication resumes its original request across entrypoints and a repository rename",
  async (initialKind) => {
    const report = {
      ...trivyReport(),
      Metadata: {},
      ArtifactName: "ssh://git@github.com/example/project.git",
    };
    const cloud = await trivyCloud(report);
    const file = cloud.fileImport;
    const selected = (header?: Record<string, unknown>) =>
      cloud.selected({ ...selectedTrivyRows(report), report: header });
    const first = initialKind === "file" ? await file() : await selected();
    await cloud.loseResponse(first);
    const body = cloud.posts[0]!;
    expect(JSON.parse(body)).toEqual(first.preview.requests[0]);
    await writeFile(
      cloud.file,
      JSON.stringify({ ...report, ArtifactName: foreignArtifactUrl }),
    );
    await expect(file()).rejects.toThrow("does not match");
    await writeFile(cloud.file, JSON.stringify(report));

    cloud.state.repositoryUrl = "https://github.com/example/renamed";
    await expect(
      selected(trivyRepositoryHeader(cloud.state.repositoryUrl)),
    ).rejects.toThrow("does not match");
    expect(cloud.posts).toEqual([body]);
    expect(
      (await selected(trivyRepositoryHeader(gitHubProject))).preview.resumed,
    ).toBe(true);
    const retry = initialKind === "file" ? await selected() : await file();
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests).toEqual(first.preview.requests);
    expect((await retry.publish()).status).toBe("complete");
    expect(cloud.posts).toEqual([body, body]);
    await expect(file()).rejects.toThrow("does not match");
  },
);

test("unverified Trivy checkpoints retain their requests and receipts for the original importer", async () => {
  const cloud = await trivyCloud();
  const prepare = cloud.fileImport;
  cloud.state.brokenReadback = true;
  const failure = await (
    await prepare()
  )
    .publish()
    .catch((error: unknown) => error);
  if (!(failure instanceof ExternalPublicationError)) throw failure;
  const filename = failure.result.savedSubmission!;
  cloud.state.brokenReadback = false;
  const retry = await prepare();
  const { accountId, requests, receipts, inputProjection } = JSON.parse(
    await readFile(filename, "utf8"),
  );
  expect(receipts).toHaveLength(1);
  const original = JSON.stringify({
    accountId,
    requests,
    receipts,
    inputProjection,
  });
  await writeFile(filename, original);
  await expect(prepare()).rejects.toThrow("the build that created it");
  await expect(retry.publish()).rejects.toThrow();
  expect(await readFile(filename, "utf8")).toBe(original);
  expect(cloud.posts).toHaveLength(1);
});

test("Endor source repository binding preserves immutable requests across a repository rename", async () => {
  const input: any = endorSarif();
  input.runs[0].versionControlProvenance = [
    {
      repositoryUri: "https://GITHUB.COM/EXAMPLE/PROJECT.git",
      revisionId: "synthetic-revision",
    },
  ];
  const original = structuredClone(input);
  const f = await fixture(input);
  const selected = { ...options, provider: "endor" as const };
  f.state.loseResponse = true;
  const first = await prepareExternalPublication(f.file, selected, f.deps);
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  const changedDestination = {
    ...f.deps,
    fetch: async (url: string, init: RequestInit) => {
      const response = await f.deps.fetch(url, init);
      if (new URL(url).pathname.endsWith("/repositories")) {
        const body = await response.json();
        body.data[0].url = "https://github.com/other/project";
        return Response.json(body);
      }
      return response;
    },
  };
  const retry = await prepareExternalPublication(
    f.file,
    selected,
    changedDestination,
  );
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).status).toBe("complete");
  expect(f.posts[1]).toBe(f.posts[0]);
  expect([...f.reports.values()][0]!.evidence.source_data).toMatchObject({
    runContext: {
      versionControlProvenance: original.runs[0].versionControlProvenance,
    },
  });
  const posted = f.posts.length;
  await expect(
    prepareExternalPublication(f.file, selected, changedDestination),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(posted);
  expect(input).toEqual(original);
});

test("publication rejects malformed options without writing findings", async () => {
  const f = await fixture();
  const missingSourceKey = [
    ...f.command.slice(1, f.command.indexOf("--source-key") + 1),
    "--dry-run",
    "--yes",
  ];
  for (const flags of [
    ["--json"],
    ["--json", "--filter-output", "--token-limit"],
    ["--filter-output", "--to"],
  ]) {
    const cli = createCliTest(main);
    expect(
      await cli.runCli(["publish", ...flags, ...missingSourceKey], f.cliDeps),
    ).toBe(2);
    expect(cli.stderr.text()).toContain("Missing value for flag");
  }
  const extraArguments = createCliTest(main);
  expect(
    await extraArguments.runCli(
      [
        "--filter-output",
        "--token-limit",
        ...f.command,
        "--yes",
        "extra-1",
        "extra-2",
      ],
      f.cliDeps,
    ),
  ).toBe(2);
  expect(extraArguments.stderr.text()).toContain(
    "Unexpected positional argument",
  );
  const preview = createCliTest(main);
  expect(
    await preview.runCli(
      ["--json", ...f.command, "--dry-run", "--yes"],
      f.cliDeps,
    ),
  ).toBe(0);
  expect(JSON.parse(preview.stdout.text())).toMatchObject({ dryRun: true });
  expect(f.posts).toHaveLength(0);
});

test("a held primitive retry cannot republish after a newer boxed approval", async () => {
  const f = await fixture();
  const prepare = (elapsed: unknown) =>
    prepareNormalizedExternalPublication(
      scoredFindings(12, { elapsed }),
      options,
      f.deps,
    );
  const original = await prepare(2.5);
  f.state.loseResponse = true;
  await expect(original.publish()).rejects.toThrow(/resume the saved request/);
  const held = await prepare(2.5);
  expect(held.preview.resumed).toBe(true);
  const completed = await (await prepare(2.5)).publish();

  const newer = await prepare(new Number(2.5));
  const newerId = newer.preview.requests[0]!.request_id;
  expect(newerId).not.toBe(original.preview.requests[0]!.request_id);
  f.state.loseResponse = true;
  await expect(newer.publish()).rejects.toThrow(/resume the saved request/);
  const before = [...f.posts];
  expect(await held.publish()).toEqual(completed);
  expect(f.posts).toEqual(before);

  const remaining = await prepare(2.5);
  expect(remaining.preview.requests).toEqual(newer.preview.requests);
  expect((await remaining.publish()).receipts[0]!.id).toBe(newerId);
  const directory = join(f.root, "state", "external-finding-publications");
  const filename = (await readdir(directory)).find((name) =>
    name.endsWith(".result.json"),
  )!;
  const resultPath = join(directory, filename);
  const saved = await readFile(resultPath, "utf8");
  await expect(held.publish()).rejects.toThrow(/changed after preview/);
  expect(await readFile(resultPath, "utf8")).toBe(saved);
  expect(f.posts).toEqual([
    ...before,
    JSON.stringify(newer.preview.requests[0]),
  ]);
});

const concurrentBoxedApproval =
  "concurrent prepares reuse only the matching completed boxed approval";
test(concurrentBoxedApproval, async () => {
  const { runTestInSubprocess } = await import("./support/test-subprocess.js");
  if (runTestInSubprocess(import.meta.filename, concurrentBoxedApproval))
    return;

  for (const state of [
    "original result",
    "newer pending",
    "newer complete",
    "released result",
    "released different",
    "released malformed",
  ]) {
    const { f, prepare, directory, path, request } =
      await oldScoreApproval("evidence");
    const atLock = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    const lstat = fs.lstat;
    let holdFirst = true;
    const metadata = spyOn(fs, "lstat").mockImplementation((async (
      ...args: Parameters<typeof fs.lstat>
    ) => {
      const file = String(args[0]);
      if (
        holdFirst &&
        file.startsWith(directory) &&
        file.endsWith(".lock.sqlite")
      ) {
        holdFirst = false;
        atLock.resolve();
        await release.promise;
      }
      return lstat(...args);
    }) as typeof fs.lstat);

    const waiting = prepare(new Number(2.5));
    try {
      await Promise.race([atLock.promise, waiting]);
      const leader = await prepare(new Number(2.5));
      const { wireKey } = JSON.parse(await readFile(path, "utf8"));
      const completed = await leader.publish();
      expect(completed.receipts[0]!.id).toBe(request.request_id);
      expect(f.posts).toEqual([JSON.stringify(request)]);
      let pending: { path: string; bytes: string } | undefined;
      if (state.startsWith("released")) {
        // The released publisher stores this receipt under its original checkpoint filename.
        const oldResult = path.replace(/\.pending\.json$/, ".result.json");
        const currentName = `${wireKey}.result.json`;
        const seed = (await readdir(directory)).find(
          (name) => name.endsWith(".result.json") && name !== currentName,
        )!;
        const currentResult = join(directory, currentName);
        await fs.rename(currentResult, oldResult);
        if (state === "released malformed") {
          const result = JSON.parse(await readFile(oldResult, "utf8"));
          result.receipts[0].results = [];
          await writeFile(oldResult, JSON.stringify(result));
        } else if (state === "released different") {
          await fs.copyFile(join(directory, seed), oldResult);
        } else {
          // A different completed request can still occupy the current result filename.
          await fs.copyFile(join(directory, seed), currentResult);
        }
      } else if (state !== "original result") {
        const newer = await prepare(2.5);
        const newerId = newer.preview.requests[0]!.request_id;
        expect(newerId).not.toBe(request.request_id);
        if (state === "newer pending") {
          f.state.throttle = true;
          await expect(newer.publish()).rejects.toThrow("Slow down");
          const [name] = (await readdir(directory)).filter((name) =>
            name.endsWith(".pending.json"),
          );
          const path = join(directory, name!);
          pending = { path, bytes: await readFile(path, "utf8") };
          expect(JSON.parse(pending.bytes).requests[0].request_id).toBe(
            newerId,
          );
          f.state.throttle = false;
        } else {
          expect((await newer.publish()).receipts[0]!.id).toBe(newerId);
        }
      }
      const before = [...f.posts];
      release.resolve();
      if (state === "released malformed") {
        await expect(waiting).rejects.toThrow();
      } else if (state === "newer complete" || state === "released different") {
        await expect(waiting).rejects.toThrow(/changed while preparing/);
      } else {
        const trailing = await waiting;
        expect(trailing.preview.resumed).toBe(true);
        expect(trailing.preview.requests[0]!.request_id).toBe(
          request.request_id,
        );
        expect(await trailing.publish()).toEqual(completed);
      }
      if (pending)
        expect(await readFile(pending.path, "utf8")).toBe(pending.bytes);
      expect(f.posts).toEqual(before);
    } finally {
      release.resolve();
      metadata.mockRestore();
      await Promise.allSettled([waiting]);
    }
  }
});

test("a lookup hint cannot substitute for the tagged approval", async () => {
  const { f, prepare, directory, path, filename, request } =
    await oldScoreApproval("evidence");
  f.state.throttle = true;
  await expect((await prepare(new Number(2.5))).publish()).rejects.toThrow(
    "Slow down",
  );
  const tag = JSON.parse(await readFile(path, "utf8"));
  const lookup = join(directory, `${tag.wireKey}.lookup.json`);
  const suffix = ".pending.json";
  expect(JSON.parse(await readFile(lookup, "utf8"))).toBe(
    filename.slice(0, -suffix.length),
  );

  const otherReport = { units: "seconds" };
  const other = await prepare(new Number(3.5), otherReport);
  await expect(other.publish()).rejects.toThrow("Slow down");
  const [otherName] = (await readdir(directory)).filter(
    (name) => name.endsWith(suffix) && name !== filename,
  );
  const otherPath = join(directory, otherName!);
  const otherSaved = await readFile(otherPath, "utf8");
  const otherTag = JSON.parse(otherSaved);
  expect(otherTag.wireKey).not.toBe(tag.wireKey);
  const otherKey = otherName!.slice(0, -suffix.length);
  expect(
    JSON.parse(
      await readFile(
        join(directory, `${otherTag.wireKey}.lookup.json`),
        "utf8",
      ),
    ),
  ).toBe(otherKey);
  f.posts.length = 0;
  f.state.throttle = false;

  const outside = join(directory, "..", "foreign.pending.json");
  await writeFile(outside, otherSaved, { mode: 0o600 });
  const reads = spyOn(fs, "readFile");
  try {
    for (const hint of [
      undefined,
      "{",
      JSON.stringify("../foreign"),
      JSON.stringify(otherKey),
    ]) {
      if (hint === undefined) await rm(lookup);
      else await writeFile(lookup, hint);
      const actual = await prepare(2.5);
      expect(actual.preview.resumed).toBe(true);
      expect(actual.preview.requests[0]!.request_id).toBe(request.request_id);
    }
    expect(reads.mock.calls.map(([path]) => String(path))).not.toContain(
      outside,
    );
  } finally {
    reads.mockRestore();
  }
  const completed = await (await prepare(2.5)).publish();
  expect(completed.receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request)]);
  expect(await readFile(otherPath, "utf8")).toBe(otherSaved);

  const held = await prepare(3.5, otherReport);
  expect(held.preview.requests[0]!.request_id).toBe(
    other.preview.requests[0]!.request_id,
  );
  await rm(otherPath);
  await expect(held.publish()).rejects.toThrow(/changed after preview/);
  const fresh = await prepare(3.5, otherReport);
  expect(fresh.preview.resumed).toBe(false);
  expect(fresh.preview.requests[0]!.request_id).not.toBe(
    other.preview.requests[0]!.request_id,
  );
  expect(f.posts).toEqual([JSON.stringify(request)]);
});

test("a lookup write or cleanup failure leaves the approved request usable", async () => {
  const { f, prepare, path, directory, request } =
    await oldScoreApproval("evidence");
  const rename = fs.rename;
  const write = spyOn(fs, "rename").mockImplementation(async (from, to) => {
    if (String(to).endsWith(".lookup.json"))
      throw new Error("Lookup write failed");
    return rename(from, to);
  });
  f.state.throttle = true;
  try {
    const boxed = await prepare(new Number(2.5));
    await expect(boxed.publish()).rejects.toThrow("Slow down");
    expect(
      write.mock.calls.some(([, to]) => String(to).endsWith(".lookup.json")),
    ).toBe(true);
  } finally {
    write.mockRestore();
  }
  const tag = JSON.parse(await readFile(path, "utf8"));
  const lookup = join(directory, `${tag.wireKey}.lookup.json`);
  expect(await Bun.file(lookup).exists()).toBe(false);
  f.state.throttle = false;
  const remove = fs.rm;
  const cleanup = spyOn(fs, "rm").mockImplementation(async (file, options) => {
    if (String(file) === lookup) throw new Error("Lookup cleanup failed");
    return remove(file, options);
  });
  try {
    const retry = await prepare(2.5);
    expect(retry.preview.resumed).toBe(true);
    const result = await retry.publish();
    expect(result.status).toBe("complete");
    expect(result.verified).toBe(1);
    expect(result.receipts[0]!.id).toBe(request.request_id);
    expect(cleanup.mock.calls.some(([file]) => String(file) === lookup)).toBe(
      true,
    );
  } finally {
    cleanup.mockRestore();
  }
  expect(await Bun.file(path).exists()).toBe(false);
  expect(await Bun.file(lookup).exists()).toBe(true);
  expect((await prepare(2.5)).preview.resumed).toBe(false);
  expect(f.posts).toEqual([JSON.stringify(request), JSON.stringify(request)]);
});

test("partially unboxing an approved input resumes its verified wire request", async () => {
  const { f, prepare, directory, request } = await oldScoreApproval(
    "evidence",
    false,
  );
  // This filename, projection and request ID came from the released SDK with b boxed.
  request.request_id = "dd905f37-1437-44a3-b559-8c88fe873e52";
  Object.assign(request.items[0]!.evidence.source_data, {
    score: { a: 7, b: 99 },
  });
  const { path: oldPath, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "ad0ce218fdfcfa75455f2fbda30dc6e248a79419190e5fa77a7c12005ead7926.pending.json",
    requests: [request],
    inputDigest:
      "232fbafeda24e0939a033a0d59479908389a8e167612feabc174e36f716303a5",
    savedEvidenceDigest:
      "3a5021a32dc41a1fe4b2d8e2f74abfd1238ef63cf5bfb4cf44cb28bb09e5bfad",
  });
  const partial = () => prepare({ a: 7, b: new Number(2) });
  await expect(partial()).rejects.toThrow("cannot be matched");

  const approved = await prepare({ a: new Number(7), b: new Number(2) });
  f.state.throttle = true;
  await expect(approved.publish()).rejects.toThrow("Slow down");
  f.state.throttle = false;
  const body = JSON.stringify(approved.preview.requests[0]);
  const hinted = await partial();
  expect(hinted.preview.resumed).toBe(true);
  expect(JSON.stringify(hinted.preview.requests[0])).toBe(body);
  const lookup = (await readdir(directory)).find((name) =>
    name.endsWith(".lookup.json"),
  )!;
  await rm(join(directory, lookup));
  const retry = await partial();
  expect(retry.preview.resumed).toBe(true);
  expect(JSON.stringify(retry.preview.requests[0])).toBe(body);
  expect((await retry.publish()).receipts[0]!.id).toBe(
    approved.preview.requests[0]!.request_id,
  );
  expect(f.posts).toEqual([body, body]);
  expect(await readFile(oldPath, "utf8")).toBe(saved);
});

test("preparing across a checkpoint handoff returns the observed approval", async () => {
  const {
    f,
    prepare,
    path: boxedPath,
  } = await oldScoreApproval("evidence", false);
  const first = await prepare(2.5);
  f.state.loseResponse = true;
  const interrupted = await first.publish().catch((error: unknown) => error);
  if (!(interrupted instanceof ExternalPublicationError)) throw interrupted;
  const canonicalPath = interrupted.result.savedSubmission!;
  const leading = await prepare(2.5);

  const captured = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  let hold = true;
  const read = fs.readFile;
  const reads = spyOn(fs, "readFile").mockImplementation((async (
    ...args: Parameters<typeof read>
  ) => {
    const bytes = await read(...args);
    if (hold && String(args[0]) === canonicalPath) {
      hold = false;
      captured.resolve();
      await release.promise;
    }
    return bytes;
  }) as typeof read);
  const waiting = prepare(2.5);
  try {
    await Promise.race([captured.promise, waiting]);
    expect(hold).toBe(false);
    const completed = await leading.publish();
    expect(await Bun.file(canonicalPath).exists()).toBe(false);
    const next = await prepare(new Number(2.5));
    expect(next.preview.requests[0]!.request_id).not.toBe(
      first.preview.requests[0]!.request_id,
    );
    f.state.throttle = true;
    await expect(next.publish()).rejects.toThrow("Slow down");
    const newer = await readFile(boxedPath, "utf8");
    const before = [...f.posts];
    release.resolve();
    const trailing = await waiting;
    expect(trailing.preview.resumed).toBe(true);
    expect(trailing.preview.requests).toEqual(first.preview.requests);
    expect(await trailing.publish()).toEqual(completed);
    expect(await readFile(boxedPath, "utf8")).toBe(newer);
    expect(f.posts).toEqual(before);
  } finally {
    release.resolve();
    reads.mockRestore();
    await Promise.allSettled([waiting]);
  }
});

test("a changing GitHub ref cannot expand an older pending publication", async () => {
  const f = await fixture();
  const prepare = (
    selected: ReturnType<typeof normalizeGitHubCodeScanningAlerts>,
  ) =>
    prepareNormalizedExternalPublication(
      selected,
      { ...options, provider: "github" },
      f.deps,
    );
  const first = importedAlert();
  const preview = (
    await prepare(normalizeGitHubCodeScanningAlerts([first], "cloud"))
  ).preview;
  // The released reader excluded the second alert before its rule serializer ran.
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "0b43d13c77ddf5fa43ce0bb536402595aea270191adde5974f2206753fa607b1.pending.json",
    accountId: preview.accountId,
    requests: [
      {
        ...preview.requests[0]!,
        request_id: "f49f8193-10b0-4c6c-a20d-390304a5f8d0",
      },
    ],
    inputDigest:
      "af139e1baa9e9e70a47d4ef0f811cb3960e9c280252affab51c250e7e6f9aa88",
  });
  expect(hash("sha256", saved)).toBe(
    "5f17c21d058c685c128d488b5a2a1e466fa5d18e37cc5284268b95ef25307293",
  );

  const second = importedAlert();
  second.number = second.alert.number = 13;
  second.url = second.alert.html_url = first.url.replace(/12$/, "13");
  let ref = "";
  Object.defineProperty(second.alert.most_recent_instance, "ref", {
    enumerable: true,
    get: () => ref,
  });
  Object.defineProperty(second.alert.rule, "toJSON", {
    value() {
      ref = "refs/heads/changed";
      return { ...this };
    },
  });
  const selected = normalizeGitHubCodeScanningAlerts([first, second], "cloud");
  expect(selected.findings).toHaveLength(2);
  await expect(prepare(selected)).rejects.toThrow("cannot be matched");
  expect(f.posts).toHaveLength(0);
  expect(await readFile(path, "utf8")).toBe(saved);
});

test("a normalized Buffer at the Cloud depth limit resumes only its released request", async () => {
  const f = await fixture();
  const prepare = (leaf: unknown) => {
    let tree = leaf;
    for (let i = 0; i < 17; i++) tree = { nested: tree };
    const selected = scoredFindings(new Number(2.5));
    Object.assign(selected.findings[0]!.evidence.source_data, { tree });
    return prepareReleased(f, selected);
  };
  await expect(prepare(Buffer.from([1]))).rejects.toThrow(
    "Cloud JSON depth limit of 20",
  );

  // The released SDK cloned this Buffer into a Uint8Array with one fewer JSON level.
  const request = {
    ...(await prepare({ 0: 1 })).preview.requests[0]!,
    request_id: "54bf2d2b-9380-415e-a364-963088768421",
  };
  const serialized = JSON.stringify(request);
  expect(hash("sha256", serialized)).toBe(
    "5d105b251af91c09d0b206404bd9332031da8e3cb4bb02a9b8add4e4c21814c4",
  );
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "8376bdd00875ba8349ea341fab1c1d7c91eface0f2346d5eacf28e5c534a6d6a.pending.json",
    requests: [request],
    inputDigest:
      "4eace8a1f10136be4258341e48f747f3609919238018ad5f8d84ceebfe469bb2",
    savedEvidenceDigest:
      "68702d81bc70bb23815207a069b0780b2b5b1f304250ca4696ecfe129c48e497",
  });
  await expect(prepare(Buffer.from([2]))).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toHaveLength(0);

  const recovered = await prepare(Buffer.from([1]));
  expect(recovered.preview.resumed).toBe(true);
  expect((await recovered.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([serialized]);
});

test("the local GitHub reader recovers its released Buffer at the Cloud depth limit", async () => {
  const f = await fixture();
  const selected = (leaf: unknown) => {
    const row = importedAlert();
    let payload = leaf;
    for (let i = 0; i < 16; i++) payload = { nested: payload };
    Object.assign(row.alert, { payload });
    return normalizeGitHubCodeScanningAlerts([row], "local");
  };
  const prepare = (input: ReturnType<typeof selected>) =>
    prepareReleased(f, input, { ...options, provider: "github" });
  await expect(prepare(selected(Buffer.from([1])))).rejects.toThrow(
    "Cloud JSON depth limit of 20",
  );

  // The released publisher sent the native byte without the Buffer's JSON envelope.
  const request = {
    ...(await prepare(selected({ 0: 1 }))).preview.requests[0]!,
    request_id: "3681fc33-491a-4ef4-877c-4cdd6f7dac6c",
  };
  const wire = JSON.stringify(request);
  expect(hash("sha256", wire)).toBe(
    "0603739963094b95e0f454f2cfd70ec9ee9f7abf891d43d536a67ad27dcf7b95",
  );
  const { path, saved } = await stageReleasedCheckpoint(f, {
    filename:
      "0f045c3b26dc68db90c2d4e8462be50efa7a758d256398e22f13d1fe070e552a.pending.json",
    requests: [request],
    inputDigest:
      "85488c56d0f48bb7dff1f931e69603aa4aa75c1ef287bf612fd84dc7df369aa2",
  });

  const edited = selected(Buffer.from([1]));
  edited.findings[0]!.evidence.title = "Edited after the local read";
  await expect(prepare(edited)).rejects.toThrow("Cloud JSON depth limit of 20");
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toHaveLength(0);

  const resumed = await prepare(selected(Buffer.from([1])));
  expect(resumed.preview.resumed).toBe(true);
  expect((await resumed.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([wire]);
});

test.each([
  [
    "cloned",
    ["main"],
    "0e174a52fb4c08c30d5b452239859f60186b2e5f3ea11476b7c174712b5f9dca",
    "f97a11da51b2461c09e003c6167239198cde1e28a0b0ec97d8e40a512f396c99",
  ],
  [
    "reversed",
    ["a", "b"],
    "a64d3d2ca1432fae7c53f2880f7e6719f4e4f673ce61e85f8084980d95bc55ae",
    "28c71167a82f47a1f038e6469f36a8f740fe3584ba67f8d4a52d5dbcbdff44d5",
  ],
] as const)(
  "preserves a released GitHub Buffer checkpoint with %s reader output",
  async (kind, refs, key, digest) => {
    const f = await fixture();
    const prepare = (bytes: unknown) => {
      const rows = refs.map((ref) => {
        const row = importedAlert(`refs/heads/${ref}`);
        Object.assign(row.alert, { bytes });
        return row;
      });
      const result = normalizeGitHubCodeScanningAlerts(rows);
      if (kind === "reversed") result.findings.reverse();
      return prepareReleased(
        f,
        kind === "cloned" ? structuredClone(result) : result,
        { ...options, provider: "github" },
      );
    };
    // The released reader cloned each Buffer into a Uint8Array before publication.
    const requests = (await prepare({ 0: 1 })).preview.requests;
    const { checkpoint, directory, path, saved } =
      await stageReleasedCheckpoint(f, {
        filename: `${key}.pending.json`,
        requests,
        inputDigest: digest,
      });
    await expect(prepare(Buffer.from([1]))).rejects.toThrow(
      "checkpoint was preserved",
    );
    expect(await readFile(path, "utf8")).toBe(saved);
    expect(f.posts).toHaveLength(0);
    if (kind === "cloned") {
      expect((await prepare(Buffer.from([2]))).preview.resumed).toBe(false);

      // A migrated approval can be linked to its scoped wire key from an older filename.
      const linkedPath = join(directory, `${"a".repeat(64)}.pending.json`);
      await fs.rename(path, linkedPath);
      const linked = {
        ...checkpoint,
        wireKey: key,
        inputProjection: { ...checkpoint.inputProjection, identityFormat: 2 },
      };
      await writeFile(
        linkedPath,
        JSON.stringify({ ...linked, legacyApproval: true }),
      );
      await expect(prepare(Buffer.from([1]))).rejects.toThrow(
        "checkpoint was preserved",
      );
      // A format-2 request for the plain indexed object is an independent selection.
      await writeFile(linkedPath, JSON.stringify(linked));
      expect((await prepare(Buffer.from([1]))).preview.resumed).toBe(false);
    }
  },
);

test("the GitHub reader resumes a released boxed score whose Buffer fit the Cloud request", async () => {
  const f = await fixture();
  const row = importedAlert();
  const extension = {
    score: new Number(1e-7),
    bytes: Buffer.from([1]),
    pad: "",
  };
  Object.assign(row.alert, { extension });
  const normalize = () => normalizeGitHubCodeScanningAlerts([row], "cloud");
  const prepare = (input = normalize()) =>
    prepareNormalizedExternalPublication(
      input,
      { ...options, provider: "github" },
      f.deps,
    );

  // Rebuild the released request without storing the 256 KiB row in the fixture.
  const priorReader = structuredClone(normalize());
  priorReader.findings[0]!.evidence.source_data = { ...row };
  const template = await prepare();
  const request = JSON.parse(JSON.stringify(template.preview.requests[0]));
  request.request_id = "5e640fea-52f8-43c2-ba4c-a0822c040458";
  extension.pad = "x".repeat(260303);
  const wire = request.items[0].evidence;
  wire.source_data.alert.extension.bytes = { "0": 1 };
  wire.source_data.alert.extension.pad = extension.pad;
  expect(
    Buffer.byteLength(JSON.stringify(priorReader.findings[0]!.evidence)),
  ).toBe(256 * 1024);
  const bodyHash =
    "69a99d16710c9dc0710268e00b91ecdbb45df094d2918ec9797163332bcd37c5";
  expect(Buffer.byteLength(JSON.stringify(wire))).toBe(262123);
  expect(hash("sha256", JSON.stringify(request))).toBe(bodyHash);
  await expect(prepare()).rejects.toThrow("Cloud limit of 256 KiB");
  await expect(prepare(priorReader)).rejects.toThrow("Cloud limit of 256 KiB");
  expect(f.posts).toHaveLength(0);

  await stageReleasedCheckpoint(f, {
    filename:
      "c03e748fff72692564d445fc232317c164f16cf16fc5b1969bbee80d98bdb97e.pending.json",
    requests: [request],
    inputDigest:
      "6d0cd82bed91273c26d2d9cd6eea9814f7ce3ac33af58a266f6554617d560362",
  });

  const resumed = await prepare(priorReader);
  expect(resumed.preview.resumed).toBe(true);
  expect(resumed.preview.excluded).toEqual([]);
  f.state.brokenReadback = true;
  await expect(resumed.publish()).rejects.toThrow("Readback unavailable");
  f.state.brokenReadback = false;
  const completed = await (await prepare()).publish();
  expect(completed).toMatchObject({
    status: "complete",
    ready: 1,
    excluded: [],
    unacknowledged: 0,
    counts: { created: 1 },
    verified: 1,
  });
  expect(completed.receipts.map(({ id }) => id)).toEqual([request.request_id]);
  expect(f.posts.map((body) => hash("sha256", body))).toEqual([bodyHash]);
});

const sonarReport = sonarCapture(exampleRepository);
const trivy = trivyReport();
const endorSource = endorFinding();
const boundEndorSarif = endorSarif();
Object.assign(boundEndorSarif.runs[0]!, {
  versionControlProvenance: [{ repositoryUri: exampleRepository }],
});
const endorVulnerability = endorSource.spec.finding_metadata.vulnerability;
test.each(["package", "malware aliases"] as const)(
  "the Endor private upload retains the reviewed %s when its other enrichment exceeds Cloud limits",
  async (retained) => {
    const keepPackage = retained === "package";
    const packageName = keepPackage ? "alternate-package" : "x".repeat(513);
    const aliases = keepPackage
      ? Array.from({ length: 99 }, (_, i) => `MAL-${i}`)
      : ["MAL-example"];
    const raw = {
      ...endorSource,
      spec: {
        ...endorSource.spec,
        target_dependency_name: null,
        target_dependency_package_name: packageName,
        finding_metadata: {
          vulnerability: endorVulnerability,
          malware: { spec: { aliases } },
        },
      },
    };
    const { inbox, uploads, prepareFile } = await privateUploadFixture(
      raw,
      "endor",
    );
    inbox.formats = ["endor.findings_json.v1"];
    await expect(prepareFile()).rejects.toThrow("security.findings.v1");
    inbox.formats.push("security.findings.v1");
    const prepared = await prepareFile();
    expect(prepared.preview.privateImport?.format).toBe("security.findings.v1");
    await expect(prepared.publish()).rejects.toThrow(
      "Interrupted private upload",
    );
    const { findings, format } = JSON.parse(uploads[0]!.bytes);
    expect(format).toBe("security.findings.v1");
    expect(findings).toHaveLength(1);
    const { evidence } = findings[0];
    expect(evidence.source_data).toEqual(raw);
    expect(evidence.advisory_ids).toEqual([
      endorVulnerability.meta.name,
      ...endorVulnerability.spec.aliases,
      ...(keepPackage ? [] : aliases),
    ]);
    expect(evidence.packages ?? []).toEqual(
      keepPackage
        ? endorSource.spec.dependency_file_paths.map((path) => ({
            name: packageName,
            ecosystem: "npm",
            installed_version: endorSource.spec.target_dependency_version,
            manifest_path: path,
            fixed_versions: [],
          }))
        : [],
    );
  },
);

test("an interrupted native Endor checkpoint retains its original bytes and IDs until its inbox changes", async () => {
  const raw = {
    ...endorSource,
    extra: "x".repeat(190 * 1024),
    spec: {
      ...endorSource.spec,
      target_dependency_name: null,
      target_dependency_package_name: "x".repeat(495),
      dependency_file_paths: Array.from(
        { length: 100 },
        (_, i) => `modules/${i}/yarn.lock`,
      ),
    },
  };
  const { f, inbox, uploads, prepareFile, jobs, fileId, settings } =
    await privateUploadFixture(raw, "endor");
  f.state.catalogHeaders = {};
  const repositoryPreview = await prepareFile();
  f.state.catalogHeaders["Codex-Security-Private-Import-Providers"] = "endor";
  const fresh = await prepareFile();
  expect(fresh.preview.privateImport?.format).toBe("security.findings.v1");
  expect(fresh.preview.findings[0]!.evidence).toMatchObject({
    packages: [],
    source_data: raw,
  });
  inbox.formats = ["endor.findings_json.v1"];
  await expect(prepareFile()).rejects.toThrow("security.findings.v1");
  // This released checkpoint predates structured-only uploads for reduced Endor fields.
  const key =
    "52629feec0c5f197e2bce1779b908306b6b01d232112b359451da0da111c6ccd";
  const checkpoint = {
    format: "endor.findings_json.v1",
    apiBaseUrl: "https://chatgpt.com/backend-api/aardvark",
    accountId: "synthetic-account",
    contextVersion: inbox.version,
    source: { provider: "endor", source_key: settings.sourceKey },
    repository: { id: options.repository, repo_connector_id: "github" },
    sha256: "2aba52fd27bf9b6b2fdf6cb84b701a61690266a29924fb6d6a25e9a4c1574341",
    uploadRequestId: "200ce23c-1576-4525-8b58-50c43812bce8",
    jobRequestId: "9bceaf8a-8ef4-4bbc-99a7-78fc0d6dcbcf",
  };
  await f.writeCheckpoint(key + ".private-import.json", checkpoint);
  const retry = await prepareFile();
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.privateImport).toMatchObject({
    format: checkpoint.format,
    sha256: checkpoint.sha256,
  });
  expect(checkpoint.sha256).not.toBe(fresh.preview.privateImport?.sha256);
  await expect(retry.publish()).rejects.toThrow("Interrupted private upload");
  expect(uploads).toEqual([
    { id: checkpoint.uploadRequestId, bytes: JSON.stringify(raw) },
  ]);
  await expect(repositoryPreview.publish()).rejects.toThrow(
    "A private import already owns this selection",
  );
  inbox.recoverUpload = true;
  expect((await (await prepareFile()).publish()).privateJob?.status).toBe(
    "completed",
  );
  expect(jobs).toEqual([
    {
      request_id: checkpoint.jobRequestId,
      context_version: inbox.version,
      ...privateJobFields("endor", fileId, checkpoint.format),
    },
  ]);
  inbox.version = "new-inbox";
  inbox.formats.push("security.findings.v1");
  const next = await prepareFile();
  expect(next.preview.resumed).toBe(false);
  expect(next.preview.privateImport?.sha256).toBe(
    fresh.preview.privateImport?.sha256,
  );
  inbox.recoverUpload = false;
  await expect(next.publish()).rejects.toThrow("Interrupted private upload");
  const uploaded = JSON.parse(uploads.at(-1)!.bytes);
  expect(uploaded.format).toBe("security.findings.v1");
  expect(uploaded.findings).toHaveLength(1);
  expect(uploaded.findings[0].evidence).toMatchObject({
    packages: [],
    source_data: raw,
  });
});

const versionThreeReports = [
  ["blackduck", blackDuckBomReport(), { row: blackDuckBomRow() }],
  [
    "checkmarx",
    { scanID: "scan-a", totalCount: 1, results: [checkmarxSastRow()] },
    { row: checkmarxSastRow() },
  ],
  ["sonar", sonarReport, { issue: sonarReport.pages[0]!.issues[0]! }],
  ["trivy", trivy, { vulnerability: trivy.Results[0]!.Vulnerabilities[0]! }],
  ["veracode", veracodePolicyPage(), { row: veracodePolicyRow() }],
] as const;

test.each([
  ...versionThreeReports.map(([provider, raw, retained]) => ({
    provider,
    raw,
    retained,
    sourceRepositoryUrl: provider === "trivy" ? undefined : exampleRepository,
    format: "security.findings.v1" as const,
    jobVersion: 3 as const,
  })),
  {
    provider: "github",
    format: "security.findings.v1",
    raw: [importedAlert()],
  },
  ...awsReaderUpgrades.map((upgrade) => ({
    ...upgrade,
    format: "security.findings.v1" as const,
    jobVersion: 2 as const,
  })),
  { provider: "snyk", format: "security.findings.v1", raw: snykSarif() },
  {
    provider: "endor",
    format: "security.findings.v1",
    raw: [
      {
        uuid: "malware-example",
        meta: { name: "Malicious package" },
        spec: {
          project_uuid: "project",
          target_dependency_package_name: "npm://example@1.0.0",
          finding_metadata: { malware: { meta: { name: "MAL-2099-0001" } } },
        },
      },
    ],
    normalizePrevious: (report: unknown) =>
      normalizePreviousEndorFindings(report),
    previousSha256:
      "a6a869d6ac1ac02acf44849bbd55d571e350ff9ef3c8ca8562891eb8cdd64708",
  },
  {
    provider: "endor",
    format: "security.findings.v1",
    raw: boundEndorSarif,
    rename: true,
  },
  {
    provider: "endor",
    format: "endor.findings_json.v1",
    raw: { list: { objects: [endorFinding()] } },
  },
  {
    provider: "wiz",
    format: "wiz.vulnerability_json.v1",
    raw: [
      {
        id: "occurrence-1",
        name: "CVE-2099-0001",
        detailedName: "example-package",
        vendorSeverity: "HIGH",
        vulnerableAsset: { id: "asset-1" },
      },
    ],
  },
] as const)(
  "a signed-in $provider private import resumes lost upload and job responses",
  async (scenario) => {
    const { provider, format, raw } = scenario;
    const sourceRepositoryUrl =
      "sourceRepositoryUrl" in scenario
        ? scenario.sourceRepositoryUrl
        : undefined;
    const f = await fixture(raw);
    const originalBytes = await readFile(f.file, "utf8");
    const settings = {
      ...options,
      provider,
      sourceRepositoryUrl,
      ...(provider === "trivy" && { trivyScanRoot: "." }),
    };
    let contextVersion = "generation-a";
    let formats = [
      "security.findings.v1",
      "endor.findings_json.v1",
      "wiz.vulnerability_json.v1",
    ];
    let expectedFormat: typeof format = format;
    let loseResponses = true;
    let unavailable = false;
    let terminal: "completed" | "failed" | "cancelled" = "completed";
    let advertised = false;
    const v1Jobs = "/finding-imports/jobs";
    const jobVersion =
      "jobVersion" in scenario ? scenario.jobVersion : undefined;
    const requestedVersion = String(jobVersion ?? 2);
    const versionedJobs = jobVersion ? `/v${jobVersion}${v1Jobs}` : v1Jobs;
    const upgrade = provider === "inspector" || provider === "checkmarx";
    // An older acknowledgement also keeps the provider on its unversioned route.
    let acknowledgedVersion = upgrade ? undefined : requestedVersion;
    if (provider === "checkmarx") acknowledgedVersion = "2";
    let expectedJobsPath = upgrade ? v1Jobs : versionedJobs;
    let canCreate = true;
    let reportCount = 1;
    let unorderedUpdates = 0;
    const uploadedReports: { id: string; bytes: string }[] = [];
    let jobRequest: string | undefined;
    let loseNextJobResponse = true;
    const jobBodies: string[] = [];
    const fileId = "aifile_" + "a".repeat(32);
    let jobId = "import_" + "b".repeat(32);
    const calls: string[] = [];
    const fileMetadata = () =>
      privateFileMetadata(fileId, uploadedReports.at(-1)!.bytes);
    const jobFields = () => privateJobFields(provider, fileId, expectedFormat);
    const job = (status: string) =>
      privateJobReceipt(
        { ...jobFields(), request_id: jobRequest },
        jobId,
        status,
        reportCount,
        unorderedUpdates,
      );
    const deps = {
      ...f.deps,
      fetch: async (url: string, init: RequestInit) => {
        const path = new URL(url).pathname.replace("/backend-api/aardvark", "");
        expect(new Headers(init.headers).get("Authorization")).toBe(
          "Bearer synthetic-token",
        );
        expect(new Headers(init.headers).get("ChatGPT-Account-ID")).toBe(
          "synthetic-account",
        );
        expect(init.redirect).toBe("error");
        calls.push(`${init.method} ${path}`);
        if (path === "/external/repositories") {
          const response = await f.deps.fetch(url, init);
          const headers = new Headers();
          if (advertised)
            headers.set("Codex-Security-Private-Import-Providers", provider);
          const version = "Codex-Security-Private-Import-Job-Version";
          expect(new Headers(init.headers).get(version)).toBe(requestedVersion);
          if (acknowledgedVersion) headers.set(version, acknowledgedVersion);
          return new Response(response.body, { headers });
        }
        if (path.startsWith("/external/")) return f.deps.fetch(url, init);
        if (path === "/finding-imports/context")
          return privateInboxContext(contextVersion, formats, canCreate);
        if (path === "/finding-imports/files") {
          const form = init.body as FormData;
          expect(form.get("context_version")).toBe(contextVersion);
          expect(form.get("purpose")).toBe("report");
          const id = String(form.get("request_id"));
          const bytes = await (form.get("file") as Blob).text();
          if (expectedFormat === "security.findings.v1") {
            const doc = JSON.parse(bytes);
            expect(doc.format).toBe(expectedFormat);
            expect(doc.findings[0].source_finding_id).toBeTruthy();
            expect(doc.findings[0].evidence.source_data).toBeTruthy();
            reportCount = doc.findings.length;
            if ("retained" in scenario) {
              expect(doc.findings).toHaveLength(1);
              expect(doc.findings[0].evidence.source_data).toMatchObject(
                scenario.retained,
              );
            }
            if (provider === "inspector" || provider === "continuum") {
              const native = provider === "inspector" ? raw.findings : [raw];
              const expected = loseResponses ? native.slice(0, 1) : native;
              expect(doc.findings).toHaveLength(expected.length);
              for (const row of expected) {
                const finding = doc.findings.find(
                  (item: { source_finding_id: string }) =>
                    item.source_finding_id === row.findingArn,
                );
                expect(finding?.evidence.source_data.finding).toEqual(row);
              }
            }
          } else {
            expect(bytes).toBe(originalBytes);
          }
          uploadedReports.push({ id, bytes });
          if (loseResponses && uploadedReports.length === 1)
            throw new Error("lost upload response");
          return Response.json(fileMetadata());
        }
        const fileRequest = uploadedReports.at(-1)?.id;
        if (path === `/finding-imports/file-requests/${fileRequest}`) {
          if ("previousSha256" in scenario && uploadedReports.length === 1)
            return new Response(null, { status: 404 });
          return Response.json(fileMetadata());
        }
        if (path === expectedJobsPath) {
          jobBodies.push(String(init.body));
          const body = JSON.parse(String(init.body));
          expect(body.request_id).not.toBe(fileRequest);
          expect(body).toEqual({
            request_id: body.request_id,
            context_version: contextVersion,
            ...jobFields(),
          });
          if (!loseResponses) {
            expect(body.request_id).not.toBe(jobRequest);
            jobRequest = body.request_id;
            jobId =
              terminal === "completed"
                ? "import_" + "d".repeat(32)
                : "import_" + "c".repeat(32);
            return Response.json(job(terminal));
          }
          if (jobRequest) expect(body.request_id).toBe(jobRequest);
          jobRequest = body.request_id;
          if (loseNextJobResponse) {
            loseNextJobResponse = false;
            throw new Error("lost job response");
          }
          return Response.json(job("queued"), {
            headers: { "Retry-After": "0" },
          });
        }
        if (path === `${expectedJobsPath}/${jobId}`)
          return unavailable
            ? new Response(null, { status: 503 })
            : Response.json(job(terminal));
        throw new Error("Unexpected route: " + path);
      },
    };
    const prepare = () => prepareExternalPublication(f.file, settings, deps);
    const repositoryPreview = await prepare();
    f.state.environmentId = null;
    advertised = true;
    const original = await prepare();
    expect(original.preview.privateImport?.sha256).toBeTruthy();
    expect(original.preview.privateImport?.format).toBe(format);
    const cli = createCliTest(main);
    const dryRun = [...f.command, "--dry-run"];
    if (provider === "trivy") dryRun.push("--trivy-scan-root", ".");
    if (sourceRepositoryUrl)
      dryRun.push("--source-repository-url", sourceRepositoryUrl);
    dryRun[dryRun.indexOf("--provider") + 1] = provider;
    dryRun[dryRun.indexOf("--format") + 1] = "toon";
    expect(
      await cli.runCli(dryRun, { ...f.cliDeps, cloudFetch: deps.fetch }),
    ).toBe(0);
    expect(cli.stderr.text()).toContain(
      `Report: ${format} (${original.preview.privateImport?.bytes} bytes)`,
    );
    if (format === "endor.findings_json.v1") {
      const supported = formats;
      formats = [format];
      expect((await prepare()).preview.privateImport?.format).toBe(format);
      formats = supported;
    }
    expect(calls.filter((call) => call.startsWith("POST"))).toEqual([]);
    contextVersion = "generation-b";
    await expect(original.publish()).rejects.toThrow("private inbox changed");
    canCreate = false;
    await expect(prepare()).rejects.toThrow("unavailable");
    canCreate = true;
    const staged =
      "normalizePrevious" in scenario && scenario.normalizePrevious
        ? await prepareNormalizedExternalPublication(
            JSON.parse(
              JSON.stringify(
                scenario.normalizePrevious(raw, sourceRepositoryUrl ?? ""),
              ),
            ),
            settings,
            deps,
          )
        : await prepare();
    const interrupted = await staged.publish().catch((error: unknown) => error);
    if (!(interrupted instanceof ExternalPublicationError))
      throw new Error("Expected an interrupted private upload", {
        cause: interrupted,
      });
    expect(interrupted.message).toContain("lost upload response");
    const saved = JSON.parse(
      await readFile(interrupted.result.savedSubmission!, "utf8"),
    );
    expect(saved).toMatchObject({
      sha256: fileMetadata().sha256,
      uploadRequestId: uploadedReports.at(-1)!.id,
    });
    expect(saved.jobApiVersion).toBe(upgrade ? undefined : jobVersion);
    if ("previousSha256" in scenario) {
      expect(saved.sha256).toBe(scenario.previousSha256);
      expect(saved.sha256).not.toBe(original.preview.privateImport?.sha256);
    }
    await expect(repositoryPreview.publish()).rejects.toThrow(
      "previousSha256" in scenario
        ? "Another publication prepared this input"
        : "A private import already owns this selection",
    );
    expect(f.posts).toHaveLength(0);
    if ("rename" in scenario) {
      f.state.repositoryUrl = "https://github.com/example/renamed";
      expect(saved.approvedRepositoryUrl).toBe(exampleRepository);
      // Earlier checkpoints bound the immutable report and connector ID only.
      const { approvedRepositoryUrl, ...legacy } = saved;
      const path = interrupted.result.savedSubmission!;
      const pending = await prepare();
      await rm(path);
      await expect(pending.publish()).rejects.toThrow(
        "saved private import changed",
      );
      await writeFile(path, JSON.stringify(legacy), { mode: 0o600 });
      expect((await prepare()).preview.resumed).toBe(true);
      await writeFile(path, JSON.stringify(saved));
    }
    advertised = false;
    const resumed = await prepare();
    expect(resumed.preview.resumed).toBe(true);
    expect(resumed.preview.privateImport?.sha256).toBe(saved.sha256);
    await expect(resumed.publish()).rejects.toThrow("lost job response");
    expect(jobRequest).toBe(saved.jobRequestId);
    expect(calls.at(-1)).toBe(`POST ${expectedJobsPath}`);
    if (upgrade) {
      // The upgraded server accepts the same approved request on its new route.
      acknowledgedVersion = requestedVersion;
      expectedJobsPath = versionedJobs;
      loseNextJobResponse = true;
      await expect((await prepare()).publish()).rejects.toThrow(
        "lost job response",
      );
      expect(calls.at(-1)).toBe(`POST ${versionedJobs}`);
      expect(jobBodies).toHaveLength(2);
      expect(jobBodies[1]).toBe(jobBodies[0]);
      const promoted = JSON.parse(
        await readFile(interrupted.result.savedSubmission!, "utf8"),
      );
      expect(promoted).toMatchObject({
        jobApiVersion: jobVersion,
        jobRequestId: saved.jobRequestId,
        uploadRequestId: saved.uploadRequestId,
        sha256: saved.sha256,
        fileId,
      });
    }
    // Saved jobs retain their route if the catalogue acknowledgement disappears.
    acknowledgedVersion = undefined;
    const completed = await (await prepare()).publish();
    expect(completed.privateJob?.counts.created).toBe(1);
    expect(calls.at(-1)).toBe(`GET ${expectedJobsPath}/${jobId}`);
    expect(completed.receipts).toEqual([]);
    expect(completed.verified).toBe(0);
    if ("previousSha256" in scenario) {
      expect(uploadedReports).toHaveLength(2);
      expect(uploadedReports[1]).toEqual(uploadedReports[0]);
    } else {
      expect(uploadedReports).toHaveLength(1);
    }
    if (provider === "inspector") {
      // A completed old job cannot account for the newly admitted package finding.
      advertised = true;
      acknowledgedVersion = requestedVersion;
      loseResponses = false;
      const next = await prepare();
      expect(next.preview.resumed).toBe(false);
      expect(next.preview.privateImport?.sha256).toBe(
        original.preview.privateImport?.sha256,
      );
      // The code finding's changed evidence has no baseline. Only the new ARN
      // can be created in this workspace.
      unorderedUpdates = 1;
      const nextResult = await next.publish();
      expect(nextResult.privateJob?.id).not.toBe(completed.privateJob?.id);
      expect(nextResult.privateJob?.counts).toMatchObject({
        created: 1,
        error: 1,
      });
    }
    canCreate = false;
    advertised = false;
    acknowledgedVersion = requestedVersion;
    expect((await (await prepare()).publish()).privateJob?.id).toBe(jobId);
    expect(calls.at(-1)).toBe(`GET ${expectedJobsPath}/${jobId}`);
    unavailable = true;
    const acknowledged = {
      result: {
        status: "interrupted",
        counts: { created: reportCount - unorderedUpdates },
        unacknowledged: 0,
        privateJob: { id: jobId },
      },
    };
    await expect((await prepare()).publish()).rejects.toMatchObject(
      acknowledged,
    );
    unavailable = false;

    // The same context retains its native wire representation even if discovery changes.
    formats = ["security.findings.v1"];
    expect((await prepare()).preview.privateImport?.format).toBe(
      expectedFormat,
    );
    contextVersion = "generation-c";
    expectedJobsPath = versionedJobs;
    unorderedUpdates = 0;
    advertised = true;
    canCreate = true;
    loseResponses = false;
    expectedFormat = "security.findings.v1";
    terminal =
      provider === "wiz" || provider === "continuum" ? "cancelled" : "failed";
    if ("rename" in scenario) {
      await expect(prepare()).rejects.toThrow("does not match");
      f.state.repositoryUrl = exampleRepository;
    }
    const fresh = await prepare();
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.privateImport?.format).toBe(expectedFormat);
    if ("previousSha256" in scenario)
      expect(fresh.preview.privateImport?.sha256).toBe(
        original.preview.privateImport?.sha256,
      );
    expect((await fresh.publish()).privateJob?.status).toBe(terminal);
    expect(fresh.preview.privateImport?.sha256).toBe(fileMetadata().sha256);
    const failedJob = jobId;
    // The saved receipt remains readable after this provider drops out of discovery.
    advertised = false;
    acknowledgedVersion = undefined;
    const before = calls.length;
    const readOnly = await prepare();
    expect(readOnly.preview.privateImport?.retryOfJobId).toBeUndefined();
    expect((await readOnly.publish()).privateJob).toMatchObject({
      id: failedJob,
      status: terminal,
    });
    expect(calls.at(-1)).toBe(`GET ${expectedJobsPath}/${failedJob}`);
    contextVersion = "different-inbox";
    await expect(prepare()).rejects.toThrow(
      "Private findings import is unavailable",
    );
    expect(
      calls.slice(before).filter((call) => call.startsWith("POST")),
    ).toEqual([]);
    contextVersion = "generation-c";
    advertised = true;
    acknowledgedVersion = undefined; // The saved version also applies to its replacement attempt.
    if ("rename" in scenario) {
      f.state.repositoryUrl = "https://github.com/example/renamed";
      await expect(prepare()).rejects.toThrow("does not match");
      f.state.repositoryUrl = exampleRepository;
    }
    const retry = await prepare();
    const secondPreview = await prepare();
    expect(retry.preview).toMatchObject({
      resumed: false,
      privateImport: { retryOfJobId: failedJob },
    });

    // A terminal response still acknowledges the report if saving its receipt fails.
    terminal = "completed";
    const rename = fs.rename;
    const fault = spyOn(fs, "rename").mockImplementation(async (from, to) => {
      if (
        String(to).endsWith(".private-import.json") &&
        JSON.parse(await readFile(from, "utf8")).receipt?.status === "completed"
      )
        throw new Error("Checkpoint interrupted");
      return rename(from, to);
    });
    try {
      await expect(retry.publish()).rejects.toMatchObject({
        result: {
          status: "interrupted",
          counts: { created: reportCount },
          unacknowledged: 0,
          privateJob: { status: "completed" },
        },
      });
    } finally {
      fault.mockRestore();
    }
    // A second preview of the failed job replays the already-started replacement.
    loseResponses = true;
    const priorUploads = uploadedReports.length;
    expect((await secondPreview.publish()).privateJob?.id).not.toBe(failedJob);
    expect(uploadedReports).toHaveLength(priorUploads);
  },
);

function privateJobFields(provider: string, fileId: string, format: string) {
  return {
    source: { provider, source_key: options.sourceKey },
    input: { type: "file", file_id: fileId, format },
    default_targets: [
      {
        type: "repository",
        repo_id: options.repository,
        repo_connector_id: "github",
      },
    ],
  };
}

function privateFileMetadata(id: string, bytes: string) {
  return {
    object: "security.finding_import_file",
    id,
    purpose: "report",
    sha256: hash("sha256", bytes),
    bytes: Buffer.byteLength(bytes),
  };
}

function privateJobReceipt(
  request: object,
  id: string,
  status = "completed",
  total = 1,
  errors = 0,
) {
  const processed = status === "completed" ? total : 0;
  const error = status === "completed" ? errors : 0;
  return {
    ...request,
    object: "security.finding_import_job",
    id,
    status,
    counts: {
      total,
      discovered: total,
      created: processed - error,
      updated: 0,
      unchanged: 0,
      error,
      unprocessed: total - processed,
    },
    poll_after_seconds: null,
    error: null,
  };
}

function privateInboxContext(
  context_version = "generation-a",
  formats = ["security.findings.v1"],
  canCreate = true,
) {
  return Response.json({
    object: "security.finding_import_context",
    context_version,
    can_read: true,
    can_upload: canCreate,
    can_create_import_jobs: canCreate,
    formats,
    limits: {
      max_direct_file_bytes: 32 * 1024 * 1024,
      max_record_bytes: 1024 * 1024,
    },
  });
}

test.each([
  {
    data: checkmarxFormat,
    report: { sourceRepositoryUrl: exampleRepository, scanId: "123" },
    key: "0b6db48e67edf53d39403c9fd1897c34a179edf5b6cce9bffabc9f52f8757f33",
    sha256: "8b0e177506af75c363184d3627fed74325acfcada7e3ee8e9d81041c5db5b2d1",
  },
  {
    data: { vulnerableAsset: wizBranchAsset },
    report: checkmarxFormat,
    key: "7400c077334e75f2b1ca49f05eb5cc4f431b62a9f2063734f42a03d60500ea5e",
    sha256: "bf944f1fec0d2f97675f35dc8db1bee753807879fa6077e2bd8c5169889ce7ae",
  },
  {
    data: { sourceRepositoryUrl: exampleRepository },
    report: checkmarxFormat,
    key: "0c9c5eef708bb27f19dcaebb67832cc6dcd43bfbf9dee0f0d4c4d2da9145ffa8",
    sha256: "2ae1422cd86875a7be2d73f2dc8f6833e494668f6e4be9982c403d336557ef9f",
  },
])(
  "only a verified private Wiz checkpoint replays pre-Checkmarx evidence ($data)",
  async ({ data, report, key, sha256 }) => {
    const { f, deps, inbox, jobs } = await privateUploadFixture([], "wiz");
    f.state.catalogHeaders = {}; // Recovery must also work after discovery stops advertising Wiz.
    const selection = sdkSelection(
      [sdkRow(normalized().source_finding_id, data)],
      report,
    );
    const source = {
      provider: options.provider,
      source_key: options.sourceKey,
    };
    const repository = { id: options.repository, repo_connector_id: "github" };
    const checkpoint = {
      format: "security.findings.v1",
      apiBaseUrl: "https://chatgpt.com/backend-api/aardvark",
      accountId: "synthetic-account",
      contextVersion: "generation-a",
      source,
      repository,
      sha256,
      uploadRequestId: "ff52f1ac-ee15-4126-a3f4-bc9984fa0c51",
      jobRequestId: "a942a3d4-ad70-4b4d-aaca-4e1e2b70cb20",
      fileId: "aifile_" + "a".repeat(32),
    };
    const path = await f.writeCheckpoint(
      key + ".private-import.json",
      checkpoint,
    );
    const prepare = () =>
      prepareNormalizedExternalPublication(selection, options, {
        ...deps,
        environment: {
          ...f.environment,
          CODEX_SECURITY_CLOUD_BASE_URL: undefined,
          CODEX_SECURITY_CLOUD_WEB_URL: undefined,
        },
      });
    inbox.version = "different-inbox";
    await expect(prepare()).rejects.toThrow("requires the checkmarx provider");
    inbox.version = checkpoint.contextVersion;
    f.state.repositoryUrl = otherRepository;
    await expect(prepare()).rejects.toThrow(/belongs to|does not match/);
    f.state.repositoryUrl = exampleRepository;
    const resumed = await prepare();
    expect(resumed.preview.resumed).toBe(true);
    expect(resumed.preview.privateImport?.sha256).toBe(checkpoint.sha256);
    expect((await resumed.publish()).counts.created).toBe(1);
    expect(jobs).toEqual([
      {
        request_id: checkpoint.jobRequestId,
        context_version: inbox.version,
        ...privateJobFields("wiz", checkpoint.fileId, checkpoint.format),
      },
    ]);
    await rm(path);
    await expect(resumed.publish()).rejects.toThrow(
      "requires the checkmarx provider",
    );
    await expect(prepare()).rejects.toThrow("requires the checkmarx provider");
    expect(jobs).toHaveLength(1);
  },
);

test("a private preview recognizes a later repository checkpoint under its historical filename", async () => {
  const { f, deps, uploads, jobs } = await privateUploadFixture([], "wiz");
  const privatePreview = await prepareNormalizedExternalPublication(
    scoredFindings(2.5),
    options,
    deps,
  );
  f.state.catalogHeaders = {};
  const repository = await prepareNormalizedExternalPublication(
    scoredFindings(new Number(2.5)),
    options,
    f.deps,
  );
  f.state.throttle = true;
  await expect(repository.publish()).rejects.toThrow("Slow down");
  await expect(privatePreview.publish()).rejects.toThrow(
    "A repository submission is pending",
  );
  expect(uploads).toHaveLength(0);
  expect(jobs).toHaveLength(0);
  expect(f.posts).toHaveLength(1);
});

test("a private structured report retains occurrence IDs, unknown severity and source lines", () => {
  const input = [
    {
      source_finding_id: "original-occurrence",
      evidence: {
        title: "Synthetic code finding",
        severity: "unknown" as const,
        locations: [
          { path: "src/sample.ts", line: 7 },
          { path: "src/other.ts", line: 10 },
        ],
        details: { kind: "sast" as const, code: { end_line: 9 } },
        source_data: { occurrence: "original-occurrence" },
      },
    },
  ];
  const limits = { max_record_bytes: 4096, max_direct_file_bytes: 8192 };
  const report = privateReport(input, limits);
  const record = JSON.parse(report.bytes).findings[0];
  expect(record.source_finding_id).toBe(input[0]!.source_finding_id);
  expect(record.evidence.severity).toBeNull();
  expect(record.evidence.locations).toEqual([
    { path: "src/sample.ts", start_line: 7, end_line: 9 },
    { path: "src/other.ts", start_line: 10 },
  ]);
  expect(record.evidence.source_data).toEqual(input[0]!.evidence.source_data);
  expect(privateReport(input, limits).digest).toBe(report.digest);
  expect(() =>
    privateReport(input, { ...limits, max_record_bytes: 32 }),
  ).toThrow("record limit");
});

test("filtered, unsupported and changed files never upload an unreviewed native record", async () => {
  const raw = endorFinding();
  const f = await fixture(raw);
  const selection = normalizeEndorFindings(raw);
  const context = {
    object: "security.finding_import_context" as const,
    context_version: "v1",
    can_upload: true,
    can_create_import_jobs: true,
    can_read: true,
    formats: ["security.findings.v1", "endor.findings_json.v1"],
    limits: {
      max_direct_file_bytes: 32 * 1024 * 1024,
      max_record_bytes: 1024 * 1024,
    },
  };
  const select = (findings = selection, formats = context.formats) =>
    selectPrivateReport(
      findings,
      "endor",
      f.file,
      { ...context, formats },
      undefined,
    );
  expect((await select()).format).toBe("endor.findings_json.v1");
  expect((await select(selection, ["security.findings.v1"])).format).toBe(
    "security.findings.v1",
  );
  expect(
    (
      await select({
        ...selection,
        read: 2,
        excluded: [
          { position: 2, source_finding_id: null, reason: "excluded" },
        ],
      })
    ).format,
  ).toBe("security.findings.v1");
  await writeFile(
    f.file,
    JSON.stringify({ list: { objects: [raw] }, unreviewed: "omitted" }),
  );
  expect((await select()).bytes).not.toContain("unreviewed");
  await writeFile(
    f.file,
    JSON.stringify({ ...raw, meta: { ...raw.meta, name: "unreviewed" } }),
  );
  expect((await select()).bytes).not.toContain("unreviewed");
});
