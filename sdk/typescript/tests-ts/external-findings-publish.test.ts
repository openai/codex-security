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
import { normalizeEndorFindings } from "../src/endor-findings.js";
import { normalizeOpenGrepFindings } from "../src/opengrep-findings.js";
import { normalizeArmorCodeFindings } from "../src/armorcode-findings.js";
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
import { basename, dirname, join } from "node:path";
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
  type NormalizedExternalPublicationOptions,
  type PreparedExternalPublication,
} from "../src/external-findings-publish.js";
import { canonicalJson } from "../src/record.js";
import {
  normalizeSemgrepPlatformFindings,
  selectSemgrepPlatformFindings,
  semgrepPlatformFormat,
} from "../src/semgrep-platform-findings.js";
import { normalizeSemgrepFindings } from "../src/semgrep-findings.js";
import { collectSemgrepPlatformFindings } from "../src/semgrep-platform-collector.js";
import { normalizeSnykIssues } from "../src/snyk-rest-findings.js";
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
import { readTenableFindings } from "../src/tenable-findings.js";
import { tenableReport } from "./support/tenable-import-fixtures.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import {
  EXTERNAL_FINDINGS_READERS,
  type ExternalFindingsReader,
} from "../src/external-findings-read.js";
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
import { githubDependabotAlert } from "./support/github-dependabot-fixtures.js";
import {
  importedAlert,
  importedAdvisory,
} from "./support/github-import-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { normalizeTrivyFindings } from "../src/trivy-findings.js";
import { normalizeInspectorFindings } from "../src/inspector-findings.js";
import {
  trivyReport,
  trivyReportWithManyLocations,
  trivyRepositoryHeader,
} from "./support/trivy-import-fixtures.js";
import {
  prepareNormalizedLocalImport,
  type LocalExternalFindingSelection,
} from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  collectSelectedSemgrepGuardianFindings,
  listLocalExternalFindings,
  listLocalFindingPublications,
  prepareLocalExternalImport,
  prepareStoredFindingsPublication,
} from "../src/index.js";
import {
  inspectorReport,
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";
import {
  continuumDetail,
  continuumEvidenceArtifact,
  continuumIssueExport,
  continuumRepository,
  continuumValidationArtifact,
  patchArtifact,
} from "./support/continuum-import-fixtures.js";
import { normalizeBlackDuckFindings } from "../src/blackduck-findings.js";
import { normalizeVeracodeFindings } from "../src/veracode-findings.js";
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
const scannerMediaType =
  "application/vnd.openai.codex-security.scanner-imports.v1+json";
const jobVersionHeader = "Codex-Security-Private-Import-Job-Version";
const scopeHeader = "Codex-Security-Import-Scope";
const providerHeader = "Codex-Security-Private-Import-Providers";
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

test("ArmorCode rejects generic rows from a different Cloud repository before publishing", async () => {
  const sourceRepositoryUrl = "https://github.com/example/project";
  const report = {
    data: {
      findings: [
        {
          id: 1,
          title: "Unchecked index",
          scanType: ["SAST"],
          repositoryUrl: sourceRepositoryUrl,
        },
        {
          id: 2,
          title: "Vulnerable package",
          scanType: ["SCA"],
          repositoryUrl: "https://github.com/example/other",
        },
      ],
    },
  };
  const f = await fixture(report, sourceRepositoryUrl);
  const selection = {
    ...options,
    provider: "armorcode" as const,
    sourceRepositoryUrl,
  };
  await expect(
    prepareExternalPublication(f.file, selection, f.deps),
  ).rejects.toThrow("does not match the selected Cloud repository");
  await expect(
    prepareNormalizedExternalPublication(
      normalizeArmorCodeFindings(report),
      selection,
      f.deps,
    ),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.posts).toHaveLength(0);
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
    catalogMediaType: scannerMediaType,
    catalogHeaders: { [scopeHeader]: "personal" } as Record<string, string>,
    sourceLookups: [] as string[],
    postBudget: Infinity,
    conflictingFindingId: undefined as string | undefined,
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
    if (!response.hasHeader("Content-Type"))
      response.setHeader("Content-Type", "application/json");
    response.writeHead(status);
    response.end(JSON.stringify(value));
  }
  const server = createServer(async (incoming, response) => {
    try {
      expect(incoming.headers.authorization).toBe("Bearer synthetic-token");
      expect(incoming.headers["chatgpt-account-id"]).toBe("synthetic-account");
      const url = new URL(incoming.url!, "http://localhost");
      if (url.pathname.endsWith("/repositories")) {
        state.catalogReads++;
        expect(incoming.headers.accept).toBe(
          scannerMediaType + ", application/json;q=0.9",
        );
        response.setHeader("Content-Type", state.catalogMediaType);
        for (const [name, value] of Object.entries(state.catalogHeaders))
          response.setHeader(name, value);
        return json(response, {
          object: "page",
          data: [destination()],
          has_more: false,
          next: null,
        });
      }
      expect(incoming.headers.accept).toBe(state.catalogMediaType);
      if (incoming.method === "POST")
        expect(incoming.headers["content-type"]).toBe(state.catalogMediaType);
      response.setHeader("Content-Type", state.catalogMediaType);
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
        if (
          state.conflictingFindingId &&
          request.items.some(
            (item) => item.source_finding_id === state.conflictingFindingId,
          )
        )
          return json(
            response,
            { error: { message: "stale expected version" } },
            409,
          );
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

test.each([0, 1])(
  "stored Trivy and Guardian findings survive source deletion and a lost Cloud response in group %i",
  async (index) => {
    const cloud = await fixture();
    await using local = await storedPublicationFixture(cloud);
    const { repository, deps } = local;
    const report = trivyReport();
    report.Results.push({
      ...structuredClone(report.Results[0]!),
      Target: "packages/other/package-lock.json",
    });
    const trivyFile = cloud.file;
    await writeFile(trivyFile, JSON.stringify(report));
    const prepareTrivy = () =>
      prepareLocalExternalImport(
        trivyFile,
        {
          repository,
          provider: "trivy",
          sourceKey: "npm/main",
          trivyScanRoot: ".",
        },
        deps,
      );
    expect((await (await prepareTrivy()).import()).counts.created).toBe(2);
    report.Results[0]!.Vulnerabilities[0]!.Title = "Updated local evidence";
    await writeFile(trivyFile, JSON.stringify(report));
    expect((await (await prepareTrivy()).import()).counts).toEqual({
      created: 0,
      updated: 1,
      unchanged: 1,
    });
    await rm(trivyFile);

    const examples = new URL(
      "../../../examples/normalized-import/",
      import.meta.url,
    );
    const readExample = async (name: string) =>
      JSON.parse(await readFile(new URL(name, examples), "utf8"));
    const guardian = await collectSelectedSemgrepGuardianFindings(
      await readExample("guardian-selection.json"),
      { callTool: () => readExample("guardian-response.json") },
    );
    const guardianImport = await local.store(
      "semgrep",
      normalizeSemgrepFindings(guardian, {}, "local"),
    );
    expect(guardianImport.counts.created).toBe(1);

    const rows = await listLocalExternalFindings({ repository }, deps);
    const selected = [
      rows.find((row) => row.provider === "trivy" && row.version === 2)!,
      rows.find((row) => row.provider === "semgrep")!,
    ];
    const selection = {
      repository,
      findings: selected.map(({ id, version }) => ({ id, version })),
    };
    const { groups } = await local.prepare(selection);
    expect(groups).toHaveLength(2);
    const reviewedEnvironment = cloud.state.environmentId;
    cloud.state.environmentId = "different-environment";
    const changed = await local.prepare(selection);
    await expect(
      changed.groups[0]!.publish(groups[0]!.reviewId),
    ).rejects.toThrow(/review/i);
    cloud.state.environmentId = reviewedEnvironment;
    expect(cloud.posts).toHaveLength(0);

    // The caller saves the reviewed selections before sending through the existing transport.
    for (const group of groups.slice(0, index))
      expect((await group.publish(group.reviewId)).status).toBe("complete");
    cloud.state.loseResponse = true;
    const interrupted = groups[index]!;
    await expect(
      interrupted.publish(interrupted.reviewId),
    ).rejects.toMatchObject({
      result: { status: "interrupted" },
    });
    expect(cloud.posts).toHaveLength(index + 1);
    const lost = cloud.posts[index]!;
    if (index === 1) {
      const completed = (await local.prepare(groups[0]!.selection)).groups[0]!;
      await expect(completed.publish(groups[0]!.reviewId)).rejects.toThrow(
        /review/i,
      );
    }

    for (const group of groups.slice(index)) {
      const retry = await local.prepare(group.selection);
      expect(retry.groups).toHaveLength(1);
      const resumed = retry.groups[0]!;
      // Changing the display copy cannot redirect the approved request or its receipt.
      resumed.preview.findings[0]!.source_finding_id = "different-id";
      resumed.preview.destination.id = "different-destination";
      expect((await resumed.publish(group.reviewId)).status).toBe("complete");
    }
    expect(cloud.posts).toHaveLength(3);
    expect(cloud.posts.filter((body) => body === lost)).toHaveLength(2);
    expect(cloud.reports.size).toBe(2);
    const history = await listLocalFindingPublications({ repository }, deps);
    expect(history).toHaveLength(2);
    for (const row of selected) {
      const remoteRow = cloud.reports.get(row.sourceFindingId)!;
      expect(remoteRow).toMatchObject({
        source: { provider: row.provider, source_key: row.sourceKey },
        source_finding_id: row.sourceFindingId,
        version: 1,
        evidence: { title: row.evidence.title },
      });
      const link = history.find((item) => item.id === row.id)!;
      expect(link).toMatchObject({
        version: row.version,
        outcome: "created",
        cloudFindingId: remoteRow.canonical_finding_id,
        destinationId: options.repository,
      });
      expect(cloud.receipts.has(link.receiptId)).toBe(true);
    }
    expect(await listLocalExternalFindings({ repository }, deps)).toEqual(rows);
  },
);

test.each(["complete", "conflict"])(
  "stored publication recovers SQLite receipts before retiring a %s submission",
  async (finish) => {
    const cloud = await fixture();
    const rows = Array.from(
      { length: finish === "conflict" ? 101 : 1 },
      (_, i) => localFinding("row-" + i),
    );
    if (finish === "conflict") cloud.state.conflictingFindingId = "row-100";
    await using local = await storedPublicationFixture(cloud);
    const imported = await local.store("wiz", {
      read: rows.length,
      findings: rows,
      excluded: [],
    });
    const { repository } = local;
    const [group] = (
      await local.prepare({ repository, importId: imported.importId! })
    ).groups;
    using database = new Database(
      join(local.stateDirectory, "workbench.sqlite3"),
    );
    database.exec(`CREATE TRIGGER reject_receipts BEFORE INSERT ON external_finding_publications
      BEGIN SELECT RAISE(ABORT, 'receipt write interrupted'); END`);
    await expect(group!.publish(group!.reviewId)).rejects.toThrow(
      /receipt write interrupted/,
    );
    expect(cloud.receipts.size).toBe(1);
    const [originalReceiptId] = cloud.receipts.keys();
    expect(
      await listLocalFindingPublications({ repository }, local.deps),
    ).toEqual([]);
    database.exec("DROP TRIGGER reject_receipts");
    cloud.state.conflictingFindingId = undefined;

    const [retry] = (await local.prepare(group!.selection)).groups;
    expect(retry!.reviewId).toBe(group!.reviewId);
    const result = await retry!.publish(group!.reviewId);
    expect(result.status).toBe("complete");
    const firstBatch = cloud.posts[0]!;
    expect(cloud.posts.filter((body) => body === firstBatch)).toHaveLength(1);
    const links = await listLocalFindingPublications(
      { repository },
      local.deps,
    );
    expect(links).toHaveLength(rows.length);
    expect(links).toContainEqual(
      expect.objectContaining({
        id: imported.findings[0]!.id,
        receiptId: originalReceiptId,
        outcome: "created",
      }),
    );
  },
);

test("a reset retains the saved request until SQLite records its accepted receipt", async () => {
  const cloud = await fixture();
  await using local = await storedPublicationFixture(cloud);
  const imported = await local.store("wiz", {
    read: 1,
    findings: [localFinding("scope")],
    excluded: [],
  });
  const selection = {
    repository: local.repository,
    importId: imported.importId!,
  };
  const [group] = (await local.prepare(selection)).groups;
  using database = new Database(
    join(local.stateDirectory, "workbench.sqlite3"),
  );
  database.exec(
    "CREATE TRIGGER reject_links BEFORE INSERT ON external_finding_publications BEGIN SELECT RAISE(ABORT,'cannot record'); END",
  );
  await expect(group!.publish(group!.reviewId)).rejects.toThrow(
    "cannot record",
  );
  expect(cloud.posts).toHaveLength(1);
  const [receiptId] = cloud.receipts.keys();
  cloud.state.marker = "generation-2";
  cloud.reports.clear();
  await expect(local.prepare(selection)).rejects.toThrow("cannot record");
  database.exec("DROP TRIGGER reject_links");
  await expect(local.prepare(selection)).rejects.toThrow("reset");
  const links = await listLocalFindingPublications(
    { repository: local.repository },
    local.deps,
  );
  expect(links).toHaveLength(1);
  expect(links[0]?.receiptId).toBe(receiptId);
  const [fresh] = (await local.prepare(selection)).groups;
  await expect(fresh!.publish(group!.reviewId)).rejects.toThrow("changed");
  expect(cloud.posts).toHaveLength(1);
});

test("identical evidence at a later local version cannot inherit an earlier receipt", async () => {
  const cloud = await fixture();
  await using local = await storedPublicationFixture(cloud);
  const row = localFinding("pinned");
  const store = (finding: typeof row) =>
    local.store("wiz", { read: 1, findings: [finding], excluded: [] });
  const first = await store(row);
  const selection = (importId: string) => ({
    repository: local.repository,
    importId,
  });
  const [original] = (await local.prepare(selection(first.importId!))).groups;
  using database = new Database(
    join(local.stateDirectory, "workbench.sqlite3"),
  );
  database.exec(
    "CREATE TRIGGER reject_links BEFORE INSERT ON external_finding_publications BEGIN SELECT RAISE(ABORT,'cannot record'); END",
  );
  await expect(original!.publish(original!.reviewId)).rejects.toThrow(
    "cannot record",
  );
  database.exec("DROP TRIGGER reject_links");

  const direct = await prepareNormalizedExternalPublication(
    { read: 1, findings: [row], excluded: [] },
    { repository: options.repository, provider: "wiz", sourceKey: "selected" },
    local.deps,
  );
  expect(direct.preview.resumed).toBe(false);

  await store({
    ...row,
    evidence: { ...row.evidence, title: "Changed title" },
  });
  const restored = await store(row);
  expect(restored.findings[0]!.version).toBe(3);
  cloud.state.marker = "generation-2";
  cloud.reports.clear();
  const [current] = (await local.prepare(selection(restored.importId!))).groups;
  expect(current!.preview.resumed).toBe(false);
  await expect(current!.publish(original!.reviewId)).rejects.toThrow("changed");
  expect(
    await listLocalFindingPublications(
      { repository: local.repository },
      local.deps,
    ),
  ).toEqual([]);
  expect(cloud.posts).toHaveLength(1);
});

test("stored findings recover a private inbox upload and retain its job receipt", async () => {
  const { f, inbox, deps, uploads, jobs } = await privateUploadFixture(
    [],
    "wiz",
  );
  await using local = await storedPublicationFixture(f, deps.fetch);
  const { repository } = local;
  const row = localFinding();
  const imported = await local.store("wiz", {
    read: 1,
    findings: [row],
    excluded: [],
  });
  const selection = { repository, importId: imported.importId! };
  const [first] = (await local.prepare(selection)).groups;
  expect(first!.preview.privateImport).toBeDefined();
  expect(first!.selection).toEqual(selection);
  await expect(first!.publish(first!.reviewId)).rejects.toMatchObject({
    result: { status: "interrupted" },
  });
  expect(
    await listLocalFindingPublications({ repository }, local.deps),
  ).toEqual([]);
  inbox.recoverUpload = true;
  const [retry] = (await local.prepare(first!.selection)).groups;
  expect((await retry!.publish(first!.reviewId)).status).toBe("complete");
  expect(uploads).toHaveLength(1);
  expect(JSON.parse(uploads[0]!.bytes).findings[0].source_finding_id).toBe(
    row.source_finding_id,
  );
  expect(jobs).toHaveLength(1);
  const receipts = await listLocalFindingPublications(
    { repository },
    local.deps,
  );
  expect(receipts).toHaveLength(1);
  expect(receipts[0]).toMatchObject({
    id: imported.findings[0]!.id,
    version: 1,
    outcome: "private_job",
    destinationId: options.repository,
    receiptId: "import_" + "b".repeat(32),
  });
});

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
    if (advertised) delete f.state.catalogHeaders[header];
    else f.state.catalogHeaders[header] = severities;
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
          return Response.json(report, { headers: response.headers });
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

test.each([
  ["missing", {}],
  ["unknown", { [scopeHeader]: "organization" }],
  [
    "disabled workspace provider",
    { [scopeHeader]: "workspace", [providerHeader]: "snyk" },
  ],
] as [string, Record<string, string>][])(
  "discovery rejects %s without using the repository publisher",
  async (_, headers) => {
    const f = await fixture();
    f.state.catalogHeaders = headers;
    await expect(
      prepareExternalPublication(f.file, options, f.deps),
    ).rejects.toThrow(/scope|unavailable/iu);
    expect(f.state.sourceLookups).toEqual([]);
    expect(f.posts).toEqual([]);
  },
);

test("repository severity restrictions exclude unsupported rows before lookups; private imports retain them", async () => {
  const { f, prepareFile } = await privateUploadFixture(
    [normalized("unreported", "unknown")],
    "wiz",
  );
  f.state.catalogHeaders = {
    [scopeHeader]: "personal",
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
  f.state.catalogHeaders[scopeHeader] = "workspace";
  f.state.catalogHeaders[providerHeader] = "wiz";
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
  const counted = createCliTest(main);
  expect(await counted.runCli([...flags, "--token-count"], f.cliDeps)).toBe(2);
  const count = JSON.parse(counted.stdout.text());
  expect(count.error).toEqual(failure.error);
  expect(count.meta.tokenCount).toBeGreaterThan(5);
  expect(count).not.toHaveProperty("data");
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
  provider: FindingImportRequest["source"]["provider"],
  repositoryUrl?: string,
) {
  const f = await fixture(raw, repositoryUrl);
  const settings = { ...options, provider };
  f.state.catalogHeaders = {
    [scopeHeader]: "workspace",
    [providerHeader]: provider,
  };
  const inbox = {
    version: "original-inbox",
    formats: ["security.findings.v1"],
    recoverUpload: false,
    interruptUpload: true,
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
      if (pathname === "/backend-api/aardvark/finding-imports/jobs") {
        expect(init.method).toBe("POST");
        const job = JSON.parse(String(init.body));
        jobs.push(job);
        return Response.json(
          privateJobReceipt(job, "import_" + "b".repeat(32)),
          { headers: { "Content-Type": scannerMediaType } },
        );
      }
      if (pathname.endsWith("/finding-imports/files")) {
        const form = init.body as FormData;
        const bytes = await (form.get("file") as Blob).text();
        uploads.push({ id: String(form.get("request_id")), bytes });
        if (inbox.interruptUpload)
          throw new Error("Interrupted private upload");
        return Response.json(privateFileMetadata(fileId, bytes));
      }
      return f.deps.fetch(url, init);
    },
  };
  const prepareFile = () => prepareExternalPublication(f.file, settings, deps);
  return { f, settings, deps, inbox, uploads, jobs, fileId, prepareFile };
}

const tenableOptions = {
  ...options,
  provider: "tenable" as const,
  sourceRepositoryUrl: tenableReport.repository_url,
};

test("Tenable SDK retry publishes the approved file selection with the native occurrence ID and state", async () => {
  const capture = {
    ...tenableReport,
    findings: [{ ...tenableReport.findings[0]!, state: "FIXED" }],
  };
  const f = await fixture(capture, capture.repository_url);
  const first = await prepareExternalPublication(
    f.file,
    tenableOptions,
    f.deps,
  );
  expect(f.posts).toHaveLength(0);
  await f.loseResponse(first);
  f.state.repositoryUrl = "https://github.com/example/renamed";
  // SDK callers can retain the original row without carrying a file-level header.
  const { findings, read, excluded } = await readTenableFindings(
    f.file,
    capture.repository_url,
    "cloud",
  );
  const retry = await prepareNormalizedExternalPublication(
    { findings, read, excluded },
    tenableOptions,
    f.deps,
  );
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).verified).toBe(1);
  expect(f.posts).toHaveLength(2);
  expect(f.posts[1]).toBe(f.posts[0]);
  expect(f.reports.get("00017")).toMatchObject({
    source: { provider: "tenable", source_key: tenableOptions.sourceKey },
    source_finding_id: "00017",
    assessment: { state: "not_assessed" },
    evidence: {
      locations: [{ path: "src/app.ts", line: 7 }],
      source_data: { asset: capture.asset, finding: capture.findings[0] },
    },
  });
});

test("stored Tenable publication verifies the catalog and publishes the selected local version", async () => {
  const url = tenableReport.repository_url;
  const cloud = await fixture(tenableReport, url);
  await using local = await storedPublicationFixture(cloud);
  const { repository, deps } = local;
  const imported = await prepareLocalExternalImport(
    cloud.file,
    { ...tenableOptions, repository },
    deps,
  );
  await imported.import();
  const [row] = await listLocalExternalFindings({ repository }, deps);
  const selection = {
    repository,
    findings: [{ id: row!.id, version: row!.version }],
  };
  const file = await prepareExternalPublication(
    cloud.file,
    tenableOptions,
    cloud.deps,
  );
  await rm(cloud.file);

  cloud.state.repositoryUrl = "https://github.com/example/another";
  await expect(local.prepare(selection)).rejects.toThrow(/repository/i);
  expect(cloud.posts).toHaveLength(0);
  cloud.state.repositoryUrl = url;
  const { groups } = await local.prepare(selection);
  const group = groups[0]!;
  expect(group.preview.findings).toEqual(file.preview.findings);
  expect((await group.publish(group.reviewId)).verified).toBe(1);
  const record = cloud.reports.get("00017")!;
  expect(record).toMatchObject({
    source_finding_id: "00017",
    evidence: {
      source_data: {
        asset: tenableReport.asset,
        finding: tenableReport.findings[0],
      },
    },
  });
  expect(
    await listLocalFindingPublications({ repository }, deps),
  ).toMatchObject([
    {
      ...selection.findings[0],
      outcome: "created",
      cloudFindingId: record.canonical_finding_id,
    },
  ]);
});

test("Tenable verifies the catalog repository and retained SDK identity before uploading", async () => {
  const url = tenableReport.repository_url;
  const otherUrl = "https://github.com/example/another";
  const f = await fixture(tenableReport, otherUrl);
  await expect(
    prepareExternalPublication(f.file, tenableOptions, f.deps),
  ).rejects.toThrow(/repository/i);
  f.state.repositoryUrl = url;
  const parsed = await readTenableFindings(f.file, url, "cloud");
  const rejected = (input: ExternalFindings, reason: RegExp) =>
    expect(
      prepareNormalizedExternalPublication(input, tenableOptions, f.deps),
    ).rejects.toThrow(reason);
  const otherId = structuredClone(parsed);
  otherId.findings[0]!.source_finding_id = "17";
  await rejected(otherId, /finding ID|identity/i);
  const wrongReport = structuredClone(parsed);
  wrongReport.report!["repositoryUrl"] = otherUrl;
  await rejected(wrongReport, /repository/i);
  const otherAsset = structuredClone(parsed);
  const sourceData = otherAsset.findings[0]!.evidence.source_data!;
  const asset_id = "20000000-0000-4000-8000-000000000002";
  sourceData["asset"] = { ...tenableReport.asset, asset_id };
  sourceData["finding"] = { ...tenableReport.findings[0], asset_id };
  await rejected(otherAsset, /asset/i);
  const typed = structuredClone(parsed);
  typed.findings[0]!.evidence.details = {
    kind: "sast",
    repository: { url: otherUrl },
  };
  await rejected(typed, /repository/i);
  // Removing only the header must not turn native Tenable evidence into a Wiz row.
  for (const input of [parsed, { ...parsed, report: undefined }])
    await expect(
      prepareNormalizedExternalPublication(input, options, f.deps),
    ).rejects.toThrow(/tenable/i);
  expect(f.posts).toHaveLength(0);
});

test("Tenable rejects conflicting custom-host casing before authentication", async () => {
  const url = "https://git.example.test/Team/Repo";
  const otherCase = "https://git.example.test/Team/repo";
  const f = await fixture({ ...tenableReport, repository_url: url }, url);
  const parsed = await readTenableFindings(f.file, url, "cloud");
  const credentials = mock(async () => {
    throw new Error("Unexpected credential read");
  });
  const deps = { ...f.deps, credentials };
  await expect(
    prepareExternalPublication(
      f.file,
      { ...tenableOptions, sourceRepositoryUrl: otherCase },
      deps,
    ),
  ).rejects.toThrow(/repository/i);
  await expect(
    prepareNormalizedExternalPublication(
      parsed,
      { ...tenableOptions, sourceRepositoryUrl: otherCase },
      deps,
    ),
  ).rejects.toThrow(/repository/i);
  expect(credentials).not.toHaveBeenCalled();
  expect(f.posts).toHaveLength(0);
});

test("Tenable private imports require structured support and upload only the approved findings", async () => {
  const { f, deps, inbox, uploads, jobs, fileId } = await privateUploadFixture(
    tenableReport,
    "tenable",
    tenableReport.repository_url,
  );
  const prepare = () =>
    prepareExternalPublication(f.file, tenableOptions, deps);
  inbox.formats = ["wiz.vulnerability_json.v1"];
  await expect(prepare()).rejects.toThrow(/format|security\.findings\.v1/i);
  inbox.formats.push("security.findings.v1");
  const first = await prepare();
  expect(first.preview.privateImport?.format).toBe("security.findings.v1");
  expect(uploads).toHaveLength(0);
  expect(jobs).toHaveLength(0);
  await expect(first.publish()).rejects.toThrow("Interrupted private upload");
  expect(uploads).toHaveLength(1);
  expect(JSON.parse(uploads[0]!.bytes)).toMatchObject({
    format: "security.findings.v1",
    findings: [
      {
        source_finding_id: "00017",
        evidence: {
          source_data: {
            repository_url: tenableReport.repository_url,
            asset: tenableReport.asset,
            finding: tenableReport.findings[0],
          },
          locations: [{ path: "src/app.ts", start_line: 7 }],
        },
      },
    ],
  });
  inbox.recoverUpload = true;
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).status).toBe("complete");
  expect(uploads).toHaveLength(1);
  expect(jobs).toHaveLength(1);
  expect(jobs[0]).toMatchObject(
    privateJobFields("tenable", fileId, "security.findings.v1"),
  );
  expect(f.posts).toHaveLength(0);
});

test("a throttled private upload reports the retry interval and resumes the same request", async () => {
  const { f, deps, inbox, jobs } = await privateUploadFixture(
    tenableReport,
    "tenable",
    tenableReport.repository_url,
  );
  inbox.interruptUpload = false;
  const uploadIds: string[] = [];
  const prepare = () =>
    prepareExternalPublication(f.file, tenableOptions, {
      ...deps,
      fetch: async (url, init) => {
        if (new URL(url).pathname.endsWith("/finding-imports/files")) {
          uploadIds.push(String((init.body as FormData).get("request_id")));
          if (uploadIds.length === 1)
            return Response.json(
              { error: { code: "rate_limit_exceeded", message: "Slow down." } },
              { status: 429, headers: { "Retry-After": "17" } },
            );
        }
        return deps.fetch(url, init);
      },
    });
  const first = await prepare();
  await expect(first.publish()).rejects.toThrow("Slow down. Retry-After: 17.");
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).privateJob?.status).toBe("completed");
  expect(uploadIds).toEqual([expect.any(String), uploadIds[0]]);
  expect(jobs).toHaveLength(1);
});

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
  const report = {
    ...selectedSemgrepReport(
      { name: "Team/Project", url },
      { rule_name: "example.rule" },
    ),
    format: semgrepPlatformFormat,
    findingCount: 1,
    repositoryAliases: [],
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
    const renamed = "https://github.com/example/renamed";
    f.state.repositoryUrl = renamed;
    expect((await (await prepare()).publish()).verified).toBe(1);
    const normalizedInput = { ...local, report: undefined };
    const normalizedFixture = await fixture(undefined, url);
    const prepareNormalized = () =>
      prepareNormalizedExternalPublication(
        normalizedInput,
        binding,
        normalizedFixture.deps,
      );
    const normalizedPrepared = await prepareNormalized();
    await normalizedFixture.loseResponse(normalizedPrepared);
    normalizedFixture.state.repositoryUrl = renamed;
    const normalizedRetry = await prepareNormalized();
    expect(normalizedRetry.preview.resumed).toBe(true);
    expect((await normalizedRetry.publish()).verified).toBe(1);
    const freshRename = await fixture(report, renamed);
    await expect(
      prepareExternalPublication(freshRename.file, binding, freshRename.deps),
    ).rejects.toThrow(/repository/iu);
    expect(freshRename.posts).toHaveLength(0);
    const unscored = structuredClone(report);
    unscored.structuredContent.findings[0]!.severity = "UNSPECIFIED";
    const inbox = await privateUploadFixture(unscored, "semgrep", url);
    const headers = inbox.f.state.catalogHeaders;
    headers["Codex-Security-Repository-Import-Severities"] = "high";
    headers[scopeHeader] = "personal";
    await expect(inbox.prepareFile()).rejects.toMatchObject({
      selection: { findings: [], excluded: [{ position: 1 }] },
    });
    headers[scopeHeader] = "workspace";
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
  saved.evidenceDigest = hash(
    "sha256",
    canonicalJson([{ source_finding_id, evidence }]),
  );
  const bytes = JSON.stringify(saved);
  await writeFile(path, bytes);
  await expect(prepare()).rejects.toThrow(
    /semgrep provider|Saved import evidence/,
  );
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
    sourceFormat: semgrepPlatformFormat,
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
    prepare("1.2e1", null, "wiz", semgrepPlatformFormat),
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

    await f.loseResponse(first);
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
  const initial = await f.prepareNormalized(bare);
  await f.loseResponse(initial);
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
    await expect(stale.publish()).rejects.toThrow(
      "pending hosted Cloud request",
    );

    await expect(f.prepareFile()).rejects.toThrow(
      "pending hosted Cloud request",
    );
    await expect(f.prepareNormalized(changed)).rejects.toThrow(
      "pending hosted Cloud request",
    );
    expect(await readFile(pending, "utf8")).toBe(bytes);
    expect(f.posts).toHaveLength(1);
    const captured = await f.prepareNormalized(original);
    const completed = await (await f.prepareNormalized(original)).publish();
    expect(f.posts[1]).toBe(f.posts[0]);
    const newer = await f.loseResponse(await f.prepareNormalized(changed));
    const approved = await readFile(newer, "utf8");
    expect(await captured.publish()).toEqual(completed);
    expect(f.posts).toHaveLength(3);
    expect(await readFile(newer, "utf8")).toBe(approved);
    expect(
      (await (await f.prepareNormalized(changed)).publish()).counts.updated,
    ).toBe(1);
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

  f.state.loseResponse = true;
  const interrupted = createCliTest(main);
  expect(await interrupted.runCli([...args, "--yes"], deps)).toBe(2);
  expect(JSON.parse(interrupted.stdout.text()).cloud.status).toBe(
    "interrupted",
  );
  expect(f.posts).toHaveLength(1);
  const retry = createCliTest(main);
  expect(await retry.runCli([...previewArgs, "--dry-run"], deps)).toBe(0);
  expect(JSON.parse(retry.stdout.text()).capture).toBe(reviewed.capture);
  expect(f.posts).toHaveLength(1);

  const replay = createCliTest(main);
  expect(await replay.runCli([...args, "--yes"], deps)).toBe(0);
  const result = JSON.parse(replay.stdout.text());
  expect(result.local.counts.unchanged).toBe(1);
  expect(result.cloud.verified).toBe(1);
  expect(f.posts).toHaveLength(2);
  expect(f.posts[1]).toBe(f.posts[0]);
  expect(f.reports.size).toBe(1);
  const receipts = await listLocalFindingPublications(
    { repository: checkout },
    { environment },
  );
  expect(receipts).toHaveLength(1);
  expect(receipts[0]).toMatchObject({
    version: 1,
    cloudFindingId: f.reports.get("issue-1")!.canonical_finding_id,
  });
  const posted = JSON.parse(f.posts[0]!);
  expect(posted.source).toEqual({
    provider: "sonar",
    source_key: result.sourceKey,
  });
  expect(posted.items[0].source_finding_id).toBe("issue-1");
  const repository = f.destination();
  const reportsPath = `/external/repository_connectors/${repository.repo_connector_id}/repositories/${repository.id}/source_reports`;
  expect(paths).toEqual(
    new Set([
      "/external/repositories",
      reportsPath,
      "/external/finding_imports",
      `${reportsPath}/${f.reports.get("issue-1")!.id}`,
    ]),
  );
  expect(posted.items[0].evidence.source_data.issue.flows).toEqual(
    source.pages[0]!.issues[0]!.flows,
  );

  // An intervening local edit supersedes the saved pins. A fresh review of
  // the original evidence must still allow it to be imported as a new version.
  const changed = structuredClone(source);
  changed.pages[0]!.issues[0]!.message += " (changed)";
  const changedPath = join(f.root, "changed.json");
  await writeFile(changedPath, JSON.stringify(changed));
  async function importSonar(path: string, ...flags: string[]) {
    const cli = createCliTest(main);
    const command = ["import", "sonar", path, ...flags, "--format", "json"];
    expect(await cli.runCli(command, deps), cli.stderr.text()).toBe(0);
    return JSON.parse(cli.stdout.text());
  }
  const changedPreview = await importSonar(changedPath, "--dry-run");
  await importSonar(changedPreview.capture, "--yes");
  const fresh = await importSonar(capture, "--to", "cloud", "--dry-run");
  expect(fresh.capture).not.toBe(reviewed.capture);
  await importSonar(fresh.capture, "--to", "cloud", "--yes");
  const history = await listLocalFindingPublications(
    { repository: checkout },
    { environment },
  );
  expect(history.map((row) => row.version).sort()).toEqual([1, 3]);
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
    prepareNormalized(
      f,
      { ...selection, findings, report: { ...context, branch: "main" } },
      selected,
    );
  await expect(prepareNormalized(f, selection, selected)).rejects.toThrow(
    "without a ref",
  );
  await expect(
    prepareNormalized(
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
    prepareNormalized(
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
    prepareNormalized(
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

test("Cloud previews the findings file selected through a directory link and parent", async () => {
  const f = await fixture();
  const directory = join(f.root, "physical", "child");
  await mkdir(directory, { recursive: true });
  await fs.symlink(
    directory,
    join(f.root, "link"),
    process.platform === "win32" ? "junction" : "dir",
  );
  const name = basename(f.file);
  await writeFile(
    join(f.root, "physical", name),
    JSON.stringify([normalized("other")]),
  );
  const input = `link/../${name}`;
  const [expected] = JSON.parse(await readFile(`${f.root}/${input}`, "utf8"));
  const cli = createCliTest(main);
  const args = [...f.command];
  args[2] = input;
  expect(
    await cli.runCli([...args, "--dry-run"], {
      ...f.cliDeps,
      currentDirectory: () => f.root,
    }),
  ).toBe(0);
  expect(JSON.parse(cli.stdout.text()).findings).toMatchObject([
    { source_finding_id: expected.source_finding_id },
  ]);
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

test("explains a Cloud account or deployment without the import catalog", async () => {
  const f = await fixture(continuumDetail(), continuumRepository);
  const missing = (status: number) => ({
    ...f.deps,
    fetch: async () =>
      Response.json({ error: { message: "Not found" } }, { status }),
  });
  const selected = {
    ...options,
    provider: "continuum" as const,
    sourceKey: "continuum/example/project",
    sourceRepositoryUrl: continuumRepository,
  };
  await expect(
    prepareExternalPublication(f.file, selected, missing(404)),
  ).rejects.toThrow(
    "Cloud import failed (HTTP 404). Not found. Cloud import is not available for this account or deployment.",
  );
  await expect(
    prepareExternalPublication(f.file, selected, {
      ...f.deps,
      fetch: async () => new Response(null, { status: 404 }),
    }),
  ).rejects.toThrow(
    "Cloud import failed (HTTP 404). Cloud import is not available for this account or deployment.",
  );
  await expect(
    prepareExternalPublication(f.file, selected, missing(500)),
  ).rejects.toThrow(/^Cloud import failed \(HTTP 500\)\. Not found$/u);
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

const continuumPatch = patchArtifact(
  "firstpatch",
  "--- a/parser.ts\n+++ b/parser.ts\n@@ -1 +1 @@\n-parse(input);\n+parse(checked(input));\n",
);

test("Continuum Cloud publication preserves issue identity and linked source ranges", async () => {
  const report = {
    ...continuumIssueExport(),
    sourceRepositoryUrl: continuumRepository,
  };
  const { issue } = report.issues[0]!;
  const f = await fixture(report, continuumRepository);
  const selected = {
    ...options,
    provider: "continuum" as const,
    sourceKey: "continuum/example/project",
  };
  const other = await fixture(report, "https://github.com/example/other");
  await expect(
    prepareExternalPublication(other.file, selected, other.deps),
  ).rejects.toThrow("does not match the selected Cloud repository");
  const prepared = await prepareExternalPublication(f.file, selected, f.deps);
  expect(prepared.preview.requests[0]?.items).toMatchObject([
    {
      source_finding_id: issue.issueArn,
      evidence: {
        locations: [
          { path: "src/example.ts", line: 3 },
          { path: "src/other.ts", line: 12 },
          { path: "src/second.ts", line: 20 },
        ],
        details: {
          remediation_instructions: issue.summary,
          code: { end_line: 5, snippet: "readExample(input)" },
        },
        source_data: {
          issue,
          findings: [
            { findingId: "one", validation: { verdict: "TRUE_POSITIVE" } },
            { findingId: "two", lineNumber: 20, endLine: 24 },
          ],
        },
      },
    },
  ]);
  expect((await prepared.publish()).verified).toBe(1);
  expect(f.reports.has(issue.issueArn)).toBe(true);
});

test("a Continuum private upload keeps every structured signal and reports conflicting issue verdicts", async () => {
  const input = continuumIssueExport();
  const { issue } = input.issues[0]!;
  const evidence = [
    continuumEvidenceArtifact(issue.issueId),
    continuumValidationArtifact(),
    {
      artifactId: "rawvalidation",
      artifactType: "VALIDATION_EVIDENCE",
      body: { raw: "Example validation text" },
    },
    continuumEvidenceArtifact(issue.issueArn, "NOT_EXPLOITABLE", "evidence2"),
  ];
  const report = {
    ...input,
    sourceRepositoryUrl: continuumRepository,
    issues: [
      {
        ...input.issues[0]!,
        issue: {
          ...issue,
          artifacts: [
            ...evidence,
            {
              artifactType: "PATCH",
              artifactId: continuumPatch.artifactId,
              body: { patch: continuumPatch },
            },
            {
              artifactType: "EVIDENCE",
              artifactId: "narrative",
              body: { raw: "Example narrative" },
            },
          ],
        },
      },
    ],
  };
  const linked = continuumDetail();
  const { inbox, uploads, jobs, prepareFile } = await privateUploadFixture(
    report,
    "continuum",
    continuumRepository,
  );
  const prepared = await prepareFile();
  await expect(prepared.publish()).rejects.toThrow(
    "Interrupted private upload",
  );
  expect(uploads).toHaveLength(1);
  const payload = JSON.parse(uploads[0]!.bytes);
  expect(payload).toMatchObject({
    format: "security.findings.v1",
    findings: [
      {
        source_finding_id: issue.issueArn,
        evidence: {
          title: issue.name,
          severity: "high",
          locations: [
            {
              path: linked.filePath,
              start_line: linked.lineNumber,
              end_line: linked.endLine,
            },
            { path: "src/other.ts", start_line: 12 },
            { path: "src/second.ts", start_line: 20 },
          ],
          details: {
            source_status: issue.status,
            scanner_verdict: "MIXED",
            remediation_instructions: issue.summary,
            code: { snippet: linked.vulnerableCode },
          },
          source_data: {
            issue,
            patches: [continuumPatch],
            findings: [
              { findingId: linked.findingId, validation: linked.validation },
              { findingId: "two" },
            ],
          },
        },
      },
    ],
  });
  expect(payload.findings).toHaveLength(1);
  expect(payload.findings[0].evidence.source_data.evidence_artifacts).toEqual(
    evidence,
  );
  inbox.recoverUpload = true;
  expect((await (await prepareFile()).publish()).counts.created).toBe(1);
  expect(uploads).toHaveLength(1);
  expect(jobs).toHaveLength(1);
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
    "Supply the verified Inspector project binding",
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

const exampleRepository = "https://github.com/example/project";
const nativeSemgrep = semgrepJson();

test("publishes a filtered numeric Veracode CWE", async () => {
  const raw = veracodeMixedPolicyPage();
  raw._links.self.href += "&cwe=79";
  const f = await fixture(raw, exampleRepository);
  const settings = {
    ...options,
    provider: "veracode" as const,
    sourceRepositoryUrl: exampleRepository,
  };
  const prepared = await prepareExternalPublication(f.file, settings, f.deps);
  expect((await prepared.publish()).verified).toBe(2);
});

const otherRepository = "https://github.com/example/other";
const wizBranchAsset = {
  nativeType: "github#repositoryBranch",
  cloudProviderURL: exampleRepository + "/tree/main",
};

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
        `https://chatgpt.com/mcp-app/connector_openai_defense_factory/open_defense_factory#/repositories/${options.repository}/findings?source=imported`,
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
        return Response.json(receipt, { headers: response.headers });
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
        return Response.json(receipt, { headers: response.headers });
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
        return Response.json(
          {
            ...(await response.json()),
            [field]: value,
          },
          { headers: response.headers },
        );
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

test("an unexpected import response preserves the approved request for retry", async () => {
  const f = await fixture();
  let dropMediaType = true;
  const prepare = () =>
    prepareExternalPublication(f.file, options, {
      ...f.deps,
      async fetch(url, init) {
        const response = await f.deps.fetch(url, init);
        if (init.method !== "POST" || !dropMediaType) return response;
        dropMediaType = false;
        return new Response(response.body, {
          headers: { "Content-Type": "application/json" },
        });
      },
    });
  const first = await prepare();
  await expect(first.publish()).rejects.toThrow(/representation|media type/i);
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.requests).toEqual(first.preview.requests);
  expect((await retry.publish()).verified).toBe(1);
  expect(f.posts).toEqual([f.posts[0]!, f.posts[0]!]);
  expect(f.receipts.size).toBe(1);
});

test("an unexpected private job response retries the same uploaded file and job request", async () => {
  const { f, deps, inbox, uploads, jobs } = await privateUploadFixture(
    [normalized()],
    "wiz",
  );
  inbox.interruptUpload = false;
  let dropMediaType = true;
  const prepare = () =>
    prepareExternalPublication(f.file, options, {
      ...deps,
      async fetch(url, init) {
        const response = await deps.fetch(url, init);
        if (
          !new URL(url).pathname.endsWith("/finding-imports/jobs") ||
          !dropMediaType
        )
          return response;
        dropMediaType = false;
        return new Response(response.body, {
          headers: { "Content-Type": "application/json" },
        });
      },
    });
  const first = await prepare();
  await expect(first.publish()).rejects.toThrow(/representation|media type/i);
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).privateJob?.status).toBe("completed");
  expect(uploads).toHaveLength(1);
  expect(jobs).toEqual([jobs[0], jobs[0]]);
  expect(f.posts).toHaveLength(0);
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

test.each(["scope", "media type"] as const)(
  "discovery rejects a changed %s across repository pages",
  async (change) => {
    const f = await fixture(blackDuckBomReport());
    const repository = `${f.destination().url}.git`;
    const queries: URLSearchParams[] = [];
    const prepared = prepareExternalPublication(
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
              headers: {
                [scopeHeader]:
                  change === "scope" && first ? "workspace" : "personal",
                "Content-Type":
                  change === "media type" && !first
                    ? "application/json"
                    : scannerMediaType,
              },
            },
          );
        },
      },
    );
    await expect(prepared).rejects.toThrow(/scope|contract|discovery/iu);
    expect(queries.map((query) => query.get("repository"))).toEqual([
      repository,
      repository,
    ]);
    expect(queries.map((query) => query.get("page"))).toEqual([
      null,
      "next-page",
    ]);
    expect(f.posts).toHaveLength(0);
  },
);

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
  const link = `http://localhost:4200/security?preview=true#/repositories/${options.repository}/findings?source=imported`;
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
  const initialPreview = await prepareExternalPublication(
    f.file,
    githubOptions,
    f.deps,
  );
  const first = await initialPreview.publish();
  expect(first.counts.created).toBe(1);
  expect(first.verified).toBe(1);
  expect(await initialPreview.publish()).toEqual(first);
  expect(f.posts).toHaveLength(1);
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
          return Response.json(body, { headers: response.headers });
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

function scoredFindings(score: unknown, report?: Record<string, unknown>) {
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
        evidence,
      },
    ],
    report,
  };
}

type PublicationFixture = Awaited<ReturnType<typeof fixture>>;

function prepareNormalized(
  f: PublicationFixture,
  input: ExternalFindings,
  selected: NormalizedExternalPublicationOptions = options,
) {
  return prepareNormalizedExternalPublication(input, selected, f.deps);
}

test.each([false, true])(
  "an unsupported pending request is preserved (alternate filename %s)",
  async (alternate) => {
    const f = await fixture();
    const prepared = await prepareExternalPublication(f.file, options, f.deps);
    const path = await f.loseResponse(prepared);
    const original = JSON.parse(await readFile(path, "utf8"));
    const obsolete = JSON.stringify({
      accountId: original.accountId,
      requests: original.requests,
    });
    const oldPath = alternate
      ? join(dirname(path), "a".repeat(64) + ".pending.json")
      : path;
    if (alternate) await rm(path);
    await writeFile(oldPath, obsolete);
    await expect(
      prepareExternalPublication(f.file, options, f.deps),
    ).rejects.toThrow("another SDK version");
    expect(await readFile(oldPath, "utf8")).toBe(obsolete);
    expect(f.posts).toHaveLength(1);
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
    const preview = await prepareNormalized(f, input);
    expect(preview.preview.resumed).toBe(false);
    await preview.publish();
    expect(JSON.parse(f.posts[0]!).items[0].evidence.source_data.score).toBe(4);
  },
);

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
        return Response.json(body, { headers: response.headers });
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
        return Response.json(body, { headers: response.headers });
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
  const missingGlobal = createCliTest(main);
  expect(
    await missingGlobal.runCli(
      ["--filter-output", "--token-limit", ...f.command],
      f.cliDeps,
    ),
  ).toBe(2);
  expect(missingGlobal.stderr.text()).toContain(
    "Missing value for flag: --filter-output",
  );
  const extraArguments = createCliTest(main);
  expect(
    await extraArguments.runCli(
      [
        "--filter-output",
        "status",
        "--token-limit",
        "5",
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

const readerReports = {
  armorcode: {
    data: {
      findings: [
        {
          id: 1,
          title: "Unchecked index",
          scanType: ["SAST"],
          repositoryUrl: exampleRepository,
        },
      ],
    },
  },
  blackduck: blackDuckBomReport(),
  checkmarx: { scanID: "scan-a", totalCount: 1, results: [checkmarxSastRow()] },
  continuum: {
    finding: { ...continuumDetail(), createdIssueId: "oneissue" },
    patches: [continuumPatch],
  },
  endor: [endorSource],
  github: [importedAlert()],
  inspector: inspectorReport(),
  opengrep: opengrepJson(),
  semgrep: nativeSemgrep,
  snyk: snykJson(),
  sonar: sonarReport,
  tenable: tenableReport,
  trivy,
  veracode: veracodePolicyPage(),
  wiz: [
    {
      id: "occurrence-1",
      name: "CVE-2099-0001",
      detailedName: "example-package",
      vendorSeverity: "HIGH",
      vulnerableAsset: { id: "asset-1" },
    },
  ],
} satisfies Record<ExternalFindingsReader, unknown>;

const scannerReports = [
  ...EXTERNAL_FINDINGS_READERS.map((reader) => ({
    name: reader,
    reader,
    report: readerReports[reader],
  })),
  { name: "Dependabot", reader: "github", report: [githubDependabotAlert()] },
  {
    name: "GitHub repository advisory",
    reader: "github",
    report: [importedAdvisory("repository")],
  },
  {
    name: "GitHub global advisory",
    reader: "github",
    report: [importedAdvisory("global")],
  },
] as const;

test.each(scannerReports)(
  "the SDK sends $name to personal and workspace Cloud imports",
  async ({ reader, report }) => {
    const provider = reader === "opengrep" ? "semgrep" : reader;
    const url =
      reader === "tenable" ? tenableReport.repository_url : exampleRepository;
    const { f, deps, inbox, uploads, jobs, fileId } =
      await privateUploadFixture(report, provider, url);
    const paths: string[] = [];
    const prepare = () =>
      prepareExternalPublication(
        f.file,
        {
          ...options,
          provider: reader,
          ...(reader === "trivy"
            ? { trivyScanRoot: "." }
            : { sourceRepositoryUrl: url }),
        },
        {
          ...deps,
          fetch(url, init) {
            paths.push(new URL(url).pathname);
            return deps.fetch(url, init);
          },
        },
      );

    f.state.catalogHeaders = { [scopeHeader]: "personal" };
    const personal = await prepare();
    const { source_finding_id, evidence } = personal.preview.findings[0]!;
    if (reader === "continuum")
      expect(evidence.source_data?.["patches"]).toEqual([continuumPatch]);
    expect((await personal.publish()).verified).toBe(1);
    const stored = f.reports.get(source_finding_id);
    expect(stored?.source).toEqual({ provider, source_key: options.sourceKey });
    expect(stored?.evidence).toEqual(evidence);
    const root = "/backend-api/aardvark";
    const { repo_connector_id, id } = f.destination();
    const reports = `${root}/external/repository_connectors/${repo_connector_id}/repositories/${id}/source_reports`;
    expect(paths).toEqual([
      `${root}/external/repositories`,
      reports,
      `${root}/external/finding_imports`,
      `${reports}/${stored!.id}`,
    ]);

    paths.length = 0;
    f.state.catalogHeaders = {
      [scopeHeader]: "workspace",
      [providerHeader]: provider,
    };
    inbox.interruptUpload = false;
    const workspace = await prepare();
    expect((await workspace.publish()).privateJob?.status).toBe("completed");
    expect(paths).toEqual([
      `${root}/external/repositories`,
      `${root}/finding-imports/context`,
      `${root}/finding-imports/context`,
      `${root}/finding-imports/files`,
      `${root}/finding-imports/jobs`,
    ]);
    const uploaded = JSON.parse(uploads[0]!.bytes).findings;
    expect(uploaded).toHaveLength(1);
    expect(uploaded[0].source_finding_id).toBe(source_finding_id);
    const { locations, severity, ...original } = evidence;
    const {
      locations: lines,
      severity: privateSeverity,
      ...actual
    } = uploaded[0].evidence;
    expect(actual).toEqual(original);
    expect(privateSeverity).toBe(severity === "unknown" ? null : severity);
    expect(
      lines?.map((entry: { path: string; start_line: number | null }) => ({
        path: entry.path,
        line: entry.start_line,
      })),
    ).toEqual(locations);
    expect(jobs).toMatchObject([
      privateJobFields(provider, fileId, "security.findings.v1"),
    ]);
    expect(f.posts).toHaveLength(1);
  },
);

test.each(["wiz", "endor", "snyk"] as const)(
  "the released personal Cloud API still accepts %s",
  async (provider) => {
    const f = await fixture(readerReports[provider], exampleRepository);
    f.state.catalogMediaType = "application/json";
    f.state.catalogHeaders = {
      "Codex-Security-Repository-Import-Severities":
        "critical,high,medium,low,informational",
    };
    const prepared = await prepareExternalPublication(
      f.file,
      {
        ...options,
        provider,
        sourceRepositoryUrl: exampleRepository,
      },
      f.deps,
    );
    expect((await prepared.publish()).verified).toBe(1);
    expect(f.posts).toHaveLength(1);
  },
);

test.each([
  ["unrecognized catalog", "application/json", {}],
  [
    "scope without a negotiated contract",
    "application/json",
    { [scopeHeader]: "personal" },
  ],
  ["unrecognized media type", "text/html", { [scopeHeader]: "personal" }],
  [
    "unadvertised workspace provider",
    "application/json",
    { [providerHeader]: "snyk" },
  ],
  [
    "missing private job version",
    "application/json",
    { [providerHeader]: "continuum" },
  ],
  [
    "wrong private job version",
    "application/json",
    { [providerHeader]: "continuum", [jobVersionHeader]: "3" },
  ],
  [
    "unsupported personal provider",
    "application/json",
    { "Codex-Security-Repository-Import-Severities": "high" },
  ],
] as [string, string, Record<string, string>][])(
  "Continuum rejects %s before transferring evidence",
  async (_, mediaType, headers) => {
    const f = await fixture(readerReports.continuum, exampleRepository);
    f.state.catalogMediaType = mediaType;
    f.state.catalogHeaders = headers;
    const paths: string[] = [];
    await expect(
      prepareExternalPublication(
        f.file,
        {
          ...options,
          provider: "continuum",
          sourceRepositoryUrl: exampleRepository,
        },
        {
          ...f.deps,
          fetch(url, init) {
            paths.push(new URL(url).pathname);
            return f.deps.fetch(url, init);
          },
        },
      ),
    ).rejects.toThrow(/Cloud|unavailable|scope|provider|contract|catalog/i);
    expect(paths).toEqual(["/backend-api/aardvark/external/repositories"]);
    expect(f.posts).toHaveLength(0);
  },
);

test.each([
  {
    provider: "continuum",
    format: "security.findings.v1",
    raw: readerReports.continuum,
    jobApiVersion: 2,
  },
  {
    provider: "blackduck",
    format: "security.findings.v1",
    raw: readerReports.blackduck,
    jobApiVersion: 3,
  },
  {
    provider: "github",
    format: "security.findings.v1",
    raw: [importedAlert()],
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
    raw: readerReports.wiz,
  },
] as const)(
  "a signed-in $provider private import resumes lost upload and job responses",
  async (scenario) => {
    const { provider, format, raw } = scenario;
    const f = await fixture(raw);
    const originalBytes = await readFile(f.file, "utf8");
    const settings = {
      ...options,
      provider,
      ...("jobApiVersion" in scenario && {
        sourceRepositoryUrl: exampleRepository,
      }),
    };
    let contextVersion = "generation-a";
    let formats: string[] = [format];
    let expectedFormat: typeof format = format;
    let loseResponses = true;
    let unavailable = false;
    let terminal: "completed" | "failed" | "cancelled" = "completed";
    let advertised = false;
    let jobsPath = "/finding-imports/jobs";
    let jobMediaType = scannerMediaType;
    let canCreate = true;
    let reportCount = 1;
    const uploadedReports: { id: string; bytes: string }[] = [];
    let jobRequest: string | undefined;
    let loseNextJobResponse = true;
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
          const headers = new Headers(response.headers);
          if (advertised) headers.set(providerHeader, provider);
          if (
            "jobApiVersion" in scenario &&
            f.state.catalogMediaType === "application/json"
          ) {
            if (!advertised) headers.set(providerHeader, "wiz");
            expect(new Headers(init.headers).get(jobVersionHeader)).toBe(
              String(scenario.jobApiVersion),
            );
          }
          return new Response(response.body, { headers });
        }
        if (path.startsWith("/external/")) return f.deps.fetch(url, init);
        const sendsJob = path === jobsPath || path.startsWith(jobsPath + "/");
        const headers = new Headers(init.headers);
        expect(headers.get("Accept")).toBe(
          sendsJob ? jobMediaType : "application/json",
        );
        expect(headers.get("Content-Type")).toBe(
          sendsJob && init.method === "POST" ? jobMediaType : null,
        );
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
          } else {
            expect(JSON.parse(bytes)).toEqual(JSON.parse(originalBytes));
          }
          uploadedReports.push({ id, bytes });
          if (loseResponses && uploadedReports.length === 1)
            throw new Error("lost upload response");
          return Response.json(fileMetadata());
        }
        const fileRequest = uploadedReports.at(-1)?.id;
        if (path === `/finding-imports/file-requests/${fileRequest}`) {
          return Response.json(fileMetadata());
        }
        if (path === jobsPath) {
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
            return Response.json(job(terminal), {
              headers: { "Content-Type": jobMediaType },
            });
          }
          if (jobRequest) expect(body.request_id).toBe(jobRequest);
          jobRequest = body.request_id;
          if (loseNextJobResponse) {
            loseNextJobResponse = false;
            throw new Error("lost job response");
          }
          return Response.json(job("queued"), {
            headers: { "Retry-After": "0", "Content-Type": jobMediaType },
          });
        }
        if (path === `${jobsPath}/${jobId}`)
          return unavailable
            ? new Response(null, { status: 503 })
            : Response.json(job(terminal), {
                headers: { "Content-Type": jobMediaType },
              });
        throw new Error("Unexpected route: " + path);
      },
    };
    const prepare = () => prepareExternalPublication(f.file, settings, deps);
    const repositoryPreview = await prepare();
    function legacyWorkspace(version: 2 | 3) {
      f.state.catalogMediaType = "application/json";
      f.state.catalogHeaders = {
        [jobVersionHeader]: String(version),
        "Codex-Security-Repository-Import-Severities":
          "critical,high,medium,low,informational",
      };
      jobsPath = `/v${version}/finding-imports/jobs`;
      jobMediaType = "application/json";
    }
    if (provider === "continuum") legacyWorkspace(scenario.jobApiVersion);
    else f.state.catalogHeaders[scopeHeader] = "workspace";
    f.state.environmentId = null;
    advertised = true;
    const original = await prepare();
    expect(original.preview.privateImport?.sha256).toBeTruthy();
    expect(original.preview.privateImport?.format).toBe(format);
    const cli = createCliTest(main);
    const dryRun = [...f.command, "--dry-run"];
    if ("jobApiVersion" in scenario)
      dryRun.push("--source-repository-url", exampleRepository);
    dryRun[dryRun.indexOf("--provider") + 1] = provider;
    dryRun[dryRun.indexOf("--format") + 1] = "toon";
    expect(
      await cli.runCli(dryRun, { ...f.cliDeps, cloudFetch: deps.fetch }),
    ).toBe(0);
    expect(cli.stderr.text()).toContain(
      `Report: ${format} (${original.preview.privateImport?.bytes} bytes)`,
    );
    if (format !== "security.findings.v1") {
      formats = [format, "security.findings.v1"];
      expect((await prepare()).preview.privateImport?.format).toBe(
        "security.findings.v1",
      );
      formats = [format];
    }
    expect(calls.filter((call) => call.startsWith("POST"))).toEqual([]);
    contextVersion = "generation-b";
    await expect(original.publish()).rejects.toThrow("private inbox changed");
    canCreate = false;
    await expect(prepare()).rejects.toThrow("unavailable");
    canCreate = true;
    const staged = await prepare();
    const interrupted = await staged.publish().catch((error: unknown) => error);
    if (!(interrupted instanceof ExternalPublicationError))
      throw new Error("Expected an interrupted private upload", {
        cause: interrupted,
      });
    expect(interrupted.message).toContain("lost upload response");
    const checkpointPath = interrupted.result.savedSubmission!;
    const saved = JSON.parse(await readFile(checkpointPath, "utf8"));
    expect(saved).toMatchObject({
      sha256: fileMetadata().sha256,
      uploadRequestId: uploadedReports.at(-1)!.id,
    });
    await expect(repositoryPreview.publish()).rejects.toThrow(
      "A private import already owns this selection",
    );
    expect(f.posts).toHaveLength(0);
    if ("rename" in scenario) {
      f.state.repositoryUrl = "https://github.com/example/renamed";
      expect(saved.approvedRepositoryUrl).toBe(exampleRepository);
      const pending = await prepare();
      await rm(checkpointPath);
      await expect(pending.publish()).rejects.toThrow(
        "saved private import changed",
      );
      await writeFile(checkpointPath, JSON.stringify(saved));
    }
    if (provider === "blackduck") {
      expect(saved.jobApiVersion).toBeUndefined();
      legacyWorkspace(scenario.jobApiVersion);
      delete f.state.catalogHeaders[jobVersionHeader];
      const before = [...calls];
      await expect(prepare()).rejects.toThrow(/unavailable/i);
      expect(calls.slice(before.length)).toEqual([
        "GET /external/repositories",
      ]);
      f.state.catalogHeaders[jobVersionHeader] = String(scenario.jobApiVersion);
    } else {
      if (provider === "continuum")
        expect(saved.jobApiVersion).toBe(scenario.jobApiVersion);
      advertised = false;
    }
    const resumed = await prepare();
    expect(resumed.preview.resumed).toBe(true);
    expect(resumed.preview.privateImport?.sha256).toBe(saved.sha256);
    await expect(resumed.publish()).rejects.toThrow("lost job response");
    expect(jobRequest).toBe(saved.jobRequestId);
    expect(calls.at(-1)).toBe(`POST ${jobsPath}`);
    if ("jobApiVersion" in scenario) {
      expect(
        JSON.parse(await readFile(checkpointPath, "utf8")).jobApiVersion,
      ).toBe(scenario.jobApiVersion);
      delete f.state.catalogHeaders[jobVersionHeader];
      advertised = false;
    }
    const completed = await (await prepare()).publish();
    expect(completed.privateJob?.counts.created).toBe(1);
    expect(calls.at(-1)).toBe(`GET ${jobsPath}/${jobId}`);
    expect(completed.receipts).toEqual([]);
    expect(completed.verified).toBe(0);
    expect(uploadedReports).toHaveLength(1);
    canCreate = false;
    advertised = false;
    if ("jobApiVersion" in scenario) {
      const previousCalls = calls.length;
      expect((await (await prepare()).publish()).privateJob?.id).toBe(jobId);
      expect(
        calls.slice(previousCalls).filter((call) => call.startsWith("POST")),
      ).toEqual([]);
      expect(calls.at(-1)).toBe(`GET ${jobsPath}/${jobId}`);
      // The expanded job endpoint can recover the same accepted legacy job.
      f.state.catalogMediaType = scannerMediaType;
      f.state.catalogHeaders = { [scopeHeader]: "workspace" };
      jobsPath = "/finding-imports/jobs";
      jobMediaType = scannerMediaType;
    }
    const acceptedCalls = calls.length;
    expect((await (await prepare()).publish()).privateJob?.id).toBe(jobId);
    expect(calls.at(-1)).toBe(`GET ${jobsPath}/${jobId}`);
    expect(
      calls.slice(acceptedCalls).filter((call) => call.startsWith("POST")),
    ).toEqual([]);
    unavailable = true;
    const acknowledged = {
      result: {
        status: "interrupted",
        counts: { created: reportCount },
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
    advertised = true;
    canCreate = true;
    loseResponses = false;
    expectedFormat = "security.findings.v1";
    jobsPath = "/finding-imports/jobs";
    jobMediaType = scannerMediaType;
    terminal = provider === "wiz" ? "cancelled" : "failed";
    if ("rename" in scenario) {
      await expect(prepare()).rejects.toThrow("does not match");
      f.state.repositoryUrl = exampleRepository;
    }
    const fresh = await prepare();
    expect(fresh.preview.resumed).toBe(false);
    expect(fresh.preview.privateImport?.format).toBe(expectedFormat);
    expect((await fresh.publish()).privateJob?.status).toBe(terminal);
    expect(fresh.preview.privateImport?.sha256).toBe(fileMetadata().sha256);
    const failedJob = jobId;
    // The saved receipt remains readable after this provider drops out of discovery.
    advertised = false;
    const before = calls.length;
    const readOnly = await prepare();
    expect(readOnly.preview.privateImport?.retryOfJobId).toBeUndefined();
    expect((await readOnly.publish()).privateJob).toMatchObject({
      id: failedJob,
      status: terminal,
    });
    expect(calls.at(-1)).toBe(`GET ${jobsPath}/${failedJob}`);
    contextVersion = "different-inbox";
    await expect(prepare()).rejects.toThrow(
      "Private findings import is unavailable",
    );
    expect(
      calls.slice(before).filter((call) => call.startsWith("POST")),
    ).toEqual([]);
    contextVersion = "generation-c";
    advertised = true;
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

test("native private uploads encode only the reviewed occurrences", () => {
  const first = endorFinding();
  const second = { ...first, uuid: "unselected" };
  const reviewed = normalizeEndorFindings([first, second]).findings.slice(0, 1);
  const nativeFormat = "endor.findings_json.v1";
  const context = {
    object: "security.finding_import_context" as const,
    context_version: "v1",
    can_upload: true,
    can_create_import_jobs: true,
    can_read: true,
    formats: [nativeFormat],
    limits: {
      max_direct_file_bytes: 32 * 1024 * 1024,
      max_record_bytes: 1024 * 1024,
    },
  };
  const native = selectPrivateReport(reviewed, "endor", context);
  expect(native.format).toBe(nativeFormat);
  expect(JSON.parse(native.bytes)).toEqual({ list: { objects: [first] } });
  const both = { ...context, formats: [nativeFormat, "security.findings.v1"] };
  expect(selectPrivateReport(reviewed, "endor", both).format).toBe(
    "security.findings.v1",
  );
  reviewed[0]!.evidence.title = "Changed after normalization";
  expect(() => selectPrivateReport(reviewed, "endor", context)).toThrow(
    "security.findings.v1",
  );
});

function localFinding(id?: string, severity?: string) {
  const row = normalized(id, severity);
  return { ...row, evidence: validateExternalEvidence(row.evidence, "local") };
}

/** Use one disposable checkout and SQLite database for import, review and receipt lookup. */
async function storedPublicationFixture(
  cloud: Awaited<ReturnType<typeof fixture>>,
  fetch = cloud.deps.fetch,
) {
  const local = await localFindingsFixture({
    remote: cloud.state.repositoryUrl,
  });
  const { repository } = local;
  const deps = {
    fetch,
    environment: {
      ...local.environment,
      CODEX_HOME: cloud.environment.CODEX_HOME,
    },
  };
  return {
    ...local,
    deps,
    prepare: (selection: LocalExternalFindingSelection) =>
      prepareStoredFindingsPublication(selection, options, deps),
    async store(
      provider: string,
      input: ExternalFindings,
      sourceRepositoryUrl?: string,
    ) {
      const prepared = await prepareNormalizedLocalImport(
        input,
        { repository, provider, sourceKey: "selected", sourceRepositoryUrl },
        deps,
      );
      return prepared.import();
    },
  };
}

test("stored publication reports unsupported providers and Cloud-only exclusions against their local versions", async () => {
  const cloud = await fixture();
  await using local = await storedPublicationFixture(cloud);
  const { repository, deps } = local;
  cloud.state.catalogHeaders["Codex-Security-Repository-Import-Severities"] =
    "high";
  const store = (
    provider: string,
    ids: string[],
    report?: Record<string, unknown>,
  ) =>
    local.store(
      provider,
      {
        read: ids.length,
        findings: ids.map((id) =>
          localFinding(id, id === "unscored" ? "unknown" : "high"),
        ),
        excluded: [],
        report,
      },
      cloud.state.repositoryUrl,
    );
  await store("wiz", ["ready", "unscored", "too-long-" + "x".repeat(512)]);
  await store("tenant-scanner", ["local-only"]);
  const rows = await listLocalExternalFindings({ repository }, deps);
  const selection = {
    repository,
    findings: rows.map(({ id, version }) => ({ id, version })),
  };
  const excluded = rows.filter((row) => row.sourceFindingId !== "ready");
  const prepared = await local.prepare(selection);
  const group = prepared.groups[0]!;
  expect(group.preview.findings.map((f) => f.source_finding_id)).toEqual([
    "ready",
  ]);
  for (const { id, version, provider, sourceFindingId } of excluded) {
    expect(prepared.excluded).toContainEqual(
      expect.objectContaining({
        id,
        version,
        reason: expect.stringMatching(
          provider !== "wiz"
            ? /tenant-scanner/
            : sourceFindingId === "unscored"
              ? /unknown/
              : /512/,
        ),
      }),
    );
  }
  expect((await group.publish(group.reviewId)).status).toBe("partial");
  expect(cloud.posts).toHaveLength(1);
  expect(
    (await listLocalFindingPublications({ repository }, deps)).map((r) => r.id),
  ).toEqual([rows.find((r) => r.sourceFindingId === "ready")!.id]);
  const failed = await store("wiz", ["z".repeat(513)], {
    errors: ["scanner permission denied"],
  });
  await expect(
    local.prepare({ repository, importId: failed.importId! }),
  ).rejects.toThrow(/scanner permission denied/);
  cloud.state.repositoryUrl = "https://github.com/example/another";
  await expect(local.prepare(selection)).rejects.toThrow(/does not match/);
  expect(cloud.posts).toHaveLength(1);
});

test.each(["trivy", "endor"] as const)(
  "stored native %s rows use the file reader's Cloud projection when enriched fields exceed its limits",
  async (provider) => {
    const cloud = await fixture();
    await using local = await storedPublicationFixture(cloud);
    const base = endorFinding();
    const { target_dependency_name: _, ...spec } = base.spec;
    const raw = {
      ...base,
      spec: { ...spec, target_dependency_package_name: "x".repeat(513) },
    };
    const report = trivyReportWithManyLocations();
    const read = (target: "local" | "cloud") =>
      provider === "trivy"
        ? normalizeTrivyFindings(report, target, ".")
        : normalizeEndorFindings(raw, target);
    const input = read("local");
    const expected = read("cloud");
    if (provider === "trivy")
      expect(
        input.findings.some((f) => f.evidence.locations!.length > 100),
      ).toBe(true);
    else
      expect(input.findings[0]!.evidence.packages).not.toEqual(
        expected.findings[0]!.evidence.packages,
      );
    const result = await local.store(provider, input);
    const prepared = await local.prepare({
      repository: local.repository,
      importId: result.importId!,
    });
    expect(prepared.groups[0]!.preview.findings).toEqual(expected.findings);
    expect(prepared.excluded).toEqual([]);
    expect(cloud.posts).toHaveLength(0);
  },
);

test("the CLI publishes the selected Tenable occurrence", async () => {
  const f = await fixture(tenableReport, tenableReport.repository_url);
  const cli = createCliTest(main);
  const code = await cli.runCli(
    [
      "publish",
      "findings",
      f.file,
      "--to=cloud",
      "--provider=tenable",
      `--repository=${f.destination().id}`,
      `--source-repository-url=${tenableReport.repository_url}`,
      "--source-key=tenant/code-repository",
      "--format=json",
      "--yes",
    ],
    f.cliDeps,
  );
  expect(code, cli.stderr.text()).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    status: "complete",
    verified: 1,
  });
  expect(f.reports.get("00017")?.source).toEqual({
    provider: "tenable",
    source_key: "tenant/code-repository",
  });
});
