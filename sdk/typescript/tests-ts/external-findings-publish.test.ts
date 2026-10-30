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
  normalizeSnykSarif,
  snykRepositoryClaims,
} from "../src/snyk-findings.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";
import { normalizeEndorFindings } from "../src/endor-findings.js";
import { normalizeSemgrepSarif } from "../src/semgrep-findings.js";
import { createServer, type ServerResponse } from "node:http";
import { execFile } from "node:child_process";
import { hash } from "node:crypto";
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
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { gzipSync } from "node:zlib";
import { Database } from "bun:sqlite";
import { afterEach, expect, spyOn, test } from "bun:test";
import {
  ExternalPublicationError,
  prepareExternalPublication,
  prepareNormalizedExternalPublication,
  type ExternalPublicationOptions,
  type ExternalPublicationProgress,
  type PreparedExternalPublication,
} from "../src/external-findings-publish.js";
import { canonicalJson } from "../src/record.js";
import { normalizeGitRepositoryUrl } from "../src/git-remote.js";
import { readGitHubFindings } from "../src/github-findings.js";
import { readVendorFindings } from "../src/wiz-findings.js";
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
import {
  platformFinding,
  platformReport,
} from "./support/semgrep-platform-fixtures.js";
import {
  snykRestFixture,
  snykRestIssue,
  snykRestProject,
} from "./support/snyk-rest-fixtures.js";
import { normalizeTrivyFindings } from "../src/trivy-findings.js";
import { normalizeInspectorFindings } from "../src/inspector-findings.js";
import { inspectorReport } from "./support/inspector-import-fixtures.js";
import {
  trivyReport,
  trivyRepositoryHeader,
} from "./support/trivy-import-fixtures.js";
import { normalizeSnykIssues } from "../src/snyk-rest-findings.js";
import { normalizeSemgrepPlatformFindings } from "../src/semgrep-platform-findings.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { localFindingsFixture } from "./external-findings-local-helpers.js";
import {
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";

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

test("external publication requires opt-in before reading input or accessing Cloud", async () => {
  const root = await mkdtemp(join(tmpdir(), "external-import-disabled-"));
  cleanups.push(() => rm(root, { recursive: true, force: true }));
  const state = join(root, "state");
  let sideEffects = 0;
  const disabled = {
    environment: {
      CODEX_SECURITY_STATE_DIR: state,
    },
    credentials: async () => {
      sideEffects++;
      throw new Error("Unexpected credential read");
    },
    fetch: async () => {
      sideEffects++;
      throw new Error("Unexpected Cloud request");
    },
  };
  // The missing path would fail differently if the file reader ran first.
  await expect(
    prepareExternalPublication(join(root, "missing.json"), options, disabled),
  ).rejects.toThrow("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1");
  await expect(
    prepareNormalizedExternalPublication(
      { read: 0, findings: [], excluded: [] },
      options,
      disabled,
    ),
  ).rejects.toThrow("CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1");
  expect(sideEffects).toBe(0);
  await expect(readdir(state)).rejects.toThrow("ENOENT");
});

test("concurrent external publications enforce opt-in and provider options before Cloud access", async () => {
  const f = await fixture();
  const parsed = await readVendorFindings(f.file);
  let disabledSideEffects = 0;
  const disabled = {
    ...f.deps,
    environment: {
      ...f.environment,
      CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "0",
    },
    credentials: async () => {
      disabledSideEffects++;
      throw new Error("Unexpected credential read");
    },
    fetch: async () => {
      disabledSideEffects++;
      throw new Error("Unexpected Cloud request");
    },
  };
  const results = await Promise.allSettled([
    prepareExternalPublication(f.file, options, f.deps),
    prepareExternalPublication(f.file, options, disabled),
    prepareNormalizedExternalPublication(parsed, options, f.deps),
    prepareNormalizedExternalPublication(parsed, options, disabled),
  ]);
  expect(results.map((result) => result.status)).toEqual([
    "fulfilled",
    "rejected",
    "fulfilled",
    "rejected",
  ]);
  for (const result of results) {
    if (result.status === "fulfilled") {
      expect(result.value.preview.findings).toHaveLength(1);
    } else {
      expect(String(result.reason)).toContain(
        "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
      );
    }
  }
  const incompatible = { ...options, inspectorProjectMap: new Map() };
  const enabled = { ...disabled, environment: f.environment };
  const message = "map requires the inspector provider";
  await expect(
    prepareNormalizedExternalPublication(parsed, incompatible, enabled),
  ).rejects.toThrow(message);
  await expect(
    prepareExternalPublication(
      join(f.root, "missing.json"),
      incompatible,
      enabled,
    ),
  ).rejects.toThrow(message);
  expect(disabledSideEffects).toBe(0);
  expect(f.posts).toHaveLength(0);
});

for (const provider of ["wiz", "snyk"] as const) {
  test(`${provider} publication rechecks the selected Cloud opt-in after reading`, async () => {
    const f =
      provider === "snyk" ? await fixture(snykSarif()) : await fixture();
    let credentialReads = 0;
    const dependencies = {
      ...f.deps,
      environment: { ...f.environment },
      credentials: async () => {
        credentialReads++;
        throw new Error("Unexpected credential read");
      },
    };
    const pending = prepareExternalPublication(
      f.file,
      { ...options, provider },
      dependencies,
    );
    dependencies.environment.CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS = "0";
    await expect(pending).rejects.toThrow(
      "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
    );
    expect(credentialReads).toBe(0);
  });
}

test("Wiz's gzip JSON report retains finding identity, evidence and repository locations", async () => {
  const report = {
    id: "vendor-report-1",
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
      [report, { ...report, id: "vendor-report-2" }]
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
  const original = structuredClone(first.preview.requests[0]!);
  first.preview.requests[0]!.request_id = "edited-request";
  first.preview.findings[0]!.evidence.title = "Edited preview";
  first.preview.requests[0]!.items[0]!.evidence.url =
    "https://github.com/example/other/security/dependabot/1";
  correct.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow();
  expect(JSON.parse(correct.posts[0]!)).toEqual(original);
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
    CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
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
      if (url.pathname.endsWith("/repositories"))
        return json(response, {
          object: "page",
          data: [destination()],
          has_more: false,
          next: null,
        });
      if (url.pathname.endsWith("/source_reports")) {
        const report = reports.get(url.searchParams.get("source_finding_id")!);
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
  };
}

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
    f.state.loseResponse = true;
    await expect(prepared.publish()).rejects.toThrow(
      "resume the saved request",
    );
    return f.posts.at(-1)!;
  }
  return { f, input, project, map, prepare, loseResponse };
}

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
    const trivy = selectedTrivyRows(trivyReport()).findings[0]!;
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

test("a normalized Inspector retry checks its typed repository without native evidence", async () => {
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
      inspectorOptions,
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

test.each(["open-source", "code"] as const)(
  "hosted Snyk %s publishes, replays and verifies an update without assessment",
  async (product) => {
    const sourceRepositoryUrl = "https://github.com/example/project";
    const report = snykRestFixture(product, { sourceRepositoryUrl });
    const cloud = await fixture(report);
    const selected = {
      ...options,
      provider: "snyk" as const,
      sourceKey: `example/hosted/${product}`,
    };
    const publish = async () =>
      (
        await prepareExternalPublication(cloud.file, selected, cloud.deps)
      ).publish();
    expect((await publish()).counts.created).toBe(1);
    expect((await publish()).counts.unchanged).toBe(1);
    await writeFile(
      cloud.file,
      JSON.stringify(
        snykRestFixture(product, {
          sourceRepositoryUrl,
          title: "Changed finding",
          updatedAt: "2025-03-03T04:05:06Z",
        }),
      ),
    );
    const updated = await publish();
    expect(updated).toMatchObject({ verified: 1, counts: { updated: 1 } });
    expect([...cloud.reports.values()]).toMatchObject([
      {
        version: 2,
        assessment: { state: "not_assessed" },
        evidence: { title: "Changed finding" },
      },
    ]);
    await expect(
      prepareExternalPublication(
        cloud.file,
        {
          ...selected,
          sourceRepositoryUrl: "https://github.com/other/project",
        },
        cloud.deps,
      ),
    ).rejects.toThrow("does not match");
  },
);

test("hosted Snyk resolves an unverified Enterprise mapping against the connected Cloud repository", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = {
    ...snykRestFixture("open-source", { sourceRepositoryUrl: url }),
    project: snykRestProject({ origin: "github-enterprise", remote: null }),
  };
  const cloud = await fixture(report, url.toLowerCase());
  const selected = {
    ...options,
    provider: "snyk" as const,
    sourceRepositoryUrl: url.toLowerCase(),
  };
  const prepare = (sourceRepositoryUrl = selected.sourceRepositoryUrl) =>
    prepareExternalPublication(
      cloud.file,
      { ...selected, sourceRepositoryUrl },
      cloud.deps,
    );
  expect(
    (await prepare("https://scm.example.test/old/../team/project")).preview
      .findings,
  ).toHaveLength(1);
  await expect(
    prepare("https://scm.example.test/unusable path/../team/project"),
  ).rejects.toThrow("percent-encode");
  cloud.state.repositoryUrl += "-foreign";
  await expect(prepare()).rejects.toThrow("does not match");
  cloud.state.repositoryUrl = url.toLowerCase();
  report.project = snykRestProject({ origin: "gitlab", remote: url });
  await writeFile(cloud.file, JSON.stringify(report));
  await expect(prepare()).rejects.toThrow("does not match the declared");
});

test("local and Cloud preparations snapshot a class report's repository accessors before resolving its destination", async () => {
  const url = "https://scm.example.test/Team/Project";
  const checkout = url.toLowerCase();
  const cloud = await fixture([], checkout);
  const local = await localFindingsFixture({ remote: checkout });
  cleanups.push(local.dispose);
  const settings = { ...options, provider: "snyk" as const };
  let source = url;
  let platform: "github" | "other" = "other";
  const reads = { url: 0, platform: 0 };
  class ImportedReport {
    read = 1;
    findings = [
      {
        source_finding_id: "example",
        evidence: { title: "Example", severity: "low" as const },
      },
    ];
    excluded = [];
    get sourceRepositoryUrl() {
      reads.url++;
      return source;
    }
    get sourceRepositoryPlatform() {
      reads.platform++;
      return platform;
    }
  }
  const input = new Proxy(new ImportedReport(), {
    has: (target, key) => Object.hasOwn(target, key),
  });
  const localResult = prepareNormalizedLocalImport(
    input,
    { ...settings, repository: local.repository },
    {
      environment: local.environment,
      sourceRepositories: [{ url: checkout, platform: "github" }],
    },
  );
  const cloudResult = prepareNormalizedExternalPublication(
    input,
    settings,
    cloud.deps,
  );
  source = checkout;
  platform = "github";
  expect(reads).toEqual({ url: 2, platform: 2 });
  for (const result of await Promise.allSettled([localResult, cloudResult]))
    expect(result).toMatchObject({
      status: "rejected",
      reason: expect.objectContaining({
        message: expect.stringContaining("does not match"),
      }),
    });
});

test("verified Snyk repositories retain case-sensitive identity when optional raw evidence is projected out", async () => {
  const url = "https://scm.example.test/Team/Project";
  const report = {
    ...snykRestFixture("open-source", { sourceRepositoryUrl: url }),
    project: snykRestProject({ origin: "gitlab", remote: url }),
  };
  const cloud = await fixture(report, url.toLowerCase());
  const local = await localFindingsFixture({ remote: url.toLowerCase() });
  cleanups.push(local.dispose);
  const settings = { ...options, provider: "snyk" as const };
  const file = () =>
    prepareExternalPublication(cloud.file, settings, cloud.deps);
  await expect(file()).rejects.toThrow("does not match");
  const normalized = normalizeSnykIssues(report);
  const sdk = () =>
    prepareNormalizedExternalPublication(normalized, settings, cloud.deps);
  // Either the verified native row or the report binding can establish the restriction.
  delete normalized.sourceRepositoryPlatform;
  await expect(sdk()).rejects.toThrow("does not match");
  cloud.state.repositoryUrl = url;
  normalized.sourceRepositoryUrl = url.toLowerCase();
  await expect(sdk()).rejects.toThrow("does not match");
  normalized.sourceRepositoryUrl = url;
  const sibling = normalizeSnykIssues(
    snykRestFixture("code", { sourceRepositoryUrl: url }),
  ).findings[0]!;
  delete sibling.evidence.source_data;
  sibling.evidence.details!.repository!.url = url.toLowerCase();
  normalized.findings.push(sibling);
  await expect(sdk()).rejects.toThrow("does not match");
  normalized.findings.pop();
  cloud.state.repositoryUrl = url.toLowerCase();
  normalized.sourceRepositoryPlatform = "other";
  for (const finding of normalized.findings)
    delete finding.evidence.source_data;
  await expect(sdk()).rejects.toThrow("does not match");
  await expect(
    prepareNormalizedLocalImport(
      normalized,
      { ...settings, repository: local.repository },
      { environment: local.environment },
    ),
  ).rejects.toThrow("does not match");
  const unverified = normalizeSnykIssues({
    ...report,
    project: snykRestProject({ origin: "github-enterprise", remote: null }),
  });
  unverified.sourceRepositoryPlatform = "github";
  const unverifiedLocal = () =>
    prepareNormalizedLocalImport(
      unverified,
      { ...settings, repository: local.repository },
      { environment: local.environment },
    );
  await expect(unverifiedLocal()).rejects.toThrow("does not match");
  for (const finding of unverified.findings)
    delete finding.evidence.source_data;
  await expect(unverifiedLocal()).rejects.toThrow("does not match");
  cloud.state.repositoryUrl = url;
  expect((await sdk()).preview.findings).toHaveLength(1);
  expect((await file()).preview.findings).toHaveLength(1);
});

test.each(["cloud", "local"] as const)(
  "%s preparation checks retained Snyk project context after adding a finding",
  async (target) => {
    const url = "https://scm.example.test/Team/project";
    const cloud = await fixture([], url);
    const local = await localFindingsFixture({ remote: url });
    cleanups.push(local.dispose);
    const typed = normalizeSnykIssues(
      snykRestFixture("code", { sourceRepositoryUrl: url }),
    );
    delete typed.findings[0]!.evidence.source_data;
    const prepare = (
      sourceRepositoryUrl: string,
      provider: "snyk" | "semgrep" | "wiz" = "snyk",
    ) => {
      const settings = { ...options, provider };
      const empty = normalizeSnykIssues({
        ...snykRestFixture("open-source", { sourceRepositoryUrl, issues: [] }),
        project: snykRestProject({
          origin: "gitlab",
          remote: sourceRepositoryUrl,
        }),
      });
      const input = { ...empty, ...typed };
      if (provider !== "snyk") {
        delete input.sourceRepositoryUrl;
        delete input.sourceRepositoryPlatform;
      }
      return target === "cloud"
        ? prepareNormalizedExternalPublication(input, settings, cloud.deps)
        : prepareNormalizedLocalImport(
            input,
            { ...settings, repository: local.repository },
            { environment: local.environment },
          );
    };
    await expect(prepare(url + "-other")).rejects.toThrow("does not match");
    expect((await prepare(url)).preview.findings).toHaveLength(1);
    for (const provider of ["wiz", "semgrep"] as const)
      await expect(prepare(url + "-other", provider)).rejects.toThrow(
        "requires the snyk provider",
      );
  },
);

test("a pending Snyk publication binds the projected report's repository and comparison policy", async () => {
  const url = "https://scm.example.test/team/project";
  const normalized = normalizeSnykIssues({
    ...snykRestFixture("open-source", { sourceRepositoryUrl: url }),
    project: snykRestProject({ origin: "gitlab", remote: url }),
  });
  for (const finding of normalized.findings)
    delete finding.evidence.source_data;
  const cloud = await fixture([], url);
  const prepare = (repository = options.repository) =>
    prepareNormalizedExternalPublication(
      normalized,
      { ...options, provider: "snyk", repository },
      cloud.deps,
    );
  cloud.state.loseResponse = true;
  await expect(
    (await prepare(url.replace("team", "TEAM"))).publish(),
  ).rejects.toThrow("resume the saved request");
  normalized.sourceRepositoryUrl = "https://scm.example.test/Team/Project";
  await expect(prepare()).rejects.toThrow("does not match");
  normalized.sourceRepositoryUrl = url;
  delete normalized.sourceRepositoryPlatform;
  await expect(prepare()).rejects.toThrow("does not match");
  normalized.sourceRepositoryPlatform = "other";
  cloud.state.repositoryUrl = "https://scm.example.test/renamed/project";
  const retry = await prepare(
    cloud.state.repositoryUrl.replace("renamed", "RENAMED"),
  );
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).status).toBe("complete");
  expect(cloud.posts[1]).toBe(cloud.posts[0]);
});

test("hosted Semgrep accepts Enterprise casing against the connected Cloud repository", async () => {
  const url = "https://scm.example.test/Team/Proj%65ct";
  const report = platformReport();
  const row = platformFinding(7);
  const cloud = await fixture({
    ...report,
    project: { ...report.project, url },
    findings: [
      {
        ...row,
        repository: {
          name: "physical-monorepo",
          url: "ssh://g%69t@%73cm.example.test/team/project.git",
        },
      },
    ],
  });
  cloud.state.repositoryUrl = "https://scm.example.test/team/project";
  const selected = {
    ...options,
    provider: "semgrep" as const,
    sourceRepositoryUrl: cloud.state.repositoryUrl,
  };
  const prepare = () =>
    prepareExternalPublication(cloud.file, selected, cloud.deps);
  expect((await prepare()).preview.findings).toHaveLength(1);
  cloud.state.repositoryUrl += "-foreign";
  await expect(prepare()).rejects.toThrow("does not match");
});

test.each(["implicit", "explicit"] as const)(
  "a pending Snyk publication preserves its %s clone spelling approval",
  async (mapping) => {
    const url = "https://scm.example.test/Team/repo";
    const clone = url + ".git";
    const cloud = await fixture([], clone);
    const findings = [url, clone].map(
      (sourceRepositoryUrl, i) =>
        normalizeSnykIssues({
          ...snykRestFixture("open-source", {
            sourceRepositoryUrl,
            issues: [snykRestIssue({ key: "issue-" + i })],
          }),
          project: snykRestProject({ origin: "gitlab", remote: url }),
        }).findings[0]!,
    );
    findings.push({
      source_finding_id: "opaque",
      evidence: { title: "Opaque", severity: "high" },
    });
    const prepare = (sourceRepositoryUrl?: string) =>
      prepareNormalizedExternalPublication(
        { read: findings.length, excluded: [], findings, sourceRepositoryUrl },
        { ...options, provider: "snyk" },
        cloud.deps,
      );
    await expect(prepare(url)).rejects.toThrow("does not match");
    const approved = mapping === "explicit" ? url : undefined;
    if (approved) cloud.state.repositoryUrl = url;
    const original = await prepare(approved);
    cloud.state.loseResponse = true;
    await expect(original.publish()).rejects.toThrow(
      "resume the saved request",
    );
    cloud.state.repositoryUrl = "https://scm.example.test/Renamed/repo";
    await expect(prepare(approved ? undefined : url)).rejects.toThrow(
      "does not match",
    );
    expect(cloud.posts).toHaveLength(1);
    await (await prepare(approved)).publish();
    expect(cloud.posts[1]).toBe(cloud.posts[0]);
  },
);

test("a stricter Snyk declaration checks the original GitHub Enterprise target on Cloud", async () => {
  const sourceRepositoryUrl = "https://scm.example.test/Team/project";
  const cloud = await fixture([], sourceRepositoryUrl);
  const prepare = (remote: string) =>
    prepareNormalizedExternalPublication(
      {
        ...normalizeSnykIssues({
          ...snykRestFixture("open-source", { sourceRepositoryUrl }),
          project: snykRestProject({ origin: "github-enterprise", remote }),
        }),
        sourceRepositoryPlatform: "other",
      },
      { ...options, provider: "snyk" },
      cloud.deps,
    );
  expect((await prepare(sourceRepositoryUrl)).preview.findings).toHaveLength(1);
  await expect(prepare(sourceRepositoryUrl.toLowerCase())).rejects.toThrow(
    "does not match",
  );
  expect(cloud.posts).toHaveLength(0);
});

test("hosted Snyk compares legacy SSH claims with the verified platform's casing", async () => {
  const url = "https://scm.example.test/Team/my%2Drepo";
  const hosted = normalizeSnykIssues({
    ...snykRestFixture("open-source", { sourceRepositoryUrl: url }),
    project: snykRestProject({ origin: "gitlab", remote: url }),
  });
  const cloud = await fixture([], url);
  for (const format of ["plugin", "SARIF"] as const) {
    const prepare = async (owner: string) => {
      const { normalized } = await snykRepositoryEvidence(
        format,
        `git@scm.example.test:${owner}/my-repo.git`,
      );
      return prepareNormalizedExternalPublication(
        { ...hosted, findings: [...normalized.findings, ...hosted.findings] },
        { ...options, provider: "snyk" },
        cloud.deps,
      );
    };
    await expect(prepare("team")).rejects.toThrow("does not match");
    expect((await prepare("Team")).preview.findings).toHaveLength(2);
  }
  expect(cloud.posts).toHaveLength(0);
});

test("a bound retry accepts equivalent HTTP path bytes after a catalog rename", async () => {
  const original = "https://scm.example.test/Team/Jalapeño%2Drepo";
  const plain = "https://scm.example.test/Team/Jalape%C3%B1o-repo";
  const cloud = await fixture([], plain);
  const prepare = (sourceRepositoryUrl: string) =>
    prepareNormalizedExternalPublication(
      {
        read: 1,
        findings: [
          {
            source_finding_id: "issue-1",
            evidence: { title: "Example finding", severity: "high" },
          },
        ],
        excluded: [],
        sourceRepositoryUrl,
        sourceRepositoryPlatform: "other",
      },
      { ...options, provider: "snyk" },
      cloud.deps,
    );
  const first = await prepare(original);
  cloud.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  cloud.state.repositoryUrl += "-renamed";
  await expect(prepare(plain.replace("Team", "team"))).rejects.toThrow(
    "does not match",
  );
  const retry = await prepare(plain);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).verified).toBe(1);
  expect(cloud.posts[1]).toBe(cloud.posts[0]);
});

test.each([
  ["proj%2Egit", "proj%2Egit.git", false],
  ["pkg", "pKg", false],
  ["app/sub/..", "app/sub/...git", false],
  ["pr%6Fject", "pr%6Fject", true],
] as const)(
  "checks the earlier Cloud URL comparison for %s",
  async (path, catalog, safe) => {
    const prefix = "https://github.com/example/";
    const source = prefix + path;
    const cloud = await fixture([], prefix + catalog);
    const { findings } = normalizeSemgrepPlatformFindings(platformReport());
    const evidence = findings[0]!.evidence;
    delete evidence.source_data;
    evidence.details!.repository = { url: source };
    const prepare = (sourceRepositoryUrl?: string) =>
      prepareNormalizedExternalPublication(
        { read: 1, findings, excluded: [], sourceRepositoryUrl },
        { ...options, provider: "semgrep" },
        cloud.deps,
      );
    cloud.state.loseResponse = true;
    await expect((await prepare()).publish()).rejects.toThrow(
      "resume the saved request",
    );
    if (!safe) await expect(prepare(source)).rejects.toThrow("does not match");
    cloud.state.repositoryUrl = prefix + "renamed";
    if (!safe) {
      await expect(prepare(source)).rejects.toThrow("does not match");
      cloud.state.repositoryUrl = source;
    }
    const retry = await prepare(source);
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).verified).toBe(1);
    expect(cloud.posts).toEqual([cloud.posts[0]!, cloud.posts[0]!]);
  },
);

test.each([
  ["snyk", "1.0000000000000001", 1],
  ["snyk", "1e-999", 0],
  ["snyk", "1e400", null],
  ["snyk", "1.0000000000000001", "1.0000000000000001"],
  ["semgrep", "9223372036854775807", "9223372036854775807"],
] as const)(
  "checks exact %s number %s against a public request that retained %j",
  async (provider, exact, retained) => {
    const cloud = await fixture();
    const report =
      provider === "snyk"
        ? snykRestFixture("open-source", {
            sourceRepositoryUrl: cloud.state.repositoryUrl,
            issues: [snykRestIssue({ risk_score: "SCORE" })],
          })
        : platformReport([{ ...platformFinding(12), risk_score: "SCORE" }]);
    const prepare = async (token: string) => {
      await writeFile(
        cloud.file,
        JSON.stringify(report).replace('"SCORE"', token),
      );
      return prepareExternalPublication(
        cloud.file,
        { ...options, provider },
        cloud.deps,
      );
    };
    cloud.state.loseResponse = true;
    const first = await prepare(JSON.stringify(retained));
    const error = await first.publish().catch((error: unknown) => error);
    if (!(error instanceof ExternalPublicationError)) throw error;
    const path = error.result.savedSubmission!;
    // The current writer keeps the two inputs separate.
    expect((await prepare(exact)).preview.resumed).toBe(false);
    const saved = JSON.parse(await readFile(path, "utf8"));
    // The public writer hashed this fully populated evidence without the hosted scope.
    saved.inputProjection.inputDigest =
      saved.inputProjection.savedEvidenceDigest;
    const previous = JSON.stringify(saved);
    await writeFile(path, previous);
    const held = provider === "semgrep" || typeof retained !== "string";
    if (held) {
      await expect(prepare(exact)).rejects.toThrow(/number|numeric|rounded/iu);
    } else {
      const fresh = await prepare(exact);
      expect(fresh.preview.resumed).toBe(false);
      expect((await fresh.publish()).verified).toBe(1);
      expect(JSON.parse(cloud.posts[1]!).request_id).not.toBe(
        saved.requests[0].request_id,
      );
    }
    expect(await readFile(path, "utf8")).toBe(previous);
    expect(cloud.posts).toHaveLength(held ? 1 : 2);
    if (provider === "semgrep") {
      cloud.state.marker = "generation-2";
      expect((await prepare(exact)).preview.resumed).toBe(false);
      expect(await readFile(path, "utf8")).toBe(previous);
      await expect(prepare(JSON.stringify(retained))).rejects.toThrow(
        "retired without uploading",
      );
      expect(cloud.posts).toHaveLength(1);
      return;
    }
    const retry = await prepare(JSON.stringify(retained));
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).verified).toBe(1);
    expect(cloud.posts.at(-1)).toBe(cloud.posts[0]!);
  },
);

test("a repository reset retires an unbound Semgrep request after a rename", async () => {
  const { findings, sourceRepositoryUrl } =
    normalizeSemgrepPlatformFindings(platformReport());
  delete findings[0]!.evidence.source_data;
  delete findings[0]!.evidence.details;
  const cloud = await fixture([], sourceRepositoryUrl);
  const prepare = (sourceRepositoryUrl?: string) =>
    prepareNormalizedExternalPublication(
      { read: 1, findings, excluded: [], sourceRepositoryUrl },
      { ...options, provider: "semgrep" },
      cloud.deps,
    );
  const first = await prepare();
  cloud.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");

  cloud.state.repositoryUrl += "-renamed";
  await expect(prepare(sourceRepositoryUrl)).rejects.toThrow("does not match");
  cloud.state.marker = "generation-2";
  await expect(prepare(sourceRepositoryUrl)).rejects.toThrow(
    "retired without uploading",
  );
  await expect(prepare(sourceRepositoryUrl)).rejects.toThrow("does not match");
  const fresh = await prepare(cloud.state.repositoryUrl);
  expect(fresh.preview.resumed).toBe(false);
  expect(cloud.posts).toHaveLength(1);
});

test.each([
  "retained",
  "projected",
  "native-only",
  "strict",
  "case-folded",
] as const)(
  "binds a public checkpoint with %s repository evidence before retrying the POST",
  async (kind) => {
    const { findings, sourceRepositoryUrl } =
      normalizeSemgrepPlatformFindings(platformReport());
    const source =
      kind === "strict"
        ? "https://scm.example.test/Team/Repo"
        : kind === "case-folded"
          ? "https://github.com/example/Kit"
          : sourceRepositoryUrl;
    const cloud = await fixture(
      [],
      kind === "case-folded" ? source.replace("K", "K") : source,
    );
    const evidence = findings[0]!.evidence;
    if (kind !== "native-only") delete evidence.source_data;
    if (kind === "projected" || kind === "native-only") delete evidence.details;
    else evidence.details!.repository!.url = source;
    const prepare = (declared: boolean) =>
      prepareNormalizedExternalPublication(
        {
          read: 1,
          findings,
          excluded: [],
          ...(declared && { sourceRepositoryUrl: source }),
          ...(declared &&
            kind === "strict" && {
              sourceRepositoryPlatform: "other" as const,
            }),
        },
        { ...options, provider: "semgrep" },
        cloud.deps,
      );
    // The public SDK hashed validated findings, with no separate repository binding.
    const first = await prepare(false);
    cloud.state.loseResponse = true;
    const error = await first.publish().catch((error: unknown) => error);
    if (!(error instanceof ExternalPublicationError)) throw error;
    const path = error.result.savedSubmission!;
    const projection = async () =>
      JSON.parse(await readFile(path, "utf8")).inputProjection;
    const request: FindingImportRequest = JSON.parse(cloud.posts[0]!);
    const bare = hash(
      "sha256",
      canonicalJson(
        request.items.map(({ source_finding_id, evidence }) => ({
          source_finding_id,
          evidence,
        })),
      ),
    );
    if (kind === "native-only") {
      // The base SDK hashed even opaque native evidence without a repository binding.
      const saved = JSON.parse(await readFile(path, "utf8"));
      expect(saved.inputProjection.savedEvidenceDigest).toBe(bare);
      saved.inputProjection.inputDigest = bare;
      await writeFile(path, JSON.stringify(saved));
    }
    expect((await projection()).inputDigest).toBe(bare);
    if (kind === "case-folded")
      await expect(prepare(true)).rejects.toThrow("does not match");
    cloud.state.repositoryUrl =
      kind === "strict" ? source.toLowerCase() : source + "-renamed";
    if (kind !== "retained") {
      await expect(prepare(true)).rejects.toThrow("does not match");
      expect(cloud.posts).toHaveLength(1);
      cloud.state.repositoryUrl = source;
    }
    const fetch = cloud.deps.fetch;
    let digestAtPost: string | undefined;
    cloud.deps.fetch = async (url, init) => {
      if (init.method === "POST")
        digestAtPost = (await projection()).inputDigest;
      return fetch(url, init);
    };
    const unboundRetry =
      kind === "native-only" ? undefined : await prepare(false);
    const retry = await prepare(true);
    expect(retry.preview.resumed).toBe(true);
    expect((await projection()).inputDigest).toBe(bare);
    cloud.state.loseResponse = true;
    await expect(retry.publish()).rejects.toThrow("resume the saved request");
    expect(digestAtPost).toMatch(/^[a-f0-9]{64}$/u);
    expect(digestAtPost).not.toBe(bare);
    if (unboundRetry)
      await expect(unboundRetry.publish()).rejects.toThrow("does not match");
    expect(cloud.posts).toHaveLength(2);
    expect((await projection()).inputDigest).toBe(digestAtPost);
    cloud.state.repositoryUrl += "-renamed";
    expect((await (await prepare(true)).publish()).verified).toBe(1);
    expect(cloud.posts).toHaveLength(3);
    expect(new Set(cloud.posts).size).toBe(1);
  },
);

test.each(["semgrep", "snyk"] as const)(
  "%s honors strict declared repository paths in normalized evidence",
  async (provider) => {
    const sourceRepositoryUrl = "https://scm.example.test/Team/repo";
    const cloud = await fixture([], sourceRepositoryUrl);
    const prepare = (url: string, repository = options.repository) =>
      prepareNormalizedExternalPublication(
        {
          read: 1,
          excluded: [],
          sourceRepositoryUrl,
          sourceRepositoryPlatform: "other",
          findings: [
            {
              source_finding_id: "issue-1",
              evidence: {
                title: "Example",
                severity: "low",
                details: { kind: "sast", repository: { url } },
              },
            },
          ],
        },
        { ...options, provider, repository },
        cloud.deps,
      );
    expect((await prepare(sourceRepositoryUrl)).preview.findings).toHaveLength(
      1,
    );
    expect(
      (await prepare(sourceRepositoryUrl + "/%09/..")).preview.findings,
    ).toHaveLength(1);
    await expect(prepare(sourceRepositoryUrl + "/raw\t/..")).rejects.toThrow(
      "percent-encode",
    );
    await expect(
      prepare(sourceRepositoryUrl, sourceRepositoryUrl + "/raw\t/.."),
    ).rejects.toThrow("percent-encode");
    await expect(prepare(sourceRepositoryUrl.toLowerCase())).rejects.toThrow(
      "does not match",
    );
    cloud.state.repositoryUrl = sourceRepositoryUrl.toLowerCase();
    await expect(prepare(sourceRepositoryUrl)).rejects.toThrow(
      "does not match",
    );
    expect(cloud.posts).toHaveLength(0);
  },
);

test("Cloud rejects hosted repository declarations on unrelated providers before authentication", async () => {
  const input = {
    read: 1,
    excluded: [],
    findings: [],
    sourceRepositoryUrl: "https://github.com/example/repo",
  };
  for (const provider of ["wiz", "github", "endor", "inspector"] as const) {
    await expect(
      prepareNormalizedExternalPublication(
        input,
        { ...options, provider },
        {
          environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
          credentials: async () => {
            throw new Error("unexpected credential lookup");
          },
        },
      ),
    ).rejects.toThrow("require the Snyk or Semgrep provider");
  }
});

test.each(["snyk-rest-issues/v1", "semgrep-platform-findings/v1"])(
  "Cloud binds hosted %s evidence to its provider for normalized and JSONL input",
  async (format) => {
    const finding = {
      source_finding_id: "opaque",
      evidence: {
        title: "Example finding",
        severity: "low" as const,
        source_data: { format },
      },
    };
    const cloud = await fixture();
    const deps = {
      ...cloud.deps,
      credentials: async () => {
        throw new Error("unexpected credential lookup");
      },
    };
    await expect(
      prepareNormalizedExternalPublication(
        { read: 1, excluded: [], findings: [finding] },
        options,
        deps,
      ),
    ).rejects.toThrow(/provider/i);
    const path = cloud.file + ".jsonl";
    await writeFile(path, JSON.stringify(finding) + "\n");
    await expect(
      prepareExternalPublication(path, options, deps),
    ).rejects.toThrow(/provider/i);
    expect(cloud.posts).toHaveLength(0);
  },
);

test("platform-only Semgrep declarations check retained SARIF provenance before fresh publication and retry", async () => {
  const foreign = "https://github.com/example/foreign";
  const cloud = await fixture();
  const prepare = (
    sourceRepositoryUrl?: string,
    sourceRepositoryPlatform?: "github",
    repositoryUri = foreign,
  ) =>
    prepareNormalizedExternalPublication(
      {
        read: 1,
        excluded: [],
        sourceRepositoryUrl,
        sourceRepositoryPlatform,
        findings: [
          {
            source_finding_id: "sarif",
            evidence: {
              title: "Example",
              severity: "low",
              source_data: {
                runContext: {
                  versionControlProvenance: [{ repositoryUri }],
                },
              },
            },
          },
        ],
      },
      { ...options, provider: "semgrep" },
      cloud.deps,
    );
  await expect(
    prepare(foreign.replace("://", "://user:example@")),
  ).rejects.toThrow("without credentials");
  await expect(prepare("")).rejects.toThrow("Source repository URL");
  await expect(prepare(undefined, "github")).rejects.toThrow("does not match");
  const first = await prepare();
  cloud.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  await expect(prepare(foreign)).rejects.toThrow("does not match");
  await expect(prepare(undefined, "github")).rejects.toThrow("does not match");
  cloud.state.repositoryUrl = foreign;
  expect((await prepare(undefined, "github")).preview.resumed).toBe(true);
  const invalid = foreign + "/raw\x7f/..";
  const pending = await prepare(undefined, undefined, invalid);
  cloud.state.loseResponse = true;
  await expect(pending.publish()).rejects.toThrow("resume the saved request");
  await expect(prepare(undefined, "github", invalid)).rejects.toThrow(
    "percent-encode",
  );
  expect(cloud.posts).toHaveLength(2);
});

test("Semgrep keeps retained row casing bound to the declared platform on Cloud", async () => {
  const url = "https://scm.example.test/Team/repo";
  const row = platformFinding(7);
  const report = platformReport([
    { ...row, repository: { name: "repo", url } },
  ]);
  const input = normalizeSemgrepPlatformFindings({
    ...report,
    project: { ...report.project, url },
  });
  const cloud = await fixture([], url);
  const data = input.findings[0]!.evidence.source_data!;
  (data["finding"] as typeof row).repository.url = url.toLowerCase();
  await expect(
    prepareNormalizedExternalPublication(
      { ...input, sourceRepositoryPlatform: "other" },
      { ...options, provider: "semgrep" },
      cloud.deps,
    ),
  ).rejects.toThrow("repository");
  expect(cloud.posts).toHaveLength(0);
});

test.each(["report", "row", "selector", "catalog"] as const)(
  "checks the web destination of a projected Cloud report's %s URL",
  async (field) => {
    const source = "https://scm.example.test/Team/repo";
    const ambiguous = "https://scm.example.test/Team/%2e%2e/../repo";
    const cloud = await fixture([], field === "catalog" ? ambiguous : source);
    const input = normalizeSemgrepPlatformFindings(platformReport());
    input.sourceRepositoryUrl = field === "report" ? ambiguous : source;
    const evidence = input.findings[0]!.evidence;
    delete evidence.source_data;
    evidence.details!.repository!.url = field === "row" ? ambiguous : source;
    const repository = field === "selector" ? ambiguous : options.repository;
    await expect(
      prepareNormalizedExternalPublication(
        input,
        { ...options, provider: "semgrep", repository },
        cloud.deps,
      ),
    ).rejects.toThrow(/repositor/iu);
  },
);

test("hosted Semgrep binds retained SARIF provenance after typed evidence is projected out", async () => {
  const hosted = normalizeSemgrepPlatformFindings(platformReport());
  const cloud = await fixture([], hosted.sourceRepositoryUrl);
  const settings = { ...options, provider: "semgrep" as const };
  const sarif = semgrepSarif();
  function mixed(url: string) {
    const legacy = normalizeSemgrepSarif(
      {
        ...sarif,
        runs: sarif.runs.map((run) => ({
          ...run,
          versionControlProvenance: [{ repositoryUri: url }],
        })),
      },
      { sourceRepositoryUrl: url },
    );
    const row = legacy.findings[0]!;
    delete row.evidence.details;
    return { read: 2, findings: [row, ...hosted.findings], excluded: [] };
  }
  const foreign = mixed("https://github.com/example/foreign");
  for (const input of [foreign, { ...hosted, ...foreign }])
    await expect(
      prepareNormalizedExternalPublication(input, settings, cloud.deps),
    ).rejects.toThrow("does not match");
  expect(cloud.posts).toHaveLength(0);
  const valid = mixed(hosted.sourceRepositoryUrl);
  const prepare = () =>
    prepareNormalizedExternalPublication(valid, settings, cloud.deps);
  cloud.state.repositoryUrl = hosted.sourceRepositoryUrl.replace(
    "/project",
    "/proj%65ct",
  );
  const first = await prepareNormalizedExternalPublication(
    valid,
    { ...settings, repository: hosted.sourceRepositoryUrl },
    cloud.deps,
  );
  cloud.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  cloud.state.repositoryUrl += "-renamed";
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).verified).toBe(2);
  expect(cloud.posts[1]).toBe(cloud.posts[0]);
});

test.each(["semgrep", "snyk"] as const)(
  "normalized %s cannot mask a foreign native repository with the selected project",
  async (provider) => {
    const sourceRepositoryUrl = "https://github.com/example/project";
    const foreign = "https://github.com/example/other";
    const input =
      provider === "semgrep"
        ? normalizeSemgrepPlatformFindings(platformReport())
        : normalizeSnykIssues(snykRestFixture("code", { sourceRepositoryUrl }));
    const local = await localFindingsFixture({ remote: sourceRepositoryUrl });
    cleanups.push(local.dispose);
    const alias = structuredClone(input.findings[0]!);
    alias.source_finding_id = "typed-only";
    delete alias.evidence.source_data;
    alias.evidence.details!.repository!.url =
      provider === "snyk"
        ? "git@github.com:example/project.git"
        : "ssh://git@github.com/example/project.git";
    const localOptions = { ...options, provider, repository: local.repository };
    const localDeps = { environment: local.environment };
    const mixed = { ...input, read: 2, findings: [...input.findings, alias] };
    expect(
      (await prepareNormalizedLocalImport(mixed, localOptions, localDeps))
        .preview.findings,
    ).toHaveLength(2);
    const cloud = await fixture([], sourceRepositoryUrl);
    const settings = { ...options, provider };
    input.sourceRepositoryUrl = foreign;
    await expect(
      prepareNormalizedExternalPublication(input, settings, cloud.deps),
    ).rejects.toThrow("does not match the source report repository");
    cloud.state.repositoryUrl = foreign;
    input.findings[0]!.evidence.details!.repository!.url = foreign;
    await expect(
      prepareNormalizedExternalPublication(input, settings, cloud.deps),
    ).rejects.toThrow("does not match");
    expect(cloud.posts).toHaveLength(0);

    await promisify(execFile)("git", [
      "-C",
      local.repository,
      "remote",
      "add",
      "upstream",
      foreign,
    ]);
    const plain = await mkdtemp(join(local.root, "plain-"));
    for (const [sourceRepositoryUrl, error] of [
      [foreign, "does not match"],
      ["", "Source repository URL must be nonempty text"],
    ] as const)
      for (const repository of [local.repository, plain])
        await expect(
          prepareNormalizedLocalImport(
            { ...input, sourceRepositoryUrl },
            { ...localOptions, repository },
            localDeps,
          ),
        ).rejects.toThrow(error);
  },
);

test("Semgrep Supply Chain binds fresh requests to its project and resumes after a rename", async () => {
  const record = {
    ...platformFinding(3),
    found_dependency: { package: "example", version: "1" },
    vulnerability_identifier: "CVE-2025-0001",
  };
  const report = { ...platformReport([record]), product: "sca" };
  const cloud = await fixture(report);
  const settings = { ...options, provider: "semgrep" as const };
  const prepare = () =>
    prepareExternalPublication(cloud.file, settings, cloud.deps);
  const first = await prepare();
  cloud.state.loseResponse = true;
  await expect(first.publish()).rejects.toThrow("resume the saved request");
  cloud.state.repositoryUrl = "https://github.com/example/renamed";
  const changed = {
    ...normalizeSemgrepPlatformFindings(report),
    sourceRepositoryUrl: cloud.state.repositoryUrl,
  };
  await expect(
    prepareNormalizedExternalPublication(changed, settings, cloud.deps),
  ).rejects.toThrow("does not match the source report repository");
  expect(cloud.posts).toHaveLength(1);
  const retry = await prepare();
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).verified).toBe(1);
  expect(cloud.posts[1]).toBe(cloud.posts[0]);
  await expect(prepare()).rejects.toThrow("does not match");
  expect(cloud.posts).toHaveLength(2);
});

test("a canceled Cloud preparation does not open the artifact or contact the destination", async () => {
  const stopped = new Error("import stopped");
  await expect(
    prepareExternalPublication("absent-file", options, {
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
      signal: AbortSignal.abort(stopped),
    }),
  ).rejects.toBe(stopped);
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
            expect(question).toContain("skip 1 excluded");
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
    expect(second.code).toBe(0);
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
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
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
    expect((await first.publish()).counts.created).toBe(count);
    const completedPosts = f.posts.length;
    f.state.postBudget = count === 1 ? 0 : 1;
    expect((await second.publish()).counts.created).toBe(count);
    expect(f.posts.slice(completedPosts)).toEqual(
      count === 1 ? [] : [JSON.stringify(second.preview.requests[1])],
    );
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

test("repository selection is sent on every discovery page", async () => {
  const f = await fixture();
  const repository = `${f.destination().url}.git`;
  const queries: URLSearchParams[] = [];
  const prepared = await prepareExternalPublication(
    f.file,
    { ...options, repository },
    {
      ...f.deps,
      fetch: async (input, init) => {
        const url = new URL(input);
        if (!url.pathname.endsWith("/repositories"))
          return f.deps.fetch(input, init);
        queries.push(url.searchParams);
        const first = queries.length === 1;
        return Response.json({
          object: "page",
          data: first ? [] : [f.destination()],
          has_more: first,
          next: first ? "next-page" : null,
        });
      },
    },
  );
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
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    onProgress: () => {
      throw new Error("Optional observer failed");
    },
  });
  expect((await prepared.publish()).status).toBe("complete");
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
    f.state.repositoryUrl = "https://github.com:443/example/project";
    const result = await (
      await prepareExternalPublication(f.file, selected, f.deps)
    ).publish();
    expect(result.counts.created).toBe(1);
    expect(result.verified).toBe(1);
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
  expect(f.posts).toHaveLength(0);
});

test("publication JSON retains native Error messages and scanner diagnostics", async () => {
  const scannerErrors = opengrepJson().errors;
  const error = new Error("Scanner rule timed out.");
  const nested = {
    path: "src/example.ts",
    cause: new Error("Parser stopped."),
  };
  const report = { errors: [error, nested, ...scannerErrors] };
  const jsonErrors = [
    { message: error.message },
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
  const original = structuredClone(report);
  nested.cause.message = "Caller changed the diagnostic.";
  const completed = await prepared.publish();
  expect(completed.verified).toBe(1);
  for (const value of [prepared.preview.report, completed.report]) {
    expect(value).toEqual(original);
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
  f.state.repositoryUrl = "https://github.com/other/project";
  const posted = f.posts.length;
  await expect(
    prepareExternalPublication(f.file, selected, f.deps),
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

test.each([
  [
    "http://git.example.test/Example/Project",
    "http://git.example.test/example/project.git",
  ],
  [
    "https://git.example.test/Example/Project",
    "https://git.example.test/example/project.git",
  ],
  [connectedProject, "git@git.example.test:example/project.git"],
])(
  "Trivy CLI verifies Enterprise artifact %s and report remote %s before publication",
  async (artifact, remote) => {
    const report = trivyReport();
    report.ArtifactName = artifact;
    report.Metadata.RepoURL = remote;
    const scheme = remote.startsWith("http:") ? "http" : "https";
    const fixtureData = await fixture(
      report,
      `${scheme}://git.example.test/example/project`,
    );
    const command = [...fixtureData.command, "--trivy-scan-root", "."];
    command[command.indexOf("--provider") + 1] = "trivy";
    const cli = createCliTest(main);
    expect(
      await cli.runCli([...command, "--dry-run"], fixtureData.cliDeps),
    ).toBe(0);
    expect(fixtureData.posts).toHaveLength(0);
    const code = await cli.runCli([...command, "--yes"], fixtureData.cliDeps);
    expect({ code, error: cli.stderr.text() }).toEqual({ code: 0, error: "" });
    expect(fixtureData.posts).toHaveLength(1);
    expect(
      JSON.parse(fixtureData.posts[0]!).items[0].evidence.source_data.report
        .Metadata.RepoURL,
    ).toBe(remote);
    expect([...fixtureData.reports.values()]).toMatchObject([
      {
        source: { provider: "trivy" },
        assessment: { state: "not_assessed" },
      },
    ]);
  },
);

test("Trivy CLI rejects a checkout-supplied repository label even in a dry run", async () => {
  const report = trivyReport();
  report.ArtifactName = "ssh://tenant-a@git.example.test/example/project";
  report.Metadata.RepoURL = "ssh://git.example.test/example/project";
  const f = await fixture(report, connectedProject);
  const command = [...f.command, "--trivy-scan-root", "."];
  command[command.indexOf("--provider") + 1] = "trivy";
  const cli = createCliTest(main);
  for (const mode of ["--dry-run", "--yes"]) {
    expect(await cli.runCli([...command, mode], f.cliDeps)).toBe(2);
    expect(cli.stderr.text()).toContain("Trivy omitted the SSH user");
  }
  expect(f.posts).toHaveLength(0);
});

test.each([
  ["HTTPS://github.com/example/project", gitHubProject, undefined],
  ["Git+SSH://git@github.com/example/project", gitHubProject, undefined],
  [
    "http://git.example.test/example/project.git",
    connectedProject,
    "http://git.example.test/Example/Project",
  ],
  [gitHubProject, foreignArtifactUrl, undefined],
  ["git@github.com:example/project.git.git", gitHubProject, undefined],
  [
    "ssh://git@git.example.test/other/../example/project.git",
    connectedProject,
    undefined,
  ],
  [
    "https://git.example.test/example/project.git",
    "https://git.example.test/example/other",
    "https://git.example.test/Example/Project",
  ],
])(
  "Trivy source %s is rejected for Cloud destination %s by both entrypoints",
  async (source, destination, artifact) => {
    const report = trivyReport();
    if (artifact) report.ArtifactName = artifact;
    report.Metadata.RepoURL = source;
    const cloud = await fixture(report, destination);
    await expect(
      prepareExternalPublication(cloud.file, trivyOptions, cloud.deps),
    ).rejects.toThrow("does not match the selected Cloud repository");
    await expect(
      prepareNormalizedExternalPublication(
        selectedTrivyRows(report),
        trivyOptions,
        cloud.deps,
      ),
    ).rejects.toThrow("does not match the selected Cloud repository");
    expect(cloud.posts).toHaveLength(0);
  },
);

// A selected row can be imported without the original batch header.
function selectedTrivyRows(report: unknown) {
  const { findings, read, excluded } = normalizeTrivyFindings(
    report,
    "cloud",
    ".",
  );
  return { findings, read, excluded };
}

test.each([
  [false, false],
  [true, false],
  [false, true],
  [true, true],
])(
  "retained Trivy rows require their provider after renaming the ID (%j) or projecting the artifact type (%j)",
  async (renamed, projected) => {
    const rows = selectedTrivyRows(trivyReport());
    const row = rows.findings[0]!;
    if (renamed) row.source_finding_id = "selected-occurrence";
    if (projected)
      delete (row.evidence.source_data!["report"] as Record<string, unknown>)[
        "ArtifactType"
      ];
    const input = renamed && projected ? { ...rows, report: {} } : rows;
    await expectTrivyOwnership(input);
  },
);

const foreignTrivyTarget = {
  remote: foreignArtifactUrl,
  cloudRepository: foreignArtifactUrl,
};

async function expectTrivyOwnership(
  input: ReturnType<typeof normalizeTrivyFindings>,
) {
  await expectTrivyReplay(
    input,
    "Retained Trivy evidence requires the trivy provider.",
    { ...foreignTrivyTarget, provider: "wiz" },
  );
  await expectTrivyReplay(input);
  await expectTrivyReplay(input, /does not match/u, foreignTrivyTarget);
}

test.each(["native header", "repository URL"] as const)(
  "selected Trivy rows bind their retained %s after projecting other scanner fields",
  async (retained) => {
    const rows = selectedTrivyRows(trivyReport());
    const row = rows.findings[0]!;
    if (retained === "native header") {
      row.source_finding_id = "selected-occurrence";
      row.evidence.source_data = {
        report: row.evidence.source_data!["report"],
      };
    } else {
      row.evidence.source_data = {
        report: { Metadata: { RepoURL: gitHubProject } },
      };
    }
    await expectTrivyOwnership(rows);
  },
);

test("a native Trivy batch header retains its provider when rows have no source data", async () => {
  const rows = selectedTrivyRows(trivyReport());
  const row = rows.findings[0]!;
  const report = row.evidence.source_data!["report"] as Record<string, unknown>;
  row.source_finding_id = "selected-occurrence";
  delete row.evidence.source_data;
  await expectTrivyReplay(
    { ...rows, report },
    "Retained Trivy evidence requires the trivy provider.",
    { ...foreignTrivyTarget, provider: "wiz" },
  );
});

test.each(["sast", "package"] as const)(
  "adding Wiz %s fields to a native Trivy row cannot rebind its repository",
  async (kind) => {
    const rows = selectedTrivyRows(trivyReport());
    const row = rows.findings[0]!;
    const id = "selected-occurrence";
    row.source_finding_id = kind === "sast" ? `sast:${id}` : id;
    Object.assign(row.evidence.source_data!, { id });
    if (kind === "sast") {
      row.evidence.details = {
        kind: "sast",
        repository: { id: "wiz-repository", url: foreignArtifactUrl },
      };
    } else {
      Object.assign(row.evidence.source_data!, {
        name: "CVE-2099-0001",
        detailedName: "example-package",
        vendorSeverity: "HIGH",
        vulnerableAsset: { id: "example-asset" },
      });
    }
    await expectTrivyReplay(
      rows,
      "Retained Trivy evidence requires the trivy provider.",
      {
        provider: "wiz",
        remote: foreignArtifactUrl,
        cloudRepository: foreignArtifactUrl,
      },
    );
  },
);

test("Wiz SAST can carry upstream Trivy evidence while binding its own repository through inventory", async () => {
  const record = {
    ...selectedTrivyRows(trivyReport()).findings[0]!.evidence.source_data,
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
  input: ReturnType<typeof normalizeTrivyFindings>,
  error?: string | RegExp,
  {
    remote = gitHubProject,
    cloudRepository = gitHubProject,
    cloudError = error,
    provider = "trivy",
  }: {
    remote?: string;
    cloudRepository?: string;
    cloudError?: string | RegExp;
    provider?: "trivy" | "wiz";
  } = {},
) {
  const selected = { ...options, provider };
  const local = await localFindingsFixture({ remote });
  cleanups.push(local.dispose);
  const cloud = await fixture(undefined, cloudRepository);
  for (const [prepare, expected] of [
    [
      () =>
        prepareNormalizedLocalImport(
          input,
          { ...selected, repository: local.repository },
          { environment: local.environment },
        ),
      error,
    ],
    [
      () => prepareNormalizedExternalPublication(input, selected, cloud.deps),
      cloudError,
    ],
  ] as const) {
    if (expected === undefined)
      expect((await prepare()).preview.findings).toHaveLength(1);
    else await expect(prepare()).rejects.toThrow(expected);
  }
}

test.each([{}, { RepoURL: gitHubProject }])(
  "a mixed-case HTTP transport in a selected Trivy finding with metadata %j cannot bind to HTTPS",
  async (Metadata) => {
    const report = {
      ...trivyReport(),
      Metadata,
      ArtifactName: "HTTPS://github.com/example/project",
    };
    for (const remote of [gitHubProject, report.ArtifactName])
      await expectTrivyReplay(
        selectedTrivyRows(report),
        /mixed-case HTTP target|different repositories|does not match/,
        { remote },
      );
    if (!Metadata.RepoURL)
      await expectTrivyReplay(
        normalizeTrivyFindings({ ...report, Results: [] }, "local", "."),
        "mixed-case HTTP target",
        {
          remote: report.ArtifactName,
          cloudError: "No supported findings are ready to publish",
        },
      );
  },
);

const userlessSsh = "ssh://github.com/example/project";
const explicitSsh = "ssh://git@github.com/example/project";

test.each([
  [userlessSsh, undefined, userlessSsh, false],
  [userlessSsh, undefined, gitHubProject, false],
  [userlessSsh, undefined, explicitSsh, false],
  [explicitSsh, undefined, gitHubProject, true],
  ["git@github.com:example/project", undefined, gitHubProject, true],
  [userlessSsh, gitHubProject, gitHubProject, false],
  [userlessSsh, explicitSsh, gitHubProject, false],
] as const)(
  "selected Trivy SSH finding with origin %s and artifact %s on checkout %s",
  async (RepoURL, ArtifactName, remote, accepts) => {
    const input = selectedTrivyRows({ ...trivyReport(), Metadata: {} });
    const evidence = input.findings[0]!.evidence;
    evidence.source_data!["report"] = {
      SchemaVersion: 2,
      ArtifactType: "repository",
      Metadata: { RepoURL },
      ...(ArtifactName && { ArtifactName }),
    };
    evidence.details = { kind: "sast", repository: { url: gitHubProject } };
    await expectTrivyReplay(
      {
        ...input,
        report: trivyRepositoryHeader(gitHubProject),
      },
      accepts ? undefined : /Trivy omitted the SSH user/u,
      { remote },
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
  ["Kit", "Kit", false],
  ["Kit", "%E2%84%AAit", true],
] as const)(
  "matches Trivy repository paths %s and %s by HTTP path",
  async (source, target, matches) => {
    const remote = `https://github.com/example/${target}`;
    const sourceUrl = `https://github.com/example/${source}`;
    const error = matches
      ? undefined
      : /does not match|different repositories/u;
    for (const kind of ["native", "typed"] as const) {
      const report = trivyReport();
      report.Metadata.RepoURL = kind === "native" ? sourceUrl : remote;
      const rows = selectedTrivyRows(report);
      if (kind === "typed")
        rows.findings[0]!.evidence.details = {
          kind: "sast",
          repository: { url: sourceUrl },
        };
      await expectTrivyReplay(rows, error, { remote, cloudRepository: remote });
    }

    // Selecting by URL independently checks the operator's destination against the catalog.
    const cloud = await fixture([], remote);
    const rows = selectedTrivyRows({ ...trivyReport(), Metadata: {} });
    const prepare = prepareNormalizedExternalPublication(
      rows,
      { ...trivyOptions, repository: sourceUrl },
      cloud.deps,
    );
    if (matches) expect((await prepare).preview.destination.url).toBe(remote);
    else
      await expect(prepare).rejects.toThrow(
        "destination repository is not available",
      );
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

  const rows = selectedTrivyRows(trivyReport());
  const cloud = await fixture();
  await expect(
    prepareNormalizedExternalPublication(
      rows,
      { ...trivyOptions, repository: ambiguous },
      cloud.deps,
    ),
  ).rejects.toThrow(error);
  cloud.state.repositoryUrl = ambiguous;
  await expect(
    prepareNormalizedExternalPublication(rows, trivyOptions, cloud.deps),
  ).rejects.toThrow(error);
});

const uppercaseWebUrl = "HTTPS://github.com/Example/Project";
test.each([
  [uppercaseWebUrl, gitHubProject, true],
  [foreignArtifactUrl, gitHubProject, false],
  [gitHubProject, uppercaseWebUrl, false],
  [uppercaseWebUrl, uppercaseWebUrl, false],
] as const)(
  "compares a typed repository URL %s and a raw Trivy remote %s independently",
  async (typed, raw, matches) => {
    const report = trivyReport();
    report.Metadata.RepoURL = raw;
    const input = selectedTrivyRows(report);
    input.findings[0]!.evidence.details = {
      kind: "sast",
      repository: { url: typed },
    };
    await expectTrivyReplay(
      input,
      matches ? undefined : /does not match|different repositories/,
    );
  },
);

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
    const f = await fixture(report, gitHubProject);
    const normalized = normalizeTrivyFindings(report, "cloud", ".");
    const selectedRow = {
      read: 1,
      findings: [normalized.findings[0]!],
      excluded: [],
    };
    for (const prepare of [
      () => prepareExternalPublication(f.file, trivyOptions, f.deps),
      () =>
        prepareNormalizedExternalPublication(selectedRow, trivyOptions, f.deps),
    ]) {
      if (!accepts) {
        await expect(prepare()).rejects.toThrow(
          "does not match the selected Cloud repository",
        );
        continue;
      }
      const prepared = await prepare();
      const reloaded = JSON.parse(JSON.stringify(prepared.preview));
      if (ArtifactType === "repository") {
        const other = await fixture(report, foreignArtifactUrl);
        await expect(
          prepareNormalizedExternalPublication(
            reloaded,
            trivyOptions,
            other.deps,
          ),
        ).rejects.toThrow("does not match the selected Cloud repository");
      } else {
        expect(
          reloaded.findings[0].evidence.source_data.report.ArtifactName,
        ).toBe(ArtifactName);
      }
      await prepared.publish();
    }
    expect(f.posts.length > 0).toBe(accepts);
    for (const body of f.posts) {
      const report = JSON.parse(body).items[0].evidence.source_data.report;
      expect(report.ArtifactName).toBe(ArtifactName);
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
        const claims = snykRepositoryClaims(source);
        expect(claims, format).toEqual([{ url: repository }]);
        expect(
          cloudRepositoryUrlKey(
            normalizeGitRepositoryUrl(claims[0]!.url, destination),
          ) === cloudRepositoryUrlKey(destination),
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
  const paths = [
    "src/my file.ts",
    "src/my%20file.ts",
    "src/100%.ts",
    "src/100%25.ts",
  ];
  const json: any = semgrepJson();
  const sarif: any = semgrepSarif();
  delete json.results[0].extra.fingerprint;
  delete sarif.runs[0].results[0].fingerprints;
  json.results = paths.map((path) => ({ ...json.results[0], path }));
  const run = sarif.runs[0];
  run.results = paths.map((path) => {
    const result = structuredClone(run.results[0]);
    result.locations[0].physicalLocation.artifactLocation.uri = path;
    return result;
  });
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
    const cloud = await fixture(report);
    const rows = selectedTrivyRows(report);
    const file = () =>
      prepareExternalPublication(cloud.file, trivyOptions, cloud.deps);
    const selected = (header?: Record<string, unknown>) =>
      prepareNormalizedExternalPublication(
        { ...rows, report: header },
        trivyOptions,
        cloud.deps,
      );
    const first = initialKind === "file" ? await file() : await selected();
    cloud.state.loseResponse = true;
    await expect(first.publish()).rejects.toThrow("resume the saved request");
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
  },
);

test("unverified Trivy checkpoints retain their requests and receipts for the original importer", async () => {
  const cloud = await fixture(trivyReport());
  const prepare = () =>
    prepareExternalPublication(cloud.file, trivyOptions, cloud.deps);
  cloud.state.brokenReadback = true;
  await expect((await prepare()).publish()).rejects.toThrow();
  cloud.state.brokenReadback = false;
  const retry = await prepare();
  const directory = join(cloud.root, "state", "external-finding-publications");
  const filename = join(
    directory,
    (await readdir(directory)).find((name) => name.endsWith(".pending.json"))!,
  );
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

test.each([
  [
    "native Semgrep",
    semgrepJson(),
    { provider: "semgrep", sourceRepositoryUrl: gitHubProject },
  ],
  ["Trivy", trivyReport(), { provider: "trivy", trivyScanRoot: "." }],
  [
    "hosted Snyk REST",
    snykRestFixture("open-source", {
      sourceRepositoryUrl: gitHubProject,
    }),
    { provider: "snyk" },
  ],
  ["hosted Semgrep Platform", platformReport(), { provider: "semgrep" }],
] as const)(
  "a %s file checkpoint resumes after the same destination is renamed, but a fresh submission cannot",
  async (_name, report, readerOptions) => {
    const cloud = await fixture(report, gitHubProject);
    const selected = { ...options, ...readerOptions };
    const first = await prepareExternalPublication(
      cloud.file,
      selected,
      cloud.deps,
    );
    cloud.state.loseResponse = true;
    await expect(first.publish()).rejects.toThrow("resume the saved request");
    cloud.state.repositoryUrl = "https://github.com/example/renamed";
    const retry = await prepareExternalPublication(
      cloud.file,
      selected,
      cloud.deps,
    );
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).status).toBe("complete");
    expect(cloud.posts[1]).toBe(cloud.posts[0]);
    await expect(
      prepareExternalPublication(cloud.file, selected, cloud.deps),
    ).rejects.toThrow("does not match");
    expect(cloud.posts).toHaveLength(2);
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
  f.state.repositoryUrl = "https://github.com/other/project";
  const retry = await prepareExternalPublication(f.file, selected, f.deps);
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
    prepareExternalPublication(f.file, selected, f.deps),
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
