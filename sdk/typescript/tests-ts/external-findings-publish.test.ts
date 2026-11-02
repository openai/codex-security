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
  normalizeSnykSarif,
  snykRepositoryUrls,
} from "../src/snyk-findings.js";
import {
  semgrepJson,
  semgrepSarif,
} from "./support/semgrep-import-fixtures.js";
import { endorFinding, endorSarif } from "./support/endor-import-fixtures.js";
import { sonarGitTestEnvironment } from "./support/sonar-import-fixtures.js";
import { normalizeEndorFindings } from "../src/endor-findings.js";
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
import {
  snapshotNormalizedFindings,
  type ExternalFindings,
} from "../src/external-findings.js";
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
  inspectorPackageFinding,
  inspectorRepositoryUrl,
} from "./support/inspector-import-fixtures.js";
import { normalizeBlackDuckFindings } from "../src/blackduck-findings.js";
import { normalizeVeracodeFindings } from "../src/veracode-findings.js";
import {
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

test("Sonar replays the selected evidence locally and to Cloud without signing in to Sonar again", async () => {
  const repo = "https://github.com/example/project";
  const source = {
    format: "sonar-issues/v1" as const,
    server: "https://sonarcloud.io",
    organization: "example",
    project: "example_project",
    branch: "main",
    projectBase: "",
    repositoryUrl: repo,
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
  const deps = {
    ...f.deps,
    environment: {
      ...f.environment,
      CODEX_SECURITY_CLOUD_BASE_URL: undefined,
      CODEX_SECURITY_CLOUD_WEB_URL: undefined,
    },
  };
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
    prepareNormalizedExternalPublication(
      { ...selection, findings, report: { ...context, branch: "main" } },
      selected,
      deps,
    );
  await expect(
    prepareNormalizedExternalPublication(selection, selected, deps),
  ).rejects.toThrow("without a ref");
  await expect(
    prepareNormalizedExternalPublication(
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
      deps,
    ),
  ).rejects.toThrow("retained Sonar branch");
  await expect(
    prepareNormalizedExternalPublication(
      { ...rows, report: { ...context, repositoryUrl: foreign } },
      selected,
      deps,
    ),
  ).rejects.toThrow("does not match the selected Cloud repository");
  f.state.loseResponse = true;
  await expect((await prepare()).publish()).rejects.toThrow(
    "resume the saved request",
  );
  await expect(
    prepareNormalizedExternalPublication(
      { ...selection, report: { ...context, branch: "other" } },
      selected,
      deps,
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

test("Wiz can import, resume and update its own occurrence with upstream Inspector evidence", async () => {
  const record = {
    id: "wiz-vulnerability-1",
    name: "CVE-2099-1234",
    detailedName: "example-package",
    vendorSeverity: "HIGH",
    vulnerableAsset: { id: "example-asset" },
    finding: inspectorPackageFinding(),
  };
  const f = await fixture([record]);
  const prepare = () => prepareExternalPublication(f.file, options, f.deps);
  const first = await prepare();
  f.state.loseResponse = true;
  const error = await first.publish().catch((error: unknown) => error);
  if (!(error instanceof ExternalPublicationError)) throw error;
  expect(f.reports.get(record.id)?.evidence.source_data).toEqual(record);

  // A pre-Inspector checkpoint can contain the original requests without their input projection.
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
});

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

const savedBlackDuckEvidence = {
  data: { format: "blackduck-bom-6" },
  requiredProvider: "blackduck",
  digest: "d3001de83673b0f42b1d1d42cb19ea546869d41ed99504ca213b303267bb1346",
};

const savedDependabotData = {
  ...githubDependabotAlert(),
  sourceRepositoryUrl: "https://github.com/example/different",
};

test.each([
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
  async ({ selected, data, requiredProvider, filename, digest }) => {
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
    const prepare = () =>
      prepareNormalizedExternalPublication(input, selected, {
        ...f.deps,
        environment,
      });

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
    const retry = await prepare();
    expect(retry.preview.resumed).toBe(true);
    expect((await retry.publish()).counts.created).toBe(1);
    expect(f.posts.map((body) => JSON.parse(body))).toEqual([request]);
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

function releasedDependencies(f: Awaited<ReturnType<typeof fixture>>) {
  return {
    ...f.deps,
    environment: {
      ...f.environment,
      CODEX_SECURITY_CLOUD_BASE_URL: undefined,
      CODEX_SECURITY_CLOUD_WEB_URL: undefined,
    },
  };
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
    return prepareNormalizedExternalPublication(
      input,
      options,
      releasedDependencies(f),
    );
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

    await expect(
      prepareNormalizedExternalPublication(
        input,
        options,
        releasedDependencies(f),
      ),
    ).rejects.toThrow();
    expect(await readFile(path, "utf8")).toBe(saved);
    expect(f.posts).toHaveLength(0);
  },
);

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
  const publish = async () =>
    (
      await prepareNormalizedExternalPublication(
        input,
        options,
        releasedDependencies(f),
      )
    ).publish();
  await expect(publish()).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(pending);
  expect(f.posts).toEqual([JSON.stringify(request)]);

  const retry = await prepare(score);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request), JSON.stringify(request)]);
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
  const { f, request } = await oldScoreApproval("unreported");
  const input = scoredFindings(2.5);
  input.findings[0]!.evidence = new ScannerEvidence();
  const prepare = () =>
    prepareNormalizedExternalPublication(
      input,
      options,
      releasedDependencies(f),
    );
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
  const prepare = () =>
    prepareNormalizedExternalPublication(
      input,
      options,
      releasedDependencies(f),
    );
  const request = {
    ...(await prepare()).preview.requests[0]!,
    request_id: "0697e266-e0a5-4aa5-b30b-3b89cbd48ac1",
  };
  expect(hash("sha256", JSON.stringify(request))).toBe(
    "8c76780e8aca7582a293dee9483002401d6907e51833fc806cd1a058fe54b855",
  );
  const directory = join(f.root, "state", "external-finding-publications");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(
    join(
      directory,
      "749e46bc07036abe74f047011264147993bd96f384099bcf1b729c8c2634a1b0.pending.json",
    ),
    JSON.stringify({
      accountId: boxedNumberCheckpoints.accountId,
      requests: [request],
      inputProjection: {
        inputDigest:
          "49cf7aa8362d8967c5638238b719d925e7e1814d48a4a7a0844e69ef9260b869",
        savedEvidenceDigest:
          "a2d3adb20cf97c597828fd54ec361490a8a34e479a42d01d3b85ff245b0b384b",
      },
    }),
    { mode: 0o600 },
  );

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

test("a getter-backed finding keeps released approvals scoped to their deployment", async () => {
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
      { read: 1, excluded: [], findings: [finding] },
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
  const directory = join(f.root, "state", "external-finding-publications");
  const path = join(
    directory,
    "b4eed57e616f2289bf467f18fba85e2e9ba305a360a798d9e9d8125b06e148fe.pending.json",
  );
  const request = {
    ...(await prepare("one")).preview.requests[0]!,
    request_id: "bf6f1063-9647-43d8-82b9-982961522482",
  };
  const digest =
    "01ad76cac2893a22136a81e7e61aeef35edb7a51e97f2944713e744756362721";
  const saved = JSON.stringify({
    accountId: boxedNumberCheckpoints.accountId,
    requests: [request],
    inputProjection: { inputDigest: digest, savedEvidenceDigest: digest },
  });
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(path, saved, { mode: 0o600 });
  expect((await prepare("one")).preview.requests).toEqual([request]);
  const independent = await prepare("two");
  expect(independent.preview.resumed).toBe(false);
  expect(independent.preview.requests[0]!.request_id).not.toBe(
    request.request_id,
  );
  expect((await independent.publish()).verified).toBe(1);
  expect(f.posts).toEqual([JSON.stringify(independent.preview.requests[0])]);
  expect(await readFile(path, "utf8")).toBe(saved);
});

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
    const read = fs.readFile;
    const reads = spyOn(fs, "readFile").mockImplementation((async (
      ...args: Parameters<typeof read>
    ) => {
      if (String(args[0]) === unrelated)
        throw Object.assign(new Error("Unreadable unrelated approval"), {
          code: "EACCES",
        });
      return read(...args);
    }) as typeof read);
    try {
      f.state.brokenReadback = false;
      const retry = await prepare(2.5);
      expect(retry.preview.resumed).toBe(true);
      expect(JSON.stringify(retry.preview.requests)).toBe(
        JSON.stringify(boxed.preview.requests),
      );
      expect((await retry.publish()).receipts[0]!.id).toBe(approved.request_id);
      expect(f.posts).toEqual([JSON.stringify(approved)]);
      expect(files).toContain(`${checkpoint.wireKey}.lookup.json`);
      expect(
        reads.mock.calls.some(([file]) => String(file) === unrelated),
      ).toBe(false);
    } finally {
      reads.mockRestore();
    }
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
  const reads = spyOn(fs, "readFile");
  try {
    expect(await sibling.publish()).toEqual(result);
    expect(reads.mock.calls.map(([path]) => String(path))).not.toContain(
      unknown,
    );
  } finally {
    reads.mockRestore();
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
    const listings = spyOn(fs, "readdir");
    const read = fs.readFile;
    const reads = spyOn(fs, "readFile").mockImplementation((async (
      ...args: Parameters<typeof read>
    ) => {
      if (unreadable && unrelated.has(String(args[0])))
        throw Object.assign(new Error("Unreadable unrelated approval"), {
          code: "EACCES",
        });
      return read(...args);
    }) as typeof read);
    const operations = () => ({
      listed: listings.mock.calls.some(([path]) =>
        statePaths.has(String(path)),
      ),
      readUnrelated: reads.mock.calls.some(([path]) =>
        unrelated.has(String(path)),
      ),
    });
    try {
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
      await expect(prepare(4)).rejects.toThrow("Unreadable unrelated approval");
      expect(operations()).toEqual({ listed: true, readUnrelated: true });
    } finally {
      listings.mockRestore();
      reads.mockRestore();
    }
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
  const writes = spyOn(fs, "rename").mockImplementation(async (from, to) => {
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
  try {
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
  } finally {
    writes.mockRestore();
  }
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
  const read = fs.readFile;
  const unreadable = spyOn(fs, "readFile").mockImplementation((async (
    ...args: Parameters<typeof read>
  ) => {
    if (String(args[0]) === boxedPath)
      throw Object.assign(new Error("Unreadable approval"), { code: "EACCES" });
    return read(...args);
  }) as typeof read);
  try {
    primitive.f.state.throttle = true;
    await expect(held.publish()).rejects.toThrow("Slow down");
  } finally {
    unreadable.mockRestore();
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

test("a native scanner error resumes its released message-only approval", async () => {
  const { f, directory, prepare, request } = await oldScoreApproval(
    "evidence",
    false,
  );
  request.request_id = "15ab6427-635d-4537-9975-f7f536155b49";
  const path = join(
    directory,
    "19d4eb5e5738ac54ae3d847f50534f09ac60882b0145fa5abc4260299e7f02b6.pending.json",
  );
  const saved = JSON.stringify({
    accountId: boxedNumberCheckpoints.accountId,
    requests: [request],
    inputProjection: {
      inputDigest:
        "603ea14278affa7a9a27fc2a624f5a2ce8fd85460f99175bef69a0572430b59b",
      savedEvidenceDigest:
        "875a8aec2f1b7c573a6d05d983f6afa0f964a6e1c96d22c8c8691cc2de824ccc",
    },
  });
  await writeFile(path, saved, { mode: 0o600 });
  const diagnostic = () =>
    Object.assign(new Error("scanner message"), { code: "E_TEST" });
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

  const report = { errors: [diagnostic()] };
  const retry = await prepare(2.5, report);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([JSON.stringify(request)]);
  const fresh = await prepare(2.5, report);
  expect(fresh.preview.resumed).toBe(false);
  expect(fresh.preview.report?.["errors"]).toEqual([
    expect.objectContaining({ message: "scanner message", code: "E_TEST" }),
  ]);
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
  const oldPath = join(
    directory,
    "ad0ce218fdfcfa75455f2fbda30dc6e248a79419190e5fa77a7c12005ead7926.pending.json",
  );
  request.request_id = "dd905f37-1437-44a3-b559-8c88fe873e52";
  Object.assign(request.items[0]!.evidence.source_data, {
    score: { a: 7, b: 99 },
  });
  const saved = JSON.stringify({
    accountId: boxedNumberCheckpoints.accountId,
    requests: [request],
    inputProjection: {
      inputDigest:
        "232fbafeda24e0939a033a0d59479908389a8e167612feabc174e36f716303a5",
      savedEvidenceDigest:
        "3a5021a32dc41a1fe4b2d8e2f74abfd1238ef63cf5bfb4cf44cb28bb09e5bfad",
    },
  });
  await writeFile(oldPath, saved, { mode: 0o600 });
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
  const { normalizeGitHubCodeScanningAlerts } =
    await import("../src/github-findings.js");
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
  const digest =
    "af139e1baa9e9e70a47d4ef0f811cb3960e9c280252affab51c250e7e6f9aa88";
  const saved = JSON.stringify({
    accountId: preview.accountId,
    requests: [
      {
        ...preview.requests[0]!,
        request_id: "f49f8193-10b0-4c6c-a20d-390304a5f8d0",
      },
    ],
    inputProjection: { inputDigest: digest, savedEvidenceDigest: digest },
  });
  expect(hash("sha256", saved)).toBe(
    "5f17c21d058c685c128d488b5a2a1e466fa5d18e37cc5284268b95ef25307293",
  );
  const directory = join(f.root, "state", "external-finding-publications");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const path = join(
    directory,
    "0b43d13c77ddf5fa43ce0bb536402595aea270191adde5974f2206753fa607b1.pending.json",
  );
  await writeFile(path, saved, { mode: 0o600 });

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
    return prepareNormalizedExternalPublication(
      selected,
      options,
      releasedDependencies(f),
    );
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
  const directory = join(f.root, "state", "external-finding-publications");
  const path = join(
    directory,
    "8376bdd00875ba8349ea341fab1c1d7c91eface0f2346d5eacf28e5c534a6d6a.pending.json",
  );
  const saved = JSON.stringify({
    accountId: boxedNumberCheckpoints.accountId,
    requests: [request],
    inputProjection: {
      inputDigest:
        "4eace8a1f10136be4258341e48f747f3609919238018ad5f8d84ceebfe469bb2",
      savedEvidenceDigest:
        "68702d81bc70bb23815207a069b0780b2b5b1f304250ca4696ecfe129c48e497",
    },
  });
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(path, saved, { mode: 0o600 });
  await expect(prepare(Buffer.from([2]))).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(saved);
  expect(f.posts).toHaveLength(0);

  const recovered = await prepare(Buffer.from([1]));
  expect(recovered.preview.resumed).toBe(true);
  expect((await recovered.publish()).receipts[0]!.id).toBe(request.request_id);
  expect(f.posts).toEqual([serialized]);
});

test("the GitHub reader resumes a released boxed score whose Buffer fit the Cloud request", async () => {
  const { normalizeGitHubCodeScanningAlerts } =
    await import("../src/github-findings.js");
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

  const directory = join(f.root, "state", "external-finding-publications");
  const digest =
    "6d0cd82bed91273c26d2d9cd6eea9814f7ce3ac33af58a266f6554617d560362";
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(
    join(
      directory,
      "c03e748fff72692564d445fc232317c164f16cf16fc5b1969bbee80d98bdb97e.pending.json",
    ),
    JSON.stringify({
      accountId: "synthetic-account",
      requests: [request],
      inputProjection: { inputDigest: digest, savedEvidenceDigest: digest },
    }),
    { mode: 0o600 },
  );

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
