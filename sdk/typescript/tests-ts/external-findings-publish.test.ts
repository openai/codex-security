import { createServer, type ServerResponse } from "node:http";
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
import { gzipSync } from "node:zlib";
import { Database } from "bun:sqlite";
import { afterEach, expect, spyOn, test } from "bun:test";
import {
  ExternalPublicationError,
  prepareExternalPublication,
  type ExternalPublicationProgress,
} from "../src/external-findings-publish.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import {
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
import { createCliTest } from "./support/cli-run.js";

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

async function fixture(records: unknown = [normalized()]) {
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
    repo_connector_id: "github",
    url: "https://github.com/example/project",
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
  const f = await fixture([normalized(), normalized("unknown", "unknown")]);
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
    const f = await fixture([selected, normalized("unsupported", "unknown")]);
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
      expect(result).not.toHaveProperty("cloudUrl");
    } else {
      expect(cli.stdout.text()).toContain("Findings");
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

test("canceling a waiting publisher preserves the active request", async () => {
  const f = await fixture();
  const { completion: active, release } = await pauseAtPublication(f);
  const controller = new AbortController();
  const observer = observeLockContention();
  const waiting = (
    await prepareExternalPublication(f.file, options, {
      ...f.deps,
      signal: controller.signal,
    })
  ).publish();
  try {
    await Promise.race([
      observer.contended,
      waiting.then(() => {
        throw new Error("Concurrent publication skipped the active lock.");
      }),
    ]);
    controller.abort();
    await expect(waiting).rejects.toMatchObject({ name: "AbortError" });
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
});

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

test("batching preserves item order and keeps final item errors visible", async () => {
  const f = await fixture(
    Array.from({ length: 101 }, (_, index) => normalized(`vendor-${index}`)),
  );
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  expect(
    prepared.preview.requests.map((request) => request.items.length),
  ).toEqual([100, 1]);
  expect((await prepared.publish()).counts.created).toBe(101);
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
      "Could not read vendor findings as UTF-8 JSON or JSONL:",
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

test("source readback must preserve the acknowledged batch environment", async () => {
  const f = await fixture();
  const prepared = await prepareExternalPublication(f.file, options, {
    ...f.deps,
    fetch: async (url, init) => {
      const response = await f.deps.fetch(url, init);
      if (new URL(url).pathname.includes("/source_reports/")) {
        return Response.json({
          ...(await response.json()),
          environment_id: "unexpected-environment",
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
    normalized("invalid", "unknown"),
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
    normalized("invalid", "unknown"),
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

test("readback interruption distinguishes acknowledged findings from verified findings", async () => {
  const f = await fixture();
  f.state.brokenReadback = true;
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  try {
    await prepared.publish();
    throw new Error("Expected readback interruption");
  } catch (error) {
    expect(error).toBeInstanceOf(ExternalPublicationError);
    expect((error as ExternalPublicationError).result).toMatchObject({
      status: "interrupted",
      counts: { created: 1 },
      unacknowledged: 0,
      verified: 0,
    });
  }
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
  expect(result.verified).toBe(1);
  expect(f.posts).toHaveLength(1);
  expect(requested.some((url) => url.includes("/repositories?"))).toBe(true);
  expect(requested.some((url) => url.includes("/source_reports?"))).toBe(true);
  expect(requested.some((url) => url.endsWith("/finding_imports"))).toBe(true);
  expect(requested.some((url) => url.includes("/source_reports/"))).toBe(true);
});

test.each([
  "",
  "  ",
  "/relative",
  "file:///tmp/cloud",
  "https://user:password@cloud.example.test",
  "https://cloud.example.test?deployment=pilot",
  "https://cloud.example.test#pilot",
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
  expect(cli.stderr.text()).toContain("Verifying imported findings: 1/1");
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
