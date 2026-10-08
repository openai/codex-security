import { createServer, type ServerResponse } from "node:http";
import { hash } from "node:crypto";
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
import { afterEach, expect, test } from "bun:test";
import { prepareExternalPublication } from "../src/external-findings-publish.js";
import { readVendorFindings } from "../src/wiz-findings.js";
import { validateImportRequest } from "../src/external-import-contract.js";
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
    loseResponse: false,
    brokenReadback: false,
    throttle: false,
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
        if (state.throttle) {
          response.setHeader("Retry-After", "1");
          return json(response, { error: { message: "Slow down" } }, 429);
        }
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
            if (state.finalError) {
              receipt.counts.error = (receipt.counts.error ?? 0) + 1;
              receipt.results.push({
                client_id: item.client_id,
                outcome: "error",
                source_report_id: null,
                observation_id: null,
                canonical_finding_id: null,
                version: null,
                error: {
                  code: "version_conflict",
                  message: "Reload current evidence",
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
    },
  });
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

test("interactive JSON publication shows the destination and exclusions before confirmation", async () => {
  const f = await fixture([normalized(), normalized("unsupported", "unknown")]);
  const cli = createCliTest(main);
  let prompted = false;
  expect(
    await cli.runCli(f.command, {
      ...f.cliDeps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async (_question, defaultValue) => {
          prompted = true;
          expect(defaultValue).toBe(false);
          expect(cli.stderr.text()).toContain(
            "https://github.com/example/project",
          );
          expect(cli.stderr.text()).toContain(options.sourceKey);
          expect(cli.stderr.text()).toContain("synthetic-account");
          expect(cli.stderr.text()).toContain("environment-example");
          expect(cli.stderr.text()).toContain("Excluded: 1");
          expect(cli.stderr.text()).not.toContain("synthetic-token");
          expect(f.posts).toHaveLength(0);
          return true;
        },
      },
    }),
  ).toBe(0);
  expect(prompted).toBe(true);
  expect(JSON.parse(cli.stdout.text()).counts.created).toBe(1);
});

test("saved request survives an actual publisher process restart after a committed response is lost", async () => {
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
  async function run() {
    const process = Bun.spawn(
      [Bun.which("bun")!, runner, ...f.command, "--yes"],
      { env: f.environment, stdout: "pipe", stderr: "pipe" },
    );
    const [code, stdout, stderr] = await Promise.all([
      process.exited,
      new Response(process.stdout).text(),
      new Response(process.stderr).text(),
    ]);
    return { code, stdout, stderr };
  }
  f.state.loseResponse = true;
  const lost = await run();
  expect(lost.code).toBe(2);
  expect({
    size: f.reports.size,
    error: lost.stderr.includes("resume the saved request")
      ? "resumable"
      : lost.stderr,
  }).toEqual({ size: 1, error: "resumable" });
  const firstBody = f.posts[0];
  const second = await run();
  expect(second.code).toBe(0);
  expect(f.posts[1]).toBe(firstBody);
  expect(f.receipts.size).toBe(1);
  expect(JSON.parse(second.stdout).counts.created).toBe(1);
});

test("readback failure retains the accepted request; a retry replays its outcome", async () => {
  const f = await fixture();
  f.state.brokenReadback = true;
  const prepared = await prepareExternalPublication(f.file, options, f.deps);
  await expect(prepared.publish()).rejects.toThrow("resume the saved request");
  f.state.brokenReadback = false;
  const retry = await prepareExternalPublication(f.file, options, f.deps);
  expect(retry.preview.resumed).toBe(true);
  expect((await retry.publish()).counts.created).toBe(1);
  expect(f.posts[0]).toBe(f.posts[1]);
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
