import { hash } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { gzipSync } from "node:zlib";
import { isDeepStrictEqual } from "node:util";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  ExternalPublicationError,
  prepareExternalPublication,
} from "../src/external-findings-publish.js";
import { DEFAULT_CLOUD_BASE_URL } from "../src/cloud-endpoint.js";
import { validateExternalEvidence } from "../src/external-import-contract.js";
import type {
  ExternalFindingEvidence,
  FindingImportRequest,
  SourceReport,
} from "../src/external-import-models.js";
import {
  readVendorFindings,
  readVendorFindingsForPublication,
} from "../src/wiz-findings.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import previewCheckpoint from "./fixtures/wiz-preview-checkpoint.json" with { type: "json" };
import roundtripFixtures from "./fixtures/wiz-details-roundtrip.json" with { type: "json" };

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});
const repository = { id: "wiz-repository", name: "example/project" };
const repositoryUrl = "https://github.com/example/project";
const inventory = {
  nodes: [
    {
      id: "wiz-branch-inventory",
      platform: "GITHUB",
      providerID: "github.com##example/project##feature/parser",
      type: "REPOSITORY_BRANCH",
      repository: { ...repository, url: repositoryUrl },
    },
  ],
  pageInfo: { hasNextPage: false },
};
const sast = {
  id: "occurrence-1",
  name: "Untrusted query construction",
  description: "Synthetic source finding",
  severity: "HIGH",
  status: "OPEN",
  createdAt: "2026-10-01T10:00:00.123Z",
  filePath: "src/query.ts",
  startLine: 10,
  endLine: 12,
  snippet: "query(input)",
  repository,
  repositoryBranch: {
    id: "wiz-branch",
    name: "example/project/feature/parser",
  },
  weaknesses: [{ id: "CWE-89", name: "SQL injection" }],
  origin: "THIRD_PARTY_SCANNER",
  remediationInstructions: "Use a parameterized query.",
  aiAnalysis: { verdict: "FALSE_POSITIVE" },
};
const secret = {
  id: "occurrence-1",
  name: "Example credential metadata",
  severity: "MEDIUM",
  type: "API_KEY",
  confidence: "HIGH",
  validationStatus: "NOT_VALIDATED",
  isEncrypted: false,
  isManaged: true,
  status: "RESOLVED",
  lastUpdatedAt: "2026-10-01T10:00:00.987Z",
  resolvedAt: "2026-10-01T10:00:00.987Z",
  rule: { id: "example-secret-rule", name: "Example API key", type: "API_KEY" },
  resource: {
    id: "wiz-branch",
    type: "REPOSITORY_BRANCH",
    name: "example/project/feature/parser",
    typedProperties: { repository },
  },
  secretDataEntities: [
    { id: "metadata-only", name: "Example detector metadata", type: "API_KEY" },
  ],
};
const iac = {
  id: "occurrence-1",
  name: "Example infrastructure setting",
  severity: "LOW",
  status: "OPEN",
  expectedContent: "",
  foundContent: "  ",
  matchContent: "enabled = true",
  filePath: "infra/main.tf",
  startLine: 20,
  endLine: 22,
  repository,
  branch: { id: "wiz-branch", name: "feature/parser" },
  platform: "TERRAFORM",
  cloudPlatform: "AWS",
  fileURL: "https://github.com/example/project/blob/main/infra/main.tf",
  wizUrl: "https://vendor.example.test/findings/occurrence-1",
  firstSeenAt: "2026-10-01T10:00:00Z",
  lastSeenAt: "2026-10-02T10:00:00Z",
  rule: { id: "example-rule", shortId: "EXAMPLE-1", name: "Example setting" },
  resourceGraphEntity: {
    id: "logical-resource",
    type: "BUCKET",
    properties: { deployed: false },
  },
  fileRemediation: { filePath: "infra/main.tf" },
};

function envelope(root: string, nodes: unknown[], withInventory = true) {
  return {
    data: {
      [root]: { nodes, pageInfo: { hasNextPage: false } },
      ...(withInventory ? { versionControlResources: inventory } : {}),
    },
  };
}

async function fixture(payload: unknown, compressed = false) {
  const root = await mkdtemp(join(tmpdir(), "wiz-repository-findings-"));
  directories.push(root);
  const file = join(root, "selected.json");
  const contents = JSON.stringify(payload);
  await writeFile(file, compressed ? gzipSync(contents) : contents);
  return { root, file };
}

async function parse(payload: unknown) {
  const { file } = await fixture(payload);
  return readVendorFindings(file);
}

test("SAST maps source range, CWE, scanner verdict, and repository inventory without changing raw evidence", async () => {
  const { file } = await fixture(envelope("sastFindings", [sast]), true);
  const parsed = await readVendorFindings(file);
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]).toMatchObject({
    source_finding_id: "sast:occurrence-1",
    evidence: {
      severity: "high",
      locations: [{ path: "src/query.ts", line: 10 }],
      branch: "example/project/feature/parser",
      code_revision: null,
      source_scan_id: null,
      source_updated_at: null,
      advisory_ids: [],
      packages: [],
      source_data: sast,
      details: {
        kind: "sast",
        repository: { ...repository, url: repositoryUrl },
        source_status: "OPEN",
        scanner_origin: "THIRD_PARTY_SCANNER",
        scanner_verdict: "FALSE_POSITIVE",
        weakness_ids: ["CWE-89"],
        remediation_instructions: sast.remediationInstructions,
        code: { end_line: 12, snippet: "query(input)" },
      },
    },
  });
  expect(parsed.findings[0]!.evidence).not.toHaveProperty("assessment");
});

test("repository secrets preserve detector and vendor validation metadata without inventing a source location or scanned revision", async () => {
  const detailed = {
    ...secret,
    id: "detailed",
    path: "config/example.env",
    lineNumber: 3,
    vcsDetails: { initialCommitHash: "a".repeat(40) },
  };
  const parsed = await parse(envelope("secretInstances", [secret, detailed]));
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.evidence).toMatchObject({
    severity: "medium",
    locations: [],
    source_updated_at: 1790848800,
    code_revision: null,
    source_data: secret,
    details: {
      kind: "secret",
      source_status: "RESOLVED",
      rule: { id: "example-secret-rule", name: "Example API key" },
      secret: {
        type: "API_KEY",
        confidence: "HIGH",
        validation_status: "NOT_VALIDATED",
        is_encrypted: false,
        is_managed: true,
        introduced_commit: null,
      },
    },
  });
  expect(parsed.findings[1]!.evidence).toMatchObject({
    locations: [{ path: detailed.path, line: 3 }],
    code_revision: null,
    details: { secret: { introduced_commit: "a".repeat(40) } },
    source_data: detailed,
  });
});

test("IaC keeps exact empty comparison text, the rule, file link, and logical resource separately", async () => {
  const parsed = await parse(envelope("iacFindings", [iac]));
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.evidence).toMatchObject({
    url: iac.wizUrl,
    source_updated_at: null,
    code_revision: null,
    source_data: iac,
    details: {
      kind: "iac",
      rule: {
        id: "example-rule",
        short_id: "EXAMPLE-1",
        name: "Example setting",
      },
      code: { end_line: 22, snippet: "enabled = true" },
      configuration: {
        platform: "TERRAFORM",
        cloud_platform: "AWS",
        expected: "",
        actual: "  ",
      },
      file_url: iac.fileURL,
    },
  });
});

test("explicit finding families namespace reused vendor occurrence IDs", async () => {
  const parsed = await parse({
    data: {
      versionControlResources: inventory,
      sastFindings: { nodes: [sast] },
      secretInstances: { nodes: [secret] },
      iacFindings: { nodes: [iac] },
    },
  });
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings.map((finding) => finding.source_finding_id)).toEqual([
    "sast:occurrence-1",
    "secret:occurrence-1",
    "iac:occurrence-1",
  ]);
});

test("bare arrays cannot guess a new finding family even when package fields also exist", async () => {
  const ambiguous = {
    ...sast,
    detailedName: "example-package",
    vulnerableAsset: { id: "asset" },
  };
  const parsed = await parse([sast, secret, iac, ambiguous]);
  expect(parsed.findings).toEqual([]);
  expect(parsed.excluded).toHaveLength(4);
  expect(parsed.excluded.every((item) => item.reason.includes("named"))).toBe(
    true,
  );
  expect(
    (await parse(envelope("sastFindings", [ambiguous]))).findings[0]!.evidence
      .source_data,
  ).toEqual(ambiguous);
});

test("repository mapping joins only repository.id, accepts supplied URLs, and rejects conflicts", async () => {
  const wrongJoin = {
    ...inventory,
    nodes: [
      {
        ...inventory.nodes[0],
        id: repository.id,
        repository: {
          id: "different-repository",
          name: repository.name,
          url: repositoryUrl,
        },
      },
    ],
  };
  const missing = await parse({
    data: {
      sastFindings: { nodes: [sast] },
      versionControlResources: wrongJoin,
    },
  });
  expect(missing.findings).toEqual([]);
  expect(missing.excluded[0]!.reason).toContain(
    "verified source repository URL",
  );
  const enriched = {
    ...sast,
    repository: { ...repository, url: repositoryUrl },
  };
  expect(
    (await parse(envelope("sastFindings", [enriched], false))).excluded,
  ).toEqual([]);
  const conflict = {
    ...sast,
    repository: { ...repository, url: "https://github.com/example/other" },
  };
  expect(
    (await parse(envelope("sastFindings", [conflict]))).excluded[0]!.reason,
  ).toContain("conflicting");
});

test("workload secrets and cloud configuration remain visible exclusions in a mixed explicit export", async () => {
  const workload = {
    ...secret,
    id: "workload",
    resource: { ...secret.resource, type: "VIRTUAL_MACHINE" },
  };
  const parsed = await parse({
    data: {
      versionControlResources: inventory,
      secretInstances: { nodes: [secret, workload] },
      configurationFindings: {
        nodes: [{ id: "configuration", name: "Example check" }],
      },
    },
  });
  expect(parsed.findings).toHaveLength(1);
  expect(parsed.excluded).toEqual([
    expect.objectContaining({
      source_finding_id: "workload",
      reason: expect.stringContaining("Workload secrets"),
    }),
    expect.objectContaining({
      source_finding_id: "configuration",
      reason: expect.stringContaining("Cloud configuration"),
    }),
  ]);
});

test("GraphQL errors, unfinished finding pages, and unfinished inventory stop parsing", async () => {
  await expect(
    parse({
      ...envelope("sastFindings", [sast]),
      errors: [{ message: "partial" }],
    }),
  ).rejects.toThrow("GraphQL errors");
  await expect(
    parse({
      data: {
        sastFindings: { nodes: [sast], pageInfo: { hasNextPage: true } },
      },
    }),
  ).rejects.toThrow("another page");
  await expect(
    parse({
      data: {
        sastFindings: { nodes: [sast] },
        versionControlResources: {
          ...inventory,
          pageInfo: { hasNextPage: true },
        },
      },
    }),
  ).rejects.toThrow("inventory has another page");
});

test("new adapters do not fabricate missing occurrence IDs, severity, or line ranges", async () => {
  const invalid = [
    { ...sast, id: null },
    { ...sast, severity: null },
    { ...sast, startLine: null },
    { ...sast, endLine: 9 },
    { ...sast, filePath: "../outside.ts" },
  ];
  const parsed = await parse(envelope("sastFindings", invalid));
  expect(parsed.findings).toEqual([]);
  expect(parsed.excluded).toHaveLength(invalid.length);
});

test.each([
  "schema:prod.json",
  "config:prod/schema.json",
  "config/schema:prod.json",
])(
  "Wiz preserves repository-relative colon path %s and original evidence",
  async (path) => {
    const finding = { ...sast, filePath: path };
    const parsed = await parse(envelope("sastFindings", [finding]));
    expect(parsed.excluded).toEqual([]);
    expect(parsed.findings[0]!.evidence.locations).toEqual([
      { path, line: 10 },
    ]);
    expect(parsed.findings[0]!.evidence.source_data).toEqual(finding);
  },
);

test.each([
  "C:query.ts",
  "c:/query.ts",
  "D:\\query.ts",
  "/query.ts",
  "\\\\server\\query.ts",
  "../query.ts",
  "src/../query.ts",
])("external evidence rejects non-repository path %s", (path) => {
  expect(() =>
    validateExternalEvidence({
      title: "Synthetic evidence",
      severity: "high",
      locations: [{ path }],
    }),
  ).toThrow("repository-relative paths");
});

test("legacy evidence defaults retain their saved-submission bytes, including explicit null details", () => {
  const input = {
    title: "Legacy evidence",
    severity: "high",
    locations: [{ path: "package.json" }],
    packages: [{ name: "example-package" }],
  };
  const legacy = validateExternalEvidence(structuredClone(input));
  expect(hash("sha256", JSON.stringify(legacy))).toBe(
    "88f2d96656a5ad322d5f16fce7704366e359a8101d035b311a1917d4f6e31caf",
  );
  const withNull = validateExternalEvidence({
    ...structuredClone(input),
    details: null,
  });
  expect(withNull).toEqual(legacy);
  expect(withNull).not.toHaveProperty("details");
});

test("normalized JSONL retains explicit IDs, original evidence, and empty source text", async () => {
  const raw = { details: null, example: "raw evidence stays exact" };
  const payload = {
    source_finding_id: "explicit-identity",
    evidence: {
      title: "Explicit finding",
      severity: "high",
      source_data: raw,
      details: {
        kind: "sast",
        repository: { url: repositoryUrl },
        code: { snippet: "  " },
      },
    },
  };
  const parsed = await parse([payload]);
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.source_finding_id).toBe("explicit-identity");
  expect(parsed.findings[0]!.evidence.source_data).toEqual(raw);
  expect(parsed.findings[0]!.evidence.details?.code?.snippet).toBe("  ");
});

test("new detail links and long source text follow the same Cloud constraints", async () => {
  const good = { ...sast, snippet: "é".repeat(32768) };
  const tooLong = { ...sast, id: "long", snippet: "é".repeat(32769) };
  const unsafeUrl = {
    ...sast,
    id: "unsafe",
    repository: { ...repository, url: "https://user@example.test/project" },
  };
  const parsed = await parse(envelope("sastFindings", [good, tooLong]));
  expect(parsed.findings).toHaveLength(1);
  expect(parsed.excluded[0]!.reason).toContain("65536 UTF-8 bytes");
  expect(
    (await parse(envelope("sastFindings", [unsafeUrl], false))).excluded[0]!
      .reason,
  ).toContain("without credentials");
});

async function cloudFixture(payload: unknown) {
  const f = await fixture(payload);
  const environment = {
    ...process.env,
    CODEX_HOME: join(f.root, "login"),
    CODEX_SECURITY_STATE_DIR: join(f.root, "state"),
  };
  await mkdir(environment.CODEX_HOME);
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
  const destination = {
    id: "cloud-repository",
    object: "security.repository",
    repo_connector_id: "github",
    url: repositoryUrl,
    default_branch: "main",
    reset_marker: "generation-1",
    import_environment_id: "environment-1",
  };
  const posts: FindingImportRequest[] = [];
  const calls: string[] = [];
  const reports = new Map<string, SourceReport>();
  const state: {
    failReadback: boolean;
    readbackDetails?: ExternalFindingEvidence["details"];
  } = { failReadback: false };
  const transport = async (
    url: string,
    init: RequestInit,
  ): Promise<Response> => {
    calls.push(`${init.method} ${url}`);
    const target = new URL(url);
    const json = (body: unknown) =>
      new Response(JSON.stringify(body), {
        headers: { "Content-Type": "application/json" },
      });
    if (target.pathname.endsWith("/repositories"))
      return json({ data: [destination], has_more: false, next: null });
    if (target.pathname.endsWith("/source_reports")) {
      const report = reports.get(target.searchParams.get("source_finding_id")!);
      const summaries = report
        ? [
            {
              ...report,
              object: "security.source_report_summary",
              evidence: undefined,
              last_import: undefined,
              title: report.evidence.title,
              severity: report.evidence.severity,
              source_updated_at: report.evidence.source_updated_at,
            },
          ]
        : [];
      return json({ data: summaries, has_more: false, next: null });
    }
    if (target.pathname.includes("/source_reports/")) {
      if (state.failReadback)
        return new Response(
          JSON.stringify({ error: { message: "Readback unavailable" } }),
          { status: 503 },
        );
      const report = [...reports.values()].find(
        (item) => item.id === target.pathname.split("/").at(-1),
      );
      return json(
        report && state.readbackDetails
          ? {
              ...report,
              evidence: { ...report.evidence, details: state.readbackDetails },
            }
          : report,
      );
    }
    if (
      target.pathname.endsWith("/finding_imports") &&
      init.method === "POST"
    ) {
      const request = JSON.parse(String(init.body)) as FindingImportRequest;
      posts.push(request);
      const counts = { created: 0, updated: 0, unchanged: 0, error: 0 };
      const results = request.items.map((item) => {
        const previous = reports.get(item.source_finding_id);
        const outcome = previous
          ? isDeepStrictEqual(previous.evidence, item.evidence)
            ? "unchanged"
            : "updated"
          : "created";
        counts[outcome]++;
        const version =
          (previous?.version ?? 0) + (outcome === "unchanged" ? 0 : 1);
        const identity = hash("sha256", item.source_finding_id);
        const report: SourceReport = {
          id: `aif_${identity}`,
          repo_id: destination.id,
          repo_connector_id: destination.repo_connector_id,
          environment_id: "environment-1",
          canonical_finding_id:
            previous?.canonical_finding_id ?? `acf_${identity.slice(0, 32)}`,
          source: request.source,
          source_finding_id: item.source_finding_id,
          observation_id: `aio_${hash("sha256", `${identity}:${version}`)}`,
          version,
          evidence: item.evidence,
          assessment: { state: "not_assessed" },
          created_at: 1,
          updated_at: 1,
        };
        if (previous) report.id = previous.id;
        reports.set(item.source_finding_id, report);
        return {
          client_id: item.client_id,
          outcome,
          source_report_id: report.id,
          observation_id: report.observation_id,
          canonical_finding_id: report.canonical_finding_id,
          version,
        };
      });
      return json({
        id: request.request_id,
        repository: request.repository,
        source: request.source,
        actor: "synthetic-user",
        created_at: 1,
        item_count: request.items.length,
        counts,
        results,
      });
    }
    throw new Error(`Unexpected injected Cloud request ${init.method} ${url}`);
  };
  const options = {
    provider: "wiz" as const,
    sourceKey: "synthetic-tenant/wiz",
    repository: repositoryUrl,
  };
  const command = [
    "publish",
    "findings",
    f.file,
    "--to",
    "cloud",
    "--provider",
    "wiz",
    "--repository",
    repositoryUrl,
    "--source-key",
    options.sourceKey,
    "--format",
    "json",
  ];
  return {
    ...f,
    posts,
    calls,
    reports,
    state,
    destination,
    options,
    command,
    environment,
    deps: { environment, fetch: transport },
    cliDeps: { ...dependencies(), environment, cloudFetch: transport },
  };
}

for (const [root, record, kind] of [
  ["sastFindings", sast, "sast"],
  ["secretInstances", secret, "secret"],
  ["iacFindings", iac, "iac"],
] as const) {
  test(`CLI previews, publishes, and reimports ${kind} through injected transport without changing Codex assessment`, async () => {
    const f = await cloudFixture(envelope(root, [record]));
    const cli = createCliTest(main);
    expect(await cli.runCli([...f.command, "--dry-run"], f.cliDeps)).toBe(0);
    const preview = JSON.parse(cli.stdout.text());
    expect(preview.findings[0].evidence.details.kind).toBe(kind);
    expect(f.posts).toHaveLength(0);
    const upload = createCliTest(main);
    const exitCode = await upload.runCli([...f.command, "--yes"], f.cliDeps);
    expect(exitCode, upload.stdout.text() + upload.stderr.text()).toBe(0);
    expect(f.posts).toHaveLength(1);
    const first = f.reports.get(`${kind}:occurrence-1`)!;
    expect(first.assessment).toEqual({ state: "not_assessed" });
    expect(first.evidence.source_data).toEqual(record);
    const replay = await prepareExternalPublication(f.file, f.options, f.deps);
    expect((await replay.publish()).counts.unchanged).toBe(1);
    expect(f.reports.get(`${kind}:occurrence-1`)!.canonical_finding_id).toBe(
      first.canonical_finding_id,
    );
    const changed = { ...record, status: "RESOLVED" };
    await writeFile(f.file, JSON.stringify(envelope(root, [changed])));
    await (
      await prepareExternalPublication(f.file, f.options, f.deps)
    ).publish();
    expect(f.reports.get(`${kind}:occurrence-1`)!.assessment).toEqual({
      state: "not_assessed",
    });
    expect(f.reports.get(`${kind}:occurrence-1`)!.evidence.source_data).toEqual(
      changed,
    );
  });
}

test.each(["synchronous", "asynchronous"] as const)(
  "approved finding publication survives %s diagnostic stream failures",
  async (failure) => {
    const f = await cloudFixture(envelope("sastFindings", [sast]));
    const stdout = capture();
    const stderr = Object.assign(
      new Writable({
        write(_chunk, _encoding, callback) {
          callback(new Error("Synthetic diagnostic stream failure"));
        },
      }),
      { isTTY: true },
    );
    if (failure === "synchronous")
      stderr.write = () => {
        throw new Error("Synthetic diagnostic stream failure");
      };
    const code = await main(
      [...f.command.slice(0, -2), "--yes"],
      stdout.stream,
      stderr,
      f.cliDeps,
    );
    expect(code).toBe(0);
    expect(f.posts).toHaveLength(1);
    expect(f.reports.get("sast:occurrence-1")!.assessment).toEqual({
      state: "not_assessed",
    });
    expect(stdout.text()).toContain("1");
  },
);

test("a wrong source repository stops raw and normalized imports before source lookup or upload", async () => {
  const other = {
    ...sast,
    repository: { ...repository, url: "https://github.com/example/other" },
  };
  const f = await cloudFixture(envelope("sastFindings", [other], false));
  await expect(
    prepareExternalPublication(f.file, f.options, f.deps),
  ).rejects.toThrow("does not match the selected Cloud repository");
  expect(f.calls).toHaveLength(1);
  expect(f.posts).toEqual([]);
  const normalized = (await readVendorFindings(f.file)).findings;
  await writeFile(f.file, JSON.stringify(normalized));
  await expect(
    prepareExternalPublication(f.file, f.options, f.deps),
  ).rejects.toThrow("does not match");
  expect(f.posts).toEqual([]);
  expect(
    await readdir(join(f.root, "state")).catch(() => undefined),
  ).toBeUndefined();
});

const csvRow: Record<string, string> = {
  ID: "csv-occurrence-1",
  WizURL: "https://app.wiz.io/vulnerability-findings/csv-occurrence-1",
  Name: "CVE-2026-0001",
  DetailedName: "example-package",
  AssetID: "synthetic-repository-branch",
  AssetName: "example/project/feature/parser",
  CloudPlatform: "GitHub",
  CloudProviderURL: "https://github.com/example/project/tree/feature/parser",
  Severity: "HIGH",
  VendorSeverity: "LOW",
  CVSSSeverity: "CRITICAL",
  Description: 'A quoted "description", with a comma.\r\nAnd another line.',
  LocationPath: "/package-lock.json",
  Version: "1.0.0",
  FixedVersion: "2.0.0",
  DetectionMethod: "Library",
  FindingStatus: "Resolved",
  LastDetected: "2026-01-02T03:04:05Z",
};

function csvReport(
  rows: Record<string, string>[],
  headers = Object.keys(rows[0] ?? csvRow),
): string {
  const quote = (value: string) => '"' + value.replaceAll('"', '""') + '"';
  return [headers, ...rows.map((row) => headers.map((key) => row[key] ?? ""))]
    .map((cells) => cells.map(quote).join(","))
    .join("\r\n");
}

test.each(["", "\n \r\n"])(
  "JSONL retains CSV-like column names as evidence with prefix %j",
  async (prefix) => {
    const f = await fixture({});
    const records = ["first", "second"].map((id) => ({
      source_finding_id: id,
      evidence: {
        title: "Synthetic normalized finding",
        severity: "high",
        source_data: { columns: ["extra", ...Object.keys(csvRow), "other"] },
      },
    }));
    await writeFile(
      f.file,
      prefix + records.map((record) => JSON.stringify(record)).join("\r\n"),
    );
    const parsed = await readVendorFindings(f.file);
    expect(parsed.excluded).toEqual([]);
    expect(parsed.findings.map((finding) => finding.source_finding_id)).toEqual(
      ["first", "second"],
    );
    expect(
      parsed.findings.map((finding) => finding.evidence.source_data),
    ).toEqual(records.map((record) => record.evidence.source_data));
  },
);

test.each(["plain", "gzip", "bom"])(
  "Wiz Code CSV maps source claims and retains every original cell (%s)",
  async (encoding) => {
    const f = await fixture({});
    const csv = csvReport([csvRow]);
    await writeFile(
      f.file,
      encoding === "gzip"
        ? gzipSync(csv)
        : (encoding === "bom" ? "\ufeff" : "") + csv,
    );
    const parsed = await readVendorFindings(f.file);
    expect(parsed.read).toBe(1);
    expect(parsed.excluded).toEqual([]);
    expect(parsed.findings[0]).toMatchObject({
      source_finding_id: "csv-occurrence-1",
      evidence: {
        title: "example-package 1.0.0 CVE-2026-0001",
        description: csvRow["Description"],
        severity: "high",
        advisory_ids: ["CVE-2026-0001"],
        packages: [
          {
            name: "example-package",
            ecosystem: null,
            installed_version: "1.0.0",
            manifest_path: "package-lock.json",
            fixed_versions: ["2.0.0"],
          },
        ],
        locations: [{ path: "package-lock.json", line: null }],
        branch: null,
        code_revision: null,
        source_scan_id: null,
        source_updated_at: null,
        source_data: { format: "wiz-code-vulnerability-csv", row: csvRow },
      },
    });
    expect(parsed.findings[0]!.evidence.details).toBeUndefined();
  },
);

test("Wiz CSV keeps opaque columns and formula-like text without interpreting them", async () => {
  const row = Object.fromEntries([
    ...Object.entries(csvRow),
    ["__proto__", '{"admin":true}'],
    ["constructor", "opaque constructor"],
    ["source_finding_id", "opaque source id"],
    ["evidence", "opaque evidence"],
    ["Extra", "'=SUM(1,2)"],
  ]);
  const f = await fixture({});
  await writeFile(f.file, csvReport([row]));
  const parsed = await readVendorFindings(f.file);
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.source_finding_id).toBe(csvRow["ID"]!);
  expect(parsed.findings[0]!.evidence.source_data!["row"]).toEqual(row);
  expect(
    Object.getPrototypeOf(parsed.findings[0]!.evidence.source_data!["row"]),
  ).toBe(Object.prototype);
});

test.each([
  {
    Severity: "",
    VendorSeverity: "MEDIUM",
    CVSSSeverity: "HIGH",
    expected: "medium",
  },
  { Severity: "", VendorSeverity: "", CVSSSeverity: "LOW", expected: "low" },
  {
    Severity: "Informational",
    VendorSeverity: "",
    CVSSSeverity: "",
    expected: "informational",
  },
  {
    Severity: "NONE",
    VendorSeverity: "",
    CVSSSeverity: "",
    expected: "unknown",
  },
  {
    Severity: "",
    VendorSeverity: "NONE",
    CVSSSeverity: "HIGH",
    expected: "unknown",
  },
  {
    Severity: "",
    VendorSeverity: "",
    CVSSSeverity: "NONE",
    expected: "unknown",
  },
])(
  "Wiz CSV uses the reported severity fallback %j",
  async ({ expected, ...severity }) => {
    const f = await fixture({});
    await writeFile(f.file, csvReport([{ ...csvRow, ...severity }]));
    const parsed = await readVendorFindings(f.file);
    expect(parsed.findings[0]!.evidence.severity).toBe(expected);
  },
);

test.each([{ vendorSeverity: "NONE", severity: "HIGH" }, { severity: "NONE" }])(
  "Wiz JSON preserves unrated severity as unknown: %j",
  async (severity) => {
    const record = {
      id: "vendor-none",
      name: "CVE-2099-0001",
      detailedName: "example-package",
      vulnerableAsset: { id: "synthetic-asset" },
      ...severity,
    };
    const parsed = await parse(
      envelope("vulnerabilityFindings", [record], false),
    );
    expect(parsed.excluded).toEqual([]);
    expect(parsed.findings[0]!.evidence.severity).toBe("unknown");
    expect(parsed.findings[0]!.evidence.source_data).toEqual(record);
  },
);

test.each([
  { ID: "" },
  { AssetID: "" },
  { DetailedName: "" },
  { Severity: "not-a-severity" },
  { CloudPlatform: "AWS" },
  { CloudProviderURL: "https://github.com/example/project" },
  { CloudProviderURL: "not a URL" },
  { LocationPath: "/../outside/package.json" },
  { LocationPath: "C:\\outside\\package.json" },
] as Record<string, string>[])(
  "Wiz CSV excludes a malformed or unsupported occurrence without losing other rows: %j",
  async (change) => {
    const f = await fixture({});
    await writeFile(
      f.file,
      csvReport([csvRow, { ...csvRow, ID: "bad-row", ...change }]),
    );
    const parsed = await readVendorFindings(f.file);
    expect(parsed.read).toBe(2);
    expect(parsed.findings.map((finding) => finding.source_finding_id)).toEqual(
      [csvRow["ID"]!],
    );
    expect(parsed.excluded).toHaveLength(1);
    expect(parsed.excluded[0]!.position).toBe(2);
  },
);

test("Wiz CSV accepts an empty report and never uses an advisory as occurrence identity", async () => {
  const f = await fixture({});
  await writeFile(f.file, csvReport([]));
  expect(await readVendorFindings(f.file)).toEqual({
    read: 0,
    findings: [],
    excluded: [],
  });
  await writeFile(
    f.file,
    csvReport([csvRow, { ...csvRow, ID: "csv-occurrence-2" }]),
  );
  expect(
    (await readVendorFindings(f.file)).findings.map(
      (finding) => finding.source_finding_id,
    ),
  ).toEqual(["csv-occurrence-1", "csv-occurrence-2"]);
  await writeFile(f.file, csvReport([csvRow, csvRow]));
  await expect(readVendorFindings(f.file)).rejects.toThrow(
    "Duplicate source finding id",
  );
});

test.each([
  "duplicate header",
  "short row",
  "long row",
  "unterminated quote",
  "invalid UTF-8",
])(
  "Wiz CSV rejects a damaged report before publication (%s)",
  async (damage) => {
    const f = await cloudFixture({});
    let contents = csvReport([csvRow]);
    if (damage === "duplicate header")
      contents = csvReport([csvRow], [...Object.keys(csvRow), "ID"]);
    if (damage === "short row") contents = csvReport([]) + '\r\n"short"';
    if (damage === "long row") contents += ',"extra"';
    if (damage === "unterminated quote") contents = contents.slice(0, -1);
    await writeFile(
      f.file,
      damage === "invalid UTF-8"
        ? Buffer.concat([Buffer.from(contents), Buffer.from([0xff])])
        : contents,
    );
    await expect(
      prepareExternalPublication(f.file, f.options, f.deps),
    ).rejects.toThrow();
    expect(f.posts).toEqual([]);
  },
);

test.each([false, true])(
  "Wiz CSV binds the source repository before uploads, including normalized input (%p)",
  async (normalized) => {
    const f = await cloudFixture({});
    await writeFile(
      f.file,
      csvReport([
        {
          ...csvRow,
          CloudProviderURL: "https://github.com/other/project/tree/main",
        },
      ]),
    );
    if (normalized)
      await writeFile(
        f.file,
        JSON.stringify((await readVendorFindings(f.file)).findings),
      );
    await expect(
      prepareExternalPublication(f.file, f.options, f.deps),
    ).rejects.toThrow("does not match");
    expect(f.posts).toEqual([]);
    expect(f.calls.filter((call) => call.includes("/source_reports"))).toEqual(
      [],
    );
  },
);

for (const normalized of [false, true]) {
  test.each([
    [
      "https://github.example.test:443",
      "https://github.example.test:443",
      true,
    ],
    ["http://github.example.test:80", "http://github.example.test:80", true],
    [
      "https://github.example.test:8443",
      "https://github.example.test:8443",
      true,
    ],
    ["https://github.example.test:443", "https://github.example.test", false],
    ["http://github.example.test:80", "http://github.example.test", false],
    ["https://github.example.test", "https://github.example.test:443", false],
    ["http://github.example.test", "http://github.example.test:80", false],
  ])(
    `Wiz CSV preserves repository ports in ${normalized ? "normalized JSONL" : "native CSV"}: %s → %s`,
    async (source, destination, matches) => {
      const f = await cloudFixture({});
      f.destination.url = `${destination}/example/project`;
      const options = { ...f.options, repository: f.destination.id };
      const rows = ["csv-occurrence-1", "csv-occurrence-2"].map((ID) => ({
        ...csvRow,
        ID,
        CloudProviderURL: `${source}/example/project/tree/main`,
      }));
      await writeFile(f.file, csvReport(rows));
      if (normalized)
        await writeFile(
          f.file,
          (await readVendorFindings(f.file)).findings
            .map((finding) => JSON.stringify(finding))
            .join("\n"),
        );
      if (matches) {
        const prepared = await prepareExternalPublication(
          f.file,
          options,
          f.deps,
        );
        expect(prepared.preview.findings).toHaveLength(2);
        expect(prepared.preview.excluded).toEqual([]);
      } else {
        await expect(
          prepareExternalPublication(f.file, options, f.deps),
        ).rejects.toThrow("does not match");
        expect(
          f.calls.filter((call) => call.includes("/source_reports")),
        ).toEqual([]);
      }
      expect(f.posts).toEqual([]);
    },
  );
}

test("Wiz CSV retries retain acknowledged requests across column reordering and repeated imports stay unchanged", async () => {
  const f = await cloudFixture({});
  const rows = [csvRow, { ...csvRow, ID: "csv-occurrence-2" }];
  await writeFile(f.file, csvReport(rows));
  const original = await prepareExternalPublication(f.file, f.options, f.deps);
  expect(f.posts).toEqual([]);
  f.state.failReadback = true;
  await expect(original.publish()).rejects.toBeInstanceOf(
    ExternalPublicationError,
  );
  await writeFile(f.file, csvReport(rows, Object.keys(csvRow).reverse()));
  const resumed = await prepareExternalPublication(f.file, f.options, f.deps);
  expect(resumed.preview.resumed).toBe(true);
  expect(resumed.preview.requests).toEqual(original.preview.requests);
  f.state.failReadback = false;
  expect((await resumed.publish()).verified).toBe(2);
  expect(f.posts).toHaveLength(1);
  const repeated = await prepareExternalPublication(f.file, f.options, f.deps);
  const result = await repeated.publish();
  expect(result.verified).toBe(2);
  expect(result.receipts[0]!.counts.unchanged).toBe(2);
  expect([...f.reports.values()].map((report) => report.version)).toEqual([
    1, 1,
  ]);
  expect(f.posts[0]!.items[0]!.evidence.source_data!["row"]).toEqual(csvRow);
});

test("saved typed requests resume by repository ID after a repository rename", async () => {
  const f = await cloudFixture(envelope("sastFindings", [sast]));
  const options = { ...f.options, repository: f.destination.id };
  f.state.failReadback = true;
  await expect(
    (await prepareExternalPublication(f.file, options, f.deps)).publish(),
  ).rejects.toThrow("Readback unavailable");
  expect(f.posts).toHaveLength(1);
  f.destination.url = "https://github.com/example/renamed";
  f.state.failReadback = false;
  const resumed = await prepareExternalPublication(f.file, options, f.deps);
  expect(resumed.preview.resumed).toBe(true);
  expect(resumed.preview.destination.url).toBe(f.destination.url);
  expect((await resumed.publish()).verified).toBe(1);
  expect(f.posts).toHaveLength(1);
  expect(
    f.reports.get("sast:occurrence-1")!.evidence.details!.repository!.url,
  ).toBe(repositoryUrl);
});

// Expected details were serialized by the canonical Cloud validation model.
// Keep that readback independent of the CLI validator so nullable defaults cannot
// be hidden by a transport that merely echoes the submitted evidence.
for (const golden of roundtripFixtures) {
  test(`sparse ${golden.name} evidence matches canonical Cloud readback`, async () => {
    const evidence = {
      title: "Synthetic normalized finding",
      severity: "high",
      details: golden.input,
      source_data: { id: golden.name, details: null },
    };
    const f = await cloudFixture([
      { source_finding_id: golden.name, evidence },
    ]);
    f.state.readbackDetails = structuredClone(golden.expected) as NonNullable<
      ExternalFindingEvidence["details"]
    >;
    const prepared = await prepareExternalPublication(
      f.file,
      f.options,
      f.deps,
    );
    expect(prepared.preview.findings[0]!.evidence.details).toEqual(
      f.state.readbackDetails,
    );
    expect((await prepared.publish()).verified).toBe(1);
    expect(f.posts[0]!.items[0]!.evidence.source_data).toEqual(
      evidence.source_data,
    );
  });
}

test("GitHub repository metadata accepts case variants without changing source URLs", async () => {
  const supplied = {
    ...sast,
    repository: {
      ...repository,
      url: "HTTPS://GITHUB.COM/Example/PROJECT.git/",
    },
  };
  const mixedInventory = {
    ...inventory,
    nodes: [
      ...inventory.nodes,
      {
        ...inventory.nodes[0]!,
        repository: {
          ...repository,
          url: "https://github.com/EXAMPLE/Project.git/",
        },
      },
    ],
  };
  const parsed = await parse({
    data: {
      sastFindings: { nodes: [supplied] },
      versionControlResources: mixedInventory,
    },
  });
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.evidence.source_data).toEqual(supplied);
  expect(parsed.findings[0]!.evidence.details!.repository!.url).toBe(
    supplied.repository.url,
  );
});

test.each([
  [
    "https://github.com/Example/Project.git/",
    "https://github.com/example/project",
    true,
  ],
  [
    "https://EXAMPLE.ghe.com/Team/Project.git/",
    "https://example.ghe.com/team/project",
    true,
  ],
  [
    "https://github.com/Example/Other.git/",
    "https://github.com/example/project",
    false,
  ],
  [
    "https://other.ghe.com/team/project",
    "https://example.ghe.com/team/project",
    false,
  ],
  [
    "https://github.example.test/Team/Project.git/",
    "https://github.example.test/team/project",
    true,
  ],
  [
    "http://github.com/example/project",
    "https://github.com/example/project",
    false,
  ],
  [
    "https://github.com:443/example/project",
    "https://github.com/example/project",
    false,
  ],
  [
    "https://example.ghe.com/Team/Project.GIT/",
    "https://example.ghe.com/team/project",
    false,
  ],
])(
  "repository URL binding preserves identity: %s to %s",
  async (sourceUrl, destinationUrl, matches) => {
    const record = { ...sast, repository: { ...repository, url: sourceUrl } };
    const f = await cloudFixture(envelope("sastFindings", [record], false));
    f.destination.url = destinationUrl;
    const options = { ...f.options, repository: f.destination.id };
    if (matches) {
      const publication = await prepareExternalPublication(
        f.file,
        options,
        f.deps,
      );
      expect((await publication.publish()).verified).toBe(1);
      expect(f.posts[0]!.items[0]!.evidence.source_data).toEqual(record);
    } else {
      await expect(
        prepareExternalPublication(f.file, options, f.deps),
      ).rejects.toThrow("does not match");
      expect(f.posts).toEqual([]);
    }
  },
);

test.each(["github.com", "example.ghe.com", "github.example.test"])(
  "Cloud GitHub repository selection accepts a URL case variant on %s",
  async (host) => {
    const url = "https://" + host + "/example/project";
    const record = { ...sast, repository: { ...repository, url } };
    const f = await cloudFixture(envelope("sastFindings", [record], false));
    f.destination.url = url;
    const prepared = await prepareExternalPublication(
      f.file,
      {
        ...f.options,
        repository: "HTTPS://" + host.toUpperCase() + "/Example/PROJECT.git/",
      },
      f.deps,
    );
    expect(prepared.preview.destination.id).toBe(f.destination.id);
    expect(f.posts).toEqual([]);
  },
);

test("custom GitHub Enterprise binding preserves branch case and exact source evidence", async () => {
  const record = {
    ...sast,
    repository: {
      ...repository,
      name: "Team/Project",
      url: "https://github.example.test/Team/Project.git/",
    },
    repositoryBranch: {
      id: "wiz-branch",
      name: "Team/Project/Feature/Parser/More",
    },
  };
  const f = await cloudFixture(envelope("sastFindings", [record], false));
  f.destination.url = "https://github.example.test/team/project";
  f.destination.repo_connector_id = "custom-github";
  const prepared = await prepareExternalPublication(
    f.file,
    { ...f.options, repository: f.destination.id },
    f.deps,
  );
  expect((await prepared.publish()).verified).toBe(1);
  const evidence = f.posts[0]!.items[0]!.evidence;
  expect(evidence.branch).toBe(record.repositoryBranch.name);
  expect(evidence.details!.repository!.url).toBe(record.repository.url);
  expect(evidence.source_data).toEqual(record);
});

test.each([
  ["sastFindings", "Team/Project", "team/project"],
  ["sastFindings", "team/project", "Team/Project"],
  ["secretInstances", "Team/Project", "team/project"],
  ["secretInstances", "team/project", "Team/Project"],
  ["iacFindings", "Team/Project", "team/project"],
  ["iacFindings", "team/project", "Team/Project"],
])(
  "%s custom GitHub URL-only branches preserve the supplied name (%s, %s)",
  async (collection, repositoryPath, qualifier) => {
    const sourceRepository = {
      id: "wiz-repository",
      url: `https://github.example.test/${repositoryPath}`,
    };
    const branch = {
      id: "wiz-branch",
      name: `${qualifier}/Feature/Parser/More`,
    };
    const record =
      collection === "secretInstances"
        ? {
            ...secret,
            resource: {
              ...secret.resource,
              name: branch.name,
              typedProperties: { repository: sourceRepository },
            },
          }
        : collection === "iacFindings"
          ? { ...iac, repository: sourceRepository, branch }
          : { ...sast, repository: sourceRepository, repositoryBranch: branch };
    const f = await cloudFixture(envelope(collection!, [record], false));
    f.destination.url = "https://github.example.test/team/project";
    const prepared = await prepareExternalPublication(
      f.file,
      { ...f.options, repository: f.destination.id },
      f.deps,
    );
    expect((await prepared.publish()).verified).toBe(1);
    const evidence = f.posts[0]!.items[0]!.evidence;
    expect(evidence.branch).toBe(branch.name);
    expect(evidence.details!.repository!.url).toBe(sourceRepository.url);
    expect(evidence.source_data).toEqual(record);
  },
);

test("unidentified source hosts still require exact supplied and inventory URL paths", async () => {
  const record = {
    ...sast,
    repository: {
      ...repository,
      url: "https://code.example.test/Team/Project",
    },
  };
  const parsed = await parse({
    data: {
      sastFindings: { nodes: [record] },
      versionControlResources: {
        nodes: [
          {
            id: "unidentified-branch",
            repository: {
              ...repository,
              url: "https://code.example.test/team/project",
            },
          },
        ],
      },
    },
  });
  expect(parsed.findings).toEqual([]);
  expect(parsed.excluded[0]!.reason).toContain("conflicting repository URLs");
});

test.each(["named collection", "normalized JSONL"])(
  "Node reads a large %s without parsing limits",
  async (format) => {
    const count = 150_000;
    const records = Array.from({ length: count }, (_, index) => ({
      id: `vendor-${index}`,
      name: "CVE-2099-0001",
      detailedName: "example-package",
      severity: "HIGH",
      vulnerableAsset: { id: "synthetic-asset" },
    }));
    const f = await fixture(
      format === "named collection"
        ? envelope("vulnerabilityFindings", records, false)
        : {},
    );
    if (format === "normalized JSONL")
      await writeFile(
        f.file,
        records
          .map((record) =>
            JSON.stringify({
              source_finding_id: record.id,
              evidence: {
                title: "Synthetic package vulnerability",
                severity: "high",
                source_data: {
                  ...record,
                  vendorSeverity: "HIGH",
                  description: "Synthetic package vulnerability evidence.",
                },
              },
            }),
          )
          .join("\n"),
      );
    // Run the actual parser under Node; Bun does not have the same argument limit.
    const bundle = await mkdtemp(join(import.meta.dir, "..", ".wiz-parser-"));
    directories.push(bundle);
    const runner = join(bundle, "large-input.mts");
    await writeFile(
      runner,
      `
    import { readVendorFindings, readVendorFindingsForPublication } from "../src/wiz-findings.js";
    const parsed = process.argv[3] === "normalized JSONL"
      ? (await readVendorFindingsForPublication(process.argv[2]!)).current
      : await readVendorFindings(process.argv[2]!);
    console.log(JSON.stringify({
      read: parsed.read, ready: parsed.findings.length, excluded: parsed.excluded.length,
      first: parsed.findings[0]?.source_finding_id,
      last: parsed.findings.at(-1)?.source_finding_id,
    }));
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
    const child = Bun.spawn(
      [
        Bun.which("node")!,
        ...(format === "normalized JSONL" ? ["--max-old-space-size=256"] : []),
        built.outputs[0]!.path,
        f.file,
        format,
      ],
      { stdout: "pipe", stderr: "pipe" },
    );
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(exitCode, stderr).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      read: count,
      ready: count,
      excluded: 0,
      first: "vendor-0",
      last: `vendor-${count - 1}`,
    });
  },
);

// Captured after the pre-release writer at a431663b5e1 received a receipt and
// readback failed. Its filenames depended on deployment and host collation.
async function previewCheckpointFixture(base = DEFAULT_CLOUD_BASE_URL) {
  const request = previewCheckpoint.requests[0]!;
  const item = request.items[0]!;
  const { title, severity, source_data } = item.evidence;
  const f = await cloudFixture([
    {
      source_finding_id: item.source_finding_id,
      evidence: { title, severity, source_data },
    },
  ]);
  // Seed the injected Cloud transport with the observation in the saved receipt.
  await f.deps.fetch(`${base}/finding_imports`, {
    method: "POST",
    body: JSON.stringify(request),
  });
  const directory = join(
    f.environment.CODEX_SECURITY_STATE_DIR,
    "external-finding-publications",
  );
  await mkdir(directory, { recursive: true, mode: 0o700 });
  return {
    ...f,
    directory,
    prepare: () =>
      prepareExternalPublication(f.file, f.options, {
        ...f.deps,
        environment: { ...f.environment, CODEX_SECURITY_CLOUD_BASE_URL: base },
      }),
  };
}

const savedPreview = JSON.stringify(previewCheckpoint);

// Use the host's collation to recover the original filename in any locale.
function localPreviewFilename() {
  const request = previewCheckpoint.requests[0]!;
  const selection = request.items.map(({ source_finding_id, evidence }) => ({
    source_finding_id,
    evidence,
  }));
  const identity = [
    previewCheckpoint.accountId,
    request.repository.id,
    request.repository.repo_connector_id,
    request.source,
    selection,
  ];
  return `${legacyCheckpointKey(identity)}.pending.json`;
}

function legacyCheckpointKey(identity: unknown[]) {
  const encoded = JSON.stringify(identity, (_key, child: unknown) =>
    child && typeof child === "object" && !Array.isArray(child)
      ? Object.fromEntries(
          Object.entries(child).sort(([a], [b]) => a.localeCompare(b)),
        )
      : child,
  );
  return hash("sha256", encoded);
}

test.each(["distinct", "duplicate"] as const)(
  "a migrated preview checkpoint completes readback with a %s older file",
  async (kind) => {
    const f = await previewCheckpointFixture();
    const oldName = localPreviewFilename();
    const oldPath = join(f.directory, oldName);
    await writeFile(oldPath, savedPreview);
    const migrated = await f.prepare();
    expect(migrated.preview.resumed).toBe(true);
    expect<unknown[]>(migrated.preview.requests).toEqual(
      previewCheckpoint.requests,
    );
    const pendingNames = (await readdir(f.directory)).filter((name) =>
      name.endsWith(".pending.json"),
    );
    expect(pendingNames).toHaveLength(1);
    expect(pendingNames).not.toContain(oldName);
    const pendingPath = join(f.directory, pendingNames[0]!);
    expect(await readFile(pendingPath, "utf8")).toBe(savedPreview);

    // A crash can leave both names. Only an identical request can be removed.
    const old = structuredClone(previewCheckpoint);
    if (kind === "distinct") {
      old.requests[0]!.request_id = "synthetic-older-request";
      old.receipts = [];
    }
    const older = JSON.stringify(old);
    await writeFile(oldPath, older);
    const resumed = await f.prepare();
    expect<unknown[]>(resumed.preview.requests).toEqual(
      previewCheckpoint.requests,
    );
    expect(await readFile(pendingPath, "utf8")).toBe(savedPreview);
    if (kind === "duplicate") {
      await expect(readFile(oldPath, "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });
    } else {
      expect(await readFile(oldPath, "utf8")).toBe(older);
    }

    const report = f.reports.get("unicode-evidence")!;
    report.evidence.source_data = Object.fromEntries(
      Object.entries(report.evidence.source_data!).reverse(),
    );
    const beforePublish = f.calls.length;
    expect((await resumed.publish()).verified).toBe(1);
    expect(f.calls.slice(beforePublish)).toContainEqual(
      expect.stringContaining(`/source_reports/${report.id}`),
    );
    expect(f.posts).toHaveLength(1);
    if (kind === "distinct") {
      expect(await readFile(oldPath, "utf8")).toBe(older);
    } else {
      expect((await f.prepare()).preview.resumed).toBe(false);
    }
  },
);

// Pick a filename the historical writer produced under a different collation.
function foreignFilename(englishKey: string, swedishKey: string) {
  return `${"ä".localeCompare("Z") < 0 ? swedishKey : englishKey}.pending.json`;
}
const hostedForeignName = foreignFilename(
  "cde1eadb671511a7a309b2d76cf3e6f95fbb452e86543547d841be981002fbcc",
  "253163ba65ed2f1929f28c25e3d129e111ec119851244e8dcbe32a1bb4ed952a",
);
const customForeignName = foreignFilename(
  "2dcaa1dba62bf389461d0a02692f34ec3f3119bb4aacb8b21502466ae6ce0d33",
  "d64d6d01223834e06cf10a7b71fa31c730c3f3c5d08cc189f6a0d5ab6d3b6b3f",
);
const alternateBase = "https://cloud.example.test";

test.each([
  ["hosted, another locale", DEFAULT_CLOUD_BASE_URL, hostedForeignName, false],
  [
    "custom, another locale after preview",
    alternateBase,
    customForeignName,
    true,
  ],
  [
    "custom, recognizable hosted filename",
    alternateBase,
    localPreviewFilename(),
    false,
  ],
] as const)(
  "an unidentified preview checkpoint stops before upload: %s",
  async (_name, target, filename, afterPreview) => {
    const f = await previewCheckpointFixture(target);
    const path = join(f.directory, filename);
    const newer = f.reports.get("unicode-evidence")!;
    newer.version++;
    newer.evidence.description = "Newer Cloud evidence";
    const fresh = afterPreview ? await f.prepare() : undefined;
    await writeFile(path, savedPreview);
    await expect(fresh ? fresh.publish() : f.prepare()).rejects.toThrow(
      "original deployment and locale",
    );
    expect(f.posts).toHaveLength(1);
    expect(newer.evidence.description).toBe("Newer Cloud evidence");
    expect(await readFile(path, "utf8")).toBe(savedPreview);
  },
);

test.each([
  "account",
  "repository",
  "source",
  "evidence",
  "projected",
  "invalid",
])(
  "unrelated checkpoints do not block a fresh publication (%s)",
  async (difference) => {
    const f = await cloudFixture([
      {
        source_finding_id: "scope-evidence",
        evidence: { title: "Synthetic scope evidence", severity: "high" },
      },
    ]);
    const prepared = await prepareExternalPublication(
      f.file,
      f.options,
      f.deps,
    );
    const saved: {
      accountId: string;
      requests: FindingImportRequest[];
      inputProjection?: { inputDigest: string; savedEvidenceDigest: string };
    } = {
      accountId: prepared.preview.accountId,
      requests: structuredClone(prepared.preview.requests),
    };
    if (difference === "account") saved.accountId = "another-account";
    if (difference === "repository")
      saved.requests[0]!.repository.id = "another-repository";
    if (difference === "source")
      saved.requests[0]!.source.source_key = "another-source";
    if (difference === "evidence")
      saved.requests[0]!.items[0]!.evidence.title = "Different evidence";
    if (difference === "projected")
      saved.inputProjection = {
        inputDigest: "another-deployment",
        savedEvidenceDigest: "another-deployment",
      };
    const directory = join(
      f.environment.CODEX_SECURITY_STATE_DIR,
      "external-finding-publications",
    );
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const path = join(directory, `${"a".repeat(64)}.pending.json`);
    const serialized =
      difference === "invalid" ? "invalid JSON" : JSON.stringify(saved);
    await writeFile(path, serialized);
    const fresh = await prepareExternalPublication(f.file, f.options, f.deps);
    expect(fresh.preview.resumed).toBe(false);
    expect(await readFile(path, "utf8")).toBe(serialized);
    expect(f.posts).toHaveLength(0);
  },
);

test("Node resumes the same uncertain publication across locales and Unicode key order", async () => {
  const input = {
    source_finding_id: "locale-evidence",
    evidence: {
      title: "Synthetic Unicode metadata",
      severity: "high",
      source_data: { z: 1, ä: 2, é: "precomposed", "e\u0301": "combining" },
    },
  };
  const f = await cloudFixture([input]);
  const bundle = await mkdtemp(join(import.meta.dir, "..", ".wiz-locale-"));
  directories.push(bundle);
  const runner = join(bundle, "publication.mts");
  await writeFile(
    runner,
    `
    import { prepareExternalPublication } from "../src/external-findings-publish.js";
    // Select ICU collation explicitly so this also exercises both locales on
    // Windows hosts whose process default does not follow LANG.
    const collation = new Intl.Collator(process.argv[2]);
    String.prototype.localeCompare = function(other) {
      return collation.compare(String(this), other);
    };
    const prepared = await prepareExternalPublication(
      ${JSON.stringify(f.file)}, ${JSON.stringify(f.options)}, {
        environment: ${JSON.stringify({
          CODEX_HOME: f.environment.CODEX_HOME,
          CODEX_SECURITY_STATE_DIR: f.environment.CODEX_SECURITY_STATE_DIR,
        })},
        credentials: async () => ({ access_token: "synthetic-token", account_id: "synthetic-account" }),
        fetch: async (url, options) => {
          if (options.method === "POST") throw new Error("Synthetic uncertain upload");
          const body = new URL(url).pathname.endsWith("/repositories")
            ? { data: [${JSON.stringify(f.destination)}], has_more: false, next: null }
            : { data: [], has_more: false, next: null };
          return new Response(JSON.stringify(body));
        },
      },
    );
    try { await prepared.publish(); } catch (error) {
      console.log(JSON.stringify({
        locale: collation.resolvedOptions().locale,
        resumed: prepared.preview.resumed,
        requestId: prepared.preview.requests[0].request_id,
        savedSubmission: error.result.savedSubmission,
      }));
    }
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
  const run = async (locale: string) => {
    const child = Bun.spawn(
      [Bun.which("node")!, built.outputs[0]!.path, locale],
      {
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    expect(exitCode, stderr).toBe(0);
    return JSON.parse(stdout) as {
      locale: string;
      resumed: boolean;
      requestId: string;
      savedSubmission: string;
    };
  };
  const first = await run("en-US");
  expect(first.resumed).toBe(false);
  const second = await run("sv-SE");
  expect(second.locale).not.toBe(first.locale);
  expect(second.resumed).toBe(true);
  expect(second.requestId).toBe(first.requestId);
  expect(second.savedSubmission).toBe(first.savedSubmission);
  input.evidence.source_data = Object.fromEntries(
    Object.entries(input.evidence.source_data).reverse(),
  ) as typeof input.evidence.source_data;
  await writeFile(f.file, JSON.stringify([input]));
  const reordered = await run("en-US");
  expect(reordered.resumed).toBe(true);
  expect(reordered.requestId).toBe(first.requestId);
  expect(reordered.savedSubmission).toBe(first.savedSubmission);
});

for (const format of ["json", "jsonl"] as const) {
  test(`failed ${format} preparation preserves diagnostics under success-field filtering`, async () => {
    const f = await cloudFixture(envelope("sastFindings", [sast]));
    await rm(f.file);
    const cli = createCliTest(main);
    expect(
      await cli.runCli(
        [
          ...f.command.slice(0, -2),
          "--format",
          format,
          "--filter-output",
          "counts",
          "--yes",
        ],
        f.cliDeps,
      ),
    ).toBe(2);
    expect(JSON.parse(cli.stdout.text())).toMatchObject({
      status: "failed",
      error: expect.stringContaining("ENOENT"),
    });
    expect(f.calls).toEqual([]);
  });

  test(`failed ${format} full-output imports emit failure envelopes`, async () => {
    const f = await cloudFixture(envelope("sastFindings", [sast]));
    await writeFile(f.file, "{");
    const cli = createCliTest(main);
    expect(
      await cli.runCli(
        [
          ...f.command.slice(0, -2),
          "--format",
          format,
          "--full-output",
          "--yes",
        ],
        f.cliDeps,
      ),
    ).toBe(2);
    const output = JSON.parse(cli.stdout.text());
    expect(output.ok).toBe(false);
    expect(output.error.code).toBe("IMPORT_FAILED");
    expect(output.data.status).toBe("failed");
    expect(output.meta.command).toBe("publish findings");
    expect(f.calls).toEqual([]);
  });

  test(`interrupted ${format} full-output preserves acknowledged receipts and resumes`, async () => {
    const f = await cloudFixture(envelope("sastFindings", [sast]));
    f.state.failReadback = true;
    const command = [
      ...f.command.slice(0, -2),
      "--format",
      format,
      "--full-output",
      "--yes",
    ];
    const cli = createCliTest(main);
    expect(await cli.runCli(command, f.cliDeps)).toBe(2);
    const output = JSON.parse(cli.stdout.text());
    expect(output.ok).toBe(false);
    expect(output.error.code).toBe("IMPORT_FAILED");
    expect(output.data).toMatchObject({
      status: "interrupted",
      counts: { created: 1 },
      verified: 0,
    });
    expect(output.data.receipts).toHaveLength(1);
    expect(output.data.savedSubmission).toBeString();
    f.state.failReadback = false;
    const retry = createCliTest(main);
    expect(await retry.runCli(command, f.cliDeps)).toBe(0);
    expect(JSON.parse(retry.stdout.text())).toMatchObject({
      ok: true,
      data: { status: "complete", verified: 1 },
    });
    expect(f.posts).toHaveLength(1);
  });
}

test.each([undefined, "toon", "yaml", "md"])(
  "unsupported full-output format %s is rejected before reading or contacting Cloud",
  async (format) => {
    const f = await cloudFixture(envelope("sastFindings", [sast]));
    await rm(f.file);
    const cli = createCliTest(main);
    const command = [
      ...f.command.slice(0, -2),
      ...(format ? ["--format", format] : []),
      "--full-output",
      "--yes",
    ];
    expect(await cli.runCli(command, f.cliDeps)).toBe(2);
    expect(
      (cli.stdout.text() + cli.stderr.text()).replace(/\s+/g, " "),
    ).toContain("--format json or --format jsonl");
    expect(f.calls).toEqual([]);
    expect(f.posts).toEqual([]);
  },
);

for (const kind of ["sast", "secret", "iac"] as const) {
  test.each([
    [repositoryUrl, "example/project/feature/parser", null],
    [repositoryUrl, "example/project/fix", null],
    [
      "https://GitHub.com/Example/Project.git/",
      "EXAMPLE/PROJECT/Feature/Parser/More",
      null,
    ],
    [
      "https://GitHub.com/Example/Project.git/",
      "EXAMPLE/PROJECT.git/Feature/Parser/More",
      null,
    ],
    [repositoryUrl, "example/project.git/Feature/Parser", null],
    ["https://github.com/demo/demo", "demo/demo/Feature/Parser/More", "demo"],
    [
      "https://github.com/Demo/Demo.git/",
      "DEMO/DEMO.git/Feature/Parser/More",
      "demo",
    ],
    [
      "https://github.example.test/team/project",
      "PROJECT/Feature/Parser",
      "project",
    ],
    [repositoryUrl, "project/fix", "project"],
    [repositoryUrl, "other/project/fix", "other/project"],
    [repositoryUrl, "Feature/Parser", null],
    [repositoryUrl, "fix/example/project/Parser", null],
    [repositoryUrl, "example/project", null],
    ["https://github.com/", "example/project/feature/parser", null],
  ])(
    kind + " preserves the reported branch from %s: %s",
    async (url, branch, name) => {
      const repository = { url, ...(name ? { name } : {}) };
      const record =
        kind === "sast"
          ? {
              ...sast,
              repository,
              repositoryBranch: { id: "wiz-branch", name: branch },
            }
          : kind === "secret"
            ? {
                ...secret,
                resource: {
                  ...secret.resource,
                  name: branch,
                  typedProperties: { repository },
                },
              }
            : {
                ...iac,
                repository,
                branch: { id: "wiz-branch", name: branch },
              };
      const root =
        kind === "sast"
          ? "sastFindings"
          : kind === "secret"
            ? "secretInstances"
            : "iacFindings";
      const parsed = await parse(envelope(root, [record], false));
      expect(parsed.excluded).toEqual([]);
      expect(parsed.findings[0]!.evidence.branch).toBe(branch);
      expect(parsed.findings[0]!.evidence.details!.repository).toEqual({
        url,
        name,
        id: null,
      });
      expect(parsed.findings[0]!.evidence.source_data).toEqual(record);
    },
  );
}

// Synthetic nodes follow Wiz's documented VersionControlResources platform field.
const enterpriseUrl = "https://github.example.test/example/project";
function inventoryNode(platform: string | undefined, url = enterpriseUrl) {
  return {
    id: "wiz-inventory-node",
    type: "REPOSITORY_BRANCH",
    platform,
    repository: { id: repository.id, url },
  };
}

test.each([false, true])(
  "publication checkpoints survive optional inventory platform changes (%j)",
  async (withHint) => {
    const inventory = inventoryNode(
      withHint ? "GITHUB" : undefined,
      "https://github.example.test/Example/Project",
    );
    const payload = {
      data: {
        sastFindings: {
          nodes: [{ ...sast, repository: { id: repository.id } }],
        },
        versionControlResources: { nodes: [inventory] },
      },
    };
    const f = await cloudFixture(payload);
    f.destination.url = enterpriseUrl;
    const options = { ...f.options, repository: f.destination.id };
    const original = await prepareExternalPublication(f.file, options, f.deps);
    f.state.failReadback = true;
    await expect(original.publish()).rejects.toBeInstanceOf(
      ExternalPublicationError,
    );
    inventory.platform = withHint ? undefined : "GITHUB";
    await writeFile(f.file, JSON.stringify(payload));
    const retry = await prepareExternalPublication(f.file, options, f.deps);
    expect(retry.preview.findings).toEqual(original.preview.findings);
    expect(retry.preview.resumed).toBe(true);
    expect(retry.preview.requests).toEqual(original.preview.requests);
    const newer = f.reports.get("sast:occurrence-1")!;
    newer.version += 1;
    newer.evidence.description = "Newer Cloud evidence";
    f.state.failReadback = false;
    expect((await retry.publish()).verified).toBe(1);
    expect(f.posts).toHaveLength(1);
    expect(newer.evidence.description).toBe("Newer Cloud evidence");
  },
);

test.each(["project", "project/component"])(
  "inventory aliases preserve literal branch prefix %s in either row order",
  async (alias) => {
    const record = {
      ...sast,
      repository: { id: repository.id },
      repositoryBranch: {
        ...sast.repositoryBranch,
        name: `${alias.toUpperCase()}/Feature/Parser`,
      },
    };
    const nodes = ["example/project", "project", alias].map((name) => ({
      ...inventoryNode("GITHUB", repositoryUrl),
      repository: { ...repository, url: repositoryUrl, name },
    }));
    for (const selected of [nodes, [...nodes].reverse()]) {
      const parsed = await parse({
        data: {
          sastFindings: { nodes: [record] },
          versionControlResources: { nodes: selected },
        },
      });
      expect(parsed.excluded).toEqual([]);
      expect(parsed.findings[0]!.evidence.branch).toBe(
        `${alias.toUpperCase()}/Feature/Parser`,
      );
      expect(parsed.findings[0]!.evidence.source_data).toEqual(record);
    }
  },
);

test("repository display names do not remove literal branch components", async () => {
  const record = {
    ...sast,
    repository: { id: repository.id, name: "project" },
    repositoryBranch: {
      ...sast.repositoryBranch,
      name: "project/component/Feature",
    },
  };
  const parsed = await parse({
    data: {
      sastFindings: { nodes: [record] },
      versionControlResources: {
        nodes: [
          {
            ...inventoryNode("GITHUB", repositoryUrl),
            repository: {
              ...repository,
              url: repositoryUrl,
              name: "project/component",
            },
          },
        ],
      },
    },
  });
  expect(parsed.excluded).toEqual([]);
  expect(parsed.findings[0]!.evidence.branch).toBe("project/component/Feature");
});

for (const kind of ["sast", "secret", "iac"] as const) {
  test.each([false, true])(
    kind +
      " GITHUB inventory maps custom-host URLs and branches (supplied URL: %j)",
    async (withSourceUrl) => {
      const sourceUrl = "https://GITHUB.EXAMPLE.TEST/Example/PROJECT.git/";
      const sourceRepository = {
        id: repository.id,
        ...(withSourceUrl ? { url: sourceUrl } : {}),
      };
      const branch = {
        id: "wiz-branch",
        name: "EXAMPLE/PROJECT/Feature/Parser/More",
      };
      const record =
        kind === "secret"
          ? {
              ...secret,
              resource: {
                ...secret.resource,
                name: branch.name,
                typedProperties: { repository: sourceRepository },
              },
            }
          : {
              ...(kind === "sast" ? sast : iac),
              repository: sourceRepository,
              [kind === "sast" ? "repositoryBranch" : "branch"]: branch,
            };
      const root = {
        sast: "sastFindings",
        secret: "secretInstances",
        iac: "iacFindings",
      }[kind];
      const f = await cloudFixture({
        data: {
          [root]: { nodes: [record] },
          versionControlResources: {
            nodes: [
              {
                ...inventoryNode("GITHUB"),
                type: withSourceUrl ? "REPOSITORY_BRANCH" : "CI_WORKFLOW",
              },
            ],
          },
        },
      });
      f.destination.url = enterpriseUrl;
      const publication = await prepareExternalPublication(
        f.file,
        { ...f.options, repository: f.destination.id },
        f.deps,
      );
      expect((await publication.publish()).verified).toBe(1);
      const evidence = f.posts[0]!.items[0]!.evidence;
      expect(evidence.branch).toBe(branch.name);
      expect(evidence.details!.repository).toEqual({
        id: repository.id,
        name: null,
        url: withSourceUrl ? sourceUrl : enterpriseUrl,
      });
      expect(evidence.source_data).toEqual(record);
    },
  );
}

test.each(["GITLAB", "github"])(
  "inventory platform %s does not imply GitHub custom-host matching",
  async (platform) => {
    const record = {
      ...sast,
      repository: {
        ...repository,
        url: "https://github.example.test/Example/Project",
      },
    };
    const parsed = await parse({
      data: {
        sastFindings: { nodes: [record] },
        versionControlResources: { nodes: [inventoryNode(platform)] },
      },
    });
    expect(parsed.findings).toEqual([]);
    expect(parsed.excluded[0]!.reason).toContain("conflicting repository URLs");
  },
);

test.each([0, 1, 2])(
  "GITHUB inventory duplicate matching is independent of hint position %j",
  async (githubPosition) => {
    const urls = [
      "https://github.example.test/Example/Project.git/",
      "https://github.example.test/EXAMPLE/PROJECT",
      enterpriseUrl,
    ];
    const nodes = urls.map((url, index) =>
      inventoryNode(index === githubPosition ? "GITHUB" : undefined, url),
    );
    const record = {
      ...sast,
      repository: { id: repository.id },
      repositoryBranch: {
        id: "wiz-branch",
        name: "EXAMPLE/PROJECT/Feature/Parser",
      },
    };
    const parsed = await parse({
      data: {
        sastFindings: { nodes: [record] },
        versionControlResources: { nodes },
      },
    });
    expect(parsed.excluded).toEqual([]);
    expect(parsed.findings[0]!.evidence.branch).toBe(
      record.repositoryBranch.name,
    );
    expect(parsed.findings[0]!.evidence.details!.repository).toEqual({
      id: repository.id,
      name: null,
      url: urls[1]!,
    });
    expect(parsed.findings[0]!.evidence.source_data).toEqual(record);
  },
);

test("equivalent inventory rows preserve publication identity when reordered", async () => {
  const record = { ...sast, repository: { id: repository.id } };
  const nodes = [
    {
      ...inventoryNode("GITHUB"),
      repository: {
        ...repository,
        name: "Example/Project",
        url: "https://github.com/Example/Project.git",
      },
    },
    {
      ...inventoryNode(undefined),
      repository: { ...repository, url: repositoryUrl },
    },
  ];
  const payload = {
    data: {
      sastFindings: { nodes: [record] },
      versionControlResources: { nodes },
    },
  };
  const f = await cloudFixture(payload);
  const prepared = await prepareExternalPublication(f.file, f.options, f.deps);
  f.state.failReadback = true;
  await expect(prepared.publish()).rejects.toBeInstanceOf(
    ExternalPublicationError,
  );
  nodes.reverse();
  await writeFile(f.file, JSON.stringify(payload));
  const retry = await prepareExternalPublication(f.file, f.options, f.deps);
  expect(retry.preview.findings).toEqual(prepared.preview.findings);
  expect(retry.preview.findings[0]!.evidence.source_data).toEqual(record);
  expect(retry.preview.resumed).toBe(true);
  expect(retry.preview.requests[0]!.request_id).toBe(
    prepared.preview.requests[0]!.request_id,
  );
  f.state.failReadback = false;
  expect((await retry.publish()).verified).toBe(1);
  expect(f.posts).toHaveLength(1);
});

test.each(["raw", "normalized"])(
  "publication identity retains explicit branch changes (%s)",
  async (kind) => {
    const record = structuredClone(sast);
    const normalized = {
      source_finding_id: "explicit-branch",
      evidence: {
        title: "Synthetic finding",
        severity: "high",
        branch: "main",
        source_data: { id: "unchanged-source" },
      },
    };
    const input =
      kind === "raw" ? envelope("sastFindings", [record]) : [normalized];
    const f = await cloudFixture(input);
    const original = await prepareExternalPublication(
      f.file,
      f.options,
      f.deps,
    );
    f.state.failReadback = true;
    await expect(original.publish()).rejects.toBeInstanceOf(
      ExternalPublicationError,
    );
    if (kind === "raw")
      record.repositoryBranch.name = "example/project/changed";
    else normalized.evidence.branch = "changed";
    await writeFile(f.file, JSON.stringify(input));
    const changed = await prepareExternalPublication(f.file, f.options, f.deps);
    expect(changed.preview.resumed).toBe(false);
    expect(changed.preview.requests[0]!.request_id).not.toBe(
      original.preview.requests[0]!.request_id,
    );
    expect(changed.preview.findings[0]!.evidence.branch).toBe(
      kind === "raw" ? "example/project/changed" : "changed",
    );
  },
);

test.each([
  "resume",
  "reset",
  "coverage",
  "rebind",
  "prepend",
  "excluded",
  "qualifier",
])(
  "inventory normalization upgrades saved immutable requests and receipts (%s)",
  async (scenario) => {
    const record = {
      ...sast,
      vendorMetadata: { z: 1, ä: 2 },
      repository: { id: repository.id },
      ...(scenario === "qualifier"
        ? {
            repositoryBranch: {
              ...sast.repositoryBranch,
              name: "project/component/Feature",
            },
          }
        : {}),
    };
    const selected =
      scenario === "coverage"
        ? [
            { ...record, id: "already-ready", repository },
            { ...record, id: "newly-ready" },
          ]
        : scenario === "excluded"
          ? [
              record,
              {
                source_finding_id: "sast:occurrence-1",
                evidence: { title: "Excluded input", severity: "invalid" },
              },
            ]
          : [record];
    const nodes = [
      {
        ...inventoryNode("GITHUB"),
        repository: {
          ...repository,
          name:
            scenario === "qualifier" ? "project/component" : "Example/Project",
          url:
            scenario === "qualifier"
              ? repositoryUrl
              : "https://github.com/Example/Project.git",
        },
      },
      {
        ...inventoryNode("GITHUB"),
        repository: {
          ...repository,
          name:
            scenario === "coverage"
              ? "z".repeat(513)
              : scenario === "qualifier"
                ? "project"
                : repository.name,
          url: repositoryUrl,
        },
      },
    ];
    const payload = {
      data: {
        sastFindings: { nodes: selected },
        versionControlResources: { nodes },
      },
    };
    // The earlier mapper used the last inventory row. This single-row export
    // stages exactly that historical evidence with real publication receipts.
    const f = await cloudFixture({
      data: { ...payload.data, versionControlResources: { nodes: [nodes[1]] } },
    });
    const deps = {
      ...f.deps,
      environment: {
        ...f.environment,
        CODEX_SECURITY_CLOUD_BASE_URL: DEFAULT_CLOUD_BASE_URL,
      },
    };
    // Stage the old branch projection explicitly; new imports retain names.
    const historical = (await readVendorFindingsForPublication(f.file)).legacy;
    expect(historical.findings[0]!.evidence.branch).toBe(
      scenario === "qualifier" ? "component/Feature" : "feature/parser",
    );
    await writeFile(f.file, JSON.stringify(historical.findings));
    const original = await prepareExternalPublication(f.file, f.options, deps);
    f.state.failReadback = true;
    let originalPath = "";
    try {
      await original.publish();
    } catch (error) {
      expect(error).toBeInstanceOf(ExternalPublicationError);
      originalPath = (error as ExternalPublicationError).result
        .savedSubmission!;
    }
    const saved = JSON.parse(await readFile(originalPath, "utf8"));
    delete saved.inputProjection;
    await writeFile(originalPath, JSON.stringify(saved));
    expect(saved.receipts).toHaveLength(1);
    const identity = [
      original.preview.accountId,
      original.preview.destination.id,
      original.preview.destination.repo_connector_id,
      original.preview.source,
      original.preview.findings,
    ];
    const oldKey = legacyCheckpointKey(identity);
    const oldPath = join(
      f.environment.CODEX_SECURITY_STATE_DIR,
      "external-finding-publications",
      `${oldKey}.pending.json`,
    );
    if (oldPath !== originalPath) await rename(originalPath, oldPath);
    await writeFile(f.file, JSON.stringify(payload));
    if (scenario === "coverage") {
      expect((await readVendorFindings(f.file)).findings).toHaveLength(2);
      await expect(
        prepareExternalPublication(f.file, f.options, deps),
      ).rejects.toThrow("selects different findings");
      expect(JSON.parse(await readFile(oldPath, "utf8"))).toEqual(saved);
      expect(f.posts).toHaveLength(1);
      return;
    }
    if (scenario === "reset") {
      f.destination.reset_marker = "generation-2";
      await expect(
        prepareExternalPublication(f.file, f.options, deps),
      ).rejects.toThrow("saved request was retired");
      await expect(readFile(oldPath, "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });
      expect(f.posts).toHaveLength(1);
      return;
    }
    const upgraded = await prepareExternalPublication(f.file, f.options, deps);
    expect(upgraded.preview.resumed).toBe(true);
    expect(upgraded.preview.requests).toEqual(original.preview.requests);
    expect(upgraded.preview.findings).toEqual(original.preview.findings);
    let migratedPath = "";
    try {
      await upgraded.publish();
    } catch (error) {
      expect(error).toBeInstanceOf(ExternalPublicationError);
      migratedPath = (error as ExternalPublicationError).result
        .savedSubmission!;
    }
    const migrated = await readFile(migratedPath, "utf8");
    const migratedData = JSON.parse(migrated);
    expect(migratedData.requests).toEqual(saved.requests);
    expect(migratedData.receipts).toEqual(saved.receipts);
    if (scenario !== "prepend" && scenario !== "excluded") nodes.reverse();
    await writeFile(f.file, JSON.stringify(payload));
    const reordered = await prepareExternalPublication(f.file, f.options, deps);
    expect(reordered.preview.resumed).toBe(true);
    expect(reordered.preview.requests).toEqual(original.preview.requests);
    migratedData.requests[0].items[0].evidence.description =
      "Modified saved evidence";
    await writeFile(migratedPath, JSON.stringify(migratedData));
    await expect(
      prepareExternalPublication(f.file, f.options, deps),
    ).rejects.toThrow("Saved import evidence");
    await writeFile(migratedPath, migrated);
    const incomplete = JSON.parse(migrated);
    delete incomplete.inputProjection.savedEvidenceDigest;
    await writeFile(migratedPath, JSON.stringify(incomplete));
    await expect(
      prepareExternalPublication(f.file, f.options, deps),
    ).rejects.toThrow("Saved import evidence");
    await writeFile(migratedPath, migrated);
    let replay = reordered;
    if (["rebind", "prepend", "excluded"].includes(scenario)) {
      nodes.unshift({
        ...nodes[1]!,
        repository: { ...nodes[1]!.repository, name: "EXAMPLE/PROJECT" },
      });
      await writeFile(f.file, JSON.stringify(payload));
      replay = await prepareExternalPublication(f.file, f.options, deps);
      expect(replay.preview.resumed).toBe(true);
      expect(replay.preview.requests).toEqual(original.preview.requests);
      expect(replay.preview.findings).toEqual(original.preview.findings);
    }
    const newer = f.reports.get("sast:occurrence-1")!;
    newer.version += 1;
    newer.evidence.description = "Newer Cloud evidence";
    f.state.failReadback = false;
    expect((await replay.publish()).verified).toBe(1);
    expect(f.posts).toHaveLength(1);
    expect(f.reports.get("sast:occurrence-1")!.evidence.description).toBe(
      "Newer Cloud evidence",
    );
  },
);

test.each([
  ["GITHUB", "GITLAB"],
  ["GITLAB", "GITHUB"],
])("inventory platform conflicts reject %s before %s", async (first, last) => {
  await expect(
    parse({
      data: {
        sastFindings: { nodes: [sast] },
        versionControlResources: {
          nodes: [first, undefined, last].map((platform) =>
            inventoryNode(platform),
          ),
        },
      },
    }),
  ).rejects.toThrow("conflicting platforms");
});

test.each([undefined, "GITLAB"])(
  "inventory duplicate URLs stay strict without GITHUB provenance: %j",
  async (platform) => {
    await expect(
      parse({
        data: {
          sastFindings: { nodes: [sast] },
          versionControlResources: {
            nodes: [
              inventoryNode(
                platform,
                "https://github.example.test/Example/Project",
              ),
              inventoryNode(platform),
            ],
          },
        },
      }),
    ).rejects.toThrow("conflicting URLs");
  },
);

test("GITHUB inventory provenance does not permit a different repository URL", async () => {
  await expect(
    parse({
      data: {
        sastFindings: { nodes: [sast] },
        versionControlResources: {
          nodes: [
            inventoryNode("GITHUB"),
            inventoryNode(
              "GITHUB",
              "https://github.example.test/example/other",
            ),
          ],
        },
      },
    }),
  ).rejects.toThrow("conflicting URLs");
});
test("concurrent legacy inventory resumers retain the acknowledged request after migration finishes", async () => {
  const name =
    "concurrent legacy inventory resumers retain the acknowledged request after migration finishes";
  const { runTestInSubprocess } = await import("./support/test-subprocess.js");
  if (runTestInSubprocess(import.meta.filename, name)) return;
  const fs = await import("node:fs/promises");
  const { spyOn } = await import("bun:test");
  const record = { ...sast, repository: { id: repository.id } };
  const nodes = [
    {
      ...inventoryNode("GITHUB"),
      repository: {
        ...repository,
        name: "Example/Project",
        url: "https://github.com/Example/Project.git",
      },
    },
    {
      ...inventoryNode("GITHUB"),
      repository: { ...repository, url: repositoryUrl },
    },
  ];
  const payload = {
    data: {
      sastFindings: { nodes: [record] },
      versionControlResources: { nodes },
    },
  };
  const f = await cloudFixture({
    data: { ...payload.data, versionControlResources: { nodes: [nodes[1]] } },
  });
  const deps = {
    ...f.deps,
    environment: {
      ...f.environment,
      CODEX_SECURITY_CLOUD_BASE_URL: DEFAULT_CLOUD_BASE_URL,
    },
  };
  const historical = await readVendorFindingsForPublication(f.file);
  await writeFile(f.file, JSON.stringify(historical.legacy.findings));
  const original = await prepareExternalPublication(f.file, f.options, deps);
  f.state.failReadback = true;
  let originalPath = "";
  try {
    await original.publish();
  } catch (error) {
    expect(error).toBeInstanceOf(ExternalPublicationError);
    originalPath = (error as ExternalPublicationError).result.savedSubmission!;
  }
  const saved = JSON.parse(await readFile(originalPath, "utf8"));
  expect(saved.receipts).toHaveLength(1);
  const identity = [
    original.preview.accountId,
    original.preview.destination.id,
    original.preview.destination.repo_connector_id,
    original.preview.source,
  ];
  const encode = (value: unknown) =>
    JSON.stringify(value, (_key, child) =>
      child !== null && typeof child === "object" && !Array.isArray(child)
        ? Object.fromEntries(
            Object.keys(child)
              .sort()
              .map((key) => [key, child[key]]),
          )
        : child,
    );
  const directory = join(
    f.environment.CODEX_SECURITY_STATE_DIR,
    "external-finding-publications",
  );
  saved.inputProjection.inputDigest = hash(
    "sha256",
    encode(historical.legacyIdentity),
  );
  await writeFile(originalPath, JSON.stringify(saved));
  const oldKey = legacyCheckpointKey([...identity, original.preview.findings]);
  const oldPath = join(directory, `${oldKey}.pending.json`);
  if (oldPath !== originalPath) await rename(originalPath, oldPath);
  await writeFile(f.file, JSON.stringify(payload));
  const { currentIdentity } = await readVendorFindingsForPublication(f.file);
  const key = hash("sha256", encode([...identity, currentIdentity]));
  const pendingPath = join(directory, `${key}.pending.json`);
  const lockPath = join(directory, `${key}.lock.sqlite`);
  expect(pendingPath).not.toBe(oldPath);
  const firstAtLock = Promise.withResolvers<void>();
  const secondAtLock = Promise.withResolvers<void>();
  const releaseSecond = Promise.withResolvers<void>();
  const originalLstat = fs.lstat;
  let lockEntries = 0;
  const metadata = spyOn(fs, "lstat").mockImplementation((async (
    ...args: Parameters<typeof fs.lstat>
  ) => {
    if (String(args[0]) === lockPath) {
      lockEntries += 1;
      if (lockEntries === 1) {
        firstAtLock.resolve();
        await secondAtLock.promise;
      } else if (lockEntries === 2) {
        secondAtLock.resolve();
        await releaseSecond.promise;
      }
    }
    return await originalLstat(...args);
  }) as typeof fs.lstat);
  let first: ReturnType<typeof prepareExternalPublication> | undefined;
  let second: ReturnType<typeof prepareExternalPublication> | undefined;
  try {
    first = prepareExternalPublication(f.file, f.options, deps);
    await firstAtLock.promise;
    second = prepareExternalPublication(f.file, f.options, deps);
    await secondAtLock.promise;
    const leading = await first;
    expect(leading.preview.resumed).toBe(true);
    expect(leading.preview.requests).toEqual(saved.requests);
    expect(JSON.parse(await readFile(pendingPath, "utf8")).receipts).toEqual(
      saved.receipts,
    );
    f.state.failReadback = false;
    expect((await leading.publish()).verified).toBe(1);
    await expect(readFile(pendingPath, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(readFile(oldPath, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
    const newer = structuredClone(f.reports.get("sast:occurrence-1")!);
    newer.version += 1;
    newer.evidence.description =
      "Newer Cloud evidence after the first resumer completed";
    f.reports.set("sast:occurrence-1", newer);
    releaseSecond.resolve();
    const trailing = await second;
    const result = await trailing.publish();
    expect(f.posts).toHaveLength(1);
    expect(trailing.preview.resumed).toBe(true);
    expect(trailing.preview.requests).toEqual(saved.requests);
    expect(result.receipts).toEqual(saved.receipts);
    expect(result.verified).toBe(1);
    expect(f.reports.get("sast:occurrence-1")).toEqual(newer);
  } finally {
    secondAtLock.resolve();
    releaseSecond.resolve();
    await Promise.allSettled(
      [first, second].filter((value) => value !== undefined),
    );
    metadata.mockRestore();
  }
});

test("resume preview is derived from the saved upload evidence", async () => {
  const payload = {
    data: {
      sastFindings: { nodes: [{ ...sast, repository: { id: repository.id } }] },
      versionControlResources: {
        nodes: [
          {
            ...inventoryNode("GITHUB"),
            repository: {
              ...repository,
              url: repositoryUrl,
              name: "original-display-name",
            },
          },
        ],
      },
    },
  };
  const f = await cloudFixture(payload);
  const original = await prepareExternalPublication(f.file, f.options, f.deps);
  f.state.failReadback = true;
  await expect(original.publish()).rejects.toThrow("Readback unavailable");
  payload.data.versionControlResources.nodes[0]!.repository.name =
    "updated-display-name";
  await writeFile(f.file, JSON.stringify(payload));
  const resumed = await prepareExternalPublication(f.file, f.options, f.deps);
  expect(resumed.preview.resumed).toBe(true);
  expect(resumed.preview.requests).toEqual(original.preview.requests);
  expect(resumed.preview.findings[0]!.evidence).toEqual(
    resumed.preview.requests[0]!.items[0]!.evidence,
  );
});
