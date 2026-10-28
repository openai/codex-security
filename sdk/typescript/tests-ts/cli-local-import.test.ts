import { execFileSync } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  dependencies as cliDependencies,
  FakeSignals,
} from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { opengrepJson } from "./support/opengrep-import-fixtures.js";

const dependencies: typeof cliDependencies = (options = {}) => {
  const result = cliDependencies(options);
  return {
    ...result,
    environment: {
      ...result.environment,
      CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
    },
  };
};

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "local-import-cli-")),
  );
  roots.push(root);
  const repository = join(root, "example project");
  await mkdir(repository);
  execFileSync("git", ["init", "--quiet", repository]);
  execFileSync("git", [
    "-C",
    repository,
    "remote",
    "add",
    "origin",
    "https://github.com/example/project.git",
  ]);
  const file = join(root, "selected.json");
  const record = {
    id: "vendor-finding-1",
    name: "CVE-2026-0001",
    detailedName: "example-package",
    vendorSeverity: "HIGH",
    version: "1.2.3",
    fixedVersion: "1.2.4",
    locationPath: "/package-lock.json",
    vulnerableAsset: {
      id: "repository-branch-1",
      nativeType: "github#repositoryBranch",
      name: "example/project/main",
      cloudProviderURL: "https://github.com/example/project/tree/main",
    },
  };
  await writeFile(file, JSON.stringify([record]));
  const state = join(root, "state");
  const deps = {
    ...dependencies({
      currentDirectory: root,
      environment: {
        ...process.env,
        HOME: join(root, "home"),
        USERPROFILE: join(root, "home"),
        CODEX_HOME: join(root, "codex"),
        CODEX_SECURITY_STATE_DIR: state,
        CODEX_SECURITY_CLOUD_BASE_URL: "invalid-cloud-url",
      },
      onConfig: () => {
        throw new Error("Local imports must not initialize a model client");
      },
      onCodex: () => {
        throw new Error("Local imports must not invoke Codex or sign in");
      },
    }),
    cloudFetch: async () => {
      throw new Error("Local imports must not call Cloud");
    },
  };
  const command = [
    "publish",
    "findings",
    "selected.json",
    "--to",
    "local",
    "--repository",
    "example project",
    "--provider",
    "wiz",
    "--source-key",
    "tenant-example/vulnerability-finding",
    "--format",
    "json",
  ];
  return { root, repository, file, record, state, deps, command };
}

test("local preview and declined confirmation do not create database state or use Cloud", async () => {
  const f = await fixture();
  const preview = createCliTest(main);
  expect(await preview.runCli([...f.command, "--dry-run"], f.deps)).toBe(0);
  expect(preview.stderr.text()).toBe("");
  expect(JSON.parse(preview.stdout.text())).toMatchObject({
    dryRun: true,
    repository: f.repository,
    source: {
      provider: "wiz",
      source_key: "tenant-example/vulnerability-finding",
    },
    read: 1,
    findings: [
      { source_finding_id: f.record.id, evidence: { source_data: f.record } },
    ],
  });
  const declined = createCliTest(main);
  expect(
    await declined.runCli(f.command, {
      ...f.deps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async (question, defaultValue) => {
          expect(question).toContain("Store these 1 findings locally");
          expect(defaultValue).toBe(false);
          expect(declined.stderr.text()).toContain(f.repository);
          expect(declined.stderr.text()).toContain(f.record.id);
          expect(declined.stderr.text()).toContain("not assessed by Codex");
          return false;
        },
      },
    }),
  ).toBe(0);
  expect(JSON.parse(declined.stdout.text()).imported).toBe(false);
  const headless = createCliTest(main);
  expect(await headless.runCli(f.command, f.deps)).toBe(2);
  expect(headless.stderr.text()).toContain("needs confirmation");
  expect(await readdir(f.state).catch(() => [])).toEqual([]);
});

test("CLI imports a vendor report, reads local evidence, and updates the same source record", async () => {
  const f = await fixture();
  const first = createCliTest(main);
  expect(await first.runCli([...f.command, "--yes"], f.deps)).toBe(0);
  const imported = JSON.parse(first.stdout.text());
  expect(imported.counts).toEqual({ created: 1, updated: 0, unchanged: 0 });
  expect(imported.findings[0]).toMatchObject({
    repository: f.repository,
    provider: "wiz",
    sourceFindingId: f.record.id,
    version: 1,
    assessment: { state: "not_assessed" },
    evidence: { severity: "high", source_data: f.record },
  });
  const repeated = createCliTest(main);
  expect(await repeated.runCli([...f.command, "--yes"], f.deps)).toBe(0);
  expect(JSON.parse(repeated.stdout.text()).counts).toEqual({
    created: 0,
    updated: 0,
    unchanged: 1,
  });
  await writeFile(
    f.file,
    JSON.stringify([{ ...f.record, vendorSeverity: "CRITICAL" }]),
  );
  const updated = createCliTest(main);
  expect(await updated.runCli([...f.command, "--yes"], f.deps)).toBe(0);
  expect(JSON.parse(updated.stdout.text()).counts).toEqual({
    created: 0,
    updated: 1,
    unchanged: 0,
  });
  const readback = createCliTest(main);
  expect(
    await readback.runCli(["findings", "imported", "--format", "json"], {
      ...f.deps,
      currentDirectory: () => f.repository,
    }),
  ).toBe(0);
  const result = JSON.parse(readback.stdout.text());
  expect(result.repository).toBe(f.repository);
  expect(result.findings).toHaveLength(1);
  expect(result.findings[0]).toMatchObject({
    id: imported.findings[0].id,
    version: 2,
    assessment: { state: "not_assessed" },
    evidence: { severity: "critical" },
  });
  expect(result.findings[0].evidence.code_revision).toBeNull();
  expect(result.findings[0].evidence.confidence).toBeUndefined();
});

test("CLI imports OpenGrep evidence locally without assessing it", async () => {
  const f = await fixture();
  const report = opengrepJson();
  await writeFile(f.file, JSON.stringify(report));
  const sourceRepositoryUrl = "https://github.com/example/project";
  const imported = createCliTest(main);
  expect(
    await imported.runCli(
      [
        "publish",
        "findings",
        "selected.json",
        "--to",
        "local",
        "--repository",
        "example project",
        "--provider",
        "opengrep",
        "--source-repository-url",
        sourceRepositoryUrl,
        "--source-key",
        "example/opengrep",
        "--yes",
        "--format",
        "json",
      ],
      f.deps,
    ),
  ).toBe(0);
  const result = JSON.parse(imported.stdout.text());
  expect(result.report.errors).toEqual(report.errors);
  expect(result.counts).toEqual({
    created: 1,
    updated: 0,
    unchanged: 0,
  });
  const readback = createCliTest(main);
  expect(
    await readback.runCli(
      ["findings", "imported", "example project", "--format", "json"],
      f.deps,
    ),
  ).toBe(0);
  const findings = JSON.parse(readback.stdout.text()).findings;
  expect(findings).toHaveLength(1);
  expect(findings[0]).toMatchObject({
    provider: "semgrep",
    assessment: { state: "not_assessed" },
    evidence: {
      severity: "unknown",
      details: {
        scanner_origin: "OpenGrep",
        repository: { url: sourceRepositoryUrl },
      },
      source_data: {
        report: {
          version: report.version,
        },
        scan_error_count: report.errors.length,
        results: report.results,
      },
    },
  });
});

test("local import confirms exclusions and returns partial status after storing ready records", async () => {
  const f = await fixture();
  await writeFile(
    f.file,
    JSON.stringify([
      f.record,
      { ...f.record, id: "unsupported", vendorSeverity: "not-a-severity" },
    ]),
  );
  const cli = createCliTest(main);
  expect(
    await cli.runCli(f.command, {
      ...f.deps,
      externalPublicationPrompt: {
        isInteractive: () => true,
        confirm: async (question) => {
          expect(question).toContain("skip 1 excluded records");
          expect(cli.stderr.text()).toContain("Excluded: 1");
          return true;
        },
      },
    }),
  ).toBe(1);
  expect(JSON.parse(cli.stdout.text())).toMatchObject({
    read: 2,
    ready: 1,
    counts: { created: 1 },
  });
});

test.each(["SIGINT", "SIGTERM"] as const)(
  "local import forwards %s cancellation without storing findings",
  async (signalName) => {
    const signals = new FakeSignals();
    const deps = dependencies({
      signals,
      currentDirectory: resolve("workspace"),
    });
    const cli = createCliTest(main);
    let imports = 0;
    deps.prepareLocalExternalImport = async (file, options, settings) => {
      expect(file).toBe(resolve("workspace", "selected.json"));
      expect(options.repository).toBe(resolve("workspace", "project"));
      expect(settings?.environment).toBe(deps.environment);
      signals.emit(signalName);
      settings?.signal?.throwIfAborted();
      imports += 1;
      throw new Error("Import should have been canceled");
    };
    expect(
      await cli.runCli(
        [
          "publish",
          "findings",
          "selected.json",
          "--to",
          "local",
          "--repository",
          "project",
          "--provider",
          "wiz",
          "--source-key",
          "tenant-example/findings",
          "--yes",
          "--format",
          "json",
        ],
        deps,
      ),
    ).toBe(signalName === "SIGINT" ? 130 : 143);
    expect(imports).toBe(0);
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  },
);

test("imported readback resolves its repository argument and supports structured output", async () => {
  const deps = dependencies({ currentDirectory: resolve("workspace") });
  deps.listLocalExternalFindings = async ({ repository }, settings) => {
    expect(repository).toBe(resolve("workspace", "project"));
    expect(settings?.environment).toBe(deps.environment);
    expect(settings?.signal?.aborted).toBe(false);
    return [];
  };
  const cli = createCliTest(main);
  expect(
    await cli.runCli(
      ["findings", "imported", "project", "--format", "json"],
      deps,
    ),
  ).toBe(0);
  expect(JSON.parse(cli.stdout.text())).toEqual({
    repository: resolve("workspace", "project"),
    findings: [],
  });
});

for (const format of ["json", "jsonl"] as const) {
  test.each(["SIGINT", "SIGTERM"] as const)(
    `imported readback reports %s cancellation in ${format} full output`,
    async (signalName) => {
      const signals = new FakeSignals();
      const deps = dependencies({
        signals,
        currentDirectory: resolve("workspace"),
      });
      deps.listLocalExternalFindings = async (_selection, settings) => {
        expect(settings?.signal).toBeDefined();
        signals.emit(signalName);
        settings!.signal!.throwIfAborted();
        throw new Error("Readback should have been canceled");
      };
      const cli = createCliTest(main);
      expect(
        await cli.runCli(
          ["findings", "imported", "--format", format, "--full-output"],
          deps,
        ),
      ).toBe(signalName === "SIGINT" ? 130 : 143);
      expect(JSON.parse(cli.stdout.text())).toMatchObject({
        ok: false,
        error: { code: "FINDINGS_READ_FAILED", message: signalName },
      });
      expect(cli.stderr.text()).toBe("");
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    },
  );
}

test("finding import requires an explicit destination and advertises local repository paths", async () => {
  const cli = createCliTest(main);
  expect(
    await cli.runCli(["publish", "findings", "--help"], dependencies()),
  ).toBe(0);
  expect(cli.stdout.text()).toContain("local");
  expect(cli.stdout.text()).toContain("Local repository path");
  const missing = createCliTest(main);
  expect(
    await missing.runCli(
      [
        "publish",
        "findings",
        "selected.json",
        "--repository",
        "project",
        "--provider",
        "wiz",
        "--source-key",
        "tenant-example/findings",
        "--dry-run",
      ],
      dependencies(),
    ),
  ).not.toBe(0);
  expect(missing.stderr.text()).toContain("to");
});
