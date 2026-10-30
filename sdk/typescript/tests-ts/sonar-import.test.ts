import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { prepareSonarImport } from "../src/sonar-import.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

const repositoryUrl = "https://github.com/example/project";

async function fixture(root: string) {
  const checkout = join(root, "checkout");
  await mkdir(checkout);
  execFileSync("git", ["-C", checkout, "init", "--quiet"]);
  execFileSync("git", [
    "-C",
    checkout,
    "remote",
    "add",
    "origin",
    repositoryUrl,
  ]);
  const capture = join(checkout, "report.json");
  const report = {
    format: "sonar-issues/v1",
    server: "https://sonarcloud.io",
    organization: "example",
    project: "example_project",
    branch: "main",
    repositoryUrl,
    pages: [
      {
        paging: { pageIndex: 1, pageSize: 100, total: 1 },
        issues: [
          {
            key: "issue-1",
            project: "example_project",
            component: "example_project:service.ts",
            rule: "example:R1",
            type: "VULNERABILITY",
            severity: "CRITICAL",
            message: "Reviewed evidence",
          },
        ],
      },
    ],
  };
  await writeFile(capture, JSON.stringify(report));
  return {
    report,
    options: {
      cwd: checkout,
      capture,
      issueKeys: [],
      dryRun: true,
      yes: false,
    },
    deps: {
      environment: {
        ...process.env,
        CODEX_HOME: join(root, "codex"),
        CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
        CODEX_SECURITY_STATE_DIR: join(root, "state"),
      },
    },
  };
}

test("preview snapshots caller-owned evidence and rejects changes to the retained copy", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-preview-");
  const { report, options, deps } = await fixture(directory.path);
  const selection = { ...options, to: "local" } as const;
  const { info } = await prepareSonarImport(selection, deps);
  expect(info.capture).not.toBe(options.capture);
  report.pages[0]!.issues[0]!.message = "Changed evidence";
  await writeFile(options.capture, JSON.stringify(report));
  const replay = await prepareSonarImport(
    { ...selection, capture: info.capture },
    deps,
  );
  expect(replay.local.findings[0]!.evidence.description).toBe(
    "Reviewed evidence",
  );
  const changed = await prepareSonarImport(selection, deps);
  expect(changed.info.capture).not.toBe(info.capture);
  await copyFile(options.capture, info.capture);
  await expect(
    prepareSonarImport({ ...selection, capture: info.capture }, deps),
  ).rejects.toThrow("saved Sonar capture has changed");
});

test("Cloud confirmation verifies the retained evidence, account and assigned environment", async () => {
  await using directory = await scopedTemporaryDirectory(
    "sonar-cloud-preview-",
  );
  const f = await fixture(directory.path);
  let account = "account-a";
  let environmentId = "env-a";
  const selection = { ...f.options, to: "cloud" } as const;
  const deps = {
    ...f.deps,
    credentials: async () => ({
      account_id: account,
      access_token: "synthetic",
    }),
    fetch: async (url: string, options: RequestInit) => {
      expect(options.method ?? "GET").toBe("GET");
      const repositories = new URL(url).pathname.endsWith("/repositories");
      return Response.json({
        object: "page",
        has_more: false,
        next: null,
        data: repositories
          ? [
              {
                id: "repo-a",
                repo_connector_id: "github",
                url: repositoryUrl,
                import_environment_id: environmentId,
                reset_marker: "generation-1",
              },
            ]
          : [],
      });
    },
  };
  const preview = await prepareSonarImport(selection, deps);
  expect(preview.cloudError).toBeUndefined();
  const confirm = {
    ...selection,
    capture: preview.info.capture,
    yes: true,
    dryRun: false,
  };
  expect((await prepareSonarImport(confirm, deps)).cloud).toBeDefined();
  const copy = join(selection.cwd, basename(confirm.capture));
  await copyFile(confirm.capture, copy);
  expect(
    (await prepareSonarImport({ ...confirm, capture: copy }, deps)).cloudError,
  ).toContain("--to cloud --dry-run");
  account = "account-b";
  expect((await prepareSonarImport(confirm, deps)).cloudError).toContain(
    "--to cloud --dry-run",
  );
  const alternate = await prepareSonarImport(selection, deps);
  expect(alternate.info.capture).not.toBe(preview.info.capture);
  account = "account-a";
  environmentId = "env-b";
  expect((await prepareSonarImport(confirm, deps)).cloudError).toContain(
    "--to cloud --dry-run",
  );
  environmentId = "env-a";
  expect((await prepareSonarImport(confirm, deps)).cloud).toBeDefined();
  expect(await readFile(preview.info.capture, "utf8")).toBe(
    await readFile(alternate.info.capture, "utf8"),
  );
});

test("a clean Sonar project needs no Cloud credentials or upload", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-clean-");
  const { report, options, deps } = await fixture(directory.path);
  report.pages[0]!.issues = [];
  report.pages[0]!.paging.total = 0;
  await writeFile(options.capture, JSON.stringify(report));
  let cloudCalls = 0;
  const unexpectedCloudCall = async (): Promise<never> => {
    cloudCalls++;
    throw new Error("Unexpected Cloud call");
  };
  const prepared = await prepareSonarImport(
    { ...options, to: "cloud", dryRun: false, yes: true },
    { ...deps, credentials: unexpectedCloudCall, fetch: unexpectedCloudCall },
  );
  const result = await prepared.import();
  expect(result.cloudError).toBeUndefined();
  expect(result.cloud).toBeUndefined();
  expect(result.local.ready).toBe(0);
  expect(cloudCalls).toBe(0);
});
