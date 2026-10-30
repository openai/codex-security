import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  chmod,
  copyFile,
  mkdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { prepareSonarImport } from "../src/sonar-import.js";
import { prepareLocalExternalImport } from "../src/external-findings-import.js";
import { prepareNormalizedLocalImport } from "../src/external-findings-local.js";
import { normalizeSonarFindings } from "../src/sonar-findings.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";
import { sonarGitTestEnvironment } from "./support/sonar-import-fixtures.js";

const repositoryUrl = "https://github.com/example/project";

async function fixture(root: string, name = "checkout") {
  const checkout = join(root, name);
  const environment = {
    ...sonarGitTestEnvironment(),
    CODEX_HOME: join(root, "codex"),
    CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
    CODEX_SECURITY_STATE_DIR: join(root, "state"),
  };
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", checkout, ...args], { env: environment });
  await mkdir(checkout);
  git("init", "--quiet");
  git("remote", "add", "origin", repositoryUrl);
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
    git,
    report,
    options: {
      cwd: checkout,
      capture,
      issueKeys: [],
      dryRun: true,
      yes: false,
    },
    deps: { environment },
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
  const alias = join(directory.path, "capture-alias");
  await symlink(dirname(info.capture), alias, "junction");
  await copyFile(options.capture, info.capture);
  await expect(
    prepareSonarImport(
      { ...selection, capture: join(alias, basename(info.capture)) },
      deps,
    ),
  ).rejects.toThrow("saved Sonar capture has changed");
  if (process.platform !== "win32") {
    await rm(info.capture);
    await symlink(changed.info.capture, info.capture);
    await expect(
      prepareSonarImport(
        { ...selection, capture: info.capture, yes: true, dryRun: false },
        deps,
      ),
    ).rejects.toThrow("saved Sonar capture has changed");
  }
});

test("confirming a local preview in another checkout requires previewing that checkout", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-local-review-");
  const first = await fixture(directory.path);
  const second = await fixture(directory.path, "second-checkout");
  const previewOptions = {
    ...first.options,
    to: "local",
    dryRun: true,
  } as const;
  const preview = await prepareSonarImport(previewOptions, first.deps);
  const alias = join(directory.path, "capture-alias");
  await symlink(dirname(preview.info.capture), alias, "junction");
  const moved = {
    ...previewOptions,
    cwd: second.options.cwd,
    capture: join(alias, basename(preview.info.capture)),
  };
  await expect(
    prepareSonarImport({ ...moved, yes: true, dryRun: false }, first.deps),
  ).rejects.toThrow("has not been reviewed for this checkout");
  const newState = {
    environment: {
      ...second.deps.environment,
      CODEX_SECURITY_STATE_DIR: join(directory.path, "other-state"),
    },
  };
  await expect(
    prepareSonarImport(
      {
        ...previewOptions,
        capture: preview.info.capture,
        yes: true,
        dryRun: false,
      },
      newState,
    ),
  ).rejects.toThrow("has not been reviewed for this checkout");
  const renewed = await prepareSonarImport(moved, first.deps);
  expect(renewed.info.capture).not.toBe(preview.info.capture);
  const confirmed = await prepareSonarImport(
    { ...moved, capture: renewed.info.capture, yes: true, dryRun: false },
    first.deps,
  );
  expect((await confirmed.import()).local.counts.created).toBe(1);
});

test("a portable capture supports interactive review but requires the returned local preview path with --yes", async () => {
  await using directory = await scopedTemporaryDirectory(
    "sonar-portable-replay-",
  );
  const { options, deps } = await fixture(directory.path);
  const selection = { ...options, to: "local", dryRun: false } as const;
  await expect(
    prepareSonarImport({ ...selection, yes: true }, deps),
  ).rejects.toThrow("has not been reviewed for this checkout");
  const interactive = await prepareSonarImport(selection, deps);
  expect(interactive.local.findings).toHaveLength(1);
  expect(interactive.info.capture).not.toBe(options.capture);
  const callerPath = join(directory.path, "reviewed");
  await symlink(dirname(interactive.info.capture), callerPath, "junction");
  const confirmed = await prepareSonarImport(
    {
      ...selection,
      yes: true,
      capture: join(callerPath, basename(interactive.info.capture)),
    },
    deps,
  );
  expect(confirmed.info.capture).toBe(interactive.info.capture);
});

test("live import passes the expected repository to the collector before saving evidence", async () => {
  await using directory = await scopedTemporaryDirectory(
    "sonar-expected-source-",
  );
  const { options, deps } = await fixture(directory.path);
  let source: string | undefined;
  await expect(
    prepareSonarImport(
      {
        ...options,
        capture: undefined,
        to: "local",
        sourceRepositoryUrl: repositoryUrl,
      },
      {
        ...deps,
        collect: async (selection) => {
          source = selection.sourceRepositoryUrl;
          throw new Error("Conflicting Sonar binding");
        },
      },
    ),
  ).rejects.toThrow("Conflicting Sonar binding");
  expect(source).toBe(repositoryUrl);
  expect(
    await stat(deps.environment.CODEX_SECURITY_STATE_DIR).catch(() => null),
  ).toBeNull();
});

test("Cloud confirmation verifies the retained evidence, account and assigned environment", async () => {
  await using directory = await scopedTemporaryDirectory(
    "sonar-cloud-preview-",
  );
  const f = await fixture(directory.path);
  let account = "account-a";
  let environmentId = "env-a";
  let reportVersion = 0;
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
          : reportVersion
            ? [
                {
                  id: `aif_${"a".repeat(64)}`,
                  repo_id: "repo-a",
                  repo_connector_id: "github",
                  environment_id: environmentId,
                  canonical_finding_id: `acf_${"b".repeat(32)}`,
                  source: {
                    provider: "sonar",
                    source_key: new URL(url).searchParams.get("source_key"),
                  },
                  source_finding_id: "issue-1",
                  observation_id: `aio_${"c".repeat(64)}`,
                  version: reportVersion,
                  title: "Reviewed evidence",
                  severity: "high",
                  source_updated_at: null,
                  created_at: 1,
                  updated_at: 2,
                },
              ]
            : [],
      });
    },
  };
  const preview = await prepareSonarImport(selection, deps);
  expect(preview.cloudError).toBeUndefined();
  const alias = join(directory.path, "cloud-capture-alias");
  await symlink(dirname(preview.info.capture), alias, "junction");
  const confirm = {
    ...selection,
    capture: join(alias, basename(preview.info.capture)),
    yes: true,
    dryRun: false,
  };
  expect((await prepareSonarImport(confirm, deps)).cloud).toBeDefined();
  reportVersion = 1;
  expect((await prepareSonarImport(confirm, deps)).cloudError).toContain(
    "--to cloud --dry-run",
  );
  reportVersion = 0;
  const copy = join(selection.cwd, basename(confirm.capture));
  await copyFile(confirm.capture, copy);
  await expect(
    prepareSonarImport({ ...confirm, capture: copy }, deps),
  ).rejects.toThrow("--to cloud --dry-run");
  const second = await fixture(directory.path, "second");
  await expect(
    prepareSonarImport({ ...confirm, cwd: second.options.cwd }, deps),
  ).rejects.toThrow("--to cloud --dry-run");
  account = "account-b";
  expect((await prepareSonarImport(confirm, deps)).cloudError).toContain(
    "--to cloud --dry-run",
  );
  const alternate = await prepareSonarImport(selection, deps);
  expect(alternate.info.capture).not.toBe(preview.info.capture);
  if (process.platform !== "win32") {
    const outsideAlias = join(selection.cwd, basename(preview.info.capture));
    await rm(outsideAlias);
    await symlink(alternate.info.capture, outsideAlias);
    await expect(
      prepareSonarImport({ ...confirm, capture: outsideAlias }, deps),
    ).rejects.toThrow("--to cloud --dry-run");

    // Replacing the reviewed entry itself cannot select a different account's approval.
    await rm(preview.info.capture);
    await symlink(alternate.info.capture, preview.info.capture);
    expect((await prepareSonarImport(confirm, deps)).cloudError).toContain(
      "--to cloud --dry-run",
    );
  }
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
  f.git("remote", "set-url", "origin", "git@work:example/project.git");
  const manual = await prepareSonarImport(
    { ...selection, sourceRepositoryUrl: repositoryUrl },
    deps,
  );
  expect(
    (
      await prepareSonarImport(
        { ...confirm, capture: manual.info.capture },
        deps,
      )
    ).cloud,
  ).toBeDefined();
});

test("only an explicit Sonar source can map a checkout's SSH alias", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-ssh-alias-");
  const { git, report, options, deps } = await fixture(directory.path);
  git(
    "remote",
    "set-url",
    "origin",
    "https://git.example.invalid/example/project.git",
  );
  git(
    "remote",
    "add",
    "upstream",
    "git@git.example.invalid:example/project.git",
  );
  const selected = { ...options, to: "local" } as const;
  const source = {
    repository: options.cwd,
    provider: "sonar",
    sourceKey: "example",
  } as const;
  const normalized = normalizeSonarFindings(report, "", "local");
  const mismatch = "does not match a configured remote";
  await expect(
    prepareNormalizedLocalImport(normalized, source, deps),
  ).rejects.toThrow(mismatch);
  await expect(
    prepareLocalExternalImport(options.capture, source, deps),
  ).rejects.toThrow(mismatch);
  const manual = { ...source, sourceRepositoryUrl: repositoryUrl };
  expect(
    (await prepareLocalExternalImport(options.capture, manual, deps))
      .matchesRepositoryRemote,
  ).toBe(false);
  const captures: string[] = [];
  await expect(
    prepareSonarImport(selected, {
      ...deps,
      onCapture: (path) => captures.push(path),
    }),
  ).rejects.toThrow(mismatch);
  expect(captures).toHaveLength(1);
  await expect(
    prepareSonarImport({ ...selected, capture: captures[0] }, deps),
  ).rejects.toThrow(mismatch);
  const preview = await prepareSonarImport(
    { ...selected, capture: captures[0], sourceRepositoryUrl: repositoryUrl },
    deps,
  );
  expect(preview.info.capture).not.toBe(captures[0]);
  const replay = await prepareSonarImport(
    { ...selected, capture: preview.info.capture, dryRun: false, yes: true },
    deps,
  );
  expect(replay.info.capture).toBe(preview.info.capture);
  expect(replay.local.read).toBe(1);
});

test("replays a manually bound capture using the native branch as its identity", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-binding-");
  const { report, options, deps } = await fixture(directory.path);
  const { branch, repositoryUrl: url, ...unbound } = report;
  Object.assign(unbound.pages[0]!.issues[0]!, { branch });
  await writeFile(options.capture, JSON.stringify(unbound));
  const selected = { ...options, to: "local" } as const;
  const mapped = await prepareSonarImport(
    { ...selected, sourceRepositoryUrl: url },
    deps,
  );
  const replay = await prepareSonarImport(
    { ...selected, capture: mapped.info.capture },
    deps,
  );
  await writeFile(options.capture, JSON.stringify(report));
  const bound = await prepareSonarImport(selected, deps);
  expect(replay.info.capture).toBe(mapped.info.capture);
  expect(replay.info.branch).toBe(branch);
  expect(replay.info.sourceKey).toBe(bound.info.sourceKey);
});

test("a dry run cannot create the capture directory inside a checkout or its linked Git metadata", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-protected-");
  const { options, deps, git } = await fixture(directory.path, "imports");
  const selected = { ...options, to: "local" } as const;
  deps.environment.CODEX_SECURITY_STATE_DIR = directory.path;
  await expect(prepareSonarImport(selected, deps)).rejects.toThrow();
  expect(
    await stat(join(directory.path, "imports", "sonar")).catch(() => null),
  ).toBeNull();

  const other = join(directory.path, "linked");
  git(
    "-c",
    "user.name=Example",
    "-c",
    "user.email=example@example.com",
    "commit",
    "--quiet",
    "--allow-empty",
    "-m",
    "initial",
  );
  git("worktree", "add", "--quiet", "--detach", other);
  const state = join(options.cwd, ".git", "state");
  deps.environment.CODEX_SECURITY_STATE_DIR = state;
  await expect(
    prepareSonarImport({ ...selected, cwd: other }, deps),
  ).rejects.toThrow();
  expect(await stat(state).catch(() => null)).toBeNull();
});

test("rejects a Cloud checkpoint directory inside the checkout before contacting Cloud", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-checkpoints-");
  const { options, deps } = await fixture(
    directory.path,
    "external-finding-publications",
  );
  deps.environment.CODEX_SECURITY_STATE_DIR = directory.path;
  const result = await prepareSonarImport(
    { ...options, to: "cloud" },
    {
      ...deps,
      credentials: async () => {
        throw new Error("Unexpected Cloud call");
      },
    },
  );
  expect(result.cloudError).toContain(options.cwd);
  expect(result.cloud).toBeUndefined();
});

test("rejects an in-checkout state symlink pointing to an outside directory", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-state-link-");
  const { options, deps } = await fixture(directory.path);
  const outside = join(directory.path, "private");
  await mkdir(outside, { mode: 0o700 });
  const link = join(options.cwd, "state");
  await symlink(outside, link, "junction");
  deps.environment.CODEX_SECURITY_STATE_DIR = link;
  await expect(
    prepareSonarImport({ ...options, to: "local" }, deps),
  ).rejects.toThrow();
  expect(await stat(join(outside, "imports")).catch(() => null)).toBeNull();
});

test("reports the saved evidence after preparation fails", async () => {
  await using directory = await scopedTemporaryDirectory("sonar-saved-path-");
  const { options, deps, report } = await fixture(directory.path);
  const captures: string[] = [];
  await expect(
    prepareSonarImport(
      { ...options, to: "cloud", yes: true, dryRun: false },
      {
        ...deps,
        onCapture(path) {
          captures.push(path);
        },
      },
    ),
  ).rejects.toThrow("--to cloud --dry-run");
  expect(captures).toHaveLength(1);
  expect(JSON.parse(await readFile(captures[0]!, "utf8"))).toEqual(report);
});

test("rejects a non-finite native JSON number before snapshotting a capture", async () => {
  await using directory = await scopedTemporaryDirectory(
    "sonar-numeric-evidence-",
  );
  const { report, options, deps } = await fixture(directory.path);
  await writeFile(
    options.capture,
    JSON.stringify(report).replace(
      '"Reviewed evidence"',
      '"Reviewed evidence","value":1e400',
    ),
  );
  await expect(
    prepareSonarImport({ ...options, to: "local" }, deps),
  ).rejects.toThrow("finite JSON numbers");
  expect(
    await stat(deps.environment.CODEX_SECURITY_STATE_DIR).catch(() => null),
  ).toBeNull();
});

test.skipIf(process.platform === "win32")(
  "rejects a pre-existing shared capture directory",
  async () => {
    await using directory = await scopedTemporaryDirectory(
      "sonar-capture-permissions-",
    );
    const { options, deps } = await fixture(directory.path);
    const root = join(
      deps.environment.CODEX_SECURITY_STATE_DIR,
      "imports",
      "sonar",
    );
    await mkdir(root, { recursive: true, mode: 0o700 });
    await chmod(root, 0o777);
    await expect(
      prepareSonarImport({ ...options, to: "local" }, deps),
    ).rejects.toThrow();
  },
);

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
