import { afterEach, expect, spyOn, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  stat,
  writeFile,
} from "node:fs/promises";
import { devNull, tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { collectSonarIssues } from "../src/sonar-collector.js";
import { readSonarFindings } from "../src/sonar-findings.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

const server = "https://sonarqube.us";
const organization = "example";
const project = "example:service";
const repositoryUrl = "https://example.invalid/team/service";
const auth = { status: "connected", org: organization, server };
const environment = {
  ...process.env,
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
  GIT_CONFIG_GLOBAL: devNull,
  GIT_CONFIG_NOSYSTEM: "1",
};

function git(...args: string[]) {
  return execFileSync("git", args, { env: environment });
}

async function checkout() {
  const cwd = await realpath(await mkdtemp(join(tmpdir(), "sonar import ")));
  roots.push(cwd);
  git("init", "--quiet", cwd);
  git(
    "-C",
    cwd,
    "remote",
    "add",
    "origin",
    "https://synthetic-user:example@" +
      new URL(repositoryUrl).host +
      "/team/service.git",
  );
  return cwd;
}

function page(key: string, index = 1, total = 1) {
  return {
    issues: [
      {
        project,
        key,
        rule: "test:S1",
        flows: [
          {
            locations: [
              {
                component: project + ":source.ts",
                textRange: { startLine: 1, endLine: 3 },
              },
            ],
          },
        ],
      },
    ],
    components: [{ key: project + ":source.ts", path: "source.ts" }],
    paging: { pageIndex: index, pageSize: 1, total },
  };
}

function sonarSession(options: {
  pages:
    | Record<string, unknown>[]
    | ((query: URLSearchParams) => Record<string, unknown>);
  bindings?: Record<string, unknown>[];
  navigationDenied?: boolean;
  navigation?: Record<string, unknown>;
  components?: Record<string, unknown>[];
  componentsById?: Record<string, Record<string, unknown>[]>;
  repositoryUrl?: string;
  analyses?: Record<string, unknown>[] | Error;
}) {
  const commands: string[][] = [];
  const queries: URLSearchParams[] = [];
  return {
    commands,
    queries,
    run: async (args: string[]): Promise<Record<string, unknown>> => {
      commands.push(args);
      if (args[0] === "auth") return auth;
      expect(args.slice(0, 2)).toEqual(["api", "get"]);
      const url = new URL(args[2]!, server);
      if (url.pathname === "/api/project_branches/list")
        return {
          branches: [
            { name: "other", isMain: false },
            { name: "trunk", isMain: true },
          ],
        };
      if (url.pathname === "/api/navigation/component") {
        if (options.navigationDenied)
          throw new Error("Navigation requires a browser session");
        return {
          key: project,
          id: "p-1",
          badgeToken: "synthetic badge metadata",
          ...options.navigation,
        };
      }
      if (url.pathname === "/dop-translation/project-bindings") {
        expect(url.searchParams.get("url")).toBe(
          options.repositoryUrl ?? repositoryUrl,
        );
        return { bindings: options.bindings ?? [{ projectId: "p-1" }] };
      }
      if (url.pathname === "/api/components/search_projects") {
        const id = url.searchParams.get("projectIds")!;
        if (!options.componentsById) expect(id).toBe("p-1");
        expect(url.searchParams.get("organization")).toBe(organization);
        return {
          components: options.componentsById?.[id] ??
            options.components ?? [{ key: project, id: "p-1", organization }],
        };
      }
      if (url.pathname === "/api/project_analyses/search") {
        if (options.analyses instanceof Error) throw options.analyses;
        return { analyses: options.analyses ?? [] };
      }
      expect(url.pathname).toBe("/api/issues/search");
      queries.push(url.searchParams);
      if (typeof options.pages === "function")
        return options.pages(url.searchParams);
      return options.pages[Number(url.searchParams.get("p")) - 1]!;
    },
  };
}

test("uses the signed-in CLI and a verified checkout binding, retaining all security issue pages", async () => {
  const pages = [page("A", 1, 2), page("B", 2, 2)];
  const cwd = await checkout();
  const session = sonarSession({
    pages,
    analyses: [{ relativePathFromScmRoot: "" }],
  });
  const branch = "release/space & plus+";
  const capture = await collectSonarIssues(
    { cwd, branch, environment },
    session.run,
  );
  expect(session.commands[0]).toEqual(["auth", "status", "--format", "json"]);
  expect(session.commands[1]).toEqual([
    "api",
    "get",
    `/dop-translation/project-bindings?${new URLSearchParams({ url: repositoryUrl })}`,
  ]);
  expect(session.commands.flat().join(" ")).not.toContain("synthetic-user");
  expect(capture).toMatchObject({
    format: "sonar-issues/v1",
    server,
    organization,
    project,
    branch,
    repositoryUrl,
    projectBase: "",
    pages,
  });
  expect(JSON.stringify(capture)).not.toContain("synthetic");
  expect(session.queries.length).toBe(2);
  for (const query of session.queries) {
    expect(query.get("organization")).toBe(organization);
    expect(query.get("componentKeys")).toBe(project);
    expect(query.get("branch")).toBe(branch);
    expect(query.get("impactSoftwareQualities")).toBe("SECURITY");
    expect(query.get("additionalFields")).toBe("rules");
    expect(query.get("issueStatuses")).toBe("OPEN,CONFIRMED");
  }
});

test("collects the exact issue keys and PR selected in the plugin handoff", async () => {
  const cwd = await checkout();
  const issueKeys = ["A", "B"];
  const session = sonarSession({
    pages: [page("A", 1, 2), page("B", 2, 2)],
    analyses: [{ relativePathFromScmRoot: "packages/main-branch" }],
  });
  const capture = await collectSonarIssues(
    { cwd, project, pullRequest: "35", issueKeys, environment },
    session.run,
  );
  expect(capture.pullRequest).toBe("35");
  expect(capture.projectBase).toBeUndefined();
  expect(session.commands.flat().join(" ")).not.toContain(
    "/api/project_analyses/search",
  );
  const query = session.queries[0]!;
  expect(query.get("issues")).toBe("A,B");
  expect(query.get("pullRequest")).toBe("35");
  expect(query.has("branch")).toBe(false);
  expect(query.has("issueStatuses")).toBe(false);
  for (const [key, error] of [
    ["A", "were not returned"],
    ["unselected", "outside the selected"],
  ] as const) {
    const incomplete = sonarSession({ pages: [page(key)] });
    await expect(
      collectSonarIssues(
        { cwd, project, issueKeys, environment },
        incomplete.run,
      ),
    ).rejects.toThrow(error);
  }
});

const largeSelection = Array.from(
  { length: 2_000 },
  (_, index) => "example-issue-" + index,
);

function exactIssuePage(
  query: URLSearchParams,
  keys = query.get("issues")!.split(","),
) {
  const index = Number(query.get("p")),
    size = Number(query.get("ps"));
  return {
    paging: { pageIndex: index, pageSize: size, total: keys.length },
    issues: keys.slice((index - 1) * size, index * size).map((key) => ({
      key,
      project,
      component: project + ":source.ts",
      rule: "test:S1",
      type: "VULNERABILITY",
    })),
  };
}

test("a large exact selection retains each query's native pages for offline replay", async () => {
  const cwd = await checkout();
  const nativePages: Record<string, unknown>[] = [];
  const session = sonarSession({
    pages: (query) => {
      const result = exactIssuePage(query);
      nativePages.push(result);
      return result;
    },
  });
  const capture = await collectSonarIssues(
    { cwd, project, branch: "main", issueKeys: largeSelection, environment },
    session.run,
  );
  const firstPages = session.queries.filter((query) => query.get("p") === "1");
  expect(firstPages.length).toBeGreaterThan(1);
  expect(
    firstPages.flatMap((query) => query.get("issues")!.split(",")),
  ).toEqual(largeSelection);
  expect(capture.pages).toEqual(nativePages);
  expect(nativePages.length).toBeGreaterThan(firstPages.length);
  const path = join(cwd, "selection.json");
  await writeFile(path, JSON.stringify(capture));
  const replay = await readSonarFindings(path, repositoryUrl, "local");
  expect(replay.findings.map((finding) => finding.source_finding_id)).toEqual(
    largeSelection,
  );
});

test("multiple exact-key queries reject missing, foreign, and duplicate keys in later responses", async () => {
  const cwd = await checkout();
  for (const [defect, error] of [
    ["missing", /were not returned/],
    ["foreign", /outside the selected/],
    ["duplicate", /overlap/],
  ] as const) {
    const session = sonarSession({
      pages: (query) => {
        const keys = query.get("issues")!.split(",");
        if (keys[0] !== largeSelection[0]) {
          if (defect === "missing") keys.shift();
          if (defect === "foreign") keys[0] = largeSelection[0]!;
          if (defect === "duplicate") keys[0] = keys[1]!;
        }
        return exactIssuePage(query, keys);
      },
    });
    await expect(
      collectSonarIssues(
        {
          cwd,
          project,
          branch: "main",
          issueKeys: largeSelection,
          environment,
        },
        session.run,
      ),
    ).rejects.toThrow(error);
    expect(
      session.queries.filter((query) => query.get("p") === "1").length,
    ).toBeGreaterThan(1);
  }
});

test("an omitted ref and the explicit Sonar main branch produce identical captures", async () => {
  const cwd = await checkout();
  const session = sonarSession({ pages: [page("A")] });
  const implicit = await collectSonarIssues(
    { cwd, project, environment },
    session.run,
  );
  const explicit = await collectSonarIssues(
    { cwd, project, branch: "trunk", environment },
    session.run,
  );
  expect(implicit).toEqual(explicit);
  expect(session.queries.map((query) => query.get("branch"))).toEqual([
    "trunk",
    "trunk",
  ]);
});

test("SDK collection keeps the checkout and issue selection supplied when the call started", async () => {
  const cwd = await checkout();
  const session = sonarSession({ pages: [page("A")] });
  const options = {
    cwd,
    project,
    branch: "trunk",
    issueKeys: ["A"],
    sourceRepositoryUrl: repositoryUrl,
    environment: { ...environment, PATH: process.env["PATH"] },
  };
  const collection = collectSonarIssues(options, session.run);
  options.cwd = join(cwd, "absent");
  options.project = "another-project";
  options.branch = "another-branch";
  options.issueKeys[0] = "B";
  options.sourceRepositoryUrl += "-other";
  options.environment.PATH = "";
  const capture = await collection;
  expect(capture).toMatchObject({ project, branch: "trunk", repositoryUrl });
  expect(session.queries.map((query) => query.get("issues"))).toEqual(["A"]);
});

test("a supplied source repository must agree with checkout discovery and selected project metadata before issue search", async () => {
  const cwd = await checkout();
  const sourceRepositoryUrl = repositoryUrl + "-other";
  const implicit = sonarSession({ pages: [] });
  await expect(
    collectSonarIssues({ cwd, sourceRepositoryUrl, environment }, implicit.run),
  ).rejects.toThrow("--source-repository-url");
  expect(implicit.commands).toEqual([]);
  const explicit = sonarSession({
    pages: [],
    navigation: { alm: { url: sourceRepositoryUrl } },
  });
  await expect(
    collectSonarIssues(
      { cwd, project, sourceRepositoryUrl: repositoryUrl, environment },
      explicit.run,
    ),
  ).rejects.toThrow("--source-repository-url");
  expect(explicit.queries).toEqual([]);
});

test("conflicting organization, branch, and pull request on returned issues fail collection", async () => {
  const cwd = await checkout();
  for (const [selection, scope, error] of [
    [{ branch: "main" }, { organization: "other" }, /organization/],
    [{ branch: "main" }, { branch: "other" }, /branch/],
    [{ pullRequest: "12" }, { pullRequest: "13" }, /pullRequest/],
    [{ pullRequest: "12" }, { branch: "main" }, /branch and pull request/],
  ] as const) {
    const result = page("A");
    Object.assign(result.issues[0]!, scope);
    const session = sonarSession({ pages: [result] });
    await expect(
      collectSonarIssues(
        { cwd, project, ...selection, environment },
        session.run,
      ),
    ).rejects.toThrow(error);
    expect(session.queries).toHaveLength(1);
  }
});

test("automatic discovery rejects a forged Git pointer but accepts a registered linked worktree", async () => {
  const cwd = await checkout();
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "sonar worktrees ")),
  );
  roots.push(root);
  const forged = join(root, "forged");
  await mkdir(forged);
  await writeFile(join(forged, ".git"), `gitdir: ${join(cwd, ".git")}\n`);
  const session = sonarSession({ pages: [page("A")] });
  await expect(
    collectSonarIssues({ cwd: forged, environment }, session.run),
  ).rejects.toThrow("--sonar-project");
  expect(session.commands).toEqual([]);

  git(
    "-C",
    cwd,
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "--quiet",
    "--allow-empty",
    "-m",
    "fixture",
  );
  const linked = join(root, "linked");
  git("-C", cwd, "worktree", "add", "--quiet", "--detach", linked);
  const capture = await collectSonarIssues(
    { cwd: linked, environment },
    session.run,
  );
  expect(capture).toMatchObject({ project, repositoryUrl });
  expect(session.queries).toHaveLength(1);
});

test("uses the explicit project in token-only sessions and claims only a matching binding", async () => {
  const cwd = await checkout();
  for (const resolvedProject of [project, "other"]) {
    const session = sonarSession({
      pages: [page("A")],
      navigationDenied: true,
      components: [{ key: resolvedProject }],
    });
    const capture = await collectSonarIssues(
      { cwd, project, environment },
      session.run,
    );
    expect(capture.project).toBe(project);
    expect(capture.repositoryUrl).toBe(
      resolvedProject === project ? repositoryUrl : undefined,
    );
    expect(session.queries.map((query) => query.get("componentKeys"))).toEqual([
      project,
    ]);
  }
});

test("an explicit project disambiguates token-only monorepo bindings", async () => {
  const cwd = await checkout();
  const session = sonarSession({
    pages: [page("A")],
    navigationDenied: true,
    bindings: [{ projectId: "p-other" }, { projectId: "p-1" }],
    componentsById: {
      "p-other": [{ key: "other", id: "p-other", organization }],
      "p-1": [{ key: project, id: "p-1", organization }],
    },
  });
  const capture = await collectSonarIssues(
    { cwd, project, environment },
    session.run,
  );
  expect(capture.repositoryUrl).toBe(repositoryUrl);
  expect(session.queries.map((q) => q.get("componentKeys"))).toEqual([project]);
});

test("a confirmed project or organization mismatch stops before further lookups", async () => {
  const cwd = await checkout();
  for (const navigation of [{ key: "foreign" }, { organization: "foreign" }]) {
    const session = sonarSession({ pages: [], navigation });
    await expect(
      collectSonarIssues({ cwd, project, environment }, session.run),
    ).rejects.toThrow("different project or organization");
    expect(session.commands).toHaveLength(2);
  }
});

test("explicitly selecting zero issues never broadens to all open issues", async () => {
  const cwd = await checkout();
  const session = sonarSession({ pages: [] });
  await expect(
    collectSonarIssues(
      { cwd, project, issueKeys: [], environment },
      session.run,
    ),
  ).rejects.toThrow("selection is empty");
  expect(session.commands).toEqual([]);
});

test("asks for a narrower selection on the first page exceeding Sonar's search window", async () => {
  const cwd = await checkout();
  const session = sonarSession({ pages: [page("A", 1, 10_001)] });
  await expect(
    collectSonarIssues({ cwd, project, environment }, session.run),
  ).rejects.toThrow("--sonar-issue");
  expect(session.queries).toHaveLength(1);
});

test("cannot save a partial or overlapping Sonar search as a complete capture", async () => {
  const cwd = await checkout();
  for (const pages of [
    [page("A", 1, 2), page("A", 2, 2)],
    [page("A", 1, 2), page("B", 2, 1)],
  ]) {
    const session = sonarSession({ pages });
    await expect(
      collectSonarIssues(
        { cwd, project, branch: "main", environment },
        session.run,
      ),
    ).rejects.toThrow(/overlap|paging/);
  }
});

test("asks for a project before fetching findings from an ambiguous or unverified checkout", async () => {
  const cwd = await checkout();
  for (const options of [
    { bindings: [] },
    { bindings: [{ projectId: "p-1" }, { projectId: "p-2" }] },
    { components: [] },
    { components: [{ key: project }, { key: "unrelated" }] },
    { components: [{ key: project, organization: "unrelated" }] },
    { components: [{ key: project, id: "p-2" }] },
  ]) {
    const session = sonarSession({ ...options, pages: [] });
    await expect(
      collectSonarIssues({ cwd, environment }, session.run),
    ).rejects.toThrow("--sonar-project");
    expect(session.queries).toHaveLength(0);
    expect(session.commands.flat().join(" ")).not.toContain(
      "/api/navigation/component",
    );
  }
});

test("guides disconnected users to sign in and honors cancellation before opening Sonar", async () => {
  const cwd = await checkout();
  await expect(
    collectSonarIssues({ cwd, environment }, async () => ({
      status: "token_missing",
    })),
  ).rejects.toThrow("sonar auth login");
  await expect(
    collectSonarIssues({
      cwd,
      project,
      environment: { ...environment, PATH: "" },
    }),
  ).rejects.toThrow("Install the SonarQube CLI");
  const aborted = AbortSignal.abort(new Error("cancel collection"));
  await expect(
    collectSonarIssues({ cwd, signal: aborted, environment }, async () => {
      throw new Error("unexpected CLI call");
    }),
  ).rejects.toThrow("cancel collection");
});

test("requires the external import opt-in before invoking Sonar", async () => {
  const session = sonarSession({ pages: [] });
  await expect(
    collectSonarIssues(
      {
        cwd: ".",
        environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "0" },
      },
      session.run,
    ),
  ).rejects.toThrow("imports are disabled");
  expect(session.commands).toEqual([]);
});

test("projects paths only from the selected branch's recorded analysis base", async () => {
  const cwd = await checkout();
  const branch = "release/service";
  for (const [analyses, expected] of [
    [[{ relativePathFromScmRoot: "packages/service" }], "packages/service"],
    [[{ relativePathFromScmRoot: "../outside" }], undefined],
    [[{}], undefined],
    [new Error("Analysis metadata unavailable"), undefined],
  ] as Array<[Record<string, unknown>[] | Error, string | undefined]>) {
    const session = sonarSession({
      pages: [page("A")],
      analyses,
    });
    const capture = await collectSonarIssues(
      { cwd, branch, environment },
      session.run,
    );
    expect(session.commands).toContainEqual([
      "api",
      "get",
      `/api/project_analyses/search?${new URLSearchParams({ project, branch, ps: "1" })}`,
    ]);
    expect(capture.projectBase).toBe(expected);
    expect(capture.pages[0]).toEqual(page("A"));
  }
});

test.each([
  [
    "ssh://git@ssh.github.com:443/team/service.git",
    "https://github.com/team/service",
  ],
  ["git@GitHub.com:Team/Service.git", "https://github.com/Team/Service"],
  [
    "git@SSH.dev.azure.com:v3/Org/Project/Repo",
    "https://dev.azure.com/Org/Project/_git/Repo",
  ],
  [
    "git@ssh.dev.azure.com:v3/Org/Project%20Name/Repo%20Name",
    "https://dev.azure.com/Org/Project%20Name/_git/Repo%20Name",
  ],
  [
    "ssh://git@ssh.dev.azure.com:22/v3/Org/Project/Repo",
    "https://dev.azure.com/Org/Project/_git/Repo",
  ],
])(
  "verifies the HTTPS repository binding for SSH origin %s",
  async (origin, source) => {
    const cwd = await checkout();
    git("-C", cwd, "remote", "set-url", "origin", origin);
    const session = sonarSession({ pages: [page("A")], repositoryUrl: source });
    const capture = await collectSonarIssues({ cwd, environment }, session.run);
    expect(capture.repositoryUrl).toBe(source);
  },
);

test("rejects ambiguous Git transport and credential-bearing query strings before Sonar discovery", async () => {
  const cwd = await checkout();
  await writeFile(
    join(cwd, "sonar-project.properties"),
    "sonar.projectKey=unselected\n",
  );
  for (const origin of [
    "https://example.invalid/team/service.git?access_token=synthetic",
    "https://example.invalid/team/old/../service.git",
    "ssh://git@github.com/team/old/../service.git",
    "ssh://git@github.com/team/old/%2e%2e/service.git",
    "ssh://git@github.com%2f/team/service.git",
    "git@github.com:team/%73ervice.git",
    "ssh://git@ssh.dev.azure.com:2222/v3/Org/Project/Repo",
    "git@ssh.dev.azure.com:v3/Org/../Repo",
  ]) {
    git("-C", cwd, "remote", "set-url", "origin", origin);
    const session = sonarSession({ pages: [] });
    await expect(
      collectSonarIssues({ cwd, environment }, session.run),
    ).rejects.toThrow("--sonar-project");
    expect(session.commands).toEqual([]);
  }
});

test.skipIf(process.platform === "win32")(
  "Sonar's child Git cannot resolve an external symlink into the checkout",
  async () => {
    const cwd = await checkout();
    const root = await realpath(await mkdtemp(join(tmpdir(), "sonar tools ")));
    roots.push(root);
    const bin = join(root, "bin"),
      aliases = join(root, "aliases"),
      marker = join(root, "executed");
    await Promise.all([mkdir(bin), mkdir(aliases)]);
    await writeFile(
      join(cwd, "git"),
      '#!/bin/sh\ntouch "$SONAR_CHILD_MARKER"\n',
      { mode: 0o700 },
    );
    await symlink(join(cwd, "git"), join(aliases, "git"));
    await writeFile(
      join(bin, "sonar"),
      `#!/bin/sh
test "$SONAR_TOKEN" = "synthetic" || exit 1
git --version >/dev/null || exit 1
printf '{"status":"token_missing"}'
`,
      { mode: 0o700 },
    );
    await expect(
      collectSonarIssues({
        cwd,
        project,
        environment: {
          ...environment,
          PATH: [aliases, bin, process.env["PATH"]].join(delimiter),
          SONAR_CHILD_MARKER: marker,
          SONAR_TOKEN: "synthetic",
        },
      }),
    ).rejects.toThrow("sonar auth login");
    await expect(stat(marker)).rejects.toMatchObject({ code: "ENOENT" });
  },
);

test.each(["checkout", "metadata"])(
  "excludes Git in a separate caller %s from the SDK lookup",
  async (kind) => {
    const cwd = await checkout();
    const root = await realpath(await mkdtemp(join(tmpdir(), "sonar caller ")));
    roots.push(root);
    const caller = join(root, "caller");
    const metadata = join(root, "caller.git");
    git("init", "--quiet", "--separate-git-dir", metadata, caller);
    const bin = join(kind === "checkout" ? caller : metadata, "bin");
    await mkdir(bin);
    if (process.platform === "win32")
      await copyFile(process.execPath, join(bin, "git.exe"));
    else
      await writeFile(join(bin, "git"), "#!/bin/sh\nexit 1\n", { mode: 0o700 });
    const current = spyOn(process, "cwd").mockReturnValue(caller);
    try {
      const session = sonarSession({ pages: [page("A")] });
      const capture = await collectSonarIssues(
        {
          cwd,
          environment: {
            ...environment,
            PATH: [bin, process.env["PATH"]].join(delimiter),
          },
        },
        session.run,
      );
      expect(capture.repositoryUrl).toBe(repositoryUrl);
    } finally {
      current.mockRestore();
    }
  },
);
