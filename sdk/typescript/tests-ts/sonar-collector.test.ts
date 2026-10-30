import { afterEach, expect, spyOn, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { collectSonarIssues } from "../src/sonar-collector.js";

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
const link = { projectKey: project, organization, serverUrl: server };
const environment = {
  ...process.env,
  CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1",
};

async function checkout() {
  const cwd = await realpath(await mkdtemp(join(tmpdir(), "sonar import ")));
  roots.push(cwd);
  execFileSync("git", ["init", "--quiet", cwd]);
  execFileSync("git", [
    "-C",
    cwd,
    "remote",
    "add",
    "origin",
    "https://synthetic-user:example@" +
      new URL(repositoryUrl).host +
      "/team/service.git",
  ]);
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
  pages: Record<string, unknown>[];
  links?: Record<string, unknown>[];
  boundProjectId?: string;
  navigationDenied?: boolean;
  resolvedProject?: string;
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
      if (args[0] === "link") return { projects: options.links ?? [link] };
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
        };
      }
      if (url.pathname === "/dop-translation/project-bindings") {
        expect(url.searchParams.get("url")).toBe(
          options.repositoryUrl ?? repositoryUrl,
        );
        return { bindings: [{ projectId: options.boundProjectId ?? "p-1" }] };
      }
      if (url.pathname === "/api/components/search_projects") {
        expect(url.searchParams.get("projectIds")).toBe(
          options.boundProjectId ?? "p-1",
        );
        expect(url.searchParams.get("organization")).toBe(organization);
        return { components: [{ key: options.resolvedProject ?? project }] };
      }
      if (url.pathname === "/api/project_analyses/search") {
        if (options.analyses instanceof Error) throw options.analyses;
        return { analyses: options.analyses ?? [] };
      }
      expect(url.pathname).toBe("/api/issues/search");
      queries.push(url.searchParams);
      return options.pages[Number(url.searchParams.get("p")) - 1]!;
    },
  };
}

test("uses the signed-in CLI and a verified checkout binding, retaining all security issue pages", async () => {
  const pages = [page("A", 1, 2), page("B", 2, 2)];
  const cwd = await checkout();
  const session = sonarSession({
    pages,
    links: [{ ...link, projectRoot: cwd }],
    analyses: [{ relativePathFromScmRoot: "" }],
  });
  const branch = "release/space & plus+";
  const capture = await collectSonarIssues(
    { cwd, branch, environment },
    session.run,
  );
  expect(session.commands[0]).toEqual(["auth", "status", "--format", "json"]);
  expect(session.commands[1]).toEqual(["link", "list"]);
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

test("verifies a token-only session through the Sonar CLI's remote binding lookup", async () => {
  const cwd = await checkout();
  for (const resolvedProject of [project, "other"]) {
    const session = sonarSession({
      pages: [page("A")],
      navigationDenied: true,
      resolvedProject,
    });
    const request = collectSonarIssues({ cwd, environment }, session.run);
    if (resolvedProject === project)
      expect((await request).repositoryUrl).toBe(repositoryUrl);
    else {
      await expect(request).rejects.toThrow("could not verify");
      expect(session.queries).toHaveLength(0);
    }
  }
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
    { links: [link, { ...link, projectKey: "example:other" }] },
    { links: [{ ...link, serverUrl: "https://sonarcloud.io" }] },
    { links: [{ ...link, organization: "unrelated" }] },
    { boundProjectId: "another-project" },
  ]) {
    const session = sonarSession({ ...options, pages: [] });
    await expect(
      collectSonarIssues({ cwd, environment }, session.run),
    ).rejects.toThrow(/--sonar-project|another Sonar connection/);
    expect(session.queries).toHaveLength(0);
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
      links: [{ ...link, projectRoot: cwd }],
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

test("verifies the GitHub SSH-over-443 origin using its HTTPS repository binding", async () => {
  const cwd = await checkout();
  execFileSync("git", [
    "-C",
    cwd,
    "remote",
    "set-url",
    "origin",
    "ssh://git@ssh.github.com:443/team/service.git",
  ]);
  const source = "https://github.com/team/service";
  const session = sonarSession({ pages: [page("A")], repositoryUrl: source });
  const capture = await collectSonarIssues({ cwd, environment }, session.run);
  expect(capture.repositoryUrl).toBe(source);
});

test.each(["checkout", "metadata"])(
  "excludes Git in a separate caller %s from the SDK lookup",
  async (kind) => {
    const cwd = await checkout();
    const root = await realpath(await mkdtemp(join(tmpdir(), "sonar caller ")));
    roots.push(root);
    const caller = join(root, "caller");
    const metadata = join(root, "caller.git");
    execFileSync("git", [
      "init",
      "--quiet",
      "--separate-git-dir",
      metadata,
      caller,
    ]);
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
