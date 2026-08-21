import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Octokit } from "@octokit/core";
import { afterEach, describe, expect, test } from "bun:test";
import {
  runBulkScanWizard,
  type BulkScanDiscoveryDependencies,
  type BulkScanPrompt,
} from "../src/bulk-scan-discovery.js";

const temporaryDirectories: string[] = [];
const NOW = Date.parse("2026-07-22T12:00:00.000Z");
const REVISION = "0123456789abcdef0123456789abcdef01234567";

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-bulk-discovery-"));
  temporaryDirectories.push(root);
  return root;
}

class FakePrompt implements BulkScanPrompt {
  public readonly messages: string[] = [];
  public readonly questions: string[] = [];
  public interactive = true;
  public confirms: boolean[] = [];
  public inputs: string[] = [];
  public choices: string[] = [];
  public readonly searchOptions: string[][] = [];

  public isInteractive(): boolean {
    return this.interactive;
  }

  public write(value: string): void {
    this.messages.push(value);
  }

  public async confirm(question: string, fallback = false): Promise<boolean> {
    this.questions.push(question);
    return this.confirms.shift() ?? fallback;
  }

  public async input(question: string, fallback = ""): Promise<string> {
    this.questions.push(question);
    return this.inputs.shift() ?? fallback;
  }

  public async select<Value extends string>(
    question: string,
    options: readonly { label: string; value: Value }[],
  ): Promise<Value> {
    this.questions.push(question);
    this.searchOptions.push(options.map(({ label }) => label));
    const value = this.choices.shift();
    return (options.find((option) => option.value === value) ?? options[0]!)
      .value;
  }
}

interface Repository {
  fullName: string;
  visibility?: "private" | "internal" | "public";
  archived?: boolean;
  fork?: boolean;
  empty?: boolean;
  pushedAt?: string;
}

interface GitHubRequest {
  path: string;
  query?: string;
  variables?: { owner: string; cursor: string | null };
}

function discoveryDependencies(
  root: string,
  options: {
    host?: string;
    organizations?: string[];
    repositories?: Repository[];
    authenticated?: boolean;
  } = {},
): {
  dependencies: BulkScanDiscoveryDependencies;
  prompt: FakePrompt;
  hosts: string[];
  requests: GitHubRequest[];
} {
  const prompt = new FakePrompt();
  const host = options.host ?? "github.com";
  const repositories = options.repositories ?? [
    { fullName: "acme/payments-api", visibility: "private" as const },
    { fullName: "acme/identity-service", visibility: "internal" as const },
    { fullName: "acme/public-api", visibility: "public" as const },
  ];
  const hosts: string[] = [];
  const requests: GitHubRequest[] = [];

  return {
    prompt,
    hosts,
    requests,
    dependencies: {
      prompt,
      now: () => NOW,
      currentDirectory: () => root,
      ...(options.host === undefined ? {} : { githubHost: host }),
      createGitHub: async (githubHost) => {
        hosts.push(githubHost);
        if (options.authenticated === false) {
          throw new Error(
            "GitHub sign-in is required. Run 'gh auth login' first.",
          );
        }

        return new Octokit({
          auth: "test-token",
          baseUrl:
            githubHost === "github.com"
              ? "https://api.github.com"
              : `https://${githubHost}/api/v3`,
          request: {
            fetch: async (
              resource: Parameters<typeof fetch>[0],
              init?: Parameters<typeof fetch>[1],
            ) => {
              const url = new URL(
                resource instanceof Request ? resource.url : resource,
              );
              const path = url.pathname.replace(/^\/api(?:\/v3)?/u, "");
              const body =
                init?.body === undefined
                  ? undefined
                  : (JSON.parse(String(init.body)) as {
                      query: string;
                      variables: GitHubRequest["variables"];
                    });
              requests.push({
                path,
                ...(body === undefined
                  ? {}
                  : { query: body.query, variables: body.variables }),
              });

              if (path === "/user/orgs") {
                const organizations = options.organizations ?? [];
                const page = Number(url.searchParams.get("page") ?? "1");
                const perPage = Number(
                  url.searchParams.get("per_page") ?? "30",
                );
                const offset = (page - 1) * perPage;
                const next = new URL(url);
                next.searchParams.set("page", String(page + 1));
                return Response.json(
                  organizations
                    .slice(offset, offset + perPage)
                    .map((login) => ({ login })),
                  offset + perPage < organizations.length
                    ? { headers: { link: `<${next.href}>; rel="next"` } }
                    : undefined,
                );
              }
              if (path === "/user") {
                return Response.json({ login: "personal-account" });
              }
              if (path !== "/graphql" || body === undefined) {
                throw new Error(`Unexpected GitHub request: ${path}`);
              }

              const visible = repositories.filter(
                ({ archived, fork }) => !archived && !fork,
              );
              const start = Number(body.variables?.cursor ?? 0);
              const page = visible.slice(start, start + 100);
              const next = start + page.length;
              return Response.json({
                data: {
                  repositoryOwner: {
                    repositories: {
                      nodes: page.map((repository) => ({
                        nameWithOwner: repository.fullName,
                        pushedAt: repository.pushedAt ?? "2026-07-20T00:00:00Z",
                        defaultBranchRef: repository.empty
                          ? null
                          : { target: { oid: REVISION } },
                      })),
                      pageInfo: {
                        hasNextPage: next < visible.length,
                        endCursor: next < visible.length ? String(next) : null,
                      },
                    },
                  },
                },
              });
            },
          },
        });
      },
    },
  };
}

describe("bulk scan repository discovery", () => {
  test("discovers active public, private, and internal repositories with Octokit", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, hosts, requests } =
      discoveryDependencies(root);
    prompt.confirms = [true];

    const result = await runBulkScanWizard(dependencies);

    expect(result).toEqual({
      inputPath: join(root, "security-scans", "repositories.csv"),
      outputDir: join(root, "security-scans"),
      githubHost: "github.com",
    });
    expect(hosts).toEqual(["github.com"]);
    const query = requests.find(({ path }) => path === "/graphql")?.query;
    expect(query).not.toContain("privacy:");
    expect(query).toContain("isArchived: false");
    expect(query).toContain("isFork: false");
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain(
      `acme--payments-api,https://github.com/acme/payments-api.git,${REVISION}`,
    );
    expect(csv).toContain("acme--identity-service");
    expect(csv).toContain("acme--public-api");
    expect(prompt.messages.join("")).toContain("Found 3 repositories");
  });

  test("paginates repositories and stops at the 90-day cutoff", async () => {
    const root = await temporaryDirectory();
    const active = Array.from({ length: 101 }, (_value, index) => ({
      fullName: `acme/service-${index}`,
    }));
    const { dependencies, prompt, requests } = discoveryDependencies(root, {
      repositories: [
        ...active,
        { fullName: "acme/old", pushedAt: "2026-04-01T00:00:00Z" },
        ...active,
      ],
    });
    prompt.confirms = [true];

    const result = await runBulkScanWizard(dependencies);

    expect(requests.filter(({ path }) => path === "/graphql")).toHaveLength(2);
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--service-100");
    expect(csv).not.toContain("acme--old");
  });

  test("shows all repositories and scans only the selected ones", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/owl" },
        { fullName: "acme/openai" },
        { fullName: "acme/unrelated" },
      ],
    });
    prompt.confirms = [true];
    prompt.inputs = ["./custom-results"];
    prompt.choices = ["acme/owl", "acme/openai", ""];

    const result = await runBulkScanWizard(dependencies);

    expect(result?.outputDir).toBe(join(root, "custom-results"));
    expect(prompt.searchOptions).toEqual([
      ["All 3 repositories", "acme/owl", "acme/openai", "acme/unrelated"],
      ["Done (1 selected)", "acme/openai", "acme/unrelated"],
      ["Done (2 selected)", "acme/unrelated"],
    ]);
    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--owl");
    expect(csv).toContain("acme--openai");
    expect(csv).not.toContain("unrelated");
  });

  test.skipIf(process.platform !== "win32")(
    "expands a backslash home-relative output directory",
    async () => {
      const home = await temporaryDirectory();
      const currentDirectory = join(home, "current");
      await mkdir(currentDirectory);
      const { dependencies, prompt } = discoveryDependencies(currentDirectory);
      prompt.confirms = [true];
      prompt.inputs = ["~\\bulk-results"];
      const previousUserProfile = process.env["USERPROFILE"];
      process.env["USERPROFILE"] = home;
      try {
        const result = await runBulkScanWizard(dependencies);

        expect(result?.outputDir).toBe(join(home, "bulk-results"));
      } finally {
        if (previousUserProfile === undefined) {
          delete process.env["USERPROFILE"];
        } else {
          process.env["USERPROFILE"] = previousUserProfile;
        }
      }
    },
  );

  test("includes public repositories and excludes archived, forked, and empty repositories", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt } = discoveryDependencies(root, {
      repositories: [
        { fullName: "acme/service" },
        { fullName: "acme/public", visibility: "public" },
        { fullName: "acme/archive", archived: true },
        { fullName: "acme/fork", fork: true },
        { fullName: "acme/empty", empty: true },
      ],
    });
    prompt.confirms = [true];

    const result = await runBulkScanWizard(dependencies);

    const csv = await readFile(result!.inputPath, "utf8");
    expect(csv).toContain("acme--service");
    expect(csv).toContain("acme--public");
    expect(csv).not.toContain("archive");
    expect(csv).not.toContain("fork");
    expect(csv).not.toContain("empty");
  });

  test("honors GitHub Enterprise hosts", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, hosts } = discoveryDependencies(root, {
      host: "github.acme.example",
    });
    prompt.confirms = [true];

    const result = await runBulkScanWizard(dependencies);

    expect(result?.githubHost).toBe("github.acme.example");
    expect(hosts).toEqual(["github.acme.example"]);
    expect(await readFile(result!.inputPath, "utf8")).toContain(
      "https://github.acme.example/acme/payments-api.git",
    );
  });

  test("requires an existing GitHub sign-in", async () => {
    const root = await temporaryDirectory();
    const { dependencies, requests } = discoveryDependencies(root, {
      authenticated: false,
    });

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "Run 'gh auth login' first",
    );
    expect(requests).toEqual([]);
  });

  test("includes the personal account alongside organizations", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, requests } = discoveryDependencies(root, {
      organizations: ["acme"],
    });
    prompt.confirms = [true];
    prompt.choices = ["personal-account"];

    await runBulkScanWizard(dependencies);

    expect(prompt.searchOptions[0]).toEqual(["acme", "personal-account"]);
    expect(
      requests.find(({ path }) => path === "/graphql")?.variables?.owner,
    ).toBe("personal-account");
  });

  test("includes organizations beyond the first GitHub results page", async () => {
    const root = await temporaryDirectory();
    const organizations = Array.from(
      { length: 101 },
      (_value, index) => `organization-${String(index).padStart(3, "0")}`,
    );
    const { dependencies, prompt, requests } = discoveryDependencies(root, {
      organizations,
    });
    prompt.confirms = [true];
    prompt.choices = ["organization-100"];

    await runBulkScanWizard(dependencies);

    expect(prompt.searchOptions[0]).toContain("organization-100");
    expect(prompt.searchOptions[0]).toHaveLength(102);
    expect(requests.filter(({ path }) => path === "/user/orgs")).toHaveLength(
      2,
    );
    expect(
      requests.find(({ path }) => path === "/graphql")?.variables?.owner,
    ).toBe("organization-100");
  });

  test("does not write an inventory when canceled or no repositories match", async () => {
    for (const options of [
      { confirms: [false] },
      { confirms: [], repositories: [] },
    ]) {
      const root = await temporaryDirectory();
      const { dependencies, prompt } = discoveryDependencies(root, options);
      prompt.confirms = options.confirms;

      expect(await runBulkScanWizard(dependencies)).toBeNull();
      await expect(lstat(join(root, "security-scans"))).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  });

  test("rejects an existing scan without replacing its inventory", async () => {
    const root = await temporaryDirectory();
    const output = join(root, "existing-results");
    const inventory = join(output, "repositories.csv");
    await mkdir(output);
    await writeFile(inventory, "do not overwrite\n");
    const { dependencies, prompt } = discoveryDependencies(root);
    prompt.inputs = ["./existing-results"];

    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "already contains a repository list or scan",
    );
    expect(await readFile(inventory, "utf8")).toBe("do not overwrite\n");
  });

  test("requires an interactive terminal and honors cancellation", async () => {
    const root = await temporaryDirectory();
    const { dependencies, prompt, requests } = discoveryDependencies(root);
    prompt.interactive = false;
    await expect(runBulkScanWizard(dependencies)).rejects.toThrow(
      "requires a terminal",
    );

    prompt.interactive = true;
    const controller = new AbortController();
    controller.abort();
    await expect(
      runBulkScanWizard(dependencies, controller.signal),
    ).rejects.toThrow();
    expect(prompt.questions).toEqual([]);
    expect(requests).toEqual([]);
  });
});
