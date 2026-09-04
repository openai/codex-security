import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";

type Change = {
  title: string;
  body?: string;
  labels?: string[];
  breaking?: boolean;
  number?: number | null;
  sha: string;
  url: string;
};
type Section = {
  generatedHash: string | null;
  humanOwned: boolean;
  reset?: boolean;
};
type Sections = Record<"highlights" | "upgrades", Section>;
type History = {
  baseVersion: string;
  baseCommit: string;
  mainSha: string;
  packageText: string;
  changes: Change[];
};
type Plan = Omit<History, "packageText"> & {
  version: string;
  branch: string;
  title: string;
  files: Record<string, string | null>;
  humanOwned: string[];
  generated: Record<"highlights" | "upgrades", string>;
};
type GitRepository = {
  git: (...args: string[]) => string;
  ensureCommit: (sha: string) => void;
  readFile: (sha: string, path: string) => string | null;
};
type Body = Record<string, unknown>;
type GitHubClient = {
  repository: string;
  owner: string;
  repositoryUrl: string;
  request: (method: string, path: string, body?: Body) => Promise<unknown>;
  list: (path: string) => Promise<unknown[]>;
};
type Fetcher = (url: string, options: RequestInit) => Promise<Response>;
type Pull = {
  number: number;
  title: string;
  body: string;
  state: "open" | "closed";
  draft: boolean;
  merged_at: string | null;
  head: { ref: string; sha: string; repo: { full_name: string } };
  base: { ref: string };
  html_url: string;
  labels: { name: string }[];
};

const script = new URL("../scripts/release-pr.mjs", import.meta.url);
const {
  packagePath,
  notesPath,
  statePath,
  isBreakingChange,
  nextReleaseVersion,
  createReleasePlan,
  createGitRepository,
  createGitHubClient,
  readReleaseHistory,
  reconcileReleasePullRequest,
} = (await import(script.href)) as {
  packagePath: string;
  notesPath: string;
  statePath: string;
  isBreakingChange: (change: Change) => boolean;
  nextReleaseVersion: (version: string, changes: Change[]) => string;
  createReleasePlan: (
    history: History,
    previous?: {
      notes: string | null;
      state: Pick<History, "baseVersion" | "baseCommit"> & {
        sections: Sections;
      };
    } | null,
  ) => Plan;
  createGitRepository: (directory: string) => GitRepository;
  createGitHubClient: (
    repository: string,
    token: string,
    fetcher?: Fetcher,
  ) => GitHubClient;
  readReleaseHistory: (
    repo: GitRepository,
    sha: string,
    github: GitHubClient,
  ) => Promise<History>;
  reconcileReleasePullRequest: (options: {
    repo: GitRepository;
    github: GitHubClient;
    dryRun?: boolean;
  }) => Promise<{
    action: string;
    reason?: string;
    headSha?: string;
    pull?: number;
    reviewRequested?: boolean;
    plan: Plan;
  }>;
};
const releaseAutomation = new URL(
  "../scripts/release-automation.mjs",
  import.meta.url,
);
const { parseReviewedReleaseNotes, composeReleaseNotes } = (await import(
  releaseAutomation.href
)) as {
  parseReviewedReleaseNotes: (version: string, notes: string) => string;
  composeReleaseNotes: (inventory: string, summary: string) => string;
};
const template = readFileSync(
  new URL("../../../.github/PULL_REQUEST_TEMPLATE.md", import.meta.url),
  "utf8",
);
const workflow = readFileSync(
  new URL("../../../.github/workflows/node-release-pr.yml", import.meta.url),
  "utf8",
);
const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0))
    rmSync(directory, { recursive: true, force: true });
});

function packageText(version = "0.1.23", dependencies = {}) {
  return `${JSON.stringify({ name: "@openai/codex-security", version, dependencies }, null, 2)}\n`;
}

function change(
  title: string,
  number = 1,
  extra: Partial<Change> = {},
): Change {
  const result = {
    title,
    sha: String(number).padStart(40, "0"),
    number,
    url: `https://github.com/example/release-fixture/pull/${number}`,
    ...extra,
  };
  return { ...result, breaking: isBreakingChange(result) };
}

function history(changes: Change[]): History {
  return {
    baseVersion: "0.1.23",
    baseCommit: "a".repeat(40),
    mainSha: "b".repeat(40),
    packageText: packageText(),
    changes,
  };
}

function updatePlan(
  previous: Plan,
  changes: Change[],
  notes: string | null = previous.files[notesPath] ?? null,
) {
  return createReleasePlan(history(changes), {
    notes,
    state: JSON.parse(previous.files[statePath]!),
  });
}

function apiError(status: number) {
  return Object.assign(new Error(`HTTP ${status}`), { status });
}

class Fixture {
  readonly directory = mkdtempSync(join(tmpdir(), "release pr test "));
  readonly repo = createGitRepository(this.directory);
  readonly github = new FakeGitHub(this);
  readonly git = this.repo.git;

  constructor() {
    directories.push(this.directory);
    this.git("init", "-b", "main");
    this.git("config", "user.name", "Release Test");
    this.git("config", "user.email", "release-test@example.invalid");
    this.git("config", "commit.gpgsign", "false");
    this.commit(
      "main",
      {
        [packagePath]: packageText(),
        [notesPath]:
          "<!-- release-version: 0.1.23 -->\n\nPreviously reviewed release.\n",
        ".github/PULL_REQUEST_TEMPLATE.md": template,
        "sdk/typescript/src/example.ts": "export const initial = true;\n",
      },
      "release: bump to 0.1.23",
    );
  }

  head(branch = "main") {
    try {
      return this.git("rev-parse", "--verify", `refs/heads/${branch}`).trim();
    } catch {
      return null;
    }
  }

  tree(base: string | null, files: Record<string, string | null>) {
    this.git("read-tree", base ?? "--empty");
    for (const [path, content] of Object.entries(files)) {
      if (content === null) {
        this.git("update-index", "--force-remove", "--", path);
      } else {
        const blob = execFileSync("git", ["hash-object", "-w", "--stdin"], {
          cwd: this.directory,
          input: content,
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"],
        }).trim();
        this.git("update-index", "--add", "--cacheinfo", "100644", blob, path);
      }
    }
    return this.git("write-tree").trim();
  }

  commit(
    branch: string,
    files: Record<string, string | null>,
    message: string,
    from = this.head(branch),
  ) {
    const tree = this.tree(from, files);
    const sha = this.git(
      "commit-tree",
      tree,
      ...(from ? ["-p", from] : []),
      "-m",
      message,
    ).trim();
    this.git("update-ref", `refs/heads/${branch}`, sha);
    return sha;
  }

  merge(
    title: string,
    files: Record<string, string | null> = {},
    body = "",
    labels: string[] = [],
  ) {
    const sha = this.commit("main", files, `${title}\n\n${body}`);
    const pull = this.github.addPull(
      `change/${this.github.pulls.length + 1}`,
      title,
      sha,
    );
    pull.state = "closed";
    pull.merged_at = "2026-01-01T00:00:00Z";
    pull.body = body;
    pull.labels = labels.map((name) => ({ name }));
    this.github.commitPulls.set(sha, [pull]);
    return sha;
  }

  run(dryRun = false) {
    return reconcileReleasePullRequest({
      repo: this.repo,
      github: this.github,
      dryRun,
    });
  }
}

class FakeGitHub {
  readonly repository = "example/release-fixture";
  readonly owner = "example";
  readonly repositoryUrl = "https://github.com/example/release-fixture";
  readonly pulls: Pull[] = [];
  readonly commitPulls = new Map<string, Pull[]>();
  readonly comments = new Map<number, { body: string }[]>();
  readonly writes: { method: string; path: string; body: Body }[] = [];
  beforeRefWrite: (() => void) | undefined;
  afterCommit: (() => void) | undefined;
  failPullCreation = false;

  constructor(readonly fixture: Fixture) {}

  addPull(branch: string, title: string, sha: string): Pull {
    const number = this.pulls.length + 1;
    const pull: Pull = {
      number,
      title,
      body: "",
      state: "open",
      draft: false,
      merged_at: null,
      head: { ref: branch, sha, repo: { full_name: this.repository } },
      base: { ref: "main" },
      html_url: `${this.repositoryUrl}/pull/${number}`,
      labels: [],
    };
    this.pulls.push(pull);
    return pull;
  }

  async list(path: string) {
    if (path.startsWith("commits/"))
      return this.commitPulls.get(path.split("/")[1]!) ?? [];
    if (path.startsWith("pulls?")) {
      const query = new URLSearchParams(path.split("?")[1]);
      const head = query.get("head")?.slice(`${this.owner}:`.length);
      const base = query.get("base");
      return this.pulls.filter(
        (pull) =>
          pull.state === query.get("state") &&
          (!head || pull.head.ref === head) &&
          (!base || pull.base.ref === base),
      );
    }
    if (path.startsWith("issues/"))
      return this.comments.get(Number(path.split("/")[1])) ?? [];
    throw new Error(`Unexpected list: ${path}`);
  }

  async request(
    method: string,
    path: string,
    body: Body = {},
  ): Promise<unknown> {
    if (method !== "GET") this.writes.push({ method, path, body });
    if (method === "GET" && path.startsWith("git/ref/heads/")) {
      const sha = this.fixture.head(path.slice("git/ref/heads/".length));
      if (!sha) throw apiError(404);
      return { object: { sha } };
    }
    if (path === "git/trees") {
      const entries = body["tree"] as {
        path: string;
        content?: string;
        sha?: null;
      }[];
      return {
        sha: this.fixture.tree(
          body["base_tree"] as string,
          Object.fromEntries(
            entries.map((entry) => [entry.path, entry.content ?? null]),
          ),
        ),
      };
    }
    if (path === "git/commits") {
      const parents = body["parents"] as string[];
      const sha = this.fixture
        .git(
          "commit-tree",
          body["tree"] as string,
          ...parents.flatMap((parent) => ["-p", parent]),
          "-m",
          body["message"] as string,
        )
        .trim();
      const callback = this.afterCommit;
      this.afterCommit = undefined;
      callback?.();
      return { sha };
    }
    if (path === "git/refs" || path.startsWith("git/refs/heads/")) {
      const callback = this.beforeRefWrite;
      this.beforeRefWrite = undefined;
      callback?.();
      const branch =
        path === "git/refs"
          ? (body["ref"] as string).slice("refs/heads/".length)
          : path.slice("git/refs/heads/".length);
      const current = this.fixture.head(branch);
      const next = body["sha"] as string;
      if (method === "POST" && current) throw apiError(422);
      if (current) {
        expect(body["force"]).toBe(false);
        try {
          this.fixture.git("merge-base", "--is-ancestor", current, next);
        } catch {
          throw apiError(422);
        }
      }
      this.fixture.git(
        "update-ref",
        `refs/heads/${branch}`,
        next,
        current ?? "0".repeat(40),
      );
      return { object: { sha: next } };
    }
    if (method === "POST" && path === "pulls") {
      if (this.failPullCreation) throw apiError(500);
      const branch = body["head"] as string;
      const pull = this.addPull(
        branch,
        body["title"] as string,
        this.fixture.head(branch)!,
      );
      pull.body = body["body"] as string;
      pull.draft = body["draft"] as boolean;
      return pull;
    }
    if (path.startsWith("pulls/")) {
      const pull = this.pulls.find(
        (candidate) => candidate.number === Number(path.split("/")[1]),
      )!;
      if (method === "PATCH") Object.assign(pull, body);
      return {
        ...pull,
        head: {
          ...pull.head,
          sha: this.fixture.head(pull.head.ref) ?? pull.head.sha,
        },
      };
    }
    if (method === "POST" && path.startsWith("issues/")) {
      const number = Number(path.split("/")[1]);
      const comments = this.comments.get(number) ?? [];
      comments.push({ body: body["body"] as string });
      this.comments.set(number, comments);
      return {};
    }
    throw new Error(`Unexpected request: ${method} ${path}`);
  }
}

describe("GitHub request transport", () => {
  test("recovers from an errored response body without duplicating paginated results", async () => {
    const pages: number[] = [];
    const github = createGitHubClient(
      "example/release-fixture",
      "synthetic-release-token",
      async (url, options) => {
        expect(options.method).toBe("GET");
        const page = Number(new URL(url).searchParams.get("page"));
        pages.push(page);
        if (pages.length === 2) {
          const body = new ReadableStream({
            start(controller) {
              controller.error(new Error("Synthetic response body failure"));
            },
          });
          return new Response(body, { status: 500 });
        }
        return Response.json([{ number: page }], {
          headers:
            page === 1
              ? {
                  link: '<https://api.github.com/repos/example/release-fixture/pulls?per_page=1&page=2>; rel="next"',
                }
              : {},
        });
      },
    );
    expect(await github.list("pulls?per_page=1")).toEqual([
      { number: 1 },
      { number: 2 },
    ]);
    expect(pages).toEqual([1, 2, 2]);
  });

  test("reports a persistent server error after bounded read retries", async () => {
    let requests = 0;
    const github = createGitHubClient(
      "example/release-fixture",
      "synthetic-release-token",
      async () => {
        requests++;
        return Response.json({ message: "Unavailable" }, { status: 503 });
      },
    );
    await expect(
      github.request("GET", "git/ref/heads/main"),
    ).rejects.toMatchObject({
      status: 503,
      message: "GitHub GET git/ref/heads/main failed with HTTP 503.",
    });
    expect(requests).toBe(3);
  });

  test.each([
    ["POST", 500],
    ["PATCH", 503],
    ["GET", 403],
    ["GET", 404],
    ["GET", 422],
  ])(
    "does not replay a %s request that fails with HTTP %i",
    async (method, status) => {
      let requests = 0;
      const github = createGitHubClient(
        "example/release-fixture",
        "synthetic-release-token",
        async () => {
          requests++;
          return Response.json({ message: "Failed request" }, { status });
        },
      );
      await expect(github.request(method, "pulls")).rejects.toMatchObject({
        status,
      });
      expect(requests).toBe(1);
    },
  );

  test("creates and updates a draft through serialized requests, including a concurrent commit conflict", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    let conflicts = 0;
    const github = createGitHubClient(
      fixture.github.repository,
      "synthetic-release-token",
      async (url, options) => {
        const endpoint = new URL(url);
        expect(endpoint.origin).toBe("https://api.github.com");
        expect(new Headers(options.headers).get("Authorization")).toBe(
          "Bearer synthetic-release-token",
        );
        const path =
          endpoint.pathname.slice(
            `/repos/${fixture.github.repository}/`.length,
          ) + endpoint.search;
        const method = options.method!;
        try {
          const value =
            method === "GET" &&
            (path.startsWith("commits/") ||
              path.startsWith("pulls?") ||
              path.startsWith("issues/"))
              ? await fixture.github.list(path)
              : await fixture.github.request(
                  method,
                  path,
                  options.body ? JSON.parse(String(options.body)) : undefined,
                );
          return Response.json(value, {
            status: method === "POST" ? 201 : 200,
          });
        } catch (error) {
          const status = (error as { status?: number }).status;
          if (status === undefined) throw error;
          if (status === 422) conflicts++;
          return Response.json(
            { message: "Synthetic GitHub failure" },
            { status },
          );
        }
      },
    );
    const run = (dryRun = false) =>
      reconcileReleasePullRequest({ repo: fixture.repo, github, dryRun });
    expect((await run(true)).action).toBe("would-create");
    expect(fixture.github.writes).toHaveLength(0);
    const first = await run();
    fixture.merge("fix: later fix");
    fixture.github.beforeRefWrite = () => {
      const notes = fixture.repo.readFile(
        fixture.head(first.plan.branch)!,
        notesPath,
      )!;
      fixture.commit(
        first.plan.branch,
        {
          [notesPath]: notes.replace(
            "initial feature",
            "Human-reviewed release note",
          ),
        },
        "docs: review release notes",
      );
    };
    const updated = await run();
    expect(conflicts).toBe(1);
    expect(updated.pull).toBe(first.pull);
    expect(updated.plan.humanOwned).toEqual(["highlights"]);
    expect(updated.plan.files[notesPath]).toContain(
      "Human-reviewed release note",
    );
    expect(updated.reviewRequested).toBe(true);
    fixture.git(
      "merge-base",
      "--is-ancestor",
      first.headSha!,
      updated.headSha!,
    );
  });

  test.each([30, 100])(
    "follows %i-item pages without losing the original query",
    async (pageSize) => {
      const pages: number[] = [];
      const github = createGitHubClient(
        "example/release-fixture",
        "synthetic-release-token",
        async (url, options) => {
          const endpoint = new URL(url);
          expect(options.method).toBe("GET");
          expect(endpoint.searchParams.get("state")).toBe("open");
          expect(endpoint.searchParams.get("per_page")).toBe(String(pageSize));
          const page = Number(endpoint.searchParams.get("page"));
          pages.push(page);
          endpoint.searchParams.set("page", "2");
          return Response.json(
            page === 1
              ? Array.from({ length: pageSize }, (_, index) => ({
                  number: index + 1,
                }))
              : [{ number: pageSize + 1 }],
            {
              headers:
                page === 1 ? { link: `<${endpoint.href}>; rel="next"` } : {},
            },
          );
        },
      );
      const pulls = await github.list(`pulls?state=open&per_page=${pageSize}`);
      expect(pulls).toHaveLength(pageSize + 1);
      expect(pulls.at(-1)).toEqual({ number: pageSize + 1 });
      expect(pages).toEqual([1, 2]);
    },
  );
});

describe("release workflow controls", () => {
  const { permissions, jobs } = Bun.YAML.parse(workflow) as {
    permissions: Record<string, string>;
    jobs: Record<
      string,
      {
        if: string;
        permissions?: Record<string, string>;
        env: { RELEASE_PR_DRY_RUN: string };
        steps: { id?: string; if?: string }[];
      }
    >;
  };

  test.each([
    { dryRun: "false", clientId: "", createsAppToken: false },
    { dryRun: "false", clientId: "synthetic-app-id", createsAppToken: true },
    { dryRun: "true", clientId: "", createsAppToken: false },
    { dryRun: "true", clientId: "synthetic-app-id", createsAppToken: false },
  ])(
    "selects authentication for dry_run=$dryRun with client ID '$clientId'",
    ({ dryRun, clientId, createsAppToken }) => {
      const job = Object.values(jobs).find(
        ({ env }) => env.RELEASE_PR_DRY_RUN === dryRun,
      )!;
      const appToken = job.steps.find((step) => step.id === "app-token");
      const evaluate = new Function(
        "vars",
        `return (${appToken?.if ?? "false"});`,
      );
      expect(evaluate({ RELEASE_APP_CLIENT_ID: clientId })).toBe(
        createsAppToken,
      );
      const access = dryRun === "true" ? "read" : "write";
      expect(job.permissions ?? permissions).toEqual({
        contents: access,
        "pull-requests": access,
      });
    },
  );

  test.each([
    { event: "push", enabled: undefined, dryRun: undefined, expected: true },
    { event: "push", enabled: "false", dryRun: undefined, expected: true },
    { event: "push", enabled: "true", dryRun: undefined, expected: false },
    {
      event: "workflow_dispatch",
      enabled: undefined,
      dryRun: true,
      expected: true,
    },
    {
      event: "workflow_dispatch",
      enabled: undefined,
      dryRun: false,
      expected: false,
    },
    {
      event: "workflow_dispatch",
      enabled: "false",
      dryRun: false,
      expected: false,
    },
    {
      event: "workflow_dispatch",
      enabled: "true",
      dryRun: true,
      expected: true,
    },
    {
      event: "workflow_dispatch",
      enabled: "true",
      dryRun: false,
      expected: false,
    },
  ])(
    "selects preview mode for $event with enabled=$enabled and dry_run=$dryRun",
    ({ event, enabled, dryRun, expected }) => {
      const selectedJobs = Object.values(jobs).filter((job) => {
        const evaluate = new Function(
          "github",
          "inputs",
          "vars",
          `return (${job.if});`,
        );
        return evaluate(
          {
            event_name: event,
            repository: "openai/codex-security",
            ref: "refs/heads/main",
          },
          { dry_run: dryRun },
          { RELEASE_PR_ENABLED: enabled },
        );
      });
      expect(selectedJobs.map((job) => job.env.RELEASE_PR_DRY_RUN)).toEqual([
        String(expected),
      ]);
    },
  );
});

describe("pre-1.0 release policy", () => {
  test.each([
    "fix: repair output",
    "feat(sdk): add an option",
    "chore(deps): update a dependency",
    "docs: clarify setup",
    "test: add coverage",
  ])("uses a patch for %s", (title) => {
    expect(nextReleaseVersion("0.1.23", [change(title)])).toBe("0.1.24");
  });

  test.each([
    change("feat(sdk)!: remove an option"),
    change("fix: correct behavior", 1, {
      body: "Details.\n\nBREAKING CHANGE: old options were removed",
    }),
    change("chore: update behavior", 1, {
      body: "BREAKING-CHANGE: configuration changed",
    }),
    change("fix: correct behavior", 1, {
      labels: ["breaking-change", "skip-release-notes"],
    }),
  ])("uses a minor for a breaking change: $title", (breaking) => {
    expect(
      nextReleaseVersion("0.1.23", [change("fix: first fix"), breaking]),
    ).toBe("0.2.0");
  });

  test("recomputes the whole cycle, including hidden changes, without incrementing on reruns", () => {
    const changes = [
      change("feat: an addition"),
      change("fix!: incompatible behavior", 2, {
        labels: ["skip-release-notes"],
      }),
    ];
    const first = createReleasePlan(history(changes));
    const next = updatePlan(first, [...changes, change("fix: another fix", 3)]);
    expect(first.version).toBe("0.2.0");
    expect(next.version).toBe("0.2.0");
    expect(next.branch).toBe(first.branch);
    expect(next.files[notesPath]).not.toContain("incompatible behavior");
  });

  test("leaves an empty cycle at the merged version and does not invent a 1.x policy", () => {
    expect(nextReleaseVersion("0.1.23", [])).toBe("0.1.23");
    expect(() =>
      nextReleaseVersion("1.0.0", [change("feat: add behavior")]),
    ).toThrow("policy");
  });

  test.each([
    { format: "compact", indent: undefined },
    { format: "indented", indent: 2 },
  ])(
    "updates only the top-level package version with $format formatting",
    ({ indent }) => {
      const metadata = {
        config: { version: 'legacy "1.2.3"' },
        name: "@openai/codex-security",
        version: "0.1.23",
        dependencies: { example: "1.0.0" },
      };
      const text = `${JSON.stringify(metadata, null, indent)}\n`;
      const plan = createReleasePlan({
        ...history([change("fix: repair output")]),
        packageText: text,
      });
      expect(JSON.parse(plan.files[packagePath]!)).toEqual({
        ...metadata,
        version: "0.1.24",
      });
      expect(plan.files[packagePath]).toBe(
        text.replace('"0.1.23"', '"0.1.24"'),
      );
      const empty = createReleasePlan({ ...history([]), packageText: text });
      expect(empty.files[packagePath]).toBe(text);
    },
  );
});

describe("human note ownership", () => {
  test("keeps edited sections sticky while updating other sections and the header", () => {
    const first = createReleasePlan(history([change("feat: initial feature")]));
    const edited = first.files[notesPath]!.replace(
      "initial feature",
      "A reviewed explanation with [documentation](https://example.com/v0.1.24).",
    );
    const changes = [
      change("feat: initial feature"),
      change("fix!: new incompatible change", 2),
    ];
    const second = updatePlan(first, changes, edited);
    const third = updatePlan(second, [
      ...changes,
      change("feat: later feature", 3),
    ]);
    expect(third.version).toBe("0.2.0");
    expect(third.files[notesPath]).toContain("<!-- release-version: 0.2.0 -->");
    expect(third.files[notesPath]).toContain("A reviewed explanation");
    expect(third.files[notesPath]).toContain("https://example.com/v0.1.24");
    expect(third.files[notesPath]).not.toContain("later feature");
    expect(third.files[notesPath]).toContain("new incompatible change");
    expect(third.humanOwned).toEqual(["highlights"]);
    expect(third.generated.highlights).toContain("later feature");
    const originalBlock = first.files[notesPath]!.match(
      /<!-- release-section: highlights:start -->[\s\S]*?<!-- release-section: highlights:end -->/u,
    )![0];
    const restored = third.files[notesPath]!.replace(
      /<!-- release-section: highlights:start -->[\s\S]*?<!-- release-section: highlights:end -->/u,
      originalBlock,
    );
    const stillOwned = updatePlan(third, third.changes, restored);
    expect(stillOwned.humanOwned).toEqual(["highlights"]);
    expect(stillOwned.files[notesPath]).not.toContain("later feature");
  });

  test("preserves deletion, custom prose, and an explicit reset", () => {
    const first = createReleasePlan(history([change("feat: initial feature")]));
    const deleted = first.files[notesPath]!.replace(
      /<!-- release-section: upgrades:start -->[\s\S]*?<!-- release-section: upgrades:end -->/u,
      "A custom migration explanation.",
    );
    const second = updatePlan(
      first,
      [change("feat!: new interface", 2)],
      deleted,
    );
    const third = updatePlan(second, [
      change("feat!: new interface", 2),
      change("fix: later fix", 3),
    ]);
    expect(third.files[notesPath]).toContain("A custom migration explanation.");
    expect(third.files[notesPath]).not.toContain(
      "release-section: upgrades:start",
    );
    expect(third.humanOwned).toEqual(["upgrades"]);
    const state = JSON.parse(third.files[statePath]!);
    state.sections.upgrades.reset = true;
    const reset = createReleasePlan(history(third.changes), {
      notes: third.files[notesPath]!,
      state,
    });
    expect(reset.files[notesPath]).toContain("A custom migration explanation.");
    expect(reset.files[notesPath]).toContain("release-section: upgrades:start");
    expect(reset.humanOwned).toEqual([]);
  });

  test("does not recreate a deleted notes file or overwrite a section with edited markers", () => {
    const first = createReleasePlan(history([change("fix: initial fix")]));
    const deleted = updatePlan(first, [change("feat: new feature", 2)], null);
    expect(deleted.files[notesPath]).toBeNull();
    expect(
      updatePlan(deleted, [change("fix!: breaking fix", 3)]).files[notesPath],
    ).toBeNull();
    const edited = first.files[notesPath]!.replace(
      "release-section: highlights:start",
      "edited section boundary",
    );
    const preserved = updatePlan(
      first,
      [change("feat: new feature", 2)],
      edited,
    );
    expect(preserved.files[notesPath]).toContain("edited section boundary");
    expect(preserved.files[notesPath]).toContain("initial fix");
    expect(preserved.files[notesPath]).not.toContain("new feature");
  });

  test("preserves existing prose when a section loses its ownership metadata until explicitly reset", () => {
    const first = createReleasePlan(history([change("feat: initial feature")]));
    const notes = first.files[notesPath]!.replace(
      "initial feature",
      "Human-reviewed notes",
    );
    const state = JSON.parse(first.files[statePath]!);
    delete state.sections.highlights;
    const changes = [change("feat: later feature", 2)];
    const preserved = createReleasePlan(history(changes), { notes, state });
    expect(preserved.humanOwned).toEqual(["highlights"]);
    expect(preserved.files[notesPath]).toContain("Human-reviewed notes");
    expect(preserved.files[notesPath]).not.toContain("later feature");
    const nextState = JSON.parse(preserved.files[statePath]!);
    nextState.sections.highlights.reset = true;
    const reset = createReleasePlan(history(changes), {
      notes: preserved.files[notesPath] ?? null,
      state: nextState,
    });
    expect(reset.humanOwned).toEqual([]);
    expect(reset.files[notesPath]).toContain("later feature");
  });

  test("feeds the preserved canonical notes into the existing publisher", () => {
    const first = createReleasePlan(history([change("feat: initial feature")]));
    const edited = first.files[notesPath]!.replace(
      "initial feature",
      "Reviewed release behavior",
    );
    const updated = updatePlan(
      first,
      [change("fix!: breaking fix", 2)],
      edited,
    );
    const summary = parseReviewedReleaseNotes(
      updated.version,
      updated.files[notesPath]!,
    );
    const published = composeReleaseNotes(
      "Generated change inventory",
      summary,
    );
    expect(published).toContain("Reviewed release behavior");
    expect(published).toContain("Generated change inventory");
    expect(published).not.toContain("release-version:");
  });
});

describe("rolling release reconciliation", () => {
  test("previews without writes and then creates one draft, refreshes it, and reuses its branch", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature", {
      "plugins/codex-security/skills/example/SKILL.md":
        "Example plugin instructions.\n",
    });
    const preview = await fixture.run(true);
    expect(preview.action).toBe("would-create");
    expect(preview.plan.version).toBe("0.1.24");
    expect(fixture.github.writes).toHaveLength(0);
    const first = await fixture.run();
    expect(first.action).toBe("created");
    expect(first.reviewRequested).toBe(true);
    const pull = fixture.github.pulls.find(
      (candidate) => candidate.number === first.pull,
    )!;
    expect(pull.draft).toBe(true);
    expect(pull.body).toContain("- [ ]");
    pull.body += "\nMaintainer review and test results.\n";
    const humanBody = pull.body;
    fixture.merge("fix!: new interface", {
      "sdk/typescript/src/example.ts": "export const next = true;\n",
    });
    const second = await fixture.run();
    expect(second.action).toBe("updated");
    expect(second.pull).toBe(first.pull);
    expect(second.plan.version).toBe("0.2.0");
    expect(second.plan.branch).toBe(first.plan.branch);
    expect(pull.body).toBe(humanBody);
    expect(
      fixture.repo.readFile(second.headSha!, "sdk/typescript/src/example.ts"),
    ).toContain("next");
    expect(
      fixture.github.pulls.filter((candidate) => candidate.state === "open"),
    ).toHaveLength(1);
    expect(
      fixture.github.writes
        .filter(
          (write) =>
            write.path === `pulls/${pull.number}` && write.method === "PATCH",
        )
        .every((write) => Object.keys(write.body).join() === "title"),
    ).toBe(true);
    fixture.git("merge-base", "--is-ancestor", first.headSha!, second.headSha!);
    const writes = fixture.github.writes.length;
    expect((await fixture.run()).action).toBe("unchanged");
    expect(fixture.github.writes).toHaveLength(writes);
  });

  test("incorporates main-only changes without another proposal review or repeated commits", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    fixture.merge("test: add coverage", {
      "sdk/typescript/tests-ts/example.test.ts": "// Additional coverage.\n",
    });
    const updated = await fixture.run();
    expect(updated.action).toBe("updated");
    expect(updated.headSha).not.toBe(first.headSha);
    expect(updated.plan.files[packagePath]).toBe(first.plan.files[packagePath]);
    expect(updated.plan.files[notesPath]).toBe(first.plan.files[notesPath]);
    expect(updated.reviewRequested).toBe(false);
    expect(fixture.github.comments.get(first.pull!)).toHaveLength(1);
    expect(
      fixture.repo.readFile(
        updated.headSha!,
        "sdk/typescript/tests-ts/example.test.ts",
      ),
    ).toBe("// Additional coverage.\n");
    fixture.git(
      "merge-base",
      "--is-ancestor",
      fixture.head()!,
      updated.headSha!,
    );
    const writes = fixture.github.writes.length;
    const rerun = await fixture.run();
    expect(rerun.action).toBe("unchanged");
    expect(rerun.headSha).toBe(updated.headSha);
    expect(rerun.reviewRequested).toBe(false);
    expect(fixture.github.writes).toHaveLength(writes);
  });

  test("posts new suggestions for human-owned notes without repeating an unchanged proposal review", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    fixture.commit(
      first.plan.branch,
      {
        [notesPath]: first.plan.files[notesPath]!.replace(
          "initial feature",
          "Human-reviewed notes",
        ),
      },
      "docs: review release notes",
    );
    const reviewed = await fixture.run();
    const commentCount = fixture.github.comments.get(first.pull!)!.length;
    fixture.merge("feat: another feature");
    const updated = await fixture.run();
    expect(updated.plan.files).toEqual(reviewed.plan.files);
    expect(updated.reviewRequested).toBe(false);
    const comments = fixture.github.comments.get(first.pull!)!;
    expect(comments).toHaveLength(commentCount + 1);
    expect(comments.at(-1)!.body).toContain("another feature");
    expect(comments.at(-1)!.body).not.toContain("@codex review");
    const rerun = await fixture.run();
    expect(rerun.action).toBe("unchanged");
    expect(comments).toHaveLength(commentCount + 1);
  });

  test("recovers a failed review comment without another release commit", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const request = fixture.github.request.bind(fixture.github);
    let failComment = true;
    fixture.github.request = async (method, path, body) => {
      if (failComment && method === "POST" && path.startsWith("issues/")) {
        failComment = false;
        throw apiError(500);
      }
      return request(method, path, body);
    };
    await expect(fixture.run()).rejects.toThrow("HTTP 500");
    const head = fixture.head("release/next-0.1.23");
    const recovered = await fixture.run();
    expect(recovered.headSha).toBe(head!);
    expect(recovered.reviewRequested).toBe(true);
    expect(fixture.github.comments.get(recovered.pull!)).toHaveLength(1);
  });

  test("recovers review on a manual rerun after GitHub exposes the updated head", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    fixture.merge("fix: later fix");
    const request = fixture.github.request.bind(fixture.github);
    let headLagged = true;
    fixture.github.request = async (method, path, body) => {
      const result = structuredClone(await request(method, path, body));
      if (headLagged && method === "GET" && path === `pulls/${first.pull}`) {
        (result as Pull).head.sha = first.headSha!;
      }
      return result;
    };
    const pending = await fixture.run();
    expect(pending.reviewRequested).toBe(false);
    expect(pending.reason).toContain("Rerun");
    expect(fixture.github.comments.get(first.pull!)).toHaveLength(1);
    headLagged = false;
    const recovered = await fixture.run();
    expect(recovered.action).toBe("unchanged");
    expect(recovered.headSha).toBe(pending.headSha);
    expect(recovered.reviewRequested).toBe(true);
    expect(fixture.github.comments.get(first.pull!)).toHaveLength(2);
  });

  test("requests review when the proposal changes back to previously reviewed content", async () => {
    const fixture = new Fixture();
    const merged = fixture.merge("feat: initial feature");
    const first = await fixture.run();
    const mergedPull = fixture.github.commitPulls.get(merged)![0]!;
    mergedPull.title = "feat: reworded feature";
    expect((await fixture.run()).reviewRequested).toBe(true);
    mergedPull.title = "feat: initial feature";
    const restored = await fixture.run();
    expect(restored.plan.files).toEqual(first.plan.files);
    expect(restored.headSha).not.toBe(first.headSha);
    expect(restored.reviewRequested).toBe(true);
    expect(fixture.github.comments.get(first.pull!)).toHaveLength(3);
  });

  test("retries a concurrent human commit without dropping its notes or history", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    fixture.merge("fix: later fix");
    let humanSha = "";
    fixture.github.beforeRefWrite = () => {
      const notes = fixture.repo.readFile(
        fixture.head(first.plan.branch)!,
        notesPath,
      )!;
      humanSha = fixture.commit(
        first.plan.branch,
        {
          [notesPath]: notes.replace(
            "initial feature",
            "Human migration details",
          ),
        },
        "docs: review release notes",
      );
    };
    const result = await fixture.run();
    expect(result.plan.humanOwned).toEqual(["highlights"]);
    expect(result.plan.files[notesPath]).toContain("Human migration details");
    fixture.git("merge-base", "--is-ancestor", humanSha, result.headSha!);
    expect(fixture.github.comments.get(result.pull!)!.at(-1)!.body).toContain(
      "later fix",
    );
  });

  test("recomputes when main moves during the update", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    fixture.github.afterCommit = () => {
      fixture.merge("fix!: concurrent breaking change");
    };
    const result = await fixture.run();
    expect(result.plan.version).toBe("0.2.0");
    expect(result.plan.mainSha).toBe(fixture.head()!);
    expect(
      fixture.github.pulls.filter((pull) => pull.state === "open"),
    ).toHaveLength(1);
  });

  test.each(["closed", "retargeted", "ready"])(
    "does not request review after a PR is %s during its final checks",
    async (change) => {
      const fixture = new Fixture();
      fixture.merge("feat: initial feature");
      const first = await fixture.run();
      const pull = fixture.github.pulls.find(
        (candidate) => candidate.number === first.pull,
      )!;
      const commentCount = fixture.github.comments.get(pull.number)!.length;
      fixture.merge("fix: another fix");
      const request = fixture.github.request.bind(fixture.github);
      let reads = 0;
      fixture.github.request = async (method, path, body) => {
        const result = structuredClone(await request(method, path, body));
        if (
          method === "GET" &&
          path === `pulls/${pull.number}` &&
          ++reads === 1
        ) {
          if (change === "closed") pull.state = "closed";
          else if (change === "retargeted") pull.base.ref = "maintenance";
          else pull.draft = false;
        }
        return result;
      };
      const held = await fixture.run();
      expect(held.action).toBe("held");
      expect(held.reason).toContain(
        change === "ready" ? "draft" : "closed or retargeted",
      );
      expect(fixture.github.comments.get(pull.number)).toHaveLength(
        commentCount,
      );
    },
  );

  test("opens the next empty draft after repeated updates are squash-merged, without waiting for publication", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    const pull = fixture.github.pulls.find(
      (candidate) => candidate.number === first.pull,
    )!;
    fixture.merge("fix: another change before release");
    const updated = await fixture.run();
    expect(updated.headSha).not.toBe(first.headSha);
    fixture.merge(updated.plan.title, updated.plan.files);
    pull.state = "closed";
    pull.merged_at = "2026-01-01T00:00:00Z";
    const second = await fixture.run();
    expect(second.pull).not.toBe(first.pull);
    expect(second.plan.branch).not.toBe(first.plan.branch);
    expect(second.plan.baseVersion).toBe("0.1.24");
    expect(second.plan.version).toBe("0.1.24");
    expect(second.plan.changes).toHaveLength(0);
    expect(fixture.repo.readFile(second.headSha!, packagePath)).toBe(
      packageText("0.1.24"),
    );
    fixture.merge("feat: next feature");
    const third = await fixture.run();
    expect(third.pull).toBe(second.pull);
    expect(third.plan.version).toBe("0.1.25");
  });

  test("does not touch another release PR or recreate an intentionally closed proposal", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const manual = fixture.github.addPull(
      "manual-release",
      "release: prepare a release",
      fixture.head()!,
    );
    const held = await fixture.run();
    expect(held.action).toBe("held");
    expect(held.reason).toContain(`#${manual.number}`);
    expect(fixture.github.writes).toHaveLength(0);
    manual.state = "closed";
    const created = await fixture.run();
    const pull = fixture.github.pulls.find(
      (candidate) => candidate.number === created.pull,
    )!;
    pull.state = "closed";
    const writes = fixture.github.writes.length;
    expect((await fixture.run()).action).toBe("held");
    expect(fixture.github.writes).toHaveLength(writes);
    pull.state = "open";
    expect((await fixture.run()).pull).toBe(pull.number);
  });

  test("does not create a duplicate when a manual release PR opens during preparation", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    fixture.github.beforeRefWrite = () => {
      fixture.github.addPull(
        "manual-release",
        "release: prepare a manual release",
        fixture.head()!,
      );
    };
    expect((await fixture.run()).action).toBe("held");
    expect(
      fixture.github.pulls.filter((pull) => pull.state === "open"),
    ).toHaveLength(1);
  });

  test("preserves a deleted notes file on the remote branch", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    fixture.commit(
      first.plan.branch,
      { [notesPath]: null },
      "docs: remove draft notes",
    );
    fixture.merge("fix: another fix");
    const next = await fixture.run();
    expect(fixture.repo.readFile(next.headSha!, notesPath)).toBeNull();
    expect(next.plan.humanOwned).toEqual(["highlights", "upgrades"]);
  });

  test.each([
    { "sdk/typescript/src/example.ts": "Human implementation changes.\n" },
    { [packagePath]: packageText("0.1.24", { example: "1.0.0" }) },
  ])("pauses instead of losing unrelated human edits", async (files) => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    const humanSha = fixture.commit(
      first.plan.branch,
      files,
      "fix: additional human changes",
    );
    const writes = fixture.github.writes.length;
    for (const title of [
      "fix: first fix",
      "fix: second fix",
      "fix: third fix",
    ]) {
      fixture.merge(title);
      const held = await fixture.run();
      expect(held.action).toBe("held");
      expect(held.reason).toContain("edits");
      expect(fixture.head(first.plan.branch)).toBe(humanSha);
      expect(fixture.github.writes).toHaveLength(writes);
    }
  });

  test("recovers a branch whose PR creation failed without another commit or a duplicate PR", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    fixture.github.failPullCreation = true;
    await expect(fixture.run()).rejects.toThrow("HTTP 500");
    const head = fixture.head("release/next-0.1.23");
    fixture.github.failPullCreation = false;
    const result = await fixture.run();
    expect(result.action).toBe("created");
    expect(result.headSha).toBe(head!);
    expect(
      fixture.github.pulls.filter((pull) => pull.state === "open"),
    ).toHaveLength(1);
  });

  test("deduplicates rebased PRs and recognizes breaking direct commits", async () => {
    const fixture = new Fixture();
    const first = fixture.merge("feat: a rebased feature");
    const second = fixture.commit("main", {}, "feat: follow-up commit");
    fixture.github.commitPulls.set(
      second,
      fixture.github.commitPulls.get(first)!,
    );
    fixture.commit(
      "main",
      {},
      "fix: direct commit\n\nBREAKING CHANGE: configuration changes",
    );
    const releaseHistory = await readReleaseHistory(
      fixture.repo,
      fixture.head()!,
      fixture.github,
    );
    expect(releaseHistory.changes).toHaveLength(2);
    expect(
      nextReleaseVersion(releaseHistory.baseVersion, releaseHistory.changes),
    ).toBe("0.2.0");
    expect(JSON.stringify(releaseHistory.changes)).not.toContain(
      "BREAKING CHANGE:",
    );
  });

  test("uses the merge commit as the boundary for a release merged without squashing", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    const releaseTree = fixture
      .git("rev-parse", `${first.headSha}^{tree}`)
      .trim();
    const merged = fixture
      .git(
        "commit-tree",
        releaseTree,
        "-p",
        fixture.head()!,
        "-p",
        first.headSha!,
        "-m",
        first.plan.title,
      )
      .trim();
    fixture.git("update-ref", "refs/heads/main", merged);
    fixture.merge("fix: next change");
    const releaseHistory = await readReleaseHistory(
      fixture.repo,
      fixture.head()!,
      fixture.github,
    );
    expect(releaseHistory.baseCommit).toBe(merged);
    expect(releaseHistory.baseVersion).toBe("0.1.24");
    expect(releaseHistory.changes).toHaveLength(1);
    expect(
      nextReleaseVersion(releaseHistory.baseVersion, releaseHistory.changes),
    ).toBe("0.1.25");
  });
});

describe("release proposal pauses", () => {
  test.each(["open", "closed"] as const)(
    "keeps a retargeted %s proposal paused across workflow runs",
    async (state) => {
      const fixture = new Fixture();
      fixture.merge("feat: initial feature");
      const first = await fixture.run();
      const pull = fixture.github.pulls.find(
        (candidate) => candidate.number === first.pull,
      )!;
      pull.base.ref = "maintenance";
      pull.state = state;
      fixture.merge("fix: later fix");
      const writes = fixture.github.writes.length;
      const held = await fixture.run();
      expect(held.action).toBe("held");
      expect(held.reason).toContain(state === "open" ? "retargeted" : "closed");
      expect(fixture.head(first.plan.branch)).toBe(first.headSha!);
      expect(fixture.github.writes).toHaveLength(writes);
      expect(
        fixture.github.pulls.filter(
          (candidate) => candidate.head.ref === first.plan.branch,
        ),
      ).toHaveLength(1);
      pull.base.ref = "main";
      pull.state = "open";
      const resumed = await fixture.run();
      expect(resumed.action).toBe("updated");
      expect(resumed.pull).toBe(first.pull);
    },
  );

  test("does not pause for an unrelated release targeting another base", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const maintenance = fixture.github.addPull(
      "maintenance-release",
      "release: prepare a maintenance release",
      fixture.head()!,
    );
    maintenance.base.ref = "maintenance";
    const result = await fixture.run();
    expect(result.action).toBe("created");
    expect(result.pull).not.toBe(maintenance.number);
    expect(maintenance.base.ref).toBe("maintenance");
  });

  test("pauses recovery when the orphan branch gains a PR targeting another base", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    fixture.github.failPullCreation = true;
    await expect(fixture.run()).rejects.toThrow("HTTP 500");
    fixture.github.failPullCreation = false;
    const branch = "release/next-0.1.23";
    const previousHead = fixture.head(branch)!;
    fixture.merge("fix: later fix");
    fixture.github.afterCommit = () => {
      const pull = fixture.github.addPull(
        branch,
        "release: review the existing proposal",
        previousHead,
      );
      pull.base.ref = "maintenance";
    };
    const held = await fixture.run();
    expect(held.action).toBe("held");
    expect(held.reason).toContain("retargeted");
    expect(fixture.head(branch)).toBe(previousHead);
    expect(
      fixture.github.pulls.filter((candidate) => candidate.head.ref === branch),
    ).toHaveLength(1);
  });

  test("keeps a ready release proposal frozen until it returns to draft", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    const pull = fixture.github.pulls.find(
      (candidate) => candidate.number === first.pull,
    )!;
    pull.draft = false;
    pull.body += "\nMaintainer completed the final review.\n";
    const reviewedBody = pull.body;
    const reviewedTitle = pull.title;
    const reviewedHead = fixture.head(first.plan.branch);
    fixture.merge("feat!: later breaking change");
    const writes = fixture.github.writes.length;
    const held = await fixture.run();
    expect(held.action).toBe("held");
    expect(held.reason).toContain("draft");
    expect(fixture.head(first.plan.branch)).toBe(reviewedHead);
    expect(fixture.github.writes).toHaveLength(writes);
    expect(pull.title).toBe(reviewedTitle);
    expect(pull.body).toBe(reviewedBody);
    pull.draft = true;
    const resumed = await fixture.run();
    expect(resumed.action).toBe("updated");
    expect(resumed.pull).toBe(first.pull);
    expect(resumed.plan.version).toBe("0.2.0");
  });

  test("does not advance a proposal marked ready during preparation", async () => {
    const fixture = new Fixture();
    fixture.merge("feat: initial feature");
    const first = await fixture.run();
    const pull = fixture.github.pulls.find(
      (candidate) => candidate.number === first.pull,
    )!;
    fixture.merge("fix: later fix");
    fixture.github.afterCommit = () => {
      pull.draft = false;
    };
    const held = await fixture.run();
    expect(held.action).toBe("held");
    expect(fixture.head(first.plan.branch)).toBe(first.headSha!);
  });

  test.each(["new", "existing"])(
    "pauses before writing a %s release branch when another release opens",
    async (proposal) => {
      const hasPull = proposal === "existing";
      const fixture = new Fixture();
      fixture.merge("feat: initial feature");
      const first = hasPull ? await fixture.run() : null;
      if (first) fixture.merge("fix: later fix");
      const branch = first?.plan.branch ?? "release/next-0.1.23";
      const previousHead = fixture.head(branch);
      fixture.github.afterCommit = () => {
        fixture.github.addPull(
          "manual-release",
          "release: prepare a manual release",
          fixture.head()!,
        );
      };
      const held = await fixture.run();
      expect(held.action).toBe("held");
      expect(held.reason).toContain("Another release PR");
      expect(fixture.head(branch)).toBe(previousHead);
      expect(
        fixture.github.pulls.filter((candidate) => candidate.state === "open"),
      ).toHaveLength(hasPull ? 2 : 1);
    },
  );
});
