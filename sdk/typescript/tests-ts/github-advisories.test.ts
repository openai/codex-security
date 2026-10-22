import { Octokit } from "@octokit/core";
import { expect, mock, test } from "bun:test";
import {
  importGitHubAdvisories,
  type GitHubAdvisoryImportOptions,
} from "../src/github-advisories.js";
import { main } from "../src/cli.js";
import { dependencies, FakeSignals } from "./cli-fixtures.js";
import { captureCli, runCapturedCli } from "./support/cli-run.js";
import { importedAdvisory } from "./support/github-import-fixtures.js";

function client(respond: (url: URL) => Response): Octokit {
  return new Octokit({
    auth: "SYNTHETIC_ADVISORY_TOKEN",
    request: {
      fetch: async (
        resource: Parameters<typeof fetch>[0],
        init?: Parameters<typeof fetch>[1],
      ) => {
        expect(init?.method).toBe("GET");
        expect(init?.redirect).toBe("error");
        return respond(
          new URL(resource instanceof Request ? resource.url : resource),
        );
      },
    },
  });
}

test("repository advisory lists default to published and paginate cursors with full evidence", async () => {
  const paths: string[] = [];
  const github = client((url) => {
    paths.push(url.toString());
    expect(url.pathname).toBe("/repos/example/project/security-advisories");
    expect(url.searchParams.get("state")).toBe("published");
    expect(url.searchParams.get("per_page")).toBe("100");
    return Response.json(
      [importedAdvisory().advisory],
      url.searchParams.has("after")
        ? undefined
        : {
            headers: {
              link: '<https://api.github.com/repos/example/project/security-advisories?after=cursor-2>; rel="next"',
            },
          },
    );
  });
  const imported = await importGitHubAdvisories(
    { repository: "example/project" },
    { createGitHub: async () => github },
  );
  expect(paths).toHaveLength(2);
  expect(new URL(paths[1]!).searchParams.get("after")).toBe("cursor-2");
  expect(imported[0]).toEqual(importedAdvisory());
  expect(JSON.stringify(imported)).not.toContain("SYNTHETIC_ADVISORY_TOKEN");
});

test("global advisory selection uses only explicit deduplicated IDs and preserves the source family", async () => {
  const selected = importedAdvisory("global");
  const paths: string[] = [];
  const github = client((url) => {
    paths.push(url.pathname);
    return Response.json(selected.advisory);
  });
  const imported = await importGitHubAdvisories(
    {
      repository: "example/project",
      source: "global",
      advisoryIds: [selected.ghsaId.toLowerCase(), selected.ghsaId],
    },
    { createGitHub: async () => github },
  );
  expect(paths).toEqual([`/advisories/${selected.ghsaId}`]);
  expect(imported).toEqual([selected]);
});

test("explicit repository IDs allow private drafts without listing other advisories", async () => {
  const selected = importedAdvisory();
  const draft = { ...selected.advisory, state: "draft" as const };
  const github = client((url) => {
    expect(url.pathname).toBe(
      `/repos/example/project/security-advisories/${selected.ghsaId}`,
    );
    expect(url.searchParams.has("state")).toBe(false);
    return Response.json(draft);
  });
  const imported = await importGitHubAdvisories(
    { repository: "example/project", advisoryIds: [selected.ghsaId] },
    { createGitHub: async () => github },
  );
  expect(imported[0]!.advisory).toEqual(draft);
});

test("global crawl and misleading exact-ID state filters fail before GitHub authentication", async () => {
  const createGitHub = mock(async () => client(() => Response.json([])));
  await expect(
    importGitHubAdvisories(
      { repository: "example/project", source: "global" },
      { createGitHub },
    ),
  ).rejects.toThrow("explicit GHSA IDs");
  await expect(
    importGitHubAdvisories(
      {
        repository: "example/project",
        advisoryIds: [importedAdvisory().ghsaId],
        state: "draft",
      },
      { createGitHub },
    ),
  ).rejects.toThrow("only filters repository lists");
  expect(createGitHub).not.toHaveBeenCalled();
});

test("a later advisory page failure returns no incomplete selection", async () => {
  const github = client((url) =>
    url.searchParams.has("after")
      ? Response.json({ message: "Rate limit" }, { status: 429 })
      : Response.json([importedAdvisory().advisory], {
          headers: {
            link: '<https://api.github.com/repos/example/project/security-advisories?after=next>; rel="next"',
          },
        }),
  );
  await expect(
    importGitHubAdvisories(
      { repository: "example/project" },
      { createGitHub: async () => github },
    ),
  ).rejects.toThrow("rate limited");
});

test("GitHub advisory CLI exposes separate selection defaults and exact public IDs", async () => {
  let options: GitHubAdvisoryImportOptions | undefined;
  const output = captureCli(main, "stdout");
  expect(
    await output.run(
      [
        "import",
        "github-advisories",
        "example/project",
        "--github-advisory",
        importedAdvisory().ghsaId,
        "--github-advisory-source",
        "global",
        "--format",
        "json",
      ],
      dependencies({
        importGitHubAdvisories: async (value) => {
          options = value;
          return [importedAdvisory("global")];
        },
      }),
    ),
  ).toBe(0);
  expect(options).toMatchObject({
    repository: "example/project",
    source: "global",
    state: "published",
    advisoryIds: [importedAdvisory().ghsaId],
  });
  expect(JSON.parse(output.text())).toEqual([importedAdvisory("global")]);
  const schema = captureCli(main, "stdout");
  expect(
    await schema.run(
      ["import", "github-advisories", "--schema", "--format", "json"],
      dependencies(),
    ),
  ).toBe(0);
  expect(JSON.parse(schema.text())).toMatchObject({
    options: {
      properties: {
        githubAdvisorySource: { default: "repository" },
        githubState: { default: "published" },
      },
    },
  });
});

test("advisory CLI cancellation removes handlers and preserves its exit code", async () => {
  const signals = new FakeSignals();
  expect(
    await runCapturedCli(
      main,
      ["import", "github-advisories", "example/project"],
      dependencies({
        signals,
        importGitHubAdvisories: async ({ signal }) => {
          signals.emit("SIGINT");
          signal!.throwIfAborted();
          return [];
        },
      }),
    ),
  ).toBe(130);
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
});

for (const format of [
  "json",
  "jsonl",
  "toon",
  "yaml",
  "md",
  undefined,
] as const) {
  test.each([
    ["error", 2],
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)(
    `advisory CLI ${format} full output reports %s as failure`,
    async (failure, code) => {
      const signals = new FakeSignals();
      const output = captureCli(main, "stdout");
      expect(
        await output.run(
          [
            "import",
            "github-advisories",
            "example/project",
            ...(format === undefined ? [] : ["--format", format]),
            "--full-output",
          ],
          dependencies({
            signals,
            importGitHubAdvisories: async ({ signal }) => {
              if (failure === "error")
                throw new Error("advisory request failed");
              signals.emit(failure);
              signal!.throwIfAborted();
              return [];
            },
          }),
        ),
      ).toBe(code);
      if (format === "json" || format === "jsonl") {
        expect(JSON.parse(output.text())).toMatchObject({
          ok: false,
          error: {
            code: "GITHUB_IMPORT_FAILED",
            message: failure === "error" ? "advisory request failed" : failure,
          },
        });
      } else {
        expect(output.text()).toMatch(/(?:^ok:\s*|^## ok\s+)false/m);
        expect(output.text()).toContain("GITHUB_IMPORT_FAILED");
        expect(output.text()).toContain(
          failure === "error" ? "advisory request failed" : failure,
        );
      }
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
    },
  );
}
