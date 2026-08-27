import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Octokit } from "@octokit/core";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  createAuthenticatedGitHub,
  GITHUB_ALERT_STATES,
  importGitHubCodeScanningAlerts,
  type GitHubCodeScanningImportOptions,
} from "../src/github.js";
import { capture, dependencies, FakeSignals } from "./cli-fixtures.js";

function alert(number: number, ref = "refs/heads/main") {
  return {
    number,
    url: `https://api.github.com/repos/example/repository/code-scanning/alerts/${number}`,
    html_url: `https://github.com/example/repository/security/code-scanning/${number}`,
    state: "open",
    dismissed_reason: null,
    dismissed_comment: null,
    rule: {
      id: "synthetic/sql-injection",
      severity: "error",
      security_severity_level: "high",
      name: "Synthetic query finding",
      description: "A synthetic query candidate",
      full_description:
        "Synthetic full description for independent assessment.",
      help: "# Synthetic remediation\nUse parameter binding.",
      tags: ["security", "external/cwe/cwe-089"],
    },
    tool: { name: "Synthetic Scanner", version: "1.0.0", guid: null },
    most_recent_instance: {
      ref,
      commit_sha: "a".repeat(40),
      state: "open",
      message: { text: "Synthetic untrusted query input." },
      location: { path: "src/query.ts", start_line: number, end_line: number },
    },
  };
}

function github(
  respond: (
    url: URL,
    init?: Parameters<typeof fetch>[1],
  ) => Response | Promise<Response>,
): Octokit {
  return new Octokit({
    auth: "SYNTHETIC_GITHUB_TOKEN",
    request: {
      fetch: async (
        resource: Parameters<typeof fetch>[0],
        init?: Parameters<typeof fetch>[1],
      ) => {
        expect(init?.method).toBe("GET");
        expect(init?.redirect).toBe("error");
        return await respond(
          new URL(resource instanceof Request ? resource.url : resource),
          init,
        );
      },
    },
  });
}

describe("GitHub code scanning import", () => {
  test("paginates open alerts and preserves rule detail and selected-ref evidence", async () => {
    const paths: string[] = [];
    const client = github((url) => {
      paths.push(`${url.pathname}${url.search}`);
      if (url.pathname.endsWith("/alerts")) {
        expect(url.searchParams.get("state")).toBe("open");
        expect(url.searchParams.get("ref")).toBe("refs/heads/review");
        expect(url.searchParams.get("per_page")).toBe("100");
        const page = Number(url.searchParams.get("page"));
        const item = alert(page, "refs/heads/review");
        item.most_recent_instance.commit_sha = "b".repeat(40);
        return Response.json(
          [item],
          page === 1
            ? {
                headers: {
                  link: '<https://api.github.com/repos/example/repository/code-scanning/alerts?page=2>; rel="next"',
                },
              }
            : undefined,
        );
      }
      return Response.json(alert(Number(url.pathname.split("/").at(-1))));
    });
    const results = await importGitHubCodeScanningAlerts(
      { repository: "example/repository", ref: "refs/heads/review" },
      { createGitHub: async () => client },
    );
    expect(paths).toHaveLength(4);
    expect(results.map(({ number }) => number)).toEqual([1, 2]);
    expect(results[0]).toMatchObject({
      source: "github-code-scanning",
      repository: "example/repository",
      number: 1,
      url: alert(1).html_url,
      alert: {
        rule: alert(1).rule,
        tool: alert(1).tool,
        most_recent_instance: {
          ...alert(1, "refs/heads/review").most_recent_instance,
          commit_sha: "b".repeat(40),
        },
      },
    });
    expect(JSON.stringify(results)).not.toContain("SYNTHETIC_GITHUB_TOKEN");
  });

  test("imports exact alert numbers in requested order, including dismissed alerts", async () => {
    const paths: string[] = [];
    const client = github((url) => {
      paths.push(url.pathname);
      const item = alert(Number(url.pathname.split("/").at(-1)));
      return Response.json({
        ...item,
        state: "dismissed",
        dismissed_reason: "false positive",
        dismissed_comment: "Synthetic prior reviewer evidence.",
      });
    });
    const results = await importGitHubCodeScanningAlerts(
      { repository: "example/repository", alertNumbers: [42, 7, 42] },
      { createGitHub: async () => client },
    );
    expect(paths).toEqual([
      "/repos/example/repository/code-scanning/alerts/42",
      "/repos/example/repository/code-scanning/alerts/7",
    ]);
    expect(results.map(({ number }) => number)).toEqual([42, 7]);
    expect(results[0]!.alert).toMatchObject({
      state: "dismissed",
      dismissed_reason: "false positive",
      dismissed_comment: "Synthetic prior reviewer evidence.",
    });
  });

  test.each(["all", "dismissed"] as const)(
    "lists the requested %s state",
    async (state) => {
      const result = await importGitHubCodeScanningAlerts(
        { repository: "example/repository", state },
        {
          createGitHub: async () =>
            github((url) => {
              expect(url.searchParams.get("state")).toBe(
                state === "all" ? null : state,
              );
              expect(url.searchParams.has("ref")).toBe(false);
              return Response.json([]);
            }),
        },
      );
      expect(result).toEqual([]);
    },
  );

  test("selected alert numbers plus a ref retain that instance and do not filter state", async () => {
    const result = await importGitHubCodeScanningAlerts(
      { repository: "example/repository", alertNumbers: [7], ref: "review" },
      {
        createGitHub: async () =>
          github((url) => {
            if (url.pathname.endsWith("/alerts")) {
              expect(url.searchParams.get("state")).toBeNull();
              return Response.json([
                alert(8, "refs/heads/review"),
                alert(7, "refs/heads/review"),
              ]);
            }
            expect(url.pathname.endsWith("/7")).toBe(true);
            return Response.json(alert(7));
          }),
      },
    );
    expect(result).toHaveLength(1);
    expect(result[0]!.alert.most_recent_instance.ref).toBe("refs/heads/review");
    await expect(
      importGitHubCodeScanningAlerts(
        { repository: "example/repository", alertNumbers: [7], ref: "missing" },
        { createGitHub: async () => github(() => Response.json([])) },
      ),
    ).rejects.toThrow("not found on the requested reference");
  });

  test.each([
    [401, "authentication failed"],
    [403, "denied code scanning access"],
    [404, "not found or is not accessible"],
    [429, "rate limited"],
    [503, "HTTP 503"],
  ] as const)(
    "reports HTTP %i without exposing token-bearing diagnostics",
    async (status, message) => {
      const failure = await importGitHubCodeScanningAlerts(
        { repository: "example/repository" },
        {
          createGitHub: async () =>
            github(() =>
              Response.json({ message: "SYNTHETIC_GITHUB_TOKEN" }, { status }),
            ),
        },
      ).catch((error: Error) => error);
      expect(failure).toBeInstanceOf(Error);
      expect((failure as Error).message).toContain(message);
      expect((failure as Error).message).not.toContain(
        "SYNTHETIC_GITHUB_TOKEN",
      );
    },
  );

  test("validates selectors before authentication and supports cancellation", async () => {
    let authenticated = false;
    const createGitHub = async () => {
      authenticated = true;
      return github(() => Response.json([]));
    };
    for (const options of [
      { repository: "https://github.com/example/repository" },
      { repository: "example/.." },
      { repository: "example/repository", alertNumbers: [0] },
      { repository: "example/repository", alertNumbers: [1.5] },
      { repository: "example/repository", ref: " " },
      { repository: "example/repository", githubHost: "" },
      { repository: "example/repository", alertNumbers: [1], state: "all" },
    ] satisfies GitHubCodeScanningImportOptions[]) {
      await expect(
        importGitHubCodeScanningAlerts(options, { createGitHub }),
      ).rejects.toThrow();
    }
    await expect(
      importGitHubCodeScanningAlerts(
        {
          repository: "example/repository",
          signal: AbortSignal.abort(new Error("Synthetic cancellation")),
        },
        { createGitHub },
      ),
    ).rejects.toThrow("Synthetic cancellation");
    expect(authenticated).toBe(false);

    const controller = new AbortController();
    await expect(
      importGitHubCodeScanningAlerts(
        { repository: "example/repository", signal: controller.signal },
        {
          createGitHub: async () =>
            github(() => {
              controller.abort(new Error("Canceled after list"));
              return Response.json([alert(1)]);
            }),
        },
      ),
    ).rejects.toThrow("Canceled after list");
  });

  test("supports SDK tokens and Enterprise hosts without requiring gh", async () => {
    const client = await createAuthenticatedGitHub("github.example.com:8443", {
      token: "SYNTHETIC_SDK_TOKEN",
      environment: {},
    });
    expect(await client.auth()).toMatchObject({ token: "SYNTHETIC_SDK_TOKEN" });
    expect(client.request.endpoint("GET /user")).toMatchObject({
      url: "https://github.example.com:8443/api/v3/user",
    });
    await expect(
      createAuthenticatedGitHub("github.com", { token: " " }),
    ).rejects.toThrow("must not be empty");
  });
});

describe("GitHub import CLI", () => {
  test("emits complete JSON for file validation without starting Codex during import", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-github-import-"));
    try {
      const stdout = capture();
      const stderr = capture();
      const imported = await importGitHubCodeScanningAlerts(
        { repository: "example/repository", alertNumbers: [42] },
        { createGitHub: async () => github(() => Response.json(alert(42))) },
      );
      const mustNotStartCodex = () => {
        throw new Error("Import must not start Codex");
      };
      expect(
        await main(
          ["import", "github", "example/repository", "--json"],
          stdout.stream,
          stderr.stream,
          dependencies({
            importGitHubAlerts: async () => imported,
            onCodex: mustNotStartCodex,
            onRun: mustNotStartCodex,
          }),
        ),
      ).toBe(0);
      expect(stderr.text()).toBe("");
      expect(JSON.parse(stdout.text())).toEqual(imported);

      const file = join(root, "github-alerts.json");
      await writeFile(file, stdout.text());
      let input = "";
      expect(
        await main(
          ["validate", file],
          capture().stream,
          capture().stream,
          dependencies({
            currentDirectory: root,
            onCodex: (_args, _output, _environment, prompt) => {
              input = prompt!;
              return 0;
            },
          }),
        ),
      ).toBe(0);
      expect(JSON.parse(input.split("\n").at(-1)!)).toEqual([stdout.text()]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("routes repeated selectors, state, and ref and documents their schema", async () => {
    let options: GitHubCodeScanningImportOptions | undefined;
    const stdout = capture();
    expect(
      await main(
        [
          "import",
          "github",
          "example/repository",
          "--github-alert",
          "12",
          "--github-alert",
          "18",
          "--github-ref",
          "refs/heads/review",
          "--format",
          "json",
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          importGitHubAlerts: async (selected) => {
            options = selected;
            return [];
          },
        }),
      ),
    ).toBe(0);
    expect(options).toMatchObject({
      alertNumbers: [12, 18],
      ref: "refs/heads/review",
      state: "open",
    });
    expect(JSON.parse(stdout.text())).toEqual([]);
    const schema = capture();
    expect(
      await main(
        ["import", "github", "--schema", "--format", "json"],
        schema.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(schema.text())).toMatchObject({
      args: { required: ["repository"] },
      options: {
        properties: {
          githubAlert: { type: "array" },
          githubRef: { type: "string" },
          githubState: { default: "open", enum: [...GITHUB_ALERT_STATES] },
        },
      },
    });
  });

  test.each(
    [
      ["import", "github"],
      ["import", "github", "example/repository", "extra"],
      ["import", "github", "example/repository", "--github-alert"],
      ["import", "github", "example/repository", "--github-alert", "0"],
      ["import", "github", "example/repository", "--github-alert", "1.5"],
      ["import", "github", "example/repository", "--github-state", "unknown"],
    ].map((argv) => [argv] as const),
  )("rejects invalid arguments %j", async (argv) => {
    let called = false;
    expect(
      await main(
        argv,
        capture().stream,
        capture().stream,
        dependencies({
          importGitHubAlerts: async () => {
            called = true;
            return [];
          },
        }),
      ),
    ).toBe(2);
    expect(called).toBe(false);
  });

  test("returns cancellation and removes signal handlers", async () => {
    const signals = new FakeSignals();
    const stderr = capture();
    expect(
      await main(
        ["import", "github", "example/repository"],
        capture().stream,
        stderr.stream,
        dependencies({
          signals,
          importGitHubAlerts: async ({ signal }) => {
            signals.emit("SIGINT");
            signal!.throwIfAborted();
            return [];
          },
        }),
      ),
    ).toBe(130);
    expect(stderr.text()).toContain("canceled");
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });
});
