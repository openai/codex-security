import { afterEach, describe, expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runLocalHostingTransport,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

describe("GitHub patch endpoint ports", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  test.each([
    ...[false, true].flatMap((resume) =>
      [
        {
          name: "distinct HTTPS ports",
          basePort: ":8443",
          pushPort: ":9443",
          matches: false,
        },
        {
          name: "default HTTPS push",
          basePort: ":8443",
          pushPort: "",
          matches: false,
        },
        {
          name: "default HTTPS base",
          basePort: "",
          pushPort: ":8443",
          matches: false,
        },
        {
          name: "same custom HTTPS port",
          basePort: ":8443",
          pushPort: ":8443",
          matches: true,
        },
        {
          name: "explicit default HTTPS push",
          basePort: "",
          pushPort: ":443",
          matches: true,
        },
        {
          name: "explicit default HTTPS base",
          basePort: ":443",
          pushPort: "",
          matches: true,
        },
      ].map((entry) => ({ ...entry, resume, existing: false })),
    ),
    {
      name: "distinct ports with a branch-matched request",
      basePort: ":8443",
      pushPort: ":9443",
      matches: false,
      resume: true,
      existing: true,
    },
  ])(
    "preserves endpoint identity: $name, resume=$resume",
    async ({ basePort, pushPort, matches, resume, existing }) => {
      const { directory, git, remote } = await publicationRepository(fixtures);
      const host = "github.example.test";
      const base = `https://${host}${basePort}/example/repository`;
      const push = `https://${host}${pushPort}/synthetic-user/repository.git`;
      git("remote", "set-url", "origin", `${base}.git`);
      git("remote", "set-url", "--push", "origin", push);
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", "HEAD");
      if (resume) {
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
      }
      const fullUrlOverride = resume && matches && Boolean(new URL(base).port);
      const selector = `${host}${basePort}/example/repository`;
      const override = fullUrlOverride
        ? `${base}.git`
        : matches && !basePort
          ? `${resume ? "ssh" : "http"}://synthetic-user:fixture@${host}:2222/example/repository.git`
          : selector;
      const selectorHost = new URL(base).host;
      const selectors: string[] = [];
      let pushes = 0;
      let creations = 0;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment: { GH_REPO: override },
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: async (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("ls-remote"))
                return runLocalHostingTransport(
                  command,
                  ["ls-remote", "--heads", "--", remote],
                  cwd,
                  options,
                );
              if (args[0] === "push") {
                pushes++;
                expect(git("remote", "get-url", "--push", "origin")).toBe(push);
                return runLocalHostingTransport(
                  command,
                  args.map((arg) => (arg === "origin" ? remote : arg)),
                  cwd,
                  options,
                );
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe("gh");
            if (args[1] === "list") {
              expect(args[args.indexOf("--repo") + 1]).toBe(
                `${host}${basePort}/example/repository`,
              );
              return JSON.stringify(
                existing
                  ? [
                      {
                        url: `${base}/pull/7`,
                        head: commit,
                        repositoryId: "synthetic-push-id",
                        state: "OPEN",
                        crossRepository: true,
                      },
                    ]
                  : [],
              );
            }
            if (args.at(-1) === ".url") {
              expect(args[2]).toBe(`${host}${basePort}/example/repository`);
              return base;
            }
            if (args[0] === "repo") {
              const selectedRemote = await runGitRepositoryCommand(
                "git",
                ["ls-remote", "--get-url", "codex-security-push"],
                cwd,
                options,
              );
              const selectedUrl = new URL(selectedRemote.trim());
              const selected = selectedUrl.pathname
                .replace(/^\/+|\/+$/gu, "")
                .replace(/\.git$/u, "");
              if (args[1] === "set-default") {
                expect(args).toEqual(["repo", "set-default", "--view"]);
                return selected;
              }
              expect(args).toEqual([
                "repo",
                "view",
                ...(new URL(base).port ? [`${selectorHost}/${selected}`] : []),
                "--json",
                "id,url",
                "--jq",
                "tojson",
              ]);
              selectors.push(`${selectorHost}/${selected}`);
              return JSON.stringify({
                id: selected.startsWith("synthetic-user/")
                  ? "synthetic-push-id"
                  : "synthetic-fetch-id",
                url: new URL(base).port
                  ? `https://${args[2]}`
                  : `${selectedUrl.protocol}//${selectedUrl.hostname}/${selected}`,
              });
            }
            expect(args[1]).toBe("create");
            expect(args[args.indexOf("--repo") + 1]).toBe(
              `${host}${basePort}/example/repository`,
            );
            expect(args[args.indexOf("--head") + 1]).toBe(
              `synthetic-user:${branch}`,
            );
            creations++;
            return `${base}/pull/8`;
          },
        },
        { localHosting: false },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(matches ? 0 : 2);
      expect(pushes).toBe(matches ? 1 : 0);
      expect(creations).toBe(matches ? 1 : 0);
      expect(git("remote", "get-url", "--push", "origin")).toBe(push);
      if (matches) {
        expect(git("--git-dir", remote, "rev-parse", branch)).toBe(
          git("rev-parse", branch),
        );
        expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(
          `${base}/pull/8`,
        );
      } else {
        expect(outcome.stderr).toContain(
          "Patch publication requires an origin push URL on the pull request host.",
        );
        expect(selectors).not.toContain(
          `${selectorHost}/synthetic-user/repository`,
        );
        expect(git("ls-remote", remote)).toBe("");
        const saved = git(
          "config",
          `branch.${branch}.codexSecurityPatchCommit`,
        );
        expect(saved).toBe(git("rev-parse", branch));
        expect(git("show", `${saved}:src/finding-1.ts`)).toBe(
          resume ? "original" : "fixed",
        );
      }
    },
  );

  for (const account of [
    "registered",
    "push-only",
    "unregistered",
    "malformed default",
  ] as const) {
    test.skipIf(!Bun.which("gh"))(
      `checks the ${account} authority of an enterprise upstream before using it`,
      async () => {
        const { directory, git } = await publicationRepository(fixtures);
        const config = await fixtures.create("gh-patch-account-");
        const host = "forge.example.test";
        const authority = `${host}:8443`;
        const base = `${authority}/upstream/repository`;
        const branch = "codex-security/patch-scan-1";
        const commit = git("rev-parse", "HEAD");
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
        git("remote", "set-url", "origin", `git@${host}:fork/repository.git`);
        const remoteUrl = `https://${authority}/mirror/repository.git`;
        if (account === "push-only")
          git("config", "remote.enterprise.pushurl", remoteUrl);
        else git("remote", "add", "enterprise", remoteUrl);
        const registered = account === "registered" || account === "push-only";
        git(
          "config",
          "remote.enterprise.gh-resolved",
          account === "malformed default"
            ? "invalid"
            : account === "push-only"
              ? `https://synthetic-user:fixture@${authority}/upstream/repository`
              : "upstream/repository",
        );
        git("config", "remote.empty.gh-resolved", "base");
        git("remote", "add", "unused", "https://%/nothing");
        const environment = {
          GH_CONFIG_DIR: config,
          GH_ENTERPRISE_TOKEN: "synthetic-enterprise-token",
          GH_NO_UPDATE_NOTIFIER: "1",
          GH_PROMPT_DISABLED: "1",
        };
        await writeFile(
          join(config, "hosts.yml"),
          `"${host}":\n  user: synthetic\n  oauth_token: synthetic-token\n` +
            (registered
              ? `"${authority}":\n  user: synthetic\n  oauth_token: synthetic-token\n`
              : ""),
        );
        const lists: string[][] = [];
        const status: string[][] = [];
        const outcome = await runWorkflow(
          ["patch", "--resume-pr", branch, "--json"],
          {
            currentDirectory: directory,
            environment,
            onRepositoryCommand: async (command, args, cwd, options) => {
              expect(args.join(" ")).not.toContain("synthetic-user:fixture@");
              if (command === "git") {
                expect(args[0]).not.toBe("push");
                return runGitRepositoryCommand(command, args, cwd, options);
              }
              expect(command).toBe("gh");
              if (args[0] === "auth") {
                if (args.includes("--help")) return "--active";
                status.push([...args]);
                if (account === "unregistered")
                  throw new Error("No account on the selected endpoint");
                return "";
              }
              if (args[1] === "set-default") {
                const result = await promisify(execFile)(
                  Bun.which("gh")!,
                  [...args],
                  {
                    cwd: options?.directory ?? cwd,
                    env: {
                      ...process.env,
                      ...environment,
                      ...options?.environment,
                    },
                  },
                );
                return result.stdout.trim();
              }
              if (args[1] === "list") {
                lists.push([...args]);
                return JSON.stringify([
                  {
                    url: `https://${base}/pull/7`,
                    head: commit,
                    state: "OPEN",
                    repositoryId: "R_fork",
                    crossRepository: true,
                  },
                ]);
              }
              expect(args.slice(0, 3)).toEqual([
                "repo",
                "view",
                `${authority}/fork/repository`,
              ]);
              return JSON.stringify({
                id: "R_fork",
                url: `https://${authority}/fork/repository`,
              });
            },
          },
          { localHosting: false },
        );
        expect(status, outcome.stderr).toEqual(
          account === "malformed default"
            ? []
            : [["auth", "status", "--hostname", authority, "--active"]],
        );
        expect(outcome.exitCode, outcome.stderr).toBe(registered ? 0 : 2);
        if (registered) {
          expect(lists).toHaveLength(1);
          expect(lists[0]!.slice(-2)).toEqual(["--repo", base]);
          expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(
            `https://${base}/pull/7`,
          );
        } else {
          expect(lists).toHaveLength(0);
          if (account === "unregistered")
            expect(outcome.stderr).toContain(
              "No account on the selected endpoint",
            );
        }
      },
    );
  }
});
