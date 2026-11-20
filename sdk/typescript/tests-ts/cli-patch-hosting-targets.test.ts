import { describe, expect, test } from "bun:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runLocalHostingTransport,
  runWorkflow,
  savedScan,
  patchDirectories,
} from "./cli-patch-fixtures.js";
import { pathToFileURL } from "node:url";

describe("GitHub patch endpoint ports", () => {
  const fixtures = patchDirectories();

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

describe("GitLab patch destinations", () => {
  const fixtures = patchDirectories();

  test.each([
    ...[false, true].flatMap((resume) =>
      [
        "fork HTTPS",
        "fork SSH",
        "self-managed SSH alias fork",
        "self-managed IPv6 SSH alias fork",
        "same project",
        "local fetch",
        "different port mirror",
        "default port mirror",
        "same port fork",
        "explicit default port fork",
        "explicit HTTP port fork",
        "explicit SSH default port fork",
        "implicit SSH default port fork",
        "distinct SSH transport ports fork",
        "git+ssh transport port fork",
        "ssh+git transport port fork",
      ].map((mode) => ({
        mode,
        resume,
      })),
    ),
    ...[
      "file fetch",
      "fork credentials",
      "GitHub mirror",
      "Bitbucket mirror",
      "GitLab instance mirror",
      "self-managed fork",
      "same project over SSH",
      "existing fork request",
      "other fork request",
      "upstream request",
      "different saved commit",
      "source lookup failure",
    ].map((mode) => ({ mode, resume: true })),
  ])(
    "uses the selected source and target: $mode, resume=$resume",
    async ({ mode, resume }) => {
      const { directory, git, remote } = await publicationRepository(fixtures);
      const portCase = mode.includes("port");
      const alias = mode.endsWith("SSH alias fork");
      const ipv6 = mode === "self-managed IPv6 SSH alias fork";
      const host = ipv6
        ? "[2001:db8::1]"
        : mode === "self-managed fork" || alias || portCase
          ? "gitlab.example.test"
          : "gitlab.com";
      const sshScheme =
        mode === "git+ssh transport port fork"
          ? "git+ssh"
          : mode === "ssh+git transport port fork"
            ? "ssh+git"
            : undefined;
      const explicitDefault = mode.startsWith("explicit");
      const protocol = mode === "explicit HTTP port fork" ? "http" : "https";
      const fetchPort = explicitDefault
        ? protocol === "http"
          ? ":80"
          : ":443"
        : portCase && mode !== "default port mirror"
          ? ":8443"
          : "";
      const pushPort =
        portCase && !explicitDefault
          ? mode === "different port mirror"
            ? ":9443"
            : ":8443"
          : "";
      const upstream =
        mode === "explicit SSH default port fork"
          ? `ssh://git@${host}:22/example/repository.git`
          : mode === "implicit SSH default port fork"
            ? `ssh://git@${host}/example/repository.git`
            : mode === "distinct SSH transport ports fork"
              ? `ssh://git@${host}:2222/example/repository.git`
              : sshScheme
                ? `${sshScheme}://git@${host}:2222/example/repository.git`
                : `${protocol}://${host}${fetchPort}/example/repository.git`;
      const fork =
        mode === "explicit SSH default port fork" || sshScheme
          ? `git@${host}:synthetic-user/repository.git`
          : mode === "implicit SSH default port fork"
            ? `ssh://git@${host}:22/synthetic-user/repository.git`
            : mode === "distinct SSH transport ports fork"
              ? `ssh://git@${host}:2200/synthetic-user/repository.git`
              : `${protocol}://${host}${pushPort}/synthetic-user/repository.git`;
      const sameProject = mode.startsWith("same project");
      const localFetch = mode === "local fetch" || mode === "file fetch";
      const push = alias
        ? "git@gitlab-work:synthetic-user/repository.git"
        : mode === "fork credentials"
          ? "https://synthetic-user:synthetic-token@gitlab.com/synthetic-user/repository.git"
          : mode === "fork SSH"
            ? "git@gitlab.com:synthetic-user/repository.git"
            : mode === "same project over SSH"
              ? "ssh://git@gitlab.com/example/repository.git"
              : sameProject
                ? upstream
                : fork;
      const source =
        mode === "explicit SSH default port fork" || sshScheme || alias
          ? `ssh://git@${host}/synthetic-user/repository.git`
          : mode === "fork credentials"
            ? fork
            : mode === "fork SSH"
              ? "ssh://git@gitlab.com/synthetic-user/repository.git"
              : push;
      const mirror = mode.endsWith("mirror");
      const target = localFetch || mirror ? source : upstream;
      const sshConfig = alias
        ? join(await fixtures.create("gitlab-ssh-config-"), "config")
        : undefined;
      if (sshConfig)
        await writeFile(
          sshConfig,
          `Host gitlab-work\n  Hostname ${ipv6 ? "2001:0db8:0:0:0:0:0:1" : host}\n`,
        );
      const sourceId = sameProject ? 11 : 22;
      const targetId = localFetch || mirror ? sourceId : 11;
      git(
        "remote",
        "set-url",
        "origin",
        mode === "local fetch"
          ? remote
          : mode === "file fetch"
            ? pathToFileURL(remote).href
            : mirror && !portCase
              ? `https://${mode === "GitHub mirror" ? "github.com" : mode === "Bitbucket mirror" ? "bitbucket.org" : "gitlab.example.test"}/example/repository.git`
              : mode === "fork credentials"
                ? "https://synthetic-user:synthetic-token@gitlab.com/example/repository.git"
                : upstream,
      );
      git("remote", "set-url", "--push", "origin", push);
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", "HEAD");
      if (resume) {
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
      }
      const existing =
        mode === "existing fork request" || mode === "different saved commit";
      const requestSource =
        mode === "other fork request"
          ? 33
          : mode === "upstream request"
            ? targetId
            : sourceId;
      const hasRequest = existing || mode.endsWith("request");
      const url = "https://gitlab.com/example/repository/-/merge_requests/14";
      const listedTargets: string[] = [];
      const creations: string[][] = [];
      let preflights = 0;
      let patches = 0;
      let pushes = 0;
      let lookups = 0;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment: sshConfig
            ? {
                GITLAB_HOST: host,
                GIT_SSH_COMMAND:
                  "ssh -F '" +
                  sshConfig.replaceAll("\\", "/").replaceAll("'", "'\\''") +
                  "'",
              }
            : mode === "self-managed fork" || portCase
              ? { GITLAB_HOST: host }
              : {},
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            patches++;
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("ls-remote")) {
                preflights++;
                return runLocalHostingTransport(
                  command,
                  ["ls-remote", "--heads", "--", remote],
                  cwd,
                  options,
                );
              }
              if (args[0] === "push") {
                pushes++;
                return runLocalHostingTransport(
                  command,
                  args.map((arg) => (arg === "origin" ? remote : arg)),
                  cwd,
                  options,
                );
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe("glab");
            if (args[0] === "repo") {
              expect(args).toEqual([
                "repo",
                "view",
                source,
                "--output",
                "json",
                "--jq",
                ".id",
              ]);
              lookups++;
              if (mode === "source lookup failure")
                throw new Error("Synthetic project lookup unavailable");
              return String(sourceId);
            }
            if (args[1] === "list") {
              const selectedTarget = args[args.indexOf("--repo") + 1]!;
              listedTargets.push(selectedTarget);
              expect(args[args.indexOf("--source-branch") + 1]).toBe(branch);
              // Emulate glab's project filter against a branch-matched API row.
              const query = args[args.indexOf("--jq") + 1]!;
              const selectedSource = /\.source_project_id == (\d+)/u.exec(
                query,
              );
              const matches = selectedSource
                ? requestSource === Number(selectedSource[1])
                : requestSource === targetId;
              return hasRequest && selectedTarget === target && matches
                ? JSON.stringify({
                    url,
                    state: "opened",
                    head: mode === "different saved commit" ? "other" : commit,
                  })
                : "";
            }
            expect(args[1]).toBe("create");
            creations.push([...args]);
            return url;
          },
        },
        { localHosting: false },
      );
      if (mode === "explicit HTTP port fork") {
        expect(outcome.exitCode).toBe(2);
        expect(outcome.stderr).toContain("plain HTTP origin URL");
        expect(preflights).toBe(0);
        expect(patches).toBe(0);
        expect(lookups).toBe(0);
        expect(listedTargets).toEqual([]);
        expect(creations).toEqual([]);
        expect(pushes).toBe(0);
        return;
      }
      const blocked =
        mode === "different saved commit" || mode === "source lookup failure";
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      if (mode === "source lookup failure") {
        expect(outcome.stderr).toContain(
          "Synthetic project lookup unavailable",
        );
        expect(listedTargets).toEqual([]);
      } else {
        expect(listedTargets.length).toBeGreaterThan(0);
        expect(new Set(listedTargets)).toEqual(new Set([target]));
      }
      if (mode === "different saved commit")
        expect(outcome.stderr).toContain(
          "does not match the saved patch commit or is no longer open",
        );
      expect(lookups > 0).toBe(source !== target);
      expect(creations.length).toBe(existing || blocked ? 0 : 1);
      expect(pushes).toBe(creations.length);
      if (creations.length) {
        const args = creations[0]!;
        expect(args[args.indexOf("--repo") + 1]).toBe(target);
        expect(args[args.indexOf("--head") + 1]).toBe(source);
        expect(git("--git-dir", remote, "rev-parse", branch)).toBe(
          git("rev-parse", branch),
        );
      }
      if (!blocked)
        expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
    },
  );
});
