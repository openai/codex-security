import { describe, expect, test } from "bun:test";
import { symlink, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  publicationRepository,
  runPublicationCommand,
  patchDirectories,
  fixSavedFinding,
  createSavedPatchBranch,
  runHostedGit,
  runPublicationWorkflow,
  runSavedPublication,
} from "./cli-patch-fixtures.js";
import { pathToFileURL } from "node:url";

const branch = "codex-security/patch-scan-1";

describe("GitHub patch destinations", () => {
  const fixtures = patchDirectories();

  test.skipIf(process.platform === "win32").each(["stable", "replaced"])(
    "binds a relative GitHub CLI socket across the patch: %s",
    async (mode) => {
      const { directory } = await publicationRepository(fixtures);
      const caller = directory;
      const config = await fixtures.create("gh-");
      const name = " gh";
      await writeFile(
        join(config, "config.yml"),
        `http_unix_socket: "${name}"\n`,
      );
      const listen = (base: string) =>
        Bun.serve({ unix: join(base, name), fetch: () => new Response() });
      const sockets = [listen(caller)];
      let edited = false;
      let callsAfterEdit = 0;
      try {
        const outcome = await runPublicationWorkflow("issue", {
          currentDirectory: caller,
          environment: { GH_CONFIG_DIR: config },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "gh") {
              if (edited) callsAfterEdit++;
              if (args[0] === "config") {
                expect(args).toEqual(["config", "get", "http_unix_socket"]);
                return name + "\n";
              }
            }
            return runPublicationCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            if (mode === "replaced") {
              await unlink(join(caller, name));
              sockets.push(listen(caller));
            }
            edited = true;
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        });
        expect(edited, outcome.stderr).toBe(true);
        if (mode === "stable") {
          expect(outcome.exitCode, outcome.stderr).toBe(0);
          expect(callsAfterEdit).toBeGreaterThan(0);
        } else {
          expect(outcome.exitCode, outcome.stderr).toBe(2);
          expect(outcome.stderr).toContain(
            "GitHub CLI configuration changed before publication",
          );
          expect(callsAfterEdit).toBe(0);
        }
      } finally {
        for (const socket of sockets) await socket.stop(true);
      }
    },
  );

  test.each([
    ["GitHub", "creation"],
    ["GitLab", "creation"],
    ...(process.platform === "win32"
      ? []
      : [["GitLab", "symlink replacement"]]),
  ])(
    "rejects %s CLI config %s during the patch before reusing the provider",
    async (provider, mutation) => {
      const { directory, git } = await publicationRepository(fixtures);
      const gitlab = provider === "GitLab";
      const host = gitlab ? "gitlab.com" : "github.example.test";
      const config = join(directory, "src/config.yml");
      const replace = mutation === "symlink replacement";
      if (replace) {
        await writeFile(config, "{}\n");
        git("add", "src/config.yml");
        git("commit", "-m", "Initial provider configuration");
      }
      let edited = false;
      let providerCallsAfterEdit = 0;
      const outcome = await runPublicationWorkflow(
        "issue",
        {
          currentDirectory: directory,
          environment: gitlab
            ? { GLAB_CONFIG_DIR: "src" }
            : { GH_CONFIG_DIR: "src" },
          onRepositoryCommand: (command, args, cwd, options) => {
            if ((command === "gh" || command === "glab") && edited)
              providerCallsAfterEdit++;
            if (command === "glab" && args[1] === "list") return "";
            return runPublicationCommand(command, args, cwd, options);
          },
          onCodex: async (_args, output) => {
            if (replace) {
              await unlink(config);
              await symlink("routing.yml", config);
            }
            await writeFile(
              config,
              gitlab
                ? "hosts:\n  gitlab.com:\n    api_host: redirect.example.test\n"
                : "http_unix_socket: synthetic.sock\n",
            );
            edited = true;
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
        { hostingOrigin: `https://${host}/example/repository.git` },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        `${provider} CLI configuration changed before publication`,
      );
      expect(providerCallsAfterEdit).toBe(0);
    },
  );

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
      const commit = git("rev-parse", "HEAD");
      if (resume) createSavedPatchBranch(git, branch, commit);
      const selectorHost = new URL(base).host;
      const selectors: string[] = [];
      let pushes = 0;
      let creations = 0;
      const outcome = await runSavedPublication(
        directory,
        {
          environment: { GH_REPO: `${host}${basePort}/example/repository` },
          onCodex: fixSavedFinding(directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args[0] === "push") {
                pushes++;
                expect(git("remote", "get-url", "--push", "origin")).toBe(push);
              }
              return runHostedGit(remote, args, cwd, options);
            }
            expect(command).toBe("gh");
            if (args[1] === "list")
              return JSON.stringify(
                existing
                  ? [
                      {
                        url: `${base}/pull/7`,
                        head: commit,
                        repository: "synthetic-push-id",
                        crossRepository: true,
                      },
                    ]
                  : [],
              );
            if (args.at(-1) === ".url") return base;
            if (args[0] === "repo") {
              selectors.push(args[2]!);
              if (args.at(-1) === ".id")
                return args[2]!.endsWith("/synthetic-user/repository")
                  ? "synthetic-push-id"
                  : "synthetic-fetch-id";
              expect(args.at(-1)).toBe(".nameWithOwner");
              expect(args[2]).toBe(`${selectorHost}/synthetic-user/repository`);
              return "synthetic-user/repository";
            }
            expect(args[1]).toBe("create");
            expect(args[args.indexOf("--head") + 1]).toBe(
              `synthetic-user:${branch}`,
            );
            creations++;
            return `${base}/pull/8`;
          },
        },
        { localHosting: false, resumeBranch: resume ? branch : undefined },
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
      const commit = git("rev-parse", "HEAD");
      if (resume) createSavedPatchBranch(git, branch, commit);
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
      const outcome = await runSavedPublication(
        directory,
        {
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
          onCodex: fixSavedFinding(directory, () => {
            patches++;
          }),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("ls-remote")) preflights++;
              else if (args[0] === "push") pushes++;
              return runHostedGit(remote, args, cwd, options);
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
                    head: mode === "different saved commit" ? "other" : commit,
                  })
                : "";
            }
            expect(args[1]).toBe("create");
            creations.push([...args]);
            return url;
          },
        },
        { localHosting: false, resumeBranch: resume ? branch : undefined },
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
          "does not contain the saved patch commit",
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
