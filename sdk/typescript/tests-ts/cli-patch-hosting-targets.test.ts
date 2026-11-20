import { describe, expect, test } from "bun:test";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import {
  symlink,
  unlink,
  writeFile,
  mkdir,
  readFile,
  rm,
} from "node:fs/promises";
import { join, relative } from "node:path";
import {
  publicationRepository,
  runGitRepositoryCommand,
  runPublicationCommand,
  runWorkflow,
  patchDirectories,
  fixSavedFinding,
  createSavedPatchBranch,
  runHostedGit,
  runPublicationWorkflow,
  runSavedPublication,
  runLocalHostingTransport,
} from "./cli-patch-fixtures.js";
import { pathToFileURL } from "node:url";

const fixtures = patchDirectories();
const branch = "codex-security/patch-scan-1";

describe("GitHub patch destinations", () => {
  test
    .skipIf(process.platform === "win32")
    .each(["stable", "replaced", "removed caller"])(
    "binds a relative GitHub CLI socket across the patch: %s",
    async (mode) => {
      const { directory } = await publicationRepository(fixtures);
      const caller = join(directory, "src");
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
            } else if (mode === "removed caller") {
              await rm(caller, { recursive: true });
              sockets.push(listen(directory));
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
      const outcome = await runSavedPublication(
        directory,
        {
          environment: { GH_REPO: override },
          onCodex: fixSavedFinding(directory),
          onRepositoryCommand: async (command, args, cwd, options) => {
            if (command === "git") {
              if (args[0] === "push") {
                pushes++;
                expect(git("remote", "get-url", "--push", "origin")).toBe(push);
              }
              return runHostedGit(remote, args, cwd, options);
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
        const commit = git("rev-parse", "HEAD");
        createSavedPatchBranch(git, branch, commit);
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

test.each([
  "home",
  "xdg",
  "explicit",
  "empty explicit",
  ...(process.platform === "win32"
    ? ["appdata", "mixed case"]
    : ["lowercase decoy"]),
])("preserves gh configuration after caller removal: %s", async (kind) => {
  const { directory, git } = await publicationRepository(fixtures);
  const caller = join(directory, "component");
  await mkdir(caller);
  await writeFile(join(caller, "app.ts"), "before\n");
  git("add", ".");
  git("commit", "-m", "Synthetic caller baseline");
  const support = await fixtures.create("patch-gh-configuration-");
  const home = join(support, "home");
  const config =
    kind === "home" || kind === "lowercase decoy"
      ? join(home, ".config", "gh")
      : kind === "appdata"
        ? join(support, "GitHub CLI")
        : kind === "explicit"
          ? join(support, "explicit")
          : join(support, "gh");
  await mkdir(config, { recursive: true });
  await writeFile(join(config, "config.yml"), "prompt: disabled\n");
  const environment: NodeJS.ProcessEnv = {
    GH_CONFIG_DIR: kind === "empty explicit" ? "" : undefined,
    GLAB_CONFIG_DIR: undefined,
    XDG_CONFIG_HOME: undefined,
    AppData: undefined,
    HOME: relative(caller, home),
    USERPROFILE: relative(caller, home),
    GIT_CONFIG_GLOBAL: join(support, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
  };
  if (kind === "appdata") environment["AppData"] = relative(caller, support);
  else if (kind === "lowercase decoy") {
    environment["gh_config_dir"] = join(support, "decoy");
  } else if (kind !== "home") {
    environment["XDG_CONFIG_HOME"] = relative(caller, support);
    if (kind === "explicit")
      environment["GH_CONFIG_DIR"] = relative(caller, config);
    if (kind === "mixed case") {
      delete environment["XDG_CONFIG_HOME"];
      environment["xdg_config_home"] = relative(caller, support);
    }
  }
  let removed = false;
  let readsAfterRemoval = 0;
  const outcome = await runPublicationWorkflow("issue", {
    currentDirectory: caller,
    environment,
    onRepositoryCommand: async (command, args, cwd, options) => {
      if (command === "git")
        return runGitRepositoryCommand(command, args, cwd, options);
      if (command === "gh" && args[0] === "config") return "\n";
      if (removed) {
        readsAfterRemoval++;
        expect(options?.environment?.["GH_CONFIG_DIR"]).toBe(config);
        expect(
          await readFile(
            join(options!.environment!["GH_CONFIG_DIR"]!, "config.yml"),
            "utf8",
          ),
        ).toBe("prompt: disabled\n");
      }
      return args[1] === "create"
        ? "https://github.example.test/example/repository/pull/1"
        : "[]";
    },
    onCodex: async (_args, output) => {
      await rm(caller, { recursive: true });
      removed = true;
      output?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  });
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(readsAfterRemoval).toBeGreaterThan(0);
});

test.each([
  { resolver: "legacy", kind: "home" },
  { resolver: "legacy", kind: "xdg" },
  { resolver: "legacy", kind: "empty explicit" },
  { resolver: "legacy", kind: "explicit" },
  { resolver: "xdg", kind: "home" },
  { resolver: "xdg", kind: "legacy precedence" },
  { resolver: "xdg", kind: "ignored relative xdg" },
  { resolver: "xdg", kind: "empty explicit" },
  { resolver: "xdg", kind: "explicit" },
  ...(process.platform === "win32"
    ? ["expanded profile", "drive-relative xdg"]
    : ["expanded tilde", "expanded home"]
  ).map((kind) => ({ resolver: "xdg", kind })),
])(
  "preserves glab configuration after caller removal: $resolver, $kind",
  async ({ resolver, kind }) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const caller = join(directory, "component");
    await mkdir(caller);
    await writeFile(join(caller, "app.ts"), "before\n");
    git("add", ".");
    git("commit", "-m", "Synthetic caller baseline");
    git(
      "remote",
      "set-url",
      "origin",
      "https://gitlab.com/example/repository.git",
    );
    const support = await fixtures.create("patch-glab-configuration-");
    const home = join(support, "home");
    const expanded = kind.startsWith("expanded");
    const independent =
      expanded ||
      kind === "ignored relative xdg" ||
      kind === "drive-relative xdg";
    const xdg = join(expanded ? home : support, "xdg");
    const system = join(support, "system");
    const explicit = join(support, "explicit");
    const configuration =
      kind === "explicit"
        ? explicit
        : expanded ||
            kind === "xdg" ||
            (kind === "empty explicit" && resolver === "legacy")
          ? join(xdg, "glab-cli")
          : kind === "ignored relative xdg" || kind === "drive-relative xdg"
            ? join(system, "glab-cli")
            : join(home, ".config", "glab-cli");
    for (const path of [configuration, join(xdg, "glab-cli"), explicit]) {
      await mkdir(path, { recursive: true });
      await writeFile(
        join(path, "config.yml"),
        path === configuration
          ? "synthetic-selected-host\n"
          : "synthetic-other-host\n",
      );
    }
    const environment: NodeJS.ProcessEnv = {
      GLAB_CONFIG_DIR:
        kind === "explicit"
          ? relative(caller, explicit)
          : kind === "empty explicit"
            ? ""
            : undefined,
      HOME: independent ? home : relative(caller, home),
      USERPROFILE: independent ? home : relative(caller, home),
      XDG_CONFIG_HOME:
        kind === "expanded tilde"
          ? "~/xdg"
          : kind === "expanded home"
            ? "$HOME/xdg"
            : kind === "expanded profile"
              ? "%USERPROFILE%/xdg"
              : kind === "drive-relative xdg"
                ? `${directory.slice(0, 2)}xdg`
                : kind === "home"
                  ? undefined
                  : relative(caller, xdg),
      XDG_CONFIG_DIRS: system,
      GIT_CONFIG_GLOBAL: join(support, "gitconfig"),
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const inherited = { ...environment };
    const hosting = join(support, "glab.cjs");
    const calls = join(support, "calls.jsonl");
    // Exercise both glab's older XDG/HOME fallback and its newer legacy-first
    // resolver, which ignores relative XDG_CONFIG_HOME values.
    await writeFile(
      hosting,
      `
      const fs = require("node:fs");
      const path = require("node:path");
      const env = process.env;
      const home = ${JSON.stringify(resolver)} === "legacy" ? env.HOME : process.platform === "win32" ? env.USERPROFILE : env.HOME;
      const legacy = path.join(home, ".config", "glab-cli");
      const exists = (directory) => fs.existsSync(path.join(directory, "config.yml"));
      let xdg = env.XDG_CONFIG_HOME;
      if (process.platform === "win32") {
        if (xdg?.startsWith("%USERPROFILE%")) xdg = path.join(home, xdg.slice(13));
      } else {
        if (xdg?.startsWith("~")) xdg = path.join(home, xdg.slice(1));
        else if (xdg?.startsWith("$HOME")) xdg = path.join(home, xdg.slice(5));
      }
      const config = env.GLAB_CONFIG_DIR || (${JSON.stringify(resolver)} === "legacy"
        ? path.join(env.XDG_CONFIG_HOME || path.join(home, ".config"), "glab-cli")
        : exists(legacy) ? legacy
        : xdg && path.isAbsolute(xdg) && exists(path.join(xdg, "glab-cli"))
          ? path.join(xdg, "glab-cli") : path.join(env.XDG_CONFIG_DIRS, "glab-cli"));
      const selected = fs.readFileSync(path.join(config, "config.yml"), "utf8");
      if (selected !== "synthetic-selected-host\\n") throw new Error("Selected a different synthetic hosting configuration");
      fs.appendFileSync(${JSON.stringify(calls)}, JSON.stringify({ directory: process.cwd(), config }) + "\\n");
      if (process.argv[3] === "create") process.stdout.write("https://gitlab.com/example/repository/-/merge_requests/1");
    `,
    );
    let removed = false;
    const outcome = await runPublicationWorkflow(
      "issue",
      {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: async (command, args, cwd, options) => {
          const effective = { ...environment, ...options?.environment };
          if (command === "git") {
            for (const key of Object.keys(effective)) {
              if (
                key.startsWith("GIT_CONFIG_KEY_") &&
                effective[key] ===
                  "url.https://gitlab.com/example/repository.git.insteadOf"
              )
                effective[key] = `url.${remote}.insteadOf`;
            }
            const run = options?.patchTransport
              ? runLocalHostingTransport
              : runGitRepositoryCommand;
            return run(
              command,
              options?.patchTransport && args.includes("push")
                ? args.map((argument) =>
                    argument === "origin" ? remote : argument,
                  )
                : args,
              cwd,
              { ...options, environment: effective },
            );
          }
          expect(command).toBe("glab");
          if (expanded || kind === "drive-relative xdg")
            expect(effective["XDG_CONFIG_HOME"]).toBe(
              environment["XDG_CONFIG_HOME"],
            );
          return execFileSync(process.execPath, [hosting, ...args], {
            cwd: options?.directory ?? cwd,
            env: { ...process.env, ...effective },
            encoding: "utf8",
          });
        },
        onCodex: async (_args, output) => {
          expect((await readFile(calls, "utf8")).trim()).not.toBe("");
          await rm(caller, { recursive: true });
          removed = true;
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
      { localHosting: false },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(removed).toBe(true);
    const directories = (await readFile(calls, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line).directory);
    expect(directories).toContain(caller);
    expect(directories).toContain(directory);
    expect(environment).toEqual(inherited);
    expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(
      "https://gitlab.com/example/repository/-/merge_requests/1",
    );
  },
);

test.each(
  [false, true].flatMap((resume) =>
    ["github.com", "gitlab.com"].map((host) => ({ resume, host })),
  ),
)(
  "keeps HTTP transport credentials out of publication arguments: $host, resume=$resume",
  async ({ resume, host }) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const password = "SYNTHETIC_PASSWORD%40value";
    const prefix = `https://synthetic-user:${password}@${host}/example/`;
    const resolved = `${prefix}repository.git`;
    const project = `https://${host}/example/repository.git`;
    const configured = resume ? resolved : "synthetic:repository.git";
    git("remote", "set-url", "origin", configured);
    git("config", `url.${prefix}.insteadOf`, "synthetic:");
    // A resolved URL must not undergo a second insteadOf expansion.
    if (!resume)
      git("config", "url.https://unused.example.test/.insteadOf", prefix);
    const branch = "codex-security/patch-scan-1";
    const original = git("rev-parse", "HEAD");
    if (resume) {
      git("branch", branch);
      git("config", `branch.${branch}.codexSecurityPatchCommit`, original);
    }
    const environment: NodeJS.ProcessEnv = {
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "synthetic.inherited",
      GIT_CONFIG_VALUE_0: "count value",
      GIT_CONFIG_PARAMETERS: `'synthetic.parameter=parameter value' 'remote.origin.pushurl=${configured}'`,
    };
    const inherited = { ...environment };
    let preflights = 0;
    let identities = 0;
    let creates = 0;
    let pushes = 0;
    const request = `https://${host}/example/repository/${host === "gitlab.com" ? "-/merge_requests" : "pull"}/1`;
    const outcome = await runSavedPublication(
      directory,
      {
        environment,
        onCodex: fixSavedFinding(directory),
        onRepositoryCommand: async (command, args, cwd, options) => {
          expect(args.join("\n")).not.toContain(password);
          const effective = {
            ...options,
            environment: { ...environment, ...options?.environment },
          };
          const readGit = (arguments_: readonly string[]) =>
            runGitRepositoryCommand("git", arguments_, cwd, effective);
          if (command === "git") {
            const probe = args.indexOf("ls-remote");
            if (options?.patchTransport && probe >= 0) {
              preflights++;
              expect(
                await readGit(["ls-remote", "--get-url", args[probe + 3]!]),
              ).toBe(resolved);
              expect(
                await readGit(["config", "--get", "synthetic.inherited"]),
              ).toBe("count value");
              expect(
                await readGit(["config", "--get", "synthetic.parameter"]),
              ).toBe("parameter value");
              return "";
            }
            if (options?.patchTransport && args.includes("push")) {
              pushes++;
              expect(
                await readGit(["remote", "get-url", "--push", "origin"]),
              ).toBe(resolved);
              return runLocalHostingTransport(
                command,
                args.map((argument) =>
                  argument === "origin" ? remote : argument,
                ),
                cwd,
                effective,
              );
            }
            return readGit(args);
          }
          if (command === "glab") {
            expect(args[args.indexOf("--repo") + 1]).toBe(project);
            if (args[1] === "list") return "";
            expect(args[args.indexOf("--head") + 1]).toBe(project);
          } else {
            if (args[1] === "list") return "[]";
            if (args.at(-1) === ".url") return project.replace(/\.git$/u, "");
            if (args[0] === "repo") {
              identities++;
              expect(
                await readGit([
                  "ls-remote",
                  "--get-url",
                  "codex-security-push",
                ]),
              ).toBe(resolved);
              expect(
                await readGit(["config", "--get", "synthetic.inherited"]),
              ).toBe("count value");
              return args[1] === "set-default"
                ? "example/repository"
                : JSON.stringify({
                    id: "synthetic-origin-id",
                    url: project.replace(/\.git$/u, ""),
                  });
            }
          }
          creates++;
          return request;
        },
      },
      { localHosting: false, resumeBranch: resume ? branch : undefined },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(preflights).toBe(resume ? 0 : 1);
    expect(identities).toBe(host === "github.com" ? 2 : 0);
    expect(pushes).toBe(1);
    expect(creates).toBe(1);
    expect(environment).toEqual(inherited);
    expect(git("remote", "get-url", "--push", "origin")).toBe(resolved);
    expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(request);
  },
);
