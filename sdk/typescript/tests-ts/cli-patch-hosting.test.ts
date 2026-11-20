import { gitText } from "./support/shell.js";
import { loopbackProxy, loopbackTls } from "./support/loopback-git-proxy.js";
import { describe, expect, test, mock } from "bun:test";
import { execFile, execFileSync } from "node:child_process";
import {
  link,
  mkdir,
  readFile,
  realpath,
  rename,
  rmdir,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, dirname, join, parse, relative } from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { runRepositoryCommand } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";
import {
  resultWithFindings,
  savedScan,
  completePatches,
  runWorkflow,
  runGitRepositoryCommand,
  runLocalHostingTransport,
  publicationRepository as createPublicationRepository,
  patchDirectories,
  runSavedPublication,
} from "./cli-patch-fixtures.js";

describe("patch change tracking", () => {
  const fixtures = patchDirectories();
  const publicationRepository = () => createPublicationRepository(fixtures);

  test.each([
    ["local", false],
    ["included checkout", true],
    ["operator", false],
    ["environment", true],
    ["relative configuration", false],
    ["relative environment", true],
    ["missing environment", false],
    ["none", false],
  ] as const)(
    "native Git transport honors the %s proxy boundary",
    async (source, resume) => {
      const { directory, git } = await publicationRepository();
      const branch = "codex-security/patch-scan-1";
      const external = await fixtures.create("patch-native-proxy-");
      const globalConfig = join(external, "operator.gitconfig");
      const marker = join(external, "invocations");
      const environment: NodeJS.ProcessEnv = {
        GIT_CONFIG_GLOBAL: globalConfig,
        GIT_CONFIG_NOSYSTEM: "1",
        GITLAB_HOST: "127.0.0.1:1",
      };
      const writeProxy = async (program: string, label: string) => {
        const output = marker.replaceAll("\\", "/").replaceAll("'", "'\\''");
        await writeFile(
          program,
          `#!/bin/sh\nprintf '%s %s %s\\n' ${label} "$1" "$2" >> '${output}'\nexit 1\n`,
          { mode: 0o755 },
        );
      };
      const externalProxy = join(external, "operator proxy");
      const otherProxy = join(external, "unmatched proxy");
      await writeProxy(externalProxy, "operator");
      await writeProxy(otherProxy, "unmatched");
      await writeProxy(join(directory, "checkout-proxy"), "checkout");
      git("add", "checkout-proxy");
      git("commit", "-m", "Add synthetic checkout proxy");
      git(
        "remote",
        "set-url",
        "origin",
        "git://127.0.0.1:1/example/repository.git",
      );
      if (resume) {
        git("branch", branch);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchCommit`,
          git("rev-parse", "HEAD"),
        );
      }
      const addProxy = (command: string) =>
        git(
          "config",
          "--file",
          globalConfig,
          "--add",
          "core.gitProxy",
          command,
        );
      if (source === "operator" || source === "none") {
        // Git matches the first applicable domain, including the explicit port.
        addProxy(otherProxy + " for 127.0.0.1");
        addProxy((source === "none" ? "none" : externalProxy) + " for 0.1:1");
        addProxy(otherProxy);
      } else if (source === "relative configuration") {
        addProxy("./checkout-proxy");
      } else if (source === "included checkout") {
        const included = join(directory, ".git", "proxy.gitconfig");
        git("config", "--file", globalConfig, "include.path", included);
        git("config", "--file", included, "core.gitProxy", "./checkout-proxy");
      } else {
        git("config", "core.gitProxy", "./checkout-proxy");
        if (source === "environment")
          environment["GIT_PROXY_COMMAND"] = externalProxy;
        if (source === "relative environment")
          environment["GIT_PROXY_COMMAND"] = "./checkout-proxy";
        if (source === "missing environment")
          environment["GIT_PROXY_COMMAND"] = join(
            external,
            "uninstalled proxy",
          );
      }

      const onCodex = mock(() => 0);
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onCodex,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onRepositoryCommand: (tool, args, cwd, options) =>
            tool === "git"
              ? runGitRepositoryCommand(tool, args, cwd, {
                  ...options,
                  environment: { ...environment, ...options?.environment },
                })
              : "",
        },
        { localHosting: false },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(onCodex).not.toHaveBeenCalled();
      if (source === "operator" || source === "environment") {
        expect(await readFile(marker, "utf8")).toBe("operator 127.0.0.1 1\n");
      } else {
        await expect(readFile(marker)).rejects.toMatchObject({
          code: "ENOENT",
        });
        if (source === "local" || source === "included checkout")
          expect(outcome.stderr).toContain("checkout-selected core.gitProxy");
      }
    },
  );

  for (const rewritten of [false, true])
    test(
      rewritten
        ? "push rejects an external proxy rewritten through a worktree hard link"
        : "push from a component uses the external proxy selected before its alias is retargeted",
      async () => {
        const { directory, git, remote } = await publicationRepository();
        const external = await fixtures.create("patch-proxy-retarget-");
        const trusted = join(external, "trusted");
        const alias = join(external, "selected");
        const marker = join(external, "invocations");
        const linkType = process.platform === "win32" ? "junction" : "dir";
        await mkdir(trusted);
        await symlink(trusted, alias, linkType);
        const quote = (path: string) =>
          "'" + path.replaceAll("\\", "/").replaceAll("'", "'\\''") + "'";
        // Consume the native protocol's first packet, as a Git daemon would.
        // Serve the preflight from the bare fixture and stop the push at the proxy.
        await writeFile(
          join(trusted, "proxy"),
          `#!/bin/sh
header=$(dd bs=1 count=4 2>/dev/null) || exit 1
request=$(dd bs=1 count=$((0x$header - 4)) 2>/dev/null | tr '\\000' ' ')
case "$request" in
  git-upload-pack*) echo preflight >> ${quote(marker)}; exec git upload-pack ${quote(remote)} ;;
  git-receive-pack*) echo push >> ${quote(marker)} ;;
esac
exit 1
`,
          { mode: 0o755 },
        );
        await writeFile(
          join(directory, "proxy"),
          `#!/bin/sh\necho checkout >> ${quote(marker)}\nexit 1\n`,
          { mode: 0o755 },
        );
        git("add", "proxy");
        git("commit", "-m", "Add alternate checkout proxy");
        const writableLink = join(directory, "writable-proxy");
        if (rewritten) {
          await writeFile(
            join(directory, ".git", "info", "exclude"),
            "writable-proxy\n",
          );
          await link(join(trusted, "proxy"), writableLink);
        }
        git("push", "origin", "main");
        git(
          "remote",
          "set-url",
          "origin",
          "git://127.0.0.1:1/example/repository.git",
        );
        const environment = {
          GITLAB_HOST: "127.0.0.1:1",
          GIT_PROXY_COMMAND: relative(
            directory,
            join(alias, "proxy"),
          ).replaceAll("\\", "/"),
          GIT_CONFIG_GLOBAL: join(external, "gitconfig"),
          GIT_CONFIG_NOSYSTEM: "1",
        };
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--create-pr", "--json"],
          {
            currentDirectory: join(directory, "src"),
            environment,
            onCodex: async (_args, output) => {
              if (rewritten)
                await writeFile(
                  writableLink,
                  await readFile(join(directory, "proxy")),
                );
              else {
                await unlink(alias);
                await symlink(directory, alias, linkType);
              }
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              output?.stdout.write("Fixed and verified.");
              return 0;
            },
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, {
                    ...options,
                    environment: { ...environment, ...options?.environment },
                  })
                : "",
          },
          { localHosting: false },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(
          await readFile(marker, "utf8").catch(() => ""),
          outcome.stderr,
        ).toBe(rewritten ? "preflight\n" : "preflight\npush\n");
        if (rewritten)
          expect(outcome.stderr).toContain("transport executable changed");
      },
    );

  test.each([
    { key: "credential.useHttpPath", source: "local", value: "false" },
    {
      key: "credential.https://gitlab.example.test/team.useHttpPath",
      source: "branch include",
      value: "false",
    },
    {
      key: "credential.https://gitlab.example.test.username",
      source: "resume",
      value: "",
    },
  ])(
    "HTTP publication refuses checkout-selected $key from $source",
    async ({ key, source, value }) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-credential-settings-");
      const global = join(external, "operator.gitconfig");
      const environment = {
        GIT_CONFIG_GLOBAL: global,
        GIT_CONFIG_NOSYSTEM: "1",
        GITLAB_HOST: "gitlab.example.test",
      };
      const remote = "https://gitlab.example.test/team/repository.git";
      git("remote", "set-url", "origin", remote);
      git("config", "--file", global, "credential.useHttpPath", "true");
      const branch = "codex-security/patch-scan-1";
      if (source === "resume") {
        git("branch", branch);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchCommit`,
          git("rev-parse", "HEAD"),
        );
      }
      if (source !== "branch include") {
        git("config", key, value);
      } else {
        const included = join(
          directory,
          ".git",
          "credential-settings.gitconfig",
        );
        git("config", "--file", included, key, value);
        git(
          "config",
          "--file",
          global,
          "includeIf.onbranch:codex-security/**.path",
          included,
        );
      }
      const transports: string[] = [];
      const outcome = await runWorkflow(
        source === "resume"
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (tool, args, cwd, options) => {
            if (tool !== "git") return "";
            if (args.includes("ls-remote") || args[0] === "push") {
              transports.push(
                args.includes("ls-remote") ? "ls-remote" : "push",
              );
              return "";
            }
            return runGitRepositoryCommand(tool, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          },
        },
        { localHosting: false },
      );
      expect(transports).toEqual(
        source === "branch include" ? ["ls-remote"] : [],
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "checkout-selected Git credential settings",
      );
    },
  );

  test.each([
    ["preflight", "external shell"],
    ["push", "external shell"],
    ["push from removed component", "external shell"],
    ["push", "retargeted helper"],
    ["preflight", "named after reset"],
    ["preflight", "checkout relative"],
    ["preflight", "inherited checkout relative"],
    ["preflight", "askpass checkout relative"],
    ["preflight", "askpass checkout absolute"],
  ] as const)(
    "HTTPS %s honors credential helper ownership for %s",
    async (stage, selection) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-credentials-");
      const component = join(directory, "component");
      const removesComponent = stage === "push from removed component";
      if (removesComponent) await mkdir(component);
      const global = join(external, "global.gitconfig");
      let challenged = false;
      let authenticated = false;
      const services = new Set<string | null>();
      const checkoutHelper = selection.includes("checkout");
      const retarget = selection === "retargeted helper";
      const alias = join(external, "selected");
      const linkType = process.platform === "win32" ? "junction" : "dir";
      const username = "synthetic";
      const password = "synthetic-transport-only";
      const server = Bun.serve({
        tls: await loopbackTls(global, git),
        hostname: "127.0.0.1",
        port: 0,
        fetch(request) {
          const service = new URL(request.url).searchParams.get("service");
          services.add(service);
          if (
            request.headers.get("authorization") ===
            `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`
          ) {
            authenticated = true;
            if (retarget && service === "git-upload-pack") {
              // Advertise an empty Git remote so the authenticated preflight succeeds.
              return new Response("001e# service=git-upload-pack\n00000000", {
                headers: {
                  "Content-Type": "application/x-git-upload-pack-advertisement",
                },
              });
            }
            // A refused credential makes native Git call erase on the same helper.
            if (!checkoutHelper) return new Response(null, { status: 404 });
          }
          challenged = true;
          return new Response(null, {
            status: 401,
            headers: { "WWW-Authenticate": 'Basic realm="fixture"' },
          });
        },
      });
      try {
        const remote = new URL("example/repository.git", server.url).href;
        const marker = join(external, "helper-log");
        const script = join(external, "helper.cjs");
        await writeFile(
          script,
          `const fs = require("node:fs");
const [owner, action] = process.argv.slice(2);
const path = fs.readFileSync(0, "utf8").split("\\n").find(line => line.startsWith("path="));
fs.appendFileSync(${JSON.stringify(marker)}, [owner, action, path].join(" ") + "\\n");
if (action === "get") process.stdout.write(${JSON.stringify(`username=${username}\npassword=${password}\n`)});
`,
        );
        const helper = (owner: string) =>
          `!node "${script.replaceAll("\\", "/")}" ${owner}`;
        const wrapper = (owner: string) =>
          `#!/bin/sh\nexec ${helper(owner).slice(1)} "$@"\n`;
        await writeFile(
          join(directory, "helper.sh"),
          wrapper('"checkout-$PATCH_HELPER_CANARY"'),
          { mode: 0o755 },
        );
        git("add", "helper.sh");
        git("commit", "-m", "Add synthetic checkout helper");
        git("config", "--file", global, "credential.useHttpPath", "false");
        git(
          "config",
          "--file",
          global,
          `credential.${remote}.useHttpPath`,
          "true",
        );
        const scopedHelper = `credential.${server.url.origin}.helper`;
        const addHelper = (value: string) =>
          git("config", "--file", global, "--add", scopedHelper, value);
        const environment: NodeJS.ProcessEnv = {
          GIT_CONFIG_GLOBAL: global,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_TERMINAL_PROMPT: "0",
          GITLAB_HOST: server.url.origin,
          NO_PROXY: "127.0.0.1",
          PATCH_HELPER_CANARY: "synthetic",
        };
        if (removesComponent) {
          await symlink(git("--exec-path"), alias, linkType);
          environment["GIT_EXEC_PATH"] = relative(component, alias);
        }
        if (retarget) {
          const trusted = join(external, "trusted");
          await mkdir(trusted);
          await writeFile(join(trusted, "helper.sh"), wrapper("operator"), {
            mode: 0o755,
          });
          await symlink(trusted, alias, linkType);
          addHelper(`!"${join(alias, "helper.sh").replaceAll("\\", "/")}"`);
        } else if (selection === "named after reset") {
          await writeFile(
            join(external, "git-credential-fixture"),
            wrapper("operator"),
            { mode: 0o755 },
          );
          environment["PATH"] = [external, process.env["PATH"]].join(delimiter);
          addHelper("!./helper.sh");
          addHelper("");
          addHelper("codex-security-fixture-missing");
          addHelper("fixture");
        } else if (selection === "inherited checkout relative") {
          git(
            "config",
            "alias.fixture-parameters",
            '!printf "%s" "$GIT_CONFIG_PARAMETERS"',
          );
          environment["GIT_CONFIG_PARAMETERS"] = git(
            "-c",
            "credential.helper=!./helper.sh",
            "fixture-parameters",
          );
          git("config", "--unset", "alias.fixture-parameters");
        } else if (selection.startsWith("askpass")) {
          git(
            "config",
            "--file",
            global,
            "core.askPass",
            selection.endsWith("relative")
              ? "./helper.sh"
              : join(directory, "helper.sh").replaceAll("\\", "/"),
          );
        } else {
          addHelper(
            selection === "checkout relative"
              ? "!./helper.sh"
              : helper("operator"),
          );
        }
        const checkout = join(directory, ".git", "credentials.gitconfig");
        git(
          "config",
          "--file",
          checkout,
          "credential.helper",
          helper("checkout"),
        );
        git(
          "config",
          "--file",
          checkout,
          "core.askpass",
          helper("checkout-askpass").slice(1),
        );
        git(
          "config",
          "--file",
          global,
          stage !== "preflight"
            ? "includeIf.onbranch:codex-security/**.path"
            : "include.path",
          checkout,
        );
        // Exercise local scope as well as a checkout-owned file included at global scope.
        git("config", "credential.helper", helper("local"));
        git("remote", "set-url", "origin", remote);
        let modelCalls = 0;
        const outcome = await runWorkflow(
          removesComponent
            ? ["patch", "Synthetic issue", "--create-pr", "--json"]
            : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            currentDirectory: removesComponent ? component : directory,
            environment,
            onWorkbench: () =>
              savedScan(resultWithFindings(["high"]), "scan-1", directory),
            onCodex: async (args, output) => {
              modelCalls++;
              if (retarget) {
                await unlink(alias);
                await symlink(directory, alias, linkType);
              }
              if (removesComponent) await rmdir(component);
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              if (removesComponent) output?.stdout.write("Patch complete.\n");
              else completePatches(args, output);
              return 0;
            },
            onRepositoryCommand: (tool, args, cwd, options) => {
              if (tool !== "git") return "";
              if (
                stage !== "preflight" &&
                !retarget &&
                args.includes("ls-remote")
              )
                return "";
              return runRepositoryCommand(tool, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });
            },
          },
          { localHosting: false },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(modelCalls).toBe(stage === "preflight" ? 0 : 1);
        const observed = await readFile(marker, "utf8").catch((error) => {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return "";
          throw error;
        });
        if (retarget) {
          expect([...services]).toEqual([
            "git-upload-pack",
            "git-receive-pack",
          ]);
          expect(challenged).toBe(true);
          expect(authenticated).toBe(true);
          expect(observed).toContain(
            "operator get path=example/repository.git\n",
          );
          expect(observed).not.toContain("checkout-");
        } else if (checkoutHelper) {
          expect(observed, outcome.stderr).toBe("");
          expect(authenticated).toBe(false);
        } else {
          expect(challenged, outcome.stderr).toBe(true);
          expect(authenticated, outcome.stderr).toBe(true);
          expect(observed).toBe("operator get path=example/repository.git\n");
        }
      } finally {
        server.stop(true);
      }
    },
  );

  test.each(["unchanged", "branch helper", "SSH to HTTPS"] as const)(
    "preserves the operator's askpass selection across publication: %s",
    async (mode) => {
      const { directory, git, remote } = await publicationRepository();
      const external = await fixtures.create("patch-askpass-");
      const global = join(external, "gitconfig");
      const included = join(external, "branch.gitconfig");
      const helper = async (name: string) => {
        const path = join(external, name + ".sh");
        await writeFile(path, `#!/bin/sh\necho ${name}\n`, { mode: 0o755 });
        return path;
      };
      const ordinary = await helper("ordinary");
      const ssh = mode === "SSH to HTTPS";
      const https = "https://gitlab.example.test/example/repository.git";
      git(
        "remote",
        "set-url",
        "origin",
        ssh ? "git@gitlab.example.test:example/repository.git" : https,
      );
      if (!ssh) git("config", "--file", global, "core.askPass", ordinary);
      if (mode !== "unchanged") {
        git(
          "config",
          "--file",
          global,
          "includeIf.onbranch:codex-security/**.path",
          included,
        );
        if (ssh)
          git("config", "--file", included, "remote.origin.pushurl", https);
        else
          git(
            "config",
            "--file",
            included,
            "core.askPass",
            await helper("branch"),
          );
      }
      const environment = {
        GITLAB_HOST: "gitlab.example.test",
        GIT_CONFIG_GLOBAL: global,
        GIT_CONFIG_NOSYSTEM: "1",
        GIT_ASKPASS: ssh ? ordinary : undefined,
        SSH_ASKPASS: ssh ? await helper("SSH") : undefined,
        GIT_TERMINAL_PROMPT: "0",
      };
      const selections: string[] = [];
      const onRepositoryCommand: typeof runGitRepositoryCommand = async (
        tool,
        args,
        cwd,
        options,
      ) => {
        if (tool !== "git")
          return args[1] === "list"
            ? ""
            : "https://gitlab.example.test/example/repository/-/merge_requests/1";
        const context = {
          ...options,
          environment: { ...environment, ...options?.environment },
        };
        if (options?.patchTransport) {
          const preflight = args.includes("ls-remote");
          if (preflight && ssh) {
            expect(options.environment?.["GIT_SSH_COMMAND"]).toBeTruthy();
            // Exercise the literal program passed to the SSH client.
            context.environment.GIT_ASKPASS =
              options.environment?.["SSH_ASKPASS"];
            expect(context.environment.GIT_ASKPASS).toBeTruthy();
          } else {
            expect(options.environment?.["GIT_SSH_COMMAND"]).toBeUndefined();
          }
          // Git fills a synthetic password with the selected prompt.
          const filled = await runGitRepositoryCommand(
            tool,
            ["-c", "credential.helper=", "credential", "fill"],
            cwd,
            {
              ...context,
              input:
                "protocol=https\nhost=example.invalid\nusername=fixture\n\n",
            },
          );
          selections.push(filled.match(/^password=(.+)$/mu)?.[1] ?? "");
          return runLocalHostingTransport(
            tool,
            preflight
              ? ["ls-remote", "--heads", "--", remote]
              : args.map((arg) => (arg === "origin" ? remote : arg)),
            cwd,
            context,
          );
        }
        return runGitRepositoryCommand(tool, args, cwd, context);
      };
      const common = {
        currentDirectory: directory,
        environment,
        onRepositoryCommand,
      };
      const branch = "codex-security/patch-scan-1";
      const fixture = { localHosting: false };
      const fresh = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          ...common,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
        },
        fixture,
      );
      if (mode === "branch helper") {
        expect(fresh.exitCode, fresh.stderr).toBe(2);
        expect(fresh.stderr).toContain("not selected during patch preflight");
        expect(fresh.stderr).toContain(`--resume-pr ${branch}`);
        expect(selections).toEqual(["ordinary"]);
        expect(git("ls-remote", remote, `refs/heads/${branch}`)).toBe("");
        const resumed = await runWorkflow(
          ["patch", "--resume-pr", branch, "--json"],
          {
            ...common,
            onCodex: throwing("Resume attempted a second patch turn"),
          },
          fixture,
        );
        expect(resumed.exitCode, resumed.stderr).toBe(0);
      } else expect(fresh.exitCode, fresh.stderr).toBe(0);
      expect(selections).toEqual([
        ssh ? "SSH" : "ordinary",
        mode === "branch helper" ? "branch" : "ordinary",
      ]);
      expect(git("--git-dir", remote, "rev-parse", branch)).toBe(
        git("rev-parse", branch),
      );
    },
  );

  test.each(["local", "include", "separate caller include"] as const)(
    "publication preflight refuses a checkout-selected SSH command from %s",
    async (source) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-ssh-config-");
      const marker = join(external, "marker");
      const script = join(external, "ssh.cjs");
      await writeFile(
        script,
        "require('node:fs').writeFileSync(process.argv[2], 'ran'); process.exit(1);\n",
      );
      const commandPath = (value: string) => `"${value.replaceAll("\\", "/")}"`;
      const config = join(directory, "transport.gitconfig");
      const separate = source === "separate caller include";
      const tree = separate
        ? await fixtures.create("patch-ssh-worktree-")
        : directory;
      const environment: NodeJS.ProcessEnv = {};
      if (source !== "local") {
        environment["GIT_CONFIG_GLOBAL"] = join(external, "user.gitconfig");
        git(
          "config",
          "--file",
          environment["GIT_CONFIG_GLOBAL"],
          "include.path",
          config,
        );
      }
      git(
        "config",
        ...(source !== "local" ? ["--file", config] : []),
        "core.sshCommand",
        [process.execPath, script, marker].map(commandPath).join(" "),
      );
      if (source !== "local") {
        git("add", "transport.gitconfig");
        git("commit", "-m", "Synthetic checkout configuration");
      }
      if (separate) {
        git("--work-tree=" + tree, "checkout-index", "--all");
        environment["GIT_WORK_TREE"] = tree;
        environment["GIT_DIR"] = join(directory, ".git");
      }
      git(
        "remote",
        "set-url",
        "origin",
        "git@github.example.test:example/repository.git",
      );
      const model = mock(async () => 0);
      const outcome = await runWorkflow(
        separate
          ? ["patch", "Synthetic issue", "--create-pr", "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", tree),
          onCodex: model,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: { ...environment, ...options?.environment },
                })
              : "[]",
        },
        { localHosting: false },
      );
      await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("core.sshCommand");
      expect(model).not.toHaveBeenCalled();
    },
  );

  test.each([
    ["core.gitProxy", "git://gitlab.com/test/project.git", "core.gitProxy"],
    [
      "http.proxy",
      "https://gitlab.com/test/project.git",
      "checkout-selected HTTP",
    ],
    [
      "remote.origin.proxy",
      "https://gitlab.com/test/project.git",
      "remote.origin.proxy",
    ],
    [
      "credential.helper",
      "https://gitlab.com/test/project.git",
      "fixture credentials checked",
    ],
  ] as const)(
    "excludes caller-owned %s for a separate worktree",
    async (setting, remote, error) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-separate-config-");
      const tree = join(external, "tree");
      await mkdir(tree);
      git("--work-tree=" + tree, "checkout-index", "--all");
      const included = join(directory, "transport.gitconfig");
      const global = join(external, "global.gitconfig");
      git("config", "--file", global, "include.path", included);
      git("config", "--file", included, setting, "fixture-caller-value");
      git("remote", "set-url", "origin", remote);
      const environment = {
        GIT_DIR: join(directory, ".git"),
        GIT_WORK_TREE: tree,
        GIT_CONFIG_GLOBAL: global,
      };
      const model = mock(() => 0);
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onCodex: model,
          onRepositoryCommand: (tool, args, cwd, options) => {
            if (tool !== "git") return "";
            if (args.includes("ls-remote")) {
              expect(setting).toBe("credential.helper");
              expect(Object.values(options?.environment ?? {})).not.toContain(
                "fixture-caller-value",
              );
              throw new Error("fixture credentials checked");
            }
            return runGitRepositoryCommand(tool, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          },
        },
        { localHosting: false },
      );
      expect(outcome.stderr).toContain(error);
      expect(model).not.toHaveBeenCalled();
    },
  );

  test.each([
    "relative external command",
    "relative external executable",
    "relative external core command",
    "checkout program",
    "shell expansion",
    "checkout SSH configuration",
    "ambiguous known-hosts list",
  ])("binds the %s before running a patch", async (kind) => {
    const { directory, git } = await publicationRepository();
    const external = await realpath(
      await fixtures.create("patch-ssh-external-"),
    );
    const component = join(directory, "component");
    await mkdir(component);
    const safe = kind.startsWith("relative external");
    const helper = join(safe ? external : directory, "operator's ssh");
    await writeFile(helper, "", { mode: 0o700 });
    const relativeHelper = relative(directory, helper).replaceAll("\\", "/");
    const configured =
      '"' + (safe ? relativeHelper : "./" + relativeHelper) + '"';
    const environment: NodeJS.ProcessEnv = {};
    if (kind.endsWith("core command")) {
      const config = join(external, "gitconfig");
      git("config", "--file", config, "core.sshCommand", configured);
      environment["GIT_CONFIG_GLOBAL"] = config;
    } else if (kind.endsWith("executable")) {
      environment["GIT_SSH"] = relativeHelper;
    } else if (kind === "ambiguous known-hosts list") {
      const hosts = join(external, "known hosts");
      await writeFile(hosts, "");
      environment["GIT_SSH_COMMAND"] = `ssh -o "UserKnownHostsFile=${hosts}"`;
    } else {
      environment["GIT_SSH_COMMAND"] =
        kind === "shell expansion"
          ? 'ssh "$DYNAMIC_OPTION"'
          : kind === "checkout SSH configuration"
            ? "ssh -F relative/config"
            : configured;
    }
    git("remote", "set-url", "origin", "git@gitlab.com:example/repository.git");
    let probed = false;
    const model = mock(() => 0);
    const result = await runSavedPublication(
      component,
      {
        onCodex: model,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onRepositoryCommand: (tool, args, cwd, options) => {
          if (tool === "glab") return "";
          if (args.includes("ls-remote")) {
            probed = true;
            expect(options?.environment?.["GIT_SSH_COMMAND"]).toEndWith(
              " && exec '" + helper.replaceAll("'", "'\\''") + "'",
            );
            // End this preflight after observing the bound command.
            throw new Error("fixture transport inspected");
          }
          return runGitRepositoryCommand(tool, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
      },
      { localHosting: false },
    );
    expect(probed).toBe(safe);
    expect(result.stderr).toContain(
      safe ? "fixture transport inspected" : "Cannot bind the SSH transport",
    );
    expect(model).not.toHaveBeenCalled();
  });

  test
    .skipIf(process.platform === "win32")
    .each(["GIT_SSH", "GIT_ASKPASS", "SSH_ASKPASS"] as const)(
    "stops publication when a patch retargets the selected %s launcher",
    async (setting) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-ssh-launcher-");
      const launcher = join(external, "launcher");
      const approved = Bun.which("true")!;
      const replacement = Bun.which("false")!;
      await symlink(approved, launcher);
      git(
        "remote",
        "set-url",
        "origin",
        setting === "GIT_SSH"
          ? "git@work:example/repository.git"
          : "https://gitlab.com/example/repository.git",
      );
      let patched = false;
      let attemptedAuthentication = false;
      const outcome = await runSavedPublication(
        directory,
        {
          environment: { [setting]: launcher, GITLAB_HOST: "gitlab.com" },

          onCodex: async (args, output) => {
            await unlink(launcher);
            await symlink(replacement, launcher);
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            patched = true;
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (tool, args, cwd, options) => {
            if (args.includes("codex-security-ssh-config")) {
              attemptedAuthentication ||= patched;
              return "hostname gitlab.com";
            }
            if (tool !== "git" || args.includes("push")) {
              attemptedAuthentication ||= patched;
              return "";
            }
            if (args.includes("ls-remote")) return "";
            return runGitRepositoryCommand(tool, args, cwd, options);
          },
        },
        { localHosting: false },
      );
      expect(patched).toBe(true);
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("Patch transport executable changed");
      expect(attemptedAuthentication).toBe(false);
    },
  );

  test.skipIf(process.platform === "win32").each([
    ["GIT_SSH", false],
    ["GIT_ASKPASS", false],
    ["core.askPass", false],
    ["core.askPass", true],
    ["GIT_PROXY_COMMAND", false],
    ["GIT_PROXY_COMMAND", true],
  ] as const)(
    "dispatches %s through a writable launcher only when the target is protected (writable target: %p)",
    async (setting, writableTarget) => {
      const { directory, git } = await publicationRepository();
      const trusted = await fixtures.create("patch-approved-tool-");
      const writable = await fixtures.create("patch-writable-tool-");
      const launcher = join(writable, "launcher with spaces;$literal");
      const askpass = setting === "GIT_ASKPASS" || setting === "core.askPass";
      const targetDirectory = writableTarget ? writable : trusted;
      const marker = join(trusted, "invoked");
      for (const name of ["approved", "replacement"]) {
        await writeFile(
          join(targetDirectory, name),
          `#!/bin/sh\nprintf '%s' ${name} > "$LAUNCHER_MARKER"\nexit 1\n`,
          { mode: 0o755 },
        );
      }
      await symlink(join(targetDirectory, "approved"), launcher);
      const scheme = setting === "GIT_SSH" ? "ssh" : askpass ? "https" : "git";
      git(
        "remote",
        "set-url",
        "origin",
        `${scheme}://127.0.0.1:1/example/repository.git`,
      );
      const environment: NodeJS.ProcessEnv = {
        GITLAB_HOST: "127.0.0.1:1",
      };
      if (setting === "core.askPass") {
        environment["GIT_CONFIG_GLOBAL"] = join(trusted, "operator.gitconfig");
        environment["GIT_CONFIG_NOSYSTEM"] = "1";
        git(
          "config",
          "--file",
          environment["GIT_CONFIG_GLOBAL"],
          setting,
          launcher,
        );
      } else {
        environment[setting] = launcher;
      }
      const venv = join(trusted, "venv");
      let prefix: string | undefined;
      if (setting === "GIT_ASKPASS") {
        await promisify(execFile)(process.env["PYTHON"] ?? "python3", [
          "-m",
          "venv",
          "--without-pip",
          "--symlinks",
          venv,
        ]);
        environment["SSH_ASKPASS"] = join(venv, "bin", "python");
      }
      const outcome = await runSavedPublication(
        directory,
        {
          environment,
          manualCodexPreparation: true,

          onCodex: async (args, output) => {
            output!.appServer!.onPermissions!({
              directory,
              environment,
              profile: {
                extends: ":workspace",
                network: { enabled: false },
                workspace_roots: { [writable]: true },
                filesystem: { ":tmpdir": {}, ":slash_tmp": {} },
              },
            });
            await output!.appServer!.onBeforeTurn?.();
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: async (tool, args, cwd, options) => {
            if (args.includes("codex-security-ssh-config"))
              return "hostname 127.0.0.1";
            if (tool !== "git" || args.includes("ls-remote")) return "";
            if (!options?.patchTransport || !args.includes("push"))
              return runGitRepositoryCommand(tool, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });

            // The host has just revalidated the launcher. Git has yet to look it up.
            await unlink(launcher);
            await symlink(join(targetDirectory, "replacement"), launcher);
            // Exercise Git's askpass lookup without requiring an HTTP server.
            if (setting === "GIT_ASKPASS") {
              const python = options.environment!["SSH_ASKPASS"]!;
              prefix = (
                await promisify(execFile)(python, [
                  "-c",
                  "import sys; print(sys.prefix)",
                ])
              ).stdout.trim();
            }
            return runGitRepositoryCommand(
              tool,
              askpass
                ? ["-c", "credential.helper=", "credential", "fill"]
                : args,
              cwd,
              {
                ...options,
                input: askpass
                  ? "protocol=https\nhost=127.0.0.1\n\n"
                  : undefined,
                environment: {
                  ...options.environment,
                  LAUNCHER_MARKER: marker,
                  GIT_TERMINAL_PROMPT: "0",
                },
              },
            );
          },
        },
        { localHosting: false },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      if (writableTarget) {
        expect(outcome.stderr).toContain("patch-writable");
        await expect(readFile(marker)).rejects.toMatchObject({
          code: "ENOENT",
        });
      } else {
        if (setting === "GIT_ASKPASS")
          expect(prefix).toBe(await realpath(venv));
        expect(await readFile(marker, "utf8")).toBe("approved");
      }
    },
  );

  test.each([
    "ssh config",
    "identity",
    "known hosts",
    "interpreter script",
    "resume",
    "approved known-hosts update",
  ] as const)(
    "preserves selected transport file identity: %s",
    async (kind) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-transport-input-");
      const file = join(external, "operand");
      await writeFile(file, "approved\n");
      const path = file.replaceAll("\\", "/");
      const sshCommand =
        kind === "interpreter script"
          ? 'node "' + path + '"'
          : kind === "identity"
            ? 'ssh -i "' + path + '"'
            : kind === "known hosts" || kind === "approved known-hosts update"
              ? 'ssh -o "UserKnownHostsFile=' + path + '"'
              : 'ssh -F "' + path + '"';
      git("remote", "set-url", "origin", "git@work:example/repository.git");
      const branch = "codex-security/patch-scan-1";
      const resume = kind === "resume";
      if (resume) {
        git("branch", branch);
        git(
          "config",
          "branch." + branch + ".codexSecurityPatchCommit",
          git("rev-parse", "HEAD"),
        );
      }
      const approvedUpdate = kind === "approved known-hosts update";
      let changed = false;
      let pushed = false;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment: {
            GIT_SSH_COMMAND: sshCommand,
            GITLAB_HOST: "gitlab.com",
          },
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            expect(resume).toBe(false);
            if (!approvedUpdate) {
              await writeFile(file, "replaced by patch\n");
              changed = true;
            }
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: async (tool, args, cwd, options) => {
            if (args.includes("codex-security-ssh-config")) {
              if (resume && !changed) {
                await writeFile(file, "replaced during resume\n");
                changed = true;
              }
              return "hostname gitlab.com";
            }
            if (args.includes("ls-remote")) {
              if (approvedUpdate) {
                // A successful SSH connection can record a new host key.
                await writeFile(file, "operator-approved host key\n");
                changed = true;
              }
              return "";
            }
            if (args.includes("push")) {
              pushed = true;
              throw new Error("fixture reached push");
            }
            return tool === "git"
              ? runGitRepositoryCommand(tool, args, cwd, options)
              : "";
          },
        },
        { localHosting: false },
      );
      expect(changed, outcome.stderr).toBe(true);
      expect(pushed, outcome.stderr).toBe(approvedUpdate);
      expect(outcome.stderr).toContain(
        approvedUpdate
          ? "fixture reached push"
          : "Patch transport file changed",
      );
    },
  );

  test.each([
    "created during preflight",
    "stays absent",
    "replaced after preflight creation",
    "appears during the patch",
    "parent replaced",
    "writable parent",
    "dangling link",
  ] as const)(
    "binds an initially absent SSH known-hosts file: %s",
    async (mode) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-known-hosts-");
      const parent = join(external, "keys");
      const hosts = join(parent, "known_hosts");
      await mkdir(parent);
      if (mode === "dangling link") {
        const target = join(external, "removed");
        await mkdir(target);
        await symlink(
          target,
          hosts,
          process.platform === "win32" ? "junction" : "dir",
        );
        await rmdir(target);
      }
      const environment = {
        GIT_SSH_COMMAND: `ssh -o "UserKnownHostsFile=${hosts.replaceAll("\\", "/")}" -o StrictHostKeyChecking=accept-new`,
        GITLAB_HOST: "gitlab.example.test",
      };
      git(
        "remote",
        "set-url",
        "origin",
        "git@gitlab.example.test:example/repository.git",
      );
      let turnStarted = false;
      let pushed = false;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          manualCodexPreparation: true,
          onCodex: async (_args, output) => {
            output!.appServer!.onPermissions!({
              directory,
              environment,
              profile: {
                extends: ":workspace",
                workspace_roots:
                  mode === "writable parent" ? { [parent]: true } : {},
                filesystem: { ":tmpdir": {}, ":slash_tmp": {} },
              },
            });
            await output!.appServer!.onBeforeTurn?.();
            turnStarted = true;
            if (mode === "parent replaced") {
              await rename(parent, join(external, "original"));
              await mkdir(parent);
            } else if (mode === "appears during the patch") {
              await writeFile(hosts, "unexpected key\n", { flag: "wx" });
            } else if (mode === "replaced after preflight creation") {
              await writeFile(hosts, "replacement key\n", { flag: "r+" });
            }
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            output!.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
          onRepositoryCommand: async (tool, args, cwd, options) => {
            if (tool !== "git") return "";
            if (args.includes("ls-remote")) {
              if (
                mode === "created during preflight" ||
                mode === "replaced after preflight creation"
              ) {
                // Model the authorized SSH connection recording a host for the first time.
                await writeFile(hosts, "first host key\n", { flag: "wx" });
              }
              return "";
            }
            if (args.includes("push")) {
              pushed = true;
              throw new Error("fixture reached push");
            }
            return runGitRepositoryCommand(tool, args, cwd, options);
          },
        },
        { localHosting: false },
      );
      const allowed =
        mode === "created during preflight" || mode === "stays absent";
      expect(pushed, outcome.stderr).toBe(allowed);
      expect(turnStarted, outcome.stderr).toBe(
        mode !== "writable parent" && mode !== "dangling link",
      );
      if (allowed) expect(outcome.stderr).toContain("fixture reached push");
      else if (turnStarted)
        expect(outcome.stderr).toContain("Patch transport file changed");
      else if (mode === "writable parent")
        expect(outcome.stderr).toContain("outside patch-writable directories");
      if (mode === "stays absent")
        await expect(readFile(hosts)).rejects.toMatchObject({ code: "ENOENT" });
    },
  );

  test("push uses the SSH command approved before branch-conditional configuration activates", async () => {
    const { directory, git } = await publicationRepository();
    const external = await fixtures.create("patch-ssh-transport-");
    const marker = join(external, "marker");
    const script = join(external, "transport.cjs");
    const globalConfig = join(external, "user.gitconfig");
    const askPass = join(directory, ".git", "prompt.sh");
    await writeFile(askPass, "#!/bin/sh\necho synthetic\n", { mode: 0o755 });
    await writeFile(
      script,
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, JSON.stringify([process.argv[2], process.env.SSH_ASKPASS ?? ""])); process.exit(1);`,
    );
    const command = (label: string) =>
      `node "${script.replaceAll("\\", "/")}" ${label}`;
    git(
      "config",
      "--file",
      globalConfig,
      "core.sshCommand",
      command("approved"),
    );
    git(
      "config",
      "--file",
      join(directory, ".git", "patch-transport"),
      "core.sshCommand",
      command("checkout"),
    );
    git(
      "config",
      "includeIf.onbranch:codex-security/**.path",
      "patch-transport",
    );
    git("remote", "set-url", "origin", "git@gitlab.com:example/repository.git");

    const environment = {
      GIT_CONFIG_GLOBAL: globalConfig,
      SSH_ASKPASS: askPass,
      SSH_ASKPASS_REQUIRE: "force",
    };
    const outcome = await runSavedPublication(
      directory,
      {
        environment,

        onCodex: async (args, output) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
        onRepositoryCommand: (tool, args, cwd, options) => {
          if (tool === "glab") return "";
          if (args.includes("ls-remote")) {
            expect(options?.environment?.["SSH_ASKPASS"]).toBe("");
            expect(options?.environment?.["GIT_SSH_COMMAND"]).toEndWith(
              ` '${script}' 'approved'`,
            );
            return "";
          }
          return runGitRepositoryCommand(tool, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
      },
      { localHosting: false },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(git("config", "--get", "core.sshCommand")).toBe(command("checkout"));
    const received = JSON.parse(await readFile(marker, "utf8"));
    expect(received).toEqual(["approved", ""]);
  });

  test.each([false, true])(
    "automatic publication pushes without signing certificates, resume=%p",
    async (resume) => {
      const { directory, git, remote } = await publicationRepository();
      const branch = "codex-security/patch-scan-1";
      git(
        "-C",
        remote,
        "config",
        "receive.certNonceSeed",
        "synthetic-test-seed",
      );
      git("config", "push.gpgSign", resume ? "if-asked" : "true");
      git("config", "gpg.format", "openpgp");
      git(
        "config",
        "gpg.openpgp.program",
        join(directory, "nonexistent-test-signer"),
      );
      git("config", "user.signingKey", "synthetic-test-key");
      if (resume) {
        git("branch", branch);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchCommit`,
          git("rev-parse", "HEAD"),
        );
      }
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (tool, args, cwd, options) =>
            tool === "git"
              ? runGitRepositoryCommand(tool, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("-C", remote, "rev-parse", `refs/heads/${branch}`)).toBe(
        git("rev-parse", branch),
      );
    },
  );

  test("publication commits do not run a checkout-selected signer", async () => {
    const { directory, git, remote } = await publicationRepository();
    const outside = await fixtures.create("patch-signer-");
    const marker = join(outside, "called");
    const signer = join(directory, "signer");
    await writeFile(
      signer,
      `#!/bin/sh\nprintf called > '${marker.replaceAll("\\", "/").replaceAll("'", "'\\''")}'\nexit 1\n`,
      { mode: 0o755 },
    );
    git("add", "signer");
    git("commit", "-m", "Synthetic signer fixture");
    git("config", "commit.gpgSign", "true");
    git("config", "gpg.program", "./signer");
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onCodex: async (_args, output) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
        onRepositoryCommand: (tool, args, cwd, options) =>
          tool === "git"
            ? runGitRepositoryCommand(tool, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
      },
    );
    await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(git("ls-remote", remote)).toContain(git("rev-parse", "HEAD"));
  });

  test.each(
    [false, true].flatMap((resume) =>
      ["github.com", "gitlab.com"].flatMap((host) =>
        [
          "path",
          "file-url",
          ...(process.platform === "win32" ? [] : ["newline-relative"]),
          ...(process.platform === "win32" ? ["drive-relative"] : []),
        ].map((spelling) => ({ resume, host, spelling })),
      ),
    ),
  )(
    "rejects all-local pushes with a hosted fetch URL: $host, resume=$resume, $spelling",
    async ({ resume, host, spelling }) => {
      const { directory, git, remote } = await publicationRepository();
      git(
        "remote",
        "set-url",
        "origin",
        `https://${host}/example/repository.git`,
      );
      let pushUrl = remote;
      if (spelling === "file-url") pushUrl = pathToFileURL(remote).href;
      if (spelling === "newline-relative") pushUrl = "\nproject";
      if (spelling === "drive-relative") {
        pushUrl = parse(remote).root.slice(0, 2) + relative(directory, remote);
        expect(pushUrl).toMatch(/^[a-z]:[^\\/]/iu);
        expect(git("ls-remote", pushUrl)).toBe("");
      }
      git("remote", "set-url", "--push", "origin", pushUrl);
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", "HEAD");
      if (resume) {
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
      }
      const model = mock(async () => 0);
      const hosting = mock(() => "[]");
      let pushes = 0;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: model,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command !== "git") return hosting();
            if (args[0] === "push") pushes++;
            return runGitRepositoryCommand(command, args, cwd, options);
          },
        },
        { localHosting: false },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("network push URL");
      expect(model).not.toHaveBeenCalled();
      expect(hosting).not.toHaveBeenCalled();
      expect(pushes).toBe(0);
      expect(git("rev-parse", "HEAD")).toBe(commit);
      expect(git("ls-remote", remote, `refs/heads/${branch}`)).toBe("");
    },
  );

  test.each(
    [false, true].flatMap((resume) =>
      ["https", "scp", "ssh", "same-repository", "transferred"].map(
        (transport) => ({ resume, transport }),
      ),
    ),
  )(
    "publishes the pushed GitHub head: $transport, resume=$resume",
    async ({ resume, transport }) => {
      const { directory, git, remote } = await publicationRepository();
      const base = "https://github.example.test/example/repository";
      const pushOwner =
        transport === "same-repository" ? "example" : "synthetic-user";
      const configuredOwner =
        transport === "transferred" ? "previous-owner" : pushOwner;
      const path = `${configuredOwner}/repository.git`;
      const push =
        transport === "scp"
          ? `git@github.example.test:${path}`
          : transport === "ssh"
            ? `ssh://git@github.example.test/${path}`
            : `https://github.example.test/${path}`;
      git("remote", "set-url", "origin", `${base}.git`);
      git("remote", "set-url", "--push", "origin", push);
      const branch = "codex-security/patch-scan-1";
      if (resume) {
        git("branch", branch);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchCommit`,
          git("rev-parse", "HEAD"),
        );
      }
      let creates = 0;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment: { GH_REPO: "example/repository" },
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", directory),
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("ls-remote"))
                return runLocalHostingTransport(
                  command,
                  ["ls-remote", "--heads", "--", remote],
                  cwd,
                  options,
                );
              if (args[0] === "push")
                return runLocalHostingTransport(
                  command,
                  args.map((arg) => (arg === "origin" ? remote : arg)),
                  cwd,
                  options,
                );
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe("gh");
            if (args[1] === "list") return "[]";
            if (args.at(-1) === ".url") return base;
            if (args[1] === "set-default")
              return `${configuredOwner}/repository`;
            if (args.at(-1) === "tojson" && args.includes("id,url")) {
              return JSON.stringify({
                id: "synthetic-origin-id",
                url: `https://github.example.test/${pushOwner}/repository`,
              });
            }
            expect(args[args.indexOf("--head") + 1]).toBe(
              transport === "same-repository"
                ? branch
                : `${pushOwner}:${branch}`,
            );
            expect(git("--git-dir", remote, "rev-parse", branch)).toBe(
              git("rev-parse", branch),
            );
            creates++;
            return `${base}/pull/1`;
          },
        },
        { localHosting: false },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(creates).toBe(1);
      expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(`${base}/pull/1`);
    },
  );

  test.each(
    ["local", "remote"].flatMap((location) =>
      [
        "codex-security",
        "codex-security/patch-scan-1",
        "codex-security/patch-scan-1/other",
        "codex-security/patch-scan-10",
        "archive/refs/heads/codex-security",
        "archive/refs/heads/codex-security/patch-scan-1",
        "archive/refs/heads/codex-security/patch-scan-1/other",
      ].map((existing) => [location, existing] as const),
    ),
  )(
    "checks %s branch namespace %s before patching",
    async (location, existing) => {
      const { directory, git, remote } = await publicationRepository();
      if (location === "remote")
        git("push", "origin", `HEAD:refs/heads/${existing}`);
      else git("branch", existing);
      const head = git("rev-parse", "HEAD");
      const before = git("ls-remote", remote);
      const blocked = [
        "codex-security",
        "codex-security/patch-scan-1",
        "codex-security/patch-scan-1/other",
      ].includes(existing);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runSavedPublication(directory, {
        result,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onCodex,
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
      });
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      expect(onCodex).toHaveBeenCalledTimes(blocked ? 0 : 1);
      if (blocked) {
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("ls-remote", remote)).toBe(before);
      }
    },
  );

  test.each([
    ["insteadOf", "free"],
    ["insteadOf", "decoy"],
    ["insteadOf", "destination"],
    ["pushInsteadOf", "free"],
    ["pushInsteadOf", "decoy"],
    ["pushInsteadOf", "destination"],
  ] as const)(
    "checks the once-rewritten push destination: %s, collision=%s",
    async (rewrite, collision) => {
      const { directory, git } = await publicationRepository();
      const destination = await fixtures.create("patch-rewrite-destination=");
      const decoy = await fixtures.create("patch-rewrite-decoy-");
      for (const remote of [destination, decoy])
        git("clone", "--bare", directory, remote);
      const alias = join(directory, "rewrite-alias");
      git("remote", "set-url", "origin", alias);
      git("config", `url.${destination}.${rewrite}`, alias);
      git("config", `url.${decoy}.insteadOf`, destination);
      const branch = "codex-security/patch-scan-1";
      const head = git("rev-parse", "HEAD");
      if (collision !== "free")
        git(
          "--git-dir",
          collision === "decoy" ? decoy : destination,
          "update-ref",
          `refs/heads/${branch}`,
          head,
        );
      const decoyRefs = git("--git-dir", decoy, "show-ref");
      const configuration = git("config", "--get-regexp", "^(remote|url)\\.");
      expect(git("remote", "get-url", "--push", "origin")).toBe(destination);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runSavedPublication(directory, {
        result,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onCodex,
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
      });
      const blocked = collision === "destination";
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      expect(onCodex).toHaveBeenCalledTimes(blocked ? 0 : 1);
      expect(git("--git-dir", decoy, "show-ref")).toBe(decoyRefs);
      expect(git("config", "--get-regexp", "^(remote|url)\\.")).toBe(
        configuration,
      );
      if (blocked) {
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("--git-dir", destination, "rev-parse", branch)).toBe(head);
      } else {
        expect(
          git("--git-dir", destination, "show", `${branch}:src/finding-1.ts`),
        ).toBe("fixed");
      }
    },
  );

  const libcurl = /^libcurl: (\d+\.\d+\.\d+)/mu.exec(
    execFileSync("git", ["version", "--build-options"], { encoding: "utf8" }),
  )?.[1];
  test.each([
    { collision: false, credentials: "home netrc" },
    { collision: true, credentials: "home netrc" },
    { collision: false, credentials: "askpass" },
    ...(libcurl && Bun.semver.satisfies(libcurl, ">=8.16.0")
      ? [{ collision: false, credentials: "selected netrc" }]
      : []),
  ])(
    "preserves the operator's proxy, HTTPS credentials, cookie and TLS key with %j",
    async ({ collision, credentials }) => {
      const { directory, git, remote } = await publicationRepository();
      const secondary = await fixtures.create("patch-proxy-secondary-");
      git("init", "--bare", secondary);
      for (const destination of [remote, secondary])
        git("--git-dir", destination, "config", "http.receivepack", "true");
      if (collision) git("push", secondary, "HEAD:refs/heads/codex-security");
      let requests = 0;
      const environment = { ...process.env };
      const home = await fixtures.create("patch-transport-home-");
      environment["HOME"] = home;
      if (process.platform === "win32") environment["USERPROFILE"] = home;
      for (const key of Object.keys(environment))
        if (/^(?:NETRC|GIT_ASKPASS|SSH_ASKPASS)$/iu.test(key))
          delete environment[key];
      environment["GIT_CONFIG_NOSYSTEM"] = "1";
      environment["GIT_TERMINAL_PROMPT"] = "0";
      const username = "fixture";
      const askPass = join(home, "askpass");
      const password =
        credentials === "askpass"
          ? "synthetic-askpass-only"
          : "synthetic-netrc-only";
      if (credentials === "askpass") {
        environment["LC_ALL"] = "C";
        await writeFile(
          askPass,
          [
            "#!/bin/sh",
            'case "$1" in',
            `  Username*) echo username >> "$0.calls"; echo ${username} ;;`,
            `  Password*) echo password >> "$0.calls"; echo ${password} ;;`,
            "  *) exit 1 ;;",
            "esac",
            "",
          ].join("\n"),
          { mode: 0o700 },
        );
      } else {
        const netrcFile = join(
          home,
          credentials === "selected netrc"
            ? "selected credentials"
            : process.platform === "win32"
              ? "_netrc"
              : ".netrc",
        );
        if (credentials === "selected netrc")
          environment["NETRC"] = relative(directory, netrcFile);
        await writeFile(
          netrcFile,
          `machine 127.0.0.2 login ${username} password ${password}\n`,
          { mode: 0o600 },
        );
      }
      const authorization =
        "Basic " + Buffer.from(`${username}:${password}`).toString("base64");
      for (const key of Object.keys(environment))
        if (/^(?:https?|all|no)_proxy$/iu.test(key)) delete environment[key];
      const config = join(
        await fixtures.create("patch-proxy-config-"),
        "gitconfig",
      );
      if (credentials === "askpass") {
        git("config", "--file", config, "credential.helper", "");
        git(
          "config",
          "--file",
          config,
          "core.askPass",
          askPass.replaceAll("\\", "/"),
        );
      }
      const combined = !collision && credentials === "home netrc";
      const client = await loopbackTls(config, git, "client", combined);
      const serverTls = await loopbackTls(config, git);
      const proxyClient = collision
        ? undefined
        : await loopbackTls(config, git, "proxy-client", combined);
      const origin = Bun.serve({
        tls: {
          ...serverTls,
          ca: client.cert,
          requestCert: true,
          rejectUnauthorized: true,
        },
        hostname: "127.0.0.1",
        port: 0,
        async fetch(request) {
          requests++;
          if (request.headers.get("authorization") !== authorization)
            return new Response(null, {
              status: 401,
              headers: { "WWW-Authenticate": 'Basic realm="fixture"' },
            });
          if (request.headers.get("cookie") !== "patch-session=synthetic")
            return new Response(null, { status: 403 });
          const url = new URL(request.url);
          const child = Bun.spawn(["git", "http-backend"], {
            env: {
              ...environment,
              GIT_PROJECT_ROOT: dirname(remote),
              GIT_HTTP_EXPORT_ALL: "1",
              REQUEST_METHOD: request.method,
              PATH_INFO: url.pathname,
              QUERY_STRING: url.search.slice(1),
              CONTENT_TYPE: request.headers.get("content-type") ?? "",
              CONTENT_LENGTH: request.headers.get("content-length") ?? "0",
              REMOTE_USER: "synthetic",
              GIT_PROTOCOL: request.headers.get("git-protocol") ?? "",
            },
            stdin: new Uint8Array(await request.arrayBuffer()),
            stdout: "pipe",
            stderr: "pipe",
          });
          const response = Buffer.from(
            await new Response(child.stdout).arrayBuffer(),
          );
          const errors = await new Response(child.stderr).text();
          expect(await child.exited, errors).toBe(0);
          const boundary = response.indexOf("\r\n\r\n");
          const headers = new Headers();
          let status = 200;
          for (const line of response
            .subarray(0, boundary)
            .toString()
            .split("\r\n")) {
            const colon = line.indexOf(":");
            const key = line.slice(0, colon),
              value = line.slice(colon + 1).trim();
            if (key.toLowerCase() === "status") status = Number.parseInt(value);
            else headers.set(key, value);
          }
          return new Response(response.subarray(boundary + 4), {
            status,
            headers,
          });
        },
      });
      try {
        const cookieFile = join(dirname(config), "operator cookies.txt");
        await writeFile(
          cookieFile,
          "# Netscape HTTP Cookie File\n127.0.0.2\tFALSE\t/\tTRUE\t0\tpatch-session\tsynthetic\n",
        );
        git(
          "config",
          "--file",
          config,
          `http.https://127.0.0.2:${origin.port}/.cookieFile`,
          cookieFile,
        );
        using proxy = await loopbackProxy(
          origin.port!,
          proxyClient
            ? {
                ...serverTls,
                ca: proxyClient.cert,
                requestCert: true,
                rejectUnauthorized: true,
              }
            : undefined,
        );
        git(
          "remote",
          "set-url",
          "origin",
          `https://127.0.0.2:${origin.port}/${remote.split(/[\\/]/u).at(-1)!}`,
        );
        for (const destination of [remote, secondary])
          git(
            "config",
            "--file",
            config,
            "--add",
            "remote.origin.pushurl",
            `https://127.0.0.2:${origin.port}/${destination.split(/[\\/]/u).at(-1)!}`,
          );
        git("config", "--file", config, "remote.origin.proxy", proxy.url);
        if (proxyClient)
          git(
            "config",
            "--file",
            config,
            "http.proxySSLCAInfo",
            git("config", "--file", config, "http.sslCAInfo"),
          );
        environment["GIT_CONFIG_GLOBAL"] = config;
        // The proxy and origin require their own client keys.
        for (const prefix of proxyClient
          ? ["http.proxySSL", "http.ssl"]
          : ["http.ssl"]) {
          const option = prefix + (combined ? "Cert" : "Key");
          await expect(
            promisify(execFile)(
              "git",
              [
                "-c",
                `${option}=${join(dirname(config), "missing.key")}`,
                "ls-remote",
                "origin",
              ],
              { cwd: directory, env: environment },
            ),
          ).rejects.toThrow();
          if (prefix === "http.proxySSL") expect(proxy.tunnels).toBe(0);
          expect(requests).toBe(0);
        }
        if (credentials === "askpass") {
          await expect(
            promisify(execFile)(
              "git",
              ["-c", "core.askPass=", "ls-remote", "origin"],
              {
                cwd: directory,
                env: environment,
              },
            ),
          ).rejects.toThrow(/terminal prompts disabled/u);
          expect(requests).toBeGreaterThan(0);
        }
        const remoteConfig = git("config", "--get-regexp", "^remote\\.");
        let models = 0;
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            environment,
            onRepositoryCommand: async (command, args, cwd, options) => {
              if (command !== "git")
                return args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1";
              const child = promisify(execFile)("git", [...args], {
                cwd,
                env: { ...environment, ...options?.environment },
                maxBuffer: options?.maxBuffer,
                encoding: options?.encoding === "base64" ? "buffer" : "utf8",
              });
              child.child.stdin?.end(options?.input);
              const { stdout } = await child;
              const text = Buffer.isBuffer(stdout)
                ? stdout.toString(options?.encoding ?? "utf8")
                : stdout;
              return options?.trim === false ? text : text.trim();
            },
            onCodex: async (_args, output) => {
              models++;
              if (credentials === "askpass")
                await writeFile(askPass + ".calls", "");
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              output?.stdout.write("Fixed and verified.");
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(collision ? 2 : 0);
        expect(models).toBe(collision ? 0 : 1);
        expect(proxy.tunnels).toBeGreaterThan(0);
        expect(requests).toBeGreaterThanOrEqual(2);
        expect(git("config", "--get-regexp", "^remote\\.")).toBe(remoteConfig);
        if (credentials === "askpass") {
          const prompts = (await readFile(askPass + ".calls", "utf8")).split(
            /\r?\n/u,
          );
          expect(prompts).toContain("username");
          expect(prompts).toContain("password");
        }
        if (collision) expect(outcome.stderr).toContain("already exists");
        else {
          const branch = `refs/heads/${git("branch", "--show-current")}`;
          for (const destination of [remote, secondary]) {
            expect(git("--git-dir", destination, "rev-parse", branch)).toBe(
              git("rev-parse", "HEAD"),
            );
            expect(
              git(
                "--git-dir",
                destination,
                "show",
                `${branch}:src/finding-1.ts`,
              ),
            ).toBe("fixed");
          }
        }
      } finally {
        origin.stop(true);
      }
    },
  );

  test.each([
    "free",
    "occupied",
    "race",
    "option",
    "uploadpack",
    "legacy-free",
    "legacy-occupied",
    "legacy-settings",
  ] as const)(
    "preserves all push destinations: second destination=%s",
    async (destination) => {
      const occupied =
        destination === "occupied" ||
        destination === "race" ||
        destination === "legacy-occupied" ||
        destination === "legacy-settings";
      const option = destination === "option";
      const { directory, git, remote } = await publicationRepository();
      const secondary = await fixtures.create("patch-destination-secondary-");
      git("clone", "--bare", directory, secondary);
      const branch = "codex-security/patch-scan-1";
      const original = git("rev-parse", "HEAD");
      const occupy = () =>
        git(
          "--git-dir",
          secondary,
          "update-ref",
          `refs/heads/${branch}`,
          original,
        );
      if (occupied && destination !== "race") occupy();
      git("remote", "set-url", "--add", "--push", "origin", remote);
      const marker = join(directory, "upload-pack-marker");
      const script = join(directory, "upload-pack.cjs");
      if (option)
        await writeFile(
          script,
          "require('node:fs').writeFileSync(process.argv[2], 'synthetic');\n",
        );
      const commandPath = (value: string) => `"${value.replaceAll("\\", "/")}"`;
      git(
        "config",
        "--add",
        "remote.origin.pushurl",
        option
          ? `--upload-pack=${commandPath(process.execPath)} ${commandPath(script)} ${commandPath(marker)}`
          : secondary,
      );
      const environment: NodeJS.ProcessEnv = {};
      const uploadTrace = join(directory, ".git", "transport-trace");
      if (destination === "uploadpack") {
        const transportDirectory = await fixtures.create("patch-transport-");
        const transport = join(transportDirectory, "transport.cjs");
        const config = join(transportDirectory, "operator.gitconfig");
        environment["GIT_CONFIG_GLOBAL"] = config;
        await writeFile(
          transport,
          `
const { spawnSync } = require("node:child_process");
const { appendFileSync } = require("node:fs");
if (process.argv[2] === "upload-pack") appendFileSync(${JSON.stringify(uploadTrace)}, process.argv[3] + "\\n");
const result = spawnSync(${JSON.stringify(Bun.which("git")!)}, [process.argv[2], process.argv[3].replace(/\\.logical$/, "")], { stdio: "inherit" });
process.exit(result.status ?? 1);
`,
        );
        for (const operation of ["upload", "receive"])
          git(
            "config",
            "--file",
            config,
            `remote.origin.${operation}pack`,
            `${commandPath(process.execPath)} ${commandPath(transport)} ${operation}-pack`,
          );
        git("config", "--unset-all", "remote.origin.pushurl");
        git("config", "--add", "remote.origin.pushurl", `${remote}.logical`);
        git("config", "--add", "remote.origin.pushurl", `${secondary}.logical`);
        const include = `include.path=${config}`;
        git("-c", include, "push", "origin", "HEAD:refs/heads/native-control");
        git("-c", include, "ls-remote", "origin");
        await writeFile(uploadTrace, "");
      }
      if (destination.startsWith("legacy-")) {
        git("config", "--remove-section", "remote.origin");
        await mkdir(join(directory, ".git", "remotes"));
        await writeFile(
          join(directory, ".git", "remotes", "origin"),
          `URL: ${remote}\nURL: ${secondary}\nPull: refs/heads/main:refs/remotes/origin/main\n`,
        );
        if (destination === "legacy-settings")
          git("config", "remote.origin.skipDefaultUpdate", "true");
      }
      const before = git("ls-remote", secondary, `refs/heads/${branch}`);
      const result = resultWithFindings(["high"]);
      const onCodex = mock(
        async (
          args: readonly string[],
          output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
        ) => {
          if (destination === "race") occupy();
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      );
      const outcome = await runSavedPublication(directory, {
        environment,
        result,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onCodex,
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command === "git") {
            const execution = promisify(execFile)("git", [...args], {
              cwd: options?.directory ?? cwd,
              env: {
                ...process.env,
                ...environment,
                ...options?.environment,
              },
              maxBuffer: options?.maxBuffer,
              encoding: options?.encoding === "base64" ? "buffer" : "utf8",
            });
            execution.child.stdin?.end(options?.input);
            const { stdout } = await execution;
            const text = Buffer.isBuffer(stdout)
              ? stdout.toString(options?.encoding ?? "utf8")
              : stdout;
            return options?.trim === false ? text : text.trim();
          }
          return args[0] === "repo"
            ? "synthetic-origin-id"
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(occupied || option ? 2 : 0);
      if (destination === "uploadpack")
        expect(
          (await readFile(uploadTrace, "utf8")).trim().split("\n"),
        ).toEqual([`${remote}.logical`, `${secondary}.logical`]);
      expect(onCodex).toHaveBeenCalledTimes(
        (occupied && destination !== "race") || option ? 0 : 1,
      );
      await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
      if ((occupied && destination !== "race") || option) {
        if (destination.startsWith("legacy-"))
          expect(outcome.stderr).toContain("already exists");
        expect(git("rev-parse", "HEAD")).toBe(original);
        expect(git("ls-remote", remote, `refs/heads/${branch}`)).toBe("");
        expect(git("ls-remote", secondary, `refs/heads/${branch}`)).toBe(
          before,
        );
        return;
      }
      if (occupied) {
        if (occupied)
          expect(
            git("--git-dir", secondary, "rev-parse", `refs/heads/${branch}`),
          ).toBe(original);
        else
          expect(git("ls-remote", secondary, `refs/heads/${branch}`)).toBe(
            before,
          );
        const saved = git(
          "config",
          "--get",
          `branch.${branch}.codexSecurityPatchCommit`,
        );
        expect(saved).toBe(git("rev-parse", `refs/heads/${branch}`));
        expect(saved).not.toBe(original);
        expect(git("ls-remote", remote, `refs/heads/${branch}`)).toContain(
          saved,
        );
        expect(outcome.stderr).toContain("--resume-pr");
      } else {
        for (const target of [remote, secondary])
          expect(git("ls-remote", target, `refs/heads/${branch}`)).toContain(
            git("rev-parse", "HEAD"),
          );
      }
    },
  );

  test.each(
    [
      "local",
      "www",
      "www-mixed",
      "www-scp",
      "ssh-mirror",
      "https-mirror",
      "ssh-mirror-only",
      "https-mirror-only",
      "renamed",
      "transferred",
      "multiple-hosted",
      "no-candidates",
      "local-first",
      "file-first",
      "windows-first",
      "local-fetch",
      "local-fetch-ghrepo",
      "local-push-only",
      "network-push-only",
      "ssh-api",
      "ssh-api-port",
      "https-api-port",
      "scp-absolute-api-port",
      "ssh-uri-api-port",
      "ssh-uri-git+ssh-api-port",
      "ssh-uri-ssh+git-api-port",
      "ssh-enterprise",
      "ssh-enterprise-www",
      "https-enterprise-www",
      "scp",
      "scp-userless",
      "scp-ipv6",
      "scp-ipv6-userless",
      "scp-ipv6-api",
      "scp-expanded-ipv6-api",
      "ssh-uri-alias-ipv6-api",
      "scp-ipv6-scoped",
      "scp-ipv6-scoped-userless",
      "scp-percent",
      "ssh-uri-percent",
      "scp-mixed",
      "scp-absolute",
      "scp-absolute-command",
      "ssh-uri",
      "ssh-uri-mixed",
      "ssh-uri-git+ssh",
      "ssh-uri-ssh+git",
      "ssh-uri-git+ssh-command",
      "ssh-uri-ssh+git-command",
      "ssh-missing",
      "ssh-failed",
      "ssh-host",
      "ssh-empty",
      "scp-core",
      "ssh-uri-core",
      "scp-command",
      "ssh-uri-command",
      "scp-executable",
      "ssh-uri-executable",
      "scp-core-executable",
      "ssh-uri-core-executable",
    ].flatMap((transport) =>
      [false, true].flatMap((resume) =>
        (transport === "no-candidates" ? [false] : [false, true]).map(
          (ownIncluded) => ({
            transport,
            resume,
            ownIncluded,
          }),
        ),
      ),
    ),
  )(
    "uses the push repository for $transport: resume=$resume, own PR=$ownIncluded",
    async ({ transport, resume, ownIncluded }) => {
      const { directory, git, remote } = await publicationRepository();
      await writeFile(
        join(directory, ".git", "hosting-config"),
        "# Synthetic included Git configuration.\n",
      );
      git("config", "include.path", "hosting-config");
      const tools = await realpath(
        await fixtures.create("patch-ssh-fixtures-"),
      );
      const ssh = join(tools, process.platform === "win32" ? "ssh.exe" : "ssh");
      await writeFile(ssh, "", { mode: 0o700 });
      // Use native separators, including the literal backslashes in a
      // double-quoted Windows path passed through Git for Windows.
      const config = join(tools, "synthetic config");
      await writeFile(config, "");
      const configOption =
        transport === "scp-command" ? (resume ? "NoNe" : "none") : config;
      const configuredCommand = `ssh -F "${configOption}" -o ServerAliveInterval=60 -o IdentityFile=none -oUserKnownHostsFile=NoNe`;
      const coreCommand = transport.includes("core")
        ? configuredCommand
        : transport.endsWith("command")
          ? "ignored-ssh"
          : undefined;
      const environment: NodeJS.ProcessEnv = transport.endsWith("command")
        ? { GIT_SSH_COMMAND: configuredCommand, GIT_SSH: "ignored-ssh" }
        : transport.endsWith("executable")
          ? { GIT_SSH: relative(directory, ssh) }
          : {};
      if (transport === "local-fetch-ghrepo" || transport.endsWith("push-only"))
        environment["GH_REPO"] = "upstream-owner/repository";
      environment["GIT_EXEC_PATH"] = tools;
      environment["PATH"] = [git("--exec-path"), process.env["PATH"]].join(
        delimiter,
      );
      const effectiveCommand =
        environment["GIT_SSH_COMMAND"] || coreCommand
          ? `'${ssh}' '-F' '${configOption}' '-o' 'ServerAliveInterval=60' '-o' 'IdentityFile=none' '-oUserKnownHostsFile=NoNe'`
          : `'${ssh}'`;
      const alias =
        transport.includes("ipv6") && transport !== "ssh-uri-alias-ipv6-api"
          ? transport.includes("scoped")
            ? "[fe80::1%lo]"
            : transport.endsWith("ipv6-api")
              ? transport.includes("expanded")
                ? "[0:0:0:0:0:0:0:1]"
                : "[::1]"
              : "[2001:db8::1]"
          : transport.endsWith("-mixed")
            ? "GitHub-Work"
            : "github-work";
      const localFirst = [
        "local-first",
        "file-first",
        "windows-first",
      ].includes(transport);
      const localOnly =
        transport.startsWith("local-fetch") || transport === "local-push-only";
      const apiPort = transport.endsWith("-api-port") ? ":8443" : "";
      const hostingHost = transport.endsWith("ipv6-api")
        ? "[::1]"
        : transport.endsWith("-www")
          ? "www.enterprise.example.test"
          : transport === "ssh-enterprise" || apiPort
            ? "enterprise.example.test"
            : "github.com";
      const hostingUrl = `https://${hostingHost}${apiPort}`;
      if (apiPort)
        environment["GH_REPO"] = `${hostingHost}${apiPort}/upstream/repository`;
      const fetchRemote = `${hostingUrl}/fetch-owner/repository.git`;
      const mirror = transport.includes("mirror")
        ? `${transport.startsWith("ssh") ? "ssh://git@" : "https://"}mirror.example.test/srv/git/repository.git`
        : undefined;
      const sshScheme = transport.includes("git+ssh")
        ? "git+ssh"
        : transport.includes("ssh+git")
          ? "ssh+git"
          : "ssh";
      const remoteUser = transport.includes("percent") ? "git%2Duser" : "git";
      const repositoryPath = transport.includes("percent")
        ? "example/repository%2Dname.git"
        : "example/repository.git";
      const pushRemote =
        transport === "https-api-port" || transport === "https-enterprise-www"
          ? `${hostingUrl}/push-owner/repository.git`
          : transport === "www-scp"
            ? "git@www.github.com:push-owner/repository.git"
            : transport === "www" || transport === "www-mixed"
              ? `https://${transport === "www-mixed" ? "www.GitHub.COM" : "www.github.com"}/push-owner/repository.git`
              : mirror && transport.endsWith("only")
                ? mirror
                : transport === "renamed"
                  ? `${hostingUrl}/push-owner/old-name.git`
                  : transport === "transferred"
                    ? `${hostingUrl}/old-owner/repository.git`
                    : localFirst ||
                        mirror ||
                        [
                          "network-push-only",
                          "multiple-hosted",
                          "no-candidates",
                        ].includes(transport)
                      ? `${hostingUrl}/push-owner/repository.git`
                      : transport === "local" || localOnly
                        ? remote
                        : transport.endsWith("userless")
                          ? `${transport === "scp-userless" ? "github.com" : alias}:example/repository.git`
                          : transport === "ssh-api" ||
                              transport === "ssh-api-port"
                            ? `git@${hostingHost}:push-owner/repository.git`
                            : transport.startsWith("ssh-enterprise")
                              ? `git@${hostingHost}:push-owner/other-repository.git`
                              : transport.startsWith("scp")
                                ? `${remoteUser}@${alias}:${transport.includes("absolute") ? "/" : ""}${repositoryPath}`
                                : transport.startsWith("ssh-uri")
                                  ? `${sshScheme}://${remoteUser}@${alias}:2222/${repositoryPath}`
                                  : `git@${["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport) ? alias : "ssh.github.com"}:example/repository.git`;
      const aliasLookup =
        (transport.startsWith("scp") &&
          transport !== "scp-userless" &&
          !transport.endsWith("ipv6-api")) ||
        transport.startsWith("ssh-uri") ||
        ["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport);
      const lookupRemote =
        transport === "local" || transport === "local-push-only"
          ? undefined
          : localOnly ||
              (mirror && transport.endsWith("only")) ||
              ["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport)
            ? `${hostingHost}${apiPort}/fetch-owner/repository`
            : transport === "renamed"
              ? `${hostingHost}/push-owner/old-name`
              : transport === "transferred"
                ? `${hostingHost}/old-owner/repository`
                : transport.startsWith("ssh-enterprise")
                  ? `${hostingHost}/push-owner/other-repository`
                  : localFirst ||
                      mirror ||
                      [
                        "www",
                        "www-mixed",
                        "www-scp",
                        "network-push-only",
                        "multiple-hosted",
                        "no-candidates",
                        "ssh-api",
                        "ssh-api-port",
                        "https-api-port",
                        "https-enterprise-www",
                      ].includes(transport)
                    ? `${hostingHost}${apiPort}/push-owner/repository`
                    : `${hostingHost}${apiPort}/example/${transport === "scp-percent" ? "repository%2Dname" : transport === "ssh-uri-percent" ? "repository-name" : "repository"}`;
      const sshArguments = [
        ...(transport.startsWith("ssh-uri") ? ["-p", "2222"] : []),
        alias.startsWith("[")
          ? `${transport.endsWith("userless") ? "" : "git@"}${alias.slice(1, -1)}`
          : transport === "scp-userless"
            ? "github.com"
            : `${transport === "ssh-uri-percent" ? "git-user" : remoteUser}@${aliasLookup ? alias : "ssh.github.com"}`,
      ];
      if (transport !== "local") {
        git("remote", "set-url", "origin", fetchRemote);
        git(
          "remote",
          "set-url",
          "--push",
          "origin",
          mirror ??
            (transport === "multiple-hosted"
              ? `${hostingUrl}/first-owner/repository.git`
              : localFirst
                ? transport === "file-first"
                  ? pathToFileURL(remote).href
                  : transport === "windows-first"
                    ? "C:\\synthetic\\mirror.git"
                    : remote
                : pushRemote),
        );
        if (
          localFirst ||
          (mirror && !transport.endsWith("only")) ||
          transport === "multiple-hosted"
        )
          git("remote", "set-url", "--add", "--push", "origin", pushRemote);
        git(
          "remote",
          "add",
          "upstream",
          `${hostingUrl}/upstream-owner/repository.git`,
        );
      }
      if (transport.endsWith("push-only"))
        git("config", "--unset-all", "remote.origin.url");
      const branch = "codex-security/patch-scan-1";
      const commit = git("rev-parse", "HEAD");
      if (resume) {
        git("branch", branch);
        git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
        git(
          "config",
          `branch.${branch}.codexSecurityPatchPullRequestBody`,
          "Synthetic body",
        );
      }
      const unresolvedPush =
        ["ssh-missing", "ssh-failed", "ssh-empty"].includes(transport) ||
        transport === "ssh-mirror-only" ||
        transport === "https-mirror-only";
      const matchingRequest = ownIncluded && !unresolvedPush;
      const result = resultWithFindings(["high"]);
      let modelCalls = 0;
      let pushes = 0;
      let repositoryLookups = 0;
      let sshLookups = 0;
      const ownUrl = `${hostingUrl}/upstream/repository/pull/8`;
      const createdUrl = `${hostingUrl}/upstream/repository/pull/9`;
      const outcome = await runWorkflow(
        resume
          ? ["patch", "--resume-pr", branch, "--json"]
          : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.at(-1) === "^remote\\.origin\\.pushurl$") {
                // This host lookup fixture explicitly selects both destinations.
                const first =
                  mirror ?? `${hostingUrl}/first-owner/repository.git`;
                return [first, pushRemote]
                  .map(
                    (url) =>
                      `command\0command line:\0remote.origin.pushurl\n${url}\0`,
                  )
                  .join("");
              }
              if (
                args.includes("--show-scope") &&
                args.at(-1) === "core.sshCommand"
              ) {
                if (coreCommand !== undefined)
                  return `global\0file:${join(remote, "config")}\0${coreCommand}\0`;
                return `command\0command line:\0${args[args.indexOf("--default") + 1]}\0`;
              }
              if (args[0] === "-c" && args[2] === "codex-security-ssh-config") {
                sshLookups++;
                expect(args[1]).toStartWith(
                  "alias.codex-security-ssh-config=!",
                );
                expect(args[1]).toEndWith(`${effectiveCommand} -G`);
                if (
                  mirror?.startsWith("ssh:") &&
                  args.at(-1) === "git@mirror.example.test"
                ) {
                  expect(args.slice(3)).toEqual(["git@mirror.example.test"]);
                  return "hostname mirror.example.test";
                }
                expect(args.slice(3)).toEqual(sshArguments);
                if (transport === "ssh-missing" || transport === "ssh-failed")
                  throw Object.assign(
                    new Error("Synthetic SSH lookup failure"),
                    {
                      code: transport === "ssh-missing" ? 127 : 1,
                    },
                  );
                return transport === "ssh-empty"
                  ? ""
                  : `hostname ${transport.endsWith("ipv6-api") ? "::1" : transport === "ssh-host" ? "ssh.github.com" : hostingHost}`;
              }
              if (args[0] === "ls-remote") {
                expect(args.slice(0, 3)).toEqual([
                  "ls-remote",
                  "--heads",
                  "--",
                ]);
                expect(args.slice(4)).toEqual([
                  "refs/heads/codex-security",
                  `refs/heads/${branch}`,
                  `refs/heads/${branch}/*`,
                ]);
                return runLocalHostingTransport(
                  command,
                  [...args.slice(0, 3), remote, ...args.slice(4)],
                  cwd,
                  options,
                );
              }
              if (args[0] === "push") {
                if (
                  transport.startsWith("scp") ||
                  transport.startsWith("ssh") ||
                  transport === "www-scp"
                )
                  expect(options?.environment?.["GIT_SSH_COMMAND"]).toEndWith(
                    effectiveCommand,
                  );
                pushes++;
                expect(args).toEqual([
                  "push",
                  "--no-signed",
                  "--recurse-submodules=check",
                  `--force-with-lease=refs/heads/${branch}:`,
                  "origin",
                  `${git("rev-parse", branch)}:refs/heads/${branch}`,
                ]);
                return runLocalHostingTransport(
                  command,
                  [
                    "push",
                    "--no-signed",
                    "--recurse-submodules=check",
                    `--force-with-lease=refs/heads/${branch}:`,
                    remote,
                    `${git("rev-parse", branch)}:refs/heads/${branch}`,
                  ],
                  cwd,
                  options,
                );
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            if (args.at(-1) === ".url")
              return `${hostingUrl}/upstream/repository`;
            if (args[0] === "repo") {
              const selectedToken = gitText(
                ["config", "--get", "remote.codex-security-push.url"],
                {
                  cwd: options?.directory ?? cwd,
                  env: {
                    ...process.env,
                    ...environment,
                    ...options?.environment,
                  },
                },
              ).trim();
              const selectedRemote = gitText(
                ["ls-remote", "--get-url", selectedToken],
                {
                  cwd: options?.directory ?? cwd,
                  env: {
                    ...process.env,
                    ...environment,
                    ...options?.environment,
                  },
                },
              ).trim();
              expect(options?.environment?.["GH_REPO"]).toBe("");
              expect(options?.environment?.["GH_HOST"]).toBe(hostingHost);
              const unresolved =
                selectedRemote === remote ||
                selectedRemote === "origin" ||
                selectedRemote.startsWith("file:") ||
                selectedRemote.startsWith("C:\\") ||
                selectedRemote.includes("mirror.example.test") ||
                selectedRemote.toLowerCase().includes("github-work");
              const first = selectedRemote.includes("/first-owner/repository");
              const expected = first
                ? `${hostingHost}${apiPort}/first-owner/repository`
                : lookupRemote!;
              const selectedRepository = expected?.slice(
                expected.indexOf("/") + 1,
              );
              if (args[1] === "set-default") {
                expect(args).toEqual(["repo", "set-default", "--view"]);
                return unresolved ? "" : selectedRepository;
              }
              expect(unresolved).toBe(false);
              expect(args).toEqual([
                "repo",
                "view",
                ...(apiPort
                  ? [`${hostingHost}${apiPort}/${selectedRepository}`]
                  : []),
                "--json",
                "id,url",
                "--jq",
                "tojson",
              ]);
              repositoryLookups++;
              expect(
                decodeURIComponent(new URL(selectedRemote).pathname)
                  .replace(/^\/+|\/+$/gu, "")
                  .replace(/\.git$/u, ""),
              ).toBe(selectedRepository);
              return JSON.stringify({
                id: first ? "synthetic-first-id" : "synthetic-origin-id",
                url: `${hostingUrl}/${first ? "first-owner" : "canonical-owner"}/repository`,
              });
            }
            if (args[1] === "list") {
              expect(args).toEqual([
                "pr",
                "list",
                "--head",
                branch,
                "--state",
                "all",
                "--json",
                "url,state,headRefOid,headRepository,isCrossRepository",
                "--jq",
                "map({url, head: .headRefOid, state, repositoryId: .headRepository.id, crossRepository: .isCrossRepository}) | tojson",
                ...(environment["GH_REPO"]
                  ? ["--repo", environment["GH_REPO"]]
                  : []),
              ]);
              return JSON.stringify(
                transport === "no-candidates"
                  ? []
                  : [
                      {
                        url: `${hostingUrl}/upstream/repository/pull/7`,
                        head: commit,
                        repositoryId: "synthetic-foreign-id",
                        state: "OPEN",
                        crossRepository: true,
                      },
                      ...(ownIncluded
                        ? [
                            {
                              url: ownUrl,
                              head: commit,
                              repositoryId: "synthetic-origin-id",
                              state: "OPEN",
                              crossRepository: !!lookupRemote,
                            },
                          ]
                        : []),
                    ],
              );
            }
            return createdUrl;
          },
          onCodex: async (args, output) => {
            modelCalls++;
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
        },
        { localHosting: false },
      );
      if (transport === "local" || localOnly || localFirst) {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain("network push URL");
        expect(modelCalls).toBe(0);
        expect(pushes).toBe(0);
        expect(repositoryLookups).toBe(0);
        expect(sshLookups).toBe(0);
        return;
      }
      const creating = !matchingRequest;
      expect(outcome.exitCode, outcome.stderr).toBe(
        (!resume && matchingRequest) || unresolvedPush ? 2 : 0,
      );
      const attempts = !resume && !matchingRequest ? 2 : 1;
      expect(repositoryLookups).toBe(
        (!lookupRemote || unresolvedPush || transport === "no-candidates"
          ? 0
          : transport === "multiple-hosted"
            ? 2
            : 1) *
          attempts +
          (creating && !unresolvedPush ? 1 : 0),
      );
      expect(sshLookups).toBe(
        (aliasLookup || mirror?.startsWith("ssh:") ? 1 : 0) *
          (attempts + (creating ? 1 : 0)),
      );
      expect(modelCalls).toBe(resume || matchingRequest ? 0 : 1);
      expect(pushes).toBe(matchingRequest || unresolvedPush ? 0 : 1);
      if ((resume || !matchingRequest) && !unresolvedPush)
        expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(
          matchingRequest ? ownUrl : createdUrl,
        );
    },
  );

  test.each([
    "available only in Git's subprocess PATH",
    "selected explicitly from the Git metadata directory",
    "found through a relative GIT_EXEC_PATH from a subdirectory",
  ] as const)("resumes publication with SSH %s", async (mode) => {
    const metadata =
      mode === "selected explicitly from the Git metadata directory";
    const { directory, git } = await publicationRepository();
    const nested =
      mode === "found through a relative GIT_EXEC_PATH from a subdirectory";
    const caller = metadata
      ? join(directory, ".git")
      : nested
        ? join(directory, "src")
        : directory;
    const sshDirectory = await fixtures.create("patch-git-ssh-");
    const ssh = join(sshDirectory, "ssh");
    const marker = join(sshDirectory, "probe");
    await writeFile(
      ssh,
      '#!/bin/sh\n[ "$1" = "-G" ] && [ "$2" = "git@GitHub-Work" ] || exit 1\nprintf called > "$PATCH_SSH_PROBE"\nprintf "hostname github.com\\n"\n',
      { mode: 0o755 },
    );
    const emptyPath = await fixtures.create("patch-no-ssh-");
    const gitExecutable = Bun.which("git")!;
    expect(Bun.which("ssh", { PATH: emptyPath })).toBeNull();
    const environment = {
      PATH: emptyPath,
      GIT_EXEC_PATH: nested ? relative(caller, sshDirectory) : sshDirectory,
      GIT_SSH: undefined,
      GIT_SSH_COMMAND: metadata
        ? JSON.stringify(ssh.replaceAll("\\", "/"))
        : undefined,
      PATCH_SSH_PROBE: marker,
    };
    git(
      "remote",
      "set-url",
      "origin",
      "https://github.com/example/repository.git",
    );
    git(
      "remote",
      "set-url",
      "--push",
      "origin",
      "git@GitHub-Work:example/repository.git",
    );
    const branch = "codex-security/saved-patch";
    const commit = git("rev-parse", "HEAD");
    git("branch", branch);
    git("config", `branch.${branch}.codexSecurityPatchCommit`, commit);
    const url = "https://github.com/example/repository/pull/1";
    let repositoryLookups = 0;
    const outcome = await runWorkflow(
      ["patch", "--resume-pr", branch, "--json"],
      {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command === "gh") {
            if (args[0] === "pr" && args[1] === "list")
              return JSON.stringify([
                {
                  url,
                  head: commit,
                  repositoryId: "synthetic-id",
                  state: "OPEN",
                  crossRepository: true,
                },
              ]);
            if (args[1] === "set-default") {
              expect(args).toEqual(["repo", "set-default", "--view"]);
              return "example/repository";
            }
            expect(args).toEqual([
              "repo",
              "view",
              "--json",
              "id,url",
              "--jq",
              "tojson",
            ]);
            repositoryLookups++;
            return JSON.stringify({
              id: "synthetic-id",
              url: "https://github.com/example/repository",
            });
          }
          const { stdout } = await promisify(execFile)(
            command === "git" ? gitExecutable : command,
            args,
            {
              cwd,
              env: { ...process.env, ...environment, ...options?.environment },
              encoding: options?.encoding ?? "utf8",
            },
          );
          return options?.trim === false ? stdout : stdout.trim();
        },
        onCodex: throwing("must reuse the saved patch"),
      },
      { localHosting: false },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
    expect(repositoryLookups).toBe(1);
    expect(await readFile(marker, "utf8")).toBe("called");
  });
});
