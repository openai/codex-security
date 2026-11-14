import { gitText } from "./support/shell.js";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { execFile } from "node:child_process";
import {
  mkdir,
  readFile,
  realpath,
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
import { createTemporaryDirectories } from "./support/temporary-directories.js";

import {
  resultWithFindings,
  savedScan,
  completePatches,
  runWorkflow,
  runGitRepositoryCommand,
  runLocalHostingTransport,
  publicationRepository as createPublicationRepository,
} from "./cli-patch-fixtures.js";

describe("patch change tracking", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
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

  test("push from a component uses the external proxy selected before its alias is retargeted", async () => {
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
    git("push", "origin", "main");
    git(
      "remote",
      "set-url",
      "origin",
      "git://127.0.0.1:1/example/repository.git",
    );
    const environment = {
      GITLAB_HOST: "127.0.0.1:1",
      GIT_PROXY_COMMAND: relative(directory, join(alias, "proxy")).replaceAll(
        "\\",
        "/",
      ),
      GIT_CONFIG_GLOBAL: join(external, "gitconfig"),
      GIT_CONFIG_NOSYSTEM: "1",
    };
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: join(directory, "src"),
        environment,
        onCodex: async (_args, output) => {
          await unlink(alias);
          await symlink(directory, alias, linkType);
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
    expect(await readFile(marker, "utf8").catch(() => ""), outcome.stderr).toBe(
      "preflight\npush\n",
    );
  });

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

  test.each(["preflight", "push", "push from removed component"] as const)(
    "HTTP %s uses the operator credential helper without executing checkout helpers",
    async (stage) => {
      const { directory, git } = await publicationRepository();
      const external = await fixtures.create("patch-credentials-");
      const component = join(directory, "component");
      const removesComponent = stage === "push from removed component";
      if (removesComponent) await mkdir(component);
      let challenged = false;
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch() {
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
        const global = join(external, "global.gitconfig");
        await writeFile(
          script,
          `const fs = require("node:fs"); const path = fs.readFileSync(0, "utf8").split("\\n").find(line => line.startsWith("path=")); fs.appendFileSync(${JSON.stringify(marker)}, process.argv[2] + " " + path + "\\n");`,
        );
        const helper = (owner: string) =>
          `!node "${script.replaceAll("\\", "/")}" ${owner}`;
        git("config", "--file", global, "credential.useHttpPath", "false");
        git(
          "config",
          "--file",
          global,
          `credential.${remote}.useHttpPath`,
          "true",
        );
        // This helper is trusted even though its URL scope is more specific than a generic reset.
        git(
          "config",
          "--file",
          global,
          `credential.${server.url.origin}.helper`,
          helper("operator"),
        );
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
        const environment = {
          GIT_CONFIG_GLOBAL: global,
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_TERMINAL_PROMPT: "0",
          GITLAB_HOST: server.url.origin,
          NO_PROXY: "127.0.0.1",
        };
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
              if (removesComponent) await rmdir(component);
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              if (removesComponent) output?.stdout.write("Patch complete.\n");
              else completePatches(args, output);
              return 0;
            },
            onRepositoryCommand: (tool, args, cwd, options) => {
              if (tool !== "git") return "";
              if (stage !== "preflight" && args.includes("ls-remote"))
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
        expect(challenged, outcome.stderr).toBe(true);
        expect(await readFile(marker, "utf8")).toBe(
          "operator path=example/repository.git\n",
        );
      } finally {
        server.stop(true);
      }
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
    const result = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: component,
        onCodex: model,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onRepositoryCommand: (tool, args, cwd, options) => {
          if (tool === "glab") return "";
          if (args.includes("ls-remote")) {
            probed = true;
            expect(options?.environment?.["GIT_SSH_COMMAND"]).toBe(
              "'" + helper.replaceAll("'", "'\\''") + "'",
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

  test("push uses the SSH command approved before branch-conditional configuration activates", async () => {
    const { directory, git } = await publicationRepository();
    const external = await fixtures.create("patch-ssh-transport-");
    const marker = join(external, "marker");
    const script = join(external, "transport.cjs");
    const globalConfig = join(external, "user.gitconfig");
    await writeFile(
      script,
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, process.argv[2]); process.exit(1);`,
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

    const environment = { GIT_CONFIG_GLOBAL: globalConfig };
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
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
          if (tool === "glab") return "";
          if (args.includes("ls-remote")) {
            expect(options?.environment?.["GIT_SSH_COMMAND"]).toContain(
              "'approved'",
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
    expect(await readFile(marker, "utf8")).toBe("approved");
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
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
        },
      );
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
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
        },
      );
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

  test.each([false, true])(
    "preserves operator remote proxy settings with collision=%j",
    async (collision) => {
      const { directory, git, remote } = await publicationRepository();
      const secondary = await fixtures.create("patch-proxy-secondary-");
      git("init", "--bare", secondary);
      for (const destination of [remote, secondary])
        git("--git-dir", destination, "config", "http.receivepack", "true");
      if (collision) git("push", secondary, "HEAD:refs/heads/codex-security");
      let requests = 0;
      const environment = { ...process.env };
      for (const key of Object.keys(environment))
        if (/^(?:https?|all|no)_proxy$/iu.test(key)) delete environment[key];
      const proxy = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        async fetch(request) {
          requests++;
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
        git(
          "remote",
          "set-url",
          "origin",
          `http://127.0.0.2:${proxy.port}/${remote.split(/[\\/]/u).at(-1)!}`,
        );
        for (const destination of [remote, secondary])
          git(
            "remote",
            "set-url",
            "--add",
            "--push",
            "origin",
            `http://127.0.0.2:${proxy.port}/${destination.split(/[\\/]/u).at(-1)!}`,
          );
        const config = join(
          await fixtures.create("patch-proxy-config-"),
          "gitconfig",
        );
        git(
          "config",
          "--file",
          config,
          "remote.origin.proxy",
          `http://127.0.0.1:${proxy.port}`,
        );
        environment["GIT_CONFIG_GLOBAL"] = config;
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
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              output?.stdout.write("Fixed and verified.");
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(collision ? 2 : 0);
        expect(models).toBe(collision ? 0 : 1);
        expect(requests).toBeGreaterThanOrEqual(2);
        expect(git("config", "--get-regexp", "^remote\\.")).toBe(remoteConfig);
        if (collision) expect(outcome.stderr).toContain("already exists");
        else
          for (const destination of [remote, secondary])
            expect(
              git(
                "--git-dir",
                destination,
                "show",
                `${git("branch", "--show-current")}:src/finding-1.ts`,
              ),
            ).toBe("fixed");
      } finally {
        proxy.stop(true);
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
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
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
        },
      );
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
      const configuredCommand = `ssh -F "${configOption}" -o ServerAliveInterval=60`;
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
      environment["PATH"] = [tools, process.env["PATH"]].join(delimiter);
      const effectiveCommand =
        environment["GIT_SSH_COMMAND"] || coreCommand
          ? `'${ssh}' '-F' '${configOption}' '-o' 'ServerAliveInterval=60'`
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
                expect(args.slice(0, 3)).toEqual([
                  "-c",
                  `alias.codex-security-ssh-config=!${effectiveCommand} -G`,
                  "codex-security-ssh-config",
                ]);
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
                  expect(options?.environment?.["GIT_SSH_COMMAND"]).toBe(
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

  test("resumes publication with SSH available only in Git's subprocess PATH", async () => {
    const { directory, git } = await publicationRepository();
    const sshDirectory = await fixtures.create("patch-git-ssh-");
    await writeFile(
      join(sshDirectory, "ssh"),
      '#!/bin/sh\n[ "$1" = "-G" ] && [ "$2" = "git@GitHub-Work" ] || exit 1\nprintf "hostname github.com\\n"\n',
      { mode: 0o755 },
    );
    const emptyPath = await fixtures.create("patch-no-ssh-");
    const gitExecutable = Bun.which("git")!;
    expect(Bun.which("ssh", { PATH: emptyPath })).toBeNull();
    const environment = {
      PATH: emptyPath,
      GIT_EXEC_PATH: sshDirectory,
      GIT_SSH: undefined,
      GIT_SSH_COMMAND: undefined,
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
        currentDirectory: directory,
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
              encoding: "utf8",
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
  });
});
