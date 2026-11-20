import { expect, mock, test } from "bun:test";
import { spawnSync } from "node:child_process";
import {
  readFile,
  realpath,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { delimiter, join } from "node:path";
import { pathToFileURL } from "node:url";
import { runRepositoryCommand } from "../src/cli.js";
import {
  completePatches,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
  patchDirectories,
  runSavedPublication,
} from "./cli-patch-fixtures.js";

const fixtures = patchDirectories();

test("later patch grants exclude writable directories from host and SSH command lookup", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  const external = await fixtures.create("patch-ssh-search-");
  const writable = await fixtures.create("patch-ssh-later-grant-");
  const global = join(external, "gitconfig");
  const config = join(external, "ssh_config");
  const marker = join(external, "invoked");
  const helper = "synthetic-ssh-later-helper";
  await writeFile(
    config,
    "Host *\n  BatchMode yes\n  ProxyCommand " + helper + "\n",
  );
  git(
    "config",
    "--file",
    global,
    "core.sshCommand",
    `ssh -F "${config.replaceAll("\\", "/")}"`,
  );
  git(
    "remote",
    "set-url",
    "origin",
    "ssh://git@127.0.0.1:1/example/repository.git",
  );
  const environment = {
    PATH: [writable, process.env["PATH"]].join(delimiter),
    GIT_CONFIG_GLOBAL: global,
    GIT_CONFIG_NOSYSTEM: "1",
    GITLAB_HOST: "127.0.0.1",
    PATCH_SSH_MARKER: marker,
  };
  let turns = 0;
  let preflightPath: string | undefined;
  let pushPath: string | undefined;
  let pushOptions: Parameters<typeof runRepositoryCommand>[3];
  const outcome = await runSavedPublication(
    directory,
    {
      environment,
      manualCodexPreparation: true,
      onWorkbench: () =>
        savedScan(resultWithFindings(["high", "high"]), "scan-1", directory),
      async onCodex(args, output) {
        turns++;
        output!.appServer!.onPermissions!({
          directory,
          environment,
          profile: {
            extends: ":workspace",
            network: { enabled: false },
            workspace_roots: turns === 1 ? {} : { [writable]: true },
            filesystem: { ":tmpdir": {}, ":slash_tmp": {} },
          },
        });
        await output!.appServer!.onBeforeTurn?.();
        if (turns === 2)
          await writeFile(
            join(writable, helper),
            '#!/bin/sh\necho invoked > "$PATCH_SSH_MARKER"\nexit 1\n',
            { mode: 0o755 },
          );
        await writeFile(join(directory, `src/finding-${turns}.ts`), "fixed\n");
        completePatches(args, output);
        return 0;
      },
      onRepositoryCommand(tool, args, cwd, options) {
        if (tool !== "git") return "";
        if (args.includes("ls-remote")) {
          preflightPath = options?.environment?.["PATH"];
          return "";
        }
        if (options?.patchTransport && args.includes("push")) {
          pushPath = options.environment?.["PATH"];
          pushOptions = options;
        }
        return runGitRepositoryCommand(tool, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
    },
    { localHosting: false },
  );
  expect(turns).toBe(2);
  expect(preflightPath?.split(delimiter), outcome.stderr).toContain(writable);
  expect(pushPath, outcome.stderr).toBeDefined();
  expect(pushPath!.split(delimiter)).not.toContain(writable);
  expect(outcome.exitCode, outcome.stderr).toBe(2);
  await expect(readFile(marker)).rejects.toMatchObject({ code: "ENOENT" });
  const name = process.platform === "win32" ? "gh.exe" : "gh";
  const alias = join(writable, "bin");
  await symlink(external, alias, "junction");
  await writeFile(join(external, name), "", { mode: 0o755 });
  await writeFile(join(writable, name), "", { mode: 0o755 });
  const PATH = [writable, alias].join(delimiter);
  await expect(
    runRepositoryCommand("gh", ["--version"], directory, {
      loaderAccess: pushOptions?.loaderAccess,
      sandbox: { directory, environment: { PATH }, profile: {} },
    }),
  ).rejects.toThrow("gh is not available on a trusted PATH");
});

test.each([
  "initial",
  "resume",
  "changed before push",
  "changed with inherited git -c",
] as const)(
  "refuses a local receiver alongside a hosted push destination (%s)",
  async (stage) => {
    const { directory, git } = await publicationRepository(fixtures);
    const receiver = join(directory, "receiver.git");
    git("init", "--bare", receiver);
    await writeFile(
      join(receiver, "hooks", "pre-receive"),
      "#!/bin/sh\nprintf ran > receiver-ran\n",
      { mode: 0o755 },
    );
    const hosted = "git://127.0.0.1:1/team/repository.git";
    git("remote", "set-url", "origin", hosted);
    const local =
      process.platform === "win32" ? receiver : pathToFileURL(receiver).href;
    const changed = stage.startsWith("changed");
    if (!changed) git("config", "--add", "remote.origin.pushurl", local);
    git("config", "--add", "remote.origin.pushurl", hosted);
    const branch = "codex-security/patch-scan-1";
    if (stage !== "initial") {
      git("branch", branch);
      git(
        "config",
        `branch.${branch}.codexSecurityPatchCommit`,
        git("rev-parse", "HEAD"),
      );
    }
    const model = mock(async () => 0);
    const environment: NodeJS.ProcessEnv = {
      GITLAB_HOST: "127.0.0.1:1",
      ...(stage === "changed with inherited git -c"
        ? {
            GIT_CONFIG_PARAMETERS:
              "'protocol.file.allow'='always' 'test.preserved'='yes'",
          }
        : { GIT_ALLOW_PROTOCOL: "git:file" }),
    };
    const outcome = await runWorkflow(
      stage !== "initial"
        ? ["patch", "--resume-pr", branch, "--json"]
        : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onCodex: model,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git") return "";
          if (changed && args.includes("push"))
            git("config", "--replace-all", "remote.origin.pushurl", local);
          const bound = {
            ...options,
            environment: { ...environment, ...options?.environment },
          };
          if (
            stage === "changed with inherited git -c" &&
            args.includes("push")
          )
            expect(
              runGitRepositoryCommand(
                command,
                ["config", "--get", "test.preserved"],
                cwd,
                bound,
              ),
            ).toBe("yes");
          return runGitRepositoryCommand(command, args, cwd, bound);
        },
      },
      { localHosting: false },
    );
    expect(
      await readFile(join(receiver, "receiver-ran"), "utf8").catch(() => ""),
    ).toBe("");
    expect(git("--git-dir", receiver, "for-each-ref")).toBe("");
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain(
      changed ? "transport 'file' not allowed" : "network push URL",
    );
    expect(model).not.toHaveBeenCalled();
  },
);

test.each([
  "origin",
  "secondary push URL",
  "changed before push",
  "changed with inherited git -c",
])("blocks plain HTTP publication transport (%s)", async (stage) => {
  const { directory, git } = await publicationRepository(fixtures);
  const http = "http://127.0.0.1:1/team/repository.git";
  const https = "https://127.0.0.1:1/team/repository.git";
  const branch = "codex-security/patch-scan-1";
  git("remote", "set-url", "origin", stage === "origin" ? http : https);
  if (stage === "secondary push URL") {
    git("config", "--add", "remote.origin.pushurl", https);
    git("config", "--add", "remote.origin.pushurl", http);
  }
  const resume = stage.startsWith("changed");
  if (resume) {
    git("branch", branch);
    git(
      "config",
      `branch.${branch}.codexSecurityPatchCommit`,
      git("rev-parse", "HEAD"),
    );
  }
  const environment = {
    GITLAB_HOST: "127.0.0.1:1",
    ...(stage === "changed with inherited git -c"
      ? { GIT_CONFIG_PARAMETERS: "'protocol.http.allow'='always'" }
      : { GIT_ALLOW_PROTOCOL: "http:https" }),
  };
  const model = mock(async () => 0);
  const calls: string[] = [];
  const outcome = await runWorkflow(
    resume
      ? ["patch", "--resume-pr", branch, "--json"]
      : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
    {
      currentDirectory: directory,
      environment,
      onWorkbench: () =>
        savedScan(resultWithFindings(["high"]), "scan-1", directory),
      onCodex: model,
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command !== "git") {
          calls.push(command);
          return "";
        }
        if (args.includes("ls-remote"))
          throw new Error("Unexpected publication preflight transport");
        if (args.includes("push")) {
          calls.push("push");
          git("remote", "set-url", "origin", http);
        }
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
    },
    { localHosting: false },
  );
  expect(outcome.exitCode).toBe(2);
  expect(outcome.stderr).toContain(
    resume ? "transport 'http' not allowed" : "plain HTTP",
  );
  expect(calls).toEqual(resume ? ["glab", "push"] : []);
  expect(model).not.toHaveBeenCalled();
});

test.each(["github.example.test", "gitlab.com"])(
  "keeps remote credentials in Git configuration for %s",
  async (host) => {
    const { directory, git } = await publicationRepository(fixtures);
    const credential = "synthetic-token%40literal";
    const remote = `https://synthetic-user:${credential}@${host}/example/repository.git`;
    git("remote", "set-url", "origin", remote);
    const serverOption = "option=first\nsecond";
    git("config", "remote.origin.serverOption", serverOption);
    const diagnostic = `Synthetic transport failure: ${credential}`;
    const model = mock(async () => 0);
    const environment = {
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "codexsecurity.synthetic",
      GIT_CONFIG_VALUE_0: "preserved",
    };
    let transports = 0;
    const outcome = await runSavedPublication(
      directory,
      {
        environment,

        onCodex: model,
        onRepositoryCommand: (command, args, cwd, options) => {
          expect(args.join("\n")).not.toContain(credential);
          if (command !== "git") {
            if (command === "glab")
              expect(args[args.indexOf("--repo") + 1]).toBe(
                `https://${host}/example/repository.git`,
              );
            return command === "glab" ? "" : "[]";
          }
          const commandOptions = {
            ...options,
            environment: { ...environment, ...options?.environment },
          };
          const transport = args.indexOf("ls-remote");
          if (transport >= 0) {
            const alias = args[args.indexOf("--", transport) + 1]!;
            expect(
              runGitRepositoryCommand(
                "git",
                [...args.slice(0, transport), "ls-remote", "--get-url", alias],
                cwd,
                commandOptions,
              ),
            ).toBe(remote);
            expect(
              runGitRepositoryCommand(
                "git",
                [
                  ...args.slice(0, transport),
                  "config",
                  "--get",
                  `remote.${alias}.serveroption`,
                ],
                cwd,
                commandOptions,
              ),
            ).toBe(serverOption);
            expect(
              runGitRepositoryCommand(
                "git",
                ["config", "--get", "codexsecurity.synthetic"],
                cwd,
                commandOptions,
              ),
            ).toBe("preserved");
            transports++;
            throw new Error(diagnostic);
          }
          return runGitRepositoryCommand(command, args, cwd, commandOptions);
        },
      },
      { localHosting: false },
    );
    expect(outcome.exitCode).toBe(2);
    expect(transports, outcome.stderr).toBe(1);
    expect(outcome.stderr).toContain(diagnostic);
    expect(model).not.toHaveBeenCalled();
  },
);

test.each([
  "ext::fixture-helper",
  "fixture-helper://example.test/project",
  "HTTPS://example.test/project",
])("rejects a helper transport in a secondary push URL: %s", async (helper) => {
  const { directory, git } = await publicationRepository(fixtures);
  git("config", "protocol.ext.allow", "always");
  git(
    "config",
    "--add",
    "remote.origin.pushurl",
    "https://github.example.test/example/repository.git",
  );
  git("config", "--add", "remote.origin.pushurl", helper);
  const model = mock(async () => 0);
  const commands: string[] = [];
  const outcome = await runSavedPublication(
    directory,
    {
      onCodex: model,
      onRepositoryCommand: (command, args, cwd, options) => {
        commands.push(args.includes("ls-remote") ? "transport" : command);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
    },
    { localHosting: false },
  );
  expect(outcome.exitCode).toBe(2);
  expect(outcome.stderr).toContain("remote helper");
  expect(new Set(commands)).toEqual(new Set(["git"]));
  expect(model).not.toHaveBeenCalled();
});

test.each([
  ["preflight", "vcs"],
  ["patch branch", "vcs"],
  ["resume", "vcs"],
  ["preflight", "uploadpack"],
  ["preflight", "receivepack"],
  ["preflight", "proxy"],
  ["patch branch", "proxy"],
  ["resume", "proxy"],
  ["preflight", "proxyauthmethod"],
])(
  "rejects checkout-selected publication transport (%s, remote.origin.%s)",
  async (stage, field) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const key = `remote.origin.${field}`;
    const hosted = "https://gitlab.com/example/repository.git";
    const branch = "codex-security/patch-scan-1";
    git("remote", "set-url", "origin", hosted);
    if (field === "uploadpack" || field === "receivepack") {
      git("config", "--add", "remote.origin.pushurl", hosted);
      git("config", "--add", "remote.origin.pushurl", remote);
    }
    if (stage === "patch branch") {
      const include = join(directory, ".git", "patch-branch.config");
      git("config", "--file", include, key, "synthetic-helper");
      git("config", `includeIf.onbranch:${branch}.path`, include);
    } else {
      git("config", key, "synthetic-helper");
    }
    if (stage === "resume") {
      git("branch", branch);
      git(
        "config",
        `branch.${branch}.codexSecurityPatchCommit`,
        git("rev-parse", "HEAD"),
      );
    }

    const transports: string[] = [];
    let modelCalls = 0;
    const outcome = await runWorkflow(
      stage === "resume"
        ? ["patch", "--resume-pr", branch, "--json"]
        : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onCodex: async (args, output) => {
          modelCalls++;
          await writeFile(join(directory, "src", "finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git") return "";
          if (args.includes("ls-remote")) {
            transports.push("ls-remote");
            if (stage === "patch branch") return "";
            throw new Error("Unexpected preflight transport");
          }
          if (args.includes("push")) {
            transports.push("push");
            throw new Error("Unexpected publication transport");
          }
          return runGitRepositoryCommand(command, args, cwd, options);
        },
      },
      { localHosting: false },
    );
    expect(transports, outcome.stderr).toEqual(
      stage === "patch branch" ? ["ls-remote"] : [],
    );
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toMatch(
      /remote helper|remote\.origin\.|pack program|service program/i,
    );
    expect(modelCalls).toBe(stage === "patch branch" ? 1 : 0);
  },
);

test.each(["local", "included checkout", "operator"])(
  "checks the origin of HTTP transport configuration from %s",
  async (source) => {
    const { directory, git } = await publicationRepository(fixtures);
    const remote = "https://github.example.test/example/repository.git";
    git("remote", "set-url", "origin", remote);
    const external = await fixtures.create("patch-http-config-");
    const global = join(external, "global.gitconfig");
    const included = join(directory, "transport.gitconfig");
    const environment = { GIT_CONFIG_GLOBAL: global, GIT_CONFIG_NOSYSTEM: "1" };
    if (source === "local") {
      git("config", "http.sslVerify", "false");
    } else {
      const config = source === "operator" ? global : included;
      git(
        "config",
        "--file",
        config,
        "http.https://github.example.test/.curloptResolve",
        "github.example.test:443:127.0.0.1",
      );
      if (source === "included checkout")
        git("config", "--file", global, "include.path", included);
    }
    let attempted = false;
    const outcome = await runSavedPublication(
      directory,
      {
        environment,

        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git") return "[]";
          if (args.includes("ls-remote")) {
            attempted = true;
            throw new Error("Fixture transport reached");
          }
          return runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
      },
      { localHosting: false },
    );
    expect(attempted).toBe(source === "operator");
    expect(outcome.stderr).toContain(
      source === "operator"
        ? "Fixture transport reached"
        : "checkout-selected HTTP",
    );
  },
);

async function runSshPreflight(
  selected: string,
  global: string,
  marker: string,
  hostnameEnvironment?: NodeJS.ProcessEnv,
  afterHostname?: () => Promise<void>,
) {
  repositoryGit(selected)(
    "remote",
    "set-url",
    "origin",
    "ssh://git@127.0.0.1:1/team/repository.git",
  );
  const environment = {
    GIT_CONFIG_GLOBAL: global,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_SSH_VARIANT: "ssh",
    PATCH_SSH_MARKER: marker,
    ...hostnameEnvironment,
  };
  let hostnameCommand: string | undefined;
  const model = mock(async () => 0);
  const outcome = await runSavedPublication(
    selected,
    {
      environment,

      onCodex: model,
      onRepositoryCommand: async (command, args, cwd, options) => {
        if (command !== "git") return "[]";
        const phase = args.includes("codex-security-ssh-config")
          ? "hostname"
          : args.includes("ls-remote")
            ? "preflight"
            : undefined;
        if (phase === "hostname") hostnameCommand = args[1];
        const run =
          hostnameEnvironment && phase
            ? runRepositoryCommand
            : runGitRepositoryCommand;
        const result = await run(command, args, cwd, {
          ...options,
          environment: {
            ...environment,
            ...options?.environment,
            PATCH_SSH_PHASE: phase,
          },
        });
        if (phase === "hostname") await afterHostname?.();
        return result;
      },
    },
    { localHosting: false },
  );
  expect(outcome.exitCode).toBe(2);
  const invoked = await readFile(marker, "utf8").catch(
    (error: NodeJS.ErrnoException) => {
      if (error.code !== "ENOENT") throw error;
      return "";
    },
  );
  expect(model).not.toHaveBeenCalled();
  return { invoked: invoked.trim(), stderr: outcome.stderr, hostnameCommand };
}

test.each(["worktree", "operator", "linked directory"] as const)(
  "checks the enclosing worktree for SSH configuration on a subdirectory scan: %s",
  async (source) => {
    const { directory, git } = await publicationRepository(fixtures);
    const selected = join(directory, "src");
    const external = await fixtures.create("patch-subdirectory-ssh-");
    const global = join(external, "global.gitconfig");
    const marker = join(external, "ssh-invoked");
    const checkoutConfig = join(directory, "ssh.config");
    const operatorConfig = join(external, "ssh.config");
    const link = join(external, "selected");
    if (source === "linked directory")
      await symlink(
        selected,
        link,
        process.platform === "win32" ? "junction" : "dir",
      );
    // Keep the link/.. spelling when passing it to Git.
    const included =
      source === "linked directory"
        ? link.replaceAll("\\", "/") + "/../ssh.config"
        : source === "worktree"
          ? checkoutConfig
          : operatorConfig;
    git("config", "--file", global, "include.path", included);
    const script = join(external, "ssh helper.cjs");
    await writeFile(
      script,
      'require("node:fs").writeFileSync(process.env.PATCH_SSH_MARKER, process.argv[2]); process.exitCode = 1;\n',
    );
    const command = (location: string) =>
      `node ${JSON.stringify(script.replaceAll("\\", "/"))} ${location}`;
    for (const [file, owner] of [
      [checkoutConfig, "worktree"],
      [operatorConfig, "operator"],
    ] as const)
      git("config", "--file", file, "core.sshCommand", command(owner));
    // Git for Windows and POSIX can resolve a junction/.. differently.
    const fromCheckout =
      git(
        "config",
        "--file",
        global,
        "--includes",
        "--get",
        "core.sshCommand",
      ) === command("worktree");
    const result = await runSshPreflight(selected, global, marker);
    expect(result.invoked).toBe(fromCheckout ? "" : "operator");
    if (fromCheckout)
      expect(result.stderr).toContain("checkout-selected core.sshCommand");
  },
);

test.each([".", "src"])(
  "an external SSH setting cannot run a checkout-relative executable during preflight from %s",
  async (subdirectory) => {
    const { directory, git } = await publicationRepository(fixtures);
    const selected = join(directory, subdirectory);
    const external = await fixtures.create("patch-relative-ssh-");
    const global = join(external, "gitconfig");
    const marker = join(external, "invoked");
    for (const [root, owner] of [
      [directory, "worktree"],
      [join(directory, "src"), "subdirectory"],
    ] as const) {
      await writeFile(
        join(root, "transport.sh"),
        [
          "#!/bin/sh",
          `echo ${owner} > "$PATCH_SSH_MARKER"`,
          "exit 73",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
    }
    git("add", ".");
    git("commit", "-m", "Add synthetic transport names");
    git("config", "--file", global, "core.sshCommand", "./transport.sh");
    const result = await runSshPreflight(selected, global, marker);
    expect(result.invoked).toBe("");
  },
);

test.each([
  "checkout-relative",
  "operator-absolute",
  "checkout-include",
  "checkout-provider",
  "checkout-proxy",
  "checkout-match",
  ...(process.platform === "win32"
    ? []
    : ["checkout-shell", "checkout-nested-ssh", "checkout-script-fallback"]),
  "changed-config",
] as const)(
  "binds %s OpenSSH configuration during hostname lookup and transport",
  async (location) => {
    const { directory, git } = await publicationRepository(fixtures);
    const external = await fixtures.create("patch-ssh-config-");
    const global = join(external, "gitconfig");
    const config = join(external, "ssh_config");
    const marker = join(external, "invoked");
    const name = "transport.cjs";
    const startup = {
      PYTHONPATH: directory,
      PYTHONNOUSERSITE: "0",
      NODE_PATH: directory,
      OPENSSL_CONF: join(directory, "synthetic.cnf"),
      OPENSSL_CONF_INCLUDE: directory,
      OPENSSL_MODULES: directory,
      OPENSSL_ENGINES: directory,
    };
    await writeFile(startup.OPENSSL_CONF, "");
    const script =
      `const inherited = Object.entries(${JSON.stringify(startup)}).some(([key, value]) => process.env[key] === value);\n` +
      'const isolated = !inherited && process.env.PYTHONNOUSERSITE === "1";\n' +
      'const phase = isolated ? process.env.PATCH_SSH_PHASE : "inherited";\n' +
      'require("node:fs").appendFileSync(process.env.PATCH_SSH_MARKER, phase + ":" + process.argv[2] + "\\n");\n';
    const checkoutScript = join(directory, name).replaceAll("\\", "/");
    const shell =
      location === "checkout-shell" ? { SHELL: checkoutScript } : {};
    await writeFile(checkoutScript, "#!/usr/bin/env node\n" + script, {
      mode: 0o755,
    });
    const fallback = location === "checkout-script-fallback";
    if (fallback) await symlink(checkoutScript, join(external, "fallback.js"));
    else if (location !== "checkout-relative")
      await writeFile(join(external, name), script);
    const checkoutInclude = location === "checkout-include";
    const leaf =
      checkoutInclude ||
      (process.platform !== "win32" && location !== "checkout-relative")
        ? join(checkoutInclude ? directory : external, "included config")
        : config;
    if (leaf !== config) {
      const nested = join(external, "intermediate config");
      const include = (file: string) =>
        `Include "${file.replaceAll("\\", "/")}"\n`;
      await writeFile(config, include(nested));
      await writeFile(
        nested,
        include(location === "changed-config" ? leaf + "*" : leaf),
        { mode: 0o600 },
      );
    }
    const target =
      location === "checkout-relative"
        ? "./" + name
        : join(external, fallback ? "fallback" : name).replaceAll("\\", "/");
    const checkoutProxy = location === "checkout-proxy";
    const checkoutMatch = location === "checkout-match";
    const nested = location === "checkout-nested-ssh";
    const next = join(external, "nested config");
    if (nested)
      await writeFile(next, `ProxyCommand node "${checkoutScript}" proxy\n`, {
        mode: 0o600,
      });
    const match = checkoutMatch ? checkoutScript : target;
    const matchPath =
      process.platform === "win32" && !match.includes(" ")
        ? match
        : `'${match}'`;
    const proxy = nested
      ? `ssh -F "${next}" 127.0.0.1`
      : checkoutProxy && process.platform !== "win32"
        ? `"${checkoutScript}"`
        : `node "${checkoutProxy ? checkoutScript : target}"`;
    const proxyArgs =
      location === "operator-absolute" ? " route/local/socket %p [%h]:%p" : "";
    await writeFile(
      leaf,
      [
        "Host *",
        "  BatchMode yes",
        ...(location === "checkout-provider"
          ? [`  PKCS11Provider "${checkoutScript}"`]
          : []),
        `  ProxyCommand ${proxy} proxy${proxyArgs}`,
        `Match exec "node ${matchPath} match"`,
        "  LogLevel ERROR",
        "",
      ].join("\n"),
      { mode: 0o600 },
    );
    git("add", ".");
    git("commit", "-m", "Add synthetic repository SSH command");
    const sshCommand = (file: string) =>
      `ssh -F "${file.replaceAll("\\", "/")}"`;
    git("config", "--file", global, "core.sshCommand", sshCommand(config));

    // The raw SSH connection invokes both commands from this checkout.
    // MSYS can treat a drive-qualified Include as relative. Exercise the leaf directly there.
    const control = spawnSync(
      "git",
      [
        "-c",
        `alias.test-ssh-config=!${sshCommand(process.platform === "win32" ? leaf : config)}`,
        "test-ssh-config",
        "127.0.0.1",
      ],
      {
        cwd: directory,
        encoding: "utf8",
        env: {
          ...process.env,
          ...shell,
          ...startup,
          PATCH_SSH_MARKER: marker,
        },
      },
    );
    const rawMarker = await readFile(marker, "utf8").catch(
      (error: NodeJS.ErrnoException) => {
        if (error.code !== "ENOENT") throw error;
        return "";
      },
    );
    if (shell.SHELL)
      expect(rawMarker, control.stderr).toContain("inherited:-c");
    else {
      expect(rawMarker, control.stderr).toContain("inherited:match");
      expect(rawMarker, control.stderr).toContain("inherited:proxy");
    }
    await unlink(marker);

    // Git's POSIX shell may find its bundled OpenSSH before the Windows client.
    // Its argument conversion supplies the native spelling to the test process.
    const runtime = "'" + process.execPath.replaceAll("'", "'\\''") + "'";
    const selected = git(
      "-c",
      `alias.test-ssh-path=!${runtime} -p 'process.argv[1]' "$(command -v ssh)"`,
      "test-ssh-path",
    );
    const executable = await realpath(
      process.platform === "win32" && !selected.toLowerCase().endsWith(".exe")
        ? selected + ".exe"
        : selected,
    );
    const { invoked, stderr, hostnameCommand } = await runSshPreflight(
      directory,
      global,
      marker,
      { ...shell, ...startup, GITLAB_HOST: "gitlab.example.invalid" },
      location === "changed-config"
        ? () => writeFile(leaf, "# changed\n", { flag: "a" })
        : undefined,
    );
    if (shell.SHELL) {
      expect(invoked, stderr).not.toContain(":-c");
      return;
    }
    if (location.startsWith("checkout-")) {
      expect(invoked, stderr).toBe("");
      expect(hostnameCommand, stderr).toBeUndefined();
      expect(stderr).toMatch(/SSH|transport/iu);
      return;
    }
    expect(hostnameCommand, stderr).toContain(
      executable.replaceAll("'", "'\\''"),
    );
    if (location === "changed-config") {
      expect(invoked, stderr).toContain("hostname:match");
      expect(invoked, stderr).not.toContain("preflight:");
      expect(stderr).toContain("transport file changed");
    } else {
      const records = invoked.split(/\r?\n/u);
      expect(records, stderr).toContain("hostname:match");
      expect(records, stderr).toContain("preflight:match");
      expect(records, stderr).toContain("preflight:proxy");
    }
  },
);
