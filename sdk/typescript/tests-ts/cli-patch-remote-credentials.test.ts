import { afterEach, expect, mock, test } from "bun:test";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  completePatches,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

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
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
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
  const outcome = await runWorkflow(
    ["patch", "--scan", "scan-1", "--create-pr", "--json"],
    {
      currentDirectory: directory,
      onWorkbench: () =>
        savedScan(resultWithFindings(["high"]), "scan-1", directory),
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
    const hosted = field.startsWith("proxy")
      ? "http://gitlab.com/example/repository.git"
      : "https://gitlab.com/example/repository.git";
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
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        environment,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
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
