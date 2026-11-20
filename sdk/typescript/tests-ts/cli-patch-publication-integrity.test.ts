import {
  CURRENT_REPOSITORY,
  SAVED_REPOSITORY,
  addPublicationOrigin,
  runPublicationCommand,
  setupPatchWorkflowFixtures,
  resultWithFindings,
  savedScan,
  completePatches,
  patchRiskSkill,
  savedPatchFixture,
  patchDirectories,
  patchRiskSummary,
  patchArtifactFromPrompt,
  patchRiskAssessment,
  runWorkflow,
  repositoryGit,
  initializePatchGit,
  runGitRepositoryCommand,
  readAppliedText,
  publicationRepository as createPublicationRepository,
  runPublicationWorkflow,
} from "./cli-patch-fixtures.js";
import { gitText } from "./support/shell.js";
import { loopbackProxy, loopbackTls } from "./support/loopback-git-proxy.js";
import { afterEach, describe, expect, test, mock } from "bun:test";
import { execFile, execFileSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import {
  basename,
  delimiter,
  join,
  isAbsolute,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import type { JsonObject } from "../src/index.js";
import { dependencies } from "./cli-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";

const fixtures = patchDirectories();

describe("patch change tracking", () => {
  const publicationRepository = () => createPublicationRepository(fixtures);

  test.each(["patch", "scan"])(
    "keeps dirty rename destinations out of %s publication across findings",
    async (command) => {
      const { directory, git } = await publicationRepository();
      const source = "src/finding-1.ts";
      const destination = "src/new.ts";
      const original = await readFile(join(directory, source), "utf8");
      const dirty = original + "synthetic pre-existing local edit\n";
      const rewritten =
        dirty +
        Array.from(
          { length: 60 },
          (_, index) => `new patch line ${index}\n`,
        ).join("");
      await writeFile(join(directory, source), dirty);
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const result = resultWithFindings(["high", "high"]);
      result.findings.findings[1]!.locations[0]!.path = source;
      let modelCalls = 0;
      let createCalls = 0;
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
          : ["scan", directory, "--patch", "--create-pr", "--json"],
        {
          ...savedPatchFixture(directory, result),
          onRepositoryCommand: async (command, args, cwd, options) => {
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, options);
            if (args[1] === "list") return "[]";
            createCalls++;
            return "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            modelCalls++;
            if (modelCalls === 1)
              await rename(
                join(directory, source),
                join(directory, destination),
              );
            else {
              await writeFile(join(directory, source), original);
              await writeFile(join(directory, destination), rewritten);
            }
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: `occ_${modelCalls}`,
                    status: "verified",
                    files: [destination],
                    verification: "The focused regression passed.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(modelCalls).toBe(2);
      expect(git("status", "--porcelain", "--untracked-files")).toBe(
        `?? ${destination}`,
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(createCalls).toBe(0);
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
      expect(git("ls-remote", "origin")).toBe("");
      expect(await readFile(join(directory, source), "utf8")).toBe(original);
      expect(await readFile(join(directory, destination), "utf8")).toBe(
        rewritten,
      );
    },
  );

  test.each(["required", "empty"] as const)(
    "preserves the %s origin proxy during publication preflight",
    async (kind) => {
      const { directory, git } = await publicationRepository();
      const original = git("rev-parse", "HEAD");
      const requests: string[] = [];
      const globalConfig = join(
        await fixtures.create("patch-proxy-config-"),
        "gitconfig",
      );
      const server = Bun.serve({
        tls: await loopbackTls(globalConfig, git),
        hostname: "127.0.0.1",
        port: 0,
        fetch(request) {
          const path = new URL(request.url).pathname;
          requests.push(path);
          if (path === "/repository.git/info/refs")
            return new Response(`${original}\trefs/heads/main\n`, {
              headers: { "Content-Type": "text/plain" },
            });
          if (path === "/repository.git/HEAD")
            return new Response("ref: refs/heads/main\n");
          return new Response("Not found", { status: 404 });
        },
      });
      try {
        using proxy = await loopbackProxy(server.port!);
        const host = kind === "required" ? "127.0.0.2" : "127.0.0.1";
        git(
          "remote",
          "set-url",
          "origin",
          `https://${host}:${server.port}/repository.git`,
        );
        const setConfig = (key: string, value: string) =>
          git("config", "--file", globalConfig, key, value);
        setConfig("http.proxy", "http://127.0.0.1:1");
        setConfig("remote.origin.proxy", kind === "required" ? proxy.url : "");
        const environment = {
          GIT_CONFIG_GLOBAL: globalConfig,
          GIT_CONFIG_NOSYSTEM: "1",
          HTTP_PROXY: "",
          http_proxy: "",
          HTTPS_PROXY: "",
          https_proxy: "",
          ALL_PROXY: "",
          all_proxy: "",
          NO_PROXY: "",
          no_proxy: "",
        };
        const runGit: typeof runGitRepositoryCommand = async (
          command,
          args,
          cwd,
          options,
        ) => {
          expect(command).toBe("git");
          const execution = promisify(execFile)("git", [...args], {
            cwd: options?.directory ?? cwd,
            env: { ...process.env, ...environment, ...options?.environment },
            maxBuffer: options?.maxBuffer,
            encoding: options?.encoding === "base64" ? "buffer" : "utf8",
          });
          execution.child.stdin?.end(options?.input);
          const { stdout } = await execution;
          const output = Buffer.isBuffer(stdout)
            ? stdout.toString(options?.encoding ?? "utf8")
            : stdout;
          return options?.trim === false ? output : output.trim();
        };
        expect(
          await runGit("git", ["ls-remote", "origin"], directory),
        ).toContain(original);
        requests.length = 0;
        const result = resultWithFindings(["high"]);
        const onCodex = mock(
          (
            args: readonly string[],
            output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
          ) => {
            completePatches(args, output, "blocked");
            return 0;
          },
        );
        const outcome = await runPublicationWorkflow("scan", {
          currentDirectory: directory,
          environment,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git" ? runGit(command, args, cwd, options) : "[]",
        });
        expect(outcome.exitCode, outcome.stderr).toBe(1);
        expect(onCodex).toHaveBeenCalledTimes(1);
        expect(requests).toContain("/repository.git/info/refs");
        expect(git("rev-parse", "HEAD")).toBe(original);
        expect(git("status", "--porcelain")).toBe("");
      } finally {
        server.stop(true);
      }
    },
  );

  test.each([false, true])(
    "preserves mixed parent and uncommitted gitlink edits with publication=%j",
    async (publish) => {
      const { directory, git, remote } = await publicationRepository();
      const nested = join(directory, "nested");
      await mkdir(nested);
      const nestedGit = initializePatchGit(nested);
      await writeFile(join(nested, "app.ts"), "nested-original\n");
      nestedGit("add", ".");
      nestedGit("commit", "-m", "Synthetic nested baseline");
      git("add", "nested");
      git("commit", "-m", "Synthetic gitlink");
      const original = git("rev-parse", "HEAD");
      const branches = git("for-each-ref", "refs/heads");
      const index = await readFile(join(directory, ".git/index"));
      const nestedIndex = await readFile(join(nested, ".git/index"));
      const writes: string[] = [];
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          ...(publish ? ["--create-pr"] : []),
          "--json",
        ],
        {
          currentDirectory: directory,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (
              args.some((arg) =>
                ["switch", "commit", "push", "create"].includes(arg),
              )
            )
              writes.push(`${command} ${args.join(" ")}`);
            return command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              assessments++;
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              const patch = await readFile(artifact.path, "utf8");
              expect(artifact.changedFiles.sort()).toEqual([
                "nested/app.ts",
                "src/finding-1.ts",
              ]);
              expect(patch).toContain("-nested-original");
              expect(patch).toContain("+nested-fixed");
              expect(patch).toContain("+parent-fixed");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(directory, "src/finding-1.ts"),
              "parent-fixed\n",
            );
            await writeFile(join(nested, "app.ts"), "nested-fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(publish ? 2 : 0);
      expect(assessments).toBe(1);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["nested/app.ts", "src/finding-1.ts"],
      });
      expect(writes).toEqual([]);
      expect(git("rev-parse", "HEAD")).toBe(original);
      expect(git("for-each-ref", "refs/heads")).toBe(branches);
      expect(repositoryGit(remote)("for-each-ref")).toBe("");
      expect(await readFile(join(directory, ".git/index"))).toEqual(index);
      expect(await readFile(join(nested, ".git/index"))).toEqual(nestedIndex);
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "parent-fixed\n",
      );
      expect(await readFile(join(nested, "app.ts"), "utf8")).toBe(
        "nested-fixed\n",
      );
    },
  );

  for (const rewriting of [
    "ordinary",
    "overlapping",
    "equal-length",
    "push-instead",
    "trailing-space",
    "equals",
    "newline",
    "newline-multiple",
    "mixed-fetch-push-instead",
  ]) {
    test.skipIf(
      (rewriting === "trailing-space" || rewriting.startsWith("newline")) &&
        process.platform === "win32",
    )(
      `preserves the resolved push destination with ${rewriting} configuration`,
      async () => {
        const { directory, git } = await publicationRepository();
        const container = await fixtures.create("patch-resolved-url-");
        const raw = join(
          container,
          rewriting === "equals" ? "repository=v2" : "project",
        );
        const remote =
          rewriting === "trailing-space"
            ? `${raw} `
            : rewriting.startsWith("newline")
              ? `${raw}\npart`
              : `${raw}-v2`;
        git("init", "--bare", remote);
        git(
          "remote",
          "set-url",
          "origin",
          rewriting === "ordinary" ||
            rewriting === "trailing-space" ||
            rewriting === "equals" ||
            rewriting.startsWith("newline")
            ? remote
            : raw,
        );
        if (rewriting === "equal-length")
          git("config", `url.${remote}-incorrect.insteadOf`, remote);
        if (rewriting === "overlapping" || rewriting === "equal-length")
          git("config", `url.${remote}.insteadOf`, raw);
        if (
          rewriting === "push-instead" ||
          rewriting === "mixed-fetch-push-instead"
        )
          git("config", `url.${remote}.pushInsteadOf`, raw);
        if (rewriting === "mixed-fetch-push-instead")
          git(
            "config",
            "--add",
            "remote.origin.url",
            join(container, "unused-fetch"),
          );
        const secondary = join(container, "secondary");
        if (rewriting === "newline-multiple") {
          git("init", "--bare", secondary);
          git("config", "--add", "remote.origin.pushurl", remote);
          git("config", "--add", "remote.origin.pushurl", secondary);
        }
        git("push", "origin", "HEAD:refs/heads/native-control");
        const outcome = await runPublicationWorkflow("scan", {
          ...savedPatchFixture(directory),
          onRepositoryCommand: runPublicationCommand,
          onCodex: async (args, output) => {
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
        });
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(
          git(
            "--git-dir",
            remote,
            "rev-parse",
            "refs/heads/codex-security/patch-scan-1",
          ),
        ).toBe(git("rev-parse", "HEAD"));
        if (rewriting === "newline-multiple")
          expect(
            git(
              "--git-dir",
              secondary,
              "rev-parse",
              "refs/heads/codex-security/patch-scan-1",
            ),
          ).toBe(git("rev-parse", "HEAD"));
      },
    );
  }

  for (const kind of [
    "named",
    "userless",
    "canonical-host GIT_SSH",
    "canonical-host Git PATH",
    "canonical-host port",
    "canonical-host ssh+git",
  ]) {
    test.skipIf(kind.startsWith("canonical-host") && Bun.which("gh") === null)(
      `resumes publication with ${kind} SSH available only in Git's subprocess PATH`,
      async () => {
        const canonicalHost = kind.startsWith("canonical-host");
        const username = kind === "userless" ? "" : "git@";
        const host = canonicalHost ? "ssh.github.com" : "GitHub-Work";
        const ghExecutable = Bun.which("gh")!;
        const { directory, git } = await publicationRepository();
        const sshDirectory = await fixtures.create("patch-git-ssh-");
        await writeFile(
          join(sshDirectory, "ssh"),
          `#!/bin/sh\n[ "$1" = "-G" ] && [ "$2" = "${username}${host}" ] || exit 1\nprintf "hostname github.com\\n"\n`,
          { mode: 0o755 },
        );
        const emptyPath = await fixtures.create("patch-no-ssh-");
        const ghConfig = await fixtures.create("patch-gh-config-");
        const gitExecutable = Bun.which("git")!;
        await symlink(
          gitExecutable,
          join(emptyPath, process.platform === "win32" ? "git.exe" : "git"),
        );
        expect(Bun.which("ssh", { PATH: emptyPath })).toBeNull();
        const environment = {
          PATH: emptyPath,
          GIT_EXEC_PATH: sshDirectory,
          GIT_SSH:
            canonicalHost && kind !== "canonical-host Git PATH"
              ? join(sshDirectory, "ssh")
              : undefined,
          GH_CONFIG_DIR: ghConfig,
          GH_TOKEN: "synthetic-gh-test-token",
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
          kind === "canonical-host port"
            ? "ssh://git@ssh.github.com:443/example/repository.git"
            : kind === "canonical-host ssh+git"
              ? "ssh+git://git@ssh.github.com/example/repository.git"
              : `${username}${host}:example/repository.git`,
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
                const selectedToken = execFileSync(
                  gitExecutable,
                  ["config", "--get", "remote.codex-security-push.url"],
                  {
                    cwd: options?.directory ?? cwd,
                    env: {
                      ...process.env,
                      ...environment,
                      ...options?.environment,
                    },
                    encoding: "utf8",
                  },
                ).trim();
                const selectedRemote = execFileSync(
                  gitExecutable,
                  ["ls-remote", "--get-url", selectedToken],
                  {
                    cwd: options?.directory ?? cwd,
                    env: {
                      ...process.env,
                      ...environment,
                      ...options?.environment,
                    },
                    encoding: "utf8",
                  },
                ).trim();
                expect(selectedRemote).toBe(
                  "https://github.com/example/repository",
                );
                expect(options?.environment?.["GH_REPO"]).toBe("");
                expect(options?.environment?.["GH_HOST"]).toBe("github.com");
                if (args[1] === "set-default") {
                  expect(args).toEqual(["repo", "set-default", "--view"]);
                  if (canonicalHost) {
                    const { stdout } = await promisify(execFile)(
                      ghExecutable,
                      args,
                      {
                        cwd: options?.directory ?? cwd,
                        env: {
                          ...process.env,
                          ...environment,
                          ...options?.environment,
                        },
                        encoding: "utf8",
                      },
                    );
                    return stdout.trim();
                  }
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
                  cwd: options?.directory ?? cwd,
                  env: {
                    ...process.env,
                    ...environment,
                    ...options?.environment,
                  },
                  encoding: "utf8",
                },
              );
              return options?.trim === false ? stdout : stdout.trim();
            },
            onCodex: throwing("must reuse the saved patch"),
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout).pullRequest.url).toBe(url);
        expect(repositoryLookups).toBe(1);
      },
    );
  }

  test.each([
    {
      invocation: "root",
      file: "sub/local.env",
      unignore: true,
      literal: false,
    },
    {
      invocation: "sub",
      file: "sub/local.env",
      unignore: true,
      literal: false,
    },
    { invocation: "sub", file: "local.env", unignore: true, literal: false },
    {
      invocation: "sub",
      file: "sub/local.env",
      unignore: false,
      literal: false,
    },
    {
      invocation: "root",
      file: "sub/local.env",
      unignore: true,
      literal: true,
    },
    { invocation: "sub", file: "sub/local.env", unignore: true, literal: true },
    { invocation: "sub", file: "local.env", unignore: true, literal: true },
    {
      invocation: "sub",
      file: "sub/local.env",
      unignore: false,
      literal: true,
    },
  ])(
    "preserves ignored local data from publication context %j",
    async ({ invocation, file, unignore, literal }) => {
      const { directory: root, git } = await publicationRepository();
      const sub = join(root, "sub");
      await mkdir(sub);
      const rule = join(root, ".gitignore");
      await writeFile(rule, `${file}\n`);
      git("add", ".gitignore");
      git("commit", "-m", "Synthetic ignore rule");
      await writeFile(join(root, file), "synthetic local data\n");
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const outcome = await runWorkflow(
        ["patch", "Synthetic ignore update", "--create-pr", "--json"],
        {
          currentDirectory: invocation === "root" ? root : sub,
          environment: {
            ...process.env,
            GIT_LITERAL_PATHSPECS: literal ? "1" : "0",
          },
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: {
                    GIT_LITERAL_PATHSPECS: literal ? "1" : "0",
                    ...options?.environment,
                  },
                })
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            if (unignore) await writeFile(rule, "");
            else await writeFile(join(root, "src/finding-1.ts"), "fixed\n");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: unignore
                      ? [".gitignore", file]
                      : ["src/finding-1.ts"],
                    verification: "Synthetic verification.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(unignore ? 2 : 0);
      expect(await readFile(join(root, file), "utf8")).toBe(
        "synthetic local data\n",
      );
      expect(
        git("ls-tree", "-r", "--name-only", "HEAD").split("\n"),
      ).not.toContain(file);
      if (unignore) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("ls-remote", "origin")).toBe("");
      }
    },
  );

  test.each(
    ["saved", "supplied"].flatMap((mode) =>
      [false, true].flatMap((relativeDiff) =>
        ["package/.env", ".env"].flatMap((source) =>
          ["copy", "different"].map((content) => ({
            mode,
            relativeDiff,
            source,
            content,
          })),
        ),
      ),
    ),
  )(
    "checks whole-repository ignored content from $mode component with relative diff=$relativeDiff and $source/$content",
    async ({ mode, relativeDiff, source, content }) => {
      const { directory: root, git } = await publicationRepository();
      const directory = join(root, "package");
      await mkdir(directory);
      await writeFile(join(directory, "app.ts"), "original\n");
      await writeFile(join(root, ".gitignore"), ".env\n");
      git("add", ".");
      git("commit", "-m", "Synthetic component baseline");
      git("config", "diff.relative", String(relativeDiff));
      await writeFile(join(root, source), "SYNTHETIC_LOCAL_CONTENT\n");
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "app.ts";
      const outcome = await runWorkflow(
        [
          "patch",
          ...(mode === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--create-pr",
          "--json",
        ],
        {
          ...savedPatchFixture(directory, result),
          onRepositoryCommand: runPublicationCommand,
          onCodex: async (_args, output) => {
            await writeFile(
              join(directory, "new.ts"),
              content === "copy" ? "SYNTHETIC_LOCAL_CONTENT\n" : "new fix\n",
            );
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["new.ts"],
                    verification: "Synthetic check.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(content === "copy" ? 2 : 0);
      if (content === "copy") {
        expect(outcome.stderr).toContain(
          "matches pre-existing ignored content",
        );
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(await readFile(join(root, ".git", "index"))).toEqual(index);
        expect(git("ls-remote", "origin")).toBe("");
      } else expect(git("show", "HEAD:package/new.ts")).toBe("new fix");
      expect(await readFile(join(root, source), "utf8")).toBe(
        "SYNTHETIC_LOCAL_CONTENT\n",
      );
    },
  );

  test.each([false, true])(
    "publishes destination-only component renames with relative diff=%j",
    async (relativeDiff) => {
      const { directory: root, git } = await publicationRepository();
      const directory = join(root, "package");
      await mkdir(directory);
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic component baseline");
      git("config", "diff.relative", String(relativeDiff));
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "app.ts";
      const outcome = await runPublicationWorkflow("scan", {
        ...savedPatchFixture(directory, result),
        onRepositoryCommand: runPublicationCommand,
        onCodex: async (_args, output) => {
          await rename(join(directory, "app.ts"), join(directory, "new.ts"));
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["new.ts"],
                  verification: "Synthetic check.",
                },
              ],
            }),
          );
          return 0;
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("ls-tree", "-r", "--name-only", "HEAD", "--", "package")).toBe(
        "package/new.ts",
      );
      expect(git("show", "HEAD:package/new.ts")).toBe("original");
      expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
      expect(git("status", "--porcelain")).toBe("");
    },
  );

  test.each(
    ["root", "component"].flatMap((scope) =>
      [false, true].map((literal) => ({ scope, literal })),
    ),
  )(
    "assesses and publishes force-staged ignored sibling content from $scope with literal paths=$literal",
    async ({ scope, literal }) => {
      const { directory, git, remote } = await publicationRepository();
      await mkdir(join(directory, "component"));
      await writeFile(
        join(directory, "component/app.ts"),
        "component baseline\n",
      );
      await writeFile(join(directory, ".gitignore"), "generated.txt\n");
      await writeFile(join(directory, "unrelated.txt"), "baseline\n");
      git("add", ".");
      git("commit", "-m", "Synthetic ignored sibling baseline");
      const unrelated = git(
        "ls-files",
        "--stage",
        "--debug",
        "--",
        "unrelated.txt",
      );
      let calls = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--create-pr",
          "--assess-patch-risk",
          "--json",
        ],
        {
          currentDirectory:
            scope === "root" ? directory : join(directory, "component"),
          environment: literal ? { GIT_LITERAL_PATHSPECS: "1" } : {},
          onRepositoryCommand: runPublicationCommand,
          onCodex: async (_args, output) => {
            calls++;
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              expect(artifact.changedFiles).toEqual([
                "generated.txt",
                "src/finding-1.ts",
              ]);
              const verification = await fixtures.create(
                "ignored-sibling-risk-apply-",
              );
              await mkdir(join(verification, "src"));
              await writeFile(
                join(verification, "src/finding-1.ts"),
                "original\n",
              );
              repositoryGit(verification)("apply", "--check", artifact.path);
              repositoryGit(verification)("apply", artifact.path);
              expect(
                await readAppliedText(join(verification, "generated.txt")),
              ).toBe("new generated fix\n");
              expect(
                await readAppliedText(join(verification, "src/finding-1.ts")),
              ).toBe("fixed\n");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(directory, "generated.txt"),
              "new generated fix\n",
            );
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            git("add", "-f", "generated.txt");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["generated.txt", "src/finding-1.ts"],
                    verification: "Synthetic verification.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(calls).toBe(2);
      const commit = git("rev-parse", "HEAD");
      expect(repositoryGit(remote)("show", `${commit}:generated.txt`)).toBe(
        "new generated fix",
      );
      expect(repositoryGit(remote)("show", `${commit}:src/finding-1.ts`)).toBe(
        "fixed",
      );
      expect(git("show", "HEAD:unrelated.txt")).toBe("baseline");
      expect(git("ls-files", "--stage", "--debug", "--", "unrelated.txt")).toBe(
        unrelated,
      );
      expect(git("diff", "--cached", "--name-only")).toBe("");
    },
  );
});

describe("patch publication integrity", () => {
  const fixtures = setupPatchWorkflowFixtures();
  const repositories = createTemporaryDirectories();
  afterEach(repositories.cleanup);
  test(
    "preserves Git aliases and provider configuration in the Node runtime",
    async () => {
      const bundle = await mkdtemp(
        join(import.meta.dir, "..", ".patch-context-"),
      );
      fixtures.track(bundle);
      const root = await fixtures.create("patch-node-context-");
      const built = await Bun.build({
        entrypoints: [
          join(import.meta.dir, "support", "cli-patch-context.mts"),
        ],
        outdir: bundle,
        target: "node",
        packages: "external",
      });
      expect(built.success).toBe(true);
      const { stdout } = await promisify(execFile)(
        "node",
        [
          "--input-type=module",
          "--eval",
          `await import(${JSON.stringify(pathToFileURL(built.outputs[0]!.path).href)})`,
          "synthetic-launcher",
          root,
        ],
        { encoding: "utf8" },
      );
      const outcomes = JSON.parse(stdout) as {
        kind: string;
        exitCode: number;
        error: string;
        applied: boolean;
      }[];
      expect(outcomes).toHaveLength(6);
      for (const outcome of outcomes) {
        expect(outcome.exitCode, `${outcome.kind}: ${outcome.error}`).toBe(0);
        expect(outcome.applied).toBe(true);
      }
    },
    process.platform === "win32" ? 180_000 : 90_000,
  );

  test.each([
    "ordinary",
    "long checkout root",
    "HEAD filename",
    "relative Git environment",
    "configured worktree",
    "absolute symlink Git environment",
    "relative symlink Git environment",
    "relative provider configuration",
    "nested Git metadata after patch",
    "nested Git metadata with worktree environment",
    "staged component changes",
    "removed component",
    "removed component replaced by a file",
    "removed component with relative Git environment",
    "removed component with configured worktree",
    "removed component with relative index",
    "removed component with relative common directory",
    "removed component with relative object directory",
    "removed component with relative symlink Git environment",
    "removed component with relative provider configuration",
    "removed component with external askpass",
    "removed component with checkout askpass",
    "removed component with relative GitLab configuration",
    "removed component with removed provider configuration",
    ...(process.platform === "win32"
      ? []
      : [
          "removed component replaced by a directory link",
          "trailing space",
          "carriage return",
        ]),
  ])(
    "assesses and publishes root-relative patch files from a subdirectory: %s",
    async (kind) => {
      const directory = await fixtures.create(
        "codex-security-subdirectory-pr-",
      );
      const repository = join(
        directory,
        kind === "trailing space"
          ? "repository "
          : kind === "carriage return"
            ? "repository\r"
            : kind === "long checkout root"
              ? "r".repeat(Math.max(1, 180 - directory.length - 1))
              : "repository",
      );
      const extraFiles =
        kind === "long checkout root"
          ? Array.from(
              { length: 200 },
              (_, index) => `f${index.toString().padStart(3, "0")}.ts`,
            )
          : [];
      const subdirectory = join(repository, "sub");
      const removesComponent = kind.startsWith("removed component");
      const nestedMetadata = kind.startsWith("nested Git metadata");
      const assessmentAtRoot = removesComponent || nestedMetadata;
      const replacesComponent = kind.includes("replaced by");
      const changedFiles = removesComponent
        ? [
            "shared.ts",
            ...(replacesComponent ? ["sub"] : []),
            "sub/.codex/config.toml",
            "sub/app.ts",
          ]
        : [...extraFiles, "shared.ts", "sub/app.ts"];
      const alias = join(directory, "alias");
      const linkedGitRoot = `${kind.includes("relative symlink Git environment") ? relative(subdirectory, alias) : alias}${process.platform === "win32" ? "" : `${sep}..`}`;
      const gitEnvironment =
        kind === "nested Git metadata with worktree environment"
          ? { GIT_WORK_TREE: repository }
          : kind.includes("relative Git environment")
            ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
            : kind.includes("configured worktree")
              ? { GIT_DIR: "../.git" }
              : kind.includes("symlink Git environment")
                ? {
                    GIT_DIR: `${linkedGitRoot}${sep}.git`,
                    GIT_WORK_TREE: linkedGitRoot,
                  }
                : kind.includes("relative index")
                  ? { GIT_INDEX_FILE: ".git/custom-index" }
                  : kind.includes("relative common directory")
                    ? { GIT_COMMON_DIR: "../metadata" }
                    : kind.includes("relative object directory")
                      ? { GIT_OBJECT_DIRECTORY: "../metadata/objects" }
                      : {};
      // Native Windows accepts these spellings even when the SDK receives a plain env object.
      const caseInsensitiveSetting =
        process.platform === "win32" &&
        [
          "removed component with relative index",
          "removed component with relative common directory",
          "removed component with relative object directory",
        ].includes(kind);
      const componentEnvironment = caseInsensitiveSetting
        ? Object.fromEntries(
            Object.entries(gitEnvironment).map(([name, value]) => [
              name.toLowerCase(),
              value,
            ]),
          )
        : gitEnvironment;
      const askpass = join(directory, "fixture-askpass.sh");
      const sshAskpass = join(directory, "fixture-ssh-askpass.exe");
      const askpassEnvironment =
        kind === "removed component with external askpass"
          ? {
              GIT_EXEC_PATH: directory,
              GIT_ASKPASS: basename(askpass),
              SSH_ASKPASS: relative(repository, sshAskpass),
            }
          : kind === "removed component with checkout askpass"
            ? {
                GIT_ASKPASS: `sub${sep}app.ts`,
                SSH_ASKPASS: `sub${sep}app.ts`,
              }
            : {};
      const providerConfiguration = kind.includes(
        "removed provider configuration",
      )
        ? join(subdirectory, "provider-config")
        : join(directory, "provider-config");
      const providerEnvironment = kind.includes("provider configuration")
        ? { GH_CONFIG_DIR: relative(subdirectory, providerConfiguration) }
        : kind.includes("relative GitLab configuration")
          ? { GLAB_CONFIG_DIR: relative(subdirectory, providerConfiguration) }
          : {};
      const remote = join(directory, "remote.git");
      await mkdir(join(subdirectory, ".codex"), { recursive: true });
      if (kind.includes("symlink Git environment"))
        await symlink(
          process.platform === "win32" ? repository : subdirectory,
          alias,
          process.platform === "win32" ? "junction" : "dir",
        );
      if (kind === "removed component with external askpass") {
        await writeFile(askpass, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
        await writeFile(sshAskpass, "", { mode: 0o700 });
      }
      if (Object.keys(providerEnvironment).length > 0) {
        await mkdir(providerConfiguration);
        await writeFile(
          join(providerConfiguration, "config.yml"),
          "git_protocol: https\n",
        );
        if (kind.includes("removed provider configuration")) {
          await writeFile(join(repository, ".gitignore"), "provider-config/\n");
        }
      }
      await writeFile(
        join(subdirectory, ".codex", "config.toml"),
        '[mcp_servers.component]\ncommand = "synthetic-component-server"\n',
      );
      const git = initializePatchGit(repository);
      git("config", "commit.gpgsign", "false");
      git("config", "diff.relative", "true");
      if (kind.includes("configured worktree"))
        git("config", "core.worktree", repository);
      if (
        kind.includes("relative common directory") ||
        kind.includes("relative object directory")
      ) {
        // Git2.43 checks these paths before and after entering the worktree.
        for (const parent of [directory, repository])
          await symlink(
            join(repository, ".git"),
            join(parent, "metadata"),
            process.platform === "win32" ? "junction" : "dir",
          );
        await writeFile(join(repository, ".gitignore"), "metadata/\n");
      }
      for (const file of ["sub/app.ts", "shared.ts", ...extraFiles])
        await writeFile(join(repository, file), "original\n");
      if (kind === "staged component changes")
        await writeFile(join(subdirectory, "shared.ts"), "original\n");
      if (kind === "HEAD filename")
        await writeFile(join(repository, "HEAD"), "ordinary source file\n");
      git("add", ".");
      git("commit", "-m", "Initial synthetic checkout");
      if (kind === "staged component changes") {
        await writeFile(join(subdirectory, "shared.ts"), "staged component\n");
        git("add", "sub/shared.ts");
        await writeFile(join(subdirectory, "shared.ts"), "original\n");
      }
      const originalIndex = kind.includes("relative index")
        ? await readFile(join(repository, ".git/index"))
        : undefined;
      if (kind.includes("relative index"))
        await copyFile(
          join(repository, ".git/index"),
          join(repository, ".git/custom-index"),
        );
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let patchCalls = 0;
      let assessmentCalls = 0;
      let patchFinished = false;
      const postPatchGitWrites: string[][] = [];
      const postPatchPublication: string[][] = [];
      let selectedBeforePatch: string | undefined;
      let nestedAfterPatch:
        | { head: string; index: Buffer<ArrayBuffer>; objects: string }
        | undefined;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: subdirectory,
          environment: {
            ...process.env,
            ...componentEnvironment,
            ...providerEnvironment,
            ...askpassEnvironment,
          },
          onCodex: async (_args, output, environment) => {
            const assessing =
              output?.appServer?.prompt.includes(patchRiskSkill);
            expect(output?.appServer?.directory).toBe(
              assessmentAtRoot && assessing ? repository : subdirectory,
            );
            if (!(assessmentAtRoot && assessing))
              expect(
                await readFile(
                  join(output!.appServer!.directory!, ".codex", "config.toml"),
                  "utf8",
                ),
              ).toContain("synthetic-component-server");
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              assessmentCalls++;
              expect(
                resolve(
                  execFileSync("git", ["rev-parse", "--show-toplevel"], {
                    cwd: output.appServer.directory,
                    env: environment,
                    encoding: "utf8",
                  }).replace(/\n$/u, ""),
                ),
              ).toBe(repository);
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              expect(artifact.changedFiles).toEqual(changedFiles);
              expect(
                execFileSync("git", ["cat-file", "-e", artifact.base], {
                  cwd: output.appServer.directory,
                  env: environment,
                  encoding: "utf8",
                }),
              ).toBe("");
              const patch = await readFile(artifact.path, "utf8");
              expect(patch).toContain("a/sub/app.ts");
              expect(patch).toContain("a/shared.ts");
              output.stdout.write(patchRiskAssessment().report);
            } else {
              patchCalls++;
              if (nestedMetadata)
                selectedBeforePatch = git("rev-parse", "HEAD");
              if (removesComponent) {
                await rm(subdirectory, { recursive: true });
                if (kind.includes("replaced by a file"))
                  await writeFile(subdirectory, "replacement file\n");
                if (kind.includes("replaced by a directory link")) {
                  const outside = join(directory, "other-checkout");
                  await mkdir(outside);
                  await writeFile(join(outside, "app.ts"), "original\n");
                  const other = initializePatchGit(outside);
                  other("add", ".");
                  other("commit", "-m", "Synthetic other checkout");
                  await symlink(
                    outside,
                    subdirectory,
                    process.platform === "win32" ? "junction" : "dir",
                  );
                }
              } else {
                await writeFile(join(subdirectory, "app.ts"), "fixed\n");
                if (nestedMetadata) {
                  const nested = initializePatchGit(subdirectory);
                  nested("add", ".");
                  nested("commit", "-m", "Synthetic nested checkout");
                  nestedAfterPatch = {
                    head: nested("rev-parse", "HEAD"),
                    index: await readFile(join(subdirectory, ".git/index")),
                    objects: nested("count-objects", "-v"),
                  };
                }
              }
              await writeFile(join(repository, "shared.ts"), "fixed\n");
              for (const file of extraFiles)
                await writeFile(join(repository, file), "fixed\n");
              output?.stdout.write("Patch complete.");
              patchFinished = true;
            }
            return 0;
          },
          onRepositoryCommand: async (command, args, directory, options) => {
            if (command === "git") {
              if (
                nestedMetadata &&
                patchFinished &&
                args.some((argument) =>
                  [
                    "add",
                    "read-tree",
                    "update-index",
                    "write-tree",
                    "commit",
                    "push",
                    "update-ref",
                  ].includes(argument),
                )
              )
                postPatchGitWrites.push([...args]);
              if (args[0] === "push" && caseInsensitiveSetting) {
                const [setting] = Object.keys(gitEnvironment);
                const selected = options?.environment?.[setting!];
                expect(selected).toBeDefined();
                expect(isAbsolute(selected!)).toBe(true);
              }
              if (args[0] === "push" && askpassEnvironment.GIT_ASKPASS) {
                expect(options?.environment?.["GIT_ASKPASS"]).toBe(
                  kind === "removed component with external askpass"
                    ? await realpath(askpass)
                    : "",
                );
                expect(options?.environment?.["SSH_ASKPASS"]).toBe(
                  kind === "removed component with external askpass"
                    ? await realpath(sshAskpass)
                    : "",
                );
              }
              if (kind === "long checkout root")
                expect(args.join(" ").length).toBeLessThan(32767);
              if (
                providerEnvironment.GLAB_CONFIG_DIR !== undefined &&
                args[0] === "remote"
              )
                return "https://gitlab.com/example/repository.git";
              if (
                providerEnvironment.GLAB_CONFIG_DIR !== undefined &&
                args[0] === "ls-remote"
              )
                args = [...args.slice(0, 3), remote, ...args.slice(4)];
              return runGitRepositoryCommand(command, args, directory, {
                ...options,
                environment: {
                  ...componentEnvironment,
                  ...options?.environment,
                  // Local Git transport forwards relative paths to its receiver.
                  ...(kind.includes("relative symlink Git environment") &&
                  args[0] === "push"
                    ? {
                        GIT_DIR: join(repository, ".git"),
                        GIT_WORK_TREE: repository,
                      }
                    : {}),
                },
              });
            }
            if (nestedMetadata && patchFinished)
              postPatchPublication.push([...args]);
            const configName =
              providerEnvironment.GH_CONFIG_DIR !== undefined
                ? "GH_CONFIG_DIR"
                : "GLAB_CONFIG_DIR";
            const configuration =
              options?.environment?.[configName] ??
              providerEnvironment[configName];
            if (configuration !== undefined)
              expect(
                await readFile(
                  resolve(
                    options?.directory ?? directory,
                    configuration,
                    "config.yml",
                  ),
                  "utf8",
                ),
              ).toBe("git_protocol: https\n");
            return args[1] === "create"
              ? "https://github.example.test/example/repository/pull/17"
              : "";
          },
        },
      );
      if (nestedMetadata) {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(patchCalls).toBe(1);
        expect(assessmentCalls).toBe(1);
        expect(postPatchGitWrites.length).toBeGreaterThan(0);
        expect(postPatchPublication.length).toBeGreaterThan(0);
        expect(git("rev-parse", "HEAD^")).toBe(selectedBeforePatch!);
        const nested = repositoryGit(subdirectory);
        expect(nested("rev-parse", "HEAD")).toBe(nestedAfterPatch!.head);
        expect(await readFile(join(subdirectory, ".git/index"))).toEqual(
          nestedAfterPatch!.index,
        );
        expect(nested("count-objects", "-v")).toBe(nestedAfterPatch!.objects);
        expect(await readFile(join(subdirectory, "app.ts"), "utf8")).toBe(
          "fixed\n",
        );
        expect(await readFile(join(repository, "shared.ts"), "utf8")).toBe(
          "fixed\n",
        );
      }
      const missingConfiguration = kind.includes(
        "removed provider configuration",
      );
      const linkedComponent = kind.includes("replaced by a directory link");
      expect(outcome.exitCode, outcome.stderr).toBe(
        missingConfiguration || linkedComponent ? 2 : 0,
      );
      const result = JSON.parse(outcome.stdout);
      expect(result.repository).toBe(subdirectory);
      if (linkedComponent) {
        expect(result).not.toHaveProperty("applied");
        expect(result).not.toHaveProperty("filesChanged");
      } else {
        expect(result.applied).toBe(true);
        expect(result.filesChanged).toBe(changedFiles.length);
      }
      const reportedFiles = linkedComponent ? [] : changedFiles;
      if (kind === "staged component changes")
        expect(git("show", ":sub/shared.ts")).toBe("staged component");
      expect(result.files).toEqual(
        reportedFiles.map((file) =>
          relative(subdirectory, join(repository, file)).split(sep).join("/"),
        ),
      );
      expect(
        result.files.map((file: string) => resolve(result.repository, file)),
      ).toEqual(reportedFiles.map((file) => join(repository, file)));
      if (!linkedComponent)
        expect(git("show", "--format=", "--name-only", "HEAD", "--")).toBe(
          changedFiles.join("\n"),
        );
      if (missingConfiguration) {
        expect(outcome.stderr).toContain("ENOENT");
        expect(outcome.stderr).toContain(providerConfiguration);
      } else if (linkedComponent) {
        expect(outcome.stderr).toContain(
          "Patch directory now resolves outside the selected repository",
        );
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("diff", "--cached", "--name-only")).toBe("");
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(repository, "shared.ts"), "utf8")).toBe(
          "fixed\n",
        );
      } else
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
      if (linkedComponent)
        expect(await readFile(join(subdirectory, "app.ts"), "utf8")).toBe(
          "original\n",
        );
      else if (removesComponent)
        await expect(readFile(join(subdirectory, "app.ts"))).rejects.toThrow();
      if (originalIndex !== undefined) {
        expect(await readFile(join(repository, ".git/index"))).toEqual(
          originalIndex,
        );
        expect(
          gitText(["status", "--porcelain"], {
            cwd: repository,
            env: {
              ...process.env,
              GIT_INDEX_FILE: join(repository, ".git/custom-index"),
            },
          }),
        ).toBe("");
      } else if (!linkedComponent)
        expect(git("status", "--porcelain")).toBe(
          kind === "staged component changes" ? "MM sub/shared.ts" : "",
        );
    },
  );

  test.each([
    "absolute environment",
    "relative environment",
    "relative common directory",
    "relative index file",
    "relative object directory",
    "configuration",
  ])(
    "preserves discovered Git metadata for a separate worktree: %s",
    async (kind) => {
      const root = await fixtures.create("codex-security-separate-worktree-");
      const repository = join(root, "repository");
      const worktree =
        kind === "relative environment"
          ? join(root, "separate", "worktree")
          : join(root, "worktree");
      const helper = join(root, "prompt-helper.sh");
      const remote = join(root, "remote.git");
      const gitEnvironment =
        kind === "configuration"
          ? {}
          : {
              GIT_WORK_TREE:
                kind === "relative environment"
                  ? relative(repository, worktree)
                  : worktree,
              ...(kind === "relative common directory"
                ? { GIT_COMMON_DIR: "../repository/.git" }
                : {}),
              ...(kind === "relative index file"
                ? { GIT_INDEX_FILE: "../repository/.git/custom-index" }
                : {}),
              ...(kind === "relative object directory"
                ? { GIT_OBJECT_DIRECTORY: "../repository/.git/objects" }
                : {}),
            };
      const git = (...args: string[]) =>
        gitText(args, {
          cwd: repository,
          env: { ...process.env, ...gitEnvironment },
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      await mkdir(repository);
      await mkdir(worktree, { recursive: true });
      if (kind === "relative environment")
        await writeFile(helper, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
      repositoryGit(repository)("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      if (kind === "configuration") git("config", "core.worktree", worktree);
      await writeFile(join(worktree, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Initial synthetic checkout");
      repositoryGit(repository)("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--create-pr"],
        {
          currentDirectory: repository,
          environment: {
            ...process.env,
            ...gitEnvironment,
            ...(kind === "relative environment"
              ? { GIT_ASKPASS: relative(repository, helper) }
              : {}),
          },
          onCodex: async (_args, output) => {
            expect(output?.appServer?.directory).toBe(repository);
            if (output?.appServer?.prompt.includes(patchRiskSkill)) {
              const artifact = patchArtifactFromPrompt(output.appServer.prompt);
              expect(artifact.changedFiles).toEqual(["app.ts"]);
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(worktree, "app.ts"), "fixed\n");
              output?.stdout.write("Patch complete.");
            }
            return 0;
          },
          onRepositoryCommand: async (command, args, directory, options) => {
            if (
              kind === "relative environment" &&
              command === "git" &&
              args[0] === "push"
            )
              expect(options?.environment?.["GIT_ASKPASS"]).toBe(
                await realpath(helper),
              );
            return command === "git"
              ? runGitRepositoryCommand(command, args, directory, {
                  ...options,
                  environment: { ...gitEnvironment, ...options?.environment },
                })
              : args[1] === "create"
                ? "https://github.example.test/example/repository/pull/17"
                : "";
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("show", "HEAD:app.ts")).toBe("fixed");
      expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
      expect(git("status", "--porcelain")).toBe("");
    },
  );

  test.each(["scan", "patch", "direct"])(
    "keeps %s results when pull request preflight fails",
    async (command) => {
      const onCodex = mock(() => 0);
      const outcome = await runWorkflow(
        [
          command === "direct" ? "patch" : command,
          ...(command === "scan"
            ? ["--patch"]
            : command === "direct"
              ? ["Synthetic issue"]
              : ["--scan", "scan-1"]),
          "--create-pr",
          "--json",
        ],
        {
          result: resultWithFindings(["high"]),
          onCodex,
          onWorkbench: () =>
            savedScan(resultWithFindings(["high"]), "scan-1", SAVED_REPOSITORY),
          onRepositoryCommand: (command, args, repository, options) => {
            if (command === "gh")
              throw new Error("GitHub authentication failed.");
            if (args.includes("--absolute-git-dir"))
              return (
                options?.environment?.["GIT_DIR"] ??
                options?.directory ??
                repository
              );
            return args.includes("--name-only") &&
              !args.includes("HEAD") &&
              !args.includes("--cached")
              ? "src/finding-1.ts\0"
              : "";
          },
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(onCodex).not.toHaveBeenCalled();
      expect(outcome.stderr).toContain("GitHub authentication failed.");
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        ...(command === "direct"
          ? { repository: CURRENT_REPOSITORY, applied: false, files: [] }
          : { patches: [] }),
        ...(command === "patch"
          ? { scanId: "scan-1", repository: SAVED_REPOSITORY }
          : {}),
      });
    },
  );

  test.skipIf(Bun.which("gh") === null).each([
    ["github", "open", "host-only"],
    ["github", "open", "ssh+git"],
    ["github", "open", "api-port"],
    ["github", "open", "explicit-host"],
    ["github", "open", "token-only"],
    ["github", "open", "second-push"],
    ["github", "open", "later-page"],
    ["github", "open", "denied-first"],
    ["github", "open", "denied-all"],
    ["github", "open", "denied-unmatched"],
    ["github", "closed", "host-only"],
    ["gitlab", "open", "host-only"],
    ["gitlab", "closed", "host-only"],
  ])(
    "checks actual request state and bounded metadata with %s: %s (%s)",
    async (provider, state, context) => {
      const root = await fixtures.create("codex-security-gh-color-");
      const apiHost =
        context === "api-port"
          ? "forge.example.test:8443"
          : "forge.example.test";
      const url = `https://${apiHost}/example/repository/pull/15`;
      const nativeIdentity = context === "ssh+git" || context === "api-port";
      const repository = join(root, "repository");
      await mkdir(repository);
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git(
        "remote",
        "add",
        "origin",
        `https://${provider === "gitlab" ? "gitlab.com" : apiHost}/example/repository.git`,
      );
      if (context === "ssh+git")
        git(
          "remote",
          "set-url",
          "--push",
          "origin",
          "ssh+git://git@forge.example.test/example/repository.git",
        );
      const multiplePushes =
        context === "second-push" || context.startsWith("denied-");
      if (multiplePushes) {
        git(
          "remote",
          "set-url",
          "--push",
          "origin",
          "https://forge.example.test/first/repository.git",
        );
        git(
          "remote",
          "set-url",
          "--add",
          "--push",
          "origin",
          "https://forge.example.test/example/repository.git",
        );
      }
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port: 0,
        fetch: (request) =>
          new URL(request.url).pathname === "/identity"
            ? context.startsWith("denied-") &&
              (context === "denied-all" ||
                new URL(request.url).searchParams.get("id") === "R_first")
              ? Response.json(
                  {
                    message: `Synthetic lookup denied ${new URL(request.url).searchParams.get("id")}`,
                  },
                  { status: 404 },
                )
              : Response.json({
                  id: new URL(request.url).searchParams.get("id"),
                  url,
                })
            : Response.json(
                [
                  ...(provider === "github"
                    ? Array.from(
                        { length: context === "later-page" ? 30 : 1 },
                        (_, index) => ({
                          url: url.replace("/15", `/${index + 100}`),
                          state: "CLOSED",
                          headRefOid: "unrelated-commit",
                          headRepository: { id: "R_other" },
                        }),
                      )
                    : []),
                  provider === "github"
                    ? {
                        url,
                        state: state === "open" ? "OPEN" : "CLOSED",
                        headRefOid: "saved-commit",
                        headRepository: {
                          id:
                            context === "denied-unmatched"
                              ? "R_unmatched"
                              : "R_synthetic",
                        },
                      }
                    : {
                        web_url: url,
                        state: state === "open" ? "opened" : "closed",
                        sha: "saved-commit",
                        description: "synthetic description ".repeat(60_000),
                      },
                ].slice(
                  0,
                  Number(new URL(request.url).searchParams.get("limit") ?? 30),
                ),
              ),
      });
      try {
        const environment = {
          GH_REPO:
            context === "host-only"
              ? undefined
              : `${apiHost}/example/repository`,
          GH_HOST:
            context === "explicit-host"
              ? "other.example.test"
              : context === "token-only"
                ? undefined
                : "forge.example.test",
          GH_ENTERPRISE_TOKEN: "synthetic-token",
        };
        const outcome = await runWorkflow(
          ["patch", "--resume-pr", "codex-security/patch-scan-1"],
          {
            environment,
            currentDirectory: repository,
            onRepositoryCommand: async (command, args, _directory, options) => {
              if (command === "git") {
                if (
                  args[0] === "remote" ||
                  args[0] === "-c" ||
                  args[0]?.startsWith("--config-env=") ||
                  (args[0] === "config" && args[1] === "--null") ||
                  args.includes("--sq-quote")
                )
                  return runGitRepositoryCommand(
                    command,
                    args,
                    repository,
                    options,
                  );
                expect(args[0]).not.toBe("push");
                return "saved-commit";
              }
              const identity = command === "gh" && args[0] === "repo";
              if (identity) {
                const effectiveEnvironment = {
                  ...environment,
                  ...options?.environment,
                };
                expect(effectiveEnvironment.GH_HOST).toBe("forge.example.test");
                expect(effectiveEnvironment.GH_REPO).toBe("");
                if (args[1] === "set-default") {
                  if (!nativeIdentity) return "example/repository";
                  const { stdout } = await promisify(execFile)(
                    Bun.which("gh")!,
                    [...args],
                    {
                      cwd: repository,
                      env: {
                        PATH: process.env["PATH"],
                        SystemRoot: process.env["SystemRoot"],
                        HOME: root,
                        USERPROFILE: root,
                        GH_CONFIG_DIR: join(root, "gh"),
                        GH_NO_UPDATE_NOTIFIER: "1",
                        ...effectiveEnvironment,
                      },
                      encoding: "utf8",
                    },
                  );
                  return stdout.trim();
                }
                if (context === "api-port")
                  expect(args[2]).toBe(`${apiHost}/example/repository`);
              }
              const endpoint = new URL(
                identity ? "identity" : "fixture",
                server.url,
              );
              if (!identity)
                endpoint.searchParams.set(
                  "limit",
                  args.includes("--limit")
                    ? args[args.indexOf("--limit") + 1]!
                    : "30",
                );
              if (identity)
                endpoint.searchParams.set(
                  "id",
                  multiplePushes &&
                    (await runGitRepositoryCommand(
                      "git",
                      ["ls-remote", "--get-url", "codex-security-push"],
                      repository,
                      options,
                    )) === "https://forge.example.test/first/repository.git"
                    ? "R_first"
                    : "R_synthetic",
                );
              const { stdout } = await promisify(execFile)(
                Bun.which("gh")!,
                [
                  "api",
                  endpoint.href,
                  ...(args.includes("--jq")
                    ? ["--jq", args[args.indexOf("--jq") + 1]!]
                    : []),
                ],
                {
                  env: {
                    PATH: process.env["PATH"],
                    SystemRoot: process.env["SystemRoot"],
                    HOME: root,
                    USERPROFILE: root,
                    GH_CONFIG_DIR: join(root, "gh"),
                    GH_TOKEN: "synthetic-token",
                    GH_NO_UPDATE_NOTIFIER: "1",
                    CLICOLOR_FORCE:
                      provider === "github" &&
                      !["second-push", "later-page"].includes(context)
                        ? "1"
                        : "0",
                  },
                  encoding: "utf8",
                },
              );
              return stdout.trim();
            },
          },
        );
        const denied =
          context === "denied-all" || context === "denied-unmatched";
        expect(outcome.exitCode, outcome.stderr).toBe(
          !denied && state === "open" ? 0 : 2,
        );
        if (denied) {
          expect(outcome.stderr).toContain("Synthetic lookup denied R_first");
          expect(outcome.stderr).not.toContain(
            "Synthetic lookup denied R_synthetic",
          );
        } else if (state === "open") expect(outcome.stderr).toContain(url);
        else {
          expect(outcome.stderr).toContain("no longer open");
          expect(outcome.stderr).not.toContain("Retry from this repository");
        }
      } finally {
        server.stop(true);
      }
    },
  );
  test.each([
    ["gh", "bin", "component"],
    ["glab", "node_modules/.bin", "component"],
    ["gh", "bin", "external explicit worktree"],
    ["glab", "node_modules/.bin", "external configured worktree"],
  ])(
    "keeps the invocation and selected worktree outside the trusted %s PATH: %s %s",
    async (provider, path, kind) => {
      const root = await fixtures.create("codex-security-provider-path-");
      const repository = join(root, "repository");
      const external = kind!.startsWith("external");
      const component = external
        ? join(root, "invocation")
        : join(repository, "component");
      const repositoryTools = join(external ? component : repository, path!);
      const trustedTools = join(root, "trusted");
      const marker = join(root, "provider.json");
      const providerScript = join(root, "provider.mjs");
      const node = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const executable = `${provider}${process.platform === "win32" ? ".exe" : ""}`;
      await mkdir(component, { recursive: true });
      await mkdir(repository, { recursive: true });
      await mkdir(repositoryTools, { recursive: true });
      await mkdir(trustedTools);
      for (const directory of [repositoryTools, trustedTools])
        await copyFile(node, join(directory, executable));
      await writeFile(
        providerScript,
        `
import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(marker)}, JSON.stringify({
  executable: process.execPath,
  operation: process.argv[2],
  credential: process.env.GH_TOKEN === "synthetic-token",
}));
process.exit(17);
`,
      );
      await writeFile(join(component, "app.ts"), "original\n");
      if (external) await writeFile(join(repository, "app.ts"), "original\n");
      await writeFile(join(repository, ".gitignore"), "bin/\nnode_modules/\n");
      const git = initializePatchGit(repository);
      git("add", ".");
      git("commit", "-m", "Initial synthetic checkout");
      if (kind === "external configured worktree")
        git("config", "core.worktree", repository);
      git(
        "remote",
        "add",
        "origin",
        `https://${provider === "glab" ? "gitlab.com" : "github.example.test"}/example/repository.git`,
      );
      const child = Bun.spawn(
        [
          process.execPath,
          "-e",
          `
import { main, runRepositoryCommand } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)};
import { dependencies } from ${JSON.stringify(new URL("./cli-fixtures.ts", import.meta.url).href)};
process.exitCode = await main(["patch", "Synthetic issue", "--create-pr"], process.stdout, process.stderr, dependencies({
  currentDirectory: process.cwd(),
  environment: process.env,
  onRepositoryCommand: (command, args, cwd, options) => {
    // The provider binaries are copies of Node. Supply their script explicitly.
    const argv = command === "git" ? args : [${JSON.stringify(providerScript)}, ...args];
    return runRepositoryCommand(command, argv, cwd, options);
  },
  onCodex: () => { throw new Error("Provider preflight must fail before a model turn"); },
}));
`,
        ],
        {
          cwd: component,
          env: {
            PATH: [repositoryTools, trustedTools, process.env["PATH"]].join(
              delimiter,
            ),
            SystemRoot: process.env["SystemRoot"],
            PATHEXT: process.env["PATHEXT"],
            HOME: root,
            USERPROFILE: root,
            CODEX_SECURITY_STATE_DIR: join(root, "state"),
            GH_TOKEN: "synthetic-token",
            ...(external ? { GIT_DIR: join(repository, ".git") } : {}),
            ...(kind === "external explicit worktree"
              ? { GIT_WORK_TREE: repository }
              : {}),
            CI: "1",
          },
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      const stderr = await new Response(child.stderr).text();
      expect(await child.exited, stderr).toBe(2);
      expect(JSON.parse(await readFile(marker, "utf8"))).toEqual({
        executable: join(trustedTools, executable),
        operation: provider === "gh" ? "pr" : "mr",
        credential: true,
      });
    },
  );

  test.each(["ordinary", "relative Git environment"])(
    "publishes saved component findings with the selected Git cwd: %s",
    async (kind) => {
      const directory = await fixtures.create("patch-saved-component-cwd-");
      const repository = join(directory, "repository");
      const component = join(repository, "component");
      const remote = join(directory, "remote.git");
      const gitEnvironment =
        kind === "relative Git environment"
          ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
          : {};
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations = [
        { path: "app.ts", startLine: 1 },
      ];
      await mkdir(component, { recursive: true });
      await writeFile(join(component, "app.ts"), "original\n");
      await writeFile(join(repository, ".gitignore"), "local.env\n");
      const git = initializePatchGit(repository);
      git("add", ".");
      git("commit", "-m", "Synthetic initial checkout");
      await writeFile(join(repository, "local.env"), "synthetic local data\n");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan", "--create-pr", "--json"],
        {
          currentDirectory: component,
          result,
          environment: { ...process.env, ...gitEnvironment },
          onWorkbench: () => savedScan(result, "scan", component),
          onCodex: async (args, output) => {
            await writeFile(join(component, "app.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, {
                  ...options,
                  environment: { ...gitEnvironment, ...options?.environment },
                })
              : Promise.resolve(
                  args[1] === "create"
                    ? "https://github.example.test/example/repository/pull/17"
                    : command === "glab"
                      ? ""
                      : "[]",
                ),
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("show", "HEAD:component/app.ts")).toBe("fixed");
      expect(await readFile(join(repository, "local.env"), "utf8")).toBe(
        "synthetic local data\n",
      );
      expect(
        git("ls-tree", "-r", "--name-only", "HEAD").split("\n"),
      ).not.toContain("local.env");
    },
  );

  test("keeps a staged edit when a supplied patch overlaps a component file", async () => {
    const directory = await fixtures.create("patch-staged-component-overlap-");
    const repository = join(directory, "repository");
    const component = join(repository, "component");
    const remote = join(directory, "remote.git");
    await mkdir(component, { recursive: true });
    await writeFile(join(component, "app.ts"), "original\n");
    const git = initializePatchGit(repository);
    git("add", ".");
    git("commit", "-m", "Synthetic initial checkout");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    await writeFile(join(component, "app.ts"), "staged edit\n");
    git("add", "component/app.ts");
    await writeFile(join(component, "app.ts"), "original\n");
    const outcome = await runPublicationWorkflow("issue", {
      currentDirectory: component,
      onCodex: async (_args, output) => {
        await writeFile(join(component, "app.ts"), "fixed\n");
        output?.stdout.write("Patch complete.");
        return 0;
      },
      onRepositoryCommand: (command, args, cwd, options) =>
        command === "git"
          ? runGitRepositoryCommand(command, args, cwd, options)
          : Promise.resolve(args[1] === "list" ? "[]" : ""),
    });
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain(
      "Cannot publish files with uncommitted changes before patching",
    );
    expect(git("show", ":component/app.ts")).toBe("staged edit");
    expect(git("branch", "--show-current")).toBe("main");
    expect(await readFile(join(component, "app.ts"), "utf8")).toBe("fixed\n");
  });

  for (const publish of [false, true]) {
    test.skipIf(process.platform === "win32")(
      `assesses a saved target replaced by a committed directory link; publish=${publish}`,
      async () => {
        const root = await repositories.create("patch-saved-directory-link-");
        const repository = join(root, "repository");
        const component = join(repository, "component");
        const scanDir = join(root, "scan");
        await mkdir(join(component, "src"), { recursive: true });
        await mkdir(scanDir, { mode: 0o700 });
        const git = initializePatchGit(repository);
        await writeFile(join(component, "src/extract.py"), "unsafe\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const environment = {
          ...process.env,
          CODEX_HOME: join(root, "codex-home"),
          CODEX_SECURITY_STATE_DIR: join(root, "state"),
        };
        const python = await resolvePluginPython();
        const workbench = (args: readonly string[]) =>
          runWorkbench({ python, pluginRoot: PLUGIN_ROOT, environment }, args);
        const registered = await workbench([
          "register-cli-scan",
          "--repository",
          component,
          "--scan-dir",
          scanDir,
          "--recipe-json",
          JSON.stringify({
            config: {},
            mode: "standard",
            repository: component,
            target: { kind: "repository", paths: [] },
          }),
        ]);
        const scanId = registered["scanId"] as string;
        await copyCompletedScanFixture(scanDir);
        for (const name of ["scan-manifest", "findings", "coverage"]) {
          const path = join(scanDir, `${name}.json`);
          const document = JSON.parse(await readFile(path, "utf8"));
          if (name === "scan-manifest") {
            document.scan.id = scanId;
            delete document.scan.target.kind;
            delete document.scan.sealedAt;
            delete document.scan.artifacts;
          } else document.scanId = scanId;
          await writeFile(path, JSON.stringify(document));
        }
        await workbench(["complete-scan", "--scan-id", scanId]);
        const saved = await workbench(["get-scan", "--scan-id", scanId]);
        expect((saved["scan"] as JsonObject)["targetPath"]).toBe(
          await realpath(component),
        );
        git("mv", "component", "source");
        await symlink("source", component, "dir");
        git("add", ".");
        git("commit", "-m", "Move component and retain its directory link");
        const originalHead = git("rev-parse", "HEAD");
        await addPublicationOrigin(repositories, git);
        let assessments = 0;
        const outcome = await runWorkflow(
          [
            "patch",
            "--scan",
            scanId,
            "--assess-patch-risk",
            ...(publish ? ["--create-pr"] : []),
            "--json",
          ],
          {
            currentDirectory: repository,
            environment,
            onWorkbench: (args) => workbench(args),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (args, output) => {
              if (output?.appServer?.prompt.includes(patchRiskSkill)) {
                const artifact = patchArtifactFromPrompt(
                  output.appServer.prompt,
                );
                expect(artifact.changedFiles).toEqual([
                  "source/src/extract.py",
                ]);
                expect(await readFile(artifact.path, "utf8")).toContain(
                  "+fixed",
                );
                assessments += 1;
                output.stdout.write(patchRiskAssessment().report);
              } else {
                await writeFile(join(component, "src/extract.py"), "fixed\n");
                completePatches(args, output);
              }
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(assessments).toBe(1);
        expect(JSON.parse(outcome.stdout).patchRisk.report).toContain(
          patchRiskSummary(),
        );
        if (publish) {
          expect(git("diff", "--name-only", originalHead, "HEAD")).toBe(
            "source/src/extract.py",
          );
          expect(git("ls-files", "--stage", "component")).toStartWith(
            "120000 ",
          );
        } else expect(git("rev-parse", "HEAD")).toBe(originalHead);
      },
    );
  }
  for (const [command, fileLink, dirty] of [
    ["inline", false, false],
    ["saved", false, false],
    ["inline", true, false],
    ["saved", true, false],
    ["inline", false, true],
    ["saved", false, true],
  ] as const) {
    test.skipIf(fileLink && process.platform === "win32")(
      `publishes ${command} patches through an existing directory alias; file symlink=${fileLink}; local edit=${dirty}`,
      async () => {
        const root = await repositories.create("patch-directory-alias-");
        const directory = join(root, "repository");
        await mkdir(directory);
        const alias = join(root, "link");
        const result = resultWithFindings(["high"]);
        await mkdir(join(directory, "src"));
        const git = initializePatchGit(directory);
        await writeFile(join(directory, "src/finding-1.ts"), "unsafe\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const originalHead = git("rev-parse", "HEAD");
        await symlink(
          directory,
          alias,
          process.platform === "win32" ? "junction" : "dir",
        );
        await addPublicationOrigin(repositories, git);
        if (dirty)
          await writeFile(join(directory, "src/finding-1.ts"), "local edit\n");
        const outcome = await runWorkflow(
          command === "inline"
            ? ["scan", alias, "--patch", "--create-pr", "--json"]
            : ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            result,
            onWorkbench: () => savedScan(result, "scan-1", alias),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (args, output) => {
              await writeFile(join(alias, "src/finding-1.ts"), "fixed\n");
              if (fileLink) {
                await symlink("src/finding-1.ts", join(alias, "new-link.ts"));
                output?.stdout.write(
                  JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status: "verified",
                        files: ["src/finding-1.ts", "new-link.ts"],
                        verification: "The focused regression passed.",
                      },
                    ],
                  }),
                );
              } else completePatches(args, output);
              return 0;
            },
          },
        );
        if (dirty) {
          expect(outcome.exitCode).toBe(2);
          expect(outcome.stderr).toContain(
            "Cannot publish files with uncommitted changes before patching",
          );
          expect(git("rev-parse", "HEAD")).toBe(originalHead);
          expect(git("ls-remote", "origin")).toBe("");
          return;
        }
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout).pullRequest.url).toContain("/pull/1");
        expect(
          git("diff", "--name-only", originalHead, "HEAD").split("\n"),
        ).toEqual(
          fileLink ? ["new-link.ts", "src/finding-1.ts"] : ["src/finding-1.ts"],
        );
        if (fileLink)
          expect(git("ls-files", "--stage", "new-link.ts")).toStartWith(
            "120000 ",
          );
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      },
    );
  }

  test.each([
    "commit",
    "commit result",
    "checkpoint",
    "checkout",
    "checkout restoration",
    "checkout detached",
    "checkout commit",
    "checkout staged",
  ])("preserves local work when patch %s fails", async (failure) => {
    const directory = await repositories.create("patch-creation-failure-");
    const result = resultWithFindings(["high"]);
    await mkdir(join(directory, "src"));
    const git = initializePatchGit(directory);
    await writeFile(join(directory, "src/finding-1.ts"), "unsafe\n");
    await writeFile(join(directory, "other.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    await addPublicationOrigin(repositories, git);
    await writeFile(join(directory, "other.ts"), "staged work\n");
    git("add", "other.ts");
    if (failure === "checkout detached") git("switch", "--detach");
    const base = git("rev-parse", "HEAD");
    const index = git("write-tree");
    if (failure.startsWith("checkout"))
      await writeFile(
        join(directory, ".git", "hooks", "post-checkout"),
        [
          "#!/bin/sh",
          ...(failure === "checkout restoration"
            ? []
            : [
                '[ "$(git branch --show-current)" = "codex-security/patch-scan-1" ] || exit 0',
              ]),
          ...(failure === "checkout commit"
            ? [
                'git commit --only -m "Synthetic hook commit" -- src/finding-1.ts || exit 1',
              ]
            : failure === "checkout staged"
              ? ["git add -- src/finding-1.ts"]
              : []),
          `echo "Synthetic ${failure} failure" >&2`,
          "exit 1",
          "",
        ].join("\n"),
        { mode: 0o755 },
      );
    const outcome = await runPublicationWorkflow("scan", {
      ...savedPatchFixture(directory, result),
      onCodex: async (args, output) => {
        await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
        completePatches(args, output);
        return 0;
      },
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command !== "git") return "";
        if (failure === "commit result" && args.includes("commit")) {
          runGitRepositoryCommand(command, args, cwd, options);
          throw new Error("Synthetic commit result failure");
        }
        if (
          (failure === "commit" && args.includes("commit")) ||
          (failure === "checkpoint" &&
            args[0] === "config" &&
            args[1] === "--local" &&
            args[2]?.endsWith(".codexSecurityPatchCommit"))
        )
          throw new Error(`Synthetic ${failure} failure`);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
    });
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain(`Synthetic ${failure} failure`);
    expect(outcome.stderr).not.toContain("Retry from this repository");
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed\n",
    );
    expect(git("diff", "--cached", "--name-only")).toBe("other.ts");
    if (
      failure === "commit" ||
      (failure.startsWith("checkout") && failure !== "checkout commit")
    ) {
      expect(git("branch", "--show-current")).toBe(
        failure === "checkout detached" ? "" : "main",
      );
      expect(git("rev-parse", "HEAD")).toBe(base);
      if (failure === "checkout staged") {
        expect(git("show", ":other.ts")).toBe("staged work");
        expect(git("show", ":src/finding-1.ts")).toBe("unsafe");
      }
      expect(git("write-tree")).toBe(index);
      expect(outcome.stderr).not.toContain("Could not restore");
      expect(
        git(
          "for-each-ref",
          "--format=%(refname)",
          "refs/heads/codex-security/patch-scan-1",
        ),
      ).toBe("");
    } else {
      expect(git("branch", "--show-current")).toBe(
        "codex-security/patch-scan-1",
      );
      expect(git("rev-parse", "HEAD")).not.toBe(base);
      expect(outcome.stderr).toContain("checkpoint could not be saved");
    }
  });

  test.each(["gh", "glab"])(
    "refuses a %s resume when the published head differs from the saved commit",
    async (client) => {
      const onCodex = mock(() => 0);
      let pushes = 0;
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", "--json"],
        {
          onCodex,
          onRepositoryCommand: (command, args) => {
            if (command === "git") {
              if (args[0] === "config" && args[1] === "--local")
                return args.at(-1)?.endsWith("PatchCommit")
                  ? "verified-commit"
                  : "Synthetic body";
              if (args[0] === "rev-parse") return "verified-commit";
              if (args[0] === "remote")
                return `https://${client === "glab" ? "gitlab.com" : "github.example.test"}/example/repository.git`;
              if (args[0] === "push") pushes += 1;
              return "";
            }
            expect(command).toBe(client);
            const url = "https://example.test/requests/1";
            if (client === "gh" && args[0] === "repo")
              return args[1] === "set-default"
                ? "example/repository"
                : JSON.stringify({ id: "R_synthetic", url });
            const request = { url, head: "earlier-commit", state: "OPEN" };
            return JSON.stringify(
              client === "glab"
                ? request
                : [{ ...request, repositoryId: "R_synthetic" }],
            );
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("does not match the saved patch commit");
      expect(outcome.stderr).not.toContain("Retry from this repository");
      expect(pushes).toBe(0);
      expect(onCodex).not.toHaveBeenCalled();
    },
  );

  test.each([true, false])(
    "publishes a clean rename while keeping unrelated edits local; Git rename reporting=%j",
    async (renameReporting) => {
      const directory = await repositories.create("patch-clean-rename-");
      await mkdir(join(directory, "src"));
      const git = initializePatchGit(directory);
      git("config", "diff.renames", String(renameReporting));
      const original =
        "unsafe\n" +
        Array.from({ length: 12 }, (_, index) => `baseline ${index}\n`).join(
          "",
        );
      await writeFile(join(directory, "src/finding-1.ts"), original);
      await writeFile(join(directory, "other.ts"), "original unrelated\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await addPublicationOrigin(repositories, git);
      await writeFile(join(directory, "other.ts"), "local unrelated\n");
      const outcome = await runPublicationWorkflow("scan", {
        ...savedPatchFixture(directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? ""
              : "https://github.example.test/example/repository/pull/1",
        onCodex: async (_args, output) => {
          await rename(
            join(directory, "src/finding-1.ts"),
            join(directory, "src/renamed.ts"),
          );
          await writeFile(
            join(directory, "src/renamed.ts"),
            original.replace("unsafe\n", "fixed\n"),
          );
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["src/renamed.ts"],
                  verification: "The focused regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout).files).toEqual([
        "src/finding-1.ts",
        "src/renamed.ts",
      ]);
      const commit = git("rev-parse", "HEAD");
      expect(git("ls-remote", "origin")).toContain(commit);
      expect(git("--git-dir", remote, "show", `${commit}:src/renamed.ts`)).toBe(
        original.replace("unsafe\n", "fixed\n").trim(),
      );
      expect(git("--git-dir", remote, "show", `${commit}:other.ts`)).toBe(
        "original unrelated",
      );
      expect(await readFile(join(directory, "other.ts"), "utf8")).toBe(
        "local unrelated\n",
      );
    },
  );

  test.each([
    "staged",
    "unstaged",
    "assume-unchanged",
    "renamed",
    "renamed component",
    "renamed relative component",
  ])(
    "keeps %s same-file edits out of saved patch publication",
    async (dirty) => {
      for (const command of ["patch", "scan"]) {
        const directory = await repositories.create("patch-publication-");
        const scanned = dirty.includes("component")
          ? join(directory, "component")
          : directory;
        const renamed = dirty.startsWith("renamed");
        await mkdir(join(scanned, "src"), { recursive: true });
        const git = initializePatchGit(directory);
        if (dirty === "renamed relative component")
          git("config", "diff.relative", "true");
        const original =
          "unsafe\n" +
          Array.from({ length: 12 }, (_, index) => `baseline ${index}\n`).join(
            "",
          );
        await writeFile(join(scanned, "src/finding-1.ts"), original);
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const originalHead = git("rev-parse", "HEAD");
        await writeFile(
          join(scanned, "src/finding-1.ts"),
          original + "local edit\n",
        );
        if (dirty === "staged") git("add", ".");
        if (dirty === "assume-unchanged")
          git("update-index", "--assume-unchanged", "src/finding-1.ts");
        const originalIndex = git("write-tree");
        await addPublicationOrigin(repositories, git);
        const outcome = await runWorkflow(
          command === "patch"
            ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
            : ["scan", scanned, "--patch", "--create-pr", "--json"],
          {
            ...savedPatchFixture(scanned),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (args, output) => {
              const destination = renamed
                ? "src/renamed.ts"
                : "src/finding-1.ts";
              if (renamed)
                await rename(
                  join(scanned, "src/finding-1.ts"),
                  join(scanned, destination),
                );
              await writeFile(
                join(scanned, destination),
                original.replace("unsafe\n", "fixed\n") + "local edit\n",
              );
              if (renamed)
                output?.stdout.write(
                  JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status: "verified",
                        files: [destination],
                        verification: "The focused regression passed.",
                      },
                    ],
                  }),
                );
              else completePatches(args, output);
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(originalHead);
        expect(git("write-tree")).toBe(originalIndex);
        expect(git("ls-remote", "origin")).toBe("");
        expect(
          await readFile(
            join(scanned, renamed ? "src/renamed.ts" : "src/finding-1.ts"),
            "utf8",
          ),
        ).toBe(original.replace("unsafe\n", "fixed\n") + "local edit\n");
      }
    },
  );

  test.each([
    "local",
    "local ancestor",
    "local descendant",
    "local sibling",
    "remote",
    "remote ancestor",
    "remote descendant",
    "remote sibling",
    "push remote",
    "second push remote",
    "OPEN",
    "CLOSED",
    "MERGED",
    "foreign repository",
    "cross-host identity",
  ])(
    "checks an existing %s patch publication before starting the model",
    async (existing) => {
      const directory = await repositories.create("patch-repeat-");
      const git = initializePatchGit(directory);
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await addPublicationOrigin(repositories, git);
      const branch = existing.endsWith("ancestor")
        ? "codex-security"
        : existing.endsWith("descendant")
          ? "codex-security/patch-scan-1/child"
          : existing.endsWith("sibling")
            ? "codex-security/patch-other"
            : "codex-security/patch-scan-1";
      if (existing.startsWith("local")) git("branch", branch);
      let collisionRemote = remote;
      if (existing === "push remote" || existing === "second push remote") {
        const pushRemote = await repositories.create(
          "patch-repeat-push-remote-",
        );
        git("init", "--bare", pushRemote);
        if (existing === "second push remote") {
          git("remote", "set-url", "--push", "origin", remote);
          git("remote", "set-url", "--push", "--add", "origin", pushRemote);
        } else git("remote", "set-url", "--push", "origin", pushRemote);
        collisionRemote = pushRemote;
      }
      if (existing.includes("remote"))
        git("push", collisionRemote, `HEAD:refs/heads/${branch}`);
      const before = git("ls-remote", collisionRemote, `refs/heads/${branch}`);
      const originalConfig = await readFile(
        join(directory, ".git/config"),
        "utf8",
      );
      const environment = {
        ...process.env,
        GH_REPO: "github.example.test/upstream/repository",
        GIT_CONFIG_PARAMETERS:
          "'remote.origin.gh-resolved=upstream/repository'",
      };
      let identityCalls = 0;
      const result = resultWithFindings(["high"]);
      const onCodex = mock(() => 0);
      const outcome = await runPublicationWorkflow(
        "scan",
        {
          currentDirectory: directory,
          environment,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: async (command, args, cwd, options) => {
            const selected = {
              ...options,
              environment: {
                ...environment,
                ...options?.environment,
              } as NodeJS.ProcessEnv,
            };
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, selected);
            if (args[0] === "repo") {
              identityCalls++;
              expect(selected.environment["GH_REPO"]).toBe("");
              expect(
                runGitRepositoryCommand(
                  "git",
                  ["config", "--get", "remote.origin.gh-resolved"],
                  cwd,
                  selected,
                ),
              ).toBe("");
              return args[1] === "set-default"
                ? "example/repository"
                : JSON.stringify({
                    id: "R_synthetic",
                    url: "https://github.example.test/example/repository",
                  });
            }
            expect(selected.environment["GH_REPO"]).toBe(environment.GH_REPO);
            expect(selected.environment["GIT_CONFIG_PARAMETERS"]).toBe(
              environment.GIT_CONFIG_PARAMETERS,
            );
            const foreign = {
              url: "https://github.example.test/upstream/repository/pull/2",
              head: git("rev-parse", "HEAD"),
              state: "OPEN",
              repositoryId: "R_other",
            };
            if (existing === "foreign repository")
              return JSON.stringify([foreign]);
            if (existing === "cross-host identity")
              return JSON.stringify([
                {
                  ...foreign,
                  url: "https://other.example.test/example/repository/pull/2",
                  repositoryId: "R_synthetic",
                },
              ]);
            return ["OPEN", "CLOSED", "MERGED"].includes(existing)
              ? JSON.stringify([
                  foreign,
                  {
                    ...foreign,
                    url: "https://github.example.test/upstream/repository/pull/1",
                    state: existing,
                    repositoryId: "R_synthetic",
                  },
                ])
              : "";
          },
        },
        { localHosting: "git" },
      );
      expect(outcome.exitCode).toBe(2);
      expect(git("ls-remote", collisionRemote, `refs/heads/${branch}`)).toBe(
        before,
      );
      if (
        existing.endsWith("sibling") ||
        existing === "foreign repository" ||
        existing === "cross-host identity"
      ) {
        expect(onCodex).toHaveBeenCalledTimes(1);
        expect(outcome.stderr).not.toContain("already exists");
      } else {
        expect(onCodex).not.toHaveBeenCalled();
        expect(outcome.stderr).toContain("already exists");
      }
      expect(await readFile(join(directory, ".git/config"), "utf8")).toBe(
        originalConfig,
      );
      expect(environment.GH_REPO).toBe(
        "github.example.test/upstream/repository",
      );
      expect(environment.GIT_CONFIG_PARAMETERS).toBe(
        "'remote.origin.gh-resolved=upstream/repository'",
      );
      expect(identityCalls).toBe(
        [
          "OPEN",
          "CLOSED",
          "MERGED",
          "foreign repository",
          "cross-host identity",
        ].includes(existing)
          ? 2
          : 0,
      );
    },
  );
});

test.each([
  ["untracked", "during assessment"],
  ["tracked", "during assessment"],
  ["untracked", "after patch capture"],
  ["tracked", "after patch capture"],
])(
  "keeps unrelated %s edits made %s out of publication",
  async (kind, timing) => {
    const root = await fixtures.create("patch-assessment-publication-");
    const repository = join(root, "repository");
    const remote = join(root, "remote.git");
    await mkdir(repository);
    const git = initializePatchGit(repository);
    git("config", "commit.gpgsign", "false");
    await writeFile(join(repository, "app.ts"), "original\n");
    if (kind === "tracked")
      await writeFile(join(repository, "user-notes.txt"), "original notes\n");
    git("add", ".");
    git("commit", "-m", "Synthetic initial commit");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const editNotes = () =>
      writeFile(
        join(repository, "user-notes.txt"),
        "unrelated notes from concurrent work\n",
      );
    let editAfterDiff = false;
    const outcome = await runWorkflow(
      [
        "patch",
        "Synthetic issue",
        "--assess-patch-risk",
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: repository,
        onRepositoryCommand: async (command, args, directory, options) => {
          if (command !== "git")
            return args[1] === "create"
              ? "https://github.example.test/example/repository/pull/17"
              : "";
          const result = await runGitRepositoryCommand(
            command,
            args,
            directory,
            options,
          );
          if (
            editAfterDiff &&
            args.includes("diff") &&
            args.includes("--name-only") &&
            !args.includes("--cached")
          ) {
            editAfterDiff = false;
            await editNotes();
          }
          return result;
        },
        onCodex: async (_args, output) => {
          if (output?.appServer?.prompt.includes(patchRiskSkill)) {
            const artifact = patchArtifactFromPrompt(output.appServer.prompt);
            expect(artifact.changedFiles).toEqual(["app.ts"]);
            if (timing === "during assessment") await editNotes();
            output.stdout.write(patchRiskAssessment().report);
          } else {
            await writeFile(join(repository, "app.ts"), "fixed\n");
            editAfterDiff = timing === "after patch capture";
            output?.stdout.write("Patch complete.");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(git("show", "--format=", "--name-only", "HEAD", "--")).toBe(
      "app.ts",
    );
    expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
    expect(git("status", "--porcelain")).toBe(
      `${kind === "tracked" ? "M" : "??"} user-notes.txt`,
    );
    expect(await readFile(join(repository, "user-notes.txt"), "utf8")).toBe(
      "unrelated notes from concurrent work\n",
    );
  },
);
