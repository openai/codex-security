import { readAppliedText } from "./cli-patch-fixtures.js";
import { gitText } from "./support/shell.js";
import { emptyPage } from "./support/linear-pagination.js";
import { resolving } from "./support/promises.js";
import { parse as parseToml } from "smol-toml";
import { afterEach, beforeEach, describe, expect, test, mock } from "bun:test";
import { execFile, execFileSync } from "node:child_process";
import { hash } from "node:crypto";
import { existsSync } from "node:fs";
import {
  chmod,
  copyFile,
  cp,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  basename,
  delimiter,
  dirname,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { pathToFileURL } from "node:url";
import { Writable } from "node:stream";
import { promisify, stripVTControlCharacters } from "node:util";
import type { Finding, JsonObject, SeverityLevel } from "../src/index.js";
import { main } from "../src/cli.js";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";
import type { LinearClientFactory } from "../src/linear.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";
import {
  temporaryDirectory,
  createTemporaryDirectories,
} from "./support/temporary-directories.js";
import { throwing } from "./support/errors.js";
import { createCliTest } from "./support/cli-run.js";
import { resolvePluginPython, runWorkbench } from "../src/runtime.js";
import { copyCompletedScanFixture, PLUGIN_ROOT } from "./plugin-root.js";

const workflowDirectories = createTemporaryDirectories(true);
let CURRENT_REPOSITORY: string;
let SAVED_REPOSITORY: string;
beforeEach(async () => {
  const root = await workflowDirectories.create("patch-workflow-");
  CURRENT_REPOSITORY = join(root, "current", "repository");
  SAVED_REPOSITORY = join(root, "saved", "repository");
  await Promise.all(
    [
      CURRENT_REPOSITORY,
      SAVED_REPOSITORY,
      resolve(CURRENT_REPOSITORY, "../other/repository"),
    ].map((directory) => mkdir(directory, { recursive: true })),
  );
});
afterEach(workflowDirectories.cleanup);
const STATE_DIRECTORY = resolve("/tmp/codex-security-state");

function resultWithFindings(severities: readonly SeverityLevel[]) {
  const result = fakeResult(severities);
  result.findings.findings.forEach((finding, index) => {
    Object.assign(finding, {
      findingId: `csf_${index + 1}`,
      occurrenceId: `occ_${index + 1}`,
      title: `Finding ${index + 1}`,
      summary: `Summary ${index + 1}`,
      locations: [
        { path: `src/finding-${index + 1}.ts`, startLine: index + 1 },
      ],
    });
  });
  return result;
}

function savedScan(
  result: ReturnType<typeof resultWithFindings>,
  scanId = "scan-1",
  targetPath = SAVED_REPOSITORY,
): JsonObject {
  return {
    scan: {
      scanId,
      targetPath,
      findings: result.findings.findings as unknown as JsonObject[],
    },
  };
}

function completePatches(
  args: readonly string[],
  output?: Parameters<ReturnType<typeof dependencies>["runCodex"]>[1],
  status: "verified" | "blocked" = "verified",
): Finding[] {
  const prompt = output?.appServer?.prompt ?? args.at(-1)!;
  const findings = JSON.parse(prompt.split("\n").at(-1)!) as Finding[];
  output?.stdout.write(
    JSON.stringify({
      patches: findings.map((finding) => ({
        occurrenceId: finding.occurrenceId,
        status,
        files: status === "verified" ? [finding.locations[0]!.path] : [],
        ...(status === "verified"
          ? { verification: "The exploit fails and focused tests pass." }
          : { reason: "The required service is unavailable." }),
      })),
    }),
  );
  return findings;
}

function patchRiskSummary() {
  return [
    "### Recommendation: human review required",
    "",
    "The patch has moderate impact and low regression likelihood.",
    "",
    "- Protection: focused tests passed",
    "- Recovery: revert the patch commit",
  ].join("\n");
}

function patchRiskAssessment() {
  const summary = patchRiskSummary();
  return {
    report: [
      "<!-- codex-security:patch-risk-summary:start -->",
      summary,
      "<!-- codex-security:patch-risk-summary:end -->",
      "",
      "```json",
      '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
      "```",
    ].join("\n"),
  };
}

function patchRiskReport() {
  return [
    patchRiskSummary(),
    "",
    "```json",
    '{"schemaVersion":1,"recommendation":"merge","workflowLabel":"human_review_required"}',
    "```",
  ].join("\n");
}

async function runWorkflow(
  arguments_: string[],
  fixtures: Parameters<typeof dependencies>[0] = {},
  options: {
    interactive?: boolean;
    review?: boolean;
    configure?: (value: ReturnType<typeof dependencies>) => void;
  } = {},
) {
  const { stdout, stderr, runCli } = createCliTest(main, {
    stderr: options.interactive,
  });

  const current = dependencies({
    currentDirectory: CURRENT_REPOSITORY,
    onCodex: (args, output) => {
      completePatches(args, output);
      return 0;
    },
    ...fixtures,
  });
  if (options.interactive) {
    current.confirmPatchReview = async (question) => {
      stderr.stream.write(`\n${question} (y/N)\n`);
      return options.review ?? true;
    };
  }
  options.configure?.(current);
  return {
    exitCode: await runCli(arguments_, current),
    stdout: stdout.text(),
    stderr: stderr.text(),
  };
}

describe("scan and patch workflow", () => {
  const repositories = createTemporaryDirectories();
  afterEach(repositories.cleanup);
  test("preserves Git aliases and provider configuration in the Node runtime", async () => {
    const bundle = await mkdtemp(
      join(import.meta.dir, "..", ".patch-context-"),
    );
    const root = await temporaryDirectory("patch-node-context-");
    try {
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
    } finally {
      await rm(bundle, { recursive: true, force: true });
      await rm(root, { recursive: true, force: true });
    }
  });

  test.each([
    ["gh", "bin"],
    ["glab", "node_modules/.bin"],
  ])(
    "keeps the full worktree outside the trusted %s PATH",
    async (provider, path) => {
      const root = await temporaryDirectory("codex-security-provider-path-");
      const repository = join(root, "repository");
      const component = join(repository, "component");
      const repositoryTools = join(repository, path!);
      const trustedTools = join(root, "trusted");
      const marker = join(root, "provider.json");
      const preload = join(root, "provider.mjs");
      const node = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const executable = `${provider}${process.platform === "win32" ? ".exe" : ""}`;
      try {
        await mkdir(component, { recursive: true });
        await mkdir(repositoryTools, { recursive: true });
        await mkdir(trustedTools);
        for (const directory of [repositoryTools, trustedTools])
          await copyFile(node, join(directory, executable));
        await writeFile(
          preload,
          `
import { writeFileSync } from "node:fs";
import { basename } from "node:path";
if (["pr", "mr"].includes(basename(process.argv[1] ?? ""))) {
  writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ executable: process.execPath, credential: process.env.GH_TOKEN === "synthetic-token" }));
  process.exit(17);
}
`,
        );
        await writeFile(join(component, "app.ts"), "original\n");
        await writeFile(
          join(repository, ".gitignore"),
          "bin/\nnode_modules/\n",
        );
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
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
            `import { main } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)}; process.exitCode = await main(["patch", "Synthetic issue", "--create-pr"]);`,
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
              NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
              GH_TOKEN: "synthetic-token",
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
          credential: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
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
      const directory = await temporaryDirectory(
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
      const git = repositoryGit(repository);
      try {
        await mkdir(join(subdirectory, ".codex"), { recursive: true });
        if (kind.includes("symlink Git environment"))
          await symlink(
            process.platform === "win32" ? repository : subdirectory,
            alias,
            process.platform === "win32" ? "junction" : "dir",
          );
        if (Object.keys(providerEnvironment).length > 0) {
          await mkdir(providerConfiguration);
          await writeFile(
            join(providerConfiguration, "config.yml"),
            "git_protocol: https\n",
          );
          if (kind.includes("removed provider configuration")) {
            await writeFile(
              join(repository, ".gitignore"),
              "provider-config/\n",
            );
          }
        }
        await writeFile(
          join(subdirectory, ".codex", "config.toml"),
          '[mcp_servers.component]\ncommand = "synthetic-component-server"\n',
        );
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
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
          await writeFile(
            join(subdirectory, "shared.ts"),
            "staged component\n",
          );
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
              ...gitEnvironment,
              ...providerEnvironment,
            },
            onCodex: async (_args, output, environment) => {
              const assessing = output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              );
              expect(output?.appServer?.directory).toBe(
                assessmentAtRoot && assessing ? repository : subdirectory,
              );
              if (!(assessmentAtRoot && assessing))
                expect(
                  await readFile(
                    join(
                      output!.appServer!.directory!,
                      ".codex",
                      "config.toml",
                    ),
                    "utf8",
                  ),
                ).toContain("synthetic-component-server");
              if (
                output?.appServer?.prompt.includes(
                  "$codex-security:assess-patch-risk",
                )
              ) {
                expect(
                  resolve(
                    execFileSync("git", ["rev-parse", "--show-toplevel"], {
                      cwd: output.appServer.directory,
                      env: environment,
                      encoding: "utf8",
                    }).replace(/\n$/u, ""),
                  ),
                ).toBe(repository);
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                );
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
                if (removesComponent) {
                  await rm(subdirectory, { recursive: true });
                  if (kind.includes("replaced by a file"))
                    await writeFile(subdirectory, "replacement file\n");
                  if (kind.includes("replaced by a directory link")) {
                    const outside = join(directory, "other-checkout");
                    await mkdir(outside);
                    await writeFile(join(outside, "app.ts"), "original\n");
                    const other = repositoryGit(outside);
                    other("init", "--initial-branch=main");
                    other("config", "user.name", "Synthetic User");
                    other("config", "user.email", "synthetic@example.test");
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
                    const nested = repositoryGit(subdirectory);
                    nested("init", "--initial-branch=main");
                    nested("config", "user.name", "Synthetic User");
                    nested("config", "user.email", "synthetic@example.test");
                    nested("add", ".");
                    nested("commit", "-m", "Synthetic nested checkout");
                  }
                }
                await writeFile(join(repository, "shared.ts"), "fixed\n");
                for (const file of extraFiles)
                  await writeFile(join(repository, file), "fixed\n");
                output?.stdout.write("Patch complete.");
              }
              return 0;
            },
            onRepositoryCommand: async (command, args, directory, options) => {
              if (command === "git") {
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
                    ...gitEnvironment,
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
        const missingConfiguration = kind.includes(
          "removed provider configuration",
        );
        const linkedComponent = kind.includes("replaced by a directory link");
        expect(outcome.exitCode, outcome.stderr).toBe(
          missingConfiguration || linkedComponent ? 2 : 0,
        );
        const result = JSON.parse(outcome.stdout);
        expect(result.repository).toBe(subdirectory);
        expect(result.applied).toBe(!linkedComponent);
        const reportedFiles = linkedComponent ? [] : changedFiles;
        expect(result.filesChanged).toBe(reportedFiles.length);
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
          expect(git("rev-parse", "HEAD")).toBe(
            git("rev-parse", "@{upstream}"),
          );
        if (linkedComponent)
          expect(await readFile(join(subdirectory, "app.ts"), "utf8")).toBe(
            "original\n",
          );
        else if (removesComponent)
          await expect(
            readFile(join(subdirectory, "app.ts")),
          ).rejects.toThrow();
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
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
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
      const root = await temporaryDirectory(
        "codex-security-separate-worktree-",
      );
      const repository = join(root, "repository");
      const worktree = join(root, "worktree");
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
      try {
        await mkdir(repository);
        await mkdir(worktree);
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
            environment: { ...process.env, ...gitEnvironment },
            onCodex: async (_args, output) => {
              expect(output?.appServer?.directory).toBe(repository);
              if (
                output?.appServer?.prompt.includes(
                  "$codex-security:assess-patch-risk",
                )
              ) {
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                );
                expect(artifact.changedFiles).toEqual(["app.ts"]);
                output.stdout.write(patchRiskAssessment().report);
              } else {
                await writeFile(join(worktree, "app.ts"), "fixed\n");
                output?.stdout.write("Patch complete.");
              }
              return 0;
            },
            onRepositoryCommand: (command, args, directory, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, directory, {
                    ...options,
                    environment: { ...gitEnvironment, ...options?.environment },
                  })
                : args[1] === "create"
                  ? "https://github.example.test/example/repository/pull/17"
                  : "",
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(git("show", "HEAD:app.ts")).toBe("fixed");
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "@{upstream}"));
        expect(git("status", "--porcelain")).toBe("");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
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
              return options?.environment?.["GIT_DIR"] ?? repository;
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
      const root = await temporaryDirectory("codex-security-gh-color-");
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
        `https://${provider === "gitlab" ? "gitlab.com" : "forge.example.test"}/example/repository.git`,
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
      let selectedIdentityConfig = "";
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
                if (args[0] === "config" && args[1] === "--file") {
                  selectedIdentityConfig = args[3]!;
                  return runGitRepositoryCommand(command, args, root, options);
                }
                if (
                  args[0] === "remote" ||
                  args[0] === "-c" ||
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
                    selectedIdentityConfig ===
                      "url.https://forge.example.test/first/repository.git.insteadOf"
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
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each([false, true])(
    "shows progress during baseline preparation and cleans up on failure: %p",
    async (failSnapshot) => {
      const result = resultWithFindings(["high"]);
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      let snapshotHadProgress = false;
      let resultSnapshotHadProgress = false;
      let modelStarted = false;
      const setInterval = mock(() => ({}) as NodeJS.Timeout);
      const clearInterval = mock();
      const current = dependencies({
        currentDirectory: CURRENT_REPOSITORY,
        result,
        onWorkbench: () => savedScan(result),
        onRepositoryCommand: (_command, args) => {
          if (args.includes("--absolute-git-dir")) return CURRENT_REPOSITORY;
          if (args.includes("add") && !modelStarted) {
            snapshotHadProgress = stderr
              .text()
              .includes("Patching 1/1 · Finding 1");
            if (failSnapshot) throw new Error("Baseline snapshot failed.");
          }
          if (args.includes("add") && modelStarted)
            resultSnapshotHadProgress =
              setInterval.mock.calls.length > clearInterval.mock.calls.length;
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
        onCodex: (args, output) => {
          modelStarted = true;
          completePatches(args, output);
          return 0;
        },
      });
      current.setInterval = setInterval;
      current.clearInterval = clearInterval;

      const status = await runCli(
        ["scan", "--patch", "--patch-severity", "high"],
        current,
      );

      expect(snapshotHadProgress).toBe(true);
      expect(resultSnapshotHadProgress).toBe(!failSnapshot);
      expect(modelStarted).toBe(!failSnapshot);
      expect(status).toBe(failSnapshot ? 2 : 0);
      expect(setInterval.mock.calls.length).toBe(
        clearInterval.mock.calls.length,
      );
      if (failSnapshot)
        expect(stderr.text()).toContain("Baseline snapshot failed.");
    },
  );

  test("puts patch runner diagnostics on a new line after the timer", async () => {
    for (const status of [1, 2]) {
      const result = resultWithFindings(["high"]);
      const stdout = capture();
      let errors = "";
      const stderr = Object.assign(
        new Writable({
          write(chunk, _encoding, callback) {
            errors += chunk.toString();
            callback();
          },
        }),
        { isTTY: true },
      );
      const current = dependencies({
        currentDirectory: CURRENT_REPOSITORY,
        result,
        onWorkbench: () => savedScan(result),
        onCodex: async (_args, output) => {
          await new Promise<void>((resolve, reject) => {
            output!.stderr.write(
              "codex-security: Patch response failed.\n",
              (error) => {
                if (error) reject(error);
                else resolve();
              },
            );
          });
          return status;
        },
      });

      await main(
        ["patch", "--scan", "scan-1", "--json"],
        stdout.stream,
        stderr,
        current,
      );

      expect(stripVTControlCharacters(errors)).toContain(
        "\ncodex-security: Patch response failed.\n",
      );
      expect(JSON.parse(stdout.text()).patches[0].status).toBe("failed");
    }
  });

  test.each(["A long finding title ".repeat(12), "界".repeat(100)])(
    "keeps a long patch timer on one terminal row: %s",
    async (title) => {
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.title = title;
      const { stderr, runCli } = createCliTest(main, { stderr: true });

      Object.assign(stderr.stream, { columns: 36 });
      let now = 0;
      const current = dependencies({
        currentDirectory: CURRENT_REPOSITORY,
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          now = 84_000;
          setIntervalMock.mock.lastCall?.[0]?.();
          expect(completePatches(args, output)[0]!.title).toBe(title);
          return 0;
        },
      });
      const setIntervalMock = mock(current.setInterval);
      current.now = () => now;
      current.setInterval = setIntervalMock;
      current.clearInterval = () => {};

      expect(
        await runCli(["patch", "--scan", "scan-1", "--json"], current),
      ).toBe(0);

      const frames = stripVTControlCharacters(stderr.text())
        .split(/[\r\n]/u)
        .filter((line) => /^\[\d+:\d+\] Patching/u.test(line));
      expect(frames).toHaveLength(2);
      for (const frame of frames) {
        expect(Bun.stringWidth(frame)).toBeLessThan(36);
        expect(frame).toEndWith("…");
      }
    },
  );

  test("shows each patch and live activity before it finishes, with clean JSON output", async () => {
    for (const args of [
      ["scan", "--patch", "--patch-severity", "high"],
      ["patch", "--scan", "scan-1", "--json"],
    ]) {
      const result = resultWithFindings(["high", "high"]);
      const { stdout, stderr, runCli } = createCliTest(main, { stderr: true });

      let now = 0;
      let index = 0;
      const timers = new Map<NodeJS.Timeout, () => void>();
      const current = dependencies({
        currentDirectory: CURRENT_REPOSITORY,
        result,
        onWorkbench: () => savedScan(result),
        onCodex: (args, output) => {
          index += 1;
          const label = `Patching ${index}/2 · Finding ${index}`;
          expect(stderr.text()).toContain(label);
          expect(stderr.text()).not.toContain(`VERIFIED  Finding ${index}`);
          for (const delta of ["Checking ", "the ", "fix."]) {
            output!.appServer!.onEvent!({
              method: "item/reasoning/summaryTextDelta",
              params: { itemId: "reasoning-1", delta },
            });
          }
          expect(stderr.text().match(/Codex: Checking/gu) ?? []).toHaveLength(
            index - 1,
          );
          output!.appServer!.onEvent!({
            method: "item/completed",
            params: {
              item: {
                id: "reasoning-1",
                type: "reasoning",
                summary: ["Checking the fix."],
              },
            },
          });
          expect(stderr.text()).toContain("Codex: Checking the fix.");
          now += 84_000;
          for (const tick of [...timers.values()]) tick();
          expect(stderr.text()).toContain(`[01:24] ${label}`);
          completePatches(args, output);
          return 0;
        },
      });
      current.now = () => now;
      current.setInterval = (callback) => {
        const timer = {} as NodeJS.Timeout;
        timers.set(timer, callback);
        return timer;
      };
      current.clearInterval = (timer) => {
        timers.delete(timer);
      };

      expect(await runCli(args, current), stderr.text()).toBe(0);
      expect(index).toBe(2);
      expect(timers.size).toBe(0);
      const progress = stderr.text();
      expect(progress.indexOf("VERIFIED  Finding 1")).toBeLessThan(
        progress.indexOf("Patching 2/2"),
      );
      expect(progress).toContain("VERIFIED  Finding 2");
      expect(progress.match(/Codex: Checking the fix\./gu)).toHaveLength(2);
      if (args.includes("--json")) {
        expect(JSON.parse(stdout.text()).patches).toMatchObject([
          { occurrenceId: "occ_1", status: "verified" },
          { occurrenceId: "occ_2", status: "verified" },
        ]);
      }
      expect(stdout.text()).not.toContain("\u001B");
    }
  });

  test("uses plain patch progress for noninteractive runs", async () => {
    const saved = ["patch", "--scan", "scan-1", "--json"];
    for (const [interactive, environment, args] of [
      [false, {}, saved],
      [true, { CI: "1" }, saved],
      [true, { TERM: "dumb" }, saved],
      [true, {}, ["scan", "--patch", "--headless"]],
      [true, {}, ["scan", "--patch", "--json"]],
    ] as const) {
      const result = resultWithFindings(["high"]);
      const outcome = await runWorkflow(
        [...args],
        {
          result,
          environment,
          onWorkbench: () => savedScan(result),
        },
        { interactive },
      );
      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain("Patching 1/1 · Finding 1");
      expect(outcome.stderr).not.toContain("\u001B");
    }
  });

  test("stops patch progress on interruption or an agent error", async () => {
    for (const status of [130, "error"] as const) {
      const result = resultWithFindings(["high", "high"]);
      const setInterval = mock(() => ({}) as NodeJS.Timeout);
      const clearInterval = mock();
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--json"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onCodex: () => {
            if (status === "error") throw new Error("Agent failed");
            return status;
          },
        },
        {
          interactive: true,
          configure: (current) => {
            current.setInterval = setInterval;
            current.clearInterval = clearInterval;
          },
        },
      );
      expect(outcome.exitCode).not.toBe(0);
      expect(setInterval.mock.calls.length).toBe(
        clearInterval.mock.calls.length,
      );
      expect(outcome.stderr).toContain("\u001B[?25h");
      expect(outcome.stderr).not.toContain("Patching 2/2");
      expect(outcome.stderr).toContain(
        status === "error" ? "Agent failed" : "Patch operation was interrupted",
      );
    }
  });
  test("exposes the validation prompt in patch help and schema", async () => {
    const help = await runWorkflow(["patch", "--help"]);
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain("--validation-prompt-file");
    const schema = await runWorkflow(["patch", "--schema", "--json"]);
    expect(schema.exitCode).toBe(0);
    expect(
      JSON.parse(schema.stdout).options.properties.validationPromptFile,
    ).toMatchObject({ type: "string" });
  });

  test.each(["literal", "file", "linear"])(
    "passes custom validation instructions to the %s patch task",
    async (source) => {
      const repository = await temporaryDirectory("patch-validation-");
      const validation =
        "Start the local app. Exercise the fix and a legitimate request. Stop the app.\n";
      try {
        await writeFile(join(repository, "validation.md"), validation);
        await writeFile(
          join(repository, "issues.md"),
          "Synthetic security issue",
        );
        let calls = 0;
        const outcome = await runWorkflow(
          [
            "patch",
            ...(source === "linear"
              ? [
                  "--linear-issue",
                  "SEC-123",
                  "--linear-api-key",
                  "lin_api_SYNTHETIC",
                ]
              : [source === "file" ? "issues.md" : "Synthetic security issue"]),
            "--validation-prompt-file",
            "validation.md",
            "--json",
          ],
          {
            currentDirectory: repository,
            linearClient: () =>
              ({
                issue: async () => ({
                  identifier: "SEC-123",
                  title: "Synthetic security issue",
                  description: "Synthetic issue details",
                  url: "https://linear.app/example/issue/SEC-123",
                  comments: emptyPage,
                }),
              }) as unknown as ReturnType<LinearClientFactory>,
            onCodex: (_args, output) => {
              calls++;
              expect(output?.appServer?.directory).toBe(repository);
              expect(output?.appServer?.prompt).toContain(
                JSON.stringify(validation),
              );
              expect(output?.appServer?.prompt).toContain(
                "$codex-security:fix-finding",
              );
              const issues = JSON.parse(
                output!.appServer!.prompt.split("\n").at(-1)!,
              );
              expect(issues).toHaveLength(1);
              expect(issues[0]).toContain("Synthetic security issue");
              output?.stdout.write("Fixed; runtime validation passed.");
              return 0;
            },
          },
        );
        expect(outcome.exitCode).toBe(0);
        expect(calls).toBe(1);
        expect(JSON.parse(outcome.stdout).report).toBe(
          "Fixed; runtime validation passed.",
        );
      } finally {
        await rm(repository, { recursive: true, force: true });
      }
    },
  );

  test("reads validation from the invocation directory once for all saved findings", async () => {
    const directory = await temporaryDirectory("saved-patch-validation-");
    const repository = join(directory, "repository");
    const validation = "Build the app and run the regression tests.\n";
    const result = resultWithFindings(["high", "medium"]);
    let calls = 0;
    try {
      await mkdir(repository);
      await writeFile(join(directory, "validation.md"), validation);
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--validation-prompt-file",
          "validation.md",
          "--json",
        ],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onCodex: async (args, output) => {
            calls++;
            expect(output?.appServer?.directory).toBe(repository);
            expect(output?.appServer?.prompt).toContain(
              JSON.stringify(validation),
            );
            await rm(join(directory, "validation.md"), { force: true });
            completePatches(args, output, calls === 1 ? "verified" : "blocked");
            return 0;
          },
        },
      );
      expect(calls).toBe(2);
      expect(outcome.exitCode).toBe(1);
      expect(
        JSON.parse(outcome.stdout).patches.map(
          (patch: { status: string }) => patch.status,
        ),
      ).toEqual(["verified", "blocked"]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["linked", "root"],
    ["explicit", "root"],
    ["linked", "subdirectory"],
    ["explicit", "subdirectory"],
    ["linked", "nested-worktree"],
    ["explicit", "nested-worktree"],
  ])(
    "checks the invocation checkout boundary for %s prompts from a %s",
    async (kind, invocation) => {
      const root = await temporaryDirectory("patch-prompt-boundary-");
      const checkout = join(root, "invocation");
      const directory =
        invocation === "root" ? checkout : join(checkout, "nested", "cwd");
      const repository = join(root, "repository");
      const outside = join(root, "outside");
      const result = resultWithFindings(["high"]);
      let started = false;
      try {
        await Promise.all(
          [directory, repository, outside].map((path) =>
            mkdir(path, { recursive: true }),
          ),
        );
        execFileSync("git", ["init", "--quiet", checkout]);
        if (invocation === "nested-worktree")
          execFileSync("git", ["init", "--quiet", dirname(directory)]);
        await writeFile(
          join(outside, "validation.md"),
          "Run the synthetic regression test.",
        );
        await symlink(
          outside,
          join(checkout, "validation"),
          process.platform === "win32" ? "junction" : "dir",
        );
        const outcome = await runWorkflow(
          [
            "patch",
            "--scan",
            "scan-1",
            "--validation-prompt-file",
            kind === "linked"
              ? relative(
                  directory,
                  join(checkout, "validation", "validation.md"),
                )
              : join(outside, "validation.md"),
            "--json",
          ],
          {
            currentDirectory: directory,
            onWorkbench: () => savedScan(result, "scan-1", repository),
            onCodex: (args, output) => {
              started = true;
              completePatches(args, output);
              return 0;
            },
          },
        );
        expect(started).toBe(kind === "explicit");
        expect(outcome.exitCode).toBe(kind === "explicit" ? 0 : 2);
        if (kind === "linked")
          expect(outcome.stderr).toContain("directory links outside");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["missing", "empty", "directory"])(
    "rejects a %s validation prompt before starting a patch",
    async (kind) => {
      const directory = await temporaryDirectory("invalid-patch-validation-");
      try {
        const path = join(directory, "validation.md");
        if (kind === "empty") await writeFile(path, " \n");
        if (kind === "directory") await mkdir(path);
        const onCodex = mock<() => number>().mockReturnValue(0);
        const outcome = await runWorkflow(
          [
            "patch",
            "Synthetic security issue",
            "--validation-prompt-file",
            path,
            "--json",
          ],
          {
            currentDirectory: directory,
            onCodex,
          },
        );
        expect(outcome.exitCode).toBe(2);
        expect(onCodex).not.toHaveBeenCalled();
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          ok: false,
          applied: false,
        });
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("assesses patch risk only when the patch flag is selected", async () => {
    const directory = await repositories.create("saved-patch-risk-");
    for (const enabled of [false, true]) {
      const result = resultWithFindings(["high"]);
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "--model",
          "gpt-6.1-sol",
          "--effort",
          "max",
          "--auth",
          "chatgpt",
          "--scan",
          "scan-1",
          "--json",
          ...(enabled ? ["--assess-patch-risk"] : []),
        ],
        {
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex: (args, output) => {
            expect(args).toContain('model="gpt-6.1-sol"');
            expect(args).toContain('model_reasoning_effort="max"');
            expect(output?.auth).toBe("chatgpt");
            completePatches(args, output);
            return 0;
          },
        },
        {
          configure: (current) => {
            current.assessPatchRisk = async (request) => {
              expect(request.auth).toBe("chatgpt");
              expect(request.configuration.model).toBe("gpt-6.1-sol");
              expect(request.configuration.effort).toBe("max");
              assessments += 1;
              return patchRiskAssessment();
            };
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(enabled ? 1 : 0);
      expect(outcome.stderr.includes("Patch risk assessment:")).toBe(enabled);
      const resultBody = JSON.parse(outcome.stdout) as JsonObject;
      expect("patchRisk" in resultBody).toBe(enabled);
      if (enabled) {
        expect(resultBody["patchRisk"]).toEqual({
          report: patchRiskReport(),
        });
      }
    }
  });

  test("preserves patch-risk details in display and publication summaries", async () => {
    const directory = await repositories.create("patch-risk-publication-");
    const result = resultWithFindings(["high"]);
    const detail = "Diagnostic detail: token=SYNTHETIC_RISK_VALUE";
    const report = patchRiskAssessment().report.replace(
      patchRiskSummary(),
      `${patchRiskSummary()}\n\n${detail}`,
    );
    const repositoryCommands: Array<{
      command: string;
      args: readonly string[];
    }> = [];
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--assess-patch-risk",
        "--create-pr",
        "--json",
      ],
      {
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args) => {
          repositoryCommands.push({ command, args });
          if (command === "git") {
            if (
              args.includes("--show-toplevel") ||
              args.includes("--absolute-git-dir")
            )
              return directory;
            if (args[0] === "diff" && args.includes("--cached")) return "";
            if (args[0] === "remote") {
              return "https://github.example.test/example/repository.git";
            }
            return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
          }
          return args[1] === "create"
            ? "https://github.example.test/example/repository/pull/15"
            : "";
        },
      },
      {
        configure: (current) => {
          Object.assign(current, {
            assessPatchRisk: async () => ({ report }),
          });
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(outcome.stderr).toContain("Patch risk assessment:");
    expect(outcome.stderr).toContain(patchRiskSummary());
    expect(outcome.stderr).toContain(detail);
    expect(JSON.parse(outcome.stdout).patchRisk.report).toContain(detail);
    const published = repositoryCommands.find(
      ({ command, args }) => command === "gh" && args[1] === "create",
    )?.args;
    const persisted = repositoryCommands.find(
      ({ command, args }) =>
        command === "git" &&
        args[0] === "config" &&
        args[2]?.endsWith(".codexSecurityPatchPullRequestBody"),
    )?.args;
    expect(published).toBeDefined();
    expect(persisted).toBeDefined();
    for (const body of [published?.at(-1), persisted?.at(-1)]) {
      expect(body).toContain(patchRiskSummary());
      expect(body).toContain(detail);
    }
  });

  test.each([
    "literal",
    "saved rename",
    "saved outside rename",
    "supplied outside rename",
  ])("assesses only changes made during a %s patch run", async (mode) => {
    const directory = await temporaryDirectory("codex-security-patch-risk-");
    const repository = join(directory, "repository");
    await mkdir(join(repository, "sub"), { recursive: true });
    const git = repositoryGit(repository);
    const saved = mode.startsWith("saved");
    const outside = mode.includes("outside");
    const source = join(repository, outside ? "sibling" : "sub", "app.ts");
    if (outside) {
      await mkdir(join(repository, "sibling"));
      await writeFile(join(repository, "sub", "keep.ts"), "selected file\n");
    }
    let assessments = 0;

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(source, "original\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(source, "original\nuser change\n");

      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(repository, ".git/index"));
      const outcome = await runWorkflow(
        [
          "patch",
          "--model",
          "gpt-6.1-sol",
          "--effort",
          "max",
          ...(saved ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--assess-patch-risk",
          "--codex",
          "analytics.enabled=false",
          "--codex",
          'model_provider="synthetic.gateway"',
          "--codex",
          'model_providers={"synthetic.gateway"={name="Synthetic",base_url="https://gateway.example.test/v1",wire_api="responses",env_key="SYNTHETIC_KEY"}}',
        ],
        {
          currentDirectory: join(repository, "sub"),
          onWorkbench: () => {
            const result = resultWithFindings(["high"]);
            result.findings.findings[0]!.locations[0]!.path = "app.ts";
            return savedScan(result, "scan-1", join(repository, "sub"));
          },
          onCodex: async (args, output) => {
            expect(args).toContain('model="gpt-6.1-sol"');
            expect(args).toContain('model_reasoning_effort="max"');
            expect(args).toContain("analytics.enabled=false");
            expect(args).toContain('model_provider="synthetic.gateway"');
            expect(output?.modelProvider).toBe("synthetic.gateway");
            expect(output?.codexOverrides).toMatchObject({
              model_providers: {
                "synthetic.gateway": { env_key: "SYNTHETIC_KEY" },
              },
            });
            expect(
              parseToml(
                args.find((arg) => arg.startsWith("model_providers="))!,
              ),
            ).toMatchObject({
              model_providers: {
                "synthetic.gateway": { env_key: "SYNTHETIC_KEY" },
              },
            });
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; sha256: string; changedFiles: string[] };
              const patch = await readFile(artifact.path, "utf8");
              expect(patch).toContain("+patch change");
              if (mode === "literal")
                expect(patch).not.toContain("+user change");
              else {
                expect(patch).toContain("deleted file mode");
                expect(artifact.changedFiles).toEqual(
                  [
                    ...(outside ? ["sibling/app.ts"] : ["sub/app.ts"]),
                    "sub/new.ts",
                  ].sort(),
                );
              }
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            if (mode !== "literal") await rm(source);
            await writeFile(
              join(repository, "sub", mode === "literal" ? "app.ts" : "new.ts"),
              "original\nuser change\npatch change\n",
            );
            output?.stdout.write(
              !saved
                ? "Patch complete."
                : JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status: "verified",
                        files: ["new.ts"],
                        verification: "Synthetic verification",
                      },
                    ],
                  }),
            );
            return 0;
          },
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );

      const blocked = saved && outside;
      expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
      expect(assessments).toBe(blocked ? 0 : 1);
      expect(outcome.stderr).toContain(
        blocked
          ? "Patch files must remain inside the scanned repository."
          : "Patch risk assessment:",
      );
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(repository, ".git/index"))).toEqual(index);
      if (mode !== "literal") {
        expect(existsSync(source)).toBe(false);
        expect(await readFile(join(repository, "sub", "new.ts"), "utf8")).toBe(
          "original\nuser change\npatch change\n",
        );
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("creates a draft pull request with the Linear patch-risk summary", async () => {
    const directory = await temporaryDirectory(
      "codex-security-linear-patch-pr-",
    );
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/17";
    const expectedBody = [
      "Applies a security fix generated for SEC-123.",
      "",
      "## Patch risk assessment",
      "",
      patchRiskSummary(),
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const git = repositoryGit(repository);

    try {
      await mkdir(join(repository, "src"), { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "checkout-hook.sh"), "unsafe\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");

      const outcome = await runWorkflow(
        [
          "patch",
          "--linear-issue",
          "SEC-123",
          "--linear-api-key",
          "lin_api_SYNTHETIC",
          "--assess-patch-risk",
          "--create-pr",
        ],
        {
          currentDirectory: join(repository, "src"),
          linearClient: () =>
            ({
              issue: async () => ({
                identifier: "SEC-123",
                title: "Synthetic checkout hook issue",
                description:
                  "The trusted checkout hook resolves an untrusted module.",
                url: "https://linear.app/example/issue/SEC-123",
                comments: async () => ({
                  nodes: [],
                  pageInfo: { hasNextPage: false },
                  fetchNext: async () => undefined,
                }),
              }),
            }) as unknown as ReturnType<LinearClientFactory>,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { changedFiles: string[]; path: string };
              expect(artifact.changedFiles).toEqual(["src/checkout-hook.sh"]);
              expect(await readFile(artifact.path, "utf8")).toContain("+safe");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            expect(output?.appServer?.prompt).toContain("SEC-123");
            await writeFile(
              join(repository, "src", "checkout-hook.sh"),
              "safe\n",
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: (
            command,
            args,
            workingDirectory,
            commandOptions,
          ) => {
            expect(commandOptions?.directory ?? workingDirectory).toBe(
              join(repository, "src"),
            );
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            if (args[1] === "list") return "";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe(
        "codex-security/patch-SEC-123",
      );
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/checkout-hook.sh",
      );
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-SEC-123"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-SEC-123",
        "--title",
        "fix: patch verified security findings",
        "--body",
        expectedBody,
      ]);
      expect(outcome.stderr).toContain("Patch risk assessment:");
      expect(outcome.stderr).toContain(`Pull request: ${url}`);
      expect(pullRequestArguments.at(-1)).not.toContain("schemaVersion");
      expect(pullRequestArguments.at(-1)).not.toContain(
        "codex-security:patch-risk-summary",
      );
      expect(pullRequestArguments.at(-1)).not.toContain(
        "trusted checkout hook",
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("assesses a patch larger than the repository command buffer", async () => {
    const directory = await temporaryDirectory("codex-security-large-patch-");
    const repository = join(directory, "repository");
    await mkdir(repository, { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "large.txt"), "original\n");
      git("add", "--", "large.txt");
      git("commit", "-m", "Initial synthetic checkout");

      const outcome = await runWorkflow(
        ["patch", "Synthetic large issue", "--assess-patch-risk"],
        {
          currentDirectory: repository,
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; sha256: string };
              const patch = await readFile(artifact.path);
              expect(patch.byteLength).toBeGreaterThan(1024 * 1024);
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "large.txt"),
              "x".repeat(2 * 1024 * 1024),
            );
            output?.stdout.write("Patch complete.");
            return 0;
          },
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([false, true])(
    "patches selected scan findings with analytics.enabled=%p in the scanned repository and returns JSON",
    async (analyticsEnabled) => {
      const result = resultWithFindings(["critical", "high", "medium", "low"]);
      const invocations: Array<{
        args: readonly string[];
        directory: string | undefined;
        prompt: string | undefined;
      }> = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [
          "scan",
          "../other/repository",
          "--patch",
          "--codex",
          `analytics.enabled=${analyticsEnabled}`,
          "--codex",
          "features.goals=false",
          "--patch-severity",
          "high",
          "--fail-on-severity",
          "high",
          "--json",
        ],
        {
          result,
          onCodex: (args, output) => {
            invocations.push({
              args,
              directory: output?.appServer?.directory,
              prompt: output?.appServer?.prompt,
            });
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
      ]);
      expect(invocations).toHaveLength(2);
      for (const invocation of invocations) {
        expect(invocation.args[0]).toBe("app-server");
        expect(invocation.args).toContain(
          `analytics.enabled=${analyticsEnabled}`,
        );
        expect(invocation.args).not.toContain("features.goals=false");
        expect(invocation.directory).toBe(
          resolve(CURRENT_REPOSITORY, "../other/repository"),
        );
        expect(invocation.prompt).toContain("Return exactly one JSON object");
      }
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        manifest: result.manifest,
        findings: result.findings,
        patchSeverity: "high",
        patches: [
          { occurrenceId: "occ_1", status: "verified" },
          { occurrenceId: "occ_2", status: "verified" },
        ],
      });
      expect(outcome.stderr).toContain("Patching 2 confirmed findings...");
    },
  );

  test("continues with separate patch tasks when one finding fails", async () => {
    const directory = await repositories.create("separate-patch-tasks-");
    const result = resultWithFindings(["critical", "high", "medium"]);
    const tasks: string[] = [];
    const outcome = await runWorkflow(["scan", "--patch", "--json"], {
      result,
      currentDirectory: directory,
      onCodex: (args, output) => {
        expect(args[0]).toBe("app-server");
        const [finding] = JSON.parse(
          output!.appServer!.prompt.split("\n").at(-1)!,
        ) as Finding[];
        tasks.push(finding!.occurrenceId);
        if (finding!.occurrenceId === "occ_2") return 1;
        completePatches(args, output);
        return 0;
      },
    });

    expect(tasks).toEqual(["occ_1", "occ_2", "occ_3"]);
    expect(outcome.exitCode).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [
        { occurrenceId: "occ_1", status: "verified" },
        {
          occurrenceId: "occ_2",
          status: "failed",
          reason: "Patch command exited with status 1.",
        },
        { occurrenceId: "occ_3", status: "verified" },
      ],
    });
  });

  test.each(["synthetic.provider", "openai"])(
    "preserves %s command-provider authentication when patching after a scan",
    async (provider) => {
      const home = join(tmpdir(), "synthetic-auth-home");
      let providerOverride: string | undefined;
      const outcome = await runWorkflow(
        [
          "scan",
          "--patch",
          "--auth",
          "api-key",
          "--json",
          "--codex",
          `model_provider=${JSON.stringify(provider)}`,
          "--codex",
          `model_providers={${JSON.stringify(provider)}={name="Synthetic",auth={command="./synthetic-auth",args=["--json"]}}}`,
        ],
        {
          result: resultWithFindings(["high"]),
          environment: {
            CODEX_HOME: home,
          },
          onCodex: (args, output) => {
            providerOverride = args.find((arg) =>
              arg.startsWith("model_providers="),
            );
            expect(output?.modelProvider).toBe(provider);
            expect(output?.codexOverrides).toMatchObject({
              model_providers: {
                [provider]: {
                  auth: {
                    command: "./synthetic-auth",
                    args: ["--json"],
                  },
                },
              },
            });
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(parseToml(providerOverride!)).toEqual({
        model_providers: {
          [provider]: {
            name: "Synthetic",
            auth: { command: "./synthetic-auth", args: ["--json"], cwd: home },
          },
        },
      });
    },
  );

  test("passes the scan model, provider, and selected authentication to patching", async () => {
    const result = resultWithFindings(["high"]);
    let invocation: readonly string[] = [];
    let authentication: string | undefined;
    const chatgpt = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "chatgpt",
        "--model",
        "gpt-5.6-terra",
        "--effort",
        "high",
        "--json",
      ],
      {
        result,
        environment: {
          OPENAI_API_KEY: "sk-proj-SYNTHETIC_KEY_123",
          CODEX_SECURITY_STATE_DIR: STATE_DIRECTORY,
        },
        onCodex: (args, output, selectedEnvironment) => {
          invocation = args;
          authentication = output?.auth;
          expect(selectedEnvironment?.["CODEX_SECURITY_STATE_DIR"]).toBe(
            STATE_DIRECTORY,
          );
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(chatgpt.exitCode).toBe(0);
    expect(invocation).toContain('model="gpt-5.6-terra"');
    expect(invocation).toContain('model_reasoning_effort="high"');
    expect(authentication).toBe("chatgpt");

    const attributed = await runWorkflow(
      [
        "scan",
        "--patch",
        "--auth",
        "api-key",
        "--safety-identifier",
        "synthetic-user",
        "--codex",
        'model_reasoning_effort="ultra"',
        "--json",
      ],
      {
        result,
        environment: { OPENAI_API_KEY: "synthetic-key" },
        onCodex: (args, output) => {
          invocation = args;
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(attributed.exitCode).toBe(0);
    expect(invocation).toContain('safety_identifier="synthetic-user"');
    expect(invocation).toContain('model_reasoning_effort="ultra"');

    for (const selection of [
      ["--provider", "fireworks"],
      ["--codex", 'model_provider="fireworks"'],
      [
        "--codex",
        'profile="synthetic"',
        "--codex",
        'profiles.synthetic.model_provider="fireworks"',
      ],
    ]) {
      const provider = await runWorkflow(
        [
          "scan",
          "--patch",
          ...selection,
          "--model",
          "accounts/fireworks/models/example",
          "--json",
        ],
        {
          result,
          environment: { FIREWORKS_API_KEY: "SYNTHETIC_FIREWORKS_KEY_123" },
          onCodex: (args, output) => {
            invocation = args;
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(provider.exitCode).toBe(0);
      expect(invocation).toContain('model_provider="fireworks"');
      expect(
        invocation.some(
          (argument) =>
            argument.startsWith("model_providers=") &&
            argument.includes('"env_key"="FIREWORKS_API_KEY"'),
        ),
      ).toBe(true);
    }
  });

  test("publishes only verified patch files and preserves unrelated staged changes", async () => {
    const directory = await temporaryDirectory("codex-security-patch-pr-");
    const repository = join(directory, "repository");
    const remote = join(directory, "remote.git");
    const url = "https://github.example.test/example/repository/pull/15";
    const result = resultWithFindings(["high", "medium"]);
    result.findings.findings[0]!.title = "Synthetic private finding";
    const expectedPullRequestBody = [
      "Applies verified security fixes from a completed scan.",
      "",
      "## Patch risk assessment",
      "",
      patchRiskSummary(),
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const githubCommands: string[][] = [];
    await mkdir(join(repository, "src"), { recursive: true });
    const git = repositoryGit(repository);

    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
      await writeFile(join(repository, "unrelated.ts"), "original\n");
      git("add", "--", ".");
      git("commit", "-m", "Initial synthetic checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      git("push", "--set-upstream", "origin", "main");
      await writeFile(join(repository, "unrelated.ts"), "staged separately\n");
      git("add", "--", "unrelated.ts");

      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan",
          "--severity",
          "high",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: repository,
          result,
          onWorkbench: () => savedScan(result, "scan", repository),
          onCodex: async (args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              expect(output.command).toBe("patch");
              expect(output.appServer?.sandbox).toBe("read-only");
              expect(output.appServer?.prompt).toContain(
                "<!-- codex-security:patch-risk-summary:start -->",
              );
              expect(output.appServer?.prompt).toContain(
                "<!-- codex-security:patch-risk-summary:end -->",
              );
              const artifact = JSON.parse(
                output
                  .appServer!.prompt.split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as {
                path: string;
                sourceType: string;
                changedFiles: string[];
                sha256: string;
              };
              const patch = await readFile(artifact.path);
              expect(artifact.sourceType).toBe("patch_file");
              expect(artifact.changedFiles).toEqual(["src/finding-1.ts"]);
              expect(patch.toString()).toEndWith("+fixed  \n");
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(
              join(repository, "src", "finding-1.ts"),
              "fixed  \n",
            );
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (
            command,
            args,
            workingDirectory,
            commandOptions,
          ) => {
            expect(workingDirectory).toBe(repository);
            if (command === "git") {
              return runGitRepositoryCommand(
                command,
                args,
                workingDirectory,
                commandOptions,
              );
            }
            githubCommands.push([...args]);
            if (args[1] === "list") return "";
            pullRequestArguments = args;
            return url;
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
      expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
        "src/finding-1.ts",
      );
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.ts");
      expect(git("rev-parse", "HEAD")).toBe(
        git("rev-parse", "origin/codex-security/patch-scan"),
      );
      expect(pullRequestArguments).toEqual([
        "pr",
        "create",
        "--draft",
        "--head",
        "codex-security/patch-scan",
        "--title",
        "fix: patch verified security findings",
        "--body",
        expectedPullRequestBody,
      ]);
      expect(
        git(
          "config",
          "--get",
          "branch.codex-security/patch-scan.codexSecurityPatchPullRequestBody",
        ),
      ).toBe(expectedPullRequestBody);
      expect(pullRequestArguments.at(-1)).not.toContain("schemaVersion");
      expect(pullRequestArguments.at(-1)).not.toContain(
        "codex-security:patch-risk-summary",
      );
      expect(JSON.stringify(pullRequestArguments)).not.toContain(
        "Synthetic private finding",
      );
      expect(githubCommands.some((args) => args[1] === "comment")).toBe(false);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        pullRequest: { branch: "codex-security/patch-scan", url },
        patchRisk: { report: patchRiskReport() },
      });
      expect(outcome.stdout).not.toContain("codex-security:patch-risk-summary");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["github", "push"],
    ["github", "create"],
    ["gitlab", "push"],
    ["gitlab", "create"],
  ])(
    "resumes %s publication after %s fails without patching again",
    async (provider, failure) => {
      const directory = await temporaryDirectory("codex-security-pr-retry-");
      const repository = join(directory, "repository");
      const remote = join(directory, "remote.git");
      const branch = "codex-security/patch-scan-1";
      const gitlab = provider === "gitlab";
      const origin = "https://gitlab.com/example/subgroup/repository.git";
      const url = gitlab
        ? "https://gitlab.com/example/subgroup/repository/-/merge_requests/16"
        : "https://github.example.test/example/repository/pull/16";
      const result = resultWithFindings(["high"]);
      let modelCalls = 0;
      let pushCalls = 0;
      let created = 0;
      let failOnce = true;
      let publishedUrl = "";
      await mkdir(join(repository, "src"), { recursive: true });
      const git = repositoryGit(repository);

      try {
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("config", "commit.gpgsign", "false");
        await writeFile(join(repository, "src", "finding-1.ts"), "unsafe\n");
        await writeFile(join(repository, "unrelated.ts"), "original\n");
        git("add", ".");
        git("commit", "-m", "Initial synthetic checkout");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        git("push", "--set-upstream", "origin", "main");

        const fixtures: Parameters<typeof dependencies>[0] = {
          currentDirectory: repository,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onCodex: async (args, output) => {
            modelCalls += 1;
            await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (gitlab && args.join(" ") === "remote get-url origin")
                return origin;
              if (args[0] === "push") {
                pushCalls += 1;
                if (failure === "push" && failOnce) {
                  failOnce = false;
                  throw new Error("Synthetic push failure");
                }
              }
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            expect(command).toBe(gitlab ? "glab" : "gh");
            if (!gitlab && args[0] === "repo")
              return args[1] === "set-default"
                ? "example/repository"
                : JSON.stringify({ id: "R_synthetic", url });
            if (args[1] === "list") {
              if (!publishedUrl) return "";
              const request = {
                url: publishedUrl,
                head: git("rev-parse", `refs/heads/${branch}`),
                state: gitlab ? "opened" : "OPEN",
              };
              return JSON.stringify(
                gitlab
                  ? request
                  : [{ ...request, repositoryId: "R_synthetic" }],
              );
            }
            expect(args[1]).toBe("create");
            if (failure === "create" && failOnce) {
              failOnce = false;
              throw new Error("Synthetic PR service failure");
            }
            created += 1;
            publishedUrl = url;
            return url;
          },
        };

        const first = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          fixtures,
        );
        expect(first.exitCode).toBe(2);
        expect(first.stderr).toContain(`patch --resume-pr ${branch}`);
        const commit = git("rev-parse", "HEAD");
        expect(
          git("config", "--get", `branch.${branch}.codexSecurityPatchCommit`),
        ).toBe(commit);
        if (failure === "create") {
          expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        }
        await writeFile(join(repository, "unrelated.ts"), "later local work\n");

        const retry = await runWorkflow(
          ["patch", "--resume-pr", branch, "--json"],
          fixtures,
        );
        expect(retry.exitCode).toBe(0);
        expect(JSON.parse(retry.stdout)).toEqual({
          pullRequest: { branch, url },
        });
        expect(modelCalls).toBe(1);
        expect(created).toBe(1);
        expect(git("rev-parse", "HEAD")).toBe(commit);
        expect(git("rev-parse", `origin/${branch}`)).toBe(commit);
        expect(git("diff", "--name-only")).toBe("unrelated.ts");

        const pushes = pushCalls;
        const repeated = await runWorkflow(
          ["patch", "--resume-pr", branch],
          fixtures,
        );
        expect(repeated.exitCode).toBe(0);
        expect(created).toBe(1);
        expect(pushCalls).toBe(pushes);
        expect(modelCalls).toBe(1);
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("refuses to resume a missing or changed patch commit", async () => {
    for (const saved of ["", "saved-commit"]) {
      const onCodex = mock<() => number>().mockReturnValue(0);
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1"],
        {
          onCodex,
          onRepositoryCommand: (command, args) => {
            expect(command).toBe("git");
            return args[0] === "config" ? saved : "changed-commit";
          },
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        saved ? "changed since verification" : "No verified patch commit",
      );
      expect(onCodex).toHaveBeenCalledTimes(0);
    }
  });

  test("rejects new patch inputs when resuming publication", async () => {
    for (const input of [
      ["--scan", "scan-1"],
      ["--model", "gpt-6-astra"],
      ["--linear-issue", "SEC-123"],
      ["--create-pr"],
      ["--assess-patch-risk"],
      ["--validation-prompt-file", "validation.md"],
      ["--external-sandbox"],
      ["occ_1"],
    ]) {
      const onCodex = mock<() => number>().mockReturnValue(0);
      const onRepositoryCommand = mock<() => string>().mockReturnValue("");
      const outcome = await runWorkflow(
        ["patch", "--resume-pr", "codex-security/patch-scan-1", ...input],
        {
          onCodex,
          onRepositoryCommand,
        },
      );
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain("--resume-pr cannot be combined");
      expect(onCodex).not.toHaveBeenCalled();
      expect(onRepositoryCommand).not.toHaveBeenCalled();
    }
  });

  test.each(["--assess-patch-risk", "--create-pr"])(
    "retains actual edits when saved patch scope validation fails for %s",
    async (flag) => {
      const root = await repositories.create("patch-invalid-scope-");
      const repository = join(root, "repository");
      const remote = join(root, "remote.git");
      await mkdir(repository);
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(repository, ".git/index"));
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations = [
        { path: "app.ts", startLine: 1 },
      ];
      let modelCalls = 0;
      let assessments = 0;
      const writes: string[] = [];
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", flag, "--json"],
        {
          currentDirectory: repository,
          onWorkbench: () => savedScan(result, "scan-1", repository),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (
              args.some((arg) =>
                ["switch", "checkout", "commit", "push", "create"].includes(
                  arg,
                ),
              )
            )
              writes.push(`${command} ${args.join(" ")}`);
            return command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : "[]";
          },
          onCodex: async (_args, output) => {
            modelCalls++;
            await writeFile(join(repository, "app.ts"), "fixed\n");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["../outside.ts"],
                    verification: "Focused checks passed.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
        {
          configure: (current) => {
            current.assessPatchRisk = async () => {
              assessments++;
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        ok: false,
        applied: true,
        filesChanged: 1,
        files: ["app.ts"],
        patches: [{ status: "verified", files: ["../outside.ts"] }],
        error: {
          code: "PATCH_FAILED",
          message: "Patch files must remain inside the scanned repository.",
        },
      });
      expect(modelCalls).toBe(1);
      expect(assessments).toBe(0);
      expect(writes).toEqual([]);
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("branch", "--show-current")).toBe("main");
      expect(await readFile(join(repository, ".git/index"))).toEqual(index);
      expect(repositoryGit(remote)("for-each-ref")).toBe("");
      expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
        "fixed\n",
      );
      expect(existsSync(join(root, "outside.ts"))).toBe(false);
    },
  );

  test("does not publish blocked, unchanged, or repository-external patches", async () => {
    const directory = await repositories.create("patch-unpublishable-");
    for (const status of ["blocked", "no_change", "outside"] as const) {
      let commandStarted = false;
      const outcome = await runWorkflow(
        ["scan", "--patch", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: status === "outside" ? "verified" : status,
                    files: status === "outside" ? ["../outside.ts"] : [],
                    ...(status === "blocked"
                      ? { reason: "A required service is unavailable." }
                      : { verification: "Focused checks pass." }),
                  },
                ],
              }),
            );
            return 0;
          },
          onRepositoryCommand: (command, args) => {
            if (command === "git" && args.includes("--absolute-git-dir"))
              return directory;
            commandStarted ||=
              (command !== "git" && args[1] !== "list") ||
              ["checkout", "commit", "push"].includes(args[0]!);
            return status === "outside" && args.includes("--name-only")
              ? "src/finding-1.ts\0"
              : "";
          },
        },
      );

      expect(commandStarted).toBe(false);
      expect(outcome.exitCode).toBe(
        status === "blocked" ? 1 : status === "outside" ? 2 : 0,
      );
      expect(JSON.parse(outcome.stdout)).not.toHaveProperty("pullRequest");
      if (status === "outside") {
        expect(outcome.stderr).toContain(
          "Patch files must remain inside the scanned repository.",
        );
      }
    }
  });

  test("keeps completed scan results when publication preflight fails", async () => {
    const outcome = await runWorkflow(
      ["scan", "--patch", "--create-pr", "--json"],
      {
        result: resultWithFindings(["high"]),
        onRepositoryCommand: (command, args) => {
          if (command === "gh")
            throw new Error("GitHub authentication failed.");
          return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
        },
      },
    );

    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("GitHub authentication failed.");
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      patches: [],
    });
  });

  test.each([
    ["blocked", undefined],
    ["failed", undefined],
    ["malformed", undefined],
    ["verified", undefined],
    ["verified", " \n\t "],
    ["no_change", undefined],
    ["no_change", " \n\t "],
  ] as const)(
    "keeps %s patch results with verification %j unresolved",
    async (status, verification) => {
      const reason = "The requested check did not complete.";
      const outcome = await runWorkflow(
        ["scan", "--patch", "--fail-on-severity", "high", "--json"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (_args, output) => {
            output?.stdout.write(
              status === "malformed"
                ? "The patch is probably fixed."
                : JSON.stringify({
                    patches: [
                      {
                        occurrenceId: "occ_1",
                        status,
                        files: [],
                        verification,
                        ...(status === "blocked" || status === "failed"
                          ? { reason }
                          : {}),
                      },
                    ],
                  }),
            );
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(status === "blocked" ? 1 : 2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        patches: [
          {
            occurrenceId: "occ_1",
            status: status === "blocked" ? "blocked" : "failed",
            reason:
              status === "verified" || status === "no_change"
                ? "Patch verification was not reported."
                : status === "malformed"
                  ? "Patch results were not valid JSON."
                  : reason,
          },
        ],
      });
    },
  );

  test("does not patch incomplete scans or allow patching during a dry run", async () => {
    const onCodex = mock<() => number>().mockReturnValue(0);
    const incomplete = resultWithFindings(["high"]);
    incomplete.coverage.completeness = "partial";
    const partial = await runWorkflow(["scan", "--patch", "--json"], {
      result: incomplete,
      onCodex,
    });
    expect(partial.exitCode).toBe(2);
    expect(onCodex).not.toHaveBeenCalled();

    const dryRun = await runWorkflow(["scan", "--patch", "--dry-run"]);
    expect(dryRun.exitCode).toBe(2);
    expect(dryRun.stderr).toContain(
      "--patch cannot be combined with --dry-run",
    );
  });

  test("reviews full findings and honors individual interactive patch selections", async () => {
    for (const [argv, selection, expected] of [
      [
        ["scan"],
        { severity: "medium", occurrenceIds: ["occ_1", "occ_2"] },
        ["occ_1", "occ_2"],
      ],
      [
        ["scan", "--patch"],
        { severity: "low", occurrenceIds: ["occ_1", "occ_3"] },
        ["occ_1", "occ_3"],
      ],
      [["scan"], null, []],
    ] as const) {
      let reviewed: readonly Finding[] = [];
      const patched: Finding[] = [];
      const outcome = await runWorkflow(
        [...argv],
        {
          result: resultWithFindings(["high", "medium", "low"]),
          onCodex: (args, output) => {
            patched.push(...completePatches(args, output));
            return 0;
          },
        },
        {
          interactive: true,
          configure: (value) => {
            value.patchEditor = async (repository, candidates) => {
              expect(repository).toBe(CURRENT_REPOSITORY);
              reviewed = candidates;
              return selection === null
                ? null
                : {
                    severity: selection.severity,
                    occurrenceIds: [...selection.occurrenceIds],
                  };
            };
          },
        },
      );
      expect(outcome.exitCode).toBe(0);
      expect(reviewed.map(({ occurrenceId }) => occurrenceId)).toEqual([
        "occ_1",
        "occ_2",
        "occ_3",
      ]);
      expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
        ...expected,
      ]);
      if (argv[1] === "--patch") {
        expect(outcome.stderr).not.toContain(
          "Review and patch these findings?",
        );
      } else {
        expect(outcome.stderr).toContain("Review and patch these findings?");
      }
    }
  });

  test("shows normal scan findings before optionally opening patch review", async () => {
    for (const review of [true, false]) {
      let opened = false;
      let patched = false;
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(["high"]),
          onCodex: (args, output) => {
            patched = true;
            completePatches(args, output);
            return 0;
          },
        },
        {
          interactive: true,
          review,
          configure: (value) => {
            value.patchEditor = async () => {
              opened = true;
              return { severity: "high", occurrenceIds: ["occ_1"] };
            };
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr.indexOf("FINDINGS")).toBeLessThan(
        outcome.stderr.indexOf("Review and patch these findings? (y/N)"),
      );
      expect(opened).toBe(review);
      expect(patched).toBe(review);
    }
  });

  test("does not offer patch review when there are no actionable findings", async () => {
    for (const severities of [[], ["informational"]] as const) {
      const confirmPatchReview = mock(resolving(true));
      const patchEditor = mock(resolving(null));
      const outcome = await runWorkflow(
        ["scan"],
        {
          result: resultWithFindings(severities),
          environment: { NO_COLOR: "1" },
        },
        {
          interactive: true,
          configure: (value) => {
            value.confirmPatchReview = confirmPatchReview;
            value.patchEditor = patchEditor;
          },
        },
      );

      expect(outcome.exitCode).toBe(0);
      expect(outcome.stderr).toContain(`FINDINGS  ${severities.length}`);
      expect(outcome.stderr).not.toContain("Review and patch these findings?");
      expect(confirmPatchReview).not.toHaveBeenCalled();
      expect(patchEditor).not.toHaveBeenCalled();
    }
  });

  test("sanitizes interactive patch status", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    finding.title = "\u001B[31mUnsafe title\u001B[0m\nforged line";
    finding.locations[0]!.path = "src/\u001B[31mquery.ts\u001B[0m";
    const outcome = await runWorkflow(
      ["scan"],
      { result },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "high",
            occurrenceIds: ["occ_1"],
          });
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(outcome.stderr).toContain("VERIFIED  Unsafe title forged line");
    expect(outcome.stderr).not.toContain("Unsafe title\u001B[0m");
  });

  test("passes separate instructions only for interactively selected findings", async () => {
    const prompts: string[] = [];
    const patched: Finding[] = [];
    const outcome = await runWorkflow(
      ["scan"],
      {
        result: resultWithFindings(["high", "medium", "low"]),
        onCodex: (args, output) => {
          prompts.push(output!.appServer!.prompt);
          patched.push(...completePatches(args, output));
          return 0;
        },
      },
      {
        interactive: true,
        configure: (value) => {
          value.patchEditor = async () => ({
            severity: "low",
            occurrenceIds: ["occ_1", "occ_3"],
            instructions: {
              occ_1: "Reuse the shared validator.\nDo not add a dependency.",
              occ_2: "This unselected guidance must not reach the model.",
              occ_3: "Preserve the public API.",
            },
          });
        },
      },
    );

    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_3",
    ]);

    expect(prompts).toHaveLength(2);
    for (const [index, prompt] of prompts.entries()) {
      const lines = prompt.split("\n");
      const instructionsLine = lines.findIndex((line) =>
        line.startsWith("Follow these user-provided patch instructions"),
      );
      expect(instructionsLine).toBeGreaterThan(-1);
      expect(JSON.parse(lines[instructionsLine + 1]!)).toEqual(
        index === 0
          ? { occ_1: "Reuse the shared validator.\nDo not add a dependency." }
          : { occ_3: "Preserve the public API." },
      );
      expect(prompt).not.toContain("This unselected guidance");
    }
    expect(patched[0]).not.toHaveProperty("instructions");
  });

  test("creates a draft pull request when selected in the interactive review", async () => {
    const directory = await temporaryDirectory(
      "patch-interactive-publication-",
    );
    try {
      let published = false;
      const url = "https://github.example.test/example/repository/pull/13";
      const outcome = await runWorkflow(
        ["scan"],
        {
          currentDirectory: directory,
          result: resultWithFindings(["high"]),
          onRepositoryCommand: (command, args) => {
            published ||= command === "gh" && args[1] === "create";
            if (
              args.includes("--show-toplevel") ||
              args.includes("--absolute-git-dir")
            )
              return directory;
            if (args.includes("--cached")) return "";
            return command === "gh" && args[1] === "create"
              ? url
              : args.includes("--name-only")
                ? "src/finding-1.ts\0"
                : "";
          },
        },
        {
          interactive: true,
          configure: (value) => {
            value.patchEditor = async () => ({
              severity: "high",
              occurrenceIds: ["occ_1"],
              createPullRequest: true,
            });
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(published).toBe(true);
      expect(outcome.stderr).toContain(`Pull request: ${url}`);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("patches a saved scan by severity and supports structured output", async () => {
    const result = resultWithFindings(["high", "medium"]);
    let patched: Finding[] = [];
    let workingDirectory = "";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--severity", "high", "--json"],
      {
        onWorkbench: (args): JsonObject => {
          expect(args).toEqual(["get-scan", "--scan-id", "scan-1"]);
          return savedScan(result);
        },
        onCodex: (args, output) => {
          workingDirectory = output!.appServer!.directory;
          patched = completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(0);
    expect(workingDirectory).toBe(SAVED_REPOSITORY);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual(["occ_1"]);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      scanId: "scan-1",
      repository: SAVED_REPOSITORY,
      patches: [{ occurrenceId: "occ_1", status: "verified" }],
    });
  });

  test.each([
    [
      "https://github.example.test/example/repository.git",
      { GITLAB_HOST: "gitlab.com" },
      "gh",
    ],
    ["https://gitlab.com/example/subgroup/repository.git", {}, "glab"],
    ["git@gitlab.com:example/subgroup/repository.git", {}, "glab"],
    ["ssh://git@gitlab.com:2222/example/subgroup/repository.git", {}, "glab"],
    [
      "git@gitlab.example.test:example/subgroup/repository.git",
      { GITLAB_HOST: "gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_HOST: "https://gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GITLAB_URI: "https://gitlab.example.test" },
      "glab",
    ],
    [
      "https://gitlab.example.test/example/repository.git",
      { GL_HOST: "gitlab.example.test" },
      "glab",
    ],
    ["https://gitlab.example.test/example/repository.git", {}, "gh"],
  ] as const)(
    "publishes saved-finding patches for origin %s with environment %j using %s",
    async (origin, environment, client) => {
      const directory = await repositories.create(
        "patch-provider-publication-",
      );
      const result = resultWithFindings(["high"]);
      const url =
        client === "glab"
          ? "https://gitlab.example.test/example/repository/-/merge_requests/14"
          : "https://github.example.test/example/repository/pull/14";
      const publicationCommands: Array<readonly string[]> = [];
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--assess-patch-risk",
          "--create-pr",
          "--json",
        ],
        {
          environment,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, target) => {
            expect(target).toBe(directory);
            if (command === "git") {
              if (
                args.includes("--show-toplevel") ||
                args.includes("--absolute-git-dir")
              )
                return directory;
              if (args.includes("--cached")) return "";
              if (args[0] === "remote") {
                expect([
                  ["remote", "get-url", "--push", "--all", "origin"],
                  ["remote", "get-url", "origin"],
                ]).toContainEqual([...args]);
                return origin;
              }
              return args.includes("--name-only") ? "src/finding-1.ts\0" : "";
            }
            expect(command).toBe(client);
            publicationCommands.push(args);
            return args[1] === "create" ? url : "";
          },
        },
        {
          configure: (current) => {
            Object.assign(current, {
              assessPatchRisk: async () => patchRiskAssessment(),
            });
          },
        },
      );

      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(publicationCommands.map((args) => args[1])).toEqual([
        "list",
        "list",
        "create",
      ]);
      if (client === "glab") {
        expect(publicationCommands.slice(1)).toEqual([
          [
            "mr",
            "list",
            "--all",
            "--source-branch",
            "codex-security/patch-scan-1",
            "--output",
            "json",
            "--jq",
            ".[0] | select(. != null) | {url: .web_url, head: .sha, state}",
            "--repo",
            origin,
          ],
          [
            "mr",
            "create",
            "--draft",
            "--head",
            origin,
            "--source-branch",
            "codex-security/patch-scan-1",
            "--title",
            "fix: patch verified security findings",
            "--description",
            expect.stringContaining(patchRiskSummary()),
            "--yes",
            "--repo",
            origin,
          ],
        ]);
      }
      expect(outcome.stderr).toContain(
        `${client === "glab" ? "Merge" : "Pull"} request: ${url}`,
      );
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        scanId: "scan-1",
        pullRequest: { branch: "codex-security/patch-scan-1", url },
      });
    },
  );

  test.each(["patch", "scan"])(
    "escapes controls in %s pull request failures while preserving error details",
    async (command) => {
      const result = resultWithFindings(["high"]);
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr"]
          : ["scan", ".", "--patch", "--create-pr"],
        {
          result,
          onWorkbench: () => savedScan(result),
          onRepositoryCommand: throwing(
            "GitHub rejected github_pat_SYNTHETIC_SECRET_123\u001b[2J\ncontinued",
          ),
        },
      );

      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toContain(
        "GitHub rejected github_pat_SYNTHETIC_SECRET_123 [2J continued\n",
      );
      expect(outcome.stderr).not.toContain("\u001b");
    },
  );

  test("resolves a finding identifier to its saved scan and checkout", async () => {
    const result = resultWithFindings(["high"]);
    const finding = result.findings.findings[0]!;
    const calls: Array<readonly string[]> = [];
    let patched: Finding[] = [];
    const outcome = await runWorkflow(["patch", "occ_1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-global-findings") {
          return {
            findings: [
              { ...finding, scanId: "scan-1" } as unknown as JsonObject,
            ],
          };
        }
        return savedScan(result);
      },
      onCodex: (args, output) => {
        patched = completePatches(args, output);
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-global-findings", "--status", "open"],
      ["get-scan", "--scan-id", "scan-1", "--occurrence-id", "occ_1"],
    ]);
    expect(patched).toEqual([finding]);
  });

  test("selects the latest completed scan for the current repository", async () => {
    const result = resultWithFindings(["high"]);
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "latest"], {
      currentDirectory: SAVED_REPOSITORY,
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "list-scans") {
          return { scans: [{ scanId: "scan-complete" }] };
        }
        return savedScan(result, "scan-complete");
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(calls).toEqual([
      ["list-scans", "--repository", SAVED_REPOSITORY, "--status", "complete"],
      ["get-scan", "--scan-id", "scan-complete"],
    ]);
  });

  test("reads every page when saved scan findings are truncated", async () => {
    const result = resultWithFindings(["high", "medium"]);
    const patched: Finding[] = [];
    const calls: Array<readonly string[]> = [];
    const outcome = await runWorkflow(["patch", "--scan", "scan-1"], {
      onWorkbench: (args): JsonObject => {
        calls.push(args);
        if (args[0] === "get-scan") {
          return {
            scan: {
              scanId: "scan-1",
              targetPath: SAVED_REPOSITORY,
              findings: [],
              findingsTruncated: true,
            },
          };
        }
        const secondPage = args.includes("--offset");
        return {
          findingsPage: {
            findings: [
              result.findings.findings[
                secondPage ? 1 : 0
              ] as unknown as JsonObject,
            ],
            nextOffset: secondPage ? null : 1,
          },
        };
      },
      onCodex: (args, output) => {
        patched.push(...completePatches(args, output));
        return 0;
      },
    });
    expect(outcome.exitCode).toBe(0);
    expect(patched.map(({ occurrenceId }) => occurrenceId)).toEqual([
      "occ_1",
      "occ_2",
    ]);
    expect(calls).toEqual([
      ["get-scan", "--scan-id", "scan-1"],
      ["list-findings", "--scan-id", "scan-1", "--status", "open"],
      [
        "list-findings",
        "--scan-id",
        "scan-1",
        "--status",
        "open",
        "--offset",
        "1",
      ],
    ]);
  });

  test("rejects a severity threshold without an explicit patch request", async () => {
    const outcome = await runWorkflow(["scan", "--patch-severity", "high"]);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("--patch-severity requires --patch");
  });

  test("requires patching and a clean supplied-issue checkout before creating a pull request", async () => {
    const scan = await runWorkflow(["scan", "--create-pr"]);
    expect(scan.exitCode).toBe(2);
    expect(scan.stderr).toContain("--create-pr requires --patch");

    const directory = await temporaryDirectory("codex-security-dirty-pr-");
    const git = repositoryGit(directory);
    try {
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", "--", "app.ts");
      git("commit", "-m", "Initial synthetic checkout");
      await writeFile(join(directory, "app.ts"), "user change\n");
      const onCodex = mock<() => number>().mockReturnValue(0);
      const literal = await runWorkflow(
        ["patch", "Synthetic security issue", "--create-pr"],
        {
          currentDirectory: directory,
          onCodex,
          onRepositoryCommand: runGitRepositoryCommand,
        },
      );
      expect(literal.exitCode).toBe(2);
      expect(literal.stderr).toContain(
        "Pull request creation for supplied issues requires a clean working tree.",
      );
      expect(onCodex).not.toHaveBeenCalled();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test.each([
    ["gh", "bin", "component"],
    ["glab", "node_modules/.bin", "component"],
    ["gh", "bin", "external explicit worktree"],
    ["glab", "node_modules/.bin", "external configured worktree"],
  ])(
    "keeps the invocation and selected worktree outside the trusted %s PATH: %s %s",
    async (provider, path, kind) => {
      const root = await temporaryDirectory("codex-security-provider-path-");
      const repository = join(root, "repository");
      const external = kind!.startsWith("external");
      const component = external
        ? join(root, "invocation")
        : join(repository, "component");
      const repositoryTools = join(external ? component : repository, path!);
      const trustedTools = join(root, "trusted");
      const marker = join(root, "provider.json");
      const preload = join(root, "provider.mjs");
      const node = execFileSync("node", ["-p", "process.execPath"], {
        encoding: "utf8",
      }).trim();
      const executable = `${provider}${process.platform === "win32" ? ".exe" : ""}`;
      try {
        await mkdir(component, { recursive: true });
        await mkdir(repository, { recursive: true });
        await mkdir(repositoryTools, { recursive: true });
        await mkdir(trustedTools);
        for (const directory of [repositoryTools, trustedTools])
          await copyFile(node, join(directory, executable));
        await writeFile(
          preload,
          `
import { writeFileSync } from "node:fs";
import { basename } from "node:path";
if (["pr", "mr"].includes(basename(process.argv[1] ?? ""))) {
  writeFileSync(${JSON.stringify(marker)}, JSON.stringify({ executable: process.execPath, credential: process.env.GH_TOKEN === "synthetic-token" }));
  process.exit(17);
}
`,
        );
        await writeFile(join(component, "app.ts"), "original\n");
        if (external) await writeFile(join(repository, "app.ts"), "original\n");
        await writeFile(
          join(repository, ".gitignore"),
          "bin/\nnode_modules/\n",
        );
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
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
            `import { main } from ${JSON.stringify(new URL("../src/cli.ts", import.meta.url).href)}; process.exitCode = await main(["patch", "Synthetic issue", "--create-pr"]);`,
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
              NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
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
          credential: true,
        });
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );

  test.each(["ordinary", "relative Git environment"])(
    "publishes saved component findings with the selected Git cwd: %s",
    async (kind) => {
      const directory = await temporaryDirectory("patch-saved-component-cwd-");
      const repository = join(directory, "repository");
      const component = join(repository, "component");
      const remote = join(directory, "remote.git");
      const git = repositoryGit(repository);
      const gitEnvironment =
        kind === "relative Git environment"
          ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
          : {};
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations = [
        { path: "app.ts", startLine: 1 },
      ];
      try {
        await mkdir(component, { recursive: true });
        await writeFile(join(component, "app.ts"), "original\n");
        await writeFile(join(repository, ".gitignore"), "local.env\n");
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        git("add", ".");
        git("commit", "-m", "Synthetic initial checkout");
        await writeFile(
          join(repository, "local.env"),
          "synthetic local data\n",
        );
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
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  );

  test("keeps a staged edit when a supplied patch overlaps a component file", async () => {
    const directory = await temporaryDirectory(
      "patch-staged-component-overlap-",
    );
    const repository = join(directory, "repository");
    const component = join(repository, "component");
    const remote = join(directory, "remote.git");
    const git = repositoryGit(repository);
    try {
      await mkdir(component, { recursive: true });
      await writeFile(join(component, "app.ts"), "original\n");
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("add", ".");
      git("commit", "-m", "Synthetic initial checkout");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      await writeFile(join(component, "app.ts"), "staged edit\n");
      git("add", "component/app.ts");
      await writeFile(join(component, "app.ts"), "original\n");
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
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
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Cannot publish files with uncommitted changes before patching",
      );
      expect(git("show", ":component/app.ts")).toBe("staged edit");
      expect(git("branch", "--show-current")).toBe("main");
      expect(await readFile(join(component, "app.ts"), "utf8")).toBe("fixed\n");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});

test.each(["linked", "explicit"])(
  "preserves the selected worktree boundary for an external %s validation prompt",
  async (kind) => {
    const root = await temporaryDirectory("patch-external-validation-");
    const repository = join(root, "repository");
    const invocation = join(root, "invocation");
    const outside = join(root, "outside");
    const gitEnvironment = {
      GIT_DIR: join(repository, ".git"),
      GIT_WORK_TREE: repository,
    };
    let started = false;
    try {
      for (const directory of [repository, invocation, outside])
        await mkdir(directory);
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      await writeFile(
        join(outside, "validation.md"),
        "Run the synthetic regression test.",
      );
      await symlink(
        outside,
        join(repository, "validation"),
        process.platform === "win32" ? "junction" : "dir",
      );
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--assess-patch-risk",
          "--validation-prompt-file",
          join(
            kind === "linked" ? join(repository, "validation") : outside,
            "validation.md",
          ),
          "--json",
        ],
        {
          currentDirectory: invocation,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, directory, options) =>
            runGitRepositoryCommand(command, args, directory, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: (_args, output) => {
            started = true;
            expect(output?.appServer?.prompt).toContain(
              "Run the synthetic regression test.",
            );
            return 1;
          },
        },
      );
      expect(started, outcome.stderr).toBe(kind === "explicit");
      if (kind === "linked")
        expect(outcome.stderr).toContain("directory links outside");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each([
  "ordinary",
  "removed component",
  "explicit Git environment",
  "removed component with explicit Git environment",
])(
  "preserves disposable assessment worktrees and explicit Git settings: %s",
  async (kind) => {
    const root = await temporaryDirectory("patch-disposable-assessment-");
    const repository = join(root, "repository");
    const component = join(repository, "sub");
    const disposable = join(root, "disposable");
    const gitEnvironment = kind.includes("explicit Git environment")
      ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
      : {};
    try {
      await mkdir(component, { recursive: true });
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(component, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      git("worktree", "add", "--detach", disposable, "HEAD");
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: component,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, directory, options) =>
            runGitRepositoryCommand(command, args, directory, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output, environment) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const selected = gitText(
                ["-C", disposable, "rev-parse", "--show-toplevel"],
                { cwd: output.appServer.directory, env: environment },
              ).trim();
              expect(resolve(selected)).toBe(
                kind.includes("explicit Git environment")
                  ? repository
                  : disposable,
              );
              output.stdout.write(patchRiskAssessment().report);
            } else {
              if (kind.startsWith("removed component"))
                await rm(component, { recursive: true });
              else await writeFile(join(component, "app.ts"), "fixed\n");
              output?.stdout.write("Patch complete.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

describe("patch publication integrity", () => {
  const fixtures = createTemporaryDirectories();
  afterEach(fixtures.cleanup);
  for (const publish of [false, true]) {
    test.skipIf(process.platform === "win32")(
      `assesses a saved target replaced by a committed directory link; publish=${publish}`,
      async () => {
        const root = await fixtures.create("patch-saved-directory-link-");
        const repository = join(root, "repository");
        const component = join(repository, "component");
        const scanDir = join(root, "scan");
        await mkdir(join(component, "src"), { recursive: true });
        await mkdir(scanDir, { mode: 0o700 });
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
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
        const remote = await fixtures.create("patch-saved-directory-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
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
              if (
                output?.appServer?.prompt.includes(
                  "$codex-security:assess-patch-risk",
                )
              ) {
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                ) as { path: string; changedFiles: string[] };
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
        const root = await fixtures.create("patch-directory-alias-");
        const directory = join(root, "repository");
        await mkdir(directory);
        const git = repositoryGit(directory);
        const alias = join(root, "link");
        const result = resultWithFindings(["high"]);
        await mkdir(join(directory, "src"));
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(directory, "src/finding-1.ts"), "unsafe\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const originalHead = git("rev-parse", "HEAD");
        await symlink(
          directory,
          alias,
          process.platform === "win32" ? "junction" : "dir",
        );
        const remote = await fixtures.create("patch-directory-alias-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
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
    const directory = await fixtures.create("patch-creation-failure-");
    const git = repositoryGit(directory);
    const result = resultWithFindings(["high"]);
    await mkdir(join(directory, "src"));
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(directory, "src/finding-1.ts"), "unsafe\n");
    await writeFile(join(directory, "other.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const remote = await fixtures.create("patch-creation-remote-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
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
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
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
              args[1] === "--local")
          )
            throw new Error(`Synthetic ${failure} failure`);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain(`Synthetic ${failure} failure`);
    expect(outcome.stderr).not.toContain("Retry from this repository");
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed\n",
    );
    expect(git("diff", "--cached", "--name-only")).toBe(
      failure === "checkout staged" ? "other.ts\nsrc/finding-1.ts" : "other.ts",
    );
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
        expect(git("show", ":src/finding-1.ts")).toBe("fixed");
      } else expect(git("write-tree")).toBe(index);
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
              if (args[0] === "config")
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
      const directory = await fixtures.create("patch-clean-rename-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high"]);
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
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
      const remote = await fixtures.create("patch-clean-rename-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      await writeFile(join(directory, "other.ts"), "local unrelated\n");
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
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
        },
      );
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
        const directory = await fixtures.create("patch-publication-");
        const scanned = dirty.includes("component")
          ? join(directory, "component")
          : directory;
        const renamed = dirty.startsWith("renamed");
        const git = repositoryGit(directory);
        const result = resultWithFindings(["high"]);
        await mkdir(join(scanned, "src"), { recursive: true });
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
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
        const remote = await fixtures.create("patch-publication-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          command === "patch"
            ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
            : ["scan", scanned, "--patch", "--create-pr", "--json"],
          {
            currentDirectory: scanned,
            result,
            onWorkbench: () => savedScan(result, "scan-1", scanned),
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
      const directory = await fixtures.create("patch-repeat-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-repeat-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
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
        const pushRemote = await fixtures.create("patch-repeat-push-remote-");
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
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex,
          onRepositoryCommand: (command, args, cwd, options) => {
            const selected = {
              ...options,
              environment: { ...environment, ...options?.environment },
            };
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, selected);
            if (args[0] === "repo") {
              identityCalls++;
              expect(selected.environment.GH_REPO).toBe("");
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
            expect(selected.environment.GH_REPO).toBe(environment.GH_REPO);
            expect(selected.environment.GIT_CONFIG_PARAMETERS).toBe(
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

  test.each([130, 143])(
    "retains completed and partial patch changes after exit %i",
    async (status) => {
      const directory = await fixtures.create("patch-interrupted-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high", "high"]);
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      for (const index of [1, 2])
        await writeFile(join(directory, `src/finding-${index}.ts`), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      let calls = 0;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (args, output) => {
            calls += 1;
            await writeFile(
              join(directory, `src/finding-${calls}.ts`),
              "changed\n",
            );
            if (calls === 2) return status;
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode).toBe(status);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        filesChanged: 2,
        patches: [
          { occurrenceId: "occ_1", status: "verified" },
          {
            occurrenceId: "occ_2",
            status: "failed",
            files: ["src/finding-2.ts"],
          },
        ],
      });
    },
  );

  test.each(["outer", "nested"])(
    "ignores %s build output when a repository contains a gitlink",
    async (location) => {
      const directory = await fixtures.create("patch-git-ignore-");
      const git = repositoryGit(directory);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, ".gitignore"), "build.log\n");
      const nested = join(directory, "nested");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, ".gitignore"), "build.log\n");
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(
              join(location === "outer" ? directory : nested, "build.log"),
              "build finished\n",
            );
            output?.stdout.write("No source changes were needed.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: false,
        files: [],
      });
      expect(git("status", "--porcelain")).toBe("");
    },
  );

  test.each([false, true])(
    "resolves pre-existing dirty paths from the Git root for a subdirectory scan: overlap=%j",
    async (overlap) => {
      const directory = await fixtures.create(
        "patch-subdirectory-publication-",
      );
      const git = repositoryGit(directory);
      const scanned = join(directory, "package");
      await mkdir(scanned);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "package.json"), "root original\n");
      await writeFile(join(scanned, "package.json"), "unsafe\noriginal\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const dirty = overlap ? "package/package.json" : "package.json";
      await writeFile(join(directory, dirty), "unsafe\nlocal edit\n");
      git("add", dirty);
      const originalHead = git("rev-parse", "HEAD");
      const originalIndex = git("write-tree");
      const remote = await fixtures.create("patch-subdirectory-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "package.json";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: scanned,
          onWorkbench: () => savedScan(result, "scan-1", scanned),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? ""
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (args, output) => {
            await writeFile(
              join(scanned, "package.json"),
              overlap ? "fixed\nlocal edit\n" : "fixed\noriginal\n",
            );
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(overlap ? 2 : 0);
      if (overlap) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(originalHead);
        expect(git("write-tree")).toBe(originalIndex);
        expect(git("ls-remote", "origin")).toBe("");
      } else {
        expect(git("diff", "--cached", "--name-only")).toBe("package.json");
        expect(git("diff", "--name-only", originalHead, "HEAD")).toBe(
          "package/package.json",
        );
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      }
    },
  );

  test.each([
    ["committed", "root"],
    ["uncommitted", "root"],
    ["committed", "component"],
    ["uncommitted", "component"],
    ["deinitialized", "root"],
    ["deinitialized", "component"],
    ["deinitialized and assessed", "root"],
    ["deinitialized and assessed", "component"],
  ])(
    "preserves supplied-issue submodule publication with %s changes from %s",
    async (state, invocation) => {
      const deinitialized = state.startsWith("deinitialized");
      const assessed = state.endsWith("assessed");
      const committed = state !== "uncommitted";
      const directory = await fixtures.create("patch-submodule-publication-");
      const checkout = join(directory, "checkout");
      const nested = join(checkout, "dependency");
      await mkdir(nested, { recursive: true });
      const component = join(checkout, "component");
      await mkdir(component);
      const currentDirectory =
        invocation === "component" ? component : checkout;
      const git = repositoryGit(checkout);
      const inner = repositoryGit(nested);
      for (const run of [git, inner]) {
        run("init", "--initial-branch=main");
        run("config", "user.name", "Synthetic User");
        run("config", "user.email", "synthetic@example.test");
        run("config", "commit.gpgsign", "false");
      }
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      const original = inner("rev-parse", "HEAD");
      await writeFile(join(nested, "app.ts"), "fixed\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested fix");
      const fixed = inner("rev-parse", "HEAD");
      inner("checkout", original);
      if (deinitialized) {
        git(
          "config",
          "-f",
          ".gitmodules",
          "submodule.dependency.path",
          "dependency",
        );
        git(
          "config",
          "-f",
          ".gitmodules",
          "submodule.dependency.url",
          "https://github.example.test/example/dependency.git",
        );
      }
      git("add", ".");
      if (deinitialized) git("submodule", "absorbgitdirs", "dependency");
      git("commit", "-m", "Synthetic parent baseline");
      git("config", "diff.relative", "true");
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const remote = join(directory, "remote.git");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let published = false;
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--create-pr",
          ...(assessed ? ["--assess-patch-risk"] : []),
          "--json",
        ],
        {
          currentDirectory,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, options);
            if (args[1] === "list") return "";
            published = true;
            return "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[] };
              const patch = await readFile(artifact.path, "utf8");
              expect(artifact.changedFiles).toContain("dependency/app.ts");
              expect(patch).toContain(`-Subproject commit ${original}`);
              expect(patch).toContain(`+Subproject commit ${fixed}`);
              expect(patch).toContain("-original\n+fixed\n");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            if (committed) inner("checkout", fixed);
            else await writeFile(join(nested, "app.ts"), "fixed\n");
            if (deinitialized) {
              git("add", "dependency");
              git("submodule", "deinit", "-f", "--", "dependency");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(committed ? 0 : 2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: (committed
          ? ["dependency", "dependency/app.ts"]
          : ["dependency/app.ts"]
        ).map((file) =>
          relative(currentDirectory, join(checkout, file)).split(sep).join("/"),
        ),
      });
      expect(published).toBe(committed);
      expect(assessments).toBe(assessed ? 1 : 0);
      if (committed) {
        expect(git("show", "--format=", "--name-only", "HEAD")).toBe(
          "dependency",
        );
        expect(git("rev-parse", "HEAD:dependency")).toBe(fixed);
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
        if (deinitialized)
          expect(git("submodule", "status", "--", "dependency")).toStartWith(
            "-",
          );
      } else {
        expect(outcome.stderr).toContain("submodule");
        expect(git("branch", "--show-current")).toBe("main");
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("branch", "--format=%(refname)")).toBe("refs/heads/main");
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
      }
    },
  );

  test("keeps the original branch when a verified file belongs to a nested repository", async () => {
    const directory = await fixtures.create("patch-nested-publication-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const nested = join(directory, "nested");
    await mkdir(nested);
    const inner = repositoryGit(nested);
    inner("init", "--initial-branch=main");
    inner("config", "user.name", "Synthetic User");
    inner("config", "user.email", "synthetic@example.test");
    await writeFile(join(nested, "app.ts"), "unsafe\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const remote = await fixtures.create("patch-nested-remote-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "nested/app.ts";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : "",
        onCodex: async (args, output) => {
          await writeFile(join(nested, "app.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("submodule");
    expect(git("branch", "--show-current")).toBe("main");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(git("write-tree")).toBe(index);
    expect(
      git(
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/codex-security/patch-scan-1",
      ),
    ).toBe("");
    expect(git("ls-remote", "origin")).toBe("");
    expect(await readFile(join(nested, "app.ts"), "utf8")).toBe("fixed\n");
  });

  test.skipIf(process.platform === "win32")(
    "preserves trailing spaces in worktree roots during risk assessment and publication",
    async () => {
      for (const flag of ["--assess-patch-risk", "--create-pr"]) {
        const parent = await fixtures.create("patch-space-root-");
        const directory = join(parent, "checkout ");
        await mkdir(directory);
        const git = repositoryGit(directory);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(directory, "app.ts"), "unsafe\n");
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const remote = await fixtures.create("patch-space-remote-");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", flag, "--json"],
          {
            currentDirectory: directory,
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? ""
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (_args, output) => {
              await writeFile(join(directory, "app.ts"), "fixed\n");
              output?.stdout.write("Fixed and checked.");
              return 0;
            },
          },
          {
            configure: (current) => {
              current.assessPatchRisk = async (request) => {
                expect(request.repository).toBe(directory);
                return patchRiskAssessment();
              };
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(JSON.parse(outcome.stdout)).toMatchObject({ applied: true });
      }
    },
  );

  test("patches a repository with a Git tree listing larger than one MiB", async () => {
    const directory = await fixtures.create("patch-large-tree-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    const name = "a".repeat(70);
    await Promise.all(
      Array.from({ length: 10000 }, (_, index) =>
        writeFile(
          join(directory, `${name}${index.toString().padStart(5, "0")}.ts`),
          "original\n",
        ),
      ),
    );
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: directory,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        await writeFile(join(directory, "fix.ts"), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["fix.ts"],
    });
  });

  test.each([
    "unborn",
    "nested",
    "nested environment",
    "nested objects",
    "nested shared primary objects",
    "nested read-only local primary objects",
    "nested relative primary objects",
    "nested quoted primary objects",
    "nested missing local primary objects",
    "nested missing local relative primary objects",
    "nested alternate objects",
    "nested common",
    "nested relative alternates",
    "nested component relative alternates",
    "nested quoted relative alternates",
    "nested gitfile relative alternates",
    "nested replacements",
    "nested replacement namespace",
  ])("detects local patches in %s Git repositories", async (kind) => {
    const directory = await fixtures.create("patch-git-state-");
    const selectedDirectory = kind.includes("component")
      ? join(directory, "component")
      : directory;
    if (selectedDirectory !== directory) await mkdir(selectedDirectory);
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(directory, "app.ts"), "unsafe\n");
    let path = "app.ts";
    let alternateObjects: string | undefined;
    let primaryObjects: string | undefined;
    let parentIndex = "";
    let nestedIndex = "";
    if (kind.startsWith("nested")) {
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const nested = join(selectedDirectory, "nested");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner(
        "init",
        "--initial-branch=main",
        ...(kind.includes("gitfile")
          ? ["--separate-git-dir", join(directory, ".git", "nested-metadata")]
          : []),
      );
      if (kind.includes("gitfile")) inner("config", "core.worktree", nested);
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "unsafe\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      if (kind.includes("alternates") || kind === "nested alternate objects") {
        const pool = await fixtures.create(
          kind.includes("quoted")
            ? `patch-shared${delimiter}objects-`
            : "patch-shared-objects-",
        );
        alternateObjects = join(pool, "objects");
        const gitDirectory = inner("rev-parse", "--absolute-git-dir");
        await rename(join(gitDirectory, "objects"), alternateObjects);
        await mkdir(join(gitDirectory, "objects"));
        expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
        if (kind.includes("relative"))
          alternateObjects = relative(directory, alternateObjects);
        if (kind.includes("quoted"))
          alternateObjects = JSON.stringify(alternateObjects);
      }
      if (kind.includes("primary objects")) {
        const pool = await fixtures.create(
          kind.includes("quoted")
            ? `patch-shared${delimiter}primary-`
            : "patch-shared-primary-",
        );
        primaryObjects = join(pool, "objects");
        const gitDirectory = inner("rev-parse", "--absolute-git-dir");
        await rename(join(gitDirectory, "objects"), primaryObjects);
        if (!kind.includes("missing local"))
          await mkdir(join(gitDirectory, "objects"));
        if (kind.includes("read-only local"))
          await chmod(join(gitDirectory, "objects"), 0o555);
        await cp(join(directory, ".git", "objects"), primaryObjects, {
          recursive: true,
          force: false,
        });
        await rm(join(directory, ".git", "objects"), { recursive: true });
        await mkdir(join(directory, ".git", "objects"));
        expect(() => git("rev-parse", "HEAD^{tree}")).toThrow();
        expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
        parentIndex = hash(
          "sha256",
          await readFile(join(directory, ".git", "index")),
          "hex",
        );
        nestedIndex = hash(
          "sha256",
          await readFile(join(gitDirectory, "index")),
          "hex",
        );
        if (kind.includes("relative"))
          primaryObjects = relative(directory, primaryObjects);
      }
      if (kind.startsWith("nested replacement")) {
        const original = inner("rev-parse", "HEAD^{tree}");
        await writeFile(join(nested, "app.ts"), "fixed\n");
        inner("add", ".");
        const replacement = inner("write-tree");
        inner("reset", "--hard", "HEAD");
        inner("replace", original, replacement);
      }
      path = "nested/app.ts";
    }
    const gitEnvironment =
      kind === "nested environment"
        ? { GIT_DIR: ".git", GIT_WORK_TREE: directory }
        : kind === "nested objects"
          ? { GIT_OBJECT_DIRECTORY: join(directory, ".git", "objects") }
          : kind.includes("primary objects")
            ? { GIT_OBJECT_DIRECTORY: primaryObjects }
            : kind === "nested common"
              ? { GIT_COMMON_DIR: join(directory, ".git") }
              : kind.includes("alternates") ||
                  kind === "nested alternate objects"
                ? { GIT_ALTERNATE_OBJECT_DIRECTORIES: alternateObjects }
                : kind === "nested replacements"
                  ? { GIT_NO_REPLACE_OBJECTS: "1" }
                  : kind === "nested replacement namespace"
                    ? { GIT_REPLACE_REF_BASE: "refs/synthetic-replacements/" }
                    : {};
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--json"],
      {
        currentDirectory: selectedDirectory,
        onRepositoryCommand: (command, args, cwd, options) =>
          runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...gitEnvironment, ...options?.environment },
          }),
        onCodex: async (_args, output) => {
          await writeFile(join(selectedDirectory, path), "fixed\n");
          output?.stdout.write("Fixed and checked.");
          return 0;
        },
      },
      {
        configure: (current) => {
          current.environment = { ...current.environment, ...gitEnvironment };
        },
      },
    );
    if (kind.includes("missing local"))
      expect(
        existsSync(join(selectedDirectory, "nested", ".git", "objects")),
      ).toBe(false);
    if (primaryObjects !== undefined) {
      expect(
        hash("sha256", await readFile(join(directory, ".git", "index")), "hex"),
      ).toBe(parentIndex);
      expect(
        hash(
          "sha256",
          await readFile(join(selectedDirectory, "nested", ".git", "index")),
          "hex",
        ),
      ).toBe(nestedIndex);
    }
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: [
        kind === "nested component relative alternates"
          ? `component/${path}`
          : path,
      ],
    });
  });
  test.each([
    "initialized during patching",
    "initialized without edits",
    "left uninitialized",
    "already initialized with local edits",
    "shallow initialized without edits",
    "shallow initialized with edits",
    "replaced without edits",
    "replaced with edits",
    "moved with unchanged local edits",
  ])("tracks patch changes when a registered child is %s", async (state) => {
    const root = await fixtures.create("patch-submodule-initialization-");
    const repository = join(root, "repository");
    const source = join(root, "child-source");
    const child = join(repository, "dependency");
    await mkdir(repository);
    await mkdir(source);
    const git = repositoryGit(repository);
    const sourceGit = repositoryGit(source);
    for (const run of [git, sourceGit]) {
      run("init", "--initial-branch=main");
      run("config", "user.name", "Synthetic User");
      run("config", "user.email", "synthetic@example.test");
    }
    await writeFile(join(source, "app.ts"), "unsafe\noriginal\n");
    await writeFile(join(source, "HEAD"), "ordinary tracked file\n");
    sourceGit("add", ".");
    sourceGit("commit", "-m", "Synthetic child baseline");
    const originalChildHead = sourceGit("rev-parse", "HEAD");
    git(
      "-c",
      "protocol.file.allow=always",
      "submodule",
      "add",
      pathToFileURL(source).href,
      "dependency",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    const moved = state === "moved with unchanged local edits";
    const replaced = state.startsWith("replaced");
    const retained = state === "already initialized with local edits" || moved;
    const initialized = retained || replaced;
    const shallow = state.startsWith("shallow initialized");
    const changed =
      (retained && !moved) ||
      state === "initialized during patching" ||
      state === "shallow initialized with edits" ||
      state === "replaced with edits";
    if (retained)
      await writeFile(
        join(child, "app.ts"),
        (await readFile(join(child, "app.ts"), "utf8")) + "local edit\n",
      );
    else if (!initialized) git("submodule", "deinit", "-f", "--", "dependency");
    if (shallow) {
      await rm(join(repository, ".git", "modules", "dependency"), {
        recursive: true,
      });
      await writeFile(join(source, "upstream.ts"), "new upstream file\n");
      sourceGit("add", ".");
      sourceGit("commit", "-m", "Synthetic upstream change");
    }
    let expectedIndex = git("write-tree");
    const originalGitlink = git("ls-tree", "HEAD", "dependency");
    const gitTrace: unknown[] = [];
    let modelCalls = 0;
    let assessments = 0;
    let expectedContents: string | undefined;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: repository,
        onRepositoryCommand: async (command, args, cwd, options) => {
          expect(command).toBe("git");
          const directory = options?.directory ?? cwd;
          try {
            const execution = promisify(execFile)(command, [...args], {
              cwd: directory,
              env: { ...process.env, ...options?.environment },
              maxBuffer: options?.maxBuffer,
            });
            execution.child.stdin?.end(options?.input);
            const { stdout } = await execution;
            if (
              args.includes("rev-parse") &&
              ["--is-inside-git-dir", "--show-toplevel"].includes(
                args.at(-1) ?? "",
              )
            )
              gitTrace.push({ args, cwd: directory, stdout });
            return options?.trim === false ? stdout : stdout.trim();
          } catch (error) {
            const failure = error as Error & {
              code?: unknown;
              stdout?: unknown;
              stderr?: unknown;
            };
            gitTrace.push({
              args,
              cwd: directory,
              message: failure.message,
              code: failure.code,
              stdout: failure.stdout,
              stderr: failure.stderr,
            });
            throw error;
          }
        },
        onCodex: async (_args, output) => {
          modelCalls++;
          expect(
            git("submodule", "status", "--", "dependency").startsWith("-"),
          ).toBe(!initialized);
          if (!initialized && state !== "left uninitialized")
            git(
              "-c",
              "protocol.file.allow=always",
              "submodule",
              "update",
              "--init",
              ...(shallow ? ["--remote", "--depth=1"] : []),
              "--",
              "dependency",
            );
          if (replaced) {
            const replacement = join(root, "replacement-source");
            await mkdir(replacement);
            const replacementGit = repositoryGit(replacement);
            replacementGit("init", "--initial-branch=main");
            replacementGit("config", "user.name", "Synthetic User");
            replacementGit("config", "user.email", "synthetic@example.test");
            await writeFile(
              join(replacement, "app.ts"),
              "unsafe\nreplacement\n",
            );
            replacementGit("add", ".");
            replacementGit("commit", "-m", "Synthetic replacement child");
            git("rm", "-f", "--", "dependency");
            git(
              "-c",
              "protocol.file.allow=always",
              "submodule",
              "add",
              "--name",
              "replacement",
              pathToFileURL(replacement).href,
              "dependency",
            );
            expect(() =>
              repositoryGit(child)(
                "cat-file",
                "-e",
                `${originalChildHead}^{commit}`,
              ),
            ).toThrow();
          }
          if (moved) {
            const metadata = join(
              repository,
              ".git",
              "modules",
              "moved-dependency",
            );
            await rename(
              join(repository, ".git", "modules", "dependency"),
              metadata,
            );
            await writeFile(join(child, ".git"), `gitdir: ${metadata}\n`);
          }
          if (shallow) {
            const childGit = repositoryGit(child);
            expect(childGit("rev-parse", "--is-shallow-repository")).toBe(
              "true",
            );
            expect(childGit("rev-parse", "HEAD")).toBe(
              sourceGit("rev-parse", "HEAD"),
            );
            expect(() =>
              childGit("cat-file", "-e", `${originalChildHead}^{commit}`),
            ).toThrow();
          }
          if (state !== "left uninitialized") {
            expectedContents = await readFile(join(child, "app.ts"), "utf8");
            if (changed) {
              expectedContents = expectedContents.replace("unsafe", "fixed");
              await writeFile(join(child, "app.ts"), expectedContents);
            }
          }
          expectedIndex = git("write-tree");
          output?.stdout.write("Checked the synthetic patch.");
          return 0;
        },
      },
      {
        configure: (current) => {
          current.assessPatchRisk = async () => {
            assessments++;
            return patchRiskAssessment();
          };
        },
      },
    );
    const diagnostics = JSON.stringify({ outcome, modelCalls, gitTrace });
    expect(modelCalls, diagnostics).toBe(1);
    const applied = changed || shallow || replaced;
    expect(assessments, diagnostics).toBe(applied ? 1 : 0);
    expect(outcome.exitCode, diagnostics).toBe(applied ? 0 : 2);
    expect(JSON.parse(outcome.stdout), diagnostics).toMatchObject({
      applied,
      files: [
        ...(replaced ? [".gitmodules"] : []),
        ...(shallow || replaced ? ["dependency"] : []),
        ...(shallow || replaced ? ["dependency/HEAD"] : []),
        ...(changed || shallow || replaced ? ["dependency/app.ts"] : []),
        ...(shallow ? ["dependency/upstream.ts"] : []),
      ],
      ...(applied ? {} : { error: { code: "NO_PATCH_APPLIED" } }),
    });
    expect(git("write-tree")).toBe(expectedIndex);
    expect(git("ls-tree", "HEAD", "dependency")).toBe(originalGitlink);
    if (expectedContents === undefined)
      expect(git("submodule", "status", "--", "dependency")).toStartWith("-");
    else {
      expect(await readFile(join(child, "app.ts"), "utf8")).toBe(
        expectedContents,
      );
      expect(repositoryGit(child)("diff", "--name-only")).toBe(
        changed || retained ? "app.ts" : "",
      );
      if (retained) expect(expectedContents).toContain("local edit\n");
    }
  });

  test("keeps the outer executable boundary for nested patch snapshots", async () => {
    const repository = await fixtures.create("patch-nested-executable-");
    const nested = join(repository, "dependency");
    await mkdir(nested);
    const git = repositoryGit(repository);
    const inner = repositoryGit(nested);
    for (const run of [git, inner]) {
      run("init", "--initial-branch=main");
      run("config", "user.name", "Synthetic User");
      run("config", "user.email", "synthetic@example.test");
    }
    await writeFile(join(nested, "app.ts"), "original\n");
    inner("add", ".");
    inner("commit", "-m", "Synthetic nested baseline");
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    const trusted = await resolveTrustedExecutable(
      "git",
      process.env,
      repository,
    );
    expect(trusted).not.toBeNull();
    const bin = join(repository, "bin");
    await mkdir(bin);
    const repositoryGitPath = join(bin, basename(trusted!.executable));
    await copyFile(trusted!.executable, repositoryGitPath);
    await chmod(repositoryGitPath, 0o755);
    const environment = {
      ...process.env,
      PATH: [bin, process.env["PATH"]].join(delimiter),
    };
    let nestedCommands = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      onRepositoryCommand: async (command, args, cwd, options) => {
        // Exercise the same resolver used by the default command dependency.
        const selected = await resolveTrustedExecutable(
          command,
          environment,
          cwd,
        );
        expect(selected?.executable).not.toBe(repositoryGitPath);
        if (cwd === nested || args.includes(nested)) nestedCommands++;
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        await writeFile(join(nested, "app.ts"), "fixed\n");
        output?.stdout.write("Fixed and checked.");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(nestedCommands).toBeGreaterThan(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["dependency/app.ts"],
    });
  });

  test("refuses a sparse gitlink redirected outside the patch checkout", async () => {
    const directory = await fixtures.create("patch-sparse-gitlink-");
    const repository = join(directory, "repository");
    const nested = join(repository, "dependency");
    const external = join(directory, "external");
    await mkdir(nested, { recursive: true });
    await mkdir(external);
    const git = repositoryGit(repository);
    const inner = repositoryGit(nested);
    const outside = repositoryGit(external);
    for (const run of [git, inner, outside]) {
      run("init", "--initial-branch=main");
      run("config", "user.name", "Synthetic User");
      run("config", "user.email", "synthetic@example.test");
    }
    for (const [path, run] of [
      [nested, inner],
      [external, outside],
    ] as const) {
      await writeFile(join(path, "app.ts"), "original\n");
      run("add", ".");
      run("commit", "-m", "Synthetic baseline");
    }
    git("add", ".");
    git("commit", "-m", "Synthetic parent baseline");
    git("config", "core.sparseCheckout", "true");
    await writeFile(
      join(repository, ".git", "info", "sparse-checkout"),
      "/*\n!/dependency\n",
    );
    git("update-index", "--skip-worktree", "dependency");
    await rm(nested, { recursive: true });
    await symlink(
      external,
      nested,
      process.platform === "win32" ? "junction" : "dir",
    );
    const outsideFile = join(external, "uncommitted.txt");
    await writeFile(
      outsideFile,
      "Synthetic bytes outside the selected checkout\n",
    );
    const blob = outside("hash-object", outsideFile);
    const index = outside("write-tree");
    expect(() => outside("cat-file", "-e", blob)).toThrow();
    let modelCalls = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: repository,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async () => {
        modelCalls++;
        return 0;
      },
    });
    expect(() => outside("cat-file", "-e", blob)).toThrow();
    expect(outside("write-tree")).toBe(index);
    expect(modelCalls).toBe(0);
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("outside");
    expect(await readFile(outsideFile, "utf8")).toBe(
      "Synthetic bytes outside the selected checkout\n",
    );
  });

  test.each(["worktree", "metadata"])(
    "refuses a nested checkout rebound to external %s before writing objects",
    async (binding) => {
      const directory = await fixtures.create("patch-nested-binding-");
      const checkout = join(directory, "checkout");
      const nested = join(checkout, "dependency");
      const external = join(directory, "external");
      await mkdir(nested, { recursive: true });
      await mkdir(external);
      const git = repositoryGit(checkout);
      const inner = repositoryGit(nested);
      for (const run of [git, inner]) {
        run("init", "--initial-branch=main");
        run("config", "user.name", "Synthetic User");
        run("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      const outsideFile = join(external, "outside.txt");
      await writeFile(
        outsideFile,
        "Synthetic bytes outside the selected checkout\n",
      );
      const blob = git("hash-object", outsideFile);
      expect(() => inner("cat-file", "-e", blob)).toThrow();
      let objects = inner;
      if (binding === "worktree") {
        inner("config", "core.worktree", external);
      } else {
        const outside = repositoryGit(external);
        outside("init", "--initial-branch=main");
        outside("config", "user.name", "Synthetic User");
        outside("config", "user.email", "synthetic@example.test");
        outside("add", ".");
        outside("commit", "-m", "Synthetic external baseline");
        await rm(join(nested, ".git"), { recursive: true });
        await writeFile(
          join(nested, ".git"),
          `gitdir: ${join(external, ".git")}\n`,
        );
        await writeFile(
          join(nested, "app.ts"),
          "Synthetic unpublished target bytes\n",
        );
        objects = outside;
      }
      const snapshotBlob = git("hash-object", join(nested, "app.ts"));
      if (binding === "metadata")
        expect(() => objects("cat-file", "-e", snapshotBlob)).toThrow();
      let modelCalls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: checkout,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async () => {
            modelCalls++;
            return 0;
          },
        },
      );
      if (binding === "worktree")
        expect(() => inner("cat-file", "-e", blob)).toThrow();
      else expect(() => objects("cat-file", "-e", snapshotBlob)).toThrow();
      expect(modelCalls).toBe(0);
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stderr).toMatch(/worktree|metadata/u);
    },
  );

  test.each([
    ["inline", "root"],
    ["saved", "root"],
    ["saved", "component"],
  ])(
    "retains nested changed files when %s patch assessment targets a %s",
    async (kind, targetKind) => {
      const repository = await fixtures.create("patch-git-state-");
      const component = join(repository, "component");
      const nested = join(component, "nested");
      await mkdir(nested, { recursive: true });
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(component, "app.ts"), "unsafe\n");
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "unsafe\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const directory = targetKind === "root" ? repository : component;
      const path = relative(directory, join(nested, "app.ts"))
        .split(sep)
        .join("/");
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations = [{ path, startLine: 1 }];
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          ...(kind === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--assess-patch-risk",
          "--json",
        ],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onCodex: async (args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[]; sha256: string };
              const patch = await readFile(artifact.path);
              expect(artifact.changedFiles).toEqual([
                "component/nested/app.ts",
              ]);
              expect(hash("sha256", patch)).toBe(artifact.sha256);
              expect(patch.toString()).toContain(
                "diff --git a/component/nested/app.ts b/component/nested/app.ts",
              );
              expect(patch.toString()).toContain("-unsafe\n+fixed");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            expect(output?.appServer?.directory).toBe(directory);
            await writeFile(join(nested, "app.ts"), "fixed\n");
            if (kind === "saved") completePatches(args, output);
            else output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["component/nested/app.ts"],
        ...(kind === "saved" ? { patches: [{ files: [path] }] } : {}),
      });
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
    },
  );

  test.each(
    [false, true].flatMap((component) =>
      [false, true].flatMap((relativeDiff) =>
        [false, true].map((dirty) => [component, relativeDiff, dirty] as const),
      ),
    ),
  )(
    "preserves dirty rename sources with component=%j relative diff=%j dirty=%j",
    async (component, relativeDiff, dirty) => {
      const directory = await fixtures.create("patch-relative-renamed-source-");
      const git = repositoryGit(directory);
      const scanned = component ? join(directory, "component") : directory;
      await mkdir(scanned, { recursive: true });
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "diff.relative", String(relativeDiff));
      const source = join(scanned, "old.ts");
      await writeFile(source, "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      if (dirty) {
        await writeFile(source, "staged local edit\n");
        git("add", ".");
        await writeFile(source, "original\n");
      }
      const head = git("rev-parse", "HEAD");
      const index = git("write-tree");
      const remote = await fixtures.create("patch-relative-renamed-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let modelCalls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: scanned,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            modelCalls++;
            await rename(source, join(scanned, "new.ts"));
            output?.stdout.write("Synthetic rename complete.");
            return 0;
          },
        },
      );
      expect(modelCalls).toBe(1);
      expect(outcome.exitCode, outcome.stderr).toBe(dirty ? 2 : 0);
      if (dirty) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("ls-remote", "origin")).toBe("");
      } else {
        const file = component ? "component/new.ts" : "new.ts";
        expect(git("show", `HEAD:${file}`)).toBe("original");
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      }
      expect(await readFile(join(scanned, "new.ts"), "utf8")).toBe(
        "original\n",
      );
      expect(existsSync(source)).toBe(false);
    },
  );

  test.each(["ordinary", "environment", "config"])(
    "snapshots nested patches in the effective %s Git worktree",
    async (kind) => {
      const root = await fixtures.create("patch-effective-worktree-");
      const invocation = join(root, "invocation");
      const nested = join(invocation, "nested");
      const selected =
        kind === "ordinary" ? invocation : join(root, "selected");
      await mkdir(nested, { recursive: true });
      const git = repositoryGit(invocation);
      const inner = repositoryGit(nested);
      for (const run of [git, inner]) {
        run("init", "--initial-branch=main");
        run("config", "user.name", "Synthetic User");
        run("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      await writeFile(join(invocation, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      if (selected !== invocation) {
        await mkdir(selected);
        await copyFile(join(invocation, "app.ts"), join(selected, "app.ts"));
        inner("config", "core.worktree", join(selected, "nested"));
        await cp(nested, join(selected, "nested"), { recursive: true });
        if (kind === "config") git("config", "core.worktree", selected);
      }
      const gitEnvironment =
        kind === "environment" ? { GIT_WORK_TREE: selected } : {};
      const parentIndex = await readFile(join(invocation, ".git", "index"));
      const nestedIndex = await readFile(join(nested, ".git", "index"));
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: invocation,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output) => {
            await writeFile(join(selected, "app.ts"), "fixed\n");
            await writeFile(join(selected, "nested", "app.ts"), "fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["app.ts", "nested/app.ts"],
      });
      expect(await readFile(join(invocation, ".git", "index"))).toEqual(
        parentIndex,
      );
      expect(await readFile(join(nested, ".git", "index"))).toEqual(
        nestedIndex,
      );
      if (selected !== invocation) {
        expect(await readFile(join(invocation, "app.ts"), "utf8")).toBe(
          "original\n",
        );
        expect(await readFile(join(nested, "app.ts"), "utf8")).toBe(
          "original\n",
        );
      }
    },
  );

  test.each([false, true])(
    "snapshots each canonical worktree once; enclosing gitlink alias=%p",
    async (alias) => {
      const repository = await fixtures.create("patch-enclosing-alias-");
      const nested = join(repository, "dependency");
      await mkdir(nested);
      const git = repositoryGit(repository);
      const inner = repositoryGit(nested);
      for (const run of [git, inner]) {
        run("init", "--initial-branch=main");
        run("config", "user.name", "Synthetic User");
        run("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "nested original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      if (alias) {
        git("config", "core.sparseCheckout", "true");
        await writeFile(
          join(repository, ".git", "info", "sparse-checkout"),
          "/*\n!/dependency\n",
        );
        git("update-index", "--skip-worktree", "dependency");
        await rm(nested, { recursive: true });
        await symlink(
          repository,
          nested,
          process.platform === "win32" ? "junction" : "dir",
        );
      }
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: repository,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            await writeFile(join(repository, "app.ts"), "fixed\n");
            if (!alias)
              await writeFile(join(nested, "app.ts"), "nested fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(alias ? 2 : 0);
      if (alias) expect(outcome.stderr).toContain("ancestor worktree");
      else
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          applied: true,
          files: ["app.ts", "dependency/app.ts"],
        });
    },
  );
});

function repositoryGit(repository: string) {
  return (...args: string[]) =>
    execFileSync("git", args, {
      cwd: repository,
      encoding: "utf8",
      maxBuffer: Infinity,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
}

const runGitRepositoryCommand: NonNullable<
  NonNullable<Parameters<typeof dependencies>[0]>["onRepositoryCommand"]
> = (command, args, workingDirectory, options) => {
  expect(command).toBe("git");
  const result = gitText(args, {
    cwd: options?.directory ?? workingDirectory,
    env: { ...process.env, ...options?.environment },
    maxBuffer: options?.maxBuffer,
    input: options?.input,
    stdio: [options?.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  return options?.trim === false ? result : result.trim();
};

test.each(["untracked", "tracked"])(
  "keeps unrelated %s edits made during assessment out of publication",
  async (kind) => {
    const root = await temporaryDirectory("patch-assessment-publication-");
    const repository = join(root, "repository");
    const remote = join(root, "remote.git");
    const git = repositoryGit(repository);
    try {
      await mkdir(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "app.ts"), "original\n");
      if (kind === "tracked")
        await writeFile(join(repository, "user-notes.txt"), "original notes\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
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
          onRepositoryCommand: (command, args, directory, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, directory, options)
              : args[1] === "create"
                ? "https://github.example.test/example/repository/pull/17"
                : "",
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              expect(artifact.changedFiles).toEqual(["app.ts"]);
              await writeFile(
                join(repository, "user-notes.txt"),
                "unrelated notes from concurrent work\n",
              );
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
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
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each(["untracked", "tracked"])(
  "keeps unrelated %s edits made after patch capture out of publication",
  async (kind) => {
    const root = await temporaryDirectory("patch-assessment-publication-");
    const repository = join(root, "repository");
    const remote = join(root, "remote.git");
    const git = repositoryGit(repository);
    try {
      await mkdir(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      git("config", "commit.gpgsign", "false");
      await writeFile(join(repository, "app.ts"), "original\n");
      if (kind === "tracked")
        await writeFile(join(repository, "user-notes.txt"), "original notes\n");
      git("add", ".");
      git("commit", "-m", "Synthetic initial commit");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      let patched = false;
      let injected = false;
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
            if (patched && !injected && args.includes("--name-only")) {
              injected = true;
              await writeFile(
                join(repository, "user-notes.txt"),
                "unrelated notes from concurrent work\n",
              );
            }
            return result;
          },
          onCodex: async (_args, output) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              expect(artifact.changedFiles).toEqual(["app.ts"]);

              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
              patched = true;
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
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.skipIf(process.platform !== "win32")(
  "assesses direct patches with drive-relative Git metadata",
  async () => {
    const repository = await temporaryDirectory("patch-drive-relative-");
    try {
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic drive-relative baseline");
      const drive = repository.slice(0, 2);
      expect(drive).toMatch(/^[a-z]:$/iu);
      const gitEnvironment = { GIT_DIR: `${drive}.git` };
      expect(
        gitText(["rev-parse", "--git-dir"], {
          cwd: repository,
          env: { ...process.env, ...gitEnvironment },
        }).trim(),
      ).toBe(gitEnvironment.GIT_DIR);
      let calls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: repository,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output) => {
            calls++;
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
              output?.stdout.write("Fixed and checked.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(calls).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["app.ts"],
      });
    } finally {
      await rm(repository, { recursive: true, force: true });
    }
  },
);

describe("inherited patch publication context", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  test.each(
    ["environment", "config"].flatMap((selection) =>
      ["root", "package"].flatMap((scope) =>
        ["absolute", "relative"].flatMap((spelling) =>
          [false, true].map((assess) => ({
            selection,
            scope,
            spelling,
            assess,
          })),
        ),
      ),
    ),
  )(
    "preserves separately configured worktree metadata from $scope with $spelling $selection path and assessment=$assess",
    async ({ selection, scope, spelling, assess }) => {
      const root = await fixtures.create("patch-separate-worktree-");
      const metadata = join(root, "metadata");
      const tree = join(root, "selected-tree");
      const directory = scope === "root" ? metadata : join(metadata, "package");
      const nested = join(tree, "nested");
      await mkdir(directory, { recursive: true });
      await mkdir(nested, { recursive: true });
      for (const repository of [metadata, nested]) {
        const git = repositoryGit(repository);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
      }
      await writeFile(join(nested, "app.ts"), "nested before\n");
      const nestedGit = repositoryGit(nested);
      nestedGit("add", ".");
      nestedGit("commit", "-m", "Synthetic nested baseline");
      await writeFile(join(tree, "app.ts"), "before\n");
      await writeFile(join(tree, "unrelated.txt"), "original\n");
      if (selection === "config")
        repositoryGit(metadata)(
          "config",
          "core.worktree",
          spelling === "absolute"
            ? tree
            : relative(join(metadata, ".git"), tree),
        );
      const environment =
        selection === "environment"
          ? {
              GIT_WORK_TREE:
                spelling === "absolute" ? tree : relative(directory, tree),
            }
          : {};
      const beforeEnvironment = { ...environment };
      const git = (...args: string[]) =>
        runGitRepositoryCommand("git", args, directory, { environment });
      await git("add", ".");
      await git("commit", "-m", "Synthetic baseline");
      await writeFile(join(tree, "unrelated.txt"), "staged user change\n");
      await git("add", "--", join(tree, "unrelated.txt"));
      const head = await git("rev-parse", "HEAD");
      const staged = await git("diff", "--cached", "--binary");
      const indexes = [metadata, nested].map((path) =>
        join(path, ".git", "index"),
      );
      const beforeIndexes = await Promise.all(
        indexes.map((path) => readFile(path)),
      );
      let modelCalls = 0;
      let assessments = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          "--json",
          ...(assess ? ["--assess-patch-risk"] : []),
        ],
        {
          currentDirectory: directory,
          environment,
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            }),
          onCodex: async (_args, output) => {
            modelCalls++;
            await writeFile(join(tree, "app.ts"), "fixed\n");
            if (!assess)
              await writeFile(join(nested, "app.ts"), "nested fixed\n");
            output?.stdout.write("Fixed and checked.");
            return 0;
          },
        },
        {
          configure: (current) => {
            current.assessPatchRisk = async (request) => {
              assessments++;
              expect(request.repository).toBe(tree);
              expect(request.directory).toBe(directory);
              expect(request.files).toEqual(["app.ts"]);
              expect(
                await runGitRepositoryCommand(
                  "git",
                  ["rev-parse", "HEAD"],
                  tree,
                  {
                    directory: request.directory,
                    environment: request.environment,
                  },
                ),
              ).toBe(head);
              expect(
                await runGitRepositoryCommand(
                  "git",
                  ["diff", "--name-only"],
                  tree,
                  {
                    directory: request.directory,
                    environment: request.environment,
                  },
                ),
              ).toBe("app.ts");
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      expect(assessments).toBe(assess ? 1 : 0);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: assess
          ? [relative(directory, join(tree, "app.ts")).split(sep).join("/")]
          : ["app.ts", "nested/app.ts"],
      });
      expect(await git("rev-parse", "HEAD")).toBe(head);
      expect(await git("diff", "--cached", "--binary")).toBe(staged);
      expect(await Promise.all(indexes.map((path) => readFile(path)))).toEqual(
        beforeIndexes,
      );
      expect(await readFile(join(tree, "unrelated.txt"), "utf8")).toBe(
        "staged user change\n",
      );
      expect(environment).toEqual(beforeEnvironment);
    },
  );

  test.each(
    ["ordinary", "absolute", "relative", "empty"].flatMap((settings) =>
      [
        { command: "patch", flag: undefined },
        { command: "patch", flag: "--assess-patch-risk" },
        { command: "patch", flag: "--create-pr" },
        { command: "scan", flag: undefined },
        { command: "scan", flag: "--create-pr" },
      ].map((entry) => ({ settings, ...entry })),
    ),
  )(
    "preserves $command patch scope with $settings Git settings and $flag",
    async ({ settings, command, flag }) => {
      const root = await fixtures.create("patch-direct-scope-");
      const directory = join(root, "package");
      await mkdir(directory);
      const gitSettings =
        settings === "ordinary"
          ? {}
          : {
              GIT_DIR:
                settings === "relative"
                  ? "../.git"
                  : settings === "empty"
                    ? ""
                    : join(root, ".git"),
              GIT_WORK_TREE:
                settings === "relative"
                  ? ".."
                  : settings === "empty"
                    ? ""
                    : root,
            };
      const settingsBefore = JSON.stringify(gitSettings);
      let inputDependencies: ReturnType<typeof dependencies> | undefined;
      let inputRunner:
        ReturnType<typeof dependencies>["runRepositoryCommand"] | undefined;
      let modelCalls = 0;
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(directory, "app.ts"), "unsafe\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const remote = await fixtures.create("patch-direct-scope-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const scanResult = resultWithFindings(["high"]);
      scanResult.findings.findings[0]!.locations[0]!.path = "app.ts";
      const fixture: Parameters<typeof dependencies>[0] = {
        result: scanResult,
        currentDirectory: directory,
        environment: gitSettings,
        onRepositoryCommand: async (command, args, cwd, options) => {
          const gitOptions = {
            ...options,
            environment: { ...gitSettings, ...options?.environment },
          };
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, gitOptions);
          if (args[1] === "list") {
            expect(
              resolve(
                await runGitRepositoryCommand(
                  "git",
                  ["rev-parse", "--show-toplevel"],
                  cwd,
                  gitOptions,
                ),
              ),
            ).toBe(root);
            return "[]";
          }
          return "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (_args, output) => {
          modelCalls++;
          expect(output?.appServer?.directory).toBe(directory);
          await writeFile(join(directory, "app.ts"), "fixed\n");
          if (command === "scan") completePatches(_args, output);
          else output?.stdout.write("Fixed and checked.");
          return 0;
        },
      };
      const outcome = await runWorkflow(
        [
          ...(command === "scan"
            ? ["scan", ".", "--patch"]
            : ["patch", "Synthetic issue"]),
          "--json",
          ...(flag ? [flag] : []),
        ],
        fixture,
        {
          configure: (current) => {
            inputDependencies = current;
            inputRunner = current.runRepositoryCommand;
            current.assessPatchRisk = async (request) => {
              expect(request.repository).toBe(root);
              expect(request.files).toEqual(["package/app.ts"]);
              expect(
                resolve(
                  await runGitRepositoryCommand(
                    "git",
                    ["rev-parse", "--show-toplevel"],
                    request.repository,
                    {
                      directory: request.directory,
                      environment: request.environment ?? current.environment,
                    },
                  ),
                ),
              ).toBe(root);
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(inputDependencies!.runRepositoryCommand).toBe(inputRunner!);
      expect(JSON.stringify(inputDependencies!.environment)).toBe(
        settingsBefore,
      );
      expect(JSON.stringify(gitSettings)).toBe(settingsBefore);
      if (settings === "empty") {
        expect(outcome.exitCode).toBe(flag === undefined ? 0 : 2);
        expect(modelCalls).toBe(flag === undefined ? 1 : 0);
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(modelCalls).toBe(1);
      if (flag === "--create-pr") {
        const resumed = await runWorkflow(
          ["patch", "--resume-pr", git("branch", "--show-current"), "--json"],
          fixture,
        );
        expect(resumed.exitCode, resumed.stderr).toBe(0);
        expect(modelCalls).toBe(1);
      }
      const result = JSON.parse(outcome.stdout);
      if (command === "patch")
        expect({
          repository: relative(directory, result.repository),
          files: result.files,
        }).toEqual({
          repository: "",
          files: [flag === undefined ? "package/app.ts" : "app.ts"],
        });
      else
        expect(result.patches).toMatchObject([
          { status: "verified", files: ["app.ts"] },
        ]);
    },
  );

  test.each(
    ["staged", "unstaged", "assume-unchanged", "clean", "deleted-before"]
      .flatMap((dirty) =>
        ["new.ts", "old.ts/new.ts"].map((file) => [dirty, file] as const),
      )
      .concat(
        [
          "clean-staged-rename",
          "clean-staged-rename-supplied",
          "clean-source-directory",
          "clean-selected-source-directory",
          "clean-selected-absent",
          "clean-ignored-directory",
        ].flatMap((state) =>
          [
            "new.ts",
            ...(state.startsWith("clean-staged-rename") ||
            state.startsWith("clean-selected")
              ? [
                  "src/new.ts",
                  ...(process.platform === "win32" ? ["src\\new.ts"] : []),
                ]
              : []),
          ].map((file) => [state, file] as const),
        ),
      )
      .concat([
        ["clean-selected-source-directory-subdirectory", "src/new.ts"],
        ["clean-selected-absent-subdirectory", "src/new.ts"],
      ]),
  )("handles a renamed %s file at %s", async (state, file) => {
    const subdirectory = state.endsWith("-subdirectory");
    const dirty = state.replace(/-subdirectory$/u, "");
    const directory = await fixtures.create("patch-renamed-local-edits-");
    const git = repositoryGit(directory);
    const source = /^src[/\\]/u.test(file) ? "src/old.ts" : "old.ts";
    await mkdir(dirname(join(directory, source)), { recursive: true });
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await writeFile(join(directory, source), "unsafe\noriginal\n");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const supplied = dirty === "clean-staged-rename-supplied";
    const hasLocalEdits =
      !dirty.startsWith("clean") && dirty !== "deleted-before";
    const content = hasLocalEdits ? "synthetic local edit" : "original";
    if (hasLocalEdits)
      await writeFile(join(directory, source), `unsafe\n${content}\n`);
    if (dirty === "deleted-before") await rm(join(directory, source));
    if (dirty === "staged") git("add", ".");
    if (dirty === "assume-unchanged")
      git("update-index", "--assume-unchanged", source);
    await writeFile(join(directory, "unrelated.ts"), "original\n");
    await writeFile(join(directory, "hidden.ts"), "hidden\n");
    git("add", "unrelated.ts", "hidden.ts");
    git(
      "commit",
      "--only",
      "-m",
      "Unrelated baseline",
      "--",
      "unrelated.ts",
      "hidden.ts",
    );
    if (!supplied) {
      await writeFile(join(directory, "unrelated.ts"), "staged work\n");
      git("add", "unrelated.ts");
      await writeFile(join(directory, "unrelated.ts"), "working work\n");
      git("update-index", "--skip-worktree", "hidden.ts");
      await writeFile(join(directory, "intent.ts"), "intent\n");
      git("add", "--intent-to-add", "intent.ts");
    }
    const unrelated = git(
      "ls-files",
      "--stage",
      "--debug",
      "--",
      "unrelated.ts",
      "hidden.ts",
      "intent.ts",
    );
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const remote = await fixtures.create("patch-renamed-local-remote-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const result = resultWithFindings(["high"]);
    const target = subdirectory ? join(directory, "src") : directory;
    result.findings.findings[0]!.locations[0]!.path = subdirectory
      ? relative(target, join(directory, source))
      : source;
    const outcome = await runWorkflow(
      [
        "patch",
        ...(supplied ? ["Synthetic issue"] : ["--scan", "scan-1"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: target,
        onWorkbench: () => savedScan(result, "scan-1", target),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
        onCodex: async (_args, output) => {
          if (dirty.startsWith("clean-staged-rename")) git("mv", source, file);
          else await rm(join(directory, source), { force: true });
          if (
            dirty.endsWith("source-directory") ||
            dirty === "clean-ignored-directory"
          ) {
            await mkdir(join(directory, source));
            await writeFile(
              join(directory, source, "unverified.txt"),
              "unverified\n",
            );
            if (dirty === "clean-ignored-directory")
              await writeFile(
                join(directory, ".git/info/exclude"),
                "old.ts/\n",
              );
          }
          await mkdir(dirname(join(directory, file)), { recursive: true });
          await writeFile(join(directory, file), `fixed\n${content}\n`);
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: [
                    file,
                    ...(dirty.startsWith("clean-selected") ? [source] : []),
                  ].map((path) =>
                    subdirectory
                      ? relative(target, join(directory, path))
                      : path,
                  ),
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(hasLocalEdits ? 2 : 0);
    if (hasLocalEdits) {
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
      expect(git("ls-remote", "origin")).toBe("");
    } else {
      expect(git("show", `HEAD:${file.replaceAll("\\", "/")}`)).toBe(
        `fixed\n${content}`,
      );
      if (dirty.startsWith("clean"))
        expect(
          git("diff", "--name-status", "--no-renames", "HEAD^", "HEAD"),
        ).toContain(`D\t${source}`);
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
    }
    expect(
      git(
        "ls-files",
        "--stage",
        "--debug",
        "--",
        "unrelated.ts",
        "hidden.ts",
        "intent.ts",
      ),
    ).toBe(unrelated);
    expect(await readFile(join(directory, "unrelated.ts"), "utf8")).toBe(
      supplied ? "original\n" : "working work\n",
    );
    if (
      dirty.endsWith("source-directory") ||
      dirty === "clean-ignored-directory"
    ) {
      expect(
        await readFile(join(directory, source, "unverified.txt"), "utf8"),
      ).toBe("unverified\n");
      expect(
        git("ls-tree", "-r", "--name-only", "HEAD").includes("unverified.txt"),
      ).toBe(dirty === "clean-selected-source-directory");
    }
    expect(await readFile(join(directory, file), "utf8")).toBe(
      `fixed\n${content}\n`,
    );
  });

  test.each([
    ["staged", "src/finding-1.ts"],
    ["staged", "src"],
    ["unstaged", "src/finding-1.ts"],
    ["unstaged", "src"],
    ["assume-unchanged", "src/finding-1.ts"],
    ["assume-unchanged", "src"],
    ["untracked-and-ignored", "src"],
  ])("keeps %s edits out of publication of %s", async (dirty, reportedPath) => {
    for (const command of ["patch", "scan"]) {
      const directory = await fixtures.create("patch-publication-");
      const git = repositoryGit(directory);
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = reportedPath;
      await mkdir(join(directory, "src"));
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(
        join(directory, "src/finding-1.ts"),
        "unsafe\noriginal\n",
      );
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const originalHead = git("rev-parse", "HEAD");
      await writeFile(
        join(directory, "src/finding-1.ts"),
        "unsafe\nlocal edit\n",
      );
      if (dirty === "staged") git("add", ".");
      if (dirty === "assume-unchanged")
        git("update-index", "--assume-unchanged", "src/finding-1.ts");
      let expectedIndex = git("write-tree");
      const remote = await fixtures.create("patch-publication-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
          : ["scan", directory, "--patch", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (args, output) => {
            await writeFile(
              join(directory, "src/finding-1.ts"),
              "fixed\nlocal edit\n",
            );
            if (dirty === "untracked-and-ignored") {
              await writeFile(
                join(directory, ".gitignore"),
                "src/finding-1.ts\n",
              );
              git("rm", "--cached", "--force", "src/finding-1.ts");
              expectedIndex = git("write-tree");
            }
            completePatches(args, output);
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(git("rev-parse", "HEAD")).toBe(originalHead);
      expect(git("write-tree")).toBe(expectedIndex);
      expect(git("ls-remote", "origin")).toBe("");
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "fixed\nlocal edit\n",
      );
    }
  });
});

describe("patch change tracking", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);

  async function publicationRepository() {
    const directory = await fixtures.create("patch-destination-");
    const git = repositoryGit(directory);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    await mkdir(join(directory, "src"));
    await writeFile(join(directory, "src/finding-1.ts"), "original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const remote = await fixtures.create("patch-destination-origin-");
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    return { directory, git, remote };
  }

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
      let publicationDiff: string[] = [];
      const outcome = await runWorkflow(
        command === "patch"
          ? ["patch", "--scan", "scan-1", "--create-pr", "--json"]
          : ["scan", directory, "--patch", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: async (command, args, cwd, options) => {
            if (command === "git") {
              const output = await runGitRepositoryCommand(
                command,
                args,
                cwd,
                options,
              );
              if (args.includes("--find-copies-harder"))
                publicationDiff = output.split("\0").filter(Boolean);
              return output;
            }
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
      expect(publicationDiff).toEqual(["M", source, "A", destination]);
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
      const server = Bun.serve({
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
        const proxy = `http://127.0.0.1:${server.port}`;
        git(
          "remote",
          "set-url",
          "origin",
          `${kind === "required" ? "http://127.0.0.1:1" : proxy}/repository.git`,
        );
        git("config", "remote.origin.proxy", kind === "required" ? proxy : "");
        const globalConfig = join(directory, ".git", "global-config");
        await writeFile(
          globalConfig,
          kind === "empty" ? "[http]\nproxy = http://127.0.0.1:1\n" : "",
        );
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
          });
          execution.child.stdin?.end(options?.input);
          const { stdout } = await execution;
          return options?.trim === false ? stdout : stdout.trim();
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
        const outcome = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            environment,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onCodex,
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git" ? runGit(command, args, cwd, options) : "[]",
          },
        );
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
      const nestedGit = repositoryGit(nested);
      nestedGit("init", "--initial-branch=main");
      nestedGit("config", "user.name", "Synthetic User");
      nestedGit("config", "user.email", "synthetic@example.test");
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
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessments++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
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

  test.each(
    ["pre-commit", "post-checkout"].flatMap((hook) =>
      ["src/finding-1.ts", "src/finding-1.ts/fixed.ts"].map(
        (file) => [hook, file] as const,
      ),
    ),
  )("restores the complete index after %s fails for %s", async (hook, file) => {
    const { directory, git } = await publicationRepository();
    await writeFile(join(directory, "other.ts"), "original\n");
    await writeFile(join(directory, "hidden.ts"), "hidden original\n");
    git("add", ".");
    git("commit", "-m", "Synthetic unrelated files");
    await writeFile(join(directory, "other.ts"), "staged local edit\n");
    git("add", "other.ts");
    git("update-index", "--skip-worktree", "hidden.ts");
    await writeFile(join(directory, "intent.ts"), "local intent\n");
    git("add", "--intent-to-add", "intent.ts");
    const head = git("rev-parse", "HEAD");
    const entries = git("ls-files", "--stage", "-v");
    let indexBefore: Buffer<ArrayBuffer> | undefined;
    const indexPath = git(
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "index",
    );
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command !== "git") return "[]";
          const switchIndex = args.indexOf("switch");
          if (switchIndex !== -1 && args[switchIndex + 1] === "-c")
            indexBefore = await readFile(indexPath);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          await rm(join(directory, "src/finding-1.ts"));
          await mkdir(dirname(join(directory, file)), { recursive: true });
          await writeFile(join(directory, file), "fixed\n");
          const hookPath = git("rev-parse", "--git-path", `hooks/${hook}`);
          const absoluteHook = resolve(directory, hookPath);
          await writeFile(
            absoluteHook,
            "#!/bin/sh\necho 'Synthetic hook failure' >&2\nexit 1\n",
          );
          await chmod(absoluteHook, 0o755);
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: [file],
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain("Synthetic hook failure");
    expect(git("branch", "--show-current")).toBe("main");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(indexPath)).toEqual(indexBefore!);
    expect(git("ls-files", "--stage", "-v")).toBe(entries);
    expect(
      git(
        "for-each-ref",
        "--format=%(refname)",
        "refs/heads/codex-security/patch-scan-1",
      ),
    ).toBe("");
    expect(git("ls-remote", "origin")).toBe("");
    expect(await readFile(join(directory, file), "utf8")).toBe("fixed\n");
  });

  test.each(
    ["staged", "unstaged", "assume-unchanged", "clean"].flatMap((state) =>
      ["copy", "rename", "symlink", "gitlink"].map(
        (transfer) => [state, transfer] as const,
      ),
    ),
  )("protects %s content transferred by %s", async (state, transfer) => {
    const { directory, git } = await publicationRepository();
    const original = "unsafe\n" + "synthetic baseline line\n".repeat(12);
    const local =
      state === "clean" ? original : original + "synthetic local work\n";
    await writeFile(join(directory, "old.ts"), original);
    git("add", "old.ts");
    git("commit", "-m", "Synthetic source");
    await writeFile(join(directory, "old.ts"), local);
    if (state === "staged") git("add", "old.ts");
    if (state === "assume-unchanged")
      git("update-index", "--assume-unchanged", "old.ts");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
        onCodex: async (_args, output) => {
          await writeFile(
            join(directory, "new.ts"),
            local.replace("unsafe", "fixed"),
          );
          if (transfer !== "copy") await rm(join(directory, "old.ts"));
          if (transfer === "symlink")
            await symlink("new.ts", join(directory, "old.ts"));
          if (transfer === "gitlink") {
            await mkdir(join(directory, "old.ts"));
            git("-C", "old.ts", "init", "--initial-branch=main");
            git("-C", "old.ts", "config", "user.name", "Synthetic User");
            git(
              "-C",
              "old.ts",
              "config",
              "user.email",
              "synthetic@example.test",
            );
            git(
              "-C",
              "old.ts",
              "commit",
              "--allow-empty",
              "-m",
              "Synthetic nested baseline",
            );
          }
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["new.ts"],
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(state === "clean" ? 0 : 2);
    if (state !== "clean") {
      expect(outcome.stderr).toContain("uncommitted changes before patching");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("write-tree")).toBe(index);
      expect(git("ls-remote", "origin")).toBe("");
    } else {
      expect(git("show", "HEAD:new.ts")).toBe(
        local.replace("unsafe", "fixed").trim(),
      );
      if (transfer === "rename")
        expect(git("ls-tree", "HEAD", "old.ts")).toBe("");
    }
  });

  test.each(
    ["saved", "supplied"].flatMap((mode) =>
      [
        "move",
        "copy",
        "different",
        "empty",
        "generated-template",
        "generated-build",
        "symlink",
      ].map((change) => [mode, change] as const),
    ),
  )("checks ignored content before publishing %s/%s", async (mode, change) => {
    const { directory, git } = await publicationRepository();
    await writeFile(join(directory, ".gitignore"), ".env\n.cache/\ndist/\n");
    git("add", ".gitignore");
    git("commit", "-m", "Synthetic ignored paths");
    const content =
      change === "empty"
        ? ""
        : change === "generated-template"
          ? "export const enabled = true;\n"
          : change === "generated-build"
            ? "export const answer = 42;\n"
            : "SYNTHETIC_LOCAL_CONTENT\n";
    const source =
      change === "generated-template"
        ? ".cache/template.ts"
        : change === "generated-build"
          ? "dist/generated.js"
          : ".env";
    await mkdir(dirname(join(directory, source)), { recursive: true });
    if (change === "symlink") {
      const outside = await fixtures.create("ignored-link-target-");
      await writeFile(join(outside, "file"), content);
      await symlink(join(outside, "file"), join(directory, source));
    } else await writeFile(join(directory, source), content);
    const before = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git/index"));
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      [
        "patch",
        ...(mode === "saved" ? ["--scan", "scan-1"] : ["Synthetic issue"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: directory,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) =>
          command === "git"
            ? runGitRepositoryCommand(command, args, cwd, options)
            : args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1",
        onCodex: async (_args, output) => {
          if (change === "move")
            await rename(join(directory, source), join(directory, "new.ts"));
          else
            await writeFile(
              join(directory, "new.ts"),
              change === "different" ? "New independent content\n" : content,
            );
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["new.ts"],
                  verification: "Synthetic verification.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    const blocked = [
      "move",
      "copy",
      "generated-template",
      "generated-build",
    ].includes(change);
    expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
    if (blocked) {
      expect(outcome.stderr).toContain("matches pre-existing ignored content");
      expect(git("rev-parse", "HEAD")).toBe(before);
      expect(await readFile(join(directory, ".git/index"))).toEqual(index);
      expect(git("ls-remote", "origin")).toBe("");
    }
    expect(await readFile(join(directory, "new.ts"), "utf8")).toBe(
      change === "different" ? "New independent content\n" : content,
    );
  });

  test.each(
    ["root", "src"].flatMap((scope) =>
      ["file", "directory"].map((selection) => ({ scope, selection })),
    ),
  )(
    "preserves newly tracked ignored patch content from $scope with $selection selection",
    async ({ scope, selection }) => {
      const { directory, git, remote } = await publicationRepository();
      await mkdir(join(directory, "src/nested"));
      await writeFile(join(directory, "src/nested/app.ts"), "old\n");
      await writeFile(join(directory, ".gitignore"), "generated.txt\n");
      await writeFile(join(directory, "unrelated.txt"), "baseline\n");
      git("add", ".");
      git("commit", "-m", "Synthetic ignored output baseline");
      await writeFile(
        join(directory, "unrelated.txt"),
        "unrelated staged work\n",
      );
      git("add", "unrelated.txt");
      const unrelated = git(
        "ls-files",
        "--stage",
        "--debug",
        "--",
        "unrelated.txt",
      );
      const cwd = scope === "root" ? directory : join(directory, "src");
      const prefix = scope === "root" ? "src/nested" : "nested";
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = `${prefix}/app.ts`;
      let calls = 0;
      const outcome = await runWorkflow(
        [
          "patch",
          "--scan",
          "scan-1",
          "--create-pr",
          "--assess-patch-risk",
          "--json",
        ],
        {
          currentDirectory: cwd,
          onWorkbench: () => savedScan(result, "scan-1", cwd),
          onRepositoryCommand: (command, args, repository, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, repository, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            calls++;
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[] };
              expect(artifact.changedFiles).toEqual([
                "src/nested/app.ts",
                "src/nested/generated.txt",
              ]);
              const verification = await fixtures.create(
                "ignored-staged-risk-apply-",
              );
              await mkdir(join(verification, "src/nested"), {
                recursive: true,
              });
              await writeFile(join(verification, "src/nested/app.ts"), "old\n");
              repositoryGit(verification)("apply", "--check", artifact.path);
              repositoryGit(verification)("apply", artifact.path);
              expect(
                await readAppliedText(join(verification, "src/nested/app.ts")),
              ).toBe("fixed\n");
              expect(
                await readAppliedText(
                  join(verification, "src/nested/generated.txt"),
                ),
              ).toBe("new generated fix\n");
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            await writeFile(join(directory, "src/nested/app.ts"), "fixed\n");
            await writeFile(
              join(directory, "src/nested/generated.txt"),
              "new generated fix\n",
            );
            git("add", "-f", "src/nested/generated.txt");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files:
                      selection === "file"
                        ? [`${prefix}/app.ts`, `${prefix}/generated.txt`]
                        : [prefix],
                    verification: "Synthetic check.",
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
      expect(
        repositoryGit(remote)("show", `${commit}:src/nested/generated.txt`),
      ).toBe("new generated fix");
      expect(git("show", "HEAD:unrelated.txt")).toBe("baseline");
      expect(git("ls-files", "--stage", "--debug", "--", "unrelated.txt")).toBe(
        unrelated,
      );
      expect(git("diff", "--cached", "--name-only")).toBe("unrelated.txt");
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
    "newline-relative",
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
          rewriting === "newline-relative"
            ? join(directory, "\nproject")
            : rewriting === "trailing-space"
              ? `${raw} `
              : rewriting.startsWith("newline")
                ? `${raw}\npart`
                : `${raw}-v2`;
        git("init", "--bare", remote);
        git(
          "remote",
          "set-url",
          "origin",
          rewriting === "newline-relative"
            ? "\nproject"
            : rewriting === "ordinary" ||
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
        const result = resultWithFindings(["high"]);
        const outcome = await runWorkflow(
          ["patch", "--scan", "scan-1", "--create-pr", "--json"],
          {
            currentDirectory: directory,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, options)
                : args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (args, output) => {
              await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
              completePatches(args, output);
              return 0;
            },
          },
        );
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

  for (const mode of ["saved", "supplied"]) {
    test.each([
      "file",
      "literal-pathspecs",
      "directory",
      "info",
      "global",
      "unchanged",
      "unchanged-directory",
      "removed",
      "removed-unignored",
      "force-added",
      "new",
    ])(
      `preserves pre-existing ignored paths during ${mode} publication (%s)`,
      async (kind) => {
        const { directory: root, git, remote } = await publicationRepository();
        const removed = kind === "removed" || kind === "removed-unignored";
        const forced = kind === "force-added";
        const directory = kind === "unchanged-directory" || removed || forced;
        const file =
          kind === "directory"
            ? "cache/nested/local.txt"
            : directory
              ? "src/local.pyc"
              : "local.env";
        const pattern = `${kind === "directory" ? "cache/" : file}\n`;
        const unchanged =
          kind === "unchanged" || kind === "unchanged-directory";
        const rule =
          kind === "info"
            ? join(root, ".git", "info", "exclude")
            : kind === "global"
              ? join(remote, "excludes")
              : join(root, ".gitignore");
        await writeFile(
          join(root, ".gitignore"),
          rule === join(root, ".gitignore") ? pattern : "",
        );
        git("add", ".gitignore");
        git("commit", "-m", "Synthetic ignore rule");
        await writeFile(rule, pattern);
        if (kind === "global") git("config", "core.excludesFile", rule);
        if (kind !== "new") {
          await mkdir(dirname(join(root, file)), { recursive: true });
          await writeFile(join(root, file), "synthetic local data\n");
        }
        const gitEnvironment: NodeJS.ProcessEnv =
          kind === "literal-pathspecs" ? { GIT_LITERAL_PATHSPECS: "1" } : {};
        const head = git("rev-parse", "HEAD");
        let expectedIndex = git("write-tree");
        const result = resultWithFindings(["high"]);
        result.findings.findings[0]!.locations[0]!.path = file;
        const blocked = !unchanged && !removed && kind !== "new";
        const outcome = await runWorkflow(
          [
            "patch",
            ...(mode === "saved"
              ? ["--scan", "scan-1"]
              : ["Synthetic ignore update"]),
            "--create-pr",
            "--json",
          ],
          {
            currentDirectory: root,
            environment: gitEnvironment,
            onWorkbench: () => savedScan(result, "scan-1", root),
            onRepositoryCommand: (command, args, cwd, options) =>
              command === "git"
                ? runGitRepositoryCommand(command, args, cwd, {
                    ...options,
                    environment: { ...gitEnvironment, ...options?.environment },
                  })
                : args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1",
            onCodex: async (_args, output) => {
              if (!unchanged && kind !== "removed" && !forced)
                await writeFile(rule, "");
              if (kind === "new")
                await writeFile(join(root, file), "synthetic generated data\n");
              if (unchanged || removed || forced)
                await writeFile(join(root, "src/finding-1.ts"), "fixed\n");
              if (removed) await rm(join(root, file));
              if (forced) {
                git("add", "--force", file);
                expectedIndex = git("write-tree");
              }
              output?.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: "occ_1",
                      status: "verified",
                      files: directory
                        ? [
                            "src",
                            ...(kind === "removed-unignored"
                              ? [".gitignore"]
                              : []),
                          ]
                        : unchanged
                          ? ["src/finding-1.ts"]
                          : [".gitignore", file],
                      verification: "Synthetic verification.",
                    },
                  ],
                }),
              );
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(blocked ? 2 : 0);
        if (blocked) {
          expect(outcome.stderr).toContain(
            "uncommitted changes before patching",
          );
          expect(git("rev-parse", "HEAD")).toBe(head);
          expect(git("write-tree")).toBe(expectedIndex);
          expect(git("ls-remote", "origin")).toBe("");
          expect(await readFile(rule, "utf8")).toBe(forced ? pattern : "");
        } else {
          expect(git("ls-remote", "origin")).toContain(
            git("rev-parse", "HEAD"),
          );
          expect(
            git("show", `HEAD:${kind === "new" ? file : "src/finding-1.ts"}`),
          ).toBe(kind === "new" ? "synthetic generated data" : "fixed");
        }
        if (unchanged || removed)
          expect(
            git("ls-tree", "-r", "--name-only", "HEAD").split("\n"),
          ).not.toContain(file);
        if (removed)
          await expect(
            readFile(join(root, file), "utf8"),
          ).rejects.toMatchObject({ code: "ENOENT" });
        else
          expect(await readFile(join(root, file), "utf8")).toBe(
            kind === "new"
              ? "synthetic generated data\n"
              : "synthetic local data\n",
          );
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
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
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
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
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
        },
      );
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
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            calls++;
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              ) as { path: string; changedFiles: string[] };
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

describe("directory replacement publication", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  for (const state of ["clean", "unrelated", "dirty-nested", "staged-nested"])
    test(`directory replacement ${state}`, async () => {
      const root = await fixtures.create("synthetic-directory-replacement-");
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await mkdir(join(root, "entry"));
      await writeFile(join(root, "entry/old.ts"), "original\n");
      await writeFile(join(root, "other.ts"), "unrelated\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const dirtyNested = state.endsWith("nested");
      if (state !== "clean")
        await writeFile(join(root, "other.ts"), "unrelated local edits\n");
      if (dirtyNested)
        await writeFile(
          join(root, "entry/old.ts"),
          "original plus local edits\n",
        );
      if (state === "staged-nested") git("add", "entry/old.ts");
      const remote = await fixtures.create("synthetic-local-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const before = git("rev-parse", "HEAD");
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = "entry";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: root,
          onWorkbench: () => savedScan(result, "scan-1", root),
          onRepositoryCommand: (command, args, cwd, options) => {
            return command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[0] === "repo"
                ? "synthetic-repository-id"
                : args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/synthetic/project/pull/1";
          },
          onCodex: async (args, output) => {
            const previous = await readFile(join(root, "entry/old.ts"), "utf8");
            await rm(join(root, "entry"), { recursive: true });
            await writeFile(join(root, "entry"), `fixed\n${previous}`);
            completePatches(args, output);
            return 0;
          },
        },
      );
      const after = git("rev-parse", "HEAD"),
        remoteRef = git("ls-remote", "origin");
      expect(outcome.exitCode, outcome.stderr).toBe(dirtyNested ? 2 : 0);
      if (dirtyNested) {
        expect(outcome.stderr).toContain("uncommitted changes before patching");
        expect(after).toBe(before);
        expect(remoteRef).toBe("");
        expect(await readFile(join(root, "entry"), "utf8")).toContain(
          "original plus local edits",
        );
      } else {
        expect(git("show", "HEAD:entry")).toBe("fixed\noriginal");
        expect(remoteRef).toContain(after);
      }
      expect(await readFile(join(root, "other.ts"), "utf8")).toBe(
        state === "clean" ? "unrelated\n" : "unrelated local edits\n",
      );
    });
});

describe("ordinary patch snapshot context", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  test.each(
    ["ordinary", "saved", "inline"].flatMap((route) =>
      [
        "stable",
        "remove",
        "replace",
        "relative-filter",
        ...(route === "ordinary" ? [] : ["gitfile"]),
      ].flatMap((operation) =>
        (route === "inline"
          ? [undefined, "--create-pr"]
          : route === "saved"
            ? [undefined, "--assess-patch-risk", "--create-pr"]
            : [undefined, "--assess-patch-risk", "--create-pr"]
        ).flatMap((flag) =>
          ["ordinary", "relative"].map((settings) => ({
            route,
            operation,
            flag,
            settings,
            mode: flag ?? "no flag",
          })),
        ),
      ),
    ),
  )(
    "keeps $route $operation snapshots in the selected checkout with $settings settings and $mode",
    async ({ route, operation, flag, settings }) => {
      const root = await fixtures.create("patch-captured-snapshot-");
      const directory = join(root, "package");
      await mkdir(directory);
      const git = repositoryGit(root);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      if (operation === "relative-filter")
        git("config", "diff.relative", "true");
      await writeFile(join(root, "app.ts"), "unsafe\n");
      await writeFile(join(root, "unrelated.ts"), "original unrelated\n");
      await writeFile(join(directory, "keep.ts"), "component\n");
      git("add", ".");
      git("commit", "-m", "Synthetic baseline");
      const stagedUnrelated =
        flag === "--create-pr" &&
        route !== "ordinary" &&
        (operation === "stable" || operation === "relative-filter");
      if (stagedUnrelated) {
        await writeFile(join(root, "unrelated.ts"), "staged unrelated\n");
        git("add", "unrelated.ts");
      }
      const index = await readFile(join(root, ".git/index"));
      const remote = await fixtures.create("patch-captured-remote-");
      git("init", "--bare", remote);
      git("remote", "add", "origin", remote);
      const foreign = await fixtures.create("patch-unselected-checkout-");
      const foreignGit = repositoryGit(foreign);
      foreignGit("init", "--initial-branch=main");
      foreignGit("config", "user.name", "Synthetic User");
      foreignGit("config", "user.email", "synthetic@example.test");
      if (operation === "gitfile")
        foreignGit("config", "core.worktree", foreign);
      await writeFile(join(foreign, "keep.ts"), "unrelated baseline\n");
      foreignGit("add", ".");
      foreignGit("commit", "-m", "Synthetic unrelated baseline");
      await writeFile(join(foreign, "keep.ts"), "foreign preexisting edit\n");
      const foreignHead = foreignGit("rev-parse", "HEAD");
      const foreignRemote = await fixtures.create("patch-unselected-remote-");
      foreignGit("init", "--bare", foreignRemote);
      foreignGit("remote", "add", "origin", foreignRemote);
      await writeFile(
        join(foreign, "untracked.ts"),
        "unrelated local content\n",
      );
      const foreignObjects = foreignGit("count-objects", "-v");
      const foreignIndex = await readFile(join(foreign, ".git/index"));
      const environment = {
        ...(settings === "relative"
          ? { GIT_DIR: "../.git", GIT_WORK_TREE: ".." }
          : {}),
        GH_CONFIG_DIR: "provider-config",
        GIT_CONFIG_COUNT: "1",
        GIT_CONFIG_KEY_0: "core.quotePath",
        GIT_CONFIG_VALUE_0: "false",
      };
      const scan = resultWithFindings(
        operation === "gitfile" ? ["high", "high"] : ["high"],
      );
      for (const finding of scan.findings.findings)
        finding.locations[0]!.path = "keep.ts";
      const argv =
        route === "ordinary"
          ? ["patch", "Synthetic issue"]
          : route === "saved"
            ? ["patch", "--scan", "scan-1"]
            : ["scan", directory, "--patch"];
      const selectedDirectoryRemoved =
        route !== "ordinary" && operation === "remove" && flag !== undefined;
      let modelCalls = 0;
      let assessmentCalls = 0;
      let redirectedSnapshotCommands = 0;
      const outcome = await runWorkflow(
        [...argv, ...(flag ? [flag] : []), "--json"],
        {
          currentDirectory: directory,
          environment,
          result: scan,
          onWorkbench: () => savedScan(scan, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (
                operation === "replace" &&
                modelCalls > 0 &&
                (args.includes("read-tree") || args.includes("add"))
              )
                redirectedSnapshotCommands++;
              return runGitRepositoryCommand(command, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });
            }
            if (args[1] === "list") return "[]";
            expect(options?.environment?.["GH_CONFIG_DIR"]).toBe(
              resolve(directory, "provider-config"),
            );
            return "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (args, output, childEnvironment) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessmentCalls++;
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              await promisify(execFile)(
                "git",
                ["cat-file", "-e", artifact.base],
                {
                  cwd: output.appServer.directory,
                  env: childEnvironment,
                },
              );
              expect(artifact.changedFiles).toEqual(["package/keep.ts"]);
              output.stdout.write(patchRiskAssessment().report);
              return 0;
            }
            modelCalls++;
            expect(output?.appServer?.directory).toBe(directory);
            await writeFile(join(root, "app.ts"), "fixed\n");
            if (
              route !== "ordinary" &&
              operation !== "remove" &&
              operation !== "replace"
            )
              await writeFile(
                join(directory, "keep.ts"),
                operation === "gitfile"
                  ? `fixed component ${modelCalls}\n`
                  : "fixed component\n",
              );
            if (operation === "gitfile" && modelCalls === 1)
              await writeFile(
                join(directory, ".git"),
                `gitdir: ${join(foreign, ".git")}\n`,
              );
            if (operation === "remove" || operation === "replace")
              await rm(directory, { recursive: true });
            if (operation === "replace")
              await symlink(
                foreign,
                directory,
                process.platform === "win32" ? "junction" : "dir",
              );
            if (route === "ordinary")
              output?.stdout.write("Fixed and checked.");
            else completePatches(args, output);
            return 0;
          },
        },
        {
          configure: (current) => {
            if (route !== "ordinary") return;
            current.assessPatchRisk = async (request) => {
              assessmentCalls++;
              expect(request.repository).toBe(root);
              expect(request.files).toContain("app.ts");
              return patchRiskAssessment();
            };
          },
        },
      );
      expect(modelCalls).toBe(operation === "gitfile" ? 2 : 1);
      expect(assessmentCalls).toBe(
        flag === "--assess-patch-risk" &&
          operation !== "replace" &&
          !selectedDirectoryRemoved
          ? 1
          : 0,
      );
      expect(foreignGit("count-objects", "-v")).toBe(foreignObjects);
      expect(foreignGit("rev-parse", "HEAD")).toBe(foreignHead);
      expect(foreignGit("ls-remote", "origin")).toBe("");
      expect(await readFile(join(foreign, "keep.ts"), "utf8")).toBe(
        "foreign preexisting edit\n",
      );
      expect(await readFile(join(foreign, ".git/index"))).toEqual(foreignIndex);
      expect(await readFile(join(foreign, "untracked.ts"), "utf8")).toBe(
        "unrelated local content\n",
      );
      if (operation === "replace") {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Patch directory now resolves outside the selected repository",
        );
        expect(redirectedSnapshotCommands).toBe(0);
        expect(await readFile(join(root, ".git/index"))).toEqual(index);
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "main"));
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("fixed\n");
        return;
      }
      if (selectedDirectoryRemoved) {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          "Patch directory changed during patching",
        );
        expect(JSON.parse(outcome.stdout).patches).toMatchObject(
          scan.findings.findings.map(() => ({
            status: "verified",
            files: ["keep.ts"],
          })),
        );
        expect(await readFile(join(root, ".git/index"))).toEqual(index);
        expect(git("rev-parse", "HEAD")).toBe(git("rev-parse", "main"));
        expect(git("ls-remote", "origin")).toBe("");
        expect(await readFile(join(root, "app.ts"), "utf8")).toBe("fixed\n");
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      const result = JSON.parse(outcome.stdout);
      if (route === "inline") {
        expect(result.patches).toMatchObject(
          scan.findings.findings.map(() => ({
            status: "verified",
            files: ["keep.ts"],
          })),
        );
      } else {
        expect(result.applied).toBe(true);
        expect(result.files).toContain(
          route === "ordinary" && flag ? "../app.ts" : "app.ts",
        );
        expect(result.files).not.toContain("untracked.ts");
      }
      if (flag !== "--create-pr")
        expect(await readFile(join(root, ".git/index"))).toEqual(index);
      else
        expect(git("show", "HEAD:app.ts")).toBe(
          route === "ordinary" ? "fixed" : "unsafe",
        );
      expect(git("show", "HEAD:unrelated.ts")).toBe("original unrelated");
      expect(git("diff", "--cached", "--name-only")).toBe(
        stagedUnrelated ? "unrelated.ts" : "",
      );
    },
  );
});

test.each(
  ["ordinary", "environment", "config"].flatMap((binding) =>
    [false, true].flatMap((remove) =>
      [false, true].map((redirect) => ({ binding, remove, redirect })),
    ),
  ),
)(
  "keeps assessment Git discovery after component removal: $binding remove=$remove redirect=$redirect",
  async ({ binding, remove, redirect }) => {
    const root = await temporaryDirectory("patch-assessment-discovery-");
    const metadata = join(root, "metadata");
    const worktree = binding === "ordinary" ? metadata : join(root, "worktree");
    const invocation = join(metadata, "component");
    const replacement = join(root, "replacement");
    const gitEnvironment =
      binding === "environment" ? { GIT_WORK_TREE: worktree } : {};
    try {
      await mkdir(invocation, { recursive: true });
      await mkdir(worktree, { recursive: true });
      await mkdir(replacement);
      await writeFile(join(replacement, "app.ts"), "unrelated checkout\n");
      const rawGit = repositoryGit(metadata);
      rawGit("init", "--initial-branch=main");
      rawGit("config", "user.name", "Synthetic User");
      rawGit("config", "user.email", "synthetic@example.test");
      if (binding === "config") rawGit("config", "core.worktree", worktree);
      const git = (...args: string[]) =>
        gitText(args, {
          cwd: metadata,
          env: { ...process.env, ...gitEnvironment },
        }).trim();
      await writeFile(join(worktree, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic assessment baseline");
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(metadata, ".git", "index"));
      let assessmentCalls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: invocation,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output, environment) => {
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              assessmentCalls++;
              expect(
                resolve(
                  gitText(["rev-parse", "--show-toplevel"], {
                    cwd: output.appServer.directory,
                    env: environment,
                  }).trim(),
                ),
              ).toBe(worktree);
              const result = await promisify(execFile)(
                "git",
                ["rev-parse", "HEAD"],
                {
                  cwd: output.appServer.directory,
                  env: environment,
                },
              );
              expect(result.stdout.trim()).toBe(head);
              const artifact = JSON.parse(
                output.appServer.prompt
                  .split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              await promisify(execFile)(
                "git",
                ["cat-file", "-e", artifact.base],
                {
                  cwd: output.appServer.directory,
                  env: environment,
                },
              );
              expect(artifact.changedFiles).toEqual(["app.ts"]);
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(worktree, "app.ts"), "fixed\n");
              if (redirect) rawGit("config", "core.worktree", replacement);
              if (remove) await rm(invocation, { recursive: true });
              output?.stdout.write("Patch complete.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessmentCalls).toBe(1);
      expect(await readFile(join(worktree, "app.ts"), "utf8")).toBe("fixed\n");
      expect(await readFile(join(metadata, ".git", "index"))).toEqual(index);
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(replacement, "app.ts"), "utf8")).toBe(
        "unrelated checkout\n",
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

describe("patch worktree root identity", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  test.each([
    ...["ordinary", "saved", "inline"].flatMap((route) =>
      ["replace", "stable", "alias"].map((operation) => ({
        route,
        operation,
        layout: "external metadata",
      })),
    ),
    { route: "ordinary", operation: "replace", layout: "nested invocation" },
    ...["stable", "replace"].map((operation) => ({
      route: "ordinary",
      operation,
      layout: "external invocation",
    })),
  ])(
    "preserves checkout identity for $route $operation with $layout",
    async ({ route, operation, layout }) => {
      const root = await fixtures.create("patch-root-identity-");
      const foreignRoot = await fixtures.create("patch-root-unselected-");
      const external = layout !== "nested invocation";
      for (const parent of [root, foreignRoot]) {
        const worktree = join(parent, "worktree");
        await mkdir(join(worktree, "component"), { recursive: true });
        const git = repositoryGit(worktree);
        git("init", "--initial-branch=main");
        git("config", "user.name", "Synthetic User");
        git("config", "user.email", "synthetic@example.test");
        await writeFile(join(worktree, "keep.ts"), "original\n");
        await writeFile(
          join(worktree, "component", "anchor.ts"),
          "component\n",
        );
        git("add", ".");
        git("commit", "-m", "Synthetic baseline");
        const remote = join(parent, "remote.git");
        git("init", "--bare", remote);
        git("remote", "add", "origin", remote);
        if (external)
          await rename(join(worktree, ".git"), join(parent, ".git"));
      }
      const worktree = join(root, "worktree");
      const foreign = join(foreignRoot, "worktree");
      const foreignMetadata = join(external ? foreignRoot : foreign, ".git");
      const foreignGit = (...args: string[]) =>
        repositoryGit(foreignRoot)(
          "--git-dir",
          foreignMetadata,
          "--work-tree",
          foreign,
          ...args,
        );
      await writeFile(join(foreign, "keep.ts"), "foreign preexisting edit\n");
      const foreignObjects = foreignGit("count-objects", "-v");
      const foreignHead = foreignGit("rev-parse", "HEAD");
      const foreignIndex = await readFile(join(foreignMetadata, "index"));
      const foreignStatus = foreignGit("status", "--porcelain=v1");
      const directory =
        layout === "external invocation"
          ? root
          : operation === "alias"
            ? join(root, "worktree-alias")
            : external
              ? worktree
              : join(worktree, "component");
      if (operation === "alias")
        await symlink(
          worktree,
          directory,
          process.platform === "win32" ? "junction" : "dir",
        );
      const environment =
        layout === "external invocation"
          ? { GIT_WORK_TREE: worktree }
          : external
            ? { GIT_DIR: join("..", ".git") }
            : {};
      const foreignBlob = foreignGit("hash-object", join(foreign, "keep.ts"));
      const originalObjects = () =>
        repositoryGit(root)(
          "--git-dir",
          join(root, ".git"),
          "cat-file",
          "--batch-all-objects",
          "--batch-check=%(objectname)",
        ).split("\n");
      if (layout === "external invocation")
        expect(originalObjects()).not.toContain(foreignBlob);
      const scan = resultWithFindings(["high"]);
      scan.findings.findings[0]!.locations[0]!.path = "keep.ts";
      const argv =
        route === "ordinary"
          ? ["patch", "Synthetic issue"]
          : route === "saved"
            ? ["patch", "--scan", "scan-1"]
            : ["scan", directory, "--patch"];
      let modelCalls = 0;
      const outcome = await runWorkflow([...argv, "--create-pr", "--json"], {
        currentDirectory: directory,
        environment,
        result: scan,
        onWorkbench: () => savedScan(scan, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...environment, ...options?.environment },
            });
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (args, output) => {
          modelCalls++;
          if (operation === "replace") {
            await rename(worktree, join(root, "original-worktree"));
            await symlink(
              foreign,
              worktree,
              process.platform === "win32" ? "junction" : "dir",
            );
          } else await writeFile(join(worktree, "keep.ts"), "fixed\n");
          if (route === "ordinary") output?.stdout.write("Fixed and checked.");
          else completePatches(args, output);
          return 0;
        },
      });
      expect(modelCalls).toBe(1);
      if (layout === "external invocation")
        expect(originalObjects()).not.toContain(foreignBlob);
      expect(foreignGit("count-objects", "-v")).toBe(foreignObjects);
      expect(foreignGit("rev-parse", "HEAD")).toBe(foreignHead);
      expect(await readFile(join(foreignMetadata, "index"))).toEqual(
        foreignIndex,
      );
      expect(foreignGit("status", "--porcelain=v1")).toBe(foreignStatus);
      expect(foreignGit("ls-remote", "origin")).toBe("");
      expect(await readFile(join(foreign, "keep.ts"), "utf8")).toBe(
        "foreign preexisting edit\n",
      );
      expect(outcome.exitCode, outcome.stderr).toBe(
        operation === "replace" ? 2 : 0,
      );
      const published = repositoryGit(root)(
        "ls-remote",
        join(root, "remote.git"),
      );
      if (operation === "replace") expect(published).toBe("");
      else expect(published).toContain("refs/heads/codex-security/patch-");
    },
  );
});

describe("verified patch caller identity", () => {
  const fixtures = createTemporaryDirectories(true);
  afterEach(fixtures.cleanup);
  test.each(
    ["saved", "inline"].flatMap((route) =>
      [
        "move",
        "move-without-alias",
        "directory-to-file",
        "source-edit",
        "destination-overwrite",
        "source-replacement",
        "stable-alias",
        "removed-caller",
      ].map((operation) => ({ route, operation })),
    ),
  )("$route operation=$operation", async ({ route, operation }) => {
    const root = await fixtures.create("patch-caller-identity-");
    const repository = join(root, "repository");
    const component = join(repository, "component");
    const destination = join(repository, "destination");
    const alias = join(repository, "alias");
    const requested =
      operation === "move" ||
      operation === "move-without-alias" ||
      operation === "directory-to-file" ||
      operation === "removed-caller"
        ? component
        : alias;
    const remote = join(root, "remote.git");
    const redirected =
      operation !== "stable-alias" &&
      operation !== "removed-caller" &&
      operation !== "directory-to-file";
    const blocked = operation !== "stable-alias";
    await mkdir(component, { recursive: true });
    await writeFile(join(component, "app.ts"), "unsafe\n");
    await writeFile(join(component, "sibling.ts"), "original sibling\n");
    await writeFile(join(repository, "unrelated.ts"), "unrelated original\n");
    if (requested === alias)
      await symlink(
        component,
        alias,
        process.platform === "win32" ? "junction" : "dir",
      );
    if (operation === "destination-overwrite") {
      await mkdir(destination);
      await writeFile(
        join(destination, "sibling.ts"),
        "distinct destination sibling\n",
      );
    }
    const git = repositoryGit(repository);
    git("init", "--initial-branch=main");
    git("config", "user.name", "Synthetic User");
    git("config", "user.email", "synthetic@example.test");
    git("add", ".");
    git("commit", "-m", "Synthetic baseline");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(repository, ".git/index"));
    git("init", "--bare", remote);
    git("remote", "add", "origin", remote);
    const scan = resultWithFindings(["high"]);
    scan.findings.findings[0]!.locations[0]!.path = "app.ts";
    let modelCalls = 0,
      assessments = 0,
      requestsCreated = 0;
    const outcome = await runWorkflow(
      [
        ...(route === "saved"
          ? ["patch", "--scan", "scan-1", "--assess-patch-risk"]
          : ["scan", requested, "--patch"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: requested,
        result: scan,
        onWorkbench: () => savedScan(scan, "scan-1", requested),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git")
            return runGitRepositoryCommand(command, args, cwd, options);
          if (args[1] === "create") requestsCreated++;
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (args, output) => {
          if (
            output?.appServer?.prompt.includes(
              "$codex-security:assess-patch-risk",
            )
          ) {
            const artifact = JSON.parse(
              output.appServer.prompt
                .split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            );
            expect(artifact.changedFiles).toEqual(["component/app.ts"]);
            assessments++;
            output.stdout.write(patchRiskAssessment().report);
          } else {
            modelCalls++;
            if (redirected) {
              if (operation === "move" || operation === "move-without-alias")
                await rename(component, destination);
              else {
                await (
                  await import("node:fs/promises")
                ).cp(component, destination, { recursive: true });
                await rm(alias, { recursive: true });
              }
              if (operation !== "move-without-alias")
                await symlink(
                  destination,
                  requested,
                  process.platform === "win32" ? "junction" : "dir",
                );
              await writeFile(join(destination, "app.ts"), "fixed\n");
              if (operation === "source-edit")
                await writeFile(
                  join(component, "sibling.ts"),
                  "unreported source edit\n",
                );
              if (operation === "source-replacement") {
                await rm(component, { recursive: true });
                await writeFile(component, "unreported source replacement\n");
              }
            } else if (operation === "directory-to-file") {
              await rm(component, { recursive: true });
              await writeFile(component, "replacement fix\n");
            } else if (operation === "removed-caller")
              await rm(component, { recursive: true });
            else await writeFile(join(component, "app.ts"), "fixed\n");
            await writeFile(
              join(repository, "unrelated.ts"),
              "unreported root edit\n",
            );
            completePatches(args, output);
          }
          return 0;
        },
      },
    );
    expect(modelCalls).toBe(1);
    expect(JSON.parse(outcome.stdout).patches).toMatchObject([
      { occurrenceId: "occ_1", status: "verified", files: ["app.ts"] },
    ]);
    expect(await readFile(join(repository, "unrelated.ts"), "utf8")).toBe(
      "unreported root edit\n",
    );
    expect(assessments).toBe(route === "saved" && !blocked ? 1 : 0);
    if (blocked) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        "Patch directory changed during patching",
      );
      if (operation === "directory-to-file")
        expect(await readFile(component, "utf8")).toBe("replacement fix\n");
      else if (operation === "removed-caller")
        await expect(readFile(join(component, "app.ts"))).rejects.toMatchObject(
          {
            code: "ENOENT",
          },
        );
      else {
        expect(await readFile(join(destination, "app.ts"), "utf8")).toBe(
          "fixed\n",
        );
        expect(await readFile(join(destination, "sibling.ts"), "utf8")).toBe(
          "original sibling\n",
        );
      }
      if (operation === "source-edit")
        expect(await readFile(join(component, "sibling.ts"), "utf8")).toBe(
          "unreported source edit\n",
        );
      if (operation === "source-replacement")
        expect(await readFile(component, "utf8")).toBe(
          "unreported source replacement\n",
        );
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("branch", "--show-current")).toBe("main");
      expect(await readFile(join(repository, ".git/index"))).toEqual(index);
      expect(git("ls-remote", "origin")).toBe("");
      expect(requestsCreated).toBe(0);
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      expect(requestsCreated).toBe(1);
      expect(git("show", "HEAD:component/app.ts")).toBe("fixed");
      expect(git("show", "HEAD:component/sibling.ts")).toBe("original sibling");
      expect(git("show", "HEAD:unrelated.ts")).toBe("unrelated original");
    }
  });
});

test.each(["absolute", "relative", "parent primary pool"])(
  "preserves %s nested alternates from an outside invocation",
  async (kind) => {
    const root = await temporaryDirectory("patch-outside-alternate-");
    const repository = join(root, "repository");
    const invocation = join(root, "invocation");
    const nested = join(repository, "nested");
    const pool =
      kind === "parent primary pool"
        ? join(repository, ".git", "objects")
        : join(invocation, "pool", "objects");
    try {
      await mkdir(repository);
      await mkdir(invocation);
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "maintenance.auto", "false");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      if (kind === "parent primary pool") {
        await cp(join(nested, ".git", "objects"), pool, {
          recursive: true,
          force: false,
        });
        await rm(join(nested, ".git", "objects"), { recursive: true });
      } else {
        await mkdir(dirname(pool));
        await rename(join(nested, ".git", "objects"), pool);
      }
      await mkdir(join(nested, ".git", "objects"));
      expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
      const gitEnvironment = {
        GIT_DIR: join(repository, ".git"),
        GIT_WORK_TREE: repository,
        GIT_ALTERNATE_OBJECT_DIRECTORIES:
          kind === "relative" ? relative(invocation, pool) : pool,
      };
      expect(
        gitText(
          [
            "--git-dir",
            join(nested, ".git"),
            "--work-tree",
            nested,
            "rev-parse",
            "HEAD^{tree}",
          ],
          { cwd: invocation, env: { ...process.env, ...gitEnvironment } },
        ).trim(),
      ).toMatch(/^[0-9a-f]+$/);
      let calls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: invocation,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output) => {
            calls++;
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
              await writeFile(join(nested, "app.ts"), "fixed\n");
              output?.stdout.write("Fixed and checked.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(calls).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["app.ts", "nested/app.ts"].map((file) =>
          relative(invocation, join(repository, file)).split(sep).join("/"),
        ),
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each(["absolute", "relative", "quoted relative"])(
  "preserves %s nested alternates after removing an outside invocation",
  async (kind) => {
    const root = await temporaryDirectory("patch-outside-alternate-");
    const repository = join(root, "repository");
    const invocation = join(root, "temporary", "invocation");
    const nested = join(repository, "nested");
    const pool = join(root, "pool with space", "objects");
    try {
      await mkdir(repository);
      await mkdir(invocation, { recursive: true });
      const git = repositoryGit(repository);
      git("init", "--initial-branch=main");
      git("config", "user.name", "Synthetic User");
      git("config", "user.email", "synthetic@example.test");
      await writeFile(join(repository, "app.ts"), "original\n");
      git("add", ".");
      git("commit", "-m", "Synthetic parent baseline");
      await mkdir(nested);
      const inner = repositoryGit(nested);
      inner("init", "--initial-branch=main");
      inner("config", "user.name", "Synthetic User");
      inner("config", "user.email", "synthetic@example.test");
      await writeFile(join(nested, "app.ts"), "original\n");
      inner("add", ".");
      inner("commit", "-m", "Synthetic nested baseline");
      await mkdir(dirname(pool));
      await rename(join(nested, ".git", "objects"), pool);
      await mkdir(join(nested, ".git", "objects"));
      expect(() => inner("rev-parse", "HEAD^{tree}")).toThrow();
      const gitEnvironment = {
        GIT_DIR: join(repository, ".git"),
        GIT_WORK_TREE: repository,
        GIT_ALTERNATE_OBJECT_DIRECTORIES:
          kind === "absolute"
            ? pool
            : kind === "relative"
              ? relative(invocation, pool)
              : JSON.stringify(relative(invocation, pool)),
      };
      expect(
        gitText(
          [
            "--git-dir",
            join(nested, ".git"),
            "--work-tree",
            nested,
            "rev-parse",
            "HEAD^{tree}",
          ],
          { cwd: invocation, env: { ...process.env, ...gitEnvironment } },
        ).trim(),
      ).toMatch(/^[0-9a-f]+$/);
      let calls = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: invocation,
          environment: { ...process.env, ...gitEnvironment },
          onRepositoryCommand: (command, args, cwd, options) =>
            runGitRepositoryCommand(command, args, cwd, {
              ...options,
              environment: { ...gitEnvironment, ...options?.environment },
            }),
          onCodex: async (_args, output) => {
            calls++;
            if (
              output?.appServer?.prompt.includes(
                "$codex-security:assess-patch-risk",
              )
            ) {
              output.stdout.write(patchRiskAssessment().report);
            } else {
              await writeFile(join(repository, "app.ts"), "fixed\n");
              await writeFile(join(nested, "app.ts"), "fixed\n");
              await rm(invocation, { recursive: true });
              output?.stdout.write("Fixed and checked.");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(calls).toBe(2);
      expect(JSON.parse(outcome.stdout)).toMatchObject({
        applied: true,
        files: ["app.ts", "nested/app.ts"].map((file) =>
          relative(invocation, join(repository, file)).split(sep).join("/"),
        ),
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

describe("patch Git metadata identity", () => {
  test.each(["stable", "retargeted"])(
    "preserves foreign objects for a %s caller alias",
    async (kind) => {
      const root = await temporaryDirectory("patch-metadata-binding-");
      const repository = join(root, "repository");
      const foreign = join(root, "foreign");
      const destination = join(repository, "ignored");
      const alias = join(repository, "alias");
      try {
        for (const checkout of [repository, foreign]) {
          await mkdir(checkout, { recursive: true });
          const git = repositoryGit(checkout);
          git("init", "--initial-branch=main");
          git("config", "user.name", "Synthetic User");
          git("config", "user.email", "synthetic@example.test");
          await writeFile(join(checkout, "app.ts"), "original\n");
          await writeFile(join(checkout, ".gitignore"), "alias\nignored/\n");
          git("add", ".");
          git("commit", "-m", "Synthetic baseline");
        }
        await symlink(
          repository,
          alias,
          process.platform === "win32" ? "junction" : "dir",
        );
        const outside = repositoryGit(foreign);
        const foreignHead = outside("rev-parse", "HEAD");
        const foreignIndex = await readFile(join(foreign, ".git", "index"));
        const foreignObjects = outside(
          "cat-file",
          "--batch-all-objects",
          "--batch-check=%(objectname)",
        );
        let modelCalls = 0;
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--json"],
          {
            currentDirectory: alias,
            onRepositoryCommand: runGitRepositoryCommand,
            onCodex: async (_args, output) => {
              modelCalls++;
              await writeFile(join(repository, "app.ts"), "fixed\n");
              if (kind === "retargeted") {
                await mkdir(destination);
                await writeFile(
                  join(destination, ".git"),
                  `gitdir: ${join(foreign, ".git")}\n`,
                );
                await rm(alias, { recursive: true });
                await symlink(
                  destination,
                  alias,
                  process.platform === "win32" ? "junction" : "dir",
                );
              }
              output?.stdout.write("Fixed and checked.");
              return 0;
            },
          },
        );
        expect(modelCalls, outcome.stderr).toBe(1);
        expect(outcome.exitCode, outcome.stderr).toBe(
          kind === "retargeted" ? 2 : 0,
        );
        if (kind === "retargeted")
          expect(outcome.stderr).toContain(
            "Git directory changed during patching",
          );
        else
          expect(JSON.parse(outcome.stdout)).toMatchObject({
            applied: true,
            files: ["app.ts"],
          });
        expect(
          outside(
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname)",
          ),
        ).toBe(foreignObjects);
        expect(outside("rev-parse", "HEAD")).toBe(foreignHead);
        expect(await readFile(join(foreign, ".git", "index"))).toEqual(
          foreignIndex,
        );
        expect(await readFile(join(foreign, "app.ts"), "utf8")).toBe(
          "original\n",
        );
        expect(await readFile(join(repository, "app.ts"), "utf8")).toBe(
          "fixed\n",
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    },
  );
});
