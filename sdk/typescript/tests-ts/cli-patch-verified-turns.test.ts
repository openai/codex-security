import { requestMetadata } from "./support/request-metadata.js";
import { hash } from "node:crypto";
import { afterEach, expect, test, describe } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { SeverityLevel } from "../src/index.js";
import type { OnCodex } from "./cli-fixtures.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";
import {
  completePatches,
  patchRiskSummary,
  patchRiskAssessment,
  patchRiskReport,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const publicationDirectories = createApiTestFixtures("codex-security-publish-");
afterEach(publicationDirectories.cleanup);

const initialPatchFiles = {
  "src/finding-1.ts": "unsafe\n",
  "unrelated.ts": "original\n",
};

async function publicationFixtures(
  files: Record<string, string> = {},
  severities: SeverityLevel[] = ["high"],
  scanId = "scan-1",
) {
  const root = await publicationDirectories.temporaryDirectory();
  const repository = join(root, "repository");
  const remote = join(root, "remote.git");
  await mkdir(join(repository, "src"), { recursive: true });
  const git = repositoryGit(repository);
  git("init", "--initial-branch=main");
  git("config", "user.name", "Synthetic User");
  git("config", "user.email", "synthetic@example.test");
  git("config", "commit.gpgsign", "false");
  for (const [path, contents] of Object.entries(files)) {
    const file = join(repository, path);
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, contents);
  }
  git("add", "--", ".");
  git("commit", "--allow-empty", "-m", "Initial synthetic checkout");
  git("init", "--bare", remote);
  git("remote", "add", "origin", remote);
  const result = resultWithFindings(severities);
  const onCodex: OnCodex = async (args, output) => {
    await writeFile(join(repository, "src", "finding-1.ts"), "fixed\n");
    completePatches(args, output);
    return 0;
  };
  return {
    git,
    remote,
    currentDirectory: repository,
    result,
    onWorkbench: () => savedScan(result, scanId, repository),
    onCodex,
  };
}

describe("saved-finding Git publication", () => {
  test("publishes only verified patch files and preserves unrelated staged changes", async () => {
    const fixtures = await publicationFixtures(
      initialPatchFiles,
      ["high", "medium"],
      "scan",
    );
    const { currentDirectory: repository, git, result } = fixtures;
    const url = "https://github.example.test/example/repository/pull/15";
    result.findings.findings[0]!.title = "Synthetic private finding";
    const detail = "Diagnostic detail: token=SYNTHETIC_RISK_VALUE";
    const summary = `${patchRiskSummary()}\n\n${detail}`;
    const expectedPullRequestBody = [
      "Applies verified security fixes from a completed scan.",
      "",
      "## Patch risk assessment",
      "",
      summary,
    ].join("\n");
    let pullRequestArguments: readonly string[] = [];
    const githubCommands: string[][] = [];
    const dependency = "src/dependency";
    git(
      "-c",
      "protocol.file.allow=always",
      "submodule",
      "add",
      "--",
      repository,
      dependency,
    );
    git("commit", "-m", "Add fixture dependency");
    git("config", "diff.ignoreSubmodules", "all");
    git("config", "submodule.src/dependency.ignore", "all");
    git("push", "--set-upstream", "origin", "main");
    // A real bare remote without push-options support rejects any leaked option.
    git("config", "--add", "push.pushOption", "merge_request.create");
    git(
      "config",
      "--add",
      "push.pushOption",
      "secret_push_protection.skip_all",
    );
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
        ...fixtures,
        onCodex: async (args, output) => {
          if (
            output?.appServer?.prompt.includes(
              "$codex-security:assess-patch-risk",
            )
          ) {
            expect(output.command).toBe("patch");
            expect(output.appServer?.sandbox).toBe("read-only");
            expect(requestMetadata(args)).toMatchObject({
              codex_security_command: "assess-patch-risk",
            });
            expect(output.appServer?.prompt).toContain(
              "<!-- codex-security:patch-risk-summary:start -->",
            );
            expect(output.appServer?.prompt).toContain(
              "<!-- codex-security:patch-risk-summary:end -->",
            );
            expect(output.appServer?.prompt).toContain(
              "--helper validate-patch-risk-assessment <assessment.json>",
            );
            expect(output.appServer?.prompt).toContain(
              "references/windows-validation.md",
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
            expect(artifact.changedFiles.sort()).toEqual([
              dependency,
              `${dependency}/.gitmodules`,
              `${dependency}/${dependency}`,
              "src/finding-1.ts",
            ]);
            expect(patch.toString()).toContain(
              "+Subproject commit " +
                git("-C", dependency, "rev-parse", "HEAD"),
            );
            expect(patch.toString()).toContain("+fixed  \n");
            expect(hash("sha256", patch)).toBe(artifact.sha256);
            output.stdout.write(patchRiskAssessment(summary).report);
            return 0;
          }
          await writeFile(
            join(repository, "src/finding-1.ts"),
            "intermediate\n",
          );
          git("add", "--", "src/finding-1.ts");
          git("-C", dependency, "fetch", "origin", "main");
          git("-C", dependency, "checkout", "--detach", "FETCH_HEAD");
          await writeFile(join(repository, "src", "finding-1.ts"), "fixed  \n");
          output!.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["src", "unrelated.ts"],
                  verification: "Focused checks pass.",
                },
              ],
            }),
          );
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
            if (args[0] === "push") {
              const branch = git("symbolic-ref", "HEAD");
              const verified = git("rev-parse", branch);
              const later = git(
                "commit-tree",
                "HEAD^{tree}",
                "-p",
                verified,
                "-m",
                "Later commit",
              );
              git("update-ref", branch, later, verified);
              try {
                return runGitRepositoryCommand(
                  command,
                  args,
                  workingDirectory,
                  commandOptions,
                );
              } finally {
                git("update-ref", branch, verified, later);
              }
            }
            return runGitRepositoryCommand(
              command,
              args,
              workingDirectory,
              commandOptions,
            );
          }
          githubCommands.push([...args]);
          if (args[1] === "list") return "[]";
          pullRequestArguments = args;
          return url;
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(outcome.stderr).toContain("Patch risk assessment:");
    expect(outcome.stderr).toContain(summary);
    expect(git("branch", "--show-current")).toBe("codex-security/patch-scan");
    expect(git("rev-parse", "--abbrev-ref", "@{upstream}")).toBe(
      "origin/codex-security/patch-scan",
    );
    expect(
      git(
        "show",
        "--ignore-submodules=none",
        "--format=",
        "--name-only",
        "HEAD",
      ),
    ).toBe(dependency + "\nsrc/finding-1.ts");
    expect(
      git("rev-parse", "origin/codex-security/patch-scan:" + dependency),
    ).toBe(git("-C", dependency, "rev-parse", "HEAD"));
    expect(git("show", ":src/finding-1.ts")).toBe("intermediate");
    expect(outcome.stderr).toContain("Could not update local staging");
    expect(git("show", ":unrelated.ts")).toBe("staged separately");
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
      patchRisk: { report: patchRiskReport(summary) },
    });
    expect(outcome.stdout).not.toContain("codex-security:patch-risk-summary");
  });

  test.each([
    "unchanged",
    "edited, both names",
    "edited, destination only",
  ] as const)(
    "publishes a staged case-only rename with a sibling edit (%s)",
    async (mode) => {
      const fixtures = await publicationFixtures({ other: "old\n" }, [
        "high",
        "high",
      ]);
      const { currentDirectory: repository, git, remote } = fixtures;
      let turn = 0;
      let aliases = false;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          ...fixtures,
          onCodex: async (_args, output) => {
            turn++;
            let files: string[];
            if (turn === 1) {
              await writeFile(join(repository, "README"), "original\n");
              git("add", "--", "README");
              aliases = await readFile(join(repository, "readme")).then(
                () => true,
                () => false,
              );
              files = ["README"];
            } else {
              git("mv", "--", "README", "intermediate");
              git("mv", "--", "intermediate", "readme");
              if (mode !== "unchanged")
                await writeFile(join(repository, "readme"), "edited\n");
              await writeFile(join(repository, "other"), "sibling\n");
              git("add", "--", "readme", "other");
              files =
                mode === "edited, both names"
                  ? ["README", "readme", "other"]
                  : ["readme", "other"];
            }
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: `occ_${turn}`,
                    status: "verified",
                    files,
                    verification: "Verified the selected patch files.",
                  },
                ],
              }),
            );
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "create"
                ? "https://github.example.test/example/repo/pull/1"
                : "[]",
        },
      );
      if (mode === "edited, destination only") {
        expect(outcome.exitCode).toBe(2);
        if (aliases)
          expect(outcome.stderr + outcome.stdout).toContain(
            "Multiple changed Git paths",
          );
        expect(git("ls-remote", remote)).toBe("");
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(git("ls-remote", remote)).toContain(git("rev-parse", "HEAD"));
      expect(git("show", "HEAD:readme")).toBe(
        mode === "unchanged" ? "original" : "edited",
      );
      expect(git("show", "HEAD:other")).toBe("sibling");
      expect(git("ls-tree", "--name-only", "HEAD", "README")).toBe("");
    },
  );

  test.each(["edited", "ambiguous"] as const)(
    "publishes the destination without inferring an %s source deletion",
    async (kind) => {
      const files = {
        "a.ts": "original\n",
        ...(kind === "ambiguous" ? { "b.ts": "original\n" } : {}),
      };
      const fixtures = await publicationFixtures(files);
      const { currentDirectory, result, git } = fixtures;
      result.findings.findings[0]!.locations[0]!.path = "new.ts";
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          ...fixtures,
          onCodex: async (args, output) => {
            for (const source of Object.keys(files))
              await rm(join(currentDirectory, source));
            await writeFile(
              join(currentDirectory, "new.ts"),
              kind === "edited" ? "fixed\n" : "original\n",
            );
            completePatches(args, output);
            return 0;
          },
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "create"
                ? "https://github.example.test/example/repository/pull/1"
                : "[]",
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(
        git("diff", "--name-status", "--no-renames", "HEAD^", "HEAD"),
      ).toBe("A\tnew.ts");
      expect(git("show", "HEAD:a.ts")).toBe("original");
    },
  );

  test.each([
    ["entry/child", "entry"],
    ["entry", "entry/\uFFFD"],
  ])("publishes two verified turns replacing %s with %s", async (from, to) => {
    const fixtures = await publicationFixtures({ [from]: "original\n" }, [
      "high",
      "high",
    ]);
    const { currentDirectory: repository, git, remote, result } = fixtures;
    let expectedTree = "";
    result.findings.findings[0]!.locations[0]!.path = from;
    result.findings.findings[1]!.locations[0]!.path = "entry";
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        ...fixtures,
        onCodex: async (args, output) => {
          const [finding] = completePatches(args, output);
          if (finding!.occurrenceId === "occ_1") {
            await writeFile(join(repository, from), "first fix\n");
          } else {
            git("rm", "-f", "--", from);
            await mkdir(dirname(join(repository, to)), { recursive: true });
            await writeFile(join(repository, to), "second fix\n");
            if (from === "entry" && process.platform === "linux") {
              // These two sibling names are identical after UTF-8 decoding.
              const rawName = Buffer.concat([
                Buffer.from(join(repository, "entry") + "/"),
                Buffer.from([0xff]),
              ]);
              await writeFile(rawName, "raw filename fix\n");
            }
            git("add", "--", "entry");
            expectedTree = git("write-tree");
          }
          return 0;
        },
        onRepositoryCommand: (cmd, args, cwd, options) => {
          if (cmd === "gh")
            return args[1] === "create"
              ? "https://github.example.test/example/repository/pull/1"
              : "[]";
          return runGitRepositoryCommand(cmd, args, cwd, options);
        },
      },
    );

    expect(outcome.exitCode, outcome.stderr).toBe(0);
    const branch = "codex-security/patch-scan-1";
    const published = repositoryGit(remote);
    expect(published("rev-parse", `${branch}^{tree}`)).toBe(expectedTree);
    expect(published("show", `${branch}:${to}`)).toBe("second fix");
    expect(git("status", "--porcelain")).toBe("");
  });
});

test.each([
  ["worktree", "pre-existing changes"],
  ["index", "pre-existing changes"],
  ["after verification", "differs from the verified changes"],
  ["ignored input", "ignored and untracked before patching"],
  ["intent-to-add", "pre-existing changes"],
  ["earlier turn", "earlier unverified changes"],
  ["parent commit", "base changed during verification"],
] as const)(
  "keeps local edits out of saved finding publication: %s",
  async (when, diagnostic) => {
    const path = "app.ts";
    const ignored = when === "ignored input" || when === "intent-to-add";
    const fixtures = await publicationFixtures(
      { [path]: "original\n", ".gitignore": ignored ? path + "\n" : "" },
      when === "earlier turn" ? ["high", "high"] : ["high"],
    );
    const { currentDirectory: repository, git } = fixtures;
    let turn = 0;
    let pushed = false;
    if (when === "intent-to-add") git("add", "-N", "-f", "--", path);
    if (when === "worktree" || when === "index") {
      await writeFile(join(repository, path), "in progress\n");
      if (when === "index") {
        git("add", "--", path);
        await writeFile(join(repository, path), "original\n");
      }
    }

    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        ...fixtures,
        onCodex: async (_args, output) => {
          turn++;
          const reported =
            when === "earlier turn" && turn === 1 ? "other.ts" : path;
          if (ignored) await writeFile(join(repository, ".gitignore"), "");
          if (when === "parent commit")
            git("commit", "--allow-empty", "-m", "Separate commit");
          if (reported !== path)
            await writeFile(join(repository, path), "first turn\n");
          await writeFile(join(repository, reported), `updated ${turn}\n`, {
            flag: when === "intent-to-add" ? "a" : "w",
          });
          if (when === "intent-to-add") git("add", "--", reported);
          output!.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: `occ_${turn}`,
                  status: "verified",
                  files: [reported],
                  verification: "Focused checks pass.",
                },
              ],
            }),
          );
          return 0;
        },
        onRepositoryCommand: async (cmd, args, cwd, options) => {
          if (when === "after verification" && args[0] === "switch") {
            await writeFile(join(repository, path), "later edit\n");
          }
          if (args[0] === "push" || (cmd === "gh" && args[1] === "create"))
            pushed = true;
          if (cmd === "gh") return "[]";
          return runGitRepositoryCommand(cmd, args, cwd, options);
        },
      },
    );
    expect(outcome.exitCode).toBe(2);
    expect(outcome.stderr).toContain(diagnostic);
    expect(pushed).toBe(false);
    if (when !== "after verification")
      expect(git("branch", "--show-current")).toBe("main");
    if (when === "index") expect(git("show", ":" + path)).toBe("in progress");
    if (when === "intent-to-add")
      expect(git("show", ":" + path)).toBe("original\nupdated 1");
  },
);
