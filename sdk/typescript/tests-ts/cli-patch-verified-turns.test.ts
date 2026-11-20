import { requestMetadata } from "./support/request-metadata.js";
import { hash } from "node:crypto";
import { afterEach, expect, test, describe } from "bun:test";
import { mkdir, readFile, rm, writeFile, symlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { SeverityLevel } from "../src/index.js";
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
  initializePatchGit,
  patchArtifactFromPrompt,
  runPublicationWorkflow,
  publicationRepository,
  fixSavedFinding,
} from "./cli-patch-fixtures.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

const directories = createApiTestFixtures("codex-security-publish-");
afterEach(directories.cleanup);

const initialPatchFiles = {
  "src/finding-1.ts": "unsafe\n",
  "unrelated.ts": "original\n",
};

async function publicationFixtures(
  files: Record<string, string> = {},
  severities: SeverityLevel[] = ["high"],
  scanId = "scan-1",
) {
  const root = await directories.temporaryDirectory();
  const repository = join(root, "repository");
  const remote = join(root, "remote.git");
  await mkdir(join(repository, "src"), { recursive: true });
  const git = initializePatchGit(repository);
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
  return {
    git,
    remote,
    currentDirectory: repository,
    result,
    onWorkbench: () => savedScan(result, scanId, repository),
    onCodex: fixSavedFinding(repository),
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
            const artifact = patchArtifactFromPrompt(output.appServer!.prompt);
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

  test.each(["src", "SRC"])(
    "publishes the staged case-only rename of an entry already in HEAD under reported directory %s",
    async (directory) => {
      const fixtures = await publicationFixtures({
        "src/README": "original\n",
        "src/sibling": "old\n",
      });
      const { currentDirectory: repository, git, remote, result } = fixtures;
      result.findings.findings[0]!.locations[0]!.path = directory;
      const selectsDirectory = await readFile(
        join(repository, directory, "README"),
      ).then(
        () => true,
        () => false,
      );
      const index = join(repository, ".git", "index");
      let checkedIndex = false;
      const outcome = await runPublicationWorkflow("scan", {
        ...fixtures,
        onCodex: async (args, output) => {
          git("mv", "--", "src/README", "src/intermediate");
          git("mv", "--", "src/intermediate", "src/readme");
          await writeFile(join(repository, "src/readme"), "edited\n");
          git("add", "--", "src/readme");
          await writeFile(join(repository, "src/sibling"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
        onRepositoryCommand: async (command, args, cwd, options) => {
          if (command !== "git")
            return args[1] === "create"
              ? "https://github.example.test/example/repo/pull/1"
              : "[]";
          if (
            !checkedIndex &&
            args.includes("--index-info") &&
            Buffer.isBuffer(options?.input) &&
            options.input.toString("latin1").startsWith("0 ") &&
            options?.environment?.["GIT_INDEX_FILE"]
          ) {
            const before = await readFile(index);
            const output = await runGitRepositoryCommand(
              command,
              args,
              cwd,
              options,
            );
            expect(await readFile(index)).toEqual(before);
            checkedIndex = true;
            return output;
          }
          return runGitRepositoryCommand(command, args, cwd, options);
        },
      });
      if (!selectsDirectory) {
        expect(outcome.exitCode).toBe(2);
        expect(git("ls-remote", remote)).toBe("");
        return;
      }
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(checkedIndex).toBe(true);
      expect(git("ls-remote", remote)).toContain(git("rev-parse", "HEAD"));
      expect(git("ls-tree", "-r", "--name-only", "HEAD", "src")).toBe(
        "src/readme\nsrc/sibling",
      );
      expect(git("show", "HEAD:src/readme")).toBe("edited");
      expect(git("show", "HEAD:src/sibling")).toBe("fixed");
    },
  );

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
      const outcome = await runPublicationWorkflow("scan", {
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
      });
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
      const outcome = await runPublicationWorkflow("scan", {
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
      });
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
    const outcome = await runPublicationWorkflow("scan", {
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
    });

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

    const outcome = await runPublicationWorkflow("scan", {
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
    });
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

type Flow = "saved patch" | "scan threshold";
type Report =
  "empty" | "unrelated" | "actual" | "directory" | "subset" | "preexisting";

async function checkVerifiedFiles(
  flow: Flow,
  report: Report,
  location:
    "root" | "subdirectory" | "linked root" | "non-Git" | "raw alias" = "root",
) {
  const repository =
    location === "non-Git"
      ? undefined
      : await publicationRepository(directories.temporaryDirectories);
  const directory =
    repository?.directory ??
    (await directories.temporaryDirectory("verified-files-"));
  if (!repository) {
    await mkdir(join(directory, "src"));
    await writeFile(join(directory, "src/finding-1.ts"), "original\n");
  }
  const git = repository?.git;
  await writeFile(join(directory, "unrelated.ts"), "unrelated baseline\n");
  const raw = Buffer.concat([
    Buffer.from(join(directory, "src", "raw-")),
    Buffer.from([0xff]),
  ]);
  const displayedRaw = "src/raw-\ufffd";
  if (location === "raw alias") {
    await writeFile(raw, "original raw\n");
    await writeFile(
      join(directory, displayedRaw),
      "distinct Unicode baseline\n",
    );
  }
  if (git) {
    git("add", ".");
    git("commit", "-m", "Synthetic verification baseline");
  }
  await writeFile(join(directory, "local.txt"), "staged local work\n");
  git?.("add", "local.txt");
  await writeFile(join(directory, "local.txt"), "unstaged local work\n");
  let target = location === "subdirectory" ? join(directory, "src") : directory;
  if (location === "linked root") {
    const links = await directories.temporaryDirectory(
      "verified-target-links-",
    );
    target = join(links, "target");
    await symlink(
      directory,
      target,
      process.platform === "win32" ? "junction" : "dir",
    );
  }
  const changedFile =
    report === "preexisting" ? "incidental.ts" : "src/finding-1.ts";
  const reportedActual =
    location === "subdirectory" ? "finding-1.ts" : changedFile;
  const files =
    report === "empty"
      ? []
      : report === "unrelated"
        ? ["unrelated.ts"]
        : report === "preexisting"
          ? ["local.txt"]
          : report === "directory"
            ? ["src"]
            : location === "raw alias"
              ? [displayedRaw]
              : [reportedActual];
  const invalid =
    ["empty", "unrelated", "preexisting"].includes(report) ||
    location === "raw alias";
  const publish =
    flow === "saved patch" &&
    repository !== undefined &&
    location !== "linked root";
  const head = git?.("rev-parse", "HEAD");
  const refs = git?.("ls-remote", "origin");
  const indexPath = git?.(
    "rev-parse",
    "--path-format=absolute",
    "--git-path",
    "index",
  );
  let indexBefore: Buffer<ArrayBuffer> | undefined;
  let turns = 0;
  let publications = 0;
  const result = resultWithFindings(["high"]);
  result.findings.findings[0]!.locations[0]!.path =
    location === "subdirectory" ? "finding-1.ts" : "src/finding-1.ts";
  const outcome = await runWorkflow(
    [
      ...(flow === "saved patch"
        ? ["patch", "--scan", "scan-1"]
        : ["scan", "--patch", "--fail-on-severity", "high"]),
      ...(publish ? ["--create-pr"] : []),
      "--json",
    ],
    {
      currentDirectory: target,
      result,
      onWorkbench: () => savedScan(result, "scan-1", target),
      onRepositoryCommand: (command, args, cwd, options) => {
        if (command === "git")
          return runGitRepositoryCommand(command, args, cwd, options);
        if (args[1] === "create") publications++;
        return args[1] === "list"
          ? "[]"
          : "https://github.example.test/example/repository/pull/1";
      },
      onCodex: async (_args, output) => {
        turns++;
        if (indexPath) indexBefore = await readFile(indexPath);
        await writeFile(
          location === "raw alias" ? raw : join(directory, changedFile),
          "verified edit\n",
        );
        if (report === "subset")
          await writeFile(
            join(directory, "extra.ts"),
            "unreported turn edit\n",
          );
        output?.stdout.write(
          JSON.stringify({
            patches: [
              {
                occurrenceId: "occ_1",
                status: "verified",
                files,
                verification: "Synthetic focused verification passed.",
              },
            ],
          }),
        );
        return 0;
      },
    },
  );
  expect(turns).toBe(1);
  expect(outcome.exitCode, outcome.stderr).toBe(invalid ? 2 : 0);
  const value = JSON.parse(outcome.stdout);
  expect(value.patches[0]).toMatchObject(
    invalid
      ? {
          occurrenceId: "occ_1",
          status: "failed",
          reason: "Patch verification did not identify any changed files.",
        }
      : { occurrenceId: "occ_1", status: "verified", files },
  );
  if (invalid && flow === "saved patch")
    expect(value.error.code).toBe("PATCH_FAILED");
  expect(publications).toBe(!invalid && publish ? 1 : 0);
  if (invalid || !publish) {
    expect(value).not.toHaveProperty("pullRequest");
    if (git && indexPath) {
      expect(git("rev-parse", "HEAD")).toBe(head!);
      expect(git("branch", "--show-current")).toBe("main");
      expect(git("ls-remote", "origin")).toBe(refs!);
      expect(await readFile(indexPath)).toEqual(indexBefore!);
    }
  } else if (git) {
    expect(git("show", `HEAD:${changedFile}`)).toBe("verified edit");
    expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
    if (report === "subset")
      expect(git("ls-tree", "HEAD", "extra.ts")).toBe("");
  }
  if (git) expect(git("show", ":local.txt")).toBe("staged local work");
  expect(await readFile(join(directory, "local.txt"), "utf8")).toBe(
    "unstaged local work\n",
  );
  expect(
    await readFile(
      location === "raw alias" ? raw : join(directory, changedFile),
      "utf8",
    ),
  ).toBe("verified edit\n");
  if (report === "subset")
    expect(await readFile(join(directory, "extra.ts"), "utf8")).toBe(
      "unreported turn edit\n",
    );
  if (location === "raw alias")
    expect(await readFile(join(directory, displayedRaw), "utf8")).toBe(
      "distinct Unicode baseline\n",
    );
}

for (const flow of ["saved patch", "scan threshold"] as const) {
  test.each([
    "empty",
    "unrelated",
    "actual",
    "directory",
    "subset",
    "preexisting",
  ] as const)(
    `${flow} verifies reported %s paths against the current turn`,
    async (report) => checkVerifiedFiles(flow, report),
  );
}
test("saved patch matches changes beneath a scanned Git subdirectory", async () =>
  checkVerifiedFiles("saved patch", "actual", "subdirectory"));
test("saved patch matches changes through a linked target root", async () =>
  checkVerifiedFiles("saved patch", "actual", "linked root"));
test.each(["empty", "actual"] as const)(
  "scan threshold verifies %s paths without Git",
  async (report) => checkVerifiedFiles("scan threshold", report, "non-Git"),
);
test.skipIf(process.platform !== "linux")(
  "scan threshold distinguishes raw Git paths from a Unicode filename",
  async () => checkVerifiedFiles("scan threshold", "actual", "raw alias"),
);

for (const flow of ["saved patch", "scan threshold"] as const) {
  test.each(["none", "tracked", "untracked"] as const)(
    `${flow} checks a no_change result against %s edits`,
    async (edit) => {
      const { directory, git } = await publicationRepository(
        directories.temporaryDirectories,
      );
      await writeFile(join(directory, "local.txt"), "staged local work\n");
      git("add", "local.txt");
      await writeFile(join(directory, "local.txt"), "unstaged local work\n");
      const head = git("rev-parse", "HEAD");
      const refs = git("ls-remote", "origin");
      const indexPath = git(
        "rev-parse",
        "--path-format=absolute",
        "--git-path",
        "index",
      );
      let indexBefore: Buffer<ArrayBuffer> | undefined;
      let turns = 0;
      let publications = 0;
      const result = resultWithFindings(["high"]);
      const changedFile =
        edit === "tracked" ? "src/finding-1.ts" : "new-file.ts";
      const outcome = await runWorkflow(
        [
          ...(flow === "saved patch"
            ? ["patch", "--scan", "scan-1"]
            : ["scan", "--patch", "--fail-on-severity", "high"]),
          "--create-pr",
          "--json",
        ],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git")
              return runGitRepositoryCommand(command, args, cwd, options);
            if (args[1] === "create") publications++;
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            turns++;
            indexBefore = await readFile(indexPath);
            if (edit !== "none")
              await writeFile(
                join(directory, changedFile),
                "unverified edit\n",
              );
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "no_change",
                    files: [],
                    verification: "Synthetic verification reported no change.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(turns).toBe(1);
      expect(outcome.exitCode, outcome.stderr).toBe(
        edit === "none" && flow === "scan threshold" ? 0 : 2,
      );
      const value = JSON.parse(outcome.stdout);
      expect(value.patches).toEqual([
        expect.objectContaining(
          edit === "none"
            ? { occurrenceId: "occ_1", status: "no_change", files: [] }
            : {
                occurrenceId: "occ_1",
                status: "failed",
                files: [changedFile],
                reason: "Patch reported no changes, but files changed.",
              },
        ),
      ]);
      if (flow === "saved patch") {
        expect(value.error.code).toBe(
          edit === "none" ? "NO_PATCH_APPLIED" : "PATCH_FAILED",
        );
        expect(value.files).toEqual(edit === "none" ? [] : [changedFile]);
      }
      expect(value).not.toHaveProperty("pullRequest");
      expect(publications).toBe(0);
      expect(git("branch", "--show-current")).toBe("main");
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(git("ls-remote", "origin")).toBe(refs);
      expect(await readFile(indexPath)).toEqual(indexBefore!);
      expect(await readFile(join(directory, "local.txt"), "utf8")).toBe(
        "unstaged local work\n",
      );
      if (edit !== "none")
        expect(await readFile(join(directory, changedFile), "utf8")).toBe(
          "unverified edit\n",
        );
    },
  );
}
