import { afterEach, expect, test } from "bun:test";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  completePatches,
  patchRiskAssessment,
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  ...["unchanged", "stage unrelated", "rewrite selected"].flatMap((hook) =>
    [false, true].map((assess) => ({
      hook,
      assess,
      lostResult: false,
      scope: "root",
    })),
  ),
  ...["stage unrelated", "rewrite selected"].map((hook) => ({
    hook,
    assess: true,
    lostResult: true,
    scope: "root",
  })),
  ...["root", "src"].map((scope) => ({
    hook: "post-index stage unrelated",
    assess: true,
    lostResult: false,
    scope,
  })),
])(
  "checks the committed tree after a $hook hook, assessment=$assess, lost result=$lostResult, scope=$scope",
  async ({ hook, assess, lostResult, scope }) => {
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "other.ts"), "original unrelated\n");
    git("add", "other.ts");
    git("commit", "-m", "Synthetic unrelated file");
    await writeFile(join(directory, "other.ts"), "unrelated local edit\n");
    const postIndex = hook === "post-index stage unrelated";
    const hooks = join(directory, ".git", "hooks");
    const hookPath = join(
      hooks,
      postIndex ? "post-index-change" : "pre-commit",
    );
    git("config", "--local", "core.hooksPath", hooks);
    await writeFile(
      hookPath,
      [
        "#!/bin/sh",
        "set -eu",
        ...(postIndex
          ? [
              'case "${GIT_INDEX_FILE:-}" in *codex-security-patch-tree-*) ;; *) exit 0;; esac',
              '[ "$(git branch --show-current)" = "codex-security/patch-scan-1" ] || exit 0',
            ]
          : []),
        "printf 'hook ran\\n' > .git/hook-ran",
        postIndex
          ? "git -c core.hooksPath=/dev/null add -A"
          : hook === "stage unrelated"
            ? "git add -A"
            : hook === "rewrite selected"
              ? "printf 'hook rewritten\\n' > src/finding-1.ts\ngit add -- src/finding-1.ts"
              : ":",
        "",
      ].join("\n"),
    );
    await chmod(hookPath, 0o755);
    const indexPath = git(
      "rev-parse",
      "--path-format=absolute",
      "--git-path",
      "index",
    );
    let indexBefore: Buffer<ArrayBuffer> | undefined;
    let assessments = 0;
    let pushes = 0;
    let creations = 0;
    const cwd = scope === "root" ? directory : join(directory, scope);
    const result = resultWithFindings(["high"]);
    if (scope !== "root")
      result.findings.findings[0]!.locations[0]!.path = "finding-1.ts";
    const onRepositoryCommand: typeof runGitRepositoryCommand = async (
      command,
      args,
      cwd,
      options,
    ) => {
      if (command === "git") {
        const gitArgs = args[0] === "-C" ? args.slice(2) : args;
        if (gitArgs[0] === "switch" && gitArgs[1] === "-c")
          indexBefore = await readFile(indexPath);
        if (gitArgs[0] === "push") pushes++;
        const output = await runGitRepositoryCommand(
          command,
          args,
          cwd,
          options,
        );
        if (lostResult && gitArgs[0] === "commit")
          throw new Error("Synthetic commit result lost.");
        return output;
      }
      if (args[1] === "create") creations++;
      return args[1] === "list"
        ? "[]"
        : "https://github.example.test/example/repository/pull/1";
    };
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        ...(assess ? ["--assess-patch-risk"] : []),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: cwd,
        result,
        onWorkbench: () => savedScan(result, "scan-1", cwd),
        onRepositoryCommand,
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
            ) as { path: string; changedFiles: string[] };
            expect(artifact.changedFiles).toEqual(["src/finding-1.ts"]);
            const patch = await readFile(artifact.path, "utf8");
            expect(patch).toContain("+fixed");
            expect(patch).not.toContain("unrelated local edit");
            expect(patch).not.toContain("hook rewritten");
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          completePatches(args, output);
          return 0;
        },
      },
    );
    expect(assessments).toBe(assess ? 1 : 0);
    expect(await readFile(join(directory, ".git", "hook-ran"), "utf8")).toBe(
      "hook ran\n",
    );
    expect(await readFile(join(directory, "other.ts"), "utf8")).toBe(
      "unrelated local edit\n",
    );
    const branch = "codex-security/patch-scan-1";
    expect(git("show", "HEAD:src/finding-1.ts")).toBe(
      hook === "rewrite selected" ? "hook rewritten" : "fixed",
    );
    expect(git("show", "HEAD:other.ts")).toBe(
      hook === "stage unrelated" || postIndex
        ? "unrelated local edit"
        : "original unrelated",
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      hook === "rewrite selected" ? "hook rewritten\n" : "fixed\n",
    );
    if (hook === "unchanged") {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(pushes).toBe(1);
      expect(creations).toBe(1);
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      expect(git("show", "HEAD:other.ts")).toBe("original unrelated");
      expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
      return;
    }
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain(
      lostResult
        ? "Synthetic commit result lost."
        : "The patch commit does not match the captured selected changes",
    );
    expect(pushes).toBe(0);
    expect(creations).toBe(0);
    expect(await readFile(indexPath)).toEqual(indexBefore!);
    expect(git("branch", "--show-current")).toBe(branch);
    expect(git("ls-remote", "origin")).toBe("");
    expect(
      git(
        "config",
        "--local",
        "--get",
        "--default",
        "",
        `branch.${branch}.codexSecurityPatchCommit`,
      ),
    ).toBe("");
    const resumed = await runWorkflow(
      ["patch", "--resume-pr", branch, "--json"],
      {
        currentDirectory: directory,
        onRepositoryCommand,
      },
    );
    expect(resumed.exitCode).toBe(2);
    expect(resumed.stderr).toContain(
      "No verified patch commit is saved for this branch.",
    );
    expect(pushes).toBe(0);
    expect(creations).toBe(0);
  },
);
