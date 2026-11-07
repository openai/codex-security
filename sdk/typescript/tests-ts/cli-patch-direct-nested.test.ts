import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { LinearClientFactory } from "../src/linear.js";
import { emptyPage } from "./support/linear-pagination.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchRiskAssessment,
  publicationRepository,
  readAppliedText,
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

const cases = [
  ...(["literal", "file", "linear"] as const).flatMap((source) =>
    [false, true].map((parentEdit) => ({
      source,
      parentEdit,
      childEdit: true,
      committed: false,
      risk: false,
      publish: true,
    })),
  ),
  {
    source: "literal",
    parentEdit: false,
    childEdit: true,
    committed: true,
    risk: false,
    publish: true,
  },
  {
    source: "literal",
    parentEdit: true,
    childEdit: true,
    committed: false,
    risk: true,
    publish: true,
  },
  {
    source: "literal",
    parentEdit: true,
    childEdit: false,
    committed: false,
    risk: false,
    publish: true,
  },
  {
    source: "literal",
    parentEdit: true,
    childEdit: true,
    committed: false,
    risk: false,
    publish: false,
  },
] as const;

for (const {
  source,
  parentEdit,
  childEdit,
  committed,
  risk,
  publish,
} of cases) {
  test(`direct ${source} patch tracks nested changes (parent: ${parentEdit}, child: ${childEdit}, committed: ${committed}, risk: ${risk}, publish: ${publish})`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    const nested = join(directory, "nested");
    await mkdir(nested);
    const child = repositoryGit(nested);
    child("init", "--initial-branch=main");
    child("config", "user.name", "Synthetic User");
    child("config", "user.email", "synthetic@example.test");
    await writeFile(join(nested, "app.ts"), "original\n");
    child("add", ".");
    child("commit", "-m", "Synthetic child baseline");
    const childRemote = await fixtures.create("direct-patch-child-origin-");
    git("clone", "--bare", nested, childRemote);
    child("remote", "add", "origin", childRemote);
    child("fetch", "origin");
    git("config", "-f", ".gitmodules", "submodule.nested.path", "nested");
    git("config", "-f", ".gitmodules", "submodule.nested.url", childRemote);
    git("add", ".gitmodules", "nested");
    git("commit", "-m", "Synthetic registered child");
    git("submodule", "init");
    git("submodule", "absorbgitdirs", "--", "nested");
    const rootHead = git("rev-parse", "HEAD");
    const childHead = child("rev-parse", "HEAD");
    const childRefs = child("ls-remote", "origin");
    const rootIndexPath = join(directory, ".git", "index");
    const childIndexPath = join(
      child("rev-parse", "--absolute-git-dir"),
      "index",
    );
    let rootIndex: Buffer<ArrayBuffer> | undefined;
    let childIndex: Buffer<ArrayBuffer> | undefined;
    let turns = 0;
    let assessments = 0;
    let updatedChild = childHead;
    let publications = 0;
    let mutations = 0;
    const issue = join(
      await fixtures.create("direct-patch-issue-"),
      "issue.md",
    );
    await writeFile(issue, "Synthetic issue in nested/app.ts\n");
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
          : [source === "file" ? issue : "Synthetic issue in nested/app.ts"]),
        ...(publish ? ["--create-pr"] : []),
        ...(risk ? ["--assess-patch-risk"] : []),
        "--json",
      ],
      {
        currentDirectory: directory,
        linearClient: () =>
          ({
            issue: async () => ({
              identifier: "SEC-123",
              title: "Synthetic issue",
              description: "Fix nested/app.ts",
              url: "https://linear.app/example/issue/SEC-123",
              comments: emptyPage,
            }),
          }) as unknown as ReturnType<LinearClientFactory>,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git") {
            const operation = args[0] === "-C" ? args[2] : args[0];
            if (["switch", "commit", "push"].includes(operation!)) mutations++;
            return runGitRepositoryCommand(command, args, cwd, options);
          }
          if (args[1] === "list") return "[]";
          publications++;
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
            ) as { changedFiles: string[] };
            expect(artifact.changedFiles).toContain("nested/app.ts");
            expect(artifact.changedFiles).toContain("src/finding-1.ts");
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          turns++;
          expect(output?.appServer?.prompt).toContain(
            "$codex-security:fix-finding",
          );
          rootIndex = await readFile(rootIndexPath);
          childIndex = await readFile(childIndexPath);
          if (childEdit)
            await writeFile(join(nested, "app.ts"), "fixed child\n");
          if (committed) {
            child("commit", "-am", "Synthetic child fix");
            updatedChild = child("rev-parse", "HEAD");
            child("push", "origin", "HEAD:refs/heads/main");
            childIndex = await readFile(childIndexPath);
          }
          if (parentEdit)
            await writeFile(
              join(directory, "src/finding-1.ts"),
              "fixed parent\n",
            );
          output?.stdout.write("Synthetic fix complete.");
          return 0;
        },
      },
    );
    expect(turns).toBe(1);
    expect(assessments).toBe(risk ? 1 : 0);
    const response = JSON.parse(outcome.stdout);
    const expectedFiles = [
      ...(childEdit ? ["nested/app.ts"] : []),
      ...(committed ? ["nested"] : []),
      ...(parentEdit ? ["src/finding-1.ts"] : []),
    ].sort();
    if (committed) expect(response.files).toContain("nested");
    else expect(response.files).toEqual(expectedFiles);
    const rejected = publish && childEdit && !committed;
    const published = publish && !rejected;
    expect(outcome.exitCode, outcome.stderr).toBe(rejected ? 2 : 0);
    if (rejected) {
      expect(outcome.stderr).toContain(join("nested", "app.ts"));
      expect(outcome.stderr).not.toContain("No patch was applied");
    }
    expect(publications).toBe(published ? 1 : 0);
    expect(mutations).toBe(published ? 3 : 0);
    if (published) {
      expect(git("rev-parse", "HEAD")).not.toBe(rootHead);
      expect(response.pullRequest.url).toBe(
        "https://github.example.test/example/repository/pull/1",
      );
      expect(
        git("ls-remote", "origin", `refs/heads/${response.pullRequest.branch}`),
      ).toBe(
        `${git("rev-parse", "HEAD")}\trefs/heads/${response.pullRequest.branch}`,
      );
      expect(git("ls-tree", "HEAD", "nested")).toBe(
        `160000 commit ${updatedChild}\tnested`,
      );
      expect(git("diff", "--cached", "--exit-code")).toBe("");
    } else {
      expect(git("rev-parse", "HEAD")).toBe(rootHead);
      expect(git("rev-parse", "--abbrev-ref", "HEAD")).toBe("main");
      expect(await readFile(rootIndexPath)).toEqual(rootIndex!);
      expect(git("ls-remote", "origin")).toBe("");
    }
    expect(child("rev-parse", "HEAD")).toBe(updatedChild);
    expect(await readFile(childIndexPath)).toEqual(childIndex!);
    if (committed)
      expect(child("ls-remote", "origin", "refs/heads/main")).toBe(
        `${updatedChild}\trefs/heads/main`,
      );
    else expect(child("ls-remote", "origin")).toBe(childRefs);
    expect(await readAppliedText(join(nested, "app.ts"))).toBe(
      childEdit ? "fixed child\n" : "original\n",
    );
    expect(await readAppliedText(join(directory, "src/finding-1.ts"))).toBe(
      parentEdit ? "fixed parent\n" : "original\n",
    );
  });
}

for (const source of ["literal", "file"] as const) {
  test(`direct ${source} patch still edits an ordinary directory without Git`, async () => {
    const directory = await fixtures.create("direct-patch-no-git-");
    const issue = join(
      await fixtures.create("direct-patch-no-git-issue-"),
      "issue.md",
    );
    await writeFile(issue, "Synthetic ordinary-file issue\n");
    await writeFile(join(directory, "app.ts"), "original\n");
    let turns = 0;
    const outcome = await runWorkflow(
      [
        "patch",
        source === "file" ? issue : "Synthetic ordinary-file issue",
        "--json",
      ],
      {
        currentDirectory: directory,
        onRepositoryCommand: runGitRepositoryCommand,
        onCodex: async (_args, output) => {
          turns++;
          expect(output?.appServer?.prompt).toContain(
            "$codex-security:fix-finding",
          );
          await writeFile(join(directory, "app.ts"), "fixed\n");
          output?.stdout.write("Synthetic ordinary-file fix complete.");
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(turns).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
    expect(await readAppliedText(join(directory, "app.ts"))).toBe("fixed\n");
  });
}
