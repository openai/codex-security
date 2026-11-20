import { expect, test } from "bun:test";
import {
  mkdir,
  readFile,
  writeFile,
  rename,
  symlink,
  unlink,
} from "node:fs/promises";
import { join } from "node:path";
import type { LinearClientFactory } from "../src/linear.js";
import { emptyPage } from "./support/linear-pagination.js";
import {
  patchRiskAssessment,
  publicationRepository,
  readAppliedText,
  repositoryGit,
  runGitRepositoryCommand,
  runWorkflow,
  patchDirectories,
  initializePatchGit,
  runIssuePatch,
} from "./cli-patch-fixtures.js";
import { execFileSync } from "node:child_process";

const fixtures = patchDirectories();

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

test.each([
  { included: false, replaced: false, introduced: false },
  { included: true, replaced: false, introduced: false },
  { included: true, replaced: true, introduced: false },
  { included: false, replaced: false, introduced: true },
])(
  "patches ordinary tracked data containing bare Git fixtures (included config: $included, replaced: $replaced, introduced child: $introduced)",
  async ({ included, replaced, introduced }) => {
    const root = await fixtures.create("patch-bare-fixture-");
    const source = join(root, "source");
    const child = join(source, "child");
    await mkdir(child, { recursive: true });
    const app = join(root, "app.ts");
    const nestedApp = join(source, "app.ts");
    const configuration = join(source, "bare-settings");
    await writeFile(app, "before\n");
    await writeFile(nestedApp, "ordinary source\n");
    await writeFile(join(child, "input.ts"), "child source\n");
    if (included) await writeFile(configuration, "[core]\n bare = true\n");
    const git = initializePatchGit(root);
    git("add", ".");
    git("commit", "-m", "Synthetic fixture baseline");
    const administration = join(source, ".git");
    git("init", "--bare", "--initial-branch=main", administration);
    if (included) {
      git(
        "--git-dir",
        administration,
        "config",
        "include.path",
        "../bare-settings",
      );
    }
    const initializeChild = () => {
      git("init", "--initial-branch=main", child);
      git("-C", child, "config", "user.name", "Synthetic User");
      git("-C", child, "config", "user.email", "synthetic@example.test");
      git("-C", child, "add", "input.ts");
      git("-C", child, "commit", "-m", "Synthetic child baseline");
    };
    if (!introduced) initializeChild();
    expect(git("-C", source, "rev-parse", "--is-bare-repository")).toBe("true");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(root, ".git", "index"));
    const bareHead = await readFile(join(administration, "HEAD"));
    const bareConfig = await readFile(join(administration, "config"));
    let launches = 0;
    const nestedCommands: string[][] = [];
    const outcome = await runIssuePatch(root, {
      onRepositoryCommand: (command, args, cwd, options) => {
        if (
          [source, child, administration, join(child, ".git")].some(
            (path) => cwd === path || args.includes(path),
          )
        )
          nestedCommands.push([...args]);
        return runGitRepositoryCommand(command, args, cwd, options);
      },
      onCodex: async (_args, output) => {
        launches++;
        expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
          administration,
        );
        if (introduced) initializeChild();
        else
          expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
            join(child, ".git"),
          );
        if (included) {
          expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
            configuration,
          );
        }
        if (replaced) {
          await rename(configuration, join(source, "original-settings"));
          await writeFile(configuration, "[core]\n bare = false\n");
        }
        await writeFile(app, "after\n");
        await writeFile(nestedApp, "updated ordinary source\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(nestedCommands).toEqual([]);
    expect(JSON.parse(outcome.stdout).files.sort()).toEqual([
      "app.ts",
      "source/app.ts",
      ...(replaced ? ["source/bare-settings", "source/original-settings"] : []),
    ]);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(root, ".git", "index"))).toEqual(index);
    expect(await readFile(join(administration, "HEAD"))).toEqual(bareHead);
    expect(await readFile(join(administration, "config"))).toEqual(bareConfig);
    expect(await readFile(app, "utf8")).toBe("after\n");
    expect(await readFile(nestedApp, "utf8")).toBe("updated ordinary source\n");
  },
);

async function initialize(root: string) {
  const git = initializePatchGit(root);
  await writeFile(join(root, "app.ts"), "before\n");
  git("add", ".");
  git("commit", "-m", "Synthetic baseline");
  return git;
}

for (const raw of [false, true]) {
  test.skipIf(
    process.platform === "win32" || (raw && process.platform !== "linux"),
  )(
    `patch leaves a symlink replacing a tracked gitlink as data (raw name: ${raw})`,
    async () => {
      const root = await fixtures.create("patch-gitlink-symlink-");
      const foreign = await fixtures.create("patch-gitlink-unselected-");
      const support = await fixtures.create("patch-gitlink-support-");
      const git = await initialize(root);
      const other = await initialize(foreign);
      const source = join(root, "source");
      await mkdir(source);
      const inner = await initialize(source);
      const revision = inner("rev-parse", "HEAD");
      const name = raw
        ? Buffer.concat([Buffer.from("source-"), Buffer.from([0xff])])
        : Buffer.from("source");
      const selectedPath = Buffer.concat([Buffer.from(`${root}/`), name]);
      if (raw) await rename(source, selectedPath);
      execFileSync("git", ["update-index", "-z", "--index-info"], {
        cwd: root,
        input: Buffer.concat([
          Buffer.from(`160000 ${revision}\t`),
          name,
          Buffer.from([0]),
        ]),
      });
      git("commit", "-m", "Synthetic selected gitlink");
      await rename(selectedPath, join(support, "original"));
      await symlink(foreign, selectedPath);
      const effect = join(support, "hook-effect");
      const hook = join(foreign, ".git", "hooks", "synthetic-fsmonitor");
      await writeFile(
        hook,
        `#!/bin/sh\nprintf effect > '${effect.replaceAll("'", "'\\''")}'\nprintf '\\0'\n`,
        { mode: 0o755 },
      );
      other("config", "core.fsmonitor", hook);
      other("ls-files", "--cached");
      expect(await readFile(effect, "utf8")).toBe("effect");
      await unlink(effect);
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(root, ".git", "index"));
      const otherHead = other("rev-parse", "HEAD");
      const otherIndex = await readFile(join(foreign, ".git", "index"));
      const targetCommands: string[][] = [];
      let launches = 0;
      const outcome = await runIssuePatch(root, {
        onRepositoryCommand: (command, args, cwd, options) => {
          if (
            cwd === foreign ||
            args.some((arg) => arg === foreign || arg.startsWith(`${foreign}/`))
          )
            targetCommands.push([...args]);
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          launches++;
          expect(output?.appServer?.permissions?.readOnlyPaths).not.toContain(
            join(foreign, ".git"),
          );
          await writeFile(join(root, "app.ts"), "after\n");
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      });
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(launches).toBe(1);
      expect(JSON.parse(outcome.stdout).files).toEqual(["app.ts"]);
      expect(targetCommands).toEqual([]);
      expect(await readFile(effect).catch(() => undefined)).toBeUndefined();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(other("rev-parse", "HEAD")).toBe(otherHead);
      expect(await readFile(join(root, ".git", "index"))).toEqual(index);
      expect(await readFile(join(foreign, ".git", "index"))).toEqual(
        otherIndex,
      );
      expect(await readFile(join(foreign, "app.ts"), "utf8")).toBe("before\n");
      expect(await readFile(join(root, "app.ts"), "utf8")).toBe("after\n");
    },
  );
}
