import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import {
  completePatches,
  patchRiskAssessment,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

async function configuredRepository(selector: string, absolute: boolean) {
  const directory = await fixtures.create("patch-snapshot-settings-");
  const support = await fixtures.create("patch-snapshot-filter-");
  const nested = join(directory, "nested");
  await mkdir(nested);
  const git = repositoryGit(directory);
  const nestedGit = repositoryGit(nested);
  for (const run of [git, nestedGit]) {
    run("init", "--initial-branch=main");
    run("config", "user.name", "Synthetic User");
    run("config", "user.email", "synthetic@example.test");
  }
  await writeFile(join(directory, "root.txt"), "unchanged\n");
  await writeFile(join(directory, ".gitignore"), "settings\n");
  await writeFile(join(nested, "app.txt"), "original\n");
  await writeFile(join(nested, ".gitattributes"), "*.txt filter=synthetic\n");
  nestedGit("add", ".");
  nestedGit("commit", "-m", "Synthetic nested baseline");
  git("add", ".");
  git("commit", "-m", "Synthetic root baseline");
  const filter = join(support, "clean.cjs");
  await writeFile(
    filter,
    'process.stdout.write(require("node:fs").readFileSync(0,"utf8").toUpperCase());\n',
  );
  const settings = join(directory, "settings");
  git(
    "config",
    "--file",
    settings,
    "filter.synthetic.clean",
    `node ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
  );
  git("config", "--file", settings, "filter.synthetic.required", "true");
  const empty = join(support, "empty");
  await writeFile(empty, "");
  const environment: NodeJS.ProcessEnv = {
    GIT_CONFIG_GLOBAL: empty,
    GIT_CONFIG_SYSTEM: empty,
    GIT_CONFIG_NOSYSTEM: undefined,
    [selector]: absolute ? settings : "settings",
  };
  return { directory, support, nested, git, nestedGit, environment, settings };
}

for (const selector of ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"]) {
  for (const absolute of [false, true]) {
    test.each(["none", "root", "nested"])(
      `snapshot honors ${absolute ? "absolute" : "relative"} ${selector} for %s edits`,
      async (edit) => {
        const { directory, nested, git, nestedGit, environment, settings } =
          await configuredRepository(selector, absolute);
        const originalEnvironment = { ...environment };
        const config = await readFile(settings);
        const head = git("rev-parse", "HEAD");
        const nestedHead = nestedGit("rev-parse", "HEAD");
        const index = git("ls-files", "--stage");
        const nestedIndex = nestedGit("ls-files", "--stage");
        let patches = 0;
        let assessments = 0;
        const files =
          edit === "none"
            ? []
            : [edit === "root" ? "root.txt" : "nested/app.txt"];
        const outcome = await runWorkflow(
          ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
          {
            currentDirectory: directory,
            environment,
            onRepositoryCommand: (command, args, cwd, options) =>
              runGitRepositoryCommand(command, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              }),
            onCodex: async (_args, output, childEnvironment) => {
              if (
                output!.appServer!.prompt.includes("immutable patch artifact")
              ) {
                assessments++;
                const artifact = JSON.parse(
                  output!
                    .appServer!.prompt.split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
                );
                expect(artifact.changedFiles).toEqual(files);
                const verification = await fixtures.create(
                  "patch-settings-apply-",
                );
                await mkdir(join(verification, "nested"));
                await writeFile(join(verification, "root.txt"), "unchanged\n");
                await writeFile(
                  join(verification, "nested/app.txt"),
                  "ORIGINAL\n",
                );
                const verify = repositoryGit(verification);
                verify("init", "--initial-branch=main");
                verify("config", "core.autocrlf", "false");
                verify("apply", "--check", artifact.path);
                verify("apply", artifact.path);
                expect(
                  await readFile(join(verification, "root.txt"), "utf8"),
                ).toBe(edit === "root" ? "fixed\n" : "unchanged\n");
                expect(
                  await readFile(join(verification, "nested/app.txt"), "utf8"),
                ).toBe(edit === "nested" ? "FIXED\n" : "ORIGINAL\n");
                output!.stdout.write(patchRiskAssessment().report);
              } else {
                patches++;
                expect(childEnvironment?.[selector]).toBe(
                  environment[selector],
                );
                if (edit !== "none")
                  await writeFile(
                    join(
                      edit === "root" ? directory : nested,
                      edit === "root" ? "root.txt" : "app.txt",
                    ),
                    "fixed\n",
                  );
                output!.stdout.write("Synthetic patch turn completed.\n");
              }
              return 0;
            },
          },
        );
        expect(outcome.exitCode, outcome.stderr).toBe(edit === "none" ? 2 : 0);
        expect(JSON.parse(outcome.stdout)).toMatchObject({
          applied: edit !== "none",
          filesChanged: files.length,
          files,
          ...(edit === "none" ? { error: { code: "NO_PATCH_APPLIED" } } : {}),
        });
        expect(patches).toBe(1);
        expect(assessments).toBe(edit === "none" ? 0 : 1);
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(nestedGit("rev-parse", "HEAD")).toBe(nestedHead);
        expect(git("ls-files", "--stage")).toBe(index);
        expect(nestedGit("ls-files", "--stage")).toBe(nestedIndex);
        expect(await readFile(settings)).toEqual(config);
        expect(environment).toEqual(originalEnvironment);
        expect(await readFile(join(nested, "app.txt"), "utf8")).toBe(
          edit === "nested" ? "fixed\n" : "original\n",
        );
      },
    );
  }
}

test.each(["implicit", "explicit relative"])(
  "snapshot honors nested filters through an %s Git alias",
  async (kind) => {
    const { directory, support, environment } = await configuredRepository(
      "GIT_CONFIG_GLOBAL",
      false,
    );
    const alias = join(support, "alias");
    await symlink(
      directory,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    if (kind === "explicit relative") {
      environment["GIT_DIR"] = relative(directory, join(alias, ".git"));
      environment["GIT_WORK_TREE"] = directory;
    }
    let patches = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: kind === "implicit" ? alias : directory,
        environment,
        onRepositoryCommand: (command, args, cwd, options) =>
          runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          }),
        onCodex: (_args, output, childEnvironment) => {
          expect(output!.appServer!.prompt).not.toContain(
            "immutable patch artifact",
          );
          expect(childEnvironment?.["GIT_CONFIG_GLOBAL"]).toBe("settings");
          expect(childEnvironment?.["GIT_DIR"]).toBe(environment["GIT_DIR"]);
          patches++;
          output!.stdout.write("Synthetic no-op turn.\n");
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: false,
      files: [],
      error: { code: "NO_PATCH_APPLIED" },
    });
    expect(patches).toBe(1);
  },
);

test.each(["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"])(
  "snapshot preserves relative %s after removing its caller directory",
  async (selector) => {
    const { directory, nested, git, environment } = await configuredRepository(
      selector,
      false,
    );
    const component = join(directory, "component");
    await mkdir(component);
    await writeFile(join(component, "app.txt"), "component\n");
    git("add", "component/app.txt");
    git("commit", "-m", "Synthetic caller component");
    environment[selector] = "../settings";
    let patches = 0;
    let assessments = 0;
    const files = ["component/app.txt", "root.txt"];
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: component,
        environment,
        onRepositoryCommand: (command, args, cwd, options) =>
          runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          }),
        onCodex: async (_args, output, childEnvironment) => {
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            assessments++;
            const artifact = JSON.parse(
              output!
                .appServer!.prompt.split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            );
            expect(artifact.changedFiles).toEqual(files);
            const patch = await readFile(artifact.path, "utf8");
            expect(patch).toContain("-component");
            expect(patch).toContain("+fixed");
            expect(patch).not.toContain("nested/app.txt");
            output!.stdout.write(patchRiskAssessment().report);
          } else {
            patches++;
            expect(childEnvironment?.[selector]).toBe("../settings");
            await rm(component, { recursive: true });
            await writeFile(join(directory, "root.txt"), "fixed\n");
            output!.stdout.write("Synthetic patch turn completed.\n");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      applied: true,
      files: ["app.txt", "../root.txt"],
      filesChanged: 2,
    });
    expect(patches).toBe(1);
    expect(assessments).toBe(1);
    expect(await readFile(join(nested, "app.txt"), "utf8")).toBe("original\n");
    expect(environment[selector]).toBe("../settings");
  },
);

test("saved findings rebaseline with the same nested filter configuration", async () => {
  const { directory, git, environment } = await configuredRepository(
    "GIT_CONFIG_GLOBAL",
    false,
  );
  await writeFile(join(directory, "second.txt"), "second\n");
  git("add", "second.txt");
  git("commit", "-m", "Synthetic second finding");
  const result = resultWithFindings(["high", "medium"]);
  const files = ["root.txt", "second.txt"];
  for (const [index, finding] of result.findings.findings.entries())
    finding.locations[0]!.path = files[index]!;
  let patches = 0;
  let assessments = 0;
  const outcome = await runWorkflow(
    ["patch", "--scan", "scan-1", "--assess-patch-risk", "--json"],
    {
      currentDirectory: directory,
      environment,
      result,
      onWorkbench: () => savedScan(result, "scan-1", directory),
      onRepositoryCommand: (command, args, cwd, options) =>
        runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        }),
      onCodex: async (args, output, childEnvironment) => {
        if (output!.appServer!.prompt.includes("immutable patch artifact")) {
          assessments++;
          const artifact = JSON.parse(
            output!
              .appServer!.prompt.split("\n")
              .find((line) => line.startsWith('{"path":'))!,
          );
          expect(artifact.changedFiles).toEqual(files);
          const patch = await readFile(artifact.path, "utf8");
          expect(patch).toContain("-unchanged");
          expect(patch).toContain("-second");
          expect(patch).not.toContain("nested/app.txt");
          output!.stdout.write(patchRiskAssessment().report);
        } else {
          expect(childEnvironment?.["GIT_CONFIG_GLOBAL"]).toBe("settings");
          const findings = completePatches(args, output);
          expect(findings).toHaveLength(1);
          await writeFile(
            join(directory, findings[0]!.locations[0]!.path),
            `fixed ${++patches}\n`,
          );
        }
        return 0;
      },
    },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(0);
  expect(JSON.parse(outcome.stdout)).toMatchObject({
    applied: true,
    files,
    filesChanged: 2,
    patches: [
      { status: "verified", files: ["root.txt"] },
      { status: "verified", files: ["second.txt"] },
    ],
  });
  expect(patches).toBe(2);
  expect(assessments).toBe(1);
  expect(environment["GIT_CONFIG_GLOBAL"]).toBe("settings");
});
