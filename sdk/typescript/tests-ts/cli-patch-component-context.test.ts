import { afterEach, expect, test } from "bun:test";
import {
  cp,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import {
  completePatches,
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

test.each([
  { scope: "root", siblingOnly: false, literal: false },
  { scope: "component", siblingOnly: false, literal: false },
  { scope: "component", siblingOnly: true, literal: true },
])(
  "assesses and publishes ignored siblings from $scope (only sibling: $siblingOnly, literal: $literal)",
  async ({ scope, siblingOnly, literal }) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const component = join(directory, "component");
    await mkdir(component);
    await writeFile(join(component, "app.ts"), "original\n");
    await writeFile(join(directory, "unrelated.txt"), "unchanged\n");
    await writeFile(
      join(directory, ".gitignore"),
      "generated.txt\nlocal-cache.txt\n",
    );
    await writeFile(
      join(directory, "local-cache.txt"),
      "Local cached content\n",
    );
    const support = await fixtures.create("patch-component-filter-");
    const filter = join(support, "clean.cjs");
    await writeFile(
      filter,
      'process.stdout.write(require("node:fs").readFileSync(0,"utf8").toUpperCase());\n',
    );
    git(
      "config",
      "filter.synthetic.clean",
      `node ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
    );
    git("config", "filter.synthetic.required", "true");
    await writeFile(
      join(directory, ".gitattributes"),
      "component/app.ts filter=synthetic\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic component snapshot baseline");
    const caller = scope === "root" ? directory : component;
    const environment = literal ? { GIT_LITERAL_PATHSPECS: "1" } : {};
    let assessments = 0;
    let pushes = 0;
    let streamedBlobs = 0;
    const expectedFiles = siblingOnly
      ? ["generated.txt"]
      : ["component/app.ts", "generated.txt"];
    const outcome = await runWorkflow(
      [
        "patch",
        "Synthetic issue",
        "--assess-patch-risk",
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: caller,
        environment,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git")
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          if (args[0] === "push") {
            pushes++;
            return "";
          }
          if (args[0] === "cat-file" && options?.onStdout !== undefined) {
            streamedBlobs++;
            expect(options.directory).toBe(caller);
            expect(options.environment?.["GIT_WORK_TREE"]).toBe(directory);
            return runRepositoryCommand(command, args, cwd, options);
          }
          return runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          });
        },
        onCodex: async (_args, output) => {
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            assessments++;
            const artifact = JSON.parse(
              output!
                .appServer!.prompt.split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            );
            expect(artifact.changedFiles).toEqual(expectedFiles);
            const verification = await fixtures.create(
              "patch-component-assessment-",
            );
            const verify = repositoryGit(verification);
            verify(
              "clone",
              "-c",
              "core.autocrlf=false",
              "--no-hardlinks",
              directory,
              ".",
            );
            verify("apply", "--check", artifact.path);
            verify("apply", artifact.path);
            expect(
              await readFile(join(verification, "generated.txt"), "utf8"),
            ).toBe("generated fix\n");
            expect(
              await readFile(join(verification, "component/app.ts"), "utf8"),
            ).toBe(siblingOnly ? "ORIGINAL\n" : "FIXED\n");
            output!.stdout.write(patchRiskAssessment().report);
          } else {
            expect(output!.appServer!.directory).toBe(caller);
            await writeFile(
              join(directory, "generated.txt"),
              "generated fix\n",
            );
            git("add", "-f", "generated.txt");
            if (!siblingOnly)
              await writeFile(join(component, "app.ts"), "fixed\n");
            output!.stdout.write("Synthetic patch complete.\n");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(assessments).toBe(1);
    expect(pushes).toBe(1);
    expect(streamedBlobs).toBe(expectedFiles.length);
    expect(git("show", "HEAD:generated.txt")).toBe("generated fix");
    expect(git("show", "HEAD:component/app.ts")).toBe(
      siblingOnly ? "ORIGINAL" : "FIXED",
    );
    expect(git("show", "HEAD:unrelated.txt")).toBe("unchanged");
    expect(await readFile(join(directory, "local-cache.txt"), "utf8")).toBe(
      "Local cached content\n",
    );
    expect(git("diff", "--cached", "--name-only")).toBe("");
    expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
      "",
    );
  },
);

test.each(
  [
    "physical",
    "directory alias",
    "absolute Git alias",
    "relative Git alias",
  ].flatMap((mode) => [false, true].map((assess) => ({ mode, assess }))),
)(
  "saved patch preserves conditional filters through $mode (assessment: $assess)",
  async ({ mode, assess }) => {
    const { directory, git } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-saved-alias-filter-");
    const alias = join(support, "alias");
    await symlink(
      directory,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    const filter = join(support, "clean.cjs");
    await writeFile(
      filter,
      'process.stdout.write(require("node:fs").readFileSync(0,"utf8").toUpperCase());\n',
    );
    const include = join(support, "filter-config");
    git("config", "--file", include, "synthetic.marker", "alias-selected");
    git(
      "config",
      "--file",
      include,
      "filter.synthetic.clean",
      `node ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
    );
    git("config", "--file", include, "filter.synthetic.required", "true");
    git("config", "includeIf.gitdir:**/alias/.git.path", include);
    await writeFile(join(directory, "app.ts"), "original\n");
    await writeFile(join(directory, "unrelated.txt"), "unchanged\n");
    await writeFile(
      join(directory, ".gitattributes"),
      "app.ts filter=synthetic\nunrelated.txt filter=synthetic\n",
    );
    const explicit = mode.endsWith("Git alias");
    const target = mode === "directory alias" ? alias : directory;
    const environment: NodeJS.ProcessEnv = explicit
      ? {
          GIT_DIR: (mode.startsWith("absolute")
            ? join(alias, ".git")
            : relative(directory, join(alias, ".git"))
          ).replaceAll(sep, "/"),
        }
      : {};
    const selectedGit = (...args: string[]) =>
      runGitRepositoryCommand("git", args, target, { environment });
    expect(
      selectedGit("config", "--get", "--default=inactive", "synthetic.marker"),
    ).toBe(explicit ? "alias-selected" : "inactive");
    selectedGit("add", ".");
    selectedGit("commit", "-m", "Synthetic conditional filter baseline");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git/index"));
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "app.ts";
    let assessments = 0;
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--json",
        ...(assess ? ["--assess-patch-risk"] : []),
      ],
      {
        currentDirectory: directory,
        environment,
        result,
        onWorkbench: () => savedScan(result, "scan-1", target),
        onRepositoryCommand: (command, args, cwd, options) =>
          runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          }),
        onCodex: async (_args, output) => {
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            assessments++;
            const artifact = JSON.parse(
              output!
                .appServer!.prompt.split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            );
            expect(artifact.changedFiles).toEqual(["app.ts"]);
            const verification = await fixtures.create(
              "patch-alias-assessment-",
            );
            const verify = repositoryGit(verification);
            verify(
              "clone",
              "-c",
              "core.autocrlf=false",
              "--no-hardlinks",
              directory,
              ".",
            );
            verify("apply", "--check", artifact.path);
            verify("apply", artifact.path);
            expect(await readFile(join(verification, "app.ts"), "utf8")).toBe(
              explicit ? "FIXED\n" : "fixed\n",
            );
            expect(
              await readFile(join(verification, "unrelated.txt"), "utf8"),
            ).toBe(explicit ? "UNCHANGED\n" : "unchanged\n");
            output!.stdout.write(patchRiskAssessment().report);
          } else {
            await writeFile(join(directory, "app.ts"), "fixed\n");
            output!.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: ["app.ts"],
                    verification: "Synthetic conditional filter check.",
                  },
                ],
              }),
            );
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      files: ["app.ts"],
      filesChanged: 1,
    });
    expect(assessments).toBe(assess ? 1 : 0);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(join(directory, ".git/index"))).toEqual(index);
    expect(await readFile(join(directory, "unrelated.txt"), "utf8")).toBe(
      "unchanged\n",
    );
  },
);

test.each(["absolute", "relative", "relative configuration"])(
  "prepares saved component publication with %s Git settings",
  async (mode) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const component = join(directory, "component");
    await mkdir(component);
    await writeFile(join(component, "app.ts"), "original\n");
    await writeFile(
      join(component, "settings"),
      "[synthetic]\n marker=component\n",
    );
    await writeFile(join(directory, "settings"), "[synthetic]\n marker=root\n");
    git("add", ".");
    git("commit", "-m", "Synthetic saved component baseline");
    const environment: NodeJS.ProcessEnv = {
      GIT_DIR: mode === "absolute" ? join(directory, ".git") : "../.git",
      GIT_WORK_TREE: mode === "absolute" ? directory : "..",
      ...(mode === "relative configuration"
        ? { GIT_CONFIG_GLOBAL: "settings" }
        : {}),
    };
    const configured =
      mode === "relative configuration"
        ? runGitRepositoryCommand(
            "git",
            ["config", "--get", "synthetic.marker"],
            component,
            { environment },
          )
        : undefined;
    const result = resultWithFindings(["high"]);
    result.findings.findings[0]!.locations[0]!.path = "app.ts";
    let patches = 0;
    let pushes = 0;
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: component,
        environment,
        result,
        onWorkbench: () => savedScan(result, "scan-1", component),
        onRepositoryCommand: (command, args, cwd, options) => {
          const context = {
            ...options,
            environment: { ...environment, ...options?.environment },
          };
          if (command !== "git") {
            if (configured !== undefined)
              expect(
                runGitRepositoryCommand(
                  "git",
                  ["config", "--get", "synthetic.marker"],
                  cwd,
                  context,
                ),
              ).toBe(configured);
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          }
          if (args[0] === "push") {
            pushes++;
            return "";
          }
          return runGitRepositoryCommand(command, args, cwd, context);
        },
        onCodex: async (_args, output) => {
          patches++;
          expect(output!.appServer!.directory).toBe(component);
          await writeFile(join(component, "app.ts"), "fixed\n");
          output!.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["app.ts"],
                  verification: "Synthetic component check.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(patches).toBe(1);
    expect(pushes).toBe(1);
    expect(git("show", "HEAD:component/app.ts")).toBe("fixed");
    expect(git("show", "HEAD:settings")).toContain("marker=root");
    expect(git("show", "HEAD:component/settings")).toContain(
      "marker=component",
    );
    expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
      "",
    );
  },
);

for (const raw of [false, true]) {
  test.skipIf(raw && process.platform !== "linux").each([false, true])(
    `inline assessment retains ${raw ? "raw-byte" : "ordinary"} filename edits (mixed: %p)`,
    async (mixed) => {
      const { directory, git } = await publicationRepository(fixtures);
      const component = join(directory, "component");
      await mkdir(component);
      const name = raw
        ? Buffer.concat([
            Buffer.from("component/name-"),
            Buffer.from([0xff]),
            Buffer.from(".ts"),
          ])
        : Buffer.from("component/ordinary.ts");
      const path = Buffer.concat([Buffer.from(`${directory}/`), name]);
      const alias = "component/name-\ufffd.ts";
      await writeFile(path, "original\n");
      await writeFile(join(directory, alias), "untouched alias\n");
      git("add", ".");
      git("commit", "-m", "Synthetic byte-path assessment baseline");
      const head = git("rev-parse", "HEAD");
      const index = await readFile(join(directory, ".git/index"));
      let assessments = 0;
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--assess-patch-risk", "--json"],
        {
          currentDirectory: component,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            if (
              output!.appServer!.prompt.includes("immutable patch artifact")
            ) {
              assessments++;
              const artifact = JSON.parse(
                output!
                  .appServer!.prompt.split("\n")
                  .find((line) => line.startsWith('{"path":'))!,
              );
              const verification = await fixtures.create(
                "patch-byte-assessment-",
              );
              const verify = repositoryGit(verification);
              verify(
                "clone",
                "-c",
                "core.autocrlf=false",
                "--no-hardlinks",
                directory,
                ".",
              );
              verify("apply", "--check", artifact.path);
              verify("apply", artifact.path);
              expect(
                await readFile(
                  Buffer.concat([Buffer.from(`${verification}/`), name]),
                  "utf8",
                ),
              ).toBe("fixed\n");
              expect(await readFile(join(verification, alias), "utf8")).toBe(
                "untouched alias\n",
              );
              expect(
                await readFile(join(verification, "src/finding-1.ts"), "utf8"),
              ).toBe(mixed ? "other fix\n" : "original\n");
              output!.stdout.write(patchRiskAssessment().report);
            } else {
              expect(output!.appServer!.directory).toBe(component);
              await writeFile(path, "fixed\n");
              if (mixed)
                await writeFile(
                  join(directory, "src/finding-1.ts"),
                  "other fix\n",
                );
              output!.stdout.write("Synthetic byte-path patch.\n");
            }
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(assessments).toBe(1);
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(directory, ".git/index"))).toEqual(index);
      expect(await readFile(join(directory, alias), "utf8")).toBe(
        "untouched alias\n",
      );
    },
  );
}

test.each(["absolute", "relative"] as const)(
  "preserves selected common-directory aliases across finding patches: %s",
  async (selection) => {
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "src/finding-2.ts"), "original second\n");
    await writeFile(join(directory, ".gitignore"), "administration-alias\n");
    git("add", ".");
    git("commit", "-m", "Synthetic successive patch baseline");
    const administration = await realpath(join(directory, ".git"));
    const alias = join(directory, "administration-alias");
    await symlink(
      administration,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    git("config", "lfs.storage", join(alias, "lfs"));
    const environment = {
      GIT_COMMON_DIR: selection === "absolute" ? alias : "administration-alias",
    };
    const originalHead = git("rev-parse", "HEAD");
    const originalIndex = await readFile(join(administration, "index"));
    const result = resultWithFindings(["high", "high"]);
    const grants: string[][] = [];
    const boundCommonDirectories = new Set<string>();
    const outcome = await runWorkflow(["patch", "--scan", "scan-1", "--json"], {
      currentDirectory: directory,
      environment,
      result,
      onWorkbench: () => savedScan(result, "scan-1", directory),
      onRepositoryCommand: (command, args, cwd, options) => {
        const common = options?.environment?.["GIT_COMMON_DIR"];
        if (common !== undefined)
          boundCommonDirectories.add(common.replaceAll(sep, "/"));
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
      onCodex: async (args, output) => {
        grants.push([...(output!.appServer!.snapshotStoragePaths ?? [])]);
        expect(output!.appServer!.permissions!.modelOnlyReadOnlyPaths).toEqual([
          join(administration, "lfs", "objects"),
          join(administration, "lfs", "tmp"),
        ]);
        const findings = completePatches(args, output);
        expect(findings).toHaveLength(1);
        await writeFile(
          join(directory, findings[0]!.locations[0]!.path),
          `fixed ${grants.length}\n`,
        );
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(grants).toEqual([1, 2].map(() => [join(administration, "lfs")]));
    expect(boundCommonDirectories).toEqual(
      new Set([administration.replaceAll(sep, "/")]),
    );
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      files: ["src/finding-1.ts", "src/finding-2.ts"],
      filesChanged: 2,
    });
    expect(git("rev-parse", "HEAD")).toBe(originalHead);
    expect(await readFile(join(administration, "index"))).toEqual(
      originalIndex,
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed 1\n",
    );
    expect(await readFile(join(directory, "src/finding-2.ts"), "utf8")).toBe(
      "fixed 2\n",
    );
  },
);

for (const selection of [
  "absolute",
  "removed marker directory",
  "linked file in removed marker directory",
  "common override",
] as const) {
  test(`preserves selected Git-file aliases across finding patches: ${selection}`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "src/finding-2.ts"), "original second\n");
    await writeFile(
      join(directory, ".gitignore"),
      "component/\nadmin-alias\ncommon-alias\nselected.git\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic successive Git-file baseline");
    const administration = await realpath(join(directory, ".git"));
    const alias = join(directory, "admin-alias");
    const linkType = process.platform === "win32" ? "junction" : "dir";
    await symlink(administration, alias, linkType);
    const component = join(directory, "component");
    await mkdir(component);
    const removeMarker = selection.includes("removed marker directory");
    const markerDirectory = removeMarker ? component : directory;
    const marker = join(markerDirectory, "selected.git");
    const contents = `gitdir: ${removeMarker ? "../" : ""}admin-alias\n`;
    if (selection === "linked file in removed marker directory") {
      const support = await fixtures.create("patch-selected-file-source-");
      await mkdir(join(support, "nested"));
      await cp(administration, join(support, "admin-alias"), {
        recursive: true,
      });
      const source = join(support, "nested", "source.git");
      await writeFile(source, contents);
      await symlink(source, marker, "file");
    } else {
      await writeFile(marker, contents);
    }
    let common = administration;
    let storageAlias = alias;
    if (selection === "common override") {
      common = join(
        await fixtures.create("patch-selected-common-"),
        "metadata",
      );
      await cp(administration, common, { recursive: true });
      storageAlias = join(directory, "common-alias");
      await symlink(common, storageAlias, linkType);
    }
    const environment = {
      GIT_DIR: (selection === "absolute"
        ? marker
        : relative(directory, marker)
      ).replaceAll(sep, "/"),
      GIT_WORK_TREE: directory,
      ...(selection === "common override"
        ? { GIT_COMMON_DIR: storageAlias }
        : {}),
    };
    const selectedGit = (args: string[]) =>
      runGitRepositoryCommand("git", args, directory, {
        directory,
        environment,
      });
    expect(
      (await selectedGit(["rev-parse", "--absolute-git-dir"])).replaceAll(
        sep,
        "/",
      ),
    ).toBe(administration.replaceAll(sep, "/"));
    await selectedGit(["config", "lfs.storage", join(storageAlias, "lfs")]);
    const originalHead = git("rev-parse", "HEAD");
    const originalIndex = await readFile(join(administration, "index"));
    const result = resultWithFindings(["high", "high"]);
    const grants: string[][] = [];
    const boundCommonDirectories = new Set<string>();
    const outcome = await runWorkflow(["patch", "--scan", "scan-1", "--json"], {
      currentDirectory: directory,
      environment,
      result,
      onWorkbench: () => savedScan(result, "scan-1", directory),
      onRepositoryCommand: (command, args, cwd, options) => {
        const value = options?.environment?.["GIT_COMMON_DIR"];
        if (value !== undefined)
          boundCommonDirectories.add(value.replaceAll(sep, "/"));
        return runGitRepositoryCommand(command, args, cwd, {
          ...options,
          environment: { ...environment, ...options?.environment },
        });
      },
      onCodex: async (args, output) => {
        grants.push([...(output!.appServer!.snapshotStoragePaths ?? [])]);
        expect(output!.appServer!.permissions!.modelOnlyReadOnlyPaths).toEqual([
          join(common, "lfs", "objects"),
          join(common, "lfs", "tmp"),
        ]);
        const findings = completePatches(args, output);
        expect(findings).toHaveLength(1);
        await writeFile(
          join(directory, findings[0]!.locations[0]!.path),
          `fixed ${grants.length}\n`,
        );
        if (removeMarker && grants.length === 1)
          await rm(component, { recursive: true });
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(grants).toEqual([1, 2].map(() => [join(common, "lfs")]));
    expect(boundCommonDirectories).toEqual(
      new Set(
        selection === "common override" ? [common.replaceAll(sep, "/")] : [],
      ),
    );
    expect(JSON.parse(outcome.stdout)).toMatchObject({
      files: ["src/finding-1.ts", "src/finding-2.ts"],
      filesChanged: 2,
    });
    expect(git("rev-parse", "HEAD")).toBe(originalHead);
    expect(await readFile(join(administration, "index"))).toEqual(
      originalIndex,
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed 1\n",
    );
    expect(await readFile(join(directory, "src/finding-2.ts"), "utf8")).toBe(
      "fixed 2\n",
    );
  });
}

for (const linked of [false, true]) {
  test(`retains selected Git-file storage after removing its caller (linked marker: ${linked})`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    const component = join(directory, "component");
    await mkdir(component);
    await writeFile(join(component, "app.ts"), "original component\n");
    await writeFile(
      join(directory, ".gitignore"),
      "admin-alias\ncomponent/selected.git\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic Git-file caller baseline");
    const administration = await realpath(join(directory, ".git"));
    const alias = join(directory, "admin-alias");
    await symlink(
      administration,
      alias,
      process.platform === "win32" ? "junction" : "dir",
    );
    git("config", "lfs.storage", join(alias, "lfs"));
    const marker = join(component, "selected.git");
    const contents = "gitdir: ../admin-alias\n";
    if (linked) {
      const support = await fixtures.create("patch-removed-marker-source-");
      await mkdir(join(support, "nested"));
      await cp(administration, join(support, "admin-alias"), {
        recursive: true,
      });
      const source = join(support, "nested", "source.git");
      await writeFile(source, contents);
      await symlink(source, marker, "file");
    } else {
      await writeFile(marker, contents);
    }
    const environment = { GIT_DIR: "selected.git", GIT_WORK_TREE: directory };
    const originalHead = git("rev-parse", "HEAD");
    const originalIndex = await readFile(join(administration, "index"));
    let turns = 0;
    const outcome = await runWorkflow(
      ["patch", "Synthetic component issue", "--assess-patch-risk", "--json"],
      {
        currentDirectory: component,
        environment,
        onRepositoryCommand: (command, args, cwd, options) =>
          runGitRepositoryCommand(command, args, cwd, {
            ...options,
            environment: { ...environment, ...options?.environment },
          }),
        onCodex: async (_args, output) => {
          turns++;
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            expect(output!.appServer!.directory).toBe(directory);
            output!.stdout.write(patchRiskAssessment().report);
          } else {
            expect(output!.appServer!.snapshotStoragePaths).toEqual([
              join(administration, "lfs"),
            ]);
            expect(
              output!.appServer!.permissions!.modelOnlyReadOnlyPaths,
            ).toEqual([
              join(administration, "lfs", "objects"),
              join(administration, "lfs", "tmp"),
            ]);
            expect(output!.appServer!.directory).toBe(component);
            await rm(component, { recursive: true });
            await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
            output!.stdout.write("Synthetic component patch.\n");
          }
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(turns).toBe(2);
    expect(git("rev-parse", "HEAD")).toBe(originalHead);
    expect(await readFile(join(administration, "index"))).toEqual(
      originalIndex,
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed\n",
    );
    await expect(readFile(join(component, "app.ts"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  });
}
