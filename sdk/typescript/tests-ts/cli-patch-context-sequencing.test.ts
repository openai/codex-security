import { expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import {
  chmod,
  readFile,
  utimes,
  writeFile,
  mkdir,
  symlink,
} from "node:fs/promises";
import { join, basename, isAbsolute, relative, sep } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import {
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runWorkflow,
  savedScan,
  patchDirectories,
  runIssuePatch,
  runSavedPublication,
  runPublicationCommand,
  patchArtifactFromPrompt,
  runGitRepositoryCommand,
  gitWithEnvironment,
} from "./cli-patch-fixtures.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";

const fixtures = patchDirectories();
const preparedSnapshotTimeout = process.platform === "win32" ? 180_000 : 90_000;
for (const policy of ["set", "exclude", "control"] as const) {
  for (const action of [
    "no-op",
    "edit",
    "risk",
    "publish",
    "risk-publish",
    "batch",
    "batch-risk",
    "batch-publish",
    "batch-risk-publish",
    "inline-publish",
    ...(policy === "control" ? (["batch-edited-publish"] as const) : []),
  ] as const) {
    const batch = action.startsWith("batch");
    const publish = action.endsWith("publish");
    test(
      `prepared snapshot context preserves ${policy} filter policy for ${action}`,
      async () => {
        const risk = action.includes("risk");
        const inline = action === "inline-publish";
        const dataPath = inline ? "src/data" : "data";
        const { directory, remote } = await publicationRepository(fixtures);
        const home = await fixtures.create("patch-policy-home-");
        await chmod(home, 0o700);
        // The sandbox reads the operator's filter and configuration outside its private Codex home.
        const filterDirectory = await fixtures.create("patch-policy-filter-");
        const globalConfig = join(filterDirectory, "gitconfig");
        const environment = patchSnapshotEnvironment(
          await fixtures.create("patch-policy-temp-"),
          {
            ...process.env,
            CODEX_HOME: home,
            GIT_CONFIG: undefined,
            GIT_CONFIG_GLOBAL: globalConfig,
            GIT_CONFIG_SYSTEM: globalConfig,
            GIT_CONFIG_NOSYSTEM: "1",
            SNAPSHOT_STYLE: "host",
          },
        );
        const effective =
          policy === "set" ? "policy" : policy === "exclude" ? "unset" : "host";
        await writeFile(
          join(home, "config.toml"),
          `${patchSnapshotWindowsConfig()}[shell_environment_policy]\ninherit="all"\n${policy === "exclude" ? 'exclude=["SNAPSHOT_STYLE"]\n' : ""}${policy === "set" ? '[shell_environment_policy.set]\nSNAPSHOT_STYLE="policy"\n' : ""}`,
        );
        const clean = join(filterDirectory, "clean.cjs");
        const outsideWrite = join(home, "filter-write.txt");
        await writeFile(
          clean,
          `const fs=require("node:fs");const input=fs.readFileSync(0,"utf8");
if(process.env.SNAPSHOT_STATUS_TRACE === "1") fs.writeSync(2, "status-filter:"+(process.env.SNAPSHOT_STYLE??"unset")+"\\n");
if(input.startsWith("new")){try{fs.writeFileSync(${JSON.stringify(outsideWrite)},"unexpected");}catch(error){if(!["EACCES","EPERM","EROFS"].includes(error.code))throw error;}}
process.stdout.write(input+(process.env.SNAPSHOT_STYLE??"unset")+"\\n"+(input.startsWith("new")?require("node:crypto").randomUUID()+"\\n":""));\n`,
        );
        const git = (args: string[], selected = environment) =>
          execFileSync("git", args, {
            cwd: directory,
            env: selected,
            encoding: "utf8",
            stdio: ["ignore", "pipe", "pipe"],
          }).trim();
        // This operator-installed filter deliberately maps local bytes to a different blob.
        git([
          "config",
          "--file",
          globalConfig,
          "filter.synthetic.clean",
          `node ${JSON.stringify(clean.replaceAll("\\", "/"))}`,
        ]);
        await writeFile(
          join(directory, ".gitattributes"),
          `${dataPath} filter=synthetic\nsrc/new-*.txt filter=synthetic\n`,
        );
        await writeFile(join(directory, dataPath), "Unchanged filter input\n");
        // Publication starts with an index recorded using the selected filter policy.
        const recorded =
          publish && !inline
            ? {
                ...environment,
                SNAPSHOT_STYLE: policy === "exclude" ? undefined : effective,
              }
            : environment;
        git(["add", "."], recorded);
        git(["commit", "-m", "Synthetic filter baseline"], recorded);
        const originalDataBlob = git(
          ["rev-parse", `HEAD:${dataPath}`],
          recorded,
        );
        const index = await readFile(join(directory, ".git", "index"));
        const trees: string[] = [];
        let assessedPatch = "";
        let turns = 0,
          assessments = 0;
        const outcome = await runWorkflow(
          [
            ...(inline
              ? ["scan", directory, "--patch"]
              : [
                  "patch",
                  ...(batch ? ["--scan", "scan-1"] : ["Synthetic issue"]),
                ]),
            ...(risk ? ["--assess-patch-risk"] : []),
            ...(publish ? ["--create-pr"] : []),
            "--json",
          ],
          {
            currentDirectory: directory,
            environment,
            ...(inline ? { result: resultWithFindings(["high"]) } : {}),
            manualCodexPreparation: true,
            onWorkbench: () =>
              savedScan(
                resultWithFindings(["high", "medium"]),
                "scan-1",
                directory,
              ),
            onRepositoryCommand: async (command, args, cwd, options) => {
              if (command !== "git")
                return args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1";
              if (
                action === "batch-edited-publish" &&
                args[0] === "switch" &&
                args.includes("-c")
              )
                await writeFile(
                  join(directory, "src/new-1.txt"),
                  "actual later edit\n",
                );
              if (args.includes("add") && !inline)
                expect(options?.sandbox).toBeDefined();
              const status = args[0] === "status";
              const trace: Buffer[] = [];
              if (status) {
                // Force Git to recheck the same-size tracked file through its clean filter.
                await utimes(join(directory, dataPath), 1, 1);
                expect(options?.sandbox?.directory).toBe(directory);
                expect(
                  options?.sandbox?.gitEnvironment?.["GIT_OPTIONAL_LOCKS"],
                ).toBe("0");
              }
              const result = await runRepositoryCommand(command, args, cwd, {
                ...options,
                environment: {
                  ...environment,
                  ...options?.environment,
                  ...(status && { SNAPSHOT_STATUS_TRACE: "1" }),
                },
                ...(status && {
                  onStderr: (chunk: Buffer) => trace.push(chunk),
                }),
              });
              if (status)
                expect(Buffer.concat(trace).toString()).toContain(
                  "status-filter:" + effective,
                );
              if (args.includes("--dry-run"))
                await expect(readFile(outsideWrite)).rejects.toMatchObject({
                  code: "ENOENT",
                });
              if (args.includes("write-tree")) trees.push(result.trim());
              return result;
            },
            onCodex: async (_args, output) => {
              if (
                output?.appServer?.prompt.includes("immutable patch artifact")
              ) {
                assessments++;
                const artifact = patchArtifactFromPrompt(
                  output.appServer.prompt,
                );
                const patch = await readFile(artifact.path, "utf8");
                assessedPatch = patch;
                expect(patch).toContain(`+${effective}\n`);
                expect(patch).toContain("+new 1\n");
                expect(patch).toContain("+fixed");
                expect(patch).not.toContain("diff --git a/data");
                output.stdout.write(patchRiskAssessment().report);
                return 0;
              }
              output!.appServer!.onPermissions!({
                directory,
                environment,
                snapshotStoragePaths: output!.appServer!.snapshotStoragePaths,
                profile: {
                  extends: ":workspace",
                  network: { enabled: false },
                  workspace_roots: {},
                  filesystem: {
                    [filterDirectory]: { ".": "read" },
                    ...Object.fromEntries(
                      output!.appServer!.permissions!.readOnlyPaths.map(
                        (path) => [path, { ".": "read" }],
                      ),
                    ),
                    ":tmpdir": {},
                    ":slash_tmp": {},
                  },
                },
              });
              await output!.appServer!.onBeforeTurn?.();
              turns++;
              if (action !== "no-op") {
                await writeFile(
                  join(directory, `src/finding-${turns}.ts`),
                  `fixed ${turns}\n`,
                );
                await writeFile(
                  join(directory, `src/new-${turns}.txt`),
                  `new ${turns}\n`,
                );
              }
              output!.stdout.write(
                batch || inline
                  ? JSON.stringify({
                      patches: [
                        {
                          occurrenceId: `occ_${turns}`,
                          status: "verified",
                          files: inline
                            ? ["src"]
                            : [
                                `src/finding-${turns}.ts`,
                                `src/new-${turns}.txt`,
                              ],
                          verification: "Synthetic edit verified.",
                        },
                      ],
                    })
                  : "Synthetic turn complete.\n",
              );
              return 0;
            },
          },
        );
        expect(turns, outcome.stderr).toBe(batch ? 2 : 1);
        expect(await readFile(join(directory, dataPath), "utf8")).toBe(
          "Unchanged filter input\n",
        );
        if (action === "batch-edited-publish") {
          expect(outcome.exitCode).toBe(2);
          expect(outcome.stderr).toContain(
            "working tree differs from the verified changes",
          );
          expect(await readFile(join(directory, "src/new-1.txt"), "utf8")).toBe(
            "actual later edit\n",
          );
          expect(
            repositoryGit(remote)("for-each-ref", "refs/heads/codex-security/"),
          ).toBe("");
          return;
        }
        if (action === "no-op") {
          expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(2);
          expect(JSON.parse(outcome.stdout).error.code).toBe(
            "NO_PATCH_APPLIED",
          );
          expect(trees).toHaveLength(2);
          expect(trees[0]).toBe(trees[1]);
        } else if (inline) {
          // The requested directory contains a pre-existing policy difference.
          // Only the two leaves actually edited in the finding's turn can publish.
          expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(0);
        } else {
          expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(0);
          expect(JSON.parse(outcome.stdout).files).toEqual(
            batch
              ? [
                  "src/finding-1.ts",
                  "src/finding-2.ts",
                  "src/new-1.txt",
                  "src/new-2.txt",
                ]
              : ["src/finding-1.ts", "src/new-1.txt"],
          );
        }
        expect(assessments).toBe(risk ? 1 : 0);
        if (!publish)
          await expect(readFile(outsideWrite)).rejects.toMatchObject({
            code: "ENOENT",
          });
        if (publish) {
          const published = repositoryGit(remote);
          const branch = published(
            "for-each-ref",
            "--format=%(refname)",
            "refs/heads/codex-security/",
          );
          expect(published("show", `${branch}:src/finding-1.ts`)).toBe(
            "fixed 1",
          );
          if (batch)
            expect(published("show", `${branch}:src/finding-2.ts`)).toBe(
              "fixed 2",
            );
          for (let turn = 1; turn <= turns; turn++) {
            const blob = published("show", `${branch}:src/new-${turn}.txt`);
            expect(blob).toStartWith(`new ${turn}\n${effective}\n`);
            // Each filtering produces a new nonce: the commit must use the exact assessed blob.
            if (risk)
              expect(assessedPatch).toContain(
                blob
                  .split("\n")
                  .map((line) => `+${line}\n`)
                  .join(""),
              );
          }
          expect(published("rev-parse", `${branch}:${dataPath}`)).toBe(
            originalDataBlob,
          );
        } else
          expect(await readFile(join(directory, ".git", "index"))).toEqual(
            index,
          );
      },
      // Batch publication repeatedly starts native Windows sandboxes to capture
      // each finding's immutable tree and verify filtered content before pushing.
      process.platform === "win32" && batch && publish
        ? 1_200_000
        : preparedSnapshotTimeout,
    );
  }
}

test("publication keeps mixed valid and missing selected-path errors before branching", async () => {
  const { directory, remote, git } = await publicationRepository(fixtures);
  const original = git("rev-parse", "HEAD");
  const index = await readFile(join(directory, ".git", "index"));
  const outcome = await runSavedPublication(directory, {
    onRepositoryCommand: runPublicationCommand,
    onCodex: async (_args, output) => {
      await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
      output!.stdout.write(
        JSON.stringify({
          patches: [
            {
              occurrenceId: "occ_1",
              status: "verified",
              files: ["src/finding-1.ts", "src/missing.ts"],
              verification: "Synthetic edit verified.",
            },
          ],
        }),
      );
      return 0;
    },
  });
  expect(outcome.exitCode).toBe(2);
  expect(outcome.stderr).toContain(
    `pathspec '${join("src", "missing.ts")}' did not match any files`,
  );
  expect(git("rev-parse", "HEAD")).toBe(original);
  expect(git("branch", "--show-current")).toBe("main");
  expect(
    git("for-each-ref", "--format=%(refname)", "refs/heads/codex-security/"),
  ).toBe("");
  expect(repositoryGit(remote)("for-each-ref", "refs/heads/")).toBe("");
  expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
});

test.skipIf(process.platform === "win32")(
  "an unreadable patched file still fails required snapshotting",
  async () => {
    const { directory } = await publicationRepository(fixtures);
    const source = join(directory, "src/finding-1.ts");
    let turns = 0;
    try {
      const outcome = await runIssuePatch(directory, {
        onCodex: async (_args, output) => {
          turns++;
          await writeFile(source, "fixed\n");
          await chmod(source, 0);
          output!.stdout.write("Synthetic edit complete.\n");
          return 0;
        },
      });
      expect(turns).toBe(1);
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stdout + outcome.stderr).toContain("Permission denied");
      await expect(readFile(source)).rejects.toMatchObject({ code: "EACCES" });
    } finally {
      await chmod(source, 0o600);
    }
  },
);

async function applyToClone(directory: string, patch: string) {
  const clone = await fixtures.create("patch-component-assessment-");
  const git = repositoryGit(clone);
  git("clone", "-c", "core.autocrlf=false", "--no-hardlinks", directory, ".");
  git("apply", "--check", patch);
  git("apply", patch);
  return clone;
}

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
    const userConfig = join(support, "user.gitconfig");
    await writeFile(
      filter,
      'process.stdout.write(require("node:fs").readFileSync(0,"utf8").toUpperCase());\n',
    );
    git(
      "config",
      "--file",
      userConfig,
      "filter.synthetic.clean",
      `node ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
    );
    git("config", "--file", userConfig, "filter.synthetic.required", "true");
    await writeFile(
      join(directory, ".gitattributes"),
      "component/app.ts filter=synthetic\n",
    );
    git("-c", `include.path=${userConfig}`, "add", ".");
    git("commit", "-m", "Synthetic component snapshot baseline");
    const caller = scope === "root" ? directory : component;
    const environment = {
      GIT_CONFIG_GLOBAL: userConfig,
      ...(literal && { GIT_LITERAL_PATHSPECS: "1" }),
    };
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
            const artifact = patchArtifactFromPrompt(output!.appServer!.prompt);
            expect(artifact.changedFiles).toEqual(expectedFiles);
            const verification = await applyToClone(directory, artifact.path);
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
    const include = join(directory, ".git", "filter-config");
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
        onRepositoryCommand: gitWithEnvironment(environment),
        onCodex: async (_args, output) => {
          if (output!.appServer!.prompt.includes("immutable patch artifact")) {
            assessments++;
            const artifact = patchArtifactFromPrompt(output!.appServer!.prompt);
            expect(artifact.changedFiles).toEqual(["app.ts"]);
            const verification = await applyToClone(directory, artifact.path);
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

test.each([
  "absolute",
  "relative",
  "relative configuration",
  "NUL configuration",
])(
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
        : mode === "NUL configuration"
          ? {
              GIT_CONFIG_GLOBAL: "NUL",
              GIT_CONFIG_SYSTEM: "nul",
              GIT_CONFIG_NOSYSTEM: "0",
            }
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
    const outcome = await runSavedPublication(component, {
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
          if (mode === "NUL configuration") {
            for (const key of [
              "GIT_CONFIG_GLOBAL",
              "GIT_CONFIG_SYSTEM",
            ] as const) {
              const entry = context.environment[key]!;
              if (process.platform === "win32")
                expect(entry).toBe(environment[key]!);
              else {
                expect(isAbsolute(entry)).toBe(true);
                expect(basename(entry)).toBe(environment[key]!);
              }
            }
          }
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
    });
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
              const artifact = patchArtifactFromPrompt(
                output!.appServer!.prompt,
              );
              const verification = await applyToClone(directory, artifact.path);
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
