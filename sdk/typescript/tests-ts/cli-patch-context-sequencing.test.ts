import { afterEach, expect, test } from "bun:test";
import { execFileSync } from "node:child_process";
import { chmod, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import {
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";
const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
// Publication cases can run 53 native Git commands, each with Windows ACL setup.
const preparedSnapshotTimeout = process.platform === "win32" ? 180_000 : 30_000;
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
  ] as const) {
    test(
      `prepared snapshot context preserves ${policy} filter policy for ${action}`,
      async () => {
        const batch = action.startsWith("batch");
        const risk = action.includes("risk");
        const publish = action.endsWith("publish");
        const inline = action === "inline-publish";
        const dataPath = inline ? "src/data" : "data";
        const { directory, remote } = await publicationRepository(fixtures);
        const home = await fixtures.create("patch-policy-home-");
        await chmod(home, 0o700);
        const emptyConfig = join(home, "empty.gitconfig");
        await writeFile(emptyConfig, "");
        const environment = patchSnapshotEnvironment(
          await fixtures.create("patch-policy-temp-"),
          {
            ...process.env,
            CODEX_HOME: home,
            GIT_CONFIG: undefined,
            GIT_CONFIG_GLOBAL: emptyConfig,
            GIT_CONFIG_SYSTEM: emptyConfig,
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
        const clean = join(
          await fixtures.create("patch-policy-filter-"),
          "clean.cjs",
        );
        const outsideWrite = join(home, "filter-write.txt");
        await writeFile(
          clean,
          `const fs=require("node:fs");const input=fs.readFileSync(0,"utf8");
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
        git([
          "config",
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
              if (args.includes("add") && !inline)
                expect(options?.sandbox).toBeDefined();
              const result = await runRepositoryCommand(command, args, cwd, {
                ...options,
                environment: { ...environment, ...options?.environment },
              });
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
                const artifact = JSON.parse(
                  output.appServer.prompt
                    .split("\n")
                    .find((line) => line.startsWith('{"path":'))!,
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
        if (action === "no-op") {
          expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(2);
          expect(JSON.parse(outcome.stdout).error.code).toBe(
            "NO_PATCH_APPLIED",
          );
          expect(trees).toHaveLength(2);
          expect(trees[0]).toBe(trees[1]);
        } else if (inline) {
          expect(outcome.exitCode, outcome.stdout + outcome.stderr).toBe(
            policy === "control" ? 0 : 2,
          );
          if (policy !== "control")
            expect(outcome.stderr).toContain(
              "uncommitted changes before patching",
            );
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
        if (publish && !(inline && policy !== "control")) {
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
          expect(published("show", `${branch}:${dataPath}`)).toBe(
            `Unchanged filter input\n${effective}`,
          );
        } else
          expect(await readFile(join(directory, ".git", "index"))).toEqual(
            index,
          );
      },
      preparedSnapshotTimeout,
    );
  }
}

test("publication keeps mixed valid and missing selected-path errors before branching", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  const original = git("rev-parse", "HEAD");
  const index = await readFile(join(directory, ".git", "index"));
  const outcome = await runWorkflow(
    ["patch", "--scan", "scan-1", "--create-pr", "--json"],
    {
      currentDirectory: directory,
      onWorkbench: () =>
        savedScan(resultWithFindings(["high"]), "scan-1", directory),
      onRepositoryCommand: (command, args, cwd, options) =>
        command === "git"
          ? runGitRepositoryCommand(command, args, cwd, options)
          : args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1",
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
    },
  );
  expect(outcome.exitCode).toBe(2);
  expect(outcome.stderr).toContain(
    `pathspec '${join("src", "missing.ts")}' did not match any files`,
  );
  expect(git("rev-parse", "HEAD")).toBe(original);
  expect(git("branch", "--show-current")).toBe("main");
  expect(
    git("for-each-ref", "--format=%(refname)", "refs/heads/codex-security/"),
  ).toBe("");
  expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
});

test.skipIf(process.platform === "win32")(
  "an unreadable patched file still fails required snapshotting",
  async () => {
    const { directory } = await publicationRepository(fixtures);
    const source = join(directory, "src/finding-1.ts");
    let turns = 0;
    try {
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: async (_args, output) => {
            turns++;
            await writeFile(source, "fixed\n");
            await chmod(source, 0);
            output!.stdout.write("Synthetic edit complete.\n");
            return 0;
          },
        },
      );
      expect(turns).toBe(1);
      expect(outcome.exitCode).toBe(2);
      expect(outcome.stdout + outcome.stderr).toContain("Permission denied");
      await expect(readFile(source)).rejects.toMatchObject({ code: "EACCES" });
    } finally {
      await chmod(source, 0o600);
    }
  },
);
