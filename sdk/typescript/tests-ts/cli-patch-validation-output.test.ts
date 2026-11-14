import { afterEach, expect, test } from "bun:test";
import { appendFile, chmod, link, readFile, writeFile } from "node:fs/promises";
import { join, sep } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);
const diagnostic = (value: string) => value.replaceAll(sep, "/");

for (const source of ["supplied", "saved", "batch", "scan"] as const)
  for (const control of ["configuration", "hook"] as const)
    for (const fullOutput of [false, true])
      test(`retains uninspected ${source} edits after ${control} validation (full: ${fullOutput})`, async () => {
        const { directory, git, remote } =
          await publicationRepository(fixtures);
        const alias = join(directory, "control-alias");
        const active = join(
          directory,
          ".git",
          ...(control === "hook" ? ["hooks", "pre-commit"] : ["config"]),
        );
        if (control === "configuration") {
          await link(active, alias);
        } else {
          await writeFile(alias, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
          await chmod(alias, 0o755);
        }
        for (const index of [2, 3])
          await writeFile(
            join(directory, `src/finding-${index}.ts`),
            "before\n",
          );
        git("add", ".");
        git("commit", "-m", "Synthetic control baseline");
        if (control === "hook") await link(alias, active);
        git("update-index", "--refresh");
        const original = await readFile(active);
        const head = git("rev-parse", "HEAD");
        const index = await readFile(join(directory, ".git", "index"));
        const result = resultWithFindings(["high", "high", "high"]);
        const interruptedTurn = source === "batch" || source === "scan" ? 2 : 1;
        let calls = 0;
        let validationPending = false;
        const postTurnGit: string[][] = [];
        let publications = 0;
        const arguments_ =
          source === "scan"
            ? ["scan", "--patch", "--fail-on-severity", "high"]
            : [
                "patch",
                ...(source === "supplied"
                  ? ["Synthetic issue"]
                  : ["--scan", "scan-1"]),
              ];
        const outcome = await runWorkflow(
          [
            ...arguments_,
            "--create-pr",
            "--json",
            ...(fullOutput ? ["--full-output"] : []),
          ],
          {
            currentDirectory: directory,
            result,
            onWorkbench: () => savedScan(result, "scan-1", directory),
            onRepositoryCommand: (command, args, cwd, options) => {
              if (command !== "git") {
                if (args[1] === "create") publications++;
                return args[1] === "list"
                  ? "[]"
                  : "https://github.example.test/example/repository/pull/1";
              }
              if (validationPending) postTurnGit.push([...args]);
              return runGitRepositoryCommand(command, args, cwd, options);
            },
            onCodex: async (_args, output) => {
              calls++;
              await writeFile(
                join(directory, `src/finding-${calls}.ts`),
                "retained change\n",
              );
              if (calls === interruptedTurn) {
                if (control === "configuration")
                  await appendFile(alias, "\n[synthetic]\n changed = true\n");
                else await writeFile(alias, "#!/bin/sh\nexit 1\n");
                validationPending = true;
              }
              output?.stdout.write(
                JSON.stringify({
                  patches: [
                    {
                      occurrenceId: `occ_${calls}`,
                      status: "verified",
                      files: [`src/finding-${calls}.ts`],
                      verification: "Synthetic check.",
                    },
                  ],
                }),
              );
              return 0;
            },
          },
        );
        const message = `Git ${control} changed during the patch: ${active}`;
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(diagnostic(outcome.stderr)).toContain(diagnostic(message));
        expect(calls).toBe(interruptedTurn);
        expect(postTurnGit).toEqual([]);
        expect(publications).toBe(0);
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
        expect(
          repositoryGit(remote)("for-each-ref", "--format=%(refname)"),
        ).toBe("");
        expect(await readFile(active)).not.toEqual(original);
        for (let turn = 1; turn <= interruptedTurn; turn++)
          expect(
            await readFile(join(directory, `src/finding-${turn}.ts`), "utf8"),
          ).toBe("retained change\n");
        expect(
          await readFile(join(directory, "src/finding-3.ts"), "utf8"),
        ).toBe("before\n");
        const value = JSON.parse(outcome.stdout);
        if (fullOutput) expect(value.ok).toBe(false);
        if (fullOutput || source !== "scan") {
          expect({
            ...value.error,
            message: diagnostic(value.error.message),
          }).toEqual({
            code: source === "scan" ? "SCAN_FAILED" : "PATCH_FAILED",
            message: diagnostic(message),
          });
        }
        if (fullOutput && source !== "scan") {
          // Patch failures already omit data in full-output mode.
          expect(value).not.toHaveProperty("data");
          return;
        }
        const data = fullOutput ? value.data : value;
        expect(data).not.toHaveProperty("applied");
        expect(data).not.toHaveProperty("filesChanged");
        if (source !== "scan") {
          expect(data.repository).toBe(directory);
          expect(data.files).toEqual(
            interruptedTurn === 1 ? [] : ["src/finding-1.ts"],
          );
        }
        if (source !== "supplied") {
          expect(data.patches).toHaveLength(interruptedTurn);
          if (interruptedTurn === 2)
            expect(data.patches[0]).toEqual({
              occurrenceId: "occ_1",
              status: "verified",
              files: ["src/finding-1.ts"],
              verification: "Synthetic check.",
            });
          const failed = data.patches[interruptedTurn - 1];
          expect({ ...failed, reason: diagnostic(failed.reason) }).toEqual({
            occurrenceId: `occ_${interruptedTurn}`,
            status: "failed",
            files: [],
            reason: diagnostic(`${message} File changes were not inspected.`),
          });
          expect(data).not.toHaveProperty("pullRequest");
        }
      });

for (const saved of [false, true])
  test(`preserves known pre-turn output for invalid configuration (saved: ${saved})`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    const configuration = join(directory, ".git", "config");
    const original = await readFile(configuration);
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    await appendFile(configuration, "\n[broken\n");
    let calls = 0;
    const result = resultWithFindings(["high"]);
    try {
      const outcome = await runWorkflow(
        [
          "patch",
          ...(saved ? ["--scan", "scan-1"] : ["Synthetic issue"]),
          "--json",
        ],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: runGitRepositoryCommand,
          onCodex: () => {
            calls++;
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(calls).toBe(0);
      const value = JSON.parse(outcome.stdout);
      expect(value).toMatchObject({
        ok: false,
        applied: false,
        filesChanged: 0,
        files: [],
        error: { code: "PATCH_FAILED" },
      });
      expect(value.error.message).toContain("bad config line");
      expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
        "original\n",
      );
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
    } finally {
      await writeFile(configuration, original);
    }
    expect(git("rev-parse", "HEAD")).toBe(head);
  });

for (const saved of [false, true])
  test(`retains uninspected edits when a later turn preparation fails (saved: ${saved})`, async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const head = git("rev-parse", "HEAD");
    const result = resultWithFindings(["high"]);
    const failure = new Error("Synthetic later preparation failure.");
    let failPreparation = false;
    let modelTurns = 0;
    let failedPreparations = 0;
    let publications = 0;
    const outcome = await runWorkflow(
      [
        "patch",
        ...(saved ? ["--scan", "scan-1"] : ["Synthetic issue"]),
        "--create-pr",
        "--json",
      ],
      {
        currentDirectory: directory,
        result,
        manualCodexPreparation: true,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command !== "git") {
            if (args[1] === "create") publications++;
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          }
          if (failPreparation && options?.patchSnapshot) {
            failedPreparations++;
            throw failure;
          }
          return runGitRepositoryCommand(command, args, cwd, options);
        },
        onCodex: async (_args, output) => {
          await output?.appServer?.onBeforeTurn?.();
          modelTurns++;
          await writeFile(
            join(directory, "src/finding-1.ts"),
            "retained change\n",
          );
          failPreparation = true;
          await output?.appServer?.onBeforeTurn?.();
          modelTurns++;
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(modelTurns).toBe(1);
    expect(failedPreparations).toBe(1);
    expect(publications).toBe(0);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
      "",
    );
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "retained change\n",
    );
    const value = JSON.parse(outcome.stdout);
    expect(value.error).toEqual({
      code: "PATCH_FAILED",
      message: failure.message,
    });
    expect(value).not.toHaveProperty("applied");
    expect(value).not.toHaveProperty("filesChanged");
    if (saved)
      expect(value.patches).toEqual([
        {
          occurrenceId: "occ_1",
          status: "failed",
          files: [],
          reason: `${failure.message} File changes were not inspected.`,
        },
      ]);
  });
