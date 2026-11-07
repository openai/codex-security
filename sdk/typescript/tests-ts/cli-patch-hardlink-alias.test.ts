import { afterEach, expect, mock, test } from "bun:test";
import fs from "node:fs";
import { link, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  publicationRepository,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

// Keep native hardlinks, directory enumeration, and Git publication. Emulate
// only filesystem alias lookup/native spelling so every host covers ambiguity.
for (const mode of [
  "exact spelling",
  "native spelling",
  "unresolved spelling",
  "other file",
  "other parent",
  "native lookup failure",
] as const) {
  test(`publishes only the reported hardlink with ${mode}`, async () => {
    if (
      runTestInSubprocess(
        fileURLToPath(import.meta.url),
        `publishes only the reported hardlink with ${mode}`,
      )
    )
      return;
    const { directory, git } = await publicationRepository(fixtures);
    await writeFile(join(directory, "README"), "original\n");
    await link(join(directory, "README"), join(directory, "alias-7"));
    await writeFile(join(directory, "other"), "unrelated\n");
    git("add", ".");
    git("commit", "-m", "Synthetic hardlink baseline");
    expect(git("status", "--porcelain")).toBe("");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const stored = fs.lstatSync(join(directory, "README"), { bigint: true });
    const linked = fs.lstatSync(join(directory, "alias-7"), { bigint: true });
    expect(linked.dev).toBe(stored.dev);
    expect(linked.ino).toBe(stored.ino);
    const reported = mode === "exact spelling" ? "README" : "readme";
    const originalStat = fs.lstatSync;
    const originalRealpath = fs.realpathSync.native;
    let nativeLookups = 0;
    const lookup = (path: fs.PathLike, options?: fs.StatOptions) => {
      const text = Buffer.isBuffer(path) ? path.toString() : String(path);
      return originalStat(
        text === join(directory, "readme") ? join(directory, "README") : path,
        options,
      );
    };
    const native = ((path: fs.PathLike, options?: fs.EncodingOption) => {
      const text = Buffer.isBuffer(path) ? path.toString() : String(path);
      if (text !== join(directory, "readme"))
        return originalRealpath(path, options);
      nativeLookups++;
      if (mode === "native lookup failure")
        throw Object.assign(
          new Error("Synthetic native spelling unavailable"),
          {
            code: "ENOENT",
          },
        );
      const resolved =
        mode === "unresolved spelling"
          ? text
          : mode === "other file"
            ? join(directory, "other")
            : mode === "other parent"
              ? join(directory, "src", "README")
              : join(directory, "README");
      return Buffer.from(resolved);
    }) as typeof fs.realpathSync.native;
    mock.module("node:fs", () => ({
      ...fs,
      default: fs,
      lstatSync: lookup,
      realpathSync: Object.assign(fs.realpathSync.bind(fs), { native }),
    }));
    const publicationCommands: string[] = [];
    let forgeCalls = 0;
    try {
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = reported;
      const outcome = await runWorkflow(
        ["patch", "--scan", "scan-1", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          result,
          onWorkbench: () => savedScan(result, "scan-1", directory),
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              const operation = args[0] === "-C" ? args[2] : args[0];
              if (["switch", "commit", "push"].includes(operation ?? ""))
                publicationCommands.push(operation!);
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            forgeCalls++;
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            await writeFile(join(directory, "README"), "fixed\n");
            output?.stdout.write(
              JSON.stringify({
                patches: [
                  {
                    occurrenceId: "occ_1",
                    status: "verified",
                    files: [reported],
                    verification: "Synthetic regression passed.",
                  },
                ],
              }),
            );
            return 0;
          },
        },
      );
      expect(await readFile(join(directory, "README"), "utf8")).toBe("fixed\n");
      expect(await readFile(join(directory, "alias-7"), "utf8")).toBe(
        "fixed\n",
      );
      if (mode === "exact spelling" || mode === "native spelling") {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(git("show", "HEAD:README")).toBe("fixed");
        expect(git("show", "HEAD:alias-7")).toBe("original");
        expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
        if (mode === "exact spelling") expect(nativeLookups).toBe(0);
      } else {
        expect(outcome.exitCode, outcome.stderr).toBe(2);
        expect(outcome.stderr).toContain(
          mode === "native lookup failure"
            ? "Synthetic native spelling unavailable"
            : "Cannot determine the filesystem spelling",
        );
        expect(nativeLookups).toBe(1);
        expect(publicationCommands).toEqual([]);
        // The only hosting call is the initial existing-PR lookup.
        expect(forgeCalls).toBe(1);
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(git("write-tree")).toBe(index);
        expect(git("ls-remote", "origin")).toBe("");
      }
    } finally {
      mock.restore();
    }
  });
}
