import { afterEach, expect, mock, test } from "bun:test";
import fs from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
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

// Exercise filesystem aliases on every host while retaining real Git status,
// index, commits, and local-remote publication. Native filesystem controls below
// ensure that the implementation does not fold distinct POSIX names.
function simulateAliases(aliases: ReadonlyMap<string, string>) {
  const original = fs.lstatSync;
  const lookup = (path: fs.PathLike, options?: fs.StatOptions) => {
    const text = Buffer.isBuffer(path) ? path.toString() : String(path);
    return original(aliases.get(text) ?? path, options);
  };
  mock.module("node:fs", () => ({ ...fs, default: fs, lstatSync: lookup }));
}

const runCommand: typeof runGitRepositoryCommand = (
  command,
  args,
  cwd,
  options,
) =>
  command === "git"
    ? runGitRepositoryCommand(command, args, cwd, options)
    : args[1] === "list"
      ? "[]"
      : "https://github.example.test/example/repository/pull/1";

test.each([
  ["README.md", "README.md"],
  ["README.md", "readme.md"],
  [join("Source", "RÉADME.md"), join("source", "réadme.md")],
])("rejects dirty %s when the model reports %s", async (stored, reported) => {
  if (
    runTestInSubprocess(
      fileURLToPath(import.meta.url),
      `rejects dirty ${stored} when the model reports ${reported}`,
    )
  )
    return;
  const { directory, git } = await publicationRepository(fixtures);
  await mkdir(dirname(join(directory, stored)), { recursive: true });
  await writeFile(join(directory, stored), "original\n");
  git("add", ".");
  git("commit", "-m", "Synthetic file baseline");
  await writeFile(join(directory, stored), "original\nsynthetic local edit\n");
  const head = git("rev-parse", "HEAD");
  const index = git("write-tree");
  const aliases = new Map<string, string>();
  const storedParts = stored.split(sep);
  const reportedParts = reported.split(sep);
  for (let i = 0; i < storedParts.length; i++) {
    const parent = join(directory, ...storedParts.slice(0, i));
    aliases.set(join(parent, reportedParts[i]!), join(parent, storedParts[i]!));
  }
  simulateAliases(aliases);
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
          const separator = args.indexOf("--");
          const translated = args.map((arg, i) =>
            separator >= 0 && i > separator && arg === reported ? stored : arg,
          );
          return runCommand(command, translated, cwd, options);
        },
        onCodex: async (_args, output) => {
          await writeFile(
            join(directory, stored),
            "fixed\nsynthetic local edit\n",
          );
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
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("uncommitted changes before patching");
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(git("write-tree")).toBe(index);
    expect(git("ls-remote", "origin")).toBe("");
    expect(await readFile(join(directory, stored), "utf8")).toBe(
      "fixed\nsynthetic local edit\n",
    );
  } finally {
    mock.restore();
  }
});

test.each([
  "Codex-Security/patch-scan-1",
  "Codex-Security",
  "Codex-Security/patch-scan-1/child",
])("rejects aliased local ref %s before model work", async (branch) => {
  if (
    runTestInSubprocess(
      fileURLToPath(import.meta.url),
      `rejects aliased local ref ${branch} before model work`,
    )
  )
    return;
  const { directory, git } = await publicationRepository(fixtures);
  git("branch", branch);
  const refs = git(
    "rev-parse",
    "--path-format=absolute",
    "--git-path",
    "refs/heads",
  );
  simulateAliases(
    new Map([[join(refs, "codex-security"), join(refs, "Codex-Security")]]),
  );
  const head = git("rev-parse", "HEAD");
  const index = git("write-tree");
  let modelCalls = 0;
  try {
    const result = resultWithFindings(["high"]);
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        result,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: runCommand,
        onCodex: () => {
          modelCalls++;
          return 0;
        },
      },
    );
    expect(modelCalls).toBe(0);
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain(
      "Patch branch or pull request already exists",
    );
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(git("write-tree")).toBe(index);
    expect(git("ls-remote", "origin")).toBe("");
  } finally {
    mock.restore();
  }
});

test("keeps distinct native filesystem paths and refs publishable", async () => {
  const { directory, git } = await publicationRepository(fixtures);
  await writeFile(join(directory, "README.md"), "original upper\n");
  // A native alias should be rejected; distinct filesystem entries may coexist.
  const distinct = !fs.existsSync(join(directory, "readme.md"));
  if (distinct)
    await writeFile(join(directory, "readme.md"), "original lower\n");
  git("add", ".");
  git("commit", "-m", "Synthetic case baseline");
  await writeFile(join(directory, "README.md"), "synthetic local edit\n");
  git("branch", "Codex-Security/patch-scan-1");
  const head = git("rev-parse", "HEAD");
  const result = resultWithFindings(["high"]);
  result.findings.findings[0]!.locations[0]!.path = "readme.md";
  let modelCalls = 0;
  const outcome = await runWorkflow(
    ["patch", "--scan", "scan-1", "--create-pr", "--json"],
    {
      currentDirectory: directory,
      result,
      onWorkbench: () => savedScan(result, "scan-1", directory),
      onRepositoryCommand: runCommand,
      onCodex: async (_args, output) => {
        modelCalls++;
        await writeFile(join(directory, "readme.md"), "fixed lower\n");
        output?.stdout.write(
          JSON.stringify({
            patches: [
              {
                occurrenceId: "occ_1",
                status: "verified",
                files: ["readme.md"],
                verification: "Synthetic regression passed.",
              },
            ],
          }),
        );
        return 0;
      },
    },
  );
  expect(outcome.exitCode, outcome.stderr).toBe(distinct ? 0 : 2);
  expect(modelCalls).toBe(distinct ? 1 : 0);
  expect(await readFile(join(directory, "README.md"), "utf8")).toBe(
    "synthetic local edit\n",
  );
  if (distinct) {
    expect(git("show", "HEAD:README.md")).toBe("original upper");
    expect(git("show", "HEAD:readme.md")).toBe("fixed lower");
    expect(git("ls-remote", "origin")).toContain(git("rev-parse", "HEAD"));
  } else {
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(git("ls-remote", "origin")).toBe("");
  }
});
