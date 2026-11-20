import fs from "node:fs";
import { expect, mock, test } from "bun:test";
import { mkdir, readFile, writeFile, link } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  publicationRepository,
  resultWithFindings,
  completePatches,
  runPublication,
  runPublicationCommand,
  savedScan,
  patchDirectories,
  runSavedPublication,
  runGitRepositoryCommand,
} from "./cli-patch-fixtures.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = patchDirectories();

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
    const outcome = await runSavedPublication(directory, {
      result,
      onWorkbench: () => savedScan(result, "scan-1", directory),
      onRepositoryCommand: (command, args, cwd, options) => {
        const separator = args.indexOf("--");
        const translated = args.map((arg, i) =>
          separator >= 0 && i > separator && arg === reported ? stored : arg,
        );
        return runPublicationCommand(command, translated, cwd, options);
      },
      onCodex: async (args, output) => {
        await writeFile(
          join(directory, stored),
          "fixed\nsynthetic local edit\n",
        );
        completePatches(args, output, "verified", [reported]);
        return 0;
      },
    });
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
    const outcome = await runPublication(
      directory,
      ["src/finding-1.ts"],
      () => {
        modelCalls++;
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
  const outcome = await runSavedPublication(directory, {
    result,
    onWorkbench: () => savedScan(result, "scan-1", directory),
    onRepositoryCommand: runPublicationCommand,
    onCodex: async (args, output) => {
      modelCalls++;
      await writeFile(join(directory, "readme.md"), "fixed lower\n");
      completePatches(args, output, "verified", ["readme.md"]);
      return 0;
    },
  });
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

// Keep native hardlinks, directory enumeration, and Git publication. Emulate
// only filesystem alias lookup/native spelling so every host covers ambiguity.
for (const mode of [
  "exact spelling",
  "native spelling",
  "precomposed Git spelling",
  "a case-only Windows rename",
  "unresolved spelling",
  "other file",
  "other parent",
  "native lookup failure",
] as const) {
  const retainedCase = mode === "a case-only Windows rename";
  const run = test.skipIf(retainedCase && process.platform !== "win32");
  run(`publishes only the reported hardlink with ${mode}`, async () => {
    if (
      runTestInSubprocess(
        fileURLToPath(import.meta.url),
        `publishes only the reported hardlink with ${mode}`,
      )
    )
      return;
    const { directory, git } = await publicationRepository(fixtures);
    const precomposed = mode === "precomposed Git spelling";
    const storedName = precomposed ? "caf\u00e9.ts" : "README";
    const nativeName = precomposed ? "cafe\u0301.ts" : storedName;
    if (precomposed) git("config", "core.precomposeUnicode", "true");
    await writeFile(join(directory, storedName), "original\n");
    await link(join(directory, storedName), join(directory, "alias-7"));
    await writeFile(join(directory, "other"), "unrelated\n");
    git("add", ".");
    git("commit", "-m", "Synthetic hardlink baseline");
    if (retainedCase) {
      git("config", "core.ignoreCase", "true");
      fs.renameSync(join(directory, storedName), join(directory, "case-hop"));
      fs.renameSync(join(directory, "case-hop"), join(directory, "readme"));
    }
    expect(git("status", "--porcelain")).toBe("");
    const head = git("rev-parse", "HEAD");
    const index = git("write-tree");
    const stored = fs.lstatSync(join(directory, storedName), { bigint: true });
    const linked = fs.lstatSync(join(directory, "alias-7"), { bigint: true });
    expect(linked.dev).toBe(stored.dev);
    expect(linked.ino).toBe(stored.ino);
    const reported = precomposed
      ? nativeName
      : mode === "exact spelling"
        ? storedName
        : "readme";
    const originalStat = fs.lstatSync;
    const originalList = fs.readdirSync;
    const originalRealpath = fs.realpathSync.native;
    let nativeLookups = 0;
    const lookup = (path: fs.PathLike, options?: fs.StatOptions) => {
      const text = Buffer.isBuffer(path) ? path.toString() : String(path);
      return originalStat(
        text === join(directory, reported) ? join(directory, storedName) : path,
        options,
      );
    };
    const native = ((path: fs.PathLike, options?: fs.EncodingOption) => {
      const text = Buffer.isBuffer(path) ? path.toString() : String(path);
      if (text !== join(directory, precomposed ? storedName : "readme"))
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
              : join(directory, nativeName);
      return Buffer.from(resolved);
    }) as typeof fs.realpathSync.native;
    if (!retainedCase)
      mock.module("node:fs", () => ({
        ...fs,
        default: fs,
        lstatSync: lookup,
        ...(precomposed && {
          // Simulate a volume enumerating NFD while the Git tree stores NFC.
          readdirSync(path: fs.PathLike, options: { encoding: "buffer" }) {
            const names = originalList(path, options);
            if (String(path) !== directory || options?.encoding !== "buffer")
              return names;
            return names.map((name) =>
              name.equals(Buffer.from(storedName))
                ? Buffer.from(nativeName)
                : name,
            );
          },
        }),
        realpathSync: Object.assign(fs.realpathSync.bind(fs), { native }),
      }));
    const publicationCommands: string[] = [];
    let forgeCalls = 0;
    try {
      const result = resultWithFindings(["high"]);
      result.findings.findings[0]!.locations[0]!.path = reported;
      const outcome = await runSavedPublication(directory, {
        result,
        onWorkbench: () => savedScan(result, "scan-1", directory),
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git") {
            const operation = args[0] === "-C" ? args[2] : args[0];
            if (["switch", "commit", "push"].includes(operation ?? ""))
              publicationCommands.push(operation!);
            // macOS Git precomposes literal pathspec arguments before lookup.
            const separator = args.indexOf("--");
            const gitArgs =
              precomposed &&
              separator >= 0 &&
              args.includes("--literal-pathspecs")
                ? args.map((arg, i) =>
                    i > separator && arg === nativeName ? storedName : arg,
                  )
                : args;
            return runGitRepositoryCommand(command, gitArgs, cwd, options);
          }
          forgeCalls++;
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (_args, output) => {
          await writeFile(join(directory, storedName), "fixed\n");
          if (precomposed || retainedCase)
            await writeFile(join(directory, "other"), "second edit\n");
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files:
                    precomposed || retainedCase
                      ? [reported, "other"]
                      : [reported],
                  verification: "Synthetic regression passed.",
                },
              ],
            }),
          );
          return 0;
        },
      });
      expect(await readFile(join(directory, storedName), "utf8")).toBe(
        "fixed\n",
      );
      expect(await readFile(join(directory, "alias-7"), "utf8")).toBe(
        "fixed\n",
      );
      if (
        mode === "exact spelling" ||
        mode === "native spelling" ||
        precomposed ||
        retainedCase
      ) {
        expect(outcome.exitCode, outcome.stderr).toBe(0);
        expect(git("show", `HEAD:${storedName}`)).toBe("fixed");
        if (precomposed || retainedCase)
          expect(git("show", "HEAD:other")).toBe("second edit");
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
