import { expect, test, spyOn } from "bun:test";
import {
  mkdir,
  readFile,
  rename,
  writeFile,
  link,
  rm,
  symlink,
  type FileHandle,
} from "node:fs/promises";
import { join, resolve } from "node:path";
import {
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  completePatches,
  runPublication,
  runPublicationCommand,
  savedScan,
  patchDirectories,
  initializePatchGit,
} from "./cli-patch-fixtures.js";
import type { BigIntStats, Stats } from "node:fs";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = patchDirectories();

test.each(["issue", "saved"] as const)(
  "publishes a materialized tracked file outside the sparse checkout for a %s patch",
  async (mode) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    git("config", "core.autocrlf", "true");
    const outside = join(directory, "outside");
    const file = join(outside, "finding.ts");
    await mkdir(outside);
    await writeFile(file, "original\n");
    git("add", "outside/finding.ts");
    git("commit", "-m", "Add tracked source outside the cone");
    const parent = git("rev-parse", "HEAD");
    git("sparse-checkout", "set", "--cone", "src");
    expect(git("ls-files", "-t", "outside/finding.ts")).toBe(
      "S outside/finding.ts",
    );
    await expect(readFile(file)).rejects.toMatchObject({ code: "ENOENT" });
    git(
      "checkout-index",
      "--index",
      "--ignore-skip-worktree-bits",
      "--",
      "outside/finding.ts",
    );
    expect(git("--no-optional-locks", "status", "--porcelain")).toBe("");
    const result = await runPublication(
      directory,
      mode === "issue" ? "issue" : ["outside/finding.ts"],
      () => writeFile(file, "fixed\n"),
    );
    expect(result.exitCode, result.stderr).toBe(0);
    const remoteGit = repositoryGit(remote);
    const tip = remoteGit("for-each-ref", "--format=%(objectname)");
    expect(remoteGit("show", `${tip}:outside/finding.ts`)).toBe("fixed");
    expect(remoteGit("rev-parse", `${tip}^`)).toBe(parent);
  },
);

test.skipIf(process.platform !== "linux")(
  "publishes both supplied-issue edits when a raw path has a Unicode alias",
  async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const name = Buffer.from([0x72, 0xff]);
    const raw = Buffer.concat([Buffer.from(directory + "/"), name]);
    const alias = join(directory, "r\ufffd");
    await writeFile(raw, "raw before\n");
    await writeFile(alias, "alias before\n");
    git("add", "--all");
    git("commit", "-m", "Synthetic byte-path baseline");
    const result = await runPublication(directory, "issue", async () => {
      await writeFile(raw, "raw after\n");
      await writeFile(alias, "alias after\n");
    });
    expect(result.exitCode, result.stderr).toBe(0);
    const tip = repositoryGit(remote)("for-each-ref", "--format=%(objectname)");
    const entries = Buffer.from(
      await runGitRepositoryCommand("git", ["ls-tree", "-z", tip], remote, {
        encoding: "base64",
      }),
      "base64",
    )
      .toString("latin1")
      .split("\0");
    for (const [path, expected] of [
      [name, "raw after"],
      [Buffer.from("r\ufffd"), "alias after"],
    ] as const) {
      const entry = entries.find((record) =>
        record.endsWith("\t" + path.toString("latin1")),
      );
      expect(entry).toBeDefined();
      expect(
        repositoryGit(remote)(
          "cat-file",
          "blob",
          entry!.split("\t")[0]!.split(" ")[2]!,
        ),
      ).toBe(expected);
    }
    expect(git("status", "--porcelain")).toBe("");
  },
);

test.skipIf(process.platform !== "linux").each([false, true])(
  "checks ignored content at a raw publication path (copied: %p)",
  async (copied) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    await writeFile(join(directory, ".gitignore"), ".env\n");
    git("add", ".gitignore");
    git("commit", "-m", "Synthetic ignored baseline");
    const ignored = "SYNTHETIC_IGNORED_CONTENT\n";
    await writeFile(join(directory, ".env"), ignored);
    const original = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git/index"));
    const rawName = Buffer.concat([
      Buffer.from("src/new-"),
      Buffer.from([0xff]),
    ]);
    const raw = Buffer.concat([Buffer.from(`${directory}/`), rawName]);
    const alias = join(directory, "src/new-\ufffd");
    const outcome = await runPublication(directory, ["src"], async () => {
      await writeFile(
        raw,
        copied ? ignored : "Independent synthetic content\n",
      );
      await writeFile(alias, "Distinct Unicode alias\n");
    });
    expect(outcome.exitCode, outcome.stderr).toBe(copied ? 2 : 0);
    if (copied) {
      expect(outcome.stderr).toContain("matches pre-existing ignored content");
      expect(git("rev-parse", "HEAD")).toBe(original);
      expect(await readFile(join(directory, ".git/index"))).toEqual(index);
      expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
        "",
      );
    } else {
      const names = Buffer.from(
        await runGitRepositoryCommand(
          "git",
          [
            "ls-tree",
            "-r",
            "--name-only",
            "-z",
            "refs/heads/codex-security/patch-scan-1",
          ],
          remote,
          { encoding: "base64" },
        ),
        "base64",
      );
      expect(names.includes(rawName)).toBe(true);
    }
    expect(await readFile(alias, "utf8")).toBe("Distinct Unicode alias\n");
  },
);

test.skipIf(process.platform !== "linux")(
  "assesses and publishes the exact raw rename source without deleting its Unicode alias",
  async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const rawName = Buffer.concat([
      Buffer.from("src/old-"),
      Buffer.from([0xff]),
    ]);
    const raw = Buffer.concat([Buffer.from(`${directory}/`), rawName]);
    const alias = "src/old-\ufffd";
    await writeFile(raw, "Synthetic rename source\n");
    await writeFile(join(directory, alias), "Synthetic alias to keep\n");
    git("add", ".");
    git("commit", "-m", "Synthetic rename baseline");
    const original = git("rev-parse", "HEAD");
    let assessments = 0;
    const outcome = await runWorkflow(
      [
        "patch",
        "--scan",
        "scan-1",
        "--create-pr",
        "--assess-patch-risk",
        "--json",
      ],
      {
        currentDirectory: directory,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onRepositoryCommand: runPublicationCommand,
        onCodex: async (args, output) => {
          if (output?.appServer?.prompt.includes("immutable patch artifact")) {
            assessments++;
            const artifact = JSON.parse(
              output.appServer.prompt
                .split("\n")
                .find((line) => line.startsWith('{"path":'))!,
            ) as { path: string };
            const verification = await fixtures.create(
              "patch-byte-rename-apply-",
            );
            const applyGit = repositoryGit(verification);
            applyGit("clone", "--no-hardlinks", directory, ".");
            applyGit("checkout", original);
            applyGit("apply", "--check", artifact.path);
            applyGit("apply", artifact.path);
            expect(
              await readFile(join(verification, "src/new.ts"), "utf8"),
            ).toBe("Synthetic rename source\n");
            expect(await readFile(join(verification, alias), "utf8")).toBe(
              "Synthetic alias to keep\n",
            );
            await expect(
              readFile(
                Buffer.concat([Buffer.from(`${verification}/`), rawName]),
              ),
            ).rejects.toMatchObject({ code: "ENOENT" });
            output.stdout.write(patchRiskAssessment().report);
            return 0;
          }
          await rename(raw, join(directory, "src/new.ts"));
          completePatches(args, output, "verified", ["src/new.ts"]);
          return 0;
        },
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(assessments).toBe(1);
    const published = repositoryGit(remote);
    const branch = "refs/heads/codex-security/patch-scan-1";
    expect(published("show", `${branch}:src/new.ts`)).toBe(
      "Synthetic rename source",
    );
    expect(published("show", `${branch}:${alias}`)).toBe(
      "Synthetic alias to keep",
    );
    const names = Buffer.from(
      await runGitRepositoryCommand(
        "git",
        ["ls-tree", "-r", "--name-only", "-z", branch],
        remote,
        { encoding: "base64" },
      ),
      "base64",
    );
    expect(names.includes(rawName)).toBe(false);
    expect(git("diff", "--cached", "--name-only")).toBe("");
  },
);

test.skipIf(process.platform !== "linux").each(["root", "src"])(
  "publishes a selected directory without importing a replacement-decoded index path from %s",
  async (scope) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    await mkdir(join(directory, "src/nested"));
    await rename(
      join(directory, "src/finding-1.ts"),
      join(directory, "src/nested/finding-1.ts"),
    );
    const raw = Buffer.concat([
      Buffer.from(`${directory}/src/nested/file-`),
      Buffer.from([0xff]),
      Buffer.from(".txt"),
    ]);
    const alias = join(directory, "src/nested/file-\ufffd.txt");
    await writeFile(raw, "Synthetic tracked original\n");
    await writeFile(
      join(directory, ".gitignore"),
      ".env\n/src/nested/file-\ufffd.txt\n",
    );
    git("add", ".");
    git("commit", "-m", "Synthetic filename baseline");
    await writeFile(join(directory, ".env"), "SYNTHETIC_IGNORED_CONTENT\n");
    const before = git("rev-parse", "HEAD");
    const cwd = scope === "root" ? directory : join(directory, "src");
    const outcome = await runPublication(
      cwd,
      [scope === "root" ? "src/nested" : "nested"],
      async () => {
        await writeFile(join(directory, "src/nested/finding-1.ts"), "fixed\n");
        await writeFile(alias, await readFile(join(directory, ".env")));
      },
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(git("diff", "--name-only", before, "HEAD")).toBe(
      "src/nested/finding-1.ts",
    );
    const published = repositoryGit(remote);
    expect(
      published(
        "show",
        "refs/heads/codex-security/patch-scan-1:src/nested/finding-1.ts",
      ),
    ).toBe("fixed");
    expect(() =>
      published(
        "show",
        "refs/heads/codex-security/patch-scan-1:src/nested/file-\ufffd.txt",
      ),
    ).toThrow();
    expect(await readFile(raw, "utf8")).toBe("Synthetic tracked original\n");
    expect(await readFile(alias, "utf8")).toBe("SYNTHETIC_IGNORED_CONTENT\n");
  },
);

test.skipIf(process.platform !== "linux").each([false, true])(
  "checks the actual registration for a deinitialized raw gitlink beside a Unicode alias (published: %p)",
  async (published) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const module = join(directory, ".git/modules/actual");
    await mkdir(module, { recursive: true });
    const inner = repositoryGit(module);
    inner("init", "--bare");
    inner("config", "user.name", "Synthetic User");
    inner("config", "user.email", "synthetic@example.test");
    const tree = await runGitRepositoryCommand("git", ["mktree"], module, {
      input: "",
    });
    const before = inner("commit-tree", tree, "-m", "Synthetic original");
    const after = inner(
      "commit-tree",
      tree,
      "-p",
      before,
      "-m",
      "Synthetic update",
    );
    inner("update-ref", "refs/heads/main", after);
    inner("update-ref", "refs/remotes/origin/main", published ? after : before);
    const rawName = Buffer.concat([
      Buffer.from("src/nested-"),
      Buffer.from([0xfe]),
    ]);
    await mkdir(Buffer.concat([Buffer.from(`${directory}/`), rawName]));
    const stage = (commit: string) =>
      runGitRepositoryCommand(
        "git",
        ["update-index", "-z", "--index-info"],
        directory,
        {
          input: Buffer.concat([
            Buffer.from(`160000 ${commit}\t`),
            rawName,
            Buffer.from([0]),
          ]),
        },
      );
    await stage(before);
    await writeFile(
      join(directory, ".gitmodules"),
      Buffer.concat([
        Buffer.from('[submodule "actual"]\n\tpath = '),
        rawName,
        Buffer.from("\n\turl = ./synthetic-remote\n"),
      ]),
    );
    git("add", ".gitmodules");
    git("commit", "-m", "Synthetic deinitialized submodule");
    git("config", "diff.ignoreSubmodules", "all");
    const alias = join(directory, "src/nested-\ufffd");
    await writeFile(
      join(directory, ".git/info/exclude"),
      "src/nested-\ufffd/\n",
    );
    await mkdir(alias);
    const aliasGit = initializePatchGit(alias);
    aliasGit("commit", "--allow-empty", "-m", "Synthetic alias");
    const outcome = await runPublication(directory, ["src"], async () => {
      await stage(after);
    });
    expect(outcome.exitCode, outcome.stderr).toBe(published ? 0 : 2);
    if (published)
      expect(git("ls-remote", remote)).toContain(git("rev-parse", "HEAD"));
    else {
      expect(outcome.stderr).toContain(
        "not available in its remote-tracking refs",
      );
      expect(git("ls-remote", remote)).toBe("");
    }
  },
);

test.skipIf(process.platform !== "linux").each([false, true])(
  "keeps ignored byte paths distinct from clean tracked Unicode paths (same contents: %p)",
  async (sameContents) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const alias = join(directory, "local-\ufffd");
    const content = "Synthetic clean tracked content\n";
    await writeFile(alias, content);
    await writeFile(join(directory, ".gitignore"), "local-*\n");
    git("add", ".gitignore");
    git("add", "-f", alias);
    git("commit", "-m", "Synthetic distinct paths");
    const raw = Buffer.concat([
      Buffer.from(`${directory}/local-`),
      Buffer.from([0xff]),
    ]);
    await writeFile(
      raw,
      sameContents ? content : "Synthetic ignored content\n",
    );
    const original = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    let modelStarted = false;
    const outcome = await runPublication(directory, "issue", async () => {
      modelStarted = true;
      await writeFile(join(directory, "new.ts"), await readFile(alias));
    });
    expect(modelStarted).toBe(true);
    expect(outcome.exitCode, outcome.stderr).toBe(sameContents ? 2 : 0);
    if (sameContents) {
      expect(outcome.stderr).toContain("matches pre-existing ignored content");
      expect(git("rev-parse", "HEAD")).toBe(original);
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
      expect(repositoryGit(remote)("for-each-ref", "--format=%(refname)")).toBe(
        "",
      );
    } else {
      const branch = git("branch", "--show-current");
      expect(repositoryGit(remote)("show", `refs/heads/${branch}:new.ts`)).toBe(
        content.trim(),
      );
      expect(git("diff", "--name-only", "HEAD^", "HEAD")).toBe("new.ts");
    }
    expect(await readFile(alias, "utf8")).toBe(content);
    expect(await readFile(raw, "utf8")).toBe(
      sameContents ? content : "Synthetic ignored content\n",
    );
  },
);

test.skipIf(process.platform === "win32")(
  "preflights and publishes to every push destination with trailing path whitespace",
  async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const parent = await fixtures.create("patch-remote-whitespace-");
    const mirror = join(parent, "mirror ");
    await mkdir(mirror);
    git("init", "--bare", mirror);
    git("config", "--add", "remote.origin.pushurl", remote);
    git("config", "--add", "remote.origin.pushurl", mirror);
    const outcome = await runPublication(directory, "issue", () =>
      writeFile(join(directory, "src/finding-1.ts"), "fixed\n"),
    );
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    const branch = git("branch", "--show-current");
    for (const destination of [remote, mirror]) {
      expect(
        repositoryGit(destination)("rev-parse", `refs/heads/${branch}`),
      ).toBe(git("rev-parse", "HEAD"));
    }
  },
);

for (const [name, before, after] of [
  ["unchanged large identity", 2n ** 60n, 2n ** 60n],
  ["distinct small identities", 100n, 101n],
  ["colliding numeric identities", 2n ** 60n, 2n ** 60n + 1n],
] as const) {
  const title = `publication hashes the checked file with ${name}`;
  test(title, async () => {
    if (runTestInSubprocess(import.meta.path, title)) return;
    const { directory, git, remote } = await publicationRepository(fixtures);
    await writeFile(join(directory, ".gitignore"), ".env\n");
    git("add", ".gitignore");
    git("commit", "-m", "Synthetic ignored baseline");
    const path = join(directory, ".env");
    const originalContent = "SYNTHETIC_PREEXISTING_LOCAL_CONTENT\n";
    await writeFile(path, originalContent);
    const retained = join(
      await fixtures.create("publication-original-"),
      "original",
    );
    git("status", "--porcelain=v1");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    const replacing = before !== after;
    if (name === "colliding numeric identities")
      expect(Number(before)).toBe(Number(after));
    const filesystem = await import("node:fs/promises");
    const original = {
      lstat: filesystem.lstat,
      realpath: filesystem.realpath,
      open: filesystem.open,
    };
    const selected = (value: unknown) => resolve(String(value)) === path;
    const identity = (metadata: Stats | BigIntStats, value: bigint) => {
      Object.defineProperty(metadata, "ino", {
        value: typeof metadata.ino === "bigint" ? value : Number(value),
      });
      return metadata;
    };
    let replaced = false;
    const handles: FileHandle[] = [];
    const inspecting = spyOn(filesystem, "lstat").mockImplementation((async (
      ...args: Parameters<typeof original.lstat>
    ) => {
      const metadata = await original.lstat(...args);
      return selected(args[0])
        ? identity(metadata, replaced ? after : before)
        : metadata;
    }) as typeof original.lstat);
    const resolving = spyOn(filesystem, "realpath").mockImplementation((async (
      ...args: Parameters<typeof original.realpath>
    ) => {
      const canonical = await original.realpath(...args);
      if (selected(args[0]) && replacing && !replaced) {
        await rename(path, retained);
        await writeFile(path, "SYNTHETIC_REPLACEMENT_CONTENT\n");
        replaced = true;
      }
      return canonical;
    }) as typeof original.realpath);
    const opening = spyOn(filesystem, "open").mockImplementation(
      async (...args) => {
        const file = await original.open(...args);
        if (selected(args[0])) {
          handles.push(file);
          const value = replaced ? after : before;
          const stat = file.stat.bind(file);
          spyOn(file, "stat").mockImplementation((async (
            ...options: Parameters<typeof stat>
          ) => identity(await stat(...options), value)) as typeof stat);
        }
        return file;
      },
    );
    let models = 0;
    let pushes = 0;
    let creations = 0;
    try {
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          onRepositoryCommand: (command, args, cwd, options) => {
            if (command === "git") {
              if (args.includes("push")) pushes++;
              return runGitRepositoryCommand(command, args, cwd, options);
            }
            if (args[1] === "create") creations++;
            return args[1] === "list"
              ? "[]"
              : "https://github.example.test/example/repository/pull/1";
          },
          onCodex: async (_args, output) => {
            models++;
            await writeFile(
              join(directory, "selected.txt"),
              replacing ? originalContent : "Synthetic independent change\n",
            );
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(outcome.exitCode, outcome.stderr).toBe(replacing ? 2 : 0);
      expect({ models, pushes, creations }).toEqual(
        replacing
          ? { models: 0, pushes: 0, creations: 0 }
          : { models: 1, pushes: 1, creations: 1 },
      );
      expect(replaced).toBe(replacing);
      if (replacing) {
        expect(outcome.stderr).toContain(
          "Patch publication content must remain the selected regular file.",
        );
        expect(git("rev-parse", "HEAD")).toBe(head);
        expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
        expect(repositoryGit(remote)("for-each-ref")).toBe("");
        expect(await readFile(retained, "utf8")).toBe(originalContent);
        expect(await readFile(path, "utf8")).toBe(
          "SYNTHETIC_REPLACEMENT_CONTENT\n",
        );
      } else {
        expect(git("show", "HEAD:selected.txt")).toBe(
          "Synthetic independent change",
        );
        expect(await readFile(path, "utf8")).toBe(originalContent);
      }
      expect(handles.length).toBeGreaterThan(0);
      for (const handle of handles) expect(handle.fd).toBe(-1);
    } finally {
      opening.mockRestore();
      resolving.mockRestore();
      inspecting.mockRestore();
    }
  });
}

test.each([
  "hardlinked HEAD",
  "linked logs directory",
  ...(process.platform === "win32" ? [] : ["symlinked HEAD"]),
])("refuses a %s before switching the patch branch", async (mode) => {
  const { directory, git, remote } = await publicationRepository(fixtures);
  const external = await fixtures.create("patch-reflog-target-");
  const logs = join(directory, ".git", "logs");
  const headLog = join(logs, "HEAD");
  let target = join(external, "unchanged");
  if (mode === "linked logs directory") {
    const moved = join(external, "logs");
    await rename(logs, moved);
    await symlink(
      moved,
      logs,
      process.platform === "win32" ? "junction" : "dir",
    );
    target = join(moved, "HEAD");
  } else {
    await writeFile(target, "Synthetic external file\n");
    await rm(headLog);
    if (mode === "hardlinked HEAD") await link(target, headLog);
    else await symlink(target, headLog);
  }
  const before = await readFile(target);
  const branch = git("branch", "--show-current");
  const result = await publishSyntheticChange(directory);
  expect(result.exitCode).toBe(2);
  expect(result.stderr).toContain("regular, unlinked Git reflogs");
  expect(git("branch", "--show-current")).toBe(branch);
  expect(repositoryGit(remote)("for-each-ref")).toBe("");
  expect(await readFile(target)).toEqual(before);
});

test.each([
  "hardlinked worktree COMMIT_EDITMSG",
  ...(process.platform === "win32" ? [] : ["symlinked COMMIT_EDITMSG"]),
])("refuses a %s during patch publication", async (mode) => {
  const { directory, git, remote } = await publicationRepository(fixtures);
  let checkout = directory;
  if (mode === "hardlinked worktree COMMIT_EDITMSG") {
    checkout = await fixtures.create("patch-linked-worktree-");
    git("worktree", "add", "-b", "linked", checkout);
  }
  const checkoutGit = repositoryGit(checkout);
  const message = join(
    checkoutGit("rev-parse", "--absolute-git-dir"),
    "COMMIT_EDITMSG",
  );
  const notes = join(
    await fixtures.create("patch-operator-notes-"),
    "COMMIT_EDITMSG",
  );
  const contents = "Synthetic operator notes\n";
  await writeFile(notes, contents);
  await rm(message, { force: true });
  if (mode === "symlinked COMMIT_EDITMSG") await symlink(notes, message);
  else await link(notes, message);
  const branch = checkoutGit("branch", "--show-current");
  const head = checkoutGit("rev-parse", "HEAD");

  const result = await publishSyntheticChange(checkout);

  expect(result.exitCode, result.stderr).toBe(2);
  expect(result.stderr).toContain("COMMIT_EDITMSG");
  expect(await readFile(notes, "utf8")).toBe(contents);
  expect(checkoutGit("branch", "--show-current")).toBe(branch);
  expect(checkoutGit("rev-parse", "HEAD")).toBe(head);
  expect(repositoryGit(remote)("for-each-ref")).toBe("");
});

test.each(["HEAD", "refs/heads/main"])(
  "refuses to publish a private ancestor selected through a hardlinked %s",
  async (target) => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    git("switch", "-c", "private");
    await writeFile(
      join(directory, "private.txt"),
      "Synthetic private content\n",
    );
    git("add", "--", "private.txt");
    git("commit", "-m", "Private synthetic ancestor");
    const privateCommit = git("rev-parse", "HEAD");
    git("switch", "main");
    await writeFile(join(directory, ".git/info/exclude"), ".ref-alias\n");
    const alias = join(directory, ".ref-alias");
    await link(join(directory, ".git", target), alias);
    const outcome = await publishSyntheticChange(directory, () =>
      writeFile(
        alias,
        target === "HEAD" ? "ref: refs/heads/private\n" : privateCommit + "\n",
      ),
    );
    expect(outcome.exitCode, outcome.stderr).toBe(2);
    expect(outcome.stderr).toContain("patch base changed");
    expect(repositoryGit(remote)("for-each-ref")).toBe("");
    expect(() =>
      repositoryGit(remote)("cat-file", "-e", privateCommit),
    ).toThrow();
  },
);

function publishSyntheticChange(
  directory: string,
  beforeEdit?: () => Promise<void>,
) {
  return runWorkflow(["patch", "Synthetic issue", "--create-pr", "--json"], {
    currentDirectory: directory,
    onRepositoryCommand: runPublicationCommand,
    onCodex: async (_args, output) => {
      await beforeEdit?.();
      await writeFile(join(directory, "selected.txt"), "Synthetic change\n");
      output?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  });
}
