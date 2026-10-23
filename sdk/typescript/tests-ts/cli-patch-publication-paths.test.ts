import { afterEach, expect, test } from "bun:test";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchRiskAssessment,
  publicationRepository,
  repositoryGit,
  resultWithFindings,
  runGitRepositoryCommand,
  runWorkflow,
  savedScan,
} from "./cli-patch-fixtures.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

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
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onRepositoryCommand: runCommand,
        onCodex: async (_args, output) => {
          await writeFile(
            raw,
            copied ? ignored : "Independent synthetic content\n",
          );
          await writeFile(alias, "Distinct Unicode alias\n");
          output!.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["src"],
                  verification: "Synthetic directory check.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
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
        onRepositoryCommand: runCommand,
        onCodex: async (_args, output) => {
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
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["src/new.ts"],
                  verification: "Synthetic check.",
                },
              ],
            }),
          );
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
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: cwd,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", cwd),
        onRepositoryCommand: runCommand,
        onCodex: async (_args, output) => {
          await writeFile(
            join(directory, "src/nested/finding-1.ts"),
            "fixed\n",
          );
          await writeFile(alias, await readFile(join(directory, ".env")));
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: [scope === "root" ? "src/nested" : "nested"],
                  verification: "Synthetic check.",
                },
              ],
            }),
          );
          return 0;
        },
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
    const alias = join(directory, "src/nested-\ufffd");
    await writeFile(
      join(directory, ".git/info/exclude"),
      "src/nested-\ufffd/\n",
    );
    await mkdir(alias);
    const aliasGit = repositoryGit(alias);
    aliasGit("init", "--initial-branch=main");
    aliasGit("config", "user.name", "Synthetic User");
    aliasGit("config", "user.email", "synthetic@example.test");
    aliasGit("commit", "--allow-empty", "-m", "Synthetic alias");
    const outcome = await runWorkflow(
      ["patch", "--scan", "scan-1", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onWorkbench: () =>
          savedScan(resultWithFindings(["high"]), "scan-1", directory),
        onRepositoryCommand: runCommand,
        onCodex: async (_args, output) => {
          await stage(after);
          output?.stdout.write(
            JSON.stringify({
              patches: [
                {
                  occurrenceId: "occ_1",
                  status: "verified",
                  files: ["src"],
                  verification: "Synthetic check.",
                },
              ],
            }),
          );
          return 0;
        },
      },
    );
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
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onRepositoryCommand: runCommand,
        onCodex: async (_args, output) => {
          modelStarted = true;
          await writeFile(join(directory, "new.ts"), await readFile(alias));
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
    );
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
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onRepositoryCommand: runCommand,
        onCodex: async (_args, output) => {
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
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
