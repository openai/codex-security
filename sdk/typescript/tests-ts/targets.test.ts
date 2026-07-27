import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdtemp,
  mkdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import {
  DiffTarget,
  InvalidTargetError,
  normalizeRepository,
  normalizeTarget,
  repositoryRevision,
  type ScanTarget,
} from "../src/index.js";

// @ts-expect-error DiffTarget is intentionally nominal; use its constructor helpers.
const structurallyInvalidTarget: ScanTarget = {
  kind: "refs",
  base: "main",
  head: "HEAD",
};
void structurallyInvalidTarget;

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function repository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codex-security-targets-"));
  temporaryDirectories.push(root);
  const repo = join(root, "repo");
  await mkdir(join(repo, "src"), { recursive: true });
  await writeFile(join(repo, "src", "app.ts"), "export const ok = true;\n");
  git(repo, "init", "-b", "main");
  git(repo, "config", "user.email", "test@example.com");
  git(repo, "config", "user.name", "Test");
  git(repo, "add", ".");
  git(repo, "commit", "-m", "initial");
  return repo;
}

function git(repo: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8" }).trim();
}

describe("scan target normalization", () => {
  test("tolerates a temporary repository removed before cleanup", async () => {
    const repo = await repository();
    await rm(join(repo, ".."), { recursive: true, force: true });
  });

  test("normalizes repository and path targets", async () => {
    const repo = await repository();
    expect(await normalizeTarget(repo, "repository")).toEqual({
      kind: "repository",
      paths: [],
    });
    expect(
      await normalizeTarget(repo, ["src", join(repo, "src", "app.ts")]),
    ).toEqual({
      kind: "paths",
      paths: ["src", "src/app.ts"],
    });
  });

  test("rejects empty and escaping paths", async () => {
    const repo = await repository();
    await expect(normalizeTarget(repo, [""])).rejects.toThrow("empty path");
    await expect(normalizeTarget(repo, [join(repo, "..")])).rejects.toThrow(
      "outside the repository",
    );
  });

  test("reports a path that disappears during normalization as invalid", async () => {
    const repo = await repository();
    const script = `
      import { mock } from "bun:test";
      import { rmSync } from "node:fs";
      import * as original from "node:fs/promises";
      import { join } from "node:path";
      const [repo, targets] = process.argv.slice(1);
      const target = join(repo, "src", "app.ts");
      const actualRealpath = original.realpath;
      mock.module("node:fs/promises", () => ({
        ...original,
        realpath: async (path, ...args) => {
          if (path === target) rmSync(target);
          return await actualRealpath(path, ...args);
        },
      }));
      const { normalizeTarget } = await import(targets);
      try {
        await normalizeTarget(repo, [target]);
        console.log("ACCEPTED");
        process.exitCode = 2;
      } catch (error) {
        console.log(
          "REJECTED",
          error instanceof Error && error.name === "InvalidTargetError",
          error instanceof Error ? error.message : String(error),
        );
      }
    `;
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        script,
        repo,
        fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
      ],
      { encoding: "utf8" },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("REJECTED true Path target does not exist");
  });

  test("binds ref and working-tree targets to commit IDs", async () => {
    const repo = await repository();
    const revision = git(repo, "rev-parse", "HEAD");
    const refs = await normalizeTarget(repo, DiffTarget.refs({ base: "HEAD" }));
    expect(refs).toMatchObject({
      kind: "refs",
      base: revision,
      head: revision,
      baseRef: "HEAD",
      headRef: "HEAD",
    });
    const worktree = await normalizeTarget(repo, DiffTarget.workingTree());
    expect(worktree).toMatchObject({
      kind: "working_tree",
      base: revision,
      head: revision,
    });
    await expect(
      normalizeTarget(repo, DiffTarget.refs({ base: "missing", head: "HEAD" })),
    ).rejects.toThrow("unknown Git ref");
  });

  test.skipIf(process.platform === "win32")(
    "does not execute repository-local Git shims from PATH",
    async () => {
      const repo = await repository();
      const root = join(repo, "..");
      const unsafeBin = join(repo, "node_modules", ".bin");
      const linkedBin = join(root, "linked-bin");
      const marker = join(root, "git-executed");
      const unsafeGit = join(unsafeBin, "git");
      const revision = git(repo, "rev-parse", "HEAD");
      await mkdir(unsafeBin, { recursive: true });
      await mkdir(linkedBin);
      await writeFile(
        unsafeGit,
        `#!/bin/sh\nprintf 'executed\\n' > '${marker}'\nprintf 'malicious\\n'\n`,
      );
      await chmod(unsafeGit, 0o700);
      await symlink(unsafeGit, join(linkedBin, "git"));

      const script = `
        const { repositoryRevision } = await import(process.argv[1]);
        console.log(await repositoryRevision(process.argv[2]));
      `;
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          script,
          fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
          repo,
        ],
        {
          cwd: repo,
          encoding: "utf8",
          env: {
            ...process.env,
            PATH: [
              unsafeBin,
              linkedBin,
              "node_modules/.bin",
              "",
              process.env["PATH"] ?? "",
            ].join(delimiter),
          },
        },
      );
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe(revision);
      expect(existsSync(marker)).toBe(false);
    },
  );

  test.skipIf(process.platform === "win32")(
    "does not execute worktree-local Git shims when scanning a subdirectory",
    async () => {
      const repo = await repository();
      const target = join(repo, "src");
      const unsafeBin = join(repo, "node_modules", ".bin");
      const marker = join(repo, "git-executed");
      const unsafeGit = join(unsafeBin, "git");
      const revision = git(repo, "rev-parse", "HEAD");
      await mkdir(unsafeBin, { recursive: true });
      await writeFile(
        unsafeGit,
        `#!/bin/sh\nprintf 'executed\\n' > '${marker}'\nprintf 'malicious\\n'\n`,
      );
      await chmod(unsafeGit, 0o700);

      const script = `
        const { enclosingGitWorktreeRoot, repositoryRevision } = await import(process.argv[1]);
        console.log(await enclosingGitWorktreeRoot(process.argv[2]));
        console.log(await repositoryRevision(process.argv[2]));
      `;
      const result = spawnSync(
        process.execPath,
        [
          "-e",
          script,
          fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
          target,
        ],
        {
          cwd: target,
          encoding: "utf8",
          env: {
            ...process.env,
            PATH: [unsafeBin, process.env["PATH"] ?? ""].join(delimiter),
          },
        },
      );
      expect(result.status).toBe(0);
      expect(result.stdout.trim().split(/\r?\n/u)).toEqual([repo, revision]);
      expect(existsSync(marker)).toBe(false);
    },
  );

  test("keeps the requested base and head when refs diverge", async () => {
    const repo = await repository();
    git(repo, "checkout", "-b", "feature");
    await writeFile(
      join(repo, "src", "feature.ts"),
      "export const feature = true;\n",
    );
    git(repo, "add", ".");
    git(repo, "commit", "-m", "feature");
    const head = git(repo, "rev-parse", "HEAD");
    git(repo, "checkout", "main");
    await writeFile(
      join(repo, "src", "upstream.ts"),
      "export const upstream = true;\n",
    );
    git(repo, "add", ".");
    git(repo, "commit", "-m", "upstream");
    const base = git(repo, "rev-parse", "HEAD");

    expect(
      await normalizeTarget(
        repo,
        DiffTarget.refs({ base: "main", head: "feature" }),
      ),
    ).toMatchObject({
      kind: "refs",
      base,
      head,
      baseRef: "main",
      headRef: "feature",
    });
  });

  test("requires the Git worktree root", async () => {
    const repo = await repository();
    await expect(
      normalizeTarget(join(repo, "src"), DiffTarget.refs({ base: "HEAD" })),
    ).rejects.toThrow("Git worktree root");
  });

  test("rejects invalid public DiffTarget states", () => {
    expect(
      () =>
        new DiffTarget({
          kind: "typo" as "refs",
          base: "HEAD",
        }),
    ).toThrow(InvalidTargetError);
    expect(() => new DiffTarget({ kind: "refs", base: "HEAD" })).toThrow(
      "head ref",
    );
    expect(
      () =>
        new DiffTarget({ kind: "working_tree", base: "HEAD", head: "HEAD" }),
    ).toThrow("cannot specify a head");
  });

  test("keeps DiffTarget immutable and revalidates forged states", async () => {
    const refs = DiffTarget.refs({ base: "HEAD", head: "HEAD" });
    expect(Object.isFrozen(refs)).toBe(true);
    expect(() =>
      Object.assign(refs, { kind: "typo", head: undefined }),
    ).toThrow();

    const repo = await repository();
    const forged = (kind: string, base: unknown, head: unknown): DiffTarget =>
      Object.assign(Object.create(DiffTarget.prototype), { kind, base, head });
    await expect(
      normalizeTarget(repo, forged("typo", "HEAD", undefined)),
    ).rejects.toThrow("Unsupported diff target kind");
    await expect(
      normalizeTarget(repo, forged("refs", "", "HEAD")),
    ).rejects.toThrow("base ref");
    await expect(
      normalizeTarget(repo, forged("refs", "HEAD", undefined)),
    ).rejects.toThrow("head ref");
    await expect(
      normalizeTarget(repo, forged("working_tree", "HEAD", "HEAD")),
    ).rejects.toThrow("cannot specify a head");
  });

  test("honors cancellation before repository and Git validation", async () => {
    const repo = await repository();
    const controller = new AbortController();
    const reason = new DOMException("canceled", "AbortError");
    controller.abort(reason);
    await expect(normalizeRepository(repo, controller.signal)).rejects.toBe(
      reason,
    );
    await expect(
      normalizeTarget(
        repo,
        DiffTarget.refs({ base: "HEAD" }),
        controller.signal,
      ),
    ).rejects.toBe(reason);
    await expect(repositoryRevision(repo, controller.signal)).rejects.toBe(
      reason,
    );
  });

  test("keeps repeated home separators anchored under the home directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-security-home-"));
    temporaryDirectories.push(root);
    const project = join(await realpath(root), "project");
    await mkdir(project);
    const script = `
      const { normalizeRepository } = await import(process.argv[1]);
      for (const value of ["~/project", "~//project", "~///project"]) {
        console.log(await normalizeRepository(value));
      }
    `;
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        script,
        fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
      ],
      {
        encoding: "utf8",
        env: { ...process.env, HOME: root, USERPROFILE: root },
      },
    );
    expect(result.status).toBe(0);
    const canonicalProject = await realpath(project);
    expect(result.stdout.trim().split(/\r?\n/)).toEqual([
      canonicalProject,
      canonicalProject,
      canonicalProject,
    ]);
  });
});
