import { execFileSync, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  symlink,
  utimes,
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
import { enclosingGitWorktreeRoot } from "../src/targets.js";

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

async function repository(name = "repo"): Promise<string> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-targets-")),
  );
  temporaryDirectories.push(root);
  const repo = join(root, name);
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

async function createRepositoryGitShim(
  directory: string,
  marker: string,
): Promise<void> {
  await mkdir(directory, { recursive: true });

  if (process.platform === "win32") {
    const batch = `@echo off\r\necho executed> "${marker}"\r\necho malicious\r\n`;
    await Promise.all([
      writeFile(join(directory, "git.exe"), "untrusted executable fixture\n"),
      writeFile(join(directory, "git.com"), "untrusted executable fixture\n"),
      writeFile(join(directory, "git.cmd"), batch),
      writeFile(join(directory, "git.bat"), batch),
      writeFile(join(directory, "git"), "untrusted extensionless fixture\n"),
    ]);
    return;
  }

  const executable = join(directory, "git");
  await writeFile(
    executable,
    `#!/bin/sh\nprintf 'executed\\n' > '${marker}'\nprintf 'malicious\\n'\n`,
  );
  await chmod(executable, 0o700);
}

function environmentWithPath(entries: readonly string[]): NodeJS.ProcessEnv {
  const inheritedPath = Object.entries(process.env).find(
    ([name]) => name.toUpperCase() === "PATH",
  )?.[1];
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => name.toUpperCase() !== "PATH",
    ),
  );

  return {
    ...environment,
    ...(process.platform === "win32" ? { PATHEXT: ".CMD;.BAT;.COM;.EXE" } : {}),
    PATH: [...entries, inheritedPath ?? ""].join(delimiter),
  };
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
      await normalizeTarget(repo, [
        "src",
        join(repo, "src", "app.ts"),
        join(repo, "src"),
        "src/app.ts",
      ]),
    ).toEqual({
      kind: "paths",
      paths: ["src", "src/app.ts"],
    });
  });

  test.skipIf(process.platform !== "win32")(
    "rejects Windows repository roots that alias across runtimes",
    async () => {
      const root = await realpath(
        await mkdtemp(join(tmpdir(), "codex-security-repository-alias-")),
      );
      temporaryDirectories.push(root);
      const repository = join(root, "repository");
      const ambiguous = join(root, "repository.");
      const linked = join(root, "linked-repository");
      await Promise.all([mkdir(repository), mkdir(ambiguous)]);
      await symlink(ambiguous, linked, "junction");

      expect(await realpath(repository)).not.toBe(await realpath(ambiguous));
      await expect(normalizeRepository(repository)).resolves.toBe(
        await realpath(repository),
      );
      for (const path of [ambiguous, linked]) {
        await expect(normalizeRepository(path)).rejects.toThrow(
          "Windows-ambiguous components",
        );
      }
    },
  );

  test.skipIf(process.platform === "win32")(
    "preserves trailing whitespace in Git worktree paths",
    async () => {
      for (const suffix of [" ", "\r"]) {
        const repo = await repository(`repo${suffix}`);
        expect(await enclosingGitWorktreeRoot(repo)).toBe(await realpath(repo));
        await expect(
          normalizeTarget(repo, DiffTarget.refs({ base: "HEAD" })),
        ).resolves.toMatchObject({ kind: "refs" });
      }
    },
  );

  test("rejects empty and escaping paths", async () => {
    const repo = await repository();
    await expect(normalizeTarget(repo, [""])).rejects.toThrow("empty path");
    await expect(normalizeTarget(repo, [join(repo, "..")])).rejects.toThrow(
      "outside the repository",
    );
  });

  test.skipIf(process.platform !== "win32")(
    "rejects NTFS alternate streams before runtime initialization",
    async () => {
      const repo = await repository();
      const stream = join(repo, "src", "app.ts:synthetic-stream");
      await writeFile(stream, "export const hidden = true;\n");

      await expect(normalizeTarget(repo, [stream])).rejects.toThrow(
        "unsupported colon component",
      );
    },
  );

  test.skipIf(process.platform === "win32")(
    "allows colons in POSIX path components",
    async () => {
      const repo = await repository();
      const path = join(repo, "src", "app.ts:fixture");
      await writeFile(path, "export const fixture = true;\n");

      await expect(normalizeTarget(repo, [path])).resolves.toEqual({
        kind: "paths",
        paths: ["src/app.ts:fixture"],
      });
    },
  );

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

  test("preserves user Git settings while removing repository overrides", async () => {
    const repo = await repository();
    const root = join(repo, "..");
    const trace = join(root, "git-events.jsonl");
    await writeFile(
      join(repo, "src", "app.ts"),
      "export const updated = true;\n",
    );
    git(repo, "add", ".");
    git(repo, "commit", "-m", "updated");
    const revision = git(repo, "rev-parse", "HEAD");
    const parent = git(repo, "rev-parse", "HEAD^");
    const shallow = join(root, "shallow");
    await writeFile(shallow, `${revision}\n`);
    const repositoryOverrides = {
      GIT_DIR: join(root, "missing-git-dir"),
      GIT_WORK_TREE: join(root, "missing-work-tree"),
      GIT_INDEX_FILE: join(root, "missing-index"),
      GIT_OBJECT_DIRECTORY: join(root, "missing-objects"),
      GIT_ALTERNATE_OBJECT_DIRECTORIES: join(root, "missing-alternates"),
      GIT_COMMON_DIR: join(root, "missing-common"),
      GIT_REPLACE_REF_BASE: "refs/unsafe/",
      GIT_CEILING_DIRECTORIES: root,
      GIT_DISCOVERY_ACROSS_FILESYSTEM: "1",
      GIT_GRAFT_FILE: join(root, "missing-grafts"),
      GIT_IMPLICIT_WORK_TREE: "0",
      GIT_NAMESPACE: "unsafe",
      GIT_NO_REPLACE_OBJECTS: "1",
      GIT_PREFIX: "unsafe/",
      GIT_SHALLOW_FILE: shallow,
    };
    const result = spawnSync(
      process.execPath,
      [
        "-e",
        "const { DiffTarget, normalizeTarget } = await import(process.argv[1]); console.log(JSON.stringify(await normalizeTarget(process.argv[2], DiffTarget.refs({ base: 'HEAD^' }))));",
        fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
        repo,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "codex.security",
          GIT_CONFIG_VALUE_0: "SYNTHETIC_GIT_SETTING",
          GIT_TRACE2_EVENT: trace,
          GIT_TRACE2_CONFIG_PARAMS: "codex.security",
          GIT_TRACE2_ENV_VARS: [
            "GIT_SSL_CAINFO",
            "GIT_SSH_COMMAND",
            ...Object.keys(repositoryOverrides),
          ].join(","),
          GIT_SSL_CAINFO: join(root, "ca.pem"),
          GIT_SSH_COMMAND: "ssh -o BatchMode=yes",
          ...repositoryOverrides,
        },
      },
    );

    expect(result.status).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({
      kind: "refs",
      base: parent,
      head: revision,
    });
    const events = (await readFile(trace, "utf8"))
      .trim()
      .split(/\r?\n/u)
      .map((line) => JSON.parse(line) as { param?: string; value?: string });
    expect(events).toContainEqual(
      expect.objectContaining({
        param: "codex.security",
        value: "SYNTHETIC_GIT_SETTING",
      }),
    );
    for (const name of ["GIT_SSL_CAINFO", "GIT_SSH_COMMAND"]) {
      expect(events.some(({ param }) => param === name)).toBe(true);
    }
    for (const name of Object.keys(repositoryOverrides)) {
      expect(events.some(({ param }) => param === name)).toBe(false);
    }
  });

  test("does not expose Git configuration to repository fsmonitor hooks", async () => {
    const repo = await repository();
    const root = join(repo, "..");
    const hook = join(root, "fsmonitor-hook");
    const leaked = join(root, "leaked-credential");
    await writeFile(
      hook,
      `#!/bin/sh\nprintf '%s' "$GIT_CONFIG_VALUE_0" > ${JSON.stringify(leaked)}\nprintf '\\0'\n`,
    );
    await chmod(hook, 0o700);
    git(repo, "config", "core.fsmonitor", hook);

    const result = spawnSync(
      process.execPath,
      [
        "-e",
        "const { DiffTarget, normalizeTarget, validateCommittedDiffCheckout } = await import(process.argv[1]); const target = await normalizeTarget(process.argv[2], DiffTarget.refs({ base: 'HEAD' })); await validateCommittedDiffCheckout(process.argv[2], target);",
        fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
        repo,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "http.extraHeader",
          GIT_CONFIG_VALUE_0: "SYNTHETIC_GIT_CREDENTIAL",
        },
      },
    );

    expect(result.status).toBe(0);
    expect(existsSync(leaked)).toBe(false);
  });

  test("does not expose Git configuration to repository clean filters", async () => {
    const repo = await repository();
    const root = join(repo, "..");
    const filter = join(root, "clean-filter.js");
    const executed = join(root, "filter-executed");
    const leaked = join(root, "leaked-credential");
    await writeFile(
      join(repo, ".gitattributes"),
      "src/app.ts filter=capture\n",
    );
    git(repo, "add", ".gitattributes");
    git(repo, "commit", "-m", "configure attributes");
    await writeFile(
      filter,
      [
        'import { readFileSync, writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(executed)}, "executed");`,
        `if (process.env.GIT_CONFIG_VALUE_0) writeFileSync(${JSON.stringify(leaked)}, process.env.GIT_CONFIG_VALUE_0);`,
        "process.stdout.write(readFileSync(0));",
      ].join("\n"),
    );
    git(
      repo,
      "config",
      "filter.capture.clean",
      `${JSON.stringify(process.execPath.replaceAll("\\", "/"))} ${JSON.stringify(filter.replaceAll("\\", "/"))}`,
    );
    await utimes(join(repo, "src", "app.ts"), new Date(0), new Date(0));

    const result = spawnSync(
      process.execPath,
      [
        "-e",
        "const { DiffTarget, normalizeTarget, validateCommittedDiffCheckout } = await import(process.argv[1]); const target = await normalizeTarget(process.argv[2], DiffTarget.refs({ base: 'HEAD' })); await validateCommittedDiffCheckout(process.argv[2], target);",
        fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
        repo,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "http.extraHeader",
          GIT_CONFIG_VALUE_0: "SYNTHETIC_GIT_CREDENTIAL",
        },
      },
    );

    expect(result.status).toBe(0);
    expect(existsSync(executed)).toBe(true);
    expect(existsSync(leaked)).toBe(false);
  });

  test("does not expose Git configuration to repository promisor helpers", async () => {
    const repo = await repository();
    const root = join(repo, "..");
    const helper = join(root, "promisor-helper.js");
    const executed = join(root, "promisor-executed");
    const leaked = join(root, "leaked-credential");
    const revision = git(repo, "rev-parse", "HEAD");
    await writeFile(
      helper,
      [
        'import { writeFileSync } from "node:fs";',
        `writeFileSync(${JSON.stringify(executed)}, "executed");`,
        `if (process.env.GIT_CONFIG_VALUE_0) writeFileSync(${JSON.stringify(leaked)}, process.env.GIT_CONFIG_VALUE_0);`,
        "process.exit(1);",
      ].join("\n"),
    );
    git(repo, "config", "extensions.partialClone", "unsafe");
    git(repo, "config", "remote.unsafe.promisor", "true");
    git(repo, "config", "protocol.ext.allow", "always");
    git(
      repo,
      "config",
      "remote.unsafe.url",
      `ext::${process.execPath.replaceAll("\\", "/")} ${helper.replaceAll("\\", "/")}`,
    );
    await rm(
      join(repo, ".git", "objects", revision.slice(0, 2), revision.slice(2)),
    );

    const result = spawnSync(
      process.execPath,
      [
        "-e",
        "const { repositoryRevision } = await import(process.argv[1]); console.log(await repositoryRevision(process.argv[2]));",
        fileURLToPath(new URL("../src/targets.ts", import.meta.url)),
        repo,
      ],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          GIT_CONFIG_COUNT: "1",
          GIT_CONFIG_KEY_0: "http.extraHeader",
          GIT_CONFIG_VALUE_0: "SYNTHETIC_GIT_CREDENTIAL",
          GIT_ALLOW_PROTOCOL: "ext",
        },
      },
    );

    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe("null");
    expect(existsSync(executed)).toBe(false);
    expect(existsSync(leaked)).toBe(false);
  });

  test("does not execute repository-local Git shims from PATH", async () => {
    const repo = await repository();
    const root = join(repo, "..");
    const unsafeBin = join(repo, "node_modules", ".bin");
    const linkedBin = join(root, "linked-bin");
    const marker = join(root, "git-executed");
    const revision = git(repo, "rev-parse", "HEAD");
    await createRepositoryGitShim(unsafeBin, marker);
    await symlink(
      unsafeBin,
      linkedBin,
      process.platform === "win32" ? "junction" : "dir",
    );

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
        env: environmentWithPath([
          unsafeBin,
          linkedBin,
          "node_modules/.bin",
          "",
        ]),
      },
    );
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe(revision);
    expect(existsSync(marker)).toBe(false);
  });

  test("does not execute worktree-local Git shims when scanning a subdirectory", async () => {
    const repo = await repository();
    const target = join(repo, "src");
    const unsafeBin = join(repo, "node_modules", ".bin");
    const marker = join(repo, "git-executed");
    const revision = git(repo, "rev-parse", "HEAD");
    await createRepositoryGitShim(unsafeBin, marker);

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
        env: environmentWithPath([unsafeBin]),
      },
    );
    expect(result.status).toBe(0);
    expect(result.stdout.trim().split(/\r?\n/u)).toEqual([
      await realpath(repo),
      revision,
    ]);
    expect(existsSync(marker)).toBe(false);
  });

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
