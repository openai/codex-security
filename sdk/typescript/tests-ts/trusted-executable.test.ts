import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";
import { resolveTrustedExecutable } from "../src/trusted-executable.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "trusted-executable-")),
  );
  temporaryDirectories.push(path);
  return path;
}

async function resolveWindowsExecutable(
  candidate: string,
  path: string,
  protectedRoot: string,
): Promise<{
  executable: string;
  environment: Record<string, string | undefined>;
} | null> {
  if (process.platform === "win32") {
    return await resolveTrustedExecutable(
      candidate,
      { Path: path, KEEP: "ok" },
      protectedRoot,
    );
  }

  const script = `
    Object.defineProperty(process, "platform", { value: "win32" });
    const { resolveTrustedExecutable } = await import(process.argv[1]);
    console.log(JSON.stringify(await resolveTrustedExecutable(
      process.argv[2],
      { Path: process.argv[3], KEEP: "ok" },
      process.argv[4],
    )));
  `;
  const result = spawnSync(
    process.execPath,
    [
      "-e",
      script,
      fileURLToPath(new URL("../src/trusted-executable.ts", import.meta.url)),
      candidate,
      path,
      protectedRoot,
    ],
    { encoding: "utf8" },
  );
  expect(result.status).toBe(0);
  return JSON.parse(result.stdout) as {
    executable: string;
    environment: Record<string, string | undefined>;
  } | null;
}

describe("trusted executable resolution", () => {
  test("accepts safe relative PATH entries without trusting repository links", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const unsafe = join(repository, "bin");
    const linked = join(root, "linked");
    const trusted = join(root, "trusted");
    const executable = process.platform === "win32" ? "git.exe" : "git";
    await Promise.all([mkdir(unsafe, { recursive: true }), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(unsafe, executable), "untrusted executable"),
      writeFile(join(trusted, executable), "trusted executable"),
    ]);
    await chmod(join(trusted, executable), 0o700);
    await symlink(
      unsafe,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );

    expect(
      await resolveTrustedExecutable(
        "git",
        {
          PATH: ["", unsafe, linked, trusted]
            .map((entry) => (entry ? relative(process.cwd(), entry) : entry))
            .join(delimiter),
          KEEP: "ok",
        },
        repository,
      ),
    ).toEqual({
      executable: join(trusted, executable),
      environment: { KEEP: "ok", PATH: trusted },
    });
  });

  test.skipIf(process.platform === "win32")(
    "preserves the invocation name of a trusted symlinked executable",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const trusted = join(root, "trusted");
      const wrapper = join(trusted, "wrapper");
      const git = join(trusted, "git");
      await Promise.all([mkdir(repository), mkdir(trusted)]);
      await writeFile(wrapper, "#!/bin/sh\nprintf '%s\\n' \"$0\"\n");
      await chmod(wrapper, 0o700);
      await symlink(wrapper, git);

      const resolved = await resolveTrustedExecutable(
        "git",
        { PATH: trusted },
        repository,
      );
      expect(resolved).toEqual({
        executable: git,
        environment: { PATH: trusted },
      });
      if (resolved === null) throw new Error("trusted Git was not resolved");

      const result = spawnSync(resolved.executable, [], {
        encoding: "utf8",
        env: resolved.environment,
      });
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe(git);
    },
  );

  test("selects runnable Windows executables ahead of extensionless and batch files", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const first = join(root, "first");
    const second = join(root, "second");
    await Promise.all([mkdir(repository), mkdir(first), mkdir(second)]);
    await Promise.all([
      writeFile(join(first, "git"), "extensionless"),
      writeFile(join(first, "git.cmd"), "batch"),
      writeFile(join(first, "git.bat"), "batch"),
      writeFile(join(second, "git.exe"), "executable"),
      writeFile(join(second, "git.com"), "executable"),
    ]);

    expect(
      await resolveWindowsExecutable(
        "git",
        [first, second].join(delimiter),
        repository,
      ),
    ).toEqual({
      executable: join(second, "git.exe"),
      environment: { KEEP: "ok", PATH: [first, second].join(delimiter) },
    });
  });

  test("accepts a Windows COM executable and rejects batch-only candidates", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const com = join(root, "com");
    const batch = join(root, "batch");
    await Promise.all([mkdir(repository), mkdir(com), mkdir(batch)]);
    await Promise.all([
      writeFile(join(com, "python3.com"), "executable"),
      writeFile(join(batch, "python3"), "extensionless"),
      writeFile(join(batch, "python3.cmd"), "batch"),
      writeFile(join(batch, "python3.bat"), "batch"),
    ]);

    expect(await resolveWindowsExecutable("python3", com, repository)).toEqual({
      executable: join(com, "python3.com"),
      environment: { KEEP: "ok", PATH: com },
    });
    expect(
      await resolveWindowsExecutable("python3", batch, repository),
    ).toBeNull();
  });

  test("resolves already-suffixed Windows executables without adding another extension", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const first = join(root, "first");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(repository), mkdir(first), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(first, "python.exe.exe"), "wrong executable"),
      writeFile(join(trusted, "python.exe"), "python executable"),
      writeFile(join(trusted, "git.exe"), "git executable"),
      writeFile(join(trusted, "tool.com"), "com executable"),
      writeFile(join(trusted, "script.cmd"), "batch"),
    ]);

    for (const candidate of ["python.exe", "git.exe", "tool.com"]) {
      expect(
        await resolveWindowsExecutable(
          candidate,
          [first, trusted].join(delimiter),
          repository,
        ),
      ).toEqual({
        executable: join(trusted, candidate),
        environment: { KEEP: "ok", PATH: [first, trusted].join(delimiter) },
      });
    }
    expect(
      await resolveWindowsExecutable("script.cmd", trusted, repository),
    ).toBeNull();
  });

  test("resolves extensionless explicit Windows executable paths", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(repository), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(trusted, "python.exe"), "python executable"),
      writeFile(join(trusted, "python.cmd"), "batch"),
    ]);

    expect(
      await resolveWindowsExecutable(
        join(trusted, "python"),
        trusted,
        repository,
      ),
    ).toEqual({
      executable: await realpath(join(trusted, "python.exe")),
      environment: { KEEP: "ok", PATH: trusted },
    });
    expect(
      await resolveWindowsExecutable(
        join(trusted, "python.cmd"),
        trusted,
        repository,
      ),
    ).toBeNull();
  });

  test("removes PATH entries containing repository-linked Windows shims", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    const unsafe = join(repository, "node_modules", ".bin");
    const linked = join(root, "linked");
    const trusted = join(root, "trusted");
    await Promise.all([mkdir(unsafe, { recursive: true }), mkdir(trusted)]);
    await Promise.all([
      writeFile(join(unsafe, "git.cmd"), "batch"),
      writeFile(join(unsafe, "git"), "extensionless"),
      writeFile(join(trusted, "git.exe"), "executable"),
    ]);
    await symlink(
      unsafe,
      linked,
      process.platform === "win32" ? "junction" : "dir",
    );

    expect(
      await resolveWindowsExecutable(
        "git",
        [unsafe, linked, trusted].join(delimiter),
        repository,
      ),
    ).toEqual({
      executable: join(trusted, "git.exe"),
      environment: { KEEP: "ok", PATH: trusted },
    });
  });

  test.skipIf(process.platform !== "win32")(
    "resolves a real Windows executable without trusting PATHEXT, repository junctions, or PATH casing",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const unsafe = join(repository, "node_modules", ".bin");
      const linked = join(root, "linked");
      const executable = await realpath(process.execPath);
      const trusted = await realpath(dirname(executable));
      const candidate = basename(executable);
      const stem = candidate.replace(/\.(?:exe|com)$/iu, "");
      const pathExtensions = ".CMD;.BAT;.COM;.EXE";
      await mkdir(unsafe, { recursive: true });
      await Promise.all([
        writeFile(join(unsafe, candidate), "untrusted executable fixture\n"),
        writeFile(join(unsafe, `${stem}.cmd`), "@echo off\r\nexit /b 1\r\n"),
        writeFile(join(unsafe, `${stem}.bat`), "@echo off\r\nexit /b 1\r\n"),
      ]);
      await symlink(unsafe, linked, "junction");

      await expect(
        resolveTrustedExecutable(
          candidate,
          {
            pAtH: [unsafe, linked, trusted].join(delimiter),
            PATHEXT: pathExtensions,
            KEEP: "ok",
          },
          repository,
        ),
      ).resolves.toEqual({
        executable,
        environment: {
          PATHEXT: pathExtensions,
          KEEP: "ok",
          PATH: trusted,
        },
      });
    },
  );

  test.skipIf(process.platform !== "win32")(
    "resolves executables from quoted Windows PATH entries",
    async () => {
      const root = await temporaryDirectory();
      const repository = join(root, "repository");
      const unsafe = join(repository, "tools");
      const trusted = join(root, "trusted tools");
      await Promise.all([mkdir(unsafe, { recursive: true }), mkdir(trusted)]);
      await Promise.all([
        writeFile(join(unsafe, "git.exe"), "untrusted executable"),
        writeFile(join(trusted, "git.exe"), "executable"),
      ]);

      await expect(
        resolveTrustedExecutable(
          "git",
          { Path: [`"${unsafe}"`, `"${trusted}"`].join(delimiter), KEEP: "ok" },
          repository,
        ),
      ).resolves.toEqual({
        executable: join(trusted, "git.exe"),
        environment: { KEEP: "ok", PATH: trusted },
      });
    },
  );
});
