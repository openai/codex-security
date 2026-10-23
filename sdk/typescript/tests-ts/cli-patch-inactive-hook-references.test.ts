import { afterEach, expect, spyOn, test } from "bun:test";
import { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { statSync } from "node:fs";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { runRepositoryCommand } from "../src/cli.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import {
  patchSnapshotEnvironment,
  patchSnapshotWindowsConfig,
} from "./support/patch-snapshot-environment.js";
import {
  publicationRepository,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";

function observeNativeOutput(alias: string, events: Record<string, unknown>[]) {
  const restore: (() => void)[] = [];
  const wrapEmit = (
    emitter: EventEmitter,
    observe: (
      event: string | symbol,
      args: unknown[],
      emit: () => boolean,
    ) => boolean,
  ) => {
    const descriptor = Object.getOwnPropertyDescriptor(emitter, "emit");
    const original = emitter.emit;
    emitter.emit = function (event, ...args) {
      return observe(event, args, () => original.call(this, event, ...args));
    };
    restore.push(() => {
      if (descriptor) Object.defineProperty(emitter, "emit", descriptor);
      else Reflect.deleteProperty(emitter, "emit");
    });
  };
  const target = ChildProcess.prototype as ChildProcess & {
    spawn(options: unknown): unknown;
  };
  const originalSpawn = target.spawn;
  const spawning = spyOn(target, "spawn").mockImplementation(function (
    this: ChildProcess,
    options,
  ) {
    const result = originalSpawn.call(this, options);
    if (!this.spawnargs.includes(alias)) return result;
    if (process.platform === "linux") {
      try {
        const fd = statSync(`/proc/${this.pid}/fd/1`, { bigint: true });
        events.push({
          event: "spawn-fd1",
          mode: String(fd.mode),
          dev: String(fd.dev),
          ino: String(fd.ino),
        });
      } catch (error) {
        events.push({
          event: "spawn-fd1-error",
          code: (error as NodeJS.ErrnoException).code,
        });
      }
    }
    if (this.stdout)
      wrapEmit(this.stdout, (event, args, emit) => {
        if (event === "data")
          events.push({
            event: "stdout-data",
            bytes: (args[0] as Buffer).length,
          });
        else if (event === "end" || event === "close")
          events.push({ event: `stdout-${event}` });
        return emit();
      });
    wrapEmit(this, (event, args, emit) => {
      if (event !== "close") return emit();
      events.push({ event: "child-close", code: args[0], signal: args[1] });
      const originalConcat = Buffer.concat;
      const concatenation = spyOn(Buffer, "concat").mockImplementation(
        (list, length) => {
          const value = originalConcat(list, length);
          events.push({
            event: "concat",
            chunks: list.map((chunk) => chunk.length),
            bytes: value.length,
          });
          return value;
        },
      );
      try {
        return emit();
      } finally {
        concatenation.mockRestore();
      }
    });
    return result;
  });
  return () => {
    spawning.mockRestore();
    for (const action of restore) action();
  };
}

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const mode of [
  "replace direct hook",
  "replace nested hook",
  "activate missing hook",
  "change nested configuration",
  "unchanged trusted hook",
  "ordinary file beside root hooks",
  "dormant worktree",
] as const) {
  test(`captures dormant publication hook references: ${mode}`, async () => {
    const { directory, git, remote } = await publicationRepository(fixtures);
    const support = await fixtures.create("patch-inactive-hook-support-");
    const rootHooks = mode === "ordinary file beside root hooks";
    const hooks = rootHooks ? directory : join(directory, "tracked-hooks");
    const hook = join(hooks, "pre-commit");
    const effect = join(support, "effect");
    const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
    const trusted = `#!/bin/sh\nprintf trusted > ${shellPath}\n`;
    const alternate = join(directory, "alternate");
    const alternateHook = join(alternate, "tracked-hooks", "pre-commit");
    const dormantWorktree = mode === "dormant worktree";
    if (dormantWorktree) {
      await mkdir(join(alternate, "tracked-hooks"), { recursive: true });
      await writeFile(alternateHook, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    }
    const changed = `#!/bin/sh\nprintf changed > ${shellPath}\n`;
    if (!rootHooks) await mkdir(hooks);
    const missingHook = mode === "activate missing hook";
    if (!missingHook) await writeFile(hook, trusted, { mode: 0o755 });
    const config = join(directory, ".git", "branch-config");
    const nested = mode.includes("nested");
    const nestedConfig = join(support, "nested-config");
    await writeFile(
      config,
      nested
        ? `[include]\n path = ${JSON.stringify(nestedConfig.replaceAll("\\", "/"))}\n`
        : `[core]\n hooksPath = ${rootHooks ? JSON.stringify(directory.replaceAll("\\", "/")) : "tracked-hooks"}\n`,
    );
    if (dormantWorktree)
      await writeFile(
        config,
        `[core]\n worktree = ${JSON.stringify(alternate.replaceAll("\\", "/"))}\n hooksPath = tracked-hooks\n`,
      );
    if (nested)
      await writeFile(nestedConfig, "[core]\n hooksPath = tracked-hooks\n");
    git("add", ".");
    git("commit", "--allow-empty", "-m", "Synthetic dormant hook baseline");
    git("config", "includeIf.onbranch:codex-security/**.path", "branch-config");
    const head = git("rev-parse", "HEAD");
    const index = await readFile(join(directory, ".git", "index"));
    const configuration = await readFile(config);
    const remoteRefs = git("ls-remote", remote);
    let launches = 0;
    let pushes = 0;
    let creations = 0;
    const afterTurn: string[][] = [];
    const outcome = await runWorkflow(
      ["patch", "Synthetic issue", "--create-pr", "--json"],
      {
        currentDirectory: directory,
        onRepositoryCommand: (command, args, cwd, options) => {
          if (command === "git") {
            if (launches > 0) afterTurn.push([...args]);
            if (args.includes("push")) pushes++;
            return runGitRepositoryCommand(command, args, cwd, options);
          }
          if (args[1] === "create") creations++;
          return args[1] === "list"
            ? "[]"
            : "https://github.example.test/example/repository/pull/1";
        },
        onCodex: async (_args, output) => {
          launches++;
          const paths = output?.appServer?.permissions?.readOnlyPaths ?? [];
          if (!missingHook) expect(paths).toContain(hook);
          if (nested) expect(paths).toContain(nestedConfig);
          if (dormantWorktree) {
            expect(paths).not.toContain(alternateHook);
            await writeFile(alternateHook, changed);
          }
          await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
          if (mode.startsWith("replace")) {
            await rename(hook, join(support, "original-hook"));
            await writeFile(hook, changed, { mode: 0o755 });
          } else if (missingHook) {
            await writeFile(hook, changed, { mode: 0o755 });
          } else if (mode === "change nested configuration") {
            await writeFile(nestedConfig, "[core]\n hooksPath = .\n");
          } else if (rootHooks) {
            await writeFile(join(directory, "ordinary.txt"), "ordinary edit\n");
          }
          output?.stdout.write("Synthetic patch complete.\n");
          return 0;
        },
      },
    );
    expect(launches).toBe(1);
    const rejected =
      mode.startsWith("replace") ||
      missingHook ||
      mode === "change nested configuration";
    if (rejected) {
      expect(outcome.exitCode, outcome.stderr).toBe(2);
      expect(outcome.stderr).toContain(
        missingHook
          ? "Git hook became accessible during the patch"
          : mode === "change nested configuration"
            ? "Git configuration changed during the patch"
            : "Git configuration or hooks changed location during the patch",
      );
      expect(afterTurn).toEqual([]);
      expect(await readFile(effect).catch(() => null)).toBeNull();
      expect(git("rev-parse", "HEAD")).toBe(head);
      expect(await readFile(join(directory, ".git", "index"))).toEqual(index);
      expect(git("ls-remote", remote)).toBe(remoteRefs);
      expect(pushes).toBe(0);
      expect(creations).toBe(0);
    } else {
      expect(outcome.exitCode, outcome.stderr).toBe(0);
      expect(await readFile(effect, "utf8")).toBe("trusted");
      expect(await readFile(hook, "utf8")).toBe(trusted);
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      if (rootHooks)
        expect(git("show", "HEAD:ordinary.txt")).toBe("ordinary edit");
      expect(pushes).toBe(1);
      expect(creations).toBe(1);
      if (dormantWorktree) {
        expect(git("config", "--get", "core.worktree")).toBe(
          alternate.replaceAll("\\", "/"),
        );
        expect(git("rev-parse", "--show-toplevel").replaceAll("\\", "/")).toBe(
          directory.replaceAll("\\", "/"),
        );
        expect(await readFile(alternateHook, "utf8")).toBe(changed);
        // Git consumes direct core.worktree during setup, before onbranch includes.
        git("config", "--local", "core.worktree", alternate);
        expect(git("rev-parse", "--show-toplevel").replaceAll("\\", "/")).toBe(
          alternate.replaceAll("\\", "/"),
        );
      }
    }
    expect(await readFile(config)).toEqual(configuration);
    expect(await readFile(join(directory, "src/finding-1.ts"), "utf8")).toBe(
      "fixed\n",
    );
  });
}

for (const nested of [false, true]) {
  test(
    `native model permissions preserve dormant trusted hook bytes, nested: ${nested}`,
    async () => {
      const { directory, git } = await publicationRepository(fixtures);
      const support = await fixtures.create("patch-inactive-hook-native-");
      const home = join(support, "home");
      await mkdir(home);
      await writeFile(join(home, "config.toml"), patchSnapshotWindowsConfig());
      const environment = patchSnapshotEnvironment(
        await fixtures.create("patch-inactive-hook-native-temp-"),
        { ...process.env, CODEX_HOME: home },
      );
      const hooks = join(directory, "tracked-hooks");
      const hook = join(hooks, "pre-commit");
      const effect = join(support, "effect");
      const shellPath = `'${effect.replaceAll("\\", "/").replaceAll("'", "'\\''")}'`;
      const trusted = `#!/bin/sh\nprintf trusted > ${shellPath}\n`;
      const changed = `#!/bin/sh\nprintf changed > ${shellPath}\n`;
      await mkdir(hooks);
      await writeFile(hook, trusted, { mode: 0o755 });
      git("add", ".");
      git("commit", "-m", "Synthetic native dormant hook baseline");
      const config = join(directory, ".git", "branch-config");
      await writeFile(
        config,
        nested
          ? "[include]\n path = nested-config\n"
          : "[core]\n hooksPath = tracked-hooks\n",
      );
      if (nested)
        await writeFile(
          join(directory, ".git", "nested-config"),
          "[core]\n hooksPath = tracked-hooks\n",
        );
      git(
        "config",
        "includeIf.onbranch:codex-security/**.path",
        "branch-config",
      );
      const script = join(support, "attempt.cjs");
      await writeFile(
        script,
        `const fs = require("node:fs");
fs.writeSync(2, "Synthetic native hook probe started.\\n");
fs.writeSync(2, "Native probe runtime: " + JSON.stringify({ node: process.versions.node, bun: process.versions.bun }) + "\\n");
process.on("exit", code => fs.writeSync(2, "Native probe exit: " + code + "\\n"));
let denied = false;
try { fs.writeFileSync(${JSON.stringify(hook)}, ${JSON.stringify(changed)}); }
catch (error) { if (!["EACCES", "EPERM", "EROFS"].includes(error.code)) throw error; denied = true; }
fs.writeSync(2, "Native protected write denied: " + denied + "\\n");
fs.writeFileSync(${JSON.stringify(join(directory, "src/finding-1.ts"))}, "fixed\\n");
fs.writeSync(2, "Native ordinary write completed.\\n");
const payload = JSON.stringify({ denied });
try {
  const fd = fs.fstatSync(1, { bigint: true });
  fs.writeSync(2, "Native fd1: " + JSON.stringify({ mode: String(fd.mode), dev: String(fd.dev), ino: String(fd.ino) }) + "\\n");
} catch (error) { fs.writeSync(2, "Native fd1 error: " + String(error.code) + "\\n"); }
fs.writeSync(2, "Native stdout bytes: " + Buffer.byteLength(payload) + "\\n");
fs.writeSync(1, payload);
fs.writeSync(2, "Native probe reached end of script.\\n");
`,
      );
      let denied: boolean | undefined;
      let hookProtected = false;
      let nativeStage = "before model callback";
      let nativeStdout: string | undefined;
      const nativeStderr: Buffer[] = [];
      const nativeOutputEvents: Record<string, unknown>[] = [];
      const outcome = await runWorkflow(
        ["patch", "Synthetic issue", "--create-pr", "--json"],
        {
          currentDirectory: directory,
          environment,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : args[1] === "list"
                ? "[]"
                : "https://github.example.test/example/repository/pull/1",
          onCodex: async (_args, output) => {
            nativeStage = "before native command";
            const paths = output?.appServer?.permissions?.readOnlyPaths ?? [];
            hookProtected = paths.includes(hook);
            const alias = `alias.attempt=!node ${JSON.stringify(script.replaceAll("\\", "/"))}`;
            const restoreOutputObserver = observeNativeOutput(
              alias,
              nativeOutputEvents,
            );
            const result = await runRepositoryCommand(
              "git",
              ["-c", alias, "attempt"],
              directory,
              {
                onStderr: (chunk) => nativeStderr.push(chunk),
                sandbox: {
                  directory,
                  environment,
                  profile: {
                    extends: ":workspace",
                    network: { enabled: false },
                    workspace_roots: {},
                    filesystem: Object.fromEntries(
                      paths.map((path) => [path, { ".": "read" }]),
                    ),
                  },
                },
              },
            ).finally(restoreOutputObserver);
            nativeOutputEvents.push({
              event: "returned",
              bytes: Buffer.byteLength(result),
            });
            nativeStdout = result;
            nativeStage = "parsing native output";
            denied = (JSON.parse(result) as { denied: boolean }).denied;
            nativeStage = "native output parsed";
            output?.stdout.write("Synthetic patch complete.\n");
            return 0;
          },
        },
      );
      expect(
        outcome.exitCode,
        [
          outcome.stderr,
          `Native hook probe stage: ${nativeStage}`,
          `Native stdout: ${JSON.stringify(nativeStdout)}`,
          `Native output events: ${JSON.stringify(nativeOutputEvents)}`,
          `Native stderr: ${JSON.stringify(Buffer.concat(nativeStderr).toString("utf8"))}`,
        ].join("\n"),
      ).toBe(0);
      expect({
        hookProtected,
        denied,
        hook: await readFile(hook, "utf8"),
        effect: await readFile(effect, "utf8"),
      }).toEqual({
        hookProtected: true,
        denied: true,
        hook: trusted,
        effect: "trusted",
      });
      expect(git("show", "HEAD:src/finding-1.ts")).toBe("fixed");
      expect(git("show", "HEAD:tracked-hooks/pre-commit")).toBe(trusted.trim());
    },
    process.platform === "win32" ? 120_000 : 30_000,
  );
}

for (const mode of [
  "malformed",
  "unknown hook user",
  "missing nested include",
  "unknown nested include user",
  "recursive include",
] as const) {
  test(`keeps dormant configuration errors inactive: ${mode}`, async () => {
    const { directory, git } = await publicationRepository(fixtures);
    const config = join(directory, ".git", "branch-config");
    const contents =
      mode === "malformed"
        ? "[malformed\n"
        : mode === "unknown hook user"
          ? "[core]\n hooksPath = ~synthetic_missing_patch_hook_1251/hooks\n"
          : `[include]\n path = ${
              mode === "recursive include"
                ? "branch-config"
                : mode === "missing nested include"
                  ? "missing-config"
                  : "~synthetic_missing_patch_hook_1251/config"
            }\n`;
    await writeFile(config, contents);
    git("config", "includeIf.onbranch:future-branch.path", "branch-config");
    const head = git("rev-parse", "HEAD");
    let launches = 0;
    const outcome = await runWorkflow(["patch", "Synthetic issue", "--json"], {
      currentDirectory: directory,
      onRepositoryCommand: runGitRepositoryCommand,
      onCodex: async (_args, output) => {
        launches++;
        await writeFile(join(directory, "src/finding-1.ts"), "fixed\n");
        output?.stdout.write("Synthetic patch complete.\n");
        return 0;
      },
    });
    expect(outcome.exitCode, outcome.stderr).toBe(0);
    expect(launches).toBe(1);
    expect(JSON.parse(outcome.stdout).files).toEqual(["src/finding-1.ts"]);
    expect(git("rev-parse", "HEAD")).toBe(head);
    expect(await readFile(config, "utf8")).toBe(contents);
  });
}
