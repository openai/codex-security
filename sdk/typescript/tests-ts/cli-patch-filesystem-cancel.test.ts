import { afterEach, expect, mock, test } from "bun:test";
import fs from "node:fs";
import filesystem, { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { runCodexSkillCommand } from "../src/cli.js";
import {
  publicationRepository,
  runGitRepositoryCommand,
  runWorkflow,
} from "./cli-patch-fixtures.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const fixtures = createTemporaryDirectories(true);
afterEach(fixtures.cleanup);

for (const kind of ["directory", "ignored file"] as const) {
  const name = `cancels ${kind} preparation and waits for filesystem cleanup`;
  test(name, async () => {
    if (runTestInSubprocess(fileURLToPath(import.meta.url), name)) return;
    const repository =
      kind === "directory"
        ? await fixtures.create("patch-cancel-directory-")
        : (await publicationRepository(fixtures)).directory;
    const slowPath = join(repository, kind === "directory" ? "a.txt" : ".env");
    await writeFile(slowPath, "Synthetic content\n");
    await writeFile(join(repository, "b.txt"), "Other content\n");
    if (kind === "ignored file") {
      await writeFile(join(repository, ".gitignore"), ".env\n");
      runGitRepositoryCommand("git", ["add", "."], repository);
      runGitRepositoryCommand(
        "git",
        ["commit", "-m", "Synthetic ignored baseline"],
        repository,
      );
    }
    const home = await fixtures.create("patch-cancel-home-");
    await writeFile(join(home, "config.toml"), "");
    const source = `const lines=require("node:readline").createInterface({input:process.stdin});const send=m=>process.stdout.write(JSON.stringify(m)+"\\n");lines.on("line",line=>{const r=JSON.parse(line);if(r.id===undefined)return;send({id:r.id,result:r.method==="thread/start"?{thread:{id:"synthetic"},sandbox:{type:"workspaceWrite"}}:r.method==="command/exec"?{exitCode:0}:r.method==="config/read"?{config:{}}:{}});});`;
    const originalRead = fs.createReadStream;
    const originalOpen = filesystem.open;
    let slow: PassThrough | undefined;
    let cleanupComplete = false;
    let preparation: Promise<void> | undefined;
    let preparationSettled = false;
    let returned = false;
    let readsAfterReturn = 0;
    const start = () => {
      slow = new PassThrough({
        destroy(error, callback) {
          // Keep cleanup pending beyond the child's existing termination grace.
          void delay(1500).then(() => {
            cleanupComplete = true;
            callback(error);
          });
        },
      });
      setImmediate(() => process.emit("SIGTERM"));
      return slow;
    };
    const reading: typeof originalRead = (path, options) => {
      if (String(path) === slowPath && slow === undefined)
        return start() as unknown as ReturnType<typeof originalRead>;
      if (String(path).startsWith(repository) && returned) readsAfterReturn++;
      return originalRead(path, options);
    };
    const opening: typeof originalOpen = async (...args) => {
      const file = await originalOpen(...args);
      if (String(args[0]) === slowPath && kind === "ignored file") {
        file.createReadStream = () =>
          start() as unknown as ReturnType<typeof file.createReadStream>;
      }
      return file;
    };
    mock.module("node:fs", () => ({
      ...fs,
      default: fs,
      createReadStream: reading,
    }));
    mock.module("node:fs/promises", () => ({
      ...filesystem,
      default: filesystem,
      open: opening,
    }));
    try {
      const outcome = await runWorkflow(
        [
          "patch",
          "Synthetic issue",
          ...(kind === "ignored file" ? ["--create-pr"] : []),
          "--json",
        ],
        {
          currentDirectory: repository,
          environment: { ...process.env, CODEX_HOME: home },
          manualCodexPreparation: true,
          onRepositoryCommand: (command, args, cwd, options) =>
            command === "git"
              ? runGitRepositoryCommand(command, args, cwd, options)
              : "[]",
          onCodex: (_args, output, environment) => {
            const before = output!.appServer!.onBeforeTurn!;
            return runCodexSkillCommand(
              ["-e", source],
              {
                ...output!,
                auth: undefined,
                appServer: {
                  ...output!.appServer!,
                  onBeforeTurn(signal) {
                    preparation = before(signal).finally(() => {
                      preparationSettled = true;
                    });
                    return preparation;
                  },
                },
              },
              { command: process.execPath },
              environment,
            );
          },
        },
      );
      returned = true;
      expect(outcome.exitCode, outcome.stderr).toBe(143);
      expect(slow).toBeDefined();
      expect(slow!.destroyed).toBe(true);
      expect(cleanupComplete).toBe(true);
      expect(preparationSettled).toBe(true);
      expect(readsAfterReturn).toBe(0);
      expect(await readFile(slowPath, "utf8")).toBe("Synthetic content\n");
    } finally {
      slow?.destroy();
      await preparation?.catch(() => undefined);
      mock.module("node:fs", () => ({
        ...fs,
        default: fs,
        createReadStream: originalRead,
      }));
      mock.module("node:fs/promises", () => ({
        ...filesystem,
        default: filesystem,
        open: originalOpen,
      }));
    }
  });
}
