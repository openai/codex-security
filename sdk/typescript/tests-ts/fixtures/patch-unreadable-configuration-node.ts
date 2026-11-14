import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { appendFile, chmod, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { main } from "../../src/cli.js";
import { capture, dependencies } from "../cli-fixtures.js";

const { root, control, alias, activate, environment } = JSON.parse(
  readFileSync(0, "utf8"),
) as {
  root: string;
  control: string;
  alias: string;
  activate: boolean;
  environment: NodeJS.ProcessEnv;
};
const stdout = capture();
const stderr = capture();
let launches = 0;
const postModelGit: string[][] = [];
const exitCode = await main(
  ["patch", "Synthetic issue", "--json"],
  stdout.stream,
  stderr.stream,
  dependencies({
    currentDirectory: root,
    environment,
    onRepositoryCommand: (command, args, cwd, options) => {
      assert.equal(command, "git");
      if (launches > 0) postModelGit.push([...args]);
      const result = execFileSync("git", args, {
        cwd,
        env: { ...process.env, ...environment, ...options?.environment },
        encoding:
          options?.encoding === "base64" || options?.onStdout !== undefined
            ? "buffer"
            : "utf8",
        maxBuffer: options?.maxBuffer,
        input: options?.input,
        stdio: [
          options?.input === undefined ? "ignore" : "pipe",
          "pipe",
          "pipe",
        ],
      });
      if (options?.onStdout !== undefined) {
        options.onStdout(
          Buffer.isBuffer(result) ? result : Buffer.from(result),
        );
        return "";
      }
      const output = Buffer.isBuffer(result)
        ? result.toString(options?.encoding ?? "utf8")
        : result;
      return options?.trim === false ? output : output.trim();
    },
    onCodex: async (_args, output) => {
      launches++;
      if (activate) {
        assert.equal((await stat(alias)).ino, (await stat(control)).ino);
        await chmod(alias, 0o600);
        await appendFile(alias, "[synthetic]\n value = activated\n");
      }
      await writeFile(join(root, "app.ts"), "after\n");
      output?.stdout.write("Synthetic patch complete.\n");
      return 0;
    },
  }),
);
process.stdout.write(
  JSON.stringify({
    launches,
    postModelGit,
    exitCode,
    stdout: stdout.text(),
    stderr: stderr.text(),
  }),
);
