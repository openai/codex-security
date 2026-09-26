import { isAbsolute, join, resolve } from "node:path";
import { expect, spyOn, test } from "bun:test";
import { bashCommand, runCommand } from "./support/shell.js";

test.skipIf(process.platform !== "win32").each(["cmd", "bin", "mingw64/bin"])(
  "uses Git Bash when Git is found in %s",
  async (directory) => {
    const gitExecPath = await runCommand("git", ["--exec-path"], {
      timeout: 10_000,
    });
    expect(gitExecPath.status).toBe(0);
    const gitRoot = resolve(gitExecPath.stdout.trim(), "..", "..", "..");
    const which = spyOn(Bun, "which").mockReturnValue(
      join(gitRoot, directory, "git.exe"),
    );
    let bash: string;
    try {
      bash = bashCommand();
    } finally {
      which.mockRestore();
    }

    expect(isAbsolute(bash)).toBe(true);
    const result = await runCommand(bash, ["-c", "uname -s"], {
      timeout: 10_000,
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toMatch(/^MINGW/u);
  },
);
