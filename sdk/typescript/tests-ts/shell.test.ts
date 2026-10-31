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

test("captures asynchronous command input, output, and failure diagnostics", async () => {
  const input = "literal %USERNAME% !EXPAND! caf\u00e9's \u96ea\n";
  const result = await runCommand(
    process.execPath,
    [
      "-e",
      `
        let input = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (chunk) => { input += chunk; });
        process.stdin.on("end", () => {
          process.stdout.write(input);
          process.stderr.write("native stderr\\n");
          process.exitCode = 23;
        });
      `,
    ],
    { input, timeout: 30_000, windowsHide: true },
  );
  expect(result.status).toBe(23);
  expect(result.stdout).toBe(input);
  expect(result.stderr).toBe("native stderr\n");
  expect(result.signal).toBeNull();
  expect(result.error).toBeInstanceOf(Error);
});
