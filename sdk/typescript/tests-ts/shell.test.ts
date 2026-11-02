import { join } from "node:path";
import { expect, spyOn, test } from "bun:test";
import { bashCommand, runCommand, writeSource } from "./support/shell.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test.skipIf(process.platform !== "win32")(
  "uses Bash from the Git for Windows installation",
  async () => {
    const bash = bashCommand();
    if (bash !== "bash") {
      const result = await runCommand(bash, ["-c", 'test -n "$BASH_VERSION"']);
      expect(result.status, result.stderr).toBe(0);
    }

    await using fixture = await scopedTemporaryDirectory("git-bash-layout-");
    const root = join(fixture.path, "Git");
    using which = spyOn(Bun, "which");
    const bashForGitIn = (directory: string) => {
      const git = join(directory, "git.exe");
      writeSource(root, git, "");
      which.mockReturnValue(join(root, git));
      return bashCommand();
    };

    writeSource(fixture.path, "bin/bash.exe", "");
    expect(bashForGitIn("cmd")).toBe("bash");
    expect(bashForGitIn("bin")).toBe("bash");

    const shell = join("bin", "bash.exe");
    writeSource(root, shell, "");
    const prefixes = ["mingw32", "mingw64", "ucrt64", "clangarm64"];
    const bins = prefixes.map((prefix) => join(prefix, "bin"));
    for (const directory of ["cmd", "bin", ...bins]) {
      expect(bashForGitIn(directory)).toBe(join(root, shell));
    }
    writeSource(root, join("mingw64", shell), "");
    expect(bashForGitIn("mingw64/bin")).toBe(join(root, "mingw64", shell));
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
