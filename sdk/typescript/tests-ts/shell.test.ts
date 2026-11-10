import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { bashCommand, runCommand, writeSource } from "./support/shell.js";
import { scopedTemporaryDirectory } from "./support/temporary-directories.js";

test("resolves Bash within the selected Git installation", async () => {
  await using fixture = await scopedTemporaryDirectory("git-bash-layout-");
  const root = join(fixture.path, "Git");
  const shell = join("bin", "bash.exe");
  const gitIn = (directory: string) => join(root, directory, "git.exe");
  writeSource(fixture.path, shell, "");
  expect(bashCommand(null)).toBe("bash");
  expect(bashCommand(gitIn("cmd"))).toBe("bash");
  expect(bashCommand(gitIn(join("mingw64", "bin")))).toBe("bash");

  writeSource(root, shell, "");
  for (const directory of [
    "cmd",
    "bin",
    "mingw32/bin",
    "mingw64/bin",
    "ucrt64/bin",
    "clangarm64/bin",
  ]) {
    expect(bashCommand(gitIn(directory))).toBe(join(root, shell));
  }
  const nested = join("mingw64", shell);
  writeSource(root, nested, "");
  expect(bashCommand(gitIn("mingw64/bin"))).toBe(join(root, nested));
  expect(bashCommand(gitIn("unrelated/bin"))).toBe("bash");
});

const installedGitBash =
  process.platform === "win32" ? bashCommand(Bun.which("git")) : "bash";
test.skipIf(installedGitBash === "bash")(
  "Git Bash can write a Windows workflow output path",
  async () => {
    await using fixture = await scopedTemporaryDirectory(
      "bash-workflow-output-",
    );
    const output = join(fixture.path, "step output");
    const bash = bashCommand();
    expect(bash).toBe(installedGitBash);
    const result = await runCommand(bash, [
      "-c",
      'printf done > "$1"',
      "bash",
      output,
    ]);
    expect(result.status, result.stderr).toBe(0);
    expect(await readFile(output, "utf8")).toBe("done");
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
