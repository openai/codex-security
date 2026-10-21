import { expect, test } from "bun:test";
import { runCommand } from "./support/shell.js";

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
