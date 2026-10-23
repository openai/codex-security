import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

const commands = [
  ["publish", "findings"],
  ["findings", "imported"],
  ["import", "github-advisories"],
];

for (const value of [undefined, "", "0", "true"]) {
  test(`external commands are absent from discovery without opt-in (${String(value)})`, async () => {
    const environment = { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: value };
    for (const [group, command] of commands) {
      const cli = createCliTest(main);
      expect(
        await cli.runCli([group!, "--help"], dependencies({ environment })),
      ).toBe(0);
      expect(cli.stdout.text()).not.toMatch(
        new RegExp(`^\\s+${command}\\s`, "m"),
      );
      const schema = createCliTest(main);
      expect(
        await schema.runCli(
          [group!, command!, "--schema"],
          dependencies({ environment }),
        ),
      ).not.toBe(0);
    }
    const github = createCliTest(main);
    expect(
      await github.runCli(
        ["import", "github", "--help"],
        dependencies({ environment }),
      ),
    ).toBe(0);
    expect(github.stdout.text()).not.toContain("publish findings");
  });
}

test("disabled commands cannot invoke import, storage, or publication handlers", async () => {
  const unexpected = mock(async () => {
    throw new Error("Unexpected import handler");
  });
  const deps = {
    ...dependencies({
      environment: {},
      importGitHubAdvisories: unexpected,
      onWorkbench: unexpected,
    }),
    prepareLocalExternalImport: unexpected,
    listLocalExternalFindings: unexpected,
    cloudFetch: unexpected,
  };
  for (const command of [
    [
      "publish",
      "findings",
      "selected.json",
      "--to",
      "local",
      "--repository",
      ".",
      "--provider",
      "wiz",
      "--source-key",
      "synthetic/findings",
      "--yes",
    ],
    [
      "publish",
      "findings",
      "selected.json",
      "--to",
      "cloud",
      "--repository",
      "example/project",
      "--provider",
      "snyk",
      "--source-key",
      "synthetic/findings",
      "--yes",
    ],
    ["findings", "imported", "."],
    ["import", "github-advisories", "example/project"],
  ]) {
    const cli = createCliTest(main);
    expect(await cli.runCli(command, deps)).not.toBe(0);
  }
  expect(unexpected).not.toHaveBeenCalled();
});

test("opt-in exposes the commands per invocation without affecting concurrent disabled discovery", async () => {
  await Promise.all(
    [true, false].map(async (enabled) => {
      const environment = {
        CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: enabled ? "1" : "0",
      };
      for (const [group, command] of commands) {
        const cli = createCliTest(main);
        expect(
          await cli.runCli([group!, "--help"], dependencies({ environment })),
        ).toBe(0);
        expect(
          new RegExp(`^\\s+${command}\\s`, "m").test(cli.stdout.text()),
        ).toBe(enabled);
        if (enabled) {
          const help = createCliTest(main);
          expect(
            await help.runCli(
              [group!, command!, "--schema"],
              dependencies({ environment }),
            ),
          ).toBe(0);
        }
      }
    }),
  );
});

test("established scan publishing, status, scan import, and GitHub collection stay available", async () => {
  for (const command of [
    ["publish", "scan"],
    ["publish", "check"],
    ["scan", "import"],
    ["import", "github"],
  ]) {
    const cli = createCliTest(main);
    expect(
      await cli.runCli(
        [...command, "--help"],
        dependencies({ environment: {} }),
      ),
    ).toBe(0);
  }
});
