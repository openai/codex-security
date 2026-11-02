import { spawnSync } from "node:child_process";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { VERSION } from "../src/version.js";
import {
  removeTemporaryDirectory,
  temporaryDirectory,
} from "./support/temporary-directories.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { importedAlert } from "./support/github-import-fixtures.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

const commands = [
  ["publish", "findings"],
  ["findings", "imported"],
  ["import", "github-advisories"],
  ["import", "sonar"],
];

const publishLocal = [
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
];

test("disabled commands distinguish discovery requests from filter values", async () => {
  const deps = dependencies({ environment: {} });
  for (const flag of ["--schema", "--llms-full", "--help"]) {
    const cli = createCliTest(main);
    expect(
      await cli.runCli(
        [
          "--filter-output",
          `--token-limit=${flag}`,
          "publish",
          "findings",
          "--json",
        ],
        deps,
      ),
    ).toBe(2);
    expect(cli.stdout.text()).toBe("");
    expect(cli.stderr.text()).toContain(
      "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
    );
  }
  const filtered = createCliTest(main);
  expect(
    await filtered.runCli(
      [
        ...publishLocal,
        "--filter-output=--schema",
        "--full-output",
        "--format=json",
      ],
      deps,
    ),
  ).toBe(2);
  expect(JSON.parse(filtered.stdout.text()).error.code).toBe("IMPORT_FAILED");
});

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
    publishLocal,
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
    ["import", "sonar"],
  ]) {
    const cli = createCliTest(main);
    expect(await cli.runCli(command, deps)).not.toBe(0);
    expect(cli.stderr.text()).toContain(
      "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
    );
    if (command[0] === "publish") {
      for (const [flags, diagnostic] of [
        [["--unknown", "--json"], cli.stderr.text()],
        [
          ["extra.json", "--json"],
          "Unexpected positional argument for publish findings.",
        ],
        [
          ["--source-key", "--dry-run", "--json"],
          "Missing value for flag: --source-key",
        ],
      ] as const) {
        const rejected = createCliTest(main);
        expect(await rejected.runCli([...command, ...flags], deps)).toBe(2);
        expect(rejected.stdout.text()).toBe("");
        expect(rejected.stderr.text()).toContain(diagnostic);
      }
      for (const [flags, result] of [
        [["--format=yaml"], /^status: failed$/m],
        [["--format", "md"], /\|\s*status\s*\|\s*failed\s*\|/],
        [["--format", "json", "--format", "yaml"], /^status: failed$/m],
      ] as const) {
        const formatted = createCliTest(main);
        expect(await formatted.runCli([...command, ...flags], deps)).toBe(2);
        expect(formatted.stdout.text()).toMatch(result);
        expect(formatted.stdout.text()).toContain(
          "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
        );
      }
      for (const format of ["json", "jsonl"]) {
        const formatted = createCliTest(main);
        expect(
          await formatted.runCli(
            [...command, "--format", format, "--full-output"],
            deps,
          ),
        ).toBe(2);
        const message = expect.stringContaining(
          "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
        );
        expect(JSON.parse(formatted.stdout.text())).toMatchObject({
          ok: false,
          error: { code: "IMPORT_FAILED", message },
          data: { status: "failed", error: message },
        });
      }
      const unsupported = createCliTest(main);
      expect(
        await unsupported.runCli(
          [...command, "--format", "json", "--format", "yaml", "--full-output"],
          deps,
        ),
      ).toBe(2);
      expect(unsupported.stdout.text()).toContain("INVALID_ARGUMENTS");
    } else if (command[0] === "import") {
      const errorCode =
        command[1] === "sonar" ? "SONAR_IMPORT_FAILED" : "GITHUB_IMPORT_FAILED";
      for (const format of [undefined, "json", "jsonl", "yaml", "md", "toon"]) {
        const formatted = createCliTest(main);
        expect(
          await formatted.runCli(
            [
              ...command,
              "--full-output",
              ...(format === undefined ? [] : ["--format", format]),
            ],
            deps,
          ),
        ).toBe(2);
        if (format === "json" || format === "jsonl") {
          expect(JSON.parse(formatted.stdout.text())).toMatchObject({
            ok: false,
            error: { code: errorCode },
          });
        } else {
          expect(formatted.stdout.text()).toContain(errorCode);
        }
        expect(formatted.stdout.text()).toContain(
          "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
        );
      }
    }
  }
  expect(unexpected).not.toHaveBeenCalled();
});

test("a closed diagnostic pipe preserves the Sonar error envelope", async () => {
  const stdout = capture();
  const stderr = new Writable({
    write(_chunk, _encoding, done) {
      setImmediate(() =>
        done(Object.assign(new Error("closed"), { code: "EPIPE" })),
      );
    },
  });
  const closed = new Promise<void>((resolve) => stderr.once("close", resolve));
  const code = await main(
    ["import", "sonar", "--full-output", "--format=json"],
    stdout.stream,
    stderr,
    dependencies({ environment: {} }),
  );
  await closed;
  expect(code).toBe(2);
  expect(JSON.parse(stdout.text()).error.code).toBe("SONAR_IMPORT_FAILED");
});

test("rejects unsupported Sonar full-output formats before collecting findings", async () => {
  const collectSonarIssues = mock(async (): Promise<never> => {
    throw new Error("Unexpected collection");
  });
  const cli = createCliTest(main);
  const deps = {
    ...dependencies({
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
    }),
    collectSonarIssues,
  };
  expect(
    await cli.runCli(
      ["import", "sonar", "--yes", "--full-output", "--format", "yaml"],
      deps,
    ),
  ).toBe(2);
  expect(cli.stdout.text()).toContain("INVALID_ARGUMENTS");
  expect(collectSonarIssues).not.toHaveBeenCalled();
});

const installedSkills =
  "installed skills preserve import errors and collector output";
test(installedSkills, async () => {
  if (runTestInSubprocess(import.meta.path, installedSkills)) return;
  const root = await temporaryDirectory("disabled-import-skills-");
  const entry = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const run = (...args: string[]) =>
    spawnSync(process.execPath, [entry, ...args], {
      cwd: root,
      env: {
        ...process.env,
        COMPLETE: "",
        HOME: root,
        USERPROFILE: root,
        CODEX_HOME: root,
        XDG_DATA_HOME: root,
        CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "0",
        CODEX_SECURITY_NO_UPDATE_NOTICE: "1",
      },
      encoding: "utf8",
    });
  try {
    expect(run("skills", "add", "--no-global").status).toBe(0);
    for (const args of [
      [...publishLocal, "--json"],
      [
        "import",
        "github-advisories",
        "example/project",
        "--json",
        "--full-output",
      ],
    ]) {
      const result = run(...args);
      expect(result.status).toBe(2);
      expect(result.stdout).toContain(
        "CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS=1",
      );
      expect(result.stdout).not.toContain("Skills are out of date");
    }

    process.env["XDG_DATA_HOME"] = root;
    const alerts = [importedAlert()];
    const deps = dependencies({
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "1" },
      importGitHubAlerts: async () => alerts,
    });
    const args = ["import", "github", "example/project", "--json"];
    const full = createCliTest(main);
    expect(await full.runCli([...args, "--full-output"], deps)).toBe(0);
    expect(JSON.parse(full.stdout.text())).toMatchObject({
      data: alerts,
      meta: { cta: { description: "Skills are out of date:" } },
    });
    const plain = createCliTest(main);
    expect(await plain.runCli(args, deps)).toBe(0);
    expect(JSON.parse(plain.stdout.text())).toEqual(alerts);
    const yaml = createCliTest(main);
    expect(await yaml.runCli([...args, "--format=yaml"], deps)).toBe(0);
    expect(Bun.YAML.parse(yaml.stdout.text())).toEqual(alerts);
  } finally {
    await removeTemporaryDirectory(root);
  }
});

test("opt-in exposes the commands per invocation without affecting concurrent disabled discovery", async () => {
  await Promise.all(
    [true, false].map(async (enabled) => {
      const environment = {
        CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: enabled ? "1" : "0",
      };
      for (const [group, command] of commands) {
        const version = createCliTest(main);
        expect(
          await version.runCli(
            [group!, command!, "--version", "--json"],
            dependencies({ environment }),
          ),
        ).toBe(0);
        expect(version.stdout.text()).toBe(`${VERSION}\n`);
        expect(version.stderr.text()).toBe("");
        const cli = createCliTest(main);
        expect(
          await cli.runCli([group!, "--help"], dependencies({ environment })),
        ).toBe(0);
        expect(
          new RegExp(`^\\s+${command}\\s`, "m").test(cli.stdout.text()),
        ).toBe(enabled);
        const schema = createCliTest(main);
        const status = await schema.runCli(
          [group!, command!, "--schema"],
          dependencies({ environment }),
        );
        if (enabled) expect(status).toBe(0);
        else expect(status).not.toBe(0);
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
    expect(cli.stdout.text()).toContain(
      `Usage: codex-security ${command.join(" ")} `,
    );
    if (command[0] === "import" && command[1] === "github")
      expect(cli.stdout.text()).not.toContain("publish findings");
  }
});
