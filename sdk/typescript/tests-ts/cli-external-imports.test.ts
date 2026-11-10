import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Writable } from "node:stream";
import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  removeTemporaryDirectory,
  temporaryDirectory,
} from "./support/temporary-directories.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { importedAdvisory } from "./support/github-import-fixtures.js";
import { runTestInSubprocess } from "./support/test-subprocess.js";

test.each(
  Object.entries({
    publish: ["findings"],
    findings: ["imported"],
    import: ["github-advisories", "semgrep", "snyk", "sonar"],
  }),
)("%s commands are discoverable by default", async (group, commands) => {
  const deps = dependencies();
  const help = createCliTest(main);
  expect(await help.runCli([group, "--help"], deps)).toBe(0);
  const helpText = help.stdout.text();
  for (const command of commands) {
    expect(helpText).toMatch(new RegExp(`^\\s+${command}\\s`, "m"));

    const schema = createCliTest(main);
    expect(
      await schema.runCli([group, command, "--schema", "--json"], deps),
    ).toBe(0);
    expect(JSON.parse(schema.stdout.text()).output).toBeDefined();
  }
});

test("a legacy disabled setting still allows reading imported findings", async () => {
  const cli = createCliTest(main);
  const listLocalExternalFindings = mock(async () => []);
  const code = await cli.runCli(["findings", "imported", ".", "--json"], {
    ...dependencies({
      environment: { CODEX_SECURITY_ENABLE_EXTERNAL_IMPORTS: "0" },
    }),
    listLocalExternalFindings,
  });
  expect(code).toBe(0);
  expect(listLocalExternalFindings).toHaveBeenCalledTimes(1);
  expect(JSON.parse(cli.stdout.text()).findings).toEqual([]);
});

test("Semgrep import advertises its saved report format and native finding JSON strings", async () => {
  const cli = createCliTest(main);
  const code = await cli.runCli(
    ["import", "semgrep", "--schema", "--json"],
    dependencies(),
  );
  expect(code).toBe(0);
  expect(JSON.parse(cli.stdout.text()).output).toMatchObject({
    properties: {
      format: { const: "semgrep-platform-findings/v2" },
      project: { properties: { id: { type: "string" } } },
      product: { enum: ["sast", "sca", "ai_sast"] },
      findings: { type: "array", items: { type: "string" } },
    },
  });
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
    [
      "import",
      "sonar",
      "capture.json",
      "--sonar-project",
      "synthetic",
      "--full-output",
      "--format=json",
    ],
    stdout.stream,
    stderr,
    dependencies(),
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
    ...dependencies(),
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
  "stale installed skills preserve raw result objects and arrays";
test(installedSkills, async () => {
  if (runTestInSubprocess(import.meta.path, installedSkills)) return;
  const root = await temporaryDirectory("import-skills-");
  try {
    process.env["XDG_DATA_HOME"] = root;
    const skill = join(root, "codex-security-import");
    await mkdir(skill);
    await writeFile(join(skill, "SKILL.md"), "Previously installed skill.");
    await mkdir(join(root, "incur"));
    await writeFile(
      join(root, "incur", "codex-security.json"),
      JSON.stringify({
        hash: "previous-command-hash",
        skills: ["codex-security-import"],
        paths: [skill],
      }),
    );

    const advisories = [importedAdvisory()];
    const deps = dependencies({
      importGitHubAdvisories: async () => advisories,
    });
    const args = ["import", "github-advisories", "example/project", "--json"];
    const full = createCliTest(main);
    expect(await full.runCli([...args, "--full-output"], deps)).toBe(0);
    expect(JSON.parse(full.stdout.text())).toMatchObject({
      data: advisories,
      meta: { cta: { description: "Skills are out of date:" } },
    });
    const plain = createCliTest(main);
    expect(await plain.runCli(args, deps)).toBe(0);
    expect(JSON.parse(plain.stdout.text())).toEqual(advisories);
    const yaml = createCliTest(main);
    expect(await yaml.runCli([...args, "--format=yaml"], deps)).toBe(0);
    expect(Bun.YAML.parse(yaml.stdout.text())).toEqual(advisories);
    const scan = createCliTest(main);
    expect(await scan.runCli(["scan", ".", "--dry-run", "--json"], deps)).toBe(
      0,
    );
    const preflight = JSON.parse(scan.stdout.text());
    expect(preflight.dryRun).toBe(true);
    expect(preflight).not.toHaveProperty("cta");
  } finally {
    await removeTemporaryDirectory(root);
  }
});
