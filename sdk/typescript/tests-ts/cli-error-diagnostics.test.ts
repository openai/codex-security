import { chmod, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { readCodexHomeConfig } from "../src/auth.js";
import { main } from "../src/cli.js";
import { ContractValidationError } from "../src/errors.js";
import { completedEvents, runEvents } from "./support/api-events.js";
import { parseImportedFindings } from "../src/findings-import.js";
import { PLUGIN_ROOT, copyCompletedScan } from "./plugin-root.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const controls = "\u001b]52;c;U1lOVEhFVElD\u0007\u009b2J";
const detail = `Synthetic sk-proj-SYNTHETIC_KEY_123 ${controls}\nsecond diagnostic line`;
const escapedDetail =
  "Synthetic sk-proj-SYNTHETIC_KEY_123  ]52;c;U1lOVEhFVElD  2J\nsecond diagnostic line";
const escapedSingleLineDetail =
  "Synthetic sk-proj-SYNTHETIC_KEY_123  ]52;c;U1lOVEhFVElD  2J second diagnostic line";

test("feedback escapes real config diagnostics only at the text output boundary", async () => {
  const root = await temporaryDirectory("feedback-config-diagnostic-", true);
  const environment = { CODEX_HOME: root };
  try {
    await writeFile(join(root, "config.toml"), `broken = "${controls}"\n`, {
      mode: 0o600,
    });
    const failure = await readCodexHomeConfig(environment).catch(
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toContain(controls);
    expect(((failure as Error).cause as Error).message).toContain(controls);
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(
      await runCli(
        ["feedback", "--reason", "Synthetic problem"],
        dependencies({ environment }),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain(
      "Could not read the configured Codex provider",
    );
    expect(stderr.text()).toContain("]52;c;U1lOVEhFVElD");
    expect(stderr.text()).not.toMatch(
      /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u,
    );
    expect((failure as Error).message).toContain(controls);
    expect(((failure as Error).cause as Error).message).toContain(controls);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const scenario of [
  "history",
  "resume",
  "rerun",
  "scan run",
  "export",
] as const) {
  test(`${scenario} escapes text failures while preserving structured and SDK details`, async () => {
    const cause = new Error("Synthetic cause");
    const failure = new Error(detail, { cause });
    const fail = () => {
      throw failure;
    };
    const deps = dependencies({
      ...(scenario === "history" ||
      scenario === "resume" ||
      scenario === "rerun"
        ? { onWorkbench: fail }
        : {}),
      ...(scenario === "scan run" ? { onRun: fail } : {}),
    });
    if (scenario === "export") deps.exportFindings = async () => fail();
    const args =
      scenario === "history"
        ? ["feedback", "scan-known", "--reason", "Synthetic problem"]
        : scenario === "resume"
          ? ["scans", "resume", "scan-known", "--json"]
          : scenario === "rerun"
            ? ["scans", "rerun", "--json"]
            : scenario === "export"
              ? ["export", "scan", "--export-format", "json", "--output", "-"]
              : ["scan", ".", "--json"];
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(await runCli(args, deps)).toBe(2);
    expect(stderr.text()).toContain(
      scenario === "scan run" ? escapedSingleLineDetail : escapedDetail,
    );
    expect(stderr.text()).not.toContain(controls);
    if (
      scenario === "resume" ||
      scenario === "rerun" ||
      scenario.startsWith("scan")
    ) {
      expect(JSON.parse(stdout.text()).message).toContain(
        scenario === "scan run" ? escapedSingleLineDetail : detail,
      );
    } else {
      expect(stdout.text()).toBe("");
    }
    expect(failure.message).toBe(detail);
    expect(failure.cause).toBe(cause);
  });
}

test("successful raw exports preserve terminal controls as artifact bytes", async () => {
  const deps = dependencies();
  deps.exportFindings = async () => Buffer.from(detail);
  const { stdout, stderr, runCli } = createCliTest(main);
  expect(
    await runCli(
      ["export", "scan", "--export-format", "json", "--output", "-"],
      deps,
    ),
  ).toBe(0);
  expect(stdout.text()).toBe(detail);
  expect(stderr.text()).toBe("");
});

for (const command of ["import", "owners"] as const) {
  test(`${command} escapes actual malformed JSON diagnostics without changing parser details`, async () => {
    const root = await temporaryDirectory("malformed-json-diagnostic-", true);
    try {
      const source = "\u009b2J";
      const input = join(root, "findings.json");
      await writeFile(input, source);
      const failure = await parseImportedFindings(
        source,
        "json",
        PLUGIN_ROOT,
      ).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(Error);
      const message = (failure as Error).message;
      const { stdout, stderr, runCli } = createCliTest(main);
      expect(
        await runCli(
          command === "import"
            ? [
                "scan",
                "import",
                "--json",
                input,
                "--dry-run",
                "--format",
                "json",
              ]
            : ["suggest-owners", input],
          dependencies({ currentDirectory: root }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain("Findings JSON");
      expect(stderr.text()).not.toMatch(
        /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u,
      );
      expect(stdout.text()).toBe("");
      expect((failure as Error).message).toBe(message);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
}

test.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
  "preserves native artifact failures through the SDK and CLI",
  async () => {
    const root = await temporaryDirectory(
      "artifact-permission-diagnostic-",
      true,
    );
    const scanDir = await copyCompletedScan(root);
    try {
      await chmod(scanDir, 0o600);
      const failure = await runEvents(scanDir, completedEvents()).catch(
        (error: unknown) => error,
      );
      expect(failure).toBeInstanceOf(ContractValidationError);
      const cause = (failure as Error).cause as NodeJS.ErrnoException;
      expect(cause.code).toBe("EACCES");
      expect(cause.path).toBe(join(scanDir, "scan-manifest.json"));
      expect((failure as Error).message).toContain(cause.message);

      const { stdout, stderr, runCli } = createCliTest(main);
      expect(
        await runCli(
          ["scan", ".", "--json"],
          dependencies({
            onRun: () => {
              throw failure;
            },
          }),
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(cause.message);
      expect(JSON.parse(stdout.text()).message).toContain(cause.message);
      expect((failure as Error).cause).toBe(cause);
    } finally {
      await chmod(scanDir, 0o700);
      await rm(root, { recursive: true, force: true });
    }
  },
);
