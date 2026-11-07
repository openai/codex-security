import { chmod, mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { readCodexHomeConfig } from "../src/auth.js";
import { main } from "../src/cli.js";
import { ContractValidationError, IncompleteScanError } from "../src/errors.js";
import { completedEvents, runEvents } from "./support/api-events.js";
import { parseImportedFindings } from "../src/findings-import.js";
import { runWorkbench } from "../src/runtime.js";
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

test("scans list retains actual SQLite diagnostics and recovery advice", async () => {
  const root = await temporaryDirectory("history-database-diagnostic-", true);
  const stateDirectory = join(root, "state");
  const database = join(stateDirectory, "workbench.sqlite3");
  try {
    await mkdir(database, { recursive: true });
    const environment = {
      ...process.env,
      CODEX_SECURITY_STATE_DIR: stateDirectory,
    };
    const { stdout, stderr, runCli } = createCliTest(main);
    expect(
      await runCli(
        ["scans", "list"],
        dependencies({
          currentDirectory: root,
          environment,
          onWorkbench: (args, input, signal) =>
            runWorkbench(
              { pluginRoot: PLUGIN_ROOT, environment, signal },
              args,
              input,
            ),
        }),
      ),
    ).toBe(2);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Traceback");
    expect(stderr.text()).toContain(
      "sqlite3.OperationalError: unable to open database file",
    );
    expect(stderr.text()).toContain(database);
    expect(stderr.text()).toContain("SQLite journal files are writable");
    expect(stderr.text().match(/CODEX_SECURITY_STATE_DIR/gu)).toHaveLength(1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

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

test.each([
  {
    label: "filesystem",
    diagnostic:
      "EACCES: permission denied, open /synthetic/scan/artifacts/candidates.jsonl",
    advice: "cannot access the configured model",
  },
  {
    label: "wrapped filesystem",
    diagnostic:
      "EACCES: permission denied, mkdtemp /synthetic/codex-output-schema",
    causeCode: "EACCES",
    advice: undefined,
  },
  {
    label: "native refresh recovery",
    diagnostic:
      "Synthetic context: your access token could not be refreshed because you have since logged out or signed in to another account. Please sign in again. Synthetic artifact recovery failed.",
    advice: "Please sign in again.",
  },
  {
    label: "expired native refresh",
    diagnostic:
      "Synthetic context: your access token could not be refreshed because your refresh token has expired. Please log out and sign in again. Synthetic artifact recovery failed.",
    advice: "stored ChatGPT sign-in could not be refreshed",
  },
  {
    label: "authentication",
    diagnostic: "401 synthetic unauthorized request",
    advice: "Authentication failed",
  },
  {
    label: "authorization",
    diagnostic: "403 synthetic model access denied",
    advice: "cannot access the configured model",
  },
  {
    label: "stored API key authorization",
    diagnostic: "403 synthetic model access denied",
    advice: "The stored API key cannot access the configured model",
    storedApiKey: true,
  },
  {
    label: "rate limit",
    diagnostic: "429 synthetic quota exceeded",
    advice: "reached its rate limit",
  },
])(
  "retains incomplete worker $label diagnostics",
  async ({ diagnostic, advice, ...scenario }) => {
    const cause = Object.assign(new Error("Synthetic worker cause"), {
      code: "causeCode" in scenario ? scenario.causeCode : undefined,
    });
    const failure = new IncompleteScanError(`${diagnostic}; ${detail}`, {
      cause,
    });
    for (const json of [false, true]) {
      const { stdout, stderr, runCli } = createCliTest(main);
      const deps = dependencies({
        onTurn: (_repository, options) => {
          if ("storedApiKey" in scenario)
            options.onAuthentication?.({
              method: "stored_credentials",
              credentialType: "api_key",
              verified: false,
            });
        },
        onRun: () => {
          throw failure;
        },
      });
      expect(
        await runCli(["scan", ".", ...(json ? ["--json"] : [])], deps),
      ).toBe(2);
      const expected = `${diagnostic}; ${escapedSingleLineDetail}`;
      expect(stderr.text()).toContain(expected);
      if (advice === undefined) {
        expect(stderr.text()).not.toContain(
          "cannot access the configured model",
        );
      } else {
        expect(stderr.text()).toContain(advice);
        expect(stderr.text().split(advice)).toHaveLength(2);
      }
      expect(stderr.text()).not.toContain(controls);
      if (json) {
        const output = JSON.parse(stdout.text());
        expect(output).toMatchObject({ status: "failed", code: "SCAN_FAILED" });
        expect(output.message).toContain(expected);
        if (advice === undefined) {
          expect(output.message).not.toContain(
            "cannot access the configured model",
          );
        } else {
          expect(output.message).toContain(advice);
          expect(output.message.split(advice)).toHaveLength(2);
        }
      } else expect(stdout.text()).toBe("");
      expect(failure.message).toBe(`${diagnostic}; ${detail}`);
      expect(failure.cause).toBe(cause);
    }
  },
);

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
