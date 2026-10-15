import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurityError, OutputDirectoryError } from "../src/errors.js";
import {
  warningResult,
  dependencies,
  fakeResult,
  fakeSecurity,
} from "./cli-fixtures.js";
import { throwing } from "./support/errors.js";

import { createCliTest } from "./support/cli-run.js";

describe("CLI diagnostics", () => {
  test.each([
    {
      command: "policy",
      args: ["policy", "--json", "--full-output"],
      structured: true,
    },
    {
      command: "suggest-owners",
      args: ["suggest-owners", "findings.json"],
      structured: false,
    },
    {
      command: "classify-severity",
      args: ["classify-severity", "--scan", "latest"],
      structured: false,
    },
    {
      command: "dedupe",
      args: [
        "dedupe",
        "--scan",
        "latest",
        "--findings-url",
        "https://example.test/findings",
      ],
      structured: false,
    },
    {
      command: "verify-fix",
      args: ["verify-fix", "Synthetic finding"],
      structured: false,
    },
    {
      command: "patch",
      args: ["patch", "Synthetic finding", "--json"],
      structured: true,
    },
    {
      command: "scan import",
      args: ["--json", "scan", "import", "--csv", "findings.csv"],
      structured: false,
    },
    {
      command: "GitHub import",
      args: ["import", "github", "example/repository"],
      structured: false,
    },
  ])(
    "escapes terminal controls in $command failures while preserving details",
    async ({ command, args, structured }) => {
      const message =
        "Operation failed: token=SYNTHETIC_VALUE\u001b[2J\ncontinued\r\ttail";
      const fail = throwing(message);
      const deps = dependencies({ onCodex: fail, onRepositoryCommand: fail });
      deps.classifyScanSeverity = fail;
      deps.deduplicateScan = fail;
      deps.importScan = fail;
      deps.importGitHubAlerts = fail;
      if (command === "policy" || command === "suggest-owners")
        deps.currentDirectory = fail;
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(await runCli(args, deps)).toBe(2);
      expect(stderr.text()).toContain(
        "codex-security: Operation failed: token=SYNTHETIC_VALUE [2J continued  tail\n",
      );
      expect(stderr.text()).not.toContain("\u001b");
      if (structured) {
        const result = JSON.parse(stdout.text());
        expect(result.error?.message ?? result.message).toBe(message);
      }
    },
  );

  for (const failure of [
    new CodexSecurityError("token budget exceeded"),
    new CodexSecurityError("basic validation failed"),
    new OutputDirectoryError(
      "Could not write results: token=SYNTHETIC_LOCAL_VALUE",
    ),
    new CodexSecurityError("request timed out token=SYNTHETIC_TIMEOUT_VALUE"),
  ]) {
    test(`preserves scan failure details for ${failure.message}`, async () => {
      const { stdout, stderr, runCli } = createCliTest(main);

      const deps = dependencies();
      deps.createSecurity = () =>
        fakeSecurity((Promise.reject<never>).bind(Promise, failure));

      expect(await runCli(["scan", ".", "--json", "--verbose"], deps)).toBe(2);
      expect(JSON.parse(stdout.text()).message).toBe(failure.message);
      expect(stderr.text()).toContain(failure.message);
    });
  }

  test.each([
    { name: "dashboard", args: [], environment: {}, tty: true, verbose: false },
    { name: "plain", args: [], environment: {}, tty: false, verbose: false },
    {
      name: "headless",
      args: ["--headless"],
      environment: {},
      tty: true,
      verbose: false,
    },
    {
      name: "verbose flag",
      args: ["--verbose"],
      environment: {},
      tty: true,
      verbose: true,
    },
    {
      name: "debug environment",
      args: [],
      environment: { CODEX_SECURITY_LOG_LEVEL: "  DeBuG  " },
      tty: true,
      verbose: true,
    },
    {
      name: "shared debug fallback",
      args: [],
      environment: { CODEX_SECURITY_LOG_LEVEL: " ", LOG_LEVEL: " DEBUG " },
      tty: false,
      verbose: true,
    },
    {
      name: "dedicated level precedence",
      args: [],
      environment: { CODEX_SECURITY_LOG_LEVEL: "info", LOG_LEVEL: "debug" },
      tty: false,
      verbose: false,
    },
    {
      name: "verbose flag precedence",
      args: ["--verbose"],
      environment: { CODEX_SECURITY_LOG_LEVEL: "error", LOG_LEVEL: "warn" },
      tty: false,
      verbose: true,
    },
  ])("preserves warning details and verbosity for $name", async (mode) => {
    const warning = "recoverable warning: token=SYNTHETIC_WARNING_VALUE";
    const observer = "observer failure: token=SYNTHETIC_OBSERVER_VALUE";
    const { stderr, runCli } = createCliTest(main, {
      stderr: mode.tty,
    });

    const result = fakeResult([], "complete", {
      input_tokens: 200,
      cached_input_tokens: 20,
      output_tokens: 10,
    });
    const deps = dependencies({
      environment: { ...mode.environment, NO_COLOR: "1" },
    });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onAuthentication?.({
          method: "api_key",
          source: "OPENAI_API_KEY",
          verified: false,
        });
        options?.onScanStarted?.();
        options?.onCost?.(result.cost!);
        options?.onWarning?.(warning);
        options?.onObserverError?.("onWorkerStatus", new Error(observer));
        return result;
      });

    expect(await runCli(["scan", ".", ...mode.args], deps)).toBe(0);
    const output = stripVTControlCharacters(stderr.text()).replace(
      /\s+/gu,
      " ",
    );
    expect(output).toContain(`codex-security: warning: ${warning}`);
    expect(output).toContain(`onWorkerStatus observer failed: ${observer}`);
    expect(output.includes("codex-security: debug:")).toBe(mode.verbose);
    if (mode.verbose) {
      expect(output).toContain(
        `codex-security: debug: scan.warning message=${JSON.stringify(warning)}`,
      );
      expect(output).toContain(
        'authentication.selected requested="auto" method="api_key" source="OPENAI_API_KEY" verified=false',
      );
      expect(output).toContain("input_tokens=200 cached_input_tokens=20");
      expect(output).toContain(
        'scan.observer_failed observer="onWorkerStatus" classification="unknown"',
      );
    }
  });

  test("preserves target warning details in diagnostics and result data", async () => {
    const warning = "Source changed: token=SYNTHETIC_TARGET_VALUE";
    const { stdout, stderr, runCli } = createCliTest(main);

    const deps = dependencies();
    deps.createSecurity = () => fakeSecurity(warningResult(warning, true));
    expect(await runCli(["scan", ".", "--json", "--verbose"], deps)).toBe(2);
    expect(JSON.parse(stdout.text()).warnings).toEqual([warning]);
    expect(stderr.text()).toContain(`codex-security: warning: ${warning}`);
  });

  test("preserves live activity and observer messages", async () => {
    const activity = "command result: token=SYNTHETIC_ACTIVITY_VALUE";
    const observer = "observer result: token=SYNTHETIC_OBSERVER_VALUE";
    const { stderr, runCli } = createCliTest(main, { stderr: true });

    const deps = dependencies({ environment: { NO_COLOR: "1" } });
    deps.createSecurity = () =>
      fakeSecurity(async (_repository, options) => {
        options?.onScanStarted?.();
        options?.onActivity?.({
          id: "synthetic-command",
          kind: "command",
          status: "completed",
          description: activity,
          paths: [],
        });
        options?.onObserverError?.("onWorkerStatus", new Error(observer));
        return fakeResult();
      });

    expect(await runCli(["scan", "."], deps)).toBe(0);
    const output = stripVTControlCharacters(stderr.text()).replace(
      /\s+/gu,
      " ",
    );
    expect(output).toContain(activity);
    expect(output).toContain(observer);
    expect(stderr.text()).toContain("\u001B[?1049h");
    expect(stderr.text()).toContain("\u001B[?1049l");
  });
});
