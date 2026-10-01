import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurityError, OutputDirectoryError } from "../src/errors.js";
import {
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";

describe("CLI log redaction", () => {
  test("documents the opt-out in scan help and its generated schema", async () => {
    const help = capture();
    expect(
      await main(
        ["scan", "--help"],
        help.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(help.text()).toContain("CODEX_SECURITY_REDACT_LOGS=0");

    const schema = capture();
    expect(
      await main(
        ["scan", "--schema", "--format", "json"],
        schema.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(schema.text())).toMatchObject({
      options: {
        properties: {
          verbose: {
            description: expect.stringContaining(
              "CODEX_SECURITY_REDACT_LOGS=0",
            ),
          },
        },
      },
    });
  });

  test.each([
    [false, false],
    [false, true],
    [true, false],
    [true, true],
  ])(
    "isolates concurrent scan error settings with full output %p and verbose %p",
    async (fullOutput, verbose) => {
      const message = "request failed: token=SYNTHETIC_LOG_VALUE";
      const selections = [undefined, "0", "1"];
      let started = 0;
      let release!: () => void;
      const allStarted = new Promise<void>((resolve) => {
        release = resolve;
      });

      await Promise.all(
        selections.map(async (value) => {
          const stdout = capture();
          const stderr = capture();
          const deps = dependencies({
            environment: { CODEX_SECURITY_REDACT_LOGS: value },
          });
          deps.createSecurity = () => ({
            run: async () => {
              started += 1;
              if (started === selections.length) release();
              await allStarted;
              throw new CodexSecurityError(message);
            },
            preflight: async () => fakePreflight(),
            close: async () => {},
          });

          expect(
            await main(
              [
                "scan",
                ".",
                "--json",
                ...(fullOutput ? ["--full-output"] : []),
                ...(verbose ? ["--verbose"] : []),
              ],
              stdout.stream,
              stderr.stream,
              deps,
            ),
          ).toBe(2);
          const output = JSON.parse(stdout.text());
          const expected = {
            code: "SCAN_FAILED",
            message: value === "0" ? message : "[redacted]",
          };
          if (fullOutput) {
            expect(output.ok).toBe(false);
            expect(output.error).toEqual(expected);
            expect(output).not.toHaveProperty("data");
          } else {
            expect(output).toEqual({ status: "failed", ...expected });
          }
          expect(stderr.text()).toContain(expected.message);
          expect(stderr.text().includes(message)).toBe(value === "0");
          expect(stderr.text().includes("codex-security: debug:")).toBe(
            verbose,
          );
        }),
      );
    },
  );

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
  ])("keeps verbosity and redaction independent for $name", async (mode) => {
    for (const value of [undefined, "0", "1"]) {
      const warning = "recoverable warning: token=SYNTHETIC_WARNING_VALUE";
      const observer = "observer failure: token=SYNTHETIC_OBSERVER_VALUE";
      const stdout = capture();
      const stderr = capture(mode.tty);
      const result = fakeResult([], "complete", {
        input_tokens: 200,
        cached_input_tokens: 20,
        output_tokens: 10,
      });
      const deps = dependencies({
        environment: {
          ...mode.environment,
          NO_COLOR: "1",
          CODEX_SECURITY_REDACT_LOGS: value,
        },
      });
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
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
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(
        await main(
          ["scan", ".", ...mode.args],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(0);
      const output = stripVTControlCharacters(stderr.text()).replace(
        /\s+/gu,
        " ",
      );
      const expectedWarning = value === "0" ? warning : "[redacted]";
      const expectedObserver = value === "0" ? observer : "[redacted]";
      expect(output).toContain(`codex-security: warning: ${expectedWarning}`);
      expect(output).toContain(
        `onWorkerStatus observer failed: ${expectedObserver}`,
      );
      expect(output.includes("SYNTHETIC_WARNING_VALUE")).toBe(value === "0");
      expect(output.includes("SYNTHETIC_OBSERVER_VALUE")).toBe(value === "0");
      expect(output.includes("codex-security: debug:")).toBe(mode.verbose);
      if (mode.verbose) {
        expect(output).toContain(
          `codex-security: debug: scan.warning message=${JSON.stringify(expectedWarning)}`,
        );
        expect(output).toContain(
          'authentication.selected requested="auto" method="api_key" source="OPENAI_API_KEY" verified=false',
        );
        expect(output).toContain("input_tokens=200 cached_input_tokens=20");
        expect(output).toContain(
          'scan.observer_failed observer="onWorkerStatus" classification="unknown"',
        );
      }
    }
  });

  test.each([undefined, "0", "1"])(
    "preserves target-warning result data with redaction setting %p",
    async (value) => {
      const warning = "Source changed: token=SYNTHETIC_TARGET_VALUE";
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({
        environment: { CODEX_SECURITY_REDACT_LOGS: value },
      });
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
          options?.onWarning?.(warning, { kind: "target_changed" });
          return fakeResult();
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });
      expect(
        await main(
          ["scan", ".", "--json", "--verbose"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      expect(JSON.parse(stdout.text()).warnings).toEqual([warning]);
      expect(stderr.text()).toContain(
        `codex-security: warning: ${value === "0" ? warning : "[redacted]"}`,
      );
      expect(stderr.text().includes("SYNTHETIC_TARGET_VALUE")).toBe(
        value === "0",
      );
    },
  );

  test.each([
    {
      name: "local",
      failure: new OutputDirectoryError(
        "Could not write results: token=SYNTHETIC_LOCAL_VALUE",
      ),
    },
    {
      name: "network",
      failure: new CodexSecurityError(
        "network failure ECONNRESET token=SYNTHETIC_NETWORK_VALUE",
      ),
    },
    {
      name: "timeout",
      failure: new CodexSecurityError(
        "request timed out token=SYNTHETIC_TIMEOUT_VALUE",
      ),
    },
  ])("applies redaction to $name scan failures", async ({ failure }) => {
    for (const value of [undefined, "0", "1"]) {
      const stdout = capture();
      const stderr = capture();
      const deps = dependencies({
        environment: { CODEX_SECURITY_REDACT_LOGS: value },
      });
      deps.createSecurity = () => ({
        run: async () => {
          throw failure;
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });
      expect(
        await main(
          ["scan", ".", "--json", "--verbose"],
          stdout.stream,
          stderr.stream,
          deps,
        ),
      ).toBe(2);
      const message = value === "0" ? failure.message : "[redacted]";
      expect(JSON.parse(stdout.text()).message).toBe(message);
      expect(stderr.text()).toContain(message);
      expect(stderr.text().includes(failure.message)).toBe(value === "0");
    }
  });

  test.each([
    "401 invalid API key for synthetic-organization token=SYNTHETIC_AUTH_VALUE",
    "403 forbidden for synthetic-organization token=SYNTHETIC_AUTH_VALUE",
  ])(
    "keeps authentication advice independent of redaction for %s",
    async (message) => {
      const outputs = [];
      for (const value of [undefined, "0"]) {
        const stdout = capture();
        const stderr = capture();
        const deps = dependencies({
          environment: { CODEX_SECURITY_REDACT_LOGS: value },
        });
        deps.createSecurity = () => ({
          run: async () => {
            throw new CodexSecurityError(message);
          },
          preflight: async () => fakePreflight(),
          close: async () => {},
        });
        expect(
          await main(
            ["scan", ".", "--json", "--verbose"],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        expect(stderr.text()).not.toContain("SYNTHETIC_AUTH_VALUE");
        expect(stderr.text()).not.toContain("synthetic-organization");
        outputs.push({ stdout: stdout.text(), stderr: stderr.text() });
      }
      expect(outputs[0]).toEqual(outputs[1]);
    },
  );

  test.each([undefined, "0"])(
    "applies environment value %p to live activity and observer messages",
    async (value) => {
      const activity = "command result: token=SYNTHETIC_ACTIVITY_VALUE";
      const observer = "observer result: token=SYNTHETIC_OBSERVER_VALUE";
      const stdout = capture();
      const stderr = capture(true);
      const deps = dependencies({
        environment: {
          NO_COLOR: "1",
          CODEX_SECURITY_REDACT_LOGS: value,
        },
      });
      deps.createSecurity = () => ({
        run: async (_repository, options) => {
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
        },
        preflight: async () => fakePreflight(),
        close: async () => {},
      });

      expect(
        await main(["scan", "."], stdout.stream, stderr.stream, deps),
      ).toBe(0);
      const output = stripVTControlCharacters(stderr.text()).replace(
        /\s+/gu,
        " ",
      );
      if (value === "0") {
        expect(output).toContain(activity);
        expect(output).toContain(observer);
        expect(output).not.toContain("[redacted]");
      } else {
        expect(output).toContain("[redacted]");
        expect(output).not.toContain("SYNTHETIC_ACTIVITY_VALUE");
        expect(output).not.toContain("SYNTHETIC_OBSERVER_VALUE");
      }
      expect(stderr.text()).toContain("\u001B[?1049h");
      expect(stderr.text()).toContain("\u001B[?1049l");
    },
  );
});
