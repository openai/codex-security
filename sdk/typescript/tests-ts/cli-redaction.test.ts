import { stripVTControlCharacters } from "node:util";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurityError } from "../src/errors.js";
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

  test.each([false, true])(
    "isolates concurrent scan error settings with full output %p",
    async (fullOutput) => {
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
              ["scan", ".", "--json", ...(fullOutput ? ["--full-output"] : [])],
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
          // Scan stderr already preserves the original failure message.
          expect(stderr.text()).toContain(message);
        }),
      );
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
