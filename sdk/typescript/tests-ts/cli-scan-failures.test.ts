import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { CodexSecurityError } from "../src/index.js";
import {
  FakeSignals,
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";

const commands = [
  ["scan", ["scan", "."]],
  ["rerun", ["scans", "rerun", "saved-scan"]],
  ["resume", ["scans", "resume", "saved-scan"]],
] as const;

function scanDependencies() {
  return dependencies({
    onWorkbench: () => ({
      scanId: "saved-scan",
      scanDir: "/tmp/saved-scan",
      recipe: {
        repository: "/original/repository",
        target: { kind: "repository", paths: [] },
        mode: "standard",
        config: {},
      },
    }),
  });
}

function failingScan(message: string) {
  const deps = scanDependencies();
  deps.createSecurity = () => ({
    run: async () => {
      throw new CodexSecurityError(message);
    },
    preflight: async () => fakePreflight(),
    close: async () => {},
  });
  return deps;
}

function expectFailure(
  text: string,
  fullOutput: boolean,
  code: string,
  message: string,
) {
  const result = JSON.parse(text);
  if (fullOutput) {
    expect(result).toMatchObject({ ok: false, error: { code, message } });
    expect(result).not.toHaveProperty("data");
  } else {
    expect(result).toEqual({ status: "failed", code, message });
  }
}

for (const formatArgs of [
  ["--json"],
  ["--format", "json"],
  ["--format", "jsonl"],
]) {
  for (const fullOutput of [false, true]) {
    describe(`scan failures with ${formatArgs.join(" ")}${fullOutput ? " --full-output" : ""}`, () => {
      const flags = [...formatArgs, ...(fullOutput ? ["--full-output"] : [])];

      test.each(commands)(
        "formats %s execution failures consistently",
        async (_name, command) => {
          const stdout = capture();
          const stderr = capture();
          const message = "The scan could not save its results.";
          expect(
            await main(
              [...command, ...flags],
              stdout.stream,
              stderr.stream,
              failingScan(message),
            ),
          ).toBe(2);
          expectFailure(stdout.text(), fullOutput, "SCAN_FAILED", message);
          expect(stderr.text()).toContain(`${message}\n`);
        },
      );

      test.each([
        ["rerun", "SCAN_REPLAY_UNAVAILABLE"],
        ["resume", "SCAN_RESUME_UNAVAILABLE"],
      ])("preserves %s preparation failure codes", async (command, code) => {
        const stdout = capture();
        const stderr = capture();
        const message = "This scan does not have a saved launch recipe.";
        const deps = scanDependencies();
        deps.runWorkbench = async () => ({
          scanId: "saved-scan",
          scanDir: "/tmp/saved-scan",
        });
        expect(
          await main(
            ["scans", command, "saved-scan", ...flags],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        expectFailure(stdout.text(), fullOutput, code, message);
        expect(stderr.text()).toBe(`codex-security: ${message}\n`);
      });

      test("reports unavailable latest scans with the replay failure code", async () => {
        const stdout = capture();
        const stderr = capture();
        const deps = scanDependencies();
        deps.runWorkbench = async () => ({ scans: [] });
        expect(
          await main(
            ["scans", "rerun", ...flags],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        const message = "No completed scans found for the current repository.";
        expectFailure(
          stdout.text(),
          fullOutput,
          "SCAN_REPLAY_UNAVAILABLE",
          message,
        );
        expect(stderr.text()).toBe(`codex-security: ${message}\n`);
      });

      test.each(["csv", "json"])(
        "formats rerun failures independently of the %s import format",
        async (format) => {
          const stdout = capture();
          const stderr = capture();
          const message = "The saved import source is unavailable.";
          const deps = scanDependencies();
          deps.runWorkbench = async () => ({
            recipe: {
              import: { sourcePath: `/tmp/findings.${format}`, format },
            },
          });
          deps.importScan = async () => {
            throw new CodexSecurityError(message);
          };
          expect(
            await main(
              ["scans", "rerun", "saved-scan", ...flags],
              stdout.stream,
              stderr.stream,
              deps,
            ),
          ).toBe(2);
          expectFailure(
            stdout.text(),
            fullOutput,
            "SCAN_IMPORT_FAILED",
            message,
          );
          expect(stderr.text()).toBe(`codex-security: ${message}\n`);
        },
      );

      test.each(commands)(
        "preserves diagnostic text for %s failures",
        async (_name, command) => {
          const stdout = capture();
          const stderr = capture();
          const message =
            "network failure ECONNRESET Bearer SYNTHETIC_TOKEN_123";
          expect(
            await main(
              [...command, ...flags],
              stdout.stream,
              stderr.stream,
              failingScan(message),
            ),
          ).toBe(2);
          expectFailure(stdout.text(), fullOutput, "SCAN_FAILED", message);
          expect(stderr.text()).toContain(message);
        },
      );
    });
  }
}

test.each(commands)(
  "preserves successful %s JSON output",
  async (_name, command) => {
    const stdout = capture();
    expect(
      await main(
        [...command, "--json"],
        stdout.stream,
        capture().stream,
        scanDependencies(),
      ),
    ).toBe(0);
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
  },
);

test.each(commands)(
  "keeps non-JSON %s failures on stderr",
  async (_name, command) => {
    for (const flags of [[], ["--full-output"], ["--format", "yaml"]]) {
      const stdout = capture();
      const stderr = capture();
      const message = "The scan could not save its results.";
      expect(
        await main(
          [...command, ...flags],
          stdout.stream,
          stderr.stream,
          failingScan(message),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(`${message}\n`);
    }
  },
);

test.each(commands)(
  "retains %s cancellation exit codes",
  async (_name, command) => {
    for (const [signal, exitCode, message] of [
      ["SIGINT", 130, "Scan canceled by Ctrl-C."],
      ["SIGTERM", 143, "Scan terminated by SIGTERM."],
    ] as const) {
      for (const fullOutput of [false, true]) {
        const stdout = capture();
        const signals = new FakeSignals();
        const deps = dependencies({
          signals,
          onRun: () => signals.emit(signal),
        });
        deps.runWorkbench = scanDependencies().runWorkbench;
        expect(
          await main(
            [...command, "--json", ...(fullOutput ? ["--full-output"] : [])],
            stdout.stream,
            capture().stream,
            deps,
          ),
        ).toBe(exitCode);
        expectFailure(stdout.text(), fullOutput, "SCAN_FAILED", message);
      }
    }
  },
);

test("retains diagnostics when the latest-scan working directory is unavailable", async () => {
  for (const flags of [[], ["--json"], ["--json", "--full-output"]]) {
    const stdout = capture();
    const stderr = capture();
    const deps = scanDependencies();
    const message = "The working directory is unavailable.";
    deps.currentDirectory = () => {
      throw new Error(message);
    };
    expect(
      await main(
        ["scans", "rerun", ...flags],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toBe(`codex-security: ${message}\n`);
    if (flags.length === 0) expect(stdout.text()).toBe("");
    else
      expectFailure(
        stdout.text(),
        flags.includes("--full-output"),
        "SCAN_REPLAY_UNAVAILABLE",
        message,
      );
  }
});

test.each([
  [["scan"], ["SCAN_FAILED"]],
  [
    ["scans", "rerun"],
    ["SCAN_FAILED", "SCAN_REPLAY_UNAVAILABLE", "SCAN_IMPORT_FAILED"],
  ],
  [
    ["scans", "resume"],
    ["SCAN_FAILED", "SCAN_RESUME_UNAVAILABLE"],
  ],
])(
  "documents failure codes in the %j output schema",
  async (command, codes) => {
    const stdout = capture();
    expect(
      await main(
        [...command, "--schema", "--json"],
        stdout.stream,
        capture().stream,
        dependencies(),
      ),
    ).toBe(0);
    const schema = JSON.parse(stdout.text());
    const failure = schema.output.anyOf.find(
      (variant: { properties?: { status?: { const?: string } } }) =>
        variant.properties?.status?.const === "failed",
    );
    expect(failure.required).toEqual(["status", "code", "message"]);
    expect(
      failure.properties.code.enum ?? [failure.properties.code.const],
    ).toEqual(codes);
  },
);
