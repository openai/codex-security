import { describe, expect, test } from "bun:test";
import Ajv2020 from "ajv/dist/2020.js";
import { main } from "../src/cli.js";
import { CodexSecurityError } from "../src/index.js";
import {
  FakeSignals,
  SYNTHETIC_CREDENTIALS,
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";
import { captureCli, createCliTest } from "./support/cli-run.js";

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

function failingScan(message: string, onRun?: () => void) {
  const deps = scanDependencies();
  deps.createSecurity = () => ({
    run: async () => {
      onRun?.();
      throw new CodexSecurityError(message);
    },
    validate: async () => {
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
  data?: unknown,
) {
  const result = JSON.parse(text);
  if (fullOutput) {
    expect(result.ok).toBe(false);
    expect(result.error).toEqual({ code, message });
    if (data === undefined) expect(result).not.toHaveProperty("data");
    else expect(result.data).toEqual(data);
  } else {
    expect(result).toEqual({ status: "failed", code, message });
  }
}

for (const flags of [["--json"], ["--format", "jsonl", "--full-output"]]) {
  describe(`scan failures with ${flags.join(" ")}`, () => {
    const fullOutput = flags.includes("--full-output");

    test.each(commands)(
      "formats %s execution failures consistently",
      async (_name, command) => {
        const { stdout, stderr, runCli } = createCliTest(main);
        const message = `network failure ECONNRESET ${SYNTHETIC_CREDENTIALS}`;
        expect(await runCli([...command, ...flags], failingScan(message))).toBe(
          2,
        );
        expectFailure(stdout.text(), fullOutput, "SCAN_FAILED", message);
        expect(stderr.text()).toContain(`${message}\n`);
      },
    );

    test.each([
      ["rerun", "SCAN_REPLAY_UNAVAILABLE"],
      ["resume", "SCAN_RESUME_UNAVAILABLE"],
    ])("preserves %s preparation failure codes", async (command, code) => {
      const { stdout, stderr, runCli } = createCliTest(main);
      const message = "This scan does not have a saved launch recipe.";
      const deps = scanDependencies();
      deps.runWorkbench = async () => ({
        scanId: "saved-scan",
        scanDir: "/tmp/saved-scan",
      });
      expect(
        await runCli(["scans", command, "saved-scan", ...flags], deps),
      ).toBe(2);
      expectFailure(stdout.text(), fullOutput, code, message);
      expect(stderr.text()).toBe(`codex-security: ${message}\n`);
    });

    test("reports unavailable latest scans with the replay failure code", async () => {
      const { stdout, stderr, runCli } = createCliTest(main);
      const deps = scanDependencies();
      deps.runWorkbench = async () => ({ scans: [] });
      expect(await runCli(["scans", "rerun", ...flags], deps)).toBe(2);
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
        const { stdout, stderr, runCli } = createCliTest(main);
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
          await runCli(["scans", "rerun", "saved-scan", ...flags], deps),
        ).toBe(2);
        expectFailure(stdout.text(), fullOutput, "SCAN_IMPORT_FAILED", message);
        expect(stderr.text()).toBe(`codex-security: ${message}\n`);
      },
    );
  });
}

test.each(commands)(
  "preserves successful %s JSON output",
  async (_name, command) => {
    const stdout = captureCli(main, "stdout");
    expect(await stdout.run([...command, "--json"], scanDependencies())).toBe(
      0,
    );
    expect(JSON.parse(stdout.text())).toEqual(fakeResult().toJSON());
  },
);

test.each(commands)(
  "keeps non-JSON %s failures on stderr",
  async (_name, command) => {
    for (const flags of [[], ["--full-output"], ["--format", "yaml"]]) {
      const { stdout, stderr, runCli } = createCliTest(main);
      const message = "The scan could not save its results.";
      expect(await runCli([...command, ...flags], failingScan(message))).toBe(
        2,
      );
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
        const stdout = captureCli(main, "stdout");
        const signals = new FakeSignals();
        const result = fakeResult();
        const deps = dependencies({
          result,
          signals,
          onRun: () => signals.emit(signal),
        });
        deps.runWorkbench = scanDependencies().runWorkbench;
        expect(
          await stdout.run(
            [...command, "--json", ...(fullOutput ? ["--full-output"] : [])],
            deps,
          ),
        ).toBe(exitCode);
        expectFailure(
          stdout.text(),
          fullOutput,
          "SCAN_FAILED",
          message,
          fullOutput ? result.toJSON() : undefined,
        );
      }
    }
  },
);

test("retains diagnostics when the latest-scan working directory is unavailable", async () => {
  for (const flags of [[], ["--json"], ["--json", "--full-output"]]) {
    const { stdout, stderr, runCli } = createCliTest(main);
    const deps = scanDependencies();
    const message = "The working directory is unavailable.";
    deps.currentDirectory = () => {
      throw new Error(message);
    };
    expect(await runCli(["scans", "rerun", ...flags], deps)).toBe(2);
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
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run([...command, "--schema", "--json"], dependencies()),
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

test.each(commands.slice(1))(
  "preserves diagnostics and token controls for filtered %s failures",
  async (_name, command) => {
    const message =
      "Synthetic saved scan failure with its complete diagnostic.";
    for (const formatArgs of [["--json"], ["--format", "jsonl"]]) {
      for (const tokens of [
        [],
        ["--token-count"],
        ["--token-limit", "4"],
        ["--token-offset=4", "--token-limit=4"],
      ]) {
        const reference = capture();
        expect(
          await main(
            [...command, ...formatArgs, ...tokens],
            reference.stream,
            capture().stream,
            failingScan(message),
          ),
        ).toBe(2);
        for (const filter of [
          ["--filter-output", "manifest,findings"],
          ["--filter-output=manifest,findings"],
          ["--filter-output", "findings"],
          ["--filter-output=manifest"],
        ]) {
          const { stdout, stderr, runCli } = createCliTest(main);
          let runs = 0;
          expect(
            await runCli(
              [...command, ...formatArgs, ...filter, ...tokens],
              failingScan(message, () => runs++),
            ),
          ).toBe(2);
          expect(runs).toBe(1);
          expect(stdout.text()).toBe(reference.text());
          expect(stderr.text()).toContain(message);
        }
      }
    }
  },
);

test.each(["rerun", "resume"])(
  "preserves filtered %s preparation failures",
  async (command) => {
    const stdout = captureCli(main, "stdout");
    const deps = scanDependencies();
    deps.runWorkbench = async () => ({
      scanId: "saved-scan",
      scanDir: "/tmp/saved-scan",
    });
    expect(
      await stdout.run(
        [
          "scans",
          command,
          "saved-scan",
          "--json",
          "--filter-output",
          "manifest,findings",
        ],
        deps,
      ),
    ).toBe(2);
    expectFailure(
      stdout.text(),
      false,
      command === "rerun"
        ? "SCAN_REPLAY_UNAVAILABLE"
        : "SCAN_RESUME_UNAVAILABLE",
      "This scan does not have a saved launch recipe.",
    );
  },
);

test.each(commands.slice(1))(
  "preserves success filtering and full error envelopes for %s",
  async (_name, command) => {
    const success = capture();
    expect(
      await main(
        [...command, "--json", "--filter-output", "manifest,findings"],
        success.stream,
        capture().stream,
        scanDependencies(),
      ),
    ).toBe(0);
    const original = fakeResult().toJSON();
    expect(JSON.parse(success.text())).toEqual({
      manifest: original["manifest"],
      findings: original["findings"],
    });
    const failure = capture();
    const message = "Synthetic full envelope failure.";
    expect(
      await main(
        [
          ...command,
          "--json",
          "--full-output",
          "--filter-output",
          "manifest,findings",
        ],
        failure.stream,
        capture().stream,
        failingScan(message),
      ),
    ).toBe(2);
    expectFailure(failure.text(), true, "SCAN_FAILED", message);
  },
);

for (const command of ["rerun", "resume"]) {
  test.each([true, false, undefined])(
    `${command} restores owner suggestions from its saved recipe (%p)`,
    async (ownerSuggestions) => {
      let observed: boolean | undefined;
      let called = false;
      const deps = dependencies({
        onWorkbench: () => ({
          scanId: "saved-scan",
          scanDir: "/tmp/saved-scan",
          recipe: {
            repository: "/original/repository",
            target: { kind: "repository", paths: [] },
            mode: "deep",
            config: {},
            ...(ownerSuggestions === undefined ? {} : { ownerSuggestions }),
          },
        }),
        onTurn: (_repository, options) => {
          called = true;
          observed = options.ownerSuggestions;
        },
      });
      const { runCli } = createCliTest(main);
      expect(
        await runCli(["scans", command, "saved-scan", "--json"], deps),
      ).toBe(0);
      expect(called).toBe(true);
      expect(observed).toBe(ownerSuggestions);
    },
  );
}

test("scan discovery accepts caller inputs and validates the reported result variants", async () => {
  const { stdout, runCli } = createCliTest(main);
  expect(await runCli(["scan", "--schema", "--json"], dependencies())).toBe(0);
  const { options, output } = JSON.parse(stdout.text());
  const ajv = new Ajv2020({ strict: false });
  const inputs = ajv.compile(options);
  expect(inputs({ dryRun: true })).toBe(true);
  expect(inputs({ maxCost: "not a number" })).toBe(false);
  const data = ajv.compile(output);
  expect(data({ dryRun: true, ...fakePreflight() })).toBe(true);
  expect(data(JSON.parse(JSON.stringify(fakeResult(["high"]).toJSON())))).toBe(
    true,
  );
  expect(
    data({ status: "failed", code: "SCAN_FAILED", message: "Example" }),
  ).toBe(true);
  const retained = fakeResult(["medium"]);
  expect(
    data({
      mode: retained.mode,
      manifest: retained.manifest,
      findings: retained.findings,
      review: retained.review,
      scanDir: retained.scanDir,
      reportPath: retained.reportPath,
    }),
  ).toBe(true);
  expect(data({})).toBe(false);
  expect(data({ status: "failed", code: 0, message: 42 })).toBe(false);
});

test.each([
  { args: ["--max-cost"] },
  { args: ["--format"] },
  { args: ["--format", "--json"] },
  { args: ["--token-limit", "--json"] },
  { args: ["--max-cost", "invalid"] },
  { args: ["--path", "src", "--diff", "HEAD"] },
  { args: ["--token-limit", "invalid"] },
])(
  "returns a JSON error envelope for invalid scan arguments %j",
  async ({ args }) => {
    for (const flags of [["--format=jsonl"], ["--json"]]) {
      const { stdout, stderr, runCli } = createCliTest(main);
      expect(
        await runCli(
          ["scan", ".", "--dry-run", "--full-output", ...flags, ...args],
          dependencies(),
        ),
      ).toBe(2);
      const result = JSON.parse(stdout.text());
      expect(stderr.text()).toContain(result.error.message.split("\n")[0]);
      expect(result).toMatchObject({
        ok: false,
        error: { code: expect.any(String), message: expect.any(String) },
      });
    }
  },
);
