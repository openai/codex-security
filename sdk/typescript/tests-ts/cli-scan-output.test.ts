import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import { beforeAll, describe, expect, mock, test } from "bun:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.js";
import type { ThreatModel } from "../src/models.js";
import { ScanResult } from "../src/result.js";
import { dependencies, fakePreflight, fakeResult } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";
import { throwing } from "./support/errors.js";

type CliOptions = Parameters<typeof dependencies>[0];

async function run(args: string[], options: CliOptions, expectedExit = 0) {
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(await runCli(args, dependencies(options)), stderr.text()).toBe(
    expectedExit,
  );
  return { stdout: stdout.text(), stderr: stderr.text() };
}

let validate: ValidateFunction;
beforeAll(async () => {
  const { stdout, stderr } = await run(["scan", "--schema", "--json"], {
    onConfig: throwing("Schema discovery must not prepare a runtime."),
  });
  expect(stderr).toBe("");
  const { output } = JSON.parse(stdout);
  validate = new Ajv2020({ strict: false }).compile(output);
});

async function scanJson(args: string[], options: CliOptions, expectedExit = 0) {
  const { stdout } = await run(["scan", ...args], options, expectedExit);
  const data = JSON.parse(stdout);
  expect(validate(data), JSON.stringify(validate.errors)).toBe(true);
  return data;
}

function outcomeOptions(outcome: string) {
  return {
    result: fakeResult(["high"]),
    preflight: fakePreflight(),
    onRun: () => {
      if (outcome === "failed") throw new Error("Synthetic failure.");
    },
  };
}

describe("scan output schema", () => {
  test("describes completed scans, preflight, and failure separately", async () => {
    expect(validate({})).toBe(false);
    await scanJson(["--json", "--dry-run", "--token-count"], {
      preflight: fakePreflight(),
    });
    expect(validate(-1)).toBe(false);
  });

  test.each(["partial", "unknown"] as const)(
    "accepts changed-target full-output errors with legacy %s coverage",
    async (completeness) => {
      const output = await scanJson(
        [".", "--json", "--full-output"],
        {
          onTurn: (_repository, options) => {
            options.onWarning?.("Synthetic target changed.", {
              kind: "target_changed",
            });
          },
          result: fakeResult(["high"], completeness),
        },
        2,
      );
      expect(output.ok).toBe(false);
      expect(output.error.code).toBe("SCAN_FAILED");
      expect(output.error.message).toContain("target changed");
      expect(output.data.manifest).toBeDefined();
    },
  );

  test.each([
    { mode: "standard", maxTimeMinutes: undefined },
    { mode: "standard", maxTimeMinutes: 2.5 },
    { mode: "deep", maxTimeMinutes: 5760 },
  ] as const)(
    "declares the optional positive time budget for $mode dry-run: $maxTimeMinutes",
    async ({ mode, maxTimeMinutes }) => {
      const output = await scanJson(
        [".", "--mode", mode, "--dry-run", "--json"],
        { preflight: { ...fakePreflight(), mode, maxTimeMinutes } },
      );
      for (const invalid of ["2.5", 0, -1]) {
        expect(validate({ ...output, maxTimeMinutes: invalid })).toBe(false);
      }
    },
  );

  test("describes the follow-up validation returned by a completed scan", async () => {
    const output = await scanJson([".", "--validate", "--json"], {
      currentDirectory: tmpdir(),
    });
    expect(output.validation).toEqual({ status: "complete", findings: 0 });
    expect(
      validate({
        ...output,
        validation: { status: "complete", findings: "0" },
      }),
    ).toBe(false);
  });

  test.each(["completed", "dry-run", "failed"] as const)(
    "accepts actual %s command output",
    async (outcome) => {
      const options = outcomeOptions(outcome);
      const data = await scanJson(
        [".", "--json", ...(outcome === "dry-run" ? ["--dry-run"] : [])],
        options,
        outcome === "failed" ? 2 : 0,
      );
      if (outcome === "completed") {
        expect(data).toMatchObject({
          findings: options.result.findings,
          reportPath: options.result.reportPath,
        });
      } else if (outcome === "dry-run") {
        expect(data).toMatchObject({ dryRun: true });
      } else {
        expect(data).toMatchObject({ status: "failed", code: "SCAN_FAILED" });
      }
    },
  );
});

const retainedThreatModels: (ThreatModel | null)[] = [
  null,
  { summary: "Synthetic component trust boundary", assets: ["synthetic data"] },
  { format: "markdown", content: "# Synthetic threat model\n" },
];

test.each(["absent", "saved", "failed"] as const)(
  "declares optional owner-suggestion fields for a %s result",
  async (outcome) => {
    const result = fakeResult();
    if (outcome === "saved")
      result.ownerSuggestionsPath = join(result.scanDir, "owners.json");
    if (outcome === "failed")
      result.ownerSuggestionsError = "Synthetic owner suggestion failure.";
    const data = await scanJson([".", "--json"], { result });
    expect(data).toEqual(result.toJSON());
    for (const field of ["ownerSuggestionsPath", "ownerSuggestionsError"]) {
      expect(validate({ ...data, [field]: "Synthetic optional value." })).toBe(
        true,
      );
      expect(validate({ ...data, [field]: 1 })).toBe(false);
    }
  },
);

test.each(retainedThreatModels)(
  "declares nullable threat-model fields from actual scan output: %j",
  async (threatModel) => {
    const original = fakeResult(["high"]);
    const result = new ScanResult({
      manifest: {
        ...original.manifest,
        scan: {
          ...original.manifest.scan,
          ...(threatModel === null ? {} : { threatModel }),
        },
      },
      findings: original.findings,
      mode: original.mode,
      review: original.review,
      scanDir: original.scanDir,
      threadId: original.threadId,
      turnResult: original.turnResult,
      threatModelPath:
        threatModel === null ? null : join(original.scanDir, "threatmodel.md"),
    });
    const data = await scanJson([".", "--json"], { result });
    expect(data).toMatchObject({
      threatModel,
      threatModelPath: result.threatModelPath,
    });
    expect(validate({ ...data, threatModel: "wrong object type" })).toBe(false);
    expect(validate({ ...data, threatModelPath: 1 })).toBe(false);
  },
);

test.each(["completed", "dry-run"] as const)(
  "accepts actual %s full-output success envelopes",
  async (outcome) => {
    for (const format of ["json", "jsonl"]) {
      const output = await scanJson(
        [
          ".",
          "--format",
          format,
          "--full-output",
          ...(outcome === "dry-run" ? ["--dry-run"] : []),
        ],
        outcomeOptions(outcome),
      );
      expect(output.ok).toBe(true);
      expect(validate({ ...output, data: {} })).toBe(false);
    }
  },
);

test.each(["completed", "dry-run", "failed", "argument-error"] as const)(
  "accepts token-truncated %s full-output envelopes",
  async (outcome) => {
    const failed = outcome === "failed" || outcome === "argument-error";
    for (const format of ["json", "jsonl"]) {
      for (const transform of ["--token-limit", "--token-offset"]) {
        const output = await scanJson(
          [
            ".",
            "--format",
            format,
            "--full-output",
            transform,
            "2",
            ...(outcome === "dry-run" ? ["--dry-run"] : []),
            ...(outcome === "argument-error" ? ["--mode", "bogus"] : []),
          ],
          outcomeOptions(outcome),
          failed ? 2 : 0,
        );
        expect(output.ok).toBe(!failed);
        if (failed) expect(output.error).toMatchObject({ code: "SCAN_FAILED" });
        else expect(typeof output.data).toBe("string");
      }
    }
  },
);

async function runInvalid(args: string[]) {
  const onConfig = mock(throwing("Invalid arguments reached the scanner."));
  const output = await run(args, { onConfig }, 2);
  expect(onConfig).not.toHaveBeenCalled();
  return output;
}

async function expectScanFailures(
  message: string,
  leadingArgs: readonly string[],
  trailingArgs: readonly string[] = [],
) {
  for (const fullOutput of [false, true]) {
    const { stdout, stderr } = await runInvalid([
      "scan",
      ...leadingArgs,
      ...(fullOutput ? ["--full-output"] : []),
      ...trailingArgs,
    ]);
    const value = JSON.parse(stdout);
    const error = fullOutput ? value.error : value;
    expect(error.code).toBe("SCAN_FAILED");
    expect(error.message).toContain(message);
    if (fullOutput) {
      expect(value.ok).toBe(false);
      expect(value).not.toHaveProperty("data");
    } else expect(value.status).toBe("failed");
    expect(stderr).toContain(message);
  }
}

describe("scan argument errors", () => {
  test.each([
    { args: ["--mode", "bogus"], message: "--mode" },
    { args: ["--max-cost", "0"], message: "--max-cost" },
    { args: ["--workers", "0"], message: "--workers" },
    { args: ["--patch-severity", "high"], message: "requires --patch" },
    { args: ["--path"], message: "Missing value" },
    { args: ["one", "two"], message: "Unexpected positional" },
    { args: ["--unknown-option"], message: "unknown-option" },
    { args: ["--token-limit", "bogus"], message: "--token-limit" },
  ])("returns structured failures for $args", async ({ args, message }) => {
    for (const format of [
      ["--json"],
      ["--format=json"],
      ["--format", "jsonl"],
    ]) {
      await expectScanFailures(message, ["--dry-run", ...format], args);
    }
  });

  test.each([
    { args: ["--format", "--json"] },
    { args: ["--json", "--format"] },
    { args: ["--format", "--format=jsonl"] },
    { args: ["--format=jsonl", "--format"] },
    { args: ["--format=", "--json"] },
    { args: ["--json", "--format="] },
    { args: ["--format", "bogus", "--json"] },
    { args: ["--json", "--format", "bogus"] },
  ])(
    "preserves structured errors around malformed format arguments: $args",
    ({ args }) => expectScanFailures("format", args),
  );

  test("prints concise flag names and accepted values for validation errors", async () => {
    for (const [args, flag, detail] of [
      [["--mode", "bogus"], "--mode", "standard"],
      [["--max-cost", "0"], "--max-cost", ">0"],
    ] as const) {
      const { stdout, stderr } = await runInvalid(["scan", ...args]);
      expect(stdout).toBe("");
      expect(stderr).toContain(flag);
      expect(stderr).toContain(detail);
      expect(stderr).not.toContain("Details:");
    }
  });

  test("uses the last output format and does not confuse import input with output", async () => {
    for (const args of [
      ["scan", "--json", "--format", "yaml", "--path"],
      ["scan", "import", "--json", "input.json", "--unknown-option"],
    ]) {
      const { stdout } = await runInvalid(args);
      expect(stdout).toBe("");
    }
  });
});

test.each([{ invalid: ["--mode", "bogus"] }, { invalid: ["--path"] }])(
  "JSON token options preserve scan argument diagnostics for $invalid",
  async ({ invalid }) => {
    for (const fullOutput of [false, true]) {
      for (const transform of [["--token-count"], ["--token-limit=2"]]) {
        const { stdout, stderr } = await runInvalid([
          "scan",
          "--json",
          ...(fullOutput ? ["--full-output"] : []),
          ...transform,
          ...invalid,
        ]);
        expect(stderr).toContain(invalid[0]!);
        const rendered = JSON.parse(stdout);
        if (fullOutput)
          expect(rendered).toMatchObject({
            ok: false,
            error: { code: "SCAN_FAILED" },
          });
        else if (transform[0] === "--token-count")
          expect(rendered).toBeGreaterThan(0);
        else expect(rendered).toContain("[truncated: showing tokens");
      }
    }
  },
);

test.each(["json", "full-output", "token-count"])(
  "negating a prefix --%s preserves scan positional validation",
  async (flag) => {
    const { stderr } = await runInvalid([
      `--${flag}`,
      "scan",
      ".",
      "second",
      `--no-${flag}`,
      "--headless",
    ]);

    expect(stderr).toContain("Unexpected positional argument for scan");
  },
);

test("output option negation and invalid token ranges never start a scan", async () => {
  for (const flag of ["--token-limit", "--token-offset"]) {
    const { stderr } = await runInvalid([
      "scan",
      ".",
      "--json",
      "--token-count",
      flag,
      "-1",
    ]);
    expect(stderr).toContain(`${flag} requires a nonnegative integer`);
  }

  const { stdout: compact } = await runInvalid([
    "scan",
    "--json",
    "--full-output",
    "--no-full-output",
    "--token-count",
    "--no-token-count",
    "--unknown-option",
  ]);
  expect(JSON.parse(compact).status).toBe("failed");

  const { stdout: plain } = await runInvalid([
    "scan",
    "--json",
    "--no-json",
    "--unknown-option",
  ]);
  expect(plain).toBe("");
});

test("recognizes scans preceded by the global JSON flag", async () => {
  const { stdout, stderr } = await runInvalid([
    "--json",
    "scan",
    "--unknown-option",
  ]);
  expect(stderr).toContain("unknown-option");
  expect(JSON.parse(stdout)).toMatchObject({
    status: "failed",
    code: "SCAN_FAILED",
  });
});
