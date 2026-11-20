import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import { beforeAll, describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ScanResult } from "../src/result.js";
import type { ThreatModel } from "../src/models.js";
import {
  capture,
  dependencies,
  fakePreflight,
  fakeResult,
} from "./cli-fixtures.js";

let validate: ValidateFunction;
beforeAll(async () => {
  const stdout = capture();
  const stderr = capture();
  expect(
    await main(
      ["scan", "--schema", "--json"],
      stdout.stream,
      stderr.stream,
      dependencies({
        onConfig: () => {
          throw new Error("Schema discovery must not prepare a runtime.");
        },
      }),
    ),
  ).toBe(0);
  expect(stderr.text()).toBe("");
  const { output } = JSON.parse(stdout.text());
  validate = new Ajv2020({ strict: false }).compile(output);
});

async function scanJson(
  args: string[],
  options: Parameters<typeof dependencies>[0],
  expectedExit = 0,
) {
  const stdout = capture();
  const stderr = capture();
  const code = await main(
    ["scan", ...args],
    stdout.stream,
    stderr.stream,
    dependencies(options),
  );
  expect(code, stderr.text()).toBe(expectedExit);
  const data = JSON.parse(stdout.text());
  expect(validate(data), JSON.stringify(validate.errors)).toBe(true);
  return data;
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
      const result = fakeResult(["high"]);
      const data = await scanJson(
        [".", "--json", ...(outcome === "dry-run" ? ["--dry-run"] : [])],
        {
          result,
          preflight: fakePreflight(),
          onRun: () => {
            if (outcome === "failed") throw new Error("Synthetic failure.");
          },
        },
        outcome === "failed" ? 2 : 0,
      );
      if (outcome === "completed") {
        expect(data).toMatchObject({
          findings: result.findings,
          reportPath: result.reportPath,
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
        { result: fakeResult(["high"]), preflight: fakePreflight() },
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
          {
            result: fakeResult(["high"]),
            preflight: fakePreflight(),
            onRun: () => {
              if (outcome === "failed") throw new Error("Synthetic failure.");
            },
          },
          failed ? 2 : 0,
        );
        expect(output.ok).toBe(!failed);
        if (failed) expect(output.error).toMatchObject({ code: "SCAN_FAILED" });
        else expect(typeof output.data).toBe("string");
      }
    }
  },
);
