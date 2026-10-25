import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, test } from "bun:test";
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

async function scanOutputSchema() {
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
  return (JSON.parse(stdout.text()) as { output: object }).output;
}

describe("scan output schema", () => {
  test("describes completed scans, preflight, and failure separately", async () => {
    const schema = await scanOutputSchema();
    expect(schema).toMatchObject({
      anyOf: [
        {
          properties: {
            findings: { type: "object" },
            coverage: { type: "object" },
            scanDir: { type: "string" },
            reportPath: { type: "string" },
          },
        },
        {
          properties: {
            dryRun: { const: true },
            mode: { enum: ["standard", "deep"] },
            workers: { type: "integer" },
            authentication: { type: "object" },
          },
        },
        { properties: { code: { const: "SCAN_FAILED" } } },
        {
          properties: {
            ok: { const: false },
            error: { anyOf: [{ type: "object" }, { type: "string" }] },
          },
        },
        {
          properties: {
            ok: { const: true },
          },
        },
      ],
    });
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate({})).toBe(false);
  });

  test.each(["partial", "unknown"] as const)(
    "accepts changed-target full-output errors with legacy %s coverage",
    async (completeness) => {
      const validate = new Ajv2020({ strict: false }).compile(
        await scanOutputSchema(),
      );
      for (const format of ["json", "jsonl"]) {
        for (const filter of [undefined, "warnings", "findings"]) {
          const stdout = capture();
          const deps = dependencies({
            onTurn: (_repository, options) => {
              options.onWarning?.("Synthetic target changed.", {
                kind: "target_changed",
              });
            },
            result: fakeResult(["high"], completeness),
          });
          expect(
            await main(
              [
                "scan",
                ".",
                "--format",
                format,
                "--full-output",
                ...(filter === undefined ? [] : ["--filter-output", filter]),
              ],
              stdout.stream,
              capture().stream,
              deps,
            ),
          ).toBe(2);
          const output: unknown = JSON.parse(stdout.text());
          expect(output).toMatchObject({
            ok: false,
            error: { code: "SCAN_FAILED" },
          });
          expect(validate(output), JSON.stringify(validate.errors)).toBe(true);
        }
      }
    },
  );

  test.each([
    { mode: "standard", maxTimeMinutes: undefined },
    { mode: "standard", maxTimeMinutes: 2.5 },
    { mode: "deep", maxTimeMinutes: 5760 },
  ] as const)(
    "declares the optional positive time budget for $mode dry-run: $maxTimeMinutes",
    async ({ mode, maxTimeMinutes }) => {
      const schema = await scanOutputSchema();
      const validate = new Ajv2020({ strict: false }).compile(schema);
      const stdout = capture();
      expect(
        await main(
          ["scan", ".", "--mode", mode, "--dry-run", "--json"],
          stdout.stream,
          capture().stream,
          dependencies({
            preflight: { ...fakePreflight(), mode, maxTimeMinutes },
          }),
        ),
      ).toBe(0);
      const output = JSON.parse(stdout.text());
      expect(validate(output), JSON.stringify(validate.errors)).toBe(true);
      for (const invalid of ["2.5", 0, -1]) {
        expect(validate({ ...output, maxTimeMinutes: invalid })).toBe(false);
      }
    },
  );

  test("describes the follow-up validation returned by a completed scan", async () => {
    const validate = new Ajv2020({ strict: false }).compile(
      await scanOutputSchema(),
    );
    const stdout = capture();
    expect(
      await main(
        ["scan", ".", "--validate", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({ currentDirectory: tmpdir() }),
      ),
    ).toBe(0);
    const output = JSON.parse(stdout.text());
    expect(output.validation).toEqual({ status: "complete", findings: 0 });
    expect(validate(output), JSON.stringify(validate.errors)).toBe(true);
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
      const validate = new Ajv2020({ strict: false }).compile(
        await scanOutputSchema(),
      );
      const stdout = capture();
      const result = fakeResult(["high"]);
      const code = await main(
        [
          "scan",
          ".",
          "--json",
          ...(outcome === "dry-run" ? ["--dry-run"] : []),
        ],
        stdout.stream,
        capture().stream,
        dependencies({
          result,
          preflight: fakePreflight(),
          onRun: () => {
            if (outcome === "failed") throw new Error("Synthetic failure.");
          },
        }),
      );
      expect(code).toBe(outcome === "failed" ? 2 : 0);
      const data: unknown = JSON.parse(stdout.text());
      expect(validate(data), JSON.stringify(validate.errors)).toBe(true);
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
    const schema = await scanOutputSchema();
    const result = fakeResult();
    if (outcome === "saved")
      result.ownerSuggestionsPath = join(result.scanDir, "owners.json");
    if (outcome === "failed")
      result.ownerSuggestionsError = "Synthetic owner suggestion failure.";
    const stdout = capture();
    expect(
      await main(
        ["scan", ".", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({ result }),
      ),
    ).toBe(0);
    const data = JSON.parse(stdout.text());
    expect(data).toEqual(result.toJSON());
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate(data), JSON.stringify(validate.errors)).toBe(true);
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
    const schema = await scanOutputSchema();
    expect(schema).toMatchObject({
      anyOf: [
        {
          properties: {
            threatModel: { anyOf: [{ type: "object" }, { type: "null" }] },
            threatModelPath: { type: ["string", "null"] },
          },
        },
        {},
        {},
        {},
        {},
      ],
    });
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
      coverage: original.coverage,
      scanDir: original.scanDir,
      threadId: original.threadId,
      turnResult: original.turnResult,
      threatModelPath:
        threatModel === null ? null : join(original.scanDir, "threatmodel.md"),
    });
    const stdout = capture();
    expect(
      await main(
        ["scan", ".", "--json"],
        stdout.stream,
        capture().stream,
        dependencies({ result }),
      ),
    ).toBe(0);
    const data = JSON.parse(stdout.text()) as Record<string, unknown>;
    expect(data).toMatchObject({
      threatModel,
      threatModelPath: result.threatModelPath,
    });
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate(data), JSON.stringify(validate.errors)).toBe(true);
    expect(validate({ ...data, threatModel: "wrong object type" })).toBe(false);
    expect(validate({ ...data, threatModelPath: 1 })).toBe(false);
  },
);

test.each(["completed", "dry-run"] as const)(
  "accepts actual %s full-output success envelopes",
  async (outcome) => {
    const validate = new Ajv2020({ strict: false }).compile(
      await scanOutputSchema(),
    );
    for (const format of ["json", "jsonl"]) {
      const stdout = capture();
      expect(
        await main(
          [
            "scan",
            ".",
            "--format",
            format,
            "--full-output",
            ...(outcome === "dry-run" ? ["--dry-run"] : []),
          ],
          stdout.stream,
          capture().stream,
          dependencies({
            result: fakeResult(["high"]),
            preflight: fakePreflight(),
          }),
        ),
      ).toBe(0);
      const output = JSON.parse(stdout.text());
      expect(output.ok).toBe(true);
      expect(validate(output), JSON.stringify(validate.errors)).toBe(true);
      expect(validate({ ...output, data: {} })).toBe(false);
    }
  },
);

test.each(["completed", "dry-run", "failed", "argument-error"] as const)(
  "accepts token-truncated %s full-output envelopes",
  async (outcome) => {
    const validate = new Ajv2020({ strict: false }).compile(
      await scanOutputSchema(),
    );
    const failed = outcome === "failed" || outcome === "argument-error";
    for (const format of ["json", "jsonl"]) {
      for (const transform of ["--token-limit", "--token-offset"]) {
        const stdout = capture();
        expect(
          await main(
            [
              "scan",
              ".",
              "--format",
              format,
              "--full-output",
              transform,
              "2",
              ...(outcome === "dry-run" ? ["--dry-run"] : []),
              ...(outcome === "argument-error" ? ["--path"] : []),
            ],
            stdout.stream,
            capture().stream,
            dependencies({
              result: fakeResult(["high"]),
              preflight: fakePreflight(),
              onRun: () => {
                if (outcome === "failed") throw new Error("Synthetic failure.");
              },
            }),
          ),
        ).toBe(failed ? 2 : 0);
        const output = JSON.parse(stdout.text());
        expect(output.ok).toBe(!failed);
        expect(typeof output[failed ? "error" : "data"]).toBe("string");
        expect(validate(output), JSON.stringify(validate.errors)).toBe(true);
      }
    }
  },
);
