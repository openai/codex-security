import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
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
          properties: { ok: { const: false }, error: { type: "object" } },
        },
      ],
    });
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate({})).toBe(false);
  });

  test.each(["partial", "unknown"] as const)(
    "accepts actual %s full-output errors alongside completed scan shapes",
    async (completeness) => {
      const validate = new Ajv2020({ strict: false }).compile(
        await scanOutputSchema(),
      );
      for (const format of ["json", "jsonl"]) {
        for (const filter of [undefined, "warnings", "findings"]) {
          const stdout = capture();
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
              dependencies({ result: fakeResult(["high"], completeness) }),
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
