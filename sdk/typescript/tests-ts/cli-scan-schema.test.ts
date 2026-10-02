import Ajv2020 from "ajv/dist/2020.js";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
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
      ],
    });
    const validate = new Ajv2020({ strict: false }).compile(schema);
    expect(validate({})).toBe(false);
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
