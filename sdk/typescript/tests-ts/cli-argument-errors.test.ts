import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

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
      for (const fullOutput of [false, true]) {
        const stdout = capture();
        const stderr = capture();
        const deps = dependencies({
          onConfig: () => {
            throw new Error("Argument errors must not initialize the scanner.");
          },
        });
        expect(
          await main(
            [
              "scan",
              "--dry-run",
              ...format,
              ...(fullOutput ? ["--full-output"] : []),
              ...args,
            ],
            stdout.stream,
            stderr.stream,
            deps,
          ),
        ).toBe(2);
        const value = JSON.parse(stdout.text());
        const error = fullOutput ? value.error : value;
        expect(error.code).toBe("SCAN_FAILED");
        expect(error.message).toContain(message);
        if (fullOutput) {
          expect(value.ok).toBe(false);
          expect(value).not.toHaveProperty("data");
        } else expect(value.status).toBe("failed");
        expect(stderr.text()).toContain(message);
      }
    }
  });

  test("prints concise flag names and accepted values for validation errors", async () => {
    for (const [args, flag, detail] of [
      [["--mode", "bogus"], "--mode", "standard"],
      [["--max-cost", "0"], "--max-cost", ">0"],
    ] as const) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          ["scan", ...args],
          stdout.stream,
          stderr.stream,
          dependencies(),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(flag);
      expect(stderr.text()).toContain(detail);
      expect(stderr.text()).not.toContain("Details:");
    }
  });

  test("uses the last output format and does not confuse import input with output", async () => {
    for (const args of [
      ["scan", "--json", "--format", "yaml", "--path"],
      ["scan", "import", "--json", "input.json", "--unknown-option"],
    ]) {
      const stdout = capture();
      expect(
        await main(args, stdout.stream, capture().stream, dependencies()),
      ).toBe(2);
      expect(stdout.text()).toBe("");
    }
  });
});
