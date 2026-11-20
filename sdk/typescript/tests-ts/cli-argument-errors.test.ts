import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

async function runInvalid(args: string[]) {
  const stdout = capture();
  const stderr = capture();
  let initialized = false;
  const deps = dependencies({
    onConfig: () => {
      initialized = true;
      throw new Error("Invalid arguments reached the scanner.");
    },
  });
  expect(await main(args, stdout.stream, stderr.stream, deps)).toBe(2);
  expect(initialized).toBe(false);
  return { stdout: stdout.text(), stderr: stderr.text() };
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
      for (const fullOutput of [false, true]) {
        const { stdout, stderr } = await runInvalid([
          "scan",
          "--dry-run",
          ...format,
          ...(fullOutput ? ["--full-output"] : []),
          ...args,
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
    async ({ args }) => {
      for (const fullOutput of [false, true]) {
        const { stdout, stderr } = await runInvalid([
          "scan",
          ...args,
          ...(fullOutput ? ["--full-output"] : []),
        ]);
        const value = JSON.parse(stdout);
        expect(fullOutput ? value.ok : value.status).toBe(
          fullOutput ? false : "failed",
        );
        expect((fullOutput ? value.error : value).code).toBe("SCAN_FAILED");
        expect(stderr).toContain("format");
      }
    },
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
