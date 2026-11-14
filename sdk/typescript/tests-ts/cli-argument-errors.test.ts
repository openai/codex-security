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
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            ["scan", ...args, ...(fullOutput ? ["--full-output"] : [])],
            stdout.stream,
            stderr.stream,
            dependencies({
              onConfig: () => {
                throw new Error(
                  "Argument errors must not initialize the scanner.",
                );
              },
            }),
          ),
        ).toBe(2);
        const value = JSON.parse(stdout.text());
        expect(fullOutput ? value.ok : value.status).toBe(
          fullOutput ? false : "failed",
        );
        expect((fullOutput ? value.error : value).code).toBe("SCAN_FAILED");
        expect(stderr.text()).toContain("format");
      }
    },
  );

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

test.each([{ invalid: ["--mode", "bogus"] }, { invalid: ["--path"] }])(
  "JSON token options preserve scan argument diagnostics for $invalid",
  async ({ invalid }) => {
    for (const fullOutput of [false, true]) {
      for (const transform of [["--token-count"], ["--token-limit=2"]]) {
        const stdout = capture();
        const stderr = capture();
        expect(
          await main(
            [
              "scan",
              "--json",
              ...(fullOutput ? ["--full-output"] : []),
              ...transform,
              ...invalid,
            ],
            stdout.stream,
            stderr.stream,
            dependencies(),
          ),
        ).toBe(2);
        expect(stderr.text()).toContain(invalid[0]!);
        const rendered = JSON.parse(stdout.text());
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
    const stderr = capture();
    let initialized = false;
    expect(
      await main(
        [`--${flag}`, "scan", ".", "second", `--no-${flag}`, "--headless"],
        capture().stream,
        stderr.stream,
        dependencies({
          onConfig: () => {
            initialized = true;
          },
        }),
      ),
    ).toBe(2);
    expect(initialized).toBe(false);
    expect(stderr.text()).toContain("Unexpected positional argument for scan");
  },
);

test("output option negation and invalid token ranges never start a scan", async () => {
  const deps = dependencies({
    onConfig: () => {
      throw new Error("Scanner initialized for invalid arguments");
    },
  });
  for (const flag of ["--token-limit", "--token-offset"]) {
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scan", ".", "--json", "--token-count", flag, "-1"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain(`${flag} requires a nonnegative integer`);
  }
  const compact = capture();
  expect(
    await main(
      [
        "scan",
        "--json",
        "--full-output",
        "--no-full-output",
        "--token-count",
        "--no-token-count",
        "--unknown-option",
      ],
      compact.stream,
      capture().stream,
      deps,
    ),
  ).toBe(2);
  expect(JSON.parse(compact.text()).status).toBe("failed");

  const plain = capture();
  expect(
    await main(
      ["scan", "--json", "--no-json", "--unknown-option"],
      plain.stream,
      capture().stream,
      deps,
    ),
  ).toBe(2);
  expect(plain.text()).toBe("");
});

test("recognizes scans preceded by the global JSON flag", async () => {
  const stdout = capture();
  const stderr = capture();
  expect(
    await main(
      ["--json", "scan", "--unknown-option"],
      stdout.stream,
      stderr.stream,
      dependencies({
        onConfig: () => {
          throw new Error("Argument errors must not initialize the scanner.");
        },
      }),
    ),
  ).toBe(2);
  expect(stderr.text()).toContain("unknown-option");
  expect(JSON.parse(stdout.text())).toMatchObject({
    status: "failed",
    code: "SCAN_FAILED",
  });
});
