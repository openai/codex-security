import { expect, mock, test } from "bun:test";
import { main } from "../src/cli.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest, runCapturedCli } from "./support/cli-run.js";

const cve = "CVE-2023-4863";

test("assesses a CVE in the current directory and emits the report as JSON", async () => {
  const deps = dependencies();
  const report = {
    cve,
    advisories: [],
    status: "unknown" as const,
    uses: [],
    limitations: ["No deployment evidence."],
    usage: null,
  };
  deps.assessDependencyReachability = async (id, options) => {
    expect(id).toBe(cve);
    expect(options).toMatchObject({
      workingDirectory: deps.currentDirectory(),
      environment: deps.environment,
      model: "example-model",
      reasoningEffort: "high",
    });
    expect(options.signal).toBeInstanceOf(AbortSignal);
    return report;
  };
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(
    await runCli(
      [
        "exploitability",
        "check",
        cve,
        "--model",
        "example-model",
        "--effort",
        "high",
        "--json",
      ],
      deps,
    ),
    stderr.text(),
  ).toBe(0);
  expect(JSON.parse(stdout.text())).toEqual(report);
});

test("requires a single positional argument before starting an assessment", async () => {
  const deps = dependencies();
  const assess = mock(async () => {
    throw new Error("Unexpected assessment");
  });
  deps.assessDependencyReachability = assess;
  for (const args of [[], [cve, "/messages"]]) {
    expect(
      await runCapturedCli(main, ["exploitability", "check", ...args], deps),
    ).toBe(2);
  }
  expect(assess).not.toHaveBeenCalled();
});
