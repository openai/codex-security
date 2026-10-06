import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse } from "yaml";
import { resolvePluginPython } from "../src/runtime.js";

interface Step {
  name: string;
  id?: string;
  if?: string;
  run?: string;
  with?: Record<string, string>;
}

const workflow = parse(
  readFileSync(
    new URL(
      "../../../.github/workflows/invoice-desk-scan.yml",
      import.meta.url,
    ),
    "utf8",
  ),
) as { env: Record<string, string>; jobs: { scan: { steps: Step[] } } };
const steps = workflow.jobs.scan.steps;
const scan = steps.find((step) => step.id === "scan")!;
const sarif = steps.find(
  (step) => step.name === "Export completed findings as SARIF",
)!;
const metrics = steps.find(
  (step) => step.name === "Summarize and measure the scan",
)!;
const sourceSha = "a".repeat(40);
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "invoice workflow "));
  temporaryDirectories.push(directory);
  const bin = join(directory, "codex-security-cli/node_modules/.bin");
  mkdirSync(bin, { recursive: true });
  mkdirSync(join(directory, "invoice-desk"));
  writeFileSync(
    join(bin, "codex-security"),
    `#!/usr/bin/env bash
printf '%s\\0' "$@" > "$RUNNER_TEMP/arguments"
printf '%s\\n' "$MOCK_RESULT"
exit "$MOCK_EXIT_CODE"
`,
    { mode: 0o755 },
  );
  return directory;
}

function runStep(
  step: Step,
  directory: string,
  overrides: Record<string, string> = {},
  python?: string,
) {
  const root = directory.replaceAll("\\", "/");
  const bash =
    process.platform === "win32"
      ? join(
          process.env["ProgramFiles"] ?? "C:/Program Files",
          "Git/bin/bash.exe",
        )
      : "bash";
  const result = spawnSync(
    bash,
    [
      "--noprofile",
      "--norc",
      "-e",
      "-o",
      "pipefail",
      "-c",
      `${python ? 'python3() { "$WORKFLOW_TEST_PYTHON" "$@"; }\n' : ""}${step.run}`,
    ],
    {
      cwd: join(directory, "invoice-desk"),
      encoding: "utf8",
      env: {
        PATH: process.env["PATH"],
        SYSTEMROOT: process.env["SYSTEMROOT"],
        RUNNER_TEMP: root,
        GITHUB_OUTPUT: `${root}/outputs`,
        GITHUB_STEP_SUMMARY: `${root}/summary.md`,
        GITHUB_SHA: "b".repeat(40),
        SOURCE_SHA: sourceSha,
        PR_NUMBER: "7",
        CODEX_SECURITY_VERSION: workflow.env["CODEX_SECURITY_VERSION"],
        OPENAI_API_KEY: "synthetic-workflow-key",
        MOCK_EXIT_CODE: "0",
        MOCK_RESULT: '{"mock":true}',
        SCAN_EXIT_CODE: "0",
        SCAN_ELAPSED_SECONDS: "12",
        PREVIOUS_CACHE_HIT: "true",
        SCAN_CACHE_HIT: "true",
        WORKFLOW_TEST_PYTHON: python?.replaceAll("\\", "/"),
        ...overrides,
      },
    },
  );
  if (result.error) throw result.error;
  return { ...result, root };
}

function argumentsFor(directory: string) {
  return readFileSync(join(directory, "arguments"), "utf8")
    .split("\0")
    .slice(0, -1);
}

for (const status of [0, 1, 2]) {
  test(`Invoice Desk preserves scan exit ${status}, JSON, and literal arguments`, () => {
    const directory = fixture();
    const result = runStep(scan, directory, { MOCK_EXIT_CODE: String(status) });
    expect(result.status).toBe(status);
    expect(argumentsFor(directory)).toEqual([
      "scan",
      ".",
      "--provider",
      "openai",
      "--auth",
      "api-key",
      "--model",
      "gpt-5.6-sol",
      "--effort",
      "high",
      "--mode",
      "standard",
      "--headless",
      "--format",
      "json",
      "--output-dir",
      `${result.root}/invoice-desk-scan`,
    ]);
    expect(
      JSON.parse(
        readFileSync(join(directory, "invoice-desk-result.json"), "utf8"),
      ),
    ).toEqual({ mock: true });
    expect(readFileSync(join(directory, "outputs"), "utf8")).toMatch(
      new RegExp(`^exit-code=${status}\\nelapsed-seconds=\\d+\\n$`),
    );
  });
}

test("Invoice Desk reports a missing key without invoking the scanner", () => {
  const directory = fixture();
  const result = runStep(scan, directory, { OPENAI_API_KEY: "" });
  expect(result.status).toBe(2);
  expect(existsSync(join(directory, "arguments"))).toBe(false);
  expect(existsSync(join(directory, "invoice-desk-result.json"))).toBe(false);
  expect(readFileSync(join(directory, "outputs"), "utf8")).toBe(
    "exit-code=2\nelapsed-seconds=0\n",
  );
});

test("Invoice Desk exports SARIF only for a completed report-only scan", () => {
  const directory = fixture();
  const result = runStep(sarif, directory);
  expect(result.status).toBe(0);
  expect(argumentsFor(directory)).toEqual([
    "export",
    `${result.root}/invoice-desk-scan`,
    "--export-format",
    "sarif",
    "--source-root",
    `${result.root}/invoice-desk`,
    "--output",
    `${result.root}/invoice-desk.sarif`,
  ]);
  expect(sarif.if).toBe(
    "${{ !cancelled() && steps.scan.outputs.exit-code == '0' }}",
  );
});

for (const completed of [true, false]) {
  test(`Invoice Desk records metrics for ${completed ? "completed" : "failed"} scans`, async () => {
    const directory = fixture();
    if (completed) {
      mkdirSync(join(directory, "invoice-desk-scan"));
      writeFileSync(
        join(directory, "invoice-desk-result.json"),
        JSON.stringify({
          turn: { usage: { input_tokens: 23, output_tokens: 5 } },
          cost: { estimatedUsdRange: { min: 0.01, max: 0.02 } },
        }),
      );
      writeFileSync(
        join(directory, "invoice-desk-scan/findings.json"),
        JSON.stringify({
          findings: [
            { severity: { level: "high" } },
            { severity: { level: "low" } },
          ],
        }),
      );
      writeFileSync(
        join(directory, "invoice-desk-scan/coverage.json"),
        JSON.stringify({ completeness: "partial" }),
      );
    }
    const result = runStep(
      metrics,
      directory,
      { SCAN_EXIT_CODE: completed ? "0" : "2" },
      await resolvePluginPython(),
    );
    expect(result.status).toBe(0);
    const saved = JSON.parse(
      readFileSync(join(directory, "invoice-desk-metrics.json"), "utf8"),
    );
    expect(saved).toMatchObject({
      sourceSha,
      workflowSha: "b".repeat(40),
      pullRequest: 7,
      completed,
      exitCode: completed ? 0 : 2,
      elapsedSeconds: 12,
      packageCacheReusedFromPreviousRun: true,
      packageCacheRestoredForScan: true,
      findings: completed ? 2 : null,
      findingsBySeverity: completed ? { high: 1, low: 1 } : {},
      coverage: completed ? "partial" : null,
      tokenUsage: completed ? { input_tokens: 23, output_tokens: 5 } : null,
      estimatedUsdRange: completed ? { min: 0.01, max: 0.02 } : null,
      seedRecall: null,
    });
    const summary = readFileSync(join(directory, "summary.md"), "utf8");
    expect(summary).toContain(sourceSha);
    if (!completed) expect(summary).toContain("did not complete");
    const upload = steps.find(
      (step) => step.name === "Save reports and metrics",
    )!;
    expect(metrics.if).toBe(
      "${{ !cancelled() && steps.scan.outputs.exit-code != '' }}",
    );
    expect(upload.if).toBe(metrics.if);
    expect(upload.with?.["path"]).toContain(
      "${{ runner.temp }}/invoice-desk-metrics.json",
    );
  });
}

test("Invoice Desk rejects a completed scan with missing required artifacts", async () => {
  const directory = fixture();
  writeFileSync(join(directory, "invoice-desk-result.json"), "{}");
  const result = runStep(metrics, directory, {}, await resolvePluginPython());
  expect(result.status).not.toBe(0);
  expect(existsSync(join(directory, "invoice-desk-metrics.json"))).toBe(false);
  expect(existsSync(join(directory, "summary.md"))).toBe(false);
});
