import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import { parse } from "yaml";

interface Step {
  name?: string;
  task?: string;
  checkout?: string;
  condition?: string;
  fetchDepth?: number;
  persistCredentials?: boolean;
  env?: Record<string, string>;
  inputs?: Record<string, string | boolean>;
}

const pipeline = parse(
  readFileSync(
    new URL(
      "../../../examples/azure-pipelines/azure-pipelines.yml",
      import.meta.url,
    ),
    "utf8",
  ),
) as {
  trigger: string;
  resources: { repositories: { repository: string; trigger: string }[] };
  jobs: {
    variables: Record<string, string>;
    steps: (Step | Record<string, Step[]>)[];
  }[];
};
const job = pipeline.jobs[0]!;
const steps = job.steps.flatMap((step) =>
  step.task || step.checkout ? [step] : Object.values(step).flat(),
) as Step[];
const scan = steps.find((step) => step.name === "runScan")!;
const sarif = steps.find((step) => step.name === "exportSarif")!;
const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function runStep(
  step: Step,
  overrides: Record<string, string> = {},
  scanFiles: string[] = [],
) {
  const directory = mkdtempSync(join(tmpdir(), "codex azure example "));
  temporaryDirectories.push(directory);
  for (const child of ["repository with spaces", "scan", "reports"]) {
    mkdirSync(join(directory, child));
  }
  for (const file of scanFiles) {
    writeFileSync(join(directory, "scan", file), "synthetic fixture");
  }
  // Git Bash accepts forward-slash drive paths on Windows.
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
      "-c",
      `codex-security() {
  printf '%s\\0' "$@" > "$ARGUMENTS_PATH"
  printf '{"mock":true}\\n'
  return "$MOCK_EXIT_CODE"
}
${step.inputs?.["inlineScript"] ?? step.inputs?.["script"]}`,
    ],
    {
      cwd: directory,
      encoding: "utf8",
      env: {
        PATH: process.env["PATH"],
        SYSTEMROOT: process.env["SYSTEMROOT"],
        ARGUMENTS_PATH: `${root}/arguments`,
        TARGET_DIRECTORY: `${root}/repository with spaces`,
        SCAN_DIRECTORY: `${root}/scan`,
        REPORT_DIRECTORY: `${root}/reports`,
        BEDROCK_MODEL_ID: "example.model",
        SCAN_MODE: "full",
        BASE_REVISION: "HEAD^",
        FAIL_ON_SEVERITY: "none",
        MOCK_EXIT_CODE: "0",
        ...overrides,
      },
    },
  );
  if (result.error) throw result.error;
  const argumentsPath = join(directory, "arguments");
  const args = existsSync(argumentsPath)
    ? readFileSync(argumentsPath, "utf8").split("\0").slice(0, -1)
    : [];
  return { ...result, directory, root, args };
}

test("runs a report-only full scan outside the target checkout", () => {
  const result = runStep(scan);
  expect(result.status).toBe(0);
  expect(result.args).toEqual([
    "scan",
    `${result.root}/repository with spaces`,
    "--provider",
    "amazon-bedrock",
    "--model",
    "example.model",
    "--mode",
    "standard",
    "--effort",
    "high",
    "--output-dir",
    `${result.root}/scan`,
    "--json",
  ]);
});

test("passes a diff revision literally, without evaluating shell syntax", () => {
  const base = "revision with spaces; $(exit 99)";
  const result = runStep(scan, { SCAN_MODE: "diff", BASE_REVISION: base });
  expect(result.status).toBe(0);
  expect(result.args.slice(-2)).toEqual(["--diff", base]);
});

for (const status of [0, 1, 2, 130, 143]) {
  test(`preserves scan exit ${status} and records it for subsequent tasks`, () => {
    const result = runStep(scan, {
      MOCK_EXIT_CODE: String(status),
      FAIL_ON_SEVERITY: "high",
    });
    expect(result.status).toBe(status);
    expect(result.args.slice(-2)).toEqual(["--fail-on-severity", "high"]);
    expect(result.stdout).toBe(
      `##vso[task.setvariable variable=scanExitCode]${status}\n`,
    );
    expect(
      JSON.parse(
        readFileSync(join(result.directory, "reports/result.json"), "utf8"),
      ),
    ).toEqual({ mock: true });
  });
}

test("exports fingerprints and only signals readiness after a successful export", () => {
  const result = runStep(sarif);
  expect(result.status).toBe(0);
  expect(result.args).toEqual([
    "export",
    `${result.root}/scan`,
    "--export-format",
    "sarif",
    "--source-root",
    `${result.root}/repository with spaces`,
    "--output",
    `${result.root}/reports/results.sarif`,
  ]);
  expect(result.stdout).toContain(
    "##vso[task.setvariable variable=sarifReady]true\n",
  );
  const failed = runStep(sarif, { MOCK_EXIT_CODE: "2" });
  expect(failed.status).toBe(2);
  expect(failed.stdout).not.toContain("variable=sarifReady");
  expect(sarif.condition).toBe(
    "and(succeededOrFailed(), in(variables['scanExitCode'], '0', '1'))",
  );
  const publisher = steps.find(
    (step) => step.task === "AdvancedSecurity-Publish@1",
  )!;
  expect(publisher.condition).toBe(
    "and(succeededOrFailed(), eq(variables['sarifReady'], 'true'))",
  );
});

test("retains selected reports without copying raw state or credentials", () => {
  const collect = steps.find((step) => step.name === "stageReports")!;
  const reports = ["coverage.json", "findings.json", "report.md"];
  const result = runStep(collect, {}, [
    ...reports,
    "auth.json",
    "transcript.jsonl",
    "workbench.sqlite3",
  ]);
  expect(result.status).toBe(0);
  expect(readdirSync(join(result.directory, "reports")).sort()).toEqual(
    reports,
  );
  expect(runStep(collect).status).toBe(0);
});

test("uses the explicit target resource and keeps setup separate from scanning", () => {
  expect(pipeline.trigger).toBe("none");
  expect(pipeline.resources.repositories).toMatchObject([
    { repository: "target", trigger: "none" },
  ]);
  expect(job.variables["advancedsecurity.publish.repository"]).toBe(
    "$[ convertToJson(resources.repositories['target']) ]",
  );
  const checkout = steps.findIndex((step) => step.checkout === "target");
  expect(steps.findIndex((step) => step.name === "installCli")).toBeLessThan(
    checkout,
  );
  expect(steps[checkout]).toMatchObject({
    fetchDepth: 0,
    persistCredentials: false,
  });
  expect(scan.inputs?.["disableAutoCwd"]).toBe(true);
  for (const step of steps) {
    expect(step.env ?? {}).not.toHaveProperty("SYSTEM_ACCESSTOKEN");
  }
});
