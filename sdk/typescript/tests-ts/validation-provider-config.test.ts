import { expect, test, spyOn } from "bun:test";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { temporaryDirectory } from "./support/temporary-directories.js";
import { ContinuumValidationProvider } from "../src/continuum-validation-provider.js";
import { ScanResult } from "../src/index.js";
import { fakeResult } from "./cli-fixtures.js";
import { resolveProjectConfig } from "../src/project-config.js";
import { ValidationProviderSettingsSchema } from "../src/scan-settings.js";
import { main } from "../src/cli.js";
import { CodexSecurity } from "../src/api.js";
import { validationProviderFromConfiguration } from "../src/validation-providers.js";
import { dependencies } from "./cli-fixtures.js";
import { createCliTest } from "./support/cli-run.js";

const configured = {
  provider: "continuum",
  continuum: {
    environment_id: "environment-1",
    aws_profile: "continuum-personal",
    aws_region: "us-east-1",
    wait_minutes: 45,
  },
};

test("parses scan.validation provider configuration", () => {
  expect(ValidationProviderSettingsSchema.parse(configured)).toEqual(
    configured,
  );
  expect(
    resolveProjectConfig({ scan: { validation: configured } }, "/repo").options
      .validationProvider,
  ).toEqual(configured);
});

test("no provider preserves the existing validation selection", () => {
  expect(
    resolveProjectConfig({}, "/repo").options.validationProvider,
  ).toBeUndefined();
});

test("no provider preserves standalone validation output", async () => {
  const { runCli, stdout, stderr } = createCliTest(main);
  expect(
    await runCli(
      ["validate", "Synthetic finding"],
      dependencies({
        onCodex: (_args, output) => {
          output?.stdout.write("Existing static assessment.\n");
          return 0;
        },
      }),
    ),
  ).toBe(0);
  expect(stdout.text()).toBe("Existing static assessment.\n");
  expect(stderr.text()).toBe("");
});

test("SDK accepts a provider implementation and contains provider failures", async () => {
  const client = new CodexSecurity();
  const provider = {
    name: "synthetic",
    version: "1",
    validate: async () => {
      throw new Error("temporarily unavailable");
    },
  };
  const result = await client.validate({
    repositoryPath: "/repo",
    finding: "synthetic",
    validationProvider: provider,
  });
  expect(result).toMatchObject({
    disposition: "deferred",
    unavailable: "temporarily unavailable",
    outputDir: "",
    threadId: null,
    provenance: { provider: "synthetic", providerVersion: "1" },
  });
  await client.close();
});

test("provider selection has no separate CLI flag", async () => {
  for (const command of ["scan", "validate"] as const) {
    const { runCli, stderr } = createCliTest(main);
    const args =
      command === "scan"
        ? ["scan", "--validate", ".", "--validation-provider", "continuum"]
        : [
            "validate",
            "text:synthetic finding",
            "--validation-provider",
            "continuum",
          ];
    expect(await runCli(args, dependencies())).toBe(2);
    expect(stderr.text()).toContain("--validation-provider");
  }
});

test("unknown configured provider fails explicitly without network access", () => {
  expect(() =>
    validationProviderFromConfiguration({ provider: "fake-unknown" }),
  ).toThrow("Unknown validation provider: fake-unknown");
});

test.each(["--validate", "--validate=true", "--validate=continuum"])(
  "%s writes the available records and reports incomplete validation for a mixed batch",
  async (flag) => {
    const root = await temporaryDirectory("provider-cli-");
    const repository = join(root, "repo"),
      scanDir = join(root, "scan");
    const record = {
      itemId: "fake-item",
      provider: "continuum",
      verdict: "EXPLOITABLE",
      severityBefore: "high",
      severityAfter: "high",
      providerSeverity: "critical",
      reasons: [{ basis: "GRAPH" as const, reason: "Fake exposed deployment" }],
      claimMatch: "unknown" as const,
      issueUrl: "https://example.invalid/issue",
      freshness: { stale: false, reasons: [] },
    };
    const failed = {
      itemId: "fake-failed",
      provider: "continuum",
      verdict: "UNCERTAIN",
      terminalStatus: "FAILED",
      severityBefore: "medium",
      severityAfter: "medium",
      reasons: [],
      claimMatch: "unknown" as const,
      freshness: { stale: false, reasons: [] },
    };
    const batch = spyOn(
      ContinuumValidationProvider.prototype,
      "validateBatch",
    ).mockResolvedValue([
      {
        disposition: "reportable",
        report: "Fake supplemental report",
        provenance: {
          provider: "continuum",
          providerVersion: "1",
          validatedAt: "2026-11-06T15:20:00Z",
        },
        record,
      },
      {
        disposition: "deferred",
        report: "Validation failed",
        provenance: { provider: "continuum", providerVersion: "1" },
        record: failed,
      },
    ]);
    try {
      await mkdir(repository);
      await mkdir(scanDir);
      await writeFile(join(repository, "source.ts"), "// fake source\n");
      const config = join(root, "codex-security.yaml");
      await writeFile(
        config,
        `scan:\n  validation:\n    provider: ${flag === "--validate=continuum" ? "fake-unknown" : "continuum"}\n    continuum:\n      environment_id: example\n`,
      );
      const base = fakeResult(["high", "medium"]);
      const result = new ScanResult({
        manifest: base.manifest,
        findings: base.findings,
        review: base.review,
        mode: base.mode,
        scanDir,
        threadId: base.threadId,
        turnResult: base.turnResult,
      });
      const cli = createCliTest(main);
      expect(
        await cli.runCli(
          ["scan", flag, ".", "-c", config, "--json"],
          dependencies({ currentDirectory: repository, result }),
        ),
        cli.stderr.text(),
      ).toBe(0);
      expect(batch).toHaveBeenCalledTimes(1);
      expect(batch.mock.calls[0]?.[1]).toMatchObject({
        repositoryPath: repository,
        checkSubmissionTarget: expect.any(Function),
      });
      expect(
        JSON.parse(await readFile(join(scanDir, "validation.json"), "utf8")),
      ).toEqual({ schemaVersion: 1, items: [record, failed] });
      expect(await readFile(join(scanDir, "validation.md"), "utf8")).toContain(
        "Fake supplemental report",
      );
      expect(JSON.parse(cli.stdout.text()).validation).toMatchObject({
        status: "incomplete",
        recordsPath: join(scanDir, "validation.json"),
      });
    } finally {
      batch.mockRestore();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test.each(["--validate", "--validate=false"])(
  "no configured provider preserves boolean flag behavior for %s",
  async (flag) => {
    const root = await temporaryDirectory("no-provider-cli-");
    try {
      const scanDir = join(root, "scan");
      await mkdir(scanDir);
      const base = fakeResult(["high"]);
      const result = new ScanResult({
        manifest: base.manifest,
        findings: base.findings,
        review: base.review,
        mode: base.mode,
        scanDir,
        threadId: base.threadId,
        turnResult: base.turnResult,
      });
      let validations = 0;
      const cli = createCliTest(main);
      expect(
        await cli.runCli(
          ["scan", flag, ".", "--json"],
          dependencies({
            currentDirectory: root,
            result,
            onValidate: async (options) => {
              validations++;
              expect(options.validationProvider).toBeUndefined();
              return {
                disposition: "reportable",
                report: "Fake Codex-only validation",
                outputDir: "",
                threadId: null,
              };
            },
          }),
        ),
        cli.stderr.text(),
      ).toBe(0);
      expect(validations).toBe(flag === "--validate=false" ? 0 : 1);
      expect(
        JSON.parse(cli.stdout.text()).validation?.recordsPath,
      ).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);
