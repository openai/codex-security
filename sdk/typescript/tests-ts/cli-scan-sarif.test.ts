import { mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join, relative, sep } from "node:path";
import { afterEach, expect, mock, test } from "bun:test";
import { runArtifactExport } from "../src/artifact-export.js";
import { main } from "../src/cli.js";
import { ScanResult } from "../src/index.js";
import { resolvePluginPython } from "../src/runtime.js";
import {
  capture,
  dependencies,
  fakeResult,
  FakeSignals,
} from "./cli-fixtures.js";
import { copyCompletedScanFixture } from "./plugin-root.js";
import { createCliTest } from "./support/cli-run.js";
import { runCommand } from "./support/shell.js";
import { createTemporaryDirectories } from "./support/temporary-directories.js";

const temporaryDirectories = createTemporaryDirectories(true);
afterEach(() => temporaryDirectories.cleanup());

test("documents the optional SARIF file without changing presentation formats", async () => {
  const help = createCliTest(main);
  expect(await help.runCli(["scan", "--help"], dependencies())).toBe(0);
  expect(help.stdout.text()).toContain("--sarif <file>");
  const schema = createCliTest(main);
  expect(
    await schema.runCli(["scan", "--schema", "--json"], dependencies()),
  ).toBe(0);
  const options = JSON.parse(schema.stdout.text()).options;
  expect(options.properties.sarif).toMatchObject({ type: "string" });
  expect(options.required ?? []).not.toContain("sarif");
  expect(options.properties.sarif).not.toHaveProperty("default");
});

async function completedScan() {
  const directory = await temporaryDirectories.create("scan-sarif-");
  const repository = join(directory, "repository");
  const scanDir = join(directory, "scan");
  await mkdir(join(repository, "src"), { recursive: true });
  await writeFile(join(repository, "src", "extract.py"), "pass\n".repeat(50));
  await copyCompletedScanFixture(scanDir);
  const result = new ScanResult({
    manifest: JSON.parse(
      await readFile(join(scanDir, "scan-manifest.json"), "utf8"),
    ),
    findings: JSON.parse(
      await readFile(join(scanDir, "findings.json"), "utf8"),
    ),
    coverage: JSON.parse(
      await readFile(join(scanDir, "coverage.json"), "utf8"),
    ),
    scanDir,
    threadId: "synthetic-thread",
    turnResult: { status: "completed", finalResponse: "done" },
  });
  return { directory, repository, result };
}

test.each([
  ["standard", "relative"],
  ["deep", "relative"],
  ["standard", "home-relative"],
] as const)(
  "exports %s scan findings from a %s repository even when the severity threshold fails",
  async (mode, repositoryPath) => {
    const { directory, repository, result } = await completedScan();
    const output = join(directory, "results.sarif");
    const pythonPath = await resolvePluginPython();
    const deps = dependencies({ currentDirectory: directory, result });
    const exporter = mock(runArtifactExport);
    deps.exportFindings = exporter;
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          repositoryPath === "home-relative"
            ? ["~", relative(homedir(), repository)].join(sep)
            : "repository",
          "--mode",
          mode,
          "--sarif",
          "results.sarif",
          "--python",
          pythonPath,
          "--fail-on-severity",
          "high",
          "--format",
          "json",
        ],
        deps,
      ),
      stderr.text(),
    ).toBe(1);
    expect(exporter).toHaveBeenCalledTimes(1);
    expect(exporter).toHaveBeenCalledWith({
      scanDir: result.scanDir,
      format: "sarif",
      output,
      sourceRoot: repository,
      pythonPath,
      signal: expect.any(AbortSignal),
    });
    expect(JSON.parse(stdout.text())).toEqual(
      JSON.parse(JSON.stringify({ ...result.toJSON(), sarifPath: output })),
    );
    expect(stderr.text()).toContain(`SARIF: ${output}\n`);
    const sarif = JSON.parse(await readFile(output, "utf8"));
    const finding = result.findings.findings[0]!;
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0]).toMatchObject({
      ruleId: finding.ruleId,
      level: "error",
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: "src/extract.py" },
            region: { startLine: 41, endLine: 44 },
          },
        },
      ],
    });
    expect(sarif.runs[0].tool.driver.rules[0]).toMatchObject({
      id: finding.ruleId,
      properties: { "security-severity": "8.1" },
    });
  },
);

test("does not export when --sarif is omitted", async () => {
  const result = fakeResult();
  const deps = dependencies({ result });
  const exporter = mock(deps.exportFindings);
  deps.exportFindings = exporter;
  const { stdout, runCli } = createCliTest(main);

  expect(await runCli(["scan", ".", "--json"], deps)).toBe(0);
  expect(exporter).not.toHaveBeenCalled();
  expect(JSON.parse(stdout.text())).toEqual(result.toJSON());
});

test("keeps normal output on stderr when exporting SARIF", async () => {
  const { directory, repository, result } = await completedScan();
  const output = join(directory, "results.sarif");
  const signals = new FakeSignals();
  const deps = dependencies({ currentDirectory: repository, result, signals });
  deps.exportFindings = runArtifactExport;
  const { stdout, stderr, runCli } = createCliTest(main);

  expect(
    await runCli(["scan", ".", "--sarif", output], deps),
    stderr.text(),
  ).toBe(0);
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain(`SARIF: ${output}\n`);
  expect(JSON.parse(await readFile(output, "utf8")).version).toBe("2.1.0");
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
});

test.each([false, true])(
  "exports SARIF before patching and skips patches after an export failure: %j",
  async (exportFails) => {
    const { directory, repository, result } = await completedScan();
    const output = join(directory, "results.sarif");
    const finding = result.findings.findings[0]!;
    let patchCalls = 0;
    let exportedSarif = "";
    const deps = dependencies({
      currentDirectory: repository,
      result,
      onCodex: async (_args, streams) => {
        patchCalls += 1;
        exportedSarif = await readFile(output, "utf8");
        expect(JSON.parse(exportedSarif).runs[0].results).toHaveLength(1);
        await writeFile(join(repository, "src", "extract.py"), "patched\n");
        streams?.stdout.write(
          JSON.stringify({
            patches: [
              {
                occurrenceId: finding.occurrenceId,
                status: "verified",
                files: ["src/extract.py"],
                verification: "Synthetic patch verified.",
              },
            ],
          }),
        );
        return 0;
      },
    });
    const exporter = mock<typeof deps.exportFindings>(async (arguments_) => {
      if (exportFails) throw new Error("Synthetic export failure");
      return runArtifactExport(arguments_);
    });
    deps.exportFindings = exporter;
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          ".",
          "--sarif",
          output,
          "--patch",
          "--patch-severity",
          "high",
          "--json",
        ],
        deps,
      ),
      stderr.text(),
    ).toBe(exportFails ? 2 : 0);
    expect(exporter).toHaveBeenCalledTimes(1);
    expect(patchCalls).toBe(exportFails ? 0 : 1);
    if (!exportFails) {
      expect(await readFile(output, "utf8")).toBe(exportedSarif);
      expect(JSON.parse(stdout.text())).toMatchObject({
        sarifPath: output,
        patches: [{ occurrenceId: finding.occurrenceId, status: "verified" }],
      });
    }
  },
);

test("preserves a successful export when its progress notice fails", async () => {
  const { directory, repository, result } = await completedScan();
  const output = join(directory, "results.sarif");
  const deps = dependencies({ currentDirectory: repository, result });
  const exporter = mock(deps.exportFindings);
  deps.exportFindings = exporter;
  const stdout = capture();
  const stderr = capture();
  let noticeAttempted = false;

  expect(
    await main(
      ["scan", ".", "--sarif", output, "--json"],
      stdout.stream,
      {
        ...stderr.stream,
        write(chunk: string | Uint8Array) {
          if (chunk.toString().startsWith("SARIF:")) {
            noticeAttempted = true;
            throw new Error("Synthetic progress output failure");
          }
          return stderr.stream.write(chunk);
        },
      },
      deps,
    ),
    stderr.text(),
  ).toBe(0);
  expect(exporter).toHaveBeenCalledTimes(1);
  expect(noticeAttempted).toBe(true);
  expect(JSON.parse(stdout.text()).sarifPath).toBe(output);
});

test("preserves completed scan data when SARIF export fails", async () => {
  const { directory, repository, result } = await completedScan();
  const signals = new FakeSignals();
  const deps = dependencies({ currentDirectory: repository, result, signals });
  const message = "EACCES: synthetic SARIF output denied";
  deps.exportFindings = async () => {
    throw new Error(message);
  };
  const { stdout, stderr, runCli } = createCliTest(main);

  expect(
    await runCli(
      [
        "scan",
        ".",
        "--sarif",
        join(directory, "results.sarif"),
        "--json",
        "--full-output",
      ],
      deps,
    ),
  ).toBe(2);
  expect(JSON.parse(stdout.text())).toMatchObject({
    ok: false,
    error: { code: "SCAN_FAILED", message },
    data: JSON.parse(JSON.stringify(result.toJSON())),
  });
  expect(stderr.text()).toContain(message);
  expect(stderr.text()).not.toContain("SARIF:");
  expect(signals.listeners.get("SIGINT")?.size).toBe(0);
  expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  expect(JSON.parse(await readFile(result.manifestPath, "utf8"))).toEqual(
    result.manifest,
  );
});

test.each([
  ["SIGINT", 130, "rejects"],
  ["SIGINT", 130, "resolves"],
  ["SIGTERM", 143, "rejects"],
  ["SIGTERM", 143, "resolves"],
] as const)(
  "retains completed scan data after %s (exit %i) when the exporter %s",
  async (interruption, exitCode, completion) => {
    const { directory, repository, result } = await completedScan();
    const output = join(directory, "results.sarif");
    await writeFile(output, "previous export\n");
    const signals = new FakeSignals();
    const deps = dependencies({
      currentDirectory: repository,
      result,
      signals,
    });
    const exporter = mock<typeof deps.exportFindings>(async ({ signal }) => {
      expect(signal).toBeInstanceOf(AbortSignal);
      expect(signal?.aborted).toBe(false);
      signals.emit(interruption);
      expect(signal?.aborted).toBe(true);
      expect(signal?.reason).toBe(interruption);
      if (completion === "rejects") signal?.throwIfAborted();
      return undefined;
    });
    deps.exportFindings = exporter;
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", ".", "--sarif", output, "--json", "--full-output"],
        deps,
      ),
    ).toBe(exitCode);
    expect(exporter).toHaveBeenCalledTimes(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      ok: false,
      error: { code: "SCAN_FAILED" },
      data: JSON.parse(JSON.stringify(result.toJSON())),
    });
    expect(stderr.text()).not.toContain("SARIF:");
    expect(await readFile(output, "utf8")).toBe("previous export\n");
    expect(JSON.parse(await readFile(result.manifestPath, "utf8"))).toEqual(
      result.manifest,
    );
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  },
);

test.each(["dry-run", "failed", "canceled", "SIGINT"] as const)(
  "does not export a %s scan",
  async (state) => {
    const directory = await temporaryDirectories.create("scan-sarif-skip-");
    const result = fakeResult();
    const signals = new FakeSignals();
    if (state === "failed" || state === "canceled")
      result.manifest.scan.status = state;
    const deps = dependencies({
      currentDirectory: directory,
      result,
      signals,
      onRun: () => {
        if (state === "SIGINT") signals.emit("SIGINT");
      },
    });
    const exporter = mock(deps.exportFindings);
    deps.exportFindings = exporter;
    const { runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          ".",
          "--sarif",
          "results.sarif",
          "--json",
          ...(state === "dry-run" ? ["--dry-run"] : []),
        ],
        deps,
      ),
    ).toBe(state === "dry-run" ? 0 : state === "SIGINT" ? 130 : 2);
    expect(exporter).not.toHaveBeenCalled();
  },
);

test("rejects a SARIF output path that would overwrite a scan artifact", async () => {
  const { repository, result } = await completedScan();
  const before = await readFile(result.findingsPath);
  const deps = dependencies({ currentDirectory: repository, result });
  const exporter = mock(deps.exportFindings);
  deps.exportFindings = exporter;
  const { stderr, runCli } = createCliTest(main);

  expect(
    await runCli(["scan", ".", "--sarif", result.findingsPath], deps),
  ).toBe(2);
  expect(stderr.text()).toContain("cannot overwrite a scan artifact");
  expect(exporter).not.toHaveBeenCalled();
  expect(await readFile(result.findingsPath)).toEqual(before);
});

test.each([false, true])(
  "protects caller-owned output aliases only for Git worktrees: %j",
  async (gitCaller) => {
    const { directory, repository, result } = await completedScan();
    const caller = join(directory, "caller");
    const reports = join(directory, "reports");
    const output = join(reports, "results.sarif");
    await mkdir(caller);
    await mkdir(reports);
    await writeFile(output, "previous export\n");
    if (gitCaller) {
      const initialized = await runCommand("git", ["init", "--quiet", caller]);
      expect(initialized.status, initialized.stderr).toBe(0);
    }
    await symlink(
      reports,
      join(caller, "reports"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const deps = dependencies({ currentDirectory: caller, result });
    const exporter = mock(runArtifactExport);
    deps.exportFindings = exporter;
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        ["scan", repository, "--sarif", join("reports", "results.sarif")],
        deps,
      ),
      stderr.text(),
    ).toBe(gitCaller ? 2 : 0);
    if (gitCaller) {
      expect(exporter).not.toHaveBeenCalled();
      expect(stderr.text()).toContain("cannot traverse a repository symlink");
      expect(await readFile(output, "utf8")).toBe("previous export\n");
    } else {
      expect(exporter).toHaveBeenCalledTimes(1);
      expect(JSON.parse(await readFile(output, "utf8")).version).toBe("2.1.0");
      expect(stderr.text()).toContain(`SARIF: ${output}\n`);
    }
  },
);

test.each([
  "canonical",
  "alias",
  "child-directory",
  "external-child-directory",
  "external-alias-child-directory",
  "output-only-alias",
] as const)(
  "rejects repository output symlinks with a %s path",
  async (pathKind) => {
    const { directory, repository, result } = await completedScan();
    const outside = join(directory, "outside");
    const launchDirectory = join(directory, "launch");
    const alias = join(directory, "repository-alias");
    const output = join(outside, "results.sarif");
    await mkdir(outside);
    await mkdir(launchDirectory);
    if (pathKind === "child-directory" || pathKind.startsWith("external-")) {
      const initialized = await runCommand("git", [
        "init",
        "--quiet",
        repository,
      ]);
      expect(initialized.status, initialized.stderr).toBe(0);
    }
    await writeFile(output, "unchanged\n");
    const linkType = process.platform === "win32" ? "junction" : "dir";
    await symlink(repository, alias, linkType);
    await symlink(outside, join(repository, "reports"), linkType);
    const targets = {
      canonical: alias,
      alias,
      "child-directory": "src",
      "external-child-directory": join(repository, "src"),
      "external-alias-child-directory": join(alias, "src"),
      "output-only-alias": repository,
    };
    const aliasOutput = [
      "alias",
      "external-alias-child-directory",
      "output-only-alias",
    ].includes(pathKind);
    const deps = dependencies({
      currentDirectory:
        pathKind === "child-directory" ? repository : launchDirectory,
      result,
    });
    const exporter = mock(runArtifactExport);
    deps.exportFindings = exporter;
    const { stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          targets[pathKind],
          "--sarif",
          pathKind === "child-directory"
            ? join("reports", "results.sarif")
            : join(
                aliasOutput ? alias : repository,
                "reports",
                "results.sarif",
              ),
        ],
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("cannot traverse a repository symlink");
    expect(exporter).not.toHaveBeenCalled();
    expect(await readFile(output, "utf8")).toBe("unchanged\n");
  },
);
