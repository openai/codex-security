import { resolve } from "node:path";
import { Writable } from "node:stream";
import { setImmediate } from "node:timers/promises";
import { describe, expect, test, mock } from "bun:test";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies,
  fakeResult,
  FakeSignals,
} from "./cli-fixtures.js";
import { rejecting, throwing } from "./support/errors.js";
import { createCliTest, captureCli } from "./support/cli-run.js";

function importDependencies(result = fakeResult(["high", "high"])) {
  const deps = dependencies({
    currentDirectory: resolve("workspace"),
    onConfig: throwing("Import must not create a model client"),
  });
  const calls: Parameters<NonNullable<typeof deps.importScan>>[0][] = [];
  deps.importScan = async (options, settings) => {
    expect(settings?.environment).toBe(deps.environment);
    calls.push(options);
    return options.dryRun
      ? {
          dryRun: true,
          inputPath: options.sourcePath,
          format: options.format,
          findingCount: result.findings.findings.length,
        }
      : result;
  };
  return { deps, calls, result };
}

describe("scan import", () => {
  test.each(["completed", "failed", "interrupted", "preview"] as const)(
    "preserves %s import outcomes when cleanup warnings fail asynchronously",
    async (outcome) => {
      const signals = new FakeSignals();
      const deps = dependencies({ signals });
      deps.importScan = async (options, settings) => {
        settings?.onWarning?.("Synthetic scratch cleanup failure");
        if (outcome === "failed") throw new Error("Synthetic import failure");
        if (outcome === "interrupted") {
          signals.emit("SIGINT");
          options.signal?.throwIfAborted();
        }
        return options.dryRun
          ? {
              dryRun: true,
              inputPath: options.sourcePath,
              format: options.format,
              findingCount: 2,
            }
          : fakeResult(["high", "high"]);
      };
      const stdout = capture();
      const stderr = new Writable({
        write(_chunk, _encoding, callback) {
          queueMicrotask(() =>
            callback(new Error("Synthetic asynchronous stderr failure")),
          );
        },
      });
      expect(
        await main(
          [
            "scan",
            "import",
            "--json",
            "findings.json",
            "--format",
            "json",
            ...(outcome === "preview" ? ["--dry-run"] : []),
          ],
          stdout.stream,
          stderr,
          deps,
        ),
      ).toBe(outcome === "failed" ? 2 : outcome === "interrupted" ? 130 : 0);
      await setImmediate();
      expect(stderr.listenerCount("error")).toBe(0);
      expect(signals.listeners.get("SIGINT")?.size).toBe(0);
      expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
      if (outcome === "completed") {
        expect(JSON.parse(stdout.text())).toMatchObject({
          manifest: { scan: { id: "scan" } },
        });
      } else if (outcome === "preview") {
        expect(JSON.parse(stdout.text())).toMatchObject({
          dryRun: true,
          findingCount: 2,
        });
      }
    },
  );

  test("keeps required import output failures fatal", async () => {
    const { deps } = importDependencies();
    const stdout = new Writable({
      write(_chunk, _encoding, callback) {
        queueMicrotask(() =>
          callback(new Error("Synthetic import output failure")),
        );
      },
    });
    const stderr = capture();
    expect(
      await main(
        ["scan", "import", "--json", "findings.json", "--format", "json"],
        stdout,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Synthetic import output failure");
  });

  test.each(["completed", "failed"] as const)(
    "reports cleanup warnings without changing a %s import outcome",
    async (outcome) => {
      const { deps } = importDependencies();
      deps.importScan = async (_options, settings) => {
        settings?.onWarning?.("Synthetic scratch cleanup failure");
        if (outcome === "failed") throw new Error("Synthetic import failure");
        return fakeResult(["high", "high"]);
      };
      const { stdout, stderr, runCli } = createCliTest(main);
      expect(
        await runCli(
          ["scan", "import", "--json", "findings.json", "--format", "json"],
          deps,
        ),
      ).toBe(outcome === "failed" ? 2 : 0);
      expect(stderr.text()).toContain(
        "codex-security: warning: Synthetic scratch cleanup failure",
      );
      if (outcome === "failed") {
        expect(stderr.text()).toContain("Synthetic import failure");
      } else {
        expect(JSON.parse(stdout.text())).toMatchObject({
          manifest: { scan: { id: "scan" } },
        });
        expect(stderr.text()).toContain("Imported 2 findings as scan scan.");
      }
    },
  );

  test.each(["csv", "json"] as const)(
    "imports --%s while --format json controls output",
    async (format) => {
      const { deps, calls, result } = importDependencies();
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          [
            "scan",
            "import",
            `--${format}`,
            `inputs/findings.${format}`,
            "--output-dir",
            "saved scan",
            "--archive-existing",
            "--format",
            "json",
          ],
          deps,
        ),
      ).toBe(0);
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({
        sourcePath: resolve("workspace", `inputs/findings.${format}`),
        format,
        outputDir: resolve("workspace", "saved scan"),
        archiveExisting: true,
        dryRun: false,
        signal: expect.any(AbortSignal),
      });
      expect(JSON.parse(stdout.text())).toMatchObject({
        manifest: result.manifest,
        findings: result.findings,
      });
      expect(stderr.text()).toContain("Imported 2 findings as scan scan.");
    },
  );

  test.each([
    [["report.CSV"], "csv"],
    [["report.JSON"], "json"],
    [["report", "--input-format=json"], "json"],
    [["report.json", "--input-format", "csv"], "csv"],
    [["--json", "report"], "json"],
    [["--csv=--report.csv"], "csv"],
  ] as const)(
    "selects the input format for %j and emits JSON",
    async (args, format) => {
      const { deps, calls } = importDependencies();
      const { stdout, runCli } = createCliTest(main);
      expect(
        await runCli(["scan", "import", ...args, "--dry-run", "--json"], deps),
      ).toBe(0);
      expect(calls[0]?.format).toBe(format);
      expect(JSON.parse(stdout.text())).toMatchObject({ dryRun: true, format });
    },
  );

  test.each([
    { input: ["--", "--findings.json"], file: "--findings.json" },
    { input: ["--json", "findings"], file: "findings" },
  ])(
    "keeps JSON output before the import verb with $input",
    async ({ input, file }) => {
      const { deps, calls } = importDependencies();
      const { stdout, runCli } = createCliTest(main);
      expect(
        await runCli(["scan", "--json", "import", "--dry-run", ...input], deps),
      ).toBe(0);
      expect(calls[0]).toMatchObject({
        sourcePath: resolve("workspace", file),
        format: "json",
      });
      expect(JSON.parse(stdout.text())).toMatchObject({ dryRun: true });
    },
  );

  test("accepts equals input syntax and validates without saving", async () => {
    const { deps, calls } = importDependencies();
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(
        [
          "scan",
          "import",
          "--json=inputs/findings with spaces.json",
          "--dry-run",
          "--format=json",
        ],
        deps,
      ),
    ).toBe(0);
    expect(calls[0]).toMatchObject({ dryRun: true, format: "json" });
    expect(JSON.parse(stdout.text())).toEqual({
      dryRun: true,
      inputPath: resolve("workspace", "inputs/findings with spaces.json"),
      format: "json",
      findingCount: 2,
    });
    expect(stderr.text()).toBe("");
  });

  test("uses a concise singular summary for one imported finding", async () => {
    const { deps } = importDependencies(fakeResult(["high"]));
    const { stdout, stderr, runCli } = createCliTest(main);

    expect(
      await runCli(["scan", "import", "--json", "findings.json"], deps),
    ).toBe(0);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Imported 1 finding as scan scan.");
  });

  test.each([
    [[], "file"],
    [
      ["--csv", "findings.csv", "--json", "findings.json"],
      "Conflicting values for --input-format",
    ],
    [["--json"], "file"],
    [["--json", "--dry-run"], "file"],
    [["report"], "Use --input-format"],
    [
      ["--csv", "report", "--input-format", "json"],
      "Conflicting values for --input-format",
    ],
    [["--csv"], "Missing value for flag: --csv"],
    [["--json="], "--json must not be empty"],
    [
      ["--csv", "findings.csv", "extra"],
      "Unexpected positional argument for scan import",
    ],
    [
      ["--csv", "findings.csv", "--archive-existing"],
      "--archive-existing requires --output-dir",
    ],
  ])("rejects invalid import arguments %j", async (args, message) => {
    const { deps, calls } = importDependencies();
    const stderr = captureCli(main, "stderr");
    expect(await stderr.run(["scan", "import", ...args], deps)).toBe(2);
    expect(calls).toHaveLength(0);
    expect(stderr.text()).toContain(message);
  });

  test("exposes a positional file, an input format, and a separate JSON output option", async () => {
    const { deps, calls } = importDependencies();
    const help = captureCli(main, "stdout");
    expect(await help.run(["scan", "import", "--help"], deps)).toBe(0);
    expect(help.text()).toContain("FILE [options]");
    expect(help.text()).toContain("--input-format");
    expect(help.text()).toContain("--format json");
    const schema = captureCli(main, "stdout");
    expect(
      await schema.run(["scan", "import", "--schema", "--json"], deps),
    ).toBe(0);
    expect(JSON.parse(schema.text())).toMatchObject({
      args: { required: ["file"] },
      options: { properties: { inputFormat: { enum: ["csv", "json"] } } },
    });
    expect(calls).toHaveLength(0);
  });

  test.each([
    ["./import", "--json"],
    ["imports", "--json"],
    ["--json", "./import"],
  ])(
    "ordinary scan retains repository arguments and the JSON output shortcut (%s, %s)",
    async (first, second) => {
      const { stdout, runCli } = createCliTest(main);

      const onRun = mock();
      const deps = dependencies({
        onRun,
      });
      expect(await runCli(["scan", first, second], deps)).toBe(0);
      expect(onRun).toHaveBeenCalledTimes(1);
      expect(JSON.parse(stdout.text())).toMatchObject({
        manifest: { scan: { id: "scan" } },
      });
    },
  );

  test("preserves the global JSON shortcut before the scan command", async () => {
    const { deps, calls } = importDependencies();
    const stdout = captureCli(main, "stdout");
    expect(
      await stdout.run(
        ["--json", "scan", "import", "--csv", "findings.csv"],
        deps,
      ),
    ).toBe(0);
    expect(calls[0]?.format).toBe("csv");
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: "scan" } },
    });
  });

  test.each([
    { label: "shortcut", flags: ["--json"] },
    { label: "format value", flags: ["--format", "json"] },
    { label: "equals format", flags: ["--format=json"] },
  ])(
    "keeps an interleaved output $label separate from the JSON import file",
    async ({ flags }) => {
      const { deps, calls } = importDependencies();
      const { stdout, stderr, runCli } = createCliTest(main);

      expect(
        await runCli(
          ["scan", ...flags, "import", "--json", "dependencies", "--dry-run"],
          deps,
        ),
        stderr.text(),
      ).toBe(0);
      expect(calls).toHaveLength(1);
      expect(calls[0]).toMatchObject({
        sourcePath: resolve("workspace", "dependencies"),
        format: "json",
        dryRun: true,
      });
      expect(JSON.parse(stdout.text())).toMatchObject({
        dryRun: true,
        format: "json",
        findingCount: 2,
      });
    },
  );

  test("keeps a completed import successful if its summary cannot be written", async () => {
    const { deps, calls } = importDependencies();
    const stdout = capture();
    expect(
      await main(
        ["scan", "import", "--csv", "findings.csv", "--format", "json"],
        stdout.stream,
        {
          write: throwing("closed progress stream"),
        },
        deps,
      ),
    ).toBe(0);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: "scan" } },
    });
  });

  test.each(["12345678-1234-4234-8234-123456789abc", "12345678"])(
    "reruns imported scan %s from its retained source with the resolved parent UUID",
    async (selector) => {
      const scanId = "12345678-1234-4234-8234-123456789abc";
      const { deps, calls } = importDependencies();
      deps.runWorkbench = async (args) => {
        expect(args).toEqual(["get-scan-recipe", "--scan-id", selector]);
        return {
          scanId,
          recipe: {
            import: {
              format: "csv",
              sourcePath: resolve("retained", "source.csv"),
            },
          },
        };
      };
      const stdout = captureCli(main, "stdout");
      expect(
        await stdout.run(["scans", "rerun", selector, "--json"], deps),
      ).toBe(0);
      expect(calls[0]).toMatchObject({
        sourcePath: resolve("retained", "source.csv"),
        format: "csv",
        parentScanId: scanId,
      });
      expect(JSON.parse(stdout.text())).toMatchObject({
        manifest: { scan: { id: "scan" } },
      });
    },
  );

  test.each(["--validation-prompt-file", "--scan-prompt-file"])(
    "rejects %s when rerunning an imported scan",
    async (option) => {
      const { deps, calls } = importDependencies();
      deps.runWorkbench = async () => ({
        recipe: {
          import: {
            format: "csv",
            sourcePath: resolve("retained", "source.csv"),
          },
        },
      });
      const stderr = captureCli(main, "stderr");
      expect(
        await stderr.run(
          ["scans", "rerun", "previous-scan", option, "workflow.md"],
          deps,
        ),
      ).toBe(2);
      expect(stderr.text()).toContain(
        `${option} is not supported when rerunning an imported scan`,
      );
      expect(calls).toHaveLength(0);
    },
  );

  test("reports import errors without leaving signal handlers", async () => {
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.importScan = rejecting("Input JSON is not a findings document.");
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(["scan", "import", "--json", "findings.json"], deps),
    ).toBe(2);
    expect(stderr.text()).toBe(
      "codex-security: Input JSON is not a findings document.\n",
    );
    expect(signals.listeners.get("SIGINT")?.size).toBe(0);
    expect(signals.listeners.get("SIGTERM")?.size).toBe(0);
  });

  test.each([
    ["SIGINT", 130],
    ["SIGTERM", 143],
  ] as const)("cancels imports on %s", async (signal, status) => {
    const signals = new FakeSignals();
    const deps = dependencies({ signals });
    deps.importScan = async (options) => {
      signals.emit(signal);
      options.signal!.throwIfAborted();
      throw new Error("unreachable");
    };
    const stderr = captureCli(main, "stderr");
    expect(
      await stderr.run(["scan", "import", "--csv", "findings.csv"], deps),
    ).toBe(status);
    expect(stderr.text()).toContain("Scan import canceled.");
    expect(signals.listeners.get(signal)?.size).toBe(0);
  });
});
