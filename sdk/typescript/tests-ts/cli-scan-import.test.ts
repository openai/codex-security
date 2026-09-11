import { resolve } from "node:path";
import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import {
  capture,
  dependencies,
  fakeResult,
  FakeSignals,
} from "./cli-fixtures.js";

function importDependencies() {
  const deps = dependencies({
    currentDirectory: resolve("workspace"),
    onConfig: () => {
      throw new Error("Import must not create a model client");
    },
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
          findingCount: 2,
        }
      : fakeResult(["high", "high"]);
  };
  return { deps, calls };
}

describe("scan import", () => {
  test.each(["csv", "json"] as const)(
    "imports --%s while --format json controls output",
    async (format) => {
      const { deps, calls } = importDependencies();
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
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
          stdout.stream,
          stderr.stream,
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
        manifest: { scan: { id: "scan" } },
        findings: {
          findings: [
            { severity: { level: "high" } },
            { severity: { level: "high" } },
          ],
        },
      });
      expect(stderr.text()).toContain("Imported 2 findings as scan scan.");
    },
  );

  test("accepts equals input syntax and validates without saving", async () => {
    const { deps, calls } = importDependencies();
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        [
          "scan",
          "import",
          "--json=inputs/findings with spaces.json",
          "--dry-run",
          "--format=json",
        ],
        stdout.stream,
        stderr.stream,
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

  test("uses a concise summary for default output", async () => {
    const { deps } = importDependencies();
    const stdout = capture();
    const stderr = capture();
    expect(
      await main(
        ["scan", "import", "--json", "findings.json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(stdout.text()).toBe("");
    expect(stderr.text()).toContain("Imported 2 findings as scan scan.");
  });

  test.each([
    [[], "exactly one"],
    [["--csv", "findings.csv", "--json", "findings.json"], "exactly one"],
    [["--json"], "Missing value for flag: --json"],
    [["--json", "--dry-run"], "Missing value for flag: --json"],
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
    const stderr = capture();
    expect(
      await main(
        ["scan", "import", ...args],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(calls).toHaveLength(0);
    expect(stderr.text()).toContain(message);
  });

  test("exposes both source flags in help and schemas", async () => {
    const { deps, calls } = importDependencies();
    const help = capture();
    expect(
      await main(
        ["scan", "import", "--help"],
        help.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(help.text()).toContain("--csv <string>");
    expect(help.text()).toContain("--json <string>");
    expect(help.text()).toContain("--format json");
    const schema = capture();
    expect(
      await main(
        ["scan", "import", "--schema", "--format", "json"],
        schema.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(JSON.parse(schema.text())).toMatchObject({
      options: {
        properties: { csv: { type: "string" }, json: { type: "string" } },
      },
    });
    expect(calls).toHaveLength(0);
  });

  test("ordinary scan retains repository arguments and the --json output shortcut", async () => {
    const stdout = capture();
    const stderr = capture();
    let scans = 0;
    const deps = dependencies({
      onRun: () => {
        scans += 1;
      },
    });
    expect(
      await main(
        ["scan", "./import", "--json"],
        stdout.stream,
        stderr.stream,
        deps,
      ),
    ).toBe(0);
    expect(scans).toBe(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: "scan" } },
    });
  });

  test("preserves the global JSON shortcut before the scan command", async () => {
    const { deps, calls } = importDependencies();
    const stdout = capture();
    expect(
      await main(
        ["--json", "scan", "import", "--csv", "findings.csv"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls[0]?.format).toBe("csv");
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: "scan" } },
    });
  });

  test("keeps a completed import successful if its summary cannot be written", async () => {
    const { deps, calls } = importDependencies();
    const stdout = capture();
    expect(
      await main(
        ["scan", "import", "--csv", "findings.csv", "--format", "json"],
        stdout.stream,
        {
          write() {
            throw new Error("closed progress stream");
          },
        },
        deps,
      ),
    ).toBe(0);
    expect(calls).toHaveLength(1);
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: "scan" } },
    });
  });

  test("reruns an imported scan from its retained source", async () => {
    const { deps, calls } = importDependencies();
    deps.runWorkbench = async (args) => {
      expect(args).toEqual(["get-scan-recipe", "--scan-id", "previous-scan"]);
      return {
        recipe: {
          import: {
            format: "csv",
            sourcePath: resolve("retained", "source.csv"),
          },
        },
      };
    };
    const stdout = capture();
    expect(
      await main(
        ["scans", "rerun", "previous-scan", "--json"],
        stdout.stream,
        capture().stream,
        deps,
      ),
    ).toBe(0);
    expect(calls[0]).toMatchObject({
      sourcePath: resolve("retained", "source.csv"),
      format: "csv",
      parentScanId: "previous-scan",
    });
    expect(JSON.parse(stdout.text())).toMatchObject({
      manifest: { scan: { id: "scan" } },
    });
  });

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
      const stderr = capture();
      expect(
        await main(
          ["scans", "rerun", "previous-scan", option, "workflow.md"],
          capture().stream,
          stderr.stream,
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
    deps.importScan = async () => {
      throw new Error("Input JSON is not a findings document.");
    };
    const stderr = capture();
    expect(
      await main(
        ["scan", "import", "--json", "findings.json"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(2);
    expect(stderr.text()).toContain("Input JSON is not a findings document.");
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
    const stderr = capture();
    expect(
      await main(
        ["scan", "import", "--csv", "findings.csv"],
        capture().stream,
        stderr.stream,
        deps,
      ),
    ).toBe(status);
    expect(stderr.text()).toContain("Scan import canceled.");
    expect(signals.listeners.get(signal)?.size).toBe(0);
  });
});
