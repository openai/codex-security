import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { expect, test } from "bun:test";
import { Formatter } from "incur";
import { parse as parseYaml } from "yaml";
import { loadContract } from "../src/index.js";
import { copyCompletedScan, PLUGIN_ROOT } from "./plugin-root.js";
import { runCommand } from "./support/shell.js";
import { temporaryDirectory } from "./support/temporary-directories.js";

const message = "Synthetic execution failure: token=SYNTHETIC_SAVED_FAILURE";
const commands = ["scan", "resume", "rerun"] as const;
const formats = ["json", "jsonl", "yaml", "toon", undefined] as const;

async function failedCommand(
  command: (typeof commands)[number],
  format: (typeof formats)[number],
  { fullOutput = true, invalid = false, controls = [] as string[] } = {},
) {
  const root = await temporaryDirectory("cli-saved-failure-format-");
  try {
    const scanDir = await copyCompletedScan(root);
    const contract = await loadContract(scanDir, { pluginRoot: PLUGIN_ROOT });
    const scanId = contract.manifest.scan.id;
    const originalManifest = await readFile(
      join(scanDir, "scan-manifest.json"),
    );
    if (invalid) await rm(join(scanDir, "findings.json"));
    const args = [
      ...(command === "scan" ? ["scan", root] : ["scans", command, scanId]),
      ...(format === undefined ? [] : ["--format", format]),
      ...(fullOutput ? ["--full-output"] : []),
      ...controls,
    ];
    const cliUrl = new URL("../src/cli.ts", import.meta.url).href;
    const fixtureUrl = new URL("./cli-fixtures.ts", import.meta.url).href;
    const script = `
      import { main } from ${JSON.stringify(cliUrl)};
      import { dependencies } from ${JSON.stringify(fixtureUrl)};
      const scan = ${JSON.stringify({ scanId, scanDir })};
      const deps = dependencies({
        currentDirectory: ${JSON.stringify(root)},
        onWorkbench: () => ({ ...scan, recipe: {
          repository: ${JSON.stringify(root)},
          target: { kind: "repository", paths: [] }, mode: "standard", config: {},
        }}),
        onTurn: (_repository, options) => options.onScanRegistered?.(scan),
        onRun: () => { throw new Error(${JSON.stringify(message)}); },
      });
      process.exitCode = await main(${JSON.stringify(args)}, process.stdout, process.stderr, deps);
    `;
    const result = await runCommand(process.execPath, ["-e", script], {
      cwd: root,
      timeout: 30_000,
    });
    expect(result.status, result.stderr).toBe(2);
    expect(result.signal).toBeNull();
    expect(result.stderr).toContain(message);
    expect(result.stderr).toContain(scanId);
    expect(await readFile(join(scanDir, "scan-manifest.json"))).toEqual(
      originalManifest,
    );
    return {
      ...result,
      data: { ...contract, scanDir, reportPath: join(scanDir, "report.md") },
    };
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test.each(
  commands.flatMap((command) => formats.map((format) => ({ command, format }))),
)(
  "retains saved $command execution results in full $format output",
  async ({ command, format }) => {
    const result = await failedCommand(command, format);
    if (format === "json" || format === "jsonl" || format === "yaml") {
      const output =
        format === "yaml"
          ? parseYaml(result.stdout)
          : JSON.parse(result.stdout);
      expect(output).toMatchObject({
        ok: false,
        error: { code: "SCAN_FAILED", message },
        data: result.data,
        meta: { command: command === "scan" ? "scan" : `scans ${command}` },
      });
      expect(output.data).toEqual(result.data);
    } else {
      expect(result.stdout).toStartWith("ok: false\n");
      expect(result.stdout).toContain(
        Formatter.format({ error: { code: "SCAN_FAILED", message } }, "toon"),
      );
      expect(result.stdout).toContain(
        Formatter.format({ data: result.data }, "toon"),
      );
      expect(result.stdout).toContain(
        `meta:\n  command: ${command === "scan" ? "scan" : `scans ${command}`}\n`,
      );
    }
  },
);

test.each(
  commands.flatMap((command) =>
    (["yaml", "toon"] as const).map((format) => ({ command, format })),
  ),
)(
  "keeps $command $format execution failures on stderr without full output",
  async ({ command, format }) => {
    const result = await failedCommand(command, format, { fullOutput: false });
    expect(result.stdout).toBe("");
  },
);

test.each(
  commands.flatMap((command) =>
    (["yaml", "toon"] as const).map((format) => ({ command, format })),
  ),
)(
  "preserves the $command $format execution error when retained data is invalid",
  async ({ command, format }) => {
    const result = await failedCommand(command, format, { invalid: true });
    expect(result.stdout).toBe("");
    expect(result.stderr).not.toContain("findings.json");
  },
);
