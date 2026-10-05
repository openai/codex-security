import { describe, expect, test } from "bun:test";
import { main } from "../src/cli.js";
import { DEFAULT_DEEP_SCAN_SETTINGS } from "../src/deep-scan-defaults.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { captureCli } from "./support/cli-run.js";

async function help(args: readonly string[], columns?: number) {
  const stdout = capture(true);
  const stderr = capture(true);
  const calls: string[] = [];
  const unexpected = (name: string): never => {
    calls.push(name);
    throw new Error(`Help must not call ${name}.`);
  };
  const deps = dependencies({
    onConfig: () => unexpected("createSecurity"),
    onCodex: () => unexpected("runCodex"),
    onWorkbench: () => unexpected("runWorkbench"),
    onRepositoryCommand: () => unexpected("runRepositoryCommand"),
    onUpdateCheck: async () => unexpected("checkForUpdate"),
  });
  deps.prepareAuthenticationHome = async () =>
    unexpected("prepareAuthenticationHome");
  deps.importScan = async () => unexpected("importScan");
  const code = await main(
    args,
    { ...stdout.stream, ...(columns === undefined ? {} : { columns }) },
    stderr.stream,
    deps,
  );
  expect(code).toBe(0);
  expect(stderr.text()).toBe("");
  expect(calls).toEqual([]);
  return stdout.text();
}

function option(helpText: string, flag: string): string {
  const lines = helpText.split("\n");
  const start = lines.findIndex((line) => line.startsWith(`  ${flag} `));
  if (start === -1) return "";
  let end = start + 1;
  while (
    end < lines.length &&
    lines[end]!.trim() !== "" &&
    !/^  --[a-z]/u.test(lines[end]!) &&
    /^\s/u.test(lines[end]!)
  ) {
    end += 1;
  }
  return lines.slice(start, end).join(" ").replace(/\s+/gu, " ");
}

describe("CLI help", () => {
  test("groups the common workflow ahead of setup and integrations", async () => {
    const text = await help(["--help"]);
    const sections = text.split(/\n(?=[A-Z][^\n]+:\n)/u);
    const sectionFor = (command: string) =>
      sections.findIndex((section) =>
        new RegExp(`^  ${command} {2,}`, "mu").test(section),
      );
    expect(sectionFor("scan")).toBeGreaterThanOrEqual(0);
    expect(sectionFor("patch")).toBe(sectionFor("scan"));
    expect(sectionFor("scans")).toBeGreaterThan(sectionFor("scan"));
    expect(sectionFor("findings")).toBe(sectionFor("scans"));
    expect(sectionFor("login")).toBeGreaterThan(sectionFor("scan"));
    expect(sectionFor("init")).toBe(sectionFor("login"));
    expect(sectionFor("completions")).toBeGreaterThan(sectionFor("scan"));
    expect(text).toContain("codex-security scan .");
    expect(text).toContain("<command> --help");
  });

  test("shows semantic values, repeatable inputs, choices, and scan defaults", async () => {
    const text = await help(["scan", "--help"]);
    expect(text).not.toMatch(/<(?:array|string|number)>/u);
    expect(option(text, "--path")).toContain("<path>");
    expect(option(text, "--path")).toMatch(/repeat/iu);
    expect(option(text, "--codex")).toContain("<key=value>");
    expect(option(text, "--codex")).toMatch(/repeat/iu);
    expect(option(text, "--max-cost")).toContain("<usd>");
    expect(option(text, "--mode")).toContain("<mode>");
    expect(option(text, "--mode")).toContain("standard");
    expect(option(text, "--mode")).toContain("deep");
    expect(option(text, "--provider")).toContain("amazon-bedrock");
    for (const [flag, value] of [
      ["--workers", DEFAULT_DEEP_SCAN_SETTINGS.workers],
      ["--subagents", DEFAULT_DEEP_SCAN_SETTINGS.subagents],
      ["--stop-after-no-new", DEFAULT_DEEP_SCAN_SETTINGS.stopAfterNoNew],
      ["--max-discovery-runs", DEFAULT_DEEP_SCAN_SETTINGS.maxDiscoveryRuns],
    ] as const) {
      expect(option(text, flag)).toMatch(
        new RegExp(`default: ${value}\\b`, "iu"),
      );
    }
  });

  test("uses repeatable flags and bare booleans in copyable examples", async () => {
    const scan = await help(["scan", "--help"]);
    expect(scan).toContain("--path src --path tests");
    expect(scan).toMatch(
      /^  codex-security scan \. --working-tree(?:\s+#.*)?$/mu,
    );
    const publish = await help(["publish", "scan", "--help"]);
    expect(publish).not.toMatch(/--dry-run true\b/u);
    expect(publish).toMatch(
      /^  codex-security publish scan .*--dry-run(?:\s+#.*)?$/mu,
    );
  });

  test.each([
    { command: ["scan"] },
    { command: ["scan", "import"] },
    { command: ["scans", "rerun"] },
  ])("advertises supported formats for $command", async ({ command }) => {
    const text = await help([...command, "--help"]);
    const format = option(text, "--format");
    expect(format).toContain("json");
    expect(format).not.toMatch(/\bmd\b/u);
    if (command[0] === "scan") {
      expect(option(text, "--filter-output")).toBe("");
    }
  });

  test.each(["validate", "login", "logout", "serve"])(
    "%s does not promise unsupported JSON command output",
    async (command) => {
      const text = await help([command, "--help"]);
      expect(option(text, "--format")).not.toMatch(/\bjsonl?\b/u);
      expect(option(text, "--json")).toBe("");
      const schema = captureCli(main, "stdout");
      expect(
        await schema.run([command, "--schema", "--json"], dependencies()),
      ).toBe(0);
      expect(JSON.parse(schema.text())).toEqual(expect.any(Object));
    },
  );

  test("documents raw export formats without promising output transforms", async () => {
    const text = await help(["export", "--help"]);
    expect(option(text, "--export-format")).toContain("<format>");
    for (const flag of [
      "--format",
      "--json",
      "--filter-output",
      "--full-output",
      "--token-count",
      "--token-limit",
      "--token-offset",
    ]) {
      expect(option(text, flag)).toBe("");
    }
    const schema = await help(["export", "--schema", "--json"]);
    expect(JSON.parse(schema)).toMatchObject({
      options: {
        properties: {
          artifact: { enum: ["findings", "threat-model"], default: "findings" },
          exportFormat: { enum: ["csv", "json", "sarif", "md"] },
        },
      },
    });
  });

  test("distinguishes JSON file import from JSON output", async () => {
    const text = await help(["scan", "import", "--help"]);
    expect(option(text, "--json")).toContain("<file>");
    expect(option(text, "--csv")).toContain("<file>");
    expect(text.replace(/\s+/gu, " ")).toContain("--format json");
    expect(option(text, "--format")).toContain("json");
  });

  test.each([
    { args: ["-h"], usage: "codex-security <command>" },
    { args: ["--help", "scan"], usage: "codex-security scan [repository]" },
    {
      args: ["scan", "--mode", "bogus", "--help"],
      usage: "codex-security scan [repository]",
    },
    {
      args: ["scan", "--config", "missing.yaml", "--help"],
      usage: "codex-security scan [repository]",
    },
    {
      args: ["scan", "import", "--json", "--help"],
      usage: "codex-security scan import",
    },
    {
      args: ["--format", "json", "scan", "import", "--help"],
      usage: "codex-security scan import",
    },
    { args: ["scans", "--help"], usage: "codex-security scans [command]" },
    {
      args: ["findings", "--help"],
      usage: "codex-security findings [command]",
    },
    { args: ["login", "status", "--help"], usage: "codex-security login" },
    { args: ["unknown", "--help"], usage: "codex-security <command>" },
  ])("preserves help routing for $args", async ({ args, usage }) => {
    const text = await help(args);
    expect(text).toContain(`Usage: ${usage}`);
  });

  test.each([
    { command: ["mcp"] },
    { command: ["mcp", "add"] },
    { command: ["skills"] },
    { command: ["skills", "list"] },
    { command: ["completions"] },
  ])("retains framework help for $command", async ({ command }) => {
    const text = await help([...command, "--help"]);
    expect(text).toContain(`Usage: codex-security ${command.join(" ")}`);
    if (command[0] === "skills") {
      expect(text).toMatch(
        command.length === 1 ? /^Aliases: skill$/mu : /^Aliases: ls$/mu,
      );
    }
    if (command[0] === "completions") {
      for (const shell of ["bash", "fish", "nushell", "zsh"]) {
        expect(text).toContain(shell);
      }
    }
  });

  test.each([60, 80])(
    "wraps descriptions at %i columns without breaking examples",
    async (columns) => {
      for (const command of [
        [],
        ["scan"],
        ["publish", "scan"],
        ["scan", "import"],
      ]) {
        const text = await help([...command, "--help"], columns);
        expect(text).not.toMatch(/\u001b\[/u);
        for (const line of text.split("\n")) {
          if (line.startsWith("  codex-security ")) continue;
          const indent = line.length - line.trimStart().length;
          const longestToken = Math.max(
            ...line
              .trim()
              .split(/\s+/u)
              .map((word) => word.length),
          );
          expect(line.length, line).toBeLessThanOrEqual(
            Math.max(columns, indent + longestToken),
          );
        }
      }
      const text = await help(["scan", "--help"], columns);
      expect(text).toMatch(/^  codex-security scan \.(?:\s+#.*)?$/mu);
    },
  );
});
