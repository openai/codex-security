import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { Cli, Schema, z } from "incur";
import { main } from "../src/cli.js";
import {
  commandResultRestrictions,
  fullMarkdownManifestArguments,
  INCUR_VALUE_OPTIONS,
  parseIncurArguments,
  PATCH_STRUCTURED_OUTPUT_RESTRICTION,
  renderFullMarkdownManifest,
  validateCommandResultOptions,
} from "../src/cli-manifest.js";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "../src/config.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "../src/version.js";
import { capture, dependencies, fakeResult } from "./cli-fixtures.js";

interface ObjectSchema {
  properties?: Record<string, z.core.JSONSchema.JSONSchema>;
  required?: string[];
}

interface Command {
  name: string;
  schema?: {
    args?: ObjectSchema;
    options?: ObjectSchema;
    output?: ObjectSchema;
  };
  examples?: { command: string }[];
}

interface Manifest {
  version: string;
  commands: Command[];
}

function documentationDependencies() {
  const unexpected = (): never => {
    throw new Error("Documentation must not run a command or access state.");
  };
  const deps = dependencies({
    environment: {
      OPENAI_API_KEY: "SYNTHETIC_MANIFEST_KEY",
      CODEX_SECURITY_STATE_DIR: "/synthetic/private-state",
    },
  });
  deps.createSecurity = unexpected;
  deps.prepareAuthenticationHome = unexpected;
  deps.hasStoredChatGPTSignIn = unexpected;
  deps.currentDirectory = unexpected;
  deps.runCodex = unexpected;
  deps.runWorkbench = unexpected;
  deps.linearClient = unexpected;
  deps.matchFindings = unexpected;
  deps.exportFindings = unexpected;
  deps.publishScan = unexpected;
  deps.checkForUpdate = unexpected;
  return deps;
}

async function invoke(args: readonly string[]): Promise<string> {
  const stdout = capture();
  const stderr = capture(true);
  expect(
    await main(args, stdout.stream, stderr.stream, documentationDependencies()),
  ).toBe(0);
  expect(stderr.text()).toBe("");
  expect(stdout.text()).not.toContain("SYNTHETIC_MANIFEST_KEY");
  expect(stdout.text()).not.toContain("/synthetic/private-state");
  return stdout.text();
}

async function readManifest(args: readonly string[] = []): Promise<Manifest> {
  return JSON.parse(
    await invoke([...args, "--llms-full", "--format", "json"]),
  ) as Manifest;
}

function commandSections(markdown: string): Map<string, string> {
  return new Map(
    markdown
      .split(/^### codex-security /mu)
      .slice(1)
      .map((section) => {
        const newline = section.indexOf("\n");
        return [section.slice(0, newline), section.slice(newline + 1)];
      }),
  );
}

function flag(name: string): string {
  return `--${name.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`)}`;
}

describe("full CLI manifest", () => {
  test("documents every live command, argument, option, and allowed value", async () => {
    const manifest = await readManifest();
    const markdown = await invoke(["--llms-full"]);
    const sections = commandSections(markdown);

    expect(manifest.version).toBe("incur.v1");
    expect([...sections.keys()]).toEqual(
      manifest.commands.map(({ name }) => name),
    );
    expect(markdown).not.toMatch(/--[a-z][a-z0-9-]*[A-Z][A-Za-z0-9-]*/u);

    for (const command of manifest.commands) {
      const section = sections.get(command.name)!;
      for (const [name, field] of Object.entries(
        command.schema?.args?.properties ?? {},
      )) {
        const row = section
          .split("\n")
          .find((line) => line.startsWith(`| \`${name}\` |`));
        expect(row).toBeDefined();
        expect(row).toContain(field.description!);
        const required =
          command.schema?.args?.required?.includes(name) === true;
        expect(row!.split("|")[3]?.trim()).toBe(required ? "yes" : "no");
      }
      for (const [name, field] of Object.entries(
        command.schema?.options?.properties ?? {},
      )) {
        const row = section
          .split("\n")
          .find((line) => line.startsWith(`| \`${flag(name)}\` |`));
        expect(row).toBeDefined();
        expect(row).toContain(field.description!);
        expect(row!.includes("**Deprecated.**")).toBe(
          field.deprecated === true,
        );
        const details = row!.slice(
          row!.indexOf(field.description!) + field.description!.length,
        );
        const schemas = [field];
        if (typeof field.items === "object" && !Array.isArray(field.items)) {
          schemas.push(field.items);
        }
        for (const schema of schemas) {
          for (const value of schema.enum ??
            (schema.const === undefined ? [] : [schema.const])) {
            expect(details).toContain(`\`${String(value)}\``);
          }
          if (schema.pattern !== undefined) {
            expect(details).toContain(`\`${schema.pattern}\``);
          }
          for (const constraint of [
            "minimum",
            "exclusiveMinimum",
            "maximum",
            "exclusiveMaximum",
            "minLength",
            "maxLength",
          ] as const) {
            if (typeof schema[constraint] === "number") {
              expect(details).toContain(String(schema[constraint]));
            }
          }
        }
        const required =
          command.schema?.options?.required?.includes(name) === true &&
          field.default === undefined;
        expect(/\brequired\b/iu.test(details)).toBe(required);
      }
      for (const example of command.examples ?? []) {
        expect(section).toContain(`codex-security ${example.command}`);
      }
    }

    expect(sections.get("info")).toContain("| `sdkVersion` |");
    expect(sections.get("bulk-scan")).toContain(
      "--output-dir /path/outside/repositories/results",
    );
  });

  test("includes current metadata and the packaged operating guide", async () => {
    const markdown = await invoke(["--llms-full"]);
    const readme = (
      await readFile(new URL("../README.md", import.meta.url), "utf8")
    ).replace(/\r\n/gu, "\n");
    for (const title of [
      "Install",
      "Authentication",
      "CLI",
      "Local security model",
    ]) {
      const heading = `## ${title}\n`;
      const start = readme.indexOf(heading);
      expect(start).toBeGreaterThanOrEqual(0);
      const end = readme.indexOf("\n## ", start + heading.length);
      expect(markdown).toContain(
        readme.slice(start, end < 0 ? undefined : end).trim(),
      );
    }
    for (const title of [
      "Run a scan from TypeScript",
      "Containerized bulk scans",
    ]) {
      expect(markdown).not.toContain(`\n## ${title}\n`);
    }
    const defaults = scanModelConfiguration(DEFAULT_CODEX_CONFIG);
    for (const value of [
      VERSION,
      BUNDLED_PLUGIN_VERSION,
      CODEX_EXECUTABLE_VERSION,
      CODEX_SDK_VERSION,
      defaults.model,
      defaults.reasoningEffort,
      "--schema",
      "--mcp",
      "completions",
      "## Global options and integrations",
      "## Command groups",
      "## Command reference",
    ]) {
      expect(markdown).toContain(value);
    }
    for (const key of [...Object.keys(fakeResult().toJSON()), "warnings"]) {
      expect(markdown).toContain(`\`${key}\``);
    }
  });

  test("preserves descriptions for selected command groups", () => {
    const descriptions = {
      first: "First group metadata.",
      nested: "Nested group metadata.",
      second: "Second group metadata.",
    };
    const cli = Cli.create("sample")
      .command(
        Cli.create("first", { description: descriptions.first })
          .command("show", { run() {} })
          .command(
            Cli.create("nested", { description: descriptions.nested }).command(
              "show",
              { run() {} },
            ),
          ),
      )
      .command(
        Cli.create("second", { description: descriptions.second }).command(
          "show",
          { run() {} },
        ),
      );
    const commands = ["first show", "first nested show", "second show"].map(
      (name) => ({ name }),
    );
    const full = renderFullMarkdownManifest(cli, { commands });
    for (const description of Object.values(descriptions)) {
      expect(full).toContain(description);
    }
    const scoped = renderFullMarkdownManifest(
      cli,
      {
        commands: [{ name: "first nested show" }],
      },
      ["first", "nested"],
    );
    expect(scoped).toContain(descriptions.first);
    expect(scoped).toContain(descriptions.nested);
    expect(scoped).not.toContain(descriptions.second);
  });

  test("preserves group and leaf discovery without executing handlers", async () => {
    const root = await readManifest();
    const groups = new Set(
      root.commands.flatMap(({ name }) =>
        name.includes(" ") ? [name.split(" ")[0]!] : [],
      ),
    );
    for (const group of groups) {
      const expected = root.commands.filter(({ name }) =>
        name.startsWith(`${group} `),
      );
      expect((await readManifest([group])).commands).toEqual(expected);
      const short = JSON.parse(
        await invoke([group, "--llms", "--json"]),
      ) as Manifest;
      expect(short.commands.map(({ name }) => name)).toEqual(
        expected.map(({ name }) => name),
      );
      const markdown = await invoke([group, "--llms-full"]);
      expect(markdown).toStartWith(`# codex-security ${group}\n`);
      expect(markdown).not.toContain("\n## Authentication\n");
      expect([...commandSections(markdown).keys()]).toEqual(
        expected.map(({ name }) => name),
      );
    }
    for (const command of root.commands) {
      const args = command.name.split(" ");
      expect((await readManifest(args)).commands).toEqual([command]);
      const markdown = await invoke([...args, "--llms-full", "--format=md"]);
      expect(markdown).toStartWith(`# codex-security ${command.name}\n`);
      expect(markdown).not.toContain("\n## Authentication\n");
      expect([...commandSections(markdown).keys()]).toEqual([command.name]);
    }
  });

  test("includes bulk-scan output restrictions in scoped discovery", async () => {
    const stderr = capture();
    expect(
      await main(
        ["bulk-scan", "--output-dir", "results"],
        capture().stream,
        stderr.stream,
        dependencies(),
      ),
    ).toBe(2);

    const restriction = stderr
      .text()
      .replace(/^codex-security:\s*/u, "")
      .trim();
    expect(restriction).toContain("--output-dir");
    expect(restriction).toContain("repository CSV");
    expect(await invoke(["bulk-scan", "--llms-full"])).toContain(restriction);
  });

  test.each([
    ["scan-components", ["--output-dir", "synthetic-output"]],
    [
      "scan-components",
      ["--output-dir", "synthetic-output", "--auto", "--component", "src"],
    ],
    ["publish check", ["synthetic-scan", "--to", "linear"]],
    [
      "publish check",
      [
        "synthetic-scan",
        "--to",
        "linear",
        "--linear-assignee",
        "synthetic-user",
      ],
    ],
    [
      "publish check",
      [
        "synthetic-scan",
        "--to",
        "linear",
        "--linear-team",
        "synthetic-team",
        "--linear-project",
        "first",
        "--project",
        "second",
      ],
    ],
    [
      "publish scan",
      ["synthetic-scan", "--to", "linear", "--scan", "synthetic-id"],
    ],
    [
      "publish scan",
      [
        "--scan-dir",
        "synthetic-scan",
        "--to",
        "linear",
        "--scan",
        "synthetic-id",
      ],
    ],
    [
      "publish scan",
      ["synthetic-scan", "--to", "linear", "--csv", "synthetic.csv"],
    ],
    [
      "publish scan",
      ["--scan", "synthetic-id", "--to", "linear", "--csv", "synthetic.csv"],
    ],
  ] as const)(
    "documents the runtime requirement for %s %j",
    async (command, args) => {
      const stderr = capture();
      expect(
        await main(
          [...command.split(" "), ...args],
          capture().stream,
          stderr.stream,
          dependencies({ environment: {} }),
        ),
      ).toBe(2);
      const restriction = stderr
        .text()
        .split("\n", 1)[0]!
        .replace(/^codex-security:\s*/u, "")
        .trim();
      expect(restriction).not.toBe("");
      expect(restriction).not.toContain("[redacted]");
      expect(await invoke([...command.split(" "), "--llms-full"])).toContain(
        restriction,
      );
    },
  );

  test("keeps built-in operands out of the shared command-argument view", () => {
    for (const [option, value] of [
      ["--format", "md"],
      ["--filter-output", "scan"],
      ["--token-limit", "100000"],
      ["--token-offset", "0"],
    ] as const) {
      expect(
        parseIncurArguments([option, value, "scans", "show", "--llms-full"]),
      ).toEqual({
        commandArguments: ["scans", "show"],
        commandIndex: 2,
        format: option === "--format" ? value : undefined,
      });
    }
    expect(
      parseIncurArguments([
        "scans",
        "compare",
        "before",
        "after",
        "--filter-output",
        "summary",
      ]),
    ).toEqual({
      commandArguments: ["scans", "compare", "before", "after"],
      commandIndex: 0,
      format: undefined,
    });
  });

  test("preserves scoped paths when global discovery flags come first or between commands", async () => {
    for (const args of [
      ["--llms-full", "--format", "md", "scans", "show"],
      ["--filter-output", "scan", "scans", "show", "--llms-full"],
      ["--filter-output=scan", "scans", "show", "--llms-full"],
      ["--token-limit=100000", "scans", "show", "--llms-full"],
      ["scans", "--token-offset=0", "show", "--llms-full"],
    ]) {
      const markdown = await invoke(args);
      expect(markdown).toStartWith("# codex-security scans show\n");
      expect([...commandSections(markdown).keys()]).toEqual(["scans show"]);
      expect(markdown).not.toContain("\n## Authentication\n");
    }
    expect(
      await invoke(["--filter-output", "scan", "--llms-full"]),
    ).toStartWith("# codex-security\n");
  });

  test("applies token controls to the generated Markdown reference", async () => {
    const count = await invoke(["--llms-full", "--token-count"]);
    expect(Number(count.trim())).toBeGreaterThan(0);
    const scopedCount = await invoke([
      "scans",
      "--llms-full",
      "--token-count",
      "show",
    ]);
    expect(Number(scopedCount.trim())).toBeGreaterThan(0);
    expect(Number(scopedCount.trim())).toBeLessThan(Number(count.trim()));

    const limited = await invoke(["--llms-full", "--token-limit", "1"]);
    expect(limited).toContain("[truncated: showing tokens 0–1 of ");
    expect(limited.length).toBeLessThan((await invoke(["--llms-full"])).length);
  });

  test("keeps schema discovery separate from execution-only format checks", async () => {
    const schema = JSON.parse(
      await invoke(["export", "--schema", "--format", "json"]),
    );
    expect(
      JSON.parse(
        await invoke([
          "export",
          "--schema",
          "--format",
          "json",
          "--output",
          "-",
          "--export-format",
          "csv",
        ]),
      ),
    ).toEqual(schema);
  });

  test("rejects missing or empty global values before discovery", async () => {
    const rejectsMissingValue = async (
      args: readonly string[],
      option: string,
    ) => {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          args,
          stdout.stream,
          stderr.stream,
          documentationDependencies(),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).toContain(`Missing value for flag: ${option}`);
    };
    for (const option of INCUR_VALUE_OPTIONS) {
      await rejectsMissingValue([option], option);
      await rejectsMissingValue([option, "", "scans", "--llms-full"], option);
    }
    await rejectsMissingValue(
      ["scans", "--llms-full", "--format="],
      "--format",
    );
    for (const command of ["scan", "logout"]) {
      for (const discovery of ["--llms", "--llms-full", "--schema"]) {
        await rejectsMissingValue(
          [command, "--filter-output", discovery],
          "--filter-output",
        );
      }
    }
  });

  test("delegates partial shell-completion words without command validation", async () => {
    const original = {
      COMPLETE: process.env["COMPLETE"],
      _COMPLETE_INDEX: process.env["_COMPLETE_INDEX"],
    };
    try {
      process.env["COMPLETE"] = "bash";
      for (const option of INCUR_VALUE_OPTIONS) {
        for (const suffix of [[option], [option, ""]]) {
          const words = ["codex-security", ...suffix];
          process.env["_COMPLETE_INDEX"] = String(words.length - 1);
          await invoke(["--", ...words]);
        }
      }
      process.env["_COMPLETE_INDEX"] = "3";
      const completions = await invoke([
        "--",
        "codex-security",
        "--format=json",
        "scan",
        "--mo",
      ]);
      expect(completions).toContain("--model");
      expect(completions).toContain("--mode");
    } finally {
      for (const [name, value] of Object.entries(original)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  });

  test("honors explicit output formats without rewriting structured manifests", async () => {
    const markdown = await invoke(["scan", "--llms-full"]);
    for (const format of [
      ["--format", "md"],
      ["--format=md"],
      ["--json", "--format", "md"],
    ]) {
      expect(await invoke(["scan", "--llms-full", ...format])).toBe(markdown);
    }
    const manifest = await readManifest(["scan"]);
    expect(
      JSON.parse(
        await invoke(["scan", "--llms-full", "--format", "md", "--json"]),
      ),
    ).toEqual(manifest);
    expect(manifest.commands[0]?.schema?.options?.properties).toHaveProperty(
      "outputDir",
    );
    expect(
      manifest.commands[0]?.schema?.options?.properties,
    ).not.toHaveProperty("output-dir");
    expect(
      fullMarkdownManifestArguments(["--llms-full", "--mcp"]),
    ).toBeUndefined();
  });

  test("does not mutate the schemas used by the command parser", () => {
    const options = z.object({
      requiredValue: z.string().min(1),
      defaultValue: z.enum(["one", "two"]).default("one"),
    });
    const before = Schema.toJsonSchema(options);
    const cli = Cli.create("sample").command("show", {
      options,
      run() {},
    });
    const markdown = renderFullMarkdownManifest(cli, {
      commands: [{ name: "show" }],
    });
    expect(markdown).toContain("--required-value");
    expect(markdown).toContain("--default-value");
    expect(Schema.toJsonSchema(options)).toEqual(before);
    expect(options.parse({ requiredValue: "value" })).toEqual({
      requiredValue: "value",
      defaultValue: "one",
    });
  });

  test("keeps unsupported result formats rejected", async () => {
    for (const args of [
      ["scan", "--format", "md"],
      ["scan", "--filter-output", "findings"],
      ["validate", "--json"],
      ["patch", "--format", "jsonl"],
      ["login", "--json"],
      ["logout", "--json"],
      ["serve", "--json"],
    ]) {
      const stdout = capture();
      const stderr = capture();
      expect(
        await main(
          args,
          stdout.stream,
          stderr.stream,
          documentationDependencies(),
        ),
      ).toBe(2);
      expect(stdout.text()).toBe("");
      expect(stderr.text()).not.toBe("");
    }
  });

  test("documents the same result restrictions that the wrapper enforces", () => {
    const names = [
      "scan",
      "validate",
      "patch",
      "login",
      "logout",
      "serve",
      "export",
      "info",
    ];
    const cli = Cli.create("codex-security");
    for (const name of names) {
      cli.command(name, {
        run() {
          throw new Error("Manifest rendering must not run a command.");
        },
      });
    }
    const root = renderFullMarkdownManifest(cli, {
      commands: names.map((name) => ({ name })),
    });
    const sections = commandSections(root);
    for (const [command, args] of [
      ["scan", ["scan", "--format", "md"]],
      ["scan", ["scan", "--filter-output", "findings"]],
      ["validate", ["validate", "--json"]],
      ["login", ["login", "--json"]],
      ["logout", ["logout", "--json"]],
      ["serve", ["serve", "--json"]],
      [
        "export",
        ["export", "--json", "--output", "-", "--export-format", "csv"],
      ],
      ["info", ["info", "--filter-output", "findings"]],
    ] as const) {
      const restriction = validateCommandResultOptions(command, args);
      expect(restriction).toBeDefined();
      expect(commandResultRestrictions(command)).toContain(restriction!);
      expect(sections.get(command)).toContain(restriction!);
      const scoped = renderFullMarkdownManifest(
        cli,
        { commands: [{ name: command }] },
        [command],
      );
      expect(scoped).toContain(restriction!);
    }
    expect(
      validateCommandResultOptions("patch", ["patch", "--format", "jsonl"]),
    ).toBeUndefined();
    expect(commandResultRestrictions("patch")).toContain(
      PATCH_STRUCTURED_OUTPUT_RESTRICTION,
    );
    expect(sections.get("patch")).toContain(
      PATCH_STRUCTURED_OUTPUT_RESTRICTION,
    );
  });
});
