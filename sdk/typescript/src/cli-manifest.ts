import { readFileSync } from "node:fs";
import { Cli, Help, Skill, z } from "incur";
import { DEFAULT_CODEX_CONFIG, scanModelConfiguration } from "./config.js";
import {
  BUNDLED_PLUGIN_VERSION,
  CODEX_EXECUTABLE_VERSION,
  CODEX_SDK_VERSION,
  VERSION,
} from "./version.js";

interface Manifest {
  commands: { name: string }[];
}

const INCUR_FLAGS = new Set([
  "--full-output",
  "--llms",
  "--llms-full",
  "--mcp",
  "--help",
  "-h",
  "--version",
  "--schema",
  "--token-count",
]);
export const INCUR_VALUE_OPTIONS = new Set([
  "--format",
  "--filter-output",
  "--token-limit",
  "--token-offset",
]);

export const INFO_OUTPUT_SCHEMA = z.object({
  sdkVersion: z.string().describe("Codex Security package version."),
  bundledPluginVersion: z.string().describe("Bundled security plugin version."),
  scanMcp: z
    .literal(false)
    .describe("Whether scans are available over MCP; always false."),
  cancellationNote: z.string().describe("Why scans are CLI-only."),
  cliVersion: z.string().describe("Codex Security CLI version."),
  codexVersion: z.string().describe("Bundled Codex executable version."),
  codexSdkVersion: z.string().describe("Bundled Codex SDK version."),
  model: z.string().describe("Default scan model."),
  reasoningEffort: z.string().describe("Default scan reasoning effort."),
  nextStep: z.string().describe("Suggested first local preflight command."),
});

const INFO_METADATA_FIELDS = new Set(Object.keys(INFO_OUTPUT_SCHEMA.shape));
export const SCAN_MARKDOWN_RESULT_RESTRICTION =
  "Markdown output is not supported for scan results.";
export const PATCH_STRUCTURED_OUTPUT_RESTRICTION =
  "JSON and JSONL patch output require a saved finding identifier, --scan, or --resume-pr.";

interface CommandResultRule {
  commands: readonly string[];
  message(command: string): string;
  rejects?(argv: readonly string[]): boolean;
}

function hasOptionValue(
  argv: readonly string[],
  option: string,
  value: string,
): boolean {
  return argv.some(
    (argument, index) =>
      argument === `${option}=${value}` ||
      (argument === option && argv[index + 1] === value),
  );
}

function structuredOutputRequested(argv: readonly string[]): boolean {
  return (
    argv.includes("--json") ||
    hasOptionValue(argv, "--format", "json") ||
    hasOptionValue(argv, "--format", "jsonl")
  );
}

const COMMAND_RESULT_RULES: readonly CommandResultRule[] = [
  {
    commands: ["validate", "login", "logout", "serve"],
    message: (command) =>
      `${command} does not support noninteractive JSON output; run it without --json, --format json, or --format jsonl.`,
    rejects: structuredOutputRequested,
  },
  {
    commands: ["patch"],
    message: () => PATCH_STRUCTURED_OUTPUT_RESTRICTION,
  },
  {
    commands: ["export"],
    message: () =>
      "CSV stdout cannot be combined with JSON output; write CSV to a file or omit --json.",
    rejects: (argv) =>
      structuredOutputRequested(argv) &&
      hasOptionValue(argv, "--output", "-") &&
      hasOptionValue(argv, "--export-format", "csv"),
  },
  {
    commands: ["scan"],
    message: () => "--filter-output is not supported for scan results.",
    rejects: (argv) =>
      argv.some(
        (argument) =>
          argument === "--filter-output" ||
          argument.startsWith("--filter-output="),
      ),
  },
  {
    commands: ["scan"],
    message: () => SCAN_MARKDOWN_RESULT_RESTRICTION,
    rejects: (argv) => hasOptionValue(argv, "--format", "md"),
  },
  {
    commands: ["info"],
    message: () => "--filter-output must select an info metadata field.",
    rejects: (argv) =>
      argv.some((argument, index) => {
        if (
          argument !== "--filter-output" &&
          !argument.startsWith("--filter-output=")
        ) {
          return false;
        }
        const selector = argument.includes("=")
          ? argument.slice(argument.indexOf("=") + 1)
          : argv[index + 1];
        return (
          selector !== undefined &&
          !selector.split(",").every((field) => INFO_METADATA_FIELDS.has(field))
        );
      }),
  },
];

function commandResultRules(command: string): CommandResultRule[] {
  const root = command.split(" ", 1)[0]!;
  return COMMAND_RESULT_RULES.filter((rule) => rule.commands.includes(root));
}

export function commandResultRestrictions(command: string): string[] {
  const root = command.split(" ", 1)[0]!;
  return commandResultRules(command).map((rule) => rule.message(root));
}

export function validateCommandResultOptions(
  command: string,
  argv: readonly string[],
): string | undefined {
  const root = command.split(" ", 1)[0]!;
  return commandResultRules(command)
    .find((rule) => rule.rejects?.(argv) === true)
    ?.message(root);
}

/** Keep command lookup aligned with Incur's built-in option consumption. */
export function parseIncurArguments(argv: readonly string[]): {
  commandArguments: string[];
  commandIndex: number;
  format: string | undefined;
} {
  let format: string | undefined;
  let commandIndex = -1;
  const commandArguments: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--json") format = "json";
    else if (argument === "--format") format = argv[++index];
    else if (INCUR_FLAGS.has(argument)) continue;
    else if (
      INCUR_VALUE_OPTIONS.has(argument) &&
      argv[index + 1] !== undefined
    ) {
      index += 1;
    } else {
      if (commandIndex < 0) commandIndex = index;
      commandArguments.push(argument);
    }
  }
  return { commandArguments, commandIndex, format };
}

export function fullMarkdownManifestArguments(
  argv: readonly string[],
): string[] | undefined {
  if (!argv.includes("--llms-full") || argv.includes("--mcp")) return undefined;
  // Incur 0.4.13 omits the requested path from its structured manifest.
  const { commandArguments, format } = parseIncurArguments(argv);
  return format === undefined || format === "md" ? commandArguments : undefined;
}

export async function applyManifestTokenControls(
  markdown: string,
  argv: readonly string[],
): Promise<string> {
  const controls: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index]!;
    if (argument === "--token-count") {
      controls.push(argument);
    } else if (argument === "--token-limit" || argument === "--token-offset") {
      const value = argv[++index];
      if (value !== undefined) controls.push(argument, value);
    }
  }
  if (controls.length === 0) return markdown;

  const renderer = Cli.create("codex-security-manifest", {
    output: z.string(),
    run: () => markdown,
  });
  let output = "";
  let exitCode: number | undefined;
  await renderer.serve(["--format", "md", ...controls], {
    stdout: (value) => {
      output += value;
    },
    exit: (code) => {
      exitCode = code;
    },
  });
  if (exitCode !== undefined) {
    throw new Error("Could not apply manifest token controls.");
  }
  return output;
}

function commandScope(
  commands: readonly Skill.CommandInfo[],
  commandArguments: readonly string[],
): string {
  let scope = "";
  for (const argument of commandArguments) {
    const next = scope ? `${scope} ${argument}` : argument;
    if (
      !commands.some(
        ({ name }) => name === next || name?.startsWith(`${next} `),
      )
    ) {
      break;
    }
    scope = next;
    if (commands.some(({ name }) => name === scope)) break;
  }
  return scope;
}

/** Reconstruct only schema-owned guidance from Incur's human validation block. */
export function humanValidationMessage(
  cli: Cli.Cli,
  commandArguments: readonly string[],
  output: string,
): string | undefined {
  const lines = output.split("\n");
  const usage = lines.indexOf("See below for usage.");
  if (usage <= 0) return undefined;
  const commands = Cli.collectSkillCommands(
    Cli.toCommands.get(cli)!,
    [],
    new Map(),
  );
  const scope = commandScope(commands, commandArguments);
  const command = commands.find(({ name }) => name === scope);
  if (command?.options === undefined) return undefined;
  const input = z.toJSONSchema(command.options, {
    io: "input",
    unrepresentable: "any",
  });
  const required = new Set(input.required);
  const messages: string[] = [];
  for (const line of lines.slice(0, usage)) {
    const field = Object.keys(command.options.shape).find((name) => {
      const flag = `--${optionName(name)}`;
      return (
        line.startsWith(`Error: invalid value for ${flag}: `) ||
        (required.has(name) &&
          line === `Error: missing required option ${flag}`)
      );
    });
    if (field === undefined) return undefined;
    const property = input.properties?.[field];
    if (typeof property !== "object" || property === null) return undefined;
    const constraints = staticInputConstraints(property);
    if (constraints === undefined) return undefined;
    const flag = `--${optionName(field)}`;
    const problem = line.startsWith("Error: missing required option ")
      ? "Missing required option"
      : "Invalid value for";
    messages.push(
      `${problem} ${flag}. ${describeConstraints(constraints, plainValue, true).join(" ")}`,
    );
  }
  return messages.join("\n");
}

/** Render a documentation-only view; keep Incur's parsed schemas unchanged. */
export function renderFullMarkdownManifest(
  cli: Cli.Cli,
  manifest: Manifest,
  commandArguments: readonly string[] = [],
): string {
  const selected = new Set(manifest.commands.map(({ name }) => name));
  const groups = new Map<string, string>();
  const allCommands = Cli.collectSkillCommands(
    Cli.toCommands.get(cli)!,
    [],
    groups,
  );
  const scope = commandScope(allCommands, commandArguments);
  const commands = allCommands
    .filter((command) => selected.has(command.name!))
    .map((command) => ({
      ...command,
      args: documentInputs(command.args, false),
      options: documentInputs(command.options, true),
    }));
  const groupRows = [...groups]
    .filter(([name]) =>
      commands.some((command) => command.name?.startsWith(`${name} `)),
    )
    .map(
      ([name, description]) => `| \`${cli.name} ${name}\` | ${description} |`,
    );
  const defaults = scanModelConfiguration(DEFAULT_CODEX_CONFIG);
  const scopedName = scope ? `${cli.name} ${scope}` : cli.name;
  const description = scope
    ? groups.get(scope) ??
      allCommands.find(({ name }) => name === scope)?.description
    : cli.description;

  return [
    Skill.index(cli.name, commands, description).replace(
      /^# [^\n]+/u,
      `# ${scopedName}`,
    ),
    `CLI/SDK version: ${VERSION}. Bundled plugin: ${BUNDLED_PLUGIN_VERSION}. ` +
      `Codex runtime: ${CODEX_EXECUTABLE_VERSION}. Codex SDK: ${CODEX_SDK_VERSION}. ` +
      `Default model: ${defaults.model}; reasoning effort: ${defaults.reasoningEffort}.`,
    scope
      ? `Run \`${cli.name} --llms-full\` for the operating guide.`
      : readOperatingGuide(),
    "## Global options and integrations",
    "`--format` and `--json` select the output format for `--llms`, `--llms-full`, and `--schema`. `--filter-output` applies only to command results, which follow the restrictions in each command reference.",
    "```text\n" + Help.formatRoot(cli.name, { root: true }) + "\n```",
    ...(groupRows.length === 0
      ? []
      : [
          "## Command groups",
          [
            "| Group | Description |",
            "|-------|-------------|",
            ...groupRows,
          ].join("\n"),
        ]),
    "## Command reference",
    ...commands.map((command) => {
      const restrictions = commandResultRestrictions(command.name ?? "");
      return [
        Skill.generate(cli.name, [command]).replace(/^#/gmu, "###"),
        ...(restrictions.length === 0
          ? []
          : [
              "#### Command result restrictions",
              restrictions.map((restriction) => `- ${restriction}`).join("\n"),
            ]),
      ].join("\n\n");
    }),
    "",
  ].join("\n\n");
}

function readOperatingGuide(): string {
  return readFileSync(new URL("../README.md", import.meta.url), "utf8")
    .replace(/\r\n/gu, "\n")
    .split(/(?=^## )/mu)
    .filter((section) =>
      /^## (?:Install|Authentication|CLI|Local security model)\n/u.test(
        section,
      ),
    )
    .join("")
    .trim();
}

function documentInputs(
  schema: z.ZodObject | undefined,
  options: boolean,
): z.ZodObject | undefined {
  if (schema === undefined) return undefined;
  // Incur 0.4.13 renders schema keys as flags and omits input constraints.
  // Adapt only the Markdown view, not the parser or machine-readable schema.
  const input = z.toJSONSchema(schema, {
    io: "input",
    unrepresentable: "any",
  });
  const required = new Set(input.required);
  return z.object(
    Object.fromEntries(
      Object.entries(schema.shape).map(([name, field]) => {
        const property = (input.properties?.[name] ??
          {}) as z.core.JSONSchema.JSONSchema;
        const details = [field.description ?? ""];
        if (options && required.has(name)) details.push("Required.");
        details.push(...describeConstraints(property));
        if (options && property.type === "array") {
          details.push("Repeat this flag for multiple values.");
          if (Array.isArray(property.default)) {
            details.push(`Default: ${codeValue(property.default)}.`);
          }
        }
        if (
          property.type === "array" &&
          typeof property.items === "object" &&
          !Array.isArray(property.items)
        ) {
          const itemDetails = describeConstraints(property.items);
          if (itemDetails.length > 0) {
            details.push(`Each value: ${itemDetails.join(" ")}`);
          }
        }
        const key = options ? optionName(name) : name;
        return [key, field.describe(details.join(" "))];
      }),
    ),
  );
}

const CONSTRAINT_LABELS = [
  ["minimum", "Minimum"],
  ["exclusiveMinimum", "Must be greater than"],
  ["maximum", "Maximum"],
  ["exclusiveMaximum", "Must be less than"],
  ["minLength", "Minimum length"],
  ["maxLength", "Maximum length"],
] as const;

function staticInputConstraints(
  property: z.core.JSONSchema.JSONSchema,
): z.core.JSONSchema.JSONSchema | undefined {
  if (
    typeof property.type !== "string" ||
    !["string", "number", "integer", "boolean", "null"].includes(
      property.type,
    ) ||
    property.$ref !== undefined ||
    property.anyOf !== undefined ||
    property.oneOf !== undefined ||
    property.allOf !== undefined ||
    property.not !== undefined ||
    property.if !== undefined
  ) {
    return undefined;
  }
  const values =
    property.enum ??
    (property.const === undefined ? undefined : [property.const]);
  if (
    values !== undefined &&
    !values.every(
      (value) =>
        value === null ||
        typeof value === "string" ||
        typeof value === "boolean" ||
        (typeof value === "number" && Number.isFinite(value)),
    )
  ) {
    return undefined;
  }
  const constraints: z.core.JSONSchema.JSONSchema = {
    type: property.type,
    ...(values === undefined ? {} : { enum: values }),
    ...(property.pattern === undefined ? {} : { pattern: property.pattern }),
  };
  for (const [key] of CONSTRAINT_LABELS) {
    const value = property[key];
    if (value === undefined) continue;
    if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
    constraints[key] = value;
  }
  return constraints;
}

function describeConstraints(
  property: z.core.JSONSchema.JSONSchema,
  renderValue: (value: unknown) => string = codeValue,
  includeType = false,
): string[] {
  const details: string[] = [];
  if (includeType) details.push(`Expected type: ${property.type}.`);
  const values =
    property.enum ??
    (property.const === undefined ? undefined : [property.const]);
  if (values !== undefined) {
    details.push(`Allowed values: ${values.map(renderValue).join(", ")}.`);
  }
  if (property.type === "integer" && !includeType) {
    details.push("Must be an integer.");
  }
  if (property.pattern !== undefined) {
    details.push(`Pattern: ${renderValue(property.pattern)}.`);
  }
  for (const [key, label] of CONSTRAINT_LABELS) {
    if (property[key] !== undefined) {
      details.push(`${label}: ${property[key]}.`);
    }
  }
  return details;
}

function optionName(name: string): string {
  return name.replace(/[A-Z]/gu, (letter) => `-${letter.toLowerCase()}`);
}

function plainValue(value: unknown): string {
  return typeof value === "string"
    ? value
    : JSON.stringify(value) ?? String(value);
}

function codeValue(value: unknown): string {
  return `\`${plainValue(value)}\``;
}
