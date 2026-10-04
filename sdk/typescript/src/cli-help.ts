import { DEEP_SCAN_SETTINGS, DeepScanSettingsSchema } from "./scan-settings.js";

type Row = { label: string; description: string };
type Group = readonly [title: string, names: readonly string[]];

const COMMAND_GROUPS: readonly Group[] = [
  ["Scan and fix", ["scan", "policy", "validate", "patch", "verify-fix"]],
  [
    "Review and share",
    [
      "scans",
      "findings",
      "classify-severity",
      "dedupe",
      "suggest-owners",
      "export",
      "import",
      "publish",
    ],
  ],
  ["Automate", ["bulk-scan", "scan-components", "install-hook", "serve"]],
  ["Setup and support", ["login", "logout", "init", "info", "feedback"]],
];

const SCAN_GROUPS: readonly Group[] = [
  ["Scope", ["path", "diff", "head", "working-tree", "base"]],
  ["Configuration", ["config", "mode", "knowledge-base", "dry-run"]],
  ["Model and authentication", ["auth", "model", "effort", "provider"]],
  [
    "Deep Scan",
    DEEP_SCAN_SETTINGS.flatMap(([, , , flag]) =>
      flag === null ? [] : [flag.slice(2)],
    ),
  ],
  [
    "Results, progress, and limits",
    [
      "output-dir",
      "archive-existing",
      "max-cost",
      "show-cost",
      "fail-on-severity",
      "headless",
      "verbose",
    ],
  ],
  ["Patch after scanning", ["patch", "patch-severity", "create-pr"]],
];

const PUBLISH_GROUPS: readonly Group[] = [
  ["Input", ["scan", "scan-dir", "csv", "finding-id", "workflow-id"]],
  ["Destination", ["to", "findings-url"]],
  [
    "Linear",
    [
      "linear-team",
      "linear-project",
      "linear-assignee",
      "linear-api-key",
      "project",
    ],
  ],
  ["Publishing", ["dry-run", "skip-existing"]],
];

const VALUE_LABELS: Record<string, string> = {
  config: "file",
  path: "path",
  "knowledge-base": "path",
  "scan-prompt-file": "file",
  "validation-prompt-file": "file",
  "post-scan-prompt-file": "file",
  diff: "ref",
  head: "ref",
  base: "ref",
  model: "model",
  "output-dir": "path",
  "scan-dir": "path",
  "plugin-path": "path",
  "source-root": "path",
  python: "path",
  codex: "key=value",
  "max-cost": "usd",
  "max-time-hours": "hours",
  "fail-on-severity": "level",
  "patch-severity": "level",
  severity: "level",
  scan: "scan-id",
  "finding-id": "id",
  "findings-url": "url",
  output: "file",
  csv: "file",
  json: "file",
  rubric: "file",
  "export-format": "format",
  "filter-output": "keys",
  "token-limit": "count",
  "token-offset": "count",
  port: "port",
  to: "destination",
};

const OUTPUT_GROUPS: readonly Group[] = [
  ["Help and updates", ["help", "version", "update"]],
  ["Output", ["format", "json", "filter-output", "full-output"]],
];

function rowName(row: Row): string {
  return row.label.match(/--([\w-]+)/u)?.[1] ?? row.label;
}

function parseRows(lines: string[]): Row[] {
  return lines.map((line) => {
    const match = line.trim().match(/^(.*?)\s{2,}(.*)$/u);
    return { label: match?.[1] ?? line.trim(), description: match?.[2] ?? "" };
  });
}

function wrap(text: string, width: number, prefix = "", next = prefix): string {
  const lines: string[] = [];
  let line = prefix;
  let indent = prefix.length;
  for (const word of text.split(/\s+/u)) {
    if (line.length > indent && line.length + 1 + word.length > width) {
      lines.push(line);
      line = next;
      indent = next.length;
    }
    line += `${line.length > indent ? " " : ""}${word}`;
  }
  lines.push(line);
  return lines.join("\n");
}

function renderRows(title: string, rows: Row[], width: number): string {
  // Keep long option names from moving every description across the terminal.
  const column = Math.min(
    30,
    Math.floor(width / 2),
    Math.max(...rows.map((row) => row.label.length)) + 4,
  );
  return [
    `${title}:`,
    ...rows.map(({ label, description }) => {
      if (!description) return `  ${label}`;
      if (label.length + 4 > column) {
        return `  ${label}\n${wrap(description, width, "    ")}`;
      }
      return wrap(
        description,
        width,
        `  ${label}${" ".repeat(column - label.length - 2)}`,
        " ".repeat(column),
      );
    }),
  ].join("\n");
}

function groupedRows(
  rows: Row[],
  groups: readonly Group[],
  remainingTitle: string,
  width: number,
): string[] {
  const remaining = new Map(rows.map((row) => [rowName(row), row]));
  const sections: string[] = [];
  for (const [title, names] of groups) {
    const selected = names.flatMap((name) => {
      const row = remaining.get(name);
      remaining.delete(name);
      return row === undefined ? [] : [row];
    });
    if (selected.length) sections.push(renderRows(title, selected, width));
  }
  if (remaining.size) {
    sections.push(renderRows(remainingTitle, [...remaining.values()], width));
  }
  return sections;
}

function optionRow(row: Row, command: string): Row {
  const name = rowName(row);
  let { label, description } = row;
  label = label.replace(/<([^>]+)>/u, (_, type: string) => {
    const choices = type.split("|");
    if (choices.length > 1) {
      description += `${description.endsWith(".") ? "" : "."} Choices: ${choices.join(", ")}.`;
    }
    return `<${VALUE_LABELS[name] ?? (type === "number" ? "count" : name)}>`;
  });
  label = label.replace(/^--([\w-]+), (-\w)/u, "$2, --$1");
  if (command === "scan" && !/default:/iu.test(description)) {
    const setting = DEEP_SCAN_SETTINGS.find(
      ([, , , flag]) => flag === `--${name}`,
    );
    if (setting) {
      const value =
        DeepScanSettingsSchema.shape[setting[0]].meta()?.["default"];
      if (value !== undefined) description += ` (default: ${value})`;
    }
  }
  return { label, description };
}

function globalRows(rows: Row[], command: string): Row[] {
  const scan = command === "scan" || command === "scan import";
  const plainOutput = [
    "validate",
    "login",
    "logout",
    "serve",
    "export",
  ].includes(command);
  const visible = rows.filter(({ label }) => {
    if (scan && label.startsWith("--filter-output")) return false;
    return !(
      plainOutput &&
      /^(--format |--filter-output |--full-output$|--token-)/u.test(label)
    );
  });
  const formats = visible.find((row) => rowName(row) === "format");
  if (formats && (scan || command === "scans rerun")) {
    formats.label = formats.label.replace("|md", "");
  }
  if (formats && command !== "scan import") {
    visible.push({
      label: "--json",
      description: "Shorthand for --format json.",
    });
  }
  return visible.map((row) =>
    optionRow(
      row.label === "--help" ? { ...row, label: "-h, --help" } : row,
      command,
    ),
  );
}

/** Present Incur's generated help without changing its routing or command output. */
export function formatCliHelp(text: string, columns = 80): string {
  const header = text.match(
    /^(codex-security(?:@[^\s]+)?((?: [a-z][a-z-]*)*))(?: — ([^\n]*))?\n\nUsage: /u,
  );
  if (!header) return text;
  const command = header[2]!.trim();
  const sections: string[] = [];
  // Presentation width only; long paths and copyable commands remain intact.
  const width = columns > 0 ? columns : 80;
  const blocks = text.trimEnd().split(/\n\n/u);
  const examples = blocks.find((block) => block.startsWith("Examples:\n"));
  for (const [index, block] of blocks.entries()) {
    const [title = "", ...lines] = block.split("\n");
    if (index === 0) {
      sections.push(
        [header[1], header[3] && wrap(header[3], width)]
          .filter(Boolean)
          .join("\n"),
      );
    } else if (title.startsWith("Usage: ")) {
      let usage = block.replace(
        /([a-z])([A-Z])/gu,
        (_, lower: string, upper: string) => `${lower}-${upper.toLowerCase()}`,
      );
      if (command === "scans" || command === "findings") {
        usage = usage.replace("<command>", "[command]");
        usage += "\nDefault command: list";
      }
      sections.push(
        usage
          .split("\n")
          .map((line) => wrap(line, width, "", "       "))
          .join("\n"),
      );
      if (command === "") {
        sections.push(
          "Get started:\n" +
            "  codex-security login\n" +
            "  codex-security scan .\n" +
            "  codex-security findings",
        );
      } else if (examples) {
        sections.push(examples);
      }
    } else if (title === "Examples:") {
      continue;
    } else if (title === "Commands:") {
      const rows = parseRows(lines);
      sections.push(
        ...(command === ""
          ? groupedRows(rows, COMMAND_GROUPS, "Other commands", width)
          : [renderRows("Commands", rows, width)]),
      );
    } else if (title === "Options:") {
      const rows = parseRows(lines).map((row) => optionRow(row, command));
      sections.push(
        ...(command === "scan"
          ? groupedRows(rows, SCAN_GROUPS, "Advanced", width)
          : command === "publish scan"
            ? groupedRows(rows, PUBLISH_GROUPS, "Options", width)
            : [renderRows("Options", rows, width)]),
      );
    } else if (title === "Global Options:") {
      sections.push(
        ...groupedRows(
          globalRows(parseRows(lines), command),
          OUTPUT_GROUPS,
          "Agent options",
          width,
        ),
      );
    } else if (
      ["Arguments:", "Integrations:", "Environment Variables:"].includes(title)
    ) {
      const rows = parseRows(lines).map((row) => ({
        ...row,
        label:
          title === "Arguments:"
            ? row.label.replace(/([a-z])([A-Z])/gu, "$1-$2").toLowerCase()
            : row.label,
      }));
      sections.push(renderRows(title.slice(0, -1), rows, width));
    } else {
      sections.push(
        block
          .split("\n")
          .map((line) => (line.startsWith("  ") ? line : wrap(line, width)))
          .join("\n"),
      );
    }
  }
  if (command === "") {
    sections.push(
      wrap(
        "Use codex-security <command> --help for options and examples.",
        width,
      ),
    );
    sections.push("Docs: https://learn.chatgpt.com/docs/security/cli");
  }
  return `${sections.join("\n\n")}\n`;
}
