import { readFileSync, realpathSync } from "node:fs";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import { stripVTControlCharacters } from "node:util";
import { Box, Text, render, useApp, useInput, useStdout } from "ink";
import { useMemo, useRef, useState } from "react";
import { safeErrorMessage } from "./errors.js";
import type { Finding, FindingCodeEvidence } from "./models.js";

const SEVERITY_COLORS = {
  critical: "redBright",
  high: "red",
  medium: "yellow",
  low: "blueBright",
} as const;

type PatchSeverity = keyof typeof SEVERITY_COLORS;

const SEVERITIES = Object.keys(SEVERITY_COLORS) as PatchSeverity[];
const HEADING = /^[A-Z][A-Z ]+$/u;
const SOURCE_LINE = /^([› ]\s*\d* │ )(.*)$/u;

const DETAIL_ORDER = [
  "summary",
  "severity",
  "confidence",
  "rootCause",
  "validation",
  "attackPath",
  "impact",
  "likelihood",
  "reachability",
  "prerequisites",
  "counterevidence",
  "limitations",
  "locations",
  "codeEvidence",
  "remediation",
  "remediationTests",
  "preventiveControls",
  "taxonomy",
  "findingId",
  "occurrenceId",
] as const;

export interface PatchSelection {
  severity: PatchSeverity;
  occurrenceIds: string[];
  instructions?: Record<string, string>;
  createPullRequest?: boolean;
}

interface PatchTuiProps {
  repository: string;
  findings: readonly Finding[];
  onComplete(selection: PatchSelection | null): void;
  color?: boolean;
}

function safeText(value: unknown): string {
  return stripVTControlCharacters(safeErrorMessage(String(value)))
    .replaceAll(/\r\n?/gu, "\n")
    .replaceAll(/[\u0000-\u0009\u000B-\u001F\u007F-\u009F\u2028\u2029]/gu, " ");
}

function safeLine(value: unknown): string {
  return safeText(value).replaceAll("\n", " ");
}

function fieldLabel(value: string): string {
  return safeLine(value)
    .replaceAll(/([a-z\d])([A-Z])/gu, "$1 $2")
    .replaceAll("_", " ")
    .replaceAll(/\b(cwe|id)\b/giu, (match) => match.toUpperCase())
    .replace(/^./u, (match) => match.toUpperCase());
}

function detailLines(
  value: unknown,
  indent = "",
  evidence?: ReadonlyMap<string, FindingCodeEvidence>,
): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((entry) => {
      const lines = detailLines(entry, `${indent}  `, evidence);
      return lines.length === 0
        ? []
        : [`${indent}• ${lines[0]!.trimStart()}`, ...lines.slice(1)];
    });
  }
  if (typeof value !== "object" || value === null) {
    return safeText(value)
      .split("\n")
      .map((line) => `${indent}${line}`);
  }

  return Object.entries(value).flatMap(([key, entry]) => {
    if (
      entry === null ||
      entry === undefined ||
      (Array.isArray(entry) && entry.length === 0)
    ) {
      return [];
    }
    if (key === "level") {
      const level = safeLine(entry);
      return [
        `${indent}${level.replace(/^./u, (match) => match.toUpperCase())}`,
      ];
    }
    if (
      (key === "summary" || key === "rationale") &&
      typeof entry === "string"
    ) {
      return detailLines(entry, indent, evidence);
    }
    if (key === "evidenceRefs" && Array.isArray(entry)) {
      return [
        `${indent}Evidence:`,
        ...entry.map((reference) => {
          const item = evidence?.get(String(reference));
          return item === undefined
            ? `${indent}  • ${safeLine(reference)}`
            : `${indent}  • ${safeLine(item.label)} · ${safeLine(item.path)}:${item.startLine}`;
        }),
      ];
    }
    if (key === "cwe" && Array.isArray(entry)) {
      return [`${indent}CWE: ${entry.map(safeLine).join(", ")}`];
    }
    if (
      typeof entry === "object" ||
      (typeof entry === "string" && entry.includes("\n"))
    ) {
      return [
        `${indent}${fieldLabel(key)}:`,
        ...detailLines(entry, `${indent}  `, evidence),
      ];
    }
    return [`${indent}${fieldLabel(key)}: ${safeLine(entry)}`];
  });
}

function numberedCode(
  lines: readonly string[],
  startLine: number,
  location?: Finding["locations"][number],
): string[] {
  const numberWidth = String(startLine + lines.length - 1).length;
  return lines.map((line, index) => {
    const number = startLine + index;
    const highlighted =
      location !== undefined &&
      number >= location.startLine &&
      number <= (location.endLine ?? location.startLine);
    return `${highlighted ? "›" : " "} ${String(number).padStart(numberWidth)} │ ${safeLine(line)}`;
  });
}

function locationSource(
  repository: string,
  location: Finding["locations"][number],
): string[] {
  try {
    const root = realpathSync(repository);
    const path = realpathSync(resolve(root, location.path));
    const inside = relative(root, path);
    if (
      inside === ".." ||
      inside.startsWith(`..${sep}`) ||
      isAbsolute(inside)
    ) {
      return [];
    }

    const source = readFileSync(path, "utf8").split(/\r?\n/u);
    const first = Math.max(0, location.startLine - 4);
    const last = Math.min(
      source.length,
      (location.endLine ?? location.startLine) + 3,
    );
    return numberedCode(source.slice(first, last), first + 1, location);
  } catch {
    return [];
  }
}

function matchesSeverity(finding: Finding, severity: PatchSeverity): boolean {
  return (
    SEVERITIES.indexOf(finding.severity.level as PatchSeverity) <=
    SEVERITIES.indexOf(severity)
  );
}

function findingLines(
  finding: Finding,
  repository: string,
  width: number,
): string[] {
  const evidenceById = new Map(
    (finding.codeEvidence ?? []).map((item) => [item.id, item]),
  );
  const fields = [
    ...DETAIL_ORDER.map((key) => [key, finding[key]] as const),
    ...Object.entries(finding).filter(
      ([key]) =>
        key !== "title" &&
        !DETAIL_ORDER.includes(key as (typeof DETAIL_ORDER)[number]),
    ),
  ];

  const lines = [safeLine(finding.title), ""];
  for (const [key, value] of fields) {
    if (
      value === null ||
      value === undefined ||
      (Array.isArray(value) && value.length === 0)
    ) {
      continue;
    }
    lines.push(fieldLabel(key).toUpperCase());
    if (key === "codeEvidence" && Array.isArray(value)) {
      for (const evidence of value as FindingCodeEvidence[]) {
        const { label, path, startLine, endLine, code, explanation, ...other } =
          evidence;
        const location = `${safeLine(path)}:${startLine}${
          endLine === undefined ? "" : `–${endLine}`
        }`;
        lines.push(
          label ? `${safeLine(label)} · ${location}` : location,
          ...numberedCode(safeText(code).split("\n"), startLine),
          ...safeText(explanation).split("\n"),
          ...detailLines(other, "  ", evidenceById),
        );
      }
    } else if (key === "locations" && Array.isArray(value)) {
      for (const location of value as Finding["locations"]) {
        const { path, startLine, endLine, role, ...other } = location;
        lines.push(
          `${safeLine(path)}:${startLine}${endLine === undefined ? "" : `–${endLine}`}${
            role === undefined ? "" : ` · ${safeLine(role)}`
          }`,
          ...locationSource(repository, location),
          ...detailLines(other, "  ", evidenceById),
        );
      }
    } else {
      lines.push(...detailLines(value, "", evidenceById));
    }
    lines.push("");
  }

  return lines.flatMap((line) => {
    if (line.length === 0) return [""];
    const source = SOURCE_LINE.exec(line);
    const prefix = source?.[1] ?? "";
    const continuation = source
      ? `${prefix[0]}${" ".repeat(prefix.length - 3)}│ `
      : "";
    const available = Math.max(1, width - prefix.length);
    const wrapped: string[] = [];
    let remaining = source?.[2] ?? line;
    do {
      const boundary =
        remaining.length <= available
          ? -1
          : remaining.lastIndexOf(" ", available);
      const split =
        boundary > 0 && remaining.slice(0, boundary).trim().length > 0
          ? boundary
          : available;
      wrapped.push(
        `${wrapped.length === 0 ? prefix : continuation}${remaining.slice(0, split)}`,
      );
      remaining = remaining.slice(split);
      if (source === null) remaining = remaining.trimStart();
    } while (remaining.length > 0);
    return wrapped;
  });
}

function FindingDetailLine({
  line,
  section,
  title,
  severity,
  color,
}: {
  line: string;
  section: string | undefined;
  title: boolean;
  severity: PatchSeverity;
  color: boolean;
}): React.JSX.Element {
  const heading = HEADING.test(line);
  const accent = color ? "cyan" : undefined;
  const muted = color ? "gray" : undefined;
  const severityColor = color ? SEVERITY_COLORS[severity] : undefined;

  if (title || heading) {
    return (
      <Text bold wrap="truncate-end">
        {line}
      </Text>
    );
  }

  if (
    (section === "SEVERITY" && line.toLowerCase() === severity) ||
    (section === "CONFIDENCE" && /^(high|medium|low)$/iu.test(line))
  ) {
    return (
      <Text
        bold
        color={section === "SEVERITY" ? severityColor : undefined}
        wrap="truncate-end"
      >
        ● {line}
      </Text>
    );
  }

  const source = SOURCE_LINE.exec(line);
  if (source !== null) {
    return (
      <Text wrap="truncate-end">
        <Text color={line.startsWith("›") ? severityColor : muted}>
          {source[1]}
        </Text>
        <Text bold={line.startsWith("›")}>{source[2]}</Text>
      </Text>
    );
  }

  const location = /^(.*?)(\S+:\d+(?:–\d+)?)(.*)$/u.exec(line);
  if (
    location !== null &&
    (section === "LOCATIONS" || section === "CODE EVIDENCE")
  ) {
    return (
      <Text wrap="truncate-end">
        <Text>{location[1]}</Text>
        <Text color={accent}>{location[2]}</Text>
        <Text color={muted}>{location[3]}</Text>
      </Text>
    );
  }

  const labeled = /^(\s*(?:• |[A-Za-z][\w ]*:))(.*)$/u.exec(line);
  if (labeled !== null) {
    return (
      <Text wrap="truncate-end">
        <Text color={muted}>{labeled[1]}</Text>
        {labeled[2]}
      </Text>
    );
  }

  return <Text wrap="truncate-end">{line || " "}</Text>;
}

export function PatchTui({
  repository,
  findings,
  onComplete,
  color = process.env["NO_COLOR"] === undefined,
}: PatchTuiProps): React.JSX.Element {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const [pane, setPane] = useState<"findings" | "details">("findings");
  const [focused, setFocused] = useState(0);
  const focusedFinding = useRef(focused);
  const [offset, setOffset] = useState(0);
  const [preset, setPreset] = useState<PatchSeverity>("low");
  const [instructions, setInstructions] = useState<Record<string, string>>({});
  const [createPullRequest, setCreatePullRequest] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [selected, setSelected] = useState(
    () => new Set(findings.map(({ occurrenceId }) => occurrenceId)),
  );
  const rows = stdout.rows ?? 28;
  const columns = stdout.columns ?? 100;
  const visibleRows = Math.max(4, rows - 15);
  const listStart = Math.max(
    0,
    Math.min(focused - visibleRows + 1, findings.length - visibleRows),
  );
  const current = findings[focused]!;
  const details = useMemo(
    () =>
      findingLines(
        current,
        repository,
        Math.max(18, Math.floor(columns * 0.58) - 7),
      ),
    [columns, current, repository],
  );
  const maximumOffset = Math.max(0, details.length - visibleRows);
  const accent = color ? "cyan" : undefined;
  const muted = color ? "gray" : undefined;
  const instructionColor = color ? "magentaBright" : undefined;
  const success = color ? "green" : undefined;
  const severityColor = (severity: PatchSeverity) =>
    color ? SEVERITY_COLORS[severity] : undefined;
  const findingsColor =
    pane === "findings" && editing === null ? accent : muted;
  const detailsColor = pane === "details" && editing === null ? accent : muted;
  const currentInstructions = instructions[current.occurrenceId];
  const selectedFindings = findings.filter(({ occurrenceId }) =>
    selected.has(occurrenceId),
  );
  const presetMatches = findings.every(
    (finding) =>
      selected.has(finding.occurrenceId) === matchesSeverity(finding, preset),
  );

  useInput((input, key) => {
    if (editing !== null) {
      if (key.escape) {
        setEditing(null);
      } else if (key.return) {
        setInstructions((previous) => {
          const next = { ...previous };
          if (draft.trim().length === 0) delete next[editing];
          else next[editing] = draft.trim();
          return next;
        });
        setEditing(null);
      } else if (key.backspace || key.delete) {
        setDraft((previous) => previous.slice(0, -1));
      } else if (!key.ctrl && !key.meta && input.length > 0) {
        setDraft((previous) => previous + input);
      }
      return;
    }

    if (key.escape || input === "q" || (key.ctrl && input === "c")) {
      onComplete(null);
      exit();
    } else if (key.return || input === "p") {
      if (selectedFindings.length === 0) {
        onComplete(null);
      } else {
        const severity = selectedFindings.reduce<PatchSeverity>(
          (lowest, finding) =>
            matchesSeverity(finding, lowest)
              ? lowest
              : (finding.severity.level as PatchSeverity),
          "critical",
        );
        const findingInstructions = Object.fromEntries(
          Object.entries(instructions).filter(([occurrenceId]) =>
            selected.has(occurrenceId),
          ),
        );
        onComplete({
          severity,
          occurrenceIds: selectedFindings.map(
            ({ occurrenceId }) => occurrenceId,
          ),
          ...(Object.keys(findingInstructions).length === 0
            ? {}
            : { instructions: findingInstructions }),
          ...(createPullRequest ? { createPullRequest: true } : {}),
        });
      }
      exit();
    } else if (input === "r") {
      setCreatePullRequest((previous) => !previous);
    } else if (input === "i") {
      const occurrenceId = findings[focusedFinding.current]!.occurrenceId;
      setDraft(instructions[occurrenceId] ?? "");
      setEditing(occurrenceId);
    } else if (key.tab || key.leftArrow || key.rightArrow || input === "d") {
      setPane(pane === "findings" ? "details" : "findings");
    } else if (key.upArrow || key.downArrow || input === "j" || input === "k") {
      const direction = key.downArrow || input === "j" ? 1 : -1;
      if (pane === "findings") {
        focusedFinding.current = Math.max(
          0,
          Math.min(findings.length - 1, focusedFinding.current + direction),
        );
        setFocused(focusedFinding.current);
        setOffset(0);
      } else {
        setOffset(Math.max(0, Math.min(maximumOffset, offset + direction)));
      }
    } else if (key.pageUp || key.pageDown) {
      setOffset(
        Math.max(
          0,
          Math.min(
            maximumOffset,
            offset + (key.pageDown ? 1 : -1) * visibleRows,
          ),
        ),
      );
    } else if (input === " ") {
      const next = new Set(selected);
      const occurrenceId = findings[focusedFinding.current]!.occurrenceId;
      if (next.has(occurrenceId)) next.delete(occurrenceId);
      else next.add(occurrenceId);
      setSelected(next);
    } else if (input === "a" || input === "n") {
      setSelected(
        new Set(
          input === "a" ? findings.map(({ occurrenceId }) => occurrenceId) : [],
        ),
      );
    } else {
      const severity = SEVERITIES[Number(input) - 1];
      if (severity !== undefined) {
        setPreset(severity);
        setSelected(
          new Set(
            findings
              .filter((finding) => matchesSeverity(finding, severity))
              .map(({ occurrenceId }) => occurrenceId),
          ),
        );
      }
    }
  });

  return (
    <Box flexDirection="column" height={Math.max(15, rows - 1)} paddingX={1}>
      <Box justifyContent="space-between" marginBottom={1}>
        <Text bold>
          <Text color={accent}>CODEX SECURITY</Text>
          {"  "}
          {safeLine(basename(repository))}
        </Text>
        <Text>
          <Text bold color={selected.size === 0 ? muted : success}>
            {selected.size}/{findings.length}
          </Text>
          <Text dimColor> selected · </Text>
          <Text color={presetMatches ? severityColor(preset) : accent}>
            {presetMatches ? `${preset} and above` : "custom"}
          </Text>
        </Text>
      </Box>

      <Box height={visibleRows + 3}>
        <Box
          borderStyle="round"
          borderColor={findingsColor}
          flexDirection="column"
          overflow="hidden"
          paddingX={1}
          width="40%"
        >
          <Text bold color={findingsColor}>
            FINDINGS
          </Text>
          {findings
            .slice(listStart, listStart + visibleRows)
            .map((finding, index) => {
              const active = listStart + index === focused;
              const checked = selected.has(finding.occurrenceId);
              return (
                <Text key={finding.occurrenceId} wrap="truncate-end">
                  <Text color={active ? accent : muted}>
                    {active ? "› " : "  "}
                  </Text>
                  <Text color={checked ? success : muted}>
                    {checked ? "[✓] " : "[ ] "}
                  </Text>
                  <Text
                    bold
                    color={severityColor(
                      finding.severity.level as PatchSeverity,
                    )}
                  >
                    {finding.severity.level.toUpperCase()}
                  </Text>{" "}
                  {instructions[finding.occurrenceId] !== undefined ? (
                    <Text color={instructionColor}>✎ </Text>
                  ) : null}
                  <Text color={active && color ? "whiteBright" : undefined}>
                    {safeLine(finding.title)}
                  </Text>
                </Text>
              );
            })}
        </Box>

        <Box
          borderStyle="round"
          borderColor={detailsColor}
          flexDirection="column"
          flexGrow={1}
          marginLeft={1}
          overflow="hidden"
          paddingX={1}
        >
          <Text bold color={detailsColor}>
            DETAILS
            {details.length > visibleRows
              ? `  ${offset + 1}–${Math.min(details.length, offset + visibleRows)}/${details.length}`
              : ""}
          </Text>
          {details.slice(offset, offset + visibleRows).map((line, index) => (
            <FindingDetailLine
              key={offset + index}
              line={line}
              section={details
                .slice(0, offset + index + 1)
                .findLast((entry) => HEADING.test(entry))}
              title={offset + index === 0}
              severity={current.severity.level as PatchSeverity}
              color={color}
            />
          ))}
        </Box>
      </Box>

      <Box
        borderStyle="round"
        borderColor={editing === null ? muted : instructionColor}
        flexDirection="column"
        height={5}
        overflow="hidden"
        paddingX={1}
      >
        <Box justifyContent="space-between">
          <Text bold color={instructionColor}>
            PATCH INSTRUCTIONS
          </Text>
          <Text dimColor>
            {editing === null ? "i edit" : "Enter save · Esc cancel"}
          </Text>
        </Box>
        {editing === null ? (
          <Text
            color={currentInstructions ? instructionColor : muted}
            wrap="wrap"
          >
            {currentInstructions === undefined
              ? "Add instructions for this finding."
              : safeText(currentInstructions)}
          </Text>
        ) : (
          <Text wrap="truncate-start">
            <Text color={instructionColor}>{safeLine(draft)}</Text>
            <Text inverse> </Text>
          </Text>
        )}
      </Box>

      <Text wrap="truncate-end">
        <Text color={createPullRequest ? success : muted}>
          {createPullRequest ? "[✓]" : "[ ]"}
        </Text>
        {" Create draft GitHub pull request after patching "}
        <Text dimColor>(r toggle)</Text>
      </Text>

      <Text dimColor wrap="truncate-end">
        <Text color={accent}>↑↓</Text> browse · <Text color={accent}>Tab</Text>{" "}
        details · <Text color={accent}>Space</Text> select ·{" "}
        <Text color={instructionColor}>i</Text> instructions · a/n all/none
      </Text>
      <Text dimColor wrap="truncate-end">
        <Text color={severityColor("critical")}>1</Text> critical ·{" "}
        <Text color={severityColor("high")}>2</Text> high ·{" "}
        <Text color={severityColor("medium")}>3</Text> medium ·{" "}
        <Text color={severityColor("low")}>4</Text> low ·{" "}
        <Text color={success}>Enter</Text> patch · q skip
      </Text>
    </Box>
  );
}

export async function runPatchTui(
  repository: string,
  findings: readonly Finding[],
  {
    stdin = process.stdin,
    stdout = process.stderr,
    color,
  }: {
    stdin?: NodeJS.ReadStream;
    stdout?: NodeJS.WriteStream;
    color?: boolean;
  } = {},
): Promise<PatchSelection | null> {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error("Interactive patch selection requires a terminal.");
  }

  let selection: PatchSelection | null = null;
  stdout.write("\u001B[?1049h");
  try {
    stdin.resume();
    const instance = render(
      <PatchTui
        repository={repository}
        findings={findings}
        color={color}
        onComplete={(value) => {
          selection = value;
        }}
      />,
      { stdin, stdout, exitOnCtrlC: false, patchConsole: false },
    );
    await instance.waitUntilExit();
    return selection;
  } finally {
    stdout.write("\u001B[?1049l");
  }
}
