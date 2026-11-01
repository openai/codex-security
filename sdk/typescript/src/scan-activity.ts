import { isRecord } from "./record.js";
import { parseJson } from "./value.js";

const MAX_ACTIVITY_PATHS = 8;
const MAX_PROSE_CHARACTERS = 1_000;
const SHELL_TOKEN = /"(?:\\.|[^"\\])*"|'[^']*'|[^\s|;&<>]+/gu;

interface ActivityCommand {
  text: string;
  posix: boolean;
  powershell: boolean;
  script?: string;
  argv?: readonly string[];
}

export type ScanActivityStatus = "running" | "completed" | "failed";

export interface ScanActivity {
  id: string;
  kind: "command" | "tool" | "reasoning" | "message";
  status: ScanActivityStatus;
  description: string;
  paths: string[];
  worker?: number;
}

export function scanActivitiesFromEvent(
  event: Readonly<Record<string, unknown>>,
  repository: string,
): ScanActivity[] {
  const activity = scanActivityFromEvent(event, repository);
  if (activity === null) return [];

  const item = event["item"];
  if (
    activity.kind !== "reasoning" ||
    !isRecord(item) ||
    typeof item["text"] !== "string"
  ) {
    return [activity];
  }

  const summaries = Array.from(item["text"].matchAll(/\*\*([^*\r\n]+)\*\*/gu));
  if (
    summaries.length < 2 ||
    item["text"].replaceAll(/\*\*[^*\r\n]+\*\*/gu, "").trim() !== ""
  ) {
    return [activity];
  }

  return summaries.map((summary, index) => ({
    ...activity,
    id: index === 0 ? activity.id : `${activity.id}:${index}`,
    description: summary[1]!.trim(),
  }));
}

export function scanActivityFromEvent(
  event: Readonly<Record<string, unknown>>,
  repository: string,
): ScanActivity | null {
  if (
    (event["type"] !== "item.started" &&
      event["type"] !== "item.updated" &&
      event["type"] !== "item.completed") ||
    !isRecord(event["item"])
  ) {
    return null;
  }

  const item = event["item"];
  if (typeof item["id"] !== "string") return null;

  const status: ScanActivityStatus =
    item["status"] === "failed"
      ? "failed"
      : event["type"] === "item.completed"
        ? "completed"
        : "running";

  if (
    item["type"] === "command_execution" &&
    typeof item["command"] === "string"
  ) {
    const command = unwrapCommand(
      item["command"],
      item["shell"] ?? event["shell"],
    );
    return {
      id: item["id"],
      kind: "command",
      status,
      description: command.text,
      paths: commandRepositoryPaths(command, repository),
    };
  }

  if (item["type"] === "mcp_tool_call" && typeof item["tool"] === "string") {
    const arguments_ = isRecord(item["arguments"]) ? item["arguments"] : {};
    const value = arguments_["cmd"] ?? arguments_["command"];
    const command =
      typeof value === "string"
        ? unwrapCommand(value, arguments_["shell"])
        : null;
    return {
      id: item["id"],
      kind: "tool",
      status,
      description:
        item["tool"] === "exec" && command !== null
          ? command.text
          : toolDescription(item["tool"], arguments_, item["arguments"]),
      paths:
        item["tool"] === "exec" && command !== null
          ? commandRepositoryPaths(command, repository)
          : argumentRepositoryPaths(arguments_, repository),
    };
  }

  if (
    (item["type"] === "reasoning" || item["type"] === "agent_message") &&
    typeof item["text"] === "string"
  ) {
    return proseActivity(
      item["id"],
      item["type"] === "reasoning" ? "reasoning" : "message",
      status,
      item["text"],
    );
  }

  return null;
}

type ShellKind = "posix" | "powershell" | "unknown";

function shellKind(shell: unknown): ShellKind {
  if (typeof shell !== "string") return "unknown";
  if (/(?:^|[\\/])(?:powershell|pwsh)(?:\.exe)?$/iu.test(shell))
    return "powershell";
  return /(?:^|\/)(?:sh|bash|zsh)$/u.test(shell) ? "posix" : "unknown";
}

interface CommandToken {
  value: string;
  resolved: boolean;
  quoted: boolean;
}

// Read whole shell words, including adjacent quoted pieces. Expansions whose
// values are not recorded remain unresolved; this is not a shell evaluator.
function posixTokens(text: string): CommandToken[] {
  const tokens: CommandToken[] = [];
  let value = "";
  let active = false;
  let resolved = true;
  let quoted = false;
  let quote: "'" | '"' | null = null;
  const finish = () => {
    if (active)
      tokens.push({ value, resolved: resolved && quote === null, quoted });
    value = "";
    active = false;
    resolved = true;
  };
  for (let index = 0; index < text.length; index++) {
    const char = text[index]!;
    if (quote === null && /[\s|;&<>]/u.test(char)) {
      finish();
      continue;
    }
    if (!active && quote === null && char === "#") {
      const newline = text.indexOf("\n", index);
      index = newline === -1 ? text.length : newline;
      continue;
    }
    if (!active) {
      active = true;
      quoted = char === "'" || char === '"';
    }
    if (char === quote) {
      quote = null;
      continue;
    }
    if (quote === null && (char === "'" || char === '"')) {
      quote = char;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      const next = text[index + 1];
      if (next === undefined) {
        resolved = false;
        continue;
      }
      if (quote === '"' && !/[\n$`"\\]/u.test(next)) {
        value += char;
      } else {
        if (next !== "\n") value += next;
        if (next === "$" && value === "$") resolved = false;
        index++;
      }
      continue;
    }
    if (quote !== "'" && (char === "`" || text.startsWith("$(", index)))
      return tokens;
    if (char === "$" && value === "" && quote !== "'") {
      const reference =
        /^\$(?:CODEX_SECURITY_REPOSITORY|\{CODEX_SECURITY_REPOSITORY\})(?=\/|$)/u.exec(
          text.slice(index),
        );
      if (reference) {
        value += reference[0];
        index += reference[0].length - 1;
        continue;
      }
    }
    if (char === "$" && (quote !== "'" || value === "")) resolved = false;
    if (quote === null && /[*?\[\]{}]/u.test(char)) resolved = false;
    value += char;
  }
  finish();
  return tokens;
}

function scriptIndex(
  argv: readonly string[],
  kind: ShellKind,
): number | undefined {
  let commandOption = false;
  for (let index = 1; index < argv.length; index++) {
    const option = argv[index]!;
    if (kind === "powershell") {
      if (/^-Command$/iu.test(option)) return index + 1;
      if (/^-(?:NoProfile|NoLogo|NonInteractive)$/iu.test(option)) continue;
      return undefined;
    }
    if (kind !== "posix") return undefined;
    if (option === "--") return commandOption ? index + 1 : undefined;
    if (/^--(?:noprofile|norc|posix|login|restricted)$/u.test(option)) continue;
    if (/^--(?:rcfile|init-file)$/u.test(option)) {
      index++;
      continue;
    }
    if (!/^[-+][a-zA-Z]+$/u.test(option))
      return commandOption ? index : undefined;
    if (option.startsWith("-") && option.includes("c")) commandOption = true;
    // -o/+o and Bash -O/+O consume an option name, also in combined flags.
    index += option.match(/[oO]/gu)?.length ?? 0;
  }
  return undefined;
}

function unwrapCommand(
  command: string | readonly string[],
  shell?: unknown,
): ActivityCommand {
  const kind =
    shell === undefined
      ? process.platform === "win32"
        ? "powershell"
        : "posix"
      : shellKind(shell);
  if (typeof command !== "string") {
    const launcher = shellKind(command[0]);
    const index = scriptIndex(command, launcher);
    const script = index === undefined ? undefined : command[index];
    return {
      text: command
        .map((part) =>
          /^[\w./:-]+$/u.test(part) ? part : JSON.stringify(part),
        )
        .join(" "),
      posix:
        launcher === "posix" ||
        (launcher === "unknown" && shellKind(shell) === "posix"),
      powershell: launcher === "powershell",
      script:
        script === undefined
          ? undefined
          : launcher === "powershell"
            ? command.slice(index).join(" ")
            : script,
      argv:
        index === undefined
          ? command
          : command.filter((_, position) => position !== index),
    };
  }
  const normalized = command.trimStart();
  // A PowerShell wrapper is identifiable independently of the replay host.
  const powershell =
    /^(?:"([^"]+)"|([^\s"'|;&<>]+))\s+(?:-(?:NoProfile|NoLogo|NonInteractive)\s+)*-Command\s+([\s\S]*)$/iu.exec(
      normalized,
    );
  if (
    powershell &&
    shellKind(powershell[1] ?? powershell[2]) === "powershell"
  ) {
    let script = powershell[3]!;
    if (
      (script.startsWith("'") && script.endsWith("'")) ||
      (script.startsWith('"') && script.endsWith('"'))
    )
      script = script.slice(1, -1);
    return { text: script, posix: false, powershell: true };
  }
  if (/^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh)\s/u.test(normalized)) {
    const tokens = posixTokens(normalized);
    const index = scriptIndex(
      tokens.map((token) => token.value),
      "posix",
    );
    const script = index === undefined ? undefined : tokens[index];
    if (script?.resolved) {
      const operands = tokens
        .slice(index! + 1)
        .filter((token) => token.resolved)
        .map((token) => token.value);
      return {
        text:
          operands.length === 0 && script.quoted ? script.value : normalized,
        script: script.value,
        posix: true,
        powershell: false,
        argv: operands,
      };
    }
    return {
      text: normalized,
      posix: true,
      powershell: false,
      argv:
        index === undefined
          ? tokens.filter((token) => token.resolved).map((token) => token.value)
          : [],
    };
  }
  return {
    text: normalized,
    posix: kind === "posix",
    powershell: kind === "powershell",
  };
}

export function scanActivityFromSessionEvent(
  event: Readonly<Record<string, unknown>>,
  repository: string,
): ScanActivity | null {
  if (!isRecord(event["payload"])) {
    return null;
  }
  const payload = event["payload"];
  if (event["type"] === "event_msg") {
    const type = payload["type"];
    const kind =
      type === "agent_reasoning" ||
      type === "agent_reasoning_delta" ||
      type === "agent_reasoning_raw_content" ||
      type === "agent_reasoning_raw_content_delta"
        ? "reasoning"
        : type === "agent_message"
          ? "message"
          : null;
    const delta =
      type === "agent_reasoning_delta" ||
      type === "agent_reasoning_raw_content_delta";
    const text = delta
      ? payload["delta"]
      : kind === "reasoning"
        ? payload["text"]
        : payload["message"];
    if (kind === null || typeof text !== "string") return null;
    return proseActivity(
      `${type}:${typeof event["timestamp"] === "string" ? event["timestamp"] : ""}:${text}`,
      kind,
      delta ? "running" : "completed",
      text,
    );
  }
  if (event["type"] !== "response_item") return null;
  const id = payload["call_id"] ?? payload["id"];
  if (typeof id !== "string") return null;

  if (payload["type"] === "reasoning") {
    return sessionProse(id, "reasoning", payload["summary"]);
  }
  if (payload["type"] === "message" && payload["role"] === "assistant") {
    return sessionProse(id, "message", payload["content"]);
  }
  if (
    payload["type"] !== "function_call" &&
    payload["type"] !== "custom_tool_call" &&
    payload["type"] !== "local_shell_call"
  ) {
    return null;
  }
  const arguments_ = sessionCallArguments(payload);
  const name =
    typeof payload["name"] === "string"
      ? payload["name"]
      : payload["type"] === "local_shell_call"
        ? "shell"
        : null;
  if (name === null) return null;

  const value =
    arguments_["cmd"] ??
    arguments_["command"] ??
    customShellCommand(name, payload["input"]);
  const command =
    typeof value === "string"
      ? unwrapCommand(
          value,
          arguments_["shell"] ?? payload["shell"] ?? event["shell"],
        )
      : Array.isArray(value) && value.every((part) => typeof part === "string")
        ? unwrapCommand(
            value,
            arguments_["shell"] ?? payload["shell"] ?? event["shell"],
          )
        : null;
  if (
    command !== null &&
    /^(?:exec|exec_command|shell_command|shell)$/u.test(name)
  ) {
    return {
      id,
      kind: "command",
      status: "running",
      description: command.text,
      paths: commandRepositoryPaths(command, repository),
    };
  }

  return {
    id,
    kind: "tool",
    status: "running",
    description: toolDescription(name, arguments_, payload["input"]),
    paths: argumentRepositoryPaths(arguments_, repository),
  };
}

function sessionProse(
  id: string,
  kind: "reasoning" | "message",
  value: unknown,
): ScanActivity | null {
  return proseActivity(
    id,
    kind,
    "completed",
    sessionContentText(value, ["summary_text", "output_text"], " "),
  );
}

/** @internal */
export function sessionContentText(
  content: unknown,
  types: readonly string[] = ["output_text"],
  separator = "\n",
): string {
  if (!Array.isArray(content)) return "";
  return content
    .filter(
      (item): item is Record<string, unknown> & { text: string } =>
        isRecord(item) &&
        types.some((type) => item["type"] === type) &&
        typeof item["text"] === "string",
    )
    .map((item) => item.text)
    .join(separator);
}

function proseActivity(
  id: string,
  kind: "reasoning" | "message",
  status: ScanActivityStatus,
  text: string,
): ScanActivity | null {
  const description = prose(
    text
      .split(/\r?\n/u)
      .filter(
        (line) =>
          !/^CODEX_SECURITY_(?:WORKER_STATUS|SCAN_PROGRESS)\s/u.test(line),
      )
      .join("\n"),
  );
  if (description === "") {
    return null;
  }
  return { id, kind, status, description, paths: [] };
}

function prose(text: string, limit?: number): string {
  const normalized = text
    .split(
      /((?<!`)`{3,}[^`\r\n]*(?:\r?\n[\s\S]*?(?:\r?\n[ \t]*`{3,}[ \t]*(?=\r?\n|$)|$)|$)|`[^`\r\n]+`)/gu,
    )
    .reduce((result, part, index) => {
      if (index % 2 === 1) {
        if (!part.startsWith("```")) return `${result}${part}`;
        const previous = result.trimEnd();
        return `${previous}${previous === "" ? "" : "\n"}${part}\n`;
      }
      const plain = part
        .replaceAll(/\*\*([\s\S]+?)\*\*/gu, "$1")
        .replaceAll(/\s+/gu, " ");
      return `${result}${result.endsWith("\n") ? plain.trimStart() : plain}`;
    }, "")
    .trim();
  if (limit === undefined) return normalized;
  const characters = Array.from(normalized);
  return characters.length <= limit
    ? normalized
    : `${characters.slice(0, limit - 1).join("")}…`;
}

function customShellCommand(name: string, value: unknown): string | null {
  if (name !== "exec" || typeof value !== "string") return null;
  const quoted =
    /\b(?:exec_command|shell_command)\s*\(\s*\{[\s\S]{0,1024}?\b(?:cmd|command)["']?\s*:\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`)/u.exec(
      value,
    )?.[1];
  if (quoted === undefined) return null;
  if (quoted.startsWith('"')) {
    return parseJson(() => quoted) as string | null;
  }
  return quoted.slice(1, -1).replaceAll(/\\(['`\\])/gu, "$1");
}

function toolDescription(
  name: string,
  arguments_: Readonly<Record<string, unknown>>,
  input: unknown,
): string {
  if (name === "send_message" || name === "followup_task") {
    const target = arguments_["target"] ?? arguments_["recipient"];
    const message = arguments_["message"] ?? arguments_["text"];
    return `${name}${typeof target === "string" ? ` → ${target}` : ""}${typeof message === "string" ? `: ${prose(message, MAX_PROSE_CHARACTERS)}` : ""}`;
  }
  if (name === "spawn_agent") {
    const task = arguments_["message"] ?? arguments_["task"];
    return typeof task === "string"
      ? `spawn_agent · ${prose(task, MAX_PROSE_CHARACTERS)}`
      : name;
  }
  if (name === "exec" && typeof input === "string") {
    if (/\b(?:exec_command|shell_command)\s*\(/u.test(input)) {
      return "exec · run shell command";
    }
    if (/\bapply_patch\s*\(/u.test(input)) return "exec · apply patch";
    const tool = /\btools\.(?:\w+__)?(\w+)\s*\(/u.exec(input)?.[1];
    if (tool !== undefined) return tool;
    const search =
      /\bALL_TOOLS\.(?:filter|find)\s*\([\s\S]{0,512}?\/([^/\r\n]+)\/[a-z]*/u.exec(
        input,
      )?.[1];
    if (search !== undefined) {
      return `find tools · ${search.replaceAll("|", ", ").replaceAll(/(?:\.\*|\.\?|_)/gu, "-")}`;
    }
  }
  return name;
}

function sessionCallArguments(
  payload: Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  if (isRecord(payload["action"])) return payload["action"];
  const value = payload["arguments"] ?? payload["input"];
  if (isRecord(value)) return value;
  if (typeof value !== "string") return {};
  const parsed = parseJson(() => value);
  return isRecord(parsed) ? parsed : {};
}

function commandRepositoryPaths(
  command: ActivityCommand,
  repository: string,
): string[] {
  const paths = new Set<string>();
  const windows =
    command.powershell || /^(?:[a-z]:[\\/]|\\\\)/iu.test(repository);
  const normalize = (value: string) =>
    windows ? value.replaceAll("\\", "/") : value;
  const repositoryPrefix = normalize(repository).replace(/\/$/u, "");
  const script =
    command.script ?? (command.argv === undefined ? command.text : undefined);
  const candidates: { value: string; expand: boolean; posix?: boolean }[] = [];
  if (script !== undefined) {
    if (command.posix) {
      for (const token of posixTokens(script)) {
        if (token.resolved)
          candidates.push({ value: token.value, expand: true, posix: true });
      }
    } else if (command.powershell) {
      for (const token of script.match(SHELL_TOKEN) ?? []) {
        const singleQuoted = token.startsWith("'") && token.endsWith("'");
        const quoted =
          singleQuoted || (token.startsWith('"') && token.endsWith('"'));
        let value = quoted ? token.slice(1, -1) : token;
        value = normalize(value.replaceAll('\\"', '"'));
        if (value.includes('"')) continue;
        if (command.powershell && !singleQuoted) {
          value = value.replace(
            /^\$(?:env:CODEX_SECURITY_REPOSITORY|\{env:CODEX_SECURITY_REPOSITORY\})\//iu,
            "$CODEX_SECURITY_REPOSITORY/",
          );
        }
        candidates.push({ value, expand: !singleQuoted });
      }
    }
  }
  // Recorded arguments are literal values, never input to the shell lexer.
  for (const value of command.argv ?? [])
    candidates.push({ value, expand: false, posix: command.posix });
  for (const candidate of candidates) {
    const value = candidate.posix
      ? candidate.value
      : normalize(candidate.value);
    const prefixes = [`${repositoryPrefix}/`];
    if (candidate.expand)
      prefixes.push(
        "$CODEX_SECURITY_REPOSITORY/",
        "${CODEX_SECURITY_REPOSITORY}/",
      );
    for (const prefix of prefixes) {
      if (!value.startsWith(prefix)) continue;
      const path = value.slice(prefix.length).replace(/\/+$/u, "");
      if (path !== "" && !path.split("/").includes("..")) paths.add(path);
    }
    if (paths.size >= MAX_ACTIVITY_PATHS) break;
  }
  return [...paths];
}

function argumentRepositoryPaths(value: unknown, repository: string): string[] {
  if (!isRecord(value)) return [];
  const candidates = [value["path"], value["file_path"], value["paths"]].flat();
  const paths = new Set<string>();
  const prefix = `${repository.replaceAll("\\", "/").replace(/\/$/u, "")}/`;
  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;
    const normalized = candidate.replaceAll("\\", "/");
    if (normalized.startsWith(prefix)) {
      const path = normalized.slice(prefix.length);
      if (!path.split("/").includes("..")) paths.add(path);
    }
    if (paths.size >= MAX_ACTIVITY_PATHS) break;
  }
  return [...paths];
}
