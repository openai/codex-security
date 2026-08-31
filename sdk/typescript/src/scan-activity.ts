const MAX_ACTIVITY_PATHS = 8;
const MAX_PROSE_CHARACTERS = 1_000;
const SHELL_TOKEN = /"(?:\\.|[^"\\])*"|'[^']*'|[^\s|;&<>]+/gu;

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
    const command = displayCommand(item["command"]);
    return {
      id: item["id"],
      kind: "command",
      status,
      description: command,
      paths: commandRepositoryPaths(command, repository),
    };
  }

  if (item["type"] === "mcp_tool_call" && typeof item["tool"] === "string") {
    const arguments_ = isRecord(item["arguments"]) ? item["arguments"] : {};
    const value = arguments_["cmd"] ?? arguments_["command"];
    const command = typeof value === "string" ? displayCommand(value) : null;
    return {
      id: item["id"],
      kind: "tool",
      status,
      description:
        item["tool"] === "exec" && command !== null
          ? command
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

function displayCommand(command: string): string {
  const normalized = command.replaceAll(/\s+/gu, " ").trim();
  const powershell =
    process.platform === "win32"
      ? /^(?:"([^"]+)"|([^\s"'|;&<>]+))\s+(?:-NoProfile\s+)?-Command\s+(['"])(.*)\3$/iu.exec(
          normalized,
        )
      : null;
  if (
    powershell !== null &&
    /(?:^|[\\/])(?:powershell|pwsh)(?:\.exe)?$/iu.test(
      powershell[1] ?? powershell[2]!,
    )
  ) {
    return powershell[4]!;
  }
  const match =
    /^(?:\/(?:usr\/)?bin\/)?(?:zsh|bash|sh)\s+-[a-z]*c[a-z]*\s+(['"])(.*)$/u.exec(
      normalized,
    );
  if (match === null) return normalized;
  const quote = match[1]!;
  const script = match[2]!;
  return script.endsWith(quote) ? script.slice(0, -1) : script;
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
    const timestamp =
      typeof event["timestamp"] === "string" ? event["timestamp"] : "";
    return proseActivity(
      `${type}:${timestamp}:${text}`,
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
      ? value
      : Array.isArray(value) && value.every((part) => typeof part === "string")
        ? value.join(" ")
        : null;
  if (
    command !== null &&
    /^(?:exec|exec_command|shell_command|shell)$/u.test(name)
  ) {
    return scanActivityFromEvent(
      {
        type: "item.started",
        item: { id, type: "command_execution", command },
      },
      repository,
    );
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
  if (!Array.isArray(value)) return null;
  const text = value
    .filter(
      (item): item is Record<string, unknown> & { text: string } =>
        isRecord(item) &&
        (item["type"] === "summary_text" || item["type"] === "output_text") &&
        typeof item["text"] === "string",
    )
    .map((item) => item["text"])
    .join(" ");
  return proseActivity(id, kind, "completed", text);
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
      /(`{3,}[^\r\n]*(?:\r?\n[\s\S]*?(?:\r?\n[ \t]*`{3,}[ \t]*(?=\r?\n|$)|$)|$)|`[^`\r\n]+`)/gu,
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
  const match =
    /\b(?:exec_command|shell_command)\s*\(\s*\{[\s\S]{0,1024}?\b(?:cmd|command)["']?\s*:\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`)/u.exec(
      value,
    );
  if (match?.[1] === undefined) return null;
  const quoted = match[1];
  if (quoted.startsWith('"')) {
    try {
      const parsed: unknown = JSON.parse(quoted);
      return typeof parsed === "string" ? parsed : null;
    } catch {
      return null;
    }
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
  try {
    const parsed: unknown = JSON.parse(value);
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function commandRepositoryPaths(command: string, repository: string): string[] {
  const paths = new Set<string>();
  const repositoryPrefix = repository.replaceAll("\\", "/").replace(/\/$/u, "");
  for (const token of command.match(SHELL_TOKEN) ?? []) {
    let value = token;
    const singleQuoted = value.startsWith("'") && value.endsWith("'");
    if ((value.startsWith('"') && value.endsWith('"')) || singleQuoted) {
      value = value.slice(1, -1);
    }
    value = value.replaceAll('\\"', '"').replaceAll("\\", "/");
    if (process.platform === "win32" && !singleQuoted) {
      value = value.replace(
        /^\$(?:env:CODEX_SECURITY_REPOSITORY|\{env:CODEX_SECURITY_REPOSITORY\})\//iu,
        "$CODEX_SECURITY_REPOSITORY/",
      );
    }
    for (const prefix of [
      "$CODEX_SECURITY_REPOSITORY/",
      "${CODEX_SECURITY_REPOSITORY}/",
      `${repositoryPrefix}/`,
    ]) {
      if (!value.startsWith(prefix)) continue;
      const path = value
        .slice(prefix.length)
        .replace(/["'\r\n].*$/u, "")
        .trim()
        .replace(/\/+$/u, "")
        .replace(/:\d+(?::\d+)?$/u, "");
      if (
        path !== "" &&
        !path.startsWith("../") &&
        !path.split("/").includes("..")
      ) {
        paths.add(path);
      }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
