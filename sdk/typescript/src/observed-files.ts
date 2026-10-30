import { posix, win32 } from "node:path";
import { isRecord } from "./record.js";

export interface ObservedFile {
  path: string;
  threadId: string;
  callId: string;
}

type Command = { cwd?: string; words: string[] };

/** Source files identifiable in retained, model-facing shell output, not review coverage. */
export function observedFilesFromLogs(
  scan: { targetPath: string; startedAt: string; completedAt?: string | null },
  logs: { events: Record<string, unknown>[]; sessions: unknown[] },
): ObservedFile[] {
  const start = Date.parse(scan.startedAt);
  const end =
    scan.completedAt == null ? Infinity : Date.parse(scan.completedAt);
  const paths = /^[a-z]:[\\/]|^\\\\/iu.test(scan.targetPath) ? win32 : posix;
  const observed = new Map<string, ObservedFile>();
  const directories = new Map<string, string>();
  const calls = new Map<string, Command>();
  for (const entry of logs.events) {
    const { threadId, event } = entry;
    if (typeof threadId !== "string" || !isRecord(event)) continue;
    const payload = event["payload"];
    if (!isRecord(payload)) continue;
    if (
      (event["type"] === "session_meta" && payload["id"] === threadId) ||
      event["type"] === "turn_context"
    ) {
      if (typeof payload["cwd"] === "string") {
        directories.set(threadId, payload["cwd"]);
      }
      continue;
    }
    if (event["type"] !== "response_item") continue;
    const timestamp =
      typeof event["timestamp"] === "string"
        ? Date.parse(event["timestamp"])
        : NaN;
    if (!(timestamp >= start && timestamp <= end)) continue;
    const callId = payload["call_id"];
    if (typeof callId !== "string") continue;
    const key = JSON.stringify([threadId, callId]);
    if (payload["type"] === "function_call") {
      const command = shellCommand(payload, directories.get(threadId));
      if (command !== null) calls.set(key, command);
      continue;
    }
    if (payload["type"] !== "function_call_output") continue;
    const command = calls.get(key);
    if (command === undefined) continue;
    const output = retainedOutput(payload["output"]);
    if (output === null || payload["success"] === false) continue;
    for (const file of sourceFiles(command.words, output)) {
      if (/[*?\[\]{}$`]/u.test(file)) continue;
      const cwd = command.cwd;
      if (cwd !== undefined && !paths.isAbsolute(cwd)) continue;
      if (!paths.isAbsolute(file) && cwd === undefined) continue;
      const absolute = paths.resolve(cwd ?? scan.targetPath, file);
      const relative = paths.relative(scan.targetPath, absolute);
      if (
        relative === "" ||
        relative === ".." ||
        relative.startsWith(`..${paths.sep}`) ||
        paths.isAbsolute(relative)
      ) {
        continue;
      }
      const path = relative.split(paths.sep).join("/");
      const identity = paths === win32 ? path.toLowerCase() : path;
      if (!observed.has(identity)) {
        observed.set(identity, { path: identity, threadId, callId });
      }
    }
  }
  return [...observed.values()];
}

function shellCommand(
  payload: Record<string, unknown>,
  cwd: string | undefined,
): Command | null {
  const name = payload["name"];
  if (name !== "exec_command" && name !== "shell_command") return null;
  if (typeof payload["arguments"] !== "string") return null;
  let args: unknown;
  try {
    args = JSON.parse(payload["arguments"]);
  } catch {
    return null;
  }
  if (!isRecord(args)) return null;
  const command = args[name === "exec_command" ? "cmd" : "command"];
  if (typeof command !== "string") return null;
  const words = literalWords(command);
  if (words === null) return null;
  const directory = typeof args["workdir"] === "string" ? args["workdir"] : cwd;
  return { words, ...(directory === undefined ? {} : { cwd: directory }) };
}

// Only tokenize literal commands. Pipelines, substitutions, glob expansion and
// multiple commands need attribution that saved shell output does not provide.
function literalWords(command: string): string[] | null {
  const words: string[] = [];
  let word = "";
  let quote = "";
  let started = false;
  for (let index = 0; index < command.length; index++) {
    const char = command[index]!;
    if (quote !== "") {
      if (char === quote) quote = "";
      else {
        if (quote === '"' && /[$`]/u.test(char)) return null;
        word += char;
      }
      continue;
    }
    if (/[\r\n;|&<>$`(){}]/u.test(char)) return null;
    // An unquoted leading tilde depends on shell home context absent from logs.
    if (char === "~" && !started) return null;
    if (char === "'" || char === '"') {
      quote = char;
      started = true;
    } else if (char === "\\" && /[\s'"\\]/u.test(command[index + 1] ?? "")) {
      word += command[++index];
      started = true;
    } else if (/\s/u.test(char)) {
      if (started) words.push(word);
      word = "";
      started = false;
    } else {
      word += char;
      started = true;
    }
  }
  if (quote !== "") return null;
  if (started) words.push(word);
  return words;
}

function retainedOutput(value: unknown): string | null {
  const text =
    typeof value === "string"
      ? value
      : Array.isArray(value)
        ? value
            .filter((item) => isRecord(item) && item["type"] === "input_text")
            .map((item) => item["text"])
            .filter((item): item is string => typeof item === "string")
            .join("\n")
        : "";
  // These are the shell_command and unified exec model-output envelopes. Never
  // use event_msg exec output, which may precede model-output truncation.
  const envelope = text.match(
    /^(?:Exit code: \d+\nWall time: [^\n]+\n|(?:Chunk ID: [^\n]+\n)?Wall time: [^\n]+\n)[\s\S]*?\n?Output:\n?/u,
  );
  if (envelope === null) return null;
  if (
    /^(?:Exit code:|Process exited with code) (?!0(?:\n|$))\d+/mu.test(
      envelope[0],
    )
  ) {
    return null;
  }
  const output = text.slice(envelope[0].length);
  // With no retained content, truncation notices are not evidence of a read.
  const content = output
    .replace(/^Warning: truncated output \(original token count: \d+\)\n/mu, "")
    .replace(/^.*\d+ tokens truncated.*$/gmu, "");
  return content.trim() === "" ? null : content;
}

function sourceFiles(words: string[], output: string): string[] {
  const [executable, ...args] = words;
  if (executable === undefined) return [];
  const name = executable.split(/[\\/]/u).at(-1)!.toLowerCase();
  if (name === "rg" || name === "grep") {
    const search = sourceSearch(args);
    if (search === null) return [];
    return output.split(/\r?\n/u).flatMap((line) => {
      // Require a filename prefix and source text; filename-only searches and
      // count modes are rejected by sourceSearch before interpreting output.
      const match = line.match(/^((?:[a-z]:[\\/])?[^:]+):(?:\d+:)?(.+)$/iu);
      if (match === null || match[1] === name) return [];
      const file = match[1]!;
      // A search of one file normally omits its name. A colon in source text
      // is not a filename prefix unless the command's scope supports it.
      const prefixed =
        search.withFilename ||
        search.targets.length > 1 ||
        (name === "rg" && search.targets.length === 0) ||
        search.targets.some((target) => {
          const directory = target.replaceAll("\\", "/").replace(/\/$/u, "");
          return (
            directory === "." ||
            file.replaceAll("\\", "/").startsWith(`${directory}/`)
          );
        });
      return prefixed ? [file] : [];
    });
  }
  const file = singleRead(name, args);
  return file === null ? [] : [file];
}

function singleRead(name: string, args: string[]): string | null {
  let expression: string | undefined;
  const files: string[] = [];
  let options = true;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (options && arg === "--") {
      options = false;
      continue;
    }
    if (options && arg.startsWith("-")) {
      if (name === "cat" && /^-[benstuvAET]+$/u.test(arg)) continue;
      if (name === "head" || name === "tail") {
        if (/^-(?:[nc]?\d+|q)$|^--(?:lines|bytes)=\d+$/u.test(arg)) continue;
        if (["-n", "-c", "--lines", "--bytes"].includes(arg)) {
          if (!/^\d+$/u.test(args[++index] ?? "")) return null;
          continue;
        }
      }
      if (name === "nl") {
        if (/^-(?:b[ant]|w\d+|n(?:ln|rn|rz))$/u.test(arg)) continue;
        if (["-b", "-w", "-n", "-s"].includes(arg)) {
          if (args[++index] === undefined) return null;
          continue;
        }
      }
      if (name === "sed") {
        if (arg === "-n") continue;
        if (arg === "-e" && expression === undefined) {
          expression = args[++index];
          continue;
        }
      }
      if (name === "get-content") {
        const option = arg.toLowerCase();
        if (option === "-raw") continue;
        if (["-path", "-literalpath"].includes(option)) {
          const file = args[++index];
          if (file === undefined) return null;
          files.push(file);
          continue;
        }
        if (
          ["-totalcount", "-tail", "-readcount", "-encoding"].includes(option)
        ) {
          if (args[++index] === undefined) return null;
          continue;
        }
      }
      return null;
    }
    if (name === "sed" && expression === undefined) expression = arg;
    else files.push(arg);
  }
  if (!["cat", "head", "tail", "nl", "sed", "get-content"].includes(name))
    return null;
  if (
    name === "sed" &&
    !/^(?:\d+|\$)(?:,(?:\d+|\$))?p$/u.test(expression ?? "")
  )
    return null;
  return files.length === 1 && files[0] !== "-" ? files[0]! : null;
}

function sourceSearch(
  args: string[],
): { targets: string[]; withFilename: boolean } | null {
  let hasPattern = false;
  let options = true;
  let withFilename = false;
  const targets: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index]!;
    if (options && arg === "--") {
      options = false;
      continue;
    }
    if (!options || !arg.startsWith("-")) {
      if (hasPattern) targets.push(arg);
      else hasPattern = true;
      continue;
    }
    if (arg === "--with-filename") withFilename = true;
    if (/^-[nHiIsSwxFEPaUv]+$/u.test(arg)) {
      if (arg.includes("H")) withFilename = true;
      continue;
    }
    if (/^-(?:[ABCm])\d+$/u.test(arg)) continue;
    if (
      [
        "--line-number",
        "--with-filename",
        "--no-heading",
        "--hidden",
        "--fixed-strings",
        "--ignore-case",
        "--smart-case",
        "--word-regexp",
        "--invert-match",
        "--text",
        "--no-ignore",
        "--no-ignore-vcs",
        "--color=never",
      ].includes(arg)
    )
      continue;
    if (
      [
        "-e",
        "--regexp",
        "-g",
        "--glob",
        "--iglob",
        "-t",
        "--type",
        "-T",
        "--type-not",
        "-m",
        "--max-count",
        "-A",
        "-B",
        "-C",
        "--context",
        "--before-context",
        "--after-context",
      ].includes(arg)
    ) {
      if (args[++index] === undefined) return null;
      if (arg === "-e" || arg === "--regexp") hasPattern = true;
      continue;
    }
    return null;
  }
  return hasPattern ? { targets, withFilename } : null;
}
