import { readFile, realpath, stat } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";

/** A retained observable tool call and its result, without private reasoning. */
export interface ObservableToolRead {
  id: string;
  threadId?: string;
  name: string;
  input: unknown;
  output: unknown;
  cwd?: string;
  outputSource: "model_tool_response" | "captured_process_output";
}

type LineRange = [number, number];
type Evidence = { callId: string; threadId?: string };
type Source = { path: string; lines: string[] };
type Read = { source: Source; start: number; end: number; numbered: boolean };

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return undefined;
  }
}

function lines(value: string): string[] {
  const result = value.split(/\r?\n/u);
  if (result.at(-1) === "") result.pop();
  return result;
}

/** Decode a JavaScript string literal without evaluating the surrounding code. */
function literal(value: string): string | undefined {
  if (value.startsWith('"')) {
    const parsed = parseJson(value);
    return typeof parsed === "string" ? parsed : undefined;
  }
  if (!value.startsWith("'") || !value.endsWith("'")) return undefined;
  let result = "";
  for (let i = 1; i < value.length - 1; i++) {
    const character = value[i]!;
    if (character !== "\\") {
      result += character;
      continue;
    }
    const escaped = value[++i];
    const escape: Record<string, string> = {
      n: "\n",
      r: "\r",
      t: "\t",
      "'": "'",
      '"': '"',
      "\\": "\\",
    };
    if (escaped === undefined || escape[escaped] === undefined)
      return undefined;
    result += escape[escaped];
  }
  return result;
}

type Command = { command: string; workdir?: string };

function commands(input: unknown, name: string): Command[] {
  if (record(input)) {
    const command = input["cmd"] ?? input["command"];
    const workdir = input["workdir"] ?? input["cwd"];
    if (
      typeof command !== "string" ||
      (workdir !== undefined && typeof workdir !== "string")
    )
      return [];
    return [{ command, ...(workdir === undefined ? {} : { workdir }) }];
  }
  if (typeof input !== "string") return [];
  const parsed = parseJson(input);
  if (record(parsed)) return commands(parsed, name);
  if (/^(?:exec_command|shell_command|shell)$/u.test(name))
    return [{ command: input }];
  if (!/(?:^|[._])exec$/u.test(name)) return [];
  const result: Command[] = [];
  // Restrict code-mode attribution to complete flat exec argument objects.
  // Keep each literal cwd with its command. Dynamic/spread arguments are not
  // evaluated, and cannot silently inherit a different working directory.
  for (const match of input.matchAll(
    /\b(?:exec_command|shell_command)\s*\(\s*\{((?:[^{}"'`]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')*)\}\s*\)/gu,
  )) {
    const fields =
      match[1]!.match(/(?:[^,"']|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')+/gu) ??
      [];
    const args: Record<string, unknown> = {};
    let supported = true;
    for (const field of fields) {
      const property =
        /^\s*(?:([A-Za-z_$][\w$]*)|"([^"]+)"|'([^']+)')\s*:\s*(.*?)\s*$/su.exec(
          field,
        );
      if (!property) {
        supported = false;
        break;
      }
      const key = property[1] ?? property[2] ?? property[3]!;
      if (["cmd", "command", "workdir", "cwd"].includes(key)) {
        const value = literal(property[4]!);
        if (value === undefined) {
          supported = false;
          break;
        }
        args[key] = value;
      }
    }
    if (supported) result.push(...commands(args, "exec_command"));
  }
  return result;
}

// Only these concrete envelopes are used by exec_command, text(), and
// Promise.allSettled in retained tool responses. Unknown content stays evidence
// in the trace, but is not interpreted as a successful source read here.
function outputText(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(outputText);
  if (record(value)) {
    if (value["type"] === "input_text" || value["type"] === "text")
      return outputText(value["text"]);
    if ("output" in value) return outputText(value["output"]);
    if (value["status"] === "fulfilled") return outputText(value["value"]);
    if (Array.isArray(value["content"])) return outputText(value["content"]);
    return [];
  }
  if (typeof value !== "string") return [];
  const parsed = parseJson(value);
  if (
    record(parsed) &&
    (("output" in parsed &&
      ("chunk_id" in parsed ||
        "exit_code" in parsed ||
        "wall_time_seconds" in parsed)) ||
      parsed["status"] === "fulfilled" ||
      Array.isArray(parsed["content"]))
  )
    return outputText(parsed);
  // Runtime truncation may leave valid JSON behind its warning header.
  const body = value.replace(
    /^Warning: truncated output[^\n]*\n(?:Total output lines: \d+\n)?\n/u,
    "",
  );
  if (body !== value) {
    const parsedBody = parseJson(body);
    if (parsedBody !== undefined) return outputText(parsedBody);
    return []; // Incomplete JSON cannot establish which bytes were returned.
  }
  return [value];
}

function hasTruncation(value: unknown): boolean {
  if (typeof value === "string")
    return /(?:truncated output|output truncated|tokens truncated|chars truncated|characters truncated)/iu.test(
      value,
    );
  if (Array.isArray(value)) return value.some(hasTruncation);
  if (record(value)) return Object.values(value).some(hasTruncation);
  return false;
}

/** Split a shell batch into literal words and separators; never execute it. */
function shellParts(command: string): string[][] {
  const parts: string[][] = [[]];
  let word = "";
  let quote: string | undefined;
  let started = false;
  const finish = () => {
    if (started) parts.at(-1)!.push(word);
    word = "";
    started = false;
  };
  for (let i = 0; i < command.length; i++) {
    const character = command[i]!;
    if (quote !== undefined) {
      if (character === quote) quote = undefined;
      else if (
        character === "\\" &&
        quote === '"' &&
        /["\\$`]/u.test(command[i + 1] ?? "")
      )
        word += command[++i];
      else word += character;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      started = true;
    } else if (character === "\\" && i + 1 < command.length) {
      word += command[++i];
      started = true;
    } else if (character === "\n" || character === ";" || character === "&") {
      finish();
      if (parts.at(-1)!.length) parts.push([]);
    } else if (/\s/u.test(character)) finish();
    else if (character === "|") {
      finish();
      parts.at(-1)!.push("|");
    } else {
      word += character;
      started = true;
    }
  }
  if (quote !== undefined) return [];
  finish();
  return parts.filter((part) => part.length > 0);
}

function literalPath(
  path: string,
  cwd: string | undefined,
  repository: string,
): string | undefined {
  const expanded = path.replace(
    /^\$(?:CODEX_SECURITY_REPOSITORY|\{CODEX_SECURITY_REPOSITORY\})(?=[/\\]|$)/u,
    repository,
  );
  if (/[`$*?{}\[\]<>]/u.test(expanded)) return undefined;
  if (isAbsolute(expanded)) return resolve(expanded);
  return cwd === undefined ? undefined : resolve(cwd, expanded);
}

function inside(repository: string, path: string): boolean {
  const local = relative(repository, path);
  return local !== ".." && !local.startsWith(`..${sep}`) && !isAbsolute(local);
}

function ranges(values: Set<number>): LineRange[] {
  const result: LineRange[] = [];
  for (const value of [...values].sort((a, b) => a - b)) {
    const last = result.at(-1);
    if (last && value === last[1] + 1) last[1] = value;
    else result.push([value, value]);
  }
  return result;
}

/**
 * Match retained model-facing tool text to current repository source. These are
 * content-delivery observations, not claims that the model reviewed a file.
 */
export async function analyzeToolReadCoverage(
  records: readonly ObservableToolRead[],
  options: { repository: string; scopePaths?: readonly string[] },
) {
  const repository = await realpath(options.repository);
  const sources = new Map<string, Source | null>();
  const observed = new Map<
    string,
    {
      source: Source;
      direct: Set<number>;
      search: Set<number>;
      evidence: Map<string, Evidence>;
    }
  >();
  const calls: Array<
    Evidence & {
      status: "matched" | "unattributed";
      truncated: boolean;
      paths: string[];
    }
  > = [];
  const source = async (path: string): Promise<Source | null> => {
    if (sources.has(path)) return sources.get(path)!;
    let result: Source | null = null;
    try {
      const actual = await realpath(path);
      if (inside(repository, actual) && (await stat(actual)).isFile()) {
        result = {
          path: relative(repository, inside(repository, path) ? path : actual)
            .split(sep)
            .join("/"),
          lines: lines(await readFile(actual, "utf8")),
        };
      }
    } catch (error) {
      if (!(record(error) && typeof error["code"] === "string")) throw error;
      // Missing, unreadable, and non-file paths provide no source evidence.
    }
    sources.set(path, result);
    return result;
  };
  for (const item of records) {
    const evidence: Evidence = {
      callId: item.id,
      ...(item.threadId === undefined ? {} : { threadId: item.threadId }),
    };
    const paths = new Set<string>();
    const truncated = hasTruncation(item.output);
    const retain = (file: Source, line: number, kind: "direct" | "search") => {
      let entry = observed.get(file.path);
      if (!entry) {
        entry = {
          source: file,
          direct: new Set(),
          search: new Set(),
          evidence: new Map(),
        };
        observed.set(file.path, entry);
      }
      entry[kind].add(line);
      entry.evidence.set(`${item.threadId ?? ""}\0${item.id}`, evidence);
      paths.add(file.path);
    };
    if (item.outputSource === "model_tool_response") {
      const reads: Read[] = [];
      const searchDirectories = new Set<string | undefined>();
      for (const { command, workdir } of commands(item.input, item.name)) {
        let cwd =
          workdir === undefined
            ? item.cwd
            : isAbsolute(workdir)
              ? resolve(workdir)
              : item.cwd === undefined
                ? undefined
                : resolve(item.cwd, workdir);
        for (const words of shellParts(command)) {
          const executable = words[0]?.replace(/^.*[/\\]/u, "");
          if (executable === "cd" && words.length === 2) {
            cwd = literalPath(words[1]!, cwd, repository);
            continue;
          }
          const pipe = words.indexOf("|");
          const argv = pipe === -1 ? words : words.slice(0, pipe);
          if (argv.some((word) => /[<>]/u.test(word))) continue;
          if (
            executable === "rg" &&
            argv.some((word) =>
              /^(?:-[a-zA-Z]*n[a-zA-Z]*|--line-number|--json)$/u.test(word),
            )
          ) {
            searchDirectories.add(cwd);
            continue;
          }
          let start = 1;
          let end = Infinity;
          let operands: string[] = [];
          let numbered = false;
          if (
            executable === "cat" &&
            argv
              .slice(1)
              .every((word) => !word.startsWith("-") || word === "--")
          ) {
            operands = argv.slice(1).filter((word) => word !== "--");
          } else if (executable === "nl" && argv[1] === "-ba") {
            numbered = true;
            operands = argv.slice(2);
          } else if (executable === "sed" && argv[1] === "-n") {
            const range = /^(\d+)(?:,(\d+|\$))?p$/u.exec(argv[2] ?? "");
            if (!range) continue;
            start = Number(range[1]);
            end = range[2] === "$" ? Infinity : Number(range[2] ?? range[1]);
            operands = argv.slice(3);
          }
          if (pipe !== -1) {
            const tail = words.slice(pipe + 1);
            if (
              tail[0] === "head" &&
              tail[1] === "-n" &&
              /^\d+$/u.test(tail[2] ?? "") &&
              tail.length === 3
            ) {
              end = Math.min(end, start + Number(tail[2]) - 1);
            } else if (
              tail[0] === "sed" &&
              tail[1] === "-n" &&
              tail.length === 3
            ) {
              const range = /^(\d+),(\d+)p$/u.exec(tail[2]!);
              if (!range) continue;
              end = Math.min(end, start + Number(range[2]) - 1);
              start += Number(range[1]) - 1;
            } else continue;
          }
          for (const operand of operands) {
            const path = literalPath(operand, cwd, repository);
            const file = path === undefined ? null : await source(path);
            if (file)
              reads.push({
                source: file,
                start,
                end: Math.min(end, file.lines.length),
                numbered,
              });
          }
        }
      }
      for (const output of outputText(item.output)) {
        const returned = lines(output);
        const fullyMatched = new Set<Read>();
        // A complete requested excerpt is unambiguous even if its lines repeat.
        for (const read of reads) {
          const expected = read.source.lines.slice(read.start - 1, read.end);
          if (read.numbered || expected.length === 0) continue;
          // A shared excerpt cannot identify which requested file supplied it.
          // Retaining one copy of two identical files must not count both.
          if (
            reads.some((other) => {
              if (other.source.path === read.source.path || other.numbered)
                return false;
              for (
                let offset = other.start - 1;
                offset + expected.length <= other.end;
                offset++
              ) {
                if (
                  expected.every(
                    (line, index) =>
                      line === other.source.lines[offset + index],
                  )
                )
                  return true;
              }
              return false;
            })
          )
            continue;
          for (
            let offset = 0;
            offset + expected.length <= returned.length;
            offset++
          ) {
            if (
              expected.every((line, index) => line === returned[offset + index])
            ) {
              for (let line = read.start; line <= read.end; line++)
                retain(read.source, line, "direct");
              fullyMatched.add(read);
              break;
            }
          }
        }
        // For partial output, require an anchor that identifies one requested
        // source line; adjacent matching lines then retain their attribution.
        const anchors = new Map<string, Array<{ read: Read; line: number }>>();
        for (const read of reads) {
          for (let line = read.start; line <= read.end; line++) {
            const key = read.numbered
              ? `${line}\t${read.source.lines[line - 1]}`
              : read.source.lines[line - 1]!;
            const matches = anchors.get(key) ?? [];
            if (
              !matches.some(
                (match) =>
                  match.read.source.path === read.source.path &&
                  match.line === line &&
                  match.read.numbered === read.numbered,
              )
            )
              matches.push({ read, line });
            anchors.set(key, matches);
          }
        }
        const normalized = returned.map((line) =>
          line.replace(/^\s+(?=\d+\t)/u, ""),
        );
        for (let offset = 0; offset < returned.length; offset++) {
          const matches =
            anchors.get(returned[offset]!) ?? anchors.get(normalized[offset]!);
          if (matches?.length !== 1) continue;
          const { read, line } = matches[0]!;
          if (fullyMatched.has(read)) continue;
          const matchesLine = (at: number, sourceLine: number) =>
            at >= 0 &&
            at < returned.length &&
            sourceLine >= read.start &&
            sourceLine <= read.end &&
            (read.numbered
              ? normalized[at] ===
                `${sourceLine}\t${read.source.lines[sourceLine - 1]}`
              : returned[at] === read.source.lines[sourceLine - 1]);
          let begin = 0;
          let end = 0;
          while (matchesLine(offset + begin - 1, line + begin - 1)) begin--;
          while (matchesLine(offset + end + 1, line + end + 1)) end++;
          for (let delta = begin; delta <= end; delta++)
            retain(read.source, line + delta, "direct");
          // Every remaining anchor in this contiguous run has already been
          // attributed. Revisiting it makes large source reads quadratic.
          offset += end;
        }
        if (searchDirectories.size > 0) {
          for (const line of returned) {
            const match = /^(.*?):(\d+):(.*)$/u.exec(line);
            const json = parseJson(line);
            let path: string | undefined;
            let number: number | undefined;
            let text: string | undefined;
            if (
              record(json) &&
              json["type"] === "match" &&
              record(json["data"])
            ) {
              const data = json["data"];
              if (
                record(data["path"]) &&
                record(data["lines"]) &&
                typeof data["path"]["text"] === "string" &&
                typeof data["lines"]["text"] === "string" &&
                typeof data["line_number"] === "number"
              ) {
                path = data["path"]["text"];
                number = data["line_number"];
                text = data["lines"]["text"];
              }
            } else if (match) {
              path = match[1];
              number = Number(match[2]);
              text = match[3];
            }
            if (
              path === undefined ||
              number === undefined ||
              text === undefined ||
              !Number.isSafeInteger(number) ||
              number < 1
            )
              continue;
            const candidates = new Map<string, Source>();
            for (const cwd of searchDirectories) {
              const absolute = literalPath(path, cwd, repository);
              const file =
                absolute === undefined ? null : await source(absolute);
              if (!file) continue;
              candidates.set(file.path, file);
            }
            for (const [offset, content] of lines(text).entries()) {
              const matches = [...candidates.values()].filter(
                (file) => content === file.lines[number + offset - 1],
              );
              if (matches.length === 1)
                retain(matches[0]!, number + offset, "search");
            }
          }
        }
      }
    }
    calls.push({
      ...evidence,
      status: paths.size ? "matched" : "unattributed",
      truncated,
      paths: [...paths].sort(),
    });
  }
  const files = [...observed.values()]
    .map(({ source, direct, search, evidence }) => ({
      path: source.path,
      inScope:
        options.scopePaths === undefined ||
        options.scopePaths.some(
          (path) =>
            path === "." ||
            source.path === path ||
            source.path.startsWith(`${path.replace(/\/$/u, "")}/`),
        ),
      totalLines: source.lines.length,
      kind:
        direct.size === source.lines.length
          ? ("complete" as const)
          : direct.size > 0
            ? ("excerpt" as const)
            : ("search-only" as const),
      directLineRanges: ranges(direct),
      searchLineRanges: ranges(search),
      evidence: [...evidence.values()],
    }))
    .sort((a, b) => a.path.localeCompare(b.path));
  return {
    basis: "current_source_text_matched_to_retained_model_tool_output",
    files,
    calls,
    truncatedCalls: calls.filter((call) => call.truncated).length,
    unattributedCalls: calls.filter((call) => call.status === "unattributed")
      .length,
    limitations: [
      "Content delivery does not establish semantic review, and absence is not proof that a file was never read.",
      "Source lines are verified against the current checkout; changed or unavailable source can reduce attribution.",
      "Only literal cat, sed, nl, head pipelines and numbered rg output are attributed; other commands remain in the retained trace.",
      "Captured process output is not counted as model delivery. Truncated or ambiguous output can leave lines unattributed.",
    ],
  };
}
