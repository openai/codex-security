import { describe, expect, test } from "bun:test";
import { observedFilesFromLogs } from "../src/observed-files.js";

const scan = {
  targetPath: "/repo",
  startedAt: "2026-10-22T12:00:00Z",
  completedAt: "2026-10-22T12:10:00Z",
};
const during = "2026-10-22T12:01:00Z";
function event(
  payload: Record<string, unknown>,
  threadId = "parent",
  timestamp = during,
) {
  return { threadId, event: { type: "response_item", timestamp, payload } };
}
function cwd(threadId = "parent", directory = "/repo") {
  return {
    threadId,
    event: { type: "session_meta", payload: { id: threadId, cwd: directory } },
  };
}
function read(
  command: string,
  output = "export const value = 1;\n",
  options: {
    id?: string;
    thread?: string;
    timestamp?: string;
    workdir?: string;
    exitCode?: number;
    name?: "exec_command" | "shell_command";
  } = {},
) {
  const id = options.id ?? command;
  const name = options.name ?? "exec_command";
  const args = {
    [name === "exec_command" ? "cmd" : "command"]: command,
    ...(options.workdir === undefined ? {} : { workdir: options.workdir }),
  };
  return [
    event(
      {
        type: "function_call",
        call_id: id,
        name,
        arguments: JSON.stringify(args),
      },
      options.thread,
      options.timestamp,
    ),
    event(
      {
        type: "function_call_output",
        call_id: id,
        output:
          name === "shell_command"
            ? `Exit code: ${options.exitCode ?? 0}\nWall time: 0.1 seconds\nOutput:\n${output}`
            : `Chunk ID: fixture\nWall time: 0.1000 seconds\nProcess exited with code ${options.exitCode ?? 0}\nOutput:\n${output}`,
      },
      options.thread,
      options.timestamp,
    ),
  ];
}
function paths(events: Record<string, unknown>[]) {
  return observedFilesFromLogs(scan, {
    events: [cwd(), ...events],
    sessions: [],
  }).map(({ path }) => path);
}

describe("files observed in saved tool outputs", () => {
  test("deduplicates parent, worker and resumed reads and keeps supporting call identity", () => {
    expect(
      observedFilesFromLogs(scan, {
        sessions: [],
        events: [
          cwd(),
          cwd("worker", "/repo/src"),
          ...read("cat src/a.ts", undefined, { id: "first" }),
          ...read("head -n 10 ./a.ts", undefined, {
            id: "first",
            thread: "worker",
          }),
          ...read("cat /repo/src/a.ts", undefined, { id: "resumed" }),
          ...read("cat b.ts", undefined, { id: "second", thread: "worker" }),
        ],
      }),
    ).toEqual([
      { path: "src/a.ts", threadId: "parent", callId: "first" },
      { path: "src/b.ts", threadId: "worker", callId: "second" },
    ]);
  });
  test.each([
    "cat -- 'src/a file.ts'",
    "head -n 20 'src/a file.ts'",
    "tail -20 'src/a file.ts'",
    "nl -ba 'src/a file.ts'",
    "sed -n '1,20p' 'src/a file.ts'",
    "sed -n -e '1,20p' 'src/a file.ts'",
    "Get-Content -LiteralPath 'src/a file.ts' -TotalCount 20",
  ])("recognizes a single literal source read: %s", (command) => {
    expect(paths(read(command))).toEqual(["src/a file.ts"]);
  });
  test("uses retained search excerpts instead of the command's search scope", () => {
    expect(
      paths(
        read(
          "rg -n 'token' src",
          "src/a.ts:2:const token = 1;\nsrc/a.ts:9:token();\nsrc/b.ts:3:token();\n",
        ),
      ),
    ).toEqual(["src/a.ts", "src/b.ts"]);
    expect(
      paths(read("grep -H 'token' src/a.ts", "src/a.ts:const token = 1;\n")),
    ).toEqual(["src/a.ts"]);
  });
  test("excludes unresolved home expansion while retaining literal tilde paths", () => {
    expect(
      paths([
        ...read("cat ~/outside.ts"),
        ...read("cat ~other/outside.ts"),
        ...read("cat '~'/'literal.ts'"),
        ...read('cat "~/another.ts"'),
        ...read("cat src/~local.ts"),
      ]),
    ).toEqual(["~/literal.ts", "~/another.ts", "src/~local.ts"]);
  });
  test("excludes filenames, counts, scripts, compounds, failed reads and empty output", () => {
    expect(
      paths([
        ...read("rg --files", "src/a.ts\n"),
        ...read("rg -l token src", "src/a.ts\n"),
        ...read("rg -c token src", "src/a.ts:5\n"),
        ...read("grep -nc token src/a.ts", "src/a.ts:5\n"),
        ...read("rg token src/a.ts", "accidental-path: source text\n"),
        ...read("rg --heading token src", "src/a.ts\n1:token\n"),
        ...read("rg --json token src", '{"type":"match"}\n'),
        ...read("ls src", "a.ts\n"),
        ...read("python -c 'print(open(\"src/a.ts\").read())'"),
        ...read("cat src/a.ts src/b.ts"),
        ...read("cat src/*.ts"),
        ...read("cat src/a.ts; cat src/b.ts"),
        ...read("cat src/a.ts | head -10"),
        ...read("sed -n '1ihello' src/a.ts"),
        ...read("cat src/a.ts", "cat: src/a.ts: No such file or directory\n", {
          exitCode: 1,
        }),
        ...read("cat src/empty.ts", ""),
        ...read(
          "cat src/truncated.ts",
          "Warning: truncated output (original token count: 100)\n…100 tokens truncated…\n",
        ),
      ]),
    ).toEqual([]);
  });
  test("bounds calls and outputs to scan execution and pairs calls within each thread", () => {
    const crossed = read("cat crossed.ts", undefined, { id: "crossed" });
    crossed[0]!.event.timestamp = "2026-10-22T11:59:59Z";
    expect(
      paths([
        ...read("cat before.ts", undefined, {
          timestamp: "2026-10-22T11:59:00Z",
        }),
        ...read("cat after.ts", undefined, {
          timestamp: "2026-10-22T12:11:00Z",
        }),
        ...crossed,
        read("cat unknown.ts")[0]!,
        read("cat unknown.ts", undefined, { thread: "worker" })[1]!,
        ...read("cat during.ts"),
      ]),
    ).toEqual(["during.ts"]);
  });
  test("honors turn and command directories and excludes paths outside the repository", () => {
    expect(
      paths([
        {
          threadId: "parent",
          event: { type: "turn_context", payload: { cwd: "/repo/src" } },
        },
        ...read("cat local.ts"),
        ...read("cat selected.ts", undefined, { workdir: "/repo/test" }),
        ...read("cat ../../outside.ts"),
        ...read("cat /repo-other/outside.ts"),
      ]),
    ).toEqual(["src/local.ts", "test/selected.ts"]);
    expect(
      observedFilesFromLogs(scan, {
        sessions: [],
        events: read("cat unknown-cwd.ts"),
      }),
    ).toEqual([]);
  });
  test("normalizes and deduplicates Windows reads and filename-prefixed search results", () => {
    expect(
      observedFilesFromLogs(
        { ...scan, targetPath: "C:\\repo" },
        {
          sessions: [],
          events: [
            cwd("parent", "C:\\repo\\src"),
            ...read("Get-Content -Path '.\\a file.ts'"),
            ...read("Get-Content -Path 'c:\\REPO\\src\\A FILE.ts'"),
            ...read("Get-Content -Path 'D:\\outside.ts'"),
            ...read("rg -n token .", "C:\\repo\\src\\b.ts:2:token();\n"),
          ],
        },
      ).map(({ path }) => path),
    ).toEqual(["src/a file.ts", "src/b.ts"]);
  });
  test("uses only model-facing output and supports shell and content-item envelopes", () => {
    const items = read("cat items.ts");
    items[1]!.event.payload["output"] = [
      { type: "input_text", text: items[1]!.event.payload["output"] },
    ];
    const raw = read("cat raw.ts");
    raw[1]!.event.type = "event_msg";
    expect(
      paths([
        ...read("cat shell.ts", undefined, { name: "shell_command" }),
        ...items,
        ...raw,
        event({
          type: "custom_tool_call",
          name: "exec",
          call_id: "code",
          input: 'await tools.exec_command({cmd:"cat hidden.ts"})',
        }),
        event({
          type: "custom_tool_call_output",
          call_id: "code",
          output: "done",
        }),
        ...read(
          "rg -nH token src",
          "Warning: truncated output (original token count: 100)\nsrc/kept.ts:1:token();\n…100 tokens truncated…\n",
        ),
      ]),
    ).toEqual(["shell.ts", "items.ts", "src/kept.ts"]);
  });
});
