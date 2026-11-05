import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  analyzeToolReadCoverage,
  type ObservableToolRead,
} from "../src/tool-read-coverage.js";

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "tool-read-coverage-"));
  directories.push(root);
  const repository = join(root, "repository");
  await mkdir(join(repository, "src"), { recursive: true });
  await writeFile(
    join(repository, "src", "one.ts"),
    "first\nsecond\nthird\nfourth\nfifth\n",
  );
  await writeFile(join(repository, "src", "two.ts"), "alpha\nbeta\ngamma\n");
  return { root, repository };
}

function tool(
  cwd: string,
  id: string,
  command: string,
  output: unknown,
): ObservableToolRead {
  return {
    id,
    name: "exec_command",
    cwd,
    input: { cmd: command },
    output,
    outputSource: "model_tool_response",
  };
}

test.skipIf(process.platform === "win32")(
  "leaves named pipes unattributed without waiting for a writer",
  async () => {
    const { repository } = await fixture();
    const fifo = spawnSync("mkfifo", [join(repository, "pending.fifo")]);
    expect(fifo.status, fifo.stderr?.toString()).toBe(0);
    const result = await analyzeToolReadCoverage(
      [tool(repository, "pipe", "cat pending.fifo", "previous output\n")],
      { repository },
    );
    expect(result.files).toEqual([]);
    expect(result.calls[0]!.status).toBe("unattributed");
  },
);

test("merges noncontiguous excerpts and distinguishes search lines from full content", async () => {
  const { repository } = await fixture();
  const result = await analyzeToolReadCoverage(
    [
      tool(repository, "read-a", "sed -n '1,2p' src/one.ts", "first\nsecond\n"),
      tool(repository, "read-b", "sed -n '4,5p' src/one.ts", "fourth\nfifth\n"),
      tool(
        repository,
        "search",
        "rg -n third src",
        "src/one.ts:3:third\nsrc/two.ts:2:beta\n",
      ),
    ],
    { repository },
  );
  expect(result.files).toMatchObject([
    {
      path: "src/one.ts",
      kind: "excerpt",
      directLineRanges: [
        [1, 2],
        [4, 5],
      ],
      searchLineRanges: [[3, 3]],
    },
    {
      path: "src/two.ts",
      kind: "search-only",
      directLineRanges: [],
      searchLineRanges: [[2, 2]],
    },
  ]);
  expect(result.files[0]!.evidence.map((evidence) => evidence.callId)).toEqual([
    "read-a",
    "read-b",
    "search",
  ]);
});

test("attributes literal code-mode command batches and allSettled outputs without evaluating code", async () => {
  const { repository } = await fixture();
  const input =
    "const r=await Promise.allSettled([tools.exec_command({cmd:'cd \"$CODEX_SECURITY_REPOSITORY\"\\ncat src/one.ts'}),tools.exec_command({cmd:'nl -ba \"$CODEX_SECURITY_REPOSITORY/src/two.ts\" | sed -n \\'2,3p\\''})]);r.forEach(text);";
  const result = await analyzeToolReadCoverage(
    [
      {
        id: "batch",
        name: "exec",
        input,
        outputSource: "model_tool_response",
        output: [
          { type: "input_text", text: "Script completed\nOutput:\n" },
          {
            type: "input_text",
            text: JSON.stringify({
              status: "fulfilled",
              value: {
                exit_code: 0,
                output: "first\nsecond\nthird\nfourth\nfifth\n",
              },
            }),
          },
          {
            type: "input_text",
            text: JSON.stringify({
              status: "fulfilled",
              value: { exit_code: 0, output: "     2\tbeta\n     3\tgamma\n" },
            }),
          },
        ],
      },
    ],
    { repository, scopePaths: ["src/one.ts"] },
  );
  expect(result.files).toMatchObject([
    {
      path: "src/one.ts",
      kind: "complete",
      directLineRanges: [[1, 5]],
      inScope: true,
    },
    {
      path: "src/two.ts",
      kind: "excerpt",
      directLineRanges: [[2, 3]],
      inScope: false,
    },
  ]);
});

test("matches both retained ends of truncated output without crediting the gap", async () => {
  const { repository } = await fixture();
  const result = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "truncated",
        "cat src/one.ts",
        "first\nsecond\n…42 tokens truncated…\nfifth\n",
      ),
      tool(repository, "missing", "cat src/two.ts", undefined),
    ],
    { repository },
  );
  expect(result.files).toMatchObject([
    {
      path: "src/one.ts",
      kind: "excerpt",
      directLineRanges: [
        [1, 2],
        [5, 5],
      ],
    },
  ]);
  expect(result.truncatedCalls).toBe(1);
  expect(result.unattributedCalls).toBe(1);
});

test("does not infer source reads from commands, captured process output, or unknown execution", async () => {
  const { repository } = await fixture();
  const result = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "failed",
        "cat src/one.ts",
        "cat: src/one.ts: Permission denied\n",
      ),
      tool(
        repository,
        "unknown",
        "python inspect.py src/one.ts",
        "first\nsecond\nthird\nfourth\nfifth\n",
      ),
      {
        ...tool(
          repository,
          "captured",
          "cat src/one.ts",
          "first\nsecond\nthird\nfourth\nfifth\n",
        ),
        outputSource: "captured_process_output",
      },
      tool(repository, "filename-only", "rg --files src", "src/one.ts\n"),
    ],
    { repository },
  );
  expect(result.files).toEqual([]);
  expect(result.unattributedCalls).toBe(4);
});

test("verifies search text and structured rg line numbers against source", async () => {
  const { repository } = await fixture();
  const json = (line: number, content: string) =>
    JSON.stringify({
      type: "match",
      data: {
        path: { text: "src/two.ts" },
        line_number: line,
        lines: { text: content },
      },
    });
  const result = await analyzeToolReadCoverage(
    [
      tool(repository, "search", "rg --json alpha src", [
        {
          type: "input_text",
          text: json(1, "alpha\n") + "\n" + json(2, "WRONG\n"),
        },
      ]),
    ],
    { repository },
  );
  expect(result.files).toMatchObject([
    { path: "src/two.ts", searchLineRanges: [[1, 1]], kind: "search-only" },
  ]);
});

test("rejects paths and symlinks outside the repository and keeps scan instances isolated", async () => {
  const { root, repository } = await fixture();
  const outside = join(root, "outside.txt");
  await writeFile(outside, "outside source\n");
  await symlink(outside, join(repository, "linked.txt"));
  const first = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "outside",
        "cat ../outside.txt linked.txt",
        "outside source\n",
      ),
      tool(repository, "read", "cat src/two.ts", "alpha\nbeta\ngamma\n"),
    ],
    { repository },
  );
  expect(first.files.map((file) => file.path)).toEqual(["src/two.ts"]);
  expect((await analyzeToolReadCoverage([], { repository })).files).toEqual([]);
});

test("does not recover source content by repairing truncated JSON", async () => {
  const { repository } = await fixture();
  const result = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "cut-json",
        "cat src/one.ts",
        'Warning: truncated output (original token count: 100)\nTotal output lines: 1\n\n{"output":"first\\nsecond',
      ),
    ],
    { repository },
  );
  expect(result.files).toEqual([]);
  expect(result.truncatedCalls).toBe(1);
});

test("does not credit identical requested files from one ambiguous retained copy", async () => {
  const { repository } = await fixture();
  await writeFile(join(repository, "src", "same-a.ts"), "shared\n");
  await writeFile(join(repository, "src", "same-b.ts"), "shared\n");
  const result = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "shared",
        "cat src/same-a.ts src/same-b.ts",
        "shared\n…42 tokens truncated…",
      ),
    ],
    { repository },
  );
  expect(result.files).toEqual([]);
});

test("preserves JSON source text instead of interpreting arbitrary source as a result envelope", async () => {
  const { repository } = await fixture();
  const content = '{"output":"ordinary source data"}\n';
  await writeFile(join(repository, "src", "data.json"), content);
  const result = await analyzeToolReadCoverage(
    [
      tool(repository, "json", "cat src/data.json", {
        exit_code: 0,
        output: content,
      }),
      tool(
        repository,
        "redirected",
        "cat src/one.ts >/dev/null",
        "first\nsecond\nthird\nfourth\nfifth\n",
      ),
    ],
    { repository },
  );
  expect(result.files).toMatchObject([
    { path: "src/data.json", kind: "complete" },
  ]);
});

test("keeps literal working directory overrides attached to each command", async () => {
  const { repository } = await fixture();
  await mkdir(join(repository, "other"));
  await writeFile(join(repository, "other", "two.ts"), "other content\n");
  const result = await analyzeToolReadCoverage(
    [
      {
        ...tool(repository, "explicit", "cat two.ts", "alpha\nbeta\ngamma\n"),
        input: { cmd: "cat two.ts", workdir: join(repository, "src") },
      },
      {
        id: "nested",
        name: "exec",
        cwd: repository,
        outputSource: "model_tool_response",
        input: `text(await tools.exec_command({cmd:'cat two.ts',workdir:${JSON.stringify(join(repository, "other"))},max_output_tokens:1000}));`,
        output: { exit_code: 0, output: "other content\n" },
      },
      {
        id: "dynamic",
        name: "exec",
        cwd: repository,
        outputSource: "model_tool_response",
        input:
          "text(await tools.exec_command({cmd:'cat src/one.ts',workdir:chooseDirectory()}));",
        output: "first\nsecond\nthird\nfourth\nfifth\n",
      },
    ],
    { repository },
  );
  expect(result.files.map((file) => file.path)).toEqual([
    "other/two.ts",
    "src/two.ts",
  ]);
  expect(result.calls.find((call) => call.callId === "dynamic")!.status).toBe(
    "unattributed",
  );
});

test("requires a known working directory for relative paths", async () => {
  const { repository } = await fixture();
  const { cwd: _cwd, ...withoutCwd } = tool(
    repository,
    "relative",
    "cat src/two.ts",
    "alpha\nbeta\ngamma\n",
  );
  const result = await analyzeToolReadCoverage(
    [
      withoutCwd,
      tool(
        repository,
        "dynamic-cd",
        'cd "$DYNAMIC_DIRECTORY"\ncat src/two.ts',
        "alpha\nbeta\ngamma\n",
      ),
      {
        ...withoutCwd,
        id: "absolute",
        input: {
          cmd: `cat ${JSON.stringify(join(repository, "src", "two.ts"))}`,
        },
      },
    ],
    { repository },
  );
  expect(result.calls.map((call) => call.status)).toEqual([
    "unattributed",
    "unattributed",
    "matched",
  ]);
});

test("leaves search attribution unknown when different directories can supply the same retained line", async () => {
  const { repository } = await fixture();
  for (const directory of ["a", "b"]) {
    await mkdir(join(repository, directory));
    await writeFile(
      join(repository, directory, "shared.ts"),
      "const token = true;\n",
    );
  }
  const result = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "search",
        "cd a\nrg -n token .\ncd ../b\nrg -n token .",
        "./shared.ts:1:const token = true;\nWarning: truncated output",
      ),
    ],
    { repository },
  );
  expect(result.files).toEqual([]);
});

test("attributes a large numbered excerpt and its separate truncated tail", async () => {
  const { repository } = await fixture();
  const content = Array.from(
    { length: 14000 },
    (_, index) => `source line ${index + 1}`,
  );
  await writeFile(join(repository, "large.txt"), content.join("\n") + "\n");
  const numbered = (start: number, end: number) =>
    content
      .slice(start - 1, end)
      .map((line, index) => `${start + index}\t${line}`)
      .join("\n");
  const result = await analyzeToolReadCoverage(
    [
      tool(
        repository,
        "large",
        "nl -ba large.txt",
        `${numbered(1, 10000)}\n…1000 tokens truncated…\n${numbered(13999, 14000)}\n`,
      ),
    ],
    { repository },
  );
  expect(result.files[0]!.directLineRanges).toEqual([
    [1, 10000],
    [13999, 14000],
  ]);
});
