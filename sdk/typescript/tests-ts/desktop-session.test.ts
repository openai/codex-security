import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";
import { prepareDesktopSession } from "../src/desktop-session.js";

test("starts and names a Codex app task", async () => {
  const directory = await mkdtemp(
    join(tmpdir(), "codex-security-desktop-session-"),
  );
  const script = join(directory, "app-server.mjs");
  const requestsPath = join(directory, "requests.jsonl");

  try {
    await writeFile(
      script,
      [
        'import { appendFileSync } from "node:fs";',
        'import { createInterface } from "node:readline";',
        "for await (const line of createInterface({ input: process.stdin })) {",
        "  const request = JSON.parse(line);",
        '  appendFileSync(process.env.CODEX_SECURITY_TEST_REQUESTS, JSON.stringify(request) + "\\n");',
        "  if (request.id === undefined) continue;",
        '  const result = request.method === "thread/start" ? { thread: { id: "visible-thread" } } : {};',
        '  process.stdout.write(JSON.stringify({ id: request.id, result }) + "\\n");',
        "}",
        "process.exit(0);",
      ].join("\n"),
    );
    const nodeExecutable = execFileSync("node", ["-p", "process.execPath"], {
      encoding: "utf8",
    }).trim();

    await expect(
      prepareDesktopSession({
        command: { command: nodeExecutable },
        environment: {
          NODE_OPTIONS: `--import=${pathToFileURL(script).href}`,
          CODEX_SECURITY_TEST_REQUESTS: requestsPath,
        },
        config: { model: "synthetic-model" },
        workingDirectory: directory,
        title: "Security scan: example",
        signal: new AbortController().signal,
      }),
    ).resolves.toBe("visible-thread");

    const requests = (await readFile(requestsPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(requests.map(({ method }) => method)).toEqual([
      "initialize",
      "initialized",
      "thread/start",
      "thread/name/set",
    ]);
    expect(requests[2]?.["params"]).toEqual({
      cwd: directory,
      approvalPolicy: "never",
      config: { model: "synthetic-model" },
    });
    expect(requests[3]?.["params"]).toEqual({
      threadId: "visible-thread",
      name: "Security scan: example",
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
