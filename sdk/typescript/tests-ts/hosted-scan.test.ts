import { execFileSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createHash } from "node:crypto";
import { PassThrough, Writable } from "node:stream";
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  normalizeHostedScope,
  normalizeHostedPaths,
  HostedScanInputSchema,
  type HostedScanInput,
  type ScanExecutionRequest,
} from "../src/hosted-scan.js";
import { runHostedScanProtocol } from "../src/hosted-scan-protocol.js";
import { runHostProtocol } from "../src/host-protocol.js";
import { CodexSecurity, runHostedScan } from "../src/index.js";
import type {
  ScanExecutionEvent,
  ScanExecutionResult,
} from "../src/scan-executor.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function fixture(): Promise<HostedScanInput> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "hosted-scan-"));
  roots.push(root);
  const repository = join(root, "repository");
  for (const name of ["service-a", "service-b", "service-c"]) {
    await mkdir(join(repository, name), { recursive: true });
    await writeFile(
      join(repository, name, "index.ts"),
      "export const value = 1;\n",
    );
  }
  const git = (...args: string[]) =>
    execFileSync("git", ["-C", repository, ...args], {
      encoding: "utf8",
    }).trim();
  git("init", "-q");
  git("add", ".");
  git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.invalid",
    "commit",
    "-qm",
    "fixture",
  );
  return {
    version: 2,
    repository,
    revision: git("rev-parse", "HEAD"),
    scope: { paths: ["service-a"] },
    outputDirectory: join(root, "output"),
    stateDirectory: join(root, "state"),
    model: "gpt-5.6-sol",
    reasoningEffort: "high",
    identity: {
      runId: "run-1",
      attemptId: "attempt-1",
      buildId: "fixture-build",
    },
  };
}

async function writeDraft(request: ScanExecutionRequest) {
  const directory = request.runtime.outputDirectory;
  const documents = {
    "scan-manifest.json": {
      scan: {
        target: { kind: "git_revision" },
        scope: {
          summary: "Synthetic scope fixture",
          runtimeStatus: "not_run",
          limitations: [],
        },
      },
    },
    "findings.json": { findings: [] },
    "coverage.json": {
      completeness: "complete",
      inventoryStrategy:
        request.scope.paths[0] === "." ? "repository" : "scoped_path",
      surfaces: [
        {
          id: "fixture",
          label: "Synthetic scope fixture",
          disposition: "no_issue_found",
          receiptRefs: [],
          notes: "Synthetic test only.",
        },
      ],
      explicitExclusions: [],
      deferred: [],
    },
  };
  for (const [name, document] of Object.entries(documents))
    await writeFile(join(directory, name), JSON.stringify(document));
}

test.each([
  "/tmp",
  "C:/src",
  "../src",
  "src/../other",
  "src/*",
  "a,b",
  "a\\b",
  "a\n",
])("rejects unsupported scope %p", (path) =>
  expect(() => normalizeHostedScope(path)).toThrow(),
);

test.each(["service-a", "service-a/index.ts", "."])(
  "hosted Standard scope %p is finalized and sealed by the CLI",
  async (path) => {
    const input = await fixture();
    input.scope!.paths = [path];
    const requests: ScanExecutionRequest[] = [];
    const result = await runHostedScan(input, {
      executor: {
        async run(request) {
          requests.push(request);
          expect(request.identity).toEqual(input.identity);
          expect(request.runtime.environment).not.toHaveProperty(
            "OPENAI_API_KEY",
          );
          expect(request.runtime.environment).not.toHaveProperty(
            "CODEX_API_KEY",
          );
          const preflight = JSON.parse(
            execFileSync(
              request.runtime.environment["PYTHON"]!,
              [
                join(request.runtime.pluginRoot, "scripts/config_preflight.py"),
                "--profile",
                "security_scan",
                "--cwd",
                request.runtime.outputDirectory,
                "--runtime-check",
                "delegation_available=true",
                "--config",
                request.runtime.environment["CODEX_SECURITY_CONFIG_PATH"]!,
              ],
              { encoding: "utf8", env: request.runtime.environment },
            ),
          );
          expect(preflight.status).toBe("ready");
          await writeDraft(request);
          return {
            requestId: request.requestId,
            status: "completed",
            sessionId: "host-session",
            usage: {
              input_tokens: 10,
              cached_input_tokens: 0,
              output_tokens: 5,
            },
          };
        },
      },
    });
    expect(result.status, JSON.stringify(result)).toBe("completed");
    expect(requests).toHaveLength(1);
    const manifest = JSON.parse(
      await readFile(
        join(result.outputDirectory, "scan-manifest.json"),
        "utf8",
      ),
    );
    const coverage = JSON.parse(
      await readFile(join(result.outputDirectory, "coverage.json"), "utf8"),
    );
    expect(manifest.scan.scope.includePaths).toEqual([path]);
    expect(manifest.scan.target.revision).toBe(input.revision);
    expect(manifest.scan.sealedAt).toBeTruthy();
    expect(coverage.mode).toBe(path === "." ? "repository" : "scoped_path");
    expect(coverage.completeness).toBe("complete");
    expect(
      await readFile(join(result.outputDirectory, "report.md"), "utf8"),
    ).toContain(path === "." ? "repository" : path);
  },
);

test("preparation verifies revision and rejects missing or escaping paths before execution", async () => {
  const input = await fixture();
  const executor = {
    async run(): Promise<never> {
      throw new Error("must not execute");
    },
  };
  await expect(
    runHostedScan(
      { ...input, revision: "0".repeat(40), scope: { paths: ["missing"] } },
      { executor },
    ),
  ).rejects.toThrow("frozen revision");
  await expect(
    runHostedScan({ ...input, scope: { paths: ["missing"] } }, { executor }),
  ).rejects.toThrow("does not exist");
  await symlink(
    tmpdir(),
    join(input.repository, "escape"),
    process.platform === "win32" ? "junction" : "dir",
  );
  await expect(
    runHostedScan({ ...input, scope: { paths: ["escape"] } }, { executor }),
  ).rejects.toThrow("outside the repository");
});

test("remote uncertainty is terminal with no local fallback or resubmission", async () => {
  const input = await fixture();
  let calls = 0;
  const result = await runHostedScan(input, {
    executor: {
      async run() {
        calls++;
        throw new Error("Remote acceptance unknown");
      },
    },
  });
  expect(calls).toBe(1);
  expect(result.status).toBe("acceptance_unknown");
  expect(result).toHaveProperty("error", "Remote acceptance unknown");
});

test("hosted aliases require a canonical path before inference, including aliases to root", async () => {
  const input = await fixture();
  const executor = {
    async run(): Promise<never> {
      throw new Error("must not execute");
    },
  };
  for (const [name, target] of [
    ["alias", join(input.repository, "service-a")],
    ["root-alias", input.repository],
  ] as const) {
    await symlink(
      target,
      join(input.repository, name),
      process.platform === "win32" ? "junction" : "dir",
    );
    await expect(
      runHostedScan({ ...input, scope: { paths: [name] } }, { executor }),
    ).rejects.toMatchObject({ reason: "scope_alias" });
  }
});

test("a completed model turn without artifacts is not a completed scan", async () => {
  const usage = { input_tokens: 123, output_tokens: 7 };
  const result = await runHostedScan(await fixture(), {
    executor: {
      async run(request) {
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "host-session",
          usage,
        };
      },
    },
  });
  expect(result.status).not.toBe("completed");
  expect(result.artifacts).toEqual([]);
  expect(result.execution).toMatchObject({
    status: "completed",
    sessionId: "host-session",
    usage,
  });
});

test("sealed partial coverage remains incomplete", async () => {
  const result = await runHostedScan(await fixture(), {
    executor: {
      async run(request) {
        await writeDraft(request);
        const file = join(request.runtime.outputDirectory, "coverage.json");
        const coverage = JSON.parse(await readFile(file, "utf8"));
        coverage.completeness = "partial";
        coverage.surfaces[0].disposition = "needs_follow_up";
        await writeFile(file, JSON.stringify(coverage));
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "host-session",
        };
      },
    },
  });
  expect(result.status).toBe("incomplete");
  expect(result.artifacts.map((artifact) => artifact.path)).toContain(
    "coverage.json",
  );
});

test("a changed checkout cannot produce accepted completed output", async () => {
  const input = await fixture();
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        await writeDraft(request);
        execFileSync("git", [
          "-C",
          input.repository,
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.invalid",
          "commit",
          "--allow-empty",
          "-qm",
          "changed",
        ]);
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "host-session",
        };
      },
    },
  });
  expect(result.status).not.toBe("completed");
  expect(result.artifacts).toEqual([]);
});

test("hosted scans create their private nested output and state directories", async () => {
  const input = await fixture();
  input.outputDirectory = join(
    input.outputDirectory,
    "run",
    "attempt",
    "output",
  );
  input.stateDirectory = join(input.stateDirectory, "run", "attempt", "state");
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        await writeDraft(request);
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "host-session",
        };
      },
    },
  });
  expect(result.status, JSON.stringify(result)).toBe("completed");
});

test("malformed run input returns one protocol error", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => {
    text += chunk.toString();
  });
  const completed = runHostedScanProtocol(input, output);
  input.write(
    JSON.stringify({
      jsonrpc: "2.0",
      id: "run",
      method: "run",
      params: { version: 2 },
    }) + "\n",
  );
  expect(await completed).toBe(2);
  const messages = text
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(messages).toHaveLength(1);
  expect(messages[0].error.code).toBe(-32602);
});

test("a missing scope has a typed preparation error and never asks for execution", async () => {
  const params = await fixture();
  params.scope!.paths = ["missing"];
  const input = new PassThrough();
  const output = new PassThrough();
  let text = "";
  output.on("data", (chunk) => {
    text += chunk.toString();
  });
  const completed = runHostedScanProtocol(input, output);
  input.write(
    JSON.stringify({ jsonrpc: "2.0", id: "run", method: "run", params }) + "\n",
  );
  expect(await completed).toBe(2);
  const messages = text
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(messages).toHaveLength(1);
  expect(messages[0].error.data).toEqual({ reason: "scope_missing" });
});

test.each([
  { args: ["scan", "--host=true"] },
  { args: ["scan", "--host", "--path", "service-a"] },
  { args: ["scan", ".", "--host"] },
])("host mode rejects unsupported combinations %p", async ({ args }) => {
  const stdout = capture();
  const stderr = capture();
  expect(await main(args, stdout.stream, stderr.stream, dependencies())).toBe(
    2,
  );
  expect(stdout.text()).toBe("");
  expect(stderr.text()).toContain("--host must be used alone");
});

test.each([false, true])(
  "built CLI pipes support hosted execution and cancellation (%p)",
  async (cancel) => {
    const input = await fixture();
    const child = spawn(
      process.execPath.includes("bun") ? "node" : process.execPath,
      [
        join(import.meta.dirname, "../bin/codex-security.mjs"),
        "scan",
        "--host",
      ],
      {
        env: {
          PATH: process.env["PATH"],
          TMPDIR: process.env["TMPDIR"],
          SYSTEMROOT: process.env["SYSTEMROOT"],
        },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const closed = new Promise<number | null>((resolve, reject) => {
      child.on("exit", resolve);
      child.on("error", reject);
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    try {
      child.stdin.write(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "run",
          method: "run",
          params: input,
        }) + "\n",
      );
      let final;
      let executions = 0;
      for await (const line of createInterface({ input: child.stdout })) {
        const message = JSON.parse(line);
        if (message.method === "execution.run") {
          executions++;
          if (cancel) {
            child.kill("SIGTERM");
            continue;
          }
          await writeDraft(message.params);
          child.stdin.write(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result: {
                requestId: message.params.requestId,
                status: "completed",
                sessionId: "fake-host",
              },
            }) + "\n",
          );
        } else if (message.id === "run") final = message;
      }
      expect(await closed, stderr).toBe(cancel ? 143 : 0);
      expect(executions).toBe(1);
      if (!cancel) expect(final.result.status).toBe("completed");
    } finally {
      child.kill();
    }
  },
);

const progressEvent: ScanExecutionEvent = {
  type: "progress",
  progress: { phase: "discovery", filesCompleted: 1, filesTotal: 2 },
};
const activityEvent: ScanExecutionEvent = {
  type: "activity",
  activity: {
    id: "activity-1",
    kind: "tool",
    status: "running",
    description: "Reading selected files",
    paths: ["service-a/index.ts"],
  },
};

test("multiple paths are normalized together, retained in every artifact, and hashed", async () => {
  const input = await fixture();
  input.scope = { paths: ["./service-b/", "service-a", "service-a/"] };
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        expect(request.scope.paths).toEqual(["service-a", "service-b"]);
        await writeDraft(request);
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "multi-session",
        };
      },
    },
  });
  expect(result.status, JSON.stringify(result)).toBe("completed");
  expect(result.scope.paths).toEqual(["service-a", "service-b"]);
  for (const name of ["scan-manifest.json", "coverage.json"]) {
    const file = JSON.parse(
      await readFile(join(result.outputDirectory, name), "utf8"),
    );
    expect(
      name === "coverage.json"
        ? file.includePaths
        : file.scan.scope.includePaths,
    ).toEqual(["service-a", "service-b"]);
  }
  const report = await readFile(
    join(result.outputDirectory, "report.md"),
    "utf8",
  );
  expect(report).toContain("service-a");
  expect(report).toContain("service-b");
  expect(report).not.toContain("service-c");
  for (const artifact of result.artifacts) {
    const data = await readFile(join(result.outputDirectory, artifact.path));
    expect(artifact.sha256).toBe(
      createHash("sha256").update(data).digest("hex"),
    );
    expect(artifact.bytes).toBe(data.byteLength);
  }
  const manifest = JSON.parse(
    await readFile(join(result.outputDirectory, "scan-manifest.json"), "utf8"),
  );
  for (const path of Object.keys(manifest.scan.preservedSources ?? {}))
    expect(result.artifacts.map((value) => value.path)).toContain(path);
  for (const artifact of manifest.scan.artifacts)
    expect(result.artifacts.map((value) => value.path)).toContain(
      artifact.path,
    );
});

test("omitting protocol scope mirrors the CLI default of the entire repository", async () => {
  const input = await fixture();
  delete input.scope;
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        expect(request.scope.paths).toEqual(["."]);
        await writeDraft(request);
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "whole-repository",
        };
      },
    },
  });
  expect(result.status, JSON.stringify(result)).toBe("completed");
  expect(result.scope.paths).toEqual(["."]);
});

test("empty or root-mixed explicit scopes fail instead of broadening", () => {
  expect(() => normalizeHostedPaths([])).toThrow();
  expect(() => normalizeHostedPaths(["service-a", "."])).toThrow();
  expect(() => normalizeHostedPaths(["service-a", "./"])).toThrow();
  expect(normalizeHostedPaths()).toEqual(["."]);
  expect(normalizeHostedPaths(["\u{10000}", "\uE000"])).toEqual([
    "\uE000",
    "\u{10000}",
  ]);
});

test("one missing or escaping path rejects the entire multi-path request before dispatch", async () => {
  const input = await fixture();
  let dispatched = false;
  const executor = {
    async run(): Promise<never> {
      dispatched = true;
      throw new Error("Unexpected dispatch");
    },
  };
  for (const paths of [
    ["service-a", "missing"],
    ["service-a", "../escape"],
  ]) {
    await expect(
      runHostedScan({ ...input, scope: { paths } }, { executor }),
    ).rejects.toThrow();
    expect(dispatched).toBe(false);
  }
  await expect(
    runHostedScan({ ...input, scope: { paths: [] } }, { executor }),
  ).rejects.toThrow();
});

test("standalone SDK forwards progress, isolates observer errors and defaults to full scan", async () => {
  const input = await fixture();
  delete input.scope;
  const events: string[] = [];
  const result = await runHostedScan(input, {
    executor: {
      async run(request, options) {
        expect(request.scope.paths).toEqual(["."]);
        expect(request.runtime.environment).not.toHaveProperty(
          "OPENAI_API_KEY",
        );
        options.onEvent?.(progressEvent);
        options.onEvent?.(activityEvent);
        await writeDraft(request);
        return {
          requestId: request.requestId,
          status: "completed",
          sessionId: "public-sdk",
        };
      },
    },
    onEvent(event) {
      events.push(event.type);
      if (event.type === "progress")
        throw new Error("Optional progress failed");
    },
  });
  expect(result.status, JSON.stringify(result)).toBe("completed");
  expect(events).toContain("progress");
  expect(events).toContain("activity");
});

test("standalone SDK passes the frozen model settings to its executor", async () => {
  const input = await fixture();
  const requests: ScanExecutionRequest[] = [];
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        requests.push(request);
        return {
          requestId: request.requestId,
          status: "failed",
          message: "Synthetic stop after dispatch",
        };
      },
    },
  });
  expect(result.status).toBe("failed");
  expect(requests).toHaveLength(1);
  expect(requests[0]?.model).toBe(input.model);
  expect(requests[0]?.reasoningEffort).toBe(input.reasoningEffort);
});

test.each(["failed", "canceled", "acceptance_unknown"] as const)(
  "standalone SDK retains %s host identity and usage in its terminal receipt",
  async (status) => {
    const input = await fixture();
    const usage = {
      authoritative_snapshot: { input_tokens: 123, output_tokens: 7 },
    };
    let receipt: ScanExecutionResult | undefined;
    const terminal = await runHostedScan(input, {
      executor: {
        async run(request) {
          receipt = {
            requestId: request.requestId,
            status,
            sessionId: "remote-session",
            usage,
            error: {
              code: -32010,
              message: "Recorded remote outcome",
              data: { remoteTurnId: "turn-1" },
            },
          };
          return receipt;
        },
      },
    });
    expect(terminal.status).toBe(status);
    expect(terminal.execution).toEqual(receipt);
    expect(terminal.artifacts).toEqual([]);
  },
);

test("SDK cancellation waits for the executor receipt without losing known session/usage", async () => {
  const input = await fixture();
  const controller = new AbortController();
  const result = await runHostedScan(input, {
    signal: controller.signal,
    executor: {
      async run(request, options) {
        controller.abort();
        expect(options.signal.aborted).toBe(true);
        await Promise.resolve();
        return {
          requestId: request.requestId,
          status: "canceled",
          sessionId: "canceled-session",
          usage: { input_tokens: 42 },
        };
      },
    },
  });
  expect(result.status).toBe("canceled");
  expect(result.execution).toMatchObject({
    status: "canceled",
    sessionId: "canceled-session",
    usage: { input_tokens: 42 },
  });
});

test("mismatched execution receipts are never accepted or retried", async () => {
  const input = await fixture();
  let calls = 0;
  const result = await runHostedScan(input, {
    executor: {
      async run() {
        calls++;
        return {
          requestId: "other-request",
          status: "completed",
          sessionId: "known-session",
          usage: { input_tokens: 9 },
        };
      },
    },
  });
  expect(calls).toBe(1);
  expect(result.status).toBe("acceptance_unknown");
  expect(result.execution?.sessionId).toBe("known-session");
  expect(result.artifacts).toEqual([]);
});

test("same Cloud attempt does not create CLI cross-invocation replay decisions", async () => {
  const input = await fixture();
  const requests: string[] = [];
  const executor = {
    async run(request: ScanExecutionRequest): Promise<ScanExecutionResult> {
      requests.push(request.requestId);
      return {
        requestId: request.requestId,
        status: "acceptance_unknown",
        sessionId: "host-owned-session",
      };
    },
  };
  for (const suffix of ["first", "second"]) {
    const result = await runHostedScan(
      { ...input, outputDirectory: join(input.outputDirectory, suffix) },
      { executor },
    );
    expect(result.status).toBe("acceptance_unknown");
  }
  expect(requests).toHaveLength(2);
  expect(requests[0]).not.toBe(requests[1]);
});

test("wire progress and explicit cancel retain the host's cancellation receipt", async () => {
  const params = await fixture();
  const input = new PassThrough();
  const messages: Record<string, any>[] = [];
  let request: ScanExecutionRequest | undefined;
  const send = (value: unknown) => input.write(JSON.stringify(value) + "\n");
  const output = new Writable({
    write(chunk, _encoding, callback) {
      const message = JSON.parse(chunk.toString());
      messages.push(message);
      callback();
      setImmediate(() => {
        if (message.method === "execution.run") {
          request = message.params;
          send({
            jsonrpc: "2.0",
            method: "execution.progress",
            params: { requestId: request!.requestId, event: progressEvent },
          });
          send({
            jsonrpc: "2.0",
            method: "execution.progress",
            params: { requestId: request!.requestId, event: { invalid: true } },
          });
          send({ jsonrpc: "2.0", method: "cancel", params: { id: "run" } });
        } else if (message.method === "execution.cancel") {
          expect(message.params.requestId).toBe(request!.requestId);
          send({
            jsonrpc: "2.0",
            id: request!.requestId,
            result: {
              requestId: request!.requestId,
              status: "canceled",
              sessionId: "canceled-wire-session",
              usage: { input_tokens: 88 },
            },
          });
        }
      });
    },
  });
  const finished = runHostedScanProtocol(input, output);
  send({ jsonrpc: "2.0", id: "run", method: "run", params });
  expect(await finished).toBe(1);
  expect(
    messages.filter((message) => message["method"] === "execution.run"),
  ).toHaveLength(1);
  expect(messages).toContainEqual({
    jsonrpc: "2.0",
    method: "scan.progress",
    params: { id: "run", event: progressEvent },
  });
  expect(messages.at(-1)?.["result"]).toMatchObject({
    status: "canceled",
    execution: {
      sessionId: "canceled-wire-session",
      usage: { input_tokens: 88 },
    },
  });
  input.destroy();
  output.destroy();
});

test.each(["cancel", "disconnect", "signal"])(
  "blocked execution request terminates on %s",
  async (action) => {
    const params = await fixture();
    const input = new PassThrough();
    const controller = new AbortController();
    const writing = Promise.withResolvers<void>();
    let release!: () => void;
    const output = new Writable({
      write(_chunk, _encoding, callback) {
        release = callback;
        writing.resolve();
      },
    });
    const finished = runHostedScanProtocol(input, output, controller.signal);
    input.write(
      JSON.stringify({ jsonrpc: "2.0", id: "run", method: "run", params }) +
        "\n",
    );
    await writing.promise;
    if (action === "cancel")
      input.write(
        JSON.stringify({
          jsonrpc: "2.0",
          method: "cancel",
          params: { id: "run" },
        }) + "\n",
      );
    else if (action === "signal") controller.abort();
    else input.end();
    expect(await finished).toBe(2);
    expect(output.destroyed).toBe(true);
    release();
    input.destroy();
    output.destroy();
  },
);

test.each(["result", "error"])(
  "disconnect interrupts a blocked terminal %s without a second response",
  async (terminal) => {
    const input = new PassThrough();
    const writing = Promise.withResolvers<void>();
    let release!: () => void;
    let writes = 0;
    const output = new Writable({
      write(_chunk, _encoding, callback) {
        writes++;
        release = callback;
        writing.resolve();
      },
    });
    const finished = runHostProtocol(input, output, {
      label: "Scan",
      requestMethod: "execution.run",
      async run() {
        if (terminal === "error") throw new Error("Invalid run parameters");
        return { status: "completed" };
      },
    });
    input.write(
      JSON.stringify({ jsonrpc: "2.0", id: "run", method: "run", params: {} }) +
        "\n",
    );
    await writing.promise;
    input.end();
    try {
      expect(await finished).toBe(terminal === "result" ? 0 : 2);
      expect(output.destroyed).toBe(true);
      expect(writes).toBe(1);
    } finally {
      release();
      input.destroy();
      output.destroy();
    }
  },
);

test("the exported contract fixture matches v2 and rejects explicit empty scope", async () => {
  const fixture = JSON.parse(
    await readFile(
      join(import.meta.dirname, "../schemas/hosted-scan-v2.fixture.json"),
      "utf8",
    ),
  );
  expect(HostedScanInputSchema.parse(fixture.run.params).scope).toEqual({
    paths: ["service-a", "service-b"],
  });
  expect(
    HostedScanInputSchema.safeParse({
      ...fixture.run.params,
      scope: { paths: [] },
    }).success,
  ).toBe(false);
  expect(
    HostedScanInputSchema.safeParse({ ...fixture.run.params, scope: undefined })
      .success,
  ).toBe(true);
});

test("standalone SDK rejects local scan options and configuration before dispatch", async () => {
  const input = await fixture();
  let dispatched = false;
  const executor = {
    async run(): Promise<never> {
      dispatched = true;
      throw new Error("Unexpected execution");
    },
  };
  for (const extra of [
    { mode: "deep" },
    { config: { codexOverrides: { profile: "local" } } },
  ])
    await expect(
      runHostedScan({ ...input, ...extra }, { executor }),
    ).rejects.toThrow("Unrecognized key");
  expect(dispatched).toBe(false);
});

test("ordinary SDK rejects the removed hosted option instead of using local inference", async () => {
  const client = new CodexSecurity();
  try {
    await expect(
      client.run("unused-repository", {
        // @ts-expect-error Legacy JavaScript callers must fail before local inference.
        hosted: {},
      }),
    ).rejects.toThrow("Use runHostedScan with an executor");
  } finally {
    await client.close();
  }
});
