import { execFileSync, spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { hash } from "node:crypto";
import { PassThrough, Writable } from "node:stream";
import {
  appendFile,
  readFile,
  realpath,
  stat,
  symlink,
  unlink,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, isAbsolute, join } from "node:path";
import { afterEach, expect, mock, spyOn, test } from "bun:test";
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
import * as config from "../src/config.js";
import * as hostedScan from "../src/hosted-scan.js";
import * as ownerSuggestions from "../src/suggest-owners.js";
import {
  ScanExecutionEventSchema,
  ScanExecutionResultSchema,
  type ScanExecutionEvent,
  type ScanExecutionResult,
  type ScanExecutor,
} from "../src/scan-executor.js";
import { main } from "../src/cli.js";
import { capture, dependencies } from "./cli-fixtures.js";
import { normalizeTarget } from "../src/targets.js";
import { pythonExecutable } from "./support/python.js";
import { git } from "./git-fixture.js";
import { workbenchCommand } from "./support/workbench-command.js";
import {
  createApiTestFixtures,
  removeTemporaryDirectory,
} from "./support/temporary-directories.js";
import { parseJsonLines, readJson, writeJson } from "./support/json.js";
import { rejecting } from "./support/errors.js";
import { writeSource } from "./support/shell.js";

const { cleanup, temporaryDirectory } = createApiTestFixtures("hosted-scan-");
afterEach(cleanup);

test("hosted owner artifact is opt-in and included in the completed receipt", async () => {
  for (const enabled of [false, true]) {
    const input = await fixture();
    const executor = draftExecutor();
    const startThread = mock(() => {
      throw new Error("No additional owner turn");
    });
    const result = await runHostedScan(
      { ...input, ownerSuggestions: enabled },
      enabled ? { executor, ownerCodex: { startThread } } : { executor },
    );
    expect(result.status).toBe("completed");
    expect(executor.run).toHaveBeenCalledTimes(1);
    if (result.status !== "completed") throw new Error(result.status);
    expect(
      result.artifacts.some(({ path }) => path === "owner-suggestions.json"),
    ).toBe(enabled);
    const manifest = await readJson(
      join(input.outputDirectory, "scan-manifest.json"),
    );
    expect(JSON.stringify(manifest)).not.toContain("owner-suggestions.json");
    if (enabled) {
      expect(startThread).not.toHaveBeenCalled();
      expect(result).not.toHaveProperty("ownerSuggestionsError");
      expect(
        await readJson(join(input.outputDirectory, "owner-suggestions.json")),
      ).toMatchObject({
        schemaVersion: 2,
        revision: input.revision,
        results: [],
      });
    }
  }
});

test.each([false, true])(
  "owner failure preserves the completed hosted scan (cancel=%p)",
  async (cancel) => {
    const controller = new AbortController();
    const suggestion = spyOn(
      ownerSuggestions,
      "suggestOwnersInternal",
    ).mockImplementation(async () => {
      if (cancel) controller.abort();
      throw new Error("Synthetic owner-stage failure");
    });
    try {
      const input = await fixture();
      const executor = draftExecutor();
      const result = await runHostedScan(
        { ...input, ownerSuggestions: true },
        {
          executor,
          signal: controller.signal,
        },
      );
      expect(result.status).toBe("completed");
      expect(result).toHaveProperty(
        "ownerSuggestionsError",
        "Synthetic owner-stage failure",
      );
      expect(executor.run).toHaveBeenCalledTimes(1);
      expect(
        result.artifacts.some(({ path }) => path === "owner-suggestions.json"),
      ).toBe(false);
      expect(
        await readJson(join(input.outputDirectory, "scan-manifest.json")),
      ).toHaveProperty("scan.status", "completed");
    } finally {
      suggestion.mockRestore();
    }
  },
);

async function fixture(
  additionalFiles: readonly string[] = [],
): Promise<HostedScanInput> {
  const root = await temporaryDirectory();
  const repository = join(root, "repository");
  for (const name of [
    "service-a/index.ts",
    "service-b/index.ts",
    "service-c/index.ts",
    ...additionalFiles,
  ])
    writeSource(repository, name, "export const value = 1;\n");
  git(repository, "init", "-q");
  git(repository, "config", "--local", "core.autocrlf", "false");
  git(repository, "add", ".");
  git(repository, "commit", "-qm", "fixture");
  return {
    version: 2,
    repository,
    revision: git(repository, "rev-parse", "HEAD"),
    scope: { paths: ["service-a"] },
    outputDirectory: join(root, "run", "attempt", "output"),
    stateDirectory: join(root, "run", "attempt", "state"),
    model: "gpt-5.6-sol",
    reasoningEffort: "high",
    identity: {
      runId: "run-1",
      attemptId: "attempt-1",
      buildId: "fixture-build",
    },
  };
}

function hostedWorkbench(input: HostedScanInput, args: string[]) {
  const workbench = workbenchCommand(pythonExecutable()!, () => ({
    PATH: process.env["PATH"],
    SYSTEMROOT: process.env["SYSTEMROOT"],
    CODEX_SECURITY_STATE_DIR: input.stateDirectory,
  }));
  return workbench(args);
}

async function writeDraft(
  request: ScanExecutionRequest,
  receiptRefs: string[] = [],
) {
  const directory = request.runtime.outputDirectory;
  const reviewState = {
    inventoryStrategy:
      request.scope.paths[0] === "." ? "repository" : "scoped_path",
    surfaces: [
      {
        id: "fixture",
        label: "Synthetic scope fixture",
        disposition: "no_issue_found",
        receiptRefs,
        notes: "Synthetic test only.",
      },
    ],
    explicitExclusions: [],
    deferred: [],
  };
  const documents = {
    "scan-manifest.json": {
      scan: {
        mode: request.scope.paths[0] === "." ? "repository" : "scoped_path",
        reviewState,
        target: { kind: "git_revision" },
        scope: {
          summary: "Synthetic scope fixture",
          runtimeStatus: "not_run",
          limitations: [],
        },
      },
    },
    "findings.json": { findings: [] },
  };
  for (const [name, document] of Object.entries(documents))
    await writeJson(join(directory, name), document);
  return reviewState;
}

function receipt(
  request: Pick<ScanExecutionRequest, "requestId">,
  overrides: Partial<ScanExecutionResult> = {},
): ScanExecutionResult {
  return {
    requestId: request.requestId,
    status: "completed",
    sessionId: "host-session",
    ...overrides,
  };
}

function draftExecutor(
  afterDraft?: (
    ...args: Parameters<ScanExecutor["run"]>
  ) => void | Promise<void>,
) {
  return {
    run: mock<ScanExecutor["run"]>(async (request, options) => {
      await writeDraft(request);
      await afterDraft?.(request, options);
      return receipt(request);
    }),
  };
}

function noExecution() {
  return { run: mock(rejecting("must not execute")) };
}

const cleanupFailureMessage = "Synthetic hosted cleanup failed";

function failHostedCleanup() {
  const close = CodexSecurity.prototype.close;
  return spyOn(CodexSecurity.prototype, "close").mockImplementation(
    async function (this: CodexSecurity) {
      await close.call(this);
      throw new Error(cleanupFailureMessage);
    },
  );
}

function send(stream: Pick<Writable, "write">, message: object) {
  stream.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
}

async function protocolError(params: unknown) {
  const input = new PassThrough();
  const output = capture();
  const completed = runHostedScanProtocol(input, output.stream);
  send(input, { id: "run", method: "run", params });
  expect(await completed).toBe(2);
  const messages = parseJsonLines(output.text());
  expect(messages).toHaveLength(1);
  input.destroy();
  return messages[0].error;
}

function blockedOutput() {
  const writing = Promise.withResolvers<void>();
  let release!: () => void;
  const write = mock((_chunk, _encoding, callback) => {
    release = callback;
    writing.resolve();
  });
  return {
    output: new Writable({ write }),
    write,
    writing: writing.promise,
    release: () => release(),
  };
}

test.each([
  "/tmp",
  "",
  "nul\0path",
  "C:part.ts",
  "tab\tname.ts",
  "line\nname.ts",
  "invalid\ud800.ts",
  "../src",
  "src/../other",
  ...(process.platform === "win32" ? ["C:/src", "C:src", "a\\..\\b"] : []),
])("rejects unsupported scope %p", (path) =>
  expect(() => normalizeHostedScope(path)).toThrow(),
);

for (const path of ["C:part.ts", "tab\tname.ts", "line\nname.ts"]) {
  test.skipIf(process.platform === "win32")(
    `rejects tracked contract-incompatible scope ${JSON.stringify(path)} before execution`,
    async () => {
      const input = await fixture([path]);
      input.scope = { paths: [path] };
      const executor = noExecution();
      await expect(runHostedScan(input, { executor })).rejects.toMatchObject({
        reason: "scope_syntax",
      });
      expect(executor.run).not.toHaveBeenCalled();
    },
  );
}

const sealedScopes: {
  name: string;
  paths: string[];
  normalized?: string[];
  files?: string[];
  reported?: string[];
}[] = [
  { name: "repository", paths: ["."], reported: ["repository"] },
  { name: "directory", paths: ["service-a"] },
  { name: "file", paths: ["service-a/index.ts"] },
  {
    name: "multiple normalized paths",
    paths: ["./service-b/", "service-a", "service-a/"],
    normalized: ["service-a", "service-b"],
  },
  {
    name: "bracketed routes, commas and a literal tilde",
    paths: ["app/[slug]/page.tsx", "reports/a,b.ts", "~"],
    files: ["app/[slug]/page.tsx", "reports/a,b.ts", "~"],
    reported: [String.raw`app/\[slug\]/page.tsx`, '`"reports/a,b.ts"`', "~"],
  },
  ...(process.platform === "win32"
    ? []
    : [
        {
          name: "significant spaces and POSIX filename characters",
          paths: [" ", " service ", "literal/*?.ts", "service  space"],
          files: [
            " /index.ts",
            " service /index.ts",
            "service/index.ts",
            "literal/*?.ts",
            "service  space/index.ts",
            "service space/index.ts",
          ],
          reported: [
            '`" "`',
            '`" service "`',
            String.raw`literal/\*?.ts`,
            '`"service  space"`',
          ],
        },
      ]),
];

test.each(sealedScopes)(
  "hosted $name scope is retained in sealed artifacts and hashes",
  async ({ paths, normalized = paths, files, reported = normalized }) => {
    const input = await fixture(files);
    input.scope = { paths };
    if (files) {
      const ordinary = await normalizeTarget(
        input.repository,
        paths.map((path) => `./${path}`),
      );
      expect(ordinary.paths).toEqual(normalized);
    }
    const executor = draftExecutor((request) => {
      expect(request.scope.paths).toEqual(normalized);
      expect(request.identity).toEqual(input.identity);
      expect(request).toMatchObject({
        model: input.model,
        reasoningEffort: input.reasoningEffort,
      });
      for (const key of ["OPENAI_API_KEY", "CODEX_API_KEY"])
        expect(request.runtime.environment).not.toHaveProperty(key);
    });
    const result = await runHostedScan(input, { executor });
    expect(result.status, JSON.stringify(result)).toBe("completed");
    expect(executor.run).toHaveBeenCalledTimes(1);
    expect(result.scope.paths).toEqual(normalized);
    const manifest = await readJson<any>(
      join(result.outputDirectory, "scan-manifest.json"),
    );
    expect(manifest.scan.scope.includePaths).toEqual(normalized);
    expect(manifest.scan.target.revision).toBe(input.revision);
    expect(manifest.scan.sealedAt).toBeTruthy();
    expect(manifest.scan).toMatchObject({
      scope: { includePaths: normalized },
      mode: normalized[0] === "." ? "repository" : "scoped_path",
    });
    const report = await readFile(
      join(result.outputDirectory, "report.md"),
      "utf8",
    );
    for (const path of reported) expect(report).toContain(path);
    if (normalized.length > 1) expect(report).not.toContain("service-c");
    for (const artifact of result.artifacts) {
      const data = await readFile(join(result.outputDirectory, artifact.path));
      expect(artifact.sha256).toBe(hash("sha256", data));
      expect(artifact.bytes).toBe(data.byteLength);
    }
    const artifactPaths = result.artifacts.map((artifact) => artifact.path);
    for (const path of Object.keys(manifest.scan.preservedSources ?? {}))
      expect(artifactPaths).toContain(path);
    for (const artifact of manifest.scan.artifacts)
      expect(artifactPaths).toContain(artifact.path);
  },
);

test.skipIf(process.platform !== "linux").each([
  ["private", "completed"],
  ["private", "acceptance_unknown"],
  ["output", "completed"],
  ["lost", "completed"],
] as const)(
  "hosted scope generation with %s scratch preserves the %s receipt",
  async (storage, status) => {
    const input = await fixture(["service-a/nested/route [x].ts"]);
    const outputCopy = join(input.outputDirectory, "scoped-source-input.jsonl");
    let inventory = "";
    const run: ScanExecutor["run"] = async (request) => {
      const commands = request.prompt.split("\n");
      const [primary, recovery] = commands.filter((line) =>
        line.includes("--helper make-hosted-repo-scope-input "),
      );
      const environment = { ...request.runtime.environment };
      if (storage === "output")
        environment["CODEX_SECURITY_STATE_DIR"] =
          request.runtime.outputDirectory;
      const shell = (command: string) =>
        execFileSync("/bin/sh", ["-c", command], {
          cwd: request.runtime.outputDirectory,
          env: environment,
          encoding: "utf8",
        });
      const generate = (command: string) =>
        shell(command).match(/^Wrote 2 scoped paths to (.+)$/mu)![1]!;
      inventory = generate(primary!);
      if (storage !== "output") {
        expect(await realpath(dirname(inventory))).toBe(
          await realpath(request.runtime.stateDirectory),
        );
      }
      if (storage === "lost") {
        await unlink(inventory);
        inventory = generate(recovery!);
      }
      if (storage !== "private") expect(inventory).toBe(outputCopy);
      if (status === "completed") {
        await writeDraft(request);
        shell(
          commands.find((line) => line.includes("--helper bind-repo-scopes "))!,
        );
      }
      return receipt(request, { status });
    };
    const result = await runHostedScan(input, { executor: { run } });
    expect(result.status, JSON.stringify(result)).toBe(status);
    expect(result.execution?.sessionId).toBe("host-session");
    expect(parseJsonLines(await readFile(inventory, "utf8"))).toEqual([
      { path: "service-a/index.ts" },
      { path: "service-a/nested/route [x].ts" },
    ]);
    if (storage === "private")
      await expect(stat(outputCopy)).rejects.toMatchObject({ code: "ENOENT" });
  },
);

test("hosted execution preserves inspected runtime tool paths", async () => {
  const input = await fixture(["tools/placeholder.ts"]);
  const repositoryTools = await realpath(join(input.repository, "tools"));
  const linkedTools = join(await temporaryDirectory(), "linked-tools");
  const trustedTools = await realpath(dirname(process.execPath));
  await symlink(
    repositoryTools,
    linkedTools,
    process.platform === "win32" ? "junction" : "dir",
  );
  const executableAliases: string[] = [];
  for (const name of process.platform === "win32"
    ? ["node.exe"]
    : ["dirname", "node"]) {
    const directory = await temporaryDirectory();
    await symlink(
      join(repositoryTools, "placeholder.ts"),
      join(directory, name),
      "file",
    );
    executableAliases.push(await realpath(directory));
  }
  const previousPath = process.env["PATH"];
  const executor = draftExecutor();
  try {
    process.env["PATH"] = [
      repositoryTools,
      linkedTools,
      ...executableAliases,
      trustedTools,
      previousPath ?? "",
    ].join(delimiter);
    const result = await runHostedScan(input, { executor });
    expect(result.status).toBe("completed");
    expect(executor.run).toHaveBeenCalledTimes(1);
    const environment = executor.run.mock.calls[0]![0].runtime.environment;
    const paths = environment["PATH"]!.split(delimiter);
    expect(paths).not.toContain(repositoryTools);
    expect(paths).not.toContain(linkedTools);
    for (const directory of executableAliases)
      expect(paths).not.toContain(directory);
    expect(paths).toContain(trustedTools);
    expect(isAbsolute(environment["CODEX_SECURITY_GIT"] ?? "")).toBe(true);
    expect(isAbsolute(environment["PYTHON"] ?? "")).toBe(true);
  } finally {
    if (previousPath === undefined) delete process.env["PATH"];
    else process.env["PATH"] = previousPath;
  }
});

test.skipIf(process.platform === "win32")(
  "missing whitespace paths never fall back to a trimmed sibling or repository",
  async () => {
    const input = await fixture();
    const executor = noExecution();
    for (const path of [" ", " service-a "]) {
      await expect(
        runHostedScan({ ...input, scope: { paths: [path] } }, { executor }),
      ).rejects.toMatchObject({ reason: "scope_missing" });
    }
    expect(executor.run).not.toHaveBeenCalled();
  },
);

test.each(["missing", "file"] as const)(
  "hosted preparation preserves cancellation for a %s repository",
  async (kind) => {
    const root = await temporaryDirectory();
    const repository = join(root, kind);
    if (kind === "file") writeSource(root, kind, "owned fixture\n");
    const input: HostedScanInput = {
      version: 2,
      repository,
      revision: "a".repeat(40),
      outputDirectory: join(root, "output"),
      stateDirectory: join(root, "state"),
      model: "synthetic-model",
      reasoningEffort: "high",
      identity: {
        runId: "run-1",
        attemptId: "attempt-1",
        buildId: "fixture-build",
      },
    };
    const executor = noExecution();
    for (const timing of ["before", "during"] as const) {
      const controller = new AbortController();
      const reason = new Error(`Host canceled ${timing} preparation`);
      if (timing === "before") controller.abort(reason);
      const pending = runHostedScan(input, {
        executor,
        signal: controller.signal,
      });
      if (timing === "during") queueMicrotask(() => controller.abort(reason));
      await expect(pending).rejects.toBe(reason);
    }
    for (const options of [{}, { signal: new AbortController().signal }]) {
      await expect(
        runHostedScan(input, { executor, ...options }),
      ).rejects.toMatchObject({
        name: "InvalidTargetError",
        message: `Repository is not a directory: ${repository}`,
      });
    }
    const signal = AbortSignal.abort(new Error("Host canceled preparation"));
    await expect(
      runHostedScan({ ...input, revision: "invalid" }, { executor, signal }),
    ).rejects.toMatchObject({ name: "ZodError" });
    await expect(
      runHostedScan(
        { ...input, scope: { paths: ["../outside"] } },
        { executor, signal },
      ),
    ).rejects.toMatchObject({
      name: "HostedScanPreparationError",
      reason: "scope_syntax",
    });
    expect(executor.run).not.toHaveBeenCalled();
    for (const directory of [input.outputDirectory, input.stateDirectory]) {
      await expect(stat(directory)).rejects.toMatchObject({ code: "ENOENT" });
    }
  },
);

test("preparation verifies revision and rejects missing or escaping paths before execution", async () => {
  const input = await fixture();
  const executor = noExecution();
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
  expect(executor.run).not.toHaveBeenCalled();
});

test("remote uncertainty is terminal with no local fallback or resubmission", async () => {
  const executor = { run: mock(rejecting("Remote acceptance unknown")) };
  const result = await runHostedScan(await fixture(), { executor });
  expect(executor.run).toHaveBeenCalledTimes(1);
  expect(result.status).toBe("acceptance_unknown");
  expect(result).toHaveProperty("error", "Remote acceptance unknown");
});

test("hosted aliases require a canonical path before inference, including aliases to root", async () => {
  const input = await fixture();
  const executor = noExecution();
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
  expect(executor.run).not.toHaveBeenCalled();
});

test.each(["missing", "invalid"] as const)(
  "a completed model turn with %s artifacts fails the scan",
  async (artifacts) => {
    const usage = { input_tokens: 123, output_tokens: 7 };
    const result = await runHostedScan(await fixture(), {
      executor: {
        async run(request) {
          if (artifacts === "invalid") {
            await writeDraft(request);
            writeSource(
              request.runtime.outputDirectory,
              "findings.json",
              "{invalid JSON",
            );
          }
          return receipt(request, { usage });
        },
      },
    });
    expect(result.status).toBe("failed");
    expect(result.artifacts).toEqual([]);
    expect(result.execution).toMatchObject({
      status: "completed",
      sessionId: "host-session",
      usage,
    });
  },
);

test("sealed review with follow-up diagnostics remains completed", async () => {
  const result = await runHostedScan(await fixture(), {
    executor: draftExecutor(async (request) => {
      const file = join(request.runtime.outputDirectory, "scan-manifest.json");
      const manifest = await readJson<any>(file);
      manifest.scan.reviewState.surfaces[0].disposition = "needs_follow_up";
      await writeJson(file, manifest);
    }),
  });
  expect(result.status).toBe("completed");
  expect(result.artifacts.map((artifact) => artifact.path)).not.toContain(
    "coverage.json",
  );
});

test.each(["scan-manifest.json", "findings.json", "artifacts/evidence.txt"])(
  "changed bytes in %s cannot produce a completed hosted receipt",
  async (path) => {
    const original = CodexSecurity.prototype.run;
    using _swap = spyOn(CodexSecurity.prototype, "run").mockImplementation(
      async function (this: CodexSecurity, ...args) {
        const validated = await original.apply(this, args);
        await appendFile(join(validated.scanDir, path), "\n");
        return validated;
      },
    );
    const result = await runHostedScan(await fixture(), {
      executor: {
        async run(request) {
          const evidence = "artifacts/evidence.txt";
          writeSource(
            request.runtime.outputDirectory,
            evidence,
            "scan evidence",
          );
          await writeDraft(request, [evidence]);
          return receipt(request);
        },
      },
    });
    expect(result.status).toBe("failed");
    expect(result.artifacts).toEqual([]);
    expect(result).toHaveProperty(
      "error",
      `The sealed file ${path} changed before the hosted receipt was created.`,
    );
  },
);

test("hosted receipts hash MCP checkpoints as written", async () => {
  const { saveScanDraftCheckpoint } = await import(
    new URL(
      "../../../plugins/codex-security/mcp-app/src/artifact-scan-draft.ts",
      import.meta.url,
    ).href
  );
  const input = await fixture();
  const result = await runHostedScan(input, {
    executor: {
      async run(request) {
        const reviewState = await writeDraft(request);
        await saveScanDraftCheckpoint(
          {
            root: request.runtime.outputDirectory,
            repoRoot: request.repository,
            layout: "scan",
          },
          { scanId: request.scanId, findings: [], reviewState },
        );
        return receipt(request);
      },
    },
  });
  expect(result.status).toBe("completed");
  const manifest = await readJson<{
    scan: { preservedSources: Record<string, string> };
  }>(join(input.outputDirectory, "scan-manifest.json"));
  const checkpoint = result.artifacts.find(
    ({ path, sha256 }) =>
      path.startsWith("checkpoints/") &&
      Object.hasOwn(manifest.scan.preservedSources, path) &&
      sha256 !== manifest.scan.preservedSources[path],
  );
  expect(checkpoint).toBeDefined();
  const contents = await readFile(
    join(input.outputDirectory, checkpoint!.path),
  );
  expect(checkpoint!.sha256).toBe(hash("sha256", contents));
});

test("a changed checkout cannot produce accepted completed output", async () => {
  const input = await fixture();
  const result = await runHostedScan(input, {
    executor: draftExecutor(() => {
      git(input.repository, "commit", "--allow-empty", "-qm", "changed");
    }),
  });
  expect(result.status).toBe("failed");
  expect(result.artifacts).toEqual([]);
});

test("malformed run input returns one protocol error", async () => {
  expect((await protocolError({ version: 2 })).code).toBe(-32602);
});

test.each([
  { path: "missing", reason: "scope_missing" },
  { path: "C:part.ts", reason: "scope_syntax" },
  { path: "tab\tname.ts", reason: "scope_syntax" },
  { path: "line\nname.ts", reason: "scope_syntax" },
])(
  "scope %p has a typed preparation error and never asks for execution",
  async ({ path, reason }) => {
    const params = await fixture();
    params.scope!.paths = [path];
    expect((await protocolError(params)).data).toEqual({ reason });
  },
);

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
  "CLI pipes retain reasoning effort, progress and execution receipts, including cancellation (%p)",
  async (cancel) => {
    const input = await fixture();
    if (!cancel) {
      input.reasoningEffort = "synthetic-future-effort";
      input.ownerSuggestions = true;
    }
    const child = spawn(
      process.execPath,
      [join(import.meta.dirname, "../src/cli.ts"), "scan", "--host"],
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
    const messages: any[] = [];
    const usage = { input_tokens: 88 };
    let requestId: string | undefined;
    try {
      send(child.stdin, { id: "run", method: "run", params: input });
      for await (const line of createInterface({ input: child.stdout })) {
        const message = JSON.parse(line);
        messages.push(message);
        if (message.method === "execution.run") {
          expect(message.params.reasoningEffort).toBe(input.reasoningEffort);
          requestId = message.params.requestId;
          for (const event of [
            progressEvent,
            reviewProgressEvent,
            { invalid: true },
          ])
            send(child.stdin, {
              method: "execution.progress",
              params: { requestId, event },
            });
          if (cancel) {
            send(child.stdin, { method: "cancel", params: { id: "run" } });
          } else {
            await writeDraft(message.params);
            send(child.stdin, {
              id: message.id,
              result: receipt(message.params, {
                sessionId: "fake-host",
                usage,
              }),
            });
          }
        } else if (message.method === "execution.cancel") {
          expect(message.params.requestId).toBe(requestId);
          send(child.stdin, {
            id: requestId,
            result: receipt(message.params, {
              status: "canceled",
              sessionId: "fake-host",
              usage,
            }),
          });
        }
      }
      expect(await closed, stderr).toBe(cancel ? 1 : 0);
      expect(
        messages.filter((message) => message.method === "execution.run"),
      ).toHaveLength(1);
      for (const event of [progressEvent, reviewProgressEvent])
        expect(messages).toContainEqual({
          jsonrpc: "2.0",
          method: "scan.progress",
          params: { id: "run", event },
        });
      const response = messages.at(-1);
      expect(response).toMatchObject({
        id: "run",
        result: {
          status: cancel ? "canceled" : "completed",
          execution: { sessionId: "fake-host", usage },
        },
      });
      if (!cancel) {
        expect(response.result).not.toHaveProperty("ownerSuggestionsError");
        expect(response.result.artifacts).toContainEqual(
          expect.objectContaining({ path: "owner-suggestions.json" }),
        );
        expect(
          await readJson(join(input.outputDirectory, "owner-suggestions.json")),
        ).toMatchObject({
          schemaVersion: 2,
          revision: input.revision,
          results: [],
        });
      }
    } finally {
      child.kill();
    }
  },
);

const progressEvent: ScanExecutionEvent = {
  type: "progress",
  progress: { phase: "discovery", filesCompleted: 1, filesTotal: 2 },
};
const reviewProgressEvent: ScanExecutionEvent = {
  type: "progress",
  progress: {
    ...progressEvent.progress,
    phase: "validation",
    reviewItems: { completed: 3, total: 4 },
  },
};

test.each([
  { completed: -1, total: 4 },
  { completed: 5, total: 4 },
  { completed: 1.5, total: 4 },
])("rejects invalid hosted review counts %j", (reviewItems) => {
  expect(
    ScanExecutionEventSchema.safeParse({
      ...progressEvent,
      progress: { ...progressEvent.progress, reviewItems },
    }).success,
  ).toBe(false);
});

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
  const executor = noExecution();
  for (const paths of [
    [],
    ["service-a", "missing"],
    ["service-a", "../escape"],
  ]) {
    await expect(
      runHostedScan({ ...input, scope: { paths } }, { executor }),
    ).rejects.toThrow();
  }
  expect(executor.run).not.toHaveBeenCalled();
});

test("standalone SDK forwards progress, isolates observer errors and defaults to full scan", async () => {
  const input = await fixture();
  delete input.scope;
  const events: string[] = [];
  const result = await runHostedScan(input, {
    executor: draftExecutor((request, options) => {
      expect(request.scope.paths).toEqual(["."]);
      options.onEvent?.(progressEvent);
      options.onEvent?.(activityEvent);
    }),
    onEvent(event) {
      events.push(event.type);
      if (event.type === "progress")
        throw new Error("Optional progress failed");
    },
  });
  expect(result.status, JSON.stringify(result)).toBe("completed");
  expect(result.scope.paths).toEqual(["."]);
  expect(events).toContain("progress");
  expect(events).toContain("activity");
});

test.each([
  ["failed", undefined, false, "failed"],
  ["failed", "remote-session", false, "failed"],
  ["canceled", "remote-session", false, "canceled"],
  ["acceptance_unknown", "remote-session", false, "acceptance_unknown"],
  ["failed", "remote-session", true, "canceled"],
  ["canceled", "remote-session", true, "canceled"],
  ["acceptance_unknown", "remote-session", true, "acceptance_unknown"],
] as const)(
  "standalone SDK retains %s host receipt with session %p and caller abort %p, returning %s",
  async (status, sessionId, callerAborts, terminalStatus) => {
    const input = await fixture();
    const controller = new AbortController();
    const usage = {
      authoritative_snapshot: { input_tokens: 123, output_tokens: 7 },
    };
    let execution: ScanExecutionResult | undefined;
    const run = mock<ScanExecutor["run"]>(async (request, options) => {
      if (callerAborts) {
        controller.abort();
        expect(options.signal.aborted).toBe(true);
        await Promise.resolve();
      }
      execution = receipt(request, {
        status,
        sessionId,
        usage,
        error: {
          code: -32010,
          message: "Recorded remote outcome",
          data: { remoteTurnId: "turn-1" },
        },
      });
      return execution;
    });
    const terminal = await runHostedScan(input, {
      executor: { run },
      ...(callerAborts ? { signal: controller.signal } : {}),
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(terminal.status).toBe(terminalStatus);
    expect(terminal.execution).toEqual(execution);
    expect(terminal.artifacts).toEqual([]);
    const canceled = status === "canceled";
    const saved = await hostedWorkbench(input, [
      "get-scan",
      "--scan-id",
      terminal.scanId!,
    ]);
    expect(saved["scan"]).toMatchObject({
      progress: { status: canceled ? "canceled" : "failed" },
      canceledAt: canceled ? expect.any(String) : null,
      failureMessage: "Recorded remote outcome",
    });
  },
);

test("failed hosted config preparation removes its temporary runtime home", async () => {
  const input = await fixture();
  const executor = noExecution();
  let runtimeHome: string | undefined;
  const writeConfig = spyOn(config, "writeCodexConfig").mockImplementation(
    async (path) => {
      runtimeHome = dirname(path);
      throw new Error("Synthetic hosted config preparation failed");
    },
  );
  try {
    const result = await runHostedScan(input, { executor });
    expect(result).toMatchObject({
      status: "failed",
      error: "Synthetic hosted config preparation failed",
    });
    expect(executor.run).not.toHaveBeenCalled();
    expect(runtimeHome).toBeDefined();
    await expect(stat(runtimeHome!)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    writeConfig.mockRestore();
    if (runtimeHome !== undefined) await removeTemporaryDirectory(runtimeHome);
  }
});

test.each(["completed", "acceptance_unknown"] as const)(
  "SDK cleanup failure preserves the %s receipt even when its observer throws",
  async (status) => {
    const input = await fixture();
    const events: ScanExecutionEvent[] = [];
    let execution: ScanExecutionResult | undefined;
    const executor = {
      run: mock<ScanExecutor["run"]>(async (request) => {
        if (status === "completed") await writeDraft(request);
        execution = receipt(request, {
          status,
          sessionId: "known-host-session",
          usage: { input_tokens: 123, output_tokens: 7 },
          ...(status === "acceptance_unknown"
            ? {
                error: {
                  code: -32010,
                  message: "Recorded remote uncertainty",
                  data: { remoteTurnId: "turn-1" },
                },
              }
            : {}),
        });
        return execution;
      }),
    };
    const close = failHostedCleanup();
    try {
      const terminal = await runHostedScan(input, {
        executor,
        onEvent(event) {
          events.push(event);
          if (
            event.type === "activity" &&
            event.activity.id === "runtime.cleanup"
          )
            throw new Error("Optional cleanup observer failed");
        },
      });
      expect(terminal.status).toBe(status);
      expect(terminal.execution).toEqual(execution);
      expect(terminal.identity).toEqual(input.identity);
      expect(terminal.scanId).toBe(executor.run.mock.calls[0]![0].scanId);
      expect(executor.run).toHaveBeenCalledTimes(1);
      expect(close).toHaveBeenCalledTimes(1);
      expect(events).toContainEqual({
        type: "activity",
        activity: {
          id: "runtime.cleanup",
          kind: "message",
          status: "failed",
          description: expect.stringContaining(cleanupFailureMessage),
          paths: [],
        },
      });
      if (status === "completed") {
        expect(terminal.artifacts.map((artifact) => artifact.path)).toContain(
          "scan-manifest.json",
        );
        const manifest = await readJson<any>(
          join(terminal.outputDirectory, "scan-manifest.json"),
        );
        expect(manifest.scan.sealedAt).toBeTruthy();
      } else {
        expect(terminal).toHaveProperty("error", execution?.error?.message);
        expect(terminal.artifacts).toEqual([]);
      }
    } finally {
      close.mockRestore();
    }
  },
);

test("wire cleanup failure retains an uncertain terminal result and reports cleanup separately", async () => {
  const params = await fixture();
  const input = new PassThrough();
  const output = new PassThrough();
  const lines = createInterface({ input: output });
  const messages: any[] = [];
  let execution: ScanExecutionResult | undefined;
  const close = failHostedCleanup();
  try {
    const finished = runHostedScanProtocol(input, output);
    send(input, { id: "run", method: "run", params });
    for await (const line of lines) {
      const message = JSON.parse(line);
      messages.push(message);
      if (message.method === "execution.run") {
        execution = receipt(message.params, {
          status: "acceptance_unknown",
          sessionId: "known-host-session",
          usage: { input_tokens: 42 },
          error: {
            code: -32010,
            message: "Recorded remote uncertainty",
            data: { remoteTurnId: "turn-1" },
          },
        });
        send(input, { id: message.id, result: execution });
      } else if (message.id === "run") {
        break;
      }
    }
    expect(await finished).toBe(1);
    expect(close).toHaveBeenCalledTimes(1);
    expect(
      messages.filter((message) => message.method === "execution.run"),
    ).toHaveLength(1);
    expect(messages.filter((message) => message.id === "run")).toHaveLength(1);
    expect(messages.at(-1)).toMatchObject({
      id: "run",
      result: { status: "acceptance_unknown", execution },
    });
    expect(messages.at(-1).result.execution).toEqual(execution);
    expect(messages.filter((message) => "error" in message)).toEqual([]);
    expect(messages).toContainEqual({
      jsonrpc: "2.0",
      method: "scan.progress",
      params: {
        id: "run",
        event: {
          type: "activity",
          activity: {
            id: "runtime.cleanup",
            kind: "message",
            status: "failed",
            description: expect.stringContaining(cleanupFailureMessage),
            paths: [],
          },
        },
      },
    });
  } finally {
    close.mockRestore();
    lines.close();
    input.destroy();
    output.destroy();
  }
});

test("cancellation after registration retains scan identity before executor dispatch", async () => {
  const input = await fixture();
  const controller = new AbortController();
  const executor = noExecution();
  const result = await runHostedScan(input, {
    signal: controller.signal,
    onEvent(event) {
      if (
        event.type === "progress" &&
        event.progress.phase === "preflight" &&
        event.progress.filesTotal > 0
      )
        controller.abort(new Error("Invalid JSON."));
    },
    executor,
  });
  expect(result.status).toBe("canceled");
  expect(executor.run).not.toHaveBeenCalled();
  expect(result.scanId).toBeString();
  expect(result.execution).toBeUndefined();
  const history = await hostedWorkbench(input, [
    "list-scans",
    "--repository",
    input.repository,
  ]);
  expect(history["scans"]).toMatchObject([
    {
      scanId: result.scanId,
      scanDir: result.outputDirectory,
      progress: { status: "canceled" },
    },
  ]);
});

test("invalid host input records a registered scan as failed when pre-dispatch cleanup completes", async () => {
  const params = await fixture();
  const input = new PassThrough();
  const run = spyOn(hostedScan, "runHostedScan");
  try {
    const output = capture();
    const finished = runHostedScanProtocol(input, {
      write(chunk) {
        output.stream.write(chunk);
        const frame = JSON.parse(chunk.toString());
        const progress = frame.params?.event?.progress;
        if (progress?.phase === "preflight" && progress.filesTotal > 0)
          input.write("invalid JSON\n");
        return true;
      },
    });
    send(input, { id: "run", method: "run", params });
    expect(await finished).toBe(2);
    const messages = parseJsonLines(output.text());
    expect(messages.at(-1)?.error).toMatchObject({
      code: -32700,
      message: "Invalid JSON.",
    });
    expect(messages.some((frame) => frame.method === "execution.run")).toBe(
      false,
    );
    // The protocol can report the input error before the scan finishes its cleanup.
    await run.mock.results[0]!.value;
    const history = await hostedWorkbench(params, [
      "list-scans",
      "--repository",
      params.repository,
    ]);
    expect(history["scans"]).toMatchObject([
      { scanDir: params.outputDirectory, progress: { status: "failed" } },
    ]);
  } finally {
    run.mockRestore();
    input.destroy();
  }
});

test("mismatched execution receipts are never accepted or retried", async () => {
  const input = await fixture();
  const executor = {
    run: mock(async () =>
      receipt(
        { requestId: "other-request" },
        {
          sessionId: "known-session",
          usage: { input_tokens: 9 },
        },
      ),
    ),
  };
  const result = await runHostedScan(input, { executor });
  expect(executor.run).toHaveBeenCalledTimes(1);
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
      return receipt(request, {
        status: "acceptance_unknown",
        sessionId: "host-owned-session",
      });
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

test.each(["cancel", "disconnect", "signal"])(
  "blocked execution request terminates on %s",
  async (action) => {
    const params = await fixture();
    const input = new PassThrough();
    const controller = new AbortController();
    const { output, writing, release } = blockedOutput();
    const run = spyOn(hostedScan, "runHostedScan");
    try {
      const finished = runHostedScanProtocol(input, output, controller.signal);
      send(input, { id: "run", method: "run", params });
      await writing;
      if (action === "cancel")
        send(input, { method: "cancel", params: { id: "run" } });
      else if (action === "signal") controller.abort();
      else input.end();
      expect(await finished).toBe(2);
      expect(output.destroyed).toBe(true);
      expect(run).toHaveBeenCalledTimes(1);
    } finally {
      release();
      input.destroy();
      output.destroy();
      // Transport cancellation can finish before the scan closes its client.
      await Promise.allSettled(run.mock.results.map(({ value }) => value));
      run.mockRestore();
    }
  },
);

test.each(["result", "error"])(
  "output closure interrupts a blocked terminal %s without a second response",
  async (terminal) => {
    const input = new PassThrough();
    const { output, writing, release, write } = blockedOutput();
    const finished = runHostProtocol(input, output, {
      label: "Scan",
      requestMethod: "execution.run",
      async run() {
        if (terminal === "error") throw new Error("Invalid run parameters");
        return { status: "completed" };
      },
    });
    send(input, { id: "run", method: "run", params: {} });
    await writing;
    input.end();
    output.destroy();
    try {
      expect(await finished).toBe(2);
      expect(output.destroyed).toBe(true);
      expect(write).toHaveBeenCalledTimes(1);
    } finally {
      release();
      input.destroy();
      output.destroy();
    }
  },
);

test("the exported contract fixture matches v2 and rejects explicit empty scope", async () => {
  const fixture = await readJson<any>(
    join(import.meta.dirname, "../schemas/hosted-scan-v2.fixture.json"),
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
  expect(fixture.terminal.id).toBe(fixture.run.id);
  expect(fixture.terminal.result).toMatchObject({
    version: 2,
    status: "completed",
    identity: fixture.run.params.identity,
    scope: fixture.run.params.scope,
    scanId: fixture.execution.params.scanId,
    execution: ScanExecutionResultSchema.parse(fixture.response.result),
  });
});

test("standalone SDK rejects local scan options and configuration before dispatch", async () => {
  const input = await fixture();
  const executor = noExecution();
  for (const extra of [
    { mode: "deep" },
    { config: { codexOverrides: { profile: "local" } } },
  ])
    await expect(
      runHostedScan({ ...input, ...extra }, { executor }),
    ).rejects.toThrow("Unrecognized key");
  expect(executor.run).not.toHaveBeenCalled();
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
