import * as fs from "node:fs";
import * as promises from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as url from "node:url";
import * as util from "node:util";
import { expect, test } from "bun:test";
import { parse } from "smol-toml";
import { profileConfigOverrides } from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { loadBundledRuntime } from "./plugin-root.js";

type ParentSandbox = {
  filesystemDenies: string[];
  filesystemWriteRules?: Array<{ path: string; access: "read" | "write" }>;
};
type WorkerRequest = {
  kind: "discovery" | "dedup";
  promptPath: string;
  workingDirectory: string;
  subagents: number;
  signal: AbortSignal;
  resumeThreadId?: string;
  continuationPrompt?: string;
  artifactContext: {
    root: string;
    layout: "worker" | "reducer";
    deepReducer?: Record<string, never>;
  };
};
type WorkerConstructor = new (settings: {
  parentSandbox: ParentSandbox;
  artifactContext: { pluginRoot: string; repoRoot: string; scanId: string };
}) => { run(request: WorkerRequest): Promise<{ threadId?: string }> };
type WorkerOptions = {
  env: Record<string, string>;
  configOverrides: string[];
};
type WorkerLaunch = {
  options: WorkerOptions;
  thread: { workingDirectory: string; threadSource: string };
  resumedThread?: string;
  input?: string;
};
type Preflight = WorkerOptions & {
  expectedProfile: Record<string, unknown>;
};

async function bundledExecutor(
  environment: Record<string, string>,
  preflightCheck: (input: Preflight) => Promise<void> = async () => {},
) {
  const runtime = await loadBundledRuntime();
  const parentStart = runtime.indexOf(
    "var CODEX_SANDBOX_STATE_META_CAPABILITY =",
  );
  const parentEnd = runtime.indexOf("\n// ", parentStart);
  expect(parentStart).toBeGreaterThan(0);
  expect(parentEnd).toBeGreaterThan(parentStart);
  const parentSource = runtime.slice(parentStart, parentEnd);
  const recordSource = runtime.match(
    /\/\/ src\/record\.ts\n[\s\S]*?(?=\n\/\/ )/u,
  )?.[0];
  expect(recordSource).toBeDefined();
  const executorSource =
    /var CodexSdkWorkerExecutor = class \{[\s\S]*?\n\};/u.exec(runtime)?.[0];
  expect(executorSource).toBeDefined();
  const helpers = [
    "workerPermissionProfile",
    "scratchFilesystemEntry",
    "scratchInstructions",
  ].map((name) => {
    const source = new RegExp(
      `function ${name}\\([^\\n]*\\) \\{[\\s\\S]*?\\n\\}`,
      "u",
    ).exec(runtime)?.[0];
    expect(source).toBeDefined();
    return source;
  });
  const source = [recordSource, parentSource, ...helpers, executorSource].join(
    "\n",
  );
  const imports = [
    ...new Set(
      source.match(/\bimport_(?:node_(?:fs|path|os|url|util)|promises)\d*/gu),
    ),
  ];
  const modules = imports.map((name) => {
    if (name.startsWith("import_node_fs")) return fs;
    if (name.startsWith("import_node_path")) return path;
    if (name.startsWith("import_node_os")) return os;
    if (name.startsWith("import_node_url")) return url;
    if (name.startsWith("import_node_util")) return util;
    return promises;
  });
  const launches: WorkerLaunch[] = [];
  const preflights: Preflight[] = [];
  class FakeCodex {
    constructor(private readonly options: WorkerOptions) {}
    startThread(thread: WorkerLaunch["thread"]) {
      return this.thread(thread);
    }
    resumeThread(id: string, thread: WorkerLaunch["thread"]) {
      return this.thread(thread, id);
    }
    private thread(thread: WorkerLaunch["thread"], resumedThread?: string) {
      const launch: WorkerLaunch = {
        options: this.options,
        thread,
        ...(resumedThread === undefined ? {} : { resumedThread }),
      };
      launches.push(launch);
      return {
        id: resumedThread ?? "synthetic-worker-thread",
        async runStreamed(input: string) {
          launch.input = input;
          return {
            events: (async function* () {
              yield { type: "turn.completed" };
            })(),
          };
        },
      };
    }
  }
  const bindings = {
    Codex: FakeCodex,
    DeepScanNonRetryableError: Error,
    profileConfigOverrides,
    DEEP_SCAN_WORKER_PERMISSION_PROFILE_ID: "codex_security_deep_scan_worker",
    snapshotWorkerEnvironment: async () => ({ ...environment }),
    workerRuntimeSettings: async () => ({ config: {} }),
    environmentVariable: (env: Record<string, string>, key: string) => env[key],
    preflightDeepScanWorkerPermissionProfile: async (input: Preflight) => {
      preflights.push({ ...input, env: { ...input.env } });
      await preflightCheck(input);
      return { useOpenAiApiKey: false };
    },
    deepScanPermissionProfileFallbackError: () => undefined,
    resolveCodexPath: () => process.execPath,
    executablePathForSpawn: (executable: string) => executable,
    workerSubagentConfig: () => ({}),
    appendItemDiagnostic: () => {},
    classifyCodexWorkerError: (error: unknown) => error,
  };
  const Worker = new Function(
    ...imports,
    ...Object.keys(bindings),
    `${source}\nreturn CodexSdkWorkerExecutor;`,
  )(...modules, ...Object.values(bindings)) as WorkerConstructor;
  return { Worker, launches, preflights };
}

async function fixture(workerName = "worker with spaces") {
  const root = await promises.realpath(
    await promises.mkdtemp(
      path.join(os.tmpdir(), "codex-security-worker-scratch-"),
    ),
  );
  const repository = path.join(root, "source repository");
  const output = path.join(root, workerName, "output");
  const scratch = path.join(path.dirname(output), "scratch");
  const promptPath = path.join(root, "prompt.md");
  await Promise.all([
    promises.mkdir(repository),
    promises.mkdir(output, { recursive: true }),
    promises.writeFile(promptPath, "Review the synthetic repository.\n"),
  ]);
  const request: WorkerRequest = {
    kind: "discovery",
    promptPath,
    workingDirectory: output,
    subagents: 0,
    signal: new AbortController().signal,
    artifactContext: { root: output, layout: "worker" },
  };
  const artifactContext = {
    pluginRoot: root,
    repoRoot: repository,
    scanId: path.basename(root),
  };
  const environment = {
    TMPDIR: path.join(root, "host temporary directory"),
    TMP: path.join(root, "host tmp"),
    TEMP: path.join(root, "host temp"),
  };
  return {
    root,
    repository,
    output,
    scratch,
    request,
    artifactContext,
    environment,
  };
}

function profile(options: WorkerOptions) {
  const configuration = parse(options.configOverrides.join("\n"));
  expect(configuration["approval_policy"]).toBe("never");
  expect(configuration["default_permissions"]).toBe(
    "codex_security_deep_scan_worker",
  );
  return (
    configuration["permissions"] as Record<
      string,
      {
        extends: string;
        filesystem: Record<string, unknown>;
        network: { enabled: boolean };
      }
    >
  )["codex_security_deep_scan_worker"]!;
}

function temporaryEnvironment(environment: Record<string, string>) {
  return [environment["TMPDIR"], environment["TMP"], environment["TEMP"]];
}

test("bundled discovery workers retain their authorized scratch across fresh, resumed, and retried turns", async () => {
  const item = await fixture();
  try {
    const readOnly = path.join(item.scratch, "private");
    const denied = path.join(item.scratch, "**", "*.secret");
    const { Worker, launches, preflights } = await bundledExecutor(
      item.environment,
    );
    const worker = new Worker({
      artifactContext: item.artifactContext,
      parentSandbox: {
        filesystemDenies: [denied],
        filesystemWriteRules: [
          { path: item.root, access: "write" },
          { path: readOnly, access: "read" },
        ],
      },
    });
    await worker.run(item.request);
    const proof = path.join(item.scratch, "proof.txt");
    await promises.writeFile(proof, "synthetic validation evidence");
    await worker.run({
      ...item.request,
      resumeThreadId: "synthetic-resumed-thread",
      continuationPrompt: "Continue the synthetic validation.",
    });
    await worker.run(item.request);

    expect(launches).toHaveLength(3);
    expect(launches.map((launch) => launch.resumedThread)).toEqual([
      undefined,
      "synthetic-resumed-thread",
      undefined,
    ]);
    for (const [index, launch] of launches.entries()) {
      expect(profile(launch.options)).toEqual({
        extends: ":read-only",
        filesystem: {
          ":root": "read",
          [item.scratch]: "write",
          [readOnly]: "read",
          [denied]: "deny",
        },
        network: { enabled: false },
      });
      expect(launch.thread).toMatchObject({
        workingDirectory: item.output,
        threadSource: "security_scan",
      });
      expect(temporaryEnvironment(launch.options.env)).toEqual(
        Array(3).fill(item.scratch),
      );
      expect(launch.input).toContain(JSON.stringify(item.scratch));
      expect(preflights[index]!.configOverrides).toEqual(
        launch.options.configOverrides,
      );
      expect(preflights[index]!.expectedProfile).toEqual(
        profile(launch.options),
      );
      expect(temporaryEnvironment(preflights[index]!.env)).toEqual(
        temporaryEnvironment(item.environment),
      );
    }
    expect(launches[1]!.input).toStartWith(
      "Continue the synthetic validation.",
    );
    expect(await promises.readFile(proof, "utf8")).toBe(
      "synthetic validation evidence",
    );
    expect(item.environment["TMPDIR"]).toBe(
      path.join(item.root, "host temporary directory"),
    );
  } finally {
    await promises.rm(item.root, { recursive: true, force: true });
  }
});

test.each([
  "read-only parent",
  "read carveout",
  "parent denial",
  "reducer",
] as const)(
  "bundled workers retain read-only execution for %s",
  async (scenario) => {
    const item = await fixture();
    try {
      const { Worker, launches } = await bundledExecutor(item.environment);
      const denied = path.dirname(item.output);
      const parentSandbox: ParentSandbox = {
        filesystemDenies: scenario === "parent denial" ? [denied] : [],
        ...(scenario === "read-only parent"
          ? {}
          : {
              filesystemWriteRules: [
                { path: item.root, access: "write" as const },
                ...(scenario === "read carveout"
                  ? [{ path: denied, access: "read" as const }]
                  : []),
              ],
            }),
      };
      const worker = new Worker({
        artifactContext: item.artifactContext,
        parentSandbox,
      });
      const request: WorkerRequest =
        scenario === "reducer"
          ? {
              ...item.request,
              kind: "dedup",
              artifactContext: {
                root: item.output,
                layout: "reducer",
                deepReducer: {},
              },
            }
          : item.request;
      await worker.run(request);
      await worker.run({
        ...request,
        resumeThreadId: "synthetic-resumed-thread",
      });
      expect(launches).toHaveLength(2);
      for (const launch of launches) {
        expect(profile(launch.options)).toEqual({
          extends: ":read-only",
          filesystem: {
            ":root": "read",
            ...(scenario === "parent denial" ? { [denied]: "deny" } : {}),
          },
          network: { enabled: false },
        });
        expect(temporaryEnvironment(launch.options.env)).toEqual(
          temporaryEnvironment(item.environment),
        );
      }
      expect(fs.existsSync(item.scratch)).toBe(false);
    } finally {
      await promises.rm(item.root, { recursive: true, force: true });
    }
  },
);

test("bundled workers do not create scratch before their permission profile passes preflight", async () => {
  const item = await fixture();
  try {
    const { Worker, launches } = await bundledExecutor(
      item.environment,
      async (input) => {
        expect(profile(input).filesystem[item.scratch]).toBe("write");
        expect(fs.existsSync(item.scratch)).toBe(false);
        expect(temporaryEnvironment(input.env)).toEqual(
          temporaryEnvironment(item.environment),
        );
        throw new Error("synthetic permission profile rejected");
      },
    );
    const worker = new Worker({
      artifactContext: item.artifactContext,
      parentSandbox: {
        filesystemDenies: [],
        filesystemWriteRules: [{ path: item.root, access: "write" }],
      },
    });
    await expect(worker.run(item.request)).rejects.toThrow(
      "synthetic permission profile rejected",
    );
    expect(launches).toHaveLength(0);
    expect(fs.existsSync(item.scratch)).toBe(false);
  } finally {
    await promises.rm(item.root, { recursive: true, force: true });
  }
});

test.each(["one scan", "different scans"] as const)(
  "concurrent bundled workers in %s isolate temporary scratch when scan output is read-only",
  async (scenario) => {
    const items = await Promise.all([
      fixture(),
      fixture(scenario === "one scan" ? "second worker" : undefined),
    ]);
    if (scenario === "one scan") {
      items[1]!.artifactContext.scanId = items[0]!.artifactContext.scanId;
    }
    const temporaryRoot = await promises.realpath(os.tmpdir());
    const scratchRoots = items.map((item) =>
      path.join(
        temporaryRoot,
        "codex-security-deep-scratch",
        item.artifactContext.scanId,
      ),
    );
    try {
      const { Worker, launches } = await bundledExecutor(items[0]!.environment);
      await Promise.all(
        items.map((item) =>
          new Worker({
            artifactContext: item.artifactContext,
            parentSandbox: {
              filesystemDenies: [],
              filesystemWriteRules: [
                { path: temporaryRoot, access: "write" },
                { path: item.root, access: "read" },
              ],
            },
          }).run(item.request),
        ),
      );
      expect(launches).toHaveLength(2);
      for (const [index, item] of items.entries()) {
        const launch = launches.find(
          (value) => value.thread.workingDirectory === item.output,
        )!;
        const scratch = path.join(
          scratchRoots[index]!,
          path.basename(path.dirname(item.output)),
        );
        expect(profile(launch.options)).toEqual({
          extends: ":read-only",
          filesystem: { ":root": "read", [scratch]: "write" },
          network: { enabled: false },
        });
        expect(temporaryEnvironment(launch.options.env)).toEqual(
          Array(3).fill(scratch),
        );
        expect(await promises.realpath(scratch)).toBe(scratch);
        expect(fs.existsSync(item.scratch)).toBe(false);
        expect(launch.input).toContain(JSON.stringify(scratch));
      }
      expect(launches[0]!.options.env).not.toBe(launches[1]!.options.env);
      expect(launches[0]!.options.env["TMPDIR"]).not.toBe(
        launches[1]!.options.env["TMPDIR"],
      );
    } finally {
      await Promise.all(
        [...new Set([...items.map((item) => item.root), ...scratchRoots])].map(
          (directory) =>
            promises.rm(directory, { recursive: true, force: true }),
        ),
      );
    }
  },
);
