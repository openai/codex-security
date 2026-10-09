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
  scratchPath?: string;
};

async function bundledExecutor(
  environment: Record<string, string>,
  preflightCheck: (
    input: Preflight,
  ) => Promise<boolean | void> = async () => {},
  inheritedEnvironment: Record<string, string> = {},
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
    "environmentVariable",
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
    workerRuntimeSettings: async () => ({
      config: {},
      environment: inheritedEnvironment,
    }),
    preflightDeepScanWorkerPermissionProfile: async (input: Preflight) => {
      preflights.push({ ...input, env: { ...input.env } });
      const scratchWritable = await preflightCheck(input);
      if (input.scratchPath !== undefined) {
        // Native preflight prepares the directory after verifying the profile,
        // then checks write access using that profile and the original temp env.
        await promises.mkdir(input.scratchPath, { recursive: true });
      }
      return {
        useOpenAiApiKey: false,
        ...(input.scratchPath === undefined
          ? {}
          : { scratchWritable: scratchWritable ?? true }),
      };
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
  return ["TMPDIR", "TMP", "TEMP"].map((name) =>
    process.platform === "win32"
      ? Object.entries(environment).find(
          ([key]) => key.toUpperCase() === name,
        )?.[1]
      : environment[name],
  );
}

test("bundled discovery workers retain their authorized scratch across fresh, resumed, and retried turns", async () => {
  const item = await fixture();
  try {
    const readOnly = path.join(item.scratch, "private");
    const denied = path.join(item.scratch, "**", "*.secret");
    const { Worker, launches, preflights } = await bundledExecutor(
      item.environment,
      undefined,
      {
        Tmpdir: item.environment.TMPDIR,
        Tmp: item.environment.TMP,
        Temp: item.environment.TEMP,
      },
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
    expect(preflights.map((input) => input.scratchPath)).toEqual(
      Array(3).fill(item.scratch),
    );
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
      for (const name of ["TMPDIR", "TMP", "TEMP"]) {
        const keys = Object.keys(launch.options.env).filter(
          (key) => key.toUpperCase() === name,
        );
        expect(keys).toHaveLength(process.platform === "win32" ? 1 : 2);
        expect(launch.options.env[name]).toBe(item.scratch);
      }
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
      const { Worker, launches, preflights } = await bundledExecutor(
        item.environment,
      );
      const denied = path.dirname(item.output);
      const parentSandbox: ParentSandbox = {
        filesystemDenies: scenario === "parent denial" ? [denied] : [],
        ...(scenario === "read-only parent"
          ? {}
          : {
              filesystemWriteRules: [
                { path: denied, access: "write" as const },
                ...(scenario === "read carveout"
                  ? [{ path: item.scratch, access: "read" as const }]
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
      expect(preflights).toHaveLength(2);
      expect(preflights.every((input) => input.scratchPath === undefined)).toBe(
        true,
      );
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
        expect(input.scratchPath).toBe(item.scratch);
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

test.each(["temporary scratch", "read-only execution"] as const)(
  "bundled workers fall back to %s when native scratch probes reject candidates",
  async (fallback) => {
    const item = await fixture();
    const temporaryRoot = await promises.realpath(os.tmpdir());
    const environment = {
      TMPDIR: temporaryRoot,
      TMP: temporaryRoot,
      TEMP: temporaryRoot,
    };
    const temporaryScratchRoot = path.join(
      temporaryRoot,
      "codex-security-deep-scratch",
      item.artifactContext.scanId,
    );
    const temporaryScratch = path.join(
      temporaryScratchRoot,
      path.basename(path.dirname(item.output)),
    );
    try {
      const { Worker, launches, preflights } = await bundledExecutor(
        environment,
        async (input) => {
          expect(input.env).toEqual(environment);
          expect(input.expectedProfile).toEqual(profile(input));
          if (input.scratchPath !== undefined) {
            expect(profile(input).filesystem[input.scratchPath]).toBe("write");
          }
          return (
            fallback === "temporary scratch" &&
            input.scratchPath === temporaryScratch
          );
        },
      );
      const worker = new Worker({
        artifactContext: item.artifactContext,
        parentSandbox: {
          filesystemDenies: [],
          filesystemWriteRules: [{ path: temporaryRoot, access: "write" }],
        },
      });
      await worker.run(item.request);
      const probes = preflights.filter(
        (input) => input.scratchPath !== undefined,
      );
      expect(probes.length).toBeGreaterThanOrEqual(2);
      expect(probes[0]!.scratchPath).toBe(item.scratch);
      expect(probes[1]!.scratchPath).toBe(temporaryScratch);
      expect(launches).toHaveLength(1);
      const launch = launches[0]!;
      const selected = preflights.at(-1)!;
      expect(launch.options.configOverrides).toEqual(selected.configOverrides);
      expect(profile(launch.options)).toEqual({
        extends: ":read-only",
        filesystem: {
          ":root": "read",
          ...(fallback === "temporary scratch"
            ? { [temporaryScratch]: "write" }
            : {}),
        },
        network: { enabled: false },
      });
      if (fallback === "temporary scratch") {
        expect(selected.scratchPath).toBe(temporaryScratch);
        expect(temporaryEnvironment(launch.options.env)).toEqual(
          Array(3).fill(temporaryScratch),
        );
        expect(launch.input).toContain(JSON.stringify(temporaryScratch));
      } else {
        expect(selected.scratchPath).toBeUndefined();
        expect(launch.options.env).toEqual(environment);
      }
    } finally {
      await Promise.all(
        [item.root, temporaryScratchRoot].map((directory) =>
          promises.rm(directory, { recursive: true, force: true }),
        ),
      );
    }
  },
);

test("bundled resumed workers recheck native scratch access before retaining their write profile", async () => {
  const item = await fixture();
  try {
    let permitted = true;
    const { Worker, launches, preflights } = await bundledExecutor(
      item.environment,
      async () => permitted,
    );
    const worker = new Worker({
      artifactContext: item.artifactContext,
      parentSandbox: {
        filesystemDenies: [],
        filesystemWriteRules: [{ path: item.scratch, access: "write" }],
      },
    });
    await worker.run(item.request);
    const proof = path.join(item.scratch, "proof.txt");
    await promises.writeFile(proof, "retained synthetic evidence");
    permitted = false;
    await worker.run({
      ...item.request,
      resumeThreadId: "synthetic-resumed-thread",
    });
    expect(preflights.map((input) => input.scratchPath)).toEqual([
      item.scratch,
      item.scratch,
      undefined,
    ]);
    expect(launches).toHaveLength(2);
    expect(profile(launches[0]!.options).filesystem[item.scratch]).toBe(
      "write",
    );
    expect(profile(launches[1]!.options)).toEqual({
      extends: ":read-only",
      filesystem: { ":root": "read" },
      network: { enabled: false },
    });
    expect(launches[1]!.resumedThread).toBe("synthetic-resumed-thread");
    expect(launches[1]!.options.env).toEqual(item.environment);
    expect(await promises.readFile(proof, "utf8")).toBe(
      "retained synthetic evidence",
    );
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
    const temporaryRoots = items.map((item) =>
      path.join(
        scenario === "one scan" ? items[0]!.root : item.root,
        "configured temporary directory",
      ),
    );
    const scratchRoots = items.map((item, index) =>
      path.join(
        temporaryRoots[index]!,
        "codex-security-deep-scratch",
        item.artifactContext.scanId,
      ),
    );
    try {
      const executors = await Promise.all(
        items.map((_item, index) =>
          bundledExecutor(items[0]!.environment, undefined, {
            TMPDIR: temporaryRoots[index]!,
            TMP: temporaryRoots[index]!,
            TEMP: temporaryRoots[index]!,
          }),
        ),
      );
      await Promise.all(
        items.map((item, index) =>
          new executors[index]!.Worker({
            artifactContext: item.artifactContext,
            parentSandbox: {
              filesystemDenies: [],
              filesystemWriteRules: [
                { path: temporaryRoots[index]!, access: "write" },
                { path: item.root, access: "read" },
              ],
            },
          }).run(item.request),
        ),
      );
      const launches = executors.flatMap((executor) => executor.launches);
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
        items.map((item) =>
          promises.rm(item.root, { recursive: true, force: true }),
        ),
      );
    }
  },
);
