import * as childProcess from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "bun:test";
import {
  isPermissionProfileFallbackWarning,
  profileConfigOverrides,
} from "../../../plugins/codex-security/scripts/codex_profile.mjs";
import { loadBundledRuntime } from "./plugin-root.js";
import { createApiTestFixtures } from "./support/temporary-directories.js";

type PreflightOptions = {
  codexPath: string;
  cwd: string;
  configOverrides: readonly string[];
  expectedProfile: Record<string, unknown>;
  signal: AbortSignal;
  scratchPath?: string;
  allowOpenAiApiKeyFallback?: boolean;
};
type PreflightResult = { useOpenAiApiKey: boolean; scratchWritable?: boolean };
type RpcCall = { method: string; params?: Record<string, unknown> };
type Scenario = {
  rejectProfile?: boolean;
  commandResult?: unknown;
  commandError?: { code: number; message: string };
  commandTransport?: "exit" | "hang";
  forcedLoginMethod?: "chatgpt";
};

const profileId = "codex_security_deep_scan_worker";
const fixtures = createApiTestFixtures("deep scratch native preflight ");
const children = new Set<childProcess.ChildProcess>();
const nodeRequire = createRequire(import.meta.url);

afterEach(async () => {
  await Promise.all(
    [...children].map(async (child) => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      const closed = new Promise<void>((resolve) =>
        child.once("close", resolve),
      );
      child.kill("SIGKILL");
      await closed;
    }),
  );
  await fixtures.cleanup();
});

async function fixture(scenario: Scenario = {}) {
  const root = await fixtures.temporaryDirectory();
  const cwd = join(root, "worker output");
  const scratchPath = join(root, "worker scratch");
  const scriptPath = join(root, "fake app server.mjs");
  const callsPath = join(root, "calls.jsonl");
  const argvPath = join(root, "argv.json");
  const expectedProfile = {
    extends: ":read-only",
    filesystem: { ":root": "read", [scratchPath]: "write" },
    network: { enabled: false },
  };
  const configOverrides = profileConfigOverrides({
    default_permissions: profileId,
    [`permissions.${profileId}`]: expectedProfile,
  });
  await mkdir(cwd);
  await writeFile(
    scriptPath,
    fakeAppServer({
      ...scenario,
      callsPath,
      argvPath,
      profileId,
      expectedProfile,
    }),
  );
  let probeReady!: () => void;
  const probeStarted = new Promise<void>((resolve) => {
    probeReady = resolve;
  });
  const node = Bun.which("node");
  expect(node).not.toBeNull();
  const runtime = await loadBundledRuntime();
  const start = runtime.indexOf(
    "// src/deep-scan/permission-profile-preflight.ts\n",
  );
  const end = runtime.indexOf("\n// ", start + 4);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  const source = runtime.slice(start, end);
  const versionBinding = /version:\s*(version\d*)/u.exec(source)?.[1];
  expect(versionBinding).toBeDefined();
  class DeepScanNonRetryableError extends Error {
    override name = "DeepScanNonRetryableError";
  }
  const bindings = {
    require: (name: string) =>
      name === "node:child_process"
        ? {
            ...childProcess,
            spawn: (
              command: string,
              args: string[],
              options: childProcess.SpawnOptions,
            ) => {
              expect(command).toBe(process.execPath);
              const child = childProcess.spawn(
                node!,
                [scriptPath, ...args],
                options,
              );
              children.add(child);
              child.once("close", () => children.delete(child));
              let stderr = "";
              child.stderr?.on("data", (chunk: Buffer) => {
                stderr += chunk.toString("utf8");
                if (stderr.includes("SCRATCH_PROBE_READY")) probeReady();
              });
              return child;
            },
          }
        : nodeRequire(name),
    asRecord: (value: unknown) =>
      value !== null && typeof value === "object" && !Array.isArray(value)
        ? value
        : undefined,
    DeepScanNonRetryableError,
    executablePathForSpawn: (path: string) => path,
    isPermissionProfileFallbackWarning,
    [versionBinding!]: "synthetic-version",
  };
  const preflight = new Function(
    ...Object.keys(bindings),
    `${source}\nreturn preflightDeepScanWorkerPermissionProfile;`,
  )(...Object.values(bindings)) as (
    options: PreflightOptions,
  ) => Promise<PreflightResult>;
  const options: PreflightOptions = {
    codexPath: process.execPath,
    cwd,
    configOverrides,
    expectedProfile,
    scratchPath,
    signal: new AbortController().signal,
  };
  return {
    options,
    scratchPath,
    probeStarted,
    preflight,
    calls: async () =>
      (await readFile(callsPath, "utf8"))
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as RpcCall),
    argv: async () => JSON.parse(await readFile(argvPath, "utf8")) as string[],
  };
}

test("verifies the profile before a same-session native scratch probe and authentication lookup", async () => {
  const item = await fixture();
  expect(
    await item.preflight({ ...item.options, allowOpenAiApiKeyFallback: true }),
  ).toEqual({
    useOpenAiApiKey: true,
    scratchWritable: true,
  });
  expect(await item.argv()).toEqual([
    ...item.options.configOverrides.flatMap((value) => ["--config", value]),
    "app-server",
    "--stdio",
  ]);
  const calls = await item.calls();
  expect(calls.map((call) => call.method)).toEqual([
    "initialize",
    "initialized",
    "config/read",
    "permissionProfile/list",
    "command/exec",
    "account/read",
  ]);
  const probe = calls.find((call) => call.method === "command/exec")!.params!;
  expect(Object.keys(probe).sort()).toEqual(["command", "cwd"]);
  expect(probe["cwd"]).toBe(item.options.cwd);
  const command = probe["command"] as string[];
  expect(command).toHaveLength(4);
  expect(command.slice(0, 2)).toEqual([process.execPath, "-e"]);
  expect(command[2]).not.toContain(item.scratchPath);
  expect(dirname(command[3]!)).toBe(item.scratchPath);
  expect(await readdir(item.scratchPath)).toEqual([]);
});

test("a completed probe denial returns readonly availability without disrupting authentication", async () => {
  const item = await fixture({
    commandResult: {
      exitCode: 1,
      stdout: "",
      stderr: "synthetic denied write",
    },
  });
  expect(
    await item.preflight({ ...item.options, allowOpenAiApiKeyFallback: true }),
  ).toEqual({
    useOpenAiApiKey: true,
    scratchWritable: false,
  });
  expect((await item.calls()).at(-1)?.method).toBe("account/read");
});

test("omitting scratch preserves the existing preflight RPCs and result contract", async () => {
  const item = await fixture();
  const { scratchPath: _scratch, ...options } = item.options;
  expect(await item.preflight(options)).toEqual({ useOpenAiApiKey: false });
  expect((await item.calls()).map((call) => call.method)).toEqual([
    "initialize",
    "initialized",
    "config/read",
    "permissionProfile/list",
  ]);
  expect(existsSync(item.scratchPath)).toBe(false);
});

test("a verified profile rejection prevents scratch creation and execution", async () => {
  const item = await fixture({ rejectProfile: true });
  const error = await item
    .preflight(item.options)
    .catch((error: Error) => error);
  expect(error).toBeInstanceOf(Error);
  expect((error as Error).name).toBe("DeepScanNonRetryableError");
  expect(existsSync(item.scratchPath)).toBe(false);
  expect((await item.calls()).map((call) => call.method)).toEqual([
    "initialize",
    "initialized",
    "config/read",
    "permissionProfile/list",
    "configRequirements/read",
  ]);
});

test("an unusable scratch directory returns false before executing a probe", async () => {
  const item = await fixture();
  await writeFile(item.scratchPath, "synthetic existing file");
  expect(await item.preflight(item.options)).toEqual({
    useOpenAiApiKey: false,
    scratchWritable: false,
  });
  expect(
    (await item.calls()).some((call) => call.method === "command/exec"),
  ).toBe(false);
  expect(await readFile(item.scratchPath, "utf8")).toBe(
    "synthetic existing file",
  );
});

test.each([
  {},
  { exitCode: 0.5, stdout: "", stderr: "" },
  { exitCode: 0, stdout: null, stderr: "" },
  { exitCode: 0, stdout: "", stderr: 7 },
])(
  "malformed command completion propagates a preflight error: %j",
  async (commandResult) => {
    const item = await fixture({ commandResult });
    const error = await item
      .preflight(item.options)
      .catch((error: Error) => error);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).name).toBe("Error");
  },
);

test("command RPC failures retain native diagnostics and retryability", async () => {
  const item = await fixture({
    commandError: { code: -32603, message: "synthetic command RPC diagnostic" },
  });
  const error = await item
    .preflight(item.options)
    .catch((error: Error) => error);
  expect(error).toBeInstanceOf(Error);
  expect((error as Error).name).toBe("Error");
  expect((error as Error).message).toContain(
    "synthetic command RPC diagnostic",
  );
});

test("probe transport failure propagates instead of becoming a completed denial", async () => {
  const item = await fixture({ commandTransport: "exit" });
  const error = await item
    .preflight(item.options)
    .catch((error: Error) => error);
  expect(error).toBeInstanceOf(Error);
  expect((error as Error).name).toBe("Error");
  expect((error as Error).message).toContain(
    "synthetic probe transport diagnostic",
  );
});

test("aborting an in-flight native probe preserves cancellation", async () => {
  const item = await fixture({ commandTransport: "hang" });
  const controller = new AbortController();
  const reason = new Error("synthetic probe canceled");
  const pending = item
    .preflight({ ...item.options, signal: controller.signal })
    .catch((error: Error) => error);
  await item.probeStarted;
  controller.abort(reason);
  expect(await pending).toBe(reason);
});

test("forced ChatGPT authentication skips fallback lookup after a successful probe", async () => {
  const item = await fixture({ forcedLoginMethod: "chatgpt" });
  expect(
    await item.preflight({ ...item.options, allowOpenAiApiKeyFallback: true }),
  ).toEqual({
    useOpenAiApiKey: false,
    scratchWritable: true,
  });
  expect(
    (await item.calls()).some((call) => call.method === "account/read"),
  ).toBe(false);
});

function fakeAppServer(scenario: Record<string, unknown>): string {
  return `import { appendFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
const scenario = ${JSON.stringify(scenario)};
writeFileSync(scenario.argvPath, JSON.stringify(process.argv.slice(2)));
const lines = createInterface({ input: process.stdin });
lines.on("close", () => process.exit(0));
lines.on("line", (line) => {
  const call = JSON.parse(line);
  appendFileSync(scenario.callsPath, JSON.stringify(call) + "\\n");
  if (call.id === undefined) return;
  const reply = (result) => process.stdout.write(JSON.stringify({ id: call.id, result }) + "\\n");
  if (call.method === "initialize") return reply({});
  if (call.method === "config/read") return reply({ config: {
    default_permissions: scenario.profileId,
    permissions: { [scenario.profileId]: scenario.expectedProfile },
    ...(scenario.forcedLoginMethod ? { forced_login_method: scenario.forcedLoginMethod } : {}),
  } });
  if (call.method === "permissionProfile/list") return reply({
    data: [{ id: scenario.profileId, description: null, allowed: !scenario.rejectProfile }], nextCursor: null,
  });
  if (call.method === "configRequirements/read") return reply({ requirements: { allowedPermissionProfiles: { other_profile: true } } });
  if (call.method === "account/read") return reply({ requiresOpenaiAuth: true, account: null });
  if (call.method === "command/exec") {
    if (scenario.commandTransport === "hang") { process.stderr.write("SCRATCH_PROBE_READY\\n"); return; }
    if (scenario.commandTransport === "exit") { process.stderr.write("synthetic probe transport diagnostic\\n"); process.exit(17); }
    if (scenario.commandError) { process.stdout.write(JSON.stringify({ id: call.id, error: scenario.commandError }) + "\\n"); return; }
    if (Object.hasOwn(scenario, "commandResult")) return reply(scenario.commandResult);
    const result = spawnSync(call.params.command[0], call.params.command.slice(1), { cwd: call.params.cwd, encoding: "utf8" });
    return reply({ exitCode: result.status, stdout: result.stdout, stderr: result.stderr });
  }
  process.stdout.write(JSON.stringify({ id: call.id, error: { code: -32601, message: "unexpected fixture method" } }) + "\\n");
});
`;
}
