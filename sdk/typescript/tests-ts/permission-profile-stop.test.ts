import { fixtureSpawn } from "./support/codex-process.js";
import { expect, spyOn, test } from "bun:test";
import * as childProcess from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPermissionCheckedCodex } from "../src/permission-profile.js";
import { ScanPermissionError } from "../src/scan-execution.js";
import { createRequire } from "node:module";
import { mkdir } from "node:fs/promises";
import { scanRuntimeCodexConfig } from "../src/api.js";
import { createProviderProfile } from "../src/provider-profile.js";
import { preparedRuntime } from "./support/api-events.js";
import { executablePathForSpawn } from "../src/runtime.js";
import {
  createExecutionCodex,
  prepareExecutionSource,
  prepareDiscoveryExecution,
  prepareMergeExecution,
  type PreparedExecution,
} from "../src/execution-preparation.js";

test.each(
  (["discovery", "merge"] as const).flatMap((role) =>
    [false, true].map((resumed) => ({ role, resumed })),
  ),
)(
  "provider worker fallback keeps its terminal permission error: %j",
  async ({ role, resumed }) => {
    const root = await mkdtemp(join(tmpdir(), "provider-permission-stop-"));
    const home = join(root, "home");
    await mkdir(home, { mode: 0o700 });
    const executable = join(root, "synthetic-codex.exe");
    const script = join(root, "codex.cjs");
    const warningPrefix =
      "Configured value for `permission_profile` is disallowed by requirements; falling back from `";
    const warningSuffix = "` to required value `:read-only`.";
    await writeFile(
      script,
      `
const {parse} = require(${JSON.stringify(createRequire(import.meta.url).resolve("smol-toml"))});
const args = process.argv.slice(2), config = {};
const merge = (a,b) => { for(const [k,v] of Object.entries(b)) a[k] = v && typeof v === "object" && !Array.isArray(v) ? merge(a[k] ?? {},v) : v; return a; };
for(let i=0;i<args.length;i++) if(["-c","--config"].includes(args[i])) merge(config,parse(args[++i]));
if(args.includes("app-server")) require("node:readline").createInterface({input:process.stdin}).on("line",line=>{
 const request=JSON.parse(line); if(request.id===undefined)return;
 const result=request.method==="initialize"?{}:request.method==="config/read"?{config}:{data:[{id:config.default_permissions,allowed:true}],nextCursor:null};
 console.log(JSON.stringify({id:request.id,result}));
});
else { process.stdin.resume(); process.stdin.on("end",()=>{
 console.log(JSON.stringify({type:"thread.started",thread_id:"synthetic-worker"}));
 console.log(JSON.stringify({type:"error",message:${JSON.stringify(warningPrefix)}+config.default_permissions+${JSON.stringify(warningSuffix)}}));
}); }
`,
    );
    const spawning = spyOn(childProcess, "spawn").mockImplementation(
      fixtureSpawn(executablePathForSpawn(executable), script, () => {}),
    );
    const configuration = {
      model_provider: "synthetic",
      model_providers: {
        synthetic: { name: "Synthetic", wire_api: "responses" },
      },
    };
    const profile = await createProviderProfile(home, configuration);
    try {
      const source = prepareExecutionSource({
        command: { command: executable },
        configuration,
        environment: { PATH: process.env["PATH"], CODEX_HOME: home },
      });
      const session: PreparedExecution = {
        policy: "ordinary",
        source,
        runtime: { ...preparedRuntime(home), providerProfile: profile },
        runtimeHome: home,
        effectiveConfig: configuration,
        preflightConfig: {},
        sessionConfig: scanRuntimeCodexConfig(configuration, root),
        authentication: source.authentication,
        approvalPolicy: "never",
        python: process.execPath,
        releaseCredentialHome: null,
      };
      const worker =
        role === "discovery"
          ? prepareDiscoveryExecution(session)
          : prepareMergeExecution(session, 2);
      const { codex } = await createExecutionCodex(
        { surface: "sdk", command: "scan" },
        worker,
        {},
      );
      const options = { workingDirectory: root };
      const thread = resumed
        ? codex.resumeThread!("synthetic-worker", options)
        : codex.startThread(options);
      await expect(
        (async () => {
          const { events } = await thread.runStreamed(
            "Synthetic permission fallback.",
            {},
          );
          for await (const _event of events) {
          }
        })(),
      ).rejects.toBeInstanceOf(ScanPermissionError);
    } finally {
      spawning.mockRestore();
      await profile.cleanup();
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("cancellation drains a preflight child that ignores graceful termination", async () => {
  const root = await mkdtemp(join(tmpdir(), "permission-stop-"));
  const executable = join(root, "synthetic-codex.exe");
  const script = join(root, "preflight.cjs");
  await writeFile(
    script,
    `
    process.on("SIGTERM", () => {});
    require("node:readline").createInterface({ input: process.stdin }).on("line", line => {
      const request = JSON.parse(line);
      if (request.method === "initialize") console.log(JSON.stringify({ id: request.id, result: {} }));
      if (request.method === "config/read") process.stderr.write("ready\\n");
    });
    setInterval(() => {}, 1000);
  `,
  );
  const ready = Promise.withResolvers<void>();
  let child: childProcess.ChildProcess | undefined;
  const spawning = spyOn(childProcess, "spawn").mockImplementation(
    fixtureSpawn(executable, script, (spawned) => {
      child = spawned;
      spawned.stderr!.on("data", (bytes: Buffer) => {
        if (bytes.toString().includes("ready")) ready.resolve();
      });
    }),
  );
  const controller = new AbortController();
  const codex = createPermissionCheckedCodex({
    codexPathOverride: executable,
    env: { PATH: process.env["PATH"] ?? "" },
    config: {
      default_permissions: "fixture",
      permissions: {
        fixture: { filesystem: { "/": "read" }, network: { enabled: false } },
      },
    },
  });
  const pending = codex
    .startThread({ workingDirectory: root })
    .runStreamed("inert fixture", { signal: controller.signal });
  // Observe the rejection immediately, including cleanup failures.
  const settled = pending.then(
    () => new Error("Unexpected scan execution"),
    (error) => error,
  );
  try {
    await ready.promise;
    const reason = new Error("synthetic cancellation");
    controller.abort(reason);
    expect(await settled).toBe(reason);
    expect(child!.exitCode !== null || child!.signalCode !== null).toBe(true);
  } finally {
    child?.kill("SIGKILL");
    await settled;
    spawning.mockRestore();
    await rm(root, { recursive: true, force: true });
  }
}, 10000);

test.each([false, true])(
  "rejects an exited preflight child while a descendant retains its pipes (resumed: %p)",
  async (resumed) => {
    const root = await mkdtemp(join(tmpdir(), "permission-exit-"));
    const executable = join(root, "synthetic-codex.exe");
    const script = join(root, "preflight.cjs");
    await writeFile(
      script,
      `
      require("node:readline").createInterface({ input: process.stdin }).on("line", line => {
        const request = JSON.parse(line);
        if (request.method === "initialize") console.log(JSON.stringify({ id: request.id, result: {} }));
        if (request.method === "config/read") {
          const descendant = require("node:child_process").spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: ["ignore", "inherit", "inherit"] });
          process.stderr.write("descendant:" + descendant.pid + "\\n", () => process.exit(1));
        }
      });
    `,
    );
    let child: childProcess.ChildProcess | undefined;
    let descendantPid: number | undefined;
    let stderr = "";
    const spawning = spyOn(childProcess, "spawn").mockImplementation(
      fixtureSpawn(executable, script, (spawned) => {
        child = spawned;
        spawned.stderr!.on("data", (bytes: Buffer) => {
          stderr += bytes.toString();
          const match = /descendant:(\d+)\n/u.exec(stderr);
          if (match) descendantPid = Number(match[1]);
        });
      }),
    );
    const codex = createPermissionCheckedCodex({
      codexPathOverride: executable,
      env: { PATH: process.env["PATH"] ?? "" },
      config: {
        default_permissions: "fixture",
        permissions: {
          fixture: { filesystem: { "/": "read" }, network: { enabled: false } },
        },
      },
    });
    const threadOptions = { workingDirectory: root };
    const thread = resumed
      ? codex.resumeThread("synthetic-saved-thread", threadOptions)
      : codex.startThread(threadOptions);
    const pending = thread.runStreamed("inert fixture");
    const watchdog = Promise.withResolvers<never>();
    const timeout = setTimeout(
      () => watchdog.reject(new Error("Preflight did not stop after exiting")),
      5_000,
    );
    try {
      const failure = await Promise.race([pending, watchdog.promise]).catch(
        (error: unknown) => error,
      );
      expect(failure).toBeInstanceOf(Error);
      expect(failure).not.toBeInstanceOf(ScanPermissionError);
      expect(failure).toMatchObject({
        message: "Codex permission preflight ended before its response.",
      });
      expect(child!.exitCode).toBe(1);
      expect(child!.stdout!.destroyed).toBe(true);
      expect(descendantPid).toBeDefined();
      expect(spawning).toHaveBeenCalledTimes(1);
    } finally {
      spawning.mockRestore();
      clearTimeout(timeout);
      child?.kill("SIGKILL");
      if (descendantPid !== undefined) {
        try {
          process.kill(descendantPid, "SIGKILL");
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
        }
      }
      await pending.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  },
  10000,
);
