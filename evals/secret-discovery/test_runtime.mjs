import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";
import { Codex } from "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js";
import {
  codexSettings,
  preflightEval,
  prepareEval,
  runPreparedEval,
} from "./harness.mjs";

const unixOnly = { skip: process.platform === "win32", timeout: 15000 };
const sdkUrl = new URL(
  "../../sdk/typescript/node_modules/@openai/codex-sdk/dist/index.js",
  import.meta.url,
).href;
const tomlUrl = new URL(
  "../../sdk/typescript/node_modules/smol-toml/dist/index.js",
  import.meta.url,
).href;
const harnessUrl = new URL("./harness.mjs", import.meta.url).href;
const runtimeUrl = new URL("./runtime.mjs", import.meta.url).href;

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

async function waitForFile(path) {
  for (let attempt = 0; attempt < 500; attempt++) {
    try {
      await access(path);
      return;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await delay(20);
  }
  throw new Error(`Timed out waiting for ${path}`);
}

async function nativeFixture(t, mode = "complete") {
  const directory = await mkdtemp(join(tmpdir(), "eval-runtime-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const prepared = await prepareEval(join(directory, "eval"));
  const home = join(directory, "home");
  await mkdir(home);
  const executable = join(directory, "native", "bin", "codex.mjs");
  await mkdir(dirname(executable), { recursive: true });
  const result = {
    findings: prepared.fixture.positives.map((expected) => ({
      taxonomy: { category: "hardcoded-credentials", cwe: [expected.cwes[0]] },
      locations: [
        { path: expected.path, startLine: expected.line, role: "root_control" },
      ],
    })),
    coverage: {
      completeness: "complete",
      surfaces: [],
      explicitExclusions: [],
      deferred: [],
    },
  };
  await writeFile(executable, fakeNativeSource({ directory, mode, result }), {
    mode: 0o755,
  });
  const settings = codexSettings(home, executable, {
    PATH: dirname(process.execPath),
    HOME: home,
    OPENAI_API_KEY: "synthetic-env-key",
    DATABASE_URL: "synthetic-unrelated-secret",
  });
  return { directory, prepared, settings, executable };
}

// Fixed, offline app-server and exec protocol; only generated source and auth exist here.
function fakeNativeSource(scenario) {
  return `#!${process.execPath}
import { existsSync, writeFileSync, appendFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { parse } from ${JSON.stringify(tomlUrl)};
const scenario = ${JSON.stringify(scenario)};
const args = process.argv.slice(2);
const kind = args.includes("app-server") ? "preflight" : "exec";
const cwd = args.includes("--cd") ? args[args.indexOf("--cd") + 1] : process.cwd();
// Last repeated CLI keys win; parse dotted sibling keys together.
const overrides = new Map(args.flatMap((arg, index) => {
  if (arg !== "--config") return [];
  const value = args[index + 1];
  return [[value.slice(0, value.indexOf("=")), value]];
}));
const config = parse([...overrides.values()].join("\\n"));
const record = (name, value) => writeFileSync(join(scenario.directory, name + ".json"), JSON.stringify(value));
record(kind, { args, cwd: process.cwd(), effectiveCwd: cwd, config, env: process.env, pid: process.pid });
process.on("SIGTERM", () => {
  record(kind + "-stopping", { sourceExists: existsSync(cwd), homeExists: existsSync(process.env.CODEX_HOME) });
  setTimeout(() => {
    record(kind + "-stopped", { sourceExists: existsSync(cwd), homeExists: existsSync(process.env.CODEX_HOME) });
    process.exit(0);
  }, 75);
});
const send = (event) => process.stdout.write(JSON.stringify(event) + "\\n");
if (kind === "preflight") {
  setInterval(() => {}, 1000);
  const lines = createInterface({ input: process.stdin });
  lines.on("line", (line) => {
    const request = JSON.parse(line);
    appendFileSync(join(scenario.directory, "rpc.jsonl"), JSON.stringify(request) + "\\n");
    if (request.method === "initialized") return;
    let result = {};
    if (request.method === "config/read") result = { config };
    if (request.method === "permissionProfile/list") result = {
      data: [{ id: "discovery_eval", allowed: scenario.mode !== "managed-rejection" }], nextCursor: null,
    };
    if (request.method === "configRequirements/read") result = { requirements: null };
    send({ jsonrpc: "2.0", id: request.id, result });
  });
} else {
  let prompt = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { prompt += chunk; });
  process.stdin.on("end", () => {
    record("ready", { prompt });
    if (scenario.mode === "block") { setInterval(() => {}, 1000); return; }
    send({ type: "item.completed", item: { id: "final", type: "agent_message", text: JSON.stringify(scenario.result) } });
    if (scenario.mode.startsWith("fallback-")) {
      const message = "Configured value for \x60permission_profile\x60 is disallowed by requirements; falling back from \x60discovery_eval\x60 to required value \x60:read-only\x60.";
      send(scenario.mode === "fallback-item"
        ? { type: "item.completed", item: { id: "warning", type: "error", message } }
        : { type: "error", message });
      setInterval(() => {}, 1000);
    } else {
      send({ type: "turn.completed", usage: { input_tokens: 1, cached_input_tokens: 0, output_tokens: 1 } });
    }
  });
}
`;
}

test(
  "native preflight and SDK exec share effective settings and fallback auth",
  unixOnly,
  async (t) => {
    const { directory, prepared, settings } = await nativeFixture(t);
    await preflightEval(prepared, settings, new AbortController().signal);
    const { report } = await runPreparedEval(prepared, new Codex(settings));
    assert.equal(report.passed, true);
    const preflight = await readJson(join(directory, "preflight.json"));
    const exec = await readJson(join(directory, "exec.json"));
    assert.equal(preflight.cwd, prepared.repo);
    assert.equal(exec.effectiveCwd, prepared.repo);
    assert.deepEqual(preflight.config, exec.config);
    assert.deepEqual(exec.config.features, {
      memories: false,
      plugins: false,
      multi_agent: false,
      shell_snapshot: false,
    });
    assert.deepEqual(exec.config.shell_environment_policy, {
      inherit: "core",
      ignore_default_excludes: false,
    });
    assert.equal(exec.config.allow_login_shell, false);
    assert.equal(exec.config.approval_policy, "never");
    assert.equal(exec.config.model_reasoning_effort, "xhigh");
    assert.equal(exec.config.web_search, "disabled");
    assert.equal(exec.config.default_permissions, "discovery_eval");
    assert.equal(exec.config.permissions.discovery_eval.network.enabled, false);
    assert.equal(
      exec.config.permissions.discovery_eval.filesystem[
        settings.env.CODEX_HOME
      ],
      "deny",
    );
    assert.equal(exec.args.includes("--sandbox"), false);
    assert.equal(
      exec.args[exec.args.indexOf("--add-dir") + 1],
      prepared.runtime,
    );
    for (const entry of [preflight, exec]) {
      assert.equal(entry.env.CODEX_API_KEY, "synthetic-env-key");
      assert.equal(entry.env.CODEX_HOME, settings.env.CODEX_HOME);
      assert.equal(entry.env.CODEX_SQLITE_HOME, settings.env.CODEX_HOME);
      assert.equal(entry.env.DATABASE_URL, undefined);
    }
    const { CODEX_INTERNAL_ORIGINATOR_OVERRIDE, ...execEnvironment } = exec.env;
    assert.deepEqual(execEnvironment, preflight.env);
    const calls = (await readFile(join(directory, "rpc.jsonl"), "utf8"))
      .trim()
      .split("\n")
      .map(JSON.parse);
    assert.deepEqual(
      calls.map((call) => call.method),
      ["initialize", "initialized", "config/read", "permissionProfile/list"],
    );
    for (const call of calls.slice(2))
      assert.equal(call.params.cwd, prepared.repo);
  },
);

for (const [name, codexApiKey, hasLogin, expectedKey] of [
  ["blank Codex key", " \t ", false, "synthetic-env-key"],
  ["explicit Codex key", "synthetic-codex-key", false, "synthetic-codex-key"],
  ["file login", undefined, true, undefined],
]) {
  test(`native auth precedence with ${name}`, unixOnly, async (t) => {
    const { directory, prepared, settings: original } = await nativeFixture(t);
    const settings = codexSettings(
      original.env.CODEX_HOME,
      original.codexPathOverride,
      {
        ...original.env,
        CODEX_API_KEY: codexApiKey,
        OPENAI_API_KEY: " synthetic-env-key \n ",
      },
      hasLogin,
    );
    await preflightEval(prepared, settings, new AbortController().signal);
    const { report } = await runPreparedEval(prepared, new Codex(settings));
    assert.equal(report.passed, true);
    for (const processName of ["preflight", "exec"]) {
      const { env } = await readJson(join(directory, `${processName}.json`));
      assert.equal(env.CODEX_API_KEY, expectedKey);
    }
  });
}

test(
  "managed profile rejection prevents starting the SDK exec turn",
  unixOnly,
  async (t) => {
    const { directory, prepared, settings } = await nativeFixture(
      t,
      "managed-rejection",
    );
    await assert.rejects(async () => {
      await preflightEval(prepared, settings, new AbortController().signal);
      await runPreparedEval(prepared, new Codex(settings));
    }, /managed Codex policy rejected/);
    await assert.rejects(access(join(directory, "exec.json")), {
      code: "ENOENT",
    });
    await access(join(directory, "preflight-stopped.json"));
  },
);

for (const mode of ["fallback-item", "fallback-error"]) {
  test(
    `${mode} aborts the real SDK turn and discards its response`,
    unixOnly,
    async (t) => {
      const { directory, prepared, settings } = await nativeFixture(t, mode);
      await preflightEval(prepared, settings, new AbortController().signal);
      await assert.rejects(
        runPreparedEval(prepared, new Codex(settings)),
        /results were discarded/,
      );
      await access(join(directory, "exec-stopped.json"));
    },
  );
}

for (const [signal, exitCode] of [
  ["SIGINT", 130],
  ["SIGTERM", 143],
]) {
  test(
    `${signal} awaits the SDK child before removing source and auth`,
    unixOnly,
    async (t) => {
      const { directory, executable } = await nativeFixture(t, "block");
      const driver = join(directory, "driver.mjs");
      await writeFile(
        driver,
        `
import { mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Codex } from ${JSON.stringify(sdkUrl)};
import { codexSettings, preflightEval, prepareEval, runPreparedEval } from ${JSON.stringify(harnessUrl)};
import { withEvalState } from ${JSON.stringify(runtimeUrl)};
await withEvalState(async () => {
  const home = await mkdtemp(join(${JSON.stringify(directory)}, "signal-home-"));
  await writeFile(join(home, "auth.json"), '{"OPENAI_API_KEY":"synthetic-signal-key"}');
  return home;
}, async ({ root, home, signal }) => {
  await writeFile(join(${JSON.stringify(directory)}, "state.json"), JSON.stringify({ root, home }));
  const prepared = await prepareEval(root);
  const settings = codexSettings(home, ${JSON.stringify(executable)}, { PATH: ${JSON.stringify(dirname(process.execPath))}, HOME: home }, true);
  await preflightEval(prepared, settings, signal);
  await runPreparedEval(prepared, new Codex(settings), { signal });
});
`,
      );
      const child = spawn(process.execPath, [driver], {
        env: {
          PATH: dirname(process.execPath),
          HOME: directory,
          TMPDIR: directory,
        },
        stdio: ["ignore", "ignore", "pipe"],
      });
      let stderr = "";
      child.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      t.after(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
      });
      const exited = new Promise((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (code, signal) => resolve({ code, signal }));
      });
      await Promise.race([
        waitForFile(join(directory, "ready.json")),
        exited.then(() => {
          throw new Error(`Driver exited before exec was ready: ${stderr}`);
        }),
      ]);
      child.kill(signal);
      assert.deepEqual(await exited, { code: exitCode, signal: null }, stderr);
      const stopped = await readJson(join(directory, "exec-stopped.json"));
      assert.deepEqual(stopped, { sourceExists: true, homeExists: true });
      const state = await readJson(join(directory, "state.json"));
      for (const path of [state.root, state.home]) {
        await assert.rejects(access(path), { code: "ENOENT" });
      }
    },
  );
}
