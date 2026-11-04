import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs";
import path from "node:path";
import test, { type TestContext } from "node:test";
import { pathToFileURL } from "node:url";
import { stageSkillRuntime } from "./run-promptfoo.mts";

test("runtime contains checkout skill and fixtures without calibration labels", () => {
  const root = stageSkillRuntime();
  try {
    const skill = "plugins/codex-security/skills/triage-finding/SKILL.md";
    assert.equal(
      fs.readFileSync(path.join(root, skill), "utf8"),
      fs.readFileSync(
        path.resolve(import.meta.dirname, "../../..", skill),
        "utf8",
      ),
    );
    assert.ok(
      fs.existsSync(
        path.join(root, "evals/triage-finding/fixtures/repo/src/server.js"),
      ),
    );
    for (const name of ["datasets", "tests", "artifacts"])
      assert.equal(
        fs.existsSync(path.join(root, "evals/triage-finding", name)),
        false,
      );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("initializes native providers only in the Promptfoo child", async () => {
  const driver = `
    const cp = require('node:child_process');
    const spawn = cp.spawn;
    const calls = [];
    cp.spawn = (command, args, options) => {
      calls.push({ command, args, sameNodeOptions: options.env.NODE_OPTIONS === process.env.NODE_OPTIONS });
      return spawn(command, ['--eval', ''], options);
    };
    import(${JSON.stringify(new URL("./run-promptfoo.mts", import.meta.url).href)}).then(({ runPromptfoo }) => runPromptfoo(['view', '--no'])).then(code => {
      console.log(JSON.stringify({ code, calls }));
    });
  `;
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", "--eval", driver],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const code = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  assert.equal(code, 0, stderr);
  const result = JSON.parse(stdout) as {
    code: number;
    calls: { command: string; args: string[]; sameNodeOptions: boolean }[];
  };
  assert.equal(result.code, 0);
  assert.equal(result.calls.length, 2);
  const [helper, promptfoo] = result.calls;
  assert.ok(helper!.args[0]!.endsWith("build_mcp_app.mjs"));
  assert.equal(helper!.args.includes("--import"), false);
  assert.equal(promptfoo!.args[0], "--import");
  const initializer = promptfoo!.args[1]!;
  assert.equal(
    initializer.startsWith("file:")
      ? initializer
      : pathToFileURL(initializer).href,
    new URL("./initialize-provider.mts", import.meta.url).href,
  );
  assert.ok(promptfoo!.args[2]!.endsWith("entrypoint.js"));
  assert.deepEqual(promptfoo!.args.slice(3), ["view", "--no"]);
  for (const call of result.calls) {
    assert.equal(call.command, process.execPath);
    assert.equal(call.sameNodeOptions, true);
  }
});

async function interruptRunner(
  t: TestContext,
  child: ChildProcess,
  interrupt: () => void,
  exitCode: number,
) {
  t.after(() => {
    if (child.exitCode === null) child.kill("SIGKILL");
  });
  let stderr = "";
  child.stderr!.on("data", (chunk) => {
    stderr += chunk;
  });
  const exited = once(child, "exit");
  const outputEnded = once(child.stdout!, "end");
  let output = "";
  const ready = new Promise<{ root: string }>((resolve) => {
    child.stdout!.on("data", (chunk) => {
      output += chunk;
      if (output.includes("\n")) resolve(JSON.parse(output.split("\n")[0]));
    });
  });
  const { root } = await Promise.race([
    ready,
    exited.then(() => {
      throw new Error(`runner exited early: ${stderr}`);
    }),
  ]);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.ok(fs.existsSync(root));
  interrupt();
  assert.deepEqual(await exited, [exitCode, null], stderr);
  assert.equal(fs.existsSync(root), false);
  await outputEnded;
  return output;
}

test(
  "Windows console Ctrl+C lets the child save progress before runtime cleanup",
  { timeout: 15000 },
  async (t) => {
    const target = `
      const fs = require('node:fs');
      let received = 0;
      process.on('SIGINT', () => {
        received++;
        if (received > 1) process.exit(99);
        setTimeout(() => {
          console.log('saved:' + received + ':' + fs.existsSync(process.env.TRIAGE_RUNTIME_ROOT));
          process.exit(0);
        }, 150);
      });
      // IPC delivers the console event without using Windows kill(SIGINT).
      process.on('message', () => process.emit('SIGINT'));
      console.log(JSON.stringify({ root: process.env.TRIAGE_RUNTIME_ROOT }));
    `;
    const driver = `
      const cp = require('node:child_process');
      const spawn = cp.spawn;
      process.env.TEMP = require('node:os').tmpdir();
      Object.defineProperty(process, 'platform', { value: 'win32' });
      let child;
      cp.spawn = (command, args, options) => {
        if (args[0].endsWith('build_mcp_app.mjs'))
          return spawn(command, ['--eval', ''], options);
        child = spawn(command, ['--eval', ${JSON.stringify(target)}], {
          ...options, stdio: ['inherit', 'inherit', 'inherit', 'ipc'],
        });
        const kill = child.kill.bind(child);
        child.kill = signal => {
          console.log('forced:' + signal);
          return kill('SIGKILL');
        };
        return child;
      };
      process.on('message', () => {
        child.send('console-interrupt');
        process.emit('SIGINT');
      });
      import(${JSON.stringify(new URL("./run-promptfoo.mts", import.meta.url).href)}).then(({ runPromptfoo }) => runPromptfoo([])).then(code => { process.exitCode = code; process.disconnect(); });
    `;
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", "--eval", driver],
      { stdio: ["ignore", "pipe", "pipe", "ipc"] },
    );
    const output = await interruptRunner(
      t,
      child,
      () => child.send("console-interrupt"),
      130,
    );
    assert.match(output, /saved:1:true/);
    assert.doesNotMatch(output, /forced:/);
  },
);

for (const [signal, exitCode, delivery] of [
  ["SIGINT", 130, "pid"],
  ["SIGINT", 130, "group"],
  ["SIGTERM", 143, "pid"],
  ["SIGTERM", 143, "group"],
] as const) {
  test(
    `runner forwards ${signal} once (${delivery}) and removes its runtime after the child exits`,
    { skip: process.platform === "win32", timeout: 15000 },
    async (t) => {
      const target = `
      let received = 0;
      process.on(${JSON.stringify(signal)}, () => {
        received++;
        if (received > 1) process.exit(99);
        setTimeout(() => {
          console.log("graceful:" + received + ":" + require("node:fs").existsSync(process.env.TRIAGE_RUNTIME_ROOT));
          process.exit(0);
        }, 150);
      });
      console.log(JSON.stringify({ root: process.env.TRIAGE_RUNTIME_ROOT }));
      setInterval(() => {}, 1000);
    `;
      const driver = `
    const cp = require('node:child_process');
    const spawn = cp.spawn;
    cp.spawn = (command, args, options) => spawn(process.execPath, ['--eval', args[0].endsWith("build_mcp_app.mjs") ? "" : ${JSON.stringify(target)}], options);
    import(${JSON.stringify(new URL("./run-promptfoo.mts", import.meta.url).href)}).then(({ runPromptfoo }) => runPromptfoo([])).then(code => { process.exitCode = code; });
  `;
      const child = spawn(
        process.execPath,
        ["--experimental-strip-types", "--eval", driver],
        {
          stdio: ["ignore", "pipe", "pipe"],
          detached: true,
        },
      );
      const output = await interruptRunner(
        t,
        child,
        () => {
          if (delivery === "group") process.kill(-child.pid!, signal);
          else child.kill(signal);
        },
        exitCode,
      );
      assert.match(output, /graceful:1:true/);
    },
  );
}
